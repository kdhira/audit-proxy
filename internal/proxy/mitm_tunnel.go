package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kdhira/audit-proxy/internal/audit"
)

func (h *handler) handleMitmTLS(clientConn net.Conn, baseReq *http.Request, targetHost string) error {
	hostOnly := targetHost
	if strings.Contains(targetHost, ":") {
		var err error
		hostOnly, _, err = net.SplitHostPort(targetHost)
		if err != nil {
			return fmt.Errorf("split host: %w", err)
		}
	}
	leaf, err := h.mitm.LeafForHost(hostOnly)
	if err != nil {
		return fmt.Errorf("issue leaf cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"http/1.1"},
	}
	serverTLS := tls.Server(clientConn, tlsConfig)
	defer serverTLS.Close()

	if err := serverTLS.Handshake(); err != nil {
		return fmt.Errorf("client tls handshake: %w", err)
	}

	reader := bufio.NewReader(serverTLS)

	for {
		inbound, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read mitm request: %w", err)
		}
		if err := h.processMitmRequest(serverTLS, inbound, baseReq, targetHost); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (h *handler) processMitmRequest(clientConn net.Conn, inbound *http.Request, baseReq *http.Request, targetHost string) error {
	start := time.Now()
	reqID := h.nextID()

	var (
		requestBuf  *audit.LimitedBuffer
		responseBuf *audit.LimitedBuffer
	)
	defer func() {
		h.releaseBuffer(requestBuf)
		h.releaseBuffer(responseBuf)
	}()

	if inbound.Body == nil {
		inbound.Body = http.NoBody
	}
	// Align request metadata for upstream forwarding.
	inbound.URL.Scheme = "https"
	inbound.URL.Host = targetHost
	inbound.Host = targetHost
	inbound.RemoteAddr = baseReq.RemoteAddr
	inbound.RequestURI = inbound.URL.RequestURI()

	outbound, _, err := cloneRequest(inbound)
	if err != nil {
		return h.writeMitmError(clientConn, reqID, start, inbound, targetHost, fmt.Errorf("clone request: %w", err))
	}

	if h.excerptLimit > 0 && outbound.Body != nil && outbound.Body != http.NoBody {
		requestBuf = h.acquireBuffer()
		outbound.Body = audit.NewTeeReadCloser(outbound.Body, requestBuf)
	}

	if err := h.filters.ApplyRequest(outbound); err != nil {
		return h.writeMitmStatus(clientConn, reqID, start, inbound, targetHost, http.StatusForbidden, fmt.Sprintf("request blocked: %v", err))
	}

	resp, err := h.transport.RoundTrip(outbound)
	if err != nil {
		return h.writeMitmStatus(clientConn, reqID, start, inbound, targetHost, http.StatusBadGateway, fmt.Sprintf("upstream error: %v", err))
	}
	defer resp.Body.Close()

	if err := h.filters.ApplyResponse(resp); err != nil {
		return h.writeMitmStatus(clientConn, reqID, start, inbound, targetHost, http.StatusBadGateway, fmt.Sprintf("response blocked: %v", err))
	}

	if h.excerptLimit > 0 && resp.Body != nil {
		responseBuf = h.acquireBuffer()
		resp.Body = audit.NewTeeReadCloser(resp.Body, responseBuf)
	}

	if err := resp.Write(clientConn); err != nil {
		return fmt.Errorf("write mitm response: %w", err)
	}

	bodyLen := resp.ContentLength
	if bodyLen < 0 && responseBuf != nil {
		bodyLen = int64(len(responseBuf.Bytes()))
	}

	entry := audit.Entry{
		Time:      start.UTC(),
		ID:        reqID,
		Conn:      newConnMetadata(inbound, targetHost, "https"),
		Request:   newHTTPRequest(inbound),
		Response:  newHTTPResponse(resp, bodyLen),
		LatencyMS: time.Since(start).Milliseconds(),
	}
	if requestBuf != nil && requestBuf.Len() > 0 {
		entry.Attributes = ensureAttrs(entry.Attributes)
		entry.Attributes["request_excerpt"] = string(requestBuf.Bytes())
	}
	if responseBuf != nil && responseBuf.Len() > 0 {
		entry.Attributes = ensureAttrs(entry.Attributes)
		entry.Attributes["response_excerpt"] = string(responseBuf.Bytes())
	}
	entry.Attributes = ensureAttrs(entry.Attributes)
	entry.Attributes["mitm"] = "enabled"

	if matched := h.profiles.Match(outbound); matched != nil {
		entry.Profile = matched.Name()
		if attrs := matched.Annotate(outbound, resp); len(attrs) > 0 {
			entry.Attributes = mergeAttrs(entry.Attributes, attrs)
		}
	}

	if err := h.logger.Record(context.Background(), entry); err != nil {
		log.Printf("audit log write failed: %v", err)
	}

	if inbound.Body != nil {
		_ = inbound.Body.Close()
	}
	return nil
}

func (h *handler) writeMitmStatus(clientConn net.Conn, reqID string, start time.Time, inbound *http.Request, targetHost string, status int, message string) error {
	resp := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(message + "\n")),
		ContentLength: int64(len(message) + 1),
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if err := resp.Write(clientConn); err != nil {
		return fmt.Errorf("write mitm status: %w", err)
	}

	entry := audit.Entry{
		Time:      start.UTC(),
		ID:        reqID,
		Conn:      newConnMetadata(inbound, targetHost, "https"),
		Request:   newHTTPRequest(inbound),
		Response:  newHTTPResponse(resp, resp.ContentLength),
		LatencyMS: time.Since(start).Milliseconds(),
		Error:     message,
		Attributes: map[string]any{
			"mitm": "enabled",
		},
	}
	if err := h.logger.Record(context.Background(), entry); err != nil {
		log.Printf("audit log write failed: %v", err)
	}
	return nil
}

func (h *handler) writeMitmError(clientConn net.Conn, reqID string, start time.Time, inbound *http.Request, targetHost string, err error) error {
	return h.writeMitmStatus(clientConn, reqID, start, inbound, targetHost, http.StatusBadGateway, err.Error())
}
