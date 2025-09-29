package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kdhira/audit-proxy/internal/audit"
	"github.com/kdhira/audit-proxy/internal/config"
	"github.com/kdhira/audit-proxy/internal/forward"
	"github.com/kdhira/audit-proxy/internal/mitm"
	"github.com/kdhira/audit-proxy/internal/profiles"
)

// Server owns the HTTP proxy listener and helpers.
type Server struct {
	httpServer *http.Server
	transport  *http.Transport
	handler    *handler
}

// NewServer wires dependencies and returns a ready-to-run proxy server.
func NewServer(cfg config.Config, logger audit.Logger) (*Server, error) {
	if logger == nil {
		return nil, errors.New("logger must not be nil")
	}

	transport := forward.NewTransport()
	profileRegistry, err := profiles.FromNames(cfg.Profiles, cfg.ProfilesConfig)
	if err != nil {
		return nil, err
	}
	mitmManager, err := mitm.NewManager(cfg)
	if err != nil {
		return nil, err
	}
	h := &handler{
		logger:       logger,
		transport:    transport,
		allowHosts:   cfg.AllowHosts,
		filters:      buildFilterChain(cfg),
		profiles:     profileRegistry,
		mitm:         mitmManager,
		excerptLimit: cfg.ExcerptLimit,
		mitmDisabled: cfg.MITMDisableHosts,
	}
	if cfg.ExcerptLimit > 0 {
		h.bufPool = sync.Pool{New: func() any { return audit.NewLimitedBuffer(cfg.ExcerptLimit) }}
	}

	httpSrv := &http.Server{
		Addr:     cfg.Addr,
		Handler:  h,
		ErrorLog: log.New(io.Discard, "", 0),
	}

	return &Server{
		httpServer: httpSrv,
		transport:  transport,
		handler:    h,
	}, nil
}

// ListenAndServe starts the proxy and blocks until it exits.
func (s *Server) ListenAndServe() error {
	if s == nil || s.httpServer == nil {
		return errors.New("server not initialised")
	}
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the proxy server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.httpServer == nil {
		return nil
	}
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
	return s.httpServer.Shutdown(ctx)
}

type handler struct {
	logger       audit.Logger
	transport    *http.Transport
	allowHosts   []string
	requestSeq   uint64
	filters      FilterChain
	profiles     profiles.Registry
	mitm         *mitm.Manager
	excerptLimit int
	mitmDisabled []string
	bufPool      sync.Pool
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}
	h.handleHTTP(w, r)
}

func (h *handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
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

	outbound, targetHost, err := cloneRequest(r)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		h.logError(reqID, start, r, targetHost, "http", err)
		return
	}

	if !h.allowed(targetHost) {
		http.Error(w, "host not allowed", http.StatusForbidden)
		h.logError(reqID, start, r, targetHost, "http", fmt.Errorf("blocked host: %s", targetHost))
		return
	}

	if h.excerptLimit > 0 && outbound.Body != nil && outbound.Body != http.NoBody {
		requestBuf = h.acquireBuffer()
		outbound.Body = audit.NewTeeReadCloser(outbound.Body, requestBuf)
	}

	if err := h.filters.ApplyRequest(outbound); err != nil {
		http.Error(w, "request blocked", http.StatusForbidden)
		h.logError(reqID, start, r, targetHost, outbound.URL.Scheme, fmt.Errorf("request filter rejected: %w", err))
		return
	}

	resp, err := h.transport.RoundTrip(outbound)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		h.logError(reqID, start, r, targetHost, outbound.URL.Scheme, err)
		return
	}
	if h.excerptLimit > 0 && resp.Body != nil {
		responseBuf = h.acquireBuffer()
		resp.Body = audit.NewTeeReadCloser(resp.Body, responseBuf)
	}
	defer resp.Body.Close()

	if err := h.filters.ApplyResponse(resp); err != nil {
		http.Error(w, "response blocked", http.StatusBadGateway)
		h.logError(reqID, start, r, targetHost, outbound.URL.Scheme, fmt.Errorf("response filter rejected: %w", err))
		return
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	bytesCopied, copyErr := copyStream(w, resp.Body)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	if copyErr != nil && !errors.Is(copyErr, context.Canceled) {
		log.Printf("stream copy failed: %v", copyErr)
	}

	latency := time.Since(start)

	entry := audit.Entry{
		Time:      start.UTC(),
		ID:        reqID,
		Conn:      newConnMetadata(r, targetHost, outbound.URL.Scheme),
		Request:   newHTTPRequest(r),
		Response:  newHTTPResponse(resp, bytesCopied),
		LatencyMS: latency.Milliseconds(),
	}
	if requestBuf != nil && requestBuf.Len() > 0 {
		entry.Attributes = ensureAttrs(entry.Attributes)
		entry.Attributes["request_excerpt"] = string(requestBuf.Bytes())
	}
	if responseBuf != nil && responseBuf.Len() > 0 {
		entry.Attributes = ensureAttrs(entry.Attributes)
		entry.Attributes["response_excerpt"] = string(responseBuf.Bytes())
	}
	if h.mitm != nil {
		entry.Attributes = ensureAttrs(entry.Attributes)
		if h.mitmInterceptsHost(targetHost) {
			entry.Attributes["mitm"] = "enabled"
		} else if h.mitm.Enabled() {
			entry.Attributes["mitm"] = "skipped"
		} else {
			entry.Attributes["mitm"] = "disabled"
		}
	}

	if matched := h.profiles.Match(outbound); matched != nil {
		entry.Profile = matched.Name()
		if attrs := matched.Annotate(outbound, resp); len(attrs) > 0 {
			entry.Attributes = mergeAttrs(entry.Attributes, attrs)
		}
	}

	if err := h.logger.Record(context.Background(), entry); err != nil {
		log.Printf("audit log write failed: %v", err)
	}
}

func (h *handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := h.nextID()
	targetHost := r.Host

	if !h.allowed(targetHost) {
		http.Error(w, "host not allowed", http.StatusForbidden)
		h.logError(reqID, start, r, targetHost, "connect", fmt.Errorf("blocked host: %s", targetHost))
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		h.logError(reqID, start, r, targetHost, "connect", errors.New("response writer does not implement hijacker"))
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		h.logError(reqID, start, r, targetHost, "connect", fmt.Errorf("hijack failed: %w", err))
		return
	}

	defer clientConn.Close()

	_, _ = clientBuf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err := clientBuf.Flush(); err != nil {
		h.logError(reqID, start, r, targetHost, "connect", fmt.Errorf("flush failed: %w", err))
		return
	}

	if h.mitmInterceptsHost(targetHost) {
		if err := h.handleMitmTLS(clientConn, r, targetHost); err != nil {
			h.logError(reqID, start, r, targetHost, "mitm", err)
		}
		return
	}

	upstreamConn, err := net.DialTimeout("tcp", targetHost, 10*time.Second)
	if err != nil {
		clientBuf.WriteString("HTTP/1.1 502 Bad Gateway\r\n\r\n")
		clientBuf.Flush()
		h.logError(reqID, start, r, targetHost, "connect", fmt.Errorf("dial failed: %w", err))
		return
	}
	defer upstreamConn.Close()

	transferErr := tunnelConnections(clientBuf, clientConn, upstreamConn)

	latency := time.Since(start)
	entry := audit.Entry{
		Time:      start.UTC(),
		ID:        reqID,
		Conn:      newConnMetadata(r, targetHost, "connect"),
		LatencyMS: latency.Milliseconds(),
	}
	if transferErr != nil && !errors.Is(transferErr, context.Canceled) {
		entry.Error = transferErr.Error()
	}
	if h.mitm != nil {
		if entry.Attributes == nil {
			entry.Attributes = make(map[string]any)
		}
		if h.mitm.Enabled() {
			entry.Attributes["mitm"] = "planned"
		} else {
			entry.Attributes["mitm"] = "disabled"
		}
	}
	if err := h.logger.Record(context.Background(), entry); err != nil {
		log.Printf("audit log write failed: %v", err)
	}
}

func (h *handler) logError(id string, start time.Time, r *http.Request, target string, protocol string, err error) {
	entry := audit.Entry{
		Time: start.UTC(),
		ID:   id,
		Conn: audit.ConnMetadata{
			ClientAddr: audit.ClientAddrFromRequest(r),
			Target:     target,
			Protocol:   protocol,
		},
		Request:   newHTTPRequest(r),
		LatencyMS: time.Since(start).Milliseconds(),
	}
	if err != nil {
		entry.Error = err.Error()
	}
	if logErr := h.logger.Record(context.Background(), entry); logErr != nil {
		log.Printf("audit log write failed: %v", logErr)
	}
}

func (h *handler) allowed(target string) bool {
	if target == "" {
		return false
	}
	if len(h.allowHosts) == 0 {
		return true
	}
	host := target
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(target)
	}
	for _, allowed := range h.allowHosts {
		if allowed == "*" {
			return true
		}
		if strings.EqualFold(allowed, host) {
			return true
		}
	}
	return false
}

func (h *handler) nextID() string {
	seq := atomic.AddUint64(&h.requestSeq, 1)
	return fmt.Sprintf("req-%d", seq)
}

func cloneRequest(r *http.Request) (*http.Request, string, error) {
	if r.URL == nil {
		return nil, "", errors.New("missing url")
	}
	// Clone the request to avoid mutating shared state.
	outbound := r.Clone(r.Context())
	if outbound.URL.Scheme == "" {
		outbound.URL = cloneURL(outbound.URL)
		outbound.URL.Scheme = "http"
	}
	if outbound.URL.Host == "" {
		outbound.URL.Host = r.Host
	}
	outbound.RequestURI = ""
	outbound.Header = cloneHeader(r.Header)
	outbound.Header.Del("Proxy-Connection")
	outbound.Header.Del("Proxy-Authenticate")
	outbound.Header.Del("Proxy-Authorization")
	target := outbound.URL.Host
	return outbound, target, nil
}

func cloneURL(in *url.URL) *url.URL {
	if in == nil {
		return &url.URL{}
	}
	out := *in
	return &out
}

func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return make(http.Header)
	}
	out := make(http.Header, len(h))
	for k, vv := range h {
		dup := make([]string, len(vv))
		copy(dup, vv)
		out[k] = dup
	}
	return out
}

func newConnMetadata(r *http.Request, target, protocol string) audit.ConnMetadata {
	return audit.ConnMetadata{
		ClientAddr: audit.ClientAddrFromRequest(r),
		Target:     target,
		Protocol:   protocol,
	}
}

func newHTTPRequest(r *http.Request) *audit.HTTPRequest {
	if r == nil {
		return nil
	}
	return &audit.HTTPRequest{
		Method:        r.Method,
		URL:           r.URL.String(),
		Header:        audit.SanitiseHeaders(r.Header),
		ContentLength: r.ContentLength,
	}
}

func newHTTPResponse(resp *http.Response, bodyBytes int64) *audit.HTTPResponse {
	if resp == nil {
		return nil
	}
	contentLen := resp.ContentLength
	if contentLen < 0 {
		contentLen = bodyBytes
	}
	return &audit.HTTPResponse{
		Status:        resp.StatusCode,
		Header:        audit.SanitiseHeaders(resp.Header),
		ContentLength: contentLen,
	}
}

func copyStream(dst io.Writer, src io.Reader) (int64, error) {
	if dst == nil || src == nil {
		return 0, errors.New("invalid stream copy parameters")
	}
	copied, err := io.Copy(dst, src)
	return copied, err
}

func copyHeaders(dst, src http.Header) {
	for k := range dst {
		dst.Del(k)
	}
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func buildFilterChain(cfg config.Config) FilterChain {
	if len(cfg.Filters) == 0 {
		return NewFilterChain(BlockHeaderFilter{Header: "X-Audit-Block", Values: []string{"1", "true", "block"}})
	}
	return NewFilterChainFromSpecs(cfg.Filters)
}

func ensureAttrs(attrs map[string]any) map[string]any {
	if attrs == nil {
		return make(map[string]any)
	}
	return attrs
}

func mergeAttrs(base map[string]any, add map[string]any) map[string]any {
	if len(add) == 0 {
		return base
	}
	result := ensureAttrs(base)
	for k, v := range add {
		result[k] = v
	}
	return result
}

func (h *handler) mitmInterceptsHost(target string) bool {
	if h.mitm == nil || !h.mitm.Enabled() {
		return false
	}
	host := target
	if strings.Contains(host, ":") {
		var err error
		host, _, err = net.SplitHostPort(target)
		if err != nil {
			host = target
		}
	}
	for _, dis := range h.mitmDisabled {
		if strings.EqualFold(dis, host) {
			return false
		}
	}
	return true
}

func (h *handler) acquireBuffer() *audit.LimitedBuffer {
	if h.excerptLimit <= 0 {
		return nil
	}
	if buf, ok := h.bufPool.Get().(*audit.LimitedBuffer); ok {
		buf.Reset(h.excerptLimit)
		return buf
	}
	return audit.NewLimitedBuffer(h.excerptLimit)
}

func (h *handler) releaseBuffer(buf *audit.LimitedBuffer) {
	if buf == nil || h.excerptLimit <= 0 {
		return
	}
	buf.Reset(h.excerptLimit)
	h.bufPool.Put(buf)
}
