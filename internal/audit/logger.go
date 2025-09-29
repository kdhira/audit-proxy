package audit

import (
	"context"
	"net"
	"net/http"
	"time"
)

// Entry captures a single proxy interaction for JSONL emission.
type Entry struct {
	Time       time.Time      `json:"time"`
	ID         string         `json:"id,omitempty"`
	Conn       ConnMetadata   `json:"conn"`
	Request    *HTTPRequest   `json:"request,omitempty"`
	Response   *HTTPResponse  `json:"response,omitempty"`
	LatencyMS  int64          `json:"latency_ms,omitempty"`
	Profile    string         `json:"profile,omitempty"`
	Error      string         `json:"error,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// ConnMetadata describes inbound client and upstream target information.
type ConnMetadata struct {
	ClientAddr string `json:"client_addr,omitempty"`
	Target     string `json:"target"`
	Protocol   string `json:"protocol"`
}

// HTTPRequest summarises the audited request without body payloads.
type HTTPRequest struct {
	Method        string            `json:"method"`
	URL           string            `json:"url"`
	Header        map[string]string `json:"headers,omitempty"`
	ContentLength int64             `json:"content_length,omitempty"`
}

// HTTPResponse summarises the audited response.
type HTTPResponse struct {
	Status        int               `json:"status"`
	Header        map[string]string `json:"headers,omitempty"`
	ContentLength int64             `json:"content_length,omitempty"`
}

// Logger consumes audit entries for persistence.
type Logger interface {
	Record(context.Context, Entry) error
	Close() error
}

// ClientAddrFromRequest extracts the best effort client IP string.
func ClientAddrFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
