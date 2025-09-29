package proxy

import (
	"net/http"
	"testing"

	"github.com/kdhira/audit-proxy/internal/config"
)

func TestBlockHeaderFilter(t *testing.T) {
	filter := BlockHeaderFilter{Header: "X-Audit-Block", Values: []string{"block"}}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Audit-Block", "block")

	if err := filter.ApplyRequest(req); err == nil {
		t.Fatalf("expected filter to block request")
	}

	req.Header.Set("X-Audit-Block", "allow")
	if err := filter.ApplyRequest(req); err != nil {
		t.Fatalf("expected filter to allow request, got %v", err)
	}
}

func TestFilterChain(t *testing.T) {
	chain := NewFilterChain(NoopFilter{}, BlockHeaderFilter{Header: "X-Block", Values: []string{"yes"}})
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Block", "yes")

	if err := chain.ApplyRequest(req); err == nil {
		t.Fatalf("expected chain to block via header filter")
	}

	req.Header.Set("X-Block", "no")
	if err := chain.ApplyRequest(req); err != nil {
		t.Fatalf("unexpected error from chain: %v", err)
	}
}

func TestPathPrefixBlockFilter(t *testing.T) {
	filter := PathPrefixBlockFilter{Prefixes: []string{"/admin", "/internal"}}
	req, _ := http.NewRequest("GET", "http://example.com/admin/dashboard", nil)
	if err := filter.ApplyRequest(req); err == nil {
		t.Fatalf("expected path filter to block request")
	}
	req, _ = http.NewRequest("GET", "http://example.com/public", nil)
	if err := filter.ApplyRequest(req); err != nil {
		t.Fatalf("expected allow for public path: %v", err)
	}
}

func TestPathPrefixAllowFilter(t *testing.T) {
	filter := PathPrefixAllowFilter{Prefixes: []string{"/public", "/status"}}
	req, _ := http.NewRequest("GET", "http://example.com/public/data", nil)
	if err := filter.ApplyRequest(req); err != nil {
		t.Fatalf("expected allow for allowed path: %v", err)
	}
	req, _ = http.NewRequest("GET", "http://example.com/private", nil)
	if err := filter.ApplyRequest(req); err == nil {
		t.Fatalf("expected disallow for private path")
	}
}

func TestNewFilterChainFromSpecs(t *testing.T) {
	specs := []config.FilterSpec{
		{Type: "header-block", Header: "X-Audit-Block", Values: []string{"block"}},
		{Type: "path-prefix-block", Values: []string{"/secret"}},
		{Type: "path-prefix-allow", Values: []string{"/public"}},
	}
	chain := NewFilterChainFromSpecs(specs)
	req, _ := http.NewRequest("GET", "http://example.com/secret/data", nil)
	req.Header.Set("X-Audit-Block", "allow")
	if err := chain.ApplyRequest(req); err == nil {
		t.Fatalf("expected path filter to block request")
	}
	req, _ = http.NewRequest("GET", "http://example.com/public/info", nil)
	if err := chain.ApplyRequest(req); err != nil {
		t.Fatalf("expected allow for whitelisted path: %v", err)
	}
}
