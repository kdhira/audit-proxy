package audit

import (
	"net/http"
	"testing"
)

func TestSanitiseHeaders(t *testing.T) {
	input := http.Header{
		"Authorization":       []string{"Bearer sk-secret"},
		"X-Api-Key":           []string{"abc123456"},
		"Content-Type":        []string{"application/json"},
		"X-Custom-Multi":      []string{"one", "two"},
		"Proxy-Authorization": []string{"Basic foo"},
	}

	out := SanitiseHeaders(input)

	if got := out["Authorization"]; got != "Bearer sk***et" {
		t.Fatalf("expected bearer token masking, got %q", got)
	}
	if got := out["X-Api-Key"]; got != "ab***56" {
		t.Fatalf("expected API key masking, got %q", got)
	}
	if got := out["Content-Type"]; got != "application/json" {
		t.Fatalf("expected content type unchanged, got %q", got)
	}
	if got := out["X-Custom-Multi"]; got != "one, two" {
		t.Fatalf("expected multi-value join, got %q", got)
	}
	if got := out["Proxy-Authorization"]; got != "Basic ***" {
		t.Fatalf("expected proxy authorization masked, got %q", got)
	}
}

func TestMaskCoreShort(t *testing.T) {
	if got := maskCore("abc"); got != "***" {
		t.Fatalf("expected short values masked to ***; got %q", got)
	}
}
