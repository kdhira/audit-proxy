package openai

import (
	"net/http"
	"testing"
)

func TestAnnotateExtractsAttributes(t *testing.T) {
	profile := New()
	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions?stream=true", nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("OpenAI-Organization", "org-123456")
	req.Header.Set("OpenAI-Project", "proj-987654")
	req.Header.Set("OpenAI-Model", "gpt-4.1-mini")

	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("X-Request-Id", "req-abc")
	resp.Header.Set("OpenAI-Processing-Ms", "345")

	attrs := profile.Annotate(req, resp)
	if attrs == nil {
		t.Fatalf("expected attributes map")
	}

	if got, want := attrs["endpoint"], "/v1/chat/completions"; got != want {
		t.Fatalf("endpoint mismatch: got %v want %v", got, want)
	}
	if got, want := attrs["operation"], "chat.completions"; got != want {
		t.Fatalf("operation mismatch: got %v want %v", got, want)
	}
	if got, want := attrs["target_host"], "api.openai.com"; got != want {
		t.Fatalf("host mismatch: got %v want %v", got, want)
	}
	if got, want := attrs["stream"], true; got != want {
		t.Fatalf("expected stream hint true, got %v", got)
	}
	if got, want := attrs["organization"], "org***456"; got != want {
		t.Fatalf("organization masking mismatch: got %v want %v", got, want)
	}
	if got, want := attrs["project"], "pro***654"; got != want {
		t.Fatalf("project masking mismatch: got %v want %v", got, want)
	}
	if got, want := attrs["model_hint"], "gpt-4.1-mini"; got != want {
		t.Fatalf("model hint mismatch: got %v want %v", got, want)
	}
	if got, want := attrs["request_id"], "req-abc"; got != want {
		t.Fatalf("request id mismatch: got %v want %v", got, want)
	}
	if got, want := attrs["processing_ms"], "345"; got != want {
		t.Fatalf("processing ms mismatch: got %v want %v", got, want)
	}
}

func TestAnnotateNilInputs(t *testing.T) {
	profile := New()
	if attrs := profile.Annotate(nil, nil); attrs != nil {
		t.Fatalf("expected nil attributes for empty input")
	}
}
