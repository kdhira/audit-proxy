package profiles

import (
	"net/http"
	"testing"
)

func TestFromNamesWithConfig(t *testing.T) {
	reg, err := FromNames([]string{"openai"}, map[string]map[string]any{
		"openai": {"redact_system_prompt": true},
	})
	if err != nil {
		t.Fatalf("from names: %v", err)
	}
	req, _ := http.NewRequest("GET", "https://api.openai.com/v1/chat/completions", nil)
	prof := reg.Match(req)
	if prof == nil {
		t.Fatalf("expected to match openai profile")
	}
	if attrs := prof.Annotate(nil, nil); attrs != nil {
		t.Fatalf("expected nil attributes without request/response context")
	}
}
