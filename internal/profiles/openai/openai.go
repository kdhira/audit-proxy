package openai

import (
	"net/http"
	"net/url"
	"strings"
)

// Profile detects basic OpenAI API traffic for future enrichment.
type Profile struct {
	redactSystemPrompt bool
}

// New returns a stub OpenAI profile.
func New() *Profile { return &Profile{} }

// NewWithOptions allows configuring OpenAI profile behaviour via arbitrary map inputs.
func NewWithOptions(opts map[string]any) *Profile {
	p := &Profile{}
	if opts == nil {
		return p
	}
	if val, ok := opts["redact_system_prompt"].(bool); ok {
		p.redactSystemPrompt = val
	}
	return p
}

func (p *Profile) Name() string { return "openai" }

func (p *Profile) Match(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	return strings.Contains(host, "openai")
}

func (p *Profile) Annotate(req *http.Request, resp *http.Response) map[string]any {
	attrs := make(map[string]any)

	if req != nil {
		if endpoint := reqURLPath(req.URL); endpoint != "" {
			attrs["endpoint"] = endpoint
			if op := operationForPath(endpoint); op != "" {
				attrs["operation"] = op
			}
		}
		if host := hostFromRequest(req); host != "" {
			attrs["target_host"] = host
		}
		if stream := inferStreamHint(req); stream {
			attrs["stream"] = true
		}
		if v := req.Header.Get("OpenAI-Organization"); v != "" {
			attrs["organization"] = maskIdentifier(v)
		}
		if v := req.Header.Get("OpenAI-Project"); v != "" {
			attrs["project"] = maskIdentifier(v)
		}
		if v := req.Header.Get("OpenAI-Model"); v != "" {
			attrs["model_hint"] = v
		}
	}

	if resp != nil {
		if v := resp.Header.Get("X-Request-Id"); v != "" {
			attrs["request_id"] = v
		}
		if v := resp.Header.Get("OpenAI-Processing-Ms"); v != "" {
			attrs["processing_ms"] = v
		}
		if v := resp.Header.Get("OpenAI-Organization"); v != "" {
			attrs["organization"] = maskIdentifier(v)
		}
	}

	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

func reqURLPath(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Path
}

func hostFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if r.URL != nil && r.URL.Host != "" {
		return r.URL.Host
	}
	return r.Host
}

func inferStreamHint(r *http.Request) bool {
	if r == nil {
		return false
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream") {
		return true
	}
	if r.URL != nil {
		query := r.URL.Query()
		if val := strings.ToLower(query.Get("stream")); val == "true" || val == "1" {
			return true
		}
	}
	return false
}

func operationForPath(path string) string {
	switch {
	case strings.HasPrefix(path, "/v1/chat/completions"):
		return "chat.completions"
	case strings.HasPrefix(path, "/v1/completions"):
		return "completions"
	case strings.HasPrefix(path, "/v1/responses"):
		return "responses"
	case strings.HasPrefix(path, "/v1/audio/transcriptions"):
		return "audio.transcriptions"
	case strings.HasPrefix(path, "/v1/audio/translations"):
		return "audio.translations"
	default:
		return ""
	}
}

func maskIdentifier(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 4 {
		return "***"
	}
	if len(v) <= 8 {
		return v[:2] + "***" + v[len(v)-2:]
	}
	return v[:3] + "***" + v[len(v)-3:]
}
