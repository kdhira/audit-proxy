package audit

import (
	"net/http"
	"strings"
)

var sensitiveHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"x-api-key":           {},
	"api-key":             {},
	"apikey":              {},
	"x-auth-token":        {},
	"x-openai-api-key":    {},
	"openai-organization": {},
}

// SanitiseHeaders returns a copy of headers suitable for structured logs.
func SanitiseHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vv := range h {
		canonical := strings.ToLower(k)
		if _, ok := sensitiveHeaders[canonical]; ok {
			out[k] = redactValues(vv)
			continue
		}
		out[k] = strings.Join(vv, ", ")
	}
	return out
}

func redactValues(values []string) string {
	if len(values) == 0 {
		return ""
	}
	masked := make([]string, len(values))
	for i, v := range values {
		masked[i] = maskToken(v)
	}
	return strings.Join(masked, ", ")
}

func maskToken(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	parts := strings.SplitN(v, " ", 2)
	if len(parts) == 2 {
		return parts[0] + " " + maskCore(parts[1])
	}
	return maskCore(v)
}

func maskCore(v string) string {
	if len(v) <= 4 {
		return "***"
	}
	return v[:2] + "***" + v[len(v)-2:]
}
