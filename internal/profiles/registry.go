package profiles

import (
	"fmt"
	"net/http"

	"github.com/kdhira/audit-proxy/internal/profiles/generic"
	"github.com/kdhira/audit-proxy/internal/profiles/openai"
)

// Profile defines hooks for extracting domain-specific metadata.
type Profile interface {
	Name() string
	Match(*http.Request) bool
	// Annotate allows profiles to enrich an audit entry. Returning nil leaves it unchanged.
	Annotate(*http.Request, *http.Response) map[string]any
}

// Registry stores enabled profiles keyed by name.
type Registry struct {
	profiles map[string]Profile
	ordered  []Profile
}

// NewRegistry registers the provided profile implementations.
func NewRegistry(enabled []Profile) Registry {
	reg := Registry{profiles: make(map[string]Profile, len(enabled))}
	for _, p := range enabled {
		if p == nil {
			continue
		}
		reg.profiles[p.Name()] = p
		reg.ordered = append(reg.ordered, p)
	}
	return reg
}

// Enabled returns the list of registered profile names.
func (r Registry) Enabled() []string {
	names := make([]string, 0, len(r.ordered))
	for _, profile := range r.ordered {
		names = append(names, profile.Name())
	}
	return names
}

// Match attempts to find the first profile that matches the request.
func (r Registry) Match(req *http.Request) Profile {
	for _, profile := range r.ordered {
		if profile.Match(req) {
			return profile
		}
	}
	return nil
}

// FromNames constructs a registry populated with known profile implementations using optional per-profile configuration.
func FromNames(names []string, profileCfg map[string]map[string]any) (Registry, error) {
	if len(names) == 0 {
		names = []string{"generic"}
	}
	registry := NewRegistry(nil)
	for _, name := range names {
		factory, ok := defaultFactories[name]
		if !ok {
			return Registry{}, fmt.Errorf("unknown profile: %s", name)
		}
		profile := factory(profileCfg[name])
		registry.profiles[profile.Name()] = profile
		registry.ordered = append(registry.ordered, profile)
	}
	return registry, nil
}

type factory func(options map[string]any) Profile

var defaultFactories = map[string]factory{
	"generic": func(options map[string]any) Profile { return generic.New() },
	"openai": func(options map[string]any) Profile { return openai.NewWithOptions(options) },
}
