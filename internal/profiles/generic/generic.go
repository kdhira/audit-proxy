package generic

import "net/http"

// Profile is a no-op implementation that always matches.
type Profile struct{}

// New returns a generic profile instance.
func New() *Profile { return &Profile{} }

func (Profile) Name() string { return "generic" }

func (Profile) Match(*http.Request) bool { return true }

func (Profile) Annotate(*http.Request, *http.Response) map[string]any { return nil }
