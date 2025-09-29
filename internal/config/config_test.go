package config

import "testing"

func TestParseFlagsDefaults(t *testing.T) {
	cfg, err := ParseFlags(nil, []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Addr != "127.0.0.1:8080" {
		t.Errorf("expected default addr, got %s", cfg.Addr)
	}
	if len(cfg.Profiles) != 1 || cfg.Profiles[0] != "generic" {
		t.Fatalf("expected default profile generic, got %#v", cfg.Profiles)
	}
	if cfg.ExcerptLimit != 4096 {
		t.Fatalf("expected default excerpt limit 4096, got %d", cfg.ExcerptLimit)
	}
}

func TestParseFlagsMITMValidation(t *testing.T) {
	_, err := ParseFlags(nil, []string{"--mitm"})
	if err == nil {
		t.Fatalf("expected error when enabling mitm without paths")
	}
}

func TestParseFlagsAllowHosts(t *testing.T) {
	cfg, err := ParseFlags(nil, []string{"--allow-hosts", "example.com , api.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := len(cfg.AllowHosts), 2; got != want {
		t.Fatalf("expected %d hosts, got %d", want, got)
	}
	if cfg.AllowHosts[0] != "example.com" || cfg.AllowHosts[1] != "api.example.com" {
		t.Fatalf("unexpected allow hosts: %#v", cfg.AllowHosts)
	}
}

func TestParseFlagsExcerptLimitAndMitmSkip(t *testing.T) {
	cfg, err := ParseFlags(nil, []string{"--excerpt-limit", "1024", "--mitm-disable-hosts", "api.openai.com, example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ExcerptLimit != 1024 {
		t.Fatalf("expected excerpt limit 1024, got %d", cfg.ExcerptLimit)
	}
	if got := len(cfg.MITMDisableHosts); got != 2 {
		t.Fatalf("expected two mitm disable hosts, got %d", got)
	}
}

func TestValidateExcerptLimit(t *testing.T) {
	cfg := Config{Addr: "127.0.0.1:8080", Profiles: []string{"generic"}, ExcerptLimit: -1}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for negative excerpt limit")
	}
}

func TestValidateFilters(t *testing.T) {
	cfg := Config{
		Addr:     "127.0.0.1:8080",
		Profiles: []string{"generic"},
		Filters:  []FilterSpec{{Name: "bad", Type: "header-block"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for missing header")
	}
	cfg.Filters = []FilterSpec{{Type: "path-prefix-allow", Values: []string{"/"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateProfilesConfig(t *testing.T) {
	cfg := Config{
		Addr:           "127.0.0.1:8080",
		Profiles:       []string{"openai"},
		ProfilesConfig: map[string]map[string]any{"openai": {"unused": true}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
