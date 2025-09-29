package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileYAMLAndMerge(t *testing.T) {
	path := writeTempFile(t, "config.yaml", `addr: 0.0.0.0:9000
log_file: logs/custom.jsonl
profiles: [generic, openai]
mitm: true
mitm_ca: ca.pem
mitm_key: ca.key
excerpt_limit: 1024
mitm_disable_hosts: [api.openai.com]
filters:
  - name: block-header
    type: header-block
    header: X-Test
    values: [block]
`)
	fc, err := LoadFile(path)
	if err != nil {
		t.Fatalf("load file: %v", err)
	}
	base := Config{Addr: "127.0.0.1:8080", Profiles: []string{"generic"}, AllowHosts: []string{"*"}, ExcerptLimit: 4096}
	merged := Merge(base, fc)
	if merged.Addr != "0.0.0.0:9000" {
		t.Fatalf("addr merge failed")
	}
	if merged.ExcerptLimit != 1024 {
		t.Fatalf("excerpt merge failed")
	}
	if !merged.EnableMITM {
		t.Fatalf("mitm flag merge failed")
	}
	if len(merged.MITMDisableHosts) != 1 {
		t.Fatalf("disable hosts merge failed")
	}
    if len(merged.Filters) != 1 || merged.Filters[0].Header != "X-Test" {
        t.Fatalf("filters merge failed")
    }
}

func TestLoadFileJSON(t *testing.T) {
	path := writeTempFile(t, "config.json", `{"addr":"127.0.0.1:7000","profiles":["generic"]}`)
	fc, err := LoadFile(path)
	if err != nil {
		t.Fatalf("load json: %v", err)
	}
	if fc.Addr != "127.0.0.1:7000" {
		t.Fatalf("addr mismatch")
	}
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
