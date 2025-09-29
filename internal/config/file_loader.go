package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileConfig represents the subset of configuration that can be provided via file.
type FileConfig struct {
	Addr             string                       `json:"addr" yaml:"addr"`
	LogFile          string                       `json:"log_file" yaml:"log_file"`
	Profiles         []string                     `json:"profiles" yaml:"profiles"`
	AllowHosts       []string                     `json:"allow_hosts" yaml:"allow_hosts"`
	EnableMITM       *bool                        `json:"mitm" yaml:"mitm"`
	MITMCAPath       string                       `json:"mitm_ca" yaml:"mitm_ca"`
	MITMKeyPath      string                       `json:"mitm_key" yaml:"mitm_key"`
	ExcerptLimit     *int                         `json:"excerpt_limit" yaml:"excerpt_limit"`
	MITMDisableHosts []string                     `json:"mitm_disable_hosts" yaml:"mitm_disable_hosts"`
	Filters          []FilterSpec                 `json:"filters" yaml:"filters"`
	ProfilesConfig   map[string]map[string]any    `json:"profiles_config" yaml:"profiles_config"`
}

// LoadFile parses configuration from the provided file path.
func LoadFile(path string) (FileConfig, error) {
	if path == "" {
		return FileConfig{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return FileConfig{}, fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return FileConfig{}, fmt.Errorf("read config file: %w", err)
	}

	fc := FileConfig{}
	switch detectFormat(path, data) {
	case "yaml":
		err = yaml.Unmarshal(data, &fc)
	case "json":
		err = json.Unmarshal(data, &fc)
	default:
		err = errors.New("unsupported config format (use .json, .yml, or .yaml)")
	}
	if err != nil {
		return FileConfig{}, err
	}

	return fc, nil
}

// Merge overlays file configuration on top of the base Config parsed from flags/env.
func Merge(base Config, fc FileConfig) Config {
	if fc.Addr != "" {
		base.Addr = fc.Addr
	}
	if fc.LogFile != "" {
		base.LogFile = fc.LogFile
	}
	if len(fc.Profiles) > 0 {
		base.Profiles = fc.Profiles
	}
	if len(fc.AllowHosts) > 0 {
		base.AllowHosts = fc.AllowHosts
	}
	if fc.EnableMITM != nil {
		base.EnableMITM = *fc.EnableMITM
	}
	if fc.MITMCAPath != "" {
		base.MITMCAPath = fc.MITMCAPath
	}
	if fc.MITMKeyPath != "" {
		base.MITMKeyPath = fc.MITMKeyPath
	}
	if fc.ExcerptLimit != nil {
		base.ExcerptLimit = *fc.ExcerptLimit
	}
	if len(fc.MITMDisableHosts) > 0 {
		base.MITMDisableHosts = fc.MITMDisableHosts
	}
	if len(fc.Filters) > 0 {
		base.Filters = fc.Filters
	}
	if len(fc.ProfilesConfig) > 0 {
		if base.ProfilesConfig == nil {
			base.ProfilesConfig = make(map[string]map[string]any)
		}
		for name, cfg := range fc.ProfilesConfig {
			base.ProfilesConfig[name] = cfg
		}
	}
	return base
}

func detectFormat(path string, data []byte) string {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
		return "yaml"
	}
	if strings.HasSuffix(lower, ".json") {
		return "json"
	}
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		return "json"
	}
	return "yaml"
}
