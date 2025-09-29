package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// Config represents the runtime options used to start the proxy.
type Config struct {
	Addr             string
	LogFile          string
	Profiles         []string
	AllowHosts       []string
	EnableMITM       bool
	MITMCAPath       string
	MITMKeyPath      string
	ExcerptLimit     int
	MITMDisableHosts []string
	Filters          []FilterSpec
	ProfilesConfig   map[string]map[string]any
}

// FilterSpec describes filter configuration entries parsed from files.
type FilterSpec struct {
	Name   string   `json:"name" yaml:"name"`
	Type   string   `json:"type" yaml:"type"`
	Header string   `json:"header" yaml:"header"`
	Values []string `json:"values" yaml:"values"`
}

// MustParseFlags reads configuration from CLI flags and terminates the process
// if parsing fails. Prefer ParseFlags when callers want explicit error handling.
func MustParseFlags(baseSet *flag.FlagSet, args []string) Config {
	cfg, err := ParseFlags(baseSet, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "failed to parse flags: %v\n", err)
		os.Exit(2)
	}
	return cfg
}

// ParseFlags reads supported CLI flags into a Config value.
func ParseFlags(baseSet *flag.FlagSet, args []string) (Config, error) {
	fs := flag.NewFlagSet("audit-proxy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		addr        = fs.String("addr", "127.0.0.1:8080", "address the proxy listens on")
		logFile     = fs.String("log-file", "logs/audit.jsonl", "path to the JSONL log file")
		profilesStr = fs.String("profiles", "generic", "comma-separated list of profile names to enable")
		allowHosts  = fs.String("allow-hosts", "*", "comma-separated allowlist of upstream hosts (\"*\" allows all)")
		mitm        = fs.Bool("mitm", false, "enable MITM interception")
		mitmCA      = fs.String("mitm-ca", "", "path to the MITM root CA certificate")
		mitmKey     = fs.String("mitm-key", "", "path to the MITM root CA private key")
		excerpt     = fs.Int("excerpt-limit", 4096, "maximum bytes captured for request/response excerpts (0 disables)")
		mitmSkip    = fs.String("mitm-disable-hosts", "", "comma-separated list of hosts to bypass MITM even when enabled")
	)

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg := Config{
		Addr:             *addr,
		LogFile:          *logFile,
		Profiles:         normaliseList(*profilesStr),
		AllowHosts:       normaliseList(*allowHosts),
		EnableMITM:       *mitm,
		MITMCAPath:       *mitmCA,
		MITMKeyPath:      *mitmKey,
		ExcerptLimit:     *excerpt,
		MITMDisableHosts: normaliseList(*mitmSkip),
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// Validate ensures the configuration is internally consistent.
func (c Config) Validate() error {
	if c.Addr == "" {
		return errors.New("addr must not be empty")
	}
	if len(c.Profiles) == 0 {
		return errors.New("at least one profile must be specified")
	}
	if c.ExcerptLimit < 0 {
		return errors.New("excerpt limit must be zero or positive")
	}
	if c.EnableMITM {
		if c.MITMCAPath == "" || c.MITMKeyPath == "" {
			return errors.New("mitm enabled but ca/key paths not provided")
		}
	}
	if err := c.validateFilters(); err != nil {
		return err
	}
	return nil
}

func (c Config) validateFilters() error {
	for _, f := range c.Filters {
		switch f.Type {
		case "header-block":
			if f.Header == "" {
				return fmt.Errorf("filter %q missing header", f.Name)
			}
		case "path-prefix-block":
			if len(f.Values) == 0 {
				return fmt.Errorf("filter %q requires at least one prefix value", f.Name)
			}
		case "path-prefix-allow":
			if len(f.Values) == 0 {
				return fmt.Errorf("filter %q requires at least one allow prefix", f.Name)
			}
		default:
			return fmt.Errorf("unknown filter type: %s", f.Type)
		}
	}
	return nil
}


func normaliseList(s string) []string {
	if s == "" {
		return nil
	}
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
