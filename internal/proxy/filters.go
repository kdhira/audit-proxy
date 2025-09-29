package proxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/kdhira/audit-proxy/internal/config"
)

// Filter allows custom policy checks on proxied traffic.
type Filter interface {
	ApplyRequest(*http.Request) error
	ApplyResponse(*http.Response) error
}

// FilterChain executes a collection of filters sequentially.
type FilterChain struct {
	filters []Filter
}

// NewFilterChain creates a composed filter chain from provided implementations.
func NewFilterChain(filters ...Filter) FilterChain {
	return FilterChain{filters: filters}
}

// NewFilterChainFromSpecs constructs a chain based on configuration specs.
func NewFilterChainFromSpecs(specs []config.FilterSpec) FilterChain {
	if len(specs) == 0 {
		return NewFilterChain(NoopFilter{})
	}
	filters := make([]Filter, 0, len(specs))
	for _, spec := range specs {
		switch spec.Type {
		case "header-block":
			head := spec.Header
			if head == "" {
				continue
			}
			filters = append(filters, BlockHeaderFilter{Header: head, Values: spec.Values})
		case "path-prefix-block":
			if len(spec.Values) == 0 {
				continue
			}
			filters = append(filters, PathPrefixBlockFilter{Prefixes: spec.Values})
		case "path-prefix-allow":
			if len(spec.Values) == 0 {
				continue
			}
			filters = append(filters, PathPrefixAllowFilter{Prefixes: spec.Values})
		default:
			filters = append(filters, NoopFilter{})
		}
	}
	if len(filters) == 0 {
		filters = append(filters, NoopFilter{})
	}
	return NewFilterChain(filters...)
}

// ApplyRequest runs request filters until one fails.
func (c FilterChain) ApplyRequest(r *http.Request) error {
	for _, f := range c.filters {
		if err := f.ApplyRequest(r); err != nil {
			return err
		}
	}
	return nil
}

// ApplyResponse runs response filters until one fails.
func (c FilterChain) ApplyResponse(resp *http.Response) error {
	for _, f := range c.filters {
		if err := f.ApplyResponse(resp); err != nil {
			return err
		}
	}
	return nil
}

// NoopFilter is a convenience filter that performs no action.
type NoopFilter struct{}

func (NoopFilter) ApplyRequest(*http.Request) error   { return nil }
func (NoopFilter) ApplyResponse(*http.Response) error { return nil }

// BlockHeaderFilter rejects requests when a specific header equals one of the denied values.
type BlockHeaderFilter struct {
	Header string
	Values []string
}

func (f BlockHeaderFilter) ApplyRequest(r *http.Request) error {
	if r == nil {
		return nil
	}
	value := r.Header.Get(f.Header)
	if value == "" {
		return nil
	}
	for _, denied := range f.Values {
		if strings.EqualFold(value, denied) {
			return fmt.Errorf("blocked by header filter: %s=%s", f.Header, value)
		}
	}
	return nil
}

func (BlockHeaderFilter) ApplyResponse(*http.Response) error { return nil }

// PathPrefixBlockFilter rejects requests whose URL path matches specified prefixes.
type PathPrefixBlockFilter struct {
	Prefixes []string
}

func (f PathPrefixBlockFilter) ApplyRequest(r *http.Request) error {
	if r == nil || len(f.Prefixes) == 0 {
		return nil
	}
	path := r.URL.Path
	for _, prefix := range f.Prefixes {
		if strings.HasPrefix(path, prefix) {
			return fmt.Errorf("blocked by path filter: %s", prefix)
		}
	}
	return nil
}

func (PathPrefixBlockFilter) ApplyResponse(*http.Response) error { return nil }

// PathPrefixAllowFilter rejects requests whose path does NOT match an allowed prefix.
type PathPrefixAllowFilter struct {
	Prefixes []string
}

func (f PathPrefixAllowFilter) ApplyRequest(r *http.Request) error {
	if r == nil || len(f.Prefixes) == 0 {
		return nil
	}
	path := r.URL.Path
	for _, prefix := range f.Prefixes {
		if strings.HasPrefix(path, prefix) {
			return nil
		}
	}
	return fmt.Errorf("request path %q not in allowed prefixes", path)
}

func (PathPrefixAllowFilter) ApplyResponse(*http.Response) error { return nil }
