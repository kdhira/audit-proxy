package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kdhira/audit-proxy/internal/config"
)

// Manager coordinates optional MITM interception using a provided root CA.
type Manager struct {
	enabled bool
	cert    *tls.Certificate
	caPool  *x509.CertPool
	issuer  *Issuer
	leafTTL time.Duration
	mu      sync.Mutex
	cache   map[string]cachedCert
}

type cachedCert struct {
	cert    *tls.Certificate
	expires time.Time
}

const defaultLeafTTL = 6 * time.Hour

// NewManager initialises MITM state based on configuration.
func NewManager(cfg config.Config) (*Manager, error) {
	mgr := &Manager{leafTTL: defaultLeafTTL, cache: make(map[string]cachedCert)}
	if !cfg.EnableMITM {
		return mgr, nil
	}
	if cfg.MITMCAPath == "" || cfg.MITMKeyPath == "" {
		return nil, fmt.Errorf("mitm enabled but ca/key paths missing")
	}
	cert, err := tls.LoadX509KeyPair(cfg.MITMCAPath, cfg.MITMKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading mitm keypair: %w", err)
	}
	caBytes, err := os.ReadFile(cfg.MITMCAPath)
	if err != nil {
		return nil, fmt.Errorf("reading mitm ca: %w", err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caBytes); !ok {
		return nil, fmt.Errorf("failed to append mitm ca to pool")
	}
	mgr.enabled = true
	mgr.cert = &cert
	mgr.caPool = pool
	issuer, err := NewIssuer(&cert)
	if err != nil {
		return nil, err
	}
	mgr.issuer = issuer
	return mgr, nil
}

// Enabled returns whether MITM interception is active.
func (m *Manager) Enabled() bool {
	if m == nil {
		return false
	}
	return m.enabled
}

// Certificate exposes the root CA for certificate generation workflows.
func (m *Manager) Certificate() *tls.Certificate {
	return m.cert
}

// Pool returns the CA pool usable for client trust.
func (m *Manager) Pool() *x509.CertPool {
	return m.caPool
}

// Issuer exposes the certificate generator for per-host certs.
func (m *Manager) Issuer() *Issuer {
	return m.issuer
}

// LeafForHost returns a leaf certificate for the provided host, using a cache to avoid
// regenerating certificates on every CONNECT handshake.
func (m *Manager) LeafForHost(host string) (*tls.Certificate, error) {
	if !m.Enabled() {
		return nil, fmt.Errorf("mitm disabled")
	}
	cleanHost := strings.ToLower(host)
	now := time.Now()
	m.mu.Lock()
	if cached, ok := m.cache[cleanHost]; ok && now.Before(cached.expires) {
		cert := cached.cert
		m.mu.Unlock()
		return cert, nil
	}
	m.mu.Unlock()

	leaf, err := m.issuer.IssueCertificate(cleanHost)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.cache[cleanHost] = cachedCert{cert: leaf, expires: now.Add(m.leafTTL)}
	m.mu.Unlock()
	return leaf, nil
}

// Wrap will eventually terminate TLS and return a decrypted connection.
// For v0.2 planning this is a stub that signals unimplemented behaviour.
func (m *Manager) Wrap() error {
	if !m.Enabled() {
		return nil
	}
	return fmt.Errorf("mitm wrap not yet implemented")
}
