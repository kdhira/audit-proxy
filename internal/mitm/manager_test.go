package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestLeafForHostCaching(t *testing.T) {
	root := generateTestRootCert(t)
	issuer, err := NewIssuer(root)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	mgr := &Manager{
		enabled: true,
		cert:    root,
		issuer:  issuer,
		leafTTL: 50 * time.Millisecond,
		cache:   make(map[string]cachedCert),
	}

	first, err := mgr.LeafForHost("example.com")
	if err != nil {
		t.Fatalf("leaf1: %v", err)
	}
	if got := len(mgr.cache); got != 1 {
		t.Fatalf("expected cache size 1 after first cert, got %d", got)
	}

	second, err := mgr.LeafForHost("example.com")
	if err != nil {
		t.Fatalf("leaf2: %v", err)
	}
	if first == nil || second == nil {
		t.Fatalf("expected non-nil certificates")
	}
	if got := len(mgr.cache); got != 1 {
		t.Fatalf("expected cache reuse without growing, size %d", got)
	}

	time.Sleep(60 * time.Millisecond)
	third, err := mgr.LeafForHost("example.com")
	if err != nil {
		t.Fatalf("leaf3: %v", err)
	}
	if third == first {
		t.Fatalf("expected cache rotation after ttl")
	}
}

func generateTestRootCert(t *testing.T) *tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          bigIntOne(),
		Subject:               pkix.Name{CommonName: "audit-proxy-mitm-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	cert.Leaf = leaf
	return cert
}

func bigIntOne() *big.Int {
	return big.NewInt(1)
}
