package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"crypto/x509/pkix"
)

func TestIssuerIssueCertificate(t *testing.T) {
	rootCert := generateRootCert(t)
	issuer, err := NewIssuer(rootCert)
	if err != nil {
		t.Fatalf("failed to create issuer: %v", err)
	}
	leaf, err := issuer.IssueCertificate("example.com")
	if err != nil {
		t.Fatalf("issue certificate failed: %v", err)
	}
	if leaf == nil || leaf.Leaf == nil {
		t.Fatalf("expected leaf certificate with parsed metadata")
	}
	if got := leaf.Leaf.DNSNames[0]; got != "example.com" {
		t.Fatalf("unexpected dns name: %s", got)
	}
}

func generateRootCert(t *testing.T) *tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "audit-proxy-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	cert.Leaf = leaf
	return cert
}
