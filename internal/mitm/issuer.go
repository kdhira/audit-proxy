package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// Issuer mints per-host certificates signed by the configured root CA.
type Issuer struct {
	root *tls.Certificate
	mu   sync.Mutex
}

// NewIssuer derives an issuer from the root certificate used for MITM.
func NewIssuer(root *tls.Certificate) (*Issuer, error) {
	if root == nil {
		return nil, fmt.Errorf("issuer requires root certificate")
	}
	if root.PrivateKey == nil {
		return nil, fmt.Errorf("root certificate is missing private key")
	}
	if root.Leaf == nil {
		cert, err := x509.ParseCertificate(root.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parsing root certificate: %w", err)
		}
		root.Leaf = cert
	}
	return &Issuer{root: root}, nil
}

// IssueCertificate generates a certificate for the provided host.
func (i *Issuer) IssueCertificate(host string) (*tls.Certificate, error) {
	if i == nil {
		return nil, fmt.Errorf("issuer not initialised")
	}
	if host == "" {
		return nil, fmt.Errorf("host must not be empty")
	}

	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      i.root.Leaf.Subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := parseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating leaf key: %w", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, i.root.Leaf, &privKey.PublicKey, i.root.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes, i.root.Certificate[0]},
		PrivateKey:  privKey,
	}
	if leaf, err := x509.ParseCertificate(derBytes); err == nil {
		cert.Leaf = leaf
	}
	return cert, nil
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

func parseIP(host string) net.IP {
	return net.ParseIP(host)
}
