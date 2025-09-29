package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"math/big"

	"github.com/kdhira/audit-proxy/internal/audit"
	"github.com/kdhira/audit-proxy/internal/config"
)

func TestMITMInterceptsHTTPS(t *testing.T) {
	rootPEM, keyPEM := generateRootPEM(t)
	caFile := writeTempFile(t, "ca.pem", rootPEM)
	keyFile := writeTempFile(t, "ca.key", keyPEM)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("secure"))
	}))
	defer upstream.Close()

	addr := freePort(t)
	logDir := t.TempDir()
	logFile := filepath.Join(logDir, "mitm.jsonl")

	cfg := config.Config{
		Addr:             addr,
		LogFile:          logFile,
		Profiles:         []string{"generic"},
		AllowHosts:       []string{"*"},
		EnableMITM:       true,
		MITMCAPath:       caFile,
		MITMKeyPath:      keyFile,
		ExcerptLimit:     128,
		MITMDisableHosts: nil,
	}

	logger, err := audit.NewFileLogger(logFile)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	defer logger.Close()

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	srv.handler.transport = upstream.Client().Transport.(*http.Transport).Clone()

	serverErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
		close(serverErr)
	}()

	waitForPort(t, addr, 5*time.Second)

	proxyURL, _ := url.Parse("http://" + addr)
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(rootPEM); !ok {
		t.Fatalf("append root cert")
	}
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	for err := range serverErr {
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	}

	verifyLogContainsMITM(t, logFile)
}

func verifyLogContainsMITM(t *testing.T, path string) {
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	found := false
	for scanner.Scan() {
		var entry struct {
			Attributes map[string]any        `json:"attributes"`
			Response   *struct{ Status int } `json:"response"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("unmarshal log: %v", err)
		}
		if entry.Attributes != nil && entry.Attributes["mitm"] == "enabled" {
			if entry.Response == nil || entry.Response.Status != http.StatusOK {
				t.Fatalf("expected status 200 in mitm entry")
			}
			if _, ok := entry.Attributes["response_excerpt"]; !ok {
				t.Fatalf("expected response excerpt in mitm entry")
			}
			found = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan log: %v", err)
	}
	if !found {
		t.Fatalf("did not find mitm enabled entry in log")
	}
}

func generateRootPEM(t *testing.T) ([]byte, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          bigIntOne(),
		Subject:               pkix.Name{CommonName: "audit-proxy-test-root"},
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func writeTempFile(t *testing.T, name string, data []byte) string {
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitForPort(t *testing.T, addr string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %s did not become ready: %v", addr, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func bigIntOne() *big.Int {
	return big.NewInt(1)
}
