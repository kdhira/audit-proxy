package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"time"

	"github.com/kdhira/audit-proxy/internal/audit"
	"github.com/kdhira/audit-proxy/internal/config"
	"github.com/kdhira/audit-proxy/internal/proxy"
)

func main() {
	logFile := flag.String("log-file", "logs/smoke.jsonl", "path to write JSONL audit output")
	addr := flag.String("addr", "127.0.0.1:18080", "listen address for the probe proxy")
	flag.Parse()

	if err := os.MkdirAll("logs", 0o755); err != nil {
		log.Fatalf("failed creating logs dir: %v", err)
	}
	if err := os.RemoveAll(*logFile); err != nil && !os.IsNotExist(err) {
		log.Fatalf("failed to clean log file: %v", err)
	}

	upstreamHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Smoke", "http")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstreamHTTP.Close()

	upstreamHTTPS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Smoke", "https")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("secure"))
	}))
	defer upstreamHTTPS.Close()

	cfg := config.Config{
		Addr:       *addr,
		LogFile:    *logFile,
		Profiles:   []string{"generic"},
		AllowHosts: []string{"*"},
	}

	logger, err := audit.NewFileLogger(cfg.LogFile)
	if err != nil {
		log.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	server, err := proxy.NewServer(cfg, logger)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
		close(serverErr)
	}()

	time.Sleep(150 * time.Millisecond)

	proxyURL, _ := url.Parse("http://" + cfg.Addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(upstreamHTTP.URL)
	if err != nil {
		log.Fatalf("http request via proxy failed: %v", err)
	}
	_ = resp.Body.Close()

	httpsClient := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err = httpsClient.Get(upstreamHTTPS.URL)
	if err != nil {
		log.Fatalf("https request via proxy failed: %v", err)
	}
	_ = resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown failed: %v", err)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		log.Fatalf("server did not confirm shutdown")
	}
}
