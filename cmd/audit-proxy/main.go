package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kdhira/audit-proxy/internal/audit"
	"github.com/kdhira/audit-proxy/internal/config"
	"github.com/kdhira/audit-proxy/internal/proxy"
)

func main() {
	var (
		configPath   string
		validateOnly bool
	)
	flag.StringVar(&configPath, "config", "", "path to YAML/JSON configuration file")
	flag.BoolVar(&validateOnly, "validate-config", false, "loads configuration and exits after validation")
	cfg := config.MustParseFlags(flag.CommandLine, os.Args[1:])
	if configPath != "" {
		fileCfg, err := config.LoadFile(configPath)
		if err != nil {
			log.Fatalf("failed to load config file: %v", err)
		}
		cfg = config.Merge(cfg, fileCfg)
		if err := cfg.Validate(); err != nil {
			log.Fatalf("invalid merged config: %v", err)
		}
	}

	if validateOnly {
		fmt.Println("configuration validated successfully")
		return
	}

	logger, err := audit.NewFileLogger(cfg.LogFile)
	if err != nil {
		log.Fatalf("failed to create log writer: %v", err)
	}
	defer func() {
		if cerr := logger.Close(); cerr != nil {
			log.Printf("failed to close logger: %v", cerr)
		}
	}()

	srv, err := proxy.NewServer(cfg, logger)
	if err != nil {
		log.Fatalf("failed to configure proxy server: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("proxy server terminated: %v", err)
		}
		return
	}

	if err := <-serverErr; err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "proxy server exited with error: %v\n", err)
	}
}
