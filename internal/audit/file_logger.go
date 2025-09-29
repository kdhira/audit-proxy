package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// FileLogger writes audit entries as JSON Lines to disk.
type FileLogger struct {
	mu      sync.Mutex
	enc     *json.Encoder
	closer  io.Closer
	discard bool
}

// NewFileLogger builds a file-backed logger. The file is created if needed.
// When path is "-" the logger writes to stdout.
func NewFileLogger(path string) (*FileLogger, error) {
	if path == "" {
		path = "logs/audit.jsonl"
	}

	if path == "-" {
		return &FileLogger{enc: json.NewEncoder(os.Stdout), closer: nopCloser{}, discard: false}, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}

	return &FileLogger{enc: json.NewEncoder(f), closer: f}, nil
}

// Record writes a single entry to the underlying JSONL file.
func (l *FileLogger) Record(ctx context.Context, entry Entry) error {
	if l == nil || l.enc == nil {
		return errors.New("logger not initialised")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enc.Encode(entry)
}

// Close flushes the underlying file handle.
func (l *FileLogger) Close() error {
	if l == nil || l.closer == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closer.Close()
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
