package audit

import (
	"io"
	"strings"
	"testing"
)

func TestLimitedBufferTruncation(t *testing.T) {
	buf := NewLimitedBuffer(5)
	_, _ = buf.Write([]byte("hello world"))
	if got, want := string(buf.Bytes()), "hello"; got != want {
		t.Fatalf("expected truncated buffer, got %q", got)
	}
	buf.Reset(3)
	if buf.Len() != 0 {
		t.Fatalf("expected reset to clear buffer")
	}
	_, _ = buf.Write([]byte("abcde"))
	if got := string(buf.Bytes()); got != "abc" {
		t.Fatalf("reset limit not applied: %q", got)
	}
}

func TestTeeReadCloserCopiesData(t *testing.T) {
	buf := NewLimitedBuffer(10)
	src := io.NopCloser(strings.NewReader("streaming"))
	tee := NewTeeReadCloser(src, buf)
	data, err := io.ReadAll(tee)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(data) != "streaming" {
		t.Fatalf("unexpected read data: %q", data)
	}
	if err := tee.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if got, want := string(buf.Bytes()), "streaming"; got != want {
		t.Fatalf("buffer mismatch: got %q want %q", got, want)
	}
}
