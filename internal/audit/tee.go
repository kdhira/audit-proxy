package audit

import (
	"bytes"
	"io"
)

// LimitedBuffer accumulates bytes up to the configured limit.
type LimitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

// NewLimitedBuffer constructs a LimitedBuffer with the provided limit in bytes.
func NewLimitedBuffer(limit int) *LimitedBuffer {
	return &LimitedBuffer{limit: limit}
}

// Write appends to the buffer up to the size limit.
func (b *LimitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return len(p), nil
	}
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		chunk := p
		if len(chunk) > remaining {
			chunk = chunk[:remaining]
		}
		_, _ = b.buf.Write(chunk)
	}
	return len(p), nil
}

// Bytes returns the accumulated contents.
func (b *LimitedBuffer) Bytes() []byte {
	return b.buf.Bytes()
}

// Len reports the number of bytes stored so far.
func (b *LimitedBuffer) Len() int {
	return b.buf.Len()
}

// Reset clears the buffer and optionally updates the limit.
func (b *LimitedBuffer) Reset(limit int) {
	b.buf.Reset()
	if limit >= 0 {
		b.limit = limit
	}
}

// TeeReadCloser duplicates data read from the underlying reader into a buffer.
type TeeReadCloser struct {
	source io.ReadCloser
	buf    *LimitedBuffer
}

// NewTeeReadCloser wraps the provided reader and streams copies into the limited buffer.
func NewTeeReadCloser(rc io.ReadCloser, buf *LimitedBuffer) *TeeReadCloser {
	return &TeeReadCloser{source: rc, buf: buf}
}

// Read copies bytes into the buffer while passing them downstream.
func (t *TeeReadCloser) Read(p []byte) (int, error) {
	n, err := t.source.Read(p)
	if n > 0 && t.buf != nil {
		_, _ = t.buf.Write(p[:n])
	}
	return n, err
}

// Close closes the wrapped reader.
func (t *TeeReadCloser) Close() error {
	return t.source.Close()
}
