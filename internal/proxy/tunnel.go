package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
)

// tunnelConnections pipes bytes bi-directionally until either side closes.
func tunnelConnections(clientBuf *bufio.ReadWriter, clientConn net.Conn, upstream net.Conn) error {
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(upstream, clientBuf)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(clientConn, upstream)
		if bw := clientBuf.Writer; bw != nil {
			bw.Flush()
		}
		errCh <- err
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && !errorsIsBenign(err) {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func errorsIsBenign(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}
