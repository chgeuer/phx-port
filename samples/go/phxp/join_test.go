package phxp

import (
	"errors"
	"net"
	"sync"
	"testing"
)

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept failure" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

type scriptedListener struct {
	mu      sync.Mutex
	results []acceptResult
	closed  bool
}

func (listener *scriptedListener) Accept() (net.Conn, error) {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.closed {
		return nil, net.ErrClosed
	}
	if len(listener.results) == 0 {
		return nil, errors.New("script exhausted")
	}
	result := listener.results[0]
	listener.results = listener.results[1:]
	return result.conn, result.err
}

func (listener *scriptedListener) Close() error {
	listener.mu.Lock()
	listener.closed = true
	listener.mu.Unlock()
	return nil
}

func (listener *scriptedListener) Addr() net.Addr {
	return unixAddr("scripted")
}

func TestJoinedListenerRetriesTemporaryAcceptFailure(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	input := &scriptedListener{results: []acceptResult{
		{err: temporaryAcceptError{}},
		{conn: server},
	}}
	joined, err := JoinListeners(input)
	if err != nil {
		t.Fatal(err)
	}
	defer joined.Close()

	accepted, err := joined.Accept()
	if err != nil {
		t.Fatalf("temporary accept failure stopped joined listener: %v", err)
	}
	if accepted != server {
		t.Fatal("joined listener returned the wrong connection")
	}
	_ = accepted.Close()
}
