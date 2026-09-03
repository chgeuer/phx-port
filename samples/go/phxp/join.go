package phxp

import (
	"errors"
	"net"
	"sync"
	"time"
)

type joinedListener struct {
	listeners []net.Listener
	results   chan acceptResult
	done      chan struct{}
	closeOnce sync.Once
}

type acceptResult struct {
	conn net.Conn
	err  error
}

// JoinListeners combines accepted connections from multiple listeners into one
// net.Listener. Closing the returned listener closes every input listener.
func JoinListeners(listeners ...net.Listener) (net.Listener, error) {
	if len(listeners) == 0 {
		return nil, errors.New("at least one listener is required")
	}
	for _, listener := range listeners {
		if listener == nil {
			return nil, errors.New("listeners must not be nil")
		}
	}
	joined := &joinedListener{
		listeners: append([]net.Listener(nil), listeners...),
		results:   make(chan acceptResult),
		done:      make(chan struct{}),
	}
	for _, listener := range joined.listeners {
		go joined.pump(listener)
	}
	return joined, nil
}

func (listener *joinedListener) Accept() (net.Conn, error) {
	select {
	case result := <-listener.results:
		return result.conn, result.err
	case <-listener.done:
		return nil, net.ErrClosed
	}
}

func (listener *joinedListener) Close() error {
	var joinedError error
	listener.closeOnce.Do(func() {
		close(listener.done)
		for _, input := range listener.listeners {
			if err := input.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				joinedError = errors.Join(joinedError, err)
			}
		}
	})
	return joinedError
}

func (listener *joinedListener) Addr() net.Addr {
	return listener.listeners[0].Addr()
}

func (listener *joinedListener) pump(input net.Listener) {
	var retryDelay time.Duration
	for {
		conn, err := input.Accept()
		if err != nil {
			if temporary, ok := err.(interface{ Temporary() bool }); ok && temporary.Temporary() {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
					retryDelay *= 2
				}
				if maximum := time.Second; retryDelay > maximum {
					retryDelay = maximum
				}
				timer := time.NewTimer(retryDelay)
				select {
				case <-timer.C:
					continue
				case <-listener.done:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return
				}
			}
			select {
			case listener.results <- acceptResult{err: err}:
				_ = listener.Close()
			case <-listener.done:
			}
			return
		}
		retryDelay = 0
		select {
		case listener.results <- acceptResult{conn: conn}:
		case <-listener.done:
			_ = conn.Close()
			return
		}
	}
}
