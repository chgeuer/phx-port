package phxp

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

const (
	RejectInvalidDescriptor uint16 = 1
	RejectDuplicateID       uint16 = 2
	RejectAdoptionFailed    uint16 = 3
)

type ListenerConfig struct {
	Endpoint              Endpoint
	QueueSize             int
	Backlog               int
	ControlTimeout        time.Duration
	MaxControlConnections int
	ErrorLog              func(error)
}

type Metadata struct {
	ConnectionID [16]byte
	RequestedSNI string
	PeekedLength uint32
	AcceptedAtNS uint64
}

type Listener struct {
	fd       int
	path     string
	identity endpointIdentity
	timeout  time.Duration
	queue    chan *adoptedConn
	controls chan struct{}
	done     chan struct{}
	log      func(error)

	closeOnce sync.Once
	activeMu  sync.Mutex
	active    map[[16]byte]struct{}
	stateMu   sync.Mutex
	closed    bool
}

type endpointIdentity struct {
	device uint64
	inode  uint64
}

type adoptedConn struct {
	net.Conn
	metadata Metadata
	owner    *Listener
	close    sync.Once
	receipt  chan bool
}

type unixAddr string

func (a unixAddr) Network() string { return "unix" }
func (a unixAddr) String() string  { return string(a) }

func Listen(config ListenerConfig) (*Listener, error) {
	if config.Endpoint.Path == "" {
		return nil, errors.New("PHXP endpoint path is required")
	}
	if config.QueueSize == 0 {
		config.QueueSize = 128
	}
	if config.QueueSize < 1 {
		return nil, errors.New("PHXP queue size must be positive")
	}
	if config.Backlog == 0 {
		config.Backlog = 128
	}
	if config.Backlog < 1 {
		return nil, errors.New("PHXP backlog must be positive")
	}
	if config.ControlTimeout == 0 {
		config.ControlTimeout = 2 * time.Second
	}
	if config.ControlTimeout < time.Millisecond {
		return nil, errors.New("PHXP control timeout is too short")
	}
	if config.MaxControlConnections == 0 {
		config.MaxControlConnections = 32
	}
	if config.MaxControlConnections < 1 {
		return nil, errors.New("PHXP control connection limit must be positive")
	}
	if err := prepareEndpoint(config.Endpoint.Path, config.Endpoint.ValidateRuntimeRoot); err != nil {
		return nil, err
	}

	fd, err := bindControlSocket(config.Endpoint.Path)
	if err != nil {
		return nil, err
	}
	identity, err := inspectSocket(config.Endpoint.Path, false)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = syscall.Close(fd)
			removeEndpointIfOwned(config.Endpoint.Path, identity)
		}
	}()
	if err := os.Chmod(config.Endpoint.Path, 0o600); err != nil {
		return nil, fmt.Errorf("secure PHXP endpoint %s: %w", config.Endpoint.Path, err)
	}
	securedIdentity, err := inspectSocket(config.Endpoint.Path, true)
	if err != nil {
		return nil, err
	}
	if securedIdentity != identity {
		return nil, errors.New("PHXP endpoint identity changed while it was being secured")
	}
	if err := listenControlSocket(fd, config.Backlog); err != nil {
		return nil, err
	}

	listener := &Listener{
		fd:       fd,
		path:     config.Endpoint.Path,
		identity: identity,
		timeout:  config.ControlTimeout,
		queue:    make(chan *adoptedConn, config.QueueSize),
		controls: make(chan struct{}, config.MaxControlConnections),
		done:     make(chan struct{}),
		log:      config.ErrorLog,
		active:   make(map[[16]byte]struct{}),
	}
	cleanup = false
	go listener.acceptLoop()
	return listener, nil
}

func (listener *Listener) Accept() (net.Conn, error) {
	select {
	case <-listener.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case conn := <-listener.queue:
		conn.receipt <- true
		return conn, nil
	case <-listener.done:
		return nil, net.ErrClosed
	}
}

func (listener *Listener) Close() error {
	var closeErr error
	listener.closeOnce.Do(func() {
		listener.stateMu.Lock()
		listener.closed = true
		close(listener.done)
		if err := syscall.Close(listener.fd); err != nil && err != syscall.EBADF {
			closeErr = err
		}
		for {
			select {
			case conn := <-listener.queue:
				conn.receipt <- false
				_ = conn.Close()
			default:
				listener.stateMu.Unlock()
				listener.removeOwnedEndpoint()
				return
			}
		}
	})
	return closeErr
}

func (listener *Listener) Addr() net.Addr {
	return unixAddr(listener.path)
}

func MetadataFromConn(conn net.Conn) (Metadata, bool) {
	type metadataProvider interface {
		PHXPMetadata() Metadata
	}
	provider, ok := conn.(metadataProvider)
	if !ok {
		return Metadata{}, false
	}
	return provider.PHXPMetadata(), true
}

func (conn *adoptedConn) PHXPMetadata() Metadata {
	return conn.metadata
}

func (conn *adoptedConn) Close() error {
	var err error
	conn.close.Do(func() {
		err = conn.Conn.Close()
		conn.owner.releaseID(conn.metadata.ConnectionID)
	})
	return err
}

func (listener *Listener) acceptLoop() {
	for {
		control, err := acceptControl(listener.fd)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) ||
				errors.Is(err, syscall.EINTR) {
				select {
				case <-listener.done:
					return
				case <-time.After(10 * time.Millisecond):
					continue
				}
			}
			select {
			case <-listener.done:
				return
			default:
				listener.report(fmt.Errorf("accept PHXP control connection: %w", err))
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}
		select {
		case listener.controls <- struct{}{}:
			go listener.handleControl(control)
		default:
			_ = syscall.Close(control)
		}
	}
}

func (listener *Listener) handleControl(control int) {
	defer func() { <-listener.controls }()
	defer syscall.Close(control)
	if err := authenticatePeer(control); err != nil {
		listener.report(err)
		return
	}
	if err := configureControlTimeout(control, listener.timeout); err != nil {
		listener.report(err)
		return
	}

	helloPacket, err := readControlFrame(control)
	if err != nil {
		listener.report(err)
		return
	}
	hello, err := Decode(helloPacket)
	if err != nil || hello.Type != TypeHello {
		listener.report(errors.New("invalid PHXP HELLO"))
		return
	}
	if err := writeControlFrame(control, mustEncode(Message{Type: TypeReady})); err != nil {
		listener.report(err)
		return
	}

	packet, descriptors, err := receiveDescriptorFrame(control)
	if err != nil {
		closeDescriptors(descriptors)
		listener.report(err)
		return
	}
	request, err := Decode(packet)
	if err != nil || request.Type != TypeHandoff {
		closeDescriptors(descriptors)
		listener.report(errors.New("invalid PHXP HANDOFF"))
		return
	}
	if len(descriptors) != 1 {
		closeDescriptors(descriptors)
		listener.reject(control, request.ConnectionID, RejectInvalidDescriptor)
		listener.report(fmt.Errorf("PHXP HANDOFF contained %d descriptors instead of one", len(descriptors)))
		return
	}
	fd := descriptors[0]

	if err := validateConnectedTCP(fd); err != nil {
		_ = syscall.Close(fd)
		listener.reject(control, request.ConnectionID, RejectInvalidDescriptor)
		listener.report(err)
		return
	}
	if !listener.reserveID(request.ConnectionID) {
		_ = syscall.Close(fd)
		listener.reject(control, request.ConnectionID, RejectDuplicateID)
		listener.report(errors.New("duplicate PHXP connection identifier"))
		return
	}

	tcp, err := adoptTCPDescriptor(fd)
	if err != nil {
		listener.releaseID(request.ConnectionID)
		listener.reject(control, request.ConnectionID, RejectAdoptionFailed)
		listener.report(err)
		return
	}
	conn := &adoptedConn{
		Conn: tcp,
		metadata: Metadata{
			ConnectionID: request.ConnectionID,
			RequestedSNI: request.RequestedSNI,
			PeekedLength: request.PeekedLength,
			AcceptedAtNS: request.AcceptedAtNS,
		},
		owner:   listener,
		receipt: make(chan bool, 1),
	}

	listener.stateMu.Lock()
	if listener.closed {
		listener.stateMu.Unlock()
		_ = conn.Close()
		listener.reject(control, request.ConnectionID, RejectAdoptionFailed)
		return
	}
	select {
	case listener.queue <- conn:
		listener.stateMu.Unlock()
		if adopted := <-conn.receipt; !adopted {
			listener.reject(control, request.ConnectionID, RejectAdoptionFailed)
			return
		}
		if err := writeControlFrame(control, mustEncode(Message{
			Type: TypeAdopted, ConnectionID: request.ConnectionID,
		})); err != nil {
			listener.report(fmt.Errorf("PHXP connection was accepted but acknowledgement was lost: %w", err))
		}
	default:
		listener.stateMu.Unlock()
		_ = conn.Close()
		listener.reject(control, request.ConnectionID, RejectAdoptionFailed)
		listener.report(errors.New("PHXP adoption queue is full"))
	}
}

func (listener *Listener) reserveID(id [16]byte) bool {
	listener.activeMu.Lock()
	defer listener.activeMu.Unlock()
	if _, exists := listener.active[id]; exists {
		return false
	}
	listener.active[id] = struct{}{}
	return true
}

func (listener *Listener) releaseID(id [16]byte) {
	listener.activeMu.Lock()
	delete(listener.active, id)
	listener.activeMu.Unlock()
}

func (listener *Listener) reject(control int, id [16]byte, code uint16) {
	_ = writeControlFrame(control, mustEncode(Message{
		Type:          TypeRejected,
		ConnectionID:  id,
		RejectionCode: code,
	}))
}

func (listener *Listener) report(err error) {
	if listener.log != nil && err != nil {
		listener.log(err)
	}
}

func (listener *Listener) removeOwnedEndpoint() {
	removeEndpointIfOwned(listener.path, listener.identity)
}

func configureControlTimeout(fd int, timeout time.Duration) error {
	value := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &value); err != nil {
		return fmt.Errorf("configure PHXP receive timeout: %w", err)
	}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &value); err != nil {
		return fmt.Errorf("configure PHXP send timeout: %w", err)
	}
	return nil
}

func adoptTCPDescriptor(fd int) (*net.TCPConn, error) {
	if err := ensureDescriptorPolicy(fd); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "phxp-adopted-tcp")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("represent adopted descriptor as an OS file")
	}
	conn, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil {
		return nil, fmt.Errorf("represent adopted descriptor as net.Conn: %w", err)
	}
	if closeErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("release original adopted descriptor: %w", closeErr)
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("adopted descriptor did not become a TCP connection")
	}
	if err := enforceTCPConnPolicy(tcp); err != nil {
		_ = tcp.Close()
		return nil, err
	}
	if tcp.RemoteAddr() == nil || tcp.LocalAddr() == nil {
		_ = tcp.Close()
		return nil, errors.New("adopted TCP descriptor has missing addresses")
	}
	return tcp, nil
}

func validateConnectedTCP(fd int) error {
	socketType, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return fmt.Errorf("inspect handed-off descriptor type: %w", err)
	}
	if socketType != syscall.SOCK_STREAM {
		return errors.New("handed-off descriptor is not a stream socket")
	}
	if _, err := syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY); err != nil {
		return fmt.Errorf("handed-off stream is not TCP: %w", err)
	}
	peer, err := syscall.Getpeername(fd)
	if err != nil {
		return fmt.Errorf("handed-off TCP descriptor is not connected: %w", err)
	}
	local, err := syscall.Getsockname(fd)
	if err != nil {
		return fmt.Errorf("inspect handed-off TCP local address: %w", err)
	}
	if !internetSockaddr(peer) || !internetSockaddr(local) {
		return errors.New("handed-off descriptor does not have Internet socket addresses")
	}
	return nil
}

func internetSockaddr(address syscall.Sockaddr) bool {
	switch address.(type) {
	case *syscall.SockaddrInet4, *syscall.SockaddrInet6:
		return true
	default:
		return false
	}
}

func ensureDescriptorPolicy(fd int) error {
	syscall.CloseOnExec(fd)
	if err := syscall.SetNonblock(fd, true); err != nil {
		return fmt.Errorf("set adopted descriptor nonblocking: %w", err)
	}
	return verifyDescriptorPolicy(fd)
}

func enforceTCPConnPolicy(conn *net.TCPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("access adopted TCP descriptor: %w", err)
	}
	var policyErr error
	if err := raw.Control(func(fd uintptr) {
		policyErr = ensureDescriptorPolicy(int(fd))
	}); err != nil {
		return fmt.Errorf("control adopted TCP descriptor: %w", err)
	}
	return policyErr
}

func verifyDescriptorPolicy(fd int) error {
	fdFlags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFD), 0)
	if errno != 0 {
		return fmt.Errorf("inspect adopted descriptor close-on-exec flag: %w", errno)
	}
	if fdFlags&syscall.FD_CLOEXEC == 0 {
		return errors.New("adopted descriptor is not close-on-exec")
	}
	statusFlags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFL), 0)
	if errno != 0 {
		return fmt.Errorf("inspect adopted descriptor status flags: %w", errno)
	}
	if statusFlags&syscall.O_NONBLOCK == 0 {
		return errors.New("adopted descriptor is not nonblocking")
	}
	return nil
}

func closeDescriptors(descriptors []int) {
	for _, fd := range descriptors {
		_ = syscall.Close(fd)
	}
}

func mustEncode(message Message) []byte {
	packet, err := Encode(message)
	if err != nil {
		panic(err)
	}
	return packet
}
