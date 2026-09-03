//go:build darwin

package phxp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

const (
	unixPathMax   = 103
	solLocal      = 0
	localPeerCred = 1
)

type xucred struct {
	Version uint32
	UID     uint32
	NGroups int16
	_       [2]byte
	Groups  [16]uint32
}

func bindControlSocket(path string) (int, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1, fmt.Errorf("create PHXP stream socket: %w", err)
	}
	syscall.CloseOnExec(fd)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_NOSIGPIPE, 1); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("disable SIGPIPE on PHXP listener: %w", err)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("make PHXP listener nonblocking: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("bind PHXP endpoint %s: %w", path, err)
	}
	return fd, nil
}

func listenControlSocket(fd, backlog int) error {
	if err := syscall.Listen(fd, backlog); err != nil {
		return fmt.Errorf("listen on PHXP endpoint: %w", err)
	}
	return nil
}

func acceptControl(listener int) (int, error) {
	fd, _, err := syscall.Accept(listener)
	if err != nil {
		return -1, err
	}
	syscall.CloseOnExec(fd)
	if err := syscall.SetNonblock(fd, false); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_NOSIGPIPE, 1); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func authenticatePeer(fd int) error {
	peerEUID, _, err := getpeereid(fd)
	if err != nil {
		return fmt.Errorf("inspect PHXP peer credentials: %w", err)
	}
	if peerEUID != uint32(os.Geteuid()) {
		return errors.New("PHXP peer belongs to a different user")
	}
	return nil
}

// getpeereid implements Darwin getpeereid(3)'s LOCAL_PEERCRED lookup without
// requiring cgo, keeping the package buildable with CGO_ENABLED=0.
func getpeereid(fd int) (uint32, uint32, error) {
	var credentials xucred
	length := uint32(unsafe.Sizeof(credentials))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(solLocal),
		uintptr(localPeerCred),
		uintptr(unsafe.Pointer(&credentials)),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	if errno != 0 {
		return 0, 0, errno
	}
	if length < 8 || credentials.Version != 0 {
		return 0, 0, errors.New("peer credentials are malformed")
	}
	if credentials.NGroups < 1 {
		return 0, 0, errors.New("peer credentials contain no effective group")
	}
	return credentials.UID, credentials.Groups[0], nil
}

func readControlFrame(fd int) ([]byte, error) {
	initial := make([]byte, MaxPacketLength+1)
	n, err := readRetry(fd, initial)
	if err != nil {
		return nil, fmt.Errorf("receive PHXP frame: %w", err)
	}
	if n == 0 {
		return nil, io.EOF
	}
	return readStreamFrame(fdReader{fd: fd}, initial[:n])
}

func writeControlFrame(fd int, packet []byte) error {
	for len(packet) > 0 {
		n, err := writeRetry(fd, packet)
		if err != nil {
			return fmt.Errorf("send PHXP frame: %w", err)
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		packet = packet[n:]
	}
	return nil
}

func receiveDescriptorFrame(fd int) ([]byte, []int, error) {
	packet := make([]byte, MaxPacketLength+1)
	oob := make([]byte, syscall.CmsgSpace(2*4))
	n, oobn, flags, _, err := recvmsgRetry(fd, packet, oob, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("receive PHXP descriptor: %w", err)
	}
	descriptors, parseErr := parseDescriptors(oob[:oobn])
	if parseErr != nil {
		closeDescriptors(descriptors)
		return nil, nil, parseErr
	}
	for _, descriptor := range descriptors {
		syscall.CloseOnExec(descriptor)
	}
	if n == 0 {
		closeDescriptors(descriptors)
		return nil, nil, io.EOF
	}
	if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || n > MaxPacketLength {
		closeDescriptors(descriptors)
		return nil, nil, errors.New("PHXP packet or ancillary data was truncated")
	}
	frame, err := readStreamFrame(fdReader{fd: fd}, packet[:n])
	if err != nil {
		closeDescriptors(descriptors)
		return nil, nil, err
	}
	return frame, descriptors, nil
}

func endpointIsLive(path string) bool {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)
	syscall.CloseOnExec(fd)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_NOSIGPIPE, 1)
	return syscall.Connect(fd, &syscall.SockaddrUnix{Name: path}) == nil
}

type fdReader struct {
	fd int
}

func (reader fdReader) Read(buffer []byte) (int, error) {
	return readRetry(reader.fd, buffer)
}

func readRetry(fd int, buffer []byte) (int, error) {
	for {
		n, err := syscall.Read(fd, buffer)
		if err != syscall.EINTR {
			return n, err
		}
	}
}

func writeRetry(fd int, buffer []byte) (int, error) {
	for {
		n, err := syscall.Write(fd, buffer)
		if err != syscall.EINTR {
			return n, err
		}
	}
}

func recvmsgRetry(fd int, packet, oob []byte, flags int) (int, int, int, syscall.Sockaddr, error) {
	for {
		n, oobn, recvFlags, from, err := syscall.Recvmsg(fd, packet, oob, flags)
		if err != syscall.EINTR {
			return n, oobn, recvFlags, from, err
		}
	}
}

func parseDescriptors(oob []byte) ([]int, error) {
	messages, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("parse PHXP ancillary data: %w", err)
	}
	var descriptors []int
	for _, message := range messages {
		if message.Header.Level != syscall.SOL_SOCKET || message.Header.Type != syscall.SCM_RIGHTS {
			return descriptors, errors.New("PHXP HANDOFF contains unsupported ancillary data")
		}
		rights, err := syscall.ParseUnixRights(&message)
		if err != nil {
			return descriptors, fmt.Errorf("parse SCM_RIGHTS descriptors: %w", err)
		}
		descriptors = append(descriptors, rights...)
	}
	return descriptors, nil
}
