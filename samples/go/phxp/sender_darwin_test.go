//go:build darwin

package phxp

import (
	"errors"
	"net"
	"syscall"
)

func dialTestControl(path string) (int, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1, err
	}
	syscall.CloseOnExec(fd)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_NOSIGPIPE, 1); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	if err := syscall.Connect(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func sendTestDescriptor(control int, packet []byte, tcp *net.TCPConn, count int) (func(), error) {
	raw, err := tcp.SyscallConn()
	if err != nil {
		return func() {}, err
	}
	sent := 0
	var sendErr error
	if err := raw.Control(func(fd uintptr) {
		rights := make([]int, count)
		for index := range rights {
			rights[index] = int(fd)
		}
		sent, sendErr = syscall.SendmsgN(control, packet, syscall.UnixRights(rights...), nil, 0)
	}); err != nil {
		return func() {}, err
	}
	if sendErr != nil {
		return func() {}, sendErr
	}
	if sent == 0 {
		return func() {}, errors.New("descriptor-bearing sendmsg wrote no bytes")
	}
	if sent < len(packet) {
		if err := writeControlFrame(control, packet[sent:]); err != nil {
			return func() { _ = tcp.Close() }, err
		}
	}
	return func() { _ = tcp.Close() }, nil
}
