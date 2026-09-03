//go:build linux

package phxp

import (
	"errors"
	"net"
	"syscall"
)

func dialTestControl(path string) (int, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
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
	var sendErr error
	if err := raw.Control(func(fd uintptr) {
		rights := make([]int, count)
		for index := range rights {
			rights[index] = int(fd)
		}
		n, err := syscall.SendmsgN(
			control,
			packet,
			syscall.UnixRights(rights...),
			nil,
			syscall.MSG_NOSIGNAL,
		)
		if err != nil {
			sendErr = err
		} else if n != len(packet) {
			sendErr = errors.New("partial descriptor-bearing seqpacket send")
		}
	}); err != nil {
		return func() {}, err
	}
	if sendErr != nil {
		return func() {}, sendErr
	}
	if err := tcp.Close(); err != nil {
		return func() {}, err
	}
	return func() {}, nil
}
