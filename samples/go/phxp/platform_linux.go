//go:build linux

package phxp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

const unixPathMax = 107

func bindControlSocket(path string) (int, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("create PHXP seqpacket socket: %w", err)
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
	fd, _, err := syscall.Accept4(listener, syscall.SOCK_CLOEXEC)
	if err != nil {
		return -1, err
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func authenticatePeer(fd int) error {
	credentials, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return fmt.Errorf("inspect PHXP peer credentials: %w", err)
	}
	if credentials.Uid != uint32(os.Geteuid()) {
		return errors.New("PHXP peer belongs to a different user")
	}
	return nil
}

func readControlFrame(fd int) ([]byte, error) {
	packet := make([]byte, MaxPacketLength+1)
	n, _, flags, _, err := recvmsgRetry(fd, packet, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("receive PHXP frame: %w", err)
	}
	if n == 0 {
		return nil, io.EOF
	}
	if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || n > MaxPacketLength {
		return nil, errors.New("PHXP packet was truncated or exceeds its bound")
	}
	return packet[:n], nil
}

func writeControlFrame(fd int, packet []byte) error {
	n, err := syscall.SendmsgN(fd, packet, nil, nil, syscall.MSG_NOSIGNAL)
	if err != nil {
		return fmt.Errorf("send PHXP frame: %w", err)
	}
	if n != len(packet) {
		return errors.New("PHXP seqpacket response was partially sent")
	}
	return nil
}

func receiveDescriptorFrame(fd int) ([]byte, []int, error) {
	packet := make([]byte, MaxPacketLength+1)
	oob := make([]byte, syscall.CmsgSpace(2*4))
	n, oobn, flags, _, err := recvmsgRetry(fd, packet, oob, syscall.MSG_CMSG_CLOEXEC)
	if err != nil {
		return nil, nil, fmt.Errorf("receive PHXP descriptor: %w", err)
	}
	descriptors, parseErr := parseDescriptors(oob[:oobn])
	if parseErr != nil {
		closeDescriptors(descriptors)
		return nil, nil, parseErr
	}
	if n == 0 {
		closeDescriptors(descriptors)
		return nil, nil, io.EOF
	}
	if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || n > MaxPacketLength {
		closeDescriptors(descriptors)
		return nil, nil, errors.New("PHXP packet or ancillary data was truncated")
	}
	for _, descriptor := range descriptors {
		syscall.CloseOnExec(descriptor)
	}
	return packet[:n], descriptors, nil
}

func endpointIsLive(path string) bool {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)
	return syscall.Connect(fd, &syscall.SockaddrUnix{Name: path}) == nil
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
