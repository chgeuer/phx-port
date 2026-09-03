package phxp

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

type handoffResult struct {
	response Message
	err      error
}

func startTestHandoff(path string, tcp *net.TCPConn, request Message) <-chan handoffResult {
	result := make(chan handoffResult, 1)
	go func() {
		response, err := sendTestHandoff(path, tcp, request)
		result <- handoffResult{response: response, err: err}
	}()
	return result
}

func sendTestHandoff(path string, tcp *net.TCPConn, request Message) (Message, error) {
	return sendTestHandoffWithDescriptorCount(path, tcp, request, 1)
}

func sendTestHandoffWithDescriptorCount(path string, tcp *net.TCPConn, request Message, count int) (Message, error) {
	control, err := dialTestControl(path)
	if err != nil {
		return Message{}, err
	}
	defer syscall.Close(control)
	if err := configureControlTimeout(control, 2*time.Second); err != nil {
		return Message{}, err
	}
	if err := writeControlFrame(control, mustEncode(Message{Type: TypeHello})); err != nil {
		return Message{}, err
	}
	readyPacket, err := readControlFrame(control)
	if err != nil {
		return Message{}, err
	}
	ready, err := Decode(readyPacket)
	if err != nil || ready.Type != TypeReady {
		return Message{}, fmt.Errorf("invalid READY: %v", err)
	}
	packet, err := Encode(request)
	if err != nil {
		return Message{}, err
	}
	release, err := sendTestDescriptor(control, packet, tcp, count)
	if err != nil {
		return Message{}, err
	}
	defer release()
	responsePacket, err := readControlFrame(control)
	if err != nil {
		return Message{}, err
	}
	response, err := Decode(responsePacket)
	if err != nil {
		return Message{}, err
	}
	return response, nil
}

func tcpPair() (*net.TCPListener, *net.TCPConn, *net.TCPConn, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		listener.Close()
		return nil, nil, nil, err
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		client.Close()
		listener.Close()
		return nil, nil, nil, err
	}
	return listener, client, server, nil
}
