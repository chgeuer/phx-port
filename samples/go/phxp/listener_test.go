package phxp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestPeerAndDescriptorValidation(t *testing.T) {
	socketPair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}

	defer syscall.Close(socketPair[0])
	defer syscall.Close(socketPair[1])
	if err := authenticatePeer(socketPair[0]); err != nil {
		t.Fatalf("same-euid peer rejected: %v", err)
	}
	if err := validateConnectedTCP(socketPair[0]); err == nil {
		t.Fatal("connected Unix stream was accepted as TCP")
	}

	listener, client, server, err := tcpPair()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer client.Close()
	defer server.Close()
	raw, err := server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var validationErr error
	if err := raw.Control(func(fd uintptr) {
		validationErr = validateConnectedTCP(int(fd))
		if validationErr == nil {
			validationErr = ensureDescriptorPolicy(int(fd))
		}
	}); err != nil {
		t.Fatal(err)
	}
	if validationErr != nil {
		t.Fatalf("connected TCP descriptor rejected: %v", validationErr)
	}
}

func TestAdoptionClosesOriginalReceivedDescriptor(t *testing.T) {
	listener, client, server, err := tcpPair()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer client.Close()
	raw, err := server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	receivedFD := -1
	var duplicateErr error
	if err := raw.Control(func(fd uintptr) {
		receivedFD, duplicateErr = syscall.Dup(int(fd))
	}); err != nil {
		t.Fatal(err)
	}
	if duplicateErr != nil {
		t.Fatal(duplicateErr)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}

	adopted, err := adoptTCPDescriptor(receivedFD)
	if err != nil {
		t.Fatal(err)
	}
	defer adopted.Close()
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(receivedFD), uintptr(syscall.F_GETFD), 0)
	if errno != syscall.EBADF {
		t.Fatalf("original received descriptor remains usable: %v", errno)
	}
	rawAdopted, err := adopted.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var policyErr error
	if err := rawAdopted.Control(func(fd uintptr) {
		policyErr = verifyDescriptorPolicy(int(fd))
	}); err != nil {
		t.Fatal(err)
	}
	if policyErr != nil {
		t.Fatal(policyErr)
	}
}

func TestHandoffRoundTripRetainsAddressesAndData(t *testing.T) {
	directory := testDirectory(t)
	receiver, err := Listen(ListenerConfig{
		Endpoint:  Endpoint{Path: directory + "/receiver.sock"},
		QueueSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	public, client, accepted, err := tcpPair()
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()
	defer client.Close()
	peer := client.LocalAddr().String()
	local := public.Addr().String()
	payload := []byte("untouched client hello")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	id := [16]byte{0x5a}
	result := startTestHandoff(receiver.path, accepted, Message{
		Type:         TypeHandoff,
		ConnectionID: id,
		PeekedLength: uint32(len(payload)),
		AcceptedAtNS: 42,
		RequestedSNI: "www.contoso.com",
	})
	adopted, err := receiver.Accept()
	if err != nil {
		t.Fatal(err)
	}
	handoff := <-result
	if handoff.err != nil {
		t.Fatal(handoff.err)
	}
	if handoff.response.Type != TypeAdopted || handoff.response.ConnectionID != id {
		t.Fatalf("response = %#v", handoff.response)
	}
	defer adopted.Close()
	if adopted.RemoteAddr().String() != peer || adopted.LocalAddr().String() != local {
		t.Fatalf("addresses peer=%s local=%s, want peer=%s local=%s",
			adopted.RemoteAddr(), adopted.LocalAddr(), peer, local)
	}
	metadata, ok := MetadataFromConn(adopted)
	if !ok || metadata.ConnectionID != id || metadata.RequestedSNI != "www.contoso.com" ||
		metadata.PeekedLength != uint32(len(payload)) || metadata.AcceptedAtNS != 42 {
		t.Fatalf("metadata = %#v, present=%v", metadata, ok)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(adopted, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("payload = %q", received)
	}
	if _, err := adopted.Write([]byte("server reply")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("server reply"))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "server reply" {
		t.Fatalf("reply = %q", reply)
	}
}

func TestDuplicateActiveConnectionIDsAreRejected(t *testing.T) {
	directory := testDirectory(t)
	receiver, err := Listen(ListenerConfig{
		Endpoint:  Endpoint{Path: directory + "/receiver.sock"},
		QueueSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	id := [16]byte{0x77}

	public1, client1, accepted1, err := tcpPair()
	if err != nil {
		t.Fatal(err)
	}
	defer public1.Close()
	defer client1.Close()
	firstResult := startTestHandoff(receiver.path, accepted1, Message{
		Type: TypeHandoff, ConnectionID: id, RequestedSNI: "one.example",
	})
	adopted, err := receiver.Accept()
	if err != nil {
		t.Fatal(err)
	}
	first := <-firstResult
	if first.err != nil || first.response.Type != TypeAdopted {
		t.Fatalf("first handoff = %#v, %v", first.response, first.err)
	}

	public2, client2, accepted2, err := tcpPair()
	if err != nil {
		t.Fatal(err)
	}
	defer public2.Close()
	defer client2.Close()
	second, err := sendTestHandoff(receiver.path, accepted2, Message{
		Type: TypeHandoff, ConnectionID: id, RequestedSNI: "two.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Type != TypeRejected || second.ConnectionID != id ||
		second.RejectionCode != RejectDuplicateID {
		t.Fatalf("duplicate response = %#v", second)
	}

	if err := adopted.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHandoffRejectsMoreThanOneDescriptor(t *testing.T) {
	directory := testDirectory(t)
	receiver, err := Listen(ListenerConfig{
		Endpoint: Endpoint{Path: directory + "/receiver.sock"},
	})
	if err != nil {
		t.Fatal(err)
	}

	defer receiver.Close()

	public, client, accepted, err := tcpPair()
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()
	defer client.Close()
	id := [16]byte{0x33}
	response, err := sendTestHandoffWithDescriptorCount(receiver.path, accepted, Message{
		Type: TypeHandoff, ConnectionID: id, RequestedSNI: "example.test",
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if response.Type != TypeRejected || response.ConnectionID != id ||
		response.RejectionCode != RejectInvalidDescriptor {
		t.Fatalf("multiple-descriptor response = %#v", response)
	}
}

func TestFullAdoptionQueueRejectsBeforeOwnership(t *testing.T) {
	directory := testDirectory(t)
	receiver, err := Listen(ListenerConfig{
		Endpoint:  Endpoint{Path: directory + "/receiver.sock"},
		QueueSize: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	public1, client1, accepted1, err := tcpPair()
	if err != nil {
		t.Fatal(err)
	}
	defer public1.Close()
	defer client1.Close()
	firstResult := startTestHandoff(receiver.path, accepted1, Message{
		Type: TypeHandoff, ConnectionID: [16]byte{1}, RequestedSNI: "one.example",
	})
	deadline := time.Now().Add(2 * time.Second)
	for len(receiver.queue) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(receiver.queue) != 1 {
		t.Fatal("first handoff did not enter the bounded adoption queue")
	}

	public2, client2, accepted2, err := tcpPair()
	if err != nil {
		t.Fatal(err)
	}
	defer public2.Close()
	defer client2.Close()
	secondID := [16]byte{2}
	second, err := sendTestHandoff(receiver.path, accepted2, Message{
		Type: TypeHandoff, ConnectionID: secondID, RequestedSNI: "two.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Type != TypeRejected || second.ConnectionID != secondID ||
		second.RejectionCode != RejectAdoptionFailed {
		t.Fatalf("full-queue response = %#v", second)
	}

	firstConn, err := receiver.Accept()
	if err != nil {
		t.Fatal(err)
	}
	first := <-firstResult
	if first.err != nil || first.response.Type != TypeAdopted {
		t.Fatalf("first handoff = %#v, %v", first.response, first.err)
	}
	if err := firstConn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOrdinaryAndPHXPConnectionsShareHTTPPipeline(t *testing.T) {
	directory := testDirectory(t)
	receiver, err := Listen(ListenerConfig{
		Endpoint:  Endpoint{Path: directory + "/receiver.sock"},
		QueueSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	direct, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	joined, err := JoinListeners(direct, receiver)
	if err != nil {
		t.Fatal(err)
	}
	defer joined.Close()

	certificate := testCertificate(t)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	type pipelineMarker struct{}
	type observedRequest struct {
		method     string
		requestURI string
		host       string
		header     string
		protocol   string
		serverName string
		peer       string
		local      string
	}
	marker := &pipelineMarker{}
	observations := make(chan observedRequest, 2)
	var middlewareCalls atomic.Int32
	var handlerCalls atomic.Int32
	application := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handlerCalls.Add(1)
		if request.Context().Value(pipelineMarker{}) != marker {
			http.Error(writer, "middleware missing", http.StatusInternalServerError)
			return
		}
		local, _ := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
		observations <- observedRequest{
			method:     request.Method,
			requestURI: request.URL.RequestURI(),
			host:       request.Host,
			header:     request.Header.Get("X-Pipeline-Test"),
			protocol:   request.Proto,
			serverName: request.TLS.ServerName,
			peer:       request.RemoteAddr,
			local:      local.String(),
		}
		_, _ = io.WriteString(writer, "shared application response\n")
	})
	stack := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		middlewareCalls.Add(1)
		application.ServeHTTP(
			writer,
			request.WithContext(context.WithValue(request.Context(), pipelineMarker{}, marker)),
		)
	})
	server := &http.Server{
		Handler:           stack,
		ReadHeaderTimeout: 2 * time.Second,
	}
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(tls.NewListener(joined, serverTLS))
	}()
	defer func() {
		_ = server.Close()
		select {
		case <-serveResult:
		case <-time.After(2 * time.Second):
			t.Error("HTTP server did not stop")
		}
	}()

	directClient, err := tls.Dial("tcp", direct.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.test",
		NextProtos:         []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	directPeer := directClient.LocalAddr().String()
	directLocal := direct.Addr().String()
	directBody := exchangeHTTP11(t, directClient)
	_ = directClient.Close()
	directRequest := <-observations

	public, rawClient, accepted, err := tcpPair()
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()
	handoffPeer := rawClient.LocalAddr().String()
	handoffLocal := public.Addr().String()
	clientTLS := tls.Client(rawClient, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.test",
		NextProtos:         []string{"http/1.1"},
	})
	defer clientTLS.Close()
	handshakeResult := make(chan error, 1)
	go func() {
		handshakeResult <- clientTLS.HandshakeContext(context.Background())
	}()

	id := [16]byte{0x44}
	response, err := sendTestHandoff(receiver.path, accepted, Message{
		Type:         TypeHandoff,
		ConnectionID: id,
		PeekedLength: 1,
		AcceptedAtNS: 99,
		RequestedSNI: "example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Type != TypeAdopted {
		t.Fatalf("handoff response = %#v", response)
	}
	select {
	case err := <-handshakeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS handshake timed out")
	}

	handoffBody := exchangeHTTP11(t, clientTLS)
	handoffRequest := <-observations

	if directBody != handoffBody || directBody != "shared application response\n" {
		t.Fatalf("application responses differ: direct=%q handoff=%q", directBody, handoffBody)
	}
	directApplication := directRequest
	handoffApplication := handoffRequest
	directApplication.peer, directApplication.local = "", ""
	handoffApplication.peer, handoffApplication.local = "", ""
	if directApplication != handoffApplication {
		t.Fatalf("application requests differ:\n direct=%#v\nhandoff=%#v", directApplication, handoffApplication)
	}
	if middlewareCalls.Load() != 2 || handlerCalls.Load() != 2 {
		t.Fatalf("pipeline calls middleware=%d handler=%d", middlewareCalls.Load(), handlerCalls.Load())
	}
	if directRequest.peer != directPeer || directRequest.local != directLocal {
		t.Fatalf("direct addresses peer=%s local=%s, want peer=%s local=%s",
			directRequest.peer, directRequest.local, directPeer, directLocal)
	}
	if handoffRequest.peer != handoffPeer || handoffRequest.local != handoffLocal {
		t.Fatalf("PHXP addresses peer=%s local=%s, want peer=%s local=%s",
			handoffRequest.peer, handoffRequest.local, handoffPeer, handoffLocal)
	}
}

func exchangeHTTP11(t *testing.T, connection net.Conn) string {
	t.Helper()
	if _, err := io.WriteString(connection,
		"GET /same?value=1 HTTP/1.1\r\n"+
			"Host: example.test\r\n"+
			"X-Pipeline-Test: identical\r\n"+
			"Connection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
