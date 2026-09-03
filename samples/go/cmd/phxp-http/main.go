package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/chgeuer/phx-port/samples/go/phxp"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	httpsAddress := flag.String("https", envOr("PHXP_HTTPS_ADDR", "127.0.0.1:8443"), "ordinary loopback HTTPS listen address")
	certificate := flag.String("cert", os.Getenv("PHXP_TLS_CERT"), "PEM certificate chain")
	key := flag.String("key", os.Getenv("PHXP_TLS_KEY"), "PEM private key")
	project := flag.String("project", envOr("PHXP_PROJECT", "."), "development project directory")
	workload := flag.String("workload-id", os.Getenv("PHXP_WORKLOAD_ID"), "production logical workload ID")
	role := flag.String("role", envOr("PHXP_ROLE", "https"), "PHXP role")
	endpointOverride := flag.String("handoff-socket", os.Getenv("PHXP_HANDOFF_SOCKET"), "complete PHXP endpoint override")
	flag.Parse()

	if *certificate == "" || *key == "" {
		return errors.New("-cert/PHXP_TLS_CERT and -key/PHXP_TLS_KEY are required")
	}
	tcpAddress, err := net.ResolveTCPAddr("tcp", *httpsAddress)
	if err != nil {
		return fmt.Errorf("resolve ordinary HTTPS address: %w", err)
	}
	if tcpAddress.IP == nil || !tcpAddress.IP.IsLoopback() {
		return errors.New("ordinary HTTPS listener must use an explicit loopback address")
	}

	var endpoint phxp.Endpoint
	if *endpointOverride != "" {
		absolute, err := filepath.Abs(*endpointOverride)
		if err != nil {
			return err
		}
		endpoint = phxp.Endpoint{Path: absolute}
	} else {
		var identity phxp.Identity
		if *workload != "" {
			identity, err = phxp.Production(*workload)
		} else {
			identity, err = phxp.Development(*project)
		}
		if err != nil {
			return err
		}
		endpoint, err = phxp.DeriveEndpoint(identity, *role)
		if err != nil {
			return err
		}
	}

	handoff, err := phxp.Listen(phxp.ListenerConfig{
		Endpoint: endpoint,
		ErrorLog: func(err error) { log.Printf("PHXP: %v", err) },
	})
	if err != nil {
		return err
	}
	defer handoff.Close()

	direct, err := net.ListenTCP("tcp", tcpAddress)
	if err != nil {
		return fmt.Errorf("listen for ordinary HTTPS: %w", err)
	}
	defer direct.Close()
	combined, err := phxp.JoinListeners(direct, handoff)
	if err != nil {
		return err
	}
	defer combined.Close()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		local, _ := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
		protocol := request.Proto
		fmt.Fprintf(writer,
			"phxp Go handoff example\npeer=%s\nlocal=%s\nrequest=%s %s %s\ntls_server_name=%s\n",
			request.RemoteAddr, addressString(local), request.Method, request.URL.RequestURI(),
			protocol, request.TLS.ServerName)
	})
	server := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errorsChannel := make(chan error, 1)
	go func() {
		errorsChannel <- server.ServeTLS(combined, *certificate, *key)
	}()

	log.Printf("ordinary HTTPS: https://%s", direct.Addr())
	log.Printf("PHXP endpoint: %s", endpoint.Path)
	log.Printf("ordinary and PHXP connections share one net/http Server and Handler pipeline")
	log.Printf("HTTP/1.1 enabled; HTTP/2 enabled through standard net/http TLS negotiation")

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	select {
	case <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		return nil
	case err := <-errorsChannel:
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func addressString(address net.Addr) string {
	if address == nil {
		return "unknown"
	}
	return address.String()
}
