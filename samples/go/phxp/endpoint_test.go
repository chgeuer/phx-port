package phxp

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestEndpointDerivationMatchesPHXPAuthority(t *testing.T) {
	development := Identity{kind: DevelopmentIdentity, value: "/srv/contoso"}
	developmentEndpoint, err := deriveEndpoint(development, "https", "/run/user/1000")
	if err != nil {
		t.Fatal(err)
	}

	hash := endpointHash("/srv/contoso", "https")
	want := filepath.Join("/run/user/1000", "handoff", hash+".sock")
	if developmentEndpoint.Path != want || !developmentEndpoint.ValidateRuntimeRoot {
		t.Fatalf("development endpoint = %#v, want %s with runtime validation", developmentEndpoint, want)
	}

	production := Identity{kind: ProductionIdentity, value: "contoso-web"}
	productionEndpoint, err := deriveEndpoint(production, "https", "/service/runtime")
	if err != nil {
		t.Fatal(err)
	}
	want = filepath.Join("/service/runtime", "handoff", endpointHash("contoso-web", "https")+".sock")
	if productionEndpoint.Path != want || productionEndpoint.ValidateRuntimeRoot {
		t.Fatalf("production endpoint = %#v, want %s without root validation", productionEndpoint, want)
	}
}

func TestProductionEndpointRequiresRuntimeOverrideOutsideLinux(t *testing.T) {
	production := Identity{kind: ProductionIdentity, value: "contoso-web"}
	if _, err := deriveEndpointForOS(production, "https", "", "darwin"); err == nil {
		t.Fatal("macOS production endpoint derived without an explicit runtime root")
	}
	endpoint, err := deriveEndpointForOS(production, "https", "/service/runtime", "darwin")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Path != filepath.Join(
		"/service/runtime", "handoff", endpointHash("contoso-web", "https")+".sock",
	) {
		t.Fatalf("macOS production endpoint = %s", endpoint.Path)
	}
}

func TestDevelopmentIdentityCanonicalizesProjectPath(t *testing.T) {
	directory := testDirectory(t)
	actual := filepath.Join(directory, "actual")
	if err := os.Mkdir(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	identity, err := Development(link)
	if err != nil {
		t.Fatal(err)
	}
	if identity.value != actual {
		t.Fatalf("canonical identity = %q, want %q", identity.value, actual)
	}
}

func TestEndpointSecurityAndStaleHandling(t *testing.T) {
	directory := testDirectory(t)
	endpoint := filepath.Join(directory, "receiver.sock")
	listener, err := Listen(ListenerConfig{Endpoint: Endpoint{Path: endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("endpoint mode = %v", info.Mode())
	}
	if _, err := Listen(ListenerConfig{Endpoint: Endpoint{Path: endpoint}}); err == nil {
		t.Fatal("second listener replaced a live endpoint")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(endpoint); !os.IsNotExist(err) {
		t.Fatalf("owned endpoint was not removed: %v", err)
	}

	if err := os.WriteFile(endpoint, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(ListenerConfig{Endpoint: Endpoint{Path: endpoint}}); err == nil {
		t.Fatal("regular file at endpoint was replaced")
	}
}

func TestStaleSocketEndpointIsReplaced(t *testing.T) {
	directory := testDirectory(t)
	endpoint := filepath.Join(directory, "receiver.sock")
	fd, err := bindControlSocket(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := listenControlSocket(fd, 1); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Close(fd); err != nil {
		t.Fatal(err)
	}

	listener, err := Listen(ListenerConfig{Endpoint: Endpoint{Path: endpoint}})
	if err != nil {
		t.Fatalf("replace stale endpoint: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestChangedStaleSocketEndpointIsNotRemoved(t *testing.T) {
	directory := testDirectory(t)
	endpoint := filepath.Join(directory, "receiver.sock")
	stale, err := bindControlSocket(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := listenControlSocket(stale, 1); err != nil {
		t.Fatal(err)
	}
	staleIdentity, err := inspectSocket(endpoint, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Close(stale); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(endpoint); err != nil {
		t.Fatal(err)
	}

	replacement, err := bindControlSocket(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(replacement)
	if err := listenControlSocket(replacement, 1); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleEndpoint(endpoint, staleIdentity); err == nil {
		t.Fatal("changed endpoint identity was removed")
	}
	if _, err := os.Lstat(endpoint); err != nil {
		t.Fatalf("replacement endpoint was removed: %v", err)
	}
}

func TestEndpointSecurityRejectsOpenAndSymlinkedDirectories(t *testing.T) {
	directory := testDirectory(t)
	open := filepath.Join(directory, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(open); err == nil {
		t.Fatal("group-readable endpoint directory was accepted")
	}

	actual := filepath.Join(directory, "actual")
	if err := os.Mkdir(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	runtimeLink := filepath.Join(directory, "runtime")
	if err := os.Symlink(actual, runtimeLink); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runtimeLink, "handoff", "receiver.sock")
	if err := prepareEndpoint(path, true); err == nil {
		t.Fatal("symlinked runtime root was accepted")
	}
	if _, err := os.Lstat(filepath.Join(actual, "handoff")); !os.IsNotExist(err) {
		t.Fatalf("validation followed runtime symlink: %v", err)
	}
}

func TestIdentityValidation(t *testing.T) {
	for _, value := range []string{"a", "contoso-web", "api.v2_worker"} {
		if err := ValidateWorkloadID(value); err != nil {
			t.Errorf("valid workload %q: %v", value, err)
		}

		if err := ValidateRole(value); err != nil {
			t.Errorf("valid role %q: %v", value, err)
		}

	}
	for _, value := range []string{"", "-contoso", "contoso-", "Contoso", "../contoso"} {
		if err := ValidateWorkloadID(value); err == nil {
			t.Errorf("invalid workload %q was accepted", value)
		}
	}
	if err := ValidateRole("-https"); err != nil {
		t.Fatalf("role grammar is more restrictive than authority: %v", err)
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Fatal("tests must run on a supported platform")
	}
}

func TestListenerRejectsInvalidControlConnectionLimit(t *testing.T) {
	_, err := Listen(ListenerConfig{
		Endpoint:              Endpoint{Path: filepath.Join(testDirectory(t), "receiver.sock")},
		MaxControlConnections: -1,
	})
	if err == nil {
		t.Fatal("negative control connection limit was accepted")
	}
}

func testDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".phxp-test-")
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(absolute); err != nil {
			t.Errorf("remove test directory: %v", err)
		}
	})
	return absolute
}
