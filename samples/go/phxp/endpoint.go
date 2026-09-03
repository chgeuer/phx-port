package phxp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

const productionRuntimeRoot = "/run/phx-port"

type IdentityKind uint8

const (
	DevelopmentIdentity IdentityKind = iota + 1
	ProductionIdentity
)

type Identity struct {
	kind  IdentityKind
	value string
}

type Endpoint struct {
	Path                string
	ValidateRuntimeRoot bool
}

func Development(project string) (Identity, error) {
	absolute, err := filepath.Abs(project)
	if err != nil {
		return Identity{}, fmt.Errorf("make project path absolute: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return Identity{}, fmt.Errorf("canonicalize project path: %w", err)
	}
	return Identity{kind: DevelopmentIdentity, value: canonical}, nil
}

func Production(workloadID string) (Identity, error) {
	if err := ValidateWorkloadID(workloadID); err != nil {
		return Identity{}, err
	}
	return Identity{kind: ProductionIdentity, value: workloadID}, nil
}

func ValidateWorkloadID(value string) error {
	if len(value) < 1 || len(value) > 128 || !isLowerAlphaNumeric(value[0]) ||
		!isLowerAlphaNumeric(value[len(value)-1]) {
		return errors.New("logical workload ID must contain 1 through 128 lowercase ASCII letters, digits, '.', '_', or '-', and start and end with a letter or digit")
	}
	for i := range len(value) {
		c := value[i]
		if !isLowerAlphaNumeric(c) && c != '.' && c != '_' && c != '-' {
			return errors.New("logical workload ID must contain 1 through 128 lowercase ASCII letters, digits, '.', '_', or '-', and start and end with a letter or digit")
		}
	}
	return nil
}

func ValidateRole(role string) error {
	if len(role) < 1 || len(role) > 128 {
		return errors.New("role must contain 1 through 128 lowercase ASCII letters, digits, '.', '_', or '-'")
	}
	for i := range len(role) {
		c := role[i]
		if !isLowerAlphaNumeric(c) && c != '.' && c != '_' && c != '-' {
			return errors.New("role must contain 1 through 128 lowercase ASCII letters, digits, '.', '_', or '-'")
		}
	}
	return nil
}

func DeriveEndpoint(identity Identity, role string) (Endpoint, error) {
	return deriveEndpoint(identity, role, os.Getenv("PHX_PORT_RUNTIME_DIR"))
}

func deriveEndpoint(identity Identity, role, runtimeOverride string) (Endpoint, error) {
	return deriveEndpointForOS(identity, role, runtimeOverride, runtime.GOOS)
}

func deriveEndpointForOS(identity Identity, role, runtimeOverride, goos string) (Endpoint, error) {
	if err := ValidateRole(role); err != nil {
		return Endpoint{}, err
	}
	switch identity.kind {
	case DevelopmentIdentity:
		if identity.value == "" || !filepath.IsAbs(identity.value) {
			return Endpoint{}, errors.New("development identity must be a canonical absolute project path")
		}
	case ProductionIdentity:
		if err := ValidateWorkloadID(identity.value); err != nil {
			return Endpoint{}, err
		}
	default:
		return Endpoint{}, errors.New("unknown PHXP endpoint identity")
	}

	hash := endpointHash(identity.value, role)
	var root string
	validateRuntimeRoot := identity.kind == DevelopmentIdentity
	if runtimeOverride != "" {
		root = runtimeOverride
	} else if identity.kind == ProductionIdentity {
		if goos != "linux" {
			return Endpoint{}, errors.New("production PHXP endpoints require PHX_PORT_RUNTIME_DIR outside Linux")
		}
		root = productionRuntimeRoot
	} else {
		var err error
		root, err = developmentRuntimeRoot()
		if err != nil {
			return Endpoint{}, err
		}
	}
	path := filepath.Join(root, "handoff", hash+".sock")
	if len(path) > unixPathMax {
		return Endpoint{}, fmt.Errorf("PHXP endpoint path is too long: %s", path)
	}
	return Endpoint{Path: path, ValidateRuntimeRoot: validateRuntimeRoot}, nil
}

func endpointHash(identity, role string) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(identity))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(role))
	return hex.EncodeToString(digest.Sum(nil))
}

func isLowerAlphaNumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create PHXP directory %s: %w", path, err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect PHXP directory %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("PHXP directory %s is not a directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(stat.Uid) != uint32(os.Geteuid()) {
		return fmt.Errorf("PHXP directory %s belongs to a different user", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("PHXP directory %s must not grant group or other permissions", path)
	}
	return nil
}

func prepareEndpoint(path string, validateRuntimeRoot bool) error {
	parent := filepath.Dir(path)
	if parent == "." || parent == string(filepath.Separator) {
		return errors.New("PHXP endpoint has no private parent directory")
	}
	if validateRuntimeRoot {
		if err := ensurePrivateDirectory(filepath.Dir(parent)); err != nil {
			return err
		}
	}
	if err := ensurePrivateDirectory(parent); err != nil {
		return err
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect PHXP endpoint %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket PHXP path %s", path)
	}
	staleIdentity, err := inspectSocket(path, false)
	if err != nil {
		return err
	}
	if endpointIsLive(path) {
		return fmt.Errorf("another PHXP receiver is already listening at %s", path)
	}
	return removeStaleEndpoint(path, staleIdentity)
}

func removeStaleEndpoint(path string, staleIdentity endpointIdentity) error {
	currentIdentity, err := inspectSocket(path, false)
	if err != nil {
		return fmt.Errorf("reinspect stale PHXP endpoint %s: %w", path, err)
	}
	if currentIdentity != staleIdentity {
		return fmt.Errorf("PHXP endpoint %s changed during stale-socket inspection", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale PHXP endpoint %s: %w", path, err)
	}
	return nil
}

func inspectSocket(path string, requireMode bool) (endpointIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return endpointIdentity{}, fmt.Errorf("inspect PHXP endpoint %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return endpointIdentity{}, fmt.Errorf("PHXP endpoint %s is not a socket", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(stat.Uid) != uint32(os.Geteuid()) {
		return endpointIdentity{}, fmt.Errorf("PHXP endpoint %s belongs to a different user", path)
	}
	if requireMode && info.Mode().Perm() != 0o600 {
		return endpointIdentity{}, fmt.Errorf("PHXP endpoint %s must have mode 0600", path)
	}
	return endpointIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func removeEndpointIfOwned(path string, identity endpointIdentity) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != identity.device || uint64(stat.Ino) != identity.inode {
		return
	}
	_ = os.Remove(path)
}

func developmentRuntimeRoot() (string, error) {
	switch runtime.GOOS {
	case "linux":
		runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
		if runtimeDir == "" {
			return "", errors.New("XDG_RUNTIME_DIR is unavailable; set it or specify a PHXP endpoint")
		}
		return filepath.Join(runtimeDir, "phx-port"), nil
	case "darwin":
		return fmt.Sprintf("/tmp/phx-port-%d", os.Geteuid()), nil
	default:
		return "", fmt.Errorf("PHXP requires Linux or macOS, not %s", runtime.GOOS)
	}
}
