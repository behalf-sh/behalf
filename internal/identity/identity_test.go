package identity

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestGenerateSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveDevice(dir, k); err != nil {
		t.Fatal(err)
	}
	got, err := LoadDevice(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.JKT != k.JKT {
		t.Fatalf("jkt after roundtrip = %s, want %s", got.JKT, k.JKT)
	}
	if !got.Public.Equal(k.Public) || !got.Private.Equal(k.Private) {
		t.Fatal("key material differs after roundtrip")
	}
}

func TestPrivateKeyFileMode(t *testing.T) {
	dir := t.TempDir()
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveDevice(dir, k); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(DeviceKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("device key mode = %o, want 0600", fi.Mode().Perm())
	}
	if _, err := LoadOrGenerateEmitter(dir); err != nil {
		t.Fatal(err)
	}
	fi, err = os.Stat(EmitterKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("emitter key mode = %o, want 0600", fi.Mode().Perm())
	}
}

func TestJKTShape(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	// RFC 7638 thumbprint: 43 base64url chars (schema $defs/jkt).
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(k.JKT) {
		t.Fatalf("jkt %q does not match the schema jkt pattern", k.JKT)
	}
}

func TestEmitterIsDistinctFromDevice(t *testing.T) {
	dir := t.TempDir()
	dev, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveDevice(dir, dev); err != nil {
		t.Fatal(err)
	}
	em, err := LoadOrGenerateEmitter(dir)
	if err != nil {
		t.Fatal(err)
	}
	if em.JKT == dev.JKT {
		t.Fatal("emitter key must be distinct from the device key")
	}
	// Loading again returns the same emitter, not a new one.
	em2, err := LoadOrGenerateEmitter(dir)
	if err != nil {
		t.Fatal(err)
	}
	if em2.JKT != em.JKT {
		t.Fatal("emitter key must be stable across loads")
	}
}

func TestNextEmitterCounterMonotonic(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	for want := 0; want < 3; want++ {
		got, err := NextEmitterCounter(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("counter = %d, want %d", got, want)
		}
	}
}

func TestResolveDir(t *testing.T) {
	if got, err := ResolveDir("/explicit"); err != nil || got != "/explicit" {
		t.Fatalf("explicit dir: got %q, %v", got, err)
	}
	t.Setenv(EnvHome, "/from-env")
	if got, err := ResolveDir(""); err != nil || got != "/from-env" {
		t.Fatalf("env dir: got %q, %v", got, err)
	}
	t.Setenv(EnvHome, "")
	got, err := ResolveDir("")
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(home, DefaultDirName) {
		t.Fatalf("default dir = %q, want %q", got, filepath.Join(home, DefaultDirName))
	}
}

func TestLoadDeviceMissingIsNotExist(t *testing.T) {
	_, err := LoadDevice(t.TempDir())
	if !os.IsNotExist(err) {
		t.Fatalf("missing device key: err = %v, want fs not-exist", err)
	}
}
