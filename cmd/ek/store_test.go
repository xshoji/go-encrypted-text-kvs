package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.in/yaml.v3"
)

func TestValidateKey(t *testing.T) {
	for _, key := range []string{"API_TOKEN", "_LOCAL", "A1"} {
		if err := validateKey(key); err != nil {
			t.Fatalf("valid key %q: %v", key, err)
		}
	}
	for _, key := range []string{"", "1TOKEN", "api-token", "foo.bar"} {
		if err := validateKey(key); err == nil {
			t.Fatalf("invalid key %q passed", key)
		}
	}
}

func TestValidateValue(t *testing.T) {
	if err := validateValue("foo bar"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"foo\nbar", "foo\rbar", "foo\x00bar"} {
		if err := validateValue(value); err == nil {
			t.Fatalf("invalid value %q passed", value)
		}
	}
}

func TestShellQuote(t *testing.T) {
	got := shellQuote("foo'bar")
	want := `'foo'"'"'bar'`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseGlobalFlagsStopsAtCommand(t *testing.T) {
	filePath, rest, err := parseGlobalFlags([]string{"--file", "store.yaml", "set", "FOO", "--file"})
	if err != nil {
		t.Fatal(err)
	}
	if filePath != "store.yaml" {
		t.Fatalf("filePath = %q", filePath)
	}
	if strings.Join(rest, " ") != "set FOO --file" {
		t.Fatalf("rest = %#v", rest)
	}
}

func TestRandomIDIsUUIDv4(t *testing.T) {
	id, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !pattern.MatchString(id) {
		t.Fatalf("not uuid v4: %s", id)
	}
}

func TestEncryptDecryptStore(t *testing.T) {
	key, err := randomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	env := &storeEnvelope{Version: 1, Type: "encrypted-text-kvs", KeyID: "test", CreatedAt: now.Format(time.RFC3339)}
	encoded, err := encryptStore(storePlaintext{Entries: map[string]string{"API_TOKEN": "secret"}}, env, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("ciphertext contains plaintext value")
	}
	readEnv, err := readEnvelopeBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	store, err := decryptStore(readEnv, key)
	if err != nil {
		t.Fatal(err)
	}
	if store.Entries["API_TOKEN"] != "secret" {
		t.Fatalf("unexpected value %q", store.Entries["API_TOKEN"])
	}
	wrong, _ := randomBytes(32)
	if _, err := decryptStore(readEnv, wrong); err == nil {
		t.Fatal("decrypt with wrong key succeeded")
	}
}

func TestDecryptStoreRejectsInvalidNonceLength(t *testing.T) {
	key, err := randomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	env := &storeEnvelope{
		Version: 1,
		Type:    "encrypted-text-kvs",
		KeyID:   "test",
		Cipher:  envelopeCipher{Algorithm: "xchacha20poly1305", Nonce: base64.StdEncoding.EncodeToString([]byte("short"))},
		Payload: envelopePayload{Encoding: "base64", Ciphertext: base64.StdEncoding.EncodeToString(make([]byte, chacha20poly1305.Overhead))},
	}
	if _, err := decryptStore(env, key); err == nil {
		t.Fatal("invalid nonce length passed")
	}
}

func TestUnwrapRecoveryKeyRejectsUnsupportedKDFBeforeDerive(t *testing.T) {
	recovery := &recoveryFile{
		Version: 1,
		Type:    "ek-recovery-key",
		KeyID:   "test",
		KDF:     recoveryKDF{Algorithm: "argon2id", Time: 999, MemoryKiB: 1 << 30, Threads: 4, Salt: base64.StdEncoding.EncodeToString(make([]byte, 16))},
		Wrap:    recoveryWrap{Algorithm: "xchacha20poly1305", Nonce: base64.StdEncoding.EncodeToString(make([]byte, chacha20poly1305.NonceSizeX)), Ciphertext: base64.StdEncoding.EncodeToString(make([]byte, chacha20poly1305.Overhead))},
	}
	if _, err := unwrapRecoveryKey(recovery, []byte("passphrase")); err == nil {
		t.Fatal("unsupported KDF params passed")
	}
}

func TestReadStoreEnvelopeRejectsInsecurePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.yaml")
	content := []byte("version: 1\ntype: encrypted-text-kvs\nkey_id: test\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readStoreEnvelope(path); err == nil || !strings.Contains(err.Error(), "insecure file permissions") {
		t.Fatalf("expected insecure permissions error, got %v", err)
	}
}

func readEnvelopeBytes(data []byte) (*storeEnvelope, error) {
	var env storeEnvelope
	if err := yaml.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	return &env, nil
}
