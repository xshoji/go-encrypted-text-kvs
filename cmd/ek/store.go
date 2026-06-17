package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.in/yaml.v3"
)

type storeEnvelope struct {
	Version   int             `yaml:"version"`
	Type      string          `yaml:"type"`
	KeyID     string          `yaml:"key_id"`
	CreatedAt string          `yaml:"created_at"`
	UpdatedAt string          `yaml:"updated_at"`
	Cipher    envelopeCipher  `yaml:"cipher"`
	Payload   envelopePayload `yaml:"payload"`
}

type envelopeCipher struct {
	Algorithm string `yaml:"algorithm"`
	Nonce     string `yaml:"nonce"`
}
type envelopePayload struct {
	Encoding   string `yaml:"encoding"`
	Ciphertext string `yaml:"ciphertext"`
}
type storePlaintext struct {
	Version int               `yaml:"version"`
	Type    string            `yaml:"type"`
	Entries map[string]string `yaml:"entries"`
}

type recoveryFile struct {
	Version   int          `yaml:"version"`
	Type      string       `yaml:"type"`
	KeyID     string       `yaml:"key_id"`
	CreatedAt string       `yaml:"created_at"`
	KDF       recoveryKDF  `yaml:"kdf"`
	Wrap      recoveryWrap `yaml:"wrap"`
}
type recoveryKDF struct {
	Algorithm string `yaml:"algorithm"`
	Time      uint32 `yaml:"time"`
	MemoryKiB uint32 `yaml:"memory_kib"`
	Threads   uint8  `yaml:"threads"`
	Salt      string `yaml:"salt"`
}
type recoveryWrap struct {
	Algorithm  string `yaml:"algorithm"`
	Nonce      string `yaml:"nonce"`
	Ciphertext string `yaml:"ciphertext"`
}

type softwareKeyFile struct {
	Version   int          `yaml:"version"`
	Type      string       `yaml:"type"`
	KeyID     string       `yaml:"key_id"`
	CreatedAt string       `yaml:"created_at"`
	KDF       recoveryKDF  `yaml:"kdf"`
	Wrap      recoveryWrap `yaml:"wrap"`
}

func readStoreEnvelope(path string) (*storeEnvelope, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("insecure file permissions: expected 0600")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env storeEnvelope
	if err := yaml.Unmarshal(content, &env); err != nil {
		return nil, fmt.Errorf("parse store envelope: %w", err)
	}
	if env.Version != 1 {
		return nil, fmt.Errorf("unsupported store version %d", env.Version)
	}
	if env.Type != "encrypted-text-kvs" {
		return nil, fmt.Errorf("unexpected store type %q", env.Type)
	}
	if strings.TrimSpace(env.KeyID) == "" {
		return nil, fmt.Errorf("store key_id is missing")
	}
	return &env, nil
}

func encryptStore(store storePlaintext, env *storeEnvelope, key []byte, now time.Time) ([]byte, error) {
	if store.Entries == nil {
		store.Entries = map[string]string{}
	}
	store.Version = 1
	store.Type = "kvs"
	plain, err := yaml.Marshal(store)
	if err != nil {
		return nil, err
	}
	return encryptStoreYAML(plain, env, key, now)
}

func encryptStoreYAML(plain []byte, env *storeEnvelope, key []byte, now time.Time) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("unexpected key length %d", len(key))
	}
	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	env.Version = 1
	env.Type = "encrypted-text-kvs"
	env.UpdatedAt = now.Format(time.RFC3339)
	env.Cipher = envelopeCipher{Algorithm: "xchacha20poly1305", Nonce: base64.StdEncoding.EncodeToString(nonce)}
	env.Payload = envelopePayload{Encoding: "base64", Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, storeAAD(env)))}
	return yaml.Marshal(env)
}

func decryptStoreYAML(env *storeEnvelope, key []byte) ([]byte, error) {
	if env.Cipher.Algorithm != "xchacha20poly1305" {
		return nil, fmt.Errorf("unsupported cipher %q", env.Cipher.Algorithm)
	}
	if env.Payload.Encoding != "base64" {
		return nil, fmt.Errorf("unsupported payload encoding %q", env.Payload.Encoding)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Cipher.Nonce)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("invalid nonce length")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Payload.Ciphertext)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < chacha20poly1305.Overhead {
		return nil, fmt.Errorf("invalid ciphertext length")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, storeAAD(env))
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func decryptStore(env *storeEnvelope, key []byte) (storePlaintext, error) {
	plain, err := decryptStoreYAML(env, key)
	if err != nil {
		return storePlaintext{}, err
	}
	return parseStorePlaintextYAML(plain)
}

func parseStorePlaintextYAML(plain []byte) (storePlaintext, error) {
	var store storePlaintext
	if err := yaml.Unmarshal(plain, &store); err != nil {
		return storePlaintext{}, fmt.Errorf("parse plaintext YAML: %w", err)
	}
	if store.Version != 1 {
		return storePlaintext{}, validationError{fmt.Sprintf("unsupported plaintext store version %d", store.Version)}
	}
	if store.Type != "kvs" {
		return storePlaintext{}, validationError{fmt.Sprintf("unexpected plaintext store type %q", store.Type)}
	}
	if store.Entries == nil {
		store.Entries = map[string]string{}
	}
	for k, v := range store.Entries {
		if err := validateKey(k); err != nil {
			return storePlaintext{}, fmt.Errorf("invalid entry key %q: %w", k, err)
		}
		if err := validateValue(v); err != nil {
			return storePlaintext{}, fmt.Errorf("invalid value for key %q: %w", k, err)
		}
	}
	return store, nil
}

func newRecoveryFile(keyID string, key []byte, passphrase []byte, now time.Time) (*recoveryFile, error) {
	salt, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	params := recoveryKDF{Algorithm: "argon2id", Time: 3, MemoryKiB: 64 * 1024, Threads: 4, Salt: base64.StdEncoding.EncodeToString(salt)}
	wrapKey := deriveRecoveryWrapKey(passphrase, salt, params)
	defer zeroBytes(wrapKey)
	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, err
	}
	ad := []byte("go-encrypted-text-kvs|recovery-key|" + keyID)
	return &recoveryFile{Version: 1, Type: "ek-recovery-key", KeyID: keyID, CreatedAt: now.Format(time.RFC3339), KDF: params, Wrap: recoveryWrap{Algorithm: "xchacha20poly1305", Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, key, ad))}}, nil
}

func unwrapRecoveryKey(file *recoveryFile, passphrase []byte) ([]byte, error) {
	if file.Version != 1 {
		return nil, fmt.Errorf("unsupported recovery file version %d", file.Version)
	}
	if file.Type != "ek-recovery-key" {
		return nil, fmt.Errorf("unexpected recovery file type %q", file.Type)
	}
	if file.KDF.Algorithm != "argon2id" || file.Wrap.Algorithm != "xchacha20poly1305" {
		return nil, fmt.Errorf("unsupported recovery file")
	}
	if file.KDF.Time != 3 || file.KDF.MemoryKiB != 64*1024 || file.KDF.Threads != 4 {
		return nil, fmt.Errorf("unsupported recovery file KDF parameters")
	}
	salt, err := base64.StdEncoding.DecodeString(file.KDF.Salt)
	if err != nil {
		return nil, err
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("invalid recovery salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(file.Wrap.Nonce)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("invalid recovery nonce length")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(file.Wrap.Ciphertext)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < chacha20poly1305.Overhead {
		return nil, fmt.Errorf("invalid recovery ciphertext length")
	}
	wrapKey := deriveRecoveryWrapKey(passphrase, salt, file.KDF)
	defer zeroBytes(wrapKey)
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, err
	}
	key, err := aead.Open(nil, nonce, ciphertext, []byte("go-encrypted-text-kvs|recovery-key|"+file.KeyID))
	if err != nil {
		return nil, err
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("unexpected recovered key length %d", len(key))
	}
	return key, nil
}

func deriveRecoveryWrapKey(passphrase, salt []byte, params recoveryKDF) []byte {
	return argon2.IDKey(passphrase, salt, params.Time, params.MemoryKiB, params.Threads, uint32(chacha20poly1305.KeySize))
}

func newSoftwareKeyFile(keyID string, key []byte, passphrase []byte, now time.Time) (*softwareKeyFile, error) {
	salt, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	params := recoveryKDF{Algorithm: "argon2id", Time: 3, MemoryKiB: 64 * 1024, Threads: 4, Salt: base64.StdEncoding.EncodeToString(salt)}
	wrapKey := deriveRecoveryWrapKey(passphrase, salt, params)
	defer zeroBytes(wrapKey)
	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, err
	}
	ad := []byte("go-encrypted-text-kvs|software-key|" + keyID)
	return &softwareKeyFile{Version: 1, Type: "ek-software-key", KeyID: keyID, CreatedAt: now.Format(time.RFC3339), KDF: params, Wrap: recoveryWrap{Algorithm: "xchacha20poly1305", Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, key, ad))}}, nil
}

func unwrapSoftwareKey(file *softwareKeyFile, passphrase []byte) ([]byte, error) {
	if file.Version != 1 {
		return nil, fmt.Errorf("unsupported software key version %d", file.Version)
	}
	if file.Type != "ek-software-key" {
		return nil, fmt.Errorf("unexpected software key type %q", file.Type)
	}
	if file.KDF.Algorithm != "argon2id" || file.Wrap.Algorithm != "xchacha20poly1305" {
		return nil, fmt.Errorf("unsupported software key")
	}
	if file.KDF.Time != 3 || file.KDF.MemoryKiB != 64*1024 || file.KDF.Threads != 4 {
		return nil, fmt.Errorf("unsupported software key KDF parameters")
	}
	salt, err := base64.StdEncoding.DecodeString(file.KDF.Salt)
	if err != nil {
		return nil, err
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("invalid software key salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(file.Wrap.Nonce)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("invalid software key nonce length")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(file.Wrap.Ciphertext)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < chacha20poly1305.Overhead {
		return nil, fmt.Errorf("invalid software key ciphertext length")
	}
	wrapKey := deriveRecoveryWrapKey(passphrase, salt, file.KDF)
	defer zeroBytes(wrapKey)
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, err
	}
	key, err := aead.Open(nil, nonce, ciphertext, []byte("go-encrypted-text-kvs|software-key|"+file.KeyID))
	if err != nil {
		return nil, err
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("unexpected software key length %d", len(key))
	}
	return key, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ek-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return replaceFile(tmpPath, path)
}

func randomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}
func randomID() (string, error) {
	b, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
func storeAAD(env *storeEnvelope) []byte {
	return []byte(fmt.Sprintf("go-encrypted-text-kvs:v1:%s:%s:%s", env.Type, env.KeyID, env.Cipher.Algorithm))
}
func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
	runtime.KeepAlive(data)
}

var keyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validateKey(key string) error {
	if !keyPattern.MatchString(key) {
		return validationError{"invalid key name: must match [A-Za-z_][A-Za-z0-9_]*"}
	}
	return nil
}
func validateValue(value string) error {
	if strings.ContainsAny(value, "\r\x00") {
		return validationError{"invalid value: carriage return and NUL bytes are not supported"}
	}
	return nil
}
func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
