//go:build windows

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"
)

type windowsDPAPIKeyFile struct {
	Version    int              `yaml:"version"`
	Type       string           `yaml:"type"`
	KeyID      string           `yaml:"key_id"`
	CreatedAt  string           `yaml:"created_at"`
	Scope      string           `yaml:"scope"`
	Protection string           `yaml:"protection"`
	Blob       windowsDPAPIBlob `yaml:"blob"`
}

type windowsDPAPIBlob struct {
	Encoding string `yaml:"encoding"`
	Data     string `yaml:"data"`
}

func keystoreStore(keyID string, key []byte) error {
	if len(key) != chacha20poly1305.KeySize {
		return fmt.Errorf("unexpected key length %d", len(key))
	}
	if err := validateKeyID(keyID); err != nil {
		return err
	}
	path, err := windowsDPAPIKeyPath(keyID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("decrypt key already exists in OS keystore")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	protected, err := dpapiProtect(keyID, key)
	if err != nil {
		return err
	}
	file := windowsDPAPIKeyFile{
		Version:    1,
		Type:       "ek-windows-dpapi-key",
		KeyID:      keyID,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		Scope:      "current_user",
		Protection: "windows-dpapi",
		Blob: windowsDPAPIBlob{
			Encoding: "base64",
			Data:     base64.StdEncoding.EncodeToString(protected),
		},
	}
	encoded, err := yaml.Marshal(file)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, encoded, 0o600)
}

func keystoreLoad(keyID string, prompt string) ([]byte, error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, err
	}
	path, err := windowsDPAPIKeyPath(keyID)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("Windows DPAPI key not found: run \"ek recovery import-key\" to restore it")
		}
		return nil, err
	}
	var file windowsDPAPIKeyFile
	if err := yaml.Unmarshal(content, &file); err != nil {
		return nil, fmt.Errorf("parse Windows DPAPI key: %w", err)
	}
	if err := validateWindowsDPAPIKeyFile(file, keyID); err != nil {
		return nil, err
	}
	protected, err := base64.StdEncoding.DecodeString(file.Blob.Data)
	if err != nil {
		return nil, err
	}
	key, err := dpapiUnprotect(keyID, protected)
	if err != nil {
		return nil, fmt.Errorf("failed to unprotect Windows DPAPI key: not the same Windows user/machine or key file is corrupted")
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("unexpected Windows DPAPI key length %d", len(key))
	}
	return key, nil
}

func keystoreDelete(keyID string) error {
	path, err := windowsDPAPIKeyPath(keyID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func keystoreExists(keyID string) bool {
	path, err := windowsDPAPIKeyPath(keyID)
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

func keystoreName() string { return "Windows DPAPI" }

func windowsDPAPIKeyPath(keyID string) (string, error) {
	if err := validateKeyID(keyID); err != nil {
		return "", err
	}
	base := os.Getenv("LocalAppData")
	if base == "" {
		base = os.Getenv("AppData")
	}
	if base == "" {
		return "", fmt.Errorf("LocalAppData is not set")
	}
	return filepath.Join(base, "ek", "dpapi-keys", keyID+".yaml"), nil
}

func validateWindowsDPAPIKeyFile(file windowsDPAPIKeyFile, keyID string) error {
	if file.Version != 1 {
		return fmt.Errorf("unsupported Windows DPAPI key version %d", file.Version)
	}
	if file.Type != "ek-windows-dpapi-key" {
		return fmt.Errorf("unexpected Windows DPAPI key type %q", file.Type)
	}
	if file.KeyID != keyID {
		return fmt.Errorf("Windows DPAPI key_id %q does not match store key_id %q", file.KeyID, keyID)
	}
	if file.Scope != "current_user" || file.Protection != "windows-dpapi" || file.Blob.Encoding != "base64" {
		return fmt.Errorf("unsupported Windows DPAPI key file")
	}
	return nil
}

func dpapiProtect(keyID string, plain []byte) ([]byte, error) {
	in := dataBlob(plain)
	entropy := []byte("go-encrypted-text-kvs|windows-dpapi|v1|" + keyID)
	ent := dataBlob(entropy)
	desc, err := windows.UTF16PtrFromString("go-encrypted-text-kvs DEK " + keyID)
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(in, desc, ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}

func dpapiUnprotect(keyID string, protected []byte) ([]byte, error) {
	in := dataBlob(protected)
	entropy := []byte("go-encrypted-text-kvs|windows-dpapi|v1|" + keyID)
	ent := dataBlob(entropy)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(in, nil, ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}

func dataBlob(data []byte) *windows.DataBlob {
	if len(data) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}
