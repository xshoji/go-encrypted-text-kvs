//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

func keystoreStore(keyID string, key []byte) error {
	if keystoreExists(keyID) {
		return fmt.Errorf("decrypt key already exists in OS keystore")
	}
	fmt.Fprintln(os.Stderr, "warning: using passphrase-protected local key storage; this is not OS/hardware-backed")
	passphrase, err := promptPassphrase("Local key passphrase: ")
	if err != nil {
		return err
	}
	defer zeroBytes(passphrase)
	confirm, err := promptPassphrase("Confirm local key passphrase: ")
	if err != nil {
		return err
	}
	defer zeroBytes(confirm)
	if string(passphrase) != string(confirm) {
		return fmt.Errorf("local key passphrases did not match")
	}
	file, err := newSoftwareKeyFile(keyID, key, passphrase, time.Now().UTC())
	if err != nil {
		return err
	}
	encoded, err := yaml.Marshal(file)
	if err != nil {
		return err
	}
	path, err := softwareKeyPath(keyID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, encoded, 0o600)
}

func keystoreLoad(keyID string, prompt string) ([]byte, error) {
	path, err := softwareKeyPath(keyID)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("local software key not found: run \"ek recovery import-key\" to restore it")
		}
		return nil, err
	}
	var file softwareKeyFile
	if err := yaml.Unmarshal(content, &file); err != nil {
		return nil, fmt.Errorf("parse local software key: %w", err)
	}
	if file.KeyID != keyID {
		return nil, fmt.Errorf("local software key_id %q does not match store key_id %q", file.KeyID, keyID)
	}
	passphrase, err := promptPassphrase("Local key passphrase: ")
	if err != nil {
		return nil, err
	}
	defer zeroBytes(passphrase)
	key, err := unwrapSoftwareKey(&file, passphrase)
	if err != nil {
		return nil, fmt.Errorf("wrong local key passphrase or corrupted local software key")
	}
	return key, nil
}

func keystoreDelete(keyID string) error {
	path, err := softwareKeyPath(keyID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func keystoreExists(keyID string) bool {
	path, err := softwareKeyPath(keyID)
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

func keystoreName() string { return "software keystore" }

func softwareKeyPath(keyID string) (string, error) {
	base, err := softwareKeystoreBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "keys", keyID+".yaml"), nil
}

func softwareKeystoreBaseDir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "ek"), nil
}
