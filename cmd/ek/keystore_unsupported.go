//go:build !darwin

package main

import "fmt"

const unsupportedOSError = "unsupported OS: ek currently supports macOS Keychain only"

func keychainStore(keyID string, key []byte) error { return fmt.Errorf(unsupportedOSError) }
func keychainLoad(keyID string, prompt string) ([]byte, error) {
	return nil, fmt.Errorf(unsupportedOSError)
}
func keychainDelete(keyID string) error { return fmt.Errorf(unsupportedOSError) }
func keychainExists(keyID string) bool  { return false }
