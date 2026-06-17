//go:build !darwin && !linux && !windows

package main

import "fmt"

const unsupportedOSError = "unsupported OS: ek supports macOS Keychain and Linux/Windows software keystore"

func keystoreStore(keyID string, key []byte) error { return fmt.Errorf(unsupportedOSError) }
func keystoreLoad(keyID string, prompt string) ([]byte, error) {
	return nil, fmt.Errorf(unsupportedOSError)
}
func keystoreDelete(keyID string) error { return fmt.Errorf(unsupportedOSError) }
func keystoreExists(keyID string) bool  { return false }
func keystoreName() string              { return "keystore" }
