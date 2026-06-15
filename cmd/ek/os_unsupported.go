//go:build !darwin

package main

import "fmt"

func ensureSupportedOS() error { return fmt.Errorf(unsupportedOSError) }
