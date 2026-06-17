//go:build !darwin && !linux && !windows

package main

import "fmt"

func ensureSupportedOS() error { return fmt.Errorf(unsupportedOSError) }
