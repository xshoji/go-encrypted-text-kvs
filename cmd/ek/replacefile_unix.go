//go:build !windows

package main

import "os"

func replaceFile(tmpPath, path string) error {
	return os.Rename(tmpPath, path)
}
