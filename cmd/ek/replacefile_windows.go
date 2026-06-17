//go:build windows

package main

import "os"

func replaceFile(tmpPath, path string) error {
	_ = os.Remove(path)
	return os.Rename(tmpPath, path)
}
