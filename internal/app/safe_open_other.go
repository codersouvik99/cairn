//go:build !linux

package app

import "os"

// The case directory is a Linux deployment boundary. Other platforms retain
// the existing Lstat check while using the standard portable file opener.
func openInputNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
