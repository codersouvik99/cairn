//go:build linux

package app

import (
	"errors"
	"os"
	"syscall"
)

// openInputNoFollow closes the Lstat/Open race for the final input path
// component. The descriptor remains tied to the file that was opened even if
// the directory entry is replaced after this call.
func openInputNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errNoFollowSymlink
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
