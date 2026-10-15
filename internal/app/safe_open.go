package app

import "errors"

var errNoFollowSymlink = errors.New("refusing symlink input")
