package chmodfs

import (
	"os"

	"github.com/go-git/go-billy/v5"
)

func New(fs billy.Filesystem) billy.Filesystem {
	return &osfsWithChmod{
		Filesystem: fs,
	}
}

type osfsWithChmod struct {
	billy.Filesystem
}

func (fs *osfsWithChmod) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(name, mode)
}
