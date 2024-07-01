package ebutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Container runtimes like NVIDIA mount individual libraries into the container
// (e.g. `<libname>.so.<driver_version>`) and create symlinks for them
// (e.g. `<libname>.so.1`). This code helps with finding the right library
// directory for the target Linux distribution as well as locating the symlinks.
//
// Please see [#143 (comment)] for further details.
//
// [#143 (comment)]: https://github.com/coder/envbuilder/issues/143#issuecomment-2192405828

// Based on https://github.com/NVIDIA/libnvidia-container/blob/v1.15.0/src/common.h#L29
const usrLibDir = "/usr/lib64"

const debianVersionFile = "/etc/debian_version"

// libraryDirectoryPath returns the library directory. It returns a multiarch
// directory if the distribution is Debian or a derivative.
//
// Based on https://github.com/NVIDIA/libnvidia-container/blob/v1.15.0/src/nvc_container.c#L152-L165
func libraryDirectoryPath(m mounter) (string, error) {
	// Debian and its derivatives use a multiarch directory scheme.
	if _, err := m.Stat(debianVersionFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("check if debian: %w", err)
	} else if err == nil {
		return usrLibMultiarchDir, nil
	}

	return usrLibDir, nil
}

// libraryDirectorySymlinks returns a mapping of each library (basename) with a
// list of their symlinks (basename). Libraries with no symlinks do not appear
// in the mapping.
func libraryDirectorySymlinks(m mounter, libDir string) (map[string][]string, error) {
	des, err := m.ReadDir(libDir)
	if err != nil {
		return nil, fmt.Errorf("read directory %s: %w", libDir, err)
	}

	libsSymlinks := make(map[string][]string)
	for _, de := range des {
		if de.IsDir() {
			continue
		}

		if de.Type()&os.ModeSymlink != os.ModeSymlink {
			// Not a symlink. Skip.
			continue
		}

		symlink := filepath.Join(libDir, de.Name())
		path, err := m.EvalSymlinks(symlink)
		if err != nil {
			return nil, fmt.Errorf("eval symlink %s: %w", symlink, err)
		}

		path = filepath.Base(path)
		if _, ok := libsSymlinks[path]; !ok {
			libsSymlinks[path] = make([]string, 0, 1)
		}

		libsSymlinks[path] = append(libsSymlinks[path], de.Name())
	}

	return libsSymlinks, nil
}

// moveLibSymlinks moves a list of symlinks from source to destination directory.
func moveLibSymlinks(m mounter, symlinks []string, srcDir, destDir string) error {
	for _, l := range symlinks {
		oldpath := filepath.Join(srcDir, l)
		newpath := filepath.Join(destDir, l)
		if err := m.Rename(oldpath, newpath); err != nil {
			return fmt.Errorf("move symlink %s => %s: %w", oldpath, newpath, err)
		}
	}
	return nil
}
