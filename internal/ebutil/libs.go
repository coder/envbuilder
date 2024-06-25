package ebutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Based on https://github.com/NVIDIA/libnvidia-container/blob/v1.15.0/src/common.h#L29

const usrLibDir = "/usr/lib64"

const debianVersionFile = "/etc/debian_version"

// getLibDir returns the library directory. It returns a multiarch directory if
// the distribution is Debian or a derivative.
//
// Based on https://github.com/NVIDIA/libnvidia-container/blob/v1.15.0/src/nvc_container.c#L152-L165
func getLibDir(m mounter) (string, error) {
	// Debian and its derivatives use a multiarch directory scheme.
	if _, err := m.Stat(debianVersionFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("check if debian: %w", err)
	} else if err == nil {
		return usrLibMultiarchDir, nil
	}

	return usrLibDir, nil
}

// getLibsSymlinks returns the stats for all library symlinks if the library
// directory exists.
func getLibsSymlinks(m mounter, libDir string) (map[string][]string, error) {
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
