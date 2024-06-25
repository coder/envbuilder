package ebutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/coder/envbuilder/internal/notcodersdk"
	"github.com/hashicorp/go-multierror"
	"github.com/prometheus/procfs"
)

// TempRemount iterates through all read-only mounted filesystems, bind-mounts them at dest,
// and unmounts them from their original source. All mount points underneath ignorePrefixes
// will not be touched.
//
// Some container runtimes such as sysbox-runc will mount in `/lib/modules` read-only.
// See https://github.com/nestybox/sysbox/issues/564
// This trips us up because:
//  1. We call a Kaniko library function `util.DeleteFilesystem` that does exactly what it says
//     on the tin. If this hits a read-only volume mounted in, unhappiness is the result.
//  2. After deleting the filesystem and building the image, we extract it to the filesystem.
//     If some paths mounted in via volume are present at that time, unhappiness is also likely
//     to result -- especially in case of read-only mounts.
//
// To work around this we move the mounts out of the way temporarily by bind-mounting them
// while we do our thing, and move them back when we're done.
//
// It is the responsibility of the caller to call the returned function
// to restore the original mount points. If an error is encountered while attempting to perform
// the operation, calling the returned function will make a best-effort attempt to restore
// the original state.
func TempRemount(logf func(notcodersdk.LogLevel, string, ...any), dest string, ignorePrefixes ...string) (restore func() error, err error,
) {
	return tempRemount(&realMounter{}, logf, dest, ignorePrefixes...)
}

func tempRemount(m mounter, logf func(notcodersdk.LogLevel, string, ...any), base string, ignorePrefixes ...string) (restore func() error, err error) {
	mountInfos, err := m.GetMounts()
	if err != nil {
		return func() error { return nil }, fmt.Errorf("get mounts: %w", err)
	}

	// temp move of all ro mounts
	mounts := map[string]string{}
	var restoreOnce sync.Once
	var merr error
	// closer to attempt to restore original mount points
	restore = func() error {
		restoreOnce.Do(func() {
			for orig, moved := range mounts {
				if err := remount(m, moved, orig); err != nil {
					merr = multierror.Append(merr, fmt.Errorf("restore mount: %w", err))
				}
			}
		})
		return merr
	}

outer:
	for _, mountInfo := range mountInfos {
		// TODO: do this for all mounts
		if _, ok := mountInfo.Options["ro"]; !ok {
			logf(notcodersdk.LogLevelTrace, "skip rw mount %s", mountInfo.MountPoint)
			continue
		}

		for _, prefix := range ignorePrefixes {
			if strings.HasPrefix(mountInfo.MountPoint, prefix) {
				logf(notcodersdk.LogLevelTrace, "skip mount %s under ignored prefix %s", mountInfo.MountPoint, prefix)
				continue outer
			}
		}

		src := mountInfo.MountPoint
		dest := filepath.Join(base, src)
		if err := remount(m, src, dest); err != nil {
			return restore, fmt.Errorf("temp remount: %w", err)
		}

		mounts[src] = dest
	}

	return restore, nil
}

func remount(m mounter, src, dest string) error {
	stat, err := m.Stat(src)
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	var destDir string
	if stat.IsDir() {
		destDir = dest
	} else {
		destDir = filepath.Dir(dest)
	}
	if err := m.MkdirAll(destDir, 0o750); err != nil {
		return fmt.Errorf("ensure path: %w", err)
	}
	if !stat.IsDir() {
		f, err := m.OpenFile(dest, os.O_CREATE, 0o640)
		if err != nil {
			return fmt.Errorf("ensure file path: %w", err)
		}
		defer f.Close()
	}
	if err := m.Mount(src, dest, "bind", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mount %s => %s: %w", src, dest, err)
	}
	if err := m.Unmount(src, 0); err != nil {
		return fmt.Errorf("unmount orig src %s: %w", src, err)
	}
	return nil
}

// mounter is an interface to system-level calls used by TempRemount.
type mounter interface {
	// GetMounts wraps procfs.GetMounts
	GetMounts() ([]*procfs.MountInfo, error)
	// Stat wraps os.Stat
	Stat(string) (os.FileInfo, error)
	// MkdirAll wraps os.MkdirAll
	MkdirAll(string, os.FileMode) error
	// OpenFile wraps os.OpenFile
	OpenFile(string, int, os.FileMode) (*os.File, error)
	// Mount wraps syscall.Mount
	Mount(string, string, string, uintptr, string) error
	// Unmount wraps syscall.Unmount
	Unmount(string, int) error
}

// realMounter implements mounter and actually does the thing.
type realMounter struct{}

var _ mounter = &realMounter{}

func (m *realMounter) Mount(src string, dest string, fstype string, flags uintptr, data string) error {
	return syscall.Mount(src, dest, fstype, flags, data)
}

func (m *realMounter) Unmount(tgt string, flags int) error {
	return syscall.Unmount(tgt, flags)
}

func (m *realMounter) GetMounts() ([]*procfs.MountInfo, error) {
	return procfs.GetMounts()
}

func (m *realMounter) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (m *realMounter) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm)
}

func (m *realMounter) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}
