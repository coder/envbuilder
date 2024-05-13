package ebutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/coder/coder/v2/codersdk"
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
func TempRemount(logf func(codersdk.LogLevel, string, ...any), dest string, ignorePrefixes ...string) (restore func() error, err error,
) {
	return tempRemount(&realMounter{}, logf, dest, ignorePrefixes...)
}

func tempRemount(m mounter, logf func(codersdk.LogLevel, string, ...any), dest string, ignorePrefixes ...string) (restore func() error, err error) {
	mountInfos, err := m.GetMounts()
	if err != nil {
		return func() error { return nil }, fmt.Errorf("get mounts: %w", err)
	}

	// temp move of all ro mounts
	mounts := map[string]string{}
	// closer to attempt to restore original mount points
	restore = func() error {
		for src, tgt := range mounts {
			err := m.MkdirAll(src, 0o750)
			if err != nil {
				return fmt.Errorf("recreate original mountpoint %s: %w", src, err)
			}

			err = m.Mount(tgt, src, "bind", syscall.MS_BIND, "")
			if err != nil {
				return fmt.Errorf("bind mount %s => %s: %w", tgt, src, err)
			}

			err = m.Unmount(tgt, 0)
			if err != nil {
				return fmt.Errorf("unmount temporary dest %s: %w", tgt, err)
			}
		}
		return nil
	}

outer:
	for _, mountInfo := range mountInfos {
		if _, ok := mountInfo.Options["ro"]; !ok {
			logf(codersdk.LogLevelTrace, "skip rw mount %s", mountInfo.MountPoint)
			continue
		}

		for _, prefix := range ignorePrefixes {
			if strings.HasPrefix(mountInfo.MountPoint, prefix) {
				logf(codersdk.LogLevelTrace, "skip mount %s under ignored prefix %s", mountInfo.MountPoint, prefix)
				continue outer
			}
		}

		src := mountInfo.MountPoint
		tgt := filepath.Join("/", dest, src)
		err := m.MkdirAll(tgt, 0o750)
		if err != nil {
			return restore, fmt.Errorf("create temp mountpoint %s: %w", dest, err)
		}

		err = m.Mount(src, tgt, "bind", syscall.MS_BIND, "")
		if err != nil {
			return restore, fmt.Errorf("bind mount %s => %s: %s", src, dest, err.Error())
		}
		err = m.Unmount(src, 0)
		if err != nil {
			return restore, fmt.Errorf("temp unmount src %s: %s", src, err.Error())
		}

		mounts[src] = tgt
	}

	return restore, nil
}

// mounter is an interface to system-level calls used by TempRemount.
type mounter interface {
	// GetMounts wraps procfs.GetMounts
	GetMounts() ([]*procfs.MountInfo, error)
	// MkdirAll wraps os.MkdirAll
	MkdirAll(string, os.FileMode) error
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
