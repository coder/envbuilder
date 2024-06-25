package ebutil

import (
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	time "time"

	"github.com/coder/envbuilder/internal/notcodersdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/prometheus/procfs"
)

var expectedLibMultiarchDir = map[string]string{
	"amd64":   "/usr/lib/x86_64-linux-gnu",
	"arm64":   "/usr/lib/aarch64-linux-gnu",
	"ppc64le": "/usr/lib/powerpc64le-linux-gnu",
}

func Test_tempRemount(t *testing.T) {
	t.Parallel()

	t.Run("OK", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/var/lib/modules").Return(&fakeFileInfo{name: "modules", isDir: true}, nil)
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/var/lib/modules", "/.test/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/var/lib/modules", 0).Times(1).Return(nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/.test/var/lib/modules").Return(&fakeFileInfo{name: "modules", isDir: true}, nil)
		mm.EXPECT().MkdirAll("/var/lib/modules", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/.test/var/lib/modules", "/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/.test/var/lib/modules", 0).Times(1).Return(nil)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.NoError(t, err)
		// sync.Once should handle multiple remount calls
		_ = remount()
	})

	t.Run("OKFile", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/usr/bin/utility:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/usr/bin/utility").Return(&fakeFileInfo{name: "modules", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/.test/usr/bin", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/.test/usr/bin/utility", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Mount("/usr/bin/utility", "/.test/usr/bin/utility", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/usr/bin/utility", 0).Times(1).Return(nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/.test/usr/bin/utility").Return(&fakeFileInfo{name: "modules", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/usr/bin", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/usr/bin/utility", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Mount("/.test/usr/bin/utility", "/usr/bin/utility", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/.test/usr/bin/utility", 0).Times(1).Return(nil)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.NoError(t, err)
		// sync.Once should handle multiple remount calls
		_ = remount()
	})

	t.Run("OKLib", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/usr/lib64/lib.so.1:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return([]os.DirEntry{
			&fakeDirEntry{
				name: "lib.so",
				mode: os.ModeSymlink,
			},
			&fakeDirEntry{
				name: "lib.so.1",
			},
			&fakeDirEntry{
				name: "lib-other.so",
				mode: os.ModeSymlink,
			},
			&fakeDirEntry{
				name: "lib-other.so.1",
			},
			&fakeDirEntry{
				name:  "something.d",
				isDir: true,
				mode:  os.ModeDir,
			},
		}, nil)
		mm.EXPECT().EvalSymlinks("/usr/lib64/lib.so").Return("/usr/lib64/lib.so.1", nil)
		mm.EXPECT().EvalSymlinks("/usr/lib64/lib-other.so").Return("/usr/lib64/lib-other.so.1", nil)
		mm.EXPECT().Stat("/usr/lib64/lib.so.1").Return(&fakeFileInfo{name: "lib.so.1", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/.test/usr/lib64", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/.test/usr/lib64/lib.so.1", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Rename("/usr/lib64/lib.so", "/.test/usr/lib64/lib.so").Return(nil)
		mm.EXPECT().Mount("/usr/lib64/lib.so.1", "/.test/usr/lib64/lib.so.1", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/usr/lib64/lib.so.1", 0).Times(1).Return(nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/.test/usr/lib64/lib.so.1").Return(&fakeFileInfo{name: "lib.so.1", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/usr/lib64", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/usr/lib64/lib.so.1", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Rename("/.test/usr/lib64/lib.so", "/usr/lib64/lib.so").Return(nil)
		mm.EXPECT().Mount("/.test/usr/lib64/lib.so.1", "/usr/lib64/lib.so.1", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/.test/usr/lib64/lib.so.1", 0).Times(1).Return(nil)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.NoError(t, err)
		// sync.Once should handle multiple remount calls
		_ = remount()
	})

	t.Run("OKLibDebian", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/usr/lib64/lib.so.1:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return([]os.DirEntry{
			&fakeDirEntry{
				name: "lib.so",
				mode: os.ModeSymlink,
			},
			&fakeDirEntry{
				name: "lib.so.1",
			},
			&fakeDirEntry{
				name: "lib-other.so",
				mode: os.ModeSymlink,
			},
			&fakeDirEntry{
				name: "lib-other.so.1",
			},
			&fakeDirEntry{
				name:  "something.d",
				isDir: true,
				mode:  os.ModeDir,
			},
		}, nil)
		mm.EXPECT().EvalSymlinks("/usr/lib64/lib.so").Return("lib.so.1", nil)
		mm.EXPECT().EvalSymlinks("/usr/lib64/lib-other.so").Return("lib-other.so.1", nil)
		mm.EXPECT().Stat("/usr/lib64/lib.so.1").Return(&fakeFileInfo{name: "lib.so.1", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/.test/usr/lib64", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/.test/usr/lib64/lib.so.1", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Rename("/usr/lib64/lib.so", "/.test/usr/lib64/lib.so").Return(nil)
		mm.EXPECT().Mount("/usr/lib64/lib.so.1", "/.test/usr/lib64/lib.so.1", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/usr/lib64/lib.so.1", 0).Times(1).Return(nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, nil)
		mm.EXPECT().Stat("/.test/usr/lib64/lib.so.1").Return(&fakeFileInfo{name: "lib.so.1", isDir: false}, nil)
		mm.EXPECT().MkdirAll(expectedLibMultiarchDir[runtime.GOARCH], os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile(expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so.1", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Rename("/.test/usr/lib64/lib.so", expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so").Return(nil)
		mm.EXPECT().Mount("/.test/usr/lib64/lib.so.1", expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so.1", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/.test/usr/lib64/lib.so.1", 0).Times(1).Return(nil)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.NoError(t, err)
		// sync.Once should handle multiple remount calls
		_ = remount()
	})

	t.Run("OKLibFromDebianToNotDebian", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so.1:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, nil)
		mm.EXPECT().ReadDir(expectedLibMultiarchDir[runtime.GOARCH]).Return([]os.DirEntry{
			&fakeDirEntry{
				name: "lib.so",
				mode: os.ModeSymlink,
			},
			&fakeDirEntry{
				name: "lib.so.1",
			},
			&fakeDirEntry{
				name: "lib-other.so",
				mode: os.ModeSymlink,
			},
			&fakeDirEntry{
				name: "lib-other.so.1",
			},
			&fakeDirEntry{
				name:  "something.d",
				isDir: true,
				mode:  os.ModeDir,
			},
		}, nil)
		mm.EXPECT().EvalSymlinks(expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so").Return(expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so.1", nil)
		mm.EXPECT().EvalSymlinks(expectedLibMultiarchDir[runtime.GOARCH]+"/lib-other.so").Return(expectedLibMultiarchDir[runtime.GOARCH]+"/usr/lib64/lib-other.so.1", nil)
		mm.EXPECT().Stat(expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so.1").Return(&fakeFileInfo{name: "lib.so.1", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/.test"+expectedLibMultiarchDir[runtime.GOARCH], os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/.test"+expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so.1", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Rename(expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so", "/.test"+expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so").Return(nil)
		mm.EXPECT().Mount(expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so.1", "/.test"+expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so.1", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount(expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so.1", 0).Times(1).Return(nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/.test"+expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so.1").Return(&fakeFileInfo{name: "lib.so.1", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/usr/lib64", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/usr/lib64/lib.so.1", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Rename("/.test"+expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so", "/usr/lib64/lib.so").Return(nil)
		mm.EXPECT().Mount("/.test"+expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so.1", "/usr/lib64/lib.so.1", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/.test"+expectedLibMultiarchDir[runtime.GOARCH]+"/lib.so.1", 0).Times(1).Return(nil)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.NoError(t, err)
		// sync.Once should handle multiple remount calls
		_ = remount()
	})

	t.Run("OKLibNoSymlink", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/usr/lib64/lib.so.1:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return([]os.DirEntry{
			&fakeDirEntry{
				name: "lib.so.1",
			},
		}, nil)
		mm.EXPECT().Stat("/usr/lib64/lib.so.1").Return(&fakeFileInfo{name: "lib.so.1", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/.test/usr/lib64", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/.test/usr/lib64/lib.so.1", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Mount("/usr/lib64/lib.so.1", "/.test/usr/lib64/lib.so.1", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/usr/lib64/lib.so.1", 0).Times(1).Return(nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/.test/usr/lib64/lib.so.1").Return(&fakeFileInfo{name: "lib.so.1", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/usr/lib64", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/usr/lib64/lib.so.1", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Mount("/.test/usr/lib64/lib.so.1", "/usr/lib64/lib.so.1", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/.test/usr/lib64/lib.so.1", 0).Times(1).Return(nil)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.NoError(t, err)
		// sync.Once should handle multiple remount calls
		_ = remount()
	})

	t.Run("IgnorePrefixes", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, os.ErrNotExist)

		remount, err := tempRemount(mm, fakeLog(t), "/.test", "/var/lib")
		require.NoError(t, err)
		err = remount()
		require.NoError(t, err)
	})

	t.Run("ErrGetMounts", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mm.EXPECT().GetMounts().Return(nil, assert.AnError)
		remount, err := tempRemount(mm, fakeLog(t), "/.test", "/var/lib")
		require.ErrorContains(t, err, assert.AnError.Error())
		err = remount()
		require.NoError(t, err)
	})

	t.Run("ErrStatDebianVersion", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.ErrorContains(t, err, assert.AnError.Error())
		err = remount()
		require.NoError(t, err)
	})

	t.Run("ErrReadLibDir", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.ErrorContains(t, err, assert.AnError.Error())
		err = remount()
		require.NoError(t, err)
	})

	t.Run("ErrMkdirAll", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/var/lib/modules").Return(&fakeFileInfo{name: "modules", isDir: true}, nil)
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0o750)).Times(1).Return(assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.ErrorContains(t, err, assert.AnError.Error())
		err = remount()
		require.NoError(t, err)
	})

	t.Run("ErrOpenFile", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/usr/bin/utility:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/usr/bin/utility").Return(&fakeFileInfo{name: "modules", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/.test/usr/bin", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/.test/usr/bin/utility", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(nil, assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.ErrorContains(t, err, assert.AnError.Error())
		err = remount()
		require.NoError(t, err)
	})

	t.Run("ErrMoveSymlink", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/usr/lib64/lib.so.1:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return([]os.DirEntry{
			&fakeDirEntry{
				name: "lib.so",
				mode: os.ModeSymlink,
			},
			&fakeDirEntry{
				name: "lib.so.1",
			},
			&fakeDirEntry{
				name: "lib-other.so",
				mode: os.ModeSymlink,
			},
			&fakeDirEntry{
				name: "lib-other.so.1",
			},
			&fakeDirEntry{
				name:  "something.d",
				isDir: true,
				mode:  os.ModeDir,
			},
		}, nil)
		mm.EXPECT().EvalSymlinks("/usr/lib64/lib.so").Return("lib.so.1", nil)
		mm.EXPECT().EvalSymlinks("/usr/lib64/lib-other.so").Return("lib-other.so.1", nil)
		mm.EXPECT().Stat("/usr/lib64/lib.so.1").Return(&fakeFileInfo{name: "lib.so.1", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/.test/usr/lib64", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/.test/usr/lib64/lib.so.1", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Rename("/usr/lib64/lib.so", "/.test/usr/lib64/lib.so").Return(assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.ErrorContains(t, err, assert.AnError.Error())
		err = remount()
		require.NoError(t, err)
	})

	t.Run("ErrMountBind", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/var/lib/modules").Return(&fakeFileInfo{name: "modules", isDir: true}, nil)
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/var/lib/modules", "/.test/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.ErrorContains(t, err, assert.AnError.Error())
		err = remount()
		require.NoError(t, err)
	})

	t.Run("ErrUnmount", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/var/lib/modules").Return(&fakeFileInfo{name: "modules", isDir: true}, nil)
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/var/lib/modules", "/.test/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/var/lib/modules", 0).Times(1).Return(assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.ErrorContains(t, err, assert.AnError.Error())
		err = remount()
		require.NoError(t, err)
	})

	t.Run("ErrRemountStatDebianVersion", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/var/lib/modules").Return(&fakeFileInfo{name: "modules", isDir: true}, nil)
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/var/lib/modules", "/.test/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/var/lib/modules", 0).Times(1).Return(nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.ErrorContains(t, err, assert.AnError.Error())
	})

	t.Run("ErrRemountMkdirAll", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/var/lib/modules").Return(&fakeFileInfo{name: "modules", isDir: true}, nil)
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/var/lib/modules", "/.test/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/var/lib/modules", 0).Times(1).Return(nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/.test/var/lib/modules").Return(&fakeFileInfo{name: "modules", isDir: true}, nil)
		mm.EXPECT().MkdirAll("/var/lib/modules", os.FileMode(0o750)).Times(1).Return(assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.ErrorContains(t, err, assert.AnError.Error())
	})

	t.Run("ErrRemountOpenFile", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/usr/bin/utility:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/usr/bin/utility").Return(&fakeFileInfo{name: "modules", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/.test/usr/bin", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/.test/usr/bin/utility", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Mount("/usr/bin/utility", "/.test/usr/bin/utility", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/usr/bin/utility", 0).Times(1).Return(nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/.test/usr/bin/utility").Return(&fakeFileInfo{name: "modules", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/usr/bin", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/usr/bin/utility", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(nil, assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.ErrorContains(t, err, assert.AnError.Error())
	})

	t.Run("ErrRemountMoveSymlink", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/usr/lib64/lib.so.1:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return([]os.DirEntry{
			&fakeDirEntry{
				name: "lib.so",
				mode: os.ModeSymlink,
			},
			&fakeDirEntry{
				name: "lib.so.1",
			},
			&fakeDirEntry{
				name: "lib-other.so",
				mode: os.ModeSymlink,
			},
			&fakeDirEntry{
				name: "lib-other.so.1",
			},
			&fakeDirEntry{
				name:  "something.d",
				isDir: true,
				mode:  os.ModeDir,
			},
		}, nil)
		mm.EXPECT().EvalSymlinks("/usr/lib64/lib.so").Return("/usr/lib64/lib.so.1", nil)
		mm.EXPECT().EvalSymlinks("/usr/lib64/lib-other.so").Return("/usr/lib64/lib-other.so.1", nil)
		mm.EXPECT().Stat("/usr/lib64/lib.so.1").Return(&fakeFileInfo{name: "lib.so.1", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/.test/usr/lib64", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/.test/usr/lib64/lib.so.1", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Rename("/usr/lib64/lib.so", "/.test/usr/lib64/lib.so").Return(nil)
		mm.EXPECT().Mount("/usr/lib64/lib.so.1", "/.test/usr/lib64/lib.so.1", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/usr/lib64/lib.so.1", 0).Times(1).Return(nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/.test/usr/lib64/lib.so.1").Return(&fakeFileInfo{name: "lib.so.1", isDir: false}, nil)
		mm.EXPECT().MkdirAll("/usr/lib64", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().OpenFile("/usr/lib64/lib.so.1", os.O_CREATE, os.FileMode(0o640)).Times(1).Return(new(os.File), nil)
		mm.EXPECT().Rename("/.test/usr/lib64/lib.so", "/usr/lib64/lib.so").Return(assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.ErrorContains(t, err, assert.AnError.Error())
	})

	t.Run("ErrRemountMountBind", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/var/lib/modules").Return(&fakeFileInfo{name: "modules", isDir: true}, nil)
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/var/lib/modules", "/.test/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/var/lib/modules", 0).Times(1).Return(nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/.test/var/lib/modules").Return(&fakeFileInfo{name: "modules", isDir: true}, nil)
		mm.EXPECT().MkdirAll("/var/lib/modules", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/.test/var/lib/modules", "/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.ErrorContains(t, err, assert.AnError.Error())
	})

	t.Run("ErrRemountUnmount", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().ReadDir("/usr/lib64").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/var/lib/modules").Return(&fakeFileInfo{name: "modules", isDir: true}, nil)
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/var/lib/modules", "/.test/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/var/lib/modules", 0).Times(1).Return(nil)
		mm.EXPECT().Stat("/etc/debian_version").Return(nil, os.ErrNotExist)
		mm.EXPECT().Stat("/.test/var/lib/modules").Return(&fakeFileInfo{name: "modules", isDir: true}, nil)
		mm.EXPECT().MkdirAll("/var/lib/modules", os.FileMode(0o750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/.test/var/lib/modules", "/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/.test/var/lib/modules", 0).Times(1).Return(assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.ErrorContains(t, err, assert.AnError.Error())
	})
}

// convenience function for generating a slice of *procfs.MountInfo
func fakeMounts(mounts ...string) []*procfs.MountInfo {
	m := make([]*procfs.MountInfo, 0)
	for _, s := range mounts {
		mp := s
		o := make(map[string]string)
		if strings.HasSuffix(mp, ":ro") {
			mp = strings.TrimSuffix(mp, ":ro")
			o["ro"] = "true"
		}
		m = append(m, &procfs.MountInfo{MountPoint: mp, Options: o})
	}
	return m
}

func fakeLog(t *testing.T) func(notcodersdk.LogLevel, string, ...any) {
	t.Helper()
	return func(_ notcodersdk.LogLevel, s string, a ...any) {
		t.Logf(s, a...)
	}
}

type fakeFileInfo struct {
	name  string
	isDir bool
}

func (fi *fakeFileInfo) Name() string       { return fi.name }
func (fi *fakeFileInfo) Size() int64        { return 0 }
func (fi *fakeFileInfo) Mode() os.FileMode  { return 0 }
func (fi *fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fi *fakeFileInfo) IsDir() bool        { return fi.isDir }
func (fi *fakeFileInfo) Sys() any           { return nil }

var _ os.FileInfo = &fakeFileInfo{}

type fakeDirEntry struct {
	name  string
	isDir bool
	mode  os.FileMode
}

func (de *fakeDirEntry) Name() string               { return de.name }
func (de *fakeDirEntry) IsDir() bool                { return de.isDir }
func (de *fakeDirEntry) Type() os.FileMode          { return de.mode }
func (de *fakeDirEntry) Info() (os.FileInfo, error) { return nil, nil }

var _ os.DirEntry = &fakeDirEntry{}
