package ebutil

import (
	"github.com/coder/coder/v2/codersdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/prometheus/procfs"
)

func Test_tempRemount(t *testing.T) {
	t.Parallel()

	t.Run("OK", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/var/lib/modules", "/.test/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/var/lib/modules", 0).Times(1).Return(nil)
		mm.EXPECT().MkdirAll("/var/lib/modules", os.FileMode(0750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/.test/var/lib/modules", "/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/.test/var/lib/modules", 0).Times(1).Return(nil)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.NoError(t, err)
		err = remount()
		require.NoError(t, err)
	})

	t.Run("IgnorePrefixes", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)

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

	t.Run("ErrMkdirAll", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0750)).Times(1).Return(assert.AnError)

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
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0750)).Times(1).Return(nil)
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
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/var/lib/modules", "/.test/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/var/lib/modules", 0).Times(1).Return(assert.AnError)

		remount, err := tempRemount(mm, fakeLog(t), "/.test")
		require.ErrorContains(t, err, assert.AnError.Error())
		err = remount()
		require.NoError(t, err)
	})

	t.Run("ErrRemountMkdirAll", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mm := NewMockmounter(ctrl)
		mounts := fakeMounts("/home", "/var/lib/modules:ro", "/proc", "/sys")

		mm.EXPECT().GetMounts().Return(mounts, nil)
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/var/lib/modules", "/.test/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/var/lib/modules", 0).Times(1).Return(nil)
		mm.EXPECT().MkdirAll("/var/lib/modules", os.FileMode(0750)).Times(1).Return(assert.AnError)

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
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/var/lib/modules", "/.test/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/var/lib/modules", 0).Times(1).Return(nil)
		mm.EXPECT().MkdirAll("/var/lib/modules", os.FileMode(0750)).Times(1).Return(nil)
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
		mm.EXPECT().MkdirAll("/.test/var/lib/modules", os.FileMode(0750)).Times(1).Return(nil)
		mm.EXPECT().Mount("/var/lib/modules", "/.test/var/lib/modules", "bind", uintptr(syscall.MS_BIND), "").Times(1).Return(nil)
		mm.EXPECT().Unmount("/var/lib/modules", 0).Times(1).Return(nil)
		mm.EXPECT().MkdirAll("/var/lib/modules", os.FileMode(0750)).Times(1).Return(nil)
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

func fakeLog(t *testing.T) func(codersdk.LogLevel, string, ...any) {
	t.Helper()
	return func(_ codersdk.LogLevel, s string, a ...any) {
		t.Logf(s, a...)
	}
}
