package workingdir

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_WorkingDir(t *testing.T) {
	t.Parallel()

	t.Run("Default", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, defaultWorkingDirBase+"/foo", Default.Join("foo"))
		require.Equal(t, defaultWorkingDirBase, Default.Path())
		require.Equal(t, defaultWorkingDirBase+"/built", Default.Built())
		require.Equal(t, defaultWorkingDirBase+"/image", Default.Image())
	})

	t.Run("ZeroValue", func(t *testing.T) {
		t.Parallel()
		var md WorkingDir
		require.Equal(t, defaultWorkingDirBase+"/foo", md.Join("foo"))
		require.Equal(t, defaultWorkingDirBase, md.Path())
		require.Equal(t, defaultWorkingDirBase+"/built", md.Built())
		require.Equal(t, defaultWorkingDirBase+"/image", md.Image())
	})

	t.Run("At", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		md := At(tmpDir)
		require.Equal(t, tmpDir+"/foo", md.Join("foo"))
		require.Equal(t, tmpDir, md.Path())
		require.Equal(t, tmpDir+"/built", md.Built())
		require.Equal(t, tmpDir+"/image", md.Image())
	})
}
