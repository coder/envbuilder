package magicdir

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_MagicDir(t *testing.T) {
	t.Parallel()

	t.Run("Default", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, defaultMagicDirBase+"/foo", Default.Join("foo"))
		require.Equal(t, defaultMagicDirBase, Default.Path())
		require.Equal(t, defaultMagicDirBase+"/built", Default.Built())
		require.Equal(t, defaultMagicDirBase+"/image", Default.Image())
	})

	t.Run("ZeroValue", func(t *testing.T) {
		t.Parallel()
		var md MagicDir
		require.Equal(t, defaultMagicDirBase+"/foo", md.Join("foo"))
		require.Equal(t, defaultMagicDirBase, md.Path())
		require.Equal(t, defaultMagicDirBase+"/built", md.Built())
		require.Equal(t, defaultMagicDirBase+"/image", md.Image())
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
