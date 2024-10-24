package options_test

import (
	"os"
	"testing"

	"github.com/coder/envbuilder/options"
	"github.com/stretchr/testify/assert"
)

func TestGetBuildSecrets(t *testing.T) {
	t.Parallel()

	t.Run("no secrets", func(t *testing.T) {
		t.Parallel()

		// given
		os.Clearenv()

		// when
		secrets := options.GetBuildSecrets(os.Environ())

		// then
		assert.Empty(t, secrets)
	})

	t.Run("single secret", func(t *testing.T) {
		t.Parallel()

		// given
		os.Clearenv()
		os.Setenv("ENVBUILDER_BUILD_SECRET_FOO", "bar")

		// when
		secrets := options.GetBuildSecrets(os.Environ())

		// then
		assert.Equal(t, []string{"FOO=bar"}, secrets)
	})

	t.Run("multiple secrets", func(t *testing.T) {
		t.Parallel()

		// given
		os.Clearenv()
		os.Setenv("ENVBUILDER_BUILD_SECRET_FOO", "bar")
		os.Setenv("ENVBUILDER_BUILD_SECRET_BAZ", "qux")

		// when
		secrets := options.GetBuildSecrets(os.Environ())

		// then
		assert.ElementsMatch(t, []string{"FOO=bar", "BAZ=qux"}, secrets)
	})
}

func TestClearBuildSecrets(t *testing.T) {
	t.Parallel()

	t.Run("no secrets", func(t *testing.T) {
		t.Parallel()

		// given
		os.Clearenv()

		// when
		options.ClearBuildSecrets()

		// then
		assert.Empty(t, os.Environ())
	})

	t.Run("single secret", func(t *testing.T) {
		t.Parallel()

		// given
		os.Clearenv()
		os.Setenv("ENVBUILDER_BUILD_SECRET_FOO", "bar")

		// when
		options.ClearBuildSecrets()

		// then
		assert.Empty(t, os.Environ())
	})

	t.Run("multiple secrets", func(t *testing.T) {
		t.Parallel()

		// given
		os.Clearenv()
		os.Setenv("ENVBUILDER_BUILD_SECRET_FOO", "bar")
		os.Setenv("ENVBUILDER_BUILD_SECRET_BAZ", "qux")

		// when
		options.ClearBuildSecrets()

		// then
		assert.Empty(t, os.Environ())
	})

	t.Run("only build secrets are cleared", func(t *testing.T) {
		t.Parallel()

		// given
		os.Clearenv()
		os.Setenv("ENVBUILDER_BUILD_SECRET_FOO", "foo")
		os.Setenv("FOO", "foo")

		// when
		options.ClearBuildSecrets()

		// then
		assert.Equal(t, []string{"FOO=foo"}, os.Environ())
	})
}
