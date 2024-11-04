package options_test

import (
	"os"
	"strings"
	"testing"

	"github.com/coder/envbuilder/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetBuildSecrets(t *testing.T) {
	// This test cannot be run in parallel, because it needs to modify the OS environment
	tests := []struct {
		name            string
		envVars         map[string]string
		expectedSecrets []string
	}{
		{
			name:            "no secrets set",
			envVars:         map[string]string{},
			expectedSecrets: []string{},
		},
		{
			name: "single secret",
			envVars: map[string]string{
				"ENVBUILDER_BUILD_SECRET_FOO": "bar",
			},
			expectedSecrets: []string{"FOO=bar"},
		},
		{
			name: "multiple secrets",
			envVars: map[string]string{
				"ENVBUILDER_BUILD_SECRET_FOO": "bar",
				"NOT_A_SECRET":                "baz",
				"ENVBUILDER_BUILD_SECRET_BAZ": "qux",
			},
			expectedSecrets: []string{"FOO=bar", "BAZ=qux"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preserveEnv(t)
			os.Clearenv()

			options.ClearBuildSecretsFromProcessEnvironment()
			require.Empty(t, options.GetBuildSecrets(os.Environ()))

			// Set environment variables for the test case
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			// when
			secrets := options.GetBuildSecrets(os.Environ())

			// then
			assert.ElementsMatch(t, tt.expectedSecrets, secrets)
		})
	}
}

func TestClearBuildSecrets(t *testing.T) {
	// This test cannot be run in parallel, because it needs to modify the OS environment
	tests := []struct {
		name                       string
		initialEnvVars             map[string]string
		expectedSecretsBeforeClear []string
		expectedEnvironAfterClear  []string
	}{
		{
			name: "single secret",
			initialEnvVars: map[string]string{
				"ENVBUILDER_BUILD_SECRET_FOO": "bar",
			},
			expectedSecretsBeforeClear: []string{"FOO=bar"},
		},
		{
			name: "multiple secrets",
			initialEnvVars: map[string]string{
				"ENVBUILDER_BUILD_SECRET_FOO": "bar",
				"ENVBUILDER_BUILD_SECRET_BAZ": "qux",
			},
			expectedSecretsBeforeClear: []string{"FOO=bar", "BAZ=qux"},
		},
		{
			name: "only build secrets are cleared",
			initialEnvVars: map[string]string{
				"ENVBUILDER_BUILD_SECRET_FOO": "foo",
				"BAR":                         "bar",
			},
			expectedSecretsBeforeClear: []string{"FOO=foo"},
			expectedEnvironAfterClear:  []string{"BAR=bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preserveEnv(t)
			os.Clearenv()

			// Set environment variables for the test case
			for key, value := range tt.initialEnvVars {
				t.Setenv(key, value)
			}

			// Verify secrets before clearing
			secrets := options.GetBuildSecrets(os.Environ())
			assert.ElementsMatch(t, tt.expectedSecretsBeforeClear, secrets)

			// Clear the secrets
			options.ClearBuildSecretsFromProcessEnvironment()

			// Verify secrets after clearing
			environ := os.Environ()
			secrets = options.GetBuildSecrets(environ)
			assert.Empty(t, secrets)
		})
	}
}

// preserveEnv takes a snapshot of the current process environment and restores it after the current
// test to ensure that we don't cause flakes by modifying the environment for other tests.
func preserveEnv(t *testing.T) {
	envSnapshot := make(map[string]string)
	for _, envVar := range os.Environ() {
		parts := strings.SplitN(envVar, "=", 2)
		envSnapshot[parts[0]] = parts[1]
	}
	t.Cleanup(func() {
		os.Clearenv()
		for key, value := range envSnapshot {
			os.Setenv(key, value)
		}
	})
}
