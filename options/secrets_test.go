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
			envSnapshot := snapshotEnv()
			t.Cleanup(func() { assertEnvUnchanged(t, envSnapshot) })

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
	tests := []struct {
		name                       string
		initialEnvVars             map[string]string
		expectedSecretsBeforeClear []string
		expectedSecretsAfterClear  []string
		expectedEnvironAfterClear  []string
	}{
		{
			name: "single secret",
			initialEnvVars: map[string]string{
				"ENVBUILDER_BUILD_SECRET_FOO": "bar",
			},
			expectedSecretsBeforeClear: []string{"FOO=bar"},
			expectedSecretsAfterClear:  []string{},
		},
		{
			name: "multiple secrets",
			initialEnvVars: map[string]string{
				"ENVBUILDER_BUILD_SECRET_FOO": "bar",
				"ENVBUILDER_BUILD_SECRET_BAZ": "qux",
			},
			expectedSecretsBeforeClear: []string{"FOO=bar", "BAZ=qux"},
			expectedSecretsAfterClear:  []string{},
		},
		{
			name: "only build secrets are cleared",
			initialEnvVars: map[string]string{
				"ENVBUILDER_BUILD_SECRET_FOO": "foo",
				"BAR":                         "bar",
			},
			expectedSecretsBeforeClear: []string{"FOO=foo"},
			expectedSecretsAfterClear:  []string{},
			expectedEnvironAfterClear:  []string{"BAR=bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envSnapshot := snapshotEnv()
			t.Cleanup(func() { assertEnvUnchanged(t, envSnapshot) })

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
			assert.ElementsMatch(t, tt.expectedSecretsAfterClear, secrets)
			for _, env := range tt.expectedSecretsAfterClear {
				assert.Contains(t, environ, env)
			}
		})
	}
}

func snapshotEnv() map[string]string {
	envSnapshot := make(map[string]string)
	for _, envVar := range os.Environ() {
		parts := strings.SplitN(envVar, "=", 2)
		envSnapshot[parts[0]] = parts[1]
	}
	return envSnapshot
}

func assertEnvUnchanged(t *testing.T, snapshot map[string]string) {
	for key, expectedValue := range snapshot {
		currentValue, exists := os.LookupEnv(key)
		assert.True(t, exists, "expected environment variable %s to be set", key)
		assert.Equal(t, expectedValue, currentValue, "expected environment variable %s to be unchanged", key)
	}
	for _, envVar := range os.Environ() {
		key := strings.SplitN(envVar, "=", 2)[0]
		if _, exists := snapshot[key]; !exists {
			assert.Fail(t, "unexpected environment variable set", "variable %s was set during the test", key)
		}
	}
}
