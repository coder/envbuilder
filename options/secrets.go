package options

import (
	"fmt"
	"os"

	"github.com/coder/serpent"
)

var buildSecretPrefix = fmt.Sprintf("%sBUILD_SECRET_", envPrefix)

// EnvWithBuildSecretPrefix returns a string in the format of a build secret environment variable.
func EnvWithBuildSecretPrefix(secretName, secretValue string) string {
	return fmt.Sprintf("%s%s=%s", buildSecretPrefix, secretName, secretValue)
}

// GetBuildSecrets sources build secrets from the given environment.
//
// In a normal docker build, build secrets would be passed in via the
// `docker build --secret` flag. envbuilder is more analogous to a
// `docker run` that just happens to build its own container. It doesn't have
// access to the `--secret` flag. As an alternative, we source these from the
// envbuilder process environment.
func GetBuildSecrets(environ []string) []string {
	buildSecrets := serpent.ParseEnviron(environ, buildSecretPrefix).ToOS()
	return buildSecrets
}

// ClearBuildSecretsFromProcessEnvironment unsets all build secrets from the process environment.
// NOTE: This does not remove them from /proc/self/environ. They are still visible
// there unless execve(2) is called.
//
// Unlike runtime secrets in the devcontainer spec or orchestration systems like
// Kubernetes, build secrets should not be available at run time. envbuilder blurs
// the line between build time and run time by transitioning from one to the other
// within the same process in the same container.
//
// These build secrets should not make it into the runtime environment of the runtime
// container init process. It is therefore useful to unset build secret environment
// variables to ensure they aren't accidentally passed into the exec call.
func ClearBuildSecretsFromProcessEnvironment() {
	buildSecrets := serpent.ParseEnviron(os.Environ(), buildSecretPrefix)
	for _, secret := range buildSecrets {
		os.Unsetenv(buildSecretPrefix + secret.Name)
	}
}
