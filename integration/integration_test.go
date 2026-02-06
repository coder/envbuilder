package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/devcontainer/features"
	"github.com/coder/envbuilder/internal/codervendor/agentsdk"
	"github.com/coder/envbuilder/internal/codervendor/codersdk"
	"github.com/coder/envbuilder/internal/workingdir"
	"github.com/coder/envbuilder/options"
	"github.com/coder/envbuilder/testutil/gittest"
	"github.com/coder/envbuilder/testutil/mwtest"
	"github.com/coder/envbuilder/testutil/registrytest"
	"github.com/go-git/go-billy/v5/osfs"
	gossh "golang.org/x/crypto/ssh"

	clitypes "github.com/docker/cli/cli/config/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testContainerLabel   = "envbox-integration-test"
	testImageAlpine      = "localhost:5000/envbuilder-test-alpine:latest"
	testImageUbuntu      = "localhost:5000/envbuilder-test-ubuntu:latest"
	testImageBlobUnknown = "localhost:5000/envbuilder-test-blob-unknown:latest"

	// nolint:gosec // Throw-away key for testing. DO NOT REUSE.
	testSSHKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBXOGgAge/EbcejqASqZa6s8PFXZle56DiGEt0VYnljuwAAAKgM05mUDNOZ
lAAAAAtzc2gtZWQyNTUxOQAAACBXOGgAge/EbcejqASqZa6s8PFXZle56DiGEt0VYnljuw
AAAEDCawwtjrM4AGYXD1G6uallnbsgMed4cfkFsQ+mLZtOkFc4aACB78Rtx6OoBKplrqzw
8VdmV7noOIYS3RVieWO7AAAAHmNpYW5AY2RyLW1icC1mdmZmdzBuOHEwNXAuaG9tZQECAw
QFBgc=
-----END OPENSSH PRIVATE KEY-----`
)

var emptyRemoteOpts []remote.Option

func TestLogs(t *testing.T) {
	t.Parallel()

	token := uuid.NewString()
	logsDone := make(chan struct{})

	logHandler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/buildinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version": "v2.8.9"}`))
			return
		case "/api/v2/workspaceagents/me/logs":
			w.WriteHeader(http.StatusOK)
			tokHdr := r.Header.Get(codersdk.SessionTokenHeader)
			assert.Equal(t, token, tokHdr)
			var req agentsdk.PatchLogs
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			for _, log := range req.Logs {
				t.Logf("got log: %+v", log)
				if strings.Contains(log.Output, "Running init command") {
					close(logsDone)
					return
				}
			}
			return
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	logSrv := httptest.NewServer(http.HandlerFunc(logHandler))
	defer logSrv.Close()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"devcontainer.json": `{
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			"Dockerfile": fmt.Sprintf(`FROM %s`, testImageUbuntu),
		},
	})
	ctrID, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		"CODER_AGENT_URL=" + logSrv.URL,
		"CODER_AGENT_TOKEN=" + token,
		"ENVBUILDER_SETUP_SCRIPT=/bin/sh -c 'echo MY${NO_MATCH_ENV}_SETUP_SCRIPT_OUT; echo MY${NO_MATCH_ENV}_SETUP_SCRIPT_ERR' 1>&2",
		"ENVBUILDER_INIT_SCRIPT=env",
	}})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	select {
	case <-ctx.Done():
		t.Fatal("timed out waiting for logs")
	case <-logsDone:
	}

	// Wait for the container to exit
	client, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		status, err := client.ContainerInspect(ctx, ctrID)
		if !assert.NoError(t, err) {
			return false
		}
		return !status.State.Running
	}, 10*time.Second, time.Second, "container never exited")

	// Check the expected log output
	logReader, err := client.ContainerLogs(ctx, ctrID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	require.NoError(t, err)
	logBytes, err := io.ReadAll(logReader)
	require.NoError(t, err)
	logs := string(logBytes)
	require.Contains(t, logs, "CODER_AGENT_SUBSYSTEM=envbuilder")
	require.Contains(t, logs, "MY_SETUP_SCRIPT_OUT")
	require.Contains(t, logs, "MY_SETUP_SCRIPT_ERR")
}

func TestInitScriptInitCommand(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Init script will hit the below handler to signify INIT_SCRIPT works.
	initCalled := make(chan struct{})
	initSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		initCalled <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))

	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			// Let's say /bin/sh is not available and we can only use /bin/ash
			"Dockerfile": fmt.Sprintf("FROM %s\nRUN unlink /bin/sh", testImageAlpine),
		},
	})
	_, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		envbuilderEnv("INIT_SCRIPT", fmt.Sprintf(`wget -O - %q`, initSrv.URL)),
		envbuilderEnv("INIT_COMMAND", "/bin/ash"),
	}})
	require.NoError(t, err)

	select {
	case <-initCalled:
	case <-ctx.Done():
	}
	require.NoError(t, ctx.Err(), "init script did not execute for prefixed env vars")

	_, err = runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		fmt.Sprintf(`INIT_SCRIPT=wget -O - %q`, initSrv.URL),
		`INIT_COMMAND=/bin/ash`,
	}})
	require.NoError(t, err)

	select {
	case <-initCalled:
	case <-ctx.Done():
	}
	require.NoError(t, ctx.Err(), "init script did not execute for legacy env vars")
}

func TestDanglingBuildStage(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			"Dockerfile": fmt.Sprintf(`FROM %s as a
RUN date > /root/date.txt`, testImageUbuntu),
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "cat /date.txt")
	require.NotEmpty(t, strings.TrimSpace(output))
}

func TestUserFromMultistage(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			"Dockerfile": fmt.Sprintf(`FROM %s AS a
USER root
RUN useradd --create-home pickme
USER pickme
FROM a AS other
USER root
RUN useradd --create-home notme
USER notme
FROM a AS b`, testImageUbuntu),
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
	}})
	require.NoError(t, err)

	// Check that envbuilder started command as user.
	// Since envbuilder starts as root, probe for up to 10 seconds.
	for i := 0; i < 10; i++ {
		out := execContainer(t, ctr, "ps aux | awk '/^pickme * 1 / {print $1}' | sort -u")
		got := strings.TrimSpace(out)
		if got == "pickme" {
			return
		}
		time.Sleep(time.Second)
	}
	require.Fail(t, "expected pid 1 to be running as pickme")
}

func TestUidGid(t *testing.T) {
	t.Parallel()
	t.Run("MultiStage", func(t *testing.T) {
		t.Parallel()

		dockerFile := fmt.Sprintf(`FROM %s AS builder
RUN mkdir -p /myapp/somedir \
&& touch /myapp/somedir/somefile \
&& chown 123:123 /myapp/somedir \
&& chown 321:321 /myapp/somedir/somefile

FROM %s
COPY --from=builder /myapp /myapp
RUN printf "%%s\n" \
			"0 0 /myapp/" \
			"123 123 /myapp/somedir" \
			"321 321 /myapp/somedir/somefile" \
			> /tmp/expected \
&& stat -c "%%u %%g %%n" \
			/myapp/ \
			/myapp/somedir \
			/myapp/somedir/somefile \
			> /tmp/got \
&& diff -u /tmp/got /tmp/expected`, testImageAlpine, testImageAlpine)
		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				"Dockerfile": dockerFile,
			},
		})
		_, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}})
		require.NoError(t, err)
	})

	t.Run("SingleStage", func(t *testing.T) {
		t.Parallel()

		dockerFile := fmt.Sprintf(`FROM %s
RUN mkdir -p /myapp/somedir \
&& touch /myapp/somedir/somefile \
&& chown 123:123 /myapp/somedir \
&& chown 321:321 /myapp/somedir/somefile \
&& printf "%%s\n" \
			"0 0 /myapp/" \
			"123 123 /myapp/somedir" \
			"321 321 /myapp/somedir/somefile" \
			> /tmp/expected \
&& stat -c "%%u %%g %%n" \
			/myapp/ \
			/myapp/somedir \
			/myapp/somedir/somefile \
			> /tmp/got \
&& diff -u /tmp/got /tmp/expected`, testImageAlpine)
		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				"Dockerfile": dockerFile,
			},
		})
		_, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}})
		require.NoError(t, err)
	})
}

func TestForceSafe(t *testing.T) {
	t.Parallel()

	t.Run("Safe", func(t *testing.T) {
		t.Parallel()
		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				"Dockerfile": "FROM " + testImageAlpine,
			},
		})
		_, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			"KANIKO_DIR=/not/envbuilder",
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}})
		require.ErrorContains(t, err, "delete filesystem: safety check failed")
	})

	// Careful with this one!
	t.Run("Unsafe", func(t *testing.T) {
		t.Parallel()
		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				"Dockerfile": "FROM " + testImageAlpine,
			},
		})
		_, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			"KANIKO_DIR=/not/envbuilder",
			envbuilderEnv("FORCE_SAFE", "true"),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}})
		require.NoError(t, err)
	})
}

func TestFailsGitAuth(t *testing.T) {
	t.Parallel()
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
		Username: "kyle",
		Password: "testing",
	})
	_, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
	}})
	require.ErrorContains(t, err, "authentication required")
}

func TestSucceedsGitAuth(t *testing.T) {
	t.Parallel()
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
		Username: "kyle",
		Password: "testing",
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		envbuilderEnv("GIT_USERNAME", "kyle"),
		envbuilderEnv("GIT_PASSWORD", "testing"),
	}})
	require.NoError(t, err)
	gitConfig := execContainer(t, ctr, "cat /workspaces/empty/.git/config")
	require.Contains(t, gitConfig, srv.URL)
}

func TestGitSSHAuth(t *testing.T) {
	t.Parallel()

	base64Key := base64.StdEncoding.EncodeToString([]byte(testSSHKey))

	t.Run("Base64/Success", func(t *testing.T) {
		t.Parallel()

		signer, err := gossh.ParsePrivateKey([]byte(testSSHKey))
		require.NoError(t, err)
		require.NotNil(t, signer)

		tmpDir := t.TempDir()
		srvFS := osfs.New(tmpDir, osfs.WithChrootOS())

		_ = gittest.NewRepo(t, srvFS, gittest.Commit(t, "Dockerfile", "FROM "+testImageAlpine, "Initial commit"))
		tr := gittest.NewServerSSH(t, srvFS, signer.PublicKey())

		ctr, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
			envbuilderEnv("GIT_URL", tr.String()),
			envbuilderEnv("GIT_SSH_PRIVATE_KEY_BASE64", base64Key),
		}})
		require.NoError(t, err)
		dockerFilePath := execContainer(t, ctr, "find /workspaces -name Dockerfile")
		require.NotEmpty(t, dockerFilePath)
		dockerFile := execContainer(t, ctr, "cat "+dockerFilePath)
		require.Contains(t, dockerFile, testImageAlpine)
	})

	t.Run("Base64/Failure", func(t *testing.T) {
		t.Parallel()

		_, randomKey, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		signer, err := gossh.NewSignerFromKey(randomKey)
		require.NoError(t, err)
		require.NotNil(t, signer)

		tmpDir := t.TempDir()
		srvFS := osfs.New(tmpDir, osfs.WithChrootOS())

		_ = gittest.NewRepo(t, srvFS, gittest.Commit(t, "Dockerfile", "FROM "+testImageAlpine, "Initial commit"))
		tr := gittest.NewServerSSH(t, srvFS, signer.PublicKey())

		_, err = runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
			envbuilderEnv("GIT_URL", tr.String()+"."),
			envbuilderEnv("GIT_SSH_PRIVATE_KEY_BASE64", base64Key),
		}})
		require.ErrorContains(t, err, "handshake failed")
	})
}

func TestSucceedsGitAuthInURL(t *testing.T) {
	t.Parallel()
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
		Username: "kyle",
		Password: "testing",
	})

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	u.User = url.UserPassword("kyle", "testing")
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", u.String()),
		envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
	}})
	require.NoError(t, err)
	gitConfig := execContainer(t, ctr, "cat /workspaces/empty/.git/config")
	require.Contains(t, gitConfig, u.String())
}

func TestBuildFromDevcontainerWithFeatures(t *testing.T) {
	t.Parallel()

	registry := registrytest.New(t)
	feature1Ref := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/test1:latest", features.TarLayerMediaType, map[string]any{
		"devcontainer-feature.json": &features.Spec{
			ID:      "test1",
			Name:    "test1",
			Version: "1.0.0",
			Options: map[string]features.Option{
				"bananas": {
					Type: "string",
				},
			},
		},
		"install.sh": "echo $BANANAS > /test1output",
	})

	feature2Ref := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/test2:latest", features.TarLayerMediaType, map[string]any{
		"devcontainer-feature.json": &features.Spec{
			ID:      "test2",
			Name:    "test2",
			Version: "1.0.0",
			Options: map[string]features.Option{
				"pineapple": {
					Type: "string",
				},
			},
		},
		"install.sh": "echo $PINEAPPLE > /test2output",
	})

	feature3Spec, err := json.Marshal(features.Spec{
		ID:      "test3",
		Name:    "test3",
		Version: "1.0.0",
		Options: map[string]features.Option{
			"grape": {
				Type: "string",
			},
		},
	})
	require.NoError(t, err)

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
				"features": {
					"` + feature1Ref + `": {
						"bananas": "hello from test 1!"
					},
					"` + feature2Ref + `": {
						"pineapple": "hello from test 2!"
					},
					"./feature3": {
						"grape": "hello from test 3!"
					}
				}
			}`,
			".devcontainer/Dockerfile":                         "FROM " + testImageUbuntu,
			".devcontainer/feature3/devcontainer-feature.json": string(feature3Spec),
			".devcontainer/feature3/install.sh":                "echo $GRAPE > /test3output",
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
	}})
	require.NoError(t, err)

	test1Output := execContainer(t, ctr, "cat /test1output")
	require.Equal(t, "hello from test 1!", strings.TrimSpace(test1Output))

	test2Output := execContainer(t, ctr, "cat /test2output")
	require.Equal(t, "hello from test 2!", strings.TrimSpace(test2Output))

	test3Output := execContainer(t, ctr, "cat /test3output")
	require.Equal(t, "hello from test 3!", strings.TrimSpace(test3Output))
}

func TestBuildFromDevcontainerWithFeaturesInAuthRepo(t *testing.T) {
	t.Parallel()

	// Given: an empty registry with auth enabled
	authOpts := setupInMemoryRegistryOpts{
		Username: "testing",
		Password: "testing",
	}
	remoteAuthOpt := append(emptyRemoteOpts, remote.WithAuth(&authn.Basic{Username: authOpts.Username, Password: authOpts.Password}))
	testReg := setupInMemoryRegistry(t, authOpts)
	regAuthJSON, err := json.Marshal(envbuilder.DockerConfig{
		AuthConfigs: map[string]clitypes.AuthConfig{
			testReg: {
				Username: authOpts.Username,
				Password: authOpts.Password,
			},
		},
	})
	require.NoError(t, err)

	// push a feature to the registry
	featureRef := registrytest.WriteContainer(t, testReg, remoteAuthOpt, "features/test-feature:latest", features.TarLayerMediaType, map[string]any{
		"devcontainer-feature.json": &features.Spec{
			ID:      "test1",
			Name:    "test1",
			Version: "1.0.0",
			Options: map[string]features.Option{
				"bananas": {
					Type: "string",
				},
			},
		},
		"install.sh": "echo $BANANAS > /test1output",
	})

	// Create a git repo with a devcontainer.json that uses the feature
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
				"features": {
					"` + featureRef + `": {
						"bananas": "hello from test 1!"
					}
				}
			}`,
			".devcontainer/Dockerfile": "FROM " + testImageUbuntu,
		},
	})
	opts := []string{
		envbuilderEnv("GIT_URL", srv.URL),
	}

	// Test that things fail when no auth is provided
	t.Run("NoAuth", func(t *testing.T) {
		t.Parallel()

		// run the envbuilder with the auth config
		_, err := runEnvbuilder(t, runOpts{env: opts})
		require.ErrorContains(t, err, "Unauthorized")
	})

	// test that things work when auth is provided
	t.Run("WithAuth", func(t *testing.T) {
		t.Parallel()

		optsWithAuth := append(
			opts,
			envbuilderEnv("DOCKER_CONFIG_BASE64", base64.StdEncoding.EncodeToString(regAuthJSON)),
		)

		// run the envbuilder with the auth config
		ctr, err := runEnvbuilder(t, runOpts{env: optsWithAuth})
		require.NoError(t, err)

		// check that the feature was installed correctly
		testOutput := execContainer(t, ctr, "cat /test1output")
		require.Equal(t, "hello from test 1!", strings.TrimSpace(testOutput))
	})
}

func TestBuildFromDockerfileAndConfig(t *testing.T) {
	t.Parallel()

	type configFile struct {
		name string
		data string
	}
	type testCase struct {
		name         string
		env          []string
		configFile   configFile
		configBase64 string
		validate     func(t *testing.T, tc testCase, ctrID, logs string)
	}

	validateDockerConfig := func(t *testing.T, tc testCase, ctrID, logs string) {
		t.Helper()

		// Ensure that the config matches the expected value, base64 is
		// always prioritized over a file.
		got := execContainer(t, ctrID, "cat /docker_config_json")
		got = strings.TrimSpace(got)
		want := tc.configBase64
		if want == "" {
			want = tc.configFile.data
		}
		if want != "" {
			require.Contains(t, logs, "Set DOCKER_CONFIG to /.envbuilder/.docker")
			require.Equal(t, want, got)
		}

		// Ensure that a warning message is printed if config secrets
		// will remain in the container after build.
		warningMessage := "this file will remain after the build"
		if tc.configFile.name != "" {
			require.Contains(t, logs, warningMessage)
		} else {
			require.NotContains(t, logs, warningMessage)
		}
	}

	configJSONContainerPath := workingdir.Default.Join(".docker", "config.json")
	defaultConfigJSON := `{"experimental": "enabled"}`

	tests := []testCase{
		{
			name: "Plain",
			validate: func(t *testing.T, tc testCase, ctrID, logs string) {
				output := execContainer(t, ctrID, "echo hello")
				require.Equal(t, "hello", strings.TrimSpace(output))
			},
		},
		{
			name:         "ConfigBase64",
			configBase64: defaultConfigJSON,
			validate:     validateDockerConfig,
		},
		{
			name:       "BindConfigToKnownLocation",
			configFile: configFile{"/.envbuilder/config.json", defaultConfigJSON},
			validate:   validateDockerConfig,
		},
		{
			name:       "BindConfigToPath",
			env:        []string{"DOCKER_CONFIG=/secret"},
			configFile: configFile{"/secret/config.json", defaultConfigJSON},
			validate:   validateDockerConfig,
		},
		{
			name:       "BindConfigToCustomFile",
			env:        []string{"DOCKER_CONFIG=/secret/my.json"},
			configFile: configFile{"/secret/my.json", defaultConfigJSON},
			validate:   validateDockerConfig,
		},
		{
			name:         "ConfigBase64AndBindUsesBase64",
			configFile:   configFile{"/.envbuilder/config.json", `{"experimental": "disabled"}`},
			configBase64: defaultConfigJSON,
			validate:     validateDockerConfig,
		},
		{
			name:         "ConfigBase64AndCustomConfigPath",
			env:          []string{"DOCKER_CONFIG=/secret"},
			configBase64: defaultConfigJSON,
			validate:     validateDockerConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Ensures that a Git repository with a Dockerfile is cloned and built.
			srv := gittest.CreateGitServer(t, gittest.Options{
				Files: map[string]string{
					"Dockerfile": fmt.Sprintf(`
						FROM %[1]s
						RUN if [ -f %[2]q ]; then cat %[2]q > /docker_config_json; fi
					`, testImageAlpine, configJSONContainerPath),
				},
			})

			logbuf := new(bytes.Buffer)
			opts := runOpts{
				env: []string{
					envbuilderEnv("GIT_URL", srv.URL),
					envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
				},
				logbuf: logbuf,
			}

			if tt.configFile.name != "" {
				dir := t.TempDir()
				configFile := filepath.Join(dir, filepath.Base(tt.configFile.name))
				err := os.WriteFile(configFile, []byte(tt.configFile.data), 0o600)
				require.NoError(t, err, "failed to write config")

				opts.privileged = true
				opts.binds = []string{fmt.Sprintf("%s:%s:rw", configFile, tt.configFile.name)}
			}
			if tt.configBase64 != "" {
				enc := base64.StdEncoding.EncodeToString([]byte(tt.configBase64))
				tt.env = append(tt.env, envbuilderEnv("DOCKER_CONFIG_BASE64", enc))
			}

			opts.env = append(opts.env, tt.env...)

			ctrID, err := runEnvbuilder(t, opts)
			require.NoError(t, err)

			tt.validate(t, tt, ctrID, logbuf.String())

			// Always verify that the Docker configuration secret file is removed.
			output := execContainer(t, ctrID, "stat "+configJSONContainerPath)
			require.Contains(t, output, "No such file or directory")
		})
	}
}

func TestBuildPrintBuildOutput(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a Dockerfile is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine + "\nRUN echo hello",
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
	}})
	require.NoError(t, err)

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cli.Close()

	// Make sure that "hello" is printed in the logs!
	logs, _ := streamContainerLogs(t, cli, ctr)
	for {
		log := <-logs
		if log != "hello" {
			continue
		}
		break
	}
}

func TestBuildIgnoreVarRunSecrets(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a Dockerfile is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
	})
	dir := t.TempDir()
	secretVal := uuid.NewString()
	err := os.WriteFile(filepath.Join(dir, "secret"), []byte(secretVal), 0o644)
	require.NoError(t, err)

	t.Run("ReadWrite", func(t *testing.T) {
		t.Parallel()

		ctr, err := runEnvbuilder(t, runOpts{
			env: []string{
				envbuilderEnv("GIT_URL", srv.URL),
				envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
			},
			binds: []string{fmt.Sprintf("%s:/var/run/secrets:rw", dir)},
		})
		require.NoError(t, err)

		output := execContainer(t, ctr, "cat /var/run/secrets/secret")
		require.Equal(t, secretVal, strings.TrimSpace(output))
	})

	t.Run("ReadOnly", func(t *testing.T) {
		t.Parallel()

		ctr, err := runEnvbuilder(t, runOpts{
			env: []string{
				envbuilderEnv("GIT_URL", srv.URL),
				envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
			},
			binds: []string{fmt.Sprintf("%s:/var/run/secrets:ro", dir)},
		})
		require.NoError(t, err)

		output := execContainer(t, ctr, "cat /var/run/secrets/secret")
		require.Equal(t, secretVal, strings.TrimSpace(output))
	})
}

func TestBuildWithSetupScript(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a Dockerfile is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		envbuilderEnv("SETUP_SCRIPT", "echo \"INIT_ARGS=-c 'echo hi > /wow && sleep infinity'\" >> $ENVBUILDER_ENV"),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "cat /wow")
	require.Equal(t, "hi", strings.TrimSpace(output))
}

func TestBuildFromDevcontainerInCustomPath(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			".devcontainer/custom/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			".devcontainer/custom/Dockerfile": "FROM " + testImageUbuntu,
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("DEVCONTAINER_DIR", ".devcontainer/custom"),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildFromCustomWorkspaceBaseDir(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"Dockerfile": "FROM " + testImageUbuntu,
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{
		env: []string{
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
			envbuilderEnv("WORKSPACE_BASE_DIR", "/foo"),
			envbuilderEnv("GIT_URL", srv.URL),
		},
	})
	require.NoError(t, err)

	output := execContainer(t, ctr, "readlink /proc/1/cwd")
	require.Contains(t, output, "/foo/")
}

func TestBuildFromDevcontainerInSubfolder(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			".devcontainer/subfolder/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			".devcontainer/subfolder/Dockerfile": "FROM " + testImageUbuntu,
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildFromDevcontainerInRoot(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			"Dockerfile": "FROM " + testImageUbuntu,
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildCustomCertificates(t *testing.T) {
	t.Parallel()

	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
		TLS: true,
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		envbuilderEnv("SSL_CERT_BASE64", base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: srv.TLS.Certificates[0].Certificate[0],
		}))),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildStopStartCached(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a Dockerfile is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		envbuilderEnv("SKIP_REBUILD", "true"),
	}})
	require.NoError(t, err)

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cli.Close()

	ctx := context.Background()
	err = cli.ContainerStop(ctx, ctr, container.StopOptions{})
	require.NoError(t, err)

	err = cli.ContainerStart(ctx, ctr, container.StartOptions{})
	require.NoError(t, err)

	logChan, _ := streamContainerLogs(t, cli, ctr)
	for {
		log := <-logChan
		if strings.Contains(log, "Skipping build because of cache") {
			break
		}
	}
}

func TestCloneFailsFallback(t *testing.T) {
	t.Parallel()
	t.Run("BadRepo", func(t *testing.T) {
		t.Parallel()
		_, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", "bad-value"),
		}})
		require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
	})
}

func TestBuildFailsFallback(t *testing.T) {
	t.Parallel()
	t.Run("BadDockerfile", func(t *testing.T) {
		t.Parallel()
		// Ensures that a Git repository with a Dockerfile is cloned and built.
		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				"Dockerfile": "bad syntax",
			},
		})
		_, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}})
		require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
		require.ErrorContains(t, err, "dockerfile parse error")
	})
	t.Run("FailsBuild", func(t *testing.T) {
		t.Parallel()
		// Ensures that a Git repository with a Dockerfile is cloned and built.
		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				"Dockerfile": `FROM ` + testImageAlpine + `
RUN exit 1`,
			},
		})
		_, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}})
		require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
	})
	t.Run("BadDevcontainer", func(t *testing.T) {
		t.Parallel()
		// Ensures that a Git repository with a Dockerfile is cloned and built.
		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/devcontainer.json": "not json",
			},
		})
		_, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
		}})
		require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
	})
	t.Run("NoImageOrDockerfile", func(t *testing.T) {
		t.Parallel()
		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/devcontainer.json": "{}",
			},
		})
		ctr, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("FALLBACK_IMAGE", testImageAlpine),
		}})
		require.NoError(t, err)

		output := execContainer(t, ctr, "echo hello")
		require.Equal(t, "hello", strings.TrimSpace(output))
	})
}

func TestExitBuildOnFailure(t *testing.T) {
	t.Parallel()
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			"Dockerfile": "bad syntax",
		},
	})
	_, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		envbuilderEnv("FALLBACK_IMAGE", testImageAlpine),
		// Ensures that the fallback doesn't work when an image is specified.
		envbuilderEnv("EXIT_ON_BUILD_FAILURE", "true"),
	}})
	require.ErrorContains(t, err, "parsing dockerfile")
}

func TestContainerEnv(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
				"containerEnv": {
					"FROM_CONTAINER_ENV": "bar",
					"PATH": "/bin"
				},
				"remoteEnv": {
					"FROM_REMOTE_ENV": "baz",
					"PATH": "/usr/local/bin:${containerEnv:PATH}:${containerEnv:GOPATH:/go/bin}:/opt",
					"REMOTE_BAR": "${FROM_CONTAINER_ENV}"
				}
			}`,
			".devcontainer/Dockerfile": "FROM " + testImageAlpine + "\nENV FROM_DOCKERFILE=foo",
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("EXPORT_ENV_FILE", "/env"),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "cat /env")
	want := `DEVCONTAINER=true
DEVCONTAINER_CONFIG=/workspaces/empty/.devcontainer/devcontainer.json
ENVBUILDER=true
FROM_CONTAINER_ENV=bar
FROM_DOCKERFILE=foo
FROM_REMOTE_ENV=baz
PATH=/usr/local/bin:/bin:/go/bin:/opt
REMOTE_BAR=bar`
	if diff := cmp.Diff(want, strings.TrimSpace(output)); diff != "" {
		require.Failf(t, "env mismatch", "diff (-want +got):\n%s", diff)
	}
}

func TestUnsetOptionsEnv(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			".devcontainer/Dockerfile": "FROM " + testImageAlpine + "\nENV FROM_DOCKERFILE=foo",
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		"GIT_URL", srv.URL,
		envbuilderEnv("GIT_PASSWORD", "supersecret"),
		"GIT_PASSWORD", "supersecret",
		envbuilderEnv("INIT_SCRIPT", "env > /root/env.txt && sleep infinity"),
		"INIT_SCRIPT", "env > /root/env.txt && sleep infinity",
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "cat /root/env.txt")
	var os options.Options
	for _, s := range strings.Split(strings.TrimSpace(output), "\n") {
		for _, o := range os.CLI() {
			if strings.HasPrefix(s, o.Env) {
				assert.Fail(t, "environment variable should be stripped when running init script", s)
			}
			optWithoutPrefix := strings.TrimPrefix(o.Env, options.WithEnvPrefix(""))
			if strings.HasPrefix(s, optWithoutPrefix) {
				assert.Fail(t, "environment variable should be stripped when running init script", s)
			}
		}
	}
}

func TestBuildSecrets(t *testing.T) {
	t.Parallel()

	buildSecretVal := "foo"

	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			".devcontainer/Dockerfile": "FROM " + testImageAlpine +
				// Test whether build secrets are written to the default location
				"\nRUN --mount=type=secret,id=FOO cat /run/secrets/FOO > /foo_from_file" +
				// Test whether:
				// * build secrets are written to env
				// * build secrets are written to a custom target
				// * build secrets are both written to env and target if both are specified
				"\nRUN --mount=type=secret,id=FOO,env=FOO,target=/etc/foo echo $FOO > /foo_from_env && cat /etc/foo > /foo_from_custom_target" +
				// Test what happens when you specify the same secret twice
				"\nRUN --mount=type=secret,id=FOO,target=/etc/duplicate_foo --mount=type=secret,id=FOO,target=/etc/duplicate_foo cat /etc/duplicate_foo > /duplicate_foo_from_custom_target",
		},
	})

	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("GIT_PASSWORD", "supersecret"),
		envbuilderEnv("BUILD_SECRETS", fmt.Sprintf("FOO=%s", buildSecretVal)),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "cat /foo_from_file")
	assert.Equal(t, buildSecretVal, strings.TrimSpace(output))

	output = execContainer(t, ctr, "cat /foo_from_env")
	assert.Equal(t, buildSecretVal, strings.TrimSpace(output))

	output = execContainer(t, ctr, "cat /foo_from_custom_target")
	assert.Equal(t, buildSecretVal, strings.TrimSpace(output))

	output = execContainer(t, ctr, "cat /duplicate_foo_from_custom_target")
	assert.Equal(t, buildSecretVal, strings.TrimSpace(output))
}

func TestLifecycleScripts(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name         string
		files        map[string]string
		outputCmd    string
		expectOutput string
	}{
		{
			name: "build",
			files: map[string]string{
				".devcontainer/devcontainer.json": `{
					"name": "Test",
					"build": {
						"dockerfile": "Dockerfile"
					},
					"onCreateCommand": "echo create > /tmp/out",
					"updateContentCommand": ["sh", "-c", "echo update >> /tmp/out"],
					"postCreateCommand": "(echo -n postCreate. ; id -un) >> /tmp/out",
					"postStartCommand": {
						"parallel1": "echo parallel1 > /tmp/parallel1",
						"parallel2": ["sh", "-c", "echo parallel2 > /tmp/parallel2"]
					}
				}`,
				".devcontainer/Dockerfile": "FROM " + testImageAlpine + "\nUSER nobody",
			},
			outputCmd:    "cat /tmp/out /tmp/parallel1 /tmp/parallel2",
			expectOutput: "create\nupdate\npostCreate.nobody\nparallel1\nparallel2",
		},
		{
			name: "image",
			files: map[string]string{
				".devcontainer/devcontainer.json": fmt.Sprintf(`{
					"name": "Test",
					"image": %q,
					"containerUser": "nobody",
					"onCreateCommand": "echo create > /tmp/out",
					"updateContentCommand": ["sh", "-c", "echo update >> /tmp/out"],
					"postCreateCommand": "(echo -n postCreate. ; id -un) >> /tmp/out",
					"postStartCommand": {
						"parallel1": "echo parallel1 > /tmp/parallel1",
						"parallel2": ["sh", "-c", "echo parallel2 > /tmp/parallel2"]
					}
				}`, testImageAlpine),
			},
			outputCmd:    "cat /tmp/out /tmp/parallel1 /tmp/parallel2",
			expectOutput: "create\nupdate\npostCreate.nobody\nparallel1\nparallel2",
		},
		{
			name: "label",
			files: map[string]string{
				".devcontainer/Dockerfile": fmt.Sprintf(`FROM %s
					LABEL devcontainer.metadata='[{ \
						"onCreateCommand": "echo create > /tmp/out", \
						"updateContentCommand": ["sh", "-c", "echo update >> /tmp/out"], \
						"postCreateCommand": "(echo -n postCreate. ; id -un) >> /tmp/out", \
						"postStartCommand": { \
							"parallel1": "echo parallel1 > /tmp/parallel1", \
							"parallel2": ["sh", "-c", "echo parallel2 > /tmp/parallel2"] \
						} \
					}]'
					USER nobody`, testImageAlpine),
			},
			outputCmd:    "cat /tmp/out /tmp/parallel1 /tmp/parallel2",
			expectOutput: "create\nupdate\npostCreate.nobody\nparallel1\nparallel2",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			srv := gittest.CreateGitServer(t, gittest.Options{
				Files: tt.files,
			})
			env := []string{
				envbuilderEnv("GIT_URL", srv.URL),
			}
			if _, ok := tt.files[".devcontainer/devcontainer.json"]; !ok {
				env = append(env, envbuilderEnv("DOCKERFILE_PATH", ".devcontainer/Dockerfile"))
			}
			ctr, err := runEnvbuilder(t, runOpts{env: env})
			require.NoError(t, err, "failed to run envbuilder")
			output := execContainer(t, ctr, tt.outputCmd)
			require.Equal(t, tt.expectOutput, strings.TrimSpace(output))
		})
	}
}

func TestPostStartScript(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
				"postStartCommand": {
					"command1": "echo command1 output > /tmp/out1",
					"command2": ["sh", "-c", "echo 'contains \"double quotes\"' > '/tmp/out2'"]
				}
			}`,
			".devcontainer/init.sh": `#!/bin/sh
			/tmp/post-start.sh
			sleep infinity`,
			".devcontainer/Dockerfile": `FROM ` + testImageAlpine + `
COPY init.sh /bin
RUN chmod +x /bin/init.sh
USER nobody`,
		},
	})
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("POST_START_SCRIPT_PATH", "/tmp/post-start.sh"),
		envbuilderEnv("INIT_COMMAND", "/bin/init.sh"),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "cat /tmp/post-start.sh /tmp/out1 /tmp/out2")
	require.Equal(t,
		`#!/bin/sh

echo command1 output > /tmp/out1
'sh' '-c' 'echo '"'"'contains "double quotes"'"'"' > '"'"'/tmp/out2'"'"''
command1 output
contains "double quotes"`, strings.TrimSpace(output))
}

func TestPrivateRegistry(t *testing.T) {
	t.Parallel()
	t.Run("NoAuth", func(t *testing.T) {
		t.Parallel()
		// Even if something goes wrong with auth,
		// the pull will fail as "scratch" is a reserved name.
		image := setupPassthroughRegistry(t, "scratch", &setupPassthroughRegistryOptions{
			Username: "user",
			Password: "test",
		})

		// Ensures that a Git repository with a Dockerfile is cloned and built.
		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				"Dockerfile": "FROM " + image,
			},
		})
		_, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}})
		require.ErrorContains(t, err, "Unauthorized")
	})
	t.Run("Auth", func(t *testing.T) {
		t.Parallel()
		image := setupPassthroughRegistry(t, "envbuilder-test-alpine:latest", &setupPassthroughRegistryOptions{
			Username: "user",
			Password: "test",
		})

		// Ensures that a Git repository with a Dockerfile is cloned and built.
		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				"Dockerfile": "FROM " + image,
			},
		})
		config, err := json.Marshal(envbuilder.DockerConfig{
			AuthConfigs: map[string]clitypes.AuthConfig{
				image: {
					Username: "user",
					Password: "test",
				},
			},
		})
		require.NoError(t, err)

		_, err = runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
			envbuilderEnv("DOCKER_CONFIG_BASE64", base64.StdEncoding.EncodeToString(config)),
		}})
		require.NoError(t, err)
	})
	t.Run("InvalidAuth", func(t *testing.T) {
		t.Parallel()
		// Even if something goes wrong with auth,
		// the pull will fail as "scratch" is a reserved name.
		image := setupPassthroughRegistry(t, "scratch", &setupPassthroughRegistryOptions{
			Username: "user",
			Password: "banana",
		})

		// Ensures that a Git repository with a Dockerfile is cloned and built.
		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				"Dockerfile": "FROM " + image,
			},
		})
		config, err := json.Marshal(envbuilder.DockerConfig{
			AuthConfigs: map[string]clitypes.AuthConfig{
				image: {
					Username: "user",
					Password: "wrong",
				},
			},
		})
		require.NoError(t, err)

		_, err = runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
			envbuilderEnv("DOCKER_CONFIG_BASE64", base64.StdEncoding.EncodeToString(config)),
		}})
		require.ErrorContains(t, err, "Unauthorized")
	})
}

type setupPassthroughRegistryOptions struct {
	Username string
	Password string
	Upstream string
}

func setupPassthroughRegistry(t *testing.T, image string, opts *setupPassthroughRegistryOptions) string {
	t.Helper()
	if opts.Upstream == "" {
		// Default to local test registry
		opts.Upstream = "http://localhost:5000"
	}
	upstreamURL, err := url.Parse(opts.Upstream)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)

	// The Docker registry uses short-lived JWTs to authenticate
	// anonymously to pull images. To test our MITM auth, we need to
	// generate a JWT for the proxy to use.
	registry, err := name.NewRegistry(upstreamURL.Host)
	require.NoError(t, err)
	proxy.Transport, err = transport.NewWithContext(context.Background(), registry, authn.Anonymous, http.DefaultTransport, []string{})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = upstreamURL.Host
		r.URL.Host = upstreamURL.Host
		r.URL.Scheme = upstreamURL.Scheme

		if opts != nil {
			user, pass, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Access to the staging site\", charset=\"UTF-8\"")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if user != opts.Username || pass != opts.Password {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		proxy.ServeHTTP(w, r)
	}))
	return fmt.Sprintf("%s/%s", strings.TrimPrefix(srv.URL, "http://"), image)
}

func TestNoMethodFails(t *testing.T) {
	t.Parallel()

	_, err := runEnvbuilder(t, runOpts{env: []string{}})
	require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
}

func TestDockerfileBuildContext(t *testing.T) {
	t.Parallel()

	inclFile := "myfile"
	dockerfile := fmt.Sprintf(`FROM %s
COPY %s .`, testImageAlpine, inclFile)

	tests := []struct {
		name             string
		files            map[string]string
		dockerfilePath   string
		buildContextPath string
		expectedErr      string
	}{
		{
			// Dockerfile & build context are in the same dir, copying inclFile should work.
			name: "same build context (default)",
			files: map[string]string{
				"Dockerfile": dockerfile,
				inclFile:     "...",
			},
			dockerfilePath:   "Dockerfile",
			buildContextPath: "", // use default
			expectedErr:      "", // expect no errors
		},
		{
			// Dockerfile & build context are not in the same dir, build context is still the default; this should fail
			// to copy inclFile since it is not in the same dir as the Dockerfile.
			name: "different build context (default)",
			files: map[string]string{
				"a/Dockerfile":  dockerfile,
				"a/" + inclFile: "...",
			},
			dockerfilePath:   "a/Dockerfile",
			buildContextPath: "", // use default
			expectedErr:      inclFile + ": no such file or directory",
		},
		{
			// Dockerfile & build context are not in the same dir, but inclFile is in the default build context dir;
			// this should allow inclFile to be copied. This is probably not desirable though?
			name: "different build context (default, different content roots)",
			files: map[string]string{
				"a/Dockerfile": dockerfile,
				inclFile:       "...",
			},
			dockerfilePath:   "a/Dockerfile",
			buildContextPath: "", // use default
			expectedErr:      "",
		},
		{
			// Dockerfile is not in the default build context dir, but the build context has been overridden; this should
			// allow inclFile to be copied.
			name: "different build context (custom)",
			files: map[string]string{
				"a/Dockerfile":  dockerfile,
				"a/" + inclFile: "...",
			},
			dockerfilePath:   "a/Dockerfile",
			buildContextPath: "a/",
			expectedErr:      "",
		},
	}

	for _, tc := range tests {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := gittest.CreateGitServer(t, gittest.Options{
				Files: tc.files,
			})
			_, err := runEnvbuilder(t, runOpts{env: []string{
				envbuilderEnv("GIT_URL", srv.URL),
				envbuilderEnv("DOCKERFILE_PATH", tc.dockerfilePath),
				envbuilderEnv("BUILD_CONTEXT_PATH", tc.buildContextPath),
			}})

			if tc.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.expectedErr)
			}
		})
	}
}

func TestPushImage(t *testing.T) {
	t.Parallel()

	// Write a test feature to an in-memory registry.
	testFeature := registrytest.WriteContainer(t, registrytest.New(t), emptyRemoteOpts, "features/test-feature:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": `#!/bin/sh
			echo "${MESSAGE}" > /root/message.txt`,
		"devcontainer-feature.json": features.Spec{
			ID:      "test-feature",
			Name:    "test feature",
			Version: "v0.0.1",
			Options: map[string]features.Option{
				"message": {
					Type:    "string",
					Default: "hello world",
				},
			},
		},
	})

	t.Run("CacheWithoutPush", func(t *testing.T) {
		t.Parallel()

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/Dockerfile": fmt.Sprintf(`FROM %s
USER root
ARG WORKDIR=/
WORKDIR $WORKDIR
ENV FOO=bar
RUN echo $FOO > /root/foo.txt
RUN date --utc > /root/date.txt`, testImageAlpine),
				".devcontainer/devcontainer.json": fmt.Sprintf(`{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
				"features": {
					%q: {}
				}
			}`, testFeature),
			},
		})

		// Given: an empty registry
		testReg := setupInMemoryRegistry(t, setupInMemoryRegistryOpts{})
		testRepo := testReg + "/test"
		ref, err := name.ParseReference(testRepo + ":latest")
		require.NoError(t, err)
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		// When: we run envbuilder with GET_CACHED_IMAGE
		_, err = runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
			envbuilderEnv("GET_CACHED_IMAGE", "1"),
		}})
		require.ErrorContains(t, err, "error probing build cache: uncached RUN command")
		// Then: it should fail to build the image and nothing should be pushed
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		// When: we run envbuilder with no PUSH_IMAGE set
		_, err = runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
		}})
		require.NoError(t, err)

		// Then: the image tag should not be present, only the layers
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "MANIFEST_UNKNOWN", "expected image to not be present before build + push")

		// Then: re-running envbuilder with GET_CACHED_IMAGE should not succeed, as
		// the envbuilder binary is not present in the pushed image.
		_, err = runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
			envbuilderEnv("GET_CACHED_IMAGE", "1"),
		}})
		require.Regexp(t, `uncached.*command.*is not supported in cache probe mode`, err.Error())
	})

	t.Run("CacheAndPush", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		// Given: a git repository with a devcontainer.json that references the
		// feature
		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/Dockerfile": fmt.Sprintf(`FROM %s
					USER root
					ARG WORKDIR=/
					WORKDIR $WORKDIR
					ENV FOO=bar
					RUN echo $FOO > /root/foo.txt
					RUN date --utc > /root/date.txt`, testImageAlpine),
				".devcontainer/devcontainer.json": fmt.Sprintf(`
				{
					"name": "Test",
					"build": {
						"dockerfile": "Dockerfile"
					},
					"features": {
						%q: {}
					}
				}`, testFeature),
			},
		})

		// Given: an empty registry
		testReg := setupInMemoryRegistry(t, setupInMemoryRegistryOpts{})
		testRepo := testReg + "/test"
		ref, err := name.ParseReference(testRepo + ":latest")
		require.NoError(t, err)
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		opts := []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
			envbuilderEnv("VERBOSE", "1"),
		}

		// When: we run envbuilder with GET_CACHED_IMAGE
		_, err = runEnvbuilder(t, runOpts{env: append(opts,
			envbuilderEnv("GET_CACHED_IMAGE", "1"),
		)})
		require.ErrorContains(t, err, "error probing build cache: uncached RUN command")
		// Then: it should fail to build the image and nothing should be pushed
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		// When: we run envbuilder with PUSH_IMAGE set
		_ = pushImage(t, ref, nil, opts...)

		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		require.NoError(t, err)
		defer cli.Close()

		// Then: re-running envbuilder with GET_CACHED_IMAGE should succeed
		cachedRef := getCachedImage(ctx, t, cli, opts...)

		// When: we run the image we just built
		ctr := startContainerFromRef(ctx, t, cli, cachedRef)

		// Then: the envbuilder binary exists in the image!
		out := execContainer(t, ctr.ID, "/.envbuilder/bin/envbuilder --help")
		require.Regexp(t, `(?s)^USAGE:\s+envbuilder`, strings.TrimSpace(out))
		out = execContainer(t, ctr.ID, "cat /root/date.txt")
		require.NotEmpty(t, strings.TrimSpace(out))
		// Then: the feature install script was run
		out = execContainer(t, ctr.ID, "cat /root/message.txt")
		require.Equal(t, "hello world", strings.TrimSpace(out))
	})

	t.Run("CacheAndPushDevcontainerOnly", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/devcontainer.json": fmt.Sprintf(`{"image": %q}`, testImageAlpine),
			},
		})

		// Given: an empty registry
		testReg := setupInMemoryRegistry(t, setupInMemoryRegistryOpts{})
		testRepo := testReg + "/test"
		ref, err := name.ParseReference(testRepo + ":latest")
		require.NoError(t, err)
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		opts := []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
		}

		// When: we run envbuilder with GET_CACHED_IMAGE
		_, err = runEnvbuilder(t, runOpts{env: append(opts,
			envbuilderEnv("GET_CACHED_IMAGE", "1"),
		)})
		require.Regexp(t, "error probing build cache: uncached.*command.*is not supported in cache probe mode", err.Error())
		// Then: it should fail to build the image and nothing should be pushed
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		// When: we run envbuilder with PUSH_IMAGE set
		_ = pushImage(t, ref, nil, opts...)

		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		require.NoError(t, err)
		defer cli.Close()

		// Then: re-running envbuilder with GET_CACHED_IMAGE should succeed
		cachedRef := getCachedImage(ctx, t, cli, opts...)

		// When: we run the image we just built
		ctr := startContainerFromRef(ctx, t, cli, cachedRef)

		// Then: the envbuilder binary exists in the image!
		out := execContainer(t, ctr.ID, "/.envbuilder/bin/envbuilder --help")
		require.Regexp(t, `(?s)^USAGE:\s+envbuilder`, strings.TrimSpace(out))
		require.NotEmpty(t, strings.TrimSpace(out))
	})

	t.Run("CompareBuiltAndCachedImageEnvironment", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		wantSpecificOutput := []string{
			"containeruser",
			"FROM_CONTAINER=container",
			"FROM_CONTAINER_ENV=containerEnv",
			"FROM_REMOTE_ENV=remoteEnv",
			"CONTAINER_OVERRIDE_C=containerEnv",
			"CONTAINER_OVERRIDE_CR=remoteEnv",
			"CONTAINER_OVERRIDE_R=remoteEnv",
		}

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/Dockerfile": fmt.Sprintf(`
					FROM %s
					ENV FROM_CONTAINER=container
					ENV CONTAINER_OVERRIDE_C=container
					ENV CONTAINER_OVERRIDE_CR=container
					ENV CONTAINER_OVERRIDE_R=container
					RUN adduser -D containeruser
					RUN adduser -D remoteuser
					USER root
				`, testImageAlpine),
				".devcontainer/devcontainer.json": `
					{
						"dockerFile": "Dockerfile",
						"containerUser": "containeruser",
						"containerEnv": {
							"FROM_CONTAINER_ENV": "containerEnv",
							"CONTAINER_OVERRIDE_C": "containerEnv",
							"CONTAINER_OVERRIDE_CR": "containerEnv",
						},
						"remoteUser": "remoteuser",
						"remoteEnv": {
							"FROM_REMOTE_ENV": "remoteEnv",
							"CONTAINER_OVERRIDE_CR": "remoteEnv",
							"CONTAINER_OVERRIDE_R": "remoteEnv",
						},
						"onCreateCommand": "echo onCreateCommand",
						"postCreateCommand": "echo postCreateCommand",
					}
				`,
			},
		})

		// Given: an empty registry
		testReg := setupInMemoryRegistry(t, setupInMemoryRegistryOpts{})
		testRepo := testReg + "/test"
		ref, err := name.ParseReference(testRepo + ":latest")
		require.NoError(t, err)
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		opts := []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
			envbuilderEnv("INIT_SCRIPT", "echo '[start]' && whoami && env && echo '[end]'"),
			envbuilderEnv("INIT_COMMAND", "/bin/ash"),
		}

		// When: we run envbuilder with PUSH_IMAGE set
		ctrID, err := runEnvbuilder(t, runOpts{env: append(opts, envbuilderEnv("PUSH_IMAGE", "1"))})
		require.NoError(t, err, "envbuilder push image failed")

		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		require.NoError(t, err)
		defer cli.Close()

		var started bool
		var wantOutput, gotOutput []string
		logs, _ := streamContainerLogs(t, cli, ctrID)
		for {
			log := <-logs
			if log == "[start]" {
				started = true
				continue
			}
			if log == "[end]" {
				break
			}
			if started {
				wantOutput = append(wantOutput, log)
			}
		}
		started = false

		// Then: re-running envbuilder with GET_CACHED_IMAGE should succeed
		cachedRef := getCachedImage(ctx, t, cli, opts...)

		// When: we run the image we just built
		ctrID, err = runEnvbuilder(t, runOpts{
			image: cachedRef.String(),
			env:   opts,
		})
		require.NoError(t, err, "envbuilder run cached image failed")

		logs, _ = streamContainerLogs(t, cli, ctrID)
		for {
			log := <-logs
			if log == "[start]" {
				started = true
				continue
			}
			if log == "[end]" {
				break
			}
			if started {
				gotOutput = append(gotOutput, log)
			}
		}

		slices.Sort(wantOutput)
		slices.Sort(gotOutput)
		if diff := cmp.Diff(wantOutput, gotOutput); diff != "" {
			t.Fatalf("unexpected output (-want +got):\n%s", diff)
		}

		for _, want := range wantSpecificOutput {
			assert.Contains(t, gotOutput, want, "expected specific output %q to be present", want)
		}
	})

	t.Run("CacheAndPushWithNoChangeLayers", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				"Dockerfile": fmt.Sprintf(`
FROM %[1]s
RUN touch /foo
RUN echo "Hi, please don't put me in a layer (I guess you won't listen to me...)"
RUN touch /bar
`, testImageAlpine),
			},
		})

		// Given: an empty registry
		testReg := setupInMemoryRegistry(t, setupInMemoryRegistryOpts{})
		testRepo := testReg + "/test"
		ref, err := name.ParseReference(testRepo + ":latest")
		require.NoError(t, err)
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		opts := []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}

		// When: we run envbuilder with PUSH_IMAGE set
		_ = pushImage(t, ref, nil, opts...)

		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		require.NoError(t, err)
		defer cli.Close()

		// Then: re-running envbuilder with GET_CACHED_IMAGE should succeed
		cachedRef := getCachedImage(ctx, t, cli, opts...)

		// When: we run the image we just built
		ctr := startContainerFromRef(ctx, t, cli, cachedRef)

		// Then: the envbuilder binary exists in the image!
		out := execContainer(t, ctr.ID, "/.envbuilder/bin/envbuilder --help")
		require.Regexp(t, `(?s)^USAGE:\s+envbuilder`, strings.TrimSpace(out))
		require.NotEmpty(t, strings.TrimSpace(out))
	})

	t.Run("CacheAndPushAuth", func(t *testing.T) {
		t.Parallel()

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/Dockerfile": fmt.Sprintf(`FROM %s
USER root
ARG WORKDIR=/
WORKDIR $WORKDIR
ENV FOO=bar
RUN echo $FOO > /root/foo.txt
RUN date --utc > /root/date.txt`, testImageAlpine),
				".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			},
		})

		// Given: an empty registry
		authOpts := setupInMemoryRegistryOpts{
			Username: "testing",
			Password: "testing",
		}
		remoteAuthOpt := remote.WithAuth(&authn.Basic{Username: authOpts.Username, Password: authOpts.Password})
		testReg := setupInMemoryRegistry(t, authOpts)
		testRepo := testReg + "/test"
		regAuthJSON, err := json.Marshal(envbuilder.DockerConfig{
			AuthConfigs: map[string]clitypes.AuthConfig{
				testRepo: {
					Username: authOpts.Username,
					Password: authOpts.Password,
				},
			},
		})
		require.NoError(t, err)
		ref, err := name.ParseReference(testRepo + ":latest")
		require.NoError(t, err)
		_, err = remote.Image(ref, remoteAuthOpt)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		opts := []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
			envbuilderEnv("DOCKER_CONFIG_BASE64", base64.StdEncoding.EncodeToString(regAuthJSON)),
		}

		// When: we run envbuilder with GET_CACHED_IMAGE
		_, err = runEnvbuilder(t, runOpts{env: append(opts,
			envbuilderEnv("GET_CACHED_IMAGE", "1"),
		)})
		require.ErrorContains(t, err, "error probing build cache: uncached RUN command")
		// Then: it should fail to build the image and nothing should be pushed
		_, err = remote.Image(ref, remoteAuthOpt)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		// When: we run envbuilder with PUSH_IMAGE set
		_ = pushImage(t, ref, remoteAuthOpt, opts...)

		// Then: the image should be pushed
		_, err = remote.Image(ref, remoteAuthOpt)
		require.NoError(t, err, "expected image to be present after build + push")

		// Then: re-running envbuilder with GET_CACHED_IMAGE should succeed
		_, err = runEnvbuilder(t, runOpts{env: append(opts,
			envbuilderEnv("GET_CACHED_IMAGE", "1"),
		)})
		require.NoError(t, err)
	})

	t.Run("CacheAndPushAuthFail", func(t *testing.T) {
		t.Parallel()

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/Dockerfile": fmt.Sprintf(`FROM %s
USER root
ARG WORKDIR=/
WORKDIR $WORKDIR
ENV FOO=bar
RUN echo $FOO > /root/foo.txt
RUN date --utc > /root/date.txt`, testImageAlpine),
				".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			},
		})

		// Given: an empty registry
		authOpts := setupInMemoryRegistryOpts{
			Username: "testing",
			Password: "testing",
		}
		remoteAuthOpt := remote.WithAuth(&authn.Basic{Username: authOpts.Username, Password: authOpts.Password})
		testReg := setupInMemoryRegistry(t, authOpts)
		testRepo := testReg + "/test"
		ref, err := name.ParseReference(testRepo + ":latest")
		require.NoError(t, err)
		_, err = remote.Image(ref, remoteAuthOpt)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		opts := []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
		}

		// When: we run envbuilder with GET_CACHED_IMAGE
		_, err = runEnvbuilder(t, runOpts{env: append(opts,
			envbuilderEnv("GET_CACHED_IMAGE", "1"),
		)})
		require.ErrorContains(t, err, "error probing build cache: uncached RUN command")
		// Then: it should fail to build the image and nothing should be pushed
		_, err = remote.Image(ref, remoteAuthOpt)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		// When: we run envbuilder with PUSH_IMAGE and EXIT_ON_PUSH_FAILURE set
		_, err = runEnvbuilder(t, runOpts{env: append(opts,
			envbuilderEnv("PUSH_IMAGE", "1"),
			envbuilderEnv("EXIT_ON_PUSH_FAILURE", "1"),
		)})
		// Then: it should fail with an Unauthorized error
		require.ErrorContains(t, err, "401 Unauthorized", "expected unauthorized error using no auth when cache repo requires it")

		// Then: the image should not be pushed
		_, err = remote.Image(ref, remoteAuthOpt)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")
	})

	t.Run("CacheAndPushMultistage", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				"Dockerfile": fmt.Sprintf(`
FROM %[1]s AS prebuild
RUN mkdir /the-past /the-future \
	&& echo "hello from the past" > /the-past/hello.txt \
	&& cd /the-past \
	&& ln -s hello.txt hello.link \
	&& echo "hello from the future" > /the-future/hello.txt

FROM %[1]s
USER root
ARG WORKDIR=/
WORKDIR $WORKDIR
ENV FOO=bar
COPY --from=prebuild /the-past /the-past
COPY --from=prebuild /the-future/hello.txt /the-future/hello.txt
`, testImageAlpine),
			},
		})

		// Given: an empty registry
		testReg := setupInMemoryRegistry(t, setupInMemoryRegistryOpts{})
		testRepo := testReg + "/test"
		ref, err := name.ParseReference(testRepo + ":latest")
		require.NoError(t, err)
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		opts := []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}

		// When: we run envbuilder with GET_CACHED_IMAGE
		_, err = runEnvbuilder(t, runOpts{env: append(opts,
			envbuilderEnv("GET_CACHED_IMAGE", "1"),
		)})
		require.ErrorContains(t, err, "error probing build cache: uncached RUN command")
		// Then: it should fail to build the image and nothing should be pushed
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		// When: we run envbuilder with PUSH_IMAGE set
		_ = pushImage(t, ref, nil, opts...)

		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		require.NoError(t, err)
		defer cli.Close()

		// Then: re-running envbuilder with GET_CACHED_IMAGE should succeed
		cachedRef := getCachedImage(ctx, t, cli, opts...)

		// When: we run the image we just built
		ctr := startContainerFromRef(ctx, t, cli, cachedRef)

		// Then: The files from the prebuild stage are present.
		out := execContainer(t, ctr.ID, "/bin/sh -c 'cat /the-past/hello.txt /the-future/hello.txt; readlink -f /the-past/hello.link'")
		require.Equal(t, "hello from the past\nhello from the future\n/the-past/hello.txt", strings.TrimSpace(out))
	})

	t.Run("MultistgeCacheMissAfterChange", func(t *testing.T) {
		t.Parallel()
		dockerfilePrebuildContents := fmt.Sprintf(`
FROM %[1]s AS prebuild
RUN mkdir /the-past /the-future \
	&& echo "hello from the past" > /the-past/hello.txt \
	&& cd /the-past \
	&& ln -s hello.txt hello.link \
	&& echo "hello from the future" > /the-future/hello.txt

# Workaround for https://github.com/coder/envbuilder/issues/231
FROM %[1]s
`, testImageAlpine)

		dockerfileContents := fmt.Sprintf(`
FROM %s
USER root
ARG WORKDIR=/
WORKDIR $WORKDIR
ENV FOO=bar
COPY --from=prebuild /the-past /the-past
COPY --from=prebuild /the-future/hello.txt /the-future/hello.txt
RUN echo $FOO > /root/foo.txt
RUN date --utc > /root/date.txt
`, testImageAlpine)

		newServer := func(dockerfile string) *httptest.Server {
			return gittest.CreateGitServer(t, gittest.Options{
				Files: map[string]string{"Dockerfile": dockerfile},
			})
		}
		srv := newServer(dockerfilePrebuildContents + dockerfileContents)

		// Given: an empty registry
		testReg := setupInMemoryRegistry(t, setupInMemoryRegistryOpts{})
		testRepo := testReg + "/test"
		ref, err := name.ParseReference(testRepo + ":latest")
		require.NoError(t, err)
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		// When: we run envbuilder with PUSH_IMAGE set
		_ = pushImage(t, ref, nil,
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		)

		// Then: re-running envbuilder with GET_CACHED_IMAGE should succeed
		_, err = runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
			envbuilderEnv("GET_CACHED_IMAGE", "1"),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}})
		require.NoError(t, err)

		// When: we change the Dockerfile
		srv.Close()
		dockerfilePrebuildContents = strings.Replace(dockerfilePrebuildContents, "hello from the future", "hello from the future, but different", 1)
		srv = newServer(dockerfilePrebuildContents)

		// When: we rebuild the prebuild stage so that the cache is created
		_ = pushImage(t, ref, nil,
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		)

		// Then: re-running envbuilder with GET_CACHED_IMAGE should still fail
		// on the second stage because the first stage file has changed.
		srv.Close()
		srv = newServer(dockerfilePrebuildContents + dockerfileContents)
		_, err = runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
			envbuilderEnv("GET_CACHED_IMAGE", "1"),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
			envbuilderEnv("VERBOSE", "1"),
		}})
		require.ErrorContains(t, err, "error probing build cache: uncached COPY command")
	})

	t.Run("PushImageRequiresCache", func(t *testing.T) {
		t.Parallel()

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/Dockerfile": fmt.Sprintf(`FROM %s
USER root
ARG WORKDIR=/
WORKDIR $WORKDIR
ENV FOO=bar
RUN echo $FOO > /root/foo.txt
RUN date --utc > /root/date.txt`, testImageAlpine),
				".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			},
		})

		// When: we run envbuilder with PUSH_IMAGE set but no cache repo set
		_, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("PUSH_IMAGE", "1"),
		}})

		// Then: Envbuilder should fail explicitly, as it does not make sense to
		// specify PUSH_IMAGE
		require.ErrorContains(t, err, "--cache-repo must be set when using --push-image")
	})

	t.Run("PushErr/ExitOnPushFail", func(t *testing.T) {
		t.Parallel()

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/Dockerfile": fmt.Sprintf(`FROM %s
USER root
ARG WORKDIR=/
WORKDIR $WORKDIR
ENV FOO=bar
RUN echo $FOO > /root/foo.txt
RUN date --utc > /root/date.txt`, testImageAlpine),
				".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			},
		})

		// Given: registry is not set up (in this case, not a registry)
		notRegSrv := httptest.NewServer(http.NotFoundHandler())
		notRegURL := strings.TrimPrefix(notRegSrv.URL, "http://") + "/test"

		// When: we run envbuilder with PUSH_IMAGE set
		_, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", notRegURL),
			envbuilderEnv("PUSH_IMAGE", "1"),
			envbuilderEnv("EXIT_ON_PUSH_FAILURE", "1"),
		}})

		// Then: envbuilder should fail with a descriptive error
		require.ErrorContains(t, err, "failed to push to destination")
	})

	t.Run("PushErr/NoExitOnPushFail", func(t *testing.T) {
		t.Parallel()

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/Dockerfile": fmt.Sprintf(`FROM %s
USER root
ARG WORKDIR=/
WORKDIR $WORKDIR
ENV FOO=bar
RUN echo $FOO > /root/foo.txt
RUN date --utc > /root/date.txt`, testImageAlpine),
				".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			},
		})

		// Given: registry is not set up (in this case, not a registry)
		notRegSrv := httptest.NewServer(http.NotFoundHandler())
		notRegURL := strings.TrimPrefix(notRegSrv.URL, "http://") + "/test"

		// When: we run envbuilder with PUSH_IMAGE set
		_, err := runEnvbuilder(t, runOpts{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", notRegURL),
			envbuilderEnv("PUSH_IMAGE", "1"),
			envbuilderEnv("EXIT_ON_PUSH_FAILURE", "0"),
		}})

		// Then: envbuilder should not fail
		require.NoError(t, err)
	})

	t.Run("CacheAndPushDevcontainerFeaturesOverrideOption", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/devcontainer.json": fmt.Sprintf(`
					{
						"image": %q,
						"features": {
							%q: {
								"message": "my favorite color is green"
							}
						}
					}`, testImageUbuntu, testFeature),
			},
		})

		// Given: an empty registry
		testReg := setupInMemoryRegistry(t, setupInMemoryRegistryOpts{})
		testRepo := testReg + "/test"
		ref, err := name.ParseReference(testRepo + ":latest")
		require.NoError(t, err)
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		opts := []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
		}

		// When: we run envbuilder with PUSH_IMAGE set
		_ = pushImage(t, ref, nil, opts...)

		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		require.NoError(t, err)
		defer cli.Close()

		// Then: re-running envbuilder with GET_CACHED_IMAGE should succeed
		cachedRef := getCachedImage(ctx, t, cli, opts...)

		// When: we run the image we just built
		ctr := startContainerFromRef(ctx, t, cli, cachedRef)

		// Check that the feature is present in the image.
		out := execContainer(t, ctr.ID, "cat /root/message.txt")
		require.Contains(t, strings.TrimSpace(out), "my favorite color is green")
	})

	t.Run("CacheAndPushUser", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/devcontainer.json": `{
					"name": "Test",
					"build": {
						"dockerfile": "Dockerfile"
					},
				}`,
				".devcontainer/Dockerfile": fmt.Sprintf(`FROM %s
RUN useradd -m -s /bin/bash devalot
USER devalot
`, testImageUbuntu),
			},
		})

		// Given: an empty registry
		testReg := setupInMemoryRegistry(t, setupInMemoryRegistryOpts{})
		testRepo := testReg + "/test"
		ref, err := name.ParseReference(testRepo + ":latest")
		require.NoError(t, err)
		_, err = remote.Image(ref)
		require.ErrorContains(t, err, "NAME_UNKNOWN", "expected image to not be present before build + push")

		opts := []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", testRepo),
		}

		// When: we run envbuilder with PUSH_IMAGE set
		_ = pushImage(t, ref, nil, opts...)

		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		require.NoError(t, err)
		defer cli.Close()

		// Then: re-running envbuilder with GET_CACHED_IMAGE should succeed
		cachedRef := getCachedImage(ctx, t, cli, opts...)

		// When: we run the image we just built
		ctr := startContainerFromRef(ctx, t, cli, cachedRef)

		// Check that envbuilder started command as user.
		// Since envbuilder starts as root, probe for up to 10 seconds.
		for i := 0; i < 10; i++ {
			out := execContainer(t, ctr.ID, "ps aux | awk '/^devalot * 1 / {print $1}' | sort -u")
			got := strings.TrimSpace(out)
			if got == "devalot" {
				return
			}
			time.Sleep(time.Second)
		}
		require.Fail(t, "expected pid 1 to be running as devalot")
	})

	t.Run("PushDuplicateLayersNoBlobUnknown", func(t *testing.T) {
		t.Parallel()

		srv := gittest.CreateGitServer(t, gittest.Options{
			Files: map[string]string{
				".devcontainer/Dockerfile": fmt.Sprintf(`FROM %s
USER root
RUN echo "hi i r empty"
RUN echo "who u"
`, testImageBlobUnknown),
				".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			},
		})

		// NOTE(mafredri): The in-memory registry doesn't catch this error so we
		// have to use registry:2.
		ref, err := name.ParseReference(fmt.Sprintf("localhost:5000/test-blob-unknown-%s", uuid.NewString()))
		require.NoError(t, err)
		opts := []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("CACHE_REPO", ref.String()),
			envbuilderEnv("VERBOSE", "1"),
		}

		_ = pushImage(t, ref, nil, opts...)
	})
}

func TestChownHomedir(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := gittest.CreateGitServer(t, gittest.Options{
		Files: map[string]string{
			".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			".devcontainer/Dockerfile": fmt.Sprintf(`FROM %s
RUN useradd test \
  --create-home \
  --shell=/bin/bash \
  --uid=1001 \
  --user-group
USER test
`, testImageUbuntu), // Note: this isn't reproducible with Alpine for some reason.
		},
	})

	// Run envbuilder with a Docker volume mounted to homedir
	volName := fmt.Sprintf("%s%d-home", t.Name(), time.Now().Unix())
	ctr, err := runEnvbuilder(t, runOpts{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
	}, volumes: map[string]string{volName: "/home/test"}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "stat -c %u:%g /home/test/")
	require.Equal(t, "1001:1001", strings.TrimSpace(output))
}

type setupInMemoryRegistryOpts struct {
	Username string
	Password string
}

func setupInMemoryRegistry(t *testing.T, opts setupInMemoryRegistryOpts) string {
	t.Helper()
	regSrv := registrytest.New(t, mwtest.BasicAuthMW(opts.Username, opts.Password))
	return regSrv
}

// TestMain runs before all tests to build the envbuilder image.
func TestMain(m *testing.M) {
	checkTestRegistry()
	cleanOldEnvbuilders()
	ctx := context.Background()
	// Run the build script to create the envbuilder image.
	cmd := exec.CommandContext(ctx, "../scripts/build.sh")
	rdr, wtr := io.Pipe()
	defer rdr.Close()
	defer wtr.Close()
	cmd.Stdout = wtr
	cmd.Stderr = wtr
	go func() {
		scanner := bufio.NewScanner(rdr)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()
	err := cmd.Run()
	if err != nil {
		panic(err)
	}

	m.Run()
}

func checkTestRegistry() {
	resp, err := http.Get("http://localhost:5000/v2/_catalog")
	if err != nil {
		_, _ = fmt.Printf("Check test registry: %s\n", err.Error())
		_, _ = fmt.Printf("Hint: Did you run `make test-registry`?\n")
		os.Exit(1)
	}
	defer resp.Body.Close()
	v := make(map[string][]string)
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		_, _ = fmt.Printf("Read test registry catalog: %s\n", err.Error())
		_, _ = fmt.Printf("Hint: Did you run `make test-registry`?\n")
		os.Exit(1)
	}
}

// cleanOldEnvbuilders removes any old envbuilder containers.
func cleanOldEnvbuilders() {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
	defer cli.Close()
	ctrs, err := cli.ContainerList(ctx, container.ListOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{
			Key:   "label",
			Value: testContainerLabel,
		}),
	})
	if err != nil {
		panic(err)
	}
	for _, ctr := range ctrs {
		if err := cli.ContainerRemove(ctx, ctr.ID, container.RemoveOptions{
			Force: true,
		}); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to remove old test container: %s\n", err.Error())
		}
	}
}

func pushImage(t *testing.T, ref name.Reference, remoteOpt remote.Option, env ...string) v1.Image {
	t.Helper()

	var remoteOpts []remote.Option
	if remoteOpt != nil {
		remoteOpts = append(remoteOpts, remoteOpt)
	}
	opts := runOpts{
		env: append(env,
			envbuilderEnv("PUSH_IMAGE", "1"),
			envbuilderEnv("EXIT_ON_PUSH_FAILURE", "1"),
		),
	}
	_, err := runEnvbuilder(t, opts)
	require.NoError(t, err, "envbuilder push image failed")

	img, err := remote.Image(ref, remoteOpts...)
	require.NoError(t, err, "expected image to be present after build + push")

	// The image should have its directives replaced with those required
	// to run envbuilder automatically
	configFile, err := img.ConfigFile()
	require.NoError(t, err, "expected image to return a config file")

	assert.Equal(t, "root", configFile.Config.User, "user must be root")
	assert.Equal(t, "/", configFile.Config.WorkingDir, "workdir must be /")
	if assert.Len(t, configFile.Config.Entrypoint, 1) {
		assert.Equal(t, "/.envbuilder/bin/envbuilder", configFile.Config.Entrypoint[0], "incorrect entrypoint")
	}

	require.False(t, t.Failed(), "pushImage failed")

	return img
}

func getCachedImage(ctx context.Context, t *testing.T, cli *client.Client, env ...string) name.Reference {
	ctrID, err := runEnvbuilder(t, runOpts{env: append(env, envbuilderEnv("GET_CACHED_IMAGE", "1"))})
	require.NoError(t, err)

	logs, err := cli.ContainerLogs(ctx, ctrID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	require.NoError(t, err)
	defer logs.Close()
	logBytes, err := io.ReadAll(logs)
	require.NoError(t, err)

	re := regexp.MustCompile(`ENVBUILDER_CACHED_IMAGE=(\S+)`)
	matches := re.FindStringSubmatch(string(logBytes))
	require.Len(t, matches, 2, "envbuilder cached image not found")
	ref, err := name.ParseReference(matches[1])
	require.NoError(t, err, "failed to parse cached image reference")
	return ref
}

func startContainerFromRef(ctx context.Context, t *testing.T, cli *client.Client, ref name.Reference) container.CreateResponse {
	t.Helper()

	// Ensure that we can pull the image.
	rc, err := cli.ImagePull(ctx, ref.String(), image.PullOptions{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = rc.Close() })
	_, err = io.Copy(io.Discard, rc)
	require.NoError(t, err)

	// Start the container.
	ctr, err := cli.ContainerCreate(ctx, &container.Config{
		Image: ref.String(),
		Labels: map[string]string{
			testContainerLabel: "true",
		},
	}, nil, nil, nil, "")
	require.NoError(t, err)

	t.Cleanup(func() {
		// Start a new context to ensure that the container is removed.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_ = cli.ContainerRemove(ctx, ctr.ID, container.RemoveOptions{
			RemoveVolumes: true,
			Force:         true,
		})
	})

	err = cli.ContainerStart(ctx, ctr.ID, container.StartOptions{})
	require.NoError(t, err)

	return ctr
}

type runOpts struct {
	image      string
	privileged bool // Required for remounting.
	binds      []string
	env        []string
	volumes    map[string]string
	logbuf     *bytes.Buffer
}

// runEnvbuilder starts the envbuilder container with the given environment
// variables and returns the container ID.
func runEnvbuilder(t *testing.T, opts runOpts) (string, error) {
	t.Helper()
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	t.Cleanup(func() {
		cli.Close()
	})
	mounts := make([]mount.Mount, 0)
	for volName, volPath := range opts.volumes {
		mounts = append(mounts, mount.Mount{
			Type:   mount.TypeVolume,
			Source: volName,
			Target: volPath,
		})
		_, err = cli.VolumeCreate(ctx, volume.CreateOptions{
			Name: volName,
		})
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = cli.VolumeRemove(ctx, volName, true)
		})
	}
	img := "envbuilder:latest"
	if opts.image != "" {
		// Pull the image first so we can start it afterwards.
		rc, err := cli.ImagePull(ctx, opts.image, image.PullOptions{})
		require.NoError(t, err, "failed to pull image")
		t.Cleanup(func() { _ = rc.Close() })
		_, err = io.Copy(io.Discard, rc)
		require.NoError(t, err, "failed to read image pull response")
		img = opts.image
	}
	hostConfig := &container.HostConfig{
		NetworkMode: container.NetworkMode("host"),
		Binds:       opts.binds,
		Mounts:      mounts,
	}
	if opts.privileged {
		hostConfig.CapAdd = append(hostConfig.CapAdd, "SYS_ADMIN")
		hostConfig.Privileged = true
	}
	ctr, err := cli.ContainerCreate(ctx, &container.Config{
		Image: img,
		Env:   opts.env,
		Labels: map[string]string{
			testContainerLabel: "true",
		},
	}, hostConfig, nil, nil, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = cli.ContainerRemove(ctx, ctr.ID, container.RemoveOptions{
			RemoveVolumes: true,
			Force:         true,
		})
	})
	err = cli.ContainerStart(ctx, ctr.ID, container.StartOptions{})
	require.NoError(t, err)

	logChan, errChan := streamContainerLogs(t, cli, ctr.ID)
	go func() {
		for log := range logChan {
			if opts.logbuf != nil {
				opts.logbuf.WriteString(log + "\n")
			}
			if strings.HasPrefix(log, "=== Running init command") {
				errChan <- nil
				return
			}
		}
	}()
	return ctr.ID, <-errChan
}

// execContainer executes the given command in the given container and returns
// the output.
func execContainer(t *testing.T, containerID, command string) string {
	t.Helper()
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cli.Close()
	execConfig := container.ExecOptions{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          []string{"/bin/sh", "-c", command},
	}
	execID, err := cli.ContainerExecCreate(ctx, containerID, execConfig)
	require.NoError(t, err)
	resp, err := cli.ContainerExecAttach(ctx, execID.ID, container.ExecAttachOptions{})
	require.NoError(t, err)
	defer resp.Close()
	var buf bytes.Buffer
	_, err = stdcopy.StdCopy(&buf, &buf, resp.Reader)
	require.NoError(t, err)
	return buf.String()
}

func streamContainerLogs(t *testing.T, cli *client.Client, containerID string) (chan string, chan error) {
	ctx := context.Background()
	err := cli.ContainerStart(ctx, containerID, container.StartOptions{})
	require.NoError(t, err)
	rawLogs, err := cli.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Timestamps: false,
	})
	require.NoError(t, err)

	logChan := make(chan string, 32)
	errChan := make(chan error, 1)

	logsReader, logsWriter := io.Pipe()
	go func() {
		_, err := stdcopy.StdCopy(logsWriter, logsWriter, rawLogs)
		assert.NoError(t, err)
		_ = logsReader.Close()
		_ = logsWriter.Close()
	}()
	go func() {
		defer close(errChan)
		scanner := bufio.NewScanner(logsReader)
		for scanner.Scan() {
			t.Logf("%q", strings.TrimSpace(scanner.Text()))
			if strings.HasPrefix(scanner.Text(), "error: ") {
				errChan <- errors.New(scanner.Text())
				return
			}

			logChan <- scanner.Text()
		}
	}()

	return logChan, errChan
}

func envbuilderEnv(env string, value string) string {
	return fmt.Sprintf("%s=%s", options.WithEnvPrefix(env), value)
}
