package integration_test

import (
	"bufio"
	"bytes"
	"context"
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
	"strings"
	"testing"
	"time"

	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/devcontainer/features"
	"github.com/coder/envbuilder/testutil/gittest"
	"github.com/coder/envbuilder/testutil/registrytest"
	clitypes "github.com/docker/cli/cli/config/types"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testContainerLabel = "envbox-integration-test"
	testImageAlpine    = "localhost:5000/envbuilder-test-alpine:latest"
	testImageUbuntu    = "localhost:5000/envbuilder-test-ubuntu:latest"
)

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

	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			// Let's say /bin/sh is not available and we can only use /bin/ash
			"Dockerfile": fmt.Sprintf("FROM %s\nRUN unlink /bin/sh", testImageAlpine),
		},
	})
	_, err := runEnvbuilder(t, options{env: []string{
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

	_, err = runEnvbuilder(t, options{env: []string{
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

func TestForceSafe(t *testing.T) {
	t.Parallel()

	t.Run("Safe", func(t *testing.T) {
		t.Parallel()
		srv := createGitServer(t, gitServerOptions{
			files: map[string]string{
				"Dockerfile": "FROM " + testImageAlpine,
			},
		})
		_, err := runEnvbuilder(t, options{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			"KANIKO_DIR=/not/envbuilder",
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}})
		require.ErrorContains(t, err, "delete filesystem: safety check failed")
	})

	// Careful with this one!
	t.Run("Unsafe", func(t *testing.T) {
		t.Parallel()
		srv := createGitServer(t, gitServerOptions{
			files: map[string]string{
				"Dockerfile": "FROM " + testImageAlpine,
			},
		})
		_, err := runEnvbuilder(t, options{env: []string{
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
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
		username: "kyle",
		password: "testing",
	})
	_, err := runEnvbuilder(t, options{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
	}})
	require.ErrorContains(t, err, "authentication required")
}

func TestSucceedsGitAuth(t *testing.T) {
	t.Parallel()
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
		username: "kyle",
		password: "testing",
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		envbuilderEnv("GIT_USERNAME", "kyle"),
		envbuilderEnv("GIT_PASSWORD", "testing"),
	}})
	require.NoError(t, err)
	gitConfig := execContainer(t, ctr, "cat /workspaces/empty/.git/config")
	require.Contains(t, gitConfig, srv.URL)
}

func TestSucceedsGitAuthInURL(t *testing.T) {
	t.Parallel()
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
		username: "kyle",
		password: "testing",
	})

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	u.User = url.UserPassword("kyle", "testing")
	ctr, err := runEnvbuilder(t, options{env: []string{
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
	feature1Ref := registrytest.WriteContainer(t, registry, "coder/test1:latest", features.TarLayerMediaType, map[string]any{
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

	feature2Ref := registrytest.WriteContainer(t, registry, "coder/test2:latest", features.TarLayerMediaType, map[string]any{
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
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
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
	ctr, err := runEnvbuilder(t, options{env: []string{
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

func TestBuildFromDockerfile(t *testing.T) {
	// Ensures that a Git repository with a Dockerfile is cloned and built.
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		envbuilderEnv("DOCKER_CONFIG_BASE64", base64.StdEncoding.EncodeToString([]byte(`{"experimental": "enabled"}`))),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))

	// Verify that the Docker configuration secret file is removed
	output = execContainer(t, ctr, "stat "+filepath.Join(envbuilder.MagicDir, "config.json"))
	require.Contains(t, output, "No such file or directory")
}

func TestBuildPrintBuildOutput(t *testing.T) {
	// Ensures that a Git repository with a Dockerfile is cloned and built.
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine + "\nRUN echo hello",
		},
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
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
	// Ensures that a Git repository with a Dockerfile is cloned and built.
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
	})
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "secret"), []byte("test"), 0o644)
	require.NoError(t, err)
	ctr, err := runEnvbuilder(t, options{
		env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		},
		binds: []string{fmt.Sprintf("%s:/var/run/secrets", dir)},
	})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildWithSetupScript(t *testing.T) {
	// Ensures that a Git repository with a Dockerfile is cloned and built.
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
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
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			".devcontainer/custom/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			".devcontainer/custom/Dockerfile": "FROM " + testImageUbuntu,
		},
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("DEVCONTAINER_DIR", ".devcontainer/custom"),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildFromDevcontainerInSubfolder(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			".devcontainer/subfolder/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			".devcontainer/subfolder/Dockerfile": "FROM " + testImageUbuntu,
		},
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildFromDevcontainerInRoot(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
			}`,
			"Dockerfile": "FROM " + testImageUbuntu,
		},
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildCustomCertificates(t *testing.T) {
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
		tls: true,
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
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
	// Ensures that a Git repository with a Dockerfile is cloned and built.
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM " + testImageAlpine,
		},
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
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

	err = cli.ContainerStart(ctx, ctr, types.ContainerStartOptions{})
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
		_, err := runEnvbuilder(t, options{env: []string{
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
		srv := createGitServer(t, gitServerOptions{
			files: map[string]string{
				"Dockerfile": "bad syntax",
			},
		})
		_, err := runEnvbuilder(t, options{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}})
		require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
		require.ErrorContains(t, err, "dockerfile parse error")
	})
	t.Run("FailsBuild", func(t *testing.T) {
		t.Parallel()
		// Ensures that a Git repository with a Dockerfile is cloned and built.
		srv := createGitServer(t, gitServerOptions{
			files: map[string]string{
				"Dockerfile": `FROM ` + testImageAlpine + `
RUN exit 1`,
			},
		})
		_, err := runEnvbuilder(t, options{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}})
		require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
	})
	t.Run("BadDevcontainer", func(t *testing.T) {
		t.Parallel()
		// Ensures that a Git repository with a Dockerfile is cloned and built.
		srv := createGitServer(t, gitServerOptions{
			files: map[string]string{
				".devcontainer/devcontainer.json": "not json",
			},
		})
		_, err := runEnvbuilder(t, options{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
		}})
		require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
	})
	t.Run("NoImageOrDockerfile", func(t *testing.T) {
		t.Parallel()
		srv := createGitServer(t, gitServerOptions{
			files: map[string]string{
				".devcontainer/devcontainer.json": "{}",
			},
		})
		ctr, err := runEnvbuilder(t, options{env: []string{
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
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "bad syntax",
		},
	})
	_, err := runEnvbuilder(t, options{env: []string{
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
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
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
	ctr, err := runEnvbuilder(t, options{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
		envbuilderEnv("EXPORT_ENV_FILE", "/env"),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "cat /env")
	require.Contains(t, strings.TrimSpace(output),
		`FROM_CONTAINER_ENV=bar
FROM_DOCKERFILE=foo
FROM_REMOTE_ENV=baz
PATH=/usr/local/bin:/bin:/go/bin:/opt
REMOTE_BAR=bar`)
}

func TestLifecycleScripts(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := createGitServer(t, gitServerOptions{
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
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
		envbuilderEnv("GIT_URL", srv.URL),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "cat /tmp/out /tmp/parallel1 /tmp/parallel2")
	require.Equal(t,
		`create
update
postCreate.nobody
parallel1
parallel2`, strings.TrimSpace(output))
}

func TestPostStartScript(t *testing.T) {
	t.Parallel()

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	srv := createGitServer(t, gitServerOptions{
		files: map[string]string{
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
	ctr, err := runEnvbuilder(t, options{env: []string{
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
		image := setupPassthroughRegistry(t, "scratch", &registryAuth{
			Username: "user",
			Password: "test",
		})

		// Ensures that a Git repository with a Dockerfile is cloned and built.
		srv := createGitServer(t, gitServerOptions{
			files: map[string]string{
				"Dockerfile": "FROM " + image,
			},
		})
		_, err := runEnvbuilder(t, options{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
		}})
		require.ErrorContains(t, err, "Unauthorized")
	})
	t.Run("Auth", func(t *testing.T) {
		t.Parallel()
		image := setupPassthroughRegistry(t, "envbuilder-test-alpine:latest", &registryAuth{
			Username: "user",
			Password: "test",
		})

		// Ensures that a Git repository with a Dockerfile is cloned and built.
		srv := createGitServer(t, gitServerOptions{
			files: map[string]string{
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

		_, err = runEnvbuilder(t, options{env: []string{
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
		image := setupPassthroughRegistry(t, "scratch", &registryAuth{
			Username: "user",
			Password: "banana",
		})

		// Ensures that a Git repository with a Dockerfile is cloned and built.
		srv := createGitServer(t, gitServerOptions{
			files: map[string]string{
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

		_, err = runEnvbuilder(t, options{env: []string{
			envbuilderEnv("GIT_URL", srv.URL),
			envbuilderEnv("DOCKERFILE_PATH", "Dockerfile"),
			envbuilderEnv("DOCKER_CONFIG_BASE64", base64.StdEncoding.EncodeToString(config)),
		}})
		require.ErrorContains(t, err, "Unauthorized")
	})
}

type registryAuth struct {
	Username string
	Password string
}

func setupPassthroughRegistry(t *testing.T, image string, auth *registryAuth) string {
	t.Helper()
	dockerURL, err := url.Parse("http://localhost:5000")
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(dockerURL)

	// The Docker registry uses short-lived JWTs to authenticate
	// anonymously to pull images. To test our MITM auth, we need to
	// generate a JWT for the proxy to use.
	registry, err := name.NewRegistry("localhost:5000")
	require.NoError(t, err)
	proxy.Transport, err = transport.NewWithContext(context.Background(), registry, authn.Anonymous, http.DefaultTransport, []string{})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "localhost:5000"
		r.URL.Host = "localhost:5000"
		r.URL.Scheme = "http"

		if auth != nil {
			user, pass, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Access to the staging site\", charset=\"UTF-8\"")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if user != auth.Username || pass != auth.Password {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		proxy.ServeHTTP(w, r)
	}))
	return fmt.Sprintf("%s/%s", strings.TrimPrefix(srv.URL, "http://"), image)
}

func TestNoMethodFails(t *testing.T) {
	_, err := runEnvbuilder(t, options{env: []string{}})
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
			srv := createGitServer(t, gitServerOptions{
				files: tc.files,
			})
			_, err := runEnvbuilder(t, options{env: []string{
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

type gitServerOptions struct {
	files    map[string]string
	username string
	password string
	authMW   func(http.Handler) http.Handler
	tls      bool
}

// createGitServer creates a git repository with an in-memory filesystem
// and serves it over HTTP using a httptest.Server.
func createGitServer(t *testing.T, opts gitServerOptions) *httptest.Server {
	t.Helper()
	if opts.authMW == nil {
		opts.authMW = gittest.BasicAuthMW(opts.username, opts.password)
	}
	commits := make([]gittest.CommitFunc, 0)
	for path, content := range opts.files {
		commits = append(commits, gittest.Commit(t, path, content, "my test commit"))
	}
	fs := memfs.New()
	_ = gittest.NewRepo(t, fs, commits...)
	if opts.tls {
		return httptest.NewTLSServer(opts.authMW(gittest.NewServer(fs)))
	}
	return httptest.NewServer(opts.authMW(gittest.NewServer(fs)))
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
	ctrs, err := cli.ContainerList(ctx, types.ContainerListOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{
			Key:   "label",
			Value: testContainerLabel,
		}),
	})
	if err != nil {
		panic(err)
	}
	for _, ctr := range ctrs {
		cli.ContainerRemove(ctx, ctr.ID, types.ContainerRemoveOptions{
			Force: true,
		})
	}
}

type options struct {
	binds []string
	env   []string
}

// runEnvbuilder starts the envbuilder container with the given environment
// variables and returns the container ID.
func runEnvbuilder(t *testing.T, options options) (string, error) {
	t.Helper()
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	t.Cleanup(func() {
		cli.Close()
	})
	ctr, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "envbuilder:latest",
		Env:   options.env,
		Labels: map[string]string{
			testContainerLabel: "true",
		},
	}, &container.HostConfig{
		NetworkMode: container.NetworkMode("host"),
		Binds:       options.binds,
	}, nil, nil, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		cli.ContainerRemove(ctx, ctr.ID, types.ContainerRemoveOptions{
			RemoveVolumes: true,
			Force:         true,
		})
	})
	err = cli.ContainerStart(ctx, ctr.ID, types.ContainerStartOptions{})
	require.NoError(t, err)

	logChan, errChan := streamContainerLogs(t, cli, ctr.ID)
	go func() {
		for log := range logChan {
			if strings.HasPrefix(log, "=== Running the init command") {
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
	execConfig := types.ExecConfig{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          []string{"/bin/sh", "-c", command},
	}
	execID, err := cli.ContainerExecCreate(ctx, containerID, execConfig)
	require.NoError(t, err)
	resp, err := cli.ContainerExecAttach(ctx, execID.ID, types.ExecStartCheck{})
	require.NoError(t, err)
	defer resp.Close()
	var buf bytes.Buffer
	_, err = stdcopy.StdCopy(&buf, &buf, resp.Reader)
	require.NoError(t, err)
	return buf.String()
}

func streamContainerLogs(t *testing.T, cli *client.Client, containerID string) (chan string, chan error) {
	ctx := context.Background()
	err := cli.ContainerStart(ctx, containerID, types.ContainerStartOptions{})
	require.NoError(t, err)
	rawLogs, err := cli.ContainerLogs(ctx, containerID, types.ContainerLogsOptions{
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
	return fmt.Sprintf("%s=%s", envbuilder.WithEnvPrefix(env), value)
}
