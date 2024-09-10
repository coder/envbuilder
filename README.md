# envbuilder

[![discord](https://img.shields.io/discord/747933592273027093?label=discord)](https://discord.gg/coder)
[![release](https://img.shields.io/github/v/tag/coder/envbuilder)](https://github.com/coder/envbuilder/pkgs/container/envbuilder)
[![godoc](https://pkg.go.dev/badge/github.com/coder/envbuilder.svg)](https://pkg.go.dev/github.com/coder/envbuilder)
[![license](https://img.shields.io/github/license/coder/envbuilder)](./LICENSE)

Build development environments from a Dockerfile on Docker, Kubernetes, and OpenShift. Allow developers to modify their environment in a tight feedback loop.

- Supports [`devcontainer.json`](https://containers.dev/) and `Dockerfile`
- Cache image layers with registries for speedy builds
- Runs on Kubernetes, Docker, and OpenShift

<div align="center">
  <a href="#gh-light-mode-only">
    <img src="./scripts/diagram-light.svg">
  </a>
  <a href="#gh-dark-mode-only">
    <img src="./scripts/diagram-dark.svg">
  </a>
</div>

## Quickstart

The easiest way to get started is to run the `envbuilder` Docker container that clones a repository, builds the image from a Dockerfile, and runs the `$ENVBUILDER_INIT_SCRIPT` in the freshly built container.

> `/tmp/envbuilder` directory persists demo data between commands. You can choose a different directory.

```bash
docker run -it --rm \
    -v /tmp/envbuilder:/workspaces \
    -e ENVBUILDER_GIT_URL=https://github.com/coder/envbuilder-starter-devcontainer \
    -e ENVBUILDER_INIT_SCRIPT=bash \
    ghcr.io/coder/envbuilder
```

Edit `.devcontainer/Dockerfile` to add `htop`:

```bash
vim .devcontainer/Dockerfile
```

```diff
- RUN apt-get install vim sudo -y
+ RUN apt-get install vim sudo htop -y
```

Exit the container, and re-run the `docker run` command... after the build completes, `htop` should exist in the container! 🥳

> [!NOTE]
> Envbuilder performs destructive filesystem operations! To guard against accidental data
> loss, it will refuse to run if it detects that KANIKO_DIR is not set to a specific value.
> If you need to bypass this behavior for any reason, you can bypass this safety check by setting
> `ENVBUILDER_FORCE_SAFE=true`.

If you don't have a remote Git repo or you want to quickly iterate with some
local files, simply omit `ENVBUILDER_GIT_URL` and instead mount the directory
containing your code to `/workspaces/empty` inside the Envbuilder container.

For example:

```shell
# Create a sample Devcontainer and Dockerfile in the current directory
printf '{"build": { "dockerfile": "Dockerfile"}}' > devcontainer.json
printf 'FROM debian:bookworm\nRUN apt-get update && apt-get install -y cowsay' > Dockerfile

# Run envbuilder with the current directory mounted into `/workspaces/empty`.
# The instructions to add /usr/games to $PATH have been omitted for brevity.
docker run -it --rm -e ENVBUILDER_INIT_SCRIPT='/usr/games/cowsay "happy hacking"' -v $PWD:/workspaces/empty ghcr.io/coder/envbuilder:latest
```

If your `devcontainer.json` is not present in the root of the workspace folder,
you may need to specify the relative path to the file with
`ENVBUILDER_DEVCONTAINER_DIR`:

```shell
ls build/
Dockerfile devcontainer.json
docker run -it --rm -e ENVBUILDER_INIT_SCRIPT='echo $PATH' -e ENVBUILDER_DEVCONTAINER_DIR=build -v $PWD:/workspaces/empty ghcr.io/coder/envbuilder:latest
```

## Usage with Coder

Coder provides sample
[Docker](https://github.com/coder/coder/tree/main/examples/templates/devcontainer-docker)
and
[Kubernetes](https://github.com/coder/coder/tree/main/examples/templates/devcontainer-kubernetes)
templates for use with Envbuilder. You can import these templates and modify them to fit
your specific requirements.

Below are some specific points to be aware of when using Envbuilder with a Coder
deployment:

- The `ENVBUILDER_INIT_SCRIPT` should execute `coder_agent.main.init_script` in
  order for you to be able to connect to your workspace.
- In order for the Agent init script to be able to fetch the agent binary from
  your Coder deployment, the resulting Devcontainer must contain a download tool
  such as `curl`, `wget`, or `busybox`.
- `CODER_AGENT_TOKEN` should be included in the environment variables for the
  Envbuilder container. You can also set `CODER_AGENT_URL` if required.


### Git Branch Selection

Choose a branch using `ENVBUILDER_GIT_URL` with a _ref/heads_ reference. For instance:

```
ENVBUILDER_GIT_URL=https://github.com/coder/envbuilder-starter-devcontainer/#refs/heads/my-feature-branch
```

## Container Registry Authentication

envbuilder uses Kaniko to build containers. You should [follow their instructions](https://github.com/GoogleContainerTools/kaniko#pushing-to-different-registries) to create an authentication configuration.

After you have a configuration that resembles the following:

```json
{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "base64-encoded-username-and-password"
    }
  }
}
```

`base64` encode the JSON and provide it to envbuilder as the `ENVBUILDER_DOCKER_CONFIG_BASE64` environment variable.

Alternatively, if running `envbuilder` in Kubernetes, you can create an `ImagePullSecret` and
pass it into the pod as a volume mount. This example will work for all registries.

```shell
# Artifactory example
kubectl create secret docker-registry regcred \
  --docker-server=my-artifactory.jfrog.io \
  --docker-username=read-only \
  --docker-password=secret-pass \
  --docker-email=me@example.com \
  -n coder
```

```hcl
resource "kubernetes_deployment" "example" {
  metadata {
    namespace = coder
  }
  spec {
    spec {
      container {
        # Define the volumeMount with the pull credentials
        volume_mount {
          name       = "docker-config-volume"
          mount_path = "/.envbuilder/config.json"
          sub_path   = ".dockerconfigjson"
        }
      }
      # Define the volume which maps to the pull credentials
      volume {
        name = "docker-config-volume"
        secret {
          secret_name = "regcred"
        }
      }
    }
  }
}
```

### Docker Hub

Authenticate with `docker login` to generate `~/.docker/config.json`. Encode this file using the `base64` command:

```bash
$ base64 -w0 ~/.docker/config.json
ewoJImF1dGhzIjogewoJCSJodHRwczovL2luZGV4LmRvY2tlci5pby92MS8iOiB7CgkJCSJhdXRoIjogImJhc2U2NCBlbmNvZGVkIHRva2VuIgoJCX0KCX0KfQo=
```

Provide the encoded JSON config to envbuilder:

```env
ENVBUILDER_DOCKER_CONFIG_BASE64=ewoJImF1dGhzIjogewoJCSJodHRwczovL2luZGV4LmRvY2tlci5pby92MS8iOiB7CgkJCSJhdXRoIjogImJhc2U2NCBlbmNvZGVkIHRva2VuIgoJCX0KCX0KfQo=
```

### Docker-in-Docker

See [here](./docs/docker.md) for instructions on running Docker containers inside
environments built by Envbuilder.

## Git Authentication

Two methods of authentication are supported:

### HTTP Authentication

If `ENVBUILDER_GIT_URL` starts with `http://` or `https://`, envbuilder will
authenticate with `ENVBUILDER_GIT_USERNAME` and `ENVBUILDER_GIT_PASSWORD`, if set.

For access token-based authentication, follow the following schema (if empty, there's no need to provide the field):

| Provider     | `ENVBUILDER_GIT_USERNAME` | `ENVBUILDER_GIT_PASSWORD` |
| ------------ | ------------------------- | ------------------------- |
| GitHub       | [access-token]            |                           |
| GitLab       | oauth2                    | [access-token]            |
| BitBucket    | x-token-auth              | [access-token]            |
| Azure DevOps | [access-token]            |                           |

If using envbuilder inside of [Coder](https://github.com/coder/coder), you can use the `coder_external_auth` Terraform resource to automatically provide this token on workspace creation:

```hcl
data "coder_external_auth" "github" {
    id = "github"
}

resource "docker_container" "dev" {
    env = [
        ENVBUILDER_GIT_USERNAME = data.coder_external_auth.github.access_token,
    ]
}
```

### SSH Authentication

If `ENVBUILDER_GIT_URL` does not start with `http://` or `https://`,
envbuilder will assume SSH authentication. You have the following options:

1. Public/Private key authentication: set `ENVBUILDER_GIT_SSH_PRIVATE_KEY_PATH` to the path of an
   SSH private key mounted inside the container. Envbuilder will use this SSH
   key to authenticate. Example:

   ```bash
    docker run -it --rm \
      -v /tmp/envbuilder:/workspaces \
      -e ENVBUILDER_GIT_URL=git@example.com:path/to/private/repo.git \
      -e ENVBUILDER_INIT_SCRIPT=bash \
      -e ENVBUILDER_GIT_SSH_PRIVATE_KEY_PATH=/.ssh/id_rsa \
      -v /home/user/id_rsa:/.ssh/id_rsa \
      ghcr.io/coder/envbuilder
   ```

1. Agent-based authentication: set `SSH_AUTH_SOCK` and mount in your agent socket, for example:

  ```bash
    docker run -it --rm \
      -v /tmp/envbuilder:/workspaces \
      -e ENVBUILDER_GIT_URL=git@example.com:path/to/private/repo.git \
      -e ENVBUILDER_INIT_SCRIPT=bash \
      -e SSH_AUTH_SOCK=/tmp/ssh-auth-sock \
      -v $SSH_AUTH_SOCK:/tmp/ssh-auth-sock \
      ghcr.io/coder/envbuilder
  ```

> Note: by default, envbuilder will accept and log all host keys. If you need
> strict host key checking, set `SSH_KNOWN_HOSTS` and mount in a `known_hosts`
> file.


## Layer Caching

Cache layers in a container registry to speed up builds. To enable caching, [authenticate with your registry](#container-registry-authentication) and set the `ENVBUILDER_CACHE_REPO` environment variable.

```bash
CACHE_REPO=ghcr.io/coder/repo-cache
```

To experiment without setting up a registry, use `ENVBUILDER_LAYER_CACHE_DIR`:

```bash
docker run -it --rm \
  -v /tmp/envbuilder-cache:/cache \
  -e ENVBUILDER_LAYER_CACHE_DIR=/cache
  ...
```

Each layer is stored in the registry as a separate image. The image tag is the hash of the layer's contents. The image digest is the hash of the image tag. The image digest is used to pull the layer from the registry.

The performance improvement of builds depends on the complexity of your
Dockerfile. For
[`coder/coder`](https://github.com/coder/coder/blob/main/.devcontainer/Dockerfile),
uncached builds take 36m while cached builds take 40s (~98% improvement).

## Pushing the built image

Set `ENVBUILDER_PUSH_IMAGE=1` to push the entire image to the cache repo
in addition to individual layers. `ENVBUILDER_CACHE_REPO` **must** be set in
order for this to work.

> **Note:** this option forces Envbuilder to perform a "reproducible" build.
> This will force timestamps for all newly added files to be set to the start of the UNIX epoch.

## Probe Layer Cache

To check for the presence of a pre-built image, set
`ENVBUILDER_GET_CACHED_IMAGE=1`. Instead of building the image, this will
perform a "dry-run" build of the image, consulting `ENVBUILDER_CACHE_REPO` for
each layer.

If any layer is found not to be present in the cache repo, envbuilder
will exit with an error. Otherwise, the image will be emitted in the log output prefixed with the string
`ENVBUILDER_CACHED_IMAGE=...`.

## Image Caching

When the base container is large, it can take a long time to pull the image from the registry. You can pre-pull the image into a read-only volume and mount it into the container to speed up builds.

```bash
# Pull your base image from the registry to a local directory.
docker run --rm \
  -v /tmp/kaniko-cache:/cache \
  gcr.io/kaniko-project/warmer:latest \
    --cache-dir=/cache \
    --image=<your-image>

# Run envbuilder with the local image cache.
docker run -it --rm \
  -v /tmp/kaniko-cache:/image-cache:ro \
  -e ENVBUILDER_BASE_IMAGE_CACHE_DIR=/image-cache
```

In Kubernetes, you can pre-populate a persistent volume with the same warmer image, then mount it into many workspaces with the [`ReadOnlyMany` access mode](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes).

A sample script to pre-fetch a number of images can be viewed [here](./examples/kaniko-cache-warmer.sh). This can be run, for example, as a cron job to periodically fetch the latest versions of a number of base images.

## Setup Script

The `ENVBUILDER_SETUP_SCRIPT` environment variable dynamically configures the user and init command (PID 1) after the container build process.

> [!NOTE]
> `TARGET_USER` is passed to the setup script to specify who will execute `ENVBUILDER_INIT_COMMAND` (e.g., `code`).

Write the following to `$ENVBUILDER_ENV` to shape the container's init process:

- `TARGET_USER`: Identifies the `ENVBUILDER_INIT_COMMAND` executor (e.g.`root`).
- `ENVBUILDER_INIT_COMMAND`: Defines the command executed by `TARGET_USER` (e.g. `/bin/bash`).
- `ENVBUILDER_INIT_ARGS`: Arguments provided to `ENVBUILDER_INIT_COMMAND` (e.g. `-c 'sleep infinity'`).

```bash
# init.sh - change the init if systemd exists
if command -v systemd >/dev/null; then
  echo "Hey 👋 $TARGET_USER"
  echo ENVBUILDER_INIT_COMMAND=systemd >> $ENVBUILDER_ENV
else
  echo ENVBUILDER_INIT_COMMAND=bash >> $ENVBUILDER_ENV
fi

# run envbuilder with the setup script
docker run -it --rm \
  -v ./:/some-dir \
  -e ENVBUILDER_SETUP_SCRIPT=/some-dir/init.sh \
  ...
```

## Custom Certificates

- [`ENVBUILDER_SSL_CERT_FILE`](https://go.dev/src/crypto/x509/root_unix.go#L19): Specifies the path to an SSL certificate.
- [`ENVBUILDER_SSL_CERT_DIR`](https://go.dev/src/crypto/x509/root_unix.go#L25): Identifies which directory to check for SSL certificate files.
- `ENVBUILDER_SSL_CERT_BASE64`: Specifies a base64-encoded SSL certificate that will be added to the global certificate pool on start.

## Unsupported features

### Development Containers

The table keeps track of features we would love to implement. Feel free to [create a new issue](https://github.com/coder/envbuilder/issues/new) if you want Envbuilder to support it.

| Name                     | Description                                                                                                  | Known issues                                           |
| ------------------------ | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------ |
| Volume mounts            | Volumes are used to persist data and share directories between the host and container.                       | [#220](https://github.com/coder/envbuilder/issues/220) |
| Port forwarding          | Port forwarding allows exposing container ports to the host, making services accessible.                     | [#48](https://github.com/coder/envbuilder/issues/48)   |
| Script init & Entrypoint | `init` adds a tiny init process to the container and `entrypoint` sets a script to run at container startup. | [#221](https://github.com/coder/envbuilder/issues/221) |
| Customizations           | Product specific properties, for instance: _VS Code_ `settings` and `extensions`.                            | [#43](https://github.com/coder/envbuilder/issues/43)   |
| Composefile              | Define multiple containers and services for more complex development environments.                           | [#236](https://github.com/coder/envbuilder/issues/236) |

### Devfile

> [Devfiles](https://devfile.io/) automate and simplify development process by adopting the existing devfiles that are available in the [public community registry](https://registry.devfile.io/viewer).

Issue: [#113](https://github.com/coder/envbuilder/issues/113)

# Local Development

Building `envbuilder` currently **requires** a Linux system.

On MacOS or Windows systems, we recommend either using a VM or the provided `.devcontainer` for development.

**Additional Requirements:**

- `go 1.22`
- `make`
- Docker daemon (for running tests)

**Makefile targets:**

- `build`: builds and tags `envbuilder:latest` for your current architecture.
- `develop`: runs `envbuilder:latest` against a sample Git repository.
- `test`: run tests.
- `test-registry`: stands up a local registry for caching images used in tests.

<!--- Code generated by docsgen. DO NOT EDIT. --->
<!--- START docsgen --->
## Environment Variables

| Flag | Environment variable | Default | Description |
| - | - | - | - |
| `--setup-script` | `ENVBUILDER_SETUP_SCRIPT` |  | The script to run before the init script. It runs as the root user regardless of the user specified in the devcontainer.json file. SetupScript is ran as the root user prior to the init script. It is used to configure envbuilder dynamically during the runtime. e.g. specifying whether to start systemd or tiny init for PID 1. |
| `--init-script` | `ENVBUILDER_INIT_SCRIPT` |  | The script to run to initialize the workspace. Default: `sleep infinity`. |
| `--init-command` | `ENVBUILDER_INIT_COMMAND` |  | The command to run to initialize the workspace. Default: `/bin/sh`. |
| `--init-args` | `ENVBUILDER_INIT_ARGS` |  | The arguments to pass to the init command. They are split according to /bin/sh rules with https://github.com/kballard/go-shellquote. |
| `--cache-repo` | `ENVBUILDER_CACHE_REPO` |  | The name of the container registry to push the cache image to. If this is empty, the cache will not be pushed. |
| `--base-image-cache-dir` | `ENVBUILDER_BASE_IMAGE_CACHE_DIR` |  | The path to a directory where the base image can be found. This should be a read-only directory solely mounted for the purpose of caching the base image. |
| `--layer-cache-dir` | `ENVBUILDER_LAYER_CACHE_DIR` |  | The path to a directory where built layers will be stored. This spawns an in-memory registry to serve the layers from. |
| `--devcontainer-dir` | `ENVBUILDER_DEVCONTAINER_DIR` |  | The path to the folder containing the devcontainer.json file that will be used to build the workspace and can either be an absolute path or a path relative to the workspace folder. If not provided, defaults to `.devcontainer`. |
| `--devcontainer-json-path` | `ENVBUILDER_DEVCONTAINER_JSON_PATH` |  | The path to a devcontainer.json file that is either an absolute path or a path relative to DevcontainerDir. This can be used in cases where one wants to substitute an edited devcontainer.json file for the one that exists in the repo. |
| `--dockerfile-path` | `ENVBUILDER_DOCKERFILE_PATH` |  | The relative path to the Dockerfile that will be used to build the workspace. This is an alternative to using a devcontainer that some might find simpler. |
| `--build-context-path` | `ENVBUILDER_BUILD_CONTEXT_PATH` |  | Can be specified when a DockerfilePath is specified outside the base WorkspaceFolder. This path MUST be relative to the WorkspaceFolder path into which the repo is cloned. |
| `--cache-ttl-days` | `ENVBUILDER_CACHE_TTL_DAYS` |  | The number of days to use cached layers before expiring them. Defaults to 7 days. |
| `--docker-config-base64` | `ENVBUILDER_DOCKER_CONFIG_BASE64` |  | The base64 encoded Docker config file that will be used to pull images from private container registries. |
| `--fallback-image` | `ENVBUILDER_FALLBACK_IMAGE` |  | Specifies an alternative image to use when neither an image is declared in the devcontainer.json file nor a Dockerfile is present. If there's a build failure (from a faulty Dockerfile) or a misconfiguration, this image will be the substitute. Set ExitOnBuildFailure to true to halt the container if the build faces an issue. |
| `--exit-on-build-failure` | `ENVBUILDER_EXIT_ON_BUILD_FAILURE` |  | Terminates the container upon a build failure. This is handy when preferring the FALLBACK_IMAGE in cases where no devcontainer.json or image is provided. However, it ensures that the container stops if the build process encounters an error. |
| `--force-safe` | `ENVBUILDER_FORCE_SAFE` |  | Ignores any filesystem safety checks. This could cause serious harm to your system! This is used in cases where bypass is needed to unblock customers. |
| `--insecure` | `ENVBUILDER_INSECURE` |  | Bypass TLS verification when cloning and pulling from container registries. |
| `--ignore-paths` | `ENVBUILDER_IGNORE_PATHS` |  | The comma separated list of paths to ignore when building the workspace. |
| `--skip-rebuild` | `ENVBUILDER_SKIP_REBUILD` |  | Skip building if the MagicFile exists. This is used to skip building when a container is restarting. e.g. docker stop -> docker start This value can always be set to true - even if the container is being started for the first time. |
| `--git-url` | `ENVBUILDER_GIT_URL` |  | The URL of a Git repository containing a Devcontainer or Docker image to clone. This is optional. |
| `--git-clone-depth` | `ENVBUILDER_GIT_CLONE_DEPTH` |  | The depth to use when cloning the Git repository. |
| `--git-clone-single-branch` | `ENVBUILDER_GIT_CLONE_SINGLE_BRANCH` |  | Clone only a single branch of the Git repository. |
| `--git-username` | `ENVBUILDER_GIT_USERNAME` |  | The username to use for Git authentication. This is optional. |
| `--git-password` | `ENVBUILDER_GIT_PASSWORD` |  | The password to use for Git authentication. This is optional. |
| `--git-ssh-private-key-path` | `ENVBUILDER_GIT_SSH_PRIVATE_KEY_PATH` |  | Path to an SSH private key to be used for Git authentication. |
| `--git-http-proxy-url` | `ENVBUILDER_GIT_HTTP_PROXY_URL` |  | The URL for the HTTP proxy. This is optional. |
| `--workspace-folder` | `ENVBUILDER_WORKSPACE_FOLDER` |  | The path to the workspace folder that will be built. This is optional. |
| `--ssl-cert-base64` | `ENVBUILDER_SSL_CERT_BASE64` |  | The content of an SSL cert file. This is useful for self-signed certificates. |
| `--export-env-file` | `ENVBUILDER_EXPORT_ENV_FILE` |  | Optional file path to a .env file where envbuilder will dump environment variables from devcontainer.json and the built container image. |
| `--post-start-script-path` | `ENVBUILDER_POST_START_SCRIPT_PATH` |  | The path to a script that will be created by envbuilder based on the postStartCommand in devcontainer.json, if any is specified (otherwise the script is not created). If this is set, the specified InitCommand should check for the presence of this script and execute it after successful startup. |
| `--coder-agent-url` | `CODER_AGENT_URL` |  | URL of the Coder deployment. If CODER_AGENT_TOKEN is also set, logs from envbuilder will be forwarded here and will be visible in the workspace build logs. |
| `--coder-agent-token` | `CODER_AGENT_TOKEN` |  | Authentication token for a Coder agent. If this is set, then CODER_AGENT_URL must also be set. |
| `--coder-agent-subsystem` | `CODER_AGENT_SUBSYSTEM` |  | Coder agent subsystems to report when forwarding logs. The envbuilder subsystem is always included. |
| `--push-image` | `ENVBUILDER_PUSH_IMAGE` |  | Push the built image to a remote registry. This option forces a reproducible build. |
| `--get-cached-image` | `ENVBUILDER_GET_CACHED_IMAGE` |  | Print the digest of the cached image, if available. Exits with an error if not found. |
| `--remote-repo-build-mode` | `ENVBUILDER_REMOTE_REPO_BUILD_MODE` | `false` | Use the remote repository as the source of truth when building the image. Enabling this option ignores user changes to local files and they will not be reflected in the image. This can be used to improving cache utilization when multiple users are building working on the same repository. |
| `--verbose` | `ENVBUILDER_VERBOSE` |  | Enable verbose logging. |
<!--- END docsgen --->
