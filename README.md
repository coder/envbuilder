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

The easiest way to get started is to run the `envbuilder` Docker container that clones a repository, builds the image from a Dockerfile, and runs the `$INIT_SCRIPT` in the freshly built container.

> `/tmp/envbuilder` directory persists demo data between commands. You can choose a different directory.

```bash
docker run -it --rm \
    -v /tmp/envbuilder:/workspaces \
    -e GIT_URL=https://github.com/coder/envbuilder-starter-devcontainer \
    -e INIT_SCRIPT=bash \
    ghcr.io/coder/envbuilder
```

Edit `.devcontainer/Dockerfile` to add `htop`:

```bash
$ vim .devcontainer/Dockerfile
```

```diff
- RUN apt-get install vim sudo -y
+ RUN apt-get install vim sudo htop -y
```

Exit the container, and re-run the `docker run` command... after the build completes, `htop` should exist in the container! 🥳

### Git Branch Selection

Choose a branch using `GIT_URL` with a _ref/heads_ reference. For instance:

```
GIT_URL=https://github.com/coder/envbuilder-starter-devcontainer/#refs/heads/my-feature-branch
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

`base64` encode the JSON and provide it to envbuilder as the `DOCKER_CONFIG_BASE64` environment variable.

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
          mount_path = "/envbuilder/config.json"
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
DOCKER_CONFIG_BASE64=ewoJImF1dGhzIjogewoJCSJodHRwczovL2luZGV4LmRvY2tlci5pby92MS8iOiB7CgkJCSJhdXRoIjogImJhc2U2NCBlbmNvZGVkIHRva2VuIgoJCX0KCX0KfQo=
```

## Git Authentication

`GIT_USERNAME` and `GIT_PASSWORD` are environment variables to provide Git authentication for private repositories.

For access token-based authentication, follow the following schema (if empty, there's no need to provide the field):

| Provider     | `GIT_USERNAME` | `GIT_PASSWORD` |
| ------------ | -------------- | -------------- |
| GitHub       | [access-token] |                |
| GitLab       | oauth2         | [access-token] |
| BitBucket    | x-token-auth   | [access-token] |
| Azure DevOps | [access-token] |                |

If using envbuilder inside of [Coder](https://github.com/coder/coder), you can use the `coder_external_auth` Terraform resource to automatically provide this token on workspace creation:

```hcl
data "coder_external_auth" "github" {
    id = "github"
}

resource "docker_container" "dev" {
    env = [
        GIT_USERNAME = data.coder_external_auth.github.access_token,
    ]
}
```

## Layer Caching

Cache layers in a container registry to speed up builds. To enable caching, [authenticate with your registry](#container-registry-authentication) and set the `CACHE_REPO` environment variable.

```bash
CACHE_REPO=ghcr.io/coder/repo-cache
```

To experiment without setting up a registry, use `LAYER_CACHE_DIR`:

```bash
docker run -it --rm \
  -v /tmp/envbuilder-cache:/cache \
  -e LAYER_CACHE_DIR=/cache
  ...
```

Each layer is stored in the registry as a separate image. The image tag is the hash of the layer's contents. The image digest is the hash of the image tag. The image digest is used to pull the layer from the registry.

The performance improvement of builds depends on the complexity of your Dockerfile. For [`coder/coder`](https://github.com/coder/coder/blob/main/.devcontainer/Dockerfile), uncached builds take 36m while cached builds take 40s (~98% improvement).

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
  -e BASE_IMAGE_CACHE_DIR=/image-cache
```

In Kubernetes, you can pre-populate a persistent volume with the same warmer image, then mount it into many workspaces with the [`ReadOnlyMany` access mode](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes).

A sample script to pre-fetch a number of images can be viewed [here](./examples/kaniko-cache-warmer.sh). This can be run, for example, as a cron job to periodically fetch the latest versions of a number of base images.

## Setup Script

The `SETUP_SCRIPT` environment variable dynamically configures the user and init command (PID 1) after the container build process.

> [!NOTE]
> `TARGET_USER` is passed to the setup script to specify who will execute `INIT_COMMAND` (e.g., `code`).

Write the following to `$ENVBUILDER_ENV` to shape the container's init process:

- `TARGET_USER`: Identifies the `INIT_COMMAND` executor (e.g.`root`).
- `INIT_COMMAND`: Defines the command executed by `TARGET_USER` (e.g. `/bin/bash`).
- `INIT_ARGS`: Arguments provided to `INIT_COMMAND` (e.g. `-c 'sleep infinity'`).

```bash
# init.sh - change the init if systemd exists
if command -v systemd >/dev/null; then
  echo "Hey 👋 $TARGET_USER"
  echo INIT_COMMAND=systemd >> $ENVBUILDER_ENV
else
  echo INIT_COMMAND=bash >> $ENVBUILDER_ENV
fi

# run envbuilder with the setup script
docker run -it --rm \
  -v ./:/some-dir \
  -e SETUP_SCRIPT=/some-dir/init.sh \
  ...
```

## Custom Certificates

- [`SSL_CERT_FILE`](https://go.dev/src/crypto/x509/root_unix.go#L19): Specifies the path to an SSL certificate.
- [`SSL_CERT_DIR`](https://go.dev/src/crypto/x509/root_unix.go#L25): Identifies which directory to check for SSL certificate files.
- `SSL_CERT_BASE64`: Specifies a base64-encoded SSL certificate that will be added to the global certificate pool on start.

# Local Development

Building `envbuilder` currently **requires** a Linux system.

On MacOS or Windows systems, we recommend either using a VM or the provided `.devcontainer` for development.

**Additional Requirements:**

- `go 1.21`
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

| Environment variable | Default | Description |
| - | - | - |
| SETUP_SCRIPT |  | SetupScript is the script to run before the init script. It runs as the root user regardless of the user specified in the devcontainer.json file. SetupScript is ran as the root user prior to the init script. It is used to configure envbuilder dynamically during the runtime. e.g. specifying whether to start systemd or tiny init for PID 1. |
| INIT_SCRIPT | sleep infinity | InitScript is the script to run to initialize the workspace. |
| INIT_COMMAND | /bin/sh | InitCommand is the command to run to initialize the workspace. |
| INIT_ARGS |  | InitArgs are the arguments to pass to the init command. They are split according to /bin/sh rules with https://github.com/kballard/go-shellquote. |
| CACHE_REPO |  | CacheRepo is the name of the container registry to push the cache image to. If this is empty, the cache will not be pushed. |
| BASE_IMAGE_CACHE_DIR |  | BaseImageCacheDir is the path to a directory where the base image can be found. This should be a read-only directory solely mounted for the purpose of caching the base image. |
| LAYER_CACHE_DIR |  | LayerCacheDir is the path to a directory where built layers will be stored. This spawns an in-memory registry to serve the layers from. |
| DEVCONTAINER_DIR |  | DevcontainerDir is a path to the folder containing the devcontainer.json file that will be used to build the workspace and can either be an absolute path or a path relative to the workspace folder. If not provided, defaults to `.devcontainer`. |
| DEVCONTAINER_JSON_PATH |  | DevcontainerJSONPath is a path to a devcontainer.json file that is either an absolute path or a path relative to DevcontainerDir. This can be used in cases where one wants to substitute an edited devcontainer.json file for the one that exists in the repo. |
| DOCKERFILE_PATH |  | DockerfilePath is a relative path to the Dockerfile that will be used to build the workspace. This is an alternative to using a devcontainer that some might find simpler. |
| BUILD_CONTEXT_PATH |  | BuildContextPath can be specified when a DockerfilePath is specified outside the base WorkspaceFolder. This path MUST be relative to the WorkspaceFolder path into which the repo is cloned. |
| CACHE_TTL_DAYS |  | CacheTTLDays is the number of days to use cached layers before expiring them. Defaults to 7 days. |
| DOCKER_CONFIG_BASE64 |  | DockerConfigBase64 is a base64 encoded Docker config file that will be used to pull images from private container registries. |
| FALLBACK_IMAGE |  | FallbackImage specifies an alternative image to use when neither an image is declared in the devcontainer.json file nor a Dockerfile is present. If there's a build failure (from a faulty Dockerfile) or a misconfiguration, this image will be the substitute. Set ExitOnBuildFailure to true to halt the container if the build faces an issue. |
| EXIT_ON_BUILD_FAILURE |  | ExitOnBuildFailure terminates the container upon a build failure. This is handy when preferring the FALLBACK_IMAGE in cases where no devcontainer.json or image is provided. However, it ensures that the container stops if the build process encounters an error. |
| FORCE_SAFE |  | ForceSafe ignores any filesystem safety checks. This could cause serious harm to your system! This is used in cases where bypass is needed to unblock customers. |
| INSECURE |  | Insecure bypasses TLS verification when cloning and pulling from container registries. |
| IGNORE_PATHS | /var/run | IgnorePaths is a comma separated list of paths to ignore when building the workspace. |
| SKIP_REBUILD |  | SkipRebuild skips building if the MagicFile exists. This is used to skip building when a container is restarting. e.g. docker stop -> docker start This value can always be set to true - even if the container is being started for the first time. |
| GIT_URL |  | GitURL is the URL of the Git repository to clone. This is optional. |
| GIT_CLONE_DEPTH |  | GitCloneDepth is the depth to use when cloning the Git repository. |
| GIT_CLONE_SINGLE_BRANCH |  | GitCloneSingleBranch clones only a single branch of the Git repository. |
| GIT_USERNAME |  | GitUsername is the username to use for Git authentication. This is optional. |
| GIT_PASSWORD |  | GitPassword is the password to use for Git authentication. This is optional. |
| GIT_HTTP_PROXY_URL |  | GitHTTPProxyURL is the url for the http proxy. This is optional. |
| WORKSPACE_FOLDER |  | WorkspaceFolder is the path to the workspace folder that will be built. This is optional. |
| SSL_CERT_BASE64 |  | SSLCertBase64 is the content of an SSL cert file. This is useful for self-signed certificates. |
| EXPORT_ENV_FILE |  | ExportEnvFile is an optional file path to a .env file where envbuilder will dump environment variables from devcontainer.json and the built container image. |
| POST_START_SCRIPT_PATH |  | PostStartScriptPath is the path to a script that will be created by envbuilder based on the postStartCommand in devcontainer.json, if any is specified (otherwise the script is not created). If this is set, the specified InitCommand should check for the presence of this script and execute it after successful startup. |
<!--- END docsgen --->
