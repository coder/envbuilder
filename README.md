# envbuilder

[![discord](https://img.shields.io/discord/747933592273027093?label=discord)](https://discord.gg/coder)
[![release](https://img.shields.io/github/v/tag/coder/envbuilder)](https://github.com/coder/envbuilder/pkgs/container/envbuilder)
[![godoc](https://pkg.go.dev/badge/github.com/coder/envbuilder.svg)](https://pkg.go.dev/github.com/coder/envbuilder)
[![license](https://img.shields.io/github/license/coder/envbuilder)](./LICENSE)

Build development environments from a Dockerfile on Docker, Kubernetes, and OpenShift. Allow developers to modify their environment in a tight feedback loop.

- Supports a subset of [`devcontainer.json`](https://containers.dev/) and `Dockerfile`. Currently support is missing for the following `devcontainer.json` features

  - `image`
  - `build`
  - `runArgs`
  - `workspaceFolder`

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

> `/tmp/envbuilder` is used to persist data between commands for the purpose of this demo. You can change it to any directory you want.

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

## Setup Script

The `SETUP_SCRIPT` environment variable dynamically configures the user and init command (PID 1) after the container build process.

> **Note** > `TARGET_USER` is passed to the setup script to specify who will execute `INIT_COMMAND` (e.g., `code`).

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
