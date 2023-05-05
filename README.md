# envbuilder

[![discord](https://img.shields.io/discord/747933592273027093?label=discord)](https://discord.gg/coder)
[![release](https://img.shields.io/github/v/release/coder/envbuilder)](https://github.com/coder/envbuilder/releases/latest)
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

## Git Authentication

`GIT_USERNAME` and `GIT_PASSWORD` are environment variables to provide Git authentication for private repositories.

For access token-based authentication, follow the following schema (if empty, there's no need to provide the field):

| Provider     | `GIT_USERNAME` | `GIT_PASSWORD` |
| ------------ | -------------- | -------------- |
| GitHub       | [access-token] |                |
| GitLab       | oauth2         | [access-token] |
| BitBucket    | x-token-auth   | [access-token] |
| Azure DevOps | [access-token] |                |

If using envbuilder inside of [Coder](https://github.com/coder/coder), you can use the `coder_git_auth` Terraform resource to automatically provide this token on workspace creation:

```hcl
resource "coder_git_auth" "github" {
    id = "github"
}

resource "docker_container" "dev" {
    env = [
        GIT_USERNAME = coder_git_auth.github.access_token,
    ]
}
```

## Layer Caching

Cache layers in a container registry to speed up builds. To enable caching, [authenticate with your registry](#container-registry-authentication) and set the `CACHE_REPO` environment variable.

```bash
CACHE_REPO=ghcr.io/coder/repo-cache
```

Each layer is stored in the registry as a separate image. The image tag is the hash of the layer's contents. The image digest is the hash of the image tag. The image digest is used to pull the layer from the registry.
