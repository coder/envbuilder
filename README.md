<p align="center">
  <a aria-label="Join the community on Discord" href="https://discord.gg/coder"><img src="https://img.shields.io/discord/747933592273027093?label=discord"></a>
  <a aria-label="Releases" href="https://github.com/coder/envbuilder/pkgs/container/envbuilder"><img alt="" src="https://img.shields.io/github/v/tag/coder/envbuilder"></a>
  <a aria-label="GoDoc" href="https://pkg.go.dev/github.com/coder/envbuilder"><img alt="" src="https://pkg.go.dev/badge/github.com/coder/envbuilder.svg"></a>
  <a aria-label="License" href="./LICENSE"><img alt="" src="https://img.shields.io/github/license/coder/envbuilder"></a>
</p>

# Envbuilder

![envbuilder](https://github.com/user-attachments/assets/0a49f5cd-2040-4a07-84ba-8b765b954e57)

_(Video created using [asciinema](https://github.com/asciinema/asciinema) and [agg](https://github.com/asciinema/agg))_

Build development environments from a Dockerfile on Docker, Kubernetes, and OpenShift. Allow developers to modify their environment in a tight feedback loop.

- Supports [`devcontainer.json`](https://containers.dev/) and `Dockerfile`
- Cache image layers with registries for speedy builds
- Runs on Kubernetes, Docker, and OpenShift

## Getting Started

The easiest way to get started is by running the `envbuilder` Docker container that clones a repository specified by `ENVBUILDER_GIT_URL`, builds the image from a Dockerfile or `devcontainer.json`, and runs the `$ENVBUILDER_INIT_SCRIPT` in the freshly built container.

> **Tips**:
> - The `/tmp/envbuilder` directory persists demo data between commands. You can choose a different directory if needed.
> - To clone a different branch, you append it to `ENVBUILDER_GIT_URL` in the form `#refs/heads/my-branch`. For example: `https://github.com/coder/envbuilder-starter-devcontainer#refs/heads/boring-prompt`.
```bash
docker run -it --rm
    -v /tmp/envbuilder:/workspaces
    -e ENVBUILDER_GIT_URL=https://github.com/coder/envbuilder-starter-devcontainer
    -e ENVBUILDER_INIT_SCRIPT=bash
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

Exit the container and re-run the `docker run` command. After the build completes, `htop` should be available in the container! 🥳

To explore more examples, tips, and advanced usage, check out the following guides:

- [Using Local Files](./docs/using-local-files.md)
- [Usage with Coder](./docs/usage-with-coder.md)
- [Container Registry Authentication](./docs/container-registry-auth.md)
- [Git Authentication](./docs/git-auth.md)
- [Caching](./docs/caching.md)
- [Custom Certificates & Proxies](./docs/proxy.md)
- [Users](./docs/users.md)

## Setup Script

The `ENVBUILDER_SETUP_SCRIPT` environment variable dynamically configures the user and init command (PID 1) after the container build process.

> **Note**: `TARGET_USER` is passed to the setup script to specify who will execute `ENVBUILDER_INIT_COMMAND` (e.g., `code`).

Write the following to `$ENVBUILDER_ENV` to shape the container's init process:

- `TARGET_USER`: Identifies the `ENVBUILDER_INIT_COMMAND` executor (e.g., `root`).
- `ENVBUILDER_INIT_COMMAND`: Defines the command executed by `TARGET_USER` (e.g. `/bin/bash`).
- `ENVBUILDER_INIT_ARGS`: Arguments provided to `ENVBUILDER_INIT_COMMAND` (e.g., `-c 'sleep infinity'`).

```bash
# init.sh - Change the init if systemd exists
if command -v systemd >/dev/null; then
  echo "Hey 👋 $TARGET_USER"
  echo ENVBUILDER_INIT_COMMAND=systemd >> $ENVBUILDER_ENV
else
  echo ENVBUILDER_INIT_COMMAND=bash >> $ENVBUILDER_ENV
fi

# Run envbuilder with the setup script
docker run -it --rm
  -v ./:/some-dir
  -e ENVBUILDER_SETUP_SCRIPT=/some-dir/init.sh
  ...
```

## Environment Variables

You can see all the supported environment variables in [this document](./docs/env-variables.md).

### Development Containers

[This document](./docs/devcontainer-spec-support.md) keeps track of what parts of the Dev Container specification Envbuilder currently supports.

Feel free to [create a new issue](https://github.com/coder/envbuilder/issues/new) if you'd like Envbuilder to support a particular feature.

### Devfile

> [Devfiles](https://devfile.io/) automate and simplify development by adopting existing devfiles available in the [public community registry](https://registry.devfile.io/viewer).

Issue: [#113](https://github.com/coder/envbuilder/issues/113)

## Contributing

Building `envbuilder` currently **requires** a Linux system.

On macOS or Windows systems, we recommend using a VM or the provided `.devcontainer` for development.

**Additional Requirements:**

- `go 1.22`
- `make`
- Docker daemon (for running tests)

**Makefile targets:**

- `build`: Builds and tags `envbuilder:latest` for your current architecture.
- `develop`: Runs `envbuilder:latest` against a sample Git repository.
- `test`: Runs tests.
- `test-registry`: Stands up a local registry for caching images used in tests.
- `docs/env-variables.md`: Updated the [environment variables documentation](./docs/env-variables.md).
  
**Submodule Handling Fix**

An issue concerning git's submodule handling has been resolved through iterative refinements. This fix ensures robust submodule cloning and URL resolution without relying on the calls to the git binary (current fallback).
