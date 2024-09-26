<p align="center">
  <a href="https://nextjs.org" aria-label="Envbuilder">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="./docs/images/dark-logo.svg">
      <img src="./docs/images/light-logo.svg" height="75">
    </picture>
  </a>
</p>

<p align="center">
  <a aria-label="Join the community on Discord" href="https://discord.gg/coder"><img src="https://img.shields.io/discord/747933592273027093?label=discord"></a>
  <a aria-label="Releases" href="https://github.com/coder/envbuilder/pkgs/container/envbuilder"><img alt="" src="https://img.shields.io/github/v/tag/coder/envbuilder"></a>
  <a aria-label="GoDoc" href="https://pkg.go.dev/github.com/coder/envbuilder"><img alt="" src="https://pkg.go.dev/badge/github.com/coder/envbuilder.svg"></a>
  <a aria-label="License" href="./LICENSE"><img alt="" src="https://img.shields.io/github/license/coder/envbuilder"></a>
</p>

# Envbuilder

Build development environments from a Dockerfile on Docker, Kubernetes, and OpenShift. Allow developers to modify their environment in a tight feedback loop.

- Supports [`devcontainer.json`](https://containers.dev/) and `Dockerfile`
- Cache image layers with registries for speedy builds
- Runs on Kubernetes, Docker, and OpenShift

## Getting Started

The easiest way to get started is by running the `envbuilder` Docker container that clones a repository, builds the image from a Dockerfile, and runs the `$ENVBUILDER_INIT_SCRIPT` in the freshly built container.

> **Note**: The `/tmp/envbuilder` directory persists demo data between commands. You can choose a different directory if needed.

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
- [Custom Certificates](./docs/custom-certificates.md)

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

## Unsupported Features

### Development Containers

The table below keeps track of features we plan to implement. Feel free to [create a new issue](https://github.com/coder/envbuilder/issues/new) if you'd like Envbuilder to support a particular feature.

| Name                     | Description                                                                                                   | Known Issues                                           |
| ------------------------ | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| Volume mounts            | Volumes are used to persist data and share directories between the host and container.                        | [#220](https://github.com/coder/envbuilder/issues/220) |
| Port forwarding          | Port forwarding allows exposing container ports to the host, making services accessible.                      | [#48](https://github.com/coder/envbuilder/issues/48)   |
| Script init & Entrypoint | `init` adds a tiny init process to the container, and `entrypoint` sets a script to run at container startup. | [#221](https://github.com/coder/envbuilder/issues/221) |
| Customizations           | Product-specific properties, e.g., _VS Code_ settings and extensions.                                         | [#43](https://github.com/coder/envbuilder/issues/43)   |
| Composefile              | Define multiple containers and services for more complex development environments.                            | [#236](https://github.com/coder/envbuilder/issues/236) |

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
