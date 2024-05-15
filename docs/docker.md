# Docker inside Envbuilder

There are a number of approaches you can use to have access to a Docker daemon
from inside Envbuilder:

## Docker Outside of Docker (DooD)

**Security:** None
**Convenience:** High

This approach re-uses the host Docker socket and passes it inside the container.
It is the simplest approach, but offers **no security** -- any process inside the
container that can connect to the Docker socket will have access to the
underlying host.
Only use it if you are the only person using the Docker socket (for example, if
you are experimenting on your own workstation).

Example:

```shell
docker run -it --rm \
    -v /tmp/envbuilder:/workspaces \
    -e ENVBUILDER_GIT_URL=https://github.com/coder/envbuilder \
    -e ENVBUILDER_DEVCONTAINER_DIR=/workspaces/envbuilder/examples/docker/01_dood \
    -e ENVBUILDER_INIT_SCRIPT=bash \
    ghcr.io/coder/envbuilder:latest
```


## Docker-in-Docker (DinD)

**Security:** Low
**Convenience:** High

This approach entails running a Docker daemon inside the container.
This requires a privileged container to run, and therefore has a wide potential
attack surface.

Example:

> Note that due to a lack of init system, the Docker daemon
> needs to be started separately inside the container. In this example, we
> create a custom entrypoint to start the Docker daemon in the background and
> call this entrypoint via `ENVBUILDER_INIT_SCRIPT`.

```shell
docker run -it --rm \
    --privileged \
    -v /tmp/envbuilder:/workspaces \
    -e ENVBUILDER_GIT_URL=https://github.com/coder/envbuilder \
    -e ENVBUILDER_DEVCONTAINER_DIR=/workspaces/envbuilder/examples/docker/02_dind \
    -e ENVBUILDER_INIT_SCRIPT=/entrypoint.sh \
    ghcr.io/coder/envbuilder:latest
```

This can also be accomplished using the [`docker-in-docker` Devcontainer feature](https://github.com/devcontainers/features/tree/main/src/docker-in-docker).

## Rootless DinD

**Security:** Medium
**Convenience:** Medium

This approach runs a Docker daemon in *rootless* mode.
While this still requires a privileged container, this allows you to restrict
usage of the `root` user inside the container, as the Docker daemon will be run
under a "fake" root user (via `rootlesskit`). The user inside the workspace can
then be a 'regular' user without root permissions.

> Note: Once again, we use a custom entrypoint via `ENVBUILDER_INIT_SCRIPT` to
> start the Docker daemon via `rootlesskit`.

Example:

```
docker run -it --rm \
    --privileged \
    -v /tmp/envbuilder:/workspaces \
    -e ENVBUILDER_GIT_URL=https://github.com/coder/envbuilder \
    -e ENVBUILDER_DEVCONTAINER_DIR=/workspaces/envbuilder/examples/docker/03_dind_rootless \
    -e ENVBUILDER_INIT_SCRIPT=/entrypoint.sh \
    ghcr.io/coder/envbuilder:latest
```

## Docker-in-Docker using Sysbox

**Security:** High
**Convenience:** Low for infra admins, high for users

This approach requires installing the [`sysbox-runc` container
runtime](https://github.com/nestybox/sysbox/blob/master/docs/user-guide/install-package.md).
This is an alternative container runtime that provides additional benefits,
including transparently enabling Docker inside workspaces. Most notably, it
**does not require a privileged container**, so you can allow developers root
access inside their workspaces, if required.

Example:
```
docker run -it --rm \
    --privileged \
    -v /tmp/envbuilder:/workspaces \
    -e ENVBUILDER_GIT_URL=https://github.com/coder/envbuilder \
    -e ENVBUILDER_DEVCONTAINER_DIR=/workspaces/envbuilder/examples/docker/02_dind \
    -e ENVBUILDER_INIT_SCRIPT=/entrypoint.sh \
    --runtime sysbox-runc \
    ghcr.io/coder/envbuilder:latest
```

For further information on Sysbox, please consult the [Sysbox
Documentation](https://github.com/nestybox/sysbox/blob/master/docs/user-guide/README.md).
