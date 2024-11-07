# Root Privileges

Envbuilder always expects to be run as `root` in its container, as building an image will most likely require root privileges. Once the image is built, Envbuilder will drop root privileges and `exec` `ENVBUILDER_INIT_COMMAND` / `ENVBUILDER_INIT_SCRIPT` as a non-root user.

## Choosing a target user

Envbuilder will first attempt to switch to the `containerUser` defined `devcontainer.json`.
If this is not specified, it will look up the last `USER` directive from the specified `Dockerfile` or image.
If no alternative user is specified, Envbuilder will fallback to `root`.

When installing Devcontainer Features, Envbuilder will add a directive `USER ${remoteUser}` directive directly after the feature installation directives.
If `remoteUser` is not defined, it will default to `containerUser`.
