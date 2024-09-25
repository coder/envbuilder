# Using local files

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
docker run -it --rm -e ENVBUILDER_INIT_SCRIPT='bash' -v $PWD:/workspaces/empty ghcr.io/coder/envbuilder:latest
```

Alternatively, if you prefer to mount your project files elsewhere, tell
Envbuilder where to find them by specifying `ENVBUILDER_WORKSPACE_FOLDER`:

```shell
docker run -it --rm -e ENVBUILDER_INIT_SCRIPT='bash ' -e ENVBUILDER_WORKSPACE_FOLDER=/src -v $PWD:/src ghcr.io/coder/envbuilder:latest
```

By default, Envbuilder will look for a `devcontainer.json` or `Dockerfile` in
both `${ENVBUILDER_WORKSPACE_FOLDER}` and `${ENVBUILDER_WORKSPACE_FOLDER}/.devcontainer`.
You can control where it looks with `ENVBUILDER_DEVCONTAINER_DIR` if needed.

```shell
ls build/
Dockerfile devcontainer.json
docker run -it --rm -e ENVBUILDER_INIT_SCRIPT='bash' -e ENVBUILDER_DEVCONTAINER_DIR=build -v $PWD:/src ghcr.io/coder/envbuilder:latest
```
