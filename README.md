# envbuilder

Build a development environment from `devcontainer.json` or `Dockerfile` inside of a container. Enable developers to customize their environment on pre-defined infrastructure.

- Supports `devcontainer.json` and `Dockerfile`
- Cache image layers with registries
- Runs in Docker, Kubernetes, or gVisor

## Quickstart

The easiest way to play with `envbuilder` is to launch a Docker container that builds a sample image.

```bash
docker run -it --rm \
    -e REPO_URL=https://github.com/vercel/next.js \
    ghcr.io/coder/envbuilder
```
