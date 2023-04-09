# envbuilder

Build development environments from repositories in a container on Kubernetes, Docker, or gVisor. Allow developers to customize their environment on pre-defined infrastructure.

- Supports `devcontainer.json` and `Dockerfile`
- Cache image layers with registries for speedy builds
- Runs on Kubernetes, Docker, and OpenShift 

## Quickstart

The easiest way to play with `envbuilder` is to launch a Docker container that builds a sample image.

```bash
docker run -it --rm \
    -e GIT_URL=https://github.com/vercel/next.js \
    ghcr.io/coder/envbuilder
```
