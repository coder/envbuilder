# Layer Caching

Cache layers in a container registry to speed up builds. To enable caching, [authenticate with your registry](#container-registry-authentication) and set the `ENVBUILDER_CACHE_REPO` environment variable.

```bash
CACHE_REPO=ghcr.io/coder/repo-cache
```

To experiment without setting up a registry, use `ENVBUILDER_LAYER_CACHE_DIR`:

```bash
docker run -it --rm \
  -v /tmp/envbuilder-cache:/cache \
  -e ENVBUILDER_LAYER_CACHE_DIR=/cache
  ...
```

Each layer is stored in the registry as a separate image. The image tag is the hash of the layer's contents. The image digest is the hash of the image tag. The image digest is used to pull the layer from the registry.

The performance improvement of builds depends on the complexity of your
Dockerfile. For
[`coder/coder`](https://github.com/coder/coder/blob/main/.devcontainer/Dockerfile),
uncached builds take 36m while cached builds take 40s (~98% improvement).

# Pushing the built image

Set `ENVBUILDER_PUSH_IMAGE=1` to push the entire image to the cache repo
in addition to individual layers. `ENVBUILDER_CACHE_REPO` **must** be set in
order for this to work.

> **Note:** this option forces Envbuilder to perform a "reproducible" build.
> This will force timestamps for all newly added files to be set to the start of the UNIX epoch.

# Probe Layer Cache

To check for the presence of a pre-built image, set
`ENVBUILDER_GET_CACHED_IMAGE=1`. Instead of building the image, this will
perform a "dry-run" build of the image, consulting `ENVBUILDER_CACHE_REPO` for
each layer.

If any layer is found not to be present in the cache repo, envbuilder
will exit with an error. Otherwise, the image will be emitted in the log output prefixed with the string
`ENVBUILDER_CACHED_IMAGE=...`.

# Image Caching

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
  -e ENVBUILDER_BASE_IMAGE_CACHE_DIR=/image-cache
```

In Kubernetes, you can pre-populate a persistent volume with the same warmer image, then mount it into many workspaces with the [`ReadOnlyMany` access mode](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes).

A sample script to pre-fetch a number of images can be viewed [here](./examples/kaniko-cache-warmer.sh). This can be run, for example, as a cron job to periodically fetch the latest versions of a number of base images.
