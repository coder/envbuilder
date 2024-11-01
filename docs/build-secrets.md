# Build Secrets

Envbuilder supports [build secrets](https://docs.docker.com/reference/dockerfile/#run---mounttypesecret). Build secrets are useful when you need to use sensitive information during the image build process and:
* the secrets should not be present in the built image.
* the secrets should not be accessible in the container after its build has concluded.

If your Dockerfile contains directives of the form `RUN --mount=type=secret,...`, Envbuilder will attempt to mount build secrets as specified in the directive. Unlike the `docker build` command, Envbuilder does not support the `--secret` flag. Instead, Envbuilder collects build secrets from the `ENVBUILDER_BUILD_SECRETS` environment variable. These build secrets will not be present in any cached layers or images that are pushed to an image repository. Nor will they be available at run time.

## Example

To illustrate build secrets in Envbuilder, let's build, push and run a container locally. These concepts will transfer to Kubernetes or other containerised environments. Note that this example is for illustrative purposes only and is not fit for production use. Production considerations are discussed in the next section.

First, start a local docker registry, so that we can push and inspect the built image:
```bash
docker run --rm -d -p 5000:5000 --name Envbuilder-registry registry:2
```

Then, build an image based on this Dockerfile:

```Dockerfile
FROM alpine:latest

RUN --mount=type=secret,id=FOO,env cat $FOO > /foo_secret_hash.txt
RUN --mount=type=secret,id=BAR,dst=/tmp/bar.secret cat /tmp/bar.secret > /bar_secret_hash.txt
```
using this command:
```bash
docker run -it --rm \
    -e ENVBUILDER_BUILD_SECRETS='FOO=envbuilder-test-secret-foo,BAR=envbuilder-test-secret-bar' \
    -e ENVBUILDER_INIT_SCRIPT='/bin/sh' \
    -e ENVBUILDER_CACHE_REPO=$(docker inspect Envbuilder-registry | jq -r '.[].NetworkSettings.IPAddress'):5000/test-container \
    -e ENVBUILDER_PUSH_IMAGE=1 \
    -v $PWD:/workspaces/empty \
    ghcr.io/coder/Envbuilder:latest
```

This will result in a shell session inside the built container.
You can now verify two things:
* The secrets provided to build are not available once the container is running. They are no longer on disk, nor are they in the process environment, or in `/proc/self/environ`. 
* The secrets were still useful during the build. The following comnmands show that the secrets had side effects inside the build, without remaining in the image:
```bash
cat /foo_secret_hash.txt
cat /bar_secret_hash.txt
```

### Verifying that images are secret free
To verify that the build image doesn't contain build secrets, run the following:

```bash
docker pull localhost:5000/test-container:latest
docker save -o test-container.tar localhost:5000/test-container
mkdir -p test-container
tar -xf test-container.tar -C test-container/
cd test-container
# Scan image layers for secrets:
find . -type f | xargs tar -xOf 2>/dev/null  | strings | grep -rin "envbuilder-test-secret"
# Scan image manifests for secrets:
find . -type f | xargs -n1 grep -rinI 'envbuilder-test-secret'
cd ../
```

The output of both find/grep commands should be empty.
To verify that it scans correctly, replace "envbuilder-test-secret" with "Envbuilder" and rerun the commands. It should find strings related to Envbuilder that are not secrets.

Having verified that no secrets were included in the image, we can now delete the artifacts that we saved to disk.
```bash
rm -r test-container
rm -r test-container.tar
```

## Security and Production Use
The example above ignores various security concerns for the sake of simple illustration. To use build secrets securely, consider these factors:

### Build Secret Purpose and Management
Build secrets are meant for use cases where the secret should not be accessible from the built image, nor from the running container. If you need the secret at runtime, use a volume instead. Volumes that are mounted into a container will not be included in the final image, but still be available at runtime. 

Build secrets are only protected if they are not copied or moved from their location as designated in the `RUN` directive. If a build secret is used, care should be taken to ensure that it is not copied or otherwise persisted into an image layer beyond the control of Envbuilder.

### Who should be able to access build secrets, when and where?
The secure way to use build secrets with Envbuilder is to deny users access to the platform that hosts Envbuilder. Only grant access to the Envbuilder container once it has concluded its build, using a trusted non-platform channel like ssh or the coder agent running inside the container. Once control has been handed to such a runtime container process, Envbuilder will have cleared all secrets that it set from the container.

Anyone with sufficient access to attach directly to the container (eg. using `kubectl`), will be able to read build secrets if they attach to the container before it has concluded its build. Anyone with sufficient access to the platform that hosts the Envbuilder container will also be able to read these build secrets from where the platform stores them. This is true for other build systems, and containerised software in general.

If secrets should be accessible at runtime, do not use build secrets. Rather, mount the secret data using a volume or environment variable. Envbuilder will not include mounted volumes in the image that it pushes to any cache repositories, but they will still be available to users that connect to the container.

### Container Management beyond Envbuilder's control
Container orchestration systems mount certain artifacts into containers for various reasons. It is possible that some of these might grant indirect access to build secrets. Consider kubernetes. It will mount a service account token into running containers. Depending on the access granted to this service account token, it may be possible to read build secrets and other sensitive data using the kubernetes API. This should not be possible by default, but Envbuilder cannot provide such a guarantee.

When building a system that uses Envbuilder, ensure that your platform does not expose unintended secret information to the container.