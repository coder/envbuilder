# Container Registry Authentication

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

`base64` encode the JSON and provide it to envbuilder as the `ENVBUILDER_DOCKER_CONFIG_BASE64` environment variable.

Alternatively, if running `envbuilder` in Kubernetes, you can create an `ImagePullSecret` and
pass it into the pod as a volume mount. This example will work for all registries.

```shell
# Artifactory example
kubectl create secret docker-registry regcred \
  --docker-server=my-artifactory.jfrog.io \
  --docker-username=read-only \
  --docker-password=secret-pass \
  --docker-email=me@example.com \
  -n coder
```

```hcl
resource "kubernetes_deployment" "example" {
  metadata {
    namespace = coder
  }
  spec {
    spec {
      container {
        # Define the volumeMount with the pull credentials
        volume_mount {
          name       = "docker-config-volume"
          mount_path = "/.envbuilder/config.json"
          sub_path   = ".dockerconfigjson"
        }
      }
      # Define the volume which maps to the pull credentials
      volume {
        name = "docker-config-volume"
        secret {
          secret_name = "regcred"
        }
      }
    }
  }
}
```

## Docker Hub

Authenticate with `docker login` to generate `~/.docker/config.json`. Encode this file using the `base64` command:

```bash
$ base64 -w0 ~/.docker/config.json
ewoJImF1dGhzIjogewoJCSJodHRwczovL2luZGV4LmRvY2tlci5pby92MS8iOiB7CgkJCSJhdXRoIjogImJhc2U2NCBlbmNvZGVkIHRva2VuIgoJCX0KCX0KfQo=
```

Provide the encoded JSON config to envbuilder:

```env
ENVBUILDER_DOCKER_CONFIG_BASE64=ewoJImF1dGhzIjogewoJCSJodHRwczovL2luZGV4LmRvY2tlci5pby92MS8iOiB7CgkJCSJhdXRoIjogImJhc2U2NCBlbmNvZGVkIHRva2VuIgoJCX0KCX0KfQo=
```

## Docker-in-Docker

See [here](./docs/docker.md) for instructions on running Docker containers inside
environments built by Envbuilder.
