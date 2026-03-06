# Development

Building envbuilder currently **requires** a Linux system.

On macOS or Windows systems, we recommend using a VM or the provided
`.devcontainer` for development.

## Requirements

- Go (see the version in `go.mod`)
- `make`
- Docker daemon (for running tests)

## Makefile targets

- `build`: Builds and tags `envbuilder:latest` for your current architecture.
- `develop`: Runs `envbuilder:latest` against a sample Git repository.
- `test`: Runs tests.
- `test-registry`: Stands up a local registry for caching images used in tests.
- `docs/env-variables.md`: Updates the environment variables documentation.

## Dependency management

Envbuilder has several forked and interrelated dependencies that require care
when upgrading. This section documents known constraints and pitfalls.

### Kaniko

Envbuilder uses a [fork of Kaniko](https://github.com/coder/kaniko) for
container image building. The replace directive in `go.mod` points to this fork:

```
replace github.com/GoogleContainerTools/kaniko => github.com/coder/kaniko <version>
```

The Kaniko fork pins its own versions of `docker/docker`,
`containerd/containerd`, and related packages. When upgrading deps, be aware
that the versions resolved by Go's MVS (minimum version selection) may be higher
than what the Kaniko fork expects if other dependencies (like `coder/coder/v2`)
require newer versions.

### Tailscale

Envbuilder uses a [Coder fork of Tailscale](https://github.com/coder/tailscale)
via a replace directive:

```
replace tailscale.com => github.com/coder/tailscale <version>
```

The `coder/coder/v2` module depends on symbols that only exist in this fork
(e.g. `netns.SetCoderSoftIsolation`, `tsaddr.CoderServiceIPv6`). When upgrading
`coder/coder/v2`, you **must** also update the Tailscale replace to match the
version used in `coder/coder/v2`'s own `go.mod`. You can find it with:

```bash
grep 'replace tailscale.com' /path/to/coder/coder/go.mod
```

### vishvananda/netlink and tailscale/netlink

`tailscale/netlink` is a fork of `vishvananda/netlink` from 2021. Starting from
`vishvananda/netlink` v1.3.0, the `XfrmAddress.ToIPNet` method gained an
additional `family uint16` parameter, which breaks `tailscale/netlink`.

If a transitive dependency (e.g. `containerd/containerd/v2`) pulls in
`vishvananda/netlink` >= v1.3.0, you will see build errors like:

```
not enough arguments in call to msg.Sel.Daddr.ToIPNet
    have (uint8)
    want (uint8, uint16)
```

The fix is to add `exclude` directives in `go.mod` for the incompatible
versions, forcing Go to select v1.2.x:

```
exclude (
    github.com/vishvananda/netlink v1.3.0
    github.com/vishvananda/netlink v1.3.1-0.20250303224720-0e7078ed04c8
)
```

You may need to add additional exclude directives if new versions are released.

### moby/go-archive

`docker/docker` (the `+incompatible` module) imports `github.com/moby/go-archive`
and expects certain symbols (`archive.Uncompressed`, `archive.Compression`) at the
package root. In `moby/go-archive` v0.2.0, these were moved to a `compression`
subpackage and the top-level aliases were removed.

If you see errors like:

```
undefined: archive.Uncompressed
undefined: archive.Compression
```

Pin `moby/go-archive` to v0.1.0 in `go.mod`:

```bash
go mod edit -require 'github.com/moby/go-archive@v0.1.0'
go mod tidy
```

### General upgrade workflow

When upgrading `coder/coder/v2` or other major dependencies:

1. Update the dependency version in `go.mod`.
2. Compare replace directives (especially `tailscale.com`) against the
   upstream module's `go.mod` and update to match.
3. Run `go mod tidy`.
4. Run `go build ./...` and check for compilation errors.
5. If you see errors from transitive dependencies, check whether version
   conflicts can be resolved with `exclude` directives or by pinning
   specific versions with `go mod edit -require`.
6. Run `make test` to verify everything works end-to-end.
