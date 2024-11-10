# How to run Envbuilder from behind a proxy

Envbuilder can be used from behind transparent TLS proxies that would normally risk interrupting TLS verification.

A summary of how to configure Envbuilder to run behind an HTTPS proxy is provided in the next session. Thereafter an illustrative example is provided that can be followed to prove the concept from first principles before applying it in production.

## Summary
TODO (sas): set various envs and boom!

## Example
Envbuilder clones a repository that contains your devcontainer.json and optional Dockerfile so that it can build your container. If the clone is done using HTTPS, then TLS verification will have to succeed, or be disabled. If a transparent HTTPS proxy is present, TLS verification will fail unless Envbuilder trusts the certificate used by the transparent proxy. Therefore, we need to tell Envbuilder how to trust your transparent proxy. 

The summary in the previous section shows how to configure Envbuilder using Terraform for Docker and Kubernetes. For this example we'll use docker directly to avoid complexity that might result in confusion. Docker is also more likely than Terraform to already be installed in your testing environment.

Before we introduce an HTTPS proxy, let's prove that envbuilder runs normally. Run the following docker command to obtain a shell within an Envbuilder built environment:
```bash
docker run -it --rm \
    -e ENVBUILDER_INIT_SCRIPT='/bin/sh' \
    -e ENVBUILDER_GIT_URL='https://github.com/coder/envbuilder.git' \
    ghcr.io/coder/envbuilder:latest
```

Notice the log lines:
```
#1: 📦 Cloning https://github.com/coder/envbuilder.git to /workspaces/envbuilder...`
...
#1: 📦 Cloned repository! [711.221369ms]
```

After some time building, a shell will be presented inside the devcontainer environment specified in envbuilder's own repository. Assuming that envbuilder built and ran successfully, go ahead and exit the container:
```bash
exit
```

Let's now break Envbuilder by introducing a transparent TLS intercepting proxy. To do this, we'll use [mitmproxy](https://mitmproxy.org/). Start mitmproxy in a container, by running the following:
```
docker run --rm -d --name mitmproxy -v ./certs:/home/mitmproxy/.mitmproxy -p 8080:8080 -p 127.0.0.1:8081:8081 mitmproxy/mitmproxy mitmweb --web-host 0.0.0.0
```

Confirm that mitmproxy is running:
```bash
docker ps
```
yields:
```
CONTAINER ID   IMAGE                 COMMAND                  CREATED             STATUS             PORTS                                              NAMES
46f655140824   mitmproxy/mitmproxy   "docker-entrypoint.s…"   About an hour ago   Up About an hour   0.0.0.0:8080->8080/tcp, 127.0.0.1:8081->8081/tcp   mitmproxy
```

A new directory called certs should also be present in your current working directory. It will contain a CA certificate called  `mitmproxy-ca-cert.pem`. This will be what we provide to Envbuilder to help it trust our proxy.

Optionally, inspect the certificates served by mitmproxy:
```
openssl s_client -proxy localhost:8080 -servername github.com -connect github.com:443 | head -n 10
```
In the output, notice that we are served a certificate that is ostensibly for github.com. However, its issuer common name is mitmproxy and s_client couldn't verify the certificate:
```
depth=0 CN = github.com
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 CN = github.com
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 CN = github.com
verify return:1
CONNECTED(00000003)
---
Certificate chain
 0 s:CN = github.com
   i:CN = mitmproxy, O = mitmproxy
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Nov  7 15:43:48 2024 GMT; NotAfter: Nov  9 15:43:48 2025 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
```

Let's rerun Envbuilder using the proxy to see how it responds. To do this, we use the same command as before, except that we also set the `https_proxy` environment variable:
```bash
docker run -it --rm \
    -e https_proxy=https://172.17.0.2:8080 \
    -e ENVBUILDER_INIT_SCRIPT='/bin/sh' \
    -e ENVBUILDER_GIT_URL='https://github.com/coder/envbuilder.git' \
    ghcr.io/coder/envbuilder:latest
```
From the logs, notice that certificate verification fails:
```
Failed to clone repository: clone "https://github.com/coder/envbuilder.git": Get "https://github.com/coder/envbuilder.git/info/refs?service=git-upload-pack": proxyconnect tcp: tls: failed to verify certificate: x509: certificate signed by unknown authority
```

To fix this, we need to provide a ca certificate that Envbuilder can use to verify the certificate that mitmproxy serves instead of github's actual certificate. Envbuilder provides a few environment variables to accomplish this. They are all documented in the summary section above. For this example, we have the ca certificate saved in a directory. The easiest way to provide it is therefore to mount it as a volume in the envbuilder container and tell envbuilder to use it. For this, we can use the `SSL_CERT_FILE` environment variable. The command to run Envbuilder is now:
```bash
docker run -it --rm \
    -v $PWD/certs:/certs \
    -e SSL_CERT_FILE=/certs/mitmproxy-ca-cert.pem \
    -e https_proxy=https://172.17.0.2:8080 \
    -e ENVBUILDER_INIT_SCRIPT='/bin/sh' \
    -e ENVBUILDER_SETUP_SCRIPT='printenv' \
    -e ENVBUILDER_GIT_URL='https://github.com/coder/envbuilder.git' \
    ghcr.io/coder/envbuilder:latest
```
