# Custom Certificates

- [`ENVBUILDER_SSL_CERT_FILE`](https://go.dev/src/crypto/x509/root_unix.go#L19): Specifies the path to an SSL certificate.
- [`ENVBUILDER_SSL_CERT_DIR`](https://go.dev/src/crypto/x509/root_unix.go#L25): Identifies which directory to check for SSL certificate files.
- `ENVBUILDER_SSL_CERT_BASE64`: Specifies a base64-encoded SSL certificate that will be added to the global certificate pool on start.
