# Sigscan

Sigscan is a tool to primarily discover and report signed container images within a registry.  Any OCI-compliant registry is supported for Sigstore/cosign signatures as well as registries that support OCI artifacts (currently [ACR](https://azure.microsoft.com/en-us/products/container-registry), [ECR](https://aws.amazon.com/ecr/), [oras-project/registry](https://github.com/oras-project/distribution/pkgs/container/registry), and [Zot](https://zotregistry.io))

For Sigstore/cosign signatures we are following the [Signature spec](https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md) and detecting any optional PEM-encoded x509 certificates.

For OCI Artifacts and NotaryV2 signatures we are following the [Signature Specification](https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md) and detecting any Signature Manifest where artifact type is `application/vnd.cncf.notary.signature`.  From there we are extracting `annotations` that have the `io.cncf.notary.x509chain.thumbprint#S256` metadata.

Sigscan can also be used to scan the filesystem to discover and report on signed JAR as well as EXE files.  Sigscan will extract the signer certificate subjectname as well as the countersigner/timestamp (if available) subjectname.

Sigscan is made available under the Apache 2.0 license, see [LICENSE.txt](LICENSE.txt).

#### Registry Support
| Name | Compatibility | Notes |
| ---- | --------- | ---- |
| ghcr.io | :heavy_check_mark: | |
| docker.io | :heavy_check_mark: | |
| ACR | :heavy_check_mark: | |
| Docker Registry V2 | :heavy_check_mark: | |
| ORAS Project registry v1.0.0-rc.3 | :heavy_check_mark: | |
| Zot v1.4.3 | :heavy_check_mark: | |
| ECR (private) | :heavy_check_mark: | |
| ECR (public) | :heavy_check_mark: | us-east-1 only per AWS CLI [issue](https://github.com/aws/aws-cli/issues/5917) |
| GCR (public) | :heavy_check_mark: | |
| GCR (private) | :x: | |

#### FileType Support
| Type | Compatibility | Notes |
| ---- | ------------- | ----- |
| JAR  | :heavy_check_mark: | |
| EXE | :heavy_check_mark: | |

## Installation

### Homebrew

On macOS and Linux, if you have [Homebrew](https://brew.sh) you can install Sigscan with:

```shell
brew install venafi/sigscan
```

This will also install man pages and shell completion.

### Binaries

Binaries for common platforms and architectures are provided on the [releases](https://github.com/venafi/sigscan/releases/latest).
Man pages are also attached to the release.
You can generate shell completion from Sigscan itself with `sigscan completion`.

### Go Install

If you have [Go](https://go.dev/) installed you can install Sigscan using Go directly.

```shell
go install github.com/venafi/sigscan@latest
```

## Examples

Sigscan can be used to list out details of all the signed container images in the registry:

*Make sure you are authenticated to the registry as needed.*

```shell
$ sigscan repo myregistry --output pretty --username myuser --password supersecretpassword
```

Inspecting an organization's ECR public repositories:
```shell
$ sigscan repo public.ecr.aws --output pretty
```

Inspecting an organization's GHCR repositories:

```shell
$ sigscan repo ghcr.io --output pretty --org myorg --username myuser --password supersecretpassword
```

Export them for further audit:
```shell
$ sigscan repo localhost:5010 --output json --insecure | jq '.registry.signatures[].subjectname'
"CN=dev.venafidemo.com,OU=Solution Architects,O=Venafi\\, Inc.,L=San Jose,ST=CA,C=US"
"CN=dev.venafidemo.com,OU=Solution Architects,O=Venafi\\, Inc.,L=San Jose,ST=CA,C=US"
```

Inspecting the filesystem for signed artifacts
```shell
$ sigscan fs test/tempdir1/ test/tempdir2 --output json | jq
```

*EXE and Jar file types are currently supported*

## Authentication

Sigscan supports username/password as well as token credentials via the CLI arguments, and also supports the Docker credential store.  If no credentials are supplied via the CLI then Sigscan will check the local Docker credential store.

## Limitations

Sigscan will detect certificates/thumbprints in most cases
However, there are some limitations to bear in mind while using Sigscan:

- Sigscan supports HTTP (insecure) as well as HTTPS endpoints
- Sigscan supports Sigstore/cosign certificates however currently only returns the subject name.
- Sigscan supports NotaryV2 signatures however only returns the SHA256 thumbprint of the certificate.  Consumer of this client would be required to validate this thumbprint against a trusted certificate store.
- Sigscan does not verify or validate the signature.

## Usage

The usage documentation for Sigscan is included in the help text.
Invoke a command with `--help` for usage instructions, or see the manual pages.
