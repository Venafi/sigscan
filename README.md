# Sigscan

Sigscan is a tool to primarily discover and report signed container images within a registry.  Any OCI-compliant registry is supported for Sigstore/cosign signatures as well as registries that support OCI artifacts (currently [ACR](https://azure.microsoft.com/en-us/products/container-registry), [ECR](https://aws.amazon.com/ecr/), [oras-project/registry](https://github.com/oras-project/distribution/pkgs/container/registry), and [Zot](https://zotregistry.io))

For Sigstore/cosign signatures we are following the [Signature spec](https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md) and detecting any optional PEM-encoded x509 certificates.

For OCI Artifacts and NotaryV2 signatures we are following the [Signature Specification](https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md) and detecting any Signature Manifest where artifact type is `application/vnd.cncf.notary.signature`.  From there we are extracting `annotations` that have the `io.cncf.notary.x509chain.thumbprint#S256` metadata.

Sigscan can also be used to scan the filesystem to discover and report on signed JAR as well as EXE files.  Sigscan will extract the signer certificate subjectname as well as the countersigner/timestamp (if available) subjectname.

Sigscan is made available under the Apache 2.0 license, see [LICENSE](LICENSE).

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
| GAR | :heavy_check_mark: | Non-compliant Referrers API |

#### FileType Support
| Type | Compatibility | Notes |
| ---- | ------------- | ----- |
| JAR  | :heavy_check_mark: | |
| EXE | :heavy_check_mark: | |

#### SBOM Support (Experimental)
| Type | Compatibility | Notes |
| ---- | ------------- | ----- |
| OWASP [CycloneDX](https://cyclonedx.org/) | :heavy_check_mark: | `application/vnd.cyclonedx` |
| Linux Foundation [SPDX](https://spdx.dev/) | :heavy_check_mark: | `application/spdx+json` |
| OASIS [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.0/sarif-v2.0.html) | :heavy_check_mark: | `application/sarif+json` |

## Installation

### Homebrew

On macOS and Linux, if you have [Homebrew](https://brew.sh) you can install Sigscan with:

```shell
brew install venafi/tap/sigscan
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

*Note: If you are on Windows ANSI Terminal Control support (introduced in Windows 10 console build 16257 and later) is not enabled by default.  This will affect the table view when using the displaying the output table via `--output pretty`.  Run sigscan in a PowerShell console as opposed to a CMD console.  A [workaround](https://github.com/rodaine/table/issues/18) exists by running the following in Admin Mode*:

`Set-ItemProperty HKCU:\Console VirtualTerminalLevel -Type DWORD 1`

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

## What ** is not ** production ready

While parts of `sigscan` are stable, we are continuing to experiment and add new features. The following feature set is not considered stable yet, but we are commiteted to stabilizing it over time!

#### Formats/Specifications

While the [cosign](https://github.com/sigstore/cosign) code for uploading, signing, retrieving, and verifying several artifact types is stable, the format specifications for some of those types may not be considered stable yet.

These include:

* The SBOM specification for storing SBOMs in a container registry

sigscan provides experimental support for cyclonedx SBOM signatures via the cosign artifact signature mediatype `application/vnd.dev.cosign.artifact.sig.v1+json`

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
