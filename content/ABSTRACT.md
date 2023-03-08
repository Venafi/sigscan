# Abstract

Software supply chains continue to be put in the spotlight.  Kubernetes workloads have been increasing exponentially and the trustworthiness of these workloads is becoming even more important.

There are risks to running untrusted container images as well as having little visibility on how container images were built. Current container image signing tools, such as Sigstore cosign have limited enterprise key management support, and there are no ways to prevent developers from generating local software or even leverage unapproved keys from external key storage providers (e.g. AWS KMS).

Sigscan was developed to address the need from the InfoSec teams to have visibility over the identities used to sign container images and artifacts that are stored in OCI registries.  In particular sigscan identifies any image tags that were signed using Sigstore/cosign or NotaryV2, and provides a summary report of the associated code signing certificate identities.