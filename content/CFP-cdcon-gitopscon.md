#### Abstract Title
* Understanding who's signed your container images
* Gaining better visibility into who signed your container images
* Who Signed This Container Image?
* Gain better visibility into container image signatures

#### Abstract

Software supply chains continue to be put in the spotlight.  Kubernetes workloads have been increasing exponentially and the trustworthiness of these workloads is becoming even more important.

There are risks to running untrusted container images as well as having little visibility on how container images were built. Current container image signing tools, such as Sigstore cosign have limited enterprise key management support, and there are no ways to prevent developers from generating local software or even leverage unapproved keys from external key storage providers (e.g. AWS KMS).

Sigscan was developed to address the need from the InfoSec teams to have visibility over the identities used to sign container images and artifacts that are stored in OCI registries.  In particular sigscan identifies any image tags that were signed using Sigstore/cosign or NotaryV2, and provides a summary report of the associated code signing certificate identities.

#### Audience

This talk is aimed at all stakeholders that want to have visibility into what container images as well as software artifacts are signed.  At the end of the session, participants will walk away with techniques for discovering the identities around container images and software artifacts.

#### Benefits to the Ecosystem

As organizations start to develop their strategy around software supply chains, understanding how to ensure the observability of container image signatures and artifacts will be crucial.

This presentation is intended for InfoSec practitioners to help gain this visibility over container images and artifact signatures as part of an enterprise-wide strategy to enforce
which container images can be run in a Kubernetes environment.

This presentation will focus on the current state of how container image signatures are managed, where to look for them, and use these findings to remediate any non-compliant images.

At the end of the session, participants will walk away with a technique on how to discover container image signatures and map the signing identities to enterprise policy.

#### Bio

Ivan Walllis is primarily responsible for working closely with customers worldwide as they adopt their code signing strategy as part of their cloud-native security strategy.

He is currently Senior Architect, Cloud Native
Solutions at Venafi.

For more than 20+ years, Ivan has been a trusted advisor to some of the largest enterprise customers with PKI, code signing, SSH, TLS, and cryptographic systems, and is passionate about helping security teams acquire and implement machine identity management solutions. 

Ivan is also an active contributor to the open-source community, especially around the Notary v2 and Sigstore projects.


