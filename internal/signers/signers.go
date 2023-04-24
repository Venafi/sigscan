package signers

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rodaine/table"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sirupsen/logrus"
	"github.com/venafi/sigscan/cmd/sigscan/options"
	"github.com/venafi/sigscan/internal/output"
	"github.com/venafi/sigscan/internal/registry"
)

func FetchCosignImageSignatures(ctx context.Context, ref name.Reference, ociremoteOpts []ociremote.Option, sigCount *int, tbl table.Table, outOpts *options.Output, repo string, tag string, descriptor ocispec.Descriptor, out *output.RepoJSONOutput, log *logrus.Logger) error {

	sigs, err := cosign.FetchSignaturesForReference(ctx, ref, ociremoteOpts...)
	if err != nil {
		return err
	}

	for _, sig := range sigs {

		*sigCount += 1

		log.WithFields(logrus.Fields{
			"base64sig": sig.Base64Signature,
		}).Trace("Cosign")

		if outOpts.Mode == options.OutputModeJSON {
			if sig.Cert != nil {
				out.Signatures.Entries = append(out.Signatures.Entries, output.RepoJSONSignature{
					Path:               repo + ":" + tag,
					Digest:             string(descriptor.Digest),
					CertificateSubject: sig.Cert.Subject.String(),
				})
			} else {
				out.Signatures.Entries = append(out.Signatures.Entries, output.RepoJSONSignature{
					Path:               repo + ":" + tag,
					Digest:             string(descriptor.Digest),
					CertificateSubject: "Unknown KeyPair",
				})
			}
		} else {
			tbl.AddRow(repo+":"+tag, string(descriptor.Digest), "❌", "✅")
		}
	}

	return nil
}

func FetchCosignArtifactSignatures(ctx context.Context, ref name.Reference, ociremoteOpts []ociremote.Option, sigCount *int, tbl table.Table, outOpts *options.Output, imagePath string, repo string, tag string, referrer ocispec.Descriptor, out *output.RepoJSONOutput, log *logrus.Logger) error {

	signedImgRef, err := name.ParseReference(imagePath + "@" + string(referrer.Digest))
	if err != nil {
		log.WithFields(logrus.Fields{
			"signedImgRef": signedImgRef.String(),
		}).Trace("ParseReferenceSignedImgRef: " + err.Error())
	}
	digest, err := ociremote.ResolveDigest(signedImgRef, ociremoteOpts...)
	if err != nil {
		log.WithFields(logrus.Fields{
			"digest": digest.String(),
		}).Trace("ResolveDigest: " + err.Error())
	}
	index, err := ociremote.Referrers(digest, registry.CosignSigArtifactType, ociremoteOpts...)
	if err != nil {
		log.WithFields(logrus.Fields{
			"digest": digest.String(),
		}).Trace("CosignReferrers: " + err.Error())
		return err
	}
	results := index.Manifests
	numResults := len(results)
	if numResults == 0 {
		log.WithFields(logrus.Fields{
			"error": fmt.Sprintf("unable to locate reference with artifactType %s", registry.CosignSigArtifactType),
		}).Trace("NoManifests")
	} else if numResults > 1 {
		// TODO: if there is more than 1 result.. what does that even mean?
		log.WithFields(logrus.Fields{
			"error": fmt.Sprintf("there were a total of %d references with artifactType %s\n", numResults, registry.CosignSigArtifactType),
		}).Trace("CosignArtifactError")
	}
	// TODO: do this smarter using "created" annotations
	lastResult := results[numResults-1]
	st, err := name.ParseReference(fmt.Sprintf("%s@%s", digest.Repository, lastResult.Digest.String()))
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Trace("CosignParseReferenceForArtifact")
	}

	sigs, err := ociremote.Signatures(st, ociremoteOpts...)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Trace("CosignSignaturesNotFound")
	}

	sl, err := sigs.Get()
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Trace("CosignSignatureError")
	}
	log.WithFields(logrus.Fields{
		"#sigs": len(sl),
	}).Trace("CosignSignaturesFound")

	for _, sig := range sl {
		sigB64, err := sig.Base64Signature()
		if err != nil {
			log.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Trace("CosignSignatureError")
		}

		*sigCount += 1

		log.WithFields(logrus.Fields{
			"sig": sigB64,
		}).Trace("CosignArtifact")

		cert, err := sig.Cert()
		if err != nil {
			return err
		}

		if outOpts.Mode == options.OutputModeJSON {
			if cert != nil {
				out.Signatures.Entries = append(out.Signatures.Entries, output.RepoJSONSignature{
					Path:               repo + ":" + tag + "(" + referrer.ArtifactType + ")",
					Digest:             string(referrer.Digest),
					CertificateSubject: cert.Subject.String(),
				})
			} else {
				out.Signatures.Entries = append(out.Signatures.Entries, output.RepoJSONSignature{
					Path:               repo + ":" + tag + "(" + referrer.ArtifactType + ")",
					Digest:             string(referrer.Digest),
					CertificateSubject: "Unknown KeyPair",
				})
			}
		} else {
			tbl.AddRow(repo+":"+tag+"("+referrer.ArtifactType+")", string(referrer.Digest), "❌", "✅")
		}
	}

	return nil
}
