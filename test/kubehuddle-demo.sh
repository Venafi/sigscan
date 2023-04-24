#!/bin/zsh

# This script uses the slow() function from Brandon Mitchell available at 
# https://github.com/sudo-bmitch/presentations/blob/main/oci-referrers-2023/demo-script.sh#L23
# to simulate typing the commands

opt_a=0
opt_s=25

while getopts 'ahs:' option; do
  case $option in
    a) opt_a=1;;
    h) opt_h=1;;
    s) opt_s="$OPTARG";;
  esac
done
set +e
shift `expr $OPTIND - 1`

if [ $# -gt 0 -o "$opt_h" = "1" ]; then
  echo "Usage: $0 [opts]"
  echo " -h: this help message"
  echo " -s bps: speed (default $opt_s)"
  exit 1
fi

slow() {
  echo -n "\$ $@" | pv -qL $opt_s
  if [ "$opt_a" = "0" ]; then
    read lf
  else
    echo
  fi
}

SIGNER="wabbit-networks.io"
SOURCE_IMAGE=ghcr.io/zosocanuck/sample-venafi-csp-image:signed
SOURCE_REPO=ghcr.io/zosocanuck/sample-venafi-csp-image
# Set the Cosign experimental flag
export COSIGN_EXPERIMENTAL=1
export COSIGN_PASSWORD=1234 

# Script

## Show sigscan is installed
slow 'sigscan version'
sigscan version

## Create SBOMs
slow 'trivy image -f cyclonedx $SOURCE_IMAGE > ./sample-venafi-csp-image-cyclonedx.json'
trivy image -f cyclonedx $SOURCE_IMAGE > ./sample-venafi-csp-image-cyclonedx.json

slow 'trivy image -f spdx-json $SOURCE_IMAGE > ./sample-venafi-csp-image-spdx.json'
trivy image -f spdx-json $SOURCE_IMAGE > ./sample-venafi-csp-image-spdx.json

slow 'trivy image -f sarif $SOURCE_IMAGE > ./sample-venafi-csp-image.sarif'
trivy image -f sarif $SOURCE_IMAGE > ./sample-venafi-csp-image.sarif

## GHCR.io Example

### Upload SBOMs
slow 'oras attach --artifact-type application/vnd.cyclonedx --annotation "createdby=trivy" $SOURCE_IMAGE ./sample-venafi-csp-image-cyclonedx.json'
oras attach --artifact-type application/vnd.cyclonedx --annotation "createdby=trivy" $SOURCE_IMAGE ./sample-venafi-csp-image-cyclonedx.json

slow 'oras attach --artifact-type application/spdx+json --annotation "createdby=trivy" $SOURCE_IMAGE ./sample-venafi-csp-image-spdx.json'
oras attach --artifact-type application/spdx+json --annotation "createdby=trivy" $SOURCE_IMAGE ./sample-venafi-csp-image-spdx.json

slow 'oras attach --artifact-type application/sarif+json --annotation "createdby=trivy" $SOURCE_IMAGE ./sample-venafi-csp-image.sarif'
oras attach --artifact-type application/sarif+json --annotation "createdby=trivy" $SOURCE_IMAGE ./sample-venafi-csp-image.sarif

### Sign SBOMs
slow 'SOURCE_CYCLONE_DX=`regctl artifact tree --filter-artifact-type application/vnd.cyclonedx $SOURCE_IMAGE --format "{{json .}}" | jq -r '.referrer | .[0].reference.Digest'`
cosign sign --tlog-upload=false --key ./identities/signer1.key --certificate ./identities/signer1.crt --registry-referrers-mode oci-1-1 ${SOURCE_REPO}@${SOURCE_CYCLONE_DX} | echo'
SOURCE_CYCLONE_DX=`regctl artifact tree --filter-artifact-type application/vnd.cyclonedx $SOURCE_IMAGE --format "{{json .}}" | jq -r '.referrer | .[0].reference.Digest'`
cosign sign --tlog-upload=false --key ./identities/signer1.key --certificate ./identities/signer1.crt --registry-referrers-mode oci-1-1 ${SOURCE_REPO}@${SOURCE_CYCLONE_DX} | echo

### Sign SPDX SBOM
slow 'SOURCE_SPDX=`regctl artifact tree --filter-artifact-type application/spdx+json $SOURCE_IMAGE --format "{{json .}}" | jq -r '.referrer | .[0].reference.Digest'`
cosign sign --tlog-upload=false --key ./identities/signer1.key --certificate ./identities/signer1.crt --registry-referrers-mode oci-1-1 ${SOURCE_REPO}@${SOURCE_SPDX} | echo'
SOURCE_SPDX=`regctl artifact tree --filter-artifact-type application/spdx+json $SOURCE_IMAGE --format "{{json .}}" | jq -r '.referrer | .[0].reference.Digest'`
cosign sign --tlog-upload=false --key ./identities/signer1.key --certificate ./identities/signer1.crt --registry-referrers-mode oci-1-1 ${SOURCE_REPO}@${SOURCE_SPDX} | echo

### Sign Sarif SBOM
slow 'SOURCE_SARIF=`regctl artifact tree --filter-artifact-type application/sarif+json $SOURCE_IMAGE --format "{{json .}}" | jq -r '.referrer | .[0].reference.Digest'`
cosign sign --tlog-upload=false --key ./identities/signer1.key --certificate ./identities/signer1.crt --registry-referrers-mode oci-1-1 ${SOURCE_REPO}@${SOURCE_SARIF} | echo'
SOURCE_SARIF=`regctl artifact tree --filter-artifact-type application/sarif+json $SOURCE_IMAGE --format "{{json .}}" | jq -r '.referrer | .[0].reference.Digest'`
cosign sign --tlog-upload=false --key ./identities/signer1.key --certificate ./identities/signer1.crt --registry-referrers-mode oci-1-1 ${SOURCE_REPO}@${SOURCE_SARIF} | echo

### Scan


## OCI 1.1 Zot Registry Example
slow 'docker run -d -p 5002:5000 --name zotregistrytest ghcr.io/project-zot/zot-linux-amd64:latest'
docker run -d -p 5002:5000 --name zotregistrytest ghcr.io/project-zot/zot-linux-amd64:latest

slow 'skopeo --insecure-policy copy --dest-tls-verify=false --src-tls-verify=false --multi-arch=all --format=oci docker://docker.io/alpine:latest docker://localhost:5002/net-monitor:v1'
skopeo --insecure-policy copy --dest-tls-verify=false --src-tls-verify=false --multi-arch=all --format=oci docker://docker.io/alpine:latest docker://localhost:5002/net-monitor:v1

slow 'notation cert generate-test $SIGNER'
notation cert generate-test $SIGNER

slow 'notation sign -k $SIGNER --signature-manifest=artifact localhost:5002/net-monitor:v1'
notation sign -k $SIGNER --signature-manifest=artifact localhost:5002/net-monitor:v1

slow 'COSIGN_PASSWORD=1234 cosign sign --tlog-upload=false --allow-http-registry --allow-insecure-registry --key identities/signer1.key --certificate identities/signer1.crt localhost:5002/net-monitor:v1'
COSIGN_PASSWORD=1234 cosign sign --tlog-upload=false --allow-http-registry --allow-insecure-registry --key identities/signer1.key --certificate identities/signer1.crt localhost:5002/net-monitor:v1

slow 'sigscan repo localhost:5002 --insecure --output pretty'
sigscan repo localhost:5002 --insecure --output pretty



