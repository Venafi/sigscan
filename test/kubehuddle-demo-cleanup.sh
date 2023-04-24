#!/bin/zsh

SIGNER="wabbit-networks.io"

docker rm -f zotregistrytest
notation key delete $SIGNER
rm -f ~/Library/Application\ Support/notation/localkeys/$SIGNER.*
rm -rf ~/Library/Application\ Support/notation/truststore/x509/ca/$SIGNER

rm ./sample-venafi-csp-image-cyclonedx.json
rm ./sample-venafi-csp-image-spdx.json
rm ./sample-venafi-csp-image.sarif