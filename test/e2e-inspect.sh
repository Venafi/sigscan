#!/bin/bash

# GHCR.IO
../sigscan repo ghcr.io --output pretty --username zosocanuck --password ACCESS_TOKEN

# DOCKER.IO
../sigscan repo docker.io --output pretty --org venafi --username zosocanuck --password ACCESS_TOKEN

# Google Container Registry GCR and Google Artifact Registry
# us-west1-docker.pkg.dev
# echo "https://us-west1.pkg.dev" | docker-credential-gcr get
# cosign sign --key "pkcs11:slot-id=0;object=vsign-rsa2048-cert?module-path=/Library/Venafi/CodeSigning/lib/venafipkcs11.so&pin-value=1234" us-west1-docker.pkg.dev/jetstack-ivan-wallis/iwallis-test/net-monitor:v1
# notation sign --key "vsign-ztpki-rsa2048" us-west1-docker.pkg.dev/jetstack-ivan-wallis/iwallis-test/net-monitor:v1
# gcr.io
# cosign sign --tlog-upload=fase --key "pkcs11:slot-id=0;object=vsign-rsa2048-cert?module-path=/Library/Venafi/CodeSigning/lib/venafipkcs11.so&pin-value=1234" gcr.io/jetstack-ivan-wallis/net-monitor:v1
# echo "https://gcr.io" | docker-credential-gcr get
../sigscan repo us-west1-docker.pkg.dev --output pretty --token

# ECR Public
# aws ecr-public get-login-password --region us-east-1 --profile iwallis | docker login --username AWS --password-stdin public.ecr.aws
# docker tag localhost:5005/ubuntu:latest public.ecr.aws/v3y9q2u6/net-monitor:v1
# docker push public.ecr.aws/v3y9q2u6/net-monitor:v1
# cosign sign --key "pkcs11:slot-id=0;object=vsign-rsa2048-cert?module-path=/Library/Venafi/CodeSigning/lib/venafipkcs11.so&pin-value=1234" public.ecr.aws/v3y9q2u6/net-monitor:v1
../sigscan repo public.ecr.aws --output pretty

# ECR Private
# aws ecr get-login-password --region us-west-1 | docker login --username AWS --password-stdin 427380916706.dkr.ecr.us-west-1.amazonaws.com
# docker tag hello-world:latest 427380916706.dkr.ecr.us-west-1.amazonaws.com/iwallis-test
# docker push 427380916706.dkr.ecr.us-west-1.amazonaws.com/iwallis-test
# cosign sign --key "pkcs11:slot-id=0;object=vsign-rsa2048-cert?module-path=/Library/Venafi/CodeSigning/lib/venafipkcs11.so&pin-value=1234" 427380916706.dkr.ecr.us-west-1.amazonaws.com/iwallis-test
../sigscan repo 427380916706.dkr.ecr.us-west-1.amazonaws.com --output pretty


# ACR
ACR_NAME=ivanvenafi
REGISTRY=$ACR_NAME.azurecr.io
USERNAME="00000000-0000-0000-0000-000000000000"
PASSWORD=$(az acr login --name $ACR_NAME --expose-token --output tsv --query accessToken)

../sigscan repo $REGISTRY --output pretty --username $USERNAME --password $PASSWORD

# ORAS Project registry v1.0.0-rc.3
# Notary v2 test
REGISTRY=localhost:5005
../sigscan repo $REGISTRY --output pretty --insecure

# docker registryv2
# Sigstore/cosign test
# cosign with CSP keypair environment
# cosign sign --key "pkcs11:slot-id=0;object=vsign-rsa2048?module-path=/Library/Venafi/CodeSigning/lib/venafipkcs11.so&pin-value=1234" localhost:5010/alpine:signed
REGISTRY=localhost:5010
../sigscan repo $REGISTRY --output pretty --insecure
#JSON output test
../sigscan repo $REGISTRY --output json --insecure | jq '.registry.signatures[].subjectname'

# Zot
# Notary v2 test
# skopeo login localhost:5005 -u admin -p not4you --tls-verify=false
# skopeo login localhost:5015 -u admin -p Passw0rd --tls-verify=false
# skopeo --insecure-policy copy --dest-tls-verify=false --src-tls-verify=false --multi-arch=all --format=oci docker://localhost:5005/net-monitor:v1 docker://localhost:5015/net-monitor:v1

# SIGN
# notation login localhost:5015 -u admin -p Passw0rd
# notation sign --key "vsign-ztpki-rsa2048" localhost:5015/net-monitor:v1
REGISTRY=localhost:5015
../sigscan repo $REGISTRY --output pretty --insecure --username admin --password Passw0rd

