#!/bin/bash

openssl req -new -x509 -nodes -newkey ec:<(openssl ecparam -name secp256r1) -keyout identities/signer1.key -out identities/signer1.crt -days 3650 -subj "/CN=Acme Corp Signer" \
  -addext "subjectAltName=DNS:acmecorp.com,DNS:www.acmecorp.net,IP:10.0.0.1"

COSIGN_PASSWORD=1234 cosign import-key-pair --key identities/signer1.key   

mv import-cosign.key identities/signer1.key
mv import-cosign.pub identities/signer1.pub