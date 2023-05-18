PORT=5002
IMAGE=net-monitor:v1
SIGNER="wabbit-networks.io"

export NOTATION_EXPERIMENTAL=1

docker run -d -p $PORT:5000 --name zotregistrytest ghcr.io/project-zot/zot-linux-amd64:latest
skopeo --insecure-policy copy --dest-tls-verify=false --src-tls-verify=false --multi-arch=all --format=oci docker://docker.io/alpine:latest docker://localhost:$PORT/$IMAGE

# validate push
#regctl repo ls localhost:$PORT

# notaryv2 section
notation cert generate-test $SIGNER

# sign
notation sign -k $SIGNER --signature-manifest=artifact localhost:$PORT/$IMAGE

# sigscan
../sigscan repo localhost:$PORT --insecure --output pretty -v trace

# clean up
notation key delete $SIGNER
rm -f ~/Library/Application\ Support/notation/localkeys/$SIGNER.*
rm -rf ~/Library/Application\ Support/notation/truststore/x509/ca/$SIGNER
docker rm -f zotregistrytest
