PORT=5001
IMAGE=net-monitor:v1
SIGNER="wabbit-networks.io"

docker run -d -p $PORT:5000 --name orasregistrytest ghcr.io/oras-project/registry:v1.0.0-rc.4
docker build -t localhost:$PORT/namespace-test/$IMAGE https://github.com/wabbit-networks/net-monitor.git#main
docker push localhost:$PORT/namespace-test/$IMAGE

# notaryv2 section
notation cert generate-test $SIGNER

# sign
notation sign -k $SIGNER --signature-manifest=image localhost:$PORT/namespace-test/$IMAGE
notation sign -k $SIGNER --signature-manifest=artifact localhost:$PORT/namespace-test/$IMAGE

# sigscan
../sigscan repo localhost:$PORT --insecure --output pretty -v trace
../sigscan repo localhost:$PORT --insecure --output json | jq

# clean up
notation key delete $SIGNER
rm -f ~/Library/Application\ Support/notation/localkeys/$SIGNER.*
rm -rf ~/Library/Application\ Support/notation/truststore/x509/ca/$SIGNER
docker rm -f orasregistrytest
