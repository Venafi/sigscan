PORT=5001
IMAGE="us-west1-docker.pkg.dev/jetstack-ivan-wallis/iwallis-test/net-monitor:v1"
SIGNER="wabbit-networks.io"

docker build -t $IMAGE https://github.com/wabbit-networks/net-monitor.git#main
docker push $IMAGE

# notaryv2 section
notation cert generate-test $SIGNER

# sign
notation sign -k $SIGNER --signature-manifest=image $IMAGE
#notation sign -k $SIGNER --signature-manifest=artifact $IMAGE

# sigscan
../sigscan repo us-west1-docker.pkg.dev --output pretty -v trace

# clean up
notation key delete $SIGNER
rm -f ~/Library/Application\ Support/notation/localkeys/$SIGNER.*
rm -rf ~/Library/Application\ Support/notation/truststore/x509/ca/$SIGNER
