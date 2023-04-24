package registry

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/docker/hub-tool/pkg/hub"
	"github.com/google/go-github/v49/github"
	"github.com/venafi/sigscan/internal/credential"
	"github.com/venafi/sigscan/internal/crypto"
	"github.com/venafi/sigscan/internal/trace"
	"golang.org/x/oauth2"
	oremote "oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	GHCR       = "ghcr.io"
	DOCKER     = "registry-1.docker.io"
	GCR        = "gcr.io"
	GAR        = "docker.pkg.dev"
	ECR_PUBLIC = "public.ecr.aws"
	AWS_REGION = "us-east-1"
)

const (
	NotaryV2ArtifactType         = "application/vnd.cncf.notary.signature"
	NotaryV2AnnotationThumbprint = "io.cncf.notary.x509chain.thumbprint#S256"
	ArtifactManifestMediaType    = "application/vnd.oci.artifact.manifest.v1+json"
	ImageManifestMediaType       = "application/vnd.oci.image.manifest.v1+json"
	CosignSigArtifactType        = "application/vnd.dev.cosign.artifact.sig.v1+json"
	CosignSBOMArtifactType       = "application/vnd.dev.cosign.artifact.sbom.v1+json"
)

// Remote options struct.
type Remote struct {
	CACertFilePath    string
	PlainHTTP         bool
	Insecure          bool
	Configs           []string
	Username          string
	PasswordFromStdin bool
	Password          string

	//resolveFlag        []string
	resolveDialContext func(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error)
}

type Common struct {
	Debug   bool
	Verbose bool
}

func NewRegistry(host string) (reg *Remote) {
	return &Remote{}
}

// tlsConfig assembles the tls config.
func (opts *Remote) tlsConfig() (*tls.Config, error) {
	config := &tls.Config{
		InsecureSkipVerify: opts.Insecure,
	}
	if opts.CACertFilePath != "" {
		var err error
		config.RootCAs, err = crypto.LoadCertPool(opts.CACertFilePath)
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}

// Credential returns a credential based on the remote options.
func (opts *Remote) Credential() auth.Credential {
	return credential.Credential(opts.Username, opts.Password)
}

func (opts *Remote) GetAuthClient(registry string, debug bool) (client *auth.Client, cred auth.Credential, err error) {

	config, err := opts.tlsConfig()
	if err != nil {
		return nil, cred, err
	}

	resolveDialContext := opts.resolveDialContext
	if resolveDialContext == nil {
		resolveDialContext = func(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
			return dialer.DialContext
		}
	}
	client = &auth.Client{
		Client: &http.Client{
			// default value are derived from http.DefaultTransport
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: resolveDialContext(&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}),
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig:       config,
			},
		},
		Cache: auth.NewCache(),
	}

	client.SetUserAgent("sigscan")

	if debug {
		client.Client.Transport = trace.NewTransport(client.Client.Transport)
	}

	cred = opts.Credential()
	if cred != auth.EmptyCredential {
		client.Credential = func(ctx context.Context, s string) (auth.Credential, error) {
			return cred, nil
		}
	} else {
		store, err := credential.NewStore(opts.Configs...)
		if err != nil {
			return nil, cred, err
		}
		// For a user case with a registry from 'docker.io', the hostname is "registry-1.docker.io"
		// According to the the behavior of Docker CLI,
		// credential under key "https://index.docker.io/v1/" should be provided
		if registry == "docker.io" {
			client.Credential = func(ctx context.Context, hostname string) (auth.Credential, error) {
				if hostname == "registry-1.docker.io" {
					hostname = "https://index.docker.io/v1/"
				}
				return store.Credential(ctx, hostname)
			}
		} else if registry == GHCR {
			client.Credential = store.Credential
			cred, err = store.Credential(context.TODO(), GHCR)
			return client, cred, err
		} else {
			client.Credential = store.Credential
		}
	}
	return
}

func FindRepositories(ctx context.Context, org string, namespace string, username string, password string, token string, regclient *oremote.Registry, last string, fn func(repos []string) error) error {
	if regclient.Reference.Host() == GHCR {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		tc := oauth2.NewClient(ctx, ts)
		c := github.NewClient(tc)
		//v := "private"
		pt := "container"
		//opts := &github.RepositoryListOptions{Visibility: "private", Type: "private"}
		//pkgOpts := &github.PackageListOptions{Visibility: &v, PackageType: &pt}
		pkgOpts := &github.PackageListOptions{PackageType: &pt}
		//myrepos, _, err := c.Repositories.List(context.Background(), "zosocanuck", opts)

		var packages []*github.Package
		var err error

		if org != "" {
			packages, _, err = c.Organizations.ListPackages(context.Background(), org, pkgOpts)
			if err != nil {
				return fmt.Errorf(err.Error())
			}

		} else {
			packages, _, err = c.Users.ListPackages(context.Background(), "", pkgOpts)
			if err != nil {
				return fmt.Errorf(err.Error())
			}
		}

		if err != nil {
			return fmt.Errorf(err.Error())
		}

		var repos []string
		for _, r := range packages {
			repos = append(repos, string(*r.GetOwner().Login)+"/"+string(r.GetName()))
			//fmt.Printf("%v", r)
			//info := string(*r.GetOwner().Login)
			//println(info)
		}

		return fn(repos)
	} else if regclient.Reference.Host() == DOCKER {
		hubClient, err := hub.NewClient(
			hub.WithHubAccount(username),
			hub.WithHubToken(token),
		)
		if err != nil {
			return fmt.Errorf(err.Error())
		}
		var repos []string

		var account string = username

		if org != "" {
			account = org
		}

		rep, _, err := hubClient.GetRepositories(account)
		if err != nil {
			return fmt.Errorf(err.Error())
		}

		for _, r := range rep {
			repos = append(repos, string(r.Name))
		}

		return fn(repos)

	} else if strings.Contains(regclient.Reference.Host(), ECR_PUBLIC) {
		var repos []string

		// Using the SDK's default configuration, loading additional config
		// and credentials values from the environment variables, shared
		// credentials, and shared configuration files

		// Per https://github.com/aws/aws-cli/issues/5917, ECR-public actions are only supported in us-east-1
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(AWS_REGION))
		if err != nil {
			return fmt.Errorf(err.Error())
		}

		svc := ecrpublic.NewFromConfig(cfg)
		rep, err := svc.DescribeRepositories(context.Background(), &ecrpublic.DescribeRepositoriesInput{})
		if err != nil {
			return fmt.Errorf(err.Error())
		}

		for _, r := range rep.Repositories {
			repos = append(repos, strings.TrimPrefix(*r.RepositoryUri, ECR_PUBLIC+"/"))
		}

		return fn(repos)

	} else {

		if namespace != "" {
			var repos []string
			err := regclient.Repositories(ctx, last, func(repoList []string) error {
				for _, r := range repoList {
					if subRepo, found := strings.CutPrefix(r, namespace); found {
						repos = append(repos, subRepo)
					}
				}
				return nil

			})
			if err != nil {
				return fmt.Errorf((err.Error()))
			}

			return fn(repos)
		} else {
			return regclient.Repositories(ctx, last, fn)
		}
	}
}
