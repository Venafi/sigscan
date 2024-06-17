package sigscan

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/rodaine/table"
	o "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sirupsen/logrus"

	"github.com/spf13/cobra"

	"github.com/venafi/sigscan/internal/registry"

	"github.com/venafi/sigscan/cmd/sigscan/options"
	"github.com/venafi/sigscan/internal/output"
	"github.com/venafi/sigscan/internal/signers"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	_ "github.com/sassoftware/relic/v7/signers/pecoff"
	"oras.land/oras-go/v2/content"
	orasreg "oras.land/oras-go/v2/registry"
	oras "oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	stateClean    = "clean"
	stateDirty    = "dirty"
	unknown       = "unknown"
	biVCSDate     = "vcs.time"
	biVCSCommit   = "vcs.revision"
	biVCSModified = "vcs.modified"
)

type Info struct {
	GoVer      string           `json:"goVersion"`       // go version
	GoCompiler string           `json:"goCompiler"`      // go compiler
	Platform   string           `json:"platform"`        // os/arch
	VCSCommit  string           `json:"vcsCommit"`       // commit sha
	VCSDate    string           `json:"vcsDate"`         // commit date in RFC3339 format
	VCSRef     string           `json:"vcsRef"`          // commit sha + dirty if state is not clean
	VCSState   string           `json:"vcsState"`        // clean or dirty
	VCSTag     string           `json:"-"`               // tag is not available from Go
	Debug      *debug.BuildInfo `json:"debug,omitempty"` // build info debugging data
}

type RepoInspectOptions struct {
	Username     string
	Password     string
	AccessToken  string
	Insecure     bool // HTTP vs HTTPS
	Organization string
}

type repositoryOptions struct {
	registry.Remote
	registry.Common
	hostname  string
	namespace string
	//last      string
}

func GetInfo() Info {
	i := Info{
		GoVer:     unknown,
		Platform:  unknown,
		VCSCommit: unknown,
		VCSDate:   unknown,
		VCSRef:    unknown,
		VCSState:  unknown,
		VCSTag:    "",
	}

	i.GoVer = runtime.Version()
	i.GoCompiler = runtime.Compiler
	i.Platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

	if bi, ok := debug.ReadBuildInfo(); ok && bi != nil {
		i.Debug = bi
		date := biSetting(bi, biVCSDate)
		if t, err := time.Parse(time.RFC3339, date); err == nil {
			i.VCSDate = t.UTC().Format(time.RFC3339)
		}
		i.VCSCommit = biSetting(bi, biVCSCommit)
		i.VCSRef = i.VCSCommit
		modified := biSetting(bi, biVCSModified)
		if modified == "true" {
			i.VCSState = stateDirty
			i.VCSRef += "-" + stateDirty
		} else if modified == "false" {
			i.VCSState = stateClean
		}
	}

	return i
}

func biSetting(bi *debug.BuildInfo, key string) string {
	if bi == nil {
		return unknown
	}
	for _, setting := range bi.Settings {
		if setting.Key == key {
			return setting.Value
		}
	}
	return unknown
}

func DefaultRegistryClientOpts(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
		remote.WithUserAgent("cosign/experimental"),
	}
}

const (
	MediaTypeConfig       = "application/vnd.docker.container.image.v1+json"
	MediaTypeManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeForeignLayer = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
)

func parseRepoPath(opts *repositoryOptions, arg string) error {
	path := strings.TrimSuffix(arg, "/")
	if strings.Contains(path, "/") {
		reference, err := orasreg.ParseReference(path)
		if err != nil {
			return err
		}
		if reference.Reference != "" {
			return fmt.Errorf("tags or digests should not be provided")
		}
		opts.hostname = reference.Registry
		opts.namespace = reference.Repository + "/"
	} else {
		opts.hostname = path
	}
	return nil
}

func newRepoInspect(_ context.Context) *cobra.Command {

	var (
		outOpts    *options.Output
		entryCount int = 0
		sigCount   int = 0
	)

	cmd := &cobra.Command{
		Use:     "repo [flags] image",
		Short:   "Inspect container images for signatures (cosign and notaryv2)",
		Long:    "Inspect container images for signatures (cosign and notaryv2)",
		Example: `  sigscan repo myregistry --output pretty --username myuser --password supersecretpassword `,
		PreRunE: func(_ *cobra.Command, args []string) error {
			return options.MustSingleImageArgs(args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			host := args[0]

			user, _ := cmd.Flags().GetString("username")
			pass, _ := cmd.Flags().GetString("password")
			token, _ := cmd.Flags().GetString("token")
			insecure, _ := cmd.Flags().GetBool("insecure")
			org, _ := cmd.Flags().GetString("org")

			var out output.RepoJSONOutput
			var opts repositoryOptions

			out.Registry = host

			if err := parseRepoPath(&opts, host); err != nil {
				return fmt.Errorf("could not parse repository path: %w", err)
			}

			reg, err := oras.NewRegistry(opts.hostname)

			if err != nil {
				return fmt.Errorf(err.Error())
			}
			//reg.RepositoryListPageSize = 100
			//reg.Client = client

			var rem registry.Remote
			var cred auth.Credential

			reg.Client, cred, err = rem.GetAuthClient(host, false)
			if err != nil {
				return fmt.Errorf(err.Error())
			}

			// GHCR can use docker credential helper otherwise credential can be supplied via arguments
			if host == registry.GHCR && user == "" && pass == "" {
				user = cred.Username
				token = cred.Password
			}

			if host == registry.DOCKER {
				token = pass
			}

			if insecure {
				reg.PlainHTTP = true
			}

			if err = reg.Ping(ctx); err != nil {
				return fmt.Errorf("registry ping error: %s", err.Error())
			}

			if outOpts.Mode == options.OutputModePretty {
				c := color.New(color.FgHiMagenta)
				c.Println(host)
			}

			var tbl table.Table

			if outOpts.Mode == options.OutputModePretty || outOpts.Mode == options.OutputModeWide {
				//wide := outOpts.Mode == options.OutputModeWide
				headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
				columnFmt := color.New(color.FgYellow).SprintfFunc()
				tbl = table.New("Path", "Digest", "NotaryV2", "Sigstore/cosign")
				tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

			}

			err = registry.FindRepositories(ctx, org, opts.namespace, user, pass, token, reg, "", func(repos []string) error {
				for _, repo := range repos {
					if outOpts.Mode == options.OutputModePretty {
						log.WithFields(logrus.Fields{
							"repo":      repo,
							"hostname":  opts.hostname,
							"namespace": opts.namespace,
						}).Trace("FindRepositories")
					}
					var err error
					var r *oras.Repository
					var imagePath string

					if opts.namespace != "" {
						imagePath = opts.hostname + "/" + opts.namespace + repo
						log.WithFields(logrus.Fields{
							"image_path": imagePath,
						}).Trace("NewRepositoryNoNamespace")
						r, err = oras.NewRepository(opts.hostname + "/" + opts.namespace + repo)
					} else {
						imagePath = opts.hostname + "/" + repo
						log.WithFields(logrus.Fields{
							"image_path": imagePath,
						}).Trace("NewRepository")
						r, err = oras.NewRepository(fmt.Sprintf("%s/%s", opts.hostname, repo))
					}
					if err != nil {
						return fmt.Errorf("error with repository %s/%s: %s", host, repo, err.Error())
					}
					if insecure {
						r.PlainHTTP = true
					}

					// Set client for auth purposes
					r.Client = reg.Client

					// resolve a manifest by tag
					err = r.Tags(ctx, "", func(tags []string) error {
						for _, tag := range tags {
							entryCount += 1

							descriptor, err := r.Resolve(ctx, tag)
							if err != nil {
								return fmt.Errorf("error resolving tag [%s]: %s", tag, err.Error())
							}

							log.WithFields(logrus.Fields{
								"image_tag":  tag,
								"descriptor": descriptor.MediaType,
							}).Trace("Tags")

							//Sigstore/cosign signature discovery
							regOpts := o.RegistryOptions{}
							ociremoteOpts, err := regOpts.ClientOpts(ctx)
							if err != nil {
								return err
							}

							ref, _ := name.ParseReference(imagePath + ":" + tag)

							log.WithFields(logrus.Fields{
								"ref":       ref.String(),
								"mediatype": descriptor.MediaType,
								"digest":    descriptor.Digest,
							}).Trace("ParseReference")

							err = signers.FetchCosignImageSignatures(ctx, ref, ociremoteOpts, &sigCount, tbl, outOpts, repo, tag, descriptor, &out, log)
							if err != nil {
								// Disregard any errors since we want to find all the signed container images
								log.WithFields(logrus.Fields{
									"ref": ref.String(),
								}).Trace("FetchCosignImageSignatures: " + err.Error())
							}

							// ORAS NotaryV2 signature discovery
							// find its referrers by calling Referrers
							// Workaround for Google Artifact Registry given non-compliance of support for referrer api.
							// Should return 404 but returns 302 and redirects to html page
							// https://github.com/opencontainers/distribution-spec/blob/v1.1.0-rc1/spec.md#listing-referrers
							if strings.Contains(opts.hostname, registry.GAR) {
								r.SetReferrersCapability(false)
							}
							if err := r.Referrers(ctx, descriptor, "", func(referrers []ocispec.Descriptor) error {
								// for each page of the results, do the following:
								for _, referrer := range referrers {

									entryCount += 1

									// Look for SBOMs signed by cosign
									err = signers.FetchCosignArtifactSignatures(ctx, ref, ociremoteOpts, &sigCount, tbl, outOpts, imagePath, repo, tag, referrer, &out, log)
									if err != nil {
										// Disregard any errors since we want to find all the signed container images
										log.WithFields(logrus.Fields{
											"ref": ref.String(),
										}).Trace("FetchCosignArtifactSignatures: " + err.Error())
									}

									log.WithFields(logrus.Fields{
										"referrerArtifactType": referrer.ArtifactType,
										"referrerDigest":       referrer.Digest,
										"referencePath":        ref.String(),
										"sigsPath":             "TBD",
									}).Trace("Referrers")

									// for each item in this page, pull the manifest and verify its content
									rc, err := r.Fetch(ctx, referrer)
									if err != nil {
										return fmt.Errorf("error fetching referrer: %s", err.Error())
									}
									defer rc.Close() // don't forget to close
									pulledBlob, err := content.ReadAll(rc, referrer)
									if err != nil {
										return fmt.Errorf("error reading referrer: %s", err.Error())
									}

									/* Notaryv2 signatures may be accessible via Image Manifest
									https://github.com/opencontainers/image-spec/blob/main/specs-go/v1/manifest.go
									*/
									var manifest *ocispec.Manifest = &ocispec.Manifest{}

									err = json.Unmarshal(pulledBlob, manifest)
									if err != nil {
										return fmt.Errorf(err.Error())
									}

									if manifest.Config.MediaType == registry.NotaryV2ArtifactType {

										// Found NotaryV2 signature
										sigCount += 1

										if outOpts.Mode == options.OutputModePretty {
											log.WithFields(logrus.Fields{
												"repo":                      repo + ":" + tag,
												"referrerMediaType":         referrer.MediaType,
												"mediaType":                 manifest.MediaType,
												"artifactType":              manifest.Config.MediaType,
												"notaryV2EnvelopeMediaType": manifest.Layers[0].MediaType,
											}).Trace("ImageManifest")
										}

										if outOpts.Mode == options.OutputModeJSON {
											out.Signatures.Entries = append(out.Signatures.Entries, output.RepoJSONSignature{
												Path:                repo + ":" + tag,
												Digest:              string(descriptor.Digest),
												NotaryV2Thumbprints: manifest.Annotations[registry.NotaryV2AnnotationThumbprint][1 : len(manifest.Annotations[registry.NotaryV2AnnotationThumbprint])-1],
											})
										} else {
											tbl.AddRow(repo+":"+tag, string(descriptor.Digest), "✅", "❌")
										}
									}
								}
								return nil
							}); err != nil {
								if outOpts.Mode == options.OutputModePretty {
									log.WithFields(logrus.Fields{
										"path": repo + ":" + tag,
									}).Debug(err.Error())
								}
							}

						}

						return nil
					})
					if err != nil {
						return fmt.Errorf(err.Error())
					}

				}
				return nil
			})

			if outOpts.Mode == options.OutputModeJSON {
				m, err := json.Marshal(out)
				if err != nil {
					return fmt.Errorf(err.Error())
				}

				fmt.Println(string(m))
			} else if outOpts.Mode == options.OutputModePretty {
				if sigCount > 0 {
					tbl.Print()
				}
				fmt.Printf("Found %d signatures out of %d entries\n", sigCount, entryCount)
			}

			if err != nil {
				return fmt.Errorf("sigscan error: %s", err.Error())
			}

			return nil
		},
	}

	var inspectOpts RepoInspectOptions
	cmd.Flags().StringVarP(&inspectOpts.Username, "username", "u", "", "Username (required if password is set)")
	cmd.Flags().StringVarP(&inspectOpts.Password, "password", "p", "", "Password (required if username is set)")
	cmd.Flags().StringVarP(&inspectOpts.AccessToken, "token", "t", "", "Access Token")
	cmd.Flags().BoolVarP(&inspectOpts.Insecure, "insecure", "i", false, "Insecure (HTTP)")
	cmd.Flags().StringVarP(&inspectOpts.Organization, "org", "c", "", "Organization in case of Docker, Github, etc.")
	cmd.MarkFlagsRequiredTogether("username", "password")
	outOpts = options.RegisterOutputs(cmd)
	cmd.Args = cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs)

	return cmd
}
