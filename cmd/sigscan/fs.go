package sigscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/venafi/sigscan/cmd/sigscan/options"
	"github.com/venafi/sigscan/internal/output"

	_ "github.com/sassoftware/relic/v7/signers/jar"
	_ "github.com/sassoftware/relic/v7/signers/pecoff"

	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/lib/pgptools"
	"github.com/sassoftware/relic/v7/signers"
)

type FSInspectOptions struct {
	Dir string
}

func newFSInspect(_ context.Context) *cobra.Command {

	var (
		outOpts    *options.Output
		entryCount int = 0
		sigCount   int = 0
	)

	cmd := &cobra.Command{
		Use:     "fs [flags] directories",
		Short:   "Inspect select file types for signatures",
		Long:    "Inspect select file types for signatures",
		Example: `  sigscan fs test/tempdir1/ test/tempdir2 --output json | jq `,
		PreRunE: func(_ *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			dirs := cmd.Flags().Args()

			var out output.FSJSONOutput
			out.FileSystem = strings.Join(dirs, ",")

			if outOpts.Mode == options.OutputModePretty {
				c := color.New(color.FgHiMagenta)
				c.Println(out.FileSystem)
			}

			var tbl table.Table

			if outOpts.Mode == options.OutputModePretty || outOpts.Mode == options.OutputModeWide {
				//wide := outOpts.Mode == options.OutputModeWide
				headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
				columnFmt := color.New(color.FgYellow).SprintfFunc()
				tbl = table.New("Path", "Digest", "Signer", "CounterSigner")
				tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

			}

			for _, dir := range dirs {
				//out.FileSystem = dir
				_, err := os.Stat(dir)
				if os.IsNotExist(err) {
					return fmt.Errorf("file/directory: %s doesn't exist", dir)
				}

				fsys := os.DirFS(dir)
				err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, e error) error {
					if d.IsDir() || !d.Type().IsRegular() {
						return nil
					}
					entryCount += 1
					f, err := fsys.Open(p)
					if err != nil {
						return err
					}
					defer f.Close()
					opts := signers.VerifyOpts{
						NoChain:   true,
						NoDigests: true,
					}
					fos := f.(*os.File)
					fileType, compression := magic.DetectCompressed(fos)
					opts.FileName = dir
					opts.Compression = compression
					if _, err := fos.Seek(0, 0); err != nil {
						return err
					}
					mod := signers.ByMagic(fileType)
					if mod == nil {
						mod = signers.ByFileName(dir)
					}
					if mod == nil {
						return errors.New("unknown filetype")
					}
					var sigs []*signers.Signature
					if mod.VerifyStream != nil {
						r, err2 := magic.Decompress(f, opts.Compression)
						if err2 != nil {
							return err
						}
						sigs, err = mod.VerifyStream(r, opts)
					} else {
						if opts.Compression != magic.CompressedNone {
							return errors.New("cannot verify compressed file")
						}
						sigs, err = mod.Verify(fos, opts)
					}
					if err != nil {
						if _, ok := err.(pgptools.ErrNoKey); ok {
							return fmt.Errorf("%w; use --cert to specify known keys", err)
						}
						return err
					}

					log.WithFields(logrus.Fields{
						"path":                  p,
						"magic.FileType":        fileType,
						"magic.CompressionType": compression,
						"#sigs":                 len(sigs),
					}).Trace("ScanDirectories")

					for _, sig := range sigs {
						sigCount += 1
						hasher := sha256.New()
						if _, err := io.Copy(hasher, fos); err != nil {
							return err
						}

						if outOpts.Mode == options.OutputModeJSON {
							if sig.X509Signature != nil {
								if sig.X509Signature.CounterSignature != nil {
									out.Signatures.Entries = append(out.Signatures.Entries, output.FSJSONSignature{
										Path:                 p,
										Digest:               hex.EncodeToString(hasher.Sum(nil)),
										CertificateSubject:   sig.X509Signature.Certificate.Subject.String(),
										CounterSignerSubject: sig.X509Signature.CounterSignature.Certificate.Subject.String(),
									})
								} else {
									out.Signatures.Entries = append(out.Signatures.Entries, output.FSJSONSignature{
										Path:                 p,
										Digest:               hex.EncodeToString(hasher.Sum(nil)),
										CertificateSubject:   sig.X509Signature.Certificate.Subject.String(),
										CounterSignerSubject: "",
									})
								}

							}
						} else {
							if sig.X509Signature != nil {
								if sig.X509Signature.CounterSignature != nil {
									tbl.AddRow(p, hex.EncodeToString(hasher.Sum(nil)), sig.X509Signature.Certificate.Subject.String(), sig.X509Signature.CounterSignature.Certificate.Subject.String())
								} else {
									tbl.AddRow(p, hex.EncodeToString(hasher.Sum(nil)), sig.X509Signature.Certificate.Subject.String(), "N/A")
								}
							}
						}
					}

					return nil
				})
				if err != nil {
					return err
				}

			}

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

			return nil
		},
	}

	//var inspectOpts FSInspectOptions
	//cmd.Flags().StringVarP(&inspectOpts.Dir, "dir", "d", "", "walks the provided directories attempting to find signed artifacts")
	outOpts = options.RegisterOutputs(cmd)
	cmd.Args = cobra.MatchAll(cobra.MinimumNArgs(1), cobra.OnlyValidArgs)

	return cmd
}
