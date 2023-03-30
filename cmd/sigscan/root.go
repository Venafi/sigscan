// SPDX-License-Identifier: Apache-2.0

package sigscan

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/release-utils/version"
)

func NewRoot(ctx context.Context) *cobra.Command {
	root := &cobra.Command{
		Use:   "sigscan subcommand",
		Short: "Inspect container images and select file types for signatures",
		Long:  `Inspect container images and select file types for signatures and report the signing identities`,
	}

	root.AddCommand(newRepoInspect(ctx))
	root.AddCommand(newFSInspect(ctx))
	root.AddCommand(version.WithFont("starwars"))

	return root
}

func Execute() {
	ctx := signals.SetupSignalHandler()
	if err := NewRoot(ctx).Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
