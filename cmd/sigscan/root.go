// SPDX-License-Identifier: Apache-2.0

package sigscan

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

func NewRoot(ctx context.Context) *cobra.Command {
	root := &cobra.Command{
		Use:   "sigscan subcommand",
		Short: "Inspect container images for signatures (cosign or notaryv2) ",
		Long:  `TBD`,
	}

	root.AddCommand(newRepoInspect(ctx))
	root.AddCommand(newFSInspect(ctx))

	return root
}

func Execute() {
	ctx := signals.SetupSignalHandler()
	if err := NewRoot(ctx).Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
