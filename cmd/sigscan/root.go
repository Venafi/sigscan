// SPDX-License-Identifier: Apache-2.0

package sigscan

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/release-utils/version"
)

var (
	log *logrus.Logger
)

var rootOpts struct {
	verbosity string
	logopts   []string
}

func NewRoot(ctx context.Context) *cobra.Command {
	root := &cobra.Command{
		Use:           "sigscan subcommand",
		Short:         "Inspect container images and select file types for signatures",
		Long:          `Inspect container images and select file types for signatures and report the signing identities`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	log = &logrus.Logger{
		Out:       os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Hooks:     make(logrus.LevelHooks),
		Level:     logrus.WarnLevel,
	}

	root.PersistentFlags().StringVarP(&rootOpts.verbosity, "verbosity", "v", logrus.WarnLevel.String(), "Log level (debug, info, warn, error, fatal, panic)")
	root.PersistentFlags().StringArrayVar(&rootOpts.logopts, "logopt", []string{}, "Log options")
	root.RegisterFlagCompletionFunc("verbosity", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"debug", "info", "warn", "error", "fatal", "panic"}, cobra.ShellCompDirectiveNoFileComp
	})
	root.PersistentPreRunE = rootPreRun

	root.AddCommand(newRepoInspect(ctx))
	root.AddCommand(newFSInspect(ctx))
	root.AddCommand(version.WithFont("starwars"))

	return root
}

func rootPreRun(cmd *cobra.Command, args []string) error {
	lvl, err := logrus.ParseLevel(rootOpts.verbosity)
	if err != nil {
		return err
	}
	log.SetLevel(lvl)
	for _, opt := range rootOpts.logopts {
		if opt == "json" {
			log.Formatter = new(logrus.JSONFormatter)
		}
	}
	return nil
}

func Execute() {
	ctx := signals.SetupSignalHandler()
	if err := NewRoot(ctx).Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
