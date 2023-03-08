// SPDX-License-Identifier: Apache-2.0

package options

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	OutputModePretty = "pretty"
	OutputModeJSON   = "json"
	OutputModeWide   = "wide"
)

var outputModes = []string{
	OutputModePretty,
	OutputModeJSON,
	OutputModeWide,
}

// Output are options for configuring command outputs.
type Output struct {
	// Mode is the output format of the command. Defaults to "pretty".
	Mode string `json:"format"`
}

func RegisterOutputs(cmd *cobra.Command) *Output {
	var opts Output
	cmd.Flags().StringVarP(&opts.Mode, "output", "o", "pretty", `
The output mode controls how Paranoia displays the data, and what data is shown.
Supported modes are *pretty*, *wide*, *json*, and *pem*.

*pretty*: TBD

*wide*: Like pretty mode, this uses a table to format data.
Wide includes additional columns including the SHA256 and other information.

*json*: The JSON output mode emits only JSON to STDOUT.

*pem*: TBD
`)
	return &opts
}

func (o *Output) Validate() error {
	for _, m := range outputModes {
		if o.Mode == m {
			return nil
		}
	}
	return fmt.Errorf("invalid output mode %q, must be one of %s", o.Mode, strings.Join(outputModes, ", "))
}
