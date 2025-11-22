package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
	"gitlab.com/allddd/opnsense-filterlog/internal/tui"
)

const defaultLogPath = "/var/log/filter/latest.log"
const helpTemplate = `{{.Short}}

Usage:
  opnsense-filterlog [flag]... [arg]

Arguments:
  path		  filter log file to analyze, defaults to 'latest.log' if omitted

Flags:
{{.LocalFlags.FlagUsages}}
`

var version string
var rootCmd = &cobra.Command{
	Use:   "opnsense-filterlog",
	Short: "OPNsense filter log viewer",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cli *cobra.Command, args []string) {

		if v, err := cli.Flags().GetBool("version"); err != nil {
			fmt.Fprintln(os.Stderr, "error: failed to parse 'version' flag: ", err)
			os.Exit(1)
		} else if v {
			fmt.Fprintln(os.Stdout, version)
			os.Exit(0)
		}

		if len(args) == 0 {
			args = []string{defaultLogPath}
		}

		s, err := stream.NewStream(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		if err := tui.Display(s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

	},
}

func Execute(v string) {
	version = v
	rootCmd.Flags().BoolP("version", "V", false, "display version")
	rootCmd.SetHelpTemplate(helpTemplate)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
