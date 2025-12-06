package cli

import (
	"flag"
	"fmt"
	"os"
	"reflect"
	"strconv"

	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
	"gitlab.com/allddd/opnsense-filterlog/internal/tui"
)

const defaultLogPath = "/var/log/filter/latest.log"
const usageText = `terminal-based viewer for OPNsense firewall logs

Usage:
  opnsense-filterlog [flag]... [path]

Arguments:
  path	filter log file to analyze, defaults to 'latest.log' if omitted

Flags:
`

type flags struct {
	Help    bool `name:"h" usage:"display this help message and exit"`
	Version bool `name:"V" usage:"display version information and exit"`
}

// flagsDefine defines all flags set in the struct
func (f *flags) flagsDefine() {
	sv := reflect.ValueOf(f).Elem()
	st := sv.Type()
	for i := 0; i < st.NumField(); i++ {
		ft := st.Field(i)
		fv := sv.Field(i)
		name := ft.Tag.Get("name")
		usage := ft.Tag.Get("usage")
		value := ft.Tag.Get("value")
		switch fv.Kind() {
		case reflect.Bool:
			valueBool, _ := strconv.ParseBool(value)
			flag.BoolVar(fv.Addr().Interface().(*bool), name, valueBool, usage)
		case reflect.String:
			flag.StringVar(fv.Addr().Interface().(*string), name, value, usage)
		}
	}
}

func Execute(v string) {
	var f flags
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usageText)
		flag.PrintDefaults()
	}
	f.flagsDefine()
	flag.Parse()
	// check mutually exclusive flags
	count := 0
	for _, provided := range []bool{f.Help, f.Version} {
		if provided {
			if count++; count > 1 {
				fmt.Fprintln(os.Stderr, "error: mutually exclusive flags")
				flag.Usage()
				os.Exit(1)
			}
		}
	}
	// -h
	if f.Help {
		flag.Usage()
		os.Exit(0)
	}
	// -V
	if f.Version {
		fmt.Fprintln(os.Stdout, v)
		os.Exit(0)
	}
	// args
	args := flag.Args()
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
}
