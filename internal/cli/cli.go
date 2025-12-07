// Copyright (c) 2025 allddd <me@allddd.onl>
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
	Filter  string `name:"f" usage:"filter expression (requires -j)"`
	Help    bool   `name:"h" usage:"display this help message and exit"`
	Json    bool   `name:"j" usage:"display entries as JSON and exit"`
	Version bool   `name:"V" usage:"display version information and exit"`
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
	for _, provided := range []bool{f.Help, f.Json, f.Version} {
		if provided {
			if count++; count > 1 {
				fmt.Fprintln(os.Stderr, "error(cli): mutually exclusive flags")
				flag.Usage()
				os.Exit(1)
			}
		}
	}
	if !f.Json && f.Filter != "" {
		fmt.Fprintln(os.Stderr, "error(cli): -f requires -j flag")
		flag.Usage()
		os.Exit(1)
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
	// -j
	if f.Json {
		if err := displayJSON(s, f.Filter); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else {
		if err := tui.Display(s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
