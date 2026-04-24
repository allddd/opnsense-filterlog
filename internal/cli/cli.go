// Copyright (c) 2025, 2026 allddd <me@allddd.onl>
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
	"io"
	"os"
	"reflect"
	"strconv"

	"gitlab.com/allddd/opnsense-filterlog/internal/meta"
	"gitlab.com/allddd/opnsense-filterlog/internal/stream"
	"gitlab.com/allddd/opnsense-filterlog/internal/tui"
)

const defaultLogPath = "/var/log/filter/latest.log"
const usageText = `command-line tool and terminal-based viewer for OPNsense firewall logs

Usage:
  %s [flag]... [file]...

Arguments:
  file	filter log file(s) to analyze, defaults to 'latest.log' if omitted

Flags:
`

type flags struct {
	Filter  string `name:"f" usage:"filter expression (requires -j)"`
	Help    bool   `name:"h" usage:"display usage information and exit"`
	Json    bool   `name:"j" usage:"display entries as JSON and exit"`
	Version bool   `name:"V" usage:"display version information and exit"`
}

// flagsDefine defines all flags set in the struct.
func (f *flags) flagsDefine() {
	v := reflect.ValueOf(f).Elem()
	t := v.Type()
	for i := range t.NumField() {
		ft := t.Field(i)
		fv := v.Field(i)
		name := ft.Tag.Get("name")
		usage := ft.Tag.Get("usage")
		value := ft.Tag.Get("value")
		switch fv.Kind() { //nolint:exhaustive
		case reflect.Bool:
			valueBool, _ := strconv.ParseBool(value)
			flag.BoolVar(fv.Addr().Interface().(*bool), name, valueBool, usage) //nolint:forcetypeassert
		case reflect.String:
			flag.StringVar(fv.Addr().Interface().(*string), name, value, usage) //nolint:forcetypeassert
		}
	}
}

func readStdin() (string, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return "", fmt.Errorf("error(cli): could not stat stdin: %w", err)
	}
	if fi.Mode()&os.ModeCharDevice != 0 {
		return "", nil
	}
	f, err := os.CreateTemp("", meta.Name+"_*")
	if err != nil {
		return "", fmt.Errorf("error(cli): could not create temp file: %w", err)
	}
	n := f.Name()
	if _, err := io.Copy(f, os.Stdin); err != nil {
		_ = f.Close()
		_ = os.Remove(n)
		return "", fmt.Errorf("error(cli): could not copy stdin: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(n)
		return "", fmt.Errorf("error(cli): could not close temp file: %w", err)
	}
	return n, nil
}

func Execute() int {
	var f flags
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usageText, meta.Name)
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
				return 1
			}
		}
	}
	if !f.Json && f.Filter != "" {
		fmt.Fprintln(os.Stderr, "error(cli): -f requires -j flag")
		flag.Usage()
		return 1
	}
	// -h
	if f.Help {
		flag.Usage()
		return 0
	}
	// -V
	if f.Version {
		if _, err := fmt.Fprintln(os.Stdout, meta.Version); err != nil {
			return 1
		}
		return 0
	}
	// args
	args := flag.Args()
	if len(args) == 0 {
		path, err := readStdin()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if path == "" {
			path = defaultLogPath
		} else {
			defer os.Remove(path) //nolint:errcheck
		}
		args = []string{path}
	} else {
		count := 0
		for i, arg := range args {
			if arg != "-" {
				continue
			}
			count++
			if count > 1 {
				fmt.Fprintln(os.Stderr, "error(cli): duplicate stdin arg")
				return 1
			}
			path, err := readStdin()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			if path == "" {
				fmt.Fprintln(os.Stderr, "error(cli): no stdin data")
				return 1
			}
			defer os.Remove(path) //nolint:errcheck
			args[i] = path
		}
	}

	s, err := stream.NewStream(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// -j
	if f.Json {
		if err := displayJSON(s, f.Filter); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	} else {
		if err := tui.Display(s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	return 0
}
