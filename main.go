package main

import (
	"gitlab.com/allddd/opnsense-filterlog/internal/cli"
)

var Version = "dev"

func main() {
	cli.Execute(Version)
}
