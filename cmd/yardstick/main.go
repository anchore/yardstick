package main

import (
	"os"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/cli"
)

// applicationName is the non-capitalized name of the application (do not change this)
const (
	applicationName = "yardstick"
	notProvided     = "[not provided]"
)

// all variables here are provided as build-time arguments, with clear default values
var (
	version        = notProvided
	buildDate      = notProvided
	gitCommit      = notProvided
	gitDescription = notProvided
)

func main() {
	app, exit := cli.New(
		clio.Identification{
			Name:           applicationName,
			Version:        version,
			BuildDate:      buildDate,
			GitCommit:      gitCommit,
			GitDescription: gitDescription,
		},
	)

	// an error exits from inside Run with its mapped code; a gate that failed is not an error clio
	// should print, so its code is set here instead
	app.Run()
	os.Exit(*exit)
}
