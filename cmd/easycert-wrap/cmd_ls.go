// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/tredoe/flagplus"
)

var cmdLs = &flagplus.Subcommand{
	UsageLine: "ls [-req] [-cert] [-key]",
	Short:     "list",
	Long: `
"ls" lists files in the certificates directory.
Whether it is not used some flag, it lists all files related to certificates.
`,
	Run: runLs,
}

func init() {
	cmdLs.AddFlags("req", "cert", "key")
}

func runLs(cmd *flagplus.Subcommand, args []string) {
	if !*IsCert && !*IsRequest && !*IsKey {
		*IsCert = true
		*IsRequest = true
		*IsKey = true
	}

	if *IsCert {
		match, err := filepath.Glob(filepath.Join(Dir.Cert, "*"+EXT_CERT))
		if err != nil {
			log.Fatal(err)
		}
		printCert(match)
	}
	if *IsRequest {
		match, err := filepath.Glob(filepath.Join(Dir.Root, "*"+EXT_REQUEST))
		if err != nil {
			log.Fatal(err)
		}
		printCert(match)
	}
	if *IsKey {
		match, err := filepath.Glob(filepath.Join(Dir.Key, "*"+EXT_KEY))
		if err != nil {
			log.Fatal(err)
		}
		printCert(match)
	}
}

// printCert prints the name of the certificates.
func printCert(cert []string) {
	if len(cert) == 0 {
		return
	}
	for i, v := range cert {
		if i != 0 {
			fmt.Print("\t")
		}
		fmt.Print(filepath.Base(v))
	}
	fmt.Println()
}
