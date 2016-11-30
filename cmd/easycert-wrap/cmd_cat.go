// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"log"

	"github.com/tredoe/flagplus"
)

var cmdCat = &flagplus.Subcommand{
	UsageLine: "cat [-req | -cert | -key] FILE",
	Short:     "show the content",
	Long: `
"cat" shows the content of a certification-related file.
To look for the file, it uses the certificates directory when the "file" is just
a name or the path when the "file" is an absolute or relatative path.
`,
	Run: runCat,
}

func init() {
	cmdCat.AddFlags("req", "cert", "key")
}

func runCat(cmd *flagplus.Subcommand, args []string) {
	if len(args) != 1 {
		log.Print("Missing required argument: FILE")
		cmd.Usage()
	}

	file := getAbsPaths(false, args)

	if *IsCert {
		fmt.Print(InfoCert(file[0]))
	} else if *IsRequest {
		fmt.Print(InfoRequest(file[0]))
	} else if *IsKey {
		fmt.Print(InfoKey(file[0]))
	} else {
		log.Print("Missing required flag")
		cmd.Usage()
	}
}

// InfoRequest prints the certificate request in text.
func InfoRequest(file string) string {
	args := []string{"req", "-text", "-noout", "-in", file}
	return string(openssl(args...))
}

// InfoCert prints the certificate in text.
func InfoCert(file string) string {
	args := []string{"x509", "-text", "-noout", "-in", file}
	return string(openssl(args...))
}

// InfoKey prints the private key in text.
func InfoKey(file string) string {
	args := []string{"rsa", "-text", "-noout", "-in", file}
	return string(openssl(args...))
}
