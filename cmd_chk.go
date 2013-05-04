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

	"github.com/kless/gotool/flagutil"
)

var cmdChk = &flagutil.Command{
	Run:       runChk,
	UsageLine: "chk [-req | -cert | -key] FILE",
	Short:     "checking",
	Long: `
"chk" checks whether a certification-related file is right.
To look for the file, it uses the certificates directory when the "file" is just
a name or the path when the "file" is an absolute or relatative path.
`,
}

func init() {
	flagsForFileType(cmdChk)
}

func runChk(cmd *flagutil.Command, args []string) {
	if len(args) != 1 {
		log.Print("Missing required argument: FILE")
		cmd.Usage()
	}

	file := getAbsPaths(false, args)

	if *IsCert {
		CheckCert(file[0])
	} else if *IsRequest {
		CheckRequest(file[0])
	} else if *IsKey {
		CheckKey(file[0])
	} else {
		log.Print("Missing required flag")
		cmd.Usage()
	}
}

// CheckRequest checks the certificate request.
func CheckRequest(file string) {
	args := []string{"req", "-verify", "-noout", "-in", file}
	fmt.Printf("%s", openssl(args...))
}

// CheckCert checks the certificate.
func CheckCert(file string) {
	args := []string{"verify",
		"-CAfile", filepath.Join(Dir.Cert, NAME_CA+EXT_CERT),
		file,
	}
	fmt.Printf("%s", openssl(args...))
}

// CheckKey checks the private key.
func CheckKey(file string) {
	args := []string{"rsa", "-check", "-noout", "-in", file}
	fmt.Printf("%s", openssl(args...))
}
