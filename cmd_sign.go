// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
)

var cmdSign = &Command{
	Run:       runSign,
	UsageLine: "sign [-years number] NAME",
	Short:     "sign certificate request",
	Long: `
"sign" signs a certificate signing request (CSR) using the CA in the
certificates directory and generates a certificate.
`,
}

func runSign(cmd *Command, args []string) {
	if len(args) != 1 {
		log.Print("Missing required argument: NAME")
		cmd.Usage()
	}
	SignReq()
}

// SignReq signs a certificate request generating a new certificate.
func SignReq() {
	if _, err := os.Stat(File.Cert); !os.IsNotExist(err) {
		log.Fatalf("Certificate already exists: %q", File.Cert)
	}

	configFile := ""
	isForServer := false

	if _, err := os.Stat(File.SrvConfig); os.IsNotExist(err) {
		configFile = File.Config
	} else {
		isForServer = true
		configFile = File.SrvConfig
	}

	opensslArgs := []string{"ca", "-policy", "policy_anything",
		"-config", configFile, "-in", File.Request, "-out", File.Cert,
		"-days", strconv.Itoa(365 * *Years),
		//"-keyfile", File.Key,
	}
	fmt.Printf("%s", openssl(opensslArgs...))

	if err := os.Remove(File.Request); err != nil {
		log.Print(err)
	}

	fmt.Print("\n== Sign\n\n")
	fmt.Printf("\n* Remove certificate request: %q\n", File.Request)
	if isForServer {
		if err := os.Remove(configFile); err != nil {
			log.Print(err)
		}
	}

	fmt.Printf("\n== Generated\n- Certificate:\t%q\n", File.Cert)
}
