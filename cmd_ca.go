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

var cmdCA = &Command{
	Run:       runCA,
	UsageLine: "ca [-rsa-size bits] [-years number]",
	Short:     "create certification authority",
	Long: `
"ca" creates a certification authority (CA) and makes the directories and files
to handle the certificates signed by this CA.
`,
}

func init() {
	flagsForNewCert(cmdCA)
}

func runCA(cmd *Command, args []string) {
	_, err := os.Stat(File.Cert)
	if !os.IsNotExist(err) {
		log.Fatal("The certification authority's certificate exists")
	}

	// New directories and files.

	for _, v := range []string{Dir.NewCert, Dir.Revok} {
		if err = os.Mkdir(v, 0755); err != nil {
			log.Fatal(err)
		}
	}

	file, err := os.Create(File.Index)
	if err != nil {
		log.Fatal(err)
	}
	file.Close()

	file, err = os.Create(File.Serial)
	if err != nil {
		log.Fatal(err)
	}
	_, err = file.Write([]byte{'0', '1', '\n'})
	file.Close()
	if err != nil {
		log.Fatal(err)
	}

	// CA

	fmt.Print("\n== Build Certification Authority\n\n")

	opensslArgs := []string{"req", "-new",
		"-config", File.Config, "-out", File.Request, "-keyout", File.Key,
		"-newkey", "rsa:" + RSASize.String(),
	}
	fmt.Printf("%s", openssl(opensslArgs...))

	fmt.Print("\n== Sign\n\n")

	opensslArgs = []string{"ca", "-selfsign", "-batch", "-create_serial",
		"-config", File.Config, "-keyfile", File.Key, "-in", File.Request, "-out", File.Cert,
		"-days", strconv.Itoa(365 * *Years),
		"-extensions", "v3_ca",
	}
	fmt.Printf("%s", openssl(opensslArgs...))

	if err = os.Remove(File.Request); err != nil {
		log.Print(err)
	}
	if err = os.Chmod(File.Key, 0400); err != nil {
		log.Print(err)
	}

	fmt.Printf("\n== Generated\n- Certificate:\t%q\n- Private key:\t%q\n", File.Cert, File.Key)
}
