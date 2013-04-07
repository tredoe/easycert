// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"flag"
	"fmt"
)

// CheckCert checks the certificate.
func CheckCert(cmdPath string) {
	args := []string{"verify", flag.Args()[0]}
	fmt.Printf("%s\n", run(cmdPath, args...))
}

// CheckKey checks the private key.
func CheckKey(cmdPath string) {
	args := []string{"rsa", "-check", "-noout", "-in", flag.Args()[0]}
	fmt.Printf("%s\n", run(cmdPath, args...))
}

// * * *

// PrintCert prints the certificate in text.
func PrintCert(cmdPath string) {
	args := []string{"x509", "-text", "-noout", "-in", flag.Args()[0]}
	fmt.Printf("%s\n", run(cmdPath, args...))
}

// PrintKey prints the private key in text.
func PrintKey(cmdPath string) {
	args := []string{"rsa", "-text", "-noout", "-in", flag.Args()[0]}
	fmt.Printf("%s\n", run(cmdPath, args...))
}

// * * *

// PrintHash prints the hash value.
func PrintHash(cmdPath string) {
	args := []string{"x509", "-hash", "-noout", "-in", ""}

	for _, v := range flag.Args() {
		args[len(args)-1] = v // add to last argument

		fmt.Printf("'%s':\t%s\n", v, run(cmdPath, args...))
	}
}

// PrintInfo prints the subject.
func PrintInfo(cmdPath string) {
	args := []string{"x509", "-subject", "-issuer", "-enddate", "-noout", "-in", ""}

	for _, v := range flag.Args() {
		args[len(args)-1] = v

		fmt.Printf("'%s'\n%s\n----\n", v, run(cmdPath, args...))
	}
}

// PrintIssuer prints the issuer.
func PrintIssuer(cmdPath string) {
	args := []string{"x509", "-issuer", "-noout", "-in", ""}

	for _, v := range flag.Args() {
		args[len(args)-1] = v

		fmt.Printf("'%s':\t%s\n", v, run(cmdPath, args...))
	}
}

// PrintName prints the subject.
func PrintName(cmdPath string) {
	args := []string{"x509", "-subject", "-noout", "-in", ""}

	for _, v := range flag.Args() {
		args[len(args)-1] = v

		fmt.Printf("'%s':\t%s\n", v, run(cmdPath, args...))
	}
}
