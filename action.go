// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// RootCA creates a Certification Authority.
func RootCA() {
	fmt.Print("\n== Build Certification Authority\n\n")

	args := []string{"req", "-new",
		"-config", File.Config, "-out", File.Request, "-keyout", File.Key,
		"-newkey", "rsa:" + _KeySize.String(),
	}
	openssl(args...)

	fmt.Print("\n== Sign\n\n")

	args = []string{"ca", "-selfsign", "-batch", "-create_serial",
		"-config", File.Config, "-keyfile", File.Key, "-in", File.Request, "-out", File.Cert,
		"-days", strconv.Itoa(365 * *_Years),
		"-extensions", "v3_ca",
	}
	openssl(args...)

	err := os.Remove(File.Request)
	if err != nil {
		log.Print(err)
	}
	if err = os.Chmod(File.Key, 0400); err != nil {
		log.Print(err)
	}

	fmt.Printf("\n== Generated\n- Certificate:\t%q\n- Private key:\t%q\n", File.Cert, File.Key)
}

// NewRequest creates a certificate request.
func NewRequest() {
	args := []string{"req", "-new", "-nodes",
		"-config", File.Config, "-keyout", File.Key, "-out", File.Request,
		"-newkey", "rsa:" + _KeySize.String(),
	}
	openssl(args...)

	if err := os.Chmod(File.Key, 0400); err != nil {
		log.Print(err)
	}

	fmt.Printf("\n== Generated\n- Request:\t%q\n- Private key:\t%q\n", File.Request, File.Key)
}

// SignReq signs a certificate request generating a new certificate.
func SignReq() {
	args := []string{"ca", "-policy", "policy_anything",
		"-config", File.Config, "-in", File.Request, "-out", File.Cert,
		"-days", strconv.Itoa(365 * *_Years),
		//"-keyfile", File.Key,
	}
	openssl(args...)

	if err := os.Remove(File.Request); err != nil {
		log.Print(err)
	}
	fmt.Printf("\n* Remove certificate request: %q\n", File.Cert)

	fmt.Printf("\n== Generated\n- Certificate:\t%q\n", File.Cert)
}

// == Checking
//

// CheckCert checks the certificate.
func CheckCert(file string) {
	args := []string{"verify",
		"-CAfile", filepath.Join(Dir.Cert, _NAME_CA+EXT_CERT),
		file,
	}
	openssl(args...)
}

// CheckKey checks the private key.
func CheckKey(file string) {
	args := []string{"rsa", "-check", "-noout", "-in", file}
	openssl(args...)
}

// == Information
//

// PrintCert prints the certificate in text.
func PrintCert(file string) {
	args := []string{"x509", "-text", "-noout", "-in", file}
	openssl(args...)
}

// PrintKey prints the private key in text.
func PrintKey(file string) {
	args := []string{"rsa", "-text", "-noout", "-in", file}
	openssl(args...)
}

// * * *

// PrintHash prints the hash value.
func PrintHash(file string) {
	args := []string{"x509", "-hash", "-noout", "-in", file}
	openssl(args...)
}

// PrintInfo prints the subject.
func PrintInfo(file string) {
	args := []string{"x509", "-subject", "-issuer", "-enddate", "-noout", "-in", file}
	openssl(args...)
}

// PrintIssuer prints the issuer.
func PrintIssuer(file string) {
	args := []string{"x509", "-issuer", "-noout", "-in", file}
	openssl(args...)
}

// PrintName prints the subject.
func PrintName(file string) {
	args := []string{"x509", "-subject", "-noout", "-in", file}
	openssl(args...)
}

// == Run
//

// openssl executes an OpenSSL command.
func openssl(args ...string) {
	var stdout bytes.Buffer

	cmd := exec.Command(File.Cmd, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = &stdout

	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	if err = cmd.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "\n%s\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s", stdout.Bytes())
}
