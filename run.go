// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"flag"
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
	fmt.Printf("%s\n", openssl(args...))

	fmt.Print("== Sign\n\n")

	args = []string{"ca", "-selfsign", "-batch", "-create_serial",
		"-config", File.Config, "-keyfile", File.Key, "-in", File.Request, "-out", File.Cert,
		"-days", strconv.Itoa(365 * *_Years),
		"-extensions", "v3_ca",
	}
	fmt.Printf("%s\n", openssl(args...))

	err := os.Remove(File.Request)
	if err != nil {
		log.Print(err)
	}
	if err = os.Chmod(File.Key, 0400); err != nil {
		log.Print(err)
	}

	fmt.Printf("== Generated\n- Certificate:\t%q\n- Private key:\t%q\n", File.Cert, File.Key)
}

// NewRequest creates a certificate request.
func NewRequest() {
	args := []string{"req", "-new", "-nodes",
		"-config", File.Config, "-keyout", File.Key, "-out", File.Request,
		"-newkey", "rsa:" + _KeySize.String(),
		"-days", strconv.Itoa(365 * *_Years),
	}
	fmt.Printf("%s\n", openssl(args...))

	if err := os.Chmod(File.Key, 0400); err != nil {
		log.Print(err)
	}

	fmt.Printf("== Generated\n- Request:\t%q\n- Private key:\t%q\n", File.Request, File.Key)
}

// SignReq signs a certificate request generating a new certificate.
func SignReq() {
	args := []string{"ca", "-policy", "policy_anything",
		"-config", File.Config, "-in", File.Request, "-out", File.Cert,
		//"-keyfile", File.Key,
	}
	fmt.Printf("%s\n", openssl(args...))

	if err := os.Remove(File.Request); err != nil {
		log.Print(err)
	}
	fmt.Printf("* Remove certificate request: %q\n\n", File.Cert)

	fmt.Printf("== Generated\n- Certificate:\t%q\n", File.Cert)
}

// * * *

// CheckCert checks the certificate.
func CheckCert() {
	args := []string{"verify",
		"-CAfile", filepath.Join(Dir.Cert, _NAME_CA+EXT_CERT),
		flag.Args()[0],
	}
	fmt.Printf("%s\n", openssl(args...))
}

// CheckKey checks the private key.
func CheckKey() {
	args := []string{"rsa", "-check", "-noout", "-in", flag.Args()[0]}
	fmt.Printf("%s\n", openssl(args...))
}

// * * *

// PrintCert prints the certificate in text.
func PrintCert() {
	args := []string{"x509", "-text", "-noout", "-in", flag.Args()[0]}
	fmt.Printf("%s\n", openssl(args...))
}

// PrintKey prints the private key in text.
func PrintKey() {
	args := []string{"rsa", "-text", "-noout", "-in", flag.Args()[0]}
	fmt.Printf("%s\n", openssl(args...))
}

// * * *

// PrintHash prints the hash value.
func PrintHash() {
	args := []string{"x509", "-hash", "-noout", "-in", flag.Args()[0]}
	fmt.Printf("%s\n", openssl(args...))
}

// PrintInfo prints the subject.
func PrintInfo() {
	args := []string{"x509", "-subject", "-issuer", "-enddate", "-noout", "-in", ""}

	for _, v := range flag.Args() {
		args[len(args)-1] = v

		fmt.Printf("'%s'\n%s\n----\n", v, openssl(args...))
	}
}

// PrintIssuer prints the issuer.
func PrintIssuer() {
	args := []string{"x509", "-issuer", "-noout", "-in", flag.Args()[0]}
	fmt.Printf("%s\n", openssl(args...))
}

// PrintName prints the subject.
func PrintName() {
	args := []string{"x509", "-subject", "-noout", "-in", flag.Args()[0]}
	fmt.Printf("%s\n", openssl(args...))
}

// * * *

// openssl executes an OpenSSL command.
func openssl(args ...string) []byte {
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
	return bytes.TrimRight(stdout.Bytes(), "\n")
}
