// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/tredoe/flagplus"
)

var cmdInfo = &flagplus.Subcommand{
	UsageLine: "info [-end-date] [-hash] [-issuer] [-name] FILE",
	Short:     "information",
	Long: `
"info" prints out information of a certificate.
To look for the file, it uses the certificates directory when the "file" is just
a name or the path when the "file" is an absolute or relatative path.

Whether a flag is not set, then it prints full information.
`,
	Run: runInfo,
}

var (
	IsEndDate = flag.Bool("end-date", false, "print the date until it is valid")
	IsHash    = flag.Bool("hash", false, "print the hash value")
	IsIssuer  = flag.Bool("issuer", false, "print the issuer")
	IsName    = flag.Bool("name", false, "print the subject")
)

func init() {
	cmdInfo.AddFlags("end-date", "hash", "issuer", "name")
}

func runInfo(cmd *flagplus.Subcommand, args []string) {
	if len(args) != 1 {
		log.Print("Missing required argument: FILE")
		cmd.Usage()
	}

	*IsCert = true
	file := getAbsPaths(false, args)
	run := false

	if *IsEndDate {
		fmt.Print(InfoEndDate(file[0]))
		run = true
	}
	if *IsHash {
		fmt.Print(InfoHash(file[0]))
		run = true
	}
	if *IsIssuer {
		fmt.Print(InfoIssuer(file[0]))
		run = true
	}
	if *IsName {
		fmt.Print(InfoName(file[0]))
		run = true
	}
	if !run {
		fmt.Print(InfoFull(file[0]))
	}
}

// InfoFull prints all information of a certificate.
func InfoFull(file string) string {
	args := []string{"x509", "-subject", "-issuer", "-enddate", "-noout", "-in", file}
	return string(openssl(args...))
}

// InfoEndDate prints the last date that it is valid.
func InfoEndDate(file string) string {
	args := []string{"x509", "-enddate", "-noout", "-in", file}
	return string(openssl(args...))
}

// InfoHash prints the hash value.
func InfoHash(file string) string {
	args := []string{"x509", "-hash", "-noout", "-in", file}
	return string(openssl(args...))
}

// InfoIssuer prints the issuer.
func InfoIssuer(file string) string {
	args := []string{"x509", "-issuer", "-noout", "-in", file}
	return string(openssl(args...))
}

// InfoName prints the subject.
func InfoName(file string) string {
	args := []string{"x509", "-subject", "-noout", "-in", file}
	return string(openssl(args...))
}
