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
	"text/template"
)

// BuildCA creates a certification authority.
func BuildCA() {
	fmt.Print("\n== Build Certification Authority\n\n")

	args := []string{"req", "-new",
		"-config", File.Config, "-out", File.Request, "-keyout", File.Key,
		"-newkey", "rsa:" + RSASize.String(),
	}
	fmt.Printf("%s", openssl(args...))

	fmt.Print("\n== Sign\n\n")

	args = []string{"ca", "-selfsign", "-batch", "-create_serial",
		"-config", File.Config, "-keyfile", File.Key, "-in", File.Request, "-out", File.Cert,
		"-days", strconv.Itoa(365 * *Years),
		"-extensions", "v3_ca",
	}
	fmt.Printf("%s", openssl(args...))

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
	configFile := ""

	if Host.String() != "" {
		if err := serverConfig(); err != nil {
			log.Fatal(err)
		}
		configFile = File.SrvConfig
	} else {
		configFile = File.Config
	}

	args := []string{"req", "-new", "-nodes",
		"-config", configFile, "-keyout", File.Key, "-out", File.Request,
		"-newkey", "rsa:" + RSASize.String(),
	}
	fmt.Printf("%s", openssl(args...))

	if err := os.Chmod(File.Key, 0400); err != nil {
		log.Print(err)
	}

	fmt.Printf("\n== Generated\n- Request:\t%q\n- Private key:\t%q\n", File.Request, File.Key)
}

// SignReq signs a certificate request generating a new certificate.
func SignReq() {
	configFile := ""
	isForServer := false

	if _, err := os.Stat(File.SrvConfig); os.IsNotExist(err) {
		configFile = File.Config
	} else {
		isForServer = true
		configFile = File.SrvConfig
	}

	args := []string{"ca", "-policy", "policy_anything",
		"-config", configFile, "-in", File.Request, "-out", File.Cert,
		"-days", strconv.Itoa(365 * *Years),
		//"-keyfile", File.Key,
	}
	fmt.Printf("%s", openssl(args...))

	if err := os.Remove(File.Request); err != nil {
		log.Print(err)
	}
	fmt.Printf("\n* Remove certificate request: %q\n", File.Request)
	if isForServer {
		if err := os.Remove(configFile); err != nil {
			log.Print(err)
		}
	}

	fmt.Printf("\n== Generated\n- Certificate:\t%q\n", File.Cert)
}

// == Checking
//

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

// == Information
//

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

// * * *

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

// HashInfo prints the hash value.
func HashInfo(file string) string {
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

// == * * *

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

	return stdout.Bytes()
}

// serverConfig generates the configuration according for a server.
func serverConfig() error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("Could not get hostname: %s\n\n"+
			"You may want to fix your '/etc/hosts' and/or DNS setup",
			err)
	}

	tmpl, err := template.ParseFiles(File.Config + ".tmpl")
	if err != nil {
		return fmt.Errorf("Parsing error in configuration: %s", err)
	}

	configFile, err := os.Create(File.SrvConfig)
	if err != nil {
		return err
	}

	data := struct {
		HostName       string
		SubjectAltName string
	}{
		hostname,
		"subjectAltName = " + Host.String(),
	}
	err = tmpl.Execute(configFile, data)
	configFile.Close()
	if err != nil {
		return err
	}

	return nil
}
