// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Command go.mkcert generates a self-signed certificate with its private key,
// to be used in TLS conections.
//
// ssl-cert in Linux System
//
// go.mkcert is based in '/usr/sbin/make-ssl-cert' Bash script from the
// "ssl-cert" package in Ubuntu system. That package comes with a self-signed
// certificate in:
//   + /etc/ssl/certs/ssl-cert-snakeoil.pem
//   + /etc/ssl/private/ssl-cert-snakeoil.key
//
// To create a fresh certificate:
//
//   $ sudo make-ssl-cert generate-default-snakeoil [--force-overwrite]
//
// However, there is no easy way to change arguments such as "days" or the
// default bits.
//
// Checking
//
// These are basic operations to check the self-signed certificate:
//
// + Check certificate:
//
//   $ openssl verify -CAfile /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/ssl/certs/ssl-cert-snakeoil.pem
//
// + Check private key of certificate:
//
//   $ sudo openssl rsa -noout -text -check -in /etc/ssl/private/ssl-cert-snakeoil.key
//
// + Query certificate:
//
//   $ openssl x509 -noout -in /etc/ssl/certs/ssl-cert-snakeoil.pem -text
//   $ openssl x509 -noout -in /etc/ssl/certs/ssl-cert-snakeoil.pem -dates
package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"go/build"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/kless/sysuser"
)

const (
	// Directory where the configuration template is installed through "go get".
	DIR_CONFIG  = "github.com/kless/easycert/data"
	FILE_CONFIG = "tls-cert.cfg"
)

// X509Args are the OpenSSL's arguments to generate a X509 certificate.
var X509Args = []string{"req", "-new", "-x509", "-nodes"}

// == Flags

var (
	errMinSize = errors.New("key size must be at least of 2048")
	errSize    = errors.New("key size must be multiple of 1024")
)

// keySize represents the size in bits of the RSA key to generate.
type keySize int

func (s *keySize) Set(value string) error {
	i, err := strconv.Atoi(value)
	if err != nil {
		return err
	}

	if i < 2048 {
		return errMinSize
	}
	if i%1024 != 0 {
		return errSize
	}
	*s = keySize(i)
	return nil
}

func (s *keySize) String() string {
	return strconv.Itoa(int(*s))
}

var (
	fKeySize keySize = 2048 // default

	fConfig = flag.String("config", "", "configuration template for X509 certificate.\n"+
		"\tBy default, it is used the file installed with this program")
	fDays      = flag.Uint("days", 365*7, "number of days a certificate generated is valid")
	fFile      = flag.String("file", "cert-snakeoil", "certificate file name")
	fOverwrite = flag.Bool("overwrite", false, "force overwrite when certificate exists")

	fDebug  = flag.Bool("d", false, "debug mode; only create temporary files")
	fHash   = flag.Bool("hash", false, "print the hash value")
	fLangGo = flag.Bool("lang-go", false, "generate file for Go language with certificate in binary")
	fRoot   = flag.Bool("root", false, "generate file for the system in '/etc/ssl'")

	//fIn  = flag.String("in", "", "input file; default stdin")
	fOut = flag.String("out", "", "output file; default stdout")
)

func init() {
	flag.Var(&fKeySize, "size", "size in bits for the RSA key")
}

func usage() {
	fmt.Fprintf(os.Stderr, `Generate self-signed certificate.

Usage: go.mkcert -root | -lang-go | -d
`)

	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if !*fRoot && !*fLangGo && !*fDebug && !*fHash {
		usage()
	}
	if *fDebug && (*fRoot || *fLangGo) {
		usage()
	}

	log.SetFlags(0)
	log.SetPrefix("FAIL! ")

	cmdPath, err := exec.LookPath("openssl")
	if err != nil {
		log.Fatal("OpenSSL is not installed")
	}

	if *fHash {
		RunHash(cmdPath)
		os.Exit(0)
	}

	// == File names for the certificate

	var certFile, keyFile string

	if *fRoot {
		if os.Getuid() != 0 {
			log.Fatal("You must be root")
		}
		certFile = filepath.Join("/etc/ssl/certs", *fFile)
		keyFile = filepath.Join("/etc/ssl/private", *fFile)
	} else {
		certFile = filepath.Join(os.TempDir(), *fFile)
		keyFile = filepath.Join(os.TempDir(), *fFile)

		if *fLangGo {
			*fFile += ".go"
		}
	}
	certFile += ".pem"
	keyFile += ".key"

	if !*fOverwrite {
		if _, err = os.Stat(certFile); !os.IsNotExist(err) {
			log.Fatalf("File already exists: %q", certFile)
		}
		if _, err = os.Stat(keyFile); !os.IsNotExist(err) {
			log.Fatalf("File already exists: %q", keyFile)
		}

		if !*fRoot {
			if _, err = os.Stat(*fFile); !os.IsNotExist(err) {
				log.Fatalf("File already exists: %q", *fFile)
			}
		}
	}

	// == Configuration template

	// Get the path of the templates directory.
	if *fConfig == "" {
		pkg, err := build.Import(DIR_CONFIG, build.Default.GOPATH, build.FindOnly)
		if err != nil {
			log.Fatal("Data directory not found\n", err)
		}

		*fConfig = filepath.Join(pkg.Dir, FILE_CONFIG)
	}
	if _, err = os.Stat(*fConfig); os.IsNotExist(err) {
		log.Fatalf("Configuration file not found: %q", *fConfig)
	}

	host, err := os.Hostname()
	if err != nil {
		log.Fatalf("Could not get hostname: %s\n\n"+
			"You may want to fix your '/etc/hosts' and/or DNS setup",
			err)
	}

	tmpl, err := template.ParseFiles(*fConfig)
	if err != nil {
		log.Fatal("Parsing error in configuration: ", err)
	}
	tmpConfigFile, err := ioutil.TempFile("", FILE_CONFIG+"_")
	if err != nil {
		log.Fatal(err)
	}

	data := struct {
		HostName string
		AltNames string
	}{
		host,
		"IP.1 = 127.0.0.1",
	}
	err = tmpl.Execute(tmpConfigFile, data)
	tmpConfigFile.Close()
	if err != nil {
		log.Fatal(err)
	}

	// == Run "openssl"

	// Add extra arguments to command
	moreArgs := []string{
		"-config", tmpConfigFile.Name(),
		"-days", strconv.FormatUint(uint64(*fDays), 10),
		"-newkey", "rsa:" + fKeySize.String(),
		"-out", certFile, "-keyout", keyFile,
	}
	X509Args = append(X509Args, moreArgs...)
	run(cmdPath, X509Args...)

	if !*fDebug {
		if err = os.Remove(tmpConfigFile.Name()); err != nil {
			log.Print(err)
		}
	} else {
		fmt.Printf("\n## OpenSSL arguments\n%s\n\n## Temporary files\n", X509Args)
		fmt.Println("- Configuration:", tmpConfigFile.Name())
	}

	// Check whether the generated certificate is correct.
	_, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal("Load keys: ", err)
	}

	// Change modes to files generated
	if *fRoot {
		if err = os.Chmod(certFile, 0644); err != nil {
			log.Print(err)
		}
		if err = os.Chmod(keyFile, 0640); err != nil {
			log.Print(err)
		}

		group, err := sysuser.LookupGroup("ssl-cert")
		if err == nil {
			if err = os.Chown(keyFile, 0, group.Gid); err != nil {
				log.Print(err)
			}
		}
	} else {
		if *fDebug {
			fmt.Println("- Certificate:", certFile)
			fmt.Println("- Private key:", keyFile)
			os.Exit(0)
		}

		// Generate Go file

		certBlock, err := ioutil.ReadFile(certFile)
		if err != nil {
			log.Fatal(err)
		}
		keyBlock, err := ioutil.ReadFile(keyFile)
		if err != nil {
			log.Fatal(err)
		}
		// Remove temporary certificate
		for _, v := range []string{certFile, keyFile} {
			if err = os.Remove(v); err != nil {
				log.Print(err)
			}
		}

		wd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}

		version, err := exec.Command("openssl", "version").Output()
		if err != nil {
			log.Fatal(err)
		}

		file, err := os.OpenFile(*fFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}

		tmpl = template.Must(template.New("").Parse(TEMPLATE_GO))
		data := struct {
			Command   string
			System    string
			Arch      string
			Version   string
			Date      string
			Package   string
			Cert, Key string
		}{
			strings.Join(os.Args, " "),
			runtime.GOOS,
			runtime.GOARCH,
			string(bytes.TrimRight(version, "\n")),
			time.Now().Format(time.RFC822),
			filepath.Base(wd),
			GoBlock(certBlock).String(),
			GoBlock(keyBlock).String(),
		}

		err = tmpl.Execute(file, data)
		file.Close()
		if err != nil {
			log.Fatal(err)
		}
	}
}

// run executes an OpenSSL command.
func run(cmdPath string, args ...string) []byte {
	var stdout bytes.Buffer

	cmd := exec.Command(cmdPath, args...)
	cmd.Stderr = os.Stderr
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
