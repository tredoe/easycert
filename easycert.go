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
	"os/user"
	"path/filepath"

	"github.com/kless/flagplus"
)

const (
	// Where the configuration template is installed through "go get".
	_DIR_CONFIG = "github.com/kless/easycert/data"

	DIR_ROOT = ".cert" // Directory to store the certificates.
	NAME_CA  = "ca"    // Name for files related to the CA.

	FILE_CONFIG    = "openssl.cfg"
	FILE_SERVER_GO = "z-srv_cert.go"
	FILE_CLIENT_GO = "z-clt_cert.go"
)

// File extensions.
const (
	EXT_CERT  = ".crt" // Certificate (can be publicly distributed)
	EXT_KEY   = ".key" // Private key (with restrictive permissions)
	EXT_REVOK = ".crl" // Certificate revokation list (can be publicly distributed)

	// Certificate Request (it will be signed by the CA in order to create the
	// server certificate. Afterwards it is not needed and can be deleted).
	EXT_REQUEST = ".csr"

	// For files that contain both the Key and the server certificate since some
	// servers need this. Permissions should be restrictive on these files.
	EXT_CERT_AND_KEY = ".pem"
)

// DirPath represents the directory structure.
type DirPath struct {
	Root  string // Root directory with certificates.
	Cert  string // Where the server certificates are placed.
	Key   string // Where the private keys are placed.
	Revok string // Where the certificate revokation list is placed.

	// Where OpenSSL puts the created certificates in PEM (unencrypted) format
	// and in the form 'cert_serial_number.pem' (e.g. '07.pem')
	NewCert string
}

// FilePath represents the files structure.
type FilePath struct {
	Cmd       string // OpenSSL' path
	Config    string // OpenSSL's configuration file.
	SrvConfig string // OpenSSL's configuration file for a server.
	Index     string // Serves as a database for OpenSSL.
	Serial    string // Contains the next certificate’s serial number.

	Cert    string // Certificate.
	Key     string // Private key.
	Request string // Certificate request.
}

var (
	Dir  *DirPath
	File *FilePath
)

// Set the directory structure.
func init() {
	log.SetFlags(0)
	log.SetPrefix("FAIL! ")

	cmdPath, err := exec.LookPath("openssl")
	if err != nil {
		log.Fatal("OpenSSL is not installed")
	}

	user, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	root := filepath.Join(user.HomeDir, DIR_ROOT)

	Dir = &DirPath{
		Root:    root,
		Cert:    filepath.Join(root, "certs"),
		NewCert: filepath.Join(root, "newcerts"),
		Key:     filepath.Join(root, "private"),
		Revok:   filepath.Join(root, "crl"),
	}

	File = &FilePath{
		Cmd:    cmdPath,
		Config: filepath.Join(Dir.Root, FILE_CONFIG),
		Index:  filepath.Join(Dir.Root, "index.txt"),
		Serial: filepath.Join(Dir.Root, "serial"),
	}
}

func main() {
	app := flagplus.NewApp(
		"EasyCert is a tool to generate and handle certificates.",
		cmdInit,
		cmdCA,
		cmdReq,
		cmdSign,
		cmdLang,
		cmdLs,
		cmdInfo,
		cmdCat,
		cmdChk,
	)
	app.Parse()
}

// getAbsPaths returns the absolute paths of files got in the arguments.
func getAbsPaths(isCmdInfo bool, args []string) []string {
	newArgs := make([]string, len(args))

	for i, v := range args {
		if v[0] != '.' && v[0] != os.PathSeparator {
			if *IsCert /*|| isCmdInfo*/ {
				newArgs[i] = filepath.Join(Dir.Cert, v+EXT_CERT)
			} else if *IsRequest {
				newArgs[i] = filepath.Join(Dir.Root, v+EXT_REQUEST)
			} else if *IsKey {
				newArgs[i] = filepath.Join(Dir.Key, v+EXT_KEY)
			}
		}
	}
	return newArgs
}

// setCertPath sets the absolute paths of files related to certificates with
// given `name`.
func setCertPath(name string) {
	if name != NAME_CA {
		File.SrvConfig = filepath.Join(Dir.Root, name+".cfg")
	}
	File.Cert = filepath.Join(Dir.Cert, name+EXT_CERT)
	File.Key = filepath.Join(Dir.Key, name+EXT_KEY)
	File.Request = filepath.Join(Dir.Root, name+EXT_REQUEST)
}

// openssl executes an OpenSSL command.
func openssl(args ...string) []byte {
	var stdout bytes.Buffer

	cmd := exec.Command(File.Cmd, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	if err = cmd.Wait(); err != nil {
		fmt.Fprintln(os.Stderr)
		log.Fatal(err)
	}
	return stdout.Bytes()
}
