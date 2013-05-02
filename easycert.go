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
	//"go/build"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
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
	commands := NewCommands("EasyCert is a tool to generate and handle certificates.",
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

	flag.Usage = commands.Usage
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		commands.Usage()
	}

	if err := commands.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(2)
	}
}

/*
func usage() {
	fmt.Fprintf(os.Stderr, `Usage: easycert FLAG... [NAME|FILENAME]

The flags are:
`)

	flag.PrintDefaults()
	//os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NFlag() == 0 {
		fmt.Fprintf(os.Stderr, "Generate and handle certificates\n")
		os.Exit(2)
	}
}
*/

// getFilePath returns the absolute paths of files got in the arguments,
// according to the command.
func getFilePath(cmd *Command, args []string) ([]string, error) {
	cmdName := cmd.Name()
	newArgs := make([]string, len(args))

	for i, v := range args {
		switch cmdName {
		case "cat", "chk", "info":
			if v[0] != '.' && v[0] != os.PathSeparator {
				if *IsCert || cmdName == "info" {
					newArgs[i] = filepath.Join(Dir.Cert, v+EXT_CERT)
				} else if *IsRequest {
					newArgs[i] = filepath.Join(Dir.Root, v+EXT_REQUEST)
				} else if *IsKey {
					newArgs[i] = filepath.Join(Dir.Key, v+EXT_KEY)
				}
			}
		}
	}

	for _, v := range newArgs {
		if _, err := os.Stat(v); os.IsNotExist(err) {
			return nil, fmt.Errorf("File does not exists: %q", v)
		}
	}
	return newArgs, nil

	/*case *IsNewRequest, *IsSignReq, *IsCA:
		if *IsCA {
			filename = NAME_CA
		} else {
			if flag.NArg() == 0 {
				log.Fatal("Missing required argument")
			}
			filename = flag.Args()[0]
			File.SrvConfig = filepath.Join(Dir.Root, filename+".cfg")
		}
		File.Cert = filepath.Join(Dir.Cert, filename+EXT_CERT)
		File.Key = filepath.Join(Dir.Key, filename+EXT_KEY)
		File.Request = filepath.Join(Dir.Root, filename+EXT_REQUEST)

	case *IsCat, *IsInfo, *IsCheck:
		if flag.NArg() == 0 {
			log.Fatal("Missing required argument")
		}
		filename = flag.Args()[0]

		if filename[0] != '.' && filename[0] != os.PathSeparator {
			if *IsCert || *IsInfo {
				filename = filepath.Join(Dir.Cert, filename+EXT_CERT)
			} else if *IsRequest {
				filename = filepath.Join(Dir.Root, filename+EXT_REQUEST)
			} else if *IsKey {
				filename = filepath.Join(Dir.Key, filename+EXT_KEY)
			}
		}*/

	//return filename
}

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
