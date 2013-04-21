// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"errors"
	"flag"
	"fmt"
	"go/build"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"
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

// == Flags

var (
	errMinSize = errors.New("key size must be at least of 2048")
	errSize    = errors.New("key size must be multiple of 1024")
	errHost    = errors.New("must be an IP or DNS")
)

// rsaSizeFlag represents the size in bits of RSA key to generate.
type rsaSizeFlag int

func (s *rsaSizeFlag) String() string {
	return strconv.Itoa(int(*s))
}

func (s *rsaSizeFlag) Set(value string) error {
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
	*s = rsaSizeFlag(i)
	return nil
}

// hostFlag represents the hostname with IP addresses and/or domain names.
type hostFlag struct {
	ip  []string
	dns []string
}

func (h *hostFlag) String() string {
	ip := strings.Join(h.ip, ", ")
	dns := strings.Join(h.dns, ", ")

	if len(ip) != 0 && len(dns) != 0 {
		return ip + ", " + dns
	}
	return ip + dns
}

func (h *hostFlag) Set(value string) error {
	for _, v := range strings.Split(value, ",") {
		v = strings.TrimSpace(v)

		if ip := net.ParseIP(v); ip != nil {
			h.ip = append(h.ip, "IP:"+ip.String())
		} else if strings.ContainsRune(v, '.') {
			h.dns = append(h.dns, "DNS:"+v)
		} else {
			return errHost
		}
	}
	return nil
}

var (
	Host    hostFlag
	RSASize rsaSizeFlag = 2048 // default

	Years = flag.Int("years", 1,
		"number of years a certificate generated is valid;\n\twith flag `-ca`, the default is 10 years")

	IsSetup      = flag.Bool("setup", false, "make the directory structure to handle the certificates")
	IsCA         = flag.Bool("ca", false, "create the certification authority")
	IsNewRequest = flag.Bool("new-req", false, "create certificate request")
	IsSignReq    = flag.Bool("sign", false, "sign a certificate request")

	IsCheck   = flag.Bool("chk", false, "checking")
	IsCert    = flag.Bool("cert", false, "certificate")
	IsRequest = flag.Bool("req", false, "request")
	IsKey     = flag.Bool("key", false, "private key")

	// Language
	IsGoLang   = flag.Bool("lang-go", false, "generate files in Go language to handle some certificate")
	CACert     = flag.String("ca-cert", NAME_CA, "name or file of CA's certificate")
	ServerCert = flag.String("server-cert", "", "name of server's certificate")

	// Information
	IsCat      = flag.Bool("cat", false, "show the content")
	IsInfo     = flag.Bool("info", false, "print out information of the certificate")
	IsEndDate  = flag.Bool("end-date", false, "print the date until it is valid")
	IsHash     = flag.Bool("hash", false, "print the hash value")
	IsFullInfo = flag.Bool("full", false, "print extensive information")
	IsIssuer   = flag.Bool("issuer", false, "print the issuer")
	IsName     = flag.Bool("name", false, "print the subject")

	IsList = flag.Bool("ls", false, "list files in certificates directory")
)

func init() {
	flag.Var(&Host, "host", "comma-separated hostnames and IPs to generate a certificate for a server")
	flag.Var(&RSASize, "rsa-size", "size in bits for the RSA key")
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: easycert FLAG... [NAME|FILENAME]

NOTE: FILENAME is the path of a certificate file, while NAME is the name
of a file to look for in the certificates directory.

* Directory structure:
	-setup [-ca -rsa-size -years]

* Create certificate request:
	-new-req [-sign -rsa-size -years -host] NAME
	-sign NAME

* Create files for some language:
	-lang-go [-ca-cert] -server-cert

* List:
	-ls (-req -cert -key)

* Information:
	-cat (-req|-cert|-key) NAME|FILENAME
	-info -full | (-end-date -hash -issuer -name) NAME|FILENAME

* ChecK:
	-chk (-req|-cert|-key) NAME|FILENAME

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

	isExit := false

	if *IsList {
		if *IsCert {
			match, err := filepath.Glob(filepath.Join(Dir.Cert, "*"+EXT_CERT))
			if err != nil {
				log.Fatal(err)
			}
			printCert(match)
			isExit = true
		}
		if *IsRequest {
			match, err := filepath.Glob(filepath.Join(Dir.Root, "*"+EXT_REQUEST))
			if err != nil {
				log.Fatal(err)
			}
			printCert(match)
			isExit = true
		}
		if *IsKey {
			match, err := filepath.Glob(filepath.Join(Dir.Key, "*"+EXT_KEY))
			if err != nil {
				log.Fatal(err)
			}
			printCert(match)
			isExit = true
		}

		if !isExit {
			log.Fatal("Missing required flag in `-ls`")
		}
		os.Exit(0)
	}

	// Set absolute paths.
	filename := ""
	switch {
	case *IsNewRequest, *IsSignReq, *IsCA:
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
		}
	}

	if *IsNewRequest {
		if _, err := os.Stat(File.Request); !os.IsNotExist(err) {
			log.Fatalf("Certificate request already exists: %q", File.Request)
		}
		NewRequest()
		isExit = true
	}
	if *IsSignReq {
		if _, err := os.Stat(File.Cert); !os.IsNotExist(err) {
			log.Fatalf("Certificate already exists: %q", File.Cert)
		}
		if isExit {
			fmt.Print("\n== Sign\n\n")
		}
		SignReq()
		os.Exit(0)
	}
	if isExit {
		os.Exit(0)
	}

	if *IsGoLang {
		for _, v := range []string{FILE_SERVER_GO, FILE_CLIENT_GO} {
			if _, err := os.Stat(v); !os.IsNotExist(err) {
				log.Fatalf("File already exists: %q", v)
			}
		}

		if *ServerCert == "" {
			log.Fatal("Missing required parameter in flag `-server-cert`")
		}

		if *CACert == "" {
			log.Fatal("Missing required parameter in flag `-ca-cert`")
		}
		if (*CACert)[0] != '.' && (*CACert)[0] != os.PathSeparator {
			*CACert = filepath.Join(Dir.Cert, *CACert+EXT_CERT)
		}

		Cert2Lang(
			filepath.Join(Dir.Cert, *ServerCert+EXT_CERT),
			filepath.Join(Dir.Key, *ServerCert+EXT_KEY),
		)
		os.Exit(0)
	}

	if *IsCat {
		if *IsCert {
			fmt.Print(InfoCert(filename))
		} else if *IsRequest {
			fmt.Print(InfoRequest(filename))
		} else if *IsKey {
			fmt.Print(InfoKey(filename))
		} else {
			log.Fatal("Missing required flag in `-cat`")
		}
		os.Exit(0)
	}

	if *IsInfo {
		if *IsFullInfo {
			fmt.Print(InfoFull(filename))
			os.Exit(0)
		}

		if *IsEndDate {
			fmt.Print(InfoEndDate(filename))
			isExit = true
		}
		if *IsHash {
			fmt.Print(HashInfo(filename))
			isExit = true
		}
		if *IsIssuer {
			fmt.Print(InfoIssuer(filename))
			isExit = true
		}
		if *IsName {
			fmt.Print(InfoName(filename))
			isExit = true
		}

		if !isExit {
			log.Fatal("Missing required flag in `-info`")
		}
		os.Exit(0)
	}

	if *IsCheck {
		if *IsCert {
			CheckCert(filename)
		} else if *IsRequest {
			CheckRequest(filename)
		} else if *IsKey {
			CheckKey(filename)
		} else {
			log.Fatal("Missing required flag in `-chk`")
		}
		os.Exit(0)
	}

	if *IsSetup {
		if _, err := os.Stat(Dir.Root); !os.IsNotExist(err) {
			log.Fatalf("The directory structure exists: %q", Dir.Root)
		}
		Setup()
	}
	if *IsCA {
		f := flag.Lookup("years")
		if f == nil {
			panic("flag `-years` not found")
		}
		if f.DefValue == f.Value.String() {
			*Years = 10
		}

		if _, err := os.Stat(File.Cert); !os.IsNotExist(err) {
			log.Fatal("The certification authority's certificate exists")
		}
		BuildCA()
	}
}

// Setup makes the directory structure according to whether it is going to be
// used for a certification authority or to keep the certificates signed from
// an external CA.
func Setup() {
	var err error

	for _, v := range []string{Dir.Root, Dir.Cert, Dir.Key} {
		if err = os.Mkdir(v, 0755); err != nil {
			log.Fatal(err)
		}
	}
	if err = os.Chmod(Dir.Key, 0710); err != nil {
		log.Fatal(err)
	}

	if *IsCA {
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
	}

	// Configuration template

	pkg, err := build.Import(_DIR_CONFIG, build.Default.GOPATH, build.FindOnly)
	if err != nil {
		log.Fatal("Data directory not found\n", err)
	}

	configTemplate := filepath.Join(pkg.Dir, FILE_CONFIG+".tmpl")
	if _, err = os.Stat(configTemplate); os.IsNotExist(err) {
		log.Fatalf("Configuration template not found: %q", configTemplate)
	}

	tmpl, err := template.ParseFiles(configTemplate)
	if err != nil {
		log.Fatal("Parsing error in configuration: ", err)
	}

	configFile, err := os.Create(File.Config)
	if err != nil {
		log.Fatal(err)
	}

	data := struct {
		RootDir        string
		HostName       string
		SubjectAltName string
	}{
		Dir.Root,
		"",
		"",
	}
	err = tmpl.Execute(configFile, data)
	configFile.Close()
	if err != nil {
		log.Fatal(err)
	}

	// Generate template for servers
	configFile, err = os.Create(File.Config + ".tmpl")
	if err != nil {
		log.Fatal(err)
	}

	tmpl, _ = template.ParseFiles(configTemplate)
	data.HostName = "{{.HostName}}"
	data.SubjectAltName = "{{.SubjectAltName}}"

	err = tmpl.Execute(configFile, data)
	configFile.Close()
	if err != nil {
		log.Fatal(err)
	}

	if err = os.Chmod(File.Config, 0600); err != nil {
		log.Print(err)
	}
	if err = os.Chmod(File.Config+".tmpl", 0600); err != nil {
		log.Print(err)
	}

	fmt.Printf("* Directory structure created in %q\n", Dir.Root)
}

// Cert2Lang creates files in Go language to handle the certificate.
func Cert2Lang(certFile, keyFile string) {
	caCertBlock, err := ioutil.ReadFile(*CACert)
	if err != nil {
		log.Fatal(err)
	}
	certBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Fatal(err)
	}
	keyBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Fatal(err)
	}

	version, err := exec.Command(File.Cmd, "version").Output()
	if err != nil {
		log.Fatal(err)
	}

	// Server

	file, err := os.OpenFile(FILE_SERVER_GO, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	tmpl := template.Must(template.New("").Parse(TMPL_SERVER_GO))
	data := struct {
		System     string
		Arch       string
		Version    string
		Date       string
		ValidUntil string
		CACert     string
		Cert       string
		Key        string
	}{
		runtime.GOOS,
		runtime.GOARCH,
		strings.TrimRight(string(version), "\n"),
		time.Now().Format(time.RFC822),
		fmt.Sprint(strings.TrimRight(InfoEndDate(certFile), "\n")),
		GoBlock(caCertBlock).String(),
		GoBlock(certBlock).String(),
		GoBlock(keyBlock).String(),
	}

	err = tmpl.Execute(file, data)
	file.Close()
	if err != nil {
		log.Fatal(err)
	}

	// Client

	file, err = os.OpenFile(FILE_CLIENT_GO, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	tmpl = template.Must(template.New("").Parse(TMPL_CLIENT_GO))

	err = tmpl.Execute(file, data)
	file.Close()
	if err != nil {
		log.Fatal(err)
	}
}

// printCert prints the name of the certificates.
func printCert(cert []string) {
	if len(cert) == 0 {
		return
	}
	for i, v := range cert {
		if i != 0 {
			fmt.Print("\t")
		}
		fmt.Print(filepath.Base(v))
	}
	fmt.Println()
}
