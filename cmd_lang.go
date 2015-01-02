// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"flag"
	"fmt"
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

	"github.com/kless/goutil/flagplus"
)

var cmdLang = &flagplus.Subcommand{
	UsageLine: "lang [-ca file] [-server name] [-client] [-go]",
	Short:     "generate files into a language to handle the certificate",
	Long: `
"lang" generate files into a language to handle the certificate.
To look for the file, it uses the certificates directory when the "file" is just
a name or the path when the "file" is an absolute or relatative path.
`,
	Run: runLang,
}

var (
	CACert     = flag.String("ca", NAME_CA, "name or file of CA's certificate")
	ServerCert = flag.String("server", "", "name of server's certificate")

	IsClient = flag.Bool("client", false, "create generic file for the client")
	IsGo     = flag.Bool("go", true, "create files for Go language")
)

func init() {
	cmdLang.AddFlags("ca", "server", "client", "go")
}

func runLang(cmd *flagplus.Subcommand, args []string) {
	if *CACert == "" {
		log.Fatal("Missing required parameter in flag `-ca-cert`")
	}
	if (*CACert)[0] != '.' && (*CACert)[0] != os.PathSeparator {
		*CACert = filepath.Join(Dir.Cert, *CACert+EXT_CERT)
	}

	serverFile := ""
	clientFile := ""
	if *IsGo {
		serverFile = FILE_SERVER_GO
		clientFile = FILE_CLIENT_GO
	} else {
		log.Print("Missing required flag -- `-go`")
		cmd.Usage()
	}

	if *ServerCert != "" {
		if _, err := os.Stat(serverFile); !os.IsNotExist(err) {
			log.Fatalf("File already exists: %q", serverFile)
		}
	}
	if *IsClient {
		if _, err := os.Stat(clientFile); !os.IsNotExist(err) {
			log.Fatalf("File already exists: %q", clientFile)
		}
	}

	Cert2Lang()
}

// Cert2Lang creates files in Go language to handle the certificate.
func Cert2Lang() {
	version, err := exec.Command(File.Cmd, "version").Output()
	if err != nil {
		log.Fatal(err)
	}

	caCertBlock, err := ioutil.ReadFile(*CACert)
	if err != nil {
		log.Fatal(err)
	}

	// Common data to pass to templates.
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
		"",
		GoBlock(caCertBlock).String(),
		"",
		"",
	}

	if *ServerCert != "" {
		certFile := filepath.Join(Dir.Cert, *ServerCert+EXT_CERT)
		keyFile := filepath.Join(Dir.Key, *ServerCert+EXT_KEY)

		certBlock, err := ioutil.ReadFile(certFile)
		if err != nil {
			log.Fatal(err)
		}
		keyBlock, err := ioutil.ReadFile(keyFile)
		if err != nil {
			log.Fatal(err)
		}

		data.ValidUntil = fmt.Sprint(strings.TrimRight(InfoEndDate(certFile), "\n"))
		data.Cert = GoBlock(certBlock).String()
		data.Key = GoBlock(keyBlock).String()

		file, err := os.OpenFile(FILE_SERVER_GO, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}

		tmpl := template.Must(template.New("").Parse(TMPL_SERVER_GO))

		err = tmpl.Execute(file, data)
		file.Close()
		if err != nil {
			log.Fatal(err)
		}
	}

	if *IsClient {
		file, err := os.OpenFile(FILE_CLIENT_GO, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}

		tmpl := template.Must(template.New("").Parse(TMPL_CLIENT_GO))

		err = tmpl.Execute(file, data)
		file.Close()
		if err != nil {
			log.Fatal(err)
		}
	}
}

// == Template
//

const TMPL_SERVER_GO = `// MACHINE GENERATED BY easycert (github.com/kless/easycert)
// From {{.System}} ({{.Arch}}) with "{{.Version}}", on {{.Date}}
// Server valid for: {{.ValidUntil}}

package main

import (
	"crypto/tls"
	//"crypto/x509"
	"log"
)

var ServerTLSConfig *tls.Config

func init() {
	/*CA_CERT_BLOCK := {{.CACert}}*/

	CERT_BLOCK := {{.Cert}}

	KEY_BLOCK := {{.Key}}

	cert, err := tls.X509KeyPair(CERT_BLOCK, KEY_BLOCK)
	if err != nil {
		log.Fatal("server: load keys: ", err)
	}

	/*certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(CA_CERT_BLOCK); !ok {
		log.Fatal("server: CertPool: CA certificate not valid")
	}*/

	ServerTLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		//ClientCAs:    certPool,
		//ClientAuth:   tls.,
	}
}
`

const TMPL_CLIENT_GO = `// MACHINE GENERATED BY easycert (github.com/kless/easycert)
// From {{.System}} ({{.Arch}}) with "{{.Version}}", on {{.Date}}

// MUST set the filenames for both certificate and key
// var CertFile, KeyFile string

package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
)

var ClientTLSConfig *tls.Config

func init() {
	CA_CERT_BLOCK := {{.CACert}}

	cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		log.Fatal("client: load keys: ", err)
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(CA_CERT_BLOCK); !ok {
		log.Fatal("client: CertPool: CA certificate not valid")
	}

	ClientTLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
		//CipherSuites: []uint16{tls.},
	}
}
`

// GoBlock represents the definition of a "[]byte" in Go.
type GoBlock []byte

func (b GoBlock) String() string {
	s := make([]string, len(b))

	for i, v := range b {
		if i != 0 && i%18 == 0 {
			s[i-1] = s[i-1][:len(s[i-1])-1] // remove anterior space
			s[i] = "\n\t\t"
		}
		s[i] += fmt.Sprintf("%s, ", strconv.Itoa(int(v)))
	}

	i := len(s) - 1
	s[i] = s[i][:len(s[i])-1] // remove last space

	return fmt.Sprintf("[]byte{\n\t\t%s\n\t}", strings.Join(s, ""))
}
