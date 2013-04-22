// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"go/build"
	"log"
	"os"
	"path/filepath"
	"text/template"
)

var cmdInit = &Command{
	Run:       runInit,
	UsageLine: "init",
	Short:     "initialize the directory",
	Long: `
"init" makes the directory structure in the HOME directory where
the certificates are handled.
`,
}

//var initCA = cmdInit.Flag.Bool("ca", false, "create certification authority")

func runInit(cmd *Command, args []string) {
	var err error

	for _, v := range []string{Dir.Root, Dir.Cert, Dir.Key} {
		if err = os.Mkdir(v, 0755); err != nil {
			log.Fatal(err)
		}
	}
	if err = os.Chmod(Dir.Key, 0710); err != nil {
		log.Fatal(err)
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
