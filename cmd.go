// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
)

var (
	errMinSize = errors.New("key size must be at least of 2048")
	errSize    = errors.New("key size must be multiple of 1024")
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

// Flags set by multiple commands.
var (
	RSASize rsaSizeFlag = 2048 // default

	Years = flag.Int("years", 1,
		"number of years a certificate generated is valid;\n\twith `-ca` flag, the default is 10 years")
)

func init() {
	flag.Var(&RSASize, "rsa-size", "size in bits for the RSA key")
}

var commands = []*Command{
	cmdInit,
	cmdCA,
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

	return stdout.Bytes()
}
