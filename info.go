// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"flag"
	"fmt"
)

// RunHash runs OpenSSL command to print the hash value.
func RunHash(cmdPath string) {
	args := []string{"x509", "-hash", "-noout"}

	if *fOut != "" {
		args = append(args, []string{"-out", *fOut}...)
	}

	if len(flag.Args()) != 0 {
		args = append(args, []string{"-in", ""}...)
		for _, v := range flag.Args() {
			args[len(args)-1] = v // change last argument

			fmt.Printf("%s => %s\n", run(cmdPath, args...), v)
		}
	} else {
		fmt.Printf("%s", run(cmdPath, args...))
	}
}
