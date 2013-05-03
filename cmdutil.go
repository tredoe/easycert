// Copyright 2011 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code from 'http://code.google.com/p/go/source/browse/src/cmd/go/main.go'

// +build ignore

package main

import (
	"log"
	"os"
	"sync"
)

var exitStatus = 0
var exitMu sync.Mutex

func SetExitStatus(n int) {
	exitMu.Lock()
	if exitStatus < n {
		exitStatus = n
	}
	exitMu.Unlock()
}

var atexitFuncs []func()

func AtExit(f func()) {
	atexitFuncs = append(atexitFuncs, f)
}

func Exit() {
	for _, f := range atexitFuncs {
		f()
	}
	os.Exit(exitStatus)
}

func Fatalf(format string, args ...interface{}) {
	Errorf(format, args...)
	Exit()
}

func Errorf(format string, args ...interface{}) {
	log.Printf(format, args...)
	SetExitStatus(1)
}

//var logf = log.Printf

func ExitIfErrors() {
	if exitStatus != 0 {
		Exit()
	}
}
