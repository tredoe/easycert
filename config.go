// Copyright 2014 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package easycert

import "os"

// Title for the common elements of a distinguished name (DN).
var (
	Country            = "Country Name (2 letter code)"
	Organization       = "Organization Name (eg, company)"
	OrganizationalUnit = "Organizational Unit Name (eg, section)"

	Locality = "Locality Name (eg, city)"
	Province = "Province Name (eg, state in USA)"

	StreetAddress = "Street Address"
	PostalCode    = "Postal Code"

	CommonName = "Common Name (e.g. server FQDN or YOUR name)"
)

type CertAuth struct {
	KeyUsage    []string
	ExtKeyUsage []string

	BasicConstraintsValid bool
	IsCA                  bool
}

type config struct {
	ca CertAuth
}

// check checks that the configuration is correct.
func (cfg config) check() error {
	return nil
}

func t() error {
	var cfg config

	configData, err := os.ReadFile("data/easycert.yaml")
	if err != nil {
		return err
	}

	if err = goyaml.Unmarshal(configData, &cfg); err != nil {
		return
	}
	if err = cfg.check(); err != nil {
		return err
	}

	return nil
}
