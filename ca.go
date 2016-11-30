// Copyright 2014 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package easycert

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/tredoe/easycert/go13/x509"
)

// GenerateCert generate certificate for a TLS server. Outputs to 'cert.pem' and
// 'key.pem' and will overwrite existing files.
//
// + isCA:
//   whether this cert should be its own Certificate Authority
// + subject:
//   a X.509 distinguished name
// + validFor:
//   duration that certificate is valid for
// + host:
//   comma-separated hostnames and IPs to generate a certificate for
func GenerateCert(isCA bool, subject pkix.Name, validFor time.Duration) {
	// Use 256-bit random numbers
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatal("Failed to generate serial number:", err)
	}

	// Validity
	notBefore := time.Now()

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:   subject,
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(validFor),

		//KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth
		},

		BasicConstraintsValid: true,
	}
	if *isCA {
		template.IsCA = true
		template.MaxPathLen = 0
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		
	}

/*
SerialNumber, Subject, NotBefore, NotAfter, KeyUsage, ExtKeyUsage, UnknownExtKeyUsage, BasicConstraintsValid, IsCA, MaxPathLen, SubjectKeyId, DNSNames, PermittedDNSDomainsCritical, PermittedDNSDomains. 
*/

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal("Failed to create certificate:", err)
	}

}

