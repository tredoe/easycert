// Copyright 2013 Jonas mg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Command easycert handle certificates to be used in TLS conections.

In the first, there is to create the directory structure:

	easycert -new

which creates the directory '.cert' in your HOME directory.

Then, can be generated the certificate requests to be signed by a certification
authority.


Usage: easycert FLAG... [NAME|FILENAME]

NOTE: FILENAME is the path of a certificate file, while NAME is the name
of a file to look for in the certificates directory.

* Directory:
  -new [-ca -rsa-size -years]

* Certificate requests:
  -req [-rsa-size -years] [-sign] [-host] NAME
  -sign NAME

* Create files for some language:
  -lang-go -server-cert [-ca-cert]

* ChecK:
  -chk [-cert|-key] NAME|FILENAME

* Information:
  -cat [-cert|-key] NAME|FILENAME
  -i [-end-date -hash -issuer -name] NAME|FILENAME
  -i -full NAME|FILENAME

* List:
  -lc -lr

The flags are:
  -ca=false: create the certification authority
  -ca-cert="ca": name or file of CA's certificate
  -cat=false: show certificate or key
  -cert=false: the file is a certificate
  -chk=false: checking
  -end-date=false: print the date until it is valid
  -full=false: print extensive information
  -hash=false: print the hash value
  -host="": comma-separated hostnames and IPs to generate a certificate for
  -i=false: print out information of the certificate
  -issuer=false: print the issuer
  -key=false: the file is a private key
  -lang-go=false: generate files in Go language to handle some certificate
  -lc=false: list the certificates built
  -lr=false: list the request certificates built
  -name=false: print the subject
  -new=false: create the directory structure to handle the certificates
  -req=false: create a certificate request
  -rsa-size=2048: size in bits for the RSA key
  -server-cert="": name of server's certificate
  -sign=false: sign a certificate request
  -years=1: number of years a certificate generated is valid;
	with `-ca` flag, the default is 10 years
*/
package main
