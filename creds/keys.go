// Copyright (C) 2021  Shanhu Tech Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package creds

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// ParsePrivateKey parses the given private key blob.
func ParsePrivateKey(k string, bs []byte, tty bool) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode(bs)
	if b == nil {
		return nil, fmt.Errorf("%q decode failed", k)
	}

	if !x509.IsEncryptedPEMBlock(b) {
		return x509.ParsePKCS1PrivateKey(b.Bytes)
	}

	if !tty {
		return nil, fmt.Errorf("%q is encrypted", k)
	}

	prompt := fmt.Sprintf("Passphrase for %s: ", k)
	pwd, err := ReadPassword(prompt)
	if err != nil {
		return nil, err
	}

	der, err := x509.DecryptPEMBlock(b, pwd)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(der)
}

func readPrivateFile(f string, permCheck bool) ([]byte, error) {
	if permCheck {
		return ReadPrivateFile(f)
	}
	return ioutil.ReadFile(f)
}

func readPrivateKey(pemFile string, permCheck, tty bool) (
	*rsa.PrivateKey, error,
) {
	bs, err := readPrivateFile(pemFile, permCheck)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(pemFile, bs, tty)
}

// ReadPrivateKey reads a private key from a key file.
func ReadPrivateKey(pemFile string, tty bool) (*rsa.PrivateKey, error) {
	bs, err := ReadPrivateFile(pemFile)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(pemFile, bs, tty)
}
