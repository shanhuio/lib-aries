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

	"shanhu.io/misc/osutil"
)

// ParsePrivateKey parses the given private key blob.
func ParsePrivateKey(name string, bs []byte, tty bool) (
	*rsa.PrivateKey, error,
) {
	b, _ := pem.Decode(bs)
	if b == nil {
		return nil, fmt.Errorf("%q decode failed", name)
	}

	if !x509.IsEncryptedPEMBlock(b) {
		return x509.ParsePKCS1PrivateKey(b.Bytes)
	}

	if !tty {
		return nil, fmt.Errorf("%q is encrypted", name)
	}

	prompt := fmt.Sprintf("Passphrase for %s: ", name)
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

// ReadPrivateKey reads a private key from a key file.
func ReadPrivateKey(pemFile string, tty bool) (*rsa.PrivateKey, error) {
	bs, err := osutil.ReadPrivateFile(pemFile)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(pemFile, bs, tty)
}
