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

	"shanhu.io/misc/rsautil"
)

// ParsePrivateKey parses the given private key blob.
func ParsePrivateKey(name string, bs []byte, tty bool) (
	*rsa.PrivateKey, error,
) {
	if tty {
		return rsautil.ParsePrivateKeyTTY(name, bs)
	}
	return rsautil.ParsePrivateKey(bs)
}

// ReadPrivateKey reads a private key from a key file.
func ReadPrivateKey(pemFile string, tty bool) (*rsa.PrivateKey, error) {
	if tty {
		return rsautil.ReadPrivateKeyTTY(pemFile)
	}
	return rsautil.ReadPrivateKey(pemFile)
}
