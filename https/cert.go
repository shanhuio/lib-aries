// Copyright (C) 2022  Shanhu Tech Inc.
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

package https

import (
	"crypto/tls"
)

// Cert contains a certificate in memory.
type Cert struct {
	Cert []byte // Marshalled PEM block for the certificate.
	Key  []byte // Marshalled PEM block for the private key.
}

// X509KeyPair converts the PEM blocks into a X509 key pair
// for use in an HTTPS server.
func (c *Cert) X509KeyPair() (tls.Certificate, error) {
	return tls.X509KeyPair(c.Cert, c.Key)
}
