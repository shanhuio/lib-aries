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

package https

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// RSACertConfig is the configuration for creating a RSA-based HTTPS
// certificate.
type RSACertConfig struct {
	Hosts    []string
	IsCA     bool
	Start    *time.Time
	Duration time.Duration
	Bits     int
}

// NewCACert creates a CA cert for the given domain.
func NewCACert(domain string) (*Cert, error) {
	c := &RSACertConfig{
		Hosts: []string{domain},
		IsCA:  true,
	}
	return MakeRSACert(c)
}

func (c *RSACertConfig) start() time.Time {
	if c.Start != nil {
		return *c.Start
	}
	return time.Now()
}

func (c *RSACertConfig) bits() int {
	if c.Bits == 0 {
		return 2048
	}
	return c.Bits
}

func (c *RSACertConfig) duration() time.Duration {
	if c.Duration <= 0 {
		return time.Hour * 24 * 30
	}
	return c.Duration
}

// MakeRSACert creates RSA-based HTTPS certificates.
func MakeRSACert(c *RSACertConfig) (*Cert, error) {
	if len(c.Hosts) == 0 {
		return nil, fmt.Errorf("no host specified")
	}

	priv, err := rsa.GenerateKey(rand.Reader, c.bits())
	if err != nil {
		return nil, fmt.Errorf("generate private key: %s", err)
	}

	start := c.start()
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %s", err)
	}

	const org = "Acme Co"
	const keyUsage = x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDigitalSignature

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{org}},
		NotBefore:    start,
		NotAfter:     start.Add(c.duration()),

		KeyUsage:    keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
	}

	for _, h := range c.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if c.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &priv.PublicKey, priv,
	)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %s", err)
	}

	certOut := new(bytes.Buffer)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut := new(bytes.Buffer)
	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	return &Cert{
		Cert: certOut.Bytes(),
		Key:  keyOut.Bytes(),
	}, nil
}
