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

package creds

import (
	"crypto/rsa"
	"net/http"
	"time"

	"shanhu.io/aries/signin/signinapi"
	"shanhu.io/misc/errcode"
	"shanhu.io/misc/httputil"
	"shanhu.io/misc/rsautil"
	"shanhu.io/misc/signer"
	"shanhu.io/misc/timeutil"
)

// Creds is the credential that is cached after logging in. This can also be
// saved in JSON format in user's home directory.
type Creds struct {
	Server          string
	signinapi.Creds // User name is saved in this.
}

// Request contains the configuration to create a credential.
type Request struct {
	Server string
	User   string
	Key    *rsa.PrivateKey
	TTL    time.Duration

	// Transport is the http transport for the token exchange.
	Transport http.RoundTripper
}

// NewCredsFromRequest creates a new user credential by dialing the server
// using the given RSA private key.
func NewCredsFromRequest(req *Request) (*Creds, error) {
	signed, err := signer.RSASignTime(req.Key)
	if err != nil {
		return nil, err
	}

	cs := &Creds{Server: req.Server}

	c, err := httputil.NewClient(req.Server)
	if err != nil {
		return nil, err
	}
	c.Transport = req.Transport

	sr := &signinapi.Request{
		User:        req.User,
		SignedTime:  signed,
		TTLDuration: timeutil.NewDuration(req.TTL),
	}
	sr.FillLegacyTTL()
	if err := c.Call("/pubkey/signin", sr, &cs.Creds); err != nil {
		return nil, err
	}

	if got := cs.Creds.User; got != req.User {
		return nil, errcode.Internalf(
			"login as user %q, got %q", req.User, got,
		)
	}

	cs.Creds.FixTime()
	return cs, nil
}

// NewCreds creates a new user credential by dialing the server using
// the given RSA private key.
func NewCreds(server, user string, k *rsa.PrivateKey) (*Creds, error) {
	req := &Request{
		Server: server,
		User:   user,
		Key:    k,
	}
	return NewCredsFromRequest(req)
}

// DialRobot dials the server with the given key bytes.
func DialRobot(server, user string, key []byte) (*httputil.Client, error) {
	k, err := rsautil.ParsePrivateKey(key)
	if err != nil {
		return nil, errcode.Annotate(err, "parse key")
	}

	req := &Request{
		Server: server,
		User:   user,
		Key:    k,
	}
	creds, err := NewCredsFromRequest(req)
	if err != nil {
		return nil, errcode.Annotate(err, "get creds")
	}
	return httputil.NewTokenClient(server, creds.Token)
}
