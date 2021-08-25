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

package signin

import (
	"net/url"

	"shanhu.io/aries/identity"
	"shanhu.io/misc/errcode"
)

// CaAuthConfig is the configuration toe create a DirectIDGate based on a
// remote CA.
type CaAuthConfig struct {
	Audience string
	Issuer   string
	CaURL    string
}

// NewCaAuth returns a new auth gate based on a remote ID auth CA.
func NewCaAuth(config *CaAuthConfig) (*DirectIDGate, error) {
	u, err := url.Parse(config.CaURL)
	if err != nil {
		return nil, errcode.Annotate(err, "parse CA url")
	}
	card := identity.NewRemoteCard(u)
	return NewDirectIDGate(&DirectIDGateConfig{
		Audience: config.Audience,
		Issuer:   config.Issuer,
		Card:     card,
	}), nil
}
