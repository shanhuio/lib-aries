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
	"time"

	"shanhu.io/aries"
	"shanhu.io/aries/identity"
	"shanhu.io/misc/errcode"
	"shanhu.io/misc/jwt"
)

// DirectIDGate is a simple auth module that directly read ID token from
// bearer to authenticate. This is suitable for an API-based site that
// serves mostly one-shot API methods, where exchanging for an access token
// is redundant.
type DirectIDGate struct {
	audience string
	issuer   string
	card     identity.Card
	verifier jwt.Verifier
	now      func() time.Time
}

// DirectIDGateConfig returns a
type DirectIDGateConfig struct {
	Audience string
	Issuer   string
	Card     identity.Card
}

// NewDirectIDGate creates a new auth gate that directly checkes the bearer
// token as ID tokens.
func NewDirectIDGate(config *DirectIDGateConfig) *DirectIDGate {
	return &DirectIDGate{
		audience: config.Audience,
		issuer:   config.Issuer,
		card:     config.Card,
		verifier: identity.NewJWTVerifier(config.Card),
		now:      time.Now,
	}
}

// Serve does nothing and returns aries.Miss
func (g *DirectIDGate) Serve(c *aries.C) error {
	return aries.Miss
}

// Setup verifies the bearer token as an ID token. If the token is valid.
// it uses the "sub" field as the username.
func (g *DirectIDGate) Setup(c *aries.C) error {
	bearer := aries.Bearer(c)
	if bearer == "" {
		return nil
	}

	now := g.now()
	tok, err := jwt.DecodeAndVerify(bearer, g.verifier, now)
	if err != nil {
		return errcode.Annotate(err, "invalid bearer token")
	}

	wantClaims := &jwt.ClaimSet{
		Iss: g.issuer,
		Aud: g.audience,
	}
	if err := jwt.CheckClaimSet(tok.ClaimSet, wantClaims); err != nil {
		return errcode.Annotate(err, "invalid claims")
	}

	c.User = tok.ClaimSet.Sub
	return nil
}
