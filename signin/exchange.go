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
	"shanhu.io/misc/timeutil"
)

// ExchangeConfig is the config for creating an session exchanger
// that exchanges access tokens for session tokens.
type ExchangeConfig struct {
	Audience string
	Issuer   string
	Card     identity.Card
	Now      func() time.Time
}

// Exchange exchanges access tokens for a session tokens.
type Exchange struct {
	audience string
	issuer   string
	card     identity.Card
	verifier jwt.Verifier
	tokener  Tokener
	now      func() time.Time
}

// NewExchange creates an exchange that exchnages access tokens
// for session tokens from tok.
func NewExchange(
	tok Tokener, config *ExchangeConfig,
) *Exchange {
	return &Exchange{
		audience: config.Audience,
		issuer:   config.Issuer,
		card:     config.Card,
		verifier: identity.NewJWTVerifier(config.Card),
		tokener:  tok,
		now:      timeutil.NowFunc(config.Now),
	}
}

// Exchange is the API that exchanges access tokens for session tokens in the
// form of credentials.
func (x *Exchange) Exchange(c *aries.C, req *Request) (
	*Creds, error,
) {
	if req.AccessToken == "" {
		return nil, errcode.InvalidArgf("access token missing")
	}

	if err := x.card.Prepare(c.Context); err != nil {
		return nil, errcode.Annotate(err, "prepare for checking")
	}

	now := x.now()
	tok, err := jwt.DecodeAndVerify(req.AccessToken, x.verifier, now)
	if err != nil {
		return nil, errcode.Annotate(err, "invalid token")
	}

	wantClaims := &jwt.ClaimSet{
		Sub: req.User,
		Iss: x.issuer,
		Aud: x.audience,
	}
	if err := jwt.CheckClaimSet(tok.ClaimSet, wantClaims); err != nil {
		return nil, errcode.Annotate(err, "invalid claims")
	}

	ttl := timeutil.TimeDuration(req.TTLDuration)
	if ttl <= time.Duration(0) {
		return nil, errcode.Unauthorizedf("ttl too short")
	}

	token := x.tokener.Token(req.User, ttl)
	return TokenCreds(req.User, token), nil
}
