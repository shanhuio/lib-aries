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
	"context"
	"time"

	"shanhu.io/aries"
	"shanhu.io/aries/identity"
	"shanhu.io/misc/errcode"
	"shanhu.io/misc/jwt"
)

// IDExchangeConfig is the config for creating an identity
// exchange config.
type IDExchangeConfig struct {
	Audiance string
	User     string
	Card     *identity.RemoteCard
}

// IDExchange exchanges an ID token for an access token.
type IDExchange struct {
	audiance string
	user     string
	card     identity.Card
	prepare  func(ctx context.Context) error
	verifier jwt.Verifier
	tokener  Tokener
	now      func() time.Time
}

// NewIDExchange creates an new identity exchange.
func NewIDExchange(
	tok Tokener, config *IDExchangeConfig,
) *IDExchange {
	now := time.Now
	v := identity.NewJWTVerifier(config.Card, now)
	return &IDExchange{
		audiance: config.Audiance,
		user:     config.User,
		card:     config.Card,
		prepare:  config.Card.Prepare,
		verifier: v,
		tokener:  tok,
		now:      now,
	}
}

// Exchange exchanges an ID token for an access token.
func (x *IDExchange) Exchange(c *aries.C, req *Request) (
	*Creds, error,
) {
	if req.IDToken == "" {
		return nil, errcode.InvalidArgf("id token missing")
	}

	if x.prepare != nil {
		if err := x.prepare(c.Context); err != nil {
			return nil, errcode.Annotate(err, "prepare for checking")
		}
	}

	if req.User != x.user {
		return nil, errcode.Unauthorizedf("invalid user")
	}

	tok, err := jwt.DecodeAndVerify(req.IDToken, x.verifier)
	if err != nil {
		return nil, errcode.Annotate(err, "invalid token")
	}

	claims := tok.ClaimSet
	if claims.Sub != req.User {
		return nil, errcode.Unauthorizedf("subject does not match user")
	}

	if x.audiance != "" {
		if x.audiance != claims.Aud {
			return nil, errcode.Unauthorizedf("invalid audiance")
		}
	}

	now := x.now()

	claimsTTL, err := jwt.CheckTime(claims, now)
	if err != nil {
		return nil, errcode.Annotate(err, "invalid token")
	}

	ttl := time.Duration(req.TTL)
	if ttl > claimsTTL {
		// access token ttl cannot exceed claims ttl
		ttl = claimsTTL
	}
	if ttl <= time.Duration(0) {
		return nil, errcode.Unauthorizedf("ttl too short")
	}

	token, credsExpires := x.tokener.Token(req.User, ttl)
	return &Creds{
		User:    req.User,
		Token:   token,
		Expires: credsExpires.UnixNano(),
	}, nil
}