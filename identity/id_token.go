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

package identity

import (
	"time"

	"shanhu.io/misc/errcode"
	"shanhu.io/misc/jwt"
)

// SelfSignIssuer use this to indicate self signing.
const SelfSignIssuer = "."

// SignIDConfig provides the configuration to sign an ID token.
type SignIDConfig struct {
	User   string
	Domain string

	// Optional; when empty, Domain is the issuer.
	Issuer string

	// Optional; when empty, Domain is the audience.
	Audience string

	Time   time.Time
	Expiry time.Duration // Optional; default 5 minute.
}

// SignID signs an ID token.
func SignID(signer Signer, config *SignIDConfig) (string, error) {
	id := UserAtDomain(config.User, config.Domain)
	sub := id
	expiry := config.Expiry
	if expiry <= time.Duration(0) {
		expiry = 5 * time.Minute
	}

	iss := config.Issuer
	if iss == "" {
		iss = config.Domain
		sub = config.User
	}

	aud := config.Audience
	if aud == "" {
		aud = config.Domain
		if iss == SelfSignIssuer {
			sub = config.User
		}
	}

	claims := &jwt.ClaimSet{
		Sub: sub,
		Iss: iss,
		Aud: aud,
		Iat: config.Time.Unix(),
		Exp: config.Time.Add(expiry).Unix(),
	}

	return jwt.EncodeAndSign(claims, NewJWTSigner(signer))
}

// VerifySelfSignedID verifies a self-signed ID token that is presented to
// its owner host.
func VerifySelfSignedID(
	token, user, host string, card Card, t time.Time,
) (*jwt.Token, error) {
	v := NewJWTVerifier(card)
	decoded, err := jwt.DecodeAndVerify(token, v, t)
	if err != nil {
		return nil, err
	}

	claims := decoded.ClaimSet
	if claims == nil {
		return nil, errcode.Unauthorizedf("claims missing")
	}

	wantClaims := &jwt.ClaimSet{
		Iss: SelfSignIssuer,
		Sub: user,
		Aud: host,
	}
	if err := jwt.CheckClaimSet(claims, wantClaims); err != nil {
		return nil, errcode.Annotate(err, "check claims")
	}
	return decoded, nil
}
