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
	"shanhu.io/aries/keyreg"
	"shanhu.io/misc/errcode"
	"shanhu.io/misc/rsautil"
	"shanhu.io/misc/signer"
	"shanhu.io/misc/timeutil"
)

// PublicKeyExchange handles sign in using a public key registry. The request
// presents a signed time using the user's private key to authenticate.
type PublicKeyExchange struct {
	Tokener     Tokener
	KeyRegistry keyreg.KeyRegistry
}

// Exchange handles the request to exchange a public-key signed timestamp to a
// token.
func (x *PublicKeyExchange) Exchange(c *aries.C, req *Request) (
	*Creds, error,
) {
	if req.SignedTime == nil {
		return nil, errcode.InvalidArgf("signature missing")
	}

	keys, err := x.KeyRegistry.Keys(req.User)
	if err != nil {
		return nil, err
	}

	var key *rsautil.PublicKey
	for _, k := range keys {
		if k.HashStr() == req.SignedTime.KeyID {
			key = k
			break
		}
	}
	if key == nil {
		return nil, errcode.Unauthorizedf("signing key not authorized")
	}

	const window = time.Minute * 5
	if err := signer.CheckRSATimeSignature(
		req.SignedTime, key.Key(), window,
	); err != nil {
		return nil, errcode.Add(errcode.Unauthorized, err)
	}

	ttl := timeutil.TimeDuration(req.TTL)
	token, expires := x.Tokener.Token(req.User, ttl)
	return &Creds{
		User:        req.User,
		Token:       token,
		ExpiresTime: timeutil.NewTimestamp(expires),
	}, nil
}
