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

	"shanhu.io/misc/signer"
)

// Request is the request for signing in.
type Request struct {
	User       string
	SignedTime *signer.SignedRSABlock `json:",omitempty"`
	IDToken    string                 `json:",omitempty"`

	TTL int64 // Requested time to live in nanoseconds.
}

// Creds is the response for signing in. It saves the user credentials.
type Creds struct {
	User    string
	Token   string
	Expires int64 // Nanosecond timestamp.
}

// Tokener issues auth tokens for users.
type Tokener interface {
	Token(user string, ttl time.Duration) (string, time.Time)
}
