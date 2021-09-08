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
	"shanhu.io/misc/timeutil"
)

// Request is the request for signing in and creating a session.
type Request struct {
	User        string
	SignedTime  *signer.SignedRSABlock `json:",omitempty"`
	AccessToken string                 `json:",omitempty"`

	TTLDuration *timeutil.Duration `json:",omitempty"`

	TTL int64 `json:",omitempty"` // Nano duration, legacy use.
}

// FillLegacyTTL fills the legacy TTL field, so that it is backwards
// compatible.
func (r *Request) FillLegacyTTL() {
	if r.TTLDuration != nil && r.TTL == 0 {
		r.TTL = r.TTLDuration.Duration().Nanoseconds()
	}
}

// GetTTL gets the TTL. It respects the legacy TTL field.
func (r *Request) GetTTL() time.Duration {
	if r.TTLDuration == nil {
		return time.Duration(r.TTL)
	}
	return timeutil.TimeDuration(r.TTLDuration)
}

// Creds is the response for signing in. It saves the user credentials.
type Creds struct {
	User        string
	Token       string
	ExpiresTime *timeutil.Timestamp `json:",omitempty"`

	Expires int64 `json:",omitempty"` // Nanosecond timestamp, legacy use.
}

// FixTime fixes timestamps.
func (c *Creds) FixTime() {
	if c.ExpiresTime == nil && c.Expires != 0 {
		t := time.Unix(0, c.Expires)
		c.ExpiresTime = timeutil.NewTimestamp(t)
	}
}

// TokenCreds gets the credential from a token.
func TokenCreds(user string, tok *Token) *Creds {
	return &Creds{
		User:        user,
		Token:       tok.Token,
		ExpiresTime: timeutil.NewTimestamp(tok.Expire),
	}
}

// Token is a token with an expire time.
type Token struct {
	Token  string
	Expire time.Time
}

// Tokener issues auth tokens for users.
type Tokener interface {
	Token(user string, ttl time.Duration) *Token
}
