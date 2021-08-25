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
	"testing"

	"fmt"
	"net/http/httptest"
	"net/url"
	"time"

	"shanhu.io/aries"
	"shanhu.io/aries/identity"
	"shanhu.io/misc/httputil"
	"shanhu.io/misc/jwt"
)

func TestDirectIDGate(t *testing.T) {
	now := time.Now()
	nowFunc := func() time.Time { return now }

	core := identity.NewMemCore(nowFunc)
	core.Init(&identity.CoreConfig{
		Keys: []*identity.KeyConfig{{
			NotValidAfter: now.Unix() + 3600,
		}},
	})

	gate := NewDirectIDGate(&DirectIDGateConfig{
		Audience: "myapp.app",
		Issuer:   "id.shanhu.io",
		Card:     core,
		Now:      nowFunc,
	})

	admin := aries.NewRouter()
	admin.Get("user", func(c *aries.C) error {
		fmt.Fprint(c.Resp, c.User)
		return nil
	})

	app := &aries.ServiceSet{
		Auth:  gate,
		Admin: admin,
		IsAdmin: func(c *aries.C) bool {
			return c.User != ""
		},
	}

	appServer := httptest.NewServer(aries.Serve(app))
	defer appServer.Close()

	signer := identity.NewJWTSigner(core)
	idToken, err := jwt.EncodeAndSign(&jwt.ClaimSet{
		Iss: "id.shanhu.io",
		Aud: "myapp.app",
		Sub: "h8liu",
		Exp: now.Add(time.Hour).Unix(),
		Iat: now.Unix(),
		Typ: jwt.DefaultType,
	}, signer)
	if err != nil {
		t.Fatal("get id token: ", err)
	}

	appURL, err := url.Parse(appServer.URL)
	if err != nil {
		t.Fatal("parse app server url: ", err)
	}

	client := httputil.Client{
		Server: appURL,
		Token:  idToken,
	}
	got, err := client.GetString("/user")
	if err != nil {
		t.Fatal("getting the user name page: ", err)
	}
	if want := "h8liu"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
