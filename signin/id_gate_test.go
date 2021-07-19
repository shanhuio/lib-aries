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

	"context"
	"net/http/httptest"
	"net/url"
	"time"

	"shanhu.io/aries"
	"shanhu.io/aries/identity"
	"shanhu.io/misc/httputil"
	"shanhu.io/misc/jwt"
)

func TestService(t *testing.T) {
	now := time.Now()
	nowFunc := func() time.Time { return now }
	core := identity.NewMemCore(nowFunc)
	core.Init(&identity.CoreConfig{
		Keys: []*identity.KeyConfig{{
			NotValidAfter: now.Unix() + 3600,
		}},
	})

	serverRouter := aries.NewRouter()
	serverRouter.DirService("id", identity.NewService(core))

	idServer := httptest.NewServer(aries.Serve(serverRouter))
	defer idServer.Close()

	serverURL, err := url.Parse(idServer.URL)
	if err != nil {
		t.Fatal("parse server url: ", err)
	}
	cardURL := *serverURL
	cardURL.Path = "/id/get"

	remoteCard := identity.NewRemoteCard(&cardURL)
	if err := remoteCard.Prepare(context.Background()); err != nil {
		t.Fatal("prepare remote card:", err)
	}

	gate := NewIDGate(&IDGateConfig{
		Gate: &identity.GateConfig{
			Check: func(user string) (interface{}, int, error) {
				switch user {
				case "root":
					return "root", 10, nil
				case "":
					return "", 0, nil
				}
				return user, 1, nil
			},
		},
		Exchange: &IDExchangeConfig{
			Audiance: "app",
			User:     "root",
			Card:     remoteCard,
		},
	})

	admin := aries.NewRouter()
	admin.Get("admin", aries.StringFunc("admin"))

	app := &aries.ServiceSet{
		Auth:  gate,
		Admin: admin,
		IsAdmin: func(c *aries.C) bool {
			return c.UserLevel >= 10
		},
	}

	appServer := httptest.NewServer(aries.Serve(app))
	defer appServer.Close()

	// get an id token.
	signer := identity.NewJWTSigner(core)
	idToken, err := jwt.EncodeAndSign(&jwt.ClaimSet{
		Iss: "root",
		Aud: "app",
		Sub: "root",
		Exp: now.Add(time.Hour).Unix(),
		Iat: now.Unix(),
		Typ: jwt.DefaultType,
	}, signer)
	if err != nil {
		t.Fatal("getting id token:", err)
	}

	// try to exchange the id token for access token.
	appURL, err := url.Parse(appServer.URL)
	if err != nil {
		t.Fatal("parse app server url:", err)
	}

	client := httputil.Client{Server: appURL}

	creds := new(Creds)
	if err := client.Call("/idtoken/signin", &Request{
		User:    "root",
		IDToken: idToken,
		TTL:     5 * time.Minute.Nanoseconds(),
	}, creds); err != nil {
		t.Fatal("exchange for credential:", err)
	}

	client.Token = creds.Token
	t.Log("access token: ", creds.Token)

	info, err := gate.Gate().CheckToken(creds.Token, identity.TokenBearer)
	if err != nil {
		t.Error("check token: ", err)
	}
	t.Logf("token info: %v+", info)
	if info.User != "root" {
		t.Errorf("got %q user, want %q", info.User, "root")
	}

	got, err := client.GetString("/admin")
	if err != nil {
		t.Fatal("getting an admin page:", err)
	}
	if got != "admin" {
		t.Errorf("got %q, want %q", got, "admin")
	}
}
