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

package oauth

import (
	"context"
	"encoding/json"
	"fmt"

	"golang.org/x/oauth2"
	goauth2 "golang.org/x/oauth2/google"
	"shanhu.io/aries"
	"shanhu.io/misc/signer"
	"shanhu.io/misc/strutil"
)

// GoogleUserInfo stores a Google user's basic personal info.
type GoogleUserInfo struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// GetGoogleUserInfo queries Google OAuth endpoint for user info data.
func GetGoogleUserInfo(
	ctx context.Context, c *Client, tok *oauth2.Token,
) (*GoogleUserInfo, error) {
	bs, err := c.Get(ctx, tok, "https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, err
	}

	user := new(GoogleUserInfo)
	if err := json.Unmarshal(bs, user); err != nil {
		return nil, err
	}

	return user, nil
}

// GoogleApp stores the configuration of a Google oauth2 application.
type GoogleApp struct {
	ID          string
	Secret      string
	RedirectURL string

	WithProfile bool
	Scopes      []string
}

const (
	googleEmailScope   = "https://www.googleapis.com/auth/userinfo.email"
	googleProfileScope = "https://www.googleapis.com/auth/userinfo.profile"
)

type google struct{ c *Client }

func newGoogle(app *GoogleApp, s *signer.Sessions) *google {
	scopeSet := make(map[string]bool)
	// Google OAuth has to have at least one scope to get user ID.
	scopeSet[googleEmailScope] = true
	if app.WithProfile {
		scopeSet[googleProfileScope] = true
	}
	scopes := strutil.SortedList(scopeSet)
	if scopes == nil {
		scopes = []string{}
	}
	c := NewClient(
		&oauth2.Config{
			ClientID:     app.ID,
			ClientSecret: app.Secret,
			Scopes:       scopes,
			Endpoint:     goauth2.Endpoint,
			RedirectURL:  app.RedirectURL,
		}, s, MethodGoogle,
	)
	return &google{c: c}
}

func (g *google) client() *Client { return g.c }

func (g *google) callback(c *aries.C) (*UserMeta, *State, error) {
	tok, state, err := g.c.TokenState(c)
	if err != nil {
		return nil, nil, err
	}

	user, err := GetGoogleUserInfo(c.Context, g.c, tok)
	if err != nil {
		return nil, nil, err
	}

	email := user.Email
	if email == "" {
		return nil, nil, fmt.Errorf("empty login")
	}
	name := user.Name
	if name == "" {
		name = "no-name"
	}
	return &UserMeta{
		Method: MethodGoogle,
		ID:     email,
		Name:   name,
		Email:  email,
	}, state, nil
}
