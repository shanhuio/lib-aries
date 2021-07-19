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

package redirect

import (
	"shanhu.io/aries"
)

type config struct {
	RedirectToDomain string
}

type server struct {
	c *config
}

func (s *server) redirect(c *aries.C) error {
	u := *c.Req.URL // make a shallow copy
	u.Scheme = "https"
	u.Host = s.c.RedirectToDomain
	c.Redirect(u.String())
	return nil
}

func newServer(c *config) (aries.Func, error) {
	s := &server{c: c}
	return s.redirect, nil
}

func makeService(env *aries.Env) (aries.Service, error) {
	s, err := newServer(env.Config.(*config))
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Main is the main entrance for the redirect service.
func Main() {
	aries.Main(makeService, new(config), "localhost:8000")
}
