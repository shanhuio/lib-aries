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

	"log"
)

// IDGateConfig contains the configuration to create a ID gate.
type IDGateConfig struct {
	// Gate is config for the identity gate for checking identity.
	Gate *identity.GateConfig

	// Exchange is config for the identity exchange service for exchanging
	// ID tokens for access tokens.
	Exchange *IDExchangeConfig
}

// IDGate is a gate that has an "/idtoken/signin" method for signing in.
type IDGate struct {
	gate     *identity.Gate
	router   *aries.Router
	exchange *IDExchange
}

// NewIDGate creates a new ID gate with a sign in method.
func NewIDGate(config *IDGateConfig) *IDGate {
	g := identity.NewGate(config.Gate)
	ex := NewIDExchange(g, config.Exchange)

	r := aries.NewRouter()
	r.Call("idtoken/signin", ex.Exchange)

	return &IDGate{
		gate:     g,
		router:   r,
		exchange: ex,
	}
}

// Gate returns the identity gate.
func (g *IDGate) Gate() *identity.Gate {
	return g.gate
}

// Serve serves the sign in
func (g *IDGate) Serve(c *aries.C) error {
	err := g.router.Serve(c)
	if err != nil {
		log.Println(c.Path, err)
	}
	return err
}

// Setup sets up the credentials for the request.
func (g *IDGate) Setup(c *aries.C) error {
	return g.gate.Setup(c)
}

// Token returns a new session token for user that expires in ttl.
func (g *IDGate) Token(user string, ttl time.Duration) (string, time.Time) {
	return g.gate.Token(user, ttl)
}
