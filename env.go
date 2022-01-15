// Copyright (C) 2022  Shanhu Tech Inc.
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

package aries

import (
	"context"
	"net/http"
)

// Env provides the generic config structure for starting a service.
type Env struct {
	// Context is the main context for running the service.
	// This is often just context.Background()
	Context context.Context

	// Config to make the server.
	Config interface{}

	// For the server to send outgoing HTTP requests.
	Transport http.RoundTripper

	// If this is testing environment.
	Testing bool
}

// BuildFunc builds a service using the given config and logger.
type BuildFunc func(env *Env) (Service, error)
