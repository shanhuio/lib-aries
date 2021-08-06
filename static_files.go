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

package aries

import (
	"fmt"
	"net/http"
	"strings"

	"shanhu.io/misc/strutil"
)

// StaticFiles is a module that serves static files.
type StaticFiles struct {
	cacheControl string
	h            http.Handler
}

// DefaultStaticPath is the default path for static files.
const DefaultStaticPath = "_/static"

func cacheControl(ageSecs int) string {
	return fmt.Sprintf("max-age=%d; must-revalidate", ageSecs)
}

// NewStaticFiles creates a module that serves static files.
func NewStaticFiles(p string) *StaticFiles {
	p = strutil.Default(p, DefaultStaticPath)
	return &StaticFiles{
		cacheControl: cacheControl(10),
		h:            http.FileServer(http.Dir(p)),
	}
}

// CacheAge sets the maximum age for the cache.
func (s *StaticFiles) CacheAge(ageSecs int) {
	if ageSecs < 0 {
		s.cacheControl = ""
	} else {
		s.cacheControl = cacheControl(ageSecs)
	}
}

// Serve serves incoming HTTP requests.
func (s *StaticFiles) Serve(c *C) error {
	c.Req.URL.Path = c.Path
	if s.cacheControl != "" {
		c.Resp.Header().Add("Cache-Control", s.cacheControl)
	}
	if strings.HasSuffix(c.Req.URL.Path, ".js") {
		// Make sure javascript files have the correct file type.
		const jsContentType = "application/javascript;charset=UTF-8"
		c.Resp.Header().Set("Content-Type", jsContentType)
	}
	s.h.ServeHTTP(c.Resp, c.Req)
	return nil
}