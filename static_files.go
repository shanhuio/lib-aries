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
	"path/filepath"
	"strings"

	"shanhu.io/misc/osutil"
	"shanhu.io/misc/strutil"
)

type staticFileSystem struct {
	fs http.FileSystem
}

func (s *staticFileSystem) Open(name string) (http.File, error) {
	base := filepath.Base(name)
	lastDot := strings.LastIndex(base, ".")
	if lastDot >= 0 {
		return s.fs.Open(name)
	}

	if found, err := osutil.Exist(name); err != nil {
		return nil, AltInternalf(err, "fail to open %q", name)
	} else if !found {
		html := name + ".html" // try again with .html
		found, err := osutil.Exist(html)
		if err != nil {
			return nil, AltInternalf(err, "fail to open %q", html)
		}
		if found {
			return s.fs.Open(html)
		}
	}

	return s.fs.Open(name)
}

// StaticFiles is a module that serves static files.
type StaticFiles struct {
	cacheControl string
	h            http.Handler
}

// DefaultStaticPath is the default path for static files.
const DefaultStaticPath = "lib/site"

func cacheControl(ageSecs int) string {
	return fmt.Sprintf("max-age=%d; must-revalidate", ageSecs)
}

// NewStaticFiles creates a module that serves static files.
func NewStaticFiles(p string) *StaticFiles {
	p = strutil.Default(p, DefaultStaticPath)
	fs := &staticFileSystem{fs: http.Dir(p)}
	return &StaticFiles{
		cacheControl: cacheControl(10),
		h:            http.FileServer(fs),
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

var contentTypeSuffix = []struct {
	suffix      string
	contentType string
}{
	{suffix: ".js", contentType: "application/javascript;charset=UTF-8"},
	{suffix: ".css", contentType: "text/css;charset=UTF-8"},
}

// Serve serves incoming HTTP requests.
func (s *StaticFiles) Serve(c *C) error {
	c.Req.URL.Path = c.Path
	if s.cacheControl != "" {
		c.Resp.Header().Add("Cache-Control", s.cacheControl)
	}
	for _, suf := range contentTypeSuffix {
		if strings.HasSuffix(c.Req.URL.Path, suf.suffix) {
			c.Resp.Header().Set("Content-Type", suf.contentType)
			break
		}
	}
	s.h.ServeHTTP(c.Resp, c.Req)
	return nil
}
