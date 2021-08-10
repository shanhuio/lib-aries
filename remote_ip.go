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
	"net"
	"strings"
)

// RemoteIP returns the remote IP address.
func RemoteIP(c *C) net.IP {
	forwardedFor := c.Req.Header.Get("X-Forwarded-For")
	ips := strings.Split(forwardedFor, ",")
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil {
			return parsed
		}
	}

	remoteAddr := c.Req.RemoteAddr
	if remoteAddr == "@" || remoteAddr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
