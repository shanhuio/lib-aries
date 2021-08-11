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
	"context"
	"flag"
	"log"
	"net/http"
	"strings"

	"shanhu.io/misc/errcode"
	"shanhu.io/misc/jsonutil"
	"shanhu.io/misc/jsonx"
	"shanhu.io/misc/osutil"
	"shanhu.io/misc/unixhttp"
)

func loadConfig(file string, config interface{}) error {
	if file == "" {
		for _, try := range []string{
			"config.jsonx",
			"config.json",
		} {
			ok, err := osutil.IsRegular(try)
			if err != nil {
				return err
			}
			if ok {
				file = try
				break
			}
		}
	}
	if file == "" {
		return errcode.InvalidArgf("config file not specified")
	}

	if strings.HasSuffix(file, ".json") {
		return jsonutil.ReadFile(file, config)
	}
	return jsonx.ReadFile(file, config)
}

// ListenAndServe serves on the address. If the address ends
// with .sock, it ListenAndServe's on the unix domain socket.
func ListenAndServe(addr string, s Service) error {
	log.Printf("serve on %q", addr)
	if strings.HasSuffix(addr, ".sock") {
		return unixhttp.ListenAndServe(addr, Serve(s))
	}
	return http.ListenAndServe(addr, Serve(s))
}

// RunMainLegacy runs the main body of a http server.
func RunMainLegacy(
	b BuildFunc, configFile string, config interface{}, addr string,
) error {
	if config != nil {
		if err := loadConfig(configFile, config); err != nil {
			return errcode.Annotate(err, "load config file")
		}
	}

	s, err := b(&Env{
		Context: context.Background(),
		Config:  config,
	})
	if err != nil {
		return err
	}

	return ListenAndServe(addr, s)
}

// DeclareAddrFlag declares the -addr flag.
func DeclareAddrFlag(def string) *string {
	return flag.String("addr", def, "address to listen on")
}
