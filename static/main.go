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

package static

import (
	"flag"
	"log"

	"shanhu.io/aries"
)

func makeService(dir string) aries.Service {
	return aries.NewStaticFiles(dir)
}

// Main is the main entrance for smlstatic binary
func Main() {
	dir := flag.String("dir", ".", "static directory to serve")
	addr := aries.DeclareAddrFlag("localhost:8000")
	flag.Parse()

	static := makeService(*dir)
	if err := aries.ListenAndServe(*addr, static); err != nil {
		log.Fatal(err)
	}
}
