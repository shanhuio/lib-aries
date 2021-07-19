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

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"shanhu.io/aries/creds"
	"shanhu.io/misc/osutil"
	"shanhu.io/misc/rsautil"
)

type config struct {
	nbit         int
	noPassphrase bool
}

func keygen(output string, config *config) error {
	var passphrase []byte
	if !config.noPassphrase {
		pass, err := creds.ReadPassword("Key passphrase: ")
		if err != nil {
			return err
		}
		passphrase = pass
	}

	pri, pub, err := rsautil.GenerateKey(passphrase, config.nbit)
	if err != nil {
		return err
	}

	if output == "" {
		out, err := creds.HomeFile("key")
		if err != nil {
			return err
		}
		output = out
	}

	pemPath := output + ".pem"
	if yes, err := osutil.Exist(pemPath); err != nil {
		return err
	} else if yes {
		return fmt.Errorf("key file %q already exists", pemPath)
	}

	if err := ioutil.WriteFile(pemPath, pri, 0600); err != nil {
		return err
	}

	return ioutil.WriteFile(output+".pub", pub, 0600)
}

func main() {
	out := flag.String("out", "", "key path to output")
	nopass := flag.Bool("nopass", false, "no passphrase")
	nbit := flag.Int("nbit", 4096, "number of RSA bits")
	flag.Parse()

	conf := &config{
		nbit:         *nbit,
		noPassphrase: *nopass,
	}

	if err := keygen(*out, conf); err != nil {
		log.Fatal(err)
	}
}
