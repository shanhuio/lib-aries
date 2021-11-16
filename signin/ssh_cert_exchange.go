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
	"crypto/rsa"

	"shanhu.io/misc/errcode"
	"shanhu.io/misc/rsautil"
	"shanhu.io/misc/signer"
)

// SSHCertExchange is a service stub that provides session tokens if the
// user signs a challenge and the SSH certificate of it.
type SSHCertExchange struct {
	tokener Tokener

	caPublicKey *rsa.PublicKey
	chSigner    *signer.Signer
	chSrc       *ChallengeSource
}

// SSHCertExchangeConfig is the configuration to create an SSH certificate
// signin stub.
type SSHCertExchangeConfig struct {
	CAPublicKeyFile string
	ChallengeKey    []byte
}

// NewSSHCertExchange creates a new SSH certificate exchange that exchanges
// signed challenges for session tokens.
func NewSSHCertExchange(tok Tokener, conf *SSHCertExchangeConfig) (
	*SSHCertExchange, error,
) {
	caPubKey, err := rsautil.ReadPublicKey(conf.CAPublicKeyFile)
	if err != nil {
		return nil, errcode.Annotate(err, "read CA public key")
	}

	ch := signer.New(conf.ChallengeKey)
	chSrc := NewChallengeSource(&ChallengeSourceConfig{Signer: ch})
	return &SSHCertExchange{
		tokener:     tok,
		caPublicKey: caPubKey,
		chSigner:    ch,
		chSrc:       chSrc,
	}, nil
}
