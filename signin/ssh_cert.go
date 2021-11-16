package signin

import (
	"crypto/rsa"

	"shanhu.io/misc/signer"
)

// SSHCert is a service stub that provides session tokens if the user
// signs a challenge and the SSH certificate of it.
type SSHCert struct {
	caPublicKey *rsa.PublicKey
	tokener     Tokener
	chSigner    *signer.Signer
}
