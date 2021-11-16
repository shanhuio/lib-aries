package signinapi

import (
	"shanhu.io/misc/timeutil"
)

// SSHSignInRecord is the record that is being signed
type SSHSignInRecord struct {
	User      string `json:",omitempty"`
	Challenge []byte
	TTL       *timeutil.Duration
}

// SSHSignInRequest is the request to sign in with an SSH certificate
// credential.
type SSHSignInRequest struct {
	RecordBytes []byte // JSON encoded SSHSignInRecord
	Sig         []byte
	Certificate string
}
