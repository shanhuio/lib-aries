package signinapi

import (
	"shanhu.io/misc/timeutil"
)

// SSHSignInRecord is the record that is being signed
type SSHSignInRecord struct {
	Challenge []byte

	// User is the user to sign in as. This Can be used to impersonate a
	// different user.
	User string `json:",omitempty"`

	TTL *timeutil.Duration
}

// SSHSignInRequest is the request to sign in with an SSH certificate
// credential.
type SSHSignInRequest struct {
	RecordBytes []byte // JSON encoded SSHSignInRecord
	Sig         []byte
	Certificate string
}
