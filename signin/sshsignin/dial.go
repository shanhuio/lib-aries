package sshsignin

import (
	"encoding/json"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"shanhu.io/aries/signin/signinapi"
	"shanhu.io/misc/errcode"
	"shanhu.io/misc/httputil"
	"shanhu.io/misc/strutil"
)

// Config contains the configuration to sign in with an SSH
// certificate.
type Config struct {
	User       string      // Default using SHANHU_USER or system user name.
	Agent      agent.Agent // Default using SSH_AUTH_SOCK
	KeyComment string      // Default is "shanhu"
}

func (c *Config) user() (string, error) {
	if c.User != "" {
		return c.User, nil
	}
	return SysUser()
}

func (c *Config) agent() (agent.Agent, error) {
	if c.Agent != nil {
		return c.Agent, nil
	}
	return SysAgent()
}

func findKey(ag agent.Agent, comment string) (*agent.Key, error) {
	keys, err := ag.List()
	if err != nil {
		return nil, errcode.Annotate(err, "list keys")
	}
	for _, k := range keys {
		if k.Comment == comment {
			return k, nil
		}
	}
	return nil, errcode.Internalf("%q not found", comment)
}

// Dial signs in a server and returns the credentials.
func Dial(server string, config *Config) (*httputil.Client, error) {
	user, err := config.user()
	if err != nil {
		return nil, errcode.Annotate(err, "get user name")
	}

	ag, err := config.agent()
	if err != nil {
		return nil, errcode.Annotate(err, "get SSH agent")
	}

	keyComment := strutil.Default(config.KeyComment, "shanhu")
	key, err := findKey(ag, keyComment)
	if err != nil {
		return nil, errcode.Annotate(err, "find key")
	}

	client, err := httputil.NewClient(server)
	if err != nil {
		return nil, errcode.Annotate(err, "make http client")
	}

	chReq := &signinapi.ChallengeRequest{}
	chResp := new(signinapi.ChallengeResponse)
	const chPath = "/sshcert/challenge"
	if err := client.Call(chPath, chReq, chResp); err != nil {
		return nil, errcode.Annotate(err, "get challenge")
	}

	record := &signinapi.SSHSignInRecord{
		User:      user,
		Challenge: chResp.Challenge,
	}
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return nil, errcode.Annotate(err, "marshal signin record")
	}
	sig, err := ag.Sign(key, recordBytes)
	if err != nil {
		return nil, errcode.Annotate(err, "sign signin record")
	}

	req := signinapi.SSHSignInRequest{
		RecordBytes: recordBytes,
		Sig: &signinapi.SSHSignature{
			Format: sig.Format,
			Blob:   sig.Blob,
			Rest:   sig.Rest,
		},
		Certificate: string(ssh.MarshalAuthorizedKey(key)),
	}

	creds := new(signinapi.Creds)
	if err := client.Call("/sshcert/signin", req, creds); err != nil {
		return nil, err
	}

	client.Token = creds.Token
	return client, nil
}
