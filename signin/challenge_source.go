package signin

import (
	"crypto/rand"
	"io"
	"time"

	"shanhu.io/aries"
	"shanhu.io/aries/signin/signinapi"
	"shanhu.io/misc/signer"
	"shanhu.io/misc/timeutil"
)

// ChallengeSourceConfig is the configuration to create a challenge source.
type ChallengeSourceConfig struct {
	Signer *signer.Signer
	Now    func() time.Time
	Rand   io.Reader
}

// ChallengeSource is a source that can serve challenges.
type ChallengeSource struct {
	signer  *signer.Signer
	nowFunc func() time.Time
	rand    io.Reader
}

// NewChallengeSource creates a challenge source.
func NewChallengeSource(config *ChallengeSourceConfig) *ChallengeSource {
	r := config.Rand
	if r == nil {
		r = rand.Reader
	}
	return &ChallengeSource{
		signer:  config.Signer,
		nowFunc: timeutil.NowFunc(config.Now),
		rand:    r,
	}
}

// Serve serves a challenge.
func (s *ChallengeSource) Serve(
	c *aries.C, req *signinapi.ChallengeRequest,
) (*signinapi.ChallengeResponse, error) {
	t := s.nowFunc()
	signed, ch, err := s.signer.NewSignedChallenge(t, s.rand)
	if err != nil {
		return nil, err
	}
	return &signinapi.ChallengeResponse{
		Challenge: signed,
		Time:      ch.T,
	}, nil
}
