package auth

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type UserClaim struct {
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Issuer    string `json:"iss"`
	User      User   `json:"usr"`
}

func (u UserClaim) Valid() error {
	vErr := new(jwt.ValidationError)
	now := time.Now().Unix()

	// exp
	if !(now < u.ExpiresAt) {
		vErr.Inner = errors.New("token is expired")
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	// iat
	if !(now >= u.IssuedAt) {
		vErr.Inner = errors.New("token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	// nbf
	if !(now >= u.NotBefore) {
		vErr.Inner = errors.New("token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}
