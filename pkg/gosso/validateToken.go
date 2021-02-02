package gosso

import (
	"crypto"
	"fmt"

	"github.com/dfkdream/GoSSO/internal/auth"
	"github.com/dgrijalva/jwt-go"
)

func ValidateToken(token string, puk crypto.PublicKey) (*auth.User, bool, error) {
	t, err := jwt.ParseWithClaims(token, &auth.UserClaim{}, func(token *jwt.Token) (i interface{}, err error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return puk, nil
	})

	if err != nil {
		return nil, false, err
	}

	if c, ok := t.Claims.(*auth.UserClaim); ok && t.Valid {
		return &c.User, true, nil
	}

	return nil, false, nil
}
