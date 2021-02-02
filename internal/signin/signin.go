// Sign in is the only way to generate refresh token
// It does not use REST API to store refresh token as HTTPOnly Cookie for Cross-Site Access Token request
package signin

import (
	"crypto/ecdsa"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/dgrijalva/jwt-go"

	"github.com/dfkdream/permission"

	"github.com/dfkdream/GoSSO/internal/auth"
)

var refreshTokenPermissions = []permission.Permission{
	{
		Allow:      true,
		Namespaces: []string{"gosso", "token", "refresh"},
	},
}

var defaultPermissions = []permission.Permission{
	{
		Allow:      true,
		Namespaces: []string{"gosso"},
	},
}

type Handler struct {
	ds                  *auth.DataStore
	pk                  *ecdsa.PrivateKey
	refreshTokenTimeout time.Duration
}

func New(dataStore *auth.DataStore, privateKey *ecdsa.PrivateKey, tokenTimeout time.Duration) Handler {
	return Handler{
		ds:                  dataStore,
		pk:                  privateKey,
		refreshTokenTimeout: tokenTimeout,
	}
}

func (h Handler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	redirect := req.Referer()

	if req.Method != "POST" {
		http.Redirect(res, req, redirect, http.StatusTemporaryRedirect)
		return
	}

	err := req.ParseForm()
	if err != nil {
		http.Redirect(res, req, redirect, http.StatusTemporaryRedirect)
		return
	}

	username := req.FormValue("username")
	password := req.FormValue("password")

	if username == "" || password == "" {
		http.Redirect(res, req, redirect, http.StatusTemporaryRedirect)
		return
	}

	// Create admin account with default permissions if user not exists
	if h.ds.Size() == 0 {
		pw, err := auth.HashPassword(password)
		if err != nil {
			http.Redirect(res, req, redirect, http.StatusTemporaryRedirect)
			return
		}

		err = h.ds.AddUser(&auth.User{
			ID:          uuid.New(),
			Username:    username,
			Password:    pw,
			Permissions: defaultPermissions,
		})
		if err != nil {
			http.Redirect(res, req, redirect, http.StatusTemporaryRedirect)
			return
		}
	}

	u, err := h.ds.GetUserByUsername(username)
	if err != nil {
		http.Redirect(res, req, redirect, http.StatusTemporaryRedirect)
		return
	}

	if u.Password.Validate(password) {

		if r := req.FormValue("redirect"); r != "" {
			redirect = r
		} else {
			redirect = "/"
		}

		token, err := h.refreshToken(u)
		if err != nil {
			http.Redirect(res, req, redirect, http.StatusTemporaryRedirect)
			return
		}

		http.SetCookie(res, &http.Cookie{
			Name:     "token",
			Value:    token,
			Path:     "",
			Domain:   "",
			Secure:   true,
			HttpOnly: true,
			SameSite: 0,
		})

		http.Redirect(res, req, redirect, http.StatusTemporaryRedirect)
	} else {
		http.Redirect(res, req, redirect, http.StatusTemporaryRedirect)
	}
}

func (h Handler) refreshToken(u *auth.User) (string, error) {
	payload := u
	payload.Permissions = refreshTokenPermissions
	token := jwt.NewWithClaims(jwt.SigningMethodES256, auth.UserClaim{
		Issuer:    "gosso",
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
		ExpiresAt: time.Now().Add(h.refreshTokenTimeout).Unix(),
		User:      *payload,
	})
	return token.SignedString(h.pk)
}
