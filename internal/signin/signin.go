// Sign in is the only way to generate refresh token
// It does not use REST API to store refresh token as HTTPOnly Cookie for Cross-Site Access Token request
package signin

import (
	"crypto/ecdsa"
	"net/http"
	"time"

	"github.com/emicklei/go-restful/v3"

	"github.com/dfkdream/GoSSO/internal/must"

	"github.com/google/uuid"

	"github.com/dgrijalva/jwt-go"

	"github.com/dfkdream/permission"

	"github.com/dfkdream/GoSSO/internal/auth"
)

var refreshTokenPermissions = []permission.Permission{
	must.PermissionFromString("+:gosso:token:refresh"),
}

var defaultPermissions = []permission.Permission{
	must.PermissionFromString("+:gosso"),
}

type SignIn struct {
	ds                  *auth.DataStore
	pk                  *ecdsa.PrivateKey
	refreshTokenTimeout time.Duration
}

func New(dataStore *auth.DataStore, privateKey *ecdsa.PrivateKey, tokenTimeout time.Duration) SignIn {
	return SignIn{
		ds:                  dataStore,
		pk:                  privateKey,
		refreshTokenTimeout: tokenTimeout,
	}
}

func (h SignIn) signInHandler(req *restful.Request, res *restful.Response) {
	redirect := "/signin"

	redirection := func(u string) {
		http.Redirect(res.ResponseWriter, req.Request, u, http.StatusTemporaryRedirect)
	}

	username, err := req.BodyParameter("username")
	if err != nil {
		redirection(redirect)
		return
	}

	password, err := req.BodyParameter("password")
	if err != nil {
		redirection(redirect)
		return
	}

	if username == "" || password == "" {
		redirection(redirect)
		return
	}

	// Create admin account with default permissions if user not exists
	if h.ds.Size() == 0 {
		pw, err := auth.HashPassword(password)
		if err != nil {
			redirection(redirect)
			return
		}

		err = h.ds.AddUser(&auth.User{
			ID:          uuid.New(),
			Username:    username,
			Password:    pw,
			Permissions: defaultPermissions,
		})
		if err != nil {
			redirection(redirect)
			return
		}
	}

	u, err := h.ds.GetUserByUsername(username)
	if err != nil {
		redirection(redirect)
		return
	}

	if u.Password.Validate(password) {

		if r, err := req.BodyParameter("redirect"); err == nil && r != "" {
			redirect = r
		} else {
			redirect = "/"
		}

		token, err := h.generateRefreshToken(u)
		if err != nil {
			redirection(redirect)
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

		redirection(redirect)
	} else {
		redirection(redirect)
	}
}

func (h SignIn) generateRefreshToken(u *auth.User) (string, error) {
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

func (h SignIn) WebService() *restful.WebService {
	ws := new(restful.WebService)

	ws.
		Path("/signin").
		Consumes("multipart/form-data",
			"application/x-www-form-urlencoded").
		Param(ws.FormParameter("username", "User name")).
		Param(ws.FormParameter("password", "Password"))

	ws.Route(ws.POST("/").To(h.signInHandler).
		Doc("Process sign in and returns refresh token or 2fa token").
		Writes([]byte{}))
	return ws
}
