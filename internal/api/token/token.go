package token

import (
	"crypto/ecdsa"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/dfkdream/GoSSO/internal/must"

	"github.com/dfkdream/GoSSO/pkg/gosso"

	"github.com/google/certificate-transparency-go/x509"

	"github.com/dfkdream/GoSSO/internal/auth"
	"github.com/dgrijalva/jwt-go"
	"github.com/emicklei/go-restful/v3"
)

var refreshPermission = must.PermissionFromString("+:gosso:token:refresh")

type Token struct {
	ds            *auth.DataStore
	pk            *ecdsa.PrivateKey
	accessTimeout time.Duration
	pem           []byte
}

type refreshTokenResponse struct {
	Token string `json:"token"`
}

func New(dataStore *auth.DataStore, privateKey *ecdsa.PrivateKey, accessTimeout time.Duration) (*Token, error) {
	pemBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}

	return &Token{
		ds:            dataStore,
		pk:            privateKey,
		accessTimeout: accessTimeout,
		pem: pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pemBytes,
		}),
	}, nil
}

func (t Token) generateAccessToken(u auth.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, auth.UserClaim{
		Issuer:    "gosso",
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
		ExpiresAt: time.Now().Add(t.accessTimeout).Unix(),
		User:      u,
	})
	return token.SignedString(t.pk)
}

func (t Token) publicKey(_ *restful.Request, res *restful.Response) {
	_, err := res.Write(t.pem)
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
	}
}

func isRefreshToken(u *auth.User) bool {
	if len(u.Permissions) != 1 {
		return false
	}

	if !u.Permissions[0].Equals(refreshPermission) {
		return false
	}

	return refreshPermission.HasPermission(u.Permissions)
}

func (t Token) refreshToken(req *restful.Request, res *restful.Response) {
	c, err := req.Request.Cookie("token")
	if err != nil {
		_ = res.WriteError(http.StatusBadRequest, err)
		return
	}

	u, ok, err := gosso.ValidateToken(c.Value, t.pk.Public())
	if ok && u != nil {

		if !isRefreshToken(u) {
			_ = res.WriteErrorString(http.StatusForbidden, "Bad Refresh Token")
			return
		}

		usr, err := t.ds.GetUserByID(u.ID)
		if err != nil {
			_ = res.WriteError(http.StatusInternalServerError, err)
			return
		}
		at, err := t.generateAccessToken(*usr)
		if err != nil {
			_ = res.WriteError(http.StatusInternalServerError, err)
			return
		}
		err = res.WriteAsJson(refreshTokenResponse{Token: at})
		if err != nil {
			_ = res.WriteError(http.StatusInternalServerError, err)
			return
		}
		return
	}

	if err != nil {
		_ = res.WriteError(http.StatusForbidden, err)
		return
	}

	_ = res.WriteErrorString(http.StatusForbidden, "Forbidden")
}

func (t Token) WebService() *restful.WebService {
	ws := new(restful.WebService)

	ws.
		Path("/token").
		Produces(restful.MIME_JSON)

	ws.Route(ws.GET("/public-key").To(t.publicKey).
		Doc("get PEM encoded public key").
		Writes([]byte{}).
		Returns(http.StatusOK, "OK", []byte{}).
		Returns(http.StatusInternalServerError, "Internal Server Error", nil))

	ws.Route(ws.POST("/refresh").To(t.refreshToken).
		Doc("get signed access token using refresh token").
		Writes(&refreshTokenResponse{}).
		Returns(http.StatusOK, "OK", &refreshTokenResponse{}).
		Returns(http.StatusForbidden, "Forbidden", nil).
		Returns(http.StatusInternalServerError, "Internal Server Error", nil))

	return ws
}
