package signin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/emicklei/go-restful/v3"

	"github.com/dgrijalva/jwt-go"

	"github.com/dfkdream/GoSSO/internal/auth"
)

func createTempDS() *auth.DataStore {
	testDir, err := ioutil.TempDir("", "datastore")
	//fmt.Println(testDir)
	if err != nil {
		log.Fatal(err)
	}
	d, err := auth.NewDataStore(filepath.Join(testDir, "test.db"))
	if err != nil {
		log.Fatal(err)
	}
	return d
}

func TestSignIn_WebService(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ds := createTempDS()

	h := restful.NewContainer()
	h.Add(New(ds, pk, time.Hour).WebService())

	// Scenario 01 : Initialize User
	{
		data := url.Values{}
		data.Set("username", "hello")
		data.Add("password", "world")

		req := httptest.NewRequest("POST", "/signin", bytes.NewBufferString(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		tok := res.Result().Cookies()[0].Value

		token, err := jwt.Parse(tok, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return pk.Public(), nil
		})

		if err != nil {
			t.Error(err)
		}

		if !token.Valid {
			t.Error("token not valid")
		}
	}

	// Scenario 02: Invalid Sign in attempt
	{
		data := url.Values{}
		data.Set("username", "halo")
		data.Add("password", "world")

		req := httptest.NewRequest("POST", "/signin", bytes.NewBufferString(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		if len(res.Result().Cookies()) > 0 {
			t.Errorf("Expected no cookie but got %+v", res.Result().Cookies())
		}
	}

	// Scenario 03 : Valid Sign in attempt
	{
		data := url.Values{}
		data.Set("username", "hello")
		data.Add("password", "world")

		req := httptest.NewRequest("POST", "/signin", bytes.NewBufferString(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		tok := res.Result().Cookies()[0].Value

		token, err := jwt.Parse(tok, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return pk.Public(), nil
		})

		if err != nil {
			t.Error(err)
		}

		if !token.Valid {
			t.Error("token not valid")
		}
	}
}
