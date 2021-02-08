package token

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/dfkdream/GoSSO/internal/signin"

	"github.com/emicklei/go-restful/v3"

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

func TestToken_WebService(t *testing.T) {
	ds := createTempDS()

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	h := restful.NewContainer()
	h.Add(signin.New(ds, pk, 1*time.Second).WebService())
	tk, err := New(ds, pk, 1*time.Second)
	if err != nil {
		t.Error(err)
	}

	c := restful.NewContainer()
	c.Add(tk.WebService())

	// Test GET /token/public-key
	{
		req := httptest.NewRequest("GET", "/token/public-key", nil)
		res := httptest.NewRecorder()

		c.ServeHTTP(res, req)

		if res.Code != 200 {
			t.Errorf("Expected OK but got %d", res.Code)
		}
	}

	// Register user && Generate refresh token
	var rTok string
	{
		data := url.Values{}
		data.Set("username", "hello")
		data.Add("password", "world")

		req := httptest.NewRequest("POST", "/signin", bytes.NewBufferString(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

		res := httptest.NewRecorder()

		h.ServeHTTP(res, req)

		rTok = res.Result().Cookies()[0].Value
	}

	// Get Access Token
	var aTok string
	{
		req := httptest.NewRequest("POST", "/token/refresh", nil)

		req.AddCookie(&http.Cookie{
			Name:  "token",
			Value: rTok,
		})
		res := httptest.NewRecorder()

		c.ServeHTTP(res, req)

		if res.Code != http.StatusOK {
			t.Errorf("Expected OK but got %d", res.Code)
		}

		resp := new(refreshTokenResponse)
		err := json.NewDecoder(res.Body).Decode(&resp)
		if err != nil {
			t.Error(err)
		}

		aTok = resp.Token
	}

	// Request access token using access token
	{
		req := httptest.NewRequest("POST", "/token/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "token",
			Value: aTok,
		})
		res := httptest.NewRecorder()

		c.ServeHTTP(res, req)

		if res.Code != http.StatusForbidden {
			t.Errorf("Expected Forbidden but got %d", res.Code)
		}
	}

	// Invalid Refresh Token Signature
	{
		req := httptest.NewRequest("POST", "/token/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "token",
			Value: rTok + "1",
		})
		res := httptest.NewRecorder()

		c.ServeHTTP(res, req)

		if res.Code != http.StatusForbidden {
			t.Errorf("Expected Forbidden but got %d", res.Code)
		}
	}

	// Expired Refresh Token
	{
		time.Sleep(time.Second) //Add sleep to expire token

		req := httptest.NewRequest("POST", "/token/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "token",
			Value: rTok,
		})
		res := httptest.NewRecorder()

		c.ServeHTTP(res, req)

		if res.Code != http.StatusForbidden {
			t.Errorf("Expected Forbidden but got %d", res.Code)
		}
	}

	// Request without token cookie
	{
		req := httptest.NewRequest("POST", "/token/refresh", nil)
		res := httptest.NewRecorder()

		c.ServeHTTP(res, req)

		if res.Code != http.StatusBadRequest {
			t.Errorf("Expected Bad Request but got %d", res.Code)
		}
	}
}
