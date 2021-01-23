package auth

import (
	"bytes"
	"testing"
)

func TestHashPassword(t *testing.T) {
	h1, err := HashPassword("HelloWorld")
	if err != nil {
		t.Error(err)
	}

	h2, err := HashPassword("HelloWorld")
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(h1.Hash, h2.Hash) {
		t.Errorf("expected h1.Hash!=h2.Hash but equals")
	}
}

func TestPassword_Validate(t *testing.T) {
	h, err := HashPassword("HelloWorld")
	if err != nil {
		t.Error(err)
	}

	if !h.Validate("HelloWorld") {
		t.Error("expected true but got false")
	}

	if h.Validate("WrongPassword") {
		t.Error("expected false but got true")
	}
}
