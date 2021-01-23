package auth

import (
	"bytes"
	"crypto/rand"

	"golang.org/x/crypto/scrypt"
)

type Password struct {
	Hash []byte
	Salt []byte
}

func HashPassword(password string) (Password, error) {
	salt := generateSalt(32)

	hash, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return Password{}, err
	}

	return Password{
		Hash: hash,
		Salt: salt,
	}, nil
}

func (p Password) Validate(password string) bool {
	hash, err := scrypt.Key([]byte(password), p.Salt, 32768, 8, 1, 32)
	if err != nil {
		return false
	}
	return bytes.Equal(hash, p.Hash)
}

func generateSalt(bytes int) []byte {
	buff := make([]byte, bytes)
	_, _ = rand.Read(buff)
	return buff
}
