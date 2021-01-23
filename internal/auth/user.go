package auth

import (
	"github.com/dfkdream/GoSSO/internal/auth/secondfactor"
	"github.com/dfkdream/permission"
	"github.com/google/uuid"
)

type User struct {
	ID            uuid.UUID                   `storm:"unique" json:"id"`
	Username      string                      `storm:"unique" json:"username"`
	Password      Password                    `json:"-"`
	SecondFactors []secondfactor.SecondFactor `json:"-"`
	Permissions   []permission.Permission     `json:"-"`
}
