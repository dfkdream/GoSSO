package auth

import (
	"github.com/dfkdream/permission"
	"github.com/google/uuid"
)

type User struct {
	ID          uuid.UUID               `storm:"unique" json:"id"`
	Username    string                  `storm:"unique" json:"username"`
	Password    Password                `json:"-"`
	Permissions []permission.Permission `json:"permissions"`
}
