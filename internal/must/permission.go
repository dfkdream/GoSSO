package must

import (
	"log"

	"github.com/dfkdream/permission"
)

func PermissionFromString(s string) permission.Permission {
	p, err := permission.FromString(s)
	if err != nil {
		log.Fatal(err)
	}
	return p
}
