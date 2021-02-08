package user

import (
	"net/http"

	"github.com/asdine/storm/v3"
	"github.com/dfkdream/GoSSO/internal/auth"
	"github.com/dfkdream/permission"
	"github.com/emicklei/go-restful/v3"
	"github.com/google/uuid"
)

type User struct {
	ds *auth.DataStore
}

type userInfo struct {
	Username    string                  `json:"username"`
	Password    string                  `json:"password"`
	Permissions []permission.Permission `json:"permissions"`
}

func New(dataStore *auth.DataStore) *User {
	return &User{
		ds: dataStore,
	}
}

func (u User) getUsers(_ *restful.Request, res *restful.Response) {
	users, err := u.ds.GetAllUsers()
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}

	err = res.WriteEntity(users)
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}
}

func (u User) getUser(req *restful.Request, res *restful.Response) {
	uid, err := uuid.Parse(req.PathParameter("userUUID"))
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}

	usr, err := u.ds.GetUserByID(uid)
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}

	err = res.WriteEntity(usr)
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}
}

func (u User) addUser(req *restful.Request, res *restful.Response) {
	uData := new(userInfo)
	err := req.ReadEntity(uData)
	if err != nil {
		_ = res.WriteError(http.StatusBadRequest, err)
		return
	}

	if uData.Username == "" || uData.Password == "" {
		_ = res.WriteErrorString(http.StatusBadRequest, "Insufficient request parameters")
	}

	hp, err := auth.HashPassword(uData.Password)
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}

	usr := &auth.User{
		ID:          uuid.New(),
		Username:    uData.Username,
		Password:    hp,
		Permissions: uData.Permissions,
	}

	err = u.ds.AddUser(usr)
	if err != nil {
		if err == storm.ErrAlreadyExists {
			_ = res.WriteErrorString(http.StatusConflict, "Username already exists")
			return
		}

		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}

	err = res.WriteEntity(usr.ID)
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}
}

func (u User) deleteUser(req *restful.Request, res *restful.Response) {
	uid, err := uuid.Parse(req.PathParameter("userUUID"))
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}

	err = u.ds.DeleteUser(&auth.User{
		ID: uid,
	})

	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}
}

func (u User) updateUserCredentials(req *restful.Request, res *restful.Response) {
	uData := new(userInfo)
	err := req.ReadEntity(uData)
	if err != nil {
		_ = res.WriteError(http.StatusBadRequest, err)
		return
	}

	uid, err := uuid.Parse(req.PathParameter("userUUID"))
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}

	usr, err := u.ds.GetUserByID(uid)
	if err != nil {
		_ = res.WriteError(http.StatusNotFound, err)
		return
	}

	if uData.Username != "" {
		usr.Username = uData.Username
	}

	if uData.Password != "" {
		p, err := auth.HashPassword(uData.Password)
		if err != nil {
			_ = res.WriteError(http.StatusInternalServerError, err)
			return
		}

		usr.Password = p
	}

	err = u.ds.UpdateUser(usr)
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}
}

func (u User) updateUserPerms(req *restful.Request, res *restful.Response) {
	perm := make([]permission.Permission, 0)
	err := req.ReadEntity(&perm)
	if err != nil {
		_ = res.WriteError(http.StatusBadRequest, err)
		return
	}

	uid, err := uuid.Parse(req.PathParameter("userUUID"))
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}

	usr, err := u.ds.GetUserByID(uid)
	if err != nil {
		_ = res.WriteError(http.StatusNotFound, err)
		return
	}

	usr.Permissions = perm

	err = u.ds.UpdateUser(usr)
	if err != nil {
		_ = res.WriteError(http.StatusInternalServerError, err)
		return
	}

}

func (u User) WebService() *restful.WebService {
	ws := new(restful.WebService)

	ws.
		Path("/user").
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)

	ws.Route(ws.GET("/").To(u.getUsers).
		Doc("Get all users").
		Writes(&[]auth.User{}))

	ws.Route(ws.POST("/").To(u.addUser).
		Doc("Create new user").
		Reads(&userInfo{}).
		Writes(&uuid.UUID{}))

	ws.Route(ws.GET("/{userUUID}").To(u.getUser).
		Doc("Get user info with provided UUID").
		Writes(&auth.User{}))

	ws.Route(ws.DELETE("/{userUUID}").To(u.deleteUser).
		Doc("Delete user with provided UUID"))

	ws.Route(ws.POST("/{userUUID}/credential").To(u.updateUserCredentials).
		Doc("Update user credentials").
		Reads(&userInfo{}, "permissions field not used"))

	ws.Route(ws.POST("/{userUUID}/permissions").To(u.updateUserPerms).
		Doc("Update user permissions").
		Reads([]permission.Permission{}))

	return ws
}
