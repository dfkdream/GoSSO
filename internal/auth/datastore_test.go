package auth

import (
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"testing"

	"github.com/asdine/storm/v3"

	"github.com/dfkdream/permission"

	"github.com/google/uuid"
)

func compareUser(u1, u2 User) bool {
	return fmt.Sprintf("%+v", u1) == fmt.Sprintf("%+v", u2)
}

func createTempDS() *DataStore {
	testDir, err := ioutil.TempDir("", "datastore")
	//fmt.Println(testDir)
	if err != nil {
		log.Fatal(err)
	}
	d, err := NewDataStore(filepath.Join(testDir, "test.db"))
	if err != nil {
		log.Fatal(err)
	}
	return d
}

func mustHashPassword(password string) Password {
	p, err := HashPassword(password)
	if err != nil {
		log.Fatal(err)
	}
	return p
}

func TestNewDataStore(t *testing.T) {
	createTempDS()
}

func TestDataStore_AddUser(t *testing.T) {
	ds := createTempDS()

	p, err := permission.FromString("+:sso")
	if err != nil {
		t.Error(err)
	}

	u1 := &User{
		ID:          uuid.New(),
		Username:    "hello",
		Password:    mustHashPassword("world"),
		Permissions: []permission.Permission{p},
	}

	err = ds.AddUser(u1)
	if err != nil {
		t.Error(err)
	}

	u1.Username = "hello-a"
	err = ds.AddUser(u1)
	if err == nil {
		t.Error("Expected ErrAlreadyExists error but got nil")
	}

	u1.ID = uuid.New()
	u1.Username = "hello"
	err = ds.AddUser(u1)
	if err != storm.ErrAlreadyExists {
		t.Error("Expected ErrAlreadyExists error but got nil")
	}
}

func TestDataStore_GetUserByID(t *testing.T) {
	ds := createTempDS()

	p, err := permission.FromString("+:sso")
	if err != nil {
		t.Error(err)
	}

	u1 := &User{
		ID:          uuid.New(),
		Username:    "hello",
		Password:    mustHashPassword("world"),
		Permissions: []permission.Permission{p},
	}

	err = ds.AddUser(u1)
	if err != nil {
		t.Error(err)
	}

	_, err = ds.GetUserByID(uuid.New())
	if err != storm.ErrNotFound {
		t.Error(err)
	}

	u, err := ds.GetUserByID(u1.ID)
	if err != nil {
		t.Error(err)
	}

	if !compareUser(*u1, *u) {
		t.Errorf("u1 (%+v) != u (%+v)", *u1, *u)
	}
}

func TestDataStore_GetUserByUsername(t *testing.T) {
	ds := createTempDS()

	p, err := permission.FromString("+:sso")
	if err != nil {
		t.Error(err)
	}

	u1 := &User{
		ID:          uuid.New(),
		Username:    "hello",
		Password:    mustHashPassword("world"),
		Permissions: []permission.Permission{p},
	}

	err = ds.AddUser(u1)
	if err != nil {
		t.Error(err)
	}

	_, err = ds.GetUserByUsername("hello-a")
	if err != storm.ErrNotFound {
		t.Error(err)
	}

	u, err := ds.GetUserByUsername(u1.Username)
	if err != nil {
		t.Error(err)
	}

	if !compareUser(*u1, *u) {
		t.Errorf("u1 (%+v) != u (%+v)", *u1, *u)
	}
}

func TestDataStore_UpdateUser(t *testing.T) {
	ds := createTempDS()

	p, err := permission.FromString("+:sso")
	if err != nil {
		t.Error(err)
	}

	u1 := &User{
		ID:          uuid.New(),
		Username:    "hello",
		Password:    mustHashPassword("world"),
		Permissions: []permission.Permission{p},
	}

	err = ds.AddUser(u1)
	if err != nil {
		t.Error(err)
	}

	u1.Username = "hola"
	err = ds.UpdateUser(u1)
	if err != nil {
		t.Error(err)
	}

	_, err = ds.GetUserByUsername("hello")
	if err != storm.ErrNotFound {
		t.Error(err)
	}

	u, err := ds.GetUserByID(u1.ID)
	if err != nil {
		t.Error(err)
	}

	if !compareUser(*u1, *u) {
		t.Errorf("u1 (%+v) != u (%+v)", *u1, *u)
	}
}

func TestDataStore_DeleteUser(t *testing.T) {
	ds := createTempDS()

	p, err := permission.FromString("+:sso")
	if err != nil {
		t.Error(err)
	}

	u1 := &User{
		ID:          uuid.New(),
		Username:    "hello",
		Password:    mustHashPassword("world"),
		Permissions: []permission.Permission{p},
	}

	err = ds.AddUser(u1)
	if err != nil {
		t.Error(err)
	}

	err = ds.DeleteUser(u1)
	if err != nil {
		t.Error(err)
	}

	_, err = ds.GetUserByID(u1.ID)
	if err != storm.ErrNotFound {
		t.Error(err)
	}
}

func TestDataStore_Size(t *testing.T) {
	ds := createTempDS()

	if s := ds.Size(); s != 0 {
		t.Errorf("Expected Size()==0 but got %d", s)
	}

	p, err := permission.FromString("+:sso")
	if err != nil {
		t.Error(err)
	}

	u1 := &User{
		ID:          uuid.New(),
		Username:    "hello",
		Password:    mustHashPassword("world"),
		Permissions: []permission.Permission{p},
	}

	err = ds.AddUser(u1)
	if err != nil {
		t.Error(err)
	}

	if s := ds.Size(); s != 1 {
		t.Errorf("Expected Size()==1 but got %d", s)
	}

	u1.ID = uuid.New()
	u1.Username = "hola"

	err = ds.AddUser(u1)
	if err != nil {
		t.Error(err)
	}

	if s := ds.Size(); s != 2 {
		t.Errorf("Expected Size()==2 but got %d", s)
	}
}
