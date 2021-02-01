package auth

import (
	"log"

	"github.com/asdine/storm/v3"
	"github.com/asdine/storm/v3/codec/gob"
	"github.com/google/uuid"
)

type DataStore struct {
	db *storm.DB
}

func NewDataStore(path string) (*DataStore, error) {
	db, err := storm.Open(path, storm.Codec(gob.Codec))
	if err != nil {
		return nil, err
	}

	return &DataStore{
		db: db,
	}, nil
}

func (d DataStore) Size() int {
	s, err := d.db.Count(&User{})
	if err != nil {
		log.Println(err)
		return -1
	}
	return s
}

func (d DataStore) AddUser(user *User) error {
	if _, err := d.GetUserByID(user.ID); err == nil {
		return storm.ErrAlreadyExists // prevent overriding
	}

	return d.db.Save(user)
}

func (d DataStore) UpdateUser(user *User) error {
	return d.db.Update(user)
}

func (d DataStore) DeleteUser(user *User) error {
	return d.db.DeleteStruct(user)
}

func (d DataStore) GetUserByID(id uuid.UUID) (*User, error) {
	user := new(User)
	err := d.db.One("ID", id, user)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (d DataStore) GetUserByUsername(username string) (*User, error) {
	user := new(User)
	err := d.db.One("Username", username, user)
	if err != nil {
		return nil, err
	}
	return user, nil
}
