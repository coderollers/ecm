package model

import (
	"crypto"
	"github.com/go-acme/lego/v4/registration"
)

type AcmeUser struct {
	registration.User

	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *AcmeUser) GetEmail() string {
	return u.Email
}

func (u *AcmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}
