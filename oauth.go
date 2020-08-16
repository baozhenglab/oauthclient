/*
 * @author          Viet Tran <viettranx@gmail.com>
 * @copyright       2019 Viet Tran <viettranx@gmail.com>
 * @license         Apache-2.0
 */

package oauthclient

import (
	"context"
	"flag"
	"fmt"
	"golang.org/x/oauth2/clientcredentials"
	"net/http"
)

type TrustedClient interface {
	PasswordCredentialsToken(username, password string) (*Token, error)
	Introspect(token string) (*TokenIntrospect, error)
	RefreshToken(refreshToken string) (*Token, error)
	FindUserById(uid string) (*OAuthUser, error)
	FindUser(filter *OAuthUserFilter) (*OAuthUser, error)
	CreateUser(user *OAuthUserCreate) (*Token, error)
	UpdateUser(uid string, update *OAuthUserUpdate) error
	CreateUserWithEmail(email string) (*Token, error)
	CreateUserWithFacebook(fbId, email string) (*Token, error)
	CreateUserWithAccountKit(akId, email, prefix, phone string) (*Token, error)
	ChangePassword(userId, oldPass, newPass string) error
	SetUsernamePassword(userId, username, password string) error
	DeleteUser(userId string) error
}

type oauth struct {
	name       string
	clientConf clientcredentials.Config
	client     *http.Client
}

func New(name string, clientConf clientcredentials.Config) *oauth {
	return &oauth{
		name:       name,
		clientConf: clientConf,
	}
}

func (o *oauth) Name() string {
	return o.name
}

func (o *oauth) InitFlags() {
	prefix := fmt.Sprintf("%s-", o.Name())
	flag.StringVar(&o.clientConf.ClientSecret, prefix+"client-secret", o.clientConf.ClientSecret, "oauth client secret")
	flag.StringVar(&o.clientConf.ClientID, prefix+"client-id", o.clientConf.ClientID, "oauth client id")
	flag.StringVar(&o.clientConf.TokenURL, prefix+"token-url", o.clientConf.TokenURL, "oauth token url")
}

func (o *oauth) Configure() error {
	if o.clientConf.TokenURL == "" {
		return nil
	}

	o.client = o.clientConf.Client(context.Background())
	return nil
}

func (o *oauth) Run() error {
	return o.Configure()
}

func (o *oauth) Stop() <-chan bool {
	c := make(chan bool)
	go func() { c <- true }()
	return c
}

func (o *oauth) GetPrefix() string {
	return o.name
}

func (o *oauth) Get() interface{} {
	return o
}
