/*
 * @author           Viet Tran <viettranx@gmail.com>
 * @copyright        2019 Viet Tran <viettranx@gmail.com>
 * @license          Apache-2.0
 */

package oauthclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/baozhenglab/sdkcm"
	"github.com/parnurzeal/gorequest"
)

// Return Token object when login with username and password
func (o *oauth) PasswordCredentialsToken(username, password string) (*Token, error) {
	var t TokenResponse

	res, body, _ := gorequest.New().Post(o.clientConf.TokenURL).
		SetBasicAuth(o.clientConf.ClientID, o.clientConf.ClientSecret).
		SendString(url.Values{
			"grant_type": {"password"},
			"username":   {username},
			"password":   {password},
			"scope":      o.clientConf.Scopes,
		}.Encode()).End()

	if err := json.Unmarshal([]byte(body), &t); err != nil {
		return nil, sdkcm.ErrInvalidRequest(err)
	}

	if res.StatusCode != 200 {
		return nil, sdkcm.NewAppErr(errors.New(t.Error), res.StatusCode, t.Error).WithCode("wrong_username_password")
	}

	t.Token.HasUsernamePassword = true
	t.Token.IsNew = false

	return t.Token, nil
}

// Introspect return access token, refresh token, expired time and its data
func (o *oauth) Introspect(token string) (*TokenIntrospect, error) {
	var ti TokenIntrospect

	out, err := o.call(
		strings.Replace(o.clientConf.TokenURL, "token", "introspect", -1),
		url.Values{"token": []string{token}, "scope": []string{}},
	)

	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(out, &ti); err != nil {
		return nil, err
	}

	return &ti, nil
}

func (o *oauth) FindUserById(uid string) (*OAuthUser, error) {
	out, err := o.call(strings.Replace(
		o.clientConf.TokenURL,
		"token",
		fmt.Sprintf("users/%s", uid),
		-1,
	), nil)

	if err != nil {
		return nil, err
	}

	var user OAuthUser
	if err := json.Unmarshal(out, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (o *oauth) FindUser(filter *OAuthUserFilter) (*OAuthUser, error) {
	payload := url.Values{}

	if v := filter.Username; v != nil {
		payload.Add("username", *v)
	}

	if v := filter.Email; v != nil {
		payload.Add("email", *v)
	}

	if v := filter.FBId; v != nil {
		payload.Add("fb_id", *v)
	}

	if v := filter.Phone; v != nil {
		payload.Add("phone", *v)
	}

	if v := filter.PhonePrefix; v != nil {
		payload.Add("phone_prefix", *v)
	}

	out, err := o.call(strings.Replace(
		o.clientConf.TokenURL,
		"token",
		fmt.Sprintf("find-user"),
		-1,
	), payload)

	if err != nil {
		return nil, err
	}

	data := struct {
		Code int       `json:"code"`
		User OAuthUser `json:"data"`
	}{}

	if err := json.Unmarshal(out, &data); err != nil {
		return nil, err
	}

	return &data.User, nil
}

func (o *oauth) CreateUser(user *OAuthUserCreate) (*Token, error) {
	var t Token

	payload := url.Values{}
	if user.Username != nil {
		payload.Add("username", *user.Username)
	}

	if user.Password != nil {
		payload.Add("password", *user.Password)
	}

	if user.Email != nil {
		payload.Add("email", *user.Email)
	}

	if user.PhonePrefix != nil {
		payload.Add("phone_prefix", *user.PhonePrefix)
	}

	if user.Phone != nil {
		payload.Add("phone", *user.Phone)
	}

	if user.ClientId != nil {
		payload.Add("client_id", *user.ClientId)
	}

	out, err := o.call(strings.Replace(
		o.clientConf.TokenURL,
		"token",
		"users",
		-1,
	), payload)

	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(out, &t); err != nil {
		return nil, err
	}

	return &t, nil
}

func (o *oauth) CreateUserWithEmail(email string) (*Token, error) {
	var t Token

	out, err := o.call(strings.Replace(
		o.clientConf.TokenURL,
		"token",
		"users?type=gmail",
		-1,
	), url.Values{
		"email": []string{email},
	})

	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(out, &t); err != nil {
		return nil, err
	}

	return &t, nil
}

func (o *oauth) CreateUserWithFacebook(fbId, email string) (*Token, error) {
	var t Token

	out, err := o.call(strings.Replace(
		o.clientConf.TokenURL,
		"token",
		"users?type=facebook",
		-1,
	), url.Values{
		"fb_id": []string{fbId},
		"email": []string{email},
	})

	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(out, &t); err != nil {
		return nil, err
	}

	return &t, nil
}

func (o *oauth) CreateUserWithAccountKit(akId, email, prefix, phone string) (*Token, error) {
	var t Token

	out, err := o.call(strings.Replace(
		o.clientConf.TokenURL,
		"token",
		"users?type=account-kit",
		-1,
	), url.Values{
		"ak_id":        []string{akId},
		"email":        []string{email},
		"phone_prefix": []string{prefix},
		"phone":        []string{phone},
	})

	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(out, &t); err != nil {
		return nil, err
	}

	return &t, nil
}

func (o *oauth) UpdateUser(uid string, update *OAuthUserUpdate) error {
	payload := url.Values{
		"user_id": {uid},
	}

	if update.Username != nil {
		payload.Add("username", *update.Username)
	}
	if update.FirstName != nil {
		payload.Add("first_name", *update.FirstName)
	}
	if update.LastName != nil {
		payload.Add("last_name", *update.LastName)
	}
	if update.Gender != nil {
		payload.Add("gender", string(*update.Gender))
	}
	if update.Address != nil {
		payload.Add("address", *update.Address)
	}
	if update.Password != nil {
		payload.Add("password", *update.Password)
	}
	if update.Email != nil {
		payload.Add("email", *update.Email)
	}
	if update.PhonePrefix != nil {
		payload.Add("phone_prefix", *update.PhonePrefix)
	}
	if update.Phone != nil {
		payload.Add("phone", *update.Phone)
	}
	if update.Password != nil {
		payload.Add("password", *update.Password)
	}
	if update.PasswordConfirmation != nil {
		payload.Add("password_confirmation", string(*update.PasswordConfirmation))
	}
	if update.DobString != nil {
		payload.Add("dob", *update.DobString)
	}
	if update.FBId != nil {
		payload.Add("fb_id", *update.FBId)
	}
	if update.AKId != nil {
		payload.Add("ak_id", *update.AKId)
	}
	if update.AccountType != nil {
		payload.Add("account_type", string(*update.AccountType))
	}

	_, err := o.call(strings.Replace(
		o.clientConf.TokenURL,
		"token",
		fmt.Sprintf("users/%s/update", uid),
		-1,
	), payload)

	if err != nil {
		return err
	}

	return nil
}

func (o *oauth) ChangePassword(userId, oldPass, newPass string) error {
	_, err := o.call(strings.Replace(
		o.clientConf.TokenURL,
		"token",
		fmt.Sprintf("users/%s/change-password", userId),
		-1,
	), url.Values{
		"old_password": []string{oldPass},
		"new_password": []string{newPass},
	})

	if err != nil {
		return err
	}

	return nil
}

func (o *oauth) SetUsernamePassword(userId, username, password string) error {
	_, err := o.call(strings.Replace(
		o.clientConf.TokenURL,
		"token",
		fmt.Sprintf("users/%s/set-username-password", userId),
		-1,
	), url.Values{
		"username": []string{username},
		"password": []string{password},
	})

	if err != nil {
		return err
	}

	return nil
}

func (o *oauth) RevokeToken(token string) error {
	return nil
}

func (o *oauth) RefreshToken(refreshToken string) (*Token, error) {
	var t TokenResponse

	res, body, _ := gorequest.New().Post(o.clientConf.TokenURL).
		SetBasicAuth(o.clientConf.ClientID, o.clientConf.ClientSecret).
		SendString(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"scope":         o.clientConf.Scopes,
		}.Encode()).End()

	if err := json.Unmarshal([]byte(body), &t); err != nil {
		return nil, sdkcm.ErrInvalidRequest(err)
	}

	if res.StatusCode != 200 {
		return nil, sdkcm.NewAppErr(errors.New(t.Error), res.StatusCode, t.Error)
	}

	return t.Token, nil
}

func (o *oauth) DeleteUser(userId string) error {
	_, err := o.call(strings.Replace(
		o.clientConf.TokenURL,
		"token",
		fmt.Sprintf("users/%s", userId),
		-1,
	), url.Values{})

	if err != nil {
		return err
	}

	return nil
}

func (o *oauth) GetUser(userId string) error {
	_, err := o.call(strings.Replace(
		o.clientConf.TokenURL,
		"token",
		fmt.Sprintf("users/%s", userId),
		-1,
	), url.Values{})

	if err != nil {
		return err
	}

	return nil
}

func (o *oauth) call(url string, params url.Values) ([]byte, error) {
	resp, err := o.client.PostForm(url, params)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	out, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode >= 300 {
		var appErr sdkcm.AppError
		if err := json.Unmarshal(out, &appErr); err != nil {
			return nil, err
		}

		return nil, appErr
	}

	return out, nil
}
