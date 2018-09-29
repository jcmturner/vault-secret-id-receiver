package vaultclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jcmturner/restclient"
)

const (
	AppRoleLoginPath = "/v1/auth/approle/login"
)

type Session struct {
	mux           sync.RWMutex
	credentials   AppRoleCredentials
	loginResponse AppRoleLoginResponse
	validUntil    time.Time
}

type AppRoleCredentials struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}

type AppRoleLoginResponse struct {
	Auth struct {
		Renewable     bool            `json:"renewable"`
		LeaseDuration int             `json:"lease_duration"`
		Metadata      json.RawMessage `json:"metadata"`
		Policies      []string        `json:"policies"`
		Accessor      string          `json:"accessor"`
		ClientToken   string          `json:"client_token"`
	} `json:"auth"`
	Warnings      json.RawMessage `json:"warnings"`
	WrapInfo      json.RawMessage `json:"wrap_info"`
	Data          json.RawMessage `json:"data"`
	LeaseDuration int             `json:"lease_duration"`
	Renewable     bool            `json:"renewable"`
	LeaseID       string          `json:"lease_id"`
}

func Login(roleID, wrappedSecretID string) (*Session, error) {

}

func (s *Session) NewRequest(c *restclient.Config, a, u string) (err error) {
	d := fmt.Sprintf(`
			{
				"app_id": "%s",
				"user_id": "%s"
			}`, a, u)
	o := restclient.NewPostOperation().WithPath("/v1/auth/app-id/login").WithResponseTarget(s).WithBodyDataString(d)
	req, err := restclient.BuildRequest(c, o)
	s.request = req
	return
}

func (s *Session) process() (err error) {
	httpCode, err := restclient.Send(s.request)
	if err != nil {
		return
	}
	if *httpCode != http.StatusOK {
		err = fmt.Errorf("Did not get an HTTP 200 code on login, got %v with message: %v", *httpCode, s.Errors)
	}
	if s.loginResponse.Auth.LeaseDuration > 0 {
		s.validUntil = time.Now().Add(time.Duration(s.loginResponse.Auth.LeaseDuration) * time.Second)
	}
	return
}

func (s *Session) GetToken() (token string, err error) {
	// If token no longer valid re-request it first. A zero value for ValidUntil means it never expires
	if !s.validUntil.IsZero() && time.Now().After(s.validUntil) {
		err = s.process()
		if err != nil {
			return
		}
	}
	//First time login
	if s.Auth.ClientToken == "" {
		err = s.process()
		if err != nil {
			return
		}
	}
	token = s.Auth.ClientToken
	if token == "" {
		err = errors.New("Vault client token is blank")
	}
	return
}
