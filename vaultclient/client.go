package vaultclient

import (
	"errors"
	"fmt"
	"os"
	"strings"

	vaultAPI "github.com/hashicorp/vault/api"
)

type Config struct {
	Addr       string
	MaxRetries int
	CACertFile string
	ClientCert string
	ClientKey  string
}

type Client struct {
	cfg     Config
	vclient *vaultAPI.Client
}

func NewClient(cfg Config) (*Client, error) {
	var c Client
	c.cfg = cfg
	conf := vaultAPI.DefaultConfig()
	conf.Address = cfg.Addr
	conf.MaxRetries = cfg.MaxRetries
	t := &vaultAPI.TLSConfig{
		CACert:     cfg.CACertFile,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
	}
	err := conf.ConfigureTLS(t)
	if err != nil {
		return &c, err
	}
	err = conf.ReadEnvironment()
	if err != nil {
		return &c, err
	}
	c.vclient, err = vaultAPI.NewClient(conf)
	c.vclient.SetWrappingLookupFunc(wrappingLookupFunc)
	return &c, err
}

func (c *Client) Login(roleID, secretID string) error {
	path := fmt.Sprintf("auth/approle/role/%s/secret-id", roleID)
	if wrappingLookupFunc("PUT", path) != "" {
		r, err := c.vclient.Logical().Write("sys/wrapping/lookup", map[string]interface{}{
			"token": secretID,
		})
		if err != nil {
			return err
		}
		if r == nil || r.Data == nil {
			return errors.New("wrapped secret ID is not valid")
		}

		s, err := c.vclient.Logical().Unwrap(secretID)
		if err != nil {
			return err
		}
		secretID = s.Data["secret_id"].(string)
	}
	r, err := c.vclient.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return err
	}
	c.vclient.SetToken(r.Auth.ClientToken)
	return nil
}

func (c *Client) SecretID(roleID, token string) (string, error) {
	path := fmt.Sprintf("auth/approle/role/%s/secret-id", roleID)
	ot := c.vclient.Token()
	c.vclient.SetToken(token)
	r, err := c.vclient.Logical().Write(path, nil)
	c.vclient.SetToken(ot)
	if err != nil {
		return "", err
	}
	if r.WrapInfo != nil {
		return r.WrapInfo.Token, nil
	}
	return r.Data["secret_id"].(string), nil
}

func wrappingLookupFunc(operation, path string) string {
	if strings.HasPrefix(path, "auth/approle/role") && strings.HasSuffix(path, "secret-id") {
		return vaultAPI.DefaultWrappingTTL
	}
	return ""
}

func (c *Client) WriteSecret(location, key, value string) error {
	path := fmt.Sprintf("secert/%s", location)
	r, err := c.vclient.Logical().Write(path, map[string]interface{}{
		key: value,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%+v\n", r)
	return nil
}
