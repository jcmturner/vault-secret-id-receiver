package vault_secret_id_receiver

import (
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

func NewClient(cfg Config) (c *Client, err error) {
	err = c.client(cfg)
	return
}

func (c *Client) client(cfg Config) (err error) {
	conf := vaultAPI.DefaultConfig()
	conf.Address = cfg.Addr
	conf.MaxRetries = cfg.MaxRetries
	t := &vaultAPI.TLSConfig{
		CACert:     cfg.CACertFile,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
	}
	err = conf.ConfigureTLS(t)
	if err != nil {
		return
	}
	err = conf.ReadEnvironment()
	if err != nil {
		return
	}
	v, err := vaultAPI.NewClient(conf)
	if err != nil {
		return
	}
	c.vclient = v
	return
}

func (c *Client) Unwrap(t string) (*vaultAPI.Secret, error) {
	return c.vclient.Logical().Unwrap(t)
}
