package vaultclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	vaultAPI "github.com/hashicorp/vault/api"
)

type Config struct {
	Addr        string
	MaxRetries  int
	CACertFile  string
	ClientCert  string
	ClientKey   string
	ReceivePort int
	RoleID      string
}

type Client struct {
	cfg     Config
	logger  *log.Logger
	vclient *vaultAPI.Client
	renewer *vaultAPI.Renewer
	httpSrv *http.Server
}

// New creates a new client instance
func New(cfg Config, logger *log.Logger) (*Client, error) {
	var c Client
	c.cfg = cfg
	c.logger = logger
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
	if err != nil {
		return &c, err
	}
	c.vclient.SetWrappingLookupFunc(wrappingLookupFunc)
	return &c, err
}

func (c *Client) WaitForSecretID() error {
	if c.httpSrv != nil {
		err := c.httpSrv.Close()
		if err != nil {
			return fmt.Errorf("could not close existing listener")
		}
	}
	c.httpSrv = &http.Server{Addr: ":" + strconv.Itoa(c.cfg.ReceivePort), Handler: c.secretIDHandlerFunc()}
	c.logger.Printf("waiting for secret_id on port %d\n", c.cfg.ReceivePort)
	err := c.httpSrv.ListenAndServeTLS(c.cfg.ClientCert, c.cfg.ClientKey)
	if err != nil && err != http.ErrServerClosed {
		err = fmt.Errorf("error listening for secret_id: %v", err)
		c.logger.Printf("%v\n", err)
		return err
	}
	return nil
}

// Login performs and AppRole login to the roleID provided. The secretID may be provided wrapped.
func (c *Client) Login(secretID string) error {
	path := fmt.Sprintf("auth/approle/role/%s/secret-id", c.cfg.RoleID)
	if wrappingLookupFunc("PUT", path) != "" {
		// secretID should be wrapped. lookup to check if it has already been unwrapped or has expired.
		r, err := c.vclient.Logical().Write("sys/wrapping/lookup", map[string]interface{}{
			"token": secretID,
		})
		if err != nil {
			err = fmt.Errorf("potential intercept of wrapped secret_id, investigation required: %v", err)
			c.logger.Println(err.Error())
			return err
		}
		if r == nil || r.Data == nil {
			return errors.New("wrapped secret ID is not valid")
		}

		// unwrap the secretID
		s, err := c.vclient.Logical().Unwrap(secretID)
		if err != nil {
			return err
		}
		sid, ok := s.Data["secret_id"].(string)
		if !ok {
			return errors.New("could not get secret_id from unwrap response")
		}
		secretID = sid
	}
	if secretID == "" {
		return errors.New("secret_id is blank")
	}
	// perform login to get clientToken
	r, err := c.vclient.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   c.cfg.RoleID,
		"secret_id": secretID,
	})
	if err != nil {
		return err
	}
	// set the clientToken
	c.vclient.SetToken(r.Auth.ClientToken)
	c.logger.Println("login succeeded")
	if r.Auth.Renewable {
		c.logger.Println("login token will be automatically renewed")
		err = c.renewal(r)
		if err != nil {
			return fmt.Errorf("could not create renewer")
		}
	}
	if c.httpSrv != nil {
		// close the listener as it is no longer needed.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err = c.httpSrv.Shutdown(ctx)
		if err != nil {
			c.logger.Printf("error closing secret_id listener: %v\n", err)
			return fmt.Errorf("could not close secret_id listener")
		}
	}
	return nil
}

// Logout stops any further token renewals and clears the token from the client
func (c *Client) Logout() {
	if c.renewer != nil {
		c.renewer.Stop()
	}
	c.vclient.ClearToken()
	c.logger.Println("logged out")
}

// renewal starts a thread to manage the renewal of the client's token
func (c *Client) renewal(s *vaultAPI.Secret) error {
	renewer, err := c.vclient.NewRenewer(&vaultAPI.RenewerInput{
		Secret: s,
	})
	if err != nil {
		return err
	}
	c.renewer = renewer
	go c.renewer.Renew()

	go func() {
		for {
			select {
			case err := <-c.renewer.DoneCh():
				if err != nil {
					c.logger.Printf("could not renew vault token: %v\n", err)
					c.logger.Printf("listening for new secret_id on port %d", c.cfg.ReceivePort)
					err = c.WaitForSecretID()
					if err != nil {
						c.logger.Printf("error waiting for new secret_id: %v", err)
					}
				}
			case renewal := <-c.renewer.RenewCh():
				c.logger.Printf("vault token renewed at %v, valid until %v\n", renewal.RenewedAt,
					renewal.RenewedAt.Add(time.Duration(renewal.Secret.LeaseDuration)*time.Second))
			}
		}
	}()
	return nil
}

// SecretID requests a secret_id for the role. The secret_id returned can be used to login to the role.
// The secret_id may be wrapped.
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
	sid, ok := r.Data["secret_id"].(string)
	if !ok {
		return "", errors.New("could not get secret_id from response")
	}
	return sid, nil
}

// wrappingLookupFunc indicates whether a request should be returned wrapped
func wrappingLookupFunc(operation, path string) string {
	if strings.HasPrefix(path, "auth/approle/role") && strings.HasSuffix(path, "secret-id") {
		return vaultAPI.DefaultWrappingTTL
	}
	return ""
}

// CreateSecret creates a brand new secret entry in a KV v2 store: https://www.vaultproject.io/api/secret/kv/kv-v2.html
func (c *Client) CreateSecret(location string, data map[string]string) error {
	path := fmt.Sprintf("secret/data/%s", location)
	_, err := c.vclient.Logical().Write(path, map[string]interface{}{
		"options": map[string]int{
			"cas": 0,
		},
		"data": data,
	})
	if err != nil {
		return err
	}
	return nil
}

// OverwriteSecret replaces the value of a secret in a KV v2 store
func (c *Client) OverwriteSecret(location string, data map[string]string) error {
	path := fmt.Sprintf("secret/data/%s", location)
	s, err := c.ReadSecret(location, 0)
	// TODO revert when fixed: https://github.com/hashicorp/vault/issues/5680
	//md, err := s.TokenMetadata()
	md, err := tokenMetadata(s)
	if err != nil {
		return err
	}

	v, err := strconv.Atoi(md["version"])
	if err != nil {
		return err
	}
	_, err = c.vclient.Logical().Write(path, map[string]interface{}{
		"options": map[string]int{
			"cas": v,
		},
		"data": data,
	})
	if err != nil {
		return err
	}
	return nil
}

func tokenMetadata(s *vaultAPI.Secret) (map[string]string, error) {
	if s == nil {
		return nil, nil
	}

	if s.Auth != nil && len(s.Auth.Metadata) > 0 {
		return s.Auth.Metadata, nil
	}

	if s.Data == nil || (s.Data["metadata"] == nil && s.Data["meta"] == nil) {
		return nil, nil
	}

	data, ok := s.Data["metadata"].(map[string]interface{})
	if !ok {
		data, ok = s.Data["meta"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("unable to convert metadata field to expected format")
		}
	}

	metadata := make(map[string]string, len(data))
	for k, v := range data {
		switch typed := v.(type) {
		case int:
			metadata[k] = strconv.Itoa(typed)
		case json.Number:
			metadata[k] = typed.String()
		case bool:
			metadata[k] = strconv.FormatBool(typed)
		case string:
			metadata[k] = typed
		default:
			return nil, fmt.Errorf("unable to convert metadata value %v (%T) to string", v, v)
		}
	}

	return metadata, nil
}

// ReadSecret returns the secret at the defined location.
// A version of 0 will always return the latest version.
func (c *Client) ReadSecret(location string, version int) (*vaultAPI.Secret, error) {
	path := fmt.Sprintf("secret/data/%s", location)
	vstr := strconv.Itoa(version)
	return c.vclient.Logical().ReadWithData(path, map[string][]string{
		"version": {vstr},
	})
}

func (c *Client) secretIDHandlerFunc() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.logger.Printf("secret_id post received from %s\n", r.RemoteAddr)
		w = setHeaders(w)
		if r.Method != http.MethodPost {
			c.logger.Println("method of providing secret_id was not a POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		secretID, err := secretIDFromPost(r)
		if err != nil {
			c.logger.Printf("malformed secret_id post: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		go func() {
			err = c.Login(secretID)
			if err != nil {
				c.logger.Printf("client login error with secret_id provided: %v\n", err)
			}
		}()
		return
	})
}

func setHeaders(w http.ResponseWriter) http.ResponseWriter {
	w.Header().Set("Cache-Control", "no-store")
	//OWASP recommended headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "deny")
	return w
}

func secretIDFromPost(r *http.Request) (string, error) {
	reader := io.LimitReader(r.Body, 1024)
	defer r.Body.Close()
	dec := json.NewDecoder(reader)
	s := new(secretIDInput)
	err := dec.Decode(s)
	if err != nil {
		return "", fmt.Errorf("could not parse posted secret_id")
	}
	return s.SecretID, nil
}

type secretIDInput struct {
	SecretID string `json:"secret_id"`
}
