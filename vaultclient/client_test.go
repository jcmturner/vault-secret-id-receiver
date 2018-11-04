package vaultclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/jcmturner/vault-secret-id-receiver/test"
	"github.com/stretchr/testify/assert"
)

func TestClient_SecretIDListener(t *testing.T) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		t.Skip("VAULT_ADDR not set, skipping client login test")
	}
	roleID := os.Getenv("VAULT_ROLEID")
	cert, key, certPEM, _ := test.GenerateSelfSignedTLSKeyPairFiles(t)
	defer os.Remove(cert)
	defer os.Remove(key)
	l := log.New(os.Stderr, "Vault Client: ", log.Ldate|log.Ltime|log.Lshortfile)
	cfg := Config{
		Addr:        vaultAddr,
		RoleID:      roleID,
		ReceivePort: 8201,
		ClientCert:  cert,
		ClientKey:   key,
	}
	c, err := New(cfg, l)
	if err != nil {
		t.Fatalf("could not create client: %v", err)
	}
	secretID, err := c.SecretID("my-role", "root_token")
	if err != nil {
		t.Fatalf("could not get wrapped secretID: %v", err)
	}

	// Simulate external party posting the secretID
	go func() {
		// Wait 5 seconds for the client to start listening for the SecretID
		time.Sleep(time.Second * 2)
		payload := fmt.Sprintf(`{ "secret_id": "%s" }`, secretID)
		req, err := http.NewRequest(http.MethodPost, "https://127.0.0.1:8201/", strings.NewReader(payload))
		if err != nil {
			t.Fatalf("error building request: %v", err)
		}

		client := &http.Client{}
		cp := x509.NewCertPool()
		cp.AppendCertsFromPEM(certPEM)
		tlsConfig := &tls.Config{RootCAs: cp}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client.Transport = transport

		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("could not post secret_id: %v", err)
		}
		assert.Equal(t, http.StatusAccepted, resp.StatusCode, "post of secret_id was not successful")
	}()
	// This call blocks until the SecretID has been posted and login has succeeded
	err = c.WaitForSecretID()
	putGetSecrets(t, c)
}

func TestClient_Login(t *testing.T) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		t.Skip("VAULT_ADDR not set, skipping client login test")
	}
	roleID := os.Getenv("VAULT_ROLEID")
	l := log.New(os.Stderr, "Vault Client: ", log.Ldate|log.Ltime|log.Lshortfile)
	cfg := Config{
		Addr:   vaultAddr,
		RoleID: roleID,
	}
	c, err := New(cfg, l)
	if err != nil {
		t.Fatalf("could not create client: %v", err)
	}
	secretID, err := c.SecretID("my-role", "root_token")
	if err != nil {
		t.Fatalf("could not get wrapped secretID: %v", err)
	}
	err = c.Login(secretID)
	if err != nil {
		t.Fatalf("could not login client: %v", err)
	}
	c.Logout()
}

func TestClient_CreateReadUpdateSecret(t *testing.T) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		t.Skip("VAULT_ADDR not set, skipping client login test")
	}
	roleID := os.Getenv("VAULT_ROLEID")
	l := log.New(os.Stderr, "Vault Client: ", log.Ldate|log.Ltime|log.Lshortfile)
	cfg := Config{
		Addr:   vaultAddr,
		RoleID: roleID,
	}
	c, err := New(cfg, l)
	if err != nil {
		t.Fatalf("could not create client: %v", err)
	}
	secretID, err := c.SecretID("my-role", "root_token")
	if err != nil {
		t.Fatalf("could not get wrapped secretID: %v", err)
	}
	err = c.Login(secretID)
	if err != nil {
		t.Fatalf("could not login client: %v", err)
	}

	putGetSecrets(t, c)
}

func putGetSecrets(t *testing.T, c *Client) {
	location, _ := uuid.GenerateUUID()
	err := c.CreateSecret(location, map[string]string{
		"one": "helloone",
		"two": "hellotwo",
	})
	if err != nil {
		t.Fatalf("failed to create new secret: %v", err)
	}
	s, err := c.ReadSecret(location, 0)
	if err != nil {
		t.Fatalf("failed to read secret: %v", err)
	}
	one := s.Data["data"].(map[string]interface{})["one"].(string)
	two := s.Data["data"].(map[string]interface{})["two"].(string)
	if one != "helloone" || two != "hellotwo" {
		t.Errorf("secret values incorrect")
	}
	err = c.OverwriteSecret(location, map[string]string{
		"one": "thereone",
	})
	if err != nil {
		t.Fatalf("failed to update secret: %v", err)
	}
	s, err = c.ReadSecret(location, 0)
	if err != nil {
		t.Fatalf("failed to read updated secret: %v", err)
	}
	one = s.Data["data"].(map[string]interface{})["one"].(string)
	if one != "thereone" {
		t.Fatalf("updated secret not as expected")
	}
}
