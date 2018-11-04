package vaultclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/assert"
)

func TestClient_SecretIDListener(t *testing.T) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		t.Skip("VAULT_ADDR not set, skipping client login test")
	}
	cert, key, certPEM, _ := GenerateSelfSignedTLSKeyPairFiles(t)
	defer os.Remove(cert)
	defer os.Remove(key)
	l := log.New(os.Stderr, "Vault Client: ", log.Ldate|log.Ltime|log.Lshortfile)
	cfg := Config{
		Addr:        vaultAddr,
		RoleID:      "40af949a-f5d4-cb0c-2ea1-a98efc0ac1ce",
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
	l := log.New(os.Stderr, "Vault Client: ", log.Ldate|log.Ltime|log.Lshortfile)
	cfg := Config{
		Addr:   vaultAddr,
		RoleID: "40af949a-f5d4-cb0c-2ea1-a98efc0ac1ce",
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
	t.Log(c.vclient.Token())

	c.Logout()
}

func putGetSecrets(t *testing.T, c *Client) {
	location, _ := uuid.GenerateUUID()
	err := c.CreateSecret(location, map[string]string{
		"one": "hello",
		"two": "hello",
	})
	if err != nil {
		t.Fatalf("failed to create new secret: %v", err)
	}
	_, err = c.ReadSecret(location, 0)
	if err != nil {
		t.Fatalf("failed to read secret: %v", err)
	}
	err = c.OverwriteSecret(location, map[string]string{
		"one": "there",
	})
	if err != nil {
		t.Fatalf("failed to update secret: %v", err)
	}
	_, err = c.ReadSecret(location, 0)
	if err != nil {
		t.Fatalf("failed to read updated secret: %v", err)
	}
}

func GenerateSelfSignedTLSKeyPairFiles(t *testing.T) (string, string, []byte, *rsa.PrivateKey) {
	derBytes, priv := GenerateSelfSignedTLSKeyPairData(t)
	pemCertBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	certOut, _ := ioutil.TempFile(os.TempDir(), "testCert")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	keyOut, _ := ioutil.TempFile(os.TempDir(), "testKey")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	return certOut.Name(), keyOut.Name(), pemCertBytes, priv
}

func GenerateSelfSignedTLSKeyPairData(t *testing.T) ([]byte, *rsa.PrivateKey) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 2 * 365 * 24)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	template.DNSNames = append(template.DNSNames, "localhost")
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Errorf("Error creating certifcate for testing: %v", err)
	}
	return derBytes, priv
}
