# vault-secret-id-receiver

This library is part of an application secrets management solution based on [HashiCorp Vault](https://www.vaultproject.io/).
It aims to eliminate the problem of having the application store a credential for access to the secrets vault.

The [AppRole](https://www.vaultproject.io/docs/auth/approle.html) authentication method is used to access the vault.
An application can use this library to wait for a [wrapped](https://www.vaultproject.io/docs/concepts/response-wrapping.html) secret ID to be posted to a ReST interface.
Once received the library unwraps the secret ID and uses it to login and retrieve a client token.
The ReST interface is then closed down. The application can use the logged in client to retrieve secrets from the vault.
The library also manages the ongoing automatic renewal of the client's login token.

Methods are also available to be able to simply create, overwrite and read secrets in the vault.
These use the [key/value v2 store](https://www.vaultproject.io/api/secret/kv/kv-v2.html)

[![GoDoc](https://godoc.org/jcmturner/vault-secret-id-receiver?status.svg)](https://godoc.org/jcmturner/vault-secret-id-receiver)

### Configuration
The library has a configuration struct which the application can chose how to populate. For example, by loading from a JSON file.
```go
type Config struct {
	VaultURL    string
	MaxRetries  int
	CACertFile  string
	ClientCert  string
	ClientKey   string
	ReceivePort int
	RoleID      string
}
```
* VaultURL - the URL of the vault server (eg https://vault.example.com:8200).
* MaxRetries - sets the number of retries that will be used in the case of certain errors against the vault.
* CACertFile - the CA certificate, to be trusted, which signed the vault URL's certificate. 
* ClientCert - the certificate that the application will use to communicate with the vault and on the ReST interface that listens for the wrapped secret ID.
* ClientKey - the private key of the ClientCert.
* ReceivePort - the TCP port the library's ReST interface will listen on to which the wrapped secret ID should be posted.
* RoleID - the role ID for the [AppRole](https://www.vaultproject.io/docs/auth/approle.html) authentication method.

### Usage
Below are code snippets for how to use the library

##### Create the vault client and wait for the secret ID to be posted.
```go
    l := log.New(os.Stderr, "Vault Client: ", log.Ldate|log.Ltime|log.Lshortfile)
    c, err := New(cfg, l)
    if err != nil {
    	panic(fmt.Sprintf("could not create vault client: %v", err))
    }
    err = c.WaitForSecretID()
    if err != nil {
    	panic(fmt.Sprintf("error waiting for secret ID: %v", err))
    }
```
``c.WaitForSecretID()`` blocks until the secret ID has been posted.
Do this at the beginning of the initial start of the application.

##### Create, read and update secrets.
```go
    // Create secret
    location := "mysecret"
	err := c.CreateSecret(location, map[string]string{
		"key1": "value1",
		"key2": "value2",
	})
	if err != nil {
	    return fmt.Errorf("failed to create new secret: %v", err)
	}
	
	// Read secret
	s, err := c.ReadSecret(location, 0)
	if err != nil {
		return fmt.Errorf("failed to read secret: %v", err)
	}
	
	// Overwrite an existing secret
	err = c.OverwriteSecret(location, map[string]string{
		"key1": "newvalue",
	})
	if err != nil {
		return fmt.Errorf("failed to update secret: %v", err)
	}
```
The secret returned from the ``ReadSecret`` method is a HashiCorp Vault API [Secret](https://godoc.org/github.com/hashicorp/vault/api#Secret) struct.
Values can be accessed like this:
```go
	one := s.Data["data"].(map[string]interface{})["key1"].(string)
```

#### Posting the Secret ID
The secret ID should be posted by another process to the ``ReceivePort``.
The secret ID needs to be wrapped and is posted in a json payload as below: 
```json
{
  "secret_id": "wrapped-secret-id-string"
}
```