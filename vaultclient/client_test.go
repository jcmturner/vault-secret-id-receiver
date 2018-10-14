package vaultclient

import "testing"

func TestClient_Login(t *testing.T) {
	cfg := Config{
		Addr: "http://10.80.30.2:8200",
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("could not create client: %v", err)
	}
	secretID, err := c.SecretID("my-role", "root_token")
	if err != nil {
		t.Fatalf("could not get wrapped secretID: %v", err)
	}
	err = c.Login("52a3a519-aebd-f072-65ce-dfe1fa453806", secretID)
	if err != nil {
		t.Fatalf("could not login client: %v", err)
	}
	t.Log(c.vclient.Token())
	err = c.WriteSecret("foo", "bar", "secretdata")
	if err != nil {
		t.Fatalf("failed to write secret: %v", err)
	}
}
