## Running Docker Image
```
docker run --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=root_token' -p 8200:8200 -v /vagrant/config:/vault/config -d --name=vault.service vault
```

## Setup
```
curl --header "X-Vault-Token:root_token" --request POST --data '{ "policy":"path \"secret/*\" { capabilities = [\"create\",\"read\",\"update\",\"delete\",\"list\"]}" }' http://127.0.0.1:8200/v1/sys/policy/testpolicy

curl --header "X-Vault-Token:root_token" --request POST --data '{"type": "approle"}' http://127.0.0.1:8200/v1/sys/auth/approle

curl --header "X-Vault-Token:root_token" --request POST --data '{"policies": "testpolicy"}' http://127.0.0.1:8200/v1/auth/approle/role/my-role

curl --header "X-Vault-Token:root_token" http://127.0.0.1:8200/v1/auth/approle/role/my-role/role-id

curl --request POST --header "X-Vault-Token:root_token" --header "X-Vault-Wrap-TTL:30s" http://127.0.0.1:8200/v1/auth/approle/role/my-role/secret-id
```