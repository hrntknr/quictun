# quictun

```
mkdir "$HOME/Library/Application Support/net.hrntknr.quictun/"
cd "$HOME/Library/Application Support/net.hrntknr.quictun/"
openssl req -new -x509 -nodes -days 3650 -text -subj "/CN=localhost" -extensions v3_req \
    -config <(cat /etc/ssl/openssl.cnf <(printf "\n[v3_req]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=nonRepudiation,digitalSignature,keyEncipherment\nsubjectAltName=DNS:localhost")) \
    -keyout server.key -out server.crt
```

```
mkdir "$HOME/.config/quictun/"
cd "$HOME/.config/quictun/"
openssl req -new -x509 -nodes -days 3650 -text -subj "/CN=localhost" -extensions v3_req \
    -config <(cat /etc/ssl/openssl.cnf <(printf "\n[v3_req]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=nonRepudiation,digitalSignature,keyEncipherment\nsubjectAltName=DNS:localhost")) \
    -keyout server.key -out server.crt
```
