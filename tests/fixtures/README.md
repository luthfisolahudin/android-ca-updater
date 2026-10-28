# Test fixtures

Static certificates used by the suite. They have a 100-year validity so tests
never depend on the clock. Regenerate only when a scenario needs a new
certificate; the tests assert on `Test Root Alpha`, `Test Root Beta`, and
`leaf.test`.

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca-a.key -out root-a.pem \
  -days 36500 -subj "/CN=Test Root Alpha" \
  -addext "basicConstraints=critical,CA:TRUE"

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca-b.key -out root-b.pem \
  -days 36500 -subj "/CN=Test Root Beta" \
  -addext "basicConstraints=critical,CA:TRUE"

openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
  -subj "/CN=leaf.test"
printf "subjectAltName=DNS:leaf.test\n" > leaf.ext
openssl x509 -req -in leaf.csr -CA root-a.pem -CAkey ca-a.key -CAcreateserial \
  -out leaf-a.pem -days 36500 -extfile leaf.ext
```

Only the `.pem` files are committed; the private keys are throwaway material.
