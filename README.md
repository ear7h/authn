# authn

## generating a key pair

```sh
openssl ecparam -name prime256v1 -genkey -noout -out priv-key.pem
openssl ec -in priv-key.pem -pubout -out pub-key.pem
openssl pkcs8 -topk8 -nocrypt -in priv-key.pem -out priv-key1.pem
mv priv-key1.pem priv-key.pem
```
