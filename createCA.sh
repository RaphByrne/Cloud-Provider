KEYNAME=ca-key.pem
CERTNAME=ca-cert.pem

openssl genrsa -des3 -out $KEYNAME 2048
openssl req -new -x509 -days 365 -key $KEYNAME -out $CERTNAME
