NAME=name
CERTNAME=$NAME.pem
KEYNAME=$NAME-key.pem

openssl genrsa -des3 -out $KEYNAME 2048
openssl req -new -key $KEYNAME -out $NAME.csr
openssl x509 -req -days 365 -in $NAME.csr -signkey $KEYNAME -out $CERTNAME
rm -$NAME.csr
