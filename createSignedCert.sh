NAME=$1
CACERT=ca-cert.pem
CAKEY=ca-key.pem
CERTNAME=$NAME.pem
KEYNAME=$NAME-key.pem

openssl genrsa -out $KEYNAME 2048
openssl req -new -key $KEYNAME -out $NAME.csr
openssl x509 -req -days 365 -in $NAME.csr -CA $CACERT -CAkey $CAKEY -set_serial 01 -out $CERTNAME
rm $NAME.csr
