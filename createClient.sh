mkdir client
mkdir client/tmp
mkdir client/files
mkdir client/certs
cp client*.pem client/certs
cp ca-cert.pem client/certs
make clean
make client
