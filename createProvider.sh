mkdir provider
mkdir provider/certs
mkdir provider/users
touch provider/passwd
cp provider*.pem provider/certs
cp ca-cert.pem provider/certs
make clean
make provider
