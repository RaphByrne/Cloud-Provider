mkdir bank
mkdir bank/certs
touch bank/passwd
cp bank*.pem bank/certs
cp ca-cert.pem bank/certs
make clean
make bank
