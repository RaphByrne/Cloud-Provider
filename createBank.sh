mkdir bank
mkdir bank/certs
touch bank/passwd
touch bank/accounts
cp bank*.pem bank/certs
cp ca-cert.pem bank/certs
make clean
make bank
