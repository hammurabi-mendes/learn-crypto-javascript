 #!/bin/sh

OPENSSL=/usr/local/bin/openssl

${OPENSSL} genpkey -algorithm ed25519 -aes256 > ca_privkey.pem
${OPENSSL} req -new -x509 -key ca_privkey.pem -out ca_certificate.pem -days 365
${OPENSSL} genpkey -algorithm ed25519 -aes256 > serv_privkey.pem
${OPENSSL} req -new -key serv_privkey.pem -out serv_certrequest.pem
${OPENSSL} ca -config ca.config -out serv_certificate.pem -in serv_certrequest.pem -days 365

# Does not work
#${OPENSSL} dgst -sha256 -sign serv_privkey.pem -out file.txt.SIG file.txt
#${OPENSSL} dgst -sha256 -verify serv_certificate.pem -signature file.txt.SIG file.txt
