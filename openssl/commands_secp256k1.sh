 #!/bin/sh

OPENSSL=/usr/local/bin/openssl

#${OPENSSL} ecparam -name secp256k1 -genkey | ${OPENSSL} pkcs8 -topk8 -out serv2_privkey.pem
${OPENSSL} ecparam -name secp256k1 > serv2_privkey_params.pem
${OPENSSL} genpkey -paramfile serv2_privkey_params.pem -aes256 > serv2_privkey.pem 
${OPENSSL} req -new -key serv2_privkey.pem -out serv2_certrequest.pem
${OPENSSL} ca -config ca.config -out serv2_certificate.pem -in serv2_certrequest.pem -days 365

${OPENSSL} dgst -sha256 -sign serv2_privkey.pem -out file.txt.SIG file.txt
${OPENSSL} x509 -noout -pubkey -in serv2_certificate.pem | ${OPENSSL} dgst -sha256 -verify - -signature file.txt.SIG file.txt
