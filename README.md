public-private_handshake
========================

public / private keys handshake

A practical example of using an "handshake like" encryption/decryption using public/private keys to encrypt data. (Implemented using JAVA)

Generate the keys into the appropriate folder and Use the TestMain.java class to run a test.

####################################
# Generate Public/Private key pair #
####################################

will generate a 2048-bit RSA private key with all the proper encoding#

```openssl genrsa -out private.pem 2048```

will generate the public key, based on the private key, generate in DER format (with .key extension), to conform to X.509 standards#

```openssl rsa -in private.pem -inform pem -out public.key -outform der -pubout```

convert the private key to DER format as well, DER format is prefered by java (which doesn't work very well with PEM - use second line for pkcs8#

 ```openssl pkcs8 -topk8 -inform pem -in private.pem -outform der -nocrypt -out private.key```
