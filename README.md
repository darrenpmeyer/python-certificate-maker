# python-certificate-maker

Class, command-line utility, and pytest fixture for generating x509 certificates (self-signed and CSR)

| **Alpha state: don't use yet** |
|--------------------------------|

```python
import pycert_maker

# Make a self-signed certificate for localhost
cert = pycert_maker.Certificate(
                   'localhost',
                   loc="Minneapolis/Minnesota/US",
                   org="Application Testing Group@My Company, Inc.",
                   email="myemail@mydomain.tld")

# Save the certificate and key files to disk
with open('certificate.pem', 'wb') as cf:
    cf.write(cert.certificate())

with open('privatekey.pem', 'wb') as kf:
    kf.write(cert.private_key()

# Write private key encrypted to a passphrase with AES-256-CBC
with open('encryptedprivatekey.pem', 'wb') as ekf:
    ekf.write(
        cert.private_key(
            b'you should really choose a better passphrase'
        )
    )

```