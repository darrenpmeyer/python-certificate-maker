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
cert.to_disk(public="certificate.pem", private="privatekey.pem")

```