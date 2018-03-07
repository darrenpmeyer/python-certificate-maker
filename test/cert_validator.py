import OpenSSL


def validate_x509_cert(certdata, truststore=None, format=OpenSSL.crypto.FILETYPE_PEM):
    cert = OpenSSL.crypto.load_certificate(format, certdata)

    if truststore is None:
        # Make a cert store
        truststore = OpenSSL.crypto.X509Store()
        truststore.add_cert(cert)  # self-signed certs are their own trust root

    trust_context = OpenSSL.crypto.X509StoreContext(truststore, cert)

    # Validation returns None on success, raises X509StoreContextError on
    # failure. So we just run it, then return True
    trust_context.verify_certificate()
    return True
