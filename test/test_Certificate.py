import pytest

loc = "Minneapolis/Minnesota/US"
org = "Application Testing Group@My Company, Inc."
email = "myemail@mydomain.tld"


class TestFunctionalCertificate:
    def test_create_self_signed_cert_for_localhost(self):
        from test.cert_validator import validate_x509_cert
        import pycert_maker
        cert = pycert_maker.Certificate(
            'localhost',
            loc="Minneapolis/Minnesota/US",
            org="Application Testing Group@My Company, Inc.",
            email="myemail@mydomain.tld")

        assert type(cert) is pycert_maker.Certificate
        assert cert.OU == "Application Testing Group"
        assert cert.CN == "localhost"
        assert cert.O == "My Company, Inc."
        assert cert.L == "Minneapolis"
        assert cert.ST == "Minnesota"
        assert cert.C == "US"
        assert cert.email == "myemail@mydomain.tld"

        assert validate_x509_cert(cert.certificate())

    def test_create_unsigned_cert_for_localhost(self):
        import OpenSSL
        from test.cert_validator import validate_x509_cert
        import pycert_maker
        cert = pycert_maker.Certificate(
            'localhost',
            loc="Minneapolis/Minnesota/US",
            org="Application Testing Group@My Company, Inc.",
            email="myemail@mydomain.tld",
            self_sign=False)

        assert type(cert) is pycert_maker.Certificate
        assert cert.OU == "Application Testing Group"
        assert cert.CN == "localhost"
        assert cert.O == "My Company, Inc."
        assert cert.L == "Minneapolis"
        assert cert.ST == "Minnesota"
        assert cert.C == "US"
        assert cert.email == "myemail@mydomain.tld"

        with pytest.raises(OpenSSL.crypto.Error):
            validate_x509_cert(cert.certificate())

    def test_create_self_signed_cert_for_localhost_with_san(self):
        from test.cert_validator import validate_x509_cert
        import pycert_maker
        cert = pycert_maker.Certificate(
            ('localhost', 'testbox', 'hi.tld'),
            loc="Minneapolis/Minnesota/US",
            org="Application Testing Group@My Company, Inc.",
            email="myemail@mydomain.tld")

        assert type(cert) is pycert_maker.Certificate
        assert cert.OU == "Application Testing Group"
        assert cert.CN == "localhost"
        assert cert.O == "My Company, Inc."
        assert cert.L == "Minneapolis"
        assert cert.ST == "Minnesota"
        assert cert.C == "US"
        assert cert.email == "myemail@mydomain.tld"

        assert cert.SAN[0] == 'testbox'
        assert cert.SAN[1] == 'hi.tld'

        assert cert.x509.get_extension_count() > 0

        assert validate_x509_cert(cert.certificate())

class TestUnitCertificate:
    @pytest.fixture(scope='class')
    def cert(self):
        import pycert_maker
        cert = pycert_maker.Certificate(
            'localhost', loc=loc, org=org, email=email)
        return cert

    def test_object_creation(self, cert):
        import pycert_maker
        assert type(cert) is pycert_maker.Certificate

    def test_correct_o(self, cert):
        assert "My Company, Inc." == cert.O

    def test_correct_ou(self, cert):
        assert "Application Testing Group" == cert.OU

    def test_correct_cn(self, cert):
        assert 'localhost'== cert.CN

    def test_correct_l(self, cert):
        assert "Minneapolis" == cert.L

    def test_correct_st(self, cert):
        assert "Minnesota" == cert.ST

    def test_correct_c(self, cert):
        assert "US" == cert.C

    def test_correct_email(self, cert):
        assert email == cert.email

    def test_certificate_is_bytes(self, cert):
        assert type(cert.certificate()) is bytes

    def test_generate_x509_gives_x509(self):
        from pycert_maker import Certificate
        from OpenSSL.crypto import X509
        assert type(
            Certificate.generate_x509('us', 'a', 'a', 'a', 'a', 'a', 'a')
            ) is X509

    def test_certificate_is_x509(self, cert):
        from OpenSSL.crypto import X509
        assert type(cert.x509) is X509

    def test_certificate_x509_has_right_meta(self, cert):
        x509 = cert.x509.get_subject()
        assert cert.C == x509.C
        assert cert.ST == x509.ST
        assert cert.L == x509.L
        assert cert.O == x509.O
        assert cert.OU == x509.OU
        assert cert.email == x509.emailAddress

    def test_certificate_x509_has_self_issuer(self, cert):
        x509_subj = cert.x509.get_subject()
        x509_issuer = cert.x509.get_issuer()
        assert x509_subj.CN == x509_issuer.CN

    def test_certificate_is_pem_cert(self, cert):
        assert cert.certificate().startswith(b'-----BEGIN CERTIFICATE-----')

    def test_certificate_auto_generates_keypair(self, cert):
        from OpenSSL.crypto import PKey
        assert isinstance(cert.keypair, PKey)


class TestUnitCertificateWithSAN:
    @pytest.fixture(scope='class')
    def sancert(self):
        import pycert_maker
        cert = pycert_maker.Certificate(
            ('localhost', 'testbox', 'lord'), loc=loc, org=org, email=email)
        return cert

    def cert_has_san(self, cert, san=None):
        if cert.get_extension_count() <= 0:
            raise ValueError("No Extention, SAN not possible")

        certsan = []
        for i in range(0,cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                sans = ext.get_data().split(b"\x82")
                sans.pop(0)
                sans = [x[1:] for x in sans]
                certsan.extend(sans)

        if len(certsan) > 0:
            if san is None:
                return True  # we haven't been asked to check
            if len(certsan) != len(san):
                raise ValueError(
                    "SAN lengths don't match,\n\texpected: {}\n\t     got: {} ".format(
                        str(san),
                        str(certsan)
                    ))
            for i in range(0,len(san)):
                if san[i] != certsan[i]:
                    raise ValueError("item '{}' doesn't match '{}'".format(
                        certsan[i], san[i]
                    ))
            return True

        else:
            raise ValueError("No SANs found in cert")

    def test_cn_takes_iterable(self, sancert):
        assert 'localhost' == str(sancert.CN)

    def test_cn_iterable_produces_san(self, sancert):
        assert 2 == len(sancert.SAN)
        assert 'testbox' == str(sancert.SAN[0])

        assert self.cert_has_san(sancert.x509, san=[b'localhost', b'testbox', b'lord'])

