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

    def test_create_self_signed_cert_for_localhost_with_san(self):
        pytest.fail("Not implemented")


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




