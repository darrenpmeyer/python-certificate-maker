import OpenSSL
import time


class Certificate(object):
    def __init__(self, cn, loc=None, org=None, email=None, keypair=None, self_sign=True):
        self.OU, self.O = org.split('@', 1)
        self.CN = cn
        self.L, self.ST, self.C = loc.split('/', 2)
        self.email = email

        self.x509 = __class__.generate_x509(
            countryName=self.C,
            stateOrProvinceName=self.ST,
            localityName=self.L,
            organizationName=self.O,
            organizationalUnitName=self.OU,
            emailAddress=self.email,
            cn=self.CN
        )

        self.keypair = keypair

        if self.keypair is None:
            self.keypair = OpenSSL.crypto.PKey()
            self.keypair.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        self.x509.set_pubkey(self.keypair)

        if self_sign:
            # noinspection PyTypeChecker
            self.x509.sign(self.keypair, "sha512")

    @staticmethod
    def generate_x509(
            countryName,
            stateOrProvinceName,
            localityName,
            organizationName,
            organizationalUnitName,
            emailAddress,
            cn,
            san_list=None,
            issuer=None,
            expire_days=30
    ):
        x509 = OpenSSL.crypto.X509()
        subject = x509.get_subject()
        
        subject.countryName = countryName
        subject.stateOrProvinceName = stateOrProvinceName
        subject.localityName = localityName
        subject.organizationName = organizationName
        subject.organizationalUnitName = organizationalUnitName
        subject.emailAddress = emailAddress
        subject.CN = cn

        x509.set_subject(subject)

        if issuer is None:
            # self-issued
            x509.set_issuer(x509.get_subject())

        now = int(time.time())
        x509.set_serial_number(now)

        # Set expiration
        x509.gmtime_adj_notBefore(0)
        x509.gmtime_adj_notAfter(86400 * expire_days)  # seconds in a day * expire_days

        return x509

    def certificate(self):
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.x509)