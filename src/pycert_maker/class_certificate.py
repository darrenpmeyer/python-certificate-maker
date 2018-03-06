import OpenSSL

class Certificate(object):
    def __init__(self, cn, loc=None, org=None, email=None):
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
            issuer=None
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

        return x509


    def certificate(self):
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.x509)