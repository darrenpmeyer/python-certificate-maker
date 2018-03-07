import OpenSSL
import time


class Certificate(object):
    """Generate and save (primarily) self-signed x509 certificates

    Attributes:
        CN (str): Common Name for the subject, also called Subject Name
        SAN (list, optional): Subject Alternate Names; other (e.g.) hostnames
        O (str): Organization
        OU (str): Organizational Unit
        L (str): Locale (city or equivalent)
        ST (str): State, Province, or equivalent
        C (str): Country - 2 char code (e.g. CA for Canada, DE for Germany)
        email (str): Email address for contact
        keypair (:obj:`OpenSSL.crypto.PKey`, read-only):
            the public and private keys for this cert
        x509 (:obj:`OpenSSL.crypto.X509`, read-only):
            the X509 representation of the certificate

    """

    def __init__(self, cn, loc=None, org=None, email=None, keypair=None, self_sign=True):
        """Create (and, by default, sign) a new certificate

        Note:
            Only set `self_sign` to `False` if you need to make a CSR for having a CA sign
            this certificate. Future implementations may generate the CSR for you

            Pay attention to the argument formats!

        Args:
            cn (str or :obj:`list` of :obj:`str`): the host name(s) that are valid
                for this cert. If it's a list or tuple, the first value will be the
                certificate CN and the list will be the list of SANs
            loc (str): Location in the form 'Locale/State/CC'; for example use
                "Minneapolis/Minneosta/US" for the city of Minneapolis in the
                State of Minnesota, in the USA. CC is the ISO two-letter country
                code.
            org (str): 'Org Unit Name@Organization Name'; typically something like
                "Department Name@Company, Inc."
            email (str): An email address for contact related to this certificate
            keypair (:obj:`OpenSSL.crypto.PKey`, optional): if you don't want the
                keypair auto-generated, you can provie a pre-existing pair here
            self_sign (bool, optional): If you don't want the certificate to be
                self-signed, set this `False`
        """
        # noinspection PyPep8
        self.OU, self.O = org.split('@', 1)
        self.CN = cn
        self.L, self.ST, self.C = loc.split('/', 2)
        self.email = email

        self.SAN = []
        if hasattr(self.CN, '__iter__') \
                and type(self.CN) is not str \
                and type(self.CN) is not bytes:
            # is a list or tuple or close enough, we assume a SAN list
            for n in self.CN:
                self.SAN.append(n)

            self.CN = self.SAN.pop(0)

        self.x509 = __class__.generate_x509(
            countryName=self.C,
            stateOrProvinceName=self.ST,
            localityName=self.L,
            organizationName=self.O,
            organizationalUnitName=self.OU,
            emailAddress=self.email,
            cn=self.CN,
            san=self.SAN
        )

        self.keypair = keypair

        if self.keypair is None:
            self.keypair = OpenSSL.crypto.PKey()
            self.keypair.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        self.x509.set_pubkey(self.keypair)

        if self_sign:
            # noinspection PyTypeChecker
            self.x509.sign(self.keypair, "sha512")

    # noinspection PyPep8Naming
    @staticmethod
    def generate_x509(
            countryName,
            stateOrProvinceName,
            localityName,
            organizationName,
            organizationalUnitName,
            emailAddress,
            cn,
            san=None,
            issuer=None,
            expire_days=30
    ):
        """(internal) Generate the X509 certificate body, but don't sign it or apply keys to it

        Args:
            countryName:
            stateOrProvinceName:
            localityName:
            organizationName:
            organizationalUnitName:
            emailAddress:
            cn:
            san:
            issuer:
            expire_days:

        Returns:

        """
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

        if san:
            sanstr = "DNS: {}".format(cn)
            for s in san:
                sanstr += ", DNS: {}".format(s)

            x509.add_extensions([
                OpenSSL.crypto.X509Extension(
                    b"subjectAltName", False, bytes(sanstr.encode())
                )
            ])

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
        """Get the PEM-encoded certificate data"""
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.x509)

    def private_key(self, passphrase=None):
        """Get the PEM-encoded private key data, optionally encrypted

        Note:
            Encrypts with AES-256-CBC

        Args:
            passphrase (bytes or callback): a byte string specifying the passphrase
                or a callback function that will return one

        Returns:
            bytes: a PEM-encoded representation of the key or encrypted key
        """
        if passphrase is None:
            return OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.keypair)
        else:
            return OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.keypair,
                                                  cipher='aes-256-cbc', passphrase=passphrase)
