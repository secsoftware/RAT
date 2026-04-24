import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import datetime
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    CertificateSigningRequestBuilder,
    Name, NameAttribute,
    Certificate, CertificateRevocationListBuilder, IssuerAlternativeName, DNSName
)

root_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Beijing"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Beijing"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Root CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"My Root CA"),
])

root_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(root_private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    .sign(root_private_key, hashes.SHA256(), default_backend())
)

with open("root_cert.pem", "wb") as f:
    f.write(root_cert.public_bytes(serialization.Encoding.PEM))

with open("root_key.pem", "wb") as f:
    f.write(root_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

builder = x509.CertificateRevocationListBuilder()

builder = builder.issuer_name(root_cert.subject)

last_update = datetime.datetime.utcnow()
next_update = last_update + datetime.timedelta(days=30)
builder = builder.last_update(last_update)
builder = builder.next_update(next_update)

file_uri = x509.UniformResourceIdentifier("http://localhost:8000/ca_crl.der")
IDP = x509.IssuingDistributionPoint(
    full_name=[file_uri],
    relative_name=None,
    only_contains_user_certs=True,
    only_contains_ca_certs=False,
    indirect_crl=False,
    only_some_reasons=frozenset([x509.ReasonFlags.key_compromise, x509.ReasonFlags.ca_compromise,x509.ReasonFlags.certificate_hold]),
    only_contains_attribute_certs=False
)

distribution_point = x509.DistributionPoint(
    full_name=[file_uri],
    relative_name=None,
    reasons=None,
    crl_issuer=None
)
freshest_crl = x509.FreshestCRL([distribution_point])

delta=x509.DeltaCRLIndicator(2)
num=x509.CRLNumber(134026152402537916809419830168838464)

dns_name = DNSName("http://issuer.example.com")

IAN = IssuerAlternativeName([dns_name])

random_key_identifier = os.urandom(20)

aki = x509.AuthorityKeyIdentifier(
    key_identifier=random_key_identifier,
    authority_cert_issuer=None,
    authority_cert_serial_number=None
)

crl = builder.add_extension(
    num,critical=False
).add_extension(
    aki,critical=False
).add_extension(
    delta,critical=False
).add_extension(
    IDP,critical=False
).add_extension(
    IAN,critical=False
).sign(
    private_key=root_private_key,
    algorithm=hashes.SHA256(),
    backend=default_backend()
)

with open("ca_crl.der", "wb") as f:
    f.write(crl.public_bytes(encoding=serialization.Encoding.DER))

with open("ca_crl.crl", "wb") as f:
    f.write(crl.public_bytes(encoding=serialization.Encoding.PEM))