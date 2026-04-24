from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, useful
import os
from pyasn1.type import univ, namedtype, tag
from pyasn1_modules import rfc5280
from pyasn1.type.univ import ObjectIdentifier
from pyasn1.type import univ
from pyasn1.type import char

class Time(univ.Choice):
    pass

Time.componentType = namedtype.NamedTypes(
    namedtype.NamedType('utcTime', useful.UTCTime()),
    namedtype.NamedType('generalTime', useful.GeneralizedTime())
)

def load_crl(filename):
    with open(filename, 'rb') as f:
        crl_der = f.read()
    crl, _ = decoder.decode(crl_der)
    return crl

id_ad_caIssuers = univ.ObjectIdentifier("1.3.6.1.5.5.7.48.2")  # id-ad-caIssuers
id_ad_ocsp = univ.ObjectIdentifier("1.3.6.1.5.5.7.48.1")  # id-ad-ocsp
id_ce_authorityInfoAccess = univ.ObjectIdentifier("1.3.6.1.5.5.7.1.1")

def create_issuer_name(fields,fild,type):

    OID_COUNTRY = "2.5.4.6"  # Country Name (C)
    OID_STATE = "2.5.4.8"  # State/Province (ST)
    OID_LOCALITY = "2.5.4.7"  # Locality (L)
    OID_ORGANIZATION = "2.5.4.10"  # Organization (O)
    OID_ORG_UNIT = "2.5.4.11"  # Organizational Unit (OU)
    OID_COMMON_NAME = "2.5.4.3"  # Common Name (CN)

    rdn_sequence = rfc5280.RDNSequence()

    country_rdn = rfc5280.RelativeDistinguishedName()
    country_attr = rfc5280.AttributeTypeAndValue()
    country_attr["type"] = univ.ObjectIdentifier(OID_COUNTRY)
    if type=='UTF8String':
        country_attr["value"] =encoder.encode(char.UTF8String(fields.get('C', 'US')))
    else:
        country_attr["value"] = encoder.encode(char.PrintableString(fields.get('C', 'US')))
    country_rdn[0] = country_attr

    if 'C'in fields:
        rdn_sequence.append(country_rdn)

    state_rdn = rfc5280.RelativeDistinguishedName()
    state_attr = rfc5280.AttributeTypeAndValue()
    state_attr["type"] = univ.ObjectIdentifier(OID_STATE)
    if type == 'UTF8String':
        state_attr["value"] = encoder.encode( char.UTF8String(fields.get('ST', 'California')))
    else:
        state_attr["value"] = encoder.encode(char.PrintableString(fields.get('ST', 'California')))
    state_rdn[0] = state_attr

    if 'ST'in fields:
        rdn_sequence.append(state_rdn)

    locality_rdn = rfc5280.RelativeDistinguishedName()
    locality_attr = rfc5280.AttributeTypeAndValue()
    locality_attr["type"] = univ.ObjectIdentifier(OID_LOCALITY)
    if type == 'UTF8String':
        locality_attr["value"] = encoder.encode( char.UTF8String(fields.get('L', 'San Francisco')))
    else:
        locality_attr["value"] = encoder.encode(char.PrintableString(fields.get('L', 'San Francisco')))
    locality_rdn[0] = locality_attr

    if 'L'in fields:
        rdn_sequence.append(locality_rdn)

    org_rdn = rfc5280.RelativeDistinguishedName()
    org_attr = rfc5280.AttributeTypeAndValue()
    org_attr["type"] = univ.ObjectIdentifier(OID_ORGANIZATION)
    if type == 'UTF8String':
        org_attr["value"] = encoder.encode(char.UTF8String(fields.get('O', 'TechCorp')))
    else:
        org_attr["value"] = encoder.encode(char.PrintableString(fields.get('O', 'TechCorp')))
    org_rdn[0] = org_attr

    if 'O'in fields:
        rdn_sequence.append(org_rdn)

    ou_rdn = rfc5280.RelativeDistinguishedName()
    ou_attr = rfc5280.AttributeTypeAndValue()
    ou_attr["type"] = univ.ObjectIdentifier(OID_ORG_UNIT)
    if type == 'UTF8String':
        ou_attr["value"] = encoder.encode( char.UTF8String(fields.get('OU', 'Engineering')))
    else:
        ou_attr["value"] = encoder.encode( char.PrintableString(fields.get('OU', 'Engineering')))

    ou_rdn[0] = ou_attr

    if 'OU'in fields:
        rdn_sequence.append(ou_rdn)

    cn_rdn = rfc5280.RelativeDistinguishedName()
    cn_attr = rfc5280.AttributeTypeAndValue()
    cn_attr["type"] = univ.ObjectIdentifier(OID_COMMON_NAME)
    if type == 'UTF8String':
        cn_attr["value"] = encoder.encode( char.UTF8String(fields.get('CN', 'example.com')))
    else:
        cn_attr["value"] = encoder.encode(char.PrintableString(fields.get('CN', 'example.com')))
    cn_rdn[0] = cn_attr

    if 'CN'in fields:
        rdn_sequence.append(cn_rdn)

    if fild !='issuer':
        name = rfc5280.Name().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)
        )
    else:
        name = rfc5280.Name()
    name["rdnSequence"]  = rdn_sequence
    return name

def create_aki_extension(key=None,critical=False,serial=None,fields=None,type=None,string_type=None):
    aki = rfc5280.AuthorityKeyIdentifier()

    key_identifier_hex = key
    if ':' in key_identifier_hex:
        key_identifier_hex=key_identifier_hex.replace(":", "")
    try:
        key_identifier_bytes = bytes.fromhex(key_identifier_hex)
    except:
        key_identifier_bytes= key

    aki["keyIdentifier"] = key_identifier_bytes

    if type!='only_key':
        issuer_name = create_issuer_name(fields, 'aki_issuer', string_type)

        general_names = rfc5280.GeneralNames().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        )
        general_name = rfc5280.GeneralName()
        general_name["directoryName"] = issuer_name

        general_names[0] = general_name

        tagged_general_names = general_names
        aki["authorityCertIssuer"] = tagged_general_names

    if type != 'only_key':
        serial_number = univ.Integer(serial).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )
        aki["authorityCertSerialNumber"] = serial_number

    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_authorityKeyIdentifier
    extension["critical"] = critical
    extension["extnValue"] = encoder.encode(aki)

    return extension

class GeneralNamesWithTag(univ.SequenceOf):
    componentType = rfc5280.GeneralName()
    tagSet = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)

id_ce_authorityKeyIdentifier = univ.ObjectIdentifier("2.5.29.35")
id_ce_idpIdentifier = univ.ObjectIdentifier("2.5.29.28")
id_ce_deltaCRLIndicator = univ.ObjectIdentifier("2.5.29.27")


def creat_IDP(distribution_point_uri=None, only_user_certs=False, only_ca_certs=False,g_tag=False):

    idp = rfc5280.IssuingDistributionPoint()

    if distribution_point_uri:
        uri = rfc5280.GeneralName()

        if g_tag:
            uri = rfc5280.GeneralName().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    5  # CONTEXT-SPECIFIC 6
                )
            )
        uRI = char.IA5String(distribution_point_uri).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
        uri.setComponentByName('uniformResourceIdentifier', uRI)

        # GeneralNames (SEQUENCE OF GeneralName)
        general_names = rfc5280.GeneralNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        general_names.append(uri)

        distribution_point_name = rfc5280.DistributionPointName().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

        distribution_point = rfc5280.DistributionPoint()
        distribution_point['distributionPoint'] = distribution_point_name
        idp['distributionPoint'] = distribution_point['distributionPoint']

    idp['onlyContainsUserCerts'] = only_user_certs
    idp['onlyContainsCACerts'] = only_ca_certs

    extension = rfc5280.Extension()
    extension["extnID"] = id_ce_idpIdentifier
    extension["critical"] = True
    extension["extnValue"] = encoder.encode(idp)

    return extension

def add_revoked_cert(crl, serial_number, revocation_date,issuer=None):
    original_time = crl['tbsCertList']['thisUpdate']
    encoded_value = encoder.encode(original_time).hex()
    time_obj = Time()

    time_obj.setComponentByName('utcTime', useful.UTCTime(revocation_date))

    der_encoded = encoder.encode(time_obj)
    hex_string = der_encoded.hex()

    revocation_date, _ = decoder.decode(bytes.fromhex(hex_string), asn1Spec=original_time)

    sequences = univ.SequenceOf()
    extensions = rfc5280.Extensions()
    # reason
    reason_extension = rfc5280.Extension()
    reason_extension["extnID"] = ObjectIdentifier('2.5.29.21')
    reason_code_enum = univ.Enumerated(1)
    reason_extension["extnValue"] = encoder.encode(reason_code_enum)
    extensions.append(reason_extension)

    # date
    date_extension = rfc5280.Extension()
    date_extension["extnID"] = ObjectIdentifier('2.5.29.24')
    date_extension["extnValue"] = encoder.encode(revocation_date)
    extensions.append(date_extension)

    # issuer
    if issuer:
        issuer_extension = rfc5280.Extension()
        issuer_extension["extnID"] = ObjectIdentifier('2.5.29.29')
        general_names = rfc5280.GeneralNames()
        general_name = rfc5280.GeneralName()
        general_name['directoryName'] = issuer
        general_names.append(general_name)
        issuer_extension["critical"] = True
        issuer_extension["extnValue"] = encoder.encode(general_names)
        extensions.append(issuer_extension)

    serial_number = univ.Integer(serial_number)

    crlEntry = univ.Sequence(
        componentType=namedtype.NamedTypes(
            namedtype.NamedType('userCertificate', serial_number),
            namedtype.NamedType('revocationDate', revocation_date),
            namedtype.NamedType('crlEntryExtensions', extensions)
        )
    )
    crlEntry.setComponentByName('userCertificate', serial_number)
    crlEntry.setComponentByName('revocationDate', revocation_date)
    crlEntry.setComponentByName('crlEntryExtensions', extensions)
    crl['tbsCertList']['revokedCertificates'].append(crlEntry)

    return crl

def modify_ext(crl, new_ext):
    crl['tbsCertList']['crlExtensions'].append(new_ext)
    modified_cert_der = encoder.encode(crl)
    return modified_cert_der

def main():
    output_folder='generated_crls'
    rfc_file_cont=0

    with open('ca_crl.der', 'rb') as f:
        crl_data = f.read()

    crl_, _ = decoder.decode(crl_data, asn1Spec=rfc5280.CertificateList())

    crl_['tbsCertList']['crlExtensions'].clear()
    crl_o=encoder.encode(crl_)

    cert_info = {
        'CN': 'See www.entrust.net/legal-terms',
        'O': 'FNMT-RCM',
        'C': 'XX',
        'ST': 'Confusion',
        'L': 'Somewhere',
        'OU': 'ES\nO=mkcert development CA'
    }

    crl, _ = decoder.decode(crl_o, asn1Spec=rfc5280.CertificateList())
    modified_crl = add_revoked_cert(crl, 123456, '250414120000Z')
    modified_crl = add_revoked_cert(modified_crl, 123456, '250415120000Z')
    new_crl_der=encoder.encode(modified_crl)
    filename = os.path.join(output_folder, f"crl_file_test_{rfc_file_cont}.der")
    rfc_file_cont+=1
    with open(filename, 'wb') as f:
        f.write(new_crl_der)

    crl, _ = decoder.decode(crl_o, asn1Spec=rfc5280.CertificateList())
    issuer=create_issuer_name(cert_info,'not_issuer','UTF8String')
    modified_crl = add_revoked_cert(crl, 123456, '250414120000Z',issuer)

    new_crl_der = encoder.encode(modified_crl)
    filename = os.path.join(output_folder, f"crl_rfc_{rfc_file_cont}.der")
    rfc_file_cont+=1
    with open(filename, 'wb') as f:
        f.write(new_crl_der)

    crl, _ = decoder.decode(crl_o, asn1Spec=rfc5280.CertificateList())
    modified_crl = creat_IDP('https:\\example\\ca.crl.der', only_user_certs=False, only_ca_certs=False,g_tag=True)
    new_crl_der = modify_ext(crl,modified_crl)
    filename = os.path.join(output_folder, f"crl_rfc_{rfc_file_cont}.der")
    rfc_file_cont+=1
    with open(filename, 'wb') as f:
        f.write(new_crl_der)

    crl, _ = decoder.decode(crl_o, asn1Spec=rfc5280.CertificateList())
    modified_crl = creat_IDP(None, only_user_certs=True, only_ca_certs=True, g_tag=False)
    new_crl_der = modify_ext(crl, modified_crl)
    filename = os.path.join(output_folder, f"crl_rfc_{rfc_file_cont}.der")
    rfc_file_cont += 1
    with open(filename, 'wb') as f:
        f.write(new_crl_der)

    crl, _ = decoder.decode(crl_o, asn1Spec=rfc5280.CertificateList())
    modified_crl = create_aki_extension('EF69E0F7D51DE699ECDC6DD0F7E2B95C64718335',critical=True,type='only_key')
    new_crl_der = modify_ext(crl, modified_crl)
    filename = os.path.join(output_folder, f"crl_rfc_{rfc_file_cont}.der")
    rfc_file_cont += 1
    with open(filename, 'wb') as f:
        f.write(new_crl_der)

    crl, _ = decoder.decode(crl_o, asn1Spec=rfc5280.CertificateList())
    modified_crl = creat_IDP(None, only_user_certs=False, only_ca_certs=False, g_tag=False)
    new_crl_der = modify_ext(crl, modified_crl)
    filename = os.path.join(output_folder, f"crl_rfc_{rfc_file_cont}.der")
    rfc_file_cont += 1
    with open(filename, 'wb') as f:
        f.write(new_crl_der)
    print(f'According to RFC5280, {rfc_file_cont} CRL files have been generated')
if __name__ == '__main__':
    main()
