import re
import shutil
import socket
from random import random
from typing import List, Optional
import random
from pyasn1.type import univ, useful, tag
from pyasn1.type.univ import ObjectIdentifier
import os
from pyasn1.type import univ, namedtype
from pyasn1_modules import rfc5280
from pyasn1_modules.rfc5280 import AttributeValue
from pyasn1.codec.der.decoder import decode
from pyasn1.type import char
import json
import time
from pyasn1.type import univ
from pyasn1.codec.der import encoder
from pyasn1.codec.der import decoder

start_time = time.time()

class Time(univ.Choice):
    pass

Time.componentType = namedtype.NamedTypes(
    namedtype.NamedType('utcTime', useful.UTCTime()),
    namedtype.NamedType('generalTime', useful.GeneralizedTime())
)

def load_crl(filename):
    with open(filename, 'rb') as f:
        crl_der = f.read()
    return crl_der

def read_json_file(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {filename}: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def remove_parenthesized_content(input_string):
  pattern = r"\(.*?\)"

  cleaned_string = re.sub(pattern, "", input_string)

  return cleaned_string

def modify_crl_issuer(crl, new_cn,new_o,new_c,new_ou,new_l,new_st):
    tbs_crl = crl['tbsCertList']
    issuer = tbs_crl['issuer']

    test_value="test"
    utf8_bytes = char.UTF8String(test_value)
    test_v = encoder.encode(utf8_bytes)
    decoded_test, _ = decode(test_v, asn1Spec=AttributeValue())

    test_C = "US"
    utf8_bytes = char.UTF8String(test_C)
    test_c = encoder.encode(utf8_bytes)
    TEST_C, _ = decode(test_c, asn1Spec=AttributeValue())

    utf8_bytes = char.UTF8String(new_c)
    encoded_asn1 = encoder.encode(utf8_bytes)
    decoded_C, _ = decode(encoded_asn1, asn1Spec=AttributeValue())

    utf8_bytes = char.UTF8String(new_cn)
    octet_string2= encoder.encode(utf8_bytes)
    decoded_CN, _ = decode(octet_string2, asn1Spec=AttributeValue())

    utf8_bytes = char.UTF8String(new_o)
    octet_string2 = encoder.encode(utf8_bytes)
    decoded_O, _ = decode(octet_string2, asn1Spec=AttributeValue())

    utf8_bytes = char.UTF8String(new_ou)
    octet_string2 = encoder.encode(utf8_bytes)
    decoded_OU, _ = decode(octet_string2, asn1Spec=AttributeValue())

    utf8_bytes = char.UTF8String(new_l)
    octet_string2 = encoder.encode(utf8_bytes)
    decoded_L, _ = decode(octet_string2, asn1Spec=AttributeValue())

    utf8_bytes = char.UTF8String(new_st)
    octet_string2 = encoder.encode(utf8_bytes)
    decoded_ST, _ = decode(octet_string2, asn1Spec=AttributeValue())

    cont=0
    for rdn in issuer[0]:
        attribute = rdn[0]
        oid = attribute[0]
        value=attribute[1]
        print(f"OID: {oid}")
        if oid==rfc5280.AttributeType('2.5.4.6'):
            if new_c=="":
                issuer[0][cont][0][1] = TEST_C
                cont += 1
            else:
                issuer[0][cont][0][1]=decoded_C
                cont+=1
        elif oid==rfc5280.AttributeType('2.5.4.3'):
            if new_cn=="":
                issuer[0][cont][0][1] = decoded_test
                cont += 1
            else:
                issuer[0][cont][0][1] =decoded_CN
                cont+=1
        elif oid==rfc5280.AttributeType('2.5.4.10'):
            if new_o=="":
                issuer[0][cont][0][1] = decoded_test
                cont += 1
            else:
                issuer[0][cont][0][1] =decoded_O
                cont+=1
        elif oid==rfc5280.AttributeType('2.5.4.11'):
            if new_ou=="":
                issuer[0][cont][0][1] = decoded_test
                cont += 1
            else:
                issuer[0][cont][0][1] =decoded_OU
                cont+=1
        elif oid==rfc5280.AttributeType('2.5.4.7'):
            if new_l=="":
                issuer[0][cont][0][1] = decoded_test
                cont += 1
            else:
                issuer[0][cont][0][1] = decoded_L
                cont += 1
        elif oid==rfc5280.AttributeType('2.5.4.8'):
            if new_st=="":
                issuer[0][cont][0][1] = decoded_test
                cont += 1
            else:
                issuer[0][cont][0][1] =decoded_ST
                cont+=1

    crl['tbsCertList']['issuer']=issuer
    modified_cert_der = encoder.encode(crl)
    return modified_cert_der

def modify_crl_issuer_PS(crl, new_cn,new_o,new_c,new_ou,new_l,new_st):
    tbs_crl = crl['tbsCertList']
    issuer = tbs_crl['issuer']

    test_value = "test"
    printable_bytes = char.PrintableString(test_value)
    test_v = encoder.encode(printable_bytes)
    decoded_test, _ = decode(test_v, asn1Spec=AttributeValue())

    test_C = "US"
    printable_bytes = char.PrintableString(test_C)
    test_c = encoder.encode(printable_bytes)
    TEST_C, _ = decode(test_c, asn1Spec=AttributeValue())

    printable_str = char.PrintableString(new_c)
    encoded_asn1 = encoder.encode(printable_str)
    decoded_C, _ = decode(encoded_asn1, asn1Spec=AttributeValue())

    printable_str = char.PrintableString(new_cn)
    octet_string2= encoder.encode(printable_str)
    decoded_CN, _ = decode(octet_string2, asn1Spec=AttributeValue())

    printable_str = char.PrintableString(new_o)
    octet_string2 = encoder.encode(printable_str)
    decoded_O, _ = decode(octet_string2, asn1Spec=AttributeValue())

    printable_str = char.PrintableString(new_ou)
    octet_string2 = encoder.encode(printable_str)
    decoded_OU, _ = decode(octet_string2, asn1Spec=AttributeValue())

    printable_str = char.PrintableString(new_l)
    octet_string2 = encoder.encode(printable_str)
    decoded_L, _ = decode(octet_string2, asn1Spec=AttributeValue())

    printable_str = char.PrintableString(new_st)
    octet_string2 = encoder.encode(printable_str)
    decoded_ST, _ = decode(octet_string2, asn1Spec=AttributeValue())

    cont=0
    for rdn in issuer[0]:
        attribute = rdn[0]
        oid = attribute[0]
        value=attribute[1]
        print(f"OID: {oid}")
        if oid==rfc5280.AttributeType('2.5.4.6'):
            if new_c=="":
                issuer[0][cont][0][1] = TEST_C
                cont += 1
            else:
                issuer[0][cont][0][1]=decoded_C
                cont+=1
        elif oid==rfc5280.AttributeType('2.5.4.3'):
            if new_cn=="":
                issuer[0][cont][0][1] = decoded_test
                cont += 1
            else:
                issuer[0][cont][0][1] =decoded_CN
                cont+=1
        elif oid==rfc5280.AttributeType('2.5.4.10'):
            if new_o=="":
                issuer[0][cont][0][1] = decoded_test
                cont += 1
            else:
                issuer[0][cont][0][1] =decoded_O
                cont+=1
        elif oid==rfc5280.AttributeType('2.5.4.11'):
            if new_ou=="":
                issuer[0][cont][0][1] = decoded_test
                cont += 1
            else:
                issuer[0][cont][0][1] =decoded_OU
                cont+=1
        elif oid==rfc5280.AttributeType('2.5.4.7'):
            if new_l=="":
                issuer[0][cont][0][1] = decoded_test
                cont += 1
            else:
                issuer[0][cont][0][1] = decoded_L
                cont += 1
        elif oid==rfc5280.AttributeType('2.5.4.8'):
            if new_st=="":
                issuer[0][cont][0][1] = decoded_test
                cont += 1
            else:
                issuer[0][cont][0][1] =decoded_ST
                cont+=1

    crl['tbsCertList']['issuer']=issuer
    modified_cert_der = encoder.encode(crl)
    return modified_cert_der

def modify_this_update(crl, new_time,timetype,field):
    original_time=crl['tbsCertList'][field]
    encoded_value = encoder.encode(original_time).hex()
    time_obj = Time()

    if timetype=='utcTime':
        time_obj.setComponentByName('utcTime', useful.UTCTime(new_time))
    elif timetype=='generalTime':
        time_obj.setComponentByName('generalTime',useful.GeneralizedTime(new_time))

    der_encoded = encoder.encode(time_obj)
    hex_string=der_encoded.hex()
    modified_value, _ = decoder.decode(bytes.fromhex(hex_string), asn1Spec=original_time)
    crl['tbsCertList'][field]=modified_value

    modified_cert_der = encoder.encode(crl)
    return modified_cert_der

def modify_crl_num(num):

    num = num.replace(":", "")
    num = num.replace(" ", "")
    try:
        num=int(num,16)
        asn1_num = univ.Integer(num)
    except:
        asn1_num= univ.OctetString(num)

    encoder_ans1_num = encoder.encode(asn1_num)

    extension = rfc5280.Extension()
    extension['extnID'] = univ.ObjectIdentifier('2.5.29.20')  # CRLNumber OID
    extension['extnValue'] = encoder_ans1_num
    extension['critical'] = univ.Boolean(False)
    return extension

def create_issuer_name(fields,fild,type):
    OID_COUNTRY = "2.5.4.6"  # Country Name (C)
    OID_STATE = "2.5.4.8"  # State/Province (ST)
    OID_LOCALITY = "2.5.4.7"  # Locality (L)
    OID_ORGANIZATION = "2.5.4.10"  # Organization (O)
    OID_ORG_UNIT = "2.5.4.11"  # Organizational Unit (OU)
    OID_COMMON_NAME = "2.5.4.3"  # Common Name (CN)

    rdn_sequence = rfc5280.RDNSequence()

    #1. C
    country_rdn = rfc5280.RelativeDistinguishedName()
    country_attr = rfc5280.AttributeTypeAndValue()
    country_attr["type"] = univ.ObjectIdentifier(OID_COUNTRY)
    if type=='UTF8String':
        country_attr["value"] =encoder.encode( char.UTF8String(fields.get('C', 'US')))
    else:
        country_attr["value"] = encoder.encode(char.PrintableString(fields.get('C', 'US')))
    country_rdn[0] = country_attr

    if 'C'in fields:
        rdn_sequence.append(country_rdn)

    # 2. ST
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

    # 3. Locality (L)
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

    # 4. Organization (O)
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

    # 5. Organizational Unit (OU)
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

    # 6. Common Name (CN)
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

def create_aki_extension(key,serial,fields,type,string_type):

    aki = rfc5280.AuthorityKeyIdentifier()

    key_identifier_hex = key
    if ':' in key_identifier_hex:
        key_identifier_hex=key_identifier_hex.replace(":", "")
    try:
        key_identifier_bytes = bytes.fromhex(key_identifier_hex)
    except:
        key_identifier_bytes= key

    aki["keyIdentifier"] = key_identifier_bytes
    issuer_name = create_issuer_name(fields,'aki_issuer',string_type)

    general_names = rfc5280.GeneralNames().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
    )
    general_name = rfc5280.GeneralName()
    general_name["directoryName"] = issuer_name

    general_names[0] = general_name

    tagged_general_names = general_names

    if type!='only_key':
        aki["authorityCertIssuer"] = tagged_general_names
    serial_number = univ.Integer(serial).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
    )
    if type != 'only_key':
        aki["authorityCertSerialNumber"] = serial_number

    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_authorityKeyIdentifier
    extension["critical"] = False
    extension["extnValue"] = encoder.encode(aki)

    return extension

def create_ian_extension(
    dns_names: Optional[List[str]] = None,
    ip_addresses: Optional[List[str]] = None,
    uris: Optional[List[str]] = None,
    email_addresses: Optional[List[str]] = None,
    critical: bool = False
, pyasn1_error=None) -> Optional[rfc5280.Extension]:

    general_names_list: List[rfc5280.GeneralName] = []

    if dns_names is None:
        dns_names = []
    if ip_addresses is None:
        ip_addresses = []
    if uris is None:
        uris = []
    if email_addresses is None:
        email_addresses = []

    for name in dns_names:
        if name:
            gn = rfc5280.GeneralName()
            gn['dNSName'] = char.IA5String(name).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
            general_names_list.append(gn)

    for ip_str in ip_addresses:
        if not ip_str: continue
        ip_bytes = None
        try:
            ip_bytes = socket.inet_pton(socket.AF_INET, ip_str)
        except socket.error:
            try:
                ip_bytes = socket.inet_pton(socket.AF_INET6, ip_str)
            except socket.error as e:
                print(f"Warning: Failed to convert IP address '{ip_str}' to bytes: {e}. Has been skipped.")
                continue

        if ip_bytes:
            gn = rfc5280.GeneralName()
            gn['iPAddress'] = univ.OctetString(ip_bytes).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))
            general_names_list.append(gn)

    for uri_str in uris:
         if uri_str:
            gn = rfc5280.GeneralName()
            gn['uniformResourceIdentifier'] = char.IA5String(uri_str).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
            general_names_list.append(gn)

    for email_str in email_addresses:
        if email_str:
            gn = rfc5280.GeneralName()
            gn['rfc822Name'] = char.IA5String(email_str).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
            general_names_list.append(gn)

    if not general_names_list:
        print("Error: No valid alternative name has been provided for creating the SAN extension.")
        return None

    subject_alt_names = rfc5280.GeneralNames()

    for i, gn in enumerate(general_names_list):
        try:
            subject_alt_names.setComponentByPosition(i, gn, verifyConstraints=True)
        except pyasn1_error.PyAsn1Error as e:
             print(f"Error：fail to add GeneralName to GeneralNames  (index {i}): {e}")
             return None

    try:
        encoded_san_value = encoder.encode(subject_alt_names)
    except pyasn1_error.PyAsn1Error as e:
        print(f"Error：fail to encode GeneralNames objects with DER: {e}")
        return None

    ian_extension = rfc5280.Extension()
    ian_extension['extnID'] = rfc5280.id_ce_issuerAltName # SAN OID
    ian_extension['critical'] = univ.Boolean(critical)
    ian_extension['extnValue'] = univ.OctetString(encoded_san_value)

    return ian_extension

def create_delta_extension(num):
    num = num.replace(":", "")
    num = num.replace(" ", "")
    try:
        num = int(num, 16)
        asn1_num = univ.Integer(num)
    except:
        asn1_num = univ.OctetString(num)

    extension = rfc5280.Extension()
    extension["extnID"] = rfc5280.id_ce_deltaCRLIndicator
    extension["critical"] = False
    extension["extnValue"] = encoder.encode(asn1_num)

    return extension

def add_revoked_cert(crl, serial_number, inv_date,time_type):

    original_time = crl['tbsCertList']['thisUpdate']
    encoded_value = encoder.encode(original_time).hex()
    time_obj = Time()
    revocation_date1='250304000000Z'

    time_obj.setComponentByName('utcTime', useful.UTCTime(revocation_date1))

    der_encoded = encoder.encode(time_obj)
    hex_string = der_encoded.hex()
    revocation_date, _ = decoder.decode(bytes.fromhex(hex_string), asn1Spec=original_time)

    original_time = crl['tbsCertList']['thisUpdate']
    encoded_value = encoder.encode(original_time).hex()
    time_obj = Time()

    if time_type =='utcTime':
        time_obj.setComponentByName('utcTime', useful.UTCTime(inv_date))
    else:
        time_obj.setComponentByName('generalTime', useful.GeneralizedTime(inv_date))

    der_encoded = encoder.encode(time_obj)
    hex_string = der_encoded.hex()

    inv_date, _ = decoder.decode(bytes.fromhex(hex_string), asn1Spec=original_time)

    sequences=univ.SequenceOf()
    extensions = rfc5280.Extensions()
    #reason
    reason_extension=rfc5280.Extension()
    reason_extension["extnID"]=ObjectIdentifier('2.5.29.21')
    random_s=random.randint(0,10)
    reason_code_enum = univ.Enumerated(random_s)
    reason_extension["extnValue"]=encoder.encode(reason_code_enum)
    extensions.append(reason_extension)

    #date
    date_extension = rfc5280.Extension()
    date_extension["extnID"] = ObjectIdentifier('2.5.29.24')
    date_extension["extnValue"] = encoder.encode(inv_date)
    extensions.append(date_extension)

    serial_number=univ.Integer(serial_number)
    #定义
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

    new_crl_der = encoder.encode(crl)

    return new_crl_der

def append_extension(crl,extension):
    crl['tbsCertList']['crlExtensions'].append(extension)
    modified_cert_der = encoder.encode(crl)
    return modified_cert_der

json_file='crl_test_cases_ALL.json'
rules_data=read_json_file(json_file)

def empty_folder(folder_path):
    if not os.path.isdir(folder_path):
        print(f"Error: '{folder_path}' is not a valid folder path.")
        return

    print(f"Clearing folder: '{folder_path}' ...")
    for item_name in os.listdir(folder_path):
        item_path = os.path.join(folder_path, item_name)
        try:
            if os.path.isfile(item_path) or os.path.islink(item_path):
                os.unlink(item_path)
                print(f"  Deleted file: '{item_path}'")
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)
                print(f"  Deleted subfolder: '{item_path}'")
        except Exception as e:
            print(f"  Failed to delete '{item_path}'. Reason: {e}")
    print(f"Contents of folder '{folder_path}' have been cleared.")

output_folder='generated_crls'

file_cont=0

def ensure_directory_exists(directory_path):

    try:
        if not os.path.exists(directory_path):
            os.makedirs(directory_path, exist_ok=True)
            print(f"Directory created: {directory_path}")
        else:
            print(f"Directory already exists: {directory_path}")
    except Exception as e:
        print(f"Error creating directory: {e}")

ensure_directory_exists(output_folder)
empty_folder(output_folder)

crl=load_crl('ca_crl.der')
filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
file_cont += 1
with open(filename, 'wb') as f:
    f.write(crl)

crl1, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())
crl1['tbsCertList']['crlExtensions'].clear()
crl=encoder.encode(crl1)

default_fields = {
    'CN': 'example.com',         # Common Name
    'OU': 'Engineering',         # Organizational Unit
    'O': 'TechCorp',             # Organization
    'L': 'San Francisco',        # Locality
    'ST': 'California',          # State/Province
    'C': 'US'                    # Country
}
issuer_field=[]
serial_records=[]

for rule in rules_data:
    if rule['issue']:
        rule_dict=rule['issue']
        if 'thisUpdae'in rule_dict:
            this_time = rule_dict['thisUpdae']
            this_time = this_time.replace('#', '')
            this_time = this_time.replace(' ', '')
            try:
                crl1, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())
                thisUpdate='thisUpdate'
                modify_crl1=modify_this_update(crl1, this_time, 'utcTime', thisUpdate)

                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(modify_crl1)
            except:
                pass

            try:
                crl2, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())
                thisUpdate='thisUpdate'
                modify_crl2=modify_this_update(crl2, this_time, 'generalTime', thisUpdate)

                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(modify_crl2)
            except:
                pass

            try:
                crl3, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())

                modify_crl3=add_revoked_cert(crl3,123456, this_time, 'utcTime')

                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(modify_crl3)
            except:
                pass

            try:
                crl4, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())

                modify_crl4=add_revoked_cert(crl4,123456, this_time, 'generalTime')

                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(modify_crl4)
            except:
                pass

        if 'serial' in rule_dict:
            serial_num=rule_dict['serial']
            serial_num = serial_num.replace(":", "")
            serial_num = serial_num.replace(" ", "")
            serial_num = remove_parenthesized_content(serial_num)

            if serial_num not in serial_records:
                serial_records.append(serial_num)
            else:
                continue
            try:
                crl1, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())
                new_num=modify_crl_num(serial_num)
                modify_crl1=append_extension(crl1,new_num)
                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(modify_crl1)
            except Exception as e:
                pass
                print(e)

            try:
                crl2, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())
                new_aki = create_aki_extension('EF69E0F7D51DE699ECDC6DD0F7E2B95C64718335',serial_num,default_fields,'not_only_key','aki_issuer')
                modify_crl2 =append_extension(crl2,new_aki)
                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(modify_crl2)
            except:
                pass

            try:
                crl3, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())
                cert_num=int(serial_num,16)
                modify_crl3=add_revoked_cert(crl3,cert_num,'20250114120000Z','generalTime')

                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(modify_crl3)
            except Exception as e:
                pass

            try:
                crl4, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())
                new_delta=create_delta_extension(serial_num)
                modify_crl4=append_extension(crl4,new_delta)

                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(modify_crl4)
            except Exception as e:
                pass

        if 'issuer' in rule_dict:

            pattern = r"(\w+)=(.*?)(?=,|$)"

            matches = re.findall(pattern, rule_dict['issuer'], flags=re.DOTALL)

            fields = {key: val for key, val in matches}
            if fields not in issuer_field:
                issuer_field.append(fields)
            else:
                continue

            try:
                crl1, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())

                crl1['tbsCertList']['issuer'] = create_issuer_name(fields,'issuer','PrintableString')
                crl1=encoder.encode(crl1)
                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(crl1)
            except:
                pass

            try:
                crl1, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())

                crl1['tbsCertList']['issuer'] = create_issuer_name(fields, 'issuer', 'UTF8String')
                crl1 = encoder.encode(crl1)
                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(crl1)
            except:
                pass

            try:
                crl2, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())

                new_aki = create_aki_extension('EF69E0F7D51DE699ECDC6DD0F7E2B95C64718335',123456789,fields,'not_only_key','UTF8String')
                modify_crl2=append_extension(crl2,new_aki)
                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(modify_crl2)
            except:
                pass

            try:
                crl2, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())

                new_aki = create_aki_extension('EF69E0F7D51DE699ECDC6DD0F7E2B95C64718335',123456789,fields,'not_only_key','PrintableString')
                modify_crl2=append_extension(crl2,new_aki)
                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(modify_crl2)
            except:
                pass

        if 'create authorityKeyIdentifier' in rule_dict:
            aki=rule_dict['create authorityKeyIdentifier']
            if isinstance(aki,list):
                try:
                    crl1, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())
                    for key in aki:
                        key=key['KeyIdentifier']
                        new_key = create_aki_extension(key,123456,default_fields,'only_key','aki_issuer')
                        crl1=append_extension(crl1,new_key)
                        crl1, _ = decoder.decode(crl1, asn1Spec=rfc5280.CertificateList())

                    crl1=encoder.encode(crl1)

                    filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                    file_cont += 1
                    with open(filename, 'wb') as f:
                        f.write(crl1)
                except:
                    pass
            else:
                try:
                    key = aki['KeyIdentifier']
                    crl2, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())
                    new_key = create_aki_extension(key, 123456, default_fields, 'only_key','aki_issuer')
                    crl2 = append_extension(crl2, new_key)
                    filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                    file_cont += 1
                    with open(filename, 'wb') as f:
                        f.write(crl2)
                except:
                    pass
        if 'create Issuer Alternative Name' in rule_dict:
            try:
                IAN=rule_dict['create Issuer Alternative Name']

                uri = IAN['URI']
                URI=[uri]
                dns = IAN['DNS']
                DNS=[dns]
                email= IAN['email']
                Email=[email]

                crl1, _ = decoder.decode(crl, asn1Spec=rfc5280.CertificateList())
                new_ian = create_ian_extension(DNS,[],URI,Email)
                crl1 = append_extension(crl1, new_ian)
                filename = os.path.join(output_folder, f"crl_file_test_{file_cont}.der")
                file_cont += 1
                with open(filename, 'wb') as f:
                    f.write(crl1)
            except:
                pass

print('All test cases have been generated')
end_time = time.time()
print(f"Execution time for generating test cases: {end_time - start_time} seconds")
print(f"Generated {file_cont} CRL files")





