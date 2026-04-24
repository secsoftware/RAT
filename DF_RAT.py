import copy
import datetime
import json
import os
import subprocess
import re
import sys
import time
import google.generativeai as genai
import google.genai as google_genai
import traceback
from google.genai import types

start_time = datetime.datetime.now()

API_KEY = 'your_api_key'

if len(sys.argv) > 1:
    API_KEY = sys.argv[1]

genai.configure(api_key=API_KEY, transport="rest")

generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 30,
    "max_output_tokens": 3200,
    "response_mime_type": "text/plain",
}

client = google_genai.Client(api_key=API_KEY)

generate_content_config = types.GenerateContentConfig(
    thinking_config=types.ThinkingConfig(
        thinking_budget=2000,
    ),
    response_mime_type="application/json",
    temperature=1,
    top_p=0.95,
    top_k=30,
    max_output_tokens=62000,
)

models = ['gemini-2.5-flash']
current_model_index = 0
request_count = 0

models_single = ['gemini-2.0-flash']
current_model_index_single = 0

# Cryptography
from cryptography import x509
from cryptography.x509 import CertificateRevocationList
from cryptography.hazmat.backends import default_backend
import warnings

def update_model_more_json_stream(models, result1, tls_tool1, result2, tls_tool2, result3, tls_tool3, result4,
                                  tls_tool4, result5, tls_tool5):
    global analysis_prompt
    global request_count
    full_prompt = f'{analysis_prompt} {tls_tool1}:{result1}\n{tls_tool2}:{result2}\n{tls_tool3}:{result3}\n{tls_tool4}:{result4}\n{tls_tool5}:{result5}'
    cont = 0
    global current_model_index
    while cont < 10:
        try:
            full_response_text = ""
            for chunk in client.models.generate_content_stream(
                    model=models[current_model_index],
                    contents=full_prompt,
                    config=generate_content_config,
            ):
                full_response_text += chunk.text
            parsed_json = json.loads(full_response_text)
            transformed_dict = {}
            for item in parsed_json:
                tool_name = item.get("Tls_tool")
                if tool_name:
                    transformed_dict[tool_name] = item
            return transformed_dict
        except Exception as e:
            time.sleep(3)
            current_model_index += 1
            if current_model_index == len(models):
                current_model_index = 0
            cont += 1


def update_model_single(models_single, full_prompt):
    cont = 0
    global current_model_index_single
    while cont < 5:
        try:
            model = genai.GenerativeModel(models_single[current_model_index_single],
                                          generation_config=generation_config)
            response = model.generate_content(full_prompt)
            return response
        except Exception as e:
            current_model_index_single += 1
            time.sleep(3)
            if current_model_index_single == len(models_single):
                current_model_index_single = 0
            cont += 1

def CRY_parse_crl(crl_file_path):

    result = ""
    try:
        with open(crl_file_path, "rb") as local_file:
            crl_data_bytes = local_file.read()

        crl = x509.load_der_x509_crl(crl_data_bytes, default_backend())
        result = result + "thisUpdate:" + str(crl.last_update_utc) + ";" + "\n"
        result = result + "nextUpdate:" + str(crl.next_update_utc) + ";" + "\n"
        issuer = crl.issuer
        raw_issuer = str(issuer)
        formatted_issuer = raw_issuer.replace("<Name(", "").replace(")>", "").replace(",", ", ")
        result = result + "Issuer:" + str(formatted_issuer) + "\n"

        for ext in crl.extensions:
            if ext.oid == x509.oid.ExtensionOID.CRL_NUMBER:
                raw_num = str(ext.value)
                match = re.search(r"\((\d+)\)", raw_num)
                if match:
                    result = result + "CRL_Number:" + str(match.group(1)) + ";" + "\n"
            if ext.oid == x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                aki = ext.value
                if aki.key_identifier:
                    hex_string = ":".join(f'{byte:02X}' for byte in aki.key_identifier)
                    result = result + "Key_Identifier:" + str(hex_string) + ";" + '\n'
                if aki.authority_cert_issuer:
                    raw_issuer = str(aki.authority_cert_issuer)
                    formatted_issuer = raw_issuer.replace("<Name(", "").replace(")>", "").replace(",", ", ")
                    match = re.search(r'value=(.*?)(?=\])', formatted_issuer)
                    if match:
                        aki_issuer_result = match.group(1).replace("/", "")
                        result = result + "Authority_Cert_Issuer:" + str(aki_issuer_result) + ";" + "\n"
                if aki.authority_cert_serial_number:
                    result = result + "Authority_Cert_Serial_Number:" + str(
                        aki.authority_cert_serial_number) + ";" + "\n"
            if ext.oid == x509.oid.ExtensionOID.DELTA_CRL_INDICATOR:
                result = result + "Delta_CRL_Indicator:" + str(ext.value.crl_number) + ";" + "\n"
            if ext.oid == x509.oid.ExtensionOID.ISSUER_ALTERNATIVE_NAME:
                ian_string = str(ext.value)
                extracted_values = []
                dns_matches = re.findall(r"DNSName\(value='([^']*)'\)", ian_string)
                extracted_values.extend(['DNS:' + dns for dns in dns_matches])
                uri_matches = re.findall(r"UniformResourceIdentifier\(value=(['\"])(.*?)\1\)", ian_string)
                extracted_values.extend(['URI:' + match[1] for match in uri_matches])
                email_matches = re.findall(r"RFC822Name\(value='([^']*)'\)", ian_string)
                extracted_values.extend(['Email:' + email for email in email_matches])
                ian = ",".join(filter(None, extracted_values))
                result = result + "Issuer_Alternative_Name:" + str(ian) + ";" + "\n"
        for entry in crl:
            result = result + "Revoked_Cert_Serial:" + str(entry.serial_number) + ";" + "\n"
            if entry.extensions:
                for ext_entry in entry.extensions:
                    if ext_entry.oid == x509.oid.CRLEntryExtensionOID.CRL_REASON:
                        reason = str(ext_entry.value.reason).replace("_", "").replace(" ", "").replace("ReasonFlags.",
                                                                                                       "")
                        result = result + "Revoked_Cert_Reason_Code:" + str(reason) + ";" + "\n"
                    if ext_entry.oid == x509.oid.CRLEntryExtensionOID.INVALIDITY_DATE:
                        result = result + "Revoked_Cert_Invalidity_Date:" + str(ext_entry.value.invalidity_date) + ";"
        return result
    except Exception as e:
        return f"Error occurred: {e}"


def run_local_command(command_parts: list) -> str:

    try:

        process = subprocess.run(
            command_parts,
            capture_output=True,
            text=True,
            check=False
        )
        if process.returncode != 0:
            return f"Error while running command: {process.stderr.strip()}"

        return process.stdout.strip()
    except FileNotFoundError:
        return f"Error: Command not found - '{command_parts[0]}'. Please ensure it's in the system's PATH."
    except Exception as e:
        return f"Error occurred while executing command: {e}"


def go_print_crl(crl_path):
    crl_result = ""
    go_base_path = "go_code/"

    go_scripts = {
        "thisUpdate": "go_thisUpdate.go",
        "nextUpdate": "go_nextUpdate.go",
        "Issuer": "go_issuer.go",
        "CRL_Number": "go_serial.go",
        "Key_Identifier": "go_aki_key.go",
        "Authority_Cert_Serial_Number": "go_aki_serial.go",
        "Authority_Cert_Issuer": "go_aki_issuer.go",
    }

    for field, script_name in go_scripts.items():
        go_file = os.path.join(go_base_path, script_name)
        command = ["go", "run", go_file, "-crl", crl_path]
        result = run_local_command(command)

        if "Error occurred:" in result or "Error while running command:" in result:
            return result

        if script_name in ['go_aki_issuer.go', 'go_issuer.go']:
            result = result.replace('/', '')

        if field == "CRL_Number" and '<nil>' in result:
            result = 'False'

        if result:
            crl_result += f"{field}:{result}\n"

    # Special handling for scripts that need to parse complex output
    certs_go_file = os.path.join(go_base_path, "go_certs.go")
    certs_command = ["go", "run", certs_go_file, "-crl", crl_path]
    certs_result = run_local_command(certs_command)

    if "Error occurred:" in certs_result or "Error while running command:" in certs_result:
        return certs_result

    if certs_result:
        revoked_certs_str = get_revokedCerts(certs_result)
        inv_date_str = get_go_inv_date(certs_result)
        crl_result += f"Revoked_Cert_Serial and Revoked_Cert_Reason_Code:{revoked_certs_str}\n"
        crl_result += f"Revoked_Cert_Invalidity_Date:{inv_date_str or 'False'}\n"
    else:
        crl_result += f"Revoked_Cert_Serial and Revoked_Cert_Reason_Code:'False'\n"
        crl_result += f"Revoked_Cert_Invalidity_Date:'False'\n"
    return crl_result.strip()


def wolfssl_print_crl(crl_file):
    command = ["wolfssl", "crl", "-inform", "der", "-in", crl_file, "-text"]
    result = run_local_command(command)
    if "Error" in result or "bad" in result:
        return 'wolfSSL parser false'
    return result


def gnutls_print_crl(crl_file):

    command = ["certtool", "--crl-info", "--inder", "--infile", crl_file]
    result = run_local_command(command)
    if 'error:' in result or 'Error in DER parsing' in result:
        match = re.search(r"error: (.*)", result)
        if match:
            return 'gnutls parser error:' + match.group(1).strip()
        return 'gnutls parser false'
    return result


def openssl_print_crl(crl_file):

    command = ["openssl", "crl", "-inform", "DER", "-in", crl_file, "-noout", "-text"]
    result = run_local_command(command)

    if "Error" in result:
        return 'openssl parser false'
    return result


def find_der_crl_files_recursively_local(root_folder_paths: list) -> list:

    der_files_found = []
    for root_path in root_folder_paths:

        if not os.path.isdir(root_path):
            print(f"Warning: The local path '{root_path}' is not a valid folder and has been skipped.")
            continue

        print(f"\nLocally scanning the folder '{root_path}' recursively to find .der files")

        for dirpath, _, filenames in os.walk(root_path):
            for filename in filenames:
                if filename.lower().endswith(".der"):
                    full_path = os.path.join(dirpath, filename)
                    der_files_found.append(full_path)
    return der_files_found


def process_crl_file(crl_file_path: str):

    global analysis_prompt, fileld_error
    error_set = set()

    CRY_result = CRY_parse_crl(crl_file_path).replace('\\', '')
    go_result = go_print_crl(crl_file_path).replace('\\', '')
    openssl_result = openssl_print_crl(crl_file_path).replace('\/', '').replace('\\', '')
    gnutls_result = gnutls_print_crl(crl_file_path).replace('\\', '')
    wolfssl_result = wolfssl_print_crl(crl_file_path).replace('\\', '')

    error_set = error_add([CRY_result, go_result, gnutls_result], error_set)

    if error_search(error_set, fileld_error) and error_count(
            [CRY_result, openssl_result, wolfssl_result, gnutls_result, go_result]):
        fileld_error = error_search(error_set, fileld_error)
        print(f" error CRL (DER file): {crl_file_path}")
        print('CRY_result:', CRY_result)
        print('go_result:', go_result)
        print('openssl_result:', openssl_result)
        print('wolfssl_result:', wolfssl_result)
        print('gnutls_result:', gnutls_result)
        return False
    elif (error_search(error_set, fileld_error) and not error_count(
            [CRY_result, openssl_result, wolfssl_result, gnutls_result, go_result])) or (
            not error_search(error_set, fileld_error) and error_set):
        return False

    dict_dict = update_model_more_json_stream(models, CRY_result, 'cryptography', go_result, 'go', gnutls_result,
                                              'gnutls', wolfssl_result, 'wolfssl', openssl_result, 'openssl')
    if not dict_dict:
        print(f" The model failed to return a valid analysis result for the file {crl_file_path}.")
        return False

    CRY_dict = dict_dict['cryptography']
    openssl_dict = dict_dict['openssl']
    gnutls_dict = dict_dict['gnutls']
    wolfssl_dict = dict_dict['wolfssl']
    go_dict = dict_dict['go']

    if openssl_dict['Authority_Cert_Issuer'][0] == '/':
        openssl_dict['Authority_Cert_Issuer'] = openssl_dict['Authority_Cert_Issuer'].replace('/', '', 1)
    openssl_dict['Authority_Cert_Issuer'] = openssl_dict['Authority_Cert_Issuer'].replace('/', ', ')
    openssl_dict = convert_16_10(openssl_dict)
    gnutls_dict = convert_16_10(gnutls_dict)
    if gnutls_dict['CRL_Number'] != 'False':
        gnutls_dict['CRL_Number'] = str(int(gnutls_dict['CRL_Number'], 16))
    aki_key_dicts = [CRY_dict, go_dict, gnutls_dict, wolfssl_dict, openssl_dict]
    aki_key_dicts = convert(aki_key_dicts)
    aki_key_dicts = sort_issuer_dict(aki_key_dicts)

    wolfssl_dict_16_10_cert_num = copy.deepcopy(wolfssl_dict)
    wolfssl_dict_10_16_cert_num = copy.deepcopy(wolfssl_dict)

    try:
        wolfssl_dict_10_16_cert_num['Revoked_Cert_Serial'] = str(format(int(wolfssl_dict['Revoked_Cert_Serial']), 'X'))
    except:
        pass

    aki_key_dicts3 = [CRY_dict, go_dict, gnutls_dict, wolfssl_dict_10_16_cert_num, openssl_dict]

    try:
        wolfssl_dict_16_10_cert_num['Revoked_Cert_Serial'] = str(int(wolfssl_dict['Revoked_Cert_Serial'], 16))
    except:
        pass

    aki_key_dicts2 = [CRY_dict, go_dict, gnutls_dict, wolfssl_dict_16_10_cert_num, openssl_dict]

    aki_key_dicts_2 = [CRY_dict, go_dict,wolfssl_dict, openssl_dict]
    aki_key_dicts_2=convert(aki_key_dicts_2)
    aki_key_dicts_2=sort_issuer_dict(aki_key_dicts_2)

    aki_dicts = [CRY_dict,go_dict,gnutls_dict,openssl_dict]
    aki_dicts=convert(aki_dicts)
    aki_dicts=sort_issuer_dict(aki_dicts)

    aki_dicts_2 = [CRY_dict, go_dict, openssl_dict]
    aki_dicts_2=convert(aki_dicts_2)
    aki_dicts_2=sort_issuer_dict(aki_dicts_2)

    inv_date_dicts = [CRY_dict,go_dict,openssl_dict]
    inv_date_dicts=convert(inv_date_dicts)
    inv_date_dicts=sort_issuer_dict(inv_date_dicts)

    ian_delta_dicts = [CRY_dict,openssl_dict]
    ian_delta_dicts=convert(ian_delta_dicts)
    ian_delta_dicts=sort_issuer_dict(ian_delta_dicts)

    if dict_compare(aki_key_dicts,'thisUpdate'):
        print(f"Processing CRL (DER file): {crl_file_path}")
        print('openssl_thisUpdate:', openssl_dict['thisUpdate'])
        print('go_thisUpdate:', go_dict['thisUpdate'])
        print('gnutls_thisUpdate:', gnutls_dict['thisUpdate'])
        print('wolfssl_thisUpdate:', wolfssl_dict['thisUpdate'])
        print('CRY_thisUpdate:', CRY_dict['thisUpdate'])
    if dict_compare(aki_key_dicts,'nextUpdate'):
        print(f"Processing CRL (DER file): {crl_file_path}")
        print('openssl_nextUpdate:', openssl_dict['nextUpdate'])
        print('go_nextUpdate:', go_dict['nextUpdate'])
        print('gnutls_nextUpdate:', gnutls_dict['nextUpdate'])
        print('wolfssl_nextUpdate:', wolfssl_dict['nextUpdate'])
        print('CRY_nextUpdate:', CRY_dict['nextUpdate'])
    if dict_compare(aki_key_dicts,'Issuer'):
        if dict_compare(aki_key_dicts_2, 'Issuer'):
            print(f"Processing CRL (DER file): {crl_file_path}")
            print('openssl_Issuer:', openssl_dict['Issuer'])
            print('go_Issuer:', go_dict['Issuer'])
            print('wolfssl_Issuer:', wolfssl_dict['Issuer'])
            print('CRY_Issuer:', CRY_dict['Issuer'])
    if dict_compare(aki_dicts, 'CRL_Number'):
        print(f"Processing CRL (DER file): {crl_file_path}")
        print('openssl_CRL_Number:', openssl_dict['CRL_Number'])
        print('go_CRL_Number:', go_dict['CRL_Number'])
        print('gnutls_CRL_Number:', gnutls_dict['CRL_Number'])
        print('CRY_CRL_Number:', CRY_dict['CRL_Number'])
        print('wolfssl_CRL_Number:', wolfssl_dict['CRL_Number'])
    elif CRY_dict['CRL_Number']!='False':
        CRL_NUM_full_prompt = f"Does the CRL_number value of this CRL file comply with the RFC5280 specification? Please return True if yes, or False if no.CRL_number:{CRY_dict['CRL_Number']}"
        response = update_model_single(models_single, CRL_NUM_full_prompt)
        if response.text == 'False' or response.text == 'False\n':
            print(f" error CRL (DER file): {crl_file_path}")
            print(CRY_dict['CRL_Number'])
    else:
        pass

    if dict_compare(aki_dicts,'Key_Identifier'):
        print(f"Processing CRL (DER file): {crl_file_path}")
        print('openssl_Key_Identifier:', openssl_dict['Key_Identifier'])
        print('go_Key_Identifier:', go_dict['Key_Identifier'])
        print('gnutls_Key_Identifier:', gnutls_dict['Key_Identifier'])
        print('CRY_Key_Identifier:', CRY_dict['Key_Identifier'])
    if dict_compare(aki_dicts,'Authority_Cert_Issuer'):
        if dict_compare(aki_dicts_2,'Authority_Cert_Issuer'):
            print(f"Processing CRL (DER file): {crl_file_path}")
            print('openssl_Authority_Cert_Issuer:', openssl_dict['Authority_Cert_Issuer'])
            print('CRY_Authority_Cert_Issuer:', CRY_dict['Authority_Cert_Issuer'])
            print('go_Authority_Cert_Issuer:', go_dict['Authority_Cert_Issuer'])

    if dict_compare(aki_dicts,'Authority_Cert_Serial_Number'):
        print(f"Processing CRL (DER file): {crl_file_path}")
        print('openssl_Authority_Cert_Serial_Number:', openssl_dict['Authority_Cert_Serial_Number'])
        print('gnutls_Authority_Cert_Serial_Number:',gnutls_dict['Authority_Cert_Serial_Number'])
        print('go_Authority_Cert_Serial_Number:',go_dict['Authority_Cert_Serial_Number'])
        print('CRY_Authority_Cert_Serial_Number:',CRY_dict['Authority_Cert_Serial_Number'])
    elif CRY_dict['Authority_Cert_Serial_Number'] != 'False':
        serial_full_prompt = f"Does this certificate serial number comply with RFC5280 (greater than 0 and not exceed the maximum positive integer representable by 20 octets.)? Return True if compliant. Return False if not compliant. Do not reply with anything other than True or False. Serial Number: {CRY_dict['Authority_Cert_Serial_Number']}"
        response = update_model_single(models_single, serial_full_prompt)
        if response.text == 'False' or response.text == 'False\n':
            print(f" error CRL (DER file): {crl_file_path}")
            print(CRY_dict['Authority_Cert_Serial_Number'])
    else:
        pass

    if dict_compare(ian_delta_dicts,'Delta_CRL_Indicator'):
        print(f"Processing CRL (DER file): {crl_file_path}")
        print('openssl_CRL_Indicator:', openssl_dict['Delta_CRL_Indicator'])
        print('CRY_CRL_Indicator:', CRY_dict['Delta_CRL_Indicator'])
    elif CRY_dict['Delta_CRL_Indicator'] != 'False':
        CRL_NUM_full_prompt = f"Does the CRL_number value of this CRL file comply with the RFC5280 specification? Please return True if yes, or False if no.CRL_number:{CRY_dict['Delta_CRL_Indicator']}"
        response = update_model_single(models_single, CRL_NUM_full_prompt)
        if response.text == 'False' or response.text == 'False\n':
            print(f" error CRL (DER file): {crl_file_path}")
            print(CRY_dict['Delta_CRL_Indicator'])
    else:
        pass
    if dict_compare(ian_delta_dicts,'Issuer_Alternative_Name'):
        print(f"Processing CRL (DER file): {crl_file_path}")
        print('openssl_Issuer_Alternative_Name:',openssl_dict['Issuer_Alternative_Name'])
        print('CRY_Issuer_Alternative_Name:', CRY_dict['Issuer_Alternative_Name'])
    elif CRY_dict['Issuer_Alternative_Name'] != 'False' and CRY_dict['Issuer_Alternative_Name'] not in ian_dict:
        CRL_IAN_full_prompt = f'Do the DNS, URI, and Email values in the Issuer Alternative Name (IAN) extension of this CRL file comply with RFC5280? (The primary check is whether the characters within the DNS, URI, and Email values conform to their relevant RFC standards.) Return True if compliant, False otherwise. Do not reply with anything other than True or False. The respective values are: openssl_Issuer_Alternative_Name: {CRY_dict["Issuer_Alternative_Name"]}'
        response = update_model_single(models_single, CRL_IAN_full_prompt)
        if response.text == 'False' or response.text == 'False\n':
            ian_dict.add(CRY_dict['Issuer_Alternative_Name'])
            print(f" error CRL (DER file): {crl_file_path}")
            print(CRY_dict['Issuer_Alternative_Name'])
    else:
        pass


    if dict_compare(aki_key_dicts,'Revoked_Cert_Serial') and dict_compare(aki_key_dicts2,'Revoked_Cert_Serial') and dict_compare(aki_key_dicts3,'Revoked_Cert_Serial'):
        print(f"Processing CRL (DER file): {crl_file_path}")

        print('openssl_Revoked_Cert_Serial:', openssl_dict['Revoked_Cert_Serial'])
        print('CRY_Revoked_Cert_Serial:', CRY_dict['Revoked_Cert_Serial'])
        print('gnutls_Revoked_Cert_Serial:', gnutls_dict['Revoked_Cert_Serial'])
        print('wolfssl_Revoked_Cert_Serial:', wolfssl_dict['Revoked_Cert_Serial'])
        print('go_revoked_Cert_Serial:', go_dict['Revoked_Cert_Serial'])
    elif CRY_dict['Revoked_Cert_Serial'] != 'False':
        serial_full_prompt = f"Does this certificate serial number comply with RFC5280 (greater than 0 and not exceed the maximum positive integer representable by 20 octets.)? Return True if compliant. Return False if not compliant. Do not reply with anything other than True or False. Serial Number: {CRY_dict['Revoked_Cert_Serial']}"
        response = update_model_single(models_single, serial_full_prompt)
        if response.text == 'False' or response.text == 'False\n':
            print(f" error CRL (DER file): {crl_file_path}")
            print(CRY_dict['Revoked_Cert_Serial'])
    else:
        pass
    if dict_compare(inv_date_dicts,'Revoked_Cert_Reason_Code'):
        print(f"Processing CRL (DER file): {crl_file_path}")
        print('openssl_Revoked_Cert_Reason_Code:',openssl_dict['Revoked_Cert_Reason_Code'])
        print('go_Revoked_Cert_Reason_Code:',go_dict['Revoked_Cert_Reason_Code'])
        print('CRY_Revoked_Cert_Reason_Code:',CRY_dict['Revoked_Cert_Reason_Code'])
    if dict_compare(inv_date_dicts,'Revoked_Cert_Invalidity_Date'):
        print(f"Processing CRL (DER file): {crl_file_path}")
        print('openssl_Revoked_Cert_Invalidity_Date:', openssl_dict['Revoked_Cert_Invalidity_Date'])
        print('CRY_Revoked_Cert_Invalidity_Date:',CRY_dict['Revoked_Cert_Invalidity_Date'])
        print('go_Revoked_Cert_Invalidity_Date:',go_dict['Revoked_Cert_Invalidity_Date'])

def get_revokedCerts(Result):
    if not Result: return False
    pattern = re.compile(r'Serial Number:\s*([0-9a-fA-F]+).*?X509v3 CRL Reason Code:\s*([^\n]+)', re.DOTALL)
    matches = pattern.findall(Result)
    result = []
    for serial, reason in matches:
        serial = str(int(serial, 16))
        result.append(serial)
        reason = reason.replace(' ', '').strip()
        result.append(reason)
    return ', '.join(result)


def get_go_inv_date(crl_text):
    pattern = re.compile(r"2\.5\.29\.24 \(Invalidity Date\):\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*([+-]\d{4})")
    match = pattern.search(crl_text)
    if match:
        full_datetime_with_offset_str = f"{match.group(1)}{match.group(2)}"
        try:
            dt_aware = datetime.datetime.strptime(full_datetime_with_offset_str, "%Y-%m-%d %H:%M:%S%z")
            dt_utc = dt_aware.astimezone(datetime.timezone.utc)
            return dt_utc.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    return None

def sort_issuer(input_str):
    try:
        parts = [part.strip() for part in input_str.split(',') if part.strip()]
        if not parts:
            return ""

        desired_order = ['C', 'ST', 'L', 'O', 'OU', 'CN']
        parsed_dict = {}

        for part in parts:

            split_part = part.split('=', 1)
            if len(split_part) == 2:
                key = split_part[0].strip()
                value = split_part[1].strip()

                if value == 'False':
                    continue
                parsed_dict[key] = value

        sorted_parts = []
        for key in desired_order:
            if key in parsed_dict:
                sorted_parts.append(f"{key}={parsed_dict[key]}")

        return ', '.join(sorted_parts)

    except Exception as e:
        print(f"Error: {e}")
        return "False"

def convert_(dicts):
    pattern = re.compile(r"(0[xX])|([a-fA-F])")
    convert_dicts=[]
    for dict in dicts:
        if dict['CRL_Number']!='False':
            dict['CRL_Number'] = dict['CRL_Number'].replace(':','')
            if  bool(pattern.search(dict['CRL_Number'])):
                dict['CRL_Number'] = str(int(dict['CRL_Number'],16))
            if dict['CRL_Number'][0] == '0':
                dict['CRL_Number'] = str(int(dict['CRL_Number'], 16))

        if dict['Authority_Cert_Serial_Number']!='False':
            dict['Authority_Cert_Serial_Number'] = dict['Authority_Cert_Serial_Number'].replace(':','')
            if  bool(pattern.search(dict['Authority_Cert_Serial_Number'])):
                dict['Authority_Cert_Serial_Number'] = str(int(dict['Authority_Cert_Serial_Number'],16))
            if dict['Authority_Cert_Serial_Number'][0]=='0':
                dict['Authority_Cert_Serial_Number'] = str(int(dict['Authority_Cert_Serial_Number'],16))

        if dict['Revoked_Cert_Serial']!='False':
            dict['Revoked_Cert_Serial'] = dict['Revoked_Cert_Serial'].replace(':','')
            if  bool(pattern.search(dict['Revoked_Cert_Serial'])):
                dict['Revoked_Cert_Serial'] = str(int(dict['Revoked_Cert_Serial'],16))
            if  dict['Revoked_Cert_Serial'][0]=='0':
                dict['Revoked_Cert_Serial'] = str(int(dict['Revoked_Cert_Serial'], 16))

        if dict['Delta_CRL_Indicator']!='False':
            dict['Delta_CRL_Indicator'] = dict['Delta_CRL_Indicator'].replace(':','')
            if  bool(pattern.search(dict['Delta_CRL_Indicator'])):
                dict['Delta_CRL_Indicator'] = str(int(dict['Delta_CRL_Indicator'],16))
            if  dict['Delta_CRL_Indicator'][0]=='0':
                dict['Delta_CRL_Indicator'] = str(int(dict['Delta_CRL_Indicator'], 16))

        dict['Key_Identifier']=dict['Key_Identifier'].replace(':','')

        convert_dicts.append(dict)
    return convert_dicts

def dict_compare(dicts,key):
    value=[]
    for dict in dicts:
        value.append(dict[key])
    s = set(value)
    s.discard('False')  # s 现在是 {'a', 'b', 'c'}
    if len(s) > 1:
        return True
    else:
        return False

PROMPT_FILENAME = 'DF_2.5 flash'

def load_prompt(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            prompt = f.read()
            print(f"Successfully loaded prompt from '{filename}'")
            return prompt
    except FileNotFoundError:
        print(f"Error: Prompt file '{filename}' not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while reading prompt file '{filename}': {e}")
        return None

try:
    script_dir = os.path.dirname(os.path.abspath(__file__))

    prompt_full_path = os.path.join(script_dir, PROMPT_FILENAME)

    genai.configure(api_key=API_KEY, transport="rest")
    print("Generative AI SDK configured.")
except Exception as e:
    print(f"Error configuring Generative AI SDK: {e}")
    exit()

analysis_prompt = load_prompt(prompt_full_path)
fileld_error = set()


def error_count(error_list):
    count = 0
    for error in error_list:
        if error == 'wolfSSL parser false' or error == 'openssl parser false' or error == 'gnutls parser false' or 'Error occurred:' in error or 'Error while running command:' in error or 'gnutls parser error:' in error:
            count += 1

    if count == len(error_list):
        return False
    else:
        return True


# error search
def error_search(error_set, error_record):
    if not error_set:
        return False

    if error_set - (error_set & error_record):
        return error_record | error_set
    else:
        return False


def error_add(error_list, error_set):
    for error_str in error_list:
        if isinstance(error_str, str):
            if 'Error occurred:' in error_str or 'Error while running command:' in error_str or 'gnutls parser error:' in error_str:
                error_set.add(error_str)
    return error_set

def convert(dicts):
    pattern = re.compile(r"(0[xX])|([a-fA-F])")
    convert_dicts = []
    for dict in dicts:
        if dict['CRL_Number'] != 'False':
            dict['CRL_Number'] = dict['CRL_Number'].replace(':', '')
            if bool(pattern.search(dict['CRL_Number'])):
                dict['CRL_Number'] = str(int(dict['CRL_Number'], 16))
            if dict['CRL_Number'][0] == '0':
                dict['CRL_Number'] = str(int(dict['CRL_Number'], 16))

        if dict['Delta_CRL_Indicator'] != 'False':
            dict['Delta_CRL_Indicator'] = dict['Delta_CRL_Indicator'].replace(':', '')
            if bool(pattern.search(dict['Delta_CRL_Indicator'])):
                dict['Delta_CRL_Indicator'] = str(int(dict['Delta_CRL_Indicator'], 16))
            if dict['Delta_CRL_Indicator'][0] == '0':
                dict['Delta_CRL_Indicator'] = str(int(dict['Delta_CRL_Indicator'], 16))

        dict['Key_Identifier'] = dict['Key_Identifier'].replace(':', '')

        convert_dicts.append(dict)
    return convert_dicts


def convert_16_10(dict):
    if dict['Revoked_Cert_Serial'] != 'False':
        dict['Revoked_Cert_Serial'] = dict['Revoked_Cert_Serial'].replace(':', '')
        dict['Revoked_Cert_Serial'] = str(int(dict['Revoked_Cert_Serial'], 16))

    if dict['Authority_Cert_Serial_Number'] != 'False':
        dict['Authority_Cert_Serial_Number'] = dict['Authority_Cert_Serial_Number'].replace(':', '')
        dict['Authority_Cert_Serial_Number'] = str(int(dict['Authority_Cert_Serial_Number'], 16))

    return dict


def sort_issuer_dict(dicts):
    convert_dicts = []
    for dict in dicts:
        if dict['Issuer'] != 'False':
            dict['Issuer'] = sort_issuer(dict['Issuer'])
            dict['Issuer'] = dict['Issuer'].replace('\\', '')
            dict['Issuer'] = dict['Issuer'].replace('/', '')

        if dict['Authority_Cert_Issuer'] != 'False':
            dict['Authority_Cert_Issuer'] = sort_issuer(dict['Authority_Cert_Issuer'])
            dict['Authority_Cert_Issuer'] = dict['Authority_Cert_Issuer'].replace('/', '')
            dict['Authority_Cert_Issuer'] = dict['Authority_Cert_Issuer'].replace('\\', '')

        convert_dicts.append(dict)
    return convert_dicts

def dict_compare(dicts, key):
    value = []
    for dict in dicts:
        value.append(dict[key])
    s = set(value)
    s.discard('False')
    if len(s) > 1:
        return True
    else:
        return False

def sort_issuer(input_str):
    try:
        parts = [part.strip() for part in input_str.split(',') if part.strip()]
        if not parts:
            return ""

        desired_order = ['C', 'ST', 'L', 'O', 'OU', 'CN']
        parsed_dict = {}

        for part in parts:
            split_part = part.split('=', 1)
            if len(split_part) == 2:
                key = split_part[0].strip()
                value = split_part[1].strip()
                if value == 'False':
                    continue
                parsed_dict[key] = value

        sorted_parts = []
        for key in desired_order:
            if key in parsed_dict:
                sorted_parts.append(f"{key}={parsed_dict[key]}")

        return ', '.join(sorted_parts)

    except Exception as e:
        print(f"Error: {e}")
        return "False"


ian_dict = set()
if __name__ == '__main__':
    try:
        target_root_folders = ["generated_crls"]

        if not target_root_folders:
            print("Error: No target root folder path has been defined in the code.")
            exit(1)

        print("Starting to recursively search for DER-format CRL files locally...")
        all_found_der_crls = find_der_crl_files_recursively_local(target_root_folders)

        if all_found_der_crls:
            print(f"\nFound a total of {len(all_found_der_crls)} DER files. Starting processing...")
            for crl_fil in all_found_der_crls:
                processed_successfully = False
                retry_count = 0
                while retry_count < 5 and not processed_successfully:
                    try:
                        process_crl_file(crl_fil)
                        processed_successfully = True
                    except Exception as e:
                        print(f"A critical error occurred while processing file {crl_fil}: {e}")
                        traceback.print_exc()
                        retry_count += 1

            print("\nAll DER files have been processed.")
        else:
            print("\nNo DER files were found in the specified local root folder and its subfolders.")

        end_time = datetime.datetime.now()
        print(f"Total running time of differential testing: {end_time - start_time}")

    except Exception as e:
        print(f"An unknown error occurred in the main program: {e}")
        traceback.print_exc()