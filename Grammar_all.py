import google.generativeai as genai
import time
import json
import os
import sys
import re

start_time = time.time()

API_KEY = 'your_api_key'

if len(sys.argv) > 1:
    API_KEY = sys.argv[1]

if not API_KEY or API_KEY == 'your_api_key':
    print("Error: API_KEY is not set or is still the placeholder.")
    print("Please replace 'YOUR_API_KEY' with your actual API key.")
    exit()

def get_filenames_in_folder(folder_path: str) -> list:

    if not os.path.isdir(folder_path):
        print(f"Error: The provided path '{folder_path}' is not a valid folder.")
        return []

    file_list = []

    for item in os.listdir(folder_path):
        full_path = os.path.join(folder_path, item)
        if os.path.isfile(full_path):
            file_list.append(full_path)

    return file_list
ALL_INPUT_JSON_FILENAME=get_filenames_in_folder('json_')

saved=0

OUTPUT_JSON_FILENAME = 'crl_test_cases_ALL.json'
PROMPT_FILENAME = 'CRL_Test_Case_Prompt_English.txt'

GEMINI_MODEL_NAME = 'gemini-2.0-flash'
API_RETRY_LIMIT = 5
API_SLEEP_DURATION = 8

DEFAULT_ISSUER_ALT_NAME = {
    "URI": "http://localhost:8080/crl.der",
    "DNS": "test.local",
    "email": "admin@test.local"
}

DEFAULT_AKI = {
    "KeyIdentifier": "123456"
}

try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    prompt_full_path = os.path.join(script_dir, PROMPT_FILENAME)

    genai.configure(api_key=API_KEY, transport="rest")
    print("Generative AI SDK configured.")
except Exception as e:
    print(f"Error configuring Generative AI SDK: {e}")
    exit()

generation_config = {
    "temperature":0.6,
    "top_p": 0.95,
    "top_k": 30,
    "max_output_tokens": 4096,
    "response_mime_type": "text/plain",
}
try:
    model = genai.GenerativeModel(GEMINI_MODEL_NAME, generation_config=generation_config)
    print(f"Using Gemini model: {GEMINI_MODEL_NAME}")
except Exception as e:
    print(f"Error creating Generative AI model '{GEMINI_MODEL_NAME}': {e}")
    try:
        print("\nAvailable models:")
        for m in genai.list_models():
            print(f"- {m.name}")
    except Exception as list_e:
         print(f"Could not list available models: {list_e}")

    exit()
def read_json_file(filename):
    try:
        input_full_path = os.path.join(script_dir, filename)
        with open(input_full_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            print(f"Successfully loaded {len(data)} records from {input_full_path}")
            return data
    except FileNotFoundError:
        print(f"Error: Input file '{input_full_path}' not found.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from '{input_full_path}': {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while reading '{input_full_path}': {e}")
        return None

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

def fix_invalid_json_escapes(text):
    result = []
    i = 0
    # Define standard JSON escapes
    standard_escapes = ('"', '\\', '/', 'b', 'f', 'n', 'r', 't')

    while i < len(text):
        if text[i] == '\\':
            if i + 1 < len(text):
                next_char = text[i+1]
                # Check for standard simple escapes
                if next_char in standard_escapes:
                    result.append(text[i])
                    result.append(next_char)
                    i += 2
                elif next_char == 'u':
                    # Check for \uXXXX - ensure followed by 4 hex digits
                    # Use a raw string for the regex pattern to avoid issues with backslashes in pattern
                    if i + 5 < len(text) and re.match(r'[0-9a-fA-F]{4}', text[i+2:i+6]):
                         result.append(text[i:i+6])
                         i += 6
                    else:
                        # \u not followed by 4 hex digits, treat as literal \\u
                        result.append('\\\\') # Append escaped backslash
                        result.append(next_char) # Append 'u'
                        i += 2
                else:
                    # Invalid escape sequence \X, convert to \\X
                    result.append('\\\\') # Append escaped backslash
                    result.append(next_char) # Append the character that followed '\'
                    i += 2
            else:
                # Trailing backslash at the end of the string, convert to \\
                result.append('\\\\')
                i += 1
        else:
            # Normal character
            result.append(text[i])
            i += 1
    return "".join(result)

analysis_prompt = load_prompt(prompt_full_path)
if not analysis_prompt:
    exit()
for INPUT_JSON_FILENAME in ALL_INPUT_JSON_FILENAME:

    library=INPUT_JSON_FILENAME.split("_")[-1].split(".")[-2]

    issue_data = read_json_file(INPUT_JSON_FILENAME)
    if not issue_data:
        exit()

    extracted_test_cases = []
    if os.path.exists(OUTPUT_JSON_FILENAME):
        try:
            with open(OUTPUT_JSON_FILENAME, 'r', encoding='utf-8') as f:
                content = f.read()
                if content.strip():
                    loaded_data = json.loads(content)
                    if isinstance(loaded_data, list):
                        for item in loaded_data:
                             if isinstance(item, dict) and 'num' in item and 'issue' in item and isinstance(item['issue'], dict):
                                 extracted_test_cases.append(item)
                             else:
                                 print(f"Skipping non-standard format data in existing file: {item}")
                        print(f"Loaded {len(extracted_test_cases)} existing test cases from {OUTPUT_JSON_FILENAME}")
                    else:
                        print(f"Warning: Content in {OUTPUT_JSON_FILENAME} is not a list. Starting fresh.")
                else:
                    print(f"{OUTPUT_JSON_FILENAME} is empty. Starting fresh.")
        except (json.JSONDecodeError, Exception) as e:
            print(f"Warning: Error reading or parsing {OUTPUT_JSON_FILENAME}: {e}. Starting fresh.")
    else:
        print(f"{OUTPUT_JSON_FILENAME} not found. Creating a new test case list.")

    processed_count = 0
    issues_to_process = len(issue_data)
    for record in issue_data:
        processed_count += 1
        issue_number_val = record.get("issue_number", record.get("num", "N/A"))
        issue_number_str = str(issue_number_val)

        title = record.get("title", "No title provided")
        body = record.get("body", "")

        print(f"\nProcessing Issue {processed_count}/{issues_to_process} (#{issue_number_str}): {title[:80]}...")

        if body:
            body = body.encode('utf-8')[:4000].decode('utf-8', 'ignore')

        retry_count = 0
        response_text = None
        while retry_count < API_RETRY_LIMIT:
            try:
                full_prompt = f"{analysis_prompt}Issue title: '{title}'body:'{body},'"
                response = model.generate_content(full_prompt)
                raw_text = response.text.strip()
                if raw_text.startswith("```json"):
                    raw_text = raw_text[len("```json"):].strip()
                if raw_text.endswith("```"):
                    raw_text = raw_text[:-len("```")].strip()
                response_text = raw_text.strip()
                break
            except Exception as e:
                retry_count += 1
                print(f"  Error calling Gemini API (Attempt {retry_count}/{API_RETRY_LIMIT}) for issue #{issue_number_str}: {e}")
                if retry_count < API_RETRY_LIMIT:
                    print(f"  Retrying in {API_SLEEP_DURATION} seconds...")
                    time.sleep(API_SLEEP_DURATION)
                else:
                    print(f"  Failed to get response for issue #{issue_number_str} after {API_RETRY_LIMIT} attempts.")
                    response_text = None

        if response_text:
            fixed_response_text = fix_invalid_json_escapes(response_text)

            try:
                parsed_json = json.loads(fixed_response_text)

                if isinstance(parsed_json, dict):
                    keys_to_remove = []

                    if "create Issuer Alternative Name" in parsed_json and isinstance(parsed_json["create Issuer Alternative Name"], dict) and parsed_json["create Issuer Alternative Name"] == DEFAULT_ISSUER_ALT_NAME:
                        print(f"  Removing default 'create Issuer Alternative Name' for issue #{issue_number_str}.")
                        keys_to_remove.append("create Issuer Alternative Name")

                    if "create authorityKeyIdentifier" in parsed_json and isinstance(parsed_json["create authorityKeyIdentifier"], dict) and parsed_json["create authorityKeyIdentifier"] == DEFAULT_AKI:
                         print(f"  Removing default 'create authorityKeyIdentifier' for issue #{issue_number_str}.")
                         keys_to_remove.append("create authorityKeyIdentifier")

                    for key in keys_to_remove:
                        del parsed_json[key]

                if isinstance(parsed_json, dict) and parsed_json:
                    print(f"  Successfully extracted information from issue #{issue_number_str} after filtering.")
                    data = {
                        'num': library+issue_number_str,
                        "issue": parsed_json
                    }
                    extracted_test_cases.append(data)
                elif isinstance(parsed_json, dict) and not parsed_json:
                    print(f"  LLM indicated no relevant information found (returned empty JSON object '{{}}') for issue #{issue_number_str} after filtering.")
                else:
                     print(f"  Warning: LLM response for issue #{issue_number_str} parsed to JSON, but it's not a dictionary after filtering. Skipping this entry. Fixed response: {fixed_response_text}")
            except json.JSONDecodeError as e:
                print(f"  Error: Could not parse JSON response from LLM for issue #{issue_number_str} even after fixing escapes. Error: {e}. Raw response: {response_text}") # 打印原始响应以便调试
            except Exception as e:
                print(f"  An unexpected error occurred processing response for issue #{issue_number_str}: {e}")
        else:
            print(f"  Skipping issue #{issue_number_str} due to API call failure or empty response.")

        time.sleep(1)
    try:

        output_dir = os.path.dirname(OUTPUT_JSON_FILENAME)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"Created output directory: {output_dir}")

        output_full_path = os.path.join(script_dir, OUTPUT_JSON_FILENAME)

        with open(output_full_path, 'w', encoding='utf-8') as f:
            json.dump(extracted_test_cases, f, indent=4, ensure_ascii=False)
        print(f"\nSuccessfully saved {len(extracted_test_cases)} extracted test cases to {output_full_path}")
        saved+=len(extracted_test_cases)
    except Exception as e:
        print(f"\nError writing results to {output_full_path}: {e}")

print("\nProcessing complete.")

print(f"\nSuccessfully saved {saved} extracted test cases to {output_full_path}")

end_time = time.time()
print(f"Execution time for LLM to obtain mutation instructions: {end_time - start_time} seconds")