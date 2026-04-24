To accomplish the following five sequential tasks: (1) generating code for crawling GitHub issues, (2) analyzing whether the issues involve bugs related to certificate parsing or validation, (3) generating mutation directives from the analysis results to guide CRL mutations, (4) normalizing the mutated CRLs produced by applying the mutation directives into a canonical format, and (5) evaluating whether the normalized CRLs comply with the RFC 5280 specification, we designed five corresponding prompt sections, each instructing the LLM to perform one specific task. Relevant guidelines and precautions are clearly stated in every prompt section.

(1) Prompt Section I instructs the LLM to generate code for crawling GitHub issues.
    
    Begin of Prompt Section I.
    
    Role: Python Developer. 
    
    Task: Scrape GitHub issues from specific repos to detect certificate bugs via Gemini AI.
    
    Tech Stack: Selenium (Login/Scraping), Requests (Issue Details), Google Generative AI, BeautifulSoup, and JSON.
    
    Target Repos: [openssl/openssl, bouncycastle/bc-java, pyca/cryptography, golang/go, wolfSSL/wolfssl].
    
    Process:
    
    1. Setup: Config vars for Github Creds, API Keys, Chrome Path, Repo List (owner, repo, start_page, end_page).
    
    2. Login: Selenium to github.com/login, wait 60s after commit.
    
    3. Scrape IDs: Loop repos -> Loop pages. Extract Issue IDs using BS4 (Classes: issue-item-module__defaultNumberDescription--GXzri OR Link--primary).
    
    4. Get Details: Requests to api.github.com/repos/{owner}/{repo}/issues/{id}. Retry 10x. Truncate body to 3000 chars.
    
    5. AI Filter: Gemini 2.0 Flash. Rotate model instance every 2 reqs. Prompt: "Please analyze the following GitHub issue and determine whether it involves a bug related to certificate parsing or certificate validation. If it does, reply with True; if it does not, reply with False. Do not reply with anything other than True or False.Title: '{title}', Content: '{body}'".
    
    6. Save: Append valid issues to JSON (fields: repo_owner, repo_name, id, title, body).
    Constraints: Handle exceptions. Print logs. No extra libs.
    
    End of Prompt Section I.

(2) Prompt Section II directs the LLM to analyze whether the issues involve bugs related to certificate parsing or validation.

    Begin of Prompt Section II.
    
    Please analyze the following GitHub issue and determine whether it involves a bug related to certificate parsing or certificate validation. If it does, reply with True; if it does not, reply with False. Do not reply with anything other than True or False. Title: '{title}', Content: '{body}'.
    
    End of Prompt Section II.

(3) For the analysis results, Prompt Part III instructs the LLM to generate mutation directives in the form of JavaScript Object Notation (JSON) that specify the fields and mutated values.

    Begin of Prompt Section III.
    
    You are an X.509 certificate and Certificate Revocation List (CRL) expert, familiar with the RFC 5280 standard. Your task is to analyze GitHub Issue reports.

    I need you to analyze the reports and, based on the report content combined with the descriptions in the 6 examples below, return JSON information.

    Here are a few examples:
    Example 1:
    If an ASN.1 time value such as '#250102000000Z' appears in the report content, you can return:
    {
        "thisUpdate":"#250102000000Z"
    }

    Example 2:
    Extract a certificate serial number value from the report, and return the serial number value from the report in the following format:
    {
        "serial":"The certificate serial number value appearing in the report goes here"
    }

    Example 3: If certificate or CRL extension information appears in the report, please return it in the following format, if authorityKeyIdentifier or KeyIdentifier fields or Subject Key Identifier extensions appear (but remember, when the report is about the Subject Key Identifier extension, return the Subject Key Identifier extension value as the KeyIdentifier field value used to create the authorityKeyIdentifier):
    {
        "create authorityKeyIdentifier":{
        "KeyIdentifier":"The KeyIdentifier or Subject Key Identifier value that appears in the report. "
        }
    }

    Example 4: If the report involves the Issuer Alternative Name extension or the Subject Alternative Name extension, please always return according to the Issuer Alternative Name extension name, and the return format is:
    {
        "create Issuer Alternative Name":{
            "URI":"Here needs to be filled in the URI value mentioned in the report's Issuer Alternative Name extension or Subject Alternative Name extension, if not in the report return http://localhost:8080/crl.der",
            "DNS":"Here needs to be filled in the DNS value mentioned in the report's Issuer Alternative Name extension or Subject Alternative Name extension, if not in the report return test.local",
            "email":"Here needs to be filled in the email value mentioned in the report's Issuer Alternative Name extension or Subject Alternative Name extension, if not in the report return admin@test.local"
        }
    }

    Example 5: If the report contains certificate issuer field information, then return information according to the following format, only need to modify the corresponding field values that appear in the report:
    {
        "issuer":"CN=test, OU=test, O=test, L=test, ST=test, C=XX"
    }

    Example 6: If the report contains useful information for multiple fields or extensions, then return all of them, the format is the same as the previous 5 examples:
    {
        "thisUpdate":"The time value that appears in the report goes here",
        "serial":"The serial number that appears in the report goes here"
    }

    Please note: If a valid value for one example appears within the content related to another example (for instance, if a serial field value appears within the issuer field value), the value for the first example should still be extracted according to its format.

    If the issue report is not related to standard CRL fields or extensions, or certificate fields or extensions, or does not provide enough specific information to identify related fields/extensions, then output an empty JSON object: {}.

    Output only JSON objects, do not include other text.
    
    End of Prompt Section III.

(4) Prompt Section IV instructs the LLM to normalize the mutated CRLs generated by applying the mutation directives into a canonical format.

    Begin of Prompt Section IV.
    
    When executing this task, please proceed with the utmost rigor and strictly adhere to the requirements below.

    It is imperative that the returned values neither omit any information present in the parsing results, nor differ in any way from the values as they originally appear in the parsing results.

    I need you to extract information from CRL parsing results and return it in JSON format.

    Please note that since the values of the Issuer field and the Authority_Cert_Issuer field are similar, be careful not to confuse their values when returning their values.

    Below is an example of the JSON format:
    {
        "Tls_tool":"Enter the TLS name, such as openssl, cryptography, gnutls, wolfssl, and go, to be resolved here.";
        "thisUpdate":"Return the thisUpdate information using the YYYY-MM-DD HH:MM:SS format, ensuring the actual time value represented is the same as in the parsing result you are given.", 
        ...
        "Revoked_Cert_Invalidity_Date":"Return the Revoked_Cert_Invalidity_Date information using the YYYY-MM-DD HH:MM:SS format, ensuring the actual time value represented is the same as in the parsing result you are given."
    }

    Please note:

    Each returned key-value pair must be enclosed in double quotes, not single quotes.

    Different parsing results may display the same field names in different forms; analyze carefully.

    For field values that do not exist in the parsing result, set the value of the non-existent field to the string 'False'.

    If a field value in the parsing result you are given is already 'False', use 'False' as its value directly.

    Please note that you should only return the JSON, and each field value, apart from the specific value or the string 'False', should not contain any other content.

    Please note that the example below is only intended to demonstrate how to map values from the parsing results to JSON. Do not map any values that appear in the example but are absent in the parsing results I provided to you.

    Below is an example, using OpenSSL parsing results:
        Certificate Revocation List (CRL):
            Version 2 (0x1)
            ...
    The returned JSON should be:
    {
        "Tls_tool":"openssl",
        "thisUpdate":"2024-09-01 00:00:00",
        ...
    }

    Below is an example, using GnuTLS parsing results:
        X.509 Certificate Revocation List Information:
	    Version: 2
    The returned JSON should be:
    {
        "Tls_tool":"gnutls",
        "thisUpdate":"2024-09-01 00:00:00",
        ...
    }

    Below are the parsing results from 5 TLS tools. Please extract each of them into JSON format and return the information (Each returned JSON object is stored in a Python list).
    
    End of Prompt Section IV.

(5) Prompt Section V evaluates whether the normalized CRLs conform to the RFC 5280 specification.

    Begin of Prompt Section V.
    
    Does the field (e.g., CRL_number) value of this CRL file comply with the RFC5280 specification? Please return True if yes, or False if no.
    
    End of Prompt Section V.

