An example of a mutation directive is as follows. The `"num":"opensslxxxxx"` indicates that the mutation values are derived from the GitHub issue with OpenSSL ID `xxxxx`. The `"create authorityKeyIdentifier": "KeyIdentifier": ""}` specifies creating an authorityKeyIdentifier extension with an empty KeyIdentifier value. The `"issuer": "C=XX, ..."` means assigning the given distinguished name, i.e., `C=XX, ...` to the issuer field.

        {
            "num":"opensslxxxxx",
            "issue":{
                    "create authorityKeyIdentifier":{
                        "KeyIdentifier":""
                     },
                    "issuer":"C=XX, O=XX-CA, OU=Root CA, CN=XXCA Global Root CA"
            }
        },