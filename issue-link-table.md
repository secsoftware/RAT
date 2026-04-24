## report

| Number | TLS | Title | Link | State |
| ------ | ------ | ------------------------------------------------------------ | :------------------------------------------------ | --------------------------- |
| 1 | Cryptography | Cryptography parsed the CRL file with an empty Key Identifier. | https://github.com/pyca/cryptography/issues/13051 | Awaiting developer handling |
| 2 | Cryptography | Cryptography accepted a CRL file with the certificate_issuer extension but without the IDP extension. | https://github.com/pyca/cryptography/issues/12788 | Awaiting developer handling |
| 3 | Cryptography | Cryptography analyzes the IssuerAlternativeName extension with non-standard URI names. | https://github.com/pyca/cryptography/issues/12782 | Awaiting developer handling |
| 4 | Cryptography | The cryptography library parsed a CRL file with duplicate revoked certificate entries. | https://github.com/pyca/cryptography/issues/12780 | Awaiting developer handling |
| 5 | Cryptography | The cryptography system parsed a CRL file that contains a revoked certificate with a serial number of 0. | https://github.com/pyca/cryptography/issues/12771 | x509, fixed |
| 6 | Cryptography | Cryptography parsed a CRL file with the authorityCertSerialNumber set to 0. | https://github.com/pyca/cryptography/issues/12748 | x509, fixed |
| 7 | Cryptography | Cryptography parsed the '<>' symbols stored in PrintableString. | https://github.com/pyca/cryptography/issues/12698 | x509, fixed |
| 8 | GnuTLS | RFC 5280 compliance: GnuTLS accepts CRL files with duplicate revoked entries or duplicate certificate serial numbers | https://gitlab.com/gnutls/gnutls/-/issues/1704 | To do |
| 9 | GnuTLS | RFC 5280 compliance:GeneralizedTime parser accepts incorrect time values. | https://gitlab.com/gnutls/gnutls/-/issues/1702 | To do |
| 10 | GnuTLS | GnuTLS parsed the '<>' symbols stored in PrintableString. | https://gitlab.com/gnutls/gnutls/-/issues/1698 | To do |
| 11 | GnuTLS | RFC 5280 compliance:GnuTLS parsed a CRL file with the authorityCertSerialNumber set to 0. | https://gitlab.com/gnutls/gnutls/-/issues/1692 | To do |
| 12 | GnuTLS | RFC 5280 compliance: GeneralizedTime parser accepts value without seconds field | https://gitlab.com/gnutls/gnutls/-/issues/1688 | To do |
| 13 | GnuTLS | RFC 5280 compliance:GnuTLS accepted an incorrect UTC time value. | https://gitlab.com/gnutls/gnutls/-/issues/1675 | To do |
| 14 | GnuTLS | RFC 5280 compliance: UTCTime parser accepts value without seconds field | https://gitlab.com/gnutls/gnutls/-/issues/1638 | enhancement |
| 15 | GnuTLS | Gnutls reports an error for the authority_key_id in a CRL file. | https://gitlab.com/gnutls/gnutls/-/issues/1716 | To do |
| 16 | GnuTLS | RFC 5280 compliance:GnuTLS incorrectly parsed the authorityCertSerialNumber value. | https://gitlab.com/gnutls/gnutls/-/issues/1700 | To do |
| 17 | GnuTLS | RFC 5280 compliance:GnuTLS incorrectly handles the CRL Number field | https://gitlab.com/gnutls/gnutls/-/issues/1684 | To do |
| 18 | GnuTLS | RFC 5280 compliance:GnuTLS cannot parse the Country value encoded in UTF8String. | https://gitlab.com/gnutls/gnutls/-/issues/1676 | To do |
| 19 | OpenSSL | OpenSSL accepted the CRL file with an empty Key Identifier. | https://github.com/openssl/openssl/issues/27474 | Fixed but not labeled |
| 20 | OpenSSL | OpenSSL accepted a CRL file with the Certificate Issuer extension but without the IDP extension. | https://github.com/openssl/openssl/issues/27465 | feature |
| 21 | OpenSSL | OpenSSL parsed the IssuerAlternativeName extension with non-standard URI names. | https://github.com/openssl/openssl/issues/27449 | Awaiting developer handling |
| 22 | OpenSSL | OpenSSL parsed a CRL file with an incorrect Invalidity Date field value. | https://github.com/openssl/openssl/issues/27445 | bug |
| 23 | OpenSSL | The OpenSSL parsed a CRL file with duplicate revoked certificate entries or serial numbers | https://github.com/openssl/openssl/issues/27444 | feature |
| 24 | OpenSSL | OpenSSL silently ignores parse errors on Delta CRL Indicator and CRL Number extensions | https://github.com/openssl/openssl/issues/27374 | bug |
| 25 | OpenSSL | OpenSSL parsed a CRL file where both onlyContainsUserCerts and onlyContainsCACerts are set to True | https://github.com/openssl/openssl/issues/27334 | feature, fixed |
| 26 | OpenSSL | OpenSSL parsed a CRL file with the authorityCertSerialNumber set to 0. | https://github.com/openssl/openssl/issues/27321 | Fixed but not labeled |
| 27 | OpenSSL | The OpenSSL parsed a GeneralName with an incorrect tag. | https://github.com/openssl/openssl/issues/27251 | feature, fixed |
| 28 | OpenSSL | OpenSSL accepted a CRL file with an invalid AKI extension. | https://github.com/openssl/openssl/issues/27114 | feature |
| 29 | OpenSSL | The handling of the CRL Number field by OpenSSL | https://github.com/openssl/openssl/issues/27085 | feature |
| 30 | OpenSSL | OpenSSL successfully parsed a CRL file with two identical AKI extensions. | https://github.com/openssl/openssl/issues/26661 | feature, fixed |
| 31 | OpenSSL | OpenSSL accepts the IDP extension with DER encoding as an empty sequence | https://github.com/openssl/openssl/issues/27506 | bug, fixed |
| 32 | OpenSSL | The OpenSSL parsed a revoked certificate with a reason code of 7 | https://github.com/openssl/openssl/issues/27433 | feature |
| 33 | OpenSSL | OpenSSL parsed a CRL file with a revocation serial number that is a non-positive integer. | https://github.com/openssl/openssl/issues/27416 | feature |
| 34 | OpenSSL | OpenSSL incorrectly parsed the authorityCertSerialNumber value. | https://github.com/openssl/openssl/issues/27406 | bug, fixed |
| 35 | OpenSSL | OpenSSL cannot correctly parse the authorityCertIssuer field containing the characters Ö and ü. | https://github.com/openssl/openssl/issues/27207 | feature, fixed |
| 36 | OpenSSL | OpenSSL incorrectly parsed the authorityCertIssuer field information containing Chinese characters | https://github.com/openssl/openssl/issues/27196 | feature, fixed |
| 37 | OpenSSL | The AKI extension marked as critical | https://github.com/openssl/openssl/issues/27160 | Fixed but not labeled |
| 38 | OpenSSL | The issuer field of an empty DN. | https://github.com/openssl/openssl/issues/26951 | Awaiting developer handling |
| 39 | golang | crypto/x509: ParseRevocationList accepted the CRL file with an empty Key Identifier | https://github.com/golang/go/issues/74033 | Needslnvestigation |
| 40 | golang | crypto/x509: ParseCRL allows CRL files to have duplicate revoked entries and duplicate certificate serial numbers. | https://github.com/golang/go/issues/73452 | Needslnvestigation  |
| 41 | golang | crypto/x509: ParseCRL allows the Invalidity Date of revoked certificates in the CRL to be UTC time | https://github.com/golang/go/issues/73442 | Needslnvestigation |
| 42 | golang | crypto/x509: ParseCRL allows revocation serial number that is a non-positive integer | https://github.com/golang/go/issues/73433 | Needslnvestigation |
| 43 | golang | crypto/x509: ParseRevocationList accepts having both onlyContainsUserCerts and onlyContainsCACerts set to true | https://github.com/golang/go/issues/73308 | Needslnvestigation |
| 44 | golang | crypto/x509: ParseRevocationList accepts authorityCertSerialNumber set to 0 | https://github.com/golang/go/issues/73293 | Needslnvestigation |
| 45 | golang | crypto/x509: ParseRevocationList accepts a GeneralName with an incorrect tag | https://github.com/golang/go/issues/73285 | Needslnvestigation |
| 46 | golang | crypto/x509: ParseRevocationList accepts the IDP extension with DER encoding as an empty sequence | https://github.com/golang/go/issues/73284 | Needslnvestigation |
| 47 | golang | crypto/x509: ParseRevocationList accepts two AKI extensions | https://github.com/golang/go/issues/73051 | Needslnvestigation |
| 48 | golang | crypto/x509: ParseRevocationList accepts invalid AKI extension in CRL | https://github.com/golang/go/issues/73030 | Needslnvestigation |
| 49 | golang | crypto/x509: ParseRevocationList incorrect handling of the CRL Number field | https://github.com/golang/go/issues/73029 | Needslnvestigation |
| 50 | golang | crypto/x509: ParseRevocationList accepts DN with all empty values | https://github.com/golang/go/issues/73021 | Needslnvestigation |
| 51 | golang | crypto/x509: ParseRevocationList accepts invalid thisUpdate UTCTimes without seconds | https://github.com/golang/go/issues/73019 | Needslnvestigation |
| 52 | wolfSSL | wolfSSL accepts the incorrect GeneralizedTime value. | https://github.com/wolfSSL/wolfssl/issues/8597 | bug, fixed |
| 53 | wolfSSL | WolfSSL parsed a CRL file with a negative CRL number value. | https://github.com/wolfSSL/wolfssl/issues/8676 | bug, fixed |
| 54 | wolfSSL | WolfSSL parsed the '<>' symbols stored in PrintableString. | https://github.com/wolfSSL/wolfssl/issues/8656 | Awaiting developer handling |
| 55 | wolfSSL | The wolfSSL incorrectly handled the keyIdentifier field | https://github.com/wolfSSL/wolfssl/issues/8625 | bug |
| 56 | wolfSSL | wolfSSL cannot correctly process CRL files with extensions. | https://github.com/wolfSSL/wolfssl/issues/8574 | bug, fixed |
| 57 | wolfSSL | wolfSSL is unable to parse the authorityCertIssuer and authorityCertSerialNumber fields in the AKI extension of the CRL file | https://github.com/wolfSSL/wolfssl/issues/8605 | Awaiting developer handling |
| 58 | wolfSSL | Two AKI extensions | https://github.com/wolfSSL/wolfssl/issues/8591 | bug, fixed |
| 59 | wolfSSL | CRL Issuer field with an empty DN | https://github.com/wolfSSL/wolfssl/issues/8529 | Awaiting developer handling |
| 60 | wolfSSL | wolfSSL is unable to correctly process the CRL serial number field. | https://github.com/wolfSSL/wolfCLU/issues/174 | bug, fixed |