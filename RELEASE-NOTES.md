DigiDoc C library [3.10.4](https://github.com/open-eid/libdigidocpp/releases/tag/v3.10.4) release notes
-----------------------------------
- OpenSSL 1.1 support

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.10.3...v3.10.4)

DigiDoc C library [3.10.3](https://github.com/open-eid/libdigidocpp/releases/tag/v3.10.3) release notes
-----------------------------------
- Minor changes to allow build openssl 1.0 under OSX

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.10.2...v3.10.3)

DigiDoc C library [3.10.2](https://github.com/open-eid/libdigidocpp/releases/tag/v3.10.2) release notes
-----------------------------------
- Added ESTEID-SK 2015 certificate
- Fixed OSX crash

[Full Changelog](https://github.com/open-eid/libdigidocpp/compare/v3.10.1...v3.10.2)

DigiDoc C library 3.10.1 release notes
-----------------------------------
Changes compared to ver 3.10

- Fixed ddoc format and version checking. The unfixed library can crash when reading a ddoc file with unknown format and/or version value. Sertifitseerimiskeskus and RIA thank Aivar Liimets for his contribution.
- Fixed validation of DDOC 1.0-1.2 documents that were created with older version of DigiDoc3 Client (with only DDOC 1.0 format support) on Ubuntu and OSX due to incompatibility with OpenSSL base library openssl_1.0.1f. (IB-3997)



DigiDoc C library 3.10 release notes
-----------------------------------
Changes compared to ver 3.9.1

- Changed validation process of OCSP response so that the responder’s certificate reference is taken from the response instead of the signature’s XML. 
- Improved DDOC document validation. It is now checked that the issuance time of the OCSP response would be in the validity period of the signer's certificate.
- Changed the validation of DDOC documents so that multiple data files with the same name would be allowed in the container.
- Improved utility program's output during DDOC document validation. If the signer's certificate is from live CA chain but OCSP confirmation has been issued from test OCSP responder then warning 172 "Signer from LIVE CA-chain but OCSP from TEST CA-chain!" is returned. 
- Removed duplicate configuration file entry CA_CERT_6 to fix KLASS3-SK 2010 (KLASS3-SK 2010 EECCRCA.crt) certificate's configuration settings.
- Removed Finnish CA certificates from digidoc.ini default configuration file. It is recommended to use BDOC format and relevant software instead.
- Development of the software can now be monitored in GitHub environment: https://github.com/open-eid/libdigidoc

Known issues:
- Validation of documents in DDOC 1.0 format fails on Ubuntu LTS upgrade 14.4.1 and newer due to incompatibility in OpenSSL base library openssl_1.0.1f-1ubuntu2.8. The problem does not occur on Ubuntu 14.4 with openssl_1.0.1f-1ubuntu2.7, OSX and Windows platforms.



DigiDoc C library 3.9.1 release notes
-----------------------------------
Changes compared to ver 3.9

- DDOC security fixes:
	- Improved XML structure validation for DDOC files. This is a highly relevant security fix having an effect on the validation of DDOC files. The unfixed library can mistakenly give positive results on validation of invalid DDOC files with incorrect XML elements' ordering.



DigiDoc C library 3.9 release notes
-----------------------------------
Changes compared to ver 3.8

- Improved checking of signer certificate's CA chain length during signature creation and validation. Previously it was not possible to create signature if there was only one CA certificate in the certificate chain.
- Improved DDOC files' validation, added check that the signer certificate's data would match the X509SerialNumber and X509IssuerName elements' contents.
- Improved DDOC files validation, added check for Transforms elements which are not supported in DDOC files.
- Changed signature adding and removal restrictions in case of erroneous files (incl. files that are valid with warnings). No restrictions are made to adding or removing signatures, except of in case of files that are in old format (DIGIDOC-XML 1.0, 1.1, 1.2).
- Fixed error of handling quotation marks in ClaimedRole and SignatureProductionPlace elements during signature creation and validation. Quotation marks are not replaced during canonicalization according to Canonical XML Version 1.0. Note that as a result, the files that contain quotation marks in the respective elements and have been created with v3.9 might not be compatible with v3.8 of the library.
- Fixed handling of special characters <, >, & and carriage return in X509IssuerName and ResponderID elements. The characters are now replaced during canonicalization according to Canonical XML Version 1.0. Note that as a result, the files that contain these special characters in the respective elements and have been created with v3.9 might not be compatible with v3.8 of the library.
- Fixed error which occurred when parsing DDOC document's data file name that contains '&' special character. Previously, the character was erroneously displayed in escaped form.
- Fixed error that occurred during signature creation when Windows redirected directories were used. Occasionally, writing the ddoc file to redirected directory did not succeed due to synchronization problems.
- Fixed error that caused the library to exit unexpectedly when trying to parse a DDOC file that contained a large number of validation errors.
- Changed compression functionality during CDOC encryption process to deprecated, by default the data is never compressed. Removed DENC_COMPRESS_MODE configuration file parameter.
- Updated cdigidoc.exe utility program's commands "-encrypt-sk", "-encrypt-file" and "-encrypt" so that "MimeType", "OriginalMimeType" and "orig_file" encryption properties are set according to CDOC 1.0 specification.
- Changed ddsGetStatus() function in DigiDocService.h source file to deprecated status, use ddsGetStatusWithFile() instead. The ddsGetStatusWithFile() function enables to determine the DDOC file name to which the signature value is added.
- Added command "-mid-test" to cdigidoc-exe utility program, to be used for testing purposes only. The command enables to test the whole Mobile-ID signing process, including creating new DDOC container, adding data file, creating signature, validating the created signature and extracting data files.
- Fixed cdigidoc utility program's "-libraryerrors" parameter functionality. When the parameter is set then only the errors that are returned by the library are now displayed as "LIBRARY-ERROR". 
- Used coverity.com static analysis tool to find source code defects and vulnerabilities.



DigiDoc C library 3.8 release notes
-----------------------------------
Changes compared to ver 3.7.2

- Started using coverity.com static analysis tool to find source code defects and vulnerabilities. Fixed resource leak and NULL pointer problems that were discovered.
- Fixed createDataFileInMemory() method, added fixed SHA-1 digest type value when creating new data file.
- Added support for new KLASS3-SK 2010 CA certificate.
- Improved the validation of signer's certificate path, added check if all of the chain's certificates validity period includes the signature creation time (producedAt field's value in OCSP response).
- Improved error handling in case of missing CA certificates and certificates in wrong format, error code 36 is returned in this case. Only PEM format is supported for CA certificates.	
- Added support for extracting data files from container so that the data is kept only in internal memory buffers. Added command –extract-mem to cdigidoc.c utility program.
- Added validation support for DDOC signatures that are created with Finnish live and test certificates. The certificate files have to be installed with separate packages. The live certificates package contains Finnish root CA certificate (http://fineid.fi/default.aspx?id=596) and certificates which are included in the Finnish national Trust Service List (TSL) (https://www.viestintavirasto.fi/attachments/TSL-Ficora.xml). Finnish test certificates (http://fineid.fi/default.aspx?id=597) are included in the overall test certificates package.  
- Fixed error handling in case of NULL values in DDOC file’s format and version variables. Acknowledgements. Sertifitseerimiskeskus and RIA thank Aivar Liimets for his contribution.
- Added possibility get all validation error codes that were found during DDOC file’s parsing and validation process instead of only one error code returned by the validation function verifySignatureAndNotary(). Added error code 173, which is returned in case of multiple errors. Library user must check the list of multiple errors by using new API functions getLastErrorsIdx(), getErrorsInfo() (in source file DigiDocError.c). 
- Added warnings system to the library. In case of minor technical errors in the signed DigiDoc file, validation result VALID WITH WARNINGS is used, meaning that the file is legally valid but further alterations (adding/removing signatures) are restricted. It is recommended for the programmers to implement the usage validation status VALID WITH WARNINGS as described in documentation. The warnings system is implemented in cdigidoc.c utility program (identically to DigiDoc3 Client desktop applicaton), warning situations include:
	- DDOC file's <DataFile> element's xmlns attribute is missing (error code 169) 
	- The DigiDoc file format is older than officially accepted, i.e. the file is DDOC 1.0, 1.1, 1.2 (error code 171).
	- DDOC file's <X509IssuerName> or <X509SerialNumber> element's xmlns attribute is missing (error code 170).
	- The signature has been created with a test certificate (error code 172).
- Changed the priorities of DigiDoc file's validation result statuses.
- Added error codes 168 (ERR_DF_NAME), 169 (ERR_DF_WRONG_DIG), 170 (ERR_ISSUER_XMLNS), 171 (ERR_OLD_VERSION), 172 (ERR_TEST_SIGNATURE), 173 (ERR_UNKNOWN_ERROR).
- Fixed nonce asn.1 prefix verification if nonce has no prefix but first 2 bytes match required prefix value.
- Added validation check of signer’s roles. Maximum 2 <ClaimedRole> elements are supported by the library in a DDOC file.
- Added check for duplicate <DataFile> element’s fileName attribute. Multiple data files with the same file name in a single container are not supported.
- Improved <DataFile> element's Id attribute validation. Added support for <DataFile> element’s Id attribute value DO (capital O, not zero).
- Improved error handling of invalid DDOC files with a missing <DataFile> element. Error 44 ERR_BAD_DATAFILE_COUNT is produced in case of such files.
- Fixed CDOC file’s <EncryptionProperty Name="DocumentFormat"> element’s value, ENCDOC-XML 1.0 is used instead of ENCDOC-XML 1.1.
- Fixed –validate command’s output in cdigidoc.c utility program to show validation result correctly in case if one signature among multiple signatures is erroneous. 
- Removed -list command line parameter from cdigidoc.c utility program, changed -verify command so that it replaces the –list command (validates the file and also prints out the data file list). 
- Fixed error handling in cdigidoc.c utility program if input DDOC file name contained also “.cdoc” in the file’s name.
- It is not allowed to add or remove signatures from DigiDoc files with missing <DataFile> element’s xmlns attribute.
- Removed configuration file parameter CHECK_SIGNATURE_VALUE_ASN1. Signature values with erroneous ASN.1 prefix values are regarded as not valid.
- Changed function verifiedByWrongDataFileHash() to deprecated.

- DDOC/CDOC security fixes:
- Added check that <DigestValue> and <ClaimedRole> elements that are verified are within signed content. This is a highly relevant security fix. Without this fix malicious ddoc files with data not signed by original signer but added by third parties later could have been verified to be valid. 
- Fixed validation of OCSP response, added check that the OCSP response corresponds to the signer’s certificate. This is a highly relevant security fix. Without this fix specially generated ddoc file with changed OCSP response could have been verified to be valid.
- Changed process of searching for CA certificates. The certificates are searched from the secure Program Files directory that is specified with CA_CERT_PATH configuration file parameter, not from the working directory. This is a highly relevant security fix. Without this fix, CA certificate files that may have been added to the working directory with malicious intent would be used by the library.
- Fixed the opening of DDOC container with a faulty <DigestValue> tag. This is a highly relevant security fix that has an effect on the validation of DDOC files. Acknowledgements. Sertifitseerimiskeskus and RIA thank Aivar Liimets for his contribution.



DigiDoc C library 3.7.2 release notes
--------------------------------------
Changes compared to ver 3.7.1.992

- DDOC/CDOC security fixes:
  - Fixed the opening of DDOC container with a faulty DataFile name tag. This is a highly relevant security fix having an effect on the verification of DDOC files. The unfixed library can result in overwrite arbitrary files on the system with the privileges of the victim.

  

DigiDoc C library 3.7.1 release notes
-----------------------------------
Changes compared to ver 3.7.0.910

- Changed the handling of DigiDoc container which has no xmlns attribute in the <DataFile> element.



DigiDoc C library 3.7 release notes
-----------------------------------
Changes compared to ver 3.6.0.26

- Added the support of slot choice option for CDOC decryption with utility
- Fixed the search of the signer’s certificate issuer for DDOC verification
- Fixed the OCSP hash check error handling for DDOC verification: error messages are correct when there are several errors associated with a container
- Fixed the error handling of the DDOC verification function verifySignatureInfoCERT 
- Added the decrypted transport key option for testing CDOC decryption with utility
- Fixed padding control for CDOC
- Fixed padding handling of CDOC PKCS#7: now PKCS#7 padding is managed by the openssl
- Fixed the DDOC signing function ddocLocateSlotWithSignatureCert: the use of the digital stamp has improved
- Fixed the OCSP response handling for DDOC signing
- Fixed CDOC packaging according xml-enc standard
- Fixed the handling of the initial CDOC file name: the directory path is not added to the CDOC container
- Fixed the handling of special characters in the CDOC decryption
- Added Mac OSX keychain support for OCSP server access certificates in DDOC signing
- Fixed the error handling of DDOC verification in case of the lack of issuer certificates
- Fixed the DDOC verification function readAuthorityKeyIdentifier
- Added the function signDocumentWithSlotAndSigner to the signing of DDOC to allow signature over CAPI/CNG
- Added the support of signing DDOC files in the memory: no temporary files are saved
- Added the support of encryption and decryption of CDOC in the memory: no temporary files are saved
- Fixed the logic of the xmlns mirroring in the XML root element in the DDOC signing and verification 
- Added the PKCS12 support for DDOC signing
- Fixed the EVP_DecodeUpdate CDOC decryption function: buffer size improvement
- Fixed the notarizeSignatureWithIp and finalizeAndVerifyNotary2 functions for DDOC signing and verification: the setting is supported if the ocsp responder certificate has been issued from another chain than the signer’s certificate
- Fixed the hash description handling of the ASN.1 signature value for DDOC signing and verification: 13-byte and 15-byte values are supported
- Added BOM (Byte order mark) support on DDOC verification
- Fixed error handling of the missing OCSP responder certificate for DDOC verification 
- Removed support for DDOC format version 1.0, 1.1, 1.2 for DDOC signing. Only DDOC verification and exctracting files from container are supported. Creating container, signing and removing signature are not supported

 
- DDOC/CDOC security fixes:
  - Added the check of the ASN.1 structure of the nonce field for DDOC signing and verification. This is a highly relevant security fix having an effect on the verification of DDOC files. The unfixed library can mistakenly give positive results on verificaton invalid DDOC container with wrong ASN.1 structure on the nonce field.
  - Added the check of the ASN.1 structure of the signature value for DDOC signing and verification. This is a highly relevant security fix having an effect on the verification of DDOC files. The unfixed library can mistakenly give positive results on verificaton invalid DDOC container with wrong ASN.1 structure on the  signature value. 
  - Added the check of the nonce field of the signature for DDOC signing and verification. This is a highly relevant security fix having an effect on the verification of DDOC files. The unfixed library can mistakenly give positive results on verificaton invalid DDOC container with the wrong nonce field value on the signature.
  - Removed the EMBEDDED type DDOC file support for verification. This is a highly relevant security fix having an effect on the verification of DDOC files. The unfixed library can mistakenly give positive results on verificaton invalid EMBEDDED type DDOC container.
  - Fixed the signature verification of a DDOC with a faulty DataFile tag. This is a highly relevant security fix having an effect on the verification of DDOC files. The unfixed library can result in the crashing of the application or unauthorized code execution in opening of a DDOC file created with malicious intent.





DigiDoc C library 3.6 release notes
-----------------------------------
Changes compared to ver 2.6.0.18

- Changes according ETSI Plug test results
- Changes according Cross library (jdigidoc & libdigidoc & libdigidocpp) test results (DDOC, CDOC)
- Removed DETACHED, HASHCODE, DDOC 1.4, BDOC support
- CDOC padding improvements
- Updated documentation in doc folder SK-CDD-PRG-GUIDE
- Support for software based private keys
- Versioning switched to same schema (3.5, 3.6 ...) as other middleware components
- Added Mobiil-ID signing support for cdigidoc utility
- API change in functions dencOrigContent_findByIndex, dencMetaInfo_GetLibVersion, dencMetaInfo_GetFormatVersion
- DDOC/CDOC security updates:
  - Fix for decrypting or content viewing of CDOC files with broken orig_file tag. This is a significant security fix which affects CDOC decrypting. A library without this security fix can cause application crashes or allow running malicious code upon opening a deliberately created CDOC file.
  - Fix for decrypting or content viewing of CDOC files with broken EncryptionProperty tag. This is a significant security fix which affects CDOC decrypting. A library without this security fix can cause application crashes or allow running malicious code upon opening a deliberately created CDOC file
  - DigiDocService intermediate resultate file (DDOC file hashcode) verification fix. This is a significant security fix which affects verification of DDOC files. A library without this security fix can mistakenly give positive results on verificaton of invalid DDOC hashcode container.
  - Detached DDOC file verification fix. This is a significant security fix which affects verification of DDOC files. A library without this security fix can mistakenly give positive results on verificaton of invalid DDOC container.
  - Added key usage check in certificate on verification of a signature. This is a significant security fix which affects verification of DDOC files. A library without this security fix can mistakenly give positive results on verificaton of a signature created with incorrect certificate.
