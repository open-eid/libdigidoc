.TH CDIGIDOC 1 "${BUILD_DATE}" "${VERSION}" "cdigidoc man page"
.SH NAME
cdigidoc \- read, digitally sign, verify files in XAdES format and encrypt, decrypt files in XMLENC format
.SH SYNOPSIS
.B cdigidoc <command(s)> [
.I -in <input-file>
.B ] [
.I -out <output-file>
.B ] [
.I -config <config-file>
.B ]
.SH DESCRIPTION
.B cdigidoc
is an utility which provides a command line interface to the CDigiDoc library, which is a library in C programming language offering the the functionality to create files in supported DigiDoc formats, sigitally sign the DigiDoc files using smart cards or other supported cryptographic tokens, add time marks and validity confirmations to digital signatures using OCSP protocol, verify the digital signatures, and digitally encrypt and decrypt the DigiDoc files. It is also possible to use cdigidoc utility as a CGI program in web applications created in environments that cannot easily use the JDigiDoc library or call the DigiDocService webservice for digital signature functionality.
.PP
For full documentation, see
.nf
https://svn.eesti.ee/projektid/idkaart_public/branches/3.6/libdigidoc/doc/SK-CDD-PRG-GUIDE.pdf
.PP
XAdES format
.nf
http://www.w3.org/TR/XAdES
.PP
XML-ENC format
http://www.w3.org/TR/xmlenc-core
.SH OPTIONS
.IP "-?, -help"
Displays help about command syntax.
.IP "-in <input-file>"
Specifies the input file name. It is recommended to pass the full path to the file in this parameter.
.IP "-out <output-file>"
Stores the newly created or modified document in a file.
.IP "-config <configuration-file>"
Specifies the CDigiDoc configuration file name. If left unspecified, then the configuration file is looked up from default locations.
.IP "-check-cert <certificate-file-in-pem-format>"
Checks the certificate validity status. Used for checking the chosen certificate’s validity; returns an OCSP response from the certificate’s CA’s OCSP responder. Note that the command is currently not being tested. If the certificate is valid, then the return code’s (RC) value is 0.
.IP "-new [format] [version]"
Creates a new digidoc container with the specified format and version. The current digidoc format in CDigiDoc library is DIGIDOC-XML, default version is 1.3 (newest). By using the optional parameter - version - with this command, you can specify an alternative version to be created. Note: the older SK-XML format is supported only for backward compatibility.
.IP "-add <input-file> <mime-type> [<content-type>] [<charset>]"
Adds a new data file to a digidoc document. If digidoc doesn't exist then creates one in the default format. 
.RS
.TP
Input file (required)
Specifies the name of the data file (it is recommended to include full path in this parameter; the path is removed when writing to DigiDoc container file). 
.TP
Mime type (required)
Represents the MIME type of the original file like "text/plain" or "application/msword". 
.TP
Content type
Reflects how the original files are embedded in the container EMBEDDED_BASE64 (used by default).
In previous versions cdigidoc allowed content type EMBEDDED to sign pure xml or text.
.TP
Charset
UTF-8 encoding is supported and used by default.
.RE
.IP "-sign <pin-code> [[[manifest] [[city] [state] [zip] [country]] [slot(0)] [ocsp(1)] [token-type(PKCS11)] [pkcs12-file-name]]"
Adds a digital signature to the digidoc document. You can use it with following parameters:
.RS
.TP
pin code
In case of Estonian ID cards, pin code2 is used for digital signing. If signing with a software token (PKCS#12 file), then the password of PKCS#12 file should be entered here.
.TP
manifest
Role or resolution of the signer
.TP
city
City where the signature is created
.TP
state
State or province where the signature is created
.TP
zip
Postal code of the place where the signature is created
.TP
country
Country of origin. ISO 3166-type 2-character country codes are used (e.g. EE)
.TP
slot
Identifier of the signer’s private key’s slot on a smartcard. When operating for example with a single Estonian ID card, its signature key can be found in slot 1 - which is used by default.
The library makes some assumptions about PKCS#11 drivers and card layouts:
 - you have signature and/or authentication keys on the card
 - both key and certificate are in one slot
 - if you have many keys like 1 signature and 1 authentication key then they are in different slots
 - you can sign with signature key that has a corresponding certificate with "NonRepudiation" bit set.
You may need to specify a different slot to be used when for example operating with multiple smart cards on the same system.
If the slot needs to be specified during signing, then the 5 previous optional parameters (manifest, city, state, zip, country) should be filled first (either with the appropriate data or as "" for no value). 
.TP
ocsp
Specifies whether an OCSP confirmation is added to the signature that is being created. Possible values are 0 - confirmation is not added; 1 - confirmation is added. By default, the value is set to 1.
Parameter value 0 can be used when creating a technical signature. Technical signature is a signature with no OCSP confirmation and no timestamp value. 
.TP
token type
Speciafies type of signature token to be use. 
 - PKCS11 default value. Signs with a smart-card or software pkcs11 token
 - CNG on windows platforms uses CSP/CNG for signing
 - PKCS12 signs with a PKCS#12 key container that must be entered in the next parameter
. TP
pkcs12 file name
Name of the PKCS#12 key container file to be used for signing.
.RE
.IP "-mid-sign <phone-no> <per-code> [[<country>(EE)] [<lang>(EST)] [<service>(Testing)] [<manifest>] [<city> <state> <zip>]]"
Invokes mobile signing of a ddoc file using Mobile-ID and DigiDocService. 
Mobile-ID is a service based on Wireless PKI providing for mobile authentication and digital signing, currently supported by all Estonian and some Lithuanian mobile operators. 
The Mobile-ID user gets a special SIM card with private keys on it. Hash to be signed is sent over the GSM network to the phone and the user shall enter PIN code to sign. The signed result is sent back over the air. 
DigiDocService is a SOAP-based web service, access to the service is IP-based and requires a written contract with provider of DigiDocService.
You can use Mobile-ID signing with the following parameters:
.RS
.TP
phone-no
Phone number of the signer with the country code in format +xxxxxxxxx (for example +3706234566)
.TP
per-code
Identification number of the signer (personal national ID number).
.TP
country
Country of origin. ISO 3166-type 2-character country codes are used (e.g. default is EE)
.TP
lang
Language for user dialog in mobile phone. 3-character capitalized acronyms are used (e.g. default is EST)
.TP
service
Name of the service – previously agreed with Application Provider and DigiDocService operator. Maximum length – 20 chars. (e.g. default is Testing)
.TP
manifest
Role or resolution of the signer
.TP
city
City where the signature is created
.TP
state
State or province where the signature is created
.TP
zip
Postal code of the place where the signature is created
.RE
.IP "-list"
Displays the data file and signature info of a DigiDoc document just read in; verifies all signatures.
.RS
.HP
Returns Digidoc container data, in format: SignedDoc | <format-identifier> | <version> 
.HP
List of all data files, in format: DataFile | <file identifier> | <file name> | <file size in bytes> | <mime type> | <data file embedding option>
.HP
List of all signatures (if existing), in format:  Signature | <signature identifier> | <signer’s key info: last name, first name, personal code> | <verification return code> | <verification result>
.HP
Signer’s certificate information.
.HP
OCSP responder certificate information
.RE
.IP "-verify"
Returns signature verification results (if signatures exist):
.RS
.HP
Signature | <signature identifier> | <signer’s key info: last name, first name, personal code> | <verification return code> | <verification result>
.HP
Returns signer’s certificate and OCSP Responder certificate information.
.RE
.IP "-extract <data-file-id> <output-file>"
Extracts the selected data file from the DigiDoc container and stores it in a file. 
Data file id represents the ID for data file to be extracted from inside the DigiDoc container (e.g. D0, D1…). Output file represents the name of the output file.

.IP "-denc-list <input-encrypted-file>"
Displays the encrypted data and recipient’s info of an encrypted document just read in. 
.IP "-encrecv <certificate-file> [recipient] [KeyName] [CarriedKeyName]"
Adds a new recipient certificate and other metadata to an encrypted document. Certificate file (required) specifies the file from which the public key component is fetched for encrypting the data. The decryption can be performed only by using private key corresponding to that certificate. The input certificate files for encryption must come from the file system (PEM encodings are supported). Possible sources where the certificate files can be obtained from include: Windows Certificate Store ("Other Persons"), LDAP directories, ID-card in smart-card reader. For example the certificate files for Estonian ID card owners can be retrieved from a LDAP directory at ldap://ldap.sk.ee. The query can be made in following format through the web browser (IE): ldap://ldap.sk.ee:389/c=EE??sub?(serialNumber= xxxxxxxxxxx) where serial Number is the recipient’s personal identification number, e,g.38307240240).
Other parameters include:
.RS
.TP
recipient
If left unspecified, then the program assigns the CN value of the certificate passwed as first parameter. 
This is later used as a command line option to identify the recipient whose key and smart card is used to decrypt the data. 
Note: 
Although this parameter is optional, it is recommended to pass on the entire CN value from the recipient’s certificate as the recipient identifier here, especially when dealing with multiple recipients.
.TP
KeyName
Sub-element <KeyName> can be added to better identify the key object. Optional, but can be used to search for the right recipient’s key or display its data in an application.
.TP
CarriedKeyName
Sub-element <CarriedKeyName> can be added to better identify the key object. Optional, but can be used to search for the right recipient’s key or display its data in an application. 
.RE

.IP "-encrypt-sk <input-file>"
Encrypts the data from the given input file and writes the completed encrypted document in a file. Recommended for providing cross-usability with other DigiDoc software components. 
This command places the data file to be encrypted in a new DigiDoc container. Therefore handling such encrypted documents later with other DigiDoc applications is fully supported (e.g. DigiDoc3 client).
Input file (required) specifies the original data file to be encrypted. 
Note: There are also alternative encryption commands which are however not recommended for providing cross-usability with other DigiDoc software components:
.RS
.TP
.I "-encrypt <input-file>"
Encrypts the data from the given input file and writes the completed encrypted document in a file. Should be used only for encrypting small documents, already in DIGIDOC-XML format.
Input file (required) specifies the original data file to be encrypted. 
.TP
.I "-encrypt-file <input-file> <output-file>"
Encrypts the input file and writes to output file. Should be used only for encrypting large documents, already in DIGIDOC-XML format. Note that the command in not currently tested.
Input file (required) specifies the original data file to be encrypted. 
Output file (required) specifies the name of the output file which will be created in the current encrypted document format (ENCDOC-XML ver 1.0), with file extension .cdoc.
.RE
.IP "-decrypt-sk <input-file> <pin> [pkcs12-file] [slot(0)]"
Decrypts and possibly decompresses the encrypted file just read in and writes to output file. Expects the encrypted file to be inside a DigiDoc container.
Input file (required) specifies the input file’s name.
Pin (required) represents the recipient’s pin1 (in context of Estonian ID cards). 
pkcs12-file (optional) specifies the PKCS#12 file if decrypting is done with a software token.
slot deafult is slot 0 containing Estonian ID cards authentication keypair. This parameter can be used to decrypt with a key from the second id card attached to the computer etc.
Note: There are also alternative commands for decryption, depending on the encrypted file’s format, size and the certificate type used for decrypting it.
.RS
.TP
.I "-decrypt <input-file> <pin> [pkcs12-file] [slot(0)]"
Offers same functionality as -decrypt-sk, should be used for decrypting small files (which do not need to be inside a DigiDoc container).
Input file (required) specifies the input file’s name.
Pin (required) represents the recipient’s pin1 (in contexts of Estonian ID cards).
pkcs12-file (optional) specifies the PKCS#12 file if decrypting is done with a software token.
slot deafult is slot 0 containing Estonian ID cards authentication keypair. This parameter can be used to decrypt with a key from the second id card attached to the computer etc.
.TP
.I "-decrypt-file <input-file> <output-file> <pin> [pkcs12-file]"
Offers same functionality as -decrypt for decrypting documents, should be used for decrypting large files (which do not need to be inside a DigiDoc container). Expects the encrypted data not to be compressed. Note that the command is not currently tested.
Input file (required) specifies the encrypted file to be decrypted. 
Output file (required) specifies the output file name.
Pin (required) represents the recipient’s pin1 (in contexts of Estonian ID cards).
pkcs12-file (optional) specifies the PKCS#12 file if decrypting is done with a software token.
.RE
.IP "-calc-sign <cert-file> [<manifest>] [<city> <state> <zip> <country>]"
Offers an alternative to \-sign command to be used in CGI pograms. Adds signers certificate in pem format and optionally manifest and signers address and calculates the final hash value to be signed. This value is hex-encoded and can now be sent to users computer to be signed using a web plugin. This command creates an incomplete signature that lacks the actual RSA signature value. It must be stored in a temporary file and later completed using the \-add-sign-value command.
-IP "-add-sign-value <sign-value-file> <sign-id>"
Offers an alternative to \-sign command to be used in CGI pograms. Adds an RSA signature hex-encoded value to an incomplete signature created using the \-calc-sign command. This signature is still lacking the ocsp timemark, that can now be obtained using the \-get-confirmation command producing a complete XAdES signature.
.IP "-get-confirmation <signature-id>"
Adds an OCSP confirmation to a DigiDoc file’s signature.
.SH EXAMPLES
.IP "cdigidoc -new DIGIDOC-XML 1.3 -add <input-file> <mime> -sign <pin2> -out <output-file>
Creates a new signed document in DIGIDOC-XML 1.3 format, adds one input file, signs with smartcard using the default signature slot and writes to a signed document file.
.IP "cdigidoc -in <signed-input-file> -list"
Reads in a signed document, verifies signatures and prints the results to console.
.IP "cdigidoc -in <signed-input-file> -extract D0 <output-file>"
Reads in a signed document, finds the first signed document and writes it to output file.
.IP "cdigidoc -encrecv <recipient1.pem> -encrecv <recipient2.pem> -encrypt-sk <file-to-encrypt> -out <output-file.cdoc>"
Creates a new encypted file by encrypting input file that is encrypted using AES-128 and encrypts the generated randome transport key using RSA for two possible recipients identified by their certificates. Transport key is encrypted using RSA1.5.
.IP "cdigidoc -decrypt-sk <input-file.cdoc> <pin1> -out <output-file>"
Reads in encrypted file and decrypts it with smartcards first keypair (Estonian ID cards authentication key) and writes decrypted data to given putput file.
.IP "cdigidoc -decrypt-sk <input-file.cdoc> <password> <keyfile.p12d> -out <output-file>"
Reads in encrypted file and decrypts it with a PKCS#12 key-container and writes decrypted data to given putput file.

.SH AUTHORS
.B AS Sertifitseerimiskeskus (Certification Centre Ltd.)
.SH "SEE ALSO"
digidoc-tool(1), qesteidutil(1), qdigidocclient(1), qdigidoccrypto(1)
