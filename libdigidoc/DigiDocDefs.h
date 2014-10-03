#ifndef __DIGIDOC_DEFS_H__
#define __DIGIDOC_DEFS_H__
//==================================================
// FILE:  DigiDocDefs.h
// PROJECT: Digi Doc
// DESCRIPTION: Digi Doc global definitions. 
// AUTHOR:  Veiko Sinivee, S|E|B IT Partner Estonia
//==================================================
// Copyright (C) AS Sertifitseerimiskeskus
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.ode
// GNU Lesser General Public Licence is available at
// http://www.gnu.org/copyleft/lesser.html
//==========< HISTORY >=============================
//      15.06.2005      Veiko Sinivee
//==================================================


#ifdef WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #define WIN32_CSP
  #ifdef _MSC_VER
    #pragma warning( disable: 4100 4706 4204 4221 )
  #endif
  #ifdef digidoc_EXPORTS
    #define EXP_OPTION __declspec(dllexport)
  #else
    #define EXP_OPTION __declspec(dllimport)
  #endif
  #define DIGIDOC_DEPRECATED __declspec(deprecated)
#else
  #if __GNUC__ >= 4
	#define EXP_OPTION __attribute__ ((visibility("default")))
    #define DIGIDOC_DEPRECATED __attribute__ ((__deprecated__))
  #else
	#define EXP_OPTION
    #define DIGIDOC_DEPRECATED
  #endif
#endif

#ifdef WIN32
  //for _msize function
  #define FILESEPARATOR	"\\"
  #include <malloc.h>
  #include <direct.h> 
  #define snprintf _snprintf
#else
  #define FILESEPARATOR	"/"
  #define DIGI_DOC_LIB
  #include <unistd.h>
  #define _mkdir mkdir
  #define _rmdir rmdir
  #define _unlink unlink 
  #define _tzset tzset
  #define _getcwd getcwd
  #if defined(__FreeBSD__)
    #define _timezone tzone
    extern long int tzone;	/* default for Estonia, but see initDigiDocLib() */
    #define _daylight daylight
    extern int daylight;		/* default, but see initDigiDocLib() */
  #else
    #define _timezone timezone
    #define _daylight daylight
  #endif
#endif

#define WITH_BASE64_HASHING_HACK   1
// VS: disabled ecdsa support for FC13 building
//#define WITH_ECDSA   1

//#define WITH_DEPRECATED_FUNCTIONS


// old timestamp struct
#define WITH_TIMETSTAMP_STRUCT

#ifndef byte
typedef	unsigned char	byte;
#endif

#define WITH_SHA256
//==========< Digest types >=======================
#ifdef  WITH_SHA256
#define SIGNATURE_LEN	144
#else
#define SIGNATURE_LEN	128
#endif
#define DIGEST_LEN		20
#define DIGEST_SHA1		0
#define DIGEST_SHA256		1
#define DIGEST_LEN256		32
#define CERT_DATA_LEN	4096
#define X509_NAME_LEN	256
#define SIGNATURE_RSA	0
#define CONTENT_EMBEDDED	"EMBEDDED"
#define CONTENT_EMBEDDED_BASE64	"EMBEDDED_BASE64"
#define X509_NAME_BUF_LEN   500

//==========< Format types >=======================

#define SK_PKCS7_1		 "SK-PKCS#7-1.0"
#define SK_XML_1_NAME		 "SK-XML"
#define DIGIDOC_XML_1_1_NAME	 "DIGIDOC-XML"
#define SK_XML_1_VER		 "1.0"
#define DIGIDOC_XML_1_1_VER	 "1.1"
#define DIGIDOC_XML_1_2_VER	 "1.2"
#define DIGIDOC_XML_1_3_VER	 "1.3"
#define SK_NOT_VERSION		 "OCSP-1.0"

#define DIGEST_SHA1_NAME	"sha1"
#define DIGEST_SHA1_WRONG	"sha1wrong"
#define DIGEST_SHA256_NAME "sha256"
#define SIGN_RSA_NAME		"RSA"
#ifdef WITH_ECDSA
  #define SIGN_ECDSA_NAME		"ECDSA"
#endif
#define OCSP_NONCE_NAME		"OCSP Nonce"
#define RESPID_NAME_VALUE	"NAME"
#define RESPID_KEY_VALUE	"KEY HASH"
#define OCSP_SIG_TYPE		"sha1WithRSAEncryption"
#define RESPID_NAME_TYPE        1
#define RESPID_KEY_TYPE         2

#define DIGEST_METHOD_SHA1      "http://www.w3.org/2000/09/xmldsig#sha1"
#define DIGEST_METHOD_SHA256      "http://www.w3.org/2001/04/xmlenc#sha256"
#define NAMESPACE_XML_DSIG      "http://www.w3.org/2000/09/xmldsig#"
#define NAMESPACE_XADES_111     "http://uri.etsi.org/01903/v1.1.1#"
#define NAMESPACE_XADES_132     "http://uri.etsi.org/01903/v1.3.2#"
#define NAMESPACE_XADES         "http://uri.etsi.org/01903#"


//==========< Format types >=======================

#define CHARSET_ISO_8859_1	"ISO-8859-1"
#define CHARSET_UTF_8		"UTF-8"


//==========< language codes >=======================
#define DDOC_LANG_ENGLISH           0
#define DDOC_LANG_ESTONIAN          1
#define DDOC_NUM_LANGUAGES          2
#define SUPPORTED_VERSION_COUNT		5

//==========< file formats >=======================

#define FILE_FORMAT_ASN1			0
#define FILE_FORMAT_PEM				1
//#define FILE_FORMAT_

//============< OCSP paramaters >==================

#define OCSP_REQUEST_SIGN_NO			1
#define OCSP_REQUEST_SIGN_CSP			2
#define OCSP_REQUEST_SIGN_X509			3
#define OCSP_REQUEST_SIGN_PKCS11_WIN	4
#define OCSP_REQUEST_SIGN_PKCS12		5

//================== Cert search constants =========
#define CERT_SEARCH_BY_STORE			1
#define CERT_SEARCH_BY_X509				2
#define CERT_SEARCH_BY_PKCS12			3

// thes can be XOR'ed, then all criterias are used
#define CERT_STORE_SEARCH_BY_SERIAL			0x01
#define CERT_STORE_SEARCH_BY_SUBJECT_DN		0x02
#define CERT_STORE_SEARCH_BY_ISSUER_DN		0x04
#define CERT_STORE_SEARCH_BY_KEY_INFO		0x08

#define FILE_BUFSIZE	1024*16

#endif // __DIGIDOC_DEFS_H__
