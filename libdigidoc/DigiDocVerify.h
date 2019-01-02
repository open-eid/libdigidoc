#ifndef __DIGIDOC_VERIFY_H__
#define __DIGIDOC_VERIFY_H__
//==================================================
// FILE:	DigiDocVerify.h
// PROJECT:     Digi Doc
// DESCRIPTION: DigiDoc verification routines
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
// Lesser General Public License for more details.
// GNU Lesser General Public Licence is available at
// http://www.gnu.org/copyleft/lesser.html
//==========< HISTORY >=============================
//      26.04.2006      Veiko Sinivee
//                      Creation
//==================================================

#include "DigiDocDefs.h"
#include "DigiDocObj.h"
#include "DigiDocMem.h"
#include <openssl/x509.h>
#include <openssl/ocsp.h>

//==========< XML generation routines >========================

#ifdef  __cplusplus
extern "C" {
#endif

// Holds info of an xml element used in signature format
typedef struct XmlElemDef_st {
    char* szTag;			// element tag
    char  bMultiple;		// 'Y' if multiple elements allowed, 'N' if not
    void** pChildren;		// list of children terminated by NULL
} XmlElemDef;
    
// Holds info of an xml element used in signature format
typedef struct XmlElemInfo_st {
    char* szId;				// element tag
    char* szTag;			// element tag
    void* pParent;			// parent emenent info if exists
    void** pChildren;		// list of children terminated by NULL
} XmlElemInfo;
    
int XmlElemInfo_new(XmlElemInfo **ppXi, const char* id, const char* tag);
    
void XmlElemInfo_free(XmlElemInfo* pXi);
    
int XmlElemInfo_countChildren(XmlElemInfo* pXi);
    
int XmlElemInfo_addChild(XmlElemInfo* pParent, XmlElemInfo* pChild);
    
XmlElemInfo* XmlElemInfo_getRootElem(XmlElemInfo* pElem);
    
// verifies files signature
EXP_OPTION int verifyFileSignature(const char* szFileName, int nDigestType,
						byte* pSigBuf, int nSigLen,
						const char *certfile);


// Compares two byte arrays and returns 0 for OK
EXP_OPTION int compareByteArrays(const byte* dig1, int len1, const byte* dig2, int len2);

// verifies one doc's check digests in this signature
EXP_OPTION int verifySigDocDigest(const SignedDoc* pSigDoc, const SignatureInfo* pSigInfo, 
				 const DocInfo* pDocInfo, const char* szDataFile);
// verifies the mime digest of this doc in this signature
EXP_OPTION int verifySigDocMimeDigest(const SignedDoc* pSigDoc, const SignatureInfo* pSigInfo, 
				       const DocInfo* pDocInfo, const char* szFileName);

// verifies this one signature
EXP_OPTION int verifySignatureInfo(const SignedDoc* pSigDoc, const SignatureInfo* pSigInfo, 
						const char* signerCA, const char* szDataFile, int bUseCA);
    
// verifies the whole document (returns on first err)
EXP_OPTION int verifySigDoc(const SignedDoc* pSigDoc, const char* signerCA, 
							const char** caFiles, const char* caPath, const char* notCert, 
							const char* szDataFile, int bUseCA);


// Verifies the certificates signed attributes
EXP_OPTION int verifySigCert(const SignatureInfo* pSigInfo);


// Verfies NotaryInfo signature
EXP_OPTION int verifyNotaryInfo(const SignedDoc* pSigDoc, const SignatureInfo* pSigInfo,
				const NotaryInfo* pNotInfo,  
				const char ** caFiles, const char *CApath, const char* notCertFile);

// Verifies the certificates signed attributes
EXP_OPTION int verifyNotCert(const SignatureInfo* pSigInfo, const NotaryInfo* pNotInfo);

// Verfies NotaryInfo digest
EXP_OPTION int verifyNotaryDigest(const SignedDoc* pSigDoc, const NotaryInfo* pNotInfo);

// verifies signed doc 
EXP_OPTION int verifySigDocCERT(const SignedDoc* pSigDoc, const void* signerCA, 
				const X509** caCerts, 
				const char* caPath, const X509* notCert, 
				const char* szDataFile, int bUseCA);


// Verifies this signature
  EXP_OPTION int verifySignatureInfoCERT(const SignedDoc* pSigDoc, 
					 const SignatureInfo* pSigInfo, 
					 const void* signerCACert, const char* szDataFile, int bUseCA);
    
// Checks if the cert has been signed by this CA-cert
EXP_OPTION int isCertSignedByCERT(const X509* cert, const X509* caCert);


// Verfies NotaryInfo signature
EXP_OPTION int verifyNotaryInfoCERT(const SignedDoc* pSigDoc, 
				    const SignatureInfo* pSigInfo,
				    const NotaryInfo* pNotInfo,  
				    const X509** caCerts, 
				    const char *CApath, const X509* notCert);
    
//--------------------------------------------------
// Verfies NotaryInfo signature
// pSigDoc - signed doc object
// pNotInfo - NotaryInfo object
// caCerts - CA certificate pointer array terminated with NULL
// CApath - path to (directory) all certs
// notCertFile - Notary (e.g. OCSP responder) cert file 
// pSigCa - signers ca cert
//--------------------------------------------------
EXP_OPTION int verifyNotaryInfoCERT2(const SignedDoc* pSigDoc,
                                         const SignatureInfo* pSigInfo,
                                         const NotaryInfo* pNotInfo,
                                         const X509** caCerts, const char *CApath, 
                                         const X509* notCert, const X509* pSigCa);

EXP_OPTION int verifySigDocSigPropDigest(const SignatureInfo* pSigInfo);

// Calculates the digest of NotaryInfo
EXP_OPTION int calculateNotaryInfoDigest(const SignedDoc* pSigDoc, 
					const NotaryInfo* pNotInfo, byte* digBuf, int* digLen);

int readTagContents(char** data, const char* fileName, 
					const char* tagName, int nAttrs,
					const char** attNames, const char** attValues,
					int withTags);

  X509_ALGOR* setSignAlgorithm(const EVP_MD * type);

int setup_verifyCERT(X509_STORE **newX509_STORE,
		     const char *CApath, 
		     const X509** certs);
		     
EXP_OPTION int verifyEstIDSignature(const byte* digest, int digestLen, int nDigestType,
					byte* pSigBuf, int nSigLen, X509* cert);
EXP_OPTION int verifyEstIDSignature2(const byte* digest, int digestLen, int nDigestType,
					byte* pSigBuf, int nSigLen, X509* cert);
    
//===========================================================
// Checks and records the knowledge if one signature had
// missing xmlns problem
// pSigDoc - signed doc data
// returns 1 if at least one signature had this problem
//============================================================
EXP_OPTION int checkDdocWrongDigests(const SignedDoc* pSigDoc);
    
EXP_OPTION int validateElementPath(XmlElemInfo* pElem);

#ifdef  __cplusplus
}
#endif

#endif // __DIGIDOC_VERIFY_H__


