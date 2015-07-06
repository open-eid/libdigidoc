//==================================================
// FILE:	DigiDocVerify.c
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

#include "DigiDocVerify.h"
#include "DigiDocError.h"
#include "DigiDocLib.h"
#include "DigiDocDebug.h"
#include "DigiDocConvert.h"
#include "DigiDocError.h"
#include "DigiDocCert.h"
#include "DigiDocGen.h"
#include "DigiDocObj.h"


#include <openssl/sha.h>
#ifdef WITH_ECDSA
  #include <openssl/ecdsa.h>
#endif
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

//--------------------< ddoc structure def >-----------------------

const XmlElemDef eTransform = {"Transform", 'Y', NULL}; /* 1.0 */
const XmlElemDef* eTransformsCh[] = {&eTransform, NULL}; /* 1.0 */
const XmlElemDef eTransforms = {"Transforms", 'Y', (void**)&eTransformsCh}; /* 1.0 */

const XmlElemDef eDigestMethod = {"DigestMethod", 'N', NULL};
const XmlElemDef eDigestValue = {"DigestValue", 'N', NULL};
const XmlElemDef* eRefCh[] = {&eDigestMethod, &eDigestValue, &eTransforms, NULL};
const XmlElemDef eReference = {"Reference", 'Y', (void**)&eRefCh};
const XmlElemDef eSignatureMethod = {"SignatureMethod", 'N', NULL};
const XmlElemDef eCanonicalizationMethod = {"CanonicalizationMethod", 'N', NULL};
const XmlElemDef* eSigInfoCh[] = {&eCanonicalizationMethod, &eSignatureMethod, &eReference, NULL};
const XmlElemDef eSigInfo = {"SignedInfo", 'N', (void**)&eSigInfoCh};
const XmlElemDef eSigVal = {"SignatureValue", 'N', NULL};
const XmlElemDef eModulus = {"Modulus", 'N', NULL};
const XmlElemDef eExponent = {"Exponent", 'N', NULL};
const XmlElemDef* eRSAKeyValueCh[] = {&eModulus, &eExponent, NULL};
const XmlElemDef eRSAKeyValue = {"RSAKeyValue", 'N', (void**)&eRSAKeyValueCh};
const XmlElemDef* eKeyValueCh[] = {&eRSAKeyValue};
const XmlElemDef eKeyValue = {"KeyValue", 'N', (void**)&eKeyValueCh};
const XmlElemDef eX509Certificate = {"X509Certificate", 'N', NULL};
const XmlElemDef* eX509DataCh[] = {&eX509Certificate, NULL};
const XmlElemDef eX509Data = {"X509Data", 'N', (void**)&eX509DataCh};
const XmlElemDef* eKeyInfoCh[] = {&eKeyValue,&eX509Data, NULL};
const XmlElemDef eKeyInfo = {"KeyInfo", 'N', (void**)&eKeyInfoCh};


const XmlElemDef eEncapsulatedOCSPValue = {"EncapsulatedOCSPValue", 'Y', NULL};
const XmlElemDef* eOCSPValuesCh[] = {&eEncapsulatedOCSPValue, NULL};
const XmlElemDef eOCSPValues = {"OCSPValues", 'N', (void**)&eOCSPValuesCh};
const XmlElemDef* eRevocationValuesCh[] = {&eOCSPValues, &eEncapsulatedOCSPValue, NULL};  
const XmlElemDef eRevocationValues = {"RevocationValues", 'N', (void**)&eRevocationValuesCh};
const XmlElemDef eEncapsulatedX509Certificate = {"EncapsulatedX509Certificate", 'Y', NULL};
const XmlElemDef* eCertificateValuesCh[] = {&eEncapsulatedX509Certificate, NULL};
const XmlElemDef eCertificateValues = {"CertificateValues", 'N', (void**)&eCertificateValuesCh};
const XmlElemDef eResponderID = {"ResponderID", 'N', NULL};
const XmlElemDef eProducedAt = {"ProducedAt", 'N', NULL};
const XmlElemDef* eOCSPIdentifierCh[] = {&eResponderID,&eProducedAt, NULL};
const XmlElemDef eOCSPIdentifier = {"OCSPIdentifier", 'N', (void**)&eOCSPIdentifierCh};
const XmlElemDef* eDigestAlgAndValueCh[] = {&eDigestMethod,&eDigestValue, NULL};
const XmlElemDef eDigestAlgAndValue = {"DigestAlgAndValue", 'N', (void**)&eDigestAlgAndValueCh};
const XmlElemDef* eOCSPRefCh[] = {&eOCSPIdentifier,&eDigestAlgAndValue, NULL};
const XmlElemDef eOCSPRef = {"OCSPRef", 'Y', (void**)&eOCSPRefCh};
const XmlElemDef* eOCSPRefsCh[] = {&eOCSPRef, NULL};
const XmlElemDef eOCSPRefs = {"OCSPRefs", 'N', (void**)&eOCSPRefsCh};
const XmlElemDef* eCompleteRevocationRefsCh[] = {&eOCSPRefs, NULL};
const XmlElemDef eCompleteRevocationRefs = {"CompleteRevocationRefs", 'N', (void**)&eCompleteRevocationRefsCh};
//
const XmlElemDef eX509IssuerName = {"X509IssuerName", 'N', NULL};
const XmlElemDef eX509SerialNumber = {"X509SerialNumber", 'N', NULL};
const XmlElemDef* eIssuerSerialCh[] = {&eX509IssuerName,&eX509SerialNumber, NULL};
const XmlElemDef eIssuerSerial = {"IssuerSerial", 'N', (void**)&eIssuerSerialCh};
const XmlElemDef* eCertDigestCh[] = {&eDigestMethod,&eDigestValue, NULL};
const XmlElemDef eCertDigest = {"CertDigest", 'N', (void**)&eCertDigestCh};
const XmlElemDef* eCertCh[] = {&eCertDigest,&eIssuerSerial, NULL};
const XmlElemDef eCert = {"Cert", 'Y', (void**)&eCertCh};
const XmlElemDef* eCertRefsCh[] = {&eCert, NULL};
const XmlElemDef eCertRefs = {"CertRefs", 'N', (void**)&eCertRefsCh};
const XmlElemDef* eCompleteCertificateRefsCh[] = {&eCertRefs, &eCert, NULL };// 1.0
const XmlElemDef eCompleteCertificateRefs = {"CompleteCertificateRefs", 'N', (void**)&eCompleteCertificateRefsCh};
const XmlElemDef* eUnsignedSignaturePropertiesCh[] = {&eCompleteCertificateRefs,&eCompleteRevocationRefs,&eCertificateValues,&eRevocationValues, NULL};
const XmlElemDef eUnsignedSignatureProperties = {"UnsignedSignatureProperties", 'N', (void**)&eUnsignedSignaturePropertiesCh};
const XmlElemDef* eUnsignedPropertiesCh[] = {&eUnsignedSignatureProperties, NULL};
const XmlElemDef eUnsignedProperties = {"UnsignedProperties", 'N', (void**)&eUnsignedPropertiesCh};


const XmlElemDef* eSigningCertificateCh[] = {&eCert, NULL};
const XmlElemDef eSigningCertificate = {"SigningCertificate", 'N', (void**)&eSigningCertificateCh};
const XmlElemDef eSigningTime = {"SigningTime", 'N', NULL};
const XmlElemDef eSignaturePolicyImplied = {"SignaturePolicyImplied", 'N', NULL};
const XmlElemDef eCity = {"City", 'N', NULL};
const XmlElemDef eStateOrProvince = {"StateOrProvince", 'N', NULL};
const XmlElemDef ePostalCode = {"PostalCode", 'N', NULL};
const XmlElemDef eCountryName = {"CountryName", 'N', NULL};
const XmlElemDef* eSignatureProductionPlaceCh[] = {&eCity,&eStateOrProvince,&ePostalCode,&eCountryName, NULL};
const XmlElemDef eSignatureProductionPlace = {"SignatureProductionPlace", 'N', (void**)&eSignatureProductionPlaceCh};
const XmlElemDef eClaimedRole = {"ClaimedRole", 'Y', NULL};
const XmlElemDef* eClaimedRolesCh[] = {&eClaimedRole, NULL};
const XmlElemDef eClaimedRoles = {"ClaimedRoles", 'N', (void**)&eClaimedRolesCh};
const XmlElemDef* eSignerRoleCh[] = {&eClaimedRoles, NULL};
const XmlElemDef eSignerRole = {"SignerRole", 'N', (void**)&eSignerRoleCh};

const XmlElemDef* eSignaturePolicyIdentifierCh[] = {&eSignaturePolicyImplied, NULL};
const XmlElemDef eSignaturePolicyIdentifier = {"SignaturePolicyIdentifier", 'N', (void**)&eSignaturePolicyIdentifierCh};


const XmlElemDef* eSignedSignaturePropertiesCh[] = {&eSigningTime,&eSigningCertificate,&eSignaturePolicyIdentifier,&eSignatureProductionPlace,&eSignerRole, NULL};
const XmlElemDef eSignedSignatureProperties = {"SignedSignatureProperties", 'N', (void**)&eSignedSignaturePropertiesCh};
const XmlElemDef eSignedDataObjectProperties = {"SignedDataObjectProperties", 'N', NULL};
const XmlElemDef* eSignedPropertiesCh[] = {&eSignedSignatureProperties,&eSignedDataObjectProperties, NULL};
const XmlElemDef eSignedProperties  = {"SignedProperties", 'N', (void**)&eSignedPropertiesCh};

const XmlElemDef* eQualifyingPropertiesCh[] = {&eSignedProperties,&eUnsignedProperties, NULL};
const XmlElemDef eQualifyingProperties = {"QualifyingProperties", 'N', (void**)&eQualifyingPropertiesCh};

const XmlElemDef* eObjectCh[] = {&eQualifyingProperties, NULL};
const XmlElemDef eObject = {"Object", 'N', (void**)&eObjectCh};
const XmlElemDef* eSignatureCh[] = {&eSigInfo,&eSigVal,&eKeyInfo,&eObject, NULL};
const XmlElemDef eSignature = {"Signature", 'Y', (void**)&eSignatureCh};
const XmlElemDef eDataFile = {"DataFile", 'Y', NULL};
const XmlElemDef* eSigDocCh[] = {&eDataFile, &eSignature, NULL};
const XmlElemDef eSignedDoc = {"SignedDoc", 'N', (void**)&  eSigDocCh };

//--------------------------------------------------

int XmlElemInfo_new(XmlElemInfo **ppXi, const char* id, const char* tag)
{
    XmlElemInfo* pXi = NULL;
	
    //RETURN_IF_NULL_PARAM(id);
    RETURN_IF_NULL_PARAM(tag);
    ddocDebug(5, "XmlElemInfo_new", "tag: %s id: %s", (tag ? tag : "NULL"), (id ? id : "NULL"));
    pXi = (XmlElemInfo*)malloc(sizeof(XmlElemInfo));
    RETURN_IF_BAD_ALLOC(pXi);
    memset(pXi, 0, sizeof(XmlElemInfo));
    if(id)
        setString(&(pXi->szId), id, -1);
    if(tag)
        setString(&(pXi->szTag), tag, -1);
    *ppXi = pXi;
    return ERR_OK;
}


void XmlElemInfo_free(XmlElemInfo* pXi) 
{
    XmlElemInfo** p = NULL;
	
    RETURN_VOID_IF_NULL(pXi);
    ddocDebug(5, "XmlElemInfo_free", "tag: %s id: %s children: %s", (pXi->szTag ? pXi->szTag : "NULL"), (pXi->szId ? pXi->szId : "NULL"), (pXi->pChildren ? "Y" : "N"));
    for(p = (XmlElemInfo**)pXi->pChildren; p && *p; p++) 
        XmlElemInfo_free(*p);
    if(pXi->pChildren)
        free(pXi->pChildren);
    if(pXi->szId)
        free(pXi->szId);
    if(pXi->szTag)
        free(pXi->szTag);
    if(pXi)
        free(pXi);
}

int XmlElemInfo_countChildren(XmlElemInfo* pXi) 
{
    XmlElemInfo** p = NULL;
    int n = 0;
	
    if(pXi && pXi->pChildren) {
        for(p = (XmlElemInfo**)pXi->pChildren; p && *p; p++) 
            n++;
    }
    return n;
}

int XmlElemInfo_addChild(XmlElemInfo* pParent, XmlElemInfo* pChild) 
{
    int n = 0;
	
    RETURN_IF_NULL(pParent);
    RETURN_IF_NULL(pChild);
    n = XmlElemInfo_countChildren(pParent);
    pParent->pChildren = (void**)realloc(pParent->pChildren, sizeof(XmlElemInfo*) * (n + 2));
    ((XmlElemInfo**)pParent->pChildren)[n] = pChild;
    pChild->pParent = pParent;
    ((XmlElemInfo**)pParent->pChildren)[n+1] = NULL;
    return ERR_OK;
}

XmlElemInfo* XmlElemInfo_getRootElem(XmlElemInfo* pElem) 
{
    if(pElem) {
        if(!pElem->pParent)
            return pElem;
        else
            return XmlElemInfo_getRootElem(pElem->pParent);
    }
    return NULL;
}

int XmlElemInfo_getLevel(XmlElemInfo* pElem) 
{
    int n = 0;
    XmlElemInfo* p = pElem;
    while(p) {
        n++;
        p = p->pParent;
    }
    return n;
}

XmlElemInfo** XmlElemInfo_getPathElements(XmlElemInfo* pElem) 
{
    XmlElemInfo *p = 0, **pp = 0;
    int n = XmlElemInfo_getLevel(pElem);
    if(n > 0) {
        pp = (XmlElemInfo **)malloc(sizeof(XmlElemInfo *) * (n+1));
        pp[n] = 0;
        p = pElem;
        while(p && n > 0) {
            pp[n-1] = p;
            n--;
            p = p->pParent;
        }
    }
    return pp;
}


int XmlElemInfo_getPath(XmlElemInfo* pElem, DigiDocMemBuf* pMbuf) 
{
    int err = ERR_OK;
    XmlElemInfo **pp1 = 0, **pp2 = 0;
    
    RETURN_IF_NULL(pElem);
    RETURN_IF_NULL(pMbuf);
    pp2 = XmlElemInfo_getPathElements(pElem);
    for(pp1 = pp2; pp1 && *pp1; pp1++) {
        err = ddocMemAppendData(pMbuf, "/", -1);
        err = ddocMemAppendData(pMbuf, (*pp1)->szTag, -1);
    }
    free(pp2);
    return err;
}

XmlElemDef* XmlElemDef_findChildByTag(XmlElemDef* pElem, const char* tag) 
{
    XmlElemDef **p = NULL, *pe = NULL;
    if(pElem && pElem->szTag && tag && !strcmp(pElem->szTag, tag))
		return pElem;
    if(pElem && pElem->pChildren) {
        for(p = (XmlElemDef**)pElem->pChildren; p && *p; p++) {
            pe = XmlElemDef_findChildByTag(*p, tag);
            if(pe) return pe;
        }
    }
    return NULL;
}

XmlElemDef* XmlElemDef_findElemOrDirectChildByTag(XmlElemDef* pElem, const char* tag) 
{
    XmlElemDef **p = NULL;
    if(pElem && pElem->szTag && tag && !strcmp(pElem->szTag, tag))
		return pElem;
    if(pElem && pElem->pChildren) {
        for(p = (XmlElemDef**)pElem->pChildren; p && *p; p++) {
            if(p && (*p)->szTag && tag && !strcmp((*p)->szTag, tag))
                return *p;
        }
    } 
    return NULL;
}

int XmlElemInfo_countChildrenWithTag(XmlElemInfo* pElem, const char* tag) 
{
    int n = 0;
    XmlElemInfo **p = NULL;
    if(pElem && pElem->pChildren) {
        for(p = (XmlElemInfo**)pElem->pChildren; p && *p; p++) {
            if(p && (*p)->szTag && tag && !strcmp((*p)->szTag, tag))
                n++;
        }
    } 
    return n;
}

int XmlElemDef_checkPath(XmlElemDef* pRoot, XmlElemInfo* pElem)
{
    DigiDocMemBuf mbuf;
    XmlElemDef *p1 = pRoot, *p2 = 0;
    XmlElemInfo **pp1 = 0, **pp2 = 0;
    int err = ERR_OK;
    
    mbuf.pMem = 0;
    mbuf.nLen = 0;
    XmlElemInfo_getPath(pElem, &mbuf);
    ddocDebug(4, "XmlElemDef_checkPath", "Validate elem: %s path: %s", (pElem->szTag ? pElem->szTag : "NULL"), mbuf.pMem);
    ddocMemBuf_free(&mbuf);
    pp2 = XmlElemInfo_getPathElements(pElem);
    for(pp1 = pp2; pp1 && *pp1 && p1; pp1++) {
        p2 = XmlElemDef_findElemOrDirectChildByTag(p1, (*pp1)->szTag);
        ddocDebug(4, "XmlElemDef_checkPath", "Current: %s find: %s found: %s", (p1->szTag ? p1->szTag : "NULL"), ((*pp1)->szTag ? (*pp1)->szTag : "NULL"), (p2 ? "OK" : "NULL"));
        if(!p2) {
            ddocDebug(1, "XmlElemDef_checkPath", "Did not find: %s under %s", ((*pp1)->szTag ? (*pp1)->szTag : "NULL"), (p1->szTag ? p1->szTag : "NULL"));
            err = ERR_XML_VALIDATION;
        }
        p1 = p2;
    }
    free(pp2);
    
    return err;
}

int validateElementPath(XmlElemInfo* pElem)
{
    XmlElemDef* pRoot = &eSignedDoc;
    XmlElemDef* pCurr = NULL;
    int err = ERR_OK, n;
    
    ddocDebug(3, "validateElementPath", "Validate elem: %s root: %s", 
              (pElem->szTag ? pElem->szTag : "NULL"), (pRoot->szTag ? pRoot->szTag : "NULL"));
    pCurr = XmlElemDef_findChildByTag(pRoot, pElem->szTag);
    if(pCurr) {
        ddocDebug(3, "validateElementPath", "Elem: %s exists", (pElem->szTag ? pElem->szTag : "NULL"));
        err = XmlElemDef_checkPath(pRoot, pElem);
        ddocDebug(3, "validateElementPath", "Elem: %s path rc: %d", (pElem->szTag ? pElem->szTag : "NULL"), err);
        if(err) SET_LAST_ERROR(err);
        if(!err && pElem->pParent) {
            XmlElemInfo* pParent = (XmlElemInfo*)pElem->pParent;
            n = XmlElemInfo_countChildrenWithTag(pParent, pElem->szTag);
            ddocDebug(3, "validateElementPath", "Parent: %s elems: %s count: %d multiple: %c", 
                      (pParent->szTag ? pParent->szTag : "NULL"), (pElem->szTag ? pElem->szTag : "NULL"), n, pCurr->bMultiple);
            if(n > 1 && pCurr->bMultiple != 'Y') {
                ddocDebug(3, "validateElementPath", "Found: %d elems: %s under: %s but multiple not allowed", 
                          n, (pElem->szTag ? pElem->szTag : "NULL"), (pParent->szTag ? pParent->szTag : "NULL"));
                err = ERR_XML_VALIDATION;
                SET_LAST_ERROR(err);
            }
        }
    } else {
        ddocDebug(1, "validateElementPath", "Elem: %s does not exist", (pElem->szTag ? pElem->szTag : "NULL"));
        err = ERR_DIGIDOC_PARSE;
    }
	
    return err;
}


//--------------------------------------------------


//--------------------------------------------------
// Verifies files SHA1-RSA signature
// szFileName - file name
// nDigestType - digest type. Supports only SHA1 (0)
// pSigBuf - buffer to store the signature
// nSigLen - buffer size, must be at least 128
//			will be updated by actual signature length
// certfile - name of the certificate file
// returns error code or ERR_OK for success
//--------------------------------------------------
EXP_OPTION int verifyFileSignature(const char* szFileName, int nDigestType,
						byte* pSigBuf, int nSigLen,
						const char *certfile)
{
  int err = ERR_OK;
  EVP_MD_CTX  ctx;
  unsigned char buf[FILE_BUFSIZE];
  int i;
  FILE *f;
  EVP_PKEY* pkey = NULL;

  RETURN_IF_NULL_PARAM(szFileName);
  RETURN_IF_NULL_PARAM(pSigBuf);
  RETURN_IF_NULL_PARAM(certfile);
  
  if(nDigestType == DIGEST_SHA1) {
    if((err = ReadPublicKey(&pkey, certfile)) == ERR_OK) {
      if((f = fopen(szFileName,"rb")) != NULL) {
	EVP_VerifyInit(&ctx, EVP_sha1());
	for (;;) {
	  i = fread(buf, sizeof(char), FILE_BUFSIZE, f);
	  if (i <= 0) break;
	  EVP_VerifyUpdate (&ctx, buf, (unsigned long)i);
	}
	err = EVP_VerifyFinal(&ctx, pSigBuf, nSigLen, pkey);
	if(err == ERR_LIB_NONE)
	  err = ERR_OK;
	fclose(f);
	EVP_PKEY_free(pkey);								
      } // if - fopen
      else
	err = ERR_FILE_READ;
    }
    else
      err = ERR_CERT_READ;
  }
  else
    err = ERR_UNSUPPORTED_DIGEST;
  
  if (err != ERR_OK) SET_LAST_ERROR(err);
  return err;
}


//--------------------------------------------------
// Verifies files SHA1-RSA signature
// szData - input data
// dataLen - input data length
// nDigestType - digest type
// pSigBuf - buffer to store the signature
// nSigLen - buffer size, must be at least 128
//			will be updated by actual signature length
// cert - certificate data
// returns error code or ERR_OK for success
//--------------------------------------------------
EXP_OPTION int verifySignature(const char* szData, unsigned long dataLen, int nDigestType,
					byte* pSigBuf, int nSigLen, X509* cert)
{
  int err = ERR_OK;
  EVP_MD_CTX  ctx;
  EVP_PKEY* pkey = NULL;
  
  RETURN_IF_NULL_PARAM(szData);
  RETURN_IF_NULL_PARAM(pSigBuf);
  RETURN_IF_NULL_PARAM(cert);
  
  if(nDigestType == DIGEST_SHA1) {
    if((err = GetPublicKey(&pkey, cert)) == ERR_OK) {
      checkErrors();
      EVP_VerifyInit(&ctx, EVP_sha1());
      checkErrors();
      EVP_VerifyUpdate (&ctx, szData, dataLen);
      checkErrors();
      err = EVP_VerifyFinal(&ctx, pSigBuf, nSigLen, pkey);
      if(err == ERR_LIB_NONE)
	err = ERR_OK;
      checkErrors();
      EVP_PKEY_free(pkey);
      checkErrors();
    }
    else
      err = ERR_CERT_READ;
  }
  else
    err = ERR_UNSUPPORTED_DIGEST;	
  
  if (err != ERR_OK) SET_LAST_ERROR(err);
  return err;
}

//============================================================
// Compares two byte arrays and returns 0 for OK. 
// doesn't record an error on error stack
// dig1 - byte array 1
// len1 - byte array 1 length
// dig2 - byte array 2
// len2 - byte array 2 length
//============================================================
EXP_OPTION int compareByteArraysNoErr(const byte* dig1, int len1, const byte* dig2, int len2)
{
	int i;

	if(!dig1 || !dig2 || len1 != len2)
		return -1;
	for(i = 0; i < len1; i++) {
		if(dig1[i] != dig2[i]) 
			return -2;
	}
	return 0;
}

//byte sigvalasn1[] = { 48, 33, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20 };
byte sigvalasn1[] = { 
    	0x30, 0x1f, 0x30, 0x07, 0x06, 
    	0x05, 0x2b, 0x0e, 0x03, 0x02, 
    	0x1a, 0x04, 0x14 };
byte sigvalasn2[] = { 
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 
        0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };

int verifySigValAsn1(byte* sigval, int len)
{
    if(!sigval || 
       (compareByteArraysNoErr(sigval, len, sigvalasn1, sizeof(sigvalasn1)) &&
       compareByteArraysNoErr(sigval, len, sigvalasn2, sizeof(sigvalasn2)))) {
        ddocDebug(1, "verifySigValAsn1", "Invalid signature value asn.1 len: ", len);
        SET_LAST_ERROR(ERR_SIGVAL_ASN1);
        return ERR_SIGVAL_ASN1;
    }
    return ERR_OK;
}

//--------------------------------------------------
// Verifies files SHA1-RSA signature (EstID specific!!!)
// digest - digest data
// dataLen - digest data length
// nDigestType - digest type
// pSigBuf - buffer to store the signature
// nSigLen - buffer size, must be at least 128
//			will be updated by actual signature length
// cert - certificate data
// returns error code or ERR_OK for success
//--------------------------------------------------
EXP_OPTION int verifyEstIDSignature(const byte* digest, int digestLen, int nDigestType,
					byte* pSigBuf, int nSigLen, X509* cert)
{
  int err = ERR_OK, nCheckSigValAsn1 = 1;
  EVP_PKEY* pkey = 0;
  byte buf2[DIGEST_LEN+2], buf3[500], buf4[200], buf5[200],buf256[DIGEST_LEN256+2];
  int l2 = 0, l1;
  //AM 11.02.09 ecdsa-sha1 support for LI
#ifdef WITH_ECDSA
  ECDSA_SIG *ecsig;
#endif
  RETURN_IF_NULL_PARAM(digest);
  RETURN_IF_NULL_PARAM(pSigBuf);
  RETURN_IF_NULL_PARAM(cert);
  ddocDebug(3, "verifyEstIDSignature", "start");
  if(nDigestType == DIGEST_SHA1) {
    if((err = GetPublicKey(&pkey, cert)) == ERR_OK) {
      l2 = sizeof(buf3);
      memset(buf3, 0, sizeof(buf3));
      ERR_clear_error();
      //swapBytes(pSigBuf, nSigLen);
#ifdef WITH_ECDSA
	  if(pkey->type==NID_X9_62_id_ecPublicKey){
		  ecsig = ECDSA_SIG_new();
		  ecsig->r = BN_new();
		  ecsig->s = BN_new();
		  if (!BN_bin2bn(pSigBuf, nSigLen/2,ecsig->r)  || !BN_bin2bn(pSigBuf + nSigLen/2, nSigLen/2, ecsig->s)){
			ECDSA_SIG_free(ecsig);
			EVP_PKEY_free(pkey);
			return ERR_COMPARE;
		  }
		  l2 = ECDSA_do_verify(digest, digestLen, ecsig, pkey->pkey.ec);
		  ECDSA_SIG_free(ecsig);
		  if (l2 == -1){
			/* error */
			err = ERR_COMPARE;
		  }
		  else if (l2 == 0){
			/* incorrect signature */
			err = ERR_COMPARE;
		  }
		  else { /* ret == 1 */
			/* signature ok */
			err = ERR_OK;
		  }
	  }else 
#endif
		if(pkey->type==NID_rsaEncryption){
		  //clearErrors();
		  l2 = RSA_public_decrypt(nSigLen, pSigBuf, buf3, pkey->pkey.rsa, RSA_PKCS1_PADDING); //RSA_PKCS1_PADDING); //RSA_NO_PADDING);
		  checkErrors();
		  ddocDebug(3, "verifyEstIDSignature", "decryted sig-hash len: %d", l2);
		  // debug info
		  l1 = sizeof(buf4);
		  if(digestLen > 0) {
		  memset(buf4, 0, sizeof(buf4));
		  encode((const byte*)digest, digestLen, (byte*)buf4, &l1);
		  ddocDebug(3, "verifyEstIDSignature", "calculated hash: %s len: %d", buf4, digestLen);
		  }
		  l1 = sizeof(buf4);
		  if(l2 > 0) { // TODO: lisa asn.1 prefixi kontroll
		  memset(buf4, 0, sizeof(buf4));
		  encode((const byte*)buf3, l2, (byte*)buf4, &l1);
		  ddocDebug(3, "verifyEstIDSignature", "decrypted hash: %s len: %d", buf4, l2);
		  }
		  memset(buf2, 0, DIGEST_LEN);
		  checkErrors();
		  if(l2 > DIGEST_LEN) {
            err = verifySigValAsn1(buf3, l2 - DIGEST_LEN);
            memcpy(buf2, buf3 + l2 - DIGEST_LEN, DIGEST_LEN);
		  } else {
			memcpy(buf2, buf3, DIGEST_LEN);
            err = ERR_SIGVAL_ASN1;
            SET_LAST_ERROR(err);
            ddocDebug(1, "verifyEstIDSignature", "Invalid rsa-sha1 siganture length: %d", l2);
		  }
		  if(!err)
		    err = compareByteArrays(digest, digestLen, buf2, DIGEST_LEN);
		  //debug
		  l1 = sizeof(buf4);
		  encode((const byte*)digest, digestLen, (byte*)buf4, &l1);
		  l1 = sizeof(buf5);
		  encode((const byte*)buf2, DIGEST_LEN, (byte*)buf5, &l1);
		  ddocDebug(3, "verifyEstIDSignature", "comp-hash: %s sig-hash: %s, err: %d", buf4, buf5, err);
	  } else
		  err = ERR_UNSUPPORTED_SIGNATURE;

      EVP_PKEY_free(pkey);
      checkErrors();
    }
	//AM 23.04.08
	} else if(nDigestType == DIGEST_SHA256) {
    if((err = GetPublicKey(&pkey, cert)) == ERR_OK) {
      l2 = sizeof(buf3);
      memset(buf3, 0, sizeof(buf3));
      ERR_clear_error();
      //swapBytes(pSigBuf, nSigLen);
      l2 = RSA_public_decrypt(nSigLen, pSigBuf, buf3, pkey->pkey.rsa, RSA_PKCS1_PADDING); //RSA_PKCS1_PADDING); //RSA_NO_PADDING);
      checkErrors();
	  ddocDebug(3, "verifyEstIDSignature", "decryted sig-hash len: %d", l2);
	  // debug info
      l1 = sizeof(buf4);
	  if(digestLen > 0) {
      memset(buf4, 0, sizeof(buf4));
	  encode((const byte*)digest, digestLen, (byte*)buf4, &l1);
      ddocDebug(3, "verifyEstIDSignature", "calculated hash: %s len: %d", buf4, digestLen);
	  }
      l1 = sizeof(buf4);
	  if(l2 > 0) {
      memset(buf4, 0, sizeof(buf4));
	  encode((const byte*)buf3, l2, (byte*)buf4, &l1);
      ddocDebug(3, "verifyEstIDSignature", "decrypted hash: %s len: %d", buf4, l2);
	  }
      memset(buf256, 0, DIGEST_LEN);
      if(l2 > DIGEST_LEN)
		memcpy(buf256, buf3 + l2 - DIGEST_LEN, DIGEST_LEN);
      else
		memcpy(buf256, buf3, DIGEST_LEN);
      checkErrors();
			//err = compareByteArrays(digest, digestLen, buf256, DIGEST_LEN256);
      err = compareByteArrays(digest, DIGEST_LEN, buf256, DIGEST_LEN);
      //debug
      l1 = sizeof(buf4);
      encode((const byte*)digest, digestLen, (byte*)buf4, &l1);
      l1 = sizeof(buf5);
      encode((const byte*)buf256, DIGEST_LEN256, (byte*)buf5, &l1);
      ddocDebug(3, "verifyEstIDSignature", "comp-hash: %s sig-hash: %s, err: %d", buf4, buf5, err);

      EVP_PKEY_free(pkey);
      checkErrors();
    }
    else
      err = ERR_CERT_READ;
  }
  else
    err = ERR_UNSUPPORTED_DIGEST;	

  if (err != ERR_OK) SET_LAST_ERROR(err);
  ddocDebug(3, "verifyEstIDSignature", "end");
  return err;
}


//============================================================
// Compares two byte arrays and returns 0 for OK
// dig1 - byte array 1
// len1 - byte array 1 length
// dig2 - byte array 2
// len2 - byte array 2 length
//============================================================
EXP_OPTION int compareByteArrays(const byte* dig1, int len1, const byte* dig2, int len2)
{
	int err = ERR_OK, i;

	RETURN_IF_NULL_PARAM(dig1);
	RETURN_IF_NULL_PARAM(dig2);
	RETURN_IF_NOT(len1 == len2, ERR_COMPARE);	
	for(i = 0; i < len1; i++) {
		if(dig1[i] != dig2[i]) {
			err = ERR_COMPARE;
			break;
		}
	}
	return err;
}

//============================================================
// Checks and records the knowledge if one signature had
// missing xmlns problem
// pSigDoc - signed doc data
// returns 1 if at least one signature had this problem
//============================================================
EXP_OPTION int checkDdocWrongDigests(const SignedDoc* pSigDoc)
{
    int i, d, j, l, m, k, err = 0, e = 0;
    SignatureInfo *pSigInfo = 0;
    DocInfo *pDi = NULL;
    DataFile *pDf = NULL;
    
    RETURN_IF_NULL_PARAM(pSigDoc);
    d = getCountOfSignatures(pSigDoc);
    m = getCountOfDataFiles(pSigDoc);
    //printf("checkDdocWrongDigests\n");
    for(i = 0; i < d; i++) {
        pSigInfo = getSignature(pSigDoc, i);
        l = getCountOfDocInfos(pSigInfo);
        for(j = 0; j < l; j++) {
            pDi = getDocInfo(pSigInfo, j);
            for(k = 0; k < m; k++) {
                pDf = getDataFile(pSigDoc, k);
                //printf("DI: %s DF: %s content: %s\n", pDi->szDocId, pDf->szId, pDf->szContentType);
                if(!strcmp(pDi->szDocId, pDf->szId) &&
                   (!strcmp(pDf->szContentType, CONTENT_EMBEDDED) ||
                    !strcmp(pDf->szContentType, CONTENT_EMBEDDED_BASE64))) {
                       err = compareByteArrays(pDi->szDigest, pDi->nDigestLen, 
                                               (byte*)pDf->mbufDigest.pMem, pDf->mbufDigest.nLen);
                       if(err) { // check also the wrong digest
                           err = compareByteArrays(pDi->szDigest, pDi->nDigestLen, 
                                                   (byte*)pDf->mbufWrongDigest.pMem, pDf->mbufWrongDigest.nLen);
                           if(!err) {
                             setString((char**)&(pDi->szDigestType), DIGEST_SHA1_WRONG, -1);
                             e = 1;
                           }
                       }
                }
            }
        }
    }
    return e;
}

//============================================================
// Verifies the digest of the given doc in this signature
// pSigDoc - signed doc data
// pSigInfo - signature info object
// filename - file name for not embedded files
// szDataFile - name of the digidoc file
//============================================================
// FIXME : Hard to understand the logic
EXP_OPTION int verifySigDocDigest(const SignedDoc* pSigDoc, const SignatureInfo* pSigInfo, 
				 const DocInfo* pDocInfo, const char* szDataFile)
{
  int err = ERR_OK;
  int l1 = 0, l2 = 0;
  DataFile *pDf = NULL ;
  byte buf1[DIGEST_LEN+2], buf2[100], buf3[100], buf4[100];
  char *attNames = NULL, *attValues = NULL, *pTmp1 = NULL, *pTmp2 = NULL;
  //FILE *hFile;

  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(pSigDoc);
  RETURN_IF_NULL_PARAM(pDocInfo);
  pDf = getDataFileWithId(pSigDoc, pDocInfo->szDocId);
  RETURN_IF_NULL(pDf);
  RETURN_IF_NULL(pDf->szContentType);
  RETURN_IF_NULL(pDf->szDigestType);
  RETURN_IF_NULL(pDocInfo->szDigestType);
  // verify detached file signature
  ddocDebug(3, "verifySigDocDigest", "SigDoc: %s DF: %s len1: %d len2: %d, ctype: %s", 
	    pSigDoc->szFormatVer, pDf->szId, pDf->mbufDigest.nLen, 
	    pDocInfo->nDigestLen, pDf->szContentType);
  // the new digest calculation on the fly doesn't
  // work for old 1.0 files
	//AM 29.10.09
  if(!strcmp(pDf->szContentType, CONTENT_EMBEDDED) &&
     (!strcmp(pSigDoc->szFormatVer, SK_XML_1_VER) && !strcmp(pSigDoc->szFormat, SK_XML_1_NAME))) {
    attNames = "Id";
    attValues = pDf->szId;
    err = readTagContents(&pTmp2, szDataFile, "DataFile", 1, 
			  (const char**)&attNames, (const char**)&attValues, 0);
    if(err == ERR_OK) {
      pTmp1 = pTmp2;
      //skip leading newlines
      while(*pTmp1 && *pTmp1 != '<') pTmp1++;
      l1 = sizeof(buf1);
      err = calculateDigest((const byte*)pTmp1, strlen(pTmp1),
			    DIGEST_SHA1, (byte*)buf1, &l1);	
      if(err == ERR_OK) {
	err = ddocDataFile_SetDigestValue(pDf, (const char*)buf1, DIGEST_LEN);
	encode((const byte*)pDf->mbufDigest.pMem, pDf->mbufDigest.nLen, (byte*)buf3, &l2);
	ddocDebug(3, "verifySigDocDigest", "DF: %s calculated digest: %s", 
	      pDf->szId, buf3);
      }
      free(pTmp2);
    }
  }
  if(!strcmp(pDf->szContentType, CONTENT_EMBEDDED) ||
     !strcmp(pDf->szContentType, CONTENT_EMBEDDED_BASE64)){
    buf2[0] = buf3[0] = buf4[0] = 0;
    l2 = sizeof(buf2);
    if(pDocInfo->szDigest)
      bin2hex((const byte*)pDocInfo->szDigest, pDocInfo->nDigestLen, (char*)buf2, &l2);
    l2 = sizeof(buf3);
    if(pDf->mbufDigest.pMem)
      bin2hex((const byte*)pDf->mbufDigest.pMem, pDf->mbufDigest.nLen, (char*)buf3, &l2);
    l2 = sizeof(buf4);
    if(pDf->mbufWrongDigest.pMem)
      bin2hex((const byte*)pDf->mbufWrongDigest.pMem, pDf->mbufWrongDigest.nLen, (char*)buf4, &l2);

    ddocDebug(3, "verifySigDocDigest", "DF: %s len1: %d len2: %d, type1: %s type2: %s, digest1: %s digest2: %s digest3: %s", 
	      pDf->szId, pDf->mbufDigest.nLen, pDocInfo->nDigestLen, pDocInfo->szDigestType, pDf->szDigestType, buf2, buf3, buf4);
    if(strcmp(pDocInfo->szDigestType, pDf->szDigestType))
      err = ERR_DOC_DIGEST;
    else
      err = compareByteArrays(pDocInfo->szDigest, pDocInfo->nDigestLen, 
			      (byte*)pDf->mbufDigest.pMem, pDf->mbufDigest.nLen);
    if(err) { // check also the wrong digest
      err = compareByteArrays(pDocInfo->szDigest, pDocInfo->nDigestLen, 
			      (byte*)pDf->mbufWrongDigest.pMem, pDf->mbufWrongDigest.nLen);
        ddocDebug(3, "verifySigDocDigest", "wrong doc dig verify: %d", err);
        if(!err) {
          setString((char**)&(pDocInfo->szDigestType), DIGEST_SHA1_WRONG, -1);
          err = ERR_DF_WRONG_DIG;
        }
    }
    if(err != ERR_OK && err != ERR_DF_WRONG_DIG)
      err = ERR_DOC_DIGEST;
  }

  if (err != ERR_OK) SET_LAST_ERROR(err);
  ddocDebug(3, "verifySigDocDigest", "SigDoc DF: %s err: %d", 
	   pDf->szId, err);
  
  return err;
}

//============================================================
// Verifies the mime digest of the given doc in this signature
// pSigDoc - signed doc data
// pSigInfo - signature info object
// filename - file name for not embedded files
//============================================================
EXP_OPTION int verifySigDocMimeDigest(const SignedDoc* pSigDoc, const SignatureInfo* pSigInfo, 
				      const DocInfo* pDocInfo, const char* szFileName)
{
	int err = ERR_OK;
	int l1;
	DataFile* pDf;
	byte buf1[DIGEST_LEN+2];

	RETURN_IF_NULL_PARAM(pSigInfo);
	RETURN_IF_NULL_PARAM(pSigDoc);
	RETURN_IF_NULL_PARAM(pDocInfo);
	pDf = getDataFileWithId(pSigDoc, pDocInfo->szDocId);
	RETURN_IF_NULL(pDf);
	// we check mime digest only in ver 1.0
	if(!strcmp(pSigDoc->szFormatVer, SK_XML_1_VER) && !strcmp(pSigDoc->szFormat, SK_XML_1_NAME)) {
		l1 = sizeof(buf1);
		err = calculateDigest((const byte*)pDf->szMimeType, strlen(pDf->szMimeType), 
				DIGEST_SHA1, buf1, &l1);
		RETURN_IF_NOT(err == ERR_OK, err);
		err = compareByteArrays(pDocInfo->szMimeDigest, pDocInfo->nMimeDigestLen, 
				buf1, l1);
		if(err != ERR_OK)
			err = ERR_MIME_DIGEST;
	}
	if (err != ERR_OK) SET_LAST_ERROR(err);
	return err;
}


//============================================================
// Verifies the SignedProperties digest
// pSigInfo - signature info object
// from original file and use it for hash function.
// This is usefull if the file has been generated by
// another library and possibly formats these elements
// differently.
//============================================================
EXP_OPTION int verifySigDocSigPropDigest(const SignatureInfo* pSigInfo)
{
	int err = ERR_OK;

	RETURN_IF_NULL_PARAM(pSigInfo);
	err = ddocCompareDigestValues(pSigInfo->pSigPropDigest, pSigInfo->pSigPropRealDigest);
	RETURN_IF_NOT(err == ERR_OK, ERR_SIGPROP_DIGEST);
	return err;
}

int verifyCertDnPart(const char* sDN, const char* sId, const X509* pCert, int nNid)
{
    int err = ERR_OK;
    DigiDocMemBuf mbuf1, mbuf2;
    
    mbuf1.pMem = 0; mbuf1.nLen = 0;
    mbuf2.pMem = 0; mbuf2.nLen = 0;
    err = ddocCertGetDNPart(pCert, &mbuf1, nNid, 1);
    err = ddocGetDNPartFromString(sDN, sId, &mbuf2);
    ddocDebug(3, "verifyCertDnPart", "Search: %s from: %s got: %s cmp: %s", sId, sDN, 
              (const char*)mbuf2.pMem, (const char*)mbuf1.pMem);
    if(mbuf1.pMem && mbuf2.pMem && strcmp((const char*)mbuf2.pMem, (const char*)mbuf1.pMem)) {
        ddocDebug(3, "verifyCertDnPart", "Not matching entry: %s cert: %s signed: %s", sId, (const char*)mbuf1.pMem, (const char*)mbuf2.pMem);
        err = ERR_WRONG_CERT;
        SET_LAST_ERROR(err);
    }
    ddocMemBuf_free(&mbuf1);
    ddocMemBuf_free(&mbuf2);
    return err;
}


//============================================================
// Verifies the certificates signed attributes
// pSigInfo - signature info object
//============================================================
EXP_OPTION int verifySigCert(const SignatureInfo* pSigInfo)
{
  int err = ERR_OK, e1;
  int l1, l2;
  char szOtherSerial[100];
  byte buf1[DIGEST_LEN256+2], buf2[DIGEST_LEN256*2], buf3[DIGEST_LEN256*2];
  DigiDocMemBuf* pMBuf;
  CertID* pCertID = 0;
  X509* pCert;
    
  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(ddocSigInfo_GetSignersCert(pSigInfo));
  l1 = sizeof(buf1);
	pCertID = ddocCertIDList_GetCertIDOfType(pSigInfo->pCertIDs, CERTID_TYPE_SIGNERS_CERTID);
	if(pCertID->szDigestType){
		if(!strcmp(pCertID->szDigestType,DIGEST_SHA256_NAME)){
			RETURN_IF_NOT(X509_digest(ddocSigInfo_GetSignersCert(pSigInfo), 
				EVP_sha256(), buf1, (unsigned int*)&l1), ERR_X509_DIGEST); }
		else{
			RETURN_IF_NOT(X509_digest(ddocSigInfo_GetSignersCert(pSigInfo), 
				EVP_sha1(), buf1, (unsigned int*)&l1), ERR_X509_DIGEST); }
	}else{
		RETURN_IF_NOT(X509_digest(ddocSigInfo_GetSignersCert(pSigInfo), 
			EVP_sha1(), buf1, (unsigned int*)&l1), ERR_X509_DIGEST); 
    }
  // debug
  memset(buf2, 0, sizeof(buf2));
  memset(buf3, 0, sizeof(buf3));
  pMBuf = ddocSigInfo_GetSignersCert_DigestValue(pSigInfo);
  RETURN_IF_NULL_PARAM(pMBuf);
  l2 = sizeof(buf2)-1;
    encode((const byte*)pMBuf->pMem, ((pMBuf->nLen < l2/2) ? pMBuf->nLen : l2/2), (byte*)buf2, &l2);
  l2 = sizeof(buf3)-1;
  encode((const byte*)buf1, l1, (byte*)buf3, &l2);
  ddocDebug(3, "verifySigCert", "SIG: %s cdig1: %d - %s cdig2: %d - %s - %d", 
	    pSigInfo->szId, pMBuf->nLen, buf2, l1, buf3, l2);
  err = compareByteArrays((const byte*)pMBuf->pMem, pMBuf->nLen, buf1, l1);	
  RETURN_IF_NOT(err == ERR_OK, ERR_WRONG_CERT);
  err = ReadCertSerialNumber(szOtherSerial, sizeof(szOtherSerial), ddocSigInfo_GetSignersCert(pSigInfo));
  ddocDebug(3, "verifySigCert", "SIG: %s signer-cert-serial: %s cert-serial2: %s", 
	    pSigInfo->szId, ddocSigInfo_GetSignersCert_IssuerSerial(pSigInfo), szOtherSerial);
  RETURN_IF_NOT(((err == ERR_OK) && 
    !strcmp(ddocSigInfo_GetSignersCert_IssuerSerial(pSigInfo), szOtherSerial)), ERR_WRONG_CERT);
  // check key usage
     pCert = ddocSigInfo_GetSignersCert(pSigInfo);
    if(!ddocCertCheckKeyUsage(pCert, KUIDX_NON_REPUDIATION)) {
        ddocDebug(1, "verifySigCert", "SIG: %s cert has no non-repudiation key usage", pSigInfo->szId);
        SET_LAST_ERROR(ERR_SIGNERS_CERT_NON_REPU);
        return ERR_SIGNERS_CERT_NON_REPU;
    } else
        ddocDebug(3, "verifySigCert", "SIG: %s cert has non-repudiation key usage", pSigInfo->szId);
  // check cert parts
  if(pCertID && pCert) {
      e1 = verifyCertDnPart(pCertID->szIssuerName, "CN", pCert, NID_commonName);
      if(!err && e1) err = e1;
      e1 = verifyCertDnPart(pCertID->szIssuerName, "C", pCert, NID_countryName);
      if(!err && e1) err = e1;
      e1 = verifyCertDnPart(pCertID->szIssuerName, "O", pCert, NID_organization);
      if(!err && e1) err = e1;
      e1 = verifyCertDnPart(pCertID->szIssuerName, "OU", pCert, NID_organizationUnit);
      if(!err && e1) err = e1;
  }
  return err;
}


//============================================================
// Verifies this signature
// pSigDoc - signed doc data
// pSigInfo - signature info object
// signerCA - direct signer CA certs filename
// szDateFile - name of the digidoc file
// bUseCA - use CA certs or not 1/0
// from original file and use it for hash function.
// This is usefull if the file has been generated by
// another library and possibly formats these elements
// differently.
//============================================================
EXP_OPTION int verifySignatureInfo(const SignedDoc* pSigDoc, const SignatureInfo* pSigInfo, 
				   const char* signerCA, const char* szDataFile, int bUseCA)
{
  int err = ERR_OK;
  int j, k;
  X509* cert = NULL;
  DocInfo* pDocInfo = NULL;
  DataFile* pDf = NULL;
  DigiDocMemBuf *pMBuf1 = 0, *pMBuf2 = 0;

  RETURN_IF_NULL_PARAM(pSigInfo);
  clearErrors();
  pMBuf1 = ddocDigestValue_GetDigestValue(pSigInfo->pSigInfoRealDigest);
  RETURN_IF_NULL_PARAM(pMBuf1);
  pMBuf2 = ddocSigInfo_GetSignatureValue_Value((SignatureInfo*)pSigInfo);
  RETURN_IF_NULL_PARAM(pMBuf2);
  err = verifyEstIDSignature((const byte*)pMBuf1->pMem, pMBuf1->nLen, DIGEST_SHA1,
			     (byte*)pMBuf2->pMem, pMBuf2->nLen, ddocSigInfo_GetSignersCert(pSigInfo));
  if(err != ERR_OK)
    err = ERR_SIGNATURE;
  if(err == ERR_OK) {
    k = getCountOfDocInfos(pSigInfo);
    ddocDebug(4, "verifySignatureInfo", "DFs: %d", k);
    for(j = 0; (err == ERR_OK) && (j < k); j++) {
      pDocInfo = getDocInfo(pSigInfo, j);
      RETURN_IF_NULL(pDocInfo);
      ddocDebug(4, "verifySignatureInfo", "DocInfo: %s", pDocInfo->szDocId);      
      pDf = getDataFileWithId(pSigDoc, pDocInfo->szDocId);
      RETURN_IF_NULL(pDf);
      ddocDebug(4, "verifySignatureInfo", "DF: %s", pDf->szId);      
      err = verifySigDocDigest(pSigDoc, pSigInfo, pDocInfo, szDataFile);
      ddocDebug(4, "verifySignatureInfo", "DF: %s verify: %d", pDf->szId, err);  
      if(err == ERR_OK)
	err = verifySigDocMimeDigest(pSigDoc, pSigInfo, pDocInfo, NULL);			
    }
  }
  if(err == ERR_OK)
    err = verifySigDocSigPropDigest(pSigInfo);
  if(err == ERR_OK) {
    err = verifySigCert(pSigInfo);
  }
  if(err == ERR_OK) {
    cert = getSignCertData(pSigInfo);
    // VS: ver 2.2.4 - removed this check as OCSP check is sufficient
    //if(err == ERR_OK) 
    //  err = isCertValid(cert, convertStringToTimeT(pSigDoc, pSigInfo->szTimeStamp));		
    if(bUseCA && (err == ERR_OK))
      err = isCertSignedBy(cert, signerCA);
  }
  if ( err != ERR_OK) SET_LAST_ERROR(err);
  return err;
}


//============================================================
// Verifies the whole document, but returns on first error
// Use the functions defined earlier to verify all contents
// step by step.
// pSigDoc - signed doc data
// 
//============================================================
EXP_OPTION int verifySigDoc(const SignedDoc* pSigDoc, const char* signerCA, 
				 const char** caFiles, const char* caPath, const char* notCert, 
			     const char* szDataFile, int bUseCA)

{
  SignatureInfo* pSigInfo;
  int i, d, err = ERR_OK;
	
  RETURN_IF_NULL_PARAM(pSigDoc);
  d = getCountOfSignatures(pSigDoc);
  for(i = 0; i < d; i++) {
    pSigInfo = getSignature(pSigDoc, i);
    err = verifySignatureInfo(pSigDoc, pSigInfo, signerCA, 
			      szDataFile, bUseCA);
    RETURN_IF_NOT(err == ERR_OK, err);
    err = verifyNotaryInfo(pSigDoc, pSigInfo, pSigInfo->pNotary, caFiles, caPath, notCert);
    RETURN_IF_NOT(err == ERR_OK, err);
  }
  return err;
}

//============================================================
// Verifies the certificates signed attributes
// pNotInfo - notary info object
//============================================================
EXP_OPTION int verifyNotCert(const SignatureInfo* pSigInfo, const NotaryInfo* pNotInfo)
{
  int err = ERR_OK;
  int l1;
  char szOtherSerial[100];
  byte buf1[DIGEST_LEN+2];
  CertID* pCertID;
  DigiDocMemBuf* pMBuf;
  X509* pCert = 0;

  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(pNotInfo);
  pCertID = ddocSigInfo_GetCertIDOfType((SignatureInfo*)pSigInfo, CERTID_TYPE_RESPONDERS_CERTID);
  RETURN_IF_NOT(pCertID, ERR_WRONG_CERT);
  pMBuf = ddocCertID_GetDigestValue(pCertID);
  RETURN_IF_NULL(pMBuf);

  l1 = sizeof(buf1);
  ddocDebug(9, "verifyNotCert", "ddocSigInfo_GetOCSPRespondersCert start");
  pCert = ddocSigInfo_GetOCSPRespondersCert(pSigInfo);
  RETURN_IF_NOT(pCert, ERR_WRONG_CERT);
  if(pNotInfo->szDigestType!=NULL){
	if(!strcmp(pNotInfo->szDigestType,DIGEST_SHA256_NAME)){
	  RETURN_IF_NOT(X509_digest(pCert, EVP_sha256(), buf1, (unsigned int*)&l1), ERR_X509_DIGEST); }
	else {
	  RETURN_IF_NOT(X509_digest(pCert, EVP_sha1(), buf1, (unsigned int*)&l1), ERR_X509_DIGEST); }
  }else{
	RETURN_IF_NOT(X509_digest(pCert, EVP_sha1(), buf1, (unsigned int*)&l1), ERR_X509_DIGEST); }
  err = compareByteArrays((const byte*)pMBuf->pMem, pMBuf->nLen, buf1, l1);
  RETURN_IF_NOT(err == ERR_OK, ERR_WRONG_CERT);
  err = ReadCertSerialNumber(szOtherSerial, sizeof(szOtherSerial), ddocSigInfo_GetOCSPRespondersCert(pSigInfo));
  RETURN_IF_NOT(err == ERR_OK, err);
  RETURN_IF_NOT(!strcmp(ddocCertID_GetIssuerSerial(pCertID), szOtherSerial), ERR_WRONG_CERT);
  return ERR_OK;
}

//--------------------------------------------------
// Sets digest algorithm type object
// type - SHA1
//--------------------------------------------------
X509_ALGOR* setCIDAlgorithm(const EVP_MD * type)
{
	X509_ALGOR* alg = NULL;
	int nid;

	alg = X509_ALGOR_new();
	RETURN_OBJ_IF_NULL(alg, 0);
	if((alg->parameter == NULL) || 
		(alg->parameter->type != V_ASN1_NULL)) {
		ASN1_TYPE_free(alg->parameter);
		alg->parameter=ASN1_TYPE_new();
		RETURN_OBJ_IF_NULL(alg->parameter, NULL);
		alg->parameter->type=V_ASN1_NULL;
	}
	ASN1_OBJECT_free(alg->algorithm);
	if ((nid = EVP_MD_type(type)) != NID_undef) {
		alg->algorithm=OBJ_nid2obj(nid);
	}
	return alg;
}

//--------------------------------------------------
// Sets signature algorithm type object
// type - RSA+SHA1
//--------------------------------------------------
X509_ALGOR* setSignAlgorithm(const EVP_MD * type)
{
	X509_ALGOR* alg;
	//int nid;

	alg = X509_ALGOR_new();
	RETURN_OBJ_IF_NULL(alg, NULL);
	if((alg->parameter == NULL) || 
		(alg->parameter->type != V_ASN1_NULL)) {
		ASN1_TYPE_free(alg->parameter);
		alg->parameter=ASN1_TYPE_new();
		RETURN_OBJ_IF_NULL(alg->parameter, 0);
		alg->parameter->type=V_ASN1_NULL;
	}
	ASN1_OBJECT_free(alg->algorithm);
	/*if ((nid = EVP_MD_type(type)) != NID_undef) {
		alg->algorithm=OBJ_nid2obj(nid);
	}*/
	alg->algorithm = OBJ_nid2obj(type->pkey_type);
	return alg;
}

//--------------------------------------------------
// Helper function. Converts Notary info to an OCSP
// response structure. Used in verify and file writing
// functions
// pNotInfo - NotaryInfo object
// notCert - OCSP responder certificate
// pBasResp - pointer to a pointer of the new response structure
//--------------------------------------------------
int notary2ocspBasResp(const SignedDoc* pSigDoc, const NotaryInfo* pNotInfo, X509* notCert, OCSP_BASICRESP** pBasResp)
{
  OCSP_SINGLERESP * single = 0;
  SignatureInfo* pSigInfo;
  CertID* pCertID;
  CertValue* pCertVal;
  // ASN1_GENERALIZEDTIME *tp = NULL;
  int err = ERR_OK;
  const DigiDocMemBuf *pMBuf;
  DigiDocMemBuf mbuf1;
  const char *p1 = NULL;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  RETURN_IF_NULL_PARAM(notCert);
  // new basic response
  *pBasResp = OCSP_BASICRESP_new();
  RETURN_IF_NULL(*pBasResp);
  str2asn1time(pSigDoc, pNotInfo->timeProduced, (*pBasResp)->tbsResponseData->producedAt); 
  p1 = ddocNotInfo_GetResponderId_Type(pNotInfo);
  RETURN_IF_NULL(p1);
  if(!strcmp(p1, RESPID_NAME_VALUE)) {
    (*pBasResp)->tbsResponseData->responderId->type = V_OCSP_RESPID_NAME;
    (*pBasResp)->tbsResponseData->responderId->value.byName = 
      X509_NAME_dup(X509_get_subject_name(notCert));
  } else {
    (*pBasResp)->tbsResponseData->responderId->type = V_OCSP_RESPID_KEY;
    (*pBasResp)->tbsResponseData->responderId->value.byKey = 
      ASN1_OCTET_STRING_new();
    pMBuf = ddocNotInfo_GetResponderId(pNotInfo);
    RETURN_IF_NULL(pMBuf);
    ASN1_OCTET_STRING_set((*pBasResp)->tbsResponseData->responderId->value.byKey,
			  (unsigned char*)pMBuf->pMem, pMBuf->nLen);
  }
  // new single response
  single = OCSP_SINGLERESP_new();
  single->certStatus->type = V_OCSP_CERTSTATUS_GOOD;
  single->certStatus->value.good = ASN1_NULL_new();
  single->certId->hashAlgorithm = setCIDAlgorithm(EVP_sha1());
  err = ddocNotInfo_GetIssuerNameHash(pNotInfo, &mbuf1);
  ASN1_OCTET_STRING_set(single->certId->issuerNameHash, (unsigned char*)mbuf1.pMem, mbuf1.nLen);
  ddocMemBuf_free(&mbuf1);
  err = ddocNotInfo_GetIssuerKeyHash(pNotInfo, &mbuf1);
  ASN1_OCTET_STRING_set(single->certId->issuerKeyHash, (unsigned char*)mbuf1.pMem, mbuf1.nLen);
  ddocMemBuf_free(&mbuf1);
  pSigInfo = ddocGetSignatureForNotary(pSigDoc, pNotInfo);
  RETURN_IF_NULL(pSigInfo);
  pCertID = ddocSigInfo_GetCertIDOfType(pSigInfo, CERTID_TYPE_RESPONDERS_CERTID);
  if(pCertID) {
	  ddocDebug(9, "notary2ocspBasResp", "pCertID");
	  ddocMemAppendData(&mbuf1, ddocCertID_GetIssuerSerial(pCertID), -1);
  } else  {
	ddocDebug(9, "notary2ocspBasResp", "no pCertID");
	pCertVal = ddocCertValueList_GetCertValueOfType(pSigInfo->pCertValues, CERTID_VALUE_RESPONDERS_CERT);
	ddocDebug(9, "notary2ocspBasResp", "ddocCertValueList_GetCertValueOfType");
	if(pCertVal) {
		ddocMemSetLength(&mbuf1, 100);
		ReadCertSerialNumber((char*)mbuf1.pMem, mbuf1.nLen-1, pCertVal->pCert);
	}
  }
  ASN1_INTEGER_set(single->certId->serialNumber, atol((const char*)mbuf1.pMem));
  ddocMemBuf_free(&mbuf1);
  err = ddocNotInfo_GetThisUpdate(pNotInfo, &mbuf1);
  if(mbuf1.pMem && strlen((char*)mbuf1.pMem))
     str2asn1time(pSigDoc, (char*)mbuf1.pMem, single->thisUpdate);
  ddocMemBuf_free(&mbuf1);
  err = ddocNotInfo_GetNextUpdate(pNotInfo, &mbuf1);
  if(mbuf1.pMem && strlen((char*)mbuf1.pMem))
    str2asn1time(pSigDoc, (char*)mbuf1.pMem, single->nextUpdate);
  ddocMemBuf_free(&mbuf1);
  sk_OCSP_SINGLERESP_push((*pBasResp)->tbsResponseData->responses, single);
  // add nonce
  err = ddocNotInfo_GetOcspRealDigest(pSigDoc, pNotInfo, &mbuf1);
  if(!err)
    err = OCSP_basic_add1_nonce((*pBasResp), (unsigned char*)mbuf1.pMem, mbuf1.nLen);
  ddocMemBuf_free(&mbuf1);
  if (err == ERR_LIB_NONE){
    err = ERR_OK;
    // set signature 
    (*pBasResp)->signatureAlgorithm = setSignAlgorithm(EVP_sha1()); 
    err = ddocNotInfo_GetOcspSignatureValue(pNotInfo, &mbuf1);
    ASN1_OCTET_STRING_set((*pBasResp)->signature, (byte*)mbuf1.pMem, mbuf1.nLen);
    ddocMemBuf_free(&mbuf1);
  } else {
    OCSP_BASICRESP_free(*pBasResp);
	// PR. avoid double free
	*pBasResp = 0;
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_NONCE);
  }
  ddocDebug(9, "notary2ocspBasResp", "end");
  //	checkErrors();
  return ERR_OK;
}

//--------------------------------------------------
// Verfies NotaryInfo signature
// pSigDoc - signed doc object
// pNotInfo - NotaryInfo object
// caFiles - array of CA file names terminated with NULL
// CApath - path to (directory) all certs
// notCertFile - Notary (e.g. OCSP responder) cert file 
//--------------------------------------------------
EXP_OPTION int verifyNotaryInfo(const SignedDoc* pSigDoc, 
				const SignatureInfo* pSigInfo,
				const NotaryInfo* pNotInfo, 
				const char** caFiles, const char *CApath, 
				const char* notCertFile)
{
  X509** caCerts;
  X509* notCert = NULL;
  int err = ERR_OK, l1, i;
	
  RETURN_IF_NULL_PARAM(caFiles);
  RETURN_IF_NULL_PARAM(CApath);
  RETURN_IF_NULL_PARAM(notCertFile);
  // find the chain length
  // VS - ver 1.67
  for(l1 = 0; caFiles && caFiles[l1]; l1++);
  caCerts = (X509**)malloc(sizeof(void*) * (l1 + 1));
  RETURN_IF_BAD_ALLOC(caCerts);
  memset(caCerts, 0, sizeof(void*) * (l1 + 1));
  for(i = 0; i < l1; i++) {
    err = ReadCertificate(&(caCerts[i]),caFiles[i]);
    if (err != ERR_OK) {
      err = ERR_CERT_READ;
      goto cleanup;
    }
  }
  err = ReadCertificate(&notCert, notCertFile);
  if (err != ERR_OK) {
    err = ERR_CERT_READ;
    goto cleanup;
  }
  err = verifyNotaryInfoCERT(pSigDoc, pSigInfo, pNotInfo,
			     (const X509**)caCerts, CApath, notCert);
  if (err != ERR_OK) SET_LAST_ERROR(err);
  // cleanup
cleanup:
  if(notCert)
    X509_free(notCert);
  for(i = 0; i < l1; i++)
    if(caCerts[i])   
      X509_free(caCerts[i]);
  free(caCerts);
  return err;
}

//--------------------------------------------------
// Setup X509 store for verification purposes
// CApath - directory of all certs
// CA1file - highest root cert
// CA2file - actual parent cert
//--------------------------------------------------
int setup_verifyCERT(X509_STORE **newX509_STORE,
				const char *CApath, 	const X509** certs)
{
  X509_STORE *store;
  X509_LOOKUP *lookup;
  int i;
  DigiDocMemBuf mbuf1;

 mbuf1.pMem = 0;
 mbuf1.nLen = 0;
  if((store = X509_STORE_new()) == NULL) goto end;
  lookup = X509_STORE_add_lookup(store,X509_LOOKUP_file());
  if (lookup == NULL) goto end;
  for(i = 0; certs && certs[i]; i++) {
    ddocDebug(3, "setup_verifyCERT", "add cert: %d cert: %s", i, (certs[i] ? "OK" : "NULL"));
    ddocCertGetSubjectDN((X509*)certs[i], &mbuf1);
    ddocDebug(3, "setup_verifyCERT", "add cert: %d cert: %s", i, (char*)mbuf1.pMem);
    X509_STORE_add_cert(store, (X509*)certs[i]);
    ddocMemBuf_free(&mbuf1);
  }
   ddocDebug(3, "setup_verifyCERT", "certs added");
  lookup=X509_STORE_add_lookup(store,X509_LOOKUP_hash_dir());
  if (lookup == NULL) goto end;
  if (CApath) {
     ddocDebug(3, "setup_verifyCERT", "lookup dir: %s", CApath);
    if(!X509_LOOKUP_add_dir(lookup,CApath,X509_FILETYPE_PEM)) {
      //BIO_printf(bp, "Error loading directory %s\n", CApath);
      goto end;
    }
  } else X509_LOOKUP_add_dir(lookup,NULL,X509_FILETYPE_DEFAULT);
  *newX509_STORE = store;
  ERR_clear_error();
  return ERR_OK;
end:
  if (store) X509_STORE_free(store);
  SET_LAST_ERROR_RETURN_CODE(ERR_CERT_STORE_READ);
}

int verifyOcspCertId(OCSP_RESPONSE* pResp, X509* pCert, X509* pCaCert)
{
  OCSP_RESPBYTES *rb = NULL;
  OCSP_BASICRESP *br = NULL;
  OCSP_RESPDATA  *rd = NULL;
  OCSP_SINGLERESP *single = NULL;
  OCSP_CERTID *cid = NULL;
  int err = ERR_OK;
  DigiDocMemBuf mbuf1, mbuf2, mbuf3;
    
  RETURN_IF_NULL_PARAM(pResp);
  RETURN_IF_NULL_PARAM(pCert);
  RETURN_IF_NULL_PARAM(pCaCert);
  RETURN_IF_NULL_PARAM(pResp->responseBytes);
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  mbuf2.pMem = 0;
  mbuf2.nLen = 0;    
  mbuf3.pMem = 0;
  mbuf3.nLen = 0;    
  rb = pResp->responseBytes;
  if(OBJ_obj2nid(rb->responseType) != NID_id_pkix_OCSP_basic)
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_UNKNOWN_TYPE);
  if((br = OCSP_response_get1_basic(pResp)) == NULL)
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_BASIC_RESP);
 ddocCertGetSubjectDN(pCert, &mbuf2);
 ddocCertGetSubjectDN(pCaCert, &mbuf3);
  ddocDebug(4, "verifyOcspCertId", "for cert: %ld, cn: %s, ca: %s", X509_get_serialNumber(pCert), mbuf2.pMem, mbuf3.pMem);
  ddocMemBuf_free(&mbuf2);
  ddocMemBuf_free(&mbuf3);
  rd = br->tbsResponseData;
  if(ASN1_INTEGER_get(rd->version) != 0)
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_WRONG_VERSION);
  if(sk_OCSP_SINGLERESP_num(rd->responses) != 1)
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_ONE_RESPONSE);
  single = sk_OCSP_SINGLERESP_value(rd->responses, 0);
  RETURN_IF_NULL(single);
  cid = single->certId;
  RETURN_IF_NULL(cid);
  // check serial number
  if(ASN1_INTEGER_cmp(cid->serialNumber, X509_get_serialNumber(pCert)) != 0) {
    ddocDebug(4, "verifyOcspCertId", "Looking for cert-nr: %ld buf found %ld", 
        X509_get_serialNumber(pCert), ASN1_INTEGER_get(cid->serialNumber));
    return ERR_WRONG_CERT;
  }
  // check issuer name hash
  err = ddocCertGetIssuerNameDigest(pCert, &mbuf1);
  RETURN_IF_NOT(err == ERR_OK, err);
  err = compareByteArrays((byte*)mbuf1.pMem, (unsigned int)mbuf1.nLen, 
        cid->issuerNameHash->data, cid->issuerNameHash->length);
  mbuf2.pMem = cid->issuerNameHash->data;
  mbuf2.nLen = cid->issuerNameHash->length;
  ddocBin2Hex(&mbuf2, &mbuf3);
  mbuf2.pMem = 0;
  mbuf2.nLen = 0;    
  ddocBin2Hex(&mbuf1, &mbuf2);
  ddocDebug(4, "verifyOcspCertId", "Looking for name-hash: %s found %s RC: %d", 
              (char*)mbuf2.pMem, (char*)mbuf3.pMem, err);
  ddocMemBuf_free(&mbuf1);
  ddocMemBuf_free(&mbuf2);
  ddocMemBuf_free(&mbuf3);
  RETURN_IF_NOT(err == ERR_OK, ERR_WRONG_CERT);
  // check issuer key hash
  err = ddocCertGetPubkeyDigest(pCaCert, &mbuf1);
  RETURN_IF_NOT(err == ERR_OK, err);
  err = compareByteArrays((byte*)mbuf1.pMem, (unsigned int)mbuf1.nLen, 
                          cid->issuerKeyHash->data, cid->issuerKeyHash->length);
  mbuf2.pMem = cid->issuerKeyHash->data;
  mbuf2.nLen = cid->issuerKeyHash->length;
  ddocBin2Hex(&mbuf2, &mbuf3);
  mbuf2.pMem = 0;
  mbuf2.nLen = 0;    
  ddocBin2Hex(&mbuf1, &mbuf2);
  ddocDebug(4, "verifyOcspCertId", "Looking for key-hash: %s found %s RC: %d", 
              (char*)mbuf2.pMem, (char*)mbuf3.pMem, err);
  ddocMemBuf_free(&mbuf1);
  ddocMemBuf_free(&mbuf2);
  ddocMemBuf_free(&mbuf3);
  return err;
}

//--------------------------------------------------
// Verfies NotaryInfo signature
// pSigDoc - signed doc object
// pNotInfo - NotaryInfo object
// caCerts - CA certificate pointer array terminated with NULL
// CApath - path to (directory) all certs
// notCertFile - Notary (e.g. OCSP responder) cert file 
//--------------------------------------------------
EXP_OPTION int verifyNotaryInfoCERT(const SignedDoc* pSigDoc,
                                    const SignatureInfo* pSigInfo,
                                    const NotaryInfo* pNotInfo,
                                    const X509** caCerts, const char *CApath, 
                                    const X509* notCert)
{
    return verifyNotaryInfoCERT2(pSigDoc, pSigInfo, pNotInfo, caCerts, CApath, notCert, NULL);
}

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
				    const X509* notCert, const X509* pSigCa)
{
  X509_STORE *store;
  OCSP_RESPONSE* pResp = NULL;
  OCSP_BASICRESP* bs = NULL;
  STACK_OF(X509)* ver_certs = NULL;
  int err = ERR_OK, l1;
  X509 *certNotaryDirectCA = 0, *pCert = 0, *pCaCert = 0;
  DigiDocMemBuf mbuf1;
    char buf1[100], buf3[500];
  time_t tProdAt;
    
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  RETURN_IF_NULL_PARAM(pSigDoc);
  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(pNotInfo);
  RETURN_IF_NULL_PARAM(notCert);
  RETURN_IF_NULL_PARAM(caCerts);
  
  // find the chain length
  for(l1 = 0; caCerts && caCerts[l1]; l1++);
  if(l1 < 1)
    SET_LAST_ERROR_RETURN_CODE(ERR_CERT_INVALID);
  certNotaryDirectCA = (X509*)caCerts[l1-1];
  // do the signature values match?
  // not to be checked in format 1.4
  if(err) return err;
  // now create an OCSP object and check its validity
  // VS - ver 1.66
  pResp = ddocNotInfo_GetOCSPResponse_Value(pNotInfo);
  if(!pResp) {
    ddocDebug(3, "verifyNotaryInfoCERT", "OCSP missing");
    SET_LAST_ERROR_RETURN_CODE(ERR_NO_OCSP);
  }
  // debug
  //WriteOCSPResponse("test2.resp", pResp);
  if((setup_verifyCERT(&store, CApath, caCerts)) == ERR_OK) {
    ddocNotInfo_GetProducedAt_timet(pNotInfo, &tProdAt);
    X509_VERIFY_PARAM_set_time(store->param, tProdAt);
    X509_STORE_set_flags(&store, X509_V_FLAG_USE_CHECK_TIME);
    // new basic response
    // create OCSP basic response
    // in version 1.0 we calculated digest over tbsResponseData
    bs = OCSP_response_get1_basic(pResp);
    if (!bs) err = ERR_OCSP_WRONG_RESPID;
    if (err == ERR_OK) {
      ver_certs = sk_X509_new_null();
      if (ver_certs) {
          ReadCertSerialNumber(buf1, sizeof(buf1), (X509*)notCert);
          ddocCertGetSubjectDN((X509*)notCert, &mbuf1);
          sk_X509_push(ver_certs, notCert);
          // fix invalid padding flag on ddoc 1.0 signatures
          if(((!strcmp(pSigDoc->szFormatVer, SK_XML_1_VER) && !strcmp(pSigDoc->szFormat, SK_XML_1_NAME))
             || (pSigInfo->nErr1 == ERR_VER_1_0)) && (bs->signature->flags & 0x07)) {
              bs->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
          }
          err = OCSP_basic_verify(bs, ver_certs, store, OCSP_NOCHECKS);
          ddocDebug(3, "verifyNotaryInfoCERT", "OCSP verify: %d, not cet: %s cn: %s", err, buf1, mbuf1.pMem);
          if(err == ERR_LIB_NONE) {
              err = ERR_OK;
          } else {
              err = ERR_NOTARY_SIG_MATCH;
              SET_LAST_ERROR(err);
          }
          // cleanup
          sk_X509_free(ver_certs);
      }
      if(bs) OCSP_BASICRESP_free(bs);
    }
    X509_STORE_free(store);
  } else {
    err = ERR_CERT_STORE_READ;
    SET_LAST_ERROR(err);
  }
  if(pSigInfo->nErr1 == ERR_VER_1_0)
    ((SignatureInfo*)pSigInfo)->nErr1 = 0;
  ddocDebug(3, "verifyNotaryInfoCERT", "OCSP verify final: %d, not cet: %s cn: %s", err, buf1, mbuf1.pMem);
  ddocMemBuf_free(&mbuf1);
  if(err == ERR_OK) {
	ddocDebug(9, "verifyNotaryInfoCERT", "ddocSigInfo_GetOCSPRespondersCert start");
	//if(!notCert) // ???
	  notCert = ddocSigInfo_GetOCSPRespondersCert(pSigInfo);
	ddocDebug(9, "verifyNotaryInfoCERT", "ddocSigInfo_GetOCSPRespondersCert end");
    if(notCert && pNotInfo->timeProduced) { // VS: ver 1.66
      ddocDebug(9, "verifyNotaryInfoCERT", "notCert exists");
	  err = isCertValid((X509*)notCert, convertStringToTimeT(pSigDoc, pNotInfo->timeProduced)); //crash?
      if (err != ERR_OK)
	SET_LAST_ERROR(err);
    } else {
	  ddocDebug(9, "verifyNotaryInfoCERT", "notCert invalid");
      err = ERR_CERT_INVALID;
      SET_LAST_ERROR(err);
    }
    if(err == ERR_OK) {
      err = isCertSignedByCERT(notCert, certNotaryDirectCA);
      if (err != ERR_OK) 
	SET_LAST_ERROR(err);
    }
    if(err == ERR_OK) {
      err = verifyNotCert(pSigInfo, pNotInfo);
      if (err != ERR_OK)
	SET_LAST_ERROR(err);
    }
	if(err == ERR_OK) {
		err = verifyNotaryDigest(pSigDoc, pNotInfo);
		if (err != ERR_OK && err != ERR_OCSP_NONCE_SIGVAL_NOMATCH)
			SET_LAST_ERROR(ERR_NOTARY_SIG_MATCH);
	}
    if(err == ERR_OK) {
        pCert = ddocSigInfo_GetSignersCert(pSigInfo);
        pCaCert = (pSigCa != NULL) ? (X509*)pSigCa : certNotaryDirectCA;
        err = verifyOcspCertId(pResp, pCert, pCaCert);
        if (err != ERR_OK)
			SET_LAST_ERROR(err);
    }
    if(err == ERR_OK) {
       ddocDebug(3, "verifyNotaryInfoCERT", "Not: %s time-ocsp: %s time-xml: %s", 
		pNotInfo->szId, (pNotInfo->timeProduced ? pNotInfo->timeProduced : ""), 
		(pNotInfo->szProducedAt ? pNotInfo->szProducedAt : ""));
       if(pNotInfo->timeProduced && pNotInfo->szProducedAt &&
	  strcmp(pNotInfo->timeProduced, pNotInfo->szProducedAt) &&
	   strcmp(pSigDoc->szFormat, SK_XML_1_NAME)) {
          err = ERR_OCSP_MALFORMED;
	  SET_LAST_ERROR(err);
       }
    }
  }
  if(pResp)
    OCSP_RESPONSE_free(pResp);
  ddocDebug(3, "verifyNotaryInfoCERT", "Ocsp verify: %d", err);
  return err;
}


//--------------------------------------------------
// Verfies NotaryInfo digest
// pNotInfo - NotaryInfo object
//--------------------------------------------------
EXP_OPTION int verifyNotaryDigest(const SignedDoc* pSigDoc, const NotaryInfo* pNotInfo)
{
  int err, l1, l2, l3;
  byte buf1[DIGEST_LEN256+2], buf2[40], buf3[40];
  const DigiDocMemBuf *pMBuf;
  DigiDocMemBuf mbuf2;
  SignatureInfo* pSigInf = 0;
    
  mbuf2.pMem = 0;
  mbuf2.nLen = 0;
  l1 = sizeof(buf1);
  err = calculateNotaryInfoDigest(pSigDoc, pNotInfo, buf1, &l1);
  RETURN_IF_NOT(err == ERR_OK, err);
  pMBuf = ddocNotInfo_GetOcspDigest(pNotInfo);
  RETURN_IF_NULL(pMBuf);
  err = compareByteArrays(buf1, l1, (byte*)pMBuf->pMem, pMBuf->nLen);
  RETURN_IF_NOT(err == ERR_OK, err);
  // verify ocsp nonce = signature value digest
  pSigInf = ddocGetSignatureForNotary(pSigDoc, pNotInfo);
  RETURN_IF_NULL(pSigInf);
  pMBuf = ddocSigInfo_GetSignatureValue_Value(pSigInf);
  RETURN_IF_NULL(pMBuf);
  l1 = sizeof(buf1);
  err = calculateDigest((const byte*)pMBuf->pMem, pMBuf->nLen,
                          DIGEST_SHA1, (byte*)buf1, &l1);
  RETURN_IF_NOT(err == ERR_OK, err);
  err = ddocNotInfo_GetOcspRealDigest(pSigDoc, pNotInfo, &mbuf2);
  RETURN_IF_NOT(err == ERR_OK, err);
  err = compareByteArrays(buf1, l1, (byte*)mbuf2.pMem, mbuf2.nLen);
  // debug output
  l2 = sizeof(buf2);
  l3 = sizeof(buf3);
  encode((const byte*)buf1, l1, (byte*)buf2, &l2);
  encode((const byte*)mbuf2.pMem, mbuf2.nLen, (byte*)buf3, &l3);
  ddocDebug(3, "verifyNotaryDigest", "Signature: %s Notary: %s sig-val-dig: %s nonce: %s verify: %d", 
            pSigInf->szId, pNotInfo->szId, buf2, buf3, err);
  RETURN_IF_NOT(err == ERR_OK, ERR_OCSP_NONCE_SIGVAL_NOMATCH);
    
  return ERR_OK;
}


//============================================================
// Verifies the whole document, but returns on first error
// Use the functions defined earlier to verify all contents
// step by step.
// pSigDoc - signed doc data
// signerCA - direct signer CA certs filename
// szDateFile - name of the digidoc file
// bUseCA - use CA certs or not 1/0
//============================================================
EXP_OPTION int verifySigDocCERT(const SignedDoc* pSigDoc, 
				const void* signerCA, const X509** caCerts,
				 const char* caPath, const X509* notCert,
				 const char* szDataFile, int bUseCA)
{
	SignatureInfo* pSigInfo;
	int i, d, err = ERR_OK;

	RETURN_IF_NULL_PARAM(pSigDoc);
	//assert(pSigDoc);
	d = getCountOfSignatures(pSigDoc);
	for(i = 0; i < d; i++) {
		pSigInfo = getSignature(pSigDoc, i);
		err = verifySignatureInfoCERT(pSigDoc, pSigInfo, signerCA, 
			szDataFile, bUseCA);
		//RETURN_IF_NOT(err == ERR_OK, err);
		err = verifyNotaryInfoCERT(pSigDoc, pSigInfo, pSigInfo->pNotary, caCerts, caPath, notCert);
		//RETURN_IF_NOT(err == ERR_OK, err);
	}
	return err;
}

//============================================================
// Verifies this signature
// pSigDoc - signed doc data
// pSigInfo - signature info object
// signerCA - direct signer CA certs filename
// szDataFile - provide to read <SignedInfo> and <SignedProperties>
// from original file and use it for hash function.
// This is usefull if the file has been generated by
// another library and possibly formats these elements
// differently.
// bUseCA - use CA certs or not 1/0
//============================================================
EXP_OPTION int verifySignatureInfoCERT(const SignedDoc* pSigDoc, const SignatureInfo* pSigInfo, 
					const void* signerCACert, const char* szDataFile, int bUseCA)
{
	int err = ERR_OK, err2 = ERR_OK;
	int j, k, i;
	X509* cert;
	DocInfo* pDocInfo = NULL;
	DataFile* pDf = NULL;
	DigiDocMemBuf *pMBuf1, *pMBuf2;
    NotaryInfo* pNot = NULL;
    
	RETURN_IF_NULL_PARAM(pSigInfo);
	pMBuf1 = ddocSigInfo_GetSigInfoRealDigest((SignatureInfo*)pSigInfo);
	RETURN_IF_NULL_PARAM(pMBuf1);
	pMBuf2 = ddocSigInfo_GetSignatureValue_Value((SignatureInfo*)pSigInfo);
	RETURN_IF_NULL_PARAM(pMBuf2);
	ddocDebug(3, "verifySignatureInfoCERT", "Sig: %s, CA: %s", 
	    ((pSigInfo && pSigInfo->szId) ? pSigInfo->szId : "NULL"),
	    (signerCACert ? "OK" : "NULL"));
	if(pSigInfo->szDigestType){ 
		if(!strcmp(pSigInfo->szDigestType,DIGEST_SHA256_NAME))
			err = verifyEstIDSignature((const byte*)pMBuf1->pMem, pMBuf1->nLen, DIGEST_SHA256,
					(byte*)pMBuf2->pMem, pMBuf2->nLen, ddocSigInfo_GetSignersCert(pSigInfo));	
		else
			err = verifyEstIDSignature((const byte*)pMBuf1->pMem, pMBuf1->nLen, DIGEST_SHA1,
				(byte*)pMBuf2->pMem, pMBuf2->nLen, ddocSigInfo_GetSignersCert(pSigInfo));
	}else{
		err = verifyEstIDSignature((const byte*)pMBuf1->pMem, pMBuf1->nLen, DIGEST_SHA1,
			(byte*)pMBuf2->pMem, pMBuf2->nLen, ddocSigInfo_GetSignersCert(pSigInfo));}
	//RETURN_IF_NOT(err == ERR_OK, ERR_SIGNATURE);
	// check that this signature signs all DataFiles
    for(i = 0; i < getCountOfDataFiles(pSigDoc); i++) {
		pDf = getDataFile(pSigDoc, i);
		k = 0; // not found yet
		for(j = 0; j < getCountOfDocInfos(pSigInfo); j++) {
			pDocInfo = getDocInfo(pSigInfo, j);
			ddocDebug(4, "verifySignatureInfoCERT", "Check sig \'%s\' of doc: \'%s\'", pSigInfo->szId, pDocInfo->szDocId);
			if(!strcmp(pDocInfo->szDocId, pDf->szId)) {
				k = 1; // found
				break;
			}
		}
		if(!k) {
			//ddocDebug(1, "verifySignatureInfoCERT", "Signature \'%s\' does not sign doc: \'%s\'", pSigInfo->szId, pDocInfo->szDocId);
			err = ERR_DOC_DIGEST;
			SET_LAST_ERROR(err);
			//return err;
		}
	}
	// verify DataFile hashes
	k = getCountOfDocInfos(pSigInfo);
	ddocDebug(4, "verifySignatureInfoCERT", "DFs: %d", k);
	for(j = 0; (err == ERR_OK) && (j < k); j++) {
		pDocInfo = getDocInfo(pSigInfo, j);
		ddocDebug(4, "verifySignatureInfoCERT", "Verify doc: %d - \'%s\'", j, pDocInfo->szDocId);
		RETURN_IF_NULL(pDocInfo);
		pDf = getDataFileWithId(pSigDoc, pDocInfo->szDocId);
        SET_LAST_ERROR_RETURN_IF_NOT(pDf, ERR_BAD_DATAFILE_COUNT, ERR_BAD_DATAFILE_COUNT);
		//RETURN_IF_NULL(pDf);
		err = verifySigDocDigest(pSigDoc, pSigInfo, pDocInfo, szDataFile);
		//ddocDebug(4, "verifySignatureInfoCERT", "Verify doc: %s - %d", pDocInfo->szDocId, err);
		//RETURN_IF_NOT(err == ERR_OK, err);
        if(!err)
		err = verifySigDocMimeDigest(pSigDoc, pSigInfo, pDocInfo, NULL);
		//RETURN_IF_NOT(err == ERR_OK, err);
	}
    err2 = verifySigDocSigPropDigest(pSigInfo);
    if(!err) err = err2;
	err2 = verifySigCert(pSigInfo);
	if(!err) err = err2;
	cert = getSignCertData(pSigInfo);
	//#23789 - kontrollida allkirjastaja kehtivust OCSP producedAt ajal
    pNot = getNotaryWithSigId(pSigDoc, pSigInfo->szId);
    if(pNot && pNot->timeProduced) {
        err = isCertValid(cert, convertStringToTimeT(pSigDoc, pNot->timeProduced));
    }
	if(bUseCA)
	  err2 = isCertSignedByCERT((const X509*)cert, (const X509*)signerCACert);
	if(!err) err = err2;
	return err;
}

//--------------------------------------------------
// Checks if this element tag contains the
// required attributes with the given values
// data - input data, XML tags data (not content but the attributes)
// nAttrs - number of attributes to check
// attNames - array of attribute names
// attValues - array of attribute values
// returns 0 if OK (all atributes found or none desired)
//--------------------------------------------------
int checkAttrs(const char* data, int nAttrs,
				const char** attNames, const char** attValues)
{
  int remains = 0, i;
  char *pTmp1 = 0, *pTmp2 = 0;

  RETURN_IF_NULL_PARAM(data);

  if(nAttrs) {
    RETURN_IF_NULL_PARAM(attNames);
    RETURN_IF_NULL_PARAM(attValues);
    remains = nAttrs; // must find nAttrs values
    for(i = 0; i < nAttrs; i++) {
      RETURN_IF_NULL(attNames[i]);
      RETURN_IF_NULL(attValues[i]);
      if((pTmp1 = strstr(data, attNames[i])) != 0) {
	if((pTmp2 = strstr(pTmp1, "\"")) != 0) {
	  if(!strncmp(pTmp2+1, attValues[i], strlen(attValues[i])))
	    remains--; // found one
	}
      }
    }
  }
  if (remains == 0) 
    return ERR_OK;
  else 
    return remains;
}

char* findString(char* mainBuf, char* search)
{
	char* pTmp = NULL;
	// first find in the latest 2KB
	pTmp = strstr(mainBuf+2048, search);
	// if not found check the previous buffer
	// as well because the tag could have been broken
	// between two buffer borders
	if(!pTmp)
		pTmp = strstr(mainBuf, search);
	return pTmp;
}

//--------------------------------------------------
// Finds the contents of a given XML tag
// in the given file.
// data - buffer for tag content data (caller must deallocate)
// tagName - tag name to search
// nAttrs - number of attributes to check
// attNames - array of attribute names
// attValues - array of attribute values
// withTags - 1 if include tags themselves, else 0
// returns 0 if tag was found and data read.
//--------------------------------------------------
int readTagContents(char** data, const char* fileName, 
		    const char* tagName, int nAttrs,
		    const char** attNames, const char** attValues,
		    int withTags)
{
  int err = ERR_OK, status, len, level;
  FILE *hFile = 0;
  char *pTmp1 = 0, *pTmp2 = 0, *pTmp3 = 0, *pBegin = 0, *pData = NULL;
  char buf1[4097], buf2[100];

  RETURN_IF_NULL_PARAM(data);
  RETURN_IF_NULL_PARAM(fileName);
  RETURN_IF_NULL_PARAM(tagName);
  RETURN_IF_NULL_PARAM(attNames);
  RETURN_IF_NULL_PARAM(attValues);

  if((hFile = fopen(fileName, "rb")) != 0) {
    status = 0; // nothing found yet
    level = 0;
    memset(buf1, 0, sizeof(buf1));
    // allways load the second half of the buffer 
    // warning - assignment in conditional expression -> yes but the code seems clearer this way!
    while((len = fread(buf1+2048, 1, 2048, hFile)) && status < 2) {
      switch(status) {
      case 0:
	// find <tagName
	snprintf(buf2, sizeof(buf2), "<%s ", tagName);	
	pTmp1 = findString(buf1, buf2);
	while(pTmp1 && (status == 0) && ((int)(pTmp1-buf1) < (int)sizeof(buf1))) {
	  pTmp2 = strstr(pTmp1, ">");
	  if(pTmp2) {
	    *pTmp2 = 0;
	    err = checkAttrs(pTmp1, nAttrs, attNames, attValues);
	    *pTmp2 = '>';
	    if(!err) {
	      // mark the found tag
	      // in order not to later mistake this 
	      // for a new level. Take also buffer moving
	      // in account
	      pBegin = pTmp1-2048;
	      status = 1; // now search for...
	      if(withTags) {								
		snprintf(buf2, sizeof(buf2), "</%s>", tagName);				
		if((pTmp3 = strstr(pTmp1, buf2)) != 0) 
		  *(pTmp3+strlen(buf2)) = 0;
		len = strlen(pTmp1)+1;
		pData = (char*)malloc(len);
		memset(pData, 0, len);
		RETURN_IF_BAD_ALLOC(pData);
		strncpy(pData, pTmp1, len);
		if(pTmp3) {
		  *data = pData;
		  status = 2;
		}
	      } else {
		pTmp2++; // first byte of content data
		// find </tagName>
		snprintf(buf2, sizeof(buf2), "</%s>", tagName);				
		if((pTmp3 = strstr(pTmp1, buf2)) != 0) 
		  *pTmp3 = 0;								
		len = strlen(pTmp2);
		pData = (char*)malloc(len+1);
		RETURN_IF_BAD_ALLOC(pData);
		strncpy(pData, pTmp2, len);
		if(pTmp3) {
		  *data = pData;
		  status = 2;
		}
	      } // else
	    } // if(!err)
	    else
	      pTmp1 = strstr(pTmp2, buf2);
	  } // if(pTmp2)
	  else
	    pTmp1++;
	} // if(pTmp1)
	break;
      case 1:
	snprintf(buf2, sizeof(buf2), "</%s>", tagName);
	pTmp3 = findString(buf1, buf2);
	// if the found end-tag is fully in the 
	// previous buffer then if cannot be the right 
	// one because I would have noticed it in
	// the last step
	if((pTmp3+strlen(buf2)) < (buf1+2048))
	  pTmp3 = NULL;
	snprintf(buf2, sizeof(buf2), "<%s ", tagName);				
	pTmp1 = findString(buf1, buf2);
	if(pTmp1 && pTmp1 > pBegin && !pTmp3) 
	  level++;
	if(pTmp3 && !level) {
	  if(withTags) {
	    snprintf(buf2, sizeof(buf2), "</%s>", tagName);
	    *(pTmp3 + strlen(buf2)) = 0;
	  } else
	    *pTmp3 = 0;
	  *data = pData;
	  status = 2;
	}
	if(pTmp3 && level > 0)
	  level--;
	len = strlen(buf1+2048);
	if(len) {
	  RETURN_IF_NULL(pData);
	  pData = (char*)realloc(pData, strlen(pData)+len+1);
	  strncpy(strchr(pData, 0), buf1+2048, strlen(pData)+len+1);
	  *data = pData;
	}
	break;
	
      default:
	break;
      }
      memcpy(buf1, buf1+2048, 2048);
      memset(buf1+2048, 0, 2049);
    } // while
    fclose(hFile);
  } // if(hFile
  else
    err = ERR_FILE_READ;
  return (pData == NULL);
}

