//==================================================
// FILE:	DigiDocOCSP.c
// PROJECT:     Digi Doc
// DESCRIPTION: DigiDoc OCSP handling routines
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

#include <libdigidoc/DigiDocConfig.h>
#include <libdigidoc/DigiDocOCSP.h>
#include <libdigidoc/DigiDocError.h>
#include <libdigidoc/DigiDocDebug.h>
#include <libdigidoc/DigiDocConvert.h>
#include <libdigidoc/DigiDocLib.h>
#include <libdigidoc/DigiDocCert.h>
#include <libdigidoc/DigiDocVerify.h>
#include <libdigidoc/DigiDocHTTP.h>
#include <openssl/sha.h>
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
#include <ctype.h>
#include <string.h>

#ifdef FRAMEWORK
#ifdef __APPLE__
#include <Security/Security.h>
#endif

static int password_callback(char *buf, int bufsiz, int verify, void *cb_data)
{
	static const char password[] = "pass";
	int res = strlen(password);
	if (res > bufsiz)
			res = bufsiz;
	memcpy(buf, password, res);
	return res;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10010000L
static int OCSP_resp_get0_id(const OCSP_BASICRESP *bs, const ASN1_OCTET_STRING **pid, const X509_NAME **pname)
{
	*pid = NULL;
	*pname = NULL;
	const OCSP_RESPID *rid = bs->tbsResponseData->responderId;
	if (rid->type == V_OCSP_RESPID_NAME)
		*pname = rid->value.byName;
	else if (rid->type == V_OCSP_RESPID_KEY)
		*pid = rid->value.byKey;
	else
		return 0;
	return 1;
}

static const ASN1_GENERALIZEDTIME *OCSP_resp_get0_produced_at(const OCSP_BASICRESP* bs)
{
	return bs->tbsResponseData->producedAt;
}

static const OCSP_CERTID *OCSP_SINGLERESP_get0_id(const OCSP_SINGLERESP *single)
{
	return single->certId;
}

static const ASN1_OCTET_STRING *OCSP_resp_get0_signature(const OCSP_BASICRESP *bs)
{
	return bs->signature;
}

static const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x)
{
	return x->cert_info->extensions;
}

static const ASN1_TIME *X509_get0_notBefore(const X509 *x)
{
	return x->cert_info->validity->notBefore;
}

static const ASN1_TIME *X509_get0_notAfter(const X509 *x)
{
	return x->cert_info->validity->notAfter;
}
#else
# define BIO_R_BAD_HOSTNAME_LOOKUP                        102
# define OCSP_R_NO_CONTENT                                106
# define OCSP_F_OCSP_SENDREQ_BIO                          112
# define OCSP_R_SERVER_READ_ERROR                         113
# define OCSP_R_SERVER_WRITE_ERROR                        116
#endif

//================< OCSP functions> =================================

static int ddocOcspProxyAuthInfo(char *authinfo, const char *user, const char *pass)
{
    BIO *b64 = 0, *hash = 0;
	char *data = 0;

    RETURN_IF_NULL_PARAM(authinfo);
    authinfo[0] = 0;

    if(!user && !pass)
        return ERR_OK;

    b64 = BIO_new(BIO_f_base64());
    RETURN_IF_NOT(b64, ERR_NULL_POINTER);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    hash = BIO_push(b64, BIO_new(BIO_s_mem()));
    RETURN_IF_NOT(hash, ERR_NULL_POINTER);

    BIO_printf(hash, "%s:%s", user, pass);
    (void)BIO_flush(hash);

    BIO_get_mem_data(hash, &data);
    sprintf(authinfo, "Proxy-Authorization: Basic %s\r\n", data);

    BIO_free_all(hash);
    return ERR_OK;
}


//============================================================
// Decodes binary (DER) OCSP_RESPONSE data and returns a OCSP_RESPONSE object
// ppResp - pointer to a buffer to receive newly allocated OCSP_RESPONSE pointer
// data - (DER) OCSP_RESPONSE data
// len - length of data in bytes
//============================================================
EXP_OPTION int ddocDecodeOCSPResponseData(OCSP_RESPONSE **ppResp, const byte* data, int len)
{
  BIO* b1 = 0;

  // check input params
  RETURN_IF_NULL_PARAM(data);
  RETURN_IF_NULL_PARAM(ppResp);
  // mark as not read yet
  *ppResp = 0;
  // create BIO
  b1 = BIO_new_mem_buf((void*)data, len);
  RETURN_IF_NOT(b1, ERR_NULL_POINTER);
  // decode OCSP
  *ppResp = d2i_OCSP_RESPONSE_bio(b1, NULL);
  BIO_free(b1);
  ddocDebug(3, "ddocDecodeOCSPResponseData", "Decoding %d bytes DER data - OCSP_RESPONSE %s", len, (*ppResp ? "OK" : "ERROR"));
  RETURN_IF_NOT(*ppResp, ERR_OCSP_UNKNOWN_TYPE);
  return ERR_OK;
}

//============================================================
// Decodes base64 (PEM) OCSP_RESPONSE data and returns a OCSP_RESPONSE object
// ppResp - pointer to a buffer to receive newly allocated OCSP_RESPONSE pointer
// data - (PEM) OCSP_RESPONSE data
// len - length of data in bytes
//============================================================
EXP_OPTION int ddocDecodeOCSPResponsePEMData(OCSP_RESPONSE **ppResp, const byte* data, int len)
{
  byte* p1 = 0;
  int l1 = 0, err = ERR_OK;

  // check input params
  RETURN_IF_NULL_PARAM(data);
  RETURN_IF_NULL_PARAM(ppResp);
  // mark as not read yet
  *ppResp = 0;
  // allocate memory for decoding
  l1 = len; // should be enough as it shrinks
  p1 = (byte*)malloc(l1);
  RETURN_IF_BAD_ALLOC(p1);
  memset(p1, 0, l1);
  // decode base64 data
  decode((const byte*)data, len, p1, &l1);
  // decode OCSP
  err = ddocDecodeOCSPResponseData(ppResp, p1, l1);
  // cleanup
  if(p1)
	  free(p1);
  ddocDebug(3, "ddocDecodeOCSPResponsePEMData", "Decoding %d bytes PEM data - OSCP_RESPONSE %s", len, (*ppResp ? "OK" : "ERROR"));
  return err;
}

//============================================================
// Reads in an OCSP Response file in DER format
// szFileName - OCSP response file name
//============================================================
int ReadOCSPResponse(OCSP_RESPONSE **newOCSP_RESPONSE, const char* szFileName)
{
  BIO *bin = NULL;
  OCSP_RESPONSE *resp = NULL;
  int err = ERR_OK;
	
  ddocDebug(4, "ReadOCSPResponse", "File: %s", szFileName);
  RETURN_IF_NULL_PARAM(newOCSP_RESPONSE);
  RETURN_IF_NULL_PARAM(szFileName);

  if((bin = BIO_new_file(szFileName, "rb")) != NULL) {
    ddocDebug(4, "ReadOCSPResponse", "File opened");
    resp = d2i_OCSP_RESPONSE_bio(bin, NULL);
    BIO_free(bin);
    if (resp == NULL) {
      err = ERR_OCSP_WRONG_VERSION;
    }
  } else {
    ddocDebug(4, "ReadOCSPResponse", "Cannot read file:%s", szFileName);
    err =ERR_FILE_READ;
  }
  if (err != ERR_OK) SET_LAST_ERROR(err);
  *newOCSP_RESPONSE = resp;
  return err;
}

//============================================================
// Writes an OCSP Response to a file in DER format
// szFileName - OCSP response file name
// resp - OCSP response object
//============================================================
int WriteOCSPResponse(const char* szFileName, const OCSP_RESPONSE* resp)
{
  BIO* bout = 0;

  RETURN_IF_NULL_PARAM(szFileName);
  RETURN_IF_NULL_PARAM(resp);
  if((bout = BIO_new_file(szFileName, "wb")) != NULL) {
#if OPENSSL_VERSION_NUMBER > 0x00908000
    ASN1_i2d_bio((int (*)(void*, unsigned char**))i2d_OCSP_RESPONSE, bout, (unsigned char*)resp);
#else
    ASN1_i2d_bio((int (*)())i2d_OCSP_RESPONSE, bout, (unsigned char*)resp);
#endif
    //i2d_OCSP_RESPONSE_bio((unsigned char*)bout, resp);
    BIO_free(bout);
  } else 
    SET_LAST_ERROR_RETURN_CODE(ERR_FILE_WRITE);
  return ERR_OK;	
}

//============================================================
// Reads in an OCSP Request file in DER format
// szFileName - OCSP Request file name
//============================================================
int ReadOCSPRequest(OCSP_REQUEST **newOCSP_REQUEST, const char* szFileName)
{
  BIO *bin = NULL;
  OCSP_REQUEST *req = NULL;
  int err = ERR_OK;
  
  RETURN_IF_NULL_PARAM(*newOCSP_REQUEST);
  RETURN_IF_NULL_PARAM(szFileName);
  
  if((bin = BIO_new_file(szFileName, "rb")) != NULL) {
    req = d2i_OCSP_REQUEST_bio(bin, NULL);
    BIO_free(bin);
    if (req == NULL) {
      err = ERR_OCSP_WRONG_VERSION;
    }
  } else
    err =ERR_FILE_READ;
  if (err != ERR_OK) SET_LAST_ERROR(err);
  *newOCSP_REQUEST = req;
  return err;
}

//============================================================
// Writes an OCSP Request to a file in DER format
// szFileName - OCSP Request file name
// resp - OCSP Request object
//============================================================
int WriteOCSPRequest(const char* szFileName, const OCSP_REQUEST* req)
{
  BIO* bout = 0;
	
  if((bout = BIO_new_file(szFileName, "wb")) != NULL) {
#if OPENSSL_VERSION_NUMBER > 0x00908000
    ASN1_i2d_bio((int (*)(void*, unsigned char**))i2d_OCSP_RESPONSE, bout, (unsigned char*)req);
#else
    ASN1_i2d_bio((int (*)())i2d_OCSP_RESPONSE, bout, (unsigned char*)req);
#endif
    //i2d_OCSP_REQUEST_bio(bout, req);
    BIO_free(bout);
  } else
    SET_LAST_ERROR_RETURN_CODE(ERR_FILE_WRITE);
  return ERR_OK;
}



//============================================================
// Checks OCSP certificate status and handles errors
// status - status code
// return error code
//============================================================
int handleOCSPCertStatus(int status)
{
  int err = ERR_OK;
  switch(status) {
  case V_OCSP_CERTSTATUS_GOOD: // cert is ok, do nothing
    break;
  case V_OCSP_CERTSTATUS_REVOKED: // cert has been revoked
    err = ERR_OCSP_CERT_REVOKED;
    break;
  case V_OCSP_CERTSTATUS_UNKNOWN: // cert status unknown
    err = ERR_OCSP_CERT_UNKNOWN;
    break;
  default: // should never happen?
    err = ERR_OCSP_RESP_STATUS;
  }
  return err;
}

//============================================================
// Calculates NotaryInfo digest if possible
// pSigDoc - digidoc main object pointer
// pNotary - NotaryInfo object to be initialized
// return error code
//============================================================
int calcNotaryDigest(SignedDoc* pSigDoc, NotaryInfo* pNotary)
{
  int err = ERR_OK, l1;
  //AM 24.04.08 increased buffer size for sha256
	char buf1[DIGEST_LEN256+2];

  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(pSigDoc);
  l1 = sizeof(buf1);
  err = calculateNotaryInfoDigest(pSigDoc, pNotary, (byte*)buf1, &l1);
  //err = calculateOcspBasicResponseDigest(br, buf1, &l1);
  if(!err) {
    err = ddocNotInfo_SetOcspDigest(pNotary, buf1, l1);
  }
  return err;
}

//============================================================
// Initializes NotaryInfo object with data from OCSP object
// pSigDoc - digidoc main object pointer
// pNotary - NotaryInfo object to be initialized
// resp - OCSP response object
// notCert - Notary cert object
// return error code
//============================================================
int initializeNotaryInfoWithOCSP(SignedDoc *pSigDoc, NotaryInfo *pNotary, 
				OCSP_RESPONSE *resp, X509 *notCert, int initDigest)
{
  int n, err = ERR_OK, status = 0;
  char buf[500];
  OCSP_RESPBYTES *rb = NULL;
  OCSP_BASICRESP *br = NULL;
  OCSP_SINGLERESP *single = NULL;
  const OCSP_CERTID *cid = NULL;
  X509_EXTENSION *nonce;
  const ASN1_GENERALIZEDTIME *producedAt = NULL;
  //AM 26.09.08
  DigiDocMemBuf mbuf1;
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  const ASN1_OCTET_STRING *id = NULL;
  const X509_NAME *name = NULL;
  ASN1_OBJECT *hashAlgorithm = NULL;

	
  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(resp);
  ddocDebug(3, "initializeNotaryInfoWithOCSP", "OCSP status: %d", OCSP_response_status(resp));
  // save the response in memory
  err = ddocNotInfo_SetOCSPResponse_Value(pNotary, resp);

  // check the OCSP Response validity
  switch(OCSP_response_status(resp)) {
  case OCSP_RESPONSE_STATUS_SUCCESSFUL: // OK
    break;
  case OCSP_RESPONSE_STATUS_MALFORMEDREQUEST:
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_MALFORMED);
  case OCSP_RESPONSE_STATUS_INTERNALERROR:
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_INTERNALERR);
  case OCSP_RESPONSE_STATUS_TRYLATER:
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_TRYLATER);
  case OCSP_RESPONSE_STATUS_SIGREQUIRED:
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_SIGREQUIRED);
  case OCSP_RESPONSE_STATUS_UNAUTHORIZED:
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_UNAUTHORIZED);
  default:
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_UNSUCCESSFUL);
  }
  if((br = OCSP_response_get1_basic(resp)) == NULL) 
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_BASIC_RESP);
  ddocDebug(4, "initializeNotaryInfoWithOCSP", "test2");
  n = OCSP_resp_count(br);
  if(n != 1) 
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_ONE_RESPONSE);
  single = OCSP_resp_get0(br, 0);
  RETURN_IF_NULL(single);
  cid = OCSP_SINGLERESP_get0_id(single);
  RETURN_IF_NULL(cid);
  status = OCSP_single_get0_status(single, NULL, NULL, NULL, NULL);
  ddocDebug(4, "initializeNotaryInfoWithOCSP", "CertStatus-type: %d", status);
  //printf("TYPE: %d\n", single->certStatus->type);
  if(status != 0) {
	ddocDebug(4, "initializeNotaryInfoWithOCSP", "errcode: %d", handleOCSPCertStatus(status));
	SET_LAST_ERROR_RETURN_CODE(handleOCSPCertStatus(status));
  }
  //Removed 31.10.2003
  //if(single->singleExtensions) 
  //	SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_SINGLE_EXT);
  if((OCSP_BASICRESP_get_ext_count(br) != 1) ||
	 ((nonce = OCSP_BASICRESP_get_ext(br, 0)) == NULL))
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_NONCE);
  i2t_ASN1_OBJECT(buf,sizeof(buf), X509_EXTENSION_get_object(nonce));
  if(strcmp(buf, OCSP_NONCE_NAME)) 
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_NONCE);
  OCSP_resp_get0_id(br, &id, &name);
  if(name) {
    pNotary->nRespIdType = RESPID_NAME_TYPE;
  } else if(id) {
    pNotary->nRespIdType = RESPID_KEY_TYPE;
  } else {
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_WRONG_RESPID);
  }
  // producedAt
  producedAt = OCSP_resp_get0_produced_at(br);
  err = asn1time2str(pSigDoc, (ASN1_GENERALIZEDTIME*)producedAt, buf, sizeof(buf));
  setString(&(pNotary->timeProduced), buf, -1);
  n = sizeof(buf);
  if(name){
    //X509_NAME_oneline(rid->value.byName,buf,n);
	err = ddocCertGetDNFromName((X509_NAME*)name, &mbuf1);
    err = ddocNotInfo_SetResponderId(pNotary, (char*)mbuf1.pMem, -1);
    ddocMemBuf_free(&mbuf1);
  }
  if(id) {
	err = ddocNotInfo_SetResponderId(pNotary, (const char*)id->data, id->length);
  }
  OCSP_id_get0_info(NULL, &hashAlgorithm, NULL, NULL, (OCSP_CERTID*)cid);
  // digest type
  i2t_ASN1_OBJECT(buf,sizeof(buf),hashAlgorithm);
  //AM 24.11.09 why its needed? added if. 08.12.09 used for gen
  if(!pNotary->szDigestType){
	  setString(&(pNotary->szDigestType), buf, -1);
  }
#if OPENSSL_VERSION_NUMBER < 0x10010000L
  // signature algorithm
  i2t_ASN1_OBJECT(buf,sizeof(buf),br->signatureAlgorithm->algorithm);
  setString(&(pNotary->szSigType), buf, -1);
#endif
  // notary cert
  if(notCert && !err)
    err = addNotaryInfoCert(pSigDoc, pNotary, notCert);
  // get the digest from original OCSP data
  if(initDigest && notCert) {
    err = calcNotaryDigest(pSigDoc, pNotary);
  }
  if(br != NULL)
    OCSP_BASICRESP_free(br);
  if (err != ERR_OK) SET_LAST_ERROR(err);
  return err;
}

int initializeNotaryInfoWithOCSP2(SignedDoc *pSigDoc, NotaryInfo *pNotary, 
				OCSP_RESPONSE *resp, X509 *notCert, int initDigest)
{
  int n, err = ERR_OK, status = 0;
  char buf[500];
  OCSP_RESPBYTES *rb = NULL;
  OCSP_BASICRESP *br = NULL;
  // OCSP_CERTSTATUS *cst = NULL;
  OCSP_SINGLERESP *single = NULL;
  const OCSP_CERTID *cid = NULL;
  X509_EXTENSION *nonce;
  const ASN1_GENERALIZEDTIME *producedAt = NULL;
  //AM 26.09.08
  DigiDocMemBuf mbuf1;
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  const ASN1_OCTET_STRING *id = NULL;
  const X509_NAME *name = NULL;
  ASN1_OBJECT *hashAlgorithm = NULL;

	
  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(resp);
  // check the OCSP Response validity
  switch(OCSP_response_status(resp)) {
  case OCSP_RESPONSE_STATUS_SUCCESSFUL: // OK
    break;
  case OCSP_RESPONSE_STATUS_MALFORMEDREQUEST:
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_MALFORMED);
  case OCSP_RESPONSE_STATUS_INTERNALERROR:
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_INTERNALERR);
  case OCSP_RESPONSE_STATUS_TRYLATER:
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_TRYLATER);
  case OCSP_RESPONSE_STATUS_SIGREQUIRED:
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_SIGREQUIRED);
  case OCSP_RESPONSE_STATUS_UNAUTHORIZED:
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_UNAUTHORIZED);
  default:
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_UNSUCCESSFUL);
  }
  if((br = OCSP_response_get1_basic(resp)) == NULL) 
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_BASIC_RESP);
  n = OCSP_resp_count(br);
  if(n != 1) 
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_ONE_RESPONSE);
  single = OCSP_resp_get0(br, 0);
  RETURN_IF_NULL(single);
  cid = OCSP_SINGLERESP_get0_id(single);
  RETURN_IF_NULL(cid);
  status = OCSP_single_get0_status(single, NULL, NULL, NULL, NULL);
  ddocDebug(4, "initializeNotaryInfoWithOCSP", "CertStatus-type: %d", status);
  //printf("TYPE: %d\n", single->certStatus->type);
  //Am test
  /*if(single->certStatus->type != 0) {
    ddocDebug(4, "initializeNotaryInfoWithOCSP", "errcode: %d", handleOCSPCertStatus(single->certStatus->type));
    SET_LAST_ERROR_RETURN_CODE(handleOCSPCertStatus(single->certStatus->type));
  }*/
  //Removed 31.10.2003
  //if(single->singleExtensions) 
  //	SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_SINGLE_EXT);
  if((OCSP_BASICRESP_get_ext_count(br) != 1) ||
	 ((nonce = OCSP_BASICRESP_get_ext(br, 0)) == NULL))
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_NONCE);
  i2t_ASN1_OBJECT(buf,sizeof(buf),X509_EXTENSION_get_object(nonce));
  if(strcmp(buf, OCSP_NONCE_NAME)) 
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_NONCE);
  OCSP_resp_get0_id(br, &id, &name);
  if(name) {
    pNotary->nRespIdType = RESPID_NAME_TYPE;
  } else if(id) {
    pNotary->nRespIdType = RESPID_KEY_TYPE;
  } else {
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_WRONG_RESPID);
  }
  // producedAt
  producedAt = OCSP_resp_get0_produced_at(br);
  err = asn1time2str(pSigDoc, (ASN1_GENERALIZEDTIME*)producedAt, buf, sizeof(buf));
  setString(&(pNotary->timeProduced), buf, -1);
  n = sizeof(buf);
  if(name){
	err = ddocCertGetDNFromName((X509_NAME*)name, &mbuf1);
	RETURN_IF_NOT(err == ERR_OK, err);
	err = ddocNotInfo_SetResponderId(pNotary, (char*)mbuf1.pMem, -1);
	ddocMemBuf_free(&mbuf1);
  }
  if(id) {
	err = ddocNotInfo_SetResponderId(pNotary, (const char*)id->data, id->length);
  }
  OCSP_id_get0_info(NULL, &hashAlgorithm, NULL, NULL, (OCSP_CERTID*)cid);
  // digest type
  i2t_ASN1_OBJECT(buf,sizeof(buf),hashAlgorithm);
  setString(&(pNotary->szDigestType), buf, -1);
#if OPENSSL_VERSION_NUMBER < 0x10010000L
  // signature algorithm
  i2t_ASN1_OBJECT(buf,sizeof(buf),br->signatureAlgorithm->algorithm);
  setString(&(pNotary->szSigType), buf, -1);
#endif
  // notary cert
  if(notCert && !err)
    err = addNotaryInfoCert(pSigDoc, pNotary, notCert);
  // save the response in memory
  err = ddocNotInfo_SetOCSPResponse_Value(pNotary, resp);
  // get the digest from original OCSP data
  if(initDigest && notCert) {
    err = calcNotaryDigest(pSigDoc, pNotary);
  }
  if(br != NULL)
    OCSP_BASICRESP_free(br);
  if (err != ERR_OK) SET_LAST_ERROR(err);
  return err;
}

//--------------------------------------------------
// Helper function to read OCSP_RESPONSE from binary input data
// ppResp - address of newly allocated OCSP_RESPONSE object
// pMBufInData - input data
// returns error code or ERR_OK
//--------------------------------------------------
int ddocOcspReadOcspResp(OCSP_RESPONSE** ppResp, DigiDocMemBuf* pMBufInData)
{
  int err = ERR_OK;
  unsigned char* p1;

  RETURN_IF_NULL_PARAM(ppResp);
  RETURN_IF_NULL_PARAM(pMBufInData);
  RETURN_IF_NULL_PARAM(pMBufInData->pMem);
  *ppResp = 0;
  ddocDebug(4, "ddocOcspReadOcspResp", "converting: %d bytes to OCSP_RESPONSE", pMBufInData->nLen);
  p1 = (unsigned char*)pMBufInData->pMem;
  d2i_OCSP_RESPONSE(ppResp, (const unsigned char**)&p1, pMBufInData->nLen);
  ddocDebug(4, "ddocOcspReadOcspResp", "OCSP_RESPONSE: %s", (*ppResp ? "OK" : "ERR"));
  if(!(*ppResp)) err = ERR_OCSP_UNSUCCESSFUL;
  return err;
}

//--------------------------------------------------
// Helper function to write OCSP_RESPONSE to binary output data
// pResp - address of OCSP_RESPONSE object
// pMBufOutData - output data
// returns error code or ERR_OK
//--------------------------------------------------
int ddocOcspWriteOcspResp(OCSP_RESPONSE* pResp, DigiDocMemBuf* pMBufOutData)
{
  int err = ERR_OK, l1;
  unsigned char* p1;

  RETURN_IF_NULL_PARAM(pResp);
  RETURN_IF_NULL_PARAM(pMBufOutData);
  pMBufOutData->pMem = NULL;
  pMBufOutData->nLen = 0;
  // find out how big a buffer we need
  l1 = i2d_OCSP_RESPONSE(pResp, NULL);
  ddocDebug(4, "ddocOcspReadOcspResp", "converting: %d bytes from OCSP_RESPONSE", l1);
  // alloc mem
  err = ddocMemSetLength(pMBufOutData, l1 + 50);  
  p1 = (unsigned char*)pMBufOutData->pMem;
  l1 = i2d_OCSP_RESPONSE(pResp, &p1);
  pMBufOutData->nLen = l1;
  ddocDebug(4, "ddocOcspReadOcspResp", "Converted data: %d", l1);
  return err;
}

//============================================================
// Converts OCSP_RESPONSE to PEM form with or without the headers
// pResp - OCSP_RESPONSE
// bHeaders - 1= with headers, 0=no headers
// buf - output buffer newly allocated
// returns error code
//============================================================
EXP_OPTION int getOcspPEM(OCSP_RESPONSE* pResp, int bHeaders, char** buf)
{
  int l1, l2;
  char *p1, *p2;

  RETURN_IF_NULL_PARAM(buf);
  RETURN_IF_NULL_PARAM(pResp);
  l1 = i2d_OCSP_RESPONSE(pResp, NULL);
  p1 = (char*)malloc(l1+10);
  RETURN_IF_BAD_ALLOC(p1);
  p2 = p1;
  i2d_OCSP_RESPONSE(pResp, (unsigned char**)&p2);
  l2 = l1 * 2 + 200;
  *buf = (char*)malloc(l2);
  if(*buf == NULL) {
    free(p1);
    RETURN_IF_BAD_ALLOC(*buf);
  }
  memset(*buf, 0, l2);
  if(bHeaders)
    strncpy(*buf, "-----BEGIN OCSP RESPONSE-----\n", l2);
  encode((const byte*)p1, l1, (byte*)strchr(*buf, 0), &l2);
  if(bHeaders)
    strncat(*buf, "\n-----END OCSP RESPONSE-----", l2 - strlen(*buf));
  free(p1);
  return ERR_OK;
}

//============================================================
// Converts OCSP_REQUEST to DER form
// pResp - OCSP_REQUEST
// pMBuf - output buffer for OCSP req
// returns error code
//============================================================
EXP_OPTION int ddocWriteOcspDER(OCSP_REQUEST* pReq, DigiDocMemBuf* pMBuf)
{
  int l1;
  char *p1, *p2;

  RETURN_IF_NULL_PARAM(pMBuf);
  RETURN_IF_NULL_PARAM(pReq);
  l1 = i2d_OCSP_REQUEST(pReq, NULL);
  p1 = (char*)malloc(l1+10);
  RETURN_IF_BAD_ALLOC(p1);
  p2 = p1;
  i2d_OCSP_REQUEST(pReq, (unsigned char**)&p2);
  ddocMemAppendData(pMBuf, p1, l1);
  free(p1);
  return ERR_OK;
}


//--------------------------------------------------
// Helper function to return OCSP_RESPONSE in base64 form
// Memory buffer will be resized as necessary.
// Caller must release output buffer.
// pNotary - Notary object
// bHeaders - 1= with headers, 0=no headers
// pMBufOutData - output data
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocGetOcspBase64(NotaryInfo *pNotary, int bHeaders, DigiDocMemBuf* pMBufOutData)
{
  const DigiDocMemBuf *pMBuf = 0;
  DigiDocMemBuf mbuf1;

  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(pMBufOutData);
  pMBufOutData->pMem = 0;
  pMBufOutData->nLen = 0;
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  pMBuf = ddocNotInfo_GetOCSPResponse(pNotary);
  RETURN_IF_NULL(pMBuf);
  if(bHeaders) {
    ddocMemAppendData(pMBufOutData, "-----BEGIN OCSP RESPONSE-----\n", -1);
    ddocEncodeBase64(pMBuf, &mbuf1);
    ddocMemAppendData(pMBufOutData, (const char*)mbuf1.pMem, mbuf1.nLen);
    ddocMemAppendData(pMBufOutData, "\n-----END OCSP RESPONSE-----", -1);
    ddocMemBuf_free(&mbuf1);
  }
  else
    ddocEncodeBase64(pMBuf, pMBufOutData);
  return ERR_OK;
}


//--------------------------------------------------
// teeb 00:0a:df stiilis hexprinditud stringist tagasi tavalise
//--------------------------------------------------
// Tanel - ver 1.66
unsigned char *decodeHex(unsigned char *str)
{
  unsigned int i, j, k, len;
  unsigned char *ret;
  static unsigned char hex[] = { '0', '1', '2', '3', '4', '5', '6', '7', 
				 '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
  
  len = (int)(strlen((const char*)str) / 3) + 2;
  if((ret=(unsigned char*)malloc(len)) == NULL)
    return NULL;
  memset(ret, 0, len);
  for(i=0, j=0; i<strlen((const char*)str); i+=3) {
    for(k=0; k<16; k++)
      if(str[i] == hex[k])
	ret[j] = (unsigned char)(k<<4);
    for(k=0; k<16; k++)
      if(str[i+1] == hex[k])
	ret[j++] += (unsigned char)k;
  }
  return(ret);
}

//--------------------------------------------------
// otsib X.509v3 laienduste seest Authority Key Identifieri välja
//--------------------------------------------------
// Tanel - ver 1.66
unsigned char *get_authority_key(STACK_OF(X509_EXTENSION) *exts)
{
  int i, found=0;
  X509_EXTENSION *ex=0;
  ASN1_OBJECT *obj;
  ASN1_OCTET_STRING *data = NULL;
  X509V3_EXT_METHOD *met;
  void *st = NULL;
  unsigned char *p;
  STACK_OF(CONF_VALUE) *vals=NULL;
  CONF_VALUE *val;
  unsigned char *ret = 0;
  
  for(i=0; i<sk_X509_EXTENSION_num(exts); i++) {
    ex = sk_X509_EXTENSION_value(exts, i);
    obj = X509_EXTENSION_get_object(ex);
    if(OBJ_obj2nid(obj) == NID_authority_key_identifier) {
      found++;
      break;
    }
  }

  if(!found) {
    ddocDebug(4, "get_authority_key", "Extension not found");
    return(NULL);
  }
  
  met = (X509V3_EXT_METHOD*)X509V3_EXT_get(ex);
  data = X509_EXTENSION_get_data(ex);
  p = data->data;
#if OPENSSL_VERSION_NUMBER > 0x00908000
  // crashes here!
  st = ASN1_item_d2i(NULL, (const unsigned char**)&p, data->length, ASN1_ITEM_ptr(met->it));
#else
  st = ASN1_item_d2i(NULL, &p, ex->value->length, ASN1_ITEM_ptr(met->it));
#endif
  vals = met->i2v(met, st, NULL);

  /* P.R */
  ASN1_item_free((ASN1_VALUE *)st, ASN1_ITEM_ptr(met->it));
  /* P.R */
  
  for(i=0; i<sk_CONF_VALUE_num(vals); i++) {
    val = sk_CONF_VALUE_value(vals, i);
    ddocDebug(4, "get_authority_key", "Extension %s - %s", val->name, val->value);
    if(val->name && (strcmp(val->name, "keyid") == 0))
	  ret = decodeHex((unsigned char*)val->value);
  }
  /* P.R */ 
  sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
  /* P.R */
 
  return ret;

}



//--------------------------------------------------
// otsib X.509 seest Authority Key Identifieri välja
//--------------------------------------------------
unsigned char *get_authority_key_from_cert(X509 *x)
{
  unsigned char *ret = 0;
  AUTHORITY_KEYID *val = (AUTHORITY_KEYID*)X509_get_ext_d2i( x, NID_authority_key_identifier, NULL, NULL );
  if(!val) {
	ddocDebug(4, "get_authority_key_from_cert", "Extension not found");
	return(NULL);
  }

  //ret = ASN1_STRING_data(val->keyid);
  // workaround encode/decode bugs
  ret = decodeHex((unsigned char*)hex_to_string(ASN1_STRING_data(val->keyid), ASN1_STRING_length(val->keyid)));
  AUTHORITY_KEYID_free(val);

  return ret;
}



//--------------------------------------------------
// creates OCSP_CERTID without using the issuer cert
// cert - certificate for which we need certid
// returns OCSP_CERTID pointer
//--------------------------------------------------
// Tanel - ver 1.66
OCSP_CERTID* createOCSPCertid(X509 *cert, X509* pCACert)
{
  OCSP_CERTID *pId = NULL;
  X509_NAME *iname;
  ASN1_INTEGER *sno;
  DigiDocMemBuf mbuf1, mbuf2;
  AUTHORITY_KEYID *val = NULL;

  mbuf1.pMem = mbuf2.pMem = NULL;
  mbuf1.nLen = mbuf2.nLen = 0;
  if(cert != NULL) {
	  ddocCertGetSubjectDN(cert, &mbuf1);
    // standard variant would be
    //pId = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
	  if(pCACert) {
		  ddocCertGetSubjectDN(pCACert, &mbuf2);
		  ddocDebug(3, "createOCSPCertid", "Create ocsp id for cert: %s by CA: %s", (char*)mbuf1.pMem, (char*)mbuf2.pMem);
		pId = OCSP_cert_to_id(EVP_sha1(), cert, pCACert);

	  } else { // CA unknown
		  ddocDebug(3, "createOCSPCertid", "Create ocsp id for cert: %s unknown CA", (char*)mbuf1.pMem);
		// issuer name hashi arvutamine 
		val = (AUTHORITY_KEYID*)X509_get_ext_d2i(cert, NID_authority_key_identifier, NULL, NULL );
		if(!val) {
		  ddocDebug(4, "get_authority_key_from_cert", "Extension not found");
		  return(NULL);
		}
		sno = X509_get_serialNumber(cert);
		iname = X509_get_issuer_name(cert);
		pId = OCSP_cert_id_new(EVP_sha1(), iname, val->keyid, sno);
	  }
  }
  ddocMemBuf_free(&mbuf1);
  ddocMemBuf_free(&mbuf2);
  ddocDebug(3, "createOCSPCertid", "Created ocsp id %s issuer-key-hash", (pId ? "OK" : "ERR"));
  return pId;
}


//--------------------------------------------------
// Creates an OCSP_REQUEST object
// pSigDoc - address of signed document. If not NULL then
// used to check if older openssl 0.9.6 style request must
// be constructed.
// req - buffer for storing the pointer of new object
// cert - client certificate to verify
// nonce - nonce value (e.g. client signature value RSA-128 bytes)
// nlen - nonce value length
// pkey - public key used to signe th request (not used yet)
//--------------------------------------------------
// VS - ver 1.66
int createOCSPRequest(SignedDoc* pSigDoc, OCSP_REQUEST **req, 
		      X509 *cert, X509* pCACert, byte* nonce, int nlen)
{
  int err = ERR_OK, l2;
  OCSP_CERTID *id = 0;
  byte buf2[DIGEST_LEN256 * 2 + 2];
    
  RETURN_IF_NULL_PARAM(req);
  RETURN_IF_NULL_PARAM(cert);
  RETURN_IF_NULL_PARAM(nonce);
  //RETURN_IF_NULL_PARAM(pCACert);
  if((*req = OCSP_REQUEST_new()) != 0) {
    if((id = createOCSPCertid(cert, pCACert)) != 0) {
      if(OCSP_request_add0_id(*req, id)) {
	    if((err = OCSP_request_add1_nonce(*req, nonce, nlen)) != 0)
	       err = ERR_OK;
        // debug
          l2 = sizeof(buf2);
          memset(buf2, 0, l2);
          if(nlen <= DIGEST_LEN256) {
              bin2hex((const char*)nonce, nlen, (byte*)buf2, &l2);  
              ddocDebug(3, "createOCSPRequest", "Sending nonce: %s len: %d err: %d", buf2, nlen, err);
          }  
      }
    }
  }
  return err;
}

/* Quick and dirty HTTP OCSP request handler.
 * Could make this a bit cleverer by adding
 * support for non blocking BIOs and a few
 * other refinements.
 * Qick and dirty adaption of openssl -s 
 * OCSP_sendreq_bio() to add UserAgent HTTP header
 */

OCSP_RESPONSE *OCSP_sendreq_bio_withParams(BIO *b, char *path, 
				      OCSP_REQUEST *req, unsigned long ip_addr )
{
  BIO *mem = NULL;
  char tmpbuf[1024], adrhdr[100];
  OCSP_RESPONSE *resp = NULL;
  char *p, *q, *r;
  int len, retcode;
  static char req_txt[] =
"POST %s HTTP/1.0\r\n\
Content-Type: application/ocsp-request\r\n\
User-Agent: LIB %s/%s APP %s\r\n%s\
Content-Length: %d\r\n\r\n";

  adrhdr[0] = 0;
  if(ip_addr > 0)
    snprintf(adrhdr, sizeof(adrhdr), "From: %d.%d.%d.%d\r\n", 
    (int)(ip_addr>>24)&0xFF, (int)(ip_addr>>16)&0xFF, (int)(ip_addr>>8)&0xFF, (int)(ip_addr&0xFF)); 
  len = i2d_OCSP_REQUEST(req, NULL);
  if(BIO_printf(b, req_txt, path, getLibName(), getLibVersion(), 
		getGUIVersion(), (ip_addr > 0 ? adrhdr : ""), len) < 0) {
    OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_WRITE_ERROR);
    goto err;
  }
#if OPENSSL_VERSION_NUMBER > 0x00908000
  retcode = ASN1_i2d_bio((int (*)(void*, unsigned char**))i2d_OCSP_REQUEST, b, (unsigned char*)req);
#else
  retcode = ASN1_i2d_bio((int (*)())i2d_OCSP_REQUEST, b, (unsigned char*)req);
#endif
  if(retcode <= 0) {
    OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_WRITE_ERROR);
    goto err;
  }
  mem = BIO_new(BIO_s_mem());
  if(!mem) goto err;
  /* Copy response to a memory BIO: socket bios can't do gets! */
  do {
    len = BIO_read(b, tmpbuf, sizeof tmpbuf);
    if(len < 0) {
      OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_READ_ERROR);
      goto err;
    }
    BIO_write(mem, tmpbuf, len);
  } while(len > 0);
  if(BIO_gets(mem, tmpbuf, 512) <= 0) {
    OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_RESPONSE_PARSE_ERROR);
    goto err;
  }
  /* Parse the HTTP response. This will look like this:
   * "HTTP/1.0 200 OK". We need to obtain the numeric code and
   * (optional) informational message.
   */
  
  /* Skip to first white space (passed protocol info) */
  for(p = tmpbuf; *p && !isspace((unsigned char)*p); p++) continue;
  if(!*p) {
    OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_RESPONSE_PARSE_ERROR);
    goto err;
  }
  /* Skip past white space to start of response code */
  while(*p && isspace((unsigned char)*p)) p++;
  if(!*p) {
    OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_RESPONSE_PARSE_ERROR);
    goto err;
  }
  /* Find end of response code: first whitespace after start of code */
  for(q = p; *q && !isspace((unsigned char)*q); q++) continue;
  if(!*q) {
    OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_RESPONSE_PARSE_ERROR);
    goto err;
  }
  /* Set end of response code and start of message */ 
  *q++ = 0;
  /* Attempt to parse numeric code */
  retcode = strtoul(p, &r, 10);
  if(*r) goto err;
  /* Skip over any leading white space in message */
  while(*q && isspace((unsigned char)*q))  q++;
  if(*q) {
    /* Finally zap any trailing white space in message (include CRLF) */
    /* We know q has a non white space character so this is OK */
    for(r = q + strlen(q) - 1; isspace((unsigned char)*r); r--) *r = 0;
  }
  if(retcode != 200) {
    OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_RESPONSE_ERROR);
    if(!*q) { 
      ERR_add_error_data(2, "Code=", p);
    }
    else {
      ERR_add_error_data(4, "Code=", p, ",Reason=", q);
    }
    goto err;
  }
  /* Find blank line marking beginning of content */	
  while(BIO_gets(mem, tmpbuf, 512) > 0)
  {
    for(p = tmpbuf; *p && isspace((unsigned char)*p); p++) continue;
    if(!*p) break;
  }
  if(*p) {
    OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_NO_CONTENT);
    goto err;
  }
  resp = d2i_OCSP_RESPONSE_bio(mem, NULL);
  if(!resp) {
    OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,ERR_R_NESTED_ASN1_ERROR);
    goto err;
  }
 err:
  BIO_free(mem);
  return resp;
}


//--------------------------------------------------
// sends an OCSP_REQUES object to remore server and
// retrieves the OCSP_RESPONSE object
// resp - buffer to store the new responses pointer
// req - request objects pointer
// url - OCSP responder URL
// ip_addr - senders ip address if known or 0
//--------------------------------------------------
int sendOCSPRequest(OCSP_RESPONSE** resp, OCSP_REQUEST *req, 
		    char* url, char* proxyHost, char* proxyPort,
		    unsigned long ip_addr)
{	
  BIO* cbio = 0, *sbio = 0;
  SSL_CTX *ctx = NULL;
  char *host = NULL, *port = NULL, *path = "/";
  int err = ERR_OK, use_ssl = -1;
  int connResult = 0;
  long e = 0;

  RETURN_IF_NULL_PARAM(resp);
  RETURN_IF_NULL_PARAM(req);
  RETURN_IF_NULL_PARAM(url);

  //there is an HTTP proxy - connect to that instead of the target host
  ddocDebug(3, "sendOCSPRequest", "Send OCSP to: %s over: %s:%s", url,
	    (proxyHost ? proxyHost : ""), (proxyPort ? proxyPort : ""));
  if (proxyHost != 0 && *proxyHost != '\0') {
    host = proxyHost;
    if(proxyPort != 0 && *proxyPort != '\0')
      port = proxyPort;
    path = url;
  } else {
    if((err = OCSP_parse_url(url, &host, &port, &path, &use_ssl)) == 0) {
      //printf("BIO_parse_url failed\n");
		ddocDebug(1, "sendOCSPRequest", "BIO_parse_url failed: %d - %s", err, url);
      return ERR_WRONG_URL_OR_PROXY; 
    }
  }
  if((cbio = BIO_new_connect(host)) != 0) {
    if(port != NULL)
      BIO_set_conn_port(cbio, port);
    if (use_ssl == 1) {
      ctx = SSL_CTX_new(SSLv23_client_method());
      SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
      sbio = BIO_new_ssl(ctx, 1);
      cbio = BIO_push(sbio, cbio);
    }
    if ((connResult = BIO_do_connect(cbio)) > 0) {
	  e = checkErrors();
      //printf("BIO_do_connect returned %d\n", connResult);
      *resp = OCSP_sendreq_bio_withParams(cbio, path, req, ip_addr);
      //printf("OCSP_sendreq_bio answered %lX\n", *resp);
	  e = checkErrors();
	  if(ERR_GET_REASON(e) == BIO_R_BAD_HOSTNAME_LOOKUP ||
		 ERR_GET_REASON(e) == OCSP_R_SERVER_WRITE_ERROR)
		  err = ERR_CONNECTION_FAILURE;
	  //if(ERR_GET_REASON(e) == BIO_R_BAD_HOSTNAME_LOOKUP)
	//	  err = ERR_CONNECTION_FAILURE;
	  else
		err = (*resp == 0) ? ERR_OCSP_WRONG_URL : ERR_OK;
      //if (*resp == 0) 
      //  printErrors();
    } else {
		ddocDebug(1, "sendOCSPRequest", "BIO-Connection error: %d - %ld", err, e);
      //printf("BIO_do_connect failed, rc = %d, shouldRetry = %d\n", connResult, BIO_should_retry(cbio));
      //printErrors();
      //if no connection
      if (host != NULL)
	err = ERR_WRONG_URL_OR_PROXY;
      else
	err = ERR_CONNECTION_FAILURE;
    }
    BIO_free_all(cbio);
    if (use_ssl != -1) {
      OPENSSL_free(host);
      OPENSSL_free(port);
      OPENSSL_free(path);
      SSL_CTX_free(ctx);
    }
  }
  else {
    err = ERR_CONNECTION_FAILURE;
	ddocDebug(1, "sendOCSPRequest", "Connection error: %d", err);
  }
  return(err);
}


//--------------------------------------------------
// sends an OCSP_REQUES object to remore server and
// retrieves the OCSP_RESPONSE object
// resp - buffer to store the new responses pointer
// req - request objects pointer
// url - OCSP responder URL
// ip_addr - senders ip address if known or 0
//--------------------------------------------------
int sendOCSPRequest2(OCSP_RESPONSE** resp, OCSP_REQUEST *req, 
		    char* url, char* proxyHost, char* proxyPort, char *proxyUser, char *proxyPass,
		    unsigned long ip_addr)
{
  int err = ERR_OK, l1 = 0;
  DigiDocMemBuf mbuf1, mbuf2, mbuf3;
  char buf1[30], buf2[200], buf3[100], *p1;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  mbuf2.pMem = 0;
  mbuf2.nLen = 0;
  mbuf3.pMem = 0;
  mbuf3.nLen = 0;
  ddocMemAssignData(&mbuf1, "POST ", -1);
  if(proxyHost || (proxyPort && atoi(proxyPort) > 0)) {
    ddocMemAppendData(&mbuf1, url, -1);
  } else {
    p1 = strstr(url, "://");
    if(p1) p1 += 3;
    if(p1) p1 = strchr(p1, '/');
    if(p1)
      ddocMemAppendData(&mbuf1, p1, -1);
    else
      ddocMemAppendData(&mbuf1, "/", -1);
  }
  ddocMemAppendData(&mbuf1, " HTTP/1.0\r\n", -1);
  buf1[0] = buf2[0] = 0;
  if(ip_addr > 0)
    snprintf(buf1, sizeof(buf1), "From: %d.%d.%d.%d\r\n", 
    (int)(ip_addr>>24)&0xFF, (int)(ip_addr>>16)&0xFF, (int)(ip_addr>>8)&0xFF, (int)ip_addr&0xFF);
  snprintf(buf2, sizeof(buf2), "User-Agent: LIB %s/%s APP %s\r\n%s", 
	getLibName(), getLibVersion(), getGUIVersion(), (ip_addr > 0 ? buf1 : ""));
  ddocMemAppendData(&mbuf1, "Content-Type: application/ocsp-request\r\n", -1);
  ddocMemAppendData(&mbuf1, buf2, -1);
  //ddocMemAppendData(&mbuf1, "Host: www.sk.ee\r\n", -1);
  //ddocMemAppendData(&mbuf1, "Accept: */*\r\n", -1);
  // convert OCSP req
  err = ddocWriteOcspDER(req, &mbuf3);
  if(!err) {
    snprintf(buf1, sizeof(buf1), "Content-Length: %d\r\n", (int)mbuf3.nLen);
    ddocMemAppendData(&mbuf1, buf1, -1);
    ddocMemAppendData(&mbuf1, "Connection: Close\r\n", -1);
    if(proxyUser || proxyPass) {
      err = ddocOcspProxyAuthInfo(buf3, proxyUser, proxyPass);
      ddocMemAppendData(&mbuf1, buf3, -1);
    }
    if(proxyHost || (proxyPort && atoi(proxyPort) > 0)) // if we use proxy then send also Proxy-Connection
      ddocMemAppendData(&mbuf1, "Proxy-Connection: Close\r\n", -1);
    ddocMemAppendData(&mbuf1, "\r\n", -1);
    ddocMemAppendData(&mbuf1, mbuf3.pMem, mbuf3.nLen);
	ddocMemBuf_free(&mbuf3);
    ddocDebug(3, "sendOCSPRequest2", "Send to host: %s request len: %d", url, mbuf1.nLen);
    err = ddocPullUrl(url, &mbuf1, &mbuf2, proxyHost, proxyPort);
    ddocDebug(3, "sendOCSPRequest2", "Recevied len: %d RC: %d", mbuf2.nLen, err);
    if(!err && ((l1 = ddocGetHttpResponseCode(&mbuf2)) == 200)) {
	  ddocDebug(4, "sendOCSPRequest2", "HTTP response\n-----\n%s\n-----\n", mbuf2.pMem);
	  err = ddocGetHttpPayload(&mbuf2, &mbuf3);
	  if(!err)
	  err = ddocOcspReadOcspResp(resp, &mbuf3);
	} else {
        ddocDebug(1, "sendOCSPRequest2", "Ocsp request failed with http code: %d rc: %d", l1, err);
        err = ERR_OCSP_UNSUCCESSFUL;
		ddocDebug(1, "sendOCSPRequest2", "HTTP error message\n-----\n%s\n-----\n", mbuf2.pMem);
	}
  }
  // cleanup
  ddocMemBuf_free(&mbuf1);
  ddocMemBuf_free(&mbuf2);
  ddocMemBuf_free(&mbuf3);
  return err;
}


//--------------------------------------------------
// Creates and writes an OCSP_REQUEST object
// to disk
// pSigDoc - signedDoc address
// signerCertFile - cert file to verify
// issuertCertFile - this certs direct CA cert
// nonce - nonce (signature value)
// nlen - nonce length
// szOutputFile - output filename
//--------------------------------------------------
 EXP_OPTION int writeOCSPRequest(SignedDoc* pSigDoc, 
				 const char* signerCertFile, const char* issuertCertFile,
				 byte* nonce, int nlen, const char* szOutputFile) 

{
  OCSP_REQUEST *req = 0;
  X509 *cert = 0, *issuer = 0;
  int err = ERR_OK, l1;
  //EVP_PKEY* pkey; 
  byte buf1[DIGEST_LEN+2];

  RETURN_IF_NULL_PARAM(signerCertFile);
  RETURN_IF_NULL_PARAM(issuertCertFile);
  RETURN_IF_NULL_PARAM(nonce);
  RETURN_IF_NULL_PARAM(szOutputFile);

  if((err = ReadCertificate(&cert, signerCertFile)) == ERR_OK) {
    //pkey = ReadPublicKey(signerCertFile);
    if((err = ReadCertificate(&issuer, issuertCertFile)) == ERR_OK) {
      l1 = sizeof(buf1);
      calculateDigest(nonce, nlen, DIGEST_SHA1, buf1, &l1);
      err = createOCSPRequest(pSigDoc, &req, cert, issuer, buf1, l1);
      //WriteOCSPRequest(szOutputFile, req);
      X509_free(issuer);
			//AM 22.04.08
			if(req)
				OCSP_REQUEST_free(req);
    }
    X509_free(cert);
  }
  return err;
}

//--------------------------------------------------
// Signs an OCSP_REQUEST using PKCS#12 conteiner
// req - OCSP_REQUEST
// filename - PKCS#12 conteiner file
// passwd - key decryption passwd
//--------------------------------------------------
EXP_OPTION int signOCSPRequestPKCS12(OCSP_REQUEST *req, const char* filename, const char* passwd)
{
  EVP_PKEY *pkey;
  int err = ERR_OK;
  
  STACK_OF(X509)* certs = NULL;
  X509* x509=0;
#ifdef FRAMEWORK
    SecIdentityRef identity = 0;
    err = SecIdentityCopyPreference(CFSTR("ocsp.sk.ee"), 0, 0, &identity);
    if(identity) {
        SecCertificateRef certref = 0;
        SecKeyRef keyref = 0;
        err = SecIdentityCopyCertificate(identity, &certref);
        err = SecIdentityCopyPrivateKey(identity, &keyref);
        CFRelease(identity);
        RETURN_IF_NULL(certref);
        RETURN_IF_NULL(keyref);

        CFDataRef certdata = SecCertificateCopyData(certref);
        CFRelease(certref);
        RETURN_IF_NULL(certdata);
        const unsigned char *p = CFDataGetBytePtr(certdata);
        x509 = d2i_X509(0, &p, CFDataGetLength(certdata));
        CFRelease(certdata);
        RETURN_IF_NULL(x509);

        CFDataRef keydata = 0;
        SecKeyImportExportParameters params;
        memset( &params, 0, sizeof(params) );
        params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
        params.passphrase = CFSTR("pass");
        err = SecKeychainItemExport(keyref, kSecFormatWrappedPKCS8, 0, &params, &keydata);
        CFRelease(keyref);
        RETURN_IF_NULL(keydata);
        BIO *bio = BIO_new_mem_buf((void*)CFDataGetBytePtr(keydata), CFDataGetLength(keydata));
        pkey = d2i_PKCS8PrivateKey_bio(bio, 0, &password_callback, 0);
        CFRelease(keydata);
        BIO_free(bio);

        RETURN_IF_NULL(pkey);
    } else {
#endif
  RETURN_IF_NULL_PARAM(filename);
  if(strlen(filename) == 0)
    return ERR_OK;

  err = ReadCertificateByPKCS12(&x509, filename, passwd, &pkey);
  RETURN_IF_NOT(err == ERR_OK, err);
#ifdef FRAMEWORK
    }
#endif

#if 0 // miscalulates on mac time zone
  // VS: ver 1.66
  time(&tNow);
  err = isCertValid(x509, tNow);
#else
  if( X509_cmp_current_time(X509_get0_notBefore(x509)) >= 0 &&
	  X509_cmp_current_time(X509_get0_notAfter(x509)) <= 0)
    err = ERR_CERT_INVALID;
#endif
  if (err != ERR_OK)
    X509_free(x509);
  RETURN_IF_NOT(err == ERR_OK, ERR_PKCS12_EXPIRED);
  certs = sk_X509_new_null();
  RETURN_IF_NULL(certs);

  //sk_X509_push(certs, x509);
  if (! OCSP_request_sign(req,x509,pkey,EVP_sha1(),certs,0)) {
    EVP_PKEY_free(pkey);
    err = ERR_OCSP_SIGN;
    SET_LAST_ERROR(err);
  }
  X509_free(x509);
  EVP_PKEY_free(pkey);
	//AM 22.04.08
	sk_X509_free(certs);
  return err;
}

//--------------------------------------------------
// Signs an OCSP_REQUEST using X509 cert and separate keyfile
// req - OCSP_REQUEST
// certFile - signers certificate file
// keyfile - signer's key file
// passwd - key decryption passwd
//--------------------------------------------------
EXP_OPTION int signOCSPRequest(OCSP_REQUEST *req,const char* certFile,const char* keyfile,const char* passwd){
	
  EVP_PKEY *pkey;
  int err = ERR_OK;
  STACK_OF(X509)* certs = NULL;
  X509* x509 = NULL;
  
  certs = sk_X509_new_null();
  RETURN_IF_NULL_PARAM(certs);
  
  if((err = ReadCertificate(&x509, certFile)) != ERR_OK) {
    SET_LAST_ERROR_RETURN_CODE(ERR_PKCS_CERT_LOC);
  }
  sk_X509_push(certs, x509);
  if((err = ReadPrivateKey(&pkey, keyfile, passwd, FILE_FORMAT_PEM)) == ERR_OK) {
    //ASN1_item_sign(ASN1_ITEM_rptr(OCSP_REQINFO),req->optionalSignature->signatureAlgorithm,NULL,req->optionalSignature->signature,req->tbsRequest,pkey,setSignAlgorithm(EVP_sha1()));
    //OCSP_request_sign_internal(req, x509,pkey, NULL);
    if(! OCSP_request_sign(req,x509,pkey,EVP_sha1(),certs,0)){
      EVP_PKEY_free(pkey);
      SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_SIGN);
    }
    //printf("OCSP_request_sign()=%d \n",r);
    EVP_PKEY_free(pkey);
  }else{
    SET_LAST_ERROR_RETURN_CODE(ERR_PRIVKEY_READ);
  }
  return err;
}

//--------------------------------------------------
// Creates and sends an OCSP_REQUEST object
// to the notary server, receives the response
// and uses it to create a confirmation object.
// pSigDoc - signed doc info
// pSigInfo - signature info
// caCerts - responder CA certs chain
// notaryCert - notarys cert search
// pkcs12FileName -  
// pkcs12Password - 
// notaryURL - notarys URL
// proxyHost - proxy host if needed
// proxyPort - proxy port if needed
//--------------------------------------------------
EXP_OPTION int getConfirmation(SignedDoc* pSigDoc, SignatureInfo* pSigInfo, 
			       const X509** caCerts, const X509* pNotCert,
			       char* pkcs12FileName, char* pkcs12Password,
			       char* notaryURL, char* proxyHost, char* proxyPort) 

{
  // default way to invoke it is without callers ip.
  return getConfirmationWithIp(pSigDoc, pSigInfo, caCerts, pNotCert,
			       pkcs12FileName, pkcs12Password,
			       notaryURL, proxyHost, proxyPort, 0);
}

//--------------------------------------------------
// Creates and sends an OCSP_REQUEST object
// to the notary server, receives the response
// and uses it to create a confirmation object.
// pSigDoc - signed doc info
// pSigInfo - signature info
// caCerts - responder CA certs chain
// notaryCert - notarys cert search
// pkcs12FileName -  
// pkcs12Password - 
// notaryURL - notarys URL
// proxyHost - proxy host if needed
// proxyPort - proxy port if needed
// ip - callers ip address if known
//--------------------------------------------------
EXP_OPTION int getConfirmationWithIp(SignedDoc* pSigDoc, SignatureInfo* pSigInfo, 
				     const X509** caCerts, const X509* pNotCert,
				     char* pkcs12FileName, char* pkcs12Password,
				     char* notaryURL, char* proxyHost, char* proxyPort,
				     unsigned long ip)
{
  return getConfirmationWithIpEx(pSigDoc, pSigInfo, caCerts, pNotCert,
    pkcs12FileName, pkcs12Password, notaryURL, proxyHost, proxyPort, 0, 0, ip);
}

//--------------------------------------------------
// Creates and sends an OCSP_REQUEST object
// to the notary server, receives the response
// and uses it to create a confirmation object.
// pSigDoc - signed doc info
// pSigInfo - signature info
// caCerts - responder CA certs chain
// notaryCert - notarys cert search
// pkcs12FileName -
// pkcs12Password -
// notaryURL - notarys URL
// proxyHost - proxy host if needed
// proxyPort - proxy port if needed
// proxyUser - proxy user if needed
// proxyPass - proxy pass if needed
// ip - callers ip address if known
//--------------------------------------------------
EXP_OPTION int getConfirmationWithIpEx(SignedDoc* pSigDoc, SignatureInfo* pSigInfo,
                     const X509** caCerts, const X509* pNotCert,
                     char* pkcs12FileName, char* pkcs12Password,
                     char* notaryURL, char* proxyHost, char* proxyPort,
                     char* proxyUser, char* proxyPass, unsigned long ip)
{
  OCSP_REQUEST *req = 0;
  OCSP_RESPONSE *resp = 0;
  X509 *cert = 0, *pCA = 0;
  int err = ERR_OK, l1, i;
  byte buf1[DIGEST_LEN256+2];
  NotaryInfo* pNotInf = NULL;
  DigiDocMemBuf* pMBuf;

  RETURN_IF_NULL_PARAM(pSigDoc);
  RETURN_IF_NULL_PARAM(pSigInfo);
  cert = ddocSigInfo_GetSignersCert(pSigInfo);
  RETURN_IF_NULL(cert);	
  RETURN_IF_NULL_PARAM(notaryURL);
  
  clearErrors();
	
  l1 = sizeof(buf1);
  pMBuf = ddocSigInfo_GetSignatureValue_Value(pSigInfo);
  RETURN_IF_NOT(pMBuf, err);
#ifdef WIN32
  RAND_screen();
  RAND_bytes((unsigned char*)buf1, DIGEST_LEN);
#else
  if((l1 = RAND_load_file("/dev/urandom", 1024)) > 0) {
    RAND_bytes((unsigned char*)buf1, DIGEST_LEN);
    l1 = DIGEST_LEN;
  }
#endif
  err = calculateDigest(pMBuf->pMem, pMBuf->nLen, DIGEST_SHA1, buf1, &l1);
  RETURN_IF_NOT(err == ERR_OK, err);
  
  // find lowest CA cert
  for(i = 0; (caCerts != NULL) && (caCerts[i] != NULL); i++)
    pCA = (X509*)caCerts[i];
  err = createOCSPRequest(pSigDoc, &req, cert, pCA, buf1, l1);

  // if both are NULL then this means don't sign OCSP requests
  if(!err && ConfigItem_lookup_bool("SIGN_OCSP", 1) /*pkcs12FileName && pkcs12Password*/) {
    ddocDebug(3, "getConfirmationWithIp", "Sign OCSP request with: %s", pkcs12FileName);
    err=signOCSPRequestPKCS12(req, pkcs12FileName, pkcs12Password);
    ddocDebug(3, "getConfirmationWithIp", "Signing ocsp rc: %d", err);
  }
  
  if(!err) {
    ddocDebug(3, "getConfirmationWithIp", "Send OCSP to: %s over: %s:%s", notaryURL,
	    (proxyHost ? proxyHost : ""), (proxyPort ? proxyPort : ""));
    err = sendOCSPRequest2(&resp, req, notaryURL, proxyHost, proxyPort, proxyUser, proxyPass, ip);
  }
  if(!err)
    err = NotaryInfo_new(&pNotInf, pSigDoc, pSigInfo);
  //AM initializeNotaryInfoWithOCSP2?
  if(!err)
   err = initializeNotaryInfoWithOCSP(pSigDoc, pNotInf, resp, NULL, 1);

  if(!err && caCerts && pNotCert) {
    err = finalizeAndVerifyNotary(pSigDoc, pSigInfo, pNotInf, caCerts, pNotCert);
  }
  // VS - if finalizing notary fails then remove it - #8602
  if(err) {
	 if(pNotInf)
        ddocDebug(3, "getConfirmationWithIp", "Delete notary: %s because of error: %d", pNotInf->szId, err);
	 NotaryInfo_delete(pSigInfo);
  }
  if(resp)
    OCSP_RESPONSE_free(resp);
  if(req)
	OCSP_REQUEST_free(req);
  return err;
}

//--------------------------------------------------
// Adds responder certificate to notary, searches it's
// CA chain and then verifies notary
// pSigDoc - signed doc info
// pSigInfo - signature info
// caCertSearches - responder CA certs chain
// notaryCert - notarys cert search
// returns error code
//--------------------------------------------------
int EXP_OPTION finalizeAndVerifyNotary2(SignedDoc* pSigDoc, SignatureInfo* pSigInfo, 
				       NotaryInfo* pNotInf,
				       const X509** caCerts, const X509* pNotCert, const X509* pSigCa)
{
  int err = ERR_OK;

  RETURN_IF_NULL_PARAM(pNotCert);
  RETURN_IF_NULL_PARAM(caCerts);
  ddocDebug(3, "finalizeAndVerifyNotary2", "Notary: %s cert: %s", pNotInf->szId, (pNotCert ? "OK" : "NULL"));
  err = addNotaryInfoCert(pSigDoc, pNotInf, (X509*)pNotCert);
  RETURN_IF_NOT(err == ERR_OK, err);
  err = calcNotaryDigest(pSigDoc, pNotInf);
  RETURN_IF_NOT(err == ERR_OK, err);
  err = verifyNotaryInfoCERT2(pSigDoc, pSigInfo, pNotInf, caCerts, NULL, pNotCert, pSigCa);
  RETURN_IF_NOT(err == ERR_OK, err);
  ddocDebug(3, "finalizeAndVerifyNotary2", "rc: %d cert: %s cert2: %s", err, (pNotCert ? "OK" : "NULL"), (ddocSigInfo_GetOCSPRespondersCert(pSigInfo) ? "OK" : "NULL"));
  return ERR_OK;
}

//--------------------------------------------------
// Adds responder certificate to notary, searches it's
// CA chain and then verifies notary
// pSigDoc - signed doc info
// pSigInfo - signature info
// caCertSearches - responder CA certs chain
// notaryCert - notarys cert search
// returns error code
//--------------------------------------------------
int EXP_OPTION finalizeAndVerifyNotary(SignedDoc* pSigDoc, SignatureInfo* pSigInfo, 
				       NotaryInfo* pNotInf,
				       const X509** caCerts, const X509* pNotCert)
{
  return finalizeAndVerifyNotary2(pSigDoc, pSigInfo, pNotInf, caCerts, pNotCert, NULL);
}


//--------------------------------------------------
// Verfies OCSP_RESPONSE signature
// pResp - signed OCSP response
// caCerts - CA certificate pointer array terminated with NULL
// CApath - path to (directory) all certs
// notCertFile - Notary (e.g. OCSP responder) cert file 
//--------------------------------------------------
int verifyOCSPResponse(OCSP_RESPONSE* pResp, 
				    const X509** caCerts, const char *CApath, 
				    const X509* notCert)
{
  X509_STORE *store;
  OCSP_BASICRESP* bs = NULL;
  STACK_OF(X509)* ver_certs = NULL;
  int err = ERR_OK;
  
  RETURN_IF_NULL_PARAM(pResp);
  RETURN_IF_NOT(caCerts != NULL, ERR_OCSP_RESP_NOT_TRUSTED);
  RETURN_IF_NOT(notCert != NULL, ERR_OCSP_CERT_NOTFOUND);
  RETURN_IF_NOT((bs = OCSP_response_get1_basic(pResp)) != NULL, ERR_OCSP_NO_BASIC_RESP);
  // now create an OCSP object and check its validity
  if((setup_verifyCERT(&store, CApath, caCerts)) == ERR_OK) {
    // new basic response
    // create OCSP basic response
    ver_certs = sk_X509_new_null();
    if(ver_certs) {
      sk_X509_push(ver_certs, notCert);
      err = OCSP_basic_verify(bs, ver_certs, store, OCSP_TRUSTOTHER);
      if(err == ERR_LIB_NONE) {
	err = ERR_OK;
      } else {
	//checkErrors();
	SET_LAST_ERROR(ERR_OCSP_WRONG_RESPID);
	err = ERR_OCSP_WRONG_RESPID;
      }
      // cleanup
      sk_X509_free(ver_certs);
    }
    X509_STORE_free(store);
  }
  if(bs)
    OCSP_BASICRESP_free(bs);
  return err;
}

int checkNonceAndCertbyOCSP(OCSP_RESPONSE* resp, X509* cert, byte* nonce1, int nonceLen)
{
  int err = ERR_OK, n, status = 0;
  char buf[100];
  OCSP_BASICRESP *br = NULL;
  OCSP_SINGLERESP *single = NULL;
  const OCSP_CERTID *cid = NULL;
  X509_EXTENSION *nonce;
  X509_NAME *iname;
  unsigned char *ikey;
  ASN1_INTEGER *serialNumber = NULL;
  ASN1_OCTET_STRING *issuerNameHash = NULL, *issuerKeyHash = NULL, *nonceValue = NULL;
	
  RETURN_IF_NULL_PARAM(resp);
  RETURN_IF_NULL_PARAM(cert);
  if((br = OCSP_response_get1_basic(resp)) == NULL) 
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_BASIC_RESP);
  n = OCSP_resp_count(br);
  RETURN_IF_NOT(n == 1, ERR_OCSP_ONE_RESPONSE);
  single = OCSP_resp_get0(br, 0);
  RETURN_IF_NOT(single, ERR_OCSP_ONE_RESPONSE);
  cid = OCSP_SINGLERESP_get0_id(single);
  RETURN_IF_NULL(cid);
  status = OCSP_single_get0_status(single, NULL, NULL, NULL, NULL);
  err = handleOCSPCertStatus(status);
  if(err)
    SET_LAST_ERROR_RETURN_CODE(err);
  if((OCSP_BASICRESP_get_ext_count(br) != 1) ||
	 ((nonce = OCSP_BASICRESP_get_ext(br, 0)) == NULL))
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_NONCE);
  i2t_ASN1_OBJECT(buf, sizeof(buf), X509_EXTENSION_get_object(nonce));
  if(strcmp(buf, OCSP_NONCE_NAME)) 
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_NONCE);
  // check serial number
  OCSP_id_get0_info(&issuerNameHash, NULL, &issuerKeyHash, &serialNumber, (OCSP_CERTID*)cid);
  if(ASN1_INTEGER_cmp(X509_get_serialNumber(cert), serialNumber) != 0)
    SET_LAST_ERROR_RETURN_CODE(ERR_WRONG_CERT);
  // check issuer name hash
  iname = X509_get_issuer_name(cert);
  n = sizeof(buf);
  X509_NAME_digest(iname, EVP_sha1(), (byte*)buf, (unsigned int*)&n);
  err = compareByteArrays((byte*)buf, (unsigned int)n, issuerNameHash->data, issuerNameHash->length);
  RETURN_IF_NOT(err == ERR_OK, err);
  // check issuer key hash
  if((ikey = get_authority_key(X509_get0_extensions(cert))) != NULL) {
    err = compareByteArrays(ikey, strlen((const char*)ikey), 
				issuerKeyHash->data, issuerKeyHash->length);
    // cleanup ikey
    free(ikey);
  } 
  // verify nonce value
  nonceValue = X509_EXTENSION_get_data(nonce);
  if(nonceValue->length == DIGEST_LEN)
	err = compareByteArrays(nonceValue->data, nonceValue->length, nonce1, nonceLen);
  else
	err = compareByteArrays(nonceValue->data + 2, nonceValue->length - 2, nonce1, nonceLen);
  ddocDebug(3, "checkNonceAndCertbyOCSP", "nonce1-len: %d nonce2-len: %d err: %d", nonceValue->length, nonceLen, err);
  if (err != ERR_OK) SET_LAST_ERROR(err);
  if(br)
    OCSP_BASICRESP_free(br);
  return err;
}

