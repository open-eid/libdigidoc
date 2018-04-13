//==================================================
// FILE:	DigiDocObj.c
// PROJECT:     Digi Doc
// DESCRIPTION: DigiDoc helper routines for accessing dogidoc data
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

#include "DigiDocObj.h"
#include "DigiDocGen.h"
#include "DigiDocError.h"
#include "DigiDocConvert.h"
#include "DigiDocDebug.h"
#include "DigiDocCert.h"
#include "DigiDocOCSP.h"
#include "DigiDocConfig.h"
#include "DigiDocError.h"
#include <string.h>
#include <ctype.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#if OPENSSL_VERSION_NUMBER < 0x10010000L
static EVP_MD_CTX *EVP_MD_CTX_new()
{
	return (EVP_MD_CTX*)OPENSSL_malloc(sizeof(EVP_MD_CTX));
}

static void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
	OPENSSL_free(ctx);
}

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
#endif

//============================================================
// Sets a string element of a struct to a new value
// dest - element pointer
// value - new value
// valLen - value length (use -1 for null terminated strings)
//============================================================
EXP_OPTION int setString(char** dest, const char* value, int valLen) 
{
  RETURN_IF_NULL_PARAM(dest);
  RETURN_IF_NULL_PARAM(value);

  if(*dest) {
    free(*dest);
    *dest = NULL;
  }
  if(valLen == -1) {
    *dest = (char*)malloc(strlen(value)+1);
    RETURN_IF_BAD_ALLOC(*dest);
    strncpy(*dest, value, strlen(value)+1);
  } else {
    *dest = (char*)malloc(valLen);
    RETURN_IF_BAD_ALLOC(*dest);
    memcpy(*dest, value, valLen);
  }	
  return ERR_OK;
}

//============================================================
// Allocates a new SignedDoc element and initializes it
// format - format name
// version - format version
//============================================================
EXP_OPTION int SignedDoc_new(SignedDoc **pSignedDoc, const char* format, const char* version)
{
  SignedDoc* pSigDoc = NULL;
	
  RETURN_IF_NULL_PARAM(format);
  RETURN_IF_NULL_PARAM(version);
  ddocDebug(3, "SignedDoc_new", "format: %s version: %s", (format ? format : "NULL"), (version ? version : "NULL"));
  pSigDoc = (SignedDoc*)malloc(sizeof(SignedDoc));
  RETURN_IF_BAD_ALLOC(pSigDoc);
  memset(pSigDoc, 0, sizeof(SignedDoc));
  if(!strcmp(format, DIGIDOC_XML_1_1_NAME) && 
     !strcmp(version, DIGIDOC_XML_1_3_VER)) {
    setString(&(pSigDoc->szFormat), format, -1);
    setString(&(pSigDoc->szFormatVer), version, -1);
	setString(&(pSigDoc->szFileName), "", -1);
  } else {
	ddocDebug(3, "SignedDoc_new", "unsupported version");
    SET_LAST_ERROR_RETURN_CODE(ERR_UNSUPPORTED_FORMAT);
  }
  *pSignedDoc = pSigDoc;
  return ERR_OK;
}

//============================================================
// Frees the memory of SignedDoc element
// pSigDoc - element to free
//============================================================
EXP_OPTION void SignedDoc_free(SignedDoc* pSigDoc) 
{
  int i;

  RETURN_VOID_IF_NULL(pSigDoc);
  for(i = 0; (pSigDoc->pDataFiles != NULL) && 
	(i < pSigDoc->nDataFiles); i++) 
    DataFile_free(pSigDoc->pDataFiles[i]);
  if(pSigDoc->pDataFiles)
    free(pSigDoc->pDataFiles);
  for(i = 0; (pSigDoc->pSignatures != NULL) && 
	(i < pSigDoc->nSignatures); i++)
    SignatureInfo_free(pSigDoc->pSignatures[i]);
  if(pSigDoc->pSignatures)
    free(pSigDoc->pSignatures);
  if(pSigDoc->szFormat)
    free(pSigDoc->szFormat);
  if(pSigDoc->szFormatVer)
    free(pSigDoc->szFormatVer);
	if(pSigDoc->szFileName)
		free(pSigDoc->szFileName);
	if(pSigDoc->szProfile)
		free(pSigDoc->szProfile);
  if(pSigDoc)
    free(pSigDoc);
}


//============================================================
// Returns the number of data files
// pSigDoc - signed doc pointer
//============================================================
EXP_OPTION int getCountOfDataFiles(const SignedDoc* pSigDoc)
{
  RETURN_OBJ_IF_NULL(pSigDoc, 0);
  return pSigDoc->nDataFiles;
}

//============================================================
// Returns the next free data file id
// pSigDoc - signed doc pointer
//============================================================
EXP_OPTION int getNextDataFileId(const SignedDoc* pSigDoc)
{
  int id = 0, n, i;

  RETURN_OBJ_IF_NULL(pSigDoc, 0);
  for(i = 0; i < pSigDoc->nDataFiles; i++) {
    DataFile* pDataFile = pSigDoc->pDataFiles[i];
    RETURN_OBJ_IF_NULL(pDataFile, 0);
    RETURN_OBJ_IF_NULL(pDataFile->szId, 0);
    SET_LAST_ERROR_RETURN_IF_NOT(strlen(pDataFile->szId) > 1, ERR_EMPTY_STRING, 0);
    n = atoi(pDataFile->szId+1);
    if(id <= n)
      id = n+1;
  }
  return id;
}

//============================================================
// Returns the desired DataFile object
// pSigDoc - signed doc pointer
// nIdx - DataFile index (starting with 0)
//============================================================
EXP_OPTION DataFile* getDataFile(const SignedDoc* pSigDoc, int nIdx)
{
  RETURN_OBJ_IF_NULL(pSigDoc, NULL);
  SET_LAST_ERROR_RETURN_IF_NOT(nIdx < pSigDoc->nDataFiles, ERR_BAD_DATAFILE_INDEX, NULL);
  RETURN_OBJ_IF_NULL(pSigDoc->pDataFiles[nIdx], 0);
  return pSigDoc->pDataFiles[nIdx];
}

//============================================================
// Returns the last DataFile object
// pSigDoc - signed doc pointer
//============================================================
EXP_OPTION DataFile* ddocGetLastDataFile(const SignedDoc* pSigDoc)
{
  int nIdx;
  RETURN_OBJ_IF_NULL(pSigDoc, NULL);
  nIdx = pSigDoc->nDataFiles - 1;
  SET_LAST_ERROR_RETURN_IF_NOT(nIdx >= 0, ERR_BAD_DATAFILE_INDEX, NULL);
  RETURN_OBJ_IF_NULL(pSigDoc->pDataFiles[nIdx], 0);
  return pSigDoc->pDataFiles[nIdx];
}

//============================================================
// Returns the DataFile object with the given id
// pSigDoc - signed doc pointer
// id - DataFile id
//============================================================
EXP_OPTION DataFile* getDataFileWithId(const SignedDoc* pSigDoc, const char* id)
{
  DataFile* pDataFile = NULL;
  int i;
  //AA 12.11.2003
  RETURN_OBJ_IF_NULL(id, NULL);
  RETURN_OBJ_IF_NULL(pSigDoc, NULL);
  ddocDebug(4, "getDataFileWithId", "id: \'%s\', files: %d", id, pSigDoc->nDataFiles);
  for(i = 0; i < pSigDoc->nDataFiles; i++) {
    RETURN_OBJ_IF_NULL(pSigDoc->pDataFiles[i], NULL);
    RETURN_OBJ_IF_NULL(pSigDoc->pDataFiles[i]->szId, NULL);
    if(!strcmp(pSigDoc->pDataFiles[i]->szId, id)) {
      pDataFile = pSigDoc->pDataFiles[i];
      break;
    }
  }
  return pDataFile;
}


//============================================================
// Adds a new DataFile element to  a SignedDoc element and initializes it
// pSigDoc - signed document
// id - data file id
// filename - filename
// contentType - EMBEDDED or EMBEDDED_BASE64
// mime - mime type
// size - file size
// digType - digestType
// digest - file digest (SHA1)
// digLen - digest length
//============================================================
EXP_OPTION int DataFile_new(DataFile **newDataFile, 
			    SignedDoc* pSigDoc, const char* id,
			    const char* filename, const char* contentType, 
			    const char* mime, long size,
			    const byte* digest, int digLen,
			    const char* digType, const char* szCharset)
{
  char buf1[300];
  int nId = 0, i, j, n;
  DataFile **pDataFiles;
  DataFile *pDataFile;
  FILE* hFile;

  RETURN_IF_NULL_PARAM(newDataFile);
  RETURN_IF_NULL_PARAM(pSigDoc);
  ddocDebug(3, "DataFile_new", "SigDoc ver: %s, file: %s, contentType: %s, mimeType: %s", 
	    (pSigDoc ? pSigDoc->szFormatVer : "NULL"), (filename ? filename : "NULL"), contentType, mime);
  //clearErrors();
  if(!id)
    nId = getNextDataFileId(pSigDoc);
  if(pSigDoc->nDataFiles == 0) {
    SET_LAST_ERROR_RETURN_IF_NOT(!pSigDoc->pDataFiles, ERR_BAD_DATAFILE_COUNT, 0);
    pSigDoc->nDataFiles = 1;
  }
  else
    pSigDoc->nDataFiles++;	
  pDataFiles = (DataFile**)malloc((pSigDoc->nDataFiles) * sizeof(void *));
  
  RETURN_IF_BAD_ALLOC(pDataFiles);
  for(i = 0; i < pSigDoc->nDataFiles-1; i++)
    pDataFiles[i] = pSigDoc->pDataFiles[i];
  pDataFile = (DataFile*)malloc(sizeof(DataFile));
  RETURN_IF_BAD_ALLOC(pDataFile);
  memset(pDataFile, 0, sizeof(DataFile));
  pDataFiles[pSigDoc->nDataFiles-1] = pDataFile;
  if(pSigDoc->pDataFiles)
    free(pSigDoc->pDataFiles);
  pSigDoc->pDataFiles = pDataFiles;
  if(id) {
      j = 0; n = strlen(id);
      if(n < 2 || id[0] != 'D') j = -1;
      if(j == 0 && n >= 2 && !isdigit(id[1]) && id[1] != 'O') j = -1;
      for(i = 2; j == 0 && i < n; i++)
          if(!isdigit(id[i])) j = -1;
      if(j == -1) {
          ddocDebug(1, "DataFile_new", "Invalid DataFile id: %s", id);
          SET_LAST_ERROR(ERR_BAD_PARAM);
      }
    setString(&(pDataFile->szId), id, -1);
  } else {
    snprintf(buf1, sizeof(buf1), "D%d", nId);
    setString(&(pDataFile->szId), buf1, -1);
  }
  if(szCharset)
    setString(&(pDataFile->szCharset), szCharset, -1);
  else
    setString(&(pDataFile->szCharset), CHARSET_ISO_8859_1, -1);
  if(filename) {
    // in versions 1.0, 1.1 and 1.2 we used wrong encoding for OEM windows charset
    setString(&(pDataFile->szFileName), filename, -1);
    if(!strcmp(contentType, CONTENT_EMBEDDED)) {
      if((hFile = fopen(pDataFile->szFileName, "rt")) != NULL) {
	fgets(buf1, sizeof(buf1), hFile);
	if(strstr(buf1, "<?xml")) 
	  SET_LAST_ERROR(ERR_BAD_DATAFILE_XML);
	fclose(hFile);
      }
    }
  }
  if(mime)
    setString(&(pDataFile->szMimeType), mime, -1);
  if((!contentType || strcmp(contentType, CONTENT_EMBEDDED_BASE64)) 
     && !ConfigItem_lookup_bool("EMBEDDED_XML_SUPPORT", 0)) {
    SET_LAST_ERROR(ERR_BAD_DATAFILE_CONTENT_TYPE);
    return ERR_BAD_DATAFILE_CONTENT_TYPE;
  }
  if(contentType)
    setString(&(pDataFile->szContentType), contentType, -1);
  pDataFile->nSize = size;
  if(digType && strlen(digType))
    setString(&(pDataFile->szDigestType), digType, -1);
  if(digest && digLen)
    ddocMemAssignData(&(pDataFile->mbufDigest), (const char*)digest, digLen);
  *newDataFile = pDataFile;
  return ERR_OK;
}


//============================================================
// Removes this DataFile from signed doc and frees it's memory
// pSigDoc - signed doc object
// id - DataFile id to be removed
//============================================================
EXP_OPTION int DataFile_delete(SignedDoc* pSigDoc, const char* id)
{
  int err = ERR_OK, n, i, j;
  DataFile* pDataFile = NULL;
  DataFile** pDataFiles = NULL;

  RETURN_IF_NULL_PARAM(pSigDoc);
  ddocDebug(3, "DataFile_delete", "id: %s", id);
  if(pSigDoc->nSignatures > 0)
    SET_LAST_ERROR_RETURN_CODE(ERR_MODIFY_SIGNED_DOC);	
  if((pDataFile = getDataFileWithId(pSigDoc, id)) != 0) {
    n = pSigDoc->nDataFiles - 1;
    if(n > 0) {
      pDataFiles = (DataFile**)malloc(n * sizeof(void*));
      RETURN_IF_BAD_ALLOC(pDataFiles);
      for(i = j = 0; i < pSigDoc->nDataFiles; i++) {
	if(strcmp(pSigDoc->pDataFiles[i]->szId, id)) 
	  pDataFiles[j++] = pSigDoc->pDataFiles[i];
	else{
	DataFile_free(pSigDoc->pDataFiles[i]);}
      }
      free(pSigDoc->pDataFiles);
      pSigDoc->pDataFiles = pDataFiles;
      pSigDoc->nDataFiles = n;
    } else {
      for(i = 0; i < pSigDoc->nDataFiles; i++){
	DataFile_free(pSigDoc->pDataFiles[i]);}
      free(pSigDoc->pDataFiles);
      pSigDoc->pDataFiles = NULL;
      pSigDoc->nDataFiles = 0;
    }
  }
  else
    err = ERR_BAD_DATAFILE_INDEX;
  if (err != ERR_OK) SET_LAST_ERROR(err);
  return err;
}

//============================================================
// Retrieve and convert cached DataFile data if possible
// pSigDoc - signed document object
// szDocId - datafile id
// ppBuf - address of buffer pointer
// pLen - address of lenght of bytes
//============================================================
EXP_OPTION int ddocGetDataFileCachedData(SignedDoc* pSigDoc, const char* szDocId, void** ppBuf, long* pLen)
{
  DataFile* pDf;
  DigiDocMemBuf mbuf1;
  int err1 = 0;
    
  mbuf1.pMem = 0; mbuf1.nLen = 0;
    
  //RETURN_IF_NULL_PARAM(pSigDoc); // if null then don't check for cached data (old logic)
  RETURN_IF_NULL_PARAM(szDocId);
  RETURN_IF_NULL_PARAM(ppBuf);
  RETURN_IF_NULL_PARAM(pLen);
  *ppBuf = 0;
  *pLen = 0;
  if(pSigDoc) {
    pDf = getDataFileWithId(pSigDoc, szDocId);
    if(pDf && pDf->mbufContent.pMem) { // gotcha!
      int len;
      // base64 content, allocate exact length and initialize
      if(!strcmp(pDf->szContentType, CONTENT_EMBEDDED_BASE64)) {
          err1 = ddocMemSetLength(&mbuf1, pDf->mbufContent.nLen);
          if(err1) {
              ddocMemBuf_free(&mbuf1);
              return err1;
          }
	      *ppBuf = mbuf1.pMem;
          *pLen = mbuf1.nLen;
          err1 = ddocDecodeBase64(&(pDf->mbufContent), &mbuf1);
          if(err1) {
              ddocMemBuf_free(&mbuf1);
              return err1;
          }
          mbuf1.pMem = 0; mbuf1.nLen = 0; // release ownership 
      } 
      // simple text content. Make it zero terminated string
      else if(!strcmp(pDf->szContentType, CONTENT_EMBEDDED)) {
          *ppBuf = malloc(pDf->mbufContent.nLen+1);
          RETURN_IF_BAD_ALLOC(*ppBuf);
          *pLen = pDf->mbufContent.nLen;
          memcpy(*ppBuf, pDf->mbufContent.pMem, pDf->mbufContent.nLen);
          ((char*)(*ppBuf))[*pLen] = 0;
      }
    }
  }
  return ERR_OK;
}

//============================================================
// Retrieve and convert DataFile Filename atribute and convert
// to proper UTF-8 if necessary.
// pSigDoc - signed document object
// szDocId - datafile id
// ppBuf - address of buffer pointer. Caller must free the buffer
// pLen - address of lenght of bytes. Will be changed.
//============================================================
EXP_OPTION int ddocGetDataFileFilename(SignedDoc* pSigDoc, const char* szDocId, void** ppBuf, int* pLen)
{
  DataFile* pDf;

  RETURN_IF_NULL_PARAM(pSigDoc);
  RETURN_IF_NULL_PARAM(szDocId);
  RETURN_IF_NULL_PARAM(ppBuf);
  RETURN_IF_NULL_PARAM(pLen);
  *ppBuf = 0;
  *pLen = 0;
  if(pSigDoc) {
    pDf = getDataFileWithId(pSigDoc, szDocId);
    if(pDf && pDf->szFileName) { // gotcha!
      *ppBuf = unescapeXmlsym((const char*)pDf->szFileName);
      *pLen = strlen((const char*)*ppBuf);
      // in version 1.2 and earlier we had bad UTF-8 for some chars
      // check and fix it for newer clients
      if((!strcmp(pSigDoc->szFormatVer, SK_XML_1_VER) && !strcmp(pSigDoc->szFormat, SK_XML_1_NAME)) ||
	     !strcmp(pSigDoc->szFormatVer, DIGIDOC_XML_1_1_VER) ||
	     !strcmp(pSigDoc->szFormatVer, DIGIDOC_XML_1_2_VER)) {
        convWinToFName(pDf->szFileName, (char*)*ppBuf, *pLen+1);
      }
    }
  }
  return ERR_OK;
}

//--------------------------------------------------
// Checks if the size of this DataFile is less than
// max size for memory cache and if so caches the data.
// pDf - DataFile object
// maxLen - max cacheable DataFile size
// value - character values read from file
// len - length of chars ???
// isBase64 - is allready in base64 form or not (1/0)
//--------------------------------------------------
EXP_OPTION void ddocAppendDataFileData(DataFile* pDf, int maxLen, void* data, int len, int isBase64)
{
  DigiDocMemBuf mbuf1, mbuf2;
	
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  ddocDebug(5, "ddocAppendDataFileData", "append: %d, max: %d", len, maxLen);
  if(pDf && pDf->nSize < maxLen) {
    ddocDebug(6, "ddocAppendDataFileData", "DF: %s, size: %d, max: %d", pDf->szId, pDf->nSize, maxLen);
    // original content must be kept in the form it will exist in file
	if(!strcmp(pDf->szContentType, CONTENT_EMBEDDED_BASE64) && !isBase64) {
      mbuf2.pMem = data;
      mbuf2.nLen = len;
	  ddocEncodeBase64(&mbuf2, &mbuf1);
	  ddocMemAppendData(&(pDf->mbufContent), mbuf1.pMem, mbuf1.nLen);
	  ddocMemBuf_free(&mbuf1); 
	}
    else
        ddocMemAppendData(&(pDf->mbufContent), data, len);
  }
}

//--------------------------------------------------
// Creates new DataFile and assigns contet from memory
// ppDataFile address of pointer to return new DataFile object
// pSigDoc - SignedDoc object
// id - new DataFile id. Use NULL for default
// filename - filename
// contentType - content type
// mime - mime type
// pData - address of DataFile content to be assigned
// size - length of data in bytes
// return error code
//--------------------------------------------------
EXP_OPTION int createDataFileInMemory(DataFile **ppDataFile, SignedDoc* pSigDoc, const char* id,
					   const char* filename, const char* contentType, 
					   const char* mime, const char* pData, long size)
{
  int err = ERR_OK;
  DigiDocMemBuf mbuf1;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  err = DataFile_new(ppDataFile, pSigDoc, id,
					   filename, contentType, 
					   mime, size, NULL, 0, DIGEST_SHA1_NAME, NULL);
  if(!err && pData) {
      ddocAppendDataFileData(*ppDataFile, size+1, (void*)pData, size, 0);
	  // calculate hash so it can be used in signing
	  err = generateDataFileXML(pSigDoc, *ppDataFile, NULL, NULL, &mbuf1);
	  ddocMemBuf_free(&mbuf1);
  }
  return err;
}

//============================================================
// cleanup DataFile memory
// pDataFile - data file object to be cleaned up
//============================================================
EXP_OPTION void DataFile_free(DataFile* pDataFile)
{
  int i=0;

  RETURN_VOID_IF_NULL(pDataFile);
  if(pDataFile->szId)
    free(pDataFile->szId);
  if(pDataFile->szFileName)
    free(pDataFile->szFileName);
  if(pDataFile->szMimeType)
    free(pDataFile->szMimeType);
  if(pDataFile->szDigestType)
    free(pDataFile->szDigestType);
  ddocMemBuf_free(&(pDataFile->mbufDigest));
  ddocMemBuf_free(&(pDataFile->mbufWrongDigest));
  ddocMemBuf_free(&(pDataFile->mbufDetachedDigest));
  if(pDataFile->szContentType)
    free(pDataFile->szContentType);
  for(i = 0; i < pDataFile->nAttributes; i++) {
    free(pDataFile->pAttNames[i]);
    free(pDataFile->pAttValues[i]);
  }
  if(pDataFile->szCharset)
    free(pDataFile->szCharset);
  if(pDataFile->pAttNames)
    free(pDataFile->pAttNames);
  if(pDataFile->pAttValues)
    free(pDataFile->pAttValues);
  ddocMemBuf_free(&(pDataFile->mbufContent));
  free(pDataFile);
}

//--------------------------------------------------
// Accessor for Digest atribute of DataFile object.
// pDataFile - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION DigiDocMemBuf* ddocDataFile_GetDigestValue(DataFile* pDataFile)
{
  RETURN_OBJ_IF_NULL(pDataFile, NULL)
  return &(pDataFile->mbufDigest);
}

//--------------------------------------------------
// Mutatoror for Digest atribute of DataFile object.
// pDataFile - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// len - length of value in bytes [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocDataFile_SetDigestValue(DataFile* pDataFile, 
					   const char* value, long len)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pDataFile)
  RETURN_IF_NULL_PARAM(value)
  err = ddocMemAssignData(&(pDataFile->mbufDigest), value, len);
  return err;
}


//--------------------------------------------------
// Accessor for DetachedDigest atribute of DataFile object.
// pDataFile - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION DigiDocMemBuf* ddocDataFile_GetDetachedDigestValue(DataFile* pDataFile)
{
  RETURN_OBJ_IF_NULL(pDataFile, NULL)
  return &(pDataFile->mbufDetachedDigest);
}

//--------------------------------------------------
// Mutatoror for DetachedDigest atribute of DataFile object.
// pDataFile - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// len - length of value in bytes [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocDataFile_SetDetachedDigestValue(DataFile* pDataFile, 
					   const char* value, long len)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pDataFile)
  RETURN_IF_NULL_PARAM(value)
  err = ddocMemAssignData(&(pDataFile->mbufDetachedDigest), value, len);
  return err;
}

//--------------------------------------------------
// Accessor for WrongDigest atribute of DataFile object.
// pDataFile - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION DigiDocMemBuf* ddocDataFile_GetWrongDigestValue(DataFile* pDataFile)
{
  RETURN_OBJ_IF_NULL(pDataFile, NULL)
  return &(pDataFile->mbufWrongDigest);
}

//--------------------------------------------------
// Mutatoror for WrongDigest atribute of DataFile object.
// pDataFile - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// len - length of value in bytes [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocDataFile_SetWrongDigestValue(DataFile* pDataFile, 
					   const char* value, long len)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pDataFile)
  RETURN_IF_NULL_PARAM(value)
  err = ddocMemAssignData(&(pDataFile->mbufWrongDigest), value, len);
  return err;
}

//============================================================
// Removes this NotaryInfo from signed doc and frees it's memory
// pSigInfo - signature object
// id - notary id to be removed
//============================================================
EXP_OPTION int NotaryInfo_delete(SignatureInfo* pSigInfo)
{
  RETURN_IF_NULL_PARAM(pSigInfo);
  if(pSigInfo->pNotary) {
    NotaryInfo_free(pSigInfo->pNotary);
    pSigInfo->pNotary = 0;
  }
  return ERR_OK;
}

//============================================================
// Returns number of DataFile attributes
// pDataFile - data file
//============================================================
EXP_OPTION int getCountOfDataFileAttributes(const DataFile* pDataFile)
{
  RETURN_OBJ_IF_NULL(pDataFile, -1);
  return pDataFile->nAttributes;
}

//============================================================
// Adds an attribute to data file
// pDataFile - data file
// name - attribute name
// value - attribute value
//============================================================
// FIXME : Badly in need for a rewrite - memory leaks, when something fails.
int addDataFileAttribute(DataFile* pDataFile, const char* name, const char* value)
{
  char	**pp;
  int i;

  RETURN_IF_NULL_PARAM(pDataFile);
  RETURN_IF_NULL_PARAM(name);
  RETURN_IF_NULL_PARAM(value);
  if(pDataFile->nAttributes == 0) {
    RETURN_IF_NOT(!pDataFile->pAttNames, ERR_BAD_ATTR_COUNT);
    RETURN_IF_NOT(!pDataFile->pAttValues, ERR_BAD_ATTR_COUNT);
    pDataFile->nAttributes = 1;
  }
  else
    pDataFile->nAttributes++;
  // set name
  pp = (char**)malloc((pDataFile->nAttributes) * sizeof(char *));
  RETURN_IF_BAD_ALLOC(pp);
  for(i = 0; i < pDataFile->nAttributes-1; i++)
    pp[i] = pDataFile->pAttNames[i];
  if(pDataFile->pAttNames)
    free(pDataFile->pAttNames);
  pDataFile->pAttNames = pp;
  pp[pDataFile->nAttributes-1] = NULL;
  setString(&(pp[pDataFile->nAttributes-1]), name, -1);
  // set value
  pp = (char**)malloc((pDataFile->nAttributes) * sizeof(char *));
  RETURN_IF_BAD_ALLOC(pp);
  for(i = 0; i < pDataFile->nAttributes-1; i++)
    pp[i] = pDataFile->pAttValues[i];
  if(pDataFile->pAttValues)
    free(pDataFile->pAttValues);
  pDataFile->pAttValues = pp;
  pp[pDataFile->nAttributes-1] = NULL;
  setString(&(pp[pDataFile->nAttributes-1]), value, -1);
  return ERR_OK;
}


//============================================================
// Gets an attribute of a data file
// pDataFile - data file
// name - buffer for attribute name pointer
// value - buffer for attribute value pointer
//============================================================
EXP_OPTION int getDataFileAttribute(DataFile* pDataFile, int idx, char** name, char** value)
{

  RETURN_IF_NULL_PARAM(pDataFile);
  RETURN_IF_NOT(idx < pDataFile->nAttributes, ERR_BAD_ATTR_INDEX);
  RETURN_IF_NULL_PARAM(name);
  RETURN_IF_NULL_PARAM(value);
  *name = pDataFile->pAttNames[idx];
  *value = pDataFile->pAttValues[idx];
  return ERR_OK;
}

//============================================================
// Calculates the file size and digest
// pSigDoc - signed document
// id - data file id
// filename - filename
// digType - digestType (code)
//============================================================
EXP_OPTION int calculateDataFileSizeAndDigest(SignedDoc* pSigDoc, const char* id,
							const char* filename, int digType)
{
  int err = ERR_OK, len1 = 0;
  char buf1[DIGEST_LEN+2];
  long len2 = 0;
  DataFile* pDataFile;

  RETURN_IF_NULL_PARAM(pSigDoc);
  ddocDebug(3, "calculateDataFileSizeAndDigest", "File: %s id: %s", filename, id);
  pDataFile = getDataFileWithId(pSigDoc, id);
  RETURN_IF_NOT(pDataFile, ERR_FILE_READ);
  if(digType == DIGEST_SHA1) {
    // in version 1.0 we use DigestType and DigestValue
    // attrributes of DataFile element and calculate the digest
    // over the original content
    if(!strcmp(pSigDoc->szFormat, SK_XML_1_NAME) && !strcmp(pSigDoc->szFormatVer, SK_XML_1_VER)) {
      len1 = sizeof(buf1);
      err = calculateFileDigest(filename, digType,
				(byte*)buf1, &len1, &len2);
      RETURN_IF_NOT(err == ERR_OK, err);
      ddocDataFile_SetDigestValue(pDataFile, buf1, len1);
      pDataFile->nSize = len2;
    }
    // in version 1.1 we don't use those attributes
    // and we calculate the digest over the whole
    // DataFile element including the tags
    else {
      err = calculateFileSize(filename, &pDataFile->nSize);
      ddocDebug(4, "calculateDataFileSizeAndDigest", "File: %s size: %d", filename, pDataFile->nSize);
      err = generateDataFileXML(pSigDoc, pDataFile, filename, NULL, NULL); 
    }
  } 
  else
    SET_LAST_ERROR_RETURN_CODE(ERR_UNSUPPORTED_DIGEST);
  return err;
}


//=======================< DigestValue >=====================================

//--------------------------------------------------
// "Constructor" of DigestValue object
// ppDigestValue - address of buffer for newly allocated object [REQUIRED]
// szDigestMethod - digest method [OPTIONAL]
// szDigVal/lDigLen - digest value and length [OPTIONAL]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocDigestValue_new(DigestValue** ppDigestValue, 
				   const char* szDigestMethod, 
				   void* szDigVal, long lDigLen)
{
  int err = ERR_OK;

  // check input parameters
  ddocDebug(4, "ddocDigestValue_new", "DigestMethod: %s, dig-len: %ld", 
	    (szDigestMethod ? szDigestMethod : "NULL"), lDigLen);
  RETURN_IF_NULL_PARAM(ppDigestValue);
  *ppDigestValue = 0; // mark as not yet allocated
  // allocate memory for new DigestValue
  *ppDigestValue = (DigestValue*)malloc(sizeof(DigestValue));
  if(!(*ppDigestValue))
    SET_LAST_ERROR_RETURN(ERR_BAD_ALLOC, ERR_BAD_ALLOC)
  memset(*ppDigestValue, 0, sizeof(DigestValue));
  // set optional fields
  if(szDigestMethod) {
    err = ddocMemAssignString((char**)&((*ppDigestValue)->szDigestMethod), szDigestMethod);
    if(err) return err;
  } else { // default is sha1
    err = ddocMemAssignString((char**)&((*ppDigestValue)->szDigestMethod), DIGEST_METHOD_SHA1);
  }
  if(szDigVal && lDigLen) 
    err = ddocMemAssignData(&((*ppDigestValue)->mbufDigestValue), szDigVal, lDigLen);
  return err;
}

//--------------------------------------------------
// "Destructor" of DigestValue object
// pDigestValue - address of object to be deleted [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocDigestValue_free(DigestValue* pDigestValue)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pDigestValue)
  // cleanup this object
  if(pDigestValue->szDigestMethod)
    free(pDigestValue->szDigestMethod);
  ddocMemBuf_free(&(pDigestValue->mbufDigestValue));
  free(pDigestValue);
  return err;
}

//--------------------------------------------------
// Accessor for DigestMethod atribute of DigestValue object.
// pDigestValue - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION const char* ddocDigestValue_GetDigestMethod(DigestValue* pDigestValue)
{
  RETURN_OBJ_IF_NULL(pDigestValue, NULL)
  return pDigestValue->szDigestMethod;
}

//--------------------------------------------------
// Mutatoror for DigestMethod atribute of DigestValue object.
// pDigestValue - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocDigestValue_SetDigestMethod(DigestValue* pDigestValue, const char* value)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pDigestValue)
  RETURN_IF_NULL_PARAM(value)
  err = ddocMemAssignString((char**)&(pDigestValue->szDigestMethod), value);
  return err;
}

//--------------------------------------------------
// Accessor for DigestValue atribute of DigestValue object.
// pDigestValue - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION DigiDocMemBuf* ddocDigestValue_GetDigestValue(DigestValue* pDigestValue)
{
  RETURN_OBJ_IF_NULL(pDigestValue, NULL)
  return &(pDigestValue->mbufDigestValue);
}

//--------------------------------------------------
// Mutatoror for DigestValue atribute of DigestValue object.
// pDigestValue - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// len - length of value in bytes [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocDigestValue_SetDigestValue(DigestValue* pDigestValue, 
					      const char* value, long len)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pDigestValue)
  RETURN_IF_NULL_PARAM(value)
  err = ddocMemAssignData(&(pDigestValue->mbufDigestValue), value, len);
  return err;
}

//--------------------------------------------------
// Compares two DigestValue structure on equality
// pDigest1 - address of first digest [REQUIRED]
// pDigest2 - address of second digest [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
int ddocCompareDigestValues(DigestValue* pDigest1, DigestValue* pDigest2)
{
  RETURN_IF_NULL_PARAM(pDigest1)
  RETURN_IF_NULL_PARAM(pDigest2)
  return compareByteArrays((const byte*)pDigest1->mbufDigestValue.pMem, 
			    pDigest1->mbufDigestValue.nLen,
			    (const byte*)pDigest2->mbufDigestValue.pMem, 
			    pDigest2->mbufDigestValue.nLen);
}

//--------------------------------------------------
// Generates XML for <DigestValue> element
// pSigDoc - signed doc object [REQUIRED]
// pDigestValue - DigestValue object [REQUIRED]
// pBuf - memory buffer for storing xml [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
int ddocDigestValue_toXML(const DigestValue* pDigestValue, DigiDocMemBuf* pBuf)
{
  int err = ERR_OK;
  DigiDocMemBuf mbuf1;

  RETURN_IF_NULL_PARAM(pBuf)
  RETURN_IF_NULL_PARAM(pDigestValue)
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  // DigestMethod
  if(pDigestValue->szDigestMethod) {
    err = ddocGen_startElemBegin(pBuf, "DigestMethod");
    if(err) return err;
    // Algorithm atribute
    err = ddocGen_addAtribute(pBuf, "Algorithm", pDigestValue->szDigestMethod);
    if(err) return err;
    //err = ddocGen_startElemEnd(pBuf);
    //err = ddocGen_endElem(pBuf, "DigestMethod");
    // end of element start tag
    err = ddocMemAppendData(pBuf, "/>\n", -1);
  }
  if(pDigestValue->mbufDigestValue.pMem) {
    err = ddocGen_startElem(pBuf, "DigestValue");
  }

    if(err) return err;
    // digest value
    ddocEncodeBase64(&(pDigestValue->mbufDigestValue), &mbuf1);
    //AM 17.11.08 to remove newline after base64
    if(mbuf1.pMem && ((char*)mbuf1.pMem)[strlen((const char*)mbuf1.pMem)-1] == '\n')
	((char*)mbuf1.pMem)[strlen((const char*)mbuf1.pMem)-1] = 0;
    err = ddocMemAppendData(pBuf, (char*)mbuf1.pMem, -1);
    ddocMemBuf_free(&mbuf1);
    if(err) return err;
    err = ddocGen_endElem(pBuf, "DigestValue");
    err = ddocMemAppendData(pBuf, "\n", -1);
  return err;
}

//======================< SignatureValue >====================================

//--------------------------------------------------
// "Constructor" of SignatureValue object
// ppSignatureValue - address of buffer for newly allocated object [REQUIRED]
// szId - Id atribute value [OPTIONAL]
// szType - signature type [OPTIONAL]
// szDigVal/lDigLen - digest value and length [OPTIONAL]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocSignatureValue_new(SignatureValue** ppSignatureValue, 
				      const char* szId, const char* szType,
				      void* szSigVal, long lSigLen)
{
  int err = ERR_OK;

  // check input parameters
  ddocDebug(4, "ddocSignatureValue_new", "id: %s, type: %s, dig-len: %ld", 
	    (szId ? szId : "NULL"), (szType ? szType : "NULL"), lSigLen);
  RETURN_IF_NULL_PARAM(ppSignatureValue);
  *ppSignatureValue = 0; // mark as not yet allocated
  // allocate memory for new DigestValue
  *ppSignatureValue = (SignatureValue*)malloc(sizeof(SignatureValue));
  if(!(*ppSignatureValue))
    SET_LAST_ERROR_RETURN(ERR_BAD_ALLOC, ERR_BAD_ALLOC)
  memset(*ppSignatureValue, 0, sizeof(SignatureValue));
  // set optional fields
  if(szId) {
    err = ddocMemAssignString((char**)&((*ppSignatureValue)->szId), szId);
    if(err) return err;
  }
  if(szType) {
    err = ddocMemAssignString((char**)&((*ppSignatureValue)->szType), szType);
    if(err) return err;
  }
  if(szSigVal && lSigLen) 
    err = ddocMemAssignData(&((*ppSignatureValue)->mbufSignatureValue), szSigVal, lSigLen);
  return err;
}

//--------------------------------------------------
// "Destructor" of SignatureValue object
// pSignatureValue - address of object to be deleted [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocSignatureValue_free(SignatureValue* pSignatureValue)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pSignatureValue)
  // cleanup this object
  if(pSignatureValue->szId)
    free(pSignatureValue->szId);
  if(pSignatureValue->szType)
    free(pSignatureValue->szType);
  ddocMemBuf_free(&(pSignatureValue->mbufSignatureValue));
  free(pSignatureValue);
  return err;
}

//--------------------------------------------------
// Accessor for Id atribute of SignatureValue object.
// pSignatureValue - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION const char* ddocSignatureValue_GetId(const SignatureValue* pSignatureValue)
{
  RETURN_OBJ_IF_NULL(pSignatureValue, NULL)
  return pSignatureValue->szId;
}

//--------------------------------------------------
// Mutatoror for Id atribute of SignatureValue object.
// pSignatureValue - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocSignatureValue_SetId(SignatureValue* pSignatureValue, const char* value)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pSignatureValue)
  RETURN_IF_NULL_PARAM(value)
  err = ddocMemAssignString((char**)&(pSignatureValue->szId), value);
  return err;
}

//--------------------------------------------------
// Accessor for Type atribute of SignatureValue object.
// pSignatureValue - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION const char* ddocSignatureValue_GetType(const SignatureValue* pSignatureValue)
{
  RETURN_OBJ_IF_NULL(pSignatureValue, NULL)
  return pSignatureValue->szType;
}

//--------------------------------------------------
// Mutatoror for Type atribute of SignatureValue object.
// pSignatureValue - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocSignatureValue_SetType(SignatureValue* pSignatureValue, const char* value)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pSignatureValue)
  RETURN_IF_NULL_PARAM(value)
  err = ddocMemAssignString((char**)&(pSignatureValue->szType), value);
  return err;
}

//--------------------------------------------------
// Accessor for SignatureValue atribute of SignatureValue object.
// pSignatureValue - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION DigiDocMemBuf* ddocSignatureValue_GetSignatureValue(const SignatureValue* pSignatureValue)
{
  RETURN_OBJ_IF_NULL(pSignatureValue, NULL)
    return &(((SignatureValue*)pSignatureValue)->mbufSignatureValue);
}

//--------------------------------------------------
// Mutatoror for SignatureValue atribute of SignatureValue object.
// pSignatureValue - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// len - length of value in bytes [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocSignatureValue_SetSignatureValue(SignatureValue* pSignatureValue, 
						    const char* value, long len)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pSignatureValue)
  RETURN_IF_NULL_PARAM(value)
  err = ddocMemAssignData(&(pSignatureValue->mbufSignatureValue), value, len);
  return err;
}

//--------------------------------------------------
// Generates XML for <SignatureValue> element
// pSignatureValue - SignatureValue object [REQUIRED]
// pBuf - memory buffer for storing xml [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
int ddocSignatureValue_toXML(const SignatureValue* pSignatureValue, DigiDocMemBuf* pBuf)
{
  int err = ERR_OK;
  char* p;
  DigiDocMemBuf mbuf1;

  RETURN_IF_NULL_PARAM(pBuf)
  //RETURN_IF_NULL_PARAM(pSignatureValue)
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  // start of element
  err = ddocGen_startElemBegin(pBuf, "SignatureValue");
  if(err) return err;
  // Id atribute
  if(pSignatureValue) {
    p = (char*)ddocSignatureValue_GetId(pSignatureValue);
    if(p)
      err = ddocGen_addAtribute(pBuf, "Id", p);
    if(err) return err;
  }
  // end of element start tag
  err = ddocGen_startElemEnd(pBuf);
  //err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  // signature value
  if(pSignatureValue) {
    ddocEncodeBase64(ddocSignatureValue_GetSignatureValue(pSignatureValue), &mbuf1);
		//AM 17.11.08 to remove newline after base64
		if(mbuf1.pMem && ((char*)mbuf1.pMem)[strlen((const char*)mbuf1.pMem)-1] == '\n')
			((char*)mbuf1.pMem)[strlen((const char*)mbuf1.pMem)-1] = 0;
    err = ddocMemAppendData(pBuf, (char*)mbuf1.pMem, -1);
    ddocMemBuf_free(&mbuf1);
  }
  err = ddocGen_endElem(pBuf, "SignatureValue");
  err = ddocMemAppendData(pBuf, "\n", -1);
  return err;
}

//======================< CertID >====================================

//--------------------------------------------------
// "Constructor" of CertID object
// ppCertID - address of buffer for newly allocated object [REQUIRED]
// szId - Id atribute value [OPTIONAL]
// nType - certid internal type (signers or responders cert) [REQUIRED]
// szIssuerSerial - issuer serial number [OPTIONAL]
// szIssuerName - issuer DN [OPTIONAL]
// szDigVal/lDigLen - digest value and length [OPTIONAL]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertID_new(CertID** ppCertID, 
			      int nType, const char* szId,
			      const char* szIssuerSerial, const char* szIssuerName,
			      void* szDigVal, long lDigLen)
{
  int err = ERR_OK;

  // check input parameters
  ddocDebug(4, "ddocCertID_new", "id: %s, type: %d, issuer-serial: %s issuer-name: %s, dig-len: %ld", 
	    (szId ? szId : "NULL"), nType,
	    (szIssuerSerial ? szIssuerSerial : "NULL"), 
	    (szIssuerName ? szIssuerName : "NULL"), lDigLen);
  RETURN_IF_NULL_PARAM(ppCertID);
  *ppCertID = 0; // mark as not yet allocated
  // allocate memory for new CertID
  *ppCertID = (CertID*)malloc(sizeof(CertID));
  if(!(*ppCertID))
    SET_LAST_ERROR_RETURN(ERR_BAD_ALLOC, ERR_BAD_ALLOC)
  memset(*ppCertID, 0, sizeof(CertID));
  (*ppCertID)->nType = nType;
  // set optional fields
  if(szId) {
    err = ddocMemAssignString((char**)&((*ppCertID)->szId), szId);
    if(err) return err;
  }
  if(szIssuerSerial) {
    err = ddocMemAssignString((char**)&((*ppCertID)->szIssuerSerial), szIssuerSerial);
    if(err) return err;
  }
  if(szIssuerName) {
    err = ddocMemAssignString((char**)&((*ppCertID)->szIssuerName), szIssuerName);
    if(err) return err;
  }
  if(szDigVal && lDigLen) {
    if(!(*ppCertID)->pDigestValue)
      ddocDigestValue_new(&((*ppCertID)->pDigestValue), 0, szDigVal, lDigLen);
    else
      err = ddocDigestValue_SetDigestValue((*ppCertID)->pDigestValue, szDigVal, lDigLen);
  }
  return err;
}
EXP_OPTION int bdocCertID_new(CertID** ppCertID, 
			      int nType, const char* szId,
			      const char* szIssuerSerial, const char* szIssuerName,
			      void* szDigVal, long lDigLen)
{
  int err = ERR_OK;

  // check input parameters
  ddocDebug(4, "ddocCertID_new", "id: %s, type: %d, issuer-serial: %s issuer-name: %s, dig-len: %ld", 
	    (szId ? szId : "NULL"), nType,
	    (szIssuerSerial ? szIssuerSerial : "NULL"), 
	    (szIssuerName ? szIssuerName : "NULL"), lDigLen);
  RETURN_IF_NULL_PARAM(ppCertID);
  *ppCertID = 0; // mark as not yet allocated
  // allocate memory for new CertID
  *ppCertID = (CertID*)malloc(sizeof(CertID));
  if(!(*ppCertID))
    SET_LAST_ERROR_RETURN(ERR_BAD_ALLOC, ERR_BAD_ALLOC)
  memset(*ppCertID, 0, sizeof(CertID));
  (*ppCertID)->nType = nType;
  // set optional fields
  if(szId) {
    err = ddocMemAssignString((char**)&((*ppCertID)->szId), szId);
    if(err) return err;
  }
  if(szIssuerSerial) {
    err = ddocMemAssignString((char**)&((*ppCertID)->szIssuerSerial), szIssuerSerial);
    if(err) return err;
  }
  if(szIssuerName) {
    err = ddocMemAssignString((char**)&((*ppCertID)->szIssuerName), szIssuerName);
    if(err) return err;
  }
  if(szDigVal && lDigLen) {
    if(!(*ppCertID)->pDigestValue){
      ddocDigestValue_new(&((*ppCertID)->pDigestValue), 0, szDigVal, lDigLen);
    }else
      err = ddocDigestValue_SetDigestValue((*ppCertID)->pDigestValue, szDigVal, lDigLen);
  }
  return err;
}

//--------------------------------------------------
// "Destructor" of CertID object
// pCertID - address of object to be deleted [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertID_free(CertID* pCertID)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pCertID)
  // cleanup this object
  if(pCertID->szId)
    free(pCertID->szId);
  if(pCertID->szIssuerSerial)
    free(pCertID->szIssuerSerial);
  if(pCertID->szIssuerName)
    free(pCertID->szIssuerName);
  if(pCertID->pDigestValue)
    ddocDigestValue_free(pCertID->pDigestValue);
	if(pCertID->szDigestType)
		free(pCertID->szDigestType);
  free(pCertID);
  return err;
}

//--------------------------------------------------
// Accessor for IssuerSerial atribute of CertID object.
// pCertID - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION const char* ddocCertID_GetIssuerSerial(const CertID* pCertID)
{
  RETURN_OBJ_IF_NULL(pCertID, NULL)
  return pCertID->szIssuerSerial;
}

//--------------------------------------------------
// Mutatoror for IssuerSerial atribute of CertID object.
// pCertID - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertID_SetIssuerSerial(CertID* pCertID, const char* value)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pCertID)
  RETURN_IF_NULL_PARAM(value)
  err = ddocMemAssignString((char**)&(pCertID->szIssuerSerial), value);
  return err;
}

//--------------------------------------------------
// Accessor for Id atribute of CertID object.
// pCertID - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION const char* ddocCertID_GetId(const CertID* pCertID)
{
  RETURN_OBJ_IF_NULL(pCertID, NULL)
  return pCertID->szId;
}

//--------------------------------------------------
// Mutatoror for Id atribute of CertID object.
// pCertID - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertID_SetId(CertID* pCertID, const char* value)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pCertID)
  RETURN_IF_NULL_PARAM(value)
  err = ddocMemAssignString((char**)&(pCertID->szId), value);
  return err;
}

//--------------------------------------------------
// Accessor for IssuerName atribute of CertID object.
// pCertID - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION const char* ddocCertID_GetIssuerName(const CertID* pCertID)
{
  RETURN_OBJ_IF_NULL(pCertID, NULL)
  return pCertID->szIssuerName;
}

//--------------------------------------------------
// Mutatoror for IssuerName atribute of CertID object.
// pCertID - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertID_SetIssuerName(CertID* pCertID, const char* value)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pCertID)
  RETURN_IF_NULL_PARAM(value)
  err = ddocMemAssignString((char**)&(pCertID->szIssuerName), value);
  return err;
}

//--------------------------------------------------
// Accessor for DigestValue atribute of CertID object.
// pCertID - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION DigiDocMemBuf* ddocCertID_GetDigestValue(const CertID* pCertID)
{
  RETURN_OBJ_IF_NULL(pCertID, NULL)
  return ddocDigestValue_GetDigestValue(pCertID->pDigestValue);
}

//--------------------------------------------------
// Mutatoror for DigestValue atribute of CertID object.
// pCertID - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// len - length of value in bytes [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertID_SetDigestValue(CertID* pCertID, 
					 const char* value, long len)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pCertID)
  RETURN_IF_NULL_PARAM(value)
  if(!pCertID->pDigestValue)
    err = ddocDigestValue_new(&(pCertID->pDigestValue), 0, (char*)value, len);
  else
    err = ddocDigestValue_SetDigestValue(pCertID->pDigestValue, value, len);
  return err;
}

//--------------------------------------------------
// Generates XML for <Cert> element
// pSigDoc - SignedDoc object [REQUIRED]
// pCertID - CertID object [REQUIRED]
// pBuf - memory buffer for storing xml [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
int ddocCertID_toXML(const SignedDoc* pSigDoc, const CertID* pCertID, DigiDocMemBuf* pBuf)
{
  int err = ERR_OK;

  RETURN_IF_NULL_PARAM(pBuf)
  RETURN_IF_NULL_PARAM(pCertID)
  RETURN_IF_NULL_PARAM(pSigDoc)
  // start of element
  err = ddocGen_startElemBegin(pBuf, "Cert");
  if(err) return err;
  // only formats 1.0, 1.1 and 1.2 we use the Id atribute
	//AM 28.10.08 can also have 1.0 version
  if((!strcmp(pSigDoc->szFormatVer, SK_XML_1_VER) && !strcmp(pSigDoc->szFormat, SK_XML_1_NAME)) ||
     !strcmp(pSigDoc->szFormatVer, DIGIDOC_XML_1_1_VER) ||
     !strcmp(pSigDoc->szFormatVer, DIGIDOC_XML_1_2_VER)) {
    // Id atribute
    if(pCertID->szId)
      err = ddocGen_addAtribute(pBuf, "Id", pCertID->szId);
    if(err) return err;
  }
  // end of element start tag
  err = ddocGen_startElemEnd(pBuf);
  // <CertDigest>
  err = ddocGen_startElem(pBuf, "CertDigest");
  if(err) return err;
  ddocDigestValue_toXML(pCertID->pDigestValue, pBuf);
  err = ddocGen_endElem(pBuf, "CertDigest");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  // <IssuerSerial
  err = ddocGen_startElem(pBuf, "IssuerSerial");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  // only formats 1.0, 1.1 and 1.2 we use the IssuerSerial element alone
	//AM 29.10.08 
  if((!strcmp(pSigDoc->szFormatVer, SK_XML_1_VER) && !strcmp(pSigDoc->szFormat, SK_XML_1_NAME))||
     !strcmp(pSigDoc->szFormatVer, DIGIDOC_XML_1_1_VER) ||
     !strcmp(pSigDoc->szFormatVer, DIGIDOC_XML_1_2_VER)) {
    err = ddocMemAppendData(pBuf, ddocCertID_GetIssuerSerial(pCertID), -1);
  } else { // in 1.3 and 1.4 we use all subelement of <IssuerSerial> 
    err = ddocGen_startElemBegin(pBuf, "X509IssuerName");
    if(err) return err;
    err = ddocGen_addAtribute(pBuf, "xmlns", NAMESPACE_XML_DSIG);
    // end of element start tag
    err = ddocGen_startElemEnd(pBuf);
    if(err) return err;
    err = ddocMemAppendData(pBuf, ddocCertID_GetIssuerName(pCertID), -1);
    if(err) return err;
    err = ddocGen_endElem(pBuf, "X509IssuerName");
    if(err) return err;
    err = ddocMemAppendData(pBuf, "\n", -1);
    err = ddocGen_startElemBegin(pBuf, "X509SerialNumber");
    if(err) return err;
    err = ddocGen_addAtribute(pBuf, "xmlns", NAMESPACE_XML_DSIG);
    // end of element start tag
    err = ddocGen_startElemEnd(pBuf);
    if(err) return err;
    err = ddocMemAppendData(pBuf, ddocCertID_GetIssuerSerial(pCertID), -1);
    if(err) return err;
    err = ddocGen_endElem(pBuf, "X509SerialNumber");
    if(err) return err;
    err = ddocMemAppendData(pBuf, "\n", -1);
  }
  err = ddocGen_endElem(pBuf, "IssuerSerial");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  err = ddocGen_endElem(pBuf, "Cert");
  return err;
}


//--------------------------------------------------
// Generates XML for <CompleteCertificateRefs> element
// pSigDoc - SignedDoc object [REQUIRED]
// pBuf - memory buffer for storing xml [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
int ddocCompleteCertificateRefs_toXML(const SignedDoc* pSigDoc, 
				      const SignatureInfo* pSigInfo, DigiDocMemBuf* pBuf)
{
  int err = ERR_OK, i, n;
  CertID* pCertID;

  RETURN_IF_NULL_PARAM(pBuf)
  RETURN_IF_NULL_PARAM(pSigDoc)
  RETURN_IF_NULL_PARAM(pSigInfo)
  RETURN_IF_NULL(pSigInfo->pCertIDs)
  // <CompleteCertificateRefs>
  err = ddocGen_startElemBegin(pBuf, "CompleteCertificateRefs");
  if(err) return err;
  // end of element start tag
  err = ddocGen_startElemEnd(pBuf);
  if(err) return err;
  // <CertRefs> (not used in 1.0, 1.1 and 1.2
  if((strcmp(pSigDoc->szFormatVer, SK_XML_1_VER) && strcmp(pSigDoc->szFormat, SK_XML_1_NAME)) &&
     strcmp(pSigDoc->szFormatVer, DIGIDOC_XML_1_1_VER) &&
     strcmp(pSigDoc->szFormatVer, DIGIDOC_XML_1_2_VER)) {
    err = ddocGen_startElem(pBuf, "CertRefs");
    if(err) return err;
  }
  n = ddocCertIDList_GetCertIDsCount(pSigInfo->pCertIDs);
  for(i = 0; i < n; i++) {
    pCertID = ddocCertIDList_GetCertID(pSigInfo->pCertIDs, i);
    if(pCertID && pCertID->nType != CERTID_TYPE_SIGNERS_CERTID)
      ddocCertID_toXML(pSigDoc, pCertID, pBuf);
  }
  // </CertRefs> (not used in 1.0, 1.1 and 1.2
	//AM 29.10.08
  if((strcmp(pSigDoc->szFormatVer, SK_XML_1_VER) && strcmp(pSigDoc->szFormat, SK_XML_1_NAME)) &&
     strcmp(pSigDoc->szFormatVer, DIGIDOC_XML_1_1_VER) &&
     strcmp(pSigDoc->szFormatVer, DIGIDOC_XML_1_2_VER)) {
    err = ddocGen_endElem(pBuf, "CertRefs");
  }
  if(err) return err;
  err = ddocGen_endElem(pBuf, "CompleteCertificateRefs");
  return err;
}

//--------------------------------------------------
// Generates XML for <CompleteRevocationRefs> element
// pSigDoc - SignedDoc object [REQUIRED]
// pBuf - memory buffer for storing xml [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
int ddocCompleteRevocationRefs_toXML(const SignedDoc* pSigDoc, 
				     const SignatureInfo* pSigInfo, DigiDocMemBuf* pBuf)
{
  int err = ERR_OK, l1, l2;
	//AM 28.04.04 increased buffer for sha256
  char buf1[80], buf2[80], *p1, *p2;
  const DigiDocMemBuf *pMBuf = 0;

  RETURN_IF_NULL_PARAM(pBuf)
  RETURN_IF_NULL_PARAM(pSigDoc)
  RETURN_IF_NULL_PARAM(pSigInfo)
  RETURN_IF_NULL(pSigInfo->pNotary)
  // <CompleteRevocationRefs>
  err = ddocGen_startElemBegin(pBuf, "CompleteRevocationRefs");
  if(err) return err;
  // end of element start tag
  err = ddocGen_startElemEnd(pBuf);
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  // <OCSPRefs>
  err = ddocGen_startElem(pBuf, "OCSPRefs");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  // <OCSPRef>
  err = ddocGen_startElem(pBuf, "OCSPRef");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  // <OCSPIdentifier>
  err = ddocGen_startElemBegin(pBuf, "OCSPIdentifier");
  if(err) return err;
  snprintf(buf1, sizeof(buf1), "#%s", pSigInfo->pNotary->szId); 
  err = ddocGen_addAtribute(pBuf, "URI", buf1);
  err = ddocGen_startElemEnd(pBuf);
  if(err) return err;
  // <ResponderID>
  err = ddocGen_startElem(pBuf, "ResponderID");
  if(err) return err;
    if(pSigInfo->pNotary->nRespIdType == RESPID_NAME_TYPE) {
      p1 = (char*)ddocNotInfo_GetResponderId_Value(pSigInfo->pNotary);
      RETURN_IF_NULL(p1);
      err = ddocMemAppendData(pBuf, p1, -1);
      if(err) return err;
    } else if(pSigInfo->pNotary->nRespIdType == RESPID_KEY_TYPE) {
      pMBuf = ddocNotInfo_GetResponderId(pSigInfo->pNotary);
      RETURN_IF_NULL(pMBuf);
      l2 = pMBuf->nLen * 2 + 10;
      p2 = (char*)malloc(l2);
      RETURN_IF_NULL(p2);
      memset(p2, 0, l2);
      encode((const byte*)pMBuf->pMem, pMBuf->nLen, (byte*)p2, &l2);
      err = ddocMemAppendData(pBuf, p2, -1);
      if(err) return err;
    } else {
      SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_WRONG_RESPID);
    }
  err = ddocGen_endElem(pBuf, "ResponderID");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  // <ProducedAt>
  err = ddocGen_startElem(pBuf, "ProducedAt");
  if(err) return err;
  err = ddocMemAppendData(pBuf, pSigInfo->pNotary->timeProduced, -1);
  if(err) return err;
  err = ddocGen_endElem(pBuf, "ProducedAt");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  // </OCSPRef>
  err = ddocGen_endElem(pBuf, "OCSPIdentifier");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  // <DigestAlgAndValue>
  err = ddocGen_startElem(pBuf, "DigestAlgAndValue");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  // <DigestMethod>
  err = ddocGen_startElemBegin(pBuf, "DigestMethod");
  if(err) return err;
  err = ddocGen_addAtribute(pBuf, "Algorithm", DIGEST_METHOD_SHA1);
  err = ddocGen_startElemEnd(pBuf);
  if(err) return err;
  err = ddocGen_endElem(pBuf, "DigestMethod");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  // <DigestValue>
  err = ddocGen_startElem(pBuf, "DigestValue");
  if(err) return err;
  l2 = sizeof(buf2);
  err = calculateNotaryInfoDigest(pSigDoc, pSigInfo->pNotary, (byte*)buf2, &l2);
  l1 = sizeof(buf1);
  encode((const byte*)buf2, l2, (byte*)buf1, &l1);
  err = ddocMemAppendData(pBuf, buf1, -1);
  err = ddocGen_endElem(pBuf, "DigestValue");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  // </DigestAlgAndValue>
  err = ddocGen_endElem(pBuf, "DigestAlgAndValue");
  if(err) return err;
  // </OCSPRef>
  err = ddocGen_endElem(pBuf, "OCSPRef");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  // </OCSPRefs>
  err = ddocGen_endElem(pBuf, "OCSPRefs");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  if(err) return err;
  // </CompleteRevocationRefs>
  err = ddocGen_endElem(pBuf, "CompleteRevocationRefs");
  if(err) return err;
  err = ddocMemAppendData(pBuf, "\n", -1);
  return err;
}


//==========< CertIDList >====================

//--------------------------------------------------
// "Constructor" of CertIDList object
// ppCertIDList - address of buffer for newly allocated object [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertIDList_new(CertIDList** ppCertIDList)
{
  int err = ERR_OK;

  // check input parameters
  ddocDebug(3, "ddocCertIDList_new", "Create new certid list");
  RETURN_IF_NULL_PARAM(ppCertIDList);
  *ppCertIDList = (CertIDList*)malloc(sizeof(CertIDList));
  // allocate new object
  RETURN_IF_BAD_ALLOC(*ppCertIDList);
  memset(*ppCertIDList, 0, sizeof(CertIDList));
  return err;
}

//--------------------------------------------------
// "Destructor" of CertIDList object
// pCertIDList - address of object to be deleted [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertIDList_free(CertIDList* pCertIDList)
{
  int i, err = ERR_OK;
  RETURN_IF_NULL_PARAM(pCertIDList)
  // free timestamp-infos
  for(i = 0; i < pCertIDList->nCertIDs; i++) {
    if(pCertIDList->pCertIDs[i]) {
      err = ddocCertID_free(pCertIDList->pCertIDs[i]);
      if(err) return err;
    }
  }
  free(pCertIDList->pCertIDs);
  free(pCertIDList);
  return err;
}

//--------------------------------------------------
// Accessor for count of CertIDs subelement of CertIDList object.
// pCertIDList - pointer to CertIDList object [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
int ddocCertIDList_addCertID(CertIDList* pCertIDList, CertID* pCertID)
{
  CertID** pCertIDs = 0;

  RETURN_IF_NULL_PARAM(pCertIDList)
  RETURN_IF_NULL_PARAM(pCertID)
  pCertIDs = (CertID**)realloc(pCertIDList->pCertIDs, sizeof(CertID*) * (pCertIDList->nCertIDs + 1));
  RETURN_IF_BAD_ALLOC(pCertIDs);
  pCertIDList->pCertIDs = pCertIDs;
  pCertIDList->pCertIDs[pCertIDList->nCertIDs] = pCertID;
  pCertIDList->nCertIDs++;
  ddocDebug(3, "ddocCertIDList_addCertID", "added certid: %s type: %d", pCertID->szId, pCertID->nType);
  return ERR_OK;
}


//--------------------------------------------------
// Accessor for count of CertIDs subelement of CertIDList object.
// pCertIDList - pointer to CertIDList object [REQUIRED]
// returns count or -1 for error. Then use error API to check errors
//--------------------------------------------------
EXP_OPTION int ddocCertIDList_GetCertIDsCount(CertIDList* pCertIDList)
{
  SET_LAST_ERROR_RETURN_IF_NOT(pCertIDList, ERR_NULL_POINTER, -1)
  return pCertIDList->nCertIDs;
}

//--------------------------------------------------
// Accessor for CertIDs subelement of CertIDList object.
// pCertIDList - pointer to CertIDList object [REQUIRED]
// nIdx - index of CertID object [REQUIRED]
// returns CertID pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertID* ddocCertIDList_GetCertID(CertIDList* pCertIDList, int nIdx)
{
  RETURN_OBJ_IF_NULL(pCertIDList, NULL)
  SET_LAST_ERROR_RETURN_IF_NOT(nIdx >= 0 && nIdx < pCertIDList->nCertIDs, ERR_BAD_CERTID_IDX, NULL);
  RETURN_OBJ_IF_NULL(pCertIDList->pCertIDs[nIdx], 0);
  return pCertIDList->pCertIDs[nIdx];
}


//--------------------------------------------------
// Accessor for last CertIDs subelement of CertIDList object.
// pCertIDList - pointer to CertIDList object [REQUIRED]
// returns CertID pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertID* ddocCertIDList_GetLastCertID(CertIDList* pCertIDList)
{
  RETURN_OBJ_IF_NULL(pCertIDList, NULL)
  SET_LAST_ERROR_RETURN_IF_NOT(pCertIDList->nCertIDs > 0, ERR_BAD_CERTID_IDX, NULL);
  RETURN_OBJ_IF_NULL(pCertIDList->pCertIDs[pCertIDList->nCertIDs-1], 0);
  return pCertIDList->pCertIDs[pCertIDList->nCertIDs-1];
}


//--------------------------------------------------
// Deletes CertID subelement of CertIDList object.
// pCertIDList - pointer to CertIDList object [REQUIRED]
// nIdx - index of CertID object to be removed [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertIDList_DeleteCertID(CertIDList* pCertIDList, int nIdx)
{
  int err = ERR_OK, i;

  RETURN_IF_NULL_PARAM(pCertIDList)
  SET_LAST_ERROR_RETURN_IF_NOT(nIdx >= 0 && nIdx < pCertIDList->nCertIDs, ERR_BAD_CERTID_IDX, ERR_BAD_CERTID_IDX);
  RETURN_IF_NULL_PARAM(pCertIDList->pCertIDs[nIdx]);
  // delete the given object
  err = ddocCertID_free(pCertIDList->pCertIDs[nIdx]);
  if(err) return err;
  pCertIDList->pCertIDs[nIdx] = 0;
  // move other objects 1 step close to array start
  for(i = nIdx; i < pCertIDList->nCertIDs; i++) 
    pCertIDList->pCertIDs[i] = pCertIDList->pCertIDs[i+1];
  pCertIDList->pCertIDs[pCertIDList->nCertIDs - 1] = 0;
  pCertIDList->nCertIDs--;
  return err;
}

//--------------------------------------------------
// Finds a CertID object with required type
// pCertIDList - pointer to CertIDList object [REQUIRED]
// nType - type of CertID object [REQUIRED]
// returns CertID pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertID* ddocCertIDList_GetCertIDOfType(CertIDList* pCertIDList, int nType)
{
  int i;

  RETURN_OBJ_IF_NULL(pCertIDList, NULL)
  ddocDebug(4, "ddocCertIDList_GetCertIDOfType", "find type: %d", nType);
  for(i = 0; i < pCertIDList->nCertIDs; i++) {
    ddocDebug(4, "ddocCertIDList_GetCertIDOfType", "idx: %d type: %d", i, pCertIDList->pCertIDs[i]->nType);
    if(pCertIDList->pCertIDs[i]->nType == nType)
      return pCertIDList->pCertIDs[i];
  }
  return NULL;
}

//--------------------------------------------------
// Finds a CertID object with serial nr
// pCertIDList - pointer to CertIDList object [REQUIRED]
// nType - type of CertID object [REQUIRED]
// returns CertID pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertID* ddocCertIDList_GetCertIDOfSerial(CertIDList* pCertIDList, const char* szSerial)
{
  int i;

  RETURN_OBJ_IF_NULL(pCertIDList, NULL)
  RETURN_OBJ_IF_NULL(szSerial, NULL)
    ddocDebug(4, "ddocCertIDList_GetCertIDOfSerial", "find serial: %s", szSerial);
  for(i = 0; i < pCertIDList->nCertIDs; i++) {
		//AM 19.09.08
		if(pCertIDList->pCertIDs[i]->szIssuerSerial){
			if(!strcmp(pCertIDList->pCertIDs[i]->szIssuerSerial, szSerial))
				return pCertIDList->pCertIDs[i];
		}
  }
  return NULL;
}

//--------------------------------------------------
// Finds a CertID object with required type or creates a new one
// pCertIDList - pointer to CertIDList object [REQUIRED]
// nType - type of CertID object [REQUIRED]
// returns CertID pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertID* ddocCertIDList_GetOrCreateCertIDOfType(CertIDList* pCertIDList, int nType)
{
  CertID* pCertID = ddocCertIDList_GetCertIDOfType(pCertIDList, nType);
  if(!pCertID) {
    ddocCertID_new(&pCertID, nType, 0, 0, 0, 0, 0);
    if(pCertID)
      ddocCertIDList_addCertID(pCertIDList, pCertID);
  }
  return pCertID;
}

//======================< CertValue >====================================

//--------------------------------------------------
// "Constructor" of CertValue object
// ppCertValue - address of buffer for newly allocated object [REQUIRED]
// szId - Id atribute value [OPTIONAL]
// nType - certid internal type (signers or responders cert) [REQUIRED]
// pCert - certificate itself [OPTIONAL]. Must fill in later. Do not X509_free() param!
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertValue_new(CertValue** ppCertValue, 
				 int nType, const char* szId,
				 X509* pCert)
{
  int err = ERR_OK;

  // check input parameters
  ddocDebug(4, "ddocCertValue_new", "id: %s, type: %d, cert: %s", 
	    (szId ? szId : "NULL"), nType, (pCert ? "OK" : "NULL"));
  RETURN_IF_NULL_PARAM(ppCertValue);
  //RETURN_IF_NULL_PARAM(pCert);
  *ppCertValue = 0; // mark as not yet allocated
  // allocate memory for new CertValue
  *ppCertValue = (CertValue*)malloc(sizeof(CertValue));
  if(!(*ppCertValue))
    SET_LAST_ERROR_RETURN(ERR_BAD_ALLOC, ERR_BAD_ALLOC)
  memset(*ppCertValue, 0, sizeof(CertValue));
  (*ppCertValue)->nType = nType;
  if(pCert)
    (*ppCertValue)->pCert = pCert;
  // set optional fields
  if(szId) {
    err = ddocMemAssignString((char**)&((*ppCertValue)->szId), szId);
    if(err) return err;
  }
  return err;
}

//--------------------------------------------------
// "Destructor" of CertValue object
// pCertValue - address of object to be deleted [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertValue_free(CertValue* pCertValue)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pCertValue)
  // cleanup this object
  if(pCertValue->szId)
    free(pCertValue->szId);
  if(pCertValue->pCert)
    X509_free(pCertValue->pCert);
  free(pCertValue);
  return err;
}

//--------------------------------------------------
// Accessor for Id atribute of CertValue object.
// pCertValue - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION const char* ddocCertValue_GetId(CertValue* pCertValue)
{
  RETURN_OBJ_IF_NULL(pCertValue, NULL)
  return pCertValue->szId;
}

//--------------------------------------------------
// Mutatoror for Id atribute of CertValue object.
// pCertValue - address of object [REQUIRED]
// value - new value for atribute [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertValue_SetId(CertValue* pCertValue, const char* value)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pCertValue)
  RETURN_IF_NULL_PARAM(value)
  err = ddocMemAssignString((char**)&(pCertValue->szId), value);
  return err;
}

//--------------------------------------------------
// Accessor for Cert atribute of CertValue object.
// pCertValue - address of object [REQUIRED]
// returns value of atribute or NULL.
//--------------------------------------------------
EXP_OPTION X509* ddocCertValue_GetCert(CertValue* pCertValue)
{
  RETURN_OBJ_IF_NULL(pCertValue, NULL)
  return pCertValue->pCert;
}

//--------------------------------------------------
// Mutatoror for Cert atribute of CertValue object.
// pCertValue - address of object [REQUIRED]
// pCert - new value for atribute [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertValue_SetCert(CertValue* pCertValue, X509* pCert)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pCertValue)
  RETURN_IF_NULL_PARAM(pCert)
  if(pCertValue->pCert && pCertValue->pCert != pCert) // free old cert
    X509_free(pCertValue->pCert);
  else
    ddocDebug(3, "ddocCertValue_SetCert", "Not freeing old cert");
  pCertValue->pCert = pCert;
  ddocDebug(3, "ddocCertValue_SetCert", "id: %s type: %d cert: %s", pCertValue->szId, pCertValue->nType, (pCert ? "OK" : "NULL"));
  return err;
}

//--------------------------------------------------
// Generates XML for <EncapsulatedX509Certificate> element
// pCertID - CertID object [REQUIRED]
// pBuf - memory buffer for storing xml [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
int ddocCertValue_toXML(const CertValue* pCertValue, DigiDocMemBuf* pBuf)
{
  int err = ERR_OK;
  char *p1 = 0;

  RETURN_IF_NULL_PARAM(pBuf)
  RETURN_IF_NULL_PARAM(pCertValue)
  // start of element
  err = ddocGen_startElemBegin(pBuf, "EncapsulatedX509Certificate");
  if(err) return err;
  if(pCertValue->szId)
    err = ddocGen_addAtribute(pBuf, "Id", pCertValue->szId);
  if(err) return err;
  err = ddocGen_startElemEnd(pBuf);
  if(err) return err;
  //err = ddocMemAppendData(pBuf, "\n", -1);
  if(pCertValue->pCert) {
    err = getCertPEM(pCertValue->pCert, 0, &p1);
    if(p1) {
      err = ddocMemAppendData(pBuf, p1, -1);
      free(p1);
    }
  }
  if(err) return err;
  err = ddocGen_endElem(pBuf, "EncapsulatedX509Certificate");
  return err;
}

//==========< CertValueList >====================

//--------------------------------------------------
// "Constructor" of CertValueList object
// ppCertValueList - address of buffer for newly allocated object [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertValueList_new(CertValueList** ppCertValueList)
{
  int err = ERR_OK;

  // check input parameters
  ddocDebug(3, "ddocCertValueList_new", "Create new cerValue list");
  RETURN_IF_NULL_PARAM(ppCertValueList);
  *ppCertValueList = (CertValueList*)malloc(sizeof(CertValueList));
  // allocate new object
  RETURN_IF_BAD_ALLOC(*ppCertValueList);
  memset(*ppCertValueList, 0, sizeof(CertValueList));
  return err;
}

//--------------------------------------------------
// "Destructor" of CertValueList object
// pCertValueList - address of object to be deleted [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertValueList_free(CertValueList* pCertValueList)
{
  int i, err = ERR_OK;
  RETURN_IF_NULL_PARAM(pCertValueList)
  // free timestamp-infos
  for(i = 0; i < pCertValueList->nCertValues; i++) {
    if(pCertValueList->pCertValues[i]) {
      err = ddocCertValue_free(pCertValueList->pCertValues[i]);
      if(err) return err;
    }
  }
  free(pCertValueList->pCertValues);
  free(pCertValueList);
  return err;
}

//--------------------------------------------------
// Adds a CertValue element to CertValueList object.
// pCertValueList - pointer to CertValueList object [REQUIRED]
// pCertValue - new object [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertValueList_addCertValue(CertValueList* pCertValueList, CertValue* pCertValue)
{
  CertValue** pCertValues = 0;

  RETURN_IF_NULL_PARAM(pCertValueList)
  RETURN_IF_NULL_PARAM(pCertValue)
  pCertValues = (CertValue**)realloc(pCertValueList->pCertValues, sizeof(CertValue*) * (pCertValueList->nCertValues + 1));
  RETURN_IF_BAD_ALLOC(pCertValues);
  pCertValueList->pCertValues = pCertValues;
  pCertValueList->pCertValues[pCertValueList->nCertValues] = pCertValue;
  pCertValueList->nCertValues++;
  ddocDebug(4, "ddocCertValueList_addCertValue", "added cert: %s type: %d", pCertValue->szId, pCertValue->nType);
  return ERR_OK;
}

//--------------------------------------------------
// Accessor for count of CertValues subelement of CertValueList object.
// pCertValueList - pointer to CertValueList object [REQUIRED]
// returns count or -1 for error. Then use error API to check errors
//--------------------------------------------------
EXP_OPTION int ddocCertValueList_GetCertValuesCount(CertValueList* pCertValueList)
{
  SET_LAST_ERROR_RETURN_IF_NOT(pCertValueList, ERR_NULL_POINTER, -1)
  return pCertValueList->nCertValues;
}

//--------------------------------------------------
// Accessor for CertValues subelement of CertValueList object.
// pCertValueList - pointer to CertValueList object [REQUIRED]
// nIdx - index of CertValue object [REQUIRED]
// returns CertValue pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertValue* ddocCertValueList_GetCertValue(CertValueList* pCertValueList, int nIdx)
{
  RETURN_OBJ_IF_NULL(pCertValueList, NULL)
  SET_LAST_ERROR_RETURN_IF_NOT(nIdx >= 0 && nIdx < pCertValueList->nCertValues, ERR_BAD_CERTVALUE_IDX, NULL);
  RETURN_OBJ_IF_NULL(pCertValueList->pCertValues[nIdx], 0);
  return pCertValueList->pCertValues[nIdx];
}

//--------------------------------------------------
// Deletes CertValue subelement of CertValueList object.
// pCertValueList - pointer to CertValueList object [REQUIRED]
// nIdx - index of CertValue object to be removed [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocCertValueList_DeleteCertValue(CertValueList* pCertValueList, int nIdx)
{
  int err = ERR_OK, i;

  RETURN_IF_NULL_PARAM(pCertValueList)
  SET_LAST_ERROR_RETURN_IF_NOT(nIdx >= 0 && nIdx < pCertValueList->nCertValues, ERR_BAD_CERTVALUE_IDX, ERR_BAD_CERTVALUE_IDX);
  RETURN_IF_NULL_PARAM(pCertValueList->pCertValues[nIdx]);
  // delete the given object
  err = ddocCertValue_free(pCertValueList->pCertValues[nIdx]);
  if(err) return err;
  pCertValueList->pCertValues[nIdx] = 0;
  // move other objects 1 step close to array start
  for(i = nIdx; i < pCertValueList->nCertValues; i++) 
    pCertValueList->pCertValues[i] = pCertValueList->pCertValues[i+1];
  pCertValueList->pCertValues[pCertValueList->nCertValues - 1] = 0;
  pCertValueList->nCertValues--;
  return err;
}

//--------------------------------------------------
// Finds a CertValue object with required type
// pCertValueList - pointer to CertValueList object [REQUIRED]
// nType - type of CertValue object [REQUIRED]
// returns CertValue pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertValue* ddocCertValueList_GetCertValueOfType(CertValueList* pCertValueList, int nType)
{
  int i;

  RETURN_OBJ_IF_NULL(pCertValueList, NULL)
  ddocDebug(4, "ddocCertValueList_GetCertValueOfType", "find type: %d", nType);
  for(i = 0; i < pCertValueList->nCertValues; i++) {
	ddocDebug(4, "ddocCertValueList_GetCertValueOfType", "idx: %d", i);
    ddocDebug(4, "ddocCertValueList_GetCertValueOfType", "idx: %d type: %d", i, pCertValueList->pCertValues[i]->nType);
    if(pCertValueList->pCertValues[i]->nType == nType){
	  ddocDebug(4, "ddocCertValueList_GetCertValueOfType", "found");
      return pCertValueList->pCertValues[i];}
  }
  return NULL;
}

//--------------------------------------------------
// Finds a CertValue object with required type or creates a new one
// pCertValueList - pointer to CertValueList object [REQUIRED]
// nType - type of CertValue object [REQUIRED]
// returns CertValue pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertValue* ddocCertValueList_GetOrCreateCertValueOfType(CertValueList* pCertValueList, int nType)
{
  
  CertValue* pCertValue = ddocCertValueList_GetCertValueOfType(pCertValueList, nType);
  if(!pCertValue) {
    ddocCertValue_new(&pCertValue, nType, 0, 0);
    if(pCertValue)
      ddocCertValueList_addCertValue(pCertValueList, pCertValue);
  }
  return pCertValue;
}


//======================< SignatureInfo >====================================

//============================================================
// Returns the number of signatures
// pSigDoc - signed doc pointer
//============================================================
EXP_OPTION int getCountOfSignatures(const SignedDoc* pSigDoc)
{
  RETURN_OBJ_IF_NULL(pSigDoc, -1);
  return pSigDoc->nSignatures;
}

//============================================================
// Returns the next free signature id
// pSigDoc - signed doc pointer
//============================================================
EXP_OPTION int getNextSignatureId(const SignedDoc* pSigDoc)
{
  int id = 0, n, i;

  RETURN_OBJ_IF_NULL(pSigDoc, -1);
  for(i = 0; i < pSigDoc->nSignatures; i++) {
    SignatureInfo* pSignature = pSigDoc->pSignatures[i];
    RETURN_OBJ_IF_NULL(pSignature, -1);
    RETURN_OBJ_IF_NULL(pSignature->szId, -1);
    SET_LAST_ERROR_RETURN_IF_NOT(strlen(pSignature->szId) > 1, ERR_EMPTY_STRING, -1);
    n = atoi(pSignature->szId+1);
    if(id <= n)
      id = n+1;
  }
  return id;
}

//============================================================
// Returns the signature object for the given Notary
// pSigDoc - signed doc pointer
//============================================================
EXP_OPTION SignatureInfo* ddocGetSignatureForNotary(const SignedDoc* pSigDoc, 
						    const NotaryInfo* pNotInfo)
{
  int i;

  RETURN_OBJ_IF_NULL(pSigDoc, NULL);
  for(i = 0; i < pSigDoc->nSignatures; i++) {
    SignatureInfo* pSignature = pSigDoc->pSignatures[i];
    RETURN_OBJ_IF_NULL(pSignature, NULL);
    if(pSignature->pNotary == pNotInfo)
      return pSignature;
  }
  return NULL;
}

//============================================================
// Returns the desired SignatureInfo object
// pSigDoc - signed doc pointer
// nIdx - SignatureInfo index (starting with 0)
//============================================================
EXP_OPTION SignatureInfo* getSignature(const SignedDoc* pSigDoc, int nIdx)
{
  RETURN_OBJ_IF_NULL(pSigDoc, NULL);
  SET_LAST_ERROR_RETURN_IF_NOT(nIdx < pSigDoc->nSignatures, ERR_BAD_SIG_INDEX, NULL);
  RETURN_OBJ_IF_NULL(pSigDoc->pSignatures[nIdx], NULL);
  return pSigDoc->pSignatures[nIdx];
}

//============================================================
// Returns the last SignatureInfo object
// pSigDoc - signed doc pointer
//============================================================
EXP_OPTION SignatureInfo* ddocGetLastSignature(const SignedDoc* pSigDoc)
{
  int nIdx;
  RETURN_OBJ_IF_NULL(pSigDoc, NULL);
  nIdx = pSigDoc->nSignatures - 1;
  SET_LAST_ERROR_RETURN_IF_NOT(nIdx < pSigDoc->nSignatures, ERR_BAD_SIG_INDEX, NULL);
  RETURN_OBJ_IF_NULL(pSigDoc->pSignatures && pSigDoc->pSignatures[nIdx], NULL);
  return pSigDoc->pSignatures[nIdx];
}

//============================================================
// Returns the SignatureInfo object with the given id
// pSigDoc - signed doc pointer
// id - SignatureInfo id
//============================================================
EXP_OPTION SignatureInfo* getSignatureWithId(const SignedDoc* pSigDoc, const char* id)
{
  SignatureInfo* pSignature = NULL;
  int i;

  RETURN_OBJ_IF_NULL(pSigDoc, NULL);
  RETURN_OBJ_IF_NULL(id, NULL);
  for(i = 0; i < pSigDoc->nSignatures; i++) {
    RETURN_OBJ_IF_NULL(pSigDoc->pSignatures[i], NULL);
    RETURN_OBJ_IF_NULL(pSigDoc->pSignatures[i]->szId, NULL);
    if(!strcmp(pSigDoc->pSignatures[i]->szId, id)) {
      pSignature = pSigDoc->pSignatures[i];
      break;
    }
  }
  return pSignature;
}


//============================================================
// Adds a new SignedInfo element to a SignedDoc element and initializes it
// id - signature id (use NULL for default)
// return the newly created structure 
//============================================================
// FIXME : memory leaks possible..
EXP_OPTION int SignatureInfo_new(SignatureInfo **newSignatureInfo, 
				 SignedDoc* pSigDoc, const char* id)
{
  int i, nId = 0;
  SignatureInfo** pSignatures = NULL;
  SignatureInfo* pSigInfo = NULL;
  char buf[100];

  RETURN_IF_NULL_PARAM(pSigDoc);
  //clearErrors();
  if(hasSignatureWithWrongDataFileHash(pSigDoc)) {
    ddocDebug(1, "SignatureInfo_new", "Cannot add signature in ddoc with invalid DataFile hashes!");
    return ERR_FILE_WRITE;
  }
  if(!id)
    nId = getNextSignatureId(pSigDoc);
  if(pSigDoc->nSignatures == 0) {
    RETURN_IF_NOT(!pSigDoc->pSignatures, ERR_BAD_SIG_COUNT);
    pSigDoc->nSignatures = 1;
  }
  else
    pSigDoc->nSignatures++;
  pSignatures = (SignatureInfo**)malloc((pSigDoc->nSignatures) * sizeof(void *));
  RETURN_IF_BAD_ALLOC(pSignatures);
  for(i = 0; i < pSigDoc->nSignatures-1; i++)
    pSignatures[i] = pSigDoc->pSignatures[i];
  pSigInfo = (SignatureInfo*)malloc(sizeof(SignatureInfo));
  RETURN_IF_BAD_ALLOC(pSigInfo);
  memset(pSigInfo, 0, sizeof(SignatureInfo));
  pSignatures[pSigDoc->nSignatures-1] = pSigInfo;
  if(pSigDoc->pSignatures)
    free(pSigDoc->pSignatures);
  pSigDoc->pSignatures = pSignatures;
  if(id) {
    setString(&(pSigInfo->szId), id, -1);
  } else {
    snprintf(buf, sizeof(buf), "S%d", nId);
    setString(&(pSigInfo->szId), buf, -1);
  }
  // create timestamp
  createTimestamp(pSigDoc, buf, sizeof(buf));
  setString(&(pSigInfo->szTimeStamp), buf, -1);
  *newSignatureInfo = pSigInfo;
  return ERR_OK;
}


//============================================================
// Sets the signature production place info
// pSigInfo - signature info object
// city - city name
// state - state or province name
// zip - postal code
// country - country name
//============================================================
EXP_OPTION int setSignatureProductionPlace(SignatureInfo* pSigInfo,
                                const char* city, const char* state,
                                const char* zip, const char* country)
{
  char* p = 0;
  RETURN_IF_NULL_PARAM(pSigInfo);
  if(city) {
    p = (char*)escape2xmlsym(city);
    if(p) {
      setString(&(pSigInfo->sigProdPlace.szCity), p, -1);
      free(p);
    }
  }
  if(state) {
    p = (char*)escape2xmlsym(state);
    if(p) {
      setString(&(pSigInfo->sigProdPlace.szStateOrProvince), p, -1);
      free(p);
    }
  }
  if(zip) {
    p = (char*)escape2xmlsym(zip);
    if(p) {
      setString(&(pSigInfo->sigProdPlace.szPostalCode), p, -1);
      free(p);
    }
  }
  if(country) {
    p = (char*)escape2xmlsym(country);
    if(p) {
      setString(&(pSigInfo->sigProdPlace.szCountryName), country, -1);
      free(p);
    }
  }
  return ERR_OK;
}



//============================================================
// Adds a signer role 
// pSigInfo - signature info object
// nCertified - certified role? (1/0)
// role - role data
// rLen - role data length
// encode - 1=encode it with Base64, 0=use as is
//============================================================
// FIXME : memory leaks possible...
EXP_OPTION int addSignerRole(SignatureInfo* pSigInfo, int nCertified, 
				   const char* role, int rLen, int enc)
{
  int n, i;
  char **p = NULL, *b = NULL, *p1;

  RETURN_IF_NULL_PARAM(pSigInfo);
  //if(!enc && role && (strchr(role, '<') || strchr(role, '>')))
  //  SET_LAST_ERROR_RETURN(ERR_INVALID_CONTENT, ERR_INVALID_CONTENT);
  
  if(nCertified) {
    n = pSigInfo->signerRole.nCertifiedRoles + 1;
    p = (char**)malloc(n * sizeof(void*));
    RETURN_IF_BAD_ALLOC(p);
    if(pSigInfo->signerRole.nCertifiedRoles) {
      RETURN_IF_NULL(pSigInfo->signerRole.pCertifiedRoles);
      for(i = 0; i < pSigInfo->signerRole.nCertifiedRoles; i++)
	p[i] = pSigInfo->signerRole.pCertifiedRoles[i];
      free(pSigInfo->signerRole.pCertifiedRoles);
    }
    p[n-1] = 0;
    if(enc) {
      b = (char*)malloc(rLen * 2);
      RETURN_IF_BAD_ALLOC(b);
      i = sizeof(b);
      encode((const byte*)role, rLen, (byte*)b, &i);
      b[i] = 0;
      setString(&(p[n-1]), b, i);
    }
    else
      setString(&(p[n-1]), role, rLen);
    pSigInfo->signerRole.pCertifiedRoles = p;
    pSigInfo->signerRole.nCertifiedRoles = n;
  } else {
    n = pSigInfo->signerRole.nClaimedRoles + 1;
    p = (char**)malloc(n * sizeof(void*));
    RETURN_IF_BAD_ALLOC(p);
    if(pSigInfo->signerRole.nClaimedRoles) {
      RETURN_IF_NULL(pSigInfo->signerRole.pClaimedRoles);
      for(i = 0; i < pSigInfo->signerRole.nClaimedRoles; i++)
	p[i] = pSigInfo->signerRole.pClaimedRoles[i];
      free(pSigInfo->signerRole.pClaimedRoles);
    }
    p[n-1] = 0;
    if(enc) {
      b = (char*)malloc(rLen * 2);
      RETURN_IF_BAD_ALLOC(b);
      i = sizeof(b);
      encode((const byte*)role, rLen, (byte*)b, &i);
      b[i] = 0;
      setString(&(p[n-1]), b, i);
    }
    else {
      p1 = (char*)escape2xmlsym(role);
      if(p1) {
	setString(&(p[n-1]), p1, -1);
	free(p1);
      }
    }
    pSigInfo->signerRole.pClaimedRoles = p;
    pSigInfo->signerRole.nClaimedRoles = n;
  }
  return ERR_OK;
}

//============================================================
// Returns the number of signer roles
// pSigInfo - signature info object
// nCertified - certified role? (1/0)
//============================================================
EXP_OPTION int getCountOfSignerRoles(SignatureInfo* pSigInfo, int nCertified)
{
  RETURN_OBJ_IF_NULL(pSigInfo, -1);
  if(nCertified)
    return pSigInfo->signerRole.nCertifiedRoles;
  else
    return pSigInfo->signerRole.nClaimedRoles;
}


//============================================================
// Returns the desired signer role
// pSigInfo - signature info object
// nCertified - certified role? (1/0)
//============================================================
EXP_OPTION const char* getSignerRole(SignatureInfo* pSigInfo, int nCertified, int nIdx)
{
  RETURN_OBJ_IF_NULL(pSigInfo, 0);
  if(nCertified) {
    SET_LAST_ERROR_RETURN_IF_NOT(nIdx < pSigInfo->signerRole.nCertifiedRoles, ERR_BAD_ROLE_INDEX, 0);
    RETURN_OBJ_IF_NULL(pSigInfo->signerRole.pCertifiedRoles[nIdx], 0);
    return pSigInfo->signerRole.pCertifiedRoles[nIdx];
  } else {
    SET_LAST_ERROR_RETURN_IF_NOT(nIdx < pSigInfo->signerRole.nClaimedRoles, ERR_BAD_ROLE_INDEX, 0);
    RETURN_OBJ_IF_NULL(pSigInfo->signerRole.pClaimedRoles[nIdx], 0);
    return pSigInfo->signerRole.pClaimedRoles[nIdx];
  }
}


//============================================================
// Removes this SignatureInfo from signed doc and frees it's memory
// pSigDoc - signed doc object
// id - signature id to be removed
//============================================================
EXP_OPTION int SignatureInfo_delete(SignedDoc* pSigDoc, const char* id)
{
  int n, i, j, err = ERR_OK;
  SignatureInfo* pSignature;
  SignatureInfo** pSignatures;
  
  RETURN_IF_NULL_PARAM(pSigDoc);
  ddocDebug(3, "SignatureInfo_delete", "id: %s", id);
  if(hasSignatureWithWrongDataFileHash(pSigDoc)) {
    ddocDebug(1, "SignatureInfo_delete", "Cannot delete signature in ddoc with invalid DataFile hashes!");
    return ERR_FILE_WRITE;
  }
  if((pSignature = getSignatureWithId(pSigDoc, id)) != NULL) {
    n = pSigDoc->nSignatures - 1;
    if(n > 0) {
      pSignatures = (SignatureInfo**)malloc(n * sizeof(void*));
      RETURN_IF_BAD_ALLOC(pSignatures);
      for(i = j = 0; i < pSigDoc->nSignatures; i++) {
          if(strcmp(pSigDoc->pSignatures[i]->szId, id)) { 
	        pSignatures[j++] = pSigDoc->pSignatures[i];					
	      } else {
		    SignatureInfo_free(pSigDoc->pSignatures[i]);
          }
      }
      free(pSigDoc->pSignatures);
      pSigDoc->pSignatures = pSignatures;
      pSigDoc->nSignatures = j;
    } else {
      for(i = 0; i < pSigDoc->nSignatures; i++){
	SignatureInfo_free(pSigDoc->pSignatures[i]);
      free(pSigDoc->pSignatures);
      pSigDoc->pSignatures = NULL;
      pSigDoc->nSignatures = 0;}
    }
  }
  else
    err = ERR_BAD_SIG_INDEX;
  if (err != ERR_OK) SET_LAST_ERROR(err);
  return err;
}


//============================================================
// cleanup SignatureInfo memory
// pSigInfo - object to be cleaned up
//============================================================
EXP_OPTION void SignatureInfo_free(SignatureInfo* pSigInfo)
{
  int i;

  RETURN_VOID_IF_NULL(pSigInfo);
  if(pSigInfo->szId)
    free(pSigInfo->szId);
  if(pSigInfo->szTimeStamp)
    free(pSigInfo->szTimeStamp);
  if(pSigInfo->pSigPropDigest)
    ddocDigestValue_free(pSigInfo->pSigPropDigest);
  if(pSigInfo->pSigPropRealDigest)
    ddocDigestValue_free(pSigInfo->pSigPropRealDigest);
  if(pSigInfo->pSigInfoRealDigest)
    ddocDigestValue_free(pSigInfo->pSigInfoRealDigest);
  if(pSigInfo->pSigValue)
    ddocSignatureValue_free(pSigInfo->pSigValue);
  for(i = 0; i < pSigInfo->nDocs; i++) {
    DocInfo_free(pSigInfo->pDocs[i]);		
  }
  if(pSigInfo->pDocs)
    free(pSigInfo->pDocs);
  // signature production place
  if(pSigInfo->sigProdPlace.szCity)
    free(pSigInfo->sigProdPlace.szCity);
  if(pSigInfo->sigProdPlace.szStateOrProvince)
    free(pSigInfo->sigProdPlace.szStateOrProvince);
  if(pSigInfo->sigProdPlace.szPostalCode)
    free(pSigInfo->sigProdPlace.szPostalCode);
  if(pSigInfo->sigProdPlace.szCountryName)
    free(pSigInfo->sigProdPlace.szCountryName);
  // signer role
  for(i = 0; i < pSigInfo->signerRole.nClaimedRoles; i++) {
    if(pSigInfo->signerRole.pClaimedRoles[i])
      free(pSigInfo->signerRole.pClaimedRoles[i]);    
  }
  if(pSigInfo->signerRole.pClaimedRoles)
    free(pSigInfo->signerRole.pClaimedRoles);
  for(i = 0; i < pSigInfo->signerRole.nCertifiedRoles; i++) {
    if (pSigInfo->signerRole.pCertifiedRoles[i])
      free(pSigInfo->signerRole.pCertifiedRoles[i]);    
  }
  if(pSigInfo->signerRole.pCertifiedRoles)
    free(pSigInfo->signerRole.pCertifiedRoles);
  ddocMemBuf_free(&(pSigInfo->mbufOrigContent));
  if(pSigInfo->pNotary)
    NotaryInfo_free(pSigInfo->pNotary);
  if(pSigInfo->pCertIDs)
    ddocCertIDList_free(pSigInfo->pCertIDs);
  if(pSigInfo->pCertValues)
    ddocCertValueList_free(pSigInfo->pCertValues);
	//AM 23.05.08
  if(pSigInfo->szDigestType)
    free(pSigInfo->szDigestType);
  free(pSigInfo);
}

//============================================================
// Sets signatures signed properties digest
// pSigInfo - signature info object
// value - new binary digest value
// len - length of the value
//============================================================
EXP_OPTION int ddocSigInfo_SetSigPropDigest(SignatureInfo* pSigInfo, const char* value, long len)
{
  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(value);
  if(!pSigInfo->pSigPropDigest)
    ddocDigestValue_new(&(pSigInfo->pSigPropDigest), 0, 0, 0);
  return ddocDigestValue_SetDigestValue(pSigInfo->pSigPropDigest, value, len);
}

//============================================================
// Sets signatures signed properties real digest as read from file
// pSigInfo - signature info object
// value - new binary digest value
// len - length of the value
//============================================================
EXP_OPTION int ddocSigInfo_SetSigPropRealDigest(SignatureInfo* pSigInfo, const char* value, long len)
{
  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(value);
  if(!pSigInfo->pSigPropRealDigest)
    ddocDigestValue_new(&(pSigInfo->pSigPropRealDigest), 0, 0, 0);
  return ddocDigestValue_SetDigestValue(pSigInfo->pSigPropRealDigest, value, len);
}

//============================================================
// Sets signatures signed info real digest as read from file
// pSigInfo - signature info object
// value - new binary digest value
// len - length of the value
//============================================================
EXP_OPTION int ddocSigInfo_SetSigInfoRealDigest(SignatureInfo* pSigInfo, const char* value, long len)
{
  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(value);
  if(!pSigInfo->pSigInfoRealDigest)
    ddocDigestValue_new(&(pSigInfo->pSigInfoRealDigest), 0, 0, 0);
  return ddocDigestValue_SetDigestValue(pSigInfo->pSigInfoRealDigest, value, len);
}

//============================================================
// Returns signatures signed properties digest
// pSigInfo - signature info object
// return digest value as DigiDocMemBuf pointer or NULL
//============================================================
EXP_OPTION DigiDocMemBuf* ddocSigInfo_GetSigPropDigest(SignatureInfo* pSigInfo)
{
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  return ddocDigestValue_GetDigestValue(pSigInfo->pSigPropDigest);
}

//============================================================
// Returns signatures signed properties digest as read from file
// pSigInfo - signature info object
// return digest value as DigiDocMemBuf pointer or NULL
//============================================================
EXP_OPTION DigiDocMemBuf* ddocSigInfo_GetSigPropRealDigest(SignatureInfo* pSigInfo)
{
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  return ddocDigestValue_GetDigestValue(pSigInfo->pSigPropRealDigest);
}

//============================================================
// Returns signatures signed info digest as read from file
// pSigInfo - signature info object
// return digest value as DigiDocMemBuf pointer or NULL
//============================================================
EXP_OPTION DigiDocMemBuf* ddocSigInfo_GetSigInfoRealDigest(SignatureInfo* pSigInfo)
{
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  return ddocDigestValue_GetDigestValue(pSigInfo->pSigInfoRealDigest);
}

//============================================================
// Returns signatures signature-value
// pSigInfo - signature info object
// return signature-value as SignatureValue pointer or NULL
//============================================================
EXP_OPTION SignatureValue* ddocSigInfo_GetSignatureValue(SignatureInfo* pSigInfo)
{
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  return pSigInfo->pSigValue;
}

//============================================================
// Returns signatures signature-value
// pSigInfo - signature info object
// return signature-value as DigiDocMemBuf pointer or NULL
//============================================================
EXP_OPTION DigiDocMemBuf* ddocSigInfo_GetSignatureValue_Value(SignatureInfo* pSigInfo)
{
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  return ddocSignatureValue_GetSignatureValue(pSigInfo->pSigValue);
}

//============================================================
// Sets signatures signature-value
// pSigInfo - signature info object
// value - new binary signature value
// len - length of the value
//============================================================
EXP_OPTION int ddocSigInfo_SetSignatureValue(SignatureInfo* pSigInfo, const char* value, long len)
{
  char buf1[30];

  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(value);
  snprintf(buf1, sizeof(buf1), "%s-SIG", pSigInfo->szId);
  if(!pSigInfo->pSigValue) 
    ddocSignatureValue_new(&(pSigInfo->pSigValue), 0, 0, 0, 0);
  ddocSignatureValue_SetId(pSigInfo->pSigValue, buf1);
  return ddocSignatureValue_SetSignatureValue(pSigInfo->pSigValue, value, len);
}

//============================================================
// Returns signaers certs - issuer-serial
// pSigInfo - signature info object
// return required atribute value
//============================================================
EXP_OPTION const char* ddocSigInfo_GetSignersCert_IssuerSerial(const SignatureInfo* pSigInfo)
{
  CertID* pCertID = 0;
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  pCertID = ddocCertIDList_GetCertIDOfType(pSigInfo->pCertIDs, CERTID_TYPE_SIGNERS_CERTID);
  RETURN_OBJ_IF_NULL(pCertID, NULL);
  return ddocCertID_GetIssuerSerial(pCertID);
}

//============================================================
// Sets signers certs issuer serial
// pSigInfo - signature info object
// value - new value
//============================================================
EXP_OPTION int ddocSigInfo_SetSignersCert_IssuerSerial(SignatureInfo* pSigInfo, const char* value)
{
  CertID* pCertID = 0;
  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(value);
  pCertID = ddocCertIDList_GetOrCreateCertIDOfType(pSigInfo->pCertIDs, CERTID_TYPE_SIGNERS_CERTID);
  return ddocCertID_SetIssuerSerial(pCertID, value);
}

//============================================================
// Returns signaers certs - issuer-name
// pSigInfo - signature info object
// return required atribute value
//============================================================
EXP_OPTION const char* ddocSigInfo_GetSignersCert_IssuerName(const SignatureInfo* pSigInfo)
{
  CertID* pCertID = 0;
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  pCertID = ddocCertIDList_GetCertIDOfType(pSigInfo->pCertIDs, CERTID_TYPE_SIGNERS_CERTID);
  RETURN_OBJ_IF_NULL(pCertID, NULL);
  return ddocCertID_GetIssuerName(pCertID);
}

//============================================================
// Returns signaers certs - issuer-name
// pSigInfo - signature info object
// pMbuf - memory buffer to return hash
// return required atribute value
//============================================================
EXP_OPTION const char* ddocSigInfo_GetSignersCert_IssuerNameAndHash(const SignatureInfo* pSigInfo, DigiDocMemBuf *pMbuf)
{
  CertID* pCertID = 0;
  X509* pCert = 0;
/*  DigiDocMemBuf mbuf1, mbuf2, mbuf3;
  
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  mbuf2.pMem = 0;
  mbuf2.nLen = 0;
  mbuf3.pMem = 0;
  mbuf3.nLen = 0;
*/
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  RETURN_OBJ_IF_NULL(pMbuf, NULL);
  pCertID = ddocCertIDList_GetCertIDOfType(pSigInfo->pCertIDs, CERTID_TYPE_SIGNERS_CERTID);
  RETURN_OBJ_IF_NULL(pCertID, NULL);
  pCert = ddocSigInfo_GetSignersCert(pSigInfo);
  RETURN_OBJ_IF_NULL(pCert, NULL);
  /*ddocCertGetSubjectCN(pCert, &mbuf1);
  readSubjectKeyIdentifier(pCert, &mbuf2);
  ddocEncodeBase64(&mbuf2, &mbuf3);
  ddocMemBuf_free(&mbuf2);
  readAuthorityKeyIdentifier(pCert, pMbuf);
  ddocEncodeBase64(pMbuf, &mbuf2);
  ddocDebug(3, "ddocSigInfo_GetSignersCert_IssuerNameAndHash", "CN: %s subj-hash: %s issuer-hash: %s", (char*)mbuf1.pMem, (char*)mbuf3.pMem, (char*)mbuf2.pMem);
  ddocMemBuf_free(&mbuf1);
  ddocMemBuf_free(&mbuf2);
  ddocMemBuf_free(&mbuf3);*/
  readAuthorityKeyIdentifier(pCert, pMbuf);
  return ddocCertID_GetIssuerName(pCertID);
}

//============================================================
// Sets signers certs issuer name
// pSigInfo - signature info object
// value - new value
//============================================================
EXP_OPTION int ddocSigInfo_SetSignersCert_IssuerName(SignatureInfo* pSigInfo, const char* value)
{
  CertID* pCertID = 0;
  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(value);
  pCertID = ddocCertIDList_GetOrCreateCertIDOfType(pSigInfo->pCertIDs, CERTID_TYPE_SIGNERS_CERTID);
  return ddocCertID_SetIssuerName(pCertID, value);
}

//============================================================
// Returns signers certs digest as DigiDocMemBuf object
// pSigInfo - signature info object
// return signers certs digest as DigiDocMemBuf pointer or NULL
//============================================================
EXP_OPTION DigiDocMemBuf* ddocSigInfo_GetSignersCert_DigestValue(const SignatureInfo* pSigInfo)
{
  CertID* pCertID = 0;
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  pCertID = ddocCertIDList_GetCertIDOfType(pSigInfo->pCertIDs, CERTID_TYPE_SIGNERS_CERTID);
  RETURN_OBJ_IF_NULL(pCertID, NULL);
  return ddocCertID_GetDigestValue(pCertID);
}

//============================================================
// Sets signers certs digest
// pSigInfo - signature info object
// value - new binary signature value
// len - length of the value
//============================================================
EXP_OPTION int ddocSigInfo_SetSignersCert_DigestValue(SignatureInfo* pSigInfo, const char* value, long len)
{
  CertID* pCertID = 0;
  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(value);
  pCertID = ddocCertIDList_GetOrCreateCertIDOfType(pSigInfo->pCertIDs, CERTID_TYPE_SIGNERS_CERTID);
  return ddocCertID_SetDigestValue(pCertID, value, len);
}

//--------------------------------------------------
// Finds a CertID object with required type
// pSigInfo - signature info object [REQUIRED]
// nType - type of CertID object [REQUIRED]
// returns CertID pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertID* ddocSigInfo_GetCertIDOfType(const SignatureInfo* pSigInfo, int nType)
{
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  if(pSigInfo->pCertIDs)
    return ddocCertIDList_GetCertIDOfType(pSigInfo->pCertIDs, nType);
  return NULL;
}

//--------------------------------------------------
// Finds last CertID object of this signature
// pSigInfo - signature info object [REQUIRED]
// returns CertID pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertID* ddocSigInfo_GetLastCertID(const SignatureInfo* pSigInfo)
{
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  if(pSigInfo->pCertIDs)
    return ddocCertIDList_GetLastCertID(pSigInfo->pCertIDs);
  return NULL;
}


//--------------------------------------------------
// Finds a CertID object with required type or creates a new one
// pSigInfo - signature info object [REQUIRED]
// nType - type of CertID object [REQUIRED]
// returns CertID pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertID* ddocSigInfo_GetOrCreateCertIDOfType(SignatureInfo* pSigInfo, int nType)
{
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  if(!pSigInfo->pCertIDs)
    ddocCertIDList_new(&(pSigInfo->pCertIDs));
  RETURN_OBJ_IF_NULL(pSigInfo->pCertIDs, NULL);
  return ddocCertIDList_GetOrCreateCertIDOfType(pSigInfo->pCertIDs, nType);
}

//--------------------------------------------------
// Finds a CertValue object with required type
// pSigInfo - signature info object [REQUIRED]
// nType - type of CertValue object [REQUIRED]
// returns CertValue pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertValue* ddocSigInfo_GetCertValueOfType(const SignatureInfo* pSigInfo, int nType)
{
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  ddocDebug(9, "ddocSigInfo_GetCertValueOfType", "start");
  if(pSigInfo->pCertValues)
    return ddocCertValueList_GetCertValueOfType(pSigInfo->pCertValues, nType);
  ddocDebug(9, "ddocSigInfo_GetCertValueOfType", "end");
  return NULL;
}

//--------------------------------------------------
// Finds a CertValue object with required type or creates a new one
// pSigInfo - signature info object [REQUIRED]
// nType - type of CertValue object [REQUIRED]
// returns CertValue pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertValue* ddocSigInfo_GetOrCreateCertValueOfType(SignatureInfo* pSigInfo, int nType)
{
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  if(!pSigInfo->pCertValues)
    ddocCertValueList_new(&(pSigInfo->pCertValues));
  RETURN_OBJ_IF_NULL(pSigInfo->pCertValues, NULL);
  return ddocCertValueList_GetOrCreateCertValueOfType(pSigInfo->pCertValues, nType);
}

//--------------------------------------------------
// Finds last CertValue
// pSigInfo - signature info object [REQUIRED]
// returns CertValue pointer or NULL for error
//--------------------------------------------------
EXP_OPTION CertValue* ddocSigInfo_GetLastCertValue(const SignatureInfo* pSigInfo)
{
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  if(pSigInfo->pCertValues)
    return ddocCertValueList_GetCertValue(pSigInfo->pCertValues, 
		  ddocCertValueList_GetCertValuesCount(pSigInfo->pCertValues) - 1);
  return NULL;
}

//--------------------------------------------------
// Finds the signers certificate
// pSigInfo - signature info object [REQUIRED]
// returns certificate or NULL
//--------------------------------------------------
EXP_OPTION X509* ddocSigInfo_GetSignersCert(const SignatureInfo* pSigInfo)
{
  X509 *pCert = 0;
  CertValue *pCertValue = 0;
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  if(pSigInfo->pCertValues) {
    pCertValue = ddocSigInfo_GetCertValueOfType(pSigInfo, CERTID_VALUE_SIGNERS_CERT);
    if(pCertValue)
      pCert = pCertValue->pCert;
  }
  return pCert;
}

//--------------------------------------------------
// Sets the signers certificate
// pSigInfo - signature info object [REQUIRED]
// pCert - certificate [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocSigInfo_SetSignersCert(SignatureInfo* pSigInfo, X509* pCert)
{
  int err = ERR_OK;
  CertValue *pCertValue = 0;
  char  buf1[50];

  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(pCert);
  pCertValue = ddocSigInfo_GetOrCreateCertValueOfType(pSigInfo, CERTID_VALUE_SIGNERS_CERT);
  if(pCertValue) {
    snprintf(buf1, sizeof(buf1), "%s-SIGNER_CERT", pSigInfo->szId);
    err = ddocCertValue_SetId(pCertValue, buf1);
    if(!err && pCert)
      err = ddocCertValue_SetCert(pCertValue, pCert);
  }
  return err;
}

//--------------------------------------------------
// Finds the OCSP responders certificate
// pSigInfo - signature info object [REQUIRED]
// returns certificate or NULL
//--------------------------------------------------
EXP_OPTION X509* ddocSigInfo_GetOCSPRespondersCert(const SignatureInfo* pSigInfo)
{
  X509 *pCert = 0;
  CertValue *pCertValue = 0;
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  if(pSigInfo->pCertValues) {
	ddocDebug(5, "ddocSigInfo_GetOCSPRespondersCert", "start");
    pCertValue = ddocSigInfo_GetCertValueOfType(pSigInfo, CERTID_VALUE_RESPONDERS_CERT);
	ddocDebug(5, "ddocSigInfo_GetOCSPRespondersCert", "end");
    if(pCertValue){
      pCert = pCertValue->pCert;
	ddocDebug(5, "ddocSigInfo_GetOCSPRespondersCert", "test");}
  }
  ddocDebug(5, "ddocSigInfo_GetOCSPRespondersCert", "end2");
  if(pCert) ddocDebug(5, "ddocSigInfo_GetOCSPRespondersCert", "pCert exists" );
  return pCert;
}

//--------------------------------------------------
// Sets the OCSP Responders certificate
// pSigInfo - signature info object [REQUIRED]
// pCert - certificate [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocSigInfo_SetOCSPRespondersCert(SignatureInfo* pSigInfo, X509* pCert)
{
  int err = ERR_OK;
  CertValue *pCertValue = 0;
  char  buf1[50];

  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(pCert);
  pCertValue = ddocSigInfo_GetOrCreateCertValueOfType(pSigInfo, CERTID_VALUE_RESPONDERS_CERT);
  if(pCertValue) {
    snprintf(buf1, sizeof(buf1), "%s-RESPONDER_CERT", pSigInfo->szId);
    err = ddocCertValue_SetId(pCertValue, buf1);
    if(!err)
      err = ddocCertValue_SetCert(pCertValue, pCert);
  }
  return err;
}

//============================================================
// Adds a certificate and it's certid to this signature
// pSigInfo - signature info object [REQUIRED]
// pCert - vertificate [REQUIRED]
// nCertIdType - type of cert [REQUIRED]
// return error code or ERR_OK
//============================================================
EXP_OPTION int ddocSigInfo_addCert(SignatureInfo* pSigInfo, X509* pCert, int nCertIdType)
{
  int err = ERR_OK, l1;
  char buf1[100], buf2[200], buf3[300], buf4[100];
  CertID *pCertID = 0;
  DigiDocMemBuf mbuf1;
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;

  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(pCert);

  RETURN_IF_NOT(err == ERR_OK, err);
  l1 = sizeof(buf1);
  RETURN_IF_NOT(X509_digest(pCert, EVP_sha1(), (unsigned char*)buf1, 
			    (unsigned int*)&l1), ERR_X509_DIGEST);
  if(err) return err;
  err = ReadCertSerialNumber(buf2, sizeof(buf2), pCert);
  memset(buf3, 0, sizeof(buf3));
  err = ddocCertGetIssuerDN(pCert, &mbuf1);
  RETURN_IF_NOT(err == ERR_OK, err);
  // now set all those atributes
  switch(nCertIdType) {
  case CERTID_TYPE_SIGNERS_CERTID:
    err = ddocSigInfo_SetSignersCert(pSigInfo, pCert);
    snprintf(buf4, sizeof(buf4), "%s-CERTINFO", pSigInfo->szId);
    ddocCertID_new(&pCertID, CERTID_TYPE_SIGNERS_CERTID, buf4, buf2, (char*)mbuf1.pMem, buf1, l1);
    break;
  case CERTID_TYPE_RESPONDERS_CERTID:
    err = ddocSigInfo_SetOCSPRespondersCert(pSigInfo, pCert);
    snprintf(buf4, sizeof(buf4), "%s-OCSP_CERTINFO", pSigInfo->szId);
    ddocCertID_new(&pCertID, CERTID_TYPE_RESPONDERS_CERTID, buf4, buf2, (char*)mbuf1.pMem, buf1, l1);
    break;
  }
  RETURN_IF_NOT(pCertID, ERR_BAD_ALLOC);
  if(!pSigInfo->pCertIDs) {
    err = ddocCertIDList_new(&(pSigInfo->pCertIDs));
    //ddocCertID_free(pCertID); // not owner any more!
    SET_LAST_ERROR_IF_NOT(err == ERR_OK, err);
  }
  if(pCertID) {
    ddocCertIDList_addCertID(pSigInfo->pCertIDs, pCertID);
    ddocDebug(3, "ddocSigInfo_addCert", "Added signers cert-id: %s type: %d", pCertID->szId, pCertID->nType);
  }
  ddocMemBuf_free(&mbuf1);
  return err;
}



//======================< DocInfo functions >=========================================


//============================================================
// Adds a new DocInfo element to a SignatureInfo element and initializes it
// pSigInfo - signature info object
// docId - document id (use NULL for default)
// digType - digest type
// digest - documents digest
// digLen - digest length
// mime - mime type
// mimeDig - mime digest
// mimeDigLen - mime digest length
// return the newly created structure 
//============================================================
EXP_OPTION int addDocInfo(DocInfo **newDocInfo, SignatureInfo* pSigInfo, const char* docId,
			   const char* digType, const byte* digest,
			   int digLen, const byte* mimeDig, int mimeDigLen)
{
  DocInfo** pDocInfos = NULL;
  DocInfo* pDocInfo = NULL;
  int i;

  RETURN_IF_NULL_PARAM(pSigInfo);
  if(pSigInfo->nDocs == 0) {
    RETURN_IF_NOT(!pSigInfo->pDocs, ERR_BAD_DOCINFO_COUNT);
    pSigInfo->nDocs = 1;
  }
  else
    pSigInfo->nDocs++;
  pDocInfos = (DocInfo**)malloc((pSigInfo->nDocs) * sizeof(void *));
  RETURN_IF_BAD_ALLOC(pDocInfos);
  for(i = 0; i < pSigInfo->nDocs-1; i++)
    pDocInfos[i] = pSigInfo->pDocs[i];
  pDocInfo = (DocInfo*)malloc(sizeof(DocInfo)); // MEMLEAK: ???
  if (!pDocInfo) {
    free(pDocInfos);
    SET_LAST_ERROR_RETURN_CODE(ERR_BAD_ALLOC);
  }
  memset(pDocInfo, 0, sizeof(DocInfo));
  pDocInfos[pSigInfo->nDocs-1] = pDocInfo;
  // PR. leak found
  if(pSigInfo->pDocs)
	  free(pSigInfo->pDocs);
  pSigInfo->pDocs = pDocInfos;
  if(docId) 
    setString(&(pDocInfo->szDocId), docId, -1);
  if(digType)
    setString(&(pDocInfo->szDigestType), digType, -1);
  if(digest) {
    setString((char**)&(pDocInfo->szDigest), (const char*)digest, digLen);
    pDocInfo->nDigestLen = digLen;
  }
  if(mimeDig && strlen((const char*)mimeDig)) {
    setString((char**)&(pDocInfo->szMimeDigest), (const char*)mimeDig, mimeDigLen);
    pDocInfo->nMimeDigestLen = mimeDigLen;
  }
  *newDocInfo = pDocInfo;
  return ERR_OK;
}

//============================================================
// cleanup DocInfo memory
// pDocInfo - object to be cleaned up
//============================================================
EXP_OPTION void DocInfo_free(DocInfo* pDocInfo)
{
  RETURN_VOID_IF_NULL(pDocInfo);
  //assert(pDocInfo);
  if(pDocInfo->szDocId)
    free(pDocInfo->szDocId);
  if(pDocInfo->szDigestType)
    free(pDocInfo->szDigestType);
  if(pDocInfo->szDigest)
    free(pDocInfo->szDigest);
  if(pDocInfo->szMimeDigest)
    free(pDocInfo->szMimeDigest);
  // free the object itself
  free(pDocInfo);
}

//============================================================
// Returns number of DocInfos 
// pSigInfo - signature info pointer
//============================================================
EXP_OPTION int getCountOfDocInfos(const SignatureInfo* pSigInfo)
{
  RETURN_OBJ_IF_NULL(pSigInfo, -1);
  return pSigInfo->nDocs;
}

//============================================================
// Returns the desired DocInfo
// pSigInfo - signature info pointer
// idx - DocInfo index
//============================================================
EXP_OPTION DocInfo* getDocInfo(const SignatureInfo* pSigInfo, int idx)
{
  ddocDebug(3, "getDocInfo", "Idx: %d, Docs: %d", idx, pSigInfo->nDocs);
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  SET_LAST_ERROR_RETURN_IF_NOT(idx < pSigInfo->nDocs, ERR_BAD_DOCINFO_INDEX, NULL);
  RETURN_OBJ_IF_NULL(pSigInfo->pDocs, NULL);
  RETURN_OBJ_IF_NULL(pSigInfo->pDocs[idx], NULL);
  return pSigInfo->pDocs[idx];
}

//============================================================
// Returns the last DocInfo
// pSigInfo - signature info pointer
// idx - DocInfo index
//============================================================
EXP_OPTION DocInfo* ddocGetLastDocInfo(const SignatureInfo* pSigInfo)
{
  int idx;

  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  idx = pSigInfo->nDocs - 1;
  SET_LAST_ERROR_RETURN_IF_NOT(idx < pSigInfo->nDocs, ERR_BAD_DOCINFO_INDEX, NULL);
  RETURN_OBJ_IF_NULL(pSigInfo->pDocs, NULL);
  RETURN_OBJ_IF_NULL(pSigInfo->pDocs[idx], NULL);
  return pSigInfo->pDocs[idx];
}

//============================================================
// Returns the DocInfo object with the given id
// pSigInfo - signature info pointer
// id - SignatureInfo id
//============================================================
EXP_OPTION DocInfo* getDocInfoWithId(const SignatureInfo* pSigInfo, const char* id)
{
  DocInfo* pDocInfo = NULL;
  int i;

  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  //RETURN_OBJ_IF_NULL(id, NULL);
  for(i = 0; i < pSigInfo->nDocs; i++) {
    RETURN_OBJ_IF_NULL(pSigInfo->pDocs[i], NULL);
    RETURN_OBJ_IF_NULL(pSigInfo->pDocs[i]->szDocId, NULL);
    if((id && !strcmp(pSigInfo->pDocs[i]->szDocId, id)) || !id) {
      pDocInfo = pSigInfo->pDocs[i];
      break;
    }
  }
  return pDocInfo;
}

//============================================================
// Sets the DocInfo objects document digest and digest type
// pDocInfo - document info pointer
// digest - digest value
// digLen - digest value length
// digType - digest type
//============================================================
EXP_OPTION void setDocInfoDigest(DocInfo* pDocInfo, const byte* digest, 
					  int digLen, const char* digType)
{
  RETURN_VOID_IF_NULL(pDocInfo);
  if(digType)
    setString(&(pDocInfo->szDigestType), digType, -1);
  if(digest) {
    setString((char**)&(pDocInfo->szDigest), (const char*)digest, digLen);
    pDocInfo->nDigestLen = digLen;
  }
}

//============================================================
// Sets the DocInfo objects mime digest and mime type
// pDocInfo - document info pointer
// mimeDig - mime digest value
// mimeDigLen - mime digest value length
//============================================================
EXP_OPTION void setDocInfoMimeDigest(DocInfo* pDocInfo, const byte* mimeDig, 
					  int mimeDigLen)
{
  RETURN_VOID_IF_NULL(pDocInfo);
  if(mimeDig) {
    setString((char**)&(pDocInfo->szMimeDigest), (const char*)mimeDig, mimeDigLen);
    pDocInfo->nMimeDigestLen = mimeDigLen;
  }
}

//============================================================
// Adds all DocInfo elements in this file to a SignatureInfo element
// pSigInfo - signature info object
// pSigDoc - signed document
//============================================================
EXP_OPTION int addAllDocInfos(SignedDoc* pSigDoc, SignatureInfo* pSigInfo)
{
  int i, c, l2;
  int len = 0;
  //Added by AA 28/10/2003 - not defined len value
  DataFile *pDf = NULL;
  DocInfo  *pDocInfo = NULL;
  byte buf[DIGEST_LEN+2], buf2[50];
  
  RETURN_IF_NULL_PARAM(pSigDoc);
  RETURN_IF_NULL_PARAM(pSigInfo);
  c = getCountOfDataFiles(pSigDoc);
  for(i = 0; i < c; i++ ) {
    pDf = getDataFile(pSigDoc, i);
    RETURN_IF_NULL(pDf);
    buf[0] = 0;
    // in version 1.0 we use mime digest
    if(!strcmp(pSigDoc->szFormatVer, SK_XML_1_VER) && !strcmp(pSigDoc->szFormat, SK_XML_1_NAME)) {
      len = sizeof(buf);
      calculateDigest((const byte*)pDf->szMimeType, strlen(pDf->szMimeType), 
		      DIGEST_SHA1, buf, &len);
    }
    // in 1.1 we don't use mime digest
	memset(buf2, 0, sizeof(buf2));
    l2 = 0;
    encode((const byte*)pDf->mbufDigest.pMem, pDf->mbufDigest.nLen, (byte*)buf2, &l2);
	ddocDebug(3, "addAllDocInfos", "DF: %s digest \'%s\'", pDf->szId, buf2);
    addDocInfo(&pDocInfo, pSigInfo, pDf->szId,
	       pDf->szDigestType, (byte*)pDf->mbufDigest.pMem,
	       pDf->mbufDigest.nLen, buf, len);
  }
  return ERR_OK;
}

//============================================================
// Calculates and stores a signature for this SignatureInfo object
// pSigInfo - signature info object
// nSigType - signature type code
// keyfile - RSA key file
// passwd - key password
// certfile - certificate file
//============================================================
EXP_OPTION int calculateSigInfoSignature(const SignedDoc* pSigDoc, 
					 SignatureInfo* pSigInfo, int nSigType, 
					 const char* keyfile, const char* passwd, 
					 const char* certfile)
{
  int err = ERR_OK;
  char buf2[SIGNATURE_LEN], *buf1 = NULL;
  int l2, l1;
  X509 *pCert = 0;

  RETURN_IF_NULL_PARAM(pSigInfo);
  clearErrors();
  if(nSigType == SIGNATURE_RSA) {
    err = ddocSignatureValue_new(&(pSigInfo->pSigValue), 0, SIGN_RSA_NAME, 0, 0);
    if(err) return err;

    err = ReadCertificate(&pCert, certfile);
    if(!err && pCert)
      err = ddocSigInfo_SetSignersCert(pSigInfo, pCert);
    RETURN_IF_NOT(err == ERR_OK, ERR_CERT_READ);
    // Signed properties digest
    buf1 = createXMLSignedProperties(pSigDoc, pSigInfo, 0);
    RETURN_IF_NULL(buf1);
    l1 = strlen(buf1);
    l2 = sizeof(buf2);
    calculateDigest((const byte*)buf1, l1, DIGEST_SHA1, (byte*)buf2, &l2);
    free(buf1);
    err = ddocSigInfo_SetSigPropDigest(pSigInfo, buf2, l2);
    // SignedInfo digest
    buf1 = createXMLSignedInfo(pSigDoc, pSigInfo);
    RETURN_IF_NULL(buf1);
    l2 = sizeof(buf2);
    err = signData((const byte*)buf1, strlen(buf1), (byte*)buf2, &l2, DIGEST_SHA1,
		   keyfile, passwd);
    free(buf1);
    err = ddocSigInfo_SetSignatureValue(pSigInfo, buf2, l2);
  } else
    err = ERR_UNSUPPORTED_SIGNATURE;
  if (err != ERR_OK) SET_LAST_ERROR(err);
  return err;
}

//============================================================
// Calculates <SignedProperties> digest
// pSigInfo - signature info object
//============================================================
EXP_OPTION int calculateSignedPropertiesDigest(SignedDoc* pSigDoc, SignatureInfo* pSigInfo)
{
  int err = ERR_OK, l1, l2;
  byte buf1[DIGEST_LEN256+2], *buf2 = 0, *buf3 = 0;

  RETURN_IF_NULL_PARAM(pSigInfo);
  /* P.R 0->1 */
  buf2 = (byte*)createXMLSignedProperties(pSigDoc, pSigInfo, 1);
  RETURN_IF_NULL(buf2);
  buf3 = canonicalizeXML((char*)buf2, strlen((const char*)buf2));
  //dumpInFile("sigprop-sig1.txt", buf2);
  l2 = (int)strlen((const char*)buf3);
  l1 = (int)sizeof(buf1);
  calculateDigest(buf3, l2, DIGEST_SHA1, buf1, &l1);
  free(buf2);
  free(buf3);
  err = ddocSigInfo_SetSigPropDigest(pSigInfo, (char*)buf1, l1);
  return err;
}

//============================================================
// Returns 1 if this signature has 1 reference that was verified
// by wrong DataFile hash calculated not using xmlns atribute
// pSigInfo - signature info pointer
//============================================================
EXP_OPTION int verifiedByWrongDataFileHash(const SignatureInfo* pSigInfo)
{
    int i;
    
    RETURN_IF_NULL_PARAM(pSigInfo);
    for(i = 0; i < pSigInfo->nDocs; i++) {
        RETURN_IF_NULL_PARAM(pSigInfo->pDocs[i]);
        if(pSigInfo->pDocs[i] && pSigInfo->pDocs[i]->szDigestType &&
           !strcmp(pSigInfo->pDocs[i]->szDigestType, DIGEST_SHA1_WRONG))
            return 1;
    }
    return 0;
}

//============================================================
// Returns 1 if one signature has 1 reference that was verified
// by wrong DataFile hash calculated not using xmlns atribute
// pSigDoc - signed doc container pointer
//============================================================
EXP_OPTION int hasSignatureWithWrongDataFileHash(const SignedDoc* pSigDoc)
{
    int i, d, j;
    SignatureInfo *pSigInfo = 0;
    
    RETURN_IF_NULL_PARAM(pSigDoc);
    d = getCountOfSignatures(pSigDoc);
    for(i = 0; i < d; i++) {
        pSigInfo = getSignature(pSigDoc, i);
        j = verifiedByWrongDataFileHash(pSigInfo);
        if(j) return j;
    }
    return 0;
}

//============================================================
// Calculates <SignedInfo> digest
// pSigInfo - signature info object
// digBuf - buffer for digest value
// digLen - address of buffer length. Must be initialized
// with buf max len, will be changed to actual length
//============================================================
EXP_OPTION int calculateSignedInfoDigest(SignedDoc* pSigDoc, SignatureInfo* pSigInfo, byte* digBuf, int* digLen)
{
  int err = ERR_OK, l2;
  byte *buf2 = NULL;

  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(digBuf);
  buf2 = (byte*)createXMLSignedInfo(pSigDoc, pSigInfo);      
  RETURN_IF_NULL(buf2);
  l2 = strlen((const char*)buf2);
	calculateDigest(buf2, l2, DIGEST_SHA1, digBuf, digLen);
  free(buf2);
  return err;
}

//============================================================
// Sets the signature value from a file that contains
// the base64 encoded signature value
// pSigInfo - signature info object
// szSigFile - filename
//============================================================
EXP_OPTION int setSignatureValueFromFile(SignatureInfo* pSigInfo, char* szSigFile)
{
  int err = ERR_OK, i, j, slen;
  FILE* hFile = 0;
  byte buf[FILE_BUFSIZE], sbuf[300], buf1[30];
  DigiDocMemBuf mbuf1;
  char *p1;

  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(szSigFile);
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  ddocDebug(3, "setSignatureValueFromFile", "reading: %s", szSigFile);
  if((hFile = fopen(szSigFile, "rb")) != NULL) {
    slen = 0;
    memset(sbuf, 0, sizeof(sbuf));
    // collect all hex chars to sbuf
    while((i = fread(buf, sizeof(char), FILE_BUFSIZE, hFile)) > 0) {
		ddocDebug(3, "setSignatureValueFromFile", "read: %d", i);
      for(j = 0; j < i; j++) {
        if(isxdigit(buf[j])) {
          if(isdigit(buf[j])) {
	    sbuf[slen++] = buf[j];
          } else {
            sbuf[slen++] = toupper(buf[j]);
	  } // else
	} // if
      } // for
    }
    ddocDebug(3, "setSignatureValueFromFile", "input: %d - \'%s\'", slen, sbuf);
    // decode hex
    memset(buf, 0, sizeof(buf));
    j = 0;
    hex2bin((const char*)sbuf, (byte*)buf, &j);
	ddocDebug(3, "setSignatureValueFromFile", "decoded: %d", j);
    // encode in base64 again as we need it this way for signature value
    memset(sbuf, 0, sizeof(sbuf));
    slen = 0;
    encode((const byte*)buf, j, (byte*)sbuf, &slen);
	ddocDebug(3, "setSignatureValueFromFile", "encoded: %d - \'%s\'", slen, sbuf);
    if(j == SIGNATURE_LEN) {
      snprintf((char*)buf1, sizeof(buf1), "#%s-SIG", pSigInfo->szId);
      ddocSignatureValue_new(&(pSigInfo->pSigValue), (char*)buf1, SIGN_RSA_NAME, (char*)buf, j);
      //ddocMemBuf_free(&(pSigInfo->mbufOrigContent));
      if(pSigInfo->mbufOrigContent.pMem) {
        p1 = strstr((char*)pSigInfo->mbufOrigContent.pMem, "<SignatureValue");
        if(p1) p1 = strchr(p1, '>');
        if(p1) p1++;
        if(p1) *p1 = 0;
        if(p1) {
          ddocMemAssignData(&mbuf1, (char*)pSigInfo->mbufOrigContent.pMem, -1);
          ddocMemAppendData(&mbuf1, (char*)sbuf, -1);
          p1++;
		  //ddocDebug(3, "setSignatureValueFromFile", "add: %s", p1);
          ddocMemAppendData(&mbuf1, p1, -1);
        }
        ddocMemAssignData(&(pSigInfo->mbufOrigContent), (const char*)mbuf1.pMem, mbuf1.nLen);
        ddocMemBuf_free(&mbuf1);
      }
    }
    else
      err = ERR_SIGNATURE;
    fclose(hFile);
  }
  else
    err = ERR_FILE_READ;
  if (err != ERR_OK) SET_LAST_ERROR(err);
  return err;
}

//============================================================
// Sets the signature value 
// pSigInfo - signature info object
// szSignature - signature value
// sigLen - signature length
//============================================================
EXP_OPTION int setSignatureValue(SignatureInfo* pSigInfo, byte* szSignature, int sigLen)
{
  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(szSignature);
	
  //clearErrors();
  // VS: not quite sure if there's not a second constant to use instead of removing the check
  //RETURN_IF_NOT(sigLen == SIGNATURE_LEN, ERR_SIGNATURE);
  ddocSignatureValue_new(&(pSigInfo->pSigValue), 0, SIGN_RSA_NAME, szSignature, sigLen);
  ddocMemBuf_free(&(pSigInfo->mbufOrigContent));
  return ERR_OK;
}


//=====================< NotaryInfo >======================================


//============================================================
// Returns the number of notary infos
// pSigDoc - signed doc pointer
//============================================================
EXP_OPTION int getCountOfNotaryInfos(const SignedDoc* pSigDoc)
{
  int n = 0, i = 0;
  SignatureInfo* pSigInfo = 0;
  RETURN_OBJ_IF_NULL(pSigDoc, -1);
  for(i = 0; i < getCountOfSignatures(pSigDoc); i++) {
    pSigInfo = getSignature(pSigDoc, i);
    if(pSigInfo->pNotary)
      n++;
  }
  return n;
}

//============================================================
// Returns the next free notary id
// pSigDoc - signed doc pointer
//============================================================
EXP_OPTION int getNextNotaryId(const SignedDoc* pSigDoc)
{
  int id = 0, n, i;
  SignatureInfo* pSigInfo = 0;
  
  RETURN_OBJ_IF_NULL(pSigDoc, -1);
  for(i = 0; i < getCountOfSignatures(pSigDoc); i++) {
    pSigInfo = getSignature(pSigDoc, i);
    if(pSigInfo->pNotary && pSigInfo->pNotary->szId) {
      n = atoi(pSigInfo->pNotary->szId+1);
      if(id <= n)
	id = n+1;
    }
  }
  return id;
}

//============================================================
// Returns the desired NotaryInfo object
// pSigDoc - signed doc pointer
// nIdx - NotaryInfo index (starting with 0)
//============================================================
EXP_OPTION NotaryInfo* getNotaryInfo(const SignedDoc* pSigDoc, int nIdx)
{
  SignatureInfo* pSigInfo = 0;
  NotaryInfo* pNotInfo = 0;
  int n = 0, i = 0;

  RETURN_OBJ_IF_NULL(pSigDoc, NULL);
  for(i = 0; i < getCountOfSignatures(pSigDoc); i++) {
    pSigInfo = getSignature(pSigDoc, i);
    if(pSigInfo->pNotary) {
      n++;
      if(n == nIdx) {
	pNotInfo = pSigInfo->pNotary;
	break;
      }
    }
  }
  return pNotInfo;
}

//============================================================
// Returns the last NotaryInfo object
// pSigDoc - signed doc pointer
// nIdx - NotaryInfo index (starting with 0)
//============================================================
EXP_OPTION NotaryInfo* ddocGetLastNotaryInfo(const SignedDoc* pSigDoc)
{
  SignatureInfo* pSigInfo;

  RETURN_OBJ_IF_NULL(pSigDoc, NULL);
  pSigInfo = ddocGetLastSignature(pSigDoc);
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  return pSigInfo->pNotary;
}

//============================================================
// Returns the NotaryInfo object with the given id
// pSigDoc - signed doc pointer
// id - NotaryInfo id
//============================================================
EXP_OPTION NotaryInfo* getNotaryWithId(const SignedDoc* pSigDoc, const char* id)
{
  SignatureInfo* pSigInfo = 0;
  int i = 0;

  RETURN_OBJ_IF_NULL(pSigDoc, NULL);
  for(i = 0; i < getCountOfSignatures(pSigDoc); i++) {
    pSigInfo = getSignature(pSigDoc, i);
    if(pSigInfo->pNotary && pSigInfo->pNotary->szId &&
       !strcmp(pSigInfo->pNotary->szId, id)) {
      return pSigInfo->pNotary;
    }
  }
  return NULL;
}

//============================================================
// Returns the NotaryInfo object that corresponds to the given signature
// pSigDoc - signed doc pointer
// id - NotaryInfo id
//============================================================
NotaryInfo* getNotaryWithSigId(const SignedDoc* pSigDoc, const char* sigId)
{
  SignatureInfo* pSigInfo = NULL;

  RETURN_OBJ_IF_NULL(pSigDoc, NULL);
  RETURN_OBJ_IF_NULL(sigId, NULL);
  pSigInfo = getSignatureWithId(pSigDoc, sigId);
  RETURN_OBJ_IF_NULL(pSigInfo, NULL);
  return pSigInfo->pNotary;
}

//============================================================
// Returns the NotaryInfo object that corresponds to the given signature
// ore creates a new one
// pSigDoc - signed doc pointer
// id - SignatureInfo id
//============================================================
NotaryInfo* getOrCreateNotaryWithSigId(SignedDoc* pSigDoc, const char* sigId)
{
  NotaryInfo* pNotary = 0;
  SignatureInfo* pSigInfo = 0;
  RETURN_OBJ_IF_NULL(pSigDoc, NULL);
  RETURN_OBJ_IF_NULL(sigId, NULL);
  pNotary = getNotaryWithSigId(pSigDoc, sigId);
  if(!pNotary) {
    pSigInfo = getSignatureWithId(pSigDoc, sigId);
    RETURN_OBJ_IF_NULL(pSigInfo, NULL);
    NotaryInfo_new(&pNotary, pSigDoc, pSigInfo);
  }
  return pNotary;
}


//============================================================
// Adds a new Notary element to a SignedDoc element and 
// initializes it partly
// pSigInfo - signature object to be verified by this notary
// return the newly created structure
//============================================================
EXP_OPTION int NotaryInfo_new(NotaryInfo **newNotaryInfo, SignedDoc* pSigDoc, SignatureInfo* pSigInfo)
{
  int n;
  char buf[10];

  RETURN_IF_NULL_PARAM(pSigDoc);
  RETURN_IF_NULL_PARAM(pSigInfo);
  // get next notary id
  if (pSigInfo) {
    strncpy(buf, pSigInfo->szId, sizeof(buf));
    buf[0] = 'N';
    // make sure we reset the szOrigContent on this signature
    // otherwise the new confirmation will not be written to file!
    ddocMemBuf_free(&(pSigInfo->mbufOrigContent));
  } else {
    n = getNextNotaryId(pSigDoc);
    RETURN_IF_NOT(n >= 0, ERR_BAD_NOTARY_ID);
    snprintf(buf, sizeof(buf), "N%d", n);
  }
  // memory management
  pSigInfo->pNotary = (NotaryInfo*)malloc(sizeof(NotaryInfo));  // MEMLEAK:  ???
  if (!pSigInfo->pNotary)
    RETURN_IF_BAD_ALLOC(pSigInfo->pNotary);
  memset(pSigInfo->pNotary, 0, sizeof(NotaryInfo));
  // set id	
  setString(&(pSigInfo->pNotary->szId), buf, -1);
  // version
  setString(&(pSigInfo->pNotary->szNotType), SK_NOT_VERSION, -1);
  
  *newNotaryInfo = pSigInfo->pNotary;
  return ERR_OK;
}

//============================================================
// cleanup NotaryInfo memory
// pNotary - object to be cleaned up
//============================================================
EXP_OPTION void NotaryInfo_free(NotaryInfo* pNotary)
{
  RETURN_VOID_IF_NULL(pNotary);
  //assert(pNotary);
  if(pNotary->szId)
    free(pNotary->szId);
  if(pNotary->szNotType)
    free(pNotary->szNotType);
  if(pNotary->timeProduced)
    free(pNotary->timeProduced);
  if(pNotary->szProducedAt)
    free(pNotary->szProducedAt);
  ddocMemBuf_free(&(pNotary->mbufRespId));
  if(pNotary->szDigestType)
    free(pNotary->szDigestType);
  if(pNotary->szSigType)
    free(pNotary->szSigType);
  ddocMemBuf_free(&(pNotary->mbufOcspDigest));
  ddocMemBuf_free(&(pNotary->mbufOcspResponse));
  // free the object itself
  free(pNotary);
}

//============================================================
// Returns OCSP responders id as in XML document
// pNotary - Notary info
// return DigiDocMemBuf buffer pointer or NULL for error
//============================================================
EXP_OPTION const DigiDocMemBuf* ddocNotInfo_GetResponderId(const NotaryInfo* pNotary)
{
  RETURN_OBJ_IF_NULL(pNotary, NULL);
  return &(pNotary->mbufRespId);
}

//============================================================
// Returns OCSP responders id value as string
// pNotary - Notary info
// return responder id value or NULL
//============================================================
EXP_OPTION const char* ddocNotInfo_GetResponderId_Value(const NotaryInfo* pNotary)
{
  RETURN_OBJ_IF_NULL(pNotary, NULL);
  return (const char*)pNotary->mbufRespId.pMem;
}

//============================================================
// Sets OCSP responders id as in XML document
// pNotary - Notary info
// data - new responder id value
// len - length of value
// return DigiDocMemBuf buffer pointer or NULL for error
//============================================================
int ddocNotInfo_SetResponderId(NotaryInfo* pNotary, const char* data, long len)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(data);
  err = ddocMemAssignData(&(pNotary->mbufRespId), data, len);
  return err;
}

//============================================================
// Returns OCSP response as memory buffer
// pNotary - Notary info
// return DigiDocMemBuf buffer pointer or NULL for error
//============================================================
const DigiDocMemBuf* ddocNotInfo_GetOCSPResponse(const NotaryInfo* pNotary)
{
  RETURN_OBJ_IF_NULL(pNotary, NULL);
  return &(pNotary->mbufOcspResponse);
}

//============================================================
// Retrieves OCSP responses responder id type and value
// pResp - OCSP response
// pType - buffer for type
// pMbufRespId - responder id
// returns error code or ERR_OK
//============================================================
int ddocGetOcspRespIdTypeAndValue(OCSP_RESPONSE* pResp, 
				int *pType, DigiDocMemBuf* pMbufRespId)
{
  int err = ERR_OK;
  OCSP_BASICRESP *br = NULL;
  
  const X509_NAME *name = NULL;
  const ASN1_OCTET_STRING *id = NULL;
  RETURN_IF_NULL_PARAM(pResp);
  RETURN_IF_NULL_PARAM(pType);
  RETURN_IF_NULL_PARAM(pMbufRespId);
  if((br = OCSP_response_get1_basic(pResp)) == NULL) 
    SET_LAST_ERROR_RETURN_CODE(ERR_OCSP_NO_BASIC_RESP);
  if(!err && br) {
	OCSP_resp_get0_id(br, &id, &name);
	if(name) {
	  *pType = RESPID_NAME_TYPE;
	  ddocMemSetLength(pMbufRespId, 300);
        //X509_NAME_oneline(br->tbsResponseData->responderId->value.byName, (char*)pMbufRespId->pMem, pMbufRespId->nLen);
		//AM 26.09.08
		err = ddocCertGetDNFromName((X509_NAME*)name, pMbufRespId);
		//RETURN_IF_NOT(err == ERR_OK, err);
	} else if(id) {
	  *pType = RESPID_KEY_TYPE;
	  err = ddocMemAssignData(pMbufRespId, (const char*)id->data, id->length);
	} else {
        SET_LAST_ERROR(ERR_OCSP_WRONG_RESPID);
    }
  }
  if(br)
    OCSP_BASICRESP_free(br);
  return err;
}

//============================================================
// Sets OCSP respondese value as in XML document. Must pass in
// binary DER data!
// pNotary - Notary info
// data - new responder id value
// len - length of value
// return DigiDocMemBuf buffer pointer or NULL for error
//============================================================
int ddocNotInfo_SetOCSPResponse(NotaryInfo* pNotary, const char* data, long len)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(data);
  err = ddocMemAssignData(&(pNotary->mbufOcspResponse), data, len);
  return err;
}

//============================================================
// Returns OCSP response value
// pNotary - Notary info
// return OCSP_RESPONSE pointer or NULL for error. Caller must
//    use OCSP_RESPONSE_free() to release it.
//============================================================
OCSP_RESPONSE* ddocNotInfo_GetOCSPResponse_Value(const NotaryInfo* pNotary)
{
  OCSP_RESPONSE* pResp = NULL;

  RETURN_OBJ_IF_NULL(pNotary, NULL);
  RETURN_OBJ_IF_NULL(pNotary->mbufOcspResponse.pMem, NULL);
  ddocOcspReadOcspResp(&pResp, (DigiDocMemBuf*)&(pNotary->mbufOcspResponse));
  return pResp;
}

//============================================================
// Sets OCSP respondese value. Must pass in real OCSP_RESPONSE
// pNotary - Notary info
// data - new responder id value
// len - length of value
// return DigiDocMemBuf buffer pointer or NULL for error
//============================================================
int ddocNotInfo_SetOCSPResponse_Value(NotaryInfo* pNotary, OCSP_RESPONSE* pResp)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(pResp);
  err = ddocOcspWriteOcspResp(pResp, (DigiDocMemBuf*)&(pNotary->mbufOcspResponse));
  return err;
}

//============================================================
// Helper function to get OCSP response parts
// pNotary - notary object
// ppResp - adr for OCSP_RESPONSE - must free!
// ppBasResp - adr for OCSP_BASICRESP - don't free
// ppSingle - optional adr for OCSP_SINGLERESP - don't free
//============================================================
int ddocNotInfo_GetBasicResp(const NotaryInfo* pNotary, OCSP_RESPONSE **ppResp,
			     OCSP_BASICRESP **ppBasResp, OCSP_SINGLERESP **ppSingle)
{
  int err = ERR_OK;

  // check input
  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(ppResp);
  RETURN_IF_NULL_PARAM(ppBasResp);
  // single response retrieval is optional - don't check it
  *ppResp = ddocNotInfo_GetOCSPResponse_Value(pNotary);
  if(*ppResp && ppBasResp) {
    *ppBasResp = OCSP_response_get1_basic(*ppResp);
    if(*ppBasResp) {
	  if(ppSingle)
		*ppSingle = OCSP_resp_get0(*ppBasResp, 0);
    }
    else
      return ERR_OCSP_NO_BASIC_RESP;
  }
  return err;
}

//============================================================
// Returns OCSP responders id type as string
// pNotary - Notary info
// return responder id type or NULL. DO NOT free() it!
//============================================================
EXP_OPTION const char* ddocNotInfo_GetResponderId_Type(const NotaryInfo* pNotary)
{
  int err = ERR_OK;
  OCSP_RESPONSE *pResp = 0;
  OCSP_BASICRESP *br = NULL;
  const ASN1_OCTET_STRING *id = NULL;
  const X509_NAME *name = NULL;
  char *p1 = RESPID_NAME_VALUE; // default value is name - usefull in format 1.0 where we had no good OCSP response

  RETURN_OBJ_IF_NULL(pNotary, NULL);
  err = ddocNotInfo_GetBasicResp(pNotary, &pResp, &br, NULL);
  if(!err && br) {
	OCSP_resp_get0_id(br, &id, &name);
	if(name)
		p1 = RESPID_NAME_VALUE;
	else if(id)
		p1 = RESPID_KEY_VALUE;
	else
      SET_LAST_ERROR(ERR_OCSP_WRONG_RESPID);
  }
  if(pResp)
    OCSP_RESPONSE_free(pResp);
  // PR. leak found
  if(br)
    OCSP_BASICRESP_free(br);
  return p1;
}

//============================================================
// Returns OCSP responses thisUpdate atribute as string
// pNotary - Notary info
// pMBuf - buffer for thisUpdate value
// return error code OR ERR_OK.
//============================================================
EXP_OPTION int ddocNotInfo_GetThisUpdate(const NotaryInfo* pNotary, DigiDocMemBuf* pMBuf)
{
  int err = ERR_OK;
  OCSP_RESPONSE *pResp = 0;
  OCSP_BASICRESP *br = NULL;
  OCSP_SINGLERESP *single = NULL;
  ASN1_GENERALIZEDTIME *thisUpdate = NULL;

  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(pMBuf);
  err = ddocNotInfo_GetBasicResp(pNotary, &pResp, &br, &single);
  if(!err && br && single) {
    err = ddocMemSetLength(pMBuf, 50);
	OCSP_single_get0_status(single, NULL, NULL, &thisUpdate, NULL);
	ddocDebug(3, "ddocNotInfo_GetThisUpdate", "This update: %s", thisUpdate);
	if(!err && thisUpdate)
	  err = asn1time2str(NULL, thisUpdate, (char*)pMBuf->pMem, pMBuf->nLen);
  }
  if(pResp)
    OCSP_RESPONSE_free(pResp);
  // PR. leak found
  if(br)
    OCSP_BASICRESP_free(br);
  return err;
}


//============================================================
// Returns OCSP responses thisUpdate atribute as time_t
// pNotary - Notary info
// pTime - address of time_t variable
// return error code OR ERR_OK.
//============================================================
int ddocNotInfo_GetThisUpdate_timet(const NotaryInfo* pNotary, time_t* pTime)
{
  int err = ERR_OK;
  OCSP_RESPONSE *pResp = 0;
  OCSP_BASICRESP *br = NULL;
  OCSP_SINGLERESP *single = NULL;
  ASN1_GENERALIZEDTIME *thisUpdate = NULL;

  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(pTime);
  err = ddocNotInfo_GetBasicResp(pNotary, &pResp, &br, &single);
  if(!err && br && single) {
	OCSP_single_get0_status(single, NULL, NULL, &thisUpdate, NULL);
	if(!err && thisUpdate)
	  err = asn1time2time_t_local(thisUpdate, pTime);
  }
  if(pResp)
    OCSP_RESPONSE_free(pResp);
  // PR. leak found
  if(br)
    OCSP_BASICRESP_free(br);
  return err;
}

//============================================================
// Returns OCSP responses producedAt atribute as time_t
// pNotary - Notary info
// pTime - address of time_t variable
// return error code OR ERR_OK.
//============================================================
int ddocNotInfo_GetProducedAt_timet(const NotaryInfo* pNotary, time_t* pTime)
{
  int err = ERR_OK;
  OCSP_RESPONSE *pResp = 0;
  OCSP_BASICRESP *br = NULL;
  const ASN1_GENERALIZEDTIME *producedAt = NULL;

  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(pTime);
  err = ddocNotInfo_GetBasicResp(pNotary, &pResp, &br, NULL);
  producedAt = OCSP_resp_get0_produced_at(br);
  if(!err && br && producedAt) {
	err = asn1time2time_t_local((ASN1_GENERALIZEDTIME*)producedAt, pTime);
  }
	//AM 22.06.08 lets free br too
	if(br)
		OCSP_BASICRESP_free(br);
  if(pResp)
    OCSP_RESPONSE_free(pResp);
  return err;
}

//============================================================
// Returns OCSP responses producedAt from xml as time_t
// pNotary - Notary info
// pTime - address of time_t variable
// return error code OR ERR_OK.
//============================================================
int ddocNotInfo_GetProducedAtXml_timet(const NotaryInfo* pNotary, time_t* pTime)
{
  int err = ERR_OK;

  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(pTime);
  if(!err && pNotary->szProducedAt) {
    err = str2time_t(pNotary->szProducedAt, pTime);
  }
  return err;
}

//============================================================
// Returns OCSP responses nextUpdate atribute as string
// pNotary - Notary info
// pMBuf - buffer for nextUpdate value
// return error code OR ERR_OK.
//============================================================
EXP_OPTION int ddocNotInfo_GetNextUpdate(const NotaryInfo* pNotary, DigiDocMemBuf* pMBuf)
{
  int err = ERR_OK;
  OCSP_RESPONSE *pResp = 0;
  OCSP_BASICRESP *br = NULL;
  OCSP_SINGLERESP *single = NULL;
  ASN1_GENERALIZEDTIME *nextUpdate = NULL;

  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(pMBuf);
  err = ddocNotInfo_GetBasicResp(pNotary, &pResp, &br, &single);
  if(!err && br && single) {
    err = ddocMemSetLength(pMBuf, 50);
	OCSP_single_get0_status(single, NULL, NULL, NULL, &nextUpdate);
	if(!err && nextUpdate)
	  err = asn1time2str(NULL, nextUpdate, (char*)pMBuf->pMem, pMBuf->nLen);
  }
  if(pResp)
    OCSP_RESPONSE_free(pResp);
  // PR. leak found
  if(br)
    OCSP_BASICRESP_free(br);
  return err;
}

//============================================================
// Returns OCSP responses IssuerNameHash atribute
// pNotary - Notary info
// pMBuf - buffer for IssuerNameHash value
// return error code OR ERR_OK.
//============================================================
int ddocNotInfo_GetIssuerNameHash(const NotaryInfo* pNotary, DigiDocMemBuf* pMBuf)
{
  int err = ERR_OK;
  OCSP_RESPONSE *pResp = 0;
  OCSP_BASICRESP *br = NULL;
  OCSP_SINGLERESP *single = NULL;
  ASN1_OCTET_STRING *issuerNameHash = NULL;
  const OCSP_CERTID *cid = NULL;

  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(pMBuf);
  err = ddocNotInfo_GetBasicResp(pNotary, &pResp, &br, &single);
  if(!err && br) {
	cid = OCSP_SINGLERESP_get0_id(OCSP_resp_get0(br, 0));
	OCSP_id_get0_info(&issuerNameHash, NULL, NULL, NULL, (OCSP_CERTID*)cid);
	err = ddocMemAssignData(pMBuf, (const char*)issuerNameHash->data,
				issuerNameHash->length);
  }
  if(pResp)
    OCSP_RESPONSE_free(pResp);
  // PR. leak found
  if(br)
    OCSP_BASICRESP_free(br);
  return err;
}

//============================================================
// Returns OCSP responses IssuerKeyHash atribute
// pNotary - Notary info
// pMBuf - buffer for IssuerKeyHash value
// return error code OR ERR_OK.
//============================================================
int ddocNotInfo_GetIssuerKeyHash(const NotaryInfo* pNotary, DigiDocMemBuf* pMBuf)
{
  int err = ERR_OK;
  OCSP_RESPONSE *pResp = 0;
  OCSP_BASICRESP *br = NULL;
  OCSP_SINGLERESP *single = NULL;
  ASN1_OCTET_STRING *issuerKeyHash = NULL;
  const OCSP_CERTID *cid = NULL;

  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(pMBuf);
  err = ddocNotInfo_GetBasicResp(pNotary, &pResp, &br, &single);

  if(!err && br) {
	cid = OCSP_SINGLERESP_get0_id(OCSP_resp_get0(br, 0));
	OCSP_id_get0_info(NULL, NULL, &issuerKeyHash, NULL, (OCSP_CERTID*)cid);
	err = ddocMemAssignData(pMBuf, (const char*)issuerKeyHash->data,
				issuerKeyHash->length);
  }
  if(pResp)
    OCSP_RESPONSE_free(pResp);
  // PR. leak found
  if(br)
    OCSP_BASICRESP_free(br);
  return err;
}

//============================================================
// Returns OCSP responses real digest from response data
// pNotary - Notary info
// pMBuf - buffer for digest value
// return error code OR ERR_OK.
//============================================================
int ddocNotInfo_GetOcspRealDigest(const SignedDoc* pSigDoc, const NotaryInfo* pNotary, DigiDocMemBuf* pMBuf)
{
  int err = ERR_OK, nIdx = 0, l1 = 0, l2 = 0, nCheckOcspLen = 0;
  OCSP_RESPONSE *pResp = 0;
  OCSP_BASICRESP *br = NULL;
  OCSP_SINGLERESP *single = NULL;
  X509_EXTENSION *ext = NULL;
  ASN1_OCTET_STRING *value = NULL;
  byte* p = 0, buf2[DIGEST_LEN256 * 2 + 2];
    
  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(pMBuf);
  err = ddocNotInfo_GetBasicResp(pNotary, &pResp, &br, &single);
  nCheckOcspLen = ConfigItem_lookup_bool("CHECK_OCSP_NONCE", 0);
  if(!err && br) {
    nIdx = OCSP_BASICRESP_get_ext_by_NID(br, NID_id_pkix_OCSP_Nonce, -1);
    if(nIdx >= 0) {
        ext = OCSP_BASICRESP_get_ext(br, nIdx);
        if(ext != NULL) {
			value = X509_EXTENSION_get_data(ext);
			int l1 = ASN1_STRING_length(value);
			p = ASN1_STRING_data(value);
            if(l1 > 20 && p[0] == V_ASN1_OCTET_STRING && p[1] == l1-2)
              err = ddocMemAssignData(pMBuf, (const char*)p+2, l1-2);
            else
              err = ddocMemAssignData(pMBuf, (const char*)p, l1);
            // debug
            l2 = sizeof(buf2);
            memset(buf2, 0, l2);
            if(l1 <= DIGEST_LEN256) {
               bin2hex((const byte*)p, l1, (byte*)buf2, &l2);  
               ddocDebug(3, "ddocNotInfo_GetOcspRealDigest", "Not: %s nonce: %s len: %d err: %d", 
                          pNotary->szId, buf2, l1, err);
            }
            if(l1 != 22 && nCheckOcspLen && pSigDoc && strcmp(pSigDoc->szFormat, SK_XML_1_NAME)) {
                ddocDebug(1, "ddocNotInfo_GetOcspRealDigest", "Not: %s invalid nonce: %s len: %d err: %d", 
                          pNotary->szId, buf2, l1, err);
                err = ERR_OCSP_NONCE_INVALID;
            }
        }
    }
    else
      err = ERR_OCSP_NO_NONCE;
  }
  if(pResp)
    OCSP_RESPONSE_free(pResp);
  if(br)
    OCSP_BASICRESP_free(br);
  return err;
}

//============================================================
// Returns OCSP responses signature value
// pNotary - Notary info
// pMBuf - buffer for signature value
// return error code OR ERR_OK.
//============================================================
int ddocNotInfo_GetOcspSignatureValue(const NotaryInfo* pNotary, DigiDocMemBuf* pMBuf)
{
  int err = ERR_OK;
  OCSP_RESPONSE *pResp = 0;
  OCSP_BASICRESP *br = NULL;
  const ASN1_OCTET_STRING *signature = NULL;

  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(pMBuf);
  err = ddocNotInfo_GetBasicResp(pNotary, &pResp, &br, NULL);
  if(!err && br) {
	signature = OCSP_resp_get0_signature(br);
	err = ddocMemAssignData(pMBuf, (const char*)signature->data,
				signature->length);
  }
  if(pResp)
    OCSP_RESPONSE_free(pResp);
  // PR. leak found
  if(br)
    OCSP_BASICRESP_free(br);
  return err;
}

//============================================================
// Returns OCSP response digest as in XML document
// pNotary - Notary info
// return DigiDocMemBuf buffer pointer or NULL for error
//============================================================
EXP_OPTION const DigiDocMemBuf* ddocNotInfo_GetOcspDigest(const NotaryInfo* pNotary)
{
  RETURN_OBJ_IF_NULL(pNotary, NULL);
  return &(pNotary->mbufOcspDigest);
}

//============================================================
// Sets OCSP response digest id as in XML document
// pNotary - Notary info
// data - new digest value
// len - length of value
// return DigiDocMemBuf buffer pointer or NULL for error
//============================================================
int ddocNotInfo_SetOcspDigest(NotaryInfo* pNotary, const char* data, long len)
{
  int err = ERR_OK;
  RETURN_IF_NULL_PARAM(pNotary);
  RETURN_IF_NULL_PARAM(data);
  err = ddocMemAssignData(&(pNotary->mbufOcspDigest), data, len);
  return err;
}



//============================================================
// Adds a certificate to Notary and initializes Notary
// pNotary - Notary info
// cert - responders certificate
// return error code
//============================================================
int addNotaryInfoCert(SignedDoc *pSigDoc, NotaryInfo *pNotary, X509 *cert)
{
  int err = ERR_OK, n;
  char buf[300];
  CertID* pCertID = 0;
  SignatureInfo* pSigInfo = 0;
  DigiDocMemBuf mbuf1;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  ddocDebug(3, "addNotaryInfoCert", "adding cert: %s to notary: %s", (cert ? "OK" : "NULL"), pNotary->szId);
  RETURN_IF_NULL_PARAM(pNotary);
  pSigInfo = ddocGetSignatureForNotary(pSigDoc, pNotary);
  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(cert);
  RETURN_IF_NOT(err == ERR_OK, err);
  if(!ddocSigInfo_GetOCSPRespondersCert(pSigInfo))
	err = ddocSigInfo_SetOCSPRespondersCert(pSigInfo, cert);
  buf[0] = 0;
  err = ReadCertSerialNumber(buf, sizeof(buf), cert);
  if(strlen(buf)){
    pCertID = ddocCertIDList_GetCertIDOfSerial(pSigInfo->pCertIDs, buf);
  }
  if(!pCertID)
    pCertID = ddocSigInfo_GetOrCreateCertIDOfType(pSigInfo, CERTID_TYPE_RESPONDERS_CERTID);
  else //AM quick fix for smartlink bdoc
	if(pCertID->nType==0)pCertID->nType = CERTID_TYPE_RESPONDERS_CERTID;
  RETURN_IF_NULL(pCertID);
  ddocCertID_SetIssuerSerial(pCertID, buf);
  n = sizeof(buf);
  memset(buf, 0, sizeof(buf));
  n = 40;
  RETURN_IF_NOT(X509_digest(cert, EVP_sha1(), (unsigned char*)buf, (unsigned int*)&n), ERR_X509_DIGEST);
  if(!pCertID->pDigestValue)
    ddocCertID_SetDigestValue(pCertID, (const char*)buf, n);
  ddocCertGetSubjectDN(cert, &mbuf1);
  ddocCertID_SetIssuerName(pCertID, (char*)mbuf1.pMem);
  ddocMemBuf_free(&mbuf1);
  snprintf(buf, sizeof(buf), "%s-RESPONDER_CERTINFO", pSigInfo->szId);
  ddocCertID_SetId(pCertID, buf);
  ddocDebug(4, "addNotaryInfoCert", "cert: %s to notary: %s", (cert ? "OK" : "NULL"), pNotary->szId, err);
  return err;
}


//============================================================
// Removes Notary cert value and id after unsucessful verification attempt
// pSigInfo - signature info [REQUIRED]
// return error code
//============================================================
int removeNotaryInfoCert(SignatureInfo* pSigInfo)
{
  CertID* pCertID;
  CertValue* pCertVal;
  int i;

  RETURN_IF_NULL_PARAM(pSigInfo);
  // remove cert values of type responder
  for(i = 0; i < ddocCertValueList_GetCertValuesCount(pSigInfo->pCertValues); i++) {
	  pCertVal = ddocCertValueList_GetCertValue(pSigInfo->pCertValues, i);
	  if(pCertVal && pCertVal->nType == CERTID_VALUE_RESPONDERS_CERT)
        ddocCertValueList_DeleteCertValue(pSigInfo->pCertValues, i);
  }
  // remove cert ids of type responder
  for(i = 0; i < ddocCertIDList_GetCertIDsCount(pSigInfo->pCertIDs); i++) {
	  pCertID = ddocCertIDList_GetCertID(pSigInfo->pCertIDs, i);
	  if(pCertID && pCertID->nType == CERTID_TYPE_RESPONDERS_CERTID)
        ddocCertIDList_DeleteCertID(pSigInfo->pCertIDs, i);
  }
  return ERR_OK;
}

//============================================================
// Adds a new Notary SignedInfo element to a SignedDoc 
//   element and initializes it
// newNotaryInfo - newly created structure
// pSigDoc - signed doc data
// pSigInfo - signature object to be verified by this notary
// ocspRespFile - OCSP response file name
// notaryCertFile - Notary cert file name
// returns error code or ERR_OK if no error.
//============================================================
// FIXME : What to do if initializeNotaryInfoWithOCSP fails?
EXP_OPTION int NotaryInfo_new_file(NotaryInfo **newNotaryInfo, SignedDoc *pSigDoc,
					 const SignatureInfo *pSigInfo, const char *ocspRespFile,
					 const char *notaryCertFile)

{
  OCSP_RESPONSE* resp;
  X509* notCert;
  NotaryInfo* pNotInf = NULL;
  int err = ERR_OK;
	
  RETURN_IF_NULL_PARAM(pSigDoc);
  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(ocspRespFile);
  RETURN_IF_NULL_PARAM(notaryCertFile);
  err = ReadOCSPResponse(&resp, ocspRespFile);
  RETURN_IF_NOT(err == ERR_OK, ERR_FILE_READ);
  err = ReadCertificate(&notCert, notaryCertFile);
  RETURN_IF_NOT(err == ERR_OK, ERR_CERT_READ);
  err = NotaryInfo_new(&pNotInf, pSigDoc, (SignatureInfo*)pSigInfo);
  RETURN_IF_NOT(err == ERR_OK, err);
  *newNotaryInfo = pNotInf;
  err = initializeNotaryInfoWithOCSP(pSigDoc, pNotInf, resp, notCert, 1);
  RETURN_IF_NOT(err == ERR_OK, err);
  return ERR_OK;
}

// forward deklaratsioon
int notary2ocspBasResp(const SignedDoc* pSigDoc, const NotaryInfo* pNotInfo, X509* notCert, OCSP_BASICRESP** pBasResp);
int calculateOcspBasicResponseDigest(OCSP_BASICRESP* pBsResp, byte* digBuf, int* digLen);

//============================================================
// Calculates the digest of NotaryInfo
// pSigDoc - signed document pointer
// pNotInfo - notary signature info 
// digBuf - signature buffer
// digLen - signature buffer length
// returns error code
//============================================================
EXP_OPTION int calculateNotaryInfoDigest(const SignedDoc* pSigDoc, 
	const NotaryInfo* pNotInfo, byte* digBuf, int* digLen)
{
  SignatureInfo* pSigInfo;
  int err = ERR_OK;
  const DigiDocMemBuf *pMBuf = 0;

  pMBuf = ddocNotInfo_GetOCSPResponse(pNotInfo);
  RETURN_IF_NULL(pMBuf);
  pSigInfo = ddocGetSignatureForNotary(pSigDoc, pNotInfo);
  RETURN_IF_NULL_PARAM(pSigInfo);
  if(!strcmp(pNotInfo->szDigestType,DIGEST_SHA256_NAME))
    err = calculateDigest((const byte*)pMBuf->pMem, pMBuf->nLen, DIGEST_SHA256, digBuf, digLen);
  else
    err = calculateDigest((const byte*)pMBuf->pMem, pMBuf->nLen, DIGEST_SHA1, digBuf, digLen);
  if (err != ERR_OK) SET_LAST_ERROR(err);
  return err;
}

//AM 12.03.08
//--------------------------------------------------
// Sets the CA Responders certificate
// pSigInfo - signature info object [REQUIRED]
// pCert - certificate [REQUIRED]
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocSigInfo_SetCACert(SignatureInfo* pSigInfo, X509* pCert)
{
  int err = ERR_OK;
  CertValue *pCertValue = 0;
  char  buf1[50];

  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(pCert);
  pCertValue = ddocSigInfo_GetOrCreateCertValueOfType(pSigInfo, CERTID_VALUE_CA_CERT);
  if(pCertValue) {
    snprintf(buf1, sizeof(buf1), "%s-CA_CERT", pSigInfo->szId);
    err = ddocCertValue_SetId(pCertValue, buf1);
    if(!err)
      err = ddocCertValue_SetCert(pCertValue, pCert);
  }
  return err;
}

//============================================================
// Calculates and stores a signature for this SignatureInfo object
// Uses PKCS#12 file to sign the info
// pSigInfo - signature info object
// nSigType - signature type code
// szPkcs12File - PKCS#12 file
// passwd - key password
//============================================================
EXP_OPTION int calculateSignatureWithPkcs12(SignedDoc* pSigDoc, SignatureInfo* pSigInfo, 
                    const char* szPkcs12File, const char* passwd)
{
  int err = ERR_OK;
  int sigLen;
  char sigDig[100];
  char signature[256];
  char* buf1;
  int l2;
  EVP_PKEY *pkey = 0;
  X509* x509 = 0;
  EVP_MD_CTX *ctx;
  DigiDocMemBuf mbuf1;

  RETURN_IF_NULL_PARAM(pSigInfo);
  RETURN_IF_NULL_PARAM(pSigDoc);
  RETURN_IF_NULL_PARAM(szPkcs12File);
  ddocDebug(3, "calculateSignatureWithPkcs12", "Keystore: %s passwd-len: %d", 
	    szPkcs12File, (passwd ? strlen(passwd) : 0));
  // read pkcs12 file
  err = ReadCertificateByPKCS12(&x509, szPkcs12File, passwd, &pkey);
  RETURN_IF_NOT(err == ERR_OK, err);
  // try key-usage check
  if(ConfigItem_lookup_int("KEY_USAGE_CHECK", 1) && x509) {
	if(!ddocCertCheckKeyUsage(x509, KUIDX_NON_REPUDIATION)) {
		X509_free(x509);
		EVP_PKEY_free(pkey);
    	SET_LAST_ERROR(ERR_SIGNERS_CERT_NON_REPU);
        return ERR_SIGNERS_CERT_NON_REPU;
	}
  }
  // set signers cert
  setSignatureCert(pSigInfo, x509);
  // create signing timestamp
  createTimestamp(pSigDoc, (char*)sigDig, sizeof(sigDig));
  setString((char**)&(pSigInfo->szTimeStamp), (const char*)sigDig, -1);
  // Signed properties digest
  buf1 = createXMLSignedProperties(pSigDoc, pSigInfo, 0);
  mbuf1.pMem = canonicalizeXML((char*)buf1, strlen(buf1));
  mbuf1.nLen = strlen((const char*)mbuf1.pMem);
  ddocDebugWriteFile(4, "sigprop-signed.txt", &mbuf1);
  l2 = sizeof(sigDig);
  err = calculateDigest((const byte*)mbuf1.pMem, mbuf1.nLen, DIGEST_SHA1, sigDig, &l2);
  free(buf1);
  ddocMemBuf_free(&mbuf1);
  if (err != ERR_OK) {
    SET_LAST_ERROR(err);			
    return err;
  }
  ddocSigInfo_SetSigPropDigest(pSigInfo, (const char*)sigDig, l2);
  ddocSigInfo_SetSigPropRealDigest(pSigInfo, (const char*)sigDig, l2);
  // create signed info
  buf1 = createXMLSignedInfo(pSigDoc, pSigInfo);      
  if (!buf1) {
    err = ERR_NULL_POINTER;
    SET_LAST_ERROR(err);
    return err ;
  }
  mbuf1.pMem = buf1; //canonicalizeXML((char*)buf1, strlen(buf1));
  mbuf1.nLen = strlen((const char*)mbuf1.pMem);
  //ddocDebugWriteFile(4, "siginf-signed.txt", &mbuf1);
  // get digest
  l2 = sizeof(sigDig);
  err = calculateDigest((const byte*)buf1, strlen(buf1),  DIGEST_SHA1, (byte*)sigDig, &l2);
  // debug
  sigLen = sizeof(signature);
  bin2hex((const byte*)sigDig, l2, (char*)signature, &sigLen);
  sigLen = sizeof(signature);
  encode((const byte*)sigDig, l2, (char*)signature, &sigLen);
  ddocDebug(3, "calculateSignatureWithPkcs12", "Sig-inf hash b64: %s", signature);
  if (err != ERR_OK) {
    err = ERR_NULL_POINTER;
    SET_LAST_ERROR(err);
    return err;
  } 
  ddocSigInfo_SetSigInfoRealDigest(pSigInfo, (const char*)sigDig, l2);
  // sign data
  sigLen = sizeof(signature);
  memset(signature, 0, sizeof(signature));
  // sign data
  ctx = EVP_MD_CTX_new();
  EVP_SignInit(ctx, EVP_sha1());
  EVP_SignUpdate(ctx, buf1, (unsigned long)strlen(buf1));
  err = EVP_SignFinal(ctx, signature, &sigLen, pkey);
  EVP_MD_CTX_free(ctx);
  free(buf1);
  if(err == ERR_LIB_NONE)
	err = ERR_OK;
  // set signature value
  ddocSigInfo_SetSignatureValue(pSigInfo, (const char*)signature, (int)sigLen);
  ddocDebug(3, "calculateSignatureWithPkcs12", "Sig-len: %ld", sigLen);
  //X509_free(x509);
  EVP_PKEY_free(pkey);
 
  return err;
}


