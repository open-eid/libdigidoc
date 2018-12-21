//==================================================
// FILE:	DigiDocSAXParser.c
// PROJECT:     Digi Doc
// DESCRIPTION: Digi Doc functions for xml parsing using SAX interface
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
//      12.08.2004      Veiko Sinivee
//                      Creation
//==================================================

#include <libdigidoc/DigiDocDefs.h>
#include <libdigidoc/DigiDocSAXParser.h>
#include <libdigidoc/DigiDocError.h>
#include <libdigidoc/DigiDocDebug.h>
#include <libdigidoc/DigiDocConvert.h>
#include <libdigidoc/DigiDocMem.h>
#include <libdigidoc/DigiDocLib.h>
#include <libdigidoc/DigiDocCert.h>
#include <libdigidoc/DigiDocConfig.h>
#include <libdigidoc/DigiDocOCSP.h>
#include <libdigidoc/DigiDocDfExtract.h>
#include <libdigidoc/DigiDocVerify.h>
#include <libdigidoc/DigiDocGen.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <ctype.h>

#include <libxml/globals.h>
#include <libxml/xmlerror.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h> /* only for xmlNewInputFromFile() */
#include <libxml/tree.h>
#include <libxml/debugXML.h>
#include <libxml/xmlmemory.h>
#include <libxml/c14n.h>

// string used to force parser to flush it's buffers
static char g_szDataFileFlush1[] = "</DataFile>";
static char g_szDataFileFlush2[] = "<DataFile Id=\"%s\" ContentType=\"%s\">";

#ifdef WIN32
  #define snprintf  _snprintf
  #include <wchar.h>
#endif

#if OPENSSL_VERSION_NUMBER < 0x10010000L
static EVP_ENCODE_CTX *EVP_ENCODE_CTX_new()
{
	return (EVP_ENCODE_CTX*)OPENSSL_malloc(sizeof(EVP_ENCODE_CTX));
}

static void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx)
{
	OPENSSL_free(ctx);
}
#endif

extern int ddocCheckFormatAndVer(const char* format, const char* version);
extern char* canonicalizeXML(char* source, int len);
extern int escapeXMLSymbols(const char* src, int srclen, char** dest);

#define FLAG_XML_ELEM   1
#define FLAG_SIGNATURE  2
#define FLAG_SIG_PART   3
#define FLAG_TS_INP     4

//===============< SAX handlers >==============================

/*
* Working area for XML parsing with SAX
*/
typedef struct SigDocParse_st {
  SignedDoc* pSigDoc;	// document file to be filled with data
  char tag[300];		// current tag
  char ctx1[300];		// context1
  char ctx2[300];		// context2
  char ctx3[300];		// context3
  char ctx4[300];
  char ctx5[300];
  BIO* bDataFile;
  EVP_ENCODE_CTX *ectx;
  SHA_CTX sctx, sctx2; // sha1 digest context and alternat dig context
  int errcode;
  char* szInputFileName;
  int checkFileDigest;
  int nIgnoreDataFile;  // incremented each time when EMBEDDED XML content is found.
			      // used to ignore such content
  DigiDocMemBuf mbufElemData;
  char bCollectElemData;
  char bNoXMLElemData;
  int checkUTF8;
  DigiDocMemBuf mbufSigData; // <Signature>
  char bCollectSigData;
  DigiDocMemBuf mbufSigPartData; // <SignedInfo> and <SignedProperties>
  char bCollectSigPartData;
  long lMaxDFLen;
  time_t tStartParse;
  long lSize;
  char bCollectDFData;  
  DigiDocMemBuf *pMemBufDF;
  int bKeepBase64;
  char b64line[66];
  int b64pos;
  DigiDocMemBuf mbufTags;
  XmlElemInfo *eRoot, *eCurr;
} SigDocParse;

//--------------------------------------------------
// Releases memory that might have been allocated during
// the parsing process.
// pctx - pointer to parsing context
//--------------------------------------------------
void ddocSAXCleanup(SigDocParse* pctx)
{
  // field: szInputFileName is not allocated in parser!
  ddocMemBuf_free(&(pctx->mbufElemData));
  ddocMemBuf_free(&(pctx->mbufSigData));
  ddocMemBuf_free(&(pctx->mbufSigPartData));
  ddocMemBuf_free(&(pctx->mbufTags));
  if(pctx->pMemBufDF)
    ddocMemBuf_free(pctx->pMemBufDF);
  if(pctx->bDataFile)
    BIO_free(pctx->bDataFile);
  if(pctx->eRoot)
    XmlElemInfo_free(pctx->eRoot);
  memset(pctx, 0, sizeof(SigDocParse));
}

//--------------------------------------------------
// Starts collecting some element data.
// pctx - pointer to parsing context
// nFlag - 1=element, 2=signature, 3=sigprop, 4=ts-input
// bNoXml - no-xml flag
//--------------------------------------------------
int ddocSaxParseStartCollecting(SigDocParse* pctx, int nFlag, int bNoXml)
{
  RETURN_IF_NULL_PARAM(pctx);
  switch(nFlag) {
  case FLAG_XML_ELEM: 
    pctx->bCollectElemData = 1; 
    pctx->errcode = ddocMemBuf_free(&(pctx->mbufElemData));
    break;
  case FLAG_SIGNATURE: 
    pctx->bCollectSigData = 1; 
    pctx->errcode = ddocMemBuf_free(&(pctx->mbufSigData));
    break;
  case FLAG_SIG_PART: 
    pctx->bCollectSigPartData = 1; 
    pctx->errcode = ddocMemBuf_free(&(pctx->mbufSigPartData));
    break;
  }
  pctx->bNoXMLElemData = bNoXml;
  return pctx->errcode;
}

//--------------------------------------------------
// Ends collecting some element data.
// pctx - pointer to parsing context
// nFlag - 1=element, 2=signature, 3=sigprop, 4=ts-input
// bNoXml - no-xml flag
//--------------------------------------------------
int ddocSaxParseEndCollecting(SigDocParse* pctx, int nFlag, int bNoXml)
{
  RETURN_IF_NULL_PARAM(pctx);
  switch(nFlag) {
  case FLAG_XML_ELEM: 
    pctx->bCollectElemData = 0; 
    pctx->errcode = ddocMemBuf_free(&(pctx->mbufElemData));
    break;
  case FLAG_SIGNATURE: 
    pctx->bCollectSigData = 0; 
    pctx->errcode = ddocMemBuf_free(&(pctx->mbufSigData));
    break;
  case FLAG_SIG_PART: 
    pctx->bCollectSigPartData = 0; 
    pctx->errcode = ddocMemBuf_free(&(pctx->mbufSigPartData));
    break;
  }
  pctx->bNoXMLElemData = bNoXml;
  return pctx->errcode;
}

//--------------------------------------------------
// Finds the desired atribute value. 
// atts - attributes array
// name - name of searched atribute
// defval - default value if not found
//--------------------------------------------------
const char* ddocSaxParseFindAttrib(const xmlChar **atts, 
				   const char* name, const char* defval)
{
  int i;
  
  for (i = 0; (atts != NULL) && (atts[i] != NULL); i += 2) {
    if(!strcmp((const char*)atts[i], name))
      return (const char*)atts[i+1];
  }
  return defval;
}


//--------------------------------------------------
// Decodes a URI value in form #<id>-<type> or #<id>@<type>
// into its components
// uri - URI value
// id - buffer for id
// nIdLen - id buffer length
// adr - buffer for adr
// nAdrLen - adr buffer length
//--------------------------------------------------
void decodeURI(const char* uri, char* id, int nIdLen, char* adr, int nAdrLen)
{
  int j, b, i, a;

  RETURN_VOID_IF_NULL(uri);
  RETURN_VOID_IF_NULL(id);
  RETURN_VOID_IF_NULL(adr);
	
  id[0] = adr[0] = 0;
  for(i = j = a = b = 0; uri[j] && (a < nAdrLen-1) && (i < nIdLen-1); j++) {
    switch(uri[j]) {
    case '#': continue;
    case '@': // same as the next
    case '-': b = 1; continue;
    default:
      if(b)
	adr[a++] = uri[j];
      else
	id[i++] = uri[j];
    }
  }
  adr[a] = 0;
  id[i] = 0;
}


//--------------------------------------------------
// handles the start of a <SignedDoc> element.
// Creates SignedDoc structure to read in the info.
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleStartSignedDoc(SigDocParse* pctx, const xmlChar *name, const xmlChar **atts)
{
  int i;
  const char *key = NULL, *value = NULL;

  //RETURN_VOID_IF_NULL(pctx);
  //RETURN_VOID_IF_NULL(name);
  //RETURN_VOID_IF_NULL(atts);

  strncpy(pctx->ctx1, (const char*)name, sizeof(pctx->ctx1)-1);
  for (i = 0; (atts != NULL) && (atts[i] != NULL); i += 2) {
    key = (const char*)atts[i];
    value = (const char*)atts[i+1];
    if(!strcmp(key, "format"))
      setString(&(pctx->pSigDoc->szFormat), value, -1);
    if(!strcmp(key, "version"))
      setString(&(pctx->pSigDoc->szFormatVer), value, -1);
  }
  if(ddocCheckFormatAndVer(pctx->pSigDoc->szFormat,
			   pctx->pSigDoc->szFormatVer))
    SET_LAST_ERROR(ERR_UNSUPPORTED_FORMAT);
}	

void unescapeFilename(char** szFileName, const char* str1, const char* str2)
{
	DigiDocMemBuf mbuf1, mbuf2;
	mbuf1.pMem = 0;
	mbuf1.nLen = 0;
	mbuf2.pMem = 0;
	mbuf2.nLen = 0;
	ddocDebug(4, "unescapeFilename", "In: %s replace: %s with: %s", *szFileName, str1, str2);
	if(szFileName && strstr((const char*)(*szFileName), str1)) { 
	  mbuf1.pMem = *szFileName; mbuf1.nLen = strlen(*szFileName);
      ddocMemReplaceSubstr(&mbuf1, &mbuf2, str1, str2);
      setString(szFileName, (const char*)mbuf2.pMem, -1); 
	  ddocMemBuf_free(&mbuf2);
	  ddocDebug(4, "unescapeFilename", "Escaped: %s", *szFileName);
	}
}

int utf8strlen(const char* src)
{
  int i, j;
  unsigned char uc;
  for(i = 0, j = 0; src && src[i]; i++) {
    uc = (unsigned char)(0x000000FF & src[i]);
    if(uc <= 0x7F || uc >= 0xC0)
      j++;
  }
  ddocDebug(4, "utf8strlen", "Str: %s, len: %d", src, j);
  return j;
}

//--------------------------------------------------
// handles the start of a <DataFile> element.
// Reads in id, filename, mime_type and embedded attributes
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleStartDataFile(SigDocParse* pctx, const xmlChar *name, const xmlChar **atts)
{
  int i, err = ERR_OK, j;
  long size = -1;
  const char *id = 0, *mime = 0, *dtype = 0, *dvalue = 0, *ctype = 0;
  char *p = 0;
  DigiDocMemBuf mbuf1, mbuf2;
  DataFile* pDataFile = NULL;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  mbuf2.pMem = 0;
  mbuf2.nLen = 0;
  ddocDebug(4, "handleStartDataFile", "Ignore: %d", pctx->nIgnoreDataFile);
  strncpy(pctx->ctx1, (const char*)name, sizeof(pctx->ctx1));
  id = mime = dtype = dvalue = 0;
  size = 0;
  // allocate mem dynamically and calculate required size as necessary
  if(!pctx->nIgnoreDataFile) {
    pctx->bCollectElemData = 1;
  }
  for (i = 0; (atts != NULL) && (atts[i] != NULL); i += 2) {
    if(!strcmp((const char*)atts[i], "Id"))
      id = (const char*)atts[i+1];
    if(!strcmp((const char*)atts[i], "Filename")) {
	    escapeXMLSymbols((const char*)atts[i+1], -1, &p);
        if(p)
          err = ddocMemAppendData(&mbuf1, p, -1);
        free(p); p = 0;
        ddocDebug(4, "handleStartDataFile", "Filename in: \'%s\' out: \'%s\'", 
		  atts[i+1], (char*)mbuf1.pMem);
        if(strchr((char*)mbuf1.pMem, '/') || strchr((char*)mbuf1.pMem, '\\')) {
            ddocDebug(1, "handleStartDataFile", "Invalid filename: \'%s\'", (char*)mbuf1.pMem);
            SET_LAST_ERROR(ERR_DF_NAME);
            return;
        }
    }
    if(!strcmp((const char*)atts[i], "MimeType"))
      mime = (const char*)atts[i+1];
    if(!strcmp((const char*)atts[i], "ContentType"))
      ctype = (const char*)atts[i+1];
    if(!strcmp((const char*)atts[i], "DigestType"))
      dtype = (const char*)atts[i+1];
    if(!strcmp((const char*)atts[i], "DigestValue"))
      dvalue = (const char*)atts[i+1];
    if(!strcmp((const char*)atts[i], "Size"))
      size = atol((const char*)atts[i+1]);
  }	
  if (!id || (strlen(id) > 21)) {
    SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
    ddocDebug(1, "handleStartDataFile", "Arr err id: %s",  id);
    return;
  }
  // VS: check id uniqueness
  for(j = 0; j < getCountOfDataFiles(pctx->pSigDoc); j++) {
      pDataFile = getDataFile(pctx->pSigDoc, j);
      if(pDataFile && pDataFile->szId && !strcmp(pDataFile->szId, id)) {
          ddocDebug(1, "handleStartDataFile", "DF %d has same id: %s",  j, id);
          SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
          return;
      }
  }
  if (!mime || (strlen(mime) > 255)) {
    SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
    ddocDebug(1, "handleStartDataFile", "Arr err mime: %s",  mime);
    return;
  } 
  if (!mbuf1.pMem || (utf8strlen(mbuf1.pMem) > 255)) {
    SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
    return;
  }
  if (size < 0) {
    SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
    ddocDebug(1, "handleStartDataFile", "Arr err size: %d",  size);
    return;
  } 
  if (!ctype || (strlen(ctype) > 40)) {
    SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
    ddocDebug(1, "handleStartDataFile", "Arr err ctype: %s",  ctype);
    return;
  }
  if (!pctx->pSigDoc->szFormatVer) {
    SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
    ddocDebug(1, "handleStartDataFile", "Arr err sigdoc missing");
    return;
  }
  if ((dtype && (strlen(dtype) > 10)) ||
      (dvalue && (strlen(dvalue) > 100))) {
      SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
      ddocDebug(1, "handleStartDataFile", "Arr err - dtype: %s dvalue: %s", dtype, dvalue);
      return;
  }
  if((!ctype || strcmp(ctype, CONTENT_EMBEDDED_BASE64)) 
     && !ConfigItem_lookup_bool("EMBEDDED_XML_SUPPORT", 0)) {
    SET_LAST_ERROR(ERR_BAD_DATAFILE_CONTENT_TYPE);
    return;
  }
  ddocDebug(4, "handleStartDataFile", "Check ignore");
  // if not in ignore mode / level
  if(!pctx->nIgnoreDataFile) {
    strncpy(pctx->ctx2, id, sizeof(pctx->ctx2)-1);
    ddocDebug(4, "handleStartDataFile", "Start DF: %s", id);
    if(ctype && !strcmp(ctype, CONTENT_EMBEDDED_BASE64)) {
	  pctx->ectx = EVP_ENCODE_CTX_new();
	  EVP_DecodeInit(pctx->ectx);
      ddocDebug(3, "handleStartDataFile", "Init sha1");
      SHA1_Init(&(pctx->sctx));
      SHA1_Init(&(pctx->sctx2));
    }
    if(pctx->bDataFile) 
      pctx->bDataFile = BIO_new_file((char*)mbuf1.pMem, "w");
    strncpy(pctx->ctx3, ctype, sizeof(pctx->ctx3)-1);	
    if(strcmp(pctx->pSigDoc->szFormatVer, DIGIDOC_XML_1_3_VER)) {
      // copy value first
      err = ddocMemAssignData(&mbuf2, (const char*)mbuf1.pMem, mbuf1.nLen+1);
      // apply conversion - no length change
      convWinToFName((const char*)mbuf1.pMem, (char*)mbuf2.pMem, mbuf2.nLen);
      err = DataFile_new(&pDataFile, pctx->pSigDoc, id, (char*)mbuf2.pMem, ctype, 
			 mime, size, NULL, 0, dtype, CHARSET_UTF_8);
    }
    else
      err = DataFile_new(&pDataFile, pctx->pSigDoc, id, (char*)mbuf1.pMem, ctype, 
			 mime, size, NULL, 0, dtype, CHARSET_UTF_8);
    // RETURN_IF_NULL(pDataFile);
    ddocDebug(4, "handleStartDataFile", "Create DF: \'%s\' - err: %d", id, err);
    if(dvalue) {
      err = ddocMemBuf_free(&mbuf2);	  
      err = ddocDecodeBase64Data((void*)dvalue, -1, &mbuf2);
      ddocDataFile_SetDetachedDigestValue(pDataFile, (const char*)mbuf2.pMem, mbuf2.nLen);
    }
    // add other attributes
    for (i = 0; (atts != NULL) && (atts[i] != NULL); i += 2) {
      if(strcmp((const char*)atts[i], "Id") && strcmp((const char*)atts[i], "Filename") &&
	 strcmp((const char*)atts[i], "MimeType") && strcmp((const char*)atts[i], "DigestValue") &&
	 strcmp((const char*)atts[i], "Size") && strcmp((const char*)atts[i], "ContentType") &&
	 strcmp((const char*)atts[i], "DigestType") && strcmp((const char*)atts[i], "xmlns"))
	err = addDataFileAttribute(pDataFile, (const char*)atts[i], (const char*)atts[i+1]);
    }
  }
  // is it pure XML ?
  if(!strcmp(ctype, CONTENT_EMBEDDED) || pctx->nIgnoreDataFile)
    pctx->nIgnoreDataFile++;
  // cleanup
  err = ddocMemBuf_free(&mbuf2);
  err = ddocMemBuf_free(&mbuf1);
  // replace &amp; with & if necessary
  unescapeFilename(&(pDataFile->szFileName), "&amp;", "&");
  unescapeFilename(&(pDataFile->szFileName), "&apos;", "'");
  unescapeFilename(&(pDataFile->szFileName), "&quot;", "\"");
  ddocDebug(4, "handleStartDataFile", "Final filename: \'%s\'", pDataFile->szFileName);
}


//--------------------------------------------------
// handles the content of a <DataFile> element.
// Reads in data file (Base64) data, decodes it
// and writes to a file
// pctx - pointer to XML parsing work-area
// value - character values read from file
// len - length of chars ???
//--------------------------------------------------
void handleDataFile(SigDocParse* pctx, const xmlChar *value, int len) 
{
  int l, i, j;
  char buf[1024], ch;
  DataFile* pDf = 0;
  DigiDocMemBuf mbuf1;
  // decode the content data
  ddocDebug(4, "handleDataFile", "DF: %s, append len: %d", pctx->ctx2, len);
  pDf = getDataFileWithId(pctx->pSigDoc, pctx->ctx2);
  RETURN_VOID_IF_NULL(pDf);
  ddocAppendDataFileData(pDf, pctx->lMaxDFLen, (void*)value, len, !strcmp(pDf->szContentType, CONTENT_EMBEDDED_BASE64));
  if(!strcmp(pctx->ctx3, CONTENT_EMBEDDED_BASE64)) { 
    // if using DataFile Base64 hack
#ifdef WITH_BASE64_HASHING_HACK
     if(pctx->pSigDoc->szFormatVer && strcmp(pctx->pSigDoc->szFormatVer, SK_XML_1_VER) && 
		pctx->pSigDoc->szFormat && strcmp(pctx->pSigDoc->szFormat, SK_XML_1_NAME)) {
	  ch = ((char*)value)[len];
      ((char*)value)[len] = 0;
	  ddocDebug(4, "handleDataFile", "sha1 update: \'%s\' len: %d", value, len);
	  mbuf1.pMem = (char*)value;
	  mbuf1.nLen = len;
	  ddocDebugWriteFile(4, "df-data.txt", &mbuf1);
	  ((char*)value)[len] = ch;
	  SHA1_Update(&(pctx->sctx), (char*)value, len);
      SHA1_Update(&(pctx->sctx2), (char*)value, len);
	  ddocMemBuf_free(&(pctx->mbufElemData));
	  if(pctx->bDataFile) {
		i = j = 0;
		while(i < len) {
			i = (i + 512 > len) ? len : i + 512;
			l = sizeof(buf);
			memset(buf, 0, sizeof(buf));
			EVP_DecodeUpdate(pctx->ectx, (unsigned char*)buf, &l, (unsigned char*)value + j, i - j);
			BIO_write(pctx->bDataFile, buf, l);
			j = i;
		}
	  }
	 } else {
#endif
		i = j = 0;
		while(i < len) {
			i = (i + 512 > len) ? len : i + 512;
			l = sizeof(buf);
			memset(buf, 0, sizeof(buf));
			EVP_DecodeUpdate(pctx->ectx, (unsigned char*)buf, &l, (unsigned char*)value + j, i - j);
			if(pctx->bDataFile) 		
				BIO_write(pctx->bDataFile, buf, l);
			buf[l] = 0;
			ddocDebug(4, "handleDataFile", "update sha1: %s", buf);
			SHA1_Update(&(pctx->sctx), buf, l);
			SHA1_Update(&(pctx->sctx2), buf, l);
			j = i;
		}
#ifdef WITH_BASE64_HASHING_HACK
	 }
#endif
  } else if(!strcmp(pctx->ctx3, CONTENT_EMBEDDED)) {
    if(pctx->bDataFile) 		
      BIO_write(pctx->bDataFile, value, len);
  }
}


//--------------------------------------------------
// handles the end of a <DataFile> element.
// Finishes writing file data
// pctx - pointer to XML parsing work-area
// name - tag name
//--------------------------------------------------
void handleEndDataFile(SigDocParse* pctx, const xmlChar *name)
{
  int l1, err;
  long l;
  char buf[1024], *pTmp1 = 0, *pTmp2 = 0;
  DataFile* pDf = 0;
  time_t t1, t2;
  DigiDocMemBuf mbuf1;

  ddocDebug(4, "handleEndDataFile", "DF: %s", pctx->ctx2);
  if(pctx->nIgnoreDataFile > 0 && !strcmp(pctx->ctx3, CONTENT_EMBEDDED)) 
    pctx->nIgnoreDataFile--;
  if(pctx->nIgnoreDataFile)
    return;
  pDf = getDataFileWithId(pctx->pSigDoc, pctx->ctx2);
  RETURN_VOID_IF_NULL(pDf);
  RETURN_VOID_IF_NULL(pDf->szContentType);

  // if store file data
  if(pctx->bDataFile && 
     !strcmp(pDf->szContentType, CONTENT_EMBEDDED_BASE64)) {
    l1 = sizeof(buf);
	EVP_DecodeFinal(pctx->ectx, (unsigned char*)buf, &l1);
	EVP_ENCODE_CTX_free(pctx->ectx);
    BIO_write(pctx->bDataFile, buf, l1);
    BIO_free(pctx->bDataFile);
    pctx->bDataFile = NULL;			
  }	
  // in version 1.0 we calculate digest over original data
   if(pctx->pSigDoc->szFormat && !strcmp(pctx->pSigDoc->szFormat, SK_XML_1_NAME)) {
    if(!strcmp(pDf->szContentType, CONTENT_EMBEDDED_BASE64)) {
      ddocDebug(3, "handleEndDataFile", "final sha1");
      SHA1_Final((unsigned char*)buf, &(pctx->sctx));
      checkErrors();
      ddocDataFile_SetDigestValue(pDf, buf, DIGEST_LEN);
      SHA1_Final((unsigned char*)buf, &(pctx->sctx2));
      ddocDataFile_SetWrongDigestValue(pDf, buf, DIGEST_LEN);
      // debug
      l1 = sizeof(buf);
      bin2hex(pDf->mbufDigest.pMem, pDf->mbufDigest.nLen, buf, &l1);
      ddocDebug(3, "handleEndDataFile", "DF: %s calc digest: %s len: %d", 
		  pDf->szId, buf, l1);
    } else if(!strcmp(pDf->szContentType, CONTENT_EMBEDDED)) {
      if(pctx->mbufElemData.pMem) {
	l1 = sizeof(buf);
	// remove the tag end marker
	pTmp2 = (char*)(pctx->mbufElemData.pMem) + pctx->mbufElemData.nLen - 1;
	while(*pTmp2 != '<' && pTmp2 > (char*)pctx->mbufElemData.pMem)
	  pTmp2--;
	if(*pTmp2 == '<')
	  *pTmp2 = 0;
	//skip leading newlines
	pTmp1 = (char*)pctx->mbufElemData.pMem;
	while(*pTmp1 && *pTmp1 != '<') pTmp1++;
	if(pctx->bDataFile) {
	  BIO_write(pctx->bDataFile, pTmp1, strlen(pTmp1));
	  BIO_free(pctx->bDataFile);
	  pctx->bDataFile = 0;
	}
	err = calculateDigest((const byte*)pTmp1, strlen(pTmp1),
			      DIGEST_SHA1, (byte*)buf, &l1);	
	if(!err) 
	  ddocDataFile_SetDigestValue(pDf, buf, DIGEST_LEN);	
	// free collected data
	// and mark the end of data collecting mode
	ddocMemBuf_free(&(pctx->mbufElemData));
	pctx->bCollectElemData = 0;
      }
    } else if(pctx->checkFileDigest) { 
      l1 = sizeof(buf);
      err = calculateFileDigest(pDf->szFileName, 
				DIGEST_SHA1, (byte*)buf, &l1, &l);	
      if(!err)
	ddocDataFile_SetDigestValue(pDf, buf, DIGEST_LEN);
      else
	ddocMemBuf_free(&(pDf->mbufDigest));
    }
  }
  // in version 1.1 we calculate digest over the whole <DataFile>
  // in canonicalized form
  else {
	// if use base64 hack of datafile
#ifdef WITH_BASE64_HASHING_HACK
	if(!strcmp(pDf->szContentType, CONTENT_EMBEDDED_BASE64)) {
	  strncpy(buf, "</DataFile>", sizeof(buf));
	  ddocDebug(3, "handleEndDataFile", "final sha1 update: \'%s\'", buf);
	  mbuf1.pMem = "</DataFile>";
	  mbuf1.nLen = strlen("</DataFile>");
	  ddocDebugWriteFile(4, "df-data.txt", &mbuf1);
	  SHA1_Update(&(pctx->sctx), buf, strlen(buf));
      SHA1_Update(&(pctx->sctx2), buf, strlen(buf));
	  memset(buf, 0, sizeof(buf));
	  SHA1_Final((unsigned char*)buf, &(pctx->sctx));
	  ddocDataFile_SetDigestValue(pDf, buf, DIGEST_LEN);
      SHA1_Final((unsigned char*)buf, &(pctx->sctx2));
      ddocDataFile_SetWrongDigestValue(pDf, buf, DIGEST_LEN);
	  setString((char**)&(pDf->szDigestType), DIGEST_SHA1_NAME, -1);
	  // debug
	  l1 = sizeof(buf);
	  encode((const byte*)pDf->mbufDigest.pMem, pDf->mbufDigest.nLen, (byte*)buf, &l1);
	  ddocDebug(3, "handleEndDataFile", "DF: %s calc digest: %s len: %d", pDf->szId, buf, l1);
	  ddocMemBuf_free(&(pctx->mbufElemData));
	  pctx->bCollectElemData = 0;
      // wrong digest
      l1 = sizeof(buf);
      encode((const byte*)pDf->mbufWrongDigest.pMem, pDf->mbufWrongDigest.nLen, (byte*)buf, &l1);
      ddocDebug(3, "handleEndDataFile", "DF: %s alt calc digest: %s len: %d", pDf->szId, buf, l1);

	} else {
#endif
	  // debug
	time(&t1);
    ddocDebug(4, "handleEndDataFile", "DF: %s data-len: %ld, parsing time: %d [sek]", 
		(const char*)name, pctx->mbufElemData.nLen, (t1 - pctx->tStartParse));
    ddocDebug(8, "handleEndDataFile", "DF: %s data:\n%s", (const char*)name, pctx->mbufElemData.pMem);
    if(pctx->mbufElemData.pMem) {
      pTmp2 = canonicalizeXML((char*)pctx->mbufElemData.pMem, pctx->mbufElemData.nLen);
      time(&t2);
      ddocDebug(4, "handleEndDataFile", "Canonicalizing: %s, time: %d [sek]", 
		(pTmp2 ? "OK" : "ERROR"), (t2 - t1));
      if(pTmp2) {
	SHA1_Init(&(pctx->sctx));
	SHA1_Update(&(pctx->sctx), pTmp2, strlen(pTmp2));
	SHA1_Final((unsigned char*)buf,&(pctx->sctx));
    ddocDataFile_SetDigestValue(pDf, buf, DIGEST_LEN);
    setString((char**)&(pDf->szDigestType), DIGEST_SHA1_NAME, -1);
    ddocDebug(4, "handleEndDataFile", "DF: %s digest updated", pDf->szId);
    l1 = sizeof(buf);
    encode((byte*)pDf->mbufDigest.pMem, pDf->mbufDigest.nLen, (byte*)buf, &l1);
    ddocDebug(4, "handleEndDataFile", "DF: %s calc digest: %s len: %d", pDf->szId, buf, l1);
    // P.R ends
    ddocDebug(4, "handleEndDataFile", "DF: %s canonical XML: \'%s\'", pDf->szId, pTmp2);

	ddocDebug(4, "handleEndDataFile", "DF: %s calc digest: %s len: %d", 
		  pDf->szId, buf, l1);
	ddocDebug(4, "handleEndDataFile", "DF: %s canonical XML: \'%s\'", 
		  pDf->szId, pTmp2);
	free(pTmp2);
      } // if(pTmp2)
      ddocMemBuf_free(&(pctx->mbufElemData));
      pctx->bCollectElemData = 0;
    } // if(pctx->mbufElemData.pMem)
#ifdef WITH_BASE64_HASHING_HACK
	} // else not base64 hack
#endif
  } // else
}


//--------------------------------------------------
// handles the start of a <Signature> element.
// Adds a SignatureInfo struct to SignedDoc structure.
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleStartSignature(SigDocParse* pctx, const xmlChar **atts)
{
  int i, j;
  SignatureInfo *pSignatureInfo;

  if(!pctx->pSigDoc || !pctx->pSigDoc->szFormat) {
    pctx->errcode = ERR_DIGIDOC_PARSE;
    addError(pctx->errcode, __FILE__, __LINE__, "Signature not in ddoc container!");
       // ddocDebug(1, "handleStartSignature", "Signature has no ddoc container");
    //    SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
    return;
  }
  for (i = 0; (atts != NULL) && (atts[i] != NULL); i += 2) {
    if(!strcmp((const char*)atts[i], "Id")) {
      memset(pctx->ctx1, 0, sizeof(pctx->ctx1));
      memset(pctx->ctx2, 0, sizeof(pctx->ctx2));
      memset(pctx->ctx3, 0, sizeof(pctx->ctx3));
      strncpy(pctx->ctx1, (const char*)atts[i+1], /*sizeof(pctx->ctx1)-*/50);
      // check id uniqueness
        for(j = 0; j < getCountOfSignatures(pctx->pSigDoc); j++) {
            pSignatureInfo = getSignature(pctx->pSigDoc, j);
            if(pSignatureInfo && pSignatureInfo->szId && !strcmp(pSignatureInfo->szId, (const char*)atts[i+1])) {
                ddocDebug(1, "handleStartSignature", "Signature: %d has same id: %s", j, (const char*)atts[i+1]);
                SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
                return;
            }
        }
        SignatureInfo_new(&pSignatureInfo, pctx->pSigDoc, (const char*)atts[i+1]); // MEMLEAK: ???
    }
  }
}



//--------------------------------------------------
// handles the start of a <Reference> element.
// Records the reference URI attribute
// pctx - pointer to XML parsing work-area
// atts - attributes
//--------------------------------------------------
void handleStartReference(SigDocParse* pctx, const xmlChar **atts)
{
  strncpy(pctx->ctx2, ddocSaxParseFindAttrib(atts, "URI", ""), sizeof(pctx->ctx2)-1);
}

//--------------------------------------------------
// handles the start of a <SignatureMethod> element.
// Records the signature method
// pctx - pointer to XML parsing work-area
// atts - attributes
//--------------------------------------------------
void handleStartSignatureMethod(SigDocParse* pctx, const xmlChar **atts)
{
  SignatureInfo *pSigInfo;
  const char *alg;

  alg = ddocSaxParseFindAttrib(atts, "Algorithm", NULL);
  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  if((alg != NULL)  && (pSigInfo != NULL) &&
     !strcmp(alg+strlen(alg)-8, "rsa-sha1") &&
     (pctx->ctx1[0] == 'S')) {
    ddocSignatureValue_new(&(pSigInfo->pSigValue), 0, SIGN_RSA_NAME, 0, 0);
  } 
#ifdef WITH_ECDSA
	else if((alg != NULL)  && (pSigInfo != NULL) &&
     !strcmp(alg+strlen(alg)-10, "ecdsa-sha1") &&
     (pctx->ctx1[0] == 'S')) {
    ddocSignatureValue_new(&(pSigInfo->pSigValue), 0, SIGN_ECDSA_NAME, 0, 0);
  }
#endif
}


//--------------------------------------------------
// handles the start of a <DigestMethod> element.
// Records the digest method
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleStartDigestMethod(SigDocParse* pctx, const xmlChar **atts)
{
  SignatureInfo *pSigInfo;
  const char *alg;

  alg = ddocSaxParseFindAttrib(atts, "Algorithm", NULL);
  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  if((alg != NULL) && (pSigInfo != NULL) &&
     !strcmp(alg+strlen(alg)-4, "sha1"))
    strncpy(pctx->ctx3, DIGEST_SHA1_NAME, sizeof(pctx->ctx3));
  else
    pctx->ctx3[0] = 0;
}

//--------------------------------------------------
// This function should be called at the end of
// </EncapsulatedOCSPValue> to determine the correct
// types of CertID and CertValue objects.
// pSigInfo - signature object
//--------------------------------------------------
int selectCertIdAndValueTypes(SignatureInfo* pSigInfo)
{
  int err = ERR_OK, i, j, l1;
  CertID* cid;
  CertValue *cval1, *cval2;
  X509* pCert;
  char buf1[300];
  DigiDocMemBuf mbuf1, mbuf2;
  const DigiDocMemBuf *pMBuf = 0;

  RETURN_IF_NULL_PARAM(pSigInfo);
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  mbuf2.pMem = 0;
  mbuf2.nLen = 0;
  for(i = 0; pSigInfo->pCertIDs &&
	i < ddocCertIDList_GetCertIDsCount(pSigInfo->pCertIDs); i++) {
    cid = ddocCertIDList_GetCertID(pSigInfo->pCertIDs, i);
    ddocDebug(3, "selectCertIdAndValueTypes", "CID type: %d serial %s - %s", cid->nType, cid->szIssuerSerial, cid->szIssuerName);
    if(cid && cid->nType == CERTID_TYPE_UNKNOWN) {
      ddocDebug(3, "selectCertIdAndValueTypes", "Find type for cid: %s - %s", cid->szIssuerSerial, cid->szIssuerName);
      // find corresponding CertValue
      cval1 = NULL;
      for(j = 0; pSigInfo->pCertValues && 
	    (j < ddocCertValueList_GetCertValuesCount(pSigInfo->pCertValues)); j++) {
	cval2 = ddocCertValueList_GetCertValue(pSigInfo->pCertValues, j);
	if(cval2) {
	  pCert = ddocCertValue_GetCert(cval2);
	  l1 = sizeof(buf1);
	  memset(buf1, 0, l1);
	  ReadCertSerialNumber(buf1, l1, pCert);
		//AM 19.09.08
		if(cid->szIssuerSerial){
			if(!strcmp(cid->szIssuerSerial, buf1)) {
				cval1 = cval2;
				break; // found it
			}
		}
	  // should I check also hash value?
	}
      } // for certValues
      // if found matching CertID and CertValue
      if(cval1) {
	ddocDebug(3, "selectCertIdAndValueTypes", "CertID: %s - %s -> CertValue: %s", 
		  cid->szIssuerSerial, cid->szIssuerName, cval1->szId);
	// Test1: is this an OCSP responders cert?
	if(pSigInfo->pNotary)
	  pMBuf = (DigiDocMemBuf*)ddocNotInfo_GetResponderId(pSigInfo->pNotary);
	if(pMBuf) {
	  if(pSigInfo->pNotary->nRespIdType == RESPID_NAME_TYPE) {
	    err = ddocCertGetSubjectCN(ddocCertValue_GetCert(cval1), &mbuf1);
	    memset(buf1, 0, sizeof(buf1));
	    findCN((char*)pMBuf->pMem, buf1, sizeof(buf1)); // defined in DigiDocConfig.c
	    if(!strcmp(buf1, (const char*)mbuf1.pMem)) {
	      // yes this is a responders cert
	      ddocDebug(3, "selectCertIdAndValueTypes", "cert: %s responder %s -> RESPONDER", 
			(const char*)mbuf1.pMem, buf1);
	      cid->nType = CERTID_TYPE_RESPONDERS_CERTID;
	      cval1->nType = CERTID_VALUE_RESPONDERS_CERT;
	      snprintf(buf1, sizeof(buf1), "%s-RESPONDERS_CERTINFO", pSigInfo->szId);
	      ddocCertID_SetId(cid, buf1);	  
	    }
	    ddocMemBuf_free(&mbuf1);
	  } // ByName
	  if(pSigInfo->pNotary->nRespIdType == RESPID_KEY_TYPE) {
	    err = ddocCertGetPubkeyDigest(ddocCertValue_GetCert(cval1), &mbuf1);
	    l1 = sizeof(buf1);
	    memset(buf1, 0, l1);
	    bin2hex((const byte*)mbuf1.pMem, mbuf1.nLen, buf1, &l1);
	    ddocDebug(3, "selectCertIdAndValueTypes", "cert hash: %s", buf1);
	    l1 = sizeof(buf1);
	    memset(buf1, 0, l1);
	    bin2hex((const byte*)pMBuf->pMem, pMBuf->nLen, buf1, &l1);
	    ddocDebug(3, "selectCertIdAndValueTypes", "respid: %s", buf1);
	    
	    ddocEncodeBase64(&mbuf1, &mbuf2);
	    ddocMemBuf_free(&mbuf1);
	    ddocEncodeBase64(pMBuf, &mbuf1);
	    ddocDebug(3, "selectCertIdAndValueTypes", "cert: %s responder %s", 
			(const char*)mbuf2.pMem, (const char*)mbuf1.pMem);
	    if(!strcmp((const char*)mbuf2.pMem, (const char*)mbuf1.pMem)) {
	      // yes this is a responders cert
	      ddocDebug(3, "selectCertIdAndValueTypes", "cert: %s responder %s -> RESPONDER", 
			(const char*)mbuf2.pMem, (const char*)mbuf1.pMem);
	      cid->nType = CERTID_TYPE_RESPONDERS_CERTID;
	      cval1->nType = CERTID_VALUE_RESPONDERS_CERT;
	      snprintf(buf1, sizeof(buf1), "%s-RESPONDERS_CERTINFO", pSigInfo->szId);
	      ddocCertID_SetId(cid, buf1);	  
	    }
	    ddocMemBuf_free(&mbuf1);
	    ddocMemBuf_free(&mbuf2);
	  } // ByKey
	} // if pMBuf
      }
    } // for certids
  }
  return err;
}


//--------------------------------------------------
// handles the start of a <EncapsulatedOCSPValue> element.
// Records the OCSP response data
// pctx - pointer to XML parsing work-area
// name - tag name
//--------------------------------------------------
// FIXME : error handling
void handleEndEncapsulatedOCSPValue(SigDocParse* pctx)
{
  OCSP_RESPONSE* pResp;
  NotaryInfo* pNotInfo = 0;
  SignatureInfo* pSig = 0;

  // convert the X509 cert data to
  // cert and replace the pointer value
  RETURN_VOID_IF_NULL(pctx->pSigDoc->szFormatVer);
  pNotInfo = ddocGetLastNotaryInfo(pctx->pSigDoc);
  RETURN_VOID_IF_NULL(pNotInfo); // VS: 1.76 correct the check
  pSig = ddocGetLastSignature(pctx->pSigDoc);
  RETURN_VOID_IF_NULL(pSig);
  /*pctx->errcode =*/ ddocDecodeOCSPResponsePEMData(&pResp, 
	  (const byte*)pctx->mbufElemData.pMem, (int)pctx->mbufElemData.nLen);
  // cleanup
  ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
  if(pResp) {
    // in ver 1.2 we have correct OCSP digest
    // VS 1.76 - add 1.3 version too
    if(!strcmp(pctx->pSigDoc->szFormatVer, DIGIDOC_XML_1_2_VER) ||
       !strcmp(pctx->pSigDoc->szFormatVer, DIGIDOC_XML_1_3_VER)) 
      pctx->errcode = initializeNotaryInfoWithOCSP(pctx->pSigDoc, pNotInfo, pResp, ddocSigInfo_GetOCSPRespondersCert(pSig), 0);
    else // in older versions the digest was incorrect
      /*pctx->errcode =*/ initializeNotaryInfoWithOCSP(pctx->pSigDoc, pNotInfo, pResp, ddocSigInfo_GetOCSPRespondersCert(pSig), 1);
  OCSP_RESPONSE_free(pResp);
	} /*else
    checkErrors();*/
    ddocDebug(3, "handleEndEncapsulatedOCSPValue", "RC: %d", pctx->errcode);
  if(pctx->errcode)
    return;
  // now we have OCSP value too
  // determine the correct types of certid and certvalue objects now
  /*pctx->errcode =*/ selectCertIdAndValueTypes(pSig);
}


//--------------------------------------------------
// handles the start of a <SignedProperties> element.
// Records the id and target attributes 
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleStartSignedProperties(SigDocParse* pctx, const xmlChar **atts)
{
  if(!pctx->nIgnoreDataFile)
    ddocSaxParseStartCollecting(pctx, FLAG_SIG_PART, 0);
  strncpy(pctx->ctx2, ddocSaxParseFindAttrib(atts, "Id", ""), sizeof(pctx->ctx2)-1);
  strncpy(pctx->ctx3, ddocSaxParseFindAttrib(atts, "Target", ""), sizeof(pctx->ctx3)-1);
}

//--------------------------------------------------
// handles the end of a <SignedProperties> element.
// Records the digest of this element 
// pctx - pointer to XML parsing work-area
// name - tag name
//--------------------------------------------------
void handleEndSignedProperties(SigDocParse* pctx)
{
  char* pTmp2;
  char buf[DIGEST_LEN+3], buf2[40];
  int l2;
  SignatureInfo* pSigInfo;
  DigiDocMemBuf mbuf1;

  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  if(pctx->mbufSigPartData.pMem && pSigInfo) {
    ddocDebug(5, "handleEndSignedProperties", "DATA: %d ->%s", 
	      pctx->mbufSigPartData.nLen, (char*)pctx->mbufSigPartData.pMem);
    ddocDebugWriteFile(4, "sigprop-can1.txt", &(pctx->mbufSigPartData));
    pTmp2 = canonicalizeXML((char*)pctx->mbufSigPartData.pMem, pctx->mbufSigPartData.nLen);
    
    //dumpInFile("sigprop-can2.txt", pTmp2);
    if(pTmp2) {
      mbuf1.pMem = pTmp2;
      mbuf1.nLen = strlen(pTmp2);
      ddocDebugWriteFile(4, "sigprop-can2.txt", &mbuf1);
      ddocDebug(5, "handleEndSignedProperties", "HASH over: \n---\n%s\n---\n", 
	      pTmp2);
      SHA1_Init(&(pctx->sctx));
      SHA1_Update(&(pctx->sctx), pTmp2, strlen(pTmp2));
      SHA1_Final((unsigned char*)buf,&(pctx->sctx));
      ddocSigInfo_SetSigPropRealDigest(pSigInfo, buf, DIGEST_LEN);
	  l2 = 40;
	  encode((const byte*)buf, DIGEST_LEN, (byte*)buf2, &l2);
	  ddocDebug(5, "handleEndSignedProperties", "SigProp hash: %s", buf2);
      free(pTmp2);
    }
    ddocSaxParseEndCollecting(pctx, FLAG_SIG_PART, 0);
    pctx->checkUTF8 = 0;
  }
}


//--------------------------------------------------
// handles the start of a <SignedInfo> element.
// Starts recording data for digest calculation 
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleStartSignedInfo(SigDocParse* pctx)
{
  if(!pctx->nIgnoreDataFile) {
    // mark the start of data collect mode
    pctx->errcode = ddocSaxParseStartCollecting(pctx, FLAG_SIG_PART, 0);
    pctx->checkUTF8 = 1;
  }
}

//--------------------------------------------------
// handles the end of a <SignedInfo> element.
// Records the digest of this element 
// pctx - pointer to XML parsing work-area
// name - tag name
//--------------------------------------------------
void handleEndSignedInfo(SigDocParse* pctx)
{
  char* pTmp;
  char buf[DIGEST_LEN+3];
  SignatureInfo* pSigInfo;
  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  if(pctx->mbufSigPartData.pMem && pSigInfo) {
    ddocDebug(5, "handleEndSignedInfo", "DATA: %d ->%s", 
	      pctx->mbufSigPartData.nLen, (char*)pctx->mbufSigPartData.pMem);
    pTmp = canonicalizeXML((char*)pctx->mbufSigPartData.pMem, pctx->mbufSigPartData.nLen);
    ddocDebug(5, "handleEndSignedInfo", "CANONICALIZED: %d ->%s", strlen(pTmp), (char*)pTmp);
    if(pTmp) {
      SHA1_Init(&(pctx->sctx));
      SHA1_Update(&(pctx->sctx), pTmp, strlen(pTmp));
      SHA1_Final((unsigned char*)buf,&(pctx->sctx));
      ddocSigInfo_SetSigInfoRealDigest(pSigInfo, buf, DIGEST_LEN);
      free(pTmp);
    }
    pctx->errcode = ddocSaxParseEndCollecting(pctx, FLAG_SIG_PART, 0);
    pctx->checkUTF8 = 0;
  }
}


//--------------------------------------------------
// handles the start of a <Cert> element.
// Records the id attribute
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleStartCert(SigDocParse* pctx, const xmlChar **atts)
{
  char *p = 0, buf1[50];
  SignatureInfo* pSigInfo = NULL;
  CertID *pCertID = NULL;

  // used in old formats
  p = (char*)ddocSaxParseFindAttrib(atts, "Id", NULL);
  if(p)
    strncpy(pctx->ctx2, p, sizeof(pctx->ctx2)-1);
  pSigInfo = ddocGetLastSignature(pctx->pSigDoc); 
  ddocDebug(3, "handleStartCert", "Sig: %s", (pSigInfo ? pSigInfo->szId : "NULL"));
  RETURN_VOID_IF_NULL(pSigInfo);  
  // only if we are in Notary since signers cert-id is handled by <SigningCertificate>
  if(pSigInfo->pNotary) {
    // don't know what cert-id it's going to be
    ddocCertID_new(&pCertID, CERTID_TYPE_UNKNOWN, 0, 0, 0, 0, 0);
    if(!pSigInfo->pCertIDs)
      ddocCertIDList_new(&(pSigInfo->pCertIDs));
    ddocCertIDList_addCertID(pSigInfo->pCertIDs, pCertID);
    snprintf(buf1, sizeof(buf1), "%s-UNKNOWN_CERTINFO", pSigInfo->szId);
    strncpy(pctx->ctx2, buf1, sizeof(pctx->ctx2)-1);
  }
}


//--------------------------------------------------
// handles the start of a <SigningCertificate> element.
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleStartSigningCertificate(SigDocParse* pctx)
{
  SignatureInfo* pSigInfo = NULL;
  CertID *pCertID = NULL;
  X509* x509 = NULL;
  int ret = 0;
  DigiDocMemBuf mbuf1, mbuf2;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  mbuf2.pMem = 0;
  mbuf2.nLen = 0;
  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  ddocDebug(3, "handleStartSigningCertificate", "Sig: %s", 
	    (pSigInfo ? pSigInfo->szId : "NULL"));
  RETURN_VOID_IF_NULL(pSigInfo);
  pCertID = ddocSigInfo_GetOrCreateCertIDOfType(pSigInfo, CERTID_TYPE_SIGNERS_CERTID); 
  snprintf(pctx->ctx2, sizeof(pctx->ctx2)-1, "%s-CERTINFO", pSigInfo->szId);
  x509 = ddocSigInfo_GetSignersCert(pSigInfo);
  if(x509){
    ret = ddocCertGetIssuerDN(x509, &mbuf1);
    if(ret == 0) {
      if(pCertID && mbuf1.pMem)
	ddocCertID_SetIssuerName(pCertID, (char*)mbuf1.pMem);
    }
  }
}


//--------------------------------------------------
// handles the start of a <UnsignedSignatureProperties> element.
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleStartUnsignedSignatureProperties(SigDocParse* pctx)
{
  SignatureInfo* pSigInfo = NULL;
  NotaryInfo *pNotaryInfo;
	
  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  ddocDebug(3, "handleStartUnsignedSignatureProperties", "Sig: %s", 
	    (pSigInfo ? pSigInfo->szId : "NULL"));
  RETURN_VOID_IF_NULL(pSigInfo);
  (void)NotaryInfo_new(&pNotaryInfo, pctx->pSigDoc, pSigInfo);
}


//--------------------------------------------------
// handles the start of a <CompleteCertificateRefs> element.
// Records the signature id so that we can later
// capture responders cert digest
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleStartCompleteCertificateRefs(SigDocParse* pctx)
{
  SignatureInfo* pSigInfo = 0;

  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  ddocDebug(3, "handleStartCompleteCertificateRefs", "Sig: %s", (pSigInfo ? pSigInfo->szId : "NULL"));
  RETURN_VOID_IF_NULL(pSigInfo);
  snprintf(pctx->ctx2, sizeof(pctx->ctx2)-1, "%s-RESPONDER_CERTINFO", pSigInfo->szId);
}


//--------------------------------------------------
// handles the start of a <OCSPIdentifier> element.
// Records the id attribute
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleStartOCSPIdentifier(SigDocParse* pctx, const xmlChar **atts)
{
  strncpy(pctx->ctx2, ddocSaxParseFindAttrib(atts, "URI", ""), sizeof(pctx->ctx2)-1);
}

//--------------------------------------------------
// handles the start of a <X509Certificate> element.
// Records the digest method
// pctx - pointer to XML parsing work-area
// name - tag name
//--------------------------------------------------
void handleEndX509Certificate(SigDocParse* pctx)
{
  X509* x509 = 0;
  SignatureInfo* pSigInfo = 0;

  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  // convert the X509 cert data to
  // cert and replace the pointer value
  if(pSigInfo && pctx->mbufElemData.pMem) {
    pctx->errcode = ddocDecodeX509PEMData(&x509, 
	 (const char*)pctx->mbufElemData.pMem, (int)pctx->mbufElemData.nLen);
    if(x509)
      ddocSigInfo_SetSignersCert(pSigInfo, x509);
    // cleanup
    pctx->errcode = ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
  } 
}

//--------------------------------------------------
// handles the start of a <EncapsulatedX509Certificate> element.
// Records the signature id so that we can later
// capture responders cert digest
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleStartEncapsulatedX509Certificate(SigDocParse* pctx, const xmlChar **atts)
{
  SignatureInfo* pSigInfo = 0;
  const char *p1 = 0;
  CertValue *pCertValue;

  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  p1 = ddocSaxParseFindAttrib(atts, "Id", NULL);

  ddocDebug(3, "handleStartEncapsulatedX509Certificate", "Sig: %s, type: %s", 
	    (pSigInfo ? pSigInfo->szId : "NULL"), (p1 ? p1 : "NULL"));
  RETURN_VOID_IF_NULL(pSigInfo);
  if(p1) {
    if(strstr(p1, "TSA_CERT"))
      pCertValue = ddocSigInfo_GetOrCreateCertValueOfType(pSigInfo, CERTID_VALUE_TSA_CERT);
    if(strstr(p1, "RESPONDER_CERT"))
      pCertValue = ddocSigInfo_GetOrCreateCertValueOfType(pSigInfo, CERTID_VALUE_RESPONDERS_CERT);
  }
  snprintf(pctx->ctx2, sizeof(pctx->ctx2)-1, "%s-RESPONDER_CERTINFO", pSigInfo->szId);
  pctx->errcode = ddocSaxParseStartCollecting(pctx, FLAG_XML_ELEM, 1);
}

//--------------------------------------------------
// handles the end of a <EncapsulatedX509Certificate> element.
// Records the digest method
// pctx - pointer to XML parsing work-area
// name - tag name
//--------------------------------------------------
void handleEndEncapsulatedX509Certificate(SigDocParse* pctx)
{
  X509* x509 = 0;
  NotaryInfo* pNotInf = 0;
  SignatureInfo* pSigInfo = 0;
  CertValue* pCertValue = 0;

  // convert the X509 cert data to cert<
  pNotInf = ddocGetLastNotaryInfo(pctx->pSigDoc);
  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  pctx->errcode = ddocDecodeX509PEMData(&x509, 
       (const char*)pctx->mbufElemData.pMem, (int)pctx->mbufElemData.nLen);
  if(x509 && pSigInfo) {
    pCertValue = ddocSigInfo_GetLastCertValue(pSigInfo);
    if(pCertValue)
      ddocCertValue_SetCert(pCertValue, x509);
    else
      X509_free(x509); // not found, free it
  }
  // cleanup
  ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
}

char* PATH_DIGEST_VALUE_SIGNED_INFO = "/SignedDoc/Signature/SignedInfo/Reference";
char* PATH_DIGEST_VALUE_SIG_CERT = "/SignedDoc/Signature/Object/QualifyingProperties/SignedProperties/SignedSignatureProperties/SigningCertificate/Cert/CertDigest";
char* PATH_DIGEST_VALUE_CERT_REF = "/SignedDoc/Signature/Object/QualifyingProperties/UnsignedProperties/UnsignedSignatureProperties/CompleteCertificateRefs/CertRefs/Cert/CertDigest";
char* PATH_DIGEST_VALUE_CERT_REF_1_0 = "/SignedDoc/Signature/Object/QualifyingProperties/UnsignedProperties/UnsignedSignatureProperties/CompleteCertificateRefs/Cert/CertDigest";
char* PATH_DIGEST_VALUE_RVOK_REFS = "/SignedDoc/Signature/Object/QualifyingProperties/UnsignedProperties/UnsignedSignatureProperties/CompleteRevocationRefs/OCSPRefs/OCSPRef/DigestAlgAndValue";

int checkValidDigestValPath(SigDocParse* pctx, SignatureInfo* pSigInfo)
{
    if(pctx && pctx->mbufTags.pMem) {
        if(!strcmp((const char*)pctx->mbufTags.pMem, PATH_DIGEST_VALUE_CERT_REF_1_0)) {
            pSigInfo->nErr1 = ERR_VER_1_0;
            ddocDebug(1, "VER 1.0", "Ver 1.0 signature! Found element DigestValue in path: %s format: %s ver: %s", (const char*)pctx->mbufTags.pMem, pctx->pSigDoc->szFormat, pctx->pSigDoc->szFormatVer);
            if(strcmp(pctx->pSigDoc->szFormat, SK_XML_1_NAME) &&
               (strcmp(pctx->pSigDoc->szFormat, DIGIDOC_XML_1_1_NAME) ||
                !strcmp(pctx->pSigDoc->szFormatVer, DIGIDOC_XML_1_3_VER))) {
                       ddocDebug(1, "checkValidDigestValPath10-12", "Invalid XML! Found element DigestValue in path: %s format: %s ver: %s", (const char*)pctx->mbufTags.pMem, pctx->pSigDoc->szFormat, pctx->pSigDoc->szFormatVer); 
                       SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
                       if(pSigInfo && !pSigInfo->nErr1)
                           pSigInfo->nErr1 = ERR_DIGIDOC_PARSE;
                       return ERR_DIGIDOC_PARSE;
               }
               
        } else {
          if(strcmp((const char*)pctx->mbufTags.pMem, PATH_DIGEST_VALUE_SIGNED_INFO) &&
           strcmp((const char*)pctx->mbufTags.pMem, PATH_DIGEST_VALUE_SIG_CERT) &&
           strcmp((const char*)pctx->mbufTags.pMem, PATH_DIGEST_VALUE_CERT_REF) &&
           strcmp((const char*)pctx->mbufTags.pMem, PATH_DIGEST_VALUE_RVOK_REFS)) {
            ddocDebug(1, "checkValidDigestValPath", "Invalid XML! Found element DigestValue in path: %s format: %s ver: %s", (const char*)pctx->mbufTags.pMem, pctx->pSigDoc->szFormat, pctx->pSigDoc->szFormatVer); 
            SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
            if(pSigInfo && !pSigInfo->nErr1)
                pSigInfo->nErr1 = ERR_DIGIDOC_PARSE;
            return ERR_DIGIDOC_PARSE;
          }
        }
    }
    return 0;
}

char* PATH_CLAIMED_ROLE = "/SignedDoc/Signature/Object/QualifyingProperties/SignedProperties/SignedSignatureProperties/SignerRole/ClaimedRoles";

int checkValidClaimedRolePath(SigDocParse* pctx, SignatureInfo* pSigInfo)
{
    if(pctx && pctx->mbufTags.pMem) {
        if(strcmp((const char*)pctx->mbufTags.pMem, PATH_CLAIMED_ROLE)) {
            ddocDebug(1, "checkValidClaimedRolePath", "Invalid XML! Found element ClaimedRole in path: %s", (const char*)pctx->mbufTags.pMem); 
            SET_LAST_ERROR(ERR_DIGIDOC_PARSE);
            if(pSigInfo && !pSigInfo->nErr1)
                pSigInfo->nErr1 = ERR_DIGIDOC_PARSE;
            return ERR_DIGIDOC_PARSE;
        }
    }
    return 0;
}

//--------------------------------------------------
// handles the content of a <DigestValue> element.
// Decodes and reads in digest value
// pctx - pointer to XML parsing work-area
// name - tag name
// atts - attributes
//--------------------------------------------------
void handleEndDigestValue(SigDocParse* pctx) 
{
  char id[100], type[100];
  SignatureInfo* pSigInfo = NULL;
  NotaryInfo* pNotInfo = NULL;
  DocInfo* pDocInfo = NULL;
  CertID* pCertID = NULL;
  DigiDocMemBuf mbuf1;
    
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  ddocDebug(4, "handleDigestValue", "DF: %s value: %s len: %d", 
	  pctx->ctx2, (char*)pctx->mbufElemData.pMem, pctx->mbufElemData.nLen);
  // decode digest value
  ddocDecodeBase64(&(pctx->mbufElemData), &mbuf1);
  ddocDebug(4, "handleDigestValue", "decoded len: %ld", mbuf1.nLen);
  // cleanup
  ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
  // find current signature
  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  RETURN_VOID_IF_NULL(pSigInfo);
  if(checkValidDigestValPath(pctx, pSigInfo))
    return;

  decodeURI(pctx->ctx2, id, sizeof(id), type, sizeof(type));
  ddocDebug(4, "handleDigestValue", "ctx2: %s id: %s type: %s", pctx->ctx2, id, type);
  if(id[0] == 'D' || !strcmp(id, "null")) {
    RETURN_VOID_IF_NULL(pSigInfo);
    pDocInfo = getDocInfoWithId(pSigInfo, id);
    if(!strcmp(type, "MimeType") || 
       !strcmp(type, "MIME")) {
      if(pDocInfo == NULL) {
	addDocInfo(&pDocInfo, pSigInfo, id, pctx->ctx3,
		   NULL, 0, (const byte*)mbuf1.pMem, mbuf1.nLen);
      } else
	setDocInfoMimeDigest(pDocInfo, (const byte*)mbuf1.pMem, mbuf1.nLen);
    }
    else {
      if(pDocInfo == NULL) {
	addDocInfo(&pDocInfo, pSigInfo, id, pctx->ctx3,
		   (const byte*)mbuf1.pMem, mbuf1.nLen, NULL, 0); // MEMLEAK: ???
      } else
	setDocInfoDigest(pDocInfo, (const byte*)mbuf1.pMem, mbuf1.nLen, pctx->ctx3);
    }
  }
  if(id[0] == 'S') {
    if(!strcmp(type, "SignedProperties")) {
      RETURN_VOID_IF_NULL(pSigInfo);
      ddocSigInfo_SetSigPropDigest(pSigInfo, (const char*)mbuf1.pMem, mbuf1.nLen);
    }
    if(!strcmp(type, "CERTINFO")) {
      RETURN_VOID_IF_NULL(pSigInfo);
      pCertID = ddocSigInfo_GetOrCreateCertIDOfType(pSigInfo, CERTID_TYPE_SIGNERS_CERTID);
      RETURN_VOID_IF_NULL(pCertID);
      ddocCertID_SetDigestValue(pCertID, (const char*)mbuf1.pMem, mbuf1.nLen);
    }
    if(!strcmp(type, "UNKNOWN_CERTINFO")) {
      pCertID = ddocCertIDList_GetLastCertID(pSigInfo->pCertIDs);
      RETURN_VOID_IF_NULL(pCertID);
      ddocCertID_SetDigestValue(pCertID, (const char*)mbuf1.pMem, mbuf1.nLen);
    }    
  }
  if(id[0] == 'N') {
    pNotInfo = getNotaryWithId(pctx->pSigDoc, id);
    SET_LAST_ERROR_RETURN_VOID_IF_NOT(pNotInfo, ERR_OCSP_WRONG_RESPID); 
    ddocNotInfo_SetOcspDigest(pNotInfo, (const char*)mbuf1.pMem, mbuf1.nLen);
  }
  ddocMemBuf_free(&mbuf1);
}


//--------------------------------------------------
// handles the content of a <SigningTime> element.
// Reads in timestamp data
// pctx - pointer to XML parsing work-area
// value - character values read from file
// len - length of chars ???
//--------------------------------------------------
void handleEndSigningTime(SigDocParse* pctx) 
{
  SignatureInfo *pSigInfo;

  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  RETURN_VOID_IF_NULL(pSigInfo);
  if(pctx->mbufElemData.pMem) {
    setString(&(pSigInfo->szTimeStamp), (char*)pctx->mbufElemData.pMem, -1);
    ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
  }	
}

#define ADR_ENTRY_CITY   1
#define ADR_ENTRY_STATE  2
#define ADR_ENTRY_COUNTRY 3
#define ADR_ENTRY_ZIP    4

//--------------------------------------------------
// Handles address entry
// pctx - pointer to XML parsing work-area
// 
// value - character values read from file
// len - length of chars ???
//--------------------------------------------------
void handleAdrEntry(SigDocParse* pctx, int nAdr)
{
  SignatureInfo* pSigInfo;
	
  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  if(pSigInfo && pctx->mbufElemData.pMem) {
    switch(nAdr) {
    case ADR_ENTRY_CITY: 
      setString(&(pSigInfo->sigProdPlace.szCity), (const char*)pctx->mbufElemData.pMem, -1); 
      break;
    case ADR_ENTRY_STATE: 
      setString(&(pSigInfo->sigProdPlace.szStateOrProvince), (const char*)pctx->mbufElemData.pMem, -1); 
      break;
    case ADR_ENTRY_COUNTRY: 
      setString(&(pSigInfo->sigProdPlace.szCountryName), (const char*)pctx->mbufElemData.pMem, -1); 
      break;
    case ADR_ENTRY_ZIP: 
      setString(&(pSigInfo->sigProdPlace.szPostalCode), (const char*)pctx->mbufElemData.pMem, -1); 
      break;
    }
  }
  ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
}

//--------------------------------------------------
// handles the start of a <ClaimedRole> element.
// Stores the collected claimed role
// pctx - pointer to XML parsing work-area
// name - tag name
//--------------------------------------------------
void handleEndClaimedRole(SigDocParse* pctx)
{
  SignatureInfo* pSigInfo;

  if(pctx->mbufElemData.pMem) {
    pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
    if(checkValidClaimedRolePath(pctx, pSigInfo)) return;
    RETURN_VOID_IF_NULL(pSigInfo);
    addSignerRole(pSigInfo, 0, (const char*)pctx->mbufElemData.pMem, -1, 0);
    ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
    pctx->bNoXMLElemData = 0;
  }
}

//--------------------------------------------------
// handles the start of a <CertifiedRole> element.
// Stores the collected certified role
// pctx - pointer to XML parsing work-area
// name - tag name
//--------------------------------------------------
void handleEndCertifiedRole(SigDocParse* pctx)
{
  SignatureInfo* pSigInfo;
	
  if(pctx->mbufElemData.pMem) {
    pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
    RETURN_VOID_IF_NULL(pSigInfo);
    addSignerRole(pSigInfo, 1, (const char*)pctx->mbufElemData.pMem, -1, 0);
    ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
  }
}

//--------------------------------------------------
// handles the end of a <IssuerSerial> element.
// Reads in cert isseur serial number
// pctx - pointer to XML parsing work-area
// value - character values read from file
// len - length of chars ???
//--------------------------------------------------
void handleEndIssuerSerial(SigDocParse* pctx) 
{
  SignatureInfo* pSigInfo;
  char  id[20], type[20];
  CertID* pCertID;

  decodeURI(pctx->ctx2, id, sizeof(id), type, sizeof(type));
  if(!strcmp(type, "CERTINFO")) {
    pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
    pCertID = ddocSigInfo_GetCertIDOfType(pSigInfo, CERTID_TYPE_SIGNERS_CERTID);
    if(pCertID && pctx->mbufElemData.pMem)
      ddocCertID_SetIssuerSerial(pCertID, (char*)pctx->mbufElemData.pMem);
  }
  if(!strcmp(type, "UNKNOWN_CERTINFO")) {
    pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
    pCertID = ddocCertIDList_GetLastCertID(pSigInfo->pCertIDs);
    if(pCertID && pctx->mbufElemData.pMem)
      ddocCertID_SetIssuerSerial(pCertID, (char*)pctx->mbufElemData.pMem);
  }
  ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
}

//--------------------------------------------------
// handles the end of a <IssuerName> element.
// Reads in cert isseur serial number
// pctx - pointer to XML parsing work-area
// value - character values read from file
// len - length of chars ???
//--------------------------------------------------
void handleEndIssuerName(SigDocParse* pctx) 
{
  SignatureInfo* pSigInfo;
  char  id[20], type[20];
  CertID* pCertID;

  decodeURI(pctx->ctx2, id, sizeof(id), type, sizeof(type));
  if(!strcmp(type, "CERTINFO")) {
    pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
    pCertID = ddocSigInfo_GetCertIDOfType(pSigInfo, CERTID_TYPE_SIGNERS_CERTID);
    ddocDebug(3, "handleEndIssuerName", "Issuer name: %s", pctx->mbufElemData.pMem);
    if(pCertID && pctx->mbufElemData.pMem)
      ddocCertID_SetIssuerName(pCertID, (char*)pctx->mbufElemData.pMem);
  }
  if(!strcmp(type, "UNKNOWN_CERTINFO")) {
    pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
    pCertID = ddocCertIDList_GetLastCertID(pSigInfo->pCertIDs);
    if(pCertID && pctx->mbufElemData.pMem)
      ddocCertID_SetIssuerName(pCertID, (char*)pctx->mbufElemData.pMem);
  }
  ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
}

//--------------------------------------------------
// tests if this is a textform responder id
// we base the test on existence of certain
// key elements in a DN.
// return 1 if it is text form
//--------------------------------------------------
int isTextResponderId(const char* szRespId)
{
  return strstr(szRespId, "CN=") && strstr(szRespId, "C=");
}

//--------------------------------------------------
// handles the end of a </ResponderId> or <ByName> element.
// Reads in ResponderId data
// pctx - pointer to XML parsing work-area
// value - character values read from file
// len - length of chars ???
//--------------------------------------------------
void handleEndResponderID(SigDocParse* pctx) 
{
  NotaryInfo* pNotInf;
  DigiDocMemBuf mbuf1;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  RETURN_VOID_IF_NULL(pctx->pSigDoc->szFormatVer);
  pNotInf = ddocGetLastNotaryInfo(pctx->pSigDoc);
  ddocDebug(3, "handleEndResponderId", "notary: %s id: %s, len: %d", 
	  (pNotInf ? pNotInf->szId : "NULL"), (const char*)pctx->mbufElemData.pMem, pctx->mbufElemData.nLen);
  if(pNotInf && pctx->mbufElemData.pMem) {
      // in earlier format we din't have <ByName> and <ByKey>
      // so we must detect if this is text or base64
      if(isTextResponderId((const char*)pctx->mbufElemData.pMem)) {
	pctx->errcode = ddocNotInfo_SetResponderId(pNotInf, (const char*)pctx->mbufElemData.pMem, pctx->mbufElemData.nLen);
	pNotInf->nRespIdType = RESPID_NAME_TYPE;
      } else {
	ddocDecodeBase64Data(pctx->mbufElemData.pMem, pctx->mbufElemData.nLen, &mbuf1);
	pctx->errcode = ddocNotInfo_SetResponderId(pNotInf, (const char*)mbuf1.pMem, mbuf1.nLen);
	pNotInf->nRespIdType = RESPID_KEY_TYPE;
      }
    pctx->errcode = ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
  }	
}

//--------------------------------------------------
// handles the end of a </ProducedAt>
// Reads in OCSP ProducedAt timestamp
// pctx - pointer to XML parsing work-area
// value - character values read from file
// len - length of chars ???
//--------------------------------------------------
void handleEndProducedAt(SigDocParse* pctx) 
{
  NotaryInfo* pNotInf = NULL;
  
  RETURN_VOID_IF_NULL(pctx->pSigDoc);
  pNotInf = ddocGetLastNotaryInfo(pctx->pSigDoc);
  RETURN_VOID_IF_NULL(pNotInf);
  ddocDebug(3, "handleEndProducedAt", "notary: %s produced at: %s len: %d", 
	  (pNotInf ? pNotInf->szId : "NULL"), (const char*)pctx->mbufElemData.pMem, pctx->mbufElemData.nLen);
  if(pNotInf && pctx->mbufElemData.pMem) {
    setString(&(pNotInf->szProducedAt), (const char*)pctx->mbufElemData.pMem, -1 /* pctx->mbufElemData.nLen*/);
    pctx->errcode = ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
  }	
}

//--------------------------------------------------
// handles the end of a <ByKey> element.
// Reads in ResponderId data
// pctx - pointer to XML parsing work-area
// value - character values read from file
// len - length of chars ???
//--------------------------------------------------
void handleEndByKey(SigDocParse* pctx) 
{
  NotaryInfo* pNotInf;
  DigiDocMemBuf mbuf1;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  pNotInf = ddocGetLastNotaryInfo(pctx->pSigDoc);
  ddocDebug(3, "handleEndByKey", "notary: %s id: %s, len: %d", 
	  (pNotInf ? pNotInf->szId : "NULL"), (const char*)pctx->mbufElemData.pMem, pctx->mbufElemData.nLen);
  if(pNotInf && pctx->mbufElemData.pMem) {
    ddocDecodeBase64Data(pctx->mbufElemData.pMem, pctx->mbufElemData.nLen, &mbuf1);
    pctx->errcode = ddocNotInfo_SetResponderId(pNotInf, (const char*)mbuf1.pMem, mbuf1.nLen);
    pctx->errcode = ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
    pNotInf->nRespIdType = RESPID_KEY_TYPE;
  }	
  ddocMemBuf_free(&mbuf1);
}

//--------------------------------------------------
// handles the end of a <SignatureValue> element.<
// Decodes the base64 data in a buffer and assigns
// to signature value
// pctx - pointer to XML parsing work-area
// name - tag name
//--------------------------------------------------
void handleEndSignatureValue(SigDocParse* pctx)
{
  SignatureInfo* pSigInfo;
  DigiDocMemBuf mbuf1, mbuf2;
  char *p1 = 0, *p2 = 0;
  int l1;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  mbuf2.pMem = 0;
  mbuf2.nLen = 0;
  RETURN_VOID_IF_NULL(pctx->pSigDoc->szFormatVer);
  pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
  // decode signature value
  p1 = strchr((const char*)pctx->mbufElemData.pMem, '>');
  if(p1)
  p2 = strchr((const char*)p1, '<');
  if(p1 && p2) {
	  p1++;
      *p2 = 0;
      l1 = strlen(p1) + 10;
	  ddocMemSetLength(&mbuf1, l1);
      decode((const byte*)p1, strlen(p1), (byte*)mbuf1.pMem, &l1);
	  mbuf1.nLen = l1;
      if(pSigInfo && mbuf1.nLen > 0)
        ddocSigInfo_SetSignatureValue(pSigInfo, (char*)mbuf1.pMem, mbuf1.nLen);
	  ddocMemBuf_free(&mbuf1);
  }
  // cleanup
  ddocSaxParseEndCollecting(pctx, FLAG_TS_INP, 0);	  
}

//--------------------------------------------------
// Collects elements start-tag
// pctx - pointer to XML parsing work-area
// name - xml element tag name
// atts - xml atributes
// pcFlag - pointer to flag governing collection of this element
// pMBuf - DigiDocMemBuf to collect it in
//--------------------------------------------------
int ddocSaxParseCollectStartTag(SigDocParse* pctx, const xmlChar *name, const xmlChar **atts,
				char *pcFlag, DigiDocMemBuf* pMBuf)
{
  int i, addXmlns = 0, addXmlns3 = 0;
  char *p = 0;
  // if we are in collect data mode then
  // record this tag data
  if(*pcFlag) {
    // don't use this attribute for 1.0 format
    if(pctx->pSigDoc->szFormatVer && (!strcmp(pctx->pSigDoc->szFormatVer, DIGIDOC_XML_1_1_VER) ||
	!strcmp(pctx->pSigDoc->szFormatVer, DIGIDOC_XML_1_2_VER)) && 
       (!strcmp((const char*)name, "SignedProperties") ||
	!strcmp((const char*)name, "SignedInfo"))) // must have this attribute
      addXmlns = 1;
    else
      addXmlns = 0;		// don't need this atribute
      ddocDebug(3, "ddocSaxParseCollectStartTag", "Format: %s name: %s", pctx->pSigDoc->szFormatVer, (const char*)name);
    if(pctx->pSigDoc->szFormatVer && !strcmp((const char*)name, "DataFile")) {
      if(!strcmp(pctx->pSigDoc->szFormatVer, DIGIDOC_XML_1_3_VER)) // must have this attribute
        addXmlns3 = 1;
    }
    pctx->errcode = ddocMemAppendData(pMBuf, "<", -1);
    if(!pctx->errcode)
      pctx->errcode = ddocMemAppendData(pMBuf, (const char*)name, -1);
    for (i = 0; !pctx->errcode && (atts != NULL) && (atts[i] != NULL); i += 2) {
      pctx->errcode = ddocMemAppendData(pMBuf, " ", -1);
      if(!pctx->errcode)
	    pctx->errcode = ddocMemAppendData(pMBuf, (const char*)atts[i], -1);
      if(!pctx->errcode)
	    pctx->errcode = ddocMemAppendData(pMBuf, "=\"", -1);
      if(!pctx->errcode) {
	    escapeXMLSymbols((const char*)atts[i+1], -1, &p);
        if(p) {
	      pctx->errcode = ddocMemAppendData(pMBuf, p, -1);
		  free(p);
	    }
	  }
      if(!pctx->errcode)
	    pctx->errcode = ddocMemAppendData(pMBuf, "\"", -1);
      if(!strcmp((const char*)atts[i], "xmlns")) {
	    addXmlns = 0; // already has this atribute
        addXmlns3 = 0;
	  }
	} // for
    if(addXmlns && !pctx->errcode)
      pctx->errcode = ddocMemAppendData(pMBuf, " xmlns=\"http://www.w3.org/2000/09/xmldsig#\"", -1);
    if(addXmlns3 && !pctx->errcode)
      pctx->errcode = ddocMemAppendData(pMBuf, " xmlns=\"http://www.sk.ee/DigiDoc/v1.3.0#\"", -1);
    if(!pctx->errcode)
	pctx->errcode = ddocMemAppendData(pMBuf, ">", -1);
    ddocDebug(3, "ddocSaxParseCollectStartTag", "Element tag collected: %d - %s", pMBuf->nLen, (char*)pMBuf->pMem);
  }
  return pctx->errcode;
}

//--------------------------------------------------
// Collects elements start-tag. Used for ddoc 1.3 alternate DataFile hash calc
// pctx - pointer to XML parsing work-area
// name - xml element tag name
// atts - xml atributes
// pMBuf - DigiDocMemBuf to collect it in
//--------------------------------------------------
int ddocSaxParseCollectDf3AltStartTag(SigDocParse* pctx, const xmlChar *name, const xmlChar **atts, DigiDocMemBuf* pMBuf)
{
    int i;
    char *p = 0;
    // if we are in collect data mode then
    // record this tag data
    pctx->errcode = ddocMemAppendData(pMBuf, "<", -1);
    if(!pctx->errcode)
        pctx->errcode = ddocMemAppendData(pMBuf, (const char*)name, -1);
    for (i = 0; !pctx->errcode && (atts != NULL) && (atts[i] != NULL); i += 2) {
        pctx->errcode = ddocMemAppendData(pMBuf, " ", -1);
        if(!pctx->errcode)
            pctx->errcode = ddocMemAppendData(pMBuf, (const char*)atts[i], -1);
        if(!pctx->errcode)
            pctx->errcode = ddocMemAppendData(pMBuf, "=\"", -1);
        if(!pctx->errcode) {
            escapeXMLSymbols((const char*)atts[i+1], -1, &p);
            if(p) {
                pctx->errcode = ddocMemAppendData(pMBuf, p, -1);
                free(p);
            }
        }
        if(!pctx->errcode)
            pctx->errcode = ddocMemAppendData(pMBuf, "\"", -1);
    } // for
    if(!pctx->errcode)
        pctx->errcode = ddocMemAppendData(pMBuf, ">", -1);
    ddocDebug(3, "ddocSaxParseCollectDf3AltStartTag", "Element tag collected: %d - %s", pMBuf->nLen, (char*)pMBuf->pMem);
    return pctx->errcode;
}


/**
 * startElementHandler:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when an opening tag has been processed.
 */
static void startElementHandler(void *ctx, const xmlChar *name, const xmlChar **atts)
{
  SigDocParse* pctx = (SigDocParse*)ctx;
  char *pTmp1 = NULL;
  const char *sXmlns;
  DigiDocMemBuf mbuf1, mbuf2;
  SignatureInfo* pSig;
  XmlElemInfo* eEl = NULL;

  mbuf2.pMem = 0;
  mbuf2.nLen = 0;
  strncpy(pctx->tag, (const char*)name, sizeof(pctx->tag));	
  XmlElemInfo_new(&eEl, NULL, (const char*)name);
  if(!pctx->eRoot)
    pctx->eRoot = eEl;
  if(pctx->eCurr) {
    XmlElemInfo_addChild(pctx->eCurr, eEl);
  }
  pctx->eCurr = eEl;
  pctx->errcode = validateElementPath(pctx->eCurr);
  // do nothing if error has ocurred
  if(pctx->errcode) return;
  ddocMemPush(&(pctx->mbufTags), (const char*)name);
  ddocDebug(4, "startElementHandler", "<%s> path: %s", (const char*)name, (const char*)pctx->mbufTags.pMem);
    
  //printf("<%s>\n", (const char*)name);
  if(!strcmp((const char*)name, "DataFile")) {
    pctx->bCollectDFData++; // increment bypass mode
    if(pctx->bCollectDFData == 1) // only the first time
      handleStartDataFile(pctx, name, atts);
    // collect wrong/alternate digest for ddoc 1.3
    ddocSaxParseCollectDf3AltStartTag(pctx, name, atts, &mbuf2);
  }
  if(!strcmp((const char*)name, "SignedProperties")) 
    handleStartSignedProperties(pctx, atts);
  if(!strcmp((const char*)name, "SignedInfo")) 
    handleStartSignedInfo(pctx);
  // if we are not in a <DataFile> and we encounter
  // the <Signature> tag then start collecting original content
  if(!pctx->nIgnoreDataFile && 
     (!strcmp((const char*)name, "Signature") || pctx->bCollectSigData)) { 
    if(!strcmp((const char*)name, "Signature"))
      pctx->errcode = ddocSaxParseStartCollecting(pctx, FLAG_SIGNATURE, 0);
    // collect general <Signature> data<
    ddocSaxParseCollectStartTag(pctx, name, atts, &(pctx->bCollectSigData), &(pctx->mbufSigData));
  }
  // we need the tags here because of hash value calculation
  // collect general tag data
  if(!strcmp((const char*)name, "SignatureValue"))
       pctx->errcode = ddocSaxParseStartCollecting(pctx, FLAG_XML_ELEM, 0);
  ddocSaxParseCollectStartTag(pctx, name, atts, &(pctx->bCollectElemData), &(pctx->mbufElemData));
  // use base64 DataFile parsing optimization
  // only possible if: a) not 1.0 format b) base64 content c) check config settings
#ifdef WITH_BASE64_HASHING_HACK
  if((pctx->bCollectDFData == 1) && pctx->pSigDoc->szFormatVer && pctx->pSigDoc->szFormat &&
	  (strcmp(pctx->pSigDoc->szFormatVer, SK_XML_1_VER) && strcmp(pctx->pSigDoc->szFormat, SK_XML_1_NAME))&& 
	 !strcmp(pctx->ctx3, CONTENT_EMBEDDED_BASE64) ) {
	// append end tag
	ddocMemAppendData(&(pctx->mbufElemData), "</DataFile>", -1);
	pTmp1 = canonicalizeXML((char*)pctx->mbufElemData.pMem, pctx->mbufElemData.nLen);
	if(pTmp1) {
	  // remove end tag again after canonicalization
	  pTmp1[strlen(pTmp1) - 11] = 0;
	  ddocDebug(4, "startElementHandler", "Initial sha1 update: \'%s\'", pTmp1);
	  mbuf1.pMem = pTmp1;
	  mbuf1.nLen = strlen(pTmp1);
	  ddocDebugWriteFile(4, "df-data.txt", &mbuf1);
	  SHA1_Update(&(pctx->sctx), pTmp1, strlen(pTmp1));
	  free(pTmp1);
      pTmp1 = NULL;
	}
    // handle alternate digest
    ddocMemAppendData(&mbuf2, "</DataFile>", -1);
    pTmp1 = canonicalizeXML((char*)mbuf2.pMem, mbuf2.nLen);
    if(pTmp1) {
      // remove end tag again after canonicalization
      pTmp1[strlen(pTmp1) - 11] = 0;
      ddocDebug(4, "startElementHandler", "Initial alt sha1 update: \'%s\'", pTmp1);
      SHA1_Update(&(pctx->sctx2), pTmp1, strlen(pTmp1));
      free(pTmp1);
    }
	ddocMemBuf_free(&(pctx->mbufElemData));
  }
#endif
  if(mbuf2.pMem)
      ddocMemBuf_free(&mbuf2);
  // collect general <SignedProperties> data
  ddocSaxParseCollectStartTag(pctx, name, atts, &(pctx->bCollectSigPartData), &(pctx->mbufSigPartData));
  // check other start-tag-actions
  if(!pctx->nIgnoreDataFile) {
    if(!strcmp((const char*)name, "SignedDoc")) 
      handleStartSignedDoc(pctx, name, atts);
    if(!strcmp((const char*)name, "Signature")) 
      handleStartSignature(pctx, atts);
    if(!strcmp((const char*)name, "Reference")) 
      handleStartReference(pctx, atts);
    if(!strcmp((const char*)name, "SignatureMethod")) 
      handleStartSignatureMethod(pctx, atts);
    if(!strcmp((const char*)name, "DigestMethod")) 
      handleStartDigestMethod(pctx, atts);
    if(!strcmp((const char*)name, "Cert")) 
      handleStartCert(pctx, atts);
    /*if(!strcmp((const char*)name, "ResponderID"))   // TODO: do we need it ???
      handleStartResponderId(pctx, name, atts);*/
    /*    if(!strcmp((const char*)name, "Certificate"))  // TODO: do we need it ???
	  handleStartCertificate(pctx, name, atts);*/
    if(!strcmp((const char*)name, "UnsignedSignatureProperties")) 
      handleStartUnsignedSignatureProperties(pctx);
    if(!strcmp((const char*)name, "OCSPIdentifier")) 
      handleStartOCSPIdentifier(pctx, atts);
    if(!strcmp((const char*)name, "SigningCertificate")) 
      handleStartSigningCertificate(pctx);
    if(!strcmp((const char*)name, "CompleteCertificateRefs")) 
      handleStartCompleteCertificateRefs(pctx);
    if(!strcmp((const char*)name, "EncapsulatedX509Certificate")) 
      handleStartEncapsulatedX509Certificate(pctx, atts);
    // start collecting but release old if exists
    if(!strcmp((const char*)name, "X509SerialNumber") ||
       !strcmp((const char*)name, "X509IssuerName")) {
      // check xmlns
      sXmlns = ddocSaxParseFindAttrib(atts, "xmlns", NULL);
      if(sXmlns == NULL || strcmp(sXmlns, NAMESPACE_XML_DSIG)) {
          ddocDebug(1, "startElementHandler", "Invalid namespace %s for element: %s", sXmlns, name);
          SET_LAST_ERROR(ERR_ISSUER_XMLNS);
          //pctx->errcode = ERR_ISSUER_XMLNS; 
          pSig = ddocGetLastSignature(pctx->pSigDoc);
          if(pSig && !pSig->nErr1)
              pSig->nErr1 = ERR_ISSUER_XMLNS; // store this erro code by signature because it can't be found after parsing
      }
      ddocSaxParseEndCollecting(pctx, FLAG_XML_ELEM, 0);
      pctx->errcode = ddocSaxParseStartCollecting(pctx, FLAG_XML_ELEM, 1);
      
    }
      // start collecting but release old if exists
    if((!strcmp((const char*)name, "Transform") ||
       !strcmp((const char*)name, "Transforms")) &&
       pctx->pSigDoc->szFormat && !strcmp(pctx->pSigDoc->szFormat, DIGIDOC_XML_1_1_NAME)) {
        SET_LAST_ERROR(ERR_TRANSFORM_UNSUPPORTED);
        pSig = ddocGetLastSignature(pctx->pSigDoc);
        if(pSig && !pSig->nErr1)
            pSig->nErr1 = ERR_TRANSFORM_UNSUPPORTED; // store this erro code
    }
    // start collecting data of these elements
    if(!strcmp((const char*)name, "CertifiedRole") ||
       !strcmp((const char*)name, "ClaimedRole") ||
       !strcmp((const char*)name, "DigestValue") ||
       !strcmp((const char*)name, "EncapsulatedOCSPValue") ||
       !strcmp((const char*)name, "EncapsulatedTimeStamp") ||
       !strcmp((const char*)name, "X509Certificate") ||
       !strcmp((const char*)name, "SigningTime") ||
       !strcmp((const char*)name, "ResponderID") ||
       !strcmp((const char*)name, "ProducedAt") ||
       !strcmp((const char*)name, "ByName") ||
       !strcmp((const char*)name, "ByKey") ||
       !strcmp((const char*)name, "City") ||
       !strcmp((const char*)name, "StateOrProvince") ||
       !strcmp((const char*)name, "PostalCode") ||
       !strcmp((const char*)name, "CountryName") ||
       !strcmp((const char*)name, "IssuerSerial")
       )
      pctx->errcode = ddocSaxParseStartCollecting(pctx, FLAG_XML_ELEM, 1);
  }
}

//--------------------------------------------------
// Collects elements end-tag
// pctx - pointer to XML parsing work-area
// name - xml element tag name
// pcFlag - pointer to flag governing collection of this element
// pMBuf - DigiDocMemBuf to collect it in
//--------------------------------------------------
int ddocSaxParseCollectEndElement(SigDocParse* pctx, const xmlChar *name, 
				  char* pcFlag, DigiDocMemBuf* pMBuf)
{
  if(*pcFlag) {
    if(!pctx->errcode)
      pctx->errcode = ddocMemAppendData(pMBuf, "</", -1);
    if(!pctx->errcode)
      pctx->errcode = ddocMemAppendData(pMBuf, (const char*)name, -1);
    if(!pctx->errcode)
      pctx->errcode = ddocMemAppendData(pMBuf, ">", -1);
  }
  return pctx->errcode;
}

/**
 * endElementHandler:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when the end of an element has been detected.
 */
static void endElementHandler(void *ctx, const xmlChar *name)
{
  SignatureInfo* pSigInfo = NULL;
  SigDocParse* pctx = (SigDocParse*)ctx;
  const char* pTag = 0;
    
  // do nothing if error has ocurred
  if(pctx->errcode) return;
  pTag = ddocMemPop(&(pctx->mbufTags));
  if(pctx->eCurr)
    pctx->eCurr =pctx->eCurr->pParent;
  ddocDebug(4, "endElementHandler", "</%s>, popped: %s path: %s", (const char*)name, pTag, (const char*)pctx->mbufTags.pMem);
  // if we are in collect data mode then
  // collect the tag end
  if(!pctx->bNoXMLElemData)
    ddocSaxParseCollectEndElement(pctx, name, &(pctx->bCollectElemData), &(pctx->mbufElemData));

  if(!strcmp((const char*)name, "DataFile")) {
    pctx->bCollectDFData--; // decrement bypass mode
    if(pctx->bCollectDFData == 0)
      handleEndDataFile(pctx, name);
  }
  // collect separately <Signature> and <SignedProperties> data
  ddocSaxParseCollectEndElement(pctx, name, &(pctx->bCollectSigData), &(pctx->mbufSigData));
  ddocSaxParseCollectEndElement(pctx, name, &(pctx->bCollectSigPartData), &(pctx->mbufSigPartData));
  if(pctx->mbufSigData.pMem && !strcmp((const char*)name, "Signature")) {
    pSigInfo = ddocGetLastSignature(pctx->pSigDoc);
    if(pSigInfo) {
      // MEMLEAK: possible memleak if old content would not be released ???
      ddocDebug(3, "endElementHandler", "Set orig-content %s old-mem-used: %s new-content: %d", 
		pSigInfo->szId, (pSigInfo->mbufOrigContent.pMem ? "TRUE" : "FALSE"), pctx->mbufSigData.nLen);
      ddocMemBuf_free(&(pSigInfo->mbufOrigContent));
      pSigInfo->mbufOrigContent.pMem = (byte*)pctx->mbufSigData.pMem;
      pSigInfo->mbufOrigContent.nLen = pctx->mbufSigData.nLen;
      pctx->mbufSigData.pMem = 0;
      pctx->mbufSigData.nLen = 0;
    }
  }
  if(!pctx->nIgnoreDataFile) {
    if(!strcmp((const char*)name, "EncapsulatedX509Certificate")) 
      handleEndEncapsulatedX509Certificate(pctx);
    if(!strcmp((const char*)name, "EncapsulatedOCSPValue")) 
      handleEndEncapsulatedOCSPValue(pctx);
    if(!strcmp((const char*)name, "ClaimedRole")) 
      handleEndClaimedRole(pctx);
    if(!strcmp((const char*)name, "CertifiedRole")) 
      handleEndCertifiedRole(pctx);
    if(!strcmp((const char*)name, "X509Certificate")) 
      handleEndX509Certificate(pctx);
    if(!strcmp((const char*)name, "SignedProperties")) 
      handleEndSignedProperties(pctx);
    if(!strcmp((const char*)name, "SignedInfo")) 
      handleEndSignedInfo(pctx);
    if(!strcmp((const char*)name, "SignatureValue")) 
      handleEndSignatureValue(pctx);
    if(!strcmp((const char*)name, "ResponderID")) 
      handleEndResponderID(pctx);
    if(!strcmp((const char*)name, "ProducedAt")) 
      handleEndProducedAt(pctx);
    if(!strcmp((const char*)name, "ByName")) 
      handleEndResponderID(pctx);
    if(!strcmp((const char*)name, "ByKey")) 
      handleEndByKey(pctx);
    if(!strcmp((const char*)name, "DigestValue")) 
      handleEndDigestValue(pctx);
    if(!strcmp((const char*)name, "SigningTime")) 
      handleEndSigningTime(pctx);
    if(!strcmp((const char*)name, "IssuerSerial")) 
      handleEndIssuerSerial(pctx);
    if(!strcmp((const char*)name, "X509SerialNumber")) 
      handleEndIssuerSerial(pctx);
    if(!strcmp((const char*)name, "X509IssuerName")) 
      handleEndIssuerName(pctx);
    //if(!strcmp((const char*)name, "Cert")) 
    //  handleEndCert(pctx, name);
    if(!strcmp((const char*)name, "City"))
       handleAdrEntry(pctx, ADR_ENTRY_CITY);
    if(!strcmp((const char*)name, "StateOrProvince"))
       handleAdrEntry(pctx, ADR_ENTRY_STATE);
    if(!strcmp((const char*)name, "PostalCode"))
       handleAdrEntry(pctx, ADR_ENTRY_ZIP);
    if(!strcmp((const char*)name, "CountryName"))
       handleAdrEntry(pctx, ADR_ENTRY_COUNTRY);

  }
  // reset tag, but not the context because used
  pctx->tag[0] = 0;
}

/**
 * charactersHandler:
 * @ctxt:  An XML parser context
 * @ch:  a xmlChar string
 * @len: the number of xmlChar
 *
 * receiving some chars from the parser.
 * Question: how much at a time ???
 */
static void charactersHandler(void *ctx, const xmlChar *ch, int len)
{
  SigDocParse* pctx = (SigDocParse*)ctx;
  char *p = 0;
	
  // do nothing if error has ocurred
  if(pctx->errcode) return;
  // if we are in collect data mode then
  // collect this data
  ddocDebug(4, "charactersHandler", "tag: %s len: %d, elem-data: %s, sig-data: %s, collected: %d", 
	    pctx->tag, len, (pctx->mbufElemData.pMem ? "Y" : "N"), 
	    (pctx->mbufSigData.pMem ? "Y" : "N"), pctx->mbufElemData.nLen);
//#ifndef WITH_BASE64_HASHING_HACK
  if(pctx->bCollectElemData) {
    if(!pctx->errcode) {
      if(pctx->bNoXMLElemData) {
	pctx->errcode = ddocMemAppendData(&(pctx->mbufElemData), (const char*)ch, len);
      } else {
	pctx->errcode = escapeXMLSymbols((const char*)ch, len, &p);
	pctx->errcode = ddocMemAppendData(&(pctx->mbufElemData), (const char*)p, -1);
	free(p);
      }
    }
  }
//#endif
  if(pctx->bCollectSigData) {
    if(!pctx->errcode) {
      p = 0;
      pctx->errcode = escapeTextNode((const char*)ch, len, &p);
      pctx->errcode = ddocMemAppendData(&(pctx->mbufSigData), p, -1);
      free(p);
    }
  }
  if(pctx->bCollectSigPartData) {
    if(!pctx->errcode) {
      p = 0;
      pctx->errcode = escapeXMLSymbols((const char*)ch, len, &p);
      pctx->errcode = ddocMemAppendData(&(pctx->mbufSigPartData), p, -1);
      free(p);
    }
  }

  ddocDebug(5, "charactersHandler", "End collecting");
  if(!strcmp(pctx->tag, "DataFile"))
    handleDataFile(pctx, ch, len);
  //else printf("Ignoring: (%s, %d)\n", ch, len);
  ddocDebug(5, "charactersHandler", "End");
}

/**
 * startElementHandler:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when an opening tag has been processed.
 */
static void extractStartElementHandler(void *ctx, const xmlChar *name, const xmlChar **atts)
{
  const char* id = 0, *ctype = 0;
  int i, l1;
  char *p1 = 0;

  SigDocParse* pctx = (SigDocParse*)ctx;	
  strncpy(pctx->tag, (const char*)name, sizeof(pctx->tag));
  ddocDebug(5, "extractStartElementHandler", "tag: %s", pctx->tag);
  // do nothing if error has ocurred
  if(pctx->errcode) return;
  if(!strcmp((const char*)name, "DataFile")) {
    for (i = 0; (atts != NULL) && (atts[i] != NULL); i += 2) {
      if(!strcmp((const char*)atts[i], "Id"))
	id = (const char*)atts[i+1];
      if(!strcmp((const char*)atts[i], "ContentType"))
	ctype = (const char*)atts[i+1];
    } 
    if(!pctx->nIgnoreDataFile) {
      strncpy(pctx->ctx2, id, sizeof(pctx->ctx2));	
      strncpy(pctx->ctx4, ctype, sizeof(pctx->ctx4));
      if(!strcmp(pctx->ctx2, pctx->ctx3)) {
	pctx->bCollectDFData++; // increment bypass mode
	ddocDebug(4, "extractStartElementHandler", "Start DF: %s mode: %s skip: %d", 
		  pctx->ctx3, pctx->ctx1, pctx->bCollectDFData);
	if(pctx->bCollectDFData == 1) { // only the first time
	  ddocDebug(4, "extractStartElementHandler", "Init collecting DF: %s mode: %s", 
		    pctx->ctx3, pctx->ctx1);
	  if(!strcmp(pctx->ctx4, CONTENT_EMBEDDED_BASE64) && !pctx->bKeepBase64) {
		pctx->ectx = EVP_ENCODE_CTX_new();
		EVP_DecodeInit(pctx->ectx);
	    pctx->b64pos = 0;
	    pctx->lSize = 0;
	  }
	  // open output file if necessary
	  if(!pctx->bDataFile && !pctx->pMemBufDF) {
	    pctx->bDataFile = BIO_new_file(pctx->ctx5, "w");
	    ddocDebug(4, "extractStartElementHandler", "Opening file: %s", pctx->ctx5);
	    if(!pctx->bDataFile)
	      SET_LAST_ERROR(ERR_FILE_WRITE);
	  }
	}
      }
    }		
    if(!strcmp(ctype, CONTENT_EMBEDDED) || pctx->nIgnoreDataFile)
      pctx->nIgnoreDataFile++;
  }
  if(!strcmp(pctx->ctx2, pctx->ctx3) && 
     !strcmp(pctx->ctx4, CONTENT_EMBEDDED) &&
     strcmp((const char*)name, "DataFile")) {
    if(!strcmp(pctx->ctx1, CHARSET_ISO_8859_1)) { // if must convert
      // begining of the tag
      l1 = strlen((char*)name) + 10;
      p1 = (char*)malloc(l1);
      RETURN_VOID_IF_BAD_ALLOC(p1);
      if(pctx->pMemBufDF) {
	ddocMemAppendData(pctx->pMemBufDF, "<", -1);
	ddocMemAppendData(pctx->pMemBufDF, utf82ascii((const char*)name, p1, &l1), -1);
      }
      else
	BIO_printf(pctx->bDataFile, "<%s", utf82ascii((const char*)name, p1, &l1));
      free(p1);
      p1 = 0;
      for (i = 0; (atts != NULL) && (atts[i] != NULL); i += 2) {
	l1 = strlen((char*)atts[i]) + 10;
	p1 = (char*)malloc(l1);
	RETURN_VOID_IF_BAD_ALLOC(p1);
	if(pctx->pMemBufDF) {
	  ddocMemAppendData(pctx->pMemBufDF, " ", -1);
	  ddocMemAppendData(pctx->pMemBufDF, utf82ascii((const char*)atts[i], p1, &l1), -1);
	  ddocMemAppendData(pctx->pMemBufDF, "=", -1);
	}
	else
	  BIO_printf(pctx->bDataFile, " %s=", utf82ascii((const char*)atts[i], p1, &l1));
	free(p1);
	p1 = 0;
	l1 = strlen((char*)atts[i+1]) + 10;
	p1 = (char*)malloc(l1);
	RETURN_VOID_IF_BAD_ALLOC(p1);
	if(pctx->pMemBufDF) {
	  ddocMemAppendData(pctx->pMemBufDF, "\"", -1);
	  ddocMemAppendData(pctx->pMemBufDF, utf82ascii((const char*)atts[i+1], p1, &l1), -1);
	  ddocMemAppendData(pctx->pMemBufDF, "\"", -1);
	}
	else
	BIO_printf(pctx->bDataFile, "\"%s\"", utf82ascii((const char*)atts[i+1], p1, &l1));
	free(p1);
	p1 = 0;
      } // for - atributes
      if(pctx->pMemBufDF)
	ddocMemAppendData(pctx->pMemBufDF, ">", -1);
      else
	BIO_puts(pctx->bDataFile, ">");
    } // if - must convert
    else { // no need to convert
      if(pctx->pMemBufDF) {
	ddocMemAppendData(pctx->pMemBufDF, "<", -1);
	ddocMemAppendData(pctx->pMemBufDF, (const char*)name, -1);
	for (i = 0; (atts != NULL) && (atts[i] != NULL); i += 2) {
	  ddocMemAppendData(pctx->pMemBufDF, " ", -1);
	  ddocMemAppendData(pctx->pMemBufDF, (const char*)atts[i], -1);
	  p1 = 0;
	  ddocMemAppendData(pctx->pMemBufDF, "=\"", -1);
	  pctx->errcode = escapeXMLSymbols((const char*)atts[i+1], 
		  strlen((const char*)atts[i+1]), &p1);
	  ddocMemAppendData(pctx->pMemBufDF, p1, -1);
	  free(p1);
	  ddocMemAppendData(pctx->pMemBufDF, "\"", -1);
	} 
	ddocMemAppendData(pctx->pMemBufDF, ">", -1);
      } else {
	BIO_printf(pctx->bDataFile, "<%s", name);
	for (i = 0; (atts != NULL) && (atts[i] != NULL); i += 2) {
	  BIO_printf(pctx->bDataFile, " %s=\"%s\"", 
		     (const char*)atts[i], (const char*)atts[i+1]);
	} 
	BIO_puts(pctx->bDataFile, ">");
      }      
    } // else no conversion
  } // if strcmp(DataFile)
}


//--------------------------------------------------
// handles decoding base64 content. Removes all 
// whitespace and breaks the data in 64 symbol lines
// to ensure correct decoding
// pctx - pointer to XML parsing work-area
// ch - input data
// len - length of input data
// lastBlock - 1=last base64 block
//--------------------------------------------------
void extractDecodeB64(SigDocParse* pctx, const char* ch, int len, int lastBlock)
{
  int l = 0, j;
  char decData[70];

  ddocDebug(4, "extractDecodeB64", "line: %d last: %d", len, lastBlock);
  do {
    // compose a 64 char base64 line for OpenSSL's decoder
    while(pctx->b64pos < 64 && l < len) {
      if(!isspace(ch[l])) {
	pctx->b64line[pctx->b64pos] = ch[l];
	pctx->b64pos++;
      }
      l++;
    }
    // if line is ready then terminate and use it
    if(pctx->b64pos == 64 || (l == len && lastBlock)) {
      pctx->b64line[pctx->b64pos] = '\n';
      pctx->b64line[pctx->b64pos + 1] = 0;
      j = sizeof(decData);
      memset(decData, 0, j);
      ddocDebug(5, "extractDecodeB64", "decoding: %s", pctx->b64line);
	  EVP_DecodeUpdate(pctx->ectx, (unsigned char*)decData, &j,
		     (unsigned char*)pctx->b64line, pctx->b64pos + 1);
      ddocDebug(4, "extractDecodeB64", "decoding: %d -> got: %d", pctx->b64pos, j);
      if(pctx->pMemBufDF)
	ddocMemAppendData(pctx->pMemBufDF, decData, j);
      else {
	if(!pctx->pMemBufDF)
	  SET_LAST_ERROR_RETURN_VOID_IF_NOT(pctx->bDataFile, ERR_FILE_WRITE);
	BIO_write(pctx->bDataFile, decData, j);
      }
      pctx->lSize += j;
      if(l == len && lastBlock) {
	j = sizeof(decData);
	memset(decData, 0, j);
	EVP_DecodeFinal(pctx->ectx, (unsigned char*)decData, &j);
	EVP_ENCODE_CTX_free(pctx->ectx);
	ddocDebug(4, "extractDecodeB64", "decoding final got: %d", j);
	if(j > 0) {
	  if(pctx->pMemBufDF)
	    ddocMemAppendData(pctx->pMemBufDF, decData, j);
	  else {
	    if(!pctx->pMemBufDF)
	      SET_LAST_ERROR_RETURN_VOID_IF_NOT(pctx->bDataFile, ERR_FILE_WRITE);
	    BIO_write(pctx->bDataFile, decData, j);
	  }
	  pctx->lSize += j;
	}
      }
      // ready for next line
      pctx->b64pos = 0;
      //memset(&(pctx->b64line), 0, sizeof(pctx->b64line));
    }
  } while(l < len);
}


/**
 * extractBodyHandler:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when bypassing xml parser for base64 data and extracting to file
 */
void extractBodyHandler(SigDocParse* pctx, const char* ch, int len)
{
  ddocDebug(4, "extractBodyHandler", "DF: %s data: %d", pctx->ctx2, len);
  if(!pctx->pMemBufDF)
    SET_LAST_ERROR_RETURN_VOID_IF_NOT(pctx->bDataFile, ERR_FILE_WRITE);
  if(!pctx->bKeepBase64) {
    extractDecodeB64(pctx, ch, len, 0);
  } else {
	  if(pctx->pMemBufDF) {
         ddocMemAppendData(pctx->pMemBufDF, ch, len);
	  }else {
		 ddocDebug(4, "extractBodyHandler", "Writing: %s len: %d", ch, len);
         BIO_write(pctx->bDataFile, ch, len);
	  }
    pctx->lSize += len;
  }
}

/**
 * extractBodyHandler:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when bypassing xml parser for bas64 data and extracting to file
 */
void extractNoChangeHandler(SigDocParse* pctx, const char* ch, int len)
{
  int l;
  char *p = 0;

  ddocDebug(4, "extractNoChangeHandler", "DF: %s data: %d", pctx->ctx2, len);
  if(pctx->errcode) { return; }
  if(!pctx->pMemBufDF)
    SET_LAST_ERROR_RETURN_VOID_IF_NOT(pctx->bDataFile, ERR_FILE_WRITE);
  if(!strcmp(pctx->ctx4, CONTENT_EMBEDDED_BASE64)) {
    BIO_write(pctx->bDataFile, ch, len);
    pctx->lSize += len;
  } else {
    pctx->errcode = escapeXMLSymbols((const char*)ch, len, &p);
    l = strlen(p);
    pctx->lSize += l;
    if(pctx->pMemBufDF) {
      ddocMemAppendData(pctx->pMemBufDF,p, l);
	} else {
	  ddocDebug(5, "extractNoChangeHandler", "Writing: %s len: %d", p, l);
      BIO_write(pctx->bDataFile, p, l);
	}
    free(p);
    p = 0;
  }
}

/**
 * charactersHandler:
 * @ctxt:  An XML parser context
 * @ch:  a xmlChar string
 * @len: the number of xmlChar
 *
 * receiving some chars from the parser.
 * Question: how much at a time ???
 */
static void extractCharactersHandler(void *ctx, const xmlChar *ch, int len)
{
  int l;
  char *p = 0, *p2 = 0; 
  SigDocParse* pctx = (SigDocParse*)ctx;

  ddocDebug(5, "extractCharactersHandler", "tag: %s, data: %d - \'%s\'", pctx->tag, len, (char*)ch);
  // do nothing if error has ocurred
  if(pctx->errcode) { return; }
  if(!strcmp(pctx->ctx2, pctx->ctx3)) { 
    if(!strcmp(pctx->ctx1, "NO-CHANGE")) { // NO-CHANGE
      extractNoChangeHandler(pctx, (const char*)ch, len);
    }
    else { // NOT NO-CHANGE
      if(!strcmp(pctx->ctx4, CONTENT_EMBEDDED_BASE64)) {
	extractBodyHandler(pctx, (const char*)ch, len);
      }
      if(!strcmp(pctx->ctx4, CONTENT_EMBEDDED)) {
	if(!strcmp(pctx->ctx1, CHARSET_ISO_8859_1)) {
	  l = len + 10;
	  p = (char*)malloc(l);
	  RETURN_VOID_IF_BAD_ALLOC(p);
	  memset(p, 0, l);
	  UTF8Toisolat1((unsigned char*)p, &l, 
			(const unsigned char*)ch, &len);
	  escapeXMLSymbols((const char*)p, l, &p2);
	  free(p);
	  p = 0;
	  l = strlen(p2);
	  if(pctx->pMemBufDF)
	    ddocMemAppendData(pctx->pMemBufDF, p, l);
	  else
	    BIO_write(pctx->bDataFile, (unsigned char*)p, l);
	  free(p2);
	  p2 = 0;
	} else {
	  escapeXMLSymbols((const char*)ch, len, &p);
	  l = strlen(p);
	  if(pctx->pMemBufDF)
	    ddocMemAppendData(pctx->pMemBufDF, p, l);
	  else
	    BIO_write(pctx->bDataFile, (unsigned char*)p, l);
	  free(p);
	}
      }
    } // NOT NO-CHANGE
  }
  ddocDebug(5, "extractCharactersHandler", "done, errs: %d", pctx->errcode);
}

/**
 * extractEndElementHandler:
 * @ctxt:  An XML parser context
 * @name:  The element name
 *
 * called when the end of an element has been detected.
 */
static void extractEndElementHandler(void *ctx, const xmlChar *name)
{
  time_t t1;
  SigDocParse* pctx = (SigDocParse*)ctx;

  ddocDebug(5, "extractEndElementHandler", "tag: %s", (char*)name);
  // do nothing if error has ocurred
  if(pctx->errcode) { return; }
  if(!strcmp((const char*)name, "DataFile")) {
    if(pctx->nIgnoreDataFile > 0) 
      pctx->nIgnoreDataFile--;
    ddocDebug(3, "extractEndElementHandler", "DF: %s end ignore: %d skip: %d", 
	      pctx->ctx2, pctx->nIgnoreDataFile, pctx->bCollectDFData);
    if(!strcmp(pctx->ctx2, pctx->ctx3) && 
       !pctx->nIgnoreDataFile) {  
      pctx->bCollectDFData--;
      if(!pctx->bCollectDFData) {
	if(!strcmp(pctx->ctx4, CONTENT_EMBEDDED_BASE64) && 
	   strcmp(pctx->ctx1, "NO-CHANGE")) {
	  if(!pctx->bKeepBase64)
	    extractDecodeB64(pctx, NULL, 0, 1);	    
	} 
	if(!strcmp(pctx->ctx1, "NO-CHANGE")) {
	  // todo ?
	}
	time(&t1);
	ddocDebug(3, "extractEndElementHandler", "DF: %s mode: %s, time: %d [sek] total: %ld bytes", 
		  pctx->ctx3, pctx->ctx1, (t1 - pctx->tStartParse), pctx->lSize);
	// mark the end of data collecting
	pctx->ctx3[0] = 0;
	pctx->lSize = 0;
      } // if bCollectDFData == 0
    } // if not ignore DataFile   
  } // if "DataFile"
  if(pctx->ctx3[0] && !strcmp(pctx->ctx4, CONTENT_EMBEDDED)) {
    if(pctx->pMemBufDF) {
      ddocDebug(5, "extractEndElementHandler", "Last name: %s collected: \'%s\'", 
		(char*)name, (char*)pctx->pMemBufDF->pMem);
      ddocMemAppendData(pctx->pMemBufDF, "</", -1);
      ddocMemAppendData(pctx->pMemBufDF, (char*)name, -1);
      ddocMemAppendData(pctx->pMemBufDF, ">", -1);
      ddocDebug(5, "extractEndElementHandler", "Result: \'%s\'", 
		(char*)pctx->pMemBufDF->pMem);
      
    } else {
      BIO_printf(pctx->bDataFile, "</%s>", name);
    }
  }
  // reset tag
  pctx->tag[0] = 0;
}


/**
 * cdataBlockHandler:
 * @ctx: the user data (XML parser context)
 * @value:  The pcdata content
 * @len:  the block length
 *
 * called when a pcdata block has been parsed
 */
static void cdataBlockHandler(void * ctx, const xmlChar *value, int len)
{
    fprintf(stdout, "SAX.pcdata(%.20s, %d)\n", (char *) value, len);
}


/**
 * warningHandler:
 * @ctxt:  An XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Display and format a warning messages, gives file, line, position and
 * extra parameters.
 */
static void warningHandler(void * ctx, const char *msg, ...)
{
  va_list args;

  va_start(args, msg);
  ddocDebugVaArgs(2, "warningHandler", msg, args);
  va_end(args);
}

/**
 * errorHandler:
 * @ctxt:  An XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Display and format a error messages, gives file, line, position and
 * extra parameters.
 */
static void errorHandler(void *ctx, const char *msg, ...)
{
  va_list args;
  SigDocParse* pctx = (SigDocParse*)ctx;
	
  va_start(args, msg);	
  pctx->errcode = ERR_DIGIDOC_PARSE;
  ddocDebugVaArgs(1, "errorHandler", msg, args);
  addError(pctx->errcode, __FILE__, __LINE__, "XML parsing error");
  va_end(args);
}

/**
 * fatalErrorHandler:
 * @ctxt:  An XML parser context
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Display and format a fatalError messages, gives file, line, position and
 * extra parameters.
 */
static void fatalErrorHandler(void *ctx, const char *msg, ...)
{
  va_list args;
  SigDocParse* pctx = (SigDocParse*)ctx;

  va_start(args, msg);
  pctx->errcode = ERR_DIGIDOC_PARSE;
  ddocDebugVaArgs(1, "fatalErrorHandler", msg, args);
  addError(pctx->errcode, __FILE__, __LINE__, "XML parsing error");
  va_end(args);
}


xmlSAXHandler debugSAXHandlerStruct = {
    NULL, //internalSubsetHandler,
    NULL, //isStandaloneHandler,
    NULL, //hasInternalSubsetHandler,
    NULL, //hasExternalSubsetHandler,
    NULL, //resolveEntityHandler,
    NULL, //getEntityHandler,
    NULL, //entityDeclHandler,
    NULL, //notationDeclHandler,
    NULL, //attributeDeclHandler,
    NULL, //elementDeclHandler,
    NULL, //unparsedEntityDeclHandler,
    NULL, //setDocumentLocatorHandler,
    NULL, //startDocumentHandler,
    NULL, //endDocumentHandler,
    startElementHandler,
    endElementHandler,
    NULL, //referenceHandler,
    charactersHandler,
    NULL, //ignorableWhitespaceHandler,
    NULL, //processingInstructionHandler,
    NULL, //commentHandler,
    warningHandler,
    errorHandler,
    fatalErrorHandler,
    NULL, //getParameterEntityHandler,
    cdataBlockHandler,
    NULL, //externalSubsetHandler,
    1
};


xmlSAXHandlerPtr debugSAXHandler = &debugSAXHandlerStruct;


xmlSAXHandler extractSAXHandlerStruct = {
    NULL, //internalSubsetHandler,
    NULL, //isStandaloneHandler,
    NULL, //hasInternalSubsetHandler,
    NULL, //hasExternalSubsetHandler,
    NULL, //resolveEntityHandler,
    NULL, //getEntityHandler,
    NULL, //entityDeclHandler,
    NULL, //notationDeclHandler,
    NULL, //attributeDeclHandler,
    NULL, //elementDeclHandler,
    NULL, //unparsedEntityDeclHandler,
    NULL, //setDocumentLocatorHandler,
    NULL, //startDocumentHandler,
    NULL, //endDocumentHandler,
    extractStartElementHandler,
    extractEndElementHandler,
    NULL, //referenceHandler,
    extractCharactersHandler,
    NULL, //ignorableWhitespaceHandler,
    NULL, //processingInstructionHandler,
    NULL, //commentHandler,
    warningHandler,
    errorHandler,
    fatalErrorHandler,
    NULL, //getParameterEntityHandler,
    NULL, //cdataBlockHandler,
    NULL, //externalSubsetHandler,
    1
};

xmlSAXHandlerPtr extractSAXHandler = &extractSAXHandlerStruct;




//--------------------------------------------------
// Reads in signed XML document info from digidoc file
// ppSigDoc - pointer to the buffer of newly read info pointer
// szFileName - documents filename
// checkFileDigest - indicates if digests of datafiles referred by the document must be checked
// lMaxDFLen - maximum size for a DataFile whose contents will be
// kept in memory
//--------------------------------------------------
EXP_OPTION int ddocSaxReadSignedDocFromFile(SignedDoc** ppSigDoc, const char* szFileName, 
			     int checkFileDigest, long lMaxDFLen)
{
  int err = ERR_OK, ret, n;
  FILE *f;
  char chars[1028], *p, buf1[16385];
  xmlParserCtxtPtr ctxt;
  SigDocParse pctx;
  DigiDocMemBuf mbuf1;
#ifdef WIN32
  wchar_t *convFileName = 0;
  err = utf82unicode((const char*)szFileName, (char**)&convFileName, &ret);
  ddocDebug(3, "ddocSaxReadSignedDocFromFile", "file: %s, conv-file: %s", szFileName, convFileName);
#endif

  ddocDebug(3, "ddocSaxReadSignedDocFromFile", "digidoc: %s, checkDig: %d, maxDF: %ld", 
	    szFileName, checkFileDigest, lMaxDFLen);
  RETURN_IF_NULL_PARAM(ppSigDoc);
  RETURN_IF_NULL_PARAM(szFileName);
  clearErrors();
  memset(&pctx, 0, sizeof(pctx));
    pctx.pSigDoc = (SignedDoc*)malloc(sizeof(SignedDoc));
    RETURN_IF_BAD_ALLOC(pctx.pSigDoc);
    memset(pctx.pSigDoc, 0, sizeof(SignedDoc));
#ifdef WIN32
  ddocDebug(3, "ddocSaxReadSignedDocFromFile", "Opening file: %s", convFileName);
  if(!err && ((f = _wfopen(convFileName, L"rb")) != NULL)) {
#else
  ddocDebug(3, "ddocSaxReadSignedDocFromFile", "Opening file: %s", szFileName);
  if(!err && ((f = fopen(szFileName, "rb")) != NULL)) {
#endif
  ddocDebug(4, "ddocSaxReadSignedDocFromFile", "file opened");
  n=0;
      if(ftell(f) > 0) {
          ddocDebug(5, "ddocSaxReadSignedDocFromFile", "File position after open is: %d err: %d eof: %d, move to begin!", ftell(f), ferror(f), feof(f));
          fseek(f, 0, SEEK_SET);
      }
    //memset(chars,0,sizeof(chars));
    ret = fread(chars, 1, 100, f);
    if (ret > 0) {
      chars[ret] = 0; // zero terminate block data
      p = strstr(chars, "<?xml");
	if(!p) 
	  p = chars;
    n++;
    //pctx.bDataFile = (BIO*)1;
    pctx.szInputFileName = (char*)szFileName;
    pctx.checkFileDigest = checkFileDigest;
    pctx.lMaxDFLen = lMaxDFLen;
    time(&(pctx.tStartParse));
    ddocDebug(5, "ddocSaxReadSignedDocFromFile", "parse block: %d len: %d fpos: %d \n---\n%s\n---\n", n, ret, ftell(f), p);

    ctxt = xmlCreatePushParserCtxt(debugSAXHandler, &pctx,
				     p, strlen(p), szFileName);
    do {
	//memset(chars, 0, sizeof(chars)); // no longer necessary as zero terminated later here
	ret = fread(chars, 1, 1024, f);
    ddocDebug(5, "ddocSaxReadSignedDocFromFile", "read block: %d got: %d fpos: %d err: %d eof: %d", n, ret, ftell(f), ferror(f), feof(f));
    if((ferror(f) && ret <= 0) && !feof(f)) {
        ddocDebug(1, "ddocSaxReadSignedDocFromFile", "Error %d reading file: %s", ferror(f), szFileName);
        SET_LAST_ERROR_RETURN_CODE(ERR_FILE_READ);
    }
    if(ret >= 0) {
      chars[ret] = 0; // zero terminate block data
    } else {
        ddocDebug(1, "ddocSaxReadSignedDocFromFile", "No data could be read from: %s pos: %d", szFileName, ftell(f));
        break;
    }
    n++;
    ddocDebug(5, "ddocSaxReadSignedDocFromFile", "parse block: %d len: %d fpos: %d \n---\n%s\n---\n", n, ret, ftell(f), chars);

	if(pctx.bCollectDFData > 0 && !strcmp(pctx.ctx4, CONTENT_EMBEDDED_BASE64)) { // bypass mode
	  // look for new element start "<"
	  p = strchr(chars, '<');
	  // if we just enetered the bypass mode then send flush command
	  // but increment bypass mode in order not to fall out of it
	  if(pctx.bCollectDFData == 1 && !p) { // start bypass mode
	    pctx.bCollectDFData += 2; // increment with 2 so we dont return to flushing
	    ddocDebug(4, "ddocSaxReadSignedDocFromFile", "Starting bypass mode, skip: %d", 
		      pctx.bCollectDFData);
	    // force the parser to release element content 
	    // before entering into bypass mode
        ddocDebug(5, "ddocSaxReadSignedDocFromFile", "parse bypass data %s", g_szDataFileFlush1);
	    xmlParseChunk(ctxt, g_szDataFileFlush1, strlen(g_szDataFileFlush1), 0);
	    ddocDebug(4, "ddocSaxReadSignedDocFromFile", "Entering bypass mode, skip: %d", 
		      pctx.bCollectDFData);
	  }
	  if(pctx.bCollectDFData >=2 && !p /*pctx.bCollectElemData*/) { // parse in bypass mode
	    ddocDebug(4, "ddocSaxReadSignedDocFromFile", "Parsing in bypass mode, skip: %d len: %d", 
		      pctx.bCollectDFData, ret);
#ifdef WITH_BASE64_HASHING_HACK
		  ddocDebug(4, "ddocSaxReadSignedDocFromFile", "update sha1: %d - %s", ret, chars);
	      SHA1_Update(&(pctx.sctx), chars, ret);
		  mbuf1.pMem = chars;
	      mbuf1.nLen = ret;
	      ddocDebugWriteFile(4, "df-data.txt", &mbuf1);
#else
	      pctx.errcode = ddocMemAppendData(&(pctx.mbufElemData), chars, ret);
	    // update sha1
	    l1 = sizeof(buf1);
	    EVP_DecodeUpdate(&(pctx.ectx), (unsigned char*)buf1, &l1, (unsigned char*)chars, ret);
	    ddocDebug(4, "ddocSaxReadSignedDocFromFile", "update sha1: %d - %s", l1, buf1);
	    SHA1_Update(&(pctx.sctx), buf1, l1);
#endif
	  }
	  if(p) { // finish bypass mode
	    ddocDebug(4, "ddocSaxReadSignedDocFromFile", "Ending bypass mode len: %d, skip: %d", 
		      ret, pctx.bCollectDFData);
	    snprintf(buf1, sizeof(buf1), g_szDataFileFlush2, pctx.ctx3, pctx.ctx4);
	    // send finish command
        ddocDebug(5, "ddocSaxReadSignedDocFromFile", "parse finish data %s", buf1);
        xmlParseChunk(ctxt, buf1, strlen(buf1), 0);	
	    pctx.bCollectDFData = 1;	    
	    // parse the normal chunk that caused end
	    xmlParseChunk(ctxt, chars, ret, 0);
	  }
	} else { // normal mode
	  ddocDebug(4, "ddocSaxReadSignedDocFromFile", "parsing normal chunk");
	  xmlParseChunk(ctxt, chars, ret, 0);
	}

    } while(ret > 0/* && pctx.ctx3[0]*/);
      ddocDebug(5, "ddocSaxReadSignedDocFromFile", "parse end0 \n---\n%s\n---\n", chars);
      xmlParseChunk(ctxt, chars, 0, 1);
      xmlFreeParserCtxt(ctxt);
    }
    *ppSigDoc = pctx.pSigDoc;
    fclose(f);
  }
  else {
    err = ERR_FILE_READ;
    ddocDebug(1, "ddocSaxReadSignedDocFromFile", "error reading file: %s, err: %d", szFileName, err);
  }
  if (err != ERR_OK) SET_LAST_ERROR(err);
  if(!err)
    err = getLastError();
  ddocDebug(3, "ddocSaxReadSignedDocFromFile", "success reading file: %s, err: %d", szFileName, err);
  // cleanup parser context
  ddocSAXCleanup(&pctx);
  // check ddoc xmlns problem
  checkDdocWrongDigests(*ppSigDoc);
#ifdef WIN32
  free(convFileName);
#endif
      return checkUnknownErr();
}


//--------------------------------------------------
// Reads in signed XML document info
// ppSigDoc - pointer to the buffer of newly read info pointer
// szFileName - documents filename
// checkFileDigest - indicates if digests of datafiles referred by the document must be checked
// lMaxDFLen - maximum size for a DataFile whose contents will be
// kept in memory
//--------------------------------------------------
EXP_OPTION int ddocSaxReadSignedDocFromMemory(SignedDoc** ppSigDoc, const void* pData, 
				       int len, long lMaxDFLen)
{
  int err = ERR_OK;
  int ret, l2;
  SigDocParse pctx;
  char * p = 0;
    
  ddocDebug(3, "ddocSaxReadSignedDocFromMemory", "data len: %d, maxDF: %ld", len, lMaxDFLen);
  RETURN_IF_NULL_PARAM(ppSigDoc);
  RETURN_IF_NULL_PARAM(pData);

  clearErrors();
  memset(&pctx, 0, sizeof(pctx));
  pctx.pSigDoc = (SignedDoc*)malloc(sizeof(SignedDoc));
  RETURN_IF_BAD_ALLOC(pctx.pSigDoc);
  memset(pctx.pSigDoc, 0, sizeof(SignedDoc));
  //pctx.bDataFile = (BIO*)1;
  pctx.szInputFileName = 0;
  pctx.checkFileDigest = 0;
  pctx.lMaxDFLen = lMaxDFLen;
  // skip any BOM marks or other non-xml chars at the beginning
  if(pData)
    p = strstr((const char*)pData, "<?xml");
  if(p) { 
    l2 = strlen(p);
  } else {
    p = (char*)pData;
    l2 = len;
  }
  ret = xmlSAXUserParseMemory(debugSAXHandler, &pctx, (const char*)p, l2);
  *ppSigDoc = pctx.pSigDoc;
  if (err != ERR_OK) {
    SET_LAST_ERROR(err);
    ddocDebug(1, "ddocSaxReadSignedDocFromMemory", "parsing error: %d", err);
  }
  if(!err)
    err = getLastError();
  // cleanup parser context
  ddocSAXCleanup(&pctx);
  return err;
}


//--------------------------------------------------
// Reads in signed XML document and extracts the desired data file
// pSigDoc - signed document object if exists. Can be NULL
// szFileName - digidoc filename
// szDataFileName - name of the file where to store embedded data. 
// szDocId - DataFile Id atribute value
// szCharset - convert DataFile content to charset
//--------------------------------------------------
EXP_OPTION int ddocSaxExtractDataFile(SignedDoc* pSigDoc, const char* szFileName, 
				      const char* szDataFileName, const char* szDocId, 
				      const char* szCharset)
{
  FILE *f;
  int ret, err = ERR_OK;
  long len;
  char chars[1050], convFileName[1024], 
    convDataFileName[1024], *p;
  xmlParserCtxtPtr ctxt;
  SigDocParse pctx;
  void* pBuf;
  // test
  ddocDebug(3, "ddocSaxExtractDataFile", "SigDoc: %s, docid: %s, digidoc: %s, file: %s, charset: %s", (pSigDoc ? "OK" : "NULL"), szDocId, szFileName, szDataFileName, szCharset);
  return ddocExtractDataFile(pSigDoc, szFileName, szDataFileName, szDocId, szCharset);
  RETURN_IF_NULL_PARAM(szFileName);
  RETURN_IF_NULL_PARAM(szDataFileName);
  RETURN_IF_NULL_PARAM(szDocId);
  RETURN_IF_NULL_PARAM(szCharset);

  clearErrors();
  memset(&pctx, 0, sizeof(pctx));
  memset(convFileName, 0, sizeof(convFileName));
  memset(convDataFileName, 0, sizeof(convDataFileName));
  ddocConvertFileName(convDataFileName, sizeof(convDataFileName), szDataFileName);
  ddocConvertFileName(convFileName, sizeof(convFileName), szFileName);

  // test	
  return ddocExtractDataFile(pSigDoc, szFileName, szDataFileName, szDocId, szCharset);

  // try reading from memory if already cached?
  ret = ddocGetDataFileCachedData(pSigDoc, szDocId, &pBuf, &len);
  if(pBuf) { // gotcha
    ddocDebug(3, "ddocSaxExtractDataFile", "Using cached data: %d bytes", len);
    if((f = fopen(convDataFileName, "wb")) != NULL) {
      fwrite(pBuf, 1, len, f);
      fclose(f);
    } else {
      ddocDebug(1, "ddocSaxExtractDataFile", "Error writing file: %s", convDataFileName);
      SET_LAST_ERROR_RETURN_CODE(ERR_FILE_WRITE);
    }
    free(pBuf);
    return ret;
  }
  strncpy(pctx.ctx5, convDataFileName, sizeof(pctx.ctx5));
  if ((f = fopen(convFileName, "r")) != NULL) {
    pctx.pSigDoc = NULL;
    pctx.bDataFile = NULL;
    pctx.ctx1[0] = pctx.ctx2[0] = pctx.ctx3[0] = pctx.tag[0] = pctx.ctx4[0] = 0;
    pctx.errcode = ERR_OK;
    time(&(pctx.tStartParse));
    pctx.bDataFile = NULL; //BIO_new_file(szDataFileName, "w");
    strncpy(pctx.ctx1, szCharset, sizeof(pctx.ctx1));
    pctx.szInputFileName = (char*)szFileName;
    strncpy(pctx.ctx3, szDocId, sizeof(pctx.ctx3));
    memset(chars, 0, sizeof(chars));
    ret = fread(chars, 1, 10, f);
    if (ret > 0) {
      p = strstr(chars, "<?xml");
      if(!p)
	p = chars;
      ctxt = xmlCreatePushParserCtxt(extractSAXHandler, &pctx,
				     p, strlen(p), szFileName);
      do {
	memset(chars, 0, sizeof(chars));
	ret = fread(chars, 1, 1024, f);
	ddocDebug(6, "ddocSaxExtractDataFile", "Parsing %d bytes: \n%s\n", ret, chars);
	if(ret <= 0) break;
	if(pctx.bCollectDFData > 0 && 
	   !strcmp(pctx.ctx4, CONTENT_EMBEDDED_BASE64)) { // bypass mode
	  // look for new element start "<"
	  p = strchr(chars, '<');
	  // if we just entered the bypass mode then send flush command
	  // but increment bypass mode in order not to fall out of it
	  if(pctx.bCollectDFData == 1 && !p) { // start bypass mode
	    pctx.bCollectDFData += 2; // increment with 2 so we dont return to flushing
	    ddocDebug(4, "ddocSaxExtractDataFile", "Starting bypass mode, skip: %d", 
		      pctx.bCollectDFData);
	    // force the parser to release element content 
	    // before entering into bypass mode
	    xmlParseChunk(ctxt, g_szDataFileFlush1, strlen(g_szDataFileFlush1), 0);
	    ddocDebug(4, "ddocSaxExtractDataFile", "Entering bypass mode, skip: %d", 
		      pctx.bCollectDFData);
	  }
	  if(pctx.bCollectDFData >=2 && !p) { // parse in bypass mode
	    ddocDebug(4, "ddocSaxExtractDataFile", 
		      "Parsing in bypass mode, skip: %d len: %d", 
		      pctx.bCollectDFData, ret);
	    if(!strcmp(pctx.ctx1, "NO-CHANGE")) { // NO-CHANGE
	      extractNoChangeHandler(&pctx, (const char*)chars, ret);
	    } else {
	      extractBodyHandler(&pctx, (const char*)chars, ret);
	    }
	  } 
	  if(p) { // finish bypass mode
		*p = 0;
	    ddocDebug(3, "ddocSaxExtractDataFile", "Last block %d bytes: \n%s\n", ret, chars);
	    pctx.bCollectDFData = 1;	 
	    //xmlParseChunk(ctxt, chars, strlen((const char*)chars), 0);
		if(!strcmp(pctx.ctx1, "NO-CHANGE")) { // NO-CHANGE
	      extractNoChangeHandler(&pctx, (const char*)chars, strlen(chars));
	    } else {
	      extractBodyHandler(&pctx, (const char*)chars, strlen(chars));
		  extractDecodeB64(&pctx, NULL, 0, 1);
	    }
		pctx.bCollectDFData = 0; // stopp bypass attempts
	    memset(chars, 0, sizeof(chars));
		ret = 0; // stop parsing
	  }
	} else { // normal mode
	  ddocDebug(3, "ddocSaxExtractDataFile", "parsing normal chunk \n%s\n", chars);
	  xmlParseChunk(ctxt, chars, ret, 0);
	  memset(chars, 0, sizeof(chars));
	}

      } while(ret > 0 && pctx.ctx3[0]);
      ddocDebug(3, "ddocSaxExtractDataFile", "parsing last chunk\n---%s\n---", chars);
      if(strlen(chars))
        xmlParseChunk(ctxt, chars, 0, 1);
      xmlFreeParserCtxt(ctxt);
    }
    ddocDebug(5, "ddocSaxExtractDataFile", "parsing complete");
    fclose(f); 
  } else {
    ddocDebug(1, "ddocSaxExtractDataFile", "Error reading file: %s", szFileName);
    SET_LAST_ERROR_RETURN_CODE(ERR_FILE_READ);
  }
  if(!err)
    err = getLastError();
  // cleanup parser context
  ddocSAXCleanup(&pctx);
  return err;
}

//--------------------------------------------------
// Reads in signed XML document and returns the
// desired DataFile-s content in a memory buffer.
// caller is responsible for freeing the memory.
// pSigDoc - signed document object if cached
// szFileName - name of digidoc file
// szDocId - id if DataFile
// pOutBuf - address of buffer pointer
// bKeepBase64 - 1=don't decode base64, 0=decode base64
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocSAXGetDataFile(SignedDoc* pSigDoc, const char* szFileName,
				  const char* szDocId, DigiDocMemBuf* pOutBuf, 
				  int bKeepBase64)
{
  FILE *f;
  int ret, err = ERR_OK;
  char chars[1025], convFileName[1024], *p, buf1[200];
  xmlParserCtxtPtr ctxt;
  SigDocParse pctx;

  RETURN_IF_NULL_PARAM(szFileName);
  RETURN_IF_NULL_PARAM(szDocId);
  clearErrors();
  ddocDebug(3, "ddocSAXGetDataFile", "SigDoc: %s, docid: %s, digidoc: %s, keepb64: %d", 
	    (pSigDoc ? "OK" : "NULL"), szDocId, szFileName, bKeepBase64);
  // try reading from memory if already cached?
  pOutBuf->pMem = 0;
  pOutBuf->nLen = 0;
  ret = ddocGetDataFileCachedData(pSigDoc, szDocId, &(pOutBuf->pMem), &pOutBuf->nLen);
  if(pOutBuf->pMem) { // gotcha
    ddocDebug(3, "ddocSAXGetDataFile", "Using cached data: %d bytes", pOutBuf->nLen);
    return ret;
  }
  memset(&pctx, 0, sizeof(pctx));
  ddocConvertFileName( convFileName, sizeof(convFileName), szFileName );
  if ((f = fopen(convFileName, "r")) != NULL) {
    pctx.pSigDoc = NULL;
    pctx.bDataFile = NULL;
    pctx.ctx1[0] = pctx.ctx2[0] = pctx.ctx3[0] = pctx.tag[0] = pctx.ctx4[0] = 0;
    pctx.errcode = ERR_OK;
    pctx.bKeepBase64 = bKeepBase64;
    pOutBuf->pMem = 0;
    pOutBuf->nLen = 0;
    pctx.pMemBufDF = pOutBuf;
    time(&(pctx.tStartParse));
    pctx.bDataFile = NULL; //BIO_new_file(szDataFileName, "w");
    //strcpy(pctx.ctx1, szCharset);
    pctx.szInputFileName = (char*)szFileName;
    strncpy(pctx.ctx3, szDocId, sizeof(pctx.ctx3));
    memset(chars, 0, sizeof(chars));
    ret = fread(chars, 1, 100, f);
    if (ret > 0) {
      p = strstr(chars, "<?xml");
      if(!p)
	p = chars;
      ctxt = xmlCreatePushParserCtxt(extractSAXHandler, &pctx,
				     p, strlen(p), szFileName);
      do {
	memset(chars, 0, sizeof(chars));
	ret = fread(chars, 1, sizeof(chars)-1, f);
	if(ret <= 0) break;
    if(ret > 0 && ret < sizeof(chars)) chars[ret] = 0;
	if(pctx.bCollectDFData > 0) { // bypass mode
	  // look for new element start "<"
	  p = strchr(chars, '<');
	  // if we just enetered the bypass mode then send flush command
	  // but increment bypass mode in order not to fall out of it
	  if(pctx.bCollectDFData == 1 && !p) { // start bypass mode
	    pctx.bCollectDFData += 2; // increment with 2 so we dont return to flushing
	    ddocDebug(4, "ddocSAXGetDataFile", "Starting bypass mode, skip: %d", 
		      pctx.bCollectDFData);
	    // force the parser to release element content 
	    // before entering into bypass mode
	    xmlParseChunk(ctxt, g_szDataFileFlush1, strlen(g_szDataFileFlush1), 0);
	    ddocDebug(4, "ddocSAXGetDataFile", "Entering bypass mode, skip: %d", 
		      pctx.bCollectDFData);
	  }
	  if(pctx.bCollectDFData >=2 && !p) { // parse in bypass mode
	    ddocDebug(4, "ddocSAXGetDataFile", "Parsing in bypass mode, skip: %d len: %d", 
		      pctx.bCollectDFData, ret);
	    extractBodyHandler(&pctx, (const char*)chars, ret);
	  } 
	  if(p) { // finish bypass mode
	    ddocDebug(4, "ddocSAXGetDataFile", "Ending bypass mode len: %d, skip: %d", 
		      ret, pctx.bCollectDFData);
	    snprintf(buf1, sizeof(buf1), g_szDataFileFlush2, pctx.ctx3, pctx.ctx4);
	    // send finish command
	    xmlParseChunk(ctxt, buf1, strlen(buf1), 0);	
	    pctx.bCollectDFData = 1;	    
	    // parse the normal chunk that caused end
	    xmlParseChunk(ctxt, chars, ret, 0);
	  }
	} else { // normal mode
	  ddocDebug(4, "ddocSAXGetDataFile", "parsing normal chunk");
	  xmlParseChunk(ctxt, chars, ret, 0);
	}

      } while(ret > 0);
      xmlParseChunk(ctxt, chars, 0, 1);
      xmlFreeParserCtxt(ctxt);
    }
    fclose(f);
  } else {
    ddocDebug(1, "ddocSAXGetDataFile", "Error reading file: %s", szFileName);
    SET_LAST_ERROR_RETURN_CODE(ERR_FILE_READ);
  }
  if(!err)
    err = getLastError();
  // cleanup parser context
  ddocSAXCleanup(&pctx);
  return err;
}


//--------------------------------------------------
// Reads new signatures from another digidoc file
// and adds to existing digidoc. Adds only those
// signatures that don't exist in old digidoc.
// pSigDoc - signed document object
// szFileName - name of digidoc file
// returns error code or ERR_OK
//--------------------------------------------------
EXP_OPTION int ddocReadNewSignaturesFromDdoc(SignedDoc* pSigDoc, const char* szFileName)
{
  SignedDoc *pSigDoc2 = 0;
  int err = ERR_OK, n1 = 0, n2 = 0, i;
  SignatureInfo** pSignatures = NULL;

  RETURN_IF_NULL_PARAM(pSigDoc);
  RETURN_IF_NULL_PARAM(szFileName);
  // read in digidoc file
  err = ddocSaxReadSignedDocFromFile(&pSigDoc2, szFileName, 0, 0);
  if(err) {
    if(pSigDoc2) 
      SignedDoc_free(pSigDoc2);
    return err;
  }
  // copy new signatures from digidoc just read in
  // assumes that new signatures are at the end
  n1 = getCountOfSignatures(pSigDoc);
  n2 = getCountOfSignatures(pSigDoc2);
  if(n2 > n1) {
    pSignatures = (SignatureInfo**)realloc(pSigDoc->pSignatures, n2 * sizeof(void *));
    if(!pSignatures) {
      if(pSigDoc2) 
		SignedDoc_free(pSigDoc2);
      RETURN_IF_BAD_ALLOC(pSignatures);
    }
    pSigDoc->pSignatures = pSignatures;
    for(i = n1; i < n2; i++) {
      pSigDoc->pSignatures[i] = pSigDoc2->pSignatures[i]; // take ownership
      pSigDoc2->pSignatures[i] = 0; // set to NULL to prevent deallocation
	  // VS destroy hash - debug
	  ((char*)pSigDoc->pSignatures[i]->pDocs[0]->szDigest)[0] = 0x0A;
    }
    pSigDoc->nSignatures = n2;
    pSigDoc2->nSignatures = n1;
  }
  // delete new digidoc object no longer necessary
  SignedDoc_free(pSigDoc2);

  return err;
}
    
char* pHdr1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n";
char* pHdr2 = "<SignedDoc format=\"DIGIDOC-XML\" version=\"1.3\" xmlns=\"http://www.sk.ee/DigiDoc/v1.3.0#\">\n";
char* pHdr3 = "\n</SignedDoc>";
    
//--------------------------------------------------
// Adds new signature to existing ddoc
// szFileName - ddoc file name
// pSigBuf - buffer with new signature data
// nSigLen - new signature data length
//--------------------------------------------------
EXP_OPTION int ddocAddSignatureFromMemory(SignedDoc* pSigDoc, const char* szFileName, const void* pSigBuf, int nSigLen)
{
    int err = ERR_OK, n1 = 0, n2 = 0, i;
    SignatureInfo** pSignatures = NULL;
    SignedDoc *pSigDoc2 = 0;
    char buf1[102], *p1;
    FILE* f;
    DigiDocMemBuf mbuf1;
#ifdef WIN32
    wchar_t *convFileName = 0;
    int ret = 0;
#endif
    
    RETURN_IF_NULL_PARAM(pSigDoc);
    //RETURN_IF_NULL_PARAM(szFileName && strlen(szFileName));
    RETURN_IF_NULL_PARAM(pSigBuf);
    mbuf1.pMem = 0;
    mbuf1.nLen = 0;
    clearErrors();
    ddocDebug(3, "ddocAddSignatureFromMemory", "SigDoc: %s, file: %s, sig: %s, slen: %d", 
              (pSigDoc ? "OK" : "NULL"), szFileName, (pSigBuf ? "OK" : "NULL"), nSigLen);

    // read in digidoc buffer
    ddocMemAssignData(&mbuf1, pHdr1, -1);
    ddocMemAppendData(&mbuf1, pHdr2, -1);
    ddocMemAppendData(&mbuf1, pSigBuf, nSigLen);
    ddocMemAppendData(&mbuf1, pHdr3, -1);
    err = ddocSaxReadSignedDocFromMemory(&pSigDoc2, mbuf1.pMem, mbuf1.nLen, mbuf1.nLen);
    ddocMemBuf_free(&mbuf1);
    if(err) {
        ddocDebug(1, "ddocAddSignatureFromMemory", "Error: %d reading signature", err);
        if(pSigDoc2) 
            SignedDoc_free(pSigDoc2);
        return err;
    }
    // copy new signatures from digidoc just read in
    // assumes that new signatures are at the end
    n1 = getCountOfSignatures(pSigDoc);
    n2 = getCountOfSignatures(pSigDoc2);
    if(n2 > n1) {
        pSignatures = (SignatureInfo**)realloc(pSigDoc->pSignatures, n2 * sizeof(void *));
        if(!pSignatures) {
            if(pSigDoc2) 
                SignedDoc_free(pSigDoc2);
            RETURN_IF_BAD_ALLOC(pSignatures);
        }
        pSigDoc->pSignatures = pSignatures;
        for(i = n1; i < n2; i++) {
            pSigDoc->pSignatures[i] = pSigDoc2->pSignatures[i]; // take ownership
            pSigDoc2->pSignatures[i] = 0; // set to NULL to prevent deallocation
        }
        pSigDoc->nSignatures = n2;
        pSigDoc2->nSignatures = n1;
    }
    // delete new digidoc object no longer necessary
    SignedDoc_free(pSigDoc2);
    ddocDebug(3, "ddocAddSignatureFromMemory", "RC: %d adding signature", err);
    // now append new signature to existing ddoc file
    if(szFileName && strlen(szFileName)) { // if we have to update ddoc on disc
#ifdef WIN32
    err = utf82unicode((const char*)szFileName, (char**)&convFileName, &ret);
    ddocDebug(3, "ddocAddSignatureFromMemory", "file: %s, conv-file: %s", szFileName, convFileName);
    ddocDebug(3, "ddocSaxReadSignedDocFromFile", "Opening file: %s", convFileName);
    if(!err && ((f = _wfopen(convFileName, L"r+b")) != NULL)) {
#else
    ddocDebug(3, "ddocSaxReadSignedDocFromFile", "Opening file: %s", szFileName);
    if(!err && ((f = fopen(szFileName, "r+b")) != NULL)) {
#endif
        ddocDebug(3, "ddocSaxReadSignedDocFromFile", "file opened, pos: %d", ftell(f));
        // seek to file end -100 bytes anf find ddoc end tag
        err = fseek(f, -30, SEEK_END);
        ddocDebug(3, "ddocSaxReadSignedDocFromFile", "seek: %d new pos: %d", err, ftell(f));
        memset(buf1, 0, sizeof(buf1));
        n1 = fread(buf1, 1, 30, f);
        ddocDebug(3, "ddocSaxReadSignedDocFromFile", "read: %d data: %s", n1, buf1);
        p1 = strstr(buf1, "</SignedDoc>");
        if(p1) {
            *p1 = 0;
            n2 = strlen(buf1);
            ddocDebug(3, "ddocSaxReadSignedDocFromFile", "distance: %d", n2);
            err = fseek(f, -1 * (30 - n2), SEEK_END);
            ddocDebug(3, "ddocSaxReadSignedDocFromFile", "seek: %d new pos: %d", err, ftell(f));
            n1 = fwrite(pSigBuf, 1, nSigLen, f);
            ddocDebug(3, "ddocSaxReadSignedDocFromFile", "wrote: %d", n1);
            fputs("</SignedDoc>", f);
        }
        fclose(f);
    }
    } // if szFileName   
    return err;    
}

