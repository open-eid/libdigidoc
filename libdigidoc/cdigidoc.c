//==================================================
// FILE:	digidoc.c
// PROJECT:     Digi Doc
// DESCRIPTION: Utility program to demonstrate the
//   functionality of DigiDocLib
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
//      12.01.2004      Veiko Sinivee
//                      Creation
//==================================================

#include "config.h"
#include <libdigidoc/DigiDocDefs.h>
#include <libdigidoc/DigiDocLib.h>
#include <libdigidoc/DigiDocConfig.h>
#include <libdigidoc/DigiDocPKCS11.h>
#include <libdigidoc/DigiDocSAXParser.h>
#include <libdigidoc/DigiDocParser.h>
#include <libdigidoc/DigiDocEncSAXParser.h>
#include <libdigidoc/DigiDocEnc.h>
#include <libdigidoc/DigiDocEncGen.h>
#include <libdigidoc/DigiDocConvert.h>
#include <libdigidoc/DigiDocDebug.h>
#include <libdigidoc/DigiDocCert.h>
#include <libdigidoc/DigiDocObj.h>
#include <libdigidoc/DigiDocGen.h>
#include <libdigidoc/DigiDocService.h>
#include <libdigidoc/DigiDocDfExtract.h>

#ifdef WIN32
  #define snprintf  _snprintf
  #include <wchar.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/objects.h>
#include <sys/stat.h>
#include <time.h>

//==========< global constants >====================

// programm arguments
char* p_szInFile = 0;
char* p_szInEncFile = 0;
char* p_szInDecFile = 0;
char* p_szOutFile = 0;
char* p_szConfigFile = 0;
int p_parseMode = 1, g_nLibErrors = 0;

int g_cgiMode = 1;   // 1=output in CGI mode, 0=normal e.g. human readable mode
char* g_szOutputSeparator = 0;
char *errorClass[] = {"NO_ERRORS", "TECHNICAL", "USER", "LIBRARY"};
char* g_szProgNameVer = "cdigidoc/"DIGIDOC_VERSION;

//==========< forward defs >========================

void printErrorsAndWarnings(SignedDoc* pSigDoc);
int isWarning(SignedDoc* pSigDoc, int nErrCd);

//==========< helper functions for argument handling >====================



//--------------------------------------------------
// Handles one argument
//--------------------------------------------------
int checkArguments(int argc, char** argv, int* pCounter, char** dest)
{
  int nLen = 0;

  if(argc > (*pCounter)+1 && argv[(*pCounter)+1][0] != '-') {
    nLen = strlen(argv[(*pCounter)+1]) * 2;
    ddocConvertInput((const char*)argv[(*pCounter)+1], dest);
    (*pCounter)++;
  }
  return nLen;
}

//--------------------------------------------------
// checks the existence of one command line argument
//--------------------------------------------------
int hasCmdLineArg(int argc, char** argv, const char* argName)
{
  int i;

  for(i = 1; i < argc; i++) {
    if(argv[i] != NULL &&  argv[i][0] == '-' &&
       !strcmp(argv[i], argName)) {
      return i;
    }
  }
  return 0;
}

//--------------------------------------------------
// Returns the value of one command line argument
//--------------------------------------------------
int checkCmdLineArg(int argc, char** argv, const char* argName, char** dest)
{
  int i;

  *dest = 0; // mark as not found
  for(i = 1; i < argc; i++) {
    if(argv[i] != NULL &&  argv[i][0] == '-' &&
       !strcmp(argv[i], argName)) {
       if((i + 1 < argc) &&  (argv[i+1][0] != '-')) {
         ddocConvertInput((const char*)argv[i+1], dest);
         return 0;
       }
       else
         return ERR_BAD_PARAM;
    }
  }
  return 0; // not found but no error
}

//--------------------------------------------------
// prints usage statement
//--------------------------------------------------
void printUsage()
{
  fprintf(stderr, "USAGE: cdigidoc <command(s)> [-in <input-file>] [-out <output-file>] [-config <config-file>]\n");
  fprintf(stderr, "COMMANDS:\n");
  fprintf(stderr, "\t[-new] \n");
  fprintf(stderr, "\t-check-cert <-cerificate-file-name (PEM format)>\n");
  fprintf(stderr, "\t-add <file-name> <mime-type> [<content-type>] [<charset>]\n");
  fprintf(stderr, "\t-verify \n");
  fprintf(stderr, "\t-sign <pin> [[[<manifest>] [<city> <state> <zip> <country>]] [slot(0)] [ocsp(1)] [PKCS11/CNG/PKCS12] [pkcs12-file-name]]\n");
  fprintf(stderr, "\t-extract <doc-id> <file-name> [<charset>] [<file-name-charset>]\n");
  fprintf(stderr, "\t-encrypt <file-name>\n");
  fprintf(stderr, "\t-encrypt-sk <file-name>\n");
  fprintf(stderr, "\t-encrecv <cert-file> [<recipient>] [<keyname>] [<carried-key-name>]\n");
  fprintf(stderr, "\t-decrypt <file-name> <pin1> [pkcs12-file] [slot(0)]\n");
  fprintf(stderr, "\t-decrypt-sk <file-name> <pin1> [pkcs12-file] [slot(0)]\n");
  fprintf(stderr, "\t-denc-list <file-name>\n");
  fprintf(stderr, "\t-encrypt-file <in-file-name> <out-file-name> [<in-file-mime-type>]\n");
  fprintf(stderr, "\t-decrypt-file <in-file-name> <out-file-name> <pin1> [pkcs12-file]\n");

  fprintf(stderr, "\t-calc-sign <cert-file> [<manifest>] [<city> <state> <zip> <country>]\n");
  fprintf(stderr, "\t-add-sign-value <sign-value-file> <sign-id>\n");
  fprintf(stderr, "\t-del-sign <sign-id>\n");
  fprintf(stderr, "\t-get-confirmation <sign-id>\n");

  fprintf(stderr, "\t-mid-sign <phone-no> <per-code> [[<country>(EE)] [<lang>(EST)] [<service>(Testing)] [<manifest>] [<city> <state> <zip>]]\n");
  fprintf(stderr, "\t-mid-test <input-data-file> <input-mime-type> <output-ddoc> <phone-no> <per-code> [<service> (Testimine)]\n");

  fprintf(stderr, "\t-in-mem <file-name>\n");
  fprintf(stderr, "\t-add-mem <file-name> <mime-type> [<content-type>]\n");
  fprintf(stderr, "\t-out-mem <file-name>\n");
  fprintf(stderr, "\t-extract-mem <doc-id> <file-name>\n");

  fprintf(stderr, "OPTIONS:\n");
  fprintf(stderr, "\t-cgimode [<ouput-separator] - output in CGI mode\n");
  fprintf(stderr, "\t-consolemode - output in console (not cgi) mode\n");
  fprintf(stderr, "\t-SAX - use SAX parser\n");
  fprintf(stderr, "\t-libraryerrors - show all errors sent by library\n");
  fprintf(stderr, "\t-XRDR - use XmlReader parser\n");
}

//--------------------------------------------------
// Checks program runtime arguments
//--------------------------------------------------
int checkProgArguments(int argc, char** argv)
{
  int err = ERR_OK;

  // -?, -help -> print usage
  if(!err && (hasCmdLineArg(argc, argv, "-?") ||
     hasCmdLineArg(argc, argv, "-help")))
     printUsage();
  // -in <input-file>
  if(!err)
    if((err = checkCmdLineArg(argc, argv, "-in", &p_szInFile)) != ERR_OK)
      addError(err, __FILE__, __LINE__, "Missing or invalid input file name");
  // -in-mem <input-file>
  if(!err && hasCmdLineArg(argc, argv, "-in-mem")) {
    if((err = checkCmdLineArg(argc, argv, "-in-mem", &p_szInFile)) != ERR_OK) 
      addError(err, __FILE__, __LINE__, "Missing or invalid input file name");
	p_parseMode = 3;
  }
  // -SAX  -> use Sax parser (default)
  if(!err)
    if(hasCmdLineArg(argc, argv, "-SAX"))
      p_parseMode = 1;
  // -SAX  -> use Sax parser (default)
  if(!err)
    if(hasCmdLineArg(argc, argv, "-XRDR"))
      p_parseMode = 2;
  // -libraryerrors
  if(!err)
    if(hasCmdLineArg(argc, argv, "-libraryerrors"))
      g_nLibErrors = 1;
  // -out <out-file>
  if(!err)
    if((err = checkCmdLineArg(argc, argv, "-out", &p_szOutFile)) != ERR_OK)
      addError(err, __FILE__, __LINE__, "Missing or invalid output file name");
  if(!err && hasCmdLineArg(argc, argv, "-out-mem")) {
    if((err = checkCmdLineArg(argc, argv, "-out-mem", &p_szOutFile)) != ERR_OK)
      addError(err, __FILE__, __LINE__, "Missing or invalid output file name");
	  p_parseMode = 3;
  }
  // -encrypt <encryption-input-file>
  if(!err && hasCmdLineArg(argc, argv, "-encrypt"))
    if((err = checkCmdLineArg(argc, argv, "-encrypt", &p_szInEncFile)) != ERR_OK)
      addError(err, __FILE__, __LINE__, "Missing or invalid encrypt input file name");
  // -encrypt-sk <encryption-input-file>
  if(!err && hasCmdLineArg(argc, argv, "-encrypt-sk"))
    if((err = checkCmdLineArg(argc, argv, "-encrypt-sk", &p_szInEncFile)) != ERR_OK)
      addError(err, __FILE__, __LINE__, "Missing or invalid encrypt input file name");
  // -config <config-file>
  if(!err)
    if((err = checkCmdLineArg(argc, argv, "-config", &p_szConfigFile)) != ERR_OK)
      addError(err, __FILE__, __LINE__, "Missing or invalid configuration file name");
  // -CGI  -> use CGI output mode
  if(!err) 
    if(hasCmdLineArg(argc, argv, "-cgimode")) {
      g_cgiMode = 1;
      if((err = checkCmdLineArg(argc, argv, "-cgimode", &g_szOutputSeparator)) != ERR_OK) 
        addError(err, __FILE__, __LINE__, "Missing or invalid cgi output separator");
      if(!g_szOutputSeparator || !g_szOutputSeparator[0] || err) {
        g_szOutputSeparator = strdup("|");
        err = ERR_OK;
      }
    }
    if(hasCmdLineArg(argc, argv, "-consolemode")) {
      g_cgiMode = 0;
    }
  return err;
}

//--------------------------------------------------
// reads various statusflags from config file
//--------------------------------------------------
void readConfigParams()
{
  int n = 0;
  const char* s = 0;

  // check if we are in CGI mode
  n = ConfigItem_lookup_bool("DIGIDOC_CGI_MODE", 0);
  if(!g_cgiMode && n)
    g_cgiMode = n;

  s = ConfigItem_lookup("DIGIDOC_CGI_SEPARATOR");
  if(!g_szOutputSeparator && s)
    g_szOutputSeparator = (char*)strdup(s);
  if(!g_szOutputSeparator || !g_szOutputSeparator[0]) { 
	  if(g_szOutputSeparator) free(g_szOutputSeparator);
    g_szOutputSeparator = strdup("|");
  }
}


//==========< command handlers >====================

//--------------------------------------------------
// Creates a new signed doc
//--------------------------------------------------
int cmdNew(SignedDoc** ppSigDoc, const char* pFormat, const char* pVersion)
{
  int err = ERR_OK;
  const char* format = pFormat, *version = pVersion;

  if(!p_szOutFile) {
    err = ERR_BAD_PARAM;
    addError(err, __FILE__, __LINE__, "No output file specified");
    return err;
  }
  if(!format)
    format = "DIGIDOC-XML";
  if(!version)
    version = "1.3";
  if(format && version) {
     err = SignedDoc_new(ppSigDoc, format, version);
     RETURN_IF_NOT(err == ERR_OK, err);
  } else {
    err = ERR_UNSUPPORTED_FORMAT;
    addError(err, __FILE__, __LINE__, "Error finding new document format or version");
  }
  return err;
}



//--------------------------------------------------
// Adds a DataFile to signed doc
//--------------------------------------------------
int cmdAddDataFile(SignedDoc** ppSigDoc, const char* file, 
		   const char* mime, const char* content, const char* charset)
{
  int err = ERR_OK, l1;
  DataFile  *pDataFile;
  char *p = 0, buf1[300];

  // if there was no new command then implicitly create a new document
  if(!(*ppSigDoc)) {
    err = cmdNew(ppSigDoc, NULL, NULL);
    RETURN_IF_NOT(err == ERR_OK, err); 
  }
  // convert to UTF-8
  err = ddocConvertInput(file, &p);
  l1 = sizeof(buf1);
  getFullFileName(p, buf1, l1);
  freeLibMem(p);
  // add a file	
  err = DataFile_new(&pDataFile, *ppSigDoc, NULL, buf1, 
		     content, mime, 0, NULL, 0, NULL, charset);
  if(!err)
    err = calculateDataFileSizeAndDigest(*ppSigDoc, pDataFile->szId, buf1, DIGEST_SHA1);
  
  RETURN_IF_NOT(err == ERR_OK, err);
  return err;
}

//--------------------------------------------------
// Create digidoc and adds datafiles
//--------------------------------------------------
int runAddCmds(int argc, char** argv, SignedDoc** ppSigDoc)
{
  int err = ERR_OK, i;

  for(i = 1; (err == ERR_OK) && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // create new digidoc
      if(!strcmp(argv[i], "-new")) {
	    char* format = NULL;
	    char* version = NULL;
	    // optional content and charset
        checkArguments(argc, argv, &i, &format);
        checkArguments(argc, argv, &i, &version);
	    //printf("format: %s version: %s\n", format, version);
	   err = cmdNew(ppSigDoc, format, version);
	  freeLibMem(format);
	  freeLibMem(version);
	  RETURN_IF_NOT(err == ERR_OK, err);
	}
	// add a DataFile
	if(!strcmp(argv[i], "-add")) {
	  if(argc > i+2 && argv[i+1][0] != '-' && argv[i+2][0] != '-') {
	    char* file = argv[i+1];
	    char* mime = argv[i+2];
	    char* content = NULL;
	    char* charset = NULL;
	    i += 2;
	    // optional content and charset
        checkArguments(argc, argv, &i, &content);
        checkArguments(argc, argv, &i, &charset);
	    err = cmdAddDataFile(ppSigDoc, (const char*)file, (const char*)mime,
							 (const char*)(content ? content : CONTENT_EMBEDDED_BASE64), 
							 (const char*)(charset ? charset : CHARSET_UTF_8));
        freeLibMem(content);
        freeLibMem(charset);
	  } else {
	    err = ERR_BAD_PARAM;
	    addError(err, __FILE__, __LINE__, "Missing <file> and <mime-type> arguments of -add command");
	  }
      }
      
    }
  }
  return err;
}

//--------------------------------------------------
// Adds a DataFile to signed doc
//--------------------------------------------------
int cmdAddDataFileFromMem(SignedDoc** ppSigDoc, const char* file, 
		   const char* mime, const char* content)
{
  int err = ERR_OK;
  DataFile  *pDf = NULL;
  DigiDocMemBuf mbuf1;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;

  // if there was no new command then implicitly create a new document
  if(!(*ppSigDoc)) {
    err = cmdNew(ppSigDoc, NULL, NULL);
    RETURN_IF_NOT(err == ERR_OK, err); 
  }
  err = ddocReadFile(file, &mbuf1);
  if(!err)
    err = createDataFileInMemory(&pDf, *ppSigDoc, NULL, file, content, mime, mbuf1.pMem, mbuf1.nLen);
  ddocMemBuf_free(&mbuf1);
  return err;
}

//--------------------------------------------------
// Create digidoc and adds datafiles
//--------------------------------------------------
int runAddMemCmds(int argc, char** argv, SignedDoc** ppSigDoc)
{
  int err = ERR_OK, i;

  for(i = 1; (err == ERR_OK) && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // add a DataFile
      if(!strcmp(argv[i], "-add-mem")) {
	if(argc > i+2 && argv[i+1][0] != '-' && argv[i+2][0] != '-') {
	  char* file = argv[i+1];
	  char* mime = argv[i+2];
	  char* content = NULL;
	  i += 2;
	  // optional content and charset
      checkArguments(argc, argv, &i, &content);
	  err = cmdAddDataFileFromMem(ppSigDoc, (const char*)file, (const char*)mime,
                        (const char*)(content ? content : CONTENT_EMBEDDED_BASE64));
      freeLibMem(content);
	} else {
	  err = ERR_BAD_PARAM;
	  addError(err, __FILE__, __LINE__, "Missing <file> and <mime-type> arguments of -add-mem command");
	}
      }
      
    }
  }
  return err;
}

//--------------------------------------------------
// Create digidoc and adds datafiles
//--------------------------------------------------
/*int runAddSignValue(int argc, char** argv, SignedDoc** ppSigDoc)
{
  int err = ERR_OK, i;

  for(i = 1; (err == ERR_OK) && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // create new digidoc
      if(!strcmp(argv[i], "-addsignvalue")) {
		char* infile = NULL;
		char* sigid = NULL;
		char* sigvalf = NULL;
	  checkArguments(argc, argv, &i, &infile);
      checkArguments(argc, argv, &i, &sigid);
	  checkArguments(argc, argv, &i, &sigvalf);
		err = cmdReadDigiDoc(ppSigDoc, 0, 1);

      }
      // add a DataFile
      if(!strcmp(argv[i], "-addsignvalue")) {
	if(argc > i+2 && argv[i+1][0] != '-' && argv[i+2][0] != '-') {
	  char* file = argv[i+1];
	  char* mime = argv[i+2];
	  char* content = CONTENT_EMBEDDED_BASE64;
	  char* charset = CHARSET_UTF_8;
	  i += 2;
	  // optional content and charset
      checkArguments(argc, argv, &i, &content);
      checkArguments(argc, argv, &i, &charset);
	  err = cmdAddDataFile(ppSigDoc, (const char*)file, (const char*)mime,
			       (const char*)content, (const char*)charset);
	} else {
      err = ERR_BAD_PARAM;
      addError(err, __FILE__, __LINE__, "Missing <in-digidoc> and <sig-id> or <sign-value-file> arguments of -addsignvalue command");
      }
      
    }
  }
  return err;
}*/

//--------------------------------------------------
// Add ecryption recipients
//--------------------------------------------------
int runRecipientCmds(int argc, char** argv, DEncEncryptedData** ppEncData)
{
  int err = ERR_OK, i, rb = 0;
  DEncEncryptedKey* pEncKey = 0;
  X509* pCert = 0;
  DigiDocMemBuf mbuf1;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  for(i = 1; (err == ERR_OK) && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // add a recipients key
      if(!strcmp(argv[i], "-encrecv")) {
	if(argc > i+1 && argv[i+1][0] != '-') {
	  char* certfile = argv[i+1];
	  char* recipient = NULL;
	  char* keyname = NULL;
	  char* carriedkeyname = NULL;
	  char* id = NULL;
	  i++;
	  if(!(*ppEncData))
	    err = dencEncryptedData_new(ppEncData, DENC_XMLNS_XMLENC, DENC_ENC_METHOD_AES128, 0, 0, 0);
      if(!err) {
	      err = dencMetaInfo_SetLibVersion(*ppEncData);
          if(!err) {
              err = dencMetaInfo_SetFormatVersion(*ppEncData);
              if(!err) {
                  // optional arguments
                  checkArguments(argc, argv, &i, &recipient);
                  checkArguments(argc, argv, &i, &keyname);
                  checkArguments(argc, argv, &i, &carriedkeyname);
                  err = ReadCertificate(&pCert, certfile);
                  if(!err) {
                      if(!recipient) {
                          ddocCertGetSubjectCN(pCert, &mbuf1);
                          recipient = (char*)mbuf1.pMem;
                          rb = 1;
                      }
                      err = dencEncryptedKey_new(*ppEncData, &pEncKey, pCert,
                                                 DENC_ENC_METHOD_RSA1_5,
                                                 id, recipient, keyname, carriedkeyname);
                      if(rb) recipient = NULL; // was not malloc separately from mbuf1
                  }
              }
          }
      }
	  ddocMemBuf_free(&mbuf1);
      freeLibMem(recipient);
      freeLibMem(keyname);
      freeLibMem(carriedkeyname);
	} else {
	  err = ERR_BAD_PARAM;
	  addError(err, __FILE__, __LINE__, "Missing <cert-file> argument of -encrecv command");
	}
      }
    }
  }
  return err;
}


unsigned char* findFileExt(unsigned char* szFileName)
{
    int i = 0;
    
    if(szFileName && strlen(szFileName) > 0) {
        for(i = strlen(szFileName)-1; (i > 0) && (szFileName[i] != '.'); i--);
        if(szFileName[i] == '.')
            return szFileName + i + 1;
    }
    return 0;
}

int checkOldFormatVer(SignedDoc* pSigDoc)
{
    if(!pSigDoc || !pSigDoc->szFormat || !pSigDoc->szFormatVer) {
        addError(ERR_BAD_PARAM, __FILE__, __LINE__, "Format or version not specified");
        return ERR_BAD_PARAM;
    }
    if(!strcmp(pSigDoc->szFormat, SK_XML_1_NAME) || 
       (!strcmp(pSigDoc->szFormat, DIGIDOC_XML_1_1_NAME) && 
        (!strcmp(pSigDoc->szFormatVer, DIGIDOC_XML_1_1_VER) ||
         !strcmp(pSigDoc->szFormatVer, DIGIDOC_XML_1_2_VER)))) {
            SET_LAST_ERROR(ERR_OLD_VERSION);
            return ERR_OLD_VERSION;
    }
    return ERR_OK;
}

//--------------------------------------------------
// reads in a signed doc
//--------------------------------------------------
int cmdReadDigiDoc(SignedDoc** ppSigDoc, DEncEncryptedData** ppEncData, int nMode)
{
  int err = ERR_OK, e;
  int nMaxDfLen;
    unsigned char* pExt = 0;
  if(!p_szInFile) {
    err = ERR_BAD_PARAM;
    addError(err, __FILE__, __LINE__, "No input file specified");
    return err;
  }
  nMaxDfLen = ConfigItem_lookup_int("DATAFILE_MAX_CACHE", 0);
  pExt = findFileExt(p_szInFile);
    //printf("Read file: %s - ext: %s", p_szInFile, pExt);
  if(pExt && strcmp(pExt, "cdoc") == 0) {
    err = dencSaxReadEncryptedData(ppEncData, p_szInFile);
  } else if(pExt && strcmp(pExt, "ddoc") == 0) {
    switch(nMode) {
    case 2: // new XMLReader interface
      //err = ddocXRdrReadSignedDocFromFile(p_szInFile, CHARSET_ISO_8859_1, ppSigDoc, nMaxDfLen);
      break;
    case 1:
    default:
      err = ddocSaxReadSignedDocFromFile(ppSigDoc, p_szInFile, 0, nMaxDfLen);
    }
  } else {
      err = ERR_FILE_READ;
  }
  e = checkOldFormatVer(*ppSigDoc);
  if(!err && e) err = e;
  printErrorsAndWarnings(*ppSigDoc);
  return err;
}

//--------------------------------------------------
// reads in a signed doc
//--------------------------------------------------
int cmdReadDigiDocFromMem(SignedDoc** ppSigDoc, DEncEncryptedData** ppEncData)
{
  int err = ERR_OK, e;
  DigiDocMemBuf mbuf1;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  if(!p_szInFile) {
    err = ERR_BAD_PARAM;
    addError(err, __FILE__, __LINE__, "No input file specified");
    return err;
  }
  //nMaxDfLen = ConfigItem_lookup_int("DATAFILE_MAX_CACHE", 0);
  
  if(strstr(p_szInFile, ".cdoc")) {
    err = ddocReadFile(p_szInFile, &mbuf1);
    if(!err)
      err = dencSaxReadEncryptedDataFromMemory(ppEncData, &mbuf1);
  } else {
    err = ddocReadFile(p_szInFile, &mbuf1);
    if(!err)
	  err = ddocSaxReadSignedDocFromMemory(ppSigDoc, mbuf1.pMem, mbuf1.nLen, mbuf1.nLen + 1); 
  }
  ddocMemBuf_free(&mbuf1);
  e = checkOldFormatVer(*ppSigDoc);
  printErrorsAndWarnings(*ppSigDoc);
  if(!err && e) err = e;
  return err;
}

//--------------------------------------------------
// writes a digidoc in file
//--------------------------------------------------
int cmdWrite(SignedDoc* pSigDoc, DEncEncryptedData* pEncData)
{
  int err = ERR_OK;
  FILE* hFile;
#ifdef WIN32
  wchar_t *convFileName = 0;
  int l1 = 0;
#endif
  
  if(!p_szOutFile) {
    err = ERR_BAD_PARAM;
    addError(err, __FILE__, __LINE__, "No output file specified");
    return err;
  }
  if(pSigDoc)
    err = createSignedDoc(pSigDoc, p_szInFile, p_szOutFile);
  if(pEncData) {
    if(pEncData->nDataStatus == DENC_DATA_STATUS_ENCRYPTED_AND_NOT_COMPRESSED ||
       pEncData->nDataStatus == DENC_DATA_STATUS_ENCRYPTED_AND_COMPRESSED) {
      err = dencGenEncryptedData_writeToFile(pEncData, p_szOutFile);
    } else {
#ifdef WIN32
       err = utf82unicode((const char*)p_szOutFile, (char**)&convFileName, &l1);
       ddocDebug(3, "cmdWrite", "Writing file: %s, conv-file: %s len: %d", p_szOutFile, convFileName, l1);
       if((hFile = _wfopen(convFileName, L"wb")) != NULL) {
#else
      if((hFile = fopen(p_szOutFile, "wb")) != NULL) {
#endif
	fwrite((pEncData)->mbufEncryptedData.pMem, 1, 
	       (pEncData)->mbufEncryptedData.nLen, hFile);
	fclose(hFile);
      }
      else
	err = ERR_FILE_WRITE;
    }
  }
  if (err)
    addError(err, __FILE__, __LINE__, "Error writing file\n");
  return err;
}

//--------------------------------------------------
// writes a digidoc in file
//--------------------------------------------------
int cmdWriteMem(SignedDoc* pSigDoc, DEncEncryptedData* pEncData)
{
  int err = ERR_OK;
  DigiDocMemBuf mbuf1;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  if(!p_szOutFile) {
    err = ERR_BAD_PARAM;
    addError(err, __FILE__, __LINE__, "No output file specified");
    return err;
  }
  if(pSigDoc) {
    err = createSignedDocInMemory(pSigDoc, NULL, &mbuf1);
    if(!err)
		 err = ddocWriteFile(p_szOutFile, &mbuf1);
  }
  if(pEncData) {
    if(pEncData->nDataStatus == DENC_DATA_STATUS_ENCRYPTED_AND_NOT_COMPRESSED ||
       pEncData->nDataStatus == DENC_DATA_STATUS_ENCRYPTED_AND_COMPRESSED) {
       err = dencGenEncryptedData_toXML(pEncData, &mbuf1);
        if(!err)
            err = ddocWriteFile(p_szOutFile, &mbuf1);
    } else {
        err = ddocWriteFile(p_szOutFile, &(pEncData->mbufEncryptedData));
    }
  }
  ddocMemBuf_free(&mbuf1);
  if (err)
    addError(err, __FILE__, __LINE__, "Error writing file\n");
  return err;
}


//-----------------------------------------
// prints certificate info
//-----------------------------------------
void printCertificateInfo(SignedDoc* pSigDoc, X509* pCert)
{
  int err, p;
  char buf1[500];
  PolicyIdentifier* pPolicies;
  DigiDocMemBuf mbuf;
  int nPols;

  mbuf.pMem = 0;
  mbuf.nLen = 0;
  // serial number
  err = ReadCertSerialNumber(buf1, sizeof(buf1), pCert);
  if(g_cgiMode)
    fprintf(stdout, "\nX509Certificate%s%s",  g_szOutputSeparator, buf1);
  else
    fprintf(stdout, "\nX509Certificate nr: %s",  buf1);
  // issuer
  err = ddocCertGetIssuerDN(pCert, &mbuf);
  if(g_cgiMode)
    fprintf(stdout, "%s%s",  g_szOutputSeparator, (char*)mbuf.pMem);
  else
    fprintf(stdout, "\n\tIssuer: %s", (char*)mbuf.pMem);
  ddocMemBuf_free(&mbuf);
  // subject
  err = ddocCertGetSubjectDN(pCert, &mbuf);
  if(g_cgiMode)
    fprintf(stdout, "%s%s",  g_szOutputSeparator, (char*)mbuf.pMem);
  else
    fprintf(stdout, "\n\tSubject: %s", (char*)mbuf.pMem);
  ddocMemBuf_free(&mbuf);
  // ValidFrom
  memset(buf1, 0, sizeof(buf1));
  err = getCertNotBefore(pSigDoc, pCert, buf1, sizeof(buf1));
  if(g_cgiMode)
    fprintf(stdout, "%s%s",  g_szOutputSeparator, buf1);
  else
    fprintf(stdout, "\n\tNotBefore: %s", buf1);
  // ValidTo
  memset(buf1, 0, sizeof(buf1));
  err = getCertNotAfter(pSigDoc, pCert, buf1, sizeof(buf1));
  if(g_cgiMode)
    fprintf(stdout, "%s%s",  g_szOutputSeparator, buf1);
  else
    fprintf(stdout, "\n\tNotAfter: %s",  buf1);
  // policy URL
  err = readCertPolicies(pCert, &pPolicies, &nPols);
  if(nPols) {
    for(p = 0; p < nPols; p++) {
      if(g_cgiMode)
	fprintf(stdout, "\nSignaturePolicy%s%s%s%s%s%s",  
		g_szOutputSeparator, pPolicies[p].szOID,
		g_szOutputSeparator, pPolicies[p].szCPS,
		g_szOutputSeparator, pPolicies[p].szUserNotice);
      else
	fprintf(stdout, "\n\tnSignaturePolicy oid: %s cps: %s desc: %s",  pPolicies[p].szOID,
		pPolicies[p].szCPS, pPolicies[p].szUserNotice);
    } // for p < nPols
  } 
  PolicyIdentifiers_free(pPolicies, nPols);
  
}
    
char* TEST_OIDS_PREFS[] = {
		"1.3.6.1.4.1.10015.3.7", "1.3.6.1.4.1.10015.7", // tempel test
		"1.3.6.1.4.1.10015.3.3", "1.3.6.1.4.1.10015.3.11", // mid test
		"1.3.6.1.4.1.10015.3.2", // digi-id test
		"1.3.6.1.4.1.10015.3.1" // est-eid test
};
    
int checkTestCert(X509* pCert)
{
    int err = ERR_OK, i, p;
    PolicyIdentifier* pPolicies = NULL;
    DigiDocMemBuf mbuf;
    int nPols = 0;

    mbuf.pMem = 0;
    mbuf.nLen = 0;
    ddocCertGetSubjectCN(pCert, &mbuf);
    /*if(mbuf.pMem && strstr(mbuf.pMem, "TEST")) {
        printf("\n Test CN: %s", (char*)(mbuf.pMem));
        err = ERR_TEST_SIGNATURE;
    }*/
    err = readCertPolicies(pCert, &pPolicies, &nPols);
    if(!err && nPols && !err) {
        for(p = 0; p < nPols; p++) {
            //printf("\nOID: %s", pPolicies[p].szOID);
            for(i = 0; i < 6 && !err; i++) {
                if(i == 1 && // tempel - test
                   strstr(pPolicies[p].szOID, TEST_OIDS_PREFS[1]) &&
                   strstr(mbuf.pMem, "TEST")) { 
                    //printf("\nTempel-Test OID: %s", TEST_OIDS_PREFS[i]);
                    err = ERR_TEST_SIGNATURE;
                } else if(i != 1) {
                  if(strstr(pPolicies[p].szOID, TEST_OIDS_PREFS[i])) {
                    //printf("\nTest OID: %s", TEST_OIDS_PREFS[i]);
                   err = ERR_TEST_SIGNATURE;
                  }
                }
            }
        }
    }
    ddocMemBuf_free(&mbuf);
    PolicyIdentifiers_free(pPolicies, nPols);
    if(err == ERR_TEST_SIGNATURE)
        SET_LAST_ERROR(ERR_TEST_SIGNATURE);
    return err;
}
    

int isError(SignedDoc* pSigDoc, int nErrCd)
{
    return (nErrCd != ERR_OK && !isWarning(pSigDoc, nErrCd));
}

int isWarning(SignedDoc* pSigDoc, int nErrCd)
{
    if(pSigDoc && pSigDoc->szFormat && !strcmp(pSigDoc->szFormat, SK_XML_1_NAME)) {
        // currently no warnings for ddoc 1.0
        return (nErrCd == ERR_OLD_VERSION) || (nErrCd == ERR_TEST_SIGNATURE);
    } else {
      return ((nErrCd == ERR_ISSUER_XMLNS) ||
              (nErrCd == ERR_OLD_VERSION) ||
              (nErrCd == ERR_TEST_SIGNATURE) ||
              (nErrCd == ERR_DF_WRONG_DIG)                    
             );
    }
}
    
int isLibraryError(int nErrCd)
{
    return (nErrCd != ERR_OK && 
            nErrCd != ERR_OLD_VERSION &&
            nErrCd != ERR_TEST_SIGNATURE &&
            nErrCd != ERR_UNSUPPORTED_FORMAT);
}
    
int hasWarnings(SignedDoc* pSigDoc)
{
    int n;
    ErrorInfo* pErr;
    
    for(n = getLastErrorsIdx(); n >= 0; n--) {
        pErr = getErrorsInfo(n);
        if(isWarning(pSigDoc, pErr->code))
            return pErr->code;
    }
    return ERR_OK;
}

int hasErrors(SignedDoc* pSigDoc)
{
    int n;
    ErrorInfo* pErr;
        
    for(n = getLastErrorsIdx(); n >= 0; n--) {
        pErr = getErrorsInfo(n);
        if(isError(pSigDoc, pErr->code))
                return pErr->code;
    }
    return ERR_OK;
}

void printErrorsAndWarnings(SignedDoc* pSigDoc)
{
    int n, m = getLastErrorsIdx();
    ErrorInfo* pErr;
    char* pErrStr;
    
    // list all errors
    if(g_cgiMode) {
        /*for(n = 0; n < m; n++) {
            pErr = getErrorsInfo(n);
            pErrStr = getErrorString(pErr->code);
            printf("\nErr: %d cd: %d msg: %s", n, pErr->code, pErrStr);
        }*/
        for(n = m; n >= 0; n--) {
            pErr = getErrorsInfo(n);
            pErrStr = getErrorString(pErr->code);
            if(isError(pSigDoc, pErr->code))
                fprintf(stdout, "\nERROR%s%d%s%s%s%s%s%d%s%s%s%s",
                            g_szOutputSeparator, pErr->code,
                            g_szOutputSeparator, pErrStr,
                            g_szOutputSeparator, pErr->fileName,
                            g_szOutputSeparator, pErr->line,
                            g_szOutputSeparator, pErr->assertion,
                            g_szOutputSeparator, errorClass[getErrorClass(pErr->code)]);
        }
        for(n = m; n >= 0; n--) {
            pErr = getErrorsInfo(n);
            pErrStr = getErrorString(pErr->code);
            if(isWarning(pSigDoc, pErr->code))
                fprintf(stdout, "\nWARNING%s%d%s%s%s%s%s%d%s%s%s%s",
                        g_szOutputSeparator, pErr->code,
                        g_szOutputSeparator, pErrStr,
                        g_szOutputSeparator, pErr->fileName,
                        g_szOutputSeparator, pErr->line,
                        g_szOutputSeparator, pErr->assertion,
                        g_szOutputSeparator, errorClass[getErrorClass(pErr->code)]);
        }
        if(g_nLibErrors) {
            for(n = m; n >= 0; n--) {
                pErr = getErrorsInfo(n);
                if(isLibraryError(pErr->code)) {
                pErrStr = getErrorString(pErr->code);
                fprintf(stdout, "\nLIBRARY-ERROR%s%d%s%s%s%s%s%d%s%s%s%s",
                            g_szOutputSeparator, pErr->code,
                            g_szOutputSeparator, pErrStr,
                            g_szOutputSeparator, pErr->fileName,
                            g_szOutputSeparator, pErr->line,
                            g_szOutputSeparator, pErr->assertion,
                            g_szOutputSeparator, errorClass[getErrorClass(pErr->code)]);
                }
            } 
        }
    } else {
        for(n = m; n >= 0; n--) {
            pErr = getErrorsInfo(n);
            pErrStr = getErrorString(pErr->code);
            if(isError(pSigDoc, pErr->code))
                fprintf(stdout, "\nERROR: %d - %s - %s",
                            pErr->code, pErrStr, pErr->assertion);
            if(isWarning(pSigDoc, pErr->code))
                fprintf(stdout, "\nWARNING: %d - %s - %s",
                            pErr->code, pErrStr, pErr->assertion);
        }
    }
}
    
    
//--------------------------------------------------
// Verifys sigantures and notaries
//--------------------------------------------------
int cmdVerify(SignedDoc* pSigDoc)
{
  int err = ERR_OK, s, d, l, m, l1, e, e2, n1, e3;
  SignatureInfo* pSigInfo = 0;
  NotaryInfo* pNot;
  DataFile *pDf = 0;
  DigiDocMemBuf mbuf;
  X509* pRcert = 0;
  const DigiDocMemBuf* pMBuf = 0;
  char buf1[100], *p1 = 0;

  mbuf.pMem = 0;
  mbuf.nLen = 0;
  if(!pSigDoc) {
      SET_LAST_ERROR(ERR_UNSUPPORTED_FORMAT);
      return ERR_UNSUPPORTED_FORMAT;
    }
  // print signed doc format and version
  if(g_cgiMode) {
        fprintf(stdout, "\nSignedDoc%s%s%s%s",
                g_szOutputSeparator,
                pSigDoc->szFormat, g_szOutputSeparator,
                pSigDoc->szFormatVer);
  } else {
        fprintf(stdout, "\nSignedDoc format: %s version: %s\n", 
                pSigDoc->szFormat, pSigDoc->szFormatVer);
  }
  // display DataFile-s
  d = getCountOfDataFiles(pSigDoc);
  for(l = 0; l < d; l++) {
    pDf = getDataFile(pSigDoc, l);
      ddocGetDataFileFilename(pSigDoc, pDf->szId, (void**)&p1, &n1);
    if(g_cgiMode)
        fprintf(stdout, "\n\nDataFile%s%s%s%s%s%ld%s%s%s%s",
                    g_szOutputSeparator, pDf->szId, g_szOutputSeparator,
                    p1, g_szOutputSeparator,
                    pDf->nSize, g_szOutputSeparator,
                    pDf->szMimeType, g_szOutputSeparator,
                    pDf->szContentType);
    else
        fprintf(stdout, "\n\nDataFile: %s, file: %s, size: %ld, mime-type: %s content-type: %s",
                    pDf->szId, p1, pDf->nSize, pDf->szMimeType, pDf->szContentType);
      if(p1)
          freeLibMem(p1);
  }

    
  // verify signatures
  d = getCountOfSignatures(pSigDoc);
  for(s = 0; s < d; s++) {
    pSigInfo = getSignature(pSigDoc, s);
    e = ddocCertGetSubjectCN(ddocSigInfo_GetSignersCert(pSigInfo), &mbuf);
    clearErrors();
    e = verifySignatureAndNotary(pSigDoc, pSigInfo, p_szInFile);
    if(!e)
      e = hasErrors(pSigDoc);
    if(!err && e) err = e;
    e2 = checkTestCert(ddocSigInfo_GetSignersCert(pSigInfo));
    if(!err && e2) err = e2;
    if(!e && e2) e = e2;
    if(g_cgiMode) {
      fprintf(stdout, "\n\nSignature%s%s%s%s%s%d%s%s",
	      g_szOutputSeparator, 
	      pSigInfo->szId, 
	      g_szOutputSeparator,
	      (const char*)mbuf.pMem, 
	      g_szOutputSeparator,
          e, 
	      g_szOutputSeparator,
          (e ? getErrorString(e) : ""));
    } else {
      fprintf(stdout, "\n\nSignature: %s - %s - %s", pSigInfo->szId, 
	      (const char*)mbuf.pMem, ((!e) ? "OK" : "ERROR"));
    }
    ddocMemBuf_free(&mbuf);
    // print signers roles / manifests
    m = getCountOfSignerRoles(pSigInfo, 0);
    for(l = 0; l < m; l++) {
      if(g_cgiMode)
        fprintf(stdout, "\nClaimedRole%s%s", g_szOutputSeparator, getSignerRole(pSigInfo, 0, l));
      else
        fprintf(stdout, "\n\tClaimedRole: %s", getSignerRole(pSigInfo, 0, l));
    }
    if(pSigInfo->sigProdPlace.szCity || pSigInfo->sigProdPlace.szStateOrProvince ||
       pSigInfo->sigProdPlace.szPostalCode || pSigInfo->sigProdPlace.szCountryName) {
      if(g_cgiMode) {
        fprintf(stdout, "\nSignatureProductionPlace%s%s%s%s%s%s%s%s", g_szOutputSeparator,
		(pSigInfo->sigProdPlace.szCountryName ? pSigInfo->sigProdPlace.szCountryName : ""), 
		g_szOutputSeparator,
		(pSigInfo->sigProdPlace.szStateOrProvince ? pSigInfo->sigProdPlace.szStateOrProvince : ""), 
		g_szOutputSeparator,
		(pSigInfo->sigProdPlace.szCity ? pSigInfo->sigProdPlace.szCity : ""), 
		g_szOutputSeparator,
		(pSigInfo->sigProdPlace.szPostalCode ? pSigInfo->sigProdPlace.szPostalCode : ""));
      } else {
        fprintf(stdout, "\n\tnSignatureProductionPlace - Country: %s, State: %s, City: %s, Postal code: %s",
		(pSigInfo->sigProdPlace.szCountryName ? pSigInfo->sigProdPlace.szCountryName : ""),
		(pSigInfo->sigProdPlace.szStateOrProvince ? pSigInfo->sigProdPlace.szStateOrProvince : ""),
		(pSigInfo->sigProdPlace.szCity ? pSigInfo->sigProdPlace.szCity : ""),
		(pSigInfo->sigProdPlace.szPostalCode ? pSigInfo->sigProdPlace.szPostalCode : ""));
      }
  }
  // signers certificate
  if(ddocSigInfo_GetSignersCert(pSigInfo))
    printCertificateInfo(pSigDoc, ddocSigInfo_GetSignersCert(pSigInfo));
  // confirmation
  if(pSigDoc && pSigInfo) {
    pNot = getNotaryWithSigId(pSigDoc, pSigInfo->szId);
    if(pNot) {
    pMBuf = ddocNotInfo_GetResponderId(pNot);
    buf1[0] = 0;
    l1 = sizeof(buf1);
    if(pNot->nRespIdType == RESPID_NAME_TYPE) {
      strncpy(buf1, (const char*)pMBuf->pMem, l1);
    }
    if(pNot->nRespIdType == RESPID_KEY_TYPE) {
      encode((const byte*)pMBuf->pMem, pMBuf->nLen, (byte*)buf1, &l1);
    }
    }
    if(pNot && pMBuf) {
      if(g_cgiMode)
	fprintf(stdout, "\nRevocationValues%s%s%s%s",  
		g_szOutputSeparator, 
		buf1,
		g_szOutputSeparator, 
		pNot->timeProduced);
      else
	fprintf(stdout, "\n\tRevocationValues responder: %s produced-at: %s",  
		buf1, pNot->timeProduced);
      // certificate
      pRcert = ddocSigInfo_GetOCSPRespondersCert(pSigInfo);
      e3 = checkTestCert(pRcert);
      if(!e2 && e3) { // live allkirjastaja sert aga test ocsp
          fprintf(stdout, "\n\tSigner from LIVE CA-chain but OCSP from TEST CA-chain!");
          err = e3;
          SET_LAST_ERROR(e3);
      }
      printCertificateInfo(pSigDoc, pRcert);
    }
  }
      printErrorsAndWarnings(pSigDoc);
  }
  return err;
}


//--------------------------------------------------
// Signs the document and gets configrmation
//--------------------------------------------------
int cmdSign(SignedDoc* pSigDoc, const char* pin, const char* manifest,
			const char* city, const char* state, const char* zip, const char* country, 
			int nSlot, int nOcsp, int nSigner, const char* szPkcs12File)
{
  int err = ERR_OK;
  SignatureInfo* pSigInfo = NULL;
	
  ddocDebug(3, "cmdSign", "Creating new digital signature");
  err = signDocumentWithSlotAndSigner(pSigDoc, &pSigInfo, pin, manifest, 
	  city, state, zip, country, nSlot, nOcsp, nSigner, szPkcs12File);
    ddocDebug(3, "cmdSign", "End creating new digital signature");
  RETURN_IF_NOT(err == ERR_OK, err);
  return ERR_OK;
}






//#ifdef WITH_DEPRECATED_FUNCTIONS
//--------------------------------------------------
// Runs some test. This is used simply to test
// new features of the library and the functionality
// may change.
//--------------------------------------------------
void cmdTest2(const char* infile)
{
  X509* pCert = 0;
  //char buf1[X509_NAME_LEN + 10];
  int err = ERR_OK, nPols = 0;
  PolicyIdentifier *pPolicies = 0;

  ddocDebug(3, "cmdTest2", "Reading cert: %s", infile);
  err = ReadCertificate(&pCert, infile);
  if(!err && pCert) {
    err = readCertPolicies(pCert, &pPolicies, &nPols);
	printf("Read pols rc: %d pols: %d\n", err, nPols);

	  /*
    l1 = sizeof(buf1);
    memset(buf1, 0, sizeof(buf1));
    err = getCertSubjectName(pCert, buf1, &l1);
    if(g_cgiMode)
      fprintf(stdout, "\nDN%s%s%s%d",  
	      g_szOutputSeparator, buf1,
	      g_szOutputSeparator, l1);
    else
      fprintf(stdout, "\nDN: %s len: %d", buf1, l1);
	  */
  }
  if(pCert)
    X509_free(pCert);
  if(pPolicies)
      PolicyIdentifiers_free(pPolicies, nPols);
}
//#endif

//--------------------------------------------------
// Encrypts a file
//--------------------------------------------------
int cmdEncrypt(DEncEncryptedData** ppEncData, const char* szFileName) 
{
  FILE* hFile;
  SignedDoc *pSigDoc = 0;
  DEncEncryptionProperty* pEncProperty = 0;
  int len, err = ERR_OK, i = 0;
    long lFileLen;
  char buf[2048], *p = 0;
#ifdef WIN32
    wchar_t *convFileName = 0;
    err = utf82unicode((const char*)szFileName, (char**)&convFileName, &i);
#endif

  ddocDebug(3, "cmdEncrypt", "Encrypting %s rc: %d", szFileName, err);
  err = dencEncryptedData_new(ppEncData, DENC_XMLNS_XMLENC, DENC_ENC_METHOD_AES128, 0, 0, 0);
  if(!err) {
    err = dencMetaInfo_SetLibVersion(*ppEncData);
    if(!err) {
      err = dencMetaInfo_SetFormatVersion(*ppEncData);
      if(!err) {
        err = ddocConvertInput(szFileName, &p);
        if(!err) {
          err = dencEncryptionProperty_new(*ppEncData, &pEncProperty, 
                    0, 0, ENCPROP_FILENAME, getSimpleFileName(p));
          if(strstr(p, ".bdoc") || strstr(p, ".asice")) 
            err = dencEncryptedData_SetMimeType(*ppEncData, "application/vnd.etsi.asic-e+zip");
          err = calculateFileSize(szFileName, &lFileLen);
          sprintf(buf, "%ld", lFileLen);
          err = dencEncryptionProperty_new(*ppEncData, &pEncProperty, 
                            0, 0, ENCPROP_ORIG_SIZE, buf);
          freeLibMem(p);
          if(!err) {
            ddocDebug(3, "cmdEncrypt", "Opening %s rc: %d", szFileName, err);
#ifdef WIN32
  if((hFile = _wfopen(convFileName, L"rb")) != NULL) {
#else
  if((hFile = fopen(szFileName, "rb")) != NULL) {
#endif
    do {
      memset(buf,0,sizeof(buf));
      len = fread(buf, 1, sizeof(buf), hFile);
      if(len) 
	    err = dencEncryptedData_AppendData(*ppEncData, buf, len);
    } while(len && !err);
    fclose(hFile);
  } // if fopen/wfopen
  ddocDebug(3, "cmdEncrypt", "Enc data-len: %d rc: %d", (*ppEncData)->mbufEncryptedData.nLen, err);
      if(!err)
          err = dencEncryptedData_encryptData(*ppEncData, DENC_COMPRESS_NEVER);
          } // err - endProp_new
        } // err - conver filename
      } // err - serFormatVer
    } // err - setLibVer
  } // err - dencEncData_new
  return err;
}


//--------------------------------------------------
// Encrypts a file and uses SK specific method of 
// putting the file first in a ddoc container and then into
// cdoc
//--------------------------------------------------
int cmdEncryptSk(DEncEncryptedData** ppEncData, const char* szFileName) 
{
  SignedDoc *pSigDoc = 0;
  DEncEncryptionProperty* pEncProperty = 0;
  DataFile  *pDf = 0;
  int err = ERR_OK;
  long lSize;
  char buf[256], *p = 0;
  DigiDocMemBuf mbuf1;

  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  err = dencEncryptedData_new(ppEncData, DENC_XMLNS_XMLENC, DENC_ENC_METHOD_AES128, 0, 0, 0);
  if(!err) {
    err = dencMetaInfo_SetLibVersion(*ppEncData);
    if(!err) {
      err = dencMetaInfo_SetFormatVersion(*ppEncData);
      if(!err) {
        err = ddocConvertInput(szFileName, &p);
        if(!err) {
          err = dencEncryptionProperty_new(*ppEncData, &pEncProperty, 
                        0, 0, ENCPROP_FILENAME, getSimpleFileName(p));
          if(!err) {
            err = SignedDoc_new(&pSigDoc, "DIGIDOC-XML", "1.3");
            if(!err) {
              calculateFileSize(szFileName, &lSize);
              err = DataFile_new(&pDf, pSigDoc, NULL, szFileName, 
                "EMBEDDED_BASE64", "application/file", lSize, NULL, 0, NULL, NULL);
              sprintf(buf, "%ld", lSize);
              err = dencEncryptionProperty_new(*ppEncData, &pEncProperty, 
                                                 0, 0, ENCPROP_ORIG_SIZE, buf);
              if(!err) {
                err = dencOrigContent_registerDigiDoc(*ppEncData, pSigDoc);
                if(!err) {
                  sprintf(buf, "%s.ddoc", szFileName);
                  err = createSignedDoc(pSigDoc, NULL, buf);
                  if(!err) {
                    err = ddocReadFile(buf, &mbuf1);
                    if(!err) {
                      err = dencEncryptedData_AppendData(*ppEncData, mbuf1.pMem, mbuf1.nLen);
                      //ddocDebug(3, "EncTest", "Enc data: \"%s\"", mbuf1.pMem);
                      remove(buf);
                      ddocMemBuf_free(&mbuf1);
                      if(!err)
                        err = dencEncryptedData_encryptData(*ppEncData, DENC_COMPRESS_NEVER);
                    } // err - ddocReadFile
                  } // err - createSignedDoc
                } // err - origContent_register
              } // err - sigDoc_new
            } // err - sigDoc_new
            SignedDoc_free(pSigDoc);
          } // err - encProp_new
          freeLibMem(p);
        } // err - convert filename
      } // err - setFormatVer
    } // err - setLibVer
  } // err - endData_new
  return err;
}


//--------------------------------------------------
// Runs various tests. Just for trying out new features
//--------------------------------------------------
int runTestCmds(int argc, char** argv)
{
  int err = ERR_OK, i;
  char* infile = NULL;
	
  for(i = 1; (err == ERR_OK) && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      if(!strcmp(argv[i], "-test")) {
	// add a recipients key

      }
//#ifdef WITH_DEPRECATED_FUNCTIONS
      if(!strcmp(argv[i], "-test2")) {
	ddocConvertInput((const char*)argv[i+1], &infile);
	cmdTest2(argv[i+1]);	
      }
//#endif
    }
  }
  return err;
}

//--------------------------------------------------
// Encrypts whole files
//--------------------------------------------------
int runEncryptFileCmds(int argc, char** argv, DEncEncryptedData* pEncData)
{
  int err = ERR_OK, i;

  for(i = 1; (err == ERR_OK) && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // add a recipients key
      if(!strcmp(argv[i], "-encrypt-file")) {
	if(argc > i+2 && argv[i+1][0] != '-' && argv[i+2][0] != '-') {
	  char* infile = NULL;
	  char* outfile = NULL;
	  char* mime = NULL;
	  ddocConvertInput((const char*)argv[i+1], &infile);
	  ddocConvertInput((const char*)argv[i+2], &outfile);
      ddocConvertInput((const char*)argv[i+3], &mime);
      i += 3;
	  // optional arguments
	  checkArguments(argc, argv, &i, &mime);
	  // encrypt the file
	  err = dencEncryptFile(pEncData, infile, outfile, mime);
      if(infile)  freeLibMem(infile);
      if(outfile)  freeLibMem(outfile);
      if(mime)  freeLibMem(mime);
	  if(err) return err;
	} else {
	  err = ERR_BAD_PARAM;
	  addError(err, __FILE__, __LINE__, "Missing <in-file> or <out-file> argument of -encrypt-file command");
	}
      }
    }
  }
  return err;
}


//--------------------------------------------------
// Decrypts whole files
//--------------------------------------------------
int runDecryptFileCmds(int argc, char** argv)
{
  int err = ERR_OK, i;

  for(i = 1; (err == ERR_OK) && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // decrypt a file
      if(!strcmp(argv[i], "-decrypt-file")) {
	if(argc > i+2 && argv[i+1][0] != '-' && 
	   argv[i+2][0] != '-' && argv[i+3][0] != '-') {
	  char* infile = NULL;
	  char* outfile = NULL;
	  char* pin = NULL;
      char* pkcs12file = NULL;
	  ddocConvertInput((const char*)argv[i+1], &infile);
	  ddocConvertInput((const char*)argv[i+2], &outfile);
	  ddocConvertInput((const char*)argv[i+3], &pin);
      i += 3;
      // optional arguments
      checkArguments(argc, argv, &i, &pkcs12file);
	  // decrypt the file
	  err = dencSaxReadDecryptFile(infile, outfile, pin, pkcs12file);
      if(infile) freeLibMem(infile);
      if(outfile) freeLibMem(outfile);
      if(pin) freeLibMem(pin);
      if(pkcs12file) freeLibMem(pkcs12file);
	  if(err) return err;
	} else {
	  err = ERR_BAD_PARAM;
	  addError(err, __FILE__, __LINE__, "Missing <in-file>, <out-file> or <pin> argument of -decrypt-file command");
	}
      }
    }
  }
  return err;
}

//--------------------------------------------------
// Generates and encrypts a block of data with specific
// length
//--------------------------------------------------
int cmdEncryptTestSet(DEncEncryptedData** ppEncData, int nSize, char* dir, int nDdoc, int nDel) 
{
  DEncEncryptionProperty* pEncProperty = 0;
  int err = ERR_OK, i, nCompress, l2;
  char *p = 0, fname1[256], fname2[256], c, *p2;
  SignedDoc* pSigDoc = 0;
  DataFile  *pDf = 0;
  FILE* hFile;
  DigiDocMemBuf mbuf1;
	
  mbuf1.pMem = 0;
  mbuf1.nLen = 0;
  nCompress = ConfigItem_lookup_int("DENC_COMPRESS_MODE", DENC_COMPRESS_ALLWAYS);
  ddocDebug(3, "EncTest", "Test: %d", nSize);
  err = dencEncryptedData_new(ppEncData, DENC_XMLNS_XMLENC, DENC_ENC_METHOD_AES128, 0, 0, 0);
  if(err) return err;
  err = dencMetaInfo_SetLibVersion(*ppEncData);
  if(err) return err;
  err = dencMetaInfo_SetFormatVersion(*ppEncData);
  if(err) return err;
  sprintf(fname1, "%stest-%d.dat", dir, nSize);
  err = dencEncryptionProperty_new(*ppEncData, &pEncProperty, 0, 0, ENCPROP_FILENAME, fname1);
  if(err) return err;
  p = (char*)malloc(nSize+1);
  if(!p) return ERR_BAD_ALLOC;
  memset(p, 0, nSize+1);
  for(i = 0, c = 'A'; i < nSize; i++, c++) {
	  p[i] = c;
	  if(c >= 'z') c = 'A';
  }
  // append x.923 padding if last block is full
  if(nSize % 16 == 0) {
    ddocDebug(3, "EncTest", "Full size: %d. Change last 8 bytes to X.923 padding", nSize);
    p[nSize-1] = 8;
    for(i = nSize -2; i > nSize - 9; i--)
      p[i] = 0;
  }
  l2 = nSize * 2 + 1;
  p2 = (char*)malloc(l2);
  if(!p2) return ERR_BAD_ALLOC;
  memset(p2, 0, l2);
  bin2hex((const byte*)p, nSize, (byte*)p2, &l2);
	ddocDebug(3, "EncTest", "Fil data hex: \"%s\" len: %d", p2, l2);
  if((hFile = fopen(fname1, "w")) != NULL) {
	  fwrite(p, nSize, 1, hFile);
	  fclose(hFile);
  }
  free(p); p = 0;
  fname2[0] = 0;
  if(nDdoc) {
    err = dencEncryptionProperty_new(*ppEncData, &pEncProperty, 0, 0, ENCPROP_ORIG_MIME, DENC_ENCDATA_TYPE_DDOC);
    err = SignedDoc_new(&pSigDoc, "DIGIDOC-XML", "1.3");
	if(!err) {
        err = DataFile_new(&pDf, pSigDoc, NULL, fname1, "EMBEDDED_BASE64", "text/txt", nSize, NULL, 0, NULL, NULL);
		if(!err) {
			err = dencOrigContent_registerDigiDoc(*ppEncData, pSigDoc);
			if(!err) {
				sprintf(fname2, "%stest-%d.ddoc", dir, nSize);
				err = createSignedDoc(pSigDoc, NULL, fname2);
				if(!err) {
					err = ddocReadFile(fname2, &mbuf1);
					if(!err) 
						err = dencEncryptedData_AppendData(*ppEncData, mbuf1.pMem, mbuf1.nLen);
				}
			}
		}
	}
    //ddocDebug(3, "EncTest", "Enc data: \"%s\"", mbuf1.pMem);
    if(nDel && fname2[0])
      remove(fname2);
    ddocMemBuf_free(&mbuf1);
  } else {
    err = dencEncryptedData_AppendData(*ppEncData, p, nSize);
  }
  if(nDel && fname1[0])
    remove(fname1);

  if(!err)
    err = dencEncryptedData_encryptData(*ppEncData, nCompress);
  if(pSigDoc)
	  SignedDoc_free(pSigDoc);
  return err;
}

//--------------------------------------------------
// Encrypts generated test files
//--------------------------------------------------
int runEncryptTestSetCmds(int argc, char** argv)
{
  int err = ERR_OK, i, j;
  DEncEncryptedData* pEncData = 0;
  DEncEncryptedKey* pEncKey = 0;
  X509* pCert = 0;
  char fname[128];

  for(i = 1; (err == ERR_OK) && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // add a recipients key
      if(!strcmp(argv[i], "-encrypt-test-set")) {
	if(argc > i+2 && argv[i+1][0] != '-' && argv[i+2][0] != '-') {
	  char* certfile = argv[i+1];
	  char* recipient = argv[i+2];
	  char* outdir = argv[i+3];
	  int nStart = atoi(argv[i+4]);
	  int nEnd = atoi(argv[i+5]);
   	  int nDdoc = atoi(argv[i+6]);
	  int nDel = atoi(argv[i+7]);

	  for(j = nStart; j < nEnd; j++) {
	    err = ReadCertificate(&pCert, certfile);
	    if(err) return err;
	  	pEncData = 0;
		err = cmdEncryptTestSet(&pEncData, j, outdir, nDdoc, nDel);
		if(err) return err;
	     err = dencEncryptedKey_new(pEncData, &pEncKey, pCert,
				     DENC_ENC_METHOD_RSA1_5,
				     NULL, recipient, NULL, NULL);
		 sprintf(fname, "%stest-%d.cdoc", outdir, j);
		 err = dencGenEncryptedData_writeToFile(pEncData, fname);
		 dencEncryptedData_free(pEncData);
		 pEncKey = 0;
		 pEncData = 0;
	  }
	} else {
	  err = ERR_BAD_PARAM;
	  addError(err, __FILE__, __LINE__, "Invalid parameters for -encrypt-test-set command");
	}
      }
    }
  }
  return err;
}


//--------------------------------------------------
// Lists EncryptedData objects
//--------------------------------------------------
int cmdListEncryptedData(DEncEncryptedData* pEncData)
{
  int err = ERR_OK, k;
  char buf1[50], buf2[50];
  
  if(g_cgiMode) {
    fprintf(stdout, "\nEncryptedData%s%s%s%s%s%s%s%s",
	    g_szOutputSeparator, (pEncData->szId ? pEncData->szId : ""),
	    g_szOutputSeparator, (pEncData->szType ? pEncData->szType : ""),
	    g_szOutputSeparator, (pEncData->szMimeType ? pEncData->szMimeType : ""),
	    g_szOutputSeparator, (pEncData->szEncryptionMethod ? pEncData->szEncryptionMethod : ""));
    err = dencMetaInfo_GetLibVersion(pEncData, buf1, sizeof(buf1), buf2, sizeof(buf2));
    fprintf(stdout, "\nLIBRARY%s%s%s%s", g_szOutputSeparator, buf1, g_szOutputSeparator, buf2);
    err = dencMetaInfo_GetFormatVersion(pEncData, buf1, sizeof(buf1), buf2, sizeof(buf2));
    fprintf(stdout, "\nFORMAT%s%s%s%s", g_szOutputSeparator, buf1, g_szOutputSeparator, buf2);
  } else {
    fprintf(stdout, "\nEncryptedData - Id=%s Type=%s MimeType=%s EncryptionMethod=%s",
	    (pEncData->szId ? pEncData->szId : ""),
	    (pEncData->szType ? pEncData->szType : ""),
	    (pEncData->szMimeType ? pEncData->szMimeType : ""),
	    (pEncData->szEncryptionMethod ? pEncData->szEncryptionMethod : ""));
    err = dencMetaInfo_GetLibVersion(pEncData, buf1, sizeof(buf1), buf2, sizeof(buf2));
    fprintf(stdout, "\n\tLIBRARY: %s VERSION: %s", buf1, buf2);
    err = dencMetaInfo_GetFormatVersion(pEncData, buf1, sizeof(buf1), buf2, sizeof(buf2));
    fprintf(stdout, "\n\tFORMAT: %s VERSION: %s", buf1, buf2);
  }
  for(k = 0; k < pEncData->nEncryptedKeys; k++) {
    DEncEncryptedKey *pEncKey = pEncData->arrEncryptedKeys[k];
    if(g_cgiMode)
      fprintf(stdout, "\nEncryptedKey%s%s%s%s%s%s%s%s%s%s%s%s",
         g_szOutputSeparator, (pEncKey->szId ? pEncKey->szId : ""),
         g_szOutputSeparator, (pEncKey->szRecipient ? pEncKey->szRecipient : ""),
         g_szOutputSeparator, (pEncKey->szKeyName ? pEncKey->szKeyName : ""),
         g_szOutputSeparator, (pEncKey->szCarriedKeyName ? pEncKey->szCarriedKeyName : ""),
         g_szOutputSeparator, (pEncKey->szEncryptionMethod ? pEncKey->szEncryptionMethod : ""),
	     g_szOutputSeparator, (pEncKey->pCert ? "OK" : "NULL"));
    else
      fprintf(stdout, "\nEncryptedKey: Id=%s Recipient=%s KeyName=%s CarriedKeyName=%s EncryptionMethod=%s Cert: %s",
         (pEncKey->szId ? pEncKey->szId : ""),
         (pEncKey->szRecipient ? pEncKey->szRecipient : ""),
         (pEncKey->szKeyName ? pEncKey->szKeyName : ""),
         (pEncKey->szCarriedKeyName ? pEncKey->szCarriedKeyName : ""),
         (pEncKey->szEncryptionMethod ? pEncKey->szEncryptionMethod : ""),
	     (pEncKey->pCert ? "OK" : "NULL"));
  }
  if(pEncData->encProperties.nEncryptionProperties > 0) {
    if(g_cgiMode)
      fprintf(stdout, "\nEncryptionProperties%s%s",
	   g_szOutputSeparator, (pEncData->encProperties.szId ? pEncData->encProperties.szId : ""));
    else
      fprintf(stdout, "\nEncryptionProperties: %s",
	   (pEncData->encProperties.szId ? pEncData->encProperties.szId : ""));
    for(k = 0; k < pEncData->encProperties.nEncryptionProperties; k++) {
      DEncEncryptionProperty *pEncProp = pEncData->encProperties.arrEncryptionProperties[k];
      if(g_cgiMode)
        fprintf(stdout, "\nEncryptionProperty%s%s%s%s%s%s%s%s\n",
          g_szOutputSeparator, (pEncProp->szId ? pEncProp->szId : ""),
          g_szOutputSeparator, (pEncProp->szTarget ? pEncProp->szTarget : ""),
          g_szOutputSeparator, (pEncProp->szName ? pEncProp->szName : ""),
          g_szOutputSeparator, (pEncProp->szContent ? pEncProp->szContent : ""));
      else
        fprintf(stdout, "\nEncryptionProperty Id=%s Target=%s  Name=%s Content=%s\n",
          (pEncProp->szId ? pEncProp->szId : ""),
          (pEncProp->szTarget ? pEncProp->szTarget : ""),
          (pEncProp->szName ? pEncProp->szName : ""),
          (pEncProp->szContent ? pEncProp->szContent : ""));
    }
  }
  return err;
}

//--------------------------------------------------
// Add ecryption recipients
//--------------------------------------------------
int runDEncListCmds(int argc, char** argv)
{
  int err = ERR_OK, i;
  DEncEncryptedData* pEncData = 0;

  for(i = 1; (err == ERR_OK) && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // add a recipients key
      if(!strcmp(argv[i], "-denc-list")) {
	if(argc > i+1 && argv[i+1][0] != '-') {
	  char* file = argv[i+1];
	  err = dencSaxReadEncryptedData(&pEncData, file);
	  if(!err)
	    err = cmdListEncryptedData(pEncData);
	  if(pEncData && !err)
	    dencEncryptedData_free(pEncData);
	} else {
	  err = ERR_BAD_PARAM;
	  addError(err, __FILE__, __LINE__, "Missing <file> argument of -denc-list command");
	}
      }
    }
  }
  return err;
}

//--------------------------------------------------
// decryption file 
//--------------------------------------------------
int runDecryptCmds(int argc, char** argv, DEncEncryptedData** ppEncData)
{
  int err = ERR_OK, i, bDecSk = 0, nSlot = 0, nKey = 0;
  DEncEncryptedKey* pEncKey = 0;
  FILE *hFile = 0;
  SignedDoc *pSigDoc = 0;
  DataFile *pDf = 0;
  char fname1[256], *pkcs12file = 0, *infile = 0, *pin = 0, key[300];
  EVP_PKEY *pkey;
#ifdef WIN32
  wchar_t *convFileName = 0;
  int l1 = 0;
#endif

  for(i = 1; (err == ERR_OK) && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // decrypt file
      if(!strcmp(argv[i], "-decrypt") ||
         !strcmp(argv[i], "-decrypt-hex") ||
         !strcmp(argv[i], "-decrypt-sk")) {
        if(!strcmp(argv[i], "-decrypt-sk")) bDecSk = 1;
	if(argc > i+3 && 
	   argv[i+1][0] != '-' && 
	   argv[i+2][0] != '-') {
	  ddocConvertInput(argv[i+1], &infile);
	  ddocConvertInput(argv[i+2], &pin);
      nKey = 0;
      memset(key, 0, sizeof(key));
      if(!strcmp(argv[i], "-decrypt-hex")) {
          nKey = sizeof(key);
          hex2bin(pin, (byte*)key, &nKey);
      }
	  i += 2;
      if(argc > i+1 && argv[i+1][0] != '-') {
            ddocConvertInput(argv[i+1], &pkcs12file);
            i++;
      }
      if(argc > i+2 && argv[i+2][0] != '-') {
            nSlot = atoi(argv[i+2]);
            i++;
      }
    ddocDebug(3, "runDecryptCmds", "Decrypt file: %s pin: %s pkcs12: %s slot: %d", infile, pin, pkcs12file, nSlot);
	  err = dencSaxReadEncryptedData(ppEncData, infile);
	  if(err) return err;
      // if using hex key
      if(nKey > 0) {
          ddocDebug(3, "runDecryptCmds", "Decrypt with key: %s len: %d", pin, nKey);
          err = dencEncryptedData_decrypt_withKey(*ppEncData, key, nKey);
      }
      // if using pkcs12
      else if(pkcs12file != NULL && strlen(pkcs12file) > 0) {
	 ddocDebug(3, "runDecryptCmds", "Opening pkcs12 file: %s", pkcs12file);
          err = dencEncryptedData_findEncryptedKeyByPKCS12(*ppEncData, &pEncKey, &pkey, pkcs12file, pin);
      } else {
	 ddocDebug(3, "runDecryptCmds", "Connecting to pkcs11, slot: %d", nSlot);
          err = dencEncryptedData_findEncryptedKeyByPKCS11UsingSlot(*ppEncData, &pEncKey, nSlot);
      }
    if(!nKey) {
      if(pEncKey) {
        if(pkcs12file != NULL && strlen(pkcs12file) > 0)
          err = dencEncryptedData_decryptWithKey(*ppEncData, pEncKey, pkey);
        else
	      err = dencEncryptedData_decryptUsingSlot(*ppEncData, pEncKey, pin, nSlot);
	    if(err) return err;
      } else {
	    err = ERR_DENC_DECRYPT;
	    addError(err, __FILE__, __LINE__, "No transport key found for your smartcard");
      }
    }
          // read in ddoc if necessary
          if(bDecSk && p_szOutFile) {
            sprintf(fname1, "%s.ddoc", p_szOutFile);
            ddocDebug(3, "runDecryptCmds", "writing ddoc to: %s", fname1);
#ifdef WIN32
			err = utf82unicode((const char*)fname1, (char**)&convFileName, &l1);
			ddocDebug(3, "ddocReadFile", "file: %s, conv-file: %s len: %d", fname1, convFileName, i);
			if((hFile = _wfopen(convFileName, L"wb")) != NULL) {
#else
            if((hFile = fopen(fname1, "wb")) != NULL) {
#endif
              fwrite((*ppEncData)->mbufEncryptedData.pMem, (*ppEncData)->mbufEncryptedData.nLen, 1, hFile);
              fclose(hFile);
              ddocDebug(3, "runDecryptCmds", "Reading ddoc: %s", fname1);
              err = ddocSaxReadSignedDocFromFile(&pSigDoc, fname1, 0, 0);
              if(!err && getCountOfDataFiles(pSigDoc) > 0) {
                 pDf = getDataFile(pSigDoc, 0);
                 ddocDebug(3, "runDecryptCmds", "writing DF: %s to: %s", pDf->szId, p_szOutFile);
                 err = ddocExtractDataFile(pSigDoc, fname1, p_szOutFile, pDf->szId, "UTF-8");
		 dencEncryptedData_free(*ppEncData);
                 *ppEncData = NULL;
                 p_szOutFile = NULL;
              }
              SignedDoc_free(pSigDoc);
              if(fname1[0] && !remove(fname1))
                  ddocDebug(3, "runDecryptCmds", "error deleting file: %", fname1);
            }
          }
	  // p_szOutFile
	} else {
	  err = ERR_BAD_PARAM;
	  addError(err, __FILE__, __LINE__, "Missing <file> or <pin> argument of -decrypt command");
	}
      }
    }
  }
  return err;
}

//--------------------------------------------------
// Create digidoc and adds datafiles
//--------------------------------------------------
int runExtractCmds(int argc, char** argv, SignedDoc** ppSigDoc)
{
  int err = ERR_OK, i;

  for(i = 1; (err == ERR_OK) && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // add a DataFile
      if(!strcmp(argv[i], "-extract")) {
	if(argc > i+2 && argv[i+1][0] != '-' && argv[i+2][0] != '-') {
	  char* id = NULL;
	  char* file = NULL;
	  char* charset = CHARSET_UTF_8;
	  checkArguments(argc, argv, &i, &id);
	  checkArguments(argc, argv, &i, &file);
	  // optional charset & filenamecharset
	  //checkArguments(argc, argv, &i, &charset);
	  err = ddocExtractDataFile(*ppSigDoc, (const char*)p_szInFile, (const char*)file,
	    (const char*)id, (const char*)charset);
	  // report success
	  if(g_cgiMode)
		fprintf(stdout, "\nDataFile%s%s%s%s%s%d",  g_szOutputSeparator, id, 
			g_szOutputSeparator, file, g_szOutputSeparator, err);
	  else
		fprintf(stdout, "\nDataFile id: %s path: %s rc: %d",  id, file, err);

      if(id)  freeLibMem(id);
      if(file)  freeLibMem(file);
        
	} else {
	  err = ERR_BAD_PARAM;
	  addError(err, __FILE__, __LINE__, "Missing <file> argument of -extract command");
	}
      }
    }
  }
  return err;
}

//--------------------------------------------------
// Create digidoc and adds datafiles
//--------------------------------------------------
int runExtractMemCmds(int argc, char** argv, SignedDoc** ppSigDoc)
{
    int err = ERR_OK, i;
    char* pBuf = 0;
    long nLen = 0;
    FILE* hFile = 0;
    
    for(i = 1; (err == ERR_OK) && (i < argc); i++) {
        if(argv[i][0] == '-') { // all commands and options must start with -
                // extract DataFile
                if(!strcmp(argv[i], "-extract-mem")) {
                    if(argc > i+2 && argv[i+1][0] != '-' && argv[i+2][0] != '-') {
                        char* id = NULL;
                        char* file = NULL;
                        checkArguments(argc, argv, &i, &id);
                        checkArguments(argc, argv, &i, &file);
                        err = ddocGetDataFileCachedData(*ppSigDoc, id, (void**)&pBuf, &nLen);
                        printf("\nExtract DF: %s, err: %d data: %ld", id, err, nLen);
                        if(file && (hFile = fopen(file, "wb")) != NULL && pBuf && nLen) 
                            fwrite(pBuf, nLen, 1, hFile);
                        if(id) freeLibMem(id);
                        if(file) freeLibMem(file);
                        if(hFile) fclose(hFile);
                    } else {
                        err = ERR_BAD_PARAM;
                        addError(err, __FILE__, __LINE__, "Missing <file> argument of -extract command");
                    }
                }
        }
    }
    if(pBuf)
      freeLibMem(pBuf);  
    if(hFile)
        fclose(hFile);
    return err;
}

    
//--------------------------------------------------
// Verfys sigantures and notaries
//--------------------------------------------------
int runVerifyCmds(int argc, char** argv, SignedDoc* pSigDoc, DEncEncryptedData* pEncData)
{
  int err = ERR_OK, i;
  
  for(i = 1; !err && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // create new digidoc
      if(!strcmp(argv[i], "-verify")) {
		  if(pSigDoc) {
			err = cmdVerify(pSigDoc);
          }
		  if(pEncData)
			err = dencValidate(pEncData);
      }
    }
  }
  return err;	
}


//--------------------------------------------------
// Handles signature commands
//--------------------------------------------------
int runSignCmds(int argc, char** argv, SignedDoc** ppSigDoc)
{
  int err = ERR_OK, i, nManif, nSlot = 0, nOcsp = 1, nSigner = 1;

  for(i = 1; !err && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // create new digidoc
      if(!strcmp(argv[i], "-sign")) {
	  char* pin = NULL;
	  char* manifest = NULL;
	  char* city = NULL;
	  char* state = NULL;
	  char* zip = NULL;
	  char* country = NULL;
      char* sSlot = NULL;
	  char* sOcsp = NULL;
	  char* sSigner = NULL;
	  char* szPkcs12File = NULL;
	  checkArguments(argc, argv, &i, &pin);
	  // if pin is NULL check for autosign pin
	  if(!pin)
	    pin = (char*)ConfigItem_lookup("AUTOSIGN_PIN");
	  if(!pin) {
	    err = ERR_BAD_PARAM;
	    addError(err, __FILE__, __LINE__, "Missing <pin> argument of -sign command");
	    return err;
	  }
	  // check config file
	  nManif = ConfigItem_lookup_int("MANIFEST_MODE", 0);
	  if(nManif == 2) {
	    manifest = (char*)ConfigItem_lookup("DIGIDOC_ROLE_MANIFEST");
	    country = (char*)ConfigItem_lookup("DIGIDOC_ADR_COUNTRY");
	    state = (char*)ConfigItem_lookup("DIGIDOC_ADR_STATE");
	    city = (char*)ConfigItem_lookup("DIGIDOC_ADR_CITY");
	    zip = (char*)ConfigItem_lookup("DIGIDOC_ADR_ZIP");
	  }
	  // optional mainfest argument
	  checkArguments(argc, argv, &i, &manifest);
	  // optional address
	  checkArguments(argc, argv, &i, &city);
	  checkArguments(argc, argv, &i, &state);
	  checkArguments(argc, argv, &i, &zip);
	  checkArguments(argc, argv, &i, &country);
	  checkArguments(argc, argv, &i, &sSlot);
	  checkArguments(argc, argv, &i, &sOcsp);
	  checkArguments(argc, argv, &i, &sSigner);
	  if(sSlot)
	    nSlot = atoi(sSlot);
	  if(sOcsp)
	    nOcsp = atoi(sOcsp);
      if(sSigner) {
        if(!strcmp(sSigner, "PKCS11")) nSigner = 1;
        if(!strcmp(sSigner, "PKCS12")) nSigner = 3;
#ifdef WIN32
        if(!strcmp(sSigner, "CNG")) nSigner = 2;
#endif
      }
	  checkArguments(argc, argv, &i, &szPkcs12File);
	  err = cmdSign(*ppSigDoc, (const char*)pin, (const char*)manifest,
			(const char*)city, (const char*)state, (const char*)zip, 
			(const char*)country, nSlot, nOcsp, nSigner, szPkcs12File);
	  if(manifest) freeLibMem(manifest);
	  if(city) freeLibMem(city);
	  if(state) freeLibMem(state);
	  if(zip) freeLibMem(zip);
	  if(country) freeLibMem(country);
	  if(sSlot) freeLibMem(sSlot);
	  if(sOcsp) freeLibMem(sOcsp);
      if(sSigner) freeLibMem(sSigner);
	  if(szPkcs12File) freeLibMem(szPkcs12File);
      }
    }
  }
  return err;
}


//--------------------------------------------------
// Handles commands related to checking certificates
//--------------------------------------------------
int runCheckCertCmds(int argc, char** argv)
{
  int err = ERR_OK, i;
  char* szCertFile = 0;
  X509* pCert = 0;
  DigiDocMemBuf mbuf;

  mbuf.pMem = 0;
  mbuf.nLen = 0;
  for(i = 1; !err && (i < argc); i++) {
    if(!strcmp(argv[i], "-check-cert") &&
       argv[i+1][0] != '-') {
      szCertFile = argv[i+1];
      i++;
      if(szCertFile) {
	err = ReadCertificate(&pCert, szCertFile);
	if(!err && pCert) {
	  err = ddocVerifyCertByOCSP(pCert, NULL);
	  err = ddocCertGetSubjectCN(pCert, &mbuf);
	  printf("Verifying cert: %s --> RC :%d\n", (const char*)mbuf.pMem, err);
	  ddocMemBuf_free(&mbuf);
	}
	if(pCert) {
	  X509_free(pCert);
	  pCert = 0;
	}
      }
    }
  }
  return err;
}

//--------------------------------------------------
// Handles commands related to adding signature value
// from a file containging base64 encoded RSA-SHA1 signature value
//--------------------------------------------------
int runAddSignValueCmds(int argc, char** argv, SignedDoc* pSigDoc)
{
  int err = ERR_OK, i;
  char *szSignFile = 0, *szSignId = 0;
  SignatureInfo* pSignInfo = 0;

  for(i = 1; !err && (i < argc); i++) {
    if(!strcmp(argv[i], "-add-sign-value") && i < argc - 2 &&
       argv[i+1][0] != '-' && argv[i+2][0] != '-') {
      checkArguments(argc, argv, &i, &szSignFile);
      checkArguments(argc, argv, &i, &szSignId);
      if(!pSigDoc) {
	err = ERR_BAD_PARAM;
	addError(err, __FILE__, __LINE__, "No digidoc document read in yet!");
	return err;
      }
      if(szSignFile && szSignId) {
	pSignInfo = getSignatureWithId(pSigDoc, szSignId);
	if(pSignInfo) {
	  // read the file
	  err = setSignatureValueFromFile(pSignInfo, szSignFile);
	} else {
	  err = ERR_BAD_PARAM;
	  addError(err, __FILE__, __LINE__, "Wrong signature id");
	}
	// report on success
	if(g_cgiMode)
	  fprintf(stdout, "\nAddSignValue%s%s%s%s%s%d",  g_szOutputSeparator, szSignId, 
		  g_szOutputSeparator, szSignFile, g_szOutputSeparator, err);
	else
	  fprintf(stdout, "\nAddSignValue id: %s path: %s rc: %d",  szSignId, szSignFile, err);
	  } else {
	err = ERR_BAD_PARAM;
	addError(err, __FILE__, __LINE__, "Missing <sign-value-file> or <sign-id> argument of -add-sign-value command");
      }
    }
  }
  if(szSignFile) freeLibMem(szSignFile);
  if(szSignId) freeLibMem(szSignId);
  return err;
}


//--------------------------------------------------
// Handles commands related to deleting signatures
//--------------------------------------------------
int runDelSignCmds(int argc, char** argv, SignedDoc* pSigDoc)
{
  int err = ERR_OK, i;
  char *szSignId = 0;
  SignatureInfo* pSignInfo = 0;

  for(i = 1; !err && (i < argc); i++) {
    if(!strcmp(argv[i], "-del-sign") && i < argc - 1 &&
       argv[i+1][0] != '-') {
      checkArguments(argc, argv, &i, &szSignId);
      if(!pSigDoc) {
	err = ERR_BAD_PARAM;
	addError(err, __FILE__, __LINE__, "No digidoc document read in yet!");
	return err;
      }
      if(szSignId) {
	pSignInfo = getSignatureWithId(pSigDoc, szSignId);
	if(pSignInfo) {
	  err = SignatureInfo_delete(pSigDoc, szSignId);
	  // report on success
	  if(g_cgiMode)
	    fprintf(stdout, "\nDelSign%s%s%s%d",  g_szOutputSeparator, szSignId, 
		    g_szOutputSeparator, err);
	  else
	    fprintf(stdout, "\nDelSign id: %s rc: %d",  szSignId, err);

	} else {
	  err = ERR_BAD_PARAM;
	  addError(err, __FILE__, __LINE__, "wrong signature id!");
	}
      } else {
	err = ERR_BAD_PARAM;
	addError(err, __FILE__, __LINE__, "Missing <sign-id> argument of -del-sign command");
      }
    }
  }
  if(szSignId) freeLibMem(szSignId);
  return err;
}


//--------------------------------------------------
// Handles commands related to notarizing signatures
//--------------------------------------------------
int runGetConfirmationCmds(int argc, char** argv, SignedDoc* pSigDoc)
{
  int err = ERR_OK, i;
  char *szSignId = 0;
  SignatureInfo* pSignInfo = 0;

  for(i = 1; !err && (i < argc); i++) {
    if(!strcmp(argv[i], "-get-confirmation") && i < argc - 1 &&
       argv[i+1][0] != '-') {
      checkArguments(argc, argv, &i, &szSignId);
      if(!pSigDoc) {
	err = ERR_BAD_PARAM;
	addError(err, __FILE__, __LINE__, "No digidoc document read in yet!");
	return err;
      }
      if(szSignId) {
	pSignInfo = getSignatureWithId(pSigDoc, szSignId);
	if(pSignInfo) {
	  err = notarizeSignature(pSigDoc, pSignInfo);
	  // report on success
	  if(g_cgiMode)
	    fprintf(stdout, "\nNotarizeSignature%s%s%s%d",  g_szOutputSeparator, szSignId, 
		    g_szOutputSeparator, err);
	  else
	    fprintf(stdout, "\nNotarizeSignature id: %s rc: %d",  szSignId, err);

	} else {
	  err = ERR_BAD_PARAM;
	  addError(err, __FILE__, __LINE__, "wrong signature id!");
	}
	if(szSignId) freeLibMem(szSignId);
      } else {
	err = ERR_BAD_PARAM;
	addError(err, __FILE__, __LINE__, "Missing <sign-id> argument of -get-confirmation command");
      }
    }
  }
  return err;
}


//--------------------------------------------------
// Signs the document and gets configrmation
//--------------------------------------------------
int cmdCalcSign(SignedDoc* pSigDoc, const char* manifest,
		const char* city, const char* state, const char* zip, 
		const char* country, const char* certFile)
{
  int err = ERR_OK, l1;
  SignatureInfo* pSigInfo = NULL;
  X509* pCert = NULL;
  char buf1[50];

  ddocDebug(3, "cmdCalcSign", "Creating new digital signature");
  RETURN_IF_NULL_PARAM(pSigDoc);
  RETURN_IF_NULL_PARAM(certFile);
  // read certificate
  // this certificate will nto be released since new signature takes ownership!
  err = ReadCertificate(&pCert, certFile);
  RETURN_IF_NOT(err == ERR_OK, err);
  // prepare signature
  err = ddocPrepareSignature(pSigDoc, &pSigInfo,
	   manifest, city, state, zip, country, pCert, NULL);
  // base64 encode final hash
  l1 = sizeof(buf1);
  err = ddocGetSignedHash(pSigInfo, buf1, &l1, 2, 0);
  RETURN_IF_NOT(err == ERR_OK, err);
  // report on success
  if(g_cgiMode)
    fprintf(stdout, "\nSignatureHash%s%s%s%s%s%d",  g_szOutputSeparator, pSigInfo->szId, 
	    g_szOutputSeparator, buf1, g_szOutputSeparator, err);
  else
    fprintf(stdout, "\nSignatureHash id: %s hash: %s rc: %d", pSigInfo->szId, buf1, err);


  RETURN_IF_NOT(err == ERR_OK, err);
  return ERR_OK;
}

//--------------------------------------------------
// Handles signature commands
//--------------------------------------------------
int runCalcSignCmds(int argc, char** argv, SignedDoc* pSigDoc)
{
  int err = ERR_OK, i, nManif;

  for(i = 1; !err && (i < argc); i++) {
    if(argv[i][0] == '-') { // all commands and options must start with -
      // create new digidoc
      if(!strcmp(argv[i], "-calc-sign")) {
	  char* certFile = NULL;
	  char* manifest = NULL;
	  char* city = NULL;
	  char* state = NULL;
	  char* zip = NULL;
	  char* country = NULL;
	  checkArguments(argc, argv, &i, &certFile);
	  // check config file
	  nManif = ConfigItem_lookup_int("MANIFEST_MODE", 0);
	  if(nManif == 2) {
	    manifest = (char*)ConfigItem_lookup("DIGIDOC_ROLE_MANIFEST");
	    country = (char*)ConfigItem_lookup("DIGIDOC_ADR_COUNTRY");
	    state = (char*)ConfigItem_lookup("DIGIDOC_ADR_STATE");
	    city = (char*)ConfigItem_lookup("DIGIDOC_ADR_CITY");
	    zip = (char*)ConfigItem_lookup("DIGIDOC_ADR_ZIP");
	  }
	  // optional mainfest argument
	  checkArguments(argc, argv, &i, &manifest);
	  // optional address
	  checkArguments(argc, argv, &i, &city);
	  checkArguments(argc, argv, &i, &state);
	  checkArguments(argc, argv, &i, &zip);
	  checkArguments(argc, argv, &i, &country);
	  if(!certFile) {
	    err = ERR_BAD_PARAM;
	    addError(err, __FILE__, __LINE__, "Missing <cert-file> argument of -calc-sign command");
	  }
	  else
	    err = cmdCalcSign(pSigDoc, (const char*)manifest,
			(const char*)city, (const char*)state, (const char*)zip, 
			    (const char*)country, (const char*)certFile);
	  if(manifest) freeLibMem(manifest);
	  if(city) freeLibMem(city);
	  if(state) freeLibMem(state);
	  if(zip) freeLibMem(zip);
	  if(country) freeLibMem(country);
	  if(certFile) freeLibMem(certFile);
      }
    }
  }
  return err;
}


//--------------------------------------------------
// Signs the document and gets configrmation
//--------------------------------------------------
int cmdMidSign(SignedDoc* pSigDoc, const char* szPhoneNo, 
               const char* szIdCode, const char* szLang,
               const char* szService,
                const char* manifest, const char* city, 
                const char* state, const char* zip, 
                const char* country)
{
    int err = ERR_OK, nPollFreq = 0, l1, nStatus = 0;
    char* szUrl = 0, *szProxyHost = 0, *szProxyPort = 0;
    long lSesscode = 0;
    char buf1[10];
    DigiDocMemBuf mbuf1;
#ifdef WIN32
    time_t tNew, tOld;
#endif
    
    mbuf1.pMem = 0;
    mbuf1.nLen = 0;
    nPollFreq = ConfigItem_lookup_int("DDS_POLLFREQ", 0);
    szUrl = (char*)ConfigItem_lookup("DDS_URL");
    szProxyHost = (char*)ConfigItem_lookup("DDS_PROXY_HOST");
    szProxyPort = (char*)ConfigItem_lookup("DDS_PROXY_PORT");
    ddocDebug(3, "cmdMidSign", "Creating MID signature using: %s poll freq: %d", szPhoneNo, nPollFreq);
    // send signature req
    l1 = sizeof(buf1);
    ddsSign(pSigDoc, szIdCode, szPhoneNo, szLang, szService,
            manifest, city, state, zip, country, szUrl, szProxyHost, szProxyPort,
            &lSesscode, buf1, l1);
    
    // report on success
    if(g_cgiMode)
        fprintf(stdout, "\nMIDSinatureReq%s%ld%s%d",  
                g_szOutputSeparator, lSesscode, 
                g_szOutputSeparator, err);
    else
        fprintf(stdout, "\nMIDSignatureReq session: %ld rc: %d", lSesscode, err);
    // if we should keep on polling
    if(!err && nPollFreq) {
        // now check status
        do {
#ifdef WIN32
            time(&tOld);
            do {
                time(&tNew);
            } while(tNew - tOld < nPollFreq);
#else
            ddocDebug(3, "cmdMidSign", "Sleep: %d", nPollFreq);
            sleep(nPollFreq);
#endif
            err = ddsGetStatusWithFile(pSigDoc, lSesscode, szUrl, szProxyHost, szProxyPort, &nStatus, p_szInFile);
            ddocDebug(3, "cmdMidSign", "Txn: %ld status: %d err: %d", lSesscode, nStatus, err);
        } while(!err && nStatus == 1);
    }
    if(g_cgiMode)
        fprintf(stdout, "\nMID session %s%ld%s%d",  
                g_szOutputSeparator, lSesscode, 
                g_szOutputSeparator, nStatus);
    else
        fprintf(stdout, "\nMID session %ld complete status: %d", lSesscode, nStatus);
    
    RETURN_IF_NOT(err == ERR_OK, err);
    return ERR_OK;
}


//--------------------------------------------------
// Handles MID signature commands
//--------------------------------------------------
int runMidSignCmds(int argc, char** argv, SignedDoc* pSigDoc)
{
    int err = ERR_OK, i, nManif = 0;
    
    for(i = 1; !err && (i < argc); i++) {
        if(argv[i][0] == '-') { // all commands and options must start with -
            // create new digidoc
            if(!strcmp(argv[i], "-mid-sign")) {
                char* phoneNo = NULL;
                char* idcode = NULL;
                char* service = NULL;
                char* lang = NULL;
                char* manifest = NULL;
                char* city = NULL;
                char* state = NULL;
                char* zip = NULL;
                char* country = NULL;
                checkArguments(argc, argv, &i, &phoneNo);
                // check config file
                nManif = ConfigItem_lookup_int("MANIFEST_MODE", 0);
                if(nManif == 2) {
                    manifest = (char*)ConfigItem_lookup("DIGIDOC_ROLE_MANIFEST");
                    country = (char*)ConfigItem_lookup("DIGIDOC_ADR_COUNTRY");
                    state = (char*)ConfigItem_lookup("DIGIDOC_ADR_STATE");
                    city = (char*)ConfigItem_lookup("DIGIDOC_ADR_CITY");
                    zip = (char*)ConfigItem_lookup("DIGIDOC_ADR_ZIP");
                }
                // optional mainfest argument
                checkArguments(argc, argv, &i, &idcode);
                checkArguments(argc, argv, &i, &country);
                checkArguments(argc, argv, &i, &lang);
                checkArguments(argc, argv, &i, &service);
                checkArguments(argc, argv, &i, &manifest);
                checkArguments(argc, argv, &i, &city);
                checkArguments(argc, argv, &i, &state);
                checkArguments(argc, argv, &i, &zip);
                if(!phoneNo) {
                    err = ERR_BAD_PARAM;
                    addError(err, __FILE__, __LINE__, "Missing <phone-no> argument of -mid-sign command");
                }
                else
                    cmdMidSign(pSigDoc, (const char*)phoneNo, (const char*)idcode,
                               (const char*)(lang ? lang : "EST"),
                               (const char*)(service ? service : "Testimine"), (const char*)manifest,
                               (const char*)city, (const char*)state, (const char*)zip, 
                               (const char*)(country ? country : "EE"));
                if(manifest) freeLibMem(manifest);
                if(city) freeLibMem(city);
                if(state) freeLibMem(state);
                if(zip) freeLibMem(zip);
                if(country) freeLibMem(country);
                if(phoneNo) freeLibMem(phoneNo);
            }
        }
    }
    return err;
}

    
//--------------------------------------------------
// Handles MID signature commands
//--------------------------------------------------
int runMidTestCmds(int argc, char** argv, SignedDoc* pSigDoc)
{
    int err = ERR_OK, i, e1;
    SignedDoc *pSdoc = NULL;
    DataFile  *pDf = NULL;
    long lSize1, lSize2, lSize3;
    
    for(i = 1; !err && (i < argc); i++) {
        if(argv[i][0] == '-') { // all commands and options must start with -
            // create new digidoc
            if(!strcmp(argv[i], "-mid-test")) {
                char* infile = NULL;
                char* inmime = NULL;
                char* outddoc = NULL;
                char* phoneNo = NULL;
                char* idcode = NULL;
                char* service = NULL;
                checkArguments(argc, argv, &i, &infile);
                checkArguments(argc, argv, &i, &inmime);
                checkArguments(argc, argv, &i, &outddoc);
                checkArguments(argc, argv, &i, &phoneNo);
                checkArguments(argc, argv, &i, &idcode);
                checkArguments(argc, argv, &i, &service);
                if(!phoneNo || !idcode || !infile || !inmime || !outddoc) {
                    err = ERR_BAD_PARAM;
                    addError(err, __FILE__, __LINE__, "Missing <phone-no> <idcode> <infile> <inmime> or <outddoc> argument of -mid-test command");
                } else {
                    p_szInFile = outddoc;
                    printf("Creating ddoc: %s of file: %s mime: %s\n", outddoc, infile, inmime);
                    err = SignedDoc_new(&pSdoc, "DIGIDOC-XML", "1.3");
                    printf("Creating ddoc: %s rc: %d\n", outddoc, err);
                    RETURN_IF_NOT(err == ERR_OK, err);
                    err = calculateFileSize(infile, &lSize1);
                    err = DataFile_new(&pDf, pSdoc, NULL, infile, "EMBEDDED_BASE64", inmime, 0, NULL, 0, NULL, NULL);
                    err = createSignedDoc(pSdoc, NULL, outddoc);
                    if(pDf->nSize == 0 && lSize1 > 0)
                        pDf->nSize = lSize1; 
                    err = calculateFileSize(outddoc, &lSize2);
                    printf("Add data-file: %s rc: %d d-size: %ld ddoc-size: %ld\n", infile, err, lSize1, lSize2);
                    err = ddocExtractDataFile(pSdoc, outddoc, "D0.dat", "D0", "UTF-8");
                    err = calculateFileSize("D0.dat", &lSize3);
                    printf("Extract before signing rc: %d size: %ld\n", err, lSize3);
                    printf("MID signing phone: %s id-code: %s\n", phoneNo, idcode);
                    err = cmdMidSign(pSdoc, (const char*)phoneNo, (const char*)idcode,
                        "EST", (service ? service : "Testimine"), NULL, NULL, NULL, NULL, "EE");
                    err = calculateFileSize(outddoc, &lSize2);
                    printf("MID signed phone: %s id-code: %s ddoc-size: %ld rc: %d\n", phoneNo, idcode, lSize2, err);
                    err = cmdVerify(pSdoc);
                    printf("\nVerify after signing rc: %d\n", err);
                    lSize3 = 0;
                    err = ddocExtractDataFile(pSdoc, outddoc, "D0.dat", "D0", "UTF-8");
                    err = calculateFileSize("D0.dat", &lSize3);
                    printf("Extract after signing rc: %d size: %ld\n", err, lSize3);
                }
                SignedDoc_free(pSdoc);
                if(infile) freeLibMem(infile);
                if(inmime) freeLibMem(inmime);
                if(outddoc) freeLibMem(outddoc);
                if(phoneNo) freeLibMem(phoneNo);
                if(idcode) freeLibMem(idcode);
                if(service) freeLibMem(service);
            }
        }
    }
    return err;
}

    


//--------------------------------------------------
// Program main function
//--------------------------------------------------
int main(int argc, char** argv)
{
  int err = ERR_OK, e = 0;
  SignedDoc* pSigDoc = 0;
  DEncEncryptedData* pEncData = 0;
  time_t t1, t2;
#ifdef WIN32
  char buf1[250];
#endif

  if(argc <= 1) {
    printUsage();
    exit(0);
  }
  // init DigiDoc library
  initDigiDocLib();
#ifdef WIN32
  // find out program home if invoked with a long command line
  memset(buf1, 0, sizeof(buf1));
  getFileNamePath(argv[0], buf1, sizeof(buf1));
  if(strlen(buf1)) {
    strncat(buf1, "digidoc.ini", sizeof(buf1));
    err = initConfigStore(buf1);
  } else
    err = initConfigStore(NULL);
#else
  // read in config file
  err = initConfigStore(NULL);
#endif
  // clear all errors that were encountered by not finding config files
  err = checkProgArguments(argc, argv);
  time(&t1);
  // register program name and version
  setGUIVersion(g_szProgNameVer);
  ddocDebugTruncateLog();
  // use command line argument if required
  if(p_szConfigFile)
    err = readConfigFile(p_szConfigFile, ITEM_TYPE_PRIVATE);
  // read flags from config file
  readConfigParams();

  // display programm name and version
  if(g_cgiMode) {
    if(ConfigItem_lookup_bool("DIGIDOC_CGI_PRINT_HEADER", 1))
      fprintf(stdout, "%s%s%s", getLibName(), g_szOutputSeparator, getLibVersion());
  } else {
    fprintf(stdout, "%s - %s", getLibName(), getLibVersion());
  }

  // execute the commands now 
  // check certificate status throught OCSP
  if(!err)
    err = runCheckCertCmds(argc, argv);
  // read input file if necessary
  if(p_szInFile && !err) {
	if(p_parseMode != 3)
      err = cmdReadDigiDoc(&pSigDoc, &pEncData, p_parseMode);
	else
	  err = cmdReadDigiDocFromMem(&pSigDoc, &pEncData);
    // if read error was warning then continue
    if(pSigDoc && isWarning(pSigDoc, err)) 
        err = ERR_OK;
    if(err && pSigDoc)
        printErrorsAndWarnings(pSigDoc);
  }
  // various tests
  if(!err)
    err = runTestCmds(argc, argv);
  if(p_szInEncFile && !err) {
    if(hasCmdLineArg(argc, argv, "-encrypt-sk"))
      err = cmdEncryptSk(&pEncData, p_szInEncFile);
    else
      err = cmdEncrypt(&pEncData, p_szInEncFile);
  }
  // list encrypted files
  if(!err)
    err = runDEncListCmds(argc, argv);
  // add data files
  if(!err)
    err = runAddCmds(argc, argv, &pSigDoc);
  // add data files from mem
  if(!err)
    err = runAddMemCmds(argc, argv, &pSigDoc);
  // add recipients
  if(!err)
    err = runRecipientCmds(argc, argv, &pEncData);
  // encrypt whole files
  if(!err)
    err = runEncryptFileCmds(argc, argv, pEncData);
  // decrypt whole files
  if(!err)
    err = runDecryptFileCmds(argc, argv);
  // run signature commands
  if(!err)
    err = runSignCmds(argc, argv, &pSigDoc);
  // calculate signature hash commands
  if(!err)
    err = runCalcSignCmds(argc, argv, pSigDoc);
  if(!err)
    err = runMidSignCmds(argc, argv, pSigDoc);
  if(!err)
    err = runMidTestCmds(argc, argv, pSigDoc);
  // verify signatures
  if(!err) {
    e = runVerifyCmds(argc, argv, pSigDoc, pEncData);
    if(!err && e) err = e;
  }
  // extract datafiles
  if(!err)
    err = runExtractCmds(argc, argv, &pSigDoc);
  if(!err)
    err = runExtractMemCmds(argc, argv, &pSigDoc);
  // decrypt files
  if(!err)
    err = runDecryptCmds(argc, argv, &pEncData);
  // add signature value from a file
  if(!err)
    err = runAddSignValueCmds(argc, argv, pSigDoc);
  // delete signatures
  if(!err)
    err = runDelSignCmds(argc, argv, pSigDoc);
  // notarize signatures
  if(!err)
    err = runGetConfirmationCmds(argc, argv, pSigDoc);
  if(!err)
    err = runEncryptTestSetCmds(argc, argv);
  // write output file
  if(p_szOutFile && !err)
	if(p_parseMode != 3)
    	err = cmdWrite(pSigDoc, pEncData);
	else
		err = cmdWriteMem(pSigDoc, pEncData);
  time(&t2);

  printErrorsAndWarnings(pSigDoc);
  if(pSigDoc && !isError(pSigDoc, err)) { // find correct error from list
      e = hasErrors(pSigDoc);
      if((!err || !isError(pSigDoc,err)) && e) err = e;
  }
  // display programm error code and elapsed time
  if(g_cgiMode) {
    if(ConfigItem_lookup_bool("DIGIDOC_CGI_PRINT_TRAILER", 1))
        fprintf(stdout, "\n%s%s%d%s%ld", getLibName(), g_szOutputSeparator, (isError(pSigDoc,err) ? err : 0), g_szOutputSeparator, (long)(t2-t1));
  } else {
    fprintf(stdout, "\n%s - time: %ld sec result: %s", getLibName(), (long)(t2-t1), (isError(pSigDoc,err) ? "failure" : "success"));
  }
  fprintf(stdout, "\n");
  // cleanup
  if(pSigDoc)
    SignedDoc_free(pSigDoc);
  if(pEncData)
    dencEncryptedData_free(pEncData);
  if(g_szOutputSeparator)
	  free(g_szOutputSeparator);
  // cleanup
#ifndef WIN32  // TODO: somehow this free gives invalid heap error on win32
  cleanupConfigStore(NULL);
#endif
  finalizeDigiDocLib();

  return err;
}
