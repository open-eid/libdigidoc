#ifndef __DIGI_DOC_SRV_H__
#define __DIGI_DOC_SRV_H__
//==================================================
// FILE:	DigiDocService.h
// PROJECT:     Digi Doc
// DESCRIPTION: Digi Doc functions for DigiDocService access
// AUTHOR:  Veiko Sinivee, Sunset Software O†
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
//==================================================

#include <libdigidoc/DigiDocDefs.h>
#include <libdigidoc/DigiDocHTTP.h>
#include <libdigidoc/DigiDocMem.h>

#ifdef  __cplusplus
extern "C" {
#endif
    
#define STATUS_UNKNOWN                  0
#define STATUS_OUTSTANDING_TRANSACTION  1
#define STATUS_SIGNATURE                2
#define STATUS_ERROR                    3
    
    
    //------------------------------------------
    // Gets DigiDocService session status and returns status code
    // If session is ready then signature will be returned
    // pSigDoc - signed document object to be modified
    // lSesscode - session code
    // url - dds service url
    // proxyHost - proxy hostname
    // proxyPort -proxy port
    // pStatus - buffer for returning status
    // pMBufSig - buffer for returning signature
    // returns DigiDocService session status code
    // deprecated use ddsGetStatus(pSigDoc, lSesscode, url, proxyHost, proxyPort, pStatus, szFileName)
    //------------------------------------------
    DIGIDOC_DEPRECATED EXP_OPTION int ddsGetStatus(SignedDoc* pSigDoc, long lSesscode,
                                char* url, char* proxyHost, char* proxyPort,
                                int* pStatus);
    
    //------------------------------------------
    // Gets DigiDocService session status and returns status code
    // If session is ready then signature will be returned
    // pSigDoc - signed document object to be modified
    // lSesscode - session code
    // url - dds service url
    // proxyHost - proxy hostname
    // proxyPort -proxy port
    // pStatus - buffer for returning status
    // szFileName - ddoc filename to add signature from dds (optional)
    // pMBufSig - buffer for returning signature
    // returns DigiDocService session status code
    //------------------------------------------
    EXP_OPTION int ddsGetStatusWithFile(SignedDoc* pSigDoc, long lSesscode,
                                char* url, char* proxyHost, char* proxyPort,
                                int* pStatus, const char* szFileName);

  //--------------------------------------------------
  // Signs the document and gets return status back
  // pSigDoc - signed document object
  // szIdCode - personal id code
  // szPhoneNo - users phone number
  // szLang - language code
  // manifest - manifest or role
  // city - signers address , city
  // state - signers address , state or province
  // zip - signers address , postal code
  // country - signers address , country name
  // pSesscode - pointer to long int buffer for returning session code
  // szChallenge - buffer for returning challenge code (char 4)
  // nChalLen - length of challenge buffer
  // return error code or ERR_OK
  //--------------------------------------------------
  EXP_OPTION int ddsSign(SignedDoc* pSigDoc, 
                         const char* szIdCode, const char* szPhoneNo,
                         const char* szLang, const char* szServiceName,
                         const char* manifest, const char* city, 
                         const char* state, const char* zip, 
                         const char* country,
                         char* url, char* proxyHost, char* proxyPort,
                         long* pSesscode, char* szChallenge, int nChalLen);



#ifdef  __cplusplus
}
#endif


#endif // __DIGI_DOC_CFG_H__
