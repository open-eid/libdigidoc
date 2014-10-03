#ifndef __DIGI_DOC_CFG_H__
#define __DIGI_DOC_CFG_H__
//==================================================
// FILE:	DigiDocCfonfig.h
// PROJECT:     Digi Doc
// DESCRIPTION: Digi Doc functions for configuration management
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
//      08.01.2004      Veiko Sinivee
//                      Creation
//      20.03.2004      Added functions createOrReplacePrivateConfigItem()
//                      writeConfigFile() and writePrivateConfigFile()
//      20.03.2004      changed function notarizeSignature to check for PKCS12 arguments
//==================================================

#include <libdigidoc/DigiDocDefs.h>
#include <libdigidoc/DigiDocLib.h>
#include <time.h>

#ifdef  __cplusplus
extern "C" {
#endif


#include <openssl/x509.h>


// item type
#define ITEM_TYPE_UNKNOWN   0
#define ITEM_TYPE_GLOBAL    1
#define ITEM_TYPE_PRIVATE   2

// used to mark modified items to then store all together in private config file
#define ITEM_STATUS_UNKNOWN 0
#define ITEM_STATUS_OK      1
#define ITEM_STATUS_MODIFIED 2

  // holds one configuration item
  typedef struct ConfigItem_st {
	char* szKey;		// items key
	char* szValue;		// items value
	int nType;                  // items type (system wide or private)
	int nStatus;                // item status - clean/modified
  } ConfigItem;
    
  // holds one certificate item
  typedef struct CertificateItem_st {
    char* szKey;		// items key
    X509* pCert;		// certificate
  } CertificateItem;

  // array of configration items
  typedef struct ConfigurationStore_st {
	int nItems;
	ConfigItem** pItems;
    int nCerts;
    CertificateItem** pCerts;
  } ConfigurationStore;

  //--------------------------------------------------
  // Returns true (not 0) if config store structure has been inited
  //--------------------------------------------------
  EXP_OPTION int isConfigInited();

  //--------------------------------------------------
  // Initializes configuration store
  // szConfigFile - name of config file. Use NULL for default
  //--------------------------------------------------
  EXP_OPTION int initConfigStore(const char* szConfigFile);

  //--------------------------------------------------
  // Cleans memory of configuration store
  // pConfStore - configuration collection (use NULL for default)
  //--------------------------------------------------
  EXP_OPTION void cleanupConfigStore(ConfigurationStore *pConfStore);

  //--------------------------------------------------
  // Adds a new configration item
  // pConfStore - configuration collection (use NULL for default)
  // key - items key
  // value - items value
  // type - item type
  // status - item status
  // returns ERR_OK on success
  //--------------------------------------------------
  EXP_OPTION int addConfigItem(ConfigurationStore *pConfStore, const char* key, const char* value, int type, int status);
    
  //--------------------------------------------------
  // Read ca and ocsp responder certs from files and cache in memory
  //--------------------------------------------------
  int initCertificateItems();
    
  //--------------------------------------------------
  // Deletes configration item
  // key - items key
  // returns ERR_OK on success
  //--------------------------------------------------
  EXP_OPTION int ConfigItem_delete(const char* key);

  //--------------------------------------------------
  // Adds a new private configration item or modifies
  // pConfStore - configuration collection (use NULL for default)
  // an existing one
  // key - items key
  // value - items value
  // returns ERR_OK on success
  //--------------------------------------------------
  EXP_OPTION int createOrReplacePrivateConfigItem(ConfigurationStore *pConfStore, const char* key, const char* value);

  //--------------------------------------------------
  // Finds a new configration items value by key
  // key - items key
  // returns value of config item or NULL if not found
  //--------------------------------------------------
  EXP_OPTION const char* ConfigItem_lookup(const char* key);

  //--------------------------------------------------
  // Finds a new configration items value by key from the store
  // key - items key
  // pConfStore - store to search in
  // returns value of config item or NULL if not found
  //--------------------------------------------------
  EXP_OPTION const char* ConfigItem_lookup_fromStore(ConfigurationStore *pConfStore, const char* key);

  //--------------------------------------------------
  // Finds a all configration items that start with this prefix
  // pConfStore - collection of found items
  // prefix - item keys prefix
  // returns error code or ERR_OK
  //--------------------------------------------------
  int ConfigItem_findByPrefix(ConfigurationStore *pConfStore, const char* prefix);

  //--------------------------------------------------
  // Finds a numeric configration items value by key
  // key - items key
  // defValue - default value to be returned
  // returns value of config item or defValue if not found
  //--------------------------------------------------
  EXP_OPTION int ConfigItem_lookup_int(const char* key, int defValue);

  //--------------------------------------------------
  // Finds a bolean configration items value by key
  // key - items key
  // defValue - default value to be returned
  // returns value of config item or defValue if not found
  //--------------------------------------------------
  EXP_OPTION int ConfigItem_lookup_bool(const char* key, int defValue);

  //--------------------------------------------------
  // Finds a new configration items value by key
  // key - items key
  // returns value of config item or NULL if not found
  //--------------------------------------------------
  EXP_OPTION const char* ConfigItem_lookup_str(const char* key, const char* defValue);

  //--------------------------------------------------
  // Reads and parses configuration file
  // fileName - configuration file name
  // type - type of config file global/private
  // return error code or 0 for success
  //--------------------------------------------------
  EXP_OPTION int readConfigFile(const char* fileName, int type);

  //--------------------------------------------------
  // Writes a configuration file
  // fileName - configuration file name
  // type - type of config file global/private
  // return error code or 0 for success
  //--------------------------------------------------
  EXP_OPTION int writeConfigFile(const char* fileName, int type);

  //--------------------------------------------------
  // Saves all private config items in correct file
  // return error code or 0 for success
  //--------------------------------------------------
  EXP_OPTION int writePrivateConfigFile();

  //--------------------------------------------------
  // Sets a new name for private config file. Can be
  // used to override default of env(HOME)/.digidoc.conf
  // Use NULL to restore default value
  //--------------------------------------------------
  EXP_OPTION void setPrivateConfigFile(const char* fileName);

  //--------------------------------------------------
  // Finds CA certificate of the given certificate
  // ppCA - address of found CA
  // pCert - certificate whose CA we are looking for
  // return error code or 0 for success
  //  deprecated use findCAForCertificateAndSigTime()
  //--------------------------------------------------
  DIGIDOC_DEPRECATED EXP_OPTION int findCAForCertificate(X509** ppCA, const X509* pCert);

    //--------------------------------------------------
    // Finds CA certificate of the given certificate
    // ppCA - address of found CA
    // pCert - certificate whose CA we are looking for
    // tSigTime - signature timestamp
    // return error code or 0 for success
    //--------------------------------------------------
    EXP_OPTION int findCAForCertificateAndSigTime(X509** ppCA, const X509* pCert, time_t tSigTime);

  //--------------------------------------------------
  // Finds CA certificate by CN
  // ppCA - address of found CA
  // szCN - CA certs common name
  // pHash - authority-key-identifier to search for CA
  // return error code or 0 for success
  // deprecated use findCAForCNAndSigTime()
  //--------------------------------------------------
  DIGIDOC_DEPRECATED EXP_OPTION int findCAForCN(X509** ppCA, const char* szCN, DigiDocMemBuf *pHash);

    //--------------------------------------------------
    // Finds CA certificate by CN
    // ppCA - address of found CA
    // szCN - CA certs common name
    // pHash - authority-key-identifier to search for CA
    // tSigTime - signing time or 0
    // return error code or 0 for success
    //--------------------------------------------------
    EXP_OPTION int findCAForCNAndSigTime(X509** ppCA, const char* szCN, DigiDocMemBuf *pHash, time_t tSigTime);

    //--------------------------------------------------
    // Finds CA chain 
    // ppChain - address of cert pointer array
    // nMaxChain - index of last cert in returned array - 0 based
    // szCN - CN of the first CA cert (not the child cert!)
    // pCert - certificate to search ca-s for
    // return error code or 0 for success
    // deprecated use findCAChainForCNAndSigTime()
    //--------------------------------------------------
    DIGIDOC_DEPRECATED EXP_OPTION int findCAChainForCN(X509** ppChain, int* nMaxChain, const char* szCN, X509* pCert);

    //--------------------------------------------------
    // Finds CA chain 
    // ppChain - address of cert pointer array
    // nMaxChain - index of last cert in returned array - 0 based
    // szCN - CN of the first CA cert (not the child cert!)
    // pCert - certificate to search ca-s for
    // tSigTime - signature timestamp
    // return error code or 0 for success
    //--------------------------------------------------
    EXP_OPTION int findCAChainForCNAndSigTime(X509** ppChain, int* nMaxChain, const char* szCN, X509* pCert, time_t tSigTime);

  //--------------------------------------------------
  // Finds Responders certificate by CN
  // ppResp - address of found cert
  // szCN - Responder certs common name
  // hash - responder certs hash in base64 form
  // szCertSerial - specific serial number to search
  // return error code or 0 for success
  //--------------------------------------------------
  EXP_OPTION int findResponder(X509** ppResp, const char* szCN, 
			       const char* szHash, char* szCertSerial);

  //--------------------------------------------------
  // Finds Responders certificate by CN and index
  // ppResp - address of found cert
  // szCN - Responder certs common name
  // hash - responder certs hash in base64
  // nIdx - index of the certificate for this respnder. Starts at 0
  // return error code or 0 for success
  //--------------------------------------------------
  EXP_OPTION int findResponderByCNAndHashAndIndex(X509** ppResp, const char* szCN, 
						  const char* hash, int nIdx);

  //--------------------------------------------------
  // Finds Responder certificates CA certs CN
  // caCN - buffer for responders CA CN
  // len - length of buffer for CA CN
  // szCN - responder certs common name
  // hash - responder certs hash in base64 form
  // return error code or 0 for success
  //--------------------------------------------------
  EXP_OPTION int findResponderCA(char* caCN, int len, const char* szCN, const char* hash);

  //------------------------------------------
  // Get a notary confirmation for signature
  // pSigDoc - signed document pointer
  // pSigInfo - signature to notarize
  // returns error code
  //------------------------------------------
  EXP_OPTION int notarizeSignature(SignedDoc* pSigDoc, SignatureInfo* pSigInfo);

  //------------------------------------------
  // Get a notary confirmation for signature
  // pSigDoc - signed document pointer
  // pSigInfo - signature to notarize
  // ip - callers ip address if known
  // returns error code
  //------------------------------------------
  EXP_OPTION int notarizeSignatureWithIp(SignedDoc* pSigDoc, SignatureInfo* pSigInfo, unsigned long ip);

  //--------------------------------------------------
  // Signs the document and gets configrmation
  // pSigDoc - signed document pointer
  // ppSigInfo - address of new signature pointer
  // pin - smart card PIN
  // manifest - manifest / resolution (NULL)
  // city - signers city (NULL)
  // state - signers state (NULL)
  // zip - signers postal code (NULL)
  // country - signers country (NULL)
  //--------------------------------------------------
  EXP_OPTION int signDocument(SignedDoc* pSigDoc, SignatureInfo** ppSigInfo,
		   const char* pin, const char* manifest,
		   const char* city, const char* state,
		   const char* zip, const char* country);

  //--------------------------------------------------
  // Signs the document and gets configrmation
  // pSigDoc - signed document pointer
  // ppSigInfo - address of new signature pointer
  // pin - smart card PIN
  // manifest - manifest / resolution (NULL)
  // city - signers city (NULL)
  // state - signers state (NULL)
  // zip - signers postal code (NULL)
  // country - signers country (NULL)
  // signs with PKCS11
  //--------------------------------------------------
  EXP_OPTION int signDocumentWithSlot(SignedDoc* pSigDoc, SignatureInfo** ppSigInfo,
                 const char* pin, const char* manifest,
                 const char* city, const char* state,
                 const char* zip, const char* country, 
				 int nSlot, int nOcsp, int nSigner);
    
  //--------------------------------------------------
  // Signs the document and gets configrmation
  // pSigDoc - signed document pointer
  // ppSigInfo - address of new signature pointer
  // pin - smart card PIN
  // manifest - manifest / resolution (NULL)
  // city - signers city (NULL)
  // state - signers state (NULL)
  // zip - signers postal code (NULL)
  // country - signers country (NULL)
  // nSigner - 1=PKCS11, 2=CNG (Microsoft CAPI), 3=PKCS#12
  // szPkcs12FileName - PKCS#12 file name to be used for signing (required if nSigner=3)
  //--------------------------------------------------
  EXP_OPTION int signDocumentWithSlotAndSigner(SignedDoc* pSigDoc, SignatureInfo** ppSigInfo,
                                                 const char* pin, const char* manifest,
                                                 const char* city, const char* state,
                                                 const char* zip, const char* country, 
                                                 int nSlot, int nOcsp, int nSigner,
                                                 const char* szPkcs12FileName);

  //--------------------------------------------------
  // Verify this notary
  // pSigDoc - signed document pointer
  // pNotInfo - notary to verify
  // returns error code
  //--------------------------------------------------
  int verifyNotary(SignedDoc* pSigDoc, SignatureInfo* pSigInfo, NotaryInfo* pNotInfo);

  //--------------------------------------------------
  // Verify this signature and it's notary
  // pSigDoc - signed document pointer
  // pSigInfo - signature to verify
  // szFileName - input digidoc filename
  // returns error code
  //--------------------------------------------------
  EXP_OPTION int verifySignatureAndNotary(SignedDoc* pSigDoc, SignatureInfo* pSigInfo, const char* szFileName);

  //--------------------------------------------------
  // Extract common name from cert DN or responder id
  // src - DN
  // dest - buffer for CN
  // destLen - size of output buffer in bytes
  //--------------------------------------------------
  int findCN(char* src, char* dest, int destLen);

  //------------------------------------------
  // Verify certificate by OCSP
  // pCert - certificate to check
  // ppResp - address to return OCSP response. Use NULL if
  // you don't want OCSP response to be returned
  // returns error code
  //------------------------------------------
  EXP_OPTION int ddocVerifyCertByOCSP(X509* pCert, OCSP_RESPONSE **ppResp);

  //------------------------------------------
  // Verify certificate by OCSP
  // pCert - certificate to check
  // ppResp - address to return OCSP response. Use NULL if
  // you don't want OCSP response to be returned
  // returns error code
  //------------------------------------------
  EXP_OPTION int ddocVerifyCertByOCSPWithIp(X509* pCert, OCSP_RESPONSE **ppResp, unsigned long ip);

  //------------------------------------------
  // Reads an arbitrary file into memory buffer
  // szFileName - file name and path
  // pData - memory buffer object
  // returns error code
  //------------------------------------------
  EXP_OPTION int ddocReadFile(const char* szFileName, DigiDocMemBuf* pData);

  //------------------------------------------
  // Writes an arbitrary file into memory buffer
  // szFileName - file name and path
  // pData - memory buffer object
  // returns error code
  //------------------------------------------
  EXP_OPTION int ddocWriteFile(const char* szFileName, DigiDocMemBuf* pData);
	

#ifdef  __cplusplus
}
#endif


#endif // __DIGI_DOC_CFG_H__
