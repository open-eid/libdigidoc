//==================================================
// FILE:	DigiDocService.c
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

// config data comes from there
#include <config.h>
#include <libdigidoc/DigiDocConfig.h>
#include <libdigidoc/DigiDocService.h>
#include <libdigidoc/DigiDocDebug.h>
#include <libdigidoc/DigiDocMem.h>
#include <libdigidoc/DigiDocObj.h>
#include <libdigidoc/DigiDocConvert.h>
#include <libdigidoc/DigiDocGen.h>
#include <libdigidoc/DigiDocSAXParser.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

char* g_xmlHdr1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:d=\"http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl\"><SOAP-ENV:Body SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><d:MobileCreateSignature>";
char* g_xmlEnd1 = "</d:MobileCreateSignature></SOAP-ENV:Body></SOAP-ENV:Envelope>";
char* g_xmlHdr2 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:d=\"http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl\"><SOAP-ENV:Body SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><d:GetMobileCreateSignatureStatus>";
char* g_xmlEnd2 = "</d:GetMobileCreateSignatureStatus></SOAP-ENV:Body></SOAP-ENV:Envelope>";

char* g_ddsUrl = "https://digidocservice.sk.ee/DigiDocService";

int ddocXmlElem(DigiDocMemBuf* pMbuf, const char* szElem, const char* szValue)
{
    int err = ERR_OK;
    if(szValue) {
        err = ddocGen_startElem(pMbuf, szElem);
        if(!err)
            err = ddocMemAppendData(pMbuf, szValue, -1);
        if(!err)
            err = ddocGen_endElem(pMbuf, szElem);
    }
    return err;
}

int findXmlElemValue(DigiDocMemBuf* pMbMsg, const char* szTag, DigiDocMemBuf* pMbValue)
{
    char *p1, *p2;
    char tag[50];
    
    p1 = (char*)pMbMsg->pMem;
    if(p1) {
        snprintf(tag, sizeof(tag), "<%s", szTag);
        p1 = strstr(p1, tag);
        if(p1) {
            while(*p1 && *p1 != '>') p1++;
            if(*p1 && *p1 == '>') p1++;
            snprintf(tag, sizeof(tag), "</%s", szTag);
            p2 = strstr(p1, tag);
            if(p2 && p1 && (long)p2 > (long)p1) {
                ddocMemAssignData(pMbValue, p1, (int)(p2 - p1));
                return 0;
            }
        }
    }
    return -1;
}


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
                       long* pSesscode, char* szChallenge, int nChalLen)
{
    int err = ERR_OK, i, l1;
    char *p1 = 0;
    DataFile *pDf = 0;
    DigiDocMemBuf mbuf1, mbuf2, mbuf3;
    char buf1[40];
    
    mbuf1.pMem = 0;
    mbuf1.nLen = 0;
    mbuf2.pMem = 0;
    mbuf2.nLen = 0;
    mbuf3.pMem = 0;
    mbuf3.nLen = 0;
    ddocDebug(3, "ddsSign", "Creating M-ID signature using: %s", szPhoneNo);
    RETURN_IF_NULL_PARAM(pSigDoc);
    RETURN_IF_NULL_PARAM(szIdCode);
    RETURN_IF_NULL_PARAM(country);
    RETURN_IF_NULL_PARAM(szPhoneNo);
    //RETURN_IF_NULL_PARAM(url);
    if(url == NULL)
        url = g_ddsUrl;
    RETURN_IF_NULL_PARAM(pSesscode);
    RETURN_IF_NULL_PARAM(szChallenge);
    ddocMemAssignData(&mbuf2, g_xmlHdr1, -1);
    // create xml request
    err = ddocXmlElem(&mbuf2, "IDCode", szIdCode);
    err = ddocXmlElem(&mbuf2, "SignersCountry", country);
    err = ddocXmlElem(&mbuf2, "PhoneNo", szPhoneNo);
    err = ddocXmlElem(&mbuf2, "Language", szLang);
    err = ddocXmlElem(&mbuf2, "ServiceName", szServiceName);
    err = ddocXmlElem(&mbuf2, "Role", manifest);
    err = ddocXmlElem(&mbuf2, "City", city);
    err = ddocXmlElem(&mbuf2, "StateOrProvince", state);
    err = ddocXmlElem(&mbuf2, "PostalCode", zip);
    err = ddocXmlElem(&mbuf2, "CountryName", country);
    err = ddocGen_startElem(&mbuf2, "DataFiles");
    for(i = 0; i < getCountOfDataFiles(pSigDoc); i++) {
        pDf = getDataFile(pSigDoc, i);
        err = ddocGen_startElem(&mbuf2, "DataFileDigest");
        err = ddocXmlElem(&mbuf2, "Id", pDf->szId);
        err = ddocXmlElem(&mbuf2, "DigestType", pDf->szDigestType);
        l1 = sizeof(buf1);
        memset(buf1, 0, l1);
        encode((const byte*)pDf->mbufDigest.pMem, pDf->mbufDigest.nLen, (byte*)buf1, &l1);
        err = ddocXmlElem(&mbuf2, "DigestValue", buf1);
        err = ddocGen_endElem(&mbuf2, "DataFileDigest");
    }
    err = ddocGen_endElem(&mbuf2, "DataFiles");
    err = ddocXmlElem(&mbuf2, "Format", pSigDoc->szFormat);
    err = ddocXmlElem(&mbuf2, "Version", pSigDoc->szFormatVer);
    sprintf(buf1, "S%d", getNextSignatureId(pSigDoc));
    err = ddocXmlElem(&mbuf2, "SignatureID", buf1);
    err = ddocXmlElem(&mbuf2, "MessagingMode", "asynchClientServer");
    err = ddocXmlElem(&mbuf2, "AsyncConfiguration", "0");
    ddocMemAppendData(&mbuf2, g_xmlEnd1, -1);

    // create http req
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
    ddocMemAppendData(&mbuf1, "User-Agent: DigiDocLib\r\n", -1);
    ddocMemAppendData(&mbuf1, "Content-Type: text/xml; charset=utf-8\r\n", -1);
    snprintf(buf1, sizeof(buf1), "Content-Length: %d\r\n", (int)mbuf2.nLen);
    ddocMemAppendData(&mbuf1, buf1, -1);
    ddocMemAppendData(&mbuf1, "Connection: Close\r\n", -1);
    if(proxyHost || (proxyPort && atoi(proxyPort) > 0)) // if we use proxy then send also Proxy-Connection
        ddocMemAppendData(&mbuf1, "Proxy-Connection: Close\r\n", -1);
    ddocMemAppendData(&mbuf1, "SOAPAction: \"\"\r\n", -1);
    ddocMemAppendData(&mbuf1, "\r\n", -1);
    ddocMemAppendData(&mbuf1, mbuf2.pMem, mbuf2.nLen);
	ddocDebug(4, "ddsSign", "Send to host: %s request len: %d", url, mbuf1.nLen);
    ddocDebug(4, "ddsSign", "Sending: \n---\n%s\n---\n", mbuf1.pMem);
    ddocMemBuf_free(&mbuf2);
    err = ddocPullUrl(url, &mbuf1, &mbuf2, proxyHost, proxyPort);
    ddocDebug(4, "ddsSign", "Recevied len: %d RC: %d", mbuf2.nLen, err);
    //ddocDebug(3, "ddsSign", "Received: \n---\n%s\n---\n", mbuf2.pMem);
    if(!err && ((l1 = ddocGetHttpResponseCode(&mbuf2)) == 200)) {
        err = ddocGetHttpPayload(&mbuf2, &mbuf3);
        ddocMemBuf_free(&mbuf2);
        ddocDebug(4, "ddsSign", "SOAP: \n---\n%s\n---\n", mbuf3.pMem);
        err = findXmlElemValue(&mbuf3, "Sesscode", &mbuf2);
        if(!err)
          (*pSesscode) = atol((char*)mbuf2.pMem);
        //ddocDebug(3, "ddsSign", "Sesscode: %ld", (*pSesscode));
        ddocMemBuf_free(&mbuf2);
        err = findXmlElemValue(&mbuf3, "ChallengeID", &mbuf2);
        //ddocDebug(3, "ddsSign", "Challenge id %s", mbuf2.pMem);
        if(!err && mbuf2.pMem && mbuf2.nLen) {
            memset(szChallenge, 0, nChalLen);
            strncpy(szChallenge, mbuf2.pMem, mbuf2.nLen);
        }
        ddocDebug(3, "ddsSign", "Sesscode: %ld Challenge id %s RC: %d", (*pSesscode), szChallenge, err);
        ddocMemBuf_free(&mbuf2);
    }
    
    ddocMemBuf_free(&mbuf1);
    ddocMemBuf_free(&mbuf2);
    ddocMemBuf_free(&mbuf3);
    RETURN_IF_NOT(err == ERR_OK, err);
    return err;
}

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
                            int* pStatus)
{
    return ddsGetStatusWithFile(pSigDoc, lSesscode, url, proxyHost, proxyPort, pStatus, NULL);
}

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
                            int* pStatus, const char* szFileName)
{
    int err = ERR_OK, l1;
    SignatureInfo *pSigInfo = 0;
    DigiDocMemBuf mbuf1, mbuf2, mbuf3;
    char buf1[40], *p1;
    
    mbuf1.pMem = 0;
    mbuf1.nLen = 0;
    mbuf2.pMem = 0;
    mbuf2.nLen = 0;
    mbuf3.pMem = 0;
    mbuf3.nLen = 0;
    ddocDebug(3, "ddsGetStatus", "Get Status for sess: %ld", lSesscode);
    RETURN_IF_NULL_PARAM(pSigDoc);
    //RETURN_IF_NULL_PARAM(url);
    if(url == NULL)
        url = g_ddsUrl;
    RETURN_IF_NULL_PARAM(pStatus);
    *pStatus = 0;
    ddocMemAssignData(&mbuf2, g_xmlHdr2, -1);
    // create xml request
    sprintf(buf1, "%ld", lSesscode);
    err = ddocXmlElem(&mbuf2, "Sesscode", buf1);
    err = ddocXmlElem(&mbuf2, "WaitSignature", "false");
    ddocMemAppendData(&mbuf2, g_xmlEnd2, -1);
    
    // create http req
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
    ddocMemAppendData(&mbuf1, "User-Agent: DigiDocLib\r\n", -1);
    ddocMemAppendData(&mbuf1, "Content-Type: text/xml; charset=utf-8\r\n", -1);
    snprintf(buf1, sizeof(buf1), "Content-Length: %d\r\n", (int)mbuf2.nLen);
    ddocMemAppendData(&mbuf1, buf1, -1);
    ddocMemAppendData(&mbuf1, "Connection: Close\r\n", -1);
    if(proxyHost || (proxyPort && atoi(proxyPort) > 0)) // if we use proxy then send also Proxy-Connection
        ddocMemAppendData(&mbuf1, "Proxy-Connection: Close\r\n", -1);
    ddocMemAppendData(&mbuf1, "SOAPAction: \"\"\r\n", -1);
    ddocMemAppendData(&mbuf1, "\r\n", -1);
    ddocMemAppendData(&mbuf1, mbuf2.pMem, mbuf2.nLen);
	ddocDebug(4, "ddsGetStatus", "Send to host: %s request len: %d", url, mbuf1.nLen);
    ddocDebug(4, "ddsGetStatus", "Sending: \n---\n%s\n---\n", mbuf1.pMem);
    ddocMemBuf_free(&mbuf2);
    err = ddocPullUrl(url, &mbuf1, &mbuf2, proxyHost, proxyPort);
    ddocDebug(4, "ddsGetStatus", "Recevied len: %d RC: %d", mbuf2.nLen, err);
    //ddocDebug(3, "ddsSign", "Received: \n---\n%s\n---\n", mbuf2.pMem);
    if(!err && ((l1 = ddocGetHttpResponseCode(&mbuf2)) == 200)) {
        err = ddocGetHttpPayload(&mbuf2, &mbuf3);
        ddocMemBuf_free(&mbuf2);
        ddocDebug(4, "ddsGetStatus", "SOAP: \n---\n%s\n---\n", mbuf3.pMem);
        err = findXmlElemValue(&mbuf3, "Status", &mbuf2);
        if(!err && mbuf2.pMem) {
            if(!strcmp((char*)mbuf2.pMem, "OUTSTANDING_TRANSACTION"))
                (*pStatus) = STATUS_OUTSTANDING_TRANSACTION;
            if(!strcmp((char*)mbuf2.pMem, "SIGNATURE"))
                (*pStatus) = STATUS_SIGNATURE;
            if(!strcmp((char*)mbuf2.pMem, "ERROR"))
                (*pStatus) = STATUS_ERROR;
            
        }
        ddocDebug(3, "ddsGetStatus", "Sesscode: %ld Status: %d RC: %d", lSesscode, (*pStatus), err);
        ddocMemBuf_free(&mbuf2);
        if((*pStatus) == STATUS_SIGNATURE) {
            err = findXmlElemValue(&mbuf3, "Signature", &mbuf2);
            ddocDebug(4, "ddsGetStatus", "Sig-esacped: \n---\n%s\n---\n", mbuf2.pMem);
            p1 = escape2xmlsym((char*)mbuf2.pMem);
            ddocDebug(4, "ddsGetStatus", "Signature: \n---\n%s\n---\n", p1);
            err = ddocAddSignatureFromMemory(pSigDoc, szFileName, (const void*)p1, strlen(p1));
            /*sprintf(buf1, "S%d", getNextSignatureId(pSigDoc));
            SignatureInfo_new(&pSigInfo, pSigDoc, buf1);
            ddocMemAssignData(&(pSigInfo->mbufOrigContent), p1, -1);*/
            free(p1);
        }
    }
    
    ddocMemBuf_free(&mbuf1);
    ddocMemBuf_free(&mbuf2);
    ddocMemBuf_free(&mbuf3);
    RETURN_IF_NOT(err == ERR_OK, err);
    return err;
}

