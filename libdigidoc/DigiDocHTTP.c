#include <libdigidoc/DigiDocHTTP.h>
#include <libdigidoc/DigiDocError.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

//--------------------------------------------------
// Returns HTTP return code
// pBuf- buffer with HTTP response
// returns error code or HTTP response code
//--------------------------------------------------
int ddocGetHttpResponseCode(DigiDocMemBuf* pBuf)
{
  int rc = ERR_OK;
  char *p = (char*)pBuf->pMem;
  RETURN_IF_NULL_PARAM(pBuf);
  if(p && !strncmp(p, "HTTP", 4)) {
	while(*p && *p != ' ') p++;
	while(*p && !isdigit(*p)) p++;
	rc = atoi(p);
  } else
	return ERR_HTTP_ERR;
  return rc;
}

//--------------------------------------------------
// Returns HTTP response body
// pInBuf- buffer with HTTP response
// pOutBuf - buffer for response body
// returns error code or ERR_OK
//--------------------------------------------------
int ddocGetHttpPayload(DigiDocMemBuf* pInBuf, DigiDocMemBuf* pOutBuf)
{
  int err = ERR_OK;
  char *p;
  RETURN_IF_NULL_PARAM(pInBuf);
  RETURN_IF_NULL_PARAM(pOutBuf);
  if((p = strstr((char*)pInBuf->pMem, "\r\n\r\n")) != NULL) {
	p += 4;
	err = ddocMemAssignData(pOutBuf, p, pInBuf->nLen - (int)(p - (char*)pInBuf->pMem));
  } else
	return ERR_HTTP_ERR;
  return err;
}
