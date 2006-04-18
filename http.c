/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 1998-2006 Luca Deri <deri@ntop.org>
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "ntop.h"
#include "globals-report.h"


#if 0
#define URL_DEBUG 
#define HTTP_DEBUG 
#endif

/* Private structure definitions */

struct _HTTPstatus {
    int statusCode;
    char *reasonPhrase;
    char *longDescription;
};

/*
   This is the complete list of "Status Codes" and suggested
   "Reason Phrases" for HTTP responses, as stated in RFC 2068
   NOTE: the natural order is altered so "200 OK" results the
         first item in the table (index = 0)
*/
struct _HTTPstatus HTTPstatus[] = {
    { 200, "OK", NULL },
    { 100, "Continue", NULL },
    { 101, "Switching Protocols", NULL },
    { 201, "Created", NULL },
    { 202, "Accepted", NULL },
    { 203, "Non-Authoritative Information", NULL },
    { 204, "No Content", NULL },
    { 205, "Reset Content", NULL },
    { 206, "Partial Content", NULL },
    { 300, "Multiple Choices", NULL },
    { 301, "Moved Permanently", NULL },
    { 302, "Moved Temporarily", NULL },
    { 303, "See Other", NULL },
    { 304, "Not Modified", NULL },
    { 305, "Use Proxy", NULL },
    { 400, "Bad Request", "The specified request is invalid." },
    { 401, "Authorization Required", "Unauthorized to access the document." },
    { 402, "Payment Required", NULL },
    { 403, "Forbidden", "Server refused to fulfill your request." },
    { 404, "Not Found", "The server cannot find the requested page "
                        "(page expired or ntop configuration ?)." },
    { 405, "Method Not Allowed", NULL },
    { 406, "Not Acceptable", NULL },
    { 407, "Proxy Authentication Required", NULL },
    { 408, "Request Time-out", "The request was timed-out." },
    { 409, "Conflict", NULL },
    { 410, "Gone", "The page you requested is not available in your current ntop "
                   "<A HREF=\"/" CONST_INFO_NTOP_HTML "\">configuration</A>. See the ntop "
                   "<A HREF=\"/" CONST_MAN_NTOP_HTML "\">man page</A> for more information" },
    { 411, "Length Required", NULL },
    { 412, "Precondition Failed", NULL },
    { 413, "Request Entity Too Large", NULL },
    { 414, "Request-URI Too Large", NULL },
    { 415, "Unsupported Media Type", NULL },
    { 500, "Internal Server Error", NULL },
    { 501, "Not Implemented", "The requested method is not implemented by this server." },
    { 502, "Bad Gateway", NULL },
    { 503, "Service Unavailable", NULL },
    { 504, "Gateway Time-out", NULL },
    { 505, "HTTP Version not supported", "This server doesn't support the specified HTTP version." },
};

/*
  Note: the numbers below are offsets inside the HTTPstatus table,
        they must be corrected every time the table is modified.
*/
#define BITFLAG_HTTP_STATUS_200	( 0<<8)
#define BITFLAG_HTTP_STATUS_302	(11<<8)
#define BITFLAG_HTTP_STATUS_400	(15<<8)
#define BITFLAG_HTTP_STATUS_401	(16<<8)
#define BITFLAG_HTTP_STATUS_403	(18<<8)
#define BITFLAG_HTTP_STATUS_404	(19<<8)
#define BITFLAG_HTTP_STATUS_408	(23<<8)
#define BITFLAG_HTTP_STATUS_501	(32<<8)
#define BITFLAG_HTTP_STATUS_505	(36<<8)

/* ************************* */

#define MAX_NUM_COMMUNITIES    32

static u_int httpBytesSent;
char httpRequestedURL[512], theHttpUser[32], theLastHttpUser[32];
char allowedCommunities[256], *listAllowedCommunities[MAX_NUM_COMMUNITIES];
static HostAddr *requestFrom;

/* ************************* */

/* Forward */
static int readHTTPheader(char* theRequestedURL,
                          int theRequestedURLLen,
                          char *thePw,
                          int thePwLen,
                          char *theAgent,
                          int theAgentLen,
                          char *theReferer,
                          int theRefererLen,
                          char *theLanguage,
                          int theLanguageLen, int *isPostMethod);
static int returnHTTPPage(char* pageName,
                          int postLen,
                          HostAddr *from,
			  struct timeval *httpRequestedAt,
                          int *usedFork,
                          char *agent,
                          char *referer,
                          char *requestedLanguage[],
                          int numLang, int isPostMethod);

static int generateNewInternalPages(char* pageName);
static int decodeString(char *bufcoded, unsigned char *bufplain, int outbufsize);
static void logHTTPaccess(int rc, struct timeval *httpRequestedAt, u_int gzipBytesSent);
static void returnHTTPspecialStatusCode(int statusIdx, char *additionalText);
static int checkURLsecurity(char *url);
static int checkHTTPpassword(char *theRequestedURL, int theRequestedURLLen _UNUSED_, char* thePw, int thePwLen);
static char compressedFilePath[256];
static short compressFile = 0, acceptGzEncoding;
static FILE *compressFileFd=NULL;
#ifdef MAKE_WITH_ZLIB
static void compressAndSendData(u_int*);
#endif

/* ************************* */

#ifdef HAVE_OPENSSL
char* printSSLError(int errorId) {
  switch(errorId) {
  case SSL_ERROR_NONE:             return("SSL_ERROR_NONE");
  case SSL_ERROR_SSL:              return("SSL_ERROR_SSL");
  case SSL_ERROR_WANT_READ:        return("SSL_ERROR_WANT_READ");
  case SSL_ERROR_WANT_WRITE:       return("SSL_ERROR_WANT_WRITE");
  case SSL_ERROR_WANT_X509_LOOKUP: return("SSL_ERROR_WANT_X509_LOOKUP");
  case SSL_ERROR_SYSCALL:          return("SSL_ERROR_SYSCALL");
  case SSL_ERROR_ZERO_RETURN:      return("SSL_ERROR_ZERO_RETURN");
  case SSL_ERROR_WANT_CONNECT:     return("SSL_ERROR_WANT_CONNECT");
  default:                         return("???");
  }
}
#endif

/* ************************* */

static int readHTTPheader(char* theRequestedURL,
                          int theRequestedURLLen,
                          char *thePw, int thePwLen,
                          char *theAgent, int theAgentLen,
                          char *theReferer, int theRefererLen,
                          char *theLanguage, int theLanguageLen,
                          int *isPostMethod) {
#ifdef HAVE_OPENSSL
  SSL* ssl = getSSLsocket(-myGlobals.newSock);
#endif
  char aChar[8] /* just in case */, lastChar;
  char preLastChar, *lineStr;
  int rc, idxChar=0, contentLen=-1, numLine=0, topSock;
  fd_set mask;
  struct timeval wait_time;
  int errorCode=0, lineStrLen;
  char *tmpStr;

  *isPostMethod = FALSE;        /* Assume GET Method by default */
  thePw[0] = '\0';
  preLastChar = '\r';
  lastChar = '\n';
  theRequestedURL[0] = '\0';
  memset(httpRequestedURL, 0, sizeof(httpRequestedURL));

  lineStrLen = 768;
  lineStr = (char*)calloc(lineStrLen, sizeof(char));
  if(lineStr == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Not enough memory");
    return(FLAG_HTTP_INVALID_REQUEST);
  }

#ifdef HAVE_OPENSSL
  topSock = abs(myGlobals.newSock);
#else
  topSock = myGlobals.newSock;
#endif

  for(;;) {
    FD_ZERO(&mask);
    FD_SET((unsigned int)topSock, &mask);

    /* printf("About to call select()\n"); fflush(stdout); */

    if(myGlobals.newSock > 0) {
      /*
	 Call select only for HTTP.
	 Fix courtesy of Olivier Maul <oli@42.nu>
      */

      /* select returns immediately */
      wait_time.tv_sec = 10; wait_time.tv_usec = 0;
      if(select(myGlobals.newSock+1, &mask, 0, 0, &wait_time) == 0) {
	errorCode = FLAG_HTTP_REQUEST_TIMEOUT; /* Timeout */
#ifdef URL_DEBUG
	traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Timeout while reading from socket.");
#endif
	break;
      }
    }

    /* printf("About to call recv()\n"); fflush(stdout); */
    /* printf("Rcvd %d bytes\n", recv(myGlobals.newSock, aChar, 1, MSG_PEEK)); fflush(stdout); */

#ifdef HAVE_OPENSSL
    if(myGlobals.newSock < 0) {
      rc = SSL_read(ssl, aChar, 1);
      if(rc == -1)
	ntop_ssl_error_report("read");
    } else
      rc = recv(myGlobals.newSock, aChar, 1, 0);
#else
    rc = recv(myGlobals.newSock, aChar, 1, 0);
#endif

    if(rc != 1) {
      idxChar = 0;
#ifdef URL_DEBUG
      traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Socket read returned %d (errno=%d)", rc, errno);
#endif
      /* FIXME (DL): is valid to write to the socket after this condition? */
      break; /* Empty line */

    } else if((errorCode == 0) && !isprint(aChar[0]) && !isspace(aChar[0])) {
      errorCode = FLAG_HTTP_INVALID_REQUEST;
#ifdef URL_DEBUG
      traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Rcvd non expected char '%c' [%d/0x%x]", aChar[0], aChar[0], aChar[0]);
#endif
    } else {
#ifdef URL_DEBUG
      if(0) traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Rcvd char '%c' [%d/0x%x]", aChar[0], aChar[0], aChar[0]);
#endif
      if(aChar[0] == '\r') {
	/* <CR> is ignored as recommended in section 19.3 of RFC 2068 */
	continue;
      } else if(aChar[0] == '\n') {
	if(lastChar == '\n') {
	  idxChar = 0;
	  break;
	}
	numLine++;
	lineStr[idxChar] = '\0';
#ifdef URL_DEBUG
	traceEvent(CONST_TRACE_INFO, "URL_DEBUG: read HTTP %s line: %s [%d]",
	           (numLine>1) ? "header" : "request", lineStr, idxChar);
#endif
	if(errorCode != 0) {
	  ;  /* skip parsing after an error was detected */
	} else if(numLine == 1) {
	  strncpy(httpRequestedURL, lineStr,
		  sizeof(httpRequestedURL)-1)[sizeof(httpRequestedURL)-1] = '\0';

	  if(idxChar < 9) {
	    errorCode = FLAG_HTTP_INVALID_REQUEST;
#ifdef URL_DEBUG
	    traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Too short request line.");
#endif

	  } else if(strncmp(&lineStr[idxChar-9], " HTTP/", 6) != 0) {
	    errorCode = FLAG_HTTP_INVALID_REQUEST;
#ifdef URL_DEBUG
	    traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Malformed request line. [%s][idxChar=%d]",
		       &lineStr[idxChar-9], idxChar);

	    {
	      int y;

	      for(y=0; y<idxChar; y++) 
		traceEvent(CONST_TRACE_INFO, "URL_DEBUG: lineStr[%d]='%c'", y, lineStr[y]);
	    }
#endif

	  } else if((strncmp(&lineStr[idxChar-3], "1.0", 3) != 0) &&
	            (strncmp(&lineStr[idxChar-3], "1.1", 3) != 0)) {
	    errorCode = FLAG_HTTP_INVALID_VERSION;
#ifdef URL_DEBUG
	    traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Unsupported HTTP version.");
#endif

	  } else {

            lineStr[idxChar-9] = '\0'; idxChar -= 9; tmpStr = NULL;

	    if((idxChar >= 3) && (strncmp(lineStr, "GET ", 4) == 0)) {
	      tmpStr = &lineStr[4];
	    } else if((idxChar >= 4) && (strncmp(lineStr, "POST ", 5) == 0)) {
	      tmpStr = &lineStr[5];
              *isPostMethod = TRUE;
	      /*
		HEAD method could be supported with some litle modifications...
		} else if((idxChar >= 4) && (strncmp(lineStr, "HEAD ", 5) == 0)) {
		tmpStr = &lineStr[5];
	      */
	    } else {
	      errorCode = FLAG_HTTP_INVALID_METHOD;
#ifdef URL_DEBUG
	      traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Unrecognized method in request line.");
#endif
	    }

	    if(tmpStr) {
	      int beginIdx;

	      /*
		Before to copy the URL let's check whether
		it has been sent through a proxy
	      */

	      if(strncasecmp(tmpStr, "http://", 7) == 0)
		beginIdx = 7;
	      else if(strncasecmp(tmpStr, "https://", 8) == 0)
		beginIdx = 8;
	      else
		beginIdx = 0;

	      if(beginIdx > 0) {
		while((tmpStr[beginIdx] != '\0') && (tmpStr[beginIdx] != '/'))
		  beginIdx++;
	      }

	      strncpy(theRequestedURL, &tmpStr[beginIdx],
		      theRequestedURLLen-1)[theRequestedURLLen-1] = '\0';
	    }
	  }

	} else if((idxChar >= 21)
		  && (strncasecmp(lineStr, "Authorization: Basic ", 21) == 0)) {
	  strncpy(thePw, &lineStr[21], thePwLen-1)[thePwLen-1] = '\0';
#ifdef MAKE_WITH_ZLIB
	} else if((idxChar >= 17)
		  && (strncasecmp(lineStr, "Accept-Encoding: ", 17) == 0)) {
	  if(strstr(&lineStr[17], "gzip"))
	    acceptGzEncoding = 1;
#endif
#ifdef MAKE_WITH_I18N
	} else if((idxChar >= 17)
		  && (strncasecmp(lineStr, "Accept-Language: ", 17) == 0)) {
	  strncpy(theLanguage, &lineStr[17], theLanguageLen-1)[theLanguageLen-1] = '\0';
#endif
	} else if((idxChar >= 16)
		  && (strncasecmp(lineStr, "Content-Length: ", 16) == 0)) {
	  contentLen = atoi(&lineStr[16]);
#ifdef URL_DEBUG
	  traceEvent(CONST_TRACE_INFO, "URL_DEBUG: len=%d [%s/%s]", contentLen, lineStr, &lineStr[16]);
#endif
	} else if((idxChar >= 12)
		  && (strncasecmp(lineStr, "User-Agent: ", 12) == 0)) {
	  strncpy(theAgent, &lineStr[12], theAgentLen-1)[theAgentLen-1] = '\0';
	} else if((idxChar >= 9)
		  && (strncasecmp(lineStr, "Referer: ", 9) == 0)) {
	  strncpy(theReferer, &lineStr[9], theRefererLen-1)[theRefererLen-1] = '\0';
	}
	idxChar=0;
      } else if(idxChar > lineStrLen-2) {
	if(errorCode == 0) {
	  errorCode = FLAG_HTTP_INVALID_REQUEST;
#ifdef URL_DEBUG
	  traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Line too long (hackers ?)");
#endif
	}
      } else {
	lineStr[idxChar++] = aChar[0];
      }

    }
    lastChar = aChar[0];
  }

  free(lineStr);
  return((errorCode) ? errorCode : contentLen);
}

/* ************************* */

char* encodeString(char* in, char* out, u_int out_len) {
  int i, out_idx;

  out[0] = '\0';
  
  for(i = out_idx = 0; i < strlen(in); i++) {
      if(isalnum(in[i])) {
	out[out_idx++] = in[i];
	if(out_idx >= out_len) return(out);

      } else if(in[i] == ' ') {
	out[out_idx++] = '+';
	if(out_idx >= out_len) return(out);
      } else {
	char hex_str[8];

	out[out_idx++] = '%';

	sprintf(hex_str, "%02X", in[i] & 0xFF);
	out[out_idx++] = hex_str[0];
	if(out_idx >= out_len) return(out);
	out[out_idx++] = hex_str[1];
	if(out_idx >= out_len) return(out);
      }
  }
  
  out[out_idx++] = '\0';
  return(out);
}

/* ************************* */

static int decodeString(char *bufcoded,
			unsigned char *bufplain,
			int outbufsize) {
  /* single character decode */
#define DEC(c) pr2six[(int)c]
#define MAXVAL 63
  unsigned char pr2six[256];
  char six2pr[64] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9','+','/'
  };
  /* static */ int first = 1;

  int nbytesdecoded, j;
  register char *bufin = bufcoded;
  register unsigned char *bufout = bufplain;
  register int nprbytes;

  /* If this is the first call, initialize the mapping table.
   * This code should work even on non-ASCII machines.
   */
  if(first) {
    first = 0;
    for(j=0; j<256; j++) pr2six[j] = MAXVAL+1;

    for(j=0; j<64; j++) pr2six[(int)six2pr[j]] = (unsigned char) j;
  }

  /* Strip leading whitespace. */

  while(*bufcoded==' ' || *bufcoded == '\t') bufcoded++;

  /* Figure out how many characters are in the input buffer.
   * If this would decode into more bytes than would fit into
   * the output buffer, adjust the number of input bytes downwards.
   */
  bufin = bufcoded;
  while(pr2six[(int)*(bufin++)] <= MAXVAL)
    ;

  nprbytes = bufin - bufcoded - 1;
  nbytesdecoded = ((nprbytes+3)/4) * 3;
  if(nbytesdecoded > outbufsize) {
    nprbytes = (outbufsize*4)/3;
  }

  bufin = bufcoded;

  while (nprbytes > 0) {
    *(bufout++) = (unsigned char) (DEC(*bufin) << 2 | DEC(bufin[1]) >> 4);
    *(bufout++) = (unsigned char) (DEC(bufin[1]) << 4 | DEC(bufin[2]) >> 2);
    *(bufout++) = (unsigned char) (DEC(bufin[2]) << 6 | DEC(bufin[3]));
    bufin += 4;
    nprbytes -= 4;
  }

  if(nprbytes & 03) {
    if(pr2six[(int)bufin[-2]] > MAXVAL) {
      nbytesdecoded -= 2;
    } else {
      nbytesdecoded -= 1;
    }
  }

  return(nbytesdecoded);
}

/* ************************* */

static void ssiMenu_Head() {
  FlowFilterList *flows = myGlobals.flowsList;
  short foundAplugin = 0;
  char buf[LEN_GENERAL_WORK_BUFFER];
  ExtraPage *ep;

  memset(&buf, 0, sizeof(buf));

  sendStringWOssi(
             "<link rel=\"stylesheet\" href=\"/theme.css\" TYPE=\"text/css\">\n"
             "<script type=\"text/javascript\" language=\"JavaScript\" src=\"/theme.js\"></script>\n"
             "<script type=\"text/javascript\" language=\"JavaScript\" SRC=\"/JSCookMenu.js\"></script>\n"
             "<script type=\"text/javascript\" language=\"JavaScript\"><!--\n"
             "var ntopMenu =\n"
             "[\n"
             "	[null,'About',null,null,null,\n"
             "		[null,'What is ntop?','/" CONST_ABTNTOP_HTML "',null,null],\n"
             "		[null,'Show Configuration','/" CONST_INFO_NTOP_HTML "',null,null],\n"
             "		[null,'Credits','/" CONST_CREDITS_HTML "',null,null],\n"
             "		[null,'Man Page','/" CONST_MAN_NTOP_HTML "',null,null],\n"
             "		['<img src=\"/help.png\">','Help','/ntop" CONST_NTOP_HELP_HTML "',null,null],\n"
             "		['<img src=\"/bug.png\">','Report a Problem','/" CONST_PROBLEMRPT_HTML "',null,null],\n"
             "		[null,'FAQ','/faq.html',null,null],\n"
             "		['<img src=\"/Risk_high.gif\">','Risk Flags','/" CONST_NTOP_HELP_HTML "',null,null],\n"
             "		],\n"
             "	[null,'Summary',null,null,null,\n"
             "		[null,'Traffic','/" CONST_TRAFFIC_STATS_HTML "',null,null],\n"
             "		[null,'Hosts','/" CONST_HOSTS_INFO_HTML "',null,null],\n"
             "		[null,'Network Load','/" CONST_SORT_DATA_THPT_STATS_HTML "',null,null],\n");
  if(myGlobals.haveASN == TRUE)
    sendStringWOssi(
             "		[null,'ASN Info','/" CONST_AS_LIST_HTML "',null,null],\n");
  if(myGlobals.haveVLANs == TRUE)
    sendStringWOssi(
             "		[null,'VLAN Info','/" CONST_VLAN_LIST_HTML "',null,null],\n");
  sendStringWOssi(
             "		[null,'Network Flows','/" CONST_NET_FLOWS_HTML "',null,null],\n"
             "		],\n"
             "  [null,'All Protocols',null,null,null,\n"
             "          [null,'Traffic','/" CONST_SORT_DATA_PROTOS_HTML "',null,null],\n"
             "          [null,'Throughput','/" CONST_SORT_DATA_THPT_HTML "',null,null],\n"
             "          [null,'Activity','/" CONST_SORT_DATA_HOST_TRAFFIC_HTML "',null,null],\n"
             "          ],\n"
             "	[null,'IP',null,null,null,\n"
             "		[null,'Summary',null,null,null,\n"
             "				[null,'Traffic','/" CONST_SORT_DATA_IP_HTML "',null,null],\n"
             "				[null,'Multicast','/" CONST_MULTICAST_STATS_HTML "',null,null],\n"
             "				[null,'Internet Domain','/" CONST_DOMAIN_STATS_HTML "',null,null],\n"
             "				[null,'Host Clusters','/" CONST_CLUSTER_STATS_HTML "',null,null],\n"
             "				[null,'Distribution','/" CONST_IP_PROTO_DISTRIB_HTML "',null,null],\n"
             "		],\n"
             "		[null,'Traffic Directions',null,null,null,\n"
             "				[null,'Local to Local','/" CONST_IP_L_2_L_HTML "',null,null],\n"
             "				[null,'Local to Remote','/" CONST_IP_L_2_R_HTML "',null,null],\n"
             "				[null,'Remote to Local','/" CONST_IP_R_2_L_HTML "',null,null],\n"
             "				[null,'Remote to Remote','/" CONST_IP_R_2_R_HTML "',null,null],\n"
             "		],\n"
             "		[null,'Local',null,null,null,\n");
  if(myGlobals.runningPref.dontTrustMACaddr)
    sendStringWOssi(
             "				[null,'Routers','/" CONST_LOCAL_ROUTERS_LIST_HTML "',null,null],\n");
  sendStringWOssi(
             "				[null,'Ports Used','/" CONST_IP_PROTO_USAGE_HTML "',null,null],\n");
  if(myGlobals.runningPref.enableSessionHandling)
    sendStringWOssi(
             "				[null,'Active TCP/UDP Sessions','/" CONST_ACTIVE_TCP_SESSIONS_HTML "',null,null],\n");
  sendStringWOssi(
             "				[null,'Host Fingerprint','/" CONST_HOSTS_LOCAL_FINGERPRINT_HTML "',null,null],\n"
             "				[null,'Host Characterization','/" CONST_HOSTS_LOCAL_CHARACT_HTML "',null,null],\n");
#ifndef WIN32
  sendStringWOssi(
             "				[null,'Network Traffic Map','/" CONST_NETWORK_MAP_HTML "',null,null],\n");
#endif
  sendStringWOssi(
             "				[null,'Local Matrix','/" CONST_IP_TRAFFIC_MATRIX_HTML "',null,null],\n"
             "		],\n"
             "	],\n");
  if(!myGlobals.runningPref.printIpOnly) {
    sendStringWOssi(
             "	[null,'Media',null,null,null,\n"
             "		[null,'Fibre Channel',null,null,null,\n"
             "				[null,'Traffic','/" CONST_FC_DATA_HTML "',null,null],\n"
             "				[null,'Throughput','/" CONST_FC_THPT_HTML "',null,null],\n"
             "				[null,'Activity','/" CONST_FC_ACTIVITY_HTML "',null,null],\n"
             "				[null,'Hosts','/" CONST_FC_HOSTS_INFO_HTML "',null,null],\n"
             "				[null,'Traffic Per Port','/" CONST_FC_TRAFFIC_HTML "',null,null],\n");
    if(myGlobals.runningPref.enableSessionHandling) 
      sendStringWOssi(
             "				[null,'Sessions','/" CONST_FC_SESSIONS_HTML "',null,null],\n");
    sendStringWOssi(
             "				[null,'VSANs','/" CONST_VSAN_LIST_HTML "',null,null],\n"
             "				[null,'VSAN Summary','/" CONST_VSAN_DISTRIB_HTML "',null,null],\n"
             "		],\n");
    if(myGlobals.runningPref.enableSessionHandling) 
      sendStringWOssi(
             "		[null,'SCSI Sessions',null,null,null,\n"
             "				[null,'Bytes','/" CONST_SCSI_BYTES_HTML "',null,null],\n"
             "				[null,'Times','/" CONST_SCSI_TIMES_HTML "',null,null],\n"
             "				[null,'Status','/" CONST_SCSI_STATUS_HTML "',null,null],\n"
             "				[null,'Task Management','/" CONST_SCSI_TM_HTML "',null,null],\n"
             "		],\n");
  sendStringWOssi(
             "	],\n");
  }
  sendStringWOssi(
             "	[null,'Utils',null,null,null,\n"
             "		[null,'Data Dump','/dump.html',null,null],\n"
             "		[null,'View Log','/" CONST_VIEW_LOG_HTML "',null,null],\n"
             "		],\n");

  while(flows != NULL) {
    if((flows->pluginStatus.pluginPtr != NULL) && (flows->pluginStatus.pluginPtr->pluginURLname != NULL)) {
      if(foundAplugin == 0) {
        sendStringWOssi(
               "	[null,'Plugins',null,null,null,\n");
        foundAplugin = 1;
      }

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
                  "		[null,'%s',null,null,null,\n",
                  flows->pluginStatus.pluginPtr->pluginName);
      sendStringWOssi(buf);
   
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
                  "				[null,'%sctivate','/" CONST_SHOW_PLUGINS_HTML "?%s=%d',null,null],\n",
                  flows->pluginStatus.activePlugin ? "Dea" : "A",
                  flows->pluginStatus.pluginPtr->pluginURLname,
                  flows->pluginStatus.activePlugin ? 0: 1);
      sendStringWOssi(buf);

      switch(flows->pluginStatus.pluginPtr->viewConfigureFlag) {
        case NoViewNoConfigure:
          break;
        case ViewOnly:
          if(flows->pluginStatus.activePlugin) {
            safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                        "				[null,'View','/" CONST_PLUGINS_HEADER "%s',null,null],\n",
                        flows->pluginStatus.pluginPtr->pluginURLname);
            sendStringWOssi(buf);
          }
          break;
        case ConfigureOnly:
          if((flows->pluginStatus.pluginPtr->inactiveSetup) ||
             (flows->pluginStatus.activePlugin)) {
            safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                        "				[null,'Configure','/" CONST_PLUGINS_HEADER "%s',null,null],\n",
                        flows->pluginStatus.pluginPtr->pluginURLname);
            sendStringWOssi(buf);
          }
          break;
        default:
          if((flows->pluginStatus.pluginPtr->inactiveSetup) ||
             (flows->pluginStatus.activePlugin)) {
            safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                        "				[null,'View/Configure','/" CONST_PLUGINS_HEADER "%s',null,null],\n",
                        flows->pluginStatus.pluginPtr->pluginURLname);
            sendStringWOssi(buf);
          }
          break;
      }

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
                  "				[null,'Describe','/" CONST_SHOW_PLUGINS_HTML "?%s',null,null],\n",
                  flows->pluginStatus.pluginPtr->pluginURLname);
      sendStringWOssi(buf);

      ep = flows->pluginStatus.pluginPtr->extraPages;
      while((ep != NULL) && (ep->url != NULL)) {
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
                    "				[%s%s%s,'%s','/" CONST_PLUGINS_HEADER "%s/%s',null,null],\n",
                    ep->icon != NULL ? "'<img src=\"/" : "",
                    ep->icon != NULL ? ep->icon : "null",
                    ep->icon != NULL ? "\">'" : "",
                    ep->descr,
                    flows->pluginStatus.pluginPtr->pluginURLname,
                    ep->url);
        sendStringWOssi(buf);
        ep++;
      }

      sendStringWOssi(
                  "             ],\n");
    } /* true plugin */

    flows = flows->next;
  }
  if(foundAplugin != 0)
    sendStringWOssi(
             "		[null,'All','/" CONST_SHOW_PLUGINS_HTML "',null,null],\n"
             "		],\n");

  sendStringWOssi(
             "	[null,'Admin',null,null,null,\n");
  if(!myGlobals.runningPref.mergeInterfaces)
    sendStringWOssi(
             "		[null,'Switch NIC','/" CONST_SWITCH_NIC_HTML "',null,null],\n");
  sendStringWOssi(
             "		['<img src=\"/lock.png\">','Configure',null,null,null,\n"
             "			['<img src=\"/lock.png\">','Startup Options','/" CONST_CONFIG_NTOP_HTML "',null,null],\n"
             "			['<img src=\"/lock.png\">','Preferences','/"CONST_EDIT_PREFS"',null,null],\n"
             "			['<img src=\"/lock.png\">','Packet Filter','/" CONST_CHANGE_FILTER_HTML "',null,null],\n"
             "			['<img src=\"/lock.png\">','Reset Stats','/" CONST_RESET_STATS_HTML "',null,null],\n"
             "			['<img src=\"/lock.png\">','Web Users','/" CONST_SHOW_USERS_HTML "',null,null],\n"
             "			['<img src=\"/lock.png\">','Protect URLs','/" CONST_SHOW_URLS_HTML "',null,null],\n"
             "		],\n"
             "		['<img src=\"/lock.png\">','Shutdown','/" CONST_SHUTDOWN_NTOP_HTML "',null,null],\n"
             "	]\n"
             "];\n"
             "--></script>\n");
}

static void ssiMenu_Body() {
    
  sendStringWOssi(
             "<table border=\"0\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\n"
             " <tr>\n"
             "  <td colspan=\"2\" align=\"left\">\n"
             "   <table border=\"0\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\n"
             "    <tr>\n"
             "     <td colspan=\"2\" align=\"left\">");
  if(myGlobals.runningPref.instance != NULL) {
    sendStringWOssi(
             "      <table border=\"0\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\n"
             "       <tr>"
             "        <td><img src=\"/");
    if(myGlobals.runningPref.logo != NULL) {
      sendStringWOssi(myGlobals.runningPref.logo);
    } else {
      sendStringWOssi(CONST_NTOP_LOGO_GIF);
    }
    sendStringWOssi("\" class=tooltip alt=\"ntop logo\"></td>\n"
             "        <td valign=\"top\" align=\"right\" class=\"instance\">Instance:&nbsp;");
    sendStringWOssi(myGlobals.runningPref.instance);
    sendStringWOssi(
             "        </td>\n"
             "       </tr>\n"
             "      </table>");
  } else {
    sendStringWOssi(
             "      <img src=\"/" CONST_NTOP_LOGO_GIF "\">");
  }
  sendStringWOssi(
             "     </td>\n"
             "    </tr>\n"
             "   </table></td>\n"
             " </tr>\n"
             " <tr>\n"
             "  <th class=\"leftmenuitem\">\n"
             "   <div id=\"ntopMenuID\">Rut Row - bad mojo Scooby!</div>\n"
             "<script type=\"text/javascript\" language=\"JavaScript\"><!--\n"
             "        cmDraw ('ntopMenuID', ntopMenu, 'hbr', cmThemeOffice, 'ThemeOffice');\n"
             "-->\n"
             "</script></th>\n"
             "  <th class=\"leftmenuitem\" align=\"right\">(C) 1998-2006 - " CONST_MAILTO_LUCA "&nbsp;&nbsp;</th>\n"
             " </tr>\n"
             "</table>\n"
             "<p>&nbsp;</p>\n");

}

/* ************************* */

static void processSSI(const char *ssiRequest) {

  int rc;
  char *ssiVirtual,
       *ssiURIstart,
       *ssiURIend,
       *ssiPARMstart;

  myGlobals.numSSIRequests++;

#ifdef HTTP_DEBUG
  traceEvent(CONST_TRACE_INFO, "HTTP_DEBUG: SSI: Request %d = '%s'", myGlobals.numSSIRequests, ssiRequest);
#endif

  /* We need to check if it's the ONLY form we support...
   *  <!--#include virtual="uri" -->
   *
   * If it is, we need to do some of the processing we normally do in handleHTTPrequest()
   * after the receive and before returnHTTPPage(). But not all - this is, after all
   * a request made by ntop internally, or from an ntop .html page which you had to
   * be root (or the ntop userid) to install in the first place...
   *
   *  1. We need to check whether the URL is invalid, i.e. it contains '..' or
   *     similar chars that can be used for reading system files.
   *  2. We can't check the password - we no longer have the Authorization header.
   *     Besides, we already authorized the page request.
   *  3. Strip leading /s and trailing white space
   *  4. Break the URI into URI and PARM, then
   *  5. Actually process it...
   *
   * Lastly, remember ssiRequest (and pointers to it) is a COPY, so we don't have
   * to restore characters we null out. But, once we do so, we can't display the whole
   * request!
   */

  if((ssiVirtual = strstr(ssiRequest, "virtual=\"")) == NULL) {
    myGlobals.numBadSSIRequests++;
    traceEvent(CONST_TRACE_WARNING, "SSI: Ignored invalid (form): '%s'", ssiRequest);
#ifdef HTTP_DEBUG
    sendString("<!-- BAD SSI: -->");
    sendString(ssiRequest);
#endif
    return;
  }

  ssiURIstart = &ssiVirtual[strlen("virtual=\"")];

  if((ssiURIend=strchr(ssiURIstart, '"')) == NULL) {
    myGlobals.numBadSSIRequests++;
    traceEvent(CONST_TRACE_WARNING, "SSI: Ignored invalid (quotes): '%s'", ssiRequest);
#ifdef HTTP_DEBUG
    sendString("<!-- BAD SSI: -->");
    sendString(ssiRequest);
#endif
    return;
  }

  ssiURIend[0] = '\0';

#ifdef HTTP_DEBUG
  traceEvent(CONST_TRACE_INFO, "HTTP_DEBUG: SSI: Requested URI = '%s'", ssiURIstart);
#endif

  if((rc = checkURLsecurity(ssiURIstart)) != 0) {
    myGlobals.numBadSSIRequests++;
    traceEvent(CONST_TRACE_ERROR, "SSI: URL security: '%s' rejected (code=%d)",
               ssiURIstart, rc);
    return;
  }

  while(ssiURIstart[0] == '/') { ssiURIstart++; }
  while((ssiURIend > ssiURIstart) &&
         ((ssiURIend[0] == ' ') ||
          (ssiURIend[0] == '\n') ||
          (ssiURIend[0] == '\r') ||
          (ssiURIend[0] == '\t'))) { 
    ssiURIend[0] = '\0';
    ssiURIend--;
  }

  if((ssiPARMstart = strchr(ssiURIstart, '?')) != NULL) {
    /* We have parms! */
    ssiPARMstart[0] = '\0';
    ssiPARMstart++;
#ifdef HTTP_DEBUG
    traceEvent(CONST_TRACE_INFO, "HTTP_DEBUG: SSI: Adjusted URI = '%s' PARM = '%s'", ssiURIstart, ssiPARMstart);
  } else {
    traceEvent(CONST_TRACE_INFO, "HTTP_DEBUG: SSI: Adjusted URI = '%s'", ssiURIstart);
#endif
  }

  if(ssiURIstart[0] == '\0') {
    myGlobals.numBadSSIRequests++;
    traceEvent(CONST_TRACE_WARNING, "SSI: Invalid - NULL request ignored");
#ifdef HTTP_DEBUG
    sendString("<!-- BAD SSI: --><!--#include virtual=\"\" -->");
#endif
    return;
  }

  /* And so begins the actual processing of an SSI */
  sendString("\n<!-- BEGIN SSI ");
  sendString(ssiURIstart);
  if(ssiPARMstart != NULL) {
    sendString("Parm '");
    sendString(ssiPARMstart);
    sendString("'>");
  }
  sendString(" -->\n\n");

  if(strcasecmp(ssiURIstart, CONST_SSI_MENUBODY_HTML) == 0) {
    ssiMenu_Body();
  } else if(strcasecmp(ssiURIstart, CONST_SSI_MENUHEAD_HTML) == 0) {
    ssiMenu_Head();
  } else {
    
    /* Not recognized - oh dear */
    sendString("<center><p><b>ERROR</b>: Unrecognized SSI request, '");
    sendString(ssiURIstart);
    sendString("'");
    if(ssiPARMstart != NULL) {
      sendString(", with parm '");
      sendString(ssiPARMstart);
      sendString("'");
    }
    sendString("</p></center>\n");
    myGlobals.numBadSSIRequests++;
    return;
  }

  sendString("\n<!-- END SSI ");
  sendString(ssiURIstart);
  sendString(" -->\n\n");

  myGlobals.numHandledSSIRequests++;
}
  
/* ************************* */

void _sendStringLen(char *theString, unsigned int len, int allowSSI) {
  int bytesSent, rc, retries = 0;
  char *ssiStart, *ssiEnd, temp;
#ifdef WIN32
  static unsigned int fileSerial = 0;
#endif

  if(myGlobals.newSock == FLAG_DUMMY_SOCKET)
    return;

  if((allowSSI == 1) && ((ssiStart = strstr(theString, "<!--#include")) != NULL)) {

#ifdef HTTP_DEBUG
    traceEvent(CONST_TRACE_INFO, "HTTP_DEBUG: SSI: Found <!--#include");
#endif

    if((ssiEnd = strstr(ssiStart, "-->")) != NULL) {

      ssiEnd = &ssiEnd[strlen("-->")];

      /*
       * If we've found an SSI, we need to process the thirds - 
       * before, the SSI itself and after. Either end can be empty.
       * Plus the SSI might be incomplete...
       *
       * theString:  ...<!--#include ... -->... 
       *                ^ssiStart           ^ssiEnd
       */

      /* process before */
      if(ssiStart != theString) {
        temp = ssiStart[0];
        ssiStart[0] = '\0';
        sendString(theString);
        ssiStart[0] = temp;
      }

      /* process SSI */
      temp = ssiEnd[0];
      ssiEnd[0] = '\0';
      processSSI(ssiStart);
      ssiEnd[0] = temp;

      /* process after */
      if(ssiEnd[0] != '\0') {
        sendString(ssiEnd);
      }

    } else {

      myGlobals.numBadSSIRequests++;
      traceEvent(CONST_TRACE_WARNING, "SSI: Ignored invalid (no close): '%s'", ssiStart);
#ifdef HTTP_DEBUG
      sendString("<!-- BAD SSI: -->");
      sendString(ssiStart);
#endif

    } /* SSI: test for --> */

    /* We did SOMETHING with this SSI, so we're done with sendStringLen() */
    return;

  } /* SSI: test for <!--#include */

  httpBytesSent += len;

  /* traceEvent(CONST_TRACE_INFO, "%s", theString);  */
  if(len == 0)
    return; /* Nothing to send */
#ifdef MAKE_WITH_ZLIB
  else {
    if(compressFile) {
      if(compressFileFd == NULL) {
#ifdef WIN32
	safe_snprintf(__FILE__, __LINE__, compressedFilePath, sizeof(compressedFilePath), "gzip-%d.ntop", fileSerial++);
#else
	safe_snprintf(__FILE__, __LINE__, compressedFilePath, sizeof(compressedFilePath), "/tmp/ntop-gzip-%d", getpid());
#endif

	compressFileFd = gzopen(compressedFilePath, "wb");
      }

      if(gzwrite(compressFileFd, theString, len) == 0) {
	int err;
        char* gzErrorMsg;

        gzErrorMsg = (char*)gzerror(compressFileFd, &err);
        if(err == Z_ERRNO)
          traceEvent(CONST_TRACE_WARNING, "gzwrite file error %d (%s)", errno, strerror(errno));
        else
	  traceEvent(CONST_TRACE_WARNING, "gzwrite error %s(%d)", gzErrorMsg, err);

        gzclose(compressFileFd);
        unlink(compressedFilePath);
      }
      return;
    }
  }
#endif /* MAKE_WITH_ZLIB */

  bytesSent = 0;

  while(len > 0) {
  RESEND:
    errno=0;

    if(myGlobals.newSock == FLAG_DUMMY_SOCKET)
      return;

#ifdef HAVE_OPENSSL
    if(myGlobals.newSock < 0) {
      rc = SSL_write(getSSLsocket(-myGlobals.newSock), &theString[bytesSent], len);
    } else
      rc = send(myGlobals.newSock, &theString[bytesSent], (size_t)len, 0);
#else
    rc = send(myGlobals.newSock, &theString[bytesSent], (size_t)len, 0);
#endif

    //traceEvent(CONST_TRACE_INFO, "[sent=%d][supposed to send=%d]", rc, len);

    if((errno != 0) || (rc < 0)) {
      if((errno == EAGAIN /* Resource temporarily unavailable */) && (retries<3)) {
	len -= rc;
	bytesSent += rc;
	retries++;
	goto RESEND;
      } 

      if(errno == EPIPE /* Broken pipe: the  client has disconnected */) {
        traceEvent(CONST_TRACE_INFO, "EPIPE during sending of page to web client");
#ifndef WIN32
      } else if(errno == ECONNRESET /* Client reset */) {
        static econnresetcount=0;
        econnresetcount++;
        if(econnresetcount < 10)
          traceEvent(CONST_TRACE_WARNING, "ECONNRESET during sending of page to web client");
        else if(econnresetcount == 10)
          traceEvent(CONST_TRACE_WARNING, 
                     "ECONNRESET during sending of page to web client (skipping further warnings)");
#endif
      } else if(errno == EBADF /* Bad file descriptor: a
				   disconnected client is still sending */) {
        traceEvent(CONST_TRACE_INFO, "EBADF during sending of page to web client");
      } else {
        traceEvent(CONST_TRACE_INFO, "errno %d during sending of page to web client");
      }

      traceEvent(CONST_TRACE_VERYNOISY, "Failed text was %d bytes, '%s'", strlen(theString), theString);
      closeNwSocket(&myGlobals.newSock);
      return;
    } else {
      len -= rc;
      bytesSent += rc;
    }
  }
}

/* ************************* */

void _sendString(char *theString, int allowSSI) {
  _sendStringLen(theString, strlen(theString), allowSSI);
}

/* ************************* */

void printHTMLheader(char *title, char *htmlTitle, int headerFlags) {
  char buf[LEN_GENERAL_WORK_BUFFER], *theTitle;

  if(htmlTitle != NULL) theTitle = htmlTitle; else theTitle = title;

  sendString((myGlobals.runningPref.w3c == TRUE) ? CONST_W3C_DOCTYPE_LINE "\n" : "");
  sendString("<HTML>\n<HEAD>\n");
  sendString((myGlobals.runningPref.w3c == TRUE) ? CONST_W3C_CHARTYPE_LINE "\n" : "");

  if(title != NULL) {
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TITLE>%s</TITLE>\n", title);
    sendString(buf);
  } else if(myGlobals.runningPref.w3c == TRUE)
    sendString("<!-- w3c requires --><title>ntop page</title>\n");

  if((headerFlags & BITFLAG_HTML_NO_REFRESH) == 0) {
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<META HTTP-EQUIV=REFRESH CONTENT=%d>\n", myGlobals.runningPref.refreshRate);
    sendString(buf);
  }

  sendString("<META HTTP-EQUIV=Pragma CONTENT=no-cache>\n");
  sendString("<META HTTP-EQUIV=Cache-Control CONTENT=no-cache>\n");
  if((headerFlags & BITFLAG_HTML_NO_STYLESHEET) == 0) {
    sendString("<LINK REL=stylesheet HREF=\"/style.css\" type=\"text/css\">\n");
  }

  sendString("<SCRIPT SRC=\"/functions.js\" TYPE=\"text/javascript\" LANGUAGE=\"javascript\"></SCRIPT>\n");
  sendString("<script type=\"text/javascript\" language=\"javascript\" src=\"/domLib.js\"></script>\n");
  sendString("<script type=\"text/javascript\" language=\"javascript\" src=\"/domTT.js\"></script>\n");
  sendString("<script type=\"text/javascript\" language=\"javascript\">var domTT_styleClass = 'niceTitle';</script>\n");

  /* ******************************************************* */

  sendString("<link rel=\"stylesheet\" href=\"/style.css\" TYPE=\"text/css\">\n");
  ssiMenu_Head();
  sendString("</head>");

  /* ******************************************************* */

  if((headerFlags & BITFLAG_HTML_NO_BODY) == 0) {

    sendString("<body link=\"blue\" vlink=\"blue\">\n\n");
    ssiMenu_Body();

    if((theTitle != NULL) && ((headerFlags & BITFLAG_HTML_NO_HEADING) == 0))
      printSectionTitle(theTitle);
  }
}

/* ************************* */

void printHTMLtrailer(void) {
  char buf[LEN_GENERAL_WORK_BUFFER], formatBuf[32];
  int i, len, numRealDevices = 0;

  switch (myGlobals.ntopRunState) {
      case FLAG_NTOPSTATE_STOPCAP:
	sendString("\n<HR>\n<CENTER><FONT FACE=\"Helvetica, Arial, Sans Serif\" SIZE=+1><B>"
		   "Packet capture stopped"
		   "</B></FONT></CENTER>");
	break;

      case FLAG_NTOPSTATE_SHUTDOWN:
      case FLAG_NTOPSTATE_SHUTDOWNREQ:
        sendString("\n<HR>\n<CENTER><FONT FACE=\"Helvetica, Arial, Sans Serif\" SIZE=+1><B>"
	           "ntop shutting down"
	           "</B></FONT></CENTER>");
        break;

      case FLAG_NTOPSTATE_TERM:
        sendString("\n<HR>\n<CENTER><FONT FACE=\"Helvetica, Arial, Sans Serif\" SIZE=+1><B>"
	           "ntop stopped"
	           "</B></FONT></CENTER>");
        break;
  }
  
  sendString("\n<hr>\n<h5><font face=\"Helvetica, Arial, Sans Serif\" size=\"-1\"><b>\n");
  
  safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "Report created on %s ",
	      ctime(&myGlobals.actTime));
  sendString(buf);

  if(myGlobals.runningPref.rFileName == NULL) {
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "[ntop uptime: %s]\n",
	      formatSeconds(time(NULL)-myGlobals.initialSniffTime, formatBuf, sizeof(formatBuf)));
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER,
		  "[from file %s]\n",
		  myGlobals.runningPref.rFileName);
  }
  sendString(buf);

  if(theHttpUser[0] != '\0') {
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER,
		  "[HTTP user: %s]\n", theHttpUser);
    sendString(buf);
  }
  sendString("<br>\n");

  safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER,
		"Generated by <a class=external href=\"http://www.ntop.org/\">ntop</a> v.%s \n[%s]"
                "<br>&copy; 1998-2006 by " CONST_MAILTO_LUCA ", built: %s.<br>\n",
		version, osName, buildDate);
  sendString(buf);


  sendString("<script type=\"text/javascript\">function nicetitleDecorator(el) {\nvar result = el.title;\nif(el.href){\nresult += '<p>' + el.href + '</p>';\n	}\nreturn result;\n}\ndomTT_replaceTitles(nicetitleDecorator);\n</script>\n");


  if(myGlobals.checkVersionStatus != FLAG_CHECKVERSION_NOTCHECKED) {
    u_char useRed;

    switch(myGlobals.checkVersionStatus) {
    case FLAG_CHECKVERSION_OBSOLETE:
    case FLAG_CHECKVERSION_UNSUPPORTED:
    case FLAG_CHECKVERSION_NOTCURRENT:
    case FLAG_CHECKVERSION_OLDDEVELOPMENT:
    case FLAG_CHECKVERSION_DEVELOPMENT:
    case FLAG_CHECKVERSION_NEWDEVELOPMENT:
      useRed = 1;
      break;
    default:
      useRed = 0;
      break;
    }

    sendString("Version: ");
    if(useRed) sendString("<font color=\"red\">");
    sendString(reportNtopVersionCheck());
    if(useRed) sendString("</font>");
    sendString("<br>\n");
  }

  if(myGlobals.runningPref.rFileName != NULL) {
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "Listening on [%s]\n", CONST_PCAP_NW_INTERFACE_FILE);
  } else {
    buf[0] = '\0';

    for(i=len=numRealDevices=0; i<myGlobals.numDevices; i++, len=strlen(buf)) {
      if((!myGlobals.device[i].virtualDevice) && myGlobals.device[i].activeDevice) {
	safe_snprintf(__FILE__, __LINE__, &buf[len], LEN_GENERAL_WORK_BUFFER - len, "%s%s",
		    (numRealDevices>0) ? "," : "Listening on [", myGlobals.device[i].humanFriendlyName);
	numRealDevices++;
      }
    }

    if((i == 0) || (numRealDevices == 0))
      buf[0] = '\0';
    else {
      safe_snprintf(__FILE__, __LINE__, &buf[len], LEN_GENERAL_WORK_BUFFER-len, "]\n");
    }
  }

  len = strlen(buf);

  if ((myGlobals.runningPref.currentFilterExpression != NULL) &&
      (*myGlobals.runningPref.currentFilterExpression != '\0')) {
    safe_snprintf(__FILE__, __LINE__, &buf[len], LEN_GENERAL_WORK_BUFFER-len,
		"with kernel (libpcap) filtering expression </b>\"%s\"<b><br>\n",
		myGlobals.runningPref.currentFilterExpression);
  } else {
    safe_snprintf(__FILE__, __LINE__, &buf[len], LEN_GENERAL_WORK_BUFFER-len,
		"for all packets (i.e. without a filtering expression)\n<br>");
  }

  sendString(buf);

  if(!myGlobals.runningPref.mergeInterfaces) {
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "Web reports include only interface \"%s\"",
                  myGlobals.device[myGlobals.actualReportDeviceId].humanFriendlyName);
    sendString(buf);
  } else {
    sendString("Web reports include all interfaces (merged)");
  }

  sendString("</b></font></h5>\n</BODY>\n</HTML>\n");
}

/* ******************************* */

void initAccessLog(void) {

  if(myGlobals.runningPref.accessLogFile) {
    myGlobals.accessLogFd = fopen(myGlobals.runningPref.accessLogFile, "a");
    if(myGlobals.accessLogFd == NULL) {
      traceEvent(CONST_TRACE_ERROR, "Unable to create file %s. Access log is disabled.",
		 myGlobals.runningPref.accessLogFile);
    }
  }
}

/* ************************* */

void termAccessLog(void) {
  if(myGlobals.accessLogFd != NULL)
    fclose(myGlobals.accessLogFd);
}

/* ******************************* */

static void logHTTPaccess(int rc, struct timeval *httpRequestedAt, u_int gzipBytesSent) {
 char theDate[48], myUser[64], buf[24];
 struct timeval loggingAt;
 unsigned long msSpent;
 char theZone[6];
 unsigned long gmtoffset;
  struct tm t;

  if(myGlobals.accessLogFd != NULL) {
   gettimeofday(&loggingAt, NULL);

   if(httpRequestedAt != NULL)
     msSpent = (unsigned long)(delta_time(&loggingAt, httpRequestedAt)/1000);
   else
     msSpent = 0;

   /* Use standard Apache format per http://httpd.apache.org/docs/logs.html */
   strftime(theDate, sizeof(theDate), CONST_APACHELOG_TIMESPEC, localtime_r(&myGlobals.actTime, &t));

   gmtoffset =  (myGlobals.thisZone < 0) ? -myGlobals.thisZone : myGlobals.thisZone;
   safe_snprintf(__FILE__, __LINE__, theZone, sizeof(theZone), "%c%2.2ld%2.2ld",
	       (myGlobals.thisZone < 0) ? '-' : '+', gmtoffset/3600, (gmtoffset/60)%60);

   if((theHttpUser == NULL)
      || (theHttpUser[0] == '\0'))
     strncpy(myUser, "-", 64);
   else {
     safe_snprintf(__FILE__, __LINE__, myUser, sizeof(myUser), " %s ", theHttpUser);
   }

   if(gzipBytesSent > 0)
     fprintf(myGlobals.accessLogFd, "%s %s - [%s %s] \"%s\" %d %u/%u - - %lu\n",
	     _addrtostr(requestFrom, buf, sizeof(buf)),
	     myUser, theDate, theZone,
	     httpRequestedURL, rc, gzipBytesSent, httpBytesSent,
	     msSpent);
   else
     fprintf(myGlobals.accessLogFd, "%s %s - [%s %s] \"%s\" %d %u - - %lu\n",
	     _addrtostr(requestFrom, buf, sizeof(buf)),
	     myUser, theDate, theZone,
	     httpRequestedURL, rc, httpBytesSent,
	     msSpent);
   fflush(myGlobals.accessLogFd);
 }
}

/* ************************* */

static void returnHTTPbadRequest(void) {
  myGlobals.numUnsuccessfulInvalidrequests[myGlobals.newSock > 0]++;
  returnHTTPspecialStatusCode(BITFLAG_HTTP_STATUS_400, NULL);
}

/* ************************* */

static void returnHTTPaccessDenied(void) {
  myGlobals.numUnsuccessfulDenied[myGlobals.newSock > 0]++;
  returnHTTPspecialStatusCode(BITFLAG_HTTP_STATUS_401 | BITFLAG_HTTP_NEED_AUTHENTICATION, NULL);
}

/* ************************* */

static void returnHTTPaccessForbidden(void) {
  myGlobals.numUnsuccessfulForbidden[myGlobals.newSock > 0]++;
  returnHTTPspecialStatusCode(BITFLAG_HTTP_STATUS_403, NULL);
}

/* ************************* */

void returnHTTPpageNotFound(char* additionalText) {
  myGlobals.numUnsuccessfulNotfound[myGlobals.newSock > 0]++;
  returnHTTPspecialStatusCode(BITFLAG_HTTP_STATUS_404, additionalText);
}

/* ************************* */

static void returnHTTPrequestTimedOut(void) {
  myGlobals.numUnsuccessfulTimeout[myGlobals.newSock > 0]++;
  returnHTTPspecialStatusCode(BITFLAG_HTTP_STATUS_408, NULL);
}

/* ************************* */

static void returnHTTPnotImplemented(void) {
  myGlobals.numUnsuccessfulInvalidmethod[myGlobals.newSock > 0]++;
  returnHTTPspecialStatusCode(BITFLAG_HTTP_STATUS_501, NULL);
}

/* ************************* */

static void returnHTTPversionNotSupported(void) {
  myGlobals.numUnsuccessfulInvalidversion[myGlobals.newSock > 0]++;
  returnHTTPspecialStatusCode(BITFLAG_HTTP_STATUS_505, NULL);
}

/* ************************* */

void returnHTTPpageBadCommunity(void) {
  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, BITFLAG_HTTP_STATUS_200, 0);
  printHTMLheader("Bad Community", NULL, BITFLAG_HTML_NO_REFRESH | BITFLAG_HTML_NO_HEADING);

  sendString("<CENTER><P><H2><font color=red>Invalid Community</font></H2><p>"
	     "Your security settings do not allow you to see the specified page"
	     "</CENTER>");
}

/* ************************* */

static void returnHTTPspecialStatusCode(int statusFlag, char *additionalText) {
  int statusIdx;
  char buf[LEN_GENERAL_WORK_BUFFER];

  statusIdx = (statusFlag >> 8) & 0xff;
  if((statusIdx < 0) || (statusIdx > sizeof(HTTPstatus)/sizeof(HTTPstatus[0]))) {
    statusIdx = 0;
    statusFlag = 0;
#ifdef URL_DEBUG
    traceEvent(CONST_TRACE_ERROR,
	       "URL_DEBUG: INTERNAL: invalid HTTP status id (%d) set to zero.\n", statusIdx);
#endif
  }

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, statusFlag, 0);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Error %d", HTTPstatus[statusIdx].statusCode);
  printHTMLheader(buf, NULL, BITFLAG_HTML_NO_REFRESH | BITFLAG_HTML_NO_HEADING);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
	   "<H1>Error %d</H1>\n%s\n",
	   HTTPstatus[statusIdx].statusCode, HTTPstatus[statusIdx].longDescription);
  sendString(buf);

  if(strlen(httpRequestedURL) > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
	     "<P>Received request:<BR><BLOCKQUOTE><TT>&quot;%s&quot;</TT></BLOCKQUOTE>",
	     httpRequestedURL);
    sendString(buf);
  }

  if(additionalText != NULL)
    sendString(additionalText);  

  logHTTPaccess(HTTPstatus[statusIdx].statusCode, NULL, 0);
}

/* *******************************/

void returnHTTPredirect(char* destination) {
  compressFile = acceptGzEncoding = 0;

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML,
		 BITFLAG_HTTP_STATUS_302 | BITFLAG_HTTP_NO_CACHE_CONTROL | BITFLAG_HTTP_MORE_FIELDS, 1);
  sendString("Location: /");
  sendString(destination);
  sendString("\n\n");
}

/* ************************* */

void sendHTTPHeader(int mimeType, int headerFlags, int useCompressionIfAvailable) {
  int statusIdx;
  char tmpStr[256], theDate[48];
  time_t  theTime = myGlobals.actTime - (time_t)myGlobals.thisZone;
  struct tm t;

  compressFile = 0;

  statusIdx = (headerFlags >> 8) & 0xff;
  if((statusIdx < 0) || (statusIdx > sizeof(HTTPstatus)/sizeof(HTTPstatus[0]))){
    statusIdx = 0;
#ifdef URL_DEBUG
    traceEvent(CONST_TRACE_ERROR, "URL_DEBUG: INTERNAL: invalid HTTP status id (%d) set to zero.",
	       statusIdx);
#endif
  }
  safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "HTTP/1.0 %d %s\r\n",
                   HTTPstatus[statusIdx].statusCode, HTTPstatus[statusIdx].reasonPhrase);
  sendString(tmpStr);

  if( (myGlobals.runningPref.P3Pcp != NULL) || (myGlobals.runningPref.P3Puri != NULL) ) {
      sendString("P3P: ");
      if(myGlobals.runningPref.P3Pcp != NULL) {
          safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "cp=\"%s\"%s",
                              myGlobals.runningPref.P3Pcp, myGlobals.runningPref.P3Puri != NULL ? ", " : "");
          sendString(tmpStr);
      }

      if(myGlobals.runningPref.P3Puri != NULL) {
          safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "policyref=\"%s\"", myGlobals.runningPref.P3Puri);
          sendString(tmpStr);
       }
       sendString("\r\n");
  }

  /* Use en standard for this per RFC */
  strftime(theDate, sizeof(theDate)-1, CONST_RFC1945_TIMESPEC, localtime_r(&theTime, &t));
  theDate[sizeof(theDate)-1] = '\0';
  safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "Date: %s\r\n", theDate);
  sendString(tmpStr);

  if(headerFlags & BITFLAG_HTTP_IS_CACHEABLE) {
    sendString("Cache-Control: max-age=3600, must-revalidate, public\r\n");
  } else if((headerFlags & BITFLAG_HTTP_NO_CACHE_CONTROL) == 0) {
    sendString("Cache-Control: no-cache\r\n");
    sendString("Expires: 0\r\n");
  }

  if((headerFlags & BITFLAG_HTTP_KEEP_OPEN) == 0) {
    sendString("Connection: close\n");
  }

  safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "Server: ntop/%s (%s)\r\n", version, osName);
  sendString(tmpStr);

  if(headerFlags & BITFLAG_HTTP_NEED_AUTHENTICATION) {
      sendString("WWW-Authenticate: Basic realm=\"ntop HTTP server\"\r\n");
  }

  switch(mimeType) {
    case FLAG_HTTP_TYPE_HTML:
      sendString("Content-Type: text/html\r\n");
      break;
    case FLAG_HTTP_TYPE_GIF:
      sendString("Content-Type: image/gif\r\n");
      break;
    case FLAG_HTTP_TYPE_JPEG:
      sendString("Content-Type: image/jpeg\r\n");
      break;
    case FLAG_HTTP_TYPE_PNG:
      sendString("Content-Type: image/png\r\n");
      break;
    case FLAG_HTTP_TYPE_CSS:
      sendString("Content-Type: text/css\r\n");
      break;
    case FLAG_HTTP_TYPE_TEXT:
      sendString("Content-Type: text/plain\r\n");
      break;
    case FLAG_HTTP_TYPE_ICO:
      sendString("Content-Type: application/octet-stream\r\n");
      break;
    case FLAG_HTTP_TYPE_JS:
      sendString("Content-Type: text/javascript\r\n");
      break;
    case FLAG_HTTP_TYPE_XML:
      sendString("Content-Type: text/xml\r\n");
      break;
    case FLAG_HTTP_TYPE_P3P:
      sendString("Content-Type: text/xml\r\n");
      break;
    case FLAG_HTTP_TYPE_NONE:
      break;
#ifdef URL_DEBUG
    default:
      traceEvent(CONST_TRACE_ERROR,
		 "URL_DEBUG: INTERNAL: invalid MIME type code requested (%d)\n", mimeType);
#endif
  }

  if(mimeType == MIME_TYPE_CHART_FORMAT) {
    compressFile = 0;
    if(myGlobals.newSock < 0 /* SSL */) acceptGzEncoding = 0;
  } else {
    if(useCompressionIfAvailable && acceptGzEncoding)
      compressFile = 1;
  }

  if((headerFlags & BITFLAG_HTTP_MORE_FIELDS) == 0) {
    sendString("\r\n");
  }
}

/* ************************* */

static int checkURLsecurity(char *url) {
  int len, i, begin;
  char *token;
  char *workURL;

#ifdef URL_DEBUG
#endif

#if 0
    traceEvent(CONST_TRACE_INFO, "URL_DEBUG: RAW url is '%s'", url);
#endif

  /*
    Courtesy of "Burton M. Strauss III" <bstrauss@acm.org>

    This is a fix against Unicode exploits.

    Let's be really smart about this - instead of defending against
    hostile requests we don't yet know about, let's make sure it
    we only serve up the very limited set of pages we're interested
    in serving up...

    http://server[:port]/url
    Our urls end in .htm(l), .css, .jpg, .gif or .png

    We don't want to serve requests that attempt to hide or obscure our
    server.  Yes, we MIGHT somehow reject a marginally legal request, but
    tough!

    Any character that shouldn't be in a CLEAR request, causes us to
    bounce the request...

    For example,
    //, .. and /.    -- directory transversal
    \r, \n           -- used to hide stuff in logs
    :, @             -- used to obscure logins, etc.
    unicode exploits -- used to hide the above
  */

  /* No URL?  That is our default action... */
  if((url == NULL) || (url[0] == '\0'))
    return(0);

  if(strlen(url) >= MAX_LEN_URL) {
    traceEvent(CONST_TRACE_NOISY, "URL security(2): URL too long (len=%d)", strlen(url));
    return(2);
  }

  if(strstr(url, "%") != NULL) {

    /* Convert encoding (%nn) to their base characters -
     * we also handle the special case of %3A (:)
     * which we convert to _ (not :)
         * See urlFixupFromRFC1945Inplace() and urlFixupToRFC1945Inplace()
     * We handle this 1st because some of the gcc functions interpret encoding/unicode "for" us
     */
    for(i=0, begin=0; i<strlen(url); i++) {
      if(url[i] == '%') {
        if((url[i+1] == '3') && ((url[i+2] == 'A') || (url[i+2] == 'a'))) {
          url[begin++] = '_';
          i += 2;
        } else {
 	  int v1, v2;
          v1 = url[i+1] < '0' ? -1 :
              url[i+1] <= '9' ? (url[i+1] - '0') :
              url[i+1] < 'A' ? -1 :
              url[i+1] <= 'F' ? (url[i+1] - 'A' + 10) :
              url[i+1] < 'a' ? -1 :
              url[i+1] <= 'f' ? (url[i+1] - 'a' + 10) : -1;
          v2 = url[i+2] < '0' ? -1 :
              url[i+2] <= '9' ? (url[i+2] - '0') :
              url[i+2] < 'A' ? -1 :
              url[i+2] <= 'F' ? (url[i+2] - 'A' + 10) :
              url[i+2] < 'a' ? -1 :
              url[i+2] <= 'f' ? (url[i+2] - 'a' + 10) : -1;

 	  if((v1<0) || (v2<0)) {
 	    url[begin++] = '\0';
            traceEvent(CONST_TRACE_NOISY,
                       "URL security(1): Found invald percent in URL...DANGER...rejecting request partial (url=%s...)",
                       url);

            /* Explicitly, update so it's not used anywhere else in ntop */
            url[0] = '*'; url[1] = 'd'; url[2] = 'a'; url[3] = 'n'; url[4] = 'g'; url[5] = 'e'; url[6] = 'r'; url[7] = '*';
            url[8] = '\0';
            httpRequestedURL[0] = '*'; httpRequestedURL[1] = 'd'; httpRequestedURL[2] = 'a';
            httpRequestedURL[3] = 'n'; httpRequestedURL[4] = 'g'; httpRequestedURL[5] = 'e';
            httpRequestedURL[6] = 'r'; httpRequestedURL[7] = '*';
            httpRequestedURL[8] = '\0';

            return(1);
          }

          url[begin++] = v1 * 16 + v2;
          i += 2;
        }
      } else {
        url[begin++] = url[i];
      }
    }

    url[begin] = '\0';

#ifdef URL_DEBUG
    traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Decoded url is '%s', %% at %08x", url, strstr(url, "%"));
#endif
  }

  /* Still got a % - maybe it's Unicode?  Somethings fishy... */
  if(strstr(url, "%") != NULL) {
      traceEvent(CONST_TRACE_INFO,
                 "URL security(1): Found percent in decoded URL...DANGER...rejecting request (%s)", url);

      /* Explicitly, update so it's not used anywhere else in ntop */
      url[0] = '*'; url[1] = 'd'; url[2] = 'a'; url[3] = 'n'; url[4] = 'g'; url[5] = 'e'; url[6] = 'r'; url[7] = '*';
      url[8] = '\0';
      httpRequestedURL[0] = '*'; httpRequestedURL[1] = 'd'; httpRequestedURL[2] = 'a';
      httpRequestedURL[3] = 'n'; httpRequestedURL[4] = 'g'; httpRequestedURL[5] = 'e';
      httpRequestedURL[6] = 'r'; httpRequestedURL[7] = '*';
      httpRequestedURL[8] = '\0';
      return(1);
  }

  /* a double slash? */
  if(strstr(url, "//") > 0) {
    traceEvent(CONST_TRACE_NOISY, "URL security(2): Found // in URL...rejecting request");
    return(2);
  }

  /* a double &? */
  if(strstr(url, "&&") > 0) {
    traceEvent(CONST_TRACE_NOISY, "URL security(2): Found && in URL...rejecting request");
    return(2);
  }

  /* a double ?? */
  if(strstr(url, "??") > 0) {
    traceEvent(CONST_TRACE_NOISY, "URL security(2): Found ?? in URL...rejecting request");
    return(2);
  }

  /* a double dot? */
  if(strstr(url, "..") > 0) {
    traceEvent(CONST_TRACE_NOISY, "URL security(3): Found .. in URL...rejecting request");
    return(3);
  }

  /* Past the bad stuff -- check the URI (not the parameters) for prohibited characters */
  workURL = strdup(url);

   token = strchr(workURL, '?');
     if(token != NULL) {
       token[0] = '\0';
   }

#ifdef URL_DEBUG
    traceEvent(CONST_TRACE_INFO, "URL_DEBUG: uri is '%s'", workURL);
#endif

  /* Prohibited characters? */
  if((len = strcspn(workURL, CONST_URL_PROHIBITED_CHARACTERS)) < strlen(workURL)) {
    traceEvent(CONST_TRACE_NOISY,
               "URL security(4): Prohibited character(s) at %d [%c] in URL... rejecting request",
               len, workURL[len]);
    free(workURL);
    return(4);
  }

/* So far, so go - check the extension */

/* BMS - allow cvs2html/diff/diff... */
  if (strncmp(url, "cvs2html/diff/diff", strlen("cvs2html/diff/diff")) == 0) {
      return(0);
  }

/* allow w3c/p3p.xml...
 *   NOTE that we don't allow general .p3p and .xml requests
 *        Those are bounced below...
 */
  if(strncasecmp(workURL, CONST_W3C_P3P_XML, strlen(CONST_W3C_P3P_XML)) == 0) {
    free(workURL);
    return(0);
  }

  if(strncasecmp(workURL, CONST_NTOP_P3P, strlen(CONST_NTOP_P3P)) == 0) {
    free(workURL);
    return(0);
  }

#ifdef MAKE_WITH_XMLDUMP
  /* Special cases for plugins/xmldump/xxxx.xml... */
  if((strncasecmp(workURL,
             "/" CONST_PLUGINS_HEADER CONST_XMLDUMP_PLUGIN_NAME,
             strlen("/" CONST_PLUGINS_HEADER CONST_XMLDUMP_PLUGIN_NAME)) == 0) ||
    (strncasecmp(workURL, "/" CONST_XML_DTD_NAME, strlen("/" CONST_XML_DTD_NAME)) == 0)) {
    free(workURL);
    return(0);
  }
#endif

  /* Find the terminal . for checking the extension */
  for(i=strlen(workURL)-1; i >= 0; i--)
    if(workURL[i] == '.')
      break;
  i++;

  if((i > 0)
     && (!((strcasecmp(&workURL[i], "htm")  == 0) ||
	   (strcasecmp(&workURL[i], "html") == 0) ||
	   (strcasecmp(&workURL[i], "txt")  == 0) ||
	   (strcasecmp(&workURL[i], "jpg")  == 0) ||
	   (strcasecmp(&workURL[i], "png")  == 0) ||
	   (strcasecmp(&workURL[i], "gif")  == 0) ||
	   (strcasecmp(&workURL[i], "ico")  == 0) ||
	   (strcasecmp(&workURL[i], "js")   == 0) || /* Javascript */
	   (strcasecmp(&workURL[i], "pl")   == 0) || /* used for Perl CGI's */
	   (strcasecmp(&workURL[i], "css")  == 0)))) {
    traceEvent(CONST_TRACE_NOISY,
	       "URL security(5): Found bad file extension (.%s) in URL...\n",
	       &workURL[i]);
    free(workURL);
    return(5);
  }

  free(workURL);
  return(0);
}

/* ************************* */

#if defined(HAVE_ALARM) && defined(PARM_FORK_CHILD_PROCESS) && (!defined(WIN32))
static RETSIGTYPE quitNow(int signo _UNUSED_) {
  traceEvent(CONST_TRACE_ERROR, "http generation failed, alarm() tripped. Please report this to ntop-dev list!");
  returnHTTPrequestTimedOut();
  exit(0);
}
#endif

/* ************************* */

#ifdef MAKE_WITH_HTTPSIGTRAP

RETSIGTYPE httpcleanup(int signo) {
  static int msgSent = 0;
  int i;
  void *array[20];
  size_t size;
  char **strings;

  if(msgSent<10) {
    traceEvent(CONST_TRACE_ERROR, "http: caught signal %d %s", signo,
               signo == SIGHUP ? "SIGHUP" :
                 signo == SIGINT ? "SIGINT" :
                 signo == SIGQUIT ? "SIGQUIT" :
                 signo == SIGILL ? "SIGILL" :
                 signo == SIGABRT ? "SIGABRT" :
                 signo == SIGFPE ? "SIGFPE" :
                 signo == SIGKILL ? "SIGKILL" :
                 signo == SIGSEGV ? "SIGSEGV" :
                 signo == SIGPIPE ? "SIGPIPE" :
                 signo == SIGALRM ? "SIGALRM" :
                 signo == SIGTERM ? "SIGTERM" :
                 signo == SIGUSR1 ? "SIGUSR1" :
                 signo == SIGUSR2 ? "SIGUSR2" :
                 signo == SIGCHLD ? "SIGCHLD" :
 #ifdef SIGCONT
                 signo == SIGCONT ? "SIGCONT" :
 #endif
 #ifdef SIGSTOP
                 signo == SIGSTOP ? "SIGSTOP" :
 #endif
 #ifdef SIGBUS
                 signo == SIGBUS ? "SIGBUS" :
 #endif
 #ifdef SIGSYS
                 signo == SIGSYS ? "SIGSYS"
 #endif
               : "other");
    msgSent++;
  }

 #ifdef HAVE_BACKTRACE
  size = backtrace(array, 20);
  strings = (char**)backtrace_symbols(array, size);

  traceEvent(CONST_TRACE_ERROR, "http: BACKTRACE:     backtrace is:");
  if(size < 2)
      traceEvent(CONST_TRACE_ERROR, "http: BACKTRACE:         **unavailable!");
  else /* Ignore the 0th entry, that's our cleanup() */
    for(i=1; i<size; i++)
      traceEvent(CONST_TRACE_ERROR, "http: BACKTRACE:          %2d. %s", i, strings[i]);

  traceEvent(CONST_TRACE_FATALERROR, "http: ntop shutting down...");
  exit(3); /* Just in case */
 #endif
}
#endif /* MAKE_WITH_HTTPSIGTRAP */

/* ******************************************
   * This block of code generates internal  *
   * copies of the major navigational pages *
   * which are normally in the html/        *
   * directory, in case that directory is   *
   * damaged.                               *
   *                                        *
   * There are also a few real pages        *
   * in here.                               *
   *                                        *
   * Return 0 if you generated the page     *
   *        1 if not                        *
   *                                        *
   **************************************** */

static int generateNewInternalPages(char* pageName) {

/* Note we do not have CONST_INDEX_HTML nor CONST_LEFTMENU_HTML here.
 *
 * They are special cased with CONST_TRAFFIC_STATS_HTML, below, so old-style
 * URLs probably still work...
 *
 *TODO: This stuff is just to warn the user ... and both chunks should probably be
 * removed around 3.4...
 */
 
    if((strcasecmp(pageName, CONST_INDEX_INNER_HTML) == 0) ||
       (strcasecmp(pageName, CONST_LEFTMENU_HTML) == 0) ||
       (strcasecmp(pageName, CONST_LEFTMENU_NOJS_HTML) == 0) ||
       (strcasecmp(pageName, CONST_HOME_UNDERSCORE_HTML) == 0)) {
      sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
      sendString("<!-- Internally generated page -->\n");
      printHTMLheader("Welcome to ntop!", NULL, BITFLAG_HTML_NO_REFRESH);
      sendString("<h1>Problem</h1>\n"
                 "<p>The page you have requested (either explicitly or implicitly),</p>\n<pre>");

      sendString(pageName);
      sendString("</pre>\n<p>Is one which used to be part of <b>ntop</b>, but is no longer available.</p>\n"
                 "<p>The framesets used in versions 3.1 and earlier have been removed. "
                 "Please update your bookmarks or contact your system's administrator for help.</p>\n");
      return(0);
    }

    if(strcasecmp(pageName, CONST_ABTNTOP_HTML) == 0) {
      sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
      sendString("<!-- Internally generated page -->\n");
      printHTMLheader("Welcome to ntop!", NULL, BITFLAG_HTML_NO_REFRESH);
      sendString("<FONT FACE=Helvetica>\n<HR>\n");
      sendString("<b>ntop</b> shows the current network usage. It displays a list of hosts that are\n");
      sendString("currently using the network and reports information concerning the IP\n");
      sendString("(Internet Protocol) and Fibre Channel (FC) traffic generated by each host. The traffic is \n");
      sendString("sorted according to host and protocol. Protocols (user configurable) include:\n");
      sendString("<ul><li>TCP/UDP/ICMP<li>(R)ARP<li>IPX<li>DLC<li>"
		 "Decnet<li>AppleTalk<li>Netbios<li>TCP/UDP<ul><li>FTP<li>"
		 "HTTP<li>DNS<li>Telnet<li>SMTP/POP/IMAP<li>SNMP<li>\n");
      sendString("NFS<li>X11</ul>\n<p>\n");
      sendString("<li>Fibre Channel<ul><li>Control Traffic - SW2,GS3,ELS<li>SCSI</ul></ul><p>\n");
      sendString("<p><b>ntop</b>'s author strongly believes in <A class=external HREF=http://www.opensource.org/>\n");
      sendString("open source software</A> and encourages everyone to modify, improve\n ");
      sendString("and extend <b>ntop</b> in the interest of the whole Internet community according\n");
      sendString("to the enclosed licence (see COPYING).</p><p>Problems, bugs, questions, ");
      sendString("desirable enhancements, source code contributions, etc., should be sent to the ");
      sendString(CONST_MAILTO_LIST ".</p>\n");
      sendString("<p>For information on <b>ntop</b> and information privacy, see ");
      sendString("<A HREF=\"" CONST_PRIVACYNOTICE_HTML "\">this</A> page.</p>\n</font>");
      return 0;
    }
    return 1; /* Not in this bunch, boss */
}

/* **************************************** */

int isAllowedCommunity(char *community_name) {
  int i;

  //traceEvent(CONST_TRACE_INFO, "-> isAllowedCommunity(%s)", community_name);

  if(theHttpUser[0] == '\0') return(1); /* No authentication */

  for(i=0; i<MAX_NUM_COMMUNITIES; i++) {
    if(listAllowedCommunities[i] == NULL) break;

    //traceEvent(CONST_TRACE_INFO, "-> isAllowedCommunity(%s): %s", community_name, listAllowedCommunities[i]);

    if(strcmp(listAllowedCommunities[i], community_name) == 0)
      return(1);
  }

  // traceEvent(CONST_TRACE_INFO, "-> isAllowedCommunity(%s): NOT ALLOWED", community_name);
  return(0);
}


/* **************************************** */

static int returnHTTPPage(char* pageName,
                          int postLen,
                          HostAddr *from,
			  struct timeval *httpRequestedAt,
                          int *usedFork,
                          char *agent,
                          char *referer,
                          char *requestedLanguage[],
                          int numLang, int isPostMethod) {
  char *questionMark, *pageURI, *token;
  int sortedColumn = 0, printTrailer=1, idx;
  int errorCode=0, pageNum = 0, found=0, portNr=0;
  struct stat statbuf;
  FILE *fd = NULL;
  char tmpStr[512], *domainNameParm = NULL, *minus;
  char *db_key = NULL, *db_val = NULL;
  int revertOrder=0, vlanId=NO_VLAN, ifId=NO_INTERFACE;
  struct tm t;
  HostsDisplayPolicy showHostsMode = myGlobals.hostsDisplayPolicy;
  LocalityDisplayPolicy showLocalityMode = myGlobals.localityDisplayPolicy;
  int showFcHostsPage = showHostMainPage;
  int showPrefPage    = showPrefBasicPref;
  int vsanId = 0;
#if !defined(WIN32) && defined(PARM_USE_CGI)
  int rc;
#endif
  int i, showBytes = 1;

#ifdef MAKE_WITH_I18N
  int lang;
#endif

  *usedFork = 0;

#ifdef URL_DEBUG
  traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Page: '%s'", pageName);
#endif

  questionMark = strchr(pageName, '?');

  if((questionMark != NULL)
     && (questionMark[0] == '?')) {
    char requestedURL[MAX_LEN_URL];
    char *tkn;

    /* Safe strcpy as requestedURL < MAX_LEN_URL (checked by checkURLsecurity) */
    strcpy(requestedURL, &questionMark[1]);

    tkn = strtok(requestedURL, "&");

    while(tkn != NULL) {
      if(strncmp(tkn, "col=", 4) == 0) {
	idx = atoi(&tkn[4]);
	if(tkn[4] == '-') revertOrder=1;
	sortedColumn = abs(idx);
      } else if(strncmp(tkn, "dom=", 4) == 0) {
	domainNameParm = strdup(&tkn[4]);
      } else if(strncmp(tkn, "key=", 4) == 0) {
	db_key = strdup(&tkn[4]);
      } else if(strncmp(tkn, "val=", 4) == 0) {
	db_val = strdup(&tkn[4]);
      } else if(strncmp(tkn, "port=", 5) == 0) {
	portNr = atoi(&tkn[5]);
      } else if(strncmp(tkn, "unit=", 5) == 0) {
	showBytes = atoi(&tkn[5]);
      } else if(strncmp(tkn, "vlan=", 5) == 0) {
	vlanId = atoi(&tkn[5]);
      } else if(strncmp(tkn, "if=", 3) == 0) {
	ifId = atoi(&tkn[3]);
      } else if(strncmp(tkn, "vsan=", 5) == 0) {
	vsanId = atoi(&tkn[5]);
      } else if(strncmp(tkn, "showH=", 6) == 0) {
	showHostsMode = atoi(&tkn[6]);
	if((showHostsMode < showAllHosts) || (showHostsMode > showOnlyRemoteHosts))
	  showHostsMode = showAllHosts;
      } else if(strncmp(tkn, "showL=", 6) == 0) {
	showLocalityMode = atoi(&tkn[6]);
	if((showLocalityMode < showSentReceived) || (showLocalityMode > showOnlyReceived))
	  showHostsMode = showAllHosts;
      } else if(strncmp(tkn, "showF=", 6) == 0) {
	/* This is the FC Show Hosts Mode */
	showFcHostsPage = atoi(&tkn[6]);
      } else if(strncmp(tkn, "showD=", 6) == 0) {
	/* This is the configure NTOP preferences Page */
	showPrefPage = atoi(&tkn[6]);
      } else if(strncmp(tkn, "page=", 5) == 0) {
	pageNum = atoi(&tkn[5]);
	if(pageNum < 0) pageNum = 0;
      } else {
	/* legacy code: we assume this is a 'unfixed' col= */
	idx = atoi(tkn);
	if(idx < 0) revertOrder=1;
	sortedColumn = abs(idx);
      }

      tkn = strtok(NULL, "&");
    }
  }

  /* Keep the myGlobals, local and prefsDB copies in sync */
  if(myGlobals.hostsDisplayPolicy != showHostsMode) {
    char tmp[8];

    myGlobals.hostsDisplayPolicy = showHostsMode;

    if((myGlobals.hostsDisplayPolicy < showAllHosts)
       || (myGlobals.hostsDisplayPolicy > showOnlyRemoteHosts))
      myGlobals.hostsDisplayPolicy = showAllHosts;

    safe_snprintf(__FILE__, __LINE__, tmp, sizeof(tmp), "%d", myGlobals.hostsDisplayPolicy);
    storePrefsValue("globals.displayPolicy", tmp);
  }

  if(myGlobals.localityDisplayPolicy != showLocalityMode) {
    char tmp[8];

    myGlobals.localityDisplayPolicy = showLocalityMode;

    if((myGlobals.localityDisplayPolicy < showSentReceived)
       || (myGlobals.localityDisplayPolicy > showOnlyReceived))
      myGlobals.localityDisplayPolicy = showSentReceived;

    safe_snprintf(__FILE__, __LINE__, tmp, sizeof(tmp), "%d", myGlobals.localityDisplayPolicy);
    storePrefsValue("globals.displayPolicy", tmp);
  }

  if(pageName[0] == '\0')
    strncpy(pageName, CONST_TRAFFIC_STATS_HTML, sizeof(CONST_TRAFFIC_STATS_HTML));

  /* Generic w3c p3p request? force it to ours... */
  if(strncmp(pageName, CONST_W3C_P3P_XML, strlen(CONST_W3C_P3P_XML)) == 0)
    strncpy(pageName, CONST_NTOP_P3P, sizeof(CONST_NTOP_P3P));

  /*
   * Search for an .html file (ahead of the internally generated text)
   *
   *   We execute the following tests for the file
   *    0..n. look for a -<language> version based on the Accept-Language: value(s) from the user
   *    n+1.  look for a -<language> version based on the host's default setlocale() value
   *    n+2.  look for a default english version (no - tag)
   *
   *   For each directory in the list.
   *
   *   Note that pageURI is a duplicate of pageName, but drops any parameters...
   */

  pageURI = strdup(pageName);
  token   = strchr(pageURI, '?');
  if(token != NULL) token[0] = '\0';

  if(strcmp(pageURI, CONST_NETWORK_IMAGE_MAP) == 0) {
    safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
		  "%s/%s", myGlobals.spoolPath, pageURI);

    if(stat(tmpStr, &statbuf) != 0) {
      sendString("<p>ERROR: Can not locate image map file, request ignored</p>\n");
      traceEvent(CONST_TRACE_ERROR, "Can not locate image map file '%s', ignored...", tmpStr);
      free(pageURI);
      if(domainNameParm != NULL) free(domainNameParm);
      if(db_key != NULL) free(db_key);
      if(db_val != NULL) free(db_val);
      return(0);
    }

    if((fd = fopen(tmpStr, "rb")) == NULL) {
      sendString("<p>ERROR: Can not open image map file, request ignored</p>\n");
      traceEvent(CONST_TRACE_ERROR, "Can not open image map file '%s', ignored...", tmpStr);
      free(pageURI);
      if(domainNameParm != NULL) free(domainNameParm);
      if(db_key != NULL) free(db_key);
      if(db_val != NULL) free(db_val);
      return(0);
    }

  } else {
#ifdef MAKE_WITH_I18N
    for(lang=0; (!found) && lang < numLang + 2; lang++) {
#endif
      for(idx=0; (!found) && (myGlobals.dataFileDirs[idx] != NULL); idx++) {
#ifdef MAKE_WITH_I18N
	if(lang == numLang) {
	  if(myGlobals.defaultLanguage == NULL) {
	    continue;
	  }
	  safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
			"%s/html_%s/%s",
			myGlobals.dataFileDirs[idx],
			myGlobals.defaultLanguage,
			pageURI);
	} else if(lang == numLang+1) {
#endif
	  safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
			"%s/html/%s",
			myGlobals.dataFileDirs[idx],
			pageURI);
#ifdef MAKE_WITH_I18N
	} else {
	  if(requestedLanguage[lang] == NULL) {
	    continue;
	  }
	  safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
			"%s/html_%s/%s",
			myGlobals.dataFileDirs[idx],
			requestedLanguage[lang],
			pageURI);
	}
#endif

#ifdef WIN32
	i=0;
	while(tmpStr[i] != '\0') {
	  if(tmpStr[i] == '/') tmpStr[i] = '\\';
	  i++;
	}
#endif

#if defined(HTTP_DEBUG) || defined(I18N_DEBUG) || defined(URL_DEBUG)
	traceEvent(CONST_TRACE_INFO, "HTTP/I18N/URL_DEBUG: Testing for page %s at %s",
		   pageURI, tmpStr);
#endif

	if(stat(tmpStr, &statbuf) == 0) {
	  if((fd = fopen(tmpStr, "rb")) != NULL) {
	    found = 1;
	    break;
	  }

	  traceEvent(CONST_TRACE_ERROR, "Cannot open file '%s', ignored...", tmpStr);
	}

#ifdef MAKE_WITH_I18N
      }
#endif
    }
  }
   

#ifdef URL_DEBUG
  traceEvent(CONST_TRACE_INFO, "URL_DEBUG: tmpStr=%s - fd=0x%x", tmpStr, fd);
#endif

  if(fd != NULL) {
    char theDate[48],
         *buffer;
    time_t theTime;
    int sz, len = strlen(pageURI), mimeType = FLAG_HTTP_TYPE_HTML;

    if(len > 4) {
      if(strcasecmp(&pageURI[len-4], ".gif") == 0)
        mimeType = FLAG_HTTP_TYPE_GIF;
      else if(strcasecmp(&pageURI[len-4], ".jpg") == 0)
        mimeType = FLAG_HTTP_TYPE_JPEG;
      else if(strcasecmp(&pageURI[len-4], ".png") == 0)
        mimeType = FLAG_HTTP_TYPE_PNG;
      else if(strcasecmp(&pageURI[len-4], ".css") == 0)
        mimeType = FLAG_HTTP_TYPE_CSS;
      else if(strcasecmp(&pageURI[len-4], ".ico") == 0)
        mimeType = FLAG_HTTP_TYPE_ICO;
      else if(strcasecmp(&pageURI[len-3], ".js") == 0)
        mimeType = FLAG_HTTP_TYPE_JS;
      else if(strcasecmp(&pageURI[len-4], ".xml") == 0)
        /* w3c/p3p.xml */
        mimeType = FLAG_HTTP_TYPE_XML;
    }

    sendHTTPHeader(mimeType, BITFLAG_HTTP_IS_CACHEABLE | BITFLAG_HTTP_MORE_FIELDS, 1);

    compressFile = 0; /* Don't move this */

    if(myGlobals.actTime > statbuf.st_mtime) { /* just in case the system clock is wrong... */
      theTime = statbuf.st_mtime - myGlobals.thisZone;
      /* Use en standard for this per RFC */
      strftime(theDate, sizeof(theDate)-1, CONST_RFC1945_TIMESPEC, localtime_r(&theTime, &t));
      theDate[sizeof(theDate)-1] = '\0';
      safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "Last-Modified: %s\r\n", theDate);
      sendString(tmpStr);
    }

    //traceEvent(CONST_TRACE_INFO, "++++++++++= '%s'", &pageURI[len-5]);

    if((strlen(pageURI) > 5) && strcasecmp(&pageURI[len-5], ".html")) { 
      /*
	We should not send information about page length as in case
	of SSI (embedded into .html pages), the page will be actually
	longer than the file size and the browse will close the 
	connection before we sent the whole page
      */
      sendString("Accept-Ranges: bytes\n");
      
      fseek(fd, 0, SEEK_END);
      safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "Content-Length: %d\r\n", (len = ftell(fd)));
      fseek(fd, 0, SEEK_SET);
      sendString(tmpStr);
    }

    sendString("\r\n");	/* mark the end of HTTP header */

    /* We are copying a file.  Let's use a big (but not absurd) buffer. */
    sz = max(4096, min(16384, statbuf.st_size+8));
    buffer = (char*)malloc(sz);
    memset(buffer, 0, sz);
    for(;;) {
      len = fread(buffer, sizeof(char), sz-1, fd);
      if(len <= 0) break;
      sendStringLen(buffer, len);
    }
    free(buffer);

    fclose(fd);
    /* closeNwSocket(&myGlobals.newSock); */
    free(pageURI);
    if(domainNameParm != NULL) free(domainNameParm);
    if(db_key != NULL) free(db_key);
    if(db_val != NULL) free(db_val);
    return(0);
  }

  /* **************** */

  /*
     Revert to the full requested pageName, as these strncasecmp strcasecmp
     check the fronts only
  */
  free(pageURI);

  if(strncasecmp(pageName, CONST_PLUGINS_HEADER, strlen(CONST_PLUGINS_HEADER)) == 0) {
    if(domainNameParm != NULL) free(domainNameParm);
    if(db_key != NULL) free(db_key);
    if(db_val != NULL) free(db_val);
    if(handlePluginHTTPRequest(&pageName[strlen(CONST_PLUGINS_HEADER)])) {
      return(0);
    } else {
      return(FLAG_HTTP_INVALID_PAGE);
    }
  }

  if(strncasecmp(pageName, CONST_CONFIG_NTOP_HTML, strlen(CONST_CONFIG_NTOP_HTML)) == 0) {
    handleNtopConfig (pageName, showPrefPage, isPostMethod ? postLen : 0);
    if(domainNameParm != NULL) free(domainNameParm);
    if(db_key != NULL) free(db_key);
    if(db_val != NULL) free(db_val);
    return(0);
  }

  /*
    Putting this here (and not on top of this function)
    helps because at least a partial respose
    has been sent back to the user in the meantime
  */
  if(strncasecmp(pageName, CONST_SHUTDOWN_NTOP_HTML, strlen(CONST_SHUTDOWN_NTOP_HTML)) == 0) {
    shutdownNtop();
  } else if(strncasecmp(pageName, CONST_SHUTDOWNNOW_NTOP_IMG, strlen(CONST_SHUTDOWNNOW_NTOP_IMG)) == 0) {
    /* Do nothing ... handled later */
    printTrailer=0;
  } else if(strncasecmp(pageName, CONST_CHANGE_FILTER_HTML, strlen(CONST_CHANGE_FILTER_HTML)) == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    changeFilter();
  } else if(strncasecmp(pageName, CONST_DO_CHANGE_FILTER, strlen(CONST_DO_CHANGE_FILTER)) == 0) {
    printTrailer=0;
    if(doChangeFilter(postLen)==0) /* resetStats() */;
  } else if(strncasecmp(pageName, CONST_FILTER_INFO_HTML, strlen(CONST_FILTER_INFO_HTML)) == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader(NULL, NULL, BITFLAG_HTML_NO_REFRESH);
    /* printHTMLtrailer is called afterwards and inserts the relevant info */
  } else if(strncasecmp(pageName, CONST_RESET_STATS_HTML, strlen(CONST_RESET_STATS_HTML)) == 0) {
    /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("Statistics reset requested...", NULL, BITFLAG_HTML_NO_REFRESH);
    myGlobals.resetHashNow = 1; /* resetStats(); */
    sendString("<P>NOTE: Statistics will be reset at the next safe point, which "
	       "is at the end of processing for the current/next packet and "
	       "may have already occured.<br>\n"
	       "<i>Reset takes a few seconds - please do not immediately request "
	       "the next page from the ntop web server or it will appear to hang.</i></P>\n");
  } else if(strncasecmp(pageName, CONST_SWITCH_NIC_HTML, strlen(CONST_SWITCH_NIC_HTML)) == 0) {
    char *equal = strchr(pageName, '=');
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);

    if(equal == NULL)
      switchNwInterface(0);
    else
      switchNwInterface(atoi(&equal[1]));
  } else if(strcasecmp(pageName, CONST_DO_ADD_USER) == 0) {
    printTrailer=0;
    doAddUser(postLen /* \r\n */);
    theLastHttpUser[0] = '\0';
  } else if(strncasecmp(pageName, CONST_DELETE_USER, strlen(CONST_DELETE_USER)) == 0) {
    printTrailer=0;
    if((questionMark == NULL) || (questionMark[0] == '\0'))
      deleteUser(NULL);
    else
      deleteUser(&questionMark[1]);
  } else if(strncasecmp(pageName, CONST_MODIFY_URL, strlen(CONST_MODIFY_URL)) == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    if((questionMark == NULL) || (questionMark[0] == '\0')) {
      addURL(NULL);
    } else
      addURL(&questionMark[1]);
  } else if(strncasecmp(pageName, CONST_DELETE_URL, strlen(CONST_DELETE_URL)) == 0) {
    printTrailer=0;
    if((questionMark == NULL) || (questionMark[0] == '\0'))
      deleteURL(NULL);
    else
      deleteURL(&questionMark[1]);
  } else if(strcasecmp(pageName, CONST_DO_ADD_URL) == 0) {
    printTrailer=0;
    doAddURL(postLen /* \r\n */);
  } else if(strncasecmp(pageName, CONST_SHOW_PLUGINS_HTML, strlen(CONST_SHOW_PLUGINS_HTML)) == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    if(questionMark == NULL)
      showPluginsList("");
    else
      showPluginsList(&pageName[strlen(CONST_SHOW_PLUGINS_HTML)+1]);
  } else if(strcasecmp(pageName, CONST_SHOW_USERS_HTML) == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    showUsers();
  } else if(strcasecmp(pageName, CONST_ADD_USERS_HTML) == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    addUser(NULL);
    theLastHttpUser[0] = '\0';
  } else if(strncasecmp(pageName, CONST_MODIFY_USERS, strlen(CONST_MODIFY_USERS)) == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    if((questionMark == NULL) || (questionMark[0] == '\0'))
      addUser(NULL);
    else
      addUser(&questionMark[1]);
    theLastHttpUser[0] = '\0';
 } else if(strcasecmp(pageName, CONST_SHOW_URLS_HTML) == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    showURLs();
  } else if(strcasecmp(pageName, CONST_ADD_URLS_HTML) == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    addURL(NULL);
    /* Temporary here - begin

    Due to some strange problems, graph generation has some problems
    when several charts are generated concurrently.

    This NEEDS to be fixed.
    */
  } else if(strcasecmp(pageName, CONST_FAVICON_ICO) == 0) {
    /* Burton Strauss (BStrauss@acm.org) - April 2002
       favicon.ico and we don't have the file (or it would have been handled above)
       so punt!
    */
#ifdef LOG_URLS
    traceEvent(CONST_TRACE_INFO, "Note: favicon.ico request, returned 404.");
#endif
    returnHTTPpageNotFound(NULL);
    printTrailer=0;
  } else if(strncasecmp(pageName, CONST_SHOW_MUTEX_HTML, strlen(CONST_SHOW_MUTEX_HTML)) == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printTrailer=0;
    printMutexStatusReport(0);
  } else if(strncasecmp(pageName, CONST_EDIT_PREFS, strlen(CONST_EDIT_PREFS)) == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    edit_prefs(db_key, db_val);
    printTrailer=1;
  } else if(strncasecmp(pageName, CONST_PRIVACYCLEAR_HTML, strlen(CONST_PRIVACYCLEAR_HTML)) == 0) {
    storePrefsValue("globals.displayPrivacyNotice", "0");
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "PRIVACY: Flag cleared, notice will display next run");
    returnHTTPredirect(CONST_PRIVACYNOTICE_HTML);
  } else if(strncasecmp(pageName, CONST_PRIVACYFORCE_HTML, strlen(CONST_PRIVACYFORCE_HTML)) == 0) {
    storePrefsValue("globals.displayPrivacyNotice", "2");
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "PRIVACY: Flag forced, notice will display each run");
    returnHTTPredirect(CONST_PRIVACYNOTICE_HTML);
  } else if(strncasecmp(pageName, CONST_TRAFFIC_SUMMARY_HTML,
			strlen(CONST_TRAFFIC_SUMMARY_HTML)) == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    /*
      It needs to go here otherwise when we update the pcap dropped packets
      this value is updated only in the child process and not
      into the main one.
    */
    printTrafficSummary(revertOrder);
  } else if ((strncasecmp(pageName, CONST_TRAFFIC_STATS_HTML,
                          strlen(CONST_TRAFFIC_STATS_HTML)) == 0)
             || (strncasecmp(pageName, CONST_INDEX_HTML,
                          strlen(CONST_INDEX_HTML)) == 0)
             || (strncasecmp(pageName, CONST_LEFTMENU_HTML,
                             strlen(CONST_LEFTMENU_HTML)) == 0)) {
      sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);

    if((myGlobals.ntopRunState < FLAG_NTOPSTATE_RUN)
       || ((myGlobals.numDevices == 1) && (!strcmp(myGlobals.device[0].name, "none")))) {
      printHTMLheader("Configure ntop", NULL, BITFLAG_HTML_NO_REFRESH);

      safe_snprintf (__FILE__, __LINE__, tmpStr, sizeof (tmpStr),
		     "No interface has been configured. Please <a href=%s>configure ntop</a> first.",
		     CONST_CONFIG_NTOP_HTML);
      printFlagedWarning (tmpStr);
      if(domainNameParm != NULL) free(domainNameParm);
      if(db_key != NULL) free(db_key);
      if(db_val != NULL) free(db_val);
      return (0);
    }

    /*
      It needs to go here otherwise when we update the pcap dropped packets
      this value is updated only in the child process and not
      into the main one.
    */
    printTrafficStatistics(revertOrder);
  } else {

    /* OK, we're doing basic reporting ...
     *       (1) Are we really running?
     *       (2) Fork (if we can) to create a read-only, stable copy
     *       (3) Figure out which page the user wants and give it to him/her
     */
    if (myGlobals.ntopRunState < FLAG_NTOPSTATE_RUN) {
      safe_snprintf (__FILE__, __LINE__, tmpStr, sizeof (tmpStr),
		     "<I><a href=%s>Configure Ntop</a> first. No packet "
		     "captures analyzed</I>", CONST_CONFIG_NTOP_HTML);
      printFlagedWarning (tmpStr);
      if(domainNameParm != NULL) free(domainNameParm);
      if(db_key != NULL) free(db_key);
      if(db_val != NULL) free(db_val);
      return (0);
    }

#if defined(PARM_FORK_CHILD_PROCESS) && (!defined(WIN32))
    if(!myGlobals.runningPref.debugMode) {
#ifdef HANDLE_DIED_CHILD
      handleDiedChild(0); /*
			    Workaround because on this OpenBSD and
			    other platforms signal handling is broken as the system
			    creates zombies although we decided to ignore SIGCHLD
			  */
#endif /* HANDLE_DIED_CHILD */

#if !defined(WIN32) && defined(MAKE_WITH_SYSLOG)
      /* Child processes must log to syslog.
       * If no facility was set through -L | --use-syslog=facility
       * then force the default
       */
      if(myGlobals.runningPref.useSyslog == FLAG_SYSLOG_NONE) {
	static char messageSent = 0;

	if(!messageSent) {
	  messageSent = 1;
	  traceEvent(CONST_TRACE_INFO, "NOTE: -L | --use-syslog=facility not specified, child processes will log to the default (%d).",
		     DEFAULT_SYSLOG_FACILITY);
	}
      }
#endif /* !defined(WIN32) && defined(MAKE_WITH_SYSLOG) */

      /* The URLs below are "read-only" hence I can fork a copy of ntop  */
      if((myGlobals.childntoppid = fork()) < 0)
	traceEvent(CONST_TRACE_ERROR, "An error occurred while forking ntop [errno=%d]..", errno);
      else {
	*usedFork = 1;

        /* This is zero in the parent copy of the structure */
	if(myGlobals.childntoppid) {
	  /* father process */
	  myGlobals.numChildren++;
	  compressFile = 0;
          if(domainNameParm != NULL) free(domainNameParm);
          if(db_key != NULL) free(db_key);
          if(db_val != NULL) free(db_val);
	  return(0);
	} else {


#ifdef MAKE_WITH_HTTPSIGTRAP
          signal(SIGSEGV, httpcleanup);
          signal(SIGHUP,  httpcleanup);
          signal(SIGINT,  httpcleanup);
          signal(SIGQUIT, httpcleanup);
          signal(SIGILL,  httpcleanup);
          signal(SIGABRT, httpcleanup);
          signal(SIGFPE,  httpcleanup);
          signal(SIGKILL, httpcleanup);
          /* signal(SIGPIPE, httpcleanup); */
          signal(SIGTERM, httpcleanup);
          signal(SIGUSR1, httpcleanup);
          signal(SIGUSR2, httpcleanup);
          /* signal(SIGCHLD, httpcleanup); */
#ifdef SIGCONT
          signal(SIGCONT, httpcleanup);
#endif
#ifdef SIGSTOP
          signal(SIGSTOP, httpcleanup);
#endif
#ifdef SIGBUS
          signal(SIGBUS,  httpcleanup);
#endif
#ifdef SIGSYS
          signal(SIGSYS,  httpcleanup);
#endif
#endif /* MAKE_WITH_HTTPSIGTRAP */

	  detachFromTerminalUnderUnix(0);

	  /* Close inherited sockets */
#ifdef HAVE_OPENSSL
	  if(myGlobals.sslInitialized) closeNwSocket(&myGlobals.sock_ssl);
#endif /* HAVE_OPENSSL */
	  if(myGlobals.runningPref.webPort > 0) closeNwSocket(&myGlobals.sock);

#if defined(HAVE_ALARM) && defined(PARM_FORK_CHILD_PROCESS) && (!defined(WIN32))
	  signal(SIGALRM, quitNow);
	  alarm(120); /* Don't freeze */
#endif
	}
      }
    }
#endif

#if !defined(WIN32) && defined(PARM_USE_CGI)
    if(strncasecmp(pageName, CONST_CGI_HEADER, strlen(CONST_CGI_HEADER)) == 0) {
      sendString("HTTP/1.0 200 OK\r\n");
      rc = execCGI(&pageName[strlen(CONST_CGI_HEADER)]);

      if(rc != 0) {
	returnHTTPpageNotFound(NULL);
      }
    } else
#endif

      if(generateNewInternalPages(pageName) == 0) {
	/* We did the work in the function except for this */
	if(strcasecmp(pageName, CONST_HOME_HTML) != 0)
	  printTrailer=0;
      } else if(strncasecmp(pageName, CONST_FC_DATA_HTML,
			    strlen(CONST_FC_DATA_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printFcHostsTraffic(SORT_FC_DATA, sortedColumn, revertOrder,
			    pageNum, CONST_FC_DATA_HTML, showLocalityMode);
      } else if(strncasecmp(pageName, CONST_SORT_DATA_THPT_STATS_HTML,
			    strlen(CONST_SORT_DATA_THPT_STATS_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printThptStats(sortedColumn);
      } else if(strncasecmp(pageName, CONST_THPT_STATS_MATRIX_HTML,
			    strlen(CONST_THPT_STATS_MATRIX_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printThptStatsMatrix(sortedColumn);
      } else if(strncasecmp(pageName, CONST_HOSTS_INFO_HTML, strlen(CONST_HOSTS_INFO_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printHostsInfo(sortedColumn, revertOrder, pageNum, showBytes, vlanId, ifId);
      } else if(strncasecmp(pageName, CONST_FC_HOSTS_INFO_HTML,
			    strlen(CONST_FC_HOSTS_INFO_HTML)) == 0) {
        printFcHostsInfo(sortedColumn, revertOrder, pageNum, showBytes, vsanId);
      } else if(strncasecmp(pageName, CONST_HOSTS_LOCAL_FINGERPRINT_HTML,
			    strlen(CONST_HOSTS_LOCAL_FINGERPRINT_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printHostsStats(FALSE);
      } else if(strncasecmp(pageName, CONST_HOSTS_REMOTE_FINGERPRINT_HTML,
			    strlen(CONST_HOSTS_REMOTE_FINGERPRINT_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printHostsStats(TRUE);
      } else if(strncasecmp(pageName, CONST_HOSTS_LOCAL_CHARACT_HTML,
			    strlen(CONST_HOSTS_LOCAL_CHARACT_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printHostsCharacterization();
      } else if(strncasecmp(pageName, CONST_SORT_DATA_PROTOS_HTML, strlen(CONST_SORT_DATA_PROTOS_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printHostsTraffic(SORT_DATA_PROTOS, sortedColumn, revertOrder,
			  pageNum, CONST_SORT_DATA_PROTOS_HTML,
			  showHostsMode, showLocalityMode, vlanId);
      } else if(strncasecmp(pageName, CONST_SORT_DATA_IP_HTML, strlen(CONST_SORT_DATA_IP_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printHostsTraffic(SORT_DATA_IP, sortedColumn, revertOrder,
			  pageNum, CONST_SORT_DATA_IP_HTML, showHostsMode, showLocalityMode, vlanId);
      } else if(strncasecmp(pageName, CONST_SORT_DATA_THPT_HTML, strlen(CONST_SORT_DATA_THPT_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = FLAG_HOST_DUMMY_IDX; }
	printHostsTraffic(SORT_DATA_THPT, sortedColumn, revertOrder,
			  pageNum, CONST_SORT_DATA_THPT_HTML,
			  showHostsMode, showLocalityMode, vlanId);
      } else if(strncasecmp(pageName, CONST_FC_THPT_HTML,
			    strlen(CONST_FC_THPT_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = FLAG_HOST_DUMMY_IDX; }
	printFcHostsTraffic(SORT_FC_THPT, sortedColumn, revertOrder,
			    pageNum, CONST_FC_THPT_HTML, showLocalityMode);
      } else if(strncasecmp(pageName, CONST_SORT_DATA_HOST_TRAFFIC_HTML,
			    strlen(CONST_SORT_DATA_HOST_TRAFFIC_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = FLAG_HOST_DUMMY_IDX; }
	printHostsTraffic(SORT_DATA_HOST_TRAFFIC, sortedColumn, revertOrder,
			  pageNum, CONST_SORT_DATA_HOST_TRAFFIC_HTML,
			  showHostsMode, showLocalityMode, vlanId);
      } else if(strncasecmp(pageName, CONST_FC_ACTIVITY_HTML,
			    strlen(CONST_FC_ACTIVITY_HTML)) == 0) {
        sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
        if(sortedColumn == 0) { sortedColumn = FLAG_HOST_DUMMY_IDX; }
        printFcHostsTraffic(SORT_FC_ACTIVITY, sortedColumn, revertOrder,
                            pageNum, CONST_FC_ACTIVITY_HTML, showLocalityMode);
      } else if(strcasecmp(pageName, CONST_NET_FLOWS_HTML) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	listNetFlows();
      } else if(strncasecmp(pageName, CONST_IP_R_2_L_HTML, strlen(CONST_IP_R_2_L_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = 1; }
	printIpAccounting(FLAG_REMOTE_TO_LOCAL_ACCOUNTING, sortedColumn, revertOrder, pageNum);
      } else if(strncasecmp(pageName, CONST_IP_R_2_R_HTML, strlen(CONST_IP_R_2_R_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = 1; }
	printIpAccounting(FLAG_REMOTE_TO_REMOTE_ACCOUNTING, sortedColumn, revertOrder, pageNum);
      } else if(strncasecmp(pageName, CONST_IP_L_2_R_HTML, strlen(CONST_IP_L_2_R_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = 1; }
	printIpAccounting(FLAG_LOCAL_TO_REMOTE_ACCOUNTING, sortedColumn, revertOrder, pageNum);
      } else if(strncasecmp(pageName, CONST_IP_L_2_L_HTML, strlen(CONST_IP_L_2_L_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = 1; }
	printIpAccounting(FLAG_LOCAL_TO_LOCAL_ACCOUNTING, sortedColumn, revertOrder, pageNum);
      } else if(strncasecmp(pageName, CONST_ACTIVE_TCP_SESSIONS_HTML,
			    strlen(CONST_ACTIVE_TCP_SESSIONS_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printActiveTCPSessions(myGlobals.actualReportDeviceId, pageNum, NULL);
      } else if(strncasecmp(pageName, CONST_MULTICAST_STATS_HTML, strlen(CONST_MULTICAST_STATS_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printMulticastStats(sortedColumn, revertOrder, pageNum);
      } else if(strncasecmp(pageName, CONST_DOMAIN_STATS_HTML, strlen(CONST_DOMAIN_STATS_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printDomainStats(domainNameParm, 0, abs(sortedColumn), revertOrder, pageNum);
      } else if(strncasecmp(pageName, CONST_CLUSTER_STATS_HTML, strlen(CONST_CLUSTER_STATS_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printDomainStats(domainNameParm, 1, abs(sortedColumn), revertOrder, pageNum);
      } else if(strncasecmp(pageName, CONST_SHOW_PORT_TRAFFIC_HTML,
			    strlen(CONST_SHOW_PORT_TRAFFIC_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	showPortTraffic(portNr);
      } else if(strcasecmp(pageName, CONST_IP_PROTO_DISTRIB_HTML) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printHTMLheader(NULL, NULL, 0);
	printIpProtocolDistribution(FLAG_HOSTLINK_TEXT_FORMAT, revertOrder, TRUE);
      } else if(strcasecmp(pageName, CONST_IP_TRAFFIC_MATRIX_HTML) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printIpTrafficMatrix();
      } else if(strcasecmp(pageName, CONST_LOCAL_ROUTERS_LIST_HTML) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printLocalRoutersList(myGlobals.actualReportDeviceId);
      } else if(strcasecmp(pageName, CONST_AS_LIST_HTML) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printASList(myGlobals.actualReportDeviceId);
      } else if(strcasecmp(pageName, CONST_VLAN_LIST_HTML) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printVLANList(myGlobals.actualReportDeviceId);
      } else if(strcasecmp(pageName, CONST_IP_PROTO_USAGE_HTML) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printIpProtocolUsage();
      } else if(strncasecmp (pageName, CONST_FC_TRAFFIC_HTML,
			     strlen (CONST_FC_TRAFFIC_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = 1; }
	printFcAccounting(FLAG_REMOTE_TO_REMOTE_ACCOUNTING, sortedColumn, revertOrder, pageNum);
      } else if(strcasecmp(pageName, CONST_VSAN_LIST_HTML) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printVSANList(myGlobals.actualReportDeviceId);
      } else if(strcasecmp(pageName, CONST_VSAN_DISTRIB_HTML) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	drawVsanStatsGraph(myGlobals.actualReportDeviceId);
      } else if(strncasecmp (pageName, CONST_VSAN_DETAIL_HTML, strlen (CONST_VSAN_DETAIL_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printVsanDetailedInfo (vsanId, myGlobals.actualReportDeviceId);
      } else if(strncasecmp(pageName, CONST_FC_SESSIONS_HTML,
			    strlen(CONST_FC_SESSIONS_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = 1; }
	printFCSessions(myGlobals.actualReportDeviceId, sortedColumn, revertOrder,
			pageNum, pageName, NULL);
      } else if(strncasecmp(pageName, CONST_SCSI_BYTES_HTML,
			    strlen(CONST_SCSI_BYTES_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = 1; }
	printScsiSessionBytes(myGlobals.actualReportDeviceId, sortedColumn,
			      revertOrder, pageNum, pageName, NULL);
      } else if(strncasecmp(pageName, CONST_SCSI_TIMES_HTML,
			    strlen(CONST_SCSI_TIMES_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = 1; }
	printScsiSessionTimes (myGlobals.actualReportDeviceId, sortedColumn,
			       revertOrder, pageNum, pageName, NULL);
      } else if(strncasecmp(pageName, CONST_SCSI_STATUS_HTML,
			    strlen(CONST_SCSI_STATUS_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = 1; }
	printScsiSessionStatusInfo (myGlobals.actualReportDeviceId, sortedColumn,
				    revertOrder, pageNum, pageName, NULL);
      } else if(strncasecmp(pageName, CONST_SCSI_TM_HTML,
			    strlen(CONST_SCSI_TM_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	if(sortedColumn == 0) { sortedColumn = 1; }
	printScsiSessionTmInfo (myGlobals.actualReportDeviceId, sortedColumn, revertOrder,
				pageNum, pageName, NULL);
      } else if(strncasecmp(pageName, CONST_PIE_VSAN_CNTL_TRAF_DIST,
			    strlen(CONST_PIE_VSAN_CNTL_TRAF_DIST)) == 0) {
        sscanf (pageName, CONST_PIE_VSAN_CNTL_TRAF_DIST "-%d", &vsanId);
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
        drawVsanSwilsProtoDistribution(vsanId);
      } else if(strncasecmp(pageName, CONST_BAR_VSAN_TRAF_DIST_SENT,
			    strlen(CONST_BAR_VSAN_TRAF_DIST_SENT)) == 0) {
        sscanf (pageName, CONST_BAR_VSAN_TRAF_DIST_SENT "-%d", &vsanId);
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
        drawVsanDomainTrafficDistribution(vsanId, TRUE);
      } else if(strncasecmp(pageName, CONST_BAR_VSAN_TRAF_DIST_RCVD,
			    strlen(CONST_BAR_VSAN_TRAF_DIST_RCVD)) == 0) {
        sscanf (pageName, CONST_BAR_VSAN_TRAF_DIST_RCVD "-%d", &vsanId);
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
        drawVsanDomainTrafficDistribution(vsanId, FALSE);
#ifndef EMBEDDED
#ifdef CFG_USE_GRAPHICS
      } else if(strncasecmp(pageName, CONST_THROUGHPUT_GRAPH, strlen(CONST_THROUGHPUT_GRAPH)) == 0) {
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	drawThptGraph(sortedColumn);
	printTrailer=0;
      } else if(strncasecmp(pageName, CONST_PIE_IP_TRAFFIC, strlen(CONST_PIE_IP_TRAFFIC)) == 0) {
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	drawTrafficPie();
	printTrailer=0;
      } else if(strncasecmp(pageName, CONST_PIE_PKT_CAST_DIST,
			    strlen(CONST_PIE_PKT_CAST_DIST)) == 0) {
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	pktCastDistribPie();
	printTrailer=0;
      } else if(strncasecmp(pageName, CONST_PIE_PKT_SIZE_DIST,
			    strlen(CONST_PIE_PKT_SIZE_DIST)) == 0) {
	if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value > 0) {
	  sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	  pktSizeDistribPie();
	  printTrailer=0;
	} else {
	  printNoDataYet();
	}
      } else if(strncasecmp(pageName, CONST_PIE_FC_PKT_SZ_DIST,
			    strlen(CONST_PIE_FC_PKT_SZ_DIST)) == 0) {
	if(myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value > 0) {
	  sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	  fcPktSizeDistribPie();
	  printTrailer=0;
	} else {
	  printNoDataYet();
	}
      } else if(strncasecmp(pageName, CONST_PIE_TTL_DIST, strlen(CONST_PIE_TTL_DIST)) == 0) {
	if(myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value > 0) {
	  sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	  pktTTLDistribPie();
	  printTrailer=0;
	} else {
	  printNoDataYet();
	}
      } else if(strncasecmp(pageName, CONST_PIE_IPPROTO_RL_DIST,
			    strlen(CONST_PIE_IPPROTO_RL_DIST)) == 0) {
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	ipProtoDistribPie();
	printTrailer=0;
      } else if(strncasecmp(pageName, CONST_PIE_INTERFACE_DIST,
			    strlen(CONST_PIE_INTERFACE_DIST)) == 0) {
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	interfaceTrafficPie();
	printTrailer=0;
      } else if(strncasecmp(pageName, CONST_BAR_ALLPROTO_DIST,
			    strlen(CONST_BAR_ALLPROTO_DIST)) == 0) {
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	drawGlobalProtoDistribution();
	printTrailer=0;
      } else if(strncasecmp(pageName,CONST_NETWORK_MAP_HTML, strlen(CONST_NETWORK_MAP_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	makeDot();
	printTrailer=1;
      } else if(strncasecmp(pageName, CONST_BAR_IPPROTO_DIST,
			    strlen(CONST_BAR_IPPROTO_DIST)) == 0) {
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	drawGlobalIpProtoDistribution();
	printTrailer=0;
      } else if(strncasecmp(pageName, CONST_BAR_HOST_DISTANCE,
			    strlen(CONST_BAR_HOST_DISTANCE)) == 0) {
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	drawHostsDistanceGraph(0);
	printTrailer=0;
      } else if(strncasecmp(pageName, CONST_BAR_FC_PROTO_DIST,
			    strlen(CONST_BAR_FC_PROTO_DIST)) == 0) {
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	drawGlobalFcProtoDistribution();
	printTrailer=0;
      } else if(strncasecmp(pageName, CONST_BAR_LUNSTATS_DIST,
			    strlen(CONST_BAR_LUNSTATS_DIST)) == 0) {
        HostTraffic *el=NULL;
        char hostName[32], *theHost;

        theHost = &pageName[strlen(CONST_BAR_LUNSTATS_DIST)+1];
        if(strlen(theHost) >= 31) theHost[31] = 0;

        for (i=strlen(theHost); i>0; i--) {
	  if(theHost[i] == '?') {
	    theHost[i] = '\0';
	    break;
	  }
        }

        memset(hostName, 0, sizeof(hostName));
        strncpy(hostName, theHost, strlen(theHost)-strlen(CHART_FORMAT));

	if((minus = strchr(hostName, '-')) != NULL) {
	  minus[0] = '\0';
	  vlanId  = atoi(&minus[1]);
	}

        urlFixupFromRFC1945Inplace(hostName);

#ifdef URL_DEBUG
        traceEvent(CONST_TRACE_INFO, "Searching hostname: '%s' [%d]\r\n", hostName, vlanId);
#endif

        // printf("->> Searching hostname: '%s' [%d]\r\n", hostName, vlanId);

        for(el=getFirstHost(myGlobals.actualReportDeviceId);
            el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
	  if(!isFcHost(el)) {
	    if((el != myGlobals.broadcastEntry)
	       && (el->hostNumIpAddress != NULL)
	       && ((vlanId == NO_VLAN) || ((el->vlanId <= 0) || (el->vlanId == vlanId)))
	       && ((el->vlanId <= 0) || (el->vlanId == vlanId))
	       && ((strcmp(el->hostNumIpAddress, hostName) == 0)
		   || (strcmp(el->ethAddressString, hostName) == 0))) {
	      break;
	    }
          } else {
	    if((el->fcCounters->hostNumFcAddress != NULL) &&
	       strcmp(el->fcCounters->hostNumFcAddress, hostName) == 0)
	      break;
          }
        }

	if(el == NULL) {
	  returnHTTPpageNotFound(NULL);
	  printTrailer=0;
	} else {
	  if(el->community && (!isAllowedCommunity(el->community)))
	    returnHTTPpageBadCommunity();
	  else {
	    sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	    drawLunStatsBytesDistribution(el);
	  }
	  printTrailer=0;
	}
      } else if(strncasecmp(pageName, "drawLunStatsPktsDistribution",
			    strlen("drawLunStatsPktsDistribution")) == 0) {
        HostTraffic *el=NULL;
        char hostName[32], *theHost;

        theHost = &pageName[strlen("drawLunStatsPktsDistribution")+1];
        if(strlen(theHost) >= 31) theHost[31] = 0;

        for (i=strlen(theHost); i>0; i--) {
	  if(theHost[i] == '?') {
	    theHost[i] = '\0';
	    break;
	  }
        }

        memset(hostName, 0, sizeof(hostName));
        strncpy(hostName, theHost, strlen(theHost)-strlen(CHART_FORMAT));

	if((minus = strchr(hostName, '-')) != NULL) {
	  minus[0] = '\0';
	  vlanId  = atoi(&minus[1]);
	}

        urlFixupFromRFC1945Inplace(hostName);

#ifdef URL_DEBUG
        traceEvent(CONST_TRACE_INFO, "Searching hostname: '%s'\r\n", hostName);
#endif

        for(el=getFirstHost(myGlobals.actualReportDeviceId);
            el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
	  if(!isFcHost(el)) {
	    if((el != myGlobals.broadcastEntry)
	       && (el->hostNumIpAddress != NULL)
	       && ((el->vlanId <= 0) || (el->vlanId == vlanId))
	       && ((strcmp(el->hostNumIpAddress, hostName) == 0)
		   || (strcmp(el->ethAddressString, hostName) == 0)))
	      break;
	  } else {
	    if((el->fcCounters->hostNumFcAddress != NULL) &&
	       strcmp(el->fcCounters->hostNumFcAddress, hostName) == 0)
	      break;
	  }
        }

        if(el == NULL) {
	  returnHTTPpageNotFound(NULL);
	  printTrailer=0;
        } else {
	  if(el->community && (!isAllowedCommunity(el->community)))
	    returnHTTPpageBadCommunity();
	  else {
	    sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
	    drawLunStatsPktsDistribution(el);
	  }
	  printTrailer=0;
        }
      } else if(strncasecmp(pageName, "drawVsanStatsBytesDistribution",
			    strlen("drawVsanStatsBytesDistribution")) == 0) {
        sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
        drawVsanStatsBytesDistribution (myGlobals.actualReportDeviceId);
        printTrailer=0;
      } else if(strncasecmp(pageName, "drawVsanStatsPktsDistribution",
			    strlen("drawVsanStatsPktsDistribution")) == 0) {
        sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);
        drawVsanStatsPktsDistribution (myGlobals.actualReportDeviceId);
        printTrailer=0;
      } else if((strncasecmp(pageName,    "hostTrafficDistrib", strlen("hostTrafficDistrib")) == 0)
		|| (strncasecmp(pageName, "hostFragmentDistrib", strlen("hostFragmentDistrib")) == 0)
		|| (strncasecmp(pageName, "hostTotalFragmentDistrib", strlen("hostTotalFragmentDistrib")) == 0)
		|| (strncasecmp(pageName, "hostIPTrafficDistrib", strlen("hostIPTrafficDistrib")) == 0)
		|| (strncasecmp(pageName, "hostTimeTrafficDistribution", strlen("hostTimeTrafficDistribution")) == 0)
		|| (strncasecmp(pageName, "hostFcTrafficDistrib", strlen("hostFcTrafficDistrib")) == 0)
		) {
	char hostName[47], *theHost;

	if(strncasecmp(pageName, "hostTrafficDistrib", strlen("hostTrafficDistrib")) == 0) {
	  idx = 0;
	  theHost = &pageName[strlen("hostTrafficDistrib")+1];
	} else if(strncasecmp(pageName, "hostFragmentDistrib", strlen("hostFragmentDistrib")) == 0) {
	  idx = 1;
	  theHost = &pageName[strlen("hostFragmentDistrib")+1];
	} else if(strncasecmp(pageName, "hostTotalFragmentDistrib", strlen("hostTotalFragmentDistrib")) == 0) {
	  idx = 2;
	  theHost = &pageName[strlen("hostTotalFragmentDistrib")+1];
	} else if(strncasecmp(pageName, "hostTimeTrafficDistribution", strlen("hostTimeTrafficDistribution")) == 0) {
	  idx = 3;
	  theHost = &pageName[strlen("hostTimeTrafficDistribution")+1];
	} else if(strncasecmp(pageName, "hostFcTrafficDistrib", strlen("hostFcTrafficDistrib")) == 0) {
	  idx = 5;
	  theHost = &pageName[strlen("hostFcTrafficDistrib")+1];
	} else {
	  idx = 4;
	  theHost = &pageName[strlen("hostIPTrafficDistrib")+1];
	}

	if(strlen(theHost) <= strlen(CHART_FORMAT)) {
	  printNoDataYet();
	} else {
	  HostTraffic *el=NULL;

	  if(strlen(theHost) >= 47) theHost[47] = 0;
	  for(i=strlen(theHost); i>0; i--)
	    if(theHost[i] == '?') {
	      theHost[i] = '\0';
	      break;
	    }

	  memset(hostName, 0, sizeof(hostName));
	  strncpy(hostName, theHost, strlen(theHost)-strlen(CHART_FORMAT));

	  if((minus = strchr(hostName, '-')) != NULL) {
	    minus[0] = '\0';
	    vlanId  = atoi(&minus[1]);
	  }

	  urlFixupFromRFC1945Inplace(hostName);

#ifdef URL_DEBUG
	  traceEvent(CONST_TRACE_INFO, "Searching hostname: '%s'\r\n", hostName);
#endif

	  for(el=getFirstHost(myGlobals.actualReportDeviceId);
	      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
	    if(isFcHost(el)) {
              if((el->fcCounters->hostNumFcAddress != NULL) &&
		 strcmp(el->fcCounters->hostNumFcAddress, hostName) == 0)
		break;
	    } else {
	      if((el != myGlobals.broadcastEntry)
		 && (el->hostNumIpAddress != NULL)
		 && ((el->vlanId <= 0) || (el->vlanId == vlanId))
		 && ((strcmp(el->hostNumIpAddress, hostName) == 0)
                     || (strcmp(el->ethAddressString, hostName) == 0)))
		break;
	    }
	  } /* for */

	  if(el == NULL) {
	    returnHTTPpageNotFound(NULL);
	    printTrailer=0;
	  } else {
	    if(el->community && (!isAllowedCommunity(el->community))) {
	      returnHTTPpageBadCommunity();
	    } else {	    
	      sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0, 1);

	      switch(idx) {
	      case 0:
		hostTrafficDistrib(el, sortedColumn);
		break;
	      case 1:
		hostFragmentDistrib(el, sortedColumn);
		break;
	      case 2:
		hostTotalFragmentDistrib(el, sortedColumn);
		break;
	      case 3:
		hostTimeTrafficDistribution(el, sortedColumn);
		break;
	      case 4:
		hostIPTrafficDistrib(el, sortedColumn);
		break;
	      case 5:
		hostFcTrafficDistrib(el, sortedColumn);
		break;
	      }
	    }

	    printTrailer=0;
	  }
	}
#endif /* CFG_USE_GRAPHICS */
#endif /* EMBEDDED */
      } else if(strcasecmp(pageName, CONST_CREDITS_HTML) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printHTMLheader("Credits", NULL, BITFLAG_HTML_NO_REFRESH);
	sendString("<hr><br>");
	sendString("<p><b>ntop</b> was been created by ");
	sendString("<a class=external href=\"http://luca.ntop.org/\" class=tooltip title=\"Luca's home page\">");
	sendString("Luca Deri</a> while studying how to model network traffic. He was unsatisfied");
	sendString("by the many network traffic analysis tools he had access to, and decided to ");
	sendString("write a new application able to report network traffic information in a way");
	sendString("similar to the popular Unix top command. At that point in time (it was June ");
	sendString("1998) <b>ntop</b> was born.</p>");
	sendString("<p>The current release is very different from the initial one as it includes");
	sendString("many features and much additional media support.</p>");
	sendString("<p><b>ntop</b> has definitively more than one author:</p>");
	/* Addresses are blinded to prevent easy spam harvest -
	 *   see http://www.wbwip.com/wbw/emailencoder.html
	 */

	sendString("<ul><li>" CONST_MAILTO_STEFANO " has contributed several ideas and comments</li>");
	sendString("<li>" CONST_MAILTO_ABDELKADER " and " CONST_MAILTO_OLIVIER " provided IPv6 support</li>");
	sendString("<li>" CONST_MAILTO_DINESH " for SCSI & FiberChannel support</li>");
	sendString("<li>" CONST_MAILTO_BURTON " the ntop factotum (user support, bug fixing, testing, packaging).</li></ul>");
	sendString("<p>In addition, many other people downloaded this program, tested it,");
	sendString("joined the <a class=external href=\"http://lists.ntop.org/mailman/listinfo/ntop\"");
	sendString(" class=tooltip title=\"ntop mailing list signup page\">ntop</a> ");
	sendString("and <a class=external href=\"http://lists.ntop.org/mailman/listinfo/ntop-dev\"");
	sendString(" class=tooltip title=\"ntop-dev mailing list signup page\">ntop-dev</a> mailing lists,");
	sendString("reported problems, changed it and improved significantly. This is because");
	sendString("they have realised that <b>ntop</b> doesn't belong uniquely to its author,");
	sendString("but to the whole Internet community. Their names are throught the <b>ntop</b> code.</p>");
	sendString("<p>The author would like to thank all these people who contributed to <b>ntop</b>");
	sendString(" and turned it into a first class network monitoring tool. Many thanks guys!</p>");
      } else if(strncasecmp(pageName, CONST_INFO_NTOP_HTML, strlen(CONST_INFO_NTOP_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printNtopConfigInfo(FALSE, &myGlobals.runningPref);
      } else if(strncasecmp(pageName, CONST_TEXT_INFO_NTOP_HTML, strlen(CONST_TEXT_INFO_NTOP_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printNtopConfigInfo(TRUE, &myGlobals.runningPref);
	printTrailer = 0;
      } else if(strncasecmp(pageName, CONST_PROBLEMRPT_HTML, strlen(CONST_PROBLEMRPT_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printNtopProblemReport();
	printTrailer = 0;
      } else if(strncasecmp(pageName, CONST_VIEW_LOG_HTML, strlen(CONST_VIEW_LOG_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	printNtopLogReport(FALSE);
	printTrailer = 0;
      } else if(strncasecmp(pageName, CONST_DUMP_DATA_HTML, strlen(CONST_DUMP_DATA_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_TEXT, 0, 1);
	if((questionMark == NULL) || (questionMark[0] == '\0'))
	  dumpNtopHashes(NULL, NULL, myGlobals.actualReportDeviceId);
	else
	  dumpNtopHashes(NULL, &questionMark[1], myGlobals.actualReportDeviceId);
	printTrailer = 0;
      } else if(strncasecmp(pageName, CONST_DUMP_HOSTS_INDEXES_HTML,
			    strlen(CONST_DUMP_HOSTS_INDEXES_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_TEXT, 0, 1);
	if((questionMark == NULL) || (questionMark[0] == '\0'))
	  dumpNtopHashIndexes(NULL, NULL, myGlobals.actualReportDeviceId);
	else
	  dumpNtopHashIndexes(NULL, &questionMark[1], myGlobals.actualReportDeviceId);
	printTrailer = 0;
      } else if(strncasecmp(pageName, CONST_DUMP_NTOP_FLOWS_HTML,
			    strlen(CONST_DUMP_NTOP_FLOWS_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_TEXT, 0, 1);
	if((questionMark == NULL) || (questionMark[0] == '\0'))
	  dumpNtopFlows(NULL, NULL, myGlobals.actualReportDeviceId);
	else
	  dumpNtopFlows(NULL, &questionMark[1], myGlobals.actualReportDeviceId);
	printTrailer = 0;
      } else if(strncasecmp(pageName, CONST_DUMP_NTOP_HOSTS_MATRIX_HTML,
			    strlen(CONST_DUMP_NTOP_HOSTS_MATRIX_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_TEXT, 0, 1);
	if((questionMark == NULL) || (questionMark[0] == '\0'))
	  dumpNtopTrafficMatrix(NULL, NULL, myGlobals.actualReportDeviceId);
	else
	  dumpNtopTrafficMatrix(NULL, &questionMark[1], myGlobals.actualReportDeviceId);
	printTrailer = 0;
      } else if(strncasecmp(pageName, CONST_DUMP_TRAFFIC_DATA_HTML,
			    strlen(CONST_DUMP_TRAFFIC_DATA_HTML)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_TEXT, 0, 1);
	if((questionMark == NULL) || (questionMark[0] == '\0'))
	  dumpNtopTrafficInfo(NULL, NULL);
	else
	  dumpNtopTrafficInfo(NULL, &questionMark[1]);
	printTrailer = 0;
      } else if(strncasecmp(pageName, CONST_PURGE_HOST, strlen(CONST_PURGE_HOST)) == 0) {
	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	purgeHost(db_key);
      } else if(strlen(pageName) > 5) {
	char hostName[32];

	for(i=strlen(pageName); i>0; i--)
	  if(pageName[i] == '?') {
	    pageName[i] = '\0';
	    break;
	  }

	pageName[strlen(pageName)-5] = '\0';
	if(strlen(pageName) >= 31) pageName[31] = 0;
	urlFixupFromRFC1945Inplace(pageName);

	strncpy(hostName, pageName, sizeof(hostName));
	if(sortedColumn == 0) {
	  sortedColumn = 1;
	}

	printAllSessionsHTML(hostName, myGlobals.actualReportDeviceId,
			     sortedColumn, revertOrder, pageNum, pageName,
			     showFcHostsPage);
      } else {
	printTrailer = 0;
	errorCode = FLAG_HTTP_INVALID_PAGE;
      }
  }

  if(domainNameParm != NULL) free(domainNameParm);
  if(db_key != NULL) free(db_key);
  if(db_val != NULL) free(db_val);

  if(printTrailer && (postLen == -1)) printHTMLtrailer();

#if defined(PARM_FORK_CHILD_PROCESS) && (!defined(WIN32))
  if(*usedFork) {
    u_int gzipBytesSent = 0;

#ifdef MAKE_WITH_ZLIB
    if(compressFile)
      compressAndSendData(&gzipBytesSent);
#endif
    closeNwSocket(&myGlobals.newSock);
    logHTTPaccess(200, httpRequestedAt, gzipBytesSent);
    exit(0);
  }
#endif /* FORK_CHILD */

  if(pageName && (strncasecmp(pageName, 
			      CONST_SHUTDOWNNOW_NTOP_IMG, 
			      strlen(CONST_SHUTDOWNNOW_NTOP_IMG)) == 0)) {
    /* Processed the page, it's time to flag this for the web server to shutdown... */
    termAccessLog();
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "WEB: Beginning actual shutdown sequence");
    setRunState(FLAG_NTOPSTATE_SHUTDOWNREQ);
  }

  return(errorCode);
}

/* ************************* */

static int checkHTTPpassword(char *theRequestedURL,
			     int theRequestedURLLen _UNUSED_,
			     char* thePw, int thePwLen) {
  char outBuffer[65], *user = NULL, users[LEN_GENERAL_WORK_BUFFER];
  int i, rc;
  datum key, nextkey;

  theHttpUser[0] = '\0';

#ifdef URL_DEBUG
  traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Checking password-protect for '%s'", theRequestedURL);
#endif

  if(myGlobals.securityItemsLoaded == 0) {

    traceEvent(CONST_TRACE_NOISY, "SECURITY: Loading items table");

    accessMutex(&myGlobals.securityItemsMutex,  "load");

    key = gdbm_firstkey(myGlobals.pwFile);

    while(key.dptr != NULL) {
      myGlobals.securityItems[myGlobals.securityItemsLoaded++] = key.dptr;
      nextkey = gdbm_nextkey(myGlobals.pwFile, key);
      key = nextkey;

      if(myGlobals.securityItemsLoaded == MAX_NUM_PWFILE_ENTRIES) {
          traceEvent(CONST_TRACE_WARNING,
                     "Number of entries in password file, %d at limit",
                     myGlobals.securityItemsLoaded);
          break;
      }
    }

    releaseMutex(&myGlobals.securityItemsMutex);
  }

  outBuffer[0] = '\0';

  accessMutex(&myGlobals.securityItemsMutex,  "test");

  for(i=0; i<myGlobals.securityItemsLoaded; i++) {
    if(myGlobals.securityItems[i][0] == '2') /* 2 = URL */ {
      if(strncasecmp(&theRequestedURL[1], &myGlobals.securityItems[i][1],
               strlen(myGlobals.securityItems[i])-1) == 0) {
        strncpy(outBuffer,
                myGlobals.securityItems[i],
                sizeof(outBuffer)-1)[sizeof(outBuffer)-1] = '\0';
	break;
      }
    }
  }

  releaseMutex(&myGlobals.securityItemsMutex);

  if(outBuffer[0] == '\0') {
    return 1; /* This is a non protected URL */
  }

  /* Retrieve CURRENT record - it might have changed since stored above */
#ifdef URL_DEBUG
  traceEvent(CONST_TRACE_INFO, "URL_DEBUG: Retrieving '%s'", outBuffer);
#endif

  key.dptr = outBuffer;
  key.dsize = strlen(outBuffer)+1;
  nextkey = gdbm_fetch(myGlobals.pwFile, key);

  if(nextkey.dptr == NULL) {
    traceEvent(CONST_TRACE_NOISY,
               "SECURITY: request for url '%s' disallowed (I'm confused)",
               &theRequestedURL[1]);
    return 0; /* The record used to exist - it's in securityItems, now it's gone.  Punt */
  }

#ifdef URL_DEBUG
  traceEvent(CONST_TRACE_INFO, "URL_DEBUG: gdbm_fetch(..., '%s')='%s'", key.dptr, nextkey.dptr);
#endif

  i = decodeString(thePw, (unsigned char*)outBuffer, sizeof(outBuffer));

  if(i == 0) {
    user = "", thePw[0] = '\0';
    outBuffer[0] = '\0';
  } else {
    outBuffer[i] = '\0';

    for(i=0; i<(int)sizeof(outBuffer); i++)
      if(outBuffer[i] == ':') {
	outBuffer[i] = '\0';
	user = outBuffer;
	break;
      }

    strncpy(thePw, &outBuffer[i+1], thePwLen-1)[thePwLen-1] = '\0';
  }

  if(strlen(user) >= sizeof(theHttpUser)) user[sizeof(theHttpUser)-1] = '\0';
  strcpy(theHttpUser, user);

/* Following is not URL_DEBUG so we don't accidentally log the crypt()ed password value */
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: User='%s' - Pw='%s'", user, thePw);
#endif

  safe_snprintf(__FILE__, __LINE__, users, LEN_GENERAL_WORK_BUFFER, "1%s", user);

  /* Start simple.  Is the user even in the permitted list? */
  if(strstr(nextkey.dptr, users) == NULL) {
    if(nextkey.dptr != NULL) free(nextkey.dptr);
    if(strlen(&theRequestedURL[1]) > 40) {
        theRequestedURL[40]='.';
        theRequestedURL[41]='.';
        theRequestedURL[42]='.';
        theRequestedURL[43]='\0';
    }
    traceEvent(CONST_TRACE_NOISY,
               "SECURITY: user '%s' request for url '%s' disallowed",
               user == NULL ? "none" :
                 strcmp(user, "") || user[0] == '\0' ? "unspecified" : user,
               &theRequestedURL[1]);
    return 0; /* The specified user is not among those who are
                 allowed to access the URL */
  }
  free(nextkey.dptr);

#ifdef HAVE_CRYPTGETFORMAT
  /* If we have the routine retrieve the format and do the crypt_set_format first... */
  {
    datum fmtkey, fmtdata;
    char users3[LEN_GENERAL_WORK_BUFFER];

    memset(&fmtdata, 0, sizeof(fmtdata));

    safe_snprintf(__FILE__, __LINE__, users3, sizeof(users3), "3%s", user);

#ifdef URL_DEBUG
    traceEvent(CONST_TRACE_NOISY, "URL_DEBUG: Checking for crypt_set_format() for %s", users3);
#endif

    fmtkey.dptr = users3;
    fmtkey.dsize = strlen(users3) + 1;
    fmtdata = gdbm_fetch(myGlobals.pwFile, fmtkey);
    if(fmtdata.dptr != NULL) {
      rc=crypt_set_format(fmtdata.dptr);
      if(rc == 0)
        traceEvent(CONST_TRACE_WARNING, "Unable to set crypt format ... password compare may fail");
#ifdef URL_DEBUG
      else
        traceEvent(CONST_TRACE_NOISY, "URL_DEBUG: crypt_set_format(%d) ok", fmtdata.dptr);
#endif
      free (fmtdata.dptr);
    }
#ifdef URL_DEBUG
      else
        traceEvent(CONST_TRACE_NOISY, "URL_DEBUG: '3' record for %s(%d) not found", fmtkey.dptr, fmtkey.dsize);
#endif
  }
#endif

  key.dptr = users;
  key.dsize = strlen(users)+1;
  nextkey = gdbm_fetch(myGlobals.pwFile, key);

/* Following is not URL_DEBUG so we don't accidentally log the crypt()ed password value */
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Record='%s' = '%s'", users, nextkey.dptr);
#endif

  if(nextkey.dptr != NULL) {
#ifdef WIN32
    rc = !strcmp(nextkey.dptr, thePw);
#else
    rc = !strcmp(nextkey.dptr,
		 (char*)crypt((const char*)thePw, (const char*)CONST_CRYPT_SALT));
#endif
    free (nextkey.dptr);
  } else
    rc = 0;

    if(strcmp(theHttpUser, theLastHttpUser)) {
      char prefKey[64], communities[256], *item, *strtokState;
      
      strcpy(theLastHttpUser, theHttpUser);
      
      snprintf(prefKey, sizeof(prefKey), "%s%s", COMMUNITY_PREFIX, theHttpUser);
      fetchPwValue(prefKey, allowedCommunities, sizeof(allowedCommunities));
      // traceEvent(CONST_TRACE_INFO, "++++++++++++> '%s'", allowedCommunities);

      item = strtok_r(allowedCommunities, "&", &strtokState);
      for(i=0; (item != NULL) && (i < sizeof(allowedCommunities)-1); i++) {
	listAllowedCommunities[i] = item;
	item = strtok_r(NULL, "&", &strtokState);
      }     
    }

  if(rc == 0) {
    if(strlen(&theRequestedURL[1]) > 40) {
      theRequestedURL[40]='.';
      theRequestedURL[41]='.';
      theRequestedURL[42]='.';
      theRequestedURL[43]='\0';
    }
    traceEvent(CONST_TRACE_NOISY,
               "SECURITY: user '%s' request for url '%s' disallowed",
               user == NULL ? "none" :
                 strcmp(user, "") || user[0] == '\0' ? "unspecified" : user,
               &theRequestedURL[1]);
  }

  return(rc);
}

/* ************************* */

#ifdef MAKE_WITH_ZLIB

static void compressAndSendData(u_int *gzipBytesSent) {
  FILE *fd;
  int len;
  char tmpStr[256];

  memset(&tmpStr, 0, sizeof(tmpStr));

  if(gzflush(compressFileFd, Z_FINISH) != Z_OK) {
    int err;
    traceEvent(CONST_TRACE_WARNING, "gzflush error %d(%s)",
	       err, gzerror(compressFileFd, &err));
  }

  gzclose(compressFileFd);

  compressFile = 0; /* Stop compression */
  fd = fopen(compressedFilePath, "rb");

  if(fd == NULL) {
    if(gzipBytesSent != NULL)
      (*gzipBytesSent) = 0;
    return;
  }

  sendString("Content-Encoding: gzip\r\n");
  fseek(fd, 0, SEEK_END);
  safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "Content-Length: %d\r\n\r\n", (len = ftell(fd)));
  fseek(fd, 0, SEEK_SET);
  sendString(tmpStr);

  if(gzipBytesSent != NULL)
    (*gzipBytesSent) = len;

  for(;;) {
    len = fread(tmpStr, sizeof(char), 255, fd);
    if(len <= 0) break;
    sendStringLen(tmpStr, len);
  }
  fclose(fd);

  unlink(compressedFilePath);
}

#endif /* MAKE_WITH_ZLIB */

/* ************************* */

void handleHTTPrequest(HostAddr from) {
  int rc, i, skipLeading, postLen, usedFork = 0, numLang = 0;
  char requestedURL[MAX_LEN_URL], pw[64], agent[256], referer[256], workLanguage[256], *requestedURLCopy=NULL;
  struct timeval httpRequestedAt;
  u_int gzipBytesSent = 0;
  char *requestedLanguage[MAX_LANGUAGES_REQUESTED];

  char tmpStr[512];
  int isPostMethod = FALSE;

#ifdef HAVE_LIBWRAP
  struct request_info req;

  request_init(&req, RQ_DAEMON, CONST_DAEMONNAME, RQ_FILE, myGlobals.newSock, NULL);
  fromhost(&req);
  if(!hosts_access(&req)) {
    closelog(); /* just in case */
    if(myGlobals.runningPref.instance != NULL)
      openlog(myGlobals.runningPref.instance, LOG_PID, deny_severity);
    else 
      openlog(CONST_DAEMONNAME, LOG_PID, deny_severity);
    syslog(deny_severity, "refused connect from %s", eval_client(&req));
    myGlobals.numHandledBadrequests[myGlobals.newSock > 0]++;
    return;
  }
#endif /* HAVE_LIBWRAP */

  myGlobals.numHandledRequests[myGlobals.newSock > 0]++;

  gettimeofday(&httpRequestedAt, NULL);

  if(from.hostFamily == AF_INET)
    from.Ip4Address.s_addr = ntohl(from.Ip4Address.s_addr);

  requestFrom = &from;

#if defined(MAX_NUM_BAD_IP_ADDRESSES) && (MAX_NUM_BAD_IP_ADDRESSES > 0)
   /* Note if the size of the table is zero, we simply nullify all of this
      code (why bother wasting the work effort)
      Burton M. Strauss III <Burton@ntopsupport.com>, June 2002
    */

  for(i=0; i<MAX_NUM_BAD_IP_ADDRESSES; i++) {
    if(addrcmp(&myGlobals.weDontWantToTalkWithYou[i].addr,&from) == 0) {
       if((myGlobals.weDontWantToTalkWithYou[i].lastBadAccess +
           PARM_WEDONTWANTTOTALKWITHYOU_INTERVAL) < myGlobals.actTime) {
         /*
          * We 'forget' the address of this nasty guy after 5 minutes
          * since its last bad access as we hope that he will be nicer
          * with ntop in the future.
          */
         memset(&myGlobals.weDontWantToTalkWithYou[i], 0, sizeof(BadGuysAddr));
         traceEvent(CONST_TRACE_INFO, "clearing lockout for address %s",
                    _addrtostr(&from, requestedURL, sizeof(requestedURL)));
       } else {
         myGlobals.weDontWantToTalkWithYou[i].count++;
         myGlobals.numHandledBadrequests[myGlobals.newSock > 0]++;
         traceEvent(CONST_TRACE_ERROR, "Rejected request from address %s (it previously sent ntop a bad request)",
                    _addrtostr(&from, requestedURL, sizeof(requestedURL)));
         return;
       }
    }
  }
#endif

  memset(requestedURL, 0, sizeof(requestedURL));
  memset(pw, 0, sizeof(pw));
  memset(agent, 0, sizeof(agent));
  memset(referer, 0, sizeof(referer));

#ifdef MAKE_WITH_I18N
  memset(requestedLanguage, 0, sizeof(requestedLanguage));
#endif
  memset(&workLanguage, 0, sizeof(workLanguage));

  httpBytesSent = 0;
  compressFile = 0;
  compressFileFd = NULL;
  acceptGzEncoding = 0;

 postLen = readHTTPheader(requestedURL,
                          sizeof(requestedURL),
                          pw,
                          sizeof(pw),
                          agent,
                          sizeof(agent),
                          referer,
                          sizeof(referer),
                          workLanguage,
                          sizeof(workLanguage),
                          &isPostMethod);

#if defined(HTTP_DEBUG) || defined(I18N_DEBUG) || defined(URL_DEBUG)
 traceEvent(CONST_TRACE_INFO, "HTTP/I18N_URL_DEBUG: Requested URL = '%s', length = %d", requestedURL, postLen);
 traceEvent(CONST_TRACE_INFO, "HTTP/I18N_URL_DEBUG: User-Agent = '%s'", agent);
 traceEvent(CONST_TRACE_INFO, "HTTP/I18N_URL_DEBUG: Referer = '%s'", referer);

 #ifdef MAKE_WITH_I18N
  traceEvent(CONST_TRACE_INFO, "I18N_DEBUG: Accept-Language = '%s'", workLanguage);
 #endif
#endif

  if(postLen >= -1) {
    ; /* no errors, skip following tests */
  } else if(postLen == FLAG_HTTP_INVALID_REQUEST) {
    returnHTTPbadRequest();
    return;
  } else if(postLen == FLAG_HTTP_INVALID_METHOD) {
    /* Courtesy of Vanja Hrustic <vanja@relaygroup.com> */
    returnHTTPnotImplemented();
    return;
  } else if(postLen == FLAG_HTTP_INVALID_VERSION) {
    returnHTTPversionNotSupported();
    return;
  } else if(postLen == FLAG_HTTP_REQUEST_TIMEOUT) {
    returnHTTPrequestTimedOut();
    return;
  }

  /*
     We need to check whether the URL is invalid, i.e. it contains '..' or
     similar chars that can be used for reading system files
  */

  requestedURLCopy = strdup(requestedURL);

  if((rc = checkURLsecurity(requestedURLCopy)) != 0) {
    traceEvent(CONST_TRACE_ERROR, "URL security: '%s' rejected (code=%d)(client=%s)",
	       requestedURL, rc, _addrtostr(&from, tmpStr, sizeof(tmpStr)));

#if defined(MAX_NUM_BAD_IP_ADDRESSES) && (MAX_NUM_BAD_IP_ADDRESSES > 0)
  {
   /* Note if the size of the table is zero, we simply nullify all of this
      code (why bother wasting the work effort
          Burton M. Strauss III <Burton@ntopsupport.com>, June 2002
    */

    int found = 0;

    /*
       Let's record the IP address of this nasty
       guy so he will stay far from ntop
       for a while
    */
    for(i=0; i<MAX_NUM_BAD_IP_ADDRESSES-1; i++)
      if(addrcmp(&myGlobals.weDontWantToTalkWithYou[MAX_NUM_BAD_IP_ADDRESSES-1].addr,&from) == 0) {
	found = 1;
	break;
      }

    if(!found) {
      for(i=0; i<MAX_NUM_BAD_IP_ADDRESSES-1; i++) {
	addrcpy(&myGlobals.weDontWantToTalkWithYou[i].addr,&myGlobals.weDontWantToTalkWithYou[i+1].addr);
	myGlobals.weDontWantToTalkWithYou[i].lastBadAccess = myGlobals.weDontWantToTalkWithYou[i+1].lastBadAccess;
	myGlobals.weDontWantToTalkWithYou[i].count = myGlobals.weDontWantToTalkWithYou[i+1].count;
      }

      addrcpy(&myGlobals.weDontWantToTalkWithYou[MAX_NUM_BAD_IP_ADDRESSES-1].addr,&from);
      myGlobals.weDontWantToTalkWithYou[MAX_NUM_BAD_IP_ADDRESSES-1].lastBadAccess = myGlobals.actTime;
      myGlobals.weDontWantToTalkWithYou[MAX_NUM_BAD_IP_ADDRESSES-1].count = 1;
    }
  }
#endif

    returnHTTPaccessForbidden();
    free(requestedURLCopy);
    return;
  }

  free(requestedURLCopy);

  /*
    Fix courtesy of
    Michael Wescott <wescott@crosstor.com>
  */
  if((requestedURL[0] != '\0') && (requestedURL[0] != '/')) {
    returnHTTPpageNotFound(NULL);
    return;
  }

  if(checkHTTPpassword(requestedURL, sizeof(requestedURL), pw, sizeof(pw) ) != 1) {
    returnHTTPaccessDenied();
   return;
  }

  myGlobals.actTime = time(NULL); /* Don't forget this */

/*
 *  Process Accept-Language  - load requestedLanguage[] from workLanguage
 */
#ifdef MAKE_WITH_I18N
  if(workLanguage != NULL) {
    char *tmpI18Nstr, *strtokState = NULL, *workSemi;
    tmpI18Nstr = strtok_r(workLanguage, ",", &strtokState);
    while(tmpI18Nstr != NULL) {
        /* Skip leading blanks */
        while (tmpI18Nstr[0] == ' ') tmpI18Nstr++;
        /* Stop at the ; */
        workSemi = strchr(tmpI18Nstr, ';');
        if(workSemi != NULL) {
            workSemi[0] = '\0';
        }
        requestedLanguage[numLang++] = i18n_xvert_acceptlanguage2common(tmpI18Nstr);
        if(numLang > MAX_LANGUAGES_REQUESTED) {
            tmpI18Nstr = NULL;
        } else {
            tmpI18Nstr = strtok_r(NULL, ",", &strtokState);
        }
    }
  }
#endif

  skipLeading = 0;
  while (requestedURL[skipLeading] == '/') {
    skipLeading++;
  }

  if(requestedURL[0] == '\0') {
#ifdef MAKE_WITH_I18N
    for (i=numLang; i>=0; i--) {
      free(requestedLanguage[i]);
    }
#endif
    returnHTTPpageNotFound(NULL);
  }

#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: handleHTTPrequest() accessMutex(purgeMutex)...calling");
#endif
  accessMutex(&myGlobals.purgeMutex, "returnHTTPPage");
#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: handleHTTPrequest() accessMutex(purgeMutex)...locked");
#endif

#if defined(MAKE_WITH_I18N) && defined(I18N_DEBUG)
  for (i=0; i<numLang; i++) {
      traceEvent(CONST_TRACE_INFO, "I18N_DEBUG: Requested Language [%d] = '%s'",
                 i,
                 requestedLanguage[i]);
  }
#endif

  rc = returnHTTPPage(&requestedURL[1], postLen,
		      &from, &httpRequestedAt, &usedFork,
                      agent,
                      referer,
                      requestedLanguage,
                      numLang, isPostMethod);

#ifdef MAKE_WITH_I18N
  for (i=numLang-1; i>=0; i--) {
      free(requestedLanguage[i]);
  }
#endif

#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: handleHTTPrequest() releaseMutex(purgeMutex)...calling");
#endif
  releaseMutex(&myGlobals.purgeMutex);
#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: handleHTTPrequest() releaseMutex(purgeMutex)...released");
#endif


  if(rc == 0) {
    myGlobals.numSuccessfulRequests[myGlobals.newSock > 0]++;

#ifdef MAKE_WITH_ZLIB
    if(compressFile)
      compressAndSendData(&gzipBytesSent);
    else
#endif
      gzipBytesSent = 0;

    if(!usedFork)
      logHTTPaccess(200, &httpRequestedAt, gzipBytesSent);

  } else if(rc == FLAG_HTTP_INVALID_PAGE) {
    returnHTTPpageNotFound(NULL);
  }
}

/* *******************************/

int readHTTPpostData(int len, char *buf, int buflen) {
  int rc, idx=0;

#ifdef HAVE_OPENSSL
  SSL* ssl = getSSLsocket(-myGlobals.newSock);
#endif

  memset(buf, 0, buflen);

  if(len > (buflen-8)) {
    BufferTooSmall(buf, buflen);
    return (-1);
  }

  while(len > 0) {
#ifdef HAVE_OPENSSL
    if(myGlobals.newSock < 0)
      rc = SSL_read(ssl, &buf[idx], len);
    else
      rc = recv(myGlobals.newSock, &buf[idx], len, 0);
#else
    rc = recv(myGlobals.newSock, &buf[idx], len, 0);
#endif
    if(rc < 0)
      return (-1);

    idx += rc;
    len -= rc;
  }

  buf[idx] = '\0';

  while(1) {
    fd_set mask;
    struct timeval wait_time;

    FD_ZERO(&mask);
    FD_SET((unsigned int)abs(myGlobals.newSock), &mask);

    /* select returns immediately */
    wait_time.tv_sec = 0, wait_time.tv_usec = 0;
    if(select(myGlobals.newSock+1, &mask, 0, 0, &wait_time) == 1) {
      char aChar[8]; /* just in case */

#ifdef HAVE_OPENSSL
      if(myGlobals.newSock < 0)
	rc = SSL_read(ssl, aChar, 1);
      else
	rc = recv(myGlobals.newSock, aChar, 1, 0);
#else
      rc = recv(myGlobals.newSock, aChar, 1, 0);
#endif
      if(rc <= 0)
	break;
    } else
      break;
  }

#if 0
  printf("HTTP POST data: '%s' (%d)\n", buf, idx);
  fflush(stdout);
#endif

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Data: '%s' (%d)", buf, idx);
#endif

  return (idx);
}
