/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 *			    http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "ntop.h"
#include "globals-report.h"

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
    { 401, "Unauthorized", "Unauthorized to access the document." },
    { 402, "Payment Required", NULL },
    { 403, "Forbidden", "Server refused to fulfill your request." },
    { 404, "Not Found", "The server cannot found the requested page." },
    { 405, "Method Not Allowed", NULL },
    { 406, "Not Acceptable", NULL },
    { 407, "Proxy Authentication Required", NULL },
    { 408, "Request Time-out", "The request was timed-out." },
    { 409, "Conflict", NULL },
    { 410, "Gone", NULL },
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
    { 505, "HTTP Version not supported", "This server don't support the specified HTTP version." },
};

/*
  Note: the numbers below are offsets inside the HTTPstatus table,
        they must be corrected every time the table is modified.
*/
#define HTTP_FLAG_STATUS_200	( 0<<8)
#define HTTP_FLAG_STATUS_302	(11<<8)
#define HTTP_FLAG_STATUS_400	(15<<8)
#define HTTP_FLAG_STATUS_401	(16<<8)
#define HTTP_FLAG_STATUS_403	(18<<8)
#define HTTP_FLAG_STATUS_404	(19<<8)
#define HTTP_FLAG_STATUS_408	(23<<8)
#define HTTP_FLAG_STATUS_501	(32<<8)
#define HTTP_FLAG_STATUS_505	(36<<8)

#define HTTP_INVALID_REQUEST	-2
#define HTTP_INVALID_METHOD	-3
#define HTTP_INVALID_VERSION	-4
#define HTTP_REQUEST_TIMEOUT	-5
#define HTTP_FORBIDDEN_PAGE	-6
#define HTTP_INVALID_PAGE	-7

/* ************************* */

static u_int httpBytesSent;
static char httpRequestedURL[512], theUser[32];
static struct in_addr *requestFrom;
static struct timeval httpRequestedAt;
static FILE *accessLogFd=NULL;

/* ************************* */

/* Forward */
static int readHTTPheader(char* theRequestedURL, int theRequestedURLLen, char *thePw, int thePwLen);
static int decodeString(char *bufcoded, unsigned char *bufplain, int outbufsize);
static void logHTTPaccess(int rc);
static void returnHTTPspecialStatusCode(int statusIdx);
static int checkURLsecurity(char *url);
static int returnHTTPPage(char* pageName, int postLen);
static int checkHTTPpassword(char *theRequestedURL, int theRequestedURLLen _UNUSED_, char* thePw, int thePwLen);

/* ************************* */

static int readHTTPheader(char* theRequestedURL, 
                          int theRequestedURLLen, 
                          char *thePw, int thePwLen) {
#ifdef HAVE_OPENSSL
  SSL* ssl = getSSLsocket(-newSock);
#endif
  char aChar[8] /* just in case */, lastChar;
  char preLastChar, lineStr[768];
  int rc, idxChar=0, contentLen=-1, numLine=0, topSock;
  fd_set mask;
  struct timeval wait_time;
  int errorCode=0;
  char *tmpStr;

  thePw[0] = '\0';
  preLastChar = '\r';
  lastChar = '\n';
  theRequestedURL[0] = '\0';
  memset(httpRequestedURL, 0, sizeof(httpRequestedURL));

#ifdef HAVE_OPENSSL
  topSock = abs(newSock);
#else
  topSock = newSock;
#endif

  for(;;) {

    FD_ZERO(&mask);
    FD_SET((unsigned int)topSock, &mask);

    /* printf("About to call select()\n"); fflush(stdout); */

    /* select returns immediately */
    wait_time.tv_sec = 10; wait_time.tv_usec = 0;
    if(select(newSock+1, &mask, 0, 0, &wait_time) == 0) {
      errorCode = HTTP_REQUEST_TIMEOUT; /* Timeout */
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Timeout while reading from socket.\n");
#endif
      break;
    }

    /* printf("About to call recv()\n"); fflush(stdout); */
    /* printf("Rcvd %d bytes\n", recv(newSock, aChar, 1, MSG_PEEK)); fflush(stdout); */

#ifdef HAVE_OPENSSL
    if(newSock < 0)
      rc = SSL_read(ssl, aChar, 1);
    else
      rc = recv(newSock, aChar, 1, 0);
#else
    rc = recv(newSock, aChar, 1, 0);
#endif

    if(rc != 1) {
      idxChar = 0;
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Socket read returned %d (errno=%d)\n", rc, errno);
#endif
      /* FIXME (DL): is valid to write to the socket after this condition? */
      break; /* Empty line */

    } else if ((errorCode == 0) && !isprint(aChar[0]) && !isspace(aChar[0])) {
      errorCode = HTTP_INVALID_REQUEST;
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Rcvd non expected char '%c' [%d/0x%x]\n", aChar[0], aChar[0], aChar[0]);
#endif

    } else {

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
#ifdef DEBUG
	traceEvent(TRACE_INFO, "read HTTP %s line: %s [%d]\n",
	           (numLine>1) ? "header" : "request", lineStr, idxChar);
#endif
	if(errorCode != 0) {
	  ;  /* skip parsing after an error was detected */
	} else if(numLine == 1) {
	  strncpy(httpRequestedURL, lineStr, 
		  sizeof(httpRequestedURL)-1)[sizeof(httpRequestedURL)-1] = '\0';

	  if(idxChar < 9) {
	    errorCode = HTTP_INVALID_REQUEST;
#ifdef DEBUG
	    traceEvent(TRACE_INFO, "Too short request line.\n");
#endif

	  } else if(strncmp(&lineStr[idxChar-9], " HTTP/", 6) != 0) {
	    errorCode = HTTP_INVALID_REQUEST;
#ifdef DEBUG
	    traceEvent(TRACE_INFO, "Malformed request line.\n");
#endif

	  } else if((strncmp(&lineStr[idxChar-3], "1.0", 3) != 0) &&
	            (strncmp(&lineStr[idxChar-3], "1.1", 3) != 0)) {
	    errorCode = HTTP_INVALID_VERSION;
#ifdef DEBUG
	    traceEvent(TRACE_INFO, "Unsupported HTTP version.\n");
#endif

	  } else {

            lineStr[idxChar-9] = '\0'; idxChar -= 9; tmpStr = NULL;

	    if       ((idxChar >= 3) && (strncmp(lineStr, "GET ", 4) == 0)) {
	      tmpStr = &lineStr[4];
	    } else if((idxChar >= 4) && (strncmp(lineStr, "POST ", 5) == 0)) {
	      tmpStr = &lineStr[5];
/*
  HEAD method could be supported with some litle modifications...
  } else if((idxChar >= 4) && (strncmp(lineStr, "HEAD ", 5) == 0)) {
  tmpStr = &lineStr[5];
*/
	    } else {
	      errorCode = HTTP_INVALID_METHOD;
#ifdef DEBUG
	      traceEvent(TRACE_INFO, "Unrecognized method in request line.\n");
#endif
	    }

	    if(tmpStr)
	      strncpy(theRequestedURL, tmpStr, 
		      theRequestedURLLen-1)[theRequestedURLLen-1] = '\0';
	  }

	} else if((idxChar >= 21) 
		  && (strncasecmp(lineStr, "Authorization: Basic ", 21) == 0)) {
	  strncpy(thePw, &lineStr[21], thePwLen-1)[thePwLen-1] = '\0';
	} else if((idxChar >= 16) 
		  && (strncasecmp(lineStr, "Content-Length: ", 16) == 0)) {
	  contentLen = atoi(&lineStr[16]);
#ifdef DEBUG
	  traceEvent(TRACE_INFO, "len=%d [%s/%s]\n", contentLen, lineStr, &lineStr[16]); 
#endif
	}
	idxChar=0;
      } else if(idxChar > sizeof(lineStr)-2) {
	if (errorCode == 0) {
	  errorCode = HTTP_INVALID_REQUEST; 
#ifdef DEBUG
	  traceEvent(TRACE_INFO, "Line too long (hackers ?)");
#endif
	}
      } else {
	lineStr[idxChar++] = aChar[0];
      }

    }
    lastChar = aChar[0];
  }

  return((errorCode) ? errorCode : contentLen);
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
#if 0
    pr2six['A']= 0; pr2six['B']= 1; pr2six['C']= 2; pr2six['D']= 3;
    pr2six['E']= 4; pr2six['F']= 5; pr2six['G']= 6; pr2six['H']= 7;
    pr2six['I']= 8; pr2six['J']= 9; pr2six['K']=10; pr2six['L']=11;
    pr2six['M']=12; pr2six['N']=13; pr2six['O']=14; pr2six['P']=15;
    pr2six['Q']=16; pr2six['R']=17; pr2six['S']=18; pr2six['T']=19;
    pr2six['U']=20; pr2six['V']=21; pr2six['W']=22; pr2six['X']=23;
    pr2six['Y']=24; pr2six['Z']=25; pr2six['a']=26; pr2six['b']=27;
    pr2six['c']=28; pr2six['d']=29; pr2six['e']=30; pr2six['f']=31;
    pr2six['g']=32; pr2six['h']=33; pr2six['i']=34; pr2six['j']=35;
    pr2six['k']=36; pr2six['l']=37; pr2six['m']=38; pr2six['n']=39;
    pr2six['o']=40; pr2six['p']=41; pr2six['q']=42; pr2six['r']=43;
    pr2six['s']=44; pr2six['t']=45; pr2six['u']=46; pr2six['v']=47;
    pr2six['w']=48; pr2six['x']=49; pr2six['y']=50; pr2six['z']=51;
    pr2six['0']=52; pr2six['1']=53; pr2six['2']=54; pr2six['3']=55;
    pr2six['4']=56; pr2six['5']=57; pr2six['6']=58; pr2six['7']=59;
    pr2six['8']=60; pr2six['9']=61; pr2six['+']=62; pr2six['/']=63;
#endif
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

void sendStringLen(char *theString, unsigned int len) {
  int bytesSent, rc, retries = 0;
  static char buffer[2*BUF_SIZE];

  if(newSock == DUMMY_SOCKET_VALUE)
    return;

  httpBytesSent += len;

  /* traceEvent(TRACE_INFO, "%s", theString);  */
  if(len == 0)
    return; /* Nothing to send */
  else
    memcpy(buffer, theString, (size_t) ((len > sizeof(buffer)) ? sizeof(buffer) : len));

  bytesSent = 0;

  while(len > 0) {
  RESEND:
    errno=0;

#ifdef HAVE_OPENSSL
    if(newSock < 0) {
      rc = SSL_write(getSSLsocket(-newSock), &buffer[bytesSent], len);
    } else
      rc = send(newSock, &buffer[bytesSent], (size_t)len, 0);
#else
    rc = send(newSock, &buffer[bytesSent], (size_t)len, 0);
#endif

    /* traceEvent(TRACE_INFO, "rc=%d\n", rc); */

    if((errno != 0) || (rc < 0)) {
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Socket write returned %d (errno=%d)\n", rc, errno);
#endif
      if((errno == EAGAIN /* Resource temporarily unavailable */) && (retries<3)) {
	len -= rc;
	bytesSent += rc;
	retries++;
	goto RESEND;
      } else if (errno == EPIPE /* Broken pipe: the  client has disconnected */) {
	  closeNwSocket(&newSock);
	  return;
	} else if (errno == EBADF /* Bad file descriptor: a
				     disconnected client is still sending */) {
	  closeNwSocket(&newSock);
	  return;
	} else {
	  closeNwSocket(&newSock);
	  return;
	}
    } else {
      len -= rc;
      bytesSent += rc;
    }
  }
}

/* ************************* */

void sendString(char *theString) {
  sendStringLen(theString, strlen(theString));
}

/* ************************* */

void printHTMLheader(char *title, int  headerFlags) {
  char buf[BUF_SIZE];

  sendString("<HTML>\n<HEAD>\n");

  /*
  if(title != NULL) {
    if(snprintf(buf, BUF_SIZE, "<TITLE>%s</TITLE>\n", title) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }
  */

  if((headerFlags & HTML_FLAG_NO_REFRESH) == 0) {
    if(snprintf(buf, BUF_SIZE, "<META HTTP-EQUIV=REFRESH CONTENT=%d>\n", refreshRate) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }
  sendString("<META HTTP-EQUIV=Pragma CONTENT=no-cache>\n");
  sendString("<META HTTP-EQUIV=Cache-Control CONTENT=no-cache>\n");
  if((headerFlags & HTML_FLAG_NO_STYLESHEET) == 0) {
    sendString("<LINK REL=stylesheet HREF=/style.css type=\"text/css\">\n");
  }
  sendString("</HEAD>\n");
  if((headerFlags & HTML_FLAG_NO_BODY) == 0) {
    sendString("<BODY BACKGROUND=/white_bg.gif BGCOLOR=\"#FFFFFF\" LINK=blue VLINK=blue>\n");
    if((title != NULL) && ((headerFlags & HTML_FLAG_NO_HEADING) == 0))
      printSectionTitle(title);
  }
}

/* ************************* */

void printHTMLtrailer(void) {
  char buf[BUF_SIZE];
  int i, len;

  sendString("\n<P><HR>\n<FONT FACE=\"Helvetica, Arial, Sans Serif\" SIZE=-1><B>\n");

  if(snprintf(buf, BUF_SIZE, "Report created on %s [%s]<br>\n", 
	  ctime(&actTime), formatSeconds(actTime-initialSniffTime)) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, BUF_SIZE, "Generated by <A HREF=\"http://www.ntop.org/\">ntop</A> v.%s %s \n[%s] (%s build) ",
	  version, THREAD_MODE, osName, buildDate) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(rFileName != NULL) {
    if(snprintf(buf, BUF_SIZE, "listening on [%s]\n", PCAP_NW_INTERFACE) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  } else {
    int numRealDevices;
    
    for(i=len=numRealDevices=0; i<numDevices; i++, len=strlen(buf)) {      
      if(!device[i].virtualDevice) {
	if(snprintf(&buf[len], BUF_SIZE-len, "%s%s", 
		    (numRealDevices>0) ? "," : "listening on [", device[i].name) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	numRealDevices++;
      }
    }

    if(snprintf(&buf[len], BUF_SIZE-len, "]\n") < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  }

  sendString(buf);

  sendString("<BR>\n&copy; 1998-2001 by <A HREF=mailto:deri@ntop.org>L. Deri</A>\n");
  sendString("</B></FONT>\n</BODY>\n</HTML>\n");
}

/* ******************************* */

void initAccessLog(void) {
  accessLogFd = fopen(accessLogPath, "a");
  if(accessLogFd == NULL) {
    traceEvent(TRACE_ERROR, "Unable to create file %s. Access log is disabled.", 
	       accessLogPath);
  }
}

/* ******************************* */

void termAccessLog(void) {   
  if(accessLogFd != NULL)
    fclose(accessLogFd);
}

/* ************************* */

static void logHTTPaccess(int rc) {
 char theDate[48], myUser[64], buf[24];
 struct timeval loggingAt;
 unsigned long msSpent;
 struct tm t;
 char theZone[6];
 unsigned long gmtoffset;

 if(accessLogFd != NULL) {
   gettimeofday(&loggingAt, NULL);

   msSpent = (unsigned long)(delta_time(&loggingAt, &httpRequestedAt)/1000);
 
   strftime(theDate, sizeof(theDate), "%d/%b/%Y:%H:%M:%S", localtime_r(&actTime, &t));

   gmtoffset =  (thisZone < 0) ? -thisZone : thisZone;
   if(snprintf(theZone, sizeof(theZone), "%c%2.2ld%2.2ld", (thisZone < 0) ? '-' : '+', gmtoffset/3600, (gmtoffset/60)%60) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");

   if((theUser == NULL)
      || (theUser[0] == '\0'))
     strncpy(myUser, " ", 64);
   else {
     if(snprintf(myUser, sizeof(myUser), " %s ", theUser) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
   }

   NTOHL(requestFrom->s_addr);
 
   fprintf(accessLogFd, "%s -%s- [%s %s] - \"%s\" %d %d %lu\n", 
	   _intoa(*requestFrom, buf, sizeof(buf)),
	   myUser, theDate, theZone,
	   httpRequestedURL, rc, httpBytesSent,
	   msSpent);
   fflush(accessLogFd);
 }
}

#if 0 /* this is not used anymore */
/* ************************* */

static void returnHTTPaccessDenied(void) {
  sendString("HTTP/1.0 401 Unauthorized to access the document\n");
  sendString("WWW-Authenticate: Basic realm=\"ntop HTTP server [default user=admin,pw=admin];\"\n");
  sendString("Connection: close\n");
  sendString("Content-Type: text/html\n\n");
  sendString("<HTML>\n<TITLE>Error</TITLE>\n<BODY BACKGROUND=/white_bg.gif>\n"
	     "<H1>Error 401</H1>\nUnauthorized to access the document\n</BODY>\n</HTML>\n");
  logHTTPaccess(401);
}

/* ************************* */

static void returnHTTPaccessForbidden(void) {
  sendString("HTTP/1.0 403 Forbidded\n");
  sendString("Connection: close\n");
  sendString("Content-Type: text/html\n\n");
  sendString("<HTML>\n<TITLE>Error</TITLE>\n<BODY BACKGROUND=/white_bg.gif>\n"
	     "<H1>Error 401</H1>\nServer refused to fulfill your request.\n</BODY>\n</HTML>\n");
  logHTTPaccess(403);
}
#endif

/* ************************* */

static void returnHTTPbadRequest(void) {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_400);
}

static void returnHTTPaccessDenied(void) {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_401 | HTTP_FLAG_NEED_AUTHENTICATION);
}

static void returnHTTPaccessForbidden(void) {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_403);
}

static void returnHTTPpageNotFound(void) {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_404);
}

static void returnHTTPrequestTimedOut(void) {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_408);
}

static void returnHTTPnotImplemented(void) {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_501);
}

static void returnHTTPversionNotSupported(void) {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_505);
}

/* ************************* */

static void returnHTTPspecialStatusCode(int statusFlag) {
  int statusIdx;
  char buf[BUF_SIZE];

  statusIdx = (statusFlag >> 8) & 0xff;
  if((statusIdx < 0) || (statusIdx > sizeof(HTTPstatus)/sizeof(HTTPstatus[0]))) {
    statusIdx = 0;
    statusFlag = 0;
#ifdef DEBUG
    traceEvent(TRACE_WARNING, "INTERNAL ERROR: invalid HTTP status id (%d) set to zero.\n", statusIdx);
#endif
  }

  sendHTTPHeader(HTTP_TYPE_HTML, statusFlag);
  if(snprintf(buf, sizeof(buf), "Error %d", HTTPstatus[statusIdx].statusCode) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  printHTMLheader(buf, HTML_FLAG_NO_REFRESH | HTML_FLAG_NO_HEADING);
  if(snprintf(buf, sizeof(buf),
	   "<H1>Error %d</H1>\n%s\n",
	   HTTPstatus[statusIdx].statusCode, HTTPstatus[statusIdx].longDescription) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  if(strlen(httpRequestedURL) > 0) {
    if(snprintf(buf, sizeof(buf),
	     "<P>Received request:<BR><BLOCKQUOTE><TT>&quot;%s&quot;</TT></BLOCKQUOTE>",
	     httpRequestedURL) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }
  printHTMLtrailer();

  logHTTPaccess(HTTPstatus[statusIdx].statusCode);
}

/* *******************************/

void returnHTTPredirect(char* destination) {
  sendHTTPHeader(HTTP_TYPE_HTML,
		 HTTP_FLAG_STATUS_302 | HTTP_FLAG_NO_CACHE_CONTROL | HTTP_FLAG_MORE_FIELDS);
  sendString("Location: /");
  sendString(destination);
  sendString("\n\n");
}

#if 0 /* this is not used anymore */
/* ************************* */

void sendHTTPHeaderType(void) {
  sendString("Content-type: text/html\n");
  sendString("Cache-Control: no-cache\n");
  sendString("Expires: 0\n\n");
}

/* ************************* */

void sendGIFHeaderType(void) {
  sendString("Content-type: image/gif\n");
  sendString("Cache-Control: no-cache\n");
  sendString("Expires: 0\n\n");
}

/* ************************* */

void sendHTTPProtoHeader(void) {
  char tmpStr[64];

  sendString("HTTP/1.0 200 OK\n");
  if(snprintf(tmpStr, sizeof(tmpStr), "Server: ntop/%s (%s)\n", version, osName) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(tmpStr);
}
#endif

/* ************************* */

void sendHTTPHeader(int mimeType, int headerFlags) {
  int statusIdx;
  char tmpStr[64], theDate[48];
  time_t  theTime = actTime - (time_t)thisZone;
  struct tm t;

  statusIdx = (headerFlags >> 8) & 0xff;
  if((statusIdx < 0) || (statusIdx > sizeof(HTTPstatus)/sizeof(HTTPstatus[0]))){
    statusIdx = 0;
#ifdef DEBUG
    traceEvent(TRACE_WARNING, "INTERNAL ERROR: invalid HTTP status id (%d) set to zero.\n", 
	       statusIdx);
#endif
  }
  if(snprintf(tmpStr, sizeof(tmpStr), "HTTP/1.0 %d %s\n",
                   HTTPstatus[statusIdx].statusCode, HTTPstatus[statusIdx].reasonPhrase) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(tmpStr);

  strftime(theDate, sizeof(theDate)-1, "%a, %d %b %Y %H:%M:%S GMT", localtime_r(&theTime, &t));
  theDate[sizeof(theDate)-1] = '\0';
  if(snprintf(tmpStr, sizeof(tmpStr), "Date: %s\n", theDate) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(tmpStr);

  if(headerFlags & HTTP_FLAG_IS_CACHEABLE) {
    sendString("Cache-Control: max-age=3600, must-revalidate, public\n");
  } else if((headerFlags & HTTP_FLAG_NO_CACHE_CONTROL) == 0) {
    sendString("Cache-Control: no-cache\n");
  }

  if((headerFlags & HTTP_FLAG_KEEP_OPEN) == 0) {
    sendString("Connection: close\n");
  }

  if(snprintf(tmpStr, sizeof(tmpStr), "Server: ntop/%s (%s)\n", version, osName) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(tmpStr);

  if(headerFlags & HTTP_FLAG_NEED_AUTHENTICATION) {
    sendString("WWW-Authenticate: Basic realm=\"ntop HTTP server [default user=admin,pw=admin];\"\n");
  }

  switch(mimeType) {
    case HTTP_TYPE_HTML:
      sendString("Content-Type: text/html\n");
      break;
    case HTTP_TYPE_GIF:
      sendString("Content-Type: image/gif\n");
      break;
    case HTTP_TYPE_JPEG:
      sendString("Content-Type: image/jpeg\n");
      break;
    case HTTP_TYPE_PNG:
      sendString("Content-Type: image/png\n");
      break;
    case HTTP_TYPE_CSS:
      sendString("Content-Type: text/css\n");
      break;
    case HTTP_TYPE_TEXT:
      sendString("Content-Type: text/plain\n");
      break;
    case HTTP_TYPE_NONE:
      break;
#ifdef DEBUG
    default:
      traceEvent(TRACE_INFO, "INTERNAL ERROR: invalid MIME type code requested (%d)\n", mimeType);
#endif
  }

  if((headerFlags & HTTP_FLAG_NO_CACHE_CONTROL) == 0) {
    sendString("Expires: 0\n");
  }

  if((headerFlags & HTTP_FLAG_MORE_FIELDS) == 0) {
    sendString("\n");
  }
}

/* ************************* */

static int checkURLsecurity(char *url) {
  int rc = 0, i, len=strlen(url);

  for(i=1; i<len; i++)
    if((url[i] == '.') && (url[i-1] == '.')) {
      rc = 1;
      break;
    } else if((url[i] == '/') && (url[i-1] == '/')) {
      rc = 1;
      break;
    } else if((url[i] == '.') && (url[i-1] == '/')) {
      rc = 1;
      break;
    }

  return(rc);
}

/* ************************* */

static int returnHTTPPage(char* pageName, int postLen) {
  char *questionMark = strchr(pageName, '?');
  int sortedColumn, printTrailer=1, idx;
  int errorCode=0;
  struct stat statbuf;
  FILE *fd = NULL;
  char tmpStr[512];
  int revertOrder=0;
#ifdef WIN32
  int i;
#endif

  /* We need to check whether the URL
     is invalid, i.e. it contains '..' or
     similar chars that can be used to read
     system files
  */
  if(checkURLsecurity(pageName) != 0)
    return (HTTP_FORBIDDEN_PAGE);

  /* traceEvent(TRACE_INFO, "Page: '%s'\n", pageName); */

  /* Fix below courtesy of Robert Shih <robert.shih@nomura.co.uk> */
  if((questionMark == NULL)      
     || ((questionMark[0] == '?') 
	 && (((!isdigit(questionMark[1]))  && (questionMark[1] != '-'))
	     || ((!isdigit(questionMark[2])) && (questionMark[2] != '\0')))))
    sortedColumn = 0;
  else {
    if((questionMark[0] == '?') && (strlen(questionMark) > 3)) {
      questionMark[0] = '\0';
      /* questionMark = strchr(&questionMark[1], '='); */
      idx = atoi(&questionMark[1]);
      if(idx < 0) revertOrder=1;
      sortedColumn = abs(idx);
    } else {
      sortedColumn = abs(atoi(&questionMark[1]));

      if(questionMark[1] == '-')
	revertOrder=1;
    }
  }

  /*
    traceEvent(TRACE_INFO, "sortedColumn: %d - revertOrder: %d\n", 
    sortedColumn, revertOrder);
  */

  if(pageName[0] == '\0')
    strncpy(pageName, STR_INDEX_HTML, sizeof(STR_INDEX_HTML));

  /* Search in the local directory first... */
  for(idx=0; dataFileDirs[idx] != NULL; idx++) {
    if(snprintf(tmpStr, sizeof(tmpStr), "%s/html/%s", dataFileDirs[idx], pageName) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");

#ifdef WIN32
    i=0;
    while(tmpStr[i] != '\0') {
      if(tmpStr[i] == '/') tmpStr[i] = '\\';
      i++;
    }
#endif

    if(stat(tmpStr, &statbuf) == 0) {
      if((fd = fopen(tmpStr, "rb")) != NULL)
        break;
      traceEvent(TRACE_ERROR, "Cannot open file '%s', ignored...\n", tmpStr);
    }
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "tmpStr=%s - fd=0x%x\n", tmpStr, fd);
#endif

  if(fd != NULL) {
    char theDate[48];
    time_t theTime;
    struct tm t;
    int len = strlen(pageName), mimeType = HTTP_TYPE_HTML;

    if(len > 4) {
      if(strcmp(&pageName[len-4], ".gif") == 0)
        mimeType = HTTP_TYPE_GIF;
      else if(strcmp(&pageName[len-4], ".jpg") == 0)
        mimeType = HTTP_TYPE_JPEG;
      else if(strcmp(&pageName[len-4], ".png") == 0)
        mimeType = HTTP_TYPE_PNG;
      else if(strcmp(&pageName[len-4], ".css") == 0)
        mimeType = HTTP_TYPE_CSS;
    }

    sendHTTPHeader(mimeType, HTTP_FLAG_IS_CACHEABLE | HTTP_FLAG_MORE_FIELDS);

    if (actTime > statbuf.st_mtime) { /* just in case the system clock is wrong... */
        theTime = statbuf.st_mtime - thisZone;
        strftime(theDate, sizeof(theDate)-1, "%a, %d %b %Y %H:%M:%S GMT", localtime_r(&theTime, &t));
        theDate[sizeof(theDate)-1] = '\0';
        if(snprintf(tmpStr, sizeof(tmpStr), "Last-Modified: %s\n", theDate) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
        sendString(tmpStr);
    }

    fseek(fd, 0, SEEK_END);
    if(snprintf(tmpStr, sizeof(tmpStr), "Content-Length: %d\n", (len = ftell(fd))) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    fseek(fd, 0, SEEK_SET);
    sendString(tmpStr);

    sendString("\n");	/* mark the end of HTTP header */

    for(;;) {
      len = fread(tmpStr, sizeof(char), 255, fd);
      if(len <= 0) break;
      sendStringLen(tmpStr, len);
    }

    fclose(fd);
    /* closeNwSocket(&newSock); */
    return (0);
  }

#ifndef WIN32
#ifdef  USE_CGI
  if(strncmp(pageName, CGI_HEADER, strlen(CGI_HEADER)) == 0) {
    execCGI(&pageName[strlen(CGI_HEADER)]);
    return (0);
  }
#endif /* USE_CGI */
#endif

  if(strncmp(pageName, PLUGINS_HEADER, strlen(PLUGINS_HEADER)) == 0) {
    if(handlePluginHTTPRequest(&pageName[strlen(PLUGINS_HEADER)])) {
      return (0);
    } else {
      return (HTTP_INVALID_PAGE);
    }
  }

  /*
    Putting this here (and not on top of this function)
    helps because at least a partial respose
    has been send back to the user in the meantime
  */
#ifdef MULTITHREADED
  accessMutex(&hashResizeMutex, "returnHTTPpage"); 
#endif

#ifndef MICRO_NTOP
  if(strcmp(pageName, STR_INDEX_HTML) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHTMLheader("Welcome to ntop!", HTML_FLAG_NO_REFRESH | HTML_FLAG_NO_BODY);
    sendString("<frameset cols=160,* framespacing=0 border=0 frameborder=0>\n");
    sendString("    <frame src=leftmenu.html name=Menu marginwidth=0 marginheight=0>\n");
    sendString("    <frame src=home.html name=area marginwidth=5 marginheight=0>\n");
    sendString("    <noframes>\n");
    sendString("    <body>\n\n");
    sendString("    </body>\n");
    sendString("    </noframes>\n");
    sendString("</frameset>\n");
    sendString("</html>\n");
    printTrailer=0;
  } else if((strcmp(pageName, "leftmenu.html") == 0)
	    || (strcmp(pageName, "leftmenu-nojs.html") == 0)) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHTMLheader(NULL, HTML_FLAG_NO_REFRESH);
    sendString(
	       "<center>\n<pre>\n\n</pre>\n\n");
    sendString("<FONT FACE=Helvetica SIZE=+2>Welcome<br>to<br>\n");
    sendString("ntop!</FONT>\n<pre>\n</pre>\n");
    sendString("<p></center><p>\n<FONT FACE=Helvetica SIZE=-1><b>\n<ol>\n");
    sendString("<li><a href=home.html target=area>What's ntop?</a></li>\n");
    sendString("<li>Data Rcvd<ul>");
    sendString("<li><a href="STR_SORT_DATA_RECEIVED_PROTOS" target=area "
	       "ALT=\"Data Received (all protocols)\">All Protoc.</a></li>\n");
    sendString("<li><a href="STR_SORT_DATA_RECEIVED_IP" target=area "
	       "ALT=\"IP Data Received\">IP</a></li>\n");
    sendString("<li><a href="STR_SORT_DATA_RECEIVED_THPT" target=area "
	       "ALT=\"Data Received Throughput\">Thpt</a></li></ul></li>\n");
    sendString("<li><a href="STR_SORT_DATA_RCVD_HOST_TRAFFIC" target=area "
	       "ALT=\"Data Received Host Traffic\">Traffic</a></li></ul></li>\n");

    sendString("<li>Data Sent<ul>");
    sendString("<li><a href="STR_SORT_DATA_SENT_PROTOS" target=area "
	       "ALT=\"Data Sent (all protocols)\">All Protoc.</a></li>\n");
    sendString("<li><a href="STR_SORT_DATA_SENT_IP" target=area "
	       "ALT=\"IP Data Sent\">IP</a></li>\n");
    sendString("<li><a href="STR_SORT_DATA_SENT_THPT" target=area "
	       "ALT=\"Data Sent Throughput\">Thpt</a></li></ul></li>\n");
    sendString("<li><a href="STR_SORT_DATA_SENT_HOST_TRAFFIC" target=area "
	       "ALT=\"Data Sent Host Traffic\">Traffic</a></li></ul></li>\n");

    sendString("<li><a href="STR_MULTICAST_STATS" target=area ALT=\"Multicast Stats\">"
	       "Multicast Stats</a></li>\n");
    sendString("<li><a href=trafficStats.html target=area ALT=\"Traffic Statistics\">"
	       "Traffic Stats</a></li>\n");
    sendString("<li><a href="STR_DOMAIN_STATS" target=area ALT=\"Domain Traffic Statistics\">"
	       "Domain Stats</a></li>\n");
    sendString("<li><a href=localRoutersList.html target=area ALT=\"Routers List\">"
	       "Routers</a></li>\n");
    sendString("<li><a href="STR_SHOW_PLUGINS" target=area ALT=\"Plugins List\">"
	       "Plugins</a></li>\n");
    sendString("<li><a href="STR_SORT_DATA_THPT_STATS" target=area ALT=\"Throughput Statistics\">"
	       "Thpt Stats</a></li>\n");
    sendString("<li><a href="HOSTS_INFO_HTML" target=area ALT=\"Hosts Information\">"
	       "Hosts Info</a></li>\n");
    sendString("<li><a href="IP_R_2_L_HTML" target=area ALT=\"Remote to Local IP Traffic\">"
	       "R-&gt;L IP Traffic</a></li>\n");
    sendString("<li><a href="IP_L_2_R_HTML" target=area ALT=\"Local to Remote IP Traffic\">"
	       "L-&gt;R IP Traffic</a></li>\n");
    sendString("<li><a href="IP_L_2_L_HTML" target=area ALT=\"Local IP Traffic\">"
	       "L&lt;-&gt;L IP Traffic</a></li>\n");
    sendString("<li><a href=NetNetstat.html target=area ALT=\"Active TCP Sessions\">"
	       "Active TCP Sessions</a></li>\n");
    sendString("<li><a href=ipProtoDistrib.html target=area ALT=\"IP Protocol Distribution\">"
	       "IP Protocol Distribution</a></li>\n");
    sendString("<li><a href=ipProtoUsage.html target=area ALT=\"IP Protocol Subnet Usage\">"
	       "IP Protocol Usage</a></li>\n");
    sendString("<li><a href=ipTrafficMatrix.html target=area ALT=\"IP Traffic Matrix\">"
	       "IP Traffic Matrix</a></li>\n");
    sendString("<li><a href="NW_EVENTS_HTML" target=area ALT=\"Network Events\">"
	       "Network Events</a></li>\n");
    if(isLsofPresent)
      sendString("<li><a href="STR_LSOF_DATA" target=area "
		 "ALT=\"Local Processes Nw Usage\">Local Nw Usage</a></li>\n");

    if(flowsList != NULL)
      sendString("<li><a href=NetFlows.html target=area ALT=\"NetFlows\">"
		 "NetFlows List</a></li>\n");

#ifdef HAVE_GDBM_H
    sendString("<li><a href=showUsers.html target=area ALT=\"Admin Users\">Admin Users</a></li>\n");
    sendString("<li><a href=showURLs.html target=area ALT=\"Admin URLs\">Admin URLs</a></li>\n");
#endif

    if(!mergeInterfaces)
      sendString("<li><a href="SWITCH_NIC_HTML" target=area ALT=\"Switch NICs\">Switch NICs</a></li>\n");

    sendString("<li><a href="SHUTDOWN_NTOP_HTML" target=area ALT=\"Shutdown ntop\">"
	       "Shutdown ntop</a></li>\n");
    sendString("<li><a href=ntop.html target=area ALT=\"Man Page\">Man Page</a></li>\n");
    sendString("<li><a href=Credits.html target=area ALT=\"Credits\">Credits</a></li>\n");
    sendString("</ol>\n<center>\n<b>\n\n");
    sendString("<pre>\n</pre>&copy; 1998-2001<br>by<br>"
	       "<A HREF=\"http://luca.ntop.org/\" target=\"area\">"
	       "Luca Deri</A></FONT><pre>\n");
    sendString("</pre>\n</b>\n</center>\n</body>\n</html>\n");
    printTrailer=0;
  } else if(strncmp(pageName, SWITCH_NIC_HTML, strlen(SWITCH_NIC_HTML)) == 0) {
    char *equal = strchr(pageName, '=');
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    
    if(equal == NULL)
      switchNwInterface(0);
    else
      switchNwInterface(atoi(&equal[1]));
  } else if(strcmp(pageName, "home.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHTMLheader("Welcome to ntop!", HTML_FLAG_NO_REFRESH);
    sendString("<FONT FACE=Helvetica>\n<HR>\n");
    sendString("<b>ntop</b> shows the current network usage. It displays a list of hosts that are\n");
    sendString("currently using the network and reports information concerning the IP\n");
    sendString("(Internet Protocol) traffic generated by each host. The traffic is \n");
    sendString("sorted according to host and protocol. Protocols (user configurable) include:\n");
    sendString("<ul><li>TCP/UDP/ICMP<li>(R)ARP<li>IPX<li>DLC<li>"
	       "Decnet<li>AppleTalk<li>Netbios<li>IP<ul><li>FTP<li>"
	       "HTTP<li>DNS<li>Telnet<li>SMTP/POP/IMAP<li>SNMP<li>\n");
    sendString("NFS<li>X11</ul></UL>\n<p>\n");
    sendString("<b>ntop</b>'s author strongly believes in <A HREF=http://www.opensource.org/>\n");
    sendString("open source software</A> and encourages everyone to modify, improve\n ");
    sendString("and extend <b>ntop</b> in the interest of the whole Internet community according\n");
    sendString("to the enclosed licence (see COPYING).<p>Problems, bugs, questions, ");
    sendString("desirable enhancements, source code contributions, etc., should be sent to the ");
    sendString("<A HREF=mailto:ntop@ntop.org> mailing list</A>.\n</font>");
  } else if(strncmp(pageName, STR_SORT_DATA_RECEIVED_PROTOS, 
		    strlen(STR_SORT_DATA_RECEIVED_PROTOS)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHostsTraffic(0, 0, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_RECEIVED_IP, strlen(STR_SORT_DATA_RECEIVED_IP)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHostsTraffic(0, 1, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_THPT_STATS, strlen(STR_SORT_DATA_THPT_STATS)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printThptStats(sortedColumn);
  } else if(strncmp(pageName, STR_THPT_STATS_MATRIX, strlen(STR_THPT_STATS_MATRIX)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printThptStatsMatrix(sortedColumn);
  } else if(strncmp(pageName, STR_SORT_DATA_RECEIVED_THPT, strlen(STR_SORT_DATA_RECEIVED_THPT)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    if(sortedColumn == 0) { sortedColumn = HOST_DUMMY_IDX_VALUE; }
    printHostsTraffic(0, 2, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_RCVD_HOST_TRAFFIC, strlen(STR_SORT_DATA_RCVD_HOST_TRAFFIC)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    if(sortedColumn == 0) { sortedColumn = HOST_DUMMY_IDX_VALUE; }
    printHostsTraffic(0, 3, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_SENT_HOST_TRAFFIC, strlen(STR_SORT_DATA_SENT_HOST_TRAFFIC)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    if(sortedColumn == 0) { sortedColumn = HOST_DUMMY_IDX_VALUE; }
    printHostsTraffic(1, 3, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_SENT_PROTOS, strlen(STR_SORT_DATA_SENT_PROTOS)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHostsTraffic(1, 0, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_SENT_IP, strlen(STR_SORT_DATA_SENT_IP)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHostsTraffic(1, 1, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_SENT_THPT, strlen(STR_SORT_DATA_SENT_THPT)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    if(sortedColumn == 0) { sortedColumn = HOST_DUMMY_IDX_VALUE; }
    printHostsTraffic(1, 2, sortedColumn, revertOrder);
  } else if(strncmp(pageName, HOSTS_INFO_HTML, strlen(HOSTS_INFO_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHostsInfo(sortedColumn, revertOrder);
  }
  else if(isLsofPresent
	  && (strncmp(pageName, PROCESS_INFO_HTML, strlen(PROCESS_INFO_HTML)) == 0)) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printProcessInfo(sortedColumn /* process PID */);
  } else if(isLsofPresent
	    && (strncmp(pageName, STR_LSOF_DATA, strlen(STR_LSOF_DATA)) == 0)) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printLsofData(sortedColumn);
  }
  else if(strcmp(pageName, "NetFlows.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    listNetFlows();
  }
  else if(strncmp(pageName, IP_R_2_L_HTML, strlen(IP_R_2_L_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    if(sortedColumn == 0) { sortedColumn = 1; }
    printIpAccounting(REMOTE_TO_LOCAL_ACCOUNTING, sortedColumn, revertOrder);
  } else if(strncmp(pageName, IP_L_2_R_HTML, strlen(IP_L_2_R_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    if(sortedColumn == 0) { sortedColumn = 1; }
    printIpAccounting(LOCAL_TO_REMOTE_ACCOUNTING, sortedColumn, revertOrder);
  } else if(strncmp(pageName, IP_L_2_L_HTML, strlen(IP_L_2_L_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    if(sortedColumn == 0) { sortedColumn = 1; }
    printIpAccounting(LOCAL_TO_LOCAL_ACCOUNTING, sortedColumn, revertOrder);
  } else if(strcmp(pageName, "NetNetstat.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printActiveTCPSessions();
  } else if(strncmp(pageName, SHUTDOWN_NTOP_HTML, strlen(SHUTDOWN_NTOP_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    shutdownNtop();
  } else if(strncmp(pageName, RESET_STATS_HTML, strlen(RESET_STATS_HTML)) == 0) {
    /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHTMLheader("All statistics are now reseted", HTML_FLAG_NO_REFRESH);
    resetStats();
  } else if(strncmp(pageName, STR_MULTICAST_STATS, strlen(STR_MULTICAST_STATS)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printMulticastStats(sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_DOMAIN_STATS, strlen(STR_DOMAIN_STATS)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printDomainStats(NULL, abs(sortedColumn), revertOrder);
  } else if(strncmp(pageName, STR_SHOW_PLUGINS, strlen(STR_SHOW_PLUGINS)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    if(questionMark == NULL)
      showPluginsList("");
    else
      showPluginsList(&pageName[strlen(STR_SHOW_PLUGINS)+1]);
  } else if(strncmp(pageName, DOMAIN_INFO_HTML, strlen(DOMAIN_INFO_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    if(questionMark == NULL) questionMark = "";
    pageName[strlen(pageName)-5-strlen(questionMark)] = '\0';
    printDomainStats(&pageName[strlen(DOMAIN_INFO_HTML)+1], abs(sortedColumn), revertOrder);
  } else if(strcmp(pageName, TRAFFIC_STATS_HTML) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHostsTraffic(2, 0, 0, revertOrder);
    printProtoTraffic();
    sendString("<p>\n");
    printIpProtocolDistribution(LONG_FORMAT, revertOrder);
  } else if(strcmp(pageName, "ipProtoDistrib.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHTMLheader(NULL, 0);
    printIpProtocolDistribution(SHORT_FORMAT, revertOrder);
  } else if(strcmp(pageName, "ipTrafficMatrix.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printIpTrafficMatrix();
  } else if(strcmp(pageName, "localRoutersList.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printLocalRoutersList();
  } else if(strcmp(pageName, "ipProtoUsage.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printIpProtocolUsage();
#ifdef HAVE_GDCHART
  } else if(strncmp(pageName, "thptGraph", strlen("thptGraph")) == 0) {
    sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);
    drawThptGraph(sortedColumn);
    printTrailer=0;
  } else if(strncmp(pageName, "ipTrafficPie", strlen("ipTrafficPie")) == 0) {
    sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);
    drawTrafficPie();
    printTrailer=0;
  } else if(strncmp(pageName, "pktCastDistribPie", strlen("pktCastDistribPie")) == 0) {
    sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);
    pktCastDistribPie();
    printTrailer=0;
  } else if(strncmp(pageName, "pktSizeDistribPie", strlen("pktSizeDistribPie")) == 0) {
    if((device[actualReportDeviceId].rcvdPktStats.upTo128
	+device[actualReportDeviceId].rcvdPktStats.upTo256
	+device[actualReportDeviceId].rcvdPktStats.upTo512
	+device[actualReportDeviceId].rcvdPktStats.upTo1024
	+device[actualReportDeviceId].rcvdPktStats.upTo1518) > 0) {    
      sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);
      pktSizeDistribPie();
      printTrailer=0;
    } else {
      printNoDataYet();
    }
  } else if(strncmp(pageName, "ipProtoDistribPie", strlen("ipProtoDistribPie")) == 0) {
    sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);
    ipProtoDistribPie();
    printTrailer=0;
  } else if(strncmp(pageName, "interfaceTrafficPie", strlen("interfaceTrafficPie")) == 0) {
    sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);
    interfaceTrafficPie();
    printTrailer=0;
  } else if(strncmp(pageName, "drawGlobalProtoDistribution",
		    strlen("drawGlobalProtoDistribution")) == 0) {
    sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);
    drawGlobalProtoDistribution();
    printTrailer=0;
  } else if(strncmp(pageName, "drawGlobalIpProtoDistribution",
		    strlen("drawGlobalIpProtoDistribution")) == 0) {
    sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);
    drawGlobalIpProtoDistribution();
    printTrailer=0;
#endif
  } else if(strncmp(pageName, NW_EVENTS_HTML, strlen(NW_EVENTS_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHostEvents(NULL, sortedColumn, revertOrder);
  } else if(strcmp(pageName, "Credits.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHTMLheader("Credits", HTML_FLAG_NO_REFRESH);
    sendString("<FONT FACE=Helvetica>\n");
    sendString("<p><hr><br><b>ntop</b> has been created by\n");
    sendString("<A HREF=\"http://luca.ntop.org/\">Luca Deri</A> while studying how to model\n");
    sendString("network traffic. He was unsatisfied of the many network traffic analysis tools\n");
    sendString("he had access to, and decided to write a new application able to report network\n");
    sendString("traffic information in a way similar to the popular Unix top command. At that \n");
    sendString("point in time (it was June 1998) <b>ntop</b> was born.<p>The current release is very\n");
    sendString("different from the initial one for several reasons. In particular it: <ul>\n");
    sendString("<li>is much more sophisticated <li>has both a command line and a web interface\n");
    sendString("<li>is capable of handling both IP and non IP protocols </ul> <p> Although it\n");
    sendString("might not seem so, <b>ntop</b> has definitively more than an author.\n");
    sendString("<A HREF=\"mailto:stefano@ntop.org\">Stefano Suin</A> has contributed with ");
    sendString("some code fragments to the version 1.0 of <b>ntop</b>\n");
    sendString(". In addition, many other people downloaded this program, tested it,\n");
    sendString("joined the <A HREF=http://mailserver.unipi.it/lists/ntop/archive/>ntop mailing list</A>,\n");
    sendString("reported problems, changed it and improved significantly. This is because\n");
    sendString("they have realised that <b>ntop</b> doesn't belong uniquely to its author, but\n");
    sendString("to the whole Internet community. Their names are throught "
	       "the <b>ntop</b> code.<p>");
    sendString("The author would like to thank all these people who contributed to <b>ntop</b> and\n");
    sendString("turned it into a first class network monitoring tool. Many thanks guys!<p>\n");
    sendString("</FONT><p>\n");
#ifdef HAVE_GDBM_H
  } else if(strcmp(pageName, "showUsers.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    showUsers();
  } else if(strcmp(pageName, "addUser.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    addUser(NULL);
  } else if(strncmp(pageName, "modifyUser", strlen("modifyUser")) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    if((questionMark == NULL) || (questionMark[0] == '\0'))
      addUser(NULL);
    else
      addUser(&questionMark[1]);
  } else if(strncmp(pageName, "deleteUser", strlen("deleteUser")) == 0) {
    printTrailer=0;
    if((questionMark == NULL) || (questionMark[0] == '\0'))
      deleteUser(NULL);
    else
      deleteUser(&questionMark[1]);
  } else if(strcmp(pageName, "doAddUser") == 0) {
    printTrailer=0;
    doAddUser(postLen /* \r\n */);
  } else if(strcmp(pageName, "showURLs.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    showURLs();
  } else if(strcmp(pageName, "addURL.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    addURL(NULL);
  } else if(strncmp(pageName, "modifyURL", strlen("modifyURL")) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    if((questionMark == NULL) || (questionMark[0] == '\0')) {
      addURL(NULL);
    } else
      addURL(&questionMark[1]);
  } else if(strncmp(pageName, "deleteURL", strlen("deleteURL")) == 0) {
    printTrailer=0;
    if((questionMark == NULL) || (questionMark[0] == '\0'))
      deleteURL(NULL);
    else
      deleteURL(&questionMark[1]);
  } else if(strcmp(pageName, "doAddURL") == 0) {
    printTrailer=0;
    doAddURL(postLen /* \r\n */);
#endif /* HAVE_GDBM_H */
  } else if(strncmp(pageName, INFO_NTOP_HTML, strlen(INFO_NTOP_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printNtopConfigInfo();
  } else 
#endif /* MICRO_NTOP */
    if(strncmp(pageName, DUMP_DATA_HTML, strlen(DUMP_DATA_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_TEXT, 0);
    if((questionMark == NULL) || (questionMark[0] == '\0'))
      dumpNtopHashes(NULL);
    else
      dumpNtopHashes(&questionMark[1]);
    printTrailer = 0;
  } else if(strncmp(pageName, DUMP_TRAFFIC_DATA_HTML, strlen(DUMP_TRAFFIC_DATA_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_TEXT, 0);
    if((questionMark == NULL) || (questionMark[0] == '\0'))
      dumpNtopTrafficInfo(NULL);
    else
      dumpNtopTrafficInfo(&questionMark[1]);
    printTrailer = 0;
 } 
#ifndef MICRO_NTOP
    else if(strlen(pageName) > 5) {
    int i;
    char hostName[32];

    pageName[strlen(pageName)-5] = '\0';

    /* Patch for ethernet addresses and MS Explorer */
    for(i=0; pageName[i] != '\0'; i++)
      if(pageName[i] == '_')
	pageName[i] = ':';

    strncpy(hostName, pageName, sizeof(hostName));
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printAllSessionsHTML(hostName);
  } 
#endif
    else {
      printTrailer = 0;
      errorCode = HTTP_INVALID_PAGE;
    }

  if(printTrailer && (postLen == -1)) printHTMLtrailer();

#ifdef MULTITHREADED
  releaseMutex(&hashResizeMutex);
#endif
  return (errorCode);
}

/* ************************* */

#ifndef HAVE_GDBM_H
static int checkHTTPpassword(char *theRequestedURL, int theRequestedURLLen _UNUSED_,
			     char* thePw, int thePwLen) {
  return 1; /* Access granted - security is disabled */
}
#else
static int checkHTTPpassword(char *theRequestedURL, 
			     int theRequestedURLLen _UNUSED_,
			     char* thePw, int thePwLen) {
  char outBuffer[65], *user = NULL, users[BUF_SIZE];
  int i, rc;
  datum key_data, return_data;

  theUser[0] = '\0';
#ifdef DEBUG
  traceEvent(TRACE_INFO, "Checking '%s'\n", theRequestedURL);
#endif

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "checkHTTPpasswd");
#endif
  return_data = gdbm_firstkey (pwFile);
  outBuffer[0] = '\0';

  while (return_data.dptr != NULL) {
    key_data = return_data;

    if(key_data.dptr[0] == '2') /* 2 = URL */ {
      if(strncmp(&theRequestedURL[1], &key_data.dptr[1],
		 strlen(key_data.dptr)-1) == 0) {
	strncpy(outBuffer, key_data.dptr, sizeof(outBuffer)-1)[sizeof(outBuffer)-1] = '\0';
	free(key_data.dptr);
	break;
      }
    }

    return_data = gdbm_nextkey(pwFile, key_data);
    free(key_data.dptr);
  }

  if(outBuffer[0] == '\0') {
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif
    return 1; /* This is a non protected URL */
  }

  key_data.dptr = outBuffer;
  key_data.dsize = strlen(outBuffer)+1;
  return_data = gdbm_fetch(pwFile, key_data);

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

  strncpy(theUser, user, sizeof(theUser)-1)[thePwLen-1] = '\0';
 
#ifdef DEBUG
  traceEvent(TRACE_INFO, "User='%s' - Pw='%s'\n", user, thePw);
#endif

  if(snprintf(users, BUF_SIZE, "1%s", user) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");

  if(strstr(return_data.dptr, users) == NULL) {
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif
    if (return_data.dptr != NULL) free(return_data.dptr);
    return 0; /* The specified user is not among those who are
		 allowed to access the URL */
  }
  if (return_data.dptr != NULL) free(return_data.dptr);

  key_data.dptr = users;
  key_data.dsize = strlen(users)+1;
  return_data = gdbm_fetch(pwFile, key_data);


  if (return_data.dptr != NULL) {
#ifdef WIN32
    rc = !strcmp(return_data.dptr, thePw);
#else
    rc = !strcmp(return_data.dptr,
		 (char*)crypt((const char*)thePw, (const char*)CRYPT_SALT));
#endif
    free (return_data.dptr);
  } else
    rc = 0;

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif
  return(rc);

#endif /* HAVE_GDBM_H */
}

#if 0 /* this is not used anymore */
/* ************************* */

static void returnHTTPnotImplemented(void) {
  sendString("HTTP/1.0 501 Not Implemented\n");
  sendString("Connection: close\n");
  sendString("Content-Type: text/html\n\n");
  sendString("<HTML>\n<TITLE>Error</TITLE>\n<BODY BACKGROUND=white_bg.gif>\n"
	     "<H1>Error 501</H1>\nMethod not implemented\n</BODY>\n</HTML>\n");

  logHTTPaccess(501);
}
#endif

/* ************************* */

void handleHTTPrequest(struct in_addr from) {
  int postLen;
  char requestedURL[512], pw[64];
  int rc;

  gettimeofday(&httpRequestedAt, NULL);

  requestFrom = &from;

  memset(requestedURL, 0, sizeof(requestedURL));
  memset(pw, 0, sizeof(pw));

  httpBytesSent = 0;

  postLen = readHTTPheader(requestedURL, sizeof(requestedURL), pw, sizeof(pw));

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Requested URL = '%s', length = %d\n", requestedURL, postLen); 
#endif
  
  if(postLen >= -1) {
    ; /* no errors, skip following tests */
  } else if(postLen == HTTP_INVALID_REQUEST) {
    returnHTTPbadRequest();
    return;
  } else if(postLen == HTTP_INVALID_METHOD) {
    /* Courtesy of Vanja Hrustic <vanja@relaygroup.com> */
    returnHTTPnotImplemented();
    return;
  } else if(postLen == HTTP_INVALID_VERSION) {
    returnHTTPversionNotSupported();
    return;
  } else if(postLen == HTTP_REQUEST_TIMEOUT) {
    returnHTTPrequestTimedOut();
    return;
  }

  /*
    Fix courtesy of  
    Michael Wescott <wescott@crosstor.com>
  */
  if((requestedURL[0] != '\0') && (requestedURL[0] != '/')) {
    returnHTTPpageNotFound();
    return;
  }

  if(checkHTTPpassword(requestedURL, sizeof(requestedURL), pw, sizeof(pw) ) != 1) {
    returnHTTPaccessDenied();
    return;
  }

  actTime = time(NULL); /* Don't forget this */

  if((rc = returnHTTPPage(&requestedURL[1], postLen)) == 0 ) {
    logHTTPaccess(200);
  } else if(rc == HTTP_FORBIDDEN_PAGE) {
    returnHTTPaccessForbidden();
  } else if(rc == HTTP_INVALID_PAGE) {
    returnHTTPpageNotFound();
  }
}
