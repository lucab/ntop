/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
 *                         Portions by Stefano Suin <stefano@ntop.org>
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

#define USE_CGI
#include "ntop.h"
#include "globals-report.h"

#define FORK_CHILD_PROCESS
#define URL_LEN        512

/*    This list is derived from RFC1945 in sec 3.2 Uniform Resource Identifiers
      which defines the permitted characters in a URI/URL.  Specifically, the
      definitions of

      reserved       = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+"
      unsafe         = CTL | SP | <"> | "#" | "%" | "<" | ">"

      DO NOT put % here - it's special cased - it's too dangerous to handle the same...

      Courtesy of "Burton M. Strauss III" <bstrauss@acm.org>
*/
#define URL_PROHIBITED_CHARACTERS     "\001\002\003\004\005\006" \
                                  "\010\011\012\013\014\015\016" \
                                  "\020\021\022\023\024\025\026" \
                                  "\030\031\032\033\034\035\036" \
                                  " \"#+;<>@\177"

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
    { 404, "Not Found", "The server cannot found the page requested." },
    { 405, "Method Not Allowed", NULL },
    { 406, "Not Acceptable", NULL },
    { 407, "Proxy Authentication Required", NULL },
    { 408, "Request Time-out", "The request was timed-out." },
    { 409, "Conflict", NULL },
    { 410, "Gone", "The page you requested is not available in your current ntop <A HREF=/info.html>configuration</A>. See the ntop <A HREF=/ntop.html>man page</A> for more information" },
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
#define HTTP_FLAG_STATUS_410	(25<<8)
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

/* ************************* */

/* Forward */
static int readHTTPheader(char* theRequestedURL, int theRequestedURLLen, char *thePw, int thePwLen);
static int decodeString(char *bufcoded, unsigned char *bufplain, int outbufsize);
static void logHTTPaccess(int rc, struct timeval *httpRequestedAt, u_int gzipBytesSent);
static void returnHTTPspecialStatusCode(int statusIdx);
static int returnHTTPPage(char* pageName, int postLen, struct in_addr *from,
			  struct timeval *httpRequestedAt, int *usedFork);
static int checkHTTPpassword(char *theRequestedURL, int theRequestedURLLen _UNUSED_, char* thePw, int thePwLen);

#ifdef HAVE_ZLIB
static char compressedFilePath[16];
static short compressFile = 0, acceptGzEncoding;
static FILE *compressFileFd=NULL;
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
                          char *thePw, int thePwLen) {
#ifdef HAVE_OPENSSL
  SSL* ssl = getSSLsocket(-myGlobals.newSock);
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
  topSock = abs(myGlobals.newSock);
#else
  topSock = myGlobals.newSock;
#endif

  for(;;) {
    FD_ZERO(&mask);
    FD_SET((unsigned int)topSock, &mask);

    /* printf("About to call select()\n"); fflush(stdout); */

    /* select returns immediately */
    wait_time.tv_sec = 10; wait_time.tv_usec = 0;
    if(select(myGlobals.newSock+1, &mask, 0, 0, &wait_time) == 0) {
      errorCode = HTTP_REQUEST_TIMEOUT; /* Timeout */
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Timeout while reading from socket.\n");
#endif
      break;
    }

    /* printf("About to call recv()\n"); fflush(stdout); */
    /* printf("Rcvd %d bytes\n", recv(myGlobals.newSock, aChar, 1, MSG_PEEK)); fflush(stdout); */

#ifdef HAVE_OPENSSL
    if(myGlobals.newSock < 0) {
      rc = SSL_read(ssl, aChar, 1);
      if(rc == -1) {
	int theErr = SSL_get_error(ssl, rc);
	traceEvent(TRACE_ERROR, "SSL read error %d (%s)", theErr, printSSLError(theErr));
      }
    } else
      rc = recv(myGlobals.newSock, aChar, 1, 0);
#else
    rc = recv(myGlobals.newSock, aChar, 1, 0);
#endif

    if(rc != 1) {
      idxChar = 0;
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Socket read returned %d (errno=%d)\n", rc, errno);
#endif
      /* FIXME (DL): is valid to write to the socket after this condition? */
      break; /* Empty line */

    } else if((errorCode == 0) && !isprint(aChar[0]) && !isspace(aChar[0])) {
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

	    if((idxChar >= 3) && (strncmp(lineStr, "GET ", 4) == 0)) {
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
#ifdef HAVE_ZLIB
	} else if((idxChar >= 17)
		  && (strncasecmp(lineStr, "Accept-Encoding: ", 17) == 0)) {
	  if(strstr(&lineStr[17], "gzip"))
	    acceptGzEncoding = 1;
#endif
	} else if((idxChar >= 16)
		  && (strncasecmp(lineStr, "Content-Length: ", 16) == 0)) {
	  contentLen = atoi(&lineStr[16]);
#ifdef DEBUG
	  traceEvent(TRACE_INFO, "len=%d [%s/%s]\n", contentLen, lineStr, &lineStr[16]);
#endif
	}
	idxChar=0;
      } else if(idxChar > sizeof(lineStr)-2) {
	if(errorCode == 0) {
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

  if(myGlobals.newSock == DUMMY_SOCKET_VALUE)
    return;

  httpBytesSent += len;

  /* traceEvent(TRACE_INFO, "%s", theString);  */
  if(len == 0)
    return; /* Nothing to send */
  else {
#ifdef HAVE_ZLIB
    if(compressFile) {
      int i;

      if(compressFileFd == NULL) {
	sprintf(compressedFilePath, "/tmp/gzip-%d.ntop", getpid());
	compressFileFd = gzopen(compressedFilePath, "w+");
      }

      for(i=0; i<len; i++)
	gzputc(compressFileFd, theString[i]);
      return;
    } else {
      memcpy(buffer, theString, (size_t) ((len > sizeof(buffer)) ? sizeof(buffer) : len));
    }
#else
    memcpy(buffer, theString, (size_t) ((len > sizeof(buffer)) ? sizeof(buffer) : len));
#endif /* HAVE_ZLIB */
  }

  bytesSent = 0;

  while(len > 0) {
  RESEND:
    errno=0;

    if(myGlobals.newSock == DUMMY_SOCKET_VALUE)
      return;

#ifdef HAVE_OPENSSL
    if(myGlobals.newSock < 0) {
      rc = SSL_write(getSSLsocket(-myGlobals.newSock), &buffer[bytesSent], len);
    } else
      rc = send(myGlobals.newSock, &buffer[bytesSent], (size_t)len, 0);
#else
    rc = send(myGlobals.newSock, &buffer[bytesSent], (size_t)len, 0);
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
      } else if(errno == EPIPE /* Broken pipe: the  client has disconnected */) {
	closeNwSocket(&myGlobals.newSock);
	return;
      } else if(errno == EBADF /* Bad file descriptor: a
				   disconnected client is still sending */) {
	closeNwSocket(&myGlobals.newSock);
	return;
      } else {
	closeNwSocket(&myGlobals.newSock);
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

  if(title != NULL) {
    if(snprintf(buf, BUF_SIZE, "<TITLE>%s</TITLE>\n", title) < 0)
    BufferTooShort();
    sendString(buf);
  }

  if((headerFlags & HTML_FLAG_NO_REFRESH) == 0) {
    if(snprintf(buf, BUF_SIZE, "<META HTTP-EQUIV=REFRESH CONTENT=%d>\n", myGlobals.refreshRate) < 0)
      BufferTooShort();
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
	      ctime(&myGlobals.actTime), formatSeconds(myGlobals.actTime-myGlobals.initialSniffTime)) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, BUF_SIZE, "Generated by <A HREF=\"http://www.ntop.org/\">ntop</A> v.%s %s \n[%s] (%s build)<br>",
	      version, THREAD_MODE, osName, buildDate) < 0)
    BufferTooShort();
  sendString(buf);

  if(myGlobals.rFileName != NULL) {
    if(snprintf(buf, BUF_SIZE, "Listening on [%s]\n", PCAP_NW_INTERFACE) < 0)
      BufferTooShort();
  } else {
    int numRealDevices;

    for(i=len=numRealDevices=0; i<myGlobals.numDevices; i++, len=strlen(buf)) {
      if(!myGlobals.device[i].virtualDevice) {
	if(snprintf(&buf[len], BUF_SIZE-len, "%s%s",
		    (numRealDevices>0) ? "," : "listening on [", myGlobals.device[i].name) < 0)
	  BufferTooShort();
	numRealDevices++;
      }
    }

    if(snprintf(&buf[len], BUF_SIZE-len, "]\n") < 0)
      BufferTooShort();
  }

  len=strlen(buf);
  if(*myGlobals.currentFilterExpression!='\0') {
    if(snprintf(&buf[len], BUF_SIZE-len,
		"with kernel (libpcap) filtering expression </B>\"%s\"<B>\n",
		myGlobals.currentFilterExpression) < 0)
      BufferTooShort();
  } else {
    if(snprintf(&buf[len], BUF_SIZE-len,
		"without a kernel (libpcap) filtering expression\n") < 0)
      BufferTooShort();
  }

  sendString(buf);

  sendString("<BR>\n&copy; 1998-2002 by <A HREF=mailto:deri@ntop.org>Luca Deri</A>\n");
  sendString("</B></FONT>\n</BODY>\n</HTML>\n");
}

/* ******************************* */

void initAccessLog(void) {

  if(myGlobals.accessLogPath) {
    myGlobals.accessLogFd = fopen(myGlobals.accessLogPath, "a");
    if(myGlobals.accessLogFd == NULL) {
      traceEvent(TRACE_ERROR, "Unable to create file %s. Access log is disabled.",
		 myGlobals.accessLogPath);
    }
  }
}

/* ******************************* */

void termAccessLog(void) {
  if(myGlobals.accessLogFd != NULL)
    fclose(myGlobals.accessLogFd);
}

/* ************************* */

static void logHTTPaccess(int rc, struct timeval *httpRequestedAt,
			  u_int gzipBytesSent) {
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

   strftime(theDate, sizeof(theDate), "%d/%b/%Y:%H:%M:%S", localtime_r(&myGlobals.actTime, &t));

   gmtoffset =  (myGlobals.thisZone < 0) ? -myGlobals.thisZone : myGlobals.thisZone;
   if(snprintf(theZone, sizeof(theZone), "%c%2.2ld%2.2ld",
	       (myGlobals.thisZone < 0) ? '-' : '+', gmtoffset/3600, (gmtoffset/60)%60) < 0)
      BufferTooShort();

   if((theUser == NULL)
      || (theUser[0] == '\0'))
     strncpy(myUser, " ", 64);
   else {
     if(snprintf(myUser, sizeof(myUser), " %s ", theUser) < 0)
      BufferTooShort();
   }

#ifdef HAVE_ZLIB
   if(gzipBytesSent > 0)
     fprintf(myGlobals.accessLogFd, "%s -%s- [%s %s] - \"%s\" %d %u/%u %lu\n",
	     _intoa(*requestFrom, buf, sizeof(buf)),
	     myUser, theDate, theZone,
	     httpRequestedURL, rc, gzipBytesSent, httpBytesSent,
	     msSpent);
   else
     fprintf(myGlobals.accessLogFd, "%s -%s- [%s %s] - \"%s\" %d %u %lu\n",
	     _intoa(*requestFrom, buf, sizeof(buf)),
	     myUser, theDate, theZone,
	     httpRequestedURL, rc, httpBytesSent,
	     msSpent);
#else
   fprintf(myGlobals.accessLogFd, "%s -%s- [%s %s] - \"%s\" %d %d %lu\n",
	   _intoa(*requestFrom, buf, sizeof(buf)),
	   myUser, theDate, theZone,
	   httpRequestedURL, rc, httpBytesSent,
	   msSpent);
#endif
   fflush(myGlobals.accessLogFd);
 }
}

/* ************************* */

static void returnHTTPbadRequest() {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_400);
}

static void returnHTTPaccessDenied() {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_401 | HTTP_FLAG_NEED_AUTHENTICATION);
}

static void returnHTTPaccessForbidden() {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_403);
}

static void returnHTTPpageNotFound() {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_404);
}

static void returnHTTPpageGone() {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_410);
}

static void returnHTTPrequestTimedOut() {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_408);
}

static void returnHTTPnotImplemented() {
  returnHTTPspecialStatusCode(HTTP_FLAG_STATUS_501);
}

static void returnHTTPversionNotSupported() {
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
    traceEvent(TRACE_WARNING,
	       "INTERNAL ERROR: invalid HTTP status id (%d) set to zero.\n", statusIdx);
#endif
  }

  sendHTTPHeader(HTTP_TYPE_HTML, statusFlag);
  if(snprintf(buf, sizeof(buf), "Error %d", HTTPstatus[statusIdx].statusCode) < 0)
      BufferTooShort();
  printHTMLheader(buf, HTML_FLAG_NO_REFRESH | HTML_FLAG_NO_HEADING);

  if(snprintf(buf, sizeof(buf),
	   "<H1>Error %d</H1>\n%s\n",
	   HTTPstatus[statusIdx].statusCode, HTTPstatus[statusIdx].longDescription) < 0)
      BufferTooShort();

  sendString(buf);
  if(strlen(httpRequestedURL) > 0) {
    if(snprintf(buf, sizeof(buf),
	     "<P>Received request:<BR><BLOCKQUOTE><TT>&quot;%s&quot;</TT></BLOCKQUOTE>",
	     httpRequestedURL) < 0)
      BufferTooShort();
    sendString(buf);
  }

  printHTMLtrailer();

  logHTTPaccess(HTTPstatus[statusIdx].statusCode, NULL, 0);
}

/* *******************************/

void returnHTTPredirect(char* destination) {
#ifdef HAVE_ZLIB
  compressFile = acceptGzEncoding = 0;
#endif

  sendHTTPHeader(HTTP_TYPE_HTML,
		 HTTP_FLAG_STATUS_302 | HTTP_FLAG_NO_CACHE_CONTROL | HTTP_FLAG_MORE_FIELDS);
  sendString("Location: /");
  sendString(destination);
  sendString("\n\n");
}

/* ************************* */

void sendHTTPHeader(int mimeType, int headerFlags) {
  int statusIdx;
  char tmpStr[64], theDate[48];
  time_t  theTime = myGlobals.actTime - (time_t)myGlobals.thisZone;
  struct tm t;

#ifdef HAVE_ZLIB
  compressFile = 0;
#endif

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
      BufferTooShort();
  sendString(tmpStr);

  strftime(theDate, sizeof(theDate)-1, "%a, %d %b %Y %H:%M:%S GMT", localtime_r(&theTime, &t));
  theDate[sizeof(theDate)-1] = '\0';
  if(snprintf(tmpStr, sizeof(tmpStr), "Date: %s\n", theDate) < 0)
      BufferTooShort();
  sendString(tmpStr);

  if(headerFlags & HTTP_FLAG_IS_CACHEABLE) {
    sendString("Cache-Control: max-age=3600, must-revalidate, public\n");
  } else if((headerFlags & HTTP_FLAG_NO_CACHE_CONTROL) == 0) {
    sendString("Cache-Control: no-cache\n");
    sendString("Expires: 0\n");
  }

  if((headerFlags & HTTP_FLAG_KEEP_OPEN) == 0) {
    sendString("Connection: close\n");
  }

  if(snprintf(tmpStr, sizeof(tmpStr), "Server: ntop/%s (%s)\n", version, osName) < 0)
      BufferTooShort();
  sendString(tmpStr);

  if(headerFlags & HTTP_FLAG_NEED_AUTHENTICATION) {
      sendString("WWW-Authenticate: Basic realm=\"ntop HTTP server;\"\n");
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
      traceEvent(TRACE_INFO,
		 "INTERNAL ERROR: invalid MIME type code requested (%d)\n", mimeType);
#endif
  }

#ifdef HAVE_ZLIB
  if(mimeType == MIME_TYPE_CHART_FORMAT) {
    compressFile = 0;
    if(myGlobals.newSock < 0 /* SSL */) acceptGzEncoding = 0;
  } else {
    if(acceptGzEncoding) compressFile = 1;
  }
#endif

  if((headerFlags & HTTP_FLAG_MORE_FIELDS) == 0) {
    sendString("\n");
  }
}

/* ************************* */

static int checkURLsecurity(char *url) {
  int rc = 0, countOKextension, len, i;
  int countSections, countOKnumeric;
  char *token;
  char *workURL = NULL;

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

  if(strlen(url) >= URL_LEN) {
    traceEvent(TRACE_ERROR, "URL security(2): URL too long (len=%d)", strlen(url));
    return(2);
  }


#ifdef DEBUG
  traceEvent(TRACE_INFO, "URL security: Testing '%s'...\n", url);
#endif

  /* a % - Unicode?  We kill this off 1st because some of the gcc functions interpret unicode "for" us */
  /*
    if(strstr(url, "%") > 0) {
    traceEvent(TRACE_ERROR, "URL security(1): ERROR: Found percent in URL...DANGER...rejecting request\n");
    url[0] = '\0';
    return(1);
    }
  */

  /* a double slash? */
  if(strstr(url, "%%") > 0) {
    traceEvent(TRACE_ERROR, "URL security(2): ERROR: Found %% in URL...rejecting request\n");
    return(2);
  }

  /* a double slash? */
  if(strstr(url, "//") > 0) {
    traceEvent(TRACE_ERROR, "URL security(2): ERROR: Found // in URL...rejecting request\n");
    return(2);
  }

  /* a double &? */
  if(strstr(url, "&&") > 0) {
    traceEvent(TRACE_ERROR, "URL security(2): ERROR: Found && in URL...rejecting request\n");
    return(2);
  }

  /* a double ?? */
  if(strstr(url, "??") > 0) {
    traceEvent(TRACE_ERROR, "URL security(2): ERROR: Found ?? in URL...rejecting request\n");
    return(2);
  }

  /* a double dot? */
  if(strstr(url, "..") > 0) {
    traceEvent(TRACE_ERROR, "URL security(3): ERROR: Found .. in URL...rejecting request\n");
    return(3);
  }

  /* Prohibited characters? */
  if((len = strcspn(url, URL_PROHIBITED_CHARACTERS)) < strlen(url)) {
    traceEvent(TRACE_ERROR, "URL security(4): ERROR: Prohibited character(s) [%c]"
	       " in URL... rejecting request\n", url[len]);
    return(4);
  }

  /*
    We can't simply find the "." and test the extension, as
    we have to allow urls of the following special forms:

    [0..255].[0..255].[0..255].[0..255].html
    xxxxxx    (no extension - just an internal name)
    XXXXX-[0..255].[0..255].[0..255].[0..255].html

    Instead, we'll tokenize the URL on the "." and check each one
    if we get 4 valid #s plus an .htm(l)
    Or an otherwise valid extension, we're ok
  */

  countSections = countOKnumeric = countOKextension = 0;
  workURL = strdup(url);

  /* Strip off parameters */
  token = strchr(workURL, '?');
  if(token != NULL) {
    token[0] = '\0';
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "URL security: NOTE: Tokenizing '%s'...\n", workURL);
#endif

  for(i=strlen(workURL)-1; i >= 0; i--)
    if(workURL[i] == '.')
      break;
  i++;

  if((i > 0)
     && (!((strcmp(&workURL[i] , "htm") == 0)  ||
	   (strcmp(&workURL[i] , "html") == 0) ||
	   (strcmp(&workURL[i] , "txt") == 0)  ||
	   (strcmp(&workURL[i] , "jpg") == 0)  ||
	   (strcmp(&workURL[i] , "png") == 0)  ||
	   (strcmp(&workURL[i] , "gif") == 0)  ||
	   (strcmp(&workURL[i] , "ico") == 0)  ||
	   (strcmp(&workURL[i] , "css") == 0)))) {
    traceEvent(TRACE_ERROR,
	       "URL security(5): ERROR: Found bad file extension (.%s) in URL...\n",
	       &workURL[i]);
    rc = 5;
  }

  if(workURL != NULL) free(workURL);

  if(rc != 0)
    traceEvent(TRACE_ERROR,
	       "ERROR: bad char found on '%s' (rc=%d) rejecting request",
	       url, rc);

  return(rc);
}

/* ************************* */

static RETSIGTYPE quitNow(int signo _UNUSED_) {
  exit(0);
}

/* **************************************** */

static int returnHTTPPage(char* pageName, int postLen, struct in_addr *from,
			  struct timeval *httpRequestedAt, int *usedFork) {
  char *questionMark;
  int sortedColumn = 0, printTrailer=1, idx;
  int errorCode=0, pageNum = 0, found=0;
  struct stat statbuf;
  FILE *fd = NULL;
  char tmpStr[512];
  char *domainNameParm = NULL;
  int revertOrder=0, rc;
#ifdef MULTITHREADED
  u_char mutexReleased = 0;
#endif
  struct tm t;
#ifdef WIN32
  int i;
#endif

  *usedFork = 0;

  /*
     We need to check whether the URL is invalid, i.e. it contains '..' or
     similar chars that can be used for reading system files
  */
#ifdef  USE_CGI
  if(strncmp(pageName, CGI_HEADER, strlen(CGI_HEADER)))
#endif
  {
    /* This is not a CGI */
    if((rc = checkURLsecurity(pageName)) != 0) {
      traceEvent(TRACE_ERROR, "ERROR: URL security: '%s' rejected (code=%d)(client=%s)",
		 pageName, rc, _intoa(*from, tmpStr, sizeof(tmpStr)));
      returnHTTPaccessForbidden();
      return(HTTP_FORBIDDEN_PAGE);
    }
  }

  /* traceEvent(TRACE_INFO, "Page: '%s'\n", pageName); */

  questionMark = strchr(pageName, '?');

  if((questionMark != NULL)
     && (questionMark[0] == '?')) {
    char requestedURL[URL_LEN];
    char *tkn;
    
    /* Safe strcpy as requestedURL < URL_LEN (checked by checkURLsecurity) */
    strcpy(requestedURL, &questionMark[1]);

    tkn = strtok(requestedURL, "&");

    while(tkn != NULL) {
      if(strncmp(tkn, "col=", 4) == 0) {
	idx = atoi(&tkn[4]);
	if(tkn[4] == '-') revertOrder=1;
	sortedColumn = abs(idx);
       } else if(strncmp(tkn, "dom=", 4) == 0) {
	 domainNameParm = strdup(&tkn[4]);
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

  if(pageName[0] == '\0')
    strncpy(pageName, STR_INDEX_HTML, sizeof(STR_INDEX_HTML));

  /* Search in the local directory first... */
  for(idx=0; (!found) && (myGlobals.dataFileDirs[idx] != NULL); idx++) {
    int j;

    for(j=0; j<=myGlobals.borderSnifferMode; j++) {
      if(myGlobals.borderSnifferMode && (j == 0)) {
	if(snprintf(tmpStr, sizeof(tmpStr), "%s/html/j_%s",
		    myGlobals.dataFileDirs[idx], pageName) < 0)
	  BufferTooShort();
      } else {
	if(snprintf(tmpStr, sizeof(tmpStr), "%s/html/%s",
		    myGlobals.dataFileDirs[idx], pageName) < 0)
	  BufferTooShort();
      }
	
      /* traceEvent(TRACE_ERROR, "Searching '%s'\n", tmpStr); */
	
#ifdef WIN32
      i=0;
      while(tmpStr[i] != '\0') {
	if(tmpStr[i] == '/') tmpStr[i] = '\\';
	i++;
      }
#endif
	
      if(stat(tmpStr, &statbuf) == 0) {
	if((fd = fopen(tmpStr, "rb")) != NULL) {
	  found = 1;
	  break;
	}

	traceEvent(TRACE_ERROR, "Cannot open file '%s', ignored...\n", tmpStr);
      }
    }
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "tmpStr=%s - fd=0x%x\n", tmpStr, fd);
#endif

  if(fd != NULL) {
    char theDate[48];
    time_t theTime;
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

#ifdef HAVE_ZLIB
    compressFile = 0; /* Don't move this */
#endif

    if(myGlobals.actTime > statbuf.st_mtime) { /* just in case the system clock is wrong... */
        theTime = statbuf.st_mtime - myGlobals.thisZone;
        strftime(theDate, sizeof(theDate)-1, "%a, %d %b %Y %H:%M:%S GMT", localtime_r(&theTime, &t));
        theDate[sizeof(theDate)-1] = '\0';
        if(snprintf(tmpStr, sizeof(tmpStr), "Last-Modified: %s\n", theDate) < 0)
	  BufferTooShort();
        sendString(tmpStr);
    }

    sendString("Accept-Ranges: bytes\n");

    fseek(fd, 0, SEEK_END);
    if(snprintf(tmpStr, sizeof(tmpStr), "Content-Length: %d\n", (len = ftell(fd))) < 0)
      BufferTooShort();
    fseek(fd, 0, SEEK_SET);
    sendString(tmpStr);

    sendString("\n");	/* mark the end of HTTP header */

    for(;;) {
      len = fread(tmpStr, sizeof(char), 255, fd);
      if(len <= 0) break;
      sendStringLen(tmpStr, len);
    }

    fclose(fd);
    /* closeNwSocket(&myGlobals.newSock); */
    return(0);
  }

  if(strncmp(pageName, PLUGINS_HEADER, strlen(PLUGINS_HEADER)) == 0) {
    if(handlePluginHTTPRequest(&pageName[strlen(PLUGINS_HEADER)])) {
      return(0);
    } else {
      return(HTTP_INVALID_PAGE);
    }
  }

  /*
    Putting this here (and not on top of this function)
    helps because at least a partial respose
    has been send back to the user in the meantime
  */
#ifdef MULTITHREADED
  accessMutex(&myGlobals.hashResizeMutex, "returnHTTPpage");
#endif

#ifndef MICRO_NTOP
  if(strncmp(pageName, SHUTDOWN_NTOP_HTML, strlen(SHUTDOWN_NTOP_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    shutdownNtop();
  } else if(strncmp(pageName, CHANGE_FILTER_HTML, strlen(CHANGE_FILTER_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    changeFilter();
  } else if(strncmp(pageName, "doChangeFilter", strlen("doChangeFilter")) == 0) {
    printTrailer=0;
    if(doChangeFilter(postLen)==0) /*resetStats()*/;
  } else if(strncmp(pageName, FILTER_INFO_HTML, strlen(FILTER_INFO_HTML)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHTMLheader(NULL, HTML_FLAG_NO_REFRESH);
    /* printHTMLtrailer is called afterwards and inserts the relevant info */
  } else if(strncmp(pageName, RESET_STATS_HTML, strlen(RESET_STATS_HTML)) == 0) {
    /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHTMLheader("All statistics are now reset", HTML_FLAG_NO_REFRESH);
    resetStats();
  } else if(strncmp(pageName, SWITCH_NIC_HTML, strlen(SWITCH_NIC_HTML)) == 0) {
    char *equal = strchr(pageName, '=');
    sendHTTPHeader(HTTP_TYPE_HTML, 0);

    if(equal == NULL)
      switchNwInterface(0);
    else
      switchNwInterface(atoi(&equal[1]));
  } else if(strcmp(pageName, "doAddUser") == 0) {
    printTrailer=0;
    doAddUser(postLen /* \r\n */);
  } else if(strncmp(pageName, "deleteUser", strlen("deleteUser")) == 0) {
    printTrailer=0;
    if((questionMark == NULL) || (questionMark[0] == '\0'))
      deleteUser(NULL);
    else
      deleteUser(&questionMark[1]);
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
  } else if(strncmp(pageName, STR_SHOW_PLUGINS, strlen(STR_SHOW_PLUGINS)) == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    if(questionMark == NULL)
      showPluginsList("");
    else
      showPluginsList(&pageName[strlen(STR_SHOW_PLUGINS)+1]);
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
  } else if(strcmp(pageName, "showURLs.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    showURLs();
  } else if(strcmp(pageName, "addURL.html") == 0) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    addURL(NULL);
    /* Temporary here - begin

       Due to some strange problems, graph generation has some problems
       when several charts are generated concurrently.

       This NEEDS to be fixed.
    */
  } else if(strcmp(pageName, STR_FAVICON_ICO) == 0) {
    /* Burton Strauss (BStrauss@acm.org) - April 2002
       favicon.ico and we don't have the file (or it would have been handled above)
       so punt!
    */
#ifdef LOG_URLS
    traceEvent(TRACE_INFO, "Note: favicon.ico request, returned 404.\n");
#endif
    returnHTTPpageNotFound();
    printTrailer=0;
  } else {
#if defined(FORK_CHILD_PROCESS) && (!defined(WIN32))
    int childpid;

    if(!myGlobals.debugMode) {
      handleDiedChild(0); /*
			     Workaround because on this OpenBSD and
			     other platforms signal handling is broken as the system
			     creates zombies although we decided to ignore SIGCHLD
			  */

      /* The URLs below are "read-only" hence I can fork a copy of ntop  */

      if((childpid = fork()) < 0)
	traceEvent(TRACE_ERROR, "An error occurred while forking ntop [errno=%d]..", errno);
      else {
	*usedFork = 1;

	if(childpid) {
	  /* father process */
	  myGlobals.numChildren++;
#ifdef MULTITHREADED
	  releaseMutex(&myGlobals.hashResizeMutex);
#endif

#ifdef HAVE_ZLIB
	  compressFile = 0;
#endif
	  return(0);
	} else {
	  detachFromTerminal();

	  /* Close inherited sockets */
#ifdef HAVE_OPENSSL
	  if(myGlobals.sslInitialized) closeNwSocket(&myGlobals.sock_ssl);
#endif
	  if(myGlobals.webPort > 0) closeNwSocket(&myGlobals.sock);

	  setsignal(SIGALRM, quitNow);
	  alarm(120); /* Don't freeze */
	}
      }
    }
#endif

#ifndef WIN32
  if(strncmp(pageName, CGI_HEADER, strlen(CGI_HEADER)) == 0) {
    int rc;

    sendString("HTTP/1.0 200 OK\n");
    rc = execCGI(&pageName[strlen(CGI_HEADER)]);

    if(rc != 0) {
      returnHTTPpageNotFound();
    }
  } else
#endif

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
      sendString("<center>\n<pre>\n\n</pre>\n\n");
      sendString("<FONT FACE=Helvetica SIZE=+2>Welcome<br>to<br>\n");
      sendString("ntop!</FONT>\n<pre>\n</pre>\n");
      sendString("<p></center><p>\n<FONT FACE=Helvetica SIZE=-1><b>\n<ol>\n");
      sendString("<li><a href=home_.html target=area>What's ntop?</a></li>\n");
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
      sendString("<li><a href="IP_R_2_L_HTML" target=area ALT=\"Rem to Local IP Traffic\">"
		 "R-&gt;L IP Traffic</a></li>\n");
      sendString("<li><a href="IP_L_2_R_HTML" target=area ALT=\"Local to Rem IP Traffic\">"
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
      if(myGlobals.isLsofPresent)
	sendString("<li><a href="STR_LSOF_DATA" target=area "
		   "ALT=\"Local Processes Nw Usage\">Local Nw Usage</a></li>\n");

      if(myGlobals.flowsList != NULL)
	sendString("<li><a href=NetFlows.html target=area ALT=\"NetFlows\">"
		   "NetFlows List</a></li>\n");

      sendString("<li><a href=showUsers.html target=area ALT=\"Admin Users\">Admin Users</a></li>\n");
      sendString("<li><a href=showURLs.html target=area ALT=\"Admin URLs\">Admin URLs</a></li>\n");

      if(!myGlobals.mergeInterfaces)
	sendString("<li><a href="SWITCH_NIC_HTML" target=area ALT=\"Switch NICs\">Switch NICs</a></li>\n");

      sendString("<li><a href="SHUTDOWN_NTOP_HTML" target=area ALT=\"Shutdown ntop\">"
		 "Shutdown ntop</a></li>\n");
      sendString("<li><a href=ntop.html target=area ALT=\"Man Page\">Man Page</a></li>\n");
      sendString("<li><a href=Credits.html target=area ALT=\"Credits\">Credits</a></li>\n");
      sendString("</ol>\n<center>\n<b>\n\n");
      sendString("<pre>\n</pre>&copy; 1998-2002<br>by<br>"
		 "<A HREF=\"http://luca.ntop.org/\" target=\"area\">"
		 "Luca Deri</A></FONT><pre>\n");
      sendString("</pre>\n</b>\n</center>\n</body>\n</html>\n");
      printTrailer=0;
    } else if(strcmp(pageName, "home_.html") == 0) {
      if(myGlobals.filterExpressionInExtraFrame){
	sendHTTPHeader(HTTP_TYPE_HTML, 0);
        sendString("<html>\n  <frameset rows=\"*,90\" framespacing=\"0\" ");
        sendString("border=\"0\" frameborder=\"0\">\n");
        sendString("    <frame src=\"home.html\" marginwidth=\"2\" ");
        sendString("marginheight=\"2\" name=\"area\">\n");
        sendString("    <frame src=\""FILTER_INFO_HTML"\" marginwidth=\"0\" ");
        sendString("marginheight=\"0\" name=\"filterinfo\">\n");
        sendString("    <noframes>\n	 <body></body>\n    </noframes>\n");
        sendString("  </frameset>\n</html>\n");
        printTrailer=0;
      } else {	/* frame so that "area" is defined */
	sendHTTPHeader(HTTP_TYPE_HTML, 0);
        sendString("<html>\n  <frameset rows=\"100%,*\" framespacing=\"0\" ");
        sendString("border=\"0\" frameborder=\"0\">\n");
        sendString("    <frame src=\"home.html\" marginwidth=\"0\" ");
        sendString("marginheight=\"0\" name=\"area\">\n");
        sendString("    <noframes>\n	 <body></body>\n    </noframes>\n");
        sendString("  </frameset>\n</html>\n");
        printTrailer=0;
      }
    } else if(strcmp(pageName, "home.html") == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printHTMLheader("Welcome to ntop!", HTML_FLAG_NO_REFRESH);
      sendString("<FONT FACE=Helvetica>\n<HR>\n");
      sendString("<b>ntop</b> shows the current network usage. It displays a list of hosts that are\n");
      sendString("currently using the network and reports information concerning the IP\n");
      sendString("(Internet Protocol) traffic generated by each host. The traffic is \n");
      sendString("sorted according to host and protocol. Protocols (user configurable) include:\n");
      sendString("<ul><li>TCP/UDP/ICMP<li>(R)ARP<li>IPX<li>DLC<li>"
		 "Decnet<li>AppleTalk<li>Netbios<li>TCP/UDP<ul><li>FTP<li>"
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
      printHostsTraffic(0, sortedColumn, revertOrder, pageNum, STR_SORT_DATA_RECEIVED_PROTOS);
    } else if(strncmp(pageName, STR_SORT_DATA_RECEIVED_IP, strlen(STR_SORT_DATA_RECEIVED_IP)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printHostsTraffic(1, sortedColumn, revertOrder, pageNum, STR_SORT_DATA_RECEIVED_IP);
    } else if(strncmp(pageName, STR_SORT_DATA_THPT_STATS, strlen(STR_SORT_DATA_THPT_STATS)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printThptStats(sortedColumn);
    } else if(strncmp(pageName, STR_THPT_STATS_MATRIX, strlen(STR_THPT_STATS_MATRIX)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printThptStatsMatrix(sortedColumn);
    } else if(strncmp(pageName, STR_SORT_DATA_RECEIVED_THPT, strlen(STR_SORT_DATA_RECEIVED_THPT)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      if(sortedColumn == 0) { sortedColumn = HOST_DUMMY_IDX_VALUE; }
      printHostsTraffic(2, sortedColumn, revertOrder, pageNum, STR_SORT_DATA_RECEIVED_THPT);
    } else if(strncmp(pageName, STR_SORT_DATA_RCVD_HOST_TRAFFIC, strlen(STR_SORT_DATA_RCVD_HOST_TRAFFIC)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      if(sortedColumn == 0) { sortedColumn = HOST_DUMMY_IDX_VALUE; }
      printHostsTraffic(3, sortedColumn, revertOrder, pageNum, STR_SORT_DATA_RCVD_HOST_TRAFFIC);
    } else if(strncmp(pageName, STR_SORT_DATA_SENT_HOST_TRAFFIC, strlen(STR_SORT_DATA_SENT_HOST_TRAFFIC)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      if(sortedColumn == 0) { sortedColumn = HOST_DUMMY_IDX_VALUE; }
      printHostsTraffic(4, sortedColumn, revertOrder, pageNum, STR_SORT_DATA_SENT_HOST_TRAFFIC);
    } else if(strncmp(pageName, STR_SORT_DATA_SENT_PROTOS, strlen(STR_SORT_DATA_SENT_PROTOS)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printHostsTraffic(5, sortedColumn, revertOrder, pageNum, STR_SORT_DATA_SENT_PROTOS);
    } else if(strncmp(pageName, STR_SORT_DATA_SENT_IP, strlen(STR_SORT_DATA_SENT_IP)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printHostsTraffic(6, sortedColumn, revertOrder, pageNum, STR_SORT_DATA_SENT_IP);
    } else if(strncmp(pageName, STR_SORT_DATA_SENT_THPT, strlen(STR_SORT_DATA_SENT_THPT)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      if(sortedColumn == 0) { sortedColumn = HOST_DUMMY_IDX_VALUE; }
      printHostsTraffic(7, sortedColumn, revertOrder, pageNum, STR_SORT_DATA_SENT_THPT);
    } else if(strncmp(pageName, HOSTS_INFO_HTML, strlen(HOSTS_INFO_HTML)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printHostsInfo(sortedColumn, revertOrder, pageNum);
    } else if(strncmp(pageName, PROCESS_INFO_HTML, strlen(PROCESS_INFO_HTML)) == 0) {
      if(myGlobals.isLsofPresent) {
	sendHTTPHeader(HTTP_TYPE_HTML, 0);
	printProcessInfo(sortedColumn /* process PID */, myGlobals.actualReportDeviceId);
      } else {
	returnHTTPpageGone();
	printTrailer=0;
      }
    } else if(strncmp(pageName, STR_LSOF_DATA, strlen(STR_LSOF_DATA)) == 0) {
      if(myGlobals.isLsofPresent) {
	sendHTTPHeader(HTTP_TYPE_HTML, 0);
	printLsofData(sortedColumn);
      } else {
	returnHTTPpageGone();
	printTrailer=0;
      }
    } else if(strcmp(pageName, "NetFlows.html") == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      listNetFlows();
    } else if(strncmp(pageName, IP_R_2_L_HTML, strlen(IP_R_2_L_HTML)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      if(sortedColumn == 0) { sortedColumn = 1; }
      printIpAccounting(REMOTE_TO_LOCAL_ACCOUNTING, sortedColumn, revertOrder, pageNum);
    } else if(strncmp(pageName, IP_L_2_R_HTML, strlen(IP_L_2_R_HTML)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      if(sortedColumn == 0) { sortedColumn = 1; }
      printIpAccounting(LOCAL_TO_REMOTE_ACCOUNTING, sortedColumn, revertOrder, pageNum);
    } else if(strncmp(pageName, IP_L_2_L_HTML, strlen(IP_L_2_L_HTML)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      if(sortedColumn == 0) { sortedColumn = 1; }
      printIpAccounting(LOCAL_TO_LOCAL_ACCOUNTING, sortedColumn, revertOrder, pageNum);
    } else if(strncmp(pageName, "NetNetstat.html", strlen("NetNetstat.html")) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printActiveTCPSessions(myGlobals.actualReportDeviceId, pageNum);
    } else if(strncmp(pageName, STR_MULTICAST_STATS, strlen(STR_MULTICAST_STATS)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printMulticastStats(sortedColumn, revertOrder, pageNum);
    } else if(strncmp(pageName, STR_DOMAIN_STATS, strlen(STR_DOMAIN_STATS)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printDomainStats(NULL, abs(sortedColumn), revertOrder, pageNum);
    } else if(strncmp(pageName, DOMAIN_INFO_HTML, strlen(DOMAIN_INFO_HTML)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printDomainStats(domainNameParm, abs(sortedColumn), revertOrder, pageNum);
    } else if(strcmp(pageName, TRAFFIC_STATS_HTML) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printTrafficStatistics();
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
      printLocalRoutersList(myGlobals.actualReportDeviceId);
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
      if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts > 0) {
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);
	pktSizeDistribPie();
	printTrailer=0;
      } else {
	printNoDataYet();
      }
    } else if(strncmp(pageName, "pktTTLDistribPie", strlen("pktTTLDistribPie")) == 0) {
      if(myGlobals.device[myGlobals.actualReportDeviceId].ipPkts > 0) {
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);
	pktTTLDistribPie();
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
    } else if(strncmp(pageName, "hostsDistanceChart",
		      strlen("hostsDistanceChart")) == 0) {
      sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);
      drawHostsDistanceGraph();
      printTrailer=0;
    } else if(strncmp(pageName, "hostsDistanceChart",
                      strlen("hostsDistanceChart")) == 0) {
      sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);
      drawHostsDistanceGraph();
      printTrailer=0;
    } else if((strncmp(pageName, "hostTrafficDistrib", strlen("hostTrafficDistrib")) == 0)
	      || (strncmp(pageName, "hostFragmentDistrib", strlen("hostFragmentDistrib")) == 0)
	      || (strncmp(pageName, "hostTotalFragmentDistrib", strlen("hostTotalFragmentDistrib")) == 0)
	      || (strncmp(pageName, "hostIPTrafficDistrib", strlen("hostIPTrafficDistrib")) == 0)) {
      char hostName[32], *theHost;
      int idx;

    if(strncmp(pageName, "hostTrafficDistrib", strlen("hostTrafficDistrib")) == 0) {
      idx = 0;
      theHost = &pageName[strlen("hostTrafficDistrib")+1];
    } else if(strncmp(pageName, "hostFragmentDistrib", strlen("hostFragmentDistrib")) == 0) {
      idx = 1;
      theHost = &pageName[strlen("hostFragmentDistrib")+1];
    } else if(strncmp(pageName, "hostTotalFragmentDistrib", strlen("hostTotalFragmentDistrib")) == 0) {
      idx = 2;
      theHost = &pageName[strlen("hostTotalFragmentDistrib")+1];
    } else {
      idx = 3;
      theHost = &pageName[strlen("hostIPTrafficDistrib")+1];
    }

    if(strlen(theHost) <= strlen(CHART_FORMAT)) {
      printNoDataYet();
    } else {
      u_int elIdx, i;
      HostTraffic *el=NULL;

      if(strlen(theHost) >= 31) theHost[31] = 0;
      for(i=strlen(theHost); i>0; i--)
	if(theHost[i] == '?') {
	  theHost[i] = '\0';
	  break;
	}

      memset(hostName, 0, sizeof(hostName));
      strncpy(hostName, theHost, strlen(theHost)-strlen(CHART_FORMAT));

      /* Patch for ethernet addresses and MS Explorer */
      for(i=0; hostName[i] != '\0'; i++)
	if(hostName[i] == '_')
	  hostName[i] = ':';

      /* printf("HostName: '%s'\n", hostName); */

      for(elIdx=1; elIdx<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; elIdx++) {
	el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[elIdx];

	if((elIdx != myGlobals.broadcastEntryIdx)
	   && (el != NULL)
	   && (el->hostNumIpAddress != NULL)
	   && ((strcmp(el->hostNumIpAddress, hostName) == 0)
	       || (strcmp(el->ethAddressString, hostName) == 0)))
	  break;
      }

      if(el == NULL) {
	returnHTTPpageNotFound();
	printTrailer=0;
      } else {
	sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);

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
	  hostIPTrafficDistrib(el, sortedColumn);
	  break;
	}

	printTrailer=0;
      }
    }
#endif /*  HAVE_GDCHART */
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
    } else if(strncmp(pageName, INFO_NTOP_HTML, strlen(INFO_NTOP_HTML)) == 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printNtopConfigInfo(FALSE);
    } else if(strncmp(pageName, TEXT_INFO_NTOP_HTML, strlen(TEXT_INFO_NTOP_HTML)) == 0) {
      sendHTTPHeader(HTTP_TYPE_TEXT, 0);
      printNtopConfigInfo(TRUE);
      printTrailer = 0;
    } else
#endif /* MICRO_NTOP */
      if(strncmp(pageName, DUMP_DATA_HTML, strlen(DUMP_DATA_HTML)) == 0) {
	sendHTTPHeader(HTTP_TYPE_TEXT, 0);
	if((questionMark == NULL) || (questionMark[0] == '\0'))
	  dumpNtopHashes(NULL, NULL, myGlobals.actualReportDeviceId);
	else
	  dumpNtopHashes(NULL, &questionMark[1], myGlobals.actualReportDeviceId);
	printTrailer = 0;
      } else if(strncmp(pageName, DUMP_HOSTS_INDEXES_HTML, strlen(DUMP_HOSTS_INDEXES_HTML)) == 0) {
	sendHTTPHeader(HTTP_TYPE_TEXT, 0);
	if((questionMark == NULL) || (questionMark[0] == '\0'))
	  dumpNtopHashIndexes(NULL, NULL, myGlobals.actualReportDeviceId);
	else
	  dumpNtopHashIndexes(NULL, &questionMark[1], myGlobals.actualReportDeviceId);
	printTrailer = 0;
      } else if(strncmp(pageName, DUMP_NTOP_FLOWS_HTML, strlen(DUMP_NTOP_FLOWS_HTML)) == 0) {
	sendHTTPHeader(HTTP_TYPE_TEXT, 0);
	if((questionMark == NULL) || (questionMark[0] == '\0'))
	  dumpNtopFlows(NULL, NULL, myGlobals.actualReportDeviceId);
	else
	  dumpNtopFlows(NULL, &questionMark[1], myGlobals.actualReportDeviceId);
	printTrailer = 0;
      } else if(strncmp(pageName, DUMP_TRAFFIC_DATA_HTML, strlen(DUMP_TRAFFIC_DATA_HTML)) == 0) {
	sendHTTPHeader(HTTP_TYPE_TEXT, 0);
	if((questionMark == NULL) || (questionMark[0] == '\0'))
	  dumpNtopTrafficInfo(NULL, NULL);
	else
	  dumpNtopTrafficInfo(NULL, &questionMark[1]);
	printTrailer = 0;
      }
#ifndef MICRO_NTOP
      else if(strlen(pageName) > 5) {
	int i;
	char hostName[32];

	pageName[strlen(pageName)-5] = '\0';
	if(strlen(pageName) >= 31) pageName[31] = 0;

	/* Patch for ethernet addresses and MS Explorer */
	for(i=0; pageName[i] != '\0'; i++)
	  if(pageName[i] == '_')
	    pageName[i] = ':';

	strncpy(hostName, pageName, sizeof(hostName));
	sendHTTPHeader(HTTP_TYPE_HTML, 0);
	printAllSessionsHTML(hostName, myGlobals.actualReportDeviceId);
      }
#endif /* !MICRO_NTOP */
      else {
	printTrailer = 0;
	errorCode = HTTP_INVALID_PAGE;
      }
#ifndef MICRO_NTOP
  }
#endif /* !MICRO_NTOP */

  if(domainNameParm != NULL)
    free(domainNameParm);

  if(printTrailer && (postLen == -1)) printHTMLtrailer();

#ifdef MULTITHREADED
    releaseMutex(&myGlobals.hashResizeMutex);
#endif

#if defined(FORK_CHILD_PROCESS) && (!defined(WIN32))
  if(*usedFork) {
    u_int gzipBytesSent = 0;

#ifdef HAVE_ZLIB
    if(compressFile)
      compressAndSendData(&gzipBytesSent);
#endif
    closeNwSocket(&myGlobals.newSock);
    logHTTPaccess(200, httpRequestedAt, gzipBytesSent);
    exit(0);
  } else
    return(errorCode);
#else
  return(errorCode);
#endif
}

/* ************************* */

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
  accessMutex(&myGlobals.gdbmMutex, "checkHTTPpasswd");
#endif
  return_data = gdbm_firstkey(myGlobals.pwFile);
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

    return_data = gdbm_nextkey(myGlobals.pwFile, key_data);
    free(key_data.dptr);
  }

  if(outBuffer[0] == '\0') {
#ifdef MULTITHREADED
    releaseMutex(&myGlobals.gdbmMutex);
#endif
    return 1; /* This is a non protected URL */
  }

  key_data.dptr = outBuffer;
  key_data.dsize = strlen(outBuffer)+1;
  return_data = gdbm_fetch(myGlobals.pwFile, key_data);

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

  if(strlen(user) >= sizeof(theUser)) user[sizeof(theUser)-1] = '\0';
  strcpy(theUser, user);

#ifdef DEBUG
  traceEvent(TRACE_INFO, "User='%s' - Pw='%s'\n", user, thePw);
#endif

  if(snprintf(users, BUF_SIZE, "1%s", user) < 0)
    BufferTooShort();

  if(return_data.dptr != NULL) {
    if(strstr(return_data.dptr, users) == NULL) {
#ifdef MULTITHREADED
      releaseMutex(&myGlobals.gdbmMutex);
#endif
      if(return_data.dptr != NULL) free(return_data.dptr);
      return 0; /* The specified user is not among those who are
		   allowed to access the URL */
    }
    
    free(return_data.dptr);
  }

  key_data.dptr = users;
  key_data.dsize = strlen(users)+1;
  return_data = gdbm_fetch(myGlobals.pwFile, key_data);

  if(return_data.dptr != NULL) {
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
  releaseMutex(&myGlobals.gdbmMutex);
#endif
  return(rc);
}

/* ************************* */

#ifdef HAVE_ZLIB
static void compressAndSendData(u_int *gzipBytesSent) {
  FILE *fd;
  int len;
  char tmpStr[256];

  gzclose(compressFileFd);
  compressFile = 0; /* Stop compression */
  fd = fopen(compressedFilePath, "rb");

  if(fd == NULL) {
    if(gzipBytesSent != NULL)
      (*gzipBytesSent) = 0;
    return;
  }

  sendString("Content-Encoding: gzip\n");
  fseek(fd, 0, SEEK_END);
  if(snprintf(tmpStr, sizeof(tmpStr), "Content-Length: %d\n\n", (len = ftell(fd))) < 0)
    BufferTooShort();
  fseek(fd, 0, SEEK_SET);
  sendString(tmpStr);

#ifdef HAVE_ZLIB
  if(gzipBytesSent != NULL)
    (*gzipBytesSent) = len;
#endif

  for(;;) {
    len = fread(tmpStr, sizeof(char), 255, fd);
    if(len <= 0) break;
    sendStringLen(tmpStr, len);
  }
  fclose(fd);

  unlink(compressedFilePath);
}
#endif /* HAVE_ZLIB */

/* ************************* */

void handleHTTPrequest(struct in_addr from) {
  int skipLeading, postLen, usedFork = 0;
  char requestedURL[URL_LEN], pw[64];
  int rc, i;
  struct timeval httpRequestedAt;
  u_int gzipBytesSent = 0;

  myGlobals.numHandledHTTPrequests++;

  gettimeofday(&httpRequestedAt, NULL);

  requestFrom = &from;
  NTOHL(requestFrom->s_addr);

  for(i=0; i<MAX_NUM_BAD_IP_ADDRESSES; i++) {
    if(myGlobals.weDontWantToTalkWithYou[i].addr.s_addr == from.s_addr) {
      myGlobals.weDontWantToTalkWithYou[i].lastBadAccess = myGlobals.actTime;
      traceEvent(TRACE_ERROR, "Rejected request from address %s (it previously sent ntop a bad request)",
		 _intoa(from, requestedURL, sizeof(requestedURL)));
      return;
    } else if((myGlobals.weDontWantToTalkWithYou[i].lastBadAccess+300 /* 5 minutes */) < myGlobals.actTime) {
      /*
	We 'forget' the address of this nasty guy after 5 minutes
	since its last bad access as we hope that he will be nicer
	with ntop in the future.
      */
      memset(&myGlobals.weDontWantToTalkWithYou[i], 0, sizeof(BadGuysAddr));
    }
  }

  memset(requestedURL, 0, sizeof(requestedURL));
  memset(pw, 0, sizeof(pw));

  httpBytesSent = 0;

#ifdef HAVE_ZLIB
  compressFile = 0;
  compressFileFd = NULL;
  acceptGzEncoding = 0;
#endif

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

  myGlobals.actTime = time(NULL); /* Don't forget this */

  skipLeading = 0;
  while (requestedURL[skipLeading] == '/') {
    skipLeading++;
  }

  if(requestedURL[0] == '\0')
    returnHTTPpageNotFound(0);

  rc = returnHTTPPage(&requestedURL[1], postLen,
		      &from, &httpRequestedAt, &usedFork) ;
  
  if(rc == 0) {
#if defined(HAVE_ZLIB)
    if(compressFile)
      compressAndSendData(&gzipBytesSent);
    else
      gzipBytesSent = 0;
#endif

    if(!usedFork)
      logHTTPaccess(200, &httpRequestedAt, gzipBytesSent);
  } else if(rc == HTTP_FORBIDDEN_PAGE) {
    int found = 0;
    
    /* 
       Let's record the IP address of this nasty
       guy so he will stay far from ntop
       for a while
    */
    for(i=0; i<MAX_NUM_BAD_IP_ADDRESSES-1; i++)
      if(myGlobals.weDontWantToTalkWithYou[MAX_NUM_BAD_IP_ADDRESSES-1].addr.s_addr == from.s_addr) {
	found = 1;
	break;
      }
    
    if(!found) {
      for(i=0; i<MAX_NUM_BAD_IP_ADDRESSES-1; i++) {
	myGlobals.weDontWantToTalkWithYou[i].addr.s_addr   = myGlobals.weDontWantToTalkWithYou[i+1].addr.s_addr;
	myGlobals.weDontWantToTalkWithYou[i].lastBadAccess = myGlobals.weDontWantToTalkWithYou[i+1].lastBadAccess;
      }

      myGlobals.weDontWantToTalkWithYou[MAX_NUM_BAD_IP_ADDRESSES-1].addr.s_addr = from.s_addr;
      myGlobals.weDontWantToTalkWithYou[MAX_NUM_BAD_IP_ADDRESSES-1].lastBadAccess = myGlobals.actTime;
    }

    returnHTTPaccessForbidden(0);
  } else if(rc == HTTP_INVALID_PAGE) {
    returnHTTPpageNotFound(0);
  }
}
