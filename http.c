/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
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

static u_int httpBytesSent;
static char httpRequestedURL[512], theUser[32];
static struct in_addr *requestFrom;
static struct timeval httpRequestedAt;
static FILE *accessLogFd=NULL;

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

  thePw[0] = '\0';
  preLastChar = '\r';
  lastChar = '\n';
  theRequestedURL[0] = '\0';

  wait_time.tv_sec = 10, wait_time.tv_usec = 0;

#ifdef HAVE_OPENSSL
  topSock = abs(newSock);
#else
  topSock = newSock;
#endif

  for(;;) {
    int goodCharType;

    FD_ZERO(&mask);
    FD_SET((unsigned int)topSock, &mask);

    /* printf("About to call select()\n"); fflush(stdout); */

    /* select returns immediately */
    if(select(newSock+1, &mask, 0, 0, &wait_time) == 0)
      return INVALID_HTTP_REQUEST; /* Timeout */

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

    goodCharType = isprint(aChar[0]) || isspace(aChar[0]);

    if(!goodCharType) {
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Rcvd non expected char '%c' [%d]\n", 
		 aChar[0], aChar[0]);
#endif
       return INVALID_HTTP_REQUEST;
    }

    if(rc != 1) {
      idxChar=0;
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Socket read returned %d (errno=%d)\n", rc, errno);
#endif
      break; /* Empty line */
    } else {
      /* traceEvent(TRACE_INFO, "%c", lastChar);  */

      if((aChar[0] == '\n') && (lastChar == '\r') && (preLastChar == '\n')) {
	idxChar=0;
	break;
      } else {
	if(aChar[0] == '\n') {
	  numLine++;
	  lineStr[(idxChar > 0) ? idxChar-1 : idxChar] = '\0';

	  /* traceEvent(TRACE_INFO, "%s [%d]\n", lineStr, idxChar); */

	  if(numLine == 1)
	    strncpy(httpRequestedURL, lineStr, sizeof(httpRequestedURL)-1)[sizeof(httpRequestedURL)-1] = '\0';
 
	  if((idxChar >= 21) && (strncmp(lineStr, "Authorization: Basic ", 21) == 0))
	    strncpy(thePw, &lineStr[21], thePwLen-1)[thePwLen-1] = '\0';
	  else if((idxChar >= 16) && (strncasecmp(lineStr, "Content-length: ", 16) == 0)) {
	    contentLen = atoi(&lineStr[16]);
	    /* traceEvent(TRACE_INFO, "len=%d [%s/%s]\n", 
	       contentLen, lineStr, &lineStr[16]); */
	  } else if((numLine == 1) && (idxChar >= 3) && (strncmp(lineStr, "GET ", 4) == 0)) {
	    strncpy(theRequestedURL, &lineStr[4], theRequestedURLLen-1)[theRequestedURLLen-1] = '\0';
	  } else if((numLine == 1) && (idxChar >= 3) && (strncmp(lineStr, "POST ", 5) == 0)) {
	    strncpy(theRequestedURL, &lineStr[5], theRequestedURLLen-1)[theRequestedURLLen-1] = '\0';
	  } else if(numLine == 1) {
	    return(INVALID_HTTP_REQUEST);
	  }
	  idxChar=0;
	} else {
	  if(idxChar < 512)
	    lineStr[idxChar++] = aChar[0];
	  else {
#ifdef DEBUG
	    traceEvent(TRACE_INFO, "Line too long (hackers ?)");
#endif
	    return INVALID_HTTP_REQUEST; 
	  }
	}

	preLastChar = lastChar;
	lastChar = aChar[0];
      }
    }
  }

  return(contentLen);
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

  while(len > 0)
    {
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

      if((errno != 0) || (rc < 0))
	{
#ifdef DEBUG
	  traceEvent(TRACE_INFO, "Socket write returned %d (errno=%d)\n", rc, errno);
#endif
	  if((errno == EAGAIN /* Resource temporarily unavailable */) && (retries<3))
	    {
	      len -= rc;
	      bytesSent += rc;
	      retries++;
	      goto RESEND;
	    }
	  else if (errno == EPIPE /* Broken pipe: the  client has disconnected */)
	    {
	      closeNwSocket(&newSock);
	      return;
	    }
	  else if (errno == EBADF /* Bad file descriptor: a
				     disconnected client is still sending */) {
	    closeNwSocket(&newSock);
	    return;
	  } else {
	    closeNwSocket(&newSock);
	    return;
	  }
	}
      else
	{
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

void printHTTPheader(void) {
  char buf[BUF_SIZE];

  sendString("<HTML>\n<HEAD>\n<META HTTP-EQUIV=REFRESH CONTENT=");
  snprintf(buf, BUF_SIZE, "%d", refreshRate);
  sendString(buf);
  sendString(">\n<LINK REL=stylesheet HREF=/style.css type=\"text/css\">\n");
  sendString("<META HTTP-EQUIV=Pragma CONTENT=no-cache>\n");
  sendString("<META HTTP-EQUIV=Cache-Control CONTENT=no-cache>\n");
  sendString("</HEAD>\n<BODY BACKGROUND=/white_bg.gif>\n");
}

/* ************************* */

void printHTTPtrailer(void) {
  char buf2[BUF_SIZE];
  int i;

  sendString("\n</CENTER><hr><FONT FACE=Helvetica>");

  snprintf(buf2, BUF_SIZE, "<H5>Report created on %s [%s]<br>\n", 
	  ctime(&actTime), formatSeconds(actTime-initialSniffTime));
  sendString(buf2);

  snprintf(buf2, BUF_SIZE, "Generated by <A HREF=\"http://www.ntop.org/\">"
	  "ntop</A> v.%s %s [%s] (%s build)"
	  " listening on [",
	  version, THREAD_MODE, osName, buildDate);
  sendString(buf2);

  if(rFileName != NULL)
    sendString(PCAP_NW_INTERFACE);
  else
    for(i=0; i<numDevices; i++) {
      if(i>0) { sendString(","); }
      sendString(device[i].name);
    }

  sendString("]\n<br>\n<address>&copy; 1998-2000 by <A HREF=mailto:deri@ntop.org>L. Deri</A>"
	     "</H5></font></BODY></HTML>\n");
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

 if(accessLogFd != NULL) {
   gettimeofday(&loggingAt, NULL);

   msSpent = (unsigned long)(delta_time(&loggingAt, &httpRequestedAt)/1000);
 
   strftime(theDate, 32, "%d/%b/%Y:%H:%M:%S +0000", localtime_r(&actTime, &t));

   if((theUser == NULL)
      || (theUser[0] == '\0'))
     strncpy(myUser, " ", 64);
   else
     snprintf(myUser, sizeof(myUser), " %s ", theUser);

   NTOHL(requestFrom->s_addr);
 
   fprintf(accessLogFd, "%s -%s- [%s] - \"%s\" %d %d %lu\n", 
	   _intoa(*requestFrom, buf, sizeof(buf)),
	   myUser, theDate, 
	   httpRequestedURL, rc, httpBytesSent,
	   msSpent);
   fflush(accessLogFd);
 }
}

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
  snprintf(tmpStr, sizeof(tmpStr), "Server: ntop/%s (%s)\n", version, osName);
  sendString(tmpStr);
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

  if(rc == 0)
    return(rc);
  else {
    returnHTTPaccessForbidden();
    return(-1);
  }
}

/* ************************* */

static void returnHTTPPage(char* pageName, int postLen) {
  char *questionMark = strchr(pageName, '?');
  int sortedColumn, printTrailer=1, idx;
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
    return;

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
    traceEvent(TRACE_INFO, "sortedColumn: %d - revertOrder: %d\n", sortedColumn, revertOrder);
  */

  if(pageName[0] == '\0')
    strncpy(pageName, STR_INDEX_HTML, sizeof(STR_INDEX_HTML));

  /* Search in the local directory first... */
  for(idx=0; dataFileDirs[idx] != NULL; idx++) {
    snprintf(tmpStr, sizeof(tmpStr), "%s/html/%s", dataFileDirs[idx], pageName);

#ifdef WIN32
    i=0;
    while(tmpStr[i] != '\0') {
      if(tmpStr[i] == '/') tmpStr[i] = '\\';
      i++;
    }
#endif

    if((fd = fopen(tmpStr, "rb")) != NULL)
      break;
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "tmpStr=%s - fd=0x%x\n", tmpStr, fd);
#endif

  if(fd != NULL) {
    int len = strlen(pageName);

    if((len > 4)
       && ((strcmp(&pageName[len-4], ".gif") == 0)
	   || (strcmp(&pageName[len-4], ".jpg") == 0))) {
      char theDate[48];
      time_t theTime;
      struct tm t;

      sendHTTPProtoHeader();

      theTime = actTime;

      strftime(theDate, 32, "%a, %d %b %Y %H:%M:%S GMT", localtime_r(&theTime, &t));
      snprintf(tmpStr, sizeof(tmpStr), "Date: %s\n", theDate);
      sendString(tmpStr);

      theTime += 3600;

      strftime(theDate, 32, "%a, %d %b %Y %H:%M:%S GMT", localtime_r(&theTime, &t));
      snprintf(tmpStr, sizeof(tmpStr), "Expires: %s\n", theDate);
      sendString(tmpStr);

      sendString("Cache-Control: max-age=3600, must-revalidate, public\n");

      if(strcmp(&pageName[len-4], ".gif") == 0)
	sendString("Content-type: image/gif\n");
      else
	sendString("Content-type: image/jpeg\n");

      fseek(fd, 0, SEEK_END);
      snprintf(tmpStr, sizeof(tmpStr), "Content-Length: %d\n\n", (len = ftell(fd)));
      fseek(fd, 0, SEEK_SET);
      sendString(tmpStr);

    } else if((len > 4) && ((strcmp(&pageName[len-4], ".css") == 0))) {
      sendHTTPProtoHeader();
      sendString("Content-type: text/css\n");
    } else {
      sendHTTPProtoHeader();
      sendHTTPHeaderType();
    }

    for(;;) {
      len = fread(tmpStr, sizeof(char), 255, fd);
      if(len <= 0) break;
      sendStringLen(tmpStr, len);
    }

    fclose(fd);
    /* closeNwSocket(&newSock); */
    return;
  }

#ifndef WIN32
#ifdef  USE_CGI
  if(strncmp(pageName, CGI_HEADER, strlen(CGI_HEADER)) == 0) {
    execCGI(&pageName[strlen(CGI_HEADER)]);
    return;
  }
#endif /* USE_CGI */
#endif

  if((strncmp(pageName, PLUGINS_HEADER, strlen(PLUGINS_HEADER)) == 0)
     && handlePluginHTTPRequest(&pageName[strlen(PLUGINS_HEADER)]))
    return;

  /*
    Putting this here (and not on top of this function)
    helps because at least a partial respose
    has been send back to the user in the meantime
  */
#ifdef MULTITHREADED
  accessMutex(&hashResizeMutex, "returnHTTPpage"); 
#endif

  if(strcmp(pageName, STR_INDEX_HTML) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    sendString("<html>\n");
    sendString("<title>Welcome to ntop!</title>\n");
    sendString("<frameset cols=160,* framespacing=0 border=0 frameborder=0>\n");
    sendString("    <frame src=leftmenu.html name=Menu marginwidth=0 marginheight=0>\n");
    sendString("    <frame src=home.html name=area marginwidth=5 marginheight=0>\n");
    sendString("    <noframes>\n");
    sendString("    <body>\n\n");
    sendString("    </body>\n");
    sendString("    </noframes>\n");
    sendString("</frameset>\n");
    sendString("</html>\n");
  } else if((strcmp(pageName, "leftmenu.html") == 0)
	    || (strcmp(pageName, "leftmenu-nojs.html") == 0)) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    sendString("<HTML>\n<BODY BACKGROUND=/white_bg.gif>\n"
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
    sendString("<li><a href=thptStats.html target=area ALT=\"Throughput Statistics\">"
	       "Thpt Stats</a></li>\n");
    sendString("<li><a href="HOSTS_INFO_HTML" target=area ALT=\"Hosts Information\">"
	       "Hosts Info</a></li>\n");
    sendString("<li><a href=IpR2L.html target=area ALT=\"Remote to Local IP Traffic\">"
	       "R-&gt;L IP Traffic</a></li>\n");
    sendString("<li><a href=IpL2R.html target=area ALT=\"Local to Remote IP Traffic\">"
	       "L-&gt;R IP Traffic</a></li>\n");
    sendString("<li><a href=IpL2L.html target=area ALT=\"Local IP Traffic\">"
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
      sendString("<li><a href=switch.html target=area ALT=\"Switch NICs\">Switch NICs</a></li>\n");

    sendString("<li><a href="SHUTDOWN_NTOP_HTML" target=area ALT=\"Shutdown ntop\">"
	       "Shutdown ntop</a></li>\n");
    sendString("<li><a href=ntop.html target=area ALT=\"Man Page\">Man Page</a></li>\n");
    sendString("<li><a href=Credits.html target=area ALT=\"Credits\">Credits</a></li>\n");
    sendString("</ol>\n<center>\n<b>\n\n");
    sendString("<pre>\n</pre>&copy; 1998-2000<br>by<br>"
	       "<A HREF=\"http://jake.unipi.it/~deri/\" target=\"area\">"
	       "Luca Deri</A></FONT><pre>\n");
    sendString("</pre>\n</b>\n</center>\n</body>\n</html>\n");
    printTrailer=0;
  } else if(strcmp(pageName, "switch.html") == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    switchNwInterface(sortedColumn);
  } else if(strcmp(pageName, "home.html") == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    sendString("<html>\n<body BACKGROUND=/white_bg.gif><CENTER><FONT FACE=Helvetica>"
	       "<H1>Welcome to ntop!</H1></center><hr>");
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
    sendString("</font>\n");
  } else if(strncmp(pageName, STR_SORT_DATA_RECEIVED_PROTOS, 
		    strlen(STR_SORT_DATA_RECEIVED_PROTOS)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHostsTraffic(0, 0, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_RECEIVED_IP, strlen(STR_SORT_DATA_RECEIVED_IP)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHostsTraffic(0, 1, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_THPT_STATS, strlen(STR_SORT_DATA_THPT_STATS)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printThptStats(sortedColumn);
  } else if(strncmp(pageName, STR_THPT_STATS_MATRIX, strlen(STR_THPT_STATS_MATRIX)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printThptStatsMatrix(sortedColumn);
  } else if(strncmp(pageName, STR_SORT_DATA_RECEIVED_THPT, strlen(STR_SORT_DATA_RECEIVED_THPT)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    if(sortedColumn == 0) { sortedColumn = HOST_DUMMY_IDX_VALUE; }
    printHostsTraffic(0, 2, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_RCVD_HOST_TRAFFIC, strlen(STR_SORT_DATA_RCVD_HOST_TRAFFIC)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    if(sortedColumn == 0) { sortedColumn = HOST_DUMMY_IDX_VALUE; }
    printHostsTraffic(0, 3, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_SENT_HOST_TRAFFIC, strlen(STR_SORT_DATA_SENT_HOST_TRAFFIC)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    if(sortedColumn == 0) { sortedColumn = HOST_DUMMY_IDX_VALUE; }
    printHostsTraffic(1, 3, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_SENT_PROTOS, strlen(STR_SORT_DATA_SENT_PROTOS)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHostsTraffic(1, 0, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_SENT_IP, strlen(STR_SORT_DATA_SENT_IP)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHostsTraffic(1, 1, sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_SORT_DATA_SENT_THPT, strlen(STR_SORT_DATA_SENT_THPT)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    if(sortedColumn == 0) { sortedColumn = HOST_DUMMY_IDX_VALUE; }
    printHostsTraffic(1, 2, sortedColumn, revertOrder);
  } else if(strncmp(pageName, HOSTS_INFO_HTML, strlen(HOSTS_INFO_HTML)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHostsInfo(sortedColumn, revertOrder);
  }
  else if(isLsofPresent
	  && (strncmp(pageName, PROCESS_INFO_HTML, strlen(PROCESS_INFO_HTML)) == 0)) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printProcessInfo(sortedColumn /* process PID */);
  } else if(isLsofPresent
	    && (strncmp(pageName, STR_LSOF_DATA, strlen(STR_LSOF_DATA)) == 0)) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printLsofData(sortedColumn);
  }
  else if(strcmp(pageName, "NetFlows.html") == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    listNetFlows();
  }
  else if(strncmp(pageName, IP_R_2_L_HTML, strlen(IP_R_2_L_HTML)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHTTPheader();
    sendString("<CENTER><p><H1><FONT FACE=Helvetica>Remote to Local IP Traffic</FONT></H1><p>\n");
    if(sortedColumn == 0) { sortedColumn = 1; }
    printIpAccounting(REMOTE_TO_LOCAL_ACCOUNTING, sortedColumn, revertOrder);
    sendString("</CENTER>\n");
  } else if(strncmp(pageName, IP_L_2_R_HTML, strlen(IP_L_2_R_HTML)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHTTPheader();
    sendString("<CENTER><p><H1><FONT FACE=Helvetica>Local to Remote IP Traffic</FONT></H1><p>\n");
    if(sortedColumn == 0) { sortedColumn = 1; }
    printIpAccounting(LOCAL_TO_REMOTE_ACCOUNTING, sortedColumn, revertOrder);
    sendString("</CENTER>\n");
  } else if(strncmp(pageName, IP_L_2_L_HTML, strlen(IP_L_2_L_HTML)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHTTPheader();
    sendString("<CENTER><p><H1><FONT FACE=Helvetica>Local IP Traffic</FONT></H1><p>\n");
    if(sortedColumn == 0) { sortedColumn = 1; }
    printIpAccounting(LOCAL_TO_LOCAL_ACCOUNTING, sortedColumn, revertOrder);
    sendString("</CENTER>\n");
  } else if(strcmp(pageName, "NetNetstat.html") == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHTTPheader();
    sendString("<CENTER><p><H1><FONT FACE=Helvetica>Active TCP Sessions</FONT></H1><p>\n");
    printActiveTCPSessions();
    sendString("</CENTER>\n");
  } else if(strncmp(pageName, SHUTDOWN_NTOP_HTML, strlen(SHUTDOWN_NTOP_HTML)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType(); printHTTPheader();
    sendString("<CENTER><p><H1><FONT FACE=Helvetica>ntop is shutting down...</FONT></H1><p>\n");
    sendString("</CENTER>\n");
    shutdownNtop();
  } else if(strncmp(pageName, RESET_STATS_HTML, strlen(RESET_STATS_HTML)) == 0) {
    /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
    sendHTTPProtoHeader(); sendHTTPHeaderType(); printHTTPheader();
    resetStats();
    sendString("<CENTER><p><H1><FONT FACE=Helvetica>"
	       "All statistics are now reseted</FONT></H1><p>\n");
    sendString("</CENTER>\n");
  } else if(strncmp(pageName, STR_MULTICAST_STATS, strlen(STR_MULTICAST_STATS)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printMulticastStats(sortedColumn, revertOrder);
  } else if(strncmp(pageName, STR_DOMAIN_STATS, strlen(STR_DOMAIN_STATS)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printDomainStats(NULL, abs(sortedColumn), revertOrder);
  } else if(strncmp(pageName, STR_SHOW_PLUGINS, strlen(STR_SHOW_PLUGINS)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHTTPheader();
    if(questionMark == NULL)
      showPluginsList("");
    else
      showPluginsList(&pageName[strlen(STR_SHOW_PLUGINS)+1]);
  } else if(strncmp(pageName, DOMAIN_INFO_HTML, strlen(DOMAIN_INFO_HTML)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    if(questionMark == NULL) questionMark = "";
    pageName[strlen(pageName)-5-strlen(questionMark)] = '\0';
    printDomainStats(&pageName[strlen(DOMAIN_INFO_HTML)+1], abs(sortedColumn), revertOrder);
  } else if(strcmp(pageName, TRAFFIC_STATS_HTML) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHTTPheader();
    printHostsTraffic(2, 0, 0, revertOrder);
    printProtoTraffic();
    sendString("<p>\n");
    printIpProtocolDistribution(LONG_FORMAT, revertOrder);
    sendString("<p>\n");
  } else if(strcmp(pageName, "ipProtoDistrib.html") == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHTTPheader();
    printIpProtocolDistribution(SHORT_FORMAT, revertOrder);
  } else if(strcmp(pageName, "ipTrafficMatrix.html") == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHTTPheader();
    sendString("<CENTER><p><H1><FONT FACE=Helvetica>IP Subnet Traffic Matrix</FONT></H1><p>\n");
    printIpTrafficMatrix();
  } else if(strcmp(pageName, "localRoutersList.html") == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHTTPheader();
    printLocalRoutersList();
  } else if(strcmp(pageName, "ipProtoUsage.html") == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHTTPheader();
    sendString("<CENTER><p><H1><FONT FACE=Helvetica>IP Protocol Subnet Usage</FONT></H1><p>\n");
    printIpProtocolUsage();
#ifdef HAVE_GDCHART
  } else if(strncmp(pageName, "thptGraph", strlen("thptGraph")) == 0) {
    sendHTTPProtoHeader(); sendGIFHeaderType();
    drawThptGraph(sortedColumn);
  } else if(strncmp(pageName, "ipTrafficPie", strlen("ipTrafficPie")) == 0) {
    sendHTTPProtoHeader(); sendGIFHeaderType();
    drawTrafficPie();
  } else if(strncmp(pageName, "pktCastDistribPie", strlen("pktCastDistribPie")) == 0) {
    sendHTTPProtoHeader(); sendGIFHeaderType();
    pktCastDistribPie();
  } else if(strncmp(pageName, "pktSizeDistribPie", strlen("pktSizeDistribPie")) == 0) {
    sendHTTPProtoHeader(); sendGIFHeaderType();
    pktSizeDistribPie();
  } else if(strncmp(pageName, "ipProtoDistribPie", strlen("ipProtoDistribPie")) == 0) {
    sendHTTPProtoHeader(); sendGIFHeaderType();
    ipProtoDistribPie();
  } else if(strncmp(pageName, "interfaceTrafficPie", strlen("interfaceTrafficPie")) == 0) {
    sendHTTPProtoHeader(); sendGIFHeaderType();
    interfaceTrafficPie();
  } else if(strncmp(pageName, "drawGlobalProtoDistribution",
		    strlen("drawGlobalProtoDistribution")) == 0) {
    sendHTTPProtoHeader(); sendGIFHeaderType();
    drawGlobalProtoDistribution();
  } else if(strncmp(pageName, "drawGlobalIpProtoDistribution",
		    strlen("drawGlobalIpProtoDistribution")) == 0) {
    sendHTTPProtoHeader(); sendGIFHeaderType();
    drawGlobalIpProtoDistribution();
#endif
  } else if(strncmp(pageName, NW_EVENTS_HTML, strlen(NW_EVENTS_HTML)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHostEvents(NULL, sortedColumn, revertOrder);
  } else if(strcmp(pageName, "Credits.html") == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    sendString("<HTML>\n<BODY BACKGROUND=/white_bg.gif>\n<FONT FACE=Helvetica>\n");
    sendString("<H1><center>Credits</H1></center><p><hr><br><b>ntop</b> has been created by\n");
    sendString("<A HREF=\"http://jake.unipi.it/~deri/\">Luca Deri</A> while studying how to model\n");
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
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    showUsers();
  } else if(strcmp(pageName, "addUser.html") == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    addUser(NULL);
  } else if(strncmp(pageName, "modifyUser", strlen("modifyUser")) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    if((questionMark == NULL) || (questionMark[0] == '\0'))
      addUser(NULL);
    else
      addUser(&questionMark[1]);
  } else if(strncmp(pageName, "deleteUser", strlen("deleteUser")) == 0) {
    if((questionMark == NULL) || (questionMark[0] == '\0'))
      deleteUser(NULL);
    else
      deleteUser(&questionMark[1]);
  } else if(strcmp(pageName, "doAddUser") == 0) {
    printTrailer=0;
    doAddUser(postLen /* \r\n */);
  } else if(strcmp(pageName, "showURLs.html") == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    showURLs();
  } else if(strcmp(pageName, "addURL.html") == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    addURL(NULL);
  } else if(strncmp(pageName, "modifyURL", strlen("modifyURL")) == 0) {
    if((questionMark == NULL) || (questionMark[0] == '\0')) {
      sendHTTPProtoHeader(); sendHTTPHeaderType();
      addURL(NULL);
    } else
      addURL(&questionMark[1]);
  } else if(strncmp(pageName, "deleteURL", strlen("deleteURL")) == 0) {
    if((questionMark == NULL) || (questionMark[0] == '\0'))
      deleteURL(NULL);
    else
      deleteURL(&questionMark[1]);
  } else if(strncmp(pageName, INFO_NTOP_HTML, strlen(INFO_NTOP_HTML)) == 0) {
    sendHTTPProtoHeader(); sendHTTPHeaderType(); printHTTPheader();
    printNtopConfigInfo();
  } else if(strcmp(pageName, "doAddURL") == 0) {
    printTrailer=0;
    doAddURL(postLen /* \r\n */);
#endif /* HAVE_GDBM_H */
  } else if(strlen(pageName) > 5) {
    int i;
    char hostName[32];

    pageName[strlen(pageName)-5] = '\0';

    /* Patch for ethernet addresses and MS Explorer */
    for(i=0; pageName[i] != '\0'; i++)
      if(pageName[i] == '_')
	pageName[i] = ':';

    strncpy(hostName, pageName, sizeof(hostName));
    sendHTTPProtoHeader();
    sendHTTPHeaderType();
    printHTTPheader();
    printAllSessionsHTML(hostName);
    sendString("</CENTER>\n");
  } else {
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    printHTTPheader();
    sendString("<HTML>\n<TITLE>???</TITLE>\n<BODY BACKGROUND=white_bg.gif>\n<H1>Error</H1>\nUnknown page\n");
  }

  if(printTrailer && (postLen == -1)) printHTTPtrailer();

#ifdef MULTITHREADED
  releaseMutex(&hashResizeMutex);
#endif
}

/* ************************* */

#if 0
/* similar to Java.String.trim() */
void trimString(char* str) {
  int len = strlen(str), i, idx;
  char *out = (char *) malloc(sizeof(char) * (len+1));
  
  if(out == NULL) {
    str = NULL;
    return;
  }

  for(i=0, idx=0; i<len; i++)
    {
      switch(str[i])
	{
	case ' ':
	case '\t':
	  if((idx > 0)
	     && (out[idx-1] != ' ')
	     && (out[idx-1] != '\t'))
	    out[idx++] = str[i];
	  break;
	default:
	  out[idx++] = str[i];
	  break;
	}
    }

  out[idx] = '\0';
  strncpy(str, out, len);
  free(out);
}
#endif  /* #if 0 */

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

  snprintf(users, BUF_SIZE, "1%s", user);

  if(strstr(return_data.dptr, users) == NULL) {
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif
    return 0; /* The specified user is not among those who are
		 allowed to access the URL */
  }

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
}
#endif

/* ************************* */

static void returnHTTPnotImplemented(void) {
  sendString("HTTP/1.0 501 Not Implemented\n");
  sendString("Connection: close\n");
  sendString("Content-Type: text/html\n\n");
  sendString("<HTML>\n<TITLE>Error</TITLE>\n<BODY BACKGROUND=white_bg.gif>\n"
	     "<H1>Error 501</H1>\nMethod not implemented\n</BODY>\n</HTML>\n");

  logHTTPaccess(501);
}

/* ************************* */

void handleHTTPrequest(struct in_addr from) {
  int postLen;
  char requestedURL[512], pw[64];

  gettimeofday(&httpRequestedAt, NULL);

  requestFrom = &from;

  memset(requestedURL, 0, sizeof(requestedURL));
  memset(pw, 0, sizeof(pw));

  httpBytesSent = 0;

  postLen = readHTTPheader(requestedURL, sizeof(requestedURL), pw, sizeof(pw));

  if(postLen == INVALID_HTTP_REQUEST) {
    /* Courtesy of Vanja Hrustic <vanja@relaygroup.com> */
    returnHTTPnotImplemented();
    return;
  }

  if(checkHTTPpassword(requestedURL, sizeof(requestedURL), pw, sizeof(pw) ) != 1) {
    returnHTTPaccessDenied();
    return;
  }

#ifdef DEBUG
  fprintf(stdout, "URL = '%s'\n", requestedURL); 
#endif
  
  actTime = time(NULL); /* Don't forget this */

  /*
    Fix courtesy of  
    Michael Wescott <wescott@crosstor.com>
  */
  if((requestedURL[0] == '\0') || (requestedURL[0] == '/')) {
    int len = strlen(requestedURL);

    if(len >= 9) requestedURL[len-9] = '\0';
    returnHTTPPage(&requestedURL[1], postLen);
  } else {
    char buf[64];
    
    sendString("HTTP/1.0 200 OK\n");
    snprintf(buf, sizeof(buf), "Server: ntop/%s (%s)\n", version, osName);
    sendString(buf);
    sendHTTPProtoHeader(); sendHTTPHeaderType();
    sendString("<HTML>\n<TITLE>???</TITLE>\n<BODY BACKGROUND=/white_bg.gif>\n"
	       "<H1>Error</H1>\nUnkown page\n</BODY>\n</HTML>\n");
  }

  logHTTPaccess(200);
}

