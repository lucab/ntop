/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 *		  	  Centro SERRA, University of Pisa
 *		 	  http://www.ntop.org/
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

#ifndef WIN32
#include <pwd.h>
#endif

/* Forward */
void handleSingleWebConnection(fd_set *fdmask);

/* **************************************** */

void initializeWeb() {
  columnSort = 0;
  addDefaultAdminUser();
  initAccessLog();
}

/* **************************************** */

void* handleWebConnections(void* notUsed) {
#ifndef MULTITHREADED
  struct timeval wait_time;
#else
  int rc;
#endif
  fd_set mask, mask_copy;
  int topSock = sock;

  FD_ZERO(&mask);

  if(webPort > 0) 
    FD_SET((unsigned int)sock, &mask);

#ifdef HAVE_OPENSSL
  if(sslInitialized) {
    FD_SET(sock_ssl, &mask);
    if(sock_ssl > topSock)
      topSock = sock_ssl;
  }
#endif

  memcpy(&mask_copy, &mask, sizeof(fd_set));

#ifndef MULTITHREADED
  /* select returns immediately */
  wait_time.tv_sec = 0, wait_time.tv_usec = 0;
  if(select(topSock+1, &mask, 0, 0, &wait_time) == 1)
    handleSingleWebConnection(&mask);
#else
  while(capturePackets) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Select(ing)....\n");
#endif
    memcpy(&mask, &mask_copy, sizeof(fd_set));
    rc = select(topSock+1, &mask, 0, 0, NULL /* Infinite */);
#ifdef DEBUG
    traceEvent(TRACE_INFO, "select returned: %d\n", rc);
#endif
    if(rc > 0)
      handleSingleWebConnection(&mask);
  }
#endif

return(NULL); /* NOTREACHED */
}


/* ************************************* */

#ifndef WIN32
#ifdef  USE_CGI
void execCGI(char* cgiName) {
  char* userName = "nobody", line[384], buf[256];
  struct passwd * newUser = NULL;
  FILE *fd;
  int num, i;

  if(!(newUser = getpwnam(userName))) {
    traceEvent(TRACE_WARNING, "WARNING: unable to find user %s\n", userName);
    return;
  } else {
    setgid(newUser->pw_gid);
    setuid(newUser->pw_uid);
  }

  for(num=0, i=0; cgiName[i] != '\0'; i++)
    if(cgiName[i] == '?') {
      cgiName[i] = '\0';
      snprintf(buf, sizeof(buf), "QUERY_STRING=%s", &cgiName[i+1]);
      putenv(buf);
      num = 1;
      break;
    }

  if(num == 0) putenv("QUERY_STRING=");

  snprintf(line, sizeof(line), "%s/cgi/%s", getenv("PWD"), cgiName);

  if((fd = sec_popen(line, "r")) == NULL) {
    traceEvent(TRACE_WARNING, "WARNING: unable to exec %s\n", cgiName);
    return;
  } else {
    while(!feof(fd)) {
      num = fread(line, 1, 383, fd);
      if(num > 0)
	sendStringLen(line, num);
    }
    fclose(fd);
  }
}
#endif /* USE_CGI */
#endif
 
/* **************************************** */
 
#if (defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H)) || defined(WIN32) || defined(HPUX) || defined(AIX)
 void showPluginsList(char* pluginName) {
   FlowFilterList *flows = flowsList;
   short printHeader = 0;
   char tmpBuf[BUF_SIZE], *thePlugin;
   int newPluginStatus;
   
   if(pluginName[0] != '\0') {
    int i;
    
    thePlugin = pluginName;
    
    for(i=0; pluginName[i] != '\0'; i++)
      if(pluginName[i] == '=') {
	pluginName[i] = '\0';
	newPluginStatus = atoi(&pluginName[i+1]);
	break;
      }
  } else
    thePlugin = NULL;

  while(flows != NULL) {
    if((flows->pluginStatus.pluginPtr != NULL)
       && (flows->pluginStatus.pluginPtr->pluginURLname != NULL)) {

      if(thePlugin
	 && (strcmp(flows->pluginStatus.pluginPtr->pluginURLname, thePlugin) == 0))
	flows->pluginStatus.activePlugin = newPluginStatus;

      if(!printHeader) {
	/* printHTTPheader(); */
	sendString("<center><H1>Available Plugins</H1>\n<p>"
		   "<TABLE BORDER><TR>\n");
	sendString("<TR><TH>Name</TH><TH>Description</TH>"
		   "<TH>Version</TH>"
		   "<TH>Author</TH>"
		   "<TH>Active</TH>"
		   "</TR>\n");
	printHeader = 1;
      }

      snprintf(tmpBuf, sizeof(tmpBuf), "<TR %s><TH ALIGN=LEFT><A HREF=/plugins/%s>%s</TH>"
	      "<TD ALIGN=LEFT>%s</TD>"
	      "<TD ALIGN=CENTER>%s</TD>"
	      "<TD ALIGN=LEFT>%s</TD>"
	      "<TD ALIGN=CENTER><A HREF="STR_SHOW_PLUGINS"?%s=%d>%s</A></TD>"
	      "</TR>\n",
	      getRowColor(),
	      flows->pluginStatus.pluginPtr->pluginURLname,
	      flows->pluginStatus.pluginPtr->pluginURLname,
	      flows->pluginStatus.pluginPtr->pluginDescr,
	      flows->pluginStatus.pluginPtr->pluginVersion,
	      flows->pluginStatus.pluginPtr->pluginAuthor,
	      flows->pluginStatus.pluginPtr->pluginURLname,
	      flows->pluginStatus.activePlugin ? 0: 1,
	      flows->pluginStatus.activePlugin ? 
	      "Yes" : "<FONT COLOR=#FF0000>No</FONT>");
      sendString(tmpBuf);
    }

    flows = flows->next;
  }

  if(!printHeader) {
   sendString("<HTML><BODY BACKGROUND=white_bg.gif BGCOLOR=#FFFFFF><P><CENTER><H1>"
	       "<i>No Plugins available</i></H1>"
	      "</CENTER></FONT></CENTER><p>\n");
  } else {
    sendString("</TABLE><p>\n");
  }
 }

#else /* defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H) */

 void showPluginsList(char* pluginName) {
   ;
 }
 
 void loadPlugins() {
   ;
 }
 
 void unloadPlugins() {
   ;
 }
 
#endif /* defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H) */
 
 /* ************************************* */
 
 void handleSingleWebConnection(fd_set *fdmask) {
   struct sockaddr_in from;
  int from_len = sizeof(from);

  if(FD_ISSET(sock, fdmask)) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Accepting HTTP request...\n");
#endif
    newSock = accept(sock, (struct sockaddr*)&from, &from_len);
  } else {
#ifdef DEBUG
    if(sslInitialized)
      traceEvent(TRACE_INFO, "Accepting HTTPS request...\n");
#endif
#ifdef HAVE_OPENSSL
    if(sslInitialized)
      newSock = accept(sock_ssl, (struct sockaddr*)&from, &from_len); 
#else
    ;
#endif
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Request accepted (sock=%d)\n", newSock);
#endif

  if(newSock > 0) {
#ifdef HAVE_OPENSSL
    if(sslInitialized) 
      if(FD_ISSET(sock_ssl, fdmask))
	if(accept_ssl_connection(newSock) == -1) {
	  traceEvent(TRACE_WARNING, "Unable to accept SSL connection\n");
	  closeNwSocket(&newSock);
	  return;
	} else {
	  newSock = -newSock;
	}
#endif /* HAVE_OPENSSL */

#ifdef HAVE_LIBWRAP
    {
      struct request_info req;
      request_init(&req, RQ_DAEMON, DAEMONNAME, RQ_FILE, newSock, NULL);
      fromhost(&req);
      if (!hosts_access(&req)) {
	closelog(); /* just in case */
	openlog(DAEMONNAME,LOG_PID,SYSLOG_FACILITY);
	syslog(deny_severity, "refused connect from %s", eval_client(&req));
      }
      else
	handleHTTPrequest(from.sin_addr);
    }
#else
    handleHTTPrequest(from.sin_addr);
#endif /* HAVE_LIBWRAP */

    closeNwSocket(&newSock);

  }
}

/* ******************************* */

void initWeb(int webPort, char* webAddr) {
  int sockopt = 1;
  struct sockaddr_in sin;

  actualReportDeviceId = 0;

#ifdef DEBUG
  numChildren = 0;
#endif

  if(webPort > 0) {
    sin.sin_family      = AF_INET;
    sin.sin_port        = (int)htons((unsigned short int)webPort);
    sin.sin_addr.s_addr = INADDR_ANY;

#ifndef WIN32
    if (webAddr) {      /* Code added to be able to bind to a particular interface */
      if (!inet_aton(webAddr,&sin.sin_addr))
	traceEvent(TRACE_ERROR, "Unable to convert address '%s'...\n"
		   "Not binding to a particular interface!\n",  webAddr);
    }
#endif

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {
      traceEvent(TRACE_ERROR, "Unable to create a new socket");
      exit(-1);
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));
  } else
    sock = 0;

#ifdef HAVE_OPENSSL
  if(sslInitialized) {
    sock_ssl = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_ssl < 0) {
      traceEvent(TRACE_ERROR, "unable to create a new socket");
      exit(-1);
    }
      
    setsockopt(sock_ssl, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));
  }
#endif

  if(webPort > 0) {
    if(bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
      traceEvent(TRACE_WARNING, "bind: port %d already in use.", webPort);
      closeNwSocket(&sock);
      exit(-1);
    }
  }

#ifdef HAVE_OPENSSL
  if(sslInitialized) {
    sin.sin_family      = AF_INET;
    sin.sin_port        = (int)htons(sslPort);
    sin.sin_addr.s_addr = INADDR_ANY;
      
    if(bind(sock_ssl, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
      traceEvent(TRACE_ERROR, "bind: port %d already in use.", webPort);
      closeNwSocket(&sock_ssl);
      exit(-1);
    }
  }
#endif

  if(webPort > 0) {
    if(listen(sock, 5) < 0) {
      traceEvent(TRACE_WARNING, "listen error.\n");
      closeNwSocket(&sock);
      exit(-1);
    } 
  }
  
#ifdef HAVE_OPENSSL
  if(sslInitialized) 
    if(listen(sock_ssl, 5) < 0) {
      traceEvent(TRACE_WARNING, "listen error.\n");
      closeNwSocket(&sock_ssl);
      exit(-1);
    }
#endif

  if(webPort > 0) {
    /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
    if (webAddr) 
      traceEvent(TRACE_INFO, "Waiting for HTTP connections on %s port %d...\n",
		 webAddr, webPort);
    else 
      traceEvent(TRACE_INFO, "Waiting for HTTP connections on port %d...\n",
		 webPort);
  }
  
#ifdef HAVE_OPENSSL
  if(sslInitialized) 
    traceEvent(TRACE_INFO, "Waiting for HTTPS (SSL) connections on port %d...\n",
	       sslPort);
#endif
  
#ifdef MULTITHREADED
  createThread(&handleWebConnectionsThreadId, handleWebConnections, NULL);
#endif
}

/* ******************************* */

char* makeHostLink(HostTraffic *el, short mode,
		   short cutName, short addCountryFlag) {
  static char buf[5][384];
  char symIp[256], *tmpStr, linkName[256], flag[128];
  char *blinkOn, *blinkOff;
  short specialMacAddress = 0;
  static short bufIdx=0;
  short usedEthAddress=0;

  if(el == NULL)
    return("&nbsp;");

  if(broadcastHost(el)) {
    if(mode == LONG_FORMAT)
      return("<TH ALIGN=LEFT>&lt;broadcast&gt;</TH>");
    else
      return("&lt;broadcast&gt;");
  }

  if(subnetLocalHost(el)
     && FD_ISSET((unsigned long)(el->hostIpAddress.s_addr) % 256 /* C-class */,
		 &ipTrafficMatrixPromiscHosts)) {
    /* Promiscuous mode */
    blinkOn = "<BLINK><FONT COLOR=#FF0000>", blinkOff = "</FONT></BLINK>";
  } else {
    blinkOn = "", blinkOff = "";
  }

  bufIdx = (bufIdx+1)%5;

#ifdef MULTITHREADED
  accessMutex(&addressResolutionMutex, "makeHostLink");
#endif

  switch(numericFlag) {
  case 0: /* symbolic */
    tmpStr = el->hostSymIpAddress;

    if(tmpStr == NULL) {
      /* The DNS is still getting the entry name */
      if(el->hostNumIpAddress[0] != '\0')
	strncpy(symIp, el->hostNumIpAddress, sizeof(symIp));
      else {
	strncpy(symIp, el->ethAddressString, sizeof(symIp));
	usedEthAddress = 1;
      }
    } else if(tmpStr[0] != '\0') {
      strncpy(symIp, tmpStr, sizeof(symIp));
      if(tmpStr[strlen(tmpStr)-1] == ']') /* No "... [MAC]" */ {
	usedEthAddress = 1;
	specialMacAddress = 1;
      } else {
	if(cutName && (symIp[0] != '*')
	   && strcmp(symIp, el->hostNumIpAddress)) {
	  int i;

	  for(i=0; symIp[i] != '\0'; i++)
	    if(symIp[i] == '.') {
	      symIp[i] = '\0';
	      break;
	    }
	}
      }
    } else {
      strncpy(symIp, el->ethAddressString, sizeof(symIp));
      usedEthAddress = 1;
    }
    break;
  case 1:   /* numeric */
    if(el->hostNumIpAddress[0] != '\0')
      strncpy(symIp, el->hostNumIpAddress, sizeof(symIp));
    else {
      strncpy(symIp, el->ethAddressString, sizeof(symIp));
      usedEthAddress = 1;
    }
    break;
  case 2: /* ethernet address */
    strncpy(symIp, el->ethAddressString, sizeof(symIp));
    usedEthAddress = 1;
    if(symIp[0] == '\0') strncpy(symIp, separator, sizeof(symIp));
    break;
  case 3: /* ethernet constructor */
    strncpy(symIp, getVendorInfo(el->ethAddress, 1), sizeof(symIp));
    usedEthAddress = 1;
    if(symIp[0] == '\0') strncpy(symIp, el->ethAddressString, sizeof(symIp));
    if(symIp[0] == '\0') strncpy(symIp, separator, sizeof(symIp));
    break;
  }

#ifdef MULTITHREADED
    releaseMutex(&addressResolutionMutex);
#endif

  if(specialMacAddress) {
    tmpStr = el->ethAddressString;
#ifdef DEBUG
    traceEvent(TRACE_INFO, "->'%s/%s'\n", symIp, el->ethAddressString);
#endif
  } else {
    if(el->hostNumIpAddress[0] != '\0')
      tmpStr = el->hostNumIpAddress;
    else
      tmpStr = symIp;
  }

  strncpy(linkName, tmpStr, sizeof(linkName));

  if(usedEthAddress) {
    /* Patch for ethernet addresses and MS Explorer */
    int i;

    for(i=0; linkName[i] != '\0'; i++)
      if(linkName[i] == ':')
	linkName[i] = '_';
  }

  if(addCountryFlag == 0)
    flag[0] = '\0';
  else {
    snprintf(flag, sizeof(flag), "<TD ALIGN=CENTER>%s</TD>",
	    getHostCountryIconURL(el));
  }

  if(mode == LONG_FORMAT)
    snprintf(buf[bufIdx], 384, "<TH ALIGN=LEFT>%s<A HREF=\"/%s.html\">%s</A>%s</TH>%s",
	    blinkOn, linkName, symIp, blinkOff, flag);
  else
    snprintf(buf[bufIdx], 384, "%s<A HREF=\"/%s.html\">%s</A>%s%s",
	    blinkOn, linkName, symIp, blinkOff, flag);

  return(buf[bufIdx]);
}

/* ******************************* */

char* getHostName(HostTraffic *el, short cutName) {
  static char buf[5][80];
  char *tmpStr;
  static short bufIdx=0;

  if(broadcastHost(el))
    return("broadcast");

  bufIdx = (bufIdx+1)%5;

#ifdef MULTITHREADED
  accessMutex(&addressResolutionMutex, "getHostName");
#endif

  switch(numericFlag) {
  case 0: /* symbolic */
    tmpStr = el->hostSymIpAddress;

    if(tmpStr == NULL) {
      /* The DNS is still getting the entry name */
      if(el->hostNumIpAddress[0] == '\0')
	strncpy(buf[bufIdx], el->hostNumIpAddress, 80);
      else
	strncpy(buf[bufIdx], el->ethAddressString, 80);
    } else if(tmpStr[0] != '\0') {
      strncpy(buf[bufIdx], tmpStr, 80);
      if(cutName) {
	int i;

	for(i=0; buf[bufIdx][i] != '\0'; i++)
	  if((buf[bufIdx][i] == '.')
	     && (!(isdigit(buf[bufIdx][i-1])
		   && isdigit(buf[bufIdx][i+1]))
		 )) {
	    buf[bufIdx][i] = '\0';
	    break;
	  }
      }
    } else
      strncpy(buf[bufIdx], el->ethAddressString, 80);
    break;
  case 1:   /* numeric */
    if(el->hostNumIpAddress[0] != '\0')
      strncpy(buf[bufIdx], el->hostNumIpAddress, 80);
    else
      strncpy(buf[bufIdx], el->ethAddressString, 80);
    break;
  case 2: /* ethernet address */
    if(el->ethAddressString[0] != '\0')
      strncpy(buf[bufIdx], el->ethAddressString, 80);
    else
      strncpy(buf[bufIdx], el->hostNumIpAddress, 80);
    break;
  case 3: /* ethernet constructor */
    if(el->ethAddressString[0] != '\0')
      strncpy(buf[bufIdx], getVendorInfo(el->ethAddress, 1), 80);
    else
      strncpy(buf[bufIdx], el->hostNumIpAddress, 80);
    break;
  }

#ifdef MULTITHREADED
  releaseMutex(&addressResolutionMutex);
#endif

  return(buf[bufIdx]);
}

/* ********************************** */

char* calculateCellColor(TrafficCounter actualValue,
			 TrafficCounter avgTrafficLow,
			 TrafficCounter avgTrafficHigh) {

  if(actualValue < avgTrafficLow)
    return("BGCOLOR=#AAAAAAFF"); /* light blue */
  else if(actualValue < avgTrafficHigh)
    return("BGCOLOR=#00FF75"); /* light green */
  else
    return("BGCOLOR=#FF7777"); /* light red */
}


/* ************************ */

char* getCountryIconURL(char* domainName) {
  if((domainName == NULL) || (domainName[0] == '\0')) {
    /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
    return("&nbsp;");
  } else {
    static char flagBuf[128];
    char path[256];
    struct stat buf;

    snprintf(path, sizeof(path), "%s/html/statsicons/flags/%s.gif", 
	     DATAFILE_DIR, domainName);

    if(stat(path, &buf) != 0)
      return("&nbsp;");

    snprintf(flagBuf, sizeof(flagBuf), 
	     "<IMG ALIGN=ABSMIDDLE SRC=/statsicons/flags/%s.gif BORDER=0>",
	     domainName);

    return(flagBuf);
  }
}

/* ************************ */

char* getHostCountryIconURL(HostTraffic *el) {
  char path[128], *ret;
  struct stat buf;

  fillDomainName(el);

  snprintf(path, sizeof(path), "%s/html/statsicons/flags/%s.gif", 
	   DATAFILE_DIR, el->fullDomainName);

  if(stat(path, &buf) == 0)
    ret = getCountryIconURL(el->fullDomainName);
  else
    ret = getCountryIconURL(el->dotDomainName);

  if(ret == NULL)
    ret = "&nbsp;";

  return(ret);
}

/* ******************************* */

char* getRowColor() {
#define USE_COLOR

#ifdef USE_COLOR
  if(alternateColor == 0) {
    alternateColor = 1;
    return("BGCOLOR=#C3C9D9"); /* EFEFEF */ 
  } else {
    alternateColor = 0;
    return("");
  }
#else
  return("");
#endif
}

/* ******************************* */

char* getActualRowColor() {
#define USE_COLOR

#ifdef USE_COLOR
  if(alternateColor == 1) {
    return("BGCOLOR=#EFEFEF");
  } else
    return("");
#else
  return("");
#endif
}


/* ******************************* */

void switchNwInterface(int _interface) {
  int i, mwInterface=_interface-1;
  char buf[BUF_SIZE], *selected;

  sendString("<html>\n<body BACKGROUND=white_bg.gif bgcolor=#FFFFFF><CENTER><FONT FACE=Helvetica><H1>"
	     "Network Interface Switch"
	     "</H1></center><hr><p><b>");

  if(mergeInterfaces) {
    snprintf(buf, sizeof(buf), "You can switch among different inferfaces if the -M command line switch is not used. Sorry.\n", device[actualReportDeviceId].name);
    sendString(buf);
  } else if(numDevices == 1) {
    snprintf(buf, sizeof(buf), "You're currently capturing traffic from one interface [%s]. The interface switch feature is active only when you active ntop with multiple interfaces (-i command line switch). Sorry.\n", device[actualReportDeviceId].name);
    sendString(buf);
  } else if(mwInterface >= 0) {
    actualReportDeviceId = (mwInterface)%numDevices;
    snprintf(buf, sizeof(buf), "The current interface is now [%s].\n", device[actualReportDeviceId].name);
    sendString(buf);
  } else {
      sendString("Available Network Interfaces:</B><P>\n<FORM ACTION=switch.html>\n");

      for(i=0; i<numDevices; i++) {

	if(actualReportDeviceId == i)
	  selected="CHECKED";
	else
	  selected = "";

	snprintf(buf, sizeof(buf), "<INPUT TYPE=radio NAME=interface VALUE=%d %s>&nbsp;%s<br>\n",
		i, selected, device[i].name);

	sendString(buf);
      }


      sendString("<p><INPUT TYPE=submit>&nbsp;<INPUT TYPE=reset>\n</FORM>\n");
    }

    sendString("</font><p>\n");
}

/* **************************************** */

void usage() {
  char buf[80];

  snprintf(buf, sizeof(buf), "%s v.%s %s [%s] (%s build)", 
	  program_name, version, THREAD_MODE, osName, buildDate);
  traceEvent(TRACE_INFO, "%s\n", buf);

  traceEvent(TRACE_INFO, "Copyright 1998-2000 by %s\n", author);
  traceEvent(TRACE_INFO, "Get the freshest ntop from http://www.ntop.org/\n");
  snprintf(buf, sizeof(buf), "Written by %s.", author);

  traceEvent(TRACE_INFO, "%s\n", buf);

  snprintf(buf, sizeof(buf), "Usage: %s", program_name);

  traceEvent(TRACE_INFO, "%s\n", buf);

#ifdef WIN32
    traceEvent(TRACE_INFO, "    [-r <refresh time (web = %d sec)>]\n", REFRESH_TIME);
#else
    traceEvent(TRACE_INFO, "    [-r <refresh time (interactive = %d sec/web = %d sec)>]\n",
	    ALARM_TIME, REFRESH_TIME);
#endif
    traceEvent(TRACE_INFO, "    %s\n",   "[-f <traffic dump file (see tcpdump)>]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-n (numeric IP addresses)]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-p <IP protocols to monitor> (see man page)]");
#ifdef WIN32
    traceEvent(TRACE_INFO, "    %s%d Kb)>]\n", "[-B <NDIS buffer in Kbytes (default ", (int)(SIZE_BUF/1024));
#endif
#ifndef WIN32
    traceEvent(TRACE_INFO, "    %s\n",   "[-i <interface>]");
#endif
    traceEvent(TRACE_INFO, "    %s\n",   "[-S (store persistently host stats)]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-w <HTTP port>]");
#ifdef HAVE_OPENSSL
    traceEvent(TRACE_INFO, "    %s\n",   "[-W <HTTPS port>]");
#endif
    traceEvent(TRACE_INFO, "    %s\n",   "[-D <Internet domain name>]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-e <max # table rows"
#ifndef WIN32
		" (use only with -w)>"
#endif
	       );
#ifndef WIN32
    traceEvent(TRACE_INFO, "    %s\n",   "[-d (daemon mode (use only with -w))]");
#endif
    traceEvent(TRACE_INFO, "    %s\n",   "[-m <local addresses (see man page)>]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-l <log period (seconds)>]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-s <max hash size (default 32768)>]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-F <flow specs (see man page)>]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-b <client:port (ntop DB client)>]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-R <matching rules file>]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-N <don't use nmap if installed>]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-M <don't merge network interfaces (see man page)>]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-P <path for db-files>]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-g (grab session data on screen)]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-t (trace level [0-5])]");
    traceEvent(TRACE_INFO, "    %s\n",   "[-u <userid> | <username> (see man page)]");
    traceEvent(TRACE_INFO, "    %s\n\n", "[ <filter expression (like tcpdump)>]");
}

/* **************************************** */

void shutdownNtop() {
  cleanup(0);

  termAccessLog();
  termReports();
}
