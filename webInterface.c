/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 *		 	    http://www.ntop.org/
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
#ifdef HAVE_UCD_SNMP_UCD_SNMP_AGENT_INCLUDES_H
#include <ucd-snmp/version.h>
#endif

#ifdef USE_COLOR
static short alternateColor=0;
#endif

/* Forward */
void handleSingleWebConnection(fd_set *fdmask);

#ifndef MICRO_NTOP

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
      if(snprintf(buf, sizeof(buf), "QUERY_STRING=%s", &cgiName[i+1]) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      putenv(buf);
      num = 1;
      break;
    }

  if(num == 0) putenv("QUERY_STRING=");

  if(snprintf(line, sizeof(line), "%s/cgi/%s", getenv("PWD"), cgiName) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");

  if((fd = sec_popen(line, "r")) == NULL) {
    traceEvent(TRACE_WARNING, "WARNING: unable to exec %s\n", cgiName);
    return;
  } else {
    while(!feof(fd)) {
      num = fread(line, 1, 383, fd);
      if(num > 0)
	sendStringLen(line, num);
    }
    pclose(fd);
  }
}
#endif /* USE_CGI */
#endif
 
/* **************************************** */
 
#if (defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H)) || defined(WIN32) || defined(HPUX) || defined(AIX) || defined(DARWIN)
void showPluginsList(char* pluginName) {
  FlowFilterList *flows = flowsList;
  short printHeader = 0;
  char tmpBuf[BUF_SIZE], *thePlugin;
  int newPluginStatus = 0;
   
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
	printHTMLheader("Available Plugins", 0);
 	sendString("<CENTER>\n"
		   ""TABLE_ON"<TABLE BORDER=1><TR>\n"
		   "<TR><TH "TH_BG">Name</TH><TH>Description</TH>"
		   "<TH "TH_BG">Version</TH>"
		   "<TH "TH_BG">Author</TH>"
		   "<TH "TH_BG">Active</TH>"
		   "</TR>\n");
	printHeader = 1;
      }

      if(snprintf(tmpBuf, sizeof(tmpBuf), "<TR %s><TH "TH_BG" ALIGN=LEFT><A HREF=/plugins/%s>%s</TH>"
		  "<TD "TD_BG" ALIGN=LEFT>%s</TD>"
		  "<TD "TD_BG" ALIGN=CENTER>%s</TD>"
		  "<TD "TD_BG" ALIGN=LEFT>%s</TD>"
		  "<TD "TD_BG" ALIGN=CENTER><A HREF="STR_SHOW_PLUGINS"?%s=%d>%s</A></TD>"
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
		  "Yes" : "<FONT COLOR=#FF0000>No</FONT>")  < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(tmpBuf);
    }

    flows = flows->next;
  }

  if(!printHeader) {
    printHTMLheader("No Plugins available", 0);
  } else {
    sendString("</TABLE>"TABLE_OFF"<p>\n");
    sendString("</CENTER>\n");
  }
}

#else /* defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H) */

void showPluginsList(char* pluginName) {
  ;
}
 
void loadPlugins(void) {
  ;
}
 
void unloadPlugins(void) {
  ;
}
 
#endif /* defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H) */
 
/* ******************************* */

char* makeHostLink(HostTraffic *el, short mode,
		   short cutName, short addCountryFlag) {
  static char buf[5][BUF_SIZE];
  char symIp[256], *tmpStr, linkName[256], flag[128];
  char *blinkOn, *blinkOff, *dynIp;
  char *multihomed, *gwStr, *dnsStr, *printStr, *smtpStr, *healthStr = "";
  short specialMacAddress = 0;
  static short bufIdx=0;
  short usedEthAddress=0;

  if(el == NULL)
    return("&nbsp;");

  if(broadcastHost(el)) {
    if(mode == LONG_FORMAT)
      return("<TH "TH_BG" ALIGN=LEFT>&lt;broadcast&gt;</TH>");
    else
      return("&lt;broadcast&gt;");
  }

  blinkOn = "", blinkOff = "";

  bufIdx = (bufIdx+1)%5;

#ifdef MULTITHREADED
  accessMutex(&addressResolutionMutex, "makeHostLink");
#endif

  switch(numericFlag) {
  case 0: /* symbolic */
    tmpStr = el->hostSymIpAddress;

    if((tmpStr == NULL) || (tmpStr[0] == '\0')) {
      /* The DNS is still getting the entry name */
      if(el->hostNumIpAddress[0] != '\0')
	strncpy(symIp, el->hostNumIpAddress, sizeof(symIp));
      else {
	strncpy(symIp, el->ethAddressString, sizeof(symIp)); 
	usedEthAddress = 1;
      }
    } else if(tmpStr[0] != '\0') {
      strncpy(symIp, tmpStr, sizeof(symIp));
      if(tmpStr[strlen(tmpStr)-1] == ']') /* "... [MAC]" */ {
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

    if (usedEthAddress) {
      if(el->nbHostName != NULL) {
	strncpy(symIp, el->nbHostName, sizeof(linkName));
      } else if(el->ipxHostName != NULL) {
	strncpy(symIp, el->ipxHostName, sizeof(linkName));
      } 
    }

    if(el->hostNumIpAddress[0] != '\0') {
      tmpStr = el->hostNumIpAddress;
    } else {
      tmpStr = el->ethAddressString;
      /* tmpStr = symIp; */
    }
  }

  strncpy(linkName, tmpStr, sizeof(linkName));

  if(usedEthAddress) {
    /* Patch for ethernet addresses and MS Explorer */
    int i;    
    char tmpStr[256], *vendorInfo;

    if(el->nbHostName != NULL) {
      strncpy(symIp, el->nbHostName, sizeof(linkName));
    } else if(el->ipxHostName != NULL) {
      strncpy(symIp, el->ipxHostName, sizeof(linkName));      
    } else {
      vendorInfo = getVendorInfo(el->ethAddress, 0);
      if(vendorInfo[0] != '\0') {
	sprintf(tmpStr, "%s%s", vendorInfo, &linkName[8]);    
	strcpy(symIp, tmpStr); 
      }
      
      for(i=0; linkName[i] != '\0'; i++)
	if(linkName[i] == ':')
	  linkName[i] = '_';
    }
  }

  if(addCountryFlag == 0)
    flag[0] = '\0';
  else {
    if(snprintf(flag, sizeof(flag), "<TD "TD_BG" ALIGN=CENTER>%s</TD>",
		getHostCountryIconURL(el)) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  }

  if(isDHCPClient(el))   dynIp = "&nbsp;(dyn)"; else dynIp = "";
  if(isMultihomed(el))   multihomed = "&nbsp;<IMG SRC=/multihomed.gif BORDER=0>&nbsp;"; else multihomed = "";
  if(gatewayHost(el))    gwStr = "&nbsp;<IMG SRC=/router.gif BORDER=0>&nbsp;"; else gwStr = "";
  if(nameServerHost(el)) dnsStr = "&nbsp;<IMG SRC=/dns.gif BORDER=0>&nbsp;"; else dnsStr = "";
  if(isPrinter(el))      printStr = "&nbsp;<IMG SRC=/printer.gif BORDER=0>&nbsp;"; else printStr = "";
  if(isSMTPhost(el))     smtpStr = "&nbsp;<IMG SRC=/mail.gif BORDER=0>&nbsp;"; else smtpStr = "";
  
  switch(isHostHealthy(el)) {
  case 0: /* OK */
    healthStr = "";
    break;
  case 1: /* Warning */
    healthStr = "<IMG SRC=/Risk_medium.gif BORDER=0>";
    break;
  case 2: /* Error */
    healthStr = "<IMG SRC=/Risk_high.gif BORDER=0>";
    break;
  }  
 
  if(mode == LONG_FORMAT) {
    if(snprintf(buf[bufIdx], BUF_SIZE, "<TH "TH_BG" ALIGN=LEFT NOWRAP>%s"
		"<A HREF=\"/%s.html\">%s%s %s%s%s%s%s%s</A>%s</TH>%s",
		blinkOn, linkName, symIp, dynIp, 
		multihomed, gwStr, dnsStr, printStr, smtpStr, healthStr,
		blinkOff, flag) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  } else {
    if(snprintf(buf[bufIdx], BUF_SIZE, "%s<A HREF=\"/%s.html\" NOWRAP>%s%s %s%s%s%s%s%s</A>%s%s",
		blinkOn, linkName, symIp, 
		multihomed, gwStr, dnsStr, printStr, smtpStr, healthStr,
		dynIp, blinkOff, flag) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  }
  
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
    static char flagBuf[384];
    char path[256];
    struct stat buf;

    if(snprintf(path, sizeof(path), "./html/statsicons/flags/%s.gif", 
		domainName) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");

    if(stat(path, &buf) != 0) {
      if(snprintf(path, sizeof(path), "%s/html/statsicons/flags/%s.gif", 
		  DATAFILE_DIR, domainName) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");

      if(stat(path, &buf) != 0)
	return("&nbsp;");
    }

    if(snprintf(flagBuf, sizeof(flagBuf), 
		"<IMG ALIGN=MIDDLE SRC=/statsicons/flags/%s.gif BORDER=0>",
		domainName) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");

    return(flagBuf);
  }
}

/* ************************ */

char* getHostCountryIconURL(HostTraffic *el) {
  char path[128], *ret;
  struct stat buf;

  fillDomainName(el);

  if(snprintf(path, sizeof(path), "%s/html/statsicons/flags/%s.gif", 
	      DATAFILE_DIR, el->fullDomainName) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");

  if(stat(path, &buf) == 0)
    ret = getCountryIconURL(el->fullDomainName);
  else
    ret = getCountryIconURL(el->dotDomainName);

  if(ret == NULL)
    ret = "&nbsp;";

  return(ret);
}

/* ******************************* */

char* getRowColor(void) {
  /* #define USE_COLOR */

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

char* getActualRowColor(void) {
  /* #define USE_COLOR */

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

  printHTMLheader("Network Interface Switch", HTML_FLAG_NO_REFRESH); 
  sendString("<HR>\n<P>\n<FONT FACE=\"Helvetica, Arial, Sans Serif\"><B>\n");

  if(mergeInterfaces) {
    if(snprintf(buf, sizeof(buf), "You can switch among different inferfaces if the -M "
		"command line switch is not used. Sorry.\n") < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  } else if((mwInterface != -1) &&
	    ((mwInterface >= numDevices) || device[mwInterface].virtualDevice)) {
    if(snprintf(buf, sizeof(buf), "Invalid interface selected. Sorry.\n") < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  } else if(numDevices == 1) {
    if(snprintf(buf, sizeof(buf), "You're currently capturing traffic from one "
		"interface [%s]. The interface switch feature is active only when "
		"you active ntop with multiple interfaces (-i command line switch). "
		"Sorry.\n", device[actualReportDeviceId].name) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  } else if(mwInterface >= 0) {
    actualReportDeviceId = (mwInterface)%numDevices;
    if(snprintf(buf, sizeof(buf), "The current interface is now [%s].\n", 
		device[actualReportDeviceId].name) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  } else {
    sendString("Available Network Interfaces:</B><P>\n<FORM ACTION="SWITCH_NIC_HTML">\n");

    for(i=0; i<numDevices; i++) 
      if(!device[i].virtualDevice) {
	if(actualReportDeviceId == i)
	  selected="CHECKED";
	else
	  selected = "";

	if(snprintf(buf, sizeof(buf), "<INPUT TYPE=radio NAME=interface VALUE=%d %s>&nbsp;%s<br>\n",
		    i+1, selected, device[i].name) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");

	sendString(buf);
      }

    sendString("<p><INPUT TYPE=submit>&nbsp;<INPUT TYPE=reset>\n</FORM>\n");
    sendString("<B>");
  }

  sendString("</B>");
  sendString("</font><p>\n");
}

/* **************************************** */

void shutdownNtop(void) {
  printHTMLheader("ntop is shutting down...", HTML_FLAG_NO_REFRESH);
  closeNwSocket(&newSock);
  termAccessLog();
  cleanup(0);
}

/* ******************************** */

static void printFeatureConfigInfo(char* feature, char* status) {
  sendString("<TR><TH "TH_BG" ALIGN=left>");
  sendString(feature);
  sendString("</TH><TD "TD_BG" ALIGN=right>");
  sendString(status);
  sendString("</TD></TR>\n");
}

/* ******************************** */

#ifdef MULTITHREADED
static void printMutexStatus(PthreadMutex *mutexId, char *mutexName) {  
  char buf[BUF_SIZE];

  if(mutexId->lockLine == 0) /* Mutex never used */
    return;

  if(snprintf(buf, sizeof(buf), 
	      "<TR><TH "TH_BG" ALIGN=left>%s</TH><TD ALIGN=CENTER>%s</TD>"
	      "<TD ALIGN=RIGHT>%s:%d</TD>"
	      "<TD ALIGN=RIGHT>%s:%d</TD>"
	      "<TD ALIGN=RIGHT>%u</TD><TD ALIGN=LEFT>%u</TD>"
	      "<TD ALIGN=RIGHT>%d sec [%s:%d]</TD></TR>", 
	      mutexName,
	      mutexId->isLocked ? "<FONT COLOR=red>locked</FONT>" : "unlocked",
	      mutexId->lockFile, mutexId->lockLine,
	      mutexId->unlockFile, mutexId->unlockLine,
	      mutexId->numLocks, mutexId->numReleases,
	      mutexId->maxLockedDuration,
	      mutexId->maxLockedDurationUnlockFile,
	      mutexId->maxLockedDurationUnlockLine) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");

  sendString(buf);
}
#endif

void printNtopConfigInfo(void) {
  char buf[BUF_SIZE];
#ifdef HAVE_PCAP_VERSION
  extern char pcap_version[];
#endif /* HAVE_PCAP_VERSION */

  printHTMLheader("Current ntop Configuration", 0);
  sendString("<CENTER>\n");
  sendString("<P><HR><P>"TABLE_ON"<TABLE BORDER=1>\n");

  printFeatureConfigInfo("OS", osName);
  printFeatureConfigInfo("ntop version", version);
  printFeatureConfigInfo("Built on", buildDate);
#ifdef HAVE_PCAP_VERSION
  printFeatureConfigInfo("Libpcap version", pcap_version);
#endif /* HAVE_PCAP_VERSION */
#if defined(WIN32) && defined(__GNUC__)
  /* on mingw, gdbm_version not exported by library */
#else
  printFeatureConfigInfo("GDBM version", gdbm_version);
#endif
  
#ifdef HAVE_OPENSSL
  printFeatureConfigInfo("<A HREF=http://www.openssl.org/>OpenSSL Support</A>", 
			 (char*)SSLeay_version(0));
  if(sslPort != 0) {
    sprintf(buf, "%d", sslPort); 
    printFeatureConfigInfo("SSL Port", buf);
  } else
    printFeatureConfigInfo("SSL Port", "Not Active");
#else
  printFeatureConfigInfo("<A HREF=http://www.openssl.org/>OpenSSL Support</A>", "Absent");
#endif

#ifdef MULTITHREADED
  printFeatureConfigInfo("Multithreaded", "Yes");
#else
  printFeatureConfigInfo("Multithreaded", "No");
#endif

#ifdef HAVE_GDCHART
  printFeatureConfigInfo("<A HREF=http://www.fred.net/brv/chart/>GD Chart</A>", "Present");
  printFeatureConfigInfo("Chart Format", CHART_FORMAT);
#else
  printFeatureConfigInfo("<A HREF=http://www.fred.net/brv/chart/>GD Chart</A>", "Absent");
#endif

#ifdef HAVE_UCD_SNMP_UCD_SNMP_AGENT_INCLUDES_H
  printFeatureConfigInfo("<A HREF=http://net-snmp.sourceforge.net/>UCD/NET SNMP</A>", 
			 (char*)VersionInfo);
#else
  printFeatureConfigInfo("<A HREF=http://net-snmp.sourceforge.net/>UCD/NET SNMP </A>", 
			 "Absent");
#endif

#ifdef HAVE_LIBWRAP
  printFeatureConfigInfo("TCP Wrappers", "Present");
#else
  printFeatureConfigInfo("TCP Wrappers", "Absent");
#endif

#ifdef ASYNC_ADDRESS_RESOLUTION
  printFeatureConfigInfo("Async. Addr. Resolution", "Yes");
#else
  printFeatureConfigInfo("Async. Addr. Resolution", "No");
#endif

  if(isLsofPresent) 
    printFeatureConfigInfo("<A HREF=ftp://vic.cc.purdue.edu/pub/tools/unix/lsof/>lsof</A> Support", "Yes");
  else
    printFeatureConfigInfo("<A HREF=ftp://vic.cc.purdue.edu/pub/tools/unix/lsof/>lsof</A> Support",
			   "No (Either disabled [Use -E option] or missing)");

  if(isNmapPresent) 
    printFeatureConfigInfo("<A HREF=http://www.insecure.org/nmap/>nmap</A> Support", "Yes");
  else
    printFeatureConfigInfo("<A HREF=http://www.insecure.org/nmap/>nmap</A> Support", 
			   "No (Either disabled or missing)");

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left>Actual Hash Size</TH>"
	      "<TD "TD_BG"  align=right>%d</TD></TR>\n",
	      (int)device[actualReportDeviceId].actualHashSize) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

#ifdef MULTITHREADED
  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Queued Pkts to Process</TH>"
	      "<TD "TD_BG"  align=right>%d</TD></TR>\n",
	      packetQueueLen) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Max Queued Pkts</TH>"
	      "<TD "TD_BG"  align=right>%u</TD></TR>\n",
	      maxPacketQueueLen) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
#endif

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Stored Hash Hosts</TH>"
	      "<TD "TD_BG"  align=right>%d [%d %%]</TD></TR>\n",
	      (int)device[actualReportDeviceId].hostsno,
	      (((int)device[actualReportDeviceId].hostsno*100)/
	       (int)device[actualReportDeviceId].actualHashSize)) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Purged Hash Hosts</TH>"
	      "<TD "TD_BG"  align=right>%u</TD></TR>\n",
	      (unsigned int)numPurgedHosts) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># TCP Sessions</TH>"
	      "<TD "TD_BG"  align=right>%u</TD></TR>\n", 
	      device[actualReportDeviceId].numTcpSessions) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Terminated TCP Sessions</TH>"
	      "<TD "TD_BG"  align=right>%u</TD></TR>\n", 
	      (unsigned int)numTerminatedSessions) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

#if defined(MULTITHREADED) && defined(ASYNC_ADDRESS_RESOLUTION)
  accessMutex(&addressQueueMutex, "NumQueuedAddresses");
  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Queued Addresses</TH>"
	      "<TD "TD_BG"  align=right>%d</TD></TR>\n", addressQueueLen) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  releaseMutex(&addressQueueMutex);
#endif

  /* **** */

#if defined(MULTITHREADED)
  accessMutex(&addressQueueMutex, "NumQueuedAddresses");
#endif

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Addresses Resolved with DNS</TH>"
	      "<TD "TD_BG"  align=right>%ld</TD></TR>\n", numResolvedWithDNSAddresses) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Addresses Kept Numeric</TH>"
	      "<TD "TD_BG"  align=right>%ld</TD></TR>\n", numKeptNumericAddresses) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Addresses Found on Cache</TH>"
	      "<TD "TD_BG"  align=right>%ld</TD></TR>\n", numResolvedOnCacheAddresses) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

#if defined(MULTITHREADED)
  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Dropped Addresses</TH>"
	      "<TD "TD_BG"  align=right>%ld</TD></TR>\n", (long int)droppedAddresses) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
#endif

#if defined(MULTITHREADED)
  releaseMutex(&addressQueueMutex);
#endif

  /* **** */

#if defined(MULTITHREADED)
  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Active Threads</TH>"
	      "<TD "TD_BG"  align=right>%d</TD></TR>\n", numThreads) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
#endif

#ifdef MEMORY_DEBUG
  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left>Allocated Memory</TH>"
	      "<TD "TD_BG"  align=right>%s</TD></TR>\n",
	      formatBytes(allocatedMemory, 0)) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
#endif

  if(isLsofPresent) {
    if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Monitored Processes</TH>"
		"<TD "TD_BG"  align=right>%d</TD></TR>\n", numProcesses) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }

  sendString("</TABLE>"TABLE_OFF"\n");

  /* **************************** */

#ifdef MULTITHREADED
  sendString("<P>"TABLE_ON"<TABLE BORDER=1>\n");
  sendString("<TR><TH>Mutex Name</TH><TH>State</TH><TH>Last Lock</TH><TH>Last UnLock</TH>"
	     "<TH COLSPAN=2># Locks/Releases</TH><TH>Max Lock</TH></TR>");
  printMutexStatus(&gdbmMutex, "gdbmMutex");
  printMutexStatus(&packetQueueMutex, "packetQueueMutex");
  printMutexStatus(&addressResolutionMutex, "addressResolutionMutex");
  printMutexStatus(&hashResizeMutex, "hashResizeMutex");  
  if(isLsofPresent) printMutexStatus(&lsofMutex, "lsofMutex");
  printMutexStatus(&hostsHashMutex, "hostsHashMutex");
  printMutexStatus(&graphMutex, "graphMutex");
#ifdef ASYNC_ADDRESS_RESOLUTION
  if(numericFlag == 0) printMutexStatus(&addressQueueMutex, "addressQueueMutex");
#endif
  sendString("</TABLE>"TABLE_OFF"\n");
#endif /* MULTITHREADED */

  sendString("</CENTER>\n");
}

#endif /* MICRO_NTOP */

/* ******************************* */

static void initializeWeb(void) {
#ifndef MICRO_NTOP
  columnSort = 0, sortSendMode = 0;
#endif
  addDefaultAdminUser();
  initAccessLog();
}

/* **************************************** */

 /* 
    SSL fix courtesy of 
    Curtis Doty <Curtis@GreenKey.net>
 */
void initWeb(int webPort, char* webAddr, char* sslAddr) {
  int sockopt = 1;
  struct sockaddr_in sin;

  initReports();
  initializeWeb();

  actualReportDeviceId = 0;

  if(webPort > 0) {
    sin.sin_family      = AF_INET;
    sin.sin_port        = (int)htons((unsigned short int)webPort);
    sin.sin_addr.s_addr = INADDR_ANY;

#ifndef WIN32
    if(sslAddr) {
      if(!inet_aton(sslAddr,&sin.sin_addr))
	traceEvent(TRACE_ERROR, "Unable to convert address '%s'...\n"
		   "Not binding SSL to a particular interface!\n",  sslAddr);
    }

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

/* **************************************** */

void usage(void) {
  char buf[80];

  if(snprintf(buf, sizeof(buf), "%s v.%s %s [%s] (%s build)", 
	      program_name, version, THREAD_MODE, osName, buildDate) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  traceEvent(TRACE_INFO, "%s\n", buf);

  traceEvent(TRACE_INFO, "Copyright 1998-2001 by %s\n", author);
  traceEvent(TRACE_INFO, "Get the freshest ntop from http://www.ntop.org/\n");
  if(snprintf(buf, sizeof(buf), "Written by %s.", author) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");

  traceEvent(TRACE_INFO, "%s\n", buf);

  if(snprintf(buf, sizeof(buf), "Usage: %s", program_name) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");

  traceEvent(TRACE_INFO, "%s\n", buf);

  traceEvent(TRACE_INFO, "    %s\n",   "[-c <sticky hosts: idle hosts are not purged from hash>]");
#ifdef WIN32
  traceEvent(TRACE_INFO, "    [-r <refresh time (web = %d sec)>]\n", REFRESH_TIME);
#else
  traceEvent(TRACE_INFO, "    [-r <refresh time (interactive = %d sec/web = %d sec)>]\n",
	     ALARM_TIME, REFRESH_TIME);
#endif
  traceEvent(TRACE_INFO, "    %s\n",   "[-f <traffic dump file (see tcpdump)>]");
#ifndef WIN32
  traceEvent(TRACE_INFO, "    %s\n",   "[-E <enable lsof/nmap integration (if present)>]");
#endif
  traceEvent(TRACE_INFO, "    %s\n",   "[-n (numeric IP addresses)]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-p <IP protocols to monitor> (see man page)]");
#ifndef WIN32
  traceEvent(TRACE_INFO, "    %s\n",   "[-i <interface>]");
#else
  traceEvent(TRACE_INFO, "    %s\n",   "[-i <interface index>]");
#endif
  traceEvent(TRACE_INFO, "    %s\n",   "[-S <store mode> (store persistently host stats)]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-w <HTTP port>]");
#ifdef HAVE_OPENSSL
  traceEvent(TRACE_INFO, "    %s\n",   "[-W <HTTPS port>]");
#endif
  traceEvent(TRACE_INFO, "    %s\n",   "[-D <Internet domain name>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-e <max # table rows)]");
#ifndef WIN32
  traceEvent(TRACE_INFO, "    %s\n",   "[-d (daemon mode)]");
#endif
  traceEvent(TRACE_INFO, "    %s\n",   "[-m <local addresses (see man page)>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-s <max hash size (default 32768)>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-F <flow specs (see man page)>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-b <client:port (ntop DB client)>]");
#ifdef HAVE_MYSQL
  traceEvent(TRACE_INFO, "    %s\n",   "[-v <username:password:dbName (ntop mySQL client)>]");
#endif
  traceEvent(TRACE_INFO, "    %s\n",   "[-R <matching rules file>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-N <don't use nmap if installed>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-M <don't merge network interfaces (see man page)>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-q <create file ntop-suspicious-pkts.XXX.pcap>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-l <path> (dump packets captured on a file: debug only!)]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-P <path for db-files>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-g <client:port (Cisco NetFlow client)>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-t (trace level [0-5])]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-u <userid> | <username> (see man page)]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-U <mapper.pl URL> | \"\" for not displaying host location ]");
  traceEvent(TRACE_INFO, "    %s\n\n", "[ <filter expression (like tcpdump)>]");
}

/* ******************************************* */

void* handleWebConnections(void* notUsed _UNUSED_) {
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
    traceEvent(TRACE_INFO, "Select(ing) %d....", topSock);
#endif
    memcpy(&mask, &mask_copy, sizeof(fd_set));
    rc = select(topSock+1, &mask, 0, 0, NULL /* Infinite */);
#ifdef DEBUG
    traceEvent(TRACE_INFO, "select returned: %d\n", rc);
#endif
    if(rc > 0)
      handleSingleWebConnection(&mask);
  }

  traceEvent(TRACE_INFO, "Terminating Web connections...");
#endif

  return(NULL);
}

/* ************************************* */
 
void handleSingleWebConnection(fd_set *fdmask) {
  struct sockaddr_in from;
  int from_len = sizeof(from);

  errno = 0;

  if(FD_ISSET(sock, fdmask)) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Accepting HTTP request...\n");
#endif
    newSock = accept(sock, (struct sockaddr*)&from, &from_len);
  } else {
#ifdef DEBUG
#ifdef HAVE_OPENSSL
    if(sslInitialized)
      traceEvent(TRACE_INFO, "Accepting HTTPS request...\n");
#endif
#endif
#ifdef HAVE_OPENSSL
    if(sslInitialized)
      newSock = accept(sock_ssl, (struct sockaddr*)&from, &from_len); 
#else
    ;
#endif
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Request accepted (sock=%d) (errno=%d)\n", newSock, errno);
#endif

  if(newSock > 0) {
#ifdef HAVE_OPENSSL
    if(sslInitialized) 
      if(FD_ISSET(sock_ssl, fdmask)) {
	if(accept_ssl_connection(newSock) == -1) {
	  traceEvent(TRACE_WARNING, "Unable to accept SSL connection\n");
	  closeNwSocket(&newSock);
	  return;
	} else {
	  newSock = -newSock;
	}
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
  } else {
    traceEvent(TRACE_INFO, "Unable to accept HTTP(S) request (errno=%d)", errno);
  }
}

/* ******************* */

int handlePluginHTTPRequest(char* url) {
  FlowFilterList *flows = flowsList;

  while(flows != NULL)
    if((flows->pluginStatus.pluginPtr != NULL)
       && (flows->pluginStatus.pluginPtr->pluginURLname != NULL)
       && (flows->pluginStatus.pluginPtr->httpFunct != NULL)
       && (strncmp(flows->pluginStatus.pluginPtr->pluginURLname,
		   url, strlen(flows->pluginStatus.pluginPtr->pluginURLname)) == 0)) {
      char *arg;

      /* Courtesy of Roberto F. De Luca <deluca@tandar.cnea.gov.ar> */
      if(!flows->pluginStatus.activePlugin) {
 	char buf[BUF_SIZE], name[32];
 
 	sendHTTPHeader(HTTP_TYPE_HTML, 0);
 	strncpy(name, flows->pluginStatus.pluginPtr->pluginURLname, sizeof(name));
 	name[sizeof(name)-1] = '\0'; /* just in case pluginURLname is too long... */
	if((strlen(name) > 6) && (strcasecmp(&name[strlen(name)-6], "plugin") == 0))
 	  name[strlen(name)-6] = '\0';
 	if(snprintf(buf, sizeof(buf),"Status for the \"%s\" Plugin", name) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
 	printHTMLheader(buf, HTML_FLAG_NO_REFRESH);
 	printFlagedWarning("<I>This plugin is currently inactive.</I>");
 	printHTMLtrailer();
 	return(1);
      }
 
      if(strlen(url) == strlen(flows->pluginStatus.pluginPtr->pluginURLname))
	arg = "";
      else
	arg = &url[strlen(flows->pluginStatus.pluginPtr->pluginURLname)+1];

      /* traceEvent(TRACE_INFO, "Found %s [%s]\n", 
	 flows->pluginStatus.pluginPtr->pluginURLname, arg); */
      flows->pluginStatus.pluginPtr->httpFunct(arg);
      return(1);
    } else
      flows = flows->next;

  return(0); /* Plugin not found */
}
