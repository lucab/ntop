/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
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
#define USE_CGI

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
static void handleSingleWebConnection(fd_set *fdmask);

#ifndef MICRO_NTOP


#if defined(NEED_INET_ATON)
/*
 * Minimal implementation of inet_aton.
 * Cannot distinguish between failure and a local broadcast address.
 */

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif


static int inet_aton(const char *cp, struct in_addr *addr)
{
  addr->s_addr = inet_addr(cp);
  return (addr->s_addr == INADDR_NONE) ? 0 : 1;
}

#endif /* NEED_INET_ATON */



/* ************************************* */

#ifndef WIN32
int execCGI(char* cgiName) {
  char* userName = "nobody", line[384], buf[512];
  struct passwd * newUser = NULL;
  FILE *fd;
  int num, i;

  if(!(newUser = getpwnam(userName))) {
    traceEvent(TRACE_WARNING, "WARNING: unable to find user %s\n", userName);
    return(-1);
  } else {
    setgid(newUser->pw_gid);
    setuid(newUser->pw_uid);
  }

  for(num=0, i=0; cgiName[i] != '\0'; i++)
    if(cgiName[i] == '?') {
      cgiName[i] = '\0';
      if(snprintf(buf, sizeof(buf), "QUERY_STRING=%s", &cgiName[i+1]) < 0)
	BufferTooShort();
      putenv(buf);
      num = 1;
      break;
    }

  putenv("REQUEST_METHOD=GET");
  if(num == 0) putenv("QUERY_STRING=");

  if(snprintf(line, sizeof(line), "%s/cgi/%s", getenv("PWD"), cgiName) < 0)
    BufferTooShort();

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Executing CGI '%s'", line);
#endif

  if((fd = popen(line, "r")) == NULL) {
    traceEvent(TRACE_WARNING, "WARNING: unable to exec %s\n", cgiName);
    return(-1);
  } else {
    while(!feof(fd)) {
      num = fread(line, 1, 383, fd);
      if(num > 0)
	sendStringLen(line, num);
    }
    pclose(fd);
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "CGI execution completed.");
#endif

  return(0);
}
#endif

/* **************************************** */

#if(defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H)) || defined(WIN32) || defined(HPUX) || defined(AIX) || defined(DARWIN)
void showPluginsList(char* pluginName) {
  FlowFilterList *flows = myGlobals.flowsList;
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
	 && (strcmp(flows->pluginStatus.pluginPtr->pluginURLname, thePlugin) == 0)) {
	char key[64];

	flows->pluginStatus.activePlugin = newPluginStatus;

	if(snprintf(key, sizeof(key), "pluginStatus.%s", 
		    flows->pluginStatus.pluginPtr->pluginName) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");

	storePrefsValue(key, newPluginStatus ? "1" : "0");
      }

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
	BufferTooShort();
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

  if(broadcastHost(el)
     || (el->hostSerial == myGlobals.broadcastEntryIdx)
     || ((el->hostIpAddress.s_addr == 0) && (el->ethAddressString[0] == '\0'))) {
    if(mode == LONG_FORMAT)
      return("<TH "TH_BG" ALIGN=LEFT>&lt;broadcast&gt;</TH>");
    else
      return("&lt;broadcast&gt;");
  }

  blinkOn = "", blinkOff = "";

  bufIdx = (bufIdx+1)%5;

#ifdef MULTITHREADED
  accessMutex(&myGlobals.addressResolutionMutex, "makeHostLink");
#endif

  if((el == myGlobals.otherHostEntry)
     || (el->hostSerial == myGlobals.otherHostEntryIdx)) {
    char *fmt;

    if(mode == LONG_FORMAT)
      fmt = "<TH "TH_BG" ALIGN=LEFT>%s</TH>";
    else
      fmt = "%s";

    if(snprintf(buf[bufIdx], BUF_SIZE, fmt, el->hostSymIpAddress) < 0)
      BufferTooShort();

#ifdef MULTITHREADED
    releaseMutex(&myGlobals.addressResolutionMutex);
#endif
    return(buf[bufIdx]);
  }

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

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.addressResolutionMutex);
#endif

  if(specialMacAddress) {
    tmpStr = el->ethAddressString;
#ifdef DEBUG
    traceEvent(TRACE_INFO, "->'%s/%s'\n", symIp, el->ethAddressString);
#endif
  } else {
    if(usedEthAddress) {
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
      BufferTooShort();
  }

  if(isDHCPClient(el))
    dynIp = "&nbsp;<IMG ALT=\"DHCP Client\" SRC=/bulb.gif BORDER=0>&nbsp;";
  else {
    if(isDHCPServer(el))
      dynIp = "&nbsp;<IMG ALT=\"DHCP Server\" SRC=/antenna.gif BORDER=0>&nbsp;";
    else
      dynIp = "";
  }

  if(isMultihomed(el))   multihomed = "&nbsp;<IMG ALT=\"Multihomed host\" SRC=/multihomed.gif BORDER=0>"; else multihomed = "";
  if(gatewayHost(el))    gwStr = "&nbsp;<IMG ALT=Router SRC=/router.gif BORDER=0>"; else gwStr = "";
  if(nameServerHost(el)) dnsStr = "&nbsp;<IMG ALT=\"DNS Server\" SRC=/dns.gif BORDER=0>"; else dnsStr = "";
  if(isPrinter(el))      printStr = "&nbsp;<IMG ALT=Printer SRC=/printer.gif BORDER=0>"; else printStr = "";
  if(isSMTPhost(el))     smtpStr = "&nbsp;<IMG ALT=\"Mail Server (SMTP)\" SRC=/mail.gif BORDER=0>"; else smtpStr = "";

  switch(isHostHealthy(el)) {
  case 0: /* OK */
    healthStr = "";
    break;
  case 1: /* Warning */
    healthStr = "<IMG ALT=\"Medium Risk\" SRC=/Risk_medium.gif BORDER=0>";
    break;
  case 2: /* Error */
    healthStr = "<IMG ALT=\"High Risk\" SRC=/Risk_high.gif BORDER=0>";
    break;
  }

  if(mode == LONG_FORMAT) {
    if(snprintf(buf[bufIdx], BUF_SIZE, "<TH "TH_BG" ALIGN=LEFT NOWRAP>%s"
		"<A HREF=\"/%s.html\">%s</A>%s%s%s%s%s%s%s%s</TH>%s",
		blinkOn, linkName, symIp, /* el->numUses, */
		dynIp,
		multihomed, gwStr, dnsStr,
		printStr, smtpStr, healthStr,
		blinkOff, flag) < 0)
      BufferTooShort();
  } else {
    if(snprintf(buf[bufIdx], BUF_SIZE, "%s<A HREF=\"/%s.html\" NOWRAP>%s</A>"
		"%s%s%s%s%s%s%s%s%s",
		blinkOn, linkName, symIp, /* el->numUses, */
		multihomed, gwStr, dnsStr,
		printStr, smtpStr, healthStr,
		dynIp, blinkOff, flag) < 0)
      BufferTooShort();
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
  accessMutex(&myGlobals.addressResolutionMutex, "getHostName");
#endif

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

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.addressResolutionMutex);
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
      BufferTooShort();

    if(stat(path, &buf) != 0) {
      if(snprintf(path, sizeof(path), "%s/html/statsicons/flags/%s.gif",
		  DATAFILE_DIR, domainName) < 0)
	BufferTooShort();

      if(stat(path, &buf) != 0)
	return("&nbsp;");
    }

    if(snprintf(flagBuf, sizeof(flagBuf),
		"<IMG ALT=\"Flag for domain %s\" ALIGN=MIDDLE SRC=\"/statsicons/flags/%s.gif\" BORDER=0>",
		domainName, domainName) < 0) BufferTooShort();

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
    BufferTooShort();

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
  
  if(myGlobals.mergeInterfaces) {
    if(snprintf(buf, sizeof(buf), "You can't switch among different inferfaces unless the -M "
		"command line switch is used. Sorry.\n") < 0)
      BufferTooShort();
    sendString(buf);
  } else if((mwInterface != -1) &&
	    ((mwInterface >= myGlobals.numDevices) || myGlobals.device[mwInterface].virtualDevice)) {
    if(snprintf(buf, sizeof(buf), "Invalid interface selected. Sorry.\n") < 0)
      BufferTooShort();
    sendString(buf);
  } else if(myGlobals.numDevices == 1) {
    if(snprintf(buf, sizeof(buf), "You're currently capturing traffic from one "
		"interface [%s]. The interface switch feature is active only when "
		"you active ntop with multiple interfaces (-i command line switch). "
		"Sorry.\n", myGlobals.device[myGlobals.actualReportDeviceId].name) < 0)
      BufferTooShort();
    sendString(buf);
  } else if(mwInterface >= 0) {
    myGlobals.actualReportDeviceId = (mwInterface)%myGlobals.numDevices;
    if(snprintf(buf, sizeof(buf), "The current interface is now [%s].\n",
		myGlobals.device[myGlobals.actualReportDeviceId].name) < 0)
      BufferTooShort();
    sendString(buf);
  } else {
    sendString("Available Network Interfaces:</B><P>\n<FORM ACTION="SWITCH_NIC_HTML">\n");

    for(i=0; i<myGlobals.numDevices; i++)
      if(!myGlobals.device[i].virtualDevice) {
	if(myGlobals.actualReportDeviceId == i)
	  selected="CHECKED";
	else
	  selected = "";

	if(snprintf(buf, sizeof(buf), "<INPUT TYPE=radio NAME=interface VALUE=%d %s>&nbsp;%s<br>\n",
		    i+1, selected, myGlobals.device[i].name) < 0) BufferTooShort();

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
  closeNwSocket(&myGlobals.newSock);
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
    BufferTooShort();

  sendString(buf);
}
#endif

void printNtopConfigInfo(void) {
  char buf[BUF_SIZE];
  int i;
#ifdef HAVE_PCAP_VERSION
  extern char pcap_version[];
#endif /* HAVE_PCAP_VERSION */

  printHTMLheader("Current ntop Configuration", 0);
  sendString("<CENTER>\n");
  sendString("<P><HR><P>"TABLE_ON"<TABLE BORDER=1>\n");

  printFeatureConfigInfo("OS", osName);
  printFeatureConfigInfo("ntop version", version);
  printFeatureConfigInfo("Built on", buildDate);

  /* *************************** */

  sendString("<TR><TH "TH_BG" ALIGN=left>Started as</TH><TD "TD_BG" ALIGN=right>");
  for(i=0; i<myGlobals.ntop_argc; i++) {
    sendString(myGlobals.ntop_argv[i]);
    sendString(" ");
  }
  sendString("</TD></TR>\n");

  /* *************************** */

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
  if(myGlobals.sslPort != 0) {
    sprintf(buf, "%d", myGlobals.sslPort);
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

#ifdef HAVE_ZLIB
  printFeatureConfigInfo("HTTP gzip compression", "Yes (zlib version "ZLIB_VERSION")");
#else
  printFeatureConfigInfo("HTTP gzip compression", "No");
#endif


#ifdef HAVE_GDCHART
  printFeatureConfigInfo("<A HREF=http://www.fred.net/brv/chart/>GD Chart</A>", "Present");
  printFeatureConfigInfo("Chart Format", CHART_FORMAT);
#else
  printFeatureConfigInfo("<A HREF=http://www.fred.net/brv/chart/>GD Chart</A>", "Absent");
#endif

/*
#ifdef HAVE_UCD_SNMP_UCD_SNMP_AGENT_INCLUDES_H
  printFeatureConfigInfo("<A HREF=http://net-snmp.sourceforge.net/>UCD/NET SNMP</A>",
			 (char*)VersionInfo);
#else
  printFeatureConfigInfo("<A HREF=http://net-snmp.sourceforge.net/>UCD/NET SNMP </A>",
			 "Absent");
#endif
*/

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

  if(myGlobals.isLsofPresent)
    printFeatureConfigInfo("<A HREF=http://freshmeat.net/projects/lsof/>lsof</A> Support", "Yes");
  else
    printFeatureConfigInfo("<A HREF=http://freshmeat.net/projects/lsof/>lsof</A> Support",
			   "No (Either disabled [Use -E option] or missing)");

  printFeatureConfigInfo("TCP Session Handling", myGlobals.enableSessionHandling == 1 ? "Enabled" : "Disabled");
  printFeatureConfigInfo("Protocol Decoders",    myGlobals.enablePacketDecoding == 1 ? "Enabled" : "Disabled");

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># IP Protocols Being Monitored</TH>"
	      "<TD "TD_BG"  align=right>%d</TD></TR>\n", myGlobals.numIpProtosToMonitor) < 0)
    BufferTooShort();
  sendString(buf);

  printFeatureConfigInfo("Fragment Handling", myGlobals.enableFragmentHandling == 1 ? "Enabled" : "Disabled");

  if(myGlobals.isNmapPresent)
    printFeatureConfigInfo("<A HREF=http://www.insecure.org/nmap/>nmap</A> Support", "Yes");
  else
    printFeatureConfigInfo("<A HREF=http://www.insecure.org/nmap/>nmap</A> Support",
			   "No (Either disabled [Use -E option] or missing)");

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Handled HTTP Requests</TH>"
	      "<TD "TD_BG"  align=right>%lu</TD></TR>\n", myGlobals.numHandledHTTPrequests) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left>Actual Hash Size</TH>"
	      "<TD "TD_BG"  align=right>%d</TD></TR>\n",
	      (int)myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left>Host Memory Cache Size</TH>"
	      "<TD "TD_BG"  align=right>%d</TD></TR>\n", myGlobals.hostsCacheLen) < 0)
    BufferTooShort();
  sendString(buf);

#ifdef MULTITHREADED
  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Queued Pkts to Process</TH>"
	      "<TD "TD_BG"  align=right>%d</TD></TR>\n",
	      myGlobals.packetQueueLen) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Max Queued Pkts</TH>"
	      "<TD "TD_BG"  align=right>%u</TD></TR>\n",
	      myGlobals.maxPacketQueueLen) < 0)
    BufferTooShort();
  sendString(buf);
#endif

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Stored Hash Hosts</TH>"
	      "<TD "TD_BG"  align=right>%d [%d %%]</TD></TR>\n",
	      (int)myGlobals.device[myGlobals.actualReportDeviceId].hostsno,
	      (((int)myGlobals.device[myGlobals.actualReportDeviceId].hostsno*100)/
	       (int)myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize)) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Purged Hash Hosts</TH>"
	      "<TD "TD_BG"  align=right>%u</TD></TR>\n",
	      (unsigned int)myGlobals.numPurgedHosts) < 0)
    BufferTooShort();
  sendString(buf);

  if(myGlobals.enableSessionHandling) {
    if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># TCP Sessions</TH>"
		"<TD "TD_BG"  align=right>%u</TD></TR>\n",
		myGlobals.device[myGlobals.actualReportDeviceId].numTcpSessions) < 0)
      BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Terminated TCP Sessions</TH>"
		"<TD "TD_BG"  align=right>%u</TD></TR>\n",
		(unsigned int)myGlobals.numTerminatedSessions) < 0)
      BufferTooShort();
    sendString(buf);
  }

#if defined(MULTITHREADED) && defined(ASYNC_ADDRESS_RESOLUTION)
  if(myGlobals.numericFlag == 0) {
    if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Queued Addresses</TH>"
		"<TD "TD_BG"  align=right>%d</TD></TR>\n", myGlobals.addressQueueLen) < 0)
      BufferTooShort();
    sendString(buf);
  }
#endif

  /* **** */

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Addresses Resolved with DNS</TH>"
	      "<TD "TD_BG"  align=right>%ld</TD></TR>\n", myGlobals.numResolvedWithDNSAddresses) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Addresses Kept Numeric</TH>"
	      "<TD "TD_BG"  align=right>%ld</TD></TR>\n", myGlobals.numKeptNumericAddresses) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Addresses Found in Cache</TH>"
	      "<TD "TD_BG"  align=right>%ld</TD></TR>\n", myGlobals.numResolvedOnCacheAddresses) < 0)
    BufferTooShort();
  sendString(buf);

#if defined(MULTITHREADED)
  if(myGlobals.numericFlag == 0) {
    if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Dropped Addresses</TH>"
		"<TD "TD_BG"  align=right>%ld</TD></TR>\n", (long int)myGlobals.droppedAddresses) < 0)
      BufferTooShort();
    sendString(buf);
  }
#endif

#if defined(MULTITHREADED)
  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Active Threads</TH>"
	      "<TD "TD_BG"  align=right>%d</TD></TR>\n", myGlobals.numThreads) < 0)
    BufferTooShort();
  sendString(buf);
#endif

#ifdef MEMORY_DEBUG
  if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left>Allocated Memory</TH>"
	      "<TD "TD_BG"  align=right>%s</TD></TR>\n",
	      formatBytes(allocatedMemory, 0)) < 0)
    BufferTooShort();
  sendString(buf);
#endif

  if(myGlobals.isLsofPresent) {
    if(snprintf(buf, sizeof(buf), "<TR><TH "TH_BG" align=left># Monitored Processes</TH>"
		"<TD "TD_BG"  align=right>%d</TD></TR>\n", myGlobals.numProcesses) < 0)
      BufferTooShort();
    sendString(buf);
  }

  sendString("</TABLE>"TABLE_OFF"\n");

  /* **************************** */

#if defined(MULTITHREADED) && defined(DEBUG)
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
  sendString("</TABLE>"TABLE_OFF"\n");
#endif /* MULTITHREADED && DEBUG */

  sendString("</CENTER>\n");
}

#endif /* MICRO_NTOP */

/* ******************************* */

static void initializeWeb(void) {
#ifndef MICRO_NTOP
  myGlobals.columnSort = 0, myGlobals.sortSendMode = 0;
#endif
  addDefaultAdminUser();
  initAccessLog();
}

/* **************************************** */

 /*
    SSL fix courtesy of
    Curtis Doty <Curtis@GreenKey.net>
 */
void initWeb() {
  int sockopt = 1;
  struct sockaddr_in sin;

  initReports();
  initializeWeb();

  myGlobals.actualReportDeviceId = 0;

  if(myGlobals.webPort > 0) {
    sin.sin_family      = AF_INET;
    sin.sin_port        = (int)htons((unsigned short int)myGlobals.webPort);
    sin.sin_addr.s_addr = INADDR_ANY;

#ifndef WIN32
    if(myGlobals.sslAddr) {
      if(!inet_aton(myGlobals.sslAddr, &sin.sin_addr))
	traceEvent(TRACE_ERROR, "Unable to convert address '%s'...\n"
		   "Not binding SSL to a particular interface!\n", myGlobals.sslAddr);
    }

    if(myGlobals.webAddr) {
      /* Code added to be able to bind to a particular interface */
      if(!inet_aton(myGlobals.webAddr, &sin.sin_addr))
	traceEvent(TRACE_ERROR, "Unable to convert address '%s'...\n"
		   "Not binding to a particular interface!\n",  myGlobals.webAddr);
    }
#endif

    myGlobals.sock = socket(AF_INET, SOCK_STREAM, 0);
    if(myGlobals.sock < 0) {
      traceEvent(TRACE_ERROR, "Unable to create a new socket");
      exit(-1);
    }

    setsockopt(myGlobals.sock, SOL_SOCKET, SO_REUSEADDR,
	       (char *)&sockopt, sizeof(sockopt));
  } else
    myGlobals.sock = 0;

#ifdef HAVE_OPENSSL
  if(myGlobals.sslInitialized) {
    myGlobals.sock_ssl = socket(AF_INET, SOCK_STREAM, 0);
    if(myGlobals.sock_ssl < 0) {
      traceEvent(TRACE_ERROR, "unable to create a new socket");
      exit(-1);
    }

    setsockopt(myGlobals.sock_ssl, SOL_SOCKET, SO_REUSEADDR,
	       (char *)&sockopt, sizeof(sockopt));
  }
#endif

  if(myGlobals.webPort > 0) {
    if(bind(myGlobals.sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
      traceEvent(TRACE_WARNING, "bind: port %d already in use.", myGlobals.webPort);
      closeNwSocket(&myGlobals.sock);
      exit(-1);
    }
  }

#ifdef HAVE_OPENSSL
  if(myGlobals.sslInitialized) {
    sin.sin_family      = AF_INET;
    sin.sin_port        = (int)htons(myGlobals.sslPort);
    sin.sin_addr.s_addr = INADDR_ANY;

    if(bind(myGlobals.sock_ssl, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
      /* Fix below courtesy of Matthias Kattanek <mattes@mykmk.com> */
      traceEvent(TRACE_ERROR, "bind: port %d already in use.", myGlobals.sslPort);
      closeNwSocket(&myGlobals.sock_ssl);
      exit(-1);
    }
  }
#endif

  if(myGlobals.webPort > 0) {
    if(listen(myGlobals.sock, 2) < 0) {
      traceEvent(TRACE_WARNING, "listen error.\n");
      closeNwSocket(&myGlobals.sock);
      exit(-1);
    }
  }

#ifdef HAVE_OPENSSL
  if(myGlobals.sslInitialized)
    if(listen(myGlobals.sock_ssl, 2) < 0) {
      traceEvent(TRACE_WARNING, "listen error.\n");
      closeNwSocket(&myGlobals.sock_ssl);
      exit(-1);
    }
#endif

  if(myGlobals.webPort > 0) {
    /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
    if(myGlobals.webAddr)
      traceEvent(TRACE_INFO, "Waiting for HTTP connections on %s port %d...\n",
		 myGlobals.webAddr, myGlobals.webPort);
    else
      traceEvent(TRACE_INFO, "Waiting for HTTP connections on port %d...\n",
		 myGlobals.webPort);
  }

#ifdef HAVE_OPENSSL
  if(myGlobals.sslInitialized)
    traceEvent(TRACE_INFO, "Waiting for HTTPS (SSL) connections on port %d...\n",
	       myGlobals.sslPort);
#endif

#ifdef MULTITHREADED
  createThread(&myGlobals.handleWebConnectionsThreadId, handleWebConnections, NULL);
#endif
}

/* **************************************** */


/* ******************************************* */

void* handleWebConnections(void* notUsed _UNUSED_) {
#ifndef MULTITHREADED
  struct timeval wait_time;
#else
  int rc;
#endif
  fd_set mask, mask_copy;
  int topSock = myGlobals.sock;

  FD_ZERO(&mask);

  traceEvent(TRACE_INFO, "Started thread (%ld) for web server.\n",
             myGlobals.handleWebConnectionsThreadId);


  if(myGlobals.webPort > 0)
    FD_SET((unsigned int)myGlobals.sock, &mask);

#ifdef HAVE_OPENSSL
  if(myGlobals.sslInitialized) {
    FD_SET(myGlobals.sock_ssl, &mask);
    if(myGlobals.sock_ssl > topSock)
      topSock = myGlobals.sock_ssl;
  }
#endif

  memcpy(&mask_copy, &mask, sizeof(fd_set));

#ifndef MULTITHREADED
  /* select returns immediately */
  wait_time.tv_sec = 0, wait_time.tv_usec = 0;
  if(select(topSock+1, &mask, 0, 0, &wait_time) == 1)
    handleSingleWebConnection(&mask);
#else /* MULTITHREADED */
  while(myGlobals.capturePackets) {
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

static void handleSingleWebConnection(fd_set *fdmask) {
  struct sockaddr_in from;
  int from_len = sizeof(from);

  errno = 0;

  if(FD_ISSET(myGlobals.sock, fdmask)) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Accepting HTTP request...\n");
#endif
    myGlobals.newSock = accept(myGlobals.sock, (struct sockaddr*)&from, &from_len);
  } else {
#ifdef DEBUG
#ifdef HAVE_OPENSSL
    if(myGlobals.sslInitialized)
      traceEvent(TRACE_INFO, "Accepting HTTPS request...\n");
#endif
#endif
#ifdef HAVE_OPENSSL
    if(myGlobals.sslInitialized)
      myGlobals.newSock = accept(myGlobals.sock_ssl, (struct sockaddr*)&from, &from_len);
#else
    ;
#endif
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Request accepted (sock=%d) (errno=%d)\n", myGlobals.newSock, errno);
#endif

  if(myGlobals.newSock > 0) {
#ifdef HAVE_OPENSSL
    if(myGlobals.sslInitialized)
      if(FD_ISSET(myGlobals.sock_ssl, fdmask)) {
	if(accept_ssl_connection(myGlobals.newSock) == -1) {
	  traceEvent(TRACE_WARNING, "Unable to accept SSL connection\n");
	  closeNwSocket(&myGlobals.newSock);
	  return;
	} else {
	  myGlobals.newSock = -myGlobals.newSock;
	}
      }
#endif /* HAVE_OPENSSL */

#ifdef HAVE_LIBWRAP
    {
      struct request_info req;
      request_init(&req, RQ_DAEMON, DAEMONNAME, RQ_FILE, myGlobals.newSock, NULL);
      fromhost(&req);
      if(!hosts_access(&req)) {
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

    closeNwSocket(&myGlobals.newSock);
  } else {
    traceEvent(TRACE_INFO, "Unable to accept HTTP(S) request (errno=%d)", errno);
  }
}

/* ******************* */

int handlePluginHTTPRequest(char* url) {
  FlowFilterList *flows = myGlobals.flowsList;

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
	  BufferTooShort();
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
