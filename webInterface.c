/*
 *  Copyright (C) 1998-2003 Luca Deri <deri@ntop.org>
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

#if defined(HAVE_MALLINFO_MALLOC_H) && defined(HAVE_MALLOC_H) && defined(__GNUC__)
#include <malloc.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#endif

#ifdef MAKE_WITH_SSLWATCHDOG
/* Stuff for the watchdog */
#include <setjmp.h>

jmp_buf sslwatchdogJump;

/* Forward */
void* sslwatchdogChildThread(void* notUsed _UNUSED_);
void sslwatchdogSighandler (int signum);
int sslwatchdogSignal(int parentchildFlag);

#endif

#ifdef PARM_USE_COLOR
static short alternateColor=0;
#endif

/* Forward */
static void handleSingleWebConnection(fd_set *fdmask);

#if defined(CFG_NEED_INET_ATON)
/*
 * Minimal implementation of inet_aton.
 * Cannot distinguish between failure and a local broadcast address.
 */
static int inet_aton(const char *cp, struct in_addr *addr)
{
  addr->s_addr = inet_addr(cp);
  return (addr->s_addr == INADDR_NONE) ? 0 : 1;
}

#endif /* CFG_NEED_INET_ATON */

#ifdef HAVE_FILEDESCRIPTORBUG
static int tempFilesCreated=0;
#endif

/* ************************************* */

#if !defined(WIN32) && defined(PARM_USE_CGI)
int execCGI(char* cgiName) {
  char* userName = "nobody", line[384], buf[512];
  struct passwd * newUser = NULL;
  FILE *fd;
  int num, i;
  struct timeval wait_time;

  if(!(newUser = getpwnam(userName))) {
    traceEvent(CONST_TRACE_WARNING, "Unable to find user %s", userName);
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

  if(num == 0) {
    if(snprintf(line, sizeof(line), "QUERY_STRING=%s", getenv("PWD")) < 0) 
      BufferTooShort();
    putenv(line); /* PWD */
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "NOTE: CGI %s", line);
#endif
  }

  putenv("WD="CFG_DATAFILE_DIR);

  if(snprintf(line, sizeof(line), "%s/cgi/%s", CFG_DATAFILE_DIR, cgiName) < 0) 
    BufferTooShort();
  
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Executing CGI '%s'", line);
#endif

  if((fd = popen(line, "r")) == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Unable to exec %s", cgiName);
    return(-1);
  } else {
    fd_set mask;
    int allRight = 1;
    int fno = fileno(fd);
    
    for(;;) {

      FD_ZERO(&mask);
      FD_SET((unsigned int)fno, &mask);

      wait_time.tv_sec = 120; wait_time.tv_usec = 0;
      if(select(fno+1, &mask, 0, 0, &wait_time) > 0) {      
	if(!feof(fd)) {
	  num = fread(line, 1, 383, fd);
	  if(num > 0)
	    sendStringLen(line, num);
	} else
	  break;	
      } else {
	allRight = 0;
	break;
      }
    }

    pclose(fd);

#ifdef DEBUG
    if(allRight)
      traceEvent(CONST_TRACE_INFO, "CGI execution completed.");
    else
      traceEvent(CONST_TRACE_INFO, "CGI execution encountered some problems.");
#endif
    
    return(0);
  }
}
#endif /* !defined(WIN32) && defined(PARM_USE_CGI) */

/* **************************************** */

#if(defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H)) || defined(WIN32) || defined(HPUX) || defined(AIX) || defined(DARWIN)
void showPluginsList(char* pluginName) {
  FlowFilterList *flows = myGlobals.flowsList;
  short doPrintHeader = 0;
  char tmpBuf[LEN_GENERAL_WORK_BUFFER], *thePlugin, tmpBuf1[LEN_GENERAL_WORK_BUFFER];
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
	 && (strcmp(flows->pluginStatus.pluginPtr->pluginURLname, thePlugin) == 0)
	 && (flows->pluginStatus.activePlugin != newPluginStatus)) {
	char key[64];

	if(newPluginStatus == 0 /* disabled */) {
	  if(flows->pluginStatus.pluginPtr->termFunct != NULL)
	    flows->pluginStatus.pluginPtr->termFunct();
	} else {
	  if(flows->pluginStatus.pluginPtr->startFunct != NULL)
	    flows->pluginStatus.pluginPtr->startFunct();
	  if(flows->pluginStatus.pluginPtr->pluginStatusMessage != NULL)
	    newPluginStatus = 0 /* Disabled */;
	}

	flows->pluginStatus.activePlugin = newPluginStatus;

	if(snprintf(key, sizeof(key), "pluginStatus.%s", 
		    flows->pluginStatus.pluginPtr->pluginName) < 0)
	  BufferTooShort();

	storePrefsValue(key, newPluginStatus ? "1" : "0");
      }

      if(!doPrintHeader) {
	printHTMLheader("Available Plugins", 0);
 	sendString("<CENTER>\n"
		   ""TABLE_ON"<TABLE BORDER=1><TR>\n"
		   "<TR><TH "TH_BG">View</TH><TH "TH_BG">Configure</TH><TH "TH_BG">Description</TH>"
		   "<TH "TH_BG">Version</TH>"
		   "<TH "TH_BG">Author</TH>"
		   "<TH "TH_BG">Active<br><i>(click to change)</i></TH>"
		   "</TR>\n");
	doPrintHeader = 1;
      }

      if(snprintf(tmpBuf1, sizeof(tmpBuf1), "<A HREF=/plugins/%s>%s</A>",
		  flows->pluginStatus.pluginPtr->pluginURLname, flows->pluginStatus.pluginPtr->pluginURLname) < 0)
	BufferTooShort();

      if(snprintf(tmpBuf, sizeof(tmpBuf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT %s>",
		  getRowColor(),
                  flows->pluginStatus.pluginPtr->pluginStatusMessage != NULL ?
                      "rowspan=\"2\"" :
                      "") < 0)
	BufferTooShort();
      sendString(tmpBuf);

      if(flows->pluginStatus.pluginPtr->inactiveSetup) {
          sendString("&nbsp;</TH>\n");
      } else {
          if(snprintf(tmpBuf, sizeof(tmpBuf), "%s</TH>\n",
                      flows->pluginStatus.activePlugin ?
                          tmpBuf1 : flows->pluginStatus.pluginPtr->pluginURLname) < 0)
            BufferTooShort();
          sendString(tmpBuf);
      } 

      if(snprintf(tmpBuf, sizeof(tmpBuf), "<TH "TH_BG" ALIGN=LEFT %s>",
                  flows->pluginStatus.pluginPtr->pluginStatusMessage != NULL ?
                      "rowspan=\"2\"" :
                      "") < 0)
	BufferTooShort();
      sendString(tmpBuf);

      if(flows->pluginStatus.pluginPtr->inactiveSetup) {
          if(snprintf(tmpBuf, sizeof(tmpBuf), "%s</TH>\n", tmpBuf1) < 0)
            BufferTooShort();
          sendString(tmpBuf);
      } else {
          sendString("&nbsp;</TH>\n");
      } 

      if(flows->pluginStatus.pluginPtr->pluginStatusMessage != NULL) {
	if(snprintf(tmpBuf, sizeof(tmpBuf), "<TD colspan=\"4\"><font COLOR=\"#FF0000\">%s</font></TD></TR>\n<TR "TR_ON" %s>\n",
		    flows->pluginStatus.pluginPtr->pluginStatusMessage,
		    getRowColor()) < 0)
	  BufferTooShort();
	sendString(tmpBuf);
      }

      if(snprintf(tmpBuf, sizeof(tmpBuf), "<TD "TD_BG" ALIGN=LEFT>%s</TD>"
		  "<TD "TD_BG" ALIGN=CENTER>%s</TD>"
		  "<TD "TD_BG" ALIGN=LEFT>%s</TD>"
		  "<TD "TD_BG" ALIGN=CENTER><A HREF="STR_SHOW_PLUGINS"?%s=%d>%s</A></TD>"
		  "</TR>\n",
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

  if(!doPrintHeader) {
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

static char* makeHostAgeStyleSpec(HostTraffic *el, char *buf, int bufSize) {
  int age;

  /* return(""); */

  if(myGlobals.actTime - el->firstSeen > 60*60)
    age = 60;
  else if(myGlobals.actTime - el->firstSeen > 30*60)
    age = 30;
  else if(myGlobals.actTime - el->firstSeen > 15*60)
    age = 15;
  else if(myGlobals.actTime - el->firstSeen > 5*60)
    age = 5;
  else
    age = 0;
  
  snprintf(buf, bufSize, "class=\"age%dmin\"", age);
  
  return(buf);
}

/* ******************************* */

char* makeHostLink(HostTraffic *el, short mode,
		   short cutName, short addCountryFlag) {
  static char buf[5][2*LEN_GENERAL_WORK_BUFFER];
  char symIp[256], *tmpStr, linkName[256], flag[256], colorSpec[64];
  char *dynIp, *p2p, osBuf[128];
  char *multihomed, *gwStr, *brStr, *dnsStr, *printStr, *smtpStr, *healthStr = "", *userStr;
  short specialMacAddress = 0;
  static short bufIdx=0;
  short usedEthAddress=0;
  int i;

  if(el == NULL)
    return("&nbsp;");

  if(broadcastHost(el)
     || ((el->hostIpAddress.s_addr == 0) && (el->ethAddressString[0] == '\0'))) {
    FD_SET(FLAG_BROADCAST_HOST, &el->flags); /* Just to be safe */
    if(mode == FLAG_HOSTLINK_HTML_FORMAT) 
      return("<TH "TH_BG" ALIGN=LEFT>&lt;broadcast&gt;</TH>");
    else
      return("&lt;broadcast&gt;");
  }

  setHostFingerprint(el);

  bufIdx = (bufIdx+1)%5;

  accessAddrResMutex("makeHostLink");

  if((el == myGlobals.otherHostEntry)
     || (cmpSerial(&el->hostSerial, &myGlobals.otherHostEntry->hostSerial))) {
    char *fmt;

    if(mode == FLAG_HOSTLINK_HTML_FORMAT)
      fmt = "<TH "TH_BG" ALIGN=LEFT>%s</TH>";
    else
      fmt = "%s";

    if(snprintf(buf[bufIdx], LEN_GENERAL_WORK_BUFFER, fmt, el->hostSymIpAddress) < 0)
      BufferTooShort();

    releaseAddrResMutex();
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

  releaseAddrResMutex();

  if(specialMacAddress) {
    tmpStr = el->ethAddressString;
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "->'%s/%s'", symIp, el->ethAddressString);
#endif
  } else {
    if(usedEthAddress) {
      if(el->nonIPTraffic) {
	if(el->nonIPTraffic->nbHostName != NULL) {
	  strncpy(symIp, el->nonIPTraffic->nbHostName, sizeof(symIp));
	} else if(el->nonIPTraffic->ipxHostName != NULL) {
	  strncpy(symIp, el->nonIPTraffic->ipxHostName, sizeof(symIp));
	}
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
    char *vendorInfo;

    if(el->nonIPTraffic) {    
      if(el->nonIPTraffic->nbHostName != NULL) {
	strncpy(symIp, el->nonIPTraffic->nbHostName, sizeof(linkName));
      } else if(el->nonIPTraffic->ipxHostName != NULL) {
	strncpy(symIp, el->nonIPTraffic->ipxHostName, sizeof(linkName));
      } else {
	vendorInfo = getVendorInfo(el->ethAddress, 0);
	if(vendorInfo[0] != '\0') {
	  sprintf(symIp, "%s%s", vendorInfo, &linkName[8]);
	}
      }
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
    dynIp = "&nbsp;<IMG ALT=\"DHCP Client\" SRC=\"/bulb.gif\" BORDER=0>&nbsp;";
  else {
    if(isDHCPServer(el))
      dynIp = "&nbsp;<IMG ALT=\"DHCP Server\" SRC=\"/antenna.gif\" BORDER=0>&nbsp;";
    else
      dynIp = "";
  }

  if(isMultihomed(el))     multihomed = "&nbsp;<IMG ALT=Multihomed SRC=\"/multihomed.gif\"\" BORDER=0>"; else multihomed = "";
  if(isBridgeHost(el))     brStr = "&nbsp;<IMG ALT=Bridge SRC=\"/bridge.gif\" BORDER=0>"; else brStr = "";
  if(gatewayHost(el))      gwStr = "&nbsp;<IMG ALT=Router SRC=\"/router.gif\" BORDER=0>"; else gwStr = "";
  if(nameServerHost(el))   dnsStr = "&nbsp;<IMG ALT=\"DNS\" SRC=\"/dns.gif\" BORDER=0>"; else dnsStr = "";
  if(isPrinter(el))        printStr = "&nbsp;<IMG ALT=Printer SRC=\"/printer.gif\" BORDER=0>"; else printStr = "";
  if(isSMTPhost(el))       smtpStr = "&nbsp;<IMG ALT=\"Mail (SMTP)\" SRC=\"/mail.gif\" BORDER=0>"; else smtpStr = "";
  if(el->protocolInfo != NULL) {
    if(el->protocolInfo->userList != NULL) userStr = "&nbsp;<IMG ALT=Users SRC=\"/users.gif\" BORDER=0>"; else userStr = "";
    if(el->protocolInfo->fileList != NULL) p2p = "&nbsp;<IMG ALT=P2P SRC=\"/p2p.gif\" BORDER=0>"; else p2p = "";
  } else {
    userStr = "";
    p2p = "";
  }

  switch(isHostHealthy(el)) {
  case 0: /* OK */
    healthStr = "";
    break;
  case 1: /* Warning */
    healthStr = "<IMG ALT=\"Medium Risk\" SRC=\"/Risk_medium.gif\" BORDER=0>";
    break;
  case 2: /* Error */
    healthStr = "<IMG ALT=\"High Risk\" SRC=\"/Risk_high.gif\" BORDER=0>";
    break;
  }

  /* Fixup ethernet addresses for RFC1945 compliance (: is bad, _ is good) */
  for(i=0; linkName[i] != '\0'; i++)
    if(linkName[i] == ':')
      linkName[i] = '_';

  if(strstr(symIp, ":"))
    usedEthAddress = 1;

  if(mode == FLAG_HOSTLINK_HTML_FORMAT) {
    if(snprintf(buf[bufIdx], 2*LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG" ALIGN=LEFT NOWRAP>"
		"<A HREF=\"/%s.html\" %s>%s</A> %s%s%s%s%s%s%s%s%s%s%s%s</TH>%s",
		linkName, "", symIp, 
		getOSFlag(el, NULL, 0, osBuf, sizeof(osBuf)), dynIp, multihomed, 
		usedEthAddress ? "<IMG SRC=/card.gif BORDER=0>" : "", 
		gwStr, brStr, dnsStr, printStr, smtpStr, healthStr, userStr, p2p, flag) < 0)
      BufferTooShort();
  } else {
    if(snprintf(buf[bufIdx], 2*LEN_GENERAL_WORK_BUFFER, "<A HREF=\"/%s.html\" %s NOWRAP>%s</A>"
		"%s%s%s%s%s%s%s%s%s%s%s",
		linkName, makeHostAgeStyleSpec(el, colorSpec, sizeof(colorSpec)), symIp, 
		multihomed, 
		usedEthAddress ? "<IMG SRC=/card.gif BORDER=0>" : "", gwStr, dnsStr,
		printStr, smtpStr, healthStr, userStr, p2p,
		dynIp, flag) < 0)
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

  accessAddrResMutex("getHostName");
  tmpStr = el->hostSymIpAddress;

  if((tmpStr == NULL) || (tmpStr[0] == '\0')) {
    /* The DNS is still getting the entry name */
    if(el->hostNumIpAddress[0] != '\0')
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

  releaseAddrResMutex();
  return(buf[bufIdx]);
}

/* ********************************** */

char* calculateCellColor(Counter actualValue,
			 Counter avgTrafficLow, Counter avgTrafficHigh) {

  if(actualValue < avgTrafficLow)
    return("BGCOLOR=#AAAAAAFF"); /* light blue */
  else if(actualValue < avgTrafficHigh)
    return("BGCOLOR=#00FF75"); /* light green */
  else
    return("BGCOLOR=#FF7777"); /* light red */
}

/* ************************ */

char* getHostCountryIconURL(HostTraffic *el) {
  char path[128], *ret;
  struct stat buf;

  fillDomainName(el);

  if(el ->fullDomainName == NULL) {
    ret = "&nbsp;";
    return(ret);
  }

  if(snprintf(path, sizeof(path), "%s/html/statsicons/flags/%s.gif",
	      CFG_DATAFILE_DIR, el->fullDomainName) < 0)
    BufferTooShort();

  if(stat(path, &buf) == 0)
    ret = getCountryIconURL(el->fullDomainName, FALSE);
  else
    ret = getCountryIconURL(el->dotDomainName, el->dotDomainNameIsFallback);

  if(ret == NULL)
    ret = "&nbsp;";

  return(ret);
}

/* ************************ */

char* getCountryIconURL(char* domainName, u_short fullDomainNameIsFallback) {
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
		  CFG_DATAFILE_DIR, domainName) < 0)
	BufferTooShort();

      if(stat(path, &buf) != 0)
	return("&nbsp;");
    }

    if(snprintf(flagBuf, sizeof(flagBuf),
		"<IMG ALT=\"Flag for(ISO 3166 code) %s %s\" ALIGN=MIDDLE SRC=\"/statsicons/flags/%s.gif\" BORDER=0>%s",
		domainName,
                fullDomainNameIsFallback == TRUE ? 
		"(Guessing from gTLD/ccTLD)" :
		"(from p2c file)",
                domainName,
                fullDomainNameIsFallback == TRUE ? " (?)" : "") < 0) BufferTooShort();

    return(flagBuf);
  }
}

/* ******************************* */

char* getRowColor(void) {

#ifdef PARM_USE_COLOR
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

#ifdef PARM_USE_COLOR
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
  char buf[LEN_GENERAL_WORK_BUFFER], *selected;

  printHTMLheader("Network Interface Switch", BITFLAG_HTML_NO_REFRESH);
  sendString("<HR>\n");

  if(snprintf(buf, sizeof(buf), "<p><font face=\"Helvetica, Arial, Sans Serif\">Note that "
	      "the NetFlow and sFlow plugins - if enabled - force -M to be set (i.e. "
	      "they disable interface merging).</font></p>\n") < 0)
    BufferTooShort();
  sendString(buf);

  sendString("<P>\n<FONT FACE=\"Helvetica, Arial, Sans Serif\"><B>\n");
  
  if(myGlobals.mergeInterfaces) {
    if(snprintf(buf, sizeof(buf), "Sorry, but you cannot switch among different interfaces "
                "unless the -M command line switch is used.\n") < 0)
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
    char value[8];
    
    myGlobals.actualReportDeviceId = (mwInterface)%myGlobals.numDevices;
    if(snprintf(buf, sizeof(buf), "The current interface is now [%s].\n",
		myGlobals.device[myGlobals.actualReportDeviceId].name) < 0)
      BufferTooShort();
    sendString(buf);
    
    snprintf(value, sizeof(value), "%d", myGlobals.actualReportDeviceId);
    storePrefsValue("actualReportDeviceId", value);
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

    sendString("<p><INPUT TYPE=submit VALUE=\"Switch NIC\">&nbsp;<INPUT TYPE=reset VALUE=Reset>\n</FORM>\n");
    sendString("<B>");
  }

  sendString("</B>");
  sendString("</font><p>\n");
}

/* **************************************** */

void shutdownNtop(void) {
  printHTMLheader("ntop is shutting down...", BITFLAG_HTML_NO_REFRESH);
  closeNwSocket(&myGlobals.newSock);
  termAccessLog();

#ifdef MAKE_WITH_XMLDUMP
  if(myGlobals.xmlFileOut != NULL) {
    int rc;

    traceEvent(CONST_TRACE_INFO, "Saving ntop data (xml) to %s...", myGlobals.xmlFileOut);

    /* Take the shutdown dump */
    rc = dumpXML(1, NULL);
    if(rc != 0) {
      traceEvent(CONST_TRACE_ERROR, "xml save, rc %d", rc);
    }
  }
#endif

  cleanup(0);
}

/* ******************************** */

static void printFeatureConfigNum(int textPrintFlag, char* feature, int value) {
  char tmpBuf[32];

  sendString(texthtml("", "<TR><TH "TH_BG" ALIGN=\"left\" width=\"250\">"));
  sendString(feature);
  sendString(texthtml(".....", "</TH><TD "TD_BG" ALIGN=\"right\">"));
  snprintf(tmpBuf, sizeof(tmpBuf), "%d", value);
  sendString(tmpBuf);
  sendString(texthtml("\n", "</TD></TR>\n"));
}

static void printFeatureConfigInfo(int textPrintFlag, char* feature, char* status) {
  char *tmpStr, tmpBuf[LEN_GENERAL_WORK_BUFFER];
  char *strtokState;

  sendString(texthtml("", "<TR><TH "TH_BG" ALIGN=\"left\" width=\"250\">"));
  sendString(feature);
  sendString(texthtml(".....", "</TH><TD "TD_BG" ALIGN=\"right\">"));
  if(status == NULL) {
    sendString("(nil)");
  } else {
    if (snprintf(tmpBuf, sizeof(tmpBuf), "%s", status) < 0)
      BufferTooShort();
    tmpStr = strtok_r(tmpBuf, "\n", &strtokState);
    while(tmpStr != NULL) {
      sendString(tmpStr);
      tmpStr = strtok_r(NULL, "\n", &strtokState);
      if(tmpStr != NULL) {
	sendString(texthtml("\n          ", "<BR>"));
      }
    }
  }
  sendString(texthtml("\n", "</TD></TR>\n"));
}

/* ******************************** */

static void printParameterConfigInfo(int textPrintFlag, char* feature, char* status, char* defaultValue) {
  sendString(texthtml("", "<TR><TH "TH_BG" ALIGN=\"left\" width=\"250\">"));
  sendString(feature);
  sendString(texthtml(".....", "</TH><TD "TD_BG" ALIGN=\"right\">"));
  if(status == NULL) {
    if(defaultValue == NULL) {
      sendString(CONST_REPORT_ITS_DEFAULT);
    }
  } else if( (defaultValue != NULL) && (strcmp(status, defaultValue) == 0) ){
    sendString(CONST_REPORT_ITS_DEFAULT);
  }
  if(status == NULL) {
    sendString("(nil)");
  } else {
    sendString(status);
  }
  sendString(texthtml("\n", "</TD></TR>\n"));
}

/* ******************************** */

void printNtopConfigHInfo(int textPrintFlag) {
  char buf[LEN_GENERAL_WORK_BUFFER];

  sendString(texthtml("\n\nCompile Time: Debug settings in globals-defines.h\n\n",
                      "<tr><th colspan=\"2\"" TH_BG ">Compile Time: Debug settings in globals-defines.h</tr>\n"));

  printFeatureConfigInfo(textPrintFlag, "DEBUG",
#ifdef DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "ADDRESS_DEBUG",
#ifdef ADDRESS_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "DNS_DEBUG",
#ifdef DNS_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "DNS_SNIFF_DEBUG",
#ifdef DNS_SNIFF_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "FTP_DEBUG",
#ifdef FTP_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "GDBM_DEBUG",
#ifdef GDBM_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "HASH_DEBUG",
#ifdef HASH_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "HOST_FREE_DEBUG",
#ifdef HOST_FREE_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "HTTP_DEBUG",
#ifdef HTTP_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "IDLE_PURGE_DEBUG",
#ifdef IDLE_PURGE_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "INITWEB_DEBUG",
#ifdef INITWEB_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "MEMORY_DEBUG",
#ifdef MEMORY_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "NETFLOW_DEBUG",
#ifdef NETFLOW_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "SEMAPHORE_DEBUG",
#ifdef SEMAPHORE_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "SESSION_TRACE_DEBUG",
#ifdef SESSION_TRACE_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

#ifdef MAKE_WITH_SSLWATCHDOG
  printFeatureConfigInfo(textPrintFlag, "SSLWATCHDOG_DEBUG",
#ifdef SSLWATCHDOG_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );
#endif

  printFeatureConfigInfo(textPrintFlag, "STORAGE_DEBUG",
#ifdef STORAGE_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "UNKNOWN_PACKET_DEBUG",
#ifdef UNKNOWN_PACKET_DEBUG
			 "yes"
#else
			 "no"
#endif
			 );

  sendString(texthtml("\n\nCompile Time: globals-define.h\n\n",
                      "<tr><th colspan=\"2\"" TH_BG ">Compile Time: globals-define.h</tr>\n"));

  printFeatureConfigInfo(textPrintFlag, "PARM_PRINT_ALL_SESSIONS",
#ifdef PARM_PRINT_ALL_SESSIONS
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "PARM_PRINT_RETRANSMISSION_DATA",
#ifdef PARM_PRINT_RETRANSMISSION_DATA
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "PARM_FORK_CHILD_PROCESS",
#ifdef PARM_FORK_CHILD_PROCESS
			 "yes (normal)"
#else
			 "no"
#endif
			 );

#ifndef WIN32
  if(snprintf(buf, sizeof(buf),
              "globals-defines.h: %s#define PARM_USE_CGI%s",
#ifdef PARM_USE_CGI
              "", ""
#else
              "/* ", " */"
#endif
              ) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "CGI Scripts", buf);
#endif /* WIN32 */

  if(snprintf(buf, sizeof(buf),
              "globals-defines.h: %s#define PARM_USE_COLOR%s",
#ifdef PARM_USE_COLOR
              "", ""
#else
              "/* ", " */"
#endif
              ) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Alternate row colors", buf);

  if(snprintf(buf, sizeof(buf),
              "globals-defines.h: %s#define PARM_USE_HOST%s",
#ifdef PARM_USE_HOST
              "", ""
#else
              "/* ", " */"
#endif
              ) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Buggy gethostbyaddr() - use alternate implementation", buf);
  printFeatureConfigInfo(textPrintFlag, "MAKE_ASYNC_ADDRESS_RESOLUTION",
#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
			 "yes"
#else
			 "no"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_SSLWATCHDOG",
#ifdef MAKE_WITH_SSLWATCHDOG
			 "yes"
#else
			 "no"
#endif
			 );

#ifdef MAKE_WITH_SSLWATCHDOG
  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_SSLWATCHDOG_RUNTIME (derived)",
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
			 "yes"
#else
			 "no"
#endif
			 );
#endif

  if(snprintf(buf, sizeof(buf), 
              "globals-defines.h: #define MAX_NUM_BAD_IP_ADDRESSES %d", MAX_NUM_BAD_IP_ADDRESSES) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Bad IP Address table size", buf);


  if(snprintf(buf, sizeof(buf), 
              "#define PARM_MIN_WEBPAGE_AUTOREFRESH_TIME %d", PARM_MIN_WEBPAGE_AUTOREFRESH_TIME) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Minimum refresh interval (seconds)", buf);

  if(snprintf(buf, sizeof(buf),
              "#define MAX_NUM_PROTOS %d", MAX_NUM_PROTOS) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Maximum # of Protocols to show in graphs", buf);

  if(snprintf(buf, sizeof(buf),
              "#define MAX_NUM_ROUTERS %d", MAX_NUM_ROUTERS) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Maximum # of routers (Local Subnet Routers report)", buf);

  if(snprintf(buf, sizeof(buf),
              "#define MAX_NUM_DEVICES %d", MAX_NUM_DEVICES) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Maximum # of network interface devices", buf);

  if(snprintf(buf, sizeof(buf),
              "#define MAX_SUBNET_HOSTS %d", MAX_SUBNET_HOSTS) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Maximum network size (hosts per interface)", buf);

  if(snprintf(buf, sizeof(buf),
              "#define MAX_PASSIVE_FTP_SESSION_TRACKER %d", MAX_PASSIVE_FTP_SESSION_TRACKER) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Allocated # of passive FTP sessions", buf);

  if(snprintf(buf, sizeof(buf),
              "#define PARM_PASSIVE_SESSION_MINIMUM_IDLE %d", PARM_PASSIVE_SESSION_MINIMUM_IDLE) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Inactive passive FTP session timeout (seconds)", buf);


  sendString(texthtml("\n\nCompile Time: Hash Table Sizes\n\n",
                      "<tr><th colspan=\"2\"" TH_BG ">Compile Time: Hash Table Sizes</tr>\n"));

  if(snprintf(buf, sizeof(buf), 
              "#define CONST_HASH_INITIAL_SIZE %d", CONST_HASH_INITIAL_SIZE) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Size", buf);

  sendString(texthtml("\n\nCompile Time: globals-define.h\n\n",
                      "<tr><th colspan=\"2\"" TH_BG ">Compile Time: globals-define.h</tr>\n"));

  if(snprintf(buf, sizeof(buf), 
              "globals-report.h: #define CHART_FORMAT \"%s\"",
              CHART_FORMAT) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Chart Format", buf);

  sendString(texthtml("\n\nCompile Time: config.h\n\n",
                      "<tr><th colspan=\"2\"" TH_BG ">Compile Time: config.h</tr>\n"));

  /*
   * Drop the autogenerated lines (utils/config_h2.awk) in HERE 
   */

  /*                                                       B E G I N
   *
   * Autogenerated from config.h and inserted into webInterface.c 
   *      Thu Aug 21 09:34:24 CDT 2003
   *
   */

  printFeatureConfigInfo(textPrintFlag, "CFG_ETHER_HEADER_HAS_EA",
#ifdef CFG_ETHER_HEADER_HAS_EA
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "CFG_MULTITHREADED",
#ifdef CFG_MULTITHREADED
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_ALARM",
#ifdef HAVE_ALARM
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_ALLOCA",
#ifdef HAVE_ALLOCA
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_ALLOCA_H",
#ifdef HAVE_ALLOCA_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_ARPA_NAMESER_H",
#ifdef HAVE_ARPA_NAMESER_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_BACKTRACE",
#ifdef HAVE_BACKTRACE
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_BZERO",
#ifdef HAVE_BZERO
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_CTIME_R",
#ifdef HAVE_CTIME_R
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_DLFCN_H",
#ifdef HAVE_DLFCN_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_DL_H",
#ifdef HAVE_DL_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_DOPRNT",
#ifdef HAVE_DOPRNT
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_ENDPWENT",
#ifdef HAVE_ENDPWENT
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_ERRNO_H",
#ifdef HAVE_ERRNO_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_FACILITYNAMES",
#ifdef HAVE_FACILITYNAMES
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_FCNTL_H",
#ifdef HAVE_FCNTL_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_FORK",
#ifdef HAVE_FORK
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_GDBM_H",
#ifdef HAVE_GDBM_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_GD_H",
#ifdef HAVE_GD_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_GDOME_H",
#ifdef HAVE_GDOME_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_GETHOSTBYADDR",
#ifdef HAVE_GETHOSTBYADDR
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_GETHOSTBYADDR_R",
#ifdef HAVE_GETHOSTBYADDR_R
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_GETHOSTBYNAME",
#ifdef HAVE_GETHOSTBYNAME
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_GETHOSTNAME",
#ifdef HAVE_GETHOSTNAME
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_GETIPNODEBYADDR",
#ifdef HAVE_GETIPNODEBYADDR
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_GETPASS",
#ifdef HAVE_GETPASS
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_GETTIMEOFDAY",
#ifdef HAVE_GETTIMEOFDAY
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_GLIBCONFIG_H",
#ifdef HAVE_GLIBCONFIG_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_GLIB_H",
#ifdef HAVE_GLIB_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_IF_H",
#ifdef HAVE_IF_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_IN6_ADDR",
#ifdef HAVE_IN6_ADDR
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_INT16_T",
#ifdef HAVE_INT16_T
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_INT32_T",
#ifdef HAVE_INT32_T
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_INT64_T",
#ifdef HAVE_INT64_T
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_INT8_T",
#ifdef HAVE_INT8_T
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_INTTYPES_H",
#ifdef HAVE_INTTYPES_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LANGINFO_H",
#ifdef HAVE_LANGINFO_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBC",
#ifdef HAVE_LIBC
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBCRYPT",
#ifdef HAVE_LIBCRYPT
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBCRYPTO",
#ifdef HAVE_LIBCRYPTO
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBDL",
#ifdef HAVE_LIBDL
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBDLD",
#ifdef HAVE_LIBDLD
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBGD",
#ifdef HAVE_LIBGD
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBGDBM",
#ifdef HAVE_LIBGDBM
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBGDOME",
#ifdef HAVE_LIBGDOME
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBGLIB",
#ifdef HAVE_LIBGLIB
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBM",
#ifdef HAVE_LIBM
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBNSL",
#ifdef HAVE_LIBNSL
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBPCAP",
#ifdef HAVE_LIBPCAP
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBPNG",
#ifdef HAVE_LIBPNG
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBPOSIX4",
#ifdef HAVE_LIBPOSIX4
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBPTHREAD",
#ifdef HAVE_LIBPTHREAD
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBPTHREADS",
#ifdef HAVE_LIBPTHREADS
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBRESOLV",
#ifdef HAVE_LIBRESOLV
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBRT",
#ifdef HAVE_LIBRT
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBSOCKET",
#ifdef HAVE_LIBSOCKET
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBSSL",
#ifdef HAVE_LIBSSL
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBWRAP",
#ifdef HAVE_LIBWRAP
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBXML2",
#ifdef HAVE_LIBXML2
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBXNET",
#ifdef HAVE_LIBXNET
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBZ",
#ifdef HAVE_LIBZ
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIMITS_H",
#ifdef HAVE_LIMITS_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LINUX_IF_PPPOX_H",
#ifdef HAVE_LINUX_IF_PPPOX_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LOCALE_H",
#ifdef HAVE_LOCALE_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LOCALTIME_R",
#ifdef HAVE_LOCALTIME_R
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_LONG_DOUBLE",
#ifdef HAVE_LONG_DOUBLE
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_MATH_H",
#ifdef HAVE_MATH_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_MEMCHR",
#ifdef HAVE_MEMCHR
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_MEMORY_H",
#ifdef HAVE_MEMORY_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_MEMSET",
#ifdef HAVE_MEMSET
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NDIR_H",
#ifdef HAVE_NDIR_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NETDB_H",
#ifdef HAVE_NETDB_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_OPENSSL",
#ifdef HAVE_OPENSSL
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_OPENSSL_CRYPTO_H",
#ifdef HAVE_OPENSSL_CRYPTO_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_OPENSSL_ERR_H",
#ifdef HAVE_OPENSSL_ERR_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_OPENSSL_PEM_H",
#ifdef HAVE_OPENSSL_PEM_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_OPENSSL_RSA_H",
#ifdef HAVE_OPENSSL_RSA_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_OPENSSL_SSL_H",
#ifdef HAVE_OPENSSL_SSL_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_OPENSSL_X509_H",
#ifdef HAVE_OPENSSL_X509_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_PCAP_H",
#ifdef HAVE_PCAP_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_PCAP_OPEN_DEAD",
#ifdef HAVE_PCAP_OPEN_DEAD
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_PNG_H",
#ifdef HAVE_PNG_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_PTHREAD_ATFORK",
#ifdef HAVE_PTHREAD_ATFORK
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_PTHREAD_H",
#ifdef HAVE_PTHREAD_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_PUTENV",
#ifdef HAVE_PUTENV
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_PWD_H",
#ifdef HAVE_PWD_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_RE_COMP",
#ifdef HAVE_RE_COMP
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_REGCOMP",
#ifdef HAVE_REGCOMP
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_REGEX",
#ifdef HAVE_REGEX
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SCHED_H",
#ifdef HAVE_SCHED_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SCHED_YIELD",
#ifdef HAVE_SCHED_YIELD
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SECURITY_PAM_APPL_H",
#ifdef HAVE_SECURITY_PAM_APPL_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SELECT",
#ifdef HAVE_SELECT
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SEMAPHORE_H",
#ifdef HAVE_SEMAPHORE_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SETJMP_H",
#ifdef HAVE_SETJMP_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SHADOW_H",
#ifdef HAVE_SHADOW_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SIGNAL_H",
#ifdef HAVE_SIGNAL_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SNPRINTF",
#ifdef HAVE_SNPRINTF
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SOCKET",
#ifdef HAVE_SOCKET
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SQRT",
#ifdef HAVE_SQRT
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STDARG_H",
#ifdef HAVE_STDARG_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STDDEF_H",
#ifdef HAVE_STDDEF_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STDIO_H",
#ifdef HAVE_STDIO_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STDLIB_H",
#ifdef HAVE_STDLIB_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRCASECMP",
#ifdef HAVE_STRCASECMP
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRCHR",
#ifdef HAVE_STRCHR
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRCSPN",
#ifdef HAVE_STRCSPN
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRDUP",
#ifdef HAVE_STRDUP
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRERROR",
#ifdef HAVE_STRERROR
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRFTIME",
#ifdef HAVE_STRFTIME
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRING_H",
#ifdef HAVE_STRING_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRINGS_H",
#ifdef HAVE_STRINGS_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRNCASECMP",
#ifdef HAVE_STRNCASECMP
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRPBRK",
#ifdef HAVE_STRPBRK
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRRCHR",
#ifdef HAVE_STRRCHR
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRSPN",
#ifdef HAVE_STRSPN
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRSTR",
#ifdef HAVE_STRSTR
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRTOK_R",
#ifdef HAVE_STRTOK_R
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRTOUL",
#ifdef HAVE_STRTOUL
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_DIR_H",
#ifdef HAVE_SYS_DIR_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_IOCTL_H",
#ifdef HAVE_SYS_IOCTL_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_LDR_H",
#ifdef HAVE_SYS_LDR_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_NDIR_H",
#ifdef HAVE_SYS_NDIR_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_RESOURCE_H",
#ifdef HAVE_SYS_RESOURCE_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_SCHED_H",
#ifdef HAVE_SYS_SCHED_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_SOCKIO_H",
#ifdef HAVE_SYS_SOCKIO_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_TIME_H",
#ifdef HAVE_SYS_TIME_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_TYPES_H",
#ifdef HAVE_SYS_TYPES_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_UN_H",
#ifdef HAVE_SYS_UN_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_TCPD_H",
#ifdef HAVE_TCPD_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_TM_ZONE",
#ifdef HAVE_TM_ZONE
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_TZNAME",
#ifdef HAVE_TZNAME
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_U_INT16_T",
#ifdef HAVE_U_INT16_T
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_U_INT32_T",
#ifdef HAVE_U_INT32_T
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_U_INT64_T",
#ifdef HAVE_U_INT64_T
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_UINT64_T",
#ifdef HAVE_UINT64_T
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_U_INT8_T",
#ifdef HAVE_U_INT8_T
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_UNAME",
#ifdef HAVE_UNAME
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_UNISTD_H",
#ifdef HAVE_UNISTD_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_VFORK",
#ifdef HAVE_VFORK
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_VFORK_H",
#ifdef HAVE_VFORK_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_VPRINTF",
#ifdef HAVE_VPRINTF
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_WORKING_FORK",
#ifdef HAVE_WORKING_FORK
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_WORKING_VFORK",
#ifdef HAVE_WORKING_VFORK
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_ZLIB_H",
#ifdef HAVE_ZLIB_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_I18N",
#ifdef MAKE_WITH_I18N
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_SSLV3_SUPPORT",
#ifdef MAKE_WITH_SSLV3_SUPPORT
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_SSLWATCHDOG_COMPILETIME",
#ifdef MAKE_WITH_SSLWATCHDOG_COMPILETIME
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_XMLDUMP",
#ifdef MAKE_WITH_XMLDUMP
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_ZLIB",
#ifdef MAKE_WITH_ZLIB
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "__PROTOTYPES",
#ifdef __PROTOTYPES
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "PROTOTYPES",
#ifdef PROTOTYPES
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "SETVBUF_REVERSED",
#ifdef SETVBUF_REVERSED
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "TIME_WITH_SYS_TIME",
#ifdef TIME_WITH_SYS_TIME
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "TM_IN_SYS_TIME",
#ifdef TM_IN_SYS_TIME
                         "yes"
#else
                         "no"
#endif
                         );

  /*                                                       E N D
   *
   * Autogenerated from config.h and inserted into webInterface.c 
   *
   */

  /* Manual lines for special cases in config.h */

  printFeatureConfigInfo(textPrintFlag, "CFG_CONFIGFILE_DIR - config file directory", CFG_CONFIGFILE_DIR);

  printFeatureConfigInfo(textPrintFlag, "CFG_DATAFILE_DIR - data file directory", CFG_DATAFILE_DIR);

  printFeatureConfigInfo(textPrintFlag, "CFG_DBFILE_DIR - database file directory", CFG_DBFILE_DIR);

  printFeatureConfigInfo(textPrintFlag, "CFG_PLUGIN_DIR - plugin file directory", CFG_PLUGIN_DIR);

#ifdef CFG_RUN_DIR
  printFeatureConfigInfo(textPrintFlag, "CFG_RUN_DIR - run file directory", CFG_RUN_DIR);
#endif

  printFeatureConfigInfo(textPrintFlag, "CFG_NEED_GETDOMAINNAME (getdomainname(2) function)",
#ifdef CFG_NEED_GETDOMAINNAME
			 "no"
#else
			 "yes"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "CFG_xxxxxx_ENDIAN (Hardware Endian)",
#if defined(CFG_LITTLE_ENDIAN)
			 "little"
#elif defined(CFG_BIG_ENDIAN)
			 "big"
#else
			 "unknown"
#endif
			 );

  printFeatureConfigInfo(textPrintFlag, "HAVE_FILEDESCRIPTORBUG",
#ifdef HAVE_FILEDESCRIPTORBUG
                         "yes"
#else
                         "no"
#endif
                         );

  /* semi auto generated from globals-defines.h */

  sendString(texthtml("\n\nCompile Time: globals-defines.h\n\n",
                      "<tr><th colspan=\"2\"" TH_BG ">Compile Time: globals-defines.h</tr>\n"));

  /*                                                       B E G I N
   *
   * Autogenerated from globals-defines.h and inserted into webInterface.c 
   *      Thu Aug 21 09:34:24 CDT 2003
   *
   * Manual edits:

   (Already part of info.html/textinfo.html):
   MAKE_WITH_SSLWATCHDOG
   MAKE_WITH_SSLWATCHDOG_RUNTIME

   */

#ifdef EMSGSIZE
  printFeatureConfigNum(textPrintFlag, "EMSGSIZE", EMSGSIZE);
#else
  printFeatureConfigInfo(textPrintFlag, "EMSGSIZE", "undefined");
#endif

#ifdef ETHERMTU
  printFeatureConfigNum(textPrintFlag, "ETHERMTU", ETHERMTU);
#else
  printFeatureConfigInfo(textPrintFlag, "ETHERMTU", "undefined");
#endif

#ifdef LEN_CMDLINE_BUFFER
  printFeatureConfigNum(textPrintFlag, "LEN_CMDLINE_BUFFER", LEN_CMDLINE_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_CMDLINE_BUFFER", "undefined");
#endif

#ifdef LEN_FGETS_BUFFER
  printFeatureConfigNum(textPrintFlag, "LEN_FGETS_BUFFER", LEN_FGETS_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_FGETS_BUFFER", "undefined");
#endif

#ifdef LEN_GENERAL_WORK_BUFFER
  printFeatureConfigNum(textPrintFlag, "LEN_GENERAL_WORK_BUFFER", LEN_GENERAL_WORK_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_GENERAL_WORK_BUFFER", "undefined");
#endif

#ifdef LEN_MEDIUM_WORK_BUFFER
  printFeatureConfigNum(textPrintFlag, "LEN_MEDIUM_WORK_BUFFER", LEN_MEDIUM_WORK_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_MEDIUM_WORK_BUFFER", "undefined");
#endif

#ifdef LEN_SMALL_WORK_BUFFER
  printFeatureConfigNum(textPrintFlag, "LEN_SMALL_WORK_BUFFER", LEN_SMALL_WORK_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_SMALL_WORK_BUFFER", "undefined");
#endif

#ifdef LEN_TIME_STAMP_BUFFER
  printFeatureConfigNum(textPrintFlag, "LEN_TIME_STAMP_BUFFER", LEN_TIME_STAMP_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_TIME_STAMP_BUFFER", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "MAKE_NTOP_PACKETSZ_DECLARATIONS",
#ifdef MAKE_NTOP_PACKETSZ_DECLARATIONS
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_RMON_SUPPORT",
#ifdef MAKE_RMON_SUPPORT
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_FORK_COPYONWRITE",
#ifdef MAKE_WITH_FORK_COPYONWRITE
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_HTTPSIGTRAP",
#ifdef MAKE_WITH_HTTPSIGTRAP
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_NETFLOWSIGTRAP",
#ifdef MAKE_WITH_NETFLOWSIGTRAP
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_RRDSIGTRAP",
#ifdef MAKE_WITH_RRDSIGTRAP
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_SCHED_YIELD",
#ifdef MAKE_WITH_SCHED_YIELD
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_SEMAPHORES",
#ifdef MAKE_WITH_SEMAPHORES
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_SSLWATCHDOG",
#ifdef MAKE_WITH_SSLWATCHDOG
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_SSLWATCHDOG_RUNTIME",
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_SYSLOG",
#ifdef MAKE_WITH_SYSLOG
                         "yes"
#else
                         "no"
#endif
                         );

#ifdef MAX_ADDRESSES
  printFeatureConfigNum(textPrintFlag, "MAX_ADDRESSES", MAX_ADDRESSES);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_ADDRESSES", "undefined");
#endif

#ifdef MAX_ALIASES
  printFeatureConfigNum(textPrintFlag, "MAX_ALIASES", MAX_ALIASES);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_ALIASES", "undefined");
#endif

#ifdef MAX_ASSIGNED_IP_PORTS
  printFeatureConfigNum(textPrintFlag, "MAX_ASSIGNED_IP_PORTS", MAX_ASSIGNED_IP_PORTS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_ASSIGNED_IP_PORTS", "undefined");
#endif

#ifdef MAXCDNAME
  printFeatureConfigNum(textPrintFlag, "MAXCDNAME", MAXCDNAME);
#else
  printFeatureConfigInfo(textPrintFlag, "MAXCDNAME", "undefined");
#endif

#ifdef MAX_DEVICE_NAME_LEN
  printFeatureConfigNum(textPrintFlag, "MAX_DEVICE_NAME_LEN", MAX_DEVICE_NAME_LEN);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_DEVICE_NAME_LEN", "undefined");
#endif

#ifdef MAXDNAME
  printFeatureConfigNum(textPrintFlag, "MAXDNAME", MAXDNAME);
#else
  printFeatureConfigInfo(textPrintFlag, "MAXDNAME", "undefined");
#endif

#ifdef MAX_HASHDUMP_ENTRY
  printFeatureConfigNum(textPrintFlag, "MAX_HASHDUMP_ENTRY", MAX_HASHDUMP_ENTRY);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_HASHDUMP_ENTRY", "undefined");
#endif

#ifdef MAXHOSTNAMELEN
  printFeatureConfigNum(textPrintFlag, "MAXHOSTNAMELEN", MAXHOSTNAMELEN);
#else
  printFeatureConfigInfo(textPrintFlag, "MAXHOSTNAMELEN", "undefined");
#endif

#ifdef MAX_HOSTS_CACHE_LEN
  printFeatureConfigNum(textPrintFlag, "MAX_HOSTS_CACHE_LEN", MAX_HOSTS_CACHE_LEN);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_HOSTS_CACHE_LEN", "undefined");
#endif

#ifdef MAX_IP_PORT
  printFeatureConfigNum(textPrintFlag, "MAX_IP_PORT", MAX_IP_PORT);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_IP_PORT", "undefined");
#endif

#ifdef MAXLABEL
  printFeatureConfigNum(textPrintFlag, "MAXLABEL", MAXLABEL);
#else
  printFeatureConfigInfo(textPrintFlag, "MAXLABEL", "undefined");
#endif

#ifdef MAX_LANGUAGES_REQUESTED
  printFeatureConfigNum(textPrintFlag, "MAX_LANGUAGES_REQUESTED", MAX_LANGUAGES_REQUESTED);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_LANGUAGES_REQUESTED", "undefined");
#endif

#ifdef MAX_LANGUAGES_SUPPORTED
  printFeatureConfigNum(textPrintFlag, "MAX_LANGUAGES_SUPPORTED", MAX_LANGUAGES_SUPPORTED);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_LANGUAGES_SUPPORTED", "undefined");
#endif

#ifdef MAX_LASTSEEN_TABLE_SIZE
  printFeatureConfigNum(textPrintFlag, "MAX_LASTSEEN_TABLE_SIZE", MAX_LASTSEEN_TABLE_SIZE);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_LASTSEEN_TABLE_SIZE", "undefined");
#endif

#ifdef MAX_LEN_VENDOR_NAME
  printFeatureConfigNum(textPrintFlag, "MAX_LEN_VENDOR_NAME", MAX_LEN_VENDOR_NAME);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_LEN_VENDOR_NAME", "undefined");
#endif

#ifdef MAX_NFS_NAME_HASH
  printFeatureConfigNum(textPrintFlag, "MAX_NFS_NAME_HASH", MAX_NFS_NAME_HASH);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NFS_NAME_HASH", "undefined");
#endif

#ifdef MAX_NODE_TYPES
  printFeatureConfigNum(textPrintFlag, "MAX_NODE_TYPES", MAX_NODE_TYPES);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NODE_TYPES", "undefined");
#endif

#ifdef MAX_NUM_BAD_IP_ADDRESSES
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_BAD_IP_ADDRESSES", MAX_NUM_BAD_IP_ADDRESSES);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_BAD_IP_ADDRESSES", "undefined");
#endif

#ifdef MAX_NUM_CONTACTED_PEERS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_CONTACTED_PEERS", MAX_NUM_CONTACTED_PEERS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_CONTACTED_PEERS", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_DEQUEUE_THREADS",
#ifdef MAX_NUM_DEQUEUE_THREADS
                         "yes"
#else
                         "no"
#endif
                         );

#ifdef MAX_NUM_DEVICES
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_DEVICES", MAX_NUM_DEVICES);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_DEVICES", "undefined");
#endif

#ifdef MAX_NUM_DHCP_MSG
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_DHCP_MSG", MAX_NUM_DHCP_MSG);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_DHCP_MSG", "undefined");
#endif

#ifdef MAX_NUM_FIN
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_FIN", MAX_NUM_FIN);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_FIN", "undefined");
#endif

#ifdef MAX_NUM_IGNOREDFLOWS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_IGNOREDFLOWS", MAX_NUM_IGNOREDFLOWS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_IGNOREDFLOWS", "undefined");
#endif

#ifdef MAX_NUM_NETWORKS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_NETWORKS", MAX_NUM_NETWORKS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_NETWORKS", "undefined");
#endif

#ifdef MAX_NUM_PROBES
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_PROBES", MAX_NUM_PROBES);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_PROBES", "undefined");
#endif

#ifdef MAX_NUM_PROTOS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_PROTOS", MAX_NUM_PROTOS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_PROTOS", "undefined");
#endif

#ifdef MAX_NUM_PROTOS_SCREENS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_PROTOS_SCREENS", MAX_NUM_PROTOS_SCREENS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_PROTOS_SCREENS", "undefined");
#endif

#ifdef MAX_NUM_PURGED_SESSIONS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_PURGED_SESSIONS", MAX_NUM_PURGED_SESSIONS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_PURGED_SESSIONS", "undefined");
#endif

#ifdef MAX_NUM_PWFILE_ENTRIES
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_PWFILE_ENTRIES", MAX_NUM_PWFILE_ENTRIES);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_PWFILE_ENTRIES", "undefined");
#endif

#ifdef MAX_NUM_ROUTERS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_ROUTERS", MAX_NUM_ROUTERS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_ROUTERS", "undefined");
#endif

#ifdef MAX_NUM_STORED_FLAGS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_STORED_FLAGS", MAX_NUM_STORED_FLAGS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_STORED_FLAGS", "undefined");
#endif

#ifdef MAX_NUM_UNKNOWN_PROTOS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_UNKNOWN_PROTOS", MAX_NUM_UNKNOWN_PROTOS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_UNKNOWN_PROTOS", "undefined");
#endif

#ifdef MAX_PASSIVE_FTP_SESSION_TRACKER
  printFeatureConfigNum(textPrintFlag, "MAX_PASSIVE_FTP_SESSION_TRACKER", MAX_PASSIVE_FTP_SESSION_TRACKER);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_PASSIVE_FTP_SESSION_TRACKER", "undefined");
#endif

#ifdef MAX_PER_DEVICE_HASH_LIST
  printFeatureConfigNum(textPrintFlag, "MAX_PER_DEVICE_HASH_LIST", MAX_PER_DEVICE_HASH_LIST);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_PER_DEVICE_HASH_LIST", "undefined");
#endif

#ifdef MAX_SESSIONS_CACHE_LEN
  printFeatureConfigNum(textPrintFlag, "MAX_SESSIONS_CACHE_LEN", MAX_SESSIONS_CACHE_LEN);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_SESSIONS_CACHE_LEN", "undefined");
#endif

#ifdef MAX_SSL_CONNECTIONS
  printFeatureConfigNum(textPrintFlag, "MAX_SSL_CONNECTIONS", MAX_SSL_CONNECTIONS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_SSL_CONNECTIONS", "undefined");
#endif

#ifdef NAME_MAX
  printFeatureConfigNum(textPrintFlag, "NAME_MAX", NAME_MAX);
#else
  printFeatureConfigInfo(textPrintFlag, "NAME_MAX", "undefined");
#endif

#ifdef NETDB_SUCCESS
  printFeatureConfigNum(textPrintFlag, "NETDB_SUCCESS", NETDB_SUCCESS);
#else
  printFeatureConfigInfo(textPrintFlag, "NETDB_SUCCESS", "undefined");
#endif

#ifdef NS_CMPRSFLGS
  printFeatureConfigNum(textPrintFlag, "NS_CMPRSFLGS", NS_CMPRSFLGS);
#else
  printFeatureConfigInfo(textPrintFlag, "NS_CMPRSFLGS", "undefined");
#endif

#ifdef NS_MAXCDNAME
  printFeatureConfigNum(textPrintFlag, "NS_MAXCDNAME", NS_MAXCDNAME);
#else
  printFeatureConfigInfo(textPrintFlag, "NS_MAXCDNAME", "undefined");
#endif

#ifdef PACKETSZ
  printFeatureConfigNum(textPrintFlag, "PACKETSZ", PACKETSZ);
#else
  printFeatureConfigInfo(textPrintFlag, "PACKETSZ", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "PARM_ENABLE_EXPERIMENTAL",
#ifdef PARM_ENABLE_EXPERIMENTAL
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "PARM_FORK_CHILD_PROCESS",
#ifdef PARM_FORK_CHILD_PROCESS
                         "yes"
#else
                         "no"
#endif
                         );

#ifdef PARM_MIN_WEBPAGE_AUTOREFRESH_TIME
  printFeatureConfigNum(textPrintFlag, "PARM_MIN_WEBPAGE_AUTOREFRESH_TIME", PARM_MIN_WEBPAGE_AUTOREFRESH_TIME);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_MIN_WEBPAGE_AUTOREFRESH_TIME", "undefined");
#endif

#ifdef PARM_PASSIVE_SESSION_MINIMUM_IDLE
  printFeatureConfigNum(textPrintFlag, "PARM_PASSIVE_SESSION_MINIMUM_IDLE", PARM_PASSIVE_SESSION_MINIMUM_IDLE);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_PASSIVE_SESSION_MINIMUM_IDLE", "undefined");
#endif

#ifdef PARM_SESSION_PURGE_MINIMUM_IDLE
  printFeatureConfigNum(textPrintFlag, "PARM_SESSION_PURGE_MINIMUM_IDLE", PARM_SESSION_PURGE_MINIMUM_IDLE);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_SESSION_PURGE_MINIMUM_IDLE", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "PARM_SHOW_NTOP_HEARTBEAT",
#ifdef PARM_SHOW_NTOP_HEARTBEAT
                         "yes"
#else
                         "no"
#endif
                         );

#ifdef PARM_SSLWATCHDOG_WAITWOKE_LIMIT
  printFeatureConfigNum(textPrintFlag, "PARM_SSLWATCHDOG_WAITWOKE_LIMIT", PARM_SSLWATCHDOG_WAITWOKE_LIMIT);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_SSLWATCHDOG_WAITWOKE_LIMIT", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "PARM_USE_CGI",
#ifdef PARM_USE_CGI
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "PARM_USE_COLOR",
#ifdef PARM_USE_COLOR
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "PARM_USE_HOST",
#ifdef PARM_USE_HOST
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "PARM_USE_MACHASH_INVERT",
#ifdef PARM_USE_MACHASH_INVERT
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "PARM_USE_SESSIONS_CACHE",
#ifdef PARM_USE_SESSIONS_CACHE
                         "yes"
#else
                         "no"
#endif
                         );

#ifdef PARM_WEDONTWANTTOTALKWITHYOU_INTERVAL
  printFeatureConfigNum(textPrintFlag, "PARM_WEDONTWANTTOTALKWITHYOU_INTERVAL", PARM_WEDONTWANTTOTALKWITHYOU_INTERVAL);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_WEDONTWANTTOTALKWITHYOU_INTERVAL", "undefined");
#endif

#ifdef THREAD_MODE
  printFeatureConfigInfo(textPrintFlag, "THREAD_MODE", THREAD_MODE);
#else
  printFeatureConfigInfo(textPrintFlag, "THREAD_MODE", "undefined");
#endif

  /*                                                       E N D
   *
   * Autogenerated from globals-defines.h and inserted into webInterface.c 
   *
   */

  /* ***Plugins stuff************************ */
  if(textPrintFlag == TRUE) {
      sendString("\n\nPLUGINS:\n\n");

      sendString("RRD:\n");

      printFeatureConfigInfo(textPrintFlag, "RRD path", myGlobals.rrdPath);
#ifndef WIN32
      if(snprintf(buf, sizeof(buf),
                  "%04o", myGlobals.rrdDirectoryPermissions) < 0)
        BufferTooShort();
      printFeatureConfigInfo(textPrintFlag, "New directory permissions", buf);
      if(snprintf(buf, sizeof(buf),
                  "%04o", myGlobals.rrdUmask) < 0)
        BufferTooShort();
      printFeatureConfigInfo(textPrintFlag, "New file umask", buf);
#endif

  }
}

/* ******************************** */

void printHostColorCode(int textPrintFlag, int isInfo) {
  if(textPrintFlag != TRUE) {
    sendString("<CENTER><TABLE BORDER=\"0\">"
	       "<TR>"
	       "<TD COLSPAN=5 align=\"center\">The color of the host link");
    if (isInfo == 1)
        sendString(" on many pages");
    sendString(" indicates how recently the host was FIRST seen"
               "</TR>"
               "<TR>"
               "<TD>&nbsp;&nbsp;<A href=# class=\"age0min\">0 to 5 minutes</A>&nbsp;&nbsp;</TD>"
               "<TD>&nbsp;&nbsp;<A href=# class=\"age5min\">5 to 15 minutes</A>&nbsp;&nbsp;</TD>"
               "<TD>&nbsp;&nbsp;<A href=# class=\"age15min\">15 to 30 minutes</A>&nbsp;&nbsp;</TD>"
               "<TD>&nbsp;&nbsp;<A href=# class=\"age30min\">30 to 60 minutes</A>&nbsp;&nbsp;</TD>"
               "<TD>&nbsp;&nbsp;<A href=# class=\"age60min\">60+ minutes</A>&nbsp;&nbsp;</TD>"
               "</TR></TABLE></CENTER>");
  }
}

/* ******************************** */
void printNtopConfigInfo(int textPrintFlag) {
  char buf[LEN_GENERAL_WORK_BUFFER], buf2[LEN_GENERAL_WORK_BUFFER];
  int i;
  int bufLength, bufPosition, bufUsed;

#if defined(HAVE_MALLINFO_MALLOC_H) && defined(HAVE_MALLOC_H) && defined(__GNUC__)
  struct mallinfo memStats;
  int totalHostsMonitored = 0;

#ifdef HAVE_SYS_RESOURCE_H
  struct rlimit rlim;
#endif
#endif

  if(textPrintFlag)
      sendString("ntop Configuration\n\n");
  else
      printHTMLheader("ntop Configuration", 0);

  printHostColorCode(textPrintFlag, 1);
  sendString(texthtml("\n", 
                      "<CENTER>\n<P><HR><P>"TABLE_ON"<TABLE BORDER=1>\n"
                      "<tr><th colspan=2 "DARK_BG"" TH_BG ">Basic information</tr>\n"));
  printFeatureConfigInfo(textPrintFlag, "ntop version", version);
  printFeatureConfigInfo(textPrintFlag, "Built on", buildDate);
  printFeatureConfigInfo(textPrintFlag, "OS", osName);

#ifndef WIN32
  {
    char pid[16];

    if(myGlobals.daemonMode == 1) {
      sprintf(pid, "%d", myGlobals.basentoppid);
      printFeatureConfigInfo(textPrintFlag, "ntop Process Id", pid);
      sprintf(pid, "%d", getppid());
      printFeatureConfigInfo(textPrintFlag, "http Process Id", pid);
    } else {
      sprintf(pid, "%d", getppid());
      printFeatureConfigInfo(textPrintFlag, "Process Id", pid);
    }

  }
#endif
#ifdef PARM_SHOW_NTOP_HEARTBEAT
  if(snprintf(buf, sizeof(buf), "%d", myGlobals.heartbeatCounter) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Heartbeat (counter)", buf);
  sendString(texthtml("\n\n", "<tr><td colspan=2 "DARK_BG">"));
  sendString("Note: The value of the heartbeat counter is meaningless.  It's just incremented "
             "in various places. On a busy network, it will grow quickly, on a quiet network "
             "it will grow slowly.  If it STOPS being incremented, ntop is locked up. "
             "If you suspect ntop is locked up, check the Mutexes at the end of this report - "
             "a value in the 'blocked' column for more than a few seconds is a bad sign.");
  sendString(texthtml("\n\n", "</td></tr>\n"));
#endif

  /* *************************** */

  sendString(texthtml("\n\nCommand line\n\n", 
                      "<tr><th colspan=2 "DARK_BG">Command line</tr>\n"));

  sendString(texthtml("Started as....",
                      "<TR><TH "TH_BG" ALIGN=left>Started as</TH><TD "TD_BG" ALIGN=right>"));
  sendString(myGlobals.startedAs);
  sendString(texthtml("\n\n", "</TD></TR>\n"));
  
  sendString(texthtml("Resolved to....",
                      "<TR><TH "TH_BG" ALIGN=left>Resolved to</TH><TD "TD_BG" ALIGN=right>"));
  for(i=0; i<myGlobals.ntop_argc; i++) {
    sendString(myGlobals.ntop_argv[i]);
    sendString(texthtml("\n            ", " "));
    /* Note above needs to be a normal space for html case so that web browser can
       break up the lines as it needs to... */
  }
  sendString(texthtml("\n\nCommand line parameters are:\n\n", "</TD></TR>\n"));

  printParameterConfigInfo(textPrintFlag, "-a | --access-log-path",
                           myGlobals.accessLogPath,
                           DEFAULT_NTOP_ACCESS_LOG_PATH);

  printParameterConfigInfo(textPrintFlag, "-b | --disable-decoders",
                           myGlobals.enablePacketDecoding == 1 ? "No" : "Yes",
                           DEFAULT_NTOP_PACKET_DECODING == 1 ? "No" : "Yes");

  printParameterConfigInfo(textPrintFlag, "-c | --sticky-hosts",
                           myGlobals.stickyHosts == 1 ? "Yes" : "No",
                           DEFAULT_NTOP_STICKY_HOSTS == 1 ? "Yes" : "No");

#ifndef WIN32
  printParameterConfigInfo(textPrintFlag, "-d | --daemon",
                           myGlobals.daemonMode == 1 ? "Yes" : "No",
                           strcmp(myGlobals.program_name, "ntopd") == 0 ? "Yes" : DEFAULT_NTOP_DAEMON_MODE);
#endif

  if(snprintf(buf, sizeof(buf), "%s%d",
	      myGlobals.maxNumLines == CONST_NUM_TABLE_ROWS_PER_PAGE ? CONST_REPORT_ITS_DEFAULT : "",
	      myGlobals.maxNumLines) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "-e | --max-table-rows", buf);

  printParameterConfigInfo(textPrintFlag, "-f | --traffic-dump-file",
                           myGlobals.rFileName,
                           DEFAULT_NTOP_TRAFFICDUMP_FILENAME);

  printParameterConfigInfo(textPrintFlag, "-g | --track-local-hosts",
                           myGlobals.trackOnlyLocalHosts == 1 ? "Track local hosts only" : "Track all hosts",
                           DEFAULT_NTOP_TRACK_ONLY_LOCAL == 1 ? "Track local hosts only" : "Track all hosts");

  printParameterConfigInfo(textPrintFlag, "-o | --no-mac",
			   myGlobals.dontTrustMACaddr == 1 ? "Don't trust MAC Addresses" : "Trust MAC Addresses",
                           DEFAULT_NTOP_DONT_TRUST_MAC_ADDR == 1 ? "Don't trust MAC Addresses" : "Trust MAC Addresses");

  printParameterConfigInfo(textPrintFlag, "-i | --interface" CONST_REPORT_ITS_EFFECTIVE,
                           myGlobals.devices,
                           DEFAULT_NTOP_DEVICES);

  printParameterConfigInfo(textPrintFlag, "-k | --filter-expression-in-extra-frame",
                           myGlobals.filterExpressionInExtraFrame == 1 ? "Yes" : "No",
                           DEFAULT_NTOP_FILTER_IN_FRAME == 1 ? "Yes" : "No");

  if(myGlobals.pcapLog == NULL) {
    printParameterConfigInfo(textPrintFlag, "-l | --pcap-log",
			     myGlobals.pcapLog,
			     DEFAULT_NTOP_PCAP_LOG_FILENAME);
  } else {
    if(snprintf(buf, sizeof(buf), "%s/%s.&lt;device&gt;.pcap",
		myGlobals.pcapLogBasePath,
		myGlobals.pcapLog) < 0)
      BufferTooShort();
    printParameterConfigInfo(textPrintFlag, "-l | --pcap-log" CONST_REPORT_ITS_EFFECTIVE,
			     buf,
			     DEFAULT_NTOP_PCAP_LOG_FILENAME);
  }

  printParameterConfigInfo(textPrintFlag, "-m | --local-subnets" CONST_REPORT_ITS_EFFECTIVE,
                           myGlobals.localAddresses,
                           DEFAULT_NTOP_LOCAL_SUBNETS);

  printParameterConfigInfo(textPrintFlag, "-n | --numeric-ip-addresses",
                           myGlobals.numericFlag > 0 ? "Yes" : "No",
                           DEFAULT_NTOP_NUMERIC_IP_ADDRESSES > 0 ? "Yes" : "No");

  if(myGlobals.protoSpecs == NULL) {
    printFeatureConfigInfo(textPrintFlag, "-p | --protocols", CONST_REPORT_ITS_DEFAULT "internal list");
  } else {
    printFeatureConfigInfo(textPrintFlag, "-p | --protocols", myGlobals.protoSpecs);
  }

  printParameterConfigInfo(textPrintFlag, "-q | --create-suspicious-packets",
                           myGlobals.enableSuspiciousPacketDump == 1 ? "Enabled" : "Disabled",
                           DEFAULT_NTOP_SUSPICIOUS_PKT_DUMP == 1 ? "Enabled" : "Disabled");

  if(snprintf(buf, sizeof(buf), "%s%d",
	      myGlobals.refreshRate == DEFAULT_NTOP_AUTOREFRESH_INTERVAL ? CONST_REPORT_ITS_DEFAULT : "",
	      myGlobals.refreshRate) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "-r | --refresh-time", buf);

  printParameterConfigInfo(textPrintFlag, "-s | --no-promiscuous",
                           myGlobals.disablePromiscuousMode == 1 ? "Yes" : "No",
                           DEFAULT_NTOP_DISABLE_PROMISCUOUS == 1 ? "Yes" : "No");

  if(snprintf(buf, sizeof(buf), "%s%d",
	      myGlobals.traceLevel == DEFAULT_TRACE_LEVEL ? CONST_REPORT_ITS_DEFAULT : "",
	      myGlobals.traceLevel) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "-t | --trace-level", buf);

#ifndef WIN32
  if(snprintf(buf, sizeof(buf), "%s (uid=%d, gid=%d)",
	      myGlobals.effectiveUserName,
	      myGlobals.userId,
	      myGlobals.groupId) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "-u | --user", buf);
#endif

  if(myGlobals.webPort == 0) {
    strcpy(buf, "Inactive");
  } else if(myGlobals.webAddr != 0) {
    if(snprintf(buf, sizeof(buf),
		"%sActive, address %s, port %d",
		( (myGlobals.webAddr == DEFAULT_NTOP_WEB_ADDR) && (myGlobals.webPort == DEFAULT_NTOP_WEB_PORT) ) ? CONST_REPORT_ITS_DEFAULT : "",
		myGlobals.webAddr,
		myGlobals.webPort) < 0)
      BufferTooShort();
  } else {
    if(snprintf(buf, sizeof(buf),
		"%sActive, all interfaces, port %d",
		((myGlobals.webAddr == DEFAULT_NTOP_WEB_ADDR) && (myGlobals.webPort == DEFAULT_NTOP_WEB_PORT) )
		? CONST_REPORT_ITS_DEFAULT : "", myGlobals.webPort) < 0)
      BufferTooShort();
  }

  printFeatureConfigInfo(textPrintFlag, "-w | --http-server", buf);

  printParameterConfigInfo(textPrintFlag, "-z | --disable-sessions",
                           myGlobals.enableSessionHandling == 1 ? "No" : "Yes",
                           DEFAULT_NTOP_ENABLE_SESSIONHANDLE == 1 ? "No" : "Yes");

  printParameterConfigInfo(textPrintFlag, "-B | --filter-expression",
                           ((myGlobals.currentFilterExpression == NULL) ||
                            (myGlobals.currentFilterExpression[0] == '\0')) ? "none" :
			   myGlobals.currentFilterExpression,
                           DEFAULT_NTOP_FILTER_EXPRESSION == NULL ? "none" :
			   DEFAULT_NTOP_FILTER_EXPRESSION);

  printParameterConfigInfo(textPrintFlag, "-D | --domain",
                           ((myGlobals.domainName == NULL) ||
                            (myGlobals.domainName[0] == '\0')) ? "none" :
			   myGlobals.domainName,
                           DEFAULT_NTOP_DOMAIN_NAME == NULL ? "none" :
			   DEFAULT_NTOP_DOMAIN_NAME);

  printParameterConfigInfo(textPrintFlag, "-F | --flow-spec",
                           myGlobals.flowSpecs == NULL ? "none" : myGlobals.flowSpecs,
                           DEFAULT_NTOP_FLOW_SPECS == NULL ? "none" : DEFAULT_NTOP_FLOW_SPECS);

#ifndef WIN32
  printParameterConfigInfo(textPrintFlag, "-K | --enable-debug",
			   myGlobals.debugMode == 1 ? "Yes" : "No",
			   DEFAULT_NTOP_DEBUG_MODE == 1 ? "Yes" : "No");

#ifdef MAKE_WITH_SYSLOG
  if(myGlobals.useSyslog == FLAG_SYSLOG_NONE) {
    printFeatureConfigInfo(textPrintFlag, "-L | --use-syslog", "No");
  } else {
    for(i=0; myFacilityNames[i].c_name != NULL; i++) {
      if(myFacilityNames[i].c_val == myGlobals.useSyslog) {
	printFeatureConfigInfo(textPrintFlag, "-L | --use-syslog", myFacilityNames[i].c_name);
	break;
      }
    }
    if(myFacilityNames[i].c_name == NULL) {
      printFeatureConfigInfo(textPrintFlag, "-L | --use-syslog", "**UNKNOWN**");
    }
  }
#endif /* MAKE_WITH_SYSLOG */
#endif /* WIN32 */

  printParameterConfigInfo(textPrintFlag, "-M | --no-interface-merge" CONST_REPORT_ITS_EFFECTIVE,
                           myGlobals.mergeInterfaces == 1 ? "(Merging Interfaces) Yes" :
			   "(parameter -M set, Interfaces separate) No",
                           DEFAULT_NTOP_MERGE_INTERFACES == 1 ? "(Merging Interfaces) Yes" : "");

  printParameterConfigInfo(textPrintFlag, "-O | --pcap-file-path",
                           myGlobals.pcapLogBasePath,
                           CFG_DBFILE_DIR);

  printParameterConfigInfo(textPrintFlag, "-P | --db-file-path",
                           myGlobals.dbPath,
                           CFG_DBFILE_DIR);

  printParameterConfigInfo(textPrintFlag, "-Q | --spool-file-path",
                           myGlobals.spoolPath,
                           CFG_DBFILE_DIR);

  printParameterConfigInfo(textPrintFlag, "-U | --mapper",
                           myGlobals.mapperURL,
                           DEFAULT_NTOP_MAPPER_URL);

#ifdef HAVE_OPENSSL
  if(myGlobals.sslInitialized == 0) {
    strcpy(buf, "Uninitialized");
  } else if(myGlobals.sslPort == 0) {
    strcpy(buf, "Inactive");
  } else if(myGlobals.sslAddr != 0) {
    if(snprintf(buf, sizeof(buf),
		"%sActive, address %s, port %d",
		( (myGlobals.sslAddr == DEFAULT_NTOP_WEB_ADDR) && (myGlobals.sslPort == DEFAULT_NTOP_WEB_PORT) ) 
		? CONST_REPORT_ITS_DEFAULT : "", myGlobals.sslAddr,myGlobals.sslPort) < 0)
      BufferTooShort();
  } else {
    if(snprintf(buf, sizeof(buf),
		"%sActive, all interfaces, port %d",
		( (myGlobals.sslAddr == DEFAULT_NTOP_WEB_ADDR) && (myGlobals.sslPort == DEFAULT_NTOP_WEB_PORT) ) 
		? CONST_REPORT_ITS_DEFAULT : "", myGlobals.sslPort) < 0)
      BufferTooShort();
  }
  printFeatureConfigInfo(textPrintFlag, "-W | --https-server", buf);
#endif

#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  printParameterConfigInfo(textPrintFlag, "--ssl-watchdog",
                           myGlobals.useSSLwatchdog == 1 ? "Yes" : "No",
                           "No");
#endif

  printParameterConfigInfo(textPrintFlag, "--p3p-cp",
                           ((myGlobals.P3Pcp == NULL) ||
                            (myGlobals.P3Pcp[0] == '\0')) ? "none" :
                           myGlobals.P3Pcp,
                           "none");

  printParameterConfigInfo(textPrintFlag, "--p3p-uri",
                           ((myGlobals.P3Puri == NULL) ||
                            (myGlobals.P3Puri[0] == '\0')) ? "none" :
                           myGlobals.P3Puri,
                           "none");

#ifdef MAKE_WITH_XMLDUMP
  printParameterConfigInfo(textPrintFlag, "--xmlfileout",
                           myGlobals.xmlFileOut == NULL ? "(none)" : myGlobals.xmlFileOut,
                           "(none)");
  printParameterConfigInfo(textPrintFlag, "--xmlfilesnap",
                           myGlobals.xmlFileSnap == NULL ? "(none)" : myGlobals.xmlFileSnap,
                           "(none)");
  printParameterConfigInfo(textPrintFlag, "--xmlfilein",
                           myGlobals.xmlFileIn == NULL ? "(none)" : myGlobals.xmlFileIn,
                           "(none)");
#endif

#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)
  printParameterConfigInfo(textPrintFlag, "--disable-schedYield",
                           myGlobals.disableSchedYield == TRUE ? "Yes" : "No",
                           "No");
#endif

  printParameterConfigInfo(textPrintFlag, "--disable-stopcap",
                           myGlobals.disableStopcap == TRUE ? "Yes" : "No",
                           "No");

  if(snprintf(buf, sizeof(buf), "%s%d",
	      myGlobals.logExtra == 0 ? CONST_REPORT_ITS_DEFAULT : "",
	      myGlobals.logExtra) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "--log-extra", buf);

  printParameterConfigInfo(textPrintFlag, "--disable-instantsessionpurge",
                           myGlobals.disableInstantSessionPurge == TRUE ? "Yes" : "No",
                           "No");

  printParameterConfigInfo(textPrintFlag, "--disable-mutexextrainfo",
                           myGlobals.disableMutexExtraInfo == TRUE ? "Yes" : "No",
                           "No");

  sendString(texthtml("\n\n", "<tr><th colspan=2>"));
  sendString("Note: " CONST_REPORT_ITS_EFFECTIVE "   means that "
	     "this is the value after ntop has processed the parameter.");
  sendString(texthtml("\n", "<br>\n"));
  sendString(CONST_REPORT_ITS_DEFAULT "means this is the default value, usually "
	     "(but not always) set by a #define in globals-defines.h.");
  sendString(texthtml("\n\n", "</th></tr>\n"));

  /* *************************** */

  sendString(texthtml("\n\nRun time/Internal\n\n", 
                      "<tr><th colspan=2 "DARK_BG"" TH_BG ">Run time/Internal</tr>\n"));
  
  if(myGlobals.webPort != 0) {
    if(myGlobals.webAddr != 0) {
      if(snprintf(buf, sizeof(buf), "http://%s:%d", myGlobals.webAddr, myGlobals.webPort) < 0)
        BufferTooShort();
    } else {
      if(snprintf(buf, sizeof(buf), "http://any:%d", myGlobals.webPort) < 0)
        BufferTooShort();
    }
    printFeatureConfigInfo(textPrintFlag, "Web server URL", buf);
  } else {
    printFeatureConfigInfo(textPrintFlag, "Web server (http://)", "Not Active");
  }

#ifdef HAVE_OPENSSL
  if(myGlobals.sslPort != 0) {
    if(myGlobals.sslAddr != 0) {
      if(snprintf(buf, sizeof(buf), "https://%s:%d", myGlobals.sslAddr, myGlobals.sslPort) < 0)
        BufferTooShort();
    } else {
      if(snprintf(buf, sizeof(buf), "https://any:%d", myGlobals.sslPort) < 0)
        BufferTooShort();
    }
    printFeatureConfigInfo(textPrintFlag, "SSL Web server URL", buf);
  } else {
    printFeatureConfigInfo(textPrintFlag, "SSL Web server (https://)", "Not Active");
  }
#endif


  /* *************************** */

#ifdef MAKE_WITH_XMLDUMP
  printFeatureConfigInfo(textPrintFlag, "XML dump (dump.xml)", "Supported");
#endif

  /* *************************** */

#if defined(WIN32) && defined(__GNUC__)
  /* on mingw, gdbm_version not exported by library */
#else
  printFeatureConfigInfo(textPrintFlag, "GDBM version", gdbm_version);
#endif

#if defined(WIN32)
  printFeatureConfigInfo(textPrintFlag, "WinPcap version", (char*)PacketGetVersion());
#endif

#ifdef HAVE_OPENSSL
  printFeatureConfigInfo(textPrintFlag, "OpenSSL Version", (char*)SSLeay_version(0));
#endif

  printFeatureConfigInfo(textPrintFlag, "zlib version", (char*)zlibVersion());

  printFeatureConfigInfo(textPrintFlag, "Protocol Decoders",    myGlobals.enablePacketDecoding == 1 ? "Enabled" : "Disabled");
  printFeatureConfigInfo(textPrintFlag, "Fragment Handling", myGlobals.enableFragmentHandling == 1 ? "Enabled" : "Disabled");
  printFeatureConfigInfo(textPrintFlag, "Tracking only local hosts", myGlobals.trackOnlyLocalHosts == 1 ? "Yes" : "No");

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.numIpProtosToMonitor) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "# IP Protocols Being Monitored", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.numActServices) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "# Protocol slots", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.ipPortMapper.numElements) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "# IP Ports Being Monitored", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.ipPortMapper.numSlots) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "# IP Ports slots", buf);

  if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numHandledSIGPIPEerrors) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "# Handled SIGPIPE Errors", buf);

  if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numHandledHTTPrequests) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "# Handled HTTP Requests", buf);

#ifdef MAKE_WITH_SSLWATCHDOG
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  if(myGlobals.useSSLwatchdog == 1)
#endif
    {
      if(snprintf(buf, sizeof(buf), "%d", myGlobals.numHTTPSrequestTimeouts) < 0)
	BufferTooShort();
      printFeatureConfigInfo(textPrintFlag, "# HTTPS Request Timeouts", buf);
    }
#endif

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.numDevices) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Devices (Network Interfaces)", buf);

  printFeatureConfigInfo(textPrintFlag, "Domain name (short)", myGlobals.shortDomainName);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.ipCountryCount) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "IP to country flag table (entries)", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.hashCollisionsLookup) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Total Hash Collisions (Vendor/Special) (lookup)", buf);

  /* ******************** */
  buf[0] = '\0';
  for(i=0; i<myGlobals.numLocalNetworks; i++) {
    struct in_addr addr1, addr2;
    char buf1[64];
    
    addr1.s_addr = myGlobals.localNetworks[i][CONST_NETWORK_ENTRY];
    addr2.s_addr = myGlobals.localNetworks[i][CONST_NETMASK_ENTRY];
    
    if(snprintf(buf1, sizeof(buf1), "%s/%s [all devices]\n", 
		_intoa(addr1, buf1, sizeof(buf1)),
		_intoa(addr2, buf2, sizeof(buf2))) < 0) BufferTooShort();
    
    if(snprintf(buf, sizeof(buf), "%s%s", buf, buf1) < 0)
      BufferTooShort();
  }
 
  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.device[i].activeDevice) {
      char buf1[128], buf3[64];
      if(snprintf(buf1, sizeof(buf1), "%s/%s [device %s]\n",
		  _intoa(myGlobals.device[i].network, buf2, sizeof(buf2)),
		  _intoa(myGlobals.device[i].netmask, buf3, sizeof(buf3)),
		  myGlobals.device[i].humanFriendlyName) < 0)
	BufferTooShort();   
      if(snprintf(buf, sizeof(buf), "%s%s", buf, buf1) < 0)
        BufferTooShort();
    }
  }
  
  printFeatureConfigInfo(textPrintFlag, "Local Networks", buf);



#if defined(HAVE_MALLINFO_MALLOC_H) && defined(HAVE_MALLOC_H) && defined(__GNUC__)
  sendString(texthtml("\n\nMemory allocation - data segment\n\n", "<tr><th colspan=2 "DARK_BG">Memory allocation - data segment</th></tr>\n"));

  memStats = mallinfo();

#ifdef HAVE_SYS_RESOURCE_H
  getrlimit(RLIMIT_DATA, &rlim);
  if(snprintf(buf, sizeof(buf), "%d", (int)rlim.rlim_cur) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "arena limit, getrlimit(RLIMIT_DATA, ...)", buf);
#endif

  if(snprintf(buf, sizeof(buf), "%d", memStats.ordblks) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Allocated blocks (ordblks)", buf);

  if(snprintf(buf, sizeof(buf), "%d", memStats.arena) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Allocated (arena)", buf);

  if(snprintf(buf, sizeof(buf), "%d", memStats.uordblks) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Used (uordblks)", buf);

  if(snprintf(buf, sizeof(buf), "%d", memStats.fordblks) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Free (fordblks)", buf);

  if(memStats.uordblks + memStats.fordblks != memStats.arena)
    printFeatureConfigInfo(textPrintFlag, "WARNING:", "Used+Free != Allocated");

  sendString(texthtml("\n\nMemory allocation - mmapped\n\n", "<tr><th colspan=2 "DARK_BG">Memory allocation - mmapped</th></tr>\n"));

  if(snprintf(buf, sizeof(buf), "%d", memStats.hblks) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Allocated blocks (hblks)", buf);

  if(snprintf(buf, sizeof(buf), "%d", memStats.hblkhd) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Allocated bytes (hblkhd)", buf);

#endif

  if(textPrintFlag == TRUE) {
    sendString(texthtml("\n\nMemory Usage\n\n", "<tr><th colspan=2 "DARK_BG">Memory Usage</th></tr>\n"));

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.ipxsapHashLoadSize) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "IPX/SAP Hash Size (bytes)", buf);
  
    if(snprintf(buf, sizeof(buf), "%d (%.1f MB)", myGlobals.ipCountryMem, (float)myGlobals.ipCountryMem/(1024.0*1024.0)) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "IP to country flag table (bytes)", buf);

    if(myGlobals.ipCountryCount > 0) {
      if(snprintf(buf, sizeof(buf), "%.1f", (float)myGlobals.ipCountryMem/myGlobals.ipCountryCount) < 0)
	BufferTooShort();
      printFeatureConfigInfo(textPrintFlag, "Bytes per entry", buf);
    }

    if(snprintf(buf, sizeof(buf), "%d (%.1f MB)", myGlobals.asMem, (float)myGlobals.asMem/(1024.0*1024.0)) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "IP to AS (Autonomous System) number table (bytes)", buf);

#if defined(HAVE_MALLINFO_MALLOC_H) && defined(HAVE_MALLOC_H) && defined(__GNUC__)

    if(snprintf(buf, sizeof(buf), "%d", memStats.arena + memStats.hblkhd) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Current memory usage", buf);

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.baseMemoryUsage) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Base memory usage", buf);

    for(i=0; i<myGlobals.numDevices; i++)
      totalHostsMonitored += myGlobals.device[i].hostsno;

    if(totalHostsMonitored > 0) {
      if(snprintf(buf, sizeof(buf), "%d = (%d + %d)", 
		  totalHostsMonitored + myGlobals.hostsCacheLen,
		  totalHostsMonitored,
		  myGlobals.hostsCacheLen) < 0)
	BufferTooShort();
      printFeatureConfigInfo(textPrintFlag, "Hosts stored (active+cache)", buf);

      if(snprintf(buf, sizeof(buf), "%.1fKB", 
		  ((float)(memStats.arena + memStats.hblkhd - myGlobals.baseMemoryUsage) /
		   (float)(totalHostsMonitored + myGlobals.hostsCacheLen) /
		   1024.0 + 0.05)) < 0)
	BufferTooShort();
      printFeatureConfigInfo(textPrintFlag, "(very) Approximate memory per host", buf);
    }
#endif
  }

  sendString(texthtml("\n\nHost Memory Cache\n\n", "<tr><th colspan=2 "DARK_BG">Host Memory Cache</th></tr>\n"));

  if(snprintf(buf, sizeof(buf), 
              "#define MAX_HOSTS_CACHE_LEN %d", MAX_HOSTS_CACHE_LEN) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Limit", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.hostsCacheLen) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Current Size", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.hostsCacheLenMax) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Maximum Size", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.hostsCacheReused) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "# Entries Reused", buf);

#ifdef PARM_USE_SESSIONS_CACHE
  sendString(texthtml("\n\nSession Memory Cache\n\n", "<tr><th colspan=2 "DARK_BG">Session Memory Cache</th></tr>\n"));

  if(snprintf(buf, sizeof(buf), 
              "#define MAX_SESSIONS_CACHE_LEN %d", MAX_SESSIONS_CACHE_LEN) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Limit", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.sessionsCacheLen) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Current Size", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.sessionsCacheLenMax) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Maximum Size", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.sessionsCacheReused) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "# Entries Reused", buf);
#endif

  if(textPrintFlag == TRUE) {
    sendString(texthtml("\n\nMAC/IPX Hash tables\n\n", "<tr><th colspan=2 "DARK_BG">MAC/IPX Hash Tables</th></tr>\n"));

    if(snprintf(buf, sizeof(buf), "%d", MAX_IPXSAP_NAME_HASH) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "IPX/SAP Hash Size (entries)", buf);

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.ipxsapHashLoadCollisions) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "IPX/SAP Hash Collisions (load)", buf);

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.hashCollisionsLookup) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "IPX/SAP Hash Collisions (use)", buf);
  }

  /* **** */

  sendString(texthtml("\n\nPackets\n\n", "<tr><th colspan=2 "DARK_BG">Packets</th></tr>\n"));

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.receivedPackets) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Received", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.receivedPacketsProcessed) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Processed immediately", buf);

#ifdef CFG_MULTITHREADED

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.receivedPacketsQueued) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Queued", buf);

  if(myGlobals.receivedPacketsLostQ > 0) {
    if(snprintf(buf, sizeof(buf), "%d", myGlobals.receivedPacketsLostQ) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Lost in ntop queue", buf);
  }

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.packetQueueLen) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Current queue", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.maxPacketQueueLen) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Maximum queue", buf);

#endif

  /* **** */

  sendString(texthtml("\n\nHost/Session counts - global\n\n", "<tr><th colspan=2 "DARK_BG">Host/Session counts - global</th></tr>\n"));

  if(snprintf(buf, sizeof(buf), "%u", (unsigned int)myGlobals.numPurgedHosts) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Purged hosts", buf);

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.maximumHostsToPurgePerCycle) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Maximum hosts to purge per cycle", buf);

  if(textPrintFlag == TRUE) {
    if(snprintf(buf, sizeof(buf), "%d", DEFAULT_MAXIMUM_HOSTS_PURGE_PER_CYCLE) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "DEFAULT_MAXIMUM_HOSTS_PURGE_PER_CYCLE", buf);
  }

  if(myGlobals.enableSessionHandling) {
    if(snprintf(buf, sizeof(buf), "%s", formatPkts(myGlobals.numTerminatedSessions)) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Terminated Sessions", buf);
  }

  /* **** */

  for(i=0; i<myGlobals.numDevices; i++) {
    if(snprintf(buf, sizeof(buf), "\nHost/Session counts - Device %d (%s)\n", i, myGlobals.device[i].name) < 0)
      BufferTooShort();
    if(snprintf(buf2, sizeof(buf2), "<tr><th colspan=2 "DARK_BG">Host/Session counts - Device %d (%s)</th></tr>\n", i, myGlobals.device[i].name) < 0)
      BufferTooShort();
    sendString(texthtml(buf, buf2));

    printFeatureConfigInfo(textPrintFlag, "Hash Bucket Size", formatBytes(sizeof(HostTraffic), 0));

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.device[i].actualHashSize) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Actual Hash Size", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.device[i].hostsno) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Stored hosts", buf);
    
    {
      unsigned int idx, minLen=-1, maxLen=0;
      unsigned long totBuckets=0, nonEmptyBuckets=0;

      for(idx=0; idx<myGlobals.device[i].actualHashSize; idx++) {
	HostTraffic *el;

	if((el = myGlobals.device[i].hash_hostTraffic[idx]) != NULL) {	
	  unsigned int len=0;
	  
	  nonEmptyBuckets++;

	  for(; el != NULL; el = el->next) {
	    totBuckets++, len++;
	  }

	  if(minLen > len) minLen = len;
	  if(maxLen < len) maxLen = len;
	}
      }      
      
      if(snprintf(buf, sizeof(buf), "[min %u][max %u][avg %.1f]", 
		  minLen, maxLen, (float)totBuckets/(float)nonEmptyBuckets) < 0)
	BufferTooShort();
      printFeatureConfigInfo(textPrintFlag, "Bucket List Length", buf);
    }

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.device[i].hashListMaxLookups) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Max host lookup", buf);

    if(myGlobals.enableSessionHandling) {
      printFeatureConfigInfo(textPrintFlag, "Session Bucket Size", formatBytes(sizeof(IPSession), 0));

      if(snprintf(buf, sizeof(buf), "%s", formatPkts(myGlobals.device[i].numTcpSessions)) < 0)
	BufferTooShort();
      printFeatureConfigInfo(textPrintFlag, "Sessions", buf);
    
      if(snprintf(buf, sizeof(buf), "%s", formatPkts(myGlobals.device[i].maxNumTcpSessions)) < 0)
	BufferTooShort();
      printFeatureConfigInfo(textPrintFlag, "Max Num. Sessions", buf);
    }
  }

  /* **** */

  sendString(texthtml("\n\nAddress Resolution\n\n", "<tr><th colspan=2 "DARK_BG">Address Resolution</th></tr>\n"));

  sendString(texthtml("DNS sniffed:\n\n", "<tr><td align=\"center\">DNS sniffed</td>\n<td><table>\n"));

  if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.dnsSniffCount) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "DNS Packets sniffed", buf);

  if(textPrintFlag == TRUE) {
    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.dnsSniffRequestCount) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "  less 'requests'", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.dnsSniffFailedCount) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "  less 'failed'", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.dnsSniffARPACount) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "  less 'reverse dns' (in-addr.arpa)", buf);
  }

  if(snprintf(buf, sizeof(buf), "%d", (int)(myGlobals.dnsSniffCount
					    - myGlobals.dnsSniffRequestCount
					    - myGlobals.dnsSniffFailedCount
					    - myGlobals.dnsSniffARPACount)) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "DNS Packets processed", buf);

  if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.dnsSniffStoredInCache) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Stored in cache (includes aliases)", buf);

  if(textPrintFlag != TRUE) {
    sendString("</table></td></tr>\n");
  }

  if(textPrintFlag == TRUE) {
    sendString("\n\nIP to name - ipaddr2str():\n\n");

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numipaddr2strCalls) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Total calls", buf);

    if(myGlobals.numipaddr2strCalls != myGlobals.numFetchAddressFromCacheCalls) {
      if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numFetchAddressFromCacheCalls) < 0)
	BufferTooShort();
      printFeatureConfigInfo(textPrintFlag, "ERROR: cache fetch attempts != ipaddr2str() calls", buf);
    }

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numFetchAddressFromCacheCallsOK) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "....OK", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)(myGlobals.numipaddr2strCalls
					      - myGlobals.numFetchAddressFromCacheCallsOK)) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "....Total not found", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numFetchAddressFromCacheCallsFAIL) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "........Not found in cache", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numFetchAddressFromCacheCallsSTALE) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "........Too old in cache", buf);
  }

#if defined(CFG_MULTITHREADED) && defined(MAKE_ASYNC_ADDRESS_RESOLUTION)

  if(myGlobals.numericFlag == 0) {
    sendString(texthtml("\n\nQueued - dequeueAddress():\n\n", "<tr><td align=\"center\">Queued</td>\n<td><table>\n"));

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.addressQueuedCount) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Total Queued", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.addressQueuedDup) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Not queued (duplicate)", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.addressQueuedMax) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Maximum Queued", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.addressQueuedCurrent) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Current Queue", buf);

    if(textPrintFlag != TRUE) {
      sendString("</table></td></tr>\n");
    }
  }

#endif

  if(textPrintFlag == TRUE) {
    sendString("\n\nResolved - resolveAddress():\n\n");

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numResolveAddressCalls) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Addresses to resolve", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numResolveNoCacheDB) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "....less 'Error: No cache database'", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numResolvedFromCache) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "....less 'Found in ntop cache'", buf);

#ifdef PARM_USE_HOST
    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numResolvedFromHostAddresses) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "....less 'Resolved from /usr/bin/host'", buf);
#endif

    if(snprintf(buf, sizeof(buf), "%d", (int)(myGlobals.numResolveAddressCalls
#ifdef PARM_USE_HOST
					 - myGlobals.numResolvedFromHostAddresses
#endif
					 - myGlobals.numResolveNoCacheDB
					 - myGlobals.numResolvedFromCache)) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Gives: # gethost (DNS lookup) calls", buf);

    if((myGlobals.numResolveAddressCalls
#ifdef PARM_USE_HOST
	- myGlobals.numResolvedFromHostAddresses
#endif
	- myGlobals.numResolveNoCacheDB
	- myGlobals.numResolvedFromCache) != myGlobals.numAttemptingResolutionWithDNS) {
      if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numAttemptingResolutionWithDNS) < 0)
	BufferTooShort();
      printFeatureConfigInfo(textPrintFlag, "    ERROR: actual count does not match!", buf);
    }
  }

  sendString(texthtml("\n\nDNS lookup calls:\n\n", "<tr><td align=\"center\">DNS lookup calls</td>\n<td><table>\n"));

  if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numAttemptingResolutionWithDNS) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "DNS resolution attempts", buf);

  if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numResolvedWithDNSAddresses) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "....Success: Resolved", buf);

  if(snprintf(buf, sizeof(buf), "%d", (int)(myGlobals.numDNSErrorHostNotFound
					    + myGlobals.numDNSErrorNoData
					    + myGlobals.numDNSErrorNoRecovery
					    + myGlobals.numDNSErrorTryAgain
					    + myGlobals.numDNSErrorOther)) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "....Failed", buf);

  if(textPrintFlag == TRUE) {
    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numDNSErrorHostNotFound) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "........HOST_NOT_FOUND", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numDNSErrorNoData) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "........NO_DATA", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numDNSErrorNoRecovery) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "........NO_RECOVERY", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numDNSErrorTryAgain) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "........TRY_AGAIN (don't store)", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numDNSErrorOther) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "........Other error (don't store)", buf);
  }

  if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.dnsCacheStoredLookup) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "DNS lookups stored in cache", buf);

  if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numKeptNumericAddresses) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Host addresses kept numeric", buf);


  if(textPrintFlag != TRUE) {
    sendString("</table><br>\n");
    sendString("<table><tr><td><b>REMEMBER</b>:&nbsp;\n"
	       "'DNS lookups stored in cache' includes HOST_NOT_FOUND "
	       "replies, so that it may be larger than the number of "
	       "'Success: Resolved' queries.</td></tr></table>\n");
  }

  /* **** */

  if(textPrintFlag == TRUE) {
    sendString("\n\nVendor Lookup Table\n\n");

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numVendorLookupRead) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Input lines read", buf);

    if(snprintf(buf, sizeof(buf), "%d", (int)myGlobals.numVendorLookupAdded) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Records added total", buf);

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.numVendorLookupAddedSpecial) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, ".....includes special records", buf);

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.numVendorLookupCalls) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "getVendorInfo() calls", buf);

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.numVendorLookupSpecialCalls) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "getSpecialVendorInfo() calls", buf);

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.numVendorLookupFound48bit) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Found 48bit (xx:xx:xx:xx:xx:xx) match", buf);

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.numVendorLookupFound24bit) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Found 24bit (xx:xx:xx) match", buf);

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.numVendorLookupFoundMulticast) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Found multicast bit set", buf);

    if(snprintf(buf, sizeof(buf), "%d", myGlobals.numVendorLookupFoundLAA) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Found LAA (Locally assigned address) bit set", buf);

  }

  /* **** */

#if defined(CFG_MULTITHREADED)
  sendString(texthtml("\n\nThread counts\n\n", "<tr><th colspan=2 "DARK_BG">Thread counts</th></tr>\n"));

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.numThreads) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Active", buf);
  if(snprintf(buf, sizeof(buf), "%d", myGlobals.numDequeueThreads) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Dequeue", buf);
  if(snprintf(buf, sizeof(buf), "%d", myGlobals.numChildren) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Children (active)", buf);
#endif

  /* **** */

#if defined(MAX_NUM_BAD_IP_ADDRESSES) && (MAX_NUM_BAD_IP_ADDRESSES > 0)
  {
    struct tm t;
    char buf3[64], buf4[64];
    time_t lockoutExpires;
    int countBadGuys=0;

    for(i=0; i<MAX_NUM_BAD_IP_ADDRESSES; i++) {
      if(myGlobals.weDontWantToTalkWithYou[i].addr.s_addr != 0) {
	if(++countBadGuys == 1) {
	  sendString(texthtml("\n\nIP Address reject list\n\n",
			      "<tr><th colspan=2 "DARK_BG">IP Address reject list</th></tr>\n"));
	  sendString(texthtml("\nAddress ... Count ... Last Bad Access ... Lockout Expires\n",
			      "<tr><th>Rejects</th>"
			      "<td><table border=\"1\">"
			      "<tr><th>Address</th><th>Count</th>"
			      "<th>Last Bad Access</th><th>Lockout Expires</th></tr>"));
	}
      
	if(snprintf(buf, sizeof(buf), "%s", 
		    _intoa(myGlobals.weDontWantToTalkWithYou[i].addr, buf3, sizeof(buf3))) < 0)
	  BufferTooShort();
	if(snprintf(buf2, sizeof(buf2), "%d", myGlobals.weDontWantToTalkWithYou[i].count) < 0)
	  BufferTooShort();
	strftime(buf3, sizeof(buf3), "%c", 
		 localtime_r(&myGlobals.weDontWantToTalkWithYou[i].lastBadAccess, &t));
	lockoutExpires = myGlobals.weDontWantToTalkWithYou[i].lastBadAccess + 
	  PARM_WEDONTWANTTOTALKWITHYOU_INTERVAL;
	strftime(buf4, sizeof(buf4), "%c", localtime_r(&lockoutExpires, &t));
	if(textPrintFlag) {
	  sendString("    ");
	  sendString(buf);
	  sendString("... ");
	  sendString(buf2);
	  sendString("... ");
	  sendString(buf3);
	  sendString("... ");
	  sendString(buf4);
	  sendString("\n");
	} else {
	  sendString("<tr><td>");
	  sendString(buf);
	  sendString("</td><td>");
	  sendString(buf2);
	  sendString("</td><td>");
	  sendString(buf3);
	  sendString("</td><td>");
	  sendString(buf4);
	  sendString("</td></tr>\n");
	}
      }
    }

    if(countBadGuys > 0) {  
      sendString(texthtml("\n", "</table></td>\n"));

      if(snprintf(buf, sizeof(buf), "%d", PARM_WEDONTWANTTOTALKWITHYOU_INTERVAL) < 0)
	BufferTooShort();
      printFeatureConfigInfo(textPrintFlag, "Reject duration (seconds)", buf);
  
      strftime(buf, sizeof(buf), "%c", localtime_r(&myGlobals.actTime, &t));
      printFeatureConfigInfo(textPrintFlag, "It is now", buf);
    }

  }
#endif

  /* **** */

#ifdef MEMORY_DEBUG
  printFeatureConfigInfo(textPrintFlag, "Allocated Memory", formatBytes(myGlobals.allocatedMemory, 0));
#endif

  /* **** */

  sendString(texthtml("Directory (search) order\n\n", "<tr><th colspan=2 "DARK_BG">Directory (search) order</th></tr>\n"));

  bufLength = sizeof(buf);
  bufPosition = 0;
  bufUsed = 0;

  for(i=0; myGlobals.dataFileDirs[i] != NULL; i++) {
    if((bufUsed = snprintf(&buf[bufPosition],
			   bufLength,
			   "%s%s\n",
			   i > 0 ? "                " : "",
			   myGlobals.dataFileDirs[i])) < 0)
      BufferTooShort();
    if(bufUsed == 0) bufUsed = strlen(&buf[bufPosition]); /* Win32 patch */
    bufPosition += bufUsed;
    bufLength   -= bufUsed;
  }
  printFeatureConfigInfo(textPrintFlag, "Data Files", buf);

  bufLength = sizeof(buf);
  bufPosition = 0;
  bufUsed = 0;

  for(i=0; myGlobals.configFileDirs[i] != NULL; i++) {
    if((bufUsed = snprintf(&buf[bufPosition],
			   bufLength,
			   "%s%s\n",
			   i > 0 ? "                  " : "",
			   myGlobals.configFileDirs[i])) < 0)
      BufferTooShort();
    if(bufUsed == 0) bufUsed = strlen(&buf[bufPosition]); /* Win32 patch */
    bufPosition += bufUsed;
    bufLength   -= bufUsed;
  }
  printFeatureConfigInfo(textPrintFlag, "Config Files", buf);

  bufLength = sizeof(buf);
  bufPosition = 0;
  bufUsed = 0;

  for(i=0; myGlobals.pluginDirs[i] != NULL; i++) {
    if((bufUsed = snprintf(&buf[bufPosition],
			   bufLength, "%s%s\n",
			   i > 0 ? "             " : "",
			   myGlobals.pluginDirs[i])) < 0)
      BufferTooShort();
    if(bufUsed == 0) bufUsed = strlen(&buf[bufPosition]); /* Win32 patch */
    bufPosition += bufUsed;
    bufLength   -= bufUsed;
  }
  printFeatureConfigInfo(textPrintFlag, "Plugins", buf);

  /* *************************** *************************** */

#ifndef WIN32
  sendString(texthtml("\n\nCompile Time: ./configure\n\n", "<tr><th colspan=2 "DARK_BG"" TH_BG ">Compile Time: ./configure</tr>\n"));
  printFeatureConfigInfo(textPrintFlag, "./configure parameters", 
			 configure_parameters[0] == '\0' ? "&nbsp;" : configure_parameters);
  printFeatureConfigInfo(textPrintFlag, "Built on (Host)", host_system_type);
  printFeatureConfigInfo(textPrintFlag, "Built for(Target)", target_system_type);
  printFeatureConfigInfo(textPrintFlag, "compiler (cflags)", compiler_cflags);
  printFeatureConfigInfo(textPrintFlag, "include path", include_path);
  printFeatureConfigInfo(textPrintFlag, "system libraries", system_libs);
  printFeatureConfigInfo(textPrintFlag, "install path", install_path);
#endif
#if defined(__GNUC__)
  if(snprintf(buf, sizeof(buf), "%s (%d.%d.%d)",
	      __VERSION__, 
              __GNUC__, 
              __GNUC_MINOR__, 
#if defined(__GNUC_PATCHLEVEL__)
              __GNUC_PATCHLEVEL__
#else
              0
#endif
	      ) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "GNU C (gcc) version", buf);

  sendString(texthtml("\n\nInternationalization (i18n)\n\n", "<tr><th colspan=2 "DARK_BG"" TH_BG ">Internationalization (i18n)</tr>\n"));

  printFeatureConfigInfo(textPrintFlag, "i18n enabled",
#ifdef MAKE_WITH_I18N
                         "Yes"
#else
                         "No"
#endif
			 );

#ifdef MAKE_WITH_I18N

  if(textPrintFlag == TRUE) {
    printFeatureConfigInfo(textPrintFlag, "HAVE_LOCALE_H",
#ifdef HAVE_LOCALE_H
                           "present"
#else
                           "absent"
#endif
                           );

    printFeatureConfigInfo(textPrintFlag, "HAVE_LANGINFO_H",
#ifdef HAVE_LANGINFO_H
                           "present"
#else
                           "absent"
#endif
                           );

    printFeatureConfigInfo(textPrintFlag, "Locale directory (version.c)", locale_dir);
  }

  if(textPrintFlag == TRUE) {
    if(snprintf(buf, sizeof(buf),
		"globals-defines.h: #define MAX_LANGUAGES_REQUESTED %d",
		MAX_LANGUAGES_REQUESTED) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Languages - per request (Accept-Language:)", buf);
    if(snprintf(buf, sizeof(buf),
		"globals-defines.h: #define MAX_LANGUAGES_SUPPORTED %d",
		MAX_LANGUAGES_SUPPORTED) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, "Languages supported - maximum", buf);
  }

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.maxSupportedLanguages + 1) < 0)
    BufferTooShort();
  printFeatureConfigInfo(textPrintFlag, "Languages supported - actual ", buf);

  printFeatureConfigInfo(textPrintFlag, "Default language", myGlobals.defaultLanguage);

  for(i=0; i< myGlobals.maxSupportedLanguages; i++) {
    if(snprintf(buf, sizeof(buf), "Additional language %d", i+1) < 0)
      BufferTooShort();
    if(snprintf(buf2, sizeof(buf2), "'%s', time format '%s'", 
		myGlobals.supportedLanguages[i],
		myGlobals.strftimeFormat[i]) < 0)
      BufferTooShort();
    printFeatureConfigInfo(textPrintFlag, buf, buf2);
  }

#endif

#endif /* MICRO_NTOP */

  /* *************************** */

  /* At Luca's request, we generate less information for the html version...
     so I've pushed all the config.h and #define stuff into a sub-function
     (Burton - 05-Jun-2002) (Unless we're in debug mode)
  */

#if defined(DEBUG)                     || \
    defined(ADDRESS_DEBUG)             || \
    defined(DNS_DEBUG)                 || \
    defined(DNS_SNIFF_DEBUG)           || \
    defined(FRAGMENT_DEBUG)            || \
    defined(FTP_DEBUG)                 || \
    defined(GDBM_DEBUG)                || \
    defined(HASH_DEBUG)                || \
    defined(IDLE_PURGE_DEBUG)          || \
    defined(INITWEB_DEBUG)             || \
    defined(HOST_FREE_DEBUG)           || \
    defined(HTTP_DEBUG)                || \
    defined(MEMORY_DEBUG)              || \
    defined(NETFLOW_DEBUG)             || \
    defined(PACKET_DEBUG)              || \
    defined(PLUGIN_DEBUG)              || \
    defined(SEMAPHORE_DEBUG)           || \
    defined(SESSION_TRACE_DEBUG)       || \
    defined(SSLWATCHDOG_DEBUG)         || \
    defined(STORAGE_DEBUG)             || \
    defined(UNKNOWN_PACKET_DEBUG)
#else
  if(textPrintFlag == TRUE)
#endif
    printNtopConfigHInfo(textPrintFlag);

  /* *************************** */

  sendString(texthtml("\n\n", "</TABLE>"TABLE_OFF"\n"));

  /* **************************** */

#ifdef CFG_MULTITHREADED
#if !defined(DEBUG) && !defined(WIN32)
  if(myGlobals.debugMode)
#endif /* DEBUG or WIN32 */
    {
      if(myGlobals.disableMutexExtraInfo) {
        sendString(texthtml("\nMutexes:\n\n", 
			  "<P>"TABLE_ON"<TABLE BORDER=1>\n"
			  "<TR><TH>Mutex Name</TH>"
			  "<TH>State</TH>"
			  "<TH COLSPAN=2># Locks/Releases</TH>"));
      } else {
        sendString(texthtml("\nMutexes:\n\n", 
			  "<P>"TABLE_ON"<TABLE BORDER=1>\n"
			  "<TR><TH>Mutex Name</TH>"
			  "<TH>State</TH>"
			  "<TH>Last Lock</TH>"
			  "<TH>Blocked</TH>"
			  "<TH>Last UnLock</TH>"
			  "<TH COLSPAN=2># Locks/Releases</TH>"
			  "<TH>Max Lock</TH></TR>"));
      }

      printMutexStatus(textPrintFlag, &myGlobals.gdbmMutex, "gdbmMutex");
      printMutexStatus(textPrintFlag, &myGlobals.packetProcessMutex, "packetProcessMutex");
      printMutexStatus(textPrintFlag, &myGlobals.packetQueueMutex, "packetQueueMutex");
      printMutexStatus(textPrintFlag, &myGlobals.purgeMutex, "purgeMutex");

#if defined(CFG_MULTITHREADED) && defined(MAKE_ASYNC_ADDRESS_RESOLUTION)
      if(myGlobals.numericFlag == 0) 
	printMutexStatus(textPrintFlag, &myGlobals.addressResolutionMutex, "addressResolutionMutex");
#endif

      printMutexStatus(textPrintFlag, &myGlobals.hostsHashMutex,   "hostsHashMutex");
      printMutexStatus(textPrintFlag, &myGlobals.tcpSessionsMutex, "tcpSessionsMutex");
      printMutexStatus(textPrintFlag, &myGlobals.purgePortsMutex,  "purgePortsMutex");
      printMutexStatus(textPrintFlag, &myGlobals.securityItemsMutex,  "securityItemsMutex");
      sendString(texthtml("\n\n", "</TABLE>"TABLE_OFF"\n"));
    }
#endif /* CFG_MULTITHREADED */

  if(textPrintFlag != TRUE) {
    sendString("<p>Click <a href=\"textinfo.html\" alt=\"Text version of this page\">"
	       "here</a> for a more extensive, text version of this page, suitable for "
	       "inclusion into a bug report!</p>\n");
  }

  sendString(texthtml("\n", "</CENTER>\n"));
}

/* *************************** */

int printNtopLogReport(int printAsText) {
    int i, j, lines = 0;
    char buf[LEN_GENERAL_WORK_BUFFER];

    if(myGlobals.logView == NULL) return(0);

    if(!printAsText) {
      printHTMLheader("ntop Log", BITFLAG_HTTP_NO_CACHE_CONTROL);
      sendString("<HR>");
      if(snprintf(buf, sizeof(buf), "<p><font face=\"Helvetica, Arial, Sans Serif\"><center>"
                "This is a rolling display of upto the last %d ntop log messages "
                "of priority INFO or higher.  Click on the \"log\" option, above, to refresh."
                "</center></font></p>", CONST_LOG_VIEW_BUFFER_SIZE) < 0)
          BufferTooShort();
      sendString(buf);
      sendString("<HR>");
      sendString("<pre>");
    }

#ifdef CFG_MULTITHREADED
#ifdef WIN32
	WaitForSingleObject(myGlobals.logViewMutex.mutex, INFINITE);
#else
    pthread_mutex_lock(&myGlobals.logViewMutex.mutex);
#endif
#endif

    for (i=0; i<CONST_LOG_VIEW_BUFFER_SIZE; i++) {
        j = (myGlobals.logViewNext + i) % CONST_LOG_VIEW_BUFFER_SIZE;
        
        if (myGlobals.logView[j] != NULL) {
            sendString(myGlobals.logView[j]);
            lines++;
            if (myGlobals.logView[j][strlen(myGlobals.logView[j])-1] != '\n');
                sendString("\n");
        }
    }

#ifdef CFG_MULTITHREADED
#ifdef WIN32
	ReleaseMutex(myGlobals.logViewMutex.mutex);
#else
    pthread_mutex_unlock(&myGlobals.logViewMutex.mutex);
#endif
#endif

    if(!printAsText) {
      sendString("</pre>");
    }

    return(lines);
}

/* *************************** */

void printNtopProblemReport(void) {
  char buf[LEN_TIMEFORMAT_BUFFER];
#ifdef PROBLEMREPORTID_DEBUG
  char buf2[256];
#endif
  static char xvert[] = "JB6XF3PRQHNA7W5ECM8S9GLVY4TDKUZ2"; /* Scrambled just 'cause */
  time_t t;
  unsigned int v, scramble, raw;
  int i, j;

#ifndef WIN32
  struct pcap_stat pcapStats;
  memset(&pcapStats, 0, sizeof(struct pcap_stat));
#endif

  t = time(NULL);

  sendString("Cut out this entire section and paste into an e-mail message.  Fill in the\n");
  sendString("various sections with as much detail as possible and email to the ntop lists,\n");
  sendString("user questions to ntop, code/development questions to ntop-dev.\n\n");
  sendString("Note: the shortcut keys for copying the section are usually:\n");
  sendString("    1) left click anywhere in this text (select this frame),\n");
  sendString("    2) press control-a (select all), control-c (copy)\n");
  sendString("  and then\n");
  sendString("    3) press control-v (paste) in a new email message.\n\n");
  sendString("Remember: ONE problem per report!\n\n");
  sendString("The summary should be 5-10 words that indicate the problem and which would have\n");
  sendString("helped you to find a previous report of the same problem, e.g.:\n");
  sendString("   2003-02-07 cvs compile error in util.c, #define NONOPTION_P...\n\n");
  sendString("Use the SAME 'summary' as the subject of your message, with the addition\n");
  sendString("of the PR_xxxxxx value.\n\n");
  sendString("For the 'Log Extract', cut and paste the last 10-15 system log messages.\n");
  sendString("Make sure - even if it's more than 15 messages that you show at least 5\n");
  sendString("or 6 messages (or a few minutes in time) BEFORE the first sign of failure.\n\n");
  sendString("Assuming your system log is in /var/log/messages, the command is:\n");
  sendString("   grep 'ntop' /var/log/messages | head -n 15\n");
  sendString("but you may have to increase the 15 to get the right messages.\n\n");

  sendString("Note: The generated id below should be unique. It's essentially a random 6\n");
  sendString("      or 7 character tracking tag for each problem report.  Since it's\n");
  sendString("      generated on your machine, we can't just use an ever increasing global\n");
  sendString("      number.  While it should be unique, it is not traceable back to a\n");
  sendString("      specific user or machine.\n\n");
  sendString("      If it makes you uncomfortable just delete it.\n\n");
  sendString("----------------------------------------------------------------------------\n");
  sendString(">>>>> Delete this line to the top before sending...\n");

  sendString("  n t o p   v e r s i o n  '");
  sendString(version);
  sendString("'  p r o b l e m   r e p o r t\n\n");
  sendString("From:  ______________________________\n\n");
  sendString("EMail: ______________________________\n\n");
  sendString("Date:  ");
  strftime(buf, sizeof(buf)-1, "%Y-%m-%d %H:%M:%S GMT", gmtime(&t));
  buf[sizeof(buf)-1] = '\0';
  sendString(buf);
  sendString("\n\n");

  /*
   *  Generate a (hopefully) globally unique tag for each report. The goal is to create something 
   *  unique (i.e. with a very small chance of the same tag being generated), yet not traceable
   *  to a specific user/machine (unless the user chooses to identify themselves) and - even then - 
   *  which isn't traceable to a subsequent report by the same user.
   *
   *  We combine a variety of numbers which, while maintained by ntop, it has little control over
   *  and so which shouldn't produce a predictable pattern.
   *
   *    Heartbeat count (if one)
   *    epoch time in seconds
   *    Elapsed time for this ntop run.
   *
   *  So that the higher digits aren't just dependent on TOD, we add the total # of bytes seen
   *  by ntop, using bit ops to shift the volitile nibbles towards the bits where the TOD is 
   *  less random.
   *
   *  Finally, we use a scrambled string of characters (xvert, above) to then convert
   *  the 32 bit integer into a character tag.  Using A-Z + 0-9, but dropping the
   *  0, 1 O and L gives us base 32 (5 bits per character).  We generate left-to-right, least 
   *  significant to most significant because it's just easier to generate that way.
   *
   *  If you enable the flag in globals-defines.h:
   *   #define PROBLEMREPORTID_DEBUG
   *  The data being used will be printed out for you.
   *                                        
   */
  v = 0;

#ifdef PROBLEMREPORTID_DEBUG
  snprintf(buf2, sizeof(buf2), "%-12s %48s %8s %8s\n", "Item", "Raw value", "Hex", "v value");
  sendString(buf2);
#endif

#ifdef PARM_SHOW_NTOP_HEARTBEAT
  v += myGlobals.heartbeatCounter /* If we have it */ ;
#ifdef PROBLEMREPORTID_DEBUG
  snprintf(buf2, sizeof(buf2), "%-12s %48u %08x %08x\n", "Heartbeat", 
	   myGlobals.heartbeatCounter, myGlobals.heartbeatCounter, v);
  sendString(buf2);
#endif
#endif

  v += (unsigned int) t;
#ifdef PROBLEMREPORTID_DEBUG
  strftime(buf, sizeof(buf)-1, "%Y-%m-%d %H:%M:%S GMT", gmtime(&t));
  buf[sizeof(buf)-1] = '\0';
  snprintf(buf2, sizeof(buf2), "%-12s %48s %08x %08x\n", "Date/Time", buf, t, v);
  sendString(buf2);
#endif

  v += myGlobals.actTime - myGlobals.initialSniffTime;
#ifdef PROBLEMREPORTID_DEBUG
  snprintf(buf2, sizeof(buf2), "%-12s %48u %08x %08x\n", "Elapsed",
	   (myGlobals.actTime - myGlobals.initialSniffTime), 
	   (myGlobals.actTime - myGlobals.initialSniffTime), v);
  sendString(buf2);
#endif

  raw = 0;
  for(i=0; i<= myGlobals.numDevices; i++)
    raw += (unsigned int) (myGlobals.device[i].ethernetBytes.value);

#ifdef PROBLEMREPORTID_DEBUG
  snprintf(buf2, sizeof(buf2), "%-12s %48u %08x\n", "Bytes", raw, raw);
  sendString(buf2);
#endif
  /* Scramble the nibbles so we have some data high and some low. 
     Arbitrary: abcdefgh -> fhgdaecb */
  scramble = (raw & 0xf0000000) >> 16 |
    (raw & 0x0f000000) >> 24 |
    (raw & 0x00f00000) >> 16 |
    (raw & 0x000f0000)       |
    (raw & 0x0000f000) >>  4 |
    (raw & 0x00000f00) << 20 |
    (raw & 0x000000f0) << 16 |
    (raw & 0x0000000f) << 24;
  v ^= scramble;
#ifdef PROBLEMREPORTID_DEBUG
  snprintf(buf2, sizeof(buf2), "%-12s %48u %08x %08x\n", "Bytes(scramble)", 
	   scramble, scramble, v);
  sendString(buf2);
#endif

  i=0;
  memset(buf, 0, sizeof(buf));
  while(v > 0) {
    j = v % (sizeof(xvert) - 1);
    v = v / (sizeof(xvert) - 1);
    buf[i] = xvert[j];   
#ifdef PROBLEMREPORTID_DEBUG
    snprintf(buf2, sizeof(buf2), "(%2d", j);
    sendString(buf2);
#endif
    i++;
  }
#ifdef PROBLEMREPORTID_DEBUG
  sendString("\n\n");
#endif

  sendString("Problem Report Id: PR_");
  sendString(buf);
  sendString("\n\n");
  sendString("----------------------------------------------------------------------------\n");
  sendString("Summary\n\n\n\n\n\n");
  sendString("OS: __________  version: __________\n\n");
  sendString("ntop from: ______________________________ (rpm, source, ports, etc.)\n\n");
  sendString("Hardware:  CPU:           _____ (i86, SPARC, etc.)\n");
  sendString("           # Processors:  _____\n");
  sendString("           Memory:        _____ MB\n");

  sendString("\nPackets\n");
  snprintf(buf, sizeof(buf), "Received:  %10u\n", myGlobals.receivedPackets);
  sendString(buf);
  snprintf(buf, sizeof(buf), "Processed: %10u (immediately)\n", myGlobals.receivedPacketsProcessed);
  sendString(buf);

#ifdef CFG_MULTITHREADED
  snprintf(buf, sizeof(buf), "Queued:    %10u\n", myGlobals.receivedPacketsQueued);
  sendString(buf);
  snprintf(buf, sizeof(buf), "Lost:      %10u (queue full)\n", myGlobals.receivedPacketsLostQ);
  sendString(buf);
  snprintf(buf, sizeof(buf), "Queue:     Current: %u Maximum: %u\n",
           myGlobals.packetQueueLen,
           myGlobals.maxPacketQueueLen);
  sendString(buf);
#endif

  sendString("\nNetwork:\n");

  if(myGlobals.mergeInterfaces == 1) {
    sendString("Merged packet counts:\n");
    if(myGlobals.device[0].receivedPkts.value > 0) {
      snprintf(buf, sizeof(buf), "     Received:  %10u\n", myGlobals.device[0].receivedPkts.value);
      sendString(buf);
    }
    if(myGlobals.device[0].droppedPkts.value > 0) {
      snprintf(buf, sizeof(buf), "     Dropped:   %10u\n", myGlobals.device[0].droppedPkts.value);
      sendString(buf);
    }
    if(myGlobals.device[0].ethernetPkts.value > 0) {
      snprintf(buf, sizeof(buf), "     Ethernet:  %10u\n", myGlobals.device[0].ethernetPkts.value);
      sendString(buf);
    }
    if(myGlobals.device[0].broadcastPkts.value > 0) {
      snprintf(buf, sizeof(buf), "     Broadcast: %10u\n", myGlobals.device[0].broadcastPkts.value);
      sendString(buf);
    }
    if(myGlobals.device[0].multicastPkts.value > 0) {
      snprintf(buf, sizeof(buf), "     Multicast: %10u\n", myGlobals.device[0].multicastPkts.value);
      sendString(buf);
    }
    if(myGlobals.device[0].ipPkts.value > 0) {
      snprintf(buf, sizeof(buf), "     IP:        %10u\n", myGlobals.device[0].ipPkts.value);
      sendString(buf);
    }
    sendString("\n");
  }

  for(i=0; i<myGlobals.numDevices; i++) {
    snprintf(buf, sizeof(buf), "     Network Interface %2d ", i);
    sendString(buf);
    if(myGlobals.device[0].dummyDevice)
      sendString(" (dummy)");
    if(myGlobals.device[i].virtualDevice)
      sendString(" (virtual)");
    if(myGlobals.device[i].name != NULL) {
      sendString(" ");
      sendString(myGlobals.device[i].name);
    }
    if(myGlobals.device[i].humanFriendlyName != NULL) {
      if(myGlobals.device[i].name != NULL) {
	if(strcmp(myGlobals.device[i].name, myGlobals.device[i].humanFriendlyName)) {
	  sendString(" "); 
	  sendString(myGlobals.device[i].humanFriendlyName);
	}
      } else {
	sendString(" "); 
	sendString(myGlobals.device[i].humanFriendlyName);
      }
    }
    sendString("\n");

    if(myGlobals.device[i].filter != NULL) {
      sendString("      Filter: ");
      sendString(myGlobals.device[i].filter);
      sendString("\n");
    }

/* pcap_stats gets weirded out under some circumstances under WIN32 - skip this */
#ifndef WIN32 
    if((myGlobals.device[i].pcapPtr != NULL) && 
       (pcap_stats(myGlobals.device[i].pcapPtr, &pcapStats) >= 0)) {
      snprintf(buf, sizeof(buf), "     Received (pcap):%10u\n", pcapStats.ps_recv);
      sendString(buf);
      if (pcapStats.ps_ifdrop > 0) {
        snprintf(buf, sizeof(buf), "     Dropped (NIC):  %10u\n", pcapStats.ps_ifdrop);
        sendString(buf);
      }
      snprintf(buf, sizeof(buf), "     Dropped (pcap): %10u\n", pcapStats.ps_drop);
      sendString(buf);
    }
#endif

    if(myGlobals.mergeInterfaces == 0) {
      if(myGlobals.device[i].receivedPkts.value > 0) {
	snprintf(buf, sizeof(buf), "     Received:       %10u\n", myGlobals.device[i].receivedPkts.value);
	sendString(buf);
      }
      if(myGlobals.device[i].droppedPkts.value > 0) {
	snprintf(buf, sizeof(buf), "     Dropped (ntop): %10u\n", myGlobals.device[i].droppedPkts.value);
	sendString(buf);
      }
      if(myGlobals.device[i].ethernetPkts.value > 0) {
	snprintf(buf, sizeof(buf), "     Ethernet:       %10u\n", myGlobals.device[i].ethernetPkts.value);
	sendString(buf);
      }
      if(myGlobals.device[i].broadcastPkts.value > 0) {
	snprintf(buf, sizeof(buf), "     Broadcast:      %10u\n", myGlobals.device[i].broadcastPkts.value);
	sendString(buf);
      }
      if(myGlobals.device[i].multicastPkts.value > 0) {
	snprintf(buf, sizeof(buf), "     Multicast:      %10u\n", myGlobals.device[i].multicastPkts.value);
	sendString(buf);
      }
      if(myGlobals.device[i].ipPkts.value > 0) {
	snprintf(buf, sizeof(buf), "     IP:             %10u\n", myGlobals.device[i].ipPkts.value);
	sendString(buf);
      }

    }

    sendString("          Mfg: ____________________  Model: ____________________\n");
    sendString("          NIC Speed: 10/100/1000/Other  Bus: PCI ISA USB Firewire Other\n");
    sendString("          Location:  Public Internet / LAN / WAN\n");
    sendString("          Bandwidth: Dialup  DSL/CableModem  fT1  T1  10Mbps T3 100Mbps+\n");
    sendString("          # Hosts (machines): __________\n\n");
  }

  sendString("----------------------------------------------------------------------------\n");
  sendString("Log extract\n\n");
  if(myGlobals.traceLevel >= CONST_NOISY_TRACE_LEVEL) {
    sendString("  (Please cut and paste actual log lines)\n");
  } else {
    if(printNtopLogReport(TRUE) == 0) 
      sendString("  (automated extract unavailable - please cut and paste actual log lines)\n");
  }
  sendString("\n\n\n\n");
  sendString("----------------------------------------------------------------------------\n");
  sendString("Problem Description\n\n\n\n\n\n\n\n\n\n");
  sendString("----------------------------------------------------------------------------\n");
  printNtopConfigInfo(TRUE);
  sendString("----------------------------------------------------------------------------\n");
}

/* **************************************** */

#define sslOrNot (isSSL ? " ssl" : "")

void initSocket(int isSSL, int *port, int *sock, char *addr) {
  int sockopt = 1, rc;
  struct sockaddr_in sockIn;
#ifdef INITWEB_DEBUG
  char value[LEN_SMALL_WORK_BUFFER];
#endif

#ifdef HAVE_FILEDESCRIPTORBUG
  int i;
#endif

  if(*port <= 0) {
    *sock = 0;
    return;
  }

  traceEvent(CONST_TRACE_NOISY, "Initializing%s socket, port %d, address %s",
             sslOrNot, *port, addr == NULL ? "(any)" : addr);

  memset(&sockIn, 0, sizeof(sockIn));
  sockIn.sin_family = AF_INET;
  sockIn.sin_port   = (int)htons((unsigned short int)(*port));
#ifndef WIN32
  if(addr) {
    if(!inet_aton(addr, &sockIn.sin_addr)) {
      traceEvent(CONST_TRACE_ERROR, "WEB: Unable to convert address '%s' - "
                 "not binding to a particular interface", addr);
      sockIn.sin_addr.s_addr = INADDR_ANY;
    } else {
      traceEvent(CONST_TRACE_INFO, "WEB: Converted address '%s' - "
                 "binding to the specific interface", addr);
    }
  } else {
    sockIn.sin_addr.s_addr = INADDR_ANY;
  }
#else
  sockIn.sin_addr.s_addr = INADDR_ANY;
#endif

#ifdef INITWEB_DEBUG
  if (snprintf(value, sizeof(value), "%d.%d.%d.%d", \
               (int) ((sockIn.sin_addr.s_addr >> 24) & 0xff), \
               (int) ((sockIn.sin_addr.s_addr >> 16) & 0xff), \
               (int) ((sockIn.sin_addr.s_addr >>  8) & 0xff), \
               (int) ((sockIn.sin_addr.s_addr >>  0) & 0xff)) < 0) \
      BufferTooShort(); \
  traceEvent(CONST_TRACE_INFO, "INITWEB_DEBUG: sockIn = %s:%d",
             value,
             ntohs(sockIn.sin_port));
#endif

#ifdef HAVE_FILEDESCRIPTORBUG
  /* Burton - Aug2003
   *   Work-around for file descriptor bug (FreeBSD PR51535 et al)
   *   - burn some file descriptors so the socket() call doesn't get a dirty one.
   *   - it's not pretty, but it works...
   */
  if(tempFilesCreated == 0) {
    tempFilesCreated = 1;
    myGlobals.tempFpid=getpid();
    traceEvent(CONST_TRACE_INFO, "FILEDESCRIPTORBUG: Work-around activated");
    for(i=0; i<CONST_FILEDESCRIPTORBUG_COUNT; i++) {
      myGlobals.tempF[i]=0;
      memset(&myGlobals.tempFname[i], 0, LEN_MEDIUM_WORK_BUFFER);

      if(snprintf(myGlobals.tempFname[i], LEN_MEDIUM_WORK_BUFFER, "/tmp/ntop-%09u-%d", myGlobals.tempFpid, i) < 0)
        BufferTooShort();
      traceEvent(CONST_TRACE_NOISY, "FILEDESCRIPTORBUG: Creating %d, '%s'", i, myGlobals.tempFname[i]);
      errno = 0;
      myGlobals.tempF[i]=open(myGlobals.tempFname[i], O_CREAT|O_TRUNC|O_RDWR);
      if(errno != 0) {
        traceEvent(CONST_TRACE_ERROR,
                   "FILEDESCRIPTORBUG: Unable to create file - may cause problems later - '%s'(%d)",
                   strerror(errno), errno);
      } else {
        traceEvent(CONST_TRACE_NOISY,
                   "FILEDESCRIPTORBUG: Created file %d - '%s'(%d)",
                   i, myGlobals.tempFname[i], myGlobals.tempF[i]);
      }
    }
  }
#endif /* FILEDESCRIPTORBUG */

    errno = 0;
    *sock = socket(AF_INET, SOCK_STREAM, 0);
    if((*sock <= 0) || (errno != 0) ) {
      traceEvent(CONST_TRACE_FATALERROR, "WEB: Unable to create a new%s socket - returned %d, error is '%s'(%d)",
                sslOrNot, *sock, strerror(errno), errno);
      exit(-1);
    }
    traceEvent(CONST_TRACE_NOISY, "WEB: Created a new%s socket (%d)", sslOrNot, *sock);

#ifdef INITWEB_DEBUG
  traceEvent(CONST_TRACE_INFO, "INITWEB_DEBUG:%s setsockopt(%d, SOL_SOCKET, SO_REUSEADDR ...",
             sslOrNot, *sock);
#endif

  errno = 0;
  rc = setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));
  if((rc < 0) || (errno != 0)) {
    traceEvent(CONST_TRACE_FATALERROR, "WEB: Unable to set%s socket options - '%s'(%d)",
               sslOrNot, strerror(errno), errno);
    exit(-1);
  }
#ifdef INITWEB_DEBUG
  traceEvent(CONST_TRACE_INFO, "INITWEB_DEBUG:%s socket %d, options set", sslOrNot, *sock);
#endif

  errno = 0;
  rc = bind(*sock, (struct sockaddr *)&sockIn, sizeof(sockIn));
  if((rc < 0) || (errno != 0)) {
    traceEvent(CONST_TRACE_FATALERROR,
               "WEB:%s binding problem - '%s'(%d)",
               sslOrNot, strerror(errno), errno);
    traceEvent(CONST_TRACE_INFO, "Check if another instance of ntop is running"); 
    closeNwSocket(&myGlobals.sock);
    exit(-1);
  }

#ifdef INITWEB_DEBUG
  traceEvent(CONST_TRACE_INFO, "INITWEB_DEBUG:%s socket %d bound", sslOrNot, *sock);
#endif

  errno = 0;
  rc = listen(*sock, 2);
  if((rc < 0) || (errno != 0)) {
    traceEvent(CONST_TRACE_FATALERROR, "WEB:%s listen(%d, 2) error %s(%d)",
               sslOrNot,
               *sock,
               strerror(errno), errno);
    closeNwSocket(&myGlobals.sock);
    exit(-1);
  }

  traceEvent(CONST_TRACE_INFO, "Initialized%s socket, port %d, address %s",
             sslOrNot,
             *port,
             addr == NULL ? "(any)" : addr);

}

#undef sslOrNot

/* **************************************** */

/* SSL fixes courtesy of Curtis Doty <curtis@greenkey.net>
                         Matthias Kattanek <mattes@mykmk.com> */

void initWeb(void) {

  traceEvent(CONST_TRACE_INFO, "WEB: Initializing web server");

  myGlobals.columnSort = 0;
  addDefaultAdminUser();
  initAccessLog();

  traceEvent(CONST_TRACE_INFO, "WEB: Initializing tcp/ip socket connections for web server");

  if(myGlobals.webPort > 0) {
    initSocket(FALSE, &myGlobals.webPort, &myGlobals.sock, myGlobals.webAddr);
    /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
    if(myGlobals.webAddr)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "WEB: Waiting for HTTP connections on %s port %d",
		 myGlobals.webAddr, myGlobals.webPort);
    else
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "WEB: Waiting for HTTP connections on port %d",
		 myGlobals.webPort);
  }

#ifdef HAVE_OPENSSL
  if((myGlobals.sslInitialized) && (myGlobals.sslPort > 0)) {
    initSocket(TRUE, &myGlobals.sslPort, &myGlobals.sock_ssl, myGlobals.sslAddr);
    if(myGlobals.sslAddr)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "WEB: Waiting for HTTPS (SSL) connections on %s port %d",
		 myGlobals.sslAddr, myGlobals.sslPort);
    else
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "WEB: Waiting for HTTPS (SSL) connections on port %d",
		 myGlobals.sslPort);
  }
#endif

#ifdef CFG_MULTITHREADED
  traceEvent(CONST_TRACE_INFO, "WEB: Starting web server");
  createThread(&myGlobals.handleWebConnectionsThreadId, handleWebConnections, NULL);
  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Started thread (%ld) for web server",
	     myGlobals.handleWebConnectionsThreadId);

#ifdef MAKE_WITH_SSLWATCHDOG
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  if(myGlobals.useSSLwatchdog == 1)
#endif
    {
      int rc;

      traceEvent(CONST_TRACE_INFO, "WEB: Starting https:// watchdog");

#ifdef SSLWATCHDOG_DEBUG
      traceEvent(CONST_TRACE_INFO, "SSLWDDEBUG: ****S*S*L*W*A*T*C*H*D*O*G*********STARTING");
      traceEvent(CONST_TRACE_INFO, "SSLWDDEBUG: P Common     Parent         Child");
      traceEvent(CONST_TRACE_INFO, "SSLWDDEBUG: - ---------- -------------- --------------");
#endif

      if((rc = sslwatchdogGetLock(FLAG_SSLWATCHDOG_BOTH)) != 0) {
	/* Bad thing - can't lock the mutex */
	sslwatchdogErrorN(">LockErr", FLAG_SSLWATCHDOG_BOTH, rc);
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
	/* --use-sslwatchdog?  Let's cheat - turn it off */
	traceEvent(CONST_TRACE_ERROR, "SSLWDERROR: *****Turning off sslWatchdog and continuing...");
	myGlobals.useSSLwatchdog = 0;
#else
	/* ./configure parm? very bad... */
	traceEvent(CONST_TRACE_ERROR, "SSLWDERROR: *****SSL Watchdog set via ./configure, aborting...");
	cleanup(0);
#endif
      }

      sslwatchdogDebug("CreateThread", FLAG_SSLWATCHDOG_BOTH, "");
      createThread(&myGlobals.sslwatchdogChildThreadId, sslwatchdogChildThread, NULL);
      traceEvent(CONST_TRACE_INFO, "Started thread (%ld) for ssl watchdog",
		 myGlobals.sslwatchdogChildThreadId);

      signal(SIGUSR1, sslwatchdogSighandler);
      sslwatchdogDebug("setsig()", FLAG_SSLWATCHDOG_BOTH, "");

      sslwatchdogClearLock(FLAG_SSLWATCHDOG_BOTH);
    }
#endif /* MAKE_WITH_SSLWATCHDOG */

#endif /* CFG_MULTITHREADED */

  traceEvent(CONST_TRACE_NOISY, "WEB: Server started... continuing with initialization");
}


/* ************************************* */

void closeNwSocket(int *sockId) {
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Closing socket %d...", *sockId);
#endif

  if(*sockId == FLAG_DUMMY_SOCKET)
    return;

#ifdef HAVE_OPENSSL
  if(*sockId < 0)
    term_ssl_connection(-(*sockId));
  else
    closesocket(*sockId);
#else
  closesocket(*sockId);
#endif

  *sockId = FLAG_DUMMY_SOCKET;
}


/* **************************************** */

#ifndef WIN32
static void PIPEhandler(int sig) {
  myGlobals.numHandledSIGPIPEerrors++;
  signal (SIGPIPE, PIPEhandler);
}
#endif

/* **************************************** */

#ifdef MAKE_WITH_SSLWATCHDOG

int sslwatchdogWaitFor(int stateValue, int parentchildFlag, int alreadyLockedFlag) { 
  int waitwokeCount;
  int rc=0, rc1;

  sslwatchdogDebugN("WaitFor=", parentchildFlag, stateValue);

  if(alreadyLockedFlag == FLAG_SSLWATCHDOG_ENTER_LOCKED) {
    sslwatchdogDebug("Lock", parentchildFlag, "");
    if((rc = pthread_mutex_lock(&myGlobals.sslwatchdogCondvar.mutex)) != 0) {
      sslwatchdogDebugN(">LockErr", parentchildFlag, rc);
      return rc;
    } else {
      sslwatchdogDebug(">Locked", parentchildFlag, "");
    }
  }
    
  /* We're going to wait until the state = our test value or abort... */
  waitwokeCount = 0;

  while(myGlobals.sslwatchdogCondvar.predicate != stateValue) { 
    /* Test for finished flag... */ 
    if(myGlobals.sslwatchdogCondvar.predicate == FLAG_SSLWATCHDOG_FINISHED) { 
      sslwatchdogDebug(">ABORT", parentchildFlag, "");
      break;
    } 
    if(myGlobals.sslwatchdogCondvar.predicate == stateValue) { 
      sslwatchdogDebug(">Continue", parentchildFlag, "");
      break;
    } 
    if(waitwokeCount > PARM_SSLWATCHDOG_WAITWOKE_LIMIT) { 
      sslwatchdogDebug(">abort(lim)", parentchildFlag, "");
      break;
    } 
    sslwatchdogDebugN("wait", parentchildFlag, waitwokeCount);
    sslwatchdogDebug("(unlock)", parentchildFlag, "");
    rc = pthread_cond_wait(&myGlobals.sslwatchdogCondvar.condvar, 
			   &myGlobals.sslwatchdogCondvar.mutex); 
    sslwatchdogDebug("(lock)", parentchildFlag, "");
    sslwatchdogDebug("woke", parentchildFlag, "");
    waitwokeCount++;
  } /* while */

  sslwatchdogDebug("unlock", parentchildFlag, "");
  if((rc1 = pthread_mutex_unlock(&myGlobals.sslwatchdogCondvar.mutex)) != 0) {
    sslwatchdogDebugN(">UnlockErr", parentchildFlag, rc1);
    return rc1;
  } else {
    sslwatchdogDebug(">Unlocked", parentchildFlag, "");
  }
    
  return rc; /* This is the code from the while loop, above */
}

/* **************************************** */

int sslwatchdogClearLock(int parentchildFlag) {
  int rc;

  sslwatchdogDebug("unlock", parentchildFlag, "");
  if((rc = pthread_mutex_unlock(&myGlobals.sslwatchdogCondvar.mutex)) != 0) {
    sslwatchdogDebugN(">UnlockErr", parentchildFlag, rc);
  } else {
    sslwatchdogDebug(">Unlocked", parentchildFlag, "");
  };
  return rc;
}

/* **************************************** */

int sslwatchdogGetLock(int parentchildFlag) {
  int rc;

  sslwatchdogDebug("lock", parentchildFlag, "");
  if((rc = pthread_mutex_lock(&myGlobals.sslwatchdogCondvar.mutex)) != 0) {
    sslwatchdogDebugN(">LockErr", parentchildFlag, rc);
  } else {
    sslwatchdogDebug(">Locked", parentchildFlag, "");
  }

  return rc;
}

/* **************************************** */

int sslwatchdogSignal(int parentchildFlag) {
  int rc;

  sslwatchdogDebug("signaling", parentchildFlag, "");
  rc = pthread_cond_signal(&myGlobals.sslwatchdogCondvar.condvar);
  if(rc != 0) {
    sslwatchdogError("sigfail",  parentchildFlag, "");
  } else {
    sslwatchdogDebug("signal->", parentchildFlag, "");
  }

  return(rc);
}

/* **************************************** */

int sslwatchdogSetState(int stateNewValue, int parentchildFlag, 
			int enterLockedFlag, int exitLockedFlag) {
  int rc=0;
    
  sslwatchdogDebugN("SetState=", parentchildFlag, stateNewValue);

  if(enterLockedFlag != FLAG_SSLWATCHDOG_ENTER_LOCKED) {
    rc = sslwatchdogGetLock(parentchildFlag);
  }

  myGlobals.sslwatchdogCondvar.predicate = stateNewValue;
    
  sslwatchdogSignal(parentchildFlag);

  if(exitLockedFlag != FLAG_SSLWATCHDOG_RETURN_LOCKED) {
    rc = sslwatchdogClearLock(parentchildFlag);
  }

  return(rc);
}

/* **************************************** */

void sslwatchdogSighandler(int signum)
{
  /* If this goes off, the ssl_accept() below didn't respond */
  signal(SIGUSR1, SIG_DFL);
  sslwatchdogDebug("->SIGUSR1", FLAG_SSLWATCHDOG_PARENT, "");
  longjmp (sslwatchdogJump, 1);
}

/* **************************************** */
/* **************************************** */

void* sslwatchdogChildThread(void* notUsed _UNUSED_) {
  /* This is the watchdog (child) */
  int rc;
  struct timespec expiration;
    
  /* ENTRY: from above, state 0 (FLAG_SSLWATCHDOG_UNINIT) */
  sslwatchdogDebug("BEGINthread", FLAG_SSLWATCHDOG_CHILD, "");

  rc = sslwatchdogSetState(FLAG_SSLWATCHDOG_WAITINGREQUEST,
			   FLAG_SSLWATCHDOG_CHILD, 
			   0-FLAG_SSLWATCHDOG_ENTER_LOCKED,
			   0-FLAG_SSLWATCHDOG_RETURN_LOCKED);

  while(myGlobals.sslwatchdogCondvar.predicate != FLAG_SSLWATCHDOG_FINISHED) { 
    
    sslwatchdogWaitFor(FLAG_SSLWATCHDOG_HTTPREQUEST, 
		       FLAG_SSLWATCHDOG_CHILD, 
		       0-FLAG_SSLWATCHDOG_ENTER_LOCKED);
    
    expiration.tv_sec = time(NULL) + PARM_SSLWATCHDOG_WAIT_INTERVAL; /* watchdog timeout */
    expiration.tv_nsec = 0;
    sslwatchdogDebug("Expires", FLAG_SSLWATCHDOG_CHILD, formatTime(&expiration.tv_sec, 0));

    while(myGlobals.sslwatchdogCondvar.predicate == FLAG_SSLWATCHDOG_HTTPREQUEST) { 

      rc = sslwatchdogGetLock(FLAG_SSLWATCHDOG_CHILD);

      /* Suspended wait until abort or we're woken up for a request */
      /*   Note: we hold the mutex when we come back */
      sslwatchdogDebug("twait",    FLAG_SSLWATCHDOG_CHILD, "");
      sslwatchdogDebug("(unlock)", FLAG_SSLWATCHDOG_CHILD, "");
      rc = pthread_cond_timedwait(&myGlobals.sslwatchdogCondvar.condvar, 
				  &myGlobals.sslwatchdogCondvar.mutex, 
				  &expiration);

      sslwatchdogDebug("(lock)",  FLAG_SSLWATCHDOG_CHILD, "");
      sslwatchdogDebug("endwait", 
		       FLAG_SSLWATCHDOG_CHILD, 
		       ((rc == ETIMEDOUT) ? " TIMEDOUT" : ""));

      /* Something woke us up ... probably "https complete" or "finshed" message */
      if(rc == ETIMEDOUT) {
	/* No response from the parent thread... oh dear... */
	sslwatchdogDebug("send(USR1)", FLAG_SSLWATCHDOG_CHILD, "");
	rc = pthread_kill(myGlobals.handleWebConnectionsThreadId, SIGUSR1);
	if(rc != 0) {
	  sslwatchdogErrorN("sent(USR1)", FLAG_SSLWATCHDOG_CHILD, rc);
	} else {
	  sslwatchdogDebug("sent(USR1)", FLAG_SSLWATCHDOG_CHILD, "");
	}
	rc = sslwatchdogSetState(FLAG_SSLWATCHDOG_WAITINGREQUEST,
				 FLAG_SSLWATCHDOG_CHILD, 
				 FLAG_SSLWATCHDOG_ENTER_LOCKED,
				 0-FLAG_SSLWATCHDOG_RETURN_LOCKED);
	break;
      }
      if(rc == 0) {
	if(myGlobals.sslwatchdogCondvar.predicate == FLAG_SSLWATCHDOG_FINISHED) {
	  sslwatchdogDebug("woke", FLAG_SSLWATCHDOG_CHILD, "*finished*");
	  break;
	}

	/* Ok, hSWC() is done, so recycle the watchdog for next time */
	rc = sslwatchdogSetState(FLAG_SSLWATCHDOG_WAITINGREQUEST,
				 FLAG_SSLWATCHDOG_CHILD, 
				 FLAG_SSLWATCHDOG_ENTER_LOCKED,
				 0-FLAG_SSLWATCHDOG_RETURN_LOCKED);
	break;
      }

      /* rc != 0 --- error */
      rc = sslwatchdogClearLock(FLAG_SSLWATCHDOG_CHILD);

    } /* while(... == FLAG_SSLWATCHDOG_HTTPREQUEST) */
  } /* while(... != FLAG_SSLWATCHDOG_FINISHED) */

    /* Bye bye child... */

  sslwatchdogDebug("ENDthread", FLAG_SSLWATCHDOG_CHILD, "");

  return(NULL);
}
   
#endif /* MAKE_WITH_SSLWATCHDOG */

/* ******************************************* */

#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_HTTPSIGTRAP)

RETSIGTYPE webservercleanup(int signo) {
  static int msgSent = 0;
  int i;
  void *array[20];
  size_t size;
  char **strings;

  if(msgSent<10) {
    traceEvent(CONST_TRACE_FATALERROR, "webserver: caught signal %d %s", signo,
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

  traceEvent(CONST_TRACE_FATALERROR, "webserver: BACKTRACE:     backtrace is:");
  if (size < 2)
      traceEvent(CONST_TRACE_FATALERROR, "webserver: BACKTRACE:         **unavailable!");
  else
      /* Ignore the 0th entry, that's our cleanup() */
      for (i=1; i<size; i++)
          traceEvent(CONST_TRACE_FATALERROR, "webserver: BACKTRACE:          %2d. %s", i, strings[i]);
 #endif

  exit(0);
}
#endif /* CFG_MULTITHREADED && MAKE_WITH_HTTPSIGTRAP */

/* ******************************************* */

void* handleWebConnections(void* notUsed _UNUSED_) {
#ifndef CFG_MULTITHREADED
    struct timeval wait_time;
#else
    int rc;
#endif
    fd_set mask, mask_copy;
    int topSock = myGlobals.sock;

#ifdef CFG_MULTITHREADED
#ifdef MAKE_WITH_HTTPSIGTRAP
    signal(SIGSEGV, webservercleanup);
    signal(SIGHUP,  webservercleanup);
    signal(SIGINT,  webservercleanup);
    signal(SIGQUIT, webservercleanup);
    signal(SIGILL,  webservercleanup);
    signal(SIGABRT, webservercleanup);
    signal(SIGFPE,  webservercleanup);
    signal(SIGKILL, webservercleanup);
    signal(SIGPIPE, webservercleanup);
    signal(SIGALRM, webservercleanup);
    signal(SIGTERM, webservercleanup);
    signal(SIGUSR1, webservercleanup);
    signal(SIGUSR2, webservercleanup);
    /* signal(SIGCHLD, webservercleanup); */
#ifdef SIGCONT
    signal(SIGCONT, webservercleanup);
#endif
#ifdef SIGSTOP
    signal(SIGSTOP, webservercleanup);
#endif
#ifdef SIGBUS
    signal(SIGBUS,  webservercleanup);
#endif
#ifdef SIGSYS
    signal(SIGSYS,  webservercleanup);
#endif
#endif /* MAKE_WITH_HTTPSIGTRAP */

#ifndef WIN32
    traceEvent(CONST_TRACE_INFO, "THREADMGMT: web connections thread (%ld) started...", getpid());
#endif
#endif

#ifndef WIN32
#ifdef CFG_MULTITHREADED
    /*
     *  The great ntop "mysterious web server death" fix... and other tales of
     *  sorcery.
     *
     *PART1
     *
     *  The problem is that Internet Explorer (and other browsers) seem to close
     *  the connection when they receive an unknown certificate in response to
     *  an https:// request.  This causes a SIGPIPE and kills the web handling
     *  thread - sometimes (for sure, the ONLY case I know of is if ntop is
     *  run under Linux gdb connected to from a Win2K browser).
     *
     *  This code simply counts SIGPIPEs and ignores them. 
     *
     *  However, it's not that simple - under gdb under Linux (and perhaps other 
     *  OSes), the thread mask on a child thread disables our ability to set a 
     *  signal handler for SIGPIPE. However, gdb seems to trap the SIGPIPE and
     *  reflect it to the code, even if the code wouldn't see it without the debug!
     *
     *  Hence the multi-step code.
     *
     *  This code SHOULD be safe.  Many other programs have had to so this.
     *
     *  Because I'm not sure, I've put both a compile time (--enable-ignoresigpipe)
     *  and run-time --ignore-sigpipe option in place.
     *
     *  Recommended:
     *    If you aren't seeing the "mysterious death of web server" problem:
     *        don't worry - be happy.
     *    If you are, try running for a while with --ignore-sigpipe
     *        If that seems to fix it, then compile with --enable-ignoressigpipe
     *
     *PART2
     *
     *  For reasons unknown Netscape 6.2.2 (and probably others) goes into ssl_accept
     *  and never returns.
     *
     *  It's been reported as a bug in Netscape 6.2.2, that has a workaround in 
     *  openSSL 0.9.6c but I can't get it to work.
     *
     *  So, we create - also optional - and only if we're using ssl - a watchdog
     *  thread.  If we've not completed the sslAccept in a few seconds, we signal
     *  the main thread and force it to abandon the accept.
     *
     *  June 2002 - Burton M. Strauss III <Burton@ntopsupport.com>
     *
     */

    {
	sigset_t a_oset, a_nset;
	sigset_t *oset, *nset;

	/* First, build our mask - empty, except for "UNBLOCK" SIGPIPE... */
	oset = &a_oset;
	nset = &a_nset;

	sigemptyset(nset);
	rc = sigemptyset(nset);
	if(rc != 0) 
	    traceEvent(CONST_TRACE_ERROR, "SIGPIPE handler set, sigemptyset() = %d, gave %p", rc, nset);

	rc = sigaddset(nset, SIGPIPE);
	if(rc != 0)
	    traceEvent(CONST_TRACE_ERROR, "SIGPIPE handler set, sigaddset() = %d, gave %p", rc, nset);

#ifndef DARWIN
	rc = pthread_sigmask(SIG_UNBLOCK, NULL, oset);
#ifdef DEBUG
	traceEvent(CONST_TRACE_ERROR, "DEBUG: Note: SIGPIPE handler set (was), pthread_setsigmask(-, NULL, %x) returned %d", 
		   oset, rc);
#endif

	rc = pthread_sigmask(SIG_UNBLOCK, nset, oset);
	if(rc != 0)
	    traceEvent(CONST_TRACE_ERROR, "Error, SIGPIPE handler set, pthread_setsigmask(SIG_UNBLOCK, %x, %x) returned %d", 
		       nset, oset, rc);

	rc = pthread_sigmask(SIG_UNBLOCK, NULL, oset);
#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "DEBUG: Note, SIGPIPE handler set (is), pthread_setsigmask(-, NULL, %x) returned %d", 
		   oset, rc);
#endif
#endif /* DARWIN */

	if(rc == 0) {
	    signal(SIGPIPE, PIPEhandler); 
#ifdef DEBUG
	    traceEvent(CONST_TRACE_INFO, "DEBUG: Note: SIGPIPE handler set");
#endif
	}
    }
#endif /* CFG_MULTITHREADED */
#endif /* WIN32 */

    FD_ZERO(&mask);

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

#ifndef CFG_MULTITHREADED
    /* select returns immediately */
    wait_time.tv_sec = 0, wait_time.tv_usec = 0;
    if(select(topSock+1, &mask, 0, 0, &wait_time) == 1)
	handleSingleWebConnection(&mask);
#else /* CFG_MULTITHREADED */
    while(myGlobals.capturePackets != FLAG_NTOPSTATE_TERM) {
	sslwatchdogDebug("BEGINloop", FLAG_SSLWATCHDOG_BOTH, "");
#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "DEBUG: Select(ing) %d....", topSock);
#endif
	memcpy(&mask, &mask_copy, sizeof(fd_set));
	rc = select(topSock+1, &mask, 0, 0, NULL /* Infinite */);
#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "DEBUG: select returned: %d", rc);
#endif
	if(rc > 0) {
	    HEARTBEAT(1, "handleWebConnections()", NULL);
	    /* Now, handle the web connection ends up in SSL_Accept() */
	    sslwatchdogDebug("->hSWC()", FLAG_SSLWATCHDOG_PARENT, "");
	    handleSingleWebConnection(&mask);
	    sslwatchdogDebug("hSWC()->", FLAG_SSLWATCHDOG_PARENT, "");
	}
	sslwatchdogDebug("ENDloop", FLAG_SSLWATCHDOG_BOTH, "");
    }

    traceEvent(CONST_TRACE_WARNING, "THREADMGMT: web connections thread (%ld) terminated...", myGlobals.handleWebConnectionsThreadId);
    myGlobals.handleWebConnectionsThreadId = 0;

#endif /* CFG_MULTITHREADED */

    return(NULL); 

}

/* ************************************* */

static void handleSingleWebConnection(fd_set *fdmask) {
    struct sockaddr_in from;
    int from_len = sizeof(from);

    errno = 0;

    if(FD_ISSET(myGlobals.sock, fdmask)) {
#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "DEBUG: Accepting HTTP request...");
#endif
	myGlobals.newSock = accept(myGlobals.sock, (struct sockaddr*)&from, &from_len);
    } else {
#if defined(DEBUG) && defined(HAVE_OPENSSL)
	if(myGlobals.sslInitialized)
	    traceEvent(CONST_TRACE_INFO, "DEBUG: Accepting HTTPS request...");
#endif
#ifdef HAVE_OPENSSL
	if(myGlobals.sslInitialized)
	    myGlobals.newSock = accept(myGlobals.sock_ssl, (struct sockaddr*)&from, &from_len);
#else
	;
#endif
    }

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Request accepted (sock=%d) (errno=%d)", myGlobals.newSock, errno);
#endif

    if(myGlobals.newSock > 0) {
#ifdef HAVE_OPENSSL
	if(myGlobals.sslInitialized)
	    if(FD_ISSET(myGlobals.sock_ssl, fdmask)) {
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
		if(myGlobals.useSSLwatchdog == 1)
#endif
		{		
#ifdef MAKE_WITH_SSLWATCHDOG
		    int rc;

		    /* The watchdog ... */
		    if(setjmp(sslwatchdogJump) != 0) {
			int i, j, k;
			char buf[256];

			sslwatchdogError("TIMEOUT", FLAG_SSLWATCHDOG_PARENT, "processing continues!");
			myGlobals.numHTTPSrequestTimeouts++;
			traceEvent(CONST_TRACE_ERROR, 
				   "SSLWDERROR: Watchdog timer has expired. "
				   "Aborting request, but ntop processing continues!\n");
			for(i=0; i<MAX_SSL_CONNECTIONS; i++) {
			    if(myGlobals.ssl[i].socketId == myGlobals.newSock) {
				break;
			    }
			}
			if(i<MAX_SSL_CONNECTIONS) {
			    j=k=0;
			    while((k<255) && (myGlobals.ssl[i].ctx->packet[j] != '\0')) {
				if((myGlobals.ssl[i].ctx->packet[j] >= 32 /* space */) && 
				   (myGlobals.ssl[i].ctx->packet[j] < 127)) 
				    buf[k++]=myGlobals.ssl[i].ctx->packet[j];
				j++;
			    }
			    buf[k+1]='\0';
			    traceEvent(CONST_TRACE_ERROR, "SSLWDERROR: Failing request was (translated): %s", buf);
			}
			signal(SIGUSR1, sslwatchdogSighandler);
			return;
		    }

		    rc = sslwatchdogWaitFor(FLAG_SSLWATCHDOG_WAITINGREQUEST,
					    FLAG_SSLWATCHDOG_PARENT, 
					    0-FLAG_SSLWATCHDOG_ENTER_LOCKED);

		    rc = sslwatchdogSetState(FLAG_SSLWATCHDOG_HTTPREQUEST,
					     FLAG_SSLWATCHDOG_PARENT,
					     0-FLAG_SSLWATCHDOG_ENTER_LOCKED,
					     0-FLAG_SSLWATCHDOG_RETURN_LOCKED);
#endif /* MAKE_WITH_SSLWATCHDOG */
		}

		if(accept_ssl_connection(myGlobals.newSock) == -1) {
		    traceEvent(CONST_TRACE_WARNING, "Unable to accept SSL connection");
		    closeNwSocket(&myGlobals.newSock);
		    return;
		} else {
		    myGlobals.newSock = -myGlobals.newSock;
		}

#ifdef MAKE_WITH_SSLWATCHDOG
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
		if(myGlobals.useSSLwatchdog == 1)
#endif
		{
		    int rc = sslwatchdogSetState(FLAG_SSLWATCHDOG_HTTPCOMPLETE,
						 FLAG_SSLWATCHDOG_PARENT,
						 0-FLAG_SSLWATCHDOG_ENTER_LOCKED,
						 0-FLAG_SSLWATCHDOG_RETURN_LOCKED);
		    /* Wake up child */ 
		    rc = sslwatchdogSignal(FLAG_SSLWATCHDOG_PARENT);
		}
#endif /* MAKE_WITH_SSLWATCHDOG */
	    }
#endif /* HAVE_OPENSSL */

#ifdef HAVE_LIBWRAP
	{
	    struct request_info req;
	    request_init(&req, RQ_DAEMON, CONST_DAEMONNAME, RQ_FILE, myGlobals.newSock, NULL);
	    fromhost(&req);
	    if(!hosts_access(&req)) {
		closelog(); /* just in case */
		openlog(CONST_DAEMONNAME, LOG_PID, deny_severity);
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
	traceEvent(CONST_TRACE_INFO, "Unable to accept HTTP(S) request (errno=%d: %s)", errno, strerror(errno));
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
	    if((!flows->pluginStatus.activePlugin) &&
	       (!flows->pluginStatus.pluginPtr->inactiveSetup) ) {
		char buf[LEN_GENERAL_WORK_BUFFER], name[32];

		sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);
		strncpy(name, flows->pluginStatus.pluginPtr->pluginURLname, sizeof(name));
		name[sizeof(name)-1] = '\0'; /* just in case pluginURLname is too long... */
		if((strlen(name) > 6) && (strcasecmp(&name[strlen(name)-6], "plugin") == 0))
		    name[strlen(name)-6] = '\0';
		if(snprintf(buf, sizeof(buf),"Status for the \"%s\" Plugin", name) < 0)
		    BufferTooShort();
		printHTMLheader(buf, BITFLAG_HTML_NO_REFRESH);
		printFlagedWarning("<I>This plugin is currently inactive.</I>");
		printHTMLtrailer();
		return(1);
	    }

	    if(strlen(url) == strlen(flows->pluginStatus.pluginPtr->pluginURLname))
		arg = "";
	    else
		arg = &url[strlen(flows->pluginStatus.pluginPtr->pluginURLname)+1];

	    /* traceEvent(CONST_TRACE_INFO, "Found %s [%s]",
	       flows->pluginStatus.pluginPtr->pluginURLname, arg); */
	    flows->pluginStatus.pluginPtr->httpFunct(arg);
	    return(1);
	} else
	    flows = flows->next;

    return(0); /* Plugin not found */
}
