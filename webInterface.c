/*
 *  Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
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
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

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
static int inet_aton(const char *cp, struct in_addr *addr) {
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
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "QUERY_STRING=%s", &cgiName[i+1]);
      putenv(buf);
      num = 1;
      break;
    }

  putenv("REQUEST_METHOD=GET");

  if(num == 0) {
    safe_snprintf(__FILE__, __LINE__, line, sizeof(line), "QUERY_STRING=%s", getenv("PWD"));
    putenv(line); /* PWD */
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "NOTE: CGI %s", line);
#endif
  }

  putenv("WD="CFG_DATAFILE_DIR);

  safe_snprintf(__FILE__, __LINE__, line, sizeof(line), "%s/cgi/%s", CFG_DATAFILE_DIR, cgiName);
  
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
  int newPluginStatus = 0, rc=0;

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
	    flows->pluginStatus.pluginPtr->termFunct(0 /* term plugin */);
	} else {
	  if(flows->pluginStatus.pluginPtr->startFunct != NULL)
	    rc = flows->pluginStatus.pluginPtr->startFunct();
	  if(rc || (flows->pluginStatus.pluginPtr->pluginStatusMessage != NULL))
	    newPluginStatus = 0 /* Disabled */;
	}

	flows->pluginStatus.activePlugin = newPluginStatus;

	safe_snprintf(__FILE__, __LINE__, key, sizeof(key), "pluginStatus.%s", 
		    flows->pluginStatus.pluginPtr->pluginName);

	storePrefsValue(key, newPluginStatus ? "1" : "0");
      }

      if(!doPrintHeader) {
	printHTMLheader("Available Plugins", NULL, 0);
 	sendString("<CENTER>\n"
		   ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n"
		   "<TR "DARK_BG"><TH "TH_BG">View</TH><TH "TH_BG">Configure</TH>\n"
                   "<TH "TH_BG">Description</TH>\n"
		   "<TH "TH_BG">Version</TH><TH "TH_BG">Author</TH>\n"
		   "<TH "TH_BG">Active<br>[click to toggle]</TH>"
		   "</TR>\n");
	doPrintHeader = 1;
      }

      safe_snprintf(__FILE__, __LINE__, tmpBuf1, sizeof(tmpBuf1), "<A HREF=\"/plugins/%s\" title=\"Invoke plugin\">%s</A>",
		  flows->pluginStatus.pluginPtr->pluginURLname, flows->pluginStatus.pluginPtr->pluginURLname);

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT %s>",
		  getRowColor(),
                  flows->pluginStatus.pluginPtr->pluginStatusMessage != NULL ?
                      "rowspan=\"2\"" :
                      "");
      sendString(tmpBuf);

      if(flows->pluginStatus.pluginPtr->inactiveSetup) {
          sendString("&nbsp;</TH>\n");
      } else {
          safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%s</TH>\n",
                      flows->pluginStatus.activePlugin ?
                          tmpBuf1 : flows->pluginStatus.pluginPtr->pluginURLname);
          sendString(tmpBuf);
      } 

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "<TH "TH_BG" ALIGN=LEFT %s>",
                  flows->pluginStatus.pluginPtr->pluginStatusMessage != NULL ?
                      "rowspan=\"2\"" :
                      "");
      sendString(tmpBuf);

      if(flows->pluginStatus.pluginPtr->inactiveSetup) {
          safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%s</TH>\n", tmpBuf1);
          sendString(tmpBuf);
      } else {
          sendString("&nbsp;</TH>\n");
      } 

      if(flows->pluginStatus.pluginPtr->pluginStatusMessage != NULL) {
	safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "<TD colspan=\"4\"><font COLOR=\"#FF0000\">%s</font></TD></TR>\n<TR "TR_ON" %s>\n",
		    flows->pluginStatus.pluginPtr->pluginStatusMessage,
		    getRowColor());
	sendString(tmpBuf);
      }

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "<TD "TD_BG" ALIGN=LEFT>%s</TD>\n"
		  "<TD "TD_BG" ALIGN=CENTER>%s</TD>\n"
		  "<TD "TD_BG" ALIGN=LEFT>%s</TD>\n"
		  "<TD "TD_BG" ALIGN=CENTER><A HREF=\"" CONST_SHOW_PLUGINS_HTML "?%s=%d\">%s</A></TD>"
		  "</TR>\n",
		  flows->pluginStatus.pluginPtr->pluginDescr,
		  flows->pluginStatus.pluginPtr->pluginVersion,
		  flows->pluginStatus.pluginPtr->pluginAuthor,
		  flows->pluginStatus.pluginPtr->pluginURLname,
		  flows->pluginStatus.activePlugin ? 0: 1,
		  flows->pluginStatus.activePlugin ?
		  "Yes" : "<FONT COLOR=\"#FF0000\">No</FONT>");
      sendString(tmpBuf);
    }

    flows = flows->next;
  }

  if(!doPrintHeader) {
    printHTMLheader("No Plugins available", NULL, 0);
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

char* makeHostAgeStyleSpec(HostTraffic *el, char *buf, int bufSize) {
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
  
  safe_snprintf(__FILE__, __LINE__, buf, bufSize, "class=\"age%dmin\"", age);
  
  return(buf);
}

/* ******************************* */

char* makeHostLink(HostTraffic *el, short mode,
		   short cutName, short addCountryFlag,
                   char *buf, int bufLen) {
  char symIp[256], linkName[256], flag[256], colorSpec[64], vlanStr[8];
  char osBuf[128], titleBuf[256], noteBuf[256], noteBufAppend[64];
  char *dhcpBootpStr, *p2pStr, *multihomedStr, *gwStr, *brStr, *dnsStr, *printStr,
       *smtpStr, *healthStr, *userStr, *httpStr, *ntpStr;
  short usedEthAddress=0;
  int i;

  if(el == NULL)
    return("&nbsp;");

  if (el->l2Family == FLAG_HOST_TRAFFIC_AF_FC) {
      return makeFcHostLink (el, mode, cutName, TRUE, buf, bufLen);
  }

  memset(&symIp, 0, sizeof(symIp));
  memset(&linkName, 0, sizeof(linkName));
  memset(&flag, 0, sizeof(flag));
  memset(&colorSpec, 0, sizeof(colorSpec));
  memset(&osBuf, 0, sizeof(osBuf));
  memset(&titleBuf, 0, sizeof(titleBuf));
  memset(&noteBuf, 0, sizeof(noteBuf));
  memset(&noteBufAppend, 0, sizeof(noteBufAppend));

  /* Critical - for sorting order - that this routine respect hostResolvedName
   *
   * Remember - if this is being referenced in a fork()ed child, i.e as part of
   *            most reports on most systems, then setting flags in here is a waste.
   *
   *            Further, the more of that you do, the more likely that ntop will
   *            function differently if -K | --debug is set, or in single threaded
   *            mode or under gdb (debugger)!
   */

  if(el->hostResolvedNameType < FLAG_HOST_SYM_ADDR_TYPE_NONE) {
    /* <NONE is FAKE and (maybe) others we probably should NOT really be reporting on */
    char *fmt;
    char commentBuf[64];
    memset(&commentBuf, 0, sizeof(commentBuf));

    if(mode == FLAG_HOSTLINK_HTML_FORMAT)
      fmt = "<TH "TH_BG" ALIGN=LEFT>%s%s</TH>";
    else
      fmt = "%s%s";

    if(broadcastHost(el)) {
      safe_snprintf(__FILE__, __LINE__, buf, bufLen, fmt, "", "broadcast");
    } else if(el == myGlobals.otherHostEntry) {
      safe_snprintf(__FILE__, __LINE__, buf, bufLen, fmt, "", el->hostResolvedName);
    } else {
      safe_snprintf(__FILE__, __LINE__, commentBuf, sizeof(commentBuf),
                  "<!-- unknown %d lt NONE -->", el->hostResolvedNameType);
      safe_snprintf(__FILE__, __LINE__, buf, bufLen, fmt, commentBuf, el->hostResolvedName);
    }

    return(buf);
  }
 
  accessAddrResMutex("makeHostLink");

  if((el->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_NONE)
     || (el->hostResolvedName[0] == '\0') /* Safety check */
     ) {
    /* It's not officially known, so let's do what we can
     */
    if(addrnull(&el->hostIpAddress) && (el->ethAddressString[0] == '\0')) {
      FD_SET(FLAG_BROADCAST_HOST, &el->flags); /* Just to be safe */
      releaseAddrResMutex();
      if(mode == FLAG_HOSTLINK_HTML_FORMAT) 
        return("<TH "TH_BG" ALIGN=LEFT>&lt;broadcast&gt;</TH>");
      else
        return("&lt;broadcast&gt;");
    }
    if(cmpSerial(&el->hostSerial, &myGlobals.otherHostEntry->hostSerial)) {
      releaseAddrResMutex();
      if(mode == FLAG_HOSTLINK_HTML_FORMAT) 
        return("<TH "TH_BG" ALIGN=LEFT>&lt;other&gt;<!-- cmpSerial() match --></TH>");
      else
        return("&lt;other&gt;<!-- cmpSerial() match -->");
    }

    /* User other names if we have them, but follow (High->Low) the numerical
     * sequence of FLAG_HOST_SYM_ADDR_TYPE_xxx so it still sorts right
     */ 
    if(el->hostNumIpAddress[0] != '\0') {
      /* We have the IP, so the DNS is probably still getting the entry name */
      strncpy(symIp, el->hostNumIpAddress, sizeof(symIp));
#ifndef CMPFCTN_DEBUG
      if(myGlobals.runningPref.debugMode == 1)
#endif
        safe_snprintf(__FILE__, __LINE__, noteBufAppend, sizeof(noteBufAppend), "<!-- NONE:NumIpAddr(%s) -->",
                    el->hostNumIpAddress);
        strncat(noteBuf, noteBufAppend, (sizeof(noteBuf) - strlen(noteBuf) - 1));
    } else if(el->ethAddressString[0] != '\0') {
      /* Use the MAC address */
      strncpy(symIp, el->ethAddressString, sizeof(symIp));
      usedEthAddress = 1;
#ifndef CMPFCTN_DEBUG
      if(myGlobals.runningPref.debugMode == 1)
#endif
        safe_snprintf(__FILE__, __LINE__, noteBufAppend, sizeof(noteBufAppend), "<!-- NONE:MAC(%s) -->",
                    el->ethAddressString);
        strncat(noteBuf, noteBufAppend, (sizeof(noteBuf) - strlen(noteBuf) - 1));
    } else if(el->fcCounters->hostNumFcAddress[0] != '\0') {
      strncpy(symIp, el->fcCounters->hostNumFcAddress, sizeof(symIp));
#ifndef CMPFCTN_DEBUG
      if(myGlobals.runningPref.debugMode == 1)
#endif
        safe_snprintf(__FILE__, __LINE__, noteBufAppend, sizeof(noteBufAppend), "<!-- NONE:FC(%s) -->",
                    el->fcCounters->hostNumFcAddress);
        strncat(noteBuf, noteBufAppend, (sizeof(noteBuf) - strlen(noteBuf) - 1));
    } else if(el->nonIPTraffic) {    
      if(el->nonIPTraffic->nbHostName != NULL) {
        strncpy(symIp, el->nonIPTraffic->nbHostName, sizeof(symIp));
        strncat(noteBuf, " [NetBios]", (sizeof(noteBuf) - strlen(noteBuf) - 1));
      } else if(el->nonIPTraffic->ipxHostName != NULL) {
        strncpy(symIp, el->nonIPTraffic->ipxHostName, sizeof(symIp));
        strncat(noteBuf, " [IPX]", (sizeof(noteBuf) - strlen(noteBuf) - 1));
      } else if(el->nonIPTraffic->atNodeName != NULL) {
        strncpy(symIp, el->nonIPTraffic->atNodeName, sizeof(symIp));
        strncat(noteBuf, " [Appletalk]", (sizeof(noteBuf) - strlen(noteBuf) - 1));
      }
    } else {
      releaseAddrResMutex();
      if(mode == FLAG_HOSTLINK_HTML_FORMAT) 
        return("<TH "TH_BG" ALIGN=LEFT>&lt;unknown&gt;</TH>");
      else
        return("&lt;unknown&gt;");
    }
  } else {
    /* Got it? Use it! */
    strncpy(symIp, el->hostResolvedName, sizeof(symIp));
    strncpy(linkName, el->hostNumIpAddress, sizeof(linkName));
    if(el->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_NETBIOS) {
        strncat(noteBuf, " [NetBIOS]", (sizeof(noteBuf) - strlen(noteBuf) - 1));
    }
#ifndef CMPFCTN_DEBUG
    if(myGlobals.runningPref.debugMode == 1) 
#endif
      switch (el->hostResolvedNameType) {
        case FLAG_HOST_SYM_ADDR_TYPE_FCID:
        case FLAG_HOST_SYM_ADDR_TYPE_FC_WWN:
        case FLAG_HOST_SYM_ADDR_TYPE_FC_ALIAS:  
          strncat(noteBuf, " [FibreChannel]", (sizeof(noteBuf) - strlen(noteBuf) - 1));
          break;
        case FLAG_HOST_SYM_ADDR_TYPE_MAC:
          strncat(noteBuf, " [MAC]", (sizeof(noteBuf) - strlen(noteBuf) - 1));
          break;
        case FLAG_HOST_SYM_ADDR_TYPE_IPX:
          strncat(noteBuf, " [IPX]", (sizeof(noteBuf) - strlen(noteBuf) - 1));
          break;
        case FLAG_HOST_SYM_ADDR_TYPE_IP:
          strncat(noteBuf, " [IP]", (sizeof(noteBuf) - strlen(noteBuf) - 1));
          break;
        case FLAG_HOST_SYM_ADDR_TYPE_ATALK:
          strncat(noteBuf, " [Appletalk]", (sizeof(noteBuf) - strlen(noteBuf) - 1));
          break;
        case FLAG_HOST_SYM_ADDR_TYPE_NETBIOS:
          /* Do nothing - handled in open code above */
          break;
        case FLAG_HOST_SYM_ADDR_TYPE_NAME:
          break;
      }
 
    if((el->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_NAME) &&
       (el->ethAddressString[0] != '\0')) {
      strncpy(linkName, addrtostr(&(el->hostIpAddress)), sizeof(linkName));
    }
    if((el->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_MAC) && 
       (symIp[2] != ':') &&
       (el->ethAddressString[0] != '\0')) {
      /* MAC address, one which has already been fixed up with the vendor string -
         set the alt tag */
      safe_snprintf(__FILE__, __LINE__, titleBuf, sizeof(titleBuf), "%s Actual MAC address is %s",
               titleBuf, el->ethAddressString);
      /* Un 'fix' the linkName so it goes back to the native page */
      strncpy(linkName, el->ethAddressString, sizeof(linkName));
    }
  }

  /* We know this is wasted effort if this is a fork()ed child,
   * so that routine will not do the update */
  setHostFingerprint(el);

  /* From here on, we focus on setting a bunch of flags and add-ons to the
   * output (graphics, etc.) for the ultimate building of buf.
   *
   *  These are:
   *
   *     linkName - what do we link to
   *     usedEthAddress - meaning it's a MAC address, show the NIC icon
   *     symIp - what do we call it
   *     dhcpBootpStr, multihomedStr, gwStr, brStr, dnsStr, printStr, 
   *       smtpStr, httpStr, ntpStr, healthStr, userStr, p2pStr -- these are all the addons
   */

  if(symIp[strlen(symIp)-1] == ']') /* "... [MAC]" */ {
    usedEthAddress = 1;
    strncpy(symIp, el->ethAddressString, sizeof(symIp));
    safe_snprintf(__FILE__, __LINE__, noteBuf, sizeof(noteBuf), "%s<!-- [MAC] -->", noteBuf);
  }

  /* Do we add a 2nd column for the flag??? */
  if(addCountryFlag == 0)
    flag[0] = '\0';
  else {
    safe_snprintf(__FILE__, __LINE__, flag, sizeof(flag), "<td "TD_BG" align=\"center\">%s</td>",
                getHostCountryIconURL(el));
  }

  /* Set all the addon Str's */
  if(isDHCPClient(el))
    dhcpBootpStr = "&nbsp;" CONST_IMG_DHCP_CLIENT "&nbsp;";
  else {
    if(isDHCPServer(el))
      dhcpBootpStr = "&nbsp;" CONST_IMG_DHCP_SERVER "&nbsp;";
    else
      dhcpBootpStr = "";
  }

  if(isMultihomed(el))     multihomedStr = "&nbsp;" CONST_IMG_MULTIHOMED ; else multihomedStr = "";
  if(isBridgeHost(el))     brStr = "&nbsp;" CONST_IMG_BRIDGE ; else brStr = "";
  if(gatewayHost(el))      gwStr = "&nbsp;" CONST_IMG_ROUTER ; else gwStr = "";
  if(nameServerHost(el))   dnsStr = "&nbsp;" CONST_IMG_DNS_SERVER ; else dnsStr = "";
  if(isPrinter(el))        printStr = "&nbsp;" CONST_IMG_PRINTER ; else printStr = "";
  if(isSMTPhost(el))       smtpStr = "&nbsp;" CONST_IMG_SMTP_SERVER ; else smtpStr = "";
  if(isHTTPhost(el))       httpStr = "&nbsp;" CONST_IMG_HTTP_SERVER ; else httpStr = "";
  if(isNtpServer(el))      ntpStr = "&nbsp;" CONST_IMG_NTP_SERVER ; else ntpStr = "";
  if(el->protocolInfo != NULL) {
    if(el->protocolInfo->userList != NULL) userStr = "&nbsp;" CONST_IMG_HAS_USERS ; else userStr = "";
    if(isP2P(el)) p2pStr = "&nbsp;" CONST_IMG_HAS_P2P ; else p2pStr = "";
  } else {
    userStr = "";
    p2pStr = "";
  }

  switch(isHostHealthy(el)) {
    case 1: /* Minor */
      healthStr = CONST_IMG_LOW_RISK;
      break;
    case 2: /* Warning */
      healthStr = CONST_IMG_MEDIUM_RISK;
      break;
    case 3: /* Error */
      healthStr = CONST_IMG_HIGH_RISK;
      break;
    default: /* OK, bad call */
      healthStr = "";
      break;
  }

  releaseAddrResMutex();

  /* Flag set? Cutoff name at 1st . */
  if(cutName &&
     (symIp[0] != '*') &&
     strcmp(symIp, el->hostNumIpAddress)) {
    for(i=0; symIp[i] != '\0'; i++)
      if(symIp[i] == '.') {
        symIp[i] = '\0';
        break;
      }
  }

  /* If we haven't previously set linkName as part of an un-fixup, save off 
   * symIP - before the remaining 'fixups' as the linkname */
  if(linkName[0] == '\0') {
    strncpy(linkName, symIp, sizeof(linkName));
  }

  if(linkName[0] == '\0') {
    safe_snprintf(__FILE__, __LINE__, noteBuf, sizeof(noteBuf), "%s<!-- EmptyLink -->", noteBuf);
  }

  /* Fixup ethernet addresses for RFC1945 compliance (: is bad, _ is good) */
  for(i=0; linkName[i] != '\0'; i++)
    if(linkName[i] == ':')
      linkName[i] = '_';

  /* Fixup display MAC address for vendor */
  if(usedEthAddress) {
    char *vendorInfo;

    vendorInfo = getVendorInfo(el->ethAddress, 0);
    if(vendorInfo[0] != '\0') {
      safe_snprintf(__FILE__, __LINE__, symIp, sizeof(symIp), "%s%s", vendorInfo, &el->ethAddressString[8]);
      safe_snprintf(__FILE__, __LINE__, titleBuf, sizeof(titleBuf),
                  "%s Actual MAC address is %s",
                  titleBuf, el->ethAddressString);
    }
  }    

  /* An Ethernet address is used - is it Special? */
  if(symIp[2] == ':') {
    char *symEthName = getSpecialMacInfo(el, (short)(!myGlobals.separator[0]));  
    if((symEthName != NULL) && (symEthName[0] != '\0'))
      safe_snprintf(__FILE__, __LINE__, symIp, sizeof(symIp), "%s%s", symEthName, &el->ethAddressString[8]);
    usedEthAddress = 1;
  }

  if(el->vlanId > 0) {
    char tmp[256];

    safe_snprintf(__FILE__, __LINE__, vlanStr, sizeof(vlanStr), "-%d", el->vlanId);
    safe_snprintf(__FILE__, __LINE__, tmp, sizeof(tmp), "%s (vlan %d)", symIp, el->vlanId);
    safe_snprintf(__FILE__, __LINE__, symIp, sizeof(symIp), "%s", tmp);
  } else {
    vlanStr[0] = '\0';
  }

  /* Make the hostlink */
  if(mode == FLAG_HOSTLINK_HTML_FORMAT) {
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<th "TH_BG" align=\"left\" nowrap width=\"250\">\n"
		"<a href=\"/%s%s.html\" %s%s%s>%s%s</a>\n"
                "%s%s%s%s%s%s%s%s%s%s%s%s%s%s</th>%s\n",
                linkName, vlanStr,
                titleBuf[0] != '\0' ? "title=\"" : "", titleBuf, titleBuf[0] != '\0' ? "\"" : "",
                symIp, 
		noteBuf,
		getOSFlag(el, NULL, 0, osBuf, sizeof(osBuf)),
                dhcpBootpStr, multihomedStr, 
		usedEthAddress ? CONST_IMG_NIC_CARD : "", 
		gwStr, brStr, dnsStr, 
                printStr, smtpStr, httpStr, ntpStr, healthStr, userStr, p2pStr, flag);
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<a href=\"/%s%s.html\" %s nowrap width=\"250\" %s%s%s>%s%s</a>\n"
                "%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
                linkName, vlanStr,
		makeHostAgeStyleSpec(el, colorSpec, sizeof(colorSpec)), 
                titleBuf[0] != '\0' ? "title=\"" : "", titleBuf, titleBuf[0] != '\0' ? "\"" : "",
                symIp, 
		noteBuf,
		dhcpBootpStr, multihomedStr, 
		usedEthAddress ? CONST_IMG_NIC_CARD : "",
		gwStr, brStr, dnsStr, 
		printStr, smtpStr, httpStr, ntpStr, healthStr, userStr, p2pStr, flag);
  }

  return(buf);
}

/* ******************************* */

char* getHostName(HostTraffic *el, short cutName, char *buf, int bufLen) {
  char *tmpStr;

  if(broadcastHost(el))
    return("broadcast");

  accessAddrResMutex("getHostName");
  tmpStr = el->hostResolvedName;

  if (el->l2Family == FLAG_HOST_TRAFFIC_AF_FC) {
      strncpy (buf, el->hostResolvedName, 80);
  }
  else {
      if(broadcastHost(el)) {
          strcpy (buf, "broadcast");
      }
      else {
          tmpStr = el->hostResolvedName;

          if((tmpStr == NULL) || (tmpStr[0] == '\0')) {
              /* The DNS is still getting the entry name */
              if(el->hostNumIpAddress[0] != '\0')
                  strncpy(buf, el->hostNumIpAddress, 80);
              else
                  strncpy(buf, el->ethAddressString, 80);
          } else if(tmpStr[0] != '\0') {
              strncpy(buf, tmpStr, 80);
              if(cutName) {
                  int i;
                  
                  for(i=0; buf[i] != '\0'; i++)
                      if((buf[i] == '.')
                         && (!(isdigit(buf[i-1])
                               && isdigit(buf[i+1]))
                             )) {
                          buf[i] = '\0';
                          break;
                      }
              }
          } else
              strncpy(buf, el->ethAddressString, 80);
      }
  }

  releaseAddrResMutex();
  return(buf);
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
  char path[256], *img, *source;
  static char flagBuf[384];
  struct stat buf;
  int rc;

  fillDomainName(el);

  if((el->ip2ccValue != NULL) && (strcasecmp(el->ip2ccValue, "loc") == 0)) {
    return("Local<!-- RFC1918 -->");
  }

  /* Try all the possible combos of name and path */
  rc = -1; /* Start bad */

  if(el->ip2ccValue != NULL) {
    if(rc != 0) {
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "./html/statsicons/flags/%s.gif",
                  el->ip2ccValue);
      rc = stat(path, &buf);
    }
    if(rc != 0) {
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/html/statsicons/flags/%s.gif",
                  CFG_DATAFILE_DIR, el->ip2ccValue);
      rc = stat(path, &buf);
    }
    if(rc == 0) { 
      img = el->ip2ccValue;
      source = "(from p2c file)";
    }
  }

  if(rc != 0) {
    if(el->dnsTLDValue != NULL) {
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "./html/statsicons/flags/%s.gif",
                  el->dnsTLDValue);
      rc = stat(path, &buf);
  
      if(rc != 0) {
        safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/html/statsicons/flags/%s.gif",
                    CFG_DATAFILE_DIR, el->dnsTLDValue);
        rc = stat(path, &buf);
      }
      if(rc == 0) {
        img = el->dnsTLDValue;
        if(strlen(img) == 2) 
          source = "(Guessing from ccTLD)";
        else
          source = "(Guessing from gTLD)";
      }
    }
  }

  if(rc != 0) {
    /* Nothing worked... */
    safe_snprintf(__FILE__, __LINE__, flagBuf, sizeof(flagBuf), "&nbsp;<!-- No flag for %s or %s -->",
                el->ip2ccValue != NULL  ? el->ip2ccValue  : "null",
                el->dnsTLDValue != NULL ? el->dnsTLDValue : "null");
  } else {
    safe_snprintf(__FILE__, __LINE__, flagBuf, sizeof(flagBuf),
                "<img alt=\"Flag for %s code %s %s\" align=\"middle\" "
                "src=\"/statsicons/flags/%s.gif\" border=\"0\">",
                strlen(img) == 2 ? "ISO 3166" : "gTLD",
                img,
                source,
                img);
  }

  return(flagBuf);
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

  printHTMLheader("Network Interface Switch", NULL, BITFLAG_HTML_NO_REFRESH);
  sendString("<HR>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<p><font face=\"Helvetica, Arial, Sans Serif\">Note that "
	      "the NetFlow and sFlow plugins - if enabled - force -M to be set (i.e. "
	      "they disable interface merging).</font></p>\n");
  sendString(buf);

  sendString("<P>\n<FONT FACE=\"Helvetica, Arial, Sans Serif\"><B>\n");
  
  if(myGlobals.runningPref.mergeInterfaces) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Sorry, but you cannot switch among different interfaces "
                "unless the -M command line switch is specified at run time.");
    sendString(buf);
  } else if((mwInterface != -1) &&
	    ((mwInterface >= myGlobals.numDevices) || myGlobals.device[mwInterface].virtualDevice)) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Sorry, invalid interface selected.");
    sendString(buf);
  } else if(myGlobals.numDevices == 1) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Sorry, you are currently capturing traffic from only a "
		"single interface [%s].<br><br>"
                "</b> This interface switch feature is meaningful only when your ntop "
                "instance captures traffic from multiple interfaces. You must specify "
                "additional interfaces via the -i command line switch at run time.<b>",
		myGlobals.device[myGlobals.actualReportDeviceId].name);
    sendString(buf);
  } else if(mwInterface >= 0) {
    char value[8];
    
    myGlobals.actualReportDeviceId = (mwInterface)%myGlobals.numDevices;
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "The current interface is now [%s].",
		myGlobals.device[myGlobals.actualReportDeviceId].name);
    sendString(buf);
    
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", myGlobals.actualReportDeviceId);
    storePrefsValue("actualReportDeviceId", value);
  } else {
    sendString("Available Network Interfaces:</B><P>\n<FORM ACTION=" CONST_SWITCH_NIC_HTML ">\n");

    for(i=0; i<myGlobals.numDevices; i++)
      if((!myGlobals.device[i].virtualDevice) && myGlobals.device[i].activeDevice) {
	if(myGlobals.actualReportDeviceId == i)
	  selected="CHECKED";
	else
	  selected = "";

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=interface VALUE=%d %s>&nbsp;%s<br>\n",
		    i+1, selected, myGlobals.device[i].humanFriendlyName);

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
  printHTMLheader("ntop is shutting down...", NULL, BITFLAG_HTML_NO_REFRESH);
  closeNwSocket(&myGlobals.newSock);
  termAccessLog();

  cleanup(0);
}

/* ******************************** */

static void printFeatureConfigNum(int textPrintFlag, char* feature, int value) {
  char tmpBuf[32];

  sendString(texthtml("", "<TR><TH "TH_BG" ALIGN=\"left\" width=\"250\">"));
  sendString(feature);
  sendString(texthtml(".....", "</TH><TD "TD_BG" ALIGN=\"right\">"));
  safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%d", value);
  sendString(tmpBuf);
  sendString(texthtml("\n", "</TD></TR>\n"));
}

static void printFeatureConfigInfo(int textPrintFlag, char* feature, char* status) {
  char *tmpStr, tmpBuf[LEN_GENERAL_WORK_BUFFER];
  char *strtokState;

  sendString(texthtml("", "<TR><TH "TH_BG" ALIGN=\"left\" width=\"250\">"));
  sendString(feature);
  sendString(texthtml(".....", "</TH><TD "TD_BG" ALIGN=\"right\">"));
  if((status == NULL) || (status[0] == '\0')) {
    sendString("(nil)");
  } else {
    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%s", status);
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

static void printFeatureConfigInfo3ColInt(int textPrintFlag, 
                                          char* feature, 
                                          int flag1, int count1, 
                                          int flag2, int count2,
                                          int mustShow) {
  char tmpBuf[LEN_GENERAL_WORK_BUFFER];

  if((mustShow == FALSE) && (count1+count2 == 0)) { return; }

  sendString(texthtml("", "<TR><TH "TH_BG" ALIGN=\"left\" width=\"300\">"));
  sendString(feature);
  sendString(texthtml(".....", "</TH><TD "TD_BG" ALIGN=\"right\">"));
  if (flag1) {
    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%d", count1);
    sendString(tmpBuf);
  } else {
    sendString("-");
  }
  sendString(texthtml(".....", "</TD><TD "TD_BG" ALIGN=\"right\">"));
  if (flag2) {
    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%d", count2);
    sendString(tmpBuf);
  } else {
    sendString("-");
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
  if((status == NULL) ||(status[0] == '\0')) {
    sendString("(nil)");
  } else {
    sendString(status);
  }
  sendString(texthtml("\n", "</TD></TR>\n"));
}

/* ******************************** */

void printNtopConfigHInfo(int textPrintFlag) {
#ifndef WIN32
  char buf[LEN_GENERAL_WORK_BUFFER];
#endif

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

  printFeatureConfigInfo(textPrintFlag, "CHKVER_DEBUG",
#ifdef CHKVER_DEBUG
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "CMPFCTN_DEBUG",
#ifdef CMPFCTN_DEBUG
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

  printFeatureConfigInfo(textPrintFlag, "FC_DEBUG",
#ifdef FC_DEBUG
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "FINGERPRINT_DEBUG",
#ifdef FINGERPRINT_DEBUG
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "FRAGMENT_DEBUG",
#ifdef FRAGMENT_DEBUG
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

  printFeatureConfigInfo(textPrintFlag, "I18N_DEBUG",
#ifdef I18N_DEBUG
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

  printFeatureConfigInfo(textPrintFlag, "P2P_DEBUG",
#ifdef P2P_DEBUG
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "PACKET_DEBUG",
#ifdef PACKET_DEBUG
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "PARAM_DEBUG",
#ifdef PARAM_DEBUG
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "PLUGIN_DEBUG",
#ifdef PLUGIN_DEBUG
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "PROBLEMREPORTID_DEBUG",
#ifdef PROBLEMREPORTID_DEBUG
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "RRD_DEBUG",
#ifdef RRD_DEBUG
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

  printFeatureConfigInfo(textPrintFlag, "SSLWATCHDOG_DEBUG",
#ifdef SSLWATCHDOG_DEBUG
                         "yes"
#else
                         "no"
#endif
                         );

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

  printFeatureConfigInfo(textPrintFlag, "URL_DEBUG",
#ifdef URL_DEBUG
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "VENDOR_DEBUG",
#ifdef VENDOR_DEBUG
                         "yes"
#else
                         "no"
#endif
                         );

  sendString(texthtml("\n\nCompile Time: config.h\n\n",
                      "<tr><th colspan=\"2\"" TH_BG ">Compile Time: config.h</tr>\n"));

  /*
   * Drop the autogenerated lines (utils/config_h2.awk) in HERE 
   */


  /*                                                       B E G I N
   *
   * Autogenerated from config.h.in and inserted into webInterface.c 
   *      Sun Mar 21 07:25:51 CST 2004
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

  printFeatureConfigInfo(textPrintFlag, "CFG_NEED_INET_ATON",
#ifdef CFG_NEED_INET_ATON
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_ARPA_INET_H",
#ifdef HAVE_ARPA_INET_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_CRYPTGETFORMAT",
#ifdef HAVE_CRYPTGETFORMAT
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_CRYPT_H",
#ifdef HAVE_CRYPT_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_DIRENT_H",
#ifdef HAVE_DIRENT_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_FLOAT_H",
#ifdef HAVE_FLOAT_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_GETOPT_H",
#ifdef HAVE_GETOPT_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_ICMP6_H",
#ifdef HAVE_ICMP6_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_IFLIST_SYSCTL",
#ifdef HAVE_IFLIST_SYSCTL
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_INET_NTOA",
#ifdef HAVE_INET_NTOA
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_IP6_H",
#ifdef HAVE_IP6_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_LIBC_R",
#ifdef HAVE_LIBC_R
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_MALLINFO_MALLOC_H",
#ifdef HAVE_MALLINFO_MALLOC_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_MALLOC_H",
#ifdef HAVE_MALLOC_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_NET_BPF_H",
#ifdef HAVE_NET_BPF_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_NET_ETHERNET_H",
#ifdef HAVE_NET_ETHERNET_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NET_IF_DL_H",
#ifdef HAVE_NET_IF_DL_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NET_IF_H",
#ifdef HAVE_NET_IF_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NETINET_ICMP6_H",
#ifdef HAVE_NETINET_ICMP6_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NETINET_IF_ETHER_H",
#ifdef HAVE_NETINET_IF_ETHER_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NETINET_IN_H",
#ifdef HAVE_NETINET_IN_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NETINET_IN_SYSTM_H",
#ifdef HAVE_NETINET_IN_SYSTM_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NETINET_IP6_H",
#ifdef HAVE_NETINET_IP6_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NETINET_IP_H",
#ifdef HAVE_NETINET_IP_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NETINET_TCP_H",
#ifdef HAVE_NETINET_TCP_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NETINET_UDP_H",
#ifdef HAVE_NETINET_UDP_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NET_PPP_DEFS_H",
#ifdef HAVE_NET_PPP_DEFS_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_NET_ROUTE_H",
#ifdef HAVE_NET_ROUTE_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_PCAP_BPF_H",
#ifdef HAVE_PCAP_BPF_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_PCAP_SETNONBLOCK",
#ifdef HAVE_PCAP_SETNONBLOCK
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_STAT_EMPTY_STRING_BUG",
#ifdef HAVE_STAT_EMPTY_STRING_BUG
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_STDINT_H",
#ifdef HAVE_STDINT_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRUCT_TM_TM_ZONE",
#ifdef HAVE_STRUCT_TM_TM_ZONE
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYSCTL",
#ifdef HAVE_SYSCTL
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYSLOG_H",
#ifdef HAVE_SYSLOG_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_PARAM_H",
#ifdef HAVE_SYS_PARAM_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_SELECT_H",
#ifdef HAVE_SYS_SELECT_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_SOCKET_H",
#ifdef HAVE_SYS_SOCKET_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_STAT_H",
#ifdef HAVE_SYS_STAT_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_SYSCTL_H",
#ifdef HAVE_SYS_SYSCTL_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_SYSLOG_H",
#ifdef HAVE_SYS_SYSLOG_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_UTSNAME_H",
#ifdef HAVE_SYS_UTSNAME_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SYS_WAIT_H",
#ifdef HAVE_SYS_WAIT_H
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

  printFeatureConfigInfo(textPrintFlag, "INET6",
#ifdef INET6
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "LSTAT_FOLLOWS_SLASHED_SYMLINK",
#ifdef LSTAT_FOLLOWS_SLASHED_SYMLINK
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_STATIC_PLUGIN",
#ifdef MAKE_STATIC_PLUGIN
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

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_ZLIB",
#ifdef MAKE_WITH_ZLIB
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

  printFeatureConfigInfo(textPrintFlag, "STDC_HEADERS",
#ifdef STDC_HEADERS
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
   * Autogenerated from config.h.in and inserted into webInterface.c 
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
   *      Sun Mar 21 07:25:51 CST 2004
   *
   */

#ifdef CONST_ACTIVE_TCP_SESSIONS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_ACTIVE_TCP_SESSIONS_HTML", CONST_ACTIVE_TCP_SESSIONS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_ACTIVE_TCP_SESSIONS_HTML", "undefined");
#endif

#ifdef CONST_ADD_URLS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_ADD_URLS_HTML", CONST_ADD_URLS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_ADD_URLS_HTML", "undefined");
#endif

#ifdef CONST_ADD_USERS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_ADD_USERS_HTML", CONST_ADD_USERS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_ADD_USERS_HTML", "undefined");
#endif

#ifdef CONST_APACHELOG_TIMESPEC
  printFeatureConfigInfo(textPrintFlag, "CONST_APACHELOG_TIMESPEC", CONST_APACHELOG_TIMESPEC);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_APACHELOG_TIMESPEC", "undefined");
#endif

#ifdef CONST_ASLIST_FILE
  printFeatureConfigInfo(textPrintFlag, "CONST_ASLIST_FILE", CONST_ASLIST_FILE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_ASLIST_FILE", "undefined");
#endif

#ifdef CONST_AS_LIST_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_AS_LIST_HTML", CONST_AS_LIST_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_AS_LIST_HTML", "undefined");
#endif

#ifdef CONST_BAR_ALLPROTO_DIST
  printFeatureConfigInfo(textPrintFlag, "CONST_BAR_ALLPROTO_DIST", CONST_BAR_ALLPROTO_DIST);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_BAR_ALLPROTO_DIST", "undefined");
#endif

#ifdef CONST_BAR_FC_PROTO_DIST
  printFeatureConfigInfo(textPrintFlag, "CONST_BAR_FC_PROTO_DIST", CONST_BAR_FC_PROTO_DIST);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_BAR_FC_PROTO_DIST", "undefined");
#endif

#ifdef CONST_BAR_HOST_DISTANCE
  printFeatureConfigInfo(textPrintFlag, "CONST_BAR_HOST_DISTANCE", CONST_BAR_HOST_DISTANCE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_BAR_HOST_DISTANCE", "undefined");
#endif

#ifdef CONST_BAR_LUNSTATS_DIST
  printFeatureConfigInfo(textPrintFlag, "CONST_BAR_LUNSTATS_DIST", CONST_BAR_LUNSTATS_DIST);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_BAR_LUNSTATS_DIST", "undefined");
#endif

#ifdef CONST_BAR_VSAN_TRAF_DIST_RCVD
  printFeatureConfigInfo(textPrintFlag, "CONST_BAR_VSAN_TRAF_DIST_RCVD", CONST_BAR_VSAN_TRAF_DIST_RCVD);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_BAR_VSAN_TRAF_DIST_RCVD", "undefined");
#endif

#ifdef CONST_BAR_VSAN_TRAF_DIST_SENT
  printFeatureConfigInfo(textPrintFlag, "CONST_BAR_VSAN_TRAF_DIST_SENT", CONST_BAR_VSAN_TRAF_DIST_SENT);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_BAR_VSAN_TRAF_DIST_SENT", "undefined");
#endif

#ifdef CONST_BROADCAST_ENTRY
  printFeatureConfigNum(textPrintFlag, "CONST_BROADCAST_ENTRY", CONST_BROADCAST_ENTRY);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_BROADCAST_ENTRY", "undefined");
#endif

#ifdef CONST_CGI_HEADER
  printFeatureConfigInfo(textPrintFlag, "CONST_CGI_HEADER", CONST_CGI_HEADER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_CGI_HEADER", "undefined");
#endif

#ifdef CONST_CHANGE_FILTER_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_CHANGE_FILTER_HTML", CONST_CHANGE_FILTER_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_CHANGE_FILTER_HTML", "undefined");
#endif

#ifdef CONST_COLOR_1
  printFeatureConfigInfo(textPrintFlag, "CONST_COLOR_1", CONST_COLOR_1);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_COLOR_1", "undefined");
#endif

#ifdef CONST_COLOR_2
  printFeatureConfigInfo(textPrintFlag, "CONST_COLOR_2", CONST_COLOR_2);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_COLOR_2", "undefined");
#endif

#ifdef CONST_CONST_PCTG_LOW_COLOR
  printFeatureConfigInfo(textPrintFlag, "CONST_CONST_PCTG_LOW_COLOR", CONST_CONST_PCTG_LOW_COLOR);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_CONST_PCTG_LOW_COLOR", "undefined");
#endif

#ifdef CONST_CONST_PCTG_MID_COLOR
  printFeatureConfigInfo(textPrintFlag, "CONST_CONST_PCTG_MID_COLOR", CONST_CONST_PCTG_MID_COLOR);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_CONST_PCTG_MID_COLOR", "undefined");
#endif

#ifdef CONST_CREDITS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_CREDITS_HTML", CONST_CREDITS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_CREDITS_HTML", "undefined");
#endif

#ifdef CONST_CRYPT_SALT
  printFeatureConfigInfo(textPrintFlag, "CONST_CRYPT_SALT", CONST_CRYPT_SALT);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_CRYPT_SALT", "undefined");
#endif

#ifdef CONST_DAEMONNAME
  printFeatureConfigInfo(textPrintFlag, "CONST_DAEMONNAME", CONST_DAEMONNAME);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DAEMONNAME", "undefined");
#endif

#ifdef CONST_DELETE_URL
  printFeatureConfigInfo(textPrintFlag, "CONST_DELETE_URL", CONST_DELETE_URL);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DELETE_URL", "undefined");
#endif

#ifdef CONST_DELETE_USER
  printFeatureConfigInfo(textPrintFlag, "CONST_DELETE_USER", CONST_DELETE_USER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DELETE_USER", "undefined");
#endif

#ifdef CONST_DNSCACHE_LIFETIME
  printFeatureConfigNum(textPrintFlag, "CONST_DNSCACHE_LIFETIME", CONST_DNSCACHE_LIFETIME);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DNSCACHE_LIFETIME", "undefined");
#endif

#ifdef CONST_DNSCACHE_PERMITTED_AGE
  printFeatureConfigNum(textPrintFlag, "CONST_DNSCACHE_PERMITTED_AGE", CONST_DNSCACHE_PERMITTED_AGE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DNSCACHE_PERMITTED_AGE", "undefined");
#endif

#ifdef CONST_DO_ADD_URL
  printFeatureConfigInfo(textPrintFlag, "CONST_DO_ADD_URL", CONST_DO_ADD_URL);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DO_ADD_URL", "undefined");
#endif

#ifdef CONST_DO_ADD_USER
  printFeatureConfigInfo(textPrintFlag, "CONST_DO_ADD_USER", CONST_DO_ADD_USER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DO_ADD_USER", "undefined");
#endif

#ifdef CONST_DO_CHANGE_FILTER
  printFeatureConfigInfo(textPrintFlag, "CONST_DO_CHANGE_FILTER", CONST_DO_CHANGE_FILTER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DO_CHANGE_FILTER", "undefined");
#endif

#ifdef CONST_DOMAIN_STATS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_DOMAIN_STATS_HTML", CONST_DOMAIN_STATS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DOMAIN_STATS_HTML", "undefined");
#endif

#ifdef CONST_DOUBLE_TWO_MSL_TIMEOUT
  printFeatureConfigNum(textPrintFlag, "CONST_DOUBLE_TWO_MSL_TIMEOUT", CONST_DOUBLE_TWO_MSL_TIMEOUT);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DOUBLE_TWO_MSL_TIMEOUT", "undefined");
#endif

#ifdef CONST_DUMP_DATA_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_DUMP_DATA_HTML", CONST_DUMP_DATA_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DUMP_DATA_HTML", "undefined");
#endif

#ifdef CONST_DUMP_HOSTS_INDEXES_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_DUMP_HOSTS_INDEXES_HTML", CONST_DUMP_HOSTS_INDEXES_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DUMP_HOSTS_INDEXES_HTML", "undefined");
#endif

#ifdef CONST_DUMP_NTOP_FLOWS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_DUMP_NTOP_FLOWS_HTML", CONST_DUMP_NTOP_FLOWS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DUMP_NTOP_FLOWS_HTML", "undefined");
#endif

#ifdef CONST_DUMP_NTOP_HOSTS_MATRIX_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_DUMP_NTOP_HOSTS_MATRIX_HTML", CONST_DUMP_NTOP_HOSTS_MATRIX_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DUMP_NTOP_HOSTS_MATRIX_HTML", "undefined");
#endif

#ifdef CONST_DUMP_NTOP_XML
  printFeatureConfigInfo(textPrintFlag, "CONST_DUMP_NTOP_XML", CONST_DUMP_NTOP_XML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DUMP_NTOP_XML", "undefined");
#endif

#ifdef CONST_DUMP_TRAFFIC_DATA_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_DUMP_TRAFFIC_DATA_HTML", CONST_DUMP_TRAFFIC_DATA_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_DUMP_TRAFFIC_DATA_HTML", "undefined");
#endif

#ifdef CONST_FAVICON_ICO
  printFeatureConfigInfo(textPrintFlag, "CONST_FAVICON_ICO", CONST_FAVICON_ICO);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_FAVICON_ICO", "undefined");
#endif

#ifdef CONST_FC_ACTIVITY_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_FC_ACTIVITY_HTML", CONST_FC_ACTIVITY_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_FC_ACTIVITY_HTML", "undefined");
#endif

#ifdef CONST_FC_DATA_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_FC_DATA_HTML", CONST_FC_DATA_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_FC_DATA_HTML", "undefined");
#endif

#ifdef CONST_FC_HOSTS_INFO_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_FC_HOSTS_INFO_HTML", CONST_FC_HOSTS_INFO_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_FC_HOSTS_INFO_HTML", "undefined");
#endif

#ifdef CONST_FC_SESSIONS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_FC_SESSIONS_HTML", CONST_FC_SESSIONS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_FC_SESSIONS_HTML", "undefined");
#endif

#ifdef CONST_FC_THPT_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_FC_THPT_HTML", CONST_FC_THPT_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_FC_THPT_HTML", "undefined");
#endif

#ifdef CONST_FC_TRAFFIC_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_FC_TRAFFIC_HTML", CONST_FC_TRAFFIC_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_FC_TRAFFIC_HTML", "undefined");
#endif

#ifdef CONST_FILEDESCRIPTORBUG_COUNT
  printFeatureConfigNum(textPrintFlag, "CONST_FILEDESCRIPTORBUG_COUNT", CONST_FILEDESCRIPTORBUG_COUNT);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_FILEDESCRIPTORBUG_COUNT", "undefined");
#endif

#ifdef CONST_FILTER_INFO_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_FILTER_INFO_HTML", CONST_FILTER_INFO_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_FILTER_INFO_HTML", "undefined");
#endif

#ifdef CONST_FINGERPRINT_LOOP_INTERVAL
  printFeatureConfigNum(textPrintFlag, "CONST_FINGERPRINT_LOOP_INTERVAL", CONST_FINGERPRINT_LOOP_INTERVAL);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_FINGERPRINT_LOOP_INTERVAL", "undefined");
#endif

#ifdef CONST_FTPDATA
  printFeatureConfigNum(textPrintFlag, "CONST_FTPDATA", CONST_FTPDATA);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_FTPDATA", "undefined");
#endif

#ifdef CONST_GRE_PROTOCOL_TYPE
  printFeatureConfigNum(textPrintFlag, "CONST_GRE_PROTOCOL_TYPE", CONST_GRE_PROTOCOL_TYPE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_GRE_PROTOCOL_TYPE", "undefined");
#endif

#ifdef CONST_HANDLEADDRESSLISTS_MAIN
  printFeatureConfigNum(textPrintFlag, "CONST_HANDLEADDRESSLISTS_MAIN", CONST_HANDLEADDRESSLISTS_MAIN);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HANDLEADDRESSLISTS_MAIN", "undefined");
#endif

#ifdef CONST_HANDLEADDRESSLISTS_NETFLOW
  printFeatureConfigNum(textPrintFlag, "CONST_HANDLEADDRESSLISTS_NETFLOW", CONST_HANDLEADDRESSLISTS_NETFLOW);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HANDLEADDRESSLISTS_NETFLOW", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "CONST_HANDLEADDRESSLISTS_RRD",
#ifdef CONST_HANDLEADDRESSLISTS_RRD
                         "yes"
#else
                         "no"
#endif
                         );

#ifdef CONST_HASH_INITIAL_SIZE
  printFeatureConfigNum(textPrintFlag, "CONST_HASH_INITIAL_SIZE", CONST_HASH_INITIAL_SIZE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HASH_INITIAL_SIZE", "undefined");
#endif

#ifdef CONST_HOME_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_HOME_HTML", CONST_HOME_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HOME_HTML", "undefined");
#endif

#ifdef CONST_HOME_UNDERSCORE_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_HOME_UNDERSCORE_HTML", CONST_HOME_UNDERSCORE_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HOME_UNDERSCORE_HTML", "undefined");
#endif

#ifdef CONST_HOST_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_HOST_HTML", CONST_HOST_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HOST_HTML", "undefined");
#endif

#ifdef CONST_HOSTS_INFO_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_HOSTS_INFO_HTML", CONST_HOSTS_INFO_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HOSTS_INFO_HTML", "undefined");
#endif

#ifdef CONST_HOSTS_LOCAL_CHARACT_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_HOSTS_LOCAL_CHARACT_HTML", CONST_HOSTS_LOCAL_CHARACT_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HOSTS_LOCAL_CHARACT_HTML", "undefined");
#endif

#ifdef CONST_HOSTS_LOCAL_FINGERPRINT_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_HOSTS_LOCAL_FINGERPRINT_HTML", CONST_HOSTS_LOCAL_FINGERPRINT_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HOSTS_LOCAL_FINGERPRINT_HTML", "undefined");
#endif

#ifdef CONST_HOST_SORT_NOTE_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_HOST_SORT_NOTE_HTML", CONST_HOST_SORT_NOTE_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HOST_SORT_NOTE_HTML", "undefined");
#endif

#ifdef CONST_HOSTS_REMOTE_FINGERPRINT_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_HOSTS_REMOTE_FINGERPRINT_HTML", CONST_HOSTS_REMOTE_FINGERPRINT_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HOSTS_REMOTE_FINGERPRINT_HTML", "undefined");
#endif

#ifdef CONST_HTTP_ACCEPT_ALL
  printFeatureConfigInfo(textPrintFlag, "CONST_HTTP_ACCEPT_ALL", CONST_HTTP_ACCEPT_ALL);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HTTP_ACCEPT_ALL", "undefined");
#endif

#ifdef CONST_IMG_ARROW_DOWN
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_ARROW_DOWN", CONST_IMG_ARROW_DOWN);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_ARROW_DOWN", "undefined");
#endif

#ifdef CONST_IMG_ARROW_UP
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_ARROW_UP", CONST_IMG_ARROW_UP);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_ARROW_UP", "undefined");
#endif

#ifdef CONST_IMG_BRIDGE
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_BRIDGE", CONST_IMG_BRIDGE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_BRIDGE", "undefined");
#endif

#ifdef CONST_IMG_DHCP_CLIENT
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_DHCP_CLIENT", CONST_IMG_DHCP_CLIENT);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_DHCP_CLIENT", "undefined");
#endif

#ifdef CONST_IMG_DHCP_SERVER
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_DHCP_SERVER", CONST_IMG_DHCP_SERVER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_DHCP_SERVER", "undefined");
#endif

#ifdef CONST_IMG_DIRECTORY_SERVER
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_DIRECTORY_SERVER", CONST_IMG_DIRECTORY_SERVER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_DIRECTORY_SERVER", "undefined");
#endif

#ifdef CONST_IMG_DNS_SERVER
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_DNS_SERVER", CONST_IMG_DNS_SERVER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_DNS_SERVER", "undefined");
#endif

#ifdef CONST_IMG_FC_VEN_BROCADE
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FC_VEN_BROCADE", CONST_IMG_FC_VEN_BROCADE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FC_VEN_BROCADE", "undefined");
#endif

#ifdef CONST_IMG_FC_VEN_EMC
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FC_VEN_EMC", CONST_IMG_FC_VEN_EMC);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FC_VEN_EMC", "undefined");
#endif

#ifdef CONST_IMG_FC_VEN_EMULEX
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FC_VEN_EMULEX", CONST_IMG_FC_VEN_EMULEX);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FC_VEN_EMULEX", "undefined");
#endif

#ifdef CONST_IMG_FC_VEN_JNI
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FC_VEN_JNI", CONST_IMG_FC_VEN_JNI);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FC_VEN_JNI", "undefined");
#endif

#ifdef CONST_IMG_FC_VEN_SEAGATE
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FC_VEN_SEAGATE", CONST_IMG_FC_VEN_SEAGATE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FC_VEN_SEAGATE", "undefined");
#endif

#ifdef CONST_IMG_FIBRECHANNEL_SWITCH
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FIBRECHANNEL_SWITCH", CONST_IMG_FIBRECHANNEL_SWITCH);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FIBRECHANNEL_SWITCH", "undefined");
#endif

#ifdef CONST_IMG_FTP_SERVER
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FTP_SERVER", CONST_IMG_FTP_SERVER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FTP_SERVER", "undefined");
#endif

#ifdef CONST_IMG_HAS_P2P
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_HAS_P2P", CONST_IMG_HAS_P2P);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_HAS_P2P", "undefined");
#endif

#ifdef CONST_IMG_HAS_USERS
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_HAS_USERS", CONST_IMG_HAS_USERS);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_HAS_USERS", "undefined");
#endif

#ifdef CONST_IMG_HIGH_RISK
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_HIGH_RISK", CONST_IMG_HIGH_RISK);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_HIGH_RISK", "undefined");
#endif

#ifdef CONST_IMG_HTTP_SERVER
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_HTTP_SERVER", CONST_IMG_HTTP_SERVER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_HTTP_SERVER", "undefined");
#endif

#ifdef CONST_IMG_IMAP_SERVER
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_IMAP_SERVER", CONST_IMG_IMAP_SERVER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_IMAP_SERVER", "undefined");
#endif

#ifdef CONST_IMG_LOCK
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_LOCK", CONST_IMG_LOCK);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_LOCK", "undefined");
#endif

#ifdef CONST_IMG_LOW_RISK
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_LOW_RISK", CONST_IMG_LOW_RISK);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_LOW_RISK", "undefined");
#endif

#ifdef CONST_IMG_MEDIUM_RISK
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_MEDIUM_RISK", CONST_IMG_MEDIUM_RISK);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_MEDIUM_RISK", "undefined");
#endif

#ifdef CONST_IMG_MULTIHOMED
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_MULTIHOMED", CONST_IMG_MULTIHOMED);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_MULTIHOMED", "undefined");
#endif

#ifdef CONST_IMG_NIC_CARD
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_NIC_CARD", CONST_IMG_NIC_CARD);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_NIC_CARD", "undefined");
#endif

#ifdef CONST_IMG_NTP_SERVER
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_NTP_SERVER", CONST_IMG_NTP_SERVER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_NTP_SERVER", "undefined");
#endif

#ifdef CONST_IMG_OS_AIX
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_AIX", CONST_IMG_OS_AIX);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_AIX", "undefined");
#endif

#ifdef CONST_IMG_OS_BERKELEY
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_BERKELEY", CONST_IMG_OS_BERKELEY);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_BERKELEY", "undefined");
#endif

#ifdef CONST_IMG_OS_BSD
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_BSD", CONST_IMG_OS_BSD);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_BSD", "undefined");
#endif

#ifdef CONST_IMG_OS_CISCO
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_CISCO", CONST_IMG_OS_CISCO);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_CISCO", "undefined");
#endif

#ifdef CONST_IMG_OS_HP_JETDIRET
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_HP_JETDIRET", CONST_IMG_OS_HP_JETDIRET);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_HP_JETDIRET", "undefined");
#endif

#ifdef CONST_IMG_OS_HP_UX
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_HP_UX", CONST_IMG_OS_HP_UX);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_HP_UX", "undefined");
#endif

#ifdef CONST_IMG_OS_IRIX
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_IRIX", CONST_IMG_OS_IRIX);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_IRIX", "undefined");
#endif

#ifdef CONST_IMG_OS_LINUX
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_LINUX", CONST_IMG_OS_LINUX);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_LINUX", "undefined");
#endif

#ifdef CONST_IMG_OS_MAC
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_MAC", CONST_IMG_OS_MAC);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_MAC", "undefined");
#endif

#ifdef CONST_IMG_OS_NOVELL
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_NOVELL", CONST_IMG_OS_NOVELL);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_NOVELL", "undefined");
#endif

#ifdef CONST_IMG_OS_SOLARIS
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_SOLARIS", CONST_IMG_OS_SOLARIS);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_SOLARIS", "undefined");
#endif

#ifdef CONST_IMG_OS_SUNOS
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_SUNOS", CONST_IMG_OS_SUNOS);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_SUNOS", "undefined");
#endif

#ifdef CONST_IMG_OS_UNIX
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_UNIX", CONST_IMG_OS_UNIX);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_UNIX", "undefined");
#endif

#ifdef CONST_IMG_OS_WINDOWS
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_WINDOWS", CONST_IMG_OS_WINDOWS);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_OS_WINDOWS", "undefined");
#endif

#ifdef CONST_IMG_POP_SERVER
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_POP_SERVER", CONST_IMG_POP_SERVER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_POP_SERVER", "undefined");
#endif

#ifdef CONST_IMG_PRINTER
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_PRINTER", CONST_IMG_PRINTER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_PRINTER", "undefined");
#endif

#ifdef CONST_IMG_ROUTER
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_ROUTER", CONST_IMG_ROUTER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_ROUTER", "undefined");
#endif

#ifdef CONST_IMG_SCSI_DISK
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_SCSI_DISK", CONST_IMG_SCSI_DISK);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_SCSI_DISK", "undefined");
#endif

#ifdef CONST_IMG_SCSI_INITIATOR
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_SCSI_INITIATOR", CONST_IMG_SCSI_INITIATOR);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_SCSI_INITIATOR", "undefined");
#endif

#ifdef CONST_IMG_SMTP_SERVER
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_SMTP_SERVER", CONST_IMG_SMTP_SERVER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_SMTP_SERVER", "undefined");
#endif

#ifdef CONST_INDEX_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_INDEX_HTML", CONST_INDEX_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_INDEX_HTML", "undefined");
#endif

#ifdef CONST_INFO_NTOP_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_INFO_NTOP_HTML", CONST_INFO_NTOP_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_INFO_NTOP_HTML", "undefined");
#endif

#ifdef CONST_INVALIDNETMASK
  printFeatureConfigNum(textPrintFlag, "CONST_INVALIDNETMASK", CONST_INVALIDNETMASK);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_INVALIDNETMASK", "undefined");
#endif

#ifdef CONST_IP_L_2_L_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_L_2_L_HTML", CONST_IP_L_2_L_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_L_2_L_HTML", "undefined");
#endif

#ifdef CONST_IP_L_2_R_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_L_2_R_HTML", CONST_IP_L_2_R_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_L_2_R_HTML", "undefined");
#endif

#ifdef CONST_IP_PROTO_DISTRIB_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_PROTO_DISTRIB_HTML", CONST_IP_PROTO_DISTRIB_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_PROTO_DISTRIB_HTML", "undefined");
#endif

#ifdef CONST_IP_PROTO_USAGE_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_PROTO_USAGE_HTML", CONST_IP_PROTO_USAGE_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_PROTO_USAGE_HTML", "undefined");
#endif

#ifdef CONST_IP_R_2_L_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_R_2_L_HTML", CONST_IP_R_2_L_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_R_2_L_HTML", "undefined");
#endif

#ifdef CONST_IP_R_2_R_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_R_2_R_HTML", CONST_IP_R_2_R_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_R_2_R_HTML", "undefined");
#endif

#ifdef CONST_IP_TRAFFIC_MATRIX_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_TRAFFIC_MATRIX_HTML", CONST_IP_TRAFFIC_MATRIX_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IP_TRAFFIC_MATRIX_HTML", "undefined");
#endif

#ifdef CONST_ISO8601_TIMESPEC
  printFeatureConfigInfo(textPrintFlag, "CONST_ISO8601_TIMESPEC", CONST_ISO8601_TIMESPEC);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_ISO8601_TIMESPEC", "undefined");
#endif

#ifdef CONST_LEFTMENU_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_LEFTMENU_HTML", CONST_LEFTMENU_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_LEFTMENU_HTML", "undefined");
#endif

#ifdef CONST_LEFTMENU_NOJS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_LEFTMENU_NOJS_HTML", CONST_LEFTMENU_NOJS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_LEFTMENU_NOJS_HTML", "undefined");
#endif

#ifdef CONST_LEGEND_BOX_SIZE
  printFeatureConfigNum(textPrintFlag, "CONST_LEGEND_BOX_SIZE", CONST_LEGEND_BOX_SIZE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_LEGEND_BOX_SIZE", "undefined");
#endif

#ifdef CONST_LIBGD_SO
  printFeatureConfigInfo(textPrintFlag, "CONST_LIBGD_SO", CONST_LIBGD_SO);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_LIBGD_SO", "undefined");
#endif

#ifdef CONST_LOCALE_TIMESPEC
  printFeatureConfigInfo(textPrintFlag, "CONST_LOCALE_TIMESPEC", CONST_LOCALE_TIMESPEC);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_LOCALE_TIMESPEC", "undefined");
#endif

#ifdef CONST_LOCAL_ROUTERS_LIST_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_LOCAL_ROUTERS_LIST_HTML", CONST_LOCAL_ROUTERS_LIST_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_LOCAL_ROUTERS_LIST_HTML", "undefined");
#endif

#ifdef CONST_LOG_VIEW_BUFFER_SIZE
  printFeatureConfigNum(textPrintFlag, "CONST_LOG_VIEW_BUFFER_SIZE", CONST_LOG_VIEW_BUFFER_SIZE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_LOG_VIEW_BUFFER_SIZE", "undefined");
#endif

#ifdef CONST_MAGIC_NUMBER
  printFeatureConfigNum(textPrintFlag, "CONST_MAGIC_NUMBER", CONST_MAGIC_NUMBER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MAGIC_NUMBER", "undefined");
#endif

#ifdef CONST_MAN_NTOP_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_MAN_NTOP_HTML", CONST_MAN_NTOP_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MAN_NTOP_HTML", "undefined");
#endif

#ifdef CONST_MODIFY_URL
  printFeatureConfigInfo(textPrintFlag, "CONST_MODIFY_URL", CONST_MODIFY_URL);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MODIFY_URL", "undefined");
#endif

#ifdef CONST_MODIFY_USERS
  printFeatureConfigInfo(textPrintFlag, "CONST_MODIFY_USERS", CONST_MODIFY_USERS);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MODIFY_USERS", "undefined");
#endif

#ifdef CONST_MULTICAST_MASK
  printFeatureConfigNum(textPrintFlag, "CONST_MULTICAST_MASK", CONST_MULTICAST_MASK);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MULTICAST_MASK", "undefined");
#endif

#ifdef CONST_MULTICAST_STATS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_MULTICAST_STATS_HTML", CONST_MULTICAST_STATS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MULTICAST_STATS_HTML", "undefined");
#endif

#ifdef CONST_NET_FLOWS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_NET_FLOWS_HTML", CONST_NET_FLOWS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NET_FLOWS_HTML", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "CONST_NETMASK_ENTRY",
#ifdef CONST_NETMASK_ENTRY
                         "yes"
#else
                         "no"
#endif
                         );

#ifdef CONST_NETWORK_ENTRY
  printFeatureConfigNum(textPrintFlag, "CONST_NETWORK_ENTRY", CONST_NETWORK_ENTRY);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NETWORK_ENTRY", "undefined");
#endif

#ifdef CONST_NTOP_HELP_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_NTOP_HELP_HTML", CONST_NTOP_HELP_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NTOP_HELP_HTML", "undefined");
#endif

#ifdef CONST_NTOP_P3P
  printFeatureConfigInfo(textPrintFlag, "CONST_NTOP_P3P", CONST_NTOP_P3P);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NTOP_P3P", "undefined");
#endif

#ifdef CONST_NULL_HDRLEN
  printFeatureConfigNum(textPrintFlag, "CONST_NULL_HDRLEN", CONST_NULL_HDRLEN);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NULL_HDRLEN", "undefined");
#endif

#ifdef CONST_NUM_TABLE_ROWS_PER_PAGE
  printFeatureConfigNum(textPrintFlag, "CONST_NUM_TABLE_ROWS_PER_PAGE", CONST_NUM_TABLE_ROWS_PER_PAGE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NUM_TABLE_ROWS_PER_PAGE", "undefined");
#endif

#ifdef CONST_NUM_TRANSACTION_ENTRIES
  printFeatureConfigNum(textPrintFlag, "CONST_NUM_TRANSACTION_ENTRIES", CONST_NUM_TRANSACTION_ENTRIES);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NUM_TRANSACTION_ENTRIES", "undefined");
#endif

#ifdef CONST_OSFINGERPRINT_FILE
  printFeatureConfigInfo(textPrintFlag, "CONST_OSFINGERPRINT_FILE", CONST_OSFINGERPRINT_FILE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_OSFINGERPRINT_FILE", "undefined");
#endif

#ifdef CONST_P2C_FILE
  printFeatureConfigInfo(textPrintFlag, "CONST_P2C_FILE", CONST_P2C_FILE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_P2C_FILE", "undefined");
#endif

#ifdef CONST_PACKET_QUEUE_LENGTH
  printFeatureConfigNum(textPrintFlag, "CONST_PACKET_QUEUE_LENGTH", CONST_PACKET_QUEUE_LENGTH);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PACKET_QUEUE_LENGTH", "undefined");
#endif

#ifdef CONST_PATH_SEP
  printFeatureConfigNum(textPrintFlag, "CONST_PATH_SEP", CONST_PATH_SEP);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PATH_SEP", "undefined");
#endif

#ifdef CONST_PCAPNONBLOCKING_SLEEP_TIME
  printFeatureConfigNum(textPrintFlag, "CONST_PCAPNONBLOCKING_SLEEP_TIME", CONST_PCAPNONBLOCKING_SLEEP_TIME);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PCAPNONBLOCKING_SLEEP_TIME", "undefined");
#endif

#ifdef CONST_PCAP_NW_INTERFACE_FILE
  printFeatureConfigInfo(textPrintFlag, "CONST_PCAP_NW_INTERFACE_FILE", CONST_PCAP_NW_INTERFACE_FILE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PCAP_NW_INTERFACE_FILE", "undefined");
#endif

#ifdef CONST_PCTG_HIGH_COLOR
  printFeatureConfigInfo(textPrintFlag, "CONST_PCTG_HIGH_COLOR", CONST_PCTG_HIGH_COLOR);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PCTG_HIGH_COLOR", "undefined");
#endif

#ifdef CONST_PCTG_LOW
  printFeatureConfigNum(textPrintFlag, "CONST_PCTG_LOW", CONST_PCTG_LOW);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PCTG_LOW", "undefined");
#endif

#ifdef CONST_PCTG_MID
  printFeatureConfigNum(textPrintFlag, "CONST_PCTG_MID", CONST_PCTG_MID);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PCTG_MID", "undefined");
#endif

#ifdef CONST_PIE_FC_PKT_SZ_DIST
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_FC_PKT_SZ_DIST", CONST_PIE_FC_PKT_SZ_DIST);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_FC_PKT_SZ_DIST", "undefined");
#endif

#ifdef CONST_PIE_INTERFACE_DIST
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_INTERFACE_DIST", CONST_PIE_INTERFACE_DIST);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_INTERFACE_DIST", "undefined");
#endif

#ifdef CONST_PIE_IP_TRAFFIC
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_IP_TRAFFIC", CONST_PIE_IP_TRAFFIC);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_IP_TRAFFIC", "undefined");
#endif

#ifdef CONST_PIE_PKT_CAST_DIST
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_PKT_CAST_DIST", CONST_PIE_PKT_CAST_DIST);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_PKT_CAST_DIST", "undefined");
#endif

#ifdef CONST_PIE_PKT_SIZE_DIST
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_PKT_SIZE_DIST", CONST_PIE_PKT_SIZE_DIST);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_PKT_SIZE_DIST", "undefined");
#endif

#ifdef CONST_PIE_TTL_DIST
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_TTL_DIST", CONST_PIE_TTL_DIST);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_TTL_DIST", "undefined");
#endif

#ifdef CONST_PIE_VSAN_CNTL_TRAF_DIST
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_VSAN_CNTL_TRAF_DIST", CONST_PIE_VSAN_CNTL_TRAF_DIST);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PIE_VSAN_CNTL_TRAF_DIST", "undefined");
#endif

#ifdef CONST_PLUGIN_ENTRY_FCTN_NAME
  printFeatureConfigInfo(textPrintFlag, "CONST_PLUGIN_ENTRY_FCTN_NAME", CONST_PLUGIN_ENTRY_FCTN_NAME);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PLUGIN_ENTRY_FCTN_NAME", "undefined");
#endif

#ifdef CONST_PLUGIN_EXTENSION
  printFeatureConfigInfo(textPrintFlag, "CONST_PLUGIN_EXTENSION", CONST_PLUGIN_EXTENSION);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PLUGIN_EXTENSION", "undefined");
#endif

#ifdef CONST_PLUGINS_HEADER
  printFeatureConfigInfo(textPrintFlag, "CONST_PLUGINS_HEADER", CONST_PLUGINS_HEADER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PLUGINS_HEADER", "undefined");
#endif

#ifdef CONST_PPP_HDRLEN
  printFeatureConfigNum(textPrintFlag, "CONST_PPP_HDRLEN", CONST_PPP_HDRLEN);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PPP_HDRLEN", "undefined");
#endif

#ifdef CONST_PPP_PROTOCOL_TYPE
  printFeatureConfigNum(textPrintFlag, "CONST_PPP_PROTOCOL_TYPE", CONST_PPP_PROTOCOL_TYPE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PPP_PROTOCOL_TYPE", "undefined");
#endif

#ifdef CONST_PRIVACYCLEAR_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_PRIVACYCLEAR_HTML", CONST_PRIVACYCLEAR_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PRIVACYCLEAR_HTML", "undefined");
#endif

#ifdef CONST_PRIVACYFORCE_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_PRIVACYFORCE_HTML", CONST_PRIVACYFORCE_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PRIVACYFORCE_HTML", "undefined");
#endif

#ifdef CONST_PRIVACYNOTICE_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_PRIVACYNOTICE_HTML", CONST_PRIVACYNOTICE_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PRIVACYNOTICE_HTML", "undefined");
#endif

#ifdef CONST_PROBLEMRPT_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_PROBLEMRPT_HTML", CONST_PROBLEMRPT_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PROBLEMRPT_HTML", "undefined");
#endif

#ifdef CONST_REPORT_ITS_DEFAULT
  printFeatureConfigInfo(textPrintFlag, "CONST_REPORT_ITS_DEFAULT", CONST_REPORT_ITS_DEFAULT);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_REPORT_ITS_DEFAULT", "undefined");
#endif

#ifdef CONST_REPORT_ITS_EFFECTIVE
  printFeatureConfigInfo(textPrintFlag, "CONST_REPORT_ITS_EFFECTIVE", CONST_REPORT_ITS_EFFECTIVE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_REPORT_ITS_EFFECTIVE", "undefined");
#endif

#ifdef CONST_RESET_STATS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_RESET_STATS_HTML", CONST_RESET_STATS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RESET_STATS_HTML", "undefined");
#endif

#ifdef CONST_RFC1945_TIMESPEC
  printFeatureConfigInfo(textPrintFlag, "CONST_RFC1945_TIMESPEC", CONST_RFC1945_TIMESPEC);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RFC1945_TIMESPEC", "undefined");
#endif

#ifdef CONST_RRD_DEFAULT_FONT_NAME
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_DEFAULT_FONT_NAME", CONST_RRD_DEFAULT_FONT_NAME);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_DEFAULT_FONT_NAME", "undefined");
#endif

#ifdef CONST_RRD_DEFAULT_FONT_PATH
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_DEFAULT_FONT_PATH", CONST_RRD_DEFAULT_FONT_PATH);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_DEFAULT_FONT_PATH", "undefined");
#endif

#ifdef CONST_RRD_DEFAULT_FONT_SIZE
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_DEFAULT_FONT_SIZE", CONST_RRD_DEFAULT_FONT_SIZE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_DEFAULT_FONT_SIZE", "undefined");
#endif

#ifdef CONST_RRD_D_PERMISSIONS_EVERYONE
  printFeatureConfigNum(textPrintFlag, "CONST_RRD_D_PERMISSIONS_EVERYONE", CONST_RRD_D_PERMISSIONS_EVERYONE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_D_PERMISSIONS_EVERYONE", "undefined");
#endif

#ifdef CONST_RRD_D_PERMISSIONS_GROUP
  printFeatureConfigNum(textPrintFlag, "CONST_RRD_D_PERMISSIONS_GROUP", CONST_RRD_D_PERMISSIONS_GROUP);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_D_PERMISSIONS_GROUP", "undefined");
#endif

#ifdef CONST_RRD_D_PERMISSIONS_PRIVATE
  printFeatureConfigNum(textPrintFlag, "CONST_RRD_D_PERMISSIONS_PRIVATE", CONST_RRD_D_PERMISSIONS_PRIVATE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_D_PERMISSIONS_PRIVATE", "undefined");
#endif

#ifdef CONST_RRD_EXTENSION
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_EXTENSION", CONST_RRD_EXTENSION);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_EXTENSION", "undefined");
#endif

#ifdef CONST_RRD_PERMISSIONS_EVERYONE
  printFeatureConfigNum(textPrintFlag, "CONST_RRD_PERMISSIONS_EVERYONE", CONST_RRD_PERMISSIONS_EVERYONE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_PERMISSIONS_EVERYONE", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_PERMISSIONS_GROUP",
#ifdef CONST_RRD_PERMISSIONS_GROUP
                         "yes"
#else
                         "no"
#endif
                         );

#ifdef CONST_RRD_PERMISSIONS_PRIVATE
  printFeatureConfigNum(textPrintFlag, "CONST_RRD_PERMISSIONS_PRIVATE", CONST_RRD_PERMISSIONS_PRIVATE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_PERMISSIONS_PRIVATE", "undefined");
#endif

#ifdef CONST_RRD_UMASK_EVERYONE
  printFeatureConfigNum(textPrintFlag, "CONST_RRD_UMASK_EVERYONE", CONST_RRD_UMASK_EVERYONE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_UMASK_EVERYONE", "undefined");
#endif

#ifdef CONST_RRD_UMASK_GROUP
  printFeatureConfigNum(textPrintFlag, "CONST_RRD_UMASK_GROUP", CONST_RRD_UMASK_GROUP);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_UMASK_GROUP", "undefined");
#endif

#ifdef CONST_RRD_UMASK_PRIVATE
  printFeatureConfigNum(textPrintFlag, "CONST_RRD_UMASK_PRIVATE", CONST_RRD_UMASK_PRIVATE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_UMASK_PRIVATE", "undefined");
#endif

#ifdef CONST_SCSI_BYTES_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SCSI_BYTES_HTML", CONST_SCSI_BYTES_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SCSI_BYTES_HTML", "undefined");
#endif

#ifdef CONST_SCSI_STATUS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SCSI_STATUS_HTML", CONST_SCSI_STATUS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SCSI_STATUS_HTML", "undefined");
#endif

#ifdef CONST_SCSI_TIMES_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SCSI_TIMES_HTML", CONST_SCSI_TIMES_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SCSI_TIMES_HTML", "undefined");
#endif

#ifdef CONST_SCSI_TM_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SCSI_TM_HTML", CONST_SCSI_TM_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SCSI_TM_HTML", "undefined");
#endif

#ifdef CONST_SFLOW_TCPDUMP_MAGIC
  printFeatureConfigNum(textPrintFlag, "CONST_SFLOW_TCPDUMP_MAGIC", CONST_SFLOW_TCPDUMP_MAGIC);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SFLOW_TCPDUMP_MAGIC", "undefined");
#endif

#ifdef CONST_SHOW_MUTEX_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SHOW_MUTEX_HTML", CONST_SHOW_MUTEX_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SHOW_MUTEX_HTML", "undefined");
#endif

#ifdef CONST_SHOW_PLUGINS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SHOW_PLUGINS_HTML", CONST_SHOW_PLUGINS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SHOW_PLUGINS_HTML", "undefined");
#endif

#ifdef CONST_SHOW_PORT_TRAFFIC_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SHOW_PORT_TRAFFIC_HTML", CONST_SHOW_PORT_TRAFFIC_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SHOW_PORT_TRAFFIC_HTML", "undefined");
#endif

#ifdef CONST_SHOW_URLS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SHOW_URLS_HTML", CONST_SHOW_URLS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SHOW_URLS_HTML", "undefined");
#endif

#ifdef CONST_SHOW_USERS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SHOW_USERS_HTML", CONST_SHOW_USERS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SHOW_USERS_HTML", "undefined");
#endif

#ifdef CONST_SHUTDOWN_NTOP_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SHUTDOWN_NTOP_HTML", CONST_SHUTDOWN_NTOP_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SHUTDOWN_NTOP_HTML", "undefined");
#endif

#ifdef CONST_SIZE_PCAP_ERR_BUF
  printFeatureConfigNum(textPrintFlag, "CONST_SIZE_PCAP_ERR_BUF", CONST_SIZE_PCAP_ERR_BUF);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SIZE_PCAP_ERR_BUF", "undefined");
#endif

#ifdef CONST_SORT_DATA_HOST_TRAFFIC_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_HOST_TRAFFIC_HTML", CONST_SORT_DATA_HOST_TRAFFIC_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_HOST_TRAFFIC_HTML", "undefined");
#endif

#ifdef CONST_SORT_DATA_IP_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_IP_HTML", CONST_SORT_DATA_IP_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_IP_HTML", "undefined");
#endif

#ifdef CONST_SORT_DATA_PROTOS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_PROTOS_HTML", CONST_SORT_DATA_PROTOS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_PROTOS_HTML", "undefined");
#endif

#ifdef CONST_SORT_DATA_RCVD_HOST_TRAFFIC_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_RCVD_HOST_TRAFFIC_HTML", CONST_SORT_DATA_RCVD_HOST_TRAFFIC_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_RCVD_HOST_TRAFFIC_HTML", "undefined");
#endif

#ifdef CONST_SORT_DATA_SENT_HOST_TRAFFIC_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_SENT_HOST_TRAFFIC_HTML", CONST_SORT_DATA_SENT_HOST_TRAFFIC_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_SENT_HOST_TRAFFIC_HTML", "undefined");
#endif

#ifdef CONST_SORT_DATA_THPT_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_THPT_HTML", CONST_SORT_DATA_THPT_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_THPT_HTML", "undefined");
#endif

#ifdef CONST_SORT_DATA_THPT_STATS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_THPT_STATS_HTML", CONST_SORT_DATA_THPT_STATS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SORT_DATA_THPT_STATS_HTML", "undefined");
#endif

#ifdef CONST_SSL_CERTF_FILENAME
  printFeatureConfigInfo(textPrintFlag, "CONST_SSL_CERTF_FILENAME", CONST_SSL_CERTF_FILENAME);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SSL_CERTF_FILENAME", "undefined");
#endif

#ifdef CONST_SWITCH_NIC_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SWITCH_NIC_HTML", CONST_SWITCH_NIC_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SWITCH_NIC_HTML", "undefined");
#endif

#ifdef CONST_TEXT_INFO_NTOP_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_TEXT_INFO_NTOP_HTML", CONST_TEXT_INFO_NTOP_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_TEXT_INFO_NTOP_HTML", "undefined");
#endif

#ifdef CONST_THPTLABEL_TIMESPEC
  printFeatureConfigInfo(textPrintFlag, "CONST_THPTLABEL_TIMESPEC", CONST_THPTLABEL_TIMESPEC);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_THPTLABEL_TIMESPEC", "undefined");
#endif

#ifdef CONST_THPT_STATS_MATRIX_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_THPT_STATS_MATRIX_HTML", CONST_THPT_STATS_MATRIX_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_THPT_STATS_MATRIX_HTML", "undefined");
#endif

#ifdef CONST_THROUGHPUT_GRAPH
  printFeatureConfigInfo(textPrintFlag, "CONST_THROUGHPUT_GRAPH", CONST_THROUGHPUT_GRAPH);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_THROUGHPUT_GRAPH", "undefined");
#endif

#ifdef CONST_TOD_HOUR_TIMESPEC
  printFeatureConfigInfo(textPrintFlag, "CONST_TOD_HOUR_TIMESPEC", CONST_TOD_HOUR_TIMESPEC);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_TOD_HOUR_TIMESPEC", "undefined");
#endif

#ifdef CONST_TOD_NOSEC_TIMESPEC
  printFeatureConfigInfo(textPrintFlag, "CONST_TOD_NOSEC_TIMESPEC", CONST_TOD_NOSEC_TIMESPEC);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_TOD_NOSEC_TIMESPEC", "undefined");
#endif

#ifdef CONST_TOD_WSEC_TIMESPEC
  printFeatureConfigInfo(textPrintFlag, "CONST_TOD_WSEC_TIMESPEC", CONST_TOD_WSEC_TIMESPEC);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_TOD_WSEC_TIMESPEC", "undefined");
#endif

#ifdef CONST_TRAFFIC_STATS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_TRAFFIC_STATS_HTML", CONST_TRAFFIC_STATS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_TRAFFIC_STATS_HTML", "undefined");
#endif

#ifdef CONST_TRMTU
  printFeatureConfigNum(textPrintFlag, "CONST_TRMTU", CONST_TRMTU);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_TRMTU", "undefined");
#endif

#ifdef CONST_TWO_MSL_TIMEOUT
  printFeatureConfigNum(textPrintFlag, "CONST_TWO_MSL_TIMEOUT", CONST_TWO_MSL_TIMEOUT);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_TWO_MSL_TIMEOUT", "undefined");
#endif

#ifdef CONST_UNKNOWN_MTU
  printFeatureConfigNum(textPrintFlag, "CONST_UNKNOWN_MTU", CONST_UNKNOWN_MTU);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_UNKNOWN_MTU", "undefined");
#endif

#ifdef CONST_VERY_DETAIL_TRACE_LEVEL
  printFeatureConfigNum(textPrintFlag, "CONST_VERY_DETAIL_TRACE_LEVEL", CONST_VERY_DETAIL_TRACE_LEVEL);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_VERY_DETAIL_TRACE_LEVEL", "undefined");
#endif

#ifdef CONST_VIEW_LOG_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_VIEW_LOG_HTML", CONST_VIEW_LOG_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_VIEW_LOG_HTML", "undefined");
#endif

#ifdef CONST_VLAN_LIST_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_VLAN_LIST_HTML", CONST_VLAN_LIST_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_VLAN_LIST_HTML", "undefined");
#endif

#ifdef CONST_VSAN_DETAIL_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_VSAN_DETAIL_HTML", CONST_VSAN_DETAIL_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_VSAN_DETAIL_HTML", "undefined");
#endif

#ifdef CONST_VSAN_DISTRIB_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_VSAN_DISTRIB_HTML", CONST_VSAN_DISTRIB_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_VSAN_DISTRIB_HTML", "undefined");
#endif

#ifdef CONST_VSAN_LIST_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_VSAN_LIST_HTML", CONST_VSAN_LIST_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_VSAN_LIST_HTML", "undefined");
#endif

#ifdef CONST_W3C_CHARTYPE_LINE
  printFeatureConfigInfo(textPrintFlag, "CONST_W3C_CHARTYPE_LINE", CONST_W3C_CHARTYPE_LINE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_W3C_CHARTYPE_LINE", "undefined");
#endif

#ifdef CONST_W3C_DOCTYPE_LINE_32
  printFeatureConfigInfo(textPrintFlag, "CONST_W3C_DOCTYPE_LINE_32", CONST_W3C_DOCTYPE_LINE_32);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_W3C_DOCTYPE_LINE_32", "undefined");
#endif

#ifdef CONST_W3C_DOCTYPE_LINE
  printFeatureConfigInfo(textPrintFlag, "CONST_W3C_DOCTYPE_LINE", CONST_W3C_DOCTYPE_LINE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_W3C_DOCTYPE_LINE", "undefined");
#endif

#ifdef CONST_W3C_P3P_XML
  printFeatureConfigInfo(textPrintFlag, "CONST_W3C_P3P_XML", CONST_W3C_P3P_XML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_W3C_P3P_XML", "undefined");
#endif

#ifdef CONST_WIN32_PATH_NETWORKS
  printFeatureConfigInfo(textPrintFlag, "CONST_WIN32_PATH_NETWORKS", CONST_WIN32_PATH_NETWORKS);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_WIN32_PATH_NETWORKS", "undefined");
#endif

#ifdef CONST_XML_DOCTYPE_NAME
  printFeatureConfigInfo(textPrintFlag, "CONST_XML_DOCTYPE_NAME", CONST_XML_DOCTYPE_NAME);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_XML_DOCTYPE_NAME", "undefined");
#endif

#ifdef CONST_XML_DTD_NAME
  printFeatureConfigInfo(textPrintFlag, "CONST_XML_DTD_NAME", CONST_XML_DTD_NAME);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_XML_DTD_NAME", "undefined");
#endif

#ifdef CONST_XMLDUMP_PLUGIN_NAME
  printFeatureConfigInfo(textPrintFlag, "CONST_XMLDUMP_PLUGIN_NAME", CONST_XMLDUMP_PLUGIN_NAME);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_XMLDUMP_PLUGIN_NAME", "undefined");
#endif

#ifdef CONST_XML_TMP_NAME
  printFeatureConfigInfo(textPrintFlag, "CONST_XML_TMP_NAME", CONST_XML_TMP_NAME);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_XML_TMP_NAME", "undefined");
#endif

#ifdef CONTACTED_PEERS_THRESHOLD
  printFeatureConfigNum(textPrintFlag, "CONTACTED_PEERS_THRESHOLD", CONTACTED_PEERS_THRESHOLD);
#else
  printFeatureConfigInfo(textPrintFlag, "CONTACTED_PEERS_THRESHOLD", "undefined");
#endif

#ifdef DEFAULT_AS_LOOKUP_URL
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_AS_LOOKUP_URL", DEFAULT_AS_LOOKUP_URL);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_AS_LOOKUP_URL", "undefined");
#endif

#ifdef DEFAULT_NETFLOW_PORT_STR
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NETFLOW_PORT_STR", DEFAULT_NETFLOW_PORT_STR);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NETFLOW_PORT_STR", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_ACCESS_LOG_FILE", "(null)");

#ifdef DEFAULT_NTOP_AUTOREFRESH_INTERVAL
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_AUTOREFRESH_INTERVAL", DEFAULT_NTOP_AUTOREFRESH_INTERVAL);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_AUTOREFRESH_INTERVAL", "undefined");
#endif

#ifdef DEFAULT_NTOP_DAEMON_MODE
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_DAEMON_MODE", DEFAULT_NTOP_DAEMON_MODE);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_DAEMON_MODE", "undefined");
#endif

#ifdef DEFAULT_NTOP_DEBUG
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_DEBUG", DEFAULT_NTOP_DEBUG);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_DEBUG", "undefined");
#endif

#ifdef DEFAULT_NTOP_DEBUG_MODE
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_DEBUG_MODE", DEFAULT_NTOP_DEBUG_MODE);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_DEBUG_MODE", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_DEVICES", "(null)");

#ifdef DEFAULT_NTOP_DISABLE_PROMISCUOUS
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_DISABLE_PROMISCUOUS", DEFAULT_NTOP_DISABLE_PROMISCUOUS);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_DISABLE_PROMISCUOUS", "undefined");
#endif

#ifdef DEFAULT_NTOP_DOMAIN_NAME
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_DOMAIN_NAME", DEFAULT_NTOP_DOMAIN_NAME);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_DOMAIN_NAME", "undefined");
#endif

#ifdef DEFAULT_NTOP_DONT_TRUST_MAC_ADDR
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_DONT_TRUST_MAC_ADDR", DEFAULT_NTOP_DONT_TRUST_MAC_ADDR);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_DONT_TRUST_MAC_ADDR", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_ENABLE_SESSIONHANDLE",
#ifdef DEFAULT_NTOP_ENABLE_SESSIONHANDLE
                         "yes"
#else
                         "no"
#endif
                         );

#ifdef DEFAULT_NTOP_FAMILY
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_FAMILY", DEFAULT_NTOP_FAMILY);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_FAMILY", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_FILTER_EXPRESSION", "(null)");

#ifdef DEFAULT_NTOP_FILTER_IN_FRAME
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_FILTER_IN_FRAME", DEFAULT_NTOP_FILTER_IN_FRAME);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_FILTER_IN_FRAME", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_FLOW_SPECS", "(null)");

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_LOCAL_SUBNETS", "(null)");

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_MERGE_INTERFACES",
#ifdef DEFAULT_NTOP_MERGE_INTERFACES
                         "yes"
#else
                         "no"
#endif
                         );

#ifdef DEFAULT_NTOP_NUMERIC_IP_ADDRESSES
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_NUMERIC_IP_ADDRESSES", DEFAULT_NTOP_NUMERIC_IP_ADDRESSES);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_NUMERIC_IP_ADDRESSES", "undefined");
#endif

#ifdef DEFAULT_NTOP_OTHER_PKT_DUMP
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_OTHER_PKT_DUMP", DEFAULT_NTOP_OTHER_PKT_DUMP);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_OTHER_PKT_DUMP", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_PACKET_DECODING",
#ifdef DEFAULT_NTOP_PACKET_DECODING
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_PCAP_LOG_FILENAME", "(null)");

#ifdef DEFAULT_NTOP_PID_DIRECTORY
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_PID_DIRECTORY", DEFAULT_NTOP_PID_DIRECTORY);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_PID_DIRECTORY", "undefined");
#endif

#ifdef DEFAULT_NTOP_PIDFILE
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_PIDFILE", DEFAULT_NTOP_PIDFILE);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_PIDFILE", "undefined");
#endif

#ifdef DEFAULT_NTOP_STICKY_HOSTS
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_STICKY_HOSTS", DEFAULT_NTOP_STICKY_HOSTS);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_STICKY_HOSTS", "undefined");
#endif

#ifdef DEFAULT_NTOP_SUSPICIOUS_PKT_DUMP
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_SUSPICIOUS_PKT_DUMP", DEFAULT_NTOP_SUSPICIOUS_PKT_DUMP);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_SUSPICIOUS_PKT_DUMP", "undefined");
#endif

#ifdef DEFAULT_NTOP_TRACK_ONLY_LOCAL
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_TRACK_ONLY_LOCAL", DEFAULT_NTOP_TRACK_ONLY_LOCAL);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_TRACK_ONLY_LOCAL", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_TRAFFICDUMP_FILENAME", "(null)");

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_WEB_ADDR", "(null)");

#ifdef DEFAULT_NTOP_WEB_PORT
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_WEB_PORT", DEFAULT_NTOP_WEB_PORT);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_WEB_PORT", "undefined");
#endif

#ifdef DEFAULT_RRD_DAYS
  printFeatureConfigNum(textPrintFlag, "DEFAULT_RRD_DAYS", DEFAULT_RRD_DAYS);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_RRD_DAYS", "undefined");
#endif

#ifdef DEFAULT_RRD_HOURS
  printFeatureConfigNum(textPrintFlag, "DEFAULT_RRD_HOURS", DEFAULT_RRD_HOURS);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_RRD_HOURS", "undefined");
#endif

#ifdef DEFAULT_RRD_INTERVAL
  printFeatureConfigNum(textPrintFlag, "DEFAULT_RRD_INTERVAL", DEFAULT_RRD_INTERVAL);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_RRD_INTERVAL", "undefined");
#endif

#ifdef DEFAULT_RRD_MONTHS
  printFeatureConfigNum(textPrintFlag, "DEFAULT_RRD_MONTHS", DEFAULT_RRD_MONTHS);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_RRD_MONTHS", "undefined");
#endif

#ifdef DEFAULT_RRD_PERMISSIONS
  printFeatureConfigNum(textPrintFlag, "DEFAULT_RRD_PERMISSIONS", DEFAULT_RRD_PERMISSIONS);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_RRD_PERMISSIONS", "undefined");
#endif

#ifdef DEFAULT_SFLOW_COLLECTOR_PORT
  printFeatureConfigNum(textPrintFlag, "DEFAULT_SFLOW_COLLECTOR_PORT", DEFAULT_SFLOW_COLLECTOR_PORT);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_SFLOW_COLLECTOR_PORT", "undefined");
#endif

#ifdef DEFAULT_SFLOW_COLLECTOR_PORT_STR
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_SFLOW_COLLECTOR_PORT_STR", DEFAULT_SFLOW_COLLECTOR_PORT_STR);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_SFLOW_COLLECTOR_PORT_STR", "undefined");
#endif

#ifdef DEFAULT_SFLOW_SAMPLING_RATE
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_SFLOW_SAMPLING_RATE", DEFAULT_SFLOW_SAMPLING_RATE);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_SFLOW_SAMPLING_RATE", "undefined");
#endif

#ifdef DEFAULT_SNAPLEN
  printFeatureConfigNum(textPrintFlag, "DEFAULT_SNAPLEN", DEFAULT_SNAPLEN);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_SNAPLEN", "undefined");
#endif

#ifdef DEFAULT_SYSLOG_FACILITY
  printFeatureConfigNum(textPrintFlag, "DEFAULT_SYSLOG_FACILITY", DEFAULT_SYSLOG_FACILITY);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_SYSLOG_FACILITY", "undefined");
#endif

#ifdef DEFAULT_TCPWRAP_ALLOW
  printFeatureConfigNum(textPrintFlag, "DEFAULT_TCPWRAP_ALLOW", DEFAULT_TCPWRAP_ALLOW);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_TCPWRAP_ALLOW", "undefined");
#endif

#ifdef DEFAULT_TCPWRAP_DENY
  printFeatureConfigNum(textPrintFlag, "DEFAULT_TCPWRAP_DENY", DEFAULT_TCPWRAP_DENY);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_TCPWRAP_DENY", "undefined");
#endif

#ifdef DEFAULT_TRACE_LEVEL
  printFeatureConfigNum(textPrintFlag, "DEFAULT_TRACE_LEVEL", DEFAULT_TRACE_LEVEL);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_TRACE_LEVEL", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_VSAN",
#ifdef DEFAULT_VSAN
                         "yes"
#else
                         "no"
#endif
                         );

#ifdef DEFAULT_WEBSERVER_REQUEST_QUEUE_LEN
  printFeatureConfigNum(textPrintFlag, "DEFAULT_WEBSERVER_REQUEST_QUEUE_LEN", DEFAULT_WEBSERVER_REQUEST_QUEUE_LEN);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_WEBSERVER_REQUEST_QUEUE_LEN", "undefined");
#endif

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

#ifdef LEN_ADDRESS_BUFFER
  printFeatureConfigNum(textPrintFlag, "LEN_ADDRESS_BUFFER", LEN_ADDRESS_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_ADDRESS_BUFFER", "undefined");
#endif

#ifdef LEN_CMDLINE_BUFFER
  printFeatureConfigNum(textPrintFlag, "LEN_CMDLINE_BUFFER", LEN_CMDLINE_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_CMDLINE_BUFFER", "undefined");
#endif

#ifdef LEN_ETHERNET_ADDRESS_DISPLAY
  printFeatureConfigNum(textPrintFlag, "LEN_ETHERNET_ADDRESS_DISPLAY", LEN_ETHERNET_ADDRESS_DISPLAY);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_ETHERNET_ADDRESS_DISPLAY", "undefined");
#endif

#ifdef LEN_ETHERNET_ADDRESS
  printFeatureConfigNum(textPrintFlag, "LEN_ETHERNET_ADDRESS", LEN_ETHERNET_ADDRESS);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_ETHERNET_ADDRESS", "undefined");
#endif

#ifdef LEN_ETHERNET_VENDOR_DISPLAY
  printFeatureConfigNum(textPrintFlag, "LEN_ETHERNET_VENDOR_DISPLAY", LEN_ETHERNET_VENDOR_DISPLAY);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_ETHERNET_VENDOR_DISPLAY", "undefined");
#endif

#ifdef LEN_ETHERNET_VENDOR
  printFeatureConfigNum(textPrintFlag, "LEN_ETHERNET_VENDOR", LEN_ETHERNET_VENDOR);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_ETHERNET_VENDOR", "undefined");
#endif

#ifdef LEN_FC_ADDRESS_DISPLAY
  printFeatureConfigNum(textPrintFlag, "LEN_FC_ADDRESS_DISPLAY", LEN_FC_ADDRESS_DISPLAY);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_FC_ADDRESS_DISPLAY", "undefined");
#endif

#ifdef LEN_FC_ADDRESS
  printFeatureConfigNum(textPrintFlag, "LEN_FC_ADDRESS", LEN_FC_ADDRESS);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_FC_ADDRESS", "undefined");
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

#ifdef LEN_TIMEFORMAT_BUFFER
  printFeatureConfigNum(textPrintFlag, "LEN_TIMEFORMAT_BUFFER", LEN_TIMEFORMAT_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_TIMEFORMAT_BUFFER", "undefined");
#endif

#ifdef LEN_WWN_ADDRESS_DISPLAY
  printFeatureConfigNum(textPrintFlag, "LEN_WWN_ADDRESS_DISPLAY", LEN_WWN_ADDRESS_DISPLAY);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_WWN_ADDRESS_DISPLAY", "undefined");
#endif

#ifdef LEN_WWN_ADDRESS
  printFeatureConfigNum(textPrintFlag, "LEN_WWN_ADDRESS", LEN_WWN_ADDRESS);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_WWN_ADDRESS", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "MAKE_ASYNC_ADDRESS_RESOLUTION",
#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_NTOP_PACKETSZ_DECLARATIONS",
#ifdef MAKE_NTOP_PACKETSZ_DECLARATIONS
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

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_LOG_XXXXXX",
#ifdef MAKE_WITH_LOG_XXXXXX
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

#ifdef MAX_DLT_ARRAY
  printFeatureConfigNum(textPrintFlag, "MAX_DLT_ARRAY", MAX_DLT_ARRAY);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_DLT_ARRAY", "undefined");
#endif

#ifdef MAXDNAME
  printFeatureConfigNum(textPrintFlag, "MAXDNAME", MAXDNAME);
#else
  printFeatureConfigInfo(textPrintFlag, "MAXDNAME", "undefined");
#endif

#ifdef MAX_ELEMENT_HASH
  printFeatureConfigNum(textPrintFlag, "MAX_ELEMENT_HASH", MAX_ELEMENT_HASH);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_ELEMENT_HASH", "undefined");
#endif

#ifdef MAX_FC_DOMAINS
  printFeatureConfigNum(textPrintFlag, "MAX_FC_DOMAINS", MAX_FC_DOMAINS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_FC_DOMAINS", "undefined");
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

#ifdef MAX_HOSTS_PURGE_PER_CYCLE
  printFeatureConfigNum(textPrintFlag, "MAX_HOSTS_PURGE_PER_CYCLE", MAX_HOSTS_PURGE_PER_CYCLE);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_HOSTS_PURGE_PER_CYCLE", "unlimited");
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

#ifdef MAX_LEN_SYM_HOST_NAME_HTML
  printFeatureConfigNum(textPrintFlag, "MAX_LEN_SYM_HOST_NAME_HTML", MAX_LEN_SYM_HOST_NAME_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_LEN_SYM_HOST_NAME_HTML", "undefined");
#endif

#ifdef MAX_LEN_SYM_HOST_NAME
  printFeatureConfigNum(textPrintFlag, "MAX_LEN_SYM_HOST_NAME", MAX_LEN_SYM_HOST_NAME);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_LEN_SYM_HOST_NAME", "undefined");
#endif

#ifdef MAX_LEN_URL
  printFeatureConfigNum(textPrintFlag, "MAX_LEN_URL", MAX_LEN_URL);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_LEN_URL", "undefined");
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

#ifdef MAX_NUM_DEVICES_VIRTUAL
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_DEVICES_VIRTUAL", MAX_NUM_DEVICES_VIRTUAL);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_DEVICES_VIRTUAL", "undefined");
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

#ifdef MAX_NUM_LIST_ENTRIES
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_LIST_ENTRIES", MAX_NUM_LIST_ENTRIES);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_LIST_ENTRIES", "undefined");
#endif

#ifdef MAX_NUM_NETWORKS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_NETWORKS", MAX_NUM_NETWORKS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_NETWORKS", "undefined");
#endif

#ifdef MAX_NUM_OS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_OS", MAX_NUM_OS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_OS", "undefined");
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

#ifdef MAX_NUM_QUEUED_ADDRESSES
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_QUEUED_ADDRESSES", MAX_NUM_QUEUED_ADDRESSES);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_QUEUED_ADDRESSES", "undefined");
#endif

#ifdef MAX_NUM_RECENT_PORTS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_RECENT_PORTS", MAX_NUM_RECENT_PORTS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_RECENT_PORTS", "undefined");
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

#ifdef MAX_PACKET_LEN
  printFeatureConfigNum(textPrintFlag, "MAX_PACKET_LEN", MAX_PACKET_LEN);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_PACKET_LEN", "undefined");
#endif

#ifdef MAX_PATHOLOGICAL_VLAN_WARNINGS
  printFeatureConfigNum(textPrintFlag, "MAX_PATHOLOGICAL_VLAN_WARNINGS", MAX_PATHOLOGICAL_VLAN_WARNINGS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_PATHOLOGICAL_VLAN_WARNINGS", "undefined");
#endif

#ifdef MAX_PASSIVE_FTP_SESSION_TRACKER
  printFeatureConfigNum(textPrintFlag, "MAX_PASSIVE_FTP_SESSION_TRACKER", MAX_PASSIVE_FTP_SESSION_TRACKER);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_PASSIVE_FTP_SESSION_TRACKER", "undefined");
#endif

#ifdef MAX_PDA_HOST_TABLE
  printFeatureConfigNum(textPrintFlag, "MAX_PDA_HOST_TABLE", MAX_PDA_HOST_TABLE);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_PDA_HOST_TABLE", "undefined");
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

#ifdef MAX_SUBNET_HOSTS
  printFeatureConfigNum(textPrintFlag, "MAX_SUBNET_HOSTS", MAX_SUBNET_HOSTS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_SUBNET_HOSTS", "undefined");
#endif

#ifdef MAX_TOT_NUM_SESSIONS
  printFeatureConfigNum(textPrintFlag, "MAX_TOT_NUM_SESSIONS", MAX_TOT_NUM_SESSIONS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_TOT_NUM_SESSIONS", "undefined");
#endif

#ifdef MAX_USER_VSAN
  printFeatureConfigNum(textPrintFlag, "MAX_USER_VSAN", MAX_USER_VSAN);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_USER_VSAN", "undefined");
#endif

#ifdef MAX_VSANS_GRAPHED
  printFeatureConfigNum(textPrintFlag, "MAX_VSANS_GRAPHED", MAX_VSANS_GRAPHED);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_VSANS_GRAPHED", "undefined");
#endif

#ifdef MAX_VSANS
  printFeatureConfigNum(textPrintFlag, "MAX_VSANS", MAX_VSANS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_VSANS", "undefined");
#endif

#ifdef MAX_WEBSERVER_REQUEST_QUEUE_LEN
  printFeatureConfigNum(textPrintFlag, "MAX_WEBSERVER_REQUEST_QUEUE_LEN", MAX_WEBSERVER_REQUEST_QUEUE_LEN);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_WEBSERVER_REQUEST_QUEUE_LEN", "undefined");
#endif

#ifdef MAX_WIN32_NET_ALIASES
  printFeatureConfigNum(textPrintFlag, "MAX_WIN32_NET_ALIASES", MAX_WIN32_NET_ALIASES);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_WIN32_NET_ALIASES", "undefined");
#endif

#ifdef MIN_SLICE_PERCENTAGE
  printFeatureConfigNum(textPrintFlag, "MIN_SLICE_PERCENTAGE", MIN_SLICE_PERCENTAGE);
#else
  printFeatureConfigInfo(textPrintFlag, "MIN_SLICE_PERCENTAGE", "undefined");
#endif

#ifdef MIN_WEBSERVER_REQUEST_QUEUE_LEN
  printFeatureConfigNum(textPrintFlag, "MIN_WEBSERVER_REQUEST_QUEUE_LEN", MIN_WEBSERVER_REQUEST_QUEUE_LEN);
#else
  printFeatureConfigInfo(textPrintFlag, "MIN_WEBSERVER_REQUEST_QUEUE_LEN", "undefined");
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

#ifdef NETFLOW_DEVICE_NAME
  printFeatureConfigInfo(textPrintFlag, "NETFLOW_DEVICE_NAME", NETFLOW_DEVICE_NAME);
#else
  printFeatureConfigInfo(textPrintFlag, "NETFLOW_DEVICE_NAME", "undefined");
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

#ifdef PARM_HOST_PURGE_INTERVAL
  printFeatureConfigNum(textPrintFlag, "PARM_HOST_PURGE_INTERVAL", PARM_HOST_PURGE_INTERVAL);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_HOST_PURGE_INTERVAL", "undefined");
#endif

#ifdef PARM_HOST_PURGE_MINIMUM_IDLE_ACTVSES
  printFeatureConfigNum(textPrintFlag, "PARM_HOST_PURGE_MINIMUM_IDLE_ACTVSES", PARM_HOST_PURGE_MINIMUM_IDLE_ACTVSES);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_HOST_PURGE_MINIMUM_IDLE_ACTVSES", "undefined");
#endif

#ifdef PARM_HOST_PURGE_MINIMUM_IDLE_NOACTVSES
  printFeatureConfigNum(textPrintFlag, "PARM_HOST_PURGE_MINIMUM_IDLE_NOACTVSES", PARM_HOST_PURGE_MINIMUM_IDLE_NOACTVSES);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_HOST_PURGE_MINIMUM_IDLE_NOACTVSES", "undefined");
#endif

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

  printFeatureConfigInfo(textPrintFlag, "PARM_PRINT_ALL_SESSIONS",
#ifdef PARM_PRINT_ALL_SESSIONS
                         "yes"
#else
                         "no"
#endif
                         );

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

#ifdef PARM_SSLWATCHDOG_WAIT_INTERVAL
  printFeatureConfigNum(textPrintFlag, "PARM_SSLWATCHDOG_WAIT_INTERVAL", PARM_SSLWATCHDOG_WAIT_INTERVAL);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_SSLWATCHDOG_WAIT_INTERVAL", "undefined");
#endif

#ifdef PARM_SSLWATCHDOG_WAITWOKE_LIMIT
  printFeatureConfigNum(textPrintFlag, "PARM_SSLWATCHDOG_WAITWOKE_LIMIT", PARM_SSLWATCHDOG_WAITWOKE_LIMIT);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_SSLWATCHDOG_WAITWOKE_LIMIT", "undefined");
#endif

#ifdef PARM_THROUGHPUT_REFRESH_INTERVAL
  printFeatureConfigNum(textPrintFlag, "PARM_THROUGHPUT_REFRESH_INTERVAL", PARM_THROUGHPUT_REFRESH_INTERVAL);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_THROUGHPUT_REFRESH_INTERVAL", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "PARM_USE_CGI",
#ifndef WIN32
#ifdef PARM_USE_CGI
                         "yes"
#else
                         "no"
#endif
#else
                         "not available"
#endif /* WIN32 */
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

#ifdef SFLOW_DEVICE_NAME
  printFeatureConfigInfo(textPrintFlag, "SFLOW_DEVICE_NAME", SFLOW_DEVICE_NAME);
#else
  printFeatureConfigInfo(textPrintFlag, "SFLOW_DEVICE_NAME", "undefined");
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

  sendString(texthtml("\n\nCompile Time: globals-report.h\n\n",
                      "<tr><th colspan=\"2\"" TH_BG ">Compile Time: globals-report.h</tr>\n"));

  printFeatureConfigInfo(textPrintFlag, "Chart Format", CHART_FORMAT);

  /* ***Plugins stuff************************ */
  if(textPrintFlag == TRUE) {
      sendString("\n\nPLUGINS:\n\n");

      sendString("RRD:\n");

      printFeatureConfigInfo(textPrintFlag, "RRD path", myGlobals.rrdPath);
#ifndef WIN32
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                  "%04o", myGlobals.rrdDirectoryPermissions);
      printFeatureConfigInfo(textPrintFlag, "New directory permissions", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                  "%04o", myGlobals.rrdUmask);
      printFeatureConfigInfo(textPrintFlag, "New file umask", buf);
#endif

  }
}

/* ******************************** */

void printHostColorCode(int textPrintFlag, int isInfo) {
  if(textPrintFlag != TRUE) {
    sendString("<CENTER><TABLE BORDER=0>"
	       "<TR>"
	       "<TD COLSPAN=5 align=\"center\">The color of the host link");
    if(isInfo == 1)
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

#ifdef CFG_MULTITHREADED
void printMutexStatusReport(int textPrintFlag) {
  if(myGlobals.runningPref.disableMutexExtraInfo) {
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

#if defined(MAKE_ASYNC_ADDRESS_RESOLUTION)
  if(myGlobals.runningPref.numericFlag == 0) 
    printMutexStatus(textPrintFlag, &myGlobals.addressResolutionMutex, "addressResolutionMutex");
#endif

  printMutexStatus(textPrintFlag, &myGlobals.hostsHashMutex,   "hostsHashMutex");
  printMutexStatus(textPrintFlag, &myGlobals.tcpSessionsMutex, "tcpSessionsMutex");
  printMutexStatus(textPrintFlag, &myGlobals.purgePortsMutex,  "purgePortsMutex");
  printMutexStatus(textPrintFlag, &myGlobals.securityItemsMutex,  "securityItemsMutex");
  sendString(texthtml("\n\n", "</TABLE>"TABLE_OFF"\n"));

}

#endif

/* ******************************** */

void printNtopConfigInfo(int textPrintFlag, UserPref *pref) {
  char buf[LEN_GENERAL_WORK_BUFFER], buf2[LEN_GENERAL_WORK_BUFFER];
  int i, bufLength, bufPosition, bufUsed;
  unsigned int idx, minLen=-1, maxLen=0;
  unsigned long totBuckets=0, nonEmptyBuckets=0;
  
#if defined(HAVE_MALLINFO_MALLOC_H) && defined(HAVE_MALLOC_H) && defined(__GNUC__)
  struct mallinfo memStats;
  int totalHostsMonitored = 0;

#ifdef HAVE_SYS_RESOURCE_H
  struct rlimit rlim;
#endif
#endif

#ifdef HAVE_SYS_UTSNAME_H
  struct utsname unameData;
#endif

  if(textPrintFlag)
    sendString("ntop Configuration\n\n");
  else
    printHTMLheader("ntop Configuration", NULL, 0);

  printHostColorCode(textPrintFlag, 1);
  sendString(texthtml("\n", 
                      "<CENTER>\n<P><HR><P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n"
                      "<tr><th colspan=2 "DARK_BG"" TH_BG ">Basic information</tr>\n"));
  printFeatureConfigInfo(textPrintFlag, "ntop version", version);
  printFeatureConfigInfo(textPrintFlag, "Configured on", configureDate);
  printFeatureConfigInfo(textPrintFlag, "Built on", buildDate);
  printFeatureConfigInfo(textPrintFlag, "OS", osName);

  if(myGlobals.checkVersionStatus != FLAG_CHECKVERSION_NOTCHECKED) {
    printFeatureConfigInfo(textPrintFlag, "This version of ntop is", reportNtopVersionCheck());
    if(myGlobals.checkVersionStatusAgain > 0) {
      struct tm t;
      strftime(buf, sizeof(buf), CONST_LOCALE_TIMESPEC, localtime_r(&myGlobals.checkVersionStatusAgain, &t));
      printFeatureConfigInfo(textPrintFlag, "Next version recheck is", buf);
    }
  }

#ifdef HAVE_PCAP_LIB_VERSION
  printFeatureConfigInfo(textPrintFlag, "libpcap version", (char *)pcap_lib_version());
#endif

#ifndef WIN32
  {
    char pid[16];

    if(pref->daemonMode == 1) {
      safe_snprintf(__FILE__, __LINE__, pid, sizeof(pid), "%d", myGlobals.basentoppid);
      printFeatureConfigInfo(textPrintFlag, "ntop Process Id", pid);
      safe_snprintf(__FILE__, __LINE__, pid, sizeof(pid), "%d", getppid());
      printFeatureConfigInfo(textPrintFlag, "http Process Id", pid);
    } else {
      safe_snprintf(__FILE__, __LINE__, pid, sizeof(pid), "%d", getppid());
      printFeatureConfigInfo(textPrintFlag, "Process Id", pid);
    }

  }
#endif
#ifdef PARM_SHOW_NTOP_HEARTBEAT
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.heartbeatCounter);
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
  sendString(texthtml("\n\nPreferences used are:\n\n", "</TD></TR>\n"));

  printParameterConfigInfo(textPrintFlag, "-a | --access-log-file",
                           pref->accessLogFile,
                           DEFAULT_NTOP_ACCESS_LOG_FILE);

  printParameterConfigInfo(textPrintFlag, "-b | --disable-decoders",
                           pref->enablePacketDecoding == 1 ? "No" : "Yes",
                           DEFAULT_NTOP_PACKET_DECODING == 1 ? "No" : "Yes");

  printParameterConfigInfo(textPrintFlag, "-c | --sticky-hosts",
                           pref->stickyHosts == 1 ? "Yes" : "No",
                           DEFAULT_NTOP_STICKY_HOSTS == 1 ? "Yes" : "No");

#ifndef WIN32
  printParameterConfigInfo(textPrintFlag, "-d | --daemon",
                           pref->daemonMode == 1 ? "Yes" : "No",
                           strcmp(myGlobals.program_name, "ntopd") == 0 ? "Yes" : DEFAULT_NTOP_DAEMON_MODE);
#endif

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s%d",
	      pref->maxNumLines == CONST_NUM_TABLE_ROWS_PER_PAGE ? CONST_REPORT_ITS_DEFAULT : "",
	      pref->maxNumLines);
  printFeatureConfigInfo(textPrintFlag, "-e | --max-table-rows", buf);

  printParameterConfigInfo(textPrintFlag, "-f | --traffic-dump-file",
                           pref->rFileName,
                           DEFAULT_NTOP_TRAFFICDUMP_FILENAME);

  printParameterConfigInfo(textPrintFlag, "-g | --track-local-hosts",
                           pref->trackOnlyLocalHosts == 1 ? "Track local hosts only" : "Track all hosts",
                           DEFAULT_NTOP_TRACK_ONLY_LOCAL == 1 ? "Track local hosts only" : "Track all hosts");

  printParameterConfigInfo(textPrintFlag, "-o | --no-mac",
			   pref->dontTrustMACaddr == 1 ? "Don't trust MAC Addresses" : "Trust MAC Addresses",
                           DEFAULT_NTOP_DONT_TRUST_MAC_ADDR == 1 ? "Don't trust MAC Addresses" : "Trust MAC Addresses");

  printParameterConfigInfo(textPrintFlag, "-i | --interface" CONST_REPORT_ITS_EFFECTIVE,
                           pref->devices,
                           DEFAULT_NTOP_DEVICES);

  printParameterConfigInfo(textPrintFlag, "-j | --create-other-packets",
                           pref->enableOtherPacketDump == 1 ? "Enabled" : "Disabled",
                           DEFAULT_NTOP_OTHER_PKT_DUMP == 1 ? "Enabled" : "Disabled");

  printParameterConfigInfo(textPrintFlag, "-k | --filter-expression-in-extra-frame",
                           pref->filterExpressionInExtraFrame == 1 ? "Yes" : "No",
                           DEFAULT_NTOP_FILTER_IN_FRAME == 1 ? "Yes" : "No");

  if(pref->pcapLog == NULL) {
    printParameterConfigInfo(textPrintFlag, "-l | --pcap-log",
			     pref->pcapLog,
			     DEFAULT_NTOP_PCAP_LOG_FILENAME);
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/%s.&lt;device&gt;.pcap",
		pref->pcapLogBasePath,
		pref->pcapLog);
    printParameterConfigInfo(textPrintFlag, "-l | --pcap-log" CONST_REPORT_ITS_EFFECTIVE,
			     buf,
			     DEFAULT_NTOP_PCAP_LOG_FILENAME);
  }

  printParameterConfigInfo(textPrintFlag, "-m | --local-subnets" CONST_REPORT_ITS_EFFECTIVE,
                           pref->localAddresses,
                           DEFAULT_NTOP_LOCAL_SUBNETS);

  printParameterConfigInfo(textPrintFlag, "-n | --numeric-ip-addresses",
                           pref->numericFlag > 0 ? "Yes" : "No",
                           DEFAULT_NTOP_NUMERIC_IP_ADDRESSES > 0 ? "Yes" : "No");

  if(pref->protoSpecs == NULL) {
    printFeatureConfigInfo(textPrintFlag, "-p | --protocols", CONST_REPORT_ITS_DEFAULT "internal list");
  } else {
    printFeatureConfigInfo(textPrintFlag, "-p | --protocols", pref->protoSpecs);
  }

  printParameterConfigInfo(textPrintFlag, "-q | --create-suspicious-packets",
                           pref->enableSuspiciousPacketDump == 1 ? "Enabled" : "Disabled",
                           DEFAULT_NTOP_SUSPICIOUS_PKT_DUMP == 1 ? "Enabled" : "Disabled");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s%d",
	      pref->refreshRate == DEFAULT_NTOP_AUTOREFRESH_INTERVAL ? CONST_REPORT_ITS_DEFAULT : "",
	      pref->refreshRate);
  printFeatureConfigInfo(textPrintFlag, "-r | --refresh-time", buf);

  printParameterConfigInfo(textPrintFlag, "-s | --no-promiscuous",
                           pref->disablePromiscuousMode == 1 ? "Yes" : "No",
                           DEFAULT_NTOP_DISABLE_PROMISCUOUS == 1 ? "Yes" : "No");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s%d",
	      pref->traceLevel == DEFAULT_TRACE_LEVEL ? CONST_REPORT_ITS_DEFAULT : "",
	      pref->traceLevel);
  printFeatureConfigInfo(textPrintFlag, "-t | --trace-level", buf);

#ifndef WIN32
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s (uid=%d, gid=%d)",
	      myGlobals.effectiveUserName,
	      myGlobals.userId,
	      myGlobals.groupId);
  printFeatureConfigInfo(textPrintFlag, "-u | --user", buf);
#endif

  if(pref->webPort == 0) {
    strcpy(buf, "Inactive");
  } else if(pref->webAddr != 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"%sActive, address %s, port %d",
		( (pref->webAddr == DEFAULT_NTOP_WEB_ADDR) && (pref->webPort == DEFAULT_NTOP_WEB_PORT) ) ? CONST_REPORT_ITS_DEFAULT : "",
		pref->webAddr,
		pref->webPort);
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"%sActive, all interfaces, port %d",
		((pref->webAddr == DEFAULT_NTOP_WEB_ADDR) && (pref->webPort == DEFAULT_NTOP_WEB_PORT) )
		? CONST_REPORT_ITS_DEFAULT : "", pref->webPort);
  }

  printFeatureConfigInfo(textPrintFlag, "-w | --http-server", buf);

  printParameterConfigInfo(textPrintFlag, "-z | --disable-sessions",
                           pref->enableSessionHandling == 1 ? "No" : "Yes",
                           DEFAULT_NTOP_ENABLE_SESSIONHANDLE == 1 ? "No" : "Yes");

  printParameterConfigInfo(textPrintFlag, "-B | --filter-expression",
                           ((pref->currentFilterExpression == NULL) ||
                            (pref->currentFilterExpression[0] == '\0')) ? "none" :
			   pref->currentFilterExpression,
                           DEFAULT_NTOP_FILTER_EXPRESSION == NULL ? "none" :
			   DEFAULT_NTOP_FILTER_EXPRESSION);

  printParameterConfigInfo(textPrintFlag, "-D | --domain",
                           ((pref->domainName == NULL) ||
                            (pref->domainName[0] == '\0')) ? "none" :
			   pref->domainName,
                           DEFAULT_NTOP_DOMAIN_NAME == NULL ? "none" :
			   DEFAULT_NTOP_DOMAIN_NAME);

  printParameterConfigInfo(textPrintFlag, "-F | --flow-spec",
                           pref->flowSpecs == NULL ? "none" : pref->flowSpecs,
                           DEFAULT_NTOP_FLOW_SPECS == NULL ? "none" : DEFAULT_NTOP_FLOW_SPECS);

#ifndef WIN32
  printParameterConfigInfo(textPrintFlag, "-K | --enable-debug",
			   pref->debugMode == 1 ? "Yes" : "No",
			   DEFAULT_NTOP_DEBUG_MODE == 1 ? "Yes" : "No");

#ifdef MAKE_WITH_SYSLOG
  if(pref->useSyslog == FLAG_SYSLOG_NONE) {
    printFeatureConfigInfo(textPrintFlag, "-L | --use-syslog", "No");
  } else {
    for(i=0; myFacilityNames[i].c_name != NULL; i++) {
      if(myFacilityNames[i].c_val == pref->useSyslog) {
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
                           pref->mergeInterfaces == 1 ? "(Merging Interfaces) Yes" :
			   "(parameter -M set, Interfaces separate) No",
                           DEFAULT_NTOP_MERGE_INTERFACES == 1 ? "(Merging Interfaces) Yes" : "");

  printParameterConfigInfo(textPrintFlag, "-N | --wwn-map",
                           pref->fcNSCacheFile,
                           NULL);


  printParameterConfigInfo(textPrintFlag, "-O | --pcap-file-path",
                           pref->pcapLogBasePath,
                           CFG_DBFILE_DIR);

  printParameterConfigInfo(textPrintFlag, "-P | --db-file-path",
                           myGlobals.dbPath,
                           CFG_DBFILE_DIR);

  printParameterConfigInfo(textPrintFlag, "-Q | --spool-file-path",
                           pref->spoolPath,
                           CFG_DBFILE_DIR);

  printParameterConfigInfo(textPrintFlag, "-U | --mapper",
                           pref->mapperURL,
                           DEFAULT_NTOP_MAPPER_URL);

#ifdef HAVE_OPENSSL
  if(myGlobals.sslInitialized == 0) {
    strcpy(buf, "Uninitialized");
  } else if(pref->sslPort == 0) {
    strcpy(buf, "Inactive");
  } else if(pref->sslAddr != 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"%sActive, address %s, port %d",
		( (pref->sslAddr == DEFAULT_NTOP_WEB_ADDR) && (pref->sslPort == DEFAULT_NTOP_WEB_PORT) ) 
		? CONST_REPORT_ITS_DEFAULT : "", pref->sslAddr,pref->sslPort);
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"%sActive, all interfaces, port %d",
		( (pref->sslAddr == DEFAULT_NTOP_WEB_ADDR) && (pref->sslPort == DEFAULT_NTOP_WEB_PORT) ) 
		? CONST_REPORT_ITS_DEFAULT : "", pref->sslPort);
  }
  printFeatureConfigInfo(textPrintFlag, "-W | --https-server", buf);
#endif

#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)
  printParameterConfigInfo(textPrintFlag, "--disable-schedYield",
                           pref->disableSchedYield == TRUE ? "Yes" : "No",
                           "No");
#endif

  printParameterConfigInfo(textPrintFlag, "--disable-instantsessionpurge",
                           pref->disableInstantSessionPurge == TRUE ? "Yes" : "No",
                           "No");

  printParameterConfigInfo(textPrintFlag, "--disable-mutexextrainfo",
                           pref->disableMutexExtraInfo == TRUE ? "Yes" : "No",
                           "No");

  printParameterConfigInfo(textPrintFlag, "--disable-stopcap",
                           pref->disableStopcap == TRUE ? "Yes" : "No",
                           "No");

  printParameterConfigInfo(textPrintFlag, "--fc-only",
                           pref->printFcOnly == TRUE ? "Yes" : "No",
                           "No");
  
  printParameterConfigInfo(textPrintFlag, "--no-fc",
                           pref->printIpOnly == TRUE ? "Yes" : "No",
                           "No");

  printParameterConfigInfo(textPrintFlag, "--no-invalid-lun",
                           pref->noInvalidLunDisplay == TRUE ? "Yes" : "No",
                           "No");

  printParameterConfigInfo(textPrintFlag, "--p3p-cp",
                           ((pref->P3Pcp == NULL) ||
                            (pref->P3Pcp[0] == '\0')) ? "none" :
                           pref->P3Pcp,
                           "none");

  printParameterConfigInfo(textPrintFlag, "--p3p-uri",
                           ((pref->P3Puri == NULL) ||
                            (pref->P3Puri[0] == '\0')) ? "none" :
                           pref->P3Puri,
                           "none");

#if !defined(WIN32) && defined(HAVE_PCAP_SETNONBLOCK)
  printParameterConfigInfo(textPrintFlag, "--set-pcap-nonblocking",
                           pref->setNonBlocking == TRUE ? "Yes" : "No",
                           "No");
#endif

#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  printParameterConfigInfo(textPrintFlag, "--ssl-watchdog",
                           pref->useSSLwatchdog == 1 ? "Yes" : "No",
                           "No");
#endif

  printParameterConfigInfo(textPrintFlag, "--w3c",
                           pref->w3c == TRUE ? "Yes" : "No",
                           "No");

  if(textPrintFlag == FALSE) {
    sendString("<tr><td colspan=\"2\">"
               "<p><i><b>NOTE</b>: The --w3c flag makes the generated html MORE compatible with "
               "the w3c recommendations, but it in no way addresses all of the compatibility "
               "and markup issues.  We would like to make <b>ntop</b> more compatible, but "
               "some basic issues of looking decent on real-world browsers mean it will "
               "never be 100%.  If you find any issues, please report them to ntop-dev."
               "</i></p></td></tr>\n");
  }

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
  
  if(pref->webPort != 0) {
    if(pref->webAddr != 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "http://%s:%d", pref->webAddr, pref->webPort);
    } else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "http://any:%d", pref->webPort);
    }
    printFeatureConfigInfo(textPrintFlag, "Web server URL", buf);
  } else {
    printFeatureConfigInfo(textPrintFlag, "Web server (http://)", "Not Active");
  }

#ifdef HAVE_OPENSSL
  if(pref->sslPort != 0) {
    if(pref->sslAddr != 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "https://%s:%d", pref->sslAddr, pref->sslPort);
    } else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "https://any:%d", pref->sslPort);
    }
    printFeatureConfigInfo(textPrintFlag, "SSL Web server URL", buf);
  } else {
    printFeatureConfigInfo(textPrintFlag, "SSL Web server (https://)", "Not Active");
  }
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

#ifdef MAKE_WITH_ZLIB
  printFeatureConfigInfo(textPrintFlag, "zlib version", (char*)zlibVersion());
#else
  printFeatureConfigInfo(textPrintFlag, "zlib version", "disabled via --without-zlib");
#endif

  /*
   * If we've guessed at the gd version, report it
   */
if(myGlobals.gdVersionGuessValue != NULL)
  printFeatureConfigInfo(textPrintFlag, "gd version (guess)", myGlobals.gdVersionGuessValue);

#ifdef MAKE_WITH_XMLDUMP
  printFeatureConfigInfo(textPrintFlag, "XML dump (plugins/xmldump)", "Supported");
#endif

  /* *************************** */

  printFeatureConfigInfo(textPrintFlag, "Protocol Decoders",    pref->enablePacketDecoding == 1 ? "Enabled" : "Disabled");
  printFeatureConfigInfo(textPrintFlag, "Fragment Handling", myGlobals.enableFragmentHandling == 1 ? "Enabled" : "Disabled");
  printFeatureConfigInfo(textPrintFlag, "Tracking only local hosts", pref->trackOnlyLocalHosts == 1 ? "Yes" : "No");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numIpProtosToMonitor);
  printFeatureConfigInfo(textPrintFlag, "# IP Protocols Being Monitored", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numActServices);
  printFeatureConfigInfo(textPrintFlag, "# Protocol slots", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.ipPortMapper.numElements);
  printFeatureConfigInfo(textPrintFlag, "# IP Ports Being Monitored", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.ipPortMapper.numSlots);
  printFeatureConfigInfo(textPrintFlag, "# IP Ports slots", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.webServerRequestQueueLength);
  printFeatureConfigInfo(textPrintFlag, "WebServer Request Queue", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numDevices);
  printFeatureConfigInfo(textPrintFlag, "Devices (Network Interfaces)", buf);

  printFeatureConfigInfo(textPrintFlag, "Domain name (short)", myGlobals.shortDomainName);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.ipCountryCount);
  printFeatureConfigInfo(textPrintFlag, "IP to country flag table (entries)", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.hashCollisionsLookup);
  printFeatureConfigInfo(textPrintFlag, "Total Hash Collisions (Vendor/Special) (lookup)", buf);

  /* ******************** */
  buf[0] = '\0';
  for(i=0; i<myGlobals.numLocalNetworks; i++) {
    struct in_addr addr1, addr2;
    char buf1[64];
    
    addr1.s_addr = myGlobals.localNetworks[i][CONST_NETWORK_ENTRY];
    addr2.s_addr = myGlobals.localNetworks[i][CONST_NETMASK_ENTRY];
    
    safe_snprintf(__FILE__, __LINE__, buf1, sizeof(buf1), "%s/%s [all devices]\n", 
		_intoa(addr1, buf1, sizeof(buf1)),
		_intoa(addr2, buf2, sizeof(buf2)));
    
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s%s", buf, buf1);
  }
 
  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.device[i].activeDevice) {
      char buf1[128], buf3[64];
      safe_snprintf(__FILE__, __LINE__, buf1, sizeof(buf1), "%s/%s [device %s]\n",
		  _intoa(myGlobals.device[i].network, buf2, sizeof(buf2)),
		  _intoa(myGlobals.device[i].netmask, buf3, sizeof(buf3)),
		  myGlobals.device[i].humanFriendlyName);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s%s", buf, buf1);
    }
  }

  sendString(texthtml("\n\nntop Web Server\n\n",
                      "<tr><th colspan=\"2\" "DARK_BG">ntop Web Server</th></tr>\n"
                      "<tr><td colspan=\"2\" align=\"center\">\n"
                        "<table BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>\n"));

  sendString(texthtml("Item..................http://...................https://",
                      "<tr><th>Item</th><th>http://</th><th>https://</th></tr>\n"));

  printFeatureConfigInfo3ColInt(textPrintFlag, 
                                "# Handled Requests",
                                pref->webPort,
                                myGlobals.numHandledRequests[1], 
#ifdef HAVE_OPENSSL
                                pref->sslPort,
#else
				0,
#endif
                                myGlobals.numHandledRequests[0],
                                TRUE);
  printFeatureConfigInfo3ColInt(textPrintFlag, 
                                "# Successful requests (200)",
                                pref->webPort,
                                myGlobals.numSuccessfulRequests[1], 
#ifdef HAVE_OPENSSL
                                pref->sslPort,
#else
				0,
#endif
                                myGlobals.numSuccessfulRequests[0],
                                TRUE);
  printFeatureConfigInfo3ColInt(textPrintFlag, 
                                "# Bad (We don't want to talk with you) requests",
                                pref->webPort,
                                myGlobals.numHandledBadrequests[1], 
#ifdef HAVE_OPENSSL
                                pref->sslPort,
#else
				0,
#endif
                                myGlobals.numHandledBadrequests[0],
                                TRUE);
  printFeatureConfigInfo3ColInt(textPrintFlag, 
                                "# Invalid requests - 400 BAD REQUEST",
                                pref->webPort,
                                myGlobals.numUnsuccessfulInvalidrequests[1], 
#ifdef HAVE_OPENSSL
                                pref->sslPort,
#else
				0,
#endif
                                myGlobals.numUnsuccessfulInvalidrequests[0],
                                FALSE);
  printFeatureConfigInfo3ColInt(textPrintFlag, 
                                "# Invalid requests - 401 DENIED",
                                pref->webPort,
                                myGlobals.numUnsuccessfulDenied[1], 
#ifdef HAVE_OPENSSL
                                pref->sslPort,
#else
				0,
#endif
                                myGlobals.numUnsuccessfulDenied[0],
                                FALSE);
  printFeatureConfigInfo3ColInt(textPrintFlag, 
                                "# Invalid requests - 403 FORBIDDEN",
                                pref->webPort,
                                myGlobals.numUnsuccessfulForbidden[1], 
#ifdef HAVE_OPENSSL
                                pref->sslPort,
#else
				0,
#endif
                                myGlobals.numUnsuccessfulForbidden[0],
                                TRUE);
  printFeatureConfigInfo3ColInt(textPrintFlag, 
                                "# Invalid requests - 404 NOT FOUND",
                                pref->webPort,
                                myGlobals.numUnsuccessfulNotfound[1], 
#ifdef HAVE_OPENSSL
                                pref->sslPort,
#else
				0,
#endif
                                myGlobals.numUnsuccessfulNotfound[0],
                                TRUE);
  printFeatureConfigInfo3ColInt(textPrintFlag, 
                                "# Invalid requests - 408 TIMEOUT",
                                pref->webPort,
                                myGlobals.numUnsuccessfulTimeout[1], 
#ifdef HAVE_OPENSSL
                                pref->sslPort,
#else
				0,
#endif
                                myGlobals.numUnsuccessfulTimeout[0],
                                FALSE);
  printFeatureConfigInfo3ColInt(textPrintFlag, 
                                "# Invalid requests - 501 NOT IMPLEMENTED",
                                pref->webPort,
                                myGlobals.numUnsuccessfulInvalidmethod[1], 
#ifdef HAVE_OPENSSL
                                pref->sslPort,
#else
				0,
#endif
                                myGlobals.numUnsuccessfulInvalidmethod[0],
                                FALSE);
  printFeatureConfigInfo3ColInt(textPrintFlag, 
                                "# Invalid requests - 505 INVALID VERSION",
                                pref->webPort,
                                myGlobals.numUnsuccessfulInvalidversion[1], 
#ifdef HAVE_OPENSSL
                                pref->sslPort,
#else
				0,
#endif
                                myGlobals.numUnsuccessfulInvalidversion[0],
                                FALSE);
  sendString(texthtml("",
                      "<tr><td colspan=\"3\">Notes: "
                          "<li>Counts may not total because of in-process requests."
                          "<li>Each request to the ntop web server - frameset, individual "
                          "page, chart, etc. is counted separately"
                          "</td>\n"
                      "</table>\n</td></tr>\n"));

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numHandledSIGPIPEerrors);
  printFeatureConfigInfo(textPrintFlag, "# Handled SIGPIPE Errors", buf);

#ifdef MAKE_WITH_SSLWATCHDOG
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  if(pref->useSSLwatchdog == 1)
#endif
    {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numHTTPSrequestTimeouts);
      printFeatureConfigInfo(textPrintFlag, "# HTTPS Request Timeouts", buf);
    }
#endif

#if defined(HAVE_MALLINFO_MALLOC_H) && defined(HAVE_MALLOC_H) && defined(__GNUC__)
  sendString(texthtml("\n\nMemory allocation - data segment\n\n", "<tr><th colspan=2 "DARK_BG">Memory allocation - data segment</th></tr>\n"));

  memStats = mallinfo();

#ifdef HAVE_SYS_RESOURCE_H
  getrlimit(RLIMIT_DATA, &rlim);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)rlim.rlim_cur);
  printFeatureConfigInfo(textPrintFlag, "arena limit, getrlimit(RLIMIT_DATA, ...)", buf);
#endif

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", memStats.ordblks);
  printFeatureConfigInfo(textPrintFlag, "Allocated blocks (ordblks)", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", memStats.arena);
  printFeatureConfigInfo(textPrintFlag, "Allocated (arena)", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", memStats.uordblks);
  printFeatureConfigInfo(textPrintFlag, "Used (uordblks)", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", memStats.fordblks);
  printFeatureConfigInfo(textPrintFlag, "Free (fordblks)", buf);

  if(memStats.uordblks + memStats.fordblks != memStats.arena)
    printFeatureConfigInfo(textPrintFlag, "WARNING:", "Used+Free != Allocated");

  sendString(texthtml("\n\nMemory allocation - mmapped\n\n", "<tr><th colspan=2 "DARK_BG">Memory allocation - mmapped</th></tr>\n"));

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", memStats.hblks);
  printFeatureConfigInfo(textPrintFlag, "Allocated blocks (hblks)", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", memStats.hblkhd);
  printFeatureConfigInfo(textPrintFlag, "Allocated bytes (hblkhd)", buf);

#endif

  if(textPrintFlag == TRUE) {
    sendString(texthtml("\n\nMemory Usage\n\n", "<tr><th colspan=2 "DARK_BG">Memory Usage</th></tr>\n"));

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.ipxsapHashLoadSize);
    printFeatureConfigInfo(textPrintFlag, "IPX/SAP Hash Size (bytes)", buf);
  
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d (%.1f MB)", myGlobals.ipCountryMem, (float)myGlobals.ipCountryMem/(1024.0*1024.0));
    printFeatureConfigInfo(textPrintFlag, "IP to country flag table (bytes)", buf);

    if(myGlobals.ipCountryCount > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.1f", (float)myGlobals.ipCountryMem/myGlobals.ipCountryCount);
      printFeatureConfigInfo(textPrintFlag, "Bytes per entry", buf);
    }

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d (%.1f MB)", myGlobals.asMem, (float)myGlobals.asMem/(1024.0*1024.0));
    printFeatureConfigInfo(textPrintFlag, "IP to AS (Autonomous System) number table (bytes)", buf);

#if defined(HAVE_MALLINFO_MALLOC_H) && defined(HAVE_MALLOC_H) && defined(__GNUC__)

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", memStats.arena + memStats.hblkhd);
    printFeatureConfigInfo(textPrintFlag, "Current memory usage", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.baseMemoryUsage);
    printFeatureConfigInfo(textPrintFlag, "Base memory usage", buf);

    for(i=0; i<myGlobals.numDevices; i++)
      totalHostsMonitored += myGlobals.device[i].hostsno;

    if(totalHostsMonitored > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d = (%d + %d)", 
		  totalHostsMonitored + myGlobals.hostsCacheLen,
		  totalHostsMonitored,
		  myGlobals.hostsCacheLen);
      printFeatureConfigInfo(textPrintFlag, "Hosts stored (active+cache)", buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.1fKB", 
		  ((float)(memStats.arena + memStats.hblkhd - myGlobals.baseMemoryUsage) /
		   (float)(totalHostsMonitored + myGlobals.hostsCacheLen) /
		   1024.0 + 0.05));
      printFeatureConfigInfo(textPrintFlag, "(very) Approximate memory per host", buf);
    }
#endif
  }

  sendString(texthtml("\n\nHost Memory Cache\n\n", "<tr><th colspan=2 "DARK_BG">Host Memory Cache</th></tr>\n"));

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
              "#define MAX_HOSTS_CACHE_LEN %d", MAX_HOSTS_CACHE_LEN);
  printFeatureConfigInfo(textPrintFlag, "Limit", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.hostsCacheLen);
  printFeatureConfigInfo(textPrintFlag, "Current Size", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.hostsCacheLenMax);
  printFeatureConfigInfo(textPrintFlag, "Maximum Size", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.hostsCacheReused);
  printFeatureConfigInfo(textPrintFlag, "# Entries Reused", buf);

#ifdef PARM_USE_SESSIONS_CACHE
  sendString(texthtml("\n\nSession Memory Cache\n\n", "<tr><th colspan=2 "DARK_BG">Session Memory Cache</th></tr>\n"));

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
              "#define MAX_SESSIONS_CACHE_LEN %d", MAX_SESSIONS_CACHE_LEN);
  printFeatureConfigInfo(textPrintFlag, "Limit", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.sessionsCacheLen);
  printFeatureConfigInfo(textPrintFlag, "Current Size", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.sessionsCacheLenMax);
  printFeatureConfigInfo(textPrintFlag, "Maximum Size", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.sessionsCacheReused);
  printFeatureConfigInfo(textPrintFlag, "# Entries Reused", buf);
#endif

  if(textPrintFlag == TRUE) {
    sendString(texthtml("\n\nMAC/IPX Hash tables\n\n", "<tr><th colspan=2 "DARK_BG">MAC/IPX Hash Tables</th></tr>\n"));

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", MAX_IPXSAP_NAME_HASH);
    printFeatureConfigInfo(textPrintFlag, "IPX/SAP Hash Size (entries)", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.ipxsapHashLoadCollisions);
    printFeatureConfigInfo(textPrintFlag, "IPX/SAP Hash Collisions (load)", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.hashCollisionsLookup);
    printFeatureConfigInfo(textPrintFlag, "IPX/SAP Hash Collisions (use)", buf);
  }

  /* **** */

  sendString(texthtml("\n\nPackets\n\n", "<tr><th colspan=2 "DARK_BG">Packets</th></tr>\n"));

#ifdef CFG_MULTITHREADED
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.receivedPackets);
  printFeatureConfigInfo(textPrintFlag, "Received", buf);
#endif

#ifdef CFG_MULTITHREADED
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.receivedPacketsProcessed);
  printFeatureConfigInfo(textPrintFlag, "Processed Immediately", buf);
#endif

#ifdef CFG_MULTITHREADED
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.receivedPacketsQueued);
  printFeatureConfigInfo(textPrintFlag, "Queued", buf);

  if(myGlobals.receivedPacketsLostQ > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.receivedPacketsLostQ);
    printFeatureConfigInfo(textPrintFlag, "Lost in ntop queue", buf);
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.packetQueueLen);
  printFeatureConfigInfo(textPrintFlag, "Current Queue", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.maxPacketQueueLen);
  printFeatureConfigInfo(textPrintFlag, "Maximum Queue", buf);

#if !defined(WIN32) && defined(HAVE_PCAP_SETNONBLOCK)
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.setNonBlockingSleepCount);
  printFeatureConfigInfo(textPrintFlag, "--set-pcap-nonblocking sleep count", buf);
#endif

#endif

  /* **** */

  sendString(texthtml("\n\nHost/Session counts - global\n\n",
		      "<tr><th colspan=2 "DARK_BG">Host/Session counts - global</th></tr>\n"));

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%u", (unsigned int)myGlobals.numPurgedHosts);
  printFeatureConfigInfo(textPrintFlag, "Purged Hosts", buf);

#ifdef MAX_HOSTS_PURGE_PER_CYCLE
  if(textPrintFlag == TRUE) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", MAX_HOSTS_PURGE_PER_CYCLE);
    printFeatureConfigInfo(textPrintFlag, "MAX_HOSTS_PURGE_PER_CYCLE", buf);
  }
#endif

  if(pref->enableSessionHandling) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
	formatPkts(myGlobals.numTerminatedSessions, buf2, sizeof(buf2)));
    printFeatureConfigInfo(textPrintFlag, "Terminated Sessions", buf);
  }

  /* **** */

  for(i=0; i<myGlobals.numDevices; i++) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "\nHost/Session counts - Device %d (%s)\n", i, myGlobals.device[i].name);
    safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "<tr><th colspan=2 "DARK_BG">Host/Session counts - Device %d (%s)</th></tr>\n",
		i, myGlobals.device[i].name);
    sendString(texthtml(buf, buf2));
    
    printFeatureConfigInfo(textPrintFlag, "Hash Bucket Size",
			   formatBytes(sizeof(HostTraffic), 0, buf, sizeof(buf)));
    
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.device[i].actualHashSize);
    printFeatureConfigInfo(textPrintFlag, "Actual Hash Size", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.device[i].hostsno);
    printFeatureConfigInfo(textPrintFlag, "Stored hosts", buf);
    
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
      
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[min %u][max %u][avg %.1f]", 
		  minLen, maxLen, (float)totBuckets/(float)nonEmptyBuckets);
      printFeatureConfigInfo(textPrintFlag, "Bucket List Length", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.device[i].hashListMaxLookups);
    printFeatureConfigInfo(textPrintFlag, "Max host lookup", buf);

    if(pref->enableSessionHandling) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
		  formatBytes(sizeof(IPSession), 0, buf2, sizeof(buf2)));
      printFeatureConfigInfo(textPrintFlag, "Session Bucket Size", buf);
    
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
		  formatPkts(myGlobals.device[i].numTcpSessions, buf2, sizeof(buf2)));
      printFeatureConfigInfo(textPrintFlag, "Sessions", buf);
      
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s", 
		  formatPkts(myGlobals.device[i].maxNumTcpSessions, buf2, sizeof(buf2)));
      printFeatureConfigInfo(textPrintFlag, "Max Num. Sessions", buf);
    }
  }

  /* **** */

  sendString(texthtml("\n\nAddress Resolution\n\n", "<tr><th colspan=2 "DARK_BG">Address Resolution</th></tr>\n"));

  sendString(texthtml("DNS Sniffed:\n\n", "<tr><th TH "TH_BG" ALIGN=LEFT>DNS Sniffed</th>\n<td><table BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>\n"));

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.dnsSniffCount);
  printFeatureConfigInfo(textPrintFlag, "DNS Packets sniffed", buf);

  if(textPrintFlag == TRUE) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.dnsSniffRequestCount);
    printFeatureConfigInfo(textPrintFlag, "  less 'requests'", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.dnsSniffFailedCount);
    printFeatureConfigInfo(textPrintFlag, "  less 'failed'", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.dnsSniffARPACount);
    printFeatureConfigInfo(textPrintFlag, "  less 'reverse dns' (in-addr.arpa)", buf);
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)(myGlobals.dnsSniffCount
					    - myGlobals.dnsSniffRequestCount
					    - myGlobals.dnsSniffFailedCount
					    - myGlobals.dnsSniffARPACount));
  printFeatureConfigInfo(textPrintFlag, "DNS Packets processed", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.dnsSniffStoredInCache);
  printFeatureConfigInfo(textPrintFlag, "Stored in cache (includes aliases)", buf);

  if(textPrintFlag != TRUE) {
    sendString("</table></td></tr>\n");
  }

  if(textPrintFlag == TRUE) {
    sendString("\n\nIP to name - ipaddr2str():\n\n");

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numipaddr2strCalls);
    printFeatureConfigInfo(textPrintFlag, "Total calls", buf);

    if(myGlobals.numipaddr2strCalls != myGlobals.numFetchAddressFromCacheCalls) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numFetchAddressFromCacheCalls);
      printFeatureConfigInfo(textPrintFlag, "ERROR: cache fetch attempts != ipaddr2str() calls", buf);
    }

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numFetchAddressFromCacheCallsOK);
    printFeatureConfigInfo(textPrintFlag, "....OK", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)(myGlobals.numipaddr2strCalls
					      - myGlobals.numFetchAddressFromCacheCallsOK));
    printFeatureConfigInfo(textPrintFlag, "....Total not found", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numFetchAddressFromCacheCallsFAIL);
    printFeatureConfigInfo(textPrintFlag, "........Not found in cache", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numFetchAddressFromCacheCallsSTALE);
    printFeatureConfigInfo(textPrintFlag, "........Too old in cache", buf);
  }

#if defined(CFG_MULTITHREADED) && defined(MAKE_ASYNC_ADDRESS_RESOLUTION)

  if(pref->numericFlag == 0) {
    sendString(texthtml("\n\nQueued - dequeueAddress():\n\n", "<tr><TH "TH_BG" ALIGN=LEFT>Queued</th>\n<td><table BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>\n"));

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.addressQueuedCount);
    printFeatureConfigInfo(textPrintFlag, "Total Queued", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.addressQueuedDup);
    printFeatureConfigInfo(textPrintFlag, "Not queued (duplicate)", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.addressQueuedMax);
    printFeatureConfigInfo(textPrintFlag, "Maximum Queued", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.addressQueuedCurrent);
    printFeatureConfigInfo(textPrintFlag, "Current Queue", buf);

    if(textPrintFlag != TRUE) {
      sendString("</table></td></tr>\n");
    }
  }

#endif

  if(textPrintFlag == TRUE) {
    sendString("\n\nResolved - resolveAddress():\n\n");

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numResolveAddressCalls);
    printFeatureConfigInfo(textPrintFlag, "Addresses to resolve", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numResolveNoCacheDB);
    printFeatureConfigInfo(textPrintFlag, "....less 'Error: No cache database'", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numResolvedFromCache);
    printFeatureConfigInfo(textPrintFlag, "....less 'Found in ntop cache'", buf);

#ifdef PARM_USE_HOST
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numResolvedFromHostAddresses);
    printFeatureConfigInfo(textPrintFlag, "....less 'Resolved from /usr/bin/host'", buf);
#endif

#ifdef PARM_USE_HOST
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)(myGlobals.numResolveAddressCalls
					 - myGlobals.numResolvedFromHostAddresses
					 - myGlobals.numResolveNoCacheDB
					 - myGlobals.numResolvedFromCache));
#else
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)(myGlobals.numResolveAddressCalls
					 - myGlobals.numResolveNoCacheDB
					 - myGlobals.numResolvedFromCache));
#endif

    printFeatureConfigInfo(textPrintFlag, "Gives: # gethost (DNS lookup) calls", buf);

    if((myGlobals.numResolveAddressCalls
#ifdef PARM_USE_HOST
	- myGlobals.numResolvedFromHostAddresses
#endif
	- myGlobals.numResolveNoCacheDB
	- myGlobals.numResolvedFromCache) != myGlobals.numAttemptingResolutionWithDNS) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numAttemptingResolutionWithDNS);
      printFeatureConfigInfo(textPrintFlag, "    ERROR: actual count does not match!", buf);
    }
  }

  sendString(texthtml("\n\nDNS Lookup Calls:\n\n", "<tr><TH "TH_BG" ALIGN=LEFT>DNS Lookup Calls</th>\n<td><table BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>\n"));

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numAttemptingResolutionWithDNS);
  printFeatureConfigInfo(textPrintFlag, "DNS resolution attempts", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numResolvedWithDNSAddresses);
  printFeatureConfigInfo(textPrintFlag, "....Success: Resolved", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)(myGlobals.numDNSErrorHostNotFound
					    + myGlobals.numDNSErrorNoData
					    + myGlobals.numDNSErrorNoRecovery
					    + myGlobals.numDNSErrorTryAgain
					    + myGlobals.numDNSErrorOther));
  printFeatureConfigInfo(textPrintFlag, "....Failed", buf);

  if(textPrintFlag == TRUE) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numDNSErrorHostNotFound);
    printFeatureConfigInfo(textPrintFlag, "........HOST_NOT_FOUND", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numDNSErrorNoData);
    printFeatureConfigInfo(textPrintFlag, "........NO_DATA", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numDNSErrorNoRecovery);
    printFeatureConfigInfo(textPrintFlag, "........NO_RECOVERY", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numDNSErrorTryAgain);
    printFeatureConfigInfo(textPrintFlag, "........TRY_AGAIN (don't store)", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numDNSErrorOther);
    printFeatureConfigInfo(textPrintFlag, "........Other error (don't store)", buf);
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.dnsCacheStoredLookup);
  printFeatureConfigInfo(textPrintFlag, "DNS lookups stored in cache", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numKeptNumericAddresses);
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

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numVendorLookupRead);
    printFeatureConfigInfo(textPrintFlag, "Input lines read", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numVendorLookupAdded);
    printFeatureConfigInfo(textPrintFlag, "Records added total", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numVendorLookupAddedSpecial);
    printFeatureConfigInfo(textPrintFlag, ".....includes special records", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numVendorLookupCalls);
    printFeatureConfigInfo(textPrintFlag, "getVendorInfo() calls", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numVendorLookupSpecialCalls);
    printFeatureConfigInfo(textPrintFlag, "getSpecialVendorInfo() calls", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numVendorLookupFound48bit);
    printFeatureConfigInfo(textPrintFlag, "Found 48bit (xx:xx:xx:xx:xx:xx) match", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numVendorLookupFound24bit);
    printFeatureConfigInfo(textPrintFlag, "Found 24bit (xx:xx:xx) match", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numVendorLookupFoundMulticast);
    printFeatureConfigInfo(textPrintFlag, "Found multicast bit set", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numVendorLookupFoundLAA);
    printFeatureConfigInfo(textPrintFlag, "Found LAA (Locally assigned address) bit set", buf);

  }

  /* **** */

#if defined(CFG_MULTITHREADED)
  sendString(texthtml("\n\nThread counts\n\n", "<tr><th colspan=2 "DARK_BG">Thread counts</th></tr>\n"));

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numThreads);
  printFeatureConfigInfo(textPrintFlag, "Active", buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numDequeueThreads);
  printFeatureConfigInfo(textPrintFlag, "Dequeue", buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numChildren);
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
      if(!addrnull(&myGlobals.weDontWantToTalkWithYou[i].addr)) {
	if(++countBadGuys == 1) {
	  sendString(texthtml("\n\nIP Address reject list\n\n",
			      "<tr><th colspan=2 "DARK_BG">IP Address reject list</th></tr>\n"));
	  sendString(texthtml("\nAddress ... Count ... Last Bad Access ... Lockout Expires\n",
			      "<tr><th>Rejects</th>"
			      "<td><TABLE BORDER=1>"
			      "<tr><th>Address</th><th>Count</th>"
			      "<th>Last Bad Access</th><th>Lockout Expires</th></tr>"));
	}
      
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s", 
		    _addrtostr(&myGlobals.weDontWantToTalkWithYou[i].addr, buf3, sizeof(buf3)));
	safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "%d", myGlobals.weDontWantToTalkWithYou[i].count);
	strftime(buf3, sizeof(buf3), CONST_LOCALE_TIMESPEC, 
		 localtime_r(&myGlobals.weDontWantToTalkWithYou[i].lastBadAccess, &t));
	lockoutExpires = myGlobals.weDontWantToTalkWithYou[i].lastBadAccess + 
	  PARM_WEDONTWANTTOTALKWITHYOU_INTERVAL;
	strftime(buf4, sizeof(buf4), CONST_LOCALE_TIMESPEC, localtime_r(&lockoutExpires, &t));
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

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", PARM_WEDONTWANTTOTALKWITHYOU_INTERVAL);
      printFeatureConfigInfo(textPrintFlag, "Reject duration (seconds)", buf);
  
      strftime(buf, sizeof(buf), CONST_LOCALE_TIMESPEC, localtime_r(&myGlobals.actTime, &t));
      printFeatureConfigInfo(textPrintFlag, "It is now", buf);
    }

  }
#endif

  /* **** */

#ifdef MEMORY_DEBUG
  printFeatureConfigInfo(textPrintFlag, "Allocated Memory",
                         formatBytes(myGlobals.allocatedMemory, 0, buf, sizeof(buf)));
#endif

  /* **** */

  sendString(texthtml("Directory (search) order\n\n", "<tr><th colspan=2 "DARK_BG">Directory (search) order</th></tr>\n"));

  bufLength = sizeof(buf);
  bufPosition = 0;
  bufUsed = 0;

  for(i=0; myGlobals.dataFileDirs[i] != NULL; i++) {
    bufUsed = safe_snprintf(__FILE__, __LINE__, &buf[bufPosition],
			   bufLength,
			   "%s%s\n",
			   i > 0 ? "                " : "",
			   myGlobals.dataFileDirs[i]);
    if(bufUsed == 0) bufUsed = strlen(&buf[bufPosition]); /* Win32 patch */
    if(bufUsed > 0) {
      bufPosition += bufUsed;
      bufLength   -= bufUsed;
    }
  }
  printFeatureConfigInfo(textPrintFlag, "Data Files", buf);

  bufLength = sizeof(buf);
  bufPosition = 0;
  bufUsed = 0;

  for(i=0; myGlobals.configFileDirs[i] != NULL; i++) {
    bufUsed = safe_snprintf(__FILE__, __LINE__, &buf[bufPosition],
			   bufLength,
			   "%s%s\n",
			   i > 0 ? "                  " : "",
			   myGlobals.configFileDirs[i]);
    if(bufUsed == 0) bufUsed = strlen(&buf[bufPosition]); /* Win32 patch */
    if(bufUsed > 0) {
      bufPosition += bufUsed;
      bufLength   -= bufUsed;
    }
  }
  printFeatureConfigInfo(textPrintFlag, "Config Files", buf);

  bufLength = sizeof(buf);
  bufPosition = 0;
  bufUsed = 0;

  for(i=0; myGlobals.pluginDirs[i] != NULL; i++) {
    bufUsed = safe_snprintf(__FILE__, __LINE__, &buf[bufPosition],
			   bufLength, "%s%s\n",
			   i > 0 ? "             " : "",
			   myGlobals.pluginDirs[i]);
    if(bufUsed == 0) bufUsed = strlen(&buf[bufPosition]); /* Win32 patch */
    if(bufUsed > 0) {
      bufPosition += bufUsed;
      bufLength   -= bufUsed;
    }
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
 #if defined(__GNUC_PATCHLEVEL__)
  #define PATCHLEVEL __GNUC_PATCHLEVEL__
 #else
  #define PATCHLEVEL 0
 #endif
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s (%d.%d.%d)",
	      __VERSION__, 
              __GNUC__, 
              __GNUC_MINOR__, 
              PATCHLEVEL);
  printFeatureConfigInfo(textPrintFlag, "GNU C (gcc) version", buf);
 #undef PATCHLEVEL

#if defined(HAVE_SYS_UTSNAME_H) && defined(HAVE_UNAME)
  if (uname(&unameData) == 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "sysname(%s) release(%s) version(%s) machine(%s)",
                         unameData.sysname,
                         unameData.release,
                         unameData.version,
                         unameData.machine);
    printFeatureConfigInfo(textPrintFlag, "uname data", buf);
  }
#endif

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
    printFeatureConfigInfo(textPrintFlag, "Locale directory (version.c)", locale_dir);
  }

  if(textPrintFlag == TRUE) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"globals-defines.h: #define MAX_LANGUAGES_REQUESTED %d",
		MAX_LANGUAGES_REQUESTED);
    printFeatureConfigInfo(textPrintFlag, "Languages - per request (Accept-Language:)", buf);
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"globals-defines.h: #define MAX_LANGUAGES_SUPPORTED %d",
		MAX_LANGUAGES_SUPPORTED);
    printFeatureConfigInfo(textPrintFlag, "Languages supported - maximum", buf);
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.maxSupportedLanguages + 1);
  printFeatureConfigInfo(textPrintFlag, "Languages supported - actual ", buf);

  printFeatureConfigInfo(textPrintFlag, "Default language", myGlobals.defaultLanguage);

  for(i=0; i< myGlobals.maxSupportedLanguages; i++) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Additional language %d", i+1);
    safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "'%s', time format '%s'", 
		myGlobals.supportedLanguages[i],
		myGlobals.strftimeFormat[i]);
    printFeatureConfigInfo(textPrintFlag, buf, buf2);
  }

#endif /* I18N */

#ifdef HAVE_LOCALE_H
  if(textPrintFlag == TRUE) {
    struct lconv* localeInfo;

    printFeatureConfigInfo(textPrintFlag, "Locale", setlocale(LC_ALL, NULL));

    localeInfo = localeconv();
    if (localeInfo != NULL) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "1%s000%s00", 
                  localeInfo->thousands_sep,
                  localeInfo->decimal_point);
      printFeatureConfigInfo(textPrintFlag, "Numeric format", buf);
    } else {
      printFeatureConfigInfo(textPrintFlag, "Numeric format", "localeconv() returned null");
    }
  }

#endif /* LOCALE */

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
    defined(FC_DEBUG)                  || \
    defined(FINGERPRINT_DEBUG)         || \
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
    defined(UNKNOWN_PACKET_DEBUG)      || \
    defined(URL_DEBUG)
#else
  if(textPrintFlag == TRUE)
#endif
    printNtopConfigHInfo(textPrintFlag);

  /* *************************** */

  sendString(texthtml("\n\n", "</TABLE>"TABLE_OFF"\n"));

  /* **************************** */

#ifdef CFG_MULTITHREADED
 #if !defined(DEBUG) && !defined(WIN32)
  if(pref->debugMode)
 #endif /* DEBUG or WIN32 */
    printMutexStatusReport(textPrintFlag);
#endif /* CFG_MULTITHREADED */

  if(textPrintFlag != TRUE) {
    sendString("<p>Click <a href=\"" CONST_TEXT_INFO_NTOP_HTML "\" alt=\"Text version of this page\">"
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
      printHTMLheader("ntop Log", NULL, BITFLAG_HTTP_NO_CACHE_CONTROL);
      sendString("<HR>");
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<p><font face=\"Helvetica, Arial, Sans Serif\"><center>"
                "This is a rolling display of upto the last %d ntop log messages "
                "of priority INFO or higher.  Click on the \"log\" option, above, to refresh."
                "</center></font></p>", CONST_LOG_VIEW_BUFFER_SIZE);
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
        
        if(myGlobals.logView[j] != NULL) {
            sendString(myGlobals.logView[j]);
            lines++;
            if(myGlobals.logView[j][strlen(myGlobals.logView[j])-1] != '\n');
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
  char buf[LEN_MEDIUM_WORK_BUFFER];
#ifdef PROBLEMREPORTID_DEBUG
  char buf2[256];
#endif
  static char xvert[] = "JB6XF3PRQHNA7W5ECM8S9GLVY4TDKUZ2"; /* Scrambled just 'cause */
  time_t t;
  unsigned int v, scramble, raw;
  int i, j;

#ifdef HAVE_SYS_UTSNAME_H
  struct utsname unameData;
#endif

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
  strftime(buf, sizeof(buf)-1, CONST_LOCALE_TIMESPEC, gmtime(&t));
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
  safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2),
              "%-12s %48s %8s %8s\n",
              "Item", "Raw value", "Hex", "v value");
  sendString(buf2);
#endif

#ifdef PARM_SHOW_NTOP_HEARTBEAT
  v += myGlobals.heartbeatCounter /* If we have it */ ;
#ifdef PROBLEMREPORTID_DEBUG
  safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "%-12s %48u %08x %08x\n", "Heartbeat", 
	      myGlobals.heartbeatCounter, myGlobals.heartbeatCounter, v);
  sendString(buf2);
#endif
#endif

  v += (unsigned int) t;
#ifdef PROBLEMREPORTID_DEBUG
  strftime(buf, sizeof(buf)-1, CONST_LOCALE_TIMESPEC, gmtime(&t));
  buf[sizeof(buf)-1] = '\0';
  safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "%-12s %48s %08x %08x\n", "Date/Time", buf, t, v);
  sendString(buf2);
#endif

  v += myGlobals.actTime - myGlobals.initialSniffTime;
#ifdef PROBLEMREPORTID_DEBUG
  safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "%-12s %48u %08x %08x\n", "Elapsed",
	   (myGlobals.actTime - myGlobals.initialSniffTime), 
	   (myGlobals.actTime - myGlobals.initialSniffTime), v);
  sendString(buf2);
#endif

  raw = 0;
  for(i=0; i<= myGlobals.numDevices; i++)
    raw += (unsigned int) (myGlobals.device[i].ethernetBytes.value);

#ifdef PROBLEMREPORTID_DEBUG
  safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "%-12s %48u %08x\n", "Bytes", raw, raw);
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
  safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "%-12s %48u %08x %08x\n", "Bytes(scramble)", 
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
    safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "(%2d", j);
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
#if defined(HAVE_SYS_UTSNAME_H) && defined(HAVE_UNAME)
  if (uname(&unameData) == 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "sysname(%s) release(%s) version(%s) machine(%s)",
                         unameData.sysname,
                         unameData.release,
                         unameData.version,
                         unameData.machine);
    sendString("OS(uname): ");
    sendString(buf);
    sendString("\n\n");
  } else {
#endif
  sendString("OS: __________  version: __________\n\n");
#if defined(HAVE_SYS_UTSNAME_H) && defined(HAVE_UNAME)
  }
#endif
  sendString("ntop from: ______________________________ (rpm, source, ports, etc.)\n\n");
  sendString("Hardware:  CPU:           _____ (i86, SPARC, etc.)\n");
  sendString("           # Processors:  _____\n");
  sendString("           Memory:        _____ MB\n");

  sendString("\nPackets\n");

#ifdef CFG_MULTITHREADED
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Received:  %10u\n", myGlobals.receivedPackets);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Processed: %10u (immediately)\n",
              myGlobals.receivedPacketsProcessed);
  sendString(buf);
#endif

#ifdef CFG_MULTITHREADED
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Queued:    %10u\n",
              myGlobals.receivedPacketsQueued);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Lost:      %10u (queue full)\n",
              myGlobals.receivedPacketsLostQ);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Queue:     Current: %u Maximum: %u\n",
              myGlobals.packetQueueLen,
              myGlobals.maxPacketQueueLen);
  sendString(buf);
#endif

  sendString("\nNetwork:\n");

  if(myGlobals.runningPref.mergeInterfaces == 1) {
    sendString("Merged packet counts:\n");
    if(myGlobals.device[0].receivedPkts.value > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Received:  %10u\n",
                  myGlobals.device[0].receivedPkts.value);
      sendString(buf);
    }
    if(myGlobals.device[0].droppedPkts.value > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Dropped:   %10u\n",
                  myGlobals.device[0].droppedPkts.value);
      sendString(buf);
    }
    if(myGlobals.device[0].ethernetPkts.value > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Ethernet:  %10u\n",
                  myGlobals.device[0].ethernetPkts.value);
      sendString(buf);
    }
    if(myGlobals.device[0].broadcastPkts.value > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Broadcast: %10u\n",
                  myGlobals.device[0].broadcastPkts.value);
      sendString(buf);
    }
    if(myGlobals.device[0].multicastPkts.value > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Multicast: %10u\n",
                  myGlobals.device[0].multicastPkts.value);
      sendString(buf);
    }
    if(myGlobals.device[0].ipPkts.value > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     IP:        %10u\n",
                  myGlobals.device[0].ipPkts.value);
      sendString(buf);
    }
    sendString("\n");
  }

  for(i=0; i<myGlobals.numDevices; i++) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Network Interface %2d ", i);
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
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Received (pcap):%10u\n", pcapStats.ps_recv);
      sendString(buf);
      if(pcapStats.ps_ifdrop > 0) {
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Dropped (NIC):  %10u\n", pcapStats.ps_ifdrop);
        sendString(buf);
      }
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Dropped (pcap): %10u\n", pcapStats.ps_drop);
      sendString(buf);
    }
#endif

    if(myGlobals.runningPref.mergeInterfaces == 0) {
      if(myGlobals.device[i].receivedPkts.value > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Received:       %10u\n",
                     myGlobals.device[i].receivedPkts.value);
	sendString(buf);
      }
      if(myGlobals.device[i].droppedPkts.value > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Dropped (ntop): %10u\n",
                     myGlobals.device[i].droppedPkts.value);
	sendString(buf);
      }
      if(myGlobals.device[i].ethernetPkts.value > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Ethernet:       %10u\n",
                     myGlobals.device[i].ethernetPkts.value);
	sendString(buf);
      }
      if(myGlobals.device[i].broadcastPkts.value > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Broadcast:      %10u\n",
                     myGlobals.device[i].broadcastPkts.value);
	sendString(buf);
      }
      if(myGlobals.device[i].multicastPkts.value > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     Multicast:      %10u\n",
                     myGlobals.device[i].multicastPkts.value);
	sendString(buf);
      }
      if(myGlobals.device[i].ipPkts.value > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "     IP:             %10u\n",
                    myGlobals.device[i].ipPkts.value);
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
  if(myGlobals.runningPref.traceLevel >= CONST_NOISY_TRACE_LEVEL) {
    sendString("  (Please cut and paste actual log lines)\n");
  } else {
    if(printNtopLogReport(TRUE) == 0) 
      sendString("  (automated extract unavailable - please cut and paste actual log lines)\n");
  }
  sendString("\n\n\n\n");
  sendString("----------------------------------------------------------------------------\n");
  sendString("Problem Description\n\n\n\n\n\n\n\n\n\n");
  sendString("----------------------------------------------------------------------------\n");
  printNtopConfigInfo(TRUE, &myGlobals.runningPref);
  sendString("----------------------------------------------------------------------------\n");
}

/* **************************************** */

#define sslOrNot (isSSL ? " ssl" : "")

void initSocket(int isSSL, int ipv4or6, int *port, int *sock, char *addr) {
  int sockopt = 1, rc;
#if defined(INET6) && !defined(WIN32)
  struct addrinfo hints, *ai, *aitop;
  char strport[32];
  char ntop[1024];
#endif
#ifdef INITWEB_DEBUG
  char value[LEN_SMALL_WORK_BUFFER];
#endif
#if !(defined(INET6) && !defined(WIN32))
  struct sockaddr_in sockIn;
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
#if defined(INET6) && !defined(WIN32)
  memset(&hints,0,sizeof(hints));
  hints.ai_family = ipv4or6;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_socktype = SOCK_STREAM;
  safe_snprintf(__FILE__, __LINE__, strport,sizeof(strport),"%d",*port);
  if((rc = getaddrinfo(addr,strport,&hints,&aitop)) !=0) {
    traceEvent(CONST_TRACE_ERROR, "INITWEB: getaddrinfo() error %s(%d)", gai_strerror(rc), rc);
    traceEvent(CONST_TRACE_ERROR, "INITWEB: Unable to convert address '%s' - "
               "not binding to a particular interface", addr);
  } else {
    for (ai = aitop; ai; ai = ai->ai_next) {
      if(ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
        continue;
      if(getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop,sizeof(ntop),
                     strport, sizeof(strport), NI_NUMERICHOST|NI_NUMERICSERV) != 0){
        traceEvent(CONST_TRACE_ERROR, "INITWEB: getnameinfo() error %s(%d)", gai_strerror(errno), errno);
        traceEvent(CONST_TRACE_ERROR, "INITWEB: Unable to convert address '%s' - "
                   "not binding to a particular interface", addr);
      }else
        break;
    }
  }
#else
  memset(&sockIn, 0, sizeof(sockIn));
  sockIn.sin_family = AF_INET;
  sockIn.sin_port   = (int)htons((unsigned short int)(*port));

#ifndef WIN32
  if(addr) {
    if(!inet_aton(addr, &sockIn.sin_addr)) {
      traceEvent(CONST_TRACE_ERROR, "INITWEB: Unable to convert address '%s' - "
                 "not binding to a particular interface", addr);
      sockIn.sin_addr.s_addr = INADDR_ANY;
    } else {
      traceEvent(CONST_TRACE_INFO, "INITWEB: Converted address '%s' - "
                 "binding to the specific interface", addr);
    }
  } else {
    sockIn.sin_addr.s_addr = INADDR_ANY;
  }
#else
  sockIn.sin_addr.s_addr = INADDR_ANY;
#endif

#ifdef INITWEB_DEBUG
  safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d.%d.%d.%d", \
               (int) ((sockIn.sin_addr.s_addr >> 24) & 0xff), \
               (int) ((sockIn.sin_addr.s_addr >> 16) & 0xff), \
               (int) ((sockIn.sin_addr.s_addr >>  8) & 0xff), \
               (int) ((sockIn.sin_addr.s_addr >>  0) & 0xff)); \
  traceEvent(CONST_TRACE_INFO, "INITWEB_DEBUG: sockIn = %s:%d",
             value,
             ntohs(sockIn.sin_port));
#endif
#endif /* INET6 */
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

      safe_snprintf(__FILE__, __LINE__, myGlobals.tempFname[i], LEN_MEDIUM_WORK_BUFFER, "/tmp/ntop-%09u-%d", myGlobals.tempFpid, i);
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
#if defined(INET6) && !defined(WIN32)
    *sock = socket(ai->ai_family, SOCK_STREAM, 0);
#else
    *sock = socket(AF_INET, SOCK_STREAM, 0);
#endif
    if((*sock <= 0) || (errno != 0) ) {
      {
#if defined(INET6) && !defined(WIN32)
	errno = 0;
	/* It might be that IPv6 is not supported by the running system */
	*sock = socket(AF_INET, SOCK_STREAM, 0);
	if((*sock <= 0) || (errno != 0))
#endif
	  {
	    traceEvent(CONST_TRACE_FATALERROR, "INITWEB: Unable to create a new%s socket - returned %d, error is '%s'(%d)",
		       sslOrNot, *sock, strerror(errno), errno);
	    exit(-1);
	  }
      }
    }
    traceEvent(CONST_TRACE_NOISY, "INITWEB: Created a new%s socket (%d)", sslOrNot, *sock);
    
#ifdef INITWEB_DEBUG
  traceEvent(CONST_TRACE_INFO, "INITWEB_DEBUG:%s setsockopt(%d, SOL_SOCKET, SO_REUSEADDR ...",
             sslOrNot, *sock);
#endif

  errno = 0;
  rc = setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));
  if((rc < 0) || (errno != 0)) {
    traceEvent(CONST_TRACE_FATALERROR, "INITWEB: Unable to set%s socket options - '%s'(%d)",
               sslOrNot, strerror(errno), errno);
    exit(-1);
  }
#ifdef INITWEB_DEBUG
  traceEvent(CONST_TRACE_INFO, "INITWEB_DEBUG:%s socket %d, options set", sslOrNot, *sock);
#endif

  errno = 0;
#if defined(INET6) && !defined(WIN32)
  rc = bind(*sock, ai->ai_addr, ai->ai_addrlen);
  if(aitop != NULL)
    freeaddrinfo(aitop);
#else
  rc = bind(*sock, (struct sockaddr *)&sockIn, sizeof(sockIn));
#endif
  if((rc < 0) || (errno != 0)) {
    traceEvent(CONST_TRACE_FATALERROR,
               "INITWEB:%s binding problem - '%s'(%d)",
               sslOrNot, strerror(errno), errno);
    traceEvent(CONST_TRACE_INFO, "Check if another instance of ntop is running"); 
    traceEvent(CONST_TRACE_INFO, "or if the current user (-u) can bind to the specified port"); 
    closeNwSocket(&myGlobals.sock);
    exit(-1);
  }

#ifdef INITWEB_DEBUG
  traceEvent(CONST_TRACE_INFO, "INITWEB_DEBUG:%s socket %d bound", sslOrNot, *sock);
#endif

  errno = 0;
  rc = listen(*sock, myGlobals.webServerRequestQueueLength);
  if((rc < 0) || (errno != 0)) {
    traceEvent(CONST_TRACE_FATALERROR, "INITWEB:%s listen(%d, %d) error %s(%d)",
               sslOrNot,
               *sock,
               myGlobals.webServerRequestQueueLength,
               strerror(errno), errno);
    closeNwSocket(&myGlobals.sock);
    exit(-1);
  }

  traceEvent(CONST_TRACE_INFO, "INITWEB: Initialized%s socket, port %d, address %s",
             sslOrNot,
             *port,
             addr == NULL ? "(any)" : addr);

}

#undef sslOrNot

/* **************************************** */

/* SSL fixes courtesy of Curtis Doty <curtis@greenkey.net>
                         Matthias Kattanek <mattes@mykmk.com> */

void initWeb(void) {

  traceEvent(CONST_TRACE_INFO, "INITWEB: Initializing web server");

  myGlobals.columnSort = 0;
  addDefaultAdminUser(); 
  initAccessLog();

  traceEvent(CONST_TRACE_INFO, "INITWEB: Initializing tcp/ip socket connections for web server");

  if(myGlobals.runningPref.webPort > 0) {
    initSocket(FALSE, myGlobals.runningPref.ipv4or6, &myGlobals.runningPref.webPort, &myGlobals.sock, myGlobals.runningPref.webAddr);
    /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
    if(myGlobals.runningPref.webAddr)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "INITWEB: Waiting for HTTP connections on %s port %d",
		 myGlobals.runningPref.webAddr, myGlobals.runningPref.webPort);
    else
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "INITWEB: Waiting for HTTP connections on port %d",
		 myGlobals.runningPref.webPort);
  }

#ifdef HAVE_OPENSSL
  if((myGlobals.sslInitialized) && (myGlobals.runningPref.sslPort > 0)) {
    initSocket(TRUE, myGlobals.runningPref.ipv4or6, &myGlobals.runningPref.sslPort, &myGlobals.sock_ssl, myGlobals.runningPref.sslAddr);
    if(myGlobals.runningPref.sslAddr)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "INITWEB: Waiting for HTTPS (SSL) connections on %s port %d",
		 myGlobals.runningPref.sslAddr, myGlobals.runningPref.sslPort);
    else
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "INITWEB: Waiting for HTTPS (SSL) connections on port %d",
		 myGlobals.runningPref.sslPort);
  }
#endif

#ifdef CFG_MULTITHREADED
  traceEvent(CONST_TRACE_INFO, "INITWEB: Starting web server");
  createThread(&myGlobals.handleWebConnectionsThreadId, handleWebConnections, NULL);
  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Started thread (%ld) for web server",
	     myGlobals.handleWebConnectionsThreadId);

#ifdef MAKE_WITH_SSLWATCHDOG
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  if(myGlobals.runningPref.useSSLwatchdog == 1)
#endif
    {
      int rc;

      traceEvent(CONST_TRACE_INFO, "INITWEB: Starting https:// watchdog");

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
	myGlobals.runningPref.useSSLwatchdog = 0;
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

  traceEvent(CONST_TRACE_NOISY, "INITWEB: Server started... continuing with initialization");
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

void sslwatchdogSighandler(int signum) {
  /* If this goes off, the ssl_accept() below didn't respond */
  signal(SIGUSR1, SIG_DFL);
  sslwatchdogDebug("->SIGUSR1", FLAG_SSLWATCHDOG_PARENT, "");
  longjmp (sslwatchdogJump, 1);
}

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
    sslwatchdogDebug("Expires", FLAG_SSLWATCHDOG_CHILD, formatTime(&expiration.tv_sec, 0, buf, sizeof(buf)));

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
  if(size < 2)
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
	    traceEvent(CONST_TRACE_ERROR, "SIGPIPE mask, sigemptyset() = %d, gave %p", rc, nset);

	rc = sigaddset(nset, SIGPIPE);
	if(rc != 0)
	    traceEvent(CONST_TRACE_ERROR, "SIGPIPE mask, sigaddset() = %d, gave %p", rc, nset);

#ifndef DARWIN
	rc = pthread_sigmask(SIG_UNBLOCK, NULL, oset);
#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "DEBUG: SIGPIPE mask was pthread_setsigmask(-, NULL, %x) returned %d", 
		   oset, rc);
#endif

	rc = pthread_sigmask(SIG_UNBLOCK, nset, oset);
	if(rc != 0)
	    traceEvent(CONST_TRACE_ERROR, "SIGPIPE mask set, pthread_setsigmask(SIG_UNBLOCK, %x, %x) returned %d", 
		       nset, oset, rc);

	rc = pthread_sigmask(SIG_UNBLOCK, NULL, oset);
#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "DEBUG: SIGPIPE mask is pthread_setsigmask(-, NULL, %x) returned %d", 
		   oset, rc);
#endif
#endif /* DARWIN */

	if(rc == 0) {
	    signal(SIGPIPE, PIPEhandler); 
	    traceEvent(CONST_TRACE_INFO, "Note: SIGPIPE handler set (ignore)");
	}
    }
#endif /* CFG_MULTITHREADED */
#endif /* WIN32 */

    FD_ZERO(&mask);

    if(myGlobals.runningPref.webPort > 0)
	FD_SET((unsigned int)myGlobals.sock, &mask);

#ifdef HAVE_OPENSSL
    if(myGlobals.sslInitialized) {
	FD_SET(myGlobals.sock_ssl, &mask);
	if(myGlobals.sock_ssl > topSock)
	    topSock = myGlobals.sock_ssl;
    }
#endif

    memcpy(&mask_copy, &mask, sizeof(fd_set));

    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "WEB: ntop's web server is now processing requests");

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
#if defined(INET6) && !defined(WIN32)
  struct sockaddr from;
#else
  struct sockaddr_in from;
#endif
  HostAddr remote_ipaddr;
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

  if(myGlobals.newSock > 0) {
#if defined(INET6) && !defined(WIN32)
    if(from.sa_family == AF_INET) {
      addrput(AF_INET, &remote_ipaddr, &(((struct sockaddr_in *)&from)->sin_addr));
    } else if(from.sa_family == AF_INET6)
      addrput(AF_INET6, &remote_ipaddr, &(((struct sockaddr_in6 *)&from)->sin6_addr));
#else
    addrput(AF_INET, &remote_ipaddr, &(((struct sockaddr_in *)&from)->sin_addr));
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
		if(myGlobals.runningPref.useSSLwatchdog == 1)
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
		if(myGlobals.runningPref.useSSLwatchdog == 1)
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

	      handleHTTPrequest(remote_ipaddr);	    
	}
#else
	handleHTTPrequest(remote_ipaddr);
	
#endif /* HAVE_LIBWRAP */

	closeNwSocket(&myGlobals.newSock);
    } else {
	traceEvent(CONST_TRACE_INFO, "Unable to accept HTTP(S) request (errno=%d: %s)", errno, strerror(errno));
    }
}

/* ******************* */

int handlePluginHTTPRequest(char* url) {
  FlowFilterList *flows = myGlobals.flowsList;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "handlePluginHTTPRequest(%s)", url);
#endif

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

	sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
	strncpy(name, flows->pluginStatus.pluginPtr->pluginURLname, sizeof(name));
	name[sizeof(name)-1] = '\0'; /* just in case pluginURLname is too long... */
	if((strlen(name) > 6) && (strcasecmp(&name[strlen(name)-6], "plugin") == 0))
	  name[strlen(name)-6] = '\0';
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),"Status for the \"%s\" Plugin", name);
	printHTMLheader(buf, NULL, BITFLAG_HTML_NO_REFRESH);
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

