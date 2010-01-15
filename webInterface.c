/*
 *  Copyright (C) 1998-2010 Luca Deri <deri@ntop.org>
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

#ifdef PARM_USE_COLOR
static short alternateColor=0;
#endif

/* Forward */
static void handleSingleWebConnection(fd_set *fdmask);

/* **************************************** */

#if(defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H)) || defined(WIN32) || defined(DARWIN)
void showPluginsList(char* pluginName) {
  FlowFilterList *flows = myGlobals.flowsList;
  short doPrintHeader = 0, status_found = 0;
  char tmpBuf[LEN_GENERAL_WORK_BUFFER], *thePlugin, tmpBuf1[LEN_GENERAL_WORK_BUFFER];
  int newPluginStatus = 0, rc=0;

  if(pluginName[0] != '\0') {
    int i;

    thePlugin = pluginName;

    for(i=0; pluginName[i] != '\0'; i++)
      if(pluginName[i] == '=') {
	pluginName[i] = '\0';
	newPluginStatus = atoi(&pluginName[i+1]);
	status_found = 1;
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

	if(status_found) {
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
      }
    }

    if(!thePlugin || (strcmp(flows->pluginStatus.pluginPtr->pluginURLname, thePlugin) == 0)) {

      if(doPrintHeader == 0) {
        printHTMLheader(thePlugin == NULL ? "Available Plugins" : thePlugin, NULL, 0);
        sendString("<CENTER>\n"
	  	   ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n"
		   "<TR "DARK_BG"><TH "TH_BG">View</TH><TH "TH_BG">Configure</TH>\n"
                   "<TH "TH_BG">Description</TH>\n"
		   "<TH "TH_BG">Version</TH><TH "TH_BG">Author</TH>\n"
		   "<TH "TH_BG">Active<br>[click to toggle]</TH>"
		   "</TR>\n");
        doPrintHeader = 1;
      }

      safe_snprintf(__FILE__, __LINE__, tmpBuf1, sizeof(tmpBuf1), 
		    "<A HREF=\"/plugins/%s\"  class=tooltip title=\"Invoke plugin\">%s</A>",
		    flows->pluginStatus.pluginPtr->pluginURLname, flows->pluginStatus.pluginPtr->pluginURLname);

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "<TR "TR_ON" %s><TH "TH_BG" align=\"left\" %s>",
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

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "<TH "TH_BG" align=\"left\" %s>",
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
	safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), 
		      "<TD colspan=\"4\"><font COLOR=\"#FF0000\">%s</font></TD></TR>\n<TR "TR_ON" %s>\n",
		      flows->pluginStatus.pluginPtr->pluginStatusMessage,
		      getRowColor());
	sendString(tmpBuf);
      }

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "<TD "TD_BG" align=\"left\">%s</TD>\n"
		    "<TD "TD_BG" ALIGN=CENTER>%s</TD>\n"
		    "<TD "TD_BG" align=\"left\">%s</TD>\n"
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
  } /* while */

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
  char symIp[256], linkName[256], flag[256], colorSpec[64], vlanStr[8], mapStr[1024];
  char osBuf[128], titleBuf[256], noteBuf[256], noteBufAppend[64], tooltip[256];
  char *dhcpBootpStr, *p2pStr, *multihomedStr, *multivlanedStr, *gwStr, *brStr, *dnsStr, *printStr,
    *smtpStr, *healthStr, *userStr, *httpStr, *ntpStr, *voipHostStr, custom_host_name[128];
  short usedEthAddress=0;
  int i;

  if(el == NULL)
    return("&nbsp;");

  safe_snprintf(__FILE__, __LINE__, symIp, sizeof(symIp), "hostname.%s",
		(el->hostNumIpAddress[0] != '\0') ? el->hostNumIpAddress : el->ethAddressString);

  if(fetchPrefsValue(symIp, custom_host_name, sizeof(custom_host_name)) == -1) {
    custom_host_name[0] = '\0';
  }

#ifdef ENABLE_FC
  if(el->l2Family == FLAG_HOST_TRAFFIC_AF_FC) {
    return makeFcHostLink (el, mode, cutName, TRUE, buf, bufLen);
  }
#endif

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

  if((el->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_NONE)
     || (el->hostResolvedName[0] == '\0') /* Safety check */
     ) {
    /* It's not officially known, so let's do what we can
     */
    if(addrnull(&el->hostIpAddress) && (el->ethAddressString[0] == '\0')) {
      FD_SET(FLAG_BROADCAST_HOST, &el->flags); /* Just to be safe */
      if(mode == FLAG_HOSTLINK_HTML_FORMAT)
        return("<TH "TH_BG" ALIGN=LEFT>&lt;broadcast&gt;</TH>");
      else
        return("&lt;broadcast&gt;");
    }
    if(cmpSerial(&el->hostSerial, &myGlobals.otherHostEntry->hostSerial)) {
      if(mode == FLAG_HOSTLINK_HTML_FORMAT)
        return("<TH "TH_BG" ALIGN=LEFT>&lt;other&gt;<!-- cmpSerial() match --></TH>");
      else
        return("&lt;other&gt;<!-- cmpSerial() match -->");
    }

    /* User other names if we have them, but follow (High->Low) the numerical
     * sequence of FLAG_HOST_SYM_ADDR_TYPE_xxx so it still sorts right
     */
    if((el->hostNumIpAddress[0] != '\0')
       && (!((el->ethAddressString[0] == '\0') && subnetPseudoLocalHost(el)))) {
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
#ifdef ENABLE_FC
    } else if(el->fcCounters->hostNumFcAddress[0] != '\0') {
      strncpy(symIp, el->fcCounters->hostNumFcAddress, sizeof(symIp));
#ifndef CMPFCTN_DEBUG
      if(myGlobals.runningPref.debugMode == 1)
#endif
        safe_snprintf(__FILE__, __LINE__, noteBufAppend, sizeof(noteBufAppend), "<!-- NONE:FC(%s) -->",
		      el->fcCounters->hostNumFcAddress);
      strncat(noteBuf, noteBufAppend, (sizeof(noteBuf) - strlen(noteBuf) - 1));
#endif
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
      if(mode == FLAG_HOSTLINK_HTML_FORMAT)
        return("<TH "TH_BG" ALIGN=LEFT>&lt;unknown&gt;</TH>");
      else
        return("&lt;unknown&gt;");
    }
  } else {
    /* Got it? Use it! */
    strncpy(symIp, el->hostResolvedName, sizeof(symIp));

    if((el->ethAddressString[0] != '\0')
       && subnetPseudoLocalHost(el)
       && hasWrongNetmask(el)
       ) {
      strncpy(linkName, el->ethAddressString, sizeof(linkName));
      usedEthAddress = 1;
    } else
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

    if((el->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_NAME) && (el->ethAddressString[0] != '\0')) {
      strncpy(linkName, addrtostr(&(el->hostIpAddress)), sizeof(linkName));
    } else if((el->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_MAC) &&
	      (symIp[2] != ':') && (el->ethAddressString[0] != '\0')) {
      /* MAC address, one which has already been fixed up with the vendor string -
         set the alt tag */

      if(el->hostResolvedName[0] != '\0')
	safe_snprintf(__FILE__, __LINE__, titleBuf, sizeof(titleBuf), "%s %s",
		      titleBuf, el->hostResolvedName);
      else
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
   *     dhcpBootpStr, multihomedStr, multivlanedStr, gwStr, brStr, dnsStr, printStr,
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
  if(isMultivlaned(el))     multivlanedStr = "&nbsp;" CONST_IMG_MULTIVLANED ; else multivlanedStr = "";
  if(isBridgeHost(el))     brStr = "&nbsp;" CONST_IMG_BRIDGE ; else brStr = "";
  if(gatewayHost(el))      gwStr = "&nbsp;" CONST_IMG_ROUTER ; else gwStr = "";
  if(isVoIPHost(el))       voipHostStr = "&nbsp;" CONST_IMG_VOIP_HOST ; else voipHostStr = "";
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

  vlanStr[0] = '\0';
  if(el->vlanId != NO_VLAN) {
    if(!isMultivlaned(el)) {
      char tmp[256], tmpBuf[64];
      safe_snprintf(__FILE__, __LINE__, vlanStr, sizeof(vlanStr), "-%d", el->vlanId);
      safe_snprintf(__FILE__, __LINE__, tmp, sizeof(tmp), "%s (vlan %s)",
		    symIp, vlan2name(el->vlanId, tmpBuf, sizeof(tmpBuf)));
      safe_snprintf(__FILE__, __LINE__, symIp, sizeof(symIp), "%s", tmp);
    }
  }

  if((el->hostNumIpAddress[0] != '\0')
     && (!subnetPseudoLocalHost(el))
     && (!multicastHost(el))
     && (!privateIPAddress(el))
     && myGlobals.runningPref.mapperURL) {
    buildMapLink(el, mapStr, sizeof(mapStr));
  } else
    mapStr[0] = '\0';

  if(el->hwModel)
    snprintf(tooltip, sizeof(tooltip), "title=\"%s\" class=tooltip", el->hwModel);
  else if(el->description)
    snprintf(tooltip, sizeof(tooltip), "title=\"%s\" class=tooltip", el->description);
  else if(el->fingerprint)
    snprintf(tooltip, sizeof(tooltip), "title=\"%s\" class=tooltip", &el->fingerprint[1]);
  else
    snprintf(tooltip, sizeof(tooltip), " class=tooltip");

  /* Make the hostlink */
  if(mode == FLAG_HOSTLINK_HTML_FORMAT) {
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<th "TH_BG" align=\"left\" nowrap width=\"250\">\n"
		  "<a %s href=\"/%s%s.html\" %s%s%s>%s%s</a>\n"
		  "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s&nbsp;&nbsp;&nbsp;</th>%s\n",
		  tooltip, linkName, vlanStr,
		  titleBuf[0] != '\0' ? "title=\"" : "", titleBuf, titleBuf[0] != '\0' ? "\"" : "",
		  (custom_host_name[0] != '\0') ? custom_host_name : symIp,
		  noteBuf,
		  getOSFlag(el, NULL, 0, osBuf, sizeof(osBuf)),
		  dhcpBootpStr, multihomedStr, multivlanedStr,
		  usedEthAddress ? CONST_IMG_NIC_CARD : "",
		  gwStr, voipHostStr, brStr, dnsStr,
		  printStr, smtpStr, httpStr, ntpStr,
		  healthStr, userStr, p2pStr, mapStr, flag);
  } else if(mode == FLAG_HOSTLINK_TEXT_LITE_FORMAT) {
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "/%s%s.html", linkName, vlanStr);
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<a %s href=\"/%s%s.html\" %s nowrap width=\"250\" %s%s%s>%s%s</a>\n"
		  "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
		  tooltip, linkName, vlanStr,
		  makeHostAgeStyleSpec(el, colorSpec, sizeof(colorSpec)),
		  titleBuf[0] != '\0' ? "title=\"" : "",
		  titleBuf, titleBuf[0] != '\0' ? "\"" : "",
		  (custom_host_name[0] != '\0') ? custom_host_name : symIp,
		  noteBuf,
		  dhcpBootpStr, multihomedStr, multivlanedStr,
		  usedEthAddress ? CONST_IMG_NIC_CARD : "",
		  gwStr, voipHostStr, brStr, dnsStr,
		  printStr, smtpStr, httpStr, ntpStr, healthStr,
		  userStr, p2pStr, mapStr, flag);
  }

  return(buf);
}

/* ******************************* */

char* getHostName(HostTraffic *el, short cutName, char *buf, int bufLen) {
  char *tmpStr;

  if(broadcastHost(el))
    return("broadcast");

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
  char path[256], *img = NULL;
  static char flagBuf[384];
  struct stat buf;
  int rc;

  fillDomainName(el);

  if(el->geo_ip == NULL) {
#if 0
    safe_snprintf(__FILE__, __LINE__, flagBuf, sizeof(flagBuf),
		  "<img class=tooltip alt=\"Local Host\" title=\"Local Host\" "
		  "align=\"middle\" src=\"/statsicons/flags/local.gif\" border=\"0\">");
#endif
    return("&nbsp;");
  }

  if(el->geo_ip->country_code[0] == '\0') {
    safe_snprintf(__FILE__, __LINE__, flagBuf, sizeof(flagBuf),
		  "<img class=tooltip alt=\"Local Host\" title=\"Local Host\" "
		  "align=\"middle\" src=\"/statsicons/flags/local.gif\" border=\"0\">");
  } else {
    char c_buf[16] = { '\0'};
    int i;

    safe_snprintf(__FILE__, __LINE__, c_buf, sizeof(c_buf)-1, "%s", el->geo_ip->country_code);

    for(i=0; c_buf[i] != '\0'; i++) c_buf[i] = tolower(c_buf[i]);

    safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "./html/statsicons/flags/%s.gif", c_buf);
    revertSlashIfWIN32(path, 0);
    rc = stat(path, &buf);

    if(rc != 0) {
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/html/statsicons/flags/%s.gif",
		    CFG_DATAFILE_DIR, c_buf);
      revertSlashIfWIN32(path, 0);
      rc = stat(path, &buf);
    }

    if(rc == 0)
      img = c_buf;

    /* traceEvent(CONST_TRACE_WARNING, "%s", path); */
  }

  if(img == NULL) {
    /* Nothing worked... */
    safe_snprintf(__FILE__, __LINE__, flagBuf, sizeof(flagBuf),
		  "&nbsp;<!-- No flag for %s (%s) -->",
		  el->geo_ip->country_name, el->geo_ip->country_code);
  } else {
    safe_snprintf(__FILE__, __LINE__, flagBuf, sizeof(flagBuf),
		  "<img class=tooltip alt=\"Flag for %s (%s)\" title=\"Flag for %s (%s)\" align=\"middle\" "
		  "src=\"/statsicons/flags/%s.gif\" border=\"0\">",
		  el->geo_ip->country_name, el->geo_ip->country_code,
		  el->geo_ip->country_name, el->geo_ip->country_code,
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
  int i, mwInterface=_interface-1, found = 0;
  char buf[LEN_GENERAL_WORK_BUFFER], *selected;

  printHTMLheader("Network Interface Switch", NULL, BITFLAG_HTML_NO_REFRESH);
  sendString("<HR>\n");

  for(i=0; i<myGlobals.numDevices; i++)
    if(myGlobals.device[i].activeDevice) {
      found = 1;
      break;
    }

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
  } else if((myGlobals.numDevices == 1) || (!found)) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Sorry, you are currently capturing traffic from only a "
		  "single/dummy interface [%s].<br><br>"
		  "</b> This interface switch feature is meaningful only when your ntop "
		  "instance captures traffic from multiple interfaces. <br>You must specify "
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
    u_short do_enable;
    sendString("Available Network Interfaces:</B><P>\n<FORM ACTION=" CONST_SWITCH_NIC_HTML ">\n");

    if(((!myGlobals.device[myGlobals.actualReportDeviceId].virtualDevice)
	|| (myGlobals.device[myGlobals.actualReportDeviceId].sflowGlobals)
	|| (myGlobals.device[myGlobals.actualReportDeviceId].netflowGlobals))
       &&  myGlobals.device[myGlobals.actualReportDeviceId].activeDevice) {
      do_enable = 0;
    } else
      do_enable = 1;

    for(i=0; i<myGlobals.numDevices; i++)
      if(((!myGlobals.device[i].virtualDevice) || (myGlobals.device[i].sflowGlobals)|| (myGlobals.device[i].netflowGlobals))
	 &&  myGlobals.device[i].activeDevice) {
	if((myGlobals.actualReportDeviceId == i) || do_enable)
	  selected = "CHECKED", do_enable = 0;
	else
	  selected = "";

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<INPUT TYPE=radio NAME=interface VALUE=%d %s>&nbsp;%s&nbsp;[id=%d]<br>\n",
		      i+1, selected, myGlobals.device[i].humanFriendlyName, i);
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
  char buf[LEN_GENERAL_WORK_BUFFER];
  time_t theTime = time(NULL);

  memset(&buf, 0, sizeof(buf));

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "WEB: shutdown.html - request has been received - processing");

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
  printHTMLheader("ntop is shutting down...", NULL, BITFLAG_HTML_NO_REFRESH);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                "<p>Shutdown request received %s is being processed, and the "
                "<b>ntop</b> web server is closing down.</p>\n",
                ctime(&theTime));
  sendString(buf);

  theTime = time(NULL) + 2*PARM_SLEEP_LIMIT + 5;
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                "<p>Please allow up to %d seconds (until approximately %s) for all threads to terminate "
                "and the shutdown request to complete.</p>\n"
                "<p>You will not receive further messages.</p>\n",
                2*PARM_SLEEP_LIMIT + 5,
                ctime(&theTime));
  sendString(buf);

  sendString("<!-- trigger actual shutdown after rest of page is retrieved -->\n"
             "<img src=\"/" CONST_SHUTDOWNNOW_NTOP_IMG "\" width=\"0\" height=\"0\">");

  /* Return and let the web page finish up */

}

/* ******************************** */

/*  WARNING WARNING WARNING
 *
 *      Be very careful with closing tags in this section.  The slightest screw-up will cause
 *      browsers other than IE to handle these tables in ways you don't expect (usually making
 *      each cell as wide as the widest, vs. respecting the WIDTH tags.
 *
 */

static void printInfoSectionTitle(int textPrintFlag, char* section) {
  sendString(texthtml("\n\n", "<tr><th "DARK_BG" "TH_BG" colspan=\"3\" width=\"" xstr(CONST_INFOHTML_WIDTH) "\">"));
  sendString(section);
  sendString(texthtml("\n\n", "</th></tr>\n"));
}

static void printInfoSectionNote(int textPrintFlag, char* note) {
  if(textPrintFlag != TRUE) {
    sendString("<tr><td "TD_BG" colspan=\"3\" width=\"" xstr(CONST_INFOHTML_WIDTH) "\">\n"
               "<table "TABLE_DEFAULTS" border=\"0\" width=\"85%\" align=\"right\"><tr><td "TD_BG" valign=\"top\">NOTE:</td>\n"
               "<td class=\"wrap\" align=\"left\"><i>");
    sendString(note);
    sendString("</i></td></tr>\n</table>\n</td></tr>\n");
  }
}

static void printFeatureConfigNum(int textPrintFlag, char* feature, int value) {
  char tmpBuf[32];

  sendString(texthtml("", "<tr><th "DARK_BG" "TH_BG" align=\"left\" width=\"" xstr(CONST_INFOHTML_COL1_WIDTH) "\">"));
  sendString(feature);
  sendString(texthtml(".....", "</th>\n<td "TD_BG" align=\"right\" colspan=\"2\" width=\"" xstr(CONST_INFOHTML_COL23_WIDTH) "\">"));
  safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%d", value);
  sendString(tmpBuf);
  sendString(texthtml("\n", "</td></tr>\n"));
}

static void printFeatureConfigInfoHeader(int textPrintFlag, char *feature) {
  sendString(texthtml("", "<tr><th "DARK_BG" "TH_BG" ALIGN=\"left\" width=\"" xstr(CONST_INFOHTML_COL1_WIDTH) "\">"));
  sendString(feature);
  sendString(texthtml(".....", "</th>\n<td class=\"wrap\" "TD_BG" ALIGN=\"right\" colspan=\"2\" width=\"" xstr(CONST_INFOHTML_COL23_WIDTH) "\">"));
}

static void printFeatureConfigInfoFooter(int textPrintFlag) {
  sendString(texthtml("\n", "</td></tr>\n"));
}

static void printFeatureConfigInfo(int textPrintFlag, char* feature, char* status) {
  char *tmpStr, tmpBuf[LEN_GENERAL_WORK_BUFFER];
  char *strtokState;

  printFeatureConfigInfoHeader(textPrintFlag, feature);

  if((status == NULL) || (status[0] == '\0')) {
    sendString("(nil)");
  } else {
    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%s", status);
    tmpStr = strtok_r(tmpBuf, "\n", &strtokState);
    while(tmpStr != NULL) {
      sendString(tmpStr);
      tmpStr = strtok_r(NULL, "\n", &strtokState);
      if(tmpStr != NULL) {
	sendString(texthtml("\n          ", "<br>"));
      }
    }
  }

  printFeatureConfigInfoFooter(textPrintFlag);
}

static void printFeatureConfigTitle3Col(int textPrintFlag,
                                        char *textTitle,
                                        char *c1, char *c2, char *c3) {
  if(textPrintFlag == TRUE) {
    sendString(textTitle);
  } else {
    sendString("<tr><th "DARK_BG" "TH_BG" align=\"center\" width=\"" xstr(CONST_INFOHTML_COL1_WIDTH) "\">");
    sendString(c1);
    sendString("</th>\n<th "DARK_BG" "TH_BG" align=\"center\" width=\"" xstr(CONST_INFOHTML_COL2_WIDTH) "\">");
    sendString(c2);
    sendString("</th>\n<th "DARK_BG" "TH_BG" align=\"center\" width=\"" xstr(CONST_INFOHTML_COL3_WIDTH) "\">");
    sendString(c3);
    sendString("</th>\n</tr>\n");
  }
}

static void printFeatureConfigInfo3ColInt(int textPrintFlag,
                                          char* feature,
                                          int flag1, int count1,
                                          int flag2, int count2,
                                          int mustShow) {
  char tmpBuf[LEN_GENERAL_WORK_BUFFER];

  if((mustShow == FALSE) && (count1+count2 == 0)) { return; }

  sendString(texthtml("", "<tr><th "DARK_BG" "TH_BG" align=\"left\" width=\"" xstr(CONST_INFOHTML_COL1_WIDTH) "\">"));
  sendString(feature);
  sendString(texthtml(".....", "</th>\n<td "TD_BG" align=\"right\" width=\"" xstr(CONST_INFOHTML_COL2_WIDTH) "\">"));
  if (flag1) {
    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%d", count1);
    sendString(tmpBuf);
  } else {
    sendString("-");
  }
  sendString(texthtml(".....", "</td>\n<td "TD_BG" align=\"right\" width=\"" xstr(CONST_INFOHTML_COL3_WIDTH) "\">"));
  if (flag2) {
    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%d", count2);
    sendString(tmpBuf);
  } else {
    sendString("-");
  }
  sendString(texthtml("\n", "</td></tr>\n"));
}

#ifdef MAX_PROCESS_BUFFER
static void printFeatureConfigInfo3ColFlt6(int textPrintFlag,
                                           char* feature,
                                           int flag1, float value1,
                                           int flag2, float value2,
                                           int mustShow) {
  char tmpBuf[LEN_GENERAL_WORK_BUFFER];

  if((mustShow == FALSE) && (value1 == 0.0) && (value2 == 0.0)) { return; }

  sendString(texthtml("", "<tr><th "DARK_BG" "TH_BG" align=\"left\" width=\"" xstr(CONST_INFOHTML_COL1_WIDTH) "\">"));
  sendString(feature);
  sendString(texthtml(".....", "</th>\n<td "TD_BG" align=\"right\" width=\"" xstr(CONST_INFOHTML_COL2_WIDTH) "\">"));
  if (flag1) {
    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%.6f", value1);
    sendString(tmpBuf);
  } else {
    sendString(texthtml(" ", "&nbsp;"));
  }
  sendString(texthtml(".....", "</td>\n<td "TD_BG" align=\"right\" width=\"" xstr(CONST_INFOHTML_COL3_WIDTH) "\">"));
  if (flag2) {
    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%.6f", value2);
    sendString(tmpBuf);
  } else {
    sendString(texthtml(" ", "&nbsp;"));
  }
  sendString(texthtml("\n", "</td></tr>\n"));
}
#endif

/* ******************************** */

static void printParameterConfigInfo(int textPrintFlag, char* feature, char* status, char* defaultValue) {
  sendString(texthtml("", "<tr><th "DARK_BG" "TH_BG" align=\"left\" width=\"" xstr(CONST_INFOHTML_COL1_WIDTH) "\">"));
  sendString(feature);
  sendString(texthtml(".....", "</th>\n<td "TD_BG" align=\"right\" colspan=\"2\" width=\"" xstr(CONST_INFOHTML_COL23_WIDTH) "\">"));
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
  sendString(texthtml("\n", "</td></tr>\n"));
}

/* ******************************** */

void printNtopConfigHInfo(int textPrintFlag) {
#ifndef WIN32
  char buf[LEN_GENERAL_WORK_BUFFER];
#endif

  printInfoSectionTitle(textPrintFlag, "Compile Time: Debug settings in globals-defines.h");

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

  printFeatureConfigInfo(textPrintFlag, "LATENCY_DEBUG",
#ifdef LATENCY_DEBUG
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

  printFeatureConfigInfo(textPrintFlag, "MUTEX_DEBUG",
#ifdef MUTEX_DEBUG
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

  printFeatureConfigInfo(textPrintFlag, "SESSION_TRACE_DEBUG",
#ifdef SESSION_TRACE_DEBUG
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

  printInfoSectionTitle(textPrintFlag, "Compile Time: config.h");

  /*
   * Drop the autogenerated lines (utils/config_h2.awk) in HERE
   */

  /*                                                       B E G I N
   *
   * Autogenerated from config.h.in and inserted into webInterface.c
   *      Tue Aug 09 16:25:26 CDT 2005
   *
   */

  printFeatureConfigInfo(textPrintFlag, "CFG_ETHER_HEADER_HAS_EA",
#ifdef CFG_ETHER_HEADER_HAS_EA
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_DIRENT_H",
#ifdef HAVE_DIRENT_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_DLADDR",
#ifdef HAVE_DLADDR
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_FINITE",
#ifdef HAVE_FINITE
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_IEEEFP_H",
#ifdef HAVE_IEEEFP_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_ISFINITE",
#ifdef HAVE_ISFINITE
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_ISINF",
#ifdef HAVE_ISINF
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_NET_SNMP_NET_SNMP_CONFIG_H",
#ifdef HAVE_NET_SNMP_NET_SNMP_CONFIG_H
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_SCHED_H",
#ifdef HAVE_SCHED_H
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "HAVE_SCTP",
#ifdef HAVE_SCTP
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_SNMP",
#ifdef HAVE_SNMP
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

  printFeatureConfigInfo(textPrintFlag, "HAVE_STRSIGNAL",
#ifdef HAVE_STRSIGNAL
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

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_JUMBO_FRAMES",
#ifdef MAKE_WITH_JUMBO_FRAMES
                         "yes"
#else
                         "no"
#endif
                         );

  printFeatureConfigInfo(textPrintFlag, "MAKE_WITH_SNMP",
#ifdef MAKE_WITH_SNMP
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

  printFeatureConfigInfo(textPrintFlag, "CFG_xxxxxx_ENDIAN (Hardware Endian)",
#if defined(CFG_LITTLE_ENDIAN)
			 "little"
#elif defined(CFG_BIG_ENDIAN)
			 "big"
#else
			 "unknown"
#endif
			 );

  /* semi auto generated from globals-defines.h */

  printInfoSectionTitle(textPrintFlag, "Compile Time: globals-defines.h");

  /*                                                       B E G I N
   *
   * Autogenerated from globals-defines.h and inserted into webInterface.c
   *      Tue Aug 09 16:25:26 CDT 2005
   *
   */

#ifdef CONST_ABTNTOP_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_ABTNTOP_HTML", CONST_ABTNTOP_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_ABTNTOP_HTML", "undefined");
#endif

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

#ifdef CONST_ADMINPW_QUESTION
  printFeatureConfigInfo(textPrintFlag, "CONST_ADMINPW_QUESTION", CONST_ADMINPW_QUESTION);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_ADMINPW_QUESTION", "undefined");
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

#ifdef CONST_CLUSTER_STATS_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_CLUSTER_STATS_HTML", CONST_CLUSTER_STATS_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_CLUSTER_STATS_HTML", "undefined");
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

#ifdef CONST_CONFIG_NTOP_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_CONFIG_NTOP_HTML", CONST_CONFIG_NTOP_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_CONFIG_NTOP_HTML", "undefined");
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

#ifdef CONST_EDIT_PREFS
  printFeatureConfigInfo(textPrintFlag, "CONST_EDIT_PREFS", CONST_EDIT_PREFS);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_EDIT_PREFS", "undefined");
#endif

#ifdef CONST_ETTERCAP_FINGERPRINT
  printFeatureConfigInfo(textPrintFlag, "CONST_ETTERCAP_FINGERPRINT", CONST_ETTERCAP_FINGERPRINT);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_ETTERCAP_FINGERPRINT", "undefined");
#endif

#ifdef CONST_ETTERCAP_HOMEPAGE
  printFeatureConfigInfo(textPrintFlag, "CONST_ETTERCAP_HOMEPAGE", CONST_ETTERCAP_HOMEPAGE);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_ETTERCAP_HOMEPAGE", "undefined");
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

#ifdef CONST_HANDLEADDRESSLISTS_CLUSTERS
  printFeatureConfigNum(textPrintFlag, "CONST_HANDLEADDRESSLISTS_CLUSTERS", CONST_HANDLEADDRESSLISTS_CLUSTERS);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_HANDLEADDRESSLISTS_CLUSTERS", "undefined");
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

#ifdef CONST_IMG_FC_VEN_EMULEX
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FC_VEN_EMULEX", CONST_IMG_FC_VEN_EMULEX);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_FC_VEN_EMULEX", "undefined");
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

#ifdef CONST_IMG_MULTIVLANED
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_MULTIVLANED", CONST_IMG_MULTIVLANED);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_MULTIVLANED", "undefined");
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

#ifdef CONST_IMG_VOIP_HOST
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_VOIP_HOST", CONST_IMG_VOIP_HOST);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_IMG_VOIP_HOST", "undefined");
#endif

#ifdef CONST_INDEX_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_INDEX_HTML", CONST_INDEX_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_INDEX_HTML", "undefined");
#endif

#ifdef CONST_INDEX_INNER_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_INDEX_INNER_HTML", CONST_INDEX_INNER_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_INDEX_INNER_HTML", "undefined");
#endif

#ifdef CONST_INFOHTML_COL1_WIDTH
  printFeatureConfigNum(textPrintFlag, "CONST_INFOHTML_COL1_WIDTH", CONST_INFOHTML_COL1_WIDTH);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_INFOHTML_COL1_WIDTH", "undefined");
#endif

#ifdef CONST_INFOHTML_COL23_WIDTH
  printFeatureConfigNum(textPrintFlag, "CONST_INFOHTML_COL23_WIDTH", CONST_INFOHTML_COL23_WIDTH);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_INFOHTML_COL23_WIDTH", "undefined");
#endif

#ifdef CONST_INFOHTML_COL2_WIDTH
  printFeatureConfigNum(textPrintFlag, "CONST_INFOHTML_COL2_WIDTH", CONST_INFOHTML_COL2_WIDTH);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_INFOHTML_COL2_WIDTH", "undefined");
#endif

#ifdef CONST_INFOHTML_COL3_WIDTH
  printFeatureConfigNum(textPrintFlag, "CONST_INFOHTML_COL3_WIDTH", CONST_INFOHTML_COL3_WIDTH);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_INFOHTML_COL3_WIDTH", "undefined");
#endif

#ifdef CONST_INFOHTML_WIDTH
  printFeatureConfigNum(textPrintFlag, "CONST_INFOHTML_WIDTH", CONST_INFOHTML_WIDTH);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_INFOHTML_WIDTH", "undefined");
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

#ifdef CONST_UNMAGIC_NUMBER
  printFeatureConfigNum(textPrintFlag, "CONST_UNMAGIC_NUMBER", CONST_UNMAGIC_NUMBER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_UNMAGIC_NUMBER", "undefined");
#endif

#ifdef CONST_MAILTO_ABDELKADER
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_ABDELKADER", CONST_MAILTO_ABDELKADER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_ABDELKADER", "undefined");
#endif

#ifdef CONST_MAILTO_BURTON
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_BURTON", CONST_MAILTO_BURTON);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_BURTON", "undefined");
#endif

#ifdef CONST_MAILTO_DINESH
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_DINESH", CONST_MAILTO_DINESH);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_DINESH", "undefined");
#endif

#ifdef CONST_MAILTO_LIST
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_LIST", CONST_MAILTO_LIST);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_LIST", "undefined");
#endif

#ifdef CONST_MAILTO_LUCA
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_LUCA", CONST_MAILTO_LUCA);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_LUCA", "undefined");
#endif

#ifdef CONST_MAILTO_OLIVIER
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_OLIVIER", CONST_MAILTO_OLIVIER);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_OLIVIER", "undefined");
#endif

#ifdef CONST_MAILTO_STEFANO
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_STEFANO", CONST_MAILTO_STEFANO);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_MAILTO_STEFANO", "undefined");
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

#ifdef CONST_NETMASK_ENTRY
  printFeatureConfigNum(textPrintFlag, "CONST_NETMASK_ENTRY", CONST_NETMASK_ENTRY);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NETMASK_ENTRY", "undefined");
#endif

#ifdef CONST_NETWORK_ENTRY
  printFeatureConfigNum(textPrintFlag, "CONST_NETWORK_ENTRY", CONST_NETWORK_ENTRY);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NETWORK_ENTRY", "undefined");
#endif

#ifdef CONST_NETWORK_IMAGE_MAP
  printFeatureConfigInfo(textPrintFlag, "CONST_NETWORK_IMAGE_MAP", CONST_NETWORK_IMAGE_MAP);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NETWORK_IMAGE_MAP", "undefined");
#endif

#ifdef CONST_NETWORK_MAP_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_NETWORK_MAP_HTML", CONST_NETWORK_MAP_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NETWORK_MAP_HTML", "undefined");
#endif

#ifdef CONST_NTOP_HELP_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_NTOP_HELP_HTML", CONST_NTOP_HELP_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NTOP_HELP_HTML", "undefined");
#endif

#ifdef CONST_NTOP_LOGO
  printFeatureConfigInfo(textPrintFlag, "CONST_NTOP_LOGO", CONST_NTOP_LOGO);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_NTOP_LOGO", "undefined");
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

#ifdef CONST_PURGE_HOST
  printFeatureConfigInfo(textPrintFlag, "CONST_PURGE_HOST", CONST_PURGE_HOST);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_PURGE_HOST", "undefined");
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

#ifdef CONST_RRD_EXTENSION
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_EXTENSION", CONST_RRD_EXTENSION);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_RRD_EXTENSION", "undefined");
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

#ifdef CONST_SHUTDOWNNOW_NTOP_IMG
  printFeatureConfigInfo(textPrintFlag, "CONST_SHUTDOWNNOW_NTOP_IMG", CONST_SHUTDOWNNOW_NTOP_IMG);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SHUTDOWNNOW_NTOP_IMG", "undefined");
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

#ifdef CONST_SSI_MENUBODY_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SSI_MENUBODY_HTML", CONST_SSI_MENUBODY_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SSI_MENUBODY_HTML", "undefined");
#endif

#ifdef CONST_SSI_MENUHEAD_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_SSI_MENUHEAD_HTML", CONST_SSI_MENUHEAD_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_SSI_MENUHEAD_HTML", "undefined");
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

#ifdef CONST_TRAFFIC_SUMMARY_HTML
  printFeatureConfigInfo(textPrintFlag, "CONST_TRAFFIC_SUMMARY_HTML", CONST_TRAFFIC_SUMMARY_HTML);
#else
  printFeatureConfigInfo(textPrintFlag, "CONST_TRAFFIC_SUMMARY_HTML", "undefined");
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

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_FCNS_FILE", "(null)");

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_FILTER_EXPRESSION", "(null)");

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_FLOW_SPECS", "(null)");

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_LOCAL_SUBNETS", "(null)");

#ifdef DEFAULT_NTOP_MAX_HASH_ENTRIES
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_MAX_HASH_ENTRIES", DEFAULT_NTOP_MAX_HASH_ENTRIES);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_MAX_HASH_ENTRIES", "undefined");
#endif

#ifdef DEFAULT_NTOP_MAX_NUM_SESSIONS
  printFeatureConfigNum(textPrintFlag, "DEFAULT_NTOP_MAX_NUM_SESSIONS", DEFAULT_NTOP_MAX_NUM_SESSIONS);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_MAX_NUM_SESSIONS", "undefined");
#endif

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

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_P3PCP", "(null)");

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_P3PURI", "(null)");

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

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_PROTO_SPECS", "(null)");

  printFeatureConfigInfo(textPrintFlag, "DEFAULT_NTOP_SAMPLING",
#ifdef DEFAULT_NTOP_SAMPLING
                         "yes"
#else
                         "no"
#endif
                         );

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

#ifdef DEFAULT_SFLOW_PORT_STR
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_SFLOW_PORT_STR", DEFAULT_SFLOW_PORT_STR);
#else
  printFeatureConfigInfo(textPrintFlag, "DEFAULT_SFLOW_PORT_STR", "undefined");
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

#ifdef IP_L4_PORT_CHARGEN
  printFeatureConfigNum(textPrintFlag, "IP_L4_PORT_CHARGEN", IP_L4_PORT_CHARGEN);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_L4_PORT_CHARGEN", "undefined");
#endif

#ifdef IP_L4_PORT_DAYTIME
  printFeatureConfigNum(textPrintFlag, "IP_L4_PORT_DAYTIME", IP_L4_PORT_DAYTIME);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_L4_PORT_DAYTIME", "undefined");
#endif

#ifdef IP_L4_PORT_DISCARD
  printFeatureConfigNum(textPrintFlag, "IP_L4_PORT_DISCARD", IP_L4_PORT_DISCARD);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_L4_PORT_DISCARD", "undefined");
#endif

#ifdef IP_L4_PORT_ECHO
  printFeatureConfigNum(textPrintFlag, "IP_L4_PORT_ECHO", IP_L4_PORT_ECHO);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_L4_PORT_ECHO", "undefined");
#endif

#ifdef IP_TCP_PORT_FTP
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_FTP", IP_TCP_PORT_FTP);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_FTP", "undefined");
#endif

#ifdef IP_TCP_PORT_GNUTELLA1
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_GNUTELLA1", IP_TCP_PORT_GNUTELLA1);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_GNUTELLA1", "undefined");
#endif

#ifdef IP_TCP_PORT_GNUTELLA2
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_GNUTELLA2", IP_TCP_PORT_GNUTELLA2);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_GNUTELLA2", "undefined");
#endif

#ifdef IP_TCP_PORT_GNUTELLA3
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_GNUTELLA3", IP_TCP_PORT_GNUTELLA3);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_GNUTELLA3", "undefined");
#endif

#ifdef IP_TCP_PORT_HTTP
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_HTTP", IP_TCP_PORT_HTTP);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_HTTP", "undefined");
#endif

#ifdef IP_TCP_PORT_HTTPS
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_HTTPS", IP_TCP_PORT_HTTPS);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_HTTPS", "undefined");
#endif

#ifdef IP_TCP_PORT_IMAP
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_IMAP", IP_TCP_PORT_IMAP);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_IMAP", "undefined");
#endif

#ifdef IP_TCP_PORT_JETDIRECT
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_JETDIRECT", IP_TCP_PORT_JETDIRECT);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_JETDIRECT", "undefined");
#endif

#ifdef IP_TCP_PORT_KAZAA
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_KAZAA", IP_TCP_PORT_KAZAA);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_KAZAA", "undefined");
#endif

#ifdef IP_TCP_PORT_MSMSGR
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_MSMSGR", IP_TCP_PORT_MSMSGR);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_MSMSGR", "undefined");
#endif

#ifdef IP_TCP_PORT_NTOP
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_NTOP", IP_TCP_PORT_NTOP);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_NTOP", "undefined");
#endif

#ifdef IP_TCP_PORT_POP2
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_POP2", IP_TCP_PORT_POP2);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_POP2", "undefined");
#endif

#ifdef IP_TCP_PORT_POP3
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_POP3", IP_TCP_PORT_POP3);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_POP3", "undefined");
#endif

#ifdef IP_TCP_PORT_PRINTER
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_PRINTER", IP_TCP_PORT_PRINTER);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_PRINTER", "undefined");
#endif

#ifdef IP_TCP_PORT_SCCP
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_SCCP", IP_TCP_PORT_SCCP);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_SCCP", "undefined");
#endif

#ifdef IP_TCP_PORT_SKYPE
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_SKYPE", IP_TCP_PORT_SKYPE);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_SKYPE", "undefined");
#endif

#ifdef IP_TCP_PORT_SMTP
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_SMTP", IP_TCP_PORT_SMTP);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_SMTP", "undefined");
#endif

#ifdef IP_TCP_PORT_SQUID
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_SQUID", IP_TCP_PORT_SQUID);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_SQUID", "undefined");
#endif

#ifdef IP_TCP_PORT_SSH
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_SSH", IP_TCP_PORT_SSH);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_SSH", "undefined");
#endif

#ifdef IP_TCP_PORT_WINMX
  printFeatureConfigNum(textPrintFlag, "IP_TCP_PORT_WINMX", IP_TCP_PORT_WINMX);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_TCP_PORT_WINMX", "undefined");
#endif

#ifdef IP_UDP_PORT_SIP
  printFeatureConfigNum(textPrintFlag, "IP_UDP_PORT_SIP", IP_UDP_PORT_SIP);
#else
  printFeatureConfigInfo(textPrintFlag, "IP_UDP_PORT_SIP", "undefined");
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

#ifdef LEN_HUGE_WORK_BUFFER
  printFeatureConfigNum(textPrintFlag, "LEN_HUGE_WORK_BUFFER", LEN_HUGE_WORK_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "LEN_HUGE_WORK_BUFFER", "undefined");
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
  printFeatureConfigInfo(textPrintFlag, "MAX_HOSTS_PURGE_PER_CYCLE", "undefined");
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

#ifdef MAX_MULTIPLE_VLAN_WARNINGS
  printFeatureConfigNum(textPrintFlag, "MAX_MULTIPLE_VLAN_WARNINGS", MAX_MULTIPLE_VLAN_WARNINGS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_MULTIPLE_VLAN_WARNINGS", "undefined");
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

#ifdef MAX_NUM_DEQUEUE_THREADS
  printFeatureConfigNum(textPrintFlag, "MAX_NUM_DEQUEUE_THREADS", MAX_NUM_DEQUEUE_THREADS);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NUM_DEQUEUE_THREADS", "undefined");
#endif

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

#ifdef MAX_PROCESS_BUFFER
  printFeatureConfigNum(textPrintFlag, "MAX_PROCESS_BUFFER", MAX_PROCESS_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_PROCESS_BUFFER", "undefined");
#endif

#ifdef MAX_NETFLOW_FLOW_BUFFER
  printFeatureConfigNum(textPrintFlag, "MAX_NETFLOW_FLOW_BUFFER", MAX_NETFLOW_FLOW_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NETFLOW_FLOW_BUFFER", "undefined");
#endif

#ifdef MAX_NETFLOW_RECORD_BUFFER
  printFeatureConfigNum(textPrintFlag, "MAX_NETFLOW_RECORD_BUFFER", MAX_NETFLOW_RECORD_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_NETFLOW_RECORD_BUFFER", "undefined");
#endif

#ifdef MAX_RRD_CYCLE_BUFFER
  printFeatureConfigNum(textPrintFlag, "MAX_RRD_CYCLE_BUFFER", MAX_RRD_CYCLE_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_RRD_CYCLE_BUFFER", "undefined");
#endif

#ifdef MAX_RRD_PROCESS_BUFFER
  printFeatureConfigNum(textPrintFlag, "MAX_RRD_PROCESS_BUFFER", MAX_RRD_PROCESS_BUFFER);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_RRD_PROCESS_BUFFER", "undefined");
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

#ifdef MAX_VLAN
  printFeatureConfigNum(textPrintFlag, "MAX_VLAN", MAX_VLAN);
#else
  printFeatureConfigInfo(textPrintFlag, "MAX_VLAN", "undefined");
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

#ifdef NTOP_PREF_ACCESS_LOG
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_ACCESS_LOG", NTOP_PREF_ACCESS_LOG);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_ACCESS_LOG", "undefined");
#endif

#ifdef NTOP_PREF_DAEMON
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_DAEMON", NTOP_PREF_DAEMON);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_DAEMON", "undefined");
#endif

#ifdef NTOP_PREF_DBG_MODE
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_DBG_MODE", NTOP_PREF_DBG_MODE);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_DBG_MODE", "undefined");
#endif

#ifdef NTOP_PREF_DEVICES
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_DEVICES", NTOP_PREF_DEVICES);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_DEVICES", "undefined");
#endif

#ifdef NTOP_PREF_DOMAINNAME
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_DOMAINNAME", NTOP_PREF_DOMAINNAME);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_DOMAINNAME", "undefined");
#endif

#ifdef NTOP_PREF_DUMP_OTHER
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_DUMP_OTHER", NTOP_PREF_DUMP_OTHER);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_DUMP_OTHER", "undefined");
#endif

#ifdef NTOP_PREF_DUMP_SUSP
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_DUMP_SUSP", NTOP_PREF_DUMP_SUSP);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_DUMP_SUSP", "undefined");
#endif

#ifdef NTOP_PREF_EN_PROTO_DECODE
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_EN_PROTO_DECODE", NTOP_PREF_EN_PROTO_DECODE);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_EN_PROTO_DECODE", "undefined");
#endif

#ifdef NTOP_PREF_EN_SESSION
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_EN_SESSION", NTOP_PREF_EN_SESSION);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_EN_SESSION", "undefined");
#endif

#ifdef NTOP_PREF_FILTER
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_FILTER", NTOP_PREF_FILTER);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_FILTER", "undefined");
#endif

#ifdef NTOP_PREF_FLOWSPECS
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_FLOWSPECS", NTOP_PREF_FLOWSPECS);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_FLOWSPECS", "undefined");
#endif

#ifdef NTOP_PREF_IPV4
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_IPV4", NTOP_PREF_IPV4);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_IPV4", "undefined");
#endif

#ifdef NTOP_PREF_IPV4V6
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_IPV4V6", NTOP_PREF_IPV4V6);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_IPV4V6", "undefined");
#endif

#ifdef NTOP_PREF_IPV6
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_IPV6", NTOP_PREF_IPV6);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_IPV6", "undefined");
#endif

#ifdef NTOP_PREF_LOCALADDR
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_LOCALADDR", NTOP_PREF_LOCALADDR);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_LOCALADDR", "undefined");
#endif

#ifdef NTOP_PREF_KNOWNADDR
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_KNOWNADDR", NTOP_PREF_KNOWNADDR);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_KNOWNADDR", "undefined");
#endif

#ifdef NTOP_PREF_MAPPERURL
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_MAPPERURL", NTOP_PREF_MAPPERURL);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_MAPPERURL", "undefined");
#endif

#ifdef NTOP_PREF_MAXHASH
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_MAXHASH", NTOP_PREF_MAXHASH);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_MAXHASH", "undefined");
#endif

#ifdef NTOP_PREF_MAXLINES
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_MAXLINES", NTOP_PREF_MAXLINES);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_MAXLINES", "undefined");
#endif

#ifdef NTOP_PREF_MAXSESSIONS
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_MAXSESSIONS", NTOP_PREF_MAXSESSIONS);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_MAXSESSIONS", "undefined");
#endif

#ifdef NTOP_PREF_MERGEIF
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_MERGEIF", NTOP_PREF_MERGEIF);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_MERGEIF", "undefined");
#endif

#ifdef NTOP_PREF_NOBLOCK
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NOBLOCK", NTOP_PREF_NOBLOCK);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NOBLOCK", "undefined");
#endif

#ifdef NTOP_PREF_NO_INVLUN
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_INVLUN", NTOP_PREF_NO_INVLUN);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_INVLUN", "undefined");
#endif

#ifdef NTOP_PREF_NO_ISESS_PURGE
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_ISESS_PURGE", NTOP_PREF_NO_ISESS_PURGE);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_ISESS_PURGE", "undefined");
#endif

#ifdef NTOP_PREF_NO_MUTEX_EXTRA
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_MUTEX_EXTRA", NTOP_PREF_NO_MUTEX_EXTRA);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_MUTEX_EXTRA", "undefined");
#endif

#ifdef NTOP_PREF_NO_PROMISC
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_PROMISC", NTOP_PREF_NO_PROMISC);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_PROMISC", "undefined");
#endif

#ifdef NTOP_PREF_NO_SCHEDYLD
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_SCHEDYLD", NTOP_PREF_NO_SCHEDYLD);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_SCHEDYLD", "undefined");
#endif

#ifdef NTOP_PREF_NO_STOPCAP
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_STOPCAP", NTOP_PREF_NO_STOPCAP);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_STOPCAP", "undefined");
#endif

#ifdef NTOP_PREF_NO_TRUST_MAC
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_TRUST_MAC", NTOP_PREF_NO_TRUST_MAC);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NO_TRUST_MAC", "undefined");
#endif

#ifdef NTOP_PREF_NUMERIC_IP
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NUMERIC_IP", NTOP_PREF_NUMERIC_IP);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_NUMERIC_IP", "undefined");
#endif

#ifdef NTOP_PREF_P3PCP
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_P3PCP", NTOP_PREF_P3PCP);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_P3PCP", "undefined");
#endif

#ifdef NTOP_PREF_P3PURI
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_P3PURI", NTOP_PREF_P3PURI);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_P3PURI", "undefined");
#endif

#ifdef NTOP_PREF_PCAP_LOGBASE
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_PCAP_LOGBASE", NTOP_PREF_PCAP_LOGBASE);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_PCAP_LOGBASE", "undefined");
#endif

#ifdef NTOP_PREF_PCAP_LOG
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_PCAP_LOG", NTOP_PREF_PCAP_LOG);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_PCAP_LOG", "undefined");
#endif

#ifdef NTOP_PREF_PRINT_FCORIP
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_PRINT_FCORIP", NTOP_PREF_PRINT_FCORIP);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_PRINT_FCORIP", "undefined");
#endif

#ifdef NTOP_PREF_PROTOSPECS
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_PROTOSPECS", NTOP_PREF_PROTOSPECS);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_PROTOSPECS", "undefined");
#endif

#ifdef NTOP_PREF_REFRESH_RATE
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_REFRESH_RATE", NTOP_PREF_REFRESH_RATE);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_REFRESH_RATE", "undefined");
#endif

#ifdef NTOP_PREF_SAMPLING
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_SAMPLING", NTOP_PREF_SAMPLING);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_SAMPLING", "undefined");
#endif

#ifdef NTOP_PREF_SPOOLPATH
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_SPOOLPATH", NTOP_PREF_SPOOLPATH);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_SPOOLPATH", "undefined");
#endif

#ifdef NTOP_PREF_SSLPORT
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_SSLPORT", NTOP_PREF_SSLPORT);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_SSLPORT", "undefined");
#endif

#ifdef NTOP_PREF_STICKY_HOSTS
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_STICKY_HOSTS", NTOP_PREF_STICKY_HOSTS);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_STICKY_HOSTS", "undefined");
#endif

#ifdef NTOP_PREF_TRACE_LVL
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_TRACE_LVL", NTOP_PREF_TRACE_LVL);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_TRACE_LVL", "undefined");
#endif

#ifdef NTOP_PREF_TRACK_LOCAL
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_TRACK_LOCAL", NTOP_PREF_TRACK_LOCAL);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_TRACK_LOCAL", "undefined");
#endif

#ifdef NTOP_PREF_USE_SSLWATCH
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_USE_SSLWATCH", NTOP_PREF_USE_SSLWATCH);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_USE_SSLWATCH", "undefined");
#endif

#ifdef NTOP_PREF_USE_SYSLOG
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_USE_SYSLOG", NTOP_PREF_USE_SYSLOG);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_USE_SYSLOG", "undefined");
#endif

#ifdef NTOP_PREF_VALUE_AF_BOTH
  printFeatureConfigNum(textPrintFlag, "NTOP_PREF_VALUE_AF_BOTH", NTOP_PREF_VALUE_AF_BOTH);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_VALUE_AF_BOTH", "undefined");
#endif

#ifdef NTOP_PREF_VALUE_AF_INET6
  printFeatureConfigNum(textPrintFlag, "NTOP_PREF_VALUE_AF_INET6", NTOP_PREF_VALUE_AF_INET6);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_VALUE_AF_INET6", "undefined");
#endif

#ifdef NTOP_PREF_VALUE_AF_INET
  printFeatureConfigNum(textPrintFlag, "NTOP_PREF_VALUE_AF_INET", NTOP_PREF_VALUE_AF_INET);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_VALUE_AF_INET", "undefined");
#endif

#ifdef NTOP_PREF_VALUE_PRINT_BOTH
  printFeatureConfigNum(textPrintFlag, "NTOP_PREF_VALUE_PRINT_BOTH", NTOP_PREF_VALUE_PRINT_BOTH);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_VALUE_PRINT_BOTH", "undefined");
#endif

#ifdef NTOP_PREF_VALUE_PRINT_FCONLY
  printFeatureConfigNum(textPrintFlag, "NTOP_PREF_VALUE_PRINT_FCONLY", NTOP_PREF_VALUE_PRINT_FCONLY);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_VALUE_PRINT_FCONLY", "undefined");
#endif

  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_VALUE_PRINT_IPONLY",
#ifdef NTOP_PREF_VALUE_PRINT_IPONLY
                         "yes"
#else
                         "no"
#endif
                         );

#ifdef NTOP_PREF_W3C
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_W3C", NTOP_PREF_W3C);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_W3C", "undefined");
#endif

#ifdef NTOP_PREF_WEBPORT
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_WEBPORT", NTOP_PREF_WEBPORT);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_WEBPORT", "undefined");
#endif

#ifdef NTOP_PREF_WWN_MAP
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_WWN_MAP", NTOP_PREF_WWN_MAP);
#else
  printFeatureConfigInfo(textPrintFlag, "NTOP_PREF_WWN_MAP", "undefined");
#endif

#ifdef NULL_VALUE
  printFeatureConfigInfo(textPrintFlag, "NULL_VALUE", NULL_VALUE);
#else
  printFeatureConfigInfo(textPrintFlag, "NULL_VALUE", "undefined");
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

#ifdef PARM_SLEEP_LIMIT
  printFeatureConfigNum(textPrintFlag, "PARM_SLEEP_LIMIT", PARM_SLEEP_LIMIT);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_SLEEP_LIMIT", "undefined");
#endif

#ifdef PARM_THROUGHPUT_REFRESH_INTERVAL
  printFeatureConfigNum(textPrintFlag, "PARM_THROUGHPUT_REFRESH_INTERVAL", PARM_THROUGHPUT_REFRESH_INTERVAL);
#else
  printFeatureConfigInfo(textPrintFlag, "PARM_THROUGHPUT_REFRESH_INTERVAL", "undefined");
#endif

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

#ifdef UNKNOWN_P2P_FILE
  printFeatureConfigInfo(textPrintFlag, "UNKNOWN_P2P_FILE", UNKNOWN_P2P_FILE);
#else
  printFeatureConfigInfo(textPrintFlag, "UNKNOWN_P2P_FILE", "undefined");
#endif

  /*                                                       E N D
   *
   * Autogenerated from globals-defines.h and inserted into webInterface.c
   *
   */

  printInfoSectionTitle(textPrintFlag, "Compile Time: globals-report.h");

  /*                                                       B E G I N
   *
   * Autogenerated from globals-report.h and inserted into webInterface.c
   *      Tue Aug 09 16:25:26 CDT 2005
   *
   */

#ifdef BASE_PROTOS_IDX
  printFeatureConfigNum(textPrintFlag, "BASE_PROTOS_IDX", BASE_PROTOS_IDX);
#else
  printFeatureConfigInfo(textPrintFlag, "BASE_PROTOS_IDX", "undefined");
#endif

#ifdef CHART_FORMAT
  printFeatureConfigInfo(textPrintFlag, "CHART_FORMAT", CHART_FORMAT);
#else
  printFeatureConfigInfo(textPrintFlag, "CHART_FORMAT", "undefined");
#endif

#ifdef DARK_BG
  printFeatureConfigInfo(textPrintFlag, "DARK_BG", DARK_BG);
#else
  printFeatureConfigInfo(textPrintFlag, "DARK_BG", "undefined");
#endif

#ifdef DISPLAY_FC_ALIAS
  printFeatureConfigNum(textPrintFlag, "DISPLAY_FC_ALIAS", DISPLAY_FC_ALIAS);
#else
  printFeatureConfigInfo(textPrintFlag, "DISPLAY_FC_ALIAS", "undefined");
#endif

#ifdef DISPLAY_FC_DEFAULT
  printFeatureConfigNum(textPrintFlag, "DISPLAY_FC_DEFAULT", DISPLAY_FC_DEFAULT);
#else
  printFeatureConfigInfo(textPrintFlag, "DISPLAY_FC_DEFAULT", "undefined");
#endif

#ifdef DISPLAY_FC_FCID
  printFeatureConfigNum(textPrintFlag, "DISPLAY_FC_FCID", DISPLAY_FC_FCID);
#else
  printFeatureConfigInfo(textPrintFlag, "DISPLAY_FC_FCID", "undefined");
#endif

#ifdef DISPLAY_FC_WWN
  printFeatureConfigNum(textPrintFlag, "DISPLAY_FC_WWN", DISPLAY_FC_WWN);
#else
  printFeatureConfigInfo(textPrintFlag, "DISPLAY_FC_WWN", "undefined");
#endif


#ifdef SORT_DATA_HOST_TRAFFIC
  printFeatureConfigNum(textPrintFlag, "SORT_DATA_HOST_TRAFFIC", SORT_DATA_HOST_TRAFFIC);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_DATA_HOST_TRAFFIC", "undefined");
#endif

#ifdef SORT_DATA_IP
  printFeatureConfigNum(textPrintFlag, "SORT_DATA_IP", SORT_DATA_IP);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_DATA_IP", "undefined");
#endif

#ifdef SORT_DATA_PROTOS
  printFeatureConfigNum(textPrintFlag, "SORT_DATA_PROTOS", SORT_DATA_PROTOS);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_DATA_PROTOS", "undefined");
#endif

#ifdef SORT_DATA_RCVD_HOST_TRAFFIC
  printFeatureConfigNum(textPrintFlag, "SORT_DATA_RCVD_HOST_TRAFFIC", SORT_DATA_RCVD_HOST_TRAFFIC);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_DATA_RCVD_HOST_TRAFFIC", "undefined");
#endif

#ifdef SORT_DATA_RECEIVED_IP
  printFeatureConfigNum(textPrintFlag, "SORT_DATA_RECEIVED_IP", SORT_DATA_RECEIVED_IP);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_DATA_RECEIVED_IP", "undefined");
#endif

#ifdef SORT_DATA_RECEIVED_PROTOS
  printFeatureConfigNum(textPrintFlag, "SORT_DATA_RECEIVED_PROTOS", SORT_DATA_RECEIVED_PROTOS);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_DATA_RECEIVED_PROTOS", "undefined");
#endif

#ifdef SORT_DATA_RECEIVED_THPT
  printFeatureConfigNum(textPrintFlag, "SORT_DATA_RECEIVED_THPT", SORT_DATA_RECEIVED_THPT);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_DATA_RECEIVED_THPT", "undefined");
#endif

#ifdef SORT_DATA_SENT_HOST_TRAFFIC
  printFeatureConfigNum(textPrintFlag, "SORT_DATA_SENT_HOST_TRAFFIC", SORT_DATA_SENT_HOST_TRAFFIC);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_DATA_SENT_HOST_TRAFFIC", "undefined");
#endif

#ifdef SORT_DATA_SENT_IP
  printFeatureConfigNum(textPrintFlag, "SORT_DATA_SENT_IP", SORT_DATA_SENT_IP);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_DATA_SENT_IP", "undefined");
#endif

#ifdef SORT_DATA_SENT_PROTOS
  printFeatureConfigNum(textPrintFlag, "SORT_DATA_SENT_PROTOS", SORT_DATA_SENT_PROTOS);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_DATA_SENT_PROTOS", "undefined");
#endif

#ifdef SORT_DATA_SENT_THPT
  printFeatureConfigNum(textPrintFlag, "SORT_DATA_SENT_THPT", SORT_DATA_SENT_THPT);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_DATA_SENT_THPT", "undefined");
#endif

#ifdef SORT_DATA_THPT
  printFeatureConfigNum(textPrintFlag, "SORT_DATA_THPT", SORT_DATA_THPT);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_DATA_THPT", "undefined");
#endif

#ifdef SORT_FC_ACTIVITY
  printFeatureConfigNum(textPrintFlag, "SORT_FC_ACTIVITY", SORT_FC_ACTIVITY);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_FC_ACTIVITY", "undefined");
#endif

#ifdef SORT_FC_DATA
  printFeatureConfigNum(textPrintFlag, "SORT_FC_DATA", SORT_FC_DATA);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_FC_DATA", "undefined");
#endif

#ifdef SORT_FC_THPT
  printFeatureConfigNum(textPrintFlag, "SORT_FC_THPT", SORT_FC_THPT);
#else
  printFeatureConfigInfo(textPrintFlag, "SORT_FC_THPT", "undefined");
#endif

#ifdef TABLE_DEFAULTS
  printFeatureConfigInfo(textPrintFlag, "TABLE_DEFAULTS", TABLE_DEFAULTS);
#else
  printFeatureConfigInfo(textPrintFlag, "TABLE_DEFAULTS", "undefined");
#endif

#ifdef TABLE_OFF
  printFeatureConfigInfo(textPrintFlag, "TABLE_OFF", TABLE_OFF);
#else
  printFeatureConfigInfo(textPrintFlag, "TABLE_OFF", "undefined");
#endif

#ifdef TABLE_ON
  printFeatureConfigInfo(textPrintFlag, "TABLE_ON", TABLE_ON);
#else
  printFeatureConfigInfo(textPrintFlag, "TABLE_ON", "undefined");
#endif

#ifdef TD_BG
  printFeatureConfigInfo(textPrintFlag, "TD_BG", TD_BG);
#else
  printFeatureConfigInfo(textPrintFlag, "TD_BG", "undefined");
#endif

#ifdef TH_BG
  printFeatureConfigInfo(textPrintFlag, "TH_BG", TH_BG);
#else
  printFeatureConfigInfo(textPrintFlag, "TH_BG", "undefined");
#endif

#ifdef TRAFFIC_STATS
  printFeatureConfigNum(textPrintFlag, "TRAFFIC_STATS", TRAFFIC_STATS);
#else
  printFeatureConfigInfo(textPrintFlag, "TRAFFIC_STATS", "undefined");
#endif

#ifdef TR_ON
  printFeatureConfigInfo(textPrintFlag, "TR_ON", TR_ON);
#else
  printFeatureConfigInfo(textPrintFlag, "TR_ON", "undefined");
#endif

#ifdef WHEAT_BG
  printFeatureConfigInfo(textPrintFlag, "WHEAT_BG", WHEAT_BG);
#else
  printFeatureConfigInfo(textPrintFlag, "WHEAT_BG", "undefined");
#endif

  /*                                                       E N D
   *
   * Autogenerated from globals-report.h and inserted into webInterface.c
   *
   */

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
    sendString("<CENTER>\n<TABLE border=\"0\" "TABLE_DEFAULTS">"
	       "<TR>"
	       "<TD colspan=\"5\">The color of the host link");
    if(isInfo == 1)
      sendString(" on many pages");
    sendString(" indicates how recently the host was FIRST seen"
               "</TD></TR>\n"
               "<TR>"
               "<TD>&nbsp;&nbsp;<A href=\"#\" class=\"age0min\">0 to 5 minutes</A>&nbsp;&nbsp;</TD>\n"
               "<TD>&nbsp;&nbsp;<A href=\"#\" class=\"age5min\">5 to 15 minutes</A>&nbsp;&nbsp;</TD>\n"
               "<TD>&nbsp;&nbsp;<A href=\"#\" class=\"age15min\">15 to 30 minutes</A>&nbsp;&nbsp;</TD>\n"
               "<TD>&nbsp;&nbsp;<A href=\"#\" class=\"age30min\">30 to 60 minutes</A>&nbsp;&nbsp;</TD>\n"
               "<TD>&nbsp;&nbsp;<A href=\"#\" class=\"age60min\">60+ minutes</A>&nbsp;&nbsp;</TD>\n"
               "</TR>\n</TABLE>\n</CENTER>\n");
  }
}

/* ******************************** */

void printMutexStatusReport(int textPrintFlag) {
#ifdef MUTEX_DEBUG
  int i;

  sendString(texthtml("\nMutexes:\n\n",
                      "<p>"TABLE_ON"<table border=\"1\" "TABLE_DEFAULTS">\n"
                      "<tr><th "TH_BG" "DARK_BG">Mutex Name</th>\n"
                      "<th "TH_BG" "DARK_BG">State</th>\n"));
  if(!myGlobals.runningPref.disableMutexExtraInfo) {
    sendString(texthtml("",
                        "<th "TH_BG" "DARK_BG">Attempt</th>\n"
                        "<th "TH_BG" "DARK_BG">Lock</th>\n"
                        "<th "TH_BG" "DARK_BG">UnLock</th>\n"
                        "<th "TH_BG" "DARK_BG">Max Lock</th>\n"));
  }
  sendString(texthtml("", "<th "TH_BG" "DARK_BG"># Locks/Releases</th>"));

  printMutexStatus(textPrintFlag, &myGlobals.gdbmMutex, "gdbmMutex");

  for(i=0; i<myGlobals.numDevices; i++) {
    char buf[256];

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "packetProcessMutex (%s)", myGlobals.device[i].name);
    printMutexStatus(textPrintFlag, &myGlobals.device[i].packetProcessMutex, buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "packetQueueMutex (%s)", myGlobals.device[i].name);
    printMutexStatus(textPrintFlag, &myGlobals.device[i].packetQueueMutex, buf);
  }

  printMutexStatus(textPrintFlag, &myGlobals.purgeMutex, "purgeMutex");

  if(myGlobals.runningPref.numericFlag == 0)
    printMutexStatus(textPrintFlag, &myGlobals.addressResolutionMutex, "addressResolutionMutex");

  printMutexStatus(textPrintFlag, &myGlobals.hostsHashLockMutex, "hostsHashLockMutex");

  for(i=0; i<NUM_SESSION_MUTEXES; i++) {
    char buf[32];

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "tcpSessionsMutex[%d]", i);
    printMutexStatus(textPrintFlag, &myGlobals.tcpSessionsMutex[i], buf);
  }

  printMutexStatus(textPrintFlag, &myGlobals.purgePortsMutex,    "purgePortsMutex");
  printMutexStatus(textPrintFlag, &myGlobals.securityItemsMutex, "securityItemsMutex");

  sendString(texthtml("\n\n", "</table>"TABLE_OFF"</p>\n"));
#endif
}

/* ******************************** */

static void printNtopConfigInfoData(int textPrintFlag, UserPref *pref) {
  /* This prints either as text or html, but no header so it can be included in bug reports */

  char buf[2*LEN_GENERAL_WORK_BUFFER], buf2[LEN_GENERAL_WORK_BUFFER];
#ifndef WIN32
  char mainbuf[LEN_GENERAL_WORK_BUFFER];
#endif
#ifndef WIN32
  char lib[LEN_GENERAL_WORK_BUFFER], env[LEN_GENERAL_WORK_BUFFER];
#endif
  char formatBuf[96];
  int i, bufLength, bufPosition, bufUsed;
  unsigned int idx, minLen, maxLen;
  unsigned long totBuckets=0, nonEmptyBuckets=0;

#ifdef HAVE_SYS_UTSNAME_H
  struct utsname unameData;
#endif

  sendString(texthtml("<pre>",
                      "<CENTER>\n<p>&nbsp;</p>\n"
                      "<TABLE border=\"1\" "TABLE_DEFAULTS" width=\"90%\">\n"));

  printInfoSectionTitle(textPrintFlag, "Basic Information");

  safe_snprintf(__FILE__, __LINE__, formatBuf, sizeof(formatBuf), "%s (%d bit)",
		osName, sizeof(long) == 8 ? 64 : 32);
  printFeatureConfigInfo(textPrintFlag, "ntop Version", formatBuf);

#ifndef WIN32
  {
    struct passwd *passwd;           /* man getpwuid */
    passwd = getpwuid (getuid());   /* Get the uid of the running processand use it to get a record from /etc/passwd */
    printFeatureConfigInfo(textPrintFlag, "Running as user", passwd->pw_name);
  }
#endif

  printFeatureConfigInfo(textPrintFlag, "Configured on", configureDate);
  printFeatureConfigInfo(textPrintFlag, "Built on", buildDate);

  safe_snprintf(__FILE__, __LINE__, formatBuf, sizeof(formatBuf), "%s", osName);
  printFeatureConfigInfo(textPrintFlag, "OS", formatBuf);

  if(myGlobals.checkVersionStatus != FLAG_CHECKVERSION_NOTCHECKED) {
    printFeatureConfigInfo(textPrintFlag, "This version of ntop is", reportNtopVersionCheck());
    if(myGlobals.checkVersionStatusAgain > 0) {
      struct tm t;
      strftime(buf, sizeof(buf), CONST_LOCALE_TIMESPEC, localtime_r(&myGlobals.checkVersionStatusAgain, &t));
      printFeatureConfigInfo(textPrintFlag, "Next version recheck is", buf);
    }
  }

  printFeatureConfigInfo(textPrintFlag, "<A HREF=http://www.tcpdump.org>libpcap</A> Version", (char *)pcap_lib_version());

  snprintf(buf, sizeof(buf), "%1.4f", rrd_version());
  printFeatureConfigInfo(textPrintFlag, "<A HREF=http://www.rrdtool.org/>RRD</A> Version", buf);

  if(myGlobals.geo_ip_db != NULL)
    printFeatureConfigInfo(textPrintFlag, "<A HREF=http://www.maxmind.com/>GeoIP</A> Version",
			   GeoIP_database_info(myGlobals.geo_ip_db));

  if(myGlobals.geo_ip_asn_db != NULL)
    printFeatureConfigInfo(textPrintFlag, "<A HREF=http://www.maxmind.com/>GeoIP</A> AS Version",
			   GeoIP_database_info(myGlobals.geo_ip_asn_db));

#ifndef WIN32
  if(getDynamicLoadPaths(mainbuf, sizeof(mainbuf), lib, sizeof(lib), env, sizeof(env)) == 0) {
    printFeatureConfigInfo(textPrintFlag, "Running from", mainbuf);
    printFeatureConfigInfo(textPrintFlag, "Libraries in", lib);
    if(textPrintFlag == TRUE)
      printFeatureConfigInfo(textPrintFlag, "Library path", env);
  }
#endif

  if(myGlobals.runningPref.instance != NULL)
    printFeatureConfigInfo(textPrintFlag, "Instance", myGlobals.runningPref.instance);

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

  printFeatureConfigInfo(textPrintFlag, "Run State", ntopstate_text(myGlobals.ntopRunState));

  /* *************************** */

  printInfoSectionTitle(textPrintFlag, "Command Line");

  strncpy(buf, myGlobals.startedAs, sizeof(buf)-1);
  printFeatureConfigInfo(textPrintFlag, "Started as....", buf);

  buf[0]='\0';
  for(i=0; i<myGlobals.ntop_argc; i++) {
    if(i>0)
      strncat(buf, " ", (sizeof(buf) - strlen(buf) - 1));
    strncat(buf, myGlobals.ntop_argv[i], (sizeof(buf) - strlen(buf) - 1));
  }
  printFeatureConfigInfo(textPrintFlag, "Resolved to....", buf);

  printInfoSectionTitle(textPrintFlag, "Preferences Used");

  printInfoSectionNote(textPrintFlag,
		       CONST_REPORT_ITS_EFFECTIVE "   means that "
		       "this is the value after ntop has processed the parameter."
		       CONST_REPORT_ITS_DEFAULT "means this is the default value, usually "
		       "(but not always) set by a #define in globals-defines.h.");

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

  printParameterConfigInfo(textPrintFlag, "-g | --track-local-hosts",
                           pref->trackOnlyLocalHosts == 1 ? "Track local hosts only" : "Track all hosts",
                           DEFAULT_NTOP_TRACK_ONLY_LOCAL == 1 ? "Track local hosts only" : "Track all hosts");

  printParameterConfigInfo(textPrintFlag, "-i | --interface" CONST_REPORT_ITS_EFFECTIVE,
                           pref->devices,
                           DEFAULT_NTOP_DEVICES);

  printParameterConfigInfo(textPrintFlag, "-j | --create-other-packets",
                           pref->enableOtherPacketDump == 1 ? "Enabled" : "Disabled",
                           DEFAULT_NTOP_OTHER_PKT_DUMP == 1 ? "Enabled" : "Disabled");

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

  printParameterConfigInfo(textPrintFlag, "-o | --no-mac",
			   pref->dontTrustMACaddr == 1 ? "Don't trust MAC Addresses" : "Trust MAC Addresses",
                           DEFAULT_NTOP_DONT_TRUST_MAC_ADDR == 1 ? "Don't trust MAC Addresses" : "Trust MAC Addresses");

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

  if(pref->maxNumHashEntries != DEFAULT_NTOP_MAX_HASH_ENTRIES) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",
		  pref->maxNumHashEntries);
    printFeatureConfigInfo(textPrintFlag, "-x", buf);
  }

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

#ifdef ENABLE_FC
  printParameterConfigInfo(textPrintFlag, "-N | --wwn-map",
                           pref->fcNSCacheFile,
                           NULL);
#endif

  printParameterConfigInfo(textPrintFlag, "-O | --pcap-file-path",
                           pref->pcapLogBasePath,
                           CFG_DBFILE_DIR);

  printParameterConfigInfo(textPrintFlag, "-P | --db-file-path",
                           myGlobals.dbPath,
                           CFG_DBFILE_DIR);

  printParameterConfigInfo(textPrintFlag, "-Q | --spool-file-path",
                           myGlobals.spoolPath,
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

  if(pref->maxNumHashEntries != DEFAULT_NTOP_MAX_NUM_SESSIONS) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",
		  pref->maxNumSessions);
    printFeatureConfigInfo(textPrintFlag, "-X", buf);
  }

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

  printParameterConfigInfo(textPrintFlag, "--instance",
                           pref->instance,
                           NULL);

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

  printParameterConfigInfo(textPrintFlag, "--skip-version-check",
                           pref->skipVersionCheck == 1 ? "Yes" : "No",
                           "No");

  printParameterConfigInfo(textPrintFlag, "--w3c",
                           pref->w3c == TRUE ? "Yes" : "No",
                           "No");

  if(textPrintFlag == FALSE) {
    printInfoSectionNote(textPrintFlag,
			 "The --w3c flag makes the generated html MORE compatible with the w3c "
			 "recommendations, but it in no way addresses all of the compatibility "
			 "and markup issues.  We would like to make <b>ntop</b> more compatible, "
			 "but some basic issues of looking decent on real-world browsers mean it "
			 "will never be 100%.  If you find any issues, please report them to "
			 "<a class=external href=\"http://lists.ntop.org/mailman/listinfo/ntop-dev\" "
			 "title=\"ntop-dev list home page\">ntop-dev</a>.\n");
  }

  /* *************************** */

  printInfoSectionTitle(textPrintFlag, "Run time/Internal");

  if(pref->webPort != 0) {
    if(pref->webAddr != 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "http://%s:%d",
		    pref->webAddr, pref->webPort);
    } else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "http://any:%d",
		    pref->webPort);
    }
    printFeatureConfigInfo(textPrintFlag, "Web server URL", buf);
  } else {
    printFeatureConfigInfo(textPrintFlag, "Web server (http://)", "Not Active");
  }

#ifdef HAVE_OPENSSL
  if(pref->sslPort != 0) {
    if(pref->sslAddr != 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "https://%s:%d",
		    pref->sslAddr, pref->sslPort);
    } else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "https://any:%d",
		    pref->sslPort);
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

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s", Py_GetVersion());

  printFeatureConfigInfo(textPrintFlag,
			 "Embedded <A HREF=http://www.python.org>Python</A>",
#ifdef HAVE_PYTHON
			 buf
#else
			 "Not present"
#endif
			 );
  
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

  /* *************************** */

  printFeatureConfigInfo(textPrintFlag, "Protocol Decoders",
			 pref->enablePacketDecoding == 1 ? "Enabled" : "Disabled");
  printFeatureConfigInfo(textPrintFlag, "Fragment Handling",
			 myGlobals.enableFragmentHandling == 1 ? "Enabled" : "Disabled");
  printFeatureConfigInfo(textPrintFlag, "Tracking only local hosts",
			 pref->trackOnlyLocalHosts == 1 ? "Yes" : "No");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",
		myGlobals.numIpProtosToMonitor);
  printFeatureConfigInfo(textPrintFlag, "# IP Protocols Being Monitored", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",
		myGlobals.numActServices);
  printFeatureConfigInfo(textPrintFlag, "# Protocol slots", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",
		myGlobals.ipPortMapper.numElements);
  printFeatureConfigInfo(textPrintFlag, "# IP Ports Being Monitored", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",
		myGlobals.ipPortMapper.numSlots);
  printFeatureConfigInfo(textPrintFlag, "# IP Ports slots", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",
		(int)myGlobals.webServerRequestQueueLength);
  printFeatureConfigInfo(textPrintFlag, "WebServer Request Queue", buf);

  if(!myGlobals.runningPref.numericFlag) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[current: %d][max: %d][drops: %d]",
		  (int)myGlobals.addressQueuedCurrent,
		  (int)myGlobals.addressQueuedMax,
		  (int)myGlobals.addressUnresolvedDrops);
    printFeatureConfigInfo(textPrintFlag, "DNS Resolution Request Queue", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[resolved: %u][failed: %u]",
		  myGlobals.resolvedAddresses, myGlobals.failedResolvedAddresses);
    printFeatureConfigInfo(textPrintFlag, "DNS Resolved Addresses", buf);
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numDevices);
  printFeatureConfigInfo(textPrintFlag, "Devices (Network Interfaces)", buf);

  printFeatureConfigInfo(textPrintFlag, "Domain name (short)",
			 myGlobals.shortDomainName);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",
		myGlobals.hashCollisionsLookup);
  printFeatureConfigInfo(textPrintFlag,
			 "Total Hash Collisions (Vendor/Special) (lookup)", buf);

  printFeatureConfigInfo(textPrintFlag, "Database (MySQL) Support Enabled",
			 is_db_enabled() ? "Yes" : "No");

  if(is_db_enabled()) {
    printFeatureConfigInfo(textPrintFlag, "Database Configuration",
			   myGlobals.runningPref.sqlDbConfig);
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s [%u failures]",
		  formatPkts(num_db_insert, formatBuf, sizeof(formatBuf)),
		  num_db_insert_failed);
    printFeatureConfigInfo(textPrintFlag, "Database Record Insert", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "[Save Data into DB: %s] [Save Sessions into DB: %s]",
 		  myGlobals.runningPref.saveRecordsIntoDb ? "Yes" : "No",
		  myGlobals.runningPref.saveSessionsIntoDb ? "Yes" : "No");
    printFeatureConfigInfo(textPrintFlag, "Database Record Save Policy", buf);
  }

  /* *************************** */

  if(myGlobals.numLocalNetworks > 0) {
    printFeatureConfigInfoHeader(textPrintFlag, "Local Networks");

    for(i=0; i<myGlobals.numLocalNetworks; i++) {
      struct in_addr addr;
      char addr_buf[32];

      addr.s_addr = myGlobals.localNetworks[i].address[CONST_NETWORK_ENTRY];

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "%s/%d<br>", _intoa(addr, addr_buf, sizeof(addr_buf)),
		    myGlobals.localNetworks[i].address[CONST_NETMASK_V6_ENTRY]);
      sendString(buf);
    }

    printFeatureConfigInfoFooter(textPrintFlag);
  }

  /* *************************** */

  printInfoSectionTitle(textPrintFlag, "Networks");

  for(i=0; i<myGlobals.numDevices; i++) {
    char addr_buf[32], adapter_buf[128];

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/%d",
		  _intoa(myGlobals.device[i].network, addr_buf, sizeof(addr_buf)),
		  num_network_bits(myGlobals.device[i].netmask.s_addr));

    safe_snprintf(__FILE__, __LINE__, adapter_buf, sizeof(adapter_buf),
		  "%s Local Network", myGlobals.device[i].name);
    printFeatureConfigInfo(textPrintFlag, adapter_buf, buf);
  }

  /* ******************** */

  if(myGlobals.numKnownSubnets > 0) {
    printFeatureConfigInfoHeader(textPrintFlag, "Known Networks");

    for(i=0; i<myGlobals.numKnownSubnets; i++) {
      struct in_addr addr;
      char addr_buf[32];

      addr.s_addr = myGlobals.subnetStats[i].address[CONST_NETWORK_ENTRY];

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "%s/%d<br>", _intoa(addr, addr_buf, sizeof(addr_buf)),
		    myGlobals.subnetStats[i].address[CONST_NETMASK_V6_ENTRY]);
      sendString(buf);
    }

    printFeatureConfigInfoFooter(textPrintFlag);
  }

  /* ******************** */

  printInfoSectionTitle(textPrintFlag, "ntop Web Server");

  printFeatureConfigTitle3Col(textPrintFlag,
                              "Item..................http://...................https://",
                              "Item", "http://", "https://");

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

  if(textPrintFlag != TRUE) {
    printInfoSectionNote(textPrintFlag,
			 "</i><ul>\n"
			 "<li><i>Counts may not total because of in-process requests.</i></li>\n"
			 "<li><i>Each request to the ntop web server - "
			 "page, chart, etc. is counted separately</i></li></ul>\n<i>");
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numSSIRequests);
  printFeatureConfigInfo(textPrintFlag, "# SSI Requests", buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numBadSSIRequests);
  printFeatureConfigInfo(textPrintFlag, "# Bad SSI Requests", buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numHandledSSIRequests);
  printFeatureConfigInfo(textPrintFlag, "# Handled SSI Requests", buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.numHandledSIGPIPEerrors);
  printFeatureConfigInfo(textPrintFlag, "# Handled SIGPIPE Errors", buf);

  if(textPrintFlag == TRUE) {
    printInfoSectionTitle(textPrintFlag, "Memory Usage");

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.ipxsapHashLoadSize);
    printFeatureConfigInfo(textPrintFlag, "IPX/SAP Hash Size (bytes)", buf);
  }

  printInfoSectionTitle(textPrintFlag, "Host Memory Cache");

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
  printInfoSectionTitle(textPrintFlag, "Session Memory Cache");

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
    printInfoSectionTitle(textPrintFlag, "MAC/IPX Hash tables");

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", MAX_IPXSAP_NAME_HASH);
    printFeatureConfigInfo(textPrintFlag, "IPX/SAP Hash Size (entries)", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.ipxsapHashLoadCollisions);
    printFeatureConfigInfo(textPrintFlag, "IPX/SAP Hash Collisions (load)", buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.hashCollisionsLookup);
    printFeatureConfigInfo(textPrintFlag, "IPX/SAP Hash Collisions (use)", buf);
  }

  /* **** */

  printInfoSectionTitle(textPrintFlag, "Packets");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
		formatPkts(myGlobals.receivedPackets, formatBuf, sizeof(formatBuf)));
  printFeatureConfigInfo(textPrintFlag, "Received", buf);

  if(myGlobals.receivedPackets > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s (%.1f %%)",
		  formatPkts(myGlobals.receivedPacketsProcessed, formatBuf, sizeof(formatBuf)),
		  100.0*myGlobals.receivedPacketsProcessed  / myGlobals.receivedPackets);
    printFeatureConfigInfo(textPrintFlag, "Processed Immediately", buf);
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s (%.1f %%)",
		  formatPkts(myGlobals.receivedPacketsQueued, formatBuf, sizeof(formatBuf)),
                  100.0*myGlobals.receivedPacketsQueued / myGlobals.receivedPackets);
    printFeatureConfigInfo(textPrintFlag, "Queued", buf);
  }

  if(myGlobals.receivedPacketsLostQ > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.receivedPacketsLostQ);
    printFeatureConfigInfo(textPrintFlag, "Lost in ntop queue", buf);
  }

  for(i=0; i<myGlobals.numDevices; i++) {
    char label[256];

    safe_snprintf(__FILE__, __LINE__, label, sizeof(label), "Current Queue (%s)", myGlobals.device[i].name);
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.device[i].packetQueueLen);
    printFeatureConfigInfo(textPrintFlag, label, buf);

    safe_snprintf(__FILE__, __LINE__, label, sizeof(label), "Maximum Queue (%s)", myGlobals.device[i].name);
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d (Limit " xstr(CONST_PACKET_QUEUE_LENGTH) ")",
		  myGlobals.device[i].maxPacketQueueLen);
    printFeatureConfigInfo(textPrintFlag, label, buf);
  }

#ifdef MAX_PROCESS_BUFFER
  {
    char tmpBuf[LEN_GENERAL_WORK_BUFFER];
    float qminDelay=99999.0, qmaxDelay=0.0,
      /*stddev:*/ qM = 0, qT = 0, qQ, qR, qSD, qXBAR,
      pminDelay=99999.0, pmaxDelay=0.0,
      /*stddev:*/ pM=0, pT=0, pQ=0, pR=0, pSD=0, pXBAR;

    if(myGlobals.queueBufferCount >= MAX_PROCESS_BUFFER) {

      for(i=0; i<MAX_PROCESS_BUFFER; i++) {
	if(myGlobals.queueBuffer[i] > qmaxDelay)   qmaxDelay = myGlobals.queueBuffer[i];
	if(myGlobals.queueBuffer[i] < qminDelay)   qminDelay = myGlobals.queueBuffer[i];
	if(myGlobals.processBuffer[i] > pmaxDelay) pmaxDelay = myGlobals.processBuffer[i];
	if(myGlobals.processBuffer[i] < pminDelay) pminDelay = myGlobals.processBuffer[i];

	if(i==0) {
	  qM = myGlobals.queueBuffer[0];
	  qT = 0.0;
	  pM = myGlobals.processBuffer[0];
	  pT = 0.0;
	} else {
	  qQ = myGlobals.queueBuffer[i] - qM;
	  qR = qQ / (float)(i+1);
	  qM += qR;
	  qT = qT + i * qQ * qR;
	  pQ = myGlobals.processBuffer[i] - pM;
	  pR = pQ / (float)(i+1);
	  pM += pR;
	  pT = pT + i * pQ * pR;
	}
      }
      qSD = sqrtf(qT / (MAX_PROCESS_BUFFER - 1));
      qXBAR /*average*/ = qM;
      pSD = sqrtf(pT / (MAX_PROCESS_BUFFER - 1));
      pXBAR /*average*/ = pM;

      printFeatureConfigTitle3Col(textPrintFlag,
				  "Packet processing:....Queue (pre-process).......Processing\n",
				  "Packet Processing", "Queue (pre-process)", "Processing");

      printFeatureConfigInfo3ColFlt6(textPrintFlag,
				     "Minimum",
				     TRUE, qminDelay, TRUE, pminDelay,
				     TRUE);
      printFeatureConfigInfo3ColFlt6(textPrintFlag,
				     "Average",
				     TRUE, qXBAR, TRUE, pXBAR,
				     TRUE);
      printFeatureConfigInfo3ColFlt6(textPrintFlag,
				     "Maximum",
				     TRUE, qmaxDelay, TRUE, pmaxDelay,
				     TRUE);
      printFeatureConfigInfo3ColFlt6(textPrintFlag,
				     "Standard Deviation",
				     TRUE, qSD, TRUE, pSD,
				     TRUE);

      printFeatureConfigInfo3ColFlt6(textPrintFlag,
				     "Maximum ever",
				     TRUE, myGlobals.qmaxDelay, TRUE, myGlobals.pmaxDelay,
				     TRUE);

      sendString(texthtml("", "<tr><th "DARK_BG" "TH_BG" align=\"left\" width=\"" xstr(CONST_INFOHTML_COL1_WIDTH) "\">"));
      sendString("Throughput (pps) min/avg/max");

      if(textPrintFlag == TRUE) {
	sendString(".....");
      } else {
	safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf),
		      "</th>\n<td "TD_BG" align=\"center\" width=\"%d\" colspan=\"2\">",
		      CONST_INFOHTML_COL2_WIDTH + CONST_INFOHTML_COL3_WIDTH);
	sendString(tmpBuf);
      }
      /* Yes, confusing - maximum RATE is 1/minumum delay) */
      if(qmaxDelay+pmaxDelay > 0.0) {
	safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%.1f", 1.0/(qmaxDelay+pmaxDelay));
	sendString(tmpBuf);
      } else
	sendString("0");

      sendString(texthtml("/", "&nbsp;/&nbsp;"));
      if(qXBAR+pXBAR > 0.0) {
	safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%.1f", 1.0/(qXBAR+pXBAR));
	sendString(tmpBuf);
      } else
	sendString("0");

      sendString(texthtml("/", "&nbsp;/&nbsp;"));
      if(qminDelay+pminDelay > 0.0) {
	safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%.1f", 1.0/(qminDelay+pminDelay));
	sendString(tmpBuf);
      } else
	sendString("0");

      sendString(texthtml("\n", "</td></tr>\n"));

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "'Queue' time is the elapsed time between the packet arrival (libpcap) "
		    "and the gettimeofday() value as the packet starts processPacket(). For a queued "
		    "packet, this includes the time in queue. "
		    "<br><br>'Processing' time is the elapsed time between starting and finishing "
		    "processPacket().  Errors and/or unrecognized packets may cause processing to be "
		    "abandoned and those packets are not counted in the 'processing' averages. This means "
		    "that the %d packets for the 'queue' and 'processing' "
		    "calculations are not necessarily the same physical packets, and may lead to over "
		    "estimation of the per-packet 'processing' time."
		    "<br><br>Small averages are good, especially if the standard deviation is small "
		    "(standard deviation is a measurement of the variability of the actual values "
		    "around the average). The computations are based only on the most recent "
		    "%d packets processed."
		    "<br><br>\"Maximum ever\" ignores the first 100 packets for each device - this lets "
		    "<b>ntop</b> get over startup agony."
		    "<br><br>What does this mean? Not much.  Still, the 'Throughput' numbers give a very "
		    "rough indication of the packet per second rate this instance of ntop can handle.",
		    MAX_PROCESS_BUFFER,
		    MAX_PROCESS_BUFFER);
      printInfoSectionNote(textPrintFlag, buf);
    }
  }
#endif

  /* **** */

  printInfoSectionTitle(textPrintFlag, "Host/Session counts - global");

  formatPkts(myGlobals.numPurgedHosts, buf2, sizeof(buf2));
  printFeatureConfigInfo(textPrintFlag, "Purged Hosts", buf2);

#ifdef MAX_HOSTS_PURGE_PER_CYCLE
  if(textPrintFlag == TRUE) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", MAX_HOSTS_PURGE_PER_CYCLE);
    printFeatureConfigInfo(textPrintFlag, "MAX_HOSTS_PURGE_PER_CYCLE", buf);
  }
#endif

  if(myGlobals.multipleVLANedHostCount > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.multipleVLANedHostCount);
    printFeatureConfigInfo(textPrintFlag, "Multi-VLANed Hosts", buf);
  }

  if(pref->enableSessionHandling) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
		  formatPkts(myGlobals.numTerminatedSessions, buf2, sizeof(buf2)));
    printFeatureConfigInfo(textPrintFlag, "Terminated Sessions", buf);
  }

  /* **** */

  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.device[i].activeDevice) {
      safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2),
		    "Host/Session counts - %sDevice %d (%s)",
		    myGlobals.device[i].virtualDevice ? "Virtual " : "",
		    i, myGlobals.device[i].name);
      printInfoSectionTitle(textPrintFlag, buf2);

      printFeatureConfigInfo(textPrintFlag, "Hash Bucket Size",
			     formatBytes(sizeof(HostTraffic), 0, buf, sizeof(buf)));

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.device[i].actualHashSize);
      printFeatureConfigInfo(textPrintFlag, "Actual Host Hash Size", buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)myGlobals.device[i].hostsno);
      printFeatureConfigInfo(textPrintFlag, "Stored hosts", buf);

      minLen=-1, maxLen=0;
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
      printFeatureConfigInfo(textPrintFlag, "Host Bucket List Length", buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.device[i].hashListMaxLookups);
      printFeatureConfigInfo(textPrintFlag, "Max host lookup", buf);

      if(pref->enableSessionHandling) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
		      formatBytes(sizeof(IPSession), 0, buf2, sizeof(buf2)));
	printFeatureConfigInfo(textPrintFlag, "Session Bucket Size", buf);

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", MAX_TOT_NUM_SESSIONS);
	printFeatureConfigInfo(textPrintFlag, "Session Actual Hash Size", buf);

	if(myGlobals.device[i].tcpSession != NULL) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
			formatPkts(myGlobals.device[i].numTcpSessions, buf2, sizeof(buf2)));
	  printFeatureConfigInfo(textPrintFlag, "Sessions", buf);

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
			formatPkts(myGlobals.device[i].maxNumTcpSessions, buf2, sizeof(buf2)));
	  printFeatureConfigInfo(textPrintFlag, "Max Num. Sessions", buf);

	  minLen=-1, maxLen=0;
	  for(idx=0; idx<MAX_TOT_NUM_SESSIONS; idx++) {
	    IPSession *sess;

	    if((sess = myGlobals.device[i].tcpSession[idx]) != NULL) {
	      unsigned int len=0;

	      nonEmptyBuckets++;

	      for(; sess != NULL; sess = sess->next) {
		totBuckets++, len++;
	      }

	      if(minLen > len) minLen = len;
	      if(maxLen < len) maxLen = len;
	    }
	  }

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[min %u][max %u][avg %.1f]",
			minLen, maxLen, (float)totBuckets/(float)nonEmptyBuckets);
	  printFeatureConfigInfo(textPrintFlag, "Session Bucket List Length", buf);
	}
      }
    }
  }

  /* **** */

  printInfoSectionTitle(textPrintFlag, "----- Address Resolution -----");

  printInfoSectionTitle(textPrintFlag, "DNS Sniffing (other hosts requests)");

  printFeatureConfigNum(textPrintFlag, "DNS Packets sniffed", (int)myGlobals.dnsSniffCount);

  if(textPrintFlag == TRUE) {
    printFeatureConfigNum(textPrintFlag, "  less 'requests'", (int)myGlobals.dnsSniffRequestCount);
    printFeatureConfigNum(textPrintFlag, "  less 'failed'", (int)myGlobals.dnsSniffFailedCount);
    printFeatureConfigNum(textPrintFlag, "  less 'reverse dns' (in-addr.arpa)", (int)myGlobals.dnsSniffARPACount);
  }

  printFeatureConfigNum(textPrintFlag, "DNS Packets processed", (int)(myGlobals.dnsSniffCount
								      - myGlobals.dnsSniffRequestCount
								      - myGlobals.dnsSniffFailedCount
								      - myGlobals.dnsSniffARPACount));

  printFeatureConfigNum(textPrintFlag, "Stored in cache (includes aliases)", (int)myGlobals.dnsSniffStoredInCache);

  /* **** */

  if(textPrintFlag == TRUE) {
    printInfoSectionTitle(textPrintFlag, "Vendor Lookup Table");

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

  printInfoSectionTitle(textPrintFlag, "Thread counts");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numThreads);
  printFeatureConfigInfo(textPrintFlag, "Active", buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.numChildren);
  printFeatureConfigInfo(textPrintFlag, "Children (active)", buf);

  /* **** */

#if defined(MAX_NUM_BAD_IP_ADDRESSES) && (MAX_NUM_BAD_IP_ADDRESSES > 0)
  {
    //TODO Fixup for new table structure...
    struct tm t;
    char buf3[64], buf4[64];
    time_t lockoutExpires;
    int countBadGuys=0;

    for(i=0; i<MAX_NUM_BAD_IP_ADDRESSES; i++) {
      if(!addrnull(&myGlobals.weDontWantToTalkWithYou[i].addr)) {
	if(++countBadGuys == 1) {
	  printInfoSectionTitle(textPrintFlag, "IP Address reject list");
	  sendString(texthtml("\nAddress ... Count ... Last Bad Access ... Lockout Expires\n",
			      "<tr><th>Rejects</th>"
			      "<td><TABLE BORDER=1 "TABLE_DEFAULTS">"
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

#if defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 3)
  printFeatureConfigInfo(textPrintFlag, "Allocated Memory",
                         formatBytes(myGlobals.allocatedMemory, 0, buf, sizeof(buf)));
#endif

  /* **** */

  printInfoSectionTitle(textPrintFlag, "Directory (search) order");

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

  printInfoSectionNote(textPrintFlag, "REMEMBER that the . (current working directory) value will be different "
		       "when you run ntop from the command line vs. a cron job or startup script!");

  /* *************************** *************************** */

#ifndef WIN32
  printInfoSectionTitle(textPrintFlag, "Compile Time: ./configure");
  printFeatureConfigInfo(textPrintFlag, "./configure parameters",
			 configure_parameters[0] == '\0' ? "&nbsp;" : configure_parameters);
  printFeatureConfigInfo(textPrintFlag, "Built on (Host)", host_system_type);
  printFeatureConfigInfo(textPrintFlag, "Built for(Target)", target_system_type);
  printFeatureConfigInfo(textPrintFlag, "preprocessor (CPPFLAGS)", compiler_cppflags);
  printFeatureConfigInfo(textPrintFlag, "compiler (CFLAGS)", compiler_cflags);
  printFeatureConfigInfo(textPrintFlag, "include path", include_path);
  printFeatureConfigInfo(textPrintFlag, "system libraries", system_libs);
  printFeatureConfigInfo(textPrintFlag, "install path", install_path);
#endif

  /*
    #ifdef MEMORY_DEBUG
    printFeatureConfigInfo(textPrintFlag, "Memory Debug option", memoryDebug);
    #if (MEMORY_DEBUG == 1)
    printFeatureConfigInfo(textPrintFlag, "Trace File", getenv("MALLOC_TRACE"));
    #endif
    #endif
  */

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

  printInfoSectionTitle(textPrintFlag, "Internationalization (i18n)");

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

#if defined(DEBUG)                     ||	\
  defined(ADDRESS_DEBUG)             ||		\
  defined(DNS_DEBUG)                 ||		\
  defined(DNS_SNIFF_DEBUG)           ||		\
  defined(FRAGMENT_DEBUG)            ||		\
  defined(FC_DEBUG)                  ||		\
  defined(FINGERPRINT_DEBUG)         ||		\
  defined(FTP_DEBUG)                 ||		\
  defined(GDBM_DEBUG)                ||		\
  defined(HASH_DEBUG)                ||		\
  defined(IDLE_PURGE_DEBUG)          ||		\
  defined(INITWEB_DEBUG)             ||		\
  defined(HOST_FREE_DEBUG)           ||		\
  defined(HTTP_DEBUG)                ||		\
  defined(MEMORY_DEBUG)              ||		\
  defined(MUTEX_DEBUG)               ||		\
  defined(NETFLOW_DEBUG)             ||		\
  defined(PACKET_DEBUG)              ||		\
  defined(PLUGIN_DEBUG)              ||		\
  defined(SESSION_TRACE_DEBUG)       ||		\
  defined(STORAGE_DEBUG)             ||		\
  defined(UNKNOWN_PACKET_DEBUG)      ||		\
  defined(URL_DEBUG)
#else
  if(textPrintFlag == TRUE)
#endif
    printNtopConfigHInfo(textPrintFlag);

  /* *************************** */

  sendString(texthtml("\n\n", "</TABLE>\n"));

  /* **************************** */

  printMutexStatusReport(textPrintFlag);

  if(textPrintFlag != TRUE) {
    sendString("<p>[ Click <a  class=tooltip href=\"" CONST_TEXT_INFO_NTOP_HTML "\" title=\"Text version of this page\">"
	       "here</a> for a more extensive, text version of this page, suitable for "
	       "inclusion into a bug report ]</p>\n");
  }

  sendString(texthtml("</pre>", "</CENTER>\n"));
}

/* ******************************** */

void printNtopConfigInfo(int textPrintFlag, UserPref *pref) {
  /* This has the header */
  printHTMLheader("ntop Configuration", NULL, 0);
  //  sendString("<h1>ntop Configuration</h1>\n");
  printNtopConfigInfoData(textPrintFlag, pref);
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

#ifdef WIN32
  WaitForSingleObject(myGlobals.logViewMutex.mutex, INFINITE);
#else
  pthread_rwlock_wrlock(&myGlobals.logViewMutex.mutex);
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

#ifdef WIN32
  ReleaseMutex(myGlobals.logViewMutex.mutex);
#else
  pthread_rwlock_unlock(&myGlobals.logViewMutex.mutex);
#endif

  if(!printAsText) {
    sendString("</pre>");
  }

  return(lines);
}

/* *************************** */

void printNtopProblemReport(void) {
  char buf[LEN_GENERAL_WORK_BUFFER];
#ifdef PROBLEMREPORTID_DEBUG
  char buf2[256];
#endif
  static char xvert[] = "JB6XF3PRQHNA7W5ECM8S9GLVY4TDKUZ2"; /* Scrambled just 'cause */
  time_t t;
  unsigned int v, scr, raw;
  int i, j;

#ifdef HAVE_SYS_UTSNAME_H
  struct utsname unameData;
#endif

#ifndef WIN32
  struct pcap_stat pcapStats;
  memset(&pcapStats, 0, sizeof(struct pcap_stat));
#endif

  t = time(NULL);

  printHTMLheader("ntop Problem Report", NULL, 0);

  sendString("<h3>Instructions (delete this before you send)</h3>\n");
  sendString("<table border=\"1\" width=\"500\" "TABLE_DEFAULTS">\n<tr><td class=\"wrap\">");
  sendString("<p>Cut out this entire section and paste into an e-mail message.  Fill in the\n");
  sendString("various sections with as much detail as possible and email to the ntop lists.</p>\n");
  sendString("<ul><li>User-type questions (How do I?) and usage bugs should be directed to the ntop\n");
  sendString("mailing list (see http://lists.ntop.org/mailman/listinfo/ntop).</li>\n");
  sendString("<li>Code/development questions belong on the ntop-dev list (at\n");
  sendString("http://lists.ntop.org/mailman/listinfo/ntop-dev.</li></ul>\n");
  sendString("<p><b>Remember: ONE problem per report!</b></p>\n");
  sendString("<p>The summary should be 5-10 words that indicate the problem and which would have\n");
  sendString("helped you to find a previous report of the same problem, e.g.:</p>\n");
  sendString("<pre>   2003-02-07 cvs compile error in util.c, #define NONOPTION_P...</pre>\n");
  sendString("<p>Use the SAME 'summary' as the subject of your message, with the addition\n");
  sendString("of the PR_xxxxxx value.</p>\n");
  sendString("<p>For the 'Log Extract', (Unix/Linux systems) cut and paste the last 10-15 system log\n");
  sendString("messages. Try and make sure - even if it requires more than 15 messages that you show\n");
  sendString("at least 5 or 6 messages (or a few minutes in time) BEFORE the first sign of failure.</p>\n");
  sendString("<p>Assuming your system log is in /var/log/messages, the command is:</p>\n");
  sendString("<pre>   grep 'ntop' /var/log/messages | head -n 15</pre>\n");
  sendString("<p>but you may have to increase the 15 to get the right messages.</p>\n");
  sendString("</td></tr>\n<tr><td class=\"wrap\">");
  sendString("<p>The generated id below should be unique. It's essentially a random 6\n");
  sendString("or 7 character tracking tag for each problem report.  Since it's\n");
  sendString("generated on your machine, we can't just use an ever increasing global\n");
  sendString("number.  While it should be unique, it is not traceable back to a\n");
  sendString("specific user or machine. <em>If this makes you uncomfortable just delete it.</em></p>\n");
  sendString("</td></tr>\n<tr><td class=\"wrap\">");
  sendString("<p>The shortcut keys for copying this entire section are usually:</p>\n");
  sendString("<ol><li>Left click anywhere in this text (selects the frame)</li>\n");
  sendString("<li>Type control-a (select all)</li>\n");
  sendString("<li>Type control-c (copy)</li>\n");
  sendString("<li>Open a new mail message, and</li>\n");
  sendString("<li>Type control-v (paste)</li>\n");
  sendString("<li>Edit the generated text to fill in the _____s and empty sections.  Don't worry -\n");
  sendString("giving us more information is usually better that giving less</li>\n");
  sendString("<li><b>REMEMBER</b> To delete the headers and instructions (i.e. from\n");
  sendString("this line to the top) before sending...</b></li></ol>\n");
  sendString("</td></tr></table>\n");
  sendString("<hr>\n");

  sendString("<pre>\n");
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
  for(i=0; i< myGlobals.numDevices; i++)
    raw += (unsigned int) (myGlobals.device[i].ethernetBytes.value);

#ifdef PROBLEMREPORTID_DEBUG
  safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "%-12s %48u %08x\n", "Bytes", raw, raw);
  sendString(buf2);
#endif
  /* Scramble the nibbles so we have some data high and some low.
     Arbitrary: abcdefgh -> fhgdaecb */
  scr = (raw & 0xf0000000) >> 16 |
    (raw & 0x0f000000) >> 24 |
    (raw & 0x00f00000) >> 16 |
    (raw & 0x000f0000)       |
    (raw & 0x0000f000) >>  4 |
    (raw & 0x00000f00) << 20 |
    (raw & 0x000000f0) << 16 |
    (raw & 0x0000000f) << 24;
  v ^= scr;
#ifdef PROBLEMREPORTID_DEBUG
  safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "%-12s %48u %08x %08x\n", "Bytes(scramble)",
		scr, scr, v);
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

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Received:  %10u\n", myGlobals.receivedPackets);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Processed: %10u (immediately)\n",
		myGlobals.receivedPacketsProcessed);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Queued:    %10u\n",
		myGlobals.receivedPacketsQueued);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Lost:      %10u (queue full)\n",
		myGlobals.receivedPacketsLostQ);
  sendString(buf);

  for(i=0; i<myGlobals.numDevices; i++) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[s] Queue:     Current: %u Maximum: %u\n",
		  myGlobals.device[i].name,
		  myGlobals.device[i].packetQueueLen,
		  myGlobals.device[i].maxPacketQueueLen);
    sendString(buf);
  }

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
  printNtopConfigInfoData(TRUE, &myGlobals.runningPref);
  sendString("----------------------------------------------------------------------------\n");

  sendString("</pre>\n");
}

/* **************************************** */

#define sslOrNot (isSSL ? " ssl" : "")

void initSocket(int isSSL, int ipv4or6, int *port, int *sock, char *addr) {
  int sockopt = 1, rc;
#if defined(INET6) && !defined(WIN32)
  struct addrinfo hints, *ai = NULL, *aitop;
  char strport[32];
  char ntop[1024];
#endif
#ifdef INITWEB_DEBUG
  char value[LEN_SMALL_WORK_BUFFER];
#endif
#if !(defined(INET6) && !defined(WIN32))
  struct sockaddr_in sockIn;
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

  errno = 0;
#if defined(INET6) && !defined(WIN32)
  *sock = socket(ai->ai_family, SOCK_STREAM, 0);
  if((*sock < 0) || (errno != 0) ) {
    errno = 0;
    /* It might be that IPv6 is not supported by the running system */
    *sock = socket(AF_INET, SOCK_STREAM, 0);
  }
#else
  *sock = socket(AF_INET, SOCK_STREAM, 0);
#endif
  if((*sock < 0) || (errno != 0)) {
    traceEvent(CONST_TRACE_FATALERROR, "INITWEB: Unable to create a new%s socket - returned %d, error is '%s'(%d)",
	       sslOrNot, *sock, strerror(errno), errno);
    exit(37); /* Just in case */
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
    exit(38); /* Just in case */
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
    closeNwSocket(&myGlobals.sock);
    traceEvent(CONST_TRACE_ERROR,
               "INITWEB:%s binding problem - '%s'(%d)",
               sslOrNot, strerror(errno), errno);
    traceEvent(CONST_TRACE_INFO, "Check if another instance of ntop is running");
    traceEvent(CONST_TRACE_INFO, "or if the current user (-u) can bind to the specified port");
    traceEvent(CONST_TRACE_FATALERROR, "Binding problem, ntop shutting down...");
    exit(39); /* Just in case */
  }

#ifdef INITWEB_DEBUG
  traceEvent(CONST_TRACE_INFO, "INITWEB_DEBUG:%s socket %d bound", sslOrNot, *sock);
#endif

  errno = 0;
  rc = listen(*sock, myGlobals.webServerRequestQueueLength);
  if((rc < 0) || (errno != 0)) {
    closeNwSocket(&myGlobals.sock);
    traceEvent(CONST_TRACE_FATALERROR, "INITWEB:%s listen(%d, %d) error %s(%d)",
               sslOrNot,
               *sock,
               myGlobals.webServerRequestQueueLength,
               strerror(errno), errno);
    exit(40); /* Just in case */
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

  traceEvent(CONST_TRACE_INFO, "INITWEB: Initializing TCP/IP socket connections for web server");

  if(myGlobals.runningPref.webPort > 0) {
    initSocket(FALSE, myGlobals.runningPref.ipv4or6, &myGlobals.runningPref.webPort,
	       &myGlobals.sock, myGlobals.runningPref.webAddr);
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

  traceEvent(CONST_TRACE_INFO, "INITWEB: Starting web server");
  createThread(&myGlobals.handleWebConnectionsThreadId, handleWebConnections, NULL);
  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: INITWEB: Started thread for web server",
	     (long unsigned int)myGlobals.handleWebConnectionsThreadId);

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

/* ******************************************* */

#ifdef MAKE_WITH_HTTPSIGTRAP

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

  traceEvent(CONST_TRACE_ERROR, "webserver: BACKTRACE:     backtrace is:");
  if(size < 2)
    traceEvent(CONST_TRACE_ERROR, "webserver: BACKTRACE:         **unavailable!");
  else
    /* Ignore the 0th entry, that's our cleanup() */
    for (i=1; i<size; i++)
      traceEvent(CONST_TRACE_ERROR, "webserver: BACKTRACE:          %2d. %s", i, strings[i]);
#endif

  traceEvent(CONST_TRACE_FATALERROR, "webserver: ntop shutting down...");
  exit(41); /* Just in case */
}
#endif /* MAKE_WITH_HTTPSIGTRAP */

/* ******************************************* */

void* handleWebConnections(void* notUsed _UNUSED_) {
  int rc;
  fd_set mask, mask_copy;
  int topSock = myGlobals.sock;

#ifndef WIN32
  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: WEB: Server connection thread starting [p%d]",
	     (long unsigned int)pthread_self(), getpid());
#endif

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
      traceEvent(CONST_TRACE_ERROR, "SIGPIPE mask set, pthread_setsigmask(SIG_UNBLOCK, %p, %p) returned %d",
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

#ifndef WIN32
  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: WEB: Server connection thread running [p%d]",
	     (long unsigned int)pthread_self(), getpid());
#endif

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "WEB: ntop's web server is now processing requests");

  while(myGlobals.ntopRunState < FLAG_NTOPSTATE_SHUTDOWNREQ) {
    struct timeval wait_time;

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Select(ing) %d....", topSock);
#endif
    memcpy(&mask, &mask_copy, sizeof(fd_set));
    wait_time.tv_sec = PARM_SLEEP_LIMIT; wait_time.tv_usec = 0;
    rc = select(topSock+1, &mask, 0, 0, &wait_time);
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: select returned: %d", rc);
#endif
    if(rc > 0) {
      /* Now, handle the web connection ends up in SSL_Accept() */
      handleSingleWebConnection(&mask);
    }
  } /* while myGlobals.ntopRunState < FLAG_NTOPSTATE_SHUTDOWNREQ */

  myGlobals.handleWebConnectionsThreadId = 0;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: WEB: Server connection thread terminated [p%d]",
	     (long unsigned int)pthread_self(), getpid());

  if(myGlobals.ntopRunState == FLAG_NTOPSTATE_SHUTDOWNREQ) {

    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Terminating ntop based on user shutdown request");

    sleep(1);
    raise(SIGINT);
    /* Returning from above is a bad thing */

  }

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
    myGlobals.newSock = accept(myGlobals.sock, (struct sockaddr*)&from,
			       (socklen_t*)&from_len);
  } else {
#if defined(DEBUG) && defined(HAVE_OPENSSL)
    if(myGlobals.sslInitialized)
      traceEvent(CONST_TRACE_INFO, "DEBUG: Accepting HTTPS request...");
#endif
#ifdef HAVE_OPENSSL
    if(myGlobals.sslInitialized)
      myGlobals.newSock = accept(myGlobals.sock_ssl, (struct sockaddr*)&from,
				 (socklen_t*)&from_len);
#else
    ;
#endif
  }

  if(myGlobals.newSock >= 0) {
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

  if(myGlobals.newSock >= 0) {
#ifdef HAVE_OPENSSL
    if(myGlobals.sslInitialized)
      if(FD_ISSET(myGlobals.sock_ssl, fdmask)) {
	if(accept_ssl_connection(myGlobals.newSock) == -1) {
	  traceEvent(CONST_TRACE_WARNING, "Unable to accept SSL connection");
	  closeNwSocket(&myGlobals.newSock);
	  return;
	} else {
	  myGlobals.newSock = -myGlobals.newSock;
	}
      }
#endif /* HAVE_OPENSSL */

    handleHTTPrequest(remote_ipaddr);
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

/* *******************************/

#define DEVICE_NAME         "device.name."

void edit_prefs(char *db_key, char *db_val) {
  datum key, nextkey;
  int num_added = 0;
  char buf[1024];

  printHTMLheader("Edit Preferences", NULL, 0);

  sendString("<CENTER><TABLE BORDER=1 "TABLE_DEFAULTS">\n"
	     "<TR><TH ALIGN=CENTER "DARK_BG">Preference</TH>"
	     "<TH ALIGN=CENTER "DARK_BG">Configured Value</TH>"
	     "<TH ALIGN=CENTER "DARK_BG">Action</TH></TR>\n");

  if(db_key && (!strcmp(db_key, EVENTS_MASK))) {
    if(!db_val) db_val = strdup("0");
  }

  if(db_key && db_val) {
    u_short len = strlen(DEVICE_NAME);

    unescape_url(db_key);
    unescape_url(db_val);

    if(db_val[0] == '\0')
      delPrefsValue(db_key);
    else
      storePrefsValue(db_key, db_val);

    if(strncmp(db_key, DEVICE_NAME, strlen(DEVICE_NAME)) == 0) {
      int i;

      sanitize_rrd_string(db_val);

      for(i=0; i<myGlobals.numDevices; i++) {
	if((myGlobals.device[i].activeDevice) && (!strcmp(&db_key[len], myGlobals.device[i].name))) {
	  if(myGlobals.device[i].humanFriendlyName) free(myGlobals.device[i].humanFriendlyName);

	  if(db_val[0] == '\0')
	    myGlobals.device[i].humanFriendlyName = strdup(myGlobals.device[i].name);
	  else
	    myGlobals.device[i].humanFriendlyName = strdup(db_val);
	}
      }
    }
  }

  key = gdbm_firstkey(myGlobals.prefsFile);
  while (key.dptr) {
    char val[1024];

    if((db_key == NULL) || (strcmp(key.dptr, db_key) == 0)) {
      num_added++;
      if(fetchPrefsValue(key.dptr, val, sizeof(val)) == 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<FORM ACTION="CONST_EDIT_PREFS">"
		      "<TR><TH ALIGN=LEFT "DARK_BG"><INPUT TYPE=HIDDEN NAME=key VALUE=\"%s\">"
		      "<A NAME=\"%s\">%s</A></TH>"
		      "<TD>",
		      key.dptr, key.dptr, key.dptr);
	sendString(buf);

	if(!strcmp(key.dptr, EVENTS_MASK)) {
	  sendString("<SELECT NAME=val MULTIPLE>");

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<option value=%d %s>Host Creation</option>",
			hostCreation, ((atoi(val) & hostCreation) == hostCreation) ? "SELECTED" : "");
	  sendString(buf);
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<option value=%d %s>Host Deletion</option>",
			hostDeletion, ((atoi(val) & hostDeletion) == hostDeletion) ? "SELECTED" : "");
	  sendString(buf);
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<option value=%d %s>Session Creation</option>",
			sessionCreation, ((atoi(val) & sessionCreation) == sessionCreation) ? "SELECTED" : "");
	  sendString(buf);
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<option value=%d %s>Session Deletion</option>",
			sessionDeletion, ((atoi(val) & sessionDeletion) == sessionDeletion) ? "SELECTED" : "");
	  sendString(buf);
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<option value=%d %s>Host Flagged</option>",
			hostFlagged, ((atoi(val) & hostFlagged) == hostFlagged) ? "SELECTED" : "");
	  sendString(buf);
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<option value=%d %s>Host Unflagged</option>",
			hostUnflagged, ((atoi(val) & hostUnflagged) == hostUnflagged) ? "SELECTED" : "");
	  sendString(buf);

	  sendString("</SELECT>");
	} else {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<INPUT TYPE=TEXT NAME=val VALUE=\"%s\" size=60>",
			val);
	  sendString(buf);
	}

	sendString("</TD><TD ALIGN=CENTER><INPUT TYPE=SUBMIT VALUE=Set></TD></TR></FORM></A>\n");
      }
    }

    nextkey = gdbm_nextkey (myGlobals.prefsFile, key);
    free (key.dptr);
    key = nextkey;
  }

  if(((db_key == NULL) && (num_added > 0))
     || ((db_key != NULL) && (num_added == 0))) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<FORM ACTION="CONST_EDIT_PREFS">"
		  "<TR><TH ALIGN=LEFT "DARK_BG"><INPUT TYPE=TEXT NAME=key VALUE=\"%s\" size=30></TH>"
		  "<TD><INPUT TYPE=TEXT NAME=val VALUE=\"\" size=30></TD>"
		  "<TD ALIGN=CENTER><INPUT TYPE=SUBMIT VALUE=Add></TD></TR></FORM>\n",
		  (db_key == NULL) ? "" : db_key);
    sendString(buf);
  }

  sendString("</TABLE></CENTER>\n");

  sendString("<P><SMALL><B>NOTE:</B><ul>\n");
  sendString("<li>Set the value to \"\" (empty value) to delete an entry\n");
  sendString("<li>You can define a community adding an entry of type community.&lt;name&gt;=&lt;network list&gt;. For instance community.ntop.org=131.114.21.22/32\n");
  sendString("<li>You can map a numeric vlan id to a name adding an entry of type vlan.&lt;vlan id&gt;=&lt;vlan name&gt;. For instance vlan.10=Administration\n");
  sendString("</ul></SMALL><p>\n");

  if(db_key
     && ((!strcmp(db_key, EVENTS_MASK))
	 || (!strcmp(db_key, EVENTS_LOG)))) {
    init_events(); /* Reload events */
  }
}

