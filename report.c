/*
 *  Copyright (C) 1998-2009 Luca Deri <deri@ntop.org>
 *
 *  			    http://www.ntop.org/
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

static int network_mode_sort;

/* *************************** */

#ifndef WIN32
static void ignoreSignal(int signalId) {
  closeNwSocket(&myGlobals.newSock);
  (void)signal(signalId, ignoreSignal);
}
#endif

/* ******************************* */

void printBandwidthFooter(void) {
  sendString("<p><b>NOTE</b>:</p>\n<ul>"
	     "<li>You can <a href=\"" CONST_EDIT_PREFS "\">define</a> "
	     "new communities.</li>\n"
	     "<li>Click <a href=\"" CONST_HOST_SORT_NOTE_HTML "\">here</a> "
	     "for more information about host and domain sorting.</li>\n"
	     "<li>Inbound and outbound values are the percentage of the total bytes that "
	     "<b>ntop</b> has seen on the interface. Hover the mouse to see the actual "
	     "value (rounded to the nearest full percentage point). <i>The total of the "
	     "values will NOT be 100% as local traffic will be counted TWICE (once as "
	     "sent and again as received).</i></li>\n"
	     "<li>The SENT bandwidth is shown as "
	     "<img class=tooltip  align=\"absmiddle\" src=\"/gaugeS.jpg\" alt=\"Sent\" "
	     "title=\"Sent\" WIDTH=\"25\" HEIGHT=\"12\">"
	     " and the RECEIVED bandwidth is shown as "
	     "<img class=tooltip align=\"absmiddle\" src=\"/gaugeR.jpg\" alt=\"Received\" "
	     "title=\"Received\" WIDTH=\"25\" HEIGHT=\"12\"></li>\n"
	     "</ul></p>");
}

/* ******************************* */

void checkReportDevice(void) {
  int i;
  char value[LEN_SMALL_WORK_BUFFER];

  /* Show device table */
  for(i=0; i<myGlobals.numDevices; i++) {
    traceEvent(CONST_TRACE_NOISY, "Device %2d. %-30s%s%s%s",
	       i,
	       myGlobals.device[i].humanFriendlyName != NULL ?
	       myGlobals.device[i].humanFriendlyName :
	       myGlobals.device[i].name,
	       myGlobals.device[i].virtualDevice ? " (virtual)" : "",
	       myGlobals.device[i].dummyDevice ? " (dummy)" : "",
	       myGlobals.device[i].activeDevice ? " (active)" : "");
  }

  /* Corrections on stored value */
  if(myGlobals.runningPref.mergeInterfaces) {
    traceEvent(CONST_TRACE_NOISY,
               "INITWEB: Merging interfaces, reporting device forced to 0");
    storePrefsValue("actualReportDeviceId", "0");
  } else if(fetchPrefsValue("actualReportDeviceId", value, sizeof(value)) == -1) {
    traceEvent(CONST_TRACE_NOISY,
               "INITWEB: Reporting device not set, defaulting to 0");
    storePrefsValue("actualReportDeviceId", "0");
  } else if(atoi(value) >= myGlobals.numDevices) {
    traceEvent(CONST_TRACE_WARNING,
               "INITWEB: Reporting device (%d) invalid (> max, %d), defaulting to 0",
	       atoi(value), myGlobals.numDevices);
    storePrefsValue("actualReportDeviceId", "0");
  }

  /* Retrieve it */
  if(fetchPrefsValue("actualReportDeviceId", value, sizeof(value)) == -1) {
    myGlobals.actualReportDeviceId = 0;
  } else {
    myGlobals.actualReportDeviceId = atoi(value);
  }

  if(myGlobals.device[myGlobals.actualReportDeviceId].virtualDevice) {
    /* Bad idea, set to 1st non-virtual device */
    traceEvent(CONST_TRACE_WARNING,
               "INITWEB: Reporting device (%d) invalid (virtual), using 1st non-virtual device", i);
    for(i=0; i<myGlobals.numDevices; i++) {
      if(!myGlobals.device[i].virtualDevice) {
        myGlobals.actualReportDeviceId = i;
        safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", i);
        storePrefsValue("actualReportDeviceId", value);
	break;
      }
    }
  }
}

/* **************************************** */

void initReports(void) {
  myGlobals.columnSort = 0;

  checkReportDevice();

  traceEvent(CONST_TRACE_INFO,
	     "Note: Reporting device initally set to %d [%s]%s",
	     myGlobals.actualReportDeviceId,
	     myGlobals.device[myGlobals.actualReportDeviceId].humanFriendlyName != NULL ?
	     myGlobals.device[myGlobals.actualReportDeviceId].humanFriendlyName :
	     myGlobals.device[myGlobals.actualReportDeviceId].name,
	     myGlobals.runningPref.mergeInterfaces ? " (merged)" : "");
}

/* **************************************** */

int reportValues(time_t *lastTime) {
  if(myGlobals.runningPref.maxNumLines <= 0)
    myGlobals.runningPref.maxNumLines = CONST_NUM_TABLE_ROWS_PER_PAGE;

  *lastTime = time(NULL) + myGlobals.runningPref.refreshRate;

  /*
    Make sure that the other flags are't set. They have
    no effect in web mode
  */
  if(myGlobals.runningPref.refreshRate == 0)
    myGlobals.runningPref.refreshRate = DEFAULT_NTOP_AUTOREFRESH_INTERVAL;
  else if(myGlobals.runningPref.refreshRate < PARM_MIN_WEBPAGE_AUTOREFRESH_TIME)
    myGlobals.runningPref.refreshRate = PARM_MIN_WEBPAGE_AUTOREFRESH_TIME;

  return(0);
}

/* ******************************* */

void addPageIndicator(char *url, u_int pageNum,
		      u_int numEntries, u_int linesPerPage,
		      int revertOrder, int numCol, int netmode) {
  char buf[LEN_GENERAL_WORK_BUFFER/2], prevBuf[LEN_GENERAL_WORK_BUFFER/2],
    nextBuf[LEN_GENERAL_WORK_BUFFER/2], shortBuf[16], separator;
  int numPages = (numEntries+myGlobals.runningPref.maxNumLines-1)/myGlobals.runningPref.maxNumLines;
  int actPage  = pageNum+1;

  if(numPages <= 1) return;

  if(strchr(url, '?') != NULL)
    separator = '&';
  else
    separator = '?';

  if(revertOrder == -1)
    shortBuf[0] = '\0';
  else {
    safe_snprintf(__FILE__, __LINE__, shortBuf, sizeof(shortBuf),
		  "%s%d", revertOrder == 1 ? "-" : "", numCol);
  }

  if(pageNum >= 1) {
    safe_snprintf(__FILE__, __LINE__, prevBuf, sizeof(prevBuf),
		  "<td><A HREF=\"%s%cpage=0&netmode=%d&col=%s\"><IMG SRC=/fback.png BORDER=0 "TABLE_DEFAULTS" ALIGN=vbottom ALT=\"Back to first page\"></A> "
		  "<A HREF=\"%s%cpage=%d&netmode=%dcol=%s\"><IMG SRC=/back.png BORDER=0 "TABLE_DEFAULTS" ALIGN=vbottom ALT=\"Prior page\"></A></td>",
		  url, separator, netmode, shortBuf,
		  url, separator, pageNum-1, netmode, shortBuf);
  } else
    prevBuf[0] = '\0';

  if(actPage < numPages) {
    safe_snprintf(__FILE__, __LINE__, nextBuf, sizeof(nextBuf),
		  "<td><A HREF=\"%s%cpage=%d&netmode=%d&col=%s\"><IMG SRC=/forward.png BORDER=0 "TABLE_DEFAULTS" ALIGN=vbottom ALT=\"Next Page\"></A> "
		  "<A HREF=\"%s%cpage=%d&netmode=%d&col=%s\"><IMG SRC=/fforward.png BORDER=0 "TABLE_DEFAULTS" ALIGN=vbottom ALT=\"Forward to last page\"></A></td>",
		  url, separator, pageNum+1, netmode, shortBuf,
		  url, separator, numPages-1, netmode, shortBuf);
  }  else
    nextBuf[0] = '\0';

  sendString("<P><FONT FACE=Helvetica><B>");
  sendString("<table border=0><tr>\n");
  sendString(prevBuf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td valign=top> [ %d / %d ] </td>", actPage, numPages);
  sendString(buf);

  sendString(nextBuf);
  sendString("</tr></table>\n");
  sendString("</B></FONT>\n");
}

/* ******************************* */

void printTrafficSummary (int revertOrder) {
  Counter unicastPkts;
  int i;
  char buf[LEN_GENERAL_WORK_BUFFER], formatBuf[32], formatBuf1[32];
  struct pcap_stat pcapStat;

  unicastPkts = 0;
  printHTMLheader("Global Traffic Summary", NULL, 0);

  sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n");

  sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Network Interface(s)</TH>"
	     "<TD "TD_BG" ALIGN=RIGHT>");

  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%\">\n<TR "TR_ON" "DARK_BG"><TH "TH_BG" "DARK_BG">Name</TH>"
	     "<TH "TH_BG" "DARK_BG">Device</TH><TH "TH_BG" "DARK_BG">Type</TH>"
	     "<TH "TH_BG" "DARK_BG">Speed</TH><TH "TH_BG" "DARK_BG">Sampling Rate</TH><TH "TH_BG" "DARK_BG">MTU</TH>"
	     "<TH "TH_BG" "DARK_BG">Header</TH><TH "TH_BG" "DARK_BG">Address</TH>");

#ifdef INET6
  sendString("<TH "TH_BG" "DARK_BG">IPv6 Addresses</TH>");
#endif
  sendString("</TR>\n");

  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.device[i].activeDevice) {
      char buf1[128], custom_if_name[64];
      NtopIfaceAddr *ifaddr;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		    "device.name.%s", myGlobals.device[i].name);
      custom_if_name[0] = '\0';
      fetchPrefsValue(buf, custom_if_name, sizeof(custom_if_name));

      if(myGlobals.device[i].sflowGlobals || myGlobals.device[i].netflowGlobals)
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" ALIGN=CENTER><TD "TD_BG">"
		      "%s</TD>",
		      myGlobals.device[i].humanFriendlyName[0] != '\0' ?
		      myGlobals.device[i].humanFriendlyName : "&nbsp;");
      else
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" ALIGN=CENTER><TD "TD_BG">"
		      "%s <A HREF=\""CONST_EDIT_PREFS"?key=device.name.%s\">"
		      "<img class=tooltip alt=\"Change name\" src=/"CONST_EDIT_IMG" border=\"0\"></A></TD>",
		      custom_if_name,
		      (custom_if_name[0] != '\0') ? custom_if_name 
		      : ((myGlobals.device[i].uniqueIfName[0] != '\0') ? myGlobals.device[i].uniqueIfName : "&nbsp;"),
		      myGlobals.device[i].name);

      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%s</TD>",
		    myGlobals.device[i].name);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%s%s</TD>",
		    getNwInterfaceType(i), myGlobals.device[i].virtualDevice ? " virtual" : "");
      sendString(buf);

      sendString("<TD "TD_BG" ALIGN=RIGHT nowrap>&nbsp;");
      if(myGlobals.device[i].deviceSpeed > 0) {
	/* The speed is known */
	sendString(formatAdapterSpeed(myGlobals.device[i].deviceSpeed, formatBuf, sizeof(formatBuf)));
      } else
	sendString("&nbsp;");
      sendString("</TD>");

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d</TD>",
		    myGlobals.device[i].samplingRate);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d</TD>",
		    myGlobals.mtuSize[myGlobals.device[i].datalink]);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d</TD>",
		    myGlobals.headerSize[myGlobals.device[i].datalink]);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%s</TD>",
		    _intoa(myGlobals.device[i].ifAddr, buf1, sizeof(buf1)));
      sendString(buf);

#ifdef INET6
      sendString("<TD ALIGN=LEFT>");
      if(myGlobals.device[i].v6Addrs > 0) {
	for(ifaddr = myGlobals.device[i].v6Addrs;
	    ifaddr != NULL; ifaddr = ifaddr->next) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/%d<br>",
			_intop(&ifaddr->af.inet6.ifAddr, buf1, sizeof(buf1)),
			ifaddr->af.inet6.prefixlen);
	  sendString(buf);
	}
      } else
	sendString("&nbsp;");

      sendString("</TD>");
#endif
      sendString("</TR>\n");
    }
  }

  sendString("</TABLE>"TABLE_OFF);
  sendString("</TD></TR>\n");

  if(myGlobals.runningPref.domainName[0] != '\0') {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Local Domain Name</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;</TD></TR>\n",
		  myGlobals.runningPref.domainName);
    sendString(buf);
  }

  if(myGlobals.pcap_file_list == NULL) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Sampling Since</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s [%s]</TD></TR>\n",
		  ctime(&myGlobals.initialSniffTime),
		  formatSeconds(time(NULL)-myGlobals.initialSniffTime, formatBuf, sizeof(formatBuf)));
    sendString(buf);
  }
  else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Sampling Since</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  ctime(&myGlobals.initialSniffTime));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" align=left "DARK_BG">Last Packet Seen</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s [%s]</TD></TR>\n",
		  ctime((time_t *)&myGlobals.lastPktTime),
		  formatSeconds(myGlobals.lastPktTime.tv_sec-myGlobals.initialSniffTime, formatBuf, sizeof(formatBuf)));
    sendString(buf);
  }

  if((i = numActiveSenders(myGlobals.actualReportDeviceId)) > 0) {
    /* Do NOT add a '/' at the end of the path because Win32 will complain about it */
    struct stat statbuf;

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/interfaces/%s",
		  myGlobals.rrdPath != NULL ? myGlobals.rrdPath : ".",
		  myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName);

    revertSlashIfWIN32(buf, 0);

    if(stat(buf, &statbuf) != 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Active End Nodes</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%u</TD></TR>\n", i);
    } else
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Active End Nodes</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>"
		    "%u <A HREF=\"/plugins/rrdPlugin?action=arbreq&which=graph&arbfile=knownHostsNum"
		    "&arbiface=%s&start=%u&end=%u&counter=&title=%s&mode=zoom\">"
		    "<IMG valign=top class=tooltip SRC=/graph.gif border=0></A>"
		    "</TD></TR>\n",
		    i, myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, (unsigned int)(myGlobals.actTime-3600),
		    (unsigned int)myGlobals.actTime, "Active+End+Nodes");


    sendString(buf);
  }

  if((myGlobals.runningPref.currentFilterExpression != NULL)
     && (myGlobals.runningPref.currentFilterExpression[0] != '\0')) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Traffic Filter</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  myGlobals.runningPref.currentFilterExpression);


    sendString(buf);
  }

  if(myGlobals.numDevices > 1) {
    int found = 0;

    for(i=0; i<myGlobals.numDevices; i++)
      if(myGlobals.device[i].ethernetPkts.value > 0) {
	found = 1;
	break;
      }

    if(found) {
      sendString("<TR "TR_ON" BGCOLOR=white><TH "TH_BG" ALIGN=CENTER COLSPAN=3 BGCOLOR=white>"
		 "<iframe frameborder=0 SRC=\"" CONST_PIE_INTERFACE_DIST CHART_FORMAT "\"></iframe></TH></TR>\n");
    }
  }

  if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value > 0) {
    unicastPkts = myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value
      - myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value
      - myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value;

    if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value <= 0)
      myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value = 1;

    if(myGlobals.device[myGlobals.actualReportDeviceId].pcapPtr != NULL) {
      if(pcap_stats(myGlobals.device[myGlobals.actualReportDeviceId].pcapPtr, &pcapStat) >= 0) {
	Counter realDropped;

	/*
	  Recent libpcap versions do not report total/cumulative values
	  but their value is reset everytime is read
	*/

	if(myGlobals.device[myGlobals.actualReportDeviceId].receivedPkts.value > pcapStat.ps_recv) {
	  /* The counter is reset at each run */
	  realDropped = (myGlobals.device[myGlobals.actualReportDeviceId].pcapDroppedPkts.value += pcapStat.ps_drop);

	} else {
	  /* The counter is NOT reset at each run */
	  myGlobals.device[myGlobals.actualReportDeviceId].pcapDroppedPkts.value = pcapStat.ps_drop;
	  realDropped = myGlobals.device[myGlobals.actualReportDeviceId].pcapDroppedPkts.value
	    - myGlobals.device[myGlobals.actualReportDeviceId].initialPcapDroppedPkts.value;
	}

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Dropped&nbsp;(libpcap)</th>"
		      "<TD "TD_BG" align=right>%s(%.1f%%)</td></TR>\n",
		      getRowColor(),
		      formatPkts(realDropped, formatBuf, sizeof(formatBuf)), (float)(realDropped*100)
		      /(float)myGlobals.device[myGlobals.actualReportDeviceId].receivedPkts.value);
	sendString(buf);
      }
    }

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Dropped&nbsp;(ntop)</th>"
		  "<TD "TD_BG" align=right>%s(%.1f%%)</td></TR>\n",
		  getRowColor(),
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].droppedPkts.value,
			     formatBuf, sizeof(formatBuf)),
                  (float)(myGlobals.device[myGlobals.actualReportDeviceId].droppedPkts.value*100)
                  /(float)myGlobals.device[myGlobals.actualReportDeviceId].receivedPkts.value);
    sendString(buf);

    if(!myGlobals.runningPref.printFcOnly) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Unicast</th>"
		    "<TD "TD_BG" align=right>%s(%.1f%%)</td></TR>\n",
		    getRowColor(),
		    formatPkts(unicastPkts, formatBuf, sizeof(formatBuf)),
		    (float)(100*unicastPkts)/(float)myGlobals.device[myGlobals.actualReportDeviceId].
		    ethernetPkts.value);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Broadcast</th>"
		    "<TD "TD_BG" align=right>%s(%.1f%%)</td></TR>\n",
		    getRowColor(),
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value, formatBuf, sizeof(formatBuf)),
		    (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Multicast</th>"
		    "<TD "TD_BG" align=right>%s(%.1f%%)</td></TR>\n",
		    getRowColor(),
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value, formatBuf, sizeof(formatBuf)),
		    (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Packets&nbsp;too&nbsp;long [> %d]</th>"
		    "<TD "TD_BG" align=right>%s(%.1f%%)</td></TR>\n",
		    getRowColor(), myGlobals.mtuSize[myGlobals.device[myGlobals.actualReportDeviceId].datalink],
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.tooLong.value, formatBuf, sizeof(formatBuf)),
		    (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.tooLong.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Bad&nbsp;Packets&nbsp;(Checksum)</th>"
		    "<TD "TD_BG" align=right>%s(%.1f%%)</td></TR>\n",
		    getRowColor(),
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.badChecksum.value, formatBuf, sizeof(formatBuf)),
		    (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
			    rcvdPktStats.badChecksum.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value);
      sendString(buf);
    }

    /* ****************** */

    if(!myGlobals.runningPref.printIpOnly &&
       myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value > 0) {
      if(myGlobals.device[myGlobals.actualReportDeviceId].pcapPtr != NULL) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Total</th>"
		      "<TD "TD_BG" align=right COLSPAN=2>%s [%s Pkts]</td></TR>\n",
		      getRowColor(),
		      formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].fcBytes.value, 1,
				  formatBuf, sizeof(formatBuf)),
		      formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
				 formatBuf1, sizeof(formatBuf1)));
	sendString(buf);
#ifdef NOT_YET
	if(myGlobals.device[myGlobals.actualReportDeviceId].droppedPkts.value > 0) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Dropped&nbsp;by&nbsp;the&nbsp;kernel</th>"
			"<TD "TD_BG" COLSPAN=2 align=right>%s [%.2f %%]</td></TR>\n",
			getRowColor(),
			formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].droppedPkts.value,
				   formatBuf, sizeof(formatBuf)),
			(float)(myGlobals.device[myGlobals.actualReportDeviceId].droppedPkts.value*100)
			/(float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value);
	  sendString(buf);
	}
#endif
      }

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Unicast</th>"
		    "<TD "TD_BG" align=right>%s(%.1f%%)</td></TR>\n",
		    getRowColor(),
		    formatPkts(unicastPkts, formatBuf, sizeof(formatBuf)),
		    (float)(100*unicastPkts)/(float)myGlobals.device[myGlobals.actualReportDeviceId].
		    fcPkts.value);
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Broadcast</th>"
		    "<TD "TD_BG" align=right>%s(%.1f%%)</td></TR>\n",
		    getRowColor(),
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].fcBroadcastPkts.value,
			       formatBuf, sizeof(formatBuf)),
		    (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].fcBroadcastPkts.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value);
      sendString(buf);

    }
    /* ****************** */

    if(!myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
      updateThpt(0);

      sendString("<TR><TH "TH_BG" ALIGN=LEFT "DARK_BG">Network Load</TH><TD "TH_BG">\n<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%\">");
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Actual</th><TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkt/s</td></TR>\n",
		    getRowColor(), formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].actualThpt,
						    1, formatBuf, sizeof(formatBuf)),
		    myGlobals.device[myGlobals.actualReportDeviceId].actualPktsThpt);
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Last Minute</th>"
		    "<TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkt/s</td></TR>\n",
		    getRowColor(), formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].lastMinThpt,
						    1, formatBuf, sizeof(formatBuf)),
		    myGlobals.device[myGlobals.actualReportDeviceId].lastMinPktsThpt);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Last 5 Minutes</th>"
		    "<TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkt/s</td></TR>\n",
		    getRowColor(), formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].lastFiveMinsThpt,
						    1, formatBuf, sizeof(formatBuf)),
		    myGlobals.device[myGlobals.actualReportDeviceId].lastFiveMinsPktsThpt);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Peak</th>"
		    "<TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkt/s</td></TR>\n",
		    getRowColor(), formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].peakThroughput,
						    1, formatBuf, sizeof(formatBuf)),
		    myGlobals.device[myGlobals.actualReportDeviceId].peakPacketThroughput);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Average</th>"
		    "<TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkt/s</td></TR>\n",
		    getRowColor(),
		    formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value/
				     (myGlobals.actTime-myGlobals.initialSniffTime+1), 1, formatBuf, sizeof(formatBuf)),
		    /* Bug below fixed courtesy of Eddy Lai <eddy@ModernTerminals.com> */
		    ((float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value/
		     (float)(myGlobals.actTime-myGlobals.initialSniffTime+1)));
      sendString(buf);

      sendString("</TABLE>"TABLE_OFF"</TR>\n");
    }
  }

  /* ********************* */

  sendString("</TABLE></CENTER>\n");

  if(!myGlobals.runningPref.printFcOnly) {
    printProtoTraffic(FALSE);
    sendString("<p>\n");
    printIpProtocolDistribution(FLAG_HOSTLINK_HTML_FORMAT, revertOrder, FALSE);
  }
  if(!myGlobals.runningPref.printIpOnly) {
    sendString("<p>\n");
    printFcTrafficSummary(0);
  }
}

/* ******************************* */

void printTrafficStatistics(int revertOrder) {
  Counter unicastPkts, avgPktLen;
  int i;
  char buf[LEN_GENERAL_WORK_BUFFER], formatBuf[32], formatBuf1[32];
  struct stat statbuf;
  struct pcap_stat pcapStat;

  unicastPkts = 0;
  printHTMLheader("Global Traffic Statistics", NULL, 0);

  sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n");

  sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Network Interface(s)</TH>"
	     "<TD "TD_BG" ALIGN=RIGHT>");

  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%\">\n<TR "TR_ON" "DARK_BG"><TH "TH_BG" "DARK_BG">Name</TH>"
	     "<TH "TH_BG" "DARK_BG">Device</TH><TH "TH_BG" "DARK_BG">Type</TH>"
	     "<TH "TH_BG" "DARK_BG">Speed</TH><TH "TH_BG" "DARK_BG">Sampling Rate</TH><TH "TH_BG" "DARK_BG">MTU</TH>"
	     "<TH "TH_BG" "DARK_BG">Header</TH><TH "TH_BG" "DARK_BG">Address</TH>");

#ifdef INET6
  sendString("<TH "TH_BG" "DARK_BG">IPv6 Addresses</TH>");
#endif
  sendString("</TR>\n");

  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.device[i].activeDevice) {
      char buf1[128], custom_if_name[64];
      NtopIfaceAddr *ifaddr;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		    "device.name.%s", myGlobals.device[i].name);
      custom_if_name[0] = '\0';
      fetchPrefsValue(buf, custom_if_name, sizeof(custom_if_name));

      if(myGlobals.device[i].sflowGlobals || myGlobals.device[i].netflowGlobals)
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" ALIGN=CENTER><TD "TD_BG">"
		      "%s</TD>",
		      myGlobals.device[i].humanFriendlyName[0] != '\0' ?
		      myGlobals.device[i].humanFriendlyName : "&nbsp;");
      else
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" ALIGN=CENTER><TD "TD_BG">"
		      "%s <A HREF=\""CONST_EDIT_PREFS"?key=device.name.%s\">"
		      "<img class=tooltip alt=\"Change name\" src=/"CONST_EDIT_IMG" border=\"0\"></A></TD>",
		      (custom_if_name[0] != '\0') ? custom_if_name
                      : ((myGlobals.device[i].uniqueIfName[0] != '\0') ? myGlobals.device[i].uniqueIfName : "&nbsp;"),
                      myGlobals.device[i].name);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%s</TD>",
		    myGlobals.device[i].name);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%s%s</TD>",
		    getNwInterfaceType(i), myGlobals.device[i].virtualDevice ? " virtual" : "");
      sendString(buf);

      sendString("<TD "TD_BG" ALIGN=RIGHT nowrap>&nbsp;");
      if(myGlobals.device[i].deviceSpeed > 0) {
	/* The speed is known */
	sendString(formatAdapterSpeed(myGlobals.device[i].deviceSpeed, formatBuf, sizeof(formatBuf)));
      } else
	sendString("&nbsp;");
      sendString("</TD>");

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d</TD>",
		    myGlobals.device[i].samplingRate);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d</TD>",
		    myGlobals.mtuSize[myGlobals.device[i].datalink]);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d</TD>",
		    myGlobals.headerSize[myGlobals.device[i].datalink]);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%s</TD>",
		    _intoa(myGlobals.device[i].ifAddr, buf1, sizeof(buf1)));
      sendString(buf);

#ifdef INET6
      sendString("<TD ALIGN=LEFT>");
      if(myGlobals.device[i].v6Addrs > 0) {
	for(ifaddr = myGlobals.device[i].v6Addrs;
	    ifaddr != NULL; ifaddr = ifaddr->next) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/%d<br>",
			_intop(&ifaddr->af.inet6.ifAddr, buf1, sizeof(buf1)),
			ifaddr->af.inet6.prefixlen);
	  sendString(buf);
	}
      } else
	sendString("&nbsp;");

      sendString("</TD>");
#endif
      sendString("</TR>\n");
    }
  }

  sendString("</TABLE>"TABLE_OFF);
  sendString("</TD></TR>\n");

  if(myGlobals.runningPref.domainName[0] != '\0') {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Local Domain Name</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;</TD></TR>\n",
		  myGlobals.runningPref.domainName);
    sendString(buf);
  }

  if(myGlobals.pcap_file_list == NULL) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Sampling Since</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s [%s]</TD></TR>\n",
		  ctime(&myGlobals.initialSniffTime),
		  formatSeconds(time(NULL)-myGlobals.initialSniffTime, formatBuf, sizeof(formatBuf)));
    sendString(buf);
  }
  else {
    time_t t = myGlobals.lastPktTime.tv_sec;

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Sampling Since</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  ctime(&myGlobals.initialSniffTime));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" align=left "DARK_BG">Last Packet Seen</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s [%s]</TD></TR>\n",
		  ctime(&t),
		  formatSeconds(myGlobals.lastPktTime.tv_sec-myGlobals.initialSniffTime, formatBuf, sizeof(formatBuf)));
    sendString(buf);
  }

  if((i = numActiveSenders(myGlobals.actualReportDeviceId)) > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/interfaces/%s",
		  myGlobals.rrdPath != NULL ? myGlobals.rrdPath : ".",
		  myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName);

    revertSlashIfWIN32(buf, 0);

    if(stat(buf, &statbuf) != 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Active End Nodes</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%u</TD></TR>\n", i);
    } else
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Active End Nodes</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>"
		    "%u <A HREF=\"/plugins/rrdPlugin?action=arbreq&which=graph&arbfile=knownHostsNum&arbiface=%s&start=%u&end=%u&counter=&title=%s&mode=zoom\">"
		    "<IMG valign=top class=tooltip SRC=/graph.gif border=0></A>"
		    "</TD></TR>\n",
		    i, myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, (unsigned int)(myGlobals.actTime-3600),
		    (unsigned int)myGlobals.actTime, "Active+End+Nodes");


    sendString(buf);
  }

  if((myGlobals.runningPref.currentFilterExpression != NULL)
     && (myGlobals.runningPref.currentFilterExpression[0] != '\0')) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Traffic Filter</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  myGlobals.runningPref.currentFilterExpression);
    sendString(buf);
  }

  if(myGlobals.numDevices > 1) {
    int found = 0;

    for(i=0; i<myGlobals.numDevices; i++)
      if(myGlobals.device[i].ethernetPkts.value > 0) {
	found = 1;
	break;
      }

    if(found) {
      sendString("<TR "TR_ON" BGCOLOR=white><TH "TH_BG" ALIGN=CENTER COLSPAN=3 BGCOLOR=white>"
		 "<iframe frameborder=0 SRC=\"" CONST_PIE_INTERFACE_DIST CHART_FORMAT "\" width=400 height=250></iframe></TH></TR>\n");
    }
  }

  if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value > 0) {
    Counter dummyCounter;

    sendString("</TABLE>"TABLE_OFF"</CENTER>\n");

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "Traffic Report for '%s' [<A HREF=/switch.html>switch</A>]",
		  myGlobals.device[myGlobals.actualReportDeviceId].humanFriendlyName);

    printSectionTitle(buf);
    sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n");

    sendString("<TR><TH "TH_BG" align=left "DARK_BG">Packets</TH><TD "TH_BG">\n"
	       "<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%\">\n");

    unicastPkts = myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value
      - myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value
      - myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value;

    if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value <= 0)
      myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value = 1;

    if(myGlobals.device[myGlobals.actualReportDeviceId].pcapPtr != NULL) {
      if(pcap_stats(myGlobals.device[myGlobals.actualReportDeviceId].pcapPtr, &pcapStat) >= 0) {
	/*
	  Recent libpcap versions do not report total/cumulative values
	  but their value is reset everytime is read
	*/

	if(myGlobals.device[myGlobals.actualReportDeviceId].receivedPkts.value > pcapStat.ps_recv) {
	  /* The counter is reset at each run */
	  myGlobals.device[myGlobals.actualReportDeviceId].pcapDroppedPkts.value += pcapStat.ps_drop;
	} else {
	  /* The counter is NOT reset at each run */
	  myGlobals.device[myGlobals.actualReportDeviceId].pcapDroppedPkts.value = pcapStat.ps_drop;
	}

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Dropped&nbsp;(libpcap)</th>"
		      "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		      getRowColor(),
		      (float)(myGlobals.device[myGlobals.actualReportDeviceId].pcapDroppedPkts.value*100)
		      /(float)myGlobals.device[myGlobals.actualReportDeviceId].receivedPkts.value,
		      formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].pcapDroppedPkts.value,
				 formatBuf, sizeof(formatBuf)));
	sendString(buf);
      }
    }

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Dropped&nbsp;(ntop)</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(),
		  (float)(myGlobals.device[myGlobals.actualReportDeviceId].droppedPkts.value*100)
		  /(float)myGlobals.device[myGlobals.actualReportDeviceId].receivedPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].droppedPkts.value,
			     formatBuf, sizeof(formatBuf)));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Total&nbsp;Received&nbsp;(ntop)</th>"
		  "<TD "TD_BG" COLSPAN=2 align=right>%s</td></TR>\n",
		  getRowColor(), formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].receivedPkts.value,
					    formatBuf, sizeof(formatBuf)));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Total Packets Processed</th>"
		  "<TD "TD_BG" COLSPAN=2 align=right>%s</td></TR>\n",
		  getRowColor(), formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
					    formatBuf, sizeof(formatBuf)));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Unicast</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*unicastPkts)/(float)myGlobals.device[myGlobals.actualReportDeviceId].
		  ethernetPkts.value,
		  formatPkts(unicastPkts, formatBuf, sizeof(formatBuf)));
    sendString(buf);
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Broadcast</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value, formatBuf, sizeof(formatBuf)));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Multicast</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value, formatBuf, sizeof(formatBuf)));
    sendString(buf);

    if(myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value > 0)
      sendString("<TR "TR_ON" BGCOLOR=white><TH "TH_BG" ALIGN=CENTER COLSPAN=3 BGCOLOR=white>"
		 "<iframe frameborder=0 SRC=\"" CONST_PIE_PKT_CAST_DIST CHART_FORMAT "\" "
		 "width=400 height=250></iframe></TH></TR>\n");

    if(!myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
      /*
	Very rudimental formula. Note that as specified in RMON, packets smaller
	than 64 or larger than 1518 octets are not counted.
      */
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Shortest</th>"
		    "<TD "TD_BG" align=right colspan=2>%s bytes</td></TR>\n",
		    getRowColor(),
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.shortest.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);
      avgPktLen = (96*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value
		   +192*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value
		   +384*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value
		   +768*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value
		   +1271*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value)/
	(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value+1);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Average&nbsp;Size</th>"
		    "<TD "TD_BG" align=right colspan=2>%s bytes</td></TR>\n",
		    getRowColor(), formatPkts(avgPktLen, formatBuf, sizeof(formatBuf)));
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Longest</th>"
		    "<TD "TD_BG" align=right colspan=2>%s bytes</td></TR>\n",
		    getRowColor(), formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].
					      rcvdPktStats.longest.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Size&nbsp;&lt;=&nbsp;64&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktStats.upTo64.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">64&nbsp;&lt;&nbsp;Size&nbsp;&lt;=&nbsp;128&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktStats.upTo128.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">128&nbsp;&lt;&nbsp;Size&nbsp;&lt;=&nbsp;256&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktStats.upTo256.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">256&nbsp;&lt;&nbsp;Size&nbsp;&lt;=&nbsp;512&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktStats.upTo512.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">512&nbsp;&lt;&nbsp;Size&nbsp;&lt;=&nbsp;1024&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktStats.upTo1024.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">1024&nbsp;&lt;&nbsp;Size&nbsp;&lt;=&nbsp;1518&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktStats.upTo1518.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);

#ifdef MAKE_WITH_JUMBO_FRAMES
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">1518&nbsp;&lt;&nbsp;Size&nbsp;&lt;=&nbsp;2500&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktStats.upTo2500.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo2500.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">2500&nbsp;&lt;&nbsp;Size&nbsp;&lt;=&nbsp;6500&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktStats.upTo6500.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo6500.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">6500&nbsp;&lt;&nbsp;Size&nbsp;&lt;=&nbsp;9000&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktStats.upTo9000.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo9000.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">&gt;&nbsp;9000&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktStats.above9000.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above9000.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);
#else
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Size&nbsp;&gt;&nbsp;1518&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktStats.above1518.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);
#endif /* MAKE_WITH_JUMBO_FRAMES */

      if(myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value > 0)
	sendString("<TR "TR_ON" BGCOLOR=white><TH "TH_BG" ALIGN=CENTER COLSPAN=3 BGCOLOR=white>"
		   "<iframe frameborder=0 SRC=\"" CONST_PIE_PKT_SIZE_DIST  CHART_FORMAT "\" width=400 height=250></iframe></TH></TR>\n");

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Packets&nbsp;too&nbsp;long [> %d]</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), myGlobals.mtuSize[myGlobals.device[myGlobals.actualReportDeviceId].datalink],
		    (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.tooLong.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.tooLong.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Bad&nbsp;Packets&nbsp;(Checksum)</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktStats.badChecksum.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.badChecksum.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);
    }

    /* ****************** */

    if(!myGlobals.runningPref.printIpOnly &&
       myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value > 0) {
      sendString("</TABLE>"TABLE_OFF"</TR><TR><TH "TH_BG" ALIGN=LEFT "DARK_BG">FC Packets</TH><TD "TH_BG">\n<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%\">");

      if(myGlobals.device[myGlobals.actualReportDeviceId].pcapPtr != NULL) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Total</th>"
		      "<TD "TD_BG" align=right COLSPAN=2>%s [%s Pkts]</td></TR>\n",
		      getRowColor(),
		      formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].fcBytes.value, 1,
				  formatBuf, sizeof(formatBuf)),
		      formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
				 formatBuf1, sizeof(formatBuf1)));
	sendString(buf);
#ifdef NOT_YET
	if(myGlobals.device[myGlobals.actualReportDeviceId].droppedPkts.value > 0) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Dropped&nbsp;by&nbsp;the&nbsp;kernel</th>"
			"<TD "TD_BG" COLSPAN=2 align=right>%s [%.2f %%]</td></TR>\n",
			getRowColor(),
			formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].droppedPkts.value,
				   formatBuf, sizeof(formatBuf)),
			(float)(myGlobals.device[myGlobals.actualReportDeviceId].droppedPkts.value*100)
			/(float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value);
	  sendString(buf);
	}
#endif
      }

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Unicast</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*unicastPkts)/(float)myGlobals.device[myGlobals.actualReportDeviceId].
		    fcPkts.value,
		    formatPkts(unicastPkts, formatBuf, sizeof(formatBuf)));
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Broadcast</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].fcBroadcastPkts.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].fcBroadcastPkts.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Shortest</th>"
		    "<TD "TD_BG" align=right colspan=2>%s bytes</td></TR>\n",
		    getRowColor(),
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.shortest.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);

      avgPktLen = myGlobals.device[myGlobals.actualReportDeviceId].fcBytes.value/
	myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value;
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Average&nbsp;Size</th>"
		    "<TD "TD_BG" align=right colspan=2>%s bytes</td></TR>\n",
		    getRowColor(), formatPkts(avgPktLen, formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Longest</th>"
		    "<TD "TD_BG" align=right colspan=2>%s bytes</td></TR>\n",
		    getRowColor(), formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].
					      rcvdFcPktStats.longest.value, formatBuf,
					      sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">&le&nbsp;36&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdFcPktStats.upTo36.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo36.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" "DARK_BG" align=left>&le;&nbsp;48&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdFcPktStats.upTo48.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo48.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" "DARK_BG" align=left>&le;&nbsp;52&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdFcPktStats.upTo52.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo52.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" "DARK_BG" align=left>&le;&nbsp;68&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdFcPktStats.upTo68.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo68.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" "DARK_BG" align=left>&le;&nbsp;104&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdFcPktStats.upTo104.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo104.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" "DARK_BG" align=left>&le;&nbsp;548&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdFcPktStats.upTo548.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo548.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" "DARK_BG" align=left>&le;&nbsp;1060&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdFcPktStats.upTo1060.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo1060.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" "DARK_BG" align=left>&le;&nbsp;2136&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdFcPktStats.upTo2136.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo2136.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" "DARK_BG" align=left>&gt;&nbsp;2136&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdFcPktStats.above2136.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.above2136.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);

      sendString("<TR "TR_ON" BGCOLOR=white><TH "TH_BG" ALIGN=CENTER COLSPAN=3 BGCOLOR=white>"
		 "<iframe frameborder=0 SRC=\"" CONST_PIE_FC_PKT_SZ_DIST  CHART_FORMAT "\" width=400 height=250></iframe></TH></TR>\n");

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" "DARK_BG" align=left>Packets&nbsp;too&nbsp;long [> %d]</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), 2136,
		    (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.above2136.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.above2136.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" "DARK_BG" align=left>Bad&nbsp;EOF&nbsp;Frames</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdFcPktStats.badCRC.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.badCRC.value,
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);

    }
    /* ****************** */

    sendString("</TABLE>"TABLE_OFF"</TR><TR><TH "TH_BG" ALIGN=LEFT "DARK_BG">Traffic</TH><TD "TH_BG">\n<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Total</th>"
		  "<TD "TD_BG" align=right COLSPAN=2>%s [%s Pkts]</td></TR>\n",
		  getRowColor(),
		  formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value, 1, formatBuf, sizeof(formatBuf)),
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">IPv4 Traffic</th>"
		  "<TD "TD_BG" align=right COLSPAN=2>%s [%s Pkts]</td></TR>\n",
		  getRowColor(), formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value, 1, formatBuf, sizeof(formatBuf)),
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);

    if(myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Fragmented IPv4 Traffic</th>"
		    "<TD "TD_BG" align=right COLSPAN=2>%s [%.1f%%]</td></TR>\n",
		    getRowColor(),
		    formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].fragmentedIpBytes.value, 1, formatBuf, sizeof(formatBuf)),
		    (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].fragmentedIpBytes.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value);
      sendString(buf);
    }

    /* Just in case... */
    if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value >
       myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value)
      dummyCounter = myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value-
	myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value;
    else
      dummyCounter = 0;

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Non IPv4 Traffic</th>"
		  "<TD "TD_BG" align=right COLSPAN=2>%s</td></TR>\n",
		  getRowColor(), formatBytes(dummyCounter, 1, formatBuf, sizeof(formatBuf)));
    sendString(buf);

    if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value > 0)
      sendString("<TR "TR_ON" BGCOLOR=white><TH "TH_BG" ALIGN=CENTER COLSPAN=3 BGCOLOR=white>"
		 "<iframe frameborder=0 SRC=\"" CONST_PIE_IP_TRAFFIC  CHART_FORMAT "\" width=400 height=250></iframe></TH></TR>\n");

    /* ********************* */

    if(myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value > 0) {
      int avgPktTTL;

      avgPktTTL = (int)((16*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32.value
			 +48*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64.value
			 +80*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96.value
			 +112*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128.value
			 +144*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160.value
			 +176*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192.value
			 +208*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224.value
			 +240*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo255.value)/
			myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value);

      if(avgPktTTL > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Average&nbsp;TTL</th>"
		      "<TD "TD_BG" align=right COLSPAN=2>%d</td></TR>\n",
		      getRowColor(), avgPktTTL);
	sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">TTL &lt;= 32</th>"
		      "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		      getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					     rcvdPktTTLStats.upTo32.value)/
		      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		      formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32.value,
				 formatBuf, sizeof(formatBuf)));
	sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">32 &lt; TTL &lt;= 64</th>"
		      "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		      getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					     rcvdPktTTLStats.upTo64.value)/
		      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		      formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64.value,
				 formatBuf, sizeof(formatBuf)));
	sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">64 &lt; TTL &lt;= 96</th>"
		      "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		      getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					     rcvdPktTTLStats.upTo96.value)/
		      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		      formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96.value,
				 formatBuf, sizeof(formatBuf)));
	sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">96 &lt; TTL &lt;= 128</th>"
		      "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		      getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					     rcvdPktTTLStats.upTo128.value)/
		      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		      formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128.value,
				 formatBuf, sizeof(formatBuf)));
	sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">128 &lt; TTL &lt;= 160</th>"
		      "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		      getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					     rcvdPktTTLStats.upTo160.value)/
		      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		      formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160.value,
				 formatBuf, sizeof(formatBuf)));
	sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">160 &lt; TTL &lt;= 192</th>"
		      "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		      getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					     rcvdPktTTLStats.upTo192.value)/
		      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		      formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192.value,
				 formatBuf, sizeof(formatBuf)));
	sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">192 &lt; TTL &lt;= 224</th>"
		      "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		      getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					     rcvdPktTTLStats.upTo224.value)/
		      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		      formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224.value,
				 formatBuf, sizeof(formatBuf)));
	sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">224 &lt; TTL &lt;= 256</th>"
		      "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		      getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					     rcvdPktTTLStats.upTo255.value)/
		      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		      formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo255.value,
				 formatBuf, sizeof(formatBuf)));
	sendString(buf);

	sendString("<TR "TR_ON" BGCOLOR=white><TH "TH_BG" ALIGN=CENTER COLSPAN=3 BGCOLOR=white>"
		   "<iframe frameborder=0 SRC=\"" CONST_PIE_TTL_DIST  CHART_FORMAT "\" width=400 height=250></iframe></TH></TR>\n");
      }
    }

    sendString("</TABLE>"TABLE_OFF"</TR>");

    /* ************************ */

    if(myGlobals.runningPref.enableSessionHandling && drawHostsDistanceGraph(1))
      sendString("<TR><TH "TH_BG" ALIGN=LEFT "DARK_BG">Remote Hosts Distance</TH>"
                 "<TD BGCOLOR=white ALIGN=CENTER>"
		 "<iframe frameborder=0 SRC=\"" CONST_BAR_HOST_DISTANCE CHART_FORMAT "\" width=400 height=250></iframe>"
                 "</TD></TR>\n");

    if(!myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
      updateThpt(0);

      sendString("<TR><TH "TH_BG" ALIGN=LEFT "DARK_BG">Network Load</TH><TD "TH_BG">\n<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%\">");
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Actual</th><TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkt/s</td></TR>\n",
		    getRowColor(), formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].actualThpt,
						    1, formatBuf, sizeof(formatBuf)),
		    myGlobals.device[myGlobals.actualReportDeviceId].actualPktsThpt);
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Last Minute</th>"
		    "<TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkt/s</td></TR>\n",
		    getRowColor(), formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].lastMinThpt,
						    1, formatBuf, sizeof(formatBuf)),
		    myGlobals.device[myGlobals.actualReportDeviceId].lastMinPktsThpt);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Last 5 Minutes</th>"
		    "<TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkt/s</td></TR>\n",
		    getRowColor(), formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].lastFiveMinsThpt,
						    1, formatBuf, sizeof(formatBuf)),
		    myGlobals.device[myGlobals.actualReportDeviceId].lastFiveMinsPktsThpt);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Peak</th>"
		    "<TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkt/s</td></TR>\n",
		    getRowColor(), formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].peakThroughput,
						    1, formatBuf, sizeof(formatBuf)),
		    myGlobals.device[myGlobals.actualReportDeviceId].peakPacketThroughput);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left "DARK_BG">Average</th>"
		    "<TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkt/s</td></TR>\n",
		    getRowColor(),
		    formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value/
				     (myGlobals.actTime-myGlobals.initialSniffTime+1), 1, formatBuf, sizeof(formatBuf)),
		    /* Bug below fixed courtesy of Eddy Lai <eddy@ModernTerminals.com> */
		    ((float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value/
		     (float)(myGlobals.actTime-myGlobals.initialSniffTime+1)));
      sendString(buf);


#if 0
      sendString("<script>if(hasSVGSupport) {\n");
      sendString("document.write(\"<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
		 "<embed src=\"/graph_if.svg\" width=\"400\" height=\"250\" type=\"image/svg+xml\" />"
		 "</TH></TR>\n\"); }</script>\n");
#endif

#if 0
      sendString("<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
		 "<embed src=\"/bar.html\" width=\"400\" height=\"250\" SCROLLING=NO>"
		 "</TH></TR>\n");

#endif
      sendString("</TABLE>"TABLE_OFF"</TR>\n");
    }
  }

  /* ********************* */

  if(strcmp(myGlobals.device[0].name, "pcap-file")) {
    /* RRD */
    /* Do NOT add a '/' at the end of the path because Win32 will complain about it */
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/interfaces/%s",
		  myGlobals.rrdPath != NULL ? myGlobals.rrdPath : ".",
		  myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName);

    revertSlashIfWIN32(buf, 0);

    if((i = stat(buf, &statbuf)) == 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">Historical Data</TH>\n"
		    "<TD "TD_BG" align=\"right\">"
		    "[ <a href=\"/" CONST_PLUGINS_HEADER
		    "rrdPlugin?action=list&amp;key=interfaces%s%s&amp;title=interface%%20%s\">"
		    "<img class=tooltip valign=\"top\" border=\"0\" src=\"/graph.gif\""
		    " alt=\"View rrd charts of historical data for this interface\"></a> ]"
		    "</TD></TR>\n",
		    getRowColor(),
		    (myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName[0] == '/') ? "" : "/",
		    myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
		    myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName);
      sendString(buf);
    }
  }

  /* ********************* */

  sendString("</TABLE></CENTER>\n");

  if(!myGlobals.runningPref.printFcOnly) {
    printProtoTraffic(TRUE);
    sendString("<p>\n");
    printIpProtocolDistribution(FLAG_HOSTLINK_HTML_FORMAT, revertOrder, TRUE);
  }
  if(!myGlobals.runningPref.printIpOnly) {
    sendString("<p>\n");
    printFcProtocolDistribution(FLAG_HOSTLINK_HTML_FORMAT, revertOrder, TRUE);
  }
}

/* ******************************* */

int combineReportTypeLocality(int reportTypeReq, LocalityDisplayPolicy showLocalityMode) {
  int rc = reportTypeReq;

  switch(reportTypeReq) {
  case SORT_DATA_HOST_TRAFFIC:
    switch(showLocalityMode) {
    case showOnlySent:
      rc = SORT_DATA_SENT_HOST_TRAFFIC;
      break;
    case showOnlyReceived:
      rc = SORT_DATA_RCVD_HOST_TRAFFIC;
    default:
      /* Nothign to do */
      break;
    }
    break;
  case SORT_DATA_PROTOS:
    switch(showLocalityMode) {
    case showOnlySent:
      rc = SORT_DATA_SENT_PROTOS;
      break;
    case showOnlyReceived:
      rc = SORT_DATA_RECEIVED_PROTOS;
    default:
      /* Nothign to do */
      break;
    }
    break;
  case SORT_DATA_IP:
    switch(showLocalityMode) {
    case showOnlySent:
      rc = SORT_DATA_SENT_IP;
      break;
    case showOnlyReceived:
      rc = SORT_DATA_RECEIVED_IP;
    default:
      /* Nothign to do */
      break;
    }
    break;
  case SORT_DATA_THPT:
    switch(showLocalityMode) {
    case showOnlySent:
      rc = SORT_DATA_SENT_THPT;
      break;
    case showOnlyReceived:
      rc = SORT_DATA_RECEIVED_THPT;
    default:
      /* Nothign to do */
      break;
    }
    break;

  default:
    /* Nothing to do */
    break;
  }

  return(rc);
}

/* ******************************* */

void printHostsTraffic(int reportTypeReq,
		       int sortedColumn,
		       int revertOrder,
		       int pageNum,
		       char* url,
		       HostsDisplayPolicy showHostsMode,
		       LocalityDisplayPolicy showLocalityMode,
		       int vlanId) {
  u_int idx, idx1, numEntries=0;
  int printedEntries=0, hourId, maxHosts;
  char theDate[8];
  struct tm t;
  HostTraffic *el;
  HostTraffic** tmpTable;
  char buf[LEN_GENERAL_WORK_BUFFER*2], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  float sentPercent=0, rcvdPercent=0, totPercent=0;
  Counter totIpBytesSent=0, totIpBytesRcvd=0, totIpBytes=0;
  Counter totEthBytesSent=0, totEthBytesRcvd=0, totEthBytes=0;
  ProtocolsList *protoList;
  char formatBuf[32], formatBuf1[32], formatBuf2[32], formatBuf3[32],
    formatBuf4[32], formatBuf5[32], formatBuf6[32], formatBuf7[32],
    formatBuf8[32], formatBuf9[32];
  int reportType;
  u_char *vlanList;

  vlanList = calloc(1, MAX_VLAN); if(vlanList == NULL) return;
  vlanId = abs(vlanId);

  /* traceEvent(CONST_TRACE_INFO, "---> VLAN: %d", vlanId); */

  reportType = combineReportTypeLocality(reportTypeReq, showLocalityMode);

  memset(buf, 0, sizeof(buf));
  switch(reportType) {
  case SORT_DATA_RCVD_HOST_TRAFFIC:
  case SORT_DATA_SENT_HOST_TRAFFIC:
  case SORT_DATA_HOST_TRAFFIC:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Network Activity: ");
    break;
  case SORT_DATA_RECEIVED_PROTOS:
  case SORT_DATA_SENT_PROTOS:
  case SORT_DATA_PROTOS:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Network Traffic [All Protocols]: ");
    break;
  case SORT_DATA_RECEIVED_IP:
  case SORT_DATA_SENT_IP:
  case SORT_DATA_IP:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Network Traffic [TCP/IP]: ");
    break;
  case SORT_DATA_RECEIVED_THPT:
  case SORT_DATA_SENT_THPT:
  case SORT_DATA_THPT:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Network Throughput: ");
    break;
  default:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "?: ");
    break;
  }

  switch(showHostsMode) {
  case showAllHosts:
    strncat(buf, "All Hosts", (sizeof(buf) - strlen(buf) - 1));
    break;
  case showOnlyLocalHosts:
    strncat(buf, "Local Hosts", (sizeof(buf) - strlen(buf) - 1));
    break;
  case showOnlyRemoteHosts:
    strncat(buf, "Remote Hosts", (sizeof(buf) - strlen(buf) - 1));
    break;
  }

  switch(showLocalityMode) {
  case showSentReceived:
    strncat(buf, " - Data Sent+Received", (sizeof(buf) - strlen(buf) - 1));
    break;
  case showOnlySent:
    strncat(buf, " - Data Sent", (sizeof(buf) - strlen(buf) - 1));
    break;
  case showOnlyReceived:
    strncat(buf, " - Data Received", (sizeof(buf) - strlen(buf) - 1));
    break;
  }

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el))
    if((el->vlanId > 0) && (el->vlanId < MAX_VLAN)) vlanList[el->vlanId] = 1;

  printHTMLheader(buf, NULL, 0);

  printHeader(reportTypeReq, revertOrder, abs(sortedColumn), showHostsMode,
	      showLocalityMode, (char*)vlanList, vlanId);

  strftime(theDate, 8, CONST_TOD_HOUR_TIMESPEC, localtime_r(&myGlobals.actTime, &t));
  hourId = atoi(theDate);

  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno;
  /* save ths as it can change */

  tmpTable = (HostTraffic**)mallocAndInitWithReportWarn(maxHosts*sizeof(HostTraffic*),
							"printHostsTraffic");
  if(tmpTable == NULL) {
    free(vlanList);
    return;
  }

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(!isFcHost (el) && (broadcastHost(el) == 0)) {
      u_char addHost;

      if((vlanId > 0) && (vlanId < MAX_VLAN) && (el->vlanId != vlanId)) continue;
      if(el->community && (!isAllowedCommunity(el->community))) continue;

      if(((showLocalityMode == showOnlySent) && (el->bytesSent.value > 0))
	 || ((showLocalityMode == showOnlyReceived) && (el->bytesRcvd.value > 0))
	 || ((showLocalityMode == showSentReceived) && (el->bytesSent.value + el->bytesRcvd.value > 0))) {
	if(((reportType == SORT_DATA_RECEIVED_IP)
	    || (reportType == SORT_DATA_SENT_IP)
	    || (reportType == SORT_DATA_IP))
	   && (el->hostNumIpAddress[0] == '\0')) {
	  continue;
	}

	if(el->ipProtosList == NULL) continue;

	addHost = 1;

	switch(myGlobals.hostsDisplayPolicy) {
	case showOnlyLocalHosts:
	  if(!subnetPseudoLocalHost(el)) addHost = 0;
	  break;
	case showOnlyRemoteHosts:
	  if(subnetPseudoLocalHost(el)) addHost = 0;
	  break;
	default:
	  /* Nothign to do */
	  break;
	}

	if(addHost) {
	  tmpTable[numEntries++] = el;
	  if(numEntries >= (maxHosts-1))
	    break;
	}
      }
    }
  } /* for */

  if(numEntries > 0) {
    /*
      The switch below is needed to:
      - sort data according to the selected column
      - 'recycle' (somebody would call this "code reuse") the cmpFctn function
    */

    if(sortedColumn == FLAG_HOST_DUMMY_IDX)
      myGlobals.columnSort = FLAG_HOST_DUMMY_IDX; /* Host name */
    else if(sortedColumn == FLAG_DOMAIN_DUMMY_IDX)
      myGlobals.columnSort = FLAG_DOMAIN_DUMMY_IDX; /* domain name */
    else
      myGlobals.columnSort = sortedColumn;

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, ">reportType=%d/sortedColumn=%d/myGlobals.columnSort=%d<",
	       reportType, sortedColumn, myGlobals.columnSort);
#endif

    myGlobals.reportKind = reportType;
    /* if(myGlobals.columnSort == 0) myGlobals.reportKind = 0;*/

    qsort(tmpTable, numEntries, sizeof(HostTraffic*), cmpFctn);

    switch(reportType) {
    case SORT_DATA_RECEIVED_PROTOS:
    case SORT_DATA_SENT_PROTOS:
      totEthBytesSent = totEthBytesRcvd = 0;

      for(idx=0; idx<numEntries; idx++) {
	if(tmpTable[idx] != NULL) {
	  totEthBytesSent += tmpTable[idx]->bytesSent.value;
	  totEthBytesRcvd += tmpTable[idx]->bytesRcvd.value;
	}
      }

      /* Avoid core dumps */
      if(totEthBytesSent == 0) totEthBytesSent = 1;
      if(totEthBytesRcvd == 0) totEthBytesRcvd = 1;
      break;
    case SORT_DATA_PROTOS:
      totEthBytes = 0;

      for(idx=0; idx<numEntries; idx++) {
	if(tmpTable[idx] != NULL) {
	  totEthBytes += tmpTable[idx]->bytesSent.value +
	    tmpTable[idx]->bytesRcvd.value;
	}
      }

      /* Avoid core dumps */
      if(totEthBytes == 0) totEthBytes = 1;
      break;
    case SORT_DATA_RECEIVED_IP:
    case SORT_DATA_SENT_IP:
      totIpBytesSent = totIpBytesRcvd = 0;

      for(idx=0; idx<numEntries; idx++) {
	if(tmpTable[idx] != NULL) {
	  totIpBytesSent += tmpTable[idx]->ipv4BytesSent.value;
	  totIpBytesRcvd += tmpTable[idx]->ipv4BytesRcvd.value;
	}
      }

      /* Avoid core dumps */
      if(totIpBytesSent == 0) totIpBytesSent = 1;
      if(totIpBytesRcvd == 0) totIpBytesRcvd = 1;
      break;
    case SORT_DATA_IP:
      totIpBytes = 0;

      for(idx=0; idx<numEntries; idx++) {
	if(tmpTable[idx] != NULL) {
	  totIpBytes += tmpTable[idx]->ipv4BytesSent.value +
	    tmpTable[idx]->ipv4BytesRcvd.value;
	}
      }

      /* Avoid core dumps */
      if(totIpBytes == 0) totIpBytes = 1;
      break;
    }

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "totIpBytesSent=%u, totIpBytesRcvd=%u totIpBytes=%u",
	       totIpBytesSent, totIpBytesRcvd, totIpBytes);
#endif

    for(idx=pageNum*myGlobals.runningPref.maxNumLines; idx<numEntries; idx++) {
      int i;
      char webHostName[LEN_GENERAL_WORK_BUFFER];

      if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	switch(reportType) {
	case SORT_DATA_RECEIVED_PROTOS:
	case SORT_DATA_SENT_PROTOS:
	  sentPercent = (100*(float)el->bytesSent.value)/totEthBytesSent;
	  rcvdPercent = (100*(float)el->bytesRcvd.value)/totEthBytesRcvd;
	  break;
	case SORT_DATA_PROTOS:
	  totPercent = (100*(float) (el->bytesSent.value + el->bytesRcvd.value) )/totEthBytes;
	  break;
	case SORT_DATA_RECEIVED_IP:
	case SORT_DATA_SENT_IP:
	  sentPercent = (100*(float)el->ipv4BytesSent.value)/totIpBytesSent;
	  rcvdPercent = (100*(float)el->ipv4BytesRcvd.value)/totIpBytesRcvd;
	  break;
	case SORT_DATA_IP:
	  totPercent = (100*(float) (el->ipv4BytesSent.value + el->ipv4BytesRcvd.value) )/totIpBytes;
	  break;
	case SORT_DATA_RECEIVED_THPT:
	case SORT_DATA_RCVD_HOST_TRAFFIC:
	case SORT_DATA_SENT_HOST_TRAFFIC:
	case SORT_DATA_SENT_THPT:
	case TRAFFIC_STATS:
	case SORT_DATA_HOST_TRAFFIC:
	case SORT_DATA_THPT:
	  sentPercent = rcvdPercent = 0;
	  break;
	}

	/*
	  Fixed buffer overflow.
	  Courtesy of Rainer Tammer <rainer.tammer@spg.schulergroup.com>
	*/
	strncpy(webHostName, makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 1,
					  hostLinkBuf, sizeof(hostLinkBuf)),
		sizeof(webHostName));

	switch(reportType) {
	case SORT_DATA_RECEIVED_PROTOS:
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>%s"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>""<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			getRowColor(), webHostName,
			formatBytes(el->bytesRcvd.value, 1, formatBuf, sizeof(formatBuf)),
			rcvdPercent, myGlobals.separator,
			formatBytes(el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value, 1, formatBuf1, sizeof(formatBuf1)),
			formatBytes(el->udpRcvdLoc.value+el->udpRcvdFromRem.value, 1, formatBuf2, sizeof(formatBuf2)),
			formatBytes(el->icmpRcvd.value, 1, formatBuf3, sizeof(formatBuf3)),
			formatBytes(el->icmp6Rcvd.value, 1, formatBuf4, sizeof(formatBuf4)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->dlcRcvd.value, 1, formatBuf5, sizeof(formatBuf5)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->ipxRcvd.value, 1, formatBuf6, sizeof(formatBuf6)),
			formatBytes(el->ipsecRcvd.value, 1, formatBuf7, sizeof(formatBuf7)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->arp_rarpRcvd.value, 1, formatBuf8, sizeof(formatBuf8)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->appletalkRcvd.value, 1, formatBuf9, sizeof(formatBuf9))
			);
	  sendString(buf);

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->netbiosRcvd.value, 1, formatBuf1, sizeof(formatBuf1)),
			formatBytes(el->greRcvd.value, 1, formatBuf2, sizeof(formatBuf2)),
			formatBytes(el->ipv6BytesRcvd.value, 1, formatBuf3, sizeof(formatBuf3)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->stpRcvd.value, 1, formatBuf4, sizeof(formatBuf4)));
	  sendString(buf);

	  protoList = myGlobals.ipProtosList, idx1=0;
	  while(protoList != NULL) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			  el->ipProtosList[idx1] != NULL ?
			  formatBytes(el->ipProtosList[idx1]->rcvd.value, 1, formatBuf, sizeof(formatBuf)) : "0");
	    sendString(buf);

	    idx1++, protoList = protoList->next;
	  }

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->otherRcvd.value, 1, formatBuf, sizeof(formatBuf)));
	  sendString(buf);
	  break;
	case SORT_DATA_SENT_PROTOS:
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>%s"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>""<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			getRowColor(), webHostName,
			formatBytes(el->bytesSent.value, 1, formatBuf, sizeof(formatBuf)), sentPercent, myGlobals.separator,
			formatBytes(el->tcpSentLoc.value+el->tcpSentRem.value, 1, formatBuf1, sizeof(formatBuf1)),
			formatBytes(el->udpSentLoc.value+el->udpSentRem.value, 1, formatBuf2, sizeof(formatBuf2)),
			formatBytes(el->icmpSent.value, 1, formatBuf3, sizeof(formatBuf3)),
			formatBytes(el->icmp6Sent.value, 1, formatBuf4, sizeof(formatBuf4)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->dlcSent.value, 1, formatBuf5, sizeof(formatBuf5)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->ipxSent.value, 1, formatBuf6, sizeof(formatBuf6)),
			formatBytes(el->ipsecSent.value, 1, formatBuf7, sizeof(formatBuf7)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->arp_rarpSent.value, 1, formatBuf8, sizeof(formatBuf8)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->appletalkSent.value, 1, formatBuf9, sizeof(formatBuf9))
			);

	  sendString(buf);

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->netbiosSent.value, 1, formatBuf, sizeof(formatBuf)),
			formatBytes(el->greSent.value, 1, formatBuf1, sizeof(formatBuf1)),
			formatBytes(el->ipv6BytesSent.value, 1, formatBuf2, sizeof(formatBuf2)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->stpSent.value, 1, formatBuf3, sizeof(formatBuf3)));
	  sendString(buf);

	  protoList = myGlobals.ipProtosList, idx1=0;
	  while(protoList != NULL) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			  el->ipProtosList[idx1] != NULL ?
			  formatBytes(el->ipProtosList[idx1]->sent.value, 1,
				      formatBuf, sizeof(formatBuf)) : "0");
	    sendString(buf);

	    idx1++, protoList = protoList->next;
	  }

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->otherSent.value, 1, formatBuf, sizeof(formatBuf))
			);
	  sendString(buf);
	  break;
	case SORT_DATA_PROTOS:
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>%s"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>""<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			getRowColor(), webHostName,
			formatBytes(el->bytesSent.value+el->bytesRcvd.value, 1, formatBuf, sizeof(formatBuf)),
			totPercent, myGlobals.separator,
			formatBytes(el->tcpSentLoc.value+el->tcpSentRem.value+
				    el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value, 1, formatBuf1, sizeof(formatBuf1)),
			formatBytes(el->udpSentLoc.value+el->udpSentRem.value+
				    el->udpRcvdLoc.value+el->udpRcvdFromRem.value, 1, formatBuf2, sizeof(formatBuf2)),
			formatBytes(el->icmpSent.value+el->icmpRcvd.value, 1, formatBuf3, sizeof(formatBuf3)),
			formatBytes(el->icmp6Sent.value+el->icmp6Rcvd.value, 1, formatBuf4, sizeof(formatBuf4)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->dlcSent.value+el->nonIPTraffic->dlcRcvd.value,
				    1, formatBuf5, sizeof(formatBuf5)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->ipxSent.value+el->nonIPTraffic->ipxRcvd.value,
				    1, formatBuf6, sizeof(formatBuf6)),
			formatBytes(el->ipsecSent.value+el->ipsecRcvd.value, 1, formatBuf7, sizeof(formatBuf7)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->arp_rarpSent.value+el->nonIPTraffic->arp_rarpRcvd.value,
				    1, formatBuf8, sizeof(formatBuf8)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->appletalkSent.value+el->nonIPTraffic->appletalkRcvd.value,
				    1, formatBuf9, sizeof(formatBuf9))
			);

	  sendString(buf);

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->netbiosSent.value+el->nonIPTraffic->netbiosRcvd.value,
				    1, formatBuf, sizeof(formatBuf)),
			formatBytes(el->greSent.value+el->greRcvd.value, 1, formatBuf1, sizeof(formatBuf1)),
			formatBytes(el->ipv6BytesSent.value+el->ipv6BytesRcvd.value, 1, formatBuf2, sizeof(formatBuf2)),
			formatBytes(el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->stpSent.value+el->nonIPTraffic->stpRcvd.value,
				    1, formatBuf3, sizeof(formatBuf3)));
	  sendString(buf);

	  protoList = myGlobals.ipProtosList, idx1=0;
	  while(protoList != NULL) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			  el->ipProtosList[idx1] != NULL ?
			  formatBytes(el->ipProtosList[idx1]->sent.value
				      +el->ipProtosList[idx1]->rcvd.value, 1,
				      formatBuf, sizeof(formatBuf)) : "0");
	    sendString(buf);

	    idx1++, protoList = protoList->next;
	  }

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(el->nonIPTraffic == NULL ? 0 :
				    el->nonIPTraffic->otherSent.value+el->nonIPTraffic->otherRcvd.value,
				    1, formatBuf, sizeof(formatBuf))
			);
	  sendString(buf);

	  break;
	case SORT_DATA_RECEIVED_IP:
	  {
	    Counter totalIPTraffic=0;

	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>%s"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>",
			  getRowColor(), webHostName,
			  formatBytes(el->ipv4BytesRcvd.value, 1, formatBuf, sizeof(formatBuf)),
			  rcvdPercent, myGlobals.separator);
	    sendString(buf);

	    if(el->protoIPTrafficInfos) {
	      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
		if(el->protoIPTrafficInfos[i])
		  totalIPTraffic += el->protoIPTrafficInfos[i]->rcvdLoc.value+
		    el->protoIPTrafficInfos[i]->rcvdFromRem.value;
		safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			      el->protoIPTrafficInfos[i] ?
			      formatBytes(el->protoIPTrafficInfos[i]->rcvdLoc.value+
					  el->protoIPTrafficInfos[i]->rcvdFromRem.value, 1,
					  formatBuf, sizeof(formatBuf)) : "0");
		sendString(buf);
	      }
	    }

	    /* Rounding may cause troubles */
	    if(el->ipv4BytesRcvd.value > totalIPTraffic)
	      totalIPTraffic = el->ipv4BytesRcvd.value - totalIPTraffic;
	    else
	      totalIPTraffic = 0;
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			  formatBytes(totalIPTraffic, 1, formatBuf, sizeof(formatBuf)));
	    sendString(buf);
	  }
	  break;
	case SORT_DATA_SENT_IP:
	  {
	    Counter totalIPTraffic=0;

	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>%s"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>",
			  getRowColor(), webHostName,
			  formatBytes(el->ipv4BytesSent.value, 1, formatBuf, sizeof(formatBuf)),
			  sentPercent, myGlobals.separator);
	    sendString(buf);

	    if(el->protoIPTrafficInfos) {
	      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
		if(el->protoIPTrafficInfos[i])
		  totalIPTraffic += el->protoIPTrafficInfos[i]->sentLoc.value+
		    el->protoIPTrafficInfos[i]->sentRem.value;
		
		safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			      el->protoIPTrafficInfos[i] ?
			      formatBytes(el->protoIPTrafficInfos[i]->sentLoc.value+
					  el->protoIPTrafficInfos[i]->sentRem.value, 1,
					  formatBuf, sizeof(formatBuf)) : "0");
		sendString(buf);
	      }
	    }

	    /* Rounding may cause troubles */
	    if(el->ipv4BytesSent.value > totalIPTraffic)
	      totalIPTraffic = el->ipv4BytesSent.value - totalIPTraffic;
	    else
	      totalIPTraffic = 0;
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			  formatBytes(totalIPTraffic, 1, formatBuf, sizeof(formatBuf)));
	    sendString(buf);
	  }
	  break;
	case SORT_DATA_IP:
	  {
	    Counter totalIPTraffic=0;

	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>%s"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>",
			  getRowColor(), webHostName,
			  formatBytes(el->ipv4BytesSent.value+el->ipv4BytesRcvd.value, 1, formatBuf, sizeof(formatBuf)),
			  totPercent, myGlobals.separator);
	    sendString(buf);

	    if(el->protoIPTrafficInfos) {
	      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
		if(el->protoIPTrafficInfos[i])
		  totalIPTraffic += el->protoIPTrafficInfos[i]->sentLoc.value+
		    el->protoIPTrafficInfos[i]->rcvdLoc.value+
		    el->protoIPTrafficInfos[i]->sentRem.value+
		    el->protoIPTrafficInfos[i]->rcvdFromRem.value;
		safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			      el->protoIPTrafficInfos[i] ?
			      formatBytes(el->protoIPTrafficInfos[i]->sentLoc.value+
					  el->protoIPTrafficInfos[i]->rcvdLoc.value+
					  el->protoIPTrafficInfos[i]->sentRem.value+
					  el->protoIPTrafficInfos[i]->rcvdFromRem.value, 1,
					  formatBuf, sizeof(formatBuf)) : "0");
		sendString(buf);
	      }
	    }

	    /* Rounding may cause troubles */
	    if(el->ipv4BytesSent.value+el->ipv4BytesRcvd.value > totalIPTraffic)
	      totalIPTraffic = el->ipv4BytesSent.value + el->ipv4BytesRcvd.value - totalIPTraffic;
	    else
	      totalIPTraffic = 0;
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			  formatBytes(totalIPTraffic, 1, formatBuf, sizeof(formatBuf)));
	    sendString(buf);
	  }
	  break;
	case SORT_DATA_RECEIVED_THPT:
	  {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>%s"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>",
			  getRowColor(), webHostName,
			  formatThroughput(el->actualRcvdThpt, 1, formatBuf, sizeof(formatBuf)),
			  formatThroughput(el->averageRcvdThpt, 1, formatBuf1, sizeof(formatBuf1)),
			  formatThroughput(el->peakRcvdThpt, 1, formatBuf2, sizeof(formatBuf2)),
			  el->actualRcvdPktThpt,
			  el->averageRcvdPktThpt,
			  el->peakRcvdPktThpt);
	    sendString(buf);
	  }
	  break;
	case SORT_DATA_SENT_THPT:
	  {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>%s"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>",
			  getRowColor(), webHostName,
			  formatThroughput(el->actualSentThpt, 1, formatBuf, sizeof(formatBuf)),
			  formatThroughput(el->averageSentThpt, 1, formatBuf1, sizeof(formatBuf1)),
			  formatThroughput(el->peakSentThpt, 1, formatBuf2, sizeof(formatBuf2)),
			  el->actualSentPktThpt,
			  el->averageSentPktThpt,
			  el->peakSentPktThpt);
	    sendString(buf);
	  }
	  break;
	case SORT_DATA_THPT:
	  {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>%s"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>",
			  getRowColor(), webHostName,
			  formatThroughput(el->actualTThpt, 1, formatBuf, sizeof(formatBuf)),
			  formatThroughput(el->averageTThpt, 1, formatBuf1, sizeof(formatBuf1)),
			  formatThroughput(el->peakTThpt, 1, formatBuf2, sizeof(formatBuf2)),
			  el->actualTPktThpt,
			  el->averageTPktThpt,
			  el->peakTPktThpt);
	    sendString(buf);
	  }
	  break;
	case SORT_DATA_RCVD_HOST_TRAFFIC:
	case SORT_DATA_SENT_HOST_TRAFFIC:
	case SORT_DATA_HOST_TRAFFIC:
	case TRAFFIC_STATS:
	  {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s>%s", getRowColor(), webHostName);
	    sendString(buf);
	    printHostThtpShort(el, reportType, hourId);
	  }
	  break;
	}

	sendString("</TR>\n");

	/* Avoid huge tables */
	if(printedEntries++ > myGlobals.runningPref.maxNumLines)
	  break;
      }
    }
  } else
    idx = 0;

  sendString("\n</TABLE>"TABLE_OFF"\n");

  switch(reportType) {
  case SORT_DATA_RCVD_HOST_TRAFFIC:
  case SORT_DATA_SENT_HOST_TRAFFIC:
  case SORT_DATA_HOST_TRAFFIC:
  case SORT_DATA_RECEIVED_THPT:
  case SORT_DATA_SENT_THPT:
  case SORT_DATA_THPT:
    break;
  case SORT_DATA_RECEIVED_PROTOS:
  case SORT_DATA_RECEIVED_IP:
  case SORT_DATA_SENT_PROTOS:
  case SORT_DATA_SENT_IP:
  case SORT_DATA_PROTOS:
  case SORT_DATA_IP:
    sendString("<P><I>Note: These counters do not include broadcasts and will not equal the 'Global Protocol Distribution'</I></P>\n");
    break;
  }

  sendString("</CENTER>\n");

  printFooter(reportType);

  addPageIndicator(url, pageNum, numEntries, myGlobals.runningPref.maxNumLines,
		   revertOrder, abs(sortedColumn), -1);

  sendString("<p><b>NOTE</b>:</p>\n<ul>"
	     "<li>Click <a href=\"" CONST_HOST_SORT_NOTE_HTML "\">here</a> "
	     "for more information about host and domain sorting.</li>\n"
	     "</ul><p>\n");

  myGlobals.lastRefreshTime = myGlobals.actTime;
  free(vlanList);
  free(tmpTable);
}

/* ******************************* */

void printMulticastStats(int sortedColumn /* ignored so far */,
			 int revertOrder,
			 int pageNum) {
  u_int idx, numEntries=0, maxHosts;
  int printedEntries=0, i;
  HostTraffic *el;
  HostTraffic** tmpTable;
  char buf[LEN_GENERAL_WORK_BUFFER], *sign, *theAnchor[6], *arrow[6], *arrowGif;
  char formatBuf[32], formatBuf1[32], formatBuf2[32], formatBuf3[32];
  char htmlAnchor[64], htmlAnchor1[64], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];

  printHTMLheader("Multicast Statistics", NULL, 0);

  memset(buf, 0, sizeof(buf));
  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */

  tmpTable = (HostTraffic**)mallocAndInitWithReportWarn(maxHosts*sizeof(HostTraffic*), "printMulticastStats");
  if(tmpTable == NULL)
    return;

  /* All the ALT tags courtesy of "Burton M. Strauss III" <BStrauss3@attbi.com> */
  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
  } else {
    sign = "-";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
  }

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(((el->pktMulticastSent.value > 0) || (el->pktMulticastRcvd.value > 0))
       && (!broadcastHost(el))) {
      if(el->community && (!isAllowedCommunity(el->community))) continue;
      tmpTable[numEntries++] = el;
    }

    if(numEntries >= maxHosts)
      break;
  }

  if(numEntries > 0) {
    myGlobals.columnSort = sortedColumn; /* Host name */

    safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", CONST_MULTICAST_STATS_HTML, sign);
    safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=", CONST_MULTICAST_STATS_HTML);

    for(i=0; i<=5; i++)
      if(abs(myGlobals.columnSort) == i)
	arrow[i] = arrowGif, theAnchor[i] = htmlAnchor;
      else
	arrow[i] = "", theAnchor[i] = htmlAnchor1;

    sendString("<CENTER>\n");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON" "DARK_BG"><TH "TH_BG">%s0>Host%s</A></TH>\n"
		  "<TH "TH_BG">%s1>Location%s</A></TH>"
		  "<TH "TH_BG">%s2>Pkts Sent%s</A></TH>"
		  "<TH "TH_BG">%s3>Data Sent%s</A></TH>"
		  "<TH "TH_BG">%s4>Pkts Rcvd%s</A></TH>"
		  "<TH "TH_BG">%s5>Data Rcvd%s</A></TH>"
		  "</TR>\n",
		  theAnchor[0], arrow[0],
		  theAnchor[1], arrow[1],
		  theAnchor[2], arrow[2],
		  theAnchor[3], arrow[3],
		  theAnchor[4], arrow[4],
		  theAnchor[5], arrow[5]
		  );
    sendString(buf);

    qsort(tmpTable, numEntries, sizeof(HostTraffic*), cmpMulticastFctn);

    for(idx=pageNum*myGlobals.runningPref.maxNumLines; idx<numEntries; idx++) {
      if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>%s"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "</TR>\n",
		      getRowColor(), makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 1, hostLinkBuf, sizeof(hostLinkBuf)),
		      formatPkts(el->pktMulticastSent.value, formatBuf, sizeof(formatBuf)),
		      formatBytes(el->bytesMulticastSent.value, 1, formatBuf1, sizeof(formatBuf1)),
		      formatPkts(el->pktMulticastRcvd.value, formatBuf2, sizeof(formatBuf2)),
		      formatBytes(el->bytesMulticastRcvd.value, 1, formatBuf3, sizeof(formatBuf3)));

	sendString(buf);

	/* Avoid huge tables */
	if(printedEntries++ > myGlobals.runningPref.maxNumLines)
	  break;
      }
    }

    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");

    addPageIndicator(CONST_MULTICAST_STATS_HTML, pageNum, numEntries, myGlobals.runningPref.maxNumLines,
		     revertOrder, abs(sortedColumn), -1);

    printFooterHostLink();

  } else
    printNoDataYet();

  free(tmpTable);

  sendString("<P ALIGN=right><A class=external HREF=http://www.iana.org/assignments/multicast-addresses>List</A> of multicast addresses</P>\n");
}

/* ****************************************************************** */

static void makeHostName(HostTraffic *el, char *buf, int len) {
  if(el->hostResolvedName[0] != '\0') strcpy(buf, el->hostResolvedName);
  else if(el->hostNumIpAddress[0] != '\0') strcpy(buf, el->hostNumIpAddress);
  else if(el->ethAddressString[0] != '\0') strcpy(buf, el->ethAddressString);
  else {
    HostTraffic *el1;
    
    for(el1=getFirstHost(myGlobals.actualReportDeviceId);
	el1 != NULL; el1 = getNextHost(myGlobals.actualReportDeviceId, el1)) {
      if(((strcmp(el1->hostNumIpAddress, el->hostNumIpAddress) == 0) 
	  || (strcmp(el1->ethAddressString, el->ethAddressString) == 0))
	 && (el1->vlanId == el->vlanId)) {
	safe_snprintf (__FILE__, __LINE__,  buf, len, "%s", el1->hostResolvedName);
	break;
      } 
    }
  }
}

/* ****************************************************************** */

#define LOCAL_COLOR     "mistyrose2"
#define REMOTE_COLOR    "lightsteelblue1"

static int addNodeInfo(FILE *fd, HostTraffic *el) {
  char buf0[128], buf1[2*LEN_GENERAL_WORK_BUFFER];

  makeHostName(el, buf0, sizeof(buf0));
  makeHostLink(el, FLAG_HOSTLINK_TEXT_LITE_FORMAT, 0, 0, buf1, sizeof(buf1));
  if(buf1[0] != '\0') {
    fprintf(fd, "\"%s\" [URL=\"%s\", color=%s];\n", buf0, buf1,
	    subnetLocalHost(el) ? LOCAL_COLOR : REMOTE_COLOR);
    return(1);
  }
  return(0);
}

/* ****************************************************************** */

void makeDot() {
#ifdef WIN32
  returnHTTPpageNotFound("<b>This feature is not available on your platform</b>");
  return;
#else
  HostTraffic *el, *el2, tmpEl;
  char buf[LEN_GENERAL_WORK_BUFFER], buf1[LEN_GENERAL_WORK_BUFFER],
    path[384], dotPath[256];
  FILE *fd, *cmap, *in, *out, *make;
  struct stat statbuf;
  int rc;

  printHTMLheader("Local Network Traffic Map", NULL, 0);

  /*
    First of all let's see if the path of dot is inside
    the preferences
  */
  if(fetchPrefsValue("dot.path", buf, sizeof(buf)) != -1) {
    snprintf(dotPath, sizeof(dotPath), "%s", buf);
  } else {
    snprintf(dotPath, sizeof(dotPath), "/usr/local/bin/dot");
    storePrefsValue("dot.path", dotPath); /* Set the default */
  }

  revertSlashIfWIN32(dotPath, 0);

  if(stat(dotPath, &statbuf) != 0) {
    snprintf(buf, sizeof(buf),
	     "<h1>ERROR</h1>\n<center><b>Missing <A HREF=http://www.graphviz.org/>dot</A> tool (expected %s). Please set its path (key dot.path) "
	     "<A HREF="CONST_EDIT_PREFS">here</A>.</b></center>",
	     dotPath);
    sendString(buf);
    return;
  }

  snprintf(path, sizeof(path), "%s/ntop-all.dot", myGlobals.spoolPath);
  fd = fopen(path, "w");

  if(fd != NULL) {
    for(el=getFirstHost(myGlobals.actualReportDeviceId);
	el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
      int numEntries, i, urlSent = 0;

      if(el->community && (!isAllowedCommunity(el->community))) continue;

      if(subnetLocalHost(el)) {
	makeHostName(el, buf, sizeof(buf));

	for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	  if(!emptySerial(&el->contactedSentPeers.peersSerials[i])
	     && (!cmpSerial(&el->contactedSentPeers.peersSerials[i], &myGlobals.otherHostEntry->hostSerial))) {
	    if((el2 = quickHostLink(el->contactedSentPeers.peersSerials[i], myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {

	      makeHostName(el2, buf1, sizeof(buf1));
	      if(addNodeInfo(fd, el2)) {
		fprintf(fd, "\"%s\" -> \"%s\";\n", buf, buf1);
		if(!urlSent) urlSent = addNodeInfo(fd, el);
	      }
	    }
	  }

	/* ****************************** */

	for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	  if(!emptySerial(&el->contactedRcvdPeers.peersSerials[i])
	     && (!cmpSerial(&el->contactedRcvdPeers.peersSerials[i], &myGlobals.otherHostEntry->hostSerial))) {
	    if((el2 = quickHostLink(el->contactedRcvdPeers.peersSerials[i], myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	      makeHostName(el2, buf1, sizeof(buf1));

	      for(i=0; i<strlen(buf1); i++) if(buf1[i] == '\"') buf1[i] = ' ';

	      if(addNodeInfo(fd, el2)) {
		fprintf(fd, "\"%s\" -> \"%s\";\n", buf1, buf);
		if(!urlSent) urlSent = addNodeInfo(fd, el);
	      }
	    }
	  }
      }
    }

    fclose(fd);

    snprintf(path, sizeof(path), "sort -u %s/ntop-all.dot > %s/ntop-sort.dot", myGlobals.spoolPath, myGlobals.spoolPath);
    sendString("<!-- sort command is ");
    sendString(path);
    sendString(" -->\n");
    errno = 0;
    rc = system(path);
    if((rc == -1) && (errno != ECHILD)) {
      snprintf(buf, sizeof(buf),
	       "<h1>ERROR</h1>\n<center><b>Sorting of ntop-all.dot failed, rc %d</b></center>",
	       errno);
      sendString(buf);
      return;
    }

    snprintf(path, sizeof(path), "%s/ntop.dot", myGlobals.spoolPath);
    out = fopen(path, "w");

    if(out != NULL) {
      fprintf(out, "digraph ntop {\n");
      fprintf(out, "node [shape = polygon, sides=4, fontsize=9, style=filled" 
	      /* ", fontname=\"Helvetica\" */ 
	      "];\n");

      snprintf(path, sizeof(path), "%s/ntop-sort.dot", myGlobals.spoolPath);
      if((in = fopen(path, "r")) != NULL) {
	while(!feof(in) && (fgets(buf, sizeof(buf), in) != NULL))
	  fprintf(out, "%s", buf);
      }

      fprintf(out, "}\n");
      fclose(out);
      fclose(in);
    }

    /* Added -c courtesy of Max Waterman <davidmaxwaterman@fastmail.co.uk> */
    snprintf(path, sizeof(path), "%s -Tpng -Goverlap=false %s/ntop.dot -o %s/"CONST_NETWORK_IMAGE_MAP " 2>&1 ",
	     dotPath, myGlobals.spoolPath, myGlobals.spoolPath);
    sendString("<!-- dot(generate) command is ");
    sendString(path);
    sendString(" -->\n");
    errno = 0;
    make = popen(path, "r");
    if(make == NULL) {
      snprintf(buf, sizeof(buf),
	       "<h1>ERROR</h1>\n<center><p>Creation of network map failed, rc %s(%d)</p></center>\n"
	       "<p>Command was:</p>\n<pre>%s</pre>",
	       strerror(errno), errno, path);
      sendString(buf);
      return;
    }
    if(!feof(make) && (fgets(buf, sizeof(buf), make) != NULL)) {
      sendString("<h1>ERROR</h1>\n<center><p>Creation of network map failed</p></center>\n"
		 "<p>Command was:</p>\n<pre>");
      sendString(path);
      sendString("</pre>\n<p>Results were:</p>\n<pre>");
      sendString(buf);
      while(!feof(make) && (fgets(buf, sizeof(buf), make) != NULL)) {
	sendString(buf);
      }
      sendString("</pre>\n");
      return;
    }
    pclose(make);

    snprintf(path, sizeof(path), "%s -Tcmap -Goverlap=false %s/ntop.dot", dotPath, myGlobals.spoolPath);
    sendString("<!-- dot(cmap) command is ");
    sendString(path);
    sendString(" -->\n");
    cmap = popen(path, "r");

    if(cmap != NULL) {
      sendString("<p><center><img src=\"/"CONST_NETWORK_IMAGE_MAP"\" usemap=\"#G\" ismap=\"ismap\" border=\"0\">");
      sendString("</center><map id=\"G\" name=\"G\">\n");

      while(!feof(cmap) && (fgets(buf, sizeof(buf), cmap) != NULL))
	sendString(buf);

      sendString("</map>\n");

      sendString("<p><small>Graph generated by Dot, part of <A class=external HREF=http://www.graphviz.org>Graphviz</A>, created by "
		 "<A HREF=http://www.research.att.com/>AT&T Research</A>.</small>\n");

      pclose(cmap);
    } else {
      returnHTTPpageNotFound("Unable to generate cmap file (Is dot installed?)");
    }
  } else {
    returnHTTPpageNotFound("Unable to create temporary file");
  }
#endif
}

/* ******************************* */

#define NUM_TABLE_COLUMNS 13

void printHostsInfo(int sortedColumn, int revertOrder, int pageNum, int showBytes,
		    int vlanId, int ifId, int knownSubnetId) {
  u_int idx, numEntries=0, maxHosts;
  int printedEntries=0;
  unsigned short maxBandwidthUsage=1 /* avoid divisions by zero */;
  HostTraffic *el;
  HostTraffic** tmpTable;
  char buf[2*LEN_GENERAL_WORK_BUFFER], *arrowGif, *sign, *arrow[NUM_TABLE_COLUMNS],
    *theAnchor[NUM_TABLE_COLUMNS], osBuf[160];
  char htmlAnchor[64], htmlAnchor1[64];
  char formatBuf[32], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  u_char *vlanList, foundVlan = 0, vlanStr[16], ifStr[16], foundIf = 0, *ifList;
  u_int8_t *knownSubnets, foundSubnet = 0;

  vlanList = calloc(1, MAX_VLAN);
  if(vlanList == NULL) {
    traceEvent (CONST_TRACE_WARNING, "Unable to allocate memory for vlan list");
    return;
  }
  vlanId = abs(vlanId);

  ifList = calloc(1, MAX_INTERFACE);
  if(ifList == NULL) {
    traceEvent (CONST_TRACE_WARNING, "Unable to allocate memory for if list");
    free(vlanList);
    return;
  }
  ifId = abs(ifId);

  knownSubnets = calloc(sizeof(u_int8_t), myGlobals.numKnownSubnets);
  if(ifList == NULL) {
    traceEvent (CONST_TRACE_WARNING, "Unable to allocate memory for if list");
    free(vlanList); free(ifList);
    return;
  }

  ifId = abs(ifId);

  printHTMLheader("Host Information", NULL, 0);

  memset(buf, 0, sizeof(buf));
  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */

  tmpTable = (HostTraffic**)mallocAndInitWithReportWarn(maxHosts*sizeof(HostTraffic*), "printHostsInfo");
  if(tmpTable == NULL) {
    free(vlanList); free(ifList); free(knownSubnets);
    return;
  }

  if(revertOrder)
    sign = "", arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
  else
    sign = "-", arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;

  myGlobals.columnSort = sortedColumn;

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    unsigned short actUsage, actUsageS, actUsageR;

    if(isFcHost (el) || broadcastHost(el)) continue;
    if(el->community && (!isAllowedCommunity(el->community))) continue;

    if((el->vlanId != NO_VLAN) && (el->vlanId < MAX_VLAN))       { vlanList[el->vlanId] = 1, foundVlan = 1; }
    if((vlanId != NO_VLAN) && (el->vlanId != vlanId)) continue;

    if((el->known_subnet_id < myGlobals.numKnownSubnets) && (el->known_subnet_id != UNKNOWN_SUBNET_ID) )
      foundSubnet = 1, knownSubnets[el->known_subnet_id] = 1;

    if((knownSubnetId != UNKNOWN_SUBNET_ID) && (knownSubnetId != ALL_SUBNET_IDS)
       && (el->known_subnet_id != knownSubnetId))
      continue;

    if((knownSubnetId == UNKNOWN_SUBNET_ID) && (el->known_subnet_id != UNKNOWN_SUBNET_ID)) continue;

    if((el->ifId != NO_INTERFACE) && (el->ifId < MAX_INTERFACE)) { ifList[el->ifId] = 1, foundIf = 1; }
    if((ifId != NO_INTERFACE) && (el->ifId != ifId)) continue;

    if(showBytes) {
      actUsage  = (unsigned short)(0.5+100.0*(((float)el->bytesSent.value+(float)el->bytesRcvd.value)/
					      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
      actUsageS = (unsigned short)(0.5+100.0*((float)el->bytesSent.value/
					      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
      actUsageR = (unsigned short)(0.5+100.0*((float)el->bytesRcvd.value/
					      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
    } else {
      actUsage  = (unsigned short)(0.5+100.0*(((float)el->pktSent.value+(float)el->pktRcvd.value)/
					      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value));
      actUsageS = (unsigned short)(0.5+100.0*((float)el->pktSent.value/
					      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value));
      actUsageR = (unsigned short)(0.5+100.0*((float)el->pktRcvd.value/
					      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value));
    }

    el->actBandwidthUsage = actUsage;
    if(el->actBandwidthUsage > maxBandwidthUsage)
      maxBandwidthUsage = actUsage;
    el->actBandwidthUsageS = actUsageS;
    el->actBandwidthUsageR = actUsageR;

    tmpTable[numEntries++] = el;
    getHostAS(el);

    if(numEntries >= maxHosts)
      break;
  }

  /* if(numEntries > 0) */ {
    int i;

    qsort(tmpTable, numEntries, sizeof(HostTraffic*), sortHostFctn);

    safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor),
		  "<A HREF=\"/%s?col=%s", CONST_HOSTS_INFO_HTML, sign);
    safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1),
		  "<A HREF=\"/%s?col=", CONST_HOSTS_INFO_HTML);

    for(i=1; i<NUM_TABLE_COLUMNS; i++) {
      if(abs(myGlobals.columnSort) == i)
	arrow[i] = arrowGif, theAnchor[i] = htmlAnchor;
      else
	arrow[i] = "", theAnchor[i] = htmlAnchor1;
    }

    if(abs(myGlobals.columnSort) == FLAG_DOMAIN_DUMMY_IDX)
      arrow[0] = arrowGif, theAnchor[0] = htmlAnchor;
    else
      arrow[0] = "", theAnchor[0] = htmlAnchor1;

    sendString("<P ALIGN=LEFT>");

    if(vlanId > 0)
      safe_snprintf(__FILE__, __LINE__, (char*)vlanStr, sizeof(vlanStr), "&vlan=%d", vlanId);
    else
      vlanStr[0] = '\0';

    if(ifId > 0)
      safe_snprintf(__FILE__, __LINE__, (char*)ifStr, sizeof(ifStr), "&if=%d", ifId);
    else
      ifStr[0] = '\0';

    sendString("<p><table border=0>");

    if(numEntries > 0) {
      sendString("<tr><td><form action=\"../\">\n<b>Traffic Unit</b>:</td>"
		 "<td><select onchange=\"window.open(this.options[this.selectedIndex].value,'_top')\">\n");

      if(showBytes)
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<option value=\"/%s?col=%d&unit=1%s%s\" selected>Bytes</option>\n"
		      "<option value=\"/%s?col=%d&unit=0%s%s\">Packets</option>\n</select>\n",
		      CONST_HOSTS_INFO_HTML, myGlobals.columnSort, vlanStr, ifStr,
		      CONST_HOSTS_INFO_HTML, myGlobals.columnSort, vlanStr, ifStr);
      else
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<option value=\"/%s?col=%d&unit=1%s%s\">Bytes</option>\n"
		      "<option value=\"/%s?col=%d&unit=0%s%s\" selected>Packets</option>\n</select>\n",
		      CONST_HOSTS_INFO_HTML, myGlobals.columnSort, vlanStr, ifStr,
		      CONST_HOSTS_INFO_HTML, myGlobals.columnSort, vlanStr, ifStr);

      sendString(buf);
      sendString("</td></tr>\n");
    }

    if(foundVlan) {
      u_char tmpBuf[64];
      u_int8_t selected;

      sendString("<tr><td><form action=\"../\">\n<b>VLAN</b>:</td>"
		 "<td><select onchange=\"window.open(this.options[this.selectedIndex].value,'_top')\">\n");

      for(i=0; i<MAX_VLAN; i++)
	if(vlanList[i] == 1) {
	  if(i == vlanId)
	    selected = 1;
	  else
	    selected = 0;

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<option value=\"/%s?unit=%d&vlan=%d\"%s>%s</option>\n",
			CONST_HOSTS_INFO_HTML, showBytes, i,
			selected ? " selected" : "",
			vlan2name(i, (char*)tmpBuf, sizeof(tmpBuf)));

	  sendString(buf);
	}

      if(vlanId == NO_VLAN)
	selected = 1;
      else
	selected = 0;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<option value=\"/%s?unit=%d\"%s>All</option>\n",
		    CONST_HOSTS_INFO_HTML, showBytes,
		    selected ? " selected" : "");

      sendString(buf);
      sendString("</select>\n</form></td></tr>\n");
    }

    /* if(foundSubnet) */ {
      u_int8_t selected;

      sendString("<tr><td><form action=\"../\">\n<b>Subnet</b>:</td>"
		 "<td><select onchange=\"window.open(this.options[this.selectedIndex].value,'_top')\">\n");

      for(i=0; i<myGlobals.numKnownSubnets; i++)
	if(knownSubnets[i] == 1) {
	  struct in_addr addr;
	  char addr_buf[32], alias[64], key[64], *net;

	  addr.s_addr = myGlobals.subnetStats[i].address[CONST_NETWORK_ENTRY];

	  if((knownSubnetId != UNKNOWN_SUBNET_ID) && (i == knownSubnetId))
	    selected = 1;
	  else
	    selected = 0;

	  net = _intoa(addr, addr_buf, sizeof(addr_buf));

	  safe_snprintf(__FILE__, __LINE__, key, sizeof(key), "subnet.name.%s/%d",
			net, myGlobals.subnetStats[i].address[CONST_NETMASK_V6_ENTRY]);

	  alias[0] = '\0';
	  fetchPrefsValue(key, alias, sizeof(alias));

	  if(alias[0] != '\0') {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			  "<option value=\"/%s?unit=%d&subnet=%d\"%s>%s/%d %s%s%s</option>\n",
			  CONST_HOSTS_INFO_HTML, showBytes, i,
			  selected ? " selected" : "", net,
			  myGlobals.subnetStats[i].address[CONST_NETMASK_V6_ENTRY],
			  (alias[0] != '\0') ? "[" : "",
			  alias,
			  (alias[0] != '\0') ? "]" : "");
	    
	    sendString(buf);
	  }
	}

      if(knownSubnetId == UNKNOWN_SUBNET_ID) selected = 1; else selected = 0;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<option value=\"/%s?unit=%d&subnet=%d\"%s>Unknown Subnets</option>\n",
		    CONST_HOSTS_INFO_HTML, showBytes, UNKNOWN_SUBNET_ID,
		    selected ? " selected" : "");

      sendString(buf);

      if(knownSubnetId == ALL_SUBNET_IDS) selected = 1; else selected = 0;
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<option value=\"/%s?unit=%d&subnet=%d\"%s>All</option>\n"
		    "</select></form>\n</td></tr>\n",
		    CONST_HOSTS_INFO_HTML, showBytes, ALL_SUBNET_IDS,
		    selected ? " selected" : "");

      sendString(buf);
    }

    if(foundIf) {
      u_char found = 0;
      u_int8_t selected;

      sendString("<tr><td><p><form action=\"../\">\n<b>Interface Id</b>:</td><td>"
		 "<select onchange=\"window.open(this.options[this.selectedIndex].value,'_top')\">\n");

      for(i=0; i<MAX_INTERFACE; i++)
	if(ifList[i] == 1) {
	  if(i == ifId)
	    selected = 1, found = 1;
	  else
	    selected = 0;

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"/%s?unit=%d&if=%d\"%s>%d</option>\n",
			CONST_HOSTS_INFO_HTML, showBytes, i,
			selected ? " selected" : "", i);

	  sendString(buf);
	}

      if(!found)
	selected = 1;
      else
	selected = 0;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"/%s?unit=%d\"%s>All</option>\n"
		    "</select>\n</form></td></tr>\n",
		    CONST_HOSTS_INFO_HTML, showBytes, selected ? " selected" : "", i);

      sendString(buf);
    }

    sendString("</table>\n");

    if(numEntries > 0) {
      if(!myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<CENTER>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON" "DARK_BG">"
		      "<TH "TH_BG">%s1\">Host%s</A></TH>\n"
		      "<TH "TH_BG">%s"FLAG_DOMAIN_DUMMY_IDX_STR"\">Location%s</A></TH>\n"
		      "<TH "TH_BG">%s2\">IP&nbsp;Address%s</A></TH>\n"
		      "<TH "TH_BG">%s3\">MAC&nbsp;Address%s</A></TH>\n"
		      "<TH "TH_BG">%s11\">Community%s</A></TH>\n"
		      "<TH "TH_BG">%s6\">Other&nbsp;Name(s)%s</A></TH>\n"
		      "<TH "TH_BG" colspan=2>%s4\">Inbound vs Outbound%s</A></TH>\n"
		      "<TH "TH_BG">%s5\">Nw&nbsp;Board&nbsp;Vendor%s</A></TH>\n"
		      "<TH "TH_BG">%s7\">Hops&nbsp;Distance%s</A></TH>\n"
		      "<TH "TH_BG">%s8\">Host&nbsp;Contacts%s</A></TH>\n"
		      "<TH "TH_BG" COLSPAN=2>%s9\">Age/Inactivity%s</A></TH>\n"
		      "<TH "TH_BG">%s10\">AS%s</A></TH>\n"
		      "<TH "TH_BG">%s12\">Fingerprint%s</A></TH>\n"
		      "</TR>\n",
		      theAnchor[1], arrow[1],
		      theAnchor[0], arrow[0],
		      theAnchor[2], arrow[2],
		      theAnchor[3], arrow[3],
		      theAnchor[11], arrow[11],
		      theAnchor[6], arrow[6],
		      theAnchor[4], arrow[4],
		      theAnchor[5], arrow[5],
		      theAnchor[7], arrow[7],
		      theAnchor[8], arrow[8],
		      theAnchor[9], arrow[9],
		      theAnchor[10], arrow[10],
		      theAnchor[12], arrow[12]
		      );
      } else {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		      "<CENTER>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON" "DARK_BG">"
		      "<TH "TH_BG">%s1\">Host%s</A></TH>\n"
		      "<TH "TH_BG">%s"FLAG_DOMAIN_DUMMY_IDX_STR"\">Location%s</A></TH>\n"
		      "</TH><TH "TH_BG">%s2\">IP&nbsp;Address%s</A></TH>\n"
		      "<TH "TH_BG">%s11\">Community%s</A></TH>"
		      "<TH "TH_BG">%s6\">Other&nbsp;Name(s)%s</A></TH>\n"
		      "<TH "TH_BG" colspan=2>%s4\">Inbound vs Outbound%s</A></TH>\n"
		      "<TH "TH_BG">%s7\">Hops&nbsp;Distance%s</A></TH>\n"
		      "<TH "TH_BG">%s8\">Host&nbsp;Contacts%s</A></TH>\n"
		      "<TH "TH_BG" COLSPAN=2>%s9\">Age/Inactivity%s</A></TH>\n"
		      "<TH "TH_BG">%s10\">AS%s</A></TH>\n"
		      "<TH "TH_BG">%s11\">Fingerprint%s</A></TH>\n"
		      "</TR>\n",
		      theAnchor[1], arrow[1],
		      theAnchor[0], arrow[0],
		      theAnchor[2], arrow[2],
		      theAnchor[6], arrow[6],
		      theAnchor[11], arrow[11],
		      theAnchor[4], arrow[4],
		      theAnchor[7], arrow[7],
		      theAnchor[8], arrow[8],
		      theAnchor[9], arrow[9],
		      theAnchor[10], arrow[10],
		      theAnchor[12], arrow[12]
		      );
      }
      sendString(buf);

      for(idx=pageNum*myGlobals.runningPref.maxNumLines; idx<numEntries; idx++) {
	if(revertOrder)
	  el = tmpTable[numEntries-idx-1];
	else
	  el = tmpTable[idx];

	if(el != NULL) {
	  char *tmpName1, *tmpName2, *tmpName3;

	  tmpName1 = el->hostNumIpAddress;

	  if((tmpName1[0] == '\0') || (strcmp(tmpName1, "0.0.0.0") == 0))
	    tmpName1 = myGlobals.separator;

	  if(!myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
	    tmpName2 = getVendorInfo(el->ethAddress, 1);
	    if(tmpName2[0] == '\0')
	      tmpName2 = myGlobals.separator;

	    tmpName3 = el->ethAddressString;
	    if((tmpName3[0] == '\0')
	       || (strcmp(tmpName3, "00:00:00:00:00:00") == 0))
	      tmpName3 = myGlobals.separator;
	  } else {
	    tmpName2 = myGlobals.separator;
	    tmpName3 = myGlobals.separator;
	  }

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>", getRowColor());
	  sendString(buf);

	  sendString(makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 1, hostLinkBuf, sizeof(hostLinkBuf)));

	  if(!myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			  tmpName1, tmpName3);
	  } else {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			  tmpName1);
	  }
	  sendString(buf);

	  if(el->community == NULL)
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			  "<TD "TD_BG" ALIGN=RIGHT NOWRAP>&nbsp;</TD>");
	  else
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			  "<TD "TD_BG" ALIGN=RIGHT NOWRAP><A HREF=/"
			  CONST_COMMUNITIES_STATS_HTML"?community=%s>%s</A></TD>",
			  el->community, el->community);
	  sendString(buf);

	  sendString("<TD "TD_BG" ALIGN=RIGHT NOWRAP>");

	  if(el->nonIPTraffic) {
	    short numAddresses = 0;

	    if(el->nonIPTraffic->nbHostName && el->nonIPTraffic->nbDomainName) {
	      if((el->nonIPTraffic->nbAccountName != NULL) && ((el->nonIPTraffic->nbAccountName[0] != '0'))) {
		if((el->nonIPTraffic->nbDomainName != NULL) && (el->nonIPTraffic->nbDomainName[0] != '0')) {
		  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s&nbsp;%s@%s&nbsp;[%s]", getOSFlag(el, "Windows", 0, osBuf, sizeof(osBuf)),
				el->nonIPTraffic->nbAccountName, el->nonIPTraffic->nbHostName,
				el->nonIPTraffic->nbDomainName);
		} else {
		  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s&nbsp;%s@%s", getOSFlag(el, "Windows", 0, osBuf, sizeof(osBuf)),
				el->nonIPTraffic->nbAccountName, el->nonIPTraffic->nbHostName);
		}
	      } else {
		if((el->nonIPTraffic->nbDomainName != NULL) && (el->nonIPTraffic->nbDomainName[0] != '0')) {
		  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s&nbsp;%s&nbsp;[%s]", getOSFlag(el, "Windows", 0, osBuf, sizeof(osBuf)),
				el->nonIPTraffic->nbHostName, el->nonIPTraffic->nbDomainName);
		} else {
		  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s&nbsp;%s", getOSFlag(el, "Windows", 0, osBuf, sizeof(osBuf)),
				el->nonIPTraffic->nbHostName);
		}
	      }
	      sendString(buf);
	      numAddresses++;
	    } else if(el->nonIPTraffic->nbHostName) {
	      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s&nbsp;%s", getOSFlag(el, "Windows", 0, osBuf, sizeof(osBuf)),
			    el->nonIPTraffic->nbHostName);
	      sendString(buf);
	      numAddresses++;
	    }

	    if(el->nonIPTraffic->nbDescr) {
	      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), ":&nbsp;%s", el->nonIPTraffic->nbDescr);
	      sendString(buf);
	    }

	    if(el->nonIPTraffic->atNetwork) {
	      char *nodeName = el->nonIPTraffic->atNodeName;

	      if(numAddresses > 0) sendString("/");
	      if(nodeName == NULL) nodeName = "";

	      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s&nbsp;%s&nbsp;",
			    getOSFlag(el, "Mac", 0, osBuf, sizeof(osBuf)), nodeName);
	      sendString(buf);

	      if(el->nonIPTraffic->atNodeType[0] != NULL) {
		sendString("(");
		for(i=0; i<MAX_NODE_TYPES; i++)
		  if(el->nonIPTraffic->atNodeType[i] == NULL)
		    break;
		  else {
		    if(i > 0) sendString("/");
		    sendString(el->nonIPTraffic->atNodeType[i]);
		  }

		sendString(")&nbsp;");
	      }

	      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[%d.%d]",
			    el->nonIPTraffic->atNetwork, el->nonIPTraffic->atNode);
	      sendString(buf);
	      numAddresses++;
	    }

	    if(el->nonIPTraffic->ipxHostName) {
	      int numSap=0;

	      if(numAddresses > 0) sendString("/");
	      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s&nbsp;%s&nbsp;",
			    getOSFlag(el, "Novell", 0, osBuf, sizeof(osBuf)),
			    el->nonIPTraffic->ipxHostName);
	      sendString(buf);

	      for(i=0; i<el->nonIPTraffic->numIpxNodeTypes; i++) {
		char *str = getSAPInfo(el->nonIPTraffic->ipxNodeType[i], 1);

		if(str[0] != '\0') {
		  if(numSap == 0)
		    sendString("[");
		  else
		    sendString("/");

		  sendString(str);
		  numSap++;
		}
	      }

	      if(numSap > 0) sendString("]");

	      numAddresses++;
	    }
	  }

	  sendString("&nbsp;</TD>");
	  printBar(buf, sizeof(buf), el->actBandwidthUsageS, el->actBandwidthUsageR, maxBandwidthUsage, 1);

	  if(!myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%s</TD>", tmpName2);
	    sendString(buf);
	  }

	  {
	    char shortBuf[8];

	    if(!subnetPseudoLocalHost(el)) {
	      i = guessHops(el);
	    } else
	      i = 0;

	    safe_snprintf(__FILE__, __LINE__, shortBuf, sizeof(shortBuf), "%d", i % 256);

	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>&nbsp;%s</TD>",
			  (i == 0) ? "" : shortBuf);
	    sendString(buf);
	  }

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%lu</TD>",
			(unsigned long)(el->totContactedSentPeers+el->totContactedRcvdPeers));
	  sendString(buf);

#if 0
	  /* Time distance */
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s-",
			formatLatency(el->minLatency, FLAG_STATE_ACTIVE));
	  sendString(buf);

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s</TD>",
			formatLatency(el->maxLatency, FLAG_STATE_ACTIVE));
	  sendString(buf);
#endif

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td "TD_BG" align=\"right\" nowrap>%s</td>",
			formatSeconds(el->lastSeen - el->firstSeen, formatBuf, sizeof(formatBuf)));
	  sendString(buf);

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td "TD_BG" align=\"right\" nowrap>%s</td>",
			formatSeconds(myGlobals.actTime-el->lastSeen, formatBuf, sizeof(formatBuf)));
	  sendString(buf);

	  if(el->hostAS == 0) {
	    sendString("<TD "TD_BG" ALIGN=RIGHT NOWRAP>&nbsp;</TD>");
	  } else {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			  "<TD "TD_BG" ALIGN=RIGHT NOWRAP>"
			  "<a href=\"" DEFAULT_AS_LOOKUP_URL "%d\" title=\"Lookup ASN (offsite)\">%d</a>"
			  "</TD>",
			  el->hostAS, el->hostAS);
	    sendString(buf);
	  }

	  {
	    u_int flags = 0;

	    sendString("<TD "TD_BG" ALIGN=RIGHT NOWRAP>");

	    for(i=0; i<MAX_FLAG_HOST_TYPE; i++) {
	      if(FD_ISSET(i, &(el->flags)))
		sendString("<IMG SRC=/bit_on.png BORDER=0>\n");
	      else
		sendString("<IMG SRC=/bit_off.png BORDER=0>\n");
	    }
	    
	    sendString("</TD>");
	  }

	  sendString("</TR>\n");

	  printedEntries++;

	  /* Avoid huge tables */
	  if(printedEntries > myGlobals.runningPref.maxNumLines)
	    break;
	} else {
	  traceEvent(CONST_TRACE_WARNING, "qsort() problem!");
	}
      }

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");

      printFooterHostLink();

      printBandwidthFooter();

      addPageIndicator(CONST_HOSTS_INFO_HTML, pageNum, numEntries, myGlobals.runningPref.maxNumLines,
		       revertOrder, abs(sortedColumn), -1);
    }
  }

  free(tmpTable);
  free(vlanList);
  free(ifList);
  free(knownSubnets);
}

/* ************************************ */

static void printHostNwDelay(HostTraffic *el, int actualDeviceId, 
			     NetworkDelay *delay, u_int clientDelay) {
  int i;
  char buf[2*LEN_GENERAL_WORK_BUFFER];

  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON" "DARK_BG">"
	     "<TH "TH_BG">Last Time</TH><TH "TH_BG">Service</TH>"
	     "<TH "TH_BG">Last ");
  if(!clientDelay) sendString("Client"); else sendString(" Server");
  sendString(" Contact</TH><TH "TH_BG">");
  if(clientDelay) sendString("Client"); else sendString("Server");
  sendString(" Delay [min/avg/max]</TH></TR>\n");

  for(i=0; i<myGlobals.ipPortMapper.numSlots; i++) {
    time_t when;
    HostTraffic *peerHost, tmpEl;
    char webHostName[LEN_GENERAL_WORK_BUFFER], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];

    if(delay[i].num_samples == 0) continue;

    if(emptySerial(&delay[i].last_peer))
      strncpy(webHostName, "&nbsp;", sizeof(webHostName));
    else {
      peerHost = quickHostLink(delay[i].last_peer, actualDeviceId, &tmpEl);
      strncpy(webHostName, makeHostLink(peerHost, FLAG_HOSTLINK_TEXT_FORMAT, 0,
					0, hostLinkBuf, sizeof(hostLinkBuf)),
	      sizeof(webHostName));
    }

    when = delay[i].last_update.tv_sec;
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<TR "TR_ON" %s><TD "TD_BG">%s</TD>"
		  "<TD "TD_BG" ALIGN=CENTER>%s</TD><TD "TD_BG">%s</TD>"
		  "<TD "TH_BG" ALIGN=RIGHT>%.02f/%.02f/%.02f ms</TD></TR>\n",
		  getRowColor(), ctime(&when),
		  myGlobals.ipTrafficProtosNames[i] ? myGlobals.ipTrafficProtosNames[i] : "???",
		  webHostName, 
		  ((float)delay[i].min_nw_delay)/1000, 
		  delay[i].total_delay/(delay[i].num_samples*1000),
		  ((float)delay[i].max_nw_delay)/1000);
    sendString(buf);
  }

  sendString("</TABLE>"TABLE_OFF"\n");
}

/* ************************************ */

static void printHostFingerprint(HostTraffic *el) {
  int idx;
  char fingerprint[4096] = { '\0' };

  return;

  for(idx=1; idx<MAX_ASSIGNED_IP_PORTS /* 1024 */; idx++) {
    PortUsage *ports = getPortsUsage(el, idx, 0);
    int value;
    
    value = 0;

    if(ports != NULL) {
      if((ports->clientUses > 0)  && (ports->serverUses > 0))
	value = 3;
      else if(ports->serverUses > 0)
	value = 2;
      else if(ports->clientUses > 0)
	value = 1;
    }

    if(value > 0)
      snprintf(&fingerprint[strlen(fingerprint)], 
	       sizeof(fingerprint)-strlen(fingerprint), 
	       "%d", value);    
  }
  
  traceEvent (CONST_TRACE_WARNING, "[%s][%s][len=%d]",
	      el->hostNumIpAddress, fingerprint,
	      (int)sizeof(el->flags));
}

/* ************************************ */

void printAllSessionsHTML(char* host, int actualDeviceId, int sortedColumn,
			  int revertOrder, int pageNum, char *url,
			  int hostInfoPage) {
  u_int idx, i, cols = 0;
  u_int16_t vlanId = NO_VLAN;
  HostTraffic *el=NULL;
  char buf[LEN_GENERAL_WORK_BUFFER];
  char formatBuf[32], portBuf[32], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  u_short found = 0,
    foundFcHost = 0,
    vsanId = 0;
  char *tok;

  if((tok = strchr(host, '-')) != NULL) {
    vlanId = vsanId = atoi(&tok[1]);
    *tok = '\0';
  }

  /* ****************************** */

#if 0
  i=0;

  for(el=getFirstHost(actualDeviceId);
      el != NULL; el = getNextHost(actualDeviceId, el))
    traceEvent (CONST_TRACE_WARNING, "[%3d] %s", i++, el->hostNumIpAddress);
#endif
 
  /* ****************************** */

  for(el=getFirstHost(actualDeviceId);
      el != NULL; el = getNextHost(actualDeviceId, el)) {
    if(el->community && (!isAllowedCommunity(el->community))) continue;

    if(((strcmp(el->hostNumIpAddress, host) == 0) || (strcmp(el->ethAddressString, host) == 0))
       && ((vlanId == NO_VLAN) || ((el->vlanId <= 0) || (el->vlanId == vlanId)))) {
      found = 1;
      break;
    } else if((el->fcCounters != NULL)
	      && ((strncmp(fc_to_str ((u_int8_t *)&el->fcCounters->hostFcAddress),
			   host, LEN_FC_ADDRESS_DISPLAY) == 0) &&
		  ((el->fcCounters->vsanId == vsanId) || (vsanId == 0)))) {
      found = 1;
      foundFcHost = 1;
      break;
    }
  }

  /* Dennis Schoen (dennis@cns.dnsalias.org)
   *
   * send 404 if we cannot generate the requested page
   */
  if((el == NULL) || (!found)) {
    char errorAdditionalText[1024], whois[256];

    safe_snprintf(__FILE__, __LINE__, whois, sizeof(whois),
		  "[ <A class=external HREF=\"http://ws.arin.net/cgi-bin/whois.pl?queryinput=%s\">Whois</A> ]</TD></TR>\n",
		  host);

    safe_snprintf(__FILE__, __LINE__, errorAdditionalText, sizeof(errorAdditionalText),
		  "<p align=\"center\"><img class=tooltip alt=\"Warning\" src=\"/warning.gif\"></p>\n"
		  "<p align=\"center\"><font color=\"#FF0000\" size=\"+1\">"
		  "<b>ntop</b> does not currently have any information about host %s %s.</font></p>"
		  "<p>&nbsp;</p>"
		  "<p>This is most likely because the host information has been "
		  "purged as inactive.  You may wish to consider the -c | --sticky-hosts "
		  "option, although that option may substantially increase memory "
		  "requirements.</p>\n",
		  host, whois);
    returnHTTPpageNotFound(errorAdditionalText);
    return;
  }

  if(el->community && (!isAllowedCommunity(el->community))) {
    returnHTTPpageBadCommunity();
    return;
  }

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);

  /* ************************************ */

  if(found && !foundFcHost) {
    printHostDetailedInfo(el, actualDeviceId);
    printHostTrafficStats(el, actualDeviceId);
    printHostIcmpStats(el);
    printHostFragmentStats(el, actualDeviceId);
    printHostContactedPeers(el, actualDeviceId);
    printHostHTTPVirtualHosts(el, actualDeviceId);
    printHostUsedServices(el, actualDeviceId);
    printHostFingerprint(el); /* ----- **** ----- */
  } else if(foundFcHost) {
    printHTMLheader("", NULL, 0);
    printFcHostHeader(el, url, revertOrder, sortedColumn, hostInfoPage);

    switch (hostInfoPage) {
    case showHostMainPage:
      printFcHostDetailedInfo (el, actualDeviceId);
      printFcHostTrafficStats (el, actualDeviceId);
      printFcHostContactedPeers(el, actualDeviceId);
      break;
    case showHostLunStats:
      if(el->fcCounters->devType != SCSI_DEV_INITIATOR) {
	printScsiLunStats (el, actualDeviceId, sortedColumn,
			   revertOrder, pageNum, url);
      }
      break;
    case showHostLunGraphs:
      if(el->fcCounters->devType != SCSI_DEV_INITIATOR) {
	printScsiLunGraphs (el, actualDeviceId);
      }
      break;
    case showHostScsiSessionBytes:
      printScsiSessionBytes (actualDeviceId, sortedColumn, revertOrder,
			     pageNum, url, el);
      break;
    case showHostScsiSessionTimes:
      printScsiSessionTimes (actualDeviceId, sortedColumn, revertOrder,
			     pageNum, url, el);
      break;
    case showHostScsiSessionStatus:
      printScsiSessionStatusInfo (actualDeviceId, sortedColumn,
				  revertOrder, pageNum, url, el);
      break;
    case showHostScsiSessionTMInfo:
      printScsiSessionTmInfo (actualDeviceId, sortedColumn,
			      revertOrder, pageNum, url, el);
      break;
    case showHostFcSessions:
      printFCSessions (actualDeviceId, sortedColumn,
		       revertOrder, pageNum, url, el);
      break;
    }


    return;
  }

  /* ***************************************************** */

  i = 0;

  if(el->portsUsage != NULL) {
    for(idx=1; idx<MAX_ASSIGNED_IP_PORTS /* 1024 */; idx++) {
      PortUsage *ports = getPortsUsage(el, idx, 0);
      if(ports != NULL) {
	char *svc = getAllPortByNum(idx, portBuf, sizeof(portBuf));
	char webHostName[LEN_GENERAL_WORK_BUFFER];
	HostTraffic *peerHost;

	if(i == 0) {
	  printSectionTitle("TCP/UDP&nbsp;Service/Port&nbsp;Usage\n");
	  sendString("<CENTER>\n");
	  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON" "DARK_BG">"
		     "<TH "TH_BG">IP&nbsp;Service</TH>"
		     "<TH "TH_BG">Port</TH>"
		     "<TH "TH_BG">#&nbsp;Client&nbsp;Sess.</TH>"
		     "<TH "TH_BG">Last&nbsp;Client&nbsp;Peer</TH>"
		     "<TH "TH_BG">#&nbsp;Server&nbsp;Sess.</TH>"
		     "<TH "TH_BG">Last&nbsp;Server&nbsp;Peer</TH>"
		     "</TR>\n");
	  i++;
	}

	if(svc != NULL) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
			"<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
			"<TD "TD_BG" ALIGN=CENTER>%d</TD>", getRowColor(), svc, idx);
	} else {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%d</TH>"
			"<TD "TD_BG" ALIGN=CENTER>%d</TD>", getRowColor(), idx, idx);
	}

	sendString(buf);

	if(ports->clientUses > 0) {
	  /* Fix below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
	  HostTraffic tmpEl;

	  if(emptySerial(&ports->clientUsesLastPeer))
	    peerHost = NULL;
	  else
	    peerHost = quickHostLink(ports->clientUsesLastPeer, actualDeviceId, &tmpEl);

	  if(peerHost == NULL) {
	    /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
	    strncpy(webHostName, "&nbsp;", sizeof(webHostName));
	  } else
	    strncpy(webHostName, makeHostLink(peerHost, FLAG_HOSTLINK_TEXT_FORMAT, 0,
					      0, hostLinkBuf, sizeof(hostLinkBuf)),
		    sizeof(webHostName));

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d/%s</TD>"
			"<TD "TD_BG" ALIGN=CENTER>%s</TD>",
			ports->clientUses,
			formatBytes(ports->clientTraffic.value, 1, formatBuf, sizeof(formatBuf)),
			webHostName);
	  sendString(buf);
	} else
	  sendString("<TD "TD_BG">&nbsp;</TD><TD "TD_BG">&nbsp;</TD>");

	if(ports->serverUses > 0) {
	  HostTraffic tmpEl;

	  if(emptySerial(&ports->serverUsesLastPeer))
	    peerHost = NULL;
	  else
	    peerHost = quickHostLink(ports->serverUsesLastPeer, actualDeviceId, &tmpEl);

	  if(peerHost == NULL) {
	    /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
	    strncpy(webHostName, "&nbsp;", sizeof(webHostName));
	  } else
	    strncpy(webHostName, makeHostLink(peerHost, FLAG_HOSTLINK_TEXT_FORMAT, 0,
					      0, hostLinkBuf, sizeof(hostLinkBuf)), sizeof(webHostName));

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d/%s</TD>"
			"<TD "TD_BG" ALIGN=CENTER>%s</TD></TR>",
			ports->serverUses,
			formatBytes(ports->serverTraffic.value, 1, formatBuf, sizeof(formatBuf)),
			webHostName);
	  sendString(buf);
	} else
	  sendString("<TD "TD_BG">&nbsp;</TD><TD "TD_BG">&nbsp;</TD></TR>");
      }
    }
  }

  if(i > 0){
    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");
  }

  /* *********************************
********************************* */

  if((el->otherIpPortsRcvd[MAX_NUM_RECENT_PORTS-1] >= 0) || (el->otherIpPortsSent[MAX_NUM_RECENT_PORTS-1] >= 0)) {
    /* We have something to show */
    int numPrinted;

    printSectionTitle("TCP/UDP - Traffic on Other Ports\n");
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON" "DARK_BG">"
	       "<TH "TH_BG">Client Port</TH><TH "TH_BG">Server Port</TH>"
	       "</TR>\n");

    sendString("<TR "TR_ON"><TD "TD_BG" ALIGN=LEFT><UL>");

    for(idx=0, numPrinted=0; idx<MAX_NUM_RECENT_PORTS; idx++) {
      if(el->otherIpPortsSent[idx] >= 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<LI><A HREF=\"" CONST_SHOW_PORT_TRAFFIC_HTML "?port=%d\">%s</A>\n",
		      el->otherIpPortsSent[idx],
		      getAllPortByNum(el->otherIpPortsSent[idx], portBuf, sizeof(portBuf)));
	sendString(buf);
	numPrinted++;
      }
    }

    if(numPrinted == 0) sendString("&nbsp;");
    sendString("</UL></TD><TD "TD_BG" ALIGN=LEFT><UL>");

    for(idx=0, numPrinted=0; idx<MAX_NUM_RECENT_PORTS; idx++) {
      if(el->otherIpPortsRcvd[idx] >= 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<li><A HREF=\"" CONST_SHOW_PORT_TRAFFIC_HTML "?port=%d\">%s</A>\n",
		      el->otherIpPortsRcvd[idx],
		      getAllPortByNum(el->otherIpPortsRcvd[idx], portBuf, sizeof(portBuf)));
	sendString(buf);
	numPrinted++;
      }
    }

    if(numPrinted == 0) sendString("&nbsp;");
    sendString("</UL></TR></TABLE>"TABLE_OFF"</CENTER>");
  }

  /* ****************************************************************** */

  if((el->recentlyUsedClientPorts[MAX_NUM_RECENT_PORTS-1] >= 0)
     || (el->recentlyUsedServerPorts[MAX_NUM_RECENT_PORTS-1] >= 0)) {
    /* We have something to show */
    int numPrinted;

    printSectionTitle("TCP/UDP Recently Used Ports\n");
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON" "DARK_BG">"
	       "<TH "TH_BG">Client Port</TH><TH "TH_BG">Server Port</TH>"
	       "</TR>\n");

    sendString("<TR "TR_ON"><TD "TD_BG" ALIGN=LEFT><UL>");

    for(idx=0, numPrinted=0; idx<MAX_NUM_RECENT_PORTS; idx++) {
      if(el->recentlyUsedClientPorts[idx] >= 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<li><A HREF=\"" CONST_SHOW_PORT_TRAFFIC_HTML "?port=%d\">%s</A>\n",
		      el->recentlyUsedClientPorts[idx],
		      getAllPortByNum(el->recentlyUsedClientPorts[idx], portBuf, sizeof(portBuf)));
	sendString(buf);
	numPrinted++;
      }
    }

    if(numPrinted == 0) sendString("&nbsp;");

    sendString("</UL></TD><TD "TD_BG" ALIGN=LEFT><UL>");

    for(idx=0, numPrinted=0; idx<MAX_NUM_RECENT_PORTS; idx++) {
      if(el->recentlyUsedServerPorts[idx] >= 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<LI><A HREF=\"" CONST_SHOW_PORT_TRAFFIC_HTML "?port=%d\">%s</A>\n",
		      el->recentlyUsedServerPorts[idx],
		      getAllPortByNum(el->recentlyUsedServerPorts[idx], portBuf, sizeof(portBuf)));
	sendString(buf);
	numPrinted++;
      }
    }

    if(numPrinted == 0) sendString("&nbsp;");
    sendString("</UL></TR></TABLE>"TABLE_OFF"</CENTER>");
  }

  /* *************************************************** */

  if((el->protocolInfo != NULL)
     && (el->protocolInfo->fileList != NULL)) {
    FileList *list = el->protocolInfo->fileList;

    printSectionTitle("P2P Recently Exchanged Files\n");

    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON">"
	       "<TH "TH_BG" NOWRAP>File Name</TH></TR>\n");
    sendString("<TR><TD align=left NOWRAP><ol>\n");

    while(list != NULL) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<li>%s&nbsp;",
		    list->fileName);
      sendString(buf);

      if(FD_ISSET(BITFLAG_P2P_UPLOAD_MODE, &list->fileFlags))
	sendString("<IMG SRC=/upload.gif ALT=Upload VALIGN=MIDDLE>&nbsp;");
      if(FD_ISSET(BITFLAG_P2P_DOWNLOAD_MODE, &list->fileFlags))
	sendString("<IMG SRC=/download.gif ALT=Download VALIGN=MIDDLE>&nbsp;");

      list = list->next;
    }

    sendString("\n</ol></TD></TR></TABLE></CENTER>\n");
  }

  /* *************************************************** */
  
  if(el->clientDelay || el ->serverDelay) {
    printSectionTitle("Recent Sessions: Network Delay");
    
    sendString("<P>\n<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON">");
    if(el->clientDelay)  sendString("<TH "TH_BG" NOWRAP colspan=2>Client Mode</TH>");
    if(el ->serverDelay) sendString("<TH "TH_BG" NOWRAP colspan=2>Server Mode</TH></TR>\n");
    sendString("<TR>");

    if(el->clientDelay) {
      sendString("<TD ALIGN=CENTER VALIGN=TOP colspan=100%>");
      printHostNwDelay(el, actualDeviceId, el->clientDelay, 1), cols++;
      sendString("</TD>");
    }

    if(el->serverDelay) {
      sendString("<TD ALIGN=CENTER VALIGN=TOP colspan=100%>");
      printHostNwDelay(el, actualDeviceId, el->serverDelay, 0), cols++;
      sendString("</TD>");
    }
    
    sendString("</TR>\n<p>\n<tr><td");
    if(cols > 1) sendString(" colspan=2");
    sendString(" align=left><ul><li>Scenario: client &lt;--&gt; ntop &lt;--&gt; server"
	       "<li>Client Delay: the network delay (computed as RTT/2) taken"
	       "<br>by a packet sent by the client to reach ntop"
	       "<li>Server Delay: the network delay (computed as RTT/2) taken"
	       "<br>by a packet sent by the server to reach ntop"
	       "<li>All times are majored during TCP 3-way handshake"
	       "</td></tr>\n");
    sendString("</TABLE></CENTER>\n<P>\n");
  }

  /* *************************************************** */

  printHostSessions(el, actualDeviceId);
}

/* ************************************ */

void printLocalRoutersList(int actualDeviceId) {
  char buf[LEN_GENERAL_WORK_BUFFER], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  HostTraffic *el, *router;
  u_int i, j, numEntries=0;
  HostSerial routerList[MAX_NUM_ROUTERS];

  printHTMLheader("Local Subnet Routers", NULL, 0);

  if(myGlobals.runningPref.dontTrustMACaddr) {
    printNotAvailable("-o or --no-mac");
    return;
  }

  for(el=getFirstHost(actualDeviceId);
      el != NULL; el = getNextHost(actualDeviceId, el)) {

    if(el->community && (!isAllowedCommunity(el->community))) continue;

    if(subnetLocalHost(el)) {
      for(j=0; j<MAX_NUM_CONTACTED_PEERS; j++)
	if(!emptySerial(&el->contactedRouters.peersSerials[j])) {
	  short found = 0;

	  for(i=0; i<numEntries; i++) {
	    if(cmpSerial(&el->contactedRouters.peersSerials[j], &routerList[i])) {
	      found = 1;
	      break;
	    }
	  }

	  if((found == 0) && (numEntries < MAX_NUM_ROUTERS)) {
	    routerList[numEntries++] = el->contactedRouters.peersSerials[j];
	  }
	}
    }
  } /* for */

  if(numEntries == 0) {
    printNoDataYet();
    return;
  } else {
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON" "DARK_BG"><TH "TH_BG">Router Name</TH>"
	       "<TH "TH_BG">Used by</TH></TR>\n");

    for(i=0; i<numEntries; i++) {
      HostTraffic tmpEl;

      if((router = quickHostLink(routerList[i], myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TR "TR_ON" %s><TH "TH_BG" align=left>%s</TH><TD "TD_BG" ALIGN=LEFT><UL>\n",
		      getRowColor(),
		      makeHostLink(router, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				   hostLinkBuf, sizeof(hostLinkBuf)));
	sendString(buf);


	for(el=getFirstHost(actualDeviceId); el != NULL; el = getNextHost(actualDeviceId, el)) {
	  if(el->community && (!isAllowedCommunity(el->community))) continue;
	  if(subnetLocalHost(el)) {
	    for(j=0; j<MAX_NUM_CONTACTED_PEERS; j++)
	      if(cmpSerial(&el->contactedRouters.peersSerials[j], &routerList[i])) {
		safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<LI>%s</LI>\n",
			      makeHostLink(el, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
					   hostLinkBuf, sizeof(hostLinkBuf)));
		sendString(buf);
		break;
	      }
	  }
	}

	sendString("</OL></TD></TR>\n");
      }
    }

    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");

    printHostColorCode(FALSE, 0);

    printFooterHostLink();
  }
}

/* ************************************ */

void printIpAccounting(int remoteToLocal, int sortedColumn,
		       int revertOrder, int pageNum) {
  u_int idx, numEntries=0, maxHosts;
  int printedEntries=0;
  HostTraffic *el, **tmpTable;
  char buf[LEN_GENERAL_WORK_BUFFER], *str=NULL, *sign, *title=NULL;
  Counter totalBytesSent, totalBytesRcvd, totalBytes, a=0, b=0;
  float sentpct, rcvdpct;
  time_t timeDiff = time(NULL)-myGlobals.initialSniffTime;
  char *arrowGif, *arrow[48], *theAnchor[48], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  char htmlAnchor[64], htmlAnchor1[64];
  char formatBuf[32], formatBuf1[32], formatBuf2[32], formatBuf3[32];

  switch(remoteToLocal) {
  case FLAG_REMOTE_TO_LOCAL_ACCOUNTING:
    str = CONST_IP_R_2_L_HTML;
    title = "Remote to Local IP Traffic";
    break;
  case FLAG_REMOTE_TO_REMOTE_ACCOUNTING:
    str = CONST_IP_R_2_R_HTML;
    title = "Remote to Remote IP Traffic";
    break;
  case FLAG_LOCAL_TO_REMOTE_ACCOUNTING:
    str = CONST_IP_L_2_R_HTML;
    title = "Local to Remote IP Traffic";
    break;
  case FLAG_LOCAL_TO_LOCAL_ACCOUNTING:
    str = CONST_IP_L_2_L_HTML;
    title = "Local IP Traffic";
    break;
  }

  printHTMLheader(title, NULL, 0);

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
  } else {
    sign = "-";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
  }

  totalBytesSent=0, totalBytesRcvd=0;
  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */

  tmpTable = (HostTraffic**)mallocAndInitWithReportWarn(maxHosts*sizeof(HostTraffic*), "printIpAccounting");
  if(tmpTable == NULL)
    return;

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if((broadcastHost(el) == 0) /* No broadcast addresses please */
       && (multicastHost(el) == 0) /* No multicast addresses please */
       && ((el->hostNumIpAddress[0] != '\0')
	   && (!addrnull(&el->hostIpAddress))
	   /* This host speaks IP */)) {

      if(el->community && (!isAllowedCommunity(el->community))) continue;

      switch(remoteToLocal) {
      case FLAG_REMOTE_TO_LOCAL_ACCOUNTING:
	if(!subnetPseudoLocalHost(el)) {
	  if((el->bytesSentLoc.value > 0) || (el->bytesRcvdLoc.value > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentLoc.value;
	    totalBytesRcvd += el->bytesRcvdLoc.value;
	  }
	}
	break;
      case FLAG_REMOTE_TO_REMOTE_ACCOUNTING:
	if(!subnetPseudoLocalHost(el)) {
	  if((el->bytesSentRem.value > 0) || (el->bytesRcvdFromRem.value > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentRem.value;
	    totalBytesRcvd += el->bytesRcvdFromRem.value;
	  }
	}
	break;
      case FLAG_LOCAL_TO_REMOTE_ACCOUNTING:
	if(subnetPseudoLocalHost(el)) {
	  if((el->bytesSentRem.value > 0) || (el->bytesRcvdFromRem.value > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentRem.value;
	    totalBytesRcvd += el->bytesRcvdFromRem.value;
	  }
	}
	break;
      case FLAG_LOCAL_TO_LOCAL_ACCOUNTING:
	if(subnetPseudoLocalHost(el)) {
	  if((el->bytesSentLoc.value > 0) || (el->bytesRcvdLoc.value > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentLoc.value;
	    totalBytesRcvd += el->bytesRcvdLoc.value;
	  }
	}
	break;
      }

      if(numEntries >= maxHosts) break;
    }
  }

  if(numEntries > 0) {
    int i;

    myGlobals.columnSort = sortedColumn;
    myGlobals.sortFilter = remoteToLocal;
    qsort(tmpTable, numEntries, sizeof(HostTraffic*), cmpHostsFctn);

    safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", str, sign);
    safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=", str);

    for(i=1; i<=4; i++)
      if(abs(myGlobals.columnSort) == i)
	arrow[i] = arrowGif, theAnchor[i] = htmlAnchor;
      else
	arrow[i] = "", theAnchor[i] = htmlAnchor1;

    sendString("<CENTER>\n");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"80%%\">\n"
		  "<TR "TR_ON" "DARK_BG"><TH "TH_BG">"
		  "%s1>Host%s</A></TH>"
		  "<TH "TH_BG">%s2>IP&nbsp;Address%s</A></TH>\n"
		  "<TH "TH_BG" COLSPAN=2>%s3>Data&nbsp;Sent%s</A></TH>"
		  "<TH "TH_BG" COLSPAN=2>%s4>Data&nbsp;Rcvd%s</A></TH></TR>\n",
		  theAnchor[1], arrow[1],
		  theAnchor[2], arrow[2], theAnchor[3], arrow[3],
		  theAnchor[4], arrow[4]);

    sendString(buf);

    for(idx=pageNum*myGlobals.runningPref.maxNumLines; idx<numEntries; idx++) {
      if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	char *tmpName1;
	tmpName1 = el->hostNumIpAddress;
	if((tmpName1[0] == '\0') || (strcmp(tmpName1, "0.0.0.0") == 0))
	  tmpName1 = myGlobals.separator;

	switch(remoteToLocal) {
	case FLAG_REMOTE_TO_LOCAL_ACCOUNTING:
	  a = el->bytesSentLoc.value;
	  b = el->bytesRcvdLoc.value;
	  break;
	case FLAG_REMOTE_TO_REMOTE_ACCOUNTING:
	  a = el->bytesSentRem.value;
	  b = el->bytesRcvdFromRem.value;
	  break;
	case FLAG_LOCAL_TO_REMOTE_ACCOUNTING:
	  a = el->bytesSentRem.value;
	  b = el->bytesRcvdFromRem.value;
	  break;
	case FLAG_LOCAL_TO_LOCAL_ACCOUNTING:
	  a = el->bytesSentLoc.value;
	  b = el->bytesRcvdLoc.value;
	  break;
	}

	if(a < 100)  /* Avoid very small decimal values */
	  sentpct = 0;
	else
	  sentpct = (100*(float)a)/totalBytesSent;

	if(b < 100)  /* Avoid very small decimal values */
	  rcvdpct = 0;
	else
	  rcvdpct = (100*(float)b)/totalBytesRcvd;

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		      "%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD></TR>\n",
		      getRowColor(),
		      makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
		      tmpName1,
		      formatBytes(a, 1, formatBuf, sizeof(formatBuf)),
		      sentpct, myGlobals.separator,
		      formatBytes(b, 1, formatBuf1, sizeof(formatBuf1)),
		      rcvdpct, myGlobals.separator);
	sendString(buf);

	/* Avoid huge tables */
	if(printedEntries++ > myGlobals.runningPref.maxNumLines)
	  break;
      }
    }

    sendString("</TABLE>"TABLE_OFF"\n");

    addPageIndicator(str, pageNum, numEntries, myGlobals.runningPref.maxNumLines,
		     revertOrder, abs(sortedColumn), -1);

    sendString("<P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"80%\">\n<TR "TR_ON" "DARK_BG">"
	       "<TH "TH_BG">Total Traffic</TH><TH "TH_BG">Data Sent</TH>\n"
	       "<TH "TH_BG">Data Rcvd</TH><TH "TH_BG">Used Bandwidth</TH></TR>\n");

    totalBytes = totalBytesSent+totalBytesRcvd;

    /* In this case the total traffic is just half and
       the following statement holds:
       totalBytesSent == totalBytesRcvd

       Courtesy of Jac Engel <jacengel@home.nl>
    */
    if(remoteToLocal == FLAG_LOCAL_TO_LOCAL_ACCOUNTING)
      totalBytes /= 2;

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatBytes(totalBytes, 1, formatBuf, sizeof(formatBuf)),
		  formatBytes(totalBytesSent, 1, formatBuf1, sizeof(formatBuf1)),
		  formatBytes(totalBytesRcvd, 1, formatBuf2, sizeof(formatBuf2)),
		  formatThroughput((float)(totalBytes/timeDiff), 1, formatBuf3, sizeof(formatBuf3)));

    sendString(buf);
    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");

    printFooterHostLink();
  } else
    printNoDataYet();

  free(tmpTable);
}

/* ********************************** */

static char* print_flags(IPSession *session, char *buf, int buf_len) {
  snprintf(buf, buf_len,"%s%s%s%s%s&nbsp;",
	   (session->lastFlags & TH_SYN) ? " SYN" : "",
	   (session->lastFlags & TH_ACK) ? " ACK" : "",
	   (session->lastFlags & TH_FIN) ? " FIN" : "",
	   (session->lastFlags & TH_RST) ? " RST" : "",
	   (session->lastFlags & TH_PUSH) ? " PUSH" : "");

  return(buf);
}

/* ********************************** */

void printActiveTCPSessions(int actualDeviceId, int pageNum, HostTraffic *el) {
  int idx;
  char buf[1500], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER], flags_buf[64],
    hostLinkBuf1[2*LEN_GENERAL_WORK_BUFFER], *voipStr;
  int numSessions, printedSessions;
  char formatBuf[64], formatBuf1[64], formatBuf2[64], formatBuf3[64],
    formatBuf4[64], formatBuf5[64], formatBuf6[64], formatBuf7[64];

  if(!myGlobals.runningPref.enableSessionHandling) {
    if(el != NULL) return;
    printHTMLheader("Active TCP/UDP Sessions", NULL, 0);
    printNotAvailable("-z or --disable-sessions");
    return;
  }

  if((myGlobals.device[actualDeviceId].tcpSession == NULL) ||
     (myGlobals.device[actualDeviceId].numTcpSessions == 0)) {
    if(el != NULL) return;
    printHTMLheader("Active TCP/UDP Sessions", NULL, 0);
    printNoDataYet();
    return;
  }

  /*
    Due to the way sessions are handled, sessions before those to
    display need to be skipped
  */
  for(idx=1, numSessions=0, printedSessions=0; idx<MAX_TOT_NUM_SESSIONS; idx++) {
    int mutex_idx;

    if(el && (printedSessions >= el->numHostSessions)) break;

    mutex_idx = idx % NUM_SESSION_MUTEXES;

    accessMutex(&myGlobals.tcpSessionsMutex[mutex_idx], "printActiveTCPSessions");

    if(myGlobals.device[myGlobals.actualReportDeviceId].tcpSession[idx] != NULL) {
      char *sport, *dport;
      Counter dataSent, dataRcvd;
      IPSession *session = myGlobals.device[myGlobals.actualReportDeviceId].tcpSession[idx];

      while((session != NULL) && (printedSessions < myGlobals.runningPref.maxNumLines)) {
#ifndef PARM_PRINT_ALL_SESSIONS
	if(session->sessionState != FLAG_STATE_ACTIVE) {
	  session = session->next;
	  continue;
	}
#endif

	if(el && (session->initiator  != el) && (session->remotePeer != el)) {
	  session = session->next;
	  continue;
	}

	if((numSessions++) < pageNum*myGlobals.runningPref.maxNumLines) {
	  session = session->next;
	  continue;
	}

	if(printedSessions == 0) {
	  if(el == NULL)
	    printHTMLheader("Active TCP/UDP Sessions", NULL, 0);
	  else
	    printSectionTitle("Active TCP/UDP Sessions");

	  sendString("<CENTER>\n"
		     ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON" "DARK_BG">"
		     "<TH "TH_BG">Client</TH>"
		     "<TH "TH_BG">Server</TH>"
		     "<TH "TH_BG">Data&nbsp;Sent</TH>"
		     "<TH "TH_BG">Data&nbsp;Rcvd</TH>"
		     "<TH "TH_BG">Active&nbsp;Since</TH>"
		     "<TH "TH_BG">Last&nbsp;Seen</TH>"
		     "<TH "TH_BG">Duration</TH>"
		     "<TH "TH_BG">Inactive</TH>"
		     "<TH "TH_BG" COLSPAN=2>Client/Server Network Delay</TH>"
		     "<TH "TH_BG">L7 Proto</TH>"
		     "<TH "TH_BG">Note</TH>");
#ifdef PARM_PRINT_ALL_SESSIONS
	  sendString("<TH "TH_BG">State</TH>");
#endif
	  sendString("</TR>\n");
	}

	sport = getPortByNum(session->sport, IPPROTO_TCP);
	dport = getPortByNum(session->dport, IPPROTO_TCP);
	dataSent = session->bytesSent.value;
	dataRcvd = session->bytesRcvd.value;

	if(sport == NULL) {
	  static char _sport[8];
	  safe_snprintf(__FILE__, __LINE__, _sport, 8, "%d", session->sport);
	  sport = _sport;
	}

	if(dport == NULL) {
	  static char _dport[8];
	  safe_snprintf(__FILE__, __LINE__, _dport, 8, "%d", session->dport);
	  dport = _dport;
	}

	/* Sanity check */
	if((myGlobals.actTime < session->firstSeen)
	   || (session->firstSeen == 0))
	  session->firstSeen = myGlobals.actTime;
	if((myGlobals.actTime < session->lastSeen)
	   || (session->lastSeen == 0))
	  session->lastSeen = myGlobals.actTime;

	if((session->guessed_protocol != NULL)
	   && session->voipSession
	   && strstr(session->guessed_protocol, "skype"))
	  voipStr = "/skype.gif";
	else if(session->voipSession)
	  voipStr = "&nbsp&lt;VoIP&gt;";
	else
	  voipStr = "";

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		      "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%s:%s%s%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%s:%s</TD>",
		      getRowColor(),
		      makeHostLink(session->initiator, FLAG_HOSTLINK_TEXT_FORMAT,
				   0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
		      sport, session->isP2P == 1 ? "&nbsp&lt;P2P&gt;" : "",
		      voipStr, makeHostLink(session->remotePeer,
					    FLAG_HOSTLINK_TEXT_FORMAT,
					    0, 0, hostLinkBuf1,
					    sizeof(hostLinkBuf1)),
		      dport);
	sendString(buf);

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%s</TD><TD "TD_BG" ALIGN=RIGHT NOWRAP>%s</TD>"
		      "<TD "TD_BG" ALIGN=CENTER NOWRAP>%s</TD>"
		      "<TD "TD_BG" ALIGN=LEFT NOWRAP>%s</TD>",
		      formatBytes(dataSent, 1, formatBuf, sizeof(formatBuf)),
		      formatBytes(dataRcvd, 1, formatBuf1, sizeof(formatBuf1)),
		      formatTime(&(session->firstSeen), formatBuf2, sizeof(formatBuf2)),
		      formatTime(&(session->lastSeen), formatBuf3, sizeof(formatBuf3)),
		      formatSeconds(session->lastSeen-session->firstSeen, formatBuf4, sizeof(formatBuf4)),
		      formatSeconds(myGlobals.actTime-session->lastSeen, formatBuf5, sizeof(formatBuf5)),
		      formatLatency(session->clientNwDelay, session->sessionState, formatBuf6, sizeof(formatBuf6)),
		      formatLatency(session->serverNwDelay, session->sessionState, formatBuf7, sizeof(formatBuf7)),
		      (session->guessed_protocol == NULL) ? "&nbsp;" : session->guessed_protocol,
		      session->session_info ? session->session_info : print_flags(session, flags_buf, sizeof(flags_buf)) /* "&nbsp;" */);
	sendString(buf);

#ifdef PARM_PRINT_ALL_SESSIONS
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		      "<TD "TD_BG" ALIGN=CENTER>%s</TD>",
		      getSessionState(session));
	sendString(buf);
#endif
	sendString("</TR>\n");

	session = session->next;
	printedSessions++;
      }
    }

    releaseMutex(&myGlobals.tcpSessionsMutex[mutex_idx]);
  } /* for */

  if(printedSessions > 0) {
    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");

    if(el == NULL)
      addPageIndicator(CONST_ACTIVE_TCP_SESSIONS_HTML, pageNum,
		       myGlobals.device[actualDeviceId].numTcpSessions,
		       myGlobals.runningPref.maxNumLines, -1, 0, -1);

    printHostColorCode(FALSE, 0);

    printFooterHostLink();
  } else {
    if(el == NULL) {
      printHTMLheader("Active TCP/UDP Sessions", NULL, 0);
      printNoDataYet();
    }
  }
}

/* ********************************** */

void printIpProtocolUsage(void) {
  HostTraffic **hosts, *el;
  u_short clientPorts[MAX_ASSIGNED_IP_PORTS], serverPorts[MAX_ASSIGNED_IP_PORTS];
  u_int j, idx1, hostsNum=0, numPorts=0, maxHosts;
  char buf[LEN_GENERAL_WORK_BUFFER], portBuf[32], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  PortUsage *ports;

  printHTMLheader("TCP/UDP: Local Protocol Usage", NULL, 0);

  memset(clientPorts, 0, sizeof(clientPorts));
  memset(serverPorts, 0, sizeof(serverPorts));

  hosts = (HostTraffic**)mallocAndInitWithReportWarn(myGlobals.device[myGlobals.actualReportDeviceId].
						     hostsno*sizeof(HostTraffic*),
						     "printIpProtocolUsage");
  if(hosts == NULL)
    return;

  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno;

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {

    if(el->community && (!isAllowedCommunity(el->community))) continue;
    if(subnetPseudoLocalHost(el) && (el->hostNumIpAddress[0] != '\0')) {
      hosts[hostsNum++] = el;

      if(el->portsUsage != NULL) {
	ports = el->portsUsage;
	while(ports) {
	  j = ports->port;
	  if((clientPorts[j] == 0) && (serverPorts[j] == 0))
	    numPorts++;
	  clientPorts[j] += ports->clientUses;
	  serverPorts[j] += ports->serverUses;
	  ports = ports->next;
	}
      }
    }

    if(hostsNum >= maxHosts) break;
  } /* for */

  if(numPorts == 0) {
    printNoDataYet();
    free(hosts);
    return;
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<center><p>Reporting on actual traffic for %d host(s) on %d service port(s)</p></center>\n",
		hostsNum, numPorts);
  sendString(buf);

  /* Hosts are now in a contiguous structure (hosts[])... */

  sendString("<CENTER>\n");
  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON" "DARK_BG"><TH "TH_BG" COLSPAN=2>Service</TH>"
	     "<TH "TH_BG">Clients</TH><TH "TH_BG">Servers</TH>\n");

  for(j=0; j<MAX_ASSIGNED_IP_PORTS; j++)
    if((clientPorts[j] > 0) || (serverPorts[j] > 0)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		    "<TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=CENTER>%d</TD>"
		    "<TD "TD_BG">\n", getRowColor(),
		    getAllPortByNum(j, portBuf, sizeof(portBuf)), j);
      sendString(buf);

      if(clientPorts[j] > 0) {
	sendString("<UL>");
	for(idx1=0; idx1<hostsNum; idx1++) {
	  ports = getPortsUsage(hosts[idx1], j, 0);
	  if((hosts[idx1]->portsUsage != NULL)
	     && ports && (ports->clientUses > 0)) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<li>%s\n",
			  makeHostLink(hosts[idx1], FLAG_HOSTLINK_TEXT_FORMAT, 1, 0, 
				       hostLinkBuf, sizeof(hostLinkBuf)));
	    sendString(buf);
	  }
	}
	sendString("</UL>");
      } else
	sendString("&nbsp;");

      sendString("</TD><TD "TD_BG">");

      if(serverPorts[j] > 0) {
	sendString("<UL>");
	for(idx1=0; idx1<hostsNum; idx1++) {
	  ports = getPortsUsage(hosts[idx1], j, 0);
	  if((hosts[idx1]->portsUsage != NULL)
	     && ports && (ports->serverUses > 0)) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<li>%s\n",
			  makeHostLink(hosts[idx1], FLAG_HOSTLINK_TEXT_FORMAT, 1, 0,
				       hostLinkBuf, sizeof(hostLinkBuf)));
	    sendString(buf);
	  }
	}
	sendString("</UL>");
      } else
	sendString("&nbsp;");

      sendString("</TD></TR>");
    } /* for */

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");

  printHostColorCode(FALSE, 0);

  printFooterHostLink();

  free(hosts);
}

/* ********************************** */

void printBar(char *buf, int bufLen,
	      unsigned short percentageS, /* or the ONLY percentage if R = FLAG_NONSPLITBAR */
	      unsigned short percentageR,
	      unsigned short maxPercentage,
	      unsigned short ratio) {

  /* This shouldn't happen */
  if(maxPercentage > 100) { maxPercentage = 100; }

  if(percentageR == FLAG_NONSPLITBAR) {
    /* Single bar */
    if(percentageS > maxPercentage) { percentageS = maxPercentage; }

    switch(percentageS) {
    case 0:
      safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TD colspan=2 "TD_BG" %s>&nbsp;</TD>\n", getActualRowColor());
      break;
    default:
      safe_snprintf(__FILE__, __LINE__, buf, bufLen,
		    "<TD colspan=2 "TD_BG" ALIGN=LEFT>"
		    "<IMG ALIGN=ABSMIDDLE SRC=\"/gauge.jpg\" ALT=\"%d%%\" WIDTH=%d HEIGHT=12>"
		    "&nbsp;</TD>\n",
		    percentageS, ratio*percentageS);
      break;
    }
  } else {
    /* Could happen because of rounding */
    if((percentageS+percentageR) > maxPercentage)
      percentageR--;
    if((percentageS+percentageR) > maxPercentage)
      percentageS--;

    switch(percentageS+percentageR) {
    case 0:
      safe_snprintf(__FILE__, __LINE__, buf, bufLen, 
		    "<TD colspan=2 "TD_BG" %s>&nbsp;</TD>\n", getActualRowColor());
      break;
    default:
      safe_snprintf(__FILE__, __LINE__, buf, bufLen,
		    "<TD "TD_BG" ALIGN=RIGHT>"
		    "&nbsp;<IMG ALIGN=ABSMIDDLE SRC=\"/gaugeS.jpg\" ALT=\"Sent %d%%\" WIDTH=%d HEIGHT=12>"
		    "</TD><TD "TD_BG" ALIGN=LEFT>"
		    "<IMG ALIGN=ABSMIDDLE SRC=\"/gaugeR.jpg\" ALT=\"Received %d%%\" WIDTH=%d HEIGHT=12>"
		    "&nbsp;</TD>\n",
		    percentageS, ratio*percentageS, percentageR, ratio*percentageR);
      break;
    }
  }

  sendString(buf);
}

/* ********************************** */

static int cmpPortsFctn(const void *_a, const void *_b) {
  if((_a == NULL) || (_b == NULL))
    return(0);
  else {
    PortCounter *a, *b;

    a = *((PortCounter**)_a);
    b = *((PortCounter**)_b);

    if((a == NULL) || (b == NULL))
      return(0);

    if((a->sent+a->rcvd) > (b->sent+b->rcvd))
      return(-1);
    else
      return(1);
  }
}

/* ********************************** */

void printIpProtocolDistribution(int mode, int revertOrder, int printGraph) {
  int i;
  char buf[4*LEN_GENERAL_WORK_BUFFER], *sign;
  float total, partialTotal, remainingTraffic;
  float percentage;
  char formatBuf[32], formatBuf1[32], formatBuf2[32];

  if(revertOrder)
    sign = "";
  else
    sign = "-";

  if(mode == FLAG_HOSTLINK_TEXT_FORMAT) {
    printSectionTitle("IP Protocol Distribution");

#ifndef EMBEDDED
    sendString("<TR "TR_ON" BGCOLOR=white><TH "TH_BG" ALIGN=CENTER COLSPAN=3 BGCOLOR=white>"
	       "<iframe frameborder=0 SRC=\"" CONST_PIE_IPPROTO_RL_DIST  CHART_FORMAT "\" width=400 height=250></iframe></TH></TR>\n");
#endif

    printSectionTitle("Local Traffic");

    total = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local.value+
		    myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.local.value)/1024;
    if(total == 0)
      printNoDataYet();
    else {
      sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"80%\"><TR "TR_ON" "DARK_BG">"
		 "<TH "TH_BG" WIDTH=150>IP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
		 "Percentage</TH></TR>\n");
      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local.value/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP",
				"TCP", "UDP", total, percentage, 0, 0);

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"80%\"><TR "TR_ON" "DARK_BG">"
		 "<TH "TH_BG" WIDTH=150>TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250 COLSPAN=2>"
		 "Percentage</TH></TR>\n");

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local.value/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), myGlobals.ipTrafficProtosNames[i],
			  CONST_COLOR_1, partialTotal, percentage, 0, 0, 0);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Protocols",
			CONST_COLOR_1, remainingTraffic, percentage, 0, 0, 0);
      }

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }

    /* ********************************************************** */

    total = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.remote2local.value+
		    myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.remote2local.value)/1024;

    printSectionTitle("Remote to Local Traffic");

    if(total == 0)
      printNoDataYet();
    else {
      sendString("<CENTER>\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"80%\"><TR "TR_ON" "DARK_BG">"
		 "<TH "TH_BG" WIDTH=150>IP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
		 "Percentage</TH></TR>\n");

      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.remote2local.value/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP",
				"TCP", "UDP", total, percentage, 0, 0);

      sendString("</TABLE>"TABLE_OFF);
      sendString("<P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"80%\"><TR "TR_ON" "DARK_BG">"
		 "<TH "TH_BG" WIDTH=150>TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250 COLSPAN=2>"
		 "Percentage</TH></TR>\n");

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote2local.value/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), myGlobals.ipTrafficProtosNames[i],
			  CONST_COLOR_1, partialTotal, percentage, 0, 0, 0);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Protocols",
			CONST_COLOR_1, remainingTraffic, percentage, 0, 0, 0);
      }
      sendString("</TABLE>"TABLE_OFF"\n<P>\n");
      sendString("</CENTER>\n");
    }

    /* ********************************************************** */

    /* Courtesy of "Burton M. Strauss III" <BStrauss3@attbi.com> */

    printSectionTitle("Remote Traffic");

    total = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.remote.value+
		    myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.remote.value)/1024;
    if(total == 0)
      printNoDataYet();
    else {
      sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"80%\"><TR "TR_ON" "DARK_BG">"
		 "<TH "TH_BG" WIDTH=150>IP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
		 "Percentage</TH></TR>\n");
      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.remote.value/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP",
				"TCP", "UDP", total, percentage, 0, 0);

      sendString("</TABLE>"TABLE_OFF"\n");
      sendString("<P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"80%\"><TR "TR_ON" "DARK_BG">"
		 "<TH "TH_BG" WIDTH=150>TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250 COLSPAN=2>"
		 "Percentage</TH></TR>\n");

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal =
	  (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote.value/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf),
			  myGlobals.ipTrafficProtosNames[i],
			  CONST_COLOR_1, partialTotal, percentage, 0, 0, 0);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf),
			"Other&nbsp;TCP/UDP-based&nbsp;Protocols",
			CONST_COLOR_1, remainingTraffic, percentage, 0, 0, 0);
      }

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }

    /* ********************************************************** */

    printSectionTitle("Local to Remote Traffic");

    total = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local2remote.value+
		    myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.local2remote.value)/1024;
    if(total == 0)
      printNoDataYet();
    else {
      sendString("<CENTER>\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"80%\"><TR "TR_ON" "DARK_BG">"
		 "<TH "TH_BG" WIDTH=150>IP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH>"
		 "<TH "TH_BG" WIDTH=250>Percentage</TH></TR>\n");

      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].
	tcpGlobalTrafficStats.local2remote.value/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP",
				"TCP", "UDP", total, percentage, 0, 0);

      sendString("</TABLE>"TABLE_OFF);
      sendString("<P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"80%\"><TR "TR_ON" "DARK_BG">"
		 "<TH "TH_BG" WIDTH=150>TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH>"
		 "<TH "TH_BG" WIDTH=250 COLSPAN=2>Percentage</TH></TR>\n");

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].
	  ipProtoStats[i].local2remote.value/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), myGlobals.ipTrafficProtosNames[i],
			  CONST_COLOR_1, partialTotal, percentage, 0, 0, 0);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;IP-based&nbsp;Protocols",
			CONST_COLOR_1, remainingTraffic, percentage, 0, 0, 0);
      }
      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }
  } else {
    total = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value;

    if(myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList) {
      ProtocolsList *protoList = myGlobals.ipProtosList;
      int idx1 = 0;

      while(protoList != NULL) {
	if(total > (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value)
	  total -= (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value;
	else
	  total = 0;

	idx1++, protoList = protoList->next;
      }
    }

    if(total == 0)
      return;
    else {
      int numProtosFound = 0;
      float remainingFlows = 0;

      printSectionTitle("Global TCP/UDP Protocol Distribution");

      sendString("<CENTER>\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">"
		 "<TR "TR_ON" "DARK_BG"><TH "TH_BG" WIDTH=150>"
		 "TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=50>Data</TH><TH "TH_BG">Flows</TH><TH "TH_BG" COLSPAN=2 width=260>"
		 "Accumulated Percentage / Historical Protocol View</TH></TR>\n");

      remainingTraffic = 0;

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal  = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local.value
	  +myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote.value;
	partialTotal += (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote2local.value
	  +myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local2remote.value;
	remainingFlows += (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].totalFlows.value;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  numProtosFound++;
	  printTableEntry(buf, sizeof(buf),
			  myGlobals.ipTrafficProtosNames[i], CONST_COLOR_1,
			  partialTotal/1024, percentage,
			  1, myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].totalFlows.value, 1);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	float totFlows = (float)myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.totalFlows.value +
	  (float)myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.totalFlows.value;

	if(remainingFlows > totFlows)
	  remainingFlows = 0;
	else
	  remainingFlows = totFlows - remainingFlows;

	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Protocols",
			CONST_COLOR_1, remainingTraffic/1024, percentage,
			1, remainingFlows, 0);
      }

      if((numProtosFound > 0) && printGraph) {
	struct stat statbuf;

	if(strcmp(myGlobals.device[0].name, "pcap-file")) {
	  sendString("<TR "TR_ON" "DARK_BG"><TH "TH_BG" "DARK_BG">Accumulated View</TH><TD "TD_BG" COLSPAN=4 ALIGN=LEFT BGCOLOR=white>"
		     "<iframe  frameborder=0 SRC=\"" CONST_BAR_IPPROTO_DIST  CHART_FORMAT "\" width=400 height=250></iframe></TH></TR>\n");

	  /* RRD */
	  /* Do NOT add a '/' at the end of the path because Win32 will complain about it */
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/interfaces/%s",
			myGlobals.rrdPath != NULL ? myGlobals.rrdPath : ".",
			myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName);

	  revertSlashIfWIN32(buf, 0);

	  if((i = stat(buf, &statbuf)) == 0) {
	    time_t now = time(NULL);
	    u_char found = 0;

	    /* We need to check whether there are interesting rrd files in the directory */
	    DIR* directoryPointer = opendir(buf);

	    if(directoryPointer != NULL) {
	      struct dirent* dp;

	      i = 0;

	      while((dp = readdir(directoryPointer)) != NULL) {
		int len = strlen(dp->d_name);

		if(dp->d_name[0] == '.') continue;
		else if(len < 7 /* IP_ + .rrd */ ) continue;
		else if(strncmp(dp->d_name, "IP_", 3)) continue;
		else if(strstr(dp->d_name, "Flows")) continue;
		else found = 1;
	      }

	      closedir(directoryPointer);
	    }

	    if(found) {
	      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			    "<TR "TR_ON" "DARK_BG"><TH "TH_BG" "DARK_BG">Historical View</TH><TD "TD_BG" COLSPAN=4 ALIGN=left BGCOLOR=white>"
			    "<table border=0><tr><td><IMG SRC=\"/plugins/rrdPlugin?action=graphSummary&graphId=4&"
			    "key=interfaces/%s/&start=now-12h&end=now\" BORDER=0>",
			    myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName);
	      sendString(buf);

	      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			    "</td><td><A HREF=\"/plugins/rrdPlugin?mode=zoom&action=graphSummary&graphId=4&"
			    "key=interfaces/%s/&start=%u&end=%u\"><IMG valign=middle class=tooltip SRC=/graph_zoom.gif border=0></A></tr></table></TD></TR>",
			    myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, (u_int)(now - 12 * 3600), (u_int)now);
	      sendString(buf);
	    }

	    sendString("</TD></TR>\n");
	  }
	}
      }

      sendString("<TR "TR_ON"><TD "TD_BG" COLSPAN=5 ALIGN=LEFT "DARK_BG">"
		 "Note:\n"
		 "<ul><li>What is a flow?<br><ul><li>TCP: a flows is a TCP connection."
		 "<li>UDP: a flow is a set of packets with the same protocol/peers/port.</ul>"
		 "<li>TCP flows are not accounted for fully (sender and recipient) remote peers."
		 "</ul>"
		 "</TD></TR>\n");
      sendString("</TABLE>"TABLE_OFF"<P>\n");

      /* *********************** */

      if((remainingTraffic > 0)
	 && printGraph
	 /* Courtesy of Martin Winter <mwinter@noaccess.com> */
	 && (myGlobals.device[myGlobals.actualReportDeviceId].ipPorts != NULL)) {
	PortCounter **ipPorts;
	int idx = 0;

	ipPorts = (PortCounter**)calloc(MAX_IP_PORT, sizeof(PortCounter*));

	for(i=0; i<MAX_IP_PORT; i++) {
	  if(myGlobals.device[myGlobals.actualReportDeviceId].ipPorts[i] != NULL) {
	    ipPorts[idx] = myGlobals.device[myGlobals.actualReportDeviceId].ipPorts[i];
	    idx++;
	  }
	}

	if(idx > 0) {
	  printSectionTitle("TCP/UDP Traffic Port Distribution:<br>Last Minute View");

	  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON" "DARK_BG">"
		     "<TH "TH_BG" colspan=2>TCP/UDP Port</TH>"
		     "<TH "TH_BG">Total</TH><TH "TH_BG">Sent</TH><TH "TH_BG">Rcvd</TH></TR>");

	  qsort(ipPorts, idx, sizeof(PortCounter**), cmpPortsFctn);

	  if(idx > 32) idx = 32; /* Limit to 32 entries max */

	  for(i=0; i<idx; i++) {
	    if(ipPorts[i] != NULL) {
	      char portBuf[32];
	      char *symPort = getAllPortByNum(ipPorts[i]->port, portBuf, sizeof(portBuf));

	      if(symPort == NULL) symPort = "";

	      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
			    "<TH "TH_BG" ALIGN=LEFT><A HREF=\"" CONST_SHOW_PORT_TRAFFIC_HTML "?port=%d\">%s</A>"
			    "</th><td align=right>%d</td>"
			    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			    "</TR>\n",
			    getRowColor(),
			    ipPorts[i]->port, symPort, ipPorts[i]->port,
			    formatBytes(ipPorts[i]->sent+ipPorts[i]->rcvd, 1, formatBuf, sizeof(formatBuf)),
			    formatBytes(ipPorts[i]->sent, 1, formatBuf1, sizeof(formatBuf1)),
			    formatBytes(ipPorts[i]->rcvd, 1, formatBuf2, sizeof(formatBuf2)));
	      sendString(buf);
	    }
	  } /* for */

	  sendString("<tr><td align=left "DARK_BG" colspan=5>Notes:<ul>"
		     "<li>sum(total traffic per port) = 2*(total IP traffic)"
		     "<br>because the traffic per port is counted twice (sent and received)"
		     "<li>This report includes broadcast packets</ul></td></tr>\n");
	}
	free(ipPorts);
	sendString("</TABLE>"TABLE_OFF"<P></center>\n");
	if(idx >= 32)
	  sendString("<p>This extract is just a sample of the packets ntop has seen.</p>");
      } else {
	sendString("<p>Note: This report includes broadcast packets.</p>\n");
	sendString("</CENTER>\n");
      }
    }
  }
}

/* ************************ */

void printProtoTraffic(int printGraph) {
  float total, perc;
  char buf[2*LEN_GENERAL_WORK_BUFFER], formatBuf[32];

  total = myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value/1024; /* total is expressed in KBytes.value */

  if(total == 0)
    return;

  sendString("<CENTER>\n");

  if(myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value > 0) {
    printSectionTitle("Global Protocol Distribution");

    sendString("<P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON" "DARK_BG"><TH "TH_BG" WIDTH=150>Protocol</TH>"
	       "<TH "TH_BG" WIDTH=50>Data</TH><TH "TH_BG" WIDTH=250 COLSPAN=2>Percentage</TH></TR>\n");

    perc = 100*((float)myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value/
		myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value);
    if(perc > 100) perc = 100;

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" WIDTH=150 ALIGN=LEFT "DARK_BG">IP</TH>"
		  "<TD "TD_BG" WIDTH=50 ALIGN=RIGHT>%s"
		  "</td><td align=right WIDTH=50>%.1f%%</TD><TD "TD_BG" WIDTH=200>"
		  "<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%%\">",
		  getRowColor(),
		  formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value, 1,
			      formatBuf, sizeof(formatBuf)),
		  perc);
    sendString(buf);

    printTableEntry(buf, sizeof(buf), "TCP", CONST_COLOR_1,
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value/1024,
		    100*((float)myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value/
			 myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value), 0, 0, 0);
    printTableEntry(buf, sizeof(buf), "UDP", CONST_COLOR_1,
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value/1024,
		    100*((float)myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value/
			 myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value), 0, 0, 0);
    printTableEntry(buf, sizeof(buf), "ICMP", CONST_COLOR_1,
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value/1024,
		    100*((float)myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value/
			 myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value), 0, 0, 0);
    printTableEntry(buf, sizeof(buf), "ICMPv6", CONST_COLOR_1,
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].icmp6Bytes.value/1024,
		    100*((float)myGlobals.device[myGlobals.actualReportDeviceId].icmp6Bytes.value/
			 myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value), 0, 0, 0);

    if(myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList) {
      ProtocolsList *protoList = myGlobals.ipProtosList;
      int idx = 0;

      while(protoList != NULL) {
	printTableEntry(buf, sizeof(buf), protoList->protocolName, CONST_COLOR_1,
			(float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx].value/1024,
			100*((float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx].value/
			     myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value), 0, 0, 0);
	idx++, protoList = protoList->next;
      }
    }

    printTableEntry(buf, sizeof(buf), "Other&nbsp;IP", CONST_COLOR_1,
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value/1024,
		    ((float)myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value/
		     myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value), 0, 0, 0);

    sendString("</TABLE>"TABLE_OFF"</TR>");
  } else
    printGraph = 0;

  printTableEntry(buf, sizeof(buf), "(R)ARP", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value), 0, 0, 0);
  printTableEntry(buf, sizeof(buf), "DLC", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value), 0, 0, 0);
  printTableEntry(buf, sizeof(buf), "IPX", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value), 0, 0, 0);
  printTableEntry(buf, sizeof(buf), "IPsec", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ipsecBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].ipsecBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value), 0, 0, 0);
  printTableEntry(buf, sizeof(buf), "AppleTalk", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value), 0, 0, 0);
  printTableEntry(buf, sizeof(buf), "NetBios", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value), 0, 0, 0);
  printTableEntry(buf, sizeof(buf), "GRE", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].greBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].greBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value), 0, 0, 0);
  printTableEntry(buf, sizeof(buf), "IPv6", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value), 0, 0, 0);
  printTableEntry(buf, sizeof(buf), "STP", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value), 0, 0, 0);
  printTableEntry(buf, sizeof(buf), "Other", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value), 0, 0, 0);

  if(printGraph) {
    sendString("<TR "TR_ON"><TD "TD_BG" COLSPAN=4 ALIGN=CENTER BGCOLOR=white>"
	       "<iframe frameborder=0 SRC=\"" CONST_BAR_ALLPROTO_DIST  CHART_FORMAT "\" "
	       "width=650 height=250></iframe>"
	       "</TD></TR>\n");
  }

  sendString("</TABLE>"TABLE_OFF"<P></CENTER>\n");
}

/* ************************ */

void printIpTrafficMatrix(void) {
  int i, j, numEntries=0, numConsecutiveEmptyCells;
  char buf[LEN_GENERAL_WORK_BUFFER], formatBuf[32], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  short *activeHosts;
  Counter minTraffic=(Counter)LONG_MAX, maxTraffic=0, avgTraffic;
  Counter avgTrafficLow, avgTrafficHigh, tmpCounter;

  printHTMLheader("IP Subnet Traffic Matrix", NULL, 0);

  if(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix == NULL) {
    printFlagedWarning("<I>Traffic matrix is not available for the selected network interface</I>");
    return;
  }

  activeHosts = (short*)mallocAndInitWithReportWarn(myGlobals.device[myGlobals.actualReportDeviceId].numHosts*sizeof(short), "printIpTrafficMatrix");
  if(activeHosts == NULL)
    return;

  for(i=0; i<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; i++) {
    activeHosts[i] = 0;

    for(j=0; j<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; j++) {
      int id = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts+j;

      if(((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[id] != NULL)
	  && (myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[id]->bytesSent.value != 0))
	 || ((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[id] != NULL)
	     && (myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[id]->bytesRcvd.value != 0))) {
	activeHosts[i] = 1;
	numEntries++;
	break;
      }
    }

    if(activeHosts[i] == 1) {
      if(numEntries == 1) {
	sendString("<CENTER>\n");
	sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG"><SMALL>&nbsp;F&nbsp;"
		   "&nbsp;&nbsp;To<br>&nbsp;r<br>&nbsp;o<br>&nbsp;m</SMALL></TH>\n");
      }

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TH "TH_BG" ALIGN=CENTER "DARK_BG"><SMALL>%s</SMALL></TH>",
		    getHostName(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i],
				1, hostLinkBuf, sizeof(hostLinkBuf)));
      sendString(buf);
    }
  }

  if(numEntries == 0) {
    printNoDataYet();
    free(activeHosts);
    return;
  } else
    sendString("</TR>\n");

  for(i=0; i<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; i++)
    for(j=0; j<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; j++) {
      int idx = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts+j;

      if(((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx] != NULL)
	  && ((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value != 0)
	      || (myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value != 0)))) {
	if(minTraffic > myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value)
	  minTraffic = myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value;
	if(minTraffic > myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value)
	  minTraffic = myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value;
	if(maxTraffic < myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value)
	  maxTraffic = myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value;
	if(maxTraffic < myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value)
	  maxTraffic = myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value;
      }
    }

  avgTraffic = (Counter)(((float)minTraffic+(float)maxTraffic)/2);
  avgTrafficLow  = (avgTraffic*15)/100; /* 15% of the average */
  avgTrafficHigh = 2*(maxTraffic/3);   /* 75% of max traffic */


  for(i=0; i<myGlobals.device[myGlobals.actualReportDeviceId].numHosts; i++)
    if(activeHosts[i] == 1) {
      numConsecutiveEmptyCells=0;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG"><SMALL>",  getRowColor());
      sendString(buf);

      sendString(makeHostLink(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i],
			      FLAG_HOSTLINK_TEXT_FORMAT, 1, 0, hostLinkBuf, sizeof(hostLinkBuf)));
      sendString("</SMALL></TH>");

      for(j=0; j<myGlobals.device[myGlobals.actualReportDeviceId].numHosts; j++) {
	int idx = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts+j;

	if((i == j) &&
	   strcmp(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostNumIpAddress,
		  "127.0.0.1"))
	  numConsecutiveEmptyCells++;
	else if(activeHosts[j] == 1) {
	  if(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx] == NULL)
	    numConsecutiveEmptyCells++;
	  else {
	    if(numConsecutiveEmptyCells > 0) {
	      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" COLSPAN=%d>&nbsp;</TD>\n",
			    numConsecutiveEmptyCells);
	      sendString(buf);
	      numConsecutiveEmptyCells = 0;
	    }

	    tmpCounter = myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value+
	      myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value;
	    /* Fix below courtesy of Danijel Doriae <danijel.doric@industrogradnja.tel.hr> */
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER %s>"
			  "<A HREF=# onMouseOver=\"window.status='"
			  "%s';return true\" onMouseOut="
			  "\"window.status='';return true\"><SMALL>%s</SMALL></A></TH>\n",
			  calculateCellColor(tmpCounter, avgTrafficLow, avgTrafficHigh),
			  buildHTMLBrowserWindowsLabel(i, j, TRUE),
			  formatBytes(tmpCounter, 1, formatBuf, sizeof(formatBuf)));
	    sendString(buf);
	  }
	}
      }

      if(numConsecutiveEmptyCells > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" COLSPAN=%d>&nbsp;</TD>\n",
		      numConsecutiveEmptyCells);
	sendString(buf);
	numConsecutiveEmptyCells = 0;
      }

      sendString("</TR>\n");
    }

  sendString("</TABLE>"TABLE_OFF"\n<P>\n");
  sendString("</CENTER>\n");

  printFooterHostLink();

  free(activeHosts);
}

/* ************************ */

void printThptStatsMatrix(int sortedColumn) {
  int i, dataSent;
  char label[32], label1[32], buf[LEN_GENERAL_WORK_BUFFER],
    formatBuf[32], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  time_t tmpTime;
  struct tm t;
  HostTraffic *el;
  HostTraffic tmpEl;

  printHTMLheader("Network Load Statistics Matrix", NULL, 0);

  memset (&tmpEl, 0, sizeof(HostTraffic));
  if(allocFcScsiCounters(&tmpEl) == NULL) {
    traceEvent (CONST_TRACE_WARNING, "Unable to allocate memory for FC counters");
    return;
  }

  switch(sortedColumn) {
  case 0:
  case 1:
    if(myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples < 1) {
      printNoDataYet();
      free(tmpEl.fcCounters);
      return;
    }

    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON" "DARK_BG">"
	       "<TH "TH_BG">Sampling Period</TH>"
	       "<TH "TH_BG">Average Thpt</TH>"
	       "<TH "TH_BG">Top Hosts Sent Thpt</TH>"
	       "<TH "TH_BG">Top Hosts Rcvd Thpt</TH></TR>\n");

    for(i=0; i<(sortedColumn == 0 ? 10 : 60); i++) {
      if(myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].trafficValue == 0)
	break;

      if(myGlobals.pcap_file_list != NULL) {
	tmpTime = myGlobals.lastPktTime.tv_sec-(i*60);
      }
      else {
	tmpTime = myGlobals.actTime-(i*60);
      }
      strftime(label, sizeof(label), CONST_TOD_NOSEC_TIMESPEC, localtime_r(&tmpTime, &t));

      if(myGlobals.pcap_file_list != NULL) {
	tmpTime = myGlobals.lastPktTime.tv_sec -((i+1)*60);
      }
      else {
	tmpTime = myGlobals.actTime-((i+1)*60);
      }
      strftime(label1, sizeof(label), CONST_TOD_NOSEC_TIMESPEC, localtime_r(&tmpTime, &t));
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=CENTER>"
		    "<B>%s&nbsp;-&nbsp;%s</B></TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=LEFT>"
		    "<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%%>",
		    getRowColor(), label1, label,
		    formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				     last60MinutesThpt[i].trafficValue, 1,
				     formatBuf, sizeof(formatBuf)));
      sendString(buf);

      dataSent = 0;

      /* ************************* */

      if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].topHostSentSerial)) {


	if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       last60MinutesThpt[i].topHostSentSerial, myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last60MinutesThpt[i].topSentTraffic.value, 1,
					 formatBuf, sizeof(formatBuf)));
	  sendString(buf); dataSent = 1;
	}
      }

      if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].secondHostSentSerial)) {

	if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       last60MinutesThpt[i].secondHostSentSerial, myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last60MinutesThpt[i].secondSentTraffic.value, 1,
					 formatBuf, sizeof(formatBuf)));
	  sendString(buf); dataSent = 1;
	}
      }

      if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].thirdHostSentSerial)) {

	if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       last60MinutesThpt[i].thirdHostSentSerial, myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last60MinutesThpt[i].thirdSentTraffic.value, 1,
					 formatBuf, sizeof(formatBuf)));
	  sendString(buf); dataSent = 1;
	}
      }

      /* ************************* */

      if(!dataSent) sendString("&nbsp;");
      sendString("</TABLE>"TABLE_OFF"</TD><TD "TD_BG" ALIGN=LEFT><TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%%>\n");
      dataSent = 0;

      /* ************************* */

      if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].topHostRcvdSerial)) {

	if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       last60MinutesThpt[i].topHostRcvdSerial, myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last60MinutesThpt[i].topRcvdTraffic.value, 1,
					 formatBuf, sizeof(formatBuf)));
	  sendString(buf); dataSent = 1;
	}
      }

      if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].secondHostRcvdSerial)) {

	if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       last60MinutesThpt[i].secondHostRcvdSerial, myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last60MinutesThpt[i].secondRcvdTraffic.value, 1,
					 formatBuf, sizeof(formatBuf)));
	  sendString(buf); dataSent = 1;
	}
      }

      if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].thirdHostRcvdSerial)) {

	if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       last60MinutesThpt[i].thirdHostRcvdSerial, myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last60MinutesThpt[i].thirdRcvdTraffic.value, 1,
					 formatBuf, sizeof(formatBuf)));
	  sendString(buf); dataSent = 1;
	}
      }

      /* ************************* */

      if(!dataSent) sendString("&nbsp;");
      sendString("</TABLE></TD></TR>\n");
    }
    break;
  case 2:
  default:
    if(myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples < 60) {
      printNoDataYet();
      free (tmpEl.fcCounters);
      return;
    } else {
      sendString("<CENTER>\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON">"
		 "<TH "TH_BG">Sampling Period</TH><TH "TH_BG">Average Thpt</TH>"
		 "<TH "TH_BG">Top Thpt Sent Hosts</TH><TH "TH_BG">Top Rcvd Sent Hosts</TH>"
		 "</TR>\n");

      for(i=0; i<24; i++) {
	if(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].trafficValue == 0)
	  break;

        if(myGlobals.pcap_file_list != NULL) {
	  tmpTime = myGlobals.lastPktTime.tv_sec-(i*60*60);
        }
        else {
	  tmpTime = myGlobals.actTime-(i*60*60);
        }
	strftime(label, sizeof(label), CONST_TOD_NOSEC_TIMESPEC, localtime_r(&tmpTime, &t));

        if(myGlobals.pcap_file_list != NULL) {
	  tmpTime = myGlobals.lastPktTime.tv_sec-((i+1)*60*60);
        }
        else {
	  tmpTime = myGlobals.actTime-((i+1)*60*60);
        }
	strftime(label1, sizeof(label1), CONST_TOD_NOSEC_TIMESPEC, localtime_r(&tmpTime, &t));

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TD "TD_BG" ALIGN=CENTER><B>%s&nbsp;-&nbsp;%s</B></TH>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=LEFT "DARK_BG">"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">",
		      getRowColor(), label, label1,
		      formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				       last24HoursThpt[i].trafficValue, 1,
				       formatBuf, sizeof(formatBuf)));
	sendString(buf);

	/* ************************* */

	if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].topHostSentSerial)) {

	  if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].topHostSentSerial,
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			  makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			  formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					   last24HoursThpt[i].topSentTraffic.value, 1,
					   formatBuf, sizeof(formatBuf)));
	    sendString(buf);
	  }
	}

	if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].secondHostSentSerial)) {

	  if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].secondHostSentSerial,
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			  makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			  formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					   last24HoursThpt[i].secondSentTraffic.value, 1,
					   formatBuf, sizeof(formatBuf)));
	    sendString(buf);
	  }
	}

	if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].thirdHostSentSerial)) {

	  if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].thirdHostSentSerial,
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			  makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			  formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					   last24HoursThpt[i].thirdSentTraffic.value, 1,
					   formatBuf, sizeof(formatBuf)));
	    sendString(buf);
	  }
	}

	/* ************************* */

	sendString("&nbsp;");
	sendString("</TABLE>"TABLE_OFF"</TD><TD "TD_BG" ALIGN=LEFT "DARK_BG">"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n");

	/* ************************* */

	if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].topHostRcvdSerial)) {

	  if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].topHostRcvdSerial,
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			  makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			  formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					   last24HoursThpt[i].topRcvdTraffic.value, 1,
					   formatBuf, sizeof(formatBuf)));
	    sendString(buf);
	  }
	}

	if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].secondHostRcvdSerial)) {

	  if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].secondHostRcvdSerial,
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			  makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			  formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					   last24HoursThpt[i].secondRcvdTraffic.value, 1,
					   formatBuf, sizeof(formatBuf)));
	    sendString(buf);
	  }
	}

	if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].thirdHostRcvdSerial)) {

	  if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].thirdHostRcvdSerial,
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			  makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			  formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					   last24HoursThpt[i].thirdRcvdTraffic.value, 1,
					   formatBuf, sizeof(formatBuf)));
	    sendString(buf);
	  }
	}

	/* ************************* */

	sendString("&nbsp;");
	sendString("</TABLE>"TABLE_OFF"</TD></TR>\n");
      }
    }
    break;
  }

  sendString("</TABLE>"TABLE_OFF"</CENTER>\n");
  free (tmpEl.fcCounters);
}

/* ************************ */

#define RRD_THPT_URL "/plugins/rrdPlugin?action=arbreq&which=graph&arbfile=throughput&arbiface=%s&arbip=&start=%u&end=%u&counter=&title=%s"

#define RRD_THPT_STR "<tr><td align=right><A HREF=\"" CONST_THPT_STATS_MATRIX_HTML "?col=%d\" BORDER=0 BGCOLOR=white><IMG class=tooltip SRC=\"" RRD_THPT_URL "\" border=\"0\" alt=\"Domain-wide Historical Data\"></A></td><td align=left><A HREF=\"" RRD_THPT_URL "&mode=zoom\" BORDER=0 BGCOLOR=white>&nbsp;<IMG valign=middle class=tooltip SRC=/graph_zoom.gif border=0></A></td></tr>"

void printThptStats(int sortedColumn _UNUSED_) {
  char tmpBuf[1024], formatBuf[32], formatBuf1[32];
  struct stat statbuf;
  int i, useRRD = 1;
  time_t now = time(NULL);

  printHTMLheader("Network Load Statistics", NULL, 0);

  if(strcmp(myGlobals.device[0].name, "pcap-file")) {
    /*
      if(myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
      printFlagedWarning("<I>Network load statistics are not available for virtual interfaces</I>");
      return;
      }
    */

    /* Do NOT add a '/' at the end of the path because Win32 will complain about it */
#ifdef WIN32
    {
      unsigned long driveSerial;

      get_serial(&driveSerial);

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%s/%u/interfaces/%s/throughput.rrd",
		    myGlobals.rrdPath != NULL ? myGlobals.rrdVolatilePath : ".", driveSerial,
		    myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName);
    }
#else
    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%s/interfaces/%s/throughput.rrd",
		  myGlobals.rrdPath != NULL ? myGlobals.rrdVolatilePath : ".",
		  myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName);
#endif

    revertSlashIfWIN32(tmpBuf, 0);

    if((i = stat(tmpBuf, &statbuf)) != 0) {
      useRRD = 0;
      sendString("<p align=left><b>NOTE</b>: this page is not operational when the <A HREF=/plugins/rrdPlugin>RRD plugin</A> "
		 "is disabled, misconfigured or missing. Please check the ntop log file.</p>");

      return;
    }

    if(useRRD) {
      sendString("<CENTER>\n<table border=0>\n");

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), RRD_THPT_STR,
		    0,
		    myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, (unsigned int)(now-600),
		    (unsigned int)now, "Last+10+Minutes+Throughput",
		    myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, (unsigned int)(now-600),
		    (unsigned int)now, "Throughput"
		    );
      sendString(tmpBuf);

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "<tr><td align=center colspan=2><H4>Time [ %s through %s]</H4></td></tr>",
		    formatTimeStamp(0, 0, 10, formatBuf, sizeof(formatBuf)),
		    formatTimeStamp(0, 0,  0, formatBuf1, sizeof(formatBuf1)));
      sendString(tmpBuf);

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), RRD_THPT_STR,
		    1,
		    myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, (unsigned int)(now-3600),
		    (unsigned int)now, "Last+Hour+Throughput",
		    myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, (unsigned int)(now-3600),
		    (unsigned int)now, "Throughput");
      sendString(tmpBuf);
    }

    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "<tr><td align=center colspan=2><H4>Time [ %s through %s]</H4></td></tr>",
		  formatTimeStamp(0, 0, 60, formatBuf, sizeof(formatBuf)),
		  formatTimeStamp(0, 0,  0, formatBuf1, sizeof(formatBuf1)));
    sendString(tmpBuf);

    if(useRRD) {
      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), RRD_THPT_STR,
		    2, myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, (unsigned int)(now-86400),
		    (unsigned int)now, "Current+Day+Throughput",
		    myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, (unsigned int)(now-86400),
		    (unsigned int)now, "Throughput");
      sendString(tmpBuf);
    }

    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "<tr><td align=center colspan=2><H4>Time [ %s through %s]</H4></td></tr>",
		  formatTimeStamp(0, 24, 0, formatBuf, sizeof(formatBuf)),
		  formatTimeStamp(0,  0, 0, formatBuf1, sizeof(formatBuf1)));
    sendString(tmpBuf);

    if(useRRD) {
      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), RRD_THPT_STR,
		    3, myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
		    (unsigned int)(now-86400*30), (unsigned int)now, "Last+Month+Throughput",
		    myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
		    (unsigned int)(now-86400*30), (unsigned int)now, "Throughput");
      sendString(tmpBuf);
    }

    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "<tr><td align=center colspan=2><H4>Time [ %s through %s]</H4></td></tr>",
		  formatTimeStamp(30, 0, 0, formatBuf, sizeof(formatBuf)),
		  formatTimeStamp( 0, 0, 0, formatBuf1, sizeof(formatBuf1)));
    sendString(tmpBuf);

    sendString("</table></CENTER>\n");

    if(useRRD) {
      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "<p align=right>"
		    "[ <A HREF=\"/" CONST_PLUGINS_HEADER"rrdPlugin\">Change Throughput Granularity</A> ]</p>",
		    formatTimeStamp(0, 0, 10, formatBuf, sizeof(formatBuf)),
		    formatTimeStamp(0, 0,  0, formatBuf1, sizeof(formatBuf1)));
      sendString(tmpBuf);
    }
  }

  sendString("<p align=left><b>NOTE</b>: this page is not operational when the <A HREF=/plugins/rrdPlugin>RRD plugin</A> is disabled, misconfigured or missing.</p>");
}

/* ************************ */

static int cmpStatsFctn(const void *_a, const void *_b) {
  DomainStats *a = (DomainStats *)_a;
  DomainStats *b = (DomainStats *)_b;
  Counter a_=0, b_=0;
  int rc;

  if((a == NULL) && (b != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpStatsFctn() (1)");
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpStatsFctn() (2)");
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpStatsFctn() (3)");
    return(0);
  }

  /*
  traceEvent(CONST_TRACE_INFO, "--> [columnSort=%d][network_mode_sort=%d]",
	     myGlobals.columnSort, network_mode_sort);
  */

  switch(myGlobals.columnSort) {
  case 0:
    if(network_mode_sort == NETWORK_VIEW) {
      char buf1[64], buf2[64];

      char *nw_name_a = subnetId2networkName(a->known_subnet_id, buf1, sizeof(buf1));
      char *nw_name_b = subnetId2networkName(b->known_subnet_id, buf2, sizeof(buf2));

      /* traceEvent(CONST_TRACE_INFO, "--> [%s][%s]", nw_name_a, nw_name_b); */

      return(strcmp(nw_name_a, nw_name_b));
    } else if(network_mode_sort == AS_VIEW) {
      a_ = a->domainHost->hostAS , b_ = b->domainHost->hostAS;
    } else {
      /* Host */
      return(cmpFctnResolvedName(&(a->domainHost), &(b->domainHost)));
    }
    break;
  case 1: /* Domain Flag */
    /* We don't worry about whether this is single or multi domain, since if it is a single
       domain, our fallback to hostResolvedName will rule anyway.
    */
    rc = cmpFctnLocationName(a, b); return(rc);
  case 2: a_  = a->bytesSent.value, b_ = b->bytesSent.value;   break;
  case 3: a_  = a->bytesRcvd.value, b_ = b->bytesRcvd.value;   break;
  case 4: a_  = a->tcpSent.value  , b_ = b->tcpSent.value;     break;
  case 5: a_  = a->tcpRcvd.value  , b_ = b->tcpRcvd.value;     break;
  case 6: a_  = a->udpSent.value  , b_ = b->udpSent.value;     break;
  case 7: a_  = a->udpRcvd.value  , b_ = b->udpRcvd.value;     break;
  case 8: a_  = a->icmpSent.value , b_ = b->icmpSent.value;    break;
  case 9: a_  = a->icmpRcvd.value , b_ = b->icmpRcvd.value;    break;
  case 10:a_  = a->icmp6Sent.value , b_ = b->icmp6Sent.value;  break;
  case 11:a_  = a->icmp6Rcvd.value , b_ = b->icmp6Rcvd.value;  break;
  }

  if(a_ < b_)
    return(1);
  else if(a_ > b_)
    return(-1);
  else
    return(0);
}

/* ****************************************** */

#define COMMUNITY_HEADER       "community."
#define COMMUNITY_HEADER_LEN   strlen(COMMUNITY_HEADER)
#define MAX_NUM_COMMUNITIES     16

/* if myGlobals.runningPref.domainName == NULL -> print all domains */
void printDomainStats(char* domain_network_name, int network_mode,
		      int communityMode, int sortedColumn,
		      int revertOrder, int pageNum) {
  u_int idx, tmpIdx, numEntries=0, printedEntries=0, maxHosts;
  short keyValue=0, i;
  HostTraffic *el;
  char buf[3*LEN_GENERAL_WORK_BUFFER], buf1[64];
  DomainStats **stats, *tmpStats = NULL, *statsEntry;
  char htmlAnchor[2*LEN_GENERAL_WORK_BUFFER], htmlAnchor1[2*LEN_GENERAL_WORK_BUFFER],
    *sign, *arrowGif, *arrow[48], *theAnchor[48];
  Counter totBytesSent=0, totBytesRcvd=0;
  char formatBuf[32], formatBuf1[32], formatBuf2[32], formatBuf3[32], formatBuf4[32],
    formatBuf5[32], formatBuf6[32], formatBuf7[32], formatBuf8[32], formatBuf9[32],
    hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  NetworkStats localNetworks[MAX_NUM_COMMUNITIES][MAX_NUM_NETWORKS]; /* [0]=network, [1]=mask, [2]=broadcast, [3]=mask_v6 */
  u_short numLocalNetworks[MAX_NUM_COMMUNITIES], totNumCommunities=0;
  u_char *communityNames[MAX_NUM_COMMUNITIES], debug = 0;

  network_mode_sort = network_mode;

  if(!communityMode) {
    char sym_nw_name[256] = { 0 };

    if(domain_network_name == NULL)
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Statistics for all %s",
		    (network_mode == NETWORK_VIEW) ? "Networks" 
		    : ((network_mode == AS_VIEW) ? "ASs" : "Domains"));
    else {
      char link_name[256] = { 0 };

      if(network_mode > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s.name.%s",
		      (network_mode == NETWORK_VIEW) ? "network" : "as",
		      domain_network_name);

	if(fetchPrefsValue(buf, sym_nw_name, sizeof(sym_nw_name)) == -1)
	  sym_nw_name[0] = '\0';

	safe_snprintf(__FILE__, __LINE__, link_name, sizeof(link_name),
		      " <A HREF=\"%s?key=%s.name.%s\">%s</A>",
		      CONST_EDIT_PREFS,
		      (network_mode == NETWORK_VIEW) ? "network" : "as",
		      domain_network_name,
		      "<img class=tooltip alt=\"Change name\" "
		      "src=/"CONST_EDIT_IMG" border=\"0\">");
      }

      if(network_mode == AS_VIEW) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "Statistics for hosts in AS <A HREF=http://ws.arin.net/cgi-bin/whois.pl?queryinput=AS%s>%s</A> %s",
		      domain_network_name, (sym_nw_name[0] == '\0') ? domain_network_name : sym_nw_name,
		      link_name);
      } else if(network_mode == AS_GRAPH_VIEW) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "Statistics for AS <A HREF=http://ws.arin.net/cgi-bin/whois.pl?queryinput=AS%s>%s</A> %s",
		      domain_network_name, (sym_nw_name[0] == '\0') ? domain_network_name : sym_nw_name,
		      link_name);
      } else {
	char tmp_buf[64], key[64], my_domain_network_name[64], *placeholder = domain_network_name;

	if(network_mode == NETWORK_VIEW) {
	  safe_snprintf(__FILE__, __LINE__, my_domain_network_name, sizeof(my_domain_network_name),
			"%s", subnetId2networkName(atoi(domain_network_name), tmp_buf, sizeof(tmp_buf)));
	  safe_snprintf(__FILE__, __LINE__, key, sizeof(key), "subnet.name.%s", tmp_buf);
	  domain_network_name = my_domain_network_name;
	  sym_nw_name[0] = '\0';
	  fetchPrefsValue(key, sym_nw_name, sizeof(sym_nw_name));
	}

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "Statistics for hosts in %s '%s' %s",
		      (network_mode == NETWORK_VIEW) ? "network" 
		      : ((network_mode == AS_VIEW) ? "AS" : "domain"),
		      (sym_nw_name[0] == '\0') ? domain_network_name : sym_nw_name,
		      link_name);

	domain_network_name = placeholder;
      }
    }
  } else {
    char localAddresses[1024];
    datum key, nextkey;

    if(domain_network_name == NULL) {
      key = gdbm_firstkey(myGlobals.prefsFile);
      while (key.dptr) {
	char val[256];

	if((fetchPrefsValue(key.dptr, val, sizeof(val)) == 0)
	   && (!strncmp(key.dptr, COMMUNITY_HEADER, COMMUNITY_HEADER_LEN))) {
	  localAddresses[0] = '\0';
	  numLocalNetworks[totNumCommunities] = 0;
	  handleAddressLists(val, localNetworks[totNumCommunities], 
			     &numLocalNetworks[totNumCommunities],
			     localAddresses, sizeof(localAddresses),
			     CONST_HANDLEADDRESSLISTS_COMMUNITIES);
	  communityNames[totNumCommunities] = (u_char*)strdup((char*)&key.dptr[COMMUNITY_HEADER_LEN]);
	  totNumCommunities++;
	}

	nextkey = gdbm_nextkey (myGlobals.prefsFile, key);
	free (key.dptr);
	key = nextkey;
      }

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Statistics for all communities");
    } else {
      char communityAddresses[256];

      snprintf(buf, sizeof(buf), COMMUNITY_HEADER"%s", domain_network_name);
      if(fetchPrefsValue(buf, communityAddresses, sizeof(communityAddresses)) != -1) {
	localAddresses[0] = '\0';
	numLocalNetworks[totNumCommunities] = 0;
	handleAddressLists(communityAddresses, localNetworks[totNumCommunities], &numLocalNetworks[totNumCommunities],
			   localAddresses, sizeof(localAddresses),
			   CONST_HANDLEADDRESSLISTS_COMMUNITIES);
	/* communityNames[totNumCommunities] = (u_char*)strdup((char*)&domain_network_name[COMMUNITY_HEADER_LEN]);  */
	communityNames[totNumCommunities] = (u_char*)strdup(domain_network_name);

	if(debug) traceEvent(CONST_TRACE_WARNING, "communityNames[%d]=[%s]", totNumCommunities,  communityNames[totNumCommunities]);

	totNumCommunities++;
      }

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Statistics for hosts in community <i>%s</i>",
		    domain_network_name);
    }

    if(totNumCommunities == 0) {
      printHTMLheader(buf, NULL, 0);
      printFlagedWarning("<I>Empty community list. Jump to <A HREF=/"CONST_EDIT_PREFS">community definition</A>.</I>");
      if(tmpStats != NULL) free(tmpStats);
      goto free_communitys;
    }
  }

  if(debug) traceEvent(CONST_TRACE_WARNING, "totNumCommunities=%d", totNumCommunities);

  printHTMLheader(buf, NULL, 0);

  maxHosts = max(myGlobals.device[myGlobals.actualReportDeviceId].hostsno, myGlobals.numKnownSubnets);
  tmpStats = (DomainStats*)mallocAndInitWithReportWarn(maxHosts*sizeof(DomainStats), "printDomainStats");
  if(tmpStats == NULL)
    return;

  /* Fix below courtesy of Francis Pintos <francis@arhl.com.hk> */
  stats = (DomainStats**)mallocAndInitWithReportWarn(maxHosts*sizeof(DomainStats*), "printDomainStats(2)");
  if(stats == NULL) {
    /* also free the block of memory allocated a few lines up */
    if(tmpStats != NULL) free(tmpStats);
    goto free_communitys;
    return;
  }

  if(network_mode == AS_GRAPH_VIEW) {
    sendString("<center><TABLE BORDER=0 "TABLE_DEFAULTS">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<tr><td align=center>"
		  "<IMG SRC=/plugins/rrdPlugin?action=interfaceSummary&amp;key=%s/AS/%s&amp;graphId=0\">\n",
		  myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, domain_network_name);
    sendString(buf);
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "</td><td valign=middle>"
		  "<A HREF=/plugins/rrdPlugin?mode=zoom&action=interfaceSummary&amp;key=%s/AS/%s&amp;graphId=0\">"
		  "<IMG valign=middle class=tooltip SRC=/graph_zoom.gif border=0></A></td></tr>\n",
		  myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, domain_network_name);
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<tr><td align=center>"
		  "<IMG SRC=/plugins/rrdPlugin?action=interfaceSummary&amp;key=%s/AS/%s&amp;graphId=1\">\n",
		  myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, domain_network_name);
    sendString(buf);
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "</td><td valign=middle>"
		  "<A HREF=/plugins/rrdPlugin?mode=zoom&action=interfaceSummary&amp;key=%s/AS/%s&amp;graphId=1\">"
		  "<IMG valign=middle class=tooltip SRC=/graph_zoom.gif border=0></A></td></tr>\n",
		  myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, domain_network_name);
    sendString(buf);
    sendString("</table>\n</center>\n");
  } else {
    /* traceEvent(CONST_TRACE_INFO, "'%s' '%d' '%d'", domain_network_name, sortedColumn, revertOrder); */

    if((network_mode == AS_VIEW) && (domain_network_name == NULL)) {
      struct stat statbuf;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/interfaces/%s/AS/numAS.rrd",
		    myGlobals.rrdPath, myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName);

      if((i = stat(buf, &statbuf)) == 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<center>"
		      "<IMG SRC=\"/plugins/rrdPlugin?action=arbreq&which=graph&arbfile=numAS"
		      "&arbiface=%s&start=%u&end=%u&counter=&title=%s\">",
		      myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, 
		      (unsigned int)(myGlobals.actTime-3600),
		      (unsigned int)myGlobals.actTime, "Active+ASs");
	sendString(buf);

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<A HREF=\"/plugins/rrdPlugin?action=arbreq&which=graph&arbfile=numAS&"
		      "arbiface=%s&start=%u&end=%u&counter=&title=%s&mode=zoom\">"
		      "&nbsp;<IMG valign=middle class=tooltip SRC=/graph_zoom.gif border=0></A>",
		      myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, 
		      (unsigned int)(myGlobals.actTime-3600),
		      (unsigned int)myGlobals.actTime, "Active+ASs");
	sendString(buf);


	sendString("</center><p>&nbsp;<p>");
      }
    }

    if(revertOrder) {
      sign = "";
      arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
    } else {
      sign = "-";
      arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
    }

    if((network_mode == NETWORK_VIEW) && (domain_network_name == NULL)) {
      for(i=0; i<myGlobals.numKnownSubnets; i++) {
	statsEntry = &tmpStats[numEntries++];
	memset(statsEntry, 0, sizeof(DomainStats));
	statsEntry->known_subnet_id = i;
	statsEntry->domainHost = NULL;
	stats[i] = statsEntry;
      }
    }

    for(el=getFirstHost(myGlobals.actualReportDeviceId);
	el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
      fillDomainName(el);

      if(network_mode) {
	if(network_mode == NETWORK_VIEW) {
	  if((el->known_subnet_id == UNKNOWN_SUBNET_ID) || (el->known_subnet_id >= myGlobals.numKnownSubnets))
	    continue;
	  else if((domain_network_name != NULL) && (domain_network_name[0] != '\0')) {
	    if(el->known_subnet_id != atoi(domain_network_name))
	      continue;
	  }
	} else {
	  getHostAS(el);
	  if(el->hostAS == 0)
	    continue;
	  else if((domain_network_name != NULL) && (domain_network_name[0] != '\0')) {
	    if(el->hostAS != atoi(domain_network_name))
	      continue;
	  }
	}
      } else {
	/* Community */
	if(communityMode) {
	  if(domain_network_name) {
	    if (el->community == NULL) continue;
	    if(strcmp(el->community, domain_network_name))          continue;
	  }
	  if((el->community) && (!isAllowedCommunity(el->community))) continue;
      } else if(broadcastHost(el))
	  continue;
	else {	  
	  if(domain_network_name && (!communityMode)
	     && el->dnsDomainValue
	     && (strcmp(el->dnsDomainValue, domain_network_name) != 0))
	    continue;

	  if(domain_network_name && (!communityMode)
	     && ((el->dnsDomainValue == NULL)
		 || (el->dnsDomainValue[0] == '\0')
		 || (el->hostResolvedName[0] == '\0')
		 )
	     /*
	       || (el->ip2ccValue == NULL)
	       || (el->ip2ccValue == '\0') 
	     */
	     )
	    continue;
	}
      }
      
      if(domain_network_name == NULL) /* All entries */ {
	if(!communityMode) {
	  if(network_mode == NETWORK_VIEW) {
	    int s = (int)el->known_subnet_id;
	    keyValue = (short)s;
	  } else if(network_mode == AS_VIEW) {
	    keyValue = (el->hostAS % maxHosts);

	    while(stats[keyValue] != NULL) {
	      if(stats[keyValue]->domainHost->hostAS == el->hostAS)
		break;
	      else
		keyValue = (keyValue+1) % maxHosts;
	    }

	    /* traceEvent(CONST_TRACE_INFO, "--> [AS=%d]", el->hostAS); */
	  } else {
	    if(el->dnsDomainValue == NULL) continue;

	    /* Domain */
	    for(keyValue=0, tmpIdx=0; el->dnsDomainValue[tmpIdx] != '\0'; tmpIdx++)
	      keyValue += (tmpIdx+1)*(u_short)el->dnsDomainValue[tmpIdx];

	    keyValue %= maxHosts;

	    while((stats[keyValue] != NULL)
		  && (strcasecmp(stats[keyValue]->domainHost->dnsDomainValue, el->dnsDomainValue) != 0))
	      keyValue = (keyValue+1) % maxHosts;
	  }
	} else {
	  /* Community */
	  u_char found = 0;

	  if(el->hostIpAddress.hostFamily != AF_INET) continue;

	  keyValue = 0;
	all_hosts_community:

	  if(debug) traceEvent(CONST_TRACE_WARNING, "[keyValue=%d][totNumCommunities=%d]",
			       keyValue, totNumCommunities);

	  for(; keyValue<totNumCommunities; keyValue++) {
	    if(__pseudoLocalAddress(&el->hostIpAddress.addr._hostIp4Address,
				    localNetworks[keyValue], numLocalNetworks[keyValue], NULL, NULL)) {
	      found = 1;
	      break;
	    }
	  }

	  if((!found) || (keyValue >= totNumCommunities  /* due to the goto */)) continue;
	}

	if(stats[keyValue] != NULL)
	  statsEntry = stats[keyValue];
	else {
	  statsEntry = &tmpStats[numEntries++];
	  memset(statsEntry, 0, sizeof(DomainStats));

	  if(communityMode)
	    statsEntry->communityName = (char*)communityNames[keyValue];
	  else {
	    if((network_mode == NETWORK_VIEW) && (domain_network_name == NULL) /* All entries */)
	      statsEntry->known_subnet_id = el->known_subnet_id;
	    else
	      statsEntry->known_subnet_id = UNKNOWN_SUBNET_ID;

	    statsEntry->domainHost = el;
	  }

	  stats[keyValue] = statsEntry;
	  // traceEvent(CONST_TRACE_INFO, "[%d] %s/%s", numEntries, el->dnsDomainValue, el->ip2ccValue); 
	}
      } else /* Only the selected items */ {
	/*
	if(communityMode) {
	  if(!__pseudoLocalAddress(&el->hostIpAddress.addr._hostIp4Address,
				   localNetworks[0], numLocalNetworks[0], NULL, NULL))
	    continue;
	}
	*/

	statsEntry = &tmpStats[numEntries++];
	memset(statsEntry, 0, sizeof(DomainStats));
	statsEntry->domainHost = el;
	if(debug) traceEvent(CONST_TRACE_INFO, "--> Adding %s [ptr=%p]", el->hostNumIpAddress, el);
	stats[keyValue++] = statsEntry;
      }

      if(statsEntry->domainHost == NULL) statsEntry->domainHost = el;

      totBytesSent                += el->bytesSent.value;
      statsEntry->bytesSent.value += el->bytesSent.value;
      statsEntry->bytesRcvd.value += el->bytesRcvd.value;
      totBytesRcvd                += el->bytesRcvd.value;
      statsEntry->tcpSent.value   += el->tcpSentLoc.value + el->tcpSentRem.value;
      statsEntry->udpSent.value   += el->udpSentLoc.value + el->udpSentRem.value;
      statsEntry->icmpSent.value  += el->icmpSent.value;
      statsEntry->icmp6Sent.value += el->icmp6Sent.value;
      statsEntry->tcpRcvd.value   += el->tcpRcvdLoc.value + el->tcpRcvdFromRem.value;
      statsEntry->udpRcvd.value   += el->udpRcvdLoc.value + el->udpRcvdFromRem.value;
      statsEntry->icmpRcvd.value  += el->icmpRcvd.value;
      statsEntry->icmp6Rcvd.value += el->icmp6Rcvd.value;

      /* Handle overlapping communitys */
      if(keyValue < (totNumCommunities-1)) {
	keyValue++;
	goto all_hosts_community;
      }

      if(numEntries >= maxHosts) break;
    } /* for(;;) */

    if(numEntries == 0) {
      printNoDataYet();
      free(tmpStats); free(stats);
      goto free_communitys;
      return;
    }

    myGlobals.columnSort = sortedColumn;

    if(debug) traceEvent(CONST_TRACE_WARNING, "qsort(numEntries=%d)", numEntries);

    qsort(tmpStats, numEntries, sizeof(DomainStats), cmpStatsFctn);

    /* avoid division by zero */
    if(totBytesSent == 0)
      totBytesSent = 1;
    if(totBytesRcvd == 0)
      totBytesRcvd = 1;

    /* NOTE: col= must be the last parameter */
    if(domain_network_name == NULL) {
      safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?netmode=%d&col=%s",
		    communityMode ? CONST_COMMUNITIES_STATS_HTML : CONST_DOMAIN_STATS_HTML, network_mode, sign);
      safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?netmode=%d&col=",
		    communityMode ? CONST_COMMUNITIES_STATS_HTML : CONST_DOMAIN_STATS_HTML, network_mode);
    } else {
      safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?dom=%s&netmode=%dcol=%s&",
		    communityMode ? CONST_COMMUNITIES_STATS_HTML : CONST_DOMAIN_STATS_HTML, domain_network_name, network_mode, sign);
      safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?dom=%s&netmode=%d&col=",
		    communityMode ? CONST_COMMUNITIES_STATS_HTML : CONST_DOMAIN_STATS_HTML, domain_network_name, network_mode);
    }

    for(i=0; i<=15; i++)
      if(abs(myGlobals.columnSort) == i)
	arrow[i] = arrowGif, theAnchor[i] = htmlAnchor;
      else
	arrow[i] = "", theAnchor[i] = htmlAnchor1;

    /* Split below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
    sendString("<CENTER>\n" TABLE_ON "<TABLE BORDER=1 "TABLE_DEFAULTS">");

    if((network_mode == AS_VIEW) 
       && ((domain_network_name == NULL) || (domain_network_name[0] == '\0')))
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<TR "TR_ON" "DARK_BG">"
		    "<TH "TH_BG" rowspan=\"3\">%s0>Id%s</A></TH>"
		    "<TH "TH_BG" rowspan=\"3\">Description</TH>"
		    "<TH "TH_BG" rowspan=\"3\">%s1>%s%s</A></TH>"
		    "<TH "TH_BG" colspan=\"8\">TCP/IP</A></TH>"
		    "<TH "TH_BG" colspan=\"4\">ICMP</A></TH>"
		    "<TH "TH_BG">&nbsp;</TH></TR>\n",
		    theAnchor[0], arrow[0],
		    theAnchor[1], "Location",
		    arrow[1]);
    else
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<TR "TR_ON" "DARK_BG">"
		    "<TH "TH_BG" rowspan=\"3\">%s0>Name%s</A></TH>"
		    "<TH "TH_BG" rowspan=\"3\">%s1>%s%s</A></TH>"
		    "<TH "TH_BG" colspan=\"8\">TCP/IP</A></TH>"
		    "<TH "TH_BG" colspan=\"4\">ICMP</A></TH>"
		    "<TH "TH_BG">&nbsp;</TH></TR>\n",
		    theAnchor[0], arrow[0],
		    theAnchor[1], "Location",
		    arrow[1]);

    sendString(buf);

    sendString( "<TR "TR_ON" "DARK_BG">"
		"<TH "TH_BG" colspan=\"4\">Total</A></TH>"
		"<TH "TH_BG" colspan=\"2\">TCP</A></TH>"
		"<TH "TH_BG" colspan=\"2\">UDP</A></TH>"
		"<TH "TH_BG" colspan=\"2\">IPv4</A></TH>"
		"<TH "TH_BG" colspan=\"2\">IPv6</A></TH>"
		"<TH "TH_BG">Graphs</TH>\n"
		"</TR>\n");

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<TR "TR_ON" "DARK_BG">"
		  "<TH "TH_BG" colspan=\"2\">%s2>Sent%s</A></TH>"
		  "<TH "TH_BG" colspan=\"2\">%s3>Rcvd%s</A></TH>"
		  "<TH "TH_BG">%s4>Sent%s</A></TH>"
		  "<TH "TH_BG">%s5>Rcvd%s</A></TH>"
		  "<TH "TH_BG">%s6>Sent%s</A></TH>"
		  "<TH "TH_BG">%s7>Rcvd%s</A></TH>"
		  "<TH "TH_BG">%s8>Sent%s</A></TH>"
		  "<TH "TH_BG">%s9>Rcvd%s</A></TH>"
		  "<TH "TH_BG">%s10>Sent%s</A></TH>"
		  "<TH "TH_BG">%s11>Rcvd%s</A></TH>"
		  "<TH "TH_BG">&nbsp;</TH>"
		  "</TR>\n",
		  theAnchor[2], arrow[2],
		  theAnchor[3], arrow[3],
		  theAnchor[4], arrow[4],
		  theAnchor[5], arrow[5],
		  theAnchor[6], arrow[6],
		  theAnchor[7], arrow[7],
		  theAnchor[8], arrow[8],
		  theAnchor[9], arrow[9],
		  theAnchor[10], arrow[10],
		  theAnchor[11], arrow[11]);
    sendString(buf);

    for(idx=pageNum*myGlobals.runningPref.maxNumLines; idx<numEntries; idx++) {
      char sym_as_name[256];
      struct stat statbuf;

      if(revertOrder)
	statsEntry = &tmpStats[numEntries-idx-1];
      else
	statsEntry = &tmpStats[idx];

      if(domain_network_name == NULL) {
	if(network_mode == NETWORK_VIEW) {
	  char *nw_name;
	  char sym_nw_name[256];

	  nw_name = subnetId2networkName(statsEntry->known_subnet_id, buf1, sizeof(buf1));
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "network.name.%s", nw_name);

	  if(fetchPrefsValue(buf, sym_nw_name, sizeof(sym_nw_name)) == -1) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "subnet.name.%s", nw_name);
	    if(fetchPrefsValue(buf, sym_nw_name, sizeof(sym_nw_name)) == -1)
	      sym_nw_name[0] = '\0';
	  }

	  if(statsEntry->domainHost)
	    safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor),
			  "<A HREF=/%s?dom=%d&netmode=%d>%s%s%s%s</A>",
			  CONST_DOMAIN_STATS_HTML, statsEntry->known_subnet_id,
			  network_mode,
			  nw_name,
			  (sym_nw_name[0] == '\0') ? "" : " [",
			  sym_nw_name,
			  (sym_nw_name[0] == '\0') ? "" : "]");
	  else {
	    /* No traffic yet for this subnet */
	    safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor),
			  "%s%s%s%s",
			  nw_name,
			  (sym_nw_name[0] == '\0') ? "" : " [",
			  sym_nw_name,
			  (sym_nw_name[0] == '\0') ? "" : "]");
	  }
	} else if(network_mode == AS_VIEW) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "as.name.%d",
			statsEntry->domainHost->hostAS);

	  if(fetchPrefsValue(buf, sym_as_name, sizeof(sym_as_name)) != -1)
	    ;	    
	  else if(statsEntry->domainHost->hostASDescr != NULL)
	    snprintf(sym_as_name, sizeof(sym_as_name), "%s", statsEntry->domainHost->hostASDescr);
	  else
	    snprintf(sym_as_name, sizeof(sym_as_name), "No Info");

	  safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor),
			"<A HREF=/%s?dom=%d&netmode=%d>%d</A></TH><TD "TD_BG" ALIGN=RIGHT>%s",
			CONST_DOMAIN_STATS_HTML, statsEntry->domainHost->hostAS, network_mode,
			statsEntry->domainHost->hostAS, sym_as_name);
	} else
	  safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?dom=%s>%s</A>",
			communityMode ? CONST_COMMUNITIES_STATS_HTML : CONST_DOMAIN_STATS_HTML,
			communityMode ? statsEntry->communityName : statsEntry->domainHost->dnsDomainValue,
			communityMode ? statsEntry->communityName : statsEntry->domainHost->dnsDomainValue);
      } else {
	char *hostLink;
	u_int len;

#if 0
	int blankId;
	char tmpBuf[64];

	if(statsEntry->domainHost) {
	  blankId = strlen(statsEntry->domainHost->hostResolvedName)-1;
	  
	  if(statsEntry->domainHost->dnsDomainValue != NULL)
	    blankId -= strlen(statsEntry->domainHost->dnsDomainValue);

	  strncpy(tmpBuf, statsEntry->domainHost->hostResolvedName, sizeof(tmpBuf));

	  if((blankId > 0) && (strcmp(&tmpBuf[blankId+1], domain_network_name) == 0))
	    tmpBuf[blankId] = '\0';
	}
#endif

	if(network_mode == AS_VIEW) {
	  makeHostLink(statsEntry->domainHost, FLAG_HOSTLINK_TEXT_FORMAT, 0,
		       0, htmlAnchor, sizeof(htmlAnchor));
	} else {
	  hostLink = makeHostLink(statsEntry->domainHost, FLAG_HOSTLINK_TEXT_FORMAT, 1,
				  0, hostLinkBuf, sizeof(hostLinkBuf));

	  len = strlen(hostLink); if(len >= sizeof(htmlAnchor)) len = sizeof(htmlAnchor)-1;
	  strncpy(htmlAnchor, hostLink, len);
	  htmlAnchor[len] = '\0';
	}
      }

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		    "<TH "TH_BG" ALIGN=LEFT "DARK_BG">%s%s<TD "TD_BG" ALIGN=CENTER>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%%</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%%</TD>",
		    getRowColor(), htmlAnchor, (network_mode == AS_VIEW) ? "</TD>" : "</TH>",
		    ((communityMode && (!domain_network_name)) || (!statsEntry->domainHost)) ?
		    "&nbsp;" : getHostCountryIconURL(statsEntry->domainHost),
		    formatBytes(statsEntry->bytesSent.value, 1, formatBuf, sizeof(formatBuf)),
		    (100*((float)statsEntry->bytesSent.value/(float)totBytesSent)),
		    formatBytes(statsEntry->bytesRcvd.value, 1, formatBuf1, sizeof(formatBuf1)),
		    (100*((float)statsEntry->bytesRcvd.value/(float)totBytesRcvd)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		    formatBytes(statsEntry->tcpSent.value, 1, formatBuf2, sizeof(formatBuf2)),
		    formatBytes(statsEntry->tcpRcvd.value, 1, formatBuf3, sizeof(formatBuf3)),
		    formatBytes(statsEntry->udpSent.value, 1, formatBuf4, sizeof(formatBuf4)),
		    formatBytes(statsEntry->udpRcvd.value, 1, formatBuf5, sizeof(formatBuf5)),
		    formatBytes(statsEntry->icmpSent.value, 1, formatBuf6, sizeof(formatBuf6)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		    formatBytes(statsEntry->icmpRcvd.value, 1, formatBuf7, sizeof(formatBuf7)),
		    formatBytes(statsEntry->icmp6Sent.value, 1, formatBuf8, sizeof(formatBuf8)),
		    formatBytes(statsEntry->icmp6Rcvd.value, 1, formatBuf9, sizeof(formatBuf9)));
      sendString(buf);

      if(sym_as_name[0] != '\0')
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/interfaces/%s/AS/%s",
		      myGlobals.rrdPath, myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
		      sym_as_name);

      if((sym_as_name[0] != '\0') && ((i = stat(buf, &statbuf)) == 0)) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=CENTER><A HREF=\"/%s?netmode=%d&dom=%s\">"
		      "<img class=tooltip valign=top border=0 src=/graph.gif></A></TD></TR>\n",
		      CONST_DOMAIN_STATS_HTML, AS_GRAPH_VIEW, sym_as_name);
	sendString(buf);
      } else if(communityMode && statsEntry && statsEntry->communityName) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=CENTER><A HREF=\"/" CONST_PLUGINS_HEADER "rrdPlugin?action=list&community=%s\">"
		      "<img class=tooltip valign=top border=0 src=/graph.gif></A></TD></TR>\n",
		      statsEntry->communityName);
	sendString(buf);
      } else if((network_mode == NETWORK_VIEW) 
		&& ((statsEntry->domainHost != NULL)
		    || (domain_network_name == NULL))) {
	char rrdBuf[LEN_GENERAL_WORK_BUFFER];
	HostTraffic dummy;
	
	if(statsEntry->domainHost == NULL) {
	  statsEntry->domainHost = &dummy;
	  memset(&dummy, 0, sizeof(dummy));
	  dummy.known_subnet_id = statsEntry->known_subnet_id;
	}

	hostRRdGraphLink(statsEntry->domainHost, network_mode,
			 (domain_network_name == NULL) ? 1 : 0,
			 rrdBuf, sizeof(rrdBuf));
	sendString("<TD "TD_BG" ALIGN=CENTER>");

	if(rrdBuf[0] != '\0')
	  sendString(rrdBuf);
	else
	  sendString("&nbsp;");

	sendString("</TD>\n");
      } else {
	/* traceEvent(CONST_TRACE_WARNING, "--> hostRRdGraphLink(%d)", network_mode); */
	sendString("<TD "TD_BG" ALIGN=CENTER>&nbsp;</TD>\n");
      }

      /* Avoid huge tables */
      if(printedEntries++ > myGlobals.runningPref.maxNumLines)
	break;
    }

    sendString("</TABLE>"TABLE_OFF"</HTML>\n");
    sendString("</CENTER>\n");

    if(domain_network_name != NULL) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s?dom=%s",
		    communityMode ? CONST_COMMUNITIES_STATS_HTML : CONST_DOMAIN_STATS_HTML, domain_network_name);
    } else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
		    communityMode ? CONST_COMMUNITIES_STATS_HTML : CONST_DOMAIN_STATS_HTML);
    }

    addPageIndicator(buf, pageNum, numEntries,
		     myGlobals.runningPref.maxNumLines,
		     revertOrder, abs(sortedColumn), network_mode);

    if(!communityMode) {
      sendString("<p align=\"center\"><b>NOTE</b>: ");
      if(network_mode == NETWORK_VIEW)
	sendString("<small>You can define networks using the --known-subnets flag. Networks with no traffic/hosts do not have a hyperlink associated.</small>\n");
      else if(network_mode == AS_VIEW)
	sendString("<small>AS numbers are either received via monitoring protocols (e.g. NetFlow) or read from the AS-list ntop configuration file.</small>");
      else
	sendString("<small>The domain is determined by simply stripping off "
		   "the first name, so for host x.yz.com, the domain is yz.com and for host "
		   "x.y.z.com, the domain is y.z.com.</small></p>\n");
    } else {
      sendString("<p align=\"center\"><b>NOTE</b>: <small>You can define host communitys in the ntop <A HREF=/"CONST_EDIT_PREFS">preferences</A>. "
		 "Please understand that a host community is an aggregated view of hosts known to ntop.</small></p>\n");
    }

    free(tmpStats); free(stats);

  free_communitys:
    for(i=0; i<totNumCommunities; i++)
      if(communityNames[i] != NULL) free(communityNames[i]);
  }
}

/* ************************* */

void printNoDataYet(void) {
  printFlagedWarning("<I>No Data To Display (yet)</I>");
}

/* ************************* */

void printNotAvailable(char * flagName) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<I>The requested data is not available when ntop is"
		"<br>started with the command line flag %s</I>",
		flagName);
  printFlagedWarning(buf);
}

/* ************************* */

void listNetFlows(void) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  int numEntries=0;
  FlowFilterList *list = myGlobals.flowsList;
  char formatBuf[32], formatBuf1[32];

  printHTMLheader(NULL, NULL, 0);

  if(list != NULL) {
    while(list != NULL) {
      if(list->pluginStatus.activePlugin) {
	if(numEntries == 0) {
	  printSectionTitle("Network Flows");
 	  sendString("<CENTER>\n");
	  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON" "DARK_BG"><TH "TH_BG">Flow Name</TH>"
  		     "<TH "TH_BG">Packets</TH><TH "TH_BG">Traffic</TH></TR>");
  	}

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>%s"
		      "</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		      getRowColor(), list->flowName,
		      formatPkts(list->packets.value, formatBuf, sizeof(formatBuf)),
		      formatBytes(list->bytes.value, 1, formatBuf1, sizeof(formatBuf1)));
	sendString(buf);

	numEntries++;
      }

      list = list->next;
    }

    if(numEntries > 0)
      sendString("</TABLE>"TABLE_OFF"\n");

    sendString("</CENTER>\n");
  }

  sendString("<p align=left><b>NOTE</b>: Network flows have <u>no relation at all</u> with NetFlow/sFlow protocols.</p>\n");

  if(numEntries == 0) {
    sendString("<CENTER><P><H1>No Available/Active Network Flows</H1><p>"
	       " (see <A HREF=" CONST_MAN_NTOP_HTML ">man</A> page)</CENTER>\n");
  }
}

/* *********************************** */

void printHostHourlyTraffic(HostTraffic *el) {
  Counter tcSent, tcRcvd;
  int i, hourId, j;
  char theDate[8], macAddr[24], vlanStr[32];
  struct tm t;
  char buf[LEN_GENERAL_WORK_BUFFER], *targetStr;
  char hours[][24] = {"12 AM", "1 AM", "2 AM", "3 AM", "4 AM", "5 AM", "6 AM",
		      "7 AM", "8 AM", "9 AM", "10 AM", "11 AM", "12 PM", "1 PM",
		      "2 PM", "3 PM", "4 PM", "5 PM", "6 PM", "7 PM", "8 PM",
		      "9 PM", "10 PM", "11 PM"};

  if(el->trafficDistribution == NULL) return;

  strftime(theDate, 8, CONST_TOD_HOUR_TIMESPEC, localtime_r(&myGlobals.actTime, &t));
  hourId = atoi(theDate);

  /* In FC, where traffic is mostly storage traffic, the word "host" has a
   * specific meaning (SCSI Initiator) and so we distinguish the title for
   * FC_Ports
   */
  if(isFcHost (el)) {
    printSectionTitle("FibreChannel Port Traffic Stats");
  } else {
    printSectionTitle("Host Traffic Stats");
  }

  sendString("<CENTER>\n");
  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"80%\">\n<TR "TR_ON" "DARK_BG">");
  sendString("<TH "TH_BG">Time</TH>");
  sendString("<TH "TH_BG">Tot. Traffic Sent</TH>");
  sendString("<TH "TH_BG">% Traffic Sent</TH>");
  sendString("<TH "TH_BG">Tot. Traffic Rcvd</TH>");
  sendString("<TH "TH_BG">% Traffic Rcvd</TH></TR>");

  for(i=0, tcSent=0, tcRcvd=0; i<24; i++) {
    tcSent += el->trafficDistribution->last24HoursBytesSent[i].value;
    tcRcvd += el->trafficDistribution->last24HoursBytesRcvd[i].value;
  }

  for (i = 0, j = hourId; i < 24; i++) {
    j = j%24;
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=RIGHT "DARK_BG">%s</TH>\n", hours[j]);
    sendString(buf);
    printHostHourlyTrafficEntry(el, j, tcSent, tcRcvd);
    if(!j)
      j = 23;
    else
      j--;
  }

  sendString("<TR "TR_ON"><TH "TH_BG" "DARK_BG">Total</TH>\n");

  if(isFcHost (el)) {
    targetStr = el->fcCounters->hostNumFcAddress;
  }
  else {
    safe_snprintf(__FILE__, __LINE__, macAddr, sizeof(macAddr), "%s", el->ethAddressString);
    targetStr = el->hostNumIpAddress[0] == '\0' ?  macAddr : el->hostNumIpAddress;
  }

  urlFixupToRFC1945Inplace(targetStr);

  if(el->vlanId > 0) {
    safe_snprintf(__FILE__, __LINE__, vlanStr, sizeof(vlanStr), "-%d", el->vlanId);
  } else
    vlanStr[0] = '\0';

  if(tcSent > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<TD ALIGN=CENTER COLSPAN=2 "TD_BG" BGCOLOR=white>"
		  "<iframe frameborder=0 SRC=\"/hostTimeTrafficDistribution-%s%s"CHART_FORMAT"?1\" width=400 height=250></iframe></TD>\n",
		  targetStr, vlanStr);
    sendString(buf);
  } else
    sendString("<TD COLSPAN=2 "TD_BG">&nbsp;</TD>\n");

  if(tcRcvd > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD ALIGN=CENTER COLSPAN=2 "TD_BG" BGCOLOR=white>"
		  "<iframe frameborder=0 SRC=\"/hostTimeTrafficDistribution-%s%s"CHART_FORMAT"\" width=400 height=250></iframe>"
		  "</TD>\n",
		  targetStr, vlanStr);
    sendString(buf);
  } else
    sendString("<TD COLSPAN=2 "TD_BG">&nbsp;</TD>\n");

  sendString("</TR>\n");

  sendString("</TABLE>"TABLE_OFF"\n</CENTER>\n");
}

/* ************************** */

static void dumpHostsCriteria(NtopInterface *ifName, u_char criteria) {
  u_int numEntries=0, i, maxHosts;
  HostTraffic **tmpTable, *el;
  char buf[LEN_GENERAL_WORK_BUFFER];
  char formatBuf[32], formatBuf1[32], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];

  maxHosts = ifName->hostsno; /* save it as it can change */

  tmpTable = (HostTraffic**)mallocAndInitWithReportWarn(maxHosts*sizeof(HostTraffic*), "dumpHostsCriteria");
  if(tmpTable == NULL)
    return;

  switch(criteria) {
  case 1: /* VLAN */
    myGlobals.columnSort = CONST_VLAN_COLUMN_SORT;
    break;
  }

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(el->community && (!isAllowedCommunity(el->community))) continue;
    switch(criteria) {
    case 1: /* VLAN */
      if(el->vlanId > 0)  tmpTable[numEntries++] = el;
      break;
    }

    if(numEntries >= maxHosts)
      break;
  }

  if(numEntries > 0) {
    int lastId = 0;
    Counter dataSent, dataRcvd;

    qsort(tmpTable, numEntries, sizeof(HostTraffic*), sortHostFctn);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<CENTER>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n"
		  "<TR "TR_ON" "DARK_BG">"
		  "<TH "TH_BG">%s</A></TH>\n"
		  "<TH "TH_BG">Hosts</TH>\n"
		  "<TH "TH_BG">Data Sent</TH>\n"
		  "<TH "TH_BG">Data Rcvd</TH></TR>\n",
		  "VLAN");
    sendString(buf);

    dataSent = dataRcvd = 0;

    for(i=0; i<numEntries; i++) {
      el = tmpTable[numEntries-i-1];

      if((criteria == 1) && (lastId == el->vlanId)) {
        /* Same VLAN as last entry... just continue it */
        sendString("\n<br>");
      } else {
        /* New VLAN */

        if(i > 0) {
          /* Finish prior row */
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n"
			"</TR>\n",
			formatBytes(dataSent, 1, formatBuf, sizeof(formatBuf)),
			formatBytes(dataRcvd, 1, formatBuf1, sizeof(formatBuf1)));
	  sendString(buf);
        }

        /* Start new row */
	dataSent = dataRcvd = 0;

        sendString("<TR "TR_ON">\n");

	lastId = el->vlanId;
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TH "TH_BG" ALIGN=RIGHT>%d</TH>\n",
		      el->vlanId);
        sendString(buf);

        sendString("<TH "TH_BG" ALIGN=LEFT>");

      }

      sendString(makeHostLink(el, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
                              hostLinkBuf, sizeof(hostLinkBuf)));

      dataSent += el->bytesSent.value;
      dataRcvd += el->bytesRcvd.value;
    }

    if(i>0) {
      sendString("</TH>\n");

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		    formatBytes(dataSent, 1, formatBuf, sizeof(formatBuf)),
		    formatBytes(dataRcvd, 1, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);
    }

    sendString("</TR>\n</TABLE>\n</CENTER>");

  } else {
    printFlagedWarning("<I>No entries to display(yet)</I>");
  }

  free(tmpTable);
}

/* ******************************* */

void printVLANList(unsigned int deviceId) {
  printHTMLheader("VLAN Traffic Statistics", NULL, 0);

  if(deviceId > myGlobals.numDevices) {
    printFlagedWarning("<I>Invalid device specified</I>");
    return;
  }

  if(myGlobals.haveVLANs == FALSE) {
    printFlagedWarning("<I>No VLANs found (yet)</I>");
    return;
  }

  dumpHostsCriteria(&myGlobals.device[deviceId], 1 /* VLAN */);
}

/* ******************************************* */

static int recentlyUsedPort(HostTraffic *el, int portNr, int serverPort) {
  int i;

  if(el == NULL) return(0);

  for(i=0; i<MAX_NUM_RECENT_PORTS; i++) {
    if(serverPort) {
      if(el->recentlyUsedServerPorts[i] == portNr)
	return(1);
    } else {
      if(el->recentlyUsedClientPorts[i] == portNr)
	return(1);
    }
  }

  return(0);
}

/* ******************************************* */

void showPortTraffic(u_short portNr) {
  char buf[LEN_GENERAL_WORK_BUFFER], *str;
  int numRecords = 0, firstRun = 1;
  HostTraffic *el;
  char portBuf[32], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];

  str = getAllPortByNum(portNr, portBuf, sizeof(portBuf));

  if((str[0] == '?') || (atoi(str) == portNr)) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Recent Users of Port %u", portNr);
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Recent Users of Port %u (%s)", portNr, str);
  }

  printHTMLheader(buf, NULL, 0);
  sendString("<CENTER>\n");

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {

    if(el->community && (!isAllowedCommunity(el->community))) continue;

  recentlyUsedPortSent:
    if(recentlyUsedPort(el, portNr, 0)) {
      if(numRecords == 0) {
	sendString("<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "DARK_BG"><TH>Client</TH><TH>Server</TH></TR>\n");
	sendString("<TR>\n<TD nowrap><ul>\n");
      }

      sendString("\n<LI> ");
      sendString(makeHostLink(el, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)));
      numRecords++;
    }

    if(el == myGlobals.broadcastEntry) break;
  }

  if(firstRun) {
    firstRun=0;
    el = myGlobals.broadcastEntry;
    goto recentlyUsedPortSent;
  }

  firstRun = 1;

  if(numRecords > 0) {
    sendString("\n&nbsp;\n</ul></TD><TD nowrap><ul>\n");
  }

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(el->community && (!isAllowedCommunity(el->community))) continue;

  recentlyUsedPortRcvd:
    if(recentlyUsedPort(el, portNr, 1)) {
      if(numRecords == 0) {
	sendString("<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "DARK_BG"><TH>Client</TH><TH>Server</TH></TR>\n");
	sendString("<TR>\n<TD>\n");
	sendString("\n&nbsp;\n</TD><TD nowrap><ul>\n");
      }

      sendString("\n<LI> ");
      sendString(makeHostLink(el, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)));
      numRecords++;
    }

    if(el == myGlobals.broadcastEntry) break;
  }


  if(firstRun) {
    firstRun = 0;
    el = myGlobals.broadcastEntry;
    goto recentlyUsedPortRcvd;
  }

  if(numRecords == 0) {
    safe_snprintf(__FILE__, __LINE__, hostLinkBuf, sizeof(hostLinkBuf),
		  "<P>No hosts found: the information for this port "
		  "has been purged in the meantime <br>"
		  "as each host keeps the last %d server/client ports only.</CENTER><P>\n",
		  MAX_NUM_RECENT_PORTS);

    sendString(hostLinkBuf);
  } else
    sendString("\n&nbsp;\n</ul></TD>\n</TR>\n</TABLE>\n</CENTER>");

}

/* ******************************************* */

void printFcHostsTraffic(int reportType,
                         int sortedColumn,
                         int revertOrder,
                         int pageNum,
                         char* url,
                         LocalityDisplayPolicy showLocalityMode) {
  u_int idx, numEntries=0, maxHosts, whatToDo;
  int printedEntries=0, hourId;
  char theDate[8];
  struct tm t;
  HostTraffic *el;
  HostTraffic** tmpTable;
  char buf[LEN_GENERAL_WORK_BUFFER], formatBuf[8][32], vsanBuf[LEN_MEDIUM_WORK_BUFFER];
  char hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  float sentPercent=0, rcvdPercent=0, totPercent=0;
  Counter totFcBytesSent=0, totFcBytesRcvd=0, totFcBytes=0;

  memset(buf, 0, sizeof(buf));
  switch(reportType) {
  case SORT_FC_ACTIVITY:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "FibreChannel Activity");
    myGlobals.reportKind = SORT_DATA_HOST_TRAFFIC;
    showLocalityMode = 0;
    break;
  case SORT_FC_DATA:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "FibreChannel Traffic: ");
    break;
  case SORT_FC_THPT:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "FibreChannel Throughput: ");
    break;
  default:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "?? %d : ", reportType);
    break;
  }

  if(reportType != SORT_FC_ACTIVITY) {
    switch(showLocalityMode) {
    case showSentReceived:
      strncat(buf, "Data Sent+Received", sizeof(buf) - strlen(buf) - 1);
      myGlobals.reportKind = (reportType == SORT_FC_DATA) ?
	SORT_DATA_PROTOS : SORT_DATA_THPT;
      break;
    case showOnlySent:
      strncat(buf, "Data Sent", sizeof(buf) - strlen(buf) - 1);
      myGlobals.reportKind = (reportType == SORT_FC_DATA) ?
	SORT_DATA_SENT_PROTOS : SORT_DATA_SENT_THPT;
      break;
    case showOnlyReceived:
      strncat(buf, "Data Received", sizeof(buf) - strlen(buf) - 1);
      myGlobals.reportKind = (reportType == SORT_FC_DATA) ?
	SORT_DATA_RECEIVED_PROTOS : SORT_DATA_RECEIVED_THPT;
      break;
    }
  }
  printHTMLheader(buf, 0, 0);

  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */

  tmpTable =  (HostTraffic**)mallocAndInitWithReportWarn(myGlobals.device[myGlobals.actualReportDeviceId].
							 actualHashSize*sizeof(HostTraffic*), "printFcHostsTraffic");
  if(tmpTable == NULL)
    return;

  strftime(theDate, 8, CONST_TOD_HOUR_TIMESPEC, localtime_r(&myGlobals.actTime, &t));
  hourId = atoi(theDate);

  for (el = getFirstHost (myGlobals.actualReportDeviceId);
       el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {

    if(el->community && (!isAllowedCommunity(el->community))) continue;
    if(isFcHost (el)) {
      /* Skip Control VSAN traffic */
      if(el->fcCounters->vsanId > MAX_USER_VSAN) continue;

      if(((showLocalityMode == showOnlySent) && (el->fcCounters->fcBytesSent.value > 0))
	 || ((showLocalityMode == showOnlyReceived) && (el->fcCounters->fcBytesRcvd.value > 0))
	 || ((showLocalityMode == showSentReceived) && ((el->fcCounters->fcBytesSent.value > 0) ||
							(el->fcCounters->fcBytesRcvd.value > 0)))) {
	tmpTable[numEntries++]=el;

	if(numEntries >= maxHosts)
	  break;
      }
    }
  }

  if(numEntries <= 0) {
    printNoDataYet();
    free(tmpTable);
    return;
  }

  if(reportType != SORT_FC_ACTIVITY) {
    switch(showLocalityMode) {
    case showSentReceived:
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<p align=\"right\">"
		    "[<b> All </b>]&nbsp;"
		    "[ <a href=\"%s?col=%s%d&showL=1\">Sent Only</a> ]&nbsp;"
		    "[ <a href=\"%s?col=%s%d&showL=2\">Received Only</a> ]&nbsp;</p>",
		    url, revertOrder ? "-" : "", sortedColumn,
		    url, revertOrder ? "-" : "", sortedColumn);
      break;
    case showOnlySent:
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<p align=\"right\">"
		    "[ <a href=\"%s?col=%s%d&showH=%d&showL=0\">All</a> ]&nbsp;"
		    "[<b> Sent Only </b>]&nbsp;"
		    "[ <a href=\"%s?col=%s%d&showH=%d&showL=2\">Received Only</a> ]&nbsp;</p>",
		    url, revertOrder ? "-" : "", sortedColumn, showLocalityMode,
		    url, revertOrder ? "-" : "", sortedColumn, showLocalityMode);
      break;
    default:
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<p align=\"right\">"
		    "[ <a href=\"%s?col=%s%d&showH=%d&showL=0\">All</a> ]&nbsp;"
		    "[ <a href=\"%s?col=%s%d&showH=%d&showL=1\">Sent Only</a> ]&nbsp;"
		    "[<b> Received Only </b>]&nbsp;</p>",
		    url, revertOrder ? "-" : "", sortedColumn, showLocalityMode,
		    url, revertOrder ? "-" : "", sortedColumn, showLocalityMode);
      break;
    }
    sendString(buf);
  }

  printFcHeader(reportType, revertOrder, abs(sortedColumn), hourId, url);

  myGlobals.columnSort = sortedColumn;

#ifdef FC_DEBUG
  traceEvent(CONST_TRACE_INFO, "FC_DEBUG: reportType=%d/sortedColumn=%d/myGlobals.columnSort=%d",
	     reportType, sortedColumn, myGlobals.columnSort);
#endif

  qsort(tmpTable, numEntries, sizeof(HostTraffic*), cmpFcFctn);

  totFcBytesSent = totFcBytesRcvd = totFcBytes = 0;

  for(idx=0; idx<numEntries; idx++) {
    if(tmpTable[idx] != NULL) {
      /* Count 'em both - not worth the IFs */
      totFcBytesSent += tmpTable[idx]->fcCounters->fcBytesSent.value;
      totFcBytesRcvd += tmpTable[idx]->fcCounters->fcBytesRcvd.value;
      switch(showLocalityMode) {
      case showSentReceived:
	totFcBytes += tmpTable[idx]->fcCounters->fcBytesSent.value +
	  tmpTable[idx]->fcCounters->fcBytesRcvd.value;
	break;
      case showOnlySent:
	totFcBytes += tmpTable[idx]->fcCounters->fcBytesSent.value;
	break;
      case showOnlyReceived:
	totFcBytes += tmpTable[idx]->fcCounters->fcBytesRcvd.value;
	break;
      }
    }
  }

  /* Avoid core dumps */
  if(totFcBytesSent == 0) totFcBytesSent = 1;
  if(totFcBytesRcvd == 0) totFcBytesRcvd = 1;
  if(totFcBytes == 0)     totFcBytes = 1;

#ifdef FC_DEBUG
  traceEvent(CONST_TRACE_INFO, "FC_DEBUG: totIpBytesSent=%u, totIpBytesRcvd=%u totIpBytes=%u",
	     totFcBytesSent, totFcBytesRcvd, totFcBytes);
#endif

  for(idx=pageNum*myGlobals.runningPref.maxNumLines; idx<numEntries; idx++) {
    char webHostName[LEN_GENERAL_WORK_BUFFER];

    if(revertOrder)
      el = tmpTable[numEntries-idx-1];
    else
      el = tmpTable[idx];

    if(el != NULL) {
      sentPercent = (100*(float)el->fcCounters->fcBytesSent.value)/totFcBytesSent;
      rcvdPercent = (100*(float)el->fcCounters->fcBytesRcvd.value)/totFcBytesRcvd;
      totPercent = (100*(float) (el->fcCounters->fcBytesSent.value + el->fcCounters->fcBytesRcvd.value) )/totFcBytes;

      strncpy(webHostName,
	      makeFcHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0,
			     hostLinkBuf, sizeof(hostLinkBuf)),
	      sizeof(webHostName));

      /* We have two reports x three data breakdowns + activity...
	 cheat and create a number for a 1d switch() 100*Locality + SORT_FC
	 precise formula is irrelevant, as long as it's unique...
      */
      whatToDo = 100*showLocalityMode + reportType;

      switch(whatToDo) {
      case (100*showSentReceived + SORT_FC_DATA):
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
                      "%s%s"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      getRowColor(),
                      makeVsanLink (el->fcCounters->vsanId, FLAG_HOSTLINK_HTML_FORMAT,
                                    vsanBuf, sizeof(vsanBuf)),
                      webHostName,
		      formatBytes(el->fcCounters->fcBytesSent.value     +el->fcCounters->fcBytesRcvd.value,      1, formatBuf[1], 32),
                      totPercent, myGlobals.separator,
                      formatBytes(el->fcCounters->fcFcpBytesSent.value  +el->fcCounters->fcFcpBytesRcvd.value,   1, formatBuf[2], 32),
		      formatBytes(el->fcCounters->fcElsBytesSent.value  +el->fcCounters->fcElsBytesRcvd.value,   1, formatBuf[3], 32),
		      formatBytes(el->fcCounters->fcDnsBytesSent.value  +el->fcCounters->fcDnsBytesRcvd.value,   1, formatBuf[4], 32),
                      formatBytes(el->fcCounters->fcIpfcBytesSent.value +el->fcCounters->fcIpfcBytesRcvd.value,  1, formatBuf[5], 32),
                      formatBytes(el->fcCounters->fcSwilsBytesSent.value+el->fcCounters->fcSwilsBytesRcvd.value, 1, formatBuf[6], 32),
                      formatBytes(el->fcCounters->otherFcBytesSent.value+el->fcCounters->otherFcBytesRcvd.value, 1, formatBuf[7], 32));
	break;
      case (100*showOnlySent + SORT_FC_DATA):
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
                      "%s%s"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      getRowColor(),
                      makeVsanLink (el->fcCounters->vsanId, FLAG_HOSTLINK_HTML_FORMAT,
                                    vsanBuf, sizeof(vsanBuf)),
                      webHostName,
		      formatBytes(el->fcCounters->fcBytesSent.value, 1, formatBuf[1], 32),
                      sentPercent, myGlobals.separator,
                      formatBytes(el->fcCounters->fcFcpBytesSent.value, 1, formatBuf[2], 32),
		      formatBytes(el->fcCounters->fcElsBytesSent.value, 1, formatBuf[3], 32),
		      formatBytes(el->fcCounters->fcDnsBytesSent.value, 1, formatBuf[4], 32),
                      formatBytes(el->fcCounters->fcIpfcBytesSent.value, 1, formatBuf[5], 32),
                      formatBytes(el->fcCounters->fcSwilsBytesSent.value, 1, formatBuf[6], 32),
                      formatBytes(el->fcCounters->otherFcBytesSent.value, 1, formatBuf[7], 32));
	break;
      case (100*showOnlyReceived + SORT_FC_DATA):
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
                      "%s%s"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      getRowColor(),
                      makeVsanLink (el->fcCounters->vsanId, FLAG_HOSTLINK_HTML_FORMAT, vsanBuf,
                                    sizeof(vsanBuf)),
                      webHostName,
                      formatBytes(el->fcCounters->fcBytesRcvd.value, 1, formatBuf[1], 32),
		      rcvdPercent, myGlobals.separator,
		      formatBytes(el->fcCounters->fcFcpBytesRcvd.value, 1, formatBuf[2], 32),
		      formatBytes(el->fcCounters->fcElsBytesRcvd.value, 1, formatBuf[3], 32),
		      formatBytes(el->fcCounters->fcDnsBytesRcvd.value, 1, formatBuf[4], 32),
                      formatBytes(el->fcCounters->fcIpfcBytesRcvd.value, 1, formatBuf[5], 32),
                      formatBytes(el->fcCounters->fcSwilsBytesRcvd.value, 1, formatBuf[6], 32),
                      formatBytes(el->fcCounters->otherFcBytesRcvd.value, 1, formatBuf[7], 32));
	break;
      case (100*showSentReceived + SORT_FC_THPT):
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		      "%s%s"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>",
		      getRowColor(),
		      makeVsanLink (el->fcCounters->vsanId, FLAG_HOSTLINK_HTML_FORMAT,
				    vsanBuf, sizeof(vsanBuf)),
		      webHostName,
		      formatThroughput(el->actualTThpt, 1, formatBuf[0], 32),
		      formatThroughput(el->averageTThpt, 1, formatBuf[1], 32),
		      formatThroughput(el->peakTThpt, 1, formatBuf[2], 32),
		      el->actualTPktThpt,
		      el->averageTPktThpt,
		      el->peakTPktThpt);
	break;
      case (100*showOnlySent + SORT_FC_THPT):
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		      "%s%s"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>",
		      getRowColor(),
		      makeVsanLink (el->fcCounters->vsanId, FLAG_HOSTLINK_HTML_FORMAT,
				    vsanBuf, sizeof(vsanBuf)),
		      webHostName,
		      formatThroughput(el->actualSentThpt, 1, formatBuf[0], 32),
		      formatThroughput(el->averageSentThpt, 1, formatBuf[1], 32),
		      formatThroughput(el->peakSentThpt, 1, formatBuf[2], 32),
		      el->actualSentPktThpt,
		      el->averageSentPktThpt,
		      el->peakSentPktThpt);
	break;
      case (100*showOnlyReceived + SORT_FC_THPT):
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		      "%s%s"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkt/s</TD>",
		      getRowColor(),
		      makeVsanLink (el->fcCounters->vsanId, FLAG_HOSTLINK_HTML_FORMAT,
				    vsanBuf, sizeof(vsanBuf)),
		      webHostName,
		      formatThroughput(el->actualRcvdThpt, 1, formatBuf[0], 32),
		      formatThroughput(el->averageRcvdThpt, 1, formatBuf[1], 32),
		      formatThroughput(el->peakRcvdThpt, 1, formatBuf[2], 32),
		      el->actualRcvdPktThpt,
		      el->averageRcvdPktThpt,
		      el->peakRcvdPktThpt);
	break;
      case SORT_FC_ACTIVITY:
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR  "TR_ON" %s>"
		      "%s%s",
		      getRowColor(),
		      makeVsanLink (el->fcCounters->vsanId, FLAG_HOSTLINK_HTML_FORMAT,
				    vsanBuf, sizeof(vsanBuf)),
		      webHostName);
	sendString(buf);
	printHostThtpShort(el, myGlobals.reportKind, hourId);
	buf[0]='\0';
	break;
      }
      sendString(buf);
      sendString("</TR>\n");

      /* Avoid huge tables */
      if(printedEntries++ > myGlobals.runningPref.maxNumLines)
	break;
    }
  }

  sendString("\n</TABLE>"TABLE_OFF"\n");

  switch(reportType) {
  case SORT_FC_THPT:
    break;
  case SORT_FC_ACTIVITY:
    break;
  case SORT_FC_DATA:
    sendString("<P><I>Note: These counters do not include broadcasts and "
	       "will not equal the 'Global Protocol Distribution'</I></P>\n");
    break;
  }

  sendString("</CENTER>\n");

  printFooter(reportType);

  addPageIndicator(url, pageNum, numEntries, myGlobals.runningPref.maxNumLines,
		   revertOrder, abs(sortedColumn), -1);

  myGlobals.lastRefreshTime = myGlobals.actTime;
  free(tmpTable);
}

/* ************************************ */

void purgeHost(char *serialized_serial) {
  HostSerial theSerial;
  HostTraffic *el;

  printHTMLheader("Host Purge", NULL, 0);
  // printFlagedWarning("aaa"); return;

  str2serial(&theSerial, serialized_serial, strlen(serialized_serial));

#if 0
  {
    char buf[64];

    traceEvent(CONST_TRACE_INFO, "==> %s [type=%d][serial Len=%d]\n",
	       _addrtostr(&theSerial.value.ipSerial.ipAddress, buf, sizeof(buf)),
	       theSerial.serialType, strlen(serialized_serial));

  }
#endif

  el = findHostBySerial(theSerial, myGlobals.actualReportDeviceId);

  if(!el) {
    printFlagedWarning("Unable to purge the specified host: host not found");
  } else {
    int j, found = 0;

    for(j=FIRST_HOSTS_ENTRY; (!found) && (j<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize); j++) {
      HostTraffic *el1 = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[j];

      while(el1 != NULL) {
	if(el1 == el) {
	  found = 1;
	  el->to_be_deleted = 1; /* Delete it at the next run */
	  break;
	}

	el1 = el1->next;
      }
    } /* for */

    if(found) {
      char buf[LEN_GENERAL_WORK_BUFFER];

      safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER,
		    "<center>\n"
		    "<p><font color=\"#FF0000\" size=\"+1\">%s</font></p>\n"
		    "</center>\n", "Host Purged Succesfully");
      sendString(buf);
    } else
      printFlagedWarning("Unable to purge the specified host: internal error");
  }
}

/* ************************************ */

void printInterfaceStats() {
  char buf[64];
  time_t now = time(NULL);

  sendString(ctime(&now));

  snprintf(buf, sizeof(buf), "%u %u\n",
	   (unsigned int)myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value,
	   (unsigned int)(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value
			  - myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value));
  sendString(buf);
  /* traceEvent(CONST_TRACE_ERROR, "%s", buf); */
}

/* ************************************ */

void findHost(char *key) {
  HostTraffic *el=NULL;
  int num = 0;
  char buf[256], buf1[2*LEN_GENERAL_WORK_BUFFER];

  /* traceEvent(CONST_TRACE_INFO, "----------> findHost(%s)", key ? key : "<null>");  */

  sendString("{ results: [");

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    u_char do_add = 0;

    if(el == myGlobals.broadcastEntry) continue;

    if((key == NULL) || (key[0] == '\0')) do_add = 1;
    else if(el->hostNumIpAddress && strcasestr(el->hostNumIpAddress, key)) do_add = 1;
    else if(strcasestr(el->ethAddressString, key)) do_add = 2;
    else if(strcasestr(el->hostResolvedName, key)) do_add = 1;
    
    /*
    traceEvent(CONST_TRACE_INFO, "----------> findHost(%s) [%s][%s] = %d", 
	       key ? key : "<null>", el->ethAddressString, 
	       el->hostResolvedName, do_add); 
    */

    if(do_add) {
      char *str;

      if(el->hostResolvedName[0] != '\0')      str = el->hostResolvedName;
      else if(el->ethAddressString[0] != '\0') str = el->ethAddressString;
      else str = "";
      
      if(do_add == 2) {
	int i;

	safe_snprintf(__FILE__, __LINE__, buf1, sizeof(buf1),
		      "/%s.html", el->ethAddressString);

	for(i=0; i<strlen(buf1); i++) if(buf1[i] == ':') buf1[i] = '_';
	str = el->ethAddressString;
      } else
	makeHostLink(el, FLAG_HOSTLINK_TEXT_LITE_FORMAT, 0, 0, buf1, sizeof(buf1));

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "%s\n\t{ id: \"%d\", value: \"%s\", info: \"%s\" }",
		    (num > 0) ? "," : "", num, str, buf1);
      sendString(buf);
      num++;
      if(num > 32) break; /* Do not display too many entries */
    }
  }

  sendString("\n] }\n");
}

/* ************************************************** */

char* hostRRdGraphLink(HostTraffic *el, int network_mode, 
		       u_char is_subnet_host, 
		       char *tmpStr, int tmpStrLen) {
  struct stat statbuf;
  char *key, buf[256], rrd_buf[256], subnet_buf[32], buf1[64];
  int rc;

  if(is_subnet_host) {
    if(network_mode == DOMAIN_VIEW) {
      key = el->dnsDomainValue;
    } else
      key = host2networkName(el, subnet_buf, sizeof(subnet_buf));
    } else {
    if((!myGlobals.runningPref.dontTrustMACaddr) && subnetPseudoLocalHost(el)
       && (el->ethAddressString[0] != '\0') /* Really safe in case a host that was supposed to be local isn't really so */)
      key = el->ethAddressString;
    else
      key = el->hostNumIpAddress;
  }

  /* Do NOT add a '/' at the end of the path because Win32 will complain about it */
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/interfaces/%s/%s/%s/",
		myGlobals.rrdPath != NULL ? myGlobals.rrdPath : ".",
		myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
		is_subnet_host ? ((network_mode == DOMAIN_VIEW) ? "domains" : "subnet") : "hosts",
		(network_mode == DOMAIN_VIEW) ? key : dotToSlash(key, buf1, sizeof(buf1))); 

  safe_snprintf(__FILE__, __LINE__, rrd_buf, sizeof(rrd_buf), "%s/bytesRcvd.rrd", buf);
  revertSlashIfWIN32(rrd_buf, 0);
  rc = stat(rrd_buf, &statbuf);

  if(rc != 0) {
    safe_snprintf(__FILE__, __LINE__, rrd_buf, sizeof(rrd_buf), "%s/bytesSent.rrd", buf);
    revertSlashIfWIN32(rrd_buf, 0);
    rc = stat(rrd_buf, &statbuf);
  }

  if(rc == 0) {
    safe_snprintf(__FILE__, __LINE__, tmpStr, tmpStrLen,
                  "[ <a href=\"/" CONST_PLUGINS_HEADER
		  "rrdPlugin?action=list&amp;key=interfaces%s%s/%s/%s&amp;title=%s+%s\">"
                  "<img valign=\"top\" border=\"0\" src=\"/graph.gif\""
		  " class=tooltip alt=\"view rrd graphs of historical data for this %s\"></a> ]",
		  (myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName[0] == '/') ? "" : "/",
                  myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
		  is_subnet_host ? ((network_mode == DOMAIN_VIEW) ? "domains" : "subnet") : "hosts",
                  (network_mode == DOMAIN_VIEW) ? key : dotToSlash(key, buf1, sizeof(buf1)),
		  is_subnet_host ? ((network_mode == DOMAIN_VIEW) ? "subnet+" : "network+") : "host+",
		  is_subnet_host ? ((network_mode == DOMAIN_VIEW) ? key : subnet_buf) 
		  : (el->hostResolvedName[0] != '\0' ? el->hostResolvedName : el->hostNumIpAddress),
		  is_subnet_host ? ((network_mode == DOMAIN_VIEW) ? "domain" : "subnet") : "host");
  } else
    tmpStr[0] = '\0';

  return(tmpStr);
}

/* ************************************************** */
