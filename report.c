/*
 *  Copyright (C) 1998-2003 Luca Deri <deri@ntop.org>
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

/* Static */
static short domainSort = 0;

/* *************************** */

#ifndef WIN32
static void ignoreSignal(int signalId) {
  closeNwSocket(&myGlobals.newSock);
  (void)signal(signalId, ignoreSignal);
}
#endif

/* ******************************* */

void initReports(void) {
  myGlobals.columnSort = 0;
  addDefaultAdminUser();
}

/* **************************************** */

int reportValues(time_t *lastTime) {
  if(myGlobals.maxNumLines <= 0)
    myGlobals.maxNumLines = CONST_NUM_TABLE_ROWS_PER_PAGE;

  *lastTime = time(NULL) + myGlobals.refreshRate;

  /*
    Make sure that the other flags are't set. They have
    no effect in web mode
  */
  if(myGlobals.refreshRate == 0)
    myGlobals.refreshRate = DEFAULT_NTOP_AUTOREFRESH_INTERVAL;
  else if(myGlobals.refreshRate < PARM_MIN_WEBPAGE_AUTOREFRESH_TIME)
    myGlobals.refreshRate = PARM_MIN_WEBPAGE_AUTOREFRESH_TIME;

  return(0);
}

/* ******************************* */

void addPageIndicator(char *url, u_int pageNum,
		      u_int numEntries, u_int linesPerPage,
		      int revertOrder, int numCol) {
  char buf[LEN_GENERAL_WORK_BUFFER/2], prevBuf[LEN_GENERAL_WORK_BUFFER/2], nextBuf[LEN_GENERAL_WORK_BUFFER/2], shortBuf[16], separator;
  int numPages = (numEntries+myGlobals.maxNumLines-1)/myGlobals.maxNumLines;
  int actPage  = pageNum+1;

  if(numPages <= 1) return;

  if(strchr(url, '?') != NULL)
    separator = '&';
  else
    separator = '?';

  if(revertOrder == -1)
    shortBuf[0] = '\0';
  else {
    if(snprintf(shortBuf, sizeof(shortBuf),
		"%s%d", revertOrder == 1 ? "-" : "", numCol) < 0)
      BufferTooShort();
  }

  if(pageNum >= 1) {
    if(snprintf(prevBuf, sizeof(prevBuf),
		"<A HREF=\"%s%cpage=0&col=%s\"><IMG SRC=/fback.gif BORDER=0 ALIGN=vmiddle ALT=\"Back to first page\"></A> "
		"<A HREF=\"%s%cpage=%d&col=%s\"><IMG SRC=/back.gif BORDER=0 ALIGN=vmiddle ALT=\"Prior page\"></A>",
		url, separator, shortBuf, url, separator, pageNum-1, shortBuf) < 0)
      BufferTooShort();
  } else
    prevBuf[0] = '\0';

  if(actPage < numPages) {
    if(snprintf(nextBuf, sizeof(nextBuf),
		"<A HREF=\"%s%cpage=%d&col=%s\"><IMG SRC=/forward.gif BORDER=0 ALIGN=vmiddle ALT=\"Next Page\"></A> "
		"<A HREF=\"%s%cpage=%d&col=%s\"><IMG SRC=/fforward.gif BORDER=0 ALIGN=vmiddle ALT=\"Forward to last page\"></A>",
		url, separator, pageNum+1, shortBuf, url, separator, numPages-1, shortBuf) < 0)
      BufferTooShort();
  }  else
    nextBuf[0] = '\0';

  sendString("<P><FONT FACE=Helvetica><B>");
  sendString(prevBuf);

  if(snprintf(buf, sizeof(buf), " [ %d / %d ] ", actPage, numPages) < 0)
    BufferTooShort();
  sendString(buf);

  sendString(nextBuf);
  sendString("</B></FONT>\n");
}

/* ******************************* */

void printTrafficStatistics(void) {
  Counter unicastPkts, avgPktLen;
  int i;
  char buf[LEN_GENERAL_WORK_BUFFER];
  struct pcap_stat pcapStats;
  struct stat statbuf;

  unicastPkts = 0;
  printHTMLheader("Global Traffic Statistics", 0);

  sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1>\n");

  sendString("<TR "TR_ON"><TH "TH_BG" align=left>Network Interface(s)</TH>"
	     "<TD "TD_BG" ALIGN=RIGHT>");

  sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=100%%>\n<TR "TR_ON"><TH "TH_BG">Name</TH>"
	     "<TH "TH_BG">Device</TH><TH "TH_BG">Type</TH><TH "TH_BG">Speed</TH><TH "TH_BG">MTU</TH>"
	     "<TH "TH_BG">Header</TH><TH "TH_BG">Address</TH></TR>\n");

  if(myGlobals.rFileName == NULL) {
    for(i=0; i<myGlobals.numDevices; i++) {
      if(myGlobals.device[i].activeDevice) {
	char buf1[128];

	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" ALIGN=CENTER><TD "TD_BG">%s</TD>",
		    myGlobals.device[i].humanFriendlyName) < 0)
	  BufferTooShort();
	sendString(buf);

	if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%s</TD>", myGlobals.device[i].name) < 0)
	  BufferTooShort();
	sendString(buf);

	if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%s%s</TD>",
		    getNwInterfaceType(i), myGlobals.device[i].virtualDevice ? " virtual" : "") < 0)
	  BufferTooShort();
	sendString(buf);

	sendString("<TD "TD_BG" ALIGN=RIGHT nowrap>&nbsp;");
	if(myGlobals.device[i].deviceSpeed > 0) {
	  /* The speed is known */
	  sendString(formatAdapterSpeed(myGlobals.device[i].deviceSpeed));
	} else
	  sendString("&nbsp;");
	sendString("</TD>");

	if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d</TD>", myGlobals.mtuSize[myGlobals.device[i].datalink]) < 0)
	  BufferTooShort();
	sendString(buf);

	if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d</TD>", myGlobals.headerSize[myGlobals.device[i].datalink]) < 0)
	  BufferTooShort();
	sendString(buf);

	if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%s</TD></TR>\n",
		    _intoa(myGlobals.device[i].ifAddr, buf1, sizeof(buf1))) < 0)
	  BufferTooShort();
	sendString(buf);
      }
    }
  } else {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TD "TD_BG" ALIGN=CENTER>%s</TD><TD "TD_BG">&nbsp;</TD>", CONST_PCAP_NW_INTERFACE_FILE) < 0)
      BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%s</TD>", myGlobals.rFileName) < 0)
      BufferTooShort();
    sendString(buf);

    sendString("<TD "TD_BG">&nbsp;</TD>");
    sendString("<TD "TD_BG">&nbsp;</TD>");
    sendString("<TD "TD_BG">&nbsp;</TD>");
    sendString("<TD "TD_BG">&nbsp;</TD></TR>\n");
  }

  sendString("</TABLE>"TABLE_OFF);
  sendString("</TD></TR>\n");

  if(myGlobals.domainName[0] != '\0') {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" align=left>Local Domain Name</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;</TD></TR>\n",
		myGlobals.domainName) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" align=left>Sampling Since</TH>"
	      "<TD "TD_BG" ALIGN=RIGHT>%s [%s]</TD></TR>\n",
	      ctime(&myGlobals.initialSniffTime),
	      formatSeconds(myGlobals.actTime-myGlobals.initialSniffTime)) < 0)
    BufferTooShort();
  sendString(buf);

  if((i = numActiveSenders(myGlobals.actualReportDeviceId)) > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" align=left>Active Hosts</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%u</TD></TR>\n", i) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if((myGlobals.currentFilterExpression != NULL)
     && (myGlobals.currentFilterExpression[0] != '\0')) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" align=left>Traffic Filter</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		myGlobals.currentFilterExpression) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value > 0) {
    Counter dummyCounter;
    sendString("<TR><TH "TH_BG" align=left>Packets</TH><TD "TH_BG">\n<TABLE BORDER=1 WIDTH=100%>");

    if(myGlobals.numRealDevices > 1)
      sendString("<TR "TR_ON"><TD "TD_BG" ALIGN=CENTER COLSPAN=3>"
		 "<IMG SRC=interfaceTrafficPie"CHART_FORMAT"></TD></TR>\n");

    unicastPkts = myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value
      - myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value
      - myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value;

    if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value <= 0)
      myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value = 1;

    if(myGlobals.device[myGlobals.actualReportDeviceId].pcapPtr != NULL) {
      Counter droppedByKernel;

      droppedByKernel = 0;

      for(i=0; i<myGlobals.numDevices; i++)
	if(myGlobals.device[i].pcapPtr
	   && (!myGlobals.device[i].virtualDevice)) {
	  if(pcap_stats(myGlobals.device[i].pcapPtr, &pcapStats) >= 0) {
	    droppedByKernel += pcapStats.ps_drop;
	  }
	}

      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON" %s><TH "TH_BG" align=left>Total</th>"
		  "<TD "TD_BG" COLSPAN=2 align=right>%s</td></TR>\n",
		  getRowColor(), formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value)) < 0)
	BufferTooShort();
      sendString(buf);

      if(droppedByKernel > 0) {
	if(snprintf(buf, sizeof(buf),
		    "<TR "TR_ON" %s><TH "TH_BG" align=left>Dropped&nbsp;by&nbsp;the&nbsp;kernel</th>"
		    "<TD "TD_BG" COLSPAN=2 align=right>%s</td></TR>\n",
		    getRowColor(), formatPkts(droppedByKernel)) < 0)
	  BufferTooShort();
	sendString(buf);
      }

#ifdef CFG_MULTITHREADED
      if(myGlobals.device[myGlobals.actualReportDeviceId].droppedPkts.value > 0) {
	if(snprintf(buf, sizeof(buf), "<tr "TR_ON" %s><TH "TH_BG" align=left>"
		    "Dropped&nbsp;by&nbsp;ntop</th>"
		    "<TD "TD_BG" COLSPAN=2 align=right>%s</td></TR>\n",
		    getRowColor(), formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].droppedPkts.value)) < 0)
	  BufferTooShort();
	sendString(buf);
      }
#endif
    }

    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Unicast</th>"
		"<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		getRowColor(), (float)(100*unicastPkts)/(float)myGlobals.device[myGlobals.actualReportDeviceId].
		ethernetPkts.value,
		formatPkts(unicastPkts)) < 0) BufferTooShort();
    sendString(buf);
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Broadcast</th>"
		"<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value)/
		(float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value)) < 0)
      BufferTooShort();
    sendString(buf);

    if(myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value > 0) {
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Multicast</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value)) < 0)
	BufferTooShort();
      sendString(buf);
    }

    if(myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value > 0)
      sendString("<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
		 "<IMG SRC=pktCastDistribPie"CHART_FORMAT"></TH></TR>\n");

    if(!myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
      /*
	Very rudimental formula. Note that as specified in RMON, packets smaller
	than 64 or larger than 1518 octets are not counted.
      */
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Shortest</th>"
		  "<TD "TD_BG" align=right colspan=2>%s bytes</td></TR>\n",
		  getRowColor(),
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.shortest.value)) < 0)
	BufferTooShort();
      sendString(buf);
      avgPktLen = (96*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value
		   +192*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value
		   +384*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value
		   +768*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value
		   +1271*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value)/
	(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value+1);
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Average&nbsp;Size</th>"
		  "<TD "TD_BG" align=right colspan=2>%s bytes</td></TR>\n",
		  getRowColor(), formatPkts(avgPktLen)) < 0)
	BufferTooShort();
      sendString(buf);
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Longest</th>"
		  "<TD "TD_BG" align=right colspan=2>%s bytes</td></TR>\n",
		  getRowColor(), formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].
					    rcvdPktStats.longest.value)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>&lt;&nbsp;64&nbsp;bytes</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					 rcvdPktStats.upTo64.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64.value)) < 0)
	BufferTooShort();
      sendString(buf);
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>&lt;&nbsp;128&nbsp;bytes</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					 rcvdPktStats.upTo128.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value)) < 0)
	BufferTooShort();
      sendString(buf);
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>&lt;&nbsp;256&nbsp;bytes</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					 rcvdPktStats.upTo256.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value)) < 0)
	BufferTooShort();
      sendString(buf);
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>&lt;&nbsp;512&nbsp;bytes</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					 rcvdPktStats.upTo512.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value)) < 0)
	BufferTooShort();
      sendString(buf);
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>&lt;&nbsp;1024&nbsp;bytes</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					 rcvdPktStats.upTo1024.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value)) < 0)
	BufferTooShort();
      sendString(buf);
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>&lt;&nbsp;1518&nbsp;bytes</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					 rcvdPktStats.upTo1518.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value)) < 0)
	BufferTooShort();
      sendString(buf);
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>&gt;&nbsp;1518&nbsp;bytes</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					 rcvdPktStats.above1518.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518.value)) < 0)
	BufferTooShort();
      sendString(buf);

      if(myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value > 0)
	sendString("<TR "TR_ON" BGCOLOR=white><TH "TH_BG" ALIGN=CENTER COLSPAN=3>"
		   "<IMG SRC=pktSizeDistribPie"CHART_FORMAT"></TH></TR>\n");

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Packets&nbsp;too&nbsp;long [> %d]</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), myGlobals.mtuSize[myGlobals.device[myGlobals.actualReportDeviceId].datalink],
		  (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.tooLong.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.tooLong.value)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Bad&nbsp;Packets&nbsp;(Checksum)</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					 rcvdPktStats.badChecksum.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		  formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.badChecksum.value)) < 0)
	BufferTooShort();
      sendString(buf);
    }

    /* ****************** */

    sendString("</TABLE>"TABLE_OFF"</TR><TR><TH "TH_BG" ALIGN=LEFT>Traffic</TH><TD "TH_BG">\n<TABLE BORDER=1 WIDTH=100%>");
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Total</th>"
		"<TD "TD_BG" align=right COLSPAN=2>%s [%s Pkts]</td></TR>\n",
		getRowColor(),
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value, 1),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value)) < 0)
      BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>IP Traffic</th>"
		"<TD "TD_BG" align=right COLSPAN=2>%s [%s Pkts]</td></TR>\n",
		getRowColor(), formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value, 1),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value)) < 0)
      BufferTooShort();
    sendString(buf);

    if(myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value > 0) {
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Fragmented IP Traffic</th>"
		  "<TD "TD_BG" align=right COLSPAN=2>%s [%.1f%%]</td></TR>\n",
		  getRowColor(),
		  formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].fragmentedIpBytes.value, 1),
		  (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].fragmentedIpBytes.value)/
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value) < 0)
	BufferTooShort();
      sendString(buf);
    }

    /* Just in case... */
    if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value >
       myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value)
      dummyCounter = myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value-
	myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value;
    else
      dummyCounter = 0;

    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Non IP Traffic</th>"
		"<TD "TD_BG" align=right COLSPAN=2>%s</td></TR>\n",
		getRowColor(), formatBytes(dummyCounter, 1)) < 0)
      BufferTooShort();
    sendString(buf);

    if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value > 0)
      sendString("<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
		 "<IMG SRC=ipTrafficPie"CHART_FORMAT"></TH></TR>\n");

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
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Average&nbsp;TTL</th>"
		    "<TD "TD_BG" align=right COLSPAN=2>%d</td></TR>\n",
		    getRowColor(), avgPktTTL) < 0)
	  BufferTooShort();
	sendString(buf);
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>TTL &lt; 32</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktTTLStats.upTo32.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32.value)) < 0)
	  BufferTooShort();
	sendString(buf);
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>32 &lt; TTL &lt; 64</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktTTLStats.upTo64.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64.value)) < 0)
	  BufferTooShort();
	sendString(buf);
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>64 &lt; TTL &lt; 96</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktTTLStats.upTo96.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96.value)) < 0)
	  BufferTooShort();
	sendString(buf);
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>96 &lt; TTL &lt; 128</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktTTLStats.upTo128.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128.value)) < 0)
	  BufferTooShort();
	sendString(buf);
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>128 &lt; TTL &lt; 160</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktTTLStats.upTo160.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160.value)) < 0)
	  BufferTooShort();
	sendString(buf);
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>160 &lt; TTL &lt; 192</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktTTLStats.upTo192.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192.value)) < 0)
	  BufferTooShort();
	sendString(buf);
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>192 &lt; TTL &lt; 224</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktTTLStats.upTo224.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224.value)) < 0)
	  BufferTooShort();
	sendString(buf);
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>224 &lt; TTL &lt; 256</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].
					   rcvdPktTTLStats.upTo255.value)/
		    (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value,
		    formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo255.value)) < 0)
	  BufferTooShort();
	sendString(buf);

	sendString("<TR "TR_ON"><TH BGCOLOR=white COLSPAN=3>"
		   "<IMG SRC=pktTTLDistribPie"CHART_FORMAT"></TH></TR>\n");
      }
    }

    sendString("</TABLE>"TABLE_OFF"</TR>");

    /* ************************ */

    if(myGlobals.enableSessionHandling && drawHostsDistanceGraph(1))
      sendString("<TR><TH "TH_BG" ALIGN=LEFT>Remote Hosts Distance</TH><TD BGCOLOR=white ALIGN=CENTER>"
		 "<IMG SRC=hostsDistanceChart"CHART_FORMAT"></TD></TR>\n");

    if(!myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
      updateThpt(0);

      sendString("<TR><TH "TH_BG" ALIGN=LEFT>Network Load</TH><TD "TH_BG">\n<TABLE BORDER=1 WIDTH=100%>");
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Actual</th><TD "TD_BG" align=right>%s</td>"
		  "<TD "TD_BG" align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
		  getRowColor(), formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].actualThpt),
		  myGlobals.device[myGlobals.actualReportDeviceId].actualPktsThpt) < 0)
	BufferTooShort();
      sendString(buf);
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Last Minute</th>"
		  "<TD "TD_BG" align=right>%s</td>"
		  "<TD "TD_BG" align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
		  getRowColor(), formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].lastMinThpt),
		  myGlobals.device[myGlobals.actualReportDeviceId].lastMinPktsThpt) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Last 5 Minutes</th>"
		  "<TD "TD_BG" align=right>%s</td>"
		  "<TD "TD_BG" align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
		  getRowColor(), formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].lastFiveMinsThpt),
		  myGlobals.device[myGlobals.actualReportDeviceId].lastFiveMinsPktsThpt) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Peak</th>"
		  "<TD "TD_BG" align=right>%s</td>"
		  "<TD "TD_BG" align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
		  getRowColor(), formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].peakThroughput),
		  myGlobals.device[myGlobals.actualReportDeviceId].peakPacketThroughput) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Average</th>"
		  "<TD "TD_BG" align=right>%s</td>"
		  "<TD "TD_BG" align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
		  getRowColor(),
		  formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value/
				   (myGlobals.actTime-myGlobals.initialSniffTime)),
		  /* Bug below fixed courtesy of Eddy Lai <eddy@ModernTerminals.com> */
		  ((float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value/
		   (float)(myGlobals.actTime-myGlobals.initialSniffTime))) < 0)
	BufferTooShort();
      sendString(buf);
    }
  }

  sendString("</TABLE>"TABLE_OFF"</TR>\n");

  /* ********************* */

  /* RRD */
  /* Do NOT add a '/' at the end of the path because Win32 will complain about it */
  snprintf(buf, sizeof(buf), "%s/interfaces/%s", myGlobals.rrdPath,
	   myGlobals.device[myGlobals.actualReportDeviceId].humanFriendlyName);

  if((i = stat(buf, &statbuf)) == 0) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"[ <A HREF=\"/plugins/rrdPlugin?action=list&key=interfaces/%s&title=interface %s\">"
		"<IMG BORDER=0 SRC=/graph.gif></A> ]</TD></TR>\n",
		getRowColor(), "RRD Stats", myGlobals.device[myGlobals.actualReportDeviceId].humanFriendlyName,
		myGlobals.device[myGlobals.actualReportDeviceId].humanFriendlyName) < 0)
      BufferTooShort();
    sendString(buf);
  }

  /* ********************* */

  sendString("</TABLE></CENTER>\n");
}

/* ******************************* */

void printHostsTraffic(int reportType,
		       int sortedColumn,
		       int revertOrder,
		       int pageNum,
		       char* url) {
  u_int idx, idx1, numEntries=0;
  int printedEntries=0, hourId, maxHosts;
  char theDate[8];
  struct tm t;
  HostTraffic *el;
  HostTraffic** tmpTable;
  char buf[LEN_GENERAL_WORK_BUFFER];
  float sentPercent=0, rcvdPercent=0, totPercent=0;
  Counter totIpBytesSent=0, totIpBytesRcvd=0, totIpBytes=0;
  Counter totEthBytesSent=0, totEthBytesRcvd=0, totEthBytes=0;
  ProtocolsList *protoList;

  strftime(theDate, 8, "%H", localtime_r(&myGlobals.actTime, &t));
  hourId = atoi(theDate);

  memset(buf, 0, sizeof(buf));
  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */
  tmpTable = (HostTraffic**)malloc(maxHosts*sizeof(HostTraffic*));
  memset(tmpTable, 0, maxHosts*sizeof(HostTraffic*));

  switch(reportType) {
  case SORT_DATA_RECEIVED_PROTOS:
  case SORT_DATA_RECEIVED_IP:
  case SORT_DATA_RECEIVED_THPT:
  case SORT_DATA_RCVD_HOST_TRAFFIC:
    snprintf(buf, sizeof(buf), "Network Traffic: Data Received");
    break;
  case SORT_DATA_SENT_PROTOS:
  case SORT_DATA_SENT_IP:
  case SORT_DATA_SENT_THPT:
  case SORT_DATA_SENT_HOST_TRAFFIC:
    snprintf(buf, sizeof(buf), "Network Traffic: Data Sent");
    break;
  case SORT_DATA_PROTOS:
  case SORT_DATA_IP:
  case SORT_DATA_THPT:
  case SORT_DATA_HOST_TRAFFIC:
    snprintf(buf, sizeof(buf), "Network Traffic: Total Data (Sent+Received)");
    break;
  }

  printHTMLheader(buf, 0);
  printHeader(reportType, revertOrder, abs(sortedColumn));

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(broadcastHost(el) == 0) {
      if((myGlobals.sortSendMode && (el->bytesSent.value > 0))
	 || ((!myGlobals.sortSendMode) && (el->bytesRcvd.value > 0))) {
	if(((reportType == SORT_DATA_RECEIVED_IP)
	    || (reportType == SORT_DATA_SENT_IP)
	    || (reportType == SORT_DATA_IP))
	   && (el->hostNumIpAddress[0] == '\0')) {
	  continue;
	}

	tmpTable[numEntries++] = el;

	if(numEntries >= maxHosts)
	  break;
      }
    }
  } /* for */

  if(numEntries > 0) {
    /*
      The switch below is needed to:
      - sort data according to the selected column
      - 'recycle' (somebody would call this "code reuse") the cmpFctn function
    */

    myGlobals.columnSort = 0;

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
          totIpBytesSent += tmpTable[idx]->ipBytesSent.value;
          totIpBytesRcvd += tmpTable[idx]->ipBytesRcvd.value;
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
          totIpBytes += tmpTable[idx]->ipBytesSent.value +
	    tmpTable[idx]->ipBytesRcvd.value;
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

    for(idx=pageNum*myGlobals.maxNumLines; idx<numEntries; idx++) {
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
	  sentPercent = (100*(float)el->ipBytesSent.value)/totIpBytesSent;
	  rcvdPercent = (100*(float)el->ipBytesRcvd.value)/totIpBytesRcvd;
	  break;
        case SORT_DATA_IP:
	  totPercent = (100*(float) (el->ipBytesSent.value + el->ipBytesRcvd.value) )/totIpBytes;
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

	/* Fixed buffer overflow.
	   Courtesy of Rainer Tammer <rainer.tammer@spg.schulergroup.com>
	*/

	strncpy(webHostName, makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 1), sizeof(webHostName));

	switch(reportType) {
	case SORT_DATA_RECEIVED_PROTOS:
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>%s"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      getRowColor(), webHostName,
		      formatBytes(el->bytesRcvd.value, 1),
		      rcvdPercent, myGlobals.separator,
		      formatBytes(el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value, 1),
		      formatBytes(el->udpRcvdLoc.value+el->udpRcvdFromRem.value, 1),
		      formatBytes(el->icmpRcvd.value, 1),
		      formatBytes(el->dlcRcvd.value, 1),
		      formatBytes(el->ipxRcvd.value, 1),
		      formatBytes(el->decnetRcvd.value, 1),
		      formatBytes(el->arp_rarpRcvd.value, 1),
		      formatBytes(el->appletalkRcvd.value, 1)
		      ) < 0) BufferTooShort();

	  sendString(buf);

	  if(snprintf(buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      formatBytes(el->netbiosRcvd.value, 1),
		      formatBytes(el->osiRcvd.value, 1),
		      formatBytes(el->ipv6Rcvd.value, 1),
		      formatBytes(el->stpRcvd.value, 1)) < 0) BufferTooShort();
	  sendString(buf);

	  protoList = myGlobals.ipProtosList, idx1=0;
	  while(protoList != NULL) {
	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(el->ipProtosList[idx1].rcvd.value, 1)) < 0) BufferTooShort();
	    sendString(buf);
	    
	    idx1++, protoList = protoList->next;
	  }

	  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      formatBytes(el->otherRcvd.value, 1)) < 0) BufferTooShort();
	  sendString(buf);
	  break;
	case SORT_DATA_SENT_PROTOS:
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>%s"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      getRowColor(), webHostName,
		      formatBytes(el->bytesSent.value, 1), sentPercent, myGlobals.separator,
		      formatBytes(el->tcpSentLoc.value+el->tcpSentRem.value, 1),
		      formatBytes(el->udpSentLoc.value+el->udpSentRem.value, 1),
		      formatBytes(el->icmpSent.value, 1),
		      formatBytes(el->dlcSent.value, 1),
		      formatBytes(el->ipxSent.value, 1),
		      formatBytes(el->decnetSent.value, 1),
		      formatBytes(el->arp_rarpSent.value, 1),
		      formatBytes(el->appletalkSent.value, 1)
		      ) < 0) BufferTooShort();

	  sendString(buf);

	  if(snprintf(buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      formatBytes(el->netbiosSent.value, 1),
		      formatBytes(el->osiSent.value, 1),
		      formatBytes(el->ipv6Sent.value, 1),
		      formatBytes(el->stpSent.value, 1)) < 0) BufferTooShort();

	  sendString(buf);

	  protoList = myGlobals.ipProtosList, idx1=0;
	  while(protoList != NULL) {
	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(el->ipProtosList[idx1].sent.value, 1)) < 0) BufferTooShort();
	    sendString(buf);
	    
	    idx1++, protoList = protoList->next;
	  }

	  if(snprintf(buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      formatBytes(el->otherSent.value, 1)
		      ) < 0) BufferTooShort();
	  sendString(buf);
	  break;
        case SORT_DATA_PROTOS:
          if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>%s"
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>",
                      getRowColor(), webHostName,
                      formatBytes(el->bytesSent.value+el->bytesRcvd.value, 1),
		      totPercent, myGlobals.separator,
                      formatBytes(el->tcpSentLoc.value+el->tcpSentRem.value+
                                  el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value, 1),
                      formatBytes(el->udpSentLoc.value+el->udpSentRem.value+
                                  el->udpRcvdLoc.value+el->udpRcvdFromRem.value, 1),
                      formatBytes(el->icmpSent.value+el->icmpRcvd.value, 1),
                      formatBytes(el->dlcSent.value+el->dlcRcvd.value, 1),
                      formatBytes(el->ipxSent.value+el->ipxRcvd.value, 1),
                      formatBytes(el->decnetSent.value+el->decnetRcvd.value, 1),
                      formatBytes(el->arp_rarpSent.value+el->arp_rarpRcvd.value, 1),
                      formatBytes(el->appletalkSent.value+el->appletalkRcvd.value, 1)
                      ) < 0) BufferTooShort();

          sendString(buf);

          if(snprintf(buf, sizeof(buf),
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
                      formatBytes(el->netbiosSent.value+el->netbiosRcvd.value, 1),
                      formatBytes(el->osiSent.value+el->osiRcvd.value, 1),
                      formatBytes(el->ipv6Sent.value+el->ipv6Rcvd.value, 1),
                      formatBytes(el->stpSent.value+el->stpRcvd.value, 1)) < 0) BufferTooShort();
          sendString(buf);

	  protoList = myGlobals.ipProtosList, idx1=0;
	  while(protoList != NULL) {
	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(el->ipProtosList[idx1].sent.value
				    +el->ipProtosList[idx1].rcvd.value, 1)) < 0) BufferTooShort();
	    sendString(buf);
	    
	    idx1++, protoList = protoList->next;
	  }
	  
          if(snprintf(buf, sizeof(buf),
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
                      formatBytes(el->otherSent.value+el->otherRcvd.value, 1)
                      ) < 0) BufferTooShort();
          sendString(buf);

          break;
	case SORT_DATA_RECEIVED_IP:
	  {
	    Counter totalIPTraffic=0;

	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>%s"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>",
			getRowColor(), webHostName,
			formatBytes(el->ipBytesRcvd.value, 1), rcvdPercent, myGlobals.separator) < 0)
	      BufferTooShort();
	    sendString(buf);

	    for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	      totalIPTraffic += el->protoIPTrafficInfos[i].rcvdLoc.value+
		el->protoIPTrafficInfos[i].rcvdFromRem.value;
	      if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			  formatBytes(el->protoIPTrafficInfos[i].rcvdLoc.value+
				      el->protoIPTrafficInfos[i].rcvdFromRem.value, 1)) < 0)
		BufferTooShort();
	      sendString(buf);
	    }

	    /* Rounding may cause troubles */
	    if(el->ipBytesRcvd.value > totalIPTraffic)
	      totalIPTraffic = el->ipBytesRcvd.value - totalIPTraffic;
	    else
	      totalIPTraffic = 0;
	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(totalIPTraffic, 1)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	  break;
	case SORT_DATA_SENT_IP:
	  {
	    Counter totalIPTraffic=0;

	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>%s"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>",
			getRowColor(), webHostName,
			formatBytes(el->ipBytesSent.value, 1), sentPercent, myGlobals.separator) < 0)
	      BufferTooShort();
	    sendString(buf);

	    for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	      totalIPTraffic += el->protoIPTrafficInfos[i].sentLoc.value+
		el->protoIPTrafficInfos[i].sentRem.value;
	      if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			  formatBytes(el->protoIPTrafficInfos[i].sentLoc.value+
				      el->protoIPTrafficInfos[i].sentRem.value, 1)) < 0)
		BufferTooShort();
	      sendString(buf);
	    }

	    /* Rounding may cause troubles */
	    if(el->ipBytesSent.value > totalIPTraffic)
	      totalIPTraffic = el->ipBytesSent.value - totalIPTraffic;
	    else
	      totalIPTraffic = 0;
	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(totalIPTraffic, 1)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	  break;
        case SORT_DATA_IP:
          {
            Counter totalIPTraffic=0;

            if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>%s"
                        "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>",
                        getRowColor(), webHostName,
                        formatBytes(el->ipBytesSent.value+el->ipBytesRcvd.value, 1),
			totPercent, myGlobals.separator) < 0)
              BufferTooShort();
            sendString(buf);

            for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
              totalIPTraffic += el->protoIPTrafficInfos[i].sentLoc.value+
		el->protoIPTrafficInfos[i].rcvdLoc.value+
		el->protoIPTrafficInfos[i].sentRem.value+
		el->protoIPTrafficInfos[i].rcvdFromRem.value;
              if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
                          formatBytes(el->protoIPTrafficInfos[i].sentLoc.value+
                                      el->protoIPTrafficInfos[i].rcvdLoc.value+
                                      el->protoIPTrafficInfos[i].sentRem.value+
                                      el->protoIPTrafficInfos[i].rcvdFromRem.value, 1)) < 0)
                BufferTooShort();
              sendString(buf);
            }

            /* Rounding may cause troubles */
            if(el->ipBytesSent.value+el->ipBytesRcvd.value > totalIPTraffic)
              totalIPTraffic = el->ipBytesSent.value + el->ipBytesRcvd.value - totalIPTraffic;
            else
              totalIPTraffic = 0;
            if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
                        formatBytes(totalIPTraffic, 1)) < 0)
              BufferTooShort();
            sendString(buf);
          }
          break;
	case SORT_DATA_RECEIVED_THPT:
	  {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>%s"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>",
			getRowColor(), webHostName,
			formatThroughput(el->actualRcvdThpt),
			formatThroughput(el->averageRcvdThpt),
			formatThroughput(el->peakRcvdThpt),
			el->actualRcvdPktThpt,
			el->averageRcvdPktThpt,
			el->peakRcvdPktThpt) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	  break;
        case SORT_DATA_SENT_THPT:
          {
            if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>%s"
                        "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                        "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                        "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                        "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>"
                        "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>"
                        "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>",
                        getRowColor(), webHostName,
                        formatThroughput(el->actualSentThpt),
                        formatThroughput(el->averageSentThpt),
                        formatThroughput(el->peakSentThpt),
                        el->actualSentPktThpt,
                        el->averageSentPktThpt,
                        el->peakSentPktThpt) < 0)
              BufferTooShort();
            sendString(buf);
          }
          break;
        case SORT_DATA_THPT:
          {
            if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>%s"
                        "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                        "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                        "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                        "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>"
                        "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>"
                        "<TD "TD_BG" ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>",
                        getRowColor(), webHostName,
                        formatThroughput(el->actualTThpt),
                        formatThroughput(el->averageTThpt),
                        formatThroughput(el->peakTThpt),
                        el->actualTPktThpt,
                        el->averageTPktThpt,
                        el->peakTPktThpt) < 0)
              BufferTooShort();
            sendString(buf);
          }
          break;
	case SORT_DATA_RCVD_HOST_TRAFFIC:
	case SORT_DATA_SENT_HOST_TRAFFIC:
	case SORT_DATA_HOST_TRAFFIC:
	case TRAFFIC_STATS:
          {
            if(snprintf(buf, sizeof(buf), "<TR %s>%s", getRowColor(), webHostName) < 0)
              BufferTooShort();
            sendString(buf);
            printHostThtpShort(el, reportType);
          }
          break;
	}

	sendString("</TR>\n");

	/* Avoid huge tables */
	if(printedEntries++ > myGlobals.maxNumLines)
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

  addPageIndicator(url, pageNum, numEntries, myGlobals.maxNumLines,
		   revertOrder, abs(sortedColumn));

  myGlobals.lastRefreshTime = myGlobals.actTime;
  free(tmpTable);
}

/* ******************************* */

void printMulticastStats(int sortedColumn /* ignored so far */,
			 int revertOrder,
			 int pageNum) {
  u_int idx, numEntries=0, maxHosts;
  int printedEntries=0;
  HostTraffic *el;
  HostTraffic** tmpTable;
  char buf[LEN_GENERAL_WORK_BUFFER], *sign, *theAnchor[6], *arrow[6], *arrowGif;
  char htmlAnchor[64], htmlAnchor1[64];

  memset(buf, 0, sizeof(buf));
  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */
  tmpTable = (HostTraffic**)malloc(maxHosts*sizeof(HostTraffic*));
  memset(tmpTable, 0, maxHosts*sizeof(HostTraffic*));

  /* All the ALT tags courtesy of "Burton M. Strauss III" <BStrauss3@attbi.com> */
  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG ALT=\"Ascending order, click to reverse\" SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG ALT=\"Descending order, click to reverse\" SRC=arrow_down.gif BORDER=0>";
  }

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(((el->pktMulticastSent.value > 0) || (el->pktMulticastRcvd.value > 0))
       && (!broadcastHost(el)))
      tmpTable[numEntries++] = el;

    if(numEntries >= maxHosts)
      break;
  }

  printHTMLheader("Multicast Statistics", 0);

  if(numEntries > 0) {
    myGlobals.columnSort = sortedColumn; /* Host name */

    if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", STR_MULTICAST_STATS, sign) < 0)
      BufferTooShort();
    if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=", STR_MULTICAST_STATS) < 0)
      BufferTooShort();

    if(abs(myGlobals.columnSort) == 0) {
      arrow[0] = arrowGif;
      theAnchor[0] = htmlAnchor;
    } else {
      arrow[0] = "";
      theAnchor[0] = htmlAnchor1;
    }

    if(abs(myGlobals.columnSort) == 1) {
      arrow[1] = arrowGif;
      theAnchor[1] = htmlAnchor;
    } else {
      arrow[1] = "";
      theAnchor[1] = htmlAnchor1;
    }

    if(abs(myGlobals.columnSort) == 2) {
      arrow[2] = arrowGif;
      theAnchor[2] = htmlAnchor;
    } else {
      arrow[2] = "";
      theAnchor[2] = htmlAnchor1;
    }

    if(abs(myGlobals.columnSort) == 3) {
      arrow[3] = arrowGif;
      theAnchor[3] = htmlAnchor;
    } else {
      arrow[3] = "";
      theAnchor[3] = htmlAnchor1;
    }

    if(abs(myGlobals.columnSort) == 4) {
      arrow[4] = arrowGif;
      theAnchor[4] = htmlAnchor;
    } else {
      arrow[4] = "";
      theAnchor[4] = htmlAnchor1;
    }

    if(abs(myGlobals.columnSort) == 5) {
      arrow[5] = arrowGif;
      theAnchor[5] = htmlAnchor;
    } else {
      arrow[5] = "";
      theAnchor[5] = htmlAnchor1;
    }

    sendString("<CENTER>\n");
    if(snprintf(buf, sizeof(buf), ""TABLE_ON"<TABLE BORDER=1><TR "TR_ON"><TH "TH_BG">%s0>Host%s</A></TH>\n"
		"<TH "TH_BG">%s1>Domain%s</A></TH>"
		"<TH "TH_BG">%s2>Pkts.value Sent%s</A></TH>"
		"<TH "TH_BG">%s3>Data Sent%s</A></TH>"
		"<TH "TH_BG">%s4>Pkts.value Rcvd%s</A></TH>"
		"<TH "TH_BG">%s5>Data Rcvd%s</A></TH>"
		"</TR>\n",
		theAnchor[0], arrow[0],
		theAnchor[1], arrow[1],
		theAnchor[2], arrow[2],
		theAnchor[3], arrow[3],
		theAnchor[4], arrow[4],
		theAnchor[5], arrow[5]
		) < 0) BufferTooShort();
    sendString(buf);

    qsort(tmpTable, numEntries, sizeof(HostTraffic*), cmpMulticastFctn);

    for(idx=pageNum*myGlobals.maxNumLines; idx<numEntries; idx++) {
      if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>%s"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "</TR>\n",
		    getRowColor(), makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 1),
		    formatPkts(el->pktMulticastSent.value),
		    formatBytes(el->bytesMulticastSent.value, 1),
		    formatPkts(el->pktMulticastRcvd.value),
		    formatBytes(el->bytesMulticastRcvd.value, 1)) < 0) BufferTooShort();

	sendString(buf);

	/* Avoid huge tables */
	if(printedEntries++ > myGlobals.maxNumLines)
	  break;
      }
    }

    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");

    addPageIndicator(STR_MULTICAST_STATS, pageNum, numEntries, myGlobals.maxNumLines,
		     revertOrder, abs(sortedColumn));

    printFooterHostLink();

  } else
    printNoDataYet();

  free(tmpTable);
}

/* ******************************* */

#define NUM_ANCHORS 10

void printHostsInfo(int sortedColumn, int revertOrder, int pageNum) {
  u_int idx, numEntries=0, maxHosts;
  int printedEntries=0;
  unsigned short maxBandwidthUsage=1 /* avoid divisions by zero */;
  HostTraffic *el;
  HostTraffic** tmpTable;
  char buf[2*LEN_GENERAL_WORK_BUFFER], *arrowGif, *sign, *arrow[NUM_ANCHORS+1], *theAnchor[NUM_ANCHORS+1], osBuf[128];
  char htmlAnchor[64], htmlAnchor1[64];

  memset(buf, 0, sizeof(buf));
  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */
  tmpTable = (HostTraffic**)malloc(maxHosts*sizeof(HostTraffic*));
  memset(tmpTable, 0, maxHosts*sizeof(HostTraffic*));

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG ALT=\"Decending order, click to reverse\" SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG ALT=\"Descending order, click to reverse\" SRC=arrow_down.gif BORDER=0>";
  }

  myGlobals.columnSort = sortedColumn;

  printHTMLheader("Host Information", 0);

  /* printHeader(0, revertOrder, abs(sortedColumn)); */

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    unsigned short actUsage;

    actUsage = (unsigned short)(100*((float)el->bytesSent.value/
				     (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));

    el->actBandwidthUsage = actUsage;
    if(el->actBandwidthUsage > maxBandwidthUsage)
      maxBandwidthUsage = actUsage;

    tmpTable[numEntries++] = el;
    getHostAS(el);

    if(numEntries >= maxHosts)
      break;
  }

  if(numEntries > 0) {
    int i;

    qsort(tmpTable, numEntries, sizeof(HostTraffic*), sortHostFctn);

    if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", HOSTS_INFO_HTML, sign) < 0)
      BufferTooShort();
    if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=", HOSTS_INFO_HTML) < 0)
      BufferTooShort();

    for(i=1; i<=NUM_ANCHORS; i++) {
      if(abs(myGlobals.columnSort) == i) {
	arrow[i] = arrowGif;
	theAnchor[i] = htmlAnchor;
      } else {
	arrow[i] = "";
	theAnchor[i] = htmlAnchor1;
      }
    }

    if(abs(myGlobals.columnSort) == FLAG_DOMAIN_DUMMY_IDX) {
      arrow[0] = arrowGif;
      theAnchor[0] = htmlAnchor;
    } else {
      arrow[0] = "";
      theAnchor[0] = htmlAnchor1;
    }

    if(!(myGlobals.dontTrustMACaddr || myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice)) {
      if(snprintf(buf, sizeof(buf), "<CENTER>"TABLE_ON"<TABLE BORDER=1>\n<TR "TR_ON">"
		  "<TH "TH_BG">%s1>Host%s</A></TH>"
		  "<TH "TH_BG">%s"FLAG_DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
		  "</TH><TH "TH_BG">%s2>IP&nbsp;Address%s</A></TH>\n"
		  "<TH "TH_BG">%s3>MAC&nbsp;Address%s</A></TH>"
		  "<TH "TH_BG">%s6>Other&nbsp;Name(s)%s</A></TH>"
		  "<TH "TH_BG">%s4>Sent&nbsp;Bandwidth%s</A></TH>"
		  "<TH "TH_BG">%s5>Nw&nbsp;Board&nbsp;Vendor%s</A></TH>"
		  "<TH "TH_BG">%s7>Hops&nbsp;Distance%s</A></TH>"
		  "<TH "TH_BG">%s8>Host&nbsp;Contacts%s</A></TH>"
		  "<TH "TH_BG">%s9>Age%s</A></TH>"
		  "<TH "TH_BG">%s10>AS%s</A></TH>"
		  "</TR>\n",
		  theAnchor[1], arrow[1],
		  theAnchor[0], arrow[0],
		  theAnchor[2], arrow[2],
		  theAnchor[3], arrow[3],
		  theAnchor[6], arrow[6],
		  theAnchor[4], arrow[4],
		  theAnchor[5], arrow[5],
		  theAnchor[7], arrow[7],
		  theAnchor[8], arrow[8],
		  theAnchor[9], arrow[9],
		  theAnchor[10], arrow[10]
		  ) < 0)
	BufferTooShort();
    } else {
      if(snprintf(buf, sizeof(buf), "<CENTER>"TABLE_ON"<TABLE BORDER=1>\n<TR "TR_ON">"
		  "<TH "TH_BG">%s1>Host%s</A></TH>"
		  "<TH "TH_BG">%s"FLAG_DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
		  "</TH><TH "TH_BG">%s2>IP&nbsp;Address%s</A></TH>\n"
		  "<TH "TH_BG">%s6>Other&nbsp;Name(s)%s</A></TH>"
		  "<TH "TH_BG">%s4>Sent&nbsp;Bandwidth%s</A></TH>"
		  "<TH "TH_BG">%s7>Hops&nbsp;Distance%s</A></TH>"
		  "<TH "TH_BG">%s8>Host&nbsp;Contacts%s</A></TH>"
		  "<TH "TH_BG">%s9>Age%s</A></TH>"
		  "<TH "TH_BG">%s10>AS%s</A></TH>"
		  "</TR>\n",
		  theAnchor[1], arrow[1],
		  theAnchor[0], arrow[0],
		  theAnchor[2], arrow[2],
		  theAnchor[6], arrow[6],
		  theAnchor[4], arrow[4],
		  theAnchor[7], arrow[7],
		  theAnchor[8], arrow[8],
		  theAnchor[9], arrow[9],
		  theAnchor[10], arrow[10]
		  ) < 0)
	BufferTooShort();
    }
    sendString(buf);

    for(idx=pageNum*myGlobals.maxNumLines; idx<numEntries; idx++) {
      if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	char *tmpName1, *tmpName2, *tmpName3, sniffedName[MAXDNAME];
	int displaySniffedName=0;

	if(broadcastHost(el) == 0) {
	  tmpName1 = el->hostNumIpAddress;
	  if((tmpName1[0] == '\0') || (strcmp(tmpName1, "0.0.0.0") == 0))
	    tmpName1 = myGlobals.separator;

	  if(!(myGlobals.dontTrustMACaddr || myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice)) {
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

	  if((el->hostIpAddress.s_addr != 0)
	     && (getSniffedDNSName(el->hostNumIpAddress,
				   sniffedName, sizeof(sniffedName)))) {
#ifdef DEBUG
	    traceEvent(CONST_TRACE_INFO, "%s <=> %s [%s/%s]",
		       el->hostNumIpAddress, sniffedName,
		       el->hostSymIpAddress, el->hostNumIpAddress);
#endif

            if((el->hostSymIpAddress[0] == '\0') || strcmp(sniffedName, el->hostSymIpAddress)) {
	      if((el->hostSymIpAddress[0] == '\0')
		 || (strcmp(el->hostSymIpAddress, el->hostNumIpAddress) == 0)) {
		if(strlen(sniffedName) >= (MAX_LEN_SYM_HOST_NAME-1))
		  sniffedName[MAX_LEN_SYM_HOST_NAME-2] = '\0';
		strcpy(el->hostSymIpAddress, sniffedName);
	      } else
		displaySniffedName=1;
	    }
	  }

	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>", getRowColor()) < 0)
	    BufferTooShort();
	  sendString(buf);

	  sendString(makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 1));

	  if(!(myGlobals.dontTrustMACaddr || myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice)) {
	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			tmpName1, tmpName3) < 0)
	      BufferTooShort();
	  } else {
	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			tmpName1) < 0)
	      BufferTooShort();
	  }
	  sendString(buf);

	  sendString("<TD "TD_BG" ALIGN=RIGHT NOWRAP>");

	  if(el->nonIPTraffic && displaySniffedName) {
	    short numAddresses = 0;

	    if(el->nonIPTraffic->nbHostName && el->nonIPTraffic->nbDomainName) {
	      if((el->nonIPTraffic->nbAccountName != NULL) && ((el->nonIPTraffic->nbAccountName[0] != '0'))) {
		if((el->nonIPTraffic->nbDomainName != NULL) && (el->nonIPTraffic->nbDomainName[0] != '0')) {
		  if(snprintf(buf, sizeof(buf), "%s&nbsp;%s@%s&nbsp;[%s]", getOSFlag(el, "Windows", 0, osBuf, sizeof(osBuf)),
			      el->nonIPTraffic->nbAccountName, el->nonIPTraffic->nbHostName,
			      el->nonIPTraffic->nbDomainName) < 0)
		    BufferTooShort();
		} else {
		  if(snprintf(buf, sizeof(buf), "%s&nbsp;%s@%s", getOSFlag(el, "Windows", 0, osBuf, sizeof(osBuf)),
			      el->nonIPTraffic->nbAccountName, el->nonIPTraffic->nbHostName) < 0)
		    BufferTooShort();
		}
	      } else {
		if((el->nonIPTraffic->nbDomainName != NULL) && (el->nonIPTraffic->nbDomainName[0] != '0')) {
		  if(snprintf(buf, sizeof(buf), "%s&nbsp;%s&nbsp;[%s]", getOSFlag(el, "Windows", 0, osBuf, sizeof(osBuf)),
			      el->nonIPTraffic->nbHostName, el->nonIPTraffic->nbDomainName) < 0)
		    BufferTooShort();
		} else {
		  if(snprintf(buf, sizeof(buf), "%s&nbsp;%s", getOSFlag(el, "Windows", 0, osBuf, sizeof(osBuf)),
			      el->nonIPTraffic->nbHostName) < 0)
		    BufferTooShort();
		}
	      }
	      sendString(buf);
	      numAddresses++;
	    } else if(el->nonIPTraffic->nbHostName) {
	      if(snprintf(buf, sizeof(buf), "%s&nbsp;%s", getOSFlag(el, "Windows", 0, osBuf, sizeof(osBuf)),
			  el->nonIPTraffic->nbHostName) < 0) BufferTooShort();
	      sendString(buf);
	      numAddresses++;
	    }

	    if(el->nonIPTraffic->nbDescr) {
	      if(snprintf(buf, sizeof(buf), ":&nbsp;%s", el->nonIPTraffic->nbDescr) < 0)
		BufferTooShort();
	      sendString(buf);
	    }

	    if (displaySniffedName) {
	      if(numAddresses > 0) sendString("/");
              snprintf(buf, sizeof(buf), "%s", sniffedName);
	      sendString(buf);
	      numAddresses++;
            }

	    if(el->nonIPTraffic->atNetwork) {
	      char *nodeName = el->nonIPTraffic->atNodeName;

	      if(numAddresses > 0) sendString("/");
	      if(nodeName == NULL) nodeName = "";

	      if(snprintf(buf, sizeof(buf), "%s&nbsp;%s&nbsp;",
			  getOSFlag(el, "Mac", 0, osBuf, sizeof(osBuf)), nodeName) < 0)
		BufferTooShort();
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

	      if(snprintf(buf, sizeof(buf), "[%d.%d]",
			  el->nonIPTraffic->atNetwork, el->nonIPTraffic->atNode) < 0)
		BufferTooShort();
	      sendString(buf);
	      numAddresses++;
	    }

	    if(el->nonIPTraffic->ipxHostName) {
	      int numSap=0;

	      if(numAddresses > 0) sendString("/");
	      if(snprintf(buf, sizeof(buf), "%s&nbsp;%s&nbsp;",
			  getOSFlag(el, "Novell", 0, osBuf, sizeof(osBuf)),
			  el->nonIPTraffic->ipxHostName) < 0)
		BufferTooShort();
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
	  printBar(buf, sizeof(buf), el->actBandwidthUsage, maxBandwidthUsage, 3);

	  if(!(myGlobals.dontTrustMACaddr || myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice)) {
	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>", tmpName2) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }

	  {
	    char shortBuf[8];

	    if(!subnetPseudoLocalHost(el)) {
	      i = guessHops(el);
	    } else
	      i = 0;

	    sprintf(shortBuf, "%d", i % 256);

	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>&nbsp;%s</TD>",
			(i == 0) ? "" : shortBuf) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }

	  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%lu</TD>",
		      (unsigned long)(el->totContactedSentPeers+el->totContactedRcvdPeers)) < 0)
	    BufferTooShort();
	  sendString(buf);

#if 0
	  /* Time distance */
	  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s-",
		      formatLatency(el->minLatency, FLAG_STATE_ACTIVE)) < 0)
	    BufferTooShort();
	  sendString(buf);

	  if(snprintf(buf, sizeof(buf), "%s</TD>",
		      formatLatency(el->maxLatency, FLAG_STATE_ACTIVE)) < 0)
	    BufferTooShort();
	  sendString(buf);
#endif

	  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%s</A></TD>",
		      formatSeconds(el->lastSeen - el->firstSeen)) < 0)
	    BufferTooShort();
	  sendString(buf);

	  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%d</A></TD>", el->hostAS) < 0)
	    BufferTooShort();
	  sendString(buf);

	  sendString("</TR>\n");
	  printedEntries++;
	}

	/* Avoid huge tables */
	if(printedEntries > myGlobals.maxNumLines)
	  break;
      } else {
	traceEvent(CONST_TRACE_WARNING, "qsort() problem!");
      }
    }

    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");

    printFooterHostLink();

    addPageIndicator(HOSTS_INFO_HTML, pageNum, numEntries, myGlobals.maxNumLines,
		     revertOrder, abs(sortedColumn));
  }

  free(tmpTable);
}

/* ************************************ */

void printAllSessionsHTML(char* host, int actualDeviceId) {
  u_int idx, i;
  HostTraffic *el=NULL;
  char buf[LEN_GENERAL_WORK_BUFFER];
  u_short found = 0;

  for(el=getFirstHost(actualDeviceId);
      el != NULL; el = getNextHost(actualDeviceId, el)) {
    if((strcmp(el->hostNumIpAddress, host) == 0)
       || (strcmp(el->ethAddressString, host) == 0)) {
      found = 1;
      break;
    }
  }

  /* Dennis Schoen (dennis@cns.dnsalias.org)
   *
   * send 404 if we cannot generate the requested page
   */
  if((el == NULL) || (!found)) {
    returnHTTPpageNotFound();
    return;
  } else
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);

  /* ************************************ */

  printHostDetailedInfo(el, actualDeviceId);
  printHostTrafficStats(el, actualDeviceId);
  printHostIcmpStats(el);
  printHostFragmentStats(el, actualDeviceId);
  printHostContactedPeers(el, actualDeviceId);
  printHostHTTPVirtualHosts(el, actualDeviceId);
  printHostUsedServices(el, actualDeviceId);

  /* ***************************************************** */

  i = 0;

  if(el->portsUsage != NULL) {
    for(idx=1; idx<MAX_ASSIGNED_IP_PORTS /* 1024 */; idx++) {
      if(el->portsUsage[idx] != NULL) {
	char *svc = getAllPortByNum(idx);
	char webHostName[LEN_GENERAL_WORK_BUFFER];
	HostTraffic *peerHost;

	if(i == 0) {
	  printSectionTitle("TCP/UDP&nbsp;Service/Port&nbsp;Usage\n");
	  sendString("<CENTER>\n");
	  sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=100%>\n<TR "TR_ON">"
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
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		      "<TD "TD_BG" ALIGN=CENTER>%d</TD>", getRowColor(), svc, idx) < 0)
	    BufferTooShort();
	} else {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%d</TH>"
		      "<TD "TD_BG" ALIGN=CENTER>%d</TD>", getRowColor(), idx, idx) < 0)
	    BufferTooShort();
	}

	sendString(buf);

	if(el->portsUsage[idx]->clientUses > 0) {
	  /* Fix below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
	  HostTraffic tmpEl;

	  if(emptySerial(&el->portsUsage[idx]->clientUsesLastPeer))
	    peerHost = NULL;
	  else
	    peerHost = quickHostLink(el->portsUsage[idx]->clientUsesLastPeer, actualDeviceId, &tmpEl);

	  if(peerHost == NULL) {
	    /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
	    strncpy(webHostName, "&nbsp;", sizeof(webHostName));
	  } else
	    strncpy(webHostName, makeHostLink(peerHost, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0), sizeof(webHostName));

	  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d/%s</TD>"
		      "<TD "TD_BG" ALIGN=CENTER>%s</TD>",
		      el->portsUsage[idx]->clientUses,
		      formatBytes(el->portsUsage[idx]->clientTraffic.value, 1),
		      webHostName) < 0) BufferTooShort();
	  sendString(buf);
	} else
	  sendString("<TD "TD_BG">&nbsp;</TD><TD "TD_BG">&nbsp;</TD>");

	if(el->portsUsage[idx]->serverUses > 0) {
	  HostTraffic tmpEl;

	  if(emptySerial(&el->portsUsage[idx]->serverUsesLastPeer))
	    peerHost = NULL;
	  else
	    peerHost = quickHostLink(el->portsUsage[idx]->serverUsesLastPeer, actualDeviceId, &tmpEl);

	  if(peerHost == NULL) {
	    /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
	    strncpy(webHostName, "&nbsp;", sizeof(webHostName));
	  } else
	    strncpy(webHostName, makeHostLink(peerHost, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0), sizeof(webHostName));

	  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d/%s</TD>"
		      "<TD "TD_BG" ALIGN=CENTER>%s</TD></TR>",
		      el->portsUsage[idx]->serverUses,
		      formatBytes(el->portsUsage[idx]->serverTraffic.value, 1),
		      webHostName) < 0) BufferTooShort();
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

  if((el->recentlyUsedClientPorts[MAX_NUM_RECENT_PORTS-1] > 0)
     || (el->recentlyUsedServerPorts[MAX_NUM_RECENT_PORTS-1] > 0)) {
    /* We have something to show */
    int numPrinted;

    printSectionTitle("TCP/UDP Recently Used Ports\n");
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1>\n<TR "TR_ON">"
	       "<TH "TH_BG">Client Port</TH><TH "TH_BG">Server Port</TH>"
	       "</TR>\n");

    sendString("<TR "TR_ON"><TD "TD_BG" ALIGN=LEFT><UL>");

    for(idx=0, numPrinted=0; idx<MAX_NUM_RECENT_PORTS; idx++) {
      if(el->recentlyUsedClientPorts[idx] > 0) {
	if(snprintf(buf, sizeof(buf), "<li><A HREF=\""SHOW_PORT_TRAFFIC"?port=%d\">%s</A>\n",
		    el->recentlyUsedClientPorts[idx],
		    getAllPortByNum(el->recentlyUsedClientPorts[idx])) < 0)
	  BufferTooShort();
	sendString(buf);
	numPrinted++;
      }
    }

    if(numPrinted == 0) sendString("&nbsp;");

    sendString("</UL></TD><TD "TD_BG" ALIGN=LEFT><UL>");

    for(idx=0, numPrinted=0; idx<MAX_NUM_RECENT_PORTS; idx++) {
      if(el->recentlyUsedServerPorts[idx] > 0) {
	if(snprintf(buf, sizeof(buf), "<LI><A HREF=\""SHOW_PORT_TRAFFIC"?port=%d\">%s</A>\n",
		    el->recentlyUsedServerPorts[idx],
		    getAllPortByNum(el->recentlyUsedServerPorts[idx])) < 0)
	  BufferTooShort();
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
    sendString(""TABLE_ON"<TABLE BORDER=1>\n<TR "TR_ON">"
	       "<TH "TH_BG" NOWRAP>File Name</TH></TR>\n");
    sendString("<TR><TD ALIGN=left><ol>\n");

    while(list != NULL) {
      if(snprintf(buf, sizeof(buf), "<li>%s&nbsp",
		  list->fileName) < 0)
	BufferTooShort();
      sendString(buf);

      if(FD_ISSET(BITFLAG_P2P_UPLOAD_MODE, &list->fileFlags))   sendString("<IMG SRC=/upload.gif ALT=Upload VALIGN=MIDDLE>&nbsp;");
      if(FD_ISSET(BITFLAG_P2P_DOWNLOAD_MODE, &list->fileFlags)) sendString("<IMG SRC=/download.gif ALT=Download VALIGN=MIDDLE>&nbsp;");

      list = list->next;
    }

    sendString("\n</ol></TD></TR></TABLE></CENTER>\n");
  }

  /* *************************************************** */

  printHostSessions(el, actualDeviceId);
}

/* ************************************ */

void printLocalRoutersList(int actualDeviceId) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  HostTraffic *el, *router;
  u_int i, j, numEntries=0;
  HostSerial routerList[MAX_NUM_ROUTERS];

  printHTMLheader("Local Subnet Routers", 0);

  if(myGlobals.dontTrustMACaddr) {
    printNotAvailable("-o or --no-mac");
    return;
  }

  for(el=getFirstHost(actualDeviceId);
      el != NULL; el = getNextHost(actualDeviceId, el)) {
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
    sendString(""TABLE_ON"<TABLE BORDER=1><TR "TR_ON"><TH "TH_BG">Router Name</TH>"
	       "<TH "TH_BG">Used by</TH></TR>\n");

    for(i=0; i<numEntries; i++) {
      HostTraffic tmpEl;

      if((router = quickHostLink(routerList[i], myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=left>%s</TH><TD "TD_BG" ALIGN=LEFT><UL>\n",
		    getRowColor(),
		    makeHostLink(router, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0)) < 0) BufferTooShort();
	sendString(buf);


	for(el=getFirstHost(actualDeviceId);
	    el != NULL; el = getNextHost(actualDeviceId, el)) {
	  if(subnetLocalHost(el)) {
	    for(j=0; j<MAX_NUM_CONTACTED_PEERS; j++)
	      if(cmpSerial(&el->contactedRouters.peersSerials[j], &routerList[i])) {
		if(snprintf(buf, sizeof(buf), "<LI>%s</LI>\n",
			    makeHostLink(el, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0)) < 0)
		  BufferTooShort();
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
  char *arrowGif, *arrow[48], *theAnchor[48];
  char htmlAnchor[64], htmlAnchor1[64];

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG ALT=\"Decending order, click to reverse\" SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG ALT=\"Ascending order, click to reverse\" SRC=arrow_down.gif BORDER=0>";
  }

  totalBytesSent=0, totalBytesRcvd=0;
  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */
  tmpTable = (HostTraffic**)malloc(maxHosts*sizeof(HostTraffic*));
  memset(tmpTable, 0, maxHosts*sizeof(HostTraffic*));

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if((broadcastHost(el) == 0) /* No broadcast addresses please */
       && (multicastHost(el) == 0) /* No multicast addresses please */
       && ((el->hostNumIpAddress[0] != '\0')
	   && (el->hostIpAddress.s_addr != '0' /* 0.0.0.0 */)
	   /* This host speaks IP */)) {
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

  switch(remoteToLocal) {
  case FLAG_REMOTE_TO_LOCAL_ACCOUNTING:
    str = IP_R_2_L_HTML;
    title = "Remote to Local IP Traffic";
    break;
  case FLAG_REMOTE_TO_REMOTE_ACCOUNTING:
    str = IP_R_2_R_HTML;
    title = "Remote to Remote IP Traffic";
    break;
  case FLAG_LOCAL_TO_REMOTE_ACCOUNTING:
    str = IP_L_2_R_HTML;
    title = "Local to Remote IP Traffic";
    break;
  case FLAG_LOCAL_TO_LOCAL_ACCOUNTING:
    str = IP_L_2_L_HTML;
    title = "Local IP Traffic";
    break;
  }

  printHTMLheader(title, 0);

  if(numEntries > 0) {
    myGlobals.columnSort = sortedColumn;
    myGlobals.sortFilter = remoteToLocal;
    qsort(tmpTable, numEntries, sizeof(HostTraffic*), cmpHostsFctn);

    if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", str, sign) < 0)
      BufferTooShort();
    if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=", str) < 0)
      BufferTooShort();

    if(abs(myGlobals.columnSort) == 1) {
      arrow[1] = arrowGif;
      theAnchor[1] = htmlAnchor;
    } else {
      arrow[1] = "";
      theAnchor[1] = htmlAnchor1;
    }

    if(abs(myGlobals.columnSort) == 2)  {
      arrow[2] = arrowGif;
      theAnchor[2] = htmlAnchor;
    } else {
      arrow[2] = "";
      theAnchor[2] = htmlAnchor1;
    }

    if(abs(myGlobals.columnSort) == 3) {
      arrow[3] = arrowGif;
      theAnchor[3] = htmlAnchor;
    } else {
      arrow[3] = "";
      theAnchor[3] = htmlAnchor1;
    }

    if(abs(myGlobals.columnSort) == 4) {
      arrow[4] = arrowGif;
      theAnchor[4] = htmlAnchor;
    } else {
      arrow[4] = "";
      theAnchor[4] = htmlAnchor1;
    }

    sendString("<CENTER>\n");
    if(snprintf(buf, sizeof(buf), ""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\">\n<TR "TR_ON"><TH "TH_BG">"
		"%s1>Host%s</A></TH>"
		"<TH "TH_BG">%s2>IP&nbsp;Address%s</A></TH>\n"
		"<TH "TH_BG" COLSPAN=2>%s3>Data&nbsp;Sent%s</A></TH>"
		"<TH "TH_BG" COLSPAN=2>%s4>Data&nbsp;Rcvd%s</A></TH></TR>\n",
		theAnchor[1], arrow[1],
		theAnchor[2], arrow[2], theAnchor[3], arrow[3],
		theAnchor[4], arrow[4]) < 0)
      BufferTooShort();

    sendString(buf);

    for(idx=pageNum*myGlobals.maxNumLines; idx<numEntries; idx++) {
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

	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>"
		    "%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD></TR>\n",
		    getRowColor(),
		    makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
		    tmpName1,
		    formatBytes(a, 1),
		    sentpct, myGlobals.separator,
		    formatBytes(b, 1),
		    rcvdpct, myGlobals.separator) < 0)
	  BufferTooShort();
	sendString(buf);

	/* Avoid huge tables */
	if(printedEntries++ > myGlobals.maxNumLines)
	  break;
      }
    }

    sendString("</TABLE>"TABLE_OFF"\n");

    addPageIndicator(str, pageNum, numEntries, myGlobals.maxNumLines,
		     revertOrder, abs(sortedColumn));

    sendString("<P>"TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\">\n<TR "TR_ON">"
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

    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		formatBytes(totalBytes, 1),
		formatBytes(totalBytesSent, 1),
		formatBytes(totalBytesRcvd, 1),
		formatThroughput((float)(totalBytes/timeDiff))) < 0)
      BufferTooShort();

    sendString(buf);
    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");

    printFooterHostLink();

  } else
    printNoDataYet();

  free(tmpTable);
}

/* ********************************** */

void printActiveTCPSessions(int actualDeviceId, int pageNum, HostTraffic *el) {
  int idx;
  char buf[LEN_GENERAL_WORK_BUFFER];
  int numSessions, printedSessions;

  if(!myGlobals.enableSessionHandling) {
    printNotAvailable("-z or --disable-sessions");
    return;
  }

  /*
    Due to the way sessions are handled, sessions before those to
    display need to be skipped
  */

  for(idx=1, numSessions=0, printedSessions=0; idx<MAX_TOT_NUM_SESSIONS; idx++) {

    if(el && (printedSessions >= el->numHostSessions)) break;

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.tcpSessionsMutex, "printActiveTCPSessions");
#endif   

    if(myGlobals.device[myGlobals.actualReportDeviceId].tcpSession[idx] != NULL) {
      char *sport, *dport;
      Counter dataSent, dataRcvd;
      IPSession *session = myGlobals.device[myGlobals.actualReportDeviceId].tcpSession[idx];

      while((session != NULL) && (printedSessions < myGlobals.maxNumLines)) {
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

	if((numSessions++) < pageNum*myGlobals.maxNumLines) {
	  session = session->next;
	  continue;
	}

	if(printedSessions == 0) {
	  printHTMLheader("Active TCP Sessions", 0);

	  sendString("<CENTER>\n");
	  sendString(""TABLE_ON"<TABLE BORDER=1><TR "TR_ON">"
		     "<TH "TH_BG">Client</TH>"
		     "<TH "TH_BG">Server</TH>"
		     "<TH "TH_BG">Data&nbsp;Sent</TH>"
		     "<TH "TH_BG">Data&nbsp;Rcvd</TH>"
		     "<TH "TH_BG">Active&nbsp;Since</TH>"
		     "<TH "TH_BG">Last&nbsp;Seen</TH>"
		     "<TH "TH_BG">Duration</TH>"
		     "<TH "TH_BG">Latency</TH>"
#ifdef PARM_PRINT_ALL_SESSIONS
		     "<TH "TH_BG">State</TH>"
#endif
		     "</TR>\n");
	}

	sport = getPortByNum(session->sport, IPPROTO_TCP);
	dport = getPortByNum(session->dport, IPPROTO_TCP);
	dataSent = session->bytesSent.value;
	dataRcvd = session->bytesRcvd.value;

	if(sport == NULL) {
	  static char _sport[8];
	  if(snprintf(_sport, 8, "%d", session->sport) < 0)
	    BufferTooShort();
	  sport = _sport;
	}

	if(dport == NULL) {
	  static char _dport[8];
	  if(snprintf(_dport, 8, "%d", session->dport) < 0)
	    BufferTooShort();
	  dport = _dport;
	}

	/* Sanity check */
	if((myGlobals.actTime < session->firstSeen)
	   || (session->firstSeen == 0))
	  session->firstSeen = myGlobals.actTime;

	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s:%s%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s:%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
#ifdef PARM_PRINT_ALL_SESSIONS
		    "<TD "TD_BG" ALIGN=CENTER>%s</TD>"
#endif
		    "</TR>\n",
		    getRowColor(),
		    makeHostLink(session->initiator, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0),
		    sport,
		    session->isP2P == 1 ? "&nbsp&lt;P2P&gt;" : "",
		    makeHostLink(session->remotePeer, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0),
		    dport,
		    formatBytes(dataSent, 1),
		    formatBytes(dataRcvd, 1),
		    formatTime(&(session->firstSeen), 1),
		    formatTime(&(session->lastSeen), 1),
		    formatSeconds(myGlobals.actTime-session->firstSeen),
		    formatLatency(session->nwLatency, session->sessionState)
#ifdef PARM_PRINT_ALL_SESSIONS
		    , getSessionState(session)
#endif
		    ) < 0) BufferTooShort();

	sendString(buf);
	session = session->next;
	printedSessions++;
      }
    }
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.tcpSessionsMutex);
#endif
  }

  if(printedSessions > 0) {
    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");

    if(el == NULL)
      addPageIndicator("NetNetstat.html", pageNum,
		       myGlobals.device[actualDeviceId].numTcpSessions,
		       myGlobals.maxNumLines, -1, 0);

    printFooterHostLink();
  } else {
    if(el == NULL) {
      printFlagedWarning("<I>No Active TCP Sessions</I>");
    }
  }
}


/* ********************************** */

void printIpProtocolUsage(void) {
  HostTraffic **hosts, *el;
  u_short clientPorts[MAX_ASSIGNED_IP_PORTS], serverPorts[MAX_ASSIGNED_IP_PORTS];
  u_int j, idx1, hostsNum=0, numPorts=0, maxHosts;
  char buf[LEN_GENERAL_WORK_BUFFER];

  printHTMLheader("TCP/UDP Protocol Subnet Usage", 0);

  memset(clientPorts, 0, sizeof(clientPorts));
  memset(serverPorts, 0, sizeof(serverPorts));

  hosts = (HostTraffic**)malloc(myGlobals.device[myGlobals.actualReportDeviceId].hostsno*sizeof(HostTraffic*));
  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */
  memset(hosts, 0, maxHosts*sizeof(HostTraffic*));

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(subnetPseudoLocalHost(el) && (el->hostNumIpAddress[0] != '\0')) {
      hosts[hostsNum++] = el;

      if(el->portsUsage != NULL) {
	for(j=0; j<MAX_ASSIGNED_IP_PORTS; j++) {
	  if(el->portsUsage[j] != NULL)  {
	    clientPorts[j] += el->portsUsage[j]->clientUses;
	    serverPorts[j] += el->portsUsage[j]->serverUses;
	    numPorts++;
	  }
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

  /* Hosts are now in a contiguous structure (hosts[])... */

  sendString("<CENTER>\n");
  sendString(""TABLE_ON"<TABLE BORDER=1><TR "TR_ON"><TH "TH_BG" COLSPAN=2>Service</TH>"
	     "<TH "TH_BG">Clients</TH><TH "TH_BG">Servers</TH>\n");

  for(j=0; j<MAX_ASSIGNED_IP_PORTS; j++)
    if((clientPorts[j] > 0) || (serverPorts[j] > 0)) {
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=CENTER>%d</TD>"
		  "<TD "TD_BG">\n", getRowColor(), getAllPortByNum(j), j) < 0) BufferTooShort();
      sendString(buf);

      if(clientPorts[j] > 0) {
	sendString("<UL>");
	for(idx1=0; idx1<hostsNum; idx1++)
	  if((hosts[idx1]->portsUsage != NULL)
	     && (hosts[idx1]->portsUsage[j] != NULL) /* added 04.03.00 Ralf Amandi */
	     && (hosts[idx1]->portsUsage[j]->clientUses > 0)) {
	    if(snprintf(buf, sizeof(buf), "<li>%s\n",
			makeHostLink(hosts[idx1], FLAG_HOSTLINK_TEXT_FORMAT, 1, 0)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	sendString("</UL>");
      } else
	sendString("&nbsp;");

      sendString("</TD><TD "TD_BG">");

      if(serverPorts[j] > 0) {
	sendString("<UL>");
	for(idx1=0; idx1<hostsNum; idx1++)
	  if((hosts[idx1]->portsUsage != NULL)
	     && (hosts[idx1]->portsUsage[j] != NULL) /* added 04.03.00 Ralf Amandi */
	     && (hosts[idx1]->portsUsage[j]->serverUses > 0)) {
	    if(snprintf(buf, sizeof(buf), "<li>%s\n",
			makeHostLink(hosts[idx1], FLAG_HOSTLINK_TEXT_FORMAT, 1, 0)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	sendString("</UL>");
      } else
	sendString("&nbsp;");

      sendString("</TD></TR>");
    } /* for */

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");

  printFooterHostLink();

  free(hosts);
}

/* ********************************** */

void printBar(char *buf, int bufLen,
	      unsigned short percentage,
	      unsigned short maxPercentage,
	      unsigned short ratio) {
  int int_perc = (int)((100*percentage)/maxPercentage);

  /* This shouldn't happen */
  if(int_perc < 0) {
    int_perc = 0;
    percentage = 0;
  } else if(int_perc > 100) {
    int_perc = 100;
    percentage = 100;
  }

  switch(int_perc) {
  case 0:
    if(snprintf(buf, bufLen, "<TD "TD_BG" %s>&nbsp;</TD>\n", getActualRowColor()) < 0)
      BufferTooShort();
    break;
  default:
    if(snprintf(buf, bufLen, "<TD "TD_BG" ALIGN=LEFT><IMG ALIGN=ABSMIDDLE SRC=/gauge.jpg"
		" ALT=\"%d%%\" WIDTH=%d HEIGHT=12>&nbsp;</TD>\n",
		int_perc, ratio*int_perc) < 0) BufferTooShort();
    break;
  }

  sendString(buf);
}


/* ********************************** */

#if 0
static void printShortTableEntry(char *buf, int bufLen,
				 char *label, char* color,
				 float total, float percentage) {
  int int_perc;

  if(total == 0) return;

  int_perc = (int)percentage;

  /* This shouldn't happen */
  if(int_perc < 0) {
    int_perc = 0;
    percentage = 0;
  } else if(int_perc > 100) {
    int_perc = 100;
    percentage = 100;
  }

  switch(int_perc) {
  case 0:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"</TR>\n",
		getRowColor(), label, formatKBytes(total)) < 0) BufferTooShort();
    break;
  case 100:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"</TR>\n",
		getRowColor(), label, formatKBytes(total)) < 0) BufferTooShort();
    break;
  default:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"</TR>\n",
		getRowColor(), label, formatKBytes(total)) < 0) BufferTooShort();
  }

  sendString(buf);
}
#endif

/* ******************************* */

static int cmpPortsFctn(const void *_a, const void *_b) {
  if((_a == NULL) || (_b == NULL))
    return(0);
  else {
    PortCounter *a, *b;

    a = *((PortCounter**)_a);
    b = *((PortCounter**)_b);

    if((a->sent+a->rcvd) > (b->sent+b->rcvd))
      return(-1);
    else
      return(1);
  }
}

/* ********************************** */

void printIpProtocolDistribution(int mode, int revertOrder) {
  int i;
  char buf[2*LEN_GENERAL_WORK_BUFFER], *sign;
  float total, partialTotal, remainingTraffic;
  float percentage;

  if(revertOrder)
    sign = "";
  else
    sign = "-";

  if(mode == FLAG_HOSTLINK_TEXT_FORMAT) {
    printSectionTitle("IP Protocol Distribution");

    sendString("<CENTER><IMG SRC=ipProtoDistribPie"CHART_FORMAT"><p>\n</CENTER>\n");

    printSectionTitle("Local Traffic");

    total = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local.value+
		    myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.local.value)/1024;
    if(total == 0)
      printNoDataYet();
    else {
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\"><TR "TR_ON">"
		 "<TH "TH_BG" WIDTH=150>IP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
		 "Percentage</TH></TR>\n");
      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local.value/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP",
				"TCP", "UDP", total, percentage);

      sendString("</TABLE>"TABLE_OFF"\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\"><TR "TR_ON">"
		 "<TH "TH_BG" WIDTH=150>TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250 COLSPAN=2>"
                 "Percentage</TH></TR>\n");

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local.value/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), myGlobals.protoIPTrafficInfos[i],
			  CONST_COLOR_1, partialTotal, percentage);
	}
      }
      
      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Prot.",
			CONST_COLOR_1, remainingTraffic, percentage);
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
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\"><TR "TR_ON">"
		 "<TH "TH_BG" WIDTH=150>IP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
		 "Percentage</TH></TR>\n");

      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.remote2local.value/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP",
				"TCP", "UDP", total, percentage);

      sendString("</TABLE>"TABLE_OFF);
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\"><TR "TR_ON">"
		 "<TH "TH_BG" WIDTH=150>TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250 COLSPAN=2>"
		 "Percentage</TH></TR>\n");

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote2local.value/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), myGlobals.protoIPTrafficInfos[i],
			  CONST_COLOR_1, partialTotal, percentage);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Prot.",
			CONST_COLOR_1, remainingTraffic, percentage);
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
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\"><TR "TR_ON">"
                 "<TH "TH_BG" WIDTH=150>IP&nbsp;Protocol</TH>"
                 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
                 "Percentage</TH></TR>\n");
      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.remote.value/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP",
                                "TCP", "UDP", total, percentage);

      sendString("</TABLE>"TABLE_OFF"\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\"><TR "TR_ON">"
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
			  myGlobals.protoIPTrafficInfos[i],
                          CONST_COLOR_1, partialTotal, percentage);
        }
      }

      if(total > remainingTraffic)
        remainingTraffic = total - remainingTraffic;
      else
        remainingTraffic = 0;

      if(remainingTraffic > 0) {
        percentage = ((float)(remainingTraffic*100))/((float)total);
        printTableEntry(buf, sizeof(buf),
			"Other&nbsp;TCP/UDP-based&nbsp;Prot.",
                        CONST_COLOR_1, remainingTraffic, percentage);
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
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\"><TR "TR_ON">"
		 "<TH "TH_BG" WIDTH=150>IP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH>"
		 "<TH "TH_BG" WIDTH=250>Percentage</TH></TR>\n");

      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local2remote.value/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP",
				"TCP", "UDP", total, percentage);

      sendString("</TABLE>"TABLE_OFF);
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\"><TR "TR_ON">"
		 "<TH "TH_BG" WIDTH=150>TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH>"
		 "<TH "TH_BG" WIDTH=250 COLSPAN=2>Percentage</TH></TR>\n");

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local2remote.value/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), myGlobals.protoIPTrafficInfos[i],
			  CONST_COLOR_1, partialTotal, percentage);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;IP-based&nbsp;Prot.",
			CONST_COLOR_1, remainingTraffic, percentage);
      }
      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }
  } else {
    total = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value;

    {
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

      printSectionTitle("Global TCP/UDP Protocol Distribution");

      sendString("<CENTER>\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=500><TR "TR_ON"><TH "TH_BG" WIDTH=150>"
		 "TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=50>Data</TH><TH "TH_BG" WIDTH=250 COLSPAN=2>"
		 "Percentage</TH></TR>\n");

      remainingTraffic = 0;

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal  = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local.value
	  +myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote.value;
	partialTotal += (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote2local.value
	  +myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local2remote.value;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  numProtosFound++;
	  printTableEntry(buf, sizeof(buf), myGlobals.protoIPTrafficInfos[i],
			  CONST_COLOR_1, partialTotal/1024, percentage);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Prot.",
			CONST_COLOR_1, remainingTraffic/1024, percentage);
      }

      if(numProtosFound > 0)
	sendString("<TR "TR_ON"><TD "TD_BG" COLSPAN=4 ALIGN=CENTER>"
		   "<IMG SRC=drawGlobalIpProtoDistribution"CHART_FORMAT"></TD></TR>\n");
      sendString("</TABLE>"TABLE_OFF"<P>\n");

      /* *********************** */

      if(remainingTraffic > 0) {
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

	  sendString(""TABLE_ON"<TABLE BORDER=1><TR "TR_ON">"
		     "<TH "TH_BG" colspan=2>TCP/UDP Port</TH>"
		     "<TH "TH_BG">Total</TH><TH "TH_BG">Sent</TH><TH "TH_BG">Rcvd</TH></TR>");

	  qsort(ipPorts, idx, sizeof(PortCounter**), cmpPortsFctn);

	  if(idx > 32) idx = 32; /* Limit to 32 entries max */

	  for(i=0; i<idx; i++) {
	    if(ipPorts[i] != NULL) {
	      char *symPort = getAllPortByNum(ipPorts[i]->port);

	      if(symPort == NULL) symPort = "";

	      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>"
                          "<TH "TH_BG" ALIGN=LEFT><A HREF=\""SHOW_PORT_TRAFFIC"?port=%d\">%s</A></th><td align=right>%d</td>"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			  "</TR>\n",
			  getRowColor(),
			  ipPorts[i]->port, symPort, ipPorts[i]->port,
			  formatBytes(ipPorts[i]->sent+ipPorts[i]->rcvd, 1),
			  formatBytes(ipPorts[i]->sent, 1),
			  formatBytes(ipPorts[i]->rcvd, 1)
			  ) < 0) BufferTooShort();
	      sendString(buf);
	    }
	  } /* for */

	  sendString("<tr><td align=left colspan=5>Notes:<ul>"
		     "<li>sum(total traffic per port) = 2*(total IP traffic)"
		     "<br>because the traffic per port is counted twice (sent and received)"
		     "<li>This report includes broadcast packets</ul></td></tr>\n");
	}
	free(ipPorts);
	sendString("</TABLE>"TABLE_OFF"<P></center>\n");
        if (idx >= 32)
	  sendString(" This extract is just a sample of the packets ntop has seen.");
        sendString("</H5>\n");
      } else {
	sendString("<p>Note:This report includes broadcast packets</p>\n");
	sendString("</CENTER>\n");
      }
    }
  }
}

/* ************************ */

void printProtoTraffic(void) {
  float total, perc;
  char buf[LEN_GENERAL_WORK_BUFFER];

  total = myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value/1024; /* total is expressed in KBytes.value */

  if(total == 0)
    return;

  printSectionTitle("Global Protocol Distribution");
  sendString("<CENTER>\n");
  sendString("<P>"TABLE_ON"<TABLE BORDER=1><TR "TR_ON"><TH "TH_BG" WIDTH=150>Protocol</TH>"
	     "<TH "TH_BG" WIDTH=50>Data</TH><TH "TH_BG" WIDTH=250 COLSPAN=2>Percentage</TH></TR>\n");

  perc = 100*((float)myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value);
  if(perc > 100) perc = 100;

  if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" WIDTH=150 ALIGN=LEFT>IP</TH>"
	      "<TD "TD_BG" WIDTH=50 ALIGN=RIGHT>%s"
	      "</td><td align=right WIDTH=50>%.1f%%</TD><TD "TD_BG" WIDTH=200>"
	      "<TABLE BORDER=1 WIDTH=\"100%%\">",
	      getRowColor(),
	      formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value, 1),
	      perc) < 0)
    BufferTooShort();
  sendString(buf);

  printTableEntry(buf, sizeof(buf), "TCP", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value));
  printTableEntry(buf, sizeof(buf), "UDP", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value));
  printTableEntry(buf, sizeof(buf), "ICMP", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value));

  {
    ProtocolsList *protoList = myGlobals.ipProtosList;    
    int idx = 0;
    
    while(protoList != NULL) {
      printTableEntry(buf, sizeof(buf), protoList->protocolName, CONST_COLOR_1,
		      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx].value/1024,
		      100*((float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx].value/
			   myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value));
      idx++, protoList = protoList->next;
    }
  }

  printTableEntry(buf, sizeof(buf), "Other&nbsp;IP", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value/1024,
		  ((float)myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value/
		   myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value));

  sendString("</TABLE>"TABLE_OFF"</TR>");

  printTableEntry(buf, sizeof(buf), "(R)ARP", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value));
  printTableEntry(buf, sizeof(buf), "DLC", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "IPX", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "Decnet", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].decnetBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].decnetBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "AppleTalk", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "NetBios", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "OSI", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].osiBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].osiBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "IPv6", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "STP", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));

  printTableEntry(buf, sizeof(buf), "Other", CONST_COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value/
		       myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));

  sendString("<TR "TR_ON"><TD "TD_BG" COLSPAN=4 ALIGN=CENTER>"
	     "<IMG SRC=drawGlobalProtoDistribution"CHART_FORMAT"></TD></TR>\n");

  sendString("</TABLE>"TABLE_OFF"<P></CENTER>\n");
}

/* ************************ */

void printProcessInfo(int processPid, int actualDeviceId) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  int i, j, numEntries=0;

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.lsofMutex, "printLsofData");
#endif

  for(i=0; i<myGlobals.numProcesses; i++)
    if((myGlobals.processes[i] != NULL)
       && (myGlobals.processes[i]->pid == processPid))
      break;

  if(myGlobals.processes[i]->pid != processPid) {
    if(snprintf(buf, sizeof(buf), "Unable to find process PID %d", processPid) < 0)
      BufferTooShort();
    printHTMLheader(buf, 0);
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.lsofMutex);
#endif
    return;
  }

  if(snprintf(buf, sizeof(buf), "Info about process %s", myGlobals.processes[i]->command) < 0)
    BufferTooShort();
  printHTMLheader(buf, 0);

  sendString("<CENTER>\n");
  sendString(""TABLE_ON"<TABLE BORDER=1>");

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>User&nbsp;Name</TH>", getRowColor()) < 0)
    BufferTooShort();
  sendString(buf);
  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n", myGlobals.processes[i]->user) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Process&nbsp;PID</TH>", getRowColor()) < 0)
    BufferTooShort();
  sendString(buf);
  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%d</TD></TR>\n", myGlobals.processes[i]->pid) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>First&nbsp;Seen</TH>", getRowColor()) < 0)
    BufferTooShort();
  sendString(buf);
  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
	      formatTime(&myGlobals.processes[i]->firstSeen, 1)) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Last&nbsp;Seen</TH>", getRowColor()) < 0)
    BufferTooShort();
  sendString(buf);
  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
	      formatTime(&myGlobals.processes[i]->lastSeen, 1)) < 0) BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Data&nbsp;Sent</TH>",
	      getRowColor()) < 0) BufferTooShort();
  sendString(buf);
  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
	      formatBytes(myGlobals.processes[i]->bytesSent.value, 1)) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Data&nbsp;Rcvd</TH>", getRowColor()) < 0)
    BufferTooShort();
  sendString(buf);
  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</T></TR>\n",
	      formatBytes(myGlobals.processes[i]->bytesRcvd.value, 1)) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Open&nbsp;TCP&nbsp;Ports"
	      "</TH><TD "TD_BG" ALIGN=RIGHT>", getRowColor()) < 0)
    BufferTooShort();
  sendString(buf);

  for(j=0; j<MAX_IP_PORT; j++)
    if(myGlobals.localPorts[j] != NULL) {
      ProcessInfoList *elem = myGlobals.localPorts[j];

      while(elem != NULL) {
	if(elem->element == myGlobals.processes[i]) {
	  if(snprintf(buf, sizeof(buf), "%d<BR>\n", j) < 0)
	    BufferTooShort();
	  sendString(buf);
	  break;
	}
	elem = elem->next;
      }
    }

  sendString("</TD></TR>\n");

  for(j=0, numEntries=0; j<MAX_NUM_CONTACTED_PEERS; j++)
    if(!emptySerial(&myGlobals.processes[i]->contactedIpPeersSerials[j])) {
      HostTraffic tmpEl;

      if(numEntries == 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Contacted&nbsp;Peers"
		    "</TH><TD "TD_BG" ALIGN=RIGHT>", getRowColor()) < 0)
	  BufferTooShort();
	sendString(buf);
      }

      if(snprintf(buf, sizeof(buf), "%s<BR>\n",
		  makeHostLink(quickHostLink(myGlobals.processes[i]->contactedIpPeersSerials[j], myGlobals.actualReportDeviceId, &tmpEl),
			       0, 0, 0)) < 0) BufferTooShort();
      sendString(buf);
      numEntries++;
    }

  sendString("</TD></TR>\n</TABLE>"TABLE_OFF"</CENTER><P>\n");

#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.lsofMutex);
#endif
}

/* ************************ */

void printLsofData(int mode) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  int i, j, found, processSize;
  int numUsers=0, numProcessesToDisplay;
  ProcessInfo **processesList;
  UsersTraffic usersTraffic[256], *usersTrafficList[256];

  /* ************************ */

  processSize = sizeof(ProcessInfo*)*myGlobals.numProcesses;
  processesList = (ProcessInfo**)malloc(processSize);

  printHTMLheader("Local Network Usage by Process", 0);
  sendString("<CENTER>\n");
  if(snprintf(buf, sizeof(buf), ""TABLE_ON"<TABLE BORDER=1><TR "TR_ON">"
	      "<TH "TH_BG"><A HREF=\"%s?1\">Process</A></TH>"
	      "<TH "TH_BG"><A HREF=\"%s?2\">PID</A></TH>"
	      "<TH "TH_BG"><A HREF=\"%s?3\">User</A></TH>"
	      "<TH "TH_BG"><A HREF=\"%s?4\">Sent</A></TH>"
	      "<TH "TH_BG"><A HREF=\"%s?5\">Rcvd</A></TH></TR>\n",
	      STR_LSOF_DATA, STR_LSOF_DATA, STR_LSOF_DATA,
	      STR_LSOF_DATA, STR_LSOF_DATA) < 0)
    BufferTooShort();
  sendString(buf);

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.lsofMutex, "buildHTMLBrowserWindowsLabel");
#endif

  memcpy(processesList, myGlobals.processes, processSize);
  myGlobals.columnSort = mode;
  qsort(processesList, myGlobals.numProcesses, sizeof(ProcessInfo*), cmpProcesses);

  /* Avoid huge tables */
  numProcessesToDisplay = myGlobals.numProcesses;
  if(numProcessesToDisplay > myGlobals.maxNumLines)
    numProcessesToDisplay = myGlobals.maxNumLines;

  for(i=0, numUsers=0; i<numProcessesToDisplay; i++) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TD "TD_BG"><A HREF=\""PROCESS_INFO_HTML"?%d\">%s</A></TD>"
		"<TD "TD_BG" ALIGN=CENTER>%d</TD>"
		"<TD "TD_BG" ALIGN=CENTER>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		getRowColor(),
		processesList[i]->pid,
		processesList[i]->command,
		processesList[i]->pid,
		processesList[i]->user,
		formatBytes(processesList[i]->bytesSent.value, 1),
		formatBytes(processesList[i]->bytesRcvd.value, 1)) < 0)
      BufferTooShort();
    sendString(buf);

    if((processesList[i]->bytesSent.value > 0) || (processesList[i]->bytesRcvd.value > 0)) {
      for(j=0, found=0; j<numUsers; j++)
	if(strcmp(usersTraffic[j].userName, processesList[i]->user) == 0) {
	  found = 1;
	  break;
	}

      if(!found) {
	usersTraffic[numUsers].userName = processesList[i]->user;
	usersTrafficList[numUsers] = &usersTraffic[numUsers];
	usersTraffic[j].bytesSent = usersTraffic[j].bytesRcvd = 0;
	numUsers++;
      }

      usersTraffic[j].bytesSent += processesList[i]->bytesSent.value;
      usersTraffic[j].bytesRcvd += processesList[i]->bytesRcvd.value;
    }
  }

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");

  /* ************************ */

  printSectionTitle("Local Network Usage by Port");
  sendString("<CENTER>\n");
  sendString(""TABLE_ON"<TABLE BORDER=1><TR "TR_ON"><TH "TH_BG">Port</TH>"
	     "<TH "TH_BG">Processes</TH></TR>\n");

  for(i=0; i<MAX_IP_PORT; i++)
    if(myGlobals.localPorts[i] != NULL) {
      ProcessInfoList *scanner;

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TD "TD_BG" ALIGN=CENTER>%d</TD><TD "TD_BG">",
		  getRowColor(), i) < 0) BufferTooShort();
      sendString(buf);

      scanner = myGlobals.localPorts[i];

      while(scanner != NULL) {
	if(snprintf(buf, sizeof(buf), "<li><A HREF=\""PROCESS_INFO_HTML"?%d\">%s</A><BR>\n",
		    scanner->element->pid, scanner->element->command) < 0)
	  BufferTooShort();
	sendString(buf);
	scanner = scanner->next;
      }

      sendString("</TR>");
    }

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");

  /* ******************************* */

  if(numUsers > 0) {
    qsort(usersTrafficList, numUsers, sizeof(UsersTraffic**), cmpUsersTraffic);

    /* Avoid huge tables */
    if(numUsers > myGlobals.maxNumLines)
      numUsers = myGlobals.maxNumLines;

    printSectionTitle("Local Network Usage by User");
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1><TR "TR_ON"><TH "TH_BG">User</TH>"
	       "<TH "TH_BG">Traffic&nbsp;in/out</TH></TR>\n");

    for(i=0; i<numUsers; i++) {
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TD "TD_BG">%s</TD>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(),
		  usersTrafficList[i]->userName,
		  formatBytes((Counter)(usersTrafficList[i]->bytesSent+
					usersTrafficList[i]->bytesRcvd), 1)) < 0)
	BufferTooShort();
      sendString(buf);
    }

    sendString("</TABLE>"TABLE_OFF"<P></CENTER>\n");
  }

#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.lsofMutex);
#endif

  free(processesList);
}

/* ************************ */

void printIpTrafficMatrix(void) {
  int i, j, numEntries=0, numConsecutiveEmptyCells;
  char buf[LEN_GENERAL_WORK_BUFFER];
  short *activeHosts;
  Counter minTraffic=(Counter)LONG_MAX, maxTraffic=0, avgTraffic;
  Counter avgTrafficLow, avgTrafficHigh, tmpCounter;

  printHTMLheader("IP Subnet Traffic Matrix", 0);

  if(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix == NULL) {
    printFlagedWarning("<I>Traffic matrix is not available for the selected network interface</I>");
    return;
  }

  activeHosts = (short*)malloc(sizeof(short)*myGlobals.device[myGlobals.actualReportDeviceId].numHosts);

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
	sendString(""TABLE_ON"<TABLE BORDER=1><TR "TR_ON"><TH "TH_BG" ALIGN=LEFT><SMALL>&nbsp;F&nbsp;"
		   "&nbsp;&nbsp;To<br>&nbsp;r<br>&nbsp;o<br>&nbsp;m</SMALL></TH>\n");
      }

      if(snprintf(buf, sizeof(buf), "<TH "TH_BG" ALIGN=CENTER><SMALL>%s</SMALL></TH>",
		  getHostName(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i], 1)) < 0)
	BufferTooShort();
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

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT><SMALL>%s</SMALL></TH>",
		  getRowColor(), makeHostLink(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i],
					      FLAG_HOSTLINK_TEXT_FORMAT, 1, 0)) < 0)
	BufferTooShort();
      sendString(buf);

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
	      if(snprintf(buf, sizeof(buf), "<TD "TD_BG" COLSPAN=%d>&nbsp;</TD>\n",
			  numConsecutiveEmptyCells) < 0) BufferTooShort();
	      sendString(buf);
	      numConsecutiveEmptyCells = 0;
	    }

	    tmpCounter = myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value+
	      myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value;
	    /* Fix below courtesy of Danijel Doriae <danijel.doric@industrogradnja.tel.hr> */
	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER %s>"
			"<A HREF=# onMouseOver=\"window.status='"
			"%s';return true\" onMouseOut="
			"\"window.status='';return true\"><SMALL>%s</SMALL></A></TH>\n",
			calculateCellColor(tmpCounter, avgTrafficLow, avgTrafficHigh),
			buildHTMLBrowserWindowsLabel(i, j),
			formatBytes(tmpCounter, 1)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	}
      }

      if(numConsecutiveEmptyCells > 0) {
	if(snprintf(buf, sizeof(buf), "<TD "TD_BG" COLSPAN=%d>&nbsp;</TD>\n",
		    numConsecutiveEmptyCells) < 0)
	  BufferTooShort();
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
  char label[32], label1[32], buf[LEN_GENERAL_WORK_BUFFER];
  time_t tmpTime;
  struct tm t;
  HostTraffic *el;

  printHTMLheader("Network Load Statistics Matrix", 0);

  switch(sortedColumn) {
  case 1:
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1>\n<TR "TR_ON">"
	       "<TH "TH_BG">Sampling Period</TH>"
	       "<TH "TH_BG">Average Thpt</TH>"
	       "<TH "TH_BG">Top Hosts Sent Thpt</TH>"
	       "<TH "TH_BG">Top Hosts Rcvd Thpt</TH></TR>\n");

    for(i=0; i<60; i++) {
      if(myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].trafficValue == 0)
	break;

      tmpTime = myGlobals.actTime-(i*60);
      strftime(label, 32, "%H:%M", localtime_r(&tmpTime, &t));
      tmpTime = myGlobals.actTime-((i+1)*60);
      strftime(label1, 32, "%H:%M", localtime_r(&tmpTime, &t));
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TD "TD_BG" ALIGN=CENTER>"
		  "<B>%s&nbsp;-&nbsp;%s</B></TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=LEFT>"
		  "<TABLE BORDER=1 WIDTH=100%%>",
		  getRowColor(), label1, label,
		  formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				   last60MinutesThpt[i].trafficValue)) < 0)
	BufferTooShort();
      sendString(buf);

      dataSent = 0;

      /* ************************* */

      if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].topHostSentSerial)) {
	HostTraffic tmpEl;

	if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       last60MinutesThpt[i].topHostSentSerial, myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
		      formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				       last60MinutesThpt[i].topSentTraffic.value)) < 0)
	    BufferTooShort();
	  sendString(buf); dataSent = 1;
	}
      }

      if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].secondHostSentSerial)) {
	HostTraffic tmpEl;

	if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       last60MinutesThpt[i].secondHostSentSerial, myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
		      formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				       last60MinutesThpt[i].secondSentTraffic.value)) < 0)
	    BufferTooShort();
	  sendString(buf); dataSent = 1;
	}
      }

      if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].thirdHostSentSerial)) {
	HostTraffic tmpEl;
	  
	if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       last60MinutesThpt[i].thirdHostSentSerial, myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
		      formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				       last60MinutesThpt[i].thirdSentTraffic.value)) < 0)
	    BufferTooShort();
	  sendString(buf); dataSent = 1;
	}
      }

      /* ************************* */

      if(!dataSent) sendString("&nbsp;");
      sendString("</TABLE>"TABLE_OFF"</TD><TD "TD_BG" ALIGN=LEFT><TABLE BORDER=1 WIDTH=100%%>\n");
      dataSent = 0;

      /* ************************* */

      if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].topHostRcvdSerial)) {
	HostTraffic tmpEl;

	if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       last60MinutesThpt[i].topHostRcvdSerial, myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
		      formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				       last60MinutesThpt[i].topRcvdTraffic.value)) < 0)
	    BufferTooShort();
	  sendString(buf); dataSent = 1;
	}
      }

      if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].secondHostRcvdSerial)) {
	HostTraffic tmpEl;

	if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       last60MinutesThpt[i].secondHostRcvdSerial, myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
		      formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				       last60MinutesThpt[i].secondRcvdTraffic.value)) < 0)
	    BufferTooShort();
	  sendString(buf); dataSent = 1;
	}
      }

      if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].thirdHostRcvdSerial)) {
	HostTraffic tmpEl;

	if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       last60MinutesThpt[i].thirdHostRcvdSerial, myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
		      formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				       last60MinutesThpt[i].thirdRcvdTraffic.value)) < 0)
	    BufferTooShort();
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
      return;
    } else {
      sendString("<CENTER>\n");
      sendString(""TABLE_ON"<TABLE BORDER=1>\n<TR "TR_ON">"
		 "<TH "TH_BG">Sampling Period</TH>"
		 "<TH "TH_BG">Average Thpt</TH>"
		 "<TH "TH_BG">Top Thpt Sent Hosts</TH>"
		 "<TH "TH_BG">Top Rcvd Sent Hosts</TH>"
		 "</TR>\n");

      for(i=0; i<24; i++) {
	if(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].trafficValue == 0)
	  break;

	tmpTime = myGlobals.actTime-(i*60*60);
	strftime(label, 32, "%H:%M", localtime_r(&tmpTime, &t));
	tmpTime = myGlobals.actTime-((i+1)*60*60);
	strftime(label1, 32, "%H:%M", localtime_r(&tmpTime, &t));
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TD "TD_BG" ALIGN=CENTER><B>%s&nbsp;-&nbsp;%s</B></TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=LEFT>"TABLE_ON"<TABLE BORDER=1>",
		    getRowColor(), label, label1,
		    formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				     last24HoursThpt[i].trafficValue)) < 0)
	  BufferTooShort();
	sendString(buf);

	/* ************************* */

	if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].topHostSentSerial)) {
	  HostTraffic tmpEl;

	  if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].topHostSentSerial,
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last24HoursThpt[i].topSentTraffic.value)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	}

	if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].secondHostSentSerial)) {
	  HostTraffic tmpEl;

	  if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].secondHostSentSerial,
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last24HoursThpt[i].secondSentTraffic.value)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	}

	if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].thirdHostSentSerial)) {
	  HostTraffic tmpEl;

	  if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].thirdHostSentSerial,
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last24HoursThpt[i].thirdSentTraffic.value)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	}

	/* ************************* */

	sendString("&nbsp;");
	sendString("</TABLE>"TABLE_OFF"</TD><TD "TD_BG" ALIGN=LEFT>"TABLE_ON"<TABLE BORDER=1>\n");

	/* ************************* */

	if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].topHostRcvdSerial)) {
	  HostTraffic tmpEl;

	  if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].topHostRcvdSerial,
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last24HoursThpt[i].topRcvdTraffic.value)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	}

	if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].secondHostRcvdSerial)) {
	  HostTraffic tmpEl;

	  if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].secondHostRcvdSerial,
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last24HoursThpt[i].secondRcvdTraffic.value)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	}

	if(!emptySerial(&myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].thirdHostRcvdSerial)) {
	  HostTraffic tmpEl;

	  if((el = quickHostLink(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].thirdHostRcvdSerial,
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last24HoursThpt[i].thirdRcvdTraffic.value)) < 0)
	      BufferTooShort();
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
}

/* ************************ */

void printThptStats(int sortedColumn _UNUSED_) {
  char tmpBuf[128];

  printHTMLheader("Network Load Statistics", 0);

  if(myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
    printFlagedWarning("<I>Network load statistics are not available for virtual interfaces</I>");
    return;
  }

  if(myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples == 0) {
    printNoDataYet();
    return;
  }

  sendString("<CENTER>\n");

  sendString("<A HREF=\"thptStatsMatrix.html?col=1\" BORDER=0>"
	     "<IMG SRC=\"thptGraph"CHART_FORMAT"?col=1\"></A><BR>\n");
  if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4>",
	      formatTimeStamp(0, 0, 0),
	      formatTimeStamp(0, 0, 60)) < 0) BufferTooShort();

  sendString(tmpBuf);

  if(myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples > 60) {
    sendString("<P><A HREF=\"thptStatsMatrix.html?col=2\" BORDER=0>"
	       "<IMG SRC=\"thptGraph"CHART_FORMAT"?col=2\"></A><BR>\n");
    if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4>",
		formatTimeStamp(0, 0, 0),
		formatTimeStamp(0, 24, 0)) < 0) BufferTooShort();

    sendString(tmpBuf);

    if(myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples > 1440 /* 60 * 24 */) {
      sendString("<P><IMG SRC=\"thptGraph"CHART_FORMAT"?col=3\"><BR>\n");
      if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4>",
		  formatTimeStamp(0, 0, 0),
		  formatTimeStamp(30, 0, 0)) < 0)
	BufferTooShort();
      sendString(tmpBuf);
    }
  }

  sendString("</CENTER>\n");
}

/* ************************ */

static int cmpStatsFctn(const void *_a, const void *_b) {
  DomainStats *a = (DomainStats *)_a;
  DomainStats *b = (DomainStats *)_b;
  Counter a_, b_;
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

  switch(myGlobals.columnSort) {
  case 1:
    rc = strcasecmp(a->domainHost->dotDomainName, b->domainHost->dotDomainName);
    if(rc == 0)
      return(strcasecmp(a->domainHost->fullDomainName, b->domainHost->fullDomainName));
    else
      return rc;
  case 2: a_  = a->bytesSent.value, b_ = b->bytesSent.value; break;
  case 3: a_  = a->bytesRcvd.value, b_ = b->bytesRcvd.value; break;
  case 4: a_  = a->tcpSent.value  , b_ = b->tcpSent.value;   break;
  case 5: a_  = a->tcpRcvd.value  , b_ = b->tcpRcvd.value;   break;
  case 6: a_  = a->udpSent.value  , b_ = b->udpSent.value;   break;
  case 7: a_  = a->udpRcvd.value  , b_ = b->udpRcvd.value;   break;
  case 8: a_  = a->icmpSent.value , b_ = b->icmpSent.value;  break;
  case 9: a_  = a->icmpRcvd.value , b_ = b->icmpRcvd.value;  break;
  default:
  case 0:
    if(domainSort) {
      /*
	if((a->domainHost == NULL) || (a->domainHost->fullDomainName == NULL)) printf("A is NULL!\n");
	if((b->domainHost == NULL) || (b->domainHost->fullDomainName == NULL)) printf("B is NULL!\n");
      */
      return(strcasecmp(a->domainHost->fullDomainName, b->domainHost->fullDomainName));
    } else {
      accessAddrResMutex("fillDomainName");
      rc = strcasecmp(a->domainHost->hostSymIpAddress, b->domainHost->hostSymIpAddress);
      releaseAddrResMutex();
    }

    return(rc);
  }

  if(a_ < b_)
    return(1);
  else if (a_ > b_)
    return(-1);
  else
    return(0);
}

/* ****************************************** */

/* if myGlobals.domainName == NULL -> print all domains */
void printDomainStats(char* domainName, int sortedColumn, int revertOrder, int pageNum) {
  u_int idx, tmpIdx, numEntries=0, printedEntries=0, len, maxHosts;
  u_short keyValue=0;
  HostTraffic *el;
  char buf[LEN_GENERAL_WORK_BUFFER];
  DomainStats **stats, *tmpStats, *statsEntry;
  char htmlAnchor[2*LEN_GENERAL_WORK_BUFFER], htmlAnchor1[2*LEN_GENERAL_WORK_BUFFER], *sign, *arrowGif, *arrow[48], *theAnchor[48];
  Counter totBytesSent=0, totBytesRcvd=0;

  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */
  len = sizeof(DomainStats)*maxHosts;
  tmpStats = (DomainStats*)malloc(len);
  memset(tmpStats, 0, len);

  /* Fix below courtesy of Francis Pintos <francis@arhl.com.hk> */
  len = sizeof(DomainStats**)*maxHosts;
  stats = (DomainStats**)malloc(len);
  memset(stats, 0, len);

  /* traceEvent(CONST_TRACE_INFO, "'%s' '%d' '%d'", domainName, sortedColumn, revertOrder); */

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG ALT=\"Decending order, click to reverse\" SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG ALT=\"Ascending order, click to reverse\" SRC=arrow_down.gif BORDER=0>";
  }

  if(domainName == NULL)
    domainSort = 1;
  else
    domainSort = 0;

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    fillDomainName(el);

    if((el->fullDomainName == NULL)
       || (el->fullDomainName[0] == '\0')
       || (el->dotDomainName == NULL)
       || (el->hostSymIpAddress[0] == '\0')
       || (el->dotDomainName == '\0')
       || broadcastHost(el)
       ) {
      continue;
    } else if((domainName != NULL)
	      && (strcmp(el->fullDomainName, domainName) != 0)) {
      continue;
    }

    if(domainName == NULL) {
      for(keyValue=0, tmpIdx=0; el->fullDomainName[tmpIdx] != '\0'; tmpIdx++)
	keyValue += (tmpIdx+1)*(u_short)el->fullDomainName[tmpIdx];

      keyValue %= maxHosts;

      while((stats[keyValue] != NULL)
	    && (strcasecmp(stats[keyValue]->domainHost->fullDomainName, el->fullDomainName) != 0))
	keyValue = (keyValue+1) % myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize;

      if(stats[keyValue] != NULL)
	statsEntry = stats[keyValue];
      else {
	statsEntry = &tmpStats[numEntries++];
	memset(statsEntry, 0, sizeof(DomainStats));
	statsEntry->domainHost = el;
	stats[keyValue] = statsEntry;
	/* traceEvent(CONST_TRACE_INFO, "[%d] %s/%s", numEntries, el->fullDomainName, el->dotDomainName); */
      }
    } else {
      statsEntry = &tmpStats[numEntries++];
      memset(statsEntry, 0, sizeof(DomainStats));
      statsEntry->domainHost = el;
      stats[keyValue++] = statsEntry;
    }

    totBytesSent          += el->bytesSent.value;
    statsEntry->bytesSent.value += el->bytesSent.value;
    statsEntry->bytesRcvd.value += el->bytesRcvd.value;
    totBytesRcvd          += el->bytesRcvd.value;
    statsEntry->tcpSent.value   += el->tcpSentLoc.value + el->tcpSentRem.value;
    statsEntry->udpSent.value   += el->udpSentLoc.value + el->udpSentRem.value;
    statsEntry->icmpSent.value  += el->icmpSent.value;
    statsEntry->tcpRcvd.value   += el->tcpRcvdLoc.value + el->tcpRcvdFromRem.value;
    statsEntry->udpRcvd.value   += el->udpRcvdLoc.value + el->udpRcvdFromRem.value;
    statsEntry->icmpRcvd.value  += el->icmpRcvd.value;

    if(numEntries >= maxHosts) break;
  } /* for(;;) */

  if((domainName == NULL) || (numEntries == 0)) {
    snprintf(buf, sizeof(buf), "Internet Domain Stats");
  } else {
    snprintf(buf, sizeof(buf), "Stats for Domain %s", domainName);
  }
  printHTMLheader(buf, 0);

  if(numEntries == 0) {
    printNoDataYet();
    free(tmpStats); free(stats);
    return;
  }

  myGlobals.columnSort = sortedColumn;

  qsort(tmpStats, numEntries, sizeof(DomainStats), cmpStatsFctn);

  /* avoid division by zero */
  if(totBytesSent == 0)
    totBytesSent = 1;
  if(totBytesRcvd == 0)
    totBytesRcvd = 1;

  if(domainName == NULL) {
    if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", STR_DOMAIN_STATS, sign) < 0)
      BufferTooShort();
    if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=", STR_DOMAIN_STATS) < 0)
      BufferTooShort();
  } else {
    if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?dom=%s&col=%s",
		DOMAIN_INFO_HTML, domainName, sign) < 0)
      BufferTooShort();
    if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?dom=%s&col=",
		DOMAIN_INFO_HTML, domainName) < 0)
      BufferTooShort();
  }

  if(abs(myGlobals.columnSort) == 0) {
    arrow[0] = arrowGif;
    theAnchor[0] = htmlAnchor;
  } else {
    arrow[0] = "";
    theAnchor[0] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 1) {
    arrow[1] = arrowGif;
    theAnchor[1] = htmlAnchor;
  } else {
    arrow[1] = "";
    theAnchor[1] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 2) {
    arrow[2] = arrowGif;
    theAnchor[2] = htmlAnchor;
  } else {
    arrow[2] = "";
    theAnchor[2] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 3) {
    arrow[3] = arrowGif;
    theAnchor[3] = htmlAnchor;
  } else {
    arrow[3] = "";
    theAnchor[3] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 4) {
    arrow[4] = arrowGif;
    theAnchor[4] = htmlAnchor;
  } else {
    arrow[4] = "";
    theAnchor[4] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 5) {
    arrow[5] = arrowGif;
    theAnchor[5] = htmlAnchor;
  } else {
    arrow[5] = "";
    theAnchor[5] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 6) {
    arrow[6] = arrowGif;
    theAnchor[6] = htmlAnchor;
  } else {
    arrow[6] = "";
    theAnchor[6] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 7) {
    arrow[7] = arrowGif;
    theAnchor[7] = htmlAnchor;
  } else {
    arrow[7] = "";
    theAnchor[7] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 8) {
    arrow[8] = arrowGif;
    theAnchor[8] = htmlAnchor;
  } else {
    arrow[8] = "";
    theAnchor[8] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 9) {
    arrow[9] = arrowGif;
    theAnchor[9] = htmlAnchor;
  } else {
    arrow[9] = "";
    theAnchor[9] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 10) {
    arrow[10] = arrowGif;
    theAnchor[10] = htmlAnchor;
  } else {
    arrow[10] = "";
    theAnchor[10] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 11) {
    arrow[11] = arrowGif;
    theAnchor[11] = htmlAnchor;
  } else {
    arrow[11] = "";
    theAnchor[11] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 12) {
    arrow[12] = arrowGif;
    theAnchor[12] = htmlAnchor;
  } else {
    arrow[12] = "";
    theAnchor[12] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 13) {
    arrow[13] = arrowGif;
    theAnchor[13] = htmlAnchor;
  } else {
    arrow[13] = "";
    theAnchor[13] = htmlAnchor1;
  }

  if(abs(myGlobals.columnSort) == 14) {
    arrow[14] = arrowGif;
    theAnchor[14] = htmlAnchor;
  } else {
    arrow[14] = "";
    theAnchor[14] = htmlAnchor1;
  }

  /* Split below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
  sendString("<CENTER>\n");
  if(snprintf(buf, sizeof(buf),
	      ""TABLE_ON"<TABLE BORDER=1><TR "TR_ON">"
	      "<TH "TH_BG">%s0>Name%s</A></TH>"
	      "<TH "TH_BG">%s1>Domain%s</A></TH>"
	      "<TH "TH_BG" COLSPAN=2>%s2>Sent%s</A></TH>"
	      "<TH "TH_BG" COLSPAN=2>%s3>Rcvd%s</A></TH>"
	      "<TH "TH_BG">%s4>TCP&nbsp;Sent%s</A></TH>",
	      theAnchor[0], arrow[0],
	      theAnchor[1], arrow[1],
	      theAnchor[2], arrow[2],
	      theAnchor[3], arrow[3],
	      theAnchor[4], arrow[4]) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
	      "<TH "TH_BG">%s5>TCP&nbsp;Rcvd%s</A></TH>"
	      "<TH "TH_BG">%s6>UDP&nbsp;Sent%s</A></TH>"
	      "<TH "TH_BG">%s7>UDP&nbsp;Rcvd%s</A></TH>"
	      "<TH "TH_BG">%s8>ICMP&nbsp;Sent%s</A></TH>"
	      "<TH "TH_BG">%s9>ICMP&nbsp;Rcvd%s</A></TH>",
	      theAnchor[5], arrow[5],
	      theAnchor[6], arrow[6],
	      theAnchor[7], arrow[7],
	      theAnchor[8], arrow[8],
	      theAnchor[9], arrow[9]) < 0)
    BufferTooShort();
  sendString(buf);

  for(idx=pageNum*myGlobals.maxNumLines; idx<numEntries; idx++) {
    if(revertOrder)
      statsEntry = &tmpStats[numEntries-idx-1];
    else
      statsEntry = &tmpStats[idx];

    if(domainName == NULL) {
      if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?dom=%s>%s</A>",
		  DOMAIN_INFO_HTML, statsEntry->domainHost->fullDomainName,
		  statsEntry->domainHost->fullDomainName) < 0)
	BufferTooShort();
    } else {
      char tmpBuf[64], *hostLink;
      int blankId;

      accessAddrResMutex("getHostIcon");

      blankId = strlen(statsEntry->domainHost->hostSymIpAddress)-
	strlen(statsEntry->domainHost->fullDomainName)-1;

      strncpy(tmpBuf, statsEntry->domainHost->hostSymIpAddress, sizeof(tmpBuf));

      releaseAddrResMutex();

      if((blankId > 0)
	 && (strcmp(&tmpBuf[blankId+1], domainName) == 0))
	tmpBuf[blankId] = '\0';

      hostLink = makeHostLink(statsEntry->domainHost, FLAG_HOSTLINK_TEXT_FORMAT, 1, 0);

      len = strlen(hostLink); if(len >= sizeof(htmlAnchor)) len = sizeof(htmlAnchor)-1;
      strncpy(htmlAnchor, hostLink, len);
      htmlAnchor[len] = '\0';
    }


    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=CENTER>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%%</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%%</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		getRowColor(), htmlAnchor,
		getHostCountryIconURL(statsEntry->domainHost),
		formatBytes(statsEntry->bytesSent.value, 1),
		(100*((float)statsEntry->bytesSent.value/(float)totBytesSent)),
		formatBytes(statsEntry->bytesRcvd.value, 1),
		(100*((float)statsEntry->bytesRcvd.value/(float)totBytesRcvd)),
		formatBytes(statsEntry->tcpSent.value, 1),
		formatBytes(statsEntry->tcpRcvd.value, 1),
		formatBytes(statsEntry->udpSent.value, 1),
		formatBytes(statsEntry->udpRcvd.value, 1),
		formatBytes(statsEntry->icmpSent.value, 1),
		formatBytes(statsEntry->icmpRcvd.value, 1)
		) < 0) BufferTooShort();
    sendString(buf);

    /* Avoid huge tables */
    if(printedEntries++ > myGlobals.maxNumLines)
      break;
  }

  sendString("</TABLE>"TABLE_OFF"</HTML>\n");
  sendString("</CENTER>\n");

  if(domainName != NULL) {
    if(snprintf(buf, sizeof(buf), "%s?dom=%s", DOMAIN_INFO_HTML, domainName) < 0)
      BufferTooShort();
  } else {
    if(snprintf(buf, sizeof(buf), "%s", STR_DOMAIN_STATS) < 0)
      BufferTooShort();
  }

  addPageIndicator(buf, pageNum, numEntries,
		   myGlobals.maxNumLines,
		   revertOrder, abs(sortedColumn));

  free(tmpStats); free(stats);
}

/* ************************* */

void printNoDataYet(void) {
  printFlagedWarning("<I>No Data To Display (yet)</I>");
}

/* ************************* */

void printNotAvailable(char * flagName) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  if(snprintf(buf, sizeof(buf), "<I>The requested data is not available when ntop is"
	      "<br>started with the command line flag %s</I>",
	      flagName) < 0)
    BufferTooShort();
  printFlagedWarning(buf);
}

/* ************************* */

void listNetFlows(void) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  int numEntries=0;
  FlowFilterList *list = myGlobals.flowsList;

  printHTMLheader(NULL, 0);

  if(list != NULL) {
    while(list != NULL) {
      if(list->pluginStatus.activePlugin) {
	if(numEntries == 0) {
	  printSectionTitle("Network Flows");
 	  sendString("<CENTER>\n");
	  sendString(""TABLE_ON"<TABLE BORDER=1><TR "TR_ON"><TH "TH_BG">Flow Name</TH>"
  		     "<TH "TH_BG">Packets</TH><TH "TH_BG">Traffic</TH></TR>");
  	}

	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s"
		    "</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		    getRowColor(), list->flowName,
		    formatPkts(list->packets.value),
		    formatBytes(list->bytes.value, 1)) < 0) BufferTooShort();
	sendString(buf);

	numEntries++;
      }

      list = list->next;
    }

    if(numEntries > 0)
      sendString("</TABLE>"TABLE_OFF"\n");

    sendString("</CENTER>\n");
  }

  if(numEntries == 0) {
    sendString("<CENTER><P><H1>No Available/Active Network Flows</H1><p>"
	       " (see <A HREF=ntop.html>man</A> page)</CENTER>\n");
  }
}

/* *********************************** */

void printHostHourlyTraffic(HostTraffic *el) {
  Counter tcSent, tcRcvd;
  int i, hourId;
  char theDate[8];
  struct tm t;

  if(el->trafficDistribution == NULL) return;

  strftime(theDate, 8, "%H", localtime_r(&myGlobals.actTime, &t));
  hourId = atoi(theDate);

  printSectionTitle("Host Traffic Stats");
  sendString("<CENTER>\n");
  sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=100%%>\n<TR>");
  sendString("<TH "TH_BG">Time</TH>");
  sendString("<TH "TH_BG">Tot. Traffic Sent</TH>");
  sendString("<TH "TH_BG">% Traffic Sent</TH>");
  sendString("<TH "TH_BG">Tot. Traffic Rcvd</TH>");
  sendString("<TH "TH_BG">% Traffic Rcvd</TH></TR>");

  for(i=0, tcSent=0, tcRcvd=0; i<24; i++) {
    tcSent += el->trafficDistribution ->last24HoursBytesSent[i].value;
    tcRcvd += el->trafficDistribution ->last24HoursBytesRcvd[i].value;
  }

  sendString("<TR><TH "TH_BG" ALIGN=LEFT>Midnight - 1AM</TH>\n");
  printHostHourlyTrafficEntry(el, 0, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>1AM - 2AM</TH>\n");
  printHostHourlyTrafficEntry(el, 1, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>2AM - 3AM</TH>\n");
  printHostHourlyTrafficEntry(el, 2, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>3AM - 4AM</TH>\n");
  printHostHourlyTrafficEntry(el, 3, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>4AM - 5AM</TH>\n");
  printHostHourlyTrafficEntry(el, 4, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>5AM - 6AM</TH>\n");
  printHostHourlyTrafficEntry(el, 5, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>6AM - 7AM</TH>\n");
  printHostHourlyTrafficEntry(el, 6, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>7AM - 8AM</TH>\n");
  printHostHourlyTrafficEntry(el, 7, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>8AM - 9AM</TH>\n");
  printHostHourlyTrafficEntry(el, 8, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>9AM - 10AM</TH>\n");
  printHostHourlyTrafficEntry(el, 9, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>10AM - 11AM</TH>\n");
  printHostHourlyTrafficEntry(el, 10, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>11AM - Noon</TH>\n");
  printHostHourlyTrafficEntry(el, 11, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>Noon - 1PM</TH>\n");
  printHostHourlyTrafficEntry(el, 12, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>1PM - 2PM</TH>\n");
  printHostHourlyTrafficEntry(el, 13, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>2PM - 3PM</TH>\n");
  printHostHourlyTrafficEntry(el, 14, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>3PM - 4PM</TH>\n");
  printHostHourlyTrafficEntry(el, 15, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>4PM - 5PM</TH>\n");
  printHostHourlyTrafficEntry(el, 16, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>5PM - 6PM</TH>\n");
  printHostHourlyTrafficEntry(el, 17, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>6PM - 7PM</TH>\n");
  printHostHourlyTrafficEntry(el, 18, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>7PM - 8PM</TH>\n");
  printHostHourlyTrafficEntry(el, 19, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>8PM - 9PM</TH>\n");
  printHostHourlyTrafficEntry(el, 20, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>9PM - 10PM</TH>\n");
  printHostHourlyTrafficEntry(el, 21, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>10PM - 11PM</TH>\n");
  printHostHourlyTrafficEntry(el, 22, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>11PM - Midnight</TH>\n");
  printHostHourlyTrafficEntry(el, 23, tcSent, tcRcvd);

  sendString("</TABLE>"TABLE_OFF"\n</CENTER>\n");
}

/* ************************** */

static void dumpHostsCriteria(NtopInterface *ifName, u_char criteria) {
  u_int numEntries=0, i, maxHosts;
  HostTraffic **tmpTable, *el;
  char buf[LEN_GENERAL_WORK_BUFFER];

  maxHosts = ifName->hostsno; /* save it as it can change */
  tmpTable = (HostTraffic**)malloc(maxHosts*sizeof(HostTraffic*));
  memset(tmpTable, 0, maxHosts*sizeof(HostTraffic*));

  switch(criteria) {
  case 0: /* AS */
    myGlobals.columnSort = 10;
    break;
  case 1: /* VLAN */
    myGlobals.columnSort = 11;
    break;
  }

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    switch(criteria) {
    case 0: /* AS */
      getHostAS(el);
      if(el->hostAS > 0)  tmpTable[numEntries++] = el;
      break;
    case 1: /* VLAN */
      if(el->vlanId > 0)  tmpTable[numEntries++] = el;
      break;
    }

    if(numEntries >= maxHosts)
      break;
  }

  if(numEntries > 0) {
    int lastId = 0;
    qsort(tmpTable, numEntries, sizeof(HostTraffic*), sortHostFctn);

    if(snprintf(buf, sizeof(buf), "<CENTER>"TABLE_ON"<TABLE BORDER=1>\n<TR "TR_ON">"
		"<TH "TH_BG">%s</A></TH><TH "TH_BG">Hosts</TH></TR>",
		criteria == 0 ? "AS" : "VLAN") < 0)
      BufferTooShort();
    sendString(buf);

    for(i=0; i<numEntries; i++) {
      el = tmpTable[numEntries-i-1];

      if(((criteria == 0) && (lastId != el->hostAS))
	 || ((criteria == 1) && (lastId != el->vlanId))) {
	if(i > 0) sendString("</TR>");

	if(criteria == 0 /* AS */) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=RIGHT>"
		      "<A HREF=\"http://ws.arin.net/cgi-bin/whois.pl?queryinput=AS%d\">%d</A>"
		      "</TH><TH "TH_BG" ALIGN=LEFT>", el->hostAS, el->hostAS) < 0)
	    BufferTooShort();
	} else {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=RIGHT>%d</TH><TH "TH_BG" ALIGN=LEFT>",
		      el->vlanId) < 0)
	    BufferTooShort();
	}

	sendString(buf);
	lastId = el->hostAS;
      }

      sendString(makeHostLink(el, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0));
      sendString("<br>\n");
    }

    sendString("</TR>\n</TABLE>\n</CENTER>");
  } else {
    printFlagedWarning("<I>No entries to display(yet)</I>");
  }

  free(tmpTable);
}

/* ************************** */

void printASList(unsigned int deviceId) {
  printHTMLheader("Autonomous Systems Traffic Statistics", 0);

  if(deviceId > myGlobals.numDevices) {
    printFlagedWarning("<I>Invalid device specified</I>");
    return;
  }

  dumpHostsCriteria(&myGlobals.device[deviceId], 0 /* AS */);
}

/* ******************************* */

void printVLANList(unsigned int deviceId) {
  printHTMLheader("VLAN Traffic Statistics", 0);

  if(deviceId > myGlobals.numDevices) {
    printFlagedWarning("<I>Invalid device specified</I>");
    return;
  }

  dumpHostsCriteria(&myGlobals.device[deviceId], 1 /* VLAN */);
}

/* ******************************************* */

static int recentlyUsedPort(HostTraffic *el, u_short portNr, int serverPort) {
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
  int numRecords = 0;
  HostTraffic *el;

  str = getAllPortByNum(portNr);

  if(str[0] == '?') {
    if(snprintf(buf, sizeof(buf), "Recent Users of Port %u", portNr) < 0)
      BufferTooShort();
  } else {
    if(snprintf(buf, sizeof(buf), "Recent Users of Port %u (%s)", portNr, str) < 0)
      BufferTooShort();
  }

  printHTMLheader(buf, 0);
  sendString("<CENTER>\n");


  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(recentlyUsedPort(el, portNr, 0)) {      
      if(numRecords == 0) {
	sendString("<TABLE BORDER>\n<TR><TH>Client</TH><TH>Server</TH></TR>\n");
	sendString("<TR>\n<TD>\n");
      }

      sendString("\n<LI> ");
      sendString(makeHostLink(el, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0));
      numRecords++;
    }
  }

  if(numRecords > 0) {
    sendString("\n&nbsp;\n</TD><TD>\n");
  }

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(el && recentlyUsedPort(el, portNr, 1)) {
      if(numRecords == 0) {
	sendString("<TABLE BORDER>\n<TR><TH>Client</TH><TH>Server</TH></TR>\n");
	sendString("<TR>\n<TD>\n");
	sendString("\n&nbsp;\n</TD><TD>\n");
      }

      sendString("\n<LI> ");
      sendString(makeHostLink(el, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0));
      numRecords++;
    }
  }

  if(numRecords == 0) {
    sendString("<P>No hosts found: the information for this port has been purged in the meantime</CENTER><P>\n");
  } else
    sendString("\n&nbsp;\n</TD>\n</TR>\n</TABLE>\n</CENTER>");    

}
