/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
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
  (void)setsignal(signalId, ignoreSignal);
}
#endif

/* ******************************* */

void initReports(void) {
#ifndef MICRO_NTOP
  myGlobals.columnSort = 0;
#endif
  addDefaultAdminUser();
}

#ifndef MICRO_NTOP

/* **************************************** */

int reportValues(time_t *lastTime) {
  if(myGlobals.maxNumLines <= 0)
    myGlobals.maxNumLines = MAX_NUM_TABLE_ROWS;

  *lastTime = time(NULL) + myGlobals.refreshRate;

  /*
    Make sure that the other flags are't set. They have
    no effect in web mode
  */
  if(myGlobals.refreshRate == 0)
    myGlobals.refreshRate = REFRESH_TIME;
  else if(myGlobals.refreshRate < MIN_REFRESH_TIME)
    myGlobals.refreshRate = MIN_REFRESH_TIME;

  return(0);
}

/* ******************************* */

void addPageIndicator(char *url, u_int pageNum,
		      u_int numEntries, u_int linesPerPage,
		      int revertOrder, int numCol) {
  char buf[BUF_SIZE/2], prevBuf[BUF_SIZE/2], nextBuf[BUF_SIZE/2], shortBuf[16], separator;
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
		url, separator, pageNum+1, shortBuf,
		url, separator, numPages-1, shortBuf) < 0)
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

void printTrafficStatistics() {
  Counter unicastPkts, avgPktLen;
  int i;
  char buf[BUF_SIZE];
  struct pcap_stat pcapStats;

  unicastPkts = 0;
  printHTMLheader("Global Traffic Statistics", 0);

  sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1>\n");

  sendString("<TR "TR_ON"><TH "TH_BG">Nw Interface Type</TH>"
	     "<TD "TD_BG" ALIGN=RIGHT>");

  if(myGlobals.mergeInterfaces) {
    for(i=0; i<myGlobals.numDevices; i++) {
      if(i > 0) sendString("<br>");

      if(myGlobals.rFileName == NULL) {
	char buf1[128], buf2[64];

	if(snprintf(buf, sizeof(buf), "%s (%s%s) [%s/%s]",
		    myGlobals.device[i].name, getNwInterfaceType(i),
		    myGlobals.device[i].virtualDevice ? " virtual" : "",
		    _intoa(myGlobals.device[i].network, buf1, sizeof(buf1)),
		    _intoa(myGlobals.device[i].netmask, buf2, sizeof(buf2))
		    ) < 0)
	  BufferTooShort();
	sendString(buf);

	if(haveTrafficHistory()) {
	  if(!myGlobals.device[i].virtualDevice) {
	    if(snprintf(buf, sizeof(buf),
		      "  [ <A HREF=\"/ntop-bin/netTraf.pl?interface=%s\">History</A> ]\n",
			myGlobals.device[i].name) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	}
      } else {
	if(snprintf(buf, sizeof(buf), "%s [%s]",
		    getNwInterfaceType(i), PCAP_NW_INTERFACE) < 0)
	  BufferTooShort();
	sendString(buf);
      }
    }
  } else {
    /* myGlobals.mergeInterfaces == 0 */
      if(!myGlobals.device[myGlobals.actualReportDeviceId].virtualDevice) {
	if(snprintf(buf, sizeof(buf), "%s [%s]",
		    getNwInterfaceType(myGlobals.actualReportDeviceId),
		    myGlobals.device[myGlobals.actualReportDeviceId].name) < 0)
	  BufferTooShort();
	sendString(buf);
      }

      if(haveTrafficHistory()) {
	if(snprintf(buf, sizeof(buf), " <A HREF=\"/ntop-bin/netTraf.pl?interface=%s\">History</A>\n",
		    myGlobals.device[myGlobals.actualReportDeviceId].name) < 0)
	  BufferTooShort();
	sendString(buf);
      }
  }

  sendString("</TD></TR>\n");

  if(myGlobals.domainName[0] != '\0') {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG">Local Domain Name</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;</TD></TR>\n",
		myGlobals.domainName) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG">Sampling Since</TH>"
	      "<TD "TD_BG" ALIGN=RIGHT>%s [%s]</TD></TR>\n",
	      ctime(&myGlobals.initialSniffTime),
	      formatSeconds(myGlobals.actTime-myGlobals.initialSniffTime)) < 0)
    BufferTooShort();
  sendString(buf);

  if((myGlobals.currentFilterExpression != NULL)
     && (myGlobals.currentFilterExpression[0] != '\0')) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG">Traffic Filter</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		myGlobals.currentFilterExpression) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value > 0) {
    Counter dummyCounter;
    sendString("<TR><TH "TH_BG">Packets</TH><TD "TH_BG">\n<TABLE BORDER=1 WIDTH=100%>");

#ifdef HAVE_GDCHART
    if(myGlobals.mergeInterfaces && (myGlobals.numDevices > 1)) {
      int numRealDevices=0;

      for(i=0; i<myGlobals.numDevices; i++)
	if(!myGlobals.device[i].virtualDevice)
	  numRealDevices++;

      if(numRealDevices > 1)
	sendString("<TR "TR_ON"><TD "TD_BG" ALIGN=CENTER COLSPAN=3>"
		   "<IMG SRC=interfaceTrafficPie"CHART_FORMAT"></TD></TR>\n");
    }
#endif

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

#ifdef MULTITHREADED
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

#ifdef HAVE_GDCHART
    if(myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value > 0)
      sendString("<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
		 "<IMG SRC=pktCastDistribPie"CHART_FORMAT"></TH></TR>\n");
#endif

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

#ifdef HAVE_GDCHART
    if(myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value > 0)
      sendString("<TR "TR_ON" BGCOLOR=white><TH "TH_BG" ALIGN=CENTER COLSPAN=3>"
		 "<IMG SRC=pktSizeDistribPie"CHART_FORMAT"></TH></TR>\n");
#endif

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

    /* ****************** */

    sendString("</TABLE>"TABLE_OFF"</TR><TR><TH "TH_BG">Traffic</TH><TD "TH_BG">\n<TABLE BORDER=1 WIDTH=100%>");
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>Total</th>"
		"<TD "TD_BG" align=right COLSPAN=2>%s [%s Pkts.value]</td></TR>\n",
		getRowColor(),
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value, 1),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value)) < 0)
      BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" align=left>IP Traffic</th>"
		"<TD "TD_BG" align=right COLSPAN=2>%s [%s Pkts.value]</td></TR>\n",
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

#ifdef HAVE_GDCHART
    if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value > 0)
      sendString("<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
		 "<IMG SRC=ipTrafficPie"CHART_FORMAT"></TH></TR>\n");
#endif

    /* ********************* */

    if(myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value > 0) {
      int avgPktTTL;

      avgPktTTL = (16*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32.value
		   +48*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64.value
		   +80*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96.value
		   +112*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128.value
		   +144*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160.value
		   +176*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192.value
		   +208*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224.value
		   +240*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo255.value)/
	myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;

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

#ifdef HAVE_GDCHART
	sendString("<TR "TR_ON"><TH BGCOLOR=white COLSPAN=3>"
		   "<IMG SRC=pktTTLDistribPie"CHART_FORMAT"></TH></TR>\n");
#endif
      }
    }

    sendString("</TABLE>"TABLE_OFF"</TR>");

    /* ************************ */

#ifdef HAVE_GDCHART
    sendString("<TR><TH "TH_BG">Remote Hosts Distance</TH><TD "TH_BG">"
	       "<IMG SRC=hostsDistanceChart"CHART_FORMAT"></TD></TR>\n");
#endif /* HAVE_GDCHART */

    /* ********************* */

    updateThpt();

    sendString("<TR><TH "TH_BG">Network Load</TH><TD "TH_BG">\n<TABLE BORDER=1 WIDTH=100%>");
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
		formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value/(myGlobals.actTime-myGlobals.initialSniffTime)),
		/* Bug below fixed courtesy of Eddy Lai <eddy@ModernTerminals.com> */
		((float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value/(float)(myGlobals.actTime-myGlobals.initialSniffTime))) < 0)
      BufferTooShort();
    sendString(buf);

  }

  sendString("</TABLE>"TABLE_OFF"</TR></TABLE></CENTER>\n");
}

/* ******************************* */

void printHostsTraffic(int reportType,
		       int sortedColumn,
		       int revertOrder,
		       int pageNum,
		       char* url) {
  u_int idx, numEntries=0;
  int printedEntries=0, hourId;
  char theDate[8];
  struct tm t;
  HostTraffic *el;
  HostTraffic** tmpTable;
  char buf[BUF_SIZE];
  float sentPercent=0, rcvdPercent=0;
  Counter totIpBytesSent=0, totIpBytesRcvd=0;
  Counter totEthBytesSent=0, totEthBytesRcvd=0;

  strftime(theDate, 8, "%H", localtime_r(&myGlobals.actTime, &t));
  hourId = atoi(theDate);

  memset(buf, 0, sizeof(buf));
  tmpTable = (HostTraffic**)malloc(myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));
  memset(tmpTable, 0, myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));

  switch(reportType) {
  case 0:
  case 1:
  case 2:
  case 3:
    snprintf(buf, sizeof(buf), "Network Traffic: Data Received");
    break;
  case 4:
  case 5:
  case 6:
  case 7:
    snprintf(buf, sizeof(buf), "Network Traffic: Data Sent");
    break;
  }

  printHTMLheader(buf, 0);
  printHeader(reportType, revertOrder, abs(sortedColumn));

  for(idx=1; idx<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; idx++) {
    if((idx != myGlobals.otherHostEntryIdx)
       && ((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && (broadcastHost(el) == 0)) {
      if((myGlobals.sortSendMode && (el->bytesSent.value > 0))
	 || ((!myGlobals.sortSendMode) && (el->bytesRcvd.value > 0))) {
	if(((reportType == 1    /* STR_SORT_DATA_RECEIVED_IP */)
	    || (reportType == 6 /* STR_SORT_DATA_SENT_IP     */))
	   && (el->hostNumIpAddress[0] == '\0')) continue;
	tmpTable[numEntries++]=el;
      }
    }
  }

  if(numEntries > 0) {
    /*
      The switch below is needed to:
      - sort data according to the selected column
      - 'recycle' (somebody would call this "code reuse") the cmpFctn function
    */

    myGlobals.columnSort = 0;

    if(sortedColumn == HOST_DUMMY_IDX_VALUE)
      myGlobals.columnSort = HOST_DUMMY_IDX_VALUE; /* Host name */
    else if(sortedColumn == DOMAIN_DUMMY_IDX_VALUE)
      myGlobals.columnSort = DOMAIN_DUMMY_IDX_VALUE; /* domain name */
    else
      myGlobals.columnSort = sortedColumn;

    /*
       reportType:

        0 STR_SORT_DATA_RECEIVED_PROTOS
        1 STR_SORT_DATA_RECEIVED_IP
        2 STR_SORT_DATA_RECEIVED_THPT
	3 STR_SORT_DATA_RCVD_HOST_TRAFFIC
	4 STR_SORT_DATA_SENT_HOST_TRAFFIC
        5 STR_SORT_DATA_SENT_PROTOS
        6 STR_SORT_DATA_SENT_IP
        7 STR_SORT_DATA_SENT_THPT
        8 TRAFFIC_STATS_HTML
    */

#ifdef DEBUG
    traceEvent(TRACE_INFO, ">reportType=%d/sortedColumn=%d/myGlobals.columnSort=%d<\n",
	       reportType, sortedColumn, myGlobals.columnSort);
#endif

    myGlobals.reportKind = reportType;
    /* if(myGlobals.columnSort == 0) myGlobals.reportKind = 0;*/

    quicksort(tmpTable, numEntries, sizeof(HostTraffic*), cmpFctn);

    switch(reportType) {
    case 0: /* STR_SORT_DATA_RECEIVED_PROTOS */
    case 5: /* STR_SORT_DATA_SENT_PROTOS */
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
    case 1: /* STR_SORT_DATA_RECEIVED_IP */
    case 6: /* STR_SORT_DATA_SENT_IP */
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
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, "totIpBytesSent=%u, totIpBytesRcvd=%u", 
	       totIpBytesSent, totIpBytesRcvd);
#endif

    for(idx=pageNum*myGlobals.maxNumLines; idx<numEntries; idx++) {
      int i;
      char webHostName[BUF_SIZE];

      if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	switch(reportType) {
        case 0: /* STR_SORT_DATA_RECEIVED_PROTOS */
        case 5: /* STR_SORT_DATA_SENT_PROTOS */
	  sentPercent = (100*(float)el->bytesSent.value)/totEthBytesSent;
	  rcvdPercent = (100*(float)el->bytesRcvd.value)/totEthBytesRcvd;
	  break;
	case 1: /* STR_SORT_DATA_RECEIVED_IP */
        case 6: /* STR_SORT_DATA_SENT_IP */
	  sentPercent = (100*(float)el->ipBytesSent.value)/totIpBytesSent;
	  rcvdPercent = (100*(float)el->ipBytesRcvd.value)/totIpBytesRcvd;
	  break;
	case 2: /* STR_SORT_DATA_RECEIVED_THPT */
	case 3: /* STR_SORT_DATA_RCVD_HOST_TRAFFIC */
	case 4: /* STR_SORT_DATA_SENT_HOST_TRAFFIC */
        case 7: /* STR_SORT_DATA_SENT_THPT */
        case 8: /* TRAFFIC_STATS_HTML */
	  sentPercent = rcvdPercent = 0;
	  break;
	}
	
	/* Fixed buffer overflow.
	   Courtesy of Rainer Tammer <rainer.tammer@spg.schulergroup.com>
	*/

	strncpy(webHostName, makeHostLink(el, LONG_FORMAT, 0, 1), sizeof(webHostName));

	switch(reportType) {
	case 0: /* STR_SORT_DATA_RECEIVED_PROTOS */
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
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      formatBytes(el->ospfRcvd.value, 1),
		      formatBytes(el->netbiosRcvd.value, 1),
		      formatBytes(el->igmpRcvd.value, 1),
		      formatBytes(el->osiRcvd.value, 1),
		      formatBytes(el->qnxRcvd.value, 1),
		      formatBytes(el->stpRcvd.value, 1),
		      formatBytes(el->otherRcvd.value, 1)
		      ) < 0) BufferTooShort();

	  sendString(buf);
	  break;
	case 5: /* STR_SORT_DATA_SENT_PROTOS */
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
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      formatBytes(el->ospfSent.value, 1),
		      formatBytes(el->netbiosSent.value, 1),
		      formatBytes(el->igmpSent.value, 1),
		      formatBytes(el->osiSent.value, 1),
		      formatBytes(el->qnxSent.value, 1),
		      formatBytes(el->stpSent.value, 1),
		      formatBytes(el->otherSent.value, 1)
		      ) < 0) BufferTooShort();

	  sendString(buf);
	  break;
	case 1: /* STR_SORT_DATA_RECEIVED_IP */
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
	case 6: /* STR_SORT_DATA_SENT_IP */
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
	case 2: /* STR_SORT_DATA_RECEIVED_THPT */
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
	case 7: /* STR_SORT_DATA_SENT_THPT */
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
	case 3: /* STR_SORT_DATA_RCVD_HOST_TRAFFIC */
	case 4: /* STR_SORT_DATA_SENT_HOST_TRAFFIC */
	case 8: /* TRAFFIC_STATS_HTML */
	  {
	    if(snprintf(buf, sizeof(buf), "<TR %s>%s", getRowColor(), webHostName) < 0)
	      BufferTooShort();
	    sendString(buf);
	    printHostThtpShort(el, 1);
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
  sendString("</CENTER>\n");

  addPageIndicator(url, pageNum, numEntries, myGlobals.maxNumLines,
		   revertOrder, abs(sortedColumn));

  myGlobals.lastRefreshTime = myGlobals.actTime;
  free(tmpTable);
}

/* ******************************* */

void printMulticastStats(int sortedColumn /* ignored so far */,
			 int revertOrder,
			 int pageNum) {
  u_int idx, numEntries=0;
  int printedEntries=0;
  HostTraffic *el;
  HostTraffic** tmpTable;
  char buf[BUF_SIZE], *sign, *theAnchor[6], *arrow[6], *arrowGif;
  char htmlAnchor[64], htmlAnchor1[64];

  memset(buf, 0, sizeof(buf));
  tmpTable = (HostTraffic**)malloc(myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));
  memset(tmpTable, 0, myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));

  /* All the ALT tags courtesy of "Burton M. Strauss III" <BStrauss3@attbi.com> */
  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG ALT=\"Ascending order, click to reverse\" SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG ALT=\"Descending order, click to reverse\" SRC=arrow_down.gif BORDER=0>";
  }

  for(idx=1; idx<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; idx++) {
    if((idx != myGlobals.otherHostEntryIdx)
       && ((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && ((el->pktMulticastSent.value > 0) || (el->pktMulticastRcvd.value > 0))
       && (!broadcastHost(el))
       )
      tmpTable[numEntries++] = el;
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

    quicksort(tmpTable, numEntries, sizeof(HostTraffic*), cmpMulticastFctn);

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
		    getRowColor(), makeHostLink(el, LONG_FORMAT, 0, 1),
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
  } else
    printNoDataYet();

  free(tmpTable);
}


/* ******************************* */

void printHostsInfo(int sortedColumn, int revertOrder, int pageNum) {
  u_int idx, numEntries;
  int printedEntries=0;
  unsigned short maxBandwidthUsage=1 /* avoid divisions by zero */;
  struct hostTraffic *el;
  struct hostTraffic** tmpTable;
  char buf[BUF_SIZE], *arrowGif, *sign, *arrow[12], *theAnchor[12];
  char htmlAnchor[64], htmlAnchor1[64];

  memset(buf, 0, sizeof(buf));
  tmpTable = (HostTraffic**)malloc(myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));
  memset(tmpTable, 0, myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));

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

  for(idx=1, numEntries=0; idx<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; idx++)
    if((idx != myGlobals.otherHostEntryIdx)
       && ((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) != NULL)) {
      unsigned short actUsage;

      actUsage = (unsigned short)(100*((float)el->bytesSent.value/
				       (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));

      el->actBandwidthUsage = actUsage;
      if(el->actBandwidthUsage > maxBandwidthUsage)
	maxBandwidthUsage = actUsage;

      tmpTable[numEntries++]=el;
    }

  if(numEntries > 0) {
    int i;

    quicksort(tmpTable, numEntries, sizeof(struct hostTraffic*), sortHostFctn);

    if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", HOSTS_INFO_HTML, sign) < 0)
      BufferTooShort();
    if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=", HOSTS_INFO_HTML) < 0)
      BufferTooShort();

    for(i=1; i<=8; i++) {
      if(abs(myGlobals.columnSort) == i) {
	arrow[i] = arrowGif;
	theAnchor[i] = htmlAnchor;
      } else {
	arrow[i] = "";
	theAnchor[i] = htmlAnchor1;
      }
    }

    if(abs(myGlobals.columnSort) == DOMAIN_DUMMY_IDX_VALUE) {
      arrow[0] = arrowGif;
      theAnchor[0] = htmlAnchor;
    } else {
      arrow[0] = "";
      theAnchor[0] = htmlAnchor1;
    }

    if(snprintf(buf, sizeof(buf), "<CENTER>"TABLE_ON"<TABLE BORDER=1>\n<TR "TR_ON">"
		"<TH "TH_BG">%s1>Host%s</A></TH>"
		"<TH "TH_BG">%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
		"</TH><TH "TH_BG">%s2>IP&nbsp;Address%s</A></TH>\n"
		"<TH "TH_BG">%s3>MAC&nbsp;Address%s</A></TH>"
		"<TH "TH_BG">%s6>Other&nbsp;Name(s)%s</A></TH>"
		"<TH "TH_BG">%s4>Sent&nbsp;Bandwidth%s</A></TH>"
		"<TH "TH_BG">%s5>Nw&nbsp;Board&nbsp;Vendor%s</A></TH>"
		"<TH "TH_BG">%s7>Hops&nbsp;Distance%s</A></TH>"
		"</TR>\n",
		theAnchor[1], arrow[1],
		theAnchor[0], arrow[0],
		theAnchor[2], arrow[2],
		theAnchor[3], arrow[3],
		theAnchor[6], arrow[6],
		theAnchor[4], arrow[4],
		theAnchor[5], arrow[5],
		theAnchor[7], arrow[7]
		) < 0)
      BufferTooShort();
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

	  tmpName2 = getVendorInfo(el->ethAddress, 1);
	  if(tmpName2[0] == '\0')
	    tmpName2 = myGlobals.separator;

	  tmpName3 = el->ethAddressString;
	  if((tmpName3[0] == '\0')
	     || (strcmp(tmpName3, "00:00:00:00:00:00") == 0))
	    tmpName3 = myGlobals.separator;

	  if((el->hostIpAddress.s_addr != 0)
	     && (getSniffedDNSName(el->hostNumIpAddress, sniffedName, sizeof(sniffedName)))) {
#ifdef DEBUG
	    traceEvent(TRACE_INFO, "%s <=> %s [%s/%s]",
		       el->hostNumIpAddress, sniffedName,
		       el->hostSymIpAddress, el->hostNumIpAddress);
#endif

            if((el->hostSymIpAddress[0] == '\0') || strcmp(sniffedName, el->hostSymIpAddress)) {
	      if((el->hostSymIpAddress[0] == '\0')
		 || (strcmp(el->hostSymIpAddress, el->hostNumIpAddress) == 0)) {
		if(strlen(sniffedName) >= (MAX_HOST_SYM_NAME_LEN-1))
		  sniffedName[MAX_HOST_SYM_NAME_LEN-2] = '\0';
		strcpy(el->hostSymIpAddress, sniffedName);
	      } else
		displaySniffedName=1;
	    }
	  }

	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>"
		      "%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      getRowColor(),
		      makeHostLink(el, LONG_FORMAT, 0, 1),
		      tmpName1, tmpName3) < 0)
	    BufferTooShort();
	  sendString(buf);

	  sendString("<TD "TD_BG" ALIGN=RIGHT NOWRAP>");

	  if(el->nbHostName || el->atNetwork || el->ipxHostName || displaySniffedName) {
	    short numAddresses = 0;

	    if(el->nbHostName && el->nbDomainName) {
	      if((el->nbAccountName != NULL) && ((el->nbAccountName[0] != '0'))) {
		if((el->nbDomainName != NULL) && (el->nbDomainName[0] != '0')) {
		  if(snprintf(buf, sizeof(buf), "%s&nbsp;%s@%s&nbsp;[%s]", getOSFlag("Windows", 0),
			      el->nbAccountName, el->nbHostName, el->nbDomainName) < 0)
		 BufferTooShort();
		} else {
		  if(snprintf(buf, sizeof(buf), "%s&nbsp;%s@%s", getOSFlag("Windows", 0),
			      el->nbAccountName, el->nbHostName) < 0)
		    BufferTooShort();
		}
	      } else {
		if((el->nbDomainName != NULL) && (el->nbDomainName[0] != '0')) {
		  if(snprintf(buf, sizeof(buf), "%s&nbsp;%s&nbsp;[%s]", getOSFlag("Windows", 0),
			      el->nbHostName, el->nbDomainName) < 0)
		    BufferTooShort();
		} else {
		  if(snprintf(buf, sizeof(buf), "%s&nbsp;%s", getOSFlag("Windows", 0),
			      el->nbHostName) < 0)
		    BufferTooShort();
		}
	      }
	      sendString(buf);
	      numAddresses++;
	    } else if(el->nbHostName) {
	      if(snprintf(buf, sizeof(buf), "%s&nbsp;%s", getOSFlag("Windows", 0),
			  el->nbHostName) < 0) BufferTooShort();
	      sendString(buf);
	      numAddresses++;
	    }

	    if(el->nbDescr) {
	      if(snprintf(buf, sizeof(buf), ":&nbsp;%s", el->nbDescr) < 0)
		BufferTooShort();
	      sendString(buf);
	    }

	    if (displaySniffedName) {
	      if(numAddresses > 0) sendString("/");
              snprintf(buf, sizeof(buf), "%s", sniffedName);
	      sendString(buf);
	      numAddresses++;
            }

	    if(el->atNetwork) {
	      char *nodeName = el->atNodeName;

	      if(numAddresses > 0) sendString("/");
	      if(nodeName == NULL) nodeName = "";

	      if(snprintf(buf, sizeof(buf), "%s&nbsp;%s&nbsp;",
			  getOSFlag("Mac", 0), nodeName) < 0)
		BufferTooShort();
	      sendString(buf);

	      if(el->atNodeType[0] != NULL) {
		sendString("(");
		for(i=0; i<MAX_NODE_TYPES; i++)
		  if(el->atNodeType[i] == NULL)
		    break;
		  else {
		    if(i > 0) sendString("/");
		    sendString(el->atNodeType[i]);
		  }

		sendString(")&nbsp;");
	      }

	      if(snprintf(buf, sizeof(buf), "[%d.%d]",
			  el->atNetwork, el->atNode) < 0)
		BufferTooShort();
	      sendString(buf);
	      numAddresses++;
	    }

	    if(el->ipxHostName) {
	      int numSap=0;

	      if(numAddresses > 0) sendString("/");
	      if(snprintf(buf, sizeof(buf), "%s&nbsp;%s&nbsp;",
			  getOSFlag("Novell", 0),
			  el->ipxHostName) < 0)
		BufferTooShort();
	      sendString(buf);

	      for(i=0; i<el->numIpxNodeTypes; i++) {
		char *str = getSAPInfo(el->ipxNodeType[i], 1);
		
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
	  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>", tmpName2) < 0)
	    BufferTooShort();
	  sendString(buf);

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

#if 0
	  /* Time distance */
	  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s-",
		      formatLatency(el->minLatency, STATE_ACTIVE)) < 0)
	    BufferTooShort();
	  sendString(buf);

	  if(snprintf(buf, sizeof(buf), "%s</TD>",
		      formatLatency(el->maxLatency, STATE_ACTIVE)) < 0)
	    BufferTooShort();
	  sendString(buf);
#endif

	  sendString("</TR>\n");
	  printedEntries++;
	}

	/* Avoid huge tables */
	if(printedEntries > myGlobals.maxNumLines)
	  break;
      } else {
	traceEvent(TRACE_WARNING, "WARNING: quicksort() problem!");
      }
    }

    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");

    addPageIndicator(HOSTS_INFO_HTML, pageNum, numEntries, myGlobals.maxNumLines,
		     revertOrder, abs(sortedColumn));
  }

  free(tmpTable);
}

/* ************************************ */

void printAllSessionsHTML(char* host, int actualDeviceId) {
  u_int idx, elIdx, i;
  HostTraffic *el=NULL;
  char buf[BUF_SIZE];
  u_short found = 0;

  for(elIdx=0; elIdx<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; elIdx++) {
    el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[elIdx];

    if((elIdx != myGlobals.broadcastEntryIdx)
       && (elIdx != myGlobals.otherHostEntryIdx)
       && (el != NULL)
       && ((strcmp(el->hostNumIpAddress, host) == 0)
	   || (strcmp(el->ethAddressString, host) == 0))) {
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
    sendHTTPHeader(HTTP_TYPE_HTML, 0);

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
    for(idx=1; idx<TOP_ASSIGNED_IP_PORTS /* 1024 */; idx++) {
      if(el->portsUsage[idx] != NULL) {
	char *svc = getAllPortByNum(idx);
	char webHostName[BUF_SIZE];
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

	  if(el->portsUsage[idx]->clientUsesLastPeer == NO_PEER)
	    peerHost = NULL;
	  else
	    peerHost = myGlobals.device[myGlobals.actualReportDeviceId].
	      hash_hostTraffic[checkSessionIdx(el->portsUsage[idx]->clientUsesLastPeer)];

	  if(peerHost == NULL) {
	    /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
	    strncpy(webHostName, "&nbsp;", sizeof(webHostName));
	  } else
	    strncpy(webHostName, makeHostLink(peerHost, SHORT_FORMAT, 0, 0), sizeof(webHostName));

	  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d/%s</TD>"
		      "<TD "TD_BG" ALIGN=CENTER>%s</TD>",
		      el->portsUsage[idx]->clientUses,
		      formatBytes(el->portsUsage[idx]->clientTraffic.value, 1),
		      webHostName) < 0) BufferTooShort();
	  sendString(buf);
	} else
	  sendString("<TD "TD_BG">&nbsp;</TD><TD "TD_BG">&nbsp;</TD>");

	if(el->portsUsage[idx]->serverUses > 0) {

	  if(el->portsUsage[idx]->serverUsesLastPeer == NO_PEER)
	    peerHost = NULL;
	  else
	    peerHost = myGlobals.device[myGlobals.actualReportDeviceId].
	      hash_hostTraffic[checkSessionIdx(el->portsUsage[idx]->serverUsesLastPeer)];

	  if(peerHost == NULL) {
	    /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
	    strncpy(webHostName, "&nbsp;", sizeof(webHostName));
	  } else
	    strncpy(webHostName, makeHostLink(peerHost, SHORT_FORMAT, 0, 0), sizeof(webHostName));

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
	if(snprintf(buf, sizeof(buf), "<li>%s\n",
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
	if(snprintf(buf, sizeof(buf), "<LI>%s\n",
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

  if(el->fileList != NULL) {
    FileList *list = el->fileList;

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

      if(FD_ISSET(P2P_UPLOAD_MODE, &list->fileFlags))   sendString("<IMG SRC=/upload.gif ALT=Upload VALIGN=MIDDLE>&nbsp;");
      if(FD_ISSET(P2P_DOWNLOAD_MODE, &list->fileFlags)) sendString("<IMG SRC=/download.gif ALT=Download VALIGN=MIDDLE>&nbsp;");

      list = list->next;
    }

    sendString("\n</ol></TD></TR></TABLE></CENTER>\n");
  }

  /* *************************************************** */

  printHostSessions(el, elIdx, actualDeviceId);
}

/* ************************************ */

void printLocalRoutersList(int actualDeviceId) {
  char buf[BUF_SIZE];
  HostTraffic *el, router;
  u_int idx, i, j, numEntries=0;
  HostSerial routerList[MAX_NUM_ROUTERS];

  printHTMLheader("Local Subnet Routers", 0);

  if(myGlobals.dontTrustMACaddr) {
    printNotAvailable();
    return;
  }

  for(idx=1; idx<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; idx++) {
    if((idx != myGlobals.otherHostEntryIdx) &&
       ((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && subnetLocalHost(el)) {

      for(j=0; j<MAX_NUM_CONTACTED_PEERS; j++)
	if(el->contactedRouters.peersIndexes[j] != NO_PEER) {
	  short found = 0;

	  for(i=0; i<numEntries; i++) {
	    if(el->contactedRouters.peersIndexes[j] == routerList[i]) {
	      found = 1;
	      break;
	    }
	  }

	  if((found == 0) && (numEntries < MAX_NUM_ROUTERS)) {
	    routerList[numEntries++] = el->contactedRouters.peersIndexes[j];
	  }
	}
    }
  }

  if(numEntries == 0) {
    printNoDataYet();
    return;
  } else {
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1><TR "TR_ON"><TH "TH_BG">Router Name</TH>"
	       "<TH "TH_BG">Used by</TH></TR>\n");

    for(i=0; i<numEntries; i++) {
      if(retrieveHost(routerList[i], &router) == 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=left>%s</TH><TD "TD_BG" ALIGN=LEFT><UL>\n",
		    getRowColor(),
		    makeHostLink(&router, SHORT_FORMAT, 0, 0)) < 0) BufferTooShort();
	sendString(buf);

	for(idx=1; idx<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; idx++)
	  if((idx != myGlobals.otherHostEntryIdx) &&
	     ((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
	     && subnetLocalHost(el)) {
	    for(j=0; j<MAX_NUM_CONTACTED_PEERS; j++)
	      if(el->contactedRouters.peersIndexes[j] == routerList[i]) {
		if(snprintf(buf, sizeof(buf), "<LI>%s</LI>\n",
			    makeHostLink(el, SHORT_FORMAT, 0, 0)) < 0)
		  BufferTooShort();
		sendString(buf);
		break;
	      }
	  }

	sendString("</OL></TD></TR>\n");
      }
    }

    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");
  }
}

/* ************************************ */

void printIpAccounting(int remoteToLocal, int sortedColumn,
		       int revertOrder, int pageNum) {
  u_int idx, numEntries;
  int printedEntries=0;
  HostTraffic *el, **tmpTable;
  char buf[BUF_SIZE], *str=NULL, *sign, *title=NULL;
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
  tmpTable = (HostTraffic**)malloc(myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));
  memset(tmpTable, 0, myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));

  for(idx=1, numEntries=0; idx<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; idx++)
    if(/* (idx != myGlobals.otherHostEntryIdx) && */
       ((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && (broadcastHost(el) == 0) /* No broadcast addresses please */
       && (multicastHost(el) == 0) /* No multicast addresses please */
       && ((el->hostNumIpAddress[0] != '\0')
	   && (el->hostIpAddress.s_addr != '0' /* 0.0.0.0 */)
	   /* This host speaks IP */)) {
      switch(remoteToLocal) {
      case REMOTE_TO_LOCAL_ACCOUNTING:
	if(!subnetPseudoLocalHost(el)) {
	  if((el->bytesSentLoc.value > 0) || (el->bytesRcvdLoc.value > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentLoc.value;
	    totalBytesRcvd += el->bytesRcvdLoc.value;
	  }
	}
	break;
      case LOCAL_TO_REMOTE_ACCOUNTING:
	if(subnetPseudoLocalHost(el)) {
	  if((el->bytesSentRem.value > 0) || (el->bytesRcvdFromRem.value > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentRem.value;
	    totalBytesRcvd += el->bytesRcvdFromRem.value;
	  }
	}
	break;
      case LOCAL_TO_LOCAL_ACCOUNTING:
	if(subnetPseudoLocalHost(el)) {
	  if((el->bytesSentLoc.value > 0) || (el->bytesRcvdLoc.value > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentLoc.value;
	    totalBytesRcvd += el->bytesRcvdLoc.value;
	  }
	}
	break;
      }
    }

  switch(remoteToLocal) {
  case REMOTE_TO_LOCAL_ACCOUNTING:
    str = IP_R_2_L_HTML;
    title = "Remote to Local IP Traffic";
    break;
  case LOCAL_TO_REMOTE_ACCOUNTING:
    str = IP_L_2_R_HTML;
    title = "Local to Remote IP Traffic";
    break;
  case LOCAL_TO_LOCAL_ACCOUNTING:
    str = IP_L_2_L_HTML;
    title = "Local IP Traffic";
    break;
  }

  printHTMLheader(title, 0);

  if(numEntries > 0) {
    myGlobals.columnSort = sortedColumn;
    myGlobals.sortFilter = remoteToLocal;
    quicksort(tmpTable, numEntries, sizeof(struct hostTraffic*), cmpHostsFctn);

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
    if(snprintf(buf, sizeof(buf), ""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\">\n<TR "TR_ON"><TH "TH_BG">"
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
	case REMOTE_TO_LOCAL_ACCOUNTING:
	  a = el->bytesSentLoc.value;
	  b = el->bytesRcvdLoc.value;
	  break;
	case LOCAL_TO_REMOTE_ACCOUNTING:
	  a = el->bytesSentRem.value;
	  b = el->bytesRcvdFromRem.value;
	  break;
	case LOCAL_TO_LOCAL_ACCOUNTING:
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
		makeHostLink(el, LONG_FORMAT, 0, 0),
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
    if(remoteToLocal == LOCAL_TO_LOCAL_ACCOUNTING)
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
  } else
    printNoDataYet();

  free(tmpTable);
}

/* ********************************** */

void printActiveTCPSessions(int actualDeviceId, int pageNum) {
  int idx, realNumSessions;
  char buf[BUF_SIZE];
  int numSessions, printedSessions;

  printHTMLheader("Active TCP Sessions", 0);

  if(!myGlobals.enableSessionHandling) {
    printNotAvailable();
    return;
  }

  /* Let's count sessions first */
  for(idx=1, realNumSessions=0; idx<myGlobals.device[myGlobals.actualReportDeviceId].numTotSessions; idx++)
    if((idx != myGlobals.otherHostEntryIdx)
       && (myGlobals.device[myGlobals.actualReportDeviceId].tcpSession[idx] != NULL)) {
      realNumSessions++;
    }

  /*
    Due to the way sessions are handled, sessions before those to
    display need to be skipped
  */

  for(idx=1, numSessions=0, printedSessions=0;
      idx<myGlobals.device[myGlobals.actualReportDeviceId].numTotSessions; idx++)
    if((idx != myGlobals.otherHostEntryIdx)
       && (myGlobals.device[myGlobals.actualReportDeviceId].tcpSession[idx] != NULL)) {
      char *sport, *dport;
      Counter dataSent, dataRcvd;
      IPSession *session = myGlobals.device[myGlobals.actualReportDeviceId].tcpSession[idx];

      while((session != NULL) && (printedSessions < myGlobals.maxNumLines)) {
#ifndef PRINT_ALL_SESSIONS
	if(session->sessionState != STATE_ACTIVE) {
	  session = session->next;
	  continue;
	}
#endif

	if((numSessions++) < pageNum*myGlobals.maxNumLines) {
	  session = session->next;
	  continue;
	}

	if(printedSessions == 0) {
	  sendString("<CENTER>\n");
	  sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\"><TR "TR_ON">"
		     "<TH "TH_BG">Client</TH>"
		     "<TH "TH_BG">Server</TH>"
		     "<TH "TH_BG">Data&nbsp;Sent</TH>"
		     "<TH "TH_BG">Data&nbsp;Rcvd</TH>"
		     "<TH "TH_BG">Active&nbsp;Since</TH>"
		     "<TH "TH_BG">Last&nbsp;Seen</TH>"
		     "<TH "TH_BG">Duration</TH>"
		     "<TH "TH_BG">Latency</TH>"
#ifdef PRINT_ALL_SESSIONS
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
		    "<TD "TD_BG" ALIGN=RIGHT>%s:%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s:%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
#ifdef PRINT_ALL_SESSIONS
		    "<TD "TD_BG" ALIGN=CENTER>%s</TD>"
#endif
		    "</TR>\n",
		    getRowColor(),
		    makeHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
				 hash_hostTraffic[checkSessionIdx(myGlobals.device[myGlobals.actualReportDeviceId].
								  tcpSession[idx]->initiatorIdx)],
				 SHORT_FORMAT, 0, 0),
		    sport,
		    makeHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
				 hash_hostTraffic[checkSessionIdx(myGlobals.device[myGlobals.actualReportDeviceId].
								  tcpSession[idx]->remotePeerIdx)],
				 SHORT_FORMAT, 0, 0),
		    dport,
		    formatBytes(dataSent, 1),
		    formatBytes(dataRcvd, 1),
		    formatTime(&(session->firstSeen), 1),
		    formatTime(&(session->lastSeen), 1),
		    formatSeconds(myGlobals.actTime-session->firstSeen),
		    formatLatency(session->nwLatency,
				  session->sessionState)
#ifdef PRINT_ALL_SESSIONS
		    , getSessionState(session)
#endif
		    ) < 0) BufferTooShort();

	sendString(buf);
	session = session->next;
	printedSessions++;
      }
    }

  if(printedSessions > 0) {
    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");

    addPageIndicator("NetNetstat.html", pageNum,
		     realNumSessions, myGlobals.maxNumLines, -1, 0);
  } else
    printFlagedWarning("<I>No Active TCP Sessions</I>");
}


/* ********************************** */

void printIpProtocolUsage(void) {
  HostTraffic **hosts;
  u_short clientPorts[TOP_ASSIGNED_IP_PORTS], serverPorts[TOP_ASSIGNED_IP_PORTS];
  u_int i, j, idx1, hostsNum=0, numPorts=0;
  char buf[BUF_SIZE];

  printHTMLheader("TCP/UDP Protocol Subnet Usage", 0);

  memset(clientPorts, 0, sizeof(clientPorts));
  memset(serverPorts, 0, sizeof(serverPorts));

  hosts = (HostTraffic**)malloc(myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));
  memset(hosts, 0, myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));

  /* Further checks courtesy of Scott Renfro <scott@renfro.org> */
  if(myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic != NULL) {
    for(i=0; i<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; i++)
      if((myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i] != NULL)
	 && subnetPseudoLocalHost(myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i])
	 && (myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i]->hostNumIpAddress[0] != '\0')) {
	hosts[hostsNum++] = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i];

	if(myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i]->portsUsage != NULL) {
	  for(j=0; j<TOP_ASSIGNED_IP_PORTS; j++) {
	    if(myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i]->portsUsage[j] != NULL)  {
	      clientPorts[j] += myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i]->portsUsage[j]->clientUses;
	      serverPorts[j] += myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i]->portsUsage[j]->serverUses;
	      numPorts++;
	    }
	  }
	}
      }
  }

  if(numPorts == 0) {
    printNoDataYet();
    free(hosts);
    return;
  }

  /* Hosts are now in a contiguous structure (hosts[])... */

  sendString("<CENTER>\n");
  sendString(""TABLE_ON"<TABLE BORDER=1><TR "TR_ON"><TH "TH_BG" COLSPAN=2>Service</TH>"
	     "<TH "TH_BG">Clients</TH><TH "TH_BG">Servers</TH>\n");

  for(j=0; j<TOP_ASSIGNED_IP_PORTS; j++)
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
			makeHostLink(hosts[idx1], SHORT_FORMAT, 1, 0)) < 0)
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
			makeHostLink(hosts[idx1], SHORT_FORMAT, 1, 0)) < 0)
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
		getRowColor(), label, formatKBytes.value(total)) < 0) BufferTooShort();
    break;
  case 100:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"</TR>\n",
		getRowColor(), label, formatKBytes.value(total)) < 0) BufferTooShort();
    break;
  default:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"</TR>\n",
		getRowColor(), label, formatKBytes.value(total)) < 0) BufferTooShort();
  }

  sendString(buf);
}
#endif

/* ********************************** */

void printIpProtocolDistribution(int mode, int revertOrder) {
  int i;
  char buf[2*BUF_SIZE], *sign;
  float total, partialTotal, remainingTraffic;
  float percentage;

  if(revertOrder)
    sign = "";
  else
    sign = "-";

 if(mode == SHORT_FORMAT) {
   printSectionTitle("IP Protocol Distribution");

#ifdef HAVE_GDCHART
   sendString("<CENTER><IMG SRC=ipProtoDistribPie"CHART_FORMAT"><p>\n</CENTER>\n");
#endif

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
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
                 "Percentage</TH></TR>\n");

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local.value/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), myGlobals.protoIPTrafficInfos[i],
			  COLOR_1, partialTotal, percentage);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Prot.",
			COLOR_1, remainingTraffic, percentage);
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
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
		 "Percentage</TH></TR>\n");

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote2local.value/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), myGlobals.protoIPTrafficInfos[i],
			  COLOR_1, partialTotal, percentage);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Prot.",
			COLOR_1, remainingTraffic, percentage);
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
                 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
                 "Percentage</TH></TR>\n");

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
        partialTotal =
	  (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote.value/1024;

        if(partialTotal > 0) {
          remainingTraffic += partialTotal;
          percentage = ((float)(partialTotal*100))/((float)total);
          printTableEntry(buf, sizeof(buf),
			  myGlobals.protoIPTrafficInfos[i],
                          COLOR_1, partialTotal, percentage);
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
                        COLOR_1, remainingTraffic, percentage);
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
		 "<TH "TH_BG" WIDTH=250>Percentage</TH></TR>\n");

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local2remote.value/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), myGlobals.protoIPTrafficInfos[i],
			  COLOR_1, partialTotal, percentage);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;IP-based&nbsp;Prot.",
			COLOR_1, remainingTraffic, percentage);
      }
      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }

  } else {
    total = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value/1024; /* total is expressed in KBytes.value */

    if(total == 0)
      return;
    else {
      int numProtosFound = 0;

      printSectionTitle("Global TCP/UDP Protocol Distribution");

      sendString("<CENTER>\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=500><TR "TR_ON"><TH "TH_BG" WIDTH=150>"
		 "TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
		 "Percentage</TH></TR>\n");

      remainingTraffic = 0;

      for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	partialTotal  = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local.value
	  +myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote.value;
	partialTotal += (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote2local.value
	  +myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local2remote.value;

	if(partialTotal > 0) {
	  partialTotal /= 1024;
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  numProtosFound++;
	  printTableEntry(buf, sizeof(buf), myGlobals.protoIPTrafficInfos[i],
			  COLOR_1, partialTotal, percentage);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Prot.",
			COLOR_1, remainingTraffic, percentage);
      }

#ifdef HAVE_GDCHART
      if(numProtosFound > 0)
	sendString("<TR "TR_ON"><TD "TD_BG" COLSPAN=3 ALIGN=CENTER>"
		   "<IMG SRC=drawGlobalIpProtoDistribution"CHART_FORMAT"></TD></TR>\n");
#endif
      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }
  }
}

/* ************************ */

void printProtoTraffic(void) {
  float total, perc;
  char buf[BUF_SIZE];

  total = myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value/1024; /* total is expressed in KBytes.value */

  if(total == 0)
    return;

  printSectionTitle("Global Protocol Distribution");
  sendString("<CENTER>\n");
  sendString("<P>"TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\"><TR "TR_ON"><TH "TH_BG" WIDTH=150>Protocol</TH>"
	     "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>Percentage</TH></TR>\n");

  perc = 100*((float)myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value);
  if(perc > 100) perc = 100;

  if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" WIDTH=150 ALIGN=LEFT>IP</TH>"
	      "<TD "TD_BG" WIDTH=100 ALIGN=RIGHT>%s"
	      "&nbsp;(%.1f%%)</TD><TD "TD_BG" WIDTH=250>"
	      "<TABLE BORDER=1 WIDTH=\"100%\">",
	      getRowColor(),
	      formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value, 1),
	      perc) < 0)
    BufferTooShort();
  sendString(buf);

  printTableEntry(buf, sizeof(buf), "TCP", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value));
  printTableEntry(buf, sizeof(buf), "UDP", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value));
  printTableEntry(buf, sizeof(buf), "ICMP", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value));
  printTableEntry(buf, sizeof(buf), "Other&nbsp;IP", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value/1024,
		  ((float)myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value));

  sendString("</TABLE>"TABLE_OFF"</TR>");

  printTableEntry(buf, sizeof(buf), "(R)ARP", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value));
  printTableEntry(buf, sizeof(buf), "DLC", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "IPX", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "Decnet", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].decnetBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].decnetBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "AppleTalk", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "OSPF", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].ospfBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].ospfBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "NetBios", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "IGMP", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].igmpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].igmpBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "OSI", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].osiBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].osiBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "QNX", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].qnxBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].qnxBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "STP", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));
  printTableEntry(buf, sizeof(buf), "Other", COLOR_1,
		  (float)myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value/1024,
		  100*((float)myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value));

#ifdef HAVE_GDCHART
  sendString("<TR "TR_ON"><TD "TD_BG" COLSPAN=3 ALIGN=CENTER>"
	     "<IMG SRC=drawGlobalProtoDistribution"CHART_FORMAT"></TD></TR>\n");
#endif

  sendString("</TABLE>"TABLE_OFF"<P></CENTER>\n");
}

/* ************************ */

void printProcessInfo(int processPid, int actualDeviceId) {
  char buf[BUF_SIZE];
  int i, j, numEntries;

#ifdef MULTITHREADED
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
#ifdef MULTITHREADED
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

  for(j=0; j<TOP_IP_PORT; j++)
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
    if(myGlobals.processes[i]->contactedIpPeersIndexes[j] != NO_PEER) {

      if(numEntries == 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Contacted&nbsp;Peers"
		    "</TH><TD "TD_BG" ALIGN=RIGHT>", getRowColor()) < 0)
	  BufferTooShort();
	sendString(buf);
      }

      if(snprintf(buf, sizeof(buf), "%s<BR>\n",
		  makeHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
			       hash_hostTraffic[checkSessionIdx(myGlobals.processes[i]->contactedIpPeersIndexes[j])],
			       0, 0, 0)) < 0) BufferTooShort();
      sendString(buf);
      numEntries++;
    }

  sendString("</TD></TR>\n</TABLE>"TABLE_OFF"</CENTER><P>\n");

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.lsofMutex);
#endif
}

/* ************************ */

void printLsofData(int mode) {
  char buf[BUF_SIZE];
  int i, j, found, processSize;
  int numUsers, numProcessesToDisplay;
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

#ifdef MULTITHREADED
  accessMutex(&myGlobals.lsofMutex, "buildHTMLBrowserWindowsLabel");
#endif

  memcpy(processesList, myGlobals.processes, processSize);
  myGlobals.columnSort = mode;
  quicksort(processesList, myGlobals.numProcesses, sizeof(ProcessInfo*), cmpProcesses);

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
	usersTrafficList[numUsers++] = &usersTraffic[numUsers];
	usersTraffic[j].bytesSent = usersTraffic[j].bytesRcvd = 0;
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

  for(i=0; i<TOP_IP_PORT; i++)
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
    quicksort(usersTrafficList, numUsers, sizeof(UsersTraffic**), cmpUsersTraffic);

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

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.lsofMutex);
#endif

  free(processesList);
}

/* ************************ */

void printIpTrafficMatrix(void) {
  int i, j, numEntries=0, numConsecutiveEmptyCells;
  char buf[BUF_SIZE];
  short *activeHosts;
  Counter minTraffic=(Counter)LONG_MAX, maxTraffic=0, avgTraffic;
  Counter avgTrafficLow, avgTrafficHigh, tmpCounter;

  printHTMLheader("IP Subnet Traffic Matrix", 0);

  activeHosts = (short*)malloc(sizeof(short)*myGlobals.device[myGlobals.actualReportDeviceId].numHosts);

  for(i=1; i<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; i++) {
    if(i == myGlobals.otherHostEntryIdx)
      continue;

    activeHosts[i] = 0;
    for(j=1; j<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; j++) {
      int id;

      if(j == myGlobals.otherHostEntryIdx)
	continue;

      id = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts+j;

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

  for(i=1; i<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; i++)
    for(j=1; j<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; j++) {
      int idx = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts+j;

      if(idx == myGlobals.otherHostEntryIdx) continue;

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


  for(i=1; i<myGlobals.device[myGlobals.actualReportDeviceId].numHosts; i++)
    if((i != myGlobals.otherHostEntryIdx) && (activeHosts[i] == 1)) {
      numConsecutiveEmptyCells=0;

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT><SMALL>%s</SMALL></TH>",
		  getRowColor(), makeHostLink(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i],
					      SHORT_FORMAT, 1, 0)) < 0)
	BufferTooShort();
      sendString(buf);

      for(j=1; j<myGlobals.device[myGlobals.actualReportDeviceId].numHosts; j++) {
	int idx = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts+j;

	if(idx == myGlobals.otherHostEntryIdx) continue;

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

  free(activeHosts);
}

/* ************************ */

void printThptStatsMatrix(int sortedColumn) {
  int i, dataSent;
  char label[32], label1[32], buf[BUF_SIZE];
  time_t tmpTime;
  struct tm t;
  HostTraffic el;

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

      if(myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].topHostSentSerial != NO_PEER) {
	if(retrieveHost(myGlobals.device[myGlobals.actualReportDeviceId].
			last60MinutesThpt[i].topHostSentSerial, &el) == 0) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(&el, LONG_FORMAT, 0, 0),
		      formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				       last60MinutesThpt[i].topSentTraffic.value)) < 0)
	    BufferTooShort();
	  sendString(buf); dataSent = 1;
	}
      }

      if(myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].secondHostSentSerial != NO_PEER) {
	if(retrieveHost(myGlobals.device[myGlobals.actualReportDeviceId].
			last60MinutesThpt[i].secondHostSentSerial, &el) == 0) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(&el, LONG_FORMAT, 0, 0),
		      formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				       last60MinutesThpt[i].secondSentTraffic.value)) < 0)
	    BufferTooShort();
	  sendString(buf); dataSent = 1;
	}
      }

      if(myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].thirdHostSentSerial != NO_PEER) {
	if(retrieveHost(myGlobals.device[myGlobals.actualReportDeviceId].
			last60MinutesThpt[i].thirdHostSentSerial, &el) == 0) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(&el, LONG_FORMAT, 0, 0),
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

      if(myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].topHostRcvdSerial != NO_PEER) {
	if(retrieveHost(myGlobals.device[myGlobals.actualReportDeviceId].
			last60MinutesThpt[i].topHostRcvdSerial, &el) == 0) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(&el, LONG_FORMAT, 0, 0),
		      formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				       last60MinutesThpt[i].topRcvdTraffic.value)) < 0)
	    BufferTooShort();
	  sendString(buf); dataSent = 1;
	}
      }

      if(myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].secondHostRcvdSerial != NO_PEER) {
	if(retrieveHost(myGlobals.device[myGlobals.actualReportDeviceId].
			last60MinutesThpt[i].secondHostRcvdSerial, &el) == 0) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(&el, LONG_FORMAT, 0, 0),
		      formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
				       last60MinutesThpt[i].secondRcvdTraffic.value)) < 0)
	    BufferTooShort();
	  sendString(buf); dataSent = 1;
	}
      }

      if(myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].thirdHostRcvdSerial != NO_PEER) {
	if(retrieveHost(myGlobals.device[myGlobals.actualReportDeviceId].
			last60MinutesThpt[i].thirdHostRcvdSerial, &el) == 0) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(&el, LONG_FORMAT, 0, 0),
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

	if(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].topHostSentSerial != NO_PEER) {
	  if(retrieveHost(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].topHostSentSerial, &el) == 0) {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(&el, LONG_FORMAT, 0, 0),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last24HoursThpt[i].topSentTraffic.value)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	}

	if(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].secondHostSentSerial != NO_PEER) {
	  if(retrieveHost(myGlobals.device[myGlobals.actualReportDeviceId].
			  last24HoursThpt[i].secondHostSentSerial, &el) == 0) {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(&el, LONG_FORMAT, 0, 0),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last24HoursThpt[i].secondSentTraffic.value)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	}

	if(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].thirdHostSentSerial != NO_PEER) {
	  if(retrieveHost(myGlobals.device[myGlobals.actualReportDeviceId].
			  last24HoursThpt[i].thirdHostSentSerial, &el) == 0) {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(&el, LONG_FORMAT, 0, 0),
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

	if(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].topHostRcvdSerial != NO_PEER) {
	  if(retrieveHost(myGlobals.device[myGlobals.actualReportDeviceId].
			  last24HoursThpt[i].topHostRcvdSerial, &el) == 0) {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(&el, LONG_FORMAT, 0, 0),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last24HoursThpt[i].topRcvdTraffic.value)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	}

	if(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].secondHostRcvdSerial != NO_PEER) {
	  if(retrieveHost(myGlobals.device[myGlobals.actualReportDeviceId].
			  last24HoursThpt[i].secondHostRcvdSerial, &el) == 0) {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(&el, LONG_FORMAT, 0, 0),
			formatThroughput(myGlobals.device[myGlobals.actualReportDeviceId].
					 last24HoursThpt[i].secondRcvdTraffic.value)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	}

	if(myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].thirdHostRcvdSerial != NO_PEER) {
	  if(retrieveHost(myGlobals.device[myGlobals.actualReportDeviceId].
			  last24HoursThpt[i].thirdHostRcvdSerial, &el) == 0) {
	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON">%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
			makeHostLink(&el, LONG_FORMAT, 0, 0),
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

  if(myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples == 0) {
    printNoDataYet();
    return;
  }

  sendString("<CENTER>\n");

#ifdef HAVE_GDCHART
   sendString("<A HREF=\"thptStatsMatrix.html?col=1\" BORDER=0>"
	      "<IMG SRC=\"thptGraph"CHART_FORMAT"?col=1\"></A><BR>\n");
   if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4>",
	   formatTimeStamp(0, 0, 0),
	   formatTimeStamp(0, 0, 60)) < 0) BufferTooShort();
#else
   sendString("<A HREF=\"thptStatsMatrix.html?col=1\" BORDER=0>");
   if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4></A><BR>",
	   formatTimeStamp(0, 0, 0),
	   formatTimeStamp(0, 0, 60)) < 0)
     BufferTooShort();
#endif

   sendString(tmpBuf);

  if(myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples > 60) {
#ifdef HAVE_GDCHART
    sendString("<P><A HREF=\"thptStatsMatrix.html?col=2\" BORDER=0>"
	       "<IMG SRC=\"thptGraph"CHART_FORMAT"?col=2\"></A><BR>\n");
    if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4>",
	    formatTimeStamp(0, 0, 0),
	    formatTimeStamp(0, 24, 0)) < 0) BufferTooShort();
#else
    sendString("<P><A HREF=\"thptStatsMatrix.html?col=2\" BORDER=0>");
    if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4></A><BR>",
	    formatTimeStamp(0, 0, 0),
	    formatTimeStamp(0, 24, 0)) < 0) BufferTooShort();
#endif

    sendString(tmpBuf);

#ifdef HAVE_GDCHART
    if(myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples > 1440 /* 60 * 24 */) {
      sendString("<P><IMG SRC=\"thptGraph"CHART_FORMAT"?col=3\"><BR>\n");
      if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4>",
	      formatTimeStamp(0, 0, 0),
	      formatTimeStamp(30, 0, 0)) < 0)
	BufferTooShort();
      sendString(tmpBuf);
    }
#endif
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
    traceEvent(TRACE_WARNING, "WARNING (1)\n");
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (2)\n");
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (3)\n");
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
  case 10: a_ = a->ospfSent.value , b_ = b->ospfSent.value;  break;
  case 11: a_ = a->ospfRcvd.value , b_ = b->ospfRcvd.value;  break;
  case 12: a_ = a->igmpSent.value , b_ = b->igmpSent.value;  break;
  case 13: a_ = a->igmpRcvd.value , b_ = b->igmpRcvd.value;  break;
  default:
  case 0:
    if(domainSort) {
      /*
	if((a->domainHost == NULL) || (a->domainHost->fullDomainName == NULL)) printf("A is NULL!\n");
	if((b->domainHost == NULL) || (b->domainHost->fullDomainName == NULL)) printf("B is NULL!\n");
      */
      return(strcasecmp(a->domainHost->fullDomainName, b->domainHost->fullDomainName));
    } else {
#ifdef MULTITHREADED
      if(myGlobals.numericFlag == 0) accessMutex(&myGlobals.addressResolutionMutex, "fillDomainName");
#endif
      rc = strcasecmp(a->domainHost->hostSymIpAddress, b->domainHost->hostSymIpAddress);
#ifdef MULTITHREADED
      if(myGlobals.numericFlag == 0) releaseMutex(&myGlobals.addressResolutionMutex);
#endif
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
  u_int idx, tmpIdx, numEntries=0, printedEntries=0, len;
  u_short keyValue=0;
  HostTraffic *el;
  char buf[BUF_SIZE];
  DomainStats **stats, *tmpStats, *statsEntry;
  char htmlAnchor[2*BUF_SIZE], htmlAnchor1[2*BUF_SIZE], *sign, *arrowGif, *arrow[48], *theAnchor[48];
  Counter totBytesSent=0, totBytesRcvd=0;

  len = sizeof(DomainStats)*myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize;
  tmpStats = (DomainStats*)malloc(len);
  memset(tmpStats, 0, len);

  /* Fix below courtesy of Francis Pintos <francis@arhl.com.hk> */
  len = sizeof(DomainStats**)*myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize;
  stats = (DomainStats**)malloc(len);
  memset(stats, 0, len);

  /* traceEvent(TRACE_INFO, "'%s' '%d' '%d'\n", domainName, sortedColumn, revertOrder); */

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

  for(idx=1; idx<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; idx++) {
    if(idx == myGlobals.otherHostEntryIdx) continue;

    if((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) == NULL)
      continue;
    else
      fillDomainName(el);

    if((el->fullDomainName == NULL)
       || (el->fullDomainName[0] == '\0')
       || (el->dotDomainName == NULL)
       || (el->hostSymIpAddress[0] == '\0')
       || (el->dotDomainName == '\0')
       || broadcastHost(el)
       )
      continue;
    else if((domainName != NULL)
	    && (strcmp(el->fullDomainName, domainName) != 0))
      continue;

    if(domainName == NULL) {
      for(keyValue=0, tmpIdx=0; el->fullDomainName[tmpIdx] != '\0'; tmpIdx++)
	keyValue += (tmpIdx+1)*(u_short)el->fullDomainName[tmpIdx];

      keyValue %= myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize;

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
	/* traceEvent(TRACE_INFO, "[%d] %s/%s\n", numEntries, el->fullDomainName, el->dotDomainName); */
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
    statsEntry->ospfSent.value  += el->ospfSent.value;
    statsEntry->igmpSent.value  += el->igmpSent.value;
    statsEntry->tcpRcvd.value   += el->tcpRcvdLoc.value + el->tcpRcvdFromRem.value;
    statsEntry->udpRcvd.value   += el->udpRcvdLoc.value + el->udpRcvdFromRem.value;
    statsEntry->icmpRcvd.value  += el->icmpRcvd.value;
    statsEntry->ospfRcvd.value  += el->ospfRcvd.value;
    statsEntry->igmpRcvd.value  += el->igmpRcvd.value;
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

  quicksort(tmpStats, numEntries, sizeof(DomainStats), cmpStatsFctn);

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

  if(snprintf(buf, sizeof(buf),
          "<TH "TH_BG">%s10>OSPF&nbsp;Sent%s</A></TH>"
          "<TH "TH_BG">%s11>OSP&nbsp;Rcvd%s</A></TH>"
          "<TH "TH_BG">%s12>IGMP&nbsp;Sent%s</A></TH>"
          "<TH "TH_BG">%s13>IGMP&nbsp;Rcvd%s</A></TH>"
          "</TR>\n",
          theAnchor[10], arrow[10],
          theAnchor[11], arrow[11],
          theAnchor[12], arrow[12],
          theAnchor[13], arrow[13]) < 0)
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

#ifdef MULTITHREADED
      if(myGlobals.numericFlag == 0) accessMutex(&myGlobals.addressResolutionMutex, "getHostIcon");
#endif

      blankId = strlen(statsEntry->domainHost->hostSymIpAddress)-
	strlen(statsEntry->domainHost->fullDomainName)-1;

      strncpy(tmpBuf, statsEntry->domainHost->hostSymIpAddress, sizeof(tmpBuf));

#ifdef MULTITHREADED
      if(myGlobals.numericFlag == 0) releaseMutex(&myGlobals.addressResolutionMutex);
#endif

      if((blankId > 0)
	 && (strcmp(&tmpBuf[blankId+1], domainName) == 0))
	tmpBuf[blankId] = '\0';

      hostLink = makeHostLink(statsEntry->domainHost, SHORT_FORMAT, 1, 0);

      len = strlen(hostLink); if(len >= sizeof(htmlAnchor)) len = sizeof(htmlAnchor)-1;
      strncpy(htmlAnchor, hostLink, len);
      htmlAnchor[len] = '\0';
    }


    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=CENTER>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%%</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%%</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
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
		formatBytes(statsEntry->icmpRcvd.value, 1),
		formatBytes(statsEntry->ospfSent.value, 1),
		formatBytes(statsEntry->ospfRcvd.value, 1),
		formatBytes(statsEntry->igmpSent.value, 1),
		formatBytes(statsEntry->igmpRcvd.value, 1)
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

void printNotAvailable(void) {
  printFlagedWarning("<I>Requested data is not available as due to"
		     "<br>the way you started ntop (command line flags)</I>");
}

/* ************************* */

void listNetFlows(void) {
  char buf[BUF_SIZE];
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

	if(haveTrafficHistory()) {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>"
		      "<A HREF=\"/ntop-bin/netTraf.pl?flow=%s\">%s</A></TH><TD "TD_BG" ALIGN=RIGHT>%s"
		      "</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		      getRowColor(), list->flowName, list->flowName,
		      formatPkts(list->packets.value),
		      formatBytes(list->bytes.value, 1)) < 0) BufferTooShort();

	} else {
	  if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s"
		      "</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		      getRowColor(), list->flowName,
		      formatPkts(list->packets.value),
		      formatBytes(list->bytes.value, 1)) < 0) BufferTooShort();
	}

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
    tcSent += el->last24HoursBytesSent[i].value;
    tcRcvd += el->last24HoursBytesRcvd[i].value;
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

#endif /* MICRO_NTOP */

/* ************************** */

int haveTrafficHistory() {
  int idx;
  static int found = 0;
  struct stat statbuf;
  
  if(found) return(1); /* cached value */

  for(idx=0, found = 0; (!found) && (myGlobals.dataFileDirs[idx] != NULL); idx++) {
    char tmpStr[384];

    if(snprintf(tmpStr, sizeof(tmpStr), "%s/data", myGlobals.dataFileDirs[idx]) < 0)
      BufferTooShort();

    if(stat(tmpStr, &statbuf) == 0) {
      return(1);
      break;
    } else {
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Unable to find history data on %s", tmpStr);
#endif
    }
  }

  return(0);
}

/* ******************************* */

void printASList(unsigned int deviceId) {

  printHTMLheader("Autonomous Systems Traffic Statistics", 0);

  if(deviceId > myGlobals.numDevices) {
    printFlagedWarning("<I>Invalid device specified</I>");
    return;
  } else if(myGlobals.device[deviceId].asHash == NULL) {
    printFlagedWarning("<I>No AS Information Available (yet).</I>");
    return;
  }

  dumpElementHash(myGlobals.device[deviceId].asHash, "AS", 1);
}

/* ******************************* */

void printVLANList(unsigned int deviceId) {

  printHTMLheader("VLAN Traffic Statistics", 0);

  if(deviceId > myGlobals.numDevices) {
    printFlagedWarning("<I>Invalid device specified</I>");
    return;
  } else if(myGlobals.device[deviceId].vlanHash == NULL) {
    printFlagedWarning("<I>No VLAN Traffic Information Available (yet).</I>");
    return;
  }

  dumpElementHash(myGlobals.device[deviceId].vlanHash, "VLAN", 0);
}
