/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
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
void ignoreSignal(int signalId) {
  closeNwSocket(&newSock);
  (void)setsignal(signalId, ignoreSignal);
}
#endif

/* ******************************* */

void initReports(void) {
#ifndef MICRO_NTOP
  columnSort = 0;
#endif
  addDefaultAdminUser();
}

#ifndef MICRO_NTOP

/* **************************************** */

int reportValues(time_t *lastTime) {
  if(maxNumLines <= 0)
    maxNumLines = MAX_NUM_TABLE_ROWS;

  *lastTime = time(NULL) + refreshRate;

  /*
    Make sure that the other flags are't set. They have
    no effect in web mode
  */
  if(refreshRate == 0)
    refreshRate = REFRESH_TIME;
  else if(refreshRate < MIN_REFRESH_TIME)
    refreshRate = MIN_REFRESH_TIME;

#ifdef WIN32
  setsignal(SIGPIPE, ignoreSignal);
  setsignal(SIGABRT, ignoreSignal);
#endif

  return(0);
}

/* ******************************* */

RETSIGTYPE printHostsTraffic(int signumber_ignored,
			     int reportType,
			     int sortedColumn,
			     int revertOrder) {
  u_int idx, numEntries=0;
  int printedEntries=0, hourId;
  char theDate[8];
  struct tm t;
  HostTraffic *el;
  HostTraffic** tmpTable;
  char buf[BUF_SIZE], buf2[BUF_SIZE];
  float sentPercent, rcvdPercent;
  struct pcap_stat stat;

  /*
    printf("%d - %d - %d - %d\n", 
    signumber_ignored, reportType, sortedColumn, revertOrder);
  */
  strftime(theDate, 8, "%H", localtime_r(&actTime, &t));  
  hourId = atoi(theDate);

  memset(buf, 0, sizeof(buf));
  tmpTable = (HostTraffic**)malloc(device[actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));
  memset(tmpTable, 0, device[actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));

  sortSendMode = signumber_ignored;

  if(sortSendMode == 0)
    snprintf(buf, sizeof(buf), "Network Traffic: Data Received");
  else if (sortSendMode == 1)
    snprintf(buf, sizeof(buf), "Network Traffic: Data Sent");
  else if (sortSendMode == 2)
    snprintf(buf, sizeof(buf), "Global Traffic Statistics");
  printHTMLheader(buf, 0);

  if(signumber_ignored == 2)
    goto PRINT_TOTALS;

  printHeader(reportType, revertOrder, abs(sortedColumn));

  for(idx=1; idx<device[actualReportDeviceId].actualHashSize; idx++) {
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && (broadcastHost(el) == 0)) {
      if((sortSendMode && (el->bytesSent > 0))
	 || ((!sortSendMode) && (el->bytesReceived > 0))) {
	if((reportType == 1) && (el->hostNumIpAddress[0] == '\0')) continue;
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

    columnSort = 0;

    if(sortedColumn == HOST_DUMMY_IDX_VALUE)
      columnSort = HOST_DUMMY_IDX_VALUE; /* Host name */
    else if(sortedColumn == DOMAIN_DUMMY_IDX_VALUE)
      columnSort = DOMAIN_DUMMY_IDX_VALUE; /* domain name */
    else if(reportType == 0 /* Interactive mode */) {
      switch(sortedColumn) {
      case 0:
	/* Nothing to do */
	break;
      case 1: /* TCP */
	screenNumber = 0, columnSort = 1;
	break;
      case 2: /* UDP */
	screenNumber = 0, columnSort = 2;
	break;
      case 3: /* ICMP */
	screenNumber = 0, columnSort = 3;
	break;
      case 4: /* DLC */
	screenNumber = 1, columnSort = 1;
	break;
      case 5: /* IPX */
	screenNumber = 1, columnSort = 2;
	break;
      case 6: /* Decnet */
	screenNumber = 1, columnSort = 3;
	break;
      case 7: /* (R)ARP */
	screenNumber = 2, columnSort = 1;
	break;
      case 8: /* AppleTalk */
	screenNumber = 2, columnSort = 2;
	break;
      case 9: /* OSPF */
	screenNumber = 2, columnSort = 3;
	break;
      case 10: /* NetBios */
	screenNumber = 3, columnSort = 1;
	break;
      case 11: /* IGMP */
	screenNumber = 3, columnSort = 2;
	break;
      case 12: /* OSI */
	screenNumber = 3, columnSort = 3;
	break;
      case 13: /* QNX */
	screenNumber = 0, columnSort = 4;
	break;
      case 14: /* STP */
	screenNumber = 1, columnSort = 5;
	break;
      case 15: /* Other */
	screenNumber = 0, columnSort = 5;
	break;
      }
    } else if(reportType == 1) {
      /* if(sortedColumn == 0) sortedColumn = 1; */
      screenNumber = DUMMY_IDX_VALUE /* dirty trick */, columnSort = sortedColumn;
    } else if((reportType == 2) /* Thpt */
	      || ((reportType == 3) /* Host Traffic */)){
      if(sortedColumn == 0) sortedColumn = 1;
      screenNumber = MAX_NUM_PROTOS_SCREENS /* dirty trick */, columnSort = sortedColumn;
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, ">reportType=%d/sortedColumn=%d/columnSort=%d/screenNumber=%d<\n",
	       reportType, sortedColumn, columnSort, screenNumber);
#endif

    quicksort(tmpTable, numEntries, sizeof(HostTraffic*), cmpFctn);

    for(idx=0; idx<numEntries; idx++) {
      int i;
      TrafficCounter a, b, c, d, e;
      char webHostName[256];

      if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	sentPercent = (100*(float)el->bytesSent)/device[actualReportDeviceId].ethernetBytes;
	rcvdPercent = (100*(float)el->bytesReceived)/device[actualReportDeviceId].ethernetBytes;

	a = el->bytesReceived, b = el->bytesSent;

	if(!sortSendMode)
	  getProtocolDataReceived(&c, &d, &e, el);
	else
	  getProtocolDataSent(&c, &d, &e, el);

	/* Fixed buffer overflow.
	   Courtesy of Rainer Tammer <rainer.tammer@spg.schulergroup.com>
	*/

	strncpy(webHostName, makeHostLink(el, LONG_FORMAT, 0, 1), sizeof(webHostName));

	if(sortSendMode) {
	  if(reportType == 0) /* Protos */ {
	    if(snprintf(buf, sizeof(buf), "<TR %s>%s"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			getRowColor(), webHostName,
			formatBytes(el->bytesSent, 1), sentPercent, separator,
			formatBytes(el->tcpSentLocally+el->tcpSentRemotely, 1),
			formatBytes(el->udpSentLocally+el->udpSentRemotely, 1),
			formatBytes(el->icmpSent, 1),
			formatBytes(el->dlcSent, 1),
			formatBytes(el->ipxSent, 1),
			formatBytes(el->decnetSent, 1),
			formatBytes(el->arp_rarpSent, 1),
			formatBytes(el->appletalkSent, 1)
			) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");

	    sendString(buf);

	    if(snprintf(buf, sizeof(buf), 
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(el->ospfSent, 1),
			formatBytes(el->netbiosSent, 1),
			formatBytes(el->igmpSent, 1),
			formatBytes(el->osiSent, 1),
			formatBytes(el->qnxSent, 1),
			formatBytes(el->stpSent, 1),
			formatBytes(el->otherSent, 1)
			) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	      
	    sendString(buf);
	  } else if(reportType == 1) /* IP Protos */ {
	    TrafficCounter totalIPTraffic=0;
	      
	    if(snprintf(buf, sizeof(buf), "<TR %s>%s"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>",
			getRowColor(), webHostName,
			formatBytes(el->bytesSent, 1), sentPercent, separator) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);

#ifdef ENABLE_NAPSTER
	    if(el->napsterStats != NULL) {
	      if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			  formatBytes(el->napsterStats->bytesSent, 1)) < 0)
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	      sendString(buf);
	    } else {
	      sendString("<TD "TD_BG" ALIGN=RIGHT>0</TD>");
	    }
#endif

	    for(i=0; i<numIpProtosToMonitor; i++) {
	      totalIPTraffic += el->protoIPTrafficInfos[i].sentLocally+
		el->protoIPTrafficInfos[i].sentRemotely;
	      if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			  formatBytes(el->protoIPTrafficInfos[i].sentLocally+
				      el->protoIPTrafficInfos[i].sentRemotely, 1)) < 0) 
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	      sendString(buf);
	    }

	    /* Rounding may cause troubles */
	    if(el->bytesSent > totalIPTraffic)
	      totalIPTraffic = (el->tcpSentLocally
				+el->tcpSentRemotely
				+el->udpSentLocally
				+el->udpSentRemotely
				+el->icmpSent
				+el->ospfSent
				+el->igmpSent)
		-totalIPTraffic;
	    else
	      totalIPTraffic = 0;
	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(totalIPTraffic, 1)) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);
	  } else if(reportType == 2) /* Throughtput */ {
	    if(snprintf(buf, sizeof(buf), "<TR %s>%s"
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
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);
	  } else if(reportType == 3) /* Host Traffic Stats */ {
	    if(snprintf(buf, sizeof(buf), "<TR %s>%s", getRowColor(), webHostName) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);
	    printHostThtpShort(el, 1);
	  }
	    
	  sendString("</TR>\n");
	} else {
	  if(reportType == 0) /* Protos */ {
	    if(snprintf(buf, sizeof(buf), "<TR %s>%s"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			getRowColor(), webHostName,
			formatBytes(el->bytesReceived, 1), rcvdPercent, separator,
			formatBytes(el->tcpReceivedLocally+el->tcpReceivedFromRemote, 1),
			formatBytes(el->udpReceivedLocally+el->udpReceivedFromRemote, 1),
			formatBytes(el->icmpReceived, 1),
			formatBytes(el->dlcReceived, 1),
			formatBytes(el->ipxReceived, 1),
			formatBytes(el->decnetReceived, 1),
			formatBytes(el->arp_rarpReceived, 1),
			formatBytes(el->appletalkReceived, 1)
			) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");

	    sendString(buf);
	    if(snprintf(buf, sizeof(buf), 
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			formatBytes(el->ospfReceived, 1),
			formatBytes(el->netbiosReceived, 1),
			formatBytes(el->igmpReceived, 1),
			formatBytes(el->osiReceived, 1),
			formatBytes(el->qnxReceived, 1),
			formatBytes(el->stpReceived, 1),
			formatBytes(el->otherReceived, 1)
			) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	      
	    sendString(buf);
	  } else if(reportType == 1) /* IP Protos */ {
	    TrafficCounter totalIPTraffic=0;

	    if(snprintf(buf, sizeof(buf), "<TR %s>%s"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>",
			getRowColor(), webHostName,
			formatBytes(el->bytesReceived, 1), 
			rcvdPercent, separator) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);

#ifdef ENABLE_NAPSTER
	    if(el->napsterStats != NULL) {
	      if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			  formatBytes(el->napsterStats->bytesRcvd, 1)) < 0)
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	      sendString(buf);
	    } else {
	      sendString("<TD "TD_BG" ALIGN=RIGHT>0</TD>");
	    }
#endif

	    for(i=0; i<numIpProtosToMonitor; i++) {
	      totalIPTraffic += el->protoIPTrafficInfos[i].receivedLocally+
		el->protoIPTrafficInfos[i].receivedFromRemote;
	      if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
			  formatBytes(el->protoIPTrafficInfos[i].receivedLocally+
				      el->protoIPTrafficInfos[i].receivedFromRemote, 1)) < 0) 
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	      sendString(buf);
	    }

	    /* Rounding may cause troubles */
	    if(el->bytesReceived > totalIPTraffic)
	      totalIPTraffic = (el->tcpReceivedLocally
				+el->tcpReceivedFromRemote
				+el->udpReceivedLocally
				+el->udpReceivedFromRemote
				+el->icmpReceived
				+el->ospfReceived
				+el->igmpReceived)-totalIPTraffic;
	    else
	      totalIPTraffic = 0;
	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>", 
			formatBytes(totalIPTraffic, 1)) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);
	  } else if(reportType == 2) /* Throughtput */ {
	    if(snprintf(buf, sizeof(buf), "<TR %s>%s"
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
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);
	  } else if(reportType == 3) /* Host Traffic Stats */ {
	    if(snprintf(buf, sizeof(buf), "<TR %s>%s",
			getRowColor(), webHostName) < 0)
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);
	    printHostThtpShort(el, 0);
	  }

	  sendString("</TR>\n");
	}

	/* Avoid huge tables */
	if(printedEntries++ > maxNumLines)
	  break;	
      }
    }
  } else
    idx = 0;

  sendString("\n</TABLE>"TABLE_OFF"\n");
  sendString("</CENTER>\n");
  
 PRINT_TOTALS:
  if(signumber_ignored == 2) {
    TrafficCounter unicastPkts=0, avgPktLen;

    if(reportType == 0) {
      int i;

      sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1>\n");

      sendString("<TR><TH "TH_BG">Nw Interface Type</TH>"
		 "<TD "TD_BG" ALIGN=RIGHT>");

      if(mergeInterfaces) {
	for(i=0; i<numDevices; i++) {
	  if(i > 0) sendString("<br>");

	  if(rFileName == NULL) {
	    char buf[32], buf1[32];

	    if(snprintf(buf2, sizeof(buf2), "%s (%s%s) [%s/%s]",
			device[i].name, getNwInterfaceType(i), 
			device[i].virtualDevice ? " virtual" : "",
			_intoa(device[i].network, buf, sizeof(buf1)),
			_intoa(device[i].netmask, buf1, sizeof(buf1))
			) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf2);
	  } else {
	    if(snprintf(buf2, sizeof(buf2), "%s [%s]",
			getNwInterfaceType(i),
			PCAP_NW_INTERFACE) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf2);
	  }
	}
      } else {
	/* mergeInterfaces == 0 */
	if(rFileName == NULL) {
	  if(!device[actualReportDeviceId].virtualDevice) {
	    if(snprintf(buf2, sizeof(buf2), "%s [%s]",
			getNwInterfaceType(actualReportDeviceId),
			device[actualReportDeviceId].name) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf2);
	  }
	} else {
	  if(snprintf(buf2, sizeof(buf2), "%s [%s]",
		      getNwInterfaceType(actualReportDeviceId),
		      PCAP_NW_INTERFACE) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf2);
	}
      }

      sendString("</TD></TR>\n");

      if(domainName[0] != '\0') {
	if(snprintf(buf2, sizeof(buf2), "<TR><TH "TH_BG">Local Domain Name</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;</TD></TR>\n",
		    domainName) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
      }

      if(snprintf(buf2, sizeof(buf2), "<TR><TH "TH_BG">Sampling Since</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s [%s]</TD></TR>\n",
		  ctime(&initialSniffTime),
		  formatSeconds(actTime-initialSniffTime)) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf2);

      sendString("<TR><TH "TH_BG">Packets</TH><TD "TH_BG">\n<TABLE BORDER=1 WIDTH=100%%>");

#ifdef HAVE_GDCHART
      if(mergeInterfaces && (numDevices > 1)) {
	int i, numRealDevices=0;
	
	for(i=0; i<numDevices; i++) 
	  if(!device[i].virtualDevice)
	    numRealDevices++;

	if(numRealDevices > 1)
	  sendString("<TR><TD "TD_BG" ALIGN=CENTER COLSPAN=3>"
		     "<IMG SRC=interfaceTrafficPie"CHART_FORMAT"></TD></TR>\n");
      }
#endif
    }

    if(device[actualReportDeviceId].pcapPtr != NULL) {
      TrafficCounter droppedByKernel;

      if(reportType == 0) {
	int i;

	droppedByKernel=0;

	for(i=0; i<numDevices; i++) 
	  if(!device[i].virtualDevice) {
	    if (pcap_stats(device[i].pcapPtr, &stat) >= 0) {
	      droppedByKernel +=  stat.ps_drop;
	    }
	  }
	
	unicastPkts = device[actualReportDeviceId].ethernetPkts
	  - device[actualReportDeviceId].broadcastPkts
	  - device[actualReportDeviceId].multicastPkts;
	/* if(unicastPkts < 0) unicastPkts = 0; */ /* It shouldn't happen */
	if(device[actualReportDeviceId].ethernetPkts <= 0)
	  device[actualReportDeviceId].ethernetPkts = 1;
	
	if(snprintf(buf2, sizeof(buf2),
		    "<tr %s><TH "TH_BG" align=left>Total</th>"
		    "<TD "TD_BG" COLSPAN=2 align=right>%s</td></TR>\n",
		    getRowColor(), formatPkts(device[actualReportDeviceId].ethernetPkts)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
	if(snprintf(buf2, sizeof(buf2),
		    "<tr %s><TH "TH_BG" align=left>Dropped&nbsp;by&nbsp;the&nbsp;kernel</th>"
		    "<TD "TD_BG" COLSPAN=2 align=right>%s</td></TR>\n",
		    getRowColor(), formatPkts(droppedByKernel)) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
#ifdef MULTITHREADED
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>"
		    "Dropped&nbsp;by&nbsp;ntop</th>"
		    "<TD "TD_BG" COLSPAN=2 align=right>%s</td></TR>\n",
		    getRowColor(), formatPkts(device[actualReportDeviceId].droppedPackets)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
#endif
      }
    }

    if(reportType == 0) {
      if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Unicast</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*unicastPkts)/(float)device[actualReportDeviceId].ethernetPkts,
		  formatPkts(unicastPkts)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf2);
      if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Broadcast</th>"
		  "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		  getRowColor(), (float)(100*device[actualReportDeviceId].broadcastPkts)/
		  (float)device[actualReportDeviceId].ethernetPkts,
		  formatPkts(device[actualReportDeviceId].broadcastPkts)) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf2);

      if(device[actualReportDeviceId].multicastPkts > 0) {
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Multicast</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*device[actualReportDeviceId].multicastPkts)/
		    (float)device[actualReportDeviceId].ethernetPkts,
		    formatPkts(device[actualReportDeviceId].multicastPkts)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
      }

      if(device[actualReportDeviceId].ethernetPkts > 0) {

#ifdef HAVE_GDCHART
	sendString("<TR><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
		   "<IMG SRC=pktCastDistribPie"CHART_FORMAT"></TH></TR>\n");
#endif

	/*
	  Very rudimental formula. Note that as specified in RMON, packets smaller
	  than 64 or larger than 1518 octets are not counted.
	*/
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Shortest</th>"
		    "<TD "TD_BG" align=right colspan=2>%s bytes</td></TR>\n",
		    getRowColor(), 
		    formatPkts((TrafficCounter)device[actualReportDeviceId].rcvdPktStats.shortest)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
	avgPktLen = (96*device[actualReportDeviceId].rcvdPktStats.upTo128
		     +192*device[actualReportDeviceId].rcvdPktStats.upTo256
		     +384*device[actualReportDeviceId].rcvdPktStats.upTo512
		     +768*device[actualReportDeviceId].rcvdPktStats.upTo1024
		     +1271*device[actualReportDeviceId].rcvdPktStats.upTo1518)/
	  (device[actualReportDeviceId].rcvdPktStats.upTo128+device[actualReportDeviceId].rcvdPktStats.upTo256
	   +device[actualReportDeviceId].rcvdPktStats.upTo512+device[actualReportDeviceId].rcvdPktStats.upTo1024
	   +device[actualReportDeviceId].rcvdPktStats.upTo1518+1);
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Average&nbsp;Size</th>"
		    "<TD "TD_BG" align=right colspan=2>%s bytes</td></TR>\n",
		    getRowColor(), formatPkts(avgPktLen)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Longest</th>"
		    "<TD "TD_BG" align=right colspan=2>%s bytes</td></TR>\n",
		    getRowColor(), formatPkts(device[actualReportDeviceId].rcvdPktStats.longest)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);

	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>&lt;&nbsp;64&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo64)/
		    (float)device[actualReportDeviceId].ethernetPkts,
		    formatPkts(device[actualReportDeviceId].rcvdPktStats.upTo64)) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>&lt;&nbsp;128&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo128)/
		    (float)device[actualReportDeviceId].ethernetPkts,
		    formatPkts(device[actualReportDeviceId].rcvdPktStats.upTo128)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>&lt;&nbsp;256&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo256)/
		    (float)device[actualReportDeviceId].ethernetPkts,
		    formatPkts(device[actualReportDeviceId].rcvdPktStats.upTo256)) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>&lt;&nbsp;512&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo512)/
		    (float)device[actualReportDeviceId].ethernetPkts,
		    formatPkts(device[actualReportDeviceId].rcvdPktStats.upTo512)) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>&lt;&nbsp;1024&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo1024)/
		    (float)device[actualReportDeviceId].ethernetPkts,
		    formatPkts(device[actualReportDeviceId].rcvdPktStats.upTo1024)) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>&lt;&nbsp;1518&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo1518)/
		    (float)device[actualReportDeviceId].ethernetPkts,
		    formatPkts(device[actualReportDeviceId].rcvdPktStats.upTo1518)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>&gt;&nbsp;1518&nbsp;bytes</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.above1518)/
		    (float)device[actualReportDeviceId].ethernetPkts,
		    formatPkts(device[actualReportDeviceId].rcvdPktStats.above1518)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);

#ifdef HAVE_GDCHART
	sendString("<TR><TH "TH_BG" ALIGN=CENTER COLSPAN=3>"
		   "<IMG SRC=pktSizeDistribPie"CHART_FORMAT"></TH></TR>\n");
#endif

	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Packets&nbsp;too&nbsp;long</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.tooLong)/
		    (float)device[actualReportDeviceId].ethernetPkts,
		    formatPkts(device[actualReportDeviceId].rcvdPktStats.tooLong)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);

	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Bad&nbsp;Packets&nbsp;(Checksum)</th>"
		    "<TD "TD_BG" align=right>%.1f%%</td><TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.badChecksum)/
		    (float)device[actualReportDeviceId].ethernetPkts,
		    formatPkts(device[actualReportDeviceId].rcvdPktStats.badChecksum)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);

	sendString("</TABLE></TR><TR><TH "TH_BG">Traffic</TH><TD "TH_BG">\n<TABLE BORDER=1 WIDTH=100%%>");
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Total</th>"
		    "<TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), formatBytes(device[actualReportDeviceId].ethernetBytes, 1)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);

	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>IP Traffic</th>"
		    "<TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(), formatBytes(device[actualReportDeviceId].ipBytes, 1)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Non IP Traffic</th>"
		    "<TD "TD_BG" align=right>%s</td></TR>\n",
		    getRowColor(),
		    formatBytes(device[actualReportDeviceId].ethernetBytes-
				device[actualReportDeviceId].ipBytes, 1)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);

#ifdef HAVE_GDCHART
	sendString("<TR><TH "TH_BG" ALIGN=CENTER COLSPAN=2><IMG SRC=ipTrafficPie"CHART_FORMAT"></TH></TR>\n");
#endif

	updateThpt();
      
	sendString("</TABLE></TR><TR><TH "TH_BG">Network Load</TH><TD "TH_BG">\n<TABLE BORDER=1 WIDTH=100%%>");
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Actual</th><TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
		    getRowColor(), formatThroughput(device[actualReportDeviceId].actualThpt),
		    device[actualReportDeviceId].actualPktsThpt) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Last Minute</th>"
		    "<TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
		    getRowColor(), formatThroughput(device[actualReportDeviceId].lastMinThpt), 
		    device[actualReportDeviceId].lastMinPktsThpt) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);

	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Last 5 Minutes</th>"
		    "<TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
		    getRowColor(), formatThroughput(device[actualReportDeviceId].lastFiveMinsThpt), 
		    device[actualReportDeviceId].lastFiveMinsPktsThpt) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);

	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Peak</th>"
		    "<TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
		    getRowColor(), formatThroughput(device[actualReportDeviceId].peakThroughput), 
		    device[actualReportDeviceId].peakPacketThroughput) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);

	if(snprintf(buf2, sizeof(buf2), "<tr %s><TH "TH_BG" align=left>Average</th>"
		    "<TD "TD_BG" align=right>%s</td>"
		    "<TD "TD_BG" align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
		    getRowColor(), 
		    formatThroughput(device[actualReportDeviceId].ethernetBytes/(actTime-initialSniffTime)), 
		    /* Bug below fixed courtesy of Eddy Lai <eddy@ModernTerminals.com> */
		    ((float)device[actualReportDeviceId].ethernetPkts/(float)(actTime-initialSniffTime))) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf2);
      }

      sendString("</TABLE></TR></TABLE></CENTER>\n");
    }
  } 

  lastRefreshTime = actTime;
  free(tmpTable);
}

/* ******************************* */

static RETSIGTYPE _printHostsTraffic(int signumber_ignored) {
  printHostsTraffic(signumber_ignored, 0, 0, 0);
#ifndef WIN32
  (void)setsignal(SIGALRM, _printHostsTraffic);
#endif
}

/* ******************************* */

void printMulticastStats(int sortedColumn /* ignored so far */,
			 int revertOrder) {
  u_int idx, numEntries=0;
  int printedEntries=0;
  HostTraffic *el;
  HostTraffic** tmpTable;
  char buf[BUF_SIZE], *sign, *theAnchor[6], *arrow[6], *arrowGif;
  char htmlAnchor[64], htmlAnchor1[64];

  memset(buf, 0, sizeof(buf));
  tmpTable = (HostTraffic**)malloc(device[actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));
  memset(tmpTable, 0, device[actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG SRC=arrow_down.gif BORDER=0>";
  }

  for(idx=1; idx<device[actualReportDeviceId].actualHashSize; idx++) {
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && ((el->pktMulticastSent > 0) || (el->pktMulticastRcvd > 0))
       && (!broadcastHost(el))
       )
      tmpTable[numEntries++] = el;
  }

  printHTMLheader("Multicast Statistics", 0);

  if(numEntries > 0) {
    columnSort = sortedColumn; /* Host name */

    if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", STR_MULTICAST_STATS, sign) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", STR_MULTICAST_STATS) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");

    if(abs(columnSort) == 0) {
      arrow[0] = arrowGif;
      theAnchor[0] = htmlAnchor;
    } else {
      arrow[0] = "";
      theAnchor[0] = htmlAnchor1;
    }

    if(abs(columnSort) == 1) {
      arrow[1] = arrowGif;
      theAnchor[1] = htmlAnchor;
    } else {
      arrow[1] = "";
      theAnchor[1] = htmlAnchor1;
    }

    if(abs(columnSort) == 2) {
      arrow[2] = arrowGif;
      theAnchor[2] = htmlAnchor;
    } else {
      arrow[2] = "";
      theAnchor[2] = htmlAnchor1;
    }

    if(abs(columnSort) == 3) {
      arrow[3] = arrowGif;
      theAnchor[3] = htmlAnchor;
    } else {
      arrow[3] = "";
      theAnchor[3] = htmlAnchor1;
    }

    if(abs(columnSort) == 4) {
      arrow[4] = arrowGif;
      theAnchor[4] = htmlAnchor;
    } else {
      arrow[4] = "";
      theAnchor[4] = htmlAnchor1;
    }

    if(abs(columnSort) == 5) {
      arrow[5] = arrowGif;
      theAnchor[5] = htmlAnchor;
    } else {
      arrow[5] = "";
      theAnchor[5] = htmlAnchor1;
    }

    sendString("<CENTER>\n");
    if(snprintf(buf, sizeof(buf), ""TABLE_ON"<TABLE BORDER=1><TR><TH "TH_BG">%s0>Host%s</A></TH>\n"
	    "<TH "TH_BG">%s1>Domain%s</A></TH>"
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
	    ) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

    quicksort(tmpTable, numEntries, sizeof(HostTraffic*), cmpMulticastFctn);

    for(idx=0; idx<numEntries; idx++) {
     if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	if(snprintf(buf, sizeof(buf), "<TR %s>%s"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"</TR>\n",
		getRowColor(), makeHostLink(el, LONG_FORMAT, 0, 1),
		formatPkts(el->pktMulticastSent),
		formatBytes(el->bytesMulticastSent, 1),
		formatPkts(el->pktMulticastRcvd),
		formatBytes(el->bytesMulticastRcvd, 1)
		) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");

	sendString(buf);

      /* Avoid huge tables */
      if(printedEntries++ > maxNumLines)
	break;
      }
    }

    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");
  } else
    printNoDataYet();

  free(tmpTable);
}


/* ******************************* */

RETSIGTYPE printHostsInfo(int sortedColumn, int revertOrder) {
  u_int idx, numEntries;
  int printedEntries=0;
  unsigned short maxBandwidthUsage=1 /* avoid divisions by zero */;
  struct hostTraffic *el;
  struct hostTraffic** tmpTable;
  char buf[BUF_SIZE], *arrowGif, *sign, *arrow[8], *theAnchor[8];
  char htmlAnchor[64], htmlAnchor1[64];

  memset(buf, 0, sizeof(buf));
  tmpTable = (HostTraffic**)malloc(device[actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));
  memset(tmpTable, 0, device[actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG SRC=arrow_down.gif BORDER=0>";
  }

  columnSort = sortedColumn;

  printHTMLheader("Host Information", 0);

  /* printHeader(0, revertOrder, abs(sortedColumn)); */

  for(idx=1, numEntries=0; idx<device[actualReportDeviceId].actualHashSize; idx++)
    if((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL) {
      unsigned short actUsage;

      actUsage = (unsigned short)(100*((float)el->bytesSent/
				       (float)device[actualReportDeviceId].ethernetBytes));

      el->actBandwidthUsage = actUsage;
      if(el->actBandwidthUsage > maxBandwidthUsage)
	maxBandwidthUsage = actUsage;

      tmpTable[numEntries++]=el;
    }

  if(numEntries > 0) {
    quicksort(tmpTable, numEntries, sizeof(struct hostTraffic*), sortHostFctn);

    if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", HOSTS_INFO_HTML, sign) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", HOSTS_INFO_HTML) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");

    if(abs(columnSort) == 1) {
      arrow[1] = arrowGif;
      theAnchor[1] = htmlAnchor;
    } else {
      arrow[1] = "";
      theAnchor[1] = htmlAnchor1;
    }

    if(abs(columnSort) == 2) {
      arrow[2] = arrowGif;
      theAnchor[2] = htmlAnchor;
    } else {
      arrow[2] = "";
      theAnchor[2] = htmlAnchor1;
    }

    if(abs(columnSort) == 3) {
      arrow[3] = arrowGif;
      theAnchor[3] = htmlAnchor;
    } else {
      arrow[3] = "";
      theAnchor[3] = htmlAnchor1;
    }

    if(abs(columnSort) == 4) {
      arrow[4] = arrowGif;
      theAnchor[4] = htmlAnchor;
    } else {
      arrow[4] = "";
      theAnchor[4] = htmlAnchor1;
    }

    if(abs(columnSort) == 5) {
      arrow[5] = arrowGif;
      theAnchor[5] = htmlAnchor;
    } else {
      arrow[5] = "";
      theAnchor[5] = htmlAnchor1;
    }

    if(abs(columnSort) == 6) {
      arrow[6] = arrowGif;
      theAnchor[6] = htmlAnchor;
    } else {
      arrow[6] = "";
      theAnchor[6] = htmlAnchor1;
    }

    if(abs(columnSort) == DOMAIN_DUMMY_IDX_VALUE) {
      arrow[0] = arrowGif;
      theAnchor[0] = htmlAnchor;
    } else {
      arrow[0] = "";
      theAnchor[0] = htmlAnchor1;
    }

    if(snprintf(buf, sizeof(buf), "<CENTER>"TABLE_ON"<TABLE BORDER=1>\n<TR>"
		"<TH "TH_BG">%s1>Host%s</A></TH>"
		"<TH "TH_BG">%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
		"</TH><TH "TH_BG">%s2>IP&nbsp;Address%s</A></TH>\n"
		"<TH "TH_BG">%s3>MAC&nbsp;Address%s</A></TH>"
		"<TH "TH_BG">%s6>Other&nbsp;Name(s)%s</A></TH>"
		"<TH "TH_BG">%s4>Sent&nbsp;Bandwidth%s</A></TH>"
		"<TH "TH_BG">%s5>Nw&nbsp;Board&nbsp;Vendor%s</A></TH>"
		"</TR>\n",
		theAnchor[1], arrow[1],
		theAnchor[0], arrow[0],
		theAnchor[2], arrow[2],
		theAnchor[3], arrow[3],
		theAnchor[6], arrow[6],
		theAnchor[4], arrow[4],
		theAnchor[5], arrow[5]) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

    for(idx=0; idx<numEntries; idx++) {
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
	    tmpName1 = separator;

	  tmpName2 = getVendorInfo(el->ethAddress, 1);
	  if(tmpName2[0] == '\0')
	    tmpName2 = separator;

	  tmpName3 = el->ethAddressString;
	  if((tmpName3[0] == '\0')
	     || (strcmp(tmpName3, "00:00:00:00:00:00") == 0))
	    tmpName3 = separator;

	  if(snprintf(buf, sizeof(buf), "<TR %s>"
		      "%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		      getRowColor(),
		      makeHostLink(el, LONG_FORMAT, 0, 1),
		      tmpName1, tmpName3) < 0) 
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);

	  sendString("<TD "TD_BG" ALIGN=RIGHT NOWRAP>");

	  if(getSniffedDNSName(el->hostNumIpAddress, sniffedName, sizeof(sniffedName))) 
            if((el->hostSymIpAddress[0] == '\0')
	       || strcmp(sniffedName, el->hostSymIpAddress)) 
              displaySniffedName=1;


	  if(el->nbHostName || el->atNetwork || el->ipxHostName || displaySniffedName) {
	    short numAddresses = 0;

	    if(el->nbHostName && el->nbDomainName) {	      
	      if(el->nbAccountName) {
		if(el->nbDomainName != NULL) {
		  if(snprintf(buf, sizeof(buf), "%s&nbsp;%s@%s&nbsp;[%s]", getOSFlag("Windows", 0),
			      el->nbAccountName, el->nbHostName, el->nbDomainName) < 0)
		 traceEvent(TRACE_ERROR, "Buffer overflow!");
		} else {
		  if(snprintf(buf, sizeof(buf), "%s&nbsp;%s@%s", getOSFlag("Windows", 0),
			      el->nbAccountName, el->nbHostName) < 0)
		    traceEvent(TRACE_ERROR, "Buffer overflow!");
		}
	      } else {
		if(el->nbDomainName != NULL) {
		  if(snprintf(buf, sizeof(buf), "%s&nbsp;%s&nbsp;[%s]", getOSFlag("Windows", 0),
			      el->nbHostName, el->nbDomainName) < 0)
		    traceEvent(TRACE_ERROR, "Buffer overflow!");
		} else {
		  if(snprintf(buf, sizeof(buf), "%s&nbsp;%s", getOSFlag("Windows", 0),
			      el->nbHostName) < 0)
		    traceEvent(TRACE_ERROR, "Buffer overflow!");
		}
	      }
	      sendString(buf);
	      numAddresses++;
	    } else if(el->nbHostName) {
	      if(snprintf(buf, sizeof(buf), "%s&nbsp;%s", getOSFlag("Windows", 0),
			  el->nbHostName) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	      sendString(buf);
	      numAddresses++;
	    }

	    if(el->nbDescr) {
	      if(snprintf(buf, sizeof(buf), ":&nbsp;%s", el->nbDescr) < 0)
		traceEvent(TRACE_ERROR, "Buffer overflow!");
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
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	      sendString(buf);

	      if(el->atNodeType[0] != NULL) {
		int i;
		
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
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	      sendString(buf);
	      numAddresses++;
	    }

	    if(el->ipxHostName) {
	      int i;
	      
	      if(numAddresses > 0) sendString("/");
	      if(snprintf(buf, sizeof(buf), "%s&nbsp;%s&nbsp;", 
			  getOSFlag("Novell", 0),
			  el->ipxHostName) < 0) 
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	      sendString(buf);

	      for(i=0; i<el->numIpxNodeTypes; i++) {
		if(i == 0) 
		  sendString("[");
		else
		  sendString("/");
		sendString(getSAPInfo(el->ipxNodeType[i], 1));
	      }

	      if(i>0) 
		sendString("]");
	      
	      numAddresses++;
	    }
	  }

	  sendString("&nbsp;</TD>");
	  printBar(buf, sizeof(buf), el->actBandwidthUsage, maxBandwidthUsage, 3);
	  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>", tmpName2) < 0) 
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	  sendString("</TR>\n");
	}

	/* Avoid huge tables */
	if(printedEntries++ > maxNumLines)
	  break;	
      } else {
	traceEvent(TRACE_WARNING, "WARNING: quicksort() problem!");
      }
    }

    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");
  }
  free(tmpTable);
}

/* ************************************ */

void printAllSessionsHTML(char* host) {
  u_int idx, elIdx, i;
  HostTraffic *el=NULL;
  char buf[BUF_SIZE];

  for(elIdx=1; elIdx<device[actualReportDeviceId].actualHashSize; elIdx++) {
    el = device[actualReportDeviceId].hash_hostTraffic[elIdx];

    if((elIdx != broadcastEntryIdx)
       && (el != NULL)
       && (el->hostNumIpAddress != NULL)
       && ((strcmp(el->hostNumIpAddress, host) == 0)
	   || (strcmp(el->ethAddressString, host) == 0)))
      break;
  }

  if(el == NULL) {
    if(snprintf(buf, sizeof(buf), 
		"Unable to generate the page requested [%s]\n", host) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    printHTMLheader(buf, 0);
    return;
  }

  /* ************************************ */

  printHostDetailedInfo(el);
  printHostTrafficStats(el);
  printHostContactedPeers(el);
  printHostUsedServices(el);

  /* ***************************************************** */

  i = 0;

  for(idx=1; idx<1024; idx++) {
    if(el->portsUsage[idx] != NULL) {
      char *svc = getAllPortByNum(idx);
      char webHostName[256];
      HostTraffic *peerHost;

      if(i == 0) {
	printSectionTitle("TCP/UDP&nbsp;Service/Port&nbsp;Usage\n");
	sendString("<CENTER>\n");
	sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=100%%>\n<TR>"
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
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		"<TD "TD_BG" ALIGN=CENTER>%d</TD>", getRowColor(), svc, idx) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      } else {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%d</TH>"
		 "<TD "TD_BG" ALIGN=CENTER>%d</TD>", getRowColor(), idx, idx) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      }

      sendString(buf);

      if(el->portsUsage[idx]->clientUses > 0) {
	/* Fix below courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */
	peerHost = device[actualReportDeviceId].
	  hash_hostTraffic[checkSessionIdx(el->portsUsage[idx]->clientUsesLastPeer)];

	if(peerHost == NULL) {
	  /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
	  strncpy(webHostName, "&nbsp;", sizeof(webHostName));
	} else
	  strncpy(webHostName, makeHostLink(peerHost, SHORT_FORMAT, 0, 0), sizeof(webHostName));

	if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d/%s</TD>"
		    "<TD "TD_BG" ALIGN=CENTER>%s</TD>",
		    el->portsUsage[idx]->clientUses,
		    formatBytes(el->portsUsage[idx]->clientTraffic, 1),
		    webHostName) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      } else
	sendString("<TD "TD_BG">&nbsp;</TD><TD "TD_BG">&nbsp;</TD>");

      if(el->portsUsage[idx]->serverUses > 0) {
	peerHost = device[actualReportDeviceId].
	  hash_hostTraffic[checkSessionIdx(el->portsUsage[idx]->serverUsesLastPeer)];

	if(peerHost == NULL) {
	  /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
	  strncpy(webHostName, "&nbsp;", sizeof(webHostName));
	} else
	  strncpy(webHostName, makeHostLink(peerHost, SHORT_FORMAT, 0, 0), sizeof(webHostName));

	if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER>%d/%s</TD>"
		"<TD "TD_BG" ALIGN=CENTER>%s</TD></TR>",
		el->portsUsage[idx]->serverUses,
		formatBytes(el->portsUsage[idx]->serverTraffic, 1),
		webHostName) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      } else
	sendString("<TD "TD_BG">&nbsp;</TD><TD "TD_BG">&nbsp;</TD></TR>");
    }
  }

  if(i > 0){
    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");
  }

  printHostSessions(el, elIdx);
}

/* ************************************ */

void printLocalRoutersList(void) {
  char buf[BUF_SIZE];
  HostTraffic *el, *router;
  u_int idx, i, j, numEntries=0;
  u_int routerList[MAX_NUM_ROUTERS];

  printHTMLheader("Local Subnet Routers", 0);

  for(idx=1; idx<device[actualReportDeviceId].actualHashSize; idx++) {
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
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
    sendString(""TABLE_ON"<TABLE BORDER=1><TR><TH "TH_BG">Router Name</TH>"
	       "<TH "TH_BG">Used by</TH></TR>\n");

    for(i=0; i<numEntries; i++) {
      router = device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(routerList[i])];
      if(router != NULL) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=left>%s</TH><TD "TD_BG" ALIGN=LEFT><UL>\n",
		getRowColor(),
		makeHostLink(router, SHORT_FORMAT, 0, 0)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);

	for(idx=1; idx<device[actualReportDeviceId].actualHashSize; idx++)
	  if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
	     && subnetLocalHost(el)) {
	    for(j=0; j<MAX_NUM_CONTACTED_PEERS; j++)
	      if(el->contactedRouters.peersIndexes[j] == routerList[i]) {
		if(snprintf(buf, sizeof(buf), "<LI>%s</LI>\n",
			    makeHostLink(el, SHORT_FORMAT, 0, 0)) < 0) 
		  traceEvent(TRACE_ERROR, "Buffer overflow!");
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

#ifdef DEBUG
void printSession(IPSession *theSession, u_short sessionType,
		  u_short sessionCounter)
{
  char *_sport, *_dport, *_sessionType, *direction;

  if(logd == NULL) return;

  _sport = getPortByNum(theSession->sport, sessionType);
  _dport = getPortByNum(theSession->dport, sessionType);

  if(_sport == NULL) {
    static char __sport[8];
    if(snprintf(__sport, 8, "%d", (int)theSession->sport) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    _sport = __sport;
  }

  if(_dport == NULL) {
    static char __dport[8];
    if(snprintf(__dport, 8, "%d", (int)theSession->dport) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    _dport = __dport;
  }

  if(sessionType == IPPROTO_TCP) {
    _sessionType = "TCP";
    direction = "<->";
  } else {
    _sessionType = "UDP";
    direction = " >";
  }

  printLogTime();

#ifdef MULTITHREADED
  accessMutex(&addressResolutionMutex, "printSessions");
#endif
  fprintf(logd," %s %s:%s %s %s:%s s=%llu/r=%llu\n",
	  _sessionType,
	  device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(theSession->initiatorIdx)]->hostSymIpAddress, _sport,
	  direction,
	  device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(theSession->remotePeerIdx)]->hostSymIpAddress, _dport,
	  (unsigned long)theSession->bytesSent,
	  (unsigned long)theSession->bytesReceived);
#ifdef MULTITHREADED
  releaseMutex(&addressResolutionMutex);
#endif
}

/* ************************************ */

static void printSessions(IPSession *sessions[], u_short type) {
  int idx;
  char* sessionType;

  if(type == IPPROTO_TCP)
    sessionType = "TCP";
  else
    sessionType = "UDP";


  if (logTimeout) {
    for(idx=1; idx<device[actualReportDeviceId].actualHashSize; idx++)
      if(sessions[idx] != NULL) {

	char *_sport = getPortByNum(sessions[idx]->sport, type);
	char *_dport = getPortByNum(sessions[idx]->dport, type);

	if(_sport == NULL) {
	  static char __sport[8];
	  if(snprintf(__sport, 8, "%d", sessions[idx]->sport) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  _sport = __sport;
	}

	if(_dport == NULL) {
	  static char __dport[8];
	  if(snprintf(__dport, 8, "%d", sessions[idx]->dport) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  _dport = __dport;
	}

	printLogTime();
#ifdef MULTITHREADED
	accessMutex(&addressResolutionMutex, "printProcessInfo");
#endif
	fprintf(logd, "%s\t%s:%s <-> %s:%s\ts=%lu/r=%lu\n",
		sessionType,
		device[actualReportDeviceId].
		hash_hostTraffic[checkSessionIdx(sessions[idx]->initiatorIdx)]->hostSymIpAddress,
		_sport,
		device[actualReportDeviceId].
		hash_hostTraffic[checkSessionIdx(sessions[idx]->remotePeerIdx)]->hostSymIpAddress,
		_dport,
		(unsigned long)sessions[idx]->bytesSent,
		(unsigned long)sessions[idx]->bytesReceived);
#ifdef MULTITHREADED
	releaseMutex(&addressResolutionMutex);
#endif
      }
  }

}

void printTCPSessions(void) { 
  printSessions(device[actualReportDeviceId].tcpSession, IPPROTO_TCP); 
}

#endif /* DEBUG */

/* ************************************ */

RETSIGTYPE printIpAccounting(int remoteToLocal, int sortedColumn,
			     int revertOrder) {
  u_int idx, numEntries;
  int printedEntries=0;
  HostTraffic *el, **tmpTable;
  char buf[BUF_SIZE], *str=NULL, *sign, *title=NULL;
  TrafficCounter totalBytesSent, totalBytesReceived, totalBytes, a=0, b=0;
  float sentpct, rcvdpct;
  time_t timeDiff = time(NULL)-initialSniffTime;
  char *arrowGif, *arrow[48], *theAnchor[48];
  char htmlAnchor[64], htmlAnchor1[64];

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG SRC=arrow_down.gif BORDER=0>";
  }

  totalBytesSent=0, totalBytesReceived=0;
  tmpTable = (HostTraffic**)malloc(device[actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));
  memset(tmpTable, 0, device[actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));
  
  for(idx=1, numEntries=0; idx<device[actualReportDeviceId].actualHashSize; idx++)
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && (broadcastHost(el) == 0) /* No broadcast addresses please */
       && (multicastHost(el) == 0) /* No multicast addresses please */
       && ((el->hostNumIpAddress[0] != '\0')
	   && (el->hostNumIpAddress[0] != '0' /* 0.0.0.0 */)
	   /* This host speaks IP */)) {
      switch(remoteToLocal) {
      case REMOTE_TO_LOCAL_ACCOUNTING:
	if(!subnetPseudoLocalHost(el)) {
	  if((el->bytesSentLocally > 0) || (el->bytesReceivedLocally > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentLocally;
	    totalBytesReceived += el->bytesReceivedLocally;
	  }
	}
	break;
      case LOCAL_TO_REMOTE_ACCOUNTING:
	if(subnetPseudoLocalHost(el)) {
	  if((el->bytesSentRemotely > 0) || (el->bytesReceivedFromRemote > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentRemotely;
	    totalBytesReceived += el->bytesReceivedFromRemote;
	  }
	}
	break;
      case LOCAL_TO_LOCAL_ACCOUNTING:
	if(subnetPseudoLocalHost(el)) {
	  if((el->bytesSentLocally > 0) || (el->bytesReceivedLocally > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentLocally;
	    totalBytesReceived += el->bytesReceivedLocally;
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
    columnSort = sortedColumn;
    sortFilter = remoteToLocal;
    quicksort(tmpTable, numEntries, sizeof(struct hostTraffic*), cmpHostsFctn);

    if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", str, sign) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", str) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");

    if(abs(columnSort) == 1) {
      arrow[1] = arrowGif;
      theAnchor[1] = htmlAnchor;
    } else {
      arrow[1] = "";
      theAnchor[1] = htmlAnchor1;
    }

    if(abs(columnSort) == 2)  {
      arrow[2] = arrowGif;
      theAnchor[2] = htmlAnchor;
    } else {
      arrow[2] = "";
      theAnchor[2] = htmlAnchor1;
    }

    if(abs(columnSort) == 3) {
      arrow[3] = arrowGif;
      theAnchor[3] = htmlAnchor;
    } else {
      arrow[3] = "";
      theAnchor[3] = htmlAnchor1;
    }

    if(abs(columnSort) == 4) {
      arrow[4] = arrowGif;
      theAnchor[4] = htmlAnchor;
    } else {
      arrow[4] = "";
      theAnchor[4] = htmlAnchor1;
    }

    sendString("<CENTER>\n");
    if(snprintf(buf, sizeof(buf), ""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\">\n<TR><TH "TH_BG">"
	    "%s1>Host%s</A></TH>"
	    "<TH "TH_BG">%s2>IP&nbsp;Address%s</A></TH>\n"
	    "<TH "TH_BG" COLSPAN=2>%s3>Data&nbsp;Sent%s</A></TH>"
	    "<TH "TH_BG" COLSPAN=2>%s4>Data&nbsp;Received%s</A></TH></TR>\n",
	    theAnchor[1], arrow[1],
	    theAnchor[2], arrow[2], theAnchor[3], arrow[3],
	    theAnchor[4], arrow[4]) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");

    sendString(buf);

    for(idx=0; idx<numEntries; idx++) {
      if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	char *tmpName1;
	tmpName1 = el->hostNumIpAddress;
	if((tmpName1[0] == '\0') || (strcmp(tmpName1, "0.0.0.0") == 0))
	  tmpName1 = separator;

	switch(remoteToLocal) {
	case REMOTE_TO_LOCAL_ACCOUNTING:
	  a = el->bytesSentLocally;
	  b = el->bytesReceivedLocally;
	  break;
	case LOCAL_TO_REMOTE_ACCOUNTING:
	  a = el->bytesSentRemotely;
	  b = el->bytesReceivedFromRemote;
	  break;
	case LOCAL_TO_LOCAL_ACCOUNTING:
	  a = el->bytesSentLocally;
	  b = el->bytesReceivedLocally;
	  break;
	}

	if(a < 100)  /* Avoid very small decimal values */
	  sentpct = 0;
	else
	  sentpct = (100*(float)a)/totalBytesSent;

	if(b < 100)  /* Avoid very small decimal values */
	  rcvdpct = 0;
	else
	  rcvdpct = (100*(float)b)/totalBytesReceived;

	if(snprintf(buf, sizeof(buf), "<TR %s>"
		"%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD></TR>\n",
		getRowColor(),
		makeHostLink(el, LONG_FORMAT, 0, 0),
		tmpName1,
		formatBytes(a, 1),
		sentpct, separator,
		formatBytes(b, 1),
		rcvdpct, separator) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);

	/* Avoid huge tables */
	if(printedEntries++ > maxNumLines)
	  break;	
      }
    }

    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("<P>"TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\">\n<TR>"
	       "<TH "TH_BG">Total Traffic</TH><TH "TH_BG">Data Sent</TH>\n"
	       "<TH "TH_BG">Data Received</TH><TH "TH_BG">Used Bandwidth</TH></TR>\n");

    totalBytes = totalBytesSent+totalBytesReceived;

    /* In this case the total traffic is just half and
       the following statement holds:
       totalBytesSent == totalBytesReceived 
       
       Courtesy of Jac Engel <jacengel@home.nl>
    */
    if(remoteToLocal == LOCAL_TO_LOCAL_ACCOUNTING)
      totalBytes /= 2;

    if(snprintf(buf, sizeof(buf), "<TR>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		formatBytes(totalBytes, 1),
		formatBytes(totalBytesSent, 1),
		formatBytes(totalBytesReceived, 1),
		formatThroughput((float)(totalBytes/timeDiff))) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");

    sendString(buf);
    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");
  } else
    printNoDataYet();

  free(tmpTable);
}

/* ********************************** */

void printActiveTCPSessions(void) {
  int idx;
  char buf[BUF_SIZE];
  int numSessions;

  printHTMLheader("Active TCP Sessions", 0);

  for(idx=1, numSessions=0; idx<device[actualReportDeviceId].numTotSessions; idx++)
    if((device[actualReportDeviceId].tcpSession[idx] != NULL)
#ifndef PRINT_ALL_ACTIVE_SESSIONS
       && (device[actualReportDeviceId].tcpSession[idx]->sessionState == STATE_ACTIVE)
#endif
       ) {

      char *sport, *dport;
      TrafficCounter dataSent, dataReceived;

      if(numSessions == 0) {
	sendString("<CENTER>\n");
	sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\"><TR>"
		   "<TH "TH_BG">Client</TH>"
		   "<TH "TH_BG">Server</TH>"
		   "<TH "TH_BG">Data&nbsp;Sent</TH>"
		   "<TH "TH_BG">Data&nbsp;Rcvd</TH>"
		   "<TH "TH_BG">Active&nbsp;Since</TH>"
		   "<TH "TH_BG">Last&nbsp;Seen</TH>"
		   "<TH "TH_BG">Duration</TH>"
		   "<TH "TH_BG">Latency</TH>"
#ifdef PRINT_ALL_ACTIVE_SESSIONS
		   "<TH "TH_BG">State</TH>"
#endif
		   "</TR>\n");
      }

      sport = getPortByNum(device[actualReportDeviceId].tcpSession[idx]->sport, IPPROTO_TCP);
      dport = getPortByNum(device[actualReportDeviceId].tcpSession[idx]->dport, IPPROTO_TCP);
      dataSent = device[actualReportDeviceId].tcpSession[idx]->bytesSent;
      dataReceived = device[actualReportDeviceId].tcpSession[idx]->bytesReceived;

      if(sport == NULL) {
	static char _sport[8];
	if(snprintf(_sport, 8, "%d", device[actualReportDeviceId].tcpSession[idx]->sport) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sport = _sport;
      }

      if(dport == NULL) {
	static char _dport[8];
	if(snprintf(_dport, 8, "%d", device[actualReportDeviceId].tcpSession[idx]->dport) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	dport = _dport;
      }

      /* Sanity check */
      if((actTime < device[actualReportDeviceId].tcpSession[idx]->firstSeen)
	 || (device[actualReportDeviceId].tcpSession[idx]->firstSeen == 0))
	device[actualReportDeviceId].tcpSession[idx]->firstSeen = actTime;

      if(snprintf(buf, sizeof(buf), "<TR %s>"
	      "<TD "TD_BG" ALIGN=RIGHT>%s:%s</TD>"
	      "<TD "TD_BG" ALIGN=RIGHT>%s:%s</TD>"
	      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
	      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
	      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
	      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
	      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
	      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
#ifdef PRINT_ALL_ACTIVE_SESSIONS
		  "<TD "TD_BG" ALIGN=CENTER>%s</TD>"
#endif
		  "</TR>\n",
		  getRowColor(),
		  makeHostLink(device[actualReportDeviceId].
			       hash_hostTraffic[checkSessionIdx(device[actualReportDeviceId].
								tcpSession[idx]->initiatorIdx)], 
			       SHORT_FORMAT, 0, 0),
		  sport,
		  makeHostLink(device[actualReportDeviceId].
			       hash_hostTraffic[checkSessionIdx(device[actualReportDeviceId].
								tcpSession[idx]->remotePeerIdx)], 
			       SHORT_FORMAT, 0, 0),
		  dport,
		  formatBytes(dataSent, 1),
		  formatBytes(dataReceived, 1),
		  formatTime(&(device[actualReportDeviceId].tcpSession[idx]->firstSeen), 1),
		  formatTime(&(device[actualReportDeviceId].tcpSession[idx]->lastSeen), 1),
		  formatSeconds(actTime-device[actualReportDeviceId].tcpSession[idx]->firstSeen),
		  formatLatency(device[actualReportDeviceId].tcpSession[idx]->nwLatency, 
				device[actualReportDeviceId].tcpSession[idx]->sessionState)
#ifdef PRINT_ALL_ACTIVE_SESSIONS
		  , getSessionState(device[actualReportDeviceId].tcpSession[idx])
#endif
		  ) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");

      sendString(buf);
      numSessions++;
    }

  if(numSessions > 0) {
    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");
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

  hosts = (HostTraffic**)malloc(device[actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));
  memset(hosts, 0, device[actualReportDeviceId].actualHashSize*sizeof(HostTraffic*));

  for(i=0; i<device[actualReportDeviceId].actualHashSize; i++)
    if((device[actualReportDeviceId].hash_hostTraffic[i] != NULL)
       && subnetPseudoLocalHost(device[actualReportDeviceId].hash_hostTraffic[i])
       && (device[actualReportDeviceId].hash_hostTraffic[i]->hostNumIpAddress[0] != '\0')) {
      hosts[hostsNum++] = device[actualReportDeviceId].hash_hostTraffic[i];

      for(j=0; j<TOP_ASSIGNED_IP_PORTS; j++) {
	if(device[actualReportDeviceId].hash_hostTraffic[i]->portsUsage[j] != NULL)  {
	  clientPorts[j] += device[actualReportDeviceId].hash_hostTraffic[i]->portsUsage[j]->clientUses;
	  serverPorts[j] += device[actualReportDeviceId].hash_hostTraffic[i]->portsUsage[j]->serverUses;
	  numPorts++;
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
  sendString(""TABLE_ON"<TABLE BORDER=1><TR><TH "TH_BG" COLSPAN=2>Service</TH>"
	     "<TH "TH_BG">Clients</TH><TH "TH_BG">Servers</TH>\n");

  for(j=0; j<TOP_ASSIGNED_IP_PORTS; j++)
    if((clientPorts[j] > 0) || (serverPorts[j] > 0)) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=CENTER>%d</TD>"
	      "<TD "TD_BG">\n", getRowColor(), getAllPortByNum(j), j) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(clientPorts[j] > 0) {
	sendString("<UL>");
	for(idx1=0; idx1<hostsNum; idx1++)
	  if((hosts[idx1]->portsUsage != NULL)
	     && (hosts[idx1]->portsUsage[j] != NULL) /* added 04.03.00 Ralf Amandi */
	     && (hosts[idx1]->portsUsage[j]->clientUses > 0)) {
	    if(snprintf(buf, sizeof(buf), "<li>%s\n",
			makeHostLink(hosts[idx1], SHORT_FORMAT, 1, 0)) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
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
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
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
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    break;
  default:
    if(snprintf(buf, bufLen, "<TD "TD_BG" ALIGN=LEFT><IMG ALIGN=ABSMIDDLE SRC=/gauge.jpg"
		" WIDTH=%d HEIGHT=12>&nbsp;</TD>\n",
		ratio*int_perc) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
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
    if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"</TR>\n",
		getRowColor(), label, formatKBytes(total)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    break;
  case 100:
    if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"</TR>\n",
		getRowColor(), label, formatKBytes(total)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    break;
  default:
    if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		"</TR>\n",
		getRowColor(), label, formatKBytes(total)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
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

    total = (float)(device[actualReportDeviceId].tcpGlobalTrafficStats.local+
		    device[actualReportDeviceId].udpGlobalTrafficStats.local)/1024;
    if(total == 0)
      printNoDataYet();
    else {
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\"><TR>"
		 "<TH "TH_BG" WIDTH=150>IP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
		 "Percentage</TH></TR>\n");
      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)device[actualReportDeviceId].tcpGlobalTrafficStats.local/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP",
				"TCP", "UDP", total, percentage);

      sendString("</TABLE>"TABLE_OFF"\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\"><TR>"
                  "<TH "TH_BG" WIDTH=150>TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
                 "Percentage</TH></TR>\n");

      for(i=0; i<numIpProtosToMonitor; i++) {
	partialTotal = (float)device[actualReportDeviceId].ipProtoStats[i].local/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), protoIPTrafficInfos[i],
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

    total = (float)(device[actualReportDeviceId].tcpGlobalTrafficStats.remote2local+
		    device[actualReportDeviceId].udpGlobalTrafficStats.remote2local)/1024;

    printSectionTitle("Remote to Local Traffic");

    if(total == 0)
      printNoDataYet();
    else {
      sendString("<CENTER>\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\"><TR>"
		 "<TH "TH_BG" WIDTH=150>IP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
		 "Percentage</TH></TR>\n");

      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)device[actualReportDeviceId].tcpGlobalTrafficStats.remote2local/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP",
				"TCP", "UDP", total, percentage);

      sendString("</TABLE>"TABLE_OFF);
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\"><TR>"
		 "<TH "TH_BG" WIDTH=150>TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
		 "Percentage</TH></TR>\n");

      for(i=0; i<numIpProtosToMonitor; i++) {
	partialTotal = (float)device[actualReportDeviceId].ipProtoStats[i].remote2local/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), protoIPTrafficInfos[i],
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

    printSectionTitle("Local to Remote Traffic");

    total = (float)(device[actualReportDeviceId].tcpGlobalTrafficStats.local2remote+
		    device[actualReportDeviceId].udpGlobalTrafficStats.local2remote)/1024;
    if(total == 0)
      printNoDataYet();
    else {
      sendString("<CENTER>\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\"><TR>"
		 "<TH "TH_BG" WIDTH=150>IP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH>"
		 "<TH "TH_BG" WIDTH=250>Percentage</TH></TR>\n");

      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)device[actualReportDeviceId].tcpGlobalTrafficStats.local2remote/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP",
				"TCP", "UDP", total, percentage);

      sendString("</TABLE>"TABLE_OFF);
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\"><TR>"
		 "<TH "TH_BG" WIDTH=150>TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH>"
		 "<TH "TH_BG" WIDTH=250>Percentage</TH></TR>\n");

      for(i=0; i<numIpProtosToMonitor; i++) {
	partialTotal = (float)device[actualReportDeviceId].ipProtoStats[i].local2remote/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), protoIPTrafficInfos[i],
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
    total = (float)device[actualReportDeviceId].ipBytes/1024; /* total is expressed in KBytes */

    if(total == 0)
      return;
    else {
      printSectionTitle("Global TCP/UDP Protocol Distribution");
      
      sendString("<CENTER>\n");
      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=500><TR><TH "TH_BG" WIDTH=150>"
		 "TCP/UDP&nbsp;Protocol</TH>"
		 "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>"
		 "Percentage</TH></TR>\n");

      remainingTraffic = 0;

      for(i=0; i<numIpProtosToMonitor; i++) {
	partialTotal  = (float)device[actualReportDeviceId].ipProtoStats[i].local
	  +device[actualReportDeviceId].ipProtoStats[i].remote;
	partialTotal += (float)device[actualReportDeviceId].ipProtoStats[i].remote2local
	  +device[actualReportDeviceId].ipProtoStats[i].local2remote;

	if(partialTotal > 0) {
	  partialTotal /= 1024;
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), protoIPTrafficInfos[i],
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
      sendString("<TR><TD "TD_BG" COLSPAN=3 ALIGN=CENTER>"
		 "<IMG SRC=drawGlobalIpProtoDistribution"CHART_FORMAT"></TD></TR>\n");
#endif
      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }
  }
}

/* ************************ */

void printProtoTraffic(void) {
  float total;
  char buf[BUF_SIZE];

  total = device[actualReportDeviceId].ethernetBytes/1024; /* total is expressed in KBytes */

  if(total == 0)
    return;

  printSectionTitle("Global Protocol Distribution");
  sendString("<CENTER>\n");
  sendString("<P>"TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\"><TR><TH "TH_BG" WIDTH=150>Protocol</TH>"
	     "<TH "TH_BG" WIDTH=100>Data</TH><TH "TH_BG" WIDTH=250>Percentage</TH></TR>\n");
  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" WIDTH=150 ALIGN=LEFT>IP</TH>"
	      "<TD "TD_BG" WIDTH=100 ALIGN=RIGHT>%s"
	      "&nbsp;(%.1f%%)</TD><TD "TD_BG" WIDTH=250>"
	      "<TABLE BORDER=1 WIDTH=\"100%%\">", 
	      getRowColor(),
	      formatBytes(device[actualReportDeviceId].ipBytes, 1),
	      100*((float)device[actualReportDeviceId].ipBytes/
		   device[actualReportDeviceId].ethernetBytes)) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  
  printTableEntry(buf, sizeof(buf), "TCP", COLOR_1,
		  (float)device[actualReportDeviceId].tcpBytes/1024,
		  100*((float)device[actualReportDeviceId].tcpBytes/device[actualReportDeviceId].ipBytes));
  printTableEntry(buf, sizeof(buf), "UDP", COLOR_1,
		  (float)device[actualReportDeviceId].udpBytes/1024,
		  100*((float)device[actualReportDeviceId].udpBytes/device[actualReportDeviceId].ipBytes));
  printTableEntry(buf, sizeof(buf), "ICMP", COLOR_1,
		  (float)device[actualReportDeviceId].icmpBytes/1024,
		  100*((float)device[actualReportDeviceId].icmpBytes/device[actualReportDeviceId].ipBytes));
  printTableEntry(buf, sizeof(buf), "Other&nbsp;IP", COLOR_1,
		  (float)device[actualReportDeviceId].otherIpBytes/1024,
		  ((float)device[actualReportDeviceId].otherIpBytes/device[actualReportDeviceId].ipBytes));

  sendString("</TABLE></TR>");

  printTableEntry(buf, sizeof(buf), "(R)ARP", COLOR_1,
		  (float)device[actualReportDeviceId].arpRarpBytes/1024,
		  100*((float)device[actualReportDeviceId].arpRarpBytes/device[actualReportDeviceId].ipBytes));
  printTableEntry(buf, sizeof(buf), "DLC", COLOR_1,
		  (float)device[actualReportDeviceId].dlcBytes/1024,
		  100*((float)device[actualReportDeviceId].dlcBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "IPX", COLOR_1,
		  (float)device[actualReportDeviceId].ipxBytes/1024,
		  100*((float)device[actualReportDeviceId].ipxBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "Decnet", COLOR_1,
		  (float)device[actualReportDeviceId].decnetBytes/1024,
		  100*((float)device[actualReportDeviceId].decnetBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "AppleTalk", COLOR_1,
		  (float)device[actualReportDeviceId].atalkBytes/1024,
		  100*((float)device[actualReportDeviceId].atalkBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "OSPF", COLOR_1,
		  (float)device[actualReportDeviceId].ospfBytes/1024,
		  100*((float)device[actualReportDeviceId].ospfBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "NetBios", COLOR_1,
		  (float)device[actualReportDeviceId].netbiosBytes/1024,
		  100*((float)device[actualReportDeviceId].netbiosBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "IGMP", COLOR_1,
		  (float)device[actualReportDeviceId].igmpBytes/1024,
		  100*((float)device[actualReportDeviceId].igmpBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "OSI", COLOR_1,
		  (float)device[actualReportDeviceId].osiBytes/1024,
		  100*((float)device[actualReportDeviceId].osiBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "QNX", COLOR_1,
		  (float)device[actualReportDeviceId].qnxBytes/1024,
		  100*((float)device[actualReportDeviceId].qnxBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "STP", COLOR_1,
		  (float)device[actualReportDeviceId].stpBytes/1024,
		  100*((float)device[actualReportDeviceId].stpBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "Other", COLOR_1,
		  (float)device[actualReportDeviceId].otherBytes/1024,
		  100*((float)device[actualReportDeviceId].otherBytes/device[actualReportDeviceId].ethernetBytes));

#ifdef HAVE_GDCHART
  sendString("<TR><TD "TD_BG" COLSPAN=3 ALIGN=CENTER>"
	     "<IMG SRC=drawGlobalProtoDistribution"CHART_FORMAT"></TD></TR>\n");
#endif

  sendString("</TABLE>"TABLE_OFF"<P></CENTER>\n");
}

/* ************************ */

void printProcessInfo(int processPid) {
  char buf[BUF_SIZE];
  int i, j, numEntries;

#ifdef MULTITHREADED
  accessMutex(&lsofMutex, "printLsofData");
#endif

  for(i=0; i<numProcesses; i++)
    if((processes[i] != NULL)
       && (processes[i]->pid == processPid))
      break;

  if(processes[i]->pid != processPid) {
    if(snprintf(buf, sizeof(buf), "Unable to find process PID %d", processPid) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    printHTMLheader(buf, 0);
#ifdef MULTITHREADED
    releaseMutex(&lsofMutex);
#endif
    return;
  }

  if(snprintf(buf, sizeof(buf), "Info about process %s", processes[i]->command) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  printHTMLheader(buf, 0);

  sendString("<CENTER>\n");
  sendString(""TABLE_ON"<TABLE BORDER=1>");

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>User&nbsp;Name</TH>", getRowColor()) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n", processes[i]->user) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Process&nbsp;PID</TH>", getRowColor()) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%d</TD></TR>\n", processes[i]->pid) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>First&nbsp;Seen</TH>", getRowColor()) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
	      formatTime(&processes[i]->firstSeen, 1)) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Last&nbsp;Seen</TH>", getRowColor()) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
	      formatTime(&processes[i]->lastSeen, 1)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Data&nbsp;Sent</TH>", 
	      getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
	      formatBytes(processes[i]->bytesSent, 1)) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Data&nbsp;Rcvd</TH>", getRowColor()) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</T></TR>\n",
	      formatBytes(processes[i]->bytesReceived, 1)) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Open&nbsp;TCP&nbsp;Ports"
	      "</TH><TD "TD_BG" ALIGN=RIGHT>", getRowColor()) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  for(j=0; j<TOP_IP_PORT; j++)
    if(localPorts[j] != NULL) {
      ProcessInfoList *elem = localPorts[j];

      while(elem != NULL) {
	if(elem->element == processes[i]) {
	  if(snprintf(buf, sizeof(buf), "%d<BR>\n", j) < 0) 
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	  break;
	}
	elem = elem->next;
      }
    }

  sendString("</TD></TR>\n");

  for(j=0, numEntries=0; j<MAX_NUM_CONTACTED_PEERS; j++)
    if(processes[i]->contactedIpPeersIndexes[j] != NO_PEER) {

      if(numEntries == 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Contacted&nbsp;Peers"
		    "</TH><TD "TD_BG" ALIGN=RIGHT>", getRowColor()) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(snprintf(buf, sizeof(buf), "%s<BR>\n",
		  makeHostLink(device[actualReportDeviceId].
			       hash_hostTraffic[checkSessionIdx(processes[i]->contactedIpPeersIndexes[j])],
			       0, 0, 0)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
      numEntries++;
    }

  sendString("</TD></TR>\n</TABLE>"TABLE_OFF"</CENTER><P>\n");

#ifdef MULTITHREADED
  releaseMutex(&lsofMutex);
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
  
  processSize = sizeof(ProcessInfo*)*numProcesses;
  processesList = (ProcessInfo**)malloc(processSize);

  printHTMLheader("Local Network Usage by Process", 0);
  sendString("<CENTER>\n");
  if(snprintf(buf, sizeof(buf), ""TABLE_ON"<TABLE BORDER=1><TR>"
	      "<TH "TH_BG"><A HREF=\"%s?1\">Process</A></TH>"
	      "<TH "TH_BG"><A HREF=\"%s?2\">PID</A></TH>"
	      "<TH "TH_BG"><A HREF=\"%s?3\">User</A></TH>"
	      "<TH "TH_BG"><A HREF=\"%s?4\">Sent</A></TH>"
	      "<TH "TH_BG"><A HREF=\"%s?5\">Rcvd</A></TH></TR>\n",
	      STR_LSOF_DATA, STR_LSOF_DATA, STR_LSOF_DATA,
	      STR_LSOF_DATA, STR_LSOF_DATA) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

#ifdef MULTITHREADED
  accessMutex(&lsofMutex, "buildHTMLBrowserWindowsLabel");
#endif

  memcpy(processesList, processes, processSize);
  columnSort = mode;
  quicksort(processesList, numProcesses, sizeof(ProcessInfo*), cmpProcesses);

  /* Avoid huge tables */
  numProcessesToDisplay = numProcesses;
  if(numProcessesToDisplay > maxNumLines)
    numProcessesToDisplay = maxNumLines;

  for(i=0, numUsers=0; i<numProcessesToDisplay; i++) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TD "TD_BG"><A HREF=\""PROCESS_INFO_HTML"?%d\">%s</A></TD>"
	    "<TD "TD_BG" ALIGN=CENTER>%d</TD>"
	    "<TD "TD_BG" ALIGN=CENTER>%s</TD>"
	    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
	    "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
	    getRowColor(),
	    processesList[i]->pid,
	    processesList[i]->command,
	    processesList[i]->pid,
	    processesList[i]->user,
	    formatBytes((TrafficCounter)processesList[i]->bytesSent, 1),
	    formatBytes((TrafficCounter)processesList[i]->bytesReceived, 1)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

    if((processesList[i]->bytesSent > 0) || (processesList[i]->bytesReceived > 0)) {
      for(j=0, found=0; j<numUsers; j++)
	if(strcmp(usersTraffic[j].userName, processesList[i]->user) == 0) {
	  found = 1;
	  break;
	}

      if(!found) {
	usersTraffic[numUsers].userName = processesList[i]->user;
	usersTrafficList[numUsers++] = &usersTraffic[numUsers];
	usersTraffic[j].bytesSent = usersTraffic[j].bytesReceived = 0;
      }

      usersTraffic[j].bytesSent     += processesList[i]->bytesSent;
      usersTraffic[j].bytesReceived += processesList[i]->bytesReceived;
    }
  }

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");
  
  /* ************************ */
  
  printSectionTitle("Local Network Usage by Port");
  sendString("<CENTER>\n");
  sendString(""TABLE_ON"<TABLE BORDER=1><TR><TH "TH_BG">Port</TH>"
	     "<TH "TH_BG">Processes</TH></TR>\n");

  for(i=0; i<TOP_IP_PORT; i++)
    if(localPorts[i] != NULL) {
      ProcessInfoList *scanner;

      if(snprintf(buf, sizeof(buf), "<TR %s><TD "TD_BG" ALIGN=CENTER>%d</TD><TD "TD_BG">", 
		  getRowColor(), i) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      scanner = localPorts[i];

      while(scanner != NULL) {
	if(snprintf(buf, sizeof(buf), "<li><A HREF=\""PROCESS_INFO_HTML"?%d\">%s</A><BR>\n",
		    scanner->element->pid, scanner->element->command) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
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
    if(numUsers > maxNumLines)
      numUsers = maxNumLines;

    printSectionTitle("Local Network Usage by User");
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1><TR><TH "TH_BG">User</TH>"
	       "<TH "TH_BG">Traffic&nbsp;in/out</TH></TR>\n");

    for(i=0; i<numUsers; i++) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TD "TD_BG">%s</TD>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(),
		  usersTrafficList[i]->userName,
		  formatBytes((TrafficCounter)(usersTrafficList[i]->bytesSent+
					       usersTrafficList[i]->bytesReceived), 1)) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }

    sendString("</TABLE>"TABLE_OFF"<P></CENTER>\n");
  }

#ifdef MULTITHREADED
  releaseMutex(&lsofMutex);
#endif

  free(processesList);
}

/* ************************ */

void printIpTrafficMatrix(void) {
  int i, j, numEntries=0, numConsecutiveEmptyCells;
  char buf[BUF_SIZE];
  short *activeHosts;
  TrafficCounter minTraffic=(TrafficCounter)LONG_MAX, maxTraffic=0, avgTraffic;
  TrafficCounter avgTrafficLow, avgTrafficHigh, tmpCounter;

  printHTMLheader("IP Subnet Traffic Matrix", 0);
  
  activeHosts = (short*)malloc(sizeof(short)*device[actualReportDeviceId].numHosts);
  
  for(i=1; i<device[actualReportDeviceId].numHosts-1; i++) {
    activeHosts[i] = 0;
    for(j=1; j<device[actualReportDeviceId].numHosts-1; j++) {
      int id = i*device[actualReportDeviceId].numHosts+j;
      
      if(((device[actualReportDeviceId].ipTrafficMatrix[id] != NULL)
	  && (device[actualReportDeviceId].ipTrafficMatrix[id]->bytesSent != 0))
	 || ((device[actualReportDeviceId].ipTrafficMatrix[id] != NULL) 
	     && (device[actualReportDeviceId].ipTrafficMatrix[id]->bytesReceived != 0))) {
	activeHosts[i] = 1;
	numEntries++;
	break;
      }
    }

    if(activeHosts[i] == 1) {
      if(numEntries == 1) {
	sendString("<CENTER>\n");
	sendString(""TABLE_ON"<TABLE BORDER=1><TR><TH "TH_BG" ALIGN=LEFT><SMALL>&nbsp;F&nbsp;"
		   "&nbsp;&nbsp;To<br>&nbsp;r<br>&nbsp;o<br>&nbsp;m</SMALL></TH>\n");
      }

      if(snprintf(buf, sizeof(buf), "<TH "TH_BG" ALIGN=CENTER><SMALL>%s</SMALL></TH>",
		  getHostName(device[actualReportDeviceId].ipTrafficMatrixHosts[i], 1)) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }
  }

  if(numEntries == 0) {
    printNoDataYet();
    free(activeHosts);
    return;
  } else
    sendString("</TR>\n");

  for(i=1; i<device[actualReportDeviceId].numHosts-1; i++)
    for(j=1; j<device[actualReportDeviceId].numHosts-1; j++) {
      int idx = i*device[actualReportDeviceId].numHosts+j;
	
      if(((device[actualReportDeviceId].ipTrafficMatrix[idx] != NULL)
	 && ((device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent != 0)
	     || (device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesReceived != 0)))) {
	if(minTraffic > device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent)
	  minTraffic = device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent;
	if(minTraffic > device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesReceived)
	  minTraffic = device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesReceived;
	if(maxTraffic < device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent)
	  maxTraffic = device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent;
	if(maxTraffic < device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesReceived)
	  maxTraffic = device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesReceived;
      }
    }

  avgTraffic = (TrafficCounter)(((float)minTraffic+(float)maxTraffic)/2);
  avgTrafficLow  = (avgTraffic*15)/100; /* 15% of the average */
  avgTrafficHigh = 2*(maxTraffic/3);   /* 75% of max traffic */


  for(i=1; i<device[actualReportDeviceId].numHosts; i++)
    if(activeHosts[i] == 1) {
      numConsecutiveEmptyCells=0;

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT><SMALL>%s</SMALL></TH>",
		  getRowColor(), makeHostLink(device[actualReportDeviceId].ipTrafficMatrixHosts[i], 
					      SHORT_FORMAT, 1, 0)) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      for(j=1; j<device[actualReportDeviceId].numHosts; j++) {
	int idx = i*device[actualReportDeviceId].numHosts+j;
	
	if((i == j) && strcmp(device[actualReportDeviceId].ipTrafficMatrixHosts[i]->hostNumIpAddress, "127.0.0.1"))
	  numConsecutiveEmptyCells++;
	else if(activeHosts[j] == 1) {
	  if(device[actualReportDeviceId].ipTrafficMatrix[idx] == NULL)
	    numConsecutiveEmptyCells++;
	  else {
	    if(numConsecutiveEmptyCells > 0) {
	      if(snprintf(buf, sizeof(buf), "<TD "TD_BG" COLSPAN=%d>&nbsp;</TD>\n", 
			  numConsecutiveEmptyCells) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	      sendString(buf);
	      numConsecutiveEmptyCells = 0;
	    }

	    tmpCounter = device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent+
	      device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesReceived;
	    /* Fix below courtesy of Danijel Doriae <danijel.doric@industrogradnja.tel.hr> */
	    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER %s>"
			"<A HREF=# onMouseOver=\"window.status='"
			"%s';return true\" onMouseOut="
			"\"window.status='';return true\"><SMALL>%s</SMALL></A></TH>\n",
			calculateCellColor(tmpCounter, avgTrafficLow, avgTrafficHigh),
			buildHTMLBrowserWindowsLabel(i, j),
			formatBytes(tmpCounter, 1)) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);
	  }
	}
      }

      if(numConsecutiveEmptyCells > 0) {
	if(snprintf(buf, sizeof(buf), "<TD "TD_BG" COLSPAN=%d>&nbsp;</TD>\n", 
		    numConsecutiveEmptyCells) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
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
  int i;
  char label[32], label1[32], buf[BUF_SIZE];
  time_t tmpTime;
  struct tm t;

  printHTMLheader("Network Load Statistics Matrix", 0);

  switch(sortedColumn) {
  case 1:
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1>\n<TR>"
	       "<TH "TH_BG">Sampling Period</TH>"
	       "<TH "TH_BG">Average Thpt</TH>"
	       "<TH "TH_BG">Top Hosts Sent Thpt</TH>"
	       "<TH "TH_BG">Top Hosts Rcvd Thpt</TH></TR>\n");

    for(i=0; i<60; i++) {
      if(device[actualReportDeviceId].last60MinutesThpt[i].trafficValue == 0)
	break;

      tmpTime = actTime-(i*60);
      strftime(label, 32, "%H:%M", localtime_r(&tmpTime, &t));
      tmpTime = actTime-((i+1)*60);
      strftime(label1, 32, "%H:%M", localtime_r(&tmpTime, &t));
      if(snprintf(buf, sizeof(buf), "<TR %s><TD "TD_BG" ALIGN=CENTER>"
		  "<B>%s&nbsp;-&nbsp;%s</B></TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=LEFT>"
		  "<TABLE BORDER=1 WIDTH=100%%>",
		  getRowColor(), label1, label,
		  formatThroughput(device[actualReportDeviceId].
				   last60MinutesThpt[i].trafficValue)) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
	 sendString(buf);

	/* Fix below courtesy of Francis Pintos <francis@arhl.com.hk> */	

	 if((device[actualReportDeviceId].last60MinutesThpt[i].topHostSentIdx != NO_PEER)
	    && (device[actualReportDeviceId].
		hash_hostTraffic[device[actualReportDeviceId].
				last60MinutesThpt[i].topHostSentIdx] != NULL)) {
      if(snprintf(buf, sizeof(buf), "<TR>%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		  makeHostLink(device[actualReportDeviceId].
			       hash_hostTraffic[device[actualReportDeviceId].
					       last60MinutesThpt[i].topHostSentIdx],
			       LONG_FORMAT, 0, 0),
		  formatThroughput(device[actualReportDeviceId].
				   last60MinutesThpt[i].topSentTraffic)) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
      
	/* Fix below courtesy of Francis Pintos <francis@arhl.com.hk> */	
      if((device[actualReportDeviceId].last60MinutesThpt[i].secondHostSentIdx != NO_PEER)
	 && (device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
							  last60MinutesThpt[i].secondHostSentIdx] != NULL)) {
	if(snprintf(buf, sizeof(buf), "<TR>%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		    makeHostLink(device[actualReportDeviceId].
				   hash_hostTraffic[device[actualReportDeviceId].
						   last60MinutesThpt[i].secondHostSentIdx],
				   LONG_FORMAT, 0, 0),
		    formatThroughput(device[actualReportDeviceId].
				     last60MinutesThpt[i].secondSentTraffic)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }
      
      /* Fix below courtesy of Francis Pintos <francis@arhl.com.hk> */
      if((device[actualReportDeviceId].last60MinutesThpt[i].thirdHostSentIdx != NO_PEER) 
	 && (device[actualReportDeviceId].
	     hash_hostTraffic[device[actualReportDeviceId].last60MinutesThpt[i].
			     thirdHostSentIdx] != NULL)) {
	if(snprintf(buf, sizeof(buf), "<TR>%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		    makeHostLink(device[actualReportDeviceId].
				 hash_hostTraffic[device[actualReportDeviceId].
						 last60MinutesThpt[i].thirdHostSentIdx],
				 LONG_FORMAT, 0, 0),
		    formatThroughput(device[actualReportDeviceId].
				     last60MinutesThpt[i].thirdSentTraffic)) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	}
	 } else
	   sendString("&nbsp;");
	 
      sendString("</TABLE></TD><TD "TD_BG" ALIGN=LEFT><TABLE BORDER=1 WIDTH=100%%>\n");

      /* *************************************** */

      
      if((device[actualReportDeviceId].last60MinutesThpt[i].topHostRcvdIdx != NO_PEER)
	 && (device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
							  last60MinutesThpt[i].topHostRcvdIdx] != NULL)) {
	if(snprintf(buf, sizeof(buf), "<TR>%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		    makeHostLink(device[actualReportDeviceId].
				 hash_hostTraffic[device[actualReportDeviceId].
						 last60MinutesThpt[i].topHostRcvdIdx],
				 LONG_FORMAT, 0, 0),
		    formatThroughput(device[actualReportDeviceId].
				     last60MinutesThpt[i].topRcvdTraffic)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	   sendString(buf);

	if((device[actualReportDeviceId].last60MinutesThpt[i].secondHostRcvdIdx != NO_PEER)
	   && (device[actualReportDeviceId].
	       hash_hostTraffic[device[actualReportDeviceId].
			       last60MinutesThpt[i].secondHostRcvdIdx] != NULL)) {
	  if(snprintf(buf, sizeof(buf), "<TR>%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(device[actualReportDeviceId].
				   hash_hostTraffic[device[actualReportDeviceId].
						   last60MinutesThpt[i].secondHostRcvdIdx],
				   LONG_FORMAT, 0, 0),
		      formatThroughput(device[actualReportDeviceId].
				       last60MinutesThpt[i].secondRcvdTraffic)) < 0) 
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	     sendString(buf);
	}

	if((device[actualReportDeviceId].last60MinutesThpt[i].thirdHostRcvdIdx != NO_PEER)
	   && (device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
							    last60MinutesThpt[i].thirdHostRcvdIdx] != NULL)) {
	  if(snprintf(buf, sizeof(buf), "<TR>%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(device[actualReportDeviceId].
				   hash_hostTraffic[device[actualReportDeviceId].
						   last60MinutesThpt[i].thirdHostRcvdIdx],
				   LONG_FORMAT, 0, 0),
		      formatThroughput(device[actualReportDeviceId].
				       last60MinutesThpt[i].thirdRcvdTraffic)) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}
      } else
	sendString("&nbsp;");

      sendString("</TABLE></TD></TR>\n");
    }
    break;
  case 2:
  default:
    if(device[actualReportDeviceId].numThptSamples < 60) {
      printNoDataYet();
      return;
    } else {
      sendString("<CENTER>\n");
      sendString(""TABLE_ON"<TABLE BORDER=1>\n<TR>"
		 "<TH "TH_BG">Sampling Period</TH>"
		 "<TH "TH_BG">Average Thpt</TH>"
		 "<TH "TH_BG">Top Thpt Sent Hosts</TH>"
		 "<TH "TH_BG">Top Rcvd Sent Hosts</TH>"
		 "</TR>\n");

      for(i=0; i<24; i++) {
	if(device[actualReportDeviceId].last24HoursThpt[i].trafficValue == 0)
	  break;

	tmpTime = actTime-(i*60*60);
	strftime(label, 32, "%H:%M", localtime_r(&tmpTime, &t));
	tmpTime = actTime-((i+1)*60*60);
	strftime(label1, 32, "%H:%M", localtime_r(&tmpTime, &t));
	if(snprintf(buf, sizeof(buf), "<TR %s><TD "TD_BG" ALIGN=CENTER><B>%s&nbsp;-&nbsp;%s</B></TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=LEFT>"TABLE_ON"<TABLE BORDER=1>",
		    getRowColor(), label, label1,
		    formatThroughput(device[actualReportDeviceId].last24HoursThpt[i].trafficValue)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	
	 if((device[actualReportDeviceId].last24HoursThpt[i].topHostRcvdIdx != NO_PEER)
	    && (device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
							     last24HoursThpt[i].topHostSentIdx] != NULL)) {
	  if(snprintf(buf, sizeof(buf), "<TR>%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		      makeHostLink(device[actualReportDeviceId].
				   hash_hostTraffic[device[actualReportDeviceId].
						   last24HoursThpt[i].topHostSentIdx],
				   LONG_FORMAT, 0, 0),
		      formatThroughput(device[actualReportDeviceId].
				       last24HoursThpt[i].topSentTraffic)) < 0) 
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);

	  if((device[actualReportDeviceId].last24HoursThpt[i].secondHostRcvdIdx != NO_PEER)
	     && (device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
							      last24HoursThpt[i].secondHostSentIdx] != NULL)) {
	    if(snprintf(buf, sizeof(buf), "<TR>%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		    makeHostLink(device[actualReportDeviceId].
				 hash_hostTraffic[device[actualReportDeviceId].
						 last24HoursThpt[i].secondHostSentIdx],
				 LONG_FORMAT, 0, 0),
		    formatThroughput(device[actualReportDeviceId].
				     last24HoursThpt[i].secondSentTraffic)) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);
	  }
	  
	  if((device[actualReportDeviceId].last24HoursThpt[i].thirdHostRcvdIdx != NO_PEER)
	     && (device[actualReportDeviceId].
		 hash_hostTraffic[device[actualReportDeviceId].last24HoursThpt[i].thirdHostSentIdx] != NULL)) {
	    if(snprintf(buf, sizeof(buf), "<TR>%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		    makeHostLink(device[actualReportDeviceId].
				 hash_hostTraffic[device[actualReportDeviceId].
						 last24HoursThpt[i].thirdHostSentIdx],
				 LONG_FORMAT, 0, 0),
		    formatThroughput(device[actualReportDeviceId].
				     last24HoursThpt[i].thirdSentTraffic)) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);
	  }
	} else
	  sendString("&nbsp;");	

	sendString("</TABLE>"TABLE_OFF"</TD><TD "TD_BG" ALIGN=LEFT>"TABLE_ON"<TABLE BORDER=1>\n");

	/* *************************************** */

	if((device[actualReportDeviceId].last24HoursThpt[i].topHostRcvdIdx != NO_PEER)
	    && (device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
							last24HoursThpt[i].topHostRcvdIdx] != NULL)) {
	  if(snprintf(buf, sizeof(buf), "<TR>%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		  makeHostLink(device[actualReportDeviceId].
			       hash_hostTraffic[device[actualReportDeviceId].
					       last24HoursThpt[i].topHostRcvdIdx],
			       LONG_FORMAT, 0, 0),
		  formatThroughput(device[actualReportDeviceId].
				   last24HoursThpt[i].topRcvdTraffic)) < 0) 
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);

	  if((device[actualReportDeviceId].last24HoursThpt[i].secondHostRcvdIdx != NO_PEER)
	     && (device[actualReportDeviceId].
		 hash_hostTraffic[device[actualReportDeviceId].
				 last24HoursThpt[i].secondHostRcvdIdx] != NULL)) {
	    if(snprintf(buf, sizeof(buf), "<TR>%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		    makeHostLink(device[actualReportDeviceId].
				 hash_hostTraffic[device[actualReportDeviceId].
						 last24HoursThpt[i].secondHostRcvdIdx],
				 LONG_FORMAT, 0, 0),
		    formatThroughput(device[actualReportDeviceId].
				     last24HoursThpt[i].secondRcvdTraffic)) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);
	  }

	  if((device[actualReportDeviceId].last24HoursThpt[i].thirdHostRcvdIdx != NO_PEER)
	     && (device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
							      last24HoursThpt[i].thirdHostRcvdIdx] != NULL)) {
	    if(snprintf(buf, sizeof(buf), "<TR>%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
		    makeHostLink(device[actualReportDeviceId].
				 hash_hostTraffic[device[actualReportDeviceId].
						 last24HoursThpt[i].thirdHostRcvdIdx],
				 LONG_FORMAT, 0, 0),
		    formatThroughput(device[actualReportDeviceId].
				     last24HoursThpt[i].thirdRcvdTraffic)) < 0) 
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    sendString(buf);
	  }
	} else
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

  if(device[actualReportDeviceId].numThptSamples == 0) {
    printNoDataYet();
    return;
  }

  sendString("<CENTER>\n");

#ifdef HAVE_GDCHART
   sendString("<A HREF=\"thptStatsMatrix.html?1\" BORDER=0>"
	      "<IMG SRC=\"thptGraph"CHART_FORMAT"?1\"></A><BR>\n");
   if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4>",
	   formatTimeStamp(0, 0, 0),
	   formatTimeStamp(0, 0, 60)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
#else
   sendString("<A HREF=\"thptStatsMatrix.html?1\" BORDER=0>");
   if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4></A><BR>",
	   formatTimeStamp(0, 0, 0),
	   formatTimeStamp(0, 0, 60)) < 0) 
     traceEvent(TRACE_ERROR, "Buffer overflow!");
#endif

   sendString(tmpBuf);

  if(device[actualReportDeviceId].numThptSamples > 60) {
#ifdef HAVE_GDCHART
    sendString("<P><A HREF=\"thptStatsMatrix.html?2\" BORDER=0>"
	       "<IMG SRC=\"thptGraph"CHART_FORMAT"?2\"></A><BR>\n");
    if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4>",
	    formatTimeStamp(0, 0, 0),
	    formatTimeStamp(0, 24, 0)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
#else
    sendString("<P><A HREF=\"thptStatsMatrix.html?2\" BORDER=0>");
    if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4></A><BR>",
	    formatTimeStamp(0, 0, 0),
	    formatTimeStamp(0, 24, 0)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
#endif

    sendString(tmpBuf);

#ifdef HAVE_GDCHART
    if(device[actualReportDeviceId].numThptSamples > 1440 /* 60 * 24 */) {
      sendString("<P><IMG SRC=\"thptGraph"CHART_FORMAT"?3\"><BR>\n");
      if(snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4>",
	      formatTimeStamp(0, 0, 0),
	      formatTimeStamp(30, 0, 0)) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
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
  TrafficCounter a_, b_;
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

  switch(columnSort) {
  case 1:
    rc = strcasecmp(a->domainHost->dotDomainName, b->domainHost->dotDomainName);
    if(rc == 0)
      return(strcasecmp(a->domainHost->fullDomainName, b->domainHost->fullDomainName));
    else
      return rc;
  case 2: a_  = a->bytesSent, b_ = b->bytesSent; break;
  case 3: a_  = a->bytesRcvd, b_ = b->bytesRcvd; break;
  case 4: a_  = a->tcpSent  , b_ = b->tcpSent;   break;
  case 5: a_  = a->tcpRcvd  , b_ = b->tcpRcvd;   break;
  case 6: a_  = a->udpSent  , b_ = b->udpSent;   break;
  case 7: a_  = a->udpRcvd  , b_ = b->udpRcvd;   break;
  case 8: a_  = a->icmpSent , b_ = b->icmpSent;  break;
  case 9: a_  = a->icmpRcvd , b_ = b->icmpRcvd;  break;
  case 10: a_ = a->ospfSent , b_ = b->ospfSent;  break;
  case 11: a_ = a->ospfRcvd , b_ = b->ospfRcvd;  break;
  case 12: a_ = a->igmpSent , b_ = b->igmpSent;  break;
  case 13: a_ = a->igmpRcvd , b_ = b->igmpRcvd;  break;
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
      accessMutex(&addressResolutionMutex, "fillDomainName");
#endif
      rc = strcasecmp(a->domainHost->hostSymIpAddress, b->domainHost->hostSymIpAddress);
#ifdef MULTITHREADED
      releaseMutex(&addressResolutionMutex);
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

/* if domainName == NULL -> print all domains */
void printDomainStats(char* domainName, int sortedColumn, int revertOrder) {
  u_int idx, tmpIdx, numEntries=0, len;
  u_short keyValue=0;
  HostTraffic *el;
  char buf[BUF_SIZE];
  DomainStats **stats, *tmpStats, *statsEntry;
  char htmlAnchor[128], htmlAnchor1[128], *sign, *arrowGif, *arrow[48], *theAnchor[48];
  TrafficCounter totBytesSent=0, totBytesRcvd=0;

  len = sizeof(DomainStats)*device[actualReportDeviceId].actualHashSize;
  tmpStats = (DomainStats*)malloc(len);
  memset(tmpStats, 0, len);

  /* Fix below courtesy of Francis Pintos <francis@arhl.com.hk> */
  len = sizeof(DomainStats**)*device[actualReportDeviceId].actualHashSize;
  stats = (DomainStats**)malloc(len);
  memset(stats, 0, len);

  /* traceEvent(TRACE_INFO, "'%s' '%d' '%d'\n", domainName, sortedColumn, revertOrder); */

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG SRC=arrow_down.gif BORDER=0>";
  }

  if(domainName == NULL)
    domainSort = 1;
  else
    domainSort = 0;

  for(idx=1; idx<device[actualReportDeviceId].actualHashSize; idx++) {
    if((el = device[actualReportDeviceId].hash_hostTraffic[idx]) == NULL)
      continue;
    else
      fillDomainName(el);

    if((el->fullDomainName == NULL)
       || (el->fullDomainName[0] == '\0')
       || (el->dotDomainName == NULL)
       || (el->dotDomainName == '\0'))
      continue;
    else if((domainName != NULL)
	    && (strcmp(el->fullDomainName, domainName) != 0))
      continue;

    if(domainName == NULL) {
      for(keyValue=0, tmpIdx=0; el->fullDomainName[tmpIdx] != '\0'; tmpIdx++)
	keyValue += (tmpIdx+1)*(u_short)el->fullDomainName[tmpIdx];

      keyValue %= device[actualReportDeviceId].actualHashSize;

      while((stats[keyValue] != NULL)
	    && (strcasecmp(stats[keyValue]->domainHost->fullDomainName, el->fullDomainName) != 0))
	keyValue = (keyValue+1) % device[actualReportDeviceId].actualHashSize;

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

    totBytesSent          += el->bytesSent;
    statsEntry->bytesSent += el->bytesSent;
    statsEntry->bytesRcvd += el->bytesReceived;
    totBytesRcvd          += el->bytesReceived;
    statsEntry->tcpSent   += el->tcpSentLocally + el->tcpSentRemotely;
    statsEntry->udpSent   += el->udpSentLocally + el->udpSentRemotely;
    statsEntry->icmpSent  += el->icmpSent;
    statsEntry->ospfSent  += el->ospfSent;
    statsEntry->igmpSent  += el->igmpSent;
    statsEntry->tcpRcvd   += el->tcpReceivedLocally + el->tcpReceivedFromRemote;
    statsEntry->udpRcvd   += el->udpReceivedLocally + el->udpReceivedFromRemote;
    statsEntry->icmpRcvd  += el->icmpReceived;
    statsEntry->ospfRcvd  += el->ospfReceived;
    statsEntry->igmpRcvd  += el->igmpReceived;
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

  columnSort = sortedColumn;

  quicksort(tmpStats, numEntries, sizeof(DomainStats), cmpStatsFctn);

  /* avoid division by zero */
  if(totBytesSent == 0)
    totBytesSent = 1;
  if(totBytesRcvd == 0)
    totBytesRcvd = 1;

  if(domainName == NULL) {
    if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", STR_DOMAIN_STATS, sign) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", STR_DOMAIN_STATS) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
 } else {
   if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s_%s.html?%s", 
	       DOMAIN_INFO_HTML, domainName, sign) < 0) 
     traceEvent(TRACE_ERROR, "Buffer overflow!");
   if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s_%s.html?", 
	       DOMAIN_INFO_HTML, domainName) < 0)
     traceEvent(TRACE_ERROR, "Buffer overflow!");
 }

  if(abs(columnSort) == 0) {
    arrow[0] = arrowGif;
    theAnchor[0] = htmlAnchor;
  } else {
    arrow[0] = "";
    theAnchor[0] = htmlAnchor1;
  }

  if(abs(columnSort) == 1) {
    arrow[1] = arrowGif;
    theAnchor[1] = htmlAnchor;
  } else {
    arrow[1] = "";
    theAnchor[1] = htmlAnchor1;
  }

  if(abs(columnSort) == 2) {
    arrow[2] = arrowGif;
    theAnchor[2] = htmlAnchor;
  } else {
    arrow[2] = "";
    theAnchor[2] = htmlAnchor1;
  }

  if(abs(columnSort) == 3) {
    arrow[3] = arrowGif;
    theAnchor[3] = htmlAnchor;
  } else {
    arrow[3] = "";
    theAnchor[3] = htmlAnchor1;
  }

  if(abs(columnSort) == 4) {
    arrow[4] = arrowGif;
    theAnchor[4] = htmlAnchor;
  } else {
    arrow[4] = "";
    theAnchor[4] = htmlAnchor1;
  }

  if(abs(columnSort) == 5) {
    arrow[5] = arrowGif;
    theAnchor[5] = htmlAnchor;
  } else {
    arrow[5] = "";
    theAnchor[5] = htmlAnchor1;
  }

  if(abs(columnSort) == 6) {
    arrow[6] = arrowGif;
    theAnchor[6] = htmlAnchor;
  } else {
    arrow[6] = "";
    theAnchor[6] = htmlAnchor1;
  }

  if(abs(columnSort) == 7) {
    arrow[7] = arrowGif;
    theAnchor[7] = htmlAnchor;
  } else {
    arrow[7] = "";
    theAnchor[7] = htmlAnchor1;
  }

  if(abs(columnSort) == 8) {
    arrow[8] = arrowGif;
    theAnchor[8] = htmlAnchor;
  } else {
    arrow[8] = "";
    theAnchor[8] = htmlAnchor1;
  }

  if(abs(columnSort) == 9) {
    arrow[9] = arrowGif;
    theAnchor[9] = htmlAnchor;
  } else {
    arrow[9] = "";
    theAnchor[9] = htmlAnchor1;
  }

  if(abs(columnSort) == 10) {
    arrow[10] = arrowGif;
    theAnchor[10] = htmlAnchor;
  } else {
    arrow[10] = "";
    theAnchor[10] = htmlAnchor1;
  }

  if(abs(columnSort) == 11) {
    arrow[11] = arrowGif;
    theAnchor[11] = htmlAnchor;
  } else {
    arrow[11] = "";
    theAnchor[11] = htmlAnchor1;
  }

  if(abs(columnSort) == 12) {
    arrow[12] = arrowGif;
    theAnchor[12] = htmlAnchor;
  } else {
    arrow[12] = "";
    theAnchor[12] = htmlAnchor1;
  }

  if(abs(columnSort) == 13) {
    arrow[13] = arrowGif;
    theAnchor[13] = htmlAnchor;
  } else {
    arrow[13] = "";
    theAnchor[13] = htmlAnchor1;
  }

  if(abs(columnSort) == 14) {
    arrow[14] = arrowGif;
    theAnchor[14] = htmlAnchor;
  } else {
    arrow[14] = "";
    theAnchor[14] = htmlAnchor1;
  }

  /* Split below courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */
  sendString("<CENTER>\n");
  if(snprintf(buf, sizeof(buf),
          ""TABLE_ON"<TABLE BORDER=1><TR>"
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
    traceEvent(TRACE_ERROR, "Buffer overflow!");
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
    traceEvent(TRACE_ERROR, "Buffer overflow!");
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
    traceEvent(TRACE_ERROR, "Buffer overflow!");

  sendString(buf);

  for(idx=0; idx<numEntries; idx++) {
    if(revertOrder)
      statsEntry = &tmpStats[numEntries-idx-1];
    else
      statsEntry = &tmpStats[idx];

    if(domainName == NULL) {
      if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s_%s.html>%s</A>",
	      DOMAIN_INFO_HTML, statsEntry->domainHost->fullDomainName,
	      statsEntry->domainHost->fullDomainName) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    } else {
      char tmpBuf[64];
      int blankId;

#ifdef MULTITHREADED
      accessMutex(&addressResolutionMutex, "getHostIcon");
#endif

      blankId = strlen(statsEntry->domainHost->hostSymIpAddress)-
	strlen(statsEntry->domainHost->fullDomainName)-1;

      strncpy(tmpBuf, statsEntry->domainHost->hostSymIpAddress, sizeof(tmpBuf));

#ifdef MULTITHREADED
      releaseMutex(&addressResolutionMutex);
#endif

      if((blankId > 0)
	 && (strcmp(&tmpBuf[blankId+1], domainName) == 0))
	tmpBuf[blankId] = '\0';

      if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s.html>%s</A>",
		  statsEntry->domainHost->hostNumIpAddress, tmpBuf) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    }

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=CENTER>%s</TD>"
	    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%%</TD>"
	    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%%</TD>"
	    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
	    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
	    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
	    "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
	    getRowColor(), htmlAnchor,
	    getHostCountryIconURL(statsEntry->domainHost),
	    formatBytes(statsEntry->bytesSent, 1),
	    (100*((float)statsEntry->bytesSent/(float)totBytesSent)),
	    formatBytes(statsEntry->bytesRcvd, 1),
	    (100*((float)statsEntry->bytesRcvd/(float)totBytesRcvd)),
	    formatBytes(statsEntry->tcpSent, 1),
	    formatBytes(statsEntry->tcpRcvd, 1),
	    formatBytes(statsEntry->udpSent, 1),
	    formatBytes(statsEntry->udpRcvd, 1),
	    formatBytes(statsEntry->icmpSent, 1),
	    formatBytes(statsEntry->icmpRcvd, 1),
	    formatBytes(statsEntry->ospfSent, 1),
	    formatBytes(statsEntry->ospfRcvd, 1),
	    formatBytes(statsEntry->igmpSent, 1),
	    formatBytes(statsEntry->igmpRcvd, 1)
	    ) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }

  sendString("</TABLE>"TABLE_OFF"</HTML>\n");
  sendString("</CENTER>\n");
  free(tmpStats); free(stats);
}

/* ************************* */

void printNoDataYet(void) {
  printFlagedWarning("<I>No Data To Display (yet)</I>");
}

/* ************************* */

void listNetFlows(void) {
  char buf[BUF_SIZE];
  int numEntries=0;
  FlowFilterList *list = flowsList;

  printHTMLheader(NULL, 0);

  if(list != NULL) {
    while(list != NULL) {
      if(list->pluginStatus.activePlugin) {
	if(numEntries == 0) {
	  printSectionTitle("Network Flows");
 	  sendString("<CENTER>\n");
	  sendString(""TABLE_ON"<TABLE BORDER=1><TR><TH "TH_BG">Flow Name</TH>"
  		     "<TH "TH_BG">Packets</TH><TH "TH_BG">Traffic</TH></TR>");
  	}

	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s"
		"</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		getRowColor(), list->flowName,
		formatPkts(list->packets),
		formatBytes(list->bytes, 1)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
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
    sendString("<CENTER><P><H1>No available/active Network Flows</H1><p>"
	       " (see <A HREF=ntop.html>man</A> page)</CENTER>\n");
  }
}

/* ****************************************** */

void printHostEvents(HostTraffic *theHost, int column, int revertOrder) {
  datum key_data, data_data, return_data;
  char tmpBuf[96], *arrow[6], *theAnchor[6];
  EventMsg *theMsgTable[MAX_NUM_EVENTS];
  EventMsg theMsgs[MAX_NUM_EVENTS];
  unsigned long shost, dhost, evtTime;
  u_short numEntries = 0, i;
  char buf[BUF_SIZE], *arrowGif, *sign;
  char htmlAnchor[64], htmlAnchor1[64];

  if(theHost == NULL) printHTMLheader(NULL, 0);

  if(eventFile == NULL) {
    if(theHost == NULL) printNoDataYet();
    return; /* No rules are currently active */
  }

  memset(theMsgTable, 0, sizeof(theMsgTable));

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "printHostEvent");
#endif
  return_data = gdbm_firstkey (eventFile);
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif

  while (return_data.dptr != NULL) {
    key_data = return_data;
#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "printHostEvents-2");
#endif
    return_data = gdbm_nextkey(eventFile, key_data);
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif

    strncpy(tmpBuf, key_data.dptr, key_data.dsize);
    tmpBuf[key_data.dsize] = 0;

    sscanf(tmpBuf, "%lu %lu %lu", &shost, &dhost, &evtTime);

    if((theHost == NULL) /* All the events */
       || (theHost->hostIpAddress.s_addr == shost)
       || (theHost->hostIpAddress.s_addr == dhost)) {
#ifdef MULTITHREADED
      accessMutex(&gdbmMutex, "printHostEvents-3");
#endif
      data_data = gdbm_fetch(eventFile, key_data);
#ifdef MULTITHREADED
      releaseMutex(&gdbmMutex);
#endif

      if(data_data.dptr != NULL) {
	if(numEntries < MAX_NUM_EVENTS) {
	  memcpy(&theMsgs[numEntries], data_data.dptr, sizeof(EventMsg));
	  theMsgTable[numEntries] = &(theMsgs[numEntries]);
	  numEntries++;
	}

	if(data_data.dptr != NULL)
	  free(data_data.dptr);
      }
    }

    free(key_data.dptr);
  } /* while */

  if(numEntries == 0) {
    if(theHost == NULL)  {
      /* All the events */
      printNoDataYet();
    }

    return;
  }

  if(theHost != NULL) {
    columnSort = 0;
    sign = "";
    arrowGif = "";
    strncpy(htmlAnchor, "<!", sizeof(htmlAnchor));
    strncpy(htmlAnchor1, "<!", sizeof(htmlAnchor1));
  } else {
    columnSort = column;

    if(revertOrder) {
      sign = "";
      arrowGif = "&nbsp;<IMG SRC=arrow_up.gif BORDER=0>";
    } else {
      sign = "-";
      arrowGif = "&nbsp;<IMG SRC=arrow_down.gif BORDER=0>";
    }

    if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", NW_EVENTS_HTML, sign)  < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", NW_EVENTS_HTML) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  }

  if(abs(column) == 0) {
    arrow[0] = arrowGif; theAnchor[0] = htmlAnchor;
  } else {
    arrow[0] = ""; theAnchor[0] = htmlAnchor1;
  }

  if(abs(column) == 1) {
    arrow[1] = arrowGif; theAnchor[1] = htmlAnchor;
  } else {
    arrow[1] = ""; theAnchor[1] = htmlAnchor1;
  }

  if(abs(column) == 2) {
    arrow[2] = arrowGif; theAnchor[2] = htmlAnchor;
  } else {
    arrow[2] = ""; theAnchor[2] = htmlAnchor1;
  }

  quicksort(theMsgTable, numEntries, sizeof(EventMsg*), cmpEventsFctn);

  if(theHost == NULL) sendString("<CENTER>\n");

  sendString("<P><H1>Network Events</H1>\n");
  sendString(""TABLE_ON"<TABLE BORDER=1>\n<TR>\n");
  if(snprintf(buf, sizeof(buf), "<TH "TH_BG">%s0>Time%s</A></TH><TH "TH_BG">%s1>Severity%s</A></TH>"
	  "<TH "TH_BG">%s2>Matched Rule%s</A></TH><TH "TH_BG">Message</TH></TR>\n",
	  theAnchor[0], arrow[0], theAnchor[1], arrow[1],
	  theAnchor[2], arrow[2]) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  for(i=0; i<numEntries; i++) {
    char *elem, *strtokState;

    if(i > MAX_NUM_EVENTS_TO_DISPLAY)
      break;

    if(revertOrder)
      elem = strtok_r(theMsgTable[numEntries-i-1]->message, " ", &strtokState);
    else
      elem = strtok_r(theMsgTable[i]->message, " ", &strtokState);

    if(snprintf(tmpBuf, sizeof(tmpBuf), "<TR %s><TD "TD_BG">", getRowColor()) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(tmpBuf);
    sendString(elem); /* 2000-03-07 */
    sendString(" ");
    elem = strtok_r(NULL, " ", &strtokState);
    sendString(elem);  /* 12:12:53 */

    sendString("</TD><TD "TD_BG" ALIGN=CENTER>");
    elem = strtok_r(NULL, " ", &strtokState);

    if(strcmp(elem, "ALARM") == 0) {
      sendString("<FONT COLOR=#FF0000>");
      sendString(elem); /* ALARM */
      sendString("</FONT>");
    } else
      sendString(elem); /* INFO,.... */

    sendString("</TD><TD "TD_BG" ALIGN=CENTER>");
    elem = strtok_r(NULL, " ", &strtokState);
    sendString(elem);  /* stealth-scan */

    sendString("</TD><TD "TD_BG" NOWRAP>");
    sendString(&elem[strlen(elem)+1]);

    sendString("</TD></TR>\n");
  }

  sendString("</TABLE>"TABLE_OFF"\n");

  if(theHost == NULL) sendString("</CENTER>\n");
}


/* *********************************** */

void printHostHourlyTraffic(HostTraffic *el) {
  TrafficCounter tcSent, tcRcvd;
  int i, hourId;
  char theDate[8];
  struct tm t;

  strftime(theDate, 8, "%H", localtime_r(&actTime, &t));  
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
    tcSent += el->last24HoursBytesSent[i];
    tcRcvd += el->last24HoursBytesRcvd[i];  
  }

  sendString("<TR><TH "TH_BG" ALIGN=LEFT>Midnight - 1AM</TH>");
  printHostHourlyTrafficEntry(el, 0, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>1AM - 2AM</TH>");
  printHostHourlyTrafficEntry(el, 1, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>2AM - 3AM</TH>");
  printHostHourlyTrafficEntry(el, 2, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>3AM - 4AM</TH>");
  printHostHourlyTrafficEntry(el, 3, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>4AM - 5AM</TH>");
  printHostHourlyTrafficEntry(el, 4, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>5AM - 6AM</TH>");
  printHostHourlyTrafficEntry(el, 5, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>6AM - 7AM</TH>");
  printHostHourlyTrafficEntry(el, 6, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>7AM - 8AM</TH>");
  printHostHourlyTrafficEntry(el, 7, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>8AM - 9AM</TH>");
  printHostHourlyTrafficEntry(el, 8, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>9AM - 10AM</TH>");
  printHostHourlyTrafficEntry(el, 9, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>10AM - 11AM</TH>");
  printHostHourlyTrafficEntry(el, 10, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>11AM - Noon</TH>");
  printHostHourlyTrafficEntry(el, 11, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>Noon - 1PM</TH>");
  printHostHourlyTrafficEntry(el, 12, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>1PM - 2PM</TH>");
  printHostHourlyTrafficEntry(el, 13, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>2PM - 3PM</TH>");
  printHostHourlyTrafficEntry(el, 14, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>3PM - 4PM</TH>");
  printHostHourlyTrafficEntry(el, 15, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>4PM - 5PM</TH>");
  printHostHourlyTrafficEntry(el, 16, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>5PM - 6PM</TH>");
  printHostHourlyTrafficEntry(el, 17, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>6PM - 7PM</TH>");
  printHostHourlyTrafficEntry(el, 18, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>7PM - 8PM</TH>");
  printHostHourlyTrafficEntry(el, 19, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>8PM - 9PM</TH>");
  printHostHourlyTrafficEntry(el, 20, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>9PM - 10PM</TH>");
  printHostHourlyTrafficEntry(el, 21, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>10PM - 11PM</TH>");
  printHostHourlyTrafficEntry(el, 22, tcSent, tcRcvd);
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>11PM - Midnight</TH>");
  printHostHourlyTrafficEntry(el, 23, tcSent, tcRcvd);

  sendString("</TABLE>"TABLE_OFF"\n");
  sendString("</CENTER>\n");
}

#endif /* MICRO_NTOP */
