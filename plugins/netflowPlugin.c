/*
 *  Copyright (C) 2002 Luca Deri <deri@ntop.org>
 *
 *  		       http://www.ntop.org/
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

#ifdef CFG_MULTITHREADED
static pthread_t netFlowThread;
static int threadActive;
#endif

/* #define DEBUG_FLOWS  */

static ProbeInfo probeList[MAX_NUM_PROBES];

/* Forward */
static void setNetFlowInSocket();
static void setNetFlowOutSocket();

/* ****************************** */

static void setNetFlowInSocket() {
  struct sockaddr_in sockIn;
  int sockopt = 1;

  if(myGlobals.netFlowInSocket > 0) {
    traceEvent(CONST_TRACE_INFO, "NetFlow collector terminated");
    closeNwSocket(&myGlobals.netFlowInSocket);
  }

  if(myGlobals.netFlowInPort > 0) {
    myGlobals.netFlowInSocket = socket(AF_INET, SOCK_DGRAM, 0);

    setsockopt(myGlobals.netFlowInSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    sockIn.sin_family            = AF_INET;
    sockIn.sin_port              = (int)htons(myGlobals.netFlowInPort);
    sockIn.sin_addr.s_addr       = INADDR_ANY;

    if(bind(myGlobals.netFlowInSocket, (struct sockaddr *)&sockIn, sizeof(sockIn)) < 0) {
      traceEvent(CONST_TRACE_WARNING, "NetFlow collector: port %d already in use.",
		 myGlobals.netFlowInPort);
      closeNwSocket(&myGlobals.netFlowInSocket);
      myGlobals.netFlowInSocket = 0;
      return;
    }

    traceEvent(CONST_TRACE_WARNING, "NetFlow collector listening on port %d.",
	       myGlobals.netFlowInPort);
  }

  if((myGlobals.netFlowInPort > 0) && (myGlobals.netFlowDeviceId == 0))
    myGlobals.netFlowDeviceId = createDummyInterface("NetFlow-device");

  myGlobals.mergeInterfaces = 0; /* Use different devices */
}

/* *************************** */

static void setNetFlowOutSocket() {
  if(myGlobals.netFlowOutSocket <= 0) {
    char value[256];
    int sockopt = 1;

    myGlobals.netFlowOutSocket = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(myGlobals.netFlowOutSocket, SOL_SOCKET, SO_REUSEADDR,
	       (char *)&sockopt, sizeof(sockopt));

    myGlobals.netFlowDest.sin_addr.s_addr = 0;
    myGlobals.netFlowDest.sin_family      = AF_INET;
    myGlobals.netFlowDest.sin_port        = (int)htons(atoi(DEFAULT_NETFLOW_PORT_STR));

    if(fetchPrefsValue("netFlow.netFlowDest", value, sizeof(value)) == -1)
      storePrefsValue("netFlow.netFlowDest", "");
    else if(value[0] != '\0') {
      myGlobals.netFlowDest.sin_addr.s_addr = inet_addr(value);
      if(myGlobals.netFlowDest.sin_addr.s_addr > 0)
	traceEvent(CONST_TRACE_INFO, "Exporting NetFlow's towards %s:%s", value, DEFAULT_NETFLOW_PORT_STR);
      else
	traceEvent(CONST_TRACE_INFO, "NetFlow export disabled");
    }
  }
}

/* ****************************** */

static void dissectFlow(char *buffer, int bufferLen) {
  NetFlow5Record the5Record;
  NetFlow7Record the7Record;

  memcpy(&the5Record, buffer, bufferLen > sizeof(the5Record) ? sizeof(the5Record): bufferLen);
  memcpy(&the7Record, buffer, bufferLen > sizeof(the7Record) ? sizeof(the7Record): bufferLen);
  
  /*
    Convert V7 flows into V5 flows in order to make ntop
    able to handle V7 flows.

    Courtesy of Bernd Ziller <bziller@ba-stuttgart.de>
  */
  if(the7Record.flowHeader.version == htons(7)) {
    int numFlows = ntohs(the7Record.flowHeader.count);
    int i, j;
    
    if(numFlows > CONST_V7FLOWS_PER_PAK) numFlows = CONST_V7FLOWS_PER_PAK;
    
    the5Record.flowHeader.version = htons(5);
    the5Record.flowHeader.count = htons(numFlows);
    /* rest of flowHeader will not be used */
    
    for(j=i=0; i<numFlows; i++) {
      the5Record.flowRecord[i].srcaddr = the7Record.flowRecord[i].srcaddr;
      the5Record.flowRecord[i].dstaddr = the7Record.flowRecord[i].dstaddr;
      the5Record.flowRecord[i].srcport = the7Record.flowRecord[i].srcport;
      the5Record.flowRecord[i].dstport = the7Record.flowRecord[i].dstport;
      the5Record.flowRecord[i].dPkts   = the7Record.flowRecord[i].dPkts;
      the5Record.flowRecord[i].dOctets = the7Record.flowRecord[i].dOctets;
      the5Record.flowRecord[i].prot    = the7Record.flowRecord[i].prot;
      /* rest of flowRecord will not be used */
    }
  }
  
  if(the5Record.flowHeader.version == htons(5)) {
    int i, numFlows = ntohs(the5Record.flowHeader.count);

    if(numFlows > CONST_V5FLOWS_PER_PAK) numFlows = CONST_V5FLOWS_PER_PAK;

#ifdef DEBUG_FLOWS
    /* traceEvent(CONST_TRACE_INFO, "dissectFlow(%d flows)", numFlows); */
#endif

    for(i=0; i<numFlows; i++) {
      int actualDeviceId;
	  Counter len;
      char theFlags[256];
      u_int16_t srcAS, dstAS;
      struct in_addr a, b;
      u_int srcHostIdx, dstHostIdx, numPkts;
      HostTraffic *srcHost=NULL, *dstHost=NULL;
      u_short sport, dport;
      TrafficCounter ctr;

      myGlobals.numNetFlowsRcvd++;

      numPkts  = ntohl(the5Record.flowRecord[i].dPkts);
      len      = (Counter)ntohl(the5Record.flowRecord[i].dOctets);

      if((numPkts == 0) || (len == 0) /* Bad flow (zero lenght) */
	 || (numPkts > len))          /* Bad flow (more packets than bytes) */
	 continue;

      a.s_addr = ntohl(the5Record.flowRecord[i].srcaddr);
      b.s_addr = ntohl(the5Record.flowRecord[i].dstaddr);
      sport    = ntohs(the5Record.flowRecord[i].srcport);
      dport    = ntohs(the5Record.flowRecord[i].dstport);

      if(myGlobals.netFlowDebug) {
	theFlags[0] = '\0';

	if(the5Record.flowRecord[i].tcp_flags & TH_SYN)  strcat(theFlags, "SYN ");
	if(the5Record.flowRecord[i].tcp_flags & TH_FIN)  strcat(theFlags, "FIN ");
	if(the5Record.flowRecord[i].tcp_flags & TH_RST)  strcat(theFlags, "RST ");
	if(the5Record.flowRecord[i].tcp_flags & TH_ACK)  strcat(theFlags, "ACK ");
	if(the5Record.flowRecord[i].tcp_flags & TH_PUSH) strcat(theFlags, "PUSH");

#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "%2d) %s:%d <-> %s:%d pkt=%u/len=%u sAS=%d/dAS=%d flags=[%s] (proto=%d)",
		   i+1,
		   _intoa(a, buf, sizeof(buf)), sport,
		   _intoa(b, buf1, sizeof(buf1)), dport,
		   ntohl(the5Record.flowRecord[i].dPkts), len,
		   ntohs(the5Record.flowRecord[i].src_as),
		   ntohs(the5Record.flowRecord[i].dst_as),
		   theFlags, the5Record.flowRecord[i].prot);
#endif
      }

      /* traceEvent(CONST_TRACE_INFO, "a=%u", the5Record.flowRecord[i].srcaddr); */

      actualDeviceId = myGlobals.netFlowDeviceId;

      if(actualDeviceId >= myGlobals.numDevices) {
	traceEvent(CONST_TRACE_ERROR, "NetFlow deviceId (%d) is out range", actualDeviceId);
	break;
      }

      myGlobals.device[actualDeviceId].ethernetPkts.value += numPkts;
      myGlobals.device[actualDeviceId].ipPkts.value       += numPkts;
      updateDevicePacketStats((u_int)len, actualDeviceId);

      myGlobals.device[actualDeviceId].ethernetBytes.value += len;
      myGlobals.device[actualDeviceId].ipBytes.value       += len;

#ifdef CFG_MULTITHREADED
      /* accessMutex(&myGlobals.hostsHashMutex, "processNetFlowPacket"); */
#endif
      dstHostIdx = getHostInfo(&b, NULL, 0, 1, myGlobals.netFlowDeviceId);
      dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
      /* traceEvent(CONST_TRACE_INFO, "dstHostIdx: %d", dstHostIdx); */
      srcHostIdx = getHostInfo(&a, NULL, 0, 1, myGlobals.netFlowDeviceId);
      srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
      /* traceEvent(CONST_TRACE_INFO, "srcHostIdx: %d", srcHostIdx); */

      if((srcHost == NULL) || (dstHost == NULL)) continue;

      srcHost->lastSeen = dstHost->lastSeen = myGlobals.actTime;
      srcHost->pktSent.value     += numPkts, dstHost->pktRcvd.value     += numPkts;
      srcHost->bytesSent.value   += len,     dstHost->bytesRcvd.value   += len;
      srcHost->ipBytesSent.value += len,     dstHost->ipBytesRcvd.value += len;

      srcAS = ntohs(the5Record.flowRecord[i].src_as), dstAS = ntohs(the5Record.flowRecord[i].dst_as);
      if(srcAS != 0) srcHost->hostAS = srcAS;
      if(dstAS != 0) dstHost->hostAS = dstAS;

      if((srcAS != 0) && (dstAS != 0)) {
		allocateElementHash(actualDeviceId, 0 /* AS hash */);
		updateElementHash(myGlobals.device[actualDeviceId].asHash, srcAS, dstAS, numPkts, len);
		}

#ifdef DEBUG_FLOWS
      /* traceEvent(CONST_TRACE_INFO, "%d/%d", srcHost->hostAS, dstHost->hostAS); */
#endif

      if((sport != 0) && (dport != 0)) {
	if(dport < sport) {
	  if(handleIP(dport, srcHost, dstHost, len, 0, 0, actualDeviceId) == -1)
	    handleIP(sport, srcHost, dstHost, len, 0, 0, actualDeviceId);
	} else {
	  if(handleIP(sport, srcHost, dstHost, len, 0, 0, actualDeviceId) == -1)
	    handleIP(dport, srcHost, dstHost, len, 0, 0, actualDeviceId);
	}
      }

      ctr.value = len;
      updatePacketCount(srcHost, dstHost, ctr, actualDeviceId);

      if(subnetPseudoLocalHost(srcHost)) {
	if(subnetPseudoLocalHost(dstHost)) {
	  incrementTrafficCounter(&srcHost->bytesSentLoc, len);
	  incrementTrafficCounter(&dstHost->bytesRcvdLoc, len);
	} else {
	  incrementTrafficCounter(&srcHost->bytesSentRem, len);
	  incrementTrafficCounter(&dstHost->bytesRcvdLoc, len);
	}
      } else {
	/* srcHost is remote */
	if(subnetPseudoLocalHost(dstHost)) {
	  incrementTrafficCounter(&srcHost->bytesSentLoc, len);
	  incrementTrafficCounter(&dstHost->bytesRcvdFromRem, len);
	} else {
	  incrementTrafficCounter(&srcHost->bytesSentRem, len);
	  incrementTrafficCounter(&dstHost->bytesRcvdFromRem, len);
	}
      }

      switch(the5Record.flowRecord[i].prot) {
      case 1: /* ICMP */
	myGlobals.device[actualDeviceId].icmpBytes.value += len;
	srcHost->icmpSent.value += len, dstHost->icmpRcvd.value += len;
	break;
      case 6: /* TCP */
	myGlobals.device[actualDeviceId].tcpBytes.value += len;
	if(subnetPseudoLocalHost(dstHost))
	  srcHost->tcpSentLoc.value += len;
	else
	  srcHost->tcpSentRem.value += len;

	if(subnetPseudoLocalHost(srcHost))
	  dstHost->tcpRcvdLoc.value += len;
	else
	  dstHost->tcpRcvdFromRem.value += len;

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	/*
	  incrementUsageCounter(&srcHost->secHostPkts->establishedTCPConnSent.value, dstHostIdx, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->establishedTCPConnRcvd.value, srcHostIdx, actualDeviceId);
	  incrementUsageCounter(&srcHost->secHostPkts->terminatedTCPConnSent.value, dstHostIdx, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->terminatedTCPConnRcvd.value, srcHostIdx, actualDeviceId);
	*/
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].numEstablishedTCPConnections, 1);
	updateInterfacePorts(actualDeviceId, sport, dport, len);
	updateUsedPorts(srcHost, dstHost, sport, dport, len);

	if(subnetPseudoLocalHost(srcHost)) {
	  if(subnetPseudoLocalHost(dstHost)) {
	    incrementTrafficCounter(&srcHost->tcpSentLoc, len);
	    incrementTrafficCounter(&dstHost->tcpRcvdLoc, len);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.local, len);
	  } else {
	    incrementTrafficCounter(&srcHost->tcpSentRem, len);
	    incrementTrafficCounter(&dstHost->tcpRcvdLoc, len);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.local2remote, len);
	  }
	} else {
	  /* srcHost is remote */
	  if(subnetPseudoLocalHost(dstHost)) {
	    incrementTrafficCounter(&srcHost->tcpSentLoc, len);
	    incrementTrafficCounter(&dstHost->tcpRcvdFromRem, len);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.remote2local, len);
	  } else {
	    incrementTrafficCounter(&srcHost->tcpSentRem, len);
	    incrementTrafficCounter(&dstHost->tcpRcvdFromRem, len);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.remote, len);
	  }
	}
	break;

      case 17: /* UDP */
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpBytes, len);
	updateInterfacePorts(actualDeviceId, sport, dport, len);
	updateUsedPorts(srcHost, dstHost, sport, dport, len);

	if(subnetPseudoLocalHost(dstHost))
	  incrementTrafficCounter(&srcHost->udpSentLoc, len);
	else
	  incrementTrafficCounter(&srcHost->udpSentRem, len);

	if(subnetPseudoLocalHost(srcHost))
	  incrementTrafficCounter(&dstHost->udpRcvdLoc, len);
	else
	  incrementTrafficCounter(&dstHost->udpRcvdFromRem, len);

	if(subnetPseudoLocalHost(srcHost)) {
	  if(subnetPseudoLocalHost(dstHost)) {
	    incrementTrafficCounter(&srcHost->udpSentLoc, len);
	    incrementTrafficCounter(&dstHost->udpRcvdLoc, len);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.local, len);
	  } else {
	    incrementTrafficCounter(&srcHost->udpSentRem, len);
	    incrementTrafficCounter(&dstHost->udpRcvdLoc, len);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.local2remote, len);
	  }
	} else {
	  /* srcHost is remote */
	  if(subnetPseudoLocalHost(dstHost)) {
	    incrementTrafficCounter(&srcHost->udpSentLoc, len);
	    incrementTrafficCounter(&dstHost->udpRcvdFromRem, len);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.remote2local, len);
	  } else {
	    incrementTrafficCounter(&srcHost->udpSentRem, len);
	    incrementTrafficCounter(&dstHost->udpRcvdFromRem, len);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.remote, len);
	  }
	}
	break;
      }

#ifdef CFG_MULTITHREADED
      /* releaseMutex(&myGlobals.hostsHashMutex); */
#endif
    }
  }  else
    myGlobals.numBadFlowsVersionsRcvd++;
}

/* ****************************** */

static void* netflowMainLoop(void* notUsed _UNUSED_) {
  fd_set netflowMask;
  int rc, len;
  u_char buffer[2048];
  struct sockaddr_in fromHost;

  if(!(myGlobals.netFlowInSocket > 0)) return(NULL);
  traceEvent(CONST_TRACE_INFO, "Welcome to NetFlow: listening on UDP port %d...", myGlobals.netFlowInPort);
#ifdef CFG_MULTITHREADED
 traceEvent(CONST_TRACE_INFO, "THREADMGMT: netFlow thread (%ld) started...\n", netFlowThread);
#endif

  for(;myGlobals.capturePackets == FLAG_NTOPSTATE_RUN;) {
    FD_ZERO(&netflowMask);
    FD_SET(myGlobals.netFlowInSocket, &netflowMask);

    if(select(myGlobals.netFlowInSocket+1, &netflowMask, NULL, NULL, NULL) > 0) {
      len = sizeof(fromHost);
      rc = recvfrom(myGlobals.netFlowInSocket, (char*)&buffer, sizeof(buffer),
		    0, (struct sockaddr*)&fromHost, &len);

#ifdef DEBUG_FLOWS
      traceEvent(CONST_TRACE_INFO, "Received NetFlow packet (len=%d) (deviceId=%d)",
		 rc,  myGlobals.netFlowDeviceId);
#endif

      if(rc > 0) {
	int i;

	myGlobals.numNetFlowsPktsRcvd++;

	NTOHL(fromHost.sin_addr.s_addr);

	for(i=0; i<MAX_NUM_PROBES; i++) {
	  if(probeList[i].probeAddr.s_addr == 0) {
	    probeList[i].probeAddr.s_addr = fromHost.sin_addr.s_addr;
	    probeList[i].pkts = 1;
	    break;
	  } else if(probeList[i].probeAddr.s_addr == fromHost.sin_addr.s_addr) {
	    probeList[i].pkts++;
	    break;
	  }
	}

	dissectFlow(buffer, rc);
      }
    } else {
      traceEvent(CONST_TRACE_INFO, "NetFlow thread is terminating...");
      break;
    }
  }

#ifdef CFG_MULTITHREADED
  threadActive = 0;
  traceEvent(CONST_TRACE_INFO, "THREADMGMT: netFlow thread (%ld) terminated...\n", netFlowThread);
#endif
  return(NULL); 
}

/* ****************************** */

static void initNetFlowFunct(void) {
  int i;
  char key[256], value[256];

#ifdef CFG_MULTITHREADED
  threadActive = 0;
#endif

  if(fetchPrefsValue("netFlow.netFlowInPort", value, sizeof(value)) == -1)
    storePrefsValue("netFlow.netFlowInPort", "0");
  else
    myGlobals.netFlowInPort = atoi(value);

  setNetFlowInSocket();

  if(fetchPrefsValue("netFlow.netFlowDest", value, sizeof(value)) == -1)
    storePrefsValue("netFlow.netFlowDest", "0");
  else
    myGlobals.netFlowDest.sin_addr.s_addr = inet_addr(value);

  setNetFlowOutSocket();

  if(fetchPrefsValue("netFlow.debug", value, sizeof(value)) == -1) {
    storePrefsValue("netFlow.debug", "0");
    myGlobals.netFlowDebug = 0;
  } else {
    myGlobals.netFlowDebug = atoi(value);
  }

  for(i=0; i<myGlobals.numDevices; i++)
    if(!myGlobals.device[i].virtualDevice) {
      if(snprintf(key, sizeof(key),
		  "netFlow.%s.exportNetFlow",
		  myGlobals.device[i].name) < 0)
	BufferTooShort();

      if(fetchPrefsValue(key, value, sizeof(value)) == -1) {
	storePrefsValue(key, "No");
      } else {
	/* traceEvent(CONST_TRACE_INFO, "%s=%s", key, value); */

	if(strcmp(value, "Yes") == 0)
	  myGlobals.device[i].exportNetFlow = FLAG_NETFLOW_EXPORT_ENABLED;
	else
	  myGlobals.device[i].exportNetFlow = FLAG_NETFLOW_EXPORT_DISABLED;
      }
    }

#ifdef CFG_MULTITHREADED
  if((myGlobals.netFlowInPort != 0)
     && (!threadActive)) {
    /* This plugin works only with threads */
    createThread(&netFlowThread, netflowMainLoop, NULL);
  }
#endif
}

/* ****************************** */

static void handleNetflowHTTPrequest(char* url) {
  char buf[512];
  int i, numEnabled = 0;
  struct in_addr theDest;

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);
  printHTMLheader("NetFlow Statistics", 0);

  sendString("<CENTER>\n<HR>\n");

  if(url != NULL) {
    char *device, *value = NULL;

    device = strtok(url, "=");
    if(device != NULL) value = strtok(NULL, "=");

    if(value && device) {
      if(strcmp(device, "port") == 0) {
	myGlobals.netFlowInPort = atoi(value);
	storePrefsValue("netFlow.netFlowInPort", value);
	setNetFlowInSocket();
      } else if(strcmp(device, "debug") == 0) {
	myGlobals.netFlowDebug = atoi(value);
	storePrefsValue("netFlow.debug", value);
      } else if(strcmp(device, "collectorIP") == 0) {
	storePrefsValue("netFlow.netFlowDest", value);
	myGlobals.netFlowDest.sin_addr.s_addr = inet_addr(value);

	if(myGlobals.netFlowDest.sin_addr.s_addr > 0)
	  traceEvent(CONST_TRACE_INFO, "Exporting NetFlow's towards %s:%s", value, DEFAULT_NETFLOW_PORT_STR);
	else
	  traceEvent(CONST_TRACE_INFO, "NetFlow export disabled");
      } else {
	for(i=0; i<myGlobals.numDevices; i++)
	  if(!myGlobals.device[i].virtualDevice) {
	    if(strcmp(myGlobals.device[i].name, device) == 0) {
	      if(snprintf(buf, sizeof(buf),
			  "netFlow.%s.exportNetFlow",
			  myGlobals.device[i].name) < 0)
		BufferTooShort();

	      /* traceEvent(CONST_TRACE_INFO, "%s=%s", buf, value); */
	      storePrefsValue(buf, value);

	      if(!strcmp(value, "No")) {
		myGlobals.device[i].exportNetFlow = FLAG_NETFLOW_EXPORT_DISABLED;
	      } else {
		myGlobals.device[i].exportNetFlow = FLAG_NETFLOW_EXPORT_ENABLED;
	      }
	    }
	  }
      }
    }
  }

  sendString("<table border=0>\n<tr><td><table border>");

  sendString("<TR "TR_ON"><TH "TH_BG">Incoming Flows</TH><TD "TD_BG"><FORM ACTION=/plugins/NetFlow METHOD=GET>"
	     "Local Collector UDP Port:</td><td "TD_BG"><INPUT NAME=port SIZE=5 VALUE=");

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.netFlowInPort) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("> <br>[default port is "DEFAULT_NETFLOW_PORT_STR"]</td><td>"
	     "<INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

  /* *************************************** */

  sendString("<TR "TR_ON"><TH "TH_BG">Outgoing Flows</TH><TD "TD_BG"><FORM ACTION=/plugins/NetFlow METHOD=GET>"
	     "Remote Collector IP Address</td> "
	     "<td "TD_BG"><INPUT NAME=collectorIP SIZE=15 VALUE=");

  theDest.s_addr = ntohl(myGlobals.netFlowDest.sin_addr.s_addr);
  sendString(_intoa(theDest, buf, sizeof(buf)));

  sendString(">:2055</td><td><INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

  sendString("<TR "TR_ON"><TH "TH_BG">Debug</TH><TD "TD_BG" align=left COLSPAN=2>"
	     "<FORM ACTION=/plugins/NetFlow METHOD=GET>");
  if(myGlobals.netFlowDebug) {
    sendString("<INPUT TYPE=radio NAME=debug VALUE=1 CHECKED>On");
    sendString("<INPUT TYPE=radio NAME=debug VALUE=0>Off");
    sendString("<br>NOTE: NetFlow packets are dumped on the ntop log");
  } else {
    sendString("<INPUT TYPE=radio NAME=debug VALUE=1>On");
    sendString("<INPUT TYPE=radio NAME=debug VALUE=0 CHECKED>Off");
  }

  sendString("</TD><td><INPUT TYPE=submit VALUE=Set></form></td></TR>\n");
  sendString("</table></tr>\n");

  sendString("<tr><td>"
	     "<b>NOTE</b>:<ol>"
	     "<li>Use 0 as port, and 0.0.0.0 as IP address to disable export/collection"
	     "<li>NetFlow packets are associated with a virtual device and not mixed to captured packets."
	     "<li>NetFlow activation may require ntop restart"
	     "<li>A virtual NetFlow device is activated only when incoming flow capture is enabled."
	     "<li>You can switch devices using this <A HREF=/switch.html>link</A>."
	     "<li>Due to the way ntop works, NetFlow export capabilities are limited. If you need a fast,<br>"
	     " light, memory savvy, highly configurable NetFlow probe, you better give <b><A HREF=http://www.ntop.org/nProbe.html>nProbe</A></b> a try."
	     "</ol></td></tr>\n");
  sendString("</table><p><hr><p>\n");

  /* ************************ */

  sendString("<TABLE BORDER>\n");
  sendString("<TR "TR_ON"><TH "TH_BG">Interface Name</TH><TH "TH_BG">NetFlow Enabled</TH></TR>\n");

  for(i=0; i<myGlobals.numDevices; i++) {
    if(!myGlobals.device[i].virtualDevice) {
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<A HREF=/plugins/NetFlow?%s=%s>%s</A></TD></TR>\n",
		  myGlobals.device[i].name, myGlobals.device[i].name,
		  myGlobals.device[i].exportNetFlow == FLAG_NETFLOW_EXPORT_ENABLED ? "No" : "Yes",
		  myGlobals.device[i].exportNetFlow == FLAG_NETFLOW_EXPORT_ENABLED ? "Yes" : "No") < 0)
	BufferTooShort();
      sendString(buf);

      if(myGlobals.device[i].exportNetFlow == FLAG_NETFLOW_EXPORT_ENABLED) numEnabled++;
    }
  }

  sendString("</TABLE>\n<P>\n");

  if(numEnabled == 0) {
    sendString("<font color=red>WARNING</font>: as all the interfaces are disabled, no flows will be exported<p>\n");
  }

/* ************************************* */

  if((myGlobals.numNetFlowsPktsRcvd > 0) || (myGlobals.numNetFlowsPktsSent > 0)) {
    sendString("<TABLE BORDER>\n");
    sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=CENTER COLSPAN=2>Flow Statistics</TH></TR>\n");

    if(myGlobals.numNetFlowsPktsRcvd > 0) {
      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT># Pkts Rcvd.value</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numNetFlowsPktsRcvd)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT># Flows Rcvd.value</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numNetFlowsRcvd)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT># Flow with Bad Version</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numBadFlowsVersionsRcvd)) < 0)
	BufferTooShort();
      sendString(buf);

      sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Flow Senders</TH><TD "TD_BG" ALIGN=LEFT>");

      for(i=0; i<MAX_NUM_PROBES; i++) {
	if(probeList[i].probeAddr.s_addr == 0) break;

	if(snprintf(buf, sizeof(buf), "%s [%s pkts]\n",
		    _intoa(probeList[i].probeAddr, buf, sizeof(buf)),
		    formatPkts(probeList[i].pkts)) < 0)
	  BufferTooShort();
	sendString(buf);
      }

      sendString("</TD></TR>\n");
    }

    if(myGlobals.numNetFlowsPktsSent > 0) {
      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT># Exported Flows</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numNetFlowsPktsSent)) < 0)
	BufferTooShort();
      sendString(buf);
    }

    sendString("</TABLE>\n");
  }


/* ************************************* */

  sendString("<p></CENTER>\n");
  sendString("<p><H5>NetFlow is a trademark of <A HREF=http://www.cisco.com/>Cisco Systems</A>.</H5>\n");
  sendString("<p><center>Return to <a href=\"../" STR_SHOW_PLUGINS "\">plugins</a> menu</center></p>\n");

  printHTMLtrailer();
}

/* ****************************** */

static void termNetflowFunct(void) {
#ifdef CFG_MULTITHREADED
  if(threadActive) {
    killThread(&netFlowThread);
    threadActive = 0;
  }
 #endif

  if(myGlobals.netFlowInSocket > 0) closeNwSocket(&myGlobals.netFlowInSocket);

  traceEvent(CONST_TRACE_INFO, "Thanks for using ntop NetFlow");
  traceEvent(CONST_TRACE_INFO, "Done.\n");
  fflush(stdout);
}

/* **************************************** */

#ifdef DEBUG_FLOWS

static void handleNetFlowPacket(u_char *_deviceId,
			      const struct pcap_pkthdr *h,
				const u_char *p) {
  int sampledPacketSize;
  int deviceId, rc;

  if(myGlobals.rFileName != NULL) {
    /* ntop is reading packets from a file */
    struct ether_header ehdr;
    u_int caplen = h->caplen;
    u_int length = h->len;
    unsigned short eth_type;
    u_int8_t flags = 0;
    struct ip ip;

    if(caplen >= sizeof(struct ether_header)) {
      memcpy(&ehdr, p, sizeof(struct ether_header));
      eth_type = ntohs(ehdr.ether_type);

      if(eth_type == ETHERTYPE_IP) {
	u_int plen, hlen;
	u_short sport, dport;

	memcpy(&ip, p+sizeof(struct ether_header), sizeof(struct ip));
	hlen = (u_int)ip.ip_hl * 4;
	NTOHL(ip.ip_dst.s_addr); NTOHL(ip.ip_src.s_addr);

	plen = length-sizeof(struct ether_header);

	if(ip.ip_p == IPPROTO_UDP) {
	  if(plen > (hlen+sizeof(struct udphdr))) {
	    char* rawSample    = (void*)(p+sizeof(struct ether_header)+hlen+sizeof(struct udphdr));
	    int   rawSampleLen = h->caplen-(sizeof(struct ether_header)+hlen+sizeof(struct udphdr));

#ifdef DEBUG_FLOWS
	    /* traceEvent(CONST_TRACE_INFO, "Rcvd from from %s", intoa(ip.ip_src)); */
#endif
	    dissectFlow(rawSample, rawSampleLen);
	  }
	}
      }
    }
  }
}

#endif

/* ****************************** */

static PluginInfo netflowPluginInfo[] = {
  { "NetFlow",
    "This plugin is used to setup, activate and deactivate ntop's NetFlow support.<br>"
      "ntop can both collect and receive NetFlow data. Received NetFlow data is "
      "reported as a separate 'NIC' in the regular ntop reports.",
    "2.0", /* version */
    "<A HREF=http://luca.ntop.org/>L.Deri</A>",
    "NetFlow", /* http://<host>:<port>/plugins/NetFlow */
    0, /* Active by default */
    1, /* Inactive setup */
    initNetFlowFunct, /* InitFunc   */
    termNetflowFunct, /* TermFunc   */
#ifdef DEBUG_FLOWS
    handleNetFlowPacket,
#else
    NULL, /* PluginFunc */
#endif
    handleNetflowHTTPrequest,
#ifdef DEBUG_FLOWS
    "udp and port 2055"
#else
    NULL  /* no capture */
#endif
  }
};

/* ***************************************** */

/* Plugin entry fctn */
#ifdef STATIC_PLUGIN
PluginInfo* netflowPluginEntryFctn(void)
#else
     PluginInfo* PluginEntryFctn(void)
#endif
{
  traceEvent(CONST_TRACE_INFO, "Welcome to %s. (C) 2002 by Luca Deri.\n",
	     netflowPluginInfo->pluginName);

  return(netflowPluginInfo);
}
