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

#define NETFLOW_DEFAULT_PORT  "2055"

#ifdef MULTITHREADED
static pthread_t netFlowThread;
static int threadActive;
#endif

/* ****************************** */

void setNetFlowInSocket() {
  struct sockaddr_in sin;
  int sockopt = 1;

  if(myGlobals.netFlowInSocket > 0) {
    traceEvent(TRACE_INFO, "NetFlow collector terminated");
    closeNwSocket(&myGlobals.netFlowInSocket);
  }

  if(myGlobals.netFlowInPort > 0) {
    myGlobals.netFlowInSocket = socket(AF_INET, SOCK_DGRAM, 0);

    setsockopt(myGlobals.netFlowInSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    sin.sin_family            = AF_INET;
    sin.sin_port              = (int)htons(myGlobals.netFlowInPort);
    sin.sin_addr.s_addr       = INADDR_ANY;

    if(bind(myGlobals.netFlowInSocket, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
      traceEvent(TRACE_WARNING, "NetFlow collector: port %d already in use.",
		 myGlobals.netFlowInPort);
      closeNwSocket(&myGlobals.netFlowInSocket);
      myGlobals.netFlowInSocket = 0;
      return;
    }

    traceEvent(TRACE_WARNING, "NetFlow collector listening on port %d.",
	       myGlobals.netFlowInPort);
  }

  if((myGlobals.netFlowInPort > 0) && (myGlobals.netFlowDeviceId == 0))
    myGlobals.netFlowDeviceId = createDummyInterface("NetFlow-device");

  myGlobals.mergeInterfaces = 0; /* Use different devices */
}

/* *************************** */

void setNetFlowOutSocket() {
  if(myGlobals.netFlowOutSocket <= 0) {
    char value[256];
    int sockopt = 1;

    myGlobals.netFlowOutSocket = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(myGlobals.netFlowOutSocket, SOL_SOCKET, SO_REUSEADDR,
	       (char *)&sockopt, sizeof(sockopt));

    myGlobals.netFlowDest.sin_addr.s_addr = 0;
    myGlobals.netFlowDest.sin_family      = AF_INET;
    myGlobals.netFlowDest.sin_port        = (int)htons(atoi(NETFLOW_DEFAULT_PORT));

    if(fetchPrefsValue("netFlow.netFlowDest", value, sizeof(value)) == -1)
      storePrefsValue("netFlow.netFlowDest", "");
    else if(value[0] != '\0') {
      myGlobals.netFlowDest.sin_addr.s_addr = inet_addr(value);
      if(myGlobals.netFlowDest.sin_addr.s_addr > 0) 
	traceEvent(TRACE_INFO, "Exporting NetFlow's towards %s:%s", value, NETFLOW_DEFAULT_PORT);
      else
	traceEvent(TRACE_INFO, "NetFlow export disabled");
    }
  }
}

/* ****************************** */

static void* netflowMainLoop(void* notUsed _UNUSED_) {
  fd_set netflowMask;
  int rc, len;
  u_char buffer[2048];
  struct sockaddr_in fromHost;

#ifndef DEBUG
  traceEvent(TRACE_INFO, "netflowMainLoop()");
#endif

  if(!(myGlobals.netFlowInSocket > 0)) return(NULL);

  traceEvent(TRACE_INFO, "Welcome to NetFlow: listening on UDP port %d...", myGlobals.netFlowInPort);
#ifdef MULTITHREADED
 traceEvent(TRACE_INFO, "Started thread (%ld) for netFlow.\n", netFlowThread);
#endif
  
  for(;myGlobals.capturePackets == 1;) {
    FD_ZERO(&netflowMask);
    FD_SET(myGlobals.netFlowInSocket, &netflowMask);

    if(select(myGlobals.netFlowInSocket+1, &netflowMask, NULL, NULL, NULL) > 0) {
      len = sizeof(fromHost);
      rc = recvfrom(myGlobals.netFlowInSocket, (char*)&buffer, sizeof(buffer),
		    0, (struct sockaddr*)&fromHost, &len);

      /*
	traceEvent(TRACE_INFO, "=>>> rawSampleLen: %d (deviceId=%d)",
	rc,  myGlobals.netFlowDeviceId);
      */

      if(rc > 0) {
	NetFlow5Record theRecord;
	int i, numFlows;

	memcpy(&theRecord, buffer, rc > sizeof(theRecord) ? sizeof(theRecord): rc);

	if(theRecord.flowHeader.version == htons(5)) {
	  numFlows = ntohs(theRecord.flowHeader.count);
	  if(numFlows > V5FLOWS_PER_PAK) numFlows = V5FLOWS_PER_PAK;

	  for(i=0; i<numFlows; i++) {
	    int actualDeviceId;
	    char buf[256], buf1[256];
	    struct in_addr a, b;
	    u_int srcHostIdx, dstHostIdx, numPkts, len;
	    HostTraffic *srcHost=NULL, *dstHost=NULL;
	    u_short sport, dport;

	    len = ntohl(theRecord.flowRecord[i].dOctets);
	    numPkts = ntohl(myGlobals.theRecord.flowRecord[i].dPkts);
	    a.s_addr = ntohl(theRecord.flowRecord[i].srcaddr);
	    b.s_addr = ntohl(theRecord.flowRecord[i].dstaddr);
	    sport = ntohs(theRecord.flowRecord[i].srcport);
	    dport = ntohs(theRecord.flowRecord[i].dstport);

	    if(0)
	      traceEvent(TRACE_INFO, "%2d) %s:%d <-> %s:%d %u/%u (proto=%d)",
			 i+1, _intoa(a, buf, sizeof(buf)),
			 sport, _intoa(b, buf1, sizeof(buf1)),
			 dport, ntohl(theRecord.flowRecord[i].dPkts),
			 len, theRecord.flowRecord[i].prot);

	    /* traceEvent(TRACE_INFO, "a=%u", theRecord.flowRecord[i].srcaddr); */

	    actualDeviceId = myGlobals.netFlowDeviceId;

	    if(actualDeviceId >= myGlobals.numDevices) {
	      traceEvent(TRACE_ERROR, "NetFlow deviceId (%d) is out range", actualDeviceId);
	      break;
	    }


	    myGlobals.device[actualDeviceId].ethernetPkts += numPkts;
	    myGlobals.device[actualDeviceId].ipPkts += numPkts;
	    updateDevicePacketStats(len, actualDeviceId);

	    myGlobals.device[actualDeviceId].ethernetBytes += len;
	    myGlobals.device[actualDeviceId].ipBytes += len;

#ifdef MULTITHREADED
	    /* accessMutex(&myGlobals.hostsHashMutex, "processNetFlowPacket"); */
#endif
	    dstHostIdx = getHostInfo(&b, NULL, 0, 1, myGlobals.netFlowDeviceId);
	    dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	    /* traceEvent(TRACE_INFO, "dstHostIdx: %d", dstHostIdx); */
	    srcHostIdx = getHostInfo(&a, NULL, 0, 1, myGlobals.netFlowDeviceId);
	    srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	    /* traceEvent(TRACE_INFO, "srcHostIdx: %d", srcHostIdx); */

	    if((srcHost == NULL) || (dstHost == NULL)) continue;

	    srcHost->lastSeen = dstHost->lastSeen = myGlobals.actTime;
	    srcHost->pktSent += numPkts, dstHost->pktRcvd += numPkts;
	    srcHost->bytesSent   += len, dstHost->bytesRcvd   += len;
	    srcHost->ipBytesSent += len, dstHost->ipBytesRcvd += len;

	    if((sport != 0) && (dport != 0)) {
	      if(dport < sport) {
		if(handleIP(dport, srcHost, dstHost, len, 0, actualDeviceId) == -1)
		  handleIP(sport, srcHost, dstHost, len, 0, actualDeviceId);
	      } else {
		if(handleIP(sport, srcHost, dstHost, len, 0, actualDeviceId) == -1)
		  handleIP(dport, srcHost, dstHost, len, 0, actualDeviceId);
	      }
	    }

	    switch(theRecord.flowRecord[i].prot) {
	    case 1: /* ICMP */
	      myGlobals.device[actualDeviceId].icmpBytes += len;
	      srcHost->icmpSent += len, dstHost->icmpRcvd += len;
	      break;
	    case 6: /* TCP */
	      myGlobals.device[actualDeviceId].tcpBytes += len;
	      if(subnetPseudoLocalHost(dstHost))
		srcHost->tcpSentLoc += len;
	      else
		srcHost->tcpSentRem += len;

	      if(subnetPseudoLocalHost(srcHost))
		dstHost->tcpRcvdLoc += len;
	      else
		dstHost->tcpRcvdFromRem += len;
	      
	      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	      /*
		incrementUsageCounter(&srcHost->secHostPkts->establishedTCPConnSent, dstHostIdx, actualDeviceId);
		incrementUsageCounter(&dstHost->secHostPkts->establishedTCPConnRcvd, srcHostIdx, actualDeviceId);
		incrementUsageCounter(&srcHost->secHostPkts->terminatedTCPConnSent, dstHostIdx, actualDeviceId);
		incrementUsageCounter(&dstHost->secHostPkts->terminatedTCPConnRcvd, srcHostIdx, actualDeviceId);
	      */
	      myGlobals.device[actualDeviceId].numEstablishedTCPConnections++;
	      updateUsedPorts(srcHost, dstHost, sport, dport, len);
      
	      break;
	    case 17: /* UDP */
	      myGlobals.device[actualDeviceId].udpBytes += len;
	      if(subnetPseudoLocalHost(dstHost))
		srcHost->udpSentLoc += len;
	      else
		srcHost->udpSentRem += len;

	      if(subnetPseudoLocalHost(srcHost))
		dstHost->udpRcvdLoc += len;
	      else
		dstHost->udpRcvdFromRem += len;
	      break;
	    }

#ifdef MULTITHREADED
	    /* releaseMutex(&myGlobals.hostsHashMutex); */
#endif
	  }
	}
      }
    } else {
      traceEvent(TRACE_INFO, "NetFlow thread is terminating...");
      break;
    }
  }

#ifdef MULTITHREADED
  threadActive = 0;
#endif
  return(0);
}

/* ****************************** */

static void initNetFlowFunct(void) {
  int i;
  char key[256], value[256];

#ifdef MULTITHREADED
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

  for(i=0; i<myGlobals.numDevices; i++)
    if(!myGlobals.device[i].virtualDevice) {
      if(snprintf(key, sizeof(key),
		  "netFlow.%s.exportNetFlow",
		  myGlobals.device[i].name) < 0)
	BufferTooShort();

      if(fetchPrefsValue(key, value, sizeof(value)) == -1) {
	storePrefsValue(key, "No");
      } else {
	/* traceEvent(TRACE_INFO, "%s=%s", key, value); */

	if(strcmp(value, "Yes") == 0)
	  myGlobals.device[i].exportNetFlow = NETFLOW_EXPORT_ENABLED;
	else
	  myGlobals.device[i].exportNetFlow = NETFLOW_EXPORT_DISABLED;
      }
    }

#ifdef MULTITHREADED
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

  sendHTTPHeader(HTTP_TYPE_HTML, 0);
  printHTMLheader("NetFlow Statistics", 0);

  sendString("<CENTER>\n<HR>\n");

  if(url != NULL) {
    char *device, *value;

    device = strtok(url, "=");
    if(device != NULL) value = strtok(NULL, "=");

    if(value && device) {
      if(strcmp(device, "port") == 0) {
	myGlobals.netFlowInPort = atoi(value);
	storePrefsValue("netFlow.netFlowInPort", value);
	setNetFlowInSocket();
      } else if(strcmp(device, "collectorIP") == 0) {
	storePrefsValue("netFlow.netFlowDest", value);
	myGlobals.netFlowDest.sin_addr.s_addr = inet_addr(value);

	if(myGlobals.netFlowDest.sin_addr.s_addr > 0) 
	  traceEvent(TRACE_INFO, "Exporting NetFlow's towards %s:%s", value, NETFLOW_DEFAULT_PORT);
	else
	  traceEvent(TRACE_INFO, "NetFlow export disabled");
      } else {
	for(i=0; i<myGlobals.numDevices; i++)
	  if(!myGlobals.device[i].virtualDevice) {
	    if(strcmp(myGlobals.device[i].name, device) == 0) {
	      if(snprintf(buf, sizeof(buf),
			  "netFlow.%s.exportNetFlow",
			  myGlobals.device[i].name) < 0)
		BufferTooShort();

	      /* traceEvent(TRACE_INFO, "%s=%s", buf, value); */
	      storePrefsValue(buf, value);

	      if(!strcmp(value, "No")) {
		myGlobals.device[i].exportNetFlow = NETFLOW_EXPORT_DISABLED;
	      } else {
		myGlobals.device[i].exportNetFlow = NETFLOW_EXPORT_ENABLED;
	      }
	    }
	  }
      }
    }
  }

  sendString("<TABLE BORDER>");
  sendString("<TR "TR_ON"><TH "TH_BG">Flow Direction</TH><TH "TH_BG" COLSPAN=2>Description</TH></TR>\n");

  sendString("<TR "TR_ON"><TH "TH_BG">Incoming</TH><TD "TD_BG"><FORM ACTION=/plugins/NetFlow METHOD=GET>"
	     "Local Collector UDP Port:</td><td "TD_BG"><INPUT NAME=port SIZE=5 VALUE=");

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.netFlowInPort) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("> <INPUT TYPE=submit VALUE=Set><br>"
	     "[default port is "NETFLOW_DEFAULT_PORT"]</FORM></td></tr>\n");

  /* *************************************** */

  sendString("<TR "TR_ON"><TH "TH_BG">Outgoing</TH><TD "TD_BG"><FORM ACTION=/plugins/NetFlow METHOD=GET>"
	     "Remote Collector IP Address</td> "
	     "<td "TD_BG"><INPUT NAME=collectorIP SIZE=15 VALUE=");

  theDest.s_addr = ntohl(myGlobals.netFlowDest.sin_addr.s_addr);
  sendString(_intoa(theDest, buf, sizeof(buf)));

  sendString(">:2055 <INPUT TYPE=submit VALUE=Set></FORM></td></tr>\n");
  sendString("<TR "TR_ON"><TH "TH_BG">&nbsp;</TH><TD "TD_BG" align=center COLSPAN=2>"
	     "NOTE: Use 0 to disable export/collection</TD></TR>\n");
  sendString("</TABLE><p>\n");

  /* ************************ */

  sendString("<TABLE BORDER>\n");
  sendString("<TR "TR_ON"><TH "TH_BG">Interface Name</TH><TH "TH_BG">NetFlow Enabled</TH></TR>\n");   

  for(i=0; i<myGlobals.numDevices; i++) {
    if(!myGlobals.device[i].virtualDevice) {
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<A HREF=/plugins/NetFlow?%s=%s>%s</A></TD></TR>\n",
		  myGlobals.device[i].name, myGlobals.device[i].name,
		  myGlobals.device[i].exportNetFlow == NETFLOW_EXPORT_ENABLED ? "No" : "Yes",
		  myGlobals.device[i].exportNetFlow == NETFLOW_EXPORT_ENABLED ? "Yes" : "No"
		  ) < 0)
	BufferTooShort();
      sendString(buf);

      if(myGlobals.device[i].exportNetFlow == NETFLOW_EXPORT_ENABLED) numEnabled++;
    }
  }

  sendString("</TABLE>\n<P>\n");

  if(numEnabled == 0) {
    sendString("<font color=red>WARNING</font>: as all the interfaces are disabled, no flows will be exported<p>\n");
  }

  sendString("<p></CENTER>\n");

  printHTMLtrailer();
}

/* ****************************** */

static void termNetflowFunct(void) {
#ifdef MULTITHREADED
  if(threadActive) {
    killThread(&netFlowThread);
    threadActive = 0;
  }
 #endif

  if(myGlobals.netFlowInSocket > 0) closeNwSocket(&myGlobals.netFlowInSocket);

  traceEvent(TRACE_INFO, "Thanks for using ntop NetFlow");
  traceEvent(TRACE_INFO, "Done.\n");
  fflush(stdout);
}

/* ****************************** */

static PluginInfo netflowPluginInfo[] = {
  { "NetFlow",
    "This plugin is used to tune ntop's NetFlow support",
    "1.1", /* version */
    "<A HREF=http://luca.ntop.org/>L.Deri</A>",
    "NetFlow", /* http://<host>:<port>/plugins/NetFlow */
    1,    /* Active */
    initNetFlowFunct, /* InitFunc   */
    termNetflowFunct, /* TermFunc   */
    NULL, /* PluginFunc */
    handleNetflowHTTPrequest,
    NULL  /* no capture */
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
  traceEvent(TRACE_INFO, "Welcome to %s. (C) 2002 by Luca Deri.\n",
	     netflowPluginInfo->pluginName);

  return(netflowPluginInfo);
}
