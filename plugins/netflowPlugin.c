/*
 *  Copyright(C) 2002 Luca Deri <deri@ntop.org>
 *
 *  		       http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

/* This plugin works only with threads */

#include "ntop.h"
#include "globals-report.h"

#ifdef CFG_MULTITHREADED
static pthread_t netFlowThread;
static int threadActive;
static PthreadMutex whiteblackListMutex;
#endif

/* #define DEBUG_FLOWS  */

static ProbeInfo probeList[MAX_NUM_PROBES];

static u_int32_t whiteNetworks[MAX_NUM_NETWORKS][3], blackNetworks[MAX_NUM_NETWORKS][3];
static u_short numWhiteNets, numBlackNets;
static u_int32_t flowIgnoredZeroPort, flowIgnoredNETFLOW, flowProcessed;
static Counter flowIgnoredZeroPortBytes, flowProcessedBytes;
static u_int flowIgnored[MAX_NUM_IGNOREDFLOWS][6]; /* src, sport, dst, dport, count, bytes */
static u_short nextFlowIgnored;
static HostTraffic *dummyHost;
static u_int dummyHostIdx;

static u_int32_t flowIgnoredLowPort, flowIgnoredHighPort, flowAssumedFtpData;
static Counter flowIgnoredLowPortBytes, flowIgnoredHighPortBytes, flowAssumedFtpDataBytes;

/* Forward */
static void setNetFlowInSocket();
static void setNetFlowOutSocket();
static void setNetFlowInterfaceMatrix();
static void freeNetFlowMatrixMemory();
static void setPluginStatus(char * status);
static void ignoreFlow(u_short* theNextFlowIgnored, u_int srcAddr, u_short sport,
		       u_int dstAddr, u_short dport, Counter len);

/* ****************************** */

static void freeNetFlowMatrixMemory() {
  /*
    NOTE: wee need to lock something here(TBD)
  */

  if((!myGlobals.device[myGlobals.netFlowDeviceId].activeDevice) ||(myGlobals.netFlowDeviceId == -1)) return;

  if(myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrix != NULL) {
    int j;

    /* Courtesy of Wies-Software <wies@wiessoft.de> */
    for(j=0; j<(myGlobals.device[myGlobals.netFlowDeviceId].numHosts*myGlobals.device[myGlobals.netFlowDeviceId].numHosts); j++)
        if(myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrix[j] != NULL)
	  free(myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrix[j]);

    free(myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrix);
  }

  if(myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrixHosts != NULL)
    free(myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrixHosts);
}

/* ************************************************** */

static void setNetFlowInterfaceMatrix() {
  if((!myGlobals.device[myGlobals.netFlowDeviceId].activeDevice) ||(myGlobals.netFlowDeviceId == -1)) return;

  myGlobals.device[myGlobals.netFlowDeviceId].numHosts       = 0xFFFFFFFF - myGlobals.netFlowIfMask.s_addr+1;
  myGlobals.device[myGlobals.netFlowDeviceId].network.s_addr = myGlobals.netFlowIfAddress.s_addr;
  myGlobals.device[myGlobals.netFlowDeviceId].netmask.s_addr = myGlobals.netFlowIfMask.s_addr;
  if(myGlobals.device[myGlobals.netFlowDeviceId].numHosts > MAX_SUBNET_HOSTS) {
    myGlobals.device[myGlobals.netFlowDeviceId].numHosts = MAX_SUBNET_HOSTS;
    traceEvent(CONST_TRACE_WARNING, "NETFLOW: Truncated network size(device %s) to %d hosts(real netmask %s).",
	       myGlobals.device[myGlobals.netFlowDeviceId].name, myGlobals.device[myGlobals.netFlowDeviceId].numHosts,
	       intoa(myGlobals.device[myGlobals.netFlowDeviceId].netmask));
  }

  myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrix =(TrafficEntry**)calloc(myGlobals.device[myGlobals.netFlowDeviceId].numHosts*
										       myGlobals.device[myGlobals.netFlowDeviceId].numHosts,
										       sizeof(TrafficEntry*));
  myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrixHosts =(struct hostTraffic**)calloc(sizeof(struct hostTraffic*),
												  myGlobals.device[myGlobals.netFlowDeviceId].numHosts);
}

/* ************************************** */

static void setNetFlowInSocket() {
  struct sockaddr_in sockIn;
  int sockopt = 1;

  if(myGlobals.netFlowInSocket > 0) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Collector terminated");
    closeNwSocket(&myGlobals.netFlowInSocket);
  }

  if(myGlobals.netFlowInPort > 0) {
    myGlobals.netFlowInSocket = socket(AF_INET, SOCK_DGRAM, 0);

    setsockopt(myGlobals.netFlowInSocket, SOL_SOCKET, SO_REUSEADDR,(char *)&sockopt, sizeof(sockopt));

    sockIn.sin_family            = AF_INET;
    sockIn.sin_port              =(int)htons(myGlobals.netFlowInPort);
    sockIn.sin_addr.s_addr       = INADDR_ANY;

    if(bind(myGlobals.netFlowInSocket,(struct sockaddr *)&sockIn, sizeof(sockIn)) < 0) {
      traceEvent(CONST_TRACE_ERROR, "NETFLOW: Collector port %d already in use",
		 myGlobals.netFlowInPort);
      closeNwSocket(&myGlobals.netFlowInSocket);
      myGlobals.netFlowInSocket = 0;
      return;
    }

    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Collector listening on port %d",
	       myGlobals.netFlowInPort);
  }

  if((myGlobals.netFlowInPort > 0) &&(myGlobals.netFlowDeviceId == -1)) {
    myGlobals.netFlowDeviceId = createDummyInterface("NetFlow-device");
    setNetFlowInterfaceMatrix();
    myGlobals.device[myGlobals.netFlowDeviceId].activeDevice = 1;
  }

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
    myGlobals.netFlowDest.sin_port        =(int)htons(atoi(DEFAULT_NETFLOW_PORT_STR));

    if(fetchPrefsValue("netFlow.netFlowDest", value, sizeof(value)) == -1)
      storePrefsValue("netFlow.netFlowDest", "");
    else if(value[0] != '\0') {
      myGlobals.netFlowDest.sin_addr.s_addr = inet_addr(value);
      if(myGlobals.netFlowDest.sin_addr.s_addr > 0)
	traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Exporting NetFlow's towards %s:%s", value, DEFAULT_NETFLOW_PORT_STR);
      else
	traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Export disabled at user request");
    }
  }
}

/* ****************************** */

static void ignoreFlow(u_short* theNextFlowIgnored, u_int srcAddr, u_short sport,
		       u_int dstAddr, u_short dport,
		       Counter len) {
  u_short lastFlowIgnored;

  lastFlowIgnored = (*theNextFlowIgnored-1+MAX_NUM_IGNOREDFLOWS) % MAX_NUM_IGNOREDFLOWS;
  if ( (flowIgnored[lastFlowIgnored][0] == srcAddr) &&
       (flowIgnored[lastFlowIgnored][1] == sport) &&
       (flowIgnored[lastFlowIgnored][2] == dstAddr) &&
       (flowIgnored[lastFlowIgnored][3] == dport) ) {
    flowIgnored[lastFlowIgnored][4]++;
    flowIgnored[lastFlowIgnored][5] += len;
  } else {
    flowIgnored[*theNextFlowIgnored][0] = srcAddr;
    flowIgnored[*theNextFlowIgnored][1] = sport;
    flowIgnored[*theNextFlowIgnored][2] = dstAddr;
    flowIgnored[*theNextFlowIgnored][3] = dport;
    flowIgnored[*theNextFlowIgnored][4] = 1;
    flowIgnored[*theNextFlowIgnored][5] = len;
    *theNextFlowIgnored = (*theNextFlowIgnored + 1) % MAX_NUM_IGNOREDFLOWS;
  }
}

/* ****************************** */

static void dissectFlow(char *buffer, int bufferLen) {
  NetFlow5Record the5Record;
  NetFlow7Record the7Record;
  int skipSRC=0, skipDST=0;

#ifdef DEBUG
  char buf[LEN_SMALL_WORK_BUFFER], buf1[LEN_SMALL_WORK_BUFFER];
#endif

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

  if(the5Record.flowHeader.version != htons(5)) {
    myGlobals.numBadNetFlowsVersionsRcvd++;
  } else {
    int i, numFlows = ntohs(the5Record.flowHeader.count);

    if(numFlows > CONST_V5FLOWS_PER_PAK) numFlows = CONST_V5FLOWS_PER_PAK;

#ifdef DEBUG_FLOWS
    /* traceEvent(CONST_TRACE_INFO, "dissectFlow(%d flows)", numFlows); */
#endif

#ifdef CFG_MULTITHREADED
    /* Lock white/black lists for duration of this flow packet */
    accessMutex(&whiteblackListMutex, "flowPacket");
#endif

    for(i=0; i<numFlows; i++) {
      int actualDeviceId;
      Counter len;
      char theFlags[256];
      u_int16_t srcAS, dstAS;
      struct in_addr a, b;
      u_int numPkts;
      HostTraffic *srcHost=NULL, *dstHost=NULL;
      u_short sport, dport, proto;
      TrafficCounter ctr;

      myGlobals.numNetFlowsRcvd++;

      numPkts  = ntohl(the5Record.flowRecord[i].dPkts);
      len      =(Counter)ntohl(the5Record.flowRecord[i].dOctets);

      /* Bad flow(zero packets) */
      if(numPkts == 0) {
         myGlobals.numBadFlowPkts++;
	 continue;
      }
      /* Bad flow(zero length) */
      if(len == 0) {
         myGlobals.numBadFlowBytes++;
	 continue;
      }
      /* Bad flow(more packets than bytes) */
      if(numPkts > len) {
         myGlobals.numBadFlowReality++;
	 continue;
      }

      myGlobals.numNetFlowsProcessed++;

      a.s_addr = ntohl(the5Record.flowRecord[i].srcaddr);
      b.s_addr = ntohl(the5Record.flowRecord[i].dstaddr);
      sport    = ntohs(the5Record.flowRecord[i].srcport);
      dport    = ntohs(the5Record.flowRecord[i].dstport);
      proto    = the5Record.flowRecord[i].prot;
      srcAS    = ntohs(the5Record.flowRecord[i].src_as);
      dstAS    = ntohs(the5Record.flowRecord[i].dst_as);

      switch(myGlobals.netFlowAggregation) {
      case noAggregation:
	/* Nothing to do */
	break;
      case portAggregation:
	a.s_addr = b.s_addr = 0; /* 0.0.0.0 */
	break;
      case hostAggregation:
	sport = dport = 0;
	break;
      case protocolAggregation:
	skipDST = skipSRC = 1;
	a.s_addr = b.s_addr = 0; /* 0.0.0.0 */
	sport = dport = 0;
	srcAS = dstAS = 0;
	break;
      case asAggregation:
	skipDST = skipSRC = 1;
	a.s_addr = b.s_addr = 0; /* 0.0.0.0 */
	sport = dport = 0;
	proto = 17; /* UDP */
	break;
      }

      if(myGlobals.netFlowDebug) {
	theFlags[0] = '\0';

	if(the5Record.flowRecord[i].tcp_flags & TH_SYN)  strcat(theFlags, "SYN ");
	if(the5Record.flowRecord[i].tcp_flags & TH_FIN)  strcat(theFlags, "FIN ");
	if(the5Record.flowRecord[i].tcp_flags & TH_RST)  strcat(theFlags, "RST ");
	if(the5Record.flowRecord[i].tcp_flags & TH_ACK)  strcat(theFlags, "ACK ");
	if(the5Record.flowRecord[i].tcp_flags & TH_PUSH) strcat(theFlags, "PUSH");

#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "%2d) %s:%d <-> %s:%d pkt=%u/len=%u sAS=%d/dAS=%d flags=[%s](proto=%d)",
		   i+1,
		   _intoa(a, buf, sizeof(buf)), sport,
		   _intoa(b, buf1, sizeof(buf1)), dport,
		   ntohl(the5Record.flowRecord[i].dPkts), len,
		   srcAS, dstAS, theFlags, proto);
#endif
      }

      /* traceEvent(CONST_TRACE_INFO, "NETFLOW_DEBUG: a=%u", the5Record.flowRecord[i].srcaddr); */

      actualDeviceId = myGlobals.netFlowDeviceId;

      if((actualDeviceId == -1) ||(actualDeviceId >= myGlobals.numDevices)) {
	traceEvent(CONST_TRACE_ERROR, "NETFLOW: deviceId(%d) is out of range - ignored", actualDeviceId);
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


      if(!skipSRC) {
	switch((skipSRC = isOKtoSave(ntohl(the5Record.flowRecord[i].srcaddr),
				     whiteNetworks, blackNetworks,
				     numWhiteNets, numBlackNets)) ) {
	case 1:
	  myGlobals.numSrcNetFlowsEntryFailedWhiteList++;
	  break;
	case 2:
	  myGlobals.numSrcNetFlowsEntryFailedBlackList++;
	  break;
	default:
	  myGlobals.numSrcNetFlowsEntryAccepted++;
	}
      }

      if(!skipDST) {
	switch((skipDST = isOKtoSave(ntohl(the5Record.flowRecord[i].dstaddr),
				      whiteNetworks, blackNetworks,
				      numWhiteNets, numBlackNets)) ) {
	case 1:
	  myGlobals.numDstNetFlowsEntryFailedWhiteList++;
	  break;
	case 2:
	  myGlobals.numDstNetFlowsEntryFailedBlackList++;
	  break;
	default:
	  myGlobals.numDstNetFlowsEntryAccepted++;
	}
      }

#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: isOKtoSave(%08x) - src - returned %s",
                 ntohl(the5Record.flowRecord[i].srcaddr),
                 skipSRC == 0 ? "OK" : skipSRC == 1 ? "failed White list" : "failed Black list");
      traceEvent(CONST_TRACE_INFO, "DEBUG: isOKtoSave(%08x) - dst - returned %s",
                 ntohl(the5Record.flowRecord[i].dstaddr),
                 skipDST == 0 ? "OK" : skipDST == 1 ? "failed White list" : "failed Black list");
#endif

      if(!skipDST)
	dstHost = lookupHost(&b, NULL, 0, 1, myGlobals.netFlowDeviceId);
      else
	dstHost = dummyHost;

      if(!skipSRC)
	srcHost = lookupHost(&a, NULL, 0, 1, myGlobals.netFlowDeviceId);
      else
	srcHost = dummyHost;

      if((srcHost == NULL) ||(dstHost == NULL)) continue;

      srcHost->lastSeen = dstHost->lastSeen = myGlobals.actTime;
      /* Commented out ... already done in updatePacketCount()                         */
      /* srcHost->pktSent.value     += numPkts, dstHost->pktRcvd.value     += numPkts; */
      /* srcHost->bytesSent.value   += len,     dstHost->bytesRcvd.value   += len;     */
      srcHost->ipBytesSent.value += len,     dstHost->ipBytesRcvd.value += len;

      if(srcAS != 0) srcHost->hostAS = srcAS;
      if(dstAS != 0) dstHost->hostAS = dstAS;

#ifdef DEBUG_FLOWS
      /* traceEvent(CONST_TRACE_INFO, "%d/%d", srcHost->hostAS, dstHost->hostAS); */
#endif

      if((sport != 0) && (dport != 0)) {
	if(dport < sport) {
	  if(handleIP(dport, srcHost, dstHost, len, 0, 0, actualDeviceId) == -1) {
	    if(handleIP(sport, srcHost, dstHost, len, 0, 0, actualDeviceId) == -1) {
              if((dport == myGlobals.netFlowInPort) || (sport == myGlobals.netFlowInPort)) {
                  flowIgnoredNETFLOW++;
              } else if(min(sport, dport) <= 1023) {
                  flowIgnoredLowPort++;
                  flowIgnoredLowPortBytes += len;
                  ignoreFlow(&nextFlowIgnored,
                         ntohl(the5Record.flowRecord[i].srcaddr), sport,
                         ntohl(the5Record.flowRecord[i].dstaddr), dport,
                         len);
              } else if(myGlobals.netFlowAssumeFTP) {
                  /* If the user wants (via a run-time parm), as a last resort
                   * we assume it's ftp-data traffic
                   */
                  handleIP((u_short)CONST_FTPDATA, srcHost, dstHost, len, 0, 0, actualDeviceId);
                  flowAssumedFtpData++;
                  flowAssumedFtpDataBytes += len; 
              } else {
                  flowIgnoredHighPort++;
                  flowIgnoredHighPortBytes += len;
                  ignoreFlow(&nextFlowIgnored,
                         ntohl(the5Record.flowRecord[i].srcaddr), sport,
                         ntohl(the5Record.flowRecord[i].dstaddr), dport,
                         len);
              }
            } else { 
              flowProcessed++;
              flowProcessedBytes += len;
            }
          } else { 
            flowProcessed++;
            flowProcessedBytes += len;
          }
	} else {
	  if(handleIP(sport, srcHost, dstHost, len, 0, 0, actualDeviceId) == -1) {
	    if(handleIP(dport, srcHost, dstHost, len, 0, 0, actualDeviceId) == -1) {
              if((dport == myGlobals.netFlowInPort) || (sport == myGlobals.netFlowInPort)) {
                  flowIgnoredNETFLOW++;
              } else if(min(sport, dport) <= 1023) {
                  flowIgnoredLowPort++;
                  flowIgnoredLowPortBytes += len;
                  ignoreFlow(&nextFlowIgnored,
                         ntohl(the5Record.flowRecord[i].srcaddr), sport,
                         ntohl(the5Record.flowRecord[i].dstaddr), dport,
                         len);
              } else if(myGlobals.netFlowAssumeFTP) {
                  /* If the user wants (via a run-time parm), as a last resort
                   * we assume it's ftp-data traffic
                   */
                  handleIP((u_short)CONST_FTPDATA, srcHost, dstHost, len, 0, 0, actualDeviceId);
                  flowAssumedFtpData++;
                  flowAssumedFtpDataBytes += len;    
              } else {
                  flowIgnoredHighPort++;
                  flowIgnoredHighPortBytes += len;
                  ignoreFlow(&nextFlowIgnored,
                         ntohl(the5Record.flowRecord[i].srcaddr), sport,
                         ntohl(the5Record.flowRecord[i].dstaddr), dport,
                         len);
              }
            } else { 
              flowProcessed++;
              flowProcessedBytes += len;
            }
          } else { 
            flowProcessed++;
            flowProcessedBytes += len;
          }
	}
      } else {
        flowIgnoredZeroPort++;
        flowIgnoredZeroPortBytes += len;
        ignoreFlow(&nextFlowIgnored,
                   ntohl(the5Record.flowRecord[i].srcaddr), sport,
                   ntohl(the5Record.flowRecord[i].dstaddr), dport,
                   len);
      }

      ctr.value = len;
      updateTrafficMatrix(srcHost, dstHost, ctr, actualDeviceId);
      updatePacketCount(srcHost, dstHost, ctr, numPkts, actualDeviceId);

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

      switch(proto) {
      case 1: /* ICMP */
	myGlobals.device[actualDeviceId].icmpBytes.value += len;
	srcHost->icmpSent.value += len, dstHost->icmpRcvd.value += len;
	break;
      case 6: /* TCP */
	myGlobals.device[actualDeviceId].tcpBytes.value += len;
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
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

#ifdef CFG_MULTITHREADED
    releaseMutex(&whiteblackListMutex);
#endif

  }
}

/* ****************************** */

#ifdef CFG_MULTITHREADED

 #ifdef MAKE_WITH_NETFLOWSIGTRAP
RETSIGTYPE netflowcleanup(int signo) {
  static int msgSent = 0;
  int i;
  void *array[20];
  size_t size;
  char **strings;

  if(msgSent<10) {
    traceEvent(CONST_TRACE_FATALERROR, "NETFLOW: caught signal %d %s", signo,
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
  /* Don't double fault... */
  /* signal(signo, SIG_DFL); */

  /* Grab the backtrace before we do much else... */
  size = backtrace(array, 20);
  strings = (char**)backtrace_symbols(array, size);

  traceEvent(CONST_TRACE_FATALERROR, "NETFLOW: BACKTRACE:     backtrace is:");
  if (size < 2) {
    traceEvent(CONST_TRACE_FATALERROR, "NETFLOW: BACKTRACE:         **unavailable!");
  } else {
    /* Ignore the 0th entry, that's our cleanup() */
    for (i=1; i<size; i++) {
      traceEvent(CONST_TRACE_FATALERROR, "NETFLOW: BACKTRACE:          %2d. %s", i, strings[i]);
    }
  }
  #endif /* HAVE_BACKTRACE */

  exit(0);
}
 #endif /* MAKE_WITH_NETFLOWSIGTRAP */

/* ****************************** */

static void* netflowMainLoop(void* notUsed _UNUSED_) {
  fd_set netflowMask;
  int rc, len;
  u_char buffer[2048];
  struct sockaddr_in fromHost;

  if(!(myGlobals.netFlowInSocket > 0)) return(NULL);

#ifdef MAKE_WITH_NETFLOWSIGTRAP
  signal(SIGSEGV, netflowcleanup);
  signal(SIGHUP,  netflowcleanup);
  signal(SIGINT,  netflowcleanup);
  signal(SIGQUIT, netflowcleanup);
  signal(SIGILL,  netflowcleanup);
  signal(SIGABRT, netflowcleanup);
  signal(SIGFPE,  netflowcleanup);
  signal(SIGKILL, netflowcleanup);
  signal(SIGPIPE, netflowcleanup);
  signal(SIGALRM, netflowcleanup);
  signal(SIGTERM, netflowcleanup);
  signal(SIGUSR1, netflowcleanup);
  signal(SIGUSR2, netflowcleanup);
  /* signal(SIGCHLD, netflowcleanup); */
#ifdef SIGCONT
  signal(SIGCONT, netflowcleanup);
#endif
#ifdef SIGSTOP
  signal(SIGSTOP, netflowcleanup);
#endif
#ifdef SIGBUS
  signal(SIGBUS,  netflowcleanup);
#endif
#ifdef SIGSYS
  signal(SIGSYS,  netflowcleanup);
#endif
#endif /* MAKE_WITH_NETFLOWSIGTRAP */

  if(myGlobals.netFlowDeviceId != -1)
    myGlobals.device[myGlobals.netFlowDeviceId].activeDevice = 1;

  threadActive = 1;
  traceEvent(CONST_TRACE_INFO, "THREADMGMT: netFlow thread(%ld) started", netFlowThread);

  for(;myGlobals.capturePackets == FLAG_NTOPSTATE_RUN;) {
    FD_ZERO(&netflowMask);
    FD_SET(myGlobals.netFlowInSocket, &netflowMask);

    if((rc = select(myGlobals.netFlowInSocket+1, &netflowMask, NULL, NULL, NULL)) > 0) {
      len = sizeof(fromHost);
      rc = recvfrom(myGlobals.netFlowInSocket,(char*)&buffer, sizeof(buffer),
		    0,(struct sockaddr*)&fromHost, &len);

#ifdef DEBUG_FLOWS
      traceEvent(CONST_TRACE_INFO, "NETFLOW_DEBUG: Received NetFlow packet(len=%d)(deviceId=%d)",
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
		if(rc < 0) {
      traceEvent(CONST_TRACE_FATALERROR, "NETFLOW: select() failed(%d, %s), terminating netFlow",
                 errno, strerror(errno));
      break;
		}
	}
  }

  threadActive = 0;
  traceEvent(CONST_TRACE_WARNING, "THREADMGMT: netFlow thread(%ld) terminated", netFlowThread);

  if(myGlobals.netFlowDeviceId != -1)
    myGlobals.device[myGlobals.netFlowDeviceId].activeDevice = 0;

  return(NULL);
}

#endif

/* ****************************** */

static int initNetFlowFunct(void) {
  int i, a, b, c, d, a1, b1, c1, d1;
  char key[256], value[1024], workList[1024];

  setPluginStatus(NULL);

  myGlobals.netFlowDeviceId = -1;

#ifdef CFG_MULTITHREADED
  threadActive = 0;
  createMutex(&whiteblackListMutex);
#else
  /* This plugin works only with threads */
  setPluginStatus("Disabled - requires POSIX thread support.");
  return(-1);
#endif

  memset(flowIgnored, 0, sizeof(flowIgnored));
  nextFlowIgnored = 0;

  if(fetchPrefsValue("netFlow.netFlowInPort", value, sizeof(value)) == -1)
    storePrefsValue("netFlow.netFlowInPort", "0");
  else
    myGlobals.netFlowInPort = atoi(value);

  if(fetchPrefsValue("netFlow.netFlowDest", value, sizeof(value)) == -1)
    storePrefsValue("netFlow.netFlowDest", "0");
  else
    myGlobals.netFlowDest.sin_addr.s_addr = inet_addr(value);

  if((fetchPrefsValue("netFlow.ifNetMask", value, sizeof(value)) == -1)
     ||(sscanf(value, "%d.%d.%d.%d%%2F%d.%d.%d.%d", &a, &b, &c, &d, &a1, &b1, &c1, &d1) != 8)) {
    storePrefsValue("netFlow.ifNetMask", "192.168.0.0/255.255.255.0");
    myGlobals.netFlowIfAddress.s_addr = 0xC0A80000;
    myGlobals.netFlowIfMask.s_addr    = 0xFFFFFF00;
  } else {
    myGlobals.netFlowIfAddress.s_addr =(a << 24) +(b << 16) +(c << 8) + d;
    myGlobals.netFlowIfMask.s_addr    =(a1 << 24) +(b1 << 16) +(c1 << 8) + d1;
  }

  if(fetchPrefsValue("netFlow.whiteList", value, sizeof(value)) == -1) {
    storePrefsValue("netFlow.whiteList", "");
    myGlobals.netFlowWhiteList = strdup("");
  } else
    myGlobals.netFlowWhiteList = strdup(value);

  if(fetchPrefsValue("netFlow.netFlowAggregation", value, sizeof(value)) == -1)
    storePrefsValue("netFlow.netFlowAggregation", "0" /* noAggregation */);
  else
    myGlobals.netFlowAggregation = atoi(value);

  if(fetchPrefsValue("netFlow.netFlowAssumeFTP", value, sizeof(value)) == -1) {
    storePrefsValue("netFlow.netFlowAssumeFTP", "0" /* no */);
    myGlobals.netFlowAssumeFTP = 0;
  } else
    myGlobals.netFlowAssumeFTP = atoi(value);

#ifdef CFG_MULTITHREADED
  accessMutex(&whiteblackListMutex, "initNetFlowFunct()w");
#endif
  handleWhiteBlackListAddresses((char*)&value,
                                whiteNetworks,
                                &numWhiteNets,
                               (char*)&workList,
                                sizeof(workList));
  if(myGlobals.netFlowWhiteList != NULL) free(myGlobals.netFlowWhiteList);
  myGlobals.netFlowWhiteList = strdup(workList);
#ifdef CFG_MULTITHREADED
  releaseMutex(&whiteblackListMutex);
#endif
  traceEvent(CONST_TRACE_INFO, "NETFLOW: White list initialized to '%s'", myGlobals.netFlowWhiteList);

  if(fetchPrefsValue("netFlow.blackList", value, sizeof(value)) == -1) {
    storePrefsValue("netFlow.blackList", "");
    myGlobals.netFlowBlackList=strdup("");
  } else
    myGlobals.netFlowBlackList=strdup(value);

#ifdef CFG_MULTITHREADED
  accessMutex(&whiteblackListMutex, "initNetFlowFunct()b");
#endif
  handleWhiteBlackListAddresses((char*)&value, blackNetworks,
                                &numBlackNets, (char*)&workList,
                                sizeof(workList));
  if(myGlobals.netFlowBlackList != NULL) free(myGlobals.netFlowBlackList);
  myGlobals.netFlowBlackList = strdup(workList);
#ifdef CFG_MULTITHREADED
  releaseMutex(&whiteblackListMutex);
#endif
  traceEvent(CONST_TRACE_INFO, "NETFLOW: Black list initialized to '%s'", myGlobals.netFlowBlackList);

  setNetFlowInSocket();
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

    /* Allocate a pure dummy for white/black list use */
    dummyHost = (HostTraffic*)malloc(sizeof(HostTraffic));
    memset(dummyHost, 0, sizeof(HostTraffic));

    dummyHost->hostIpAddress.s_addr = 0x00112233;
    strncpy(dummyHost->hostNumIpAddress, "&nbsp;",
            sizeof(dummyHost->hostNumIpAddress));
    strncpy(dummyHost->hostSymIpAddress, "white/black list dummy",
            sizeof(dummyHost->hostSymIpAddress));
    strcpy(dummyHost->ethAddressString, "00:00:00:00:00:00");
    setEmptySerial(&dummyHost->hostSerial);
    dummyHost->portsUsage = (PortUsage**)calloc(sizeof(PortUsage*), MAX_ASSIGNED_IP_PORTS);

#ifdef CFG_MULTITHREADED
  if((myGlobals.netFlowInPort != 0) &&(!threadActive)) {
    /* This plugin works only with threads */
    createThread(&netFlowThread, netflowMainLoop, NULL);
  }
#endif
  return(0);
}

/* ****************************** */

static void handleNetflowHTTPrequest(char* url) {
  char buf[512], buf1[32], buf2[32];
  char workList[1024];
  int i, numEnabled = 0;
  struct in_addr theDest;

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);
  printHTMLheader("NetFlow Statistics", 0);

  sendString("<CENTER>\n<HR>\n");

  if(url != NULL) {
    char *device, *value = NULL;

    device = strtok(url, "=");
    if(device != NULL) value = strtok(NULL, "="); else value = NULL;

    if(value && device) {
      if(strcmp(device, "port") == 0) {
	myGlobals.netFlowInPort = atoi(value);
	storePrefsValue("netFlow.netFlowInPort", value);
	setNetFlowInSocket();
      } else if(strcmp(device, "debug") == 0) {
	myGlobals.netFlowDebug = atoi(value);
	storePrefsValue("netFlow.debug", value);
      } else if(strcmp(device, "netFlowAggregation") == 0) {
	myGlobals.netFlowAggregation = atoi(value);
	storePrefsValue("netFlow.netFlowAggregation", value);
      } else if(strcmp(device, "netFlowAssumeFTP") == 0) {
	myGlobals.netFlowAssumeFTP = atoi(value);
	storePrefsValue("netFlow.netFlowAssumeFTP", value);
      } else if(strcmp(device, "ifNetMask") == 0) {
	int a, b, c, d, a1, b1, c1, d1;

	if(sscanf(value, "%d.%d.%d.%d%%2F%d.%d.%d.%d",
		  &a, &b, &c, &d, &a1, &b1, &c1, &d1) == 8) {
	  myGlobals.netFlowIfAddress.s_addr =(a << 24) +(b << 16) +(c << 8) + d;
	  myGlobals.netFlowIfMask.s_addr    =(a1 << 24) +(b1 << 16) +(c1 << 8) + d1;
	  storePrefsValue("netFlow.ifNetMask", value);
	  freeNetFlowMatrixMemory(); setNetFlowInterfaceMatrix();
	} else
	  traceEvent(CONST_TRACE_ERROR, "NETFLOW: HTTP request NetMask Parse Error(%s)", value);
      } else if(strcmp(device, "whiteList") == 0) {
          /* Cleanup the http control char xform */
          char *fPtr=value, *tPtr=value;
          while(fPtr[0] != '\0') {
              if((fPtr[0] == '%') &&(fPtr[1] == '2')) {
                  *tPtr++ =(fPtr[2] == 'C') ? ',' : '/';
                  fPtr += 3;
              } else {
                  *tPtr++ = *fPtr++;
              }
          }
          tPtr[0]='\0';

#ifdef CFG_MULTITHREADED
          accessMutex(&whiteblackListMutex, "handleNetflowHTTPrequest()w");
#endif
          handleWhiteBlackListAddresses(value,
                                        whiteNetworks,
                                        &numWhiteNets,
                                       (char*)&workList,
                                        sizeof(workList));
          if(myGlobals.netFlowWhiteList != NULL) free(myGlobals.netFlowWhiteList);
          myGlobals.netFlowWhiteList=strdup(workList);
#ifdef CFG_MULTITHREADED
          releaseMutex(&whiteblackListMutex);
#endif
          storePrefsValue("netFlow.whiteList", myGlobals.netFlowWhiteList);
      } else if(strcmp(device, "blackList") == 0) {
          /* Cleanup the http control char xform */
          char *fPtr=value, *tPtr=value;
          while(fPtr[0] != '\0') {
              if((fPtr[0] == '%') &&(fPtr[1] == '2')) {
                  *tPtr++ =(fPtr[2] == 'C') ? ',' : '/';
                  fPtr += 3;
              } else {
                  *tPtr++ = *fPtr++;
              }
          }
          tPtr[0]='\0';

#ifdef CFG_MULTITHREADED
          accessMutex(&whiteblackListMutex, "handleNetflowHTTPrequest()b");
#endif
          handleWhiteBlackListAddresses(value,
                                        blackNetworks,
                                        &numBlackNets,
                                       (char*)&workList,
                                        sizeof(workList));
          if(myGlobals.netFlowBlackList != NULL) free(myGlobals.netFlowBlackList);
          myGlobals.netFlowBlackList=strdup(workList);
#ifdef CFG_MULTITHREADED
          releaseMutex(&whiteblackListMutex);
#endif
          storePrefsValue("netFlow.blackList", myGlobals.netFlowBlackList);
      } else if(strcmp(device, "collectorIP") == 0) {
	storePrefsValue("netFlow.netFlowDest", value);
	myGlobals.netFlowDest.sin_addr.s_addr = inet_addr(value);

	if(myGlobals.netFlowDest.sin_addr.s_addr > 0)
	  traceEvent(CONST_TRACE_INFO, "NETFLOW: Exporting NetFlow's towards %s:%s", value, DEFAULT_NETFLOW_PORT_STR);
	else
	  traceEvent(CONST_TRACE_INFO, "NETFLOW: Export disabled at user request");
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


  sendString("<center><table border=0>\n<tr><td><table border>");

  sendString("<tr><th colspan=4 "DARK_BG">Incoming Flows</th></tr>");
  sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Flow Collection</TH><TD "TD_BG"><FORM ACTION=/plugins/NetFlow METHOD=GET>"
	     "Local Collector UDP Port:</td><td "TD_BG"><INPUT NAME=port SIZE=5 VALUE=");

  if(snprintf(buf, sizeof(buf), "%d", myGlobals.netFlowInPort) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("> <br>[default port is "DEFAULT_NETFLOW_PORT_STR"]</td><td>"
	     "<INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

  sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Virtual NetFlow Interface<br>Network Address</TH><TD "TD_BG"><FORM ACTION=/plugins/NetFlow METHOD=GET>"
	       "Local Network IP Address/Mask:</td><td "TD_BG"><INPUT NAME=ifNetMask SIZE=32 VALUE=\"");

  if(snprintf(buf, sizeof(buf), "%s/%s",
		_intoa(myGlobals.netFlowIfAddress, buf1, sizeof(buf1)),
		_intoa(myGlobals.netFlowIfMask, buf2, sizeof(buf2))) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("\"><br>Format: digit.digit.digit.digit/digit.digit.digit.digit<br>"
	     "This does not(yet) accept CIDR /xx notation)</td><td><INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

  sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Flow Aggregation<br>Policy</TH><TD "TD_BG" align=left COLSPAN=2>"
	     "<FORM ACTION=/plugins/NetFlow METHOD=GET><SELECT NAME=netFlowAggregation>");

  sendString("<OPTION VALUE=0 "); if(myGlobals.netFlowAggregation == noAggregation) sendString("SELECTED"); sendString(">None (no aggregation)\n");
  sendString("<OPTION VALUE=2 "); if(myGlobals.netFlowAggregation == portAggregation) sendString("SELECTED"); sendString(">TCP/UDP Port\n");
  sendString("<OPTION VALUE=1 "); if(myGlobals.netFlowAggregation == hostAggregation) sendString("SELECTED"); sendString(">Host\n");
  sendString("<OPTION VALUE=3 "); if(myGlobals.netFlowAggregation == protocolAggregation) sendString("SELECTED"); sendString(">Protocol\n");
  sendString("<OPTION VALUE=4 "); if(myGlobals.netFlowAggregation == asAggregation) sendString("SELECTED"); sendString(">AS\n");
  sendString("</SELECT></td><td><INPUT TYPE=submit VALUE=Set></FORM></TD></TR>\n");

  sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>White list</TH><TD "TD_BG"><FORM ACTION=/plugins/NetFlow METHOD=GET>"
               "IP Address/Mask(s) we store data from:</td><td "TD_BG"><INPUT NAME=whiteList SIZE=60 VALUE=\"");

  if(snprintf(buf, sizeof(buf), "%s", myGlobals.netFlowWhiteList == NULL ? " " : myGlobals.netFlowWhiteList) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("\"></td><td><INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

  sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Black list</TH><TD "TD_BG"><FORM ACTION=/plugins/NetFlow METHOD=GET>"
               "IP Address/Mask(s) we reject data from:</td><td "TD_BG"><INPUT NAME=blackList SIZE=60 VALUE=\"");

  if(snprintf(buf, sizeof(buf), "%s", myGlobals.netFlowBlackList == NULL ? " " : myGlobals.netFlowBlackList) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("\"></td><td><INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

  sendString("<tr><th colspan=4 "DARK_BG">Outgoing Flows</th></tr>");

  /* *************************************** */

  sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Interfaces</TH>"
	     "<td colspan=3><table border width=100%%><tr><TH "TH_BG">Name</th><TH "TH_BG">Flow Export Enabled</TH></tr>\n");

  for(i=0; i<myGlobals.numDevices; i++) {
    if(!myGlobals.device[i].virtualDevice) {
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<A HREF=/plugins/NetFlow?%s=%s>%s</A></TD></TR>\n",
		  myGlobals.device[i].name, myGlobals.device[i].name,
		  myGlobals.device[i].exportNetFlow == FLAG_NETFLOW_EXPORT_ENABLED ? "No" : "Yes",
		  myGlobals.device[i].exportNetFlow == FLAG_NETFLOW_EXPORT_ENABLED ? "Yes" : "No") < 0)
	BufferTooShort();
      sendString(buf);

      if(myGlobals.device[i].exportNetFlow == FLAG_NETFLOW_EXPORT_ENABLED)
	numEnabled++;
    }
  }

  sendString("<tr><td colspan=4>");
  sendString("Press the link to toggle the interface state<br>\n");

  if(numEnabled == 0) {
    sendString("<center><font color=red>WARNING</font>: as all the interfaces are disabled, no flows will be exported</center>\n");
  }

  sendString("</td></tr></table>\n</td></tr>\n");

  /* *************************** */

  sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Outgoing Flows</TH><TD "TD_BG"><FORM ACTION=/plugins/NetFlow METHOD=GET>"
	     "Remote Collector IP Address</td> "
	     "<td "TD_BG"><INPUT NAME=collectorIP SIZE=15 VALUE=");

  theDest.s_addr = ntohl(myGlobals.netFlowDest.sin_addr.s_addr);
  sendString(_intoa(theDest, buf, sizeof(buf)));

  sendString(">:2055</td><td><INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

  sendString("<tr><th colspan=4 "DARK_BG">General Options</th></tr>");

  sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Assume FTP</TH><TD "TD_BG" align=left>"
	     "<FORM ACTION=/plugins/NetFlow METHOD=GET>");
  if(myGlobals.netFlowAssumeFTP) {
    sendString("<INPUT TYPE=radio NAME=netFlowAssumeFTP VALUE=1 CHECKED>Yes");
    sendString("<INPUT TYPE=radio NAME=netFlowAssumeFTP VALUE=0>No");
  } else {
    sendString("<INPUT TYPE=radio NAME=netFlowAssumeFTP VALUE=1>Yes");
    sendString("<INPUT TYPE=radio NAME=netFlowAssumeFTP VALUE=0 CHECKED>No");
  }
  sendString("</TD><td>");
  sendString("<p>When ntop sees netflow data it only sees the port numbers and\n");
  sendString("so it can not monitor the ftp control channel to detect which\n");
  sendString("ports are being used for ftp data.\n");
  sendString("This option tells ntop to assume that data from an unknown high (&gt;1023)\n");
  sendString("port to an unknown high port should be treated as FTP data.</p>\n");
  sendString("<p><b>For most situations this is not a good assumption</b> - for example,\n");
  sendString("peer-to-peer traffic also is high port to high port.\n");
  sendString("However, in limited situations, this option enables you to obtain a more\n");
  sendString("correct view of your traffic.\n");
  sendString("<em>Use this only if you understand your data flows.</em></p>\n");
  sendString("<p><b>NOTE</b>:&nbsp;This option takes effect IMMEDIATELY.</p></td>\n");

  sendString("<td><INPUT TYPE=submit VALUE=Set></form></td></TR>\n");

  sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Debug</TH><TD "TD_BG" align=left COLSPAN=2>"
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

  sendString("<tr><td><pre>\n\n</pre>"
	     "<b>NOTE</b>:<ol>"
	     "<li>Use 0 as port, and 0.0.0.0 as IP address to disable export/collection. "
                 "Use a space to disable the white / black lists."
	     "<li>The virtual NIC, 'NetFlow-device' is activated only when incoming flow "
                 "capture is enabled."
	     "<li>NetFlow packets are associated with this separate, virtual device and are "
                 "not mixed with captured packets."
             "<li>Once the virtual NIC is activated, it will remain available for the "
                 "duration of the ntop run, even if you disable incoming flows."
             "<li>Activating incoming flows will override the command line -M | "
                 "--no-interface-merge parameter for the duration of the ntop run."
             "<li>Use a.b.c.d/32 for a single host in the white / black lists."
             "<li>If a white list is present, then data for ONLY those host(s) and network(s) "
                 "will be stored.  Data for other hosts/networks is simply thrown away. "
                 "Both source and destination are checked and processed separately.<br>"
                 "If there is no white list, that all data will be stored(unless dropped "
                 "because of a black list)."
             "<li>If a black list is present, then data for those host(s) and network(s) "
                 "will be thrown away. Again, both source and destination are checked and "
                 "processed separately.<br>"
                 "If there is no black list, then no data will be excluded(unless dropped "
                 "because of a white list)."
	     "<li>NetFlow activation may require ntop restart.<br>"
                 "<I>Changes to white / black lists take affect immediately, "
                    "but are NOT retro-active.</I>"
	     "<li>You can switch devices using this <A HREF=\"/switch.html\">link</A>."
	     "</ol></td></tr>\n");
  sendString("<tr><td>"
	     "<p>Due to the way ntop works, NetFlow export capabilities are limited. "
                "If you need a fast, light, memory savvy,<br>highly configurable NetFlow "
                "probe, you better give "
                "<b><A HREF=\"http://www.ntop.org/nProbe.html\">nProbe</A></b> a try.</p>"
	     "<p>If you are looking for a cheap, dedicated hardware NetFlow probe you "
                "should look into <b><A HREF=\"http://www.ntop.org/nBox.html\">nBox</A></b> "
                "<IMG SRC=/nboxLogo.gif>"
	     "</td></tr>\n");
  sendString("</table><p>\n");

/* ************************************* */

  if((myGlobals.numNetFlowsPktsRcvd > 0) ||(myGlobals.numNetFlowsPktsSent > 0)) {
    sendString("<hr>\n");
    printHTMLheader("Incoming Flow Statistics", 0);
    sendString("<TABLE BORDER>\n");
    sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=CENTER COLSPAN=4 "DARK_BG">Received Flows</TH></TR>\n");

    if(myGlobals.numNetFlowsPktsRcvd > 0) {
      sendString("<TR "TR_ON"><TH colspan=2 "TH_BG" ALIGN=LEFT>Flow Senders</TH><TD colspan=2 "TD_BG" ALIGN=RIGHT>");

      for(i=0; i<MAX_NUM_PROBES; i++) {
	if(probeList[i].probeAddr.s_addr == 0) break;

	if(snprintf(buf, sizeof(buf), "%s [%s pkts]<br>\n",
		    _intoa(probeList[i].probeAddr, buf, sizeof(buf)),
		    formatPkts(probeList[i].pkts)) < 0)
	  BufferTooShort();
	sendString(buf);
      }

      sendString("</TD></TR>\n");
      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH colspan=2 "TH_BG" ALIGN=LEFT>Gives: # Pkts Received</TH><TD colspan=2 "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numNetFlowsPktsRcvd)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH colspan=2 "TH_BG" ALIGN=LEFT>Less: # Pkts with bad version</TH><TD colspan=2 "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numBadNetFlowsVersionsRcvd)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH colspan=2 "TH_BG" ALIGN=LEFT>Gives: # Pkts processed</TH><TD colspan=2 "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numNetFlowsPktsRcvd - myGlobals.numBadNetFlowsVersionsRcvd)) < 0)
	BufferTooShort();
      sendString(buf);

      if(myGlobals.numNetFlowsPktsRcvd - myGlobals.numBadNetFlowsVersionsRcvd > 0) {
          if(snprintf(buf, sizeof(buf),
                      "<TR "TR_ON"><TH colspan=2 "TH_BG" ALIGN=LEFT># Flows per packet(avg)</TH>"
                      "<TD colspan=2 "TD_BG" ALIGN=RIGHT>%.1f</TD></TR>\n",
    		     (float) myGlobals.numNetFlowsRcvd /
                       (float)(myGlobals.numNetFlowsPktsRcvd - myGlobals.numBadNetFlowsVersionsRcvd)
            ) < 0)
              BufferTooShort();
          sendString(buf);
      }

      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH colspan=2 "TH_BG" ALIGN=LEFT># Flows received</TH><TD colspan=2 "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numNetFlowsRcvd)) < 0)
	BufferTooShort();
      sendString(buf);

    sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=CENTER COLSPAN=4 "DARK_BG">Discarded Flows</TH></TR>\n");
      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH colspan=2 "TH_BG" ALIGN=LEFT>Less: # Flows with zero packet count</TH><TD colspan=2 "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numBadFlowPkts)) < 0)
	BufferTooShort();
      sendString(buf);
      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH colspan=2 "TH_BG" ALIGN=LEFT>Less: # Flows with zero byte count</TH><TD colspan=2 "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numBadFlowBytes)) < 0)
	BufferTooShort();
      sendString(buf);
      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH colspan=2 "TH_BG" ALIGN=LEFT>Less: # Flows with bad data</TH><TD colspan=2 "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numBadFlowReality)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH colspan=2 "TH_BG" ALIGN=LEFT>Gives: # Flows processed</TH><TD colspan=2 "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numNetFlowsProcessed)) < 0)
	BufferTooShort();
      sendString(buf);

      if(myGlobals.numSrcNetFlowsEntryFailedWhiteList +
          myGlobals.numSrcNetFlowsEntryFailedBlackList +
          myGlobals.numDstNetFlowsEntryFailedWhiteList +
          myGlobals.numDstNetFlowsEntryFailedBlackList > 0) {

          sendString("<TR><TH COLSPAN=4 "DARK_BG">Accepted/Rejected Flows</TH></TR>");
          sendString("<TR><TD COLSPAN=4 ALIGN=\"CENTER\"><TABLE BORDER=\"1\" width=100%>");

          sendString("<TR><TD>&nbsp;</TD><TH>Source</TH><TH>Destination</TH></TR>\n");

          sendString("<TR><TH ALIGN=\"LEFT\">Rejected - Black list</TH>");
          if(snprintf(buf, sizeof(buf),
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
                      formatPkts(myGlobals.numSrcNetFlowsEntryFailedBlackList)) < 0)
            BufferTooShort();
          sendString(buf);
          if(snprintf(buf, sizeof(buf),
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
                      formatPkts(myGlobals.numDstNetFlowsEntryFailedBlackList)) < 0)
            BufferTooShort();
          sendString(buf);
          sendString("</TR>\n");

          sendString("<TR><TH ALIGN=\"LEFT\">Rejected - White list</TH>");
          if(snprintf(buf, sizeof(buf),
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
                      formatPkts(myGlobals.numSrcNetFlowsEntryFailedWhiteList)) < 0)
            BufferTooShort();
          sendString(buf);
          if(snprintf(buf, sizeof(buf),
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
                      formatPkts(myGlobals.numDstNetFlowsEntryFailedWhiteList)) < 0)
            BufferTooShort();
          sendString(buf);
          sendString("</TR>\n");

          sendString("<TR><TH ALIGN=\"LEFT\">Accepted</TH>");
          if(snprintf(buf, sizeof(buf),
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
                      formatPkts(myGlobals.numSrcNetFlowsEntryAccepted)) < 0)
            BufferTooShort();
          sendString(buf);
          if(snprintf(buf, sizeof(buf),
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
                      formatPkts(myGlobals.numDstNetFlowsEntryAccepted)) < 0)
            BufferTooShort();
          sendString(buf);
          sendString("</TR>\n");

          sendString("<TR><TH ALIGN=\"RIGHT\">Total</TH>");
          if(snprintf(buf, sizeof(buf),
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
                      formatPkts(myGlobals.numSrcNetFlowsEntryFailedBlackList +
                                 myGlobals.numSrcNetFlowsEntryFailedWhiteList +
                                 myGlobals.numSrcNetFlowsEntryAccepted)) < 0)
            BufferTooShort();
          sendString(buf);
          if(snprintf(buf, sizeof(buf),
                      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>\n",
                      formatPkts(myGlobals.numDstNetFlowsEntryFailedBlackList +
                                 myGlobals.numDstNetFlowsEntryFailedWhiteList +
                                 myGlobals.numDstNetFlowsEntryAccepted)) < 0)
            BufferTooShort();
          sendString(buf);
          sendString("</TR>\n");

          sendString("</TABLE></TD></TR>\n");
      }

#ifdef DEBUG
      sendString("<TR><TD>White net list</TD><TD>");
      if(numWhiteNets == 0) {
          sendString("none");
      } else {
          sendString("Network&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Netmask&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Hostmask<br>\n");
          for(i=0; i<numWhiteNets; i++) {
              if(snprintf(buf, sizeof(buf),
                      "<br>\n%3d.&nbsp;%08x(%3d.%3d.%3d.%3d)&nbsp;%08x(%3d.%3d.%3d.%3d)&nbsp;%08x(%3d.%3d.%3d.%3d)",
                      i,
                      whiteNetworks[i][0],
                         ((whiteNetworks[i][0] >> 24) & 0xff),
                         ((whiteNetworks[i][0] >> 16) & 0xff),
                         ((whiteNetworks[i][0] >>  8) & 0xff),
                         ((whiteNetworks[i][0]      ) & 0xff),
                      whiteNetworks[i][1],
                         ((whiteNetworks[i][1] >> 24) & 0xff),
                         ((whiteNetworks[i][1] >> 16) & 0xff),
                         ((whiteNetworks[i][1] >>  8) & 0xff),
                         ((whiteNetworks[i][1]      ) & 0xff),
                      whiteNetworks[i][2],
                         ((whiteNetworks[i][2] >> 24) & 0xff),
                         ((whiteNetworks[i][2] >> 16) & 0xff),
                         ((whiteNetworks[i][2] >>  8) & 0xff),
                         ((whiteNetworks[i][2]      ) & 0xff)
                ) < 0)
                  BufferTooShort();
              sendString(buf);
              if(i<numWhiteNets) sendString("<br>\n");
          }
      }
      sendString("</TD></TR>\n");

      sendString("<TR><TD>Black net list</TD><TD>");
      if(numBlackNets == 0) {
          sendString("none");
      } else {
          sendString("Network&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Netmask&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Hostmask<br>\n");
          for(i=0; i<numBlackNets; i++) {
              if(snprintf(buf, sizeof(buf),
                      "<br>\n%3d.&nbsp;%08x(%3d.%3d.%3d.%3d)&nbsp;%08x(%3d.%3d.%3d.%3d)&nbsp;%08x(%3d.%3d.%3d.%3d)",
                      i,
                      blackNetworks[i][0],
                         ((blackNetworks[i][0] >> 24) & 0xff),
                         ((blackNetworks[i][0] >> 16) & 0xff),
                         ((blackNetworks[i][0] >>  8) & 0xff),
                         ((blackNetworks[i][0]      ) & 0xff),
                      blackNetworks[i][1],
                         ((blackNetworks[i][1] >> 24) & 0xff),
                         ((blackNetworks[i][1] >> 16) & 0xff),
                         ((blackNetworks[i][1] >>  8) & 0xff),
                         ((blackNetworks[i][1]      ) & 0xff),
                      blackNetworks[i][2],
                         ((blackNetworks[i][2] >> 24) & 0xff),
                         ((blackNetworks[i][2] >> 16) & 0xff),
                         ((blackNetworks[i][2] >>  8) & 0xff),
                         ((blackNetworks[i][2]      ) & 0xff)
                ) < 0)
                  BufferTooShort();
              sendString(buf);
              if(i<numBlackNets) sendString("<br>\n");
          }
      }
      sendString("</TD></TR>\n");
#endif

      sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=CENTER COLSPAN=4 "DARK_BG">Less: Ignored Flows</TH></TR>\n");

      if(snprintf(buf, sizeof(buf),
                  "<TR><TH colspan=2 ALIGN=\"LEFT\">Port(s) zero (not tcp/ip)</TH>\n"
                      "<TD ALIGN=\"RIGHT\">%u</TD><TD ALIGN=\"RIGHT\">%s</TD></TR>\n",
                      flowIgnoredZeroPort,
                      formatBytes(flowIgnoredZeroPortBytes, 1)
        ) < 0)
          BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf),
                  "<TR><TH colspan=2 ALIGN=\"LEFT\">Are netFlow</TH>\n"
                      "<TD ALIGN=\"RIGHT\">%u</TD><TD>&nbsp;</TD></TR>\n",
                  flowIgnoredNETFLOW
        ) < 0)
          BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf),
                  "<TR><TH colspan=2 ALIGN=\"LEFT\">unrecognized port <= 1023</TH>\n"
                      "<TD ALIGN=\"RIGHT\">%u</TD><TD ALIGN=\"RIGHT\">%s</TD></TR>\n",
                      flowIgnoredLowPort,
                      formatBytes(flowIgnoredLowPortBytes, 1)
        ) < 0)
          BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf),
                  "<TR><TH colspan=2 ALIGN=\"LEFT\">unrecognized port > 1023</TH>\n"
                      "<TD ALIGN=\"RIGHT\">%u</TD><TD ALIGN=\"RIGHT\">%s</TD></TR>\n",
                      flowIgnoredHighPort,
                      formatBytes(flowIgnoredHighPortBytes, 1)
        ) < 0)
          BufferTooShort();
      sendString(buf);

      sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=CENTER COLSPAN=4 "DARK_BG">Gives: Counted Flows</TH></TR>\n");

      if(snprintf(buf, sizeof(buf),
                  "<TR><TH colspan=2 ALIGN=\"LEFT\">Counted</TH>\n"
                      "<TD ALIGN=\"RIGHT\">%u</TD><TD ALIGN=\"RIGHT\">%s</TD></TR>\n",
                      flowProcessed,
                      formatBytes(flowProcessedBytes, 1)
        ) < 0)
          BufferTooShort();
      sendString(buf);

      if((flowAssumedFtpData>0) || (myGlobals.netFlowAssumeFTP)) {
        if(snprintf(buf, sizeof(buf),
                    "<TR><TH colspan=2 ALIGN=\"LEFT\">Assumed ftpdata</TH>\n"
                        "<TD ALIGN=\"RIGHT\">%u</TD><TD ALIGN=\"RIGHT\">%s</TD></TR>\n",
                        flowAssumedFtpData,
                        formatBytes(flowAssumedFtpDataBytes, 1)
          ) < 0)
            BufferTooShort();
        sendString(buf);
      }
      sendString("<TR><TH COLSPAN=4 ALIGN=\"CENTER\" "DARK_BG">Most Recent Ignored Flows</th></tr>\n");
      sendString("<TR><TH COLSPAN=2>Flow</TH><TH>Bytes</TH><TH># Consecutive<br>Counts</TH></TR>\n");
      for (i=nextFlowIgnored; i<nextFlowIgnored+MAX_NUM_IGNOREDFLOWS; i++) {
          if ((flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0] != 0) &&
              (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2] != 0) ) {
             if(flowIgnored[i%MAX_NUM_IGNOREDFLOWS][4] > 1) {
                 snprintf(buf1, sizeof(buf1), "(%d) ", flowIgnored[i%MAX_NUM_IGNOREDFLOWS][4]);
             } else {
	       snprintf(buf1, sizeof(buf1), "&nbsp;");
             }
             if (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][5] > 1536*1024*1024 /* ~1.5GB */) {
                 snprintf(buf2, sizeof(buf2), "%.1fGB",
                          (float)flowIgnored[i%MAX_NUM_IGNOREDFLOWS][5] / (1024.0*1024.0*1024.0));
             } else if (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][4] > 1536*1024 /* ~1.5MB */) {
                 snprintf(buf2, sizeof(buf2), "%.1fMB",
                          (float)flowIgnored[i%MAX_NUM_IGNOREDFLOWS][5] / (1024.0*1024.0));
             } else {
                 snprintf(buf2, sizeof(buf2), "%u",
                          flowIgnored[i%MAX_NUM_IGNOREDFLOWS][5]);
             }
             if(snprintf(buf, sizeof(buf),
                         "<TR><TD align=right>%d.%d.%d.%d:%d</TD><TD align=left>-> %d.%d.%d.%d:%d</TD>"
			 "<TD align=right>%s</TD></TD><TD align=right>%s</TD></TR>\n",
                         (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0] >> 24) & 0xff,
                         (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0] >> 16) & 0xff,
                         (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0] >>  8) & 0xff,
                         (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0]      ) & 0xff,
                         flowIgnored[i%MAX_NUM_IGNOREDFLOWS][1],
                         (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2] >> 24) & 0xff,
                         (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2] >> 16) & 0xff,
                         (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2] >>  8) & 0xff,
                         (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2]      ) & 0xff,
                         flowIgnored[i%MAX_NUM_IGNOREDFLOWS][3],
                         buf2, buf1
               ) < 0)
                 BufferTooShort();
             sendString(buf);
          }
      }

#ifdef CFG_MULTITHREADED
      if(whiteblackListMutex.isLocked) {
          sendString("<TR><TH>List Mutex</TH>\n");
          printMutexStatus(FALSE, &whiteblackListMutex, "White/Black list mutex");
          sendString("&nbsp;</TD></TR>\n");
      }
#endif

    }

    if(myGlobals.numNetFlowsPktsSent > 0) {
      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT># Exported Flows</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  formatPkts(myGlobals.numNetFlowsPktsSent)) < 0)
	BufferTooShort();
      sendString(buf);
    }

    sendString("</TABLE>\n");

    sendString("<P>Click <A HREF=\"/plugins/NetFlow\">here</A> to refresh this data.</CENTER></P>\n");
  }


/* ************************************* */

  sendString("<p></CENTER></CENTER>\n");
  sendString("<p><H5>NetFlow is a trademark of <A HREF=http://www.cisco.com/>Cisco Systems</A>.</H5>\n");
  sendString("<p align=right>[ Back to <a href=\"../" STR_SHOW_PLUGINS "\">plugins</a> ]&nbsp;</p>\n");


  printHTMLtrailer();
}

/* ****************************** */

static void termNetflowFunct(void) {
#ifdef CFG_MULTITHREADED
  if(threadActive) {
    killThread(&netFlowThread);
    threadActive = 0;
  }
  deleteMutex(&whiteblackListMutex);
 #endif

  if(myGlobals.netFlowInSocket > 0) {
    closeNwSocket(&myGlobals.netFlowInSocket);
    myGlobals.device[myGlobals.netFlowDeviceId].activeDevice = 0;
  }

  traceEvent(CONST_TRACE_INFO, "NETFLOW: Thanks for using ntop NetFlow");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Done");
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
	hlen =(u_int)ip.ip_hl * 4;
	NTOHL(ip.ip_dst.s_addr); NTOHL(ip.ip_src.s_addr);

	plen = length-sizeof(struct ether_header);

	if(ip.ip_p == IPPROTO_UDP) {
	  if(plen >(hlen+sizeof(struct udphdr))) {
	    char* rawSample    =(void*)(p+sizeof(struct ether_header)+hlen+sizeof(struct udphdr));
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
    "2.3.1", /* version */
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
    "udp and port 2055",
#else
    NULL, /* no capture */
#endif
    NULL  /* no status */
  }
};

/* ***************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGIN
PluginInfo* netflowPluginEntryFctn(void)
#else
     PluginInfo* PluginEntryFctn(void)
#endif
{
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Welcome to %s.(C) 2002 by Luca Deri",
	     netflowPluginInfo->pluginName);

  return(netflowPluginInfo);
}

/* This must be here so it can access the struct PluginInfo, above */
static void setPluginStatus(char * status)
   {
       if(netflowPluginInfo->pluginStatusMessage != NULL)
           free(netflowPluginInfo->pluginStatusMessage);
       if(status == NULL) {
           netflowPluginInfo->pluginStatusMessage = NULL;
       } else {
           netflowPluginInfo->pluginStatusMessage = strdup(status);
       }
   }
