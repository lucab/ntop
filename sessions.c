/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
 *                         Portions by Stefano Suin <stefano@ntop.org>
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "ntop.h"

/* #define TRACE_TRAFFIC_INFO */

 /* ************************************ */

u_int _checkSessionIdx(u_int idx, int actualDeviceId, char* file, int line) {
  if(idx > myGlobals.device[actualDeviceId].actualHashSize) {
    traceEvent(TRACE_ERROR, "Index error idx=%u/deviceId=%d:0-%d @ [%s:%d]\n", 
	       idx, actualDeviceId, 
	       myGlobals.device[actualDeviceId].actualHashSize,
	       file, line);
    return(0); /* Last resort */
  } else 
    return(idx);
}

/* ************************************ */

static PortUsage* allocatePortUsage(void) {
  PortUsage *ptr;

#ifdef DEBUG
  printf("allocatePortUsage() called\n");
#endif

  ptr = (PortUsage*)calloc(1, sizeof(PortUsage));
  ptr->clientUsesLastPeer = NO_PEER, ptr->serverUsesLastPeer = NO_PEER;

  return(ptr);
}

/* ************************************ */

void updateUsedPorts(HostTraffic *srcHost,
		u_int srcHostIdx,
		HostTraffic *dstHost,
		u_int dstHostIdx,
		u_short sport,
		u_short dport,
		u_int length) {
  
  /* traceEvent(TRACE_INFO, "%d\n", length); */

  if((srcHost->portsUsage == NULL) || (dstHost->portsUsage == NULL))
    return;

  if((srcHostIdx != myGlobals.broadcastEntryIdx) 
     && (srcHostIdx != myGlobals.otherHostEntryIdx)) {
    if(sport < TOP_ASSIGNED_IP_PORTS) {
      if(srcHost->portsUsage[sport] == NULL)
	srcHost->portsUsage[sport] = allocatePortUsage();

#ifdef DEBUG
      traceEvent(TRACE_INFO, "Adding svr peer %u", dstHostIdx);
#endif

      srcHost->portsUsage[sport]->serverTraffic += length;
      srcHost->portsUsage[sport]->serverUses++;
      srcHost->portsUsage[sport]->serverUsesLastPeer = dstHostIdx;

      if((dstHostIdx != myGlobals.broadcastEntryIdx)
	 && (dstHostIdx != myGlobals.otherHostEntryIdx)) {

	if(dstHost->portsUsage[sport] == NULL)
	  dstHost->portsUsage[sport] = allocatePortUsage();

#ifdef DEBUG
	traceEvent(TRACE_INFO, "Adding client peer %u", dstHostIdx);
#endif

	dstHost->portsUsage[sport]->clientTraffic += length;
	dstHost->portsUsage[sport]->clientUses++;
	dstHost->portsUsage[sport]->clientUsesLastPeer = srcHostIdx;
      }
    }
  }

  if((dstHostIdx != myGlobals.broadcastEntryIdx)
     && (dstHostIdx != myGlobals.otherHostEntryIdx)) {
    if(dport < TOP_ASSIGNED_IP_PORTS) {
      if(srcHost->portsUsage[dport] == NULL)
	srcHost->portsUsage[dport] = allocatePortUsage();

#ifdef DEBUG      
      traceEvent(TRACE_INFO, "Adding client peer %u", dstHostIdx);
#endif

      srcHost->portsUsage[dport]->clientTraffic += length;
      srcHost->portsUsage[dport]->clientUses++;
      srcHost->portsUsage[dport]->clientUsesLastPeer = dstHostIdx;
      
      if((srcHostIdx != myGlobals.broadcastEntryIdx)
	 && (srcHostIdx != myGlobals.otherHostEntryIdx)) {
	if(dstHost->portsUsage[dport] == NULL)
	  dstHost->portsUsage[dport] = allocatePortUsage();

#ifdef DEBUG
	traceEvent(TRACE_INFO, "Adding svr peer %u", srcHostIdx);
#endif

	dstHost->portsUsage[dport]->serverTraffic += length;
	dstHost->portsUsage[dport]->serverUses++;
	dstHost->portsUsage[dport]->serverUsesLastPeer = srcHostIdx;
      }
    }
  }
}

/* ************************************ */

static void updateHostSessionsList(u_int theHostIdx,
				   u_short port,
				   u_int remotePeerIdx,
				   IPSession *theSession,
				   u_short sessionType,
				   u_char initiator,
				   int role, int actualDeviceId) {
  /* This is a known port hence we're interested in */
  IpGlobalSession *scanner=NULL;
  HostTraffic *theHost, *theRemHost;

  if((theHostIdx == myGlobals.broadcastEntryIdx)
     || (theHostIdx == myGlobals.otherHostEntryIdx)
     || (remotePeerIdx == myGlobals.broadcastEntryIdx)
     || (remotePeerIdx == NO_PEER)
     || (theHostIdx == NO_PEER)
     || ((theRemHost = myGlobals.device[actualDeviceId].
	  hash_hostTraffic[checkSessionIdx(remotePeerIdx)]) == NULL)
     )
    return;

  theHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(theHostIdx)];

  if((theHost == NULL) /* Probably the host has been deleted */
     || broadcastHost(theHost)) /* We could't care less of junk traffic */
    return;

  switch(sessionType) {
  case IPPROTO_TCP: /* 6 */
    scanner = theHost->tcpSessionList;
    break;
  case IPPROTO_UDP: /* 17 */
    scanner = theHost->udpSessionList;
    break;
  }

  while(scanner != NULL) {
    if(scanner->magic != MAGIC_NUMBER) {
      traceEvent(TRACE_ERROR, "===> Magic assertion failed (2) for host %s/%d",
		 theHost->hostNumIpAddress, sessionType);
      scanner = NULL;
      return;
    } else if((scanner->port == port) && (scanner->initiator == role))
      break;

    scanner = (IpGlobalSession*)(scanner->next);
  }

  if(scanner == NULL) {
    scanner = (IpGlobalSession*)malloc(sizeof(IpGlobalSession));
    memset(scanner, 0, sizeof(IpGlobalSession));
    scanner->magic = MAGIC_NUMBER;
    scanner->port = port;
    scanner->initiator = role;
    scanner->firstSeen = myGlobals.actTime;

    resetUsageCounter(&scanner->peers);

    /* Add the session to the session list */
    switch(sessionType) {
    case IPPROTO_TCP:
      scanner->next = theHost->tcpSessionList;
      theHost->tcpSessionList = scanner; /* list head */
      break;
    case IPPROTO_UDP:
      scanner->next = theHost->udpSessionList;
      theHost->udpSessionList = scanner; /* list head */
      break;
    }
  }

  scanner->lastSeen = myGlobals.actTime;
  scanner->sessionCounter++;

  incrementUsageCounter(&scanner->peers, remotePeerIdx, actualDeviceId);

  switch(sessionType) {
  case IPPROTO_TCP:
    /*
      The "IP Session History" table in the individual host
      statistic page shown swapped values for the "Bytes sent"
      and "Bytes rcvd" columns if the client opened the
      connection. For server initiated connections like
      standard (not passive) ftp-data it was OK.

      Andreas Pfaller <apfaller@yahoo.com.au>
    */

    if((initiator == SERVER_TO_CLIENT)
       || (initiator == CLIENT_TO_SERVER)) {
      scanner->bytesSent           += theSession->bytesSent;
      scanner->bytesRcvd           += theSession->bytesRcvd;
      scanner->bytesFragmentedSent += theSession->bytesFragmentedSent;
      scanner->bytesFragmentedRcvd += theSession->bytesFragmentedRcvd;
    } else {
      scanner->bytesSent           += theSession->bytesRcvd;
      scanner->bytesRcvd           += theSession->bytesSent;
      scanner->bytesFragmentedSent += theSession->bytesFragmentedRcvd;
      scanner->bytesFragmentedRcvd += theSession->bytesFragmentedSent;
    }
    break;
  case IPPROTO_UDP:
    scanner->bytesSent           += theSession->bytesSent;
    scanner->bytesRcvd           += theSession->bytesRcvd;
    scanner->bytesFragmentedSent += theSession->bytesFragmentedSent;
    scanner->bytesFragmentedRcvd += theSession->bytesFragmentedRcvd;
    break;
  }
}

/* ************************************ */

void freeSession(IPSession *sessionToPurge, int actualDeviceId) {
  /* Session to purge */

    if(sessionToPurge->magic != MAGIC_NUMBER) {
	traceEvent(TRACE_ERROR, "===> Magic assertion failed (5)");
	return;
    }

  if((sessionToPurge->initiatorIdx < myGlobals.device[actualDeviceId].actualHashSize)
     && (sessionToPurge->remotePeerIdx < myGlobals.device[actualDeviceId].actualHashSize)) {
    /* The session seems to be formally ok */

    if(sessionToPurge->sport < sessionToPurge->dport) { /* Server->Client */
      if(getPortByNum(sessionToPurge->sport, IPPROTO_TCP) != NULL) {
	updateHostSessionsList(sessionToPurge->initiatorIdx, sessionToPurge->sport,
			       sessionToPurge->remotePeerIdx, sessionToPurge,
			       IPPROTO_TCP, SERVER_TO_CLIENT, SERVER_ROLE, actualDeviceId);
	updateHostSessionsList(sessionToPurge->remotePeerIdx, sessionToPurge->sport,
			       sessionToPurge->initiatorIdx, sessionToPurge,
			       IPPROTO_TCP, CLIENT_FROM_SERVER, CLIENT_ROLE, actualDeviceId);
      }
    } else { /* Client->Server */
      if(getPortByNum(sessionToPurge->dport, IPPROTO_TCP) != NULL) {
	updateHostSessionsList(sessionToPurge->remotePeerIdx, sessionToPurge->dport,
			       sessionToPurge->initiatorIdx, sessionToPurge,
			       IPPROTO_TCP, SERVER_FROM_CLIENT, SERVER_ROLE, actualDeviceId);
	updateHostSessionsList(sessionToPurge->initiatorIdx, sessionToPurge->dport,
			       sessionToPurge->remotePeerIdx, sessionToPurge,
			       IPPROTO_TCP, CLIENT_TO_SERVER, CLIENT_ROLE, actualDeviceId);
      }
    }

    if(((sessionToPurge->bytesProtoSent == 0)
	|| (sessionToPurge->bytesProtoRcvd == 0))
       && ((sessionToPurge->nwLatency.tv_sec != 0) || (sessionToPurge->nwLatency.tv_usec != 0))
       /* "Valid" TCP session used to skip faked sessions (e.g. portscans
	  with one faked packet + 1 response [RST usually]) */
       ) {
      HostTraffic *theHost, *theRemHost;
      char *fmt = "WARNING: detected TCP connection with no data exchanged "
	"[%s:%d] -> [%s:%d] (pktSent=%d/pktRcvd=%d) (network mapping attempt?)";

      theHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(sessionToPurge->initiatorIdx)];
      theRemHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(sessionToPurge->remotePeerIdx)];

      if((theHost != NULL) && (theRemHost != NULL)) {
	allocateSecurityHostPkts(theHost);
	incrementUsageCounter(&theHost->secHostPkts->closedEmptyTCPConnSent,
			      sessionToPurge->remotePeerIdx, actualDeviceId);
	incrementUsageCounter(&theHost->secHostPkts->terminatedTCPConnServer,
			      sessionToPurge->remotePeerIdx, actualDeviceId);

	allocateSecurityHostPkts(theRemHost);
	incrementUsageCounter(&theRemHost->secHostPkts->closedEmptyTCPConnRcvd,
			      sessionToPurge->initiatorIdx, actualDeviceId);
	incrementUsageCounter(&theRemHost->secHostPkts->terminatedTCPConnClient,
			      sessionToPurge->initiatorIdx, actualDeviceId);
	

	if(myGlobals.enableSuspiciousPacketDump)
	  traceEvent(TRACE_WARNING, fmt,
		     theHost->hostSymIpAddress, sessionToPurge->sport,
		     theRemHost->hostSymIpAddress, sessionToPurge->dport,
		     sessionToPurge->pktSent, sessionToPurge->pktRcvd);
      }
    }

    handlePluginSessionTermination(sessionToPurge, actualDeviceId);
  }
  
  /*
   * Having updated the session information, 'theSession'
   * can now be purged.
   */
  sessionToPurge->magic = 0;
  myGlobals.numTerminatedSessions++;

  myGlobals.device[actualDeviceId].numTcpSessions--;

#ifdef TRACE_TRAFFIC_INFO
  {
    char buf[32], buf1[32];

    traceEvent(TRACE_INFO, "Session terminated: %s:%d<->%s:%d (# sessions = %d)",
	       _intoa(sessionToPurge->initiatorRealIp, buf, sizeof(buf)), sessionToPurge->sport,
	       _intoa(sessionToPurge->remotePeerRealIp, buf1, sizeof(buf1)), sessionToPurge->dport,
	       myGlobals.device[actualDeviceId].numTcpSessions);
  }
#endif

  free(sessionToPurge); /* No inner pointers to free */
}

/* ************************************ */

#ifndef MULTITHREADED
void scanTimedoutTCPSessions(int actualDeviceId) {
  u_int idx, i;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Called scanTimedoutTCPSessions\n");
#endif

  for(idx=0; idx<myGlobals.device[actualDeviceId].numTotSessions; idx++) {
    IPSession *nextSession, *prevSession, *thisSession = myGlobals.device[actualDeviceId].tcpSession[idx];

    prevSession = thisSession;
      
    while(thisSession != NULL) {
      if(thisSession->magic != MAGIC_NUMBER) {
	thisSession = NULL;
	myGlobals.device[actualDeviceId].numTcpSessions--;
	traceEvent(TRACE_ERROR, "===> Magic assertion failed!");
	continue;
      }
	
      nextSession = thisSession->next;
	
      if(((thisSession->sessionState == STATE_TIMEOUT)
	  && ((thisSession->lastSeen+TWO_MSL_TIMEOUT) < myGlobals.actTime))
	 || /* The branch below allows to flush sessions which have not been
	       terminated properly (we've received just one FIN (not two). It might be
	       that we've lost some packets (hopefully not). */
	 ((thisSession->sessionState >= STATE_FIN1_ACK0)
	  && ((thisSession->lastSeen+DOUBLE_TWO_MSL_TIMEOUT) < myGlobals.actTime))
	 /* The line below allows to avoid keeping very old sessions that
	    might be still open, but that are probably closed and we've
	    lost some packets */
	 || ((thisSession->lastSeen+IDLE_HOST_PURGE_TIMEOUT) < myGlobals.actTime)
	 || ((thisSession->lastSeen+IDLE_SESSION_TIMEOUT) < myGlobals.actTime)
	 ) {
	if((prevSession != NULL) && (prevSession != thisSession))
	  prevSession->next = nextSession;
	else
	  myGlobals.device[actualDeviceId].tcpSession[idx] = NULL;

	if(myGlobals.device[actualDeviceId].tcpSession[idx] == thisSession) {
#ifdef DEBUG
	  traceEvent(TRACE_WARNING, "Found problem on idx %d", idx);
#endif
	  myGlobals.device[actualDeviceId].tcpSession[idx] = thisSession->next;

	  if(myGlobals.device[actualDeviceId].tcpSession[idx] == 
	     myGlobals.device[actualDeviceId].tcpSession[idx]->next) {
	    myGlobals.device[actualDeviceId].tcpSession[idx]->next = NULL;
#ifdef DEBUG
	    traceEvent(TRACE_WARNING, "Patched problem on idx %d", idx);
#endif
	  }
	}

	freeSession(thisSession, actualDeviceId);
      }

      thisSession = nextSession;

      if(thisSession && (thisSession->next == thisSession)) {
	traceEvent(TRACE_WARNING, "Internal Error (3)");
      }
    } /* while */
  } /* end for */
}
#endif /* MULTITHREADED */

/* ************************************ */

static IPSession* handleSession(const struct pcap_pkthdr *h,
				u_short fragmentedData,
				u_int tcpWin,
				u_int srcHostIdx,
				u_short sport,
				u_int dstHostIdx,
				u_short dport,
				u_int length,
				struct tcphdr *tp,
				u_int packetDataLength,
				u_char* packetData,
				int actualDeviceId) {
  u_int idx;
  IPSession *theSession = NULL;
  short flowDirection = CLIENT_TO_SERVER;
  char addedNewEntry = 0;
  u_short sessionType, check, found=0;
  u_short sessSport, sessDport;
  HostTraffic *srcHost, *dstHost, *hostToUpdate = NULL;
  struct timeval tvstrct;
  u_char rcStr[256];
  int len = 0;

  if((!myGlobals.enableSessionHandling) || (myGlobals.device[actualDeviceId].numTotSessions == 0))
    return(NULL);

  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];

  if((srcHost == NULL) || (dstHost == NULL)) {
    traceEvent(TRACE_INFO, "Sanity check failed (3) [Low memory?]");
    return(NULL);
  }

  /*
    Note: do not move the {...} down this function
    because BOOTP uses broadcast addresses hence
    it would be filtered out by the (**) check
  */
  if(myGlobals.enablePacketDecoding && (tp == NULL /* UDP session */))
    handleBootp(srcHost, dstHost, sport, dport, packetDataLength, packetData, actualDeviceId);

  if(broadcastHost(srcHost) || broadcastHost(dstHost)) /* (**) */
    return(theSession);

  if(tp == NULL)
    sessionType = IPPROTO_UDP;
  else {
    sessSport = ntohs(tp->th_sport);
    sessDport = ntohs(tp->th_dport);
    sessionType = IPPROTO_TCP;
  }

  /*
   * The hash key has to be calculated in a specular
   * way: its value has to be the same regardless
   * of the flow direction.
   *
   * Patch on the line below courtesy of
   * Paul Chapman <pchapman@fury.bio.dfo.ca>
   */
  idx = (u_int)((srcHost->hostIpAddress.s_addr+
		 dstHost->hostIpAddress.s_addr+
		 sport+dport) % myGlobals.device[actualDeviceId].numTotSessions);
  
#ifdef DEBUG
  traceEvent(TRACE_INFO, "%s:%d->%s:%d %d->",
	     srcHost->hostSymIpAddress, sport,
	     dstHost->hostSymIpAddress, dport, idx);
#endif

  if(sessionType == IPPROTO_TCP) {
    IPSession *prevSession;

    prevSession = theSession = myGlobals.device[actualDeviceId].tcpSession[idx];

    while(theSession != NULL) {
      if(theSession && (theSession->next == theSession)) {
	traceEvent(TRACE_WARNING, "Internal Error (4) (idx=%d)", idx);
	theSession->next = NULL;
      }      

      if((theSession->initiatorIdx == srcHostIdx)
	 && (theSession->remotePeerIdx == dstHostIdx)
	 && (theSession->sport == sport)
	 && (theSession->dport == dport)) {
	found = 1;
	flowDirection = CLIENT_TO_SERVER;
	break;
      } else if((theSession->initiatorIdx == dstHostIdx)
		&& (theSession->remotePeerIdx == srcHostIdx)
		&& (theSession->sport == dport)
		&& (theSession->dport == sport)) {
	found = 1;
	flowDirection = SERVER_TO_CLIENT;
	break;
      } else {
	/* Delete the session if too old */
	if(((theSession->lastSeen+IDLE_HOST_PURGE_TIMEOUT) < myGlobals.actTime)
	   || ((theSession->lastSeen+IDLE_SESSION_TIMEOUT) < myGlobals.actTime)) {
	  IPSession *nextSession = theSession->next;

	  if(myGlobals.device[actualDeviceId].tcpSession[idx] == theSession) {
	    myGlobals.device[actualDeviceId].tcpSession[idx] = nextSession;
	  } else {
	    prevSession->next = nextSession;
	  }
	  
	  freeSession(theSession, actualDeviceId);
	  theSession = nextSession;
	} else {
	  prevSession = theSession;
	  theSession = theSession->next;
	}
      }
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, "Search for session: %d (%d <-> %d)", found, sport, dport);
#endif

    if(!found) {
      /* New Session */
#ifdef DEBUG
      printf(" NEW ");
#endif

#ifdef DEBUG
      traceEvent(TRACE_INFO, "TCP hash [act size: %d][max size: %d]",
		 myGlobals.device[actualDeviceId].numTcpSessions,
		 (myGlobals.device[actualDeviceId].numTotSessions*AVERAGE_BUCKET_FILL));
#endif

      /* We don't check for space here as the datastructure allows
	 ntop to store sessions as needed 
      */
      /* There's enough space left in the hashtable */
      theSession = (IPSession*)malloc(sizeof(IPSession));
      memset(theSession, 0, sizeof(IPSession));
      addedNewEntry = 1;

      if(tp->th_flags == TH_SYN) {
	theSession->nwLatency.tv_sec = h->ts.tv_sec;
	theSession->nwLatency.tv_usec = h->ts.tv_usec;
	theSession->sessionState = STATE_SYN;
      }

      theSession->magic = MAGIC_NUMBER;
      myGlobals.device[actualDeviceId].numTcpSessions++;

      theSession->initiatorRealIp.s_addr = srcHost->hostIpAddress.s_addr;
      theSession->remotePeerRealIp.s_addr = dstHost->hostIpAddress.s_addr;

#ifdef TRACE_TRAFFIC_INFO
      traceEvent(TRACE_INFO, "New TCP session [%s:%d] <-> [%s:%d] (# sessions = %d)",
		 dstHost->hostNumIpAddress, dport,
		 srcHost->hostNumIpAddress, sport,
		 myGlobals.device[actualDeviceId].numTcpSessions);
#endif

#ifdef MULTITHREADED
      accessMutex(&myGlobals.hashResizeMutex, "newSession");
#endif
      theSession->next = myGlobals.device[actualDeviceId].tcpSession[idx];
      myGlobals.device[actualDeviceId].tcpSession[idx] = theSession;
#ifdef MULTITHREADED
      releaseMutex(&myGlobals.hashResizeMutex);
#endif
      theSession->initiatorIdx = checkSessionIdx(srcHostIdx);
      theSession->remotePeerIdx = checkSessionIdx(dstHostIdx);
      theSession->sport = sport;
      theSession->dport = dport;
      theSession->passiveFtpSession = isPassiveSession(dstHost->hostIpAddress.s_addr, dport);
      theSession->firstSeen = myGlobals.actTime;
      flowDirection = CLIENT_TO_SERVER;
    } 

#ifdef DEBUG
    traceEvent(TRACE_INFO, "->%d\n", idx);
#endif
    theSession->lastSeen = myGlobals.actTime;

    /* ***************************************** */

    if(packetDataLength >= sizeof(rcStr))
      len = sizeof(rcStr);
    else
      len = packetDataLength;

    if(myGlobals.enablePacketDecoding) {
      if((sport == 80 /* HTTP */) 
	 && (theSession->bytesProtoRcvd == 0)
	 && (packetDataLength > 0)) {
	strncpy(rcStr, packetData, 16);
	rcStr[16] = '\0';

	if(strncmp(rcStr, "HTTP/1", 6) == 0) {
	  int rc;
	  time_t microSecTimeDiff;

	  u_int16_t transactionId = (u_int16_t)(3*srcHost->hostIpAddress.s_addr
						+dstHost->hostIpAddress.s_addr+5*dport+7*sport);

	  /* to be 64bit-proof we have to copy the elements */
	  tvstrct.tv_sec = h->ts.tv_sec;
	  tvstrct.tv_usec = h->ts.tv_usec;
	  microSecTimeDiff = getTimeMapping(transactionId, tvstrct);

#ifdef HTTP_DEBUG
	  traceEvent(TRACE_INFO, "%s->%s [%s]\n",
		     srcHost->hostSymIpAddress,
		     dstHost->hostSymIpAddress,
		     rcStr);
#endif
	  if(srcHost->httpStats == NULL) {
	    srcHost->httpStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	    memset(srcHost->httpStats, 0, sizeof(ServiceStats));
	  }

	  if(dstHost->httpStats == NULL) {
	    dstHost->httpStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	    memset(dstHost->httpStats, 0, sizeof(ServiceStats));
	  }

	  rc = atoi(&rcStr[9]);

	  if(rc == 200) /* HTTP/1.1 200 OK */ {
	    srcHost->httpStats->numPositiveReplSent++;
	    dstHost->httpStats->numPositiveReplRcvd++;
	  } else {
	    srcHost->httpStats->numNegativeReplSent++;
	    dstHost->httpStats->numNegativeReplRcvd++;
	  }

	  FD_SET(HOST_SVC_HTTP, &srcHost->flags);

	  if(microSecTimeDiff > 0) {
	    if(subnetLocalHost(dstHost)) {
	      if((srcHost->httpStats->fastestMicrosecLocalReqMade == 0)
		 || (microSecTimeDiff < srcHost->httpStats->fastestMicrosecLocalReqServed))
		srcHost->httpStats->fastestMicrosecLocalReqServed = microSecTimeDiff;
	      if(microSecTimeDiff > srcHost->httpStats->slowestMicrosecLocalReqServed)
		srcHost->httpStats->slowestMicrosecLocalReqServed = microSecTimeDiff;
	    } else {
	      if((srcHost->httpStats->fastestMicrosecRemReqMade == 0)
		 || (microSecTimeDiff < srcHost->httpStats->fastestMicrosecRemReqServed))
		srcHost->httpStats->fastestMicrosecRemReqServed = microSecTimeDiff;
	      if(microSecTimeDiff > srcHost->httpStats->slowestMicrosecRemReqServed)
		srcHost->httpStats->slowestMicrosecRemReqServed = microSecTimeDiff;
	    }

	    if(subnetLocalHost(srcHost)) {
	      if((dstHost->httpStats->fastestMicrosecLocalReqMade == 0)
		 || (microSecTimeDiff < dstHost->httpStats->fastestMicrosecLocalReqMade))
		dstHost->httpStats->fastestMicrosecLocalReqMade = microSecTimeDiff;
	      if(microSecTimeDiff > dstHost->httpStats->slowestMicrosecLocalReqMade)
		dstHost->httpStats->slowestMicrosecLocalReqMade = microSecTimeDiff;
	    } else {
	      if((dstHost->httpStats->fastestMicrosecRemReqMade == 0)
		 || (microSecTimeDiff < dstHost->httpStats->fastestMicrosecRemReqMade))
		dstHost->httpStats->fastestMicrosecRemReqMade = microSecTimeDiff;
	      if(microSecTimeDiff > dstHost->httpStats->slowestMicrosecRemReqMade)
		dstHost->httpStats->slowestMicrosecRemReqMade = microSecTimeDiff;
	    }
	  } else {
#ifdef DEBUG
	    traceEvent(TRACE_INFO, "getTimeMapping(0x%X) failed for HTTP", transactionId);
#endif
	  }
	}
      } else if((dport == 80 /* HTTP */) && (packetDataLength > 0)) {
	if(theSession->bytesProtoSent == 0) {
	  char *rcStr;

	  rcStr = (char*)malloc(packetDataLength+1);
	  strncpy(rcStr, packetData, packetDataLength);
	  rcStr[packetDataLength] = '\0';

#ifdef HTTP_DEBUG
	  printf("%s->%s [%s]\n",
		 srcHost->hostSymIpAddress,
		 dstHost->hostSymIpAddress,
		 rcStr);
#endif

	  if(isInitialHttpData(rcStr)) {
	    char *strtokState, *row;

	    u_int16_t transactionId = (u_int16_t)(srcHost->hostIpAddress.s_addr+
						  3*dstHost->hostIpAddress.s_addr
						  +5*sport+7*dport);
	    /* to be 64bit-proof we have to copy the elements */
	    tvstrct.tv_sec = h->ts.tv_sec;
	    tvstrct.tv_usec = h->ts.tv_usec;
	    addTimeMapping(transactionId, tvstrct);

	    if(srcHost->httpStats == NULL) {
	      srcHost->httpStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	      memset(srcHost->httpStats, 0, sizeof(ServiceStats));
	    }
	    if(dstHost->httpStats == NULL) {
	      dstHost->httpStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	      memset(dstHost->httpStats, 0, sizeof(ServiceStats));
	    }

	    if(subnetLocalHost(dstHost))
	      srcHost->httpStats->numLocalReqSent++;
	    else
	      srcHost->httpStats->numRemReqSent++;

	    if(subnetLocalHost(srcHost))
	      dstHost->httpStats->numLocalReqRcvd++;
	    else
	      dstHost->httpStats->numRemReqRcvd++;

	    row = strtok_r(rcStr, "\n", &strtokState);

	    while(row != NULL) {
	      if(strncmp(row, "User-Agent:", 11) == 0) {
		char *token, *tokState, *browser = NULL, *os = NULL;

		row[strlen(row)-1] = '\0';

		/*
		  Mozilla/4.0 (compatible; MSIE 5.01; Windows 98)
		  Mozilla/4.7 [en] (X11; I; SunOS 5.8 i86pc)
		  Mozilla/4.76 [en] (Win98; U)
		*/
#ifdef DEBUG
		printf("=> '%s' (len=%d)\n", &row[12], packetDataLength);
#endif
		browser = token = strtok_r(&row[12], "(", &tokState);
		if(token == NULL) break; else token = strtok_r(NULL, ";", &tokState);
		if(token == NULL) break;

		if(strcmp(token, "compatible") == 0) {
		  browser = token = strtok_r(NULL, ";", &tokState);
		  os = token = strtok_r(NULL, ")", &tokState);
		} else {
		  char *tok1, *tok2;

		  tok1 = strtok_r(NULL, ";", &tokState);
		  tok2 = strtok_r(NULL, ")", &tokState);

		  if(tok2 == NULL) os = token; else  os = tok2;
		}

#ifdef DEBUG
		if(browser != NULL) {
		  trimString(browser);
		  printf("Browser='%s'\n", browser);
		}
#endif

		if(os != NULL) {
		  trimString(os);
#ifdef DEBUG
		  printf("OS='%s'\n", os);
#endif
		  if(srcHost->osName == NULL) {
		    srcHost->osName = strdup(os);
		  }
		}
		break;
	      }

	      row = strtok_r(NULL, "\n", &strtokState);
	    }

	    /* printf("==>\n\n%s\n\n", rcStr); */

	  } else {
	    if(myGlobals.enableSuspiciousPacketDump) {
	      traceEvent(TRACE_WARNING, "WARNING: unknown protocol (no HTTP) detected (trojan?) "
			 "at port 80 %s:%d->%s:%d [%s]\n",
			 srcHost->hostSymIpAddress, sport,
			 dstHost->hostSymIpAddress, dport,
			 rcStr);

	      dumpSuspiciousPacket(actualDeviceId);
	    }
	  }

	  free(rcStr);
	}
      } else if(((sport == 25 /* SMTP */)  || (dport == 25 /* SMTP */))
		&& (theSession->sessionState == STATE_ACTIVE)) {
	if(sport == 25) 
	  FD_SET(HOST_SVC_SMTP, &srcHost->flags); 
	else 
	  FD_SET(HOST_SVC_SMTP, &dstHost->flags);
      } else if(((dport == 515 /* printer */) || (sport == 515)) 
		&& (theSession->sessionState == STATE_ACTIVE)) {
	if(sport == 515) 
	  FD_SET(HOST_TYPE_PRINTER, &srcHost->flags);
	else 
	  FD_SET(HOST_TYPE_PRINTER, &dstHost->flags);
      } else if(((sport == 109 /* pop2 */) || (sport == 110 /* pop3 */)
		 || (dport == 109 /* pop2 */) || (dport == 110 /* pop3 */))
		&& (theSession->sessionState == STATE_ACTIVE)) {
	if((sport == 109) || (sport == 110))
	  FD_SET(HOST_SVC_POP, &srcHost->flags); 
	else
	  FD_SET(HOST_SVC_POP, &dstHost->flags);

      } else if(((sport == 143 /* imap */) || (dport == 143 /* imap */))
		&& (theSession->sessionState == STATE_ACTIVE)) {
	if(sport == 143) 
	  FD_SET(HOST_SVC_IMAP, &srcHost->flags); 
	else
	  FD_SET(HOST_SVC_IMAP, &dstHost->flags);
      }
    } else {
      /* !myGlobals.enablePacketDecoding */
      
      switch(sport) {
      case 21:
	FD_SET(HOST_SVC_FTP, &srcHost->flags);
	break;
      case 25:
	FD_SET(HOST_SVC_SMTP, &srcHost->flags);
	break;
      case 80:
      case 443:
	FD_SET(HOST_SVC_HTTP, &srcHost->flags);
	break;
      case 109:
      case 110:
	FD_SET(HOST_SVC_POP, &srcHost->flags); 
	break;
      case 143:
	FD_SET(HOST_SVC_IMAP, &srcHost->flags); 
	break;
      case 515:
	FD_SET(HOST_TYPE_PRINTER, &srcHost->flags);
	break;
      }
    }

    if((theSession->sessionState == STATE_ACTIVE)
       && ((theSession->nwLatency.tv_sec != 0)
	   || (theSession->nwLatency.tv_usec != 0))
       /* This session started *after* ntop started (i.e. ntop
	  didn't miss the beginning of the session). If the session
	  started *before* ntop started up then nothing can be said
	  about the protocol.
       */
       ) {
      if(packetDataLength >= sizeof(rcStr))
	len = sizeof(rcStr)-1;
      else
	len = packetDataLength;

      /*
	This is a brand new session: let's check whether this is
	not a faked session (i.e. a known protocol is running at
	an unknown port)
      */
      if((theSession->bytesProtoSent == 0) && (len > 0)) {
	memset(rcStr, 0, sizeof(rcStr));
	strncpy(rcStr, packetData, len);

	if(myGlobals.enablePacketDecoding) {
	  if((dport != 80)
	     && (dport != 3000  /* ntop  */)
	     && (dport != 3128  /* squid */)
	     && isInitialHttpData(rcStr)) {
	    if(myGlobals.enableSuspiciousPacketDump) {
	      traceEvent(TRACE_WARNING, "WARNING: HTTP detected at wrong port (trojan?) "
			 "%s:%d -> %s:%d [%s]",
			 srcHost->hostSymIpAddress, sport,
			 dstHost->hostSymIpAddress, dport,
			 rcStr);
	      dumpSuspiciousPacket(actualDeviceId);
	    }
	  } else if((sport != 21) && (sport != 25) && isInitialFtpData(rcStr)) {
	    if(myGlobals.enableSuspiciousPacketDump) {
	      traceEvent(TRACE_WARNING, "WARNING: FTP/SMTP detected at wrong port (trojan?) "
			 "%s:%d -> %s:%d [%s]",
			 dstHost->hostSymIpAddress, dport,
			 srcHost->hostSymIpAddress, sport,
			 rcStr);
	      dumpSuspiciousPacket(actualDeviceId);
	    }
	  } else if(((sport == 21) || (sport == 25)) && (!isInitialFtpData(rcStr))) {
	    if(myGlobals.enableSuspiciousPacketDump) {
	      traceEvent(TRACE_WARNING, "WARNING:  unknown protocol (no FTP/SMTP) detected (trojan?) "
			 "at port %d %s:%d -> %s:%d [%s]", sport,
			 dstHost->hostSymIpAddress, dport,
			 srcHost->hostSymIpAddress, sport,
			 rcStr);
	      dumpSuspiciousPacket(actualDeviceId);
	    }
	  } else if((sport != 22) && (dport != 22) &&  isInitialSshData(rcStr)) {
	    if(myGlobals.enableSuspiciousPacketDump) {
	      traceEvent(TRACE_WARNING, "WARNING: SSH detected at wrong port (trojan?) "
			 "%s:%d -> %s:%d [%s]  ",
			 dstHost->hostSymIpAddress, dport,
			 srcHost->hostSymIpAddress, sport,
			 rcStr);
	      dumpSuspiciousPacket(actualDeviceId);
	    }
	  } else if(((sport == 22) || (dport == 22)) && (!isInitialSshData(rcStr))) {
	    if(myGlobals.enableSuspiciousPacketDump) {
	      traceEvent(TRACE_WARNING, "WARNING: unknown protocol (no SSH) detected (trojan?) "
			 "at port 22 %s:%d -> %s:%d [%s]",
			 dstHost->hostSymIpAddress, dport,
			 srcHost->hostSymIpAddress, sport,
			 rcStr);
	      dumpSuspiciousPacket(actualDeviceId);
	    }
	  }
	}
      }
    }

    if(packetDataLength >= sizeof(rcStr))
      len = sizeof(rcStr)-1;
    else
      len = packetDataLength;
    
    /*
      We leave this is for the moment as we don't expect that
      this takes up much CPU time 
    */
    if(1 /* myGlobals.enablePacketDecoding */) {
      if(len > 0) {
	if(sport == 21) {
	  FD_SET(HOST_SVC_FTP, &srcHost->flags);
	  memset(rcStr, 0, sizeof(rcStr));

	  strncpy(rcStr, packetData, len);
	  /*
	    227 Entering Passive Mode (131,114,21,11,156,95)
	    131.114.21.11:40012 (40012 = 156 * 256 + 95)
	  */
	  if(strncmp(rcStr, "227", 3) == 0) {
	    int a, b, c, d, e, f;

	    sscanf(&rcStr[27], "%d,%d,%d,%d,%d,%d",
		   &a, &b, &c, &d, &e, &f);
	    sprintf(rcStr, "%d.%d.%d.%d", a, b, c, d);

#ifdef DEBUG
	    traceEvent(TRACE_INFO, "FTP: (%d) [%d.%d.%d.%d:%d]",
		       inet_addr(rcStr), a, b, c, d, (e*256+f));
#endif
	    addPassiveSessionInfo(htonl((unsigned long)inet_addr(rcStr)), (e*256+f));
	  }
	}
      } /* len > 0 */
    }

    /* ***************************************** */

    if((theSession->minWindow > tcpWin) || (theSession->minWindow == 0))
      theSession->minWindow = tcpWin;

    if((theSession->maxWindow < tcpWin) || (theSession->maxWindow == 0))
      theSession->maxWindow = tcpWin;

#ifdef DEBUG
    if(tp->th_flags & TH_ACK) printf("ACK ");
    if(tp->th_flags & TH_SYN) printf("SYN ");
    if(tp->th_flags & TH_FIN) printf("FIN ");
    if(tp->th_flags & TH_RST) printf("RST ");
    if(tp->th_flags & TH_PUSH) printf("PUSH");
    printf(" [%d]\n", tp->th_flags);
    printf("sessionsState=%d\n", theSession->sessionState);
#endif

    if((tp->th_flags == (TH_SYN|TH_ACK)) && (theSession->sessionState == STATE_SYN))  {
      theSession->sessionState = STATE_SYN_ACK;
    } else if((tp->th_flags == TH_ACK) && (theSession->sessionState == STATE_SYN_ACK)) {
      if(h->ts.tv_sec >= theSession->nwLatency.tv_sec) {
	theSession->nwLatency.tv_sec = h->ts.tv_sec-theSession->nwLatency.tv_sec;

	if((h->ts.tv_usec - theSession->nwLatency.tv_usec) < 0) {
	  theSession->nwLatency.tv_usec = 1000000 - (h->ts.tv_usec - theSession->nwLatency.tv_usec);
	  if(theSession->nwLatency.tv_usec > 1000000) theSession->nwLatency.tv_usec = 1000000;
	  theSession->nwLatency.tv_sec--;
	} else
	  theSession->nwLatency.tv_usec = h->ts.tv_usec-theSession->nwLatency.tv_usec;
	
	theSession->nwLatency.tv_sec /= 2;
	theSession->nwLatency.tv_usec /= 2;
	
	/* Sanity check */
	if(theSession->nwLatency.tv_sec > 1000) {
	  /* 
	     This value seems to be wrong so it's better to ignore it
	     rather than showing a false/wrong/dummy value
	  */
	  theSession->nwLatency.tv_usec = theSession->nwLatency.tv_sec = 0;
	}

	theSession->sessionState = STATE_ACTIVE;
      } else {
	/* The latency value is negative. There's something wrong so let's drop it */
	theSession->nwLatency.tv_usec = theSession->nwLatency.tv_sec = 0;
      }

      if(subnetLocalHost(srcHost)) {
	hostToUpdate = dstHost;
      } else if(subnetLocalHost(dstHost)) {
	hostToUpdate = srcHost;
      } else
	hostToUpdate = NULL;

      if(hostToUpdate != NULL) {
	u_long a, b, c;
	
	a = hostToUpdate->minLatency.tv_usec + 1000*hostToUpdate->minLatency.tv_sec;
	b = hostToUpdate->maxLatency.tv_usec + 1000*hostToUpdate->maxLatency.tv_sec;
	c = theSession->nwLatency.tv_usec + 1000*theSession->nwLatency.tv_sec;
	
	if(a > c) {
	  hostToUpdate->minLatency.tv_usec = theSession->nwLatency.tv_usec;
	  hostToUpdate->minLatency.tv_sec  = theSession->nwLatency.tv_sec;
	}

	if(b < c) {
	  hostToUpdate->maxLatency.tv_usec = theSession->nwLatency.tv_usec;
	  hostToUpdate->maxLatency.tv_sec  = theSession->nwLatency.tv_sec;
	}
      }
      
      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      incrementUsageCounter(&srcHost->secHostPkts->establishedTCPConnSent, dstHostIdx, actualDeviceId);
      incrementUsageCounter(&dstHost->secHostPkts->establishedTCPConnRcvd, srcHostIdx, actualDeviceId);
      myGlobals.device[actualDeviceId].numEstablishedTCPConnections++;
    } else if((addedNewEntry == 0)
	      && ((theSession->sessionState == STATE_SYN) || (theSession->sessionState == STATE_SYN_ACK))
	      && (!(tp->th_flags & TH_RST))) {
      /*
	We might have lost a packet so:
	- we cannot calculate latency
	- we don't set the state to initialized
      */

      theSession->nwLatency.tv_sec = theSession->nwLatency.tv_usec = 0;
      theSession->sessionState = STATE_ACTIVE;

      /*
	ntop has no way to know who started the connection
	as the connection already started. Hence we use this simple
	heuristic algorithm:
	if(sport < dport) {
	sport = server;
	srchost = server host;
	}
      */

      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      if(sport > dport) {
	incrementUsageCounter(&srcHost->secHostPkts->establishedTCPConnSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->establishedTCPConnRcvd, srcHostIdx, actualDeviceId);
	/* This simulates a connection establishment */
	incrementUsageCounter(&srcHost->secHostPkts->synPktsSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->synPktsRcvd, srcHostIdx, actualDeviceId);
      } else {
	incrementUsageCounter(&srcHost->secHostPkts->establishedTCPConnRcvd, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->establishedTCPConnSent, srcHostIdx, actualDeviceId);
	/* This simulates a connection establishment */
	incrementUsageCounter(&dstHost->secHostPkts->synPktsSent, srcHostIdx, actualDeviceId);
	incrementUsageCounter(&srcHost->secHostPkts->synPktsRcvd, dstHostIdx, actualDeviceId);
      }

      myGlobals.device[actualDeviceId].numEstablishedTCPConnections++;
    }

       
    /*
     *
     * In this case the session is over hence the list of
     * sessions initiated/received by the hosts can be updated
     *
     */
    if(tp->th_flags & TH_FIN) {
      u_int32_t fin = ntohl(tp->th_seq)+packetDataLength;

      if(sport < dport) /* Server->Client */
	check = (fin != theSession->lastSCFin);
      else /* Client->Server */
	check = (fin != theSession->lastCSFin);

      if(check) {
	/* This is not a duplicated (retransmitted) FIN */
	theSession->finId[theSession->numFin] = fin;
	theSession->numFin = (theSession->numFin+1) % MAX_NUM_FIN;;

	if(sport < dport) /* Server->Client */
	  theSession->lastSCFin = fin;
	else /* Client->Server */
	  theSession->lastCSFin = fin;
	switch(theSession->sessionState) {
	case STATE_ACTIVE:
	  theSession->sessionState = STATE_FIN1_ACK0;
	  break;
	case STATE_FIN1_ACK0:
	  theSession->sessionState = STATE_FIN2_ACK1;
	  break;
	case STATE_FIN1_ACK1:
	  theSession->sessionState = STATE_FIN2_ACK1;
	  break;
#ifdef DEBUG
	default:
	  traceEvent(TRACE_ERROR, "ERROR: unable to handle received FIN (%u) !\n", fin);
#endif
	}
      } else {
#ifdef DEBUG
	printf("Rcvd Duplicated FIN %u\n", fin);
#endif
      }
    } else if(tp->th_flags == TH_ACK) {
      u_int32_t ack = ntohl(tp->th_ack);

      if((ack == theSession->lastAckIdI2R) && (ack == theSession->lastAckIdR2I)) {
	if(theSession->initiatorIdx == srcHostIdx) {
	  theSession->numDuplicatedAckI2R++;
	  theSession->bytesRetranI2R += length;
	  myGlobals.device[actualDeviceId].hash_hostTraffic[theSession->initiatorIdx]->pktDuplicatedAckSent++;
	  myGlobals.device[actualDeviceId].hash_hostTraffic[theSession->remotePeerIdx]->pktDuplicatedAckRcvd++;

#ifdef DEBUG
	  traceEvent(TRACE_INFO, "Duplicated ACK %ld [ACKs=%d/bytes=%d]: ",
		     ack, theSession->numDuplicatedAckI2R,
		     (int)theSession->bytesRetranI2R);
#endif
	} else {
	  theSession->numDuplicatedAckR2I++;
	  theSession->bytesRetranR2I += length;
	  myGlobals.device[actualDeviceId].hash_hostTraffic[theSession->remotePeerIdx]->pktDuplicatedAckSent++;
	  myGlobals.device[actualDeviceId].hash_hostTraffic[theSession->initiatorIdx]->pktDuplicatedAckRcvd++;
#ifdef DEBUG
	  traceEvent(TRACE_INFO, "Duplicated ACK %ld [ACKs=%d/bytes=%d]: ",
		     ack, theSession->numDuplicatedAckR2I,
		     (int)theSession->bytesRetranR2I);
#endif
	}

#ifdef DEBUG
	printf("%s:%d->",
	       myGlobals.device[actualDeviceId].hash_hostTraffic[theSession->initiatorIdx]->hostSymIpAddress,
	       theSession->sport);
   	printf("%s:%d\n",
	       myGlobals.device[actualDeviceId].hash_hostTraffic[theSession->remotePeerIdx]->hostSymIpAddress,
	       theSession->dport);
#endif
      }

      if(theSession->initiatorIdx == srcHostIdx)
	theSession->lastAckIdI2R = ack;
      else
	theSession->lastAckIdR2I = ack;

      if(theSession->numFin > 0) {
	int i;

	if(sport < dport) /* Server->Client */
	  check = (ack != theSession->lastSCAck);
	else /* Client->Server */
	  check = (ack != theSession->lastCSAck);

	if(check) {
	  /* This is not a duplicated ACK */

	  if(sport < dport) /* Server->Client */
	    theSession->lastSCAck = ack;
	  else /* Client->Server */
	    theSession->lastCSAck = ack;

	  for(i=0; i<theSession->numFin; i++) {
	    if((theSession->finId[i]+1) == ack) {
	      theSession->numFinAcked++;
	      theSession->finId[i] = 0;

	      switch(theSession->sessionState) {
	      case STATE_FIN1_ACK0:
		theSession->sessionState = STATE_FIN1_ACK1;
		break;
	      case STATE_FIN2_ACK0:
		theSession->sessionState = STATE_FIN2_ACK1;
		break;
	      case STATE_FIN2_ACK1:
		theSession->sessionState = STATE_FIN2_ACK2;
		break;
#ifdef DEBUG
	      default:
		printf("ERROR: unable to handle received ACK (%u) !\n", ack);
#endif
	      }
	      break;
	    }
	  }
	}
      }
    }

    theSession->lastFlags = tp->th_flags;

    if((theSession->sessionState == STATE_FIN2_ACK2)
       || (tp->th_flags & TH_RST)) /* abortive release */ {
      if(theSession->sessionState == STATE_SYN_ACK) {
	/*
	  Rcvd RST packet before to complete the 3-way handshake.
	  Note that the message is emitted only of the reset is received
	  while in STATE_SYN_ACK. In fact if it has been received in
	  STATE_SYN this message has not to be emitted because this is
	  a rejected session.
	*/
	if(myGlobals.enableSuspiciousPacketDump) {
	  traceEvent(TRACE_WARNING, "WARNING: TCP session [%s:%d]<->[%s:%d] reset by %s "
		     "without completing 3-way handshake",
		     srcHost->hostSymIpAddress, sport,
		     dstHost->hostSymIpAddress, dport,
		     srcHost->hostSymIpAddress);
	  dumpSuspiciousPacket(actualDeviceId);
	}
      }

      theSession->sessionState = STATE_TIMEOUT;      
      updateUsedPorts(srcHost, srcHostIdx, dstHost, dstHostIdx, sport, dport,
		      (u_int)(theSession->bytesSent+theSession->bytesRcvd));
    }

    /* printf("%d\n", theSession->sessionState);  */

    /* ****************************** */

    if(tp->th_flags == (TH_RST|TH_ACK)) {
      /* RST|ACK is sent when a connection is refused */
      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      incrementUsageCounter(&srcHost->secHostPkts->rstAckPktsSent, dstHostIdx, actualDeviceId);
      incrementUsageCounter(&dstHost->secHostPkts->rstAckPktsRcvd, srcHostIdx, actualDeviceId);
    } else if(tp->th_flags & TH_RST) {
      if(((theSession->initiatorIdx == srcHostIdx)
	  && (theSession->lastRem2InitiatorFlags[0] == TH_ACK)
	  && (theSession->bytesSent == 0))
	 || ((theSession->initiatorIdx == dstHostIdx)
	     && (theSession->lastInitiator2RemFlags[0] == TH_ACK)
	     && (theSession->bytesRcvd == 0))) {
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->ackScanRcvd, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->ackScanSent, srcHostIdx, actualDeviceId);
	if(myGlobals.enableSuspiciousPacketDump) {
	  traceEvent(TRACE_WARNING, "WARNING: host [%s:%d] performed ACK scan of host [%s:%d]",
		     dstHost->hostSymIpAddress, dport,
		     srcHost->hostSymIpAddress, sport);
	  dumpSuspiciousPacket(actualDeviceId);
	}
      }
      /* Connection terminated */
      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      incrementUsageCounter(&srcHost->secHostPkts->rstPktsSent, dstHostIdx, actualDeviceId);
      incrementUsageCounter(&dstHost->secHostPkts->rstPktsRcvd, srcHostIdx, actualDeviceId);
    } else if(tp->th_flags == (TH_SYN|TH_FIN)) {
      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      incrementUsageCounter(&srcHost->secHostPkts->synFinPktsSent, dstHostIdx, actualDeviceId);
      incrementUsageCounter(&dstHost->secHostPkts->synFinPktsRcvd, srcHostIdx, actualDeviceId);
    } else if(tp->th_flags == (TH_FIN|TH_PUSH|TH_URG)) {
      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      incrementUsageCounter(&srcHost->secHostPkts->finPushUrgPktsSent, dstHostIdx, actualDeviceId);
      incrementUsageCounter(&dstHost->secHostPkts->finPushUrgPktsRcvd, srcHostIdx, actualDeviceId);
    } else if(tp->th_flags == TH_SYN) {
      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      incrementUsageCounter(&srcHost->secHostPkts->synPktsSent, dstHostIdx, actualDeviceId);
      incrementUsageCounter(&dstHost->secHostPkts->synPktsRcvd, srcHostIdx, actualDeviceId);
    } else if(tp->th_flags == 0x0 /* NULL */) {
      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      incrementUsageCounter(&srcHost->secHostPkts->nullPktsSent, dstHostIdx, actualDeviceId);
      incrementUsageCounter(&dstHost->secHostPkts->nullPktsRcvd, srcHostIdx, actualDeviceId);
    }

    /* **************************** */

    if(myGlobals.enableSuspiciousPacketDump) {
      /*
	For more info about checks below see
	http://www.synnergy.net/Archives/Papers/dethy/host-detection.txt
      */
      if((srcHostIdx == dstHostIdx)
	 /* && (sport == dport)  */ /* Caveat: what about Win NT 3.51 ? */
	 && (tp->th_flags == TH_SYN)) {      
	traceEvent(TRACE_WARNING, "WARNING: detected Land Attack against host %s:%d",
		   srcHost->hostSymIpAddress, sport);
	dumpSuspiciousPacket(actualDeviceId);      
      }

      if(tp->th_flags == (TH_RST|TH_ACK)) {
	if((((theSession->initiatorIdx == srcHostIdx)
	     && (theSession->lastRem2InitiatorFlags[0] == TH_SYN))
	    || ((theSession->initiatorIdx == dstHostIdx)
		&& (theSession->lastInitiator2RemFlags[0] == TH_SYN)))
	   ) {
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&dstHost->secHostPkts->rejectedTCPConnSent, srcHostIdx, actualDeviceId);
	  incrementUsageCounter(&srcHost->secHostPkts->rejectedTCPConnRcvd, dstHostIdx, actualDeviceId);

	  if(myGlobals.enableSuspiciousPacketDump) {
	    traceEvent(TRACE_INFO, "Host %s rejected TCP session from %s [%s:%d]<->[%s:%d] (port closed?)",
		       srcHost->hostSymIpAddress, dstHost->hostSymIpAddress,
		       dstHost->hostSymIpAddress, dport,
		       srcHost->hostSymIpAddress, sport);
	    dumpSuspiciousPacket(actualDeviceId);
	  }
	} else if(((theSession->initiatorIdx == srcHostIdx)
		   && (theSession->lastRem2InitiatorFlags[0] == (TH_FIN|TH_PUSH|TH_URG)))
		  || ((theSession->initiatorIdx == dstHostIdx)
		      && (theSession->lastInitiator2RemFlags[0] == (TH_FIN|TH_PUSH|TH_URG)))) {
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&dstHost->secHostPkts->xmasScanSent, srcHostIdx, actualDeviceId);
	  incrementUsageCounter(&srcHost->secHostPkts->xmasScanRcvd, dstHostIdx, actualDeviceId);

	  if(myGlobals.enableSuspiciousPacketDump) {
	    traceEvent(TRACE_WARNING, "WARNING: host [%s:%d] performed XMAS scan of host [%s:%d]",
		       dstHost->hostSymIpAddress, dport,
		       srcHost->hostSymIpAddress, sport);
	    dumpSuspiciousPacket(actualDeviceId);
	  }
	} else if(((theSession->initiatorIdx == srcHostIdx)
		   && ((theSession->lastRem2InitiatorFlags[0] & TH_FIN) == TH_FIN))
		  || ((theSession->initiatorIdx == dstHostIdx)
		      && ((theSession->lastInitiator2RemFlags[0] & TH_FIN) == TH_FIN))) {
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&dstHost->secHostPkts->finScanSent, srcHostIdx, actualDeviceId);
	  incrementUsageCounter(&srcHost->secHostPkts->finScanRcvd, dstHostIdx, actualDeviceId);

	  if(myGlobals.enableSuspiciousPacketDump) {
	    traceEvent(TRACE_WARNING, "WARNING: host [%s:%d] performed FIN scan of host [%s:%d]",
		       dstHost->hostSymIpAddress, dport,
		       srcHost->hostSymIpAddress, sport);
	    dumpSuspiciousPacket(actualDeviceId);
	  }
	} else if(((theSession->initiatorIdx == srcHostIdx)
		   && (theSession->lastRem2InitiatorFlags[0] == 0)
		   && (theSession->bytesRcvd > 0))
		  || ((theSession->initiatorIdx == dstHostIdx)
		      && ((theSession->lastInitiator2RemFlags[0] == 0))
		      && (theSession->bytesSent > 0))) {
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->nullScanRcvd, dstHostIdx, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->nullScanSent, srcHostIdx, actualDeviceId);

	  if(myGlobals.enableSuspiciousPacketDump) {
	    traceEvent(TRACE_WARNING, "WARNING: host [%s:%d] performed NULL scan of host [%s:%d]",
		       dstHost->hostSymIpAddress, dport,
		       srcHost->hostSymIpAddress, sport);
	    dumpSuspiciousPacket(actualDeviceId);
	  }
	}
      }

      /* **************************** */

      /* Save session flags */
      if(theSession->initiatorIdx == srcHostIdx) {
	int i;

	for(i=0; i<MAX_NUM_STORED_FLAGS-1; i++)
	  theSession->lastInitiator2RemFlags[i+1] =
	    theSession->lastInitiator2RemFlags[i];

	theSession->lastInitiator2RemFlags[0] = tp->th_flags;
      } else {
	int i;

	for(i=0; i<MAX_NUM_STORED_FLAGS-1; i++)
	  theSession->lastRem2InitiatorFlags[i+1] =
	    theSession->lastRem2InitiatorFlags[i];

	theSession->lastRem2InitiatorFlags[0] = tp->th_flags;
      }
    }

    if(flowDirection == CLIENT_TO_SERVER) {
      theSession->bytesProtoSent += packetDataLength;
      theSession->bytesSent      += length;
      theSession->pktSent++;
      if(fragmentedData) theSession->bytesFragmentedSent += packetDataLength;
    } else {
      theSession->bytesProtoRcvd += packetDataLength;
      theSession->bytesRcvd  += length;
      theSession->pktRcvd++;
      if(fragmentedData) theSession->bytesFragmentedRcvd += packetDataLength;
    }

    /* Immediately free the session */
    if(theSession->sessionState == STATE_TIMEOUT) {
      if(myGlobals.device[actualDeviceId].tcpSession[idx] == theSession) {
	myGlobals.device[actualDeviceId].tcpSession[idx] = theSession->next;
      } else {
	prevSession->next = theSession->next;
      }

      freeSession(theSession, actualDeviceId);
      return(NULL);
    }
  } else if(sessionType == IPPROTO_UDP) {
    IPSession tmpSession;

    memset(&tmpSession, 0, sizeof(IPSession));

    updateUsedPorts(srcHost, srcHostIdx, dstHost, dstHostIdx, sport, dport, length);

    tmpSession.lastSeen = myGlobals.actTime;
    tmpSession.initiatorIdx = checkSessionIdx(srcHostIdx),
      tmpSession.remotePeerIdx = checkSessionIdx(dstHostIdx);
    tmpSession.bytesSent = (TrafficCounter)length, tmpSession.bytesRcvd = 0;
    tmpSession.sport = sport, tmpSession.dport = dport;
    if(fragmentedData) tmpSession.bytesFragmentedSent += packetDataLength;

    if(getPortByNum(sport, sessionType) != NULL) {
      updateHostSessionsList(srcHostIdx, sport, dstHostIdx, &tmpSession,
			     sessionType, SERVER_TO_CLIENT, SERVER_ROLE, actualDeviceId);
      tmpSession.bytesSent = 0, tmpSession.bytesRcvd = (TrafficCounter)length;
      updateHostSessionsList(dstHostIdx, sport, srcHostIdx, &tmpSession,
			     sessionType, CLIENT_FROM_SERVER, CLIENT_ROLE, actualDeviceId);
    } else {
      if(myGlobals.isLsofPresent) {
#ifdef MULTITHREADED
	accessMutex(&myGlobals.lsofMutex, "HandleSession-1");
#endif
	myGlobals.updateLsof = 1; /* Force lsof update */
#if defined(MULTITHREADED)
	releaseMutex(&myGlobals.lsofMutex);
#endif
      }
    }

    if(getPortByNum(dport, sessionType) != NULL) {
      updateHostSessionsList(srcHostIdx, dport, dstHostIdx, &tmpSession,
			     sessionType, CLIENT_TO_SERVER, CLIENT_ROLE, actualDeviceId);
      tmpSession.bytesSent = 0, tmpSession.bytesRcvd = (TrafficCounter)length;
      updateHostSessionsList(dstHostIdx, dport, srcHostIdx, &tmpSession,
			     sessionType, SERVER_FROM_CLIENT, SERVER_ROLE, actualDeviceId);
    } else {
      if(myGlobals.isLsofPresent) {
#if defined(MULTITHREADED)
	accessMutex(&myGlobals.lsofMutex, "HandleSession-2");
#endif
	myGlobals.updateLsof = 1; /* Force lsof update */
#if defined(MULTITHREADED)
	releaseMutex(&myGlobals.lsofMutex);
#endif
      }
    }
  }

  if((sport == 7)     || (dport == 7)  /* echo */
     || (sport == 9)  || (dport == 9)  /* discard */
     || (sport == 13) || (dport == 13) /* daytime */
     || (sport == 19) || (dport == 19) /* chargen */
     ) {
    char *fmt = "WARNING: detected traffic [%s:%d] -> [%s:%d] on "
      "a diagnostic port (network mapping attempt?)";

    if(myGlobals.enableSuspiciousPacketDump) {
      traceEvent(TRACE_WARNING, fmt,
		 srcHost->hostSymIpAddress, sport,
		 dstHost->hostSymIpAddress, dport);
      dumpSuspiciousPacket(actualDeviceId);
    }

    if((dport == 7)
       || (dport == 9)
       || (dport == 13)
       || (dport == 19)) {
      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      if(sessionType == IPPROTO_UDP) {
	incrementUsageCounter(&srcHost->secHostPkts->udpToDiagnosticPortSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->udpToDiagnosticPortRcvd, srcHostIdx, actualDeviceId);
      } else {
	incrementUsageCounter(&srcHost->secHostPkts->tcpToDiagnosticPortSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->tcpToDiagnosticPortRcvd, srcHostIdx, actualDeviceId);
      }
    } else /* sport == 7 */ {
      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      if(sessionType == IPPROTO_UDP) {
	incrementUsageCounter(&srcHost->secHostPkts->udpToDiagnosticPortSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->udpToDiagnosticPortRcvd, srcHostIdx, actualDeviceId);
      } else {
	incrementUsageCounter(&srcHost->secHostPkts->tcpToDiagnosticPortSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->tcpToDiagnosticPortRcvd, srcHostIdx, actualDeviceId);
      }
    }
  }

  if(fragmentedData && (packetDataLength <= 128)) {
    char *fmt = "WARNING: detected tiny fragment (%d bytes) "
      "[%s:%d] -> [%s:%d] (network mapping attempt?)";
    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    incrementUsageCounter(&srcHost->secHostPkts->tinyFragmentSent, dstHostIdx, actualDeviceId);
    incrementUsageCounter(&dstHost->secHostPkts->tinyFragmentRcvd, srcHostIdx, actualDeviceId);
    if(myGlobals.enableSuspiciousPacketDump) {
      traceEvent(TRACE_WARNING, fmt, packetDataLength,
		 srcHost->hostSymIpAddress, sport,
		 dstHost->hostSymIpAddress, dport);
      dumpSuspiciousPacket(actualDeviceId);
    }
  }

  return(theSession);
}

/* ************************************ */

#ifndef WIN32
static void addLsofContactedPeers(ProcessInfo *process,
				  u_int peerHostIdx, int actualDeviceId) {
  u_int i;

  if((process == NULL)
     || (peerHostIdx == NO_PEER)
     || broadcastHost(myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(peerHostIdx)]))
    return;

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
    if(process->contactedIpPeersIndexes[i] == peerHostIdx)
      return;

  process->contactedIpPeersIndexes[process->contactedIpPeersIdx] = peerHostIdx;
  process->contactedIpPeersIdx = (process->contactedIpPeersIdx+1) % MAX_NUM_CONTACTED_PEERS;
}
#endif /* WIN32 */

/* ************************************ */

#ifndef WIN32
static void handleLsof(u_int srcHostIdx,
		       u_short sport,
		       u_int dstHostIdx,
		       u_short dport,
		       u_int length, 
		       int actualDeviceId) {
  HostTraffic *srcHost, *dstHost;

#ifdef MULTITHREADED
  accessMutex(&myGlobals.lsofMutex, "readLsofInfo-3");
#endif

  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];

  if(subnetLocalHost(srcHost))
    if((sport < TOP_IP_PORT) && (myGlobals.localPorts[sport] != NULL)) {
      ProcessInfoList *scanner = myGlobals.localPorts[sport];

      while(scanner != NULL) {
	scanner->element->bytesSent += length;
	scanner->element->lastSeen   = myGlobals.actTime;
	addLsofContactedPeers(scanner->element, dstHostIdx, actualDeviceId);
	scanner = scanner->next;
      }
    }

  if(subnetLocalHost(dstHost))
    if((dport < TOP_IP_PORT) && (myGlobals.localPorts[dport] != NULL)) {
      ProcessInfoList *scanner = myGlobals.localPorts[dport];

      while(scanner != NULL) {
	scanner->element->bytesRcvd += length;
	scanner->element->lastSeen   = myGlobals.actTime;
	addLsofContactedPeers(scanner->element, srcHostIdx, actualDeviceId);
	scanner = scanner->next;
      }
    }
#ifdef MULTITHREADED
  releaseMutex(&myGlobals.lsofMutex);
#endif
}
#endif /* WIN32*/

/* *********************************** */

IPSession* handleTCPSession(const struct pcap_pkthdr *h,
			    u_short fragmentedData,
			    u_int tcpWin,
			    u_int srcHostIdx,
			    u_short sport,
			    u_int dstHostIdx,
			    u_short dport,
			    u_int length,
			    struct tcphdr *tp,
			    u_int tcpDataLength,
			    u_char* packetData, 
			    int actualDeviceId) {
  IPSession* theSession;

  theSession = handleSession(h, fragmentedData, tcpWin,
			     srcHostIdx, sport,
			     dstHostIdx, dport,
			     length, tp,
			     tcpDataLength, packetData, 
			     actualDeviceId);

#ifndef WIN32
  if(myGlobals.isLsofPresent)
    handleLsof(srcHostIdx, sport, dstHostIdx, dport, length, actualDeviceId);
#endif

  return(theSession);
}

/* ************************************ */

IPSession* handleUDPSession(const struct pcap_pkthdr *h,
			    u_short fragmentedData,
			    u_int srcHostIdx,
			    u_short sport,
			    u_int dstHostIdx,
			    u_short dport,
			    u_int length,
			    u_char* packetData,
			    int actualDeviceId) {
  IPSession* theSession;

  theSession = handleSession(h, fragmentedData, 0,
			     srcHostIdx, sport,
			     dstHostIdx, dport, length,
			     NULL, length, packetData, actualDeviceId);
  
#ifndef WIN32  
  if(myGlobals.isLsofPresent)
    handleLsof(srcHostIdx, sport, dstHostIdx, dport, length, actualDeviceId);
#endif

  return(theSession);
}

/* ******************* */

void handlePluginSessionTermination(IPSession *sessionToPurge, int actualDeviceId) {
#ifdef SESSION_PLUGIN
  FlowFilterList *flows = myGlobals.flowsList;

  while(flows != NULL) {
    if((flows->pluginStatus.pluginPtr != NULL)
       && (flows->pluginStatus.pluginPtr->sessionFunct != NULL)
       && (!flows->pluginStatus.activePlugin)) {
      flows->pluginStatus.pluginPtr->sessionFunct(sessionToPurge, actualDeviceId);
    }
    
    flows = flows->next;
  }
#endif

  sendTCPSessionFlow(sessionToPurge, actualDeviceId);
  notifyTCPSession(sessionToPurge, actualDeviceId);
}

