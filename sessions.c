/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
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

/* #define SESSION_TRACE_DEBUG 1 */

/* ************************************ */

u_int _checkSessionIdx(u_int idx, int actualDeviceId, char* file, int line) {
  if(idx > myGlobals.device[actualDeviceId].actualHashSize) {
    traceEvent(CONST_TRACE_ERROR, "Index error idx=%u/deviceId=%d:0-%d @ [%s:%d]",
	       idx, actualDeviceId,
	       myGlobals.device[actualDeviceId].actualHashSize-1,
	       file, line);
    return(0); /* Last resort */
  } else
    return(idx);
}

/* ************************************ */

void updatePortList(HostTraffic *theHost, int clientPort, int serverPort) {
  if(theHost == NULL) return;

  if(clientPort >= 0)
    addPortToList(theHost, theHost->recentlyUsedClientPorts, clientPort);

  if(serverPort >= 0)
    addPortToList(theHost, theHost->recentlyUsedServerPorts, serverPort);
}

/* ************************************ */

static void updateHTTPVirtualHosts(char *virtualHostName,
				   HostTraffic *theRemHost,
				   TrafficCounter bytesSent, TrafficCounter bytesRcvd) {

  if(virtualHostName != NULL) {
    VirtualHostList *list;
    int numEntries = 0;

    if(theRemHost->protocolInfo == NULL) {
      theRemHost->protocolInfo = (ProtocolInfo*)malloc(sizeof(ProtocolInfo));
      memset(theRemHost->protocolInfo, 0, sizeof(ProtocolInfo));
    }

    list = theRemHost->protocolInfo->httpVirtualHosts;

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "updateHTTPVirtualHosts: %s for host %s [s=%u,r=%u]",
	       virtualHostName, theRemHost->hostNumIpAddress,
	       (unsigned int)bytesSent.value, (unsigned int)bytesRcvd.value);
#endif

    while(list != NULL) {
      if(strcmp(list->virtualHostName, virtualHostName) == 0) {
	incrementTrafficCounter(&list->bytesSent, bytesSent.value),
	  incrementTrafficCounter(&list->bytesRcvd, bytesRcvd.value);
	break;
      } else {
	list = list->next;
	numEntries++;
      }
    }

    if((list == NULL) && (numEntries < MAX_NUM_LIST_ENTRIES)) {
      list = (VirtualHostList*)malloc(sizeof(VirtualHostList));
      list->virtualHostName = strdup(virtualHostName);
      list->bytesSent = bytesSent, list->bytesRcvd = bytesRcvd;
      list->next = theRemHost->protocolInfo->httpVirtualHosts;
      theRemHost->protocolInfo->httpVirtualHosts = list;
    }
  }
}

/* ************************************ */

static void updateFileList(char *fileName, u_char upDownloadMode, HostTraffic *theRemHost) {
  if(fileName != NULL) {
    FileList *list, *lastPtr = NULL;
    int numEntries = 0;

    if(theRemHost->protocolInfo == NULL) theRemHost->protocolInfo = calloc(1, sizeof(ProtocolInfo));
    list = theRemHost->protocolInfo->fileList;

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "updateFileList: %s for host %s",
	       fileName, theRemHost->hostNumIpAddress);
#endif

    while(list != NULL) {
      if(strcmp(list->fileName, fileName) == 0) {
	FD_SET(upDownloadMode, &list->fileFlags);
	return;
      } else {
	lastPtr = list;
	list = list->next;
	numEntries++;
      }
    }

    if(list == NULL) {
      list = (FileList*)malloc(sizeof(FileList));
      list->fileName = strdup(fileName);
      FD_ZERO(&list->fileFlags);
      FD_SET(upDownloadMode, &list->fileFlags);
      list->next = NULL;

      if(numEntries >= MAX_NUM_LIST_ENTRIES) {
	FileList *ptr = theRemHost->protocolInfo->fileList->next;

	lastPtr->next = list; /* Append */
	/* Free the first entry */
	free(theRemHost->protocolInfo->fileList->fileName);
	free(theRemHost->protocolInfo->fileList);
	/* The first ptr points to the second element */
	theRemHost->protocolInfo->fileList = ptr;
      } else {
	list->next = theRemHost->protocolInfo->fileList;
	theRemHost->protocolInfo->fileList = list;
      }
    }
  }
}

/* ************************************ */

void updateHostUsers(char *userName, int userType, HostTraffic *theHost) {
  int i;

  if(userName[0] == '\0') return;

  /* Convert to lowercase */
  for(i=strlen(userName)-1; i>=0; i--) userName[i] = tolower(userName[i]);

  if(isSMTPhost(theHost)) {
    /*
      If this is a SMTP server the local users are
      not really meaningful
    */

    if((theHost->protocolInfo != NULL)
       && (theHost->protocolInfo->userList != NULL)) {
      UserList *list = theHost->protocolInfo->userList;

      /*
	It might be that ntop added users before it
	realized this host was a SMTP server. They must
	be removed.
      */

      while(list != NULL) {
	UserList *next = list->next;

	free(list->userName);
	free(list);
	list = next;
      }

      theHost->protocolInfo->userList = NULL;
    }

    return; /* That's all for now */
  }

  if(userName != NULL) {
    UserList *list;
    int numEntries = 0;

    if(theHost->protocolInfo == NULL) theHost->protocolInfo = calloc(1, sizeof(ProtocolInfo));
    list = theHost->protocolInfo->userList;

    while(list != NULL) {
      if(strcmp(list->userName, userName) == 0) {
	FD_SET(userType, &list->userFlags);
	return; /* Nothing to do: this user is known */
      } else {
	list = list->next;
	numEntries++;
      }
    }

    if((list == NULL) && (numEntries < MAX_NUM_LIST_ENTRIES)) {
      list = (UserList*)malloc(sizeof(UserList));
      list->userName = strdup(userName);
      list->next = theHost->protocolInfo->userList;
      FD_ZERO(&list->userFlags);
      FD_SET(userType, &list->userFlags);
      theHost->protocolInfo->userList = list;
    }
  }
}

/* ************************************ */

void updateUsedPorts(HostTraffic *srcHost,
		     HostTraffic *dstHost,
		     u_short sport,
		     u_short dport,
		     u_int length) {
  u_short clientPort, serverPort;
  PortUsage *ports;
  int sport_idx = mapGlobalToLocalIdx(sport);
  int dport_idx = mapGlobalToLocalIdx(dport);

  /* Now let's update the list of ports recently used by the hosts */
  if((sport > dport) || broadcastHost(dstHost)) {
    clientPort = sport, serverPort = dport;

    if(sport_idx == -1) addPortToList(srcHost, srcHost->otherIpPortsSent, sport);
    if(dport_idx == -1) addPortToList(dstHost, dstHost->otherIpPortsRcvd, dport);

    if(srcHost != myGlobals.otherHostEntry)
      updatePortList(srcHost, clientPort, -1);
    if(dstHost != myGlobals.otherHostEntry)
      updatePortList(dstHost, -1, serverPort);
  } else {
    clientPort = dport, serverPort = sport;

    if(srcHost != myGlobals.otherHostEntry)
      updatePortList(srcHost, -1, serverPort);
    if(dstHost != myGlobals.otherHostEntry)
      updatePortList(dstHost, clientPort, -1);
  }

  /* **************** */

  if(/* (srcHost == dstHost) || */
     broadcastHost(srcHost) || broadcastHost(dstHost))
    return;

  if(sport < MAX_ASSIGNED_IP_PORTS) {
    ports = getPortsUsage(srcHost, sport, 1);

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Adding svr peer %u", dstHost->hostTrafficBucket);
#endif

    incrementTrafficCounter(&ports->serverTraffic, length);
    ports->serverUses++, ports->serverUsesLastPeer = dstHost->hostSerial;

    ports = getPortsUsage(dstHost, sport, 1);

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Adding client peer %u", dstHost->hostTrafficBucket);
#endif

    incrementTrafficCounter(&ports->clientTraffic, length);
    ports->clientUses++, ports->clientUsesLastPeer = srcHost->hostSerial;
  }

  if(dport < MAX_ASSIGNED_IP_PORTS) {
    ports = getPortsUsage(srcHost, dport, 1);

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Adding client peer %u", dstHost->hostTrafficBucket);
#endif

    incrementTrafficCounter(&ports->clientTraffic, length);
    ports->clientUses++, ports->clientUsesLastPeer = dstHost->hostSerial;

    ports = getPortsUsage(dstHost, dport, 1);

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Adding svr peer %u", srcHost->hostTrafficBucket);
#endif

    incrementTrafficCounter(&ports->serverTraffic, length);
    ports->serverUses++, ports->serverUsesLastPeer = srcHost->hostSerial;
  }
}

/* ************************************ */

void freeSession(IPSession *sessionToPurge, int actualDeviceId,
		 u_char allocateMemoryIfNeeded,
		 u_char lockMutex /* unused so far */) {
  /* Session to purge */

  if(sessionToPurge->magic != CONST_MAGIC_NUMBER) {
    traceEvent(CONST_TRACE_ERROR, "===> Magic assertion failed (5)");
    return;
  }

  if((sessionToPurge->initiator == NULL) || (sessionToPurge->remotePeer == NULL)) {
    traceEvent(CONST_TRACE_ERROR, "Either initiator or remote peer is NULL");
    return;
  } else {
    sessionToPurge->initiator->numHostSessions--, sessionToPurge->remotePeer->numHostSessions--;
  }

  if(((sessionToPurge->bytesProtoSent.value == 0)
      || (sessionToPurge->bytesProtoRcvd.value == 0))
     && ((sessionToPurge->nwLatency.tv_sec != 0) || (sessionToPurge->nwLatency.tv_usec != 0))
     /*
       "Valid" TCP session used to skip faked sessions (e.g. portscans
       with one faked packet + 1 response [RST usually])
     */
     ) {
    HostTraffic *theHost, *theRemHost;
    char *fmt = "Detected TCP connection with no data exchanged "
      "[%s:%d] -> [%s:%d] (pktSent=%d/pktRcvd=%d) (network mapping attempt?)";

    theHost = sessionToPurge->initiator, theRemHost = sessionToPurge->remotePeer;

    if((theHost != NULL) && (theRemHost != NULL) && allocateMemoryIfNeeded) {
      allocateSecurityHostPkts(theHost);
      incrementUsageCounter(&theHost->secHostPkts->closedEmptyTCPConnSent, theRemHost, actualDeviceId);
      incrementUsageCounter(&theHost->secHostPkts->terminatedTCPConnServer, theRemHost, actualDeviceId);

      allocateSecurityHostPkts(theRemHost);
      incrementUsageCounter(&theRemHost->secHostPkts->closedEmptyTCPConnRcvd, theHost, actualDeviceId);
      incrementUsageCounter(&theRemHost->secHostPkts->terminatedTCPConnClient, theHost, actualDeviceId);

      incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.closedEmptyTCPConn, 1);
      incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.terminatedTCPConn, 1);

      if(myGlobals.runningPref.enableSuspiciousPacketDump)
	traceEvent(CONST_TRACE_WARNING, fmt,
		   theHost->hostResolvedName, sessionToPurge->sport,
		   theRemHost->hostResolvedName, sessionToPurge->dport,
		   sessionToPurge->pktSent, sessionToPurge->pktRcvd);
    }
  }

#ifdef SESSION_TRACE_DEBUG
  {
    char buf[32], buf1[32];

    traceEvent(CONST_TRACE_INFO, "SESSION_TRACE_DEBUG: Session terminated: %s:%d<->%s:%d (lastSeend=%d) (# sessions = %d)",
	       _addrtostr(&sessionToPurge->initiatorRealIp, buf, sizeof(buf)), sessionToPurge->sport,
	       _addrtostr(&sessionToPurge->remotePeerRealIp, buf1, sizeof(buf1)), sessionToPurge->dport,
	       sessionToPurge->lastSeen,  myGlobals.device[actualDeviceId].numTcpSessions);
  }
#endif

  /*
   * Having updated the session information, 'theSession'
   * can now be purged.
   */
  sessionToPurge->magic = 0;

  if(sessionToPurge->virtualPeerName != NULL)
    free(sessionToPurge->virtualPeerName);

  if(sessionToPurge->session_info != NULL)
    free(sessionToPurge->session_info);

  myGlobals.numTerminatedSessions++;
  myGlobals.device[actualDeviceId].numTcpSessions--;

#ifdef PARM_USE_SESSIONS_CACHE
  /* Memory recycle */
  if(myGlobals.sessionsCacheLen < (MAX_SESSIONS_CACHE_LEN-1)) {
    myGlobals.sessionsCache[myGlobals.sessionsCacheLen++] = sessionToPurge;
    if (myGlobals.sessionsCacheLen > myGlobals.sessionsCacheLenMax)
        myGlobals.sessionsCacheLenMax = myGlobals.sessionsCacheLen;
  } else {
    /* No room left: it's time to free the bucket */
    free(sessionToPurge); /* No inner pointers to free */
  }
#else
  free(sessionToPurge);
#endif
}

/* ************************************ */

/* ************************************ */

void freeFcSession(FCSession *sessionToPurge, int actualDeviceId,
                   u_char allocateMemoryIfNeeded,
                   u_char lockMutex /* unused so far */)
{
    int i;

    /* Session to purge */

    if(sessionToPurge->magic != CONST_MAGIC_NUMBER) {
        traceEvent(CONST_TRACE_ERROR, "===> Magic assertion failed (5)");
        return;
    }

    if((sessionToPurge->initiator == NULL) || (sessionToPurge->remotePeer == NULL)) {
        traceEvent(CONST_TRACE_ERROR, "Either initiator or remote peer is NULL");
        return;
    } else {
        sessionToPurge->initiator->numHostSessions--, sessionToPurge->remotePeer->numHostSessions--;
    }

    for (i = 0; i < MAX_LUNS_SUPPORTED; i++) {
        if (sessionToPurge->activeLuns[i] != NULL) {
            free (sessionToPurge->activeLuns[i]);
        }
    }
    /*
     * Having updated the session information, 'theSession'
     * can now be purged.
     */
    sessionToPurge->magic = 0;

    myGlobals.numTerminatedSessions++;
    myGlobals.device[actualDeviceId].numFcSessions--;

#ifdef PARM_USE_SESSIONS_CACHE
    /* Memory recycle */
    if(myGlobals.sessionsCacheLen < (MAX_SESSIONS_CACHE_LEN-1)) {
        myGlobals.sessionsCache[myGlobals.sessionsCacheLen++] = sessionToPurge;
        if (myGlobals.sessionsCacheLen > myGlobals.sessionsCacheLenMax)
            myGlobals.sessionsCacheLenMax = myGlobals.sessionsCacheLen;
    } else {
        /* No room left: it's time to free the bucket */
        free(sessionToPurge); /* No inner pointers to free */
    }
#else
    free(sessionToPurge);
#endif
}

/* ************************************ */

/*
  Description:
  This function is called periodically to free
  those sessions that have been inactive for
  too long.
*/

/* #define DEBUG */

void scanTimedoutTCPSessions(int actualDeviceId) {
  u_int _idx, freeSessionCount=0, purgeLimit;
  static u_int idx = 0;

  /* Patch below courtesy of "Kouprie, Robbert" <R.Kouprie@DTO.TUDelft.NL> */
     if((!myGlobals.runningPref.enableSessionHandling)
	|| (myGlobals.device[actualDeviceId].tcpSession == NULL)
	|| (myGlobals.device[actualDeviceId].numTcpSessions == 0))
     return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Called scanTimedoutTCPSessions (device=%d, sessions=%d)",
	     actualDeviceId, myGlobals.device[actualDeviceId].numTcpSessions);
#endif

  purgeLimit = myGlobals.device[actualDeviceId].numTcpSessions/2;

  for(_idx=0; _idx<MAX_TOT_NUM_SESSIONS; _idx++) {
    IPSession *nextSession, *prevSession, *theSession;

    idx = (idx + 1) % MAX_TOT_NUM_SESSIONS;

    if(freeSessionCount > purgeLimit) break;

    prevSession = theSession = myGlobals.device[actualDeviceId].tcpSession[idx];

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.tcpSessionsMutex, "purgeIdleHosts");
#endif

    while(theSession != NULL) {
      if(theSession->magic != CONST_MAGIC_NUMBER) {
	theSession = NULL;
	myGlobals.device[actualDeviceId].numTcpSessions--;
	traceEvent(CONST_TRACE_ERROR, "===> Magic assertion failed!");
	continue;
      }

      nextSession = theSession->next;

      if(((theSession->sessionState == FLAG_STATE_TIMEOUT)
	  && ((theSession->lastSeen+CONST_TWO_MSL_TIMEOUT) < myGlobals.actTime))
	 || /* The branch below allows to flush sessions which have not been
	       terminated properly (we've received just one FIN (not two). It might be
	       that we've lost some packets (hopefully not). */
	 ((theSession->sessionState >= FLAG_STATE_FIN1_ACK0)
	  && ((theSession->lastSeen+CONST_DOUBLE_TWO_MSL_TIMEOUT) < myGlobals.actTime))
	 /* The line below allows to avoid keeping very old sessions that
	    might be still open, but that are probably closed and we've
	    lost some packets */
	 || ((theSession->lastSeen+PARM_HOST_PURGE_MINIMUM_IDLE_ACTVSES) < myGlobals.actTime)
	 || ((theSession->lastSeen+PARM_SESSION_PURGE_MINIMUM_IDLE) < myGlobals.actTime)
	 /* Purge sessions that are not yet active and that have not completed
	    the 3-way handshave within 1 minute */
	 || ((theSession->sessionState < FLAG_STATE_ACTIVE) && ((theSession->lastSeen+60) < myGlobals.actTime))
	 /* Purge active sessions where one of the two peers has not sent any data
	    (it might be that ntop has created the session bucket because it has
	    thought that the session was already started) since 120 seconds */
	 || ((theSession->sessionState >= FLAG_STATE_ACTIVE)
	     && ((theSession->bytesSent.value == 0) || (theSession->bytesRcvd.value == 0))
	     && ((theSession->lastSeen+120) < myGlobals.actTime))
	 ) {

	if(myGlobals.device[actualDeviceId].tcpSession[idx] == theSession) {
	  myGlobals.device[actualDeviceId].tcpSession[idx] = nextSession;
	  prevSession = myGlobals.device[actualDeviceId].tcpSession[idx];
	} else
	  prevSession->next = nextSession;

	freeSessionCount++;
	freeSession(theSession, actualDeviceId, 1, 0 /* locked by the purge thread */);
	theSession = prevSession;
      } else /* This session will NOT be freed */ {
	prevSession = theSession;
	theSession = nextSession;
      }
    } /* while */
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.tcpSessionsMutex);
#endif
  } /* end for */

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: scanTimedoutTCPSessions: freed %u sessions", freeSessionCount);
#endif
}

/* #undef DEBUG */

/* *********************************** */

static void handleFTPSession(const struct pcap_pkthdr *h,
			     HostTraffic *srcHost, u_short sport,
			     HostTraffic *dstHost, u_short dport,
			     u_int packetDataLength, u_char* packetData,
			     IPSession *theSession,
			     int actualDeviceId) {
  char *rcStr;

  if(sport == IP_TCP_PORT_FTP)
    FD_SET(FLAG_HOST_TYPE_SVC_FTP, &srcHost->flags);
  else
    FD_SET(FLAG_HOST_TYPE_SVC_FTP, &dstHost->flags);

  if(((theSession->bytesProtoRcvd.value < 64)
      || (theSession->bytesProtoSent.value < 64))
     /* The sender name is sent at the beginning of the communication */
     && (packetDataLength > 7)) {
    if ((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
      traceEvent (CONST_TRACE_WARNING, "handleFTPSession: Unable to "
		  "allocate memory, FTP Session handling incomplete\n");
      return;
    }

    memcpy(rcStr, packetData, packetDataLength);
    rcStr[packetDataLength-2] = '\0';

    if((strncmp(rcStr, "USER ", 5) == 0) && strcmp(&rcStr[5], "anonymous")) {
      if(sport == 21)
	updateHostUsers(&rcStr[5], BITFLAG_FTP_USER, dstHost);
      else
	updateHostUsers(&rcStr[5], BITFLAG_FTP_USER, srcHost);

#ifdef FTP_DEBUG
      printf("FTP_DEBUG: %s:%d->%s:%d [%s]\n",
	     srcHost->hostNumIpAddress, sport, dstHost->hostNumIpAddress, dport,
	     &rcStr[5]);
#endif
    }

    free(rcStr);
  }
}

/* *********************************** */

static void handleSMTPSession (const struct pcap_pkthdr *h,
                               HostTraffic *srcHost, u_short sport,
                               HostTraffic *dstHost, u_short dport,
                               u_int packetDataLength, u_char* packetData,
                               IPSession *theSession, int actualDeviceId) {
  char *rcStr;

  if(sport == IP_TCP_PORT_SMTP)
    FD_SET(FLAG_HOST_TYPE_SVC_SMTP, &srcHost->flags);
  else
    FD_SET(FLAG_HOST_TYPE_SVC_SMTP, &dstHost->flags);

  if(((theSession->bytesProtoRcvd.value < 64)
      || (theSession->bytesProtoSent.value < 64))
     /* The sender name is sent at the beginning of the communication */
     && (packetDataLength > 7)) {
    int beginIdx = 11, i;

    if ((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
      traceEvent (CONST_TRACE_WARNING, "handleSMTPSession: Unable to "
		  "allocate memory, SMTP Session handling incomplete\n");
      return;
    }
    memcpy(rcStr, packetData, packetDataLength-1);
    rcStr[packetDataLength-1] = '\0';

#ifdef SMTP_DEBUG
    traceEvent (CONST_TRACE_INFO, "SMTP: %s", rcStr);
#endif

    if(strncasecmp(rcStr, "MAIL FROM:", 10) == 0) {
      if(iscntrl(rcStr[strlen(rcStr)-1])) rcStr[strlen(rcStr)-1] = '\0';
      rcStr[strlen(rcStr)-1] = '\0';
      if(rcStr[beginIdx] == '<') beginIdx++;

      i=beginIdx+1;
      while(rcStr[i] != '\0') {
	if(rcStr[i] == '>') {
	  rcStr[i] = '\0';
	  break;
	}

	i++;
      }

      if(sport == 25)
	updateHostUsers(&rcStr[beginIdx], BITFLAG_SMTP_USER, dstHost);
      else
	updateHostUsers(&rcStr[beginIdx], BITFLAG_SMTP_USER, srcHost);

#ifdef SMTP_DEBUG
      printf("SMTP_DEBUG: %s:%d->%s:%d [%s]\n",
	     srcHost->hostNumIpAddress, sport, dstHost->hostNumIpAddress, dport,
	     &rcStr[beginIdx]);
#endif
    }

    free(rcStr);
  }
}

/* *********************************** */

static void handlePOPSession (const struct pcap_pkthdr *h,
                              HostTraffic *srcHost, u_short sport,
                              HostTraffic *dstHost, u_short dport,
                              u_int packetDataLength, u_char* packetData,
                              IPSession *theSession, int actualDeviceId) {
  char *rcStr;

  if((sport == IP_TCP_PORT_POP2) || (sport == IP_TCP_PORT_POP3))
    FD_SET(FLAG_HOST_TYPE_SVC_POP, &srcHost->flags);
  else
    FD_SET(FLAG_HOST_TYPE_SVC_POP, &dstHost->flags);

  if(((theSession->bytesProtoRcvd.value < 64)
      || (theSession->bytesProtoSent.value < 64)) /* The user name is sent at the beginning of the communication */
     && (packetDataLength > 4)) {

    if ((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
      traceEvent (CONST_TRACE_WARNING, "handlePOPSession: Unable to "
		  "allocate memory, POP Session handling incomplete\n");
      return;
    }
    memcpy(rcStr, packetData, packetDataLength);
    rcStr[packetDataLength-1] = '\0';

    if(strncmp(rcStr, "USER ", 5) == 0) {
      if(iscntrl(rcStr[strlen(rcStr)-1])) rcStr[strlen(rcStr)-1] = '\0';
      if((sport == 109) || (sport == 110))
	updateHostUsers(&rcStr[5], BITFLAG_POP_USER, dstHost);
      else
	updateHostUsers(&rcStr[5], BITFLAG_POP_USER, srcHost);

#ifdef POP_DEBUG
      printf("POP_DEBUG: %s->%s [%s]\n",
	     srcHost->hostNumIpAddress, dstHost->hostNumIpAddress,
	     &rcStr[5]);
#endif
    }

    free(rcStr);
  }
}

/* *********************************** */

static void handleIMAPSession (const struct pcap_pkthdr *h,
                               HostTraffic *srcHost, u_short sport,
                               HostTraffic *dstHost, u_short dport,
                               u_int packetDataLength, u_char* packetData,
                               IPSession *theSession, int actualDeviceId) {
  char *rcStr;

  if(sport == IP_TCP_PORT_IMAP)
    FD_SET(FLAG_HOST_TYPE_SVC_IMAP, &srcHost->flags);
  else
    FD_SET(FLAG_HOST_TYPE_SVC_IMAP, &dstHost->flags);

  if(((theSession->bytesProtoRcvd.value < 64)
      || (theSession->bytesProtoSent.value < 64))
     /* The sender name is sent at the beginning of the communication */
     && (packetDataLength > 7)) {

    if ((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
      traceEvent (CONST_TRACE_WARNING, "handleIMAPSession: Unable to "
		  "allocate memory, IMAP Session handling incomplete\n");
      return;
    }
    memcpy(rcStr, packetData, packetDataLength);
    rcStr[packetDataLength-1] = '\0';

    if(strncmp(rcStr, "2 login ", 8) == 0) {
      int beginIdx = 10;

      while(rcStr[beginIdx] != '\0') {
	if(rcStr[beginIdx] == '\"') {
	  rcStr[beginIdx] = '\0';
	  break;
	}
	beginIdx++;
      }

      if(sport == 143)
	updateHostUsers(&rcStr[9], BITFLAG_IMAP_USER, dstHost);
      else
	updateHostUsers(&rcStr[9], BITFLAG_IMAP_USER, srcHost);

#ifdef IMAP_DEBUG
      printf("IMAP_DEBUG: %s:%d->%s:%d [%s]\n",
	     srcHost->hostNumIpAddress, sport, dstHost->hostNumIpAddress, dport,
	     &rcStr[9]);
#endif
    }

    free(rcStr);
  }
}

/* *********************************** */

#define SIP_INVITE        "INVITE" /* User Info */
#define SIP_OK            "SIP/2.0 200 Ok" /* Stream Info */

static void handleSIPSession(const struct pcap_pkthdr *h,
			     HostTraffic *srcHost, u_short sport,
			     HostTraffic *dstHost, u_short dport,
			     u_int packetDataLength, u_char* packetData,
			     IPSession *theSession, int actualDeviceId) {
  char *rcStr;

  if(packetDataLength > 64) {
    if((!strncasecmp((char*)packetData, SIP_INVITE, strlen(SIP_INVITE)))
       || (!strncasecmp((char*)packetData, SIP_OK, strlen(SIP_OK)))) {
      char *row, *strtokState, *from = NULL, *to = NULL,
	*server = NULL, *audio = NULL, *video = NULL;

      if((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
	traceEvent(CONST_TRACE_WARNING, "handleSIPSession: Unable to "
		   "allocate memory, SIP Session handling incomplete\n");
	return;
      }

      memcpy(rcStr, packetData, packetDataLength);
      rcStr[packetDataLength-1] = '\0';

      if(0) {
	traceEvent(CONST_TRACE_WARNING, "-------------------------");
	traceEvent(CONST_TRACE_WARNING, rcStr);
	traceEvent(CONST_TRACE_WARNING, "-------------------------");
      }

      row = strtok_r((char*)rcStr, "\r\n", &strtokState);
      while(row != NULL) {
	if((from == NULL)
	   && ((!strncmp(row, "From: ", 6))  || (!strncmp(row, "f: ", 3)))) {
	  from = row;
	} else if((to == NULL)
		  && ((!strncmp(row, "To: ", 4)) || (!strncmp(row, "t: ", 3)))) {
	  to = row;
	} else if((server == NULL) && (!strncmp(row, "Server: ", 8))) {
	  server = row;
	} else if((audio == NULL) && (!strncmp(row, "m=audio ", 8))) {
	  audio = row;
	} else if((video == NULL) && (!strncmp(row, "m=video ", 8))) {
	  video = row;
	}

	row = strtok_r(NULL, "\r\n", &strtokState);
      }

      if(server) {
	strtok_r(server, ":", &strtokState);
	server = strtok_r(NULL, ":", &strtokState);
#ifdef SIP_DEBUG
	traceEvent (CONST_TRACE_WARNING, "Server '%s'", server);
#endif
      }

      if(from && to && (!strncasecmp((char*)packetData, SIP_INVITE, strlen(SIP_INVITE)))) {
	strtok_r(from, ":", &strtokState);
	strtok_r(NULL, ":\"", &strtokState);
	from = strtok_r(NULL, "\"@>", &strtokState);

	strtok_r(to, ":", &strtokState);
	strtok_r(NULL, "\":", &strtokState);
	to = strtok_r(NULL, "\"@>", &strtokState);

#ifdef SIP_DEBUG
	traceEvent (CONST_TRACE_WARNING, "'%s'->'%s'", from, to);
#endif
	updateHostUsers(from, BITFLAG_VOIP_USER, srcHost);
	updateHostUsers(to, BITFLAG_VOIP_USER, dstHost);

	if(theSession->session_info == NULL) {
	  char tmpStr[256];
	  
	  snprintf(tmpStr, sizeof(tmpStr), "%s called %s", from, to);
	  theSession->session_info = strdup(tmpStr);
	}	
      }

      if(audio) {
	strtok_r(audio, " ", &strtokState);
	audio = strtok_r(NULL, " ", &strtokState);
#ifdef SIP_DEBUG
	traceEvent (CONST_TRACE_WARNING, "RTP '%s:%s'", srcHost->hostNumIpAddress, audio);
#endif
	/* FIX: we need to handle IPv6 at some point */
	addVoIPSessionInfo(&srcHost->hostIpAddress, atoi(audio), theSession->session_info);
      }

      if(video) {
	strtok_r(video, " ", &strtokState);
	video = strtok_r(NULL, " ", &strtokState);
#ifdef SIP_DEBUG
	traceEvent (CONST_TRACE_WARNING, "RTP '%s:%s'", srcHost->hostNumIpAddress, video);
#endif
	addVoIPSessionInfo(&srcHost->hostIpAddress, atoi(video), theSession->session_info);
      }

      if(server != NULL)
	FD_SET(FLAG_HOST_TYPE_SVC_VOIP_GATEWAY, &srcHost->flags);
      else
	FD_SET(FLAG_HOST_TYPE_SVC_VOIP_CLIENT, &srcHost->flags);

      free(rcStr);
    }
  }
}

/* *********************************** */

static void handleSCCPSession(const struct pcap_pkthdr *h,
			      HostTraffic *srcHost, u_short sport,
			      HostTraffic *dstHost, u_short dport,
			      u_int packetDataLength, u_char* packetData,
			      IPSession *theSession, int actualDeviceId) {
  char *rcStr;

  if(packetDataLength > 64) {
    u_int16_t message_id;
    /* NOTE: message_id is coded in little endian */
    memcpy(&message_id, &packetData[8], sizeof(message_id)); 
#ifdef CFG_BIG_ENDIAN
    message_id = ntohs(message_id);
#endif


    if((message_id == 0x8F /* CallInfoMessage */)
    && (packetDataLength > 200)) {
      char *calling_party_name, *calling_party;
      char *called_party_name, *called_party;
      char caller[64], called[64];

      if((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
	traceEvent(CONST_TRACE_WARNING, "handleSCCPSession: Unable to "
		   "allocate memory, SCCP Session handling incomplete\n");
	return;
      }

      memcpy(rcStr, packetData, packetDataLength);
      rcStr[packetDataLength-1] = '\0';

      calling_party_name = &rcStr[12];
      calling_party      = &rcStr[12+40];
      called_party_name = &rcStr[12+40+24];
      called_party      = &rcStr[12+40+24+40];

#ifdef SCCP_DEBUG
      traceEvent(CONST_TRACE_WARNING, "SCCP: msg_id='%u'", message_id);
      traceEvent(CONST_TRACE_WARNING, "SCCP: calling_party_name='%s'", calling_party_name);
      traceEvent(CONST_TRACE_WARNING, "SCCP: calling_party='%s'", calling_party);
      traceEvent(CONST_TRACE_WARNING, "SCCP: called_party_name='%s'", called_party_name);
      traceEvent(CONST_TRACE_WARNING, "SCCP: called_party='%s'", called_party);
#endif

      if(calling_party_name[0] != '\0')
	snprintf(caller, sizeof(caller), "%s <%s>", calling_party_name, calling_party);
      else
	snprintf(caller, sizeof(caller), "%s", calling_party);
      
      if(called_party_name[0] != '\0')
	snprintf(called, sizeof(called), "%s <%s>", called_party_name, called_party);
      else
	snprintf(called, sizeof(called), "%s", called_party);

      if(theSession->session_info == NULL) {
	char tmpStr[256];

	snprintf(tmpStr, sizeof(tmpStr), "%s called %s", caller, called);
	theSession->session_info = strdup(tmpStr);
      }

      if(sport == IP_TCP_PORT_SCCP)
	addVoIPSessionInfo(&srcHost->hostIpAddress, sport, theSession->session_info);
      else if(dport == IP_TCP_PORT_SCCP)
	addVoIPSessionInfo(&dstHost->hostIpAddress, dport, theSession->session_info);

      FD_SET(FLAG_HOST_TYPE_SVC_VOIP_GATEWAY, &dstHost->flags);
      FD_SET(FLAG_HOST_TYPE_SVC_VOIP_CLIENT, &srcHost->flags);
      
      updateHostUsers(caller, BITFLAG_VOIP_USER, srcHost);

      free(rcStr);
    }
  }
}

/* *********************************** */

static void handleMsnMsgrSession (const struct pcap_pkthdr *h,
                                  HostTraffic *srcHost, u_short sport,
                                  HostTraffic *dstHost, u_short dport,
                                  u_int packetDataLength, u_char* packetData,
                                  IPSession *theSession, int actualDeviceId) {
  u_char *rcStr;
  char *row;

  if((rcStr = (u_char*)malloc(packetDataLength+1)) == NULL) {
    traceEvent (CONST_TRACE_WARNING, "handleMsnMsgrSession: Unable to "
		"allocate memory, MsnMsgr Session handling incomplete\n");
    return;
  }
  memcpy(rcStr, packetData, packetDataLength);
  rcStr[packetDataLength] = '\0';

  if((dport == IP_TCP_PORT_MSMSGR) && (strncmp((char*)rcStr, "USR 6 TWN I ", 12) == 0)) {
    row = strtok((char*)&rcStr[12], "\n\r");
    if(strstr(row, "@")) {
      /* traceEvent(CONST_TRACE_INFO, "User='%s'@[%s/%s]", row, srcHost->hostResolvedName, srcHost->hostNumIpAddress); */
      updateHostUsers(row, BITFLAG_MESSENGER_USER, srcHost);
    }
  } else if((dport == IP_TCP_PORT_MSMSGR) && (strncmp((char*)rcStr, "ANS 1 ", 6) == 0)) {
    row = strtok((char*)&rcStr[6], " \n\r");
    if(strstr(row, "@")) {
      /* traceEvent(CONST_TRACE_INFO, "User='%s'@[%s/%s]", row, srcHost->hostResolvedName, srcHost->hostNumIpAddress); */
      updateHostUsers(row, BITFLAG_MESSENGER_USER, srcHost);
    }
  } else if((dport == IP_TCP_PORT_MSMSGR) && (strncmp((char*)rcStr, "MSG ", 4) == 0)) {
    row = strtok((char*)&rcStr[4], " ");
    if(strstr(row, "@")) {
      /* traceEvent(CONST_TRACE_INFO, "User='%s' [%s]@[%s->%s]", row, rcStr, srcHost->hostResolvedName, dstHost->hostResolvedName); */
      updateHostUsers(row, BITFLAG_MESSENGER_USER, srcHost);
    }
    free(rcStr);
  }
}

/* *********************************** */

static void handleWinMxSession (const struct pcap_pkthdr *h,
                                HostTraffic *srcHost, u_short sport,
                                HostTraffic *dstHost, u_short dport,
                                u_int packetDataLength, u_char* packetData,
                                IPSession *theSession, int actualDeviceId) {
  u_char *rcStr;

  if (((theSession->bytesProtoSent.value == 3    /* GET */)  &&
       (theSession->bytesProtoRcvd.value <= 1 /* 1 */))
      || ((theSession->bytesProtoSent.value == 4 /* SEND */) &&
	  (theSession->bytesProtoRcvd.value <= 1 /* 1 */))) {
    char *user, *strtokState, *strtokState1, *row, *file;
    int i, begin=0;

    theSession->isP2P = FLAG_P2P_WINMX;

    if ((rcStr = (u_char*)malloc(packetDataLength+1)) == NULL) {
      traceEvent (CONST_TRACE_WARNING, "handleWinMxSession: Unable to "
		  "allocate memory, WINMX Session handling incomplete\n");
      return;
    }
    memcpy(rcStr, packetData, packetDataLength);
    rcStr[packetDataLength] = '\0';

    row = strtok_r((char*)rcStr, "\"", &strtokState);

    if(row != NULL) {
      user = strtok_r(row, "_", &strtokState1);
      file = strtok_r(NULL, "\"", &strtokState);

      if((user != NULL) && (file != NULL)) {
	for(i=0; file[i] != '\0'; i++) {
	  if(file[i] == '\\') begin = i;
	}

	begin++;
	file = &file[begin];
	if(strlen(file) > 64) file[strlen(file)-64] = '\0';

#ifdef P2P_DEBUG
	traceEvent(CONST_TRACE_INFO, "WinMX: %s->%s [%s][%s]",
		   srcHost->hostNumIpAddress,
		   dstHost->hostNumIpAddress,
		   user, file);
#endif

	if(theSession->bytesProtoSent.value == 3) {
	  /* GET */
	  updateFileList(file,  BITFLAG_P2P_DOWNLOAD_MODE, srcHost);
	  updateFileList(file,  BITFLAG_P2P_UPLOAD_MODE,   dstHost);
	  updateHostUsers(user, BITFLAG_P2P_USER, srcHost);
	} else {
	  /* SEND */
	  updateFileList(file,  BITFLAG_P2P_UPLOAD_MODE,   srcHost);
	  updateFileList(file,  BITFLAG_P2P_DOWNLOAD_MODE, dstHost);
	  updateHostUsers(user, BITFLAG_P2P_USER, dstHost);
	}
      }
    }

    free(rcStr);
  }
}

/* *********************************** */

static void handleGnutellaSession(const struct pcap_pkthdr *h,
				  HostTraffic *srcHost, u_short sport,
                                   HostTraffic *dstHost, u_short dport,
                                   u_int packetDataLength, u_char* packetData,
                                   IPSession *theSession, int actualDeviceId) {
  u_char *rcStr, tmpStr[256];

  if(theSession->bytesProtoSent.value == 0) {
    char *strtokState, *row;
    char *theStr = "GET /get/";

    if ((rcStr = (u_char*)malloc(packetDataLength+1)) == NULL) {
      traceEvent (CONST_TRACE_WARNING, "handleGnutellaSession: Unable to "
		  "allocate memory, Gnutella Session handling incomplete\n");
      return;
    }
    memcpy(rcStr, packetData, packetDataLength);
    rcStr[packetDataLength] = '\0';

    if(strncmp((char*)rcStr, theStr, strlen(theStr)) == 0) {
      char *file;
      int i, begin=0;

      row = strtok_r((char*)rcStr, "\n", &strtokState);
      file = &row[strlen(theStr)+1];
      if(strlen(file) > 10) file[strlen(file)-10] = '\0';

      for(i=0; file[i] != '\0'; i++) {
	if(file[i] == '/') begin = i;
      }

      begin++;

      unescape((char*)tmpStr, sizeof(tmpStr), &file[begin]);

#ifdef P2P_DEBUG
      traceEvent(CONST_TRACE_INFO, "Gnutella: %s->%s [%s]",
		 srcHost->hostNumIpAddress,
		 dstHost->hostNumIpAddress,
		 tmpStr);
#endif
      updateFileList((char*)tmpStr, BITFLAG_P2P_DOWNLOAD_MODE, srcHost);
      updateFileList((char*)tmpStr, BITFLAG_P2P_UPLOAD_MODE, dstHost);
      theSession->isP2P = FLAG_P2P_GNUTELLA;
    }
    free(rcStr);
  }
}

/* *********************************** */

static void handleKazaaSession(const struct pcap_pkthdr *h,
                               HostTraffic *srcHost, u_short sport,
                               HostTraffic *dstHost, u_short dport,
                               u_int packetDataLength, u_char* packetData,
                               IPSession *theSession, int actualDeviceId) {
  char *rcStr;
  char tmpStr[256];

  if(theSession->bytesProtoSent.value == 0) {
    char *strtokState, *row;

    if ((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
      traceEvent (CONST_TRACE_WARNING, "handleKazaaSession: Unable to "
		  "allocate memory, Kazaa Session handling incomplete\n");
      return;
    }
    memcpy(rcStr, packetData, packetDataLength);
    rcStr[packetDataLength] = '\0';

    if(strncmp(rcStr, "GET ", 4) == 0) {
      row = strtok_r(rcStr, "\n", &strtokState);

      while(row != NULL) {
	if(strncmp(row, "GET /", 4) == 0) {
	  char *theStr = "GET /.hash=";
	  if(strncmp(row, theStr, strlen(theStr)) != 0) {
	    char *strtokState1, *file = strtok_r(&row[4], " ", &strtokState1);
	    int i, begin=0;

	    if(file != NULL) {
	      for(i=0; file[i] != '\0'; i++) {
		if(file[i] == '/') begin = i;
	      }

	      begin++;

	      unescape(tmpStr, sizeof(tmpStr), &file[begin]);

#ifdef P2P_DEBUG
	      traceEvent(CONST_TRACE_INFO, "Kazaa: %s->%s [%s]",
			 srcHost->hostNumIpAddress,
			 dstHost->hostNumIpAddress,
			 tmpStr);
#endif
	      updateFileList(tmpStr, BITFLAG_P2P_DOWNLOAD_MODE, srcHost);
	      updateFileList(tmpStr, BITFLAG_P2P_UPLOAD_MODE, dstHost);
	      theSession->isP2P = FLAG_P2P_KAZAA;
	    }
	  }
	} else if(strncmp(row, "X-Kazaa-Username", 15) == 0) {
	  char *user;

	  row[strlen(row)-1] = '\0';

	  user = &row[18];
	  if(strlen(user) > 48)
	    user[48] = '\0';

	  /* traceEvent(CONST_TRACE_INFO, "DEBUG: USER='%s'", user); */

	  updateHostUsers(user, BITFLAG_P2P_USER, srcHost);
	  theSession->isP2P = FLAG_P2P_KAZAA;
	}

	row = strtok_r(NULL, "\n", &strtokState);
      }

      /* printf("==>\n\n%s\n\n", rcStr); */
    }
    free(rcStr);

  } else if (((theSession->bytesProtoSent.value > 0)
	      || (theSession->bytesProtoSent.value < 32))) {
    char *strtokState, *row;

    if ((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
      traceEvent (CONST_TRACE_WARNING, "handleKazaaSession: Unable to "
		  "allocate memory, Kazaa Session handling incomplete\n");
      return;
    }
    memcpy(rcStr, packetData, packetDataLength);
    rcStr[packetDataLength] = '\0';

    if(strncmp(rcStr, "HTTP", 4) == 0) {
      row = strtok_r(rcStr, "\n", &strtokState);

      while(row != NULL) {
	char *str = "X-KazaaTag: 4=";

	if(strncmp(row, str, strlen(str)) == 0) {
	  char *file = &row[strlen(str)];

	  file[strlen(file)-1] = '\0';
#ifdef P2P_DEBUG
	  traceEvent(CONST_TRACE_INFO, "Uploading '%s'", file);
#endif
	  updateFileList(file, BITFLAG_P2P_UPLOAD_MODE, srcHost);
	  updateFileList(file, BITFLAG_P2P_DOWNLOAD_MODE, dstHost);
	  theSession->isP2P = FLAG_P2P_KAZAA;
	  break;
	}
	row = strtok_r(NULL, "\n", &strtokState);
      }
    }
    free(rcStr);
  }
}

/* *********************************** */

static void handleHTTPSession(const struct pcap_pkthdr *h,
                              HostTraffic *srcHost, u_short sport,
                              HostTraffic *dstHost, u_short dport,
                              u_int packetDataLength, u_char* packetData,
                              IPSession *theSession, int actualDeviceId) {
  char *rcStr, tmpStr[256];
  struct timeval tvstrct;

  if (sport == IP_TCP_PORT_HTTP) FD_SET(FLAG_HOST_TYPE_SVC_HTTP, &srcHost->flags);
  if (dport == IP_TCP_PORT_HTTP) FD_SET(FLAG_HOST_TYPE_SVC_HTTP, &dstHost->flags);

  if ((sport == IP_TCP_PORT_HTTP)
      && (theSession->bytesProtoRcvd.value == 0)) {
    memcpy(tmpStr, packetData, 16);
    tmpStr[16] = '\0';

    if(strncmp(tmpStr, "HTTP/1", 6) == 0) {
      int rc;
      time_t microSecTimeDiff;

      u_int16_t transactionId = computeTransId(&srcHost->hostIpAddress,
					       &dstHost->hostIpAddress,
					       sport,dport);

      /* to be 64bit-proof we have to copy the elements */
      tvstrct.tv_sec = h->ts.tv_sec;
      tvstrct.tv_usec = h->ts.tv_usec;
      microSecTimeDiff = getTimeMapping(transactionId, tvstrct);

#ifdef HTTP_DEBUG
      traceEvent(CONST_TRACE_INFO, "HTTP_DEBUG: %s->%s [%s]",
		 srcHost->hostResolvedName,
		 dstHost->hostResolvedName, tmpStr);
#endif

      if(srcHost->protocolInfo == NULL) srcHost->protocolInfo = calloc(1, sizeof(ProtocolInfo));
      if(dstHost->protocolInfo == NULL) dstHost->protocolInfo = calloc(1, sizeof(ProtocolInfo));

      if(srcHost->protocolInfo->httpStats == NULL) {
	srcHost->protocolInfo->httpStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	memset(srcHost->protocolInfo->httpStats, 0, sizeof(ServiceStats));
      }

      if(dstHost->protocolInfo->httpStats == NULL) {
	dstHost->protocolInfo->httpStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	memset(dstHost->protocolInfo->httpStats, 0, sizeof(ServiceStats));
      }

      rc = atoi(&tmpStr[9]);

      if(rc == 200) /* HTTP/1.1 200 OK */ {
	incrementTrafficCounter(&srcHost->protocolInfo->httpStats->numPositiveReplSent, 1);
	incrementTrafficCounter(&dstHost->protocolInfo->httpStats->numPositiveReplRcvd, 1);
      } else {
	incrementTrafficCounter(&srcHost->protocolInfo->httpStats->numNegativeReplSent, 1);
	incrementTrafficCounter(&dstHost->protocolInfo->httpStats->numNegativeReplRcvd, 1);
      }

      if(microSecTimeDiff > 0) {
	if(subnetLocalHost(dstHost)) {
	  if((srcHost->protocolInfo->httpStats->fastestMicrosecLocalReqMade == 0)
	     || (microSecTimeDiff < srcHost->protocolInfo->httpStats->fastestMicrosecLocalReqServed))
	    srcHost->protocolInfo->httpStats->fastestMicrosecLocalReqServed = microSecTimeDiff;
	  if(microSecTimeDiff > srcHost->protocolInfo->httpStats->slowestMicrosecLocalReqServed)
	    srcHost->protocolInfo->httpStats->slowestMicrosecLocalReqServed = microSecTimeDiff;
	} else {
	  if((srcHost->protocolInfo->httpStats->fastestMicrosecRemReqMade == 0)
	     || (microSecTimeDiff < srcHost->protocolInfo->httpStats->fastestMicrosecRemReqServed))
	    srcHost->protocolInfo->httpStats->fastestMicrosecRemReqServed = microSecTimeDiff;
	  if(microSecTimeDiff > srcHost->protocolInfo->httpStats->slowestMicrosecRemReqServed)
	    srcHost->protocolInfo->httpStats->slowestMicrosecRemReqServed = microSecTimeDiff;
	}

	if(subnetLocalHost(srcHost)) {
	  if((dstHost->protocolInfo->httpStats->fastestMicrosecLocalReqMade == 0)
	     || (microSecTimeDiff < dstHost->protocolInfo->httpStats->fastestMicrosecLocalReqMade))
	    dstHost->protocolInfo->httpStats->fastestMicrosecLocalReqMade = microSecTimeDiff;
	  if(microSecTimeDiff > dstHost->protocolInfo->httpStats->slowestMicrosecLocalReqMade)
	    dstHost->protocolInfo->httpStats->slowestMicrosecLocalReqMade = microSecTimeDiff;
	} else {
	  if((dstHost->protocolInfo->httpStats->fastestMicrosecRemReqMade == 0)
	     || (microSecTimeDiff < dstHost->protocolInfo->httpStats->fastestMicrosecRemReqMade))
	    dstHost->protocolInfo->httpStats->fastestMicrosecRemReqMade = microSecTimeDiff;
	  if(microSecTimeDiff > dstHost->protocolInfo->httpStats->slowestMicrosecRemReqMade)
	    dstHost->protocolInfo->httpStats->slowestMicrosecRemReqMade = microSecTimeDiff;
	}
      } else {
#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "DEBUG: getTimeMapping(0x%X) failed for HTTP", transactionId);
#endif
      }
    }
  } else if (dport == IP_TCP_PORT_HTTP) {
    if(theSession->bytesProtoSent.value == 0) {
      if ((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
	traceEvent (CONST_TRACE_WARNING, "handleHTTPSession: Unable to "
		    "allocate memory, HTTP Session handling incomplete\n");
	return;
      }
      memcpy(rcStr, packetData, packetDataLength);
      rcStr[packetDataLength] = '\0';

#ifdef HTTP_DEBUG
      printf("HTTP_DEBUG: %s->%s [%s]\n",
	     srcHost->hostResolvedName,
	     dstHost->hostResolvedName,
	     rcStr);
#endif

      if(isInitialHttpData(rcStr)) {
	char *strtokState, *row;

	u_int16_t transactionId = computeTransId(&srcHost->hostIpAddress,
						 &dstHost->hostIpAddress,
						 sport,dport);
	/* to be 64bit-proof we have to copy the elements */
	tvstrct.tv_sec = h->ts.tv_sec;
	tvstrct.tv_usec = h->ts.tv_usec;
	addTimeMapping(transactionId, tvstrct);

	if(srcHost->protocolInfo == NULL) srcHost->protocolInfo = calloc(1, sizeof(ProtocolInfo));
	if(dstHost->protocolInfo == NULL) dstHost->protocolInfo = calloc(1, sizeof(ProtocolInfo));

	if(srcHost->protocolInfo->httpStats == NULL) {
	  srcHost->protocolInfo->httpStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	  memset(srcHost->protocolInfo->httpStats, 0, sizeof(ServiceStats));
	}
	if(dstHost->protocolInfo->httpStats == NULL) {
	  dstHost->protocolInfo->httpStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	  memset(dstHost->protocolInfo->httpStats, 0, sizeof(ServiceStats));
	}

	if(subnetLocalHost(dstHost))
	  incrementTrafficCounter(&srcHost->protocolInfo->httpStats->numLocalReqSent, 1);
	else
	  incrementTrafficCounter(&srcHost->protocolInfo->httpStats->numRemReqSent, 1);

	if(subnetLocalHost(srcHost))
	  incrementTrafficCounter(&dstHost->protocolInfo->httpStats->numLocalReqRcvd, 1);
	else
	  incrementTrafficCounter(&dstHost->protocolInfo->httpStats->numRemReqRcvd, 1);

	row = strtok_r(rcStr, "\n", &strtokState);

	while(row != NULL) {
	  int len = strlen(row);

	  if((len > 12) && (strncmp(row, "User-Agent:", 11) == 0)) {
	    char *token, *tokState, *browser = NULL, *os = NULL;

	    row[len-1] = '\0';

	    /*
	      Mozilla/4.0 (compatible; MSIE 5.01; Windows 98)
	      Mozilla/4.7 [en] (X11; I; SunOS 5.8 i86pc)
	      Mozilla/4.76 [en] (Win98; U)
	    */
#ifdef DEBUG
	    printf("DEBUG: => '%s' (len=%d)\n", &row[12], packetDataLength);
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
	      printf("DEBUG: Browser='%s'\n", browser);
	    }
#endif

	    if(os != NULL) {
	      trimString(os);
#ifdef DEBUG
	      printf("DEBUG: OS='%s'\n", os);
#endif

	      if(srcHost->fingerprint == NULL) {
		char buffer[128], *delimiter;

		safe_snprintf(__FILE__, __LINE__, buffer, sizeof(buffer), ":%s", os);

		if((delimiter = strchr(buffer, ';')) != NULL) delimiter[0] = '\0';
		if((delimiter = strchr(buffer, '(')) != NULL) delimiter[0] = '\0';
		if((delimiter = strchr(buffer, ')')) != NULL) delimiter[0] = '\0';

		accessAddrResMutex("makeHostLink");
		srcHost->fingerprint = strdup(buffer);
		releaseAddrResMutex();
	      }
	    }
	    break;
	  } else if((len > 6) && (strncmp(row, "Host:", 5) == 0)) {
	    char *host;

	    row[len-1] = '\0';

	    host = &row[6];
	    if(strlen(host) > 48)
	      host[48] = '\0';

#ifdef DEBUG
	    printf("DEBUG: HOST='%s'\n", host);
#endif
	    if(theSession->virtualPeerName == NULL)
	      theSession->virtualPeerName = strdup(host);
	  }

	  row = strtok_r(NULL, "\n", &strtokState);
	}

	/* printf("==>\n\n%s\n\n", rcStr); */

      } else {
	if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	  traceEvent(CONST_TRACE_WARNING, "unknown protocol (no HTTP) detected (trojan?) "
		     "at port 80 %s:%d->%s:%d [%s]\n",
		     srcHost->hostResolvedName, sport,
		     dstHost->hostResolvedName, dport,
		     rcStr);

	  dumpSuspiciousPacket(actualDeviceId);
	}
      }

      free(rcStr);
    }
  }
}

/* *********************************** */

/*
 * This routine performs all sorts of security checks on the TCP packet and
 * dumps suspicious packets, if dumpSuspiciousPacket is set.
 */
static void tcpSessionSecurityChecks (const struct pcap_pkthdr *h,
                                      HostTraffic *srcHost,
                                      u_short sport,
                                      HostTraffic *dstHost,
                                      u_short dport,
                                      struct tcphdr *tp,
                                      u_int packetDataLength,
                                      u_char* packetData,
                                      u_short addedNewEntry,
                                      IPSession *theSession,
                                      int actualDeviceId) {
  int len;
  char tmpStr[256];

  if((theSession->sessionState == FLAG_STATE_ACTIVE)
     && ((theSession->nwLatency.tv_sec != 0)
	 || (theSession->nwLatency.tv_usec != 0))
     ) {
    /* This session started *after* ntop started (i.e. ntop
       didn't miss the beginning of the session). If the session
       started *before* ntop started up then nothing can be said
       about the protocol.
    */
    if(packetDataLength >= sizeof(tmpStr))
      len = sizeof(tmpStr)-1;
    else
      len = packetDataLength;

    /*
      This is a brand new session: let's check whether this is
      not a faked session (i.e. a known protocol is running at
      an unknown port)
    */
    if((theSession->bytesProtoSent.value == 0) && (len > 0)) {
      memset(tmpStr, 0, sizeof(tmpStr));
      memcpy(tmpStr, packetData, len);

      if(myGlobals.runningPref.enablePacketDecoding) {
	if ((dport != IP_TCP_PORT_HTTP)
	    && (dport != IP_TCP_PORT_NTOP)
	    && (dport != IP_TCP_PORT_SQUID)
	    && isInitialHttpData(tmpStr)) {
	  if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	    traceEvent(CONST_TRACE_WARNING, "HTTP detected at wrong port (trojan?) "
		       "%s:%d -> %s:%d [%s]",
		       srcHost->hostResolvedName, sport,
		       dstHost->hostResolvedName, dport,
		       tmpStr);
	    dumpSuspiciousPacket(actualDeviceId);
	  }
	} else if((sport != IP_TCP_PORT_FTP) && (sport != IP_TCP_PORT_SMTP)
		  && isInitialFtpData(tmpStr)) {
	  if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	    traceEvent(CONST_TRACE_WARNING, "FTP/SMTP detected at wrong port (trojan?) "
		       "%s:%d -> %s:%d [%s]",
		       dstHost->hostResolvedName, dport,
		       srcHost->hostResolvedName, sport,
		       tmpStr);
	    dumpSuspiciousPacket(actualDeviceId);
	  }
	} else if(((sport == IP_TCP_PORT_FTP) || (sport == IP_TCP_PORT_SMTP)) &&
		  (!isInitialFtpData(tmpStr))) {
	  if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	    traceEvent(CONST_TRACE_WARNING, "Unknown protocol (no FTP/SMTP) detected (trojan?) "
		       "at port %d %s:%d -> %s:%d [%s]", sport,
		       dstHost->hostResolvedName, dport,
		       srcHost->hostResolvedName, sport,
		       tmpStr);
	    dumpSuspiciousPacket(actualDeviceId);
	  }
	} else if((sport != IP_TCP_PORT_SSH) && (dport != IP_TCP_PORT_SSH)
		  &&  isInitialSshData(tmpStr)) {
	  if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	    traceEvent(CONST_TRACE_WARNING, "SSH detected at wrong port (trojan?) "
		       "%s:%d -> %s:%d [%s]  ",
		       dstHost->hostResolvedName, dport,
		       srcHost->hostResolvedName, sport,
		       tmpStr);
	    dumpSuspiciousPacket(actualDeviceId);
	  }
	} else if(((sport == IP_TCP_PORT_SSH) || (dport == IP_TCP_PORT_SSH)) &&
		  (!isInitialSshData(tmpStr))) {
	  if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	    traceEvent(CONST_TRACE_WARNING, "Unknown protocol (no SSH) detected (trojan?) "
		       "at port 22 %s:%d -> %s:%d [%s]",
		       dstHost->hostResolvedName, dport,
		       srcHost->hostResolvedName, sport,
		       tmpStr);
	    dumpSuspiciousPacket(actualDeviceId);
	  }
	}
      }
    }
  }

  /*
   * Security checks based on TCP Flags
   */
  if((tp->th_flags == TH_ACK) && (theSession->sessionState == FLAG_FLAG_STATE_SYN_ACK)) {
    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    incrementUsageCounter(&srcHost->secHostPkts->establishedTCPConnSent, dstHost, actualDeviceId);
    incrementUsageCounter(&dstHost->secHostPkts->establishedTCPConnRcvd, srcHost, actualDeviceId);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.establishedTCPConn, 1);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].numEstablishedTCPConnections, 1);
  }
  else if ((addedNewEntry == 0)
	   && ((theSession->sessionState == FLAG_STATE_SYN)
	       || (theSession->sessionState == FLAG_FLAG_STATE_SYN_ACK))
	   && (!(tp->th_flags & TH_RST))) {
    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    if(sport > dport) {
      incrementUsageCounter(&srcHost->secHostPkts->establishedTCPConnSent, dstHost, actualDeviceId);
      incrementUsageCounter(&dstHost->secHostPkts->establishedTCPConnRcvd, srcHost, actualDeviceId);
      /* This simulates a connection establishment */
      incrementUsageCounter(&srcHost->secHostPkts->synPktsSent, dstHost, actualDeviceId);
      incrementUsageCounter(&dstHost->secHostPkts->synPktsRcvd, srcHost, actualDeviceId);
      incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.synPkts, 1);
    } else {
      incrementUsageCounter(&srcHost->secHostPkts->establishedTCPConnRcvd, dstHost, actualDeviceId);
      incrementUsageCounter(&dstHost->secHostPkts->establishedTCPConnSent, srcHost, actualDeviceId);
      /* This simulates a connection establishment */
      incrementUsageCounter(&dstHost->secHostPkts->synPktsSent, srcHost, actualDeviceId);
      incrementUsageCounter(&srcHost->secHostPkts->synPktsRcvd, dstHost, actualDeviceId);

      incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.establishedTCPConn, 1);
      incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.synPkts, 1);
    }

  }

  if(tp->th_flags == (TH_RST|TH_ACK)) {
    /* RST|ACK is sent when a connection is refused */
    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    incrementUsageCounter(&srcHost->secHostPkts->rstAckPktsSent, dstHost, actualDeviceId);
    incrementUsageCounter(&dstHost->secHostPkts->rstAckPktsRcvd, srcHost, actualDeviceId);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.rstAckPkts, 1);
  } else if(tp->th_flags & TH_RST) {
    if(((theSession->initiator == srcHost)
	&& (theSession->lastRem2InitiatorFlags[0] == TH_ACK)
	&& (theSession->bytesSent.value == 0))
       || ((theSession->initiator == dstHost)
	   && (theSession->lastInitiator2RemFlags[0] == TH_ACK)
	   && (theSession->bytesRcvd.value == 0))) {
      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      incrementUsageCounter(&srcHost->secHostPkts->ackXmasFinSynNullScanRcvd, dstHost, actualDeviceId);
      incrementUsageCounter(&dstHost->secHostPkts->ackXmasFinSynNullScanSent, srcHost, actualDeviceId);
      incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.ackXmasFinSynNullScan, 1);

      if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING, "Host [%s:%d] performed ACK scan of host [%s:%d]",
		   dstHost->hostResolvedName, dport,
		   srcHost->hostResolvedName, sport);
	dumpSuspiciousPacket(actualDeviceId);
      }
    }
    /* Connection terminated */
    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    incrementUsageCounter(&srcHost->secHostPkts->rstPktsSent, dstHost, actualDeviceId);
    incrementUsageCounter(&dstHost->secHostPkts->rstPktsRcvd, srcHost, actualDeviceId);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.rstPkts, 1);
  } else if(tp->th_flags == (TH_SYN|TH_FIN)) {
    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    incrementUsageCounter(&srcHost->secHostPkts->synFinPktsSent, dstHost, actualDeviceId);
    incrementUsageCounter(&dstHost->secHostPkts->synFinPktsRcvd, srcHost, actualDeviceId);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.synFinPkts, 1);
  } else if(tp->th_flags == (TH_FIN|TH_PUSH|TH_URG)) {
    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    incrementUsageCounter(&srcHost->secHostPkts->finPushUrgPktsSent, dstHost, actualDeviceId);
    incrementUsageCounter(&dstHost->secHostPkts->finPushUrgPktsRcvd, srcHost, actualDeviceId);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.finPushUrgPkts, 1);
  } else if(tp->th_flags == TH_SYN) {
    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    incrementUsageCounter(&srcHost->secHostPkts->synPktsSent, dstHost, actualDeviceId);
    incrementUsageCounter(&dstHost->secHostPkts->synPktsRcvd, srcHost, actualDeviceId);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.synPkts, 1);
  } else if(tp->th_flags == 0x0 /* NULL */) {
    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    incrementUsageCounter(&srcHost->secHostPkts->nullPktsSent, dstHost, actualDeviceId);
    incrementUsageCounter(&dstHost->secHostPkts->nullPktsRcvd, srcHost, actualDeviceId);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.nullPkts, 1);
  }

  /* **************************** */

  if(myGlobals.runningPref.enableSuspiciousPacketDump) {
    /*
      For more info about checks below see
      http://www.synnergy.net/Archives/Papers/dethy/host-detection.txt
    */
    if((srcHost == dstHost)
       /* && (sport == dport)  */ /* Caveat: what about Win NT 3.51 ? */
       && (tp->th_flags == TH_SYN)) {
      traceEvent(CONST_TRACE_WARNING, "Detected Land Attack against host %s:%d",
		 srcHost->hostResolvedName, sport);
      dumpSuspiciousPacket(actualDeviceId);
    }

    if(tp->th_flags == (TH_RST|TH_ACK)) {
      if((((theSession->initiator == srcHost)
	   && (theSession->lastRem2InitiatorFlags[0] == TH_SYN))
	  || ((theSession->initiator == dstHost)
	      && (theSession->lastInitiator2RemFlags[0] == TH_SYN)))
	 ) {
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&dstHost->secHostPkts->rejectedTCPConnSent, srcHost, actualDeviceId);
	incrementUsageCounter(&srcHost->secHostPkts->rejectedTCPConnRcvd, dstHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.rejectedTCPConn, 1);

	traceEvent(CONST_TRACE_INFO, "Host %s rejected TCP session from %s [%s:%d]<->[%s:%d] (port closed?)",
		   srcHost->hostResolvedName, dstHost->hostResolvedName,
		   dstHost->hostResolvedName, dport,
		   srcHost->hostResolvedName, sport);
	dumpSuspiciousPacket(actualDeviceId);
      } else if(((theSession->initiator == srcHost)
		 && (theSession->lastRem2InitiatorFlags[0] == (TH_FIN|TH_PUSH|TH_URG)))
		|| ((theSession->initiator == dstHost)
		    && (theSession->lastInitiator2RemFlags[0] == (TH_FIN|TH_PUSH|TH_URG)))) {
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&dstHost->secHostPkts->ackXmasFinSynNullScanSent, srcHost, actualDeviceId);
	incrementUsageCounter(&srcHost->secHostPkts->ackXmasFinSynNullScanRcvd, dstHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.ackXmasFinSynNullScan, 1);

	traceEvent(CONST_TRACE_WARNING, "Host [%s:%d] performed XMAS scan of host [%s:%d]",
		   dstHost->hostResolvedName, dport,
		   srcHost->hostResolvedName, sport);
	dumpSuspiciousPacket(actualDeviceId);
      } else if(((theSession->initiator == srcHost)
		 && ((theSession->lastRem2InitiatorFlags[0] & TH_FIN) == TH_FIN))
		|| ((theSession->initiator == dstHost)
		    && ((theSession->lastInitiator2RemFlags[0] & TH_FIN) == TH_FIN))) {
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&dstHost->secHostPkts->ackXmasFinSynNullScanSent, srcHost, actualDeviceId);
	incrementUsageCounter(&srcHost->secHostPkts->ackXmasFinSynNullScanRcvd, dstHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.ackXmasFinSynNullScan, 1);

	traceEvent(CONST_TRACE_WARNING, "Host [%s:%d] performed FIN scan of host [%s:%d]",
		   dstHost->hostResolvedName, dport,
		   srcHost->hostResolvedName, sport);
	dumpSuspiciousPacket(actualDeviceId);
      } else if(((theSession->initiator == srcHost)
		 && (theSession->lastRem2InitiatorFlags[0] == 0)
		 && (theSession->bytesRcvd.value > 0))
		|| ((theSession->initiator == dstHost)
		    && ((theSession->lastInitiator2RemFlags[0] == 0))
		    && (theSession->bytesSent.value > 0))) {
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->ackXmasFinSynNullScanRcvd, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->ackXmasFinSynNullScanSent, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.ackXmasFinSynNullScan, 1);

	traceEvent(CONST_TRACE_WARNING, "Host [%s:%d] performed NULL scan of host [%s:%d]",
		   dstHost->hostResolvedName, dport,
		   srcHost->hostResolvedName, sport);
	dumpSuspiciousPacket(actualDeviceId);
      }
    }

    /* **************************** */

    /* Save session flags */
    if(theSession->initiator == srcHost) {
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
}

/* *********************************** */

static int portRange(int sport, int dport, int minPort, int maxPort) {
  return(((sport >= minPort) && (sport <= maxPort))
	 || ((dport >= minPort) && (dport <= maxPort)));
}

/* *********************************** */

static IPSession* handleTCPSession(const struct pcap_pkthdr *h,
                                   u_short fragmentedData, u_int tcpWin,
                                   HostTraffic *srcHost, u_short sport,
                                   HostTraffic *dstHost, u_short dport,
                                   u_int length, struct tcphdr *tp,
                                   u_int packetDataLength, u_char* packetData,
                                   int actualDeviceId, u_short *newSession) {
  IPSession *prevSession;
  u_int idx;
  IPSession *theSession = NULL;
  short flowDirection = FLAG_CLIENT_TO_SERVER;
  char addedNewEntry = 0;
  u_short check, found=0;
  HostTraffic *hostToUpdate = NULL;
  u_char *rcStr, tmpStr[256];
  int len = 0;
  char *pnotes, *snotes, *dnotes;

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.tcpSessionsMutex, "handleTCPSession");
#endif

  idx = computeIdx(&srcHost->hostIpAddress,&dstHost->hostIpAddress, sport, dport);
  idx %= MAX_TOT_NUM_SESSIONS;

  prevSession = theSession = myGlobals.device[actualDeviceId].tcpSession[idx];

  while(theSession != NULL) {
    if(theSession && (theSession->next == theSession)) {
      traceEvent(CONST_TRACE_WARNING, "Internal Error (4) (idx=%d)", idx);
      theSession->next = NULL;
    }

    if((theSession->initiator == srcHost)
       && (theSession->remotePeer == dstHost)
       && (theSession->sport == sport)
       && (theSession->dport == dport)) {
      found = 1;
      flowDirection = FLAG_CLIENT_TO_SERVER;
      break;
    } else if((theSession->initiator == dstHost)
	      && (theSession->remotePeer == srcHost)
	      && (theSession->sport == dport)
	      && (theSession->dport == sport)) {
      found = 1;
      flowDirection = FLAG_SERVER_TO_CLIENT;
      break;
    } else {
      prevSession = theSession;
      theSession  = theSession->next;
    }
  } /* while */

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Search for session: %d (%d <-> %d)",
	     found, sport, dport);
#endif

  if(!found) {
    /* New Session */
#ifdef DEBUG
    printf("DEBUG: NEW ");
#endif

    (*newSession) = 1; /* This is a new session */
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.totalFlows,
			    2 /* 2 x monodirectional flows */);

    if(myGlobals.device[actualDeviceId].numTcpSessions >= myGlobals.runningPref.maxNumSessions) {
      static char messageShown = 0;

      if(!messageShown) {
	messageShown = 1;
	traceEvent(CONST_TRACE_INFO, "WARNING: Max num TCP sessions (%u) reached (see -X)",
		   myGlobals.runningPref.maxNumSessions);
      }

      return(NULL);
    }

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: TCP hash [act size: %d]",
	       myGlobals.device[actualDeviceId].numTcpSessions);
#endif

    /*
       We don't check for space here as the datastructure allows
       ntop to store sessions as needed
    */
#ifdef PARM_USE_SESSIONS_CACHE
    /* There's enough space left in the hashtable */
    if (myGlobals.sessionsCacheLen > 0) {
      theSession = myGlobals.sessionsCache[--myGlobals.sessionsCacheLen];
      myGlobals.sessionsCacheReused++;
      /*
	traceEvent(CONST_TRACE_INFO, "Fetched session from pointers cache (len=%d)",
	(int)myGlobals.sessionsCacheLen);
      */
    } else
#endif
      if((theSession = (IPSession*)malloc(sizeof(IPSession))) == NULL) return(NULL);

    memset(theSession, 0, sizeof(IPSession));
    addedNewEntry = 1;

    if(tp->th_flags == TH_SYN) {
      theSession->nwLatency.tv_sec = h->ts.tv_sec;
      theSession->nwLatency.tv_usec = h->ts.tv_usec;
      theSession->sessionState = FLAG_STATE_SYN;
    }

    theSession->magic = CONST_MAGIC_NUMBER;

    addrcpy(&theSession->initiatorRealIp,&srcHost->hostIpAddress);
    addrcpy(&theSession->remotePeerRealIp,&dstHost->hostIpAddress);

#ifdef SESSION_TRACE_DEBUG
    traceEvent(CONST_TRACE_INFO, "SESSION_TRACE_DEBUG: New TCP session [%s:%d] <-> [%s:%d] (# sessions = %d)",
	       dstHost->hostNumIpAddress, dport,
	       srcHost->hostNumIpAddress, sport,
	       myGlobals.device[actualDeviceId].numTcpSessions);
#endif

    myGlobals.device[actualDeviceId].numTcpSessions++;

    if(myGlobals.device[actualDeviceId].numTcpSessions > myGlobals.device[actualDeviceId].maxNumTcpSessions)
      myGlobals.device[actualDeviceId].maxNumTcpSessions = myGlobals.device[actualDeviceId].numTcpSessions;

    theSession->next = myGlobals.device[actualDeviceId].tcpSession[idx];
    myGlobals.device[actualDeviceId].tcpSession[idx] = theSession;

    theSession->initiator  = srcHost, theSession->remotePeer = dstHost;
    theSession->initiator->numHostSessions++, theSession->remotePeer->numHostSessions++;
    theSession->sport = sport;
    theSession->dport = dport;
    theSession->passiveFtpSession = isPassiveSession(&dstHost->hostIpAddress, dport, &pnotes);
    theSession->voipSession       = isVoIPSession(&srcHost->hostIpAddress, sport, &snotes)
      || isVoIPSession(&dstHost->hostIpAddress, dport, &dnotes);

    if(pnotes) theSession->session_info = pnotes;
    else if(snotes) theSession->session_info = snotes;
    else if(dnotes) theSession->session_info = dnotes;
    else theSession->session_info = NULL;

    theSession->firstSeen = myGlobals.actTime;
    flowDirection = FLAG_CLIENT_TO_SERVER;
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: ->%d", idx);
#endif
  theSession->lastSeen = myGlobals.actTime;

  /* ***************************************** */

  if(packetDataLength >= sizeof(tmpStr))
    len = sizeof(tmpStr);
  else
    len = packetDataLength;

  if(myGlobals.runningPref.enablePacketDecoding
     && ((theSession->bytesProtoSent.value > 0) && (theSession->bytesProtoSent.value < 128))
     /* Reduce protocol decoding effort */
     ) {
    if (((sport == IP_TCP_PORT_HTTP) || (dport == IP_TCP_PORT_HTTP))
	&& (packetDataLength > 0)) {
      handleHTTPSession(h, srcHost, sport, dstHost, dport,
			 packetDataLength, packetData, theSession,
			 actualDeviceId);
    } else if((dport == IP_TCP_PORT_KAZAA) && (packetDataLength > 0)) {
      handleKazaaSession(h, srcHost, sport, dstHost, dport,
			  packetDataLength, packetData, theSession,
			  actualDeviceId);
    } else if (((dport == IP_TCP_PORT_GNUTELLA1) ||
		(dport == IP_TCP_PORT_GNUTELLA2) ||
		(dport == IP_TCP_PORT_GNUTELLA3))
	       && (packetDataLength > 0)) {
      handleGnutellaSession(h, srcHost, sport, dstHost, dport,
			     packetDataLength, packetData, theSession,
			     actualDeviceId);
    } else if((dport == IP_TCP_PORT_WINMX) && (packetDataLength > 0)) {
      handleWinMxSession(h, srcHost, sport, dstHost, dport,
			  packetDataLength, packetData, theSession,
			  actualDeviceId);
    } else if (((sport == IP_TCP_PORT_MSMSGR) ||
		(dport == IP_TCP_PORT_MSMSGR))
	       && (packetDataLength > 0)) {
      handleMsnMsgrSession(h, srcHost, sport, dstHost, dport,
			    packetDataLength, packetData, theSession,
			    actualDeviceId);
    } else if(((sport == IP_TCP_PORT_SMTP) ||
	       (dport == IP_TCP_PORT_SMTP))
	      && (theSession->sessionState == FLAG_STATE_ACTIVE)) {
      handleSMTPSession(h, srcHost, sport, dstHost, dport,
			 packetDataLength, packetData, theSession,
			 actualDeviceId);
    } else if(((sport == IP_TCP_PORT_FTP)  ||
	       (dport == IP_TCP_PORT_FTP))
	      && (theSession->sessionState == FLAG_STATE_ACTIVE)) {
      handleFTPSession(h, srcHost, sport, dstHost, dport,
			packetDataLength, packetData, theSession,
			actualDeviceId);
    } else if(((dport == IP_TCP_PORT_PRINTER) || (sport == IP_TCP_PORT_PRINTER))
	      && (theSession->sessionState == FLAG_STATE_ACTIVE)) {
      if(sport == IP_TCP_PORT_PRINTER)
	FD_SET(FLAG_HOST_TYPE_PRINTER, &srcHost->flags);
      else
	FD_SET(FLAG_HOST_TYPE_PRINTER, &dstHost->flags);
    } else if(((sport == IP_TCP_PORT_POP2) || (sport == IP_TCP_PORT_POP3)
	       || (dport == IP_TCP_PORT_POP2) || (dport == IP_TCP_PORT_POP3))
	      && (theSession->sessionState == FLAG_STATE_ACTIVE)) {
      handlePOPSession(h, srcHost, sport, dstHost, dport,
			packetDataLength, packetData, theSession,
			actualDeviceId);
    } else if(((sport == IP_TCP_PORT_IMAP) || (dport == IP_TCP_PORT_IMAP))
	      && (theSession->sessionState == FLAG_STATE_ACTIVE)) {
      handleIMAPSession(h, srcHost, sport, dstHost, dport,
			 packetDataLength, packetData, theSession,
			 actualDeviceId);
    } else {
      /*
	T. Karagiannis and others

	File-sharing in the Internet: A characterization of
	P2P traffic in the backbone
      */

      /* Further decoders */
      if((!theSession->isP2P)
	 && (packetDataLength > 0)
	 && ((theSession->bytesProtoSent.value > 0) && (theSession->bytesProtoSent.value < 1400))) {
	rcStr = (u_char*)malloc(len+1);
	memcpy(rcStr, packetData, len);
	rcStr[len-1] = '\0';

	/* See dcplusplus.sourceforge.net */
	if(portRange(sport, dport, 411, 412)
	   || (!strncmp((char*)rcStr, "$Connect", 8))
	   || (!strncmp((char*)rcStr, "$Direction", 10))
	   || (!strncmp((char*)rcStr, "$Hello", 6))
	   || (!strncmp((char*)rcStr, "$Key", 4))
	   || (!strncmp((char*)rcStr, "$Lock", 5))
	   || (!strncmp((char*)rcStr, "$MyInfo", 7))
	   || (!strncmp((char*)rcStr, "$Pin", 4))
	   || (!strncmp((char*)rcStr, "$Quit", 5))
	   || (!strncmp((char*)rcStr, "$Send", 5))
	   || (!strncmp((char*)rcStr, "$SR", 3))
	   || (!strncmp((char*)rcStr, "$Search", 7))) {
	  theSession->isP2P = FLAG_P2P_DIRECTCONNECT;
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_DOWNLOAD_MODE, srcHost);
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_UPLOAD_MODE,   dstHost);
	} else if(!strncmp((char*)rcStr, "$MyNick", 7)) {
	  theSession->isP2P = FLAG_P2P_DIRECTCONNECT;
	  updateHostUsers(strtok((char*)&rcStr[8], "|"), BITFLAG_P2P_USER, srcHost);
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_DOWNLOAD_MODE, srcHost);
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_UPLOAD_MODE,   dstHost);
	} else if(!strncmp((char*)rcStr, "$Get", 4)) {
	  char *file = strtok((char*)&rcStr[5], "$");
	  theSession->isP2P = FLAG_P2P_DIRECTCONNECT;
	  updateFileList(file, BITFLAG_P2P_DOWNLOAD_MODE, srcHost);
	  updateFileList(file, BITFLAG_P2P_UPLOAD_MODE,   dstHost);
	} else if(portRange(sport, dport, 4661, 4665)
		  || (rcStr[0] == 0xE3) || (rcStr[0] == 0xC5)) {
	  theSession->isP2P = FLAG_P2P_EDONKEY;
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_DOWNLOAD_MODE, srcHost);
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_UPLOAD_MODE,   dstHost);
	} else if(portRange(sport, dport, 6881, 6889)
		  || (!strncmp((char*)rcStr, "GET /announce?info_hash", 23))
		  || (!strncmp((char*)rcStr, "GET /torrents/", 14))
		  || (!strncmp((char*)rcStr, "GET TrackPak", 12))
		  || (!strncmp((char*)rcStr, "0x13BitTorrent", 14))) {
	  theSession->isP2P = FLAG_P2P_BITTORRENT;
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_DOWNLOAD_MODE, srcHost);
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_UPLOAD_MODE,   dstHost);
	} else if(portRange(sport, dport, 6346, 6347)
		  || (!strncmp((char*)rcStr,    "GNUTELLA", 8))
		  || (!strncmp((char*)rcStr, "GIV", 3))
		  || (!strncmp((char*)rcStr, "GET /uri-res/", 13))) {
	  theSession->isP2P = FLAG_P2P_GNUTELLA;
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_DOWNLOAD_MODE, srcHost);
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_UPLOAD_MODE,   dstHost);
	} else if((!strncmp((char*)rcStr,   "GET hash:", 9))
		  || (!strncmp((char*)rcStr, "PUSH", 4))
		  || (!strncmp((char*)rcStr, "GET /uri-res/", 12))) {
	  /* Ares */
	  theSession->isP2P = FLAG_P2P_OTHER_PROTOCOL;
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_DOWNLOAD_MODE, srcHost);
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_UPLOAD_MODE,   dstHost);
	} else if((!strncmp((char*)rcStr,    "GET /$$$$$$$$$/", 15))) {
	  /* EarthStation5 */
	  theSession->isP2P = FLAG_P2P_OTHER_PROTOCOL;
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_DOWNLOAD_MODE, srcHost);
	  updateFileList(UNKNOWN_P2P_FILE, BITFLAG_P2P_UPLOAD_MODE,   dstHost);
	}

	free(rcStr);
      }
    }
  } else {
    /* !myGlobals.enablePacketDecoding */

    switch(sport) {
    case IP_TCP_PORT_FTP:
      FD_SET(FLAG_HOST_TYPE_SVC_FTP, &srcHost->flags);
      break;
    case IP_TCP_PORT_SMTP:
      FD_SET(FLAG_HOST_TYPE_SVC_SMTP, &srcHost->flags);
      break;
    case IP_TCP_PORT_HTTP:
    case IP_TCP_PORT_HTTPS:
      FD_SET(FLAG_HOST_TYPE_SVC_HTTP, &srcHost->flags);
      break;
    case IP_TCP_PORT_POP2:
    case IP_TCP_PORT_POP3:
      FD_SET(FLAG_HOST_TYPE_SVC_POP, &srcHost->flags);
      break;
    case IP_TCP_PORT_IMAP:
      FD_SET(FLAG_HOST_TYPE_SVC_IMAP, &srcHost->flags);
      break;
    case IP_TCP_PORT_PRINTER:
    case IP_TCP_PORT_JETDIRECT:
      FD_SET(FLAG_HOST_TYPE_PRINTER, &srcHost->flags);
      break;
    }

    switch(dport) {
    case IP_TCP_PORT_FTP:
      FD_SET(FLAG_HOST_TYPE_SVC_FTP, &dstHost->flags);
      break;
    case IP_TCP_PORT_SMTP:
      FD_SET(FLAG_HOST_TYPE_SVC_SMTP, &dstHost->flags);
      break;
    case IP_TCP_PORT_HTTP:
    case IP_TCP_PORT_HTTPS:
      FD_SET(FLAG_HOST_TYPE_SVC_HTTP, &dstHost->flags);
      break;
    case IP_TCP_PORT_POP2:
    case IP_TCP_PORT_POP3:
      FD_SET(FLAG_HOST_TYPE_SVC_POP, &dstHost->flags);
      break;
    case IP_TCP_PORT_IMAP:
      FD_SET(FLAG_HOST_TYPE_SVC_IMAP, &dstHost->flags);
      break;
    case IP_TCP_PORT_PRINTER:
    case IP_TCP_PORT_JETDIRECT:
      FD_SET(FLAG_HOST_TYPE_PRINTER, &dstHost->flags);
      break;
    }
  }

  if(packetDataLength >= sizeof(tmpStr))
    len = sizeof(tmpStr)-1;
  else
    len = packetDataLength;

  /*
    We process some FTP stuff even if protocol decoding is disabled as we
    assume that this doesn't take up much CPU time
  */
  if(len > 0) {
    if ((sport == IP_TCP_PORT_FTP) || (dport == IP_TCP_PORT_FTP)) {
      memset(tmpStr, 0, sizeof(tmpStr));
      memcpy(tmpStr, packetData, len);

      /* traceEvent(CONST_TRACE_INFO, "FTP: %s", tmpStr); */

      /*
	227 Entering Passive Mode (131,114,21,11,156,95)
	PORT 172,22,5,95,7,36

	131.114.21.11:40012 (40012 = 156 * 256 + 95)
      */
      if((strncmp((char*)tmpStr, "227", 3) == 0)
	 || (strncmp((char*)tmpStr, "PORT", 4) == 0)) {
	int a, b, c, d, e, f;

	if(strncmp((char*)tmpStr, "PORT", 4) == 0) {
	  sscanf((char*)&tmpStr[5], "%d,%d,%d,%d,%d,%d", &a, &b, &c, &d, &e, &f);
	} else {
	  sscanf((char*)&tmpStr[27], "%d,%d,%d,%d,%d,%d", &a, &b, &c, &d, &e, &f);
	}
	
	addPassiveSessionInfo(&srcHost->hostIpAddress, (e*256+f), "Passive FTP session");
      }
    } else if((sport == IP_UDP_PORT_SIP) && (dport == IP_UDP_PORT_SIP)) {
      handleSIPSession(h, srcHost, sport, dstHost, dport,
		       packetDataLength, packetData, theSession,
		       actualDeviceId);
    } else if(((sport == IP_TCP_PORT_SCCP) && (dport > 1024))
	      || ((dport == IP_TCP_PORT_SCCP) && (sport > 1024))) {
      handleSCCPSession(h, srcHost, sport, dstHost, dport,
			packetDataLength, packetData, theSession,
			actualDeviceId);
    }
  } /* len > 0 */

    /* ***************************************** */

  if((theSession->minWindow > tcpWin) || (theSession->minWindow == 0))
    theSession->minWindow = tcpWin;

  if((theSession->maxWindow < tcpWin) || (theSession->maxWindow == 0))
    theSession->maxWindow = tcpWin;

#ifdef DEBUG
  printf("DEBUG: sessionsState=%d\n", theSession->sessionState);
#endif

  /* Latency measurement */
  if((tp->th_flags == (TH_SYN|TH_ACK)) && (theSession->sessionState == FLAG_STATE_SYN))  {
    theSession->sessionState = FLAG_FLAG_STATE_SYN_ACK;
  } else if((tp->th_flags == TH_ACK) && (theSession->sessionState == FLAG_FLAG_STATE_SYN_ACK)) {
    if(h->ts.tv_sec >= theSession->nwLatency.tv_sec) {
      theSession->nwLatency.tv_sec = h->ts.tv_sec-theSession->nwLatency.tv_sec;

      if((h->ts.tv_usec - theSession->nwLatency.tv_usec) < 0) {
	theSession->nwLatency.tv_usec = 1000000 + h->ts.tv_usec - theSession->nwLatency.tv_usec;
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

      theSession->sessionState = FLAG_STATE_ACTIVE;
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

  } else if ((addedNewEntry == 0)
	     && ((theSession->sessionState == FLAG_STATE_SYN)
		 || (theSession->sessionState == FLAG_FLAG_STATE_SYN_ACK))
	     && (!(tp->th_flags & TH_RST))) {
    /*
      We might have lost a packet so:
      - we cannot calculate latency
      - we don't set the state to initialized
    */

    theSession->nwLatency.tv_sec = theSession->nwLatency.tv_usec = 0;
    theSession->sessionState = FLAG_STATE_ACTIVE;

    /*
      ntop has no way to know who started the connection
      as the connection already started. Hence we use this simple
      heuristic algorithm:
      if(sport < dport) {
      sport = server;
      srchost = server host;
      }
    */

    if(sport > dport) {
      flowDirection = FLAG_CLIENT_TO_SERVER;
    } else {
      flowDirection = FLAG_SERVER_TO_CLIENT;
    }

    incrementTrafficCounter(&myGlobals.device[actualDeviceId].numEstablishedTCPConnections, 1);
  }

  /* Don't move the following call from here unless you know what you're
   * doing.
   *
   * This routine takes care of almost all the security checks such as:
   * - Dumping suspicious packets based on certain invalid TCP Flag combos
   * - Counting packets & bytes based on certain invalid TCP Flag combos
   * - Checking if a known protocol is running at a not well-known port
   */
  tcpSessionSecurityChecks (h, srcHost, sport, dstHost, dport, tp,
			    packetDataLength, packetData, addedNewEntry,
			    theSession, actualDeviceId);
  /*
   *
   * In this case the session is over hence the list of
   * sessions initiated/received by the hosts can be updated
   *
   */
  if(tp->th_flags & TH_FIN) {
    u_int32_t fin = ntohl(tp->th_seq);

    if(sport < dport) /* Server->Client */
      check = (fin != theSession->lastSCFin);
    else /* Client->Server */
      check = (fin != theSession->lastCSFin);

    if(check) {
      /* This is not a duplicated (retransmitted) FIN */
      theSession->finId[theSession->numFin] = fin;
      theSession->numFin = (theSession->numFin+1) % MAX_NUM_FIN;

      if(sport < dport) /* Server->Client */
	theSession->lastSCFin = fin;
      else /* Client->Server */
	theSession->lastCSFin = fin;

      if(tp->th_flags & TH_ACK) {
	/* This is a FIN_ACK */
	theSession->sessionState = FLAG_STATE_FIN2_ACK2;
      } else {
	switch(theSession->sessionState) {
	case FLAG_STATE_ACTIVE:
	  theSession->sessionState = FLAG_STATE_FIN1_ACK0;
	  break;
	case FLAG_STATE_FIN1_ACK0:
	  theSession->sessionState = FLAG_STATE_FIN2_ACK1;
	  break;
	case FLAG_STATE_FIN1_ACK1:
	  theSession->sessionState = FLAG_STATE_FIN2_ACK1;
	  break;
#ifdef DEBUG
	default:
	  traceEvent(CONST_TRACE_ERROR, "DEBUG: Unable to handle received FIN (%u) !", fin);
#endif
	}
      }
    } else {
#ifdef DEBUG
      printf("DEBUG: Rcvd Duplicated FIN %u\n", fin);
#endif
    }
  } else if(tp->th_flags == TH_ACK) {
    u_int32_t ack = ntohl(tp->th_ack);

    if((ack == theSession->lastAckIdI2R) && (ack == theSession->lastAckIdR2I)) {
      if(theSession->initiator == srcHost) {
	theSession->numDuplicatedAckI2R++;
	incrementTrafficCounter(&theSession->bytesRetranI2R, length);
	incrementTrafficCounter(&theSession->initiator->pktDuplicatedAckSent, 1);
	incrementTrafficCounter(&theSession->remotePeer->pktDuplicatedAckRcvd, 1);

#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "DEBUG: Duplicated ACK %ld [ACKs=%d/bytes=%d]: ",
		   ack, theSession->numDuplicatedAckI2R,
		   (int)theSession->bytesRetranI2R.value);
#endif
      } else {
	theSession->numDuplicatedAckR2I++;
	incrementTrafficCounter(&theSession->bytesRetranR2I, length);
	incrementTrafficCounter(&theSession->remotePeer->pktDuplicatedAckSent, 1);
	incrementTrafficCounter(&theSession->initiator->pktDuplicatedAckRcvd, 1);
#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "Duplicated ACK %ld [ACKs=%d/bytes=%d]: ",
		   ack, theSession->numDuplicatedAckR2I,
		   (int)theSession->bytesRetranR2I.value);
#endif
      }
    }

    if(theSession->initiator == srcHost)
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
	    case FLAG_STATE_FIN1_ACK0:
	      theSession->sessionState = FLAG_STATE_FIN1_ACK1;
	      break;
	    case FLAG_STATE_FIN2_ACK0:
	      theSession->sessionState = FLAG_STATE_FIN2_ACK1;
	      break;
	    case FLAG_STATE_FIN2_ACK1:
	      theSession->sessionState = FLAG_STATE_FIN2_ACK2;
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

  if((theSession->sessionState == FLAG_STATE_FIN2_ACK2)
     || (tp->th_flags & TH_RST)) /* abortive release */ {
    if(theSession->sessionState == FLAG_FLAG_STATE_SYN_ACK) {
      /*
	Rcvd RST packet before to complete the 3-way handshake.
	Note that the message is emitted only of the reset is received
	while in FLAG_FLAG_STATE_SYN_ACK. In fact if it has been received in
	FLAG_STATE_SYN this message has not to be emitted because this is
	a rejected session.
      */
      if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING, "TCP session [%s:%d]<->[%s:%d] reset by %s "
		   "without completing 3-way handshake",
		   srcHost->hostResolvedName, sport,
		   dstHost->hostResolvedName, dport,
		   srcHost->hostResolvedName);
	dumpSuspiciousPacket(actualDeviceId);
      }

      theSession->sessionState = FLAG_STATE_TIMEOUT;
    }

    if(myGlobals.runningPref.disableInstantSessionPurge != TRUE)
      theSession->sessionState = FLAG_STATE_TIMEOUT;

    if(sport == IP_TCP_PORT_HTTP)
      updateHTTPVirtualHosts(theSession->virtualPeerName, srcHost,
			     theSession->bytesSent, theSession->bytesRcvd);
    else
      updateHTTPVirtualHosts(theSession->virtualPeerName, dstHost,
			     theSession->bytesRcvd, theSession->bytesSent);
  }

  /* Update session stats */
  if(flowDirection == FLAG_CLIENT_TO_SERVER) {
    incrementTrafficCounter(&theSession->bytesProtoSent, packetDataLength);
    incrementTrafficCounter(&theSession->bytesSent, length);
    theSession->pktSent++;
    if(fragmentedData) incrementTrafficCounter(&theSession->bytesFragmentedSent, packetDataLength);
  } else {
    incrementTrafficCounter(&theSession->bytesProtoRcvd, packetDataLength);
    incrementTrafficCounter(&theSession->bytesRcvd, length);
    theSession->pktRcvd++;
    if(fragmentedData) incrementTrafficCounter(&theSession->bytesFragmentedRcvd, packetDataLength);
  }

  /* Immediately free the session */
  if(theSession->sessionState == FLAG_STATE_TIMEOUT) {
    if(myGlobals.device[actualDeviceId].tcpSession[idx] == theSession) {
      myGlobals.device[actualDeviceId].tcpSession[idx] = theSession->next;
    } else
      prevSession->next = theSession->next;

#if DELAY_SESSION_PURGE
    theSession->sessionState = FLAG_STATE_END; /* Session freed by scanTimedoutTCPSessions */
#else
    freeSession(theSession, actualDeviceId, 1, 1 /* lock purgeMutex */);
#endif
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.tcpSessionsMutex);
#endif
    return(NULL);
  }

#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.tcpSessionsMutex);
#endif

  return(theSession);
}

/* ************************************ */

static void handleUDPSession(const struct pcap_pkthdr *h,
                             u_short fragmentedData, HostTraffic *srcHost,
                             u_short sport, HostTraffic *dstHost,
                             u_short dport, u_int length,
                             u_char* packetData,
			     int actualDeviceId, u_short *newSession) {
  /*
  IPSession tmpSession;

  memset(&tmpSession, 0, sizeof(IPSession));
  tmpSession.lastSeen = myGlobals.actTime;
  tmpSession.initiator = srcHost, tmpSession.remotePeer = dstHost;
  tmpSession.bytesSent.value = length, tmpSession.bytesRcvd.value = 0;
  tmpSession.sport = sport, tmpSession.dport = dport;
  if(fragmentedData) incrementTrafficCounter(&tmpSession.bytesFragmentedSent, length);
  */

  (*newSession) = 1; /* This is always a new session */
}

/* ************************************ */

IPSession* handleSession(const struct pcap_pkthdr *h,
                         u_short fragmentedData, u_int tcpWin,
                         HostTraffic *srcHost, u_short sport,
                         HostTraffic *dstHost, u_short dport,
                         u_int length, struct tcphdr *tp,
                         u_int packetDataLength, u_char* packetData,
                         int actualDeviceId, u_short *newSession) {
  IPSession *theSession = NULL;
  u_short sessionType = 0;
  struct tcphdr static_tp;

  (*newSession) = 0; /* Default */

  if((!myGlobals.runningPref.enableSessionHandling)
     || (myGlobals.device[actualDeviceId].tcpSession == NULL))
    return(NULL);

  if((srcHost == NULL) || (dstHost == NULL)) {
    traceEvent(CONST_TRACE_ERROR, "Sanity check failed (3) [Low memory?]");
    return(NULL);
  }

  /*
    Note: do not move the {...} down this function
    because BOOTP uses broadcast addresses hence
    it would be filtered out by the (**) check
  */
  if (myGlobals.runningPref.enablePacketDecoding && (tp == NULL /* UDP session */) &&
      (srcHost->hostIpAddress.hostFamily == AF_INET &&
       dstHost->hostIpAddress.hostFamily == AF_INET))
    handleBootp(srcHost, dstHost, sport, dport, packetDataLength, packetData, actualDeviceId);

  if(broadcastHost(srcHost) || broadcastHost(dstHost)) /* (**) */
    return(theSession);

  if(tp == NULL)
    sessionType = IPPROTO_UDP;
  else
    sessionType = IPPROTO_TCP;

#ifdef SESSION_TRACE_DEBUG
  {
    char buf[32], buf1[32];

    traceEvent(CONST_TRACE_INFO, "DEBUG: [%s] %s:%d -> %s:%d [idx=%d]",
	       sessionType == IPPROTO_UDP ? "UDP" : "TCP",
	       _addrtostr(&srcHost->hostIpAddress, buf, sizeof(buf)), sport,
	       _addrtostr(&dstHost->hostIpAddress, buf1, sizeof(buf1)), dport, idx);

    if(tp) {
      printf("DEBUG: [%d]", tp->th_flags);
      if(tp->th_flags & TH_ACK) printf("ACK ");
      if(tp->th_flags & TH_SYN) printf("SYN ");
      if(tp->th_flags & TH_FIN) printf("FIN ");
      if(tp->th_flags & TH_RST) printf("RST ");
      if(tp->th_flags & TH_PUSH) printf("PUSH");
      printf("\n");
    }
  }
#endif

  if((sessionType == IPPROTO_UDP) && (tp == NULL)) {
    tp = &static_tp;
    memset(tp, 0, sizeof(struct tcphdr));
  }

  if((!multicastHost(dstHost))
     && ((sessionType == IPPROTO_TCP)
	 /* Simulate a TCP connection for the SIP protocol */
	 || (((sport == IP_UDP_PORT_SIP) && (dport == IP_UDP_PORT_SIP)
	      || ((sport > 1024) && (dport > 1024)) /* Needed for SIP */))
	 || (((sport == IP_TCP_PORT_SCCP) && (dport > 1024)
	      || ((sport > 1024) && (dport == IP_TCP_PORT_SCCP)) /* Needed for SCCP */))
	 )) {
    theSession = handleTCPSession(h, fragmentedData, tcpWin, srcHost, sport,
				  dstHost, dport, length, tp, packetDataLength,
				   packetData, actualDeviceId, newSession);
  } else if(sessionType == IPPROTO_UDP) {
    /* We don't create any permanent structures for UDP sessions */
    handleUDPSession(h, fragmentedData, srcHost, sport, dstHost, dport,
		      length, packetData, actualDeviceId, newSession);
  }

  if((sport == IP_L4_PORT_ECHO)       || (dport == IP_L4_PORT_ECHO)
     || (sport == IP_L4_PORT_DISCARD) || (dport == IP_L4_PORT_DISCARD)
     || (sport == IP_L4_PORT_DAYTIME) || (dport == IP_L4_PORT_DAYTIME)
     || (sport == IP_L4_PORT_CHARGEN) || (dport == IP_L4_PORT_CHARGEN)
     ) {
    char *fmt = "Detected traffic [%s:%d] -> [%s:%d] on "
      "a diagnostic port (network mapping attempt?)";

    if(myGlobals.runningPref.enableSuspiciousPacketDump) {
      traceEvent(CONST_TRACE_WARNING, fmt,
		 srcHost->hostResolvedName, sport,
		 dstHost->hostResolvedName, dport);
      dumpSuspiciousPacket(actualDeviceId);
    }

    if((dport == IP_L4_PORT_ECHO)
       || (dport == IP_L4_PORT_DISCARD)
       || (dport == IP_L4_PORT_DAYTIME)
       || (dport == IP_L4_PORT_CHARGEN)) {
      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      if(sessionType == IPPROTO_UDP) {
	incrementUsageCounter(&srcHost->secHostPkts->udpToDiagnosticPortSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->udpToDiagnosticPortRcvd, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.udpToDiagnosticPort, 1);
      } else {
	incrementUsageCounter(&srcHost->secHostPkts->tcpToDiagnosticPortSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->tcpToDiagnosticPortRcvd, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.tcpToDiagnosticPort, 1);
      }
    } else /* sport == 7 */ {
      allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
      if(sessionType == IPPROTO_UDP) {
	incrementUsageCounter(&srcHost->secHostPkts->udpToDiagnosticPortSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->udpToDiagnosticPortRcvd, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.udpToDiagnosticPort, 1);
      } else {
	incrementUsageCounter(&srcHost->secHostPkts->tcpToDiagnosticPortSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->tcpToDiagnosticPortRcvd, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.tcpToDiagnosticPort, 1);
      }
    }
  }

  if(fragmentedData && (packetDataLength <= 128)) {
    char *fmt = "Detected tiny fragment (%d bytes) "
      "[%s:%d] -> [%s:%d] (network mapping attempt?)";
    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    incrementUsageCounter(&srcHost->secHostPkts->tinyFragmentSent, dstHost, actualDeviceId);
    incrementUsageCounter(&dstHost->secHostPkts->tinyFragmentRcvd, srcHost, actualDeviceId);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.tinyFragment, 1);

    if(myGlobals.runningPref.enableSuspiciousPacketDump) {
      traceEvent(CONST_TRACE_WARNING, fmt, packetDataLength,
		 srcHost->hostResolvedName, sport,
		 dstHost->hostResolvedName, dport);
      dumpSuspiciousPacket(actualDeviceId);
    }
  }

  return(theSession);
}

/* ******************* */

static int getScsiCmdType(u_char scsiCmd, u_int32_t *ioSize, const u_char *bp) {
  int cmdType;

  *ioSize = 0;

  switch (scsiCmd) {
  case SCSI_SBC2_READ6:
    cmdType = SCSI_READ_CMD;
    *ioSize = (u_int32_t)bp[16];
    break;
  case SCSI_SBC2_READ10:
    cmdType = SCSI_READ_CMD;
    *ioSize = ntohs (*(u_short *)&bp[19]);
    break;
  case SCSI_SBC2_READ12:
    cmdType = SCSI_READ_CMD;
    *ioSize = ntohl (*(u_int32_t *)&bp[18]);
    break;
  case SCSI_SBC2_READ16:
    cmdType = SCSI_READ_CMD;
    *ioSize = ntohl (*(u_int32_t *)&bp[22]);
    break;
  case SCSI_SBC2_WRITE6:
    cmdType = SCSI_WR_CMD;
    *ioSize = (u_int32_t)bp[16];
    break;
  case SCSI_SBC2_WRITE10:
    cmdType = SCSI_WR_CMD;
    *ioSize = ntohs (*(u_short *)&bp[19]);
    break;
  case SCSI_SBC2_WRITE12:
    cmdType = SCSI_WR_CMD;
    *ioSize = ntohl (*(u_int32_t *)&bp[18]);
    break;
  case SCSI_SBC2_WRITE16:
    cmdType = SCSI_WR_CMD;
    *ioSize = ntohl (*(u_int32_t *)&bp[22]);
    break;
  default:
    cmdType = SCSI_NONRDWR_CMD;
    break;
  }

  return (cmdType);
}

static int getScsiLunCmdInfo (FCSession *theSession, u_int16_t *lun,
                              u_char *cmd, u_int16_t oxid)
{
  u_int16_t i;

  if (theSession->lastScsiOxid == oxid) {
    /* simple match */
    *lun = theSession->lastLun;
    *cmd = theSession->lastScsiCmd;

    return (TRUE);
  }

  /* Search through the LUN set to identify matching command */
  /* TBD: Need to fix this as it can be quite slow if a data has no matching
   * cmd in the capture such as if the capture began in the middle of a large
   * transfer.
   */
  for (i = 0; i < MAX_LUNS_SUPPORTED; i++) {
    if (theSession->activeLuns[i] != NULL) {
      if (theSession->activeLuns[i]->lastOxid == oxid) {
	*lun = i;
	*cmd = theSession->activeLuns[i]->lastScsiCmd;

	return (TRUE);
      }
    }
  }

  return (FALSE);
}

static void scsiSetMinMaxRTT (struct timeval *rtt, struct timeval *minRTT,
                              struct timeval *maxRTT)
{
  if (rtt->tv_sec > maxRTT->tv_sec) {
    *maxRTT = *rtt;
  }
  else if ((rtt->tv_sec == maxRTT->tv_sec) &&
	   (rtt->tv_usec > maxRTT->tv_usec)) {
    *maxRTT = *rtt;
  }

  if ((rtt->tv_sec < minRTT->tv_sec) ||
      ((minRTT->tv_sec == 0) &&
       (minRTT->tv_usec == 0))) {
    *minRTT = *rtt;
  }
  else if ((rtt->tv_sec == minRTT->tv_sec) &&
	   (rtt->tv_usec < minRTT->tv_usec)) {
    *minRTT = *rtt;
  }
}

static void processScsiPkt(const struct pcap_pkthdr *h,
                           HostTraffic *srcHost, HostTraffic *dstHost,
                           u_int length, u_int payload_len, u_short oxid,
                           u_short rxid, u_char rCtl, u_char isXchgOrig,
                           const u_char *bp, FCSession *theSession,
                           int actualDeviceId)
{
  u_char cmd, status, task_mgmt;
  struct timeval rtt;
  u_int16_t lun;
  u_int32_t xferRdySize, ioSize, duration = 0, hostDur = 0, iops;
  int iocmdType;
  ScsiLunTrafficInfo *lunStats = NULL,
    *hostLunStats = NULL;

  if((srcHost == NULL) || (dstHost == NULL)) {
    traceEvent(CONST_TRACE_ERROR, "Sanity check failed (3) [Low memory?]");
    return;
  }

  /* This field distinguishes between diff FCP frame types */
  rCtl &= 0xF;

  /*
   * Increment session counters.
   */
  if (isXchgOrig) {
    incrementTrafficCounter (&theSession->fcpBytesSent, length);
  }
  else {
    incrementTrafficCounter (&theSession->fcpBytesRcvd, length);
  }

  if (rCtl != FCP_IU_CMD) {

    /* Get the last SCSI Cmd, LUN matching this {VSAN, S_ID, D_ID, OX_ID}
       tuple */
    if (!getScsiLunCmdInfo (theSession, &lun, &cmd, oxid)) {
      /* No matching command/lun found. Skip */
      if (isXchgOrig) {
	incrementTrafficCounter (&theSession->unknownLunBytesSent,
				 length);
      }
      else {
	incrementTrafficCounter (&theSession->unknownLunBytesRcvd,
				 length);
      }
      return;
    }
    lunStats = theSession->activeLuns[lun];
    if (lunStats == NULL) {
      /* No LUN structure has been allocated for this LUN yet. This means
       * it cannot be tracked as well. So, just return.
       */
      if (isXchgOrig) {
	incrementTrafficCounter (&theSession->unknownLunBytesSent,
				 length);
      }
      else {
	incrementTrafficCounter (&theSession->unknownLunBytesRcvd,
				 length);
      }
      return;
    }

    if (theSession->initiator == srcHost) {
      hostLunStats = dstHost->fcCounters->activeLuns[lun];
    }
    else {
      hostLunStats = srcHost->fcCounters->activeLuns[lun];
    }

    if (hostLunStats == NULL) {
      /* No LUN structure has been allocated for this LUN yet. This means
       * it cannot be tracked as well. So, just return.
       */
      if (isXchgOrig) {
	incrementTrafficCounter (&theSession->unknownLunBytesSent,
				 length);
      }
      else {
	incrementTrafficCounter (&theSession->unknownLunBytesRcvd,
				 length);
      }
      return;
    }
  }

  switch (rCtl) {
  case FCP_IU_CMD:
    srcHost->fcCounters->devType = SCSI_DEV_INITIATOR;
    if (dstHost->fcCounters->devType == SCSI_DEV_UNINIT) {
      dstHost->fcCounters->devType = myGlobals.scsiDefaultDevType;
    }

    if (bp[0] != 0) {
      /* We have a multi-level LUN, lets see more before we give up */
      if (bp[2] != 0) {
	traceEvent (CONST_TRACE_WARNING, "Have a multi-level LUN for %s,"
		    "so stats can be tracked for this LUN.\n",
		    dstHost->fcCounters->hostNumFcAddress);
	if (isXchgOrig) {
	  incrementTrafficCounter (&theSession->unknownLunBytesSent,
				   length);
	}
	else {
	  incrementTrafficCounter (&theSession->unknownLunBytesRcvd,
				   length);
	}
	return;
      }
      else {
	lun = ntohs (*(u_int16_t *)&bp[0]);
      }
    }
    else {
      lun = (u_int16_t)bp[1]; /* 2nd byte alone has LUN info */
    }

    if (lun > MAX_LUNS_SUPPORTED) {
      traceEvent (CONST_TRACE_WARNING, "Cannot track LUNs > %d (for %s),"
		  "so stats can be tracked for this LUN.\n",
		  MAX_LUNS_SUPPORTED, dstHost->fcCounters->hostNumFcAddress);
      if (isXchgOrig) {
	incrementTrafficCounter (&theSession->unknownLunBytesSent,
				 length);
      }
      else {
	incrementTrafficCounter (&theSession->unknownLunBytesRcvd,
				 length);
      }
      return;
    }

    /* Check if LUN structure is allocated */
    if (theSession->activeLuns[lun] == NULL) {
      theSession->activeLuns[lun] = (ScsiLunTrafficInfo *)malloc (sizeof (ScsiLunTrafficInfo));
      if (theSession->activeLuns[lun] == NULL) {
	traceEvent (CONST_TRACE_ERROR, "Unable to allocate LUN for %d:%s\n",
		    lun, dstHost->fcCounters->hostNumFcAddress);
	if (isXchgOrig) {
	  incrementTrafficCounter (&theSession->unknownLunBytesSent,
				   length);
	}
	else {
	  incrementTrafficCounter (&theSession->unknownLunBytesRcvd,
				   length);
	}
	return;
      }
      memset ((char *)theSession->activeLuns[lun], 0,
	      sizeof (ScsiLunTrafficInfo));
      theSession->activeLuns[lun]->firstSeen.tv_sec = h->ts.tv_sec;
      theSession->activeLuns[lun]->firstSeen.tv_usec = h->ts.tv_usec;
      theSession->activeLuns[lun]->lastIopsTime.tv_sec = h->ts.tv_sec;
      theSession->activeLuns[lun]->lastIopsTime.tv_usec = h->ts.tv_usec;
    }

    if (lun > theSession->lunMax) {
      theSession->lunMax = lun;
    }

    /* Also allocate LUN stats structure in the host data structure */
    if (theSession->initiator == srcHost) {
      if (dstHost->fcCounters->activeLuns[lun] == NULL) {
	dstHost->fcCounters->activeLuns[lun] = (ScsiLunTrafficInfo *)malloc (sizeof (ScsiLunTrafficInfo));

	if (dstHost->fcCounters->activeLuns[lun] == NULL) {
	  traceEvent (CONST_TRACE_ERROR, "Unable to allocate host LUN for %d:%s\n",
		      lun, dstHost->fcCounters->hostNumFcAddress);
	  if (isXchgOrig) {
	    incrementTrafficCounter (&theSession->unknownLunBytesSent,
				     length);
	  }
	  else {
	    incrementTrafficCounter (&theSession->unknownLunBytesRcvd,
				     length);
	  }
	  return;
	}
	memset ((char *)dstHost->fcCounters->activeLuns[lun], 0,
		sizeof (ScsiLunTrafficInfo));
	dstHost->fcCounters->activeLuns[lun]->firstSeen.tv_sec = h->ts.tv_sec;
	dstHost->fcCounters->activeLuns[lun]->firstSeen.tv_usec = h->ts.tv_usec;
	dstHost->fcCounters->activeLuns[lun]->lastIopsTime.tv_sec = h->ts.tv_sec;
	dstHost->fcCounters->activeLuns[lun]->lastIopsTime.tv_usec = h->ts.tv_usec;
      }
      hostLunStats = dstHost->fcCounters->activeLuns[lun];
    }
    else {
      if (srcHost->fcCounters->activeLuns[lun] == NULL) {
	srcHost->fcCounters->activeLuns[lun] = (ScsiLunTrafficInfo *)malloc (sizeof (ScsiLunTrafficInfo));
	if (srcHost->fcCounters->activeLuns[lun] == NULL) {
	  traceEvent (CONST_TRACE_ERROR, "Unable to allocate host LUN for %d:%s\n",
		      lun, srcHost->fcCounters->hostNumFcAddress);
	  if (isXchgOrig) {
	    incrementTrafficCounter (&theSession->unknownLunBytesSent,
				     length);
	  }
	  else {
	    incrementTrafficCounter (&theSession->unknownLunBytesRcvd,
				     length);
	  }
	  return;
	}
	memset ((char *)srcHost->fcCounters->activeLuns[lun], 0, sizeof (ScsiLunTrafficInfo));
	srcHost->fcCounters->activeLuns[lun]->firstSeen.tv_sec = h->ts.tv_sec;
	srcHost->fcCounters->activeLuns[lun]->firstSeen.tv_usec = h->ts.tv_usec;
	srcHost->fcCounters->activeLuns[lun]->lastIopsTime.tv_sec = h->ts.tv_sec;
	srcHost->fcCounters->activeLuns[lun]->lastIopsTime.tv_usec = h->ts.tv_usec;
      }
      hostLunStats = srcHost->fcCounters->activeLuns[lun];
    }

    lunStats = theSession->activeLuns[lun];
    if ((duration = h->ts.tv_sec - lunStats->lastIopsTime.tv_sec) >= 1) {
      /* compute iops every sec at least */
      iops = (float) (lunStats->cmdsFromLastIops/duration);

      if (iops > lunStats->maxIops) {
	lunStats->maxIops = iops;
      }

      if (iops &&
	  ((iops < lunStats->minIops) || (lunStats->minIops == 0))) {
	lunStats->minIops = iops;
      }

      lunStats->cmdsFromLastIops = 0;
      lunStats->lastIopsTime.tv_sec = h->ts.tv_sec;
      lunStats->lastIopsTime.tv_usec = h->ts.tv_usec;
    }
    else {
      lunStats->cmdsFromLastIops++;
    }

    if ((hostDur = h->ts.tv_sec - hostLunStats->lastIopsTime.tv_sec) >= 1) {
      iops = (float) hostLunStats->cmdsFromLastIops/hostDur;

      if (iops > hostLunStats->maxIops) {
	hostLunStats->maxIops = iops;
      }

      if (iops &&
	  ((iops < hostLunStats->minIops) || (hostLunStats->minIops == 0))) {
	hostLunStats->minIops = iops;
      }
      hostLunStats->cmdsFromLastIops = 0;
      hostLunStats->lastIopsTime.tv_sec = h->ts.tv_sec;
      hostLunStats->lastIopsTime.tv_usec = h->ts.tv_usec;
    }
    else {
      hostLunStats->cmdsFromLastIops++;
    }

    lunStats->lastSeen.tv_sec = hostLunStats->lastSeen.tv_sec = h->ts.tv_sec;
    lunStats->lastSeen.tv_usec = hostLunStats->lastSeen.tv_usec = h->ts.tv_usec;
    lunStats->reqTime.tv_sec = hostLunStats->reqTime.tv_sec = h->ts.tv_sec;
    lunStats->reqTime.tv_usec = hostLunStats->reqTime.tv_usec = h->ts.tv_usec;

    cmd = theSession->lastScsiCmd = lunStats->lastScsiCmd = bp[12];
    iocmdType = getScsiCmdType (cmd, &ioSize, bp);

    if (cmd == SCSI_SPC2_INQUIRY) {
      /* Check if this is a general inquiry or page inquiry */
      if (bp[13] & 0x1) {
	theSession->lastScsiCmd = SCSI_SPC2_INQUIRY_EVPD;
      }
    }
    theSession->lastScsiOxid = lunStats->lastOxid = oxid;
    theSession->lastLun = lun;

    if (iocmdType == SCSI_READ_CMD) {
      incrementTrafficCounter (&theSession->numScsiRdCmd, 1);
      incrementTrafficCounter (&lunStats->numScsiRdCmd, 1);
      incrementTrafficCounter (&hostLunStats->numScsiRdCmd, 1);

      lunStats->frstRdDataRcvd = TRUE;
      hostLunStats->frstRdDataRcvd = TRUE;

      /* Session-specific Stats */
      if (ioSize > lunStats->maxRdSize) {
	lunStats->maxRdSize = ioSize;
      }

      if ((ioSize < lunStats->minRdSize) || (!lunStats->minRdSize)) {
	lunStats->minRdSize = ioSize;
      }

      /* LUN-specific Stats */
      if (ioSize > hostLunStats->maxRdSize) {
	hostLunStats->maxRdSize = ioSize;
      }

      if ((ioSize < hostLunStats->minRdSize) || (!hostLunStats->minRdSize)) {
	hostLunStats->minRdSize = ioSize;
      }
    }
    else if (iocmdType == SCSI_WR_CMD) {
      incrementTrafficCounter (&theSession->numScsiWrCmd, 1);
      incrementTrafficCounter (&lunStats->numScsiWrCmd, 1);
      incrementTrafficCounter (&hostLunStats->numScsiWrCmd, 1);

      lunStats->frstWrDataRcvd = TRUE;
      hostLunStats->frstWrDataRcvd = TRUE;

      /* Session-specific Stats */
      if (ioSize > lunStats->maxWrSize) {
	lunStats->maxWrSize = ioSize;
      }

      if ((ioSize < lunStats->minWrSize) || (!lunStats->minWrSize)) {
	lunStats->minWrSize = ioSize;
      }

      /* LUN-specific Stats */
      if (ioSize > hostLunStats->maxWrSize) {
	hostLunStats->maxWrSize = ioSize;
      }

      if ((ioSize < hostLunStats->minWrSize) || (!hostLunStats->minWrSize)) {
	hostLunStats->minWrSize = ioSize;
      }
    }
    else {
      incrementTrafficCounter (&theSession->numScsiOtCmd, 1);
      incrementTrafficCounter (&lunStats->numScsiOtCmd, 1);
      incrementTrafficCounter (&hostLunStats->numScsiOtCmd, 1);
    }

    if ((task_mgmt = bp[10]) != 0) {
      switch (task_mgmt) {
      case SCSI_TM_ABORT_TASK_SET:
	lunStats->abrtTaskSetCnt++;
	hostLunStats->abrtTaskSetCnt++;
	break;

      case SCSI_TM_CLEAR_TASK_SET:
	lunStats->clearTaskSetCnt++;
	hostLunStats->clearTaskSetCnt++;
	break;

      case SCSI_TM_LUN_RESET:
	lunStats->lunRstCnt++;
	hostLunStats->lunRstCnt++;
	lunStats->lastLunRstTime = myGlobals.actTime;
	hostLunStats->lastLunRstTime = myGlobals.actTime;
	break;

      case SCSI_TM_TARGET_RESET:
	lunStats->tgtRstCnt++;
	hostLunStats->tgtRstCnt++;
	lunStats->lastTgtRstTime = myGlobals.actTime;
	hostLunStats->lastTgtRstTime = myGlobals.actTime;
	break;

      case SCSI_TM_CLEAR_ACA:
	lunStats->clearAcaCnt++;
	hostLunStats->clearAcaCnt++;
	break;
      }
    }

    if (theSession->initiator == srcHost) {
      incrementTrafficCounter (&(lunStats->bytesSent), length);
      lunStats->pktSent++;

      incrementTrafficCounter (&hostLunStats->bytesRcvd, length);
      hostLunStats->pktRcvd++;
    }
    else {
      incrementTrafficCounter (&lunStats->bytesRcvd, length);
      lunStats->pktRcvd++;

      incrementTrafficCounter (&hostLunStats->bytesSent, length);
      hostLunStats->pktSent++;
    }

    break;
  case FCP_IU_DATA:
    switch (cmd) {
    case SCSI_SPC2_INQUIRY:

      /* verify that we don't copy info for a non-existent LUN */
      if ((bp[0] & 0xE0) == 0x30) {
	traceEvent (CONST_TRACE_WARNING, "processScsiPkt: Invalid LUN ignored\n");
      }
      else {
	if ((bp[0]&0x1F) == SCSI_DEV_NODEV) {
	  lunStats->invalidLun = TRUE;
	  hostLunStats->invalidLun = TRUE;
	}
	else {
	  srcHost->fcCounters->devType = bp[0]&0x1F;
	}

	if (length >= 24+8) {
	  strncpy((char*)srcHost->fcCounters->vendorId, (char*)&bp[8], 8);
	}
	if (length >= 24+8+16) {
	  strncpy((char*)srcHost->fcCounters->productId, (char*)&bp[16], 16);
	}
	if (length >= 24+8+16+4) {
	  strncpy((char*)srcHost->fcCounters->productRev, (char*)&bp[32], 4);
	}
      }
      break;
#ifdef NOTYET
    case SCSI_SPC2_REPORTLUNS:
      listlen = ntohl (*(int32_t *)&bp[0]);
      offset = 4;

      if (listlen > (length-24)) {
	listlen = length-24;
      }

      while ((listlen > 0) && (listlen > offset)) {
	if (bp[offset] != 0) {
	  srcHost->lunsGt256 = TRUE;
	}
	listlen -= 8;
	offset += 8;
      }

      break;
    case SCSI_SBC2_READCAPACITY:
      break;
#endif
    }

    iocmdType = getScsiCmdType (lunStats->lastScsiCmd, &ioSize, bp);

    if (iocmdType == SCSI_READ_CMD) {
      incrementTrafficCounter (&lunStats->scsiRdBytes, payload_len);
      incrementTrafficCounter (&hostLunStats->scsiRdBytes, payload_len);

      if (lunStats->frstRdDataRcvd) {
	lunStats->frstRdDataRcvd = FALSE;
	rtt.tv_sec = h->ts.tv_sec - lunStats->reqTime.tv_sec;
	rtt.tv_usec = h->ts.tv_usec - lunStats->reqTime.tv_usec;

	scsiSetMinMaxRTT (&rtt, &lunStats->minRdFrstDataRTT,
			  &lunStats->maxRdFrstDataRTT);
	scsiSetMinMaxRTT (&rtt, &hostLunStats->minRdFrstDataRTT,
			  &hostLunStats->maxRdFrstDataRTT);
      }
    }
    else if (iocmdType == SCSI_WR_CMD) {
      incrementTrafficCounter (&lunStats->scsiWrBytes, payload_len);
      incrementTrafficCounter (&hostLunStats->scsiWrBytes, payload_len);

      if (lunStats->frstWrDataRcvd) {
	lunStats->frstWrDataRcvd = FALSE;
	rtt.tv_sec = h->ts.tv_sec - lunStats->reqTime.tv_sec;
	rtt.tv_usec = h->ts.tv_usec - lunStats->reqTime.tv_usec;

	scsiSetMinMaxRTT (&rtt, &lunStats->minWrFrstDataRTT,
			  &lunStats->maxWrFrstDataRTT);
	scsiSetMinMaxRTT (&rtt, &hostLunStats->minWrFrstDataRTT,
			  &hostLunStats->maxWrFrstDataRTT);
      }
    }
    else {
      incrementTrafficCounter (&lunStats->scsiOtBytes, payload_len);
      incrementTrafficCounter (&hostLunStats->scsiOtBytes, payload_len);
    }

    if (theSession->initiator == srcHost) {
      incrementTrafficCounter (&(lunStats->bytesSent), length);
      lunStats->pktSent++;

      incrementTrafficCounter (&(hostLunStats->bytesRcvd), length);
      hostLunStats->pktRcvd++;
    }
    else {
      incrementTrafficCounter (&lunStats->bytesRcvd, length);
      lunStats->pktRcvd++;

      incrementTrafficCounter (&hostLunStats->bytesSent, length);
      hostLunStats->pktSent++;
    }

    break;
  case FCP_IU_XFER_RDY:
    xferRdySize = ntohl (*(u_int32_t *)&bp[4]);

    if (xferRdySize > lunStats->maxXferRdySize) {
      lunStats->maxXferRdySize = xferRdySize;
    }
    else if ((lunStats->minXferRdySize > xferRdySize) ||
	     (!lunStats->minXferRdySize)) {
      lunStats->minXferRdySize = xferRdySize;
    }

    if (xferRdySize > hostLunStats->maxXferRdySize) {
      hostLunStats->maxXferRdySize = xferRdySize;
    }
    else if ((hostLunStats->minXferRdySize > xferRdySize) ||
	     (!hostLunStats->minXferRdySize)) {
      hostLunStats->minXferRdySize = xferRdySize;
    }

    if (theSession->initiator == srcHost) {
      incrementTrafficCounter (&(lunStats->bytesSent), length);
      lunStats->pktSent++;

      incrementTrafficCounter (&(hostLunStats->bytesRcvd), length);
      hostLunStats->pktRcvd++;
    }
    else {
      incrementTrafficCounter (&lunStats->bytesRcvd, length);
      lunStats->pktRcvd++;

      incrementTrafficCounter (&hostLunStats->bytesSent, length);
      hostLunStats->pktSent++;
    }

    if (lunStats->frstWrDataRcvd) {
      rtt.tv_sec = h->ts.tv_sec - lunStats->reqTime.tv_sec;
      rtt.tv_usec = h->ts.tv_usec - lunStats->reqTime.tv_usec;

      scsiSetMinMaxRTT (&rtt, &lunStats->minXfrRdyRTT,
			&lunStats->maxXfrRdyRTT);
      scsiSetMinMaxRTT (&rtt, &hostLunStats->minXfrRdyRTT,
			&hostLunStats->maxXfrRdyRTT);
    }

    break;
  case FCP_IU_RSP:
    rtt.tv_sec = h->ts.tv_sec - lunStats->reqTime.tv_sec;
    rtt.tv_usec = h->ts.tv_usec - lunStats->reqTime.tv_usec;

    status = bp[11];

    if (status != SCSI_STATUS_GOOD) {
      /* TBD: Some failures are notifications; verify & flag real errors
       * only
       */
      lunStats->numFailedCmds++;
      hostLunStats->numFailedCmds++;

      if (myGlobals.runningPref.enableSuspiciousPacketDump) {
	dumpSuspiciousPacket (actualDeviceId);
      }

      switch (status) {
      case SCSI_STATUS_CHK_CONDITION:
	lunStats->chkCondCnt++;
	hostLunStats->chkCondCnt++;
	break;

      case SCSI_STATUS_BUSY:
	lunStats->busyCnt++;
	hostLunStats->busyCnt++;
	break;

      case SCSI_STATUS_RESV_CONFLICT:
	lunStats->resvConflictCnt++;
	hostLunStats->resvConflictCnt++;
	break;

      case SCSI_STATUS_TASK_SET_FULL:
	lunStats->taskSetFullCnt++;
	hostLunStats->taskSetFullCnt++;
	break;

      case SCSI_STATUS_TASK_ABORTED:
	lunStats->taskAbrtCnt++;
	hostLunStats->taskAbrtCnt++;
	break;

      default:
	lunStats->otherStatusCnt++;
	hostLunStats->otherStatusCnt++;
	break;
      }
    }

    if (theSession->initiator == srcHost) {
      incrementTrafficCounter (&(lunStats->bytesSent), length);
      lunStats->pktSent++;

      incrementTrafficCounter (&hostLunStats->bytesRcvd, length);
      hostLunStats->pktRcvd++;
    }
    else {
      incrementTrafficCounter (&lunStats->bytesRcvd, length);
      lunStats->pktRcvd++;

      incrementTrafficCounter (&(hostLunStats->bytesSent), length);
      hostLunStats->pktSent++;
    }

    scsiSetMinMaxRTT (&rtt, &lunStats->minRTT, &lunStats->maxRTT);
    scsiSetMinMaxRTT (&rtt, &hostLunStats->minRTT, &hostLunStats->maxRTT);

    break;

  default:
    break;
  }
}

static void processSwRscn (const u_char *bp, u_short vsanId, int actualDeviceId)
{
  u_char event;
  FcAddress affectedId;
  HostTraffic *affectedHost;
  u_int detectFn;

  if ((detectFn = ntohl (*(u_int32_t *)&bp[8])) == FC_SW_RSCN_FABRIC_DETECT) {
    /* Only fabric-detected events have online/offline events */
    event = bp[4] & 0xF0;

    if (!event) {
      /* return as this is not an online/offline event */
      return;
    }

    affectedId.domain = bp[5];
    affectedId.area = bp[6];
    affectedId.port = bp[7];

    if ((affectedHost = lookupFcHost (&affectedId, vsanId,
				      actualDeviceId)) != NULL) {
      if (event == FC_SW_RSCN_PORT_ONLINE) {
	affectedHost->fcCounters->lastOnlineTime = myGlobals.actTime;
      }
      else if (event == FC_SW_RSCN_PORT_OFFLINE) {
	affectedHost->fcCounters->lastOfflineTime = myGlobals.actTime;
	incrementTrafficCounter (&affectedHost->fcCounters->numOffline, 1);
      }
    }
  }
}

FCSession* handleFcSession(const struct pcap_pkthdr *h,
			   u_short fragmentedData,
			   HostTraffic *srcHost, HostTraffic *dstHost,
			   u_int length, u_int payload_len, u_short oxid,
			   u_short rxid, u_short protocol, u_char rCtl,
			   u_char isXchgOrig, const u_char *bp,
			   int actualDeviceId)
{
  u_int idx;
  FCSession *theSession = NULL, *prevSession;
  char addedNewEntry = 0;
  u_short found=0;
  char cmd;
  FcFabricElementHash *hash;
  u_char opcode;
  u_char gs_type, gs_stype;

  if(!myGlobals.runningPref.enableSessionHandling)
    return(NULL);

  if((srcHost == NULL) || (dstHost == NULL)) {
    traceEvent(CONST_TRACE_ERROR, "Sanity check failed (3) [Low memory?]");
    return(NULL);
  }

  if ((srcHost->fcCounters->vsanId > MAX_VSANS) || (dstHost->fcCounters->vsanId > MAX_VSANS)) {
    traceEvent (CONST_TRACE_WARNING, "Not following session for invalid"
		" VSAN pair %d:%d", srcHost->fcCounters->vsanId, dstHost->fcCounters->vsanId);
    return (NULL);
  }

  /*
   * The hash key has to be calculated such that its value has to be the same
   * regardless of the flow direction.
   */
  idx = (u_int)(((*(u_int32_t *)&srcHost->fcCounters->hostFcAddress) +
		 (*(u_int32_t *)&dstHost->fcCounters->hostFcAddress)) +
		srcHost->fcCounters->vsanId + dstHost->fcCounters->vsanId);

  idx %= MAX_TOT_NUM_SESSIONS;

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.fcSessionsMutex, "handleFcSession");
#endif

  prevSession = theSession = myGlobals.device[actualDeviceId].fcSession[idx];

  while(theSession != NULL) {
    if(theSession && (theSession->next == theSession)) {
      traceEvent(CONST_TRACE_WARNING, "Internal Error (4) (idx=%d)", idx);
      theSession->next = NULL;
    }

    if((theSession->initiator == srcHost)
       && (theSession->remotePeer == dstHost)) {
      found = 1;
      break;
    } else if ((theSession->initiator == dstHost)
	       && (theSession->remotePeer == srcHost)) {
      found = 1;
      break;
    } else {
      prevSession = theSession;
      theSession  = theSession->next;
    }
  } /* while */

  if(!found) {
    /* New Session */
#ifdef DEBUG
    printf("DEBUG: NEW ");

    traceEvent(CONST_TRACE_INFO, "DEBUG: FC hash [act size: %d]",
	       myGlobals.device[actualDeviceId].numFcSessions);
#endif

    /* We don't check for space here as the datastructure allows
       ntop to store sessions as needed
    */
#ifdef PARM_USE_SESSIONS_CACHE
    /* There's enough space left in the hashtable */
    /* Verify this doesn't break anything in FC. This section hasn't been
     * tested
     */
    if(myGlobals.sessionsCacheLen > 0) {
      theSession = myGlobals.fcsessionsCache[--myGlobals.sessionsCacheLen];
      myGlobals.sessionsCacheReused++;
      /*
	traceEvent(CONST_TRACE_INFO, "Fetched session from pointers cache (len=%d)",
	(int)myGlobals.sessionsCacheLen);
      */
    } else
#endif
      if ( (theSession = (FCSession*)malloc(sizeof(FCSession))) == NULL) return(NULL);

    memset(theSession, 0, sizeof(FCSession));
    addedNewEntry = 1;

    theSession->magic = CONST_MAGIC_NUMBER;

    theSession->initiatorAddr = srcHost->fcCounters->hostFcAddress;
    theSession->remotePeerAddr = dstHost->fcCounters->hostFcAddress;

#ifdef SESSION_TRACE_DEBUG
    traceEvent(CONST_TRACE_INFO, "SESSION_TRACE_DEBUG: New FC session [%s] <-> [%s] (# sessions = %d)",
	       dstHost->fcCounters->hostNumFcAddress,
	       srcHost->fcCounters->hostNumFcAddress,
	       myGlobals.device[actualDeviceId].numFcSessions);
#endif

    myGlobals.device[actualDeviceId].numFcSessions++;

    if(myGlobals.device[actualDeviceId].numFcSessions > myGlobals.device[actualDeviceId].maxNumFcSessions)
      myGlobals.device[actualDeviceId].maxNumFcSessions = myGlobals.device[actualDeviceId].numFcSessions;

    if ((myGlobals.device[actualDeviceId].fcSession[idx] != NULL) &&
	(myGlobals.device[actualDeviceId].fcSession[idx]->magic != CONST_MAGIC_NUMBER)) {
      traceEvent(CONST_TRACE_WARNING, "handleFcSession: Internal Error (4) (idx=%d)",
		 idx);
      theSession->next = NULL;
    }
    else {
      theSession->next = myGlobals.device[actualDeviceId].fcSession[idx];
    }
    myGlobals.device[actualDeviceId].fcSession[idx] = theSession;

    if (isXchgOrig) {
      theSession->initiator = srcHost;
      theSession->remotePeer = dstHost;
    }
    else {
      theSession->initiator = dstHost;
      theSession->remotePeer = srcHost;
    }
    theSession->firstSeen.tv_sec = h->ts.tv_sec;
    theSession->firstSeen.tv_usec = h->ts.tv_usec;
    theSession->sessionState = FLAG_STATE_ACTIVE;
    theSession->deviceId = actualDeviceId;
    theSession->initiator->numHostSessions++;
    theSession->remotePeer->numHostSessions++;
  }

  theSession->lastSeen.tv_sec = h->ts.tv_sec;
  theSession->lastSeen.tv_usec = h->ts.tv_usec;

  /* Typically in FC, the exchange originator is always the same entity in a
   * flow
   */
  if (isXchgOrig) {
    incrementTrafficCounter (&(theSession->bytesSent), length);
    theSession->pktSent++;
  }
  else {
    incrementTrafficCounter (&theSession->bytesRcvd, length);
    theSession->pktRcvd++;
  }

  switch (protocol) {
  case FC_FTYPE_SCSI:
    processScsiPkt (h, srcHost, dstHost, length, payload_len, oxid, rxid,
		    rCtl, isXchgOrig, bp, theSession, actualDeviceId);

    break;
  case FC_FTYPE_ELS:
    cmd = bp[0];

    if ((theSession->lastElsCmd == FC_ELS_CMD_PLOGI) && (cmd == FC_ELS_CMD_ACC)) {
      fillFcHostInfo (bp, srcHost);
    }
    else if ((theSession->lastElsCmd == FC_ELS_CMD_LOGO) && (cmd == FC_ELS_CMD_ACC)) {
      theSession->sessionState = FLAG_STATE_END;
    }

    if (isXchgOrig) {
      incrementTrafficCounter (&theSession->fcElsBytesSent, length);
    }
    else {
      incrementTrafficCounter (&theSession->fcElsBytesRcvd, length);
    }

    theSession->lastElsCmd = cmd;

    break;
  case FC_FTYPE_FCCT:
    gs_type = bp[4];
    gs_stype = bp[5];

    if (((gs_type == FCCT_GSTYPE_DIRSVC) && (gs_stype == FCCT_GSSUBTYPE_DNS)) ||
	((gs_type == FCCT_GSTYPE_MGMTSVC) && (gs_stype == FCCT_GSSUBTYPE_UNS))) {
      if (isXchgOrig) {
	incrementTrafficCounter (&theSession->fcDnsBytesSent, length);
      }
      else {
	incrementTrafficCounter (&theSession->fcDnsBytesRcvd, length);
      }
    }
    else {
      if (isXchgOrig) {
	incrementTrafficCounter (&theSession->otherBytesSent, length);
      }
      else {
	incrementTrafficCounter (&theSession->otherBytesRcvd, length);
      }
    }
    break;
  case FC_FTYPE_SWILS:
  case FC_FTYPE_SWILS_RSP:

    if (isXchgOrig) {
      incrementTrafficCounter (&theSession->fcSwilsBytesSent, length);
    }
    else {
      incrementTrafficCounter (&theSession->fcSwilsBytesRcvd, length);
    }

    hash = getFcFabricElementHash (srcHost->fcCounters->vsanId, actualDeviceId);
    if (hash == NULL) {
      break;
    }
    if (protocol == FC_FTYPE_SWILS) {
      theSession->lastSwilsOxid = oxid;
      theSession->lastSwilsCmd = bp[0];
      opcode = bp[0];
    }
    else if (oxid == theSession->lastSwilsOxid) {
      opcode = theSession->lastSwilsCmd;
    }
    else {
      opcode = -1;        /* Uninitialized */
    }
    switch (opcode) {
    case FC_SWILS_BF:
    case FC_SWILS_RCF:
    case FC_SWILS_EFP:
    case FC_SWILS_DIA:
    case FC_SWILS_RDI:
      incrementTrafficCounter (&hash->dmBytes, length);
      incrementTrafficCounter (&hash->dmPkts, 1);
      break;
    case FC_SWILS_HLO:
    case FC_SWILS_LSU:
    case FC_SWILS_LSA:
      incrementTrafficCounter (&hash->fspfBytes, length);
      incrementTrafficCounter (&hash->fspfPkts, 1);
      break;
    case FC_SWILS_RSCN:
      incrementTrafficCounter (&hash->rscnBytes, length);
      incrementTrafficCounter (&hash->rscnPkts, 1);
      processSwRscn (bp, srcHost->fcCounters->vsanId, actualDeviceId);
      break;
    case FC_SWILS_DRLIR:
    case FC_SWILS_DSCN:
      break;
    case FC_SWILS_MR:
    case FC_SWILS_ACA:
    case FC_SWILS_RCA:
    case FC_SWILS_SFC:
    case FC_SWILS_UFC:
      incrementTrafficCounter (&hash->zsBytes, length);
      incrementTrafficCounter (&hash->zsPkts, 1);
      break;
    case FC_SWILS_ELP:
    case FC_SWILS_ESC:
    default:
      incrementTrafficCounter (&hash->otherCtlBytes, length);
      incrementTrafficCounter (&hash->otherCtlPkts, 1);
      break;
    }
    break;
  case FC_FTYPE_SBCCS:
    break;
  case FC_FTYPE_IP:
    if (isXchgOrig) {
      incrementTrafficCounter (&theSession->ipfcBytesSent, length);
    }
    else {
      incrementTrafficCounter (&theSession->ipfcBytesRcvd, length);
    }
    break;

  default:
    if (isXchgOrig) {
      incrementTrafficCounter (&theSession->otherBytesSent, length);
    }
    else {
      incrementTrafficCounter (&theSession->otherBytesRcvd, length);
    }
    break;
  }

#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.fcSessionsMutex);
#endif
  return (theSession);
}
