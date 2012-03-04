/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *                          http://www.ntop.org
 *
 *          Copyright (C) 1998-2012 Luca Deri <deri@ntop.org>
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

#define tcp_flags(a, b) ((a & (b)) == (b))

/* ************************************ */

u_int _checkSessionIdx(u_int idx, int actualDeviceId, char* file, int line) {
  if(idx > myGlobals.device[actualDeviceId].hosts.actualHashSize) {
    traceEvent(CONST_TRACE_ERROR, "Index error idx=%u/deviceId=%d:0-%d @ [%s:%d]",
	       idx, actualDeviceId,
	       myGlobals.device[actualDeviceId].hosts.actualHashSize-1,
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

  if((virtualHostName != NULL) 
     && (strlen(virtualHostName) > 3) /* Sanity */
     ) {
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

void updateHostUsers(char *userName, int userType, HostTraffic *theHost) {
  int i;

  if(userName[0] == '\0') return;

  /* Convert to lowercase */
  for(i=(int)strlen(userName)-1; i>=0; i--) userName[i] = tolower(userName[i]);

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
  if(length > 0) {
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
      ports->serverUses++, ports->serverUsesLastPeer = dstHost->serialHostIndex;

      ports = getPortsUsage(dstHost, sport, 1);

#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: Adding client peer %u", dstHost->hostTrafficBucket);
#endif

      incrementTrafficCounter(&ports->clientTraffic, length);
      ports->clientUses++, ports->clientUsesLastPeer = srcHost->serialHostIndex;
    }

    if(dport < MAX_ASSIGNED_IP_PORTS) {
      ports = getPortsUsage(srcHost, dport, 1);

#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: Adding client peer %u", dstHost->hostTrafficBucket);
#endif

      incrementTrafficCounter(&ports->clientTraffic, length);
      ports->clientUses++, ports->clientUsesLastPeer = dstHost->serialHostIndex;

      ports = getPortsUsage(dstHost, dport, 1);

#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: Adding svr peer %u", srcHost->hostTrafficBucket);
#endif

      incrementTrafficCounter(&ports->serverTraffic, length);
      ports->serverUses++, ports->serverUsesLastPeer = srcHost->serialHostIndex;
    }
  }
}

/* ************************************ */

void freeOpenDPI(IPSession *sessionToPurge) {
  if(sessionToPurge->l7.flow != NULL) {
    if(sessionToPurge->l7.src != NULL) {
      free(sessionToPurge->l7.src);
      sessionToPurge->l7.src = NULL;
    }

    if(sessionToPurge->l7.dst != NULL) {
      free(sessionToPurge->l7.dst);
      sessionToPurge->l7.dst = NULL;
    }

    free(sessionToPurge->l7.flow);
    sessionToPurge->l7.flow = NULL;
  }
}

/* ************************************ */

void freeSession(IPSession *sessionToPurge, int actualDeviceId,
		 u_char allocateMemoryIfNeeded,
		 u_char lockMutex /* unused so far */) {
  /* Session to purge */

  notifyEvent(sessionDeletion, NULL, sessionToPurge, 0);

  if(sessionToPurge->magic != CONST_MAGIC_NUMBER) {
    traceEvent(CONST_TRACE_ERROR, "Bad magic number (expected=%d/real=%d) freeSession()",
	       CONST_MAGIC_NUMBER, sessionToPurge->magic);
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
     && ((sessionToPurge->clientNwDelay.tv_sec != 0) || (sessionToPurge->clientNwDelay.tv_usec != 0)
	 || (sessionToPurge->serverNwDelay.tv_sec != 0) || (sessionToPurge->serverNwDelay.tv_usec != 0)
	 )
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

    traceEvent(CONST_TRACE_INFO, "SESSION_TRACE_DEBUG: Session terminated: %s:%d <-> %s:%d (lastSeend=%d) (# sessions = %d)",
	       _addrtostr(&sessionToPurge->initiatorRealIp, buf, sizeof(buf)), sessionToPurge->sport,
	       _addrtostr(&sessionToPurge->remotePeerRealIp, buf1, sizeof(buf1)), sessionToPurge->dport,
	       sessionToPurge->lastSeen,  myGlobals.device[actualDeviceId].numSessions-1);
  }
#endif

  /*
   * Having updated the session information, 'theSession'
   * can now be purged.
   */

  if(sessionToPurge->virtualPeerName != NULL)
    free(sessionToPurge->virtualPeerName);

  if(sessionToPurge->session_info != NULL)
    free(sessionToPurge->session_info);

  myGlobals.numTerminatedSessions++;
  myGlobals.device[actualDeviceId].numSessions--;

  freeOpenDPI(sessionToPurge);

  /* Flag in delete process */
  memset(sessionToPurge, 0, sizeof(IPSession));
  sessionToPurge->magic = CONST_UNMAGIC_NUMBER;

  free(sessionToPurge);
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
  u_int idx, freeSessionCount = 0, tot_sessions = 0;

  /* Patch below courtesy of "Kouprie, Robbert" <R.Kouprie@DTO.TUDelft.NL> */
     if((!myGlobals.runningPref.enableSessionHandling)
	|| (myGlobals.device[actualDeviceId].sessions == NULL)
	|| (myGlobals.device[actualDeviceId].numSessions == 0))
     return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Called scanTimedoutTCPSessions (device=%d, sessions=%d)",
	     actualDeviceId, myGlobals.device[actualDeviceId].numSessions);
#endif

  /*
    NOTE

    We need to scan all session and not just a part of them as we need to make
    sure we have freed sessions whose peers were previously marked for deletion
    in purgeIdleHosts(int actDevice);
   */

  for(idx=0; idx<MAX_TOT_NUM_SESSIONS; idx++) {
    IPSession *nextSession, *prevSession, *headSession;
    int mutex_idx;

    if(myGlobals.device[actualDeviceId].sessions[idx] == NULL) continue;

    mutex_idx = idx % NUM_SESSION_MUTEXES;
    accessMutex(&myGlobals.sessionsMutex[mutex_idx], "purgeIdleHosts");
    prevSession = NULL, headSession = myGlobals.device[actualDeviceId].sessions[idx];

    while(headSession != NULL) {
      u_char free_session;

      tot_sessions++;

      if(headSession->magic != CONST_MAGIC_NUMBER) {
	myGlobals.device[actualDeviceId].numSessions--;
        traceEvent(CONST_TRACE_ERROR, "Bad magic number (expected=%d/real=%d) scanTimedoutTCPSessions() [idx=%u][head=%p][session=%p]",
	           CONST_MAGIC_NUMBER, headSession->magic, idx, myGlobals.device[actualDeviceId].sessions[idx], headSession);
	headSession = NULL;
	continue;
      }

      free_session = 0;

      if(
	 /* One of the session peers has been marked for deletion */
	 (headSession->initiator->magic == CONST_UNMAGIC_NUMBER)
	 || (headSession->remotePeer->magic == CONST_UNMAGIC_NUMBER)	 
	 || ((headSession->sessionState == FLAG_STATE_TIMEOUT)
	     && ((headSession->lastSeen+CONST_TWO_MSL_TIMEOUT) < myGlobals.actTime))
	 || /* The branch below allows to flush sessions which have not been
	       terminated properly (we've received just one FIN (not two). It might be
	       that we've lost some packets (hopefully not). */
	 ((headSession->sessionState >= FLAG_STATE_FIN1_ACK0)
	  && ((headSession->lastSeen+CONST_DOUBLE_TWO_MSL_TIMEOUT) < myGlobals.actTime))
	 /* The line below allows to avoid keeping very old sessions that
	    might be still open, but that are probably closed and we've
	    lost some packets */
	 || ((headSession->lastSeen+PARM_HOST_PURGE_MINIMUM_IDLE_ACTVSES) < myGlobals.actTime)
	 || ((headSession->lastSeen+PARM_SESSION_PURGE_MINIMUM_IDLE) < myGlobals.actTime)
	 /* Purge sessions that are not yet active and that have not completed
	    the 3-way handshave within 1 minute */
	 || ((headSession->sessionState < FLAG_STATE_ACTIVE) && ((headSession->lastSeen+60) < myGlobals.actTime))
	 /* Purge active sessions where one of the two peers has not sent any data
	    (it might be that ntop has created the session bucket because it has
	    thought that the session was already started) since 120 seconds */
	 || ((headSession->sessionState >= FLAG_STATE_ACTIVE)
	     && ((headSession->bytesSent.value == 0) || (headSession->bytesRcvd.value == 0))
	     && ((headSession->lastSeen+120) < myGlobals.actTime))
	 ) {
	free_session = 1;
      } else /* This session will NOT be freed */ {
	free_session = 0;
      }

      nextSession = headSession->next;

      if(free_session) {
	if(myGlobals.device[actualDeviceId].sessions[idx] == headSession) {
          myGlobals.device[actualDeviceId].sessions[idx] = nextSession, prevSession = NULL;
        } else {
          if(prevSession)
	    prevSession->next = nextSession;
	  else
	    traceEvent(CONST_TRACE_ERROR, "Internal error: pointer inconsistency");
        }

	freeSessionCount++;
        freeSession(headSession, actualDeviceId, 1, 0 /* locked by the purge thread */);
      } else {
	/* This session is not for free */
	prevSession = headSession;
      }

      headSession = nextSession;
    } /* while */

    releaseMutex(&myGlobals.sessionsMutex[mutex_idx]);
  } /* end for */

  //#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: scanTimedoutTCPSessions: freed %u sessions [total: %u sessions]",
	     freeSessionCount, tot_sessions);
  //#endif
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
    setHostFlag(FLAG_HOST_TYPE_SVC_FTP, srcHost);
  else
    setHostFlag(FLAG_HOST_TYPE_SVC_FTP, dstHost);

  if(((theSession->bytesProtoRcvd.value < 64)
      || (theSession->bytesProtoSent.value < 64))
     /* The sender name is sent at the beginning of the communication */
     && (packetDataLength > 7)) {
    if((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
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
    setHostFlag(FLAG_HOST_TYPE_SVC_SMTP, srcHost);
  else
    setHostFlag(FLAG_HOST_TYPE_SVC_SMTP, dstHost);

  if(((theSession->bytesProtoRcvd.value < 64)
      || (theSession->bytesProtoSent.value < 64))
     /* The sender name is sent at the beginning of the communication */
     && (packetDataLength > 7)) {
    int beginIdx = 11, i;

    if((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
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
    setHostFlag(FLAG_HOST_TYPE_SVC_POP, srcHost);
  else
    setHostFlag(FLAG_HOST_TYPE_SVC_POP, dstHost);

  if(((theSession->bytesProtoRcvd.value < 64)
      || (theSession->bytesProtoSent.value < 64)) /* The user name is sent at the beginning of the communication */
     && (packetDataLength > 4)) {

    if((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
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
    setHostFlag(FLAG_HOST_TYPE_SVC_IMAP, srcHost);
  else
    setHostFlag(FLAG_HOST_TYPE_SVC_IMAP, dstHost);

  if(((theSession->bytesProtoRcvd.value < 64)
      || (theSession->bytesProtoSent.value < 64))
     /* The sender name is sent at the beginning of the communication */
     && (packetDataLength > 7)) {

    if((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
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

typedef struct {
  u_int16_t src_call, dst_call; /* Together they form the callId */
  u_int32_t timestamp;
  u_int8_t outbound_seq_num, inbound_seq_num;
  u_int8_t frame_class /* 2 = voice */, frame_subclass;
  /* Payload */
} IAX2Header;

#define IAX2_STR_LEN   32

typedef struct {
  u_int8_t element_id, element_len;
  char element_data[IAX2_STR_LEN];
} IAX2PayloadElement;

/* IAX2 packets courtesy of richard.crouch@vodafone.com */

static void handleAsteriskSession(const struct pcap_pkthdr *h,
				  HostTraffic *srcHost, u_short sport,
				  HostTraffic *dstHost, u_short dport,
				  u_int packetDataLength, u_char* packetData,
				  IPSession *theSession, int actualDeviceId) {
  u_char debug = 0;

  if(packetDataLength > sizeof(IAX2Header)) {
    IAX2Header *header = (IAX2Header*)packetData;
    u_int16_t pkt_shift;

    if(debug) {
      traceEvent(CONST_TRACE_WARNING, "-------------------------");
      traceEvent(CONST_TRACE_WARNING, "[Class=%d][SubClass=%d]", header->frame_class, header->frame_subclass);
    }

    if(header->frame_class == 6) /* IAX */ {
      char caller_name[IAX2_STR_LEN] = { '\0' };
      char caller_num[IAX2_STR_LEN]  = { '\0' };
      char called_num[IAX2_STR_LEN]  = { '\0' };
      char username[IAX2_STR_LEN]    = { '\0' };

      pkt_shift = sizeof(IAX2Header);

      while(packetDataLength > (pkt_shift + 2 /* element_id+element_len */)) {
	IAX2PayloadElement *pe = (IAX2PayloadElement*)&packetData[pkt_shift];
	char tmpStr[IAX2_STR_LEN] = { '\0' };
	u_short len;

	if(pe->element_len >= (sizeof(tmpStr)-1))
	  len = sizeof(tmpStr)-2;
	else
	  len = pe->element_len;

	memcpy(tmpStr, pe->element_data, len);

	switch(pe->element_id) {
	case 1:  /* Called Number */
	  strcpy(called_num, tmpStr);
	  break;
	case 2:  /* Calling Number */
	  strcpy(caller_num, tmpStr);
	  break;
	case 4:  /* Caller Name */
	  strcpy(caller_name, tmpStr);
	  break;
	case 6:  /* UserName (used for authentication) */
	  strcpy(username, tmpStr);
	  break;
	case 13: /* Original Number Being Called */
	  break;
	}

	if(debug) traceEvent(CONST_TRACE_WARNING, "\t[Id=%d][Len=%d][%s]",
			     pe->element_id, pe->element_len, tmpStr);

	pkt_shift += (pe->element_len+2);
      } /* while */

      if(debug) {
	traceEvent(CONST_TRACE_WARNING, "-------------------------");
      }

      if(username[0] != '\0') updateHostUsers(username, BITFLAG_VOIP_USER, srcHost);

      if(((theSession->session_info == NULL) || (theSession->session_info[0] == '\0'))
	 && (caller_name[0] != '\0')
	 && (called_num[0] != '\0')) {
	char logStr[256];

	setHostFlag(FLAG_HOST_TYPE_SVC_VOIP_CLIENT,  srcHost);
	setHostFlag(FLAG_HOST_TYPE_SVC_VOIP_GATEWAY, dstHost);

	safe_snprintf(__FILE__, __LINE__, logStr, sizeof(logStr),
		      "%s <%s> -> <%s>",
		      caller_name, caller_num,  called_num);

	theSession->session_info = strdup(logStr);
      }
    }
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

	  safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "%s called %s", from, to);
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
	setHostFlag(FLAG_HOST_TYPE_SVC_VOIP_GATEWAY, srcHost);
      else
	setHostFlag(FLAG_HOST_TYPE_SVC_VOIP_CLIENT, srcHost);

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
      char caller[2048], called[2048];

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
	safe_snprintf(__FILE__, __LINE__, caller, sizeof(caller), "%s <%s>", calling_party_name, calling_party);
      else
	safe_snprintf(__FILE__, __LINE__, caller, sizeof(caller), "%s", calling_party);

      if(called_party_name[0] != '\0')
	safe_snprintf(__FILE__, __LINE__, called, sizeof(called), "%s <%s>", called_party_name, called_party);
      else
	safe_snprintf(__FILE__, __LINE__, called, sizeof(called), "%s", called_party);

      if(theSession->session_info == NULL) {
	char tmpStr[2048];

	safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "%s called %s", caller, called);
	theSession->session_info = strdup(tmpStr);
      }

      if(sport == IP_TCP_PORT_SCCP)
	addVoIPSessionInfo(&srcHost->hostIpAddress, sport, theSession->session_info);
      else if(dport == IP_TCP_PORT_SCCP)
	addVoIPSessionInfo(&dstHost->hostIpAddress, dport, theSession->session_info);

      setHostFlag(FLAG_HOST_TYPE_SVC_VOIP_GATEWAY, dstHost);
      setHostFlag(FLAG_HOST_TYPE_SVC_VOIP_CLIENT, srcHost);

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

static void handleHTTPSSession(const struct pcap_pkthdr *h,
			       const u_char *p,
			       HostTraffic *srcHost, u_short sport,
			       HostTraffic *dstHost, u_short dport,
			       u_int packetDataLength, char* packetData,
			       IPSession *theSession, int actualDeviceId) {
  u_int offset, base_offset = 43;
  char *vhost_name = NULL;

  if(packetData[0] == 0x16 /* Handshake */) {
    u_int16_t total_len  = packetData[4] + 5 /* SSL Header */;
    u_int8_t handshake_protocol = packetData[5];

    if(handshake_protocol == 0x02 /* Server Hello */) {
      int i;

      for(i=total_len; i < packetDataLength-3; i++) {
	if((packetData[i] == 0x04)
	   && (packetData[i+1] == 0x03)
	   && (packetData[i+2] == 0x0c)) {
	  u_int8_t server_len = packetData[i+3];

	  if(server_len+i+3 < packetDataLength) {
	    char *server_name = &packetData[i+4], buffer[64];
	    u_int8_t begin = 0, len, j, num_dots;

	    while(begin < server_len) {
	      if(!isprint(server_name[begin]))
		begin++;
	      else
		break;
	    }

	    len = min(server_len-begin, sizeof(buffer)-1);
	    strncpy(buffer, &server_name[begin], len);
	    buffer[len] = '\0';

	    /* We now have to check if this looks like an IP address or host name */
	    for(j=0, num_dots = 0; j<len; j++) {
	      if(!isprint((buffer[j]))) {
		num_dots = 0; /* This is not what we look for */
		break;
	      } else if(buffer[j] == '.') {
		num_dots++;
		if(num_dots >=2) break;
	      }
	    }

	    if(num_dots >= 2) {
#ifdef DEBUG
	      traceEvent(TRACE_NORMAL, "[S] -> '%s' [%u -> %u]", buffer, sport, dport);
#endif
	      vhost_name = strdup(buffer);
	    }
	  }
	}
      }
    } else if(handshake_protocol == 0x01 /* Client Hello */) {
      u_int16_t session_id_len = packetData[base_offset];
      u_int16_t cypher_len =  packetData[session_id_len+base_offset+2];

      offset = base_offset + session_id_len + cypher_len + 2;

      if(offset < total_len) {
	u_int16_t compression_len;
	u_int16_t extensions_len;

	compression_len = packetData[offset+1];
	offset += compression_len + 3;
	extensions_len = packetData[offset];

	if((extensions_len+offset) < total_len) {
	  u_int16_t extension_offset = 1; /* Move to the first extension */

	  while(extension_offset < extensions_len) {
	    u_int16_t extension_id, extension_len;

	    memcpy(&extension_id, &packetData[offset+extension_offset], 2);
	    extension_offset += 2;

	    memcpy(&extension_len, &packetData[offset+extension_offset], 2);
	    extension_offset += 2;

	    extension_id = ntohs(extension_id), extension_len = ntohs(extension_len);

	    /* traceEvent(TRACE_NORMAL, "extension_id=0x%X [%u -> %u]", extension_id, sport, dport); */

	    if(extension_id == 0) {
	      u_int begin = 0,len;
	      char *server_name = &packetData[offset+extension_offset], buffer[64];

	      while(begin < extension_len) {
		if(!isprint(server_name[begin]))
		  begin++;
		else
		  break;
	      }

	      len = (int)min(extension_len-begin, sizeof(buffer)-1);
	      strncpy(buffer, &server_name[begin], len);
	      buffer[len] = '\0';

#ifdef DEBUG
	      traceEvent(TRACE_NORMAL, "[C] -> '%s' [%u -> %u]", buffer, sport, dport);
#endif
	      vhost_name = strdup(buffer);
	      break; /* We're happy now */
	    }

	    extension_offset += extension_len;
	  }
	}
      }
    }
  }

  if(vhost_name) {
    if (theSession->virtualPeerName == NULL) {
      HostTraffic *server = (theSession->sport == IP_TCP_PORT_HTTPS) ? theSession->initiator : theSession->remotePeer;

      setHostName(server, vhost_name);
      theSession->virtualPeerName = vhost_name;
    } else
      free(vhost_name);
  }
}

/* *********************************** */

static void handleHTTPSession(const struct pcap_pkthdr *h,
			      const u_char *p,
                              HostTraffic *srcHost, u_short sport,
                              HostTraffic *dstHost, u_short dport,
                              u_int packetDataLength, u_char* packetData,
                              IPSession *theSession, int actualDeviceId) {
  char *rcStr, tmpStr[256] = { '\0' };
  struct timeval tvstrct;

  if(sport == IP_TCP_PORT_HTTP) setHostFlag(FLAG_HOST_TYPE_SVC_HTTP, srcHost);
  if(dport == IP_TCP_PORT_HTTP) setHostFlag(FLAG_HOST_TYPE_SVC_HTTP, dstHost);

  if((sport == IP_TCP_PORT_HTTP)
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

      if(srcHost->protocolInfo == NULL) allocHostTrafficCounterMemory(srcHost, protocolInfo, sizeof(ServiceStats));
      if(dstHost->protocolInfo == NULL) allocHostTrafficCounterMemory(dstHost, protocolInfo, sizeof(ServiceStats));

      /* Fix courtesy of Ronald Roskens <ronr@econet.com> */
      allocHostTrafficCounterMemory(srcHost, protocolInfo->httpStats, sizeof(ServiceStats));
      allocHostTrafficCounterMemory(dstHost, protocolInfo->httpStats, sizeof(ServiceStats));

      rc = atoi(&tmpStr[9]);

      if(rc == 200) /* HTTP/1.1 200 OK */ {
	incrementHostTrafficCounter(srcHost, protocolInfo->httpStats->numPositiveReplSent, 1);
	incrementHostTrafficCounter(dstHost, protocolInfo->httpStats->numPositiveReplRcvd, 1);
      } else {
	incrementHostTrafficCounter(srcHost, protocolInfo->httpStats->numNegativeReplSent, 1);
	incrementHostTrafficCounter(dstHost, protocolInfo->httpStats->numNegativeReplRcvd, 1);
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
  } else if(dport == IP_TCP_PORT_HTTP) {
    if(theSession->bytesProtoSent.value == 0) {
      if((rcStr = (char*)malloc(packetDataLength+1)) == NULL) {
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

	if(srcHost->protocolInfo == NULL) allocHostTrafficCounterMemory(srcHost, protocolInfo, sizeof(ServiceStats));
	if(dstHost->protocolInfo == NULL) allocHostTrafficCounterMemory(dstHost, protocolInfo, sizeof(ServiceStats));

	/* Fix courtesy of Ronald Roskens <ronr@econet.com> */
	allocHostTrafficCounterMemory(srcHost, protocolInfo->httpStats, sizeof(ServiceStats));
	allocHostTrafficCounterMemory(dstHost, protocolInfo->httpStats, sizeof(ServiceStats));

	if(subnetLocalHost(dstHost)) {
	  incrementHostTrafficCounter(srcHost, protocolInfo->httpStats->numLocalReqSent, 1);
	} else {
	  incrementHostTrafficCounter(srcHost, protocolInfo->httpStats->numRemReqSent, 1);
	}

	if(subnetLocalHost(srcHost)) {
	  incrementHostTrafficCounter(dstHost, protocolInfo->httpStats->numLocalReqRcvd, 1);
	} else {
	  incrementHostTrafficCounter(dstHost, protocolInfo->httpStats->numRemReqRcvd, 1);
	}

	row = strtok_r(rcStr, "\n", &strtokState);

	while(row != NULL) {
	  int len = (int)strlen(row);

	  if((len > 12) && (strncmp(row, "User-Agent:", 11) == 0)) {
	    char *token, *tokState = NULL, *os = NULL;

	    row[len-1] = '\0';

	    /*
	      Mozilla/4.0 (compatible; MSIE 5.01; Windows 98)
	      Mozilla/4.7 [en] (X11; I; SunOS 5.8 i86pc)
	      Mozilla/4.76 [en] (Win98; U)
	    */
#ifdef DEBUG
	    printf("DEBUG: => '%s' (len=%d)\n", &row[12], packetDataLength);
#endif
	    token = strtok_r(&row[12], "(", &tokState);
	    if(token != NULL) token = strtok_r(NULL, ";", &tokState);

	    if(token) {
	      if(strcmp(token, "compatible") == 0) {
		token = strtok_r(NULL, ";", &tokState);
		os = token = strtok_r(NULL, ")", &tokState);
	      } else {
		char *tok2;

		strtok_r(NULL, ";", &tokState);
		tok2 = strtok_r(NULL, ")", &tokState);

		if(tok2 == NULL) os = token; else  os = tok2;
	      }
	    }

	    if(os != NULL) {
	      trimString(os);
#ifdef DEBUG
	      printf("DEBUG: OS='%s'\n", os);
#endif

	      if(srcHost->fingerprint == NULL) {
		char buffer[512], *delimiter;

		safe_snprintf(__FILE__, __LINE__, buffer, sizeof(buffer), ":%s", os);

		if((delimiter = strchr(buffer, ';')) != NULL) delimiter[0] = '\0';
		if((delimiter = strchr(buffer, '(')) != NULL) delimiter[0] = '\0';
		if((delimiter = strchr(buffer, ')')) != NULL) delimiter[0] = '\0';

		srcHost->fingerprint = strdup(buffer);
	      }
	    }
	  } else if((len > 6) && (strncmp(row, "Host:", 5) == 0)) {
	    char *host;

	    row[len-1] = '\0';

	    host = &row[6];
	    if(strlen(host) > 48)
	      host[48] = '\0';

#ifdef DEBUG
	    printf("DEBUG: HOST='%s'\n", host);
#endif
	    if(theSession->virtualPeerName == NULL) {
	      HostTraffic *server = (theSession->sport == IP_TCP_PORT_HTTP) ? theSession->initiator : theSession->remotePeer;

	      /* if(server->hostResolvedName[0] == '\0') */ setHostName(server, host);
	      theSession->virtualPeerName = strdup(host);
	    }
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

	  dumpSuspiciousPacket(actualDeviceId, h, p);
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
static void tcpSessionSecurityChecks(const struct pcap_pkthdr *h,
				     const u_char *p,
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

  if(tp == NULL) return; /* No TCP */

  if((theSession->sessionState == FLAG_STATE_ACTIVE)
     && ((theSession->clientNwDelay.tv_sec != 0) || (theSession->clientNwDelay.tv_usec != 0)
	 || (theSession->serverNwDelay.tv_sec != 0) || (theSession->serverNwDelay.tv_usec != 0)
	 )
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

      /*
	FIX - check if se see a protocol on a non standard port
	and in this case dump it
      */
#if 0
      if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING, "Unknown protocol (no SSH) detected (trojan?) "
		   "at port 22 %s:%d -> %s:%d [%s]",
		   dstHost->hostResolvedName, dport,
		   srcHost->hostResolvedName, sport,
		   tmpStr);
	dumpSuspiciousPacket(actualDeviceId, h, p);
      }
#endif
    }
  }

  /*
   * Security checks based on TCP Flags
   */
  if((tp->th_flags == TH_ACK) && (theSession->sessionState == FLAG_STATE_SYN_ACK)) {
    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    incrementUsageCounter(&srcHost->secHostPkts->establishedTCPConnSent, dstHost, actualDeviceId);
    incrementUsageCounter(&dstHost->secHostPkts->establishedTCPConnRcvd, srcHost, actualDeviceId);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.establishedTCPConn, 1);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].numEstablishedTCPConnections, 1);
    theSession->sessionState = FLAG_STATE_ACTIVE;
  }
  else if((addedNewEntry == 0)
	   && ((theSession->sessionState == FLAG_STATE_SYN)
	       || (theSession->sessionState == FLAG_STATE_SYN_ACK))
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
	dumpSuspiciousPacket(actualDeviceId, h, p);
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
      dumpSuspiciousPacket(actualDeviceId, h, p);
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

	traceEvent(CONST_TRACE_INFO, "Host %s rejected TCP session from %s [%s:%d] <-> [%s:%d] (port closed?)",
		   srcHost->hostResolvedName, dstHost->hostResolvedName,
		   dstHost->hostResolvedName, dport,
		   srcHost->hostResolvedName, sport);
	dumpSuspiciousPacket(actualDeviceId, h, p);
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
	dumpSuspiciousPacket(actualDeviceId, h, p);
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
	dumpSuspiciousPacket(actualDeviceId, h, p);
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
	dumpSuspiciousPacket(actualDeviceId, h, p);
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

#if 0
static int portRange(int sport, int dport, int minPort, int maxPort) {
  return(((sport >= minPort) && (sport <= maxPort))
	 || ((dport >= minPort) && (dport <= maxPort)));
}
#endif

/* ****************************************************** */

static void timeval_diff(struct timeval *begin,
			 struct timeval *end, struct timeval *result) {
  if(end->tv_sec >= begin->tv_sec) {
    result->tv_sec = end->tv_sec-begin->tv_sec;

    if((end->tv_usec - begin->tv_usec) < 0) {
      result->tv_usec = 1000000 + end->tv_usec - begin->tv_usec;
      if(result->tv_usec > 1000000) begin->tv_usec = 1000000;
      result->tv_sec--;
    } else
      result->tv_usec = end->tv_usec-begin->tv_usec;

    result->tv_sec /= 2, result->tv_usec /= 2;
  } else
    result->tv_sec = 0, result->tv_usec = 0;
}

/* *********************************** */

static void updateNetworkDelay(NetworkDelay *delayStats,
			       HostSerialIndex *peer, u_int16_t peer_port,
			       struct timeval *delay,
			       struct timeval *when,
			       int port_idx) {
  u_long int_delay;

  if(0)
    traceEvent(CONST_TRACE_WARNING,
	       "updateNetworkDelay(port=%d [idx=%d], delay=%.2f ms)",
	       peer_port, port_idx, (float)int_delay/1000);

  if(port_idx == -1) return;

  int_delay = delay->tv_sec * 1000000 + delay->tv_usec;
  if((when->tv_sec == 0) && (when->tv_usec == 0)) gettimeofday(when, NULL);
  memcpy(&delayStats[port_idx].last_update, when, sizeof(struct timeval));

  if(delayStats[port_idx].min_nw_delay == 0)
    delayStats[port_idx].min_nw_delay = int_delay;
  else
    delayStats[port_idx].min_nw_delay = min(delayStats[port_idx].min_nw_delay, int_delay);

  if(delayStats[port_idx].max_nw_delay == 0)
    delayStats[port_idx].max_nw_delay = int_delay;
  else
    delayStats[port_idx].max_nw_delay = max(delayStats[port_idx].max_nw_delay, int_delay);

  delayStats[port_idx].total_delay += int_delay, delayStats[port_idx].num_samples++;
  delayStats[port_idx].peer_port = peer_port;
  memcpy(&delayStats[port_idx].last_peer, peer, sizeof(HostSerial));
}

/* *********************************** */

void updatePeersDelayStats(HostTraffic *peer_a,
			   HostSerialIndex *peer_b_serial,
			   u_int16_t port,
			   struct timeval *nwDelay,
			   struct timeval *synAckTime,
			   struct timeval *ackTime,
			   u_char is_client_delay,
			   int port_idx) {
  /* traceEvent(CONST_TRACE_WARNING, "----------> updateSessionDelayStats()");  */

  if((!subnetPseudoLocalHost(peer_a)) || (port_idx == -1)) return;

  if(is_client_delay) {
    if((nwDelay->tv_sec > 0) || (nwDelay->tv_usec > 0)) {
      if(peer_a->clientDelay == NULL)
	peer_a->clientDelay = (NetworkDelay*)calloc(sizeof(NetworkDelay),
						    myGlobals.ipPortMapper.numSlots);

      if(peer_a->clientDelay == NULL) {
	traceEvent(CONST_TRACE_ERROR, "Sanity check failed [Low memory?]");
	return;
      }

      updateNetworkDelay(peer_a->clientDelay,
			 peer_b_serial,
			 port,
			 nwDelay,
			 synAckTime,
			 port_idx);
    }
  } else {
    if((nwDelay->tv_sec > 0) || (nwDelay->tv_usec > 0)) {
      if(peer_a->serverDelay == NULL)
	peer_a->serverDelay = (NetworkDelay*)calloc(sizeof(NetworkDelay),
						    myGlobals.ipPortMapper.numSlots);
      if(peer_a->serverDelay == NULL) {
	traceEvent(CONST_TRACE_ERROR, "Sanity check failed [Low memory?]");
	return;
      }

      updateNetworkDelay(peer_a->serverDelay,
			 peer_b_serial,
			 port,
			 nwDelay,
			 ackTime,
			 port_idx);
    }
  }
}

/* *********************************** */

void updateSessionDelayStats(IPSession* session) {
  int port_idx, port;

  /* traceEvent(CONST_TRACE_WARNING, "----------> updateSessionDelayStats()");  */

  port = session->dport;
  if((port_idx = mapGlobalToLocalIdx(port)) == -1) {
    port = session->sport;
    if((port_idx = mapGlobalToLocalIdx(port)) == -1) {
      return;
    }
  }

  if(subnetPseudoLocalHost(session->initiator))
    updatePeersDelayStats(session->initiator,
			  &session->remotePeer->serialHostIndex,
			  port,
			  &session->clientNwDelay,
			  &session->synAckTime,
			  NULL, 1 /* client */, port_idx);

  if(subnetPseudoLocalHost(session->remotePeer))
    updatePeersDelayStats(session->remotePeer,
			  &session->initiator->serialHostIndex,
			  port,
			  &session->serverNwDelay,
			  NULL,
			  &session->ackTime,
			  0 /* server */, port_idx);
}

/* *********************************** */

static IPSession* handleTCPUDPSession(u_int proto, const struct pcap_pkthdr *h,
				      const u_char *p,
				      u_short fragmentedData, u_int tcpWin,
				      HostTraffic *srcHost, u_short sport,
				      HostTraffic *dstHost, u_short dport,
				      u_int sent_length, u_int rcvd_length /* Always 0 except for NetFlow v9 */,
				      u_int ip_offset, struct tcphdr *tp,
				      u_int packetDataLength, u_char* packetData,
				      int actualDeviceId, u_short *newSession,
				      u_int16_t major_proto) {
  IPSession *prevSession;
  u_int idx;
  IPSession *theSession = NULL;
  short flowDirection = FLAG_CLIENT_TO_SERVER;
  char addedNewEntry = 0;
  u_short check, found=0;
  HostTraffic *hostToUpdate = NULL;
  u_char tmpStr[256];
  int len = 0, mutex_idx;
  char *pnotes = NULL, *snotes = NULL, *dnotes = NULL;
  /* Latency measurement */
  char buf[32], buf1[32];

  memset(&buf, 0, sizeof(buf));
  memset(&buf1, 0, sizeof(buf1));

  idx = computeIdx(&srcHost->hostIpAddress, &dstHost->hostIpAddress, sport, dport) % MAX_TOT_NUM_SESSIONS;
  mutex_idx = idx % NUM_SESSION_MUTEXES;

  accessMutex(&myGlobals.sessionsMutex[mutex_idx], "handleTCPUDPSession");
  prevSession = theSession = myGlobals.device[actualDeviceId].sessions[idx];

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "handleTCPUDPSession [%s%s%s%s%s]",
	     (tp->th_flags & TH_SYN) ? " SYN" : "",
	     (tp->th_flags & TH_ACK) ? " ACK" : "",
	     (tp->th_flags & TH_FIN) ? " FIN" : "",
	     (tp->th_flags & TH_RST) ? " RST" : "",
	     (tp->th_flags & TH_PUSH) ? " PUSH" : "");
#endif

  while(theSession != NULL) {
    if(theSession->next == theSession) {
      traceEvent(CONST_TRACE_WARNING, "Internal Error (4) (idx=%d)", idx);
      theSession->next = NULL;
    }

    if((theSession->proto == proto)
       && (theSession->initiator == srcHost)
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
    int rc;

    (*newSession) = 1; /* This is a new session */
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.totalFlows,
			    2 /* 2 x monodirectional flows */);

    if(myGlobals.device[actualDeviceId].numSessions >= myGlobals.runningPref.maxNumSessions) {
      static char messageShown = 0;

      if(!messageShown) {
	messageShown = 1;
	traceEvent(CONST_TRACE_INFO, "WARNING: Max num TCP sessions (%u) reached (see -X)",
		   myGlobals.runningPref.maxNumSessions);
      }

      releaseMutex(&myGlobals.sessionsMutex[mutex_idx]);
      return(NULL);
    }

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: TCP hash [act size: %d]",
	       myGlobals.device[actualDeviceId].numSessions);
#endif

    /*
      We don't check for space here as the datastructure allows
      ntop to store sessions as needed
    */
    if((theSession = (IPSession*)malloc(sizeof(IPSession))) == NULL) {
      releaseMutex(&myGlobals.sessionsMutex[mutex_idx]);
      return(NULL);
    }

    memset(theSession, 0, sizeof(IPSession));
    addedNewEntry = 1;

    if(major_proto != IPOQUE_PROTOCOL_UNKNOWN) {
      theSession->l7.major_proto = major_proto;
    } else {
      rc = mapGlobalToLocalIdx(sport);
      if(rc == -1) 
	rc = mapGlobalToLocalIdx(dport);

      if(rc != -1) {
	/* We have found a protocol defined thus we map the protocol */
	theSession->l7.major_proto = IPOQUE_MAX_SUPPORTED_PROTOCOLS + rc;
      } else {
	if(myGlobals.device[actualDeviceId].l7.l7handler != NULL) {
	  static u_int8_t once = 0;

	  if((theSession->l7.flow = calloc(1, myGlobals.l7.flow_struct_size)) == NULL) {
	    if(!once) {
	      traceEvent(CONST_TRACE_ERROR, "NULL theSession (not enough memory?)");
	      once = 1;
	    }

	    free(theSession);
	    releaseMutex(&myGlobals.sessionsMutex[mutex_idx]);
	    return(NULL);
	  }

	  theSession->l7.src = calloc(1, myGlobals.l7.proto_size);
	  theSession->l7.dst = calloc(1, myGlobals.l7.proto_size);

	  if((theSession->l7.src == NULL) || (theSession->l7.dst == NULL)) {
	    if(!once) {
	      traceEvent(CONST_TRACE_ERROR, "NULL theSession (not enough memory?)");
	      once = 1;
	    }

	    if(theSession->l7.src) free(theSession->l7.src);
	    if(theSession->l7.dst) free(theSession->l7.dst);
	    free(theSession);

	    releaseMutex(&myGlobals.sessionsMutex[mutex_idx]);
	    return(NULL);
	  }
	}
      }
    }

    if(tp && (tp->th_flags == TH_SYN)) {
      theSession->synTime.tv_sec = h->ts.tv_sec;
      theSession->synTime.tv_usec = h->ts.tv_usec;
      theSession->sessionState = FLAG_STATE_SYN;
      /* traceEvent(CONST_TRACE_ERROR, "DEBUG: SYN [%d.%d]", h->ts.tv_sec, h->ts.tv_usec); */
    }

    theSession->magic = CONST_MAGIC_NUMBER;

    addrcpy(&theSession->initiatorRealIp,  &srcHost->hostIpAddress);
    addrcpy(&theSession->remotePeerRealIp, &dstHost->hostIpAddress);

#ifdef SESSION_TRACE_DEBUG
    traceEvent(CONST_TRACE_INFO, "SESSION_TRACE_DEBUG: New TCP session [%s:%d] <-> [%s:%d] (# sessions = %d)",
	       dstHost->hostNumIpAddress, dport,
	       srcHost->hostNumIpAddress, sport,
	       myGlobals.device[actualDeviceId].numSessions);
#endif

    myGlobals.device[actualDeviceId].numSessions++;

    if(myGlobals.device[actualDeviceId].numSessions > myGlobals.device[actualDeviceId].maxNumSessions)
      myGlobals.device[actualDeviceId].maxNumSessions = myGlobals.device[actualDeviceId].numSessions;

    /* Add it to the list as head element */
    theSession->next = myGlobals.device[actualDeviceId].sessions[idx];
    myGlobals.device[actualDeviceId].sessions[idx] = theSession;

    theSession->initiator  = srcHost, theSession->remotePeer = dstHost;
    theSession->initiator->numHostSessions++, theSession->remotePeer->numHostSessions++;
    theSession->proto = proto, theSession->sport = sport, theSession->dport = dport;

    theSession->passiveFtpSession = isPassiveSession(&dstHost->hostIpAddress, dport, &pnotes);
    theSession->voipSession       = isVoIPSession(&srcHost->hostIpAddress, sport, &snotes)
      || isVoIPSession(&dstHost->hostIpAddress, dport, &dnotes);

    if(pnotes) theSession->session_info = pnotes;
    else if(snotes) theSession->session_info = snotes;
    else if(dnotes) theSession->session_info = dnotes;
    else theSession->session_info = NULL;

    theSession->firstSeen = myGlobals.actTime;
    flowDirection = FLAG_CLIENT_TO_SERVER;

    notifyEvent(sessionCreation, NULL, theSession, 0);
  } /* End of new session branch */

  if(tp)
    theSession->lastFlags |= tp->th_flags;

  /* traceEvent(CONST_TRACE_ERROR, "--> DEBUG: [state=%d][flags=%d]", theSession->sessionState, tp->th_flags); */
  if(tp
     && (theSession->sessionState == FLAG_STATE_SYN)
     && (tp->th_flags == (TH_SYN | TH_ACK))) {
    theSession->synAckTime.tv_sec  = h->ts.tv_sec;
    theSession->synAckTime.tv_usec = h->ts.tv_usec;
    timeval_diff(&theSession->synTime, (struct timeval*)&h->ts, &theSession->serverNwDelay);
    /* Sanity check */
    if(theSession->serverNwDelay.tv_sec > 1000) {
      /*
	This value seems to be wrong so it's better to ignore it
	rather than showing a false/wrong/dummy value
      */
      theSession->serverNwDelay.tv_usec = 0, theSession->serverNwDelay.tv_sec = 0;
    }

    theSession->sessionState = FLAG_STATE_SYN_ACK;
    /* traceEvent(CONST_TRACE_ERROR, "DEBUG: SYN_ACK [%d.%d]", h->ts.tv_sec, h->ts.tv_usec); */
  } else if(tp
	    && (theSession->sessionState == FLAG_STATE_SYN_ACK)
	    && (tp->th_flags == TH_ACK)) {
    theSession->ackTime.tv_sec = h->ts.tv_sec;
    theSession->ackTime.tv_usec = h->ts.tv_usec;

    /* traceEvent(CONST_TRACE_ERROR, "DEBUG: ACK [%d.%d]", h->ts.tv_sec, h->ts.tv_usec); */

    if(theSession->synTime.tv_sec > 0) {
      timeval_diff(&theSession->synAckTime, (struct timeval*)&h->ts, &theSession->clientNwDelay);
      /* Sanity check */
      if(theSession->clientNwDelay.tv_sec > 1000) {
	/*
	  This value seems to be wrong so it's better to ignore it
	  rather than showing a false/wrong/dummy value
	*/
	theSession->clientNwDelay.tv_usec = 0, theSession->clientNwDelay.tv_sec = 0;
      }

      updateSessionDelayStats(theSession);
    }

    theSession->sessionState = FLAG_STATE_ACTIVE;
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
     && ((theSession->bytesProtoSent.value >= 0) && (theSession->bytesProtoSent.value < 128))
     /* Reduce protocol decoding effort */
     ) {
    if(((sport == IP_TCP_PORT_HTTP) || (dport == IP_TCP_PORT_HTTP))
       && (packetDataLength > 0)) {
      handleHTTPSession(h, p, srcHost, sport, dstHost, dport,
			packetDataLength, packetData, theSession,
			actualDeviceId);
    } else if(((sport == IP_TCP_PORT_HTTPS) || (dport == IP_TCP_PORT_HTTPS))
	      && (packetDataLength > 0)) {
      handleHTTPSSession(h, p, srcHost, sport, dstHost, dport,
			 packetDataLength, (char*)packetData, theSession,
			 actualDeviceId);
    } else if(((sport == IP_TCP_PORT_MSMSGR) ||
	       (dport == IP_TCP_PORT_MSMSGR))
	      && (packetDataLength > 0)) {
      handleMsnMsgrSession(h, srcHost, sport, dstHost, dport,
			   packetDataLength, packetData, theSession,
			   actualDeviceId);
    } else if(((sport == IP_TCP_PORT_SMTP) || (dport == IP_TCP_PORT_SMTP))
	      && (theSession->sessionState == FLAG_STATE_ACTIVE)) {
      handleSMTPSession(h, srcHost, sport, dstHost, dport,
			packetDataLength, packetData, theSession,
			actualDeviceId);
    } else if(((sport == IP_TCP_PORT_FTP)  || (dport == IP_TCP_PORT_FTP))
	      && (theSession->sessionState == FLAG_STATE_ACTIVE)) {
      handleFTPSession(h, srcHost, sport, dstHost, dport,
		       packetDataLength, packetData, theSession,
		       actualDeviceId);
    } else if(((dport == IP_TCP_PORT_PRINTER) || (sport == IP_TCP_PORT_PRINTER))
	      && (theSession->sessionState == FLAG_STATE_ACTIVE)) {
      if(sport == IP_TCP_PORT_PRINTER)
	setHostFlag(FLAG_HOST_TYPE_PRINTER, srcHost);
      else
	setHostFlag(FLAG_HOST_TYPE_PRINTER, dstHost);
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
    }
  } else {
    /* !myGlobals.enablePacketDecoding */

    switch(sport) {
    case IP_TCP_PORT_FTP:
      setHostFlag(FLAG_HOST_TYPE_SVC_FTP, srcHost);
      break;
    case IP_TCP_PORT_SMTP:
      setHostFlag(FLAG_HOST_TYPE_SVC_SMTP, srcHost);
      break;
    case IP_TCP_PORT_HTTP:
    case IP_TCP_PORT_HTTPS:
      setHostFlag(FLAG_HOST_TYPE_SVC_HTTP, srcHost);
      break;
    case IP_TCP_PORT_POP2:
    case IP_TCP_PORT_POP3:
    case IP_TCP_PORT_POPS:
      setHostFlag(FLAG_HOST_TYPE_SVC_POP, srcHost);
      break;
    case IP_TCP_PORT_IMAP:
    case IP_TCP_PORT_IMAPS:
      setHostFlag(FLAG_HOST_TYPE_SVC_IMAP, srcHost);
      break;
    case IP_TCP_PORT_PRINTER:
    case IP_TCP_PORT_JETDIRECT:
      setHostFlag(FLAG_HOST_TYPE_PRINTER, srcHost);
      break;
    }

    switch(dport) {
    case IP_TCP_PORT_FTP:
      setHostFlag(FLAG_HOST_TYPE_SVC_FTP, dstHost);
      break;
    case IP_TCP_PORT_SMTP:
      setHostFlag(FLAG_HOST_TYPE_SVC_SMTP, dstHost);
      break;
    case IP_TCP_PORT_HTTP:
    case IP_TCP_PORT_HTTPS:
      setHostFlag(FLAG_HOST_TYPE_SVC_HTTP, dstHost);
      break;
    case IP_TCP_PORT_POP2:
    case IP_TCP_PORT_POP3:
      setHostFlag(FLAG_HOST_TYPE_SVC_POP, dstHost);
      break;
    case IP_TCP_PORT_IMAP:
      setHostFlag(FLAG_HOST_TYPE_SVC_IMAP, dstHost);
      break;
    case IP_TCP_PORT_PRINTER:
    case IP_TCP_PORT_JETDIRECT:
      setHostFlag(FLAG_HOST_TYPE_PRINTER, dstHost);
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
    if((sport == IP_TCP_PORT_FTP) || (dport == IP_TCP_PORT_FTP)) {
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
    } else if((sport == IP_UDP_PORT_IAX2) && (dport == IP_UDP_PORT_IAX2)) {
      handleAsteriskSession(h, srcHost, sport, dstHost, dport,
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

  if((theSession->lastFlags == (TH_SYN|TH_ACK)) && (theSession->sessionState == FLAG_STATE_SYN))  {
    theSession->sessionState = FLAG_STATE_SYN_ACK;
  } else if((theSession->lastFlags == TH_ACK) && (theSession->sessionState == FLAG_STATE_SYN_ACK)) {
    if(1)
      traceEvent(CONST_TRACE_NOISY, "LATENCY: %s:%d->%s:%d [CND: %d us][SND: %d us]",
		 _addrtostr(&theSession->initiatorRealIp, buf, sizeof(buf)),
		 theSession->sport,
		 _addrtostr(&theSession->remotePeerRealIp, buf1, sizeof(buf1)),
		 theSession->dport,
		 (int)(theSession->clientNwDelay.tv_sec * 1000000 + theSession->clientNwDelay.tv_usec),
		 (int)(theSession->serverNwDelay.tv_sec * 1000000 + theSession->serverNwDelay.tv_usec)
		 );

    theSession->sessionState = FLAG_STATE_ACTIVE;
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_WARNING, "DEBUG: sessionsState=%d\n", theSession->sessionState);
#endif

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
    c = theSession->clientNwDelay.tv_usec + 1000*theSession->clientNwDelay.tv_sec
      + theSession->serverNwDelay.tv_usec + 1000*theSession->serverNwDelay.tv_sec;

    if(a > c) {
      hostToUpdate->minLatency.tv_sec  = theSession->clientNwDelay.tv_sec + theSession->serverNwDelay.tv_sec;
      hostToUpdate->minLatency.tv_usec = theSession->clientNwDelay.tv_usec + theSession->serverNwDelay.tv_usec;
      if(hostToUpdate->minLatency.tv_usec > 1000)
	hostToUpdate->minLatency.tv_usec -= 1000, hostToUpdate->minLatency.tv_sec++;
    }

    if(b < c) {
      hostToUpdate->maxLatency.tv_sec  = theSession->clientNwDelay.tv_sec + theSession->serverNwDelay.tv_sec;
      hostToUpdate->maxLatency.tv_usec = theSession->clientNwDelay.tv_usec + theSession->serverNwDelay.tv_usec;
      if(hostToUpdate->maxLatency.tv_usec > 1000)
	hostToUpdate->maxLatency.tv_usec -= 1000, hostToUpdate->maxLatency.tv_sec++;
    }
  } else if((addedNewEntry == 0)
	    && ((theSession->sessionState == FLAG_STATE_SYN)
		|| (theSession->sessionState == FLAG_STATE_SYN_ACK))
	    && (!(theSession->lastFlags & TH_RST))) {
    /*
      We might have lost a packet so:
      - we cannot calculate latency
      - we don't set the state to initialized
    */

    /*
      theSession->clientNwDelay.tv_usec = theSession->clientNwDelay.tv_sec = 0;
      theSession->serverNwDelay.tv_usec = theSession->serverNwDelay.tv_sec = 0;
    */

#ifdef LATENCY_DEBUG
    traceEvent(CONST_TRACE_NOISY, "LATENCY: (%s ->0x%x%s%s%s%s%s) %s:%d->%s:%d invalid (lost packet?), ignored",
	       (theSession->sessionState == FLAG_STATE_SYN) ? "SYN" : "SYN_ACK",
	       theSession->lastFlags,
	       (theSession->lastFlags & TH_SYN) ? " SYN" : "",
	       (theSession->lastFlags & TH_ACK) ? " ACK" : "",
	       (theSession->lastFlags & TH_FIN) ? " FIN" : "",
	       (theSession->lastFlags & TH_RST) ? " RST" : "",
	       (theSession->lastFlags & TH_PUSH) ? " PUSH" : "",
	       _addrtostr(&theSession->initiatorRealIp, buf, sizeof(buf)),
	       theSession->sport,
	       _addrtostr(&theSession->remotePeerRealIp, buf1, sizeof(buf1)),
	       theSession->dport);
#endif
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

  if(tp != NULL) {
    /* Don't move the following call from here unless you know what you're
     * doing.
     *
     * This routine takes care of almost all the security checks such as:
     * - Dumping suspicious packets based on certain invalid TCP Flag combos
     * - Counting packets & bytes based on certain invalid TCP Flag combos
     * - Checking if a known protocol is running at a not well-known port
     */
    tcpSessionSecurityChecks(h, p, srcHost, sport, dstHost, dport, tp,
			     packetDataLength, packetData, addedNewEntry,
			     theSession, actualDeviceId);
    /*
     *
     * In this case the session is over hence the list of
     * sessions initiated/received by the hosts can be updated
     *
     */
    if(theSession->lastFlags & TH_FIN) {
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

	if(theSession->lastFlags & TH_ACK) {
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
    } else if(theSession->lastFlags == TH_ACK) {
      u_int32_t ack = ntohl(tp->th_ack);

      if((ack == theSession->lastAckIdI2R) && (ack == theSession->lastAckIdR2I)) {
	if(theSession->initiator == srcHost) {
	  incrementTrafficCounter(&theSession->bytesRetranI2R, sent_length+rcvd_length);
	  incrementTrafficCounter(&theSession->initiator->pktsDuplicatedAckSent, 1);
	  incrementTrafficCounter(&theSession->remotePeer->pktsDuplicatedAckRcvd, 1);

#ifdef DEBUG
	  traceEvent(CONST_TRACE_INFO, "DEBUG: Duplicated ACK %ld [ACKs=%d/bytes=%d]: ",
		     ack, theSession->numDuplicatedAckI2R,
		     (int)theSession->bytesRetranI2R.value);
#endif
	} else {
	  incrementTrafficCounter(&theSession->bytesRetranR2I, sent_length+rcvd_length);
	  incrementTrafficCounter(&theSession->remotePeer->pktsDuplicatedAckSent, 1);
	  incrementTrafficCounter(&theSession->initiator->pktsDuplicatedAckRcvd, 1);
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
    } else if(theSession->lastFlags & TH_RST) {
      theSession->sessionState = FLAG_STATE_TIMEOUT;
    }

#if 0
    traceEvent(CONST_TRACE_NOISY, "==> %s%s%s%s%s",
	       (theSession->lastFlags & TH_SYN) ? " SYN" : "",
	       (theSession->lastFlags & TH_ACK) ? " ACK" : "",
	       (theSession->lastFlags & TH_FIN) ? " FIN" : "",
	       (theSession->lastFlags & TH_RST) ? " RST" : "",
	       (theSession->lastFlags & TH_PUSH) ? " PUSH" : "");

    traceEvent(CONST_TRACE_NOISY, "==> %s [len=%d]",
	       print_flags(theSession, buf, sizeof(buf)), length);
#endif

    if((theSession->sessionState == FLAG_STATE_FIN2_ACK2)
       || (theSession->lastFlags & TH_RST)) /* abortive release */ {
      if(theSession->sessionState == FLAG_STATE_SYN_ACK) {
	/*
	  Rcvd RST packet before to complete the 3-way handshake.
	  Note that the message is emitted only of the reset is received
	  while in FLAG_STATE_SYN_ACK. In fact if it has been received in
	  FLAG_STATE_SYN this message has not to be emitted because this is
	  a rejected session.
	*/
	if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	  traceEvent(CONST_TRACE_WARNING, "TCP session [%s:%d]<->[%s:%d] reset by %s "
		     "without completing 3-way handshake",
		     srcHost->hostResolvedName, sport,
		     dstHost->hostResolvedName, dport,
		     srcHost->hostResolvedName);
	  dumpSuspiciousPacket(actualDeviceId, h, p);
	}

	theSession->sessionState = FLAG_STATE_TIMEOUT;
      }

      if(sport == IP_TCP_PORT_HTTP)
	updateHTTPVirtualHosts(theSession->virtualPeerName, srcHost,
			       theSession->bytesSent, theSession->bytesRcvd);
      else
	updateHTTPVirtualHosts(theSession->virtualPeerName, dstHost,
			       theSession->bytesRcvd, theSession->bytesSent);
    }
  }

  /* Update session stats */
  if(flowDirection == FLAG_CLIENT_TO_SERVER) {
    incrementTrafficCounter(&theSession->bytesProtoSent, packetDataLength);
    incrementTrafficCounter(&theSession->bytesSent, sent_length);
    incrementTrafficCounter(&theSession->bytesRcvd, rcvd_length);
    theSession->pktSent++;
  } else {
    incrementTrafficCounter(&theSession->bytesProtoRcvd, packetDataLength);
    incrementTrafficCounter(&theSession->bytesRcvd, sent_length);
    incrementTrafficCounter(&theSession->bytesSent, rcvd_length);
    theSession->pktRcvd++;
  }

  if((theSession->pktRcvd < 20) && (theSession->pktSent < 20)) {
    if((ip_offset > 0) && (theSession->l7.major_proto == IPOQUE_PROTOCOL_UNKNOWN)) {
      u_int64_t when = ((u_int64_t) h->ts.tv_sec) * 1000 /* detection_tick_resolution */ + h->ts.tv_usec / 1000 /* (1000000 / detection_tick_resolution) */;

      accessMutex(&myGlobals.device[actualDeviceId].l7.l7Mutex, "l7Mutex");
      theSession->l7.major_proto = ipoque_detection_process_packet(myGlobals.device[actualDeviceId].l7.l7handler,
								   theSession->l7.flow, (u_int8_t *)&p[ip_offset],
								   h->caplen-ip_offset, when,
								   (sport == theSession->sport) ? theSession->l7.src : theSession->l7.dst,
								   (sport == theSession->sport) ? theSession->l7.dst : theSession->l7.src);
      releaseMutex(&myGlobals.device[actualDeviceId].l7.l7Mutex);

      if(theSession->l7.major_proto != IPOQUE_PROTOCOL_UNKNOWN) {
	/* traceEvent(CONST_TRACE_ERROR, "l7.major_proto=%d", theSession->l7.major_proto); */
	freeOpenDPI(theSession);

	switch(theSession->l7.major_proto) {
	case IPOQUE_PROTOCOL_MAIL_SMTP:
	  setHostFlag(FLAG_HOST_TYPE_SVC_SMTP, srcHost);
	  break;
	case IPOQUE_PROTOCOL_MAIL_POP:
	  setHostFlag(FLAG_HOST_TYPE_SVC_POP, srcHost);
	  break;
	case IPOQUE_PROTOCOL_MAIL_IMAP:
	  setHostFlag(FLAG_HOST_TYPE_SVC_IMAP, srcHost);
	  break;
	case IPOQUE_PROTOCOL_LDAP:
	  setHostFlag(FLAG_HOST_TYPE_SVC_DIRECTORY, srcHost);
	  break;
	case IPOQUE_PROTOCOL_FTP:
	  setHostFlag(FLAG_HOST_TYPE_SVC_FTP, srcHost);
	  break;
	case IPOQUE_PROTOCOL_HTTP:
	  setHostFlag(FLAG_HOST_TYPE_SVC_HTTP, srcHost);
	  break;
	case IPOQUE_PROTOCOL_NETBIOS:
	  setHostFlag(FLAG_HOST_TYPE_SVC_WINS, srcHost);
	  break;
	case NTOP_PROTOCOL_FACEBOOK:
	  setHostFlag(FLAG_HOST_TYPE_SVC_FACEBOOK_CLIENT, srcHost);
	  break;
	case NTOP_PROTOCOL_TWITTER:
	  setHostFlag(FLAG_HOST_TYPE_SVC_TWITTER_CLIENT, srcHost);
	  break;
	}
      }
    }
  } else if((!theSession->l7.proto_guessed)
	    && (theSession->l7.major_proto == IPOQUE_PROTOCOL_UNKNOWN)) {
    theSession->l7.major_proto = 
      ntop_guess_undetected_protocol(proto, 
				     srcHost->hostIp4Address.s_addr, sport, 
				     dstHost->hostIp4Address.s_addr, dport);
    theSession->l7.proto_guessed = 1;
  }

  if(theSession->l7.major_proto != IPOQUE_PROTOCOL_UNKNOWN)
    freeOpenDPI(theSession);

  myGlobals.device[actualDeviceId].l7.protoTraffic[theSession->l7.major_proto] += h->len;

  if(myGlobals.l7.numSupportedProtocols > theSession->l7.major_proto) {
    srcHost->l7.traffic[theSession->l7.major_proto].bytesSent += h->len;
    dstHost->l7.traffic[theSession->l7.major_proto].bytesRcvd += h->len;
  } else
    traceEvent(CONST_TRACE_WARNING, "Internal error: protocol overflow [%u/%u]",
	       theSession->l7.major_proto, myGlobals.l7.numSupportedProtocols);

  /* Immediately free the session */
  if(theSession->sessionState == FLAG_STATE_TIMEOUT) {
    if(myGlobals.device[actualDeviceId].sessions[idx] == theSession) {
      myGlobals.device[actualDeviceId].sessions[idx] = theSession->next;
    } else
      prevSession->next = theSession->next;

#if DELAY_SESSION_PURGE
    theSession->sessionState = FLAG_STATE_END; /* Session freed by scanTimedoutTCPSessions */
#else
    freeSession(theSession, actualDeviceId, 1, 1 /* lock purgeMutex */);
#endif
    releaseMutex(&myGlobals.sessionsMutex[mutex_idx]);
    return(NULL);
  }

  releaseMutex(&myGlobals.sessionsMutex[mutex_idx]);
  return(theSession);
}

/* ************************************ */

IPSession* handleSession(const struct pcap_pkthdr *h,
			 const u_char *p,
			 u_int8_t proto,
                         u_short fragmentedData, u_int tcpWin,
                         HostTraffic *srcHost, u_short sport,
                         HostTraffic *dstHost, u_short dport,
                         u_int sent_length, u_int rcvd_length /* Always 0 except for NetFlow v9 */,
			 u_int ip_offset, struct tcphdr *tp,
                         u_int packetDataLength, u_char* packetData,
                         int actualDeviceId, u_short *newSession,
			 u_int16_t major_proto,
			 u_char real_session /* vs. faked/netflow-session */) {
  IPSession *theSession = NULL;
  u_short sessionType = 0;
  struct tcphdr static_tp;

  (*newSession) = 0; /* Default */

  if(!myGlobals.runningPref.enableSessionHandling)
    return(NULL);
  else {
    if(myGlobals.device[actualDeviceId].sessions == NULL)
      myGlobals.device[actualDeviceId].sessions = (IPSession**)calloc(sizeof(IPSession*), MAX_TOT_NUM_SESSIONS);
  }

  if(myGlobals.device[actualDeviceId].sessions == NULL)
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
  if(myGlobals.runningPref.enablePacketDecoding 
     && (proto == IPPROTO_UDP)
     && (p != NULL)
     && (srcHost->hostIpAddress.hostFamily == AF_INET)
     && (dstHost->hostIpAddress.hostFamily == AF_INET))
    handleBootp(srcHost, dstHost, sport, dport, packetDataLength, packetData, actualDeviceId, h, p);

  if(broadcastHost(srcHost) || broadcastHost(dstHost)) /* (**) */
    return(theSession);

  sessionType = proto;

#ifdef SESSION_TRACE_DEBUG
  {
    char buf[32], buf1[32];

    traceEvent(CONST_TRACE_INFO, "DEBUG: [%s] %s:%d -> %s:%d",
	       sessionType == IPPROTO_UDP ? "UDP" : "TCP",
	       _addrtostr(&srcHost->hostIpAddress, buf, sizeof(buf)), sport,
	       _addrtostr(&dstHost->hostIpAddress, buf1, sizeof(buf1)), dport);

    if(tp) {
      printf("DEBUG: [%d]", tp->th_flags);
      if(tp->th_flags & TH_ACK)  printf("ACK ");
      if(tp->th_flags & TH_SYN)  printf("SYN ");
      if(tp->th_flags & TH_FIN)  printf("FIN ");
      if(tp->th_flags & TH_RST)  printf("RST ");
      if(tp->th_flags & TH_PUSH) printf("PUSH");
      printf("\n");
    }
  }
#endif

  if((sessionType == IPPROTO_UDP) && (tp == NULL)) {
    tp = &static_tp;
    memset(tp, 0, sizeof(struct tcphdr));
  }

  theSession = handleTCPUDPSession(sessionType, h, p, fragmentedData, tcpWin, srcHost, sport,
				   dstHost, dport, sent_length, rcvd_length,
				   ip_offset, tp, packetDataLength,
				   packetData, actualDeviceId, newSession, major_proto);

  if(p != NULL) {
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
	dumpSuspiciousPacket(actualDeviceId, h, p);
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
	dumpSuspiciousPacket(actualDeviceId, h, p);
      }
    }
  }

  return(theSession);
}

/* ************************************ */

char *getProtoName(u_int8_t proto, u_short protoId) {
  if((proto == IPPROTO_TCP) 
     || (proto == IPPROTO_UDP) 
     || (proto == 0 /* any */)) {
    char *prot_long_str[] = { IPOQUE_PROTOCOL_LONG_STRING };
    
    if(protoId < IPOQUE_MAX_SUPPORTED_PROTOCOLS)
      return(prot_long_str[protoId]);
    else if(protoId <= (IPOQUE_MAX_SUPPORTED_PROTOCOLS + myGlobals.numIpProtosToMonitor)) {
      u_int id = protoId - IPOQUE_MAX_SUPPORTED_PROTOCOLS;
      return(myGlobals.ipTrafficProtosNames[id]);
    } else
      return(prot_long_str[IPOQUE_PROTOCOL_UNKNOWN]);
  } else {
    return("");
  }
}

