/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
 *
 *  			     http://www.ntop.org/
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

/*
 * Copyright (c) 1994, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
  #define DNS_SNIFF_DEBUG
  #define DNS_DEBUG
  #define GDBM_DEBUG
  #define FREE_HOST_INFO
  #define PURGE_DEBUG
  #define PACKET_DEBUG
  #define FRAGMENT_DEBUG
*/

/* #define HASH_DEBUG */

#define SESSION_PATCH /* Experimental (L.Deri) */

/* #define PRINT_UNKNOWN_PACKETS */
/* #define MAPPING_DEBUG */


#include "ntop.h"

static const struct pcap_pkthdr *h_save;
static const u_char *p_save;
static u_char ethBroadcast[] = { 255, 255, 255, 255, 255, 255 };

#ifdef HASH_DEBUG
static void dumpHash(); /* Forward */
#endif

 /* ************************************ */

u_int _checkSessionIdx(u_int idx, int actualDeviceId, char* file, int line) {
  if(idx > myGlobals.device[actualDeviceId].actualHashSize)
    traceEvent(TRACE_ERROR,
	       "Index error idx=%u @ [%s:%d]\n", idx, file, line);
  return(idx);
}

/* ******************************* */

u_int findHostInfo(struct in_addr *hostIpAddress, int actualDeviceId) {
  u_int i;

  for(i=0; i<myGlobals.device[actualDeviceId].actualHashSize; i++)
    if(myGlobals.device[actualDeviceId].hash_hostTraffic[i] != NULL)
      if(myGlobals.device[actualDeviceId].hash_hostTraffic[i]->hostIpAddress.s_addr
	 == hostIpAddress->s_addr)
	return i;

  return(NO_PEER);
}

/* ******************************* */

u_int getHostInfo(struct in_addr *hostIpAddress,
		  u_char *ether_addr,
		  u_char checkForMultihoming,
		  u_char forceUsingIPaddress,
		  int actualDeviceId) {
  u_int idx, i, isMultihomed = 0, numRuns=0, initialIdx;
#ifndef MULTITHREADED
  u_int run=0;
#endif
  HostTraffic *el=NULL;
  u_int firstEmptySlot = NO_PEER;
  char buf[32];
  short useIPAddressForSearching = forceUsingIPaddress;
  char* symEthName = NULL, *ethAddr;
  u_char setSpoofingFlag = 0, hostFound = 0;

  if((hostIpAddress == NULL) && (ether_addr == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING: both Ethernet and IP addresses are NULL");
    return(NO_PEER);
  }

  idx = computeInitialHashIdx(hostIpAddress, ether_addr, 
			      &useIPAddressForSearching, actualDeviceId);
  initialIdx = idx;

#ifdef DEBUG
  if(strcmp(etheraddr_string(ether_addr), "00:D0:B7:19:C0:4C") == 0) {
    traceEvent(TRACE_INFO, "INFO: here we go [initialIdx=%d]", initialIdx);
    dumpHash();
  }
#endif

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Searching from slot %d [size=%d]\n",
	     idx, myGlobals.device[actualDeviceId].actualHashSize);
#endif

  /* 
     IMPORTANT NOTE
     don't set i=1 because the real index is idx and not i     
  */

  if(myGlobals.trackOnlyLocalHosts && (initialIdx == myGlobals.otherHostEntryIdx)) {
    el = myGlobals.device[actualDeviceId].hash_hostTraffic[myGlobals.otherHostEntryIdx];
    hostFound = 1;
  } else {
    for(i=0; i<myGlobals.device[actualDeviceId].actualHashSize; i++) {
    HASH_SLOT_FOUND:
      el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx]; /* (**) */
#ifdef HASH_DEBUG
      numRuns++;
#endif
      if(el != NULL) {
	if(useIPAddressForSearching == 0) {
	  /* compare with the ethernet-address */
	  if (memcmp(el->ethAddress, ether_addr, ETHERNET_ADDRESS_LEN) == 0) {
	    if(hostIpAddress != NULL) {
	      if((!isMultihomed) && checkForMultihoming) {
		/*
		  This is a local address hence this is
		  a potential multihomed host.
		*/

		if((el->hostIpAddress.s_addr != 0x0)
		   && (el->hostIpAddress.s_addr != hostIpAddress->s_addr)) {
		  isMultihomed = 1;
		  FD_SET(HOST_MULTIHOMED, &el->flags);
		}

		if(el->hostNumIpAddress[0] == '\0') {
		  /* This entry didn't have IP fields set: let's set them now */
		  el->hostIpAddress.s_addr = hostIpAddress->s_addr;
		  strncpy(el->hostNumIpAddress,
			  _intoa(*hostIpAddress, buf, sizeof(buf)),
			  sizeof(el->hostNumIpAddress));

		  if(myGlobals.numericFlag == 0)
		    ipaddr2str(el->hostIpAddress, actualDeviceId);

		  /* else el->hostSymIpAddress = el->hostNumIpAddress;
		     The line below isn't necessary because (**) has
		     already set the pointer */
		  if(isBroadcastAddress(&el->hostIpAddress))
		    FD_SET(BROADCAST_HOST_FLAG, &el->flags);
		}
	      }
	    }
	  
	    hostFound = 1;
	    break;
	  } else if((hostIpAddress != NULL)
		    && (el->hostIpAddress.s_addr == hostIpAddress->s_addr)) {
	    /* Spoofing or duplicated MAC address:
	       two hosts with the same IP address and different MAC
	       addresses
	    */

	    setSpoofingFlag = 1;

	    if(!hasDuplicatedMac(el)) {
	      FD_SET(HOST_DUPLICATED_MAC, &el->flags);

	      if(myGlobals.enableSuspiciousPacketDump) {
		traceEvent(TRACE_WARNING,
			   "Two MAC addresses found for the same IP address "
			   "%s: [%s/%s] (spoofing detected?)",
			   el->hostNumIpAddress,
			   etheraddr_string(ether_addr), el->ethAddressString);
		dumpSuspiciousPacket(actualDeviceId);
	      }
	    }
	  }
	} else {       	
	  if(el->hostIpAddress.s_addr == hostIpAddress->s_addr) {
	    hostFound = 1;
	    break;
	  }
	}
      } else {
	/* ************************

	   -- 1 --

	   This code needs to be optimised. In fact everytime a
	   new host is added to the hash, the whole hash has to
	   be scan. This shouldn't happen with hashes. Unfortunately
	   due to the way ntop works, a entry can appear and
	   disappear several times from the hash, hence its position
	   in the hash might change.

	   See also -- 2 --.

	   Courtesy of Andreas Pfaller <apfaller@yahoo.com.au>.

	   ************************ */

	if(firstEmptySlot == NO_PEER) 
	  firstEmptySlot = idx;
      }

      idx = (idx+1) % myGlobals.device[actualDeviceId].actualHashSize;
    }
  }

  if(!hostFound) {
    if(firstEmptySlot != NO_PEER) {
      /* New table entry */
      int len;

      if(myGlobals.usePersistentStorage) {
	if((hostIpAddress == NULL) || (isLocalAddress(hostIpAddress)))
	  el = resurrectHostTrafficInstance(etheraddr_string(ether_addr));
	else
	  el = resurrectHostTrafficInstance(_intoa(*hostIpAddress, buf, sizeof(buf)));
      } else
	el = NULL;

      if(el == NULL) {
	el = (HostTraffic*)malloc(sizeof(HostTraffic));
	memset(el, 0, sizeof(HostTraffic));
	el->firstSeen=myGlobals.actTime;
      }

      resetHostsVariables(el);

      if(isMultihomed) FD_SET(HOST_MULTIHOMED, &el->flags);     

      el->portsUsage = (PortUsage**)calloc(sizeof(PortUsage*), TOP_ASSIGNED_IP_PORTS);

      len = (size_t)myGlobals.numIpProtosToMonitor*sizeof(ProtoTrafficInfo);
      el->protoIPTrafficInfos = (ProtoTrafficInfo*)malloc(len);
      memset(el->protoIPTrafficInfos, 0, len);

      myGlobals.device[actualDeviceId].hash_hostTraffic[firstEmptySlot] = el; /* Insert a new entry */
      idx = firstEmptySlot;
      myGlobals.device[actualDeviceId].hostsno++;

#ifdef DEBUG
      traceEvent(TRACE_INFO, "Adding idx=%d on device=%d [actualHashSize=%d]\n",
		 firstEmptySlot, actualDeviceId, myGlobals.device[actualDeviceId].actualHashSize);
#endif

      if(ether_addr != NULL) {
	if((hostIpAddress == NULL)
	   || ((hostIpAddress != NULL)
	       && isPseudoLocalAddress(hostIpAddress)
	       /* && (!isBroadcastAddress(hostIpAddress))*/
	       )) {
	  /* This is a local address and then the
	     ethernet address does make sense */
	  ethAddr = etheraddr_string(ether_addr);

	  memcpy(el->ethAddress, ether_addr, ETHERNET_ADDRESS_LEN);
	  strncpy(el->ethAddressString, ethAddr, sizeof(el->ethAddressString));
	  symEthName = getSpecialMacInfo(el, (short)(!myGlobals.separator[0]));
	  FD_SET(SUBNET_LOCALHOST_FLAG, &el->flags);
	  FD_SET(SUBNET_PSEUDO_LOCALHOST_FLAG, &el->flags);
	} else if(hostIpAddress != NULL) {
	  /* This is packet that's being routed or belonging to a
	     remote network that uses the same physical wire (or forged)*/
	  memcpy(el->lastEthAddress, ether_addr, ETHERNET_ADDRESS_LEN);

	  memcpy(el->ethAddress, &hostIpAddress->s_addr, 4); /* Dummy/unique eth address */
	  if(!myGlobals.borderSnifferMode) FD_CLR(SUBNET_LOCALHOST_FLAG, &el->flags);

	  if(isPrivateAddress(hostIpAddress)) FD_SET(PRIVATE_IP_ADDRESS, &el->flags);

	  if(!isBroadcastAddress(hostIpAddress)) {
	    if(myGlobals.borderSnifferMode || isPseudoLocalAddress(hostIpAddress))
	      FD_SET(SUBNET_PSEUDO_LOCALHOST_FLAG, &el->flags);
	    else
	      FD_CLR(SUBNET_PSEUDO_LOCALHOST_FLAG, &el->flags);
	  }
	} else {
	  FD_CLR(SUBNET_LOCALHOST_FLAG, &el->flags);
	  FD_CLR(SUBNET_PSEUDO_LOCALHOST_FLAG, &el->flags);
	}

	if(strncmp(el->ethAddressString, "FF:", 3) == 0) {
	  /*
	    The trick below allows me not to duplicate the
	    "<broadcast>" string in the code
	  */
	  el->hostIpAddress.s_addr = INADDR_BROADCAST;
	  FD_SET(BROADCAST_HOST_FLAG, &el->flags);
	  if(isMulticastAddress(&el->hostIpAddress))
	    FD_SET(MULTICAST_HOST_FLAG, &el->flags);
	  strncpy(el->hostNumIpAddress,
		  _intoa(el->hostIpAddress, buf, sizeof(buf)),
		  strlen(el->hostNumIpAddress));
	  strncpy(el->hostSymIpAddress, el->hostNumIpAddress,
		  MAX_HOST_SYM_NAME_LEN);

	  if((el->hostIpAddress.s_addr != 0x0) /* 0.0.0.0 */
	     && (el->hostIpAddress.s_addr != 0xFFFFFFFF) /* 255.255.255.255 */
	     && isBroadcastAddress(&el->hostIpAddress)) {
	    /* 
	       The sender of this packet has obviously a wrong netmask because:
	       - it is a local host
	       - it has sent a packet to a broadcast address 
	       - it has not used the FF:FF:FF:FF:FF:FF MAC address
	    */

	    traceEvent(TRACE_WARNING, "WARNING: Wrong netmask detected [%s/%s]",
		       _intoa(el->hostIpAddress, buf, sizeof(buf)),
		       el->ethAddressString);
	  }

	} else if(hostIpAddress != NULL) {
	  el->hostIpAddress.s_addr = hostIpAddress->s_addr;
	  strncpy(el->hostNumIpAddress,
		  _intoa(*hostIpAddress, buf, sizeof(buf)),
		  sizeof(el->hostNumIpAddress));
	  if(isBroadcastAddress(&el->hostIpAddress)) FD_SET(BROADCAST_HOST_FLAG, &el->flags);
	  if(isMulticastAddress(&el->hostIpAddress)) FD_SET(MULTICAST_HOST_FLAG, &el->flags);
	  if(isPrivateAddress(hostIpAddress))        FD_SET(PRIVATE_IP_ADDRESS,  &el->flags);

	  /* Trick to fill up the address cache */
	  if(myGlobals.numericFlag == 0)
	    ipaddr2str(el->hostIpAddress, actualDeviceId);
	  else
	    strncpy(el->hostSymIpAddress,
		    el->hostNumIpAddress, MAX_HOST_SYM_NAME_LEN);
	} else {
	  /* el->hostNumIpAddress == "" */
	  if(symEthName[0] != '\0') {
	    char buf[MAX_HOST_SYM_NAME_LEN];

	    if(snprintf(buf, sizeof(buf), "%s <IMG SRC=/card.gif BORDER=0>", symEthName) < 0)
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    else
	      strncpy(el->hostSymIpAddress, buf, MAX_HOST_SYM_NAME_LEN);
	  } else
	    strncpy(el->hostSymIpAddress,
		    el->hostNumIpAddress, MAX_HOST_SYM_NAME_LEN);
	}

#ifdef DEBUG
	/*if((strcmp(etheraddr_string(ether_addr), "08:00:20:89:79:D7") == 0)
	  || (strcmp(el->hostSymIpAddress, "more") == 0))*/
	printf("Added a new hash_hostTraffic entry [%s/%s/%s/%d]\n",
	       etheraddr_string(ether_addr), el->hostSymIpAddress,
	       el->hostNumIpAddress, myGlobals.device[actualDeviceId].hostsno);
#endif

	el->lastSeen = myGlobals.actTime;
	checkSpoofing(idx, actualDeviceId);
      }
    } else {
      /* The hashtable is full */
#ifndef MULTITHREADED
      if(run == 0) {
	purgeIdleHosts(1, actualDeviceId);
      } else
#else
	{
	  /* No space yet: let's delete the oldest table entry */
	  int candidate = 0;
	  time_t lastSeenCandidate=0;
	  HostTraffic* hostToFree;

	  for(i=1; i<myGlobals.device[actualDeviceId].actualHashSize; i++)
	    if(myGlobals.device[actualDeviceId].hash_hostTraffic[i] != NULL) {
	      if((candidate == 0)
		 || (myGlobals.device[actualDeviceId].hash_hostTraffic[i]->lastSeen
		     < lastSeenCandidate)) {
		candidate = i;
		if((myGlobals.device[actualDeviceId].hash_hostTraffic[i]->lastSeen
		    +IDLE_HOST_PURGE_TIMEOUT)
		   > myGlobals.actTime)
		  break;
		else
		  lastSeenCandidate = myGlobals.device[actualDeviceId].
		    hash_hostTraffic[i]->lastSeen;
	      }
	    }

	  hostToFree = myGlobals.device[actualDeviceId].hash_hostTraffic[candidate];
	  freeHostInfo(actualDeviceId, candidate, 1, actualDeviceId);
	  idx = candidate; /* this is a hint for (**) */
	}
#endif

#ifndef MULTITHREADED
      run++;
#endif
      goto HASH_SLOT_FOUND;
    }
  } else {
#ifdef HASH_DEBUG
    if((numRuns*2) > myGlobals.device[actualDeviceId].actualHashSize) {
      traceEvent(TRACE_ERROR, "Num Runs: %d/%d [idx=%d][initialIdx=%d]", 
		 numRuns, myGlobals.device[actualDeviceId].actualHashSize, 
		 idx, initialIdx);
      dumpHash();
    }
#endif
  }

  if(el != NULL) {
    el->lastSeen = myGlobals.actTime;

    if(setSpoofingFlag)
      FD_SET(HOST_DUPLICATED_MAC, &el->flags);

#ifdef DEBUG
    traceEvent(TRACE_INFO, "getHostInfo(idx=%d/actualDeviceId=%d) [%s/%s/%s/%d/%d]\n",
	       idx, actualDeviceId,
	       etheraddr_string(ether_addr), el->hostSymIpAddress,
	       el->hostNumIpAddress, myGlobals.device[actualDeviceId].hostsno,
	       useIPAddressForSearching);
#endif
  }

  return(idx);
}

/* ************************************ */

char* getNamedPort(int port) {
  static char outStr[2][8];
  static short portBufIdx=0;
  char* svcName;

  portBufIdx = (portBufIdx+1)%2;

  svcName = getPortByNum(port, IPPROTO_TCP);
  if(svcName == NULL)
    svcName = getPortByNum(port, IPPROTO_UDP);

  if(svcName == NULL) {
    if(snprintf(outStr[portBufIdx], 8, "%d", port) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  } else {
    strncpy(outStr[portBufIdx], svcName, 8);
  }

  return(outStr[portBufIdx]);
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
      traceEvent(TRACE_ERROR, "===> Magic assertion failed (2)");
      scanner = NULL;
      break;
    } else if((scanner->port == port)
	      && (scanner->initiator == role))
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

#ifdef DEBUG
  printSession(theSession, sessionType, scanner->sessionCounter);
#endif

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

void allocateSecurityHostPkts(HostTraffic *srcHost) {
  if(srcHost->secHostPkts == NULL) {
    srcHost->secHostPkts = (SecurityHostProbes*)malloc(sizeof(SecurityHostProbes));
    resetSecurityHostTraffic(srcHost);
  }
}

/* ************************************ */

void freeSession(IPSession *sessionToPurge, int actualDeviceId) {
  /* Session to purge */
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
      allocateSecurityHostPkts(theRemHost);
      incrementUsageCounter(&theRemHost->secHostPkts->closedEmptyTCPConnRcvd,
			    sessionToPurge->initiatorIdx, actualDeviceId);

      if(myGlobals.enableSuspiciousPacketDump)
	traceEvent(TRACE_WARNING, fmt,
		   theHost->hostSymIpAddress, sessionToPurge->sport,
		   theRemHost->hostSymIpAddress, sessionToPurge->dport,
		   sessionToPurge->pktSent, sessionToPurge->pktRcvd);
    }
  }


  /*
   * Having updated the session information, 'theSession'
   * can now be purged.
   */
  sessionToPurge->magic = 0;
  if(myGlobals.enableNetFlowSupport) sendTCPSessionFlow(sessionToPurge, actualDeviceId);
  notifyTCPSession(sessionToPurge, actualDeviceId);
#ifdef HAVE_MYSQL
  mySQLnotifyTCPSession(sessionToPurge, actualDeviceId);
#endif
  myGlobals.numTerminatedSessions++;

  myGlobals.device[actualDeviceId].numTcpSessions--;

#ifdef DEBUG
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

	  if(myGlobals.device[actualDeviceId].tcpSession[idx] == myGlobals.device[actualDeviceId].tcpSession[idx]->next) {
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

static void updateUsedPorts(HostTraffic *srcHost,
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

static void updateRoutedTraffic(HostTraffic *router) {
  if(router != NULL) {
    if(router->routedTraffic == NULL) {
      int mallocLen = sizeof(RoutingCounter);
      
	router->routedTraffic = (RoutingCounter*)malloc(mallocLen);
	memset(router->routedTraffic, 0, mallocLen);
    }
    
    if(router->routedTraffic != NULL) { /* malloc() didn't fail */
      router->routedTraffic->routedPkts++;
      router->routedTraffic->routedBytes += h_save->len - sizeof(struct ether_header);
    }
  }
}


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
  u_int idx, i;
  IPSession *theSession = NULL;
  short flowDirection = CLIENT_TO_SERVER;
  char addedNewEntry = 0;
  u_short sessionType, check, found=0;
#ifdef ENABLE_NAPSTER
  u_short napsterDownload = 0;
#endif
  u_short sessSport, sessDport;
  HostTraffic *srcHost, *dstHost;
  struct timeval tvstrct;
  u_int firstEmptySlot = NO_PEER;
  u_char rcStr[256];
  int len = 0;

  if(!myGlobals.enableSessionHandling)
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

 RESCAN_LIST:
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
    traceEvent(TRACE_INFO, "Search for session: %d (%d <-> %d)",
	       found, sport, dport);
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

      /* MULTIPLY_FACTORY courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
      if(myGlobals.device[actualDeviceId].numTcpSessions >
	 (myGlobals.device[actualDeviceId].numTotSessions*AVERAGE_BUCKET_FILL)) {
	/* If possible this table will be enlarged */

	if(extendTcpSessionsHash(actualDeviceId) == 0) {
	  /* The table has been extended successfully */

	  /* A goto il necessary as when the hash is extended all
	     the pointers changed hence some references (eg. sessions[])
	     are no longer valid) */
	  goto RESCAN_LIST;
	}
      }

      if(myGlobals.device[actualDeviceId].numTcpSessions >
	 (myGlobals.device[actualDeviceId].numTotSessions*MULTIPLY_FACTORY)) {
	return(NULL); /* No space left */
      } else {
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

#ifdef TRACE_TRAFFIC_INFO
	traceEvent(TRACE_INFO, "New TCP session [%s:%d] <-> [%s:%d] (# sessions = %d)",
		   dstHost->hostNumIpAddress, dport,
		   srcHost->hostNumIpAddress, sport,
		   myGlobals.device[actualDeviceId].numTcpSessions);
#endif

#ifdef ENABLE_NAPSTER
	/* Let's check whether this is a Napster session */
	if(numNapsterSvr > 0) {
	  for(i=0; i<MAX_NUM_NAPSTER_SERVER; i++) {
	    if(((myGlobals.napsterSvr[i].serverPort == sport)
		&& (myGlobals.napsterSvr[i].serverAddress.s_addr == srcHost->hostIpAddress.s_addr))
	       || ((myGlobals.napsterSvr[i].serverPort == dport)
		   && (myGlobals.napsterSvr[i].serverAddress.s_addr == dstHost->hostIpAddress.s_addr))) {
	      theSession->napsterSession = 1;
	      myGlobals.napsterSvr[i].serverPort = 0; /* Free slot */
	      numNapsterSvr--;
	      FD_SET(HOST_SVC_NAPSTER_CLIENT, &srcHost->flags);
	      FD_SET(HOST_SVC_NAPSTER_SERVER, &dstHost->flags);

#ifdef TRACE_TRAFFIC_INFO
	      traceEvent(TRACE_INFO, "NAPSTER new download session: %s->%s\n",
			 srcHost->hostSymIpAddress,
			 dstHost->hostSymIpAddress);
#endif

	      if(srcHost->napsterStats == NULL) {
		srcHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
		memset(srcHost->napsterStats, 0, sizeof(NapsterStats));
	      }

	      if(dstHost->napsterStats == NULL) {
		dstHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
		memset(dstHost->napsterStats, 0, sizeof(NapsterStats));
	      }

	      srcHost->napsterStats->numDownloadsRequested++,
		dstHost->napsterStats->numDownloadsServed++;
	    }
	  }
	}

	if(!theSession->napsterSession)  {
	  /* This session has not been recognized as a Napster
	     session. It might be that ntop has been started
	     after the session started, or that ntop has
	     lost a few packets. Let's do a final check...
	  */
#define NAPSTER_DOMAIN "napster.com"

	  if(
	     (((strlen(srcHost->hostSymIpAddress) > strlen(NAPSTER_DOMAIN))
	       && (strcmp(&srcHost->hostSymIpAddress[strlen(srcHost->hostSymIpAddress)-
						    strlen(NAPSTER_DOMAIN)],
			  NAPSTER_DOMAIN) == 0) && (sport == 8888)))
	     ||
	     (((strlen(dstHost->hostSymIpAddress) > strlen(NAPSTER_DOMAIN))
	       && (strcmp(&dstHost->hostSymIpAddress[strlen(dstHost->hostSymIpAddress)-
						    strlen(NAPSTER_DOMAIN)],
			  NAPSTER_DOMAIN) == 0)) && (dport == 8888))) {

	    theSession->napsterSession = 1;

#ifdef TRACE_TRAFFIC_INFO
	    traceEvent(TRACE_INFO, "NAPSTER new session: %s <->%s\n",
		       srcHost->hostSymIpAddress,
		       dstHost->hostSymIpAddress);
#endif

	    if(srcHost->napsterStats == NULL) {
	      srcHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
	      memset(srcHost->napsterStats, 0, sizeof(NapsterStats));
	    }

	    if(dstHost->napsterStats == NULL) {
	      dstHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
	      memset(dstHost->napsterStats, 0, sizeof(NapsterStats));
	    }

	    if(sport == 8888) {
	      FD_SET(HOST_SVC_NAPSTER_SERVER, &srcHost->flags);
	      FD_SET(HOST_SVC_NAPSTER_CLIENT, &dstHost->flags);
	      srcHost->napsterStats->numConnectionsServed++,
		dstHost->napsterStats->numConnectionsRequested++;
	    } else {
	      FD_SET(HOST_SVC_NAPSTER_CLIENT, &srcHost->flags);
	      FD_SET(HOST_SVC_NAPSTER_SERVER, &dstHost->flags);
	      srcHost->napsterStats->numConnectionsRequested++,
		dstHost->napsterStats->numConnectionsServed++;
	    }
	  }
	}
#endif /* ENABLE_NAPSTER */
      }

      theSession->next = myGlobals.device[actualDeviceId].tcpSession[idx];
      myGlobals.device[actualDeviceId].tcpSession[idx] = theSession;
      theSession->initiatorIdx = checkSessionIdx(srcHostIdx);
      theSession->remotePeerIdx = checkSessionIdx(dstHostIdx);
      theSession->sport = sport;
      theSession->dport = dport;
      theSession->passiveFtpSession = isPassiveSession(dstHost->hostIpAddress.s_addr, dport);
      theSession->firstSeen = myGlobals.actTime;
      flowDirection = CLIENT_TO_SERVER;

#ifdef DEBUG
      printSession(theSession, sessionType, 0);
#endif
    } 
#if 0
    else {
      /* Existing session */

      if(theSession != myGlobals.device[actualDeviceId].tcpSession[idx]) {
	/* Move the session at the beginning of the list */
	prevSession->next = theSession->next;
	theSession->next = myGlobals.device[actualDeviceId].tcpSession[idx];
	myGlobals.device[actualDeviceId].tcpSession[idx] = theSession;

	/*
	traceEvent(TRACE_INFO, "Swapped session: %s:%d->%s:%d",
		   srcHost->hostNumIpAddress, sport,
		   dstHost->hostNumIpAddress, dport);
	*/
      }
    }
#endif

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
	    FD_SET(HOST_SVC_HTTP, &srcHost->flags);
	    dstHost->httpStats->numPositiveReplRcvd++;
	  } else {
	    srcHost->httpStats->numNegativeReplSent++;
	    FD_SET(HOST_SVC_HTTP, &srcHost->flags);
	    dstHost->httpStats->numNegativeReplRcvd++;
	  }

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
#ifdef ENABLE_NAPSTER
      } else if((sport == 8875 /* Napster Redirector */)
		&& (packetDataLength > 5)) {
	char address[64] = { 0 };
	int i;

	FD_SET(HOST_SVC_NAPSTER_REDIRECTOR, &srcHost->flags);
	FD_SET(HOST_SVC_NAPSTER_CLIENT,     &dstHost->flags);

	if(packetDataLength >= sizeof(address))
	  len = sizeof(address)-1;
	else
	  len = packetDataLength;

	strncpy(address, packetData, len);
	address[len-2] = 0;

#ifdef TRACE_TRAFFIC_INFO
	traceEvent(TRACE_INFO, "NAPSTER: %s->%s [%s][len=%d]\n",
		   srcHost->hostSymIpAddress,
		   dstHost->hostSymIpAddress,
		   address, packetDataLength);
#endif

	for(i=1; i<len-2; i++)
	  if(address[i] == ':') {
	    address[i] = '\0';
	    break;
	  }

	myGlobals.napsterSvr[myGlobals.napsterSvrInsertIdx].serverAddress.s_addr = ntohl(inet_addr(address));
	myGlobals.napsterSvr[myGlobals.napsterSvrInsertIdx].serverPort = atoi(&address[i+1]);
	myGlobals.napsterSvrInsertIdx = (myGlobals.napsterSvrInsertIdx+1) % MAX_NUM_NAPSTER_SERVER;
	numNapsterSvr++;

	if(srcHost->napsterStats == NULL) {
	  srcHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
	  memset(srcHost->napsterStats, 0, sizeof(NapsterStats));
	}
	if(dstHost->napsterStats == NULL) {
	  dstHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
	  memset(dstHost->napsterStats, 0, sizeof(NapsterStats));
	}

	srcHost->napsterStats->numConnectionsServed++,
	  dstHost->napsterStats->numConnectionsRequested++;
#endif /* NASPTER */
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
    
    if(myGlobals.enablePacketDecoding) {
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

#ifdef ENABLE_NAPSTER
    if(myGlobals.enablePacketDecoding) {
      /* Let's decode some Napster packets */
      if((!theSession->napsterSession)
	 && (packetData != NULL)
	 && (packetDataLength == 1)
	 && (theSession->bytesProtoRcvd == 0) /* This condition will not hold if you
						 move this line of code down this
						 function */
	 ) {
	/*
	  If this is a Napster Download then it should
	  look like "0x31 GET username song ...."
	*/

	if(packetData[0] == 0x31) {
	  theSession->napsterSession = 1;
	  napsterDownload = 1;
	}

	/*
	  traceEvent(TRACE_INFO, "Session check: %s:%d->%s:%d [%x]\n",
	  srcHost->hostSymIpAddress, sport,
	  dstHost->hostSymIpAddress, dport, packetData[0]);
	*/
      }

      if(theSession->napsterSession && (packetDataLength > 0) ) {
	if(srcHost->napsterStats == NULL) {
	  srcHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
	  memset(srcHost->napsterStats, 0, sizeof(NapsterStats));
	}

	if(dstHost->napsterStats == NULL) {
	  dstHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
	  memset(dstHost->napsterStats, 0, sizeof(NapsterStats));
	}

	srcHost->napsterStats->bytesSent += packetDataLength,
	  dstHost->napsterStats->bytesRcvd += packetDataLength;

	if(napsterDownload) {
	  FD_SET(HOST_SVC_NAPSTER_CLIENT, &srcHost->flags);
	  FD_SET(HOST_SVC_NAPSTER_CLIENT, &dstHost->flags);

#ifdef TRACE_TRAFFIC_INFO
	  traceEvent(TRACE_INFO, "NAPSTER new download session: %s->%s\n",
		     dstHost->hostSymIpAddress,
		     srcHost->hostSymIpAddress);
#endif
	  dstHost->napsterStats->numDownloadsRequested++,
	    srcHost->napsterStats->numDownloadsServed++;
	} else if((packetData != NULL) && (packetDataLength > 4)) {
	  if((packetData[1] == 0x0) && (packetData[2] == 0xC8) && (packetData[3] == 0x00)) {
	    srcHost->napsterStats->numSearchSent++, dstHost->napsterStats->numSearchRcvd++;

#ifdef TRACE_TRAFFIC_INFO
	    traceEvent(TRACE_INFO, "NAPSTER search: %s->%s\n",
		       srcHost->hostSymIpAddress,
		       dstHost->hostSymIpAddress);
#endif
	  } else if((packetData[1] == 0x0)
		    && (packetData[2] == 0xCC) && (packetData[3] == 0x00)) {
	    char tmpBuf[64], *remoteHost, *remotePort, *strtokState;

	    struct in_addr shost;

	    srcHost->napsterStats->numDownloadsRequested++,
	      dstHost->napsterStats->numDownloadsServed++;

	    /*
	      LEN 00 CC 00 <remote user name>
	      <remote user IP> <remote user port> <payload>
	    */

	    memcpy(tmpBuf, &packetData[4], (packetDataLength<64) ? packetDataLength : 63);
	    strtok_r(tmpBuf, " ", &strtokState); /* remote user */
	    if((remoteHost = strtok_r(NULL, " ", &strtokState)) != NULL) {
	      if((remotePort = strtok_r(NULL, " ", &strtokState)) != NULL) {

		myGlobals.napsterSvr[myGlobals.napsterSvrInsertIdx].serverPort = atoi(remotePort);
		if(myGlobals.napsterSvr[myGlobals.napsterSvrInsertIdx].serverPort != 0) {
		  myGlobals.napsterSvr[myGlobals.napsterSvrInsertIdx].serverAddress.s_addr = inet_addr(remoteHost);
		  myGlobals.napsterSvrInsertIdx = (myGlobals.napsterSvrInsertIdx+1) % MAX_NUM_NAPSTER_SERVER;
		  numNapsterSvr++;
		  shost.s_addr = inet_addr(remoteHost);
#ifdef TRACE_TRAFFIC_INFO
		  traceEvent(TRACE_INFO, "NAPSTER: %s requested download from %s:%s",
			     srcHost->hostSymIpAddress, remoteHost, remotePort);
#endif
		}
	      }
	    }
	  }
	}
      }
    }
#endif
       
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

#ifdef DEBUG
    printSession(&tmpSession, sessionType, 0);
#endif

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

  if((sport == 7)  || (dport == 7)  /* echo */
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

/* ************************************ */

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

/* *********************************** */

static IPSession* handleTCPSession(const struct pcap_pkthdr *h,
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
  IPSession* theSession = NULL;

  if(
#ifdef SESSION_PATCH
     1
#else
     (tp->th_flags & TH_SYN) == 0
#endif
     ) {
    /* When we receive SYN it means that the client is trying to
       open a session with the server hence the session is NOT YET
       open. That's why we don't count this as a session in this
       case.
    */
    theSession = handleSession(h, fragmentedData, tcpWin,
			       srcHostIdx, sport,
			       dstHostIdx, dport,
			       length, tp,
			       tcpDataLength, packetData, 
			       actualDeviceId);
  }

  if(myGlobals.isLsofPresent)
    handleLsof(srcHostIdx, sport, dstHostIdx, dport, length, actualDeviceId);

  return(theSession);
}

/* ************************************ */

static IPSession* handleUDPSession(const struct pcap_pkthdr *h,
				   u_short fragmentedData,
				   u_int srcHostIdx,
				   u_short sport,
				   u_int dstHostIdx,
				   u_short dport,
				   u_int length,
				   u_char* packetData,
				   int actualDeviceId) {
  IPSession* theSession = handleSession(h, fragmentedData, 0,
					srcHostIdx, sport,
					dstHostIdx, dport, length,
					NULL, length, packetData, actualDeviceId);

  if(myGlobals.isLsofPresent)
    handleLsof(srcHostIdx, sport, dstHostIdx, dport, length, actualDeviceId);

  return(theSession);
}

/* ************************************ */

static int handleIP(u_short port,
		    u_int srcHostIdx,
		    u_int dstHostIdx,
		    u_int length,
		    u_short isPassiveSession,
		    int actualDeviceId) {
  int idx;
  HostTraffic *srcHost, *dstHost;

  if(isPassiveSession) {
    /* Emulate non passive session */
    idx = mapGlobalToLocalIdx(20 /* ftp-data */);
  } else
    idx = mapGlobalToLocalIdx(port);

  if(idx == -1)
    return(-1); /* Unable to locate requested index */

  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];

  if((srcHost == NULL) || (dstHost == NULL)) {
    traceEvent(TRACE_INFO, "Sanity check failed (4) [Low memory?]");
    return(-1);
  }

  if(idx != NO_PEER) {
    if(subnetPseudoLocalHost(srcHost)) {
      if(subnetPseudoLocalHost(dstHost)) {
	if((srcHostIdx != myGlobals.broadcastEntryIdx) 
	   && (srcHostIdx != myGlobals.otherHostEntryIdx) 
	   && (!broadcastHost(srcHost)))
	  srcHost->protoIPTrafficInfos[idx].sentLoc += length;
	if((dstHostIdx != myGlobals.broadcastEntryIdx) 
	   && (dstHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(dstHost)))
	  dstHost->protoIPTrafficInfos[idx].rcvdLoc += length;
	myGlobals.device[actualDeviceId].ipProtoStats[idx].local += length;
      } else {
	if((srcHostIdx != myGlobals.broadcastEntryIdx) 
	   && (srcHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(srcHost)))
	  srcHost->protoIPTrafficInfos[idx].sentRem += length;
	if((dstHostIdx != myGlobals.broadcastEntryIdx) 
	   && (dstHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(dstHost)))
	  dstHost->protoIPTrafficInfos[idx].rcvdLoc += length;
	myGlobals.device[actualDeviceId].ipProtoStats[idx].local2remote += length;
      }
    } else {
      /* srcHost is remote */
      if(subnetPseudoLocalHost(dstHost)) {
	if((srcHostIdx != myGlobals.broadcastEntryIdx) 
	   && (srcHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(srcHost)))
	  srcHost->protoIPTrafficInfos[idx].sentLoc += length;
	if((dstHostIdx != myGlobals.broadcastEntryIdx) 
	   && (dstHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(dstHost)))
	  dstHost->protoIPTrafficInfos[idx].rcvdFromRem += length;
	myGlobals.device[actualDeviceId].ipProtoStats[idx].remote2local += length;
      } else {
	if((srcHostIdx != myGlobals.broadcastEntryIdx) 
	   && (srcHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(srcHost)))
	  srcHost->protoIPTrafficInfos[idx].sentRem += length;
	if((dstHostIdx != myGlobals.broadcastEntryIdx)
	   && (dstHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(dstHost)))
	  dstHost->protoIPTrafficInfos[idx].rcvdFromRem += length;
	myGlobals.device[actualDeviceId].ipProtoStats[idx].remote += length;
      }
    }
  }

  return(idx);
}

/* ************************************ */

static void addContactedPeers(u_int senderIdx, u_int receiverIdx, int actualDeviceId) {
  short i, found;
  HostTraffic *sender, *receiver;

  if(senderIdx == receiverIdx)
    return;

  sender = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(senderIdx)];
  receiver = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(receiverIdx)];

  /* ******************************* */

  if((senderIdx != myGlobals.broadcastEntryIdx) 
     && (senderIdx != myGlobals.otherHostEntryIdx)) {
    if(sender != NULL) {
      for(found=0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	if(sender->contactedSentPeers.peersIndexes[i] != NO_PEER) {
	  if((sender->contactedSentPeers.peersIndexes[i] == receiverIdx)
	     || (((receiverIdx == myGlobals.broadcastEntryIdx) 
		  || (receiverIdx == myGlobals.otherHostEntryIdx)
		  || broadcastHost(receiver))
		 && broadcastHost(myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(sender->contactedSentPeers.peersIndexes[i])]))) {
	    found = 1;
	    break;
	  }
	}

      if(found == 0)
	incrementUsageCounter(&sender->contactedSentPeers, receiverIdx, actualDeviceId);
    }
  }

  /* ******************************* */
  if((receiverIdx != myGlobals.broadcastEntryIdx) 
     && (receiverIdx != myGlobals.otherHostEntryIdx)) {
    if(receiver != NULL) {
      for(found=0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	if(receiver->contactedRcvdPeers.peersIndexes[i] != NO_PEER) {
	  if((receiver->contactedRcvdPeers.peersIndexes[i] == senderIdx)
	     || (((senderIdx == myGlobals.broadcastEntryIdx) 
		  || (senderIdx == myGlobals.otherHostEntryIdx)
		  || broadcastHost(sender))
		 && broadcastHost(myGlobals.device[actualDeviceId].
				  hash_hostTraffic[checkSessionIdx(receiver->contactedRcvdPeers.peersIndexes[i])]))) {
	    found = 1;
	    break;
	  }
	}

      if(found == 0)
	incrementUsageCounter(&receiver->contactedRcvdPeers, senderIdx, actualDeviceId);
    }
  }
}

/* *****************************************
 *
 * Fragment handling code courtesy of
 * Andreas Pfaller <apfaller@yahoo.com.au>
 *
 * NOTE:
 * the code below has a small (neglictable) limitation
 * as described below.
 *
 * Subject: ntop 1.3.2: Fragment handling
 * Date:    Mon, 7 Aug 2000 16:05:45 +0200
 * From:    a.pfaller@pop.gun.de (Andreas Pfaller)
 *   To:    l.deri@tecsiel.it (Luca Deri)
 *
 * I have also had a look at the code you added to handle
 * overlapping  fragments. It again assumes specific package
 * ordering (either 1,2,..,n  or  n,n-1,..,1) which the IP protocol
 * does not guarantee. The above assumptions are probably true
 * for most users but in some setups they are nearly never true.
 * Consider two host connected by multiple network cards
 *
 * e.g.:
 *      +--------+ eth0         eth0 +--------+
 *      |        |-------------------|        |
 *      | HOST A |                   | HOST B |
 *      |        |-------------------|        |
 *      +--------+ eth1         eth1 +--------+
 *
 * which distribute traffic on this interfaces to achive better
 * throughput (Called bonding in Linux, Etherchannel by Cisco or
 * trunking by Sun). A simple algorithm simple uses the interfaces
 * in a cyclic way. Since packets are not always the same length
 * or the interfaces my have different speeds more complicated
 * ones use other methods to try to achive maximum throughput.
 * In such an environment you have very high probability for
 * out of order packets.
 *
 * ***************************************** */

#ifdef FRAGMENT_DEBUG
static void dumpFragmentData(IpFragment *fragment) {
  printf("IPFragment (%p)\n", fragment);
  printf("  %s:%d->%s:%d\n",
         fragment->src->hostSymIpAddress, fragment->sport,
         fragment->dest->hostSymIpAddress, fragment->dport);
  printf("  FragmentId=%d\n", fragment->fragmentId);
  printf("  lastOffset=%d, totalPacketLength=%d\n",
         fragment->lastOffset, fragment->totalPacketLength);
  printf("  totalDataLength=%d, expectedDataLength=%d\n",
         fragment->totalDataLength, fragment->expectedDataLength);
  fflush(stdout);
}
#endif

/* ************************************ */

static IpFragment *searchFragment(HostTraffic *srcHost,
				  HostTraffic *dstHost,
				  u_int fragmentId, 
				  int actualDeviceId) {
  IpFragment *fragment = myGlobals.device[actualDeviceId].fragmentList;

  while ((fragment != NULL)
         && ((fragment->src != srcHost)
	     || (fragment->dest != dstHost)
	     || (fragment->fragmentId != fragmentId)))
    fragment = fragment->next;

  return(fragment);
}

/* ************************************ */

void deleteFragment(IpFragment *fragment, int actualDeviceId) {

  if (fragment->prev == NULL)
    myGlobals.device[actualDeviceId].fragmentList = fragment->next;
  else
    fragment->prev->next = fragment->next;

  free(fragment);
}

/* ************************************ */

/* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
static void checkFragmentOverlap(u_int srcHostIdx,
                                 u_int dstHostIdx,
                                 IpFragment *fragment,
                                 u_int fragmentOffset,
                                 u_int dataLength, 
				 int actualDeviceId) {
  if (fragment->fragmentOrder == UNKNOWN_FRAGMENT_ORDER) {
    if(fragment->lastOffset > fragmentOffset)
      fragment->fragmentOrder = DECREASING_FRAGMENT_ORDER;
    else
      fragment->fragmentOrder = INCREASING_FRAGMENT_ORDER;
  }

  if ( (fragment->fragmentOrder == INCREASING_FRAGMENT_ORDER
        && fragment->lastOffset+fragment->lastDataLength > fragmentOffset)
       ||
       (fragment->fragmentOrder == DECREASING_FRAGMENT_ORDER
        && fragment->lastOffset < fragmentOffset+dataLength)) {
    if(myGlobals.enableSuspiciousPacketDump) {
      char buf[BUF_SIZE];
      snprintf(buf, BUF_SIZE, "Detected overlapping packet fragment [%s->%s]: "
               "fragment id=%d, actual offset=%d, previous offset=%d\n",
               fragment->src->hostSymIpAddress,
               fragment->dest->hostSymIpAddress,
               fragment->fragmentId, fragmentOffset,
               fragment->lastOffset);

      logMessage(buf, NTOP_WARNING_MSG);
      dumpSuspiciousPacket(actualDeviceId);
    }

    allocateSecurityHostPkts(fragment->src); allocateSecurityHostPkts(fragment->dest);
    incrementUsageCounter(&fragment->src->secHostPkts->overlappingFragmentSent, dstHostIdx, actualDeviceId);
    incrementUsageCounter(&fragment->dest->secHostPkts->overlappingFragmentRcvd, srcHostIdx, actualDeviceId);
  }
}

/* ************************************ */

static u_int handleFragment(HostTraffic *srcHost,
			    u_int srcHostIdx,
                            HostTraffic *dstHost,
			    u_int dstHostIdx,
                            u_short *sport,
                            u_short *dport,
                            u_int fragmentId,
                            u_int off,
                            u_int packetLength,
                            u_int dataLength, 
			    int actualDeviceId) {
  IpFragment *fragment;
  u_int fragmentOffset, length;

  if(!myGlobals.enableFragmentHandling)
    return(0);

  fragmentOffset = (off & 0x1FFF)*8;

  fragment = searchFragment(srcHost, dstHost, fragmentId, actualDeviceId);

  if (fragment == NULL) {
    /* new fragment */
    fragment = (IpFragment*) malloc(sizeof(IpFragment));
    if (fragment == NULL)
      return(0); /* out of memory, not much we can do */
    memset(fragment, 0, sizeof(IpFragment));
    fragment->src = srcHost;
    fragment->dest = dstHost;
    fragment->fragmentId = fragmentId;
    fragment->firstSeen = myGlobals.actTime;
    fragment->fragmentOrder = UNKNOWN_FRAGMENT_ORDER;
    fragment->next = myGlobals.device[actualDeviceId].fragmentList;
    fragment->prev = NULL;
    myGlobals.device[actualDeviceId].fragmentList = fragment;
  } else
    checkFragmentOverlap(srcHostIdx, dstHostIdx, fragment, 
			 fragmentOffset, dataLength, actualDeviceId);

  fragment->lastOffset = fragmentOffset;
  fragment->totalPacketLength += packetLength;
  fragment->totalDataLength += dataLength;
  fragment->lastDataLength = dataLength;

  if (fragmentOffset == 0) {
    /* first fragment contains port numbers */
    fragment->sport = *sport;
    fragment->dport = *dport;
  } else if (!(off & IP_MF)) /* last fragment->we know the total data size */
    fragment->expectedDataLength = fragmentOffset+dataLength;

#ifdef FRAGMENT_DEBUG
  dumpFragmentData(fragment);
#endif

  /* Now check if we have all the data needed for the statistics */
  if ((fragment->sport != 0) && (fragment->dport != 0) /* first fragment rcvd */
      /* last fragment rcvd */
      && (fragment->expectedDataLength != 0)
      /* probably all fragments rcvd */
      && (fragment->totalDataLength >= fragment->expectedDataLength)) {
    *sport = fragment->sport;
    *dport = fragment->dport;
    length = fragment->totalPacketLength;
    deleteFragment(fragment, actualDeviceId);
  } else {
    *sport = 0;
    *dport = 0;
    length = 0;
  }

  return length;
}

/* ************************************ */

void purgeOldFragmentEntries(int actualDeviceId) {
  IpFragment *fragment, *next;
  u_int fragcnt=0, expcnt=0;

  fragment = myGlobals.device[actualDeviceId].fragmentList;

  while(fragment != NULL) {
    fragcnt++;
    next = fragment->next;
    if((fragment->firstSeen + DOUBLE_TWO_MSL_TIMEOUT) < myGlobals.actTime) {
      expcnt++;
#ifdef FRAGMENT_DEBUG
      dumpFragmentData(fragment);
#endif
      deleteFragment(fragment, actualDeviceId);
    }
    fragment=next;
  }

#ifdef FRAGMENT_DEBUG
  if(fragcnt) {
    printf("fragcnt=%d, expcnt=%d\n", fragcnt, expcnt);
    fflush(stdout);
  }
#endif
}

/* ************************************ */

static void checkNetworkRouter(HostTraffic *srcHost,
			       HostTraffic *dstHost,
			       u_char *ether_dst, int actualDeviceId) {
  if((subnetLocalHost(srcHost) && (!subnetLocalHost(dstHost)) 
      && (!broadcastHost(dstHost)) && (!multicastHost(dstHost)))
     || (subnetLocalHost(dstHost) && (!subnetLocalHost(srcHost)) 
	 && (!broadcastHost(srcHost)) && (!multicastHost(srcHost)))) {
    u_int routerIdx, j;
    HostTraffic *router;

    routerIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
    
    router = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(routerIdx)];
    
    if(((router->hostNumIpAddress[0] != '\0')
       && (broadcastHost(router)
	   || multicastHost(router)
	   || (!subnetLocalHost(router)) /* No IP: is this a special Multicast address ? */))
       || (router->hostIpAddress.s_addr == dstHost->hostIpAddress.s_addr)
       || (memcmp(router->ethAddress, dstHost->ethAddress, ETHERNET_ADDRESS_LEN) == 0)
       )
      return;

    for(j=0; j<MAX_NUM_CONTACTED_PEERS; j++) {
      if(srcHost->contactedRouters.peersIndexes[j] == routerIdx)
	break;
      else if(srcHost->contactedRouters.peersIndexes[j] == NO_PEER) {
	srcHost->contactedRouters.peersIndexes[j] = routerIdx;
	break;
      }
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, "(%s/%s/%s) -> (%s/%s/%s) routed by [idx=%d/%s/%s/%s]",
	       srcHost->ethAddressString, srcHost->hostNumIpAddress, srcHost->hostSymIpAddress, 
	       dstHost->ethAddressString, dstHost->hostNumIpAddress, dstHost->hostSymIpAddress, 
	       routerIdx,
	       router->ethAddressString,
	       router->hostNumIpAddress,
	       router->hostSymIpAddress);

#endif
    FD_SET(GATEWAY_HOST_FLAG, &router->flags);
    updateRoutedTraffic(router);
  }
}

/* ************************************ */

static void updatePacketCount(u_int srcHostIdx, u_int dstHostIdx,
                              TrafficCounter length, int actualDeviceId) {
  
  HostTraffic *srcHost, *dstHost;
  unsigned short hourId;
  struct tm t, *thisTime;

  if(/* (srcHostIdx == dstHostIdx) || */
     (srcHostIdx == NO_PEER) || (dstHostIdx == NO_PEER))
    return; /* It looks there's something wrong here */

  thisTime = localtime_r(&myGlobals.actTime, &t);
  hourId = thisTime->tm_hour % 24 /* just in case... */;;

  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];

  if((srcHost == NULL) || (dstHost == NULL))
    return;

  srcHost->pktSent++;

  srcHost->last24HoursBytesSent[hourId] += length,
    dstHost->last24HoursBytesRcvd[hourId] += length;

  if((dstHostIdx == myGlobals.broadcastEntryIdx)
     || broadcastHost(dstHost)) {
    srcHost->pktBroadcastSent++;
    srcHost->bytesBroadcastSent += length;
    myGlobals.device[actualDeviceId].broadcastPkts++;
  } else if(isMulticastAddress(&(dstHost->hostIpAddress))) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "%s->%s\n",
	       srcHost->hostSymIpAddress, dstHost->hostSymIpAddress);
#endif
    srcHost->pktMulticastSent++;
    srcHost->bytesMulticastSent += length;
    dstHost->pktMulticastRcvd++;
    dstHost->bytesMulticastRcvd += length;
    myGlobals.device[actualDeviceId].multicastPkts++;
  }

  srcHost->bytesSent += length;
  if(dstHost != NULL) dstHost->bytesRcvd += length;

  dstHost->pktRcvd++;

  if((dstHost != NULL) /*&& (!broadcastHost(dstHost))*/)
    addContactedPeers(srcHostIdx, dstHostIdx, actualDeviceId);
}

/* ************************************ */

void updateHostName(HostTraffic *el) {

  if((el->hostNumIpAddress[0] == '\0')
     || (el->hostSymIpAddress == NULL)
     || strcmp(el->hostSymIpAddress, el->hostNumIpAddress) == 0) {
    int i;

    if(el->nbHostName != NULL) {
      /*
	Use NetBIOS name (when available) if the
	IP address has not been resolved.
      */
      memset(el->hostSymIpAddress, 0, sizeof(el->hostSymIpAddress));
      strcpy(el->hostSymIpAddress, el->nbHostName);
    } else if(el->ipxHostName != NULL)
      strcpy(el->hostSymIpAddress, el->ipxHostName);
    else if(el->atNodeName != NULL)
      strcpy(el->hostSymIpAddress, el->atNodeName);

    if(el->hostSymIpAddress[0] != '\0')
      for(i=0; el->hostSymIpAddress[i] != '\0'; i++)
	el->hostSymIpAddress[i] = (char)tolower(el->hostSymIpAddress[i]);
  }
}

/* ************************************ */

static void updateDevicePacketTTLStats(u_int ttl, int actualDeviceId) {
  if(ttl < 32) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo32++;
  else if(ttl < 64) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo64++;
  else if(ttl < 96) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo96++;
  else if(ttl < 128) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo128++;
  else if(ttl < 160) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo160++;
  else if(ttl < 192) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo192++;
  else if(ttl < 224) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo224++;
  else myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo255++;
}

/* ************************************ */

static void processIpPkt(const u_char *bp,
			 const struct pcap_pkthdr *h,
			 u_int length,
			 u_char *ether_src,
			 u_char *ether_dst, 
			 int actualDeviceId) {
  u_short sport, dport;
  struct ip ip;
  struct tcphdr tp;
  struct udphdr up;
  struct icmp icmpPkt;
  u_int hlen, tcpDataLength, udpDataLength, off, tcpUdpLen;
  char *proto;
  u_int srcHostIdx, dstHostIdx;
  HostTraffic *srcHost=NULL, *dstHost=NULL;
  u_char etherAddrSrc[ETHERNET_ADDRESS_LEN+1],
    etherAddrDst[ETHERNET_ADDRESS_LEN+1], forceUsingIPaddress = 0;
  struct timeval tvstrct;
  u_char *theData;

  myGlobals.device[actualDeviceId].ipBytes += length; myGlobals.device[actualDeviceId].ipPkts++;

  /* Need to copy this over in case bp isn't properly aligned.
   * This occurs on SunOS 4.x at least.
   * Paul D. Smith <psmith@baynetworks.com>
   */
  memcpy(&ip, bp, sizeof(struct ip));
  hlen = (u_int)ip.ip_hl * 4;

  if(in_cksum((const u_short *)bp, hlen, 0) != 0) {
    myGlobals.device[actualDeviceId].rcvdPktStats.badChecksum++;
  }

  if(ip.ip_p == GRE_PROTOCOL_TYPE) {
    /*
      Cisco GRE (Generic Routing Encapsulation)
      Tunnels (RFC 1701, 1702)
    */
    GreTunnel tunnel;

    memcpy(&tunnel, bp+hlen, sizeof(GreTunnel));

    if(ntohs(tunnel.protocol) == PPP_PROTOCOL_TYPE) {
      PPPTunnelHeader pppTHeader;

      memcpy(&pppTHeader, bp+hlen+sizeof(GreTunnel), sizeof(PPPTunnelHeader));

      if(ntohs(pppTHeader.protocol) == 0x21 /* IP */) {

	memcpy(&ip, bp+hlen+sizeof(GreTunnel)+sizeof(PPPTunnelHeader), sizeof(struct ip));
	hlen = (u_int)ip.ip_hl * 4;
	ether_src = NULL, ether_dst = NULL;
      }
    }
  }

  if((ether_src == NULL) && (ether_dst == NULL)) {
    /* Ethernet-less protocols (e.g. PPP/RAW IP) */

    memcpy(etherAddrSrc, &(ip.ip_src.s_addr), sizeof(ip.ip_src.s_addr));
    etherAddrSrc[ETHERNET_ADDRESS_LEN] = '\0';
    ether_src = etherAddrSrc;

    memcpy(etherAddrDst, &(ip.ip_dst.s_addr), sizeof(ip.ip_dst.s_addr));
    etherAddrDst[ETHERNET_ADDRESS_LEN] = '\0';
    ether_dst = etherAddrDst;
  }

  NTOHL(ip.ip_dst.s_addr); NTOHL(ip.ip_src.s_addr);

  if((!myGlobals.borderSnifferMode) 
     && isBroadcastAddress(&ip.ip_dst) 
     && (memcmp(ether_dst, ethBroadcast, 6) != 0)) {
    /* forceUsingIPaddress = 1; */

    srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
    srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
    if(srcHost != NULL) {
      if(myGlobals.enableSuspiciousPacketDump && (!hasWrongNetmask(srcHost))) {
	/* Dump the first packet only */

	traceEvent(TRACE_WARNING, "Host %s has a wrong netmask",
		   etheraddr_string(ether_src));
	dumpSuspiciousPacket(actualDeviceId);
      }
      FD_SET(HOST_WRONG_NETMASK, &srcHost->flags);
    }
  }

  /*
    IMPORTANT:
    do NOT change the order of the lines below (see isBroadcastAddress call)
  */
  dstHostIdx = getHostInfo(&ip.ip_dst, ether_dst, 1, 0, actualDeviceId);
  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];

  srcHostIdx = getHostInfo(&ip.ip_src, ether_src,
			   /*
			     Don't check for multihoming when
			     the destination address is a broadcast address
			   */
			   (!isBroadcastAddress(&dstHost->hostIpAddress)),
			   forceUsingIPaddress, actualDeviceId);
  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];

  if(srcHost == NULL) {
    /* Sanity check */
    traceEvent(TRACE_INFO, "Sanity check failed (1) [Low memory?]");
    return; /* It might be that there's not enough memory that that
	       dstHostIdx = getHostInfo(&ip.ip_dst, ether_dst) caused
	       srcHost to be freed */
  } else {
    /* Lock the instance so that the next call
       to getHostInfo won't purge it */
    srcHost->instanceInUse++;
  }

  if(dstHost == NULL) {
    /* Sanity check */
    traceEvent(TRACE_INFO, "Sanity check failed (2) [Low memory?]");
    return;
  } else {
    /* Lock the instance so that the next call
       to getHostInfo won't purge it */
    dstHost->instanceInUse++;
  }

#ifdef DEBUG
  if(myGlobals.rFileName != NULL) {
    static int numPkt=1;

    traceEvent(TRACE_INFO, "%d) %s -> %s",
	       numPkt++,
	       srcHost->hostNumIpAddress,
	       dstHost->hostNumIpAddress);
    fflush(stdout);
  }
#endif
  
  updateDevicePacketTTLStats(ip.ip_ttl, actualDeviceId);

  if(ip.ip_ttl != 255) {
    /*
      TTL can be calculated only when the packet
      is originated by the sender
     */
    if((srcHost->minTTL == 0) || (ip.ip_ttl < srcHost->minTTL)) srcHost->minTTL = ip.ip_ttl;
    if((ip.ip_ttl > srcHost->maxTTL)) srcHost->maxTTL = ip.ip_ttl;
  }

  if(!myGlobals.borderSnifferMode) checkNetworkRouter(srcHost, dstHost, ether_dst, actualDeviceId);
  updatePacketCount(srcHostIdx, dstHostIdx, (TrafficCounter)h->len, actualDeviceId);
  updateTrafficMatrix(srcHost, dstHost, (TrafficCounter)length, actualDeviceId);

  srcHost->ipBytesSent += length, dstHost->ipBytesRcvd += length;

  if(subnetPseudoLocalHost(srcHost)) {
    if(subnetPseudoLocalHost(dstHost)) {
      srcHost->bytesSentLoc += length;
      dstHost->bytesRcvdLoc += length;
    } else {
      srcHost->bytesSentRem += length;
      dstHost->bytesRcvdLoc += length;
    }
  } else {
    /* srcHost is remote */
    if(subnetPseudoLocalHost(dstHost)) {
      srcHost->bytesSentLoc += length;
      dstHost->bytesRcvdFromRem += length;
    } else {
      srcHost->bytesSentRem += length;
      dstHost->bytesRcvdFromRem += length;
    }
  }

#if PACKET_DEBUG
  /*
   * Time to show the IP Packet Header (when enabled).
   */
  if (fd && myGlobals.device [actualDeviceId] . ipv)
    fprintf (fd, "IP:     ----- IP Header -----\n"),
      fprintf (fd, "IP:\n"),
      fprintf (fd, "IP:     Packet %ld arrived at %s\n", myGlobals.device [actualDeviceId] ,
	       timestamp (& myGlobals.lastPktTime, ABS_FMT)),
      fprintf (fd, "IP:     Total size  = %d : header = %d : data = %d\n",
	       ip_size, ip_hlen, ip_size - ip_hlen),
      fprintf (fd, "IP:     Source      = %s\n", inet_ntoa (ip->ip_src)),
      fprintf (fd, "IP:     Destination = %s\n", inet_ntoa (ip->ip_dst)),
      fflush (fd);
#endif

  off = ntohs(ip.ip_off);

  if (off & 0x3fff) {
    /* 
       This is a fragment: fragment handling is handled by handleFragment()
       called below.

       Courtesy of Andreas Pfaller
     */
    myGlobals.device[actualDeviceId].fragmentedIpBytes += length;
    
    switch(ip.ip_p) {
    case IPPROTO_TCP:
      srcHost->tcpFragmentsSent += length, dstHost->tcpFragmentsRcvd += length;
      break;
    case IPPROTO_UDP:
      srcHost->udpFragmentsSent += length, dstHost->udpFragmentsRcvd += length;
      break;
    case IPPROTO_ICMP:
      srcHost->icmpFragmentsSent += length, dstHost->icmpFragmentsRcvd += length;
      break;
    }
  }
  
  tcpUdpLen = ntohs(ip.ip_len) - hlen;

  switch(ip.ip_p) {
  case IPPROTO_TCP:
    myGlobals.device[actualDeviceId].tcpBytes += tcpUdpLen;

    if(tcpUdpLen < sizeof(struct tcphdr)) {
      if(myGlobals.enableSuspiciousPacketDump) {
	traceEvent(TRACE_WARNING, "WARNING: Malformed TCP pkt %s->%s detected (packet too short)",
		   srcHost->hostSymIpAddress,
		   dstHost->hostSymIpAddress);
	dumpSuspiciousPacket(actualDeviceId);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHostIdx, actualDeviceId);
      }
    } else {
      proto = "TCP";
      memcpy(&tp, bp+hlen, sizeof(struct tcphdr));

      /* Sanity check */
      if(tcpUdpLen > (tp.th_off * 4)) {
	tcpDataLength = tcpUdpLen - (tp.th_off * 4);
	theData = (u_char*)(bp+hlen+(tp.th_off * 4));
      } else {
	tcpDataLength = 0;
	theData = NULL;
      }

      sport = ntohs(tp.th_sport);
      dport = ntohs(tp.th_dport);

      if(myGlobals.tcpChain) {
	u_int displ;

	if(off & 0x3fff)
	  displ = 0; /* Fragment */
	else
	  displ = tp.th_off * 4;

	checkFilterChain(srcHost, srcHostIdx,
			 dstHost, dstHostIdx,
			 sport, dport,
			 tcpDataLength, /* packet length */
			 displ+sizeof(struct tcphdr), /* offset from packet header */
			 tp.th_flags, /* TCP flags */
			 IPPROTO_TCP,
			 (u_char)(off & 0x3fff), /* 1 = fragment, 0 = packet */
			 bp, /* pointer to packet content */
			 myGlobals.tcpChain, TCP_RULE, actualDeviceId);
      }

      /*
	Don't move this code on top as it is supposed to stay here
	as it modifies sport/sport 
	
	Courtesy of Andreas Pfaller
      */
      if(off & 0x3fff) {
	/* Handle fragmented packets */
	length = handleFragment(srcHost, srcHostIdx, dstHost, dstHostIdx,
				&sport, &dport,
				ntohs(ip.ip_id), off, length,
				ntohs(ip.ip_len) - hlen, actualDeviceId);       
      }
      
      if((sport > 0) && (dport > 0)) {
	IPSession *theSession;
	u_short isPassiveSession = 0, nonFullyRemoteSession = 1;

	/* It might be that tcpDataLength is 0 when
	   the rcvd packet is fragmented and the main
	   packet has not yet been rcvd */

	if(subnetPseudoLocalHost(srcHost)) {
	  if(subnetPseudoLocalHost(dstHost)) {
	    srcHost->tcpSentLoc += length;
	    dstHost->tcpRcvdLoc += length;
	    myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.local += length;
	  } else {
	    srcHost->tcpSentRem += length;
	    dstHost->tcpRcvdLoc += length;
	    myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.local2remote += length;
	  }
	} else {
	  /* srcHost is remote */
	  if(subnetPseudoLocalHost(dstHost)) {
	    srcHost->tcpSentLoc += length;
	    dstHost->tcpRcvdFromRem += length;
	    myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.remote2local += length;
	  } else {
	    srcHost->tcpSentRem += length;
	    dstHost->tcpRcvdFromRem += length;
	    myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.remote += length;
	    nonFullyRemoteSession = 0;
	  }
	}

	if(nonFullyRemoteSession) {
	  theSession = handleTCPSession(h, (off & 0x3fff), tp.th_win,
					srcHostIdx, sport, dstHostIdx,
					dport, length, &tp, tcpDataLength,
					theData, actualDeviceId);
	  if(theSession == NULL)
	    isPassiveSession = 0;
	  else
	    isPassiveSession = theSession->passiveFtpSession;
	}

	/* choose most likely port for protocol traffic accounting
	 * by trying lower number port first. This is based
	 * on the assumption that lower port numbers are more likely
	 * to be the servers and clients usually dont use ports <1024
	 * This is only relevant if both port numbers are used to
	 * gather service statistics.
	 * e.g. traffic between port 2049 (nfsd) and 113 (nntp) will
	 * be counted as nntp traffic in all directions by this heuristic
	 * and not as nntp in one direction and nfs in the return direction.
	 *
	 * Courtesy of Andreas Pfaller <apfaller@yahoo.com.au>
	 */
	if(dport < sport) {
	  if(handleIP(dport, srcHostIdx, dstHostIdx, length, isPassiveSession, actualDeviceId) == -1)
	    handleIP(sport, srcHostIdx, dstHostIdx, length, isPassiveSession, actualDeviceId);
	} else {
	  if(handleIP(sport, srcHostIdx, dstHostIdx, length, isPassiveSession, actualDeviceId) == -1)
	    handleIP(dport, srcHostIdx, dstHostIdx, length, isPassiveSession, actualDeviceId);
	}
      }
    }
    break;

  case IPPROTO_UDP:
    proto = "UDP";
    myGlobals.device[actualDeviceId].udpBytes += tcpUdpLen;

    if(tcpUdpLen < sizeof(struct udphdr)) {
      if(myGlobals.enableSuspiciousPacketDump) {
	traceEvent(TRACE_WARNING, "WARNING: Malformed UDP pkt %s->%s detected (packet too short)",
		   srcHost->hostSymIpAddress,
		   dstHost->hostSymIpAddress);
	dumpSuspiciousPacket(actualDeviceId);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHostIdx, actualDeviceId);
      }
    } else {
      udpDataLength = tcpUdpLen - sizeof(struct udphdr);
      memcpy(&up, bp+hlen, sizeof(struct udphdr));

#ifdef SLACKWARE
      sport = ntohs(up.source);
      dport = ntohs(up.dest);
#else
      sport = ntohs(up.uh_sport);
      dport = ntohs(up.uh_dport);
#endif

      if(!(off & 0x3fff)) {
	if(((sport == 53) || (dport == 53) /* domain */)
	   && myGlobals.enablePacketDecoding
	   && (bp != NULL) /* packet long enough */) {
	  short isRequest = 0, positiveReply = 0;
	  u_int16_t transactionId = 0;

	  /* The DNS chain will be checked here */
	  transactionId = processDNSPacket(bp+hlen+sizeof(struct udphdr), 
					   udpDataLength, &isRequest, &positiveReply);

#ifdef DNS_SNIFF_DEBUG
	  traceEvent(TRACE_INFO, "%s:%d->%s:%d [request: %d][positive reply: %d]\n",
		     srcHost->hostSymIpAddress, sport,
		     dstHost->hostSymIpAddress, dport,
		     isRequest, positiveReply);
#endif

	  if(srcHost->dnsStats == NULL) {
	    srcHost->dnsStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	    memset(srcHost->dnsStats, 0, sizeof(ServiceStats));
	  }

	  if(dstHost->dnsStats == NULL) {
	    dstHost->dnsStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	    memset(dstHost->dnsStats, 0, sizeof(ServiceStats));
	  }

	  if(isRequest) {
	    /* to be 64bit-proof we have to copy the elements */
	    tvstrct.tv_sec = h->ts.tv_sec;
	    tvstrct.tv_usec = h->ts.tv_usec;
	    addTimeMapping(transactionId, tvstrct);

	    if(subnetLocalHost(dstHost))
	      srcHost->dnsStats->numLocalReqSent++;
	    else
	      srcHost->dnsStats->numRemReqSent++;

	    if(subnetLocalHost(srcHost))
	      dstHost->dnsStats->numLocalReqRcvd++;
	    else
	      dstHost->dnsStats->numRemReqRcvd++;
	  } else {
	    time_t microSecTimeDiff;

	    /* to be 64bit-safe we have to copy the elements */
	    tvstrct.tv_sec = h->ts.tv_sec;
	    tvstrct.tv_usec = h->ts.tv_usec;
	    microSecTimeDiff = getTimeMapping(transactionId, tvstrct);

	    if(microSecTimeDiff > 0) {
#ifdef DEBUG
	      traceEvent(TRACE_INFO, "TransactionId=0x%X [%.1f ms]\n",
			 transactionId, ((float)microSecTimeDiff)/1000);
#endif

	      if(microSecTimeDiff > 0) {
		if(subnetLocalHost(dstHost)) {
		  if((srcHost->dnsStats->fastestMicrosecLocalReqServed == 0)
		     || (microSecTimeDiff < srcHost->dnsStats->fastestMicrosecLocalReqServed))
		    srcHost->dnsStats->fastestMicrosecLocalReqServed = microSecTimeDiff;
		  if(microSecTimeDiff > srcHost->dnsStats->slowestMicrosecLocalReqServed)
		    srcHost->dnsStats->slowestMicrosecLocalReqServed = microSecTimeDiff;
		} else {
		  if((srcHost->dnsStats->fastestMicrosecRemReqServed == 0)
		     || (microSecTimeDiff < srcHost->dnsStats->fastestMicrosecRemReqServed))
		    srcHost->dnsStats->fastestMicrosecRemReqServed = microSecTimeDiff;
		  if(microSecTimeDiff > srcHost->dnsStats->slowestMicrosecRemReqServed)
		    srcHost->dnsStats->slowestMicrosecRemReqServed = microSecTimeDiff;
		}

		if(subnetLocalHost(srcHost)) {
		  if((dstHost->dnsStats->fastestMicrosecLocalReqMade == 0)
		     || (microSecTimeDiff < dstHost->dnsStats->fastestMicrosecLocalReqMade))
		    dstHost->dnsStats->fastestMicrosecLocalReqMade = microSecTimeDiff;
		  if(microSecTimeDiff > dstHost->dnsStats->slowestMicrosecLocalReqMade)
		    dstHost->dnsStats->slowestMicrosecLocalReqMade = microSecTimeDiff;
		} else {
		  if((dstHost->dnsStats->fastestMicrosecRemReqMade == 0)
		     || (microSecTimeDiff < dstHost->dnsStats->fastestMicrosecRemReqMade))
		    dstHost->dnsStats->fastestMicrosecRemReqMade = microSecTimeDiff;
		  if(microSecTimeDiff > dstHost->dnsStats->slowestMicrosecRemReqMade)
		    dstHost->dnsStats->slowestMicrosecRemReqMade = microSecTimeDiff;
		}
	      } else {
#ifdef DEBUG
		traceEvent(TRACE_INFO, "getTimeMapping(0x%X) failed for DNS",
			   transactionId);
#endif
	      }
	    }

	    /* Courtesy of Roberto F. De Luca <deluca@tandar.cnea.gov.ar> */
	    FD_SET(NAME_SERVER_HOST_FLAG, &srcHost->flags);

	    if(positiveReply) {
	      srcHost->dnsStats->numPositiveReplSent++;
	      dstHost->dnsStats->numPositiveReplRcvd++;
	    } else {
	      srcHost->dnsStats->numNegativeReplSent++;
	      dstHost->dnsStats->numNegativeReplRcvd++;
	    }
	  }
	  
	} else {
	  if(myGlobals.enablePacketDecoding) 
	    handleNetbios(srcHost, dstHost, sport, dport,
			  udpDataLength, bp,
			  length, hlen);
	}
      }

      if(myGlobals.udpChain) {
	u_int displ;

	if (off & 0x3fff)
	  displ = 0; /* Fragment */
	else
	  displ = sizeof(struct udphdr);

	checkFilterChain(srcHost, srcHostIdx,
			 dstHost, dstHostIdx,
			 sport, dport,
			 udpDataLength, /* packet length */
			 hlen,   /* offset from packet header */
			 0,	   /* there are no UDP flags :-( */
			 IPPROTO_UDP,
			 (u_char)(off & 0x3fff), /* 1 = fragment, 0 = packet */
			 bp, /* pointer to packet content */
			 myGlobals.udpChain, UDP_RULE, actualDeviceId);
      }

      /*
	Don't move this code on top as it is supposed to stay here
	as it modifies sport/sport 
	
	Courtesy of Andreas Pfaller
      */
      if(off & 0x3fff) {
	/* Handle fragmented packets */
	length = handleFragment(srcHost, srcHostIdx, dstHost, dstHostIdx,
				&sport, &dport,
				ntohs(ip.ip_id), off, length,
				ntohs(ip.ip_len) - hlen, actualDeviceId);       
      }      

      if((sport > 0) && (dport > 0)) {
	u_short nonFullyRemoteSession = 1;

	/* It might be that udpBytes is 0 when
	   the rcvd packet is fragmented and the main
	   packet has not yet been rcvd */

	if(subnetPseudoLocalHost(srcHost)) {
	  if(subnetPseudoLocalHost(dstHost)) {
	    srcHost->udpSentLoc += length;
	    dstHost->udpRcvdLoc += length;
	    myGlobals.device[actualDeviceId].udpGlobalTrafficStats.local += length;
	  } else {
	    srcHost->udpSentRem += length;
	    dstHost->udpRcvdLoc += length;
	    myGlobals.device[actualDeviceId].udpGlobalTrafficStats.local2remote += length;
	  }
	} else {
	  /* srcHost is remote */
	  if(subnetPseudoLocalHost(dstHost)) {
	    srcHost->udpSentLoc += length;
	    dstHost->udpRcvdFromRem += length;
	    myGlobals.device[actualDeviceId].udpGlobalTrafficStats.remote2local += length;
	  } else {
	    srcHost->udpSentRem += length;
	    dstHost->udpRcvdFromRem += length;
	    myGlobals.device[actualDeviceId].udpGlobalTrafficStats.remote += length;
	    nonFullyRemoteSession = 0;
	  }
	}
  
        /* Handle UDP traffic like TCP, above - 
	   That is: if we know about the lower# port, even if it's the destination,
	   classify the traffic that way.
	   (BMS 12-2001)
	*/
        if (dport < sport) {
	  if (handleIP(dport, srcHostIdx, dstHostIdx, length, 0, actualDeviceId) == -1)
	    handleIP(sport, srcHostIdx, dstHostIdx, length, 0, actualDeviceId);
        } else {
	  if (handleIP(sport, srcHostIdx, dstHostIdx, length, 0, actualDeviceId) == -1)
	    handleIP(dport, srcHostIdx, dstHostIdx, length, 0, actualDeviceId);
        }

	if(nonFullyRemoteSession)
	  handleUDPSession(h, (off & 0x3fff),
			   srcHostIdx, sport, dstHostIdx,
			   dport, udpDataLength,
			   (u_char*)(bp+hlen+sizeof(struct udphdr)), actualDeviceId);
	
	if(myGlobals.enableNetFlowSupport) sendUDPflow(srcHost, dstHost, sport, dport, length);	
      }
    }
    break;

  case IPPROTO_ICMP:
    myGlobals.device[actualDeviceId].icmpBytes += length;

    if(tcpUdpLen < sizeof(struct icmp)) {
      if(myGlobals.enableSuspiciousPacketDump) {
	traceEvent(TRACE_WARNING, "WARNING: Malformed ICMP pkt %s->%s detected (packet too short)",
		   srcHost->hostSymIpAddress,
		   dstHost->hostSymIpAddress);
	dumpSuspiciousPacket(actualDeviceId);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHostIdx, actualDeviceId);
      }
    } else {
      proto = "ICMP";
      memcpy(&icmpPkt, bp+hlen, sizeof(struct icmp));

      srcHost->icmpSent += length;
      dstHost->icmpRcvd += length;

      if(off & 0x3fff) {
	char *fmt = "WARNING: detected ICMP fragment [%s -> %s] (network attack attempt?)";

	srcHost->icmpFragmentsSent += length, dstHost->icmpFragmentsRcvd += length;
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->icmpFragmentSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->icmpFragmentRcvd, srcHostIdx, actualDeviceId);
	if(myGlobals.enableSuspiciousPacketDump) {
	  traceEvent(TRACE_WARNING, fmt,
		     srcHost->hostSymIpAddress, dstHost->hostSymIpAddress);
	  dumpSuspiciousPacket(actualDeviceId);
	}
      }

      /* ************************************************************* */

      if(icmpPkt.icmp_type <= ICMP_MAXTYPE) {
	short dumpPacket = 1;
	if(srcHost->icmpInfo == NULL) {
	  srcHost->icmpInfo = (IcmpHostInfo*)malloc(sizeof(IcmpHostInfo));
	  memset(srcHost->icmpInfo, 0, sizeof(IcmpHostInfo));
	}

	srcHost->icmpInfo->icmpMsgSent[icmpPkt.icmp_type]++;

	if(dstHost->icmpInfo == NULL) {
	  dstHost->icmpInfo = (IcmpHostInfo*)malloc(sizeof(IcmpHostInfo));
	  memset(dstHost->icmpInfo, 0, sizeof(IcmpHostInfo));
	}

	dstHost->icmpInfo->icmpMsgRcvd[icmpPkt.icmp_type]++;

	switch (icmpPkt.icmp_type) {
	case ICMP_ECHOREPLY:
	case ICMP_ECHO:
	  /* Do not log anything */
	  dumpPacket = 0;
	  break;

	case ICMP_UNREACH:
	case ICMP_REDIRECT:
	case ICMP_ROUTERADVERT:
	case ICMP_TIMXCEED:
	case ICMP_PARAMPROB:
	case ICMP_MASKREPLY:
	case ICMP_MASKREQ:
	case ICMP_INFO_REQUEST:
	case ICMP_INFO_REPLY:
	case ICMP_TIMESTAMP:
	case ICMP_TIMESTAMPREPLY:
	case ICMP_SOURCE_QUENCH:
	  if(myGlobals.enableSuspiciousPacketDump) {
	    dumpSuspiciousPacket(actualDeviceId);
	  }
	  break;
	}

	if(myGlobals.enableSuspiciousPacketDump && dumpPacket) {
	  if(!((icmpPkt.icmp_type == 3) && (icmpPkt.icmp_code == 3))) {
	    /*
	      Avoid to print twice the same message:
 	      - Detected ICMP msg (type=3/code=3) from lhost -> ahost
	      - Host [ahost] sent UDP data to a closed port of host [lhost:10001]
	      (scan attempt?)
	    */

	    traceEvent(TRACE_INFO, "Detected ICMP msg [type=%s/code=%d] %s->%s",
		       mapIcmpType(icmpPkt.icmp_type), icmpPkt.icmp_code,
		       srcHost->hostSymIpAddress, dstHost->hostSymIpAddress);
	  }
	}
      }

      /* ************************************************************* */

      if(subnetPseudoLocalHost(srcHost))
	if(subnetPseudoLocalHost(dstHost))
	  myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.local += length;
	else
	  myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.local2remote += length;
      else /* srcHost is remote */
	if(subnetPseudoLocalHost(dstHost))
	  myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.remote2local += length;
	else
	  myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.remote += length;

      if(myGlobals.icmpChain)
	checkFilterChain(srcHost, srcHostIdx,
			 dstHost, dstHostIdx,
			 0 /* sport */, 0 /* dport */,
			 length, /* packet length */
			 0,   /* offset from packet header */
			 icmpPkt.icmp_type,
			 IPPROTO_ICMP,
			 0, /* 1 = fragment, 0 = packet */
			 bp+hlen, /* pointer to packet content */
			 myGlobals.icmpChain, ICMP_RULE, actualDeviceId);

      if((icmpPkt.icmp_type == ICMP_ECHO)
	 && (broadcastHost(dstHost) || multicastHost(dstHost)))
	smurfAlert(srcHostIdx, dstHostIdx, actualDeviceId);
      else if(icmpPkt.icmp_type == ICMP_DEST_UNREACHABLE /* Destination Unreachable */) {
	u_int16_t dport;
	struct ip *oip = &icmpPkt.icmp_ip;

	switch(icmpPkt.icmp_code) {
	case ICMP_UNREACH_PORT: /* Port Unreachable */
	  memcpy(&dport, ((u_char *)bp+hlen+30), sizeof(dport));
	  dport = ntohs(dport);
	  switch (oip->ip_p) {
	  case IPPROTO_TCP:
	    if(myGlobals.enableSuspiciousPacketDump)
	      traceEvent(TRACE_WARNING,
			 "Host [%s] sent TCP data to a closed port of host [%s:%d] (scan attempt?)",
			 dstHost->hostSymIpAddress, srcHost->hostSymIpAddress, dport);
	    /* Simulation of rejected TCP connection */
	    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	    incrementUsageCounter(&srcHost->secHostPkts->rejectedTCPConnSent, dstHostIdx, actualDeviceId);
	    incrementUsageCounter(&dstHost->secHostPkts->rejectedTCPConnRcvd, srcHostIdx, actualDeviceId);
	    break;

	  case IPPROTO_UDP:
	    if(myGlobals.enableSuspiciousPacketDump)
	      traceEvent(TRACE_WARNING,
			 "Host [%s] sent UDP data to a closed port of host [%s:%d] (scan attempt?)",
			 dstHost->hostSymIpAddress, srcHost->hostSymIpAddress, dport);
	    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	    incrementUsageCounter(&dstHost->secHostPkts->udpToClosedPortSent, srcHostIdx, actualDeviceId);
	    incrementUsageCounter(&srcHost->secHostPkts->udpToClosedPortRcvd, dstHostIdx, actualDeviceId);
	    break;
	  }
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpPortUnreachSent, dstHostIdx, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpPortUnreachRcvd, srcHostIdx, actualDeviceId);
	  break;

	case ICMP_UNREACH_NET:
	case ICMP_UNREACH_HOST:
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpHostNetUnreachSent, dstHostIdx, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpHostNetUnreachRcvd, srcHostIdx, actualDeviceId);
	  break;

	case ICMP_UNREACH_PROTOCOL: /* Protocol Unreachable */
	  if(myGlobals.enableSuspiciousPacketDump)
	    traceEvent(TRACE_WARNING, /* See http://www.packetfactory.net/firewalk/ */
		       "Host [%s] rcvd a ICMP protocol Unreachable from host [%s]"
		       " (Firewalking scan attempt?)",
		       dstHost->hostSymIpAddress,
		       srcHost->hostSymIpAddress);
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpProtocolUnreachSent, dstHostIdx, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpProtocolUnreachRcvd, srcHostIdx, actualDeviceId);
	  break;
	case ICMP_UNREACH_NET_PROHIB:    /* Net Administratively Prohibited */
	case ICMP_UNREACH_HOST_PROHIB:   /* Host Administratively Prohibited */
	case ICMP_UNREACH_FILTER_PROHIB: /* Access Administratively Prohibited */
	  if(myGlobals.enableSuspiciousPacketDump)
	    traceEvent(TRACE_WARNING, /* See http://www.packetfactory.net/firewalk/ */
		       "Host [%s] sent ICMP Administratively Prohibited packet to host [%s]"
		       " (Firewalking scan attempt?)",
		       dstHost->hostSymIpAddress, srcHost->hostSymIpAddress);
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpAdminProhibitedSent, dstHostIdx, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpAdminProhibitedRcvd, srcHostIdx, actualDeviceId);
	  break;
	}
	if(myGlobals.enableSuspiciousPacketDump) dumpSuspiciousPacket(actualDeviceId);
      }
      sendICMPflow(srcHost, dstHost, length);
    }
    break;

  case IPPROTO_OSPF:
    proto = "OSPF";
    myGlobals.device[actualDeviceId].ospfBytes += length;
    srcHost->ospfSent += length;
    dstHost->ospfRcvd += length;
    break;

  case IPPROTO_IGMP:
    proto = "IGMP";
    myGlobals.device[actualDeviceId].igmpBytes += length;
    srcHost->igmpSent += length;
    dstHost->igmpRcvd += length;
    break;

  default:
    proto = "IP (Other)";
    myGlobals.device[actualDeviceId].otherIpBytes += length;
    sport = dport = 0;
    srcHost->otherSent += length;
    dstHost->otherRcvd += length;
    break;
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "IP=%d TCP=%d UDP=%d ICMP=%d (len=%d)\n",
	     (int)myGlobals.device[actualDeviceId].ipBytes,
	     (int)myGlobals.device[actualDeviceId].tcpBytes,
	     (int)myGlobals.device[actualDeviceId].udpBytes,
	     (int)myGlobals.device[actualDeviceId].icmpBytes, length);
#endif

  /* Unlock the instance */
  srcHost->instanceInUse--, dstHost->instanceInUse--;
}

/* ************************************ */

#ifdef MULTITHREADED
void queuePacket(u_char * _deviceId,
		 const struct pcap_pkthdr *h,
		 const u_char *p) {
  int len;

  /* ***************************     
     - If the queue is full then wait until a slot is freed
     
     - If the queue is getting full then periodically wait
     until a slot is freed
     **************************** */

#ifdef WIN32_DEMO
  static int numQueuedPackets=0;

  if(numQueuedPackets++ >= MAX_NUM_PACKETS)
    return;
#endif

  if(!myGlobals.capturePackets) return;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Got packet from %s (%d)\n", myGlobals.device[*_deviceId].name, *_deviceId);
#endif

  if(myGlobals.packetQueueLen >= PACKET_QUEUE_LENGTH) {
    int deviceId;
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Dropping packet!!! [packet queue=%d/max=%d]\n",
		 myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif
    
#ifdef WIN32
    deviceId = 0;
#else
    deviceId = (int)_deviceId;
#endif
    
    myGlobals.device[getActualInterface(deviceId)].droppedPkts++;
    
#ifdef HAVE_SCHED_H
    sched_yield(); /* Allow other threads (dequeue) to run */
#endif
    sleep(1);
  } else {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "About to queue packet... \n");
#endif
    accessMutex(&myGlobals.packetQueueMutex, "queuePacket");
    memcpy(&myGlobals.packetQueue[myGlobals.packetQueueHead].h, h, sizeof(struct pcap_pkthdr));
    memset(myGlobals.packetQueue[myGlobals.packetQueueHead].p, 0, sizeof(myGlobals.packetQueue[myGlobals.packetQueueHead].p));
    /* Just to be safe */
    len = h->caplen;
    if(len >= DEFAULT_SNAPLEN) len = DEFAULT_SNAPLEN-1;
    memcpy(myGlobals.packetQueue[myGlobals.packetQueueHead].p, p, len);
    myGlobals.packetQueue[myGlobals.packetQueueHead].h.caplen = len;
    myGlobals.packetQueue[myGlobals.packetQueueHead].deviceId = (int)((void*)_deviceId);
    myGlobals.packetQueueHead = (myGlobals.packetQueueHead+1) % PACKET_QUEUE_LENGTH;
    myGlobals.packetQueueLen++;
    if(myGlobals.packetQueueLen > myGlobals.maxPacketQueueLen)
      myGlobals.maxPacketQueueLen = myGlobals.packetQueueLen;
    releaseMutex(&myGlobals.packetQueueMutex);
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Queued packet... [packet queue=%d/max=%d]\n",
	       myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

#ifdef DEBUG_THREADS
    traceEvent(TRACE_INFO, "+ [packet queue=%d/max=%d]\n", myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif
  }

#ifdef USE_SEMAPHORES
  incrementSem(&myGlobals.queueSem);
#else
  signalCondvar(&myGlobals.queueCondvar);
#endif
#ifdef HAVE_SCHED_H
  sched_yield(); /* Allow other threads (dequeue) to run */
#endif
}

/* ************************************ */

void cleanupPacketQueue(void) {
  ; /* Nothing to do */
}

/* ************************************ */

void* dequeuePacket(void* notUsed _UNUSED_) {
  PacketInformation pktInfo;

  while(myGlobals.capturePackets) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Waiting for packet...\n");
#endif
    
    while((myGlobals.packetQueueLen == 0)
	  && (myGlobals.capturePackets) /* Courtesy of Wies-Software <wies@wiessoft.de> */) {
#ifdef USE_SEMAPHORES
      waitSem(&myGlobals.queueSem);
#else
      waitCondvar(&myGlobals.queueCondvar);
#endif
    }
    
    if(!myGlobals.capturePackets) break;

#ifdef DEBUG
    traceEvent(TRACE_INFO, "Got packet...\n");
#endif
    accessMutex(&myGlobals.packetQueueMutex, "dequeuePacket");
    memcpy(&pktInfo.h, &myGlobals.packetQueue[myGlobals.packetQueueTail].h,
	   sizeof(struct pcap_pkthdr));
    memcpy(pktInfo.p, myGlobals.packetQueue[myGlobals.packetQueueTail].p, DEFAULT_SNAPLEN);
    pktInfo.deviceId = myGlobals.packetQueue[myGlobals.packetQueueTail].deviceId;
    myGlobals.packetQueueTail = (myGlobals.packetQueueTail+1) % PACKET_QUEUE_LENGTH;
    myGlobals.packetQueueLen--;
    releaseMutex(&myGlobals.packetQueueMutex);
#ifdef DEBUG_THREADS
    traceEvent(TRACE_INFO, "- [packet queue=%d/max=%d]\n", myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

#ifdef DEBUG
    traceEvent(TRACE_INFO, "Processing packet... [packet queue=%d/max=%d]\n",
	       myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

    myGlobals.actTime = time(NULL);
    processPacket((u_char*)((long)pktInfo.deviceId), &pktInfo.h, pktInfo.p);
  }

  return(NULL); /* NOTREACHED */
}

#endif /* MULTITHREADED */


/* ************************************ */

static void flowsProcess(const struct pcap_pkthdr *h, const u_char *p, int deviceId) {
  FlowFilterList *list = myGlobals.flowsList;

  while(list != NULL) {
    if((list->pluginStatus.activePlugin)
       && (list->fcode[deviceId].bf_insns != NULL)
       && (bpf_filter(list->fcode[deviceId].bf_insns,
		      (u_char*)p, h->len, h->caplen))) {
      list->bytes += h->len;
      list->packets++;
      if(list->pluginStatus.pluginPtr != NULL) {
	void(*pluginFunc)(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p);

	pluginFunc = (void(*)(u_char *_deviceId, const struct pcap_pkthdr*,
			      const u_char*))list->pluginStatus.pluginPtr->pluginFunc;
	pluginFunc((u_char*)&deviceId, h, p);
#ifdef DEBUG
	printf("Match on %s for '%s'\n", myGlobals.device[deviceId].name,
	       list->flowName);
#endif
      }
    } else {
#ifdef DEBUG
      traceEvent(TRACE_INFO, "No match on %s for '%s'\n", myGlobals.device[deviceId].name,
		 list->flowName);
#endif
    }

    list = list->next;
  }
}

/* ************************************ */

/*
 * time stamp presentation formats
 */
#define DELTA_FMT      1   /* the time since receiving the previous packet */
#define ABS_FMT        2   /* the current time */
#define RELATIVE_FMT   3   /* the time relative to the first packet rcvd */


struct timeval current_pkt = {0,0};
struct timeval first_pkt = {0,0};
struct timeval last_pkt = {0,0};

#if PACKET_DEBUG
/*
 * The time difference in milliseconds.
 *
 * Rocco Carbone <rocco@ntop.org>
 */
static time_t delta_time_in_milliseconds (struct timeval * now,
					  struct timeval * before) {
  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  time_t delta_seconds = now->tv_sec - before->tv_sec;
  time_t delta_milliseconds = (now->tv_usec - before->tv_usec) / 1000;

  if (delta_milliseconds < 0)
    { /* manually carry a one from the seconds field */
      delta_milliseconds += 1000; 		/* 1e3 */
      -- delta_seconds;
    }
  return ((delta_seconds * 1000) + delta_milliseconds);
}
#endif

/* ************************************************ */

#if PACKET_DEBUG
/*
 * Return a well formatted timestamp.
 */
static char* timestamp(const struct timeval* t, int fmt) {
  static char buf [16] = {0};

  time_t now = time((time_t*) 0);
  struct tm *tm, myTm;

  tm = localtime_r(&now, &myTm);

  gettimeofday(&current_pkt, NULL);

  switch(fmt)
    {
    default:
    case DELTA_FMT:
      /*
       * calculate the difference in milliseconds since
       * the previous packet was displayed
       */
      if(snprintf(buf, 16, "%10ld ms",
		  delta_time_in_milliseconds(&current_pkt, &last_pkt)) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      break;

    case ABS_FMT:
      if(snprintf(buf, 16, "%02d:%02d:%02d.%06d",
		  tm->tm_hour, tm->tm_min, tm->tm_sec, (int)t->tv_usec) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      break;

    case RELATIVE_FMT:
      /*
       * calculate the difference in milliseconds
       * since the previous packet was displayed
       */
      if(snprintf(buf, 16, "%10ld ms",
		  delta_time_in_milliseconds(&current_pkt, &first_pkt)) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      break;
    }

  return (buf);
}
#endif

/* ************************************ */

static void updateDevicePacketStats(u_int length, int actualDeviceId) {
  if(length < 64) myGlobals.device[actualDeviceId].rcvdPktStats.upTo64++;
  else if(length < 128) myGlobals.device[actualDeviceId].rcvdPktStats.upTo128++;
  else if(length < 256) myGlobals.device[actualDeviceId].rcvdPktStats.upTo256++;
  else if(length < 512) myGlobals.device[actualDeviceId].rcvdPktStats.upTo512++;
  else if(length < 1024) myGlobals.device[actualDeviceId].rcvdPktStats.upTo1024++;
  else if(length < 1518) myGlobals.device[actualDeviceId].rcvdPktStats.upTo1518++;
  else myGlobals.device[actualDeviceId].rcvdPktStats.above1518++;

  if((myGlobals.device[actualDeviceId].rcvdPktStats.shortest == 0)
     || (myGlobals.device[actualDeviceId].rcvdPktStats.shortest > length))
    myGlobals.device[actualDeviceId].rcvdPktStats.shortest = length;

  if(myGlobals.device[actualDeviceId].rcvdPktStats.longest < length)
    myGlobals.device[actualDeviceId].rcvdPktStats.longest = length;
}

/* ***************************************************** */

void dumpSuspiciousPacket(int actualDeviceId) {
  if(myGlobals.device[actualDeviceId].pcapErrDumper != NULL)
    pcap_dump((u_char*)myGlobals.device[actualDeviceId].pcapErrDumper, h_save, p_save);
}

/* ***************************************************** */

/*
 * This is the top level routine of the printer.  'p' is the points
 * to the ether header of the packet, 'tvp' is the timestamp,
 * 'length' is the length of the packet off the wire, and 'caplen'
 * is the number of bytes actually captured.
 */

void processPacket(u_char *_deviceId,
		   const struct pcap_pkthdr *h,
		   const u_char *p) {
  struct ether_header ehdr;
  struct tokenRing_header *trp;
  struct fddi_header *fddip;
  u_int hlen, caplen = h->caplen;
  u_int headerDisplacement = 0, length = h->len;
  const u_char *orig_p = p, *p1;
  u_char *ether_src=NULL, *ether_dst=NULL;
  unsigned short eth_type=0;
  /* Token-Ring Strings */
  struct tokenRing_llc *trllc;
  FILE * fd;
  unsigned char ipxBuffer[128];
  int deviceId, actualDeviceId;

#ifdef DEBUG
  {
      static long numPkt=0;

      traceEvent(TRACE_INFO, "%ld (%ld)\n", numPkt++, length);

      /* 
      if(numPkt=100000) {
	int i;

	for(i=0; i<myGlobals.numDevices; i++)
	  freeHostInstances(i);
      }
      */
  }
#endif

  if(!myGlobals.capturePackets)
    return;

  h_save = h, p_save = p;

#ifdef DEBUG
  if(myGlobals.rFileName != NULL) {
    traceEvent(TRACE_INFO, ".");
    fflush(stdout);
  }
#endif

  /* 
     This allows me to fetch the time from
     the captured packet instead of calling
     time(NULL).
  */
  myGlobals.actTime = h->ts.tv_sec;

#ifdef WIN32
  deviceId = 0;
#else
  deviceId = (int)_deviceId;
#endif

  actualDeviceId = getActualInterface(deviceId);

#ifdef DEBUG
  traceEvent(TRACE_INFO, "deviceId=%d - actualDeviceId=%ld\n", deviceId, actualDeviceId);
#endif

  updateDevicePacketStats(length, actualDeviceId);

  myGlobals.device[actualDeviceId].ethernetPkts++;
  myGlobals.device[actualDeviceId].ethernetBytes += h->len;

  if(myGlobals.device[actualDeviceId].pcapDumper != NULL)
    pcap_dump((u_char*)myGlobals.device[actualDeviceId].pcapDumper, h, p);

  if(length > myGlobals.mtuSize[myGlobals.device[deviceId].datalink]) {
    /* Sanity check */
    if(myGlobals.enableSuspiciousPacketDump) {
      traceEvent(TRACE_INFO, "Packet # %u too long (len = %u)!\n", 
		 (unsigned int)myGlobals.device[deviceId].ethernetPkts, 
		 (unsigned int)length);
      dumpSuspiciousPacket(actualDeviceId);
    }

    /* Fix below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
    length = myGlobals.mtuSize[myGlobals.device[deviceId].datalink];
    myGlobals.device[actualDeviceId].rcvdPktStats.tooLong++;
  }

  if(myGlobals.device[actualDeviceId].hostsno > myGlobals.device[actualDeviceId].topHashThreshold)
    resizeHostHash(actualDeviceId, EXTEND_HASH, actualDeviceId); /* Extend table */
  else if((myGlobals.device[actualDeviceId].actualHashSize != HASH_INITIAL_SIZE)
	  && (myGlobals.device[actualDeviceId].hostsno < (myGlobals.device[actualDeviceId].topHashThreshold/2)))
    resizeHostHash(actualDeviceId, RESIZE_HASH, actualDeviceId); /* Shrink table */

#ifdef MULTITHREADED
  accessMutex(&myGlobals.hostsHashMutex, "processPacket");
#endif

#ifdef DEBUG
  traceEvent(TRACE_INFO, "actualDeviceId = %d\n", actualDeviceId);
#endif

  hlen = (myGlobals.device[deviceId].datalink == DLT_NULL) ? NULL_HDRLEN : sizeof(struct ether_header);

#ifndef MULTITHREADED
  /*
   * Let's check whether it's time to free up
   * some space before to continue....
   */
  if(myGlobals.device[actualDeviceId].hostsno > myGlobals.device[actualDeviceId].topHashThreshold)
    purgeIdleHosts(0 /* Delete only idle hosts */, actualDeviceId);
#endif

  memcpy(&myGlobals.lastPktTime, &h->ts, sizeof(myGlobals.lastPktTime));

  fd = myGlobals.device[deviceId].fdv;

  /*
   * Show a hash character for each packet captured
   */
  if (fd && myGlobals.device[deviceId].hashing) {
    fprintf (fd, "#");
    fflush(fd);
  }

  /* ethernet assumed */
  if(caplen >= hlen) {
    HostTraffic *srcHost=NULL, *dstHost=NULL;
    u_int srcHostIdx, dstHostIdx;

    memcpy(&ehdr, p, sizeof(struct ether_header));

    switch(myGlobals.device[deviceId].datalink) {
    case DLT_FDDI:
      fddip = (struct fddi_header *)p;
      length -= FDDI_HDRLEN;
      p += FDDI_HDRLEN;
      caplen -= FDDI_HDRLEN;

      extract_fddi_addrs(fddip, (char *)ESRC(&ehdr), (char *)EDST(&ehdr));
      ether_src = (u_char*)ESRC(&ehdr), ether_dst = (u_char*)EDST(&ehdr);

      if((fddip->fc & FDDIFC_CLFF) == FDDIFC_LLC_ASYNC) {
	struct llc llc;

	/*
	  Info on SNAP/LLC:
	  http://www.erg.abdn.ac.uk/users/gorry/course/lan-pages/llc.html
	  http://www.ece.wpi.edu/courses/ee535/hwk96/hwk3cd96/li/li.html
	  http://www.ece.wpi.edu/courses/ee535/hwk96/hwk3cd96/li/li.html
	*/
	memcpy((char *)&llc, (char *)p, min(caplen, sizeof(llc)));
	if(llc.ssap == LLCSAP_SNAP && llc.dsap == LLCSAP_SNAP
	    && llc.llcui == LLC_UI) {
	  if(caplen >= sizeof(llc)) {
	    caplen -= sizeof(llc);
	    length -= sizeof(llc);
	    p += sizeof(llc);

	    if(EXTRACT_16BITS(&llc.ethertype[0]) == ETHERTYPE_IP) {
	      /* encapsulated IP packet */
	      processIpPkt(p, h, length, ether_src, ether_dst, actualDeviceId);
	      /*
		Patch below courtesy of
		Fabrice Bellet <Fabrice.Bellet@creatis.insa-lyon.fr>
	      */
#ifdef MULTITHREADED
	      releaseMutex(&myGlobals.hostsHashMutex);
#endif
	      return;
	    }
	  }
	}
      }
      break;

    case DLT_NULL: /* loopaback interface */
      /*
	Support for ethernet headerless interfaces (e.g. lo0)
	Courtesy of Martin Kammerhofer <dada@sbox.tu-graz.ac.at>
      */

      length -= NULL_HDRLEN; /* don't count nullhdr */

      /* All this crap is due to the old little/big endian story... */
      if((p[0] == 0) && (p[1] == 0) && (p[2] == 8) && (p[3] == 0))
	eth_type = ETHERTYPE_IP;
      else if((p[0] == 0) && (p[1] == 0) && (p[2] == 0x86) && (p[3] == 0xdd))
	eth_type = ETHERTYPE_IPv6;
      ether_src = ether_dst = myGlobals.dummyEthAddress;
      break;

    case DLT_PPP:
      headerDisplacement = PPP_HDRLEN;
      /*
	PPP is like RAW IP. The only difference is that PPP
	has a header that's not present in RAW IP.

	IMPORTANT: DO NOT PUT A break BELOW this comment
      */

    case DLT_RAW: /* RAW IP (no ethernet header) */
      length -= headerDisplacement; /* don't count PPP header */
      ether_src = ether_dst = NULL;
      processIpPkt(p+headerDisplacement, h, length, NULL, NULL, actualDeviceId);
      break;

    case DLT_IEEE802: /* Token Ring */
      trp = (struct tokenRing_header*)p;
      ether_src = (u_char*)trp->trn_shost, ether_dst = (u_char*)trp->trn_dhost;

      hlen = sizeof(struct tokenRing_header) - 18;

      if(trp->trn_shost[0] & TR_RII) /* Source Routed Packet */
	hlen += ((ntohs(trp->trn_rcf) & TR_RCF_LEN_MASK) >> 8);

      length -= hlen, caplen -= hlen;

      p += hlen;
      trllc = (struct tokenRing_llc *)p;

      if(trllc->dsap == 0xAA && trllc->ssap == 0xAA)
	hlen = sizeof(struct tokenRing_llc);
      else
	hlen = sizeof(struct tokenRing_llc) - 5;

      length -= hlen, caplen -= hlen;

      p += hlen;

      if(hlen == sizeof(struct tokenRing_llc))
	eth_type = ntohs(trllc->ethType);
      else
	eth_type = 0;
      break;

    default:
      eth_type = ntohs(ehdr.ether_type);
      /*
	NOTE:
	eth_type is a 32 bit integer (eg. 0x0800). If the first
	byte is NOT null (08 in the example below) then this is
	a Ethernet II frame, otherwise is a IEEE 802.3 Ethernet
	frame.
      */
      ether_src = ESRC(&ehdr), ether_dst = EDST(&ehdr);
    } /* switch(myGlobals.device[deviceId].datalink) */

#if PACKET_DEBUG
    /*
     * Time to show the Ethernet Packet Header (when enabled).
     */
    if(fd && myGlobals.device [deviceId].ethv)
      fprintf (fd, "ETHER:  ----- Ether Header -----\n"),
	fprintf (fd, "ETHER:\n"),
	fprintf (fd, "ETHER:  Packet %ld arrived at %s\n",
		 myGlobals.device [actualDeviceId].ethernetPkts, timestamp (& h->ts, ABS_FMT)),
	fprintf (fd, "ETHER:  Total size  = %d : header = %d : data = %d\n",
		 length, hlen, length - hlen),
	fprintf (fd, "ETHER:  Source      = %s\n", etheraddr_string (ether_src)),
	fprintf (fd, "ETHER:  Destination = %s\n", etheraddr_string (ether_dst));
    fflush (fd);
#endif

    if((myGlobals.device[deviceId].datalink != DLT_PPP) 
       && (myGlobals.device[deviceId].datalink != DLT_RAW)) {
      if((!myGlobals.borderSnifferMode) && (eth_type == 0x8137)) {
	/* IPX */
	IPXpacket ipxPkt;

	srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	if(srcHost == NULL) {
	  /* Sanity check */
	  traceEvent(TRACE_INFO, "Sanity check failed (5) [Low memory?]");
	} else {
	  /* Lock the instance so that the next call
	     to getHostInfo won't purge it */
	  srcHost->instanceInUse++;
	}

	dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
	dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	if(dstHost == NULL) {
	  /* Sanity check */
	  traceEvent(TRACE_INFO, "Sanity check failed (6) [Low memory?]");
	} else {
	  /* Lock the instance so that the next call
	     to getHostInfo won't purge it */
	  dstHost->instanceInUse++;
	}
	memcpy((char *)&ipxPkt, (char *)p+sizeof(struct ether_header), sizeof(IPXpacket));

	if(ntohs(ipxPkt.dstSocket) == 0x0452) {
	  /* SAP */
	  int displ = sizeof(struct ether_header);
	  p1 = p+displ;
	  length -= displ;
	  goto handleIPX;
	} else {
	  srcHost->ipxSent += length, dstHost->ipxRcvd += length;
	  myGlobals.device[actualDeviceId].ipxBytes += length;
	  updatePacketCount(srcHostIdx, dstHostIdx, (TrafficCounter)length, actualDeviceId);
	}
      } else if((myGlobals.device[deviceId].datalink == DLT_IEEE802) && (eth_type < ETHERMTU)) {
	trp = (struct tokenRing_header*)orig_p;
	ether_src = (u_char*)trp->trn_shost, ether_dst = (u_char*)trp->trn_dhost;
	srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	if(srcHost == NULL) {
	  /* Sanity check */
	  traceEvent(TRACE_INFO, "Sanity check failed (7) [Low memory?]");
	} else {
	  /* Lock the instance so that the next call
	     to getHostInfo won't purge it */
	  srcHost->instanceInUse++;
	}

	dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
	dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	if(dstHost == NULL) {
	  /* Sanity check */
	  traceEvent(TRACE_INFO, "Sanity check failed (8) [Low memory?]");
	} else {
	  /* Lock the instance so that the next call
	     to getHostInfo won't purge it */
	  dstHost->instanceInUse++;
	}

	srcHost->otherSent += length;
	dstHost->otherRcvd += length;
	updatePacketCount(srcHostIdx, dstHostIdx, (TrafficCounter)length, actualDeviceId);
      } else if((myGlobals.device[deviceId].datalink != DLT_IEEE802)
		&& (eth_type <= ETHERMTU) && (length > 3)) {
	/* The code below has been taken from tcpdump */
	u_char sap_type;
	struct llc llcHeader;

	if((ether_dst != NULL)
	   && (!myGlobals.borderSnifferMode)
	   && (strcmp(etheraddr_string(ether_dst), "FF:FF:FF:FF:FF:FF") == 0)
	   && (p[sizeof(struct ether_header)] == 0xff)
	   && (p[sizeof(struct ether_header)+1] == 0xff)
	   && (p[sizeof(struct ether_header)+4] == 0x0)) {
	  /* IPX */

	  srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	  if(srcHost == NULL) {
	    /* Sanity check */
	    traceEvent(TRACE_INFO, "Sanity check failed (9) [Low memory?]");
	  } else {
	    /* Lock the instance so that the next call
	       to getHostInfo won't purge it */
	    srcHost->instanceInUse++;
	  }

	  dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
	  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	  if(dstHost == NULL) {
	    /* Sanity check */
	    traceEvent(TRACE_INFO, "Sanity check failed (10) [Low memory?]");
	  } else {
	    /* Lock the instance so that the next call
	       to getHostInfo won't purge it */
	    dstHost->instanceInUse++;
	  }

	  srcHost->ipxSent += length, dstHost->ipxRcvd += length;
	  myGlobals.device[actualDeviceId].ipxBytes += length;
	} else if(!myGlobals.borderSnifferMode) {
	    /* MAC addresses are meaningful here */
	  srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	  dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);

	  if((srcHostIdx != NO_PEER) && (dstHostIdx != NO_PEER)) {
	  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];

	  if((srcHost == NULL) || (dstHost == NULL)) {
	    traceEvent(TRACE_INFO, "Sanity check failed (13) [Low memory?]");
	    return;
	  }
	  
	  p1 = (u_char*)(p+hlen);

	  /* Watch out for possible alignment problems */
	  memcpy(&llcHeader, (char*)p1, min(length, sizeof(llcHeader)));

	  sap_type = llcHeader.ssap & ~LLC_GSAP;
	  llcsap_string(sap_type);

	  if(sap_type == 0x42) {
	    /* Spanning Tree */
	    srcHost->stpSent += length, dstHost->stpRcvd += length;
	    myGlobals.device[actualDeviceId].stpBytes += length;
	  } else if(myGlobals.enablePacketDecoding && (sap_type == 0xE0)) {
	    /* NetWare */
	    if(!(llcHeader.ssap == LLCSAP_GLOBAL && llcHeader.dsap == LLCSAP_GLOBAL)) {
	      p1 += 3; /* LLC Header (short myGlobals.version) */
	    }

	  handleIPX:
	    /* IPX packet beginning */
	    if(length > 128)
	      memcpy(ipxBuffer, p1, 128);
	    else
	      memcpy(ipxBuffer, p1, length);
	    if((ipxBuffer[16] == 0x04)    /* SAP (Service Advertising Protocol) (byte 0) */
	       && (ipxBuffer[17] == 0x52) /* SAP (Service Advertising Protocol) (byte 1) */
	       && (ipxBuffer[30] == 0x0)  /* SAP Response (byte 0) */
	       && (ipxBuffer[31] == 0x02) /* SAP Response (byte 1) */) {
	      u_int16_t serverType;
	      char serverName[56];
	      int i, found;

	      memcpy(&serverType, &ipxBuffer[32], 2);

	      serverType = ntohs(serverType);

	      memcpy(serverName, &ipxBuffer[34], 56); serverName[56] = '\0';
	      for(i=0; i<56; i++)
		if(serverName[i] == '!') {
		  serverName[i] = '\0';
		  break;
		}

	      for(i=0, found=0; i<srcHost->numIpxNodeTypes; i++)
		if(srcHost->ipxNodeType[i] == serverType) {
		  found = 1;
		  break;
		}

	      if((!found) && (srcHost->numIpxNodeTypes < MAX_NODE_TYPES)) {
		srcHost->ipxNodeType[srcHost->numIpxNodeTypes] = serverType;
		srcHost->numIpxNodeTypes++;

		switch(serverType) {
		case 0x0007: /* Print server */
		case 0x0003: /* Print Queue */
		case 0x8002: /* Intel NetPort Print Server */
		case 0x030c: /* HP LaserJet / Quick Silver */
		  FD_SET(HOST_TYPE_PRINTER, &srcHost->flags);
		  break;

		case 0x0027: /* TCP/IP gateway */
		case 0x0021: /* NAS SNA gateway */
		case 0x055d: /* Attachmate SNA gateway */
		  FD_SET(GATEWAY_HOST_FLAG, &srcHost->flags);
		  /* ==> updateRoutedTraffic(srcHost);
		     is not needed as there are no routed packets */
		  break;

		case 0x0004: /* File server */
		case 0x0005: /* Job server */
		case 0x0008: /* Archive server */
		case 0x0009: /* Archive server */
		case 0x002e: /* Archive Server Dynamic SAP */
		case 0x0098: /* NetWare access server */
		case 0x009a: /* Named Pipes server */
		case 0x0111: /* Test server */
		case 0x03e1: /* UnixWare Application Server */
		case 0x0810: /* ELAN License Server Demo */
		  FD_SET(HOST_TYPE_SERVER, &srcHost->flags);
		  break;

		case 0x0278: /* NetWare Directory server */
		  FD_SET(HOST_SVC_DIRECTORY, &srcHost->flags);
		  break;

		case 0x0024: /* Rem bridge */
		case 0x0026: /* Bridge server */
		  FD_SET(HOST_SVC_BRIDGE, &srcHost->flags);
		  break;

		case 0x0640: /* NT Server-RPC/GW for NW/Win95 User Level Sec */
		case 0x064e: /* NT Server-IIS */
		  FD_SET(HOST_TYPE_SERVER, &srcHost->flags);
		  break;

		case 0x0133: /* NetWare Name Service */
		  FD_SET(NAME_SERVER_HOST_FLAG, &srcHost->flags);
		  break;
		}
	      }

	      if(srcHost->ipxHostName == NULL) {
		int i;

		for(i=1; i<strlen(serverName); i++)
		  if((serverName[i] == '_') && (serverName[i-1] == '_')) {
		    serverName[i-1] = '\0'; /* Avoid weird names */
		    break;
		  }

		if(strlen(serverName) >= (MAX_HOST_SYM_NAME_LEN-1)) serverName[MAX_HOST_SYM_NAME_LEN-2] = '\0';
		srcHost->ipxHostName = strdup(serverName);
		for(i=0; srcHost->ipxHostName[i] != '\0'; i++)
		  srcHost->ipxHostName[i] = tolower(srcHost->ipxHostName[i]);

		updateHostName(srcHost);
	      }
#ifdef DEBUG
	      traceEvent(TRACE_INFO, "%s [%s][%x]\n", serverName,
			 getSAPInfo(serverType, 0), serverType);
#endif
	    }

	    srcHost->ipxSent += length, dstHost->ipxRcvd += length;
	    myGlobals.device[actualDeviceId].ipxBytes += length;
	  } else if((llcHeader.ssap == LLCSAP_NETBIOS)
		    && (llcHeader.dsap == LLCSAP_NETBIOS)) {
	    /* Netbios */
	    srcHost->netbiosSent += length;
	    dstHost->netbiosRcvd += length;
	    myGlobals.device[actualDeviceId].netbiosBytes += length;
	  } else if((sap_type == 0xF0) 
		    || (sap_type == 0xB4)
		    || (sap_type == 0xC4)
		    || (sap_type == 0xF8)) {
	    /* DLC (protocol used for printers) */
	    srcHost->dlcSent += length;
	    dstHost->dlcRcvd += length; FD_SET(HOST_TYPE_PRINTER, &dstHost->flags);
	    myGlobals.device[actualDeviceId].dlcBytes += length;
	  } else if(sap_type == 0xAA /* SNAP */) {
	    u_int16_t snapType;

	    p1 = (u_char*)(p1+sizeof(llcHeader));
	    memcpy(&snapType, p1, sizeof(snapType));

	    snapType = ntohs(snapType);
	    /*
	      See section
	      "ETHERNET NUMBERS OF INTEREST" in RFC 1060

	      http://www.faqs.org/rfcs/rfc1060.html
	    */
	    if(myGlobals.enablePacketDecoding
	       && ((snapType == 0x809B) || (snapType == 0x80F3))) {
	      /* Appletalk */
	      AtDDPheader ddpHeader;

	      memcpy(&ddpHeader, (char*)p1, sizeof(AtDDPheader));

	      srcHost->atNetwork = ntohs(ddpHeader.srcNet), srcHost->atNode = ddpHeader.srcNode;
	      dstHost->atNetwork = ntohs(ddpHeader.dstNet), dstHost->atNode = ddpHeader.dstNode;

	      if(ddpHeader.ddpType == 2) {
		/* Appletalk NBP (Name Binding Protocol) */
		AtNBPheader nbpHeader;
		int numTuples, i;

		p1 = (u_char*)(p1+13);
		memcpy(&nbpHeader, (char*)p1, sizeof(AtNBPheader));
		numTuples = nbpHeader.function & 0x0F;

		if((nbpHeader.function == 0x21) && (numTuples == 1)) {
		  char nodeName[256];
		  int displ;

		  p1 = (u_char*)(p1+2);

		  if(p1[6] == '=')
		    displ = 2;
		  else
		    displ = 0;

		  memcpy(nodeName, &p1[6+displ], p1[5+displ]);
		  nodeName[p1[5+displ]] = '\0';

		  if(strlen(nodeName) >= (MAX_HOST_SYM_NAME_LEN-1)) 
		    nodeName[MAX_HOST_SYM_NAME_LEN-2] = '\0';
		  srcHost->atNodeName = strdup(nodeName);
		  updateHostName(srcHost);

		  memcpy(nodeName, &p1[7+p1[5+displ]+displ], p1[6+p1[5+displ]+displ]);
		  nodeName[p1[6+p1[5+displ]]] = '\0';

		  for(i=0; i<MAX_NODE_TYPES; i++)
		    if((srcHost->atNodeType[i] == NULL)
		       || (strcmp(srcHost->atNodeType[i], nodeName) == 0))
		      break;

		  if(srcHost->atNodeType[i] == NULL)
		    srcHost->atNodeType[i] = strdup(nodeName);
		}
	      }

	      srcHost->appletalkSent += length;
	      dstHost->appletalkRcvd += length;
	      myGlobals.device[actualDeviceId].atalkBytes += length;
	    } else {
	      if((llcHeader.ctl.snap_ether.snap_orgcode[0] == 0x0)
		 && (llcHeader.ctl.snap_ether.snap_orgcode[1] == 0x0)
		 && (llcHeader.ctl.snap_ether.snap_orgcode[2] == 0x0C) /* Cisco */) {
		/* NOTE:
		   If llcHeader.ctl.snap_ether.snap_ethertype[0] == 0x20
		   && llcHeader.ctl.snap_ether.snap_ethertype[1] == 0x0
		   this is Cisco Discovery Protocol
		*/

		FD_SET(GATEWAY_HOST_FLAG, &srcHost->flags);
	      }

	      srcHost->otherSent += length;
	      dstHost->otherRcvd += length;
	      myGlobals.device[actualDeviceId].otherBytes += length;
	    }
	  } else if(myGlobals.enablePacketDecoding
		    && ((sap_type == 0x06)
			|| (sap_type == 0xFE)
			|| (sap_type == 0xFC))) {  /* OSI */
	    srcHost->osiSent += length;
	    dstHost->osiRcvd += length;
	    myGlobals.device[actualDeviceId].osiBytes += length;
	  } else {
	    /* Unknown Protocol */
#ifdef PRINT_UNKNOWN_PACKETS
	    traceEvent(TRACE_INFO, "[%u] [%x] %s %s > %s\n", (u_short)sap_type,(u_short)sap_type,
		       etheraddr_string(ether_src),
		       llcsap_string(llcHeader.ssap & ~LLC_GSAP),
		       etheraddr_string(ether_dst));
#endif
	    srcHost->otherSent += length;
	    dstHost->otherRcvd += length;
	    myGlobals.device[actualDeviceId].otherBytes += length;
	  }
	  updatePacketCount(srcHostIdx, dstHostIdx, (TrafficCounter)length, actualDeviceId);
	  }
	}
      } else if(eth_type == ETHERTYPE_IP) {
	if((myGlobals.device[deviceId].datalink == DLT_IEEE802) && (eth_type > ETHERMTU))
	  processIpPkt(p, h, length, ether_src, ether_dst, actualDeviceId);
	else
	  processIpPkt(p+hlen, h, length, ether_src, ether_dst, actualDeviceId);
      } else  /* Non IP */ if(!myGlobals.borderSnifferMode) {
	    /* MAC addresses are meaningful here */
	struct ether_arp arpHdr;
	struct in_addr addr;

	if(eth_type == ETHERTYPE_IPv6) {
	  static int firstTimeIpv6=1;

	  if(firstTimeIpv6) {
	    traceEvent(TRACE_WARNING, "IPv6 is unsupported: assuming raw."); /* To Do */
	    firstTimeIpv6 = 0;
	  }
	}

	if(length > hlen)
	  length -= hlen;
	else
	  length = 0;

	srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	if(srcHost == NULL) {
	  /* Sanity check */
	  traceEvent(TRACE_INFO, "Sanity check failed (11) [Low memory?]");
	} else {
	  /* Lock the instance so that the next call
	     to getHostInfo won't purge it */
	  srcHost->instanceInUse++;
	}

	dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
	dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	if(dstHost == NULL) {
	  /* Sanity check */
	  traceEvent(TRACE_INFO, "Sanity check failed (12) [Low memory?]");
	} else {
	  /* Lock the instance so that the next call
	     to getHostInfo won't purge it */
	  dstHost->instanceInUse++;
	}

	switch(eth_type) {
	case ETHERTYPE_ARP: /* ARP - Address resolution Protocol */
	  memcpy(&arpHdr, p+hlen, sizeof(arpHdr));
	  if(EXTRACT_16BITS(&arpHdr.arp_pro) == ETHERTYPE_IP) {
	    int arpOp = EXTRACT_16BITS(&arpHdr.arp_op);
	    
	    switch(arpOp) {
	    case ARPOP_REPLY: /* ARP REPLY */
	      memcpy(&addr.s_addr, arpHdr.arp_tpa, sizeof(addr.s_addr));
	      addr.s_addr = ntohl(addr.s_addr);
	      dstHostIdx = getHostInfo(&addr, (u_char*)&arpHdr.arp_tha, 0, 0, actualDeviceId);
	      dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	      memcpy(&addr.s_addr, arpHdr.arp_spa, sizeof(addr.s_addr));
	      addr.s_addr = ntohl(addr.s_addr);
	      srcHostIdx = getHostInfo(&addr, (u_char*)&arpHdr.arp_sha, 0, 0, actualDeviceId);
	      srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	      if(srcHost != NULL) srcHost->arpReplyPktsSent++;
	      if(dstHost != NULL) dstHost->arpReplyPktsRcvd++;
	      /* DO NOT ADD A break ABOVE ! */
	    case ARPOP_REQUEST: /* ARP request */
	      memcpy(&addr.s_addr, arpHdr.arp_spa, sizeof(addr.s_addr));
	      addr.s_addr = ntohl(addr.s_addr);
	      srcHostIdx = getHostInfo(&addr, (u_char*)&arpHdr.arp_sha, 0, 0, actualDeviceId);
	      srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	      if((arpOp == ARPOP_REQUEST) && (srcHost != NULL)) srcHost->arpReqPktsSent++;
	    }
	  }
	  /* DO NOT ADD A break ABOVE ! */
	case ETHERTYPE_REVARP: /* Reverse ARP */
	  if(srcHost != NULL) srcHost->arp_rarpSent += length;
	  if(dstHost != NULL) dstHost->arp_rarpRcvd += length;
	  myGlobals.device[actualDeviceId].arpRarpBytes += length;
	  break;
	case ETHERTYPE_DN: /* Decnet */
	  srcHost->decnetSent += length;
	  dstHost->decnetRcvd += length;
	  myGlobals.device[actualDeviceId].decnetBytes += length;
	  break;
	case ETHERTYPE_ATALK: /* AppleTalk */
	case ETHERTYPE_AARP:
	  srcHost->appletalkSent += length;
	  dstHost->appletalkRcvd += length;
	  myGlobals.device[actualDeviceId].atalkBytes += length;
	  break;
	case ETHERTYPE_QNX:
	  srcHost->qnxSent += length;
	  dstHost->qnxRcvd += length;
	  myGlobals.device[actualDeviceId].qnxBytes += length;
	  break;
	default:
#ifdef PRINT_UNKNOWN_PACKETS
	  traceEvent(TRACE_INFO, "%s/%s->%s/%s [eth type %d (0x%x)]\n",
		     srcHost->hostNumIpAddress, srcHost->ethAddressString,
		     dstHost->hostNumIpAddress, dstHost->ethAddressString,
		     eth_type, eth_type);
#endif
	  srcHost->otherSent += length;
	  dstHost->otherRcvd += length;
	  myGlobals.device[actualDeviceId].otherBytes += length;
	  break;
	}

	updatePacketCount(srcHostIdx, dstHostIdx, (TrafficCounter)length, actualDeviceId);
      }
    }

    /* Unlock the instances */
    if(srcHost != NULL) srcHost->instanceInUse--;
    if(dstHost != NULL) dstHost->instanceInUse--;
  }

  if(myGlobals.flowsList != NULL) /* Handle flows last */
    flowsProcess(h, p, deviceId);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.hostsHashMutex);
#endif
}

/* ************************************ */

void updateOSName(HostTraffic *el) {
  datum key_data, data_data;

  if(el->osName == NULL) {
    char *theName = NULL, tmpBuf[256];

    if(el->hostNumIpAddress[0] == '\0') {
      el->osName = strdup("");
      return;
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, "updateOSName(%s)\n", el->hostNumIpAddress);
#endif

    if(snprintf(tmpBuf, sizeof(tmpBuf), "@%s", el->hostNumIpAddress) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    key_data.dptr = tmpBuf;
    key_data.dsize = strlen(tmpBuf)+1;

#ifdef MULTITHREADED
    accessMutex(&myGlobals.gdbmMutex, "updateOSName");
#endif

    if(myGlobals.gdbm_file == NULL) {
#ifdef MULTITHREADED
      releaseMutex(&myGlobals.gdbmMutex);
#endif
      return; /* ntop is quitting... */
    }

    data_data = gdbm_fetch(myGlobals.gdbm_file, key_data);

#ifdef MULTITHREADED
    releaseMutex(&myGlobals.gdbmMutex);
#endif

    if(data_data.dptr != NULL) {
      strncpy(tmpBuf, data_data.dptr, sizeof(tmpBuf));
      free(data_data.dptr);
      theName = tmpBuf;
    }

    if((theName == NULL)
       && (subnetPseudoLocalHost(el)) /* Courtesy of Jan Johansson <j2@mupp.net> */)
      theName = getHostOS(el->hostNumIpAddress, -1, NULL);

    if(theName == NULL)
      el->osName = strdup("");
    else {
      el->osName = strdup(theName);

      updateDBOSname(el);

#ifdef HAVE_MYSQL
      mySQLupdateDBOSname(el);
#endif

      if(snprintf(tmpBuf, sizeof(tmpBuf), "@%s", el->hostNumIpAddress) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      key_data.dptr = tmpBuf;
      key_data.dsize = strlen(tmpBuf)+1;
      data_data.dptr = el->osName;
      data_data.dsize = strlen(el->osName)+1;

      if(myGlobals.gdbm_file == NULL) return; /* ntop is quitting... */

#ifdef MULTITHREADED
      accessMutex(&myGlobals.gdbmMutex, "updateOSName");
#endif
      if(gdbm_store(myGlobals.gdbm_file, key_data, data_data, GDBM_REPLACE) != 0)
	printf("Error while adding myGlobals.osName for '%s'\n.\n", el->hostNumIpAddress);
      else {
#ifdef GDBM_DEBUG
	printf("Added data: %s [%s]\n", tmpBuf, el->osName);
#endif
      }

#ifdef MULTITHREADED
      releaseMutex(&myGlobals.gdbmMutex);
#endif
    }
  }
}

/* ************************************ */

/* Do not delete this line! */
#undef incrementUsageCounter

void _incrementUsageCounter(UsageCounter *counter,
			    u_int peerIdx, int deviceId, 
			    char* file, int line) {
  u_int i, found=0;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "INFO: incrementUsageCounter(%u) @ %s:%d", peerIdx, file, line);
#endif

  if((peerIdx >= myGlobals.device[deviceId].actualHashSize) && (peerIdx != NO_PEER)) {
    traceEvent(TRACE_WARNING, "WARNING: Index %u out of range [0..%u] @ %s:%d",
	       peerIdx, myGlobals.device[deviceId].actualHashSize, file, line);
    return;
  }

  counter->value++;

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
    if(counter->peersIndexes[i] == NO_PEER) {
      counter->peersIndexes[i] = peerIdx, found = 1;
      break;
    } else if(counter->peersIndexes[i] == peerIdx) {
      found = 1;
      break;
    }
  }

  if(!found) {
    for(i=0; i<MAX_NUM_CONTACTED_PEERS-1; i++)
      counter->peersIndexes[i] = counter->peersIndexes[i+1];

    counter->peersIndexes[MAX_NUM_CONTACTED_PEERS-1] = peerIdx;
  }
}

/* ************************************ */

#ifdef HASH_DEBUG
/* Debug only */
static void dumpHash() {
  int i;
  
  for(i=1; i<myGlobals.device[0].actualHashSize; i++) {
    HostTraffic *el = myGlobals.device[0].hash_hostTraffic[i];
  
    if(el != NULL) {
      traceEvent(TRACE_INFO, "(%3d) %s / %s", 
		 i,
		 el->ethAddressString,
		 el->hostNumIpAddress);
    }
  }
}
#endif /* DEBUG */
