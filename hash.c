/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 * 			    http://www.ntop.org/
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

/* Static */
static u_char printedHashWarning = 0;

/* ******************************* */

u_int computeInitialHashIdx(struct in_addr *hostIpAddress,
			    u_char *ether_addr,
			    short* useIPAddressForSearching) {
  u_int idx;

  if(((*useIPAddressForSearching) == 1)
     || ((ether_addr == NULL) && (hostIpAddress != NULL))) {
    idx = 0;
    memcpy(&idx, &hostIpAddress->s_addr, 4);
    (*useIPAddressForSearching) = 1;
  } else if(memcmp(ether_addr, /* 0 doesn't matter */
		   device[0].hash_hostTraffic[broadcastEntryIdx]->ethAddress,
		   ETHERNET_ADDRESS_LEN) == 0) {
    idx = broadcastEntryIdx;
    (*useIPAddressForSearching) = 0;
  } else if(hostIpAddress == NULL) {
    memcpy(&idx, &ether_addr[ETHERNET_ADDRESS_LEN-sizeof(u_int)], sizeof(u_int));
    (*useIPAddressForSearching) = 0;
  } else if ((hostIpAddress->s_addr == 0x0)
	     || (hostIpAddress->s_addr == 0x1)) {
    idx = 0;
    memcpy(&idx, &hostIpAddress->s_addr, 4);
    (*useIPAddressForSearching) = 1;
  } else if(isBroadcastAddress(hostIpAddress)) {
    idx = broadcastEntryIdx;
    (*useIPAddressForSearching) = 1;
  } else if(isPseudoLocalAddress(hostIpAddress)) {
    memcpy(&idx, &ether_addr[ETHERNET_ADDRESS_LEN-sizeof(u_int)], sizeof(u_int));
    (*useIPAddressForSearching) = 0;
  } else {
    idx = 0;
    memcpy(&idx, &hostIpAddress->s_addr, 4);
    (*useIPAddressForSearching) = 1;
  }

#ifdef DEBUG
  if(hostIpAddress != NULL)
    traceEvent(TRACE_INFO, "computeInitialHashIdx(%s/%s/%d) = %u\n",
	       intoa(*hostIpAddress),
	       etheraddr_string(ether_addr),
	       (*useIPAddressForSearching), idx);
  else
    traceEvent(TRACE_INFO, "computeInitialHashIdx(<>/%s/%d) = %u\n",
	       etheraddr_string(ether_addr),
	       (*useIPAddressForSearching), idx);
#endif

  return(idx);
}

/* ******************************* */

static int _mapIdx(u_int* mappings, u_int lastHashSize, u_int idx,
		   char* fileName, int fileLine) {

  if(idx == NO_PEER) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Mapping empty index %d [%s:%d]",
	       idx, fileName, fileLine);
#endif
    return(NO_PEER);
  } else if(idx >= lastHashSize) {
    traceEvent(TRACE_WARNING,
	       "Index %d out of range (0...%d) [%s:%d]",
	       idx, lastHashSize, fileName, fileLine);
    return(NO_PEER);
  } else if(mappings[idx] == NO_PEER) {
    traceEvent(TRACE_WARNING,
	       "Mapping failed for index %d [%s:%d]",
	       idx, fileName, fileLine);
    return(NO_PEER);
  } else {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Mapping %d -> %d [%s:%d]",
	       idx, mappings[idx], fileName, fileLine);
#endif
    return(mappings[idx]);
  }
}

/* ******************************* */

static int _mapUsageCounter(u_int *myMappings, int myLastHashSize,
			    UsageCounter *counter, char *file, int line) {
  int i, numFull=0;

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
    if(counter->peersIndexes[i] != NO_PEER) {
      counter->peersIndexes[i] = _mapIdx(myMappings, myLastHashSize,
					 counter->peersIndexes[i], file, line);
      if(counter->peersIndexes[i] != NO_PEER)
	numFull++;
    }
  }

  return(numFull);
}

#define mapUsageCounter(a)  _mapUsageCounter(mappings, lastHashSize, a, __FILE__, __LINE__)
#define mapIdx(a)           _mapIdx(mappings, lastHashSize, a, __FILE__, __LINE__)

/* ************************************ */

static IpGlobalSession* purgeIdleHostSessions(u_int *mappings, u_int lastHashSize,
					      IpGlobalSession *sessionScanner) {
  if(sessionScanner != NULL) {
    IpGlobalSession *returnValue;

    if(sessionScanner->next != NULL)
      sessionScanner->next = purgeIdleHostSessions(mappings, lastHashSize, sessionScanner->next);

    if(mapUsageCounter(&sessionScanner->peers) == 0) {
      /* There are no peers hence we can delete this entry */
      returnValue = sessionScanner->next;
      free(sessionScanner);
    } else
      returnValue = sessionScanner;

    return(returnValue);
  } else
    return(NULL);
}

/* ******************************* */

void resizeHostHash(int deviceToExtend, short hashAction) {
  u_int idx, *mappings;
  float multiplier;
  u_int i, j, newSize, lastHashSize;
  struct hostTraffic **hash_hostTraffic;
  short numCmp = 0;
  struct ipGlobalSession *scanner=NULL;

  if(!capturePackets)
    return;

 if(hashAction == EXTEND_HASH)
    multiplier = HASH_EXTEND_RATIO;
  else
    multiplier = HASH_RESIZE_RATIO;

  newSize = (int)(device[deviceToExtend].actualHashSize*multiplier);
  newSize = newSize - (newSize % 2); /* I want an even hash size */

#ifndef MULTITHREADED
  /* Courtesy of Roberto F. De Luca <deluca@tandar.cnea.gov.ar> */
  /* FIXME (DL): purgeIdleHosts() acts on actualDeviceId instead of deviceToExtend */
  if(newSize > maxHashSize) /* Hard Limit */ {
    purgeIdleHosts(1, actualDeviceId);
    return;
  } else
    purgeIdleHosts(0, actualDeviceId); /* Delete only idle hosts */
#else

  if(newSize > maxHashSize) /* Hard Limit */ {
    if(!printedHashWarning) {
      traceEvent(TRACE_WARNING, "Unable to extend the hash: hard limit (%d) reached",
		 maxHashSize);
      printedHashWarning = 1;
    }
    return;
  }

  printedHashWarning = 0;
  accessMutex(&hostsHashMutex,  "resizeHostHash(processPacket)");
  accessMutex(&hashResizeMutex, "resizeHostHash");
#endif

  if(device[deviceToExtend].actualHashSize < newSize)
    traceEvent(TRACE_INFO, "Extending hash: [old=%d, new=%d]\n",
	       device[deviceToExtend].actualHashSize, newSize);
  else
    traceEvent(TRACE_INFO, "Shrinking hash: [old=%d, new=%d]\n",
	       device[deviceToExtend].actualHashSize, newSize);

  i = sizeof(HostTraffic*)*newSize;
  hash_hostTraffic = malloc(i); memset(hash_hostTraffic, 0, i);
  i = sizeof(int)*device[deviceToExtend].actualHashSize;
  mappings = malloc(i);
  for(j=1; j<device[deviceToExtend].actualHashSize; j++)
    mappings[j] = NO_PEER;

  /* Broadcast Entry */
  hash_hostTraffic[0] = device[deviceToExtend].hash_hostTraffic[0];
  mappings[0] = 0;

  for(i=1; i<device[deviceToExtend].actualHashSize; i++)
    if(device[deviceToExtend].hash_hostTraffic[i] != NULL) {
      idx = computeInitialHashIdx(&device[deviceToExtend].hash_hostTraffic[i]->hostIpAddress,
				  device[deviceToExtend].hash_hostTraffic[i]->ethAddress,
				  &numCmp);

      idx = (u_int)((idx*3) % newSize);

#ifdef DEBUG
      traceEvent(TRACE_INFO, "Searching from slot %d [size=%d]\n", idx, newSize);
#endif

      for(j=1; j<newSize; j++) {
	if(hash_hostTraffic[idx] == NULL) {
	  hash_hostTraffic[idx] = device[deviceToExtend].hash_hostTraffic[i];
	  mappings[i] = idx;
#ifdef MAPPING_DEBUG
	  traceEvent(TRACE_INFO, "Adding mapping %d -> %d\n", i, idx);
#endif
	  break;
	} else
	  idx = (idx+1) % newSize;
      }
    }

  lastHashSize = device[deviceToExtend].actualHashSize;
  free(device[deviceToExtend].hash_hostTraffic);
  device[deviceToExtend].hash_hostTraffic = hash_hostTraffic;
  device[deviceToExtend].actualHashSize = newSize;
  device[deviceToExtend].hashThreshold = (unsigned int)(device[deviceToExtend].actualHashSize/2);
  device[deviceToExtend].topHashThreshold =
    (unsigned int)(device[deviceToExtend].actualHashSize*HASH_EXTEND_THRESHOLD);

  for(j=1; j<newSize; j++)
    if(device[deviceToExtend].hash_hostTraffic[j] != NULL) {
      HostTraffic *theHost = device[deviceToExtend].hash_hostTraffic[j];

      mapUsageCounter(&theHost->contactedRouters);

      /* ********************************* */

      mapUsageCounter(&theHost->contactedSentPeers);
      mapUsageCounter(&theHost->contactedRcvdPeers);

      if(theHost->securityHostPkts != NULL) {
	mapUsageCounter(&theHost->securityHostPkts->synPktsSent);
	mapUsageCounter(&theHost->securityHostPkts->rstPktsSent);
	mapUsageCounter(&theHost->securityHostPkts->rstAckPktsSent);
	mapUsageCounter(&theHost->securityHostPkts->synFinPktsSent);
	mapUsageCounter(&theHost->securityHostPkts->finPushUrgPktsSent);
	mapUsageCounter(&theHost->securityHostPkts->nullPktsSent);
	mapUsageCounter(&theHost->securityHostPkts->ackScanSent);
	mapUsageCounter(&theHost->securityHostPkts->xmasScanSent);
	mapUsageCounter(&theHost->securityHostPkts->finScanSent);
	mapUsageCounter(&theHost->securityHostPkts->nullScanSent);
	mapUsageCounter(&theHost->securityHostPkts->rejectedTCPConnSent);
	mapUsageCounter(&theHost->securityHostPkts->establishedTCPConnSent);
	mapUsageCounter(&theHost->securityHostPkts->udpToClosedPortSent);
	mapUsageCounter(&theHost->securityHostPkts->udpToDiagnosticPortSent);
	mapUsageCounter(&theHost->securityHostPkts->tcpToDiagnosticPortSent);
	mapUsageCounter(&theHost->securityHostPkts->tinyFragmentSent);
	mapUsageCounter(&theHost->securityHostPkts->icmpFragmentSent);
	mapUsageCounter(&theHost->securityHostPkts->overlappingFragmentSent);
	mapUsageCounter(&theHost->securityHostPkts->closedEmptyTCPConnSent);

	mapUsageCounter(&theHost->securityHostPkts->rstAckPktsRcvd);
	mapUsageCounter(&theHost->securityHostPkts->synFinPktsRcvd);
	mapUsageCounter(&theHost->securityHostPkts->finPushUrgPktsRcvd);
	mapUsageCounter(&theHost->securityHostPkts->nullPktsRcvd);
	mapUsageCounter(&theHost->securityHostPkts->ackScanRcvd);
	mapUsageCounter(&theHost->securityHostPkts->xmasScanRcvd);
	mapUsageCounter(&theHost->securityHostPkts->finScanRcvd);
	mapUsageCounter(&theHost->securityHostPkts->nullScanRcvd);
	mapUsageCounter(&theHost->securityHostPkts->rejectedTCPConnRcvd);
	mapUsageCounter(&theHost->securityHostPkts->establishedTCPConnRcvd);
	mapUsageCounter(&theHost->securityHostPkts->udpToClosedPortRcvd);
	mapUsageCounter(&theHost->securityHostPkts->udpToDiagnosticPortRcvd);
	mapUsageCounter(&theHost->securityHostPkts->tcpToDiagnosticPortRcvd);
	mapUsageCounter(&theHost->securityHostPkts->tinyFragmentRcvd);
	mapUsageCounter(&theHost->securityHostPkts->icmpFragmentRcvd);
	mapUsageCounter(&theHost->securityHostPkts->overlappingFragmentRcvd);
	mapUsageCounter(&theHost->securityHostPkts->closedEmptyTCPConnRcvd);
      }

      for(i=0; i<TOP_ASSIGNED_IP_PORTS; i++) {
	if(theHost->portsUsage[i] == NULL)
	  continue;
#ifdef DEBUG
	else {
	  printf("[idx=%3d][j=%3d] %x\n", i, j, theHost->portsUsage[i]);
	}
#endif

	if(theHost->portsUsage[i]->clientUsesLastPeer != NO_PEER)
	  theHost->portsUsage[i]->clientUsesLastPeer = mapIdx(theHost->portsUsage[i]->clientUsesLastPeer);
	if(theHost->portsUsage[i]->clientUsesLastPeer == NO_PEER) theHost->portsUsage[i]->clientUses = 0;

	if(theHost->portsUsage[i]->serverUsesLastPeer != NO_PEER)
	  theHost->portsUsage[i]->serverUsesLastPeer = mapIdx(theHost->portsUsage[i]->serverUsesLastPeer);
	if(theHost->portsUsage[i]->serverUsesLastPeer == NO_PEER) theHost->portsUsage[i]->serverUses = 0;

	if((theHost->portsUsage[i]->clientUsesLastPeer == NO_PEER)
	   && (theHost->portsUsage[i]->serverUsesLastPeer == NO_PEER)) {
	  free(theHost->portsUsage[i]);
	  theHost->portsUsage[i] = NULL;
	}
      }

      for(i=0; i<2; i++) {
	if(i == 0)
	  scanner = theHost->tcpSessionList;
	else
	  scanner = theHost->udpSessionList;

	while(scanner != NULL) {
	  mapUsageCounter(&scanner->peers);
	  scanner = (IpGlobalSession*)(scanner->next);
	}
      }
    }

  for(i=0; i<ruleSerialIdentifier; i++)
    if(filterRulesList[i] != NULL)
      if(filterRulesList[i]->queuedPacketRules != NULL) {
	for(j=0; j<MAX_NUM_RULES; j++)
	  if(filterRulesList[i]->queuedPacketRules[j] != NULL) {
	    filterRulesList[i]->queuedPacketRules[j]->srcHostIdx =
	      mapIdx(filterRulesList[i]->queuedPacketRules[j]->srcHostIdx);
	    filterRulesList[i]->queuedPacketRules[j]->dstHostIdx =
	      mapIdx(filterRulesList[i]->queuedPacketRules[j]->dstHostIdx);
	  }
      }

  for(j=0; j<60; j++) {
    if(device[deviceToExtend].last60MinutesThpt[j].topHostSentIdx != NO_PEER)
      device[deviceToExtend].last60MinutesThpt[j].topHostSentIdx =
	mapIdx(device[deviceToExtend].last60MinutesThpt[j].topHostSentIdx);

    if(device[deviceToExtend].last60MinutesThpt[j].secondHostSentIdx != NO_PEER)
      device[deviceToExtend].last60MinutesThpt[j].secondHostSentIdx =
	mapIdx(device[deviceToExtend].last60MinutesThpt[j].secondHostSentIdx);

    if(device[deviceToExtend].last60MinutesThpt[j].thirdHostSentIdx != NO_PEER)
      device[deviceToExtend].last60MinutesThpt[j].thirdHostSentIdx =
	mapIdx(device[deviceToExtend].last60MinutesThpt[j].thirdHostSentIdx);

    /* ***** */

    if(device[deviceToExtend].last60MinutesThpt[j].topHostRcvdIdx != NO_PEER)
      device[deviceToExtend].last60MinutesThpt[j].topHostRcvdIdx =
	mapIdx(device[deviceToExtend].last60MinutesThpt[j].topHostRcvdIdx);

    if(device[deviceToExtend].last60MinutesThpt[j].secondHostRcvdIdx != NO_PEER)
      device[deviceToExtend].last60MinutesThpt[j].secondHostRcvdIdx =
	mapIdx(device[deviceToExtend].last60MinutesThpt[j].secondHostRcvdIdx);

    if(device[deviceToExtend].last60MinutesThpt[j].thirdHostRcvdIdx != NO_PEER)
      device[deviceToExtend].last60MinutesThpt[j].thirdHostRcvdIdx =
	mapIdx(device[deviceToExtend].last60MinutesThpt[j].thirdHostRcvdIdx);
  }

  for(j=0; j<24; j++) {
    if(device[deviceToExtend].last24HoursThpt[j].topHostSentIdx != NO_PEER)
      device[deviceToExtend].last24HoursThpt[j].topHostSentIdx =
	mapIdx(device[deviceToExtend].last24HoursThpt[j].topHostSentIdx);

    if(device[deviceToExtend].last24HoursThpt[j].secondHostSentIdx != NO_PEER)
      device[deviceToExtend].last24HoursThpt[j].secondHostSentIdx =
	mapIdx(device[deviceToExtend].last24HoursThpt[j].secondHostSentIdx);

    if(device[deviceToExtend].last24HoursThpt[j].thirdHostSentIdx != NO_PEER)
      device[deviceToExtend].last24HoursThpt[j].thirdHostSentIdx =
	mapIdx(device[deviceToExtend].last24HoursThpt[j].thirdHostSentIdx);

    /* ***** */

    if(device[deviceToExtend].last24HoursThpt[j].topHostRcvdIdx != NO_PEER)
      device[deviceToExtend].last24HoursThpt[j].topHostRcvdIdx =
	mapIdx(device[deviceToExtend].last24HoursThpt[j].topHostRcvdIdx);

    if(device[deviceToExtend].last24HoursThpt[j].secondHostRcvdIdx != NO_PEER)
      device[deviceToExtend].last24HoursThpt[j].secondHostRcvdIdx =
	mapIdx(device[deviceToExtend].last24HoursThpt[j].secondHostRcvdIdx);

    if(device[deviceToExtend].last24HoursThpt[j].thirdHostRcvdIdx != NO_PEER)
      device[deviceToExtend].last24HoursThpt[j].thirdHostRcvdIdx =
	mapIdx(device[deviceToExtend].last24HoursThpt[j].thirdHostRcvdIdx);
  }

  if(isLsofPresent) {
#ifdef MULTITHREADED
    accessMutex(&lsofMutex, "processes Map");
#endif
    for(j=0; j<numProcesses; j++) {
      if(processes[j] != NULL) {
	int i;

	for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
	  if(processes[j]->contactedIpPeersIndexes[i] != NO_PEER)
	    processes[j]->contactedIpPeersIndexes[i] =
	      mapIdx(processes[j]->contactedIpPeersIndexes[i]);
	}
      }
    }
#ifdef MULTITHREADED
    releaseMutex(&lsofMutex);
#endif
  }

  for(j=0; j<device[deviceToExtend].numTotSessions; j++) {
    if(device[deviceToExtend].tcpSession[j] != NULL) {
      device[deviceToExtend].tcpSession[j]->initiatorIdx  =
	mapIdx(device[deviceToExtend].tcpSession[j]->initiatorIdx);
      device[deviceToExtend].tcpSession[j]->remotePeerIdx =
	mapIdx(device[deviceToExtend].tcpSession[j]->remotePeerIdx);

      if((device[deviceToExtend].tcpSession[j]->initiatorIdx == NO_PEER)
	 || (device[deviceToExtend].tcpSession[j]->remotePeerIdx == NO_PEER)) {
	/* Session to purge */
	notifyTCPSession(device[deviceToExtend].tcpSession[j]);
#ifdef HAVE_MYSQL
	mySQLnotifyTCPSession(device[deviceToExtend].tcpSession[j]);
#endif
	free(device[deviceToExtend].tcpSession[j]); /* No inner pointers to free */
	device[deviceToExtend].numTcpSessions--;
	device[deviceToExtend].tcpSession[j] = NULL;
      }
    }
  }

  free(mappings);

  /* *************************************** */

#ifdef DEBUG
  traceEvent(TRACE_INFO, "================= Hash Size %d ==========================\n",
	     device[deviceToExtend].actualHashSize);

  for(j=1,i=0; j<device[deviceToExtend].actualHashSize; j++)
    if(theHost != NULL) {
      traceEvent(TRACE_INFO, "%s [%s] (idx=%d)\n",
		 theHost->hostNumIpAddress,
		 theHost->ethAddressString,
		 j);
      i++;
    }

  traceEvent(TRACE_INFO, "================== %d entries ======================\n", i);
#endif

  /* *************************************** */

#ifdef MULTITHREADED
  releaseMutex(&hashResizeMutex);
  releaseMutex(&hostsHashMutex);
#endif

#ifdef MAPPING_DEBUG
  traceEvent(TRACE_INFO, "Hash extended succesfully\n");
#endif
}

/* ************************************ */

static void freeHostSessions(u_int hostIdx, int theDevice) {
  int i;

  for(i=0; i<device[theDevice].numTotSessions; i++) {
    if((device[theDevice].tcpSession[i] != NULL)
       && ((device[theDevice].tcpSession[i]->initiatorIdx == hostIdx)
	   || (device[theDevice].tcpSession[i]->remotePeerIdx == hostIdx))) {

      free(device[theDevice].tcpSession[i]);
      device[theDevice].tcpSession[i] = NULL;
      device[theDevice].numTcpSessions--;
    }
  }
}

/* **************************************** */

static int _checkIndex(u_int *flaggedHosts, u_int flaggedHostsLen, u_int idx,
		       char *fileName, int fileLine) {
  if(idx == NO_PEER) {
    return(0);
  } else if(idx > flaggedHostsLen) {
    traceEvent(TRACE_WARNING, "WARNING: index %u out of range 0-%u [%s:%d]",
	       idx, flaggedHostsLen, fileName, fileLine);
    return(0);
  } else
    return(flaggedHosts[idx]);
}

#define checkIndex(a) _checkIndex(flaggedHosts, flaggedHostsLen, a, __FILE__, __LINE__)

/* **************************************** */

static void _checkUsageCounter(u_int *flaggedHosts, u_int flaggedHostsLen,
			       UsageCounter *counter,
			       char *fileName, int fileLine) {
  int i;

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
    if(_checkIndex(flaggedHosts, flaggedHostsLen, counter->peersIndexes[i],
		   fileName, fileLine))
      counter->peersIndexes[i] = NO_PEER;
  }
}

#define checkUsageCounter(a, b, c) _checkUsageCounter(a, b, c, __FILE__, __LINE__)

/* **************************************** */

static void _checkPortUsage(u_int *mappings, u_int lastHashSize,
			    PortUsage **portsUsage,
			    char *fileName, int fileLine) {
  int i;

  for(i=0; i<TOP_ASSIGNED_IP_PORTS; i++) {
    if(portsUsage[i] == NULL)
      continue;
    
    if(portsUsage[i]->clientUsesLastPeer != NO_PEER)
      portsUsage[i]->clientUsesLastPeer = mapIdx(portsUsage[i]->clientUsesLastPeer);
    if(portsUsage[i]->clientUsesLastPeer == NO_PEER) portsUsage[i]->clientUses = 0;
    
    if(portsUsage[i]->serverUsesLastPeer != NO_PEER)
      portsUsage[i]->serverUsesLastPeer = mapIdx(portsUsage[i]->serverUsesLastPeer);
    if(portsUsage[i]->serverUsesLastPeer == NO_PEER) portsUsage[i]->serverUses = 0;
    
    if((portsUsage[i]->clientUsesLastPeer == NO_PEER)
       && (portsUsage[i]->serverUsesLastPeer == NO_PEER)) {
      free(portsUsage[i]);
      portsUsage[i] = NULL;
    }
  }
}

#define checkPortUsage(a, b, c) _checkPortUsage(a, b, c, __FILE__, __LINE__)

/* **************************************** */

static void removeGlobalHostPeers(HostTraffic *el,
				  u_int *flaggedHosts,
				  u_int flaggedHostsLen) {
#ifdef DEBUG
  traceEvent(TRACE_INFO, "Entering removeGlobalHostPeers(0x%X)", el);
#endif

  if(!capturePackets) return;

  if(el->tcpSessionList != NULL)
    el->tcpSessionList = purgeIdleHostSessions(flaggedHosts, flaggedHostsLen, el->tcpSessionList);

  if(el->udpSessionList != NULL)
    el->udpSessionList = purgeIdleHostSessions(flaggedHosts, flaggedHostsLen, el->udpSessionList);

  checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->contactedSentPeers);
  checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->contactedRcvdPeers);

  if(el->securityHostPkts != NULL) {
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->synPktsSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->rstPktsSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->rstAckPktsSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->synFinPktsSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->finPushUrgPktsSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->nullPktsSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->ackScanSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->xmasScanSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->finScanSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->nullScanSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->rejectedTCPConnSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->establishedTCPConnSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->udpToClosedPortSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->udpToDiagnosticPortSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->tcpToDiagnosticPortSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->tinyFragmentSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->icmpFragmentSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->overlappingFragmentSent);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->closedEmptyTCPConnSent);

    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->synPktsRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->rstAckPktsRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->rstPktsRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->synFinPktsRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->finPushUrgPktsRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->nullPktsRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->ackScanRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->xmasScanRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->finScanRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->nullScanRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->rejectedTCPConnRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->establishedTCPConnRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->udpToClosedPortRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->udpToDiagnosticPortRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->tcpToDiagnosticPortRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->tinyFragmentRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->icmpFragmentRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->overlappingFragmentRcvd);
    checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->securityHostPkts->closedEmptyTCPConnRcvd);
  }

  checkUsageCounter(flaggedHosts, flaggedHostsLen, &el->contactedRouters);
  checkPortUsage(flaggedHosts, flaggedHostsLen, el->portsUsage);
  
#ifdef DEBUG
  traceEvent(TRACE_INFO, "Leaving removeGlobalHostPeers()");
#endif
}

/* **************************************** */

void freeHostInfo(int theDevice, u_int hostIdx, u_short refreshHash) {
  u_int j, i;
  HostTraffic *host;
  IpGlobalSession *nextElement, *element;

  host = device[theDevice].hash_hostTraffic[checkSessionIdx(hostIdx)];

  if(host == NULL)
    return;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Entering freeHostInfo(%s, %u)",
	     host->hostNumIpAddress, hostIdx);
#endif

  /* Courtesy of Roberto F. De Luca <deluca@tandar.cnea.gov.ar> */
  /* FIXME (DL): checkSessionIdx() acts on actualDeviceId instead of theDevice */

  updateHostTraffic(host);
#ifdef HAVE_MYSQL
  mySQLupdateHostTraffic(host);
#endif

  device[theDevice].hash_hostTraffic[hostIdx] = NULL;
  device[theDevice].hostsno--;

#ifdef FREE_HOST_INFO
  traceEvent(TRACE_INFO, "Deleted a hash_hostTraffic entry [slotId=%d/%s]\n",
	     hostIdx, host->hostSymIpAddress);
#endif

  if(host->protoIPTrafficInfos != NULL) free(host->protoIPTrafficInfos);
  if(host->nbHostName != NULL)          free(host->nbHostName);
  if(host->nbAccountName != NULL)       free(host->nbAccountName);
  if(host->nbDomainName != NULL)        free(host->nbDomainName);
  if(host->nbDescr != NULL)             free(host->nbDescr);
  if(host->atNodeName != NULL)          free(host->atNodeName);
  for(i=0; i<MAX_NODE_TYPES; i++)
    if(host->atNodeType[i] != NULL)
      free(host->atNodeType[i]);
  if(host->atNodeName != NULL)          free(host->atNodeName);
  if(host->ipxHostName != NULL)         free(host->ipxHostName);

  if(host->securityHostPkts != NULL) {
    free(host->securityHostPkts);
    host->securityHostPkts = NULL; /* just to be safe in case of persistent storage */
  }

  if(host->osName != NULL)
    free(host->osName);

  for(i=0; i<numProcesses; i++) {
    if(processes[i] != NULL) {
      for(j=0; j<MAX_NUM_CONTACTED_PEERS; j++)
	if(processes[i]->contactedIpPeersIndexes[j] == hostIdx)
	  processes[i]->contactedIpPeersIndexes[j] = NO_PEER;
    }
  }

  for(i=0; i<60; i++) {
    if(device[theDevice].last60MinutesThpt[i].topHostSentIdx == hostIdx)
      device[theDevice].last60MinutesThpt[i].topHostSentIdx = NO_PEER;

    if(device[theDevice].last60MinutesThpt[i].secondHostSentIdx == hostIdx)
      device[theDevice].last60MinutesThpt[i].secondHostSentIdx = NO_PEER;

    if(device[theDevice].last60MinutesThpt[i].thirdHostSentIdx == hostIdx)
      device[theDevice].last60MinutesThpt[i].thirdHostSentIdx = NO_PEER;
    /* ***** */
    if(device[theDevice].last60MinutesThpt[i].topHostRcvdIdx == hostIdx)
      device[theDevice].last60MinutesThpt[i].topHostRcvdIdx = NO_PEER;

    if(device[theDevice].last60MinutesThpt[i].secondHostRcvdIdx == hostIdx)
      device[theDevice].last60MinutesThpt[i].secondHostRcvdIdx = NO_PEER;

    if(device[theDevice].last60MinutesThpt[i].thirdHostRcvdIdx == hostIdx)
      device[theDevice].last60MinutesThpt[i].thirdHostRcvdIdx = NO_PEER;
  }

  for(i=0; i<24; i++) {
    if(device[theDevice].last24HoursThpt[i].topHostSentIdx == hostIdx)
      device[theDevice].last24HoursThpt[i].topHostSentIdx = NO_PEER;

    if(device[theDevice].last24HoursThpt[i].secondHostSentIdx == hostIdx)
      device[theDevice].last24HoursThpt[i].secondHostSentIdx = NO_PEER;

    if(device[theDevice].last24HoursThpt[i].thirdHostSentIdx == hostIdx)
      device[theDevice].last24HoursThpt[i].thirdHostSentIdx = NO_PEER;
    /* ***** */
    if(device[theDevice].last24HoursThpt[i].topHostRcvdIdx == hostIdx)
      device[theDevice].last24HoursThpt[i].topHostRcvdIdx = NO_PEER;

    if(device[theDevice].last24HoursThpt[i].secondHostRcvdIdx == hostIdx)
      device[theDevice].last24HoursThpt[i].secondHostRcvdIdx = NO_PEER;

    if(device[theDevice].last24HoursThpt[i].thirdHostRcvdIdx == hostIdx)
      device[theDevice].last24HoursThpt[i].thirdHostRcvdIdx = NO_PEER;
  }

  /*
    Check whether there are hosts that have the host being
    purged as peer. Fixes courtesy of
    Andreas Pfaller <a.pfaller@pop.gun.de>.
  */

  if(refreshHash) {
    u_int *myflaggedHosts;
    int len, idx;

    len = sizeof(u_int)*device[theDevice].actualHashSize;
    myflaggedHosts = (u_int*)malloc(len);
    memset(myflaggedHosts, 0, len);
    myflaggedHosts[hostIdx] = 1; /* Set the entry to free */

    for(idx=1; idx<device[theDevice].actualHashSize; idx++) {
      if((idx != hostIdx) /* Don't remove the instance we're freeing */
	 && (device[theDevice].hash_hostTraffic[idx] != NULL)) {
	removeGlobalHostPeers(device[theDevice].hash_hostTraffic[idx],
			      myflaggedHosts, len); /* Finally refresh the hash */
      }
    }

    free(myflaggedHosts);
  }

  if(host->portsUsage != NULL) {
    for(i=0; i<TOP_ASSIGNED_IP_PORTS; i++)
      if(host->portsUsage[i] != NULL) {
	free(host->portsUsage[i]);
	host->portsUsage[i] = NULL;
      }

    free(host->portsUsage);
  }

  for(i=0; i<2; i++) {
    if(i == 0)
      element = host->tcpSessionList;
    else
      element = host->udpSessionList;

    while(element != NULL) {
      nextElement = element->next;
      /*
	The 'peers' field shouldn't be a problem because an idle host
	isn't supposed to have any session
      */
      free(element);
      element = nextElement;
    }
  }

  freeHostSessions(hostIdx, theDevice);

  /* ************************************* */

  if(isLsofPresent) {
#ifdef MULTITHREADED
    accessMutex(&lsofMutex, "readLsofInfo-2");
#endif
    for(j=0; j<TOP_IP_PORT; j++) {
      if(localPorts[j] != NULL) {
	ProcessInfoList *scanner = localPorts[j];

	while(scanner != NULL) {
	  if(scanner->element != NULL) {
	    int i;

	    for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
	      if(scanner->element->contactedIpPeersIndexes[i] == hostIdx)
		scanner->element->contactedIpPeersIndexes[i] = NO_PEER;
	    }
	  }

	  scanner = scanner->next;
	}
      }
    }
#ifdef MULTITHREADED
    releaseMutex(&lsofMutex);
#endif
  }

  if(host->icmpInfo     != NULL) free(host->icmpInfo);
  if(host->dnsStats     != NULL) free(host->dnsStats);
  if(host->httpStats    != NULL) free(host->httpStats);
#ifdef ENABLE_NAPSTER
  if(host->napsterStats != NULL) free(host->napsterStats);
#endif
  if(host->dhcpStats    != NULL) free(host->dhcpStats);

  /* ********** */

  if(usePersistentStorage != 0) {
    if((!broadcastHost(host))
       && ((usePersistentStorage == 1)
	   || subnetPseudoLocalHost(host)
	   /*
	     Courtesy of
	     Joel Crisp <jcrisp@dyn21-126.trilogy.com>
	   */
	   ))
      storeHostTrafficInstance(host);
  }

  free(host);

  numPurgedHosts++;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Leaving freeHostInfo()");
#endif
}

/* ************************************ */

void freeHostInstances(void) {
  u_int idx, i, max, num=0;

  if(mergeInterfaces)
    max = 1;
  else
    max = numDevices;

  traceEvent(TRACE_INFO, "Freeing hash host instances... (%d device(s) to save)\n", max);

  for(i=0; i<max; i++) {
    actualDeviceId = i;
    for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++) {
      if(device[actualDeviceId].hash_hostTraffic[idx] != NULL) {
	num++;
	freeHostInfo(actualDeviceId, idx, 0);
      }
    }
  }

  traceEvent(TRACE_INFO, "%d instances freed\n", num);
}

/* ************************************ */

void purgeIdleHosts(int ignoreIdleTime, int actDevice) {
  u_int idx, numFreedBuckets=0, len;
  time_t startTime = time(NULL);
  static time_t lastPurgeTime = 0;
  u_int *theFlaggedHosts;

  if(startTime < (lastPurgeTime+(SESSION_SCAN_DELAY/2)))
    return; /* Too short */
  else
    lastPurgeTime = startTime;

  traceEvent(TRACE_INFO, "Purging Idle Hosts... (ignoreIdleTime=%d, actDevice=%d)",
	     ignoreIdleTime, actDevice);

#ifdef MULTITHREADED
  accessMutex(&hostsHashMutex, "scanIdleLoop");
#endif
  purgeOldFragmentEntries(); /* let's do this too */
#ifdef MULTITHREADED
  releaseMutex(&hostsHashMutex);
#endif

  len = sizeof(u_int)*device[actDevice].actualHashSize;
  theFlaggedHosts = (u_int*)malloc(len);
  memset(theFlaggedHosts, 0, len);

#ifdef MULTITHREADED
  accessMutex(&hostsHashMutex, "scanIdleLoop");
#endif
  /* Calculates entries to free */
  for(idx=1; idx<device[actDevice].actualHashSize; idx++)
    if((device[actDevice].hash_hostTraffic[idx] != NULL)
       && (device[actDevice].hash_hostTraffic[idx]->instanceInUse == 0)
       && (!subnetPseudoLocalHost(device[actDevice].hash_hostTraffic[idx]))) {

      if((ignoreIdleTime)
	 || (((device[actDevice].hash_hostTraffic[idx]->lastSeen+
	       IDLE_HOST_PURGE_TIMEOUT) < actTime) && (!stickyHosts)))
	theFlaggedHosts[idx]=1;
    }

  /* Now free the entries */
  for(idx=1; idx<device[actDevice].actualHashSize; idx++) {
    if(theFlaggedHosts[idx] == 1) {
      freeHostInfo(actDevice, idx, 0);
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Host (idx=%d) purged (%d hosts purged)",
		 idx, numFreedBuckets);
#endif
      numFreedBuckets++;
    } else if(device[actDevice].hash_hostTraffic[idx] != NULL) {
      /*
	 This entry is not removed but we need to remove
	 all the references to the freed instances
      */
      removeGlobalHostPeers(device[actDevice].hash_hostTraffic[idx],
			    theFlaggedHosts, len); /* Finally refresh the hash */
    }
  }

#ifdef MULTITHREADED
  releaseMutex(&hostsHashMutex);
#endif

  free(theFlaggedHosts);

  traceEvent(TRACE_INFO, "Purging completed (%d sec/%d hosts deleted).",
	     (int)(time(NULL)-startTime), numFreedBuckets);
}

/* ******************************************** */

int extendTcpSessionsHash() {
  const short extensionFactor = 2;
  static short displayError = 1;

  if((device[actualDeviceId].numTotSessions*extensionFactor) <= MAX_HASH_SIZE) {
    /* Fine we can enlarge the table now */
    IPSession** tmpSession;
    int i, newLen, idx;

    newLen = extensionFactor*sizeof(IPSession*)*device[actualDeviceId].numTotSessions;

    tmpSession = device[actualDeviceId].tcpSession;
    device[actualDeviceId].tcpSession = (IPSession**)malloc(newLen);
    memset(device[actualDeviceId].tcpSession, 0, newLen);

    newLen = device[actualDeviceId].numTotSessions*extensionFactor;
    for(i=0; i<device[actualDeviceId].numTotSessions; i++) {
      if(tmpSession[i] != NULL) {
	idx = (u_int)((tmpSession[i]->initiatorRealIp.s_addr+
		       tmpSession[i]->remotePeerRealIp.s_addr+
		       tmpSession[i]->sport+
		       tmpSession[i]->dport) % newLen);

	while(device[actualDeviceId].tcpSession[idx] != NULL)
	  idx = (idx+1) % newLen;

	device[actualDeviceId].tcpSession[idx] = tmpSession[i];
      }
    }
    free(tmpSession);

    device[actualDeviceId].numTotSessions *= extensionFactor;

    displayError = 1;
    traceEvent(TRACE_INFO, "Extending TCP hash [new size: %d]",
	       device[actualDeviceId].numTotSessions);
    return(0);
  } else {
    if(displayError) {
      traceEvent(TRACE_WARNING, "WARNING: unable to further extend TCP hash [actual size: %d]",
		 device[actualDeviceId].numTotSessions);
      displayError = 0;
    }

    return(-1);
  }
}
