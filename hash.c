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
#define FREE_LIST_LEN   32
static HostTraffic *freeHostList[FREE_LIST_LEN];
static int nextIdxToFree=0, freeListLen=0;


/* ************************************ */

static void purgeIdleHostSessions(u_int hostIdx,
                                  IpGlobalSession **sessionScanner) {
  u_int i, peerFound;
  u_int *scanner;
  IpGlobalSession *theScanner = *sessionScanner,
    *prevScanner = *sessionScanner;

  while(theScanner != NULL) {
    scanner = theScanner->peersIdx;
    for(i=0, peerFound=0; i<MAX_NUM_SESSION_PEERS; i++) {
      if(scanner[i] == hostIdx)
	scanner[i] = NO_PEER;
      if(scanner[i] != NO_PEER) 
	peerFound++;
    }

    if(peerFound == 0) {
      /* This entry should be removed */
      if(theScanner == prevScanner) {
	*sessionScanner = (*sessionScanner)->next;
	prevScanner = *sessionScanner;
      } else {
	prevScanner->next = theScanner->next;
      }

      free(theScanner);
      theScanner = prevScanner;
    } else {
      prevScanner = theScanner;
      theScanner = theScanner->next;
    }
  }
}

/* ******************************* */

u_int computeInitialHashIdx(struct in_addr *hostIpAddress,
			    u_char *ether_addr,
			    short* useIPAddressForSearching)
{
  u_int idx;

  if((ether_addr == NULL) && (hostIpAddress != NULL)) {
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
  } else if (isLocalAddress(hostIpAddress)) {
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

static int _mapIdx(u_int* mappings, u_int idx, 
		   u_int lastHashSize, 
		   char* fileName, int fileLine) {

  if(idx == NO_PEER) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Mapping empty index %d [%s:%d]", 
	       idx, fileName, fileLine);
#endif
    return(NO_PEER);
  } else if(mappings[idx] == NO_PEER) {
    traceEvent(TRACE_WARNING, 
	       "Mapping failed for index %d [%s:%d]", 
	       idx, fileName, fileLine);
    return(NO_PEER);
  } else if(idx >= lastHashSize) {
    traceEvent(TRACE_WARNING, 
	       "Index %d out of range (0...%d) [%s:%d]", 
	       idx, lastHashSize, fileName, fileLine);
    return(NO_PEER);
  } else {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Mapping %d -> %d [%s:%d]", 
	       idx, mappings[idx], fileName, fileLine);
#endif
    return(mappings[idx]);
  }
}

#define mapIdx(theMap)  _mapIdx(mappings, theMap, lastHashSize, __FILE__, __LINE__)

/* ******************************* */

void resizeHostHash(int deviceToExtend, float multiplier) {
  u_int idx, *mappings;
  u_int i, j, newSize, k, lastHashSize;
  struct hostTraffic **hash_hostTraffic;
  short numCmp;

  newSize = (int)(device[deviceToExtend].actualHashSize*multiplier);
  newSize = newSize - (newSize % 2); /* I want an even hash size */
  
  /* Courtesy of Roberto F. De Luca <deluca@tandar.cnea.gov.ar> */
  /* FIXME (DL): purgeIdleHosts() acts on actualDeviceId instead of deviceToExtend */
  if(newSize > maxHashSize) /* Hard Limit */ {
    purgeIdleHosts(1);
    return;
  } else
    purgeIdleHosts(0); /* Delete only idle hosts */

#if defined(MULTITHREADED)
  if(device[actualDeviceId].hostsno < (device[deviceToExtend].actualHashSize*0.85)) {
    if(tryLockMutex(&hostsHashMutex, "resizeHostHash(processPacket)") != 0) {
#ifdef DEBUG
      traceEvent(TRACE_INFO, "The table is already locked: let's try later");
#endif
      return;
    }
  } else {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "The table is too full: we must wait on the semaphore now");
#endif
    accessMutex(&hostsHashMutex, "resizeHostHash(processPacket)");
  }
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

      for(j=0; j<newSize; j++) {
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
  device[deviceToExtend].hashThreshold =
    (unsigned int)(device[deviceToExtend].actualHashSize*0.5);
  device[deviceToExtend].topHashThreshold =
    (unsigned int)(device[deviceToExtend].actualHashSize*0.75);

  for(j=1; j<newSize; j++)
    if(device[deviceToExtend].hash_hostTraffic[j] != NULL) {

      for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
	if(device[deviceToExtend].hash_hostTraffic[j]->contactedSentPeersIndexes[i] != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->contactedSentPeersIndexes[i] =
	    mapIdx(device[deviceToExtend].
				  hash_hostTraffic[j]->contactedSentPeersIndexes[i]);
	}
      }

      for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
	if(device[deviceToExtend].hash_hostTraffic[j]->contactedRcvdPeersIndexes[i] != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->contactedRcvdPeersIndexes[i] =
	    mapIdx(device[deviceToExtend].
				  hash_hostTraffic[j]->contactedRcvdPeersIndexes[i]);
	}
      }

      for(i=0; i<MAX_NUM_HOST_ROUTERS; i++) {
	if(device[deviceToExtend].hash_hostTraffic[j]->contactedRouters[i] != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->contactedRouters[i]
	    = mapIdx(device[deviceToExtend].
				    hash_hostTraffic[j]->contactedRouters[i]);
	}
      }

      /* ********************************* */

      for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.synPktsSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.synPktsSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.synPktsSent.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.rstPktsSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.rstPktsSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.rstPktsSent.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.rstAckPktsSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.rstAckPktsSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.rstAckPktsSent.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.synFinPktsSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.synFinPktsSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.synFinPktsSent.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.finPushUrgPktsSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.finPushUrgPktsSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.finPushUrgPktsSent.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.nullPktsSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.nullPktsSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.nullPktsSent.peersIndexes[i]);
	}
	
	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.ackScanSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.ackScanSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.ackScanSent.peersIndexes[i]);
	}
	
	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.xmasScanSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.xmasScanSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.xmasScanSent.peersIndexes[i]);
	}
	
	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.finScanSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.finScanSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.finScanSent.peersIndexes[i]);
	}
	
	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.nullScanSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.nullScanSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.nullScanSent.peersIndexes[i]);
	}
	
	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.rejectedTCPConnSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.rejectedTCPConnSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.rejectedTCPConnSent.peersIndexes[i]);
	}
	
	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.establishedTCPConnSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.establishedTCPConnSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.establishedTCPConnSent.peersIndexes[i]);
	}
	
	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.udpToClosedPortSent.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.udpToClosedPortSent.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.udpToClosedPortSent.peersIndexes[i]);
	}
	
	/* ************** */

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.synPktsRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.synPktsRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.synPktsRcvd.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.rstPktsRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.rstPktsRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.rstPktsRcvd.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.rstAckPktsRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.rstAckPktsRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.rstAckPktsRcvd.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.synFinPktsRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.synFinPktsRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.synFinPktsRcvd.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.finPushUrgPktsRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.finPushUrgPktsRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.finPushUrgPktsRcvd.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.nullPktsRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.nullPktsRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.nullPktsRcvd.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.ackScanRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.ackScanRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.ackScanRcvd.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.xmasScanRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.xmasScanRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.xmasScanRcvd.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.finScanRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.finScanRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.finScanRcvd.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.nullScanRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.nullScanRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.nullScanRcvd.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.rejectedTCPConnRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.rejectedTCPConnRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.rejectedTCPConnRcvd.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.establishedTCPConnRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.establishedTCPConnRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.establishedTCPConnRcvd.peersIndexes[i]);
	}

	if(device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.udpToClosedPortRcvd.peersIndexes[i]
	   != NO_PEER) {
	  device[deviceToExtend].hash_hostTraffic[j]->securityHostPkts.udpToClosedPortRcvd.peersIndexes[i]
	    = mapIdx(device[deviceToExtend].
		     hash_hostTraffic[j]->securityHostPkts.udpToClosedPortRcvd.peersIndexes[i]);
	}
      }

      for(i=0; i<TOP_ASSIGNED_IP_PORTS; i++) {
	if(device[deviceToExtend].hash_hostTraffic[j]->portsUsage[i] == NULL)
	  continue;

	device[deviceToExtend].hash_hostTraffic[j]->portsUsage[i]->clientUsesLastPeer =
	  mapIdx(device[deviceToExtend].
		 hash_hostTraffic[j]->portsUsage[i]->clientUsesLastPeer);

	device[deviceToExtend].hash_hostTraffic[j]->portsUsage[i]->serverUsesLastPeer =
	  mapIdx(device[deviceToExtend].
		 hash_hostTraffic[j]->portsUsage[i]->serverUsesLastPeer);
      }

      /* ********************************* */

      for(k=0; k<2; k++) {
	struct ipGlobalSession *scanner=NULL;

	if(k == 0)
	  scanner = device[deviceToExtend].hash_hostTraffic[j]->tcpSessionList;
	else
	  scanner = device[deviceToExtend].hash_hostTraffic[j]->udpSessionList;

	while(scanner != NULL) {
	  for(i=0; i<MAX_NUM_SESSION_PEERS; i++)
	    if(scanner->peersIdx[i] != NO_PEER) {
	      scanner->peersIdx[i] = mapIdx(scanner->peersIdx[i]);
	    }

	  scanner = (IpGlobalSession*)(scanner->next);
	}
      }

      /* ********************************* */
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

#ifdef MULTITHREADED
  accessMutex(&lsofMutex, "processes Map");
#endif
  for(j=0; j<MAX_NUM_PROCESSES; j++) {
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

  for(j=0; j<HASHNAMESIZE; j++) {
    if(tcpSession[j] != NULL) {
      tcpSession[j]->initiatorIdx  = mapIdx(tcpSession[j]->initiatorIdx);
      tcpSession[j]->remotePeerIdx = mapIdx(tcpSession[j]->remotePeerIdx);

      if((tcpSession[j]->initiatorIdx == NO_PEER)
	 || (tcpSession[j]->remotePeerIdx == NO_PEER)) {
	/* Session to purge */
	notifyTCPSession(tcpSession[j]);
	free(tcpSession[j]); /* No inner pointers to free */
	numTcpSessions--;
	tcpSession[j] = NULL;
      }
    }

    if(udpSession[j] != NULL) {
      udpSession[j]->initiatorIdx  = mapIdx(udpSession[j]->initiatorIdx);
      udpSession[j]->remotePeerIdx = mapIdx(udpSession[j]->remotePeerIdx);

      if((udpSession[j]->initiatorIdx == NO_PEER)
	 || (udpSession[j]->remotePeerIdx == NO_PEER)) {
	/* Session to purge */
	free(udpSession[j]); /* No inner pointers to free */
	numUdpSessions--;
	udpSession[j] = NULL;
      }
    }
  }

  free(mappings);

  /* *************************************** */

#ifdef DEBUG
  traceEvent(TRACE_INFO, "================= Hash Size %d ==========================\n",
	 device[deviceToExtend].actualHashSize);

  for(j=1,i=0; j<device[deviceToExtend].actualHashSize; j++)
    if(device[deviceToExtend].hash_hostTraffic[j] != NULL) {
      traceEvent(TRACE_INFO, "%s [%s] (idx=%d)\n",
	     device[deviceToExtend].hash_hostTraffic[j]->hostNumIpAddress,
	     device[deviceToExtend].hash_hostTraffic[j]->ethAddressString,
	     j);
      i++;
    }

  traceEvent(TRACE_INFO, "================== %d entries ======================\n", i);
#endif

  /* *************************************** */

#if defined(MULTITHREADED)
  releaseMutex(&hashResizeMutex);
  releaseMutex(&hostsHashMutex);
#endif

#ifdef MAPPING_DEBUG
  traceEvent(TRACE_INFO, "Hash extended succesfully\n");
#endif
}

/* ************************************ */

/* Delayed free */
void freeHostInfo(int theDevice, u_int hostIdx) {
  u_int idx, j, i;
  HostTraffic *host = device[theDevice].hash_hostTraffic[checkSessionIdx(hostIdx)];

  if(host == NULL)
    return;

  /* Courtesy of Roberto F. De Luca <deluca@tandar.cnea.gov.ar> */
  /* FIXME (DL): checkSessionIdx() acts on actualDeviceId instead of theDevice */

  updateHostTraffic(host);

  device[theDevice].hash_hostTraffic[hostIdx] = NULL;
  device[theDevice].hostsno--;

#ifdef FREE_HOST_INFO
  traceEvent(TRACE_INFO, "Deleted a hash_hostTraffic entry [slotId=%d/%s]\n",
	 hostIdx, host->hostSymIpAddress);
#endif

  free(host->protoIPTrafficInfos);
  if(host->nbHostName != NULL)   free(host->nbHostName);
  if(host->nbDomainName != NULL) free(host->nbDomainName);
  if(host->atNodeName != NULL)   free(host->atNodeName);
  for(i=0; i<MAX_NODE_TYPES; i++)
    if(host->atNodeType[i] != NULL)   
      free(host->atNodeType[i]);
  if(host->atNodeName != NULL)   free(host->atNodeName);
  if(host->ipxHostName != NULL)  free(host->ipxHostName);

  if(host->osName != NULL)
    free(host->osName);

  for(i=0; i<2; i++) {
    IpGlobalSession *nextElement, *element;

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

  for(i=0; i<TOP_ASSIGNED_IP_PORTS; i++)
    if(host->portsUsage[i] != NULL)
      free(host->portsUsage[i]);

  for(i=0; i<MAX_NUM_PROCESSES; i++) {
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
  for(idx=1; idx<device[theDevice].actualHashSize; idx++) {
    HostTraffic *el;

    if(idx != hostIdx) {
      /* Skip the host we're currently freeing */
      el = device[theDevice].hash_hostTraffic[idx];
    
      if(el != NULL) {
	if(el->tcpSessionList != NULL)
	  purgeIdleHostSessions(hostIdx, &el->tcpSessionList);

	if(el->udpSessionList != NULL)
	  purgeIdleHostSessions(hostIdx, &el->udpSessionList);

	for(j=0; j<MAX_NUM_CONTACTED_PEERS; j++) {
	  if(el->contactedSentPeersIndexes[j] == hostIdx)
	    el->contactedSentPeersIndexes[j] = NO_PEER;
	  if(el->contactedRcvdPeersIndexes[j] == hostIdx)
	    el->contactedRcvdPeersIndexes[j] = NO_PEER;
	  if(el->securityHostPkts.synPktsSent.peersIndexes[j] == hostIdx)
	    el->securityHostPkts.synPktsSent.peersIndexes[j] = NO_PEER;
	  if(el->securityHostPkts.rstAckPktsSent.peersIndexes[j] == hostIdx)
	    el->securityHostPkts.rstAckPktsSent.peersIndexes[j] = NO_PEER;
	  if(el->securityHostPkts.rstPktsSent.peersIndexes[j] == hostIdx)
	    el->securityHostPkts.rstPktsSent.peersIndexes[j] = NO_PEER;
	  if(el->securityHostPkts.synFinPktsSent.peersIndexes[j] == hostIdx)
	    el->securityHostPkts.synFinPktsSent.peersIndexes[j] = NO_PEER;
	  if(el->securityHostPkts.finPushUrgPktsSent.peersIndexes[j] == hostIdx)
	    el->securityHostPkts.finPushUrgPktsSent.peersIndexes[j] = NO_PEER;
	  if(el->securityHostPkts.nullPktsSent.peersIndexes[j] == hostIdx)
	    el->securityHostPkts.nullPktsSent.peersIndexes[j] = NO_PEER;

	  if(el->securityHostPkts.synPktsRcvd.peersIndexes[j] == hostIdx)
	    el->securityHostPkts.synPktsRcvd.peersIndexes[j] = NO_PEER;
	  if(el->securityHostPkts.rstAckPktsRcvd.peersIndexes[j] == hostIdx)
	    el->securityHostPkts.rstAckPktsRcvd.peersIndexes[j] = NO_PEER;
	  if(el->securityHostPkts.rstPktsRcvd.peersIndexes[j] == hostIdx)
	    el->securityHostPkts.rstPktsRcvd.peersIndexes[j] = NO_PEER;
	  if(el->securityHostPkts.synFinPktsRcvd.peersIndexes[j] == hostIdx)
	    el->securityHostPkts.synFinPktsRcvd.peersIndexes[j] = NO_PEER;
	  if(el->securityHostPkts.finPushUrgPktsRcvd.peersIndexes[j] == hostIdx)
	    el->securityHostPkts.finPushUrgPktsRcvd.peersIndexes[j] = NO_PEER;
	  if(el->securityHostPkts.nullPktsRcvd.peersIndexes[j] == hostIdx)
	    el->securityHostPkts.nullPktsRcvd.peersIndexes[j] = NO_PEER;
	}

	for(j=0; j<MAX_NUM_HOST_ROUTERS; j++)
	  if(el->contactedRouters[j] == hostIdx)
	    el->contactedRouters[j] = NO_PEER;

	for(j=0; j<TOP_ASSIGNED_IP_PORTS; j++)
	  if(el->portsUsage[j] != NULL) {
	    if((el->portsUsage[j]->clientUsesLastPeer == hostIdx)
	       || (el->portsUsage[j]->serverUsesLastPeer == hostIdx)) {
	      free(el->portsUsage[j]);
	      el->portsUsage[j] = NULL;
	    }
	  }
      }
    }
  } /* for */

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

  if(host->icmpInfo     != NULL) free(host->icmpInfo);
  if(host->dnsStats     != NULL) free(host->dnsStats);
  if(host->httpStats    != NULL) free(host->httpStats);
  if(host->napsterStats != NULL) free(host->napsterStats);
  if(host->dhcpStats    != NULL) free(host->dhcpStats);

  /* ********** */

  if((!broadcastHost(host))
     && ((usePersistentStorage == 1)
	 || subnetPseudoLocalHost(host) /* <==== 
					   Courtesy of  
					   Joel Crisp <jcrisp@dyn21-126.trilogy.com>
					*/
	 ))
    storeHostTrafficInstance(host);

  if(freeListLen == FREE_LIST_LEN) {
    free(freeHostList[nextIdxToFree]); /* This is the real free */
    freeHostList[nextIdxToFree] = host;
    nextIdxToFree = (nextIdxToFree+1) % FREE_LIST_LEN;
  } else
    freeHostList[freeListLen++] = host;
}

/* ************************************ */

void freeHostInstances(void) {
  u_int idx, i, max, num=0;

  if(mergeInterfaces)
    max = 1;
  else
    max = numDevices;

  traceEvent(TRACE_INFO, "\nFreeing hash host instances... (%d device(s) to save)\n", max);

  for(i=0; i<max; i++) {
    actualDeviceId = i;
    for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++) {
      if(device[actualDeviceId].hash_hostTraffic[idx] != NULL) {
	num++;
	freeHostInfo(actualDeviceId, idx);
      }
    }
  }

  for(i=0; i<FREE_LIST_LEN; i++)
    if(freeHostList[i] != NULL)
      free(freeHostList[i]);

  traceEvent(TRACE_INFO, "\n%d instances freed\n", num);
}

/* ************************************ */

void purgeIdleHosts(int ignoreIdleTime) {
  u_int idx, numFreedBuckets=0, freeEntry=0;

#ifdef PURGE_DEBUG
  traceEvent(TRACE_INFO, "Purging (%d)....\n", ignoreIdleTime);
#endif

  purgeOldFragmentEntries(); /* let's do this too */

  for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++)
    if((device[actualDeviceId].hash_hostTraffic[idx] != NULL)
       && (device[actualDeviceId].hash_hostTraffic[idx]->instanceInUse == 0)
       && (!subnetPseudoLocalHost(device[actualDeviceId].hash_hostTraffic[idx]))) {

      if(ignoreIdleTime)
	freeEntry=1;
      else if(((device[actualDeviceId].hash_hostTraffic[idx]->lastSeen+
		IDLE_HOST_PURGE_TIMEOUT) < actTime)
	      && (!stickyHosts))
	freeEntry=1;
      else
	freeEntry=0;

      if(freeEntry) {
	/* updateHostTraffic(device[actualDeviceId].hash_hostTraffic[idx]); */
	freeHostInfo(actualDeviceId, idx);
	numFreedBuckets++;

	if((device[actualDeviceId].hostsno < device[actualDeviceId].hashThreshold)
	   || (numFreedBuckets > MIN_NUM_FREED_BUCKETS))
	  break; /* We freed enough space */
      }
    }
}

