/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
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

static float timeval_subtract (struct timeval x, struct timeval y); /* forward */

/* ******************************* */

u_int computeInitialHashIdx(struct in_addr *hostIpAddress,
			    u_char *ether_addr,
			    short* useIPAddressForSearching,
			    int actualDeviceId) {
  u_int idx = 0;

  if(myGlobals.dontTrustMACaddr)  /* MAC addresses don't make sense here */
    (*useIPAddressForSearching) = 1;

  if(((*useIPAddressForSearching) == 1)
     || ((ether_addr == NULL)
	 && (hostIpAddress != NULL))) {
    if(myGlobals.trackOnlyLocalHosts
       && (!isLocalAddress(hostIpAddress))
       && (!_pseudoLocalAddress(hostIpAddress)))
      idx = myGlobals.otherHostEntryIdx;
    else
      memcpy(&idx, &hostIpAddress->s_addr, 4);

    (*useIPAddressForSearching) = 1;
  } else if(memcmp(ether_addr, /* 0 doesn't matter */
		   myGlobals.device[0].hash_hostTraffic[myGlobals.broadcastEntryIdx]->ethAddress,
		   ETHERNET_ADDRESS_LEN) == 0) {
    idx = myGlobals.broadcastEntryIdx;
    (*useIPAddressForSearching) = 0;
  } else if(hostIpAddress == NULL) {
    memcpy(&idx, &ether_addr[ETHERNET_ADDRESS_LEN-sizeof(u_int)], sizeof(u_int));
    (*useIPAddressForSearching) = 0;
  } else if ((hostIpAddress->s_addr == 0x0)
	     || (hostIpAddress->s_addr == 0x1)) {
    if(myGlobals.trackOnlyLocalHosts)
      idx = myGlobals.otherHostEntryIdx;
    else
      memcpy(&idx, &hostIpAddress->s_addr, 4);

    (*useIPAddressForSearching) = 1;
  } else if(isBroadcastAddress(hostIpAddress)) {
    idx = myGlobals.broadcastEntryIdx;
    (*useIPAddressForSearching) = 1;
  } else if(isPseudoLocalAddress(hostIpAddress)) {
    memcpy(&idx, &ether_addr[ETHERNET_ADDRESS_LEN-sizeof(u_int)], sizeof(u_int));
    (*useIPAddressForSearching) = 0;
  } else {
    if(hostIpAddress != NULL) {
      if(myGlobals.trackOnlyLocalHosts && (!isPseudoLocalAddress(hostIpAddress)))
	idx = myGlobals.otherHostEntryIdx;
      else
	memcpy(&idx, &hostIpAddress->s_addr, 4);
    } else {
      idx = NO_PEER;
      traceEvent(TRACE_WARNING, "WARNING: Index calculation problem");
    }

    (*useIPAddressForSearching) = 1;
  }

#ifdef DEBUG
  if(hostIpAddress != NULL)
    traceEvent(TRACE_INFO, "computeInitialHashIdx(%s/%s/%d) = %u\n",
	       intoa(*hostIpAddress),
	       etheraddr_string(ether_addr),
	       (*useIPAddressForSearching), idx);
  else
    traceEvent(TRACE_INFO, "computeInitialHashIdx(%s/%d) = %u\n",
	       etheraddr_string(ether_addr),
	       (*useIPAddressForSearching), idx);
#endif

  return((u_int)idx);
}

/* ************************************ */
/*
  Description:
  This function is called when a host is freed. Therefore
  it is necessary to free all the (eventual) sessions of 
  such host.  
*/

#define MUTEX_FHS_MASK         (max(0, min(65535, (1 << MUTEX_FHS_GRANULARITY) - 1)))

static void freeHostSessions(u_int hostIdx, int theDevice) {
  int i, rc, eCount=0, mutexLocked = 0; 

  for(i=0; i<myGlobals.device[theDevice].numTotSessions; i++) {
    IPSession *prevSession, *nextSession, *theSession;

#ifdef MULTITHREADED
    if(myGlobals.capturePackets == 1 /* i.e. active, not cleanup */ ) {
      if((i & MUTEX_FHS_MASK) == 0) {
	accessMutex(&myGlobals.tcpSessionsMutex, "freeHostSessions");
	mutexLocked = 1;
      }
    } else
      return;
#endif

    prevSession = theSession = myGlobals.device[theDevice].tcpSession[i];

    while(theSession != NULL) {
      nextSession = theSession->next;

      if((theSession->initiatorIdx == hostIdx) || (theSession->remotePeerIdx == hostIdx)) {
	if(myGlobals.device[theDevice].tcpSession[i] == theSession) {
	  myGlobals.device[theDevice].tcpSession[i] = nextSession;
	  prevSession = myGlobals.device[theDevice].tcpSession[i];
	} else
	  prevSession->next = nextSession;
	
	freeSession(theSession, theDevice, 0 /* don't allocate */);
	theSession = prevSession;
      } else {
	prevSession = theSession;
	theSession = nextSession;
      }

      if(theSession && (theSession->next == theSession)) {
	traceEvent(TRACE_WARNING, "Internal Error (1)");
      }
    } /* while */

#ifdef MULTITHREADED
    if (myGlobals.capturePackets == 1 /* i.e. active, not cleanup */ ) {
      if (((i+1) & MUTEX_FHS_MASK) == 0) {
	if(mutexLocked) {
	  releaseMutex(&myGlobals.tcpSessionsMutex);
	  mutexLocked = 0;
	}
#ifdef HAVE_SCHED_H
	sched_yield(); /* Allow other threads to run */
#endif
      }
    }
#endif
  }

#ifdef MULTITHREADED
  if(mutexLocked)
    releaseMutex(&myGlobals.tcpSessionsMutex);
#endif
}

/* ********************************* */

static void purgeHostIdx(int actualDeviceId, HostTraffic *el) {
  u_short allRight = 0;

  if(el == NULL) {
    traceEvent(TRACE_ERROR, "ERROR: purgeHostIdx() failed [NULL pointer]");
    return;
  }

  if(el->hostTrafficBucket < myGlobals.device[actualDeviceId].actualHashSize) {
    HashList *list, *prevList;

    if((list = myGlobals.device[actualDeviceId].hashList[el->hashListBucket]) != NULL) {
      prevList = list;

      while(list != NULL) {
	if(list->idx == el->hostTrafficBucket) {
	  allRight = 1;
	  break;
	} else {
	  prevList = list;
	  list = list->next;
	}
      }

      if(allRight) {
	if(list == myGlobals.device[actualDeviceId].hashList[el->hashListBucket])
	  myGlobals.device[actualDeviceId].hashList[el->hashListBucket] = list->next;
	else
	  prevList->next = list->next;

	if(myGlobals.device[actualDeviceId].insertIdx > el->hostTrafficBucket)
	  myGlobals.device[actualDeviceId].insertIdx = el->hostTrafficBucket;
	free(list);
      }
    }
  } else {
    traceEvent(TRACE_ERROR, "ERROR: %d is out of range [0..%d]",  el->hostTrafficBucket,
	       myGlobals.device[actualDeviceId].actualHashSize-1);
  }

  if((!allRight) && (el->hostTrafficBucket != myGlobals.broadcastEntryIdx))
    traceEvent(TRACE_ERROR, "ERROR: purgeHostIdx(%d,%d) failed [host not found]",
	       actualDeviceId, el->hostTrafficBucket);
}

/* **************************************** */

void freeHostInfo(int theDevice, HostTraffic *host, int actualDeviceId) {
  u_int j, i;
  IpGlobalSession *nextElement, *element;

  if(host == NULL)
    return;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Entering freeHostInfo(%u)", host->hostTrafficBucket);
#endif

  myGlobals.device[theDevice].hostsno--;

#ifdef HOST_FREE_DEBUG
  traceEvent(TRACE_INFO, "HOST_FREE_DEBUG: Deleted a hash_hostTraffic entry [slotId=%d/%s]\n",
	     host->hostTrafficBucket, host->hostSymIpAddress);
#endif

  if(host->protoIPTrafficInfos != NULL) free(host->protoIPTrafficInfos);
  if(host->nonIPTraffic) {
    if(host->nonIPTraffic->nbHostName != NULL)          free(host->nonIPTraffic->nbHostName);
    if(host->nonIPTraffic->nbAccountName != NULL)       free(host->nonIPTraffic->nbAccountName);
    if(host->nonIPTraffic->nbDomainName != NULL)        free(host->nonIPTraffic->nbDomainName);
    if(host->nonIPTraffic->nbDescr != NULL)             free(host->nonIPTraffic->nbDescr);
    if(host->nonIPTraffic->atNodeName != NULL)          free(host->nonIPTraffic->atNodeName);
    for(i=0; i<MAX_NODE_TYPES; i++)       if(host->nonIPTraffic->atNodeType[i] != NULL) free(host->nonIPTraffic->atNodeType[i]);
    if(host->nonIPTraffic->atNodeName != NULL)          free(host->nonIPTraffic->atNodeName);
    if(host->nonIPTraffic->ipxHostName != NULL)         free(host->nonIPTraffic->ipxHostName);
    free(host->nonIPTraffic);
  }

  if(host->secHostPkts != NULL) {
    free(host->secHostPkts);
    host->secHostPkts = NULL; /* just to be safe in case of persistent storage */
  }

  if(host->osName != NULL)
    free(host->osName);

  if(myGlobals.isLsofPresent) {
    for(i=0; i<myGlobals.numProcesses; i++) {
      if(myGlobals.processes[i] != NULL) {
	for(j=0; j<MAX_NUM_CONTACTED_PEERS; j++)
	  if(myGlobals.processes[i]->contactedIpPeersIndexes[j] == host->hostTrafficBucket)
	    myGlobals.processes[i]->contactedIpPeersIndexes[j] = NO_PEER;
      }
    }
  }

  if(host->routedTraffic != NULL) free(host->routedTraffic);

  if(host->portsUsage != NULL) {
    for(i=0; i<TOP_ASSIGNED_IP_PORTS; i++) {
      if(host->portsUsage[i] != NULL) {
	free(host->portsUsage[i]);
      }
    }

    free(host->portsUsage);
  }

  if(myGlobals.enableSessionHandling) {
    for(i=0; i<2; i++) {
      if(i == 0)
	element = host->tcpSessionList;
      else
	element = host->udpSessionList;

      while(element != NULL) {
	if(element->magic != MAGIC_NUMBER) {
	  traceEvent(TRACE_ERROR, "===> Magic assertion failed (3) for host %s", host->hostNumIpAddress);
	}

	nextElement = element->next;
	/*
	  The 'peers' field shouldn't be a problem because an idle host
	  isn't supposed to have any session
	*/
	free(element);
	element = nextElement;
      }
    }

    host->tcpSessionList = host->udpSessionList = NULL;


    HEARTBEAT(1, "freeHostInfo() calling freeHostSessions(), mutex: [%s %s:%d]",   
	      myGlobals.tcpSessionsMutex.isLocked ? "Locked" : "Unlocked",
	      myGlobals.tcpSessionsMutex.lockFile,
	      myGlobals.tcpSessionsMutex.lockLine);
    freeHostSessions(host->hostTrafficBucket, actualDeviceId);
    HEARTBEAT(1, "freeHostInfo() returned from freeHostSessions(), mutex: [%s %s:%d]",   
	      myGlobals.tcpSessionsMutex.isLocked ? "Locked" : "Unlocked",
	      myGlobals.tcpSessionsMutex.lockFile,
	      myGlobals.tcpSessionsMutex.lockLine);
  }

  if(myGlobals.enablePacketDecoding && (host->protocolInfo != NULL)) {
    if(host->protocolInfo->httpVirtualHosts != NULL) {
      VirtualHostList *list = host->protocolInfo->httpVirtualHosts;
    
      while(list != NULL) {
	VirtualHostList *next = list->next;
	if(list->virtualHostName != NULL) /* This is a silly check as it should be true all the time */
	  free(list->virtualHostName);
	free(list);
	list = next;
      }
    }
 
    if(host->protocolInfo->userList != NULL) {
      UserList *list = host->protocolInfo->userList;
    
      while(list != NULL) {
	UserList *next = list->next;
	free(list->userName);
	free(list);
	list = next;
      }
    }

    if(host->protocolInfo->fileList != NULL) {
      FileList *list = host->protocolInfo->fileList;
      
      while(list != NULL) {
	FileList *next = list->next;
	free(list->fileName);
	free(list);
	list = next;
      }
    }

    if(host->protocolInfo->dnsStats  != NULL) free(host->protocolInfo->dnsStats);
    if(host->protocolInfo->httpStats != NULL) free(host->protocolInfo->httpStats);
    if(host->protocolInfo->dhcpStats != NULL) free(host->protocolInfo->dhcpStats);    
  }

  /* ************************************* */

  if(myGlobals.isLsofPresent) {
#ifdef MULTITHREADED
    accessMutex(&myGlobals.lsofMutex, "readLsofInfo-2");
#endif
    for(j=0; j<TOP_IP_PORT; j++) {
      if(myGlobals.localPorts[j] != NULL) {
	ProcessInfoList *scanner = myGlobals.localPorts[j];

	while(scanner != NULL) {
	  if(scanner->element != NULL) {
	    for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
	      if(scanner->element->contactedIpPeersIndexes[i] == host->hostTrafficBucket)
		scanner->element->contactedIpPeersIndexes[i] = NO_PEER;
	    }
	  }

	  scanner = scanner->next;
	}
      }
    }
#ifdef MULTITHREADED
    releaseMutex(&myGlobals.lsofMutex);
#endif
  }

  if(host->icmpInfo     != NULL) free(host->icmpInfo);

  /* ********** */

  purgeHostIdx(theDevice, host);

  /* If this is one of the special ones, let's clear the other pointer to it
   * to prevent a free of freed memory error later.
   */
  if (host == myGlobals.otherHostEntry)
      myGlobals.otherHostEntry = NULL;
  if (host == myGlobals.broadcastEntry)
      myGlobals.broadcastEntry = NULL;
  /*
    Do not free the host pointer but add it to
    a list of 'ready to use' pointers.

    Memory Recycle
  */

  if(myGlobals.hostsCacheLen < (MAX_HOSTS_CACHE_LEN-1)) {
    myGlobals.hostsCache[myGlobals.hostsCacheLen++] = host;
  } else {
    /* No room left: it's time to free the bucket */
    free(host);
  }

  myGlobals.numPurgedHosts++;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Leaving freeHostInfo()");
#endif
}

/* ************************************ */

void freeHostInstances(int actualDeviceId) {
  u_int idx, i, max, num=0;

  if(myGlobals.mergeInterfaces)
    max = 1;
  else
    max = myGlobals.numDevices;

  traceEvent(TRACE_INFO, "Freeing hash host instances... (%d device(s) to save)\n", max);

  for(i=0; i<max; i++) {
    actualDeviceId = i;
    for(idx=1; idx<myGlobals.device[actualDeviceId].actualHashSize; idx++) {
      if(myGlobals.device[actualDeviceId].hash_hostTraffic[idx] != NULL) {
	num++;
        HEARTBEAT(1, "freeHostInstances() calling freeHostInfo(), mutex: [%s %s:%d]",   
		  myGlobals.tcpSessionsMutex.isLocked ? "Locked" : "Unlocked",
		  myGlobals.tcpSessionsMutex.lockFile,
		  myGlobals.tcpSessionsMutex.lockLine);
	freeHostInfo(actualDeviceId, myGlobals.device[actualDeviceId].hash_hostTraffic[idx], actualDeviceId);
        HEARTBEAT(1, "freeHostInstances() returned from freeHostInfo(), mutex: [%s %s:%d]",   
		  myGlobals.tcpSessionsMutex.isLocked ? "Locked" : "Unlocked",
		  myGlobals.tcpSessionsMutex.lockFile,
		  myGlobals.tcpSessionsMutex.lockLine);
	myGlobals.device[actualDeviceId].hash_hostTraffic[idx] = NULL;
#ifdef HAVE_SCHED_H
	sched_yield(); /* Allow other threads to run */
#endif
      }
    }
  }

  traceEvent(TRACE_INFO, "%d instances freed\n", num);
}

/* ************************************ */

/* Subtract the `struct timeval' values X and Y */

static float timeval_subtract (struct timeval x, struct timeval y) {
  return ((long int) x.tv_sec * 1000000 + 
          (long int) x.tv_usec - 
          (long int) y.tv_sec * 1000000 - 
          (long int) y.tv_usec) / 1000000.0;
}

/* ************************************ */

void purgeIdleHosts(int actDevice) {
  u_int idx, numFreedBuckets=0, maxBucket = 0, theIdx, hashFull = 0, hashLen;
  time_t startTime = time(NULL), purgeTime;
  static time_t lastPurgeTime[MAX_NUM_DEVICES];
  static char firstRun = 1;
  HostTraffic **theFlaggedHosts = NULL;
  u_int len;
  int newHostsToPurgePerCycle;
  char purgeStats[128];

  float hiresDeltaTime;
  struct timeval hiresTimeStart, hiresTimeEnd;

  if(myGlobals.rFileName != NULL) return;

  if(firstRun) {
    traceEvent(TRACE_INFO, "IDLE_PURGE: purgeIdleHosts firstRun (mutex every %d times through the loop)\n",
                           MUTEX_FHS_MASK+1);
    firstRun = 0;
    memset(lastPurgeTime, 0, sizeof(lastPurgeTime));
  }

  gettimeofday(&hiresTimeStart, NULL);

  updateDeviceThpt(actDevice);

  if(startTime < (lastPurgeTime[actDevice]+PURGE_HOSTS_DELAY))
    return; /* Too short */
  else
    lastPurgeTime[actDevice] = startTime;

  /* How many do we allow to be purged?  Well, it's 1/3 of the hash size, at least 8.
   *
   *  The upper limit is myGlobals.maximumHostsToPurgePerCycle, which is initialized
   *  to a constant (512) and may -- if the --dynamic-purge-limits was specified, 
   *  be adjusted up or down below...
   */
  len = max(min(myGlobals.maximumHostsToPurgePerCycle, myGlobals.device[actDevice].hostsno/3), 8);

  theFlaggedHosts = (HostTraffic**)malloc(sizeof(HostTraffic*)*len);
  purgeTime = startTime-PURGE_HOSTS_DELAY; /* Time used to decide whether a host need to be purged */

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Purging Idle Hosts... [actDevice=%d]", actDevice);
#endif

#ifdef MULTITHREADED
  accessMutex(&myGlobals.hostsHashMutex, "purgeIdleHosts");
#endif
  purgeOldFragmentEntries(actDevice); /* let's do this too */
#ifdef MULTITHREADED
  releaseMutex(&myGlobals.hostsHashMutex);
#endif

  /* Calculates entries to free */
  hashLen = myGlobals.device[actDevice].actualHashSize;
  theIdx = (myGlobals.actTime % hashLen) /* random start */;
  hashFull=0;

#ifdef IDLE_PURGE_DEBUG
  traceEvent(TRACE_INFO, "IDLE_PURGE_DEBUG: BEGINING selection: upto %d hosts, "
                         "starting ('random') at %d, actual size is %d...\n", 
                         len,
                         theIdx,
                         hashLen);
#endif

  for (idx=1; idx<hashLen; idx++) {
    HostTraffic *el;

    if((theIdx == myGlobals.broadcastEntryIdx) || (theIdx == myGlobals.otherHostEntryIdx)) {
      theIdx = (theIdx+1) % hashLen;
      continue;
    }

#ifdef MULTITHREADED
    accessMutex(&myGlobals.hostsHashMutex, "scanIdleLoop");
#endif
    if((el = myGlobals.device[actDevice].hash_hostTraffic[theIdx]) != NULL) {
      if((!hashFull) 
	 && (el->refCount == 0) 
	 && (el->lastSeen < purgeTime)) {

	if((!myGlobals.stickyHosts)
	   || (el->hostNumIpAddress[0] == '\0') /* Purge MAC addresses too */
	   || (!subnetPseudoLocalHost(el))) {
	  theFlaggedHosts[maxBucket++] = el;

	  if(el->hostTrafficBucket != theIdx) {
	    traceEvent(TRACE_ERROR, "ERROR: Index mismatch (hostTrafficBucket=%d/theIdx=%d)",
		       el->hostTrafficBucket, theIdx);
	    el->hostTrafficBucket = theIdx; /* Error recovery */
	  }

	  myGlobals.device[actDevice].hash_hostTraffic[theIdx] = NULL; /* (*) */
	  if(maxBucket >= (len-1)) {
#ifdef IDLE_PURGE_DEBUG
            traceEvent(TRACE_INFO, "IDLE_PURGE_DEBUG: selected to limit...\n");
#endif
	    hashFull = 1;	
#ifdef MULTITHREADED
	    releaseMutex(&myGlobals.hostsHashMutex);
#endif
	    continue;
	  }
	}
      }
    }

#ifdef MULTITHREADED
    releaseMutex(&myGlobals.hostsHashMutex);
#endif

    theIdx = (theIdx+1) % hashLen;
  }

#ifdef IDLE_PURGE_DEBUG
  traceEvent(TRACE_INFO, "IDLE_PURGE_DEBUG: FINISHED selection, %d hosts selected...\n",
                         maxBucket);
#endif

  /* Now free the entries */
  for(idx=0; idx<maxBucket; idx++) {
#ifdef IDLE_PURGE_DEBUG
    traceEvent(TRACE_INFO, "IDLE_PURGE_DEBUG: Purging host %d... %s",
	                   idx, theFlaggedHosts[idx]->hostSymIpAddress);
#endif

    HEARTBEAT(1, "purgeIdleHosts() calling freeHostInfo(), mutex: [%s %s:%d]",   
                 myGlobals.tcpSessionsMutex.isLocked ? "Locked" : "Unlocked",
                 myGlobals.tcpSessionsMutex.lockFile,
                 myGlobals.tcpSessionsMutex.lockLine);
    freeHostInfo(actDevice, theFlaggedHosts[idx], actDevice);
    HEARTBEAT(1, "purgeIdleHosts() returning freeHostInfo(), mutex: [%s %s:%d]",   
                 myGlobals.tcpSessionsMutex.isLocked ? "Locked" : "Unlocked",
                 myGlobals.tcpSessionsMutex.lockFile,
                 myGlobals.tcpSessionsMutex.lockLine);
    numFreedBuckets++;
#ifdef HAVE_SCHED_H
    sched_yield(); /* Allow other threads to run */
#endif
  }

  free(theFlaggedHosts);

  if(myGlobals.enableSessionHandling)
    scanTimedoutTCPSessions(actDevice); /* let's check timedout sessions too */

  gettimeofday(&hiresTimeEnd, NULL);
  hiresDeltaTime=timeval_subtract(hiresTimeEnd, hiresTimeStart);

  if(numFreedBuckets > 0) {
      if(snprintf(purgeStats, 
                  sizeof(purgeStats), 
                  "Device %d: %d hosts deleted, elapsed time is %.6f seconds (%.6f per host).", 
                  actDevice,
                  numFreedBuckets,
                  hiresDeltaTime,
                  hiresDeltaTime / numFreedBuckets) < 0)
          BufferTooShort();
  } else {
      if(snprintf(purgeStats, 
                  sizeof(purgeStats), 
                  "Device %d: no hosts deleted.",
                  actDevice) < 0)
          BufferTooShort();
  }
#ifdef IDLE_PURGE_DEBUG
  traceEvent(TRACE_INFO, "IDLE_PURGE_DEBUG: %s\n", purgeStats);
#endif

  if ((myGlobals.dynamicPurgeLimits == 1) && (numFreedBuckets > 0)) {
      /* 
       * Dynamically adjust the maximum # of hosts we'll purge per cycle
       * so that it takes no more than a parameter (in seconds).
       */

#ifdef IDLE_PURGE_DEBUG
      traceEvent(TRACE_INFO, "IDLE_PURGE_DEBUG: Time targets MIN %.2f ... actual %.6f ... MAX %.2f\n",
                             NTOP_IDLE_PURGE_MINIMUM_TARGET_TIME,
                             hiresDeltaTime,
                             NTOP_IDLE_PURGE_MAXIMUM_TARGET_TIME);
#endif

      if (hiresDeltaTime > NTOP_IDLE_PURGE_MAXIMUM_TARGET_TIME) {
          if (myGlobals.maximumHostsToPurgePerCycle > 64) {
              /*
               * Shrink it based on time (i.e. 1s target / 2s actual = 50%)
               *   But keep it at least 64 and shrink by at least 8 each time... 
               */
              newHostsToPurgePerCycle =
                    max( 64, 
                         min( myGlobals.maximumHostsToPurgePerCycle - 8,
                              numFreedBuckets / 
                              (int) (hiresDeltaTime / NTOP_IDLE_PURGE_MAXIMUM_TARGET_TIME)));
              traceEvent(TRACE_INFO, "IDLE_PURGE: Adjusting maximumHostsToPurgePerCycle from %d to %d...\n", 
                                     myGlobals.maximumHostsToPurgePerCycle,
                                     newHostsToPurgePerCycle);
              myGlobals.maximumHostsToPurgePerCycle = newHostsToPurgePerCycle;
#ifdef IDLE_PURGE_DEBUG
           } else {
               traceEvent(TRACE_INFO, "IDLE_PURGE_DEBUG: Unable to adjust below 64 host minimum...\n");
#endif
           }
      } else if (numFreedBuckets < myGlobals.maximumHostsToPurgePerCycle - 8) {
#ifdef IDLE_PURGE_DEBUG
          traceEvent(TRACE_INFO, "IDLE_PURGE_DEBUG: Purged too few to adjust...\n");
#endif
      } else if (hiresDeltaTime < NTOP_IDLE_PURGE_MINIMUM_TARGET_TIME) {
          /*
           * Grow it by ADJ+1/ADJ (e.g. 10%), at least 8...
           */
          newHostsToPurgePerCycle =
                max( myGlobals.maximumHostsToPurgePerCycle + 8,
                     (NTOP_IDLE_PURGE_ADJUST_FACTOR + 1) *
                     myGlobals.maximumHostsToPurgePerCycle / 
                     NTOP_IDLE_PURGE_ADJUST_FACTOR);
          traceEvent(TRACE_INFO, "IDLE_PURGE: Adjusting maximumHostsToPurgePerCycle from %d to %d...\n", 
                     myGlobals.maximumHostsToPurgePerCycle,
                     newHostsToPurgePerCycle);
          myGlobals.maximumHostsToPurgePerCycle = newHostsToPurgePerCycle;
#ifdef IDLE_PURGE_DEBUG
      } else {
          traceEvent(TRACE_INFO, "IDLE_PURGE_DEBUG: No adjustment necessary...\n");
#endif
      }
  }
}

/* **************************************************** */

u_int getHostInfo(struct in_addr *hostIpAddress,
		  u_char *ether_addr,
		  u_char checkForMultihoming,
		  u_char forceUsingIPaddress,
		  int actualDeviceId) {
  u_int idx, i, isMultihomed = 0;
#ifndef MULTITHREADED
  u_int run=0;
#endif
  HostTraffic *el=NULL;
  unsigned char buf[MAX_HOST_SYM_NAME_LEN_HTML];
  short useIPAddressForSearching = forceUsingIPaddress;
  char* symEthName = NULL, *ethAddr;
  u_char setSpoofingFlag = 0;
  u_int hostFound = 0;
  HashList *list = NULL;

  /* traceEvent(TRACE_INFO, "getHostInfo(%s)", _intoa(*hostIpAddress, buf, sizeof(buf))); */


  if((hostIpAddress == NULL) && (ether_addr == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING: both Ethernet and IP addresses are NULL");
    return(NO_PEER);
  }

  idx = computeInitialHashIdx(hostIpAddress, ether_addr,
			      &useIPAddressForSearching, actualDeviceId);

  idx = idx % myGlobals.hashListSize;

  if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx)) {
    hostFound = 0;  /* This is the same type as the one of HashList */

    if(myGlobals.device[actualDeviceId].hashList[idx] != NULL) {
      list = myGlobals.device[actualDeviceId].hashList[idx];

      while(list != NULL) {
	el = myGlobals.device[actualDeviceId].hash_hostTraffic[list->idx];

	if(el != NULL) {
	  if(useIPAddressForSearching == 0) {
	    /* compare with the ethernet-address */
	    if(memcmp(el->ethAddress, ether_addr, ETHERNET_ADDRESS_LEN) == 0) {

	      if(hostIpAddress != NULL) {
		if((!isMultihomed) && checkForMultihoming) {
		  /* This is a local address hence this is a potential multihomed host. */

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

	      setSpoofingFlag = 1;
	      hostFound = 1;
	      break;
	    }
	  } else {
	    if(el->hostIpAddress.s_addr == hostIpAddress->s_addr) {
	      hostFound = 1;
	      break;
	    }
	  }
	}

	list = list->next;
      }
    }

    if(!hostFound) {
      /* New host entry */
      int len, currentIdx;

      if(myGlobals.hostsCacheLen > 0) {
	el = myGlobals.hostsCache[--myGlobals.hostsCacheLen];
	/*
	    traceEvent(TRACE_INFO, "Fetched host from pointers cache (len=%d)",
	    (int)myGlobals.hostsCacheLen);
	*/
      } else
	el = (HostTraffic*)malloc(sizeof(HostTraffic));
      
      memset(el, 0, sizeof(HostTraffic));
      el->firstSeen = myGlobals.actTime;
            
      resetHostsVariables(el);

      if(isMultihomed)
	FD_SET(HOST_MULTIHOMED, &el->flags);

      if(!myGlobals.largeNetwork)
	el->portsUsage = (PortUsage**)calloc(sizeof(PortUsage*), TOP_ASSIGNED_IP_PORTS);

      len = (size_t)myGlobals.numIpProtosToMonitor*sizeof(ProtoTrafficInfo);
      el->protoIPTrafficInfos = (ProtoTrafficInfo*)malloc(len);
      memset(el->protoIPTrafficInfos, 0, len);

      list = malloc(sizeof(HashList));
      list->next = myGlobals.device[actualDeviceId].hashList[idx];
      myGlobals.device[actualDeviceId].hashList[idx] = list;

      hostFound = 0;
      for(currentIdx=0,
	    /* NOTE: we need % below because insertIdx may be beyond the list end */
	    i = (myGlobals.device[actualDeviceId].insertIdx % myGlobals.device[actualDeviceId].actualHashSize);
	  currentIdx<myGlobals.device[actualDeviceId].actualHashSize; currentIdx++) {
	if(myGlobals.device[actualDeviceId].hash_hostTraffic[i] == NULL) {
	  hostFound = i;
	  break;
	} else
	  i = (i + 1) % myGlobals.device[actualDeviceId].actualHashSize;
      }

      if(!hostFound) {
        int ptrLen;
        void *oldPtr = myGlobals.device[actualDeviceId].hash_hostTraffic;

        list->idx = myGlobals.device[actualDeviceId].actualHashSize;
        if(myGlobals.device[actualDeviceId].actualHashSize < HASH_MINIMUM_SIZE)
          myGlobals.device[actualDeviceId].actualHashSize = HASH_MINIMUM_SIZE;
        else if(myGlobals.device[actualDeviceId].actualHashSize >= HASH_FACTOR_MAXIMUM)
          myGlobals.device[actualDeviceId].actualHashSize += HASH_TERMINAL_INCREASE;
        else
          myGlobals.device[actualDeviceId].actualHashSize *= HASH_INCREASE_FACTOR;

        ptrLen = sizeof(struct hostTraffic*);
        ptrLen *= myGlobals.device[actualDeviceId].actualHashSize;
	
        myGlobals.device[actualDeviceId].hash_hostTraffic = (struct hostTraffic**)malloc(ptrLen);
        memset(myGlobals.device[actualDeviceId].hash_hostTraffic, 0, ptrLen);
        memcpy(myGlobals.device[actualDeviceId].hash_hostTraffic,
               oldPtr, sizeof(struct hostTraffic*)*list->idx);
        free(oldPtr);

	traceEvent(TRACE_INFO, "Extending hash size [newSize=%d][deviceId=%d]",
		   myGlobals.device[actualDeviceId].actualHashSize, actualDeviceId);
      } else
	list->idx = hostFound;

      myGlobals.device[actualDeviceId].insertIdx = list->idx + 1; /* NOTE: insertIdx can go beyond the list end */
      el->hostTrafficBucket = list->idx;
      el->hashListBucket    = idx;
      myGlobals.device[actualDeviceId].hash_hostTraffic[el->hostTrafficBucket] = el; /* Insert a new entry */
      myGlobals.device[actualDeviceId].hostsno++;

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
	  FD_CLR(SUBNET_LOCALHOST_FLAG, &el->flags);

	  if(isPrivateAddress(hostIpAddress)) FD_SET(PRIVATE_IP_ADDRESS, &el->flags);

	  if(!isBroadcastAddress(hostIpAddress)) {
	    if(isPseudoLocalAddress(hostIpAddress))
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
	  strncpy(el->hostSymIpAddress, el->hostNumIpAddress, MAX_HOST_SYM_NAME_LEN-1);

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
	}

#ifdef DEBUG
	/*if((strcmp(etheraddr_string(ether_addr), "08:00:20:89:79:D7") == 0)
	  || (strcmp(el->hostSymIpAddress, "more") == 0))*/
	printf("Added a new hash_hostTraffic entry [%s/%s/%s/%d]\n",
	       etheraddr_string(ether_addr), el->hostSymIpAddress,
	       el->hostNumIpAddress, myGlobals.device[actualDeviceId].hostsno);
#endif

	el->lastSeen = myGlobals.actTime;
	checkSpoofing(list->idx, actualDeviceId);
      }

      if(hostIpAddress != NULL) {
	if(myGlobals.dontTrustMACaddr && (ether_addr != NULL))
	  memcpy(el->lastEthAddress, ether_addr, ETHERNET_ADDRESS_LEN);

	el->hostIpAddress.s_addr = hostIpAddress->s_addr;
	strncpy(el->hostNumIpAddress,
		_intoa(*hostIpAddress, buf, sizeof(buf)),
		sizeof(el->hostNumIpAddress));
	if(isBroadcastAddress(&el->hostIpAddress)) FD_SET(BROADCAST_HOST_FLAG, &el->flags);
	if(isMulticastAddress(&el->hostIpAddress)) FD_SET(MULTICAST_HOST_FLAG, &el->flags);
	if(isPrivateAddress(hostIpAddress))        FD_SET(PRIVATE_IP_ADDRESS,  &el->flags);
	if((ether_addr == NULL) && (isPseudoLocalAddress(hostIpAddress)))
	  FD_SET(SUBNET_PSEUDO_LOCALHOST_FLAG, &el->flags);

	/* Trick to fill up the address cache */
	if(myGlobals.numericFlag == 0)
	  ipaddr2str(el->hostIpAddress, actualDeviceId);
	else
	  strncpy(el->hostSymIpAddress, el->hostNumIpAddress, MAX_HOST_SYM_NAME_LEN-1);
      } else {
	/* el->hostNumIpAddress == "" */
	if(symEthName[0] != '\0') {
	  if(snprintf(buf, sizeof(buf), "%s <IMG SRC=/card.gif BORDER=0>", symEthName) < 0)
	    BufferTooShort();

	  buf[MAX_HOST_SYM_NAME_LEN-1] = '\0';
	  strncpy(el->hostSymIpAddress, buf, MAX_HOST_SYM_NAME_LEN-1);
	} else
	  strncpy(el->hostSymIpAddress, el->hostNumIpAddress, MAX_HOST_SYM_NAME_LEN-1);
      }

#ifdef HASH_DEBUG
      traceEvent(TRACE_INFO, "HASH_DEBUG: Adding %s/%s [idx=%d][device=%d][actualHashSize=%d][#hosts=%d]\n",
		 el->ethAddressString, el->hostNumIpAddress, list->idx, actualDeviceId,
		 myGlobals.device[actualDeviceId].actualHashSize, myGlobals.device[actualDeviceId].hostsno);
#endif

      {
	if(el->hostNumIpAddress[0] == '\0') {
	  buf[0] = 1; /* This is a MAC */
	  buf[1] = 0;
	  memcpy(&buf[2], el->ethAddress, 6);
	} else {
	  buf[0] = 0; /* This is an IP */
	  buf[1] = 0; buf[2] = 0; buf[3] = 0;
	  memcpy(&buf[4], &el->hostIpAddress.s_addr, 4);
	}

#ifdef NTOP_LITTLE_ENDIAN
	{
	  unsigned char buf1[8];

	  for(i=0; i<8; i++)
	    buf1[i] = buf[7-i];
	  
	  memcpy(buf, buf1, 8);
	}
#endif
	memcpy(&el->hostSerial, buf, 8);
      }
    }

    if(el != NULL) {
      el->lastSeen = myGlobals.actTime;

      if(setSpoofingFlag)
	FD_SET(HOST_DUPLICATED_MAC, &el->flags);

#ifdef DEBUG
      traceEvent(TRACE_INFO, "getHostInfo(idx=%d/actualDeviceId=%d) [%s/%s/%s/%d/%d]\n",
		 list->idx, actualDeviceId,
		 etheraddr_string(ether_addr), el->hostSymIpAddress,
		 el->hostNumIpAddress, myGlobals.device[actualDeviceId].hostsno,
		 useIPAddressForSearching);
#endif
    }
  } else
    return(idx);

  if(el == NULL)
    traceEvent(TRACE_INFO, "getHostInfo(idx=%d)(ptr=%x)",
	       list->idx, myGlobals.device[actualDeviceId].hash_hostTraffic[list->idx]);

  return(list->idx);
}

/* ************************************ */

int retrieveHost(HostSerial theSerial, HostTraffic *el) {
  HostTraffic *theEntry = NULL;
  int found = 0;
  u_int idx;

  if((theSerial != NO_PEER)
     && (theSerial != myGlobals.broadcastEntryIdx /* Safety check: broadcast */)) {
    char theBytes[8];

    if(theSerial == myGlobals.broadcastEntryIdx) {
      memcpy(el, myGlobals.broadcastEntry, sizeof(HostTraffic));
      return(0);
    } else if(theSerial == myGlobals.otherHostEntryIdx) {
      memcpy(el, myGlobals.otherHostEntry, sizeof(HostTraffic));
      return(0);
    }
    
    /*
       Unused
        |
        |        IP
        V     -------
      X X X X X X X X 
      ^   -----------
      |        MAC
      | 
      1 = MAC
      0 = IP

    */

    memcpy(theBytes, &theSerial, 8);

#ifdef NTOP_LITTLE_ENDIAN
    {
      unsigned char buf1[8];
      int i;

      for(i=0; i<8; i++)
	buf1[i] = theBytes[7-i];

      memcpy(theBytes, buf1, 8);
    }
#endif

    memset(el, 0, sizeof(HostTraffic));
    el->hostSerial = theSerial;

    if(theBytes[0] == 0) {
      /* IP */
      char buf[32];

      memcpy(&el->hostIpAddress.s_addr, &theBytes[4], 4);

      for(idx=1; idx<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; idx++) {
	if((idx != myGlobals.otherHostEntryIdx) &&
	   ((theEntry = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) != NULL)) {
	  if(el->hostIpAddress.s_addr == theEntry->hostIpAddress.s_addr) {
	    found = 1;
	    break;
	  }
	}
      }
      
      if(!found) {
	strncpy(el->hostNumIpAddress,
		_intoa(el->hostIpAddress, buf, sizeof(buf)),
		sizeof(el->hostNumIpAddress));
	fetchAddressFromCache(el->hostIpAddress, el->hostSymIpAddress);
	if(strcmp(el->hostSymIpAddress, el->hostNumIpAddress) == 0) {
	  char sniffedName[MAXDNAME];
	
	  if(getSniffedDNSName(el->hostNumIpAddress, sniffedName, sizeof(sniffedName)))
	    strcpy(el->hostSymIpAddress, sniffedName);
	}
      } else {
	memcpy(el, theEntry, sizeof(HostTraffic));
      }
    } else {
      /* MAC */
      char *ethAddr;

      memcpy(el->ethAddress, &theBytes[2], ETHERNET_ADDRESS_LEN);

      for(idx=1; idx<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; idx++) {
	if((idx != myGlobals.otherHostEntryIdx) &&
	   ((theEntry = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) != NULL)) {
	  if(memcmp(el->ethAddress, theEntry->ethAddress, ETHERNET_ADDRESS_LEN) == 0) {
	    found = 1;
	    break;
	  }
	}
      }

      if(!found) {
	ethAddr = etheraddr_string(el->ethAddress);
	strncpy(el->ethAddressString, ethAddr, sizeof(el->ethAddressString));
	el->hostIpAddress.s_addr = 0x1234; /* dummy */
      } else {
	memcpy(el, theEntry, sizeof(HostTraffic));
      }
    }

    return(0);
  } else
    return(-1);
}

/* ************************************ */
/* ************************************ */
/* ************************************ */

#ifdef HASH_DEBUG
/* Debug only */
static void dumpHash() {
  int i;

  for(i=1; i<myGlobals.device[0].actualHashSize; i++) {
    HostTraffic *el = myGlobals.device[0].hash_hostTraffic[i];

    if(el != NULL) {
      traceEvent(TRACE_INFO, "HASH_DEBUG: (%3d) %s / %s",
                 i,
                 el->ethAddressString,
                 el->hostNumIpAddress);
    }
  }
}
#endif /* DEBUG */



