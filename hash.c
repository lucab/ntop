/*
 *  Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
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


/* #define HASH_DEBUG */

/* #define DNS_DEBUG */

#ifdef HASH_DEBUG
static void hashSanityCheck();
static void hostHashSanityCheck(HostTraffic *host);
#endif

/* ******************************* */

u_int hashHost(HostAddr *hostIpAddress,  u_char *ether_addr,
	       short* useIPAddressForSearching, HostTraffic **el,
	       int actualDeviceId) {
  u_int idx = 0;
  *el = NULL;

  if(myGlobals.dontTrustMACaddr)  /* MAC addresses don't make sense here */
    (*useIPAddressForSearching) = 1;

  if((*useIPAddressForSearching) && (hostIpAddress == NULL)) {
#if 0
    traceEvent(CONST_TRACE_WARNING, "Index calculation problem (hostIpAddress=%x, ether_addr=%x)",
	       hostIpAddress, ether_addr);
#endif
    return(FLAG_NO_PEER);
  }

  if(((*useIPAddressForSearching) == 1)
     || ((ether_addr == NULL) && (hostIpAddress != NULL))) {
    if(myGlobals.trackOnlyLocalHosts
       && (!isLocalAddress(hostIpAddress, actualDeviceId))
       && (!_pseudoLocalAddress(hostIpAddress))) {
      *el = myGlobals.otherHostEntry;
      return(OTHER_HOSTS_ENTRY);
    } else {
      /* idx = hostIpAddress->s_addr; */
      if(hostIpAddress->hostFamily == AF_INET)
	idx = (hostIpAddress->Ip4Address.s_addr & 0xffff) ^ ((hostIpAddress->Ip4Address.s_addr >> 15) & 0xffff);
#ifdef INET6
      else if(hostIpAddress->hostFamily == AF_INET6)
	idx = in6_hash(&hostIpAddress->Ip6Address);
#endif
    }

    (*useIPAddressForSearching) = 1;
  } else if(memcmp(ether_addr, myGlobals.broadcastEntry->ethAddress, LEN_ETHERNET_ADDRESS) == 0) {
    *el = myGlobals.broadcastEntry;
    return(BROADCAST_HOSTS_ENTRY);
  } else if(hostIpAddress == NULL) {
    memcpy(&idx, &ether_addr[LEN_ETHERNET_ADDRESS-sizeof(u_int)], sizeof(u_int));
    (*useIPAddressForSearching) = 0;
  } else if(isBroadcastAddress(hostIpAddress)) {
    *el = myGlobals.broadcastEntry;
    return(BROADCAST_HOSTS_ENTRY);
  } else if(isPseudoLocalAddress(hostIpAddress, actualDeviceId)) {
    memcpy(&idx, &ether_addr[LEN_ETHERNET_ADDRESS-sizeof(u_int)], sizeof(u_int));
    (*useIPAddressForSearching) = 0;
  } else {
    if(hostIpAddress != NULL) {
      if(myGlobals.trackOnlyLocalHosts
	 && (!isPseudoLocalAddress(hostIpAddress, actualDeviceId))) {
	*el = myGlobals.otherHostEntry;
	return(OTHER_HOSTS_ENTRY);
      } else {
	/* idx = hostIpAddress->s_addr; */
	if(hostIpAddress->hostFamily == AF_INET)
	  idx = (hostIpAddress->Ip4Address.s_addr & 0xffff) ^ ((hostIpAddress->Ip4Address.s_addr >> 15) & 0xffff);
#ifdef INET6
	else if(hostIpAddress->hostFamily == AF_INET6)
	  idx = in6_hash(&hostIpAddress->Ip6Address);
#endif
      }
    } else {
      idx = FLAG_NO_PEER;
      traceEvent(CONST_TRACE_WARNING, "Index calculation problem (1)");
    }

    (*useIPAddressForSearching) = 1;
  }

  idx = idx % myGlobals.device[actualDeviceId].actualHashSize;
  
  /* Skip reserved entries */
  if((idx == BROADCAST_HOSTS_ENTRY) || (idx == OTHER_HOSTS_ENTRY))
    idx = FIRST_HOSTS_ENTRY;
  
#ifdef DEBUG
  if(hostIpAddress != NULL) {
    char buf[LEN_ETHERNET_ADDRESS_DISPLAY];

    traceEvent(CONST_TRACE_INFO, "hashHost(%s/%s/%d) = %u",
	       intoa(*hostIpAddress),
	       etheraddr_string(ether_addr, buf),
	       (*useIPAddressForSearching), idx);
  } else {
    char buf[LEN_ETHERNET_ADDRESS_DISPLAY];

    traceEvent(CONST_TRACE_INFO, "hashHost(%s/%d) = %u",
	       etheraddr_string(ether_addr, buf),
	       (*useIPAddressForSearching), idx);
  }
#endif

  return(idx);
}

/* ************************************ */

u_int hashFcHost (FcAddress *fcaddr, u_short vsanId, HostTraffic **el,
                  int actualDeviceId)
{
  u_int idx = 0;

  *el = NULL;

  if(fcaddr == NULL) {
#if 0
    traceEvent(CONST_TRACE_WARNING, "Index calculation problem (hostIpAddress=%x, ether_addr=%x)",
	       hostIpAddress, ether_addr);
#endif
    return(FLAG_NO_PEER);
  }

  idx = (fcaddr->domain & 0xff) ^ (fcaddr->area & 0xff) ^ (fcaddr->port & 0xff) ^ vsanId;

  if(actualDeviceId == -1) {
      idx = idx % CONST_HASH_INITIAL_SIZE;
  }
  else {
      idx = idx % myGlobals.device[actualDeviceId].actualHashSize;
  }

  /* Skip reserved entries */
  if((idx == BROADCAST_HOSTS_ENTRY) || (idx == OTHER_HOSTS_ENTRY))
    idx = FIRST_HOSTS_ENTRY;

  return(idx);
}

/* ************************************ */
/*
  Description:
  This function is called when a host is freed. Therefore
  it is necessary to free all the (eventual) sessions of
  such host.
*/

static void freeHostSessions(HostTraffic *host, int theDevice) {
  int i;

  if(host->l2Family == FLAG_HOST_TRAFFIC_AF_ETH) {
      for(i=0; i<MAX_TOT_NUM_SESSIONS; i++) {
          IPSession *prevSession, *nextSession, *theSession;

    if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN /* i.e. active, not cleanup */ )
      return;

    if(host->numHostSessions == 0) return;

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.tcpSessionsMutex, "freeHostSessions");
#endif

    prevSession = theSession = myGlobals.device[theDevice].tcpSession[i];

    while(theSession != NULL) {
      nextSession = theSession->next;

      if(host->numHostSessions == 0) break;

      if((theSession->initiator == host) || (theSession->remotePeer == host)) {
	if(myGlobals.device[theDevice].tcpSession[i] == theSession) {
	  myGlobals.device[theDevice].tcpSession[i] = nextSession;
	  prevSession = myGlobals.device[theDevice].tcpSession[i];
	} else
	  prevSession->next = nextSession;

	freeSession(theSession, theDevice, 0 /* don't allocate */,
		    0 /* locked by the purge thread */);
	theSession = prevSession;
      } else {
	prevSession = theSession;
	theSession = nextSession;
      }

      if(theSession && (theSession->next == theSession)) {
	traceEvent(CONST_TRACE_WARNING, "Internal Error (1)");
      }
    } /* while */

#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.tcpSessionsMutex);
#ifdef MAKE_WITH_SCHED_YIELD
    sched_yield(); /* Allow other threads to run */
#endif
#endif
  } /* for */
      
      if(host->numHostSessions > 0) {
	traceEvent(CONST_TRACE_ERROR, "====> Host %s/%s has %d sessions still to be purged",
		   host->hostNumIpAddress, host->hostResolvedName, host->numHostSessions);
      }
  }
  else {
    for(i=0; i<MAX_TOT_NUM_SESSIONS; i++) {
          FCSession *prevSession, *nextSession, *theSession;
	  
          if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN /* i.e. active, not cleanup */ )
              return;

          if(host->numHostSessions == 0) return;

#ifdef CFG_MULTITHREADED
          accessMutex(&myGlobals.fcSessionsMutex, "freeHostSessions");
#endif

          prevSession = theSession = myGlobals.device[theDevice].fcSession[i];

          while(theSession != NULL) {
              nextSession = theSession->next;

              if(host->numHostSessions == 0) break;

              if((theSession->initiator == host) || (theSession->remotePeer == host)) {
                  if(myGlobals.device[theDevice].fcSession[i] == theSession) {
                      myGlobals.device[theDevice].fcSession[i] = nextSession;
                      prevSession = myGlobals.device[theDevice].fcSession[i];
                  } else
                      prevSession->next = nextSession;

                  freeFcSession(theSession, theDevice, 0 /* don't allocate */,
                                0 /* locked by the purge thread */);
                  theSession = prevSession;
              } else {
                  prevSession = theSession;
                  theSession = nextSession;
              }

              if(theSession && (theSession->next == theSession)) {
                  traceEvent(CONST_TRACE_WARNING, "Internal Error (1)");
              }
          } /* while */

#ifdef CFG_MULTITHREADED
          releaseMutex(&myGlobals.fcSessionsMutex);
#ifdef MAKE_WITH_SCHED_YIELD
          sched_yield(); /* Allow other threads to run */
#endif
#endif
      } /* for */

      if(host->numHostSessions > 0) {
          traceEvent(CONST_TRACE_ERROR, "====> Host %s/%s has %d sessions still to be purged",
                     host->hostNumIpAddress, host->hostResolvedName, host->numHostSessions);
      }
  }
}

/* **************************************** */

void freeHostInfo(HostTraffic *host, int actualDeviceId) {
  u_int i, deleteAddressFromCache = 1;

  if((host == NULL) || myGlobals.device[actualDeviceId].virtualDevice)
    return;

  /* If this is one of the special ones, let's clear the other pointer to it
   * to prevent a free of freed memory error later.
   */
  if(host == myGlobals.otherHostEntry) {
    traceEvent(CONST_TRACE_WARNING, "Attempting to call freeHostInfo(otherHostEntry)");
    return;
  }

  if(host == myGlobals.broadcastEntry) {
    traceEvent(CONST_TRACE_WARNING, "Attempting to call freeHostInfo(broadcastEntry)");
    return;
  }

  if(host->magic != CONST_MAGIC_NUMBER) {
    traceEvent(CONST_TRACE_WARNING, "Error: bad magic number (expected=%d/real=%d)",
	       CONST_MAGIC_NUMBER, host->magic);
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Entering freeHostInfo(%u)", host->hostTrafficBucket);
#endif

  /* ********** */

#if 0
  traceEvent(CONST_TRACE_INFO, "HOST_FREE_DEBUG: Deleting a hash_hostTraffic entry [%s/%s/%s][idx=%d]",
	     host->ethAddressString, host->hostNumIpAddress, host->hostResolvedName, host->hostTrafficBucket);
#endif

  if(deleteAddressFromCache) {
    datum key_data;

    if(host->hostIpAddress.hostFamily == AF_INET) {
      key_data.dptr = (void*)&host->hostIpAddress.Ip4Address.s_addr;
      key_data.dsize = 4;
    }
#ifdef INET6
    else if(host->hostIpAddress.hostFamily == AF_INET6) {
      key_data.dptr = (void*)&host->hostIpAddress.Ip6Address.s6_addr;
      key_data.dsize = 16;
    }
#endif
    else
      key_data.dsize = 0;

    if(key_data.dsize) {
      gdbm_delete(myGlobals.addressQueueFile, key_data);
      
#ifdef DNS_DEBUG
      traceEvent(CONST_TRACE_INFO, "HOST_FREE_DEBUG: Deleting from GDBM address cache host [%s/%s]",
		 host->hostNumIpAddress, host->hostResolvedName);
#endif
    }
  }

  handlePluginHostCreationDeletion(host, 0 /* host deletion */);

  /* Make sure this host is not part of the ipTrafficMatrixHosts list */
  if((myGlobals.device[actualDeviceId].ipTrafficMatrix != NULL)
     && (myGlobals.device[actualDeviceId].numHosts > 0)
     && isMatrixHost(host, actualDeviceId)) {
    int id = matrixHostHash(host, actualDeviceId, 0);

    myGlobals.device[actualDeviceId].ipTrafficMatrixHosts[id] = NULL;

    for(i=0; i<myGlobals.device[actualDeviceId].numHosts-1; i++) {
      myGlobals.device[actualDeviceId].ipTrafficMatrix[id*myGlobals.device[actualDeviceId].numHosts+i] = NULL;
      myGlobals.device[actualDeviceId].ipTrafficMatrix[i*myGlobals.device[actualDeviceId].numHosts+id] = NULL;
    }
  }

  if(myGlobals.device[actualDeviceId].fcTrafficMatrix != NULL) {
      int id = matrixHostHash (host, actualDeviceId, 0);
      
      myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[id] = NULL;
      
      for(i=0; i<myGlobals.device[actualDeviceId].numHosts-1; i++) {
          myGlobals.device[actualDeviceId].fcTrafficMatrix[id*myGlobals.device[actualDeviceId].numHosts+i] = NULL;
          myGlobals.device[actualDeviceId].fcTrafficMatrix[i*myGlobals.device[actualDeviceId].numHosts+id] = NULL;
      }
  }
    
  freeHostSessions(host, actualDeviceId);

  if(host->fcCounters != NULL) {
    if(host->l2Family == FLAG_HOST_TRAFFIC_AF_FC) {
      for (i = 0; i < MAX_LUNS_SUPPORTED; i++) {
	if(host->fcCounters->activeLuns[i] != NULL) {
	  free(host->fcCounters->activeLuns[i]);
	}
      }
    }

    free(host->fcCounters);
  }

  myGlobals.device[actualDeviceId].hostsno--;

  if(host->protoIPTrafficInfos != NULL) {
    for(i=0; i<myGlobals.numIpProtosToMonitor; i++)
      if(host->protoIPTrafficInfos[i] != NULL) 
	free(host->protoIPTrafficInfos[i]);
    
    free(host->protoIPTrafficInfos);
  }

  if(host->ipProtosList != NULL) {
    for(i=0; i<myGlobals.numIpProtosList; i++)
      if(host->ipProtosList[i] != NULL) 
	free(host->ipProtosList[i]);
    
    free(host->ipProtosList);
  }

  if(host->nonIPTraffic) {
    if(host->nonIPTraffic->nbHostName != NULL)          free(host->nonIPTraffic->nbHostName);
    if(host->nonIPTraffic->nbAccountName != NULL)       free(host->nonIPTraffic->nbAccountName);
    if(host->nonIPTraffic->nbDomainName != NULL)        free(host->nonIPTraffic->nbDomainName);
    if(host->nonIPTraffic->nbDescr != NULL)             free(host->nonIPTraffic->nbDescr);
    if(host->nonIPTraffic->atNodeName != NULL)          free(host->nonIPTraffic->atNodeName);
    for(i=0; i<MAX_NODE_TYPES; i++)
      if(host->nonIPTraffic->atNodeType[i] != NULL) free(host->nonIPTraffic->atNodeType[i]);
    if(host->nonIPTraffic->atNodeName != NULL)          free(host->nonIPTraffic->atNodeName);
    if(host->nonIPTraffic->ipxHostName != NULL)         free(host->nonIPTraffic->ipxHostName);
    if(host->nonIPTraffic->unknownProtoSent   != NULL)  free(host->nonIPTraffic->unknownProtoSent);
    if(host->nonIPTraffic->unknownProtoRcvd   != NULL)  free(host->nonIPTraffic->unknownProtoRcvd);
    free(host->nonIPTraffic);
  }

  if(host->nonIpProtoTrafficInfos != NULL) {
    NonIpProtoTrafficInfo *list = host->nonIpProtoTrafficInfos;

    while(list != NULL) {
      NonIpProtoTrafficInfo *next = list->next;
      free(list);
      list = next;
    }
  }

  if(host->secHostPkts != NULL) {
    free(host->secHostPkts);
    host->secHostPkts = NULL; /* just to be safe in case of persistent storage */
  }

  if(host->fingerprint != NULL)
    free(host->fingerprint);

  if(host->routedTraffic != NULL) free(host->routedTraffic);

  if(host->portsUsage != NULL) {
    for(i=0; i<MAX_ASSIGNED_IP_PORTS; i++) {
      if(host->portsUsage[i] != NULL) {
	free(host->portsUsage[i]);
      }
    }

    free(host->portsUsage);
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
        if(list->userName != NULL)
          free(list->userName);
	free(list);
	list = next;
      }
    }

    if(host->protocolInfo->fileList != NULL) {
      FileList *list = host->protocolInfo->fileList;

      while(list != NULL) {
	FileList *next = list->next;
        if(list->fileName != NULL) 
          free(list->fileName);
	free(list);
	list = next;
      }
    }

    if(host->protocolInfo->dnsStats  != NULL) free(host->protocolInfo->dnsStats);
    if(host->protocolInfo->httpStats != NULL) free(host->protocolInfo->httpStats);
    if(host->protocolInfo->dhcpStats != NULL) free(host->protocolInfo->dhcpStats);
  }
  if(host->protocolInfo != NULL) free(host->protocolInfo);

  /* ************************************* */

  if(host->icmpInfo != NULL) free(host->icmpInfo);
  if(host->trafficDistribution != NULL) free(host->trafficDistribution);

  if(host->dnsDomainValue != NULL) free(host->dnsDomainValue);
  host->dnsDomainValue = NULL;
  if(host->dnsTLDValue != NULL) free(host->dnsTLDValue);
  host->dnsTLDValue = NULL;
  if(host->ip2ccValue != NULL) free(host->ip2ccValue);
  host->ip2ccValue = NULL;

  /* ********** */
  /*
    #ifdef HASH_DEBUG
    hostHashSanityCheck(host);
    #endif
  */

  /*
    Do not free the host pointer but add it to
    a list of 'ready to use' pointers.

    Memory Recycle
  */

#if RECYCLE_MEMORY
  if(myGlobals.hostsCacheLen < (MAX_HOSTS_CACHE_LEN-1)) {
    myGlobals.hostsCache[myGlobals.hostsCacheLen++] = host;
    if(myGlobals.hostsCacheLen > myGlobals.hostsCacheLenMax)
      myGlobals.hostsCacheLenMax = myGlobals.hostsCacheLen;
  } else
#endif
    {

#if(0)
/* Temporary code to see what's being covered up by the memset() below */
      char xbuf[1024];
      int ii;
      memset(xbuf, 0, sizeof(xbuf));
      safe_snprintf(__FILE__, __LINE__, xbuf, sizeof(xbuf), 
                  "TEMP: free of host (0x%08x) magic(%u) not cleared:", host, host->magic);
      ii=strlen(xbuf);
      if(host->dnsDomainValue != NULL)
        strncat(xbuf, " dnsDomainValue", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->dnsTLDValue != NULL)
        strncat(xbuf, " dnsTLDValue", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->ip2ccValue != NULL)
        strncat(xbuf, " ip2ccValue", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->fingerprint != NULL)
        strncat(xbuf, " fingerprint", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->nonIPTraffic != NULL)
        strncat(xbuf, " nonIPTraffic", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->nonIpProtoTrafficInfos != NULL)
        strncat(xbuf, " nonIpProtoTrafficInfos", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->trafficDistribution != NULL)
        strncat(xbuf, " trafficDistribution", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->routedTraffic != NULL)
        strncat(xbuf, " routedTraffic", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->portsUsage != NULL)
        strncat(xbuf, " portsUsage", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->protocolInfo != NULL)
        strncat(xbuf, " protocolInfo", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->secHostPkts != NULL)
        strncat(xbuf, " secHostPkts", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->icmpInfo != NULL)
        strncat(xbuf, " icmpInfo", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->ipProtosList != NULL)
        strncat(xbuf, " ipProtosList", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->protoIPTrafficInfos != NULL)
        strncat(xbuf, " protoIPTrafficInfos", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->unknownProtoSent != NULL)
        strncat(xbuf, " unknownProtoSent", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->unknownProtoRcvd != NULL)
        strncat(xbuf, " unknownProtoRcvd", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(host->next != NULL)
        strncat(xbuf, " next", (sizeof(xbuf) - strlen(xbuf) - 1));
      if(strlen(xbuf) != ii)
        traceEvent(CONST_TRACE_INFO, xbuf);
#endif

      /* No room left: it's time to free the bucket */
      memset(host, 0, sizeof(HostTraffic)); /* Debug code */
      free(host);      
   }

  myGlobals.numPurgedHosts++;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Leaving freeHostInfo()");
#endif
}

/* ************************************ */

/*
  This function is called before the final
  cleanup when ntop shutsdown
*/
void freeHostInstances(int actualDeviceId) {
  u_int idx, i, max, num=0;

  if(myGlobals.mergeInterfaces)
    max = 1;
  else
    max = myGlobals.numDevices;

  traceEvent(CONST_TRACE_INFO, "FREE_HOST: Start, %d device(s)", max);

  for(i=0; i<max; i++) {
    if(myGlobals.device[i].dummyDevice) {
      i++;
      if(i >= myGlobals.numDevices) break;
    }
    actualDeviceId = i;

#ifdef HASH_DEBUG
    hashSanityCheck();
#endif

    for(idx=FIRST_HOSTS_ENTRY; idx<myGlobals.device[actualDeviceId].actualHashSize; idx++) {
      HostTraffic *el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];

      while(el != NULL) {
	HostTraffic *nextEl = el->next;
	el->next = NULL;
	num++;
	freeHostInfo(el, actualDeviceId);
#ifdef MAKE_WITH_SCHED_YIELD
	sched_yield(); /* Allow other threads to run */
#endif
	el = nextEl;
      }

      myGlobals.device[actualDeviceId].hash_hostTraffic[idx] = NULL;
    } /* for */

#ifdef HASH_DEBUG
    hashSanityCheck();
#endif
  }

  traceEvent(CONST_TRACE_INFO, "FREE_HOST: End, freed %d", num);
}

/* ************************************ */

void purgeIdleHosts(int actDevice) {
  u_int idx, numFreedBuckets=0, numHosts = 0;
  time_t startTime = time(NULL), noSessionPurgeTime, withSessionPurgeTime;
  static time_t lastPurgeTime[MAX_NUM_DEVICES];
  static char firstRun = 1;
  HostTraffic **theFlaggedHosts = NULL;
  u_int maxHosts, scannedHosts=0;
  float hiresDeltaTime;
  struct timeval hiresTimeStart, hiresTimeEnd;
  HostTraffic *el, *prev, *next;

  if(myGlobals.rFileName != NULL) return;

#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: purgeIdleHosts() invoked");
#endif

  if(firstRun) {
    firstRun = 0;
    memset(lastPurgeTime, 0, sizeof(lastPurgeTime));
  }

  gettimeofday(&hiresTimeStart, NULL);

  if(startTime < (lastPurgeTime[actDevice]+PARM_HOST_PURGE_INTERVAL))
    return; /* Too short */
  else
    lastPurgeTime[actDevice] = startTime;

  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */
  theFlaggedHosts = (HostTraffic**)malloc(maxHosts*sizeof(HostTraffic*));
  memset(theFlaggedHosts, 0, maxHosts*sizeof(HostTraffic*));

  /* Time used to decide whether a host need to be purged */
  noSessionPurgeTime   = startTime-PARM_HOST_PURGE_MINIMUM_IDLE_NOACTVSES; 
  withSessionPurgeTime = startTime-PARM_HOST_PURGE_MINIMUM_IDLE_ACTVSES;

#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: Beginning noS < %d, wS < %d", noSessionPurgeTime, withSessionPurgeTime);
#endif

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.hostsHashMutex, "purgeIdleHosts");
#endif
  purgeOldFragmentEntries(actDevice); /* let's do this too */
#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.hostsHashMutex);
#endif

#ifdef CFG_MULTITHREADED
#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: accessMutex(purgeMutex)...calling");
#endif
  accessMutex(&myGlobals.purgeMutex, "purgeIdleHosts");
#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: accessMutex(purgeMutex)...locked");
#endif
#endif

#ifdef HASH_DEBUG
  hashSanityCheck();
#endif

  for(idx=0; idx<myGlobals.device[actDevice].actualHashSize; idx++) {
#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.hostsHashMutex, "scanIdleLoop");
#endif

    if((el = myGlobals.device[actDevice].hash_hostTraffic[idx]) != NULL) {
      prev = NULL;

      while(el) {
	if((el->refCount == 0) 
	   && (   ((el->numHostSessions == 0) && (el->lastSeen < noSessionPurgeTime))
	       || ((el->numHostSessions > 0)  && (el->lastSeen < withSessionPurgeTime)))
	   && (!broadcastHost(el))
	   && ((!myGlobals.stickyHosts)
	       || ((el->l2Family == FLAG_HOST_TRAFFIC_AF_ETH) &&
                   ((el->hostNumIpAddress[0] == '\0') /* Purge MAC addresses too */
                    || (!subnetPseudoLocalHost(el))))      /* Purge remote
                                                            * hosts only */
               || ((el->l2Family == FLAG_HOST_TRAFFIC_AF_FC) &&
                   (el->fcCounters->hostNumFcAddress[0] == '\0')))
            ) {
	  /* Host selected for deletion */
	  theFlaggedHosts[numHosts++] = el;
	  next = el->next;

	  if(prev != NULL)
	    prev->next = next;
	  else
	    myGlobals.device[actDevice].hash_hostTraffic[idx] = next;

          el->next = NULL;
	  el = next;
	} else {
	  /* Move to next host */
	  prev = el;
	  el = el->next;
	}

	scannedHosts++;
#ifdef MAX_HOSTS_PURGE_PER_CYCLE
	if(numHosts >= MAX_HOSTS_PURGE_PER_CYCLE) break;
#endif
	if(numHosts >= (maxHosts-1)) break;
      } /* while */

      if(numHosts >= (maxHosts-1)) {
#ifdef CFG_MULTITHREADED
        releaseMutex(&myGlobals.hostsHashMutex);
#endif
        break;
      }
    }
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.hostsHashMutex);
#endif
  }

#ifdef HASH_DEBUG
  hashSanityCheck();
#endif

#ifdef CFG_MULTITHREADED
#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: releaseMutex(purgeMutex)...calling");
#endif
  releaseMutex(&myGlobals.purgeMutex);
#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: releaseMutex(purgeMutex)...released");
#endif
#endif

  traceEvent(CONST_TRACE_NOISY, "IDLE_PURGE: FINISHED selection, %d [out of %d] hosts selected",
	     numHosts, scannedHosts);

  /* Now free the entries */
  for(idx=0; idx<numHosts; idx++) {
#ifdef IDLE_PURGE_DEBUG
    traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: Purging host %d [last seen=%d]... %s",
	       idx, theFlaggedHosts[idx]->lastSeen, theFlaggedHosts[idx]->hostResolvedName);
#endif
    freeHostInfo(theFlaggedHosts[idx], actDevice);
    numFreedBuckets++;
#ifdef MAKE_WITH_SCHED_YIELD
    sched_yield(); /* Allow other threads to run */
#endif
  }

  free(theFlaggedHosts);

  if(myGlobals.enableSessionHandling)
    scanTimedoutTCPSessions(actDevice); /* let's check timedout sessions too */

  gettimeofday(&hiresTimeEnd, NULL);
  hiresDeltaTime = timeval_subtract(hiresTimeEnd, hiresTimeStart);

  if(numFreedBuckets > 0)
    traceEvent(CONST_TRACE_NOISY, 
	       "IDLE_PURGE: Device %d [%s]: %d hosts deleted, elapsed time is %.6f seconds (%.6f per host)",
	       actDevice,
	       myGlobals.device[actDevice].name,
	       numFreedBuckets,
	       hiresDeltaTime,
	       hiresDeltaTime / numFreedBuckets);
  else
    traceEvent(CONST_TRACE_NOISY, "IDLE_PURGE: Device %d: no hosts deleted", actDevice);
}

/* **************************************************** */

void setHostSerial(HostTraffic *el) {
  /* Nothing to do */
  if(el->hostSerial.serialType != SERIAL_NONE)
    return;

  if(isFcHost(el)) {
    if(el->fcCounters->hostNumFcAddress[0] != '\0') {
      el->hostSerial.serialType = SERIAL_FC;
      el->hostSerial.value.fcSerial.fcAddress.domain = el->fcCounters->hostFcAddress.domain;
      el->hostSerial.value.fcSerial.fcAddress.area = el->fcCounters->hostFcAddress.area;
      el->hostSerial.value.fcSerial.fcAddress.port = el->fcCounters->hostFcAddress.port;
      el->hostSerial.value.fcSerial.vsanId = el->fcCounters->vsanId;
    }
    else
      traceEvent (CONST_TRACE_ERROR, "setHostSerial: Received NULL FC Address entry");
  }
  else if(el->hostNumIpAddress[0] == '\0') {
    el->hostSerial.serialType = SERIAL_MAC;
    memcpy(&el->hostSerial.value.ethSerial.ethAddress, el->ethAddress, LEN_ETHERNET_ADDRESS);
    el->hostSerial.value.ethSerial.vlanId = el->vlanId;
  } else {
    if(el->hostIpAddress.hostFamily == AF_INET){
      el->hostSerial.serialType = SERIAL_IPV4;
    } else if(el->hostIpAddress.hostFamily == AF_INET6){
      el->hostSerial.serialType = SERIAL_IPV6;
    }

    addrcpy(&el->hostSerial.value.ipSerial.ipAddress, &el->hostIpAddress);
    el->hostSerial.value.ipSerial.vlanId = el->vlanId;
  }
}

/* ********************************************************* */

/*
  Searches a host and returns it. If the host is not
  present in the hash a new bucket is created
*/
HostTraffic* lookupHost(HostAddr *hostIpAddress, u_char *ether_addr, short vlanId,
			u_char checkForMultihoming, u_char forceUsingIPaddress,
			int actualDeviceId) {
  u_int idx, isMultihomed = 0;
#ifndef CFG_MULTITHREADED
  u_int run=0;
#endif
  HostTraffic *el=NULL;
  u_char buf[MAX_LEN_SYM_HOST_NAME_HTML];
  short useIPAddressForSearching = forceUsingIPaddress;
  char* symEthName = NULL, *ethAddr;
  u_char setSpoofingFlag = 0;
  u_short numRuns=0;
  u_int hostFound = 0;
  u_int updateIPinfo = 0;

  if((hostIpAddress == NULL) && (ether_addr == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "Both Ethernet and IP addresses are NULL");
    return(NULL);
  }

#ifdef DEBUG 
  traceEvent(CONST_TRACE_NOISY, "DEBUG: lookupHost(%s, %s, m=%u, f=%u, dev=%d, vlan=%d)",
             addrtostr(hostIpAddress),
             etheraddr_string(ether_addr, buf),
             checkForMultihoming, forceUsingIPaddress, actualDeviceId, vlanId);
#endif

#ifdef HASH_DEBUG
  hashSanityCheck();
#endif

  idx = hashHost(hostIpAddress, ether_addr,
		 &useIPAddressForSearching,
		 &el, actualDeviceId);

  /* Remember the side effect of above routine - if -o | --no-mac is set,\
   * useIPAddressForSearching is now 1
   */

  /* If we found it or had an error */
  if(el != NULL)
    return(el); /* Found */
  else if(idx == FLAG_NO_PEER)
    return(NULL);
  else
    el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];

  while (el != NULL) {
    if(el->magic != CONST_MAGIC_NUMBER) {
      traceEvent(CONST_TRACE_WARNING, "Error: bad magic number (expected=%d/real=%d) [deviceId=%d]",
		 CONST_MAGIC_NUMBER, el->magic, actualDeviceId);
    }

    if(el->hostTrafficBucket != idx) {
      traceEvent(CONST_TRACE_WARNING, "Error: wrong bucketIdx %s/%s (expected=%d/real=%d) [deviceId=%d]",
		 el->ethAddressString, el->hostNumIpAddress,
		 idx, el->hostTrafficBucket, actualDeviceId);
    }

    if(vlanId == el->vlanId) {
      if(useIPAddressForSearching == 0) {
	/* compare with the ethernet-address then the IP address */
	if(memcmp(el->ethAddress, ether_addr, LEN_ETHERNET_ADDRESS) == 0) {
	  if((hostIpAddress != NULL) && 
	     (hostIpAddress->hostFamily == el->hostIpAddress.hostFamily)) {
	    if((!isMultihomed) && checkForMultihoming) {
	      /* This is a local address hence this is a potential multihomed host. */

	      if(!(addrnull(&el->hostIpAddress))
		 && (addrcmp(&el->hostIpAddress,hostIpAddress) != 0)) {
		isMultihomed = 1;
		FD_SET(FLAG_HOST_TYPE_MULTIHOMED, &el->flags);
	      } else {
		updateIPinfo = 1;
	      }
	    }
	    hostFound = 1;
	    break;	
	  } else if(hostIpAddress == NULL){  /* Only Mac Addresses */
	    hostFound = 1;
	    break;
	  } else { /* MAC match found and we have the IP - need to update... */
	    updateIPinfo = 1;
	    hostFound = 1;
	    break;
	  }
	} else if((hostIpAddress != NULL)
		  && (addrcmp(&el->hostIpAddress, hostIpAddress) == 0)) {
	  /* Spoofing or duplicated MAC address:
	     two hosts with the same IP address and different MAC
	     addresses
	  */

	  if(!hasDuplicatedMac(el)) {
	    FD_SET(FLAG_HOST_DUPLICATED_MAC, &el->flags);

	    if(myGlobals.enableSuspiciousPacketDump) {
	      char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

	      traceEvent(CONST_TRACE_WARNING,
			 "Two MAC addresses found for the same IP address "
			 "%s: [%s/%s] (spoofing detected?)",
			 el->hostNumIpAddress,
			 etheraddr_string(ether_addr, etherbuf), el->ethAddressString);
	      dumpSuspiciousPacket(actualDeviceId);
	    }
	  }

	  setSpoofingFlag = 1;
	  hostFound = 1;
	  break;
	}
      } else {
	/* -o | --no-mac (or NetFlow, which doesn't have MACs) - compare with only the IP address */
	if(addrcmp(&el->hostIpAddress, hostIpAddress) == 0) {
	  hostFound = 1;
	  break;
	}
      }
    }

    el = el->next;
    numRuns++;
  } /* while */

  if(numRuns > myGlobals.device[actualDeviceId].hashListMaxLookups)
    myGlobals.device[actualDeviceId].hashListMaxLookups = numRuns ;

  if(hostFound) {
    /* Existing host entry */
    if((updateIPinfo == 1) &&
       (el->hostNumIpAddress[0] == '\0')) {
      /* This entry didn't have IP fields set: let's set them now */
      addrcpy(&el->hostIpAddress, hostIpAddress);
      strncpy(el->hostNumIpAddress,
              _addrtostr(hostIpAddress, buf, sizeof(buf)),
              sizeof(el->hostNumIpAddress));
      setResolvedName(el, el->hostNumIpAddress, FLAG_HOST_SYM_ADDR_TYPE_IP);
  
      if(myGlobals.numericFlag == 0)
        ipaddr2str(el->hostIpAddress, 1);

      if(isBroadcastAddress(&el->hostIpAddress))
        FD_SET(FLAG_BROADCAST_HOST, &el->flags);
    }

  } else {
    /* New host entry */
    int len;

    if(myGlobals.device[actualDeviceId].hostsno >= myGlobals.maxNumHashEntries) {
      static char messageShown = 0;

      if(!messageShown) {
	messageShown = 1;
	traceEvent(CONST_TRACE_INFO, "WARNING: Max num hash entries (%u) reached (see -x)", 
		   myGlobals.maxNumHashEntries);
      }
      
      return(NULL);
    }

#if RECYCLE_MEMORY
    if(myGlobals.hostsCacheLen > 0) {
      el = myGlobals.hostsCache[--myGlobals.hostsCacheLen];
      myGlobals.hostsCacheReused++;
      /*
	traceEvent(CONST_TRACE_INFO, "Fetched host from pointers cache (len=%d)",
	(int)myGlobals.hostsCacheLen);
      */
    } else
#endif
      {
	if((el = (HostTraffic*)malloc(sizeof(HostTraffic))) == NULL)
	  return(NULL);
      }

    memset(el, 0, sizeof(HostTraffic));
    el->firstSeen = myGlobals.actTime;

    resetHostsVariables(el);
    el->vlanId = vlanId;

    if(isMultihomed)
      FD_SET(FLAG_HOST_TYPE_MULTIHOMED, &el->flags);

    el->portsUsage = (PortUsage**)calloc(sizeof(PortUsage*), MAX_ASSIGNED_IP_PORTS);

    len = (size_t)myGlobals.numIpProtosList*sizeof(ShortProtoTrafficInfo**);
    if((el->ipProtosList = (ShortProtoTrafficInfo**)malloc(len)) == NULL) return(NULL);
    memset(el->ipProtosList, 0, len);
    
    len = (size_t)myGlobals.numIpProtosToMonitor*sizeof(ProtoTrafficInfo**);
    if((el->protoIPTrafficInfos = (ProtoTrafficInfo**)malloc(len)) == NULL) return(NULL);
    memset(el->protoIPTrafficInfos, 0, len);

    el->magic = CONST_MAGIC_NUMBER;
    el->hostTrafficBucket = idx; /* Set the bucket index */
    el->originalHostTrafficBucket = idx; /* Set the bucket index */

    /* traceEvent(CONST_TRACE_INFO, "new entry added at bucket %d", idx); */

    /* Put the new entry on top of the list */
    el->next = myGlobals.device[actualDeviceId].hash_hostTraffic[el->hostTrafficBucket];
    myGlobals.device[actualDeviceId].hash_hostTraffic[el->hostTrafficBucket] = el;  /* Insert a new entry */
    myGlobals.device[actualDeviceId].hostsno++;

    if(ether_addr != NULL) {
      if((hostIpAddress == NULL)
	 || ((hostIpAddress != NULL)
	     && isPseudoLocalAddress(hostIpAddress, actualDeviceId)
	     /* && (!isBroadcastAddress(hostIpAddress))*/
	     )) {
	char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

	/* This is a local address and then the
	   ethernet address does make sense */
	ethAddr = etheraddr_string(ether_addr, etherbuf);

	memcpy(el->ethAddress, ether_addr, LEN_ETHERNET_ADDRESS);
	strncpy(el->ethAddressString, ethAddr, sizeof(el->ethAddressString));
	symEthName = getSpecialMacInfo(el, (short)(!myGlobals.separator[0]));
	FD_SET(FLAG_SUBNET_LOCALHOST, &el->flags);
	FD_SET(FLAG_SUBNET_PSEUDO_LOCALHOST, &el->flags);
      } else if(hostIpAddress != NULL) {
	/* This is packet that's being routed or belonging to a
	   remote network that uses the same physical wire (or forged)*/
	memcpy(el->lastEthAddress, ether_addr, LEN_ETHERNET_ADDRESS);

	if(hostIpAddress != NULL) {
	  if(hostIpAddress->hostFamily == AF_INET)
	    memcpy(el->ethAddress, &hostIpAddress->Ip4Address.s_addr, 4); /* Dummy/unique eth address */
#ifdef INET6
	  else if(hostIpAddress->hostFamily == AF_INET6)
	    memcpy(el->ethAddress, &hostIpAddress->Ip6Address.s6_addr[8], 4);
#endif
	  
	  FD_CLR(FLAG_SUBNET_LOCALHOST, &el->flags);
	  
	  if(isPrivateAddress(hostIpAddress)) FD_SET(FLAG_PRIVATE_IP_ADDRESS, &el->flags);
	  
	  if(!isBroadcastAddress(hostIpAddress)) {
	    if(isPseudoLocalAddress(hostIpAddress, actualDeviceId))
	      FD_SET(FLAG_SUBNET_PSEUDO_LOCALHOST, &el->flags);
	    else
	      FD_CLR(FLAG_SUBNET_PSEUDO_LOCALHOST, &el->flags);
	  }
	}
      } else {
	FD_CLR(FLAG_SUBNET_LOCALHOST, &el->flags);
	FD_CLR(FLAG_SUBNET_PSEUDO_LOCALHOST, &el->flags);
      }

      if(strncmp(el->ethAddressString, "FF:", 3) == 0) {
	/*
	  The trick below allows me not to duplicate the
	  "<broadcast>" string in the code
	*/
	
	if(hostIpAddress != NULL) {
	  if(hostIpAddress->hostFamily == AF_INET)
	    el->hostIp4Address.s_addr = INADDR_BROADCAST;
#ifdef INET6
	  else if(hostIpAddress->hostFamily == AF_INET6)
	    el->hostIp6Address = _in6addr_linklocal_allnodes;
#endif
	}

	FD_SET(FLAG_BROADCAST_HOST, &el->flags);
	if(isMulticastAddress(&el->hostIpAddress))
	  FD_SET(FLAG_MULTICAST_HOST, &el->flags);
	strncpy(el->hostNumIpAddress,
		_addrtostr(&el->hostIpAddress, buf, sizeof(buf)),
		strlen(el->hostNumIpAddress));
        setResolvedName(el, el->hostNumIpAddress, FLAG_HOST_SYM_ADDR_TYPE_IP);

	if((!addrnull(&el->hostIpAddress)) /* 0.0.0.0 */
	   && (!addrfull(&el->hostIpAddress)) /* 255.255.255.255 */
	   && isBroadcastAddress(&el->hostIpAddress)) {
	  /*
	    The sender of this packet has obviously a wrong netmask because:
	    - it is a local host
	    - it has sent a packet to a broadcast address
	    - it has not used the FF:FF:FF:FF:FF:FF MAC address
	  */

	  traceEvent(CONST_TRACE_WARNING, "Wrong netmask detected [%s/%s]",
		     _addrtostr(&el->hostIpAddress, buf, sizeof(buf)),
		     el->ethAddressString);
	}
      }

#ifdef DEBUG
      {
	char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

	/*
	  if((strcmp(etheraddr_string(ether_addr, etherbuf), "08:00:20:89:79:D7") == 0)
	  || (strcmp(el->hostResolvedName, "more") == 0))
	*/
	printf("Added a new hash_hostTraffic entry [%s/%s/%s/%d][idx=%d]\n",
	       etheraddr_string(ether_addr, etherbuf), el->hostResolvedName,
	       el->hostNumIpAddress, myGlobals.device[actualDeviceId].hostsno, idx);
      }
#endif

      el->lastSeen = myGlobals.actTime;

      if(myGlobals.enableSuspiciousPacketDump)
	checkSpoofing(el, actualDeviceId);
    }

    if(hostIpAddress != NULL) {
      if(myGlobals.dontTrustMACaddr && (ether_addr != NULL))
	memcpy(el->lastEthAddress, ether_addr, LEN_ETHERNET_ADDRESS);

      addrcpy(&el->hostIpAddress,hostIpAddress);
      strncpy(el->hostNumIpAddress,
	      _addrtostr(hostIpAddress, buf, sizeof(buf)),
	      sizeof(el->hostNumIpAddress));
      if(isBroadcastAddress(&el->hostIpAddress)) FD_SET(FLAG_BROADCAST_HOST, &el->flags);
      if(isMulticastAddress(&el->hostIpAddress)) FD_SET(FLAG_MULTICAST_HOST, &el->flags);
      if(isPrivateAddress(hostIpAddress))        FD_SET(FLAG_PRIVATE_IP_ADDRESS,  &el->flags);
      if((ether_addr == NULL) && (isPseudoLocalAddress(hostIpAddress, actualDeviceId)))
	FD_SET(FLAG_SUBNET_PSEUDO_LOCALHOST, &el->flags);

      setResolvedName(el, el->hostNumIpAddress, FLAG_HOST_SYM_ADDR_TYPE_IP);

      /* Trick to fill up the address cache */
      if(myGlobals.numericFlag == 0)
	ipaddr2str(el->hostIpAddress, 1);

    } else {
      /* This is a new entry and hostIpAddress was NOT set.  Fill in MAC address, if we have it */
      if(symEthName[0] != '\0') {
        /* This is a local address so we have the MAC address */
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s%s", symEthName, &el->ethAddressString[8]);

	buf[MAX_LEN_SYM_HOST_NAME-1] = '\0';
        setResolvedName(el, buf, FLAG_HOST_SYM_ADDR_TYPE_MAC);
      }
    }

#ifdef HASH_DEBUG
      traceEvent(CONST_TRACE_INFO, "HASH_DEBUG: Adding %s/%s [idx=%d][device=%d][actualHashSize=%d][#hosts=%d]",
		 el->ethAddressString, el->hostNumIpAddress, idx, actualDeviceId,
		 myGlobals.device[actualDeviceId].actualHashSize, myGlobals.device[actualDeviceId].hostsno);
#endif

    setHostSerial(el);
    handlePluginHostCreationDeletion(el, 1 /* host creation */);
  }


  if(el != NULL) {
    el->lastSeen = myGlobals.actTime;

    if(setSpoofingFlag)
      FD_SET(FLAG_HOST_DUPLICATED_MAC, &el->flags);

#ifdef DEBUG
    {
      if((hostIpAddress != NULL) && (hostIpAddress->hostFamily == AF_INET6)){
	char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];
	traceEvent(CONST_TRACE_INFO, "lookupHost(idx=%d/actualDeviceId=%d) [%s/%s/%s/%d/%d]",
		   idx, actualDeviceId,
		   etheraddr_string(ether_addr, etherbuf), el->hostResolvedName,
		   el->hostNumIpAddress, myGlobals.device[actualDeviceId].hostsno,
		   useIPAddressForSearching);
      }
    }
#endif
  }

#ifdef DEBUG
  if(el == NULL)
    traceEvent(CONST_TRACE_INFO, "lookupHost(idx=%d) is NULL", idx);
#endif

#ifdef HASH_DEBUG
  hashSanityCheck();
#endif

  return(el);
}

HostTraffic *lookupFcHost (FcAddress *hostFcAddress, u_short vsanId,
                           int actualDeviceId)
{
    u_int idx;
#ifndef CFG_MULTITHREADED
    u_int run=0;
#endif
    HostTraffic *el=NULL;
    FcNameServerCacheEntry *fcnsEntry;
    u_short numRuns=0;
    u_int hostFound = 0;

    if(hostFcAddress == NULL) {
        traceEvent(CONST_TRACE_ERROR, "lookupFcHost: Call invoked with NULL"
                   "FC Address, vsan = %d, device = %d", vsanId,
                   actualDeviceId);
        return(NULL);
    }

    idx = hashFcHost (hostFcAddress, vsanId, &el, actualDeviceId);

    if(el != NULL) {
        return (el);
    }
    else if(idx == FLAG_NO_PEER)
        return(NULL);
    else
        el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];


    hostFound = 0;  /* This is the same type as the one of HashList */
    
    while(el != NULL) {
        if(el->magic != CONST_MAGIC_NUMBER) {
            traceEvent(CONST_TRACE_WARNING, "Error: bad magic number (expected=%d/real=%d)",
                       CONST_MAGIC_NUMBER, el->magic);
        }
      
        if(el->hostTrafficBucket != idx) {
            traceEvent(CONST_TRACE_WARNING, "Error: wrong bucketIdx %s/%s (expected=%d/real=%d)",
                       el->ethAddressString, el->hostNumIpAddress,
                       idx, el->hostTrafficBucket);
        }
      
        if ((el->fcCounters != NULL) &&
            (memcmp ((u_int8_t *)&(el->fcCounters->hostFcAddress), hostFcAddress, LEN_FC_ADDRESS) == 0)) {
            hostFound = 1;
            break;
        }

        el = el->next;
        numRuns++;
    }
        
  if(numRuns > myGlobals.device[actualDeviceId].hashListMaxLookups) {
      myGlobals.device[actualDeviceId].hashListMaxLookups = numRuns ;
  }

  if(!hostFound) {
      /* New host entry */
      
    if(myGlobals.device[actualDeviceId].hostsno >= myGlobals.maxNumHashEntries) {
      static char messageShown = 0;

      if(!messageShown) {
	messageShown = 1;
	traceEvent(CONST_TRACE_INFO, "WARNING: Max num hash entries (%u) reached (see -x)", 
		   myGlobals.maxNumHashEntries);
      }
      
      return(NULL);
    }
    
#if RECYCLE_MEMORY
    if(myGlobals.hostsCacheLen > 0) {
      el = myGlobals.hostsCache[--myGlobals.hostsCacheLen];
      myGlobals.hostsCacheReused++;
      /*
	traceEvent(CONST_TRACE_INFO, "Fetched host from pointers cache (len=%d)",
	(int)myGlobals.hostsCacheLen);
      */
    } else
#endif
    {
      if((el = (HostTraffic*)malloc(sizeof(HostTraffic))) == NULL) 
	return(NULL);
    }
        
    memset(el, 0, sizeof(HostTraffic));
    el->firstSeen = myGlobals.actTime;

    resetHostsVariables(el);
        
    if(allocFcScsiCounters(el) == NULL) return(NULL);
    el->l2Family = FLAG_HOST_TRAFFIC_AF_FC;
    el->fcCounters->devType = SCSI_DEV_UNINIT;
    el->magic = CONST_MAGIC_NUMBER;
    el->hostTrafficBucket = idx;
      
    el->next = myGlobals.device[actualDeviceId].hash_hostTraffic[el->hostTrafficBucket];
    myGlobals.device[actualDeviceId].hash_hostTraffic[el->hostTrafficBucket] = el;  /* Insert a new entry */
    myGlobals.device[actualDeviceId].hostsno++;

    el->fcCounters->hostFcAddress.domain = hostFcAddress->domain;
    el->fcCounters->hostFcAddress.area = hostFcAddress->area;
    el->fcCounters->hostFcAddress.port = hostFcAddress->port;
    safe_snprintf(__FILE__, __LINE__, el->fcCounters->hostNumFcAddress, sizeof(el->fcCounters->hostNumFcAddress),
                  fc_to_str ((u_int8_t *)hostFcAddress));
    /* TBD: Resolve FC_ID to WWN */
    el->fcCounters->vsanId = vsanId;

    /* If there is a cache entry, use it */
    if((fcnsEntry = findFcHostNSCacheEntry (&el->fcCounters->hostFcAddress, vsanId)) != NULL) {
      if(fcnsEntry->alias != NULL)
	setResolvedName(el, fcnsEntry->alias, FLAG_HOST_SYM_ADDR_TYPE_FC_ALIAS);
      else
	setResolvedName(el, fcnsEntry->pWWN.str, FLAG_HOST_SYM_ADDR_TYPE_FC_WWN);
      
        memcpy (el->fcCounters->pWWN.str, fcnsEntry->pWWN.str, LEN_WWN_ADDRESS);
        memcpy (el->fcCounters->nWWN.str, fcnsEntry->nWWN.str, LEN_WWN_ADDRESS);
    }
    else {
        setResolvedName(el, el->fcCounters->hostNumFcAddress, FLAG_HOST_SYM_ADDR_TYPE_FCID);
    }
    
#ifdef HASH_DEBUG
    traceEvent(CONST_TRACE_INFO, "HASH_DEBUG: Adding %s/%s [idx=%d][device=%d][actualHashSize=%d][#hosts=%d]",
               el->ethAddressString, el->hostNumIpAddress, list->idx, actualDeviceId,
               myGlobals.device[actualDeviceId].actualHashSize, myGlobals.device[actualDeviceId].hostsno);
#endif
    setHostSerial(el);
  }
  
  if(el != NULL) {
      el->lastSeen = myGlobals.actTime;
  }

  if(el == NULL)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "getHostInfo(idx=%d)(ptr=%x)",
                 idx, (void*)myGlobals.device[actualDeviceId].hash_hostTraffic[idx]);
  
#ifdef HASH_DEBUG
  hashSanityCheck();
#endif

  return(el);
}

/* ************************************ */

#ifdef HASH_DEBUG

static void dumpHash() {
  int i=0;
  HostTraffic *el;

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    traceEvent(CONST_TRACE_INFO, "HASH_DEBUG: (%3d) %s / %s [bkt=%d][orig bkt=%d][next=0x%X]",
	       i++, el->ethAddressString, el->hostNumIpAddress,
	       el->hostTrafficBucket, el->originalHostTrafficBucket,
	       el->next);
  }
}

/* ***************************************** */

static void hashSanityCheck() {
  int i=0;

  for(i=FIRST_HOSTS_ENTRY; i<myGlobals.device[0].actualHashSize; i++) {
    HostTraffic *el = myGlobals.device[0].hash_hostTraffic[i];

    while(el != NULL) {
      if(el->hostTrafficBucket != i)
	traceEvent(CONST_TRACE_ERROR, "HASH: (%3d) %s / %s [bkt=%d][orig bkt=%d][next=0x%X]",
		   i, el->ethAddressString, el->hostNumIpAddress,
		   el->hostTrafficBucket, el->originalHostTrafficBucket,
		   el->next);
      el = el->next;
    }
  }
}

/* ***************************************** */

static void hostHashSanityCheck(HostTraffic *host) {
  int i=0;

  for(i=FIRST_HOSTS_ENTRY; i<myGlobals.device[0].actualHashSize; i++) {
    HostTraffic *el = myGlobals.device[0].hash_hostTraffic[i];

    while(el != NULL) {
      if(el == host)
	traceEvent(CONST_TRACE_ERROR, "HOST HASH: (%3d) %s / %s [bkt=%d][orig bkt=%d][next=0x%X]",
		   i, el->ethAddressString, el->hostNumIpAddress,
		   el->hostTrafficBucket, el->originalHostTrafficBucket,
		   el->next);
      el = el->next;
    }
  }
}

#endif /* HASH_DEBUG */

