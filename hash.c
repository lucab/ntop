/*
 *  Copyright (C) 1998-2011 Luca Deri <deri@ntop.org>
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

static u_int sec_idle_with_no_sessions, sec_idle_with_sessions;

/* ******************************* */

u_int hashHost(HostAddr *hostIpAddress,  u_char *ether_addr,
	       short* useIPAddressForSearching, HostTraffic **el,
	       int actualDeviceId) {
  u_int idx = 0;
  *el = NULL;

  if(myGlobals.runningPref.dontTrustMACaddr)  /* MAC addresses don't make sense here */
    (*useIPAddressForSearching) = 1;

  if((*useIPAddressForSearching) && (hostIpAddress == NULL)) {
#if 0
    traceEvent(CONST_TRACE_WARNING, "Index calculation problem (hostIpAddress=%x, ether_addr=%x)",
	       hostIpAddress, ether_addr);
#endif
    return(FLAG_NO_PEER);
  }

  if(((*useIPAddressForSearching) == 1) || ((ether_addr == NULL) && (hostIpAddress != NULL))) {
    if(myGlobals.runningPref.trackOnlyLocalHosts
       && (!isLocalAddress(hostIpAddress, actualDeviceId, NULL, NULL))
       && (!_pseudoLocalAddress(hostIpAddress, NULL, NULL))) {
      *el = myGlobals.otherHostEntry;
      return(OTHER_HOSTS_ENTRY);
    } else {
      /* idx = hostIpAddress->s_addr; */
      if(hostIpAddress->hostFamily == AF_INET)
	idx = (hostIpAddress->Ip4Address.s_addr & 0xffff)
	  ^ ((hostIpAddress->Ip4Address.s_addr >> 15) & 0xffff);
      else if(hostIpAddress->hostFamily == AF_INET6)
	idx = in6_hash(&hostIpAddress->Ip6Address);
    }

    (*useIPAddressForSearching) = 1;
  } else if(memcmp(ether_addr, myGlobals.broadcastEntry->ethAddress, LEN_ETHERNET_ADDRESS) == 0) {
    *el = myGlobals.broadcastEntry;
    return(BROADCAST_HOSTS_ENTRY);
  } else if((hostIpAddress == NULL)
	    || isPseudoLocalAddress(hostIpAddress, actualDeviceId, NULL, NULL)) {
    memcpy(&idx, &ether_addr[LEN_ETHERNET_ADDRESS-sizeof(u_int)], sizeof(u_int));
    (*useIPAddressForSearching) = 0;
  } else if(isBroadcastAddress(hostIpAddress, NULL, NULL)) {
    *el = myGlobals.broadcastEntry;
    return(BROADCAST_HOSTS_ENTRY);
  } else {
    if(hostIpAddress != NULL) {
      if(myGlobals.runningPref.trackOnlyLocalHosts
	 && (!isPseudoLocalAddress(hostIpAddress, actualDeviceId, NULL, NULL))) {
	*el = myGlobals.otherHostEntry;
	return(OTHER_HOSTS_ENTRY);
      } else {
	/* idx = hostIpAddress->s_addr; */
	if(hostIpAddress->hostFamily == AF_INET)
	  idx = (hostIpAddress->Ip4Address.s_addr & 0xffff) ^ ((hostIpAddress->Ip4Address.s_addr >> 15) & 0xffff);
	else if(hostIpAddress->hostFamily == AF_INET6)
	  idx = in6_hash(&hostIpAddress->Ip6Address);
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

  return(idx);
}

/* **************************************** */

void freeHostInfo(HostTraffic *host, int actualDeviceId) {
  u_int i, deleteAddressFromCache = 1;

  if(host == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Attempting to call freeHostInfo(NULL)");
    return;
  } else
    notifyEvent(hostDeletion, host, NULL, 0);

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

  if((host->magic != CONST_MAGIC_NUMBER) && (host->magic != CONST_UNMAGIC_NUMBER)) {
    traceEvent(CONST_TRACE_ERROR, "Bad magic number (expected=%d/real=%d) freeHostInfo()",
	       CONST_MAGIC_NUMBER, host->magic);
    return;
  }

  /* Flag that this entry is being deleted. */
  host->magic = CONST_UNMAGIC_NUMBER;

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
    } else if(host->hostIpAddress.hostFamily == AF_INET6) {
      key_data.dptr = (void*)&host->hostIpAddress.Ip6Address.s6_addr;
      key_data.dsize = 16;
    }
    else
      key_data.dsize = 0;
  }

  handlePluginHostCreationDeletion(host, (u_short)actualDeviceId, 0 /* host deletion */);

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

  if(host->portsUsage != NULL) freePortsUsage(host);

  if(myGlobals.runningPref.enablePacketDecoding && (host->protocolInfo != NULL)) {
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

    if(host->protocolInfo->dnsStats  != NULL) free(host->protocolInfo->dnsStats);
    if(host->protocolInfo->httpStats != NULL) free(host->protocolInfo->httpStats);
    if(host->protocolInfo->dhcpStats != NULL) free(host->protocolInfo->dhcpStats);
  }
  if(host->protocolInfo != NULL) free(host->protocolInfo);

  /* ************************************* */

  if(host->icmpInfo != NULL) free(host->icmpInfo);
  if(host->trafficDistribution != NULL) free(host->trafficDistribution);
  if(host->clientDelay != NULL) free(host->clientDelay);
  if(host->serverDelay != NULL) free(host->serverDelay);
  if(host->dnsDomainValue != NULL) free(host->dnsDomainValue);
  host->dnsDomainValue = NULL;
  if(host->dnsTLDValue != NULL) free(host->dnsTLDValue);
  host->dnsTLDValue = NULL;
  if(host->hostASDescr != NULL) free(host->hostASDescr);
  if(host->description != NULL) free(host->description);
  if(host->hwModel != NULL) free(host->hwModel);
  if(host->community != NULL) free(host->community);
  if(host->geo_ip) GeoIPRecord_delete(host->geo_ip);

  /* ********** */
  /*
    #ifdef HASH_DEBUG
    hostHashSanityCheck(host);
    #endif
  */

  memset(host, 0, sizeof(HostTraffic)); /* Debug code */
  free(host);

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

  if(myGlobals.runningPref.mergeInterfaces)
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

    if(myGlobals.ntopRunState >= FLAG_NTOPSTATE_SHUTDOWN) break;

      while(el != NULL) {
	HostTraffic *nextEl = el->next;
	el->next = NULL;
	num++;
	freeHostInfo(el, actualDeviceId);
	ntop_conditional_sched_yield(); /* Allow other threads to run */
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

void readSessionPurgeParams() {
  char buf[32], *key;

  key = "purge_host.seconds_idle_with_no_sessions";
  if(fetchPrefsValue(key, buf, sizeof(buf)) == 0) {
    sec_idle_with_no_sessions = atoi(buf);
  } else {
    sec_idle_with_no_sessions = PARM_HOST_PURGE_MINIMUM_IDLE_NOACTVSES;
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%u", sec_idle_with_no_sessions);
    storePrefsValue(key, buf);
  }

  key = "purge_host.seconds_idle_with_sessions";
  if(fetchPrefsValue(key, buf, sizeof(buf)) == 0) {
    sec_idle_with_sessions = atoi(buf);
  } else {
    sec_idle_with_sessions = PARM_HOST_PURGE_MINIMUM_IDLE_ACTVSES;
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%u", sec_idle_with_sessions);
    storePrefsValue(key, buf);
  }
}

/* ************************************ */

int is_host_ready_to_purge(int actDevice, HostTraffic *el, time_t now) {
  /* Time used to decide whether a host need to be purged */
  time_t noSessionPurgeTime   = now-sec_idle_with_no_sessions;
  time_t withSessionPurgeTime = now-sec_idle_with_sessions;

  if(el->to_be_deleted
     || ((myGlobals.pcap_file_list == NULL)
	 && (el->refCount == 0)
	 && ((((el->numHostSessions == 0) && (el->lastSeen < noSessionPurgeTime))
	      || ((el->numHostSessions > 0)  && (el->lastSeen < withSessionPurgeTime))))
	 && (!broadcastHost(el)) && (el != myGlobals.otherHostEntry)
	 && (myGlobals.device[actDevice].virtualDevice /* e.g. sFlow/NetFlow */
	     || (!myGlobals.runningPref.stickyHosts)
	     || (((el->hostNumIpAddress[0] == '\0') /* Purge MAC addresses too */
		  || (!subnetPseudoLocalHost(el)))) /* Purge remote hosts only */
	     )
	 )
     )
    return(1);
  else
    return(0);
}

/* ************************************ */

int purgeIdleHosts(int actDevice) {
  u_int idx, numFreedBuckets=0, numHosts = 0;
  time_t now = time(NULL);
  static time_t lastPurgeTime[MAX_NUM_DEVICES];
  static char firstRun = 1;
  HostTraffic **theFlaggedHosts = NULL;
  u_int maxHosts, scannedHosts=0;
  float hiresDeltaTime;
  struct timeval hiresTimeStart, hiresTimeEnd;
  HostTraffic *el, *prev, *next;

  /* if(myGlobals.runningPref.rFileName != NULL) return; */

#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: purgeIdleHosts() invoked");
#endif

  if(firstRun) {
    firstRun = 0;
    memset(lastPurgeTime, 0, sizeof(lastPurgeTime));
  }

  gettimeofday(&hiresTimeStart, NULL);

  if(now < (lastPurgeTime[actDevice]+PARM_HOST_PURGE_INTERVAL))
    return(0); /* Too short */
  else
    lastPurgeTime[actDevice] = now;

  maxHosts = myGlobals.device[actDevice].hostsno; /* save it as it can change */
  myGlobals.piMem = maxHosts*sizeof(HostTraffic*);
  theFlaggedHosts = (HostTraffic**)calloc(1, myGlobals.piMem);

  purgeOldFragmentEntries(actDevice); /* let's do this too */

#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: accessMutex(purgeMutex)...calling");
#endif
  accessMutex(&myGlobals.purgeMutex, "purgeIdleHosts");
#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: accessMutex(purgeMutex)...locked");
#endif

#ifdef HASH_DEBUG
  hashSanityCheck();
#endif

  accessMutex(&myGlobals.hostsHashLockMutex, "scanIdleLoop");

  for(idx=0; idx<myGlobals.device[actDevice].actualHashSize; idx++) {
    if(myGlobals.ntopRunState >= FLAG_NTOPSTATE_SHUTDOWN) break;

    if((el = myGlobals.device[actDevice].hash_hostTraffic[idx]) != NULL) {
      prev = NULL;

      while(el) {
	if(is_host_ready_to_purge(actDevice, el, now)) {
	  if(!el->to_be_deleted) {
	    el->to_be_deleted = 1; /* Delete it at the next run */

	    /* Skip it and move to next host */
	    prev = el;
	    el = el->next;
	  } else {
	  /* Host selected for deletion */
	  theFlaggedHosts[numHosts++] = el;
	  el->magic = CONST_UNMAGIC_NUMBER;
	  remove_valid_ptr(el);
	  next = el->next;

	  if(prev != NULL)
	    prev->next = next;
	  else
	    myGlobals.device[actDevice].hash_hostTraffic[idx] = next;

          el->next = NULL;
	  el = next;
	  }
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
        break;
      }
    }
  }

  releaseMutex(&myGlobals.hostsHashLockMutex);

#ifdef HASH_DEBUG
  hashSanityCheck();
#endif

#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: releaseMutex(purgeMutex)...calling");
#endif
  releaseMutex(&myGlobals.purgeMutex);
#ifdef IDLE_PURGE_DEBUG
  traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: releaseMutex(purgeMutex)...released");
#endif

  traceEvent(CONST_TRACE_NOISY, "IDLE_PURGE: Device %d [%s] FINISHED selection, "
	     "%d [out of %d] hosts selected",
	     actDevice, myGlobals.device[actDevice].name, numHosts, scannedHosts);

  /* Now free the entries */
  for(idx=0; idx<numHosts; idx++) {
#ifdef IDLE_PURGE_DEBUG
    traceEvent(CONST_TRACE_INFO, "IDLE_PURGE_DEBUG: Purging host %d [last seen=%d]... %s",
	       idx, theFlaggedHosts[idx]->lastSeen, theFlaggedHosts[idx]->hostResolvedName);
#endif
    freeHostInfo(theFlaggedHosts[idx], actDevice);
    numFreedBuckets++;
    ntop_conditional_sched_yield(); /* Allow other threads to run */
  }

  free(theFlaggedHosts);

  if(myGlobals.runningPref.enableSessionHandling)
    scanTimedoutTCPSessions(actDevice); /* let's check timedout sessions too */

  gettimeofday(&hiresTimeEnd, NULL);
  hiresDeltaTime = timeval_subtract(hiresTimeEnd, hiresTimeStart);

  if(numFreedBuckets > 0)
    traceEvent(CONST_TRACE_NOISY,
	       "IDLE_PURGE: Device %d [%s]: %d/%d hosts deleted, elapsed time is %.6f seconds (%.6f per host)",
	       actDevice, myGlobals.device[actDevice].name,
	       numFreedBuckets, maxHosts,
	       hiresDeltaTime,
	       hiresDeltaTime / numFreedBuckets);
  else
    traceEvent(CONST_TRACE_NOISY, "IDLE_PURGE: Device %s: no hosts [out of %d] deleted",
	       myGlobals.device[actDevice].name, maxHosts);

  return(numFreedBuckets);
}

/* **************************************************** */

/* NOTE - myGlobals.serialLockMutex MUST be locked by caller */
void dumpHostSerial(HostSerial *serial, HostSerialIndex serialHostIndex) {
  datum data_data, key_data;

  // FIX - Implement periodic serial purging
  // traceEvent(CONST_TRACE_WARNING, "dumpHostSerial(%u)", serialHostIndex);

  /* 1 - Dump key(serial) */
  key_data.dptr = (char*)serial, key_data.dsize = sizeof(HostSerial);
  data_data.dptr = (char*)&serialHostIndex, data_data.dsize = sizeof(serialHostIndex);

  if(gdbm_store(myGlobals.serialFile, key_data, data_data, GDBM_REPLACE) != 0)
    traceEvent(CONST_TRACE_ERROR, "While adding host serial %u", serialHostIndex);

  /* 2 - Dump key(serialHostIndex) */
  key_data.dptr = (char*)&serialHostIndex, key_data.dsize = sizeof(serialHostIndex);
  data_data.dptr = (char*)serial, data_data.dsize = sizeof(HostSerial);

  if(gdbm_store(myGlobals.serialFile, key_data, data_data, GDBM_REPLACE) != 0)
    traceEvent(CONST_TRACE_ERROR, "While adding host serial %u", serialHostIndex);
}

/* **************************************************** */

HostSerial* getHostSerialFromId(HostSerialIndex serialHostIndex, HostSerial *serial) {
  datum return_data, key_data;

  accessMutex(&myGlobals.serialLockMutex, "getHostSerialFromId");

  key_data.dptr = (char*)&serialHostIndex, key_data.dsize = sizeof(serialHostIndex);
  return_data = gdbm_fetch(myGlobals.serialFile, key_data);

  if(return_data.dptr != NULL) {
    memcpy(serial, return_data.dptr, sizeof(HostSerial));
    free(return_data.dptr);
  } else {
    /* Not found */
    memset(serial, 0, sizeof(HostSerial));
    serial->serialType = SERIAL_NONE;
    traceEvent(CONST_TRACE_WARNING, "Failed getHostSerialFromId(%u)", serialHostIndex);
  }

  releaseMutex(&myGlobals.serialLockMutex);

  return(serial);
}

/* **************************************************** */

HostSerialIndex getHostIdFromSerial(HostSerial *serial) {
  datum return_data, key_data;
  HostSerialIndex serialHostIndex;

  accessMutex(&myGlobals.serialLockMutex, "getHostSerialFromId");

  key_data.dptr = (char*)serial, key_data.dsize = sizeof(HostSerial);
  return_data = gdbm_fetch(myGlobals.serialFile, key_data);

  if(return_data.dptr != NULL) {
    memcpy(&serialHostIndex, return_data.dptr, sizeof(serialHostIndex));
    free(return_data.dptr);
  } else {
    /* Not found */
    serialHostIndex = 0;
    traceEvent(CONST_TRACE_WARNING, "Failed getHostIdFromSerial(%u)", serialHostIndex);
  }

  releaseMutex(&myGlobals.serialLockMutex);

  return(serialHostIndex);
}

/* **************************************************** */

void setHostSerial(HostTraffic *el) {
  /* Nothing to do */
  if(el->hostSerial.serialType != SERIAL_NONE)
    return;

  memset(&el->hostSerial, 0, sizeof(HostSerial));

  if(el->hostNumIpAddress[0] == '\0') {
    el->hostSerial.serialType = SERIAL_MAC;
    memcpy(&el->hostSerial.value.ethSerial.ethAddress, el->ethAddress, LEN_ETHERNET_ADDRESS);
    el->hostSerial.value.ethSerial.vlanId = el->vlanId;
  } else {
    if(el->hostIpAddress.hostFamily == AF_INET) {
      el->hostSerial.serialType = SERIAL_IPV4;
    } else if(el->hostIpAddress.hostFamily == AF_INET6) {
      el->hostSerial.serialType = SERIAL_IPV6;
    }

    addrcpy(&el->hostSerial.value.ipSerial.ipAddress, &el->hostIpAddress);
    el->hostSerial.value.ipSerial.vlanId = el->vlanId;
  }

  /* We now need to fill in the serialId field */
  accessMutex(&myGlobals.serialLockMutex, "setHostSerial");
  el->serialHostIndex = ++myGlobals.hostSerialCounter; /* Start from 1 (0 = UNKNOWN_SERIAL_INDEX) */
  dumpHostSerial(&el->hostSerial, el->serialHostIndex);
  releaseMutex(&myGlobals.serialLockMutex);
}

/* ********************************************************* */

/*
  Searches a host and returns it. If the host is not
  present in the hash a new bucket is created
*/
HostTraffic* _lookupHost(HostAddr *hostIpAddress, u_char *ether_addr, u_int16_t vlanId,
			 u_char checkForMultihoming, u_char forceUsingIPaddress,
			 int actualDeviceId, char *file, int line,
			 const struct pcap_pkthdr *h, const u_char *p) {
  u_int idx, isMultihomed = 0;
  HostTraffic *el=NULL;
  char buf[MAX_LEN_SYM_HOST_NAME_HTML];
  short useIPAddressForSearching = forceUsingIPaddress;
  char* symEthName = NULL, *ethAddr;
  u_char setSpoofingFlag = 0, locked_mutex = 0;
  u_short numRuns=0;
  u_int hostFound = 0;
  u_int updateIPinfo = 0;
  u_int32_t the_local_network, the_local_network_mask;

  if((hostIpAddress == NULL) && (ether_addr == NULL)) {
    traceEvent(CONST_TRACE_WARNING,
	       "Both Ethernet and IP addresses are NULL in lookupHost()[%s:%d]",
	       file, line);
    return(NULL);
  }

#ifdef HASH_DEBUG
  hashSanityCheck();
#endif

  idx = hashHost(hostIpAddress, ether_addr,
		 &useIPAddressForSearching,
		 &el, actualDeviceId);

#ifdef DEBUG
  if(0)
    traceEvent(CONST_TRACE_NOISY, "DEBUG: lookupHost(%s, %s, m=%u, f=%u, dev=%d, vlan=%d) [idx=%d]",
	       addrtostr(hostIpAddress),
	       etheraddr_string(ether_addr, buf),
	       checkForMultihoming, forceUsingIPaddress, actualDeviceId, vlanId, idx);
  else
    traceEvent(CONST_TRACE_WARNING, "DEBUG: lookupHost(%s, %s, isLocalAddress=%u, _pseudoLocalAddress=%u) [idx=%d]",
	       hostIpAddress ? addrtostr(hostIpAddress) : "<null>",
	       etheraddr_string(ether_addr, buf),
	       hostIpAddress ? isLocalAddress(hostIpAddress, actualDeviceId, NULL, NULL) : 0,
	       hostIpAddress ? _pseudoLocalAddress(hostIpAddress, NULL, NULL) : 0,
	       idx);
#endif

  /* Remember the side effect of above routine - if -o | --no-mac is set,\
   * useIPAddressForSearching is now 1
   */

  /* If we found it or had an error */
  if(el != NULL)
    return(el); /* Found */
  else if(idx == FLAG_NO_PEER)
    return(NULL);
  else {
    el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];
    if(el) {
      lockHostsHashMutex(el, "_lookupHost");
      el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];
      locked_mutex = 1;
    }
  }

  while (el != NULL) {
    if(el->magic != CONST_MAGIC_NUMBER) {
      traceEvent(CONST_TRACE_ERROR,
                 "Bad magic number (expected=%d/real=%d) [deviceId=%d] lookupHost()[%s:%d]",
		 CONST_MAGIC_NUMBER, el->magic, actualDeviceId,
                 file, line);
      break; /* Can't trust this chain ... */
    }

    if(el->hostTrafficBucket != idx) {
      traceEvent(CONST_TRACE_WARNING,
                 "Error: wrong bucketIdx %s/%s (expected=%d/real=%d) [deviceId=%d] lookupHost()[%s:%d]",
		 el->ethAddressString, el->hostNumIpAddress,
		 idx, el->hostTrafficBucket, actualDeviceId,
                 file, line);
    }

    if(!is_host_ready_to_purge(actualDeviceId, el, myGlobals.actTime)) {
      if(useIPAddressForSearching == 0) {
	/* compare with the ethernet-address then the IP address */
	if(memcmp(el->ethAddress, ether_addr, LEN_ETHERNET_ADDRESS) == 0) {
	  if((hostIpAddress != NULL) && (hostIpAddress->hostFamily == el->hostIpAddress.hostFamily)) {
	    if((!isMultihomed) && checkForMultihoming) {
	      /* This is a local address hence this is a potential multihomed host. */

	      if(!(addrnull(&el->hostIpAddress)) &&
		 (addrcmp(&el->hostIpAddress,hostIpAddress) != 0)) {
		isMultihomed = 1;
		setHostFlag(FLAG_HOST_TYPE_MULTIHOMED, el);
	      } else {
		updateIPinfo = 1;
	      }
	    }
	    hostFound = 1;
	    break;
	  } else if(hostIpAddress == NULL) {  /* Only Mac Addresses */
	    hostFound = 1;
	    break;
	  } else { /* MAC match found and we have the IP - need to update... */
	    updateIPinfo = 1;
	    hostFound = 1;
	    break;
	  }
	} else if((hostIpAddress != NULL) &&
		  (addrcmp(&el->hostIpAddress, hostIpAddress) == 0)) {
	  /* Spoofing or duplicated MAC address:
	     two hosts with the same IP address and different MAC
	     addresses
	  */

	  if(!hasDuplicatedMac(el)) {
	    setHostFlag(FLAG_HOST_DUPLICATED_MAC, el);

	    if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	      char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

	      traceEvent(CONST_TRACE_WARNING,
			 "Two MAC addresses found for the same IP address "
			 "%s: [%s/%s] (spoofing detected?)",
			 el->hostNumIpAddress,
			 etheraddr_string(ether_addr, etherbuf), el->ethAddressString);
	      dumpSuspiciousPacket(actualDeviceId, h, p);
	    }
	  }

	  setSpoofingFlag = 1;
	  hostFound = 1;
	  break;
	}
      } else {
	/* -o | --no-mac (or NetFlow, which doesn't have MACs) - compare with only the IP address */
	if((addrcmp(&el->hostIpAddress, hostIpAddress) == 0)
	   || (ether_addr && (memcmp(el->ethAddress, ether_addr, LEN_ETHERNET_ADDRESS) == 0))) {
	  hostFound = 1;
	  break;
	}
      }
    }
    el = el->next;
    numRuns++;
  } /* while */

  if(locked_mutex)
    unlockHostsHashMutex(myGlobals.device[actualDeviceId].hash_hostTraffic[idx]), locked_mutex = 0;

  if((hostFound == 1) && (vlanId != NO_VLAN) && (el->vlanId != NO_VLAN)
     && (vlanId != el->vlanId) && (!isMultivlaned(el))) {
    setHostFlag(FLAG_HOST_TYPE_MULTIVLANED, el);

    if(myGlobals.multipleVLANedHostCount == 0) {
      traceEvent(CONST_TRACE_ERROR, "mVLAN: Host (identical IP/MAC) found on multiple VLANs [%d][%d]", vlanId, el->vlanId);
      traceEvent(CONST_TRACE_INFO,  "mVLAN: ntop continues but will consolidate and thus probably overcount this traffic");
      traceEvent(CONST_TRACE_NOISY, "mVLAN: Up to %d examples will be printed", MAX_MULTIPLE_VLAN_WARNINGS);
    }

    if(++myGlobals.multipleVLANedHostCount < MAX_MULTIPLE_VLAN_WARNINGS) {
      if(ether_addr)
	traceEvent(CONST_TRACE_NOISY, "mVLAN: Device %d Host %s (%02x:%02x:%02x:%02x:%02x:%02x) VLANs %d and %d",
		   actualDeviceId,
		   addrtostr(hostIpAddress),
		   ether_addr[0], ether_addr[1], ether_addr[2],
		   ether_addr[3], ether_addr[4], ether_addr[5],
		   min(vlanId, el->vlanId),
                 max(vlanId, el->vlanId));
    }
  }

  if(numRuns > myGlobals.device[actualDeviceId].hashListMaxLookups)
    myGlobals.device[actualDeviceId].hashListMaxLookups = numRuns;

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

      if(myGlobals.runningPref.numericFlag != noDnsResolution)
        ipaddr2str(el, el->hostIpAddress, el->vlanId, actualDeviceId);

      if(isBroadcastAddress(&el->hostIpAddress, NULL, NULL))
        setHostFlag(FLAG_BROADCAST_HOST, el);
    }
  } else {
    /* New host entry */
    int len;

    if(myGlobals.device[actualDeviceId].hostsno >= myGlobals.runningPref.maxNumHashEntries) {
      static char messageShown = 0;

      if(!messageShown) {
	messageShown = 1;
	traceEvent(CONST_TRACE_INFO, "WARNING: Max num hash entries (%u) reached (see -x)",
		   myGlobals.runningPref.maxNumHashEntries);
      }

      if(locked_mutex) unlockHostsHashMutex(myGlobals.device[actualDeviceId].hash_hostTraffic[idx]), locked_mutex = 0;
      return(NULL);
    }

    if((el = (HostTraffic*)malloc(sizeof(HostTraffic))) == NULL) {
      if(locked_mutex) unlockHostsHashMutex(myGlobals.device[actualDeviceId].hash_hostTraffic[idx]), locked_mutex = 0;
      return(NULL);
    }

    memset(el, 0, sizeof(HostTraffic));
    el->firstSeen = myGlobals.actTime;

    resetHostsVariables(el);
    el->vlanId = vlanId;

    if(isMultihomed)
      setHostFlag(FLAG_HOST_TYPE_MULTIHOMED, el);

    if(el->portsUsage != NULL)
      freePortsUsage(el);

    len = (size_t)myGlobals.numIpProtosList*sizeof(ShortProtoTrafficInfo**);
    if((el->ipProtosList = (ShortProtoTrafficInfo**)malloc(len)) == NULL) {
      if(locked_mutex) unlockHostsHashMutex(myGlobals.device[actualDeviceId].hash_hostTraffic[idx]), locked_mutex = 0;
      return(NULL);
    }
    memset(el->ipProtosList, 0, len);

    /*
    len = (size_t)myGlobals.numIpProtosToMonitor*sizeof(ProtoTrafficInfo**);
    if((el->protoIPTrafficInfos = (ProtoTrafficInfo**)malloc(len)) == NULL) {
      if(locked_mutex) unlockHostsHashMutex(myGlobals.device[actualDeviceId].hash_hostTraffic[idx]), locked_mutex = 0;
      return(NULL);
    }
    memset(el->protoIPTrafficInfos, 0, len);
    */

    el->magic = CONST_MAGIC_NUMBER;
    el->hostTrafficBucket = idx; /* Set the bucket index */

    /* traceEvent(CONST_TRACE_INFO, "new entry added at bucket %d", idx); */

    /* Put the new entry on top of the list */
    el->next = myGlobals.device[actualDeviceId].hash_hostTraffic[el->hostTrafficBucket];
    myGlobals.device[actualDeviceId].hash_hostTraffic[el->hostTrafficBucket] = el;  /* Insert a new entry */
    myGlobals.device[actualDeviceId].hostsno++;

    if(0)
      traceEvent(CONST_TRACE_INFO, "-> Allocated(%d) [tot=%d]",
		 actualDeviceId, myGlobals.device[actualDeviceId].hostsno);

    the_local_network = 0, the_local_network_mask = 0;

    if(ether_addr != NULL) {
      if((hostIpAddress == NULL)
	 || ((hostIpAddress != NULL)
	     && isPseudoLocalAddress(hostIpAddress, actualDeviceId, &the_local_network, &the_local_network_mask)
	     /* && (!isBroadcastAddress(hostIpAddress, &the_local_network, &the_local_network_mask))*/
	     )) {
	char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

	/* This is a local address and then the
	   ethernet address does make sense */
	ethAddr = etheraddr_string(ether_addr, etherbuf);

	memcpy(el->ethAddress, ether_addr, LEN_ETHERNET_ADDRESS);
	strncpy(el->ethAddressString, ethAddr, sizeof(el->ethAddressString));
	symEthName = getSpecialMacInfo(el, (short)(!myGlobals.separator[0]));
	setHostFlag(FLAG_SUBNET_LOCALHOST, el);
	setHostFlag(FLAG_SUBNET_PSEUDO_LOCALHOST, el);
	/* traceEvent(CONST_TRACE_WARNING, "-> %u/%u", the_local_network, the_local_network_mask); */
      } else if(hostIpAddress != NULL) {
	/* This is packet that's being routed or belonging to a
	   remote network that uses the same physical wire (or forged)*/
	memcpy(el->lastEthAddress, ether_addr, LEN_ETHERNET_ADDRESS);

	if(hostIpAddress->hostFamily == AF_INET)
	  memcpy(el->ethAddress, &hostIpAddress->Ip4Address.s_addr, 4); /* Dummy/unique eth address */
	else if(hostIpAddress->hostFamily == AF_INET6)
	  memcpy(el->ethAddress, &hostIpAddress->Ip6Address.s6_addr[8], 4);

	clearHostFlag(FLAG_SUBNET_LOCALHOST, el);

	if(isPrivateAddress(hostIpAddress, &the_local_network, &the_local_network_mask))
	  setHostFlag(FLAG_PRIVATE_IP_ADDRESS, el);

	if(!isBroadcastAddress(hostIpAddress, &the_local_network, &the_local_network_mask)) {
	  if(isPseudoLocalAddress(hostIpAddress, actualDeviceId, &the_local_network, &the_local_network_mask))
	    setHostFlag(FLAG_SUBNET_PSEUDO_LOCALHOST, el);
	  else
	    clearHostFlag(FLAG_SUBNET_PSEUDO_LOCALHOST, el);
	}
      } else {
	clearHostFlag(FLAG_SUBNET_LOCALHOST, el);
	clearHostFlag(FLAG_SUBNET_PSEUDO_LOCALHOST, el);
      }

      updateHostKnownSubnet(el);

      if(strncmp(el->ethAddressString, "FF:", 3) == 0) {
	/*
	  The trick below allows me not to duplicate the
	  "<broadcast>" string in the code
	*/

	if(hostIpAddress != NULL) {
	  if(hostIpAddress->hostFamily == AF_INET)
	    el->hostIp4Address.s_addr = INADDR_BROADCAST;
	  else if(hostIpAddress->hostFamily == AF_INET6)
	    el->hostIp6Address = _in6addr_linklocal_allnodes;
	}

	setHostFlag(FLAG_BROADCAST_HOST, el);
	if(isMulticastAddress(&el->hostIpAddress, &the_local_network, &the_local_network_mask))
	  setHostFlag(FLAG_MULTICAST_HOST, el);
	strncpy(el->hostNumIpAddress,
		_addrtostr(&el->hostIpAddress, buf, sizeof(buf)),
		strlen(el->hostNumIpAddress));
        setResolvedName(el, el->hostNumIpAddress, FLAG_HOST_SYM_ADDR_TYPE_IP);

	if((!addrnull(&el->hostIpAddress)) /* 0.0.0.0 */
	   && (!addrfull(&el->hostIpAddress)) /* 255.255.255.255 */
	   && isBroadcastAddress(&el->hostIpAddress, &the_local_network, &the_local_network_mask)) {
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

      if(myGlobals.runningPref.enableSuspiciousPacketDump)
	checkSpoofing(el, actualDeviceId, h, p);
    }

    if(hostIpAddress != NULL) {
      if(myGlobals.runningPref.dontTrustMACaddr && (ether_addr != NULL))
	memcpy(el->lastEthAddress, ether_addr, LEN_ETHERNET_ADDRESS);

      addrcpy(&el->hostIpAddress, hostIpAddress);
      strncpy(el->hostNumIpAddress,
	      _addrtostr(hostIpAddress, buf, sizeof(buf)),
	      sizeof(el->hostNumIpAddress));
      if(isBroadcastAddress(&el->hostIpAddress, &the_local_network, &the_local_network_mask)) setHostFlag(FLAG_BROADCAST_HOST, el);
      if(isMulticastAddress(&el->hostIpAddress, &the_local_network, &the_local_network_mask)) setHostFlag(FLAG_MULTICAST_HOST, el);
      if(isPrivateAddress(hostIpAddress, &the_local_network, &the_local_network_mask))        setHostFlag(FLAG_PRIVATE_IP_ADDRESS, el);
      if((ether_addr == NULL) && (isPseudoLocalAddress(hostIpAddress, actualDeviceId, &the_local_network, &the_local_network_mask)))
	setHostFlag(FLAG_SUBNET_PSEUDO_LOCALHOST, el);

      setResolvedName(el, el->hostNumIpAddress, FLAG_HOST_SYM_ADDR_TYPE_IP);
      updateHostKnownSubnet(el);

      /* Trick to fill up the address cache */
      if(myGlobals.runningPref.numericFlag != noDnsResolution)
	ipaddr2str(el, el->hostIpAddress, el->vlanId, actualDeviceId);

      /* getHostAS(el); */
    } else {
      /* This is a new entry and hostIpAddress was NOT set.  Fill in MAC address, if we have it */
      if(symEthName[0] != '\0') {
        /* This is a local address so we have the MAC address */
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s%s",
		      symEthName, &el->ethAddressString[8]);

	buf[MAX_LEN_SYM_HOST_NAME-1] = '\0';
        setResolvedName(el, buf, FLAG_HOST_SYM_ADDR_TYPE_MAC);
      }
    }

#ifdef HASH_DEBUG
      traceEvent(CONST_TRACE_INFO, "HASH_DEBUG: Adding %s/%s [idx=%d][device=%d]"
		 "[actualHashSize=%d][#hosts=%d]",
		 el->ethAddressString, el->hostNumIpAddress, idx, actualDeviceId,
		 myGlobals.device[actualDeviceId].actualHashSize,
		 myGlobals.device[actualDeviceId].hostsno);
#endif

    setHostSerial(el);
    handlePluginHostCreationDeletion(el, (u_short)actualDeviceId, 1 /* host creation */);

    notifyEvent(hostCreation, el, NULL, 0);
  }

  if(el != NULL) {
    el->lastSeen = myGlobals.actTime;

    if(setSpoofingFlag)
      setHostFlag(FLAG_HOST_DUPLICATED_MAC, el);

#ifdef DEBUG
    {
      if((hostIpAddress != NULL) && (hostIpAddress->hostFamily == AF_INET6)) {
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

  if(locked_mutex) unlockHostsHashMutex(myGlobals.device[actualDeviceId].hash_hostTraffic[idx]), locked_mutex = 0;

  return(el);
}

/* ************************************ */

#ifdef HASH_DEBUG

static void dumpHash() {
  int i=0;
  HostTraffic *el;

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    traceEvent(CONST_TRACE_INFO, "HASH_DEBUG: (%3d) %s / %s [bkt=%d][next=0x%X]",
	       i++, el->ethAddressString, el->hostNumIpAddress,
	       el->hostTrafficBucket, el->next);
  }
}

/* ***************************************** */

static void hashSanityCheck() {
  int i=0;

  for(i=FIRST_HOSTS_ENTRY; i<myGlobals.device[0].actualHashSize; i++) {
    HostTraffic *el = myGlobals.device[0].hash_hostTraffic[i];

    while(el != NULL) {
      if(el->hostTrafficBucket != i)
	traceEvent(CONST_TRACE_ERROR, "HASH: (%3d) %s / %s [bkt=%d][next=0x%X]",
		   i, el->ethAddressString, el->hostNumIpAddress,
		   el->hostTrafficBucket, el->next);
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
	traceEvent(CONST_TRACE_ERROR, "HOST HASH: (%3d) %s / %s [bkt=%d][next=0x%X]",
		   i, el->ethAddressString, el->hostNumIpAddress,
		   el->hostTrafficBucket, el->next);
      el = el->next;
    }
  }
}

#endif /* HASH_DEBUG */

/* ******************************

   Utility functions used by the remote plugin

   ****************************** */

#define MAX_NUM_VALID_PTRS   8
static void* valid_ptrs[MAX_NUM_VALID_PTRS] = { NULL };

void add_valid_ptr(void* ptr) {
  int i;

  traceEvent(CONST_TRACE_INFO, "add_valid_ptr(%p)", ptr);

  for(i=0; i<MAX_NUM_VALID_PTRS; i++) {
    if(valid_ptrs[i] == NULL) {
      valid_ptrs[i] = ptr;
      break;
    }
  }

  valid_ptrs[MAX_NUM_VALID_PTRS-1] = ptr;
}

/* ****************************** */

void remove_valid_ptr(void* ptr) {
  int i;

  for(i=0; i<MAX_NUM_VALID_PTRS; i++) {
    if(valid_ptrs[i] == ptr) {
      valid_ptrs[i] = NULL;
      return;
    }
  }

  /* traceEvent(CONST_TRACE_ERROR, "remove_valid_ptr(%p) failed", ptr); */
}

/* ****************************** */

int is_valid_ptr(void* ptr) {
  int i;

  for(i=0; i<MAX_NUM_VALID_PTRS; i++) {
    if(valid_ptrs[i] == ptr) {
      if(i > 0) {
	/* Move towards the top */
	void *swap = valid_ptrs[i-1];
	valid_ptrs[i-1] = valid_ptrs[i];
	valid_ptrs[i] = swap;
      }

      traceEvent(CONST_TRACE_INFO, "is_valid_ptr(%p): 1", ptr);
      return(1);
    }
  }

  traceEvent(CONST_TRACE_INFO, "is_valid_ptr(%p): 0", ptr);
  return(0);
}

