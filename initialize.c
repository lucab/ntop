/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
 *
 *  			    http://www.ntop.org/
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

#include "ntop.h"

static u_char threadsInitialized = 0;

/* ******************************* */

void initIPServices(void) {
  FILE* fd;
  int idx, numSlots, len;

  traceEvent(TRACE_INFO, "Initializing IP services...");

  protoIPTrafficInfos = NULL;

#ifdef WIN32
  initWinsock32();
#endif

  /* Let's count the entries first */
  numSlots = 0;
  for(idx=0; configFileDirs[idx] != NULL; idx++) {
    char tmpStr[64];

    if(snprintf(tmpStr, sizeof(tmpStr), "%s/services", configFileDirs[idx]) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    fd = fopen(tmpStr, "r");

    if(fd != NULL) {
      char tmpLine[512];

      while(fgets(tmpLine, 512, fd))
	if((tmpLine[0] != '#') && (strlen(tmpLine) > 10)) {
	  /* discard  9/tcp sink null */
	  numSlots++;
	}
      fclose(fd);
    }
  }

  if(numSlots == 0) numSlots = HASH_INITIAL_SIZE;
  numActServices = 2*numSlots; /* Double the hash */

  /* ************************************* */

#ifdef ENABLE_NAPSTER
  memset(napsterSvr, 0, sizeof(napsterSvr));
#endif

  len = sizeof(ServiceEntry*)*numActServices;
  udpSvc = (ServiceEntry**)malloc(len);
  memset(udpSvc, 0, len);
  tcpSvc = (ServiceEntry**)malloc(len);
  memset(tcpSvc, 0, len);

  for(idx=0; configFileDirs[idx] != NULL; idx++) {
    char tmpStr[64];

    if(snprintf(tmpStr, sizeof(tmpStr), "%s/services", configFileDirs[idx]) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    fd = fopen(tmpStr, "r");

    if(fd != NULL) {
      char tmpLine[512];

      while(fgets(tmpLine, 512, fd))
	if((tmpLine[0] != '#') && (strlen(tmpLine) > 10)) {
	  /* discard  9/tcp sink null */
	  char name[64], proto[16];
	  int numPort;

	  /* Fix below courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */
	  if (3 == sscanf(tmpLine, "%63[^ \t] %d/%15s", name, &numPort, proto)) {
	    /* traceEvent(TRACE_INFO, "'%s' - '%s' - '%d'\n", name, proto, numPort); */

	    if(strcmp(proto, "tcp") == 0)
	      addPortHashEntry(tcpSvc, numPort, name);
	    else
	      addPortHashEntry(udpSvc, numPort, name);
	  }
	}
      fclose(fd);
      break;
    }
  }

  /* Add some basic services, just in case they
     are not included in /etc/services */
  addPortHashEntry(tcpSvc, 21,  "ftp");
  addPortHashEntry(tcpSvc, 20,  "ftp-data");
  addPortHashEntry(tcpSvc, 80,  "http");
  addPortHashEntry(tcpSvc, 443, "https");
  addPortHashEntry(tcpSvc, 42,  "name");
  addPortHashEntry(tcpSvc, 23,  "telnet");
  addPortHashEntry(udpSvc, 137, "netbios-ns");
  addPortHashEntry(tcpSvc, 137, "netbios-ns");
  addPortHashEntry(udpSvc, 138, "netbios-dgm");
  addPortHashEntry(tcpSvc, 138, "netbios-dgm");
  addPortHashEntry(udpSvc, 139, "netbios-ssn");
  addPortHashEntry(tcpSvc, 139, "netbios-ssn");
  addPortHashEntry(tcpSvc, 109, "pop-2");
  addPortHashEntry(tcpSvc, 110, "pop-3");
  addPortHashEntry(tcpSvc, 1109,"kpop");
  addPortHashEntry(udpSvc, 161, "snmp");
  addPortHashEntry(udpSvc, 162, "snmp-trap");
  addPortHashEntry(udpSvc, 635, "mount");
  addPortHashEntry(udpSvc, 640, "pcnfs");
  addPortHashEntry(udpSvc, 650, "bwnfs");
  addPortHashEntry(udpSvc, 2049,"nfsd");
  addPortHashEntry(udpSvc, 1110,"nfsd-status");

  initPassiveSessions();
}

/* ******************************* */

/*
   Function below courtesy of
   Eric Dumazet <dada1@cosmosbay.com>
*/
static void resetDevice(int deviceId) {
  int len;
  void *ptr;
  
  device[deviceId].actualHashSize = topHashSize = HASH_INITIAL_SIZE;  
  device[deviceId].hashThreshold = (unsigned int)(device[deviceId].actualHashSize*0.5);
  device[deviceId].topHashThreshold = (unsigned int)(device[deviceId].actualHashSize*0.75);

  ptr = calloc(HASH_INITIAL_SIZE, sizeof(HostTraffic*));
  device[deviceId].hash_hostTraffic = ptr;
  
  device[deviceId].lastTotalPkts = device[deviceId].lastBroadcastPkts = 0;
  device[deviceId].lastMulticastPkts = 0;
  device[deviceId].lastEthernetBytes = device[deviceId].lastIpBytes = 0;
  device[deviceId].lastNonIpBytes = 0;

  device[deviceId].tcpBytes = device[deviceId].udpBytes = 0;
  device[deviceId].icmpBytes = device[deviceId].dlcBytes = 0;
  device[deviceId].ipxBytes = device[deviceId].netbiosBytes = 0;
  device[deviceId].decnetBytes = device[deviceId].arpRarpBytes = 0;
  device[deviceId].atalkBytes = device[deviceId].otherBytes = 0;
  device[deviceId].otherIpBytes = 0;

  device[deviceId].lastThptUpdate = device[deviceId].lastMinThptUpdate =
    device[deviceId].lastHourThptUpdate = device[deviceId].lastFiveMinsThptUpdate = time(NULL);
  device[deviceId].lastMinEthernetBytes = device[deviceId].lastFiveMinsEthernetBytes = 0;
  memset(&device[deviceId].tcpGlobalTrafficStats, 0, sizeof(SimpleProtoTrafficInfo));
  memset(&device[deviceId].udpGlobalTrafficStats, 0, sizeof(SimpleProtoTrafficInfo));
  memset(&device[deviceId].icmpGlobalTrafficStats, 0, sizeof(SimpleProtoTrafficInfo));
  memset(device[deviceId].last60MinutesThpt, 0, sizeof(device[deviceId].last60MinutesThpt));
  memset(device[deviceId].last24HoursThpt, 0, sizeof(device[deviceId].last24HoursThpt));
  memset(device[deviceId].last30daysThpt, 0, sizeof(device[deviceId].last30daysThpt));
  device[deviceId].last60MinutesThptIdx=0, device[deviceId].last24HoursThptIdx=0,
    device[deviceId].last30daysThptIdx=0;
  device[deviceId].hostsno = 1; /* Broadcast entry */

  len = (size_t)numIpProtosToMonitor*sizeof(SimpleProtoTrafficInfo);

  if(device[deviceId].ipProtoStats == NULL)
    device[deviceId].ipProtoStats = (SimpleProtoTrafficInfo*)malloc(len);

  memset(device[deviceId].ipProtoStats, 0, len);
}

/* ******************************* */

void initCounters(int _mergeInterfaces) {
#ifndef WIN32
  char *p;
#endif
  int len, i;

  numPurgedHosts = numTerminatedSessions = 0;

  mergeInterfaces = _mergeInterfaces;

#ifndef WIN32
  /*
   * The name of the local domain is now calculated properly
   * Kimmo Suominen <kim@tac.nyc.ny.us>
   */

  if(domainName[0] == '\0') {
    if((getdomainname(domainName, MAXHOSTNAMELEN) != 0)
       || (domainName[0] == '\0')
       || (strcmp(domainName, "(none)") == 0)) {
      if((gethostname(domainName, MAXHOSTNAMELEN) == 0)
	 && ((p = memchr(domainName, '.', MAXHOSTNAMELEN)) != NULL)) {
	domainName[MAXHOSTNAMELEN - 1] = '\0';
	/*
	 * Replaced memmove with memcpy
	 * Igor Schein <igor@txc.com>
	 */
	++p;
	memcpy(domainName, p, (MAXHOSTNAMELEN+domainName-p));

      } else
	domainName[0] = '\0';
    }

    if(domainName[0] == '\0') {
      char szLclHost[64];
      struct hostent *lpstHostent;
      struct in_addr stLclAddr;

      gethostname(szLclHost, 64);
      lpstHostent = gethostbyname(szLclHost);
      if (lpstHostent) {
	struct hostent *hp;

	stLclAddr.s_addr = ntohl(*(lpstHostent->h_addr));

	hp = (struct hostent*)gethostbyaddr((char*)lpstHostent->h_addr, 4, AF_INET);

	if (hp && (hp->h_name)) {
	  char *dotp = (char*)hp->h_name;
	  int i;

	  for(i=0; (dotp[i] != '\0') && (dotp[i] != '.'); i++)
	    ;

	  if(dotp[i] == '.')
	    strncpy(domainName, &dotp[i+1], MAXHOSTNAMELEN);
	}
      }
    }

    if(domainName[0] == '\0') {
      /* Last chance.... */
      /* strncpy(domainName, "please_set_your_local_domain.org", MAXHOSTNAMELEN); */
      ;
    }
  }
#endif

  len = strlen(domainName)-1;

  while((len > 0) && (domainName[len] != '.'))
    len--;

  if(len == 0)
    shortDomainName = domainName;
  else
    shortDomainName = &domainName[len+1];

  separator = "&nbsp;";

  memset(transTimeHash, 0, sizeof(transTimeHash));
  memset(dummyEthAddress, 0, ETHERNET_ADDRESS_LEN);
  for(len=0; len<ETHERNET_ADDRESS_LEN; len++)
    dummyEthAddress[len] = len;

  for(i=0; i<numDevices; i++) {
    device[i].numTotSessions = HASH_INITIAL_SIZE; /* Initial value */
    len = sizeof(IPSession*)*device[i].numTotSessions;
    device[i].tcpSession = (IPSession**)malloc(len);
    memset(device[i].tcpSession, 0, len);
    device[i].fragmentList = NULL;
  }

  broadcastEntry = (HostTraffic*)malloc(sizeof(HostTraffic));
  memset(broadcastEntry, 0, sizeof(HostTraffic));
  resetHostsVariables(broadcastEntry);

  /* Set address to FF:FF:FF:FF:FF:FF */
  for(i=0; i<ETHERNET_ADDRESS_LEN; i++)
    broadcastEntry->ethAddress[i] = 0xFF;

  broadcastEntry->hostIpAddress.s_addr = 0xFFFFFFFF;
  strncpy(broadcastEntry->hostNumIpAddress, "broadcast",
	  sizeof(broadcastEntry->hostNumIpAddress));
  strncpy(broadcastEntry->hostSymIpAddress, broadcastEntry->hostNumIpAddress,
	  sizeof(broadcastEntry->hostSymIpAddress));
  strcpy(broadcastEntry->ethAddressString, "FF:FF:FF:FF:FF:FF");
  FD_SET(SUBNET_LOCALHOST_FLAG, &broadcastEntry->flags);
  FD_SET(BROADCAST_HOST_FLAG, &broadcastEntry->flags);
  FD_SET(SUBNET_PSEUDO_LOCALHOST_FLAG, &broadcastEntry->flags);

  broadcastEntryIdx = 0;

  if(trackOnlyLocalHosts) {
    otherHostEntry = (HostTraffic*)malloc(sizeof(HostTraffic));
    memset(otherHostEntry, 0, sizeof(HostTraffic));

    otherHostEntry->hostIpAddress.s_addr = 0x00112233;
    strncpy(otherHostEntry->hostNumIpAddress, "0.1.2.3",
	    sizeof(otherHostEntry->hostNumIpAddress));
    strncpy(otherHostEntry->hostSymIpAddress, "Remaining Host(s)",
	    sizeof(otherHostEntry->hostSymIpAddress));
    strcpy(otherHostEntry->ethAddressString, "00:00:00:00:00:00");   
    otherHostEntryIdx = broadcastEntryIdx+1;
  } else {
    /* We let ntop think that otherHostEntryIdx does not exist */
    otherHostEntry = NULL;
    otherHostEntryIdx = broadcastEntryIdx;
  }

  nextSessionTimeoutScan = time(NULL)+SESSION_SCAN_DELAY;
  thisZone = gmt2local(0);

  numProcesses = 0;
  
  resetStats();

  createVendorTable();
  initialSniffTime = lastRefreshTime = time(NULL);
  capturePackets = 1;
  endNtop = 0;

  numHandledHTTPrequests = 0;  
}

/* ******************************* */

void resetStats(void) {
  int i, interfacesToCreate;

  traceEvent(TRACE_INFO, "Resetting traffic statistics...");

#ifdef MULTITHREADED
  if(threadsInitialized)
    accessMutex(&hostsHashMutex, "resetStats");
#endif

  if(mergeInterfaces)
    interfacesToCreate = 1;
  else
    interfacesToCreate = numDevices;

  /* Do not reset the first entry (broadcastEntry) */
  for(i=0; i<interfacesToCreate; i++) {
    u_int j;

    for(j=1; j<device[i].actualHashSize; j++)
      if(device[i].hash_hostTraffic[j] != NULL) {
	freeHostInfo(i, j, 1);
	device[i].hash_hostTraffic[j] = NULL;
      }

    resetDevice(i);

    for(j=0; j<device[i].numTotSessions; j++)
      if(device[i].tcpSession[j] != NULL) {
	free(device[i].tcpSession[j]);
	device[i].tcpSession[j] = NULL;
      }

    device[i].numTcpSessions = 0;

    device[i].hash_hostTraffic[broadcastEntryIdx] = broadcastEntry;
    if(otherHostEntry != NULL)
      device[i].hash_hostTraffic[otherHostEntryIdx] = otherHostEntry;      
  }

#ifdef MULTITHREADED
  if(threadsInitialized)
    releaseMutex(&hostsHashMutex);
#endif
}

/* ******************************* */

int initGlobalValues(void) {
  actualDeviceId = 0;

#ifndef WIN32
  if((rFileName == NULL) && (geteuid() != 0)) {
    traceEvent(TRACE_INFO, "Sorry, you must be superuser in order to run ntop.\n");
    exit(-1);
  }
#endif

#ifdef HAVE_OPENSSL
  traceEvent(TRACE_INFO, "Initializing SSL...");
  init_ssl();
#endif

  switch(accuracyLevel) {
  case HIGH_ACCURACY_LEVEL:
    enableSessionHandling = enablePacketDecoding = enableFragmentHandling = 1, trackOnlyLocalHosts = 0;
    break;
  case MEDIUM_ACCURACY_LEVEL:
    enableSessionHandling = 1, enablePacketDecoding = 0, enableFragmentHandling = trackOnlyLocalHosts = 1;
    break;
  case LOW_ACCURACY_LEVEL:
    enableSessionHandling = enablePacketDecoding = enableFragmentHandling = 0, trackOnlyLocalHosts = 1;
    break;    
  }

  if(borderSnifferMode) {
    /* Override everything that has been set before */
    enableSessionHandling = enablePacketDecoding = enableFragmentHandling = 0;
#ifdef MULTITHREADED
    numDequeueThreads = MAX_NUM_DEQUEUE_THREADS;
#endif
    trackOnlyLocalHosts = 1;
  } else {
#ifdef MULTITHREADED
    numDequeueThreads = 1;
#endif
  }

  return(0);
}

/* ******************************* */

void postCommandLineArgumentsInitialization(time_t *lastTime _UNUSED_) {

#ifndef WIN32
  if(daemonMode)
    daemonize();
#endif

  if(numIpProtosToMonitor == 0)
    addDefaultProtocols();

#ifndef MULTITHREADED
  if(logTimeout != 0)
    nextLogTime = time(NULL) + logTimeout;
#endif
}

/* ******************************* */

void initGdbm(void) {
  char tmpBuf[200];
#ifdef FALLBACK
  int firstTime=1;
#endif

  traceEvent(TRACE_INFO, "Initializing GDBM...");

#ifdef HAVE_GDBM_H

  /* Courtesy of Andreas Pfaller <a.pfaller@pop.gun.de>. */
  if(snprintf(tmpBuf, sizeof(tmpBuf), "%s/addressCache.db", dbPath) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");

  unlink(tmpBuf); /* Delete the old one (if present) */ 
  addressCache = gdbm_open (tmpBuf, 0, GDBM_WRCREAT, 00664, NULL);

  if(addressCache == NULL) {
    traceEvent(TRACE_ERROR, "Database '%s' open failed: %s\n",
#if defined(WIN32) && defined(__GNUC__)
	       tmpBuf, "unknown gdbm errno");
#else
    tmpBuf, gdbm_strerror(gdbm_errno));
#endif
  
  traceEvent(TRACE_ERROR, "Possible solution: please use '-P <directory>'\n");
  exit(-1);
 }

  /* Courtesy of Andreas Pfaller <a.pfaller@pop.gun.de>. */
  if(snprintf(tmpBuf, sizeof(tmpBuf), "%s/dnsCache.db", dbPath) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");

  gdbm_file = gdbm_open (tmpBuf, 0, GDBM_WRCREAT, 00664, NULL);

#ifdef FALLBACK
 RETRY_INIT_GDBM:
#endif
  if(gdbm_file == NULL) {
    traceEvent(TRACE_ERROR, "Database '%s' open failed: %s\n",
#if defined(WIN32) && defined(__GNUC__)
	       tmpBuf, "unknown gdbm errno");
#else
    tmpBuf, gdbm_strerror(gdbm_errno));
#endif

    traceEvent(TRACE_ERROR, "Possible solution: please use '-P <directory>'\n");
    exit(-1);
} else {
  if(snprintf(tmpBuf, sizeof(tmpBuf), "%s/ntop_pw.db", dbPath) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
    pwFile = gdbm_open (tmpBuf, 0, GDBM_WRCREAT, 00664, NULL);

    if(pwFile == NULL) {
      traceEvent(TRACE_ERROR, "FATAL ERROR: Database '%s' cannot be opened.", tmpBuf);
      exit(-1);
    }

    if(snprintf(tmpBuf, sizeof(tmpBuf), "%s/hostsInfo.db", dbPath) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    hostsInfoFile = gdbm_open (tmpBuf, 0, GDBM_WRCREAT, 00664, NULL);

    if(hostsInfoFile == NULL) {
      traceEvent(TRACE_ERROR, "FATAL ERROR: Database '%s' cannot be opened.", tmpBuf);
      exit(-1);
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, "The ntop.db database contains %d entries.\n", numDbEntries);
#endif
  }
#endif /* GDBM */
}

/* ******************************* */

void initThreads(int enableThUpdate, int enableIdleHosts, int enableDBsupport) {
int i;
#ifdef HAVE_GDBM_H
#ifdef MULTITHREADED
  numThreads = 0;
  createMutex(&gdbmMutex);
#endif
#endif

#ifdef MULTITHREADED
  packetQueueLen = maxPacketQueueLen = packetQueueHead = packetQueueTail = 0;

#ifdef USE_SEMAPHORES
  createSem(&queueSem, 0);
#ifdef ASYNC_ADDRESS_RESOLUTION
  createSem(&queueAddressSem, 0);
#endif
#else
  createCondvar(&queueCondvar);
#ifdef ASYNC_ADDRESS_RESOLUTION
  createCondvar(&queueAddressCondvar);
#endif
#endif

  createMutex(&packetQueueMutex);
  createMutex(&addressResolutionMutex);
  createMutex(&hashResizeMutex);

  if (isLsofPresent)
    createMutex(&lsofMutex);

  createMutex(&hostsHashMutex);
  createMutex(&graphMutex);

  /*
   * (1) - NPA - Network Packet Analyzer (main thread)
   */
      createThread(&dequeueThreadId, dequeuePacket, NULL);
      traceEvent(TRACE_INFO, "Started thread (%ld) for network packet analyser.\n",
	         dequeueThreadId);

  /*
   * (2) - HTS - Host Traffic Statistics
   */
  createThread(&hostTrafficStatsThreadId, updateHostTrafficStatsThptLoop, NULL);
  traceEvent (TRACE_INFO, "Started thread (%ld) for host traffic statistics.\n",
	      hostTrafficStatsThreadId);

  /*
   * (3) - TU - Throughput Update - optional
   */
  if (enableThUpdate) {
    createThread(&thptUpdateThreadId, updateThptLoop, NULL);
    traceEvent (TRACE_INFO, "Started thread (%ld) for throughput update.", thptUpdateThreadId);
  }

  /*
   * (4) - SIH - Scan Idle Hosts - optional
   */
  if (enableIdleHosts && (rFileName == NULL)) {

    if(!borderSnifferMode) {
    createThread(&scanIdleThreadId, scanIdleLoop, NULL);
    traceEvent (TRACE_INFO, "Started thread (%ld) for idle hosts detection.\n",
		scanIdleThreadId);
     }

if(enableSessionHandling) {
    createThread(&scanIdleSessionsThreadId, scanIdleSessionsLoop, NULL);
    traceEvent (TRACE_INFO, "Started thread (%ld) for idle TCP sessions detection.\n",
		scanIdleSessionsThreadId);
}
  }

#ifndef MICRO_NTOP
  /*
   * (5) - DBU - DB Update - optional
   */
  if (enableDBsupport) {
    createThread(&dbUpdateThreadId, updateDBHostsTrafficLoop, NULL);
    traceEvent (TRACE_INFO, "Started thread (%ld) for DB update.\n", dbUpdateThreadId);
  }
#endif /* MICRO_NTOP */

  numResolvedWithDNSAddresses = numKeptNumericAddresses = numResolvedOnCacheAddresses = 0;
#ifdef ASYNC_ADDRESS_RESOLUTION
  if(numericFlag == 0) {
    /*
     * (6) - DNSAR - DNS Address Resolution - optional
     */
for(i=0; i<numDequeueThreads; i++) {
createThread(&dequeueAddressThreadId[i], dequeueAddress, NULL);
traceEvent (TRACE_INFO, "Started thread (%ld) for DNS address resolution.\n",
		dequeueAddressThreadId[i]);
}

    /*
     * (7) - Purge old host addresses
     */
     createThread(&purgeAddressThreadId, cleanupExpiredHostEntriesLoop, NULL);
     traceEvent (TRACE_INFO, "Started thread (%ld) for address purge.", purgeAddressThreadId);
   }
#endif
#endif

  threadsInitialized = 1;
}

/* ******************************* */

void initApps(void) {
  if(isLsofPresent) {
#ifdef MULTITHREADED
#ifndef WIN32
    updateLsof = 1;
    memset(localPorts, 0, sizeof(localPorts)); /* localPorts is used by lsof */
    /*
     * (7) - LSOF - optional
     */
    createThread(&lsofThreadId, periodicLsofLoop, NULL);
    traceEvent (TRACE_INFO, "Started thread (%ld) for lsof support.\n", lsofThreadId);
#endif /* WIN32 */
#else
    if(isLsofPresent) readLsofInfo();
#endif
  }
}

/* ******************************* */

void initDevices(char* devices) {
  char ebuf[PCAP_ERRBUF_SIZE], *myDevices;
  int i, j, mallocLen;
  NtopInterface *tmpDevice;
  char *tmpDev;
#ifdef WIN32
  char *ifName, intNames[32][256];
  int ifIdx = 0;
  int defaultIdx = -1;
#endif

  traceEvent(TRACE_INFO, "Initializing network devices...");

  myDevices = devices;
  device = NULL;

  /* Determine the device name if not specified */
  ebuf[0] = '\0';

#ifdef WIN32
  memset(intNames, 0, sizeof(intNames));

  tmpDev = pcap_lookupdev(ebuf);

  if(tmpDev == NULL) {
    traceEvent(TRACE_INFO, "Unable to locate default interface (%s)", ebuf);
    exit(-1);
  }

  ifName = tmpDev;

  if(!isWinNT()) {	 
	 for(i=0;; i++) {
      if(tmpDev[i] == 0) {
	if(ifName[0] == '\0')
	  break;
	else {
	  traceEvent(TRACE_INFO, "Found interface [index=%d] '%s'", ifIdx, ifName);

	  if(ifIdx < 32) {
	    strcpy(intNames[ifIdx], ifName);
	    if(defaultIdx == -1) {
	      if(strncmp(intNames[ifIdx], "PPP", 3) /* Avoid to use the PPP interface */
		 && strncmp(intNames[ifIdx], "ICSHARE", 6)) { /* Avoid to use the internet sharing interface */
		defaultIdx = ifIdx;
	      }
	    }
	  }

	  ifIdx++;
	  ifName = &tmpDev[i+1];
	}
      }
    }

    tmpDev = intNames[defaultIdx];
  } else {
    /* WinNT/2K */
    static char tmpString[128];
    int i, j;

      while(tmpDev[0] != '\0') {
		for(j=0, i=0; !((tmpDev[i] == 0) && (tmpDev[i+1] == 0)); i++) {
		 if(tmpDev[i] != 0)
		  tmpString[j++] = tmpDev[i];
		 }

      tmpString[j++] = 0;
      traceEvent(TRACE_INFO, "Found interface [index=%d] '%s'", ifIdx, tmpString);
      tmpDev = &tmpDev[i+3];
      strcpy(intNames[ifIdx++], tmpString);
	  defaultIdx = 0;
	}
	  if(defaultIdx != -1)
		tmpDev = intNames[defaultIdx]; /* Default */
  }
#endif

  if (myDevices == NULL) {
    /* No default device selected */
#ifndef WIN32
    tmpDev = pcap_lookupdev(ebuf);
     
    if(tmpDev == NULL) {
      traceEvent(TRACE_INFO, "Unable to locate default interface (%s)\n", ebuf);
      exit(-1);
    }
#endif

    device = (NtopInterface*)calloc(1, sizeof(NtopInterface));
    device[0].name = strdup(tmpDev);
    numDevices=1;
  } else {
#ifdef WIN32
    u_int selectedDevice = atoi(devices);

    if(selectedDevice < ifIdx) {
      tmpDev = intNames[selectedDevice];
    } else {
      traceEvent(TRACE_INFO, "Index out of range [0..%d]", ifIdx);
      exit(-1);
    }
#else
    char *strtokState;

    tmpDev = strtok_r(myDevices, ",", &strtokState);
#endif
    numDevices = 0;
 
    while(tmpDev != NULL) {
#ifndef WIN32
      char *nwInterface;

      deviceSanityCheck(tmpDev); /* These checks do not apply to Win32 */

      if((nwInterface = strchr(tmpDev, ':')) != NULL) {
 	/* This is a virtual nwInterface */
 	int i, found=0;
 
 	nwInterface[0] = 0;
 
 	for(i=0; i<numDevices; i++)
 	  if(device[i].name && (strcmp(device[i].name, tmpDev) == 0)) {
 	    found = 1;
 	    break;
 	  }
 
 	if(found) {
 	  tmpDev = strtok_r(NULL, ",", &strtokState);
 	  continue;
 	}
      }
#endif
 
      mallocLen = sizeof(NtopInterface)*(numDevices+1);
      tmpDevice = (NtopInterface*)malloc(mallocLen);
      memset(tmpDevice, 0, mallocLen);
      
	/* Fix courtesy of Marius <marius@tbs.co.za> */
      if(numDevices > 0) {
	memcpy(tmpDevice, device, sizeof(NtopInterface)*numDevices);
	free(device);
      }

      device = tmpDevice;
 
      device[numDevices++].name = strdup(tmpDev);
 
#ifndef WIN32
      tmpDev = strtok_r(NULL, ",", &strtokState);
#else
      break;
#endif

#ifndef MULTITHREADED
      if(tmpDev != NULL) {
	traceEvent(TRACE_WARNING, "WARNING: ntop can handle multiple interfaces only\n"
		   "         if thread support is enabled. Only interface\n"
		   "         '%s' will be used.\n", device[0].name);
	break;
      }
#endif
 
      if(numDevices >= MAX_NUM_DEVICES) {
	traceEvent(TRACE_INFO, "WARNING: ntop can handle up to %d interfaces.",
		   numDevices);
	break;
      }
    }

  }

  /* ******************************************* */

  if(rFileName == NULL) {
    /* When sniffing from a multihomed interface
       it is necessary to add all the virtual interfaces
       because ntop has to know all the local addresses */
    for(i=0, j=numDevices; i<j; i++) {
      getLocalHostAddress(&device[i].ifAddr, device[i].name);

      if(strncmp(device[i].name, "lo", 2)) { /* Do not care of virtual loopback interfaces */
	int k;
	char tmpDeviceName[16];
	struct in_addr myLocalHostAddress;

	if(numDevices < MAX_NUM_DEVICES) {
	  for(k=0; k<8; k++) {
	    if(snprintf(tmpDeviceName, sizeof(tmpDeviceName), "%s:%d", device[i].name, k) < 0)
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	    if(getLocalHostAddress(&myLocalHostAddress, tmpDeviceName) == 0) {
	      /* The virtual interface exists */

	      mallocLen = sizeof(NtopInterface)*(numDevices+1);
	      tmpDevice = (NtopInterface*)malloc(mallocLen);
	      memset(tmpDevice, 0, mallocLen);
	      memcpy(tmpDevice, device, sizeof(NtopInterface)*numDevices);
	      free(device);
	      device = tmpDevice;

	      device[numDevices].ifAddr.s_addr = myLocalHostAddress.s_addr;
	      if(myLocalHostAddress.s_addr == device[i].ifAddr.s_addr)
		continue; /* No virtual Interfaces */
	      device[numDevices++].name = strdup(tmpDeviceName);
#ifdef DEBUG
	      traceEvent(TRACE_INFO, "Added: %s\n", tmpDeviceName);
#endif
	    } else
	      break; /* No virtual interface */
	  }
	}
      }
    }
  }

  for(i=0; i<numDevices; i++)
    getLocalHostAddress(&device[i].network, device[i].name);
}

/* ******************************* */

static void initRules(char *rulesFile) {
  if((rulesFile != NULL) && (rulesFile[0] != '\0')) {
    char tmpBuf[200];

    traceEvent(TRACE_INFO, "Parsing ntop rules...");

    handleRules = 1;
    parseRules(rulesFile);

    if(snprintf(tmpBuf, sizeof(tmpBuf), "%s/event.db", dbPath) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    eventFile = gdbm_open (tmpBuf, 0, GDBM_WRCREAT, 00664, NULL);

    if(eventFile == NULL) {
      traceEvent(TRACE_ERROR, "FATAL ERROR: Database '%s' cannot be opened.", tmpBuf);
      exit(-1);
    }
  } else
    eventFile = NULL;
}

/* ******************************* */

void initLibpcap(char* rulesFile, int numDevices) {
  char ebuf[PCAP_ERRBUF_SIZE];

  if(rFileName == NULL) {
    int i;

    initRules(rulesFile);

    for(i=0; i<numDevices; i++) {
      /* Fire up libpcap for each specified device */
      char myName[80];

      /* Support for virtual devices */
      char *column = strchr(device[i].name, ':');

      /*
	The timeout below for packet capture
	has been set to 100ms.

	Courtesy of: Nicolai Petri <Nicolai@atomic.dk>
      */
      if(column == NULL) {
	device[i].pcapPtr = pcap_open_live(device[i].name, DEFAULT_SNAPLEN, 1, 100 /* ms */, ebuf);

	if(device[i].pcapPtr == NULL) {
	  traceEvent(TRACE_INFO, ebuf);
	  traceEvent(TRACE_INFO, "Please select another interface using the -i flag.");
	  exit(-1);
	}

	if(pcapLog != NULL) {
	  if(strlen(pcapLog) > 64)
	    pcapLog[64] = '\0';

	  sprintf(myName, "%s.%s.pcap", pcapLog, device[i].name);
	  device[i].pcapDumper = pcap_dump_open(device[i].pcapPtr, myName);

	  if(device[i].pcapDumper == NULL) {
	    traceEvent(TRACE_INFO, ebuf);
	    exit(-1);
	  }
	}

	if(enableSuspiciousPacketDump) {
	  sprintf(myName, "ntop-suspicious-pkts.%s.pcap", device[i].name);
	  device[i].pcapErrDumper = pcap_dump_open(device[i].pcapPtr, myName);

	  if(device[i].pcapErrDumper == NULL)
	    traceEvent(TRACE_INFO, ebuf);
	}
      } else {
	column[0] = 0;
	device[i].virtualDevice = 1;
	column[0] = ':';
      }
    }

    for(i=0; i<numDevices; i++) {
      if(pcap_lookupnet(device[i].name, &device[i].network.s_addr,
			&device[i].netmask.s_addr, ebuf) < 0) {
	/* Fix for IP-less interfaces (e.g. bridge)
	   Courtesy of Diana Eichert <deicher@sandia.gov>
	*/
	device[i].network.s_addr = htonl(0);
	device[i].netmask.s_addr = htonl(0xFFFFFFFF);
      } else {
	device[i].network.s_addr = htonl(device[i].network.s_addr);
	device[i].netmask.s_addr = htonl(device[i].netmask.s_addr);
      }
    }
  } else {
    device[0].pcapPtr = pcap_open_offline(rFileName, ebuf);
    device[0].name[0] = '\0';
    numDevices = 1;

    if(device[0].pcapPtr == NULL) {
      traceEvent(TRACE_INFO, ebuf);
      exit(-1);
    }
  }


#ifdef WIN32
  /* This looks like a Win32 libpcap open issue... */
  {
    struct hostent* h;
    char szBuff[80];

    gethostname(szBuff, 79);
    h=gethostbyname(szBuff);
    device[0].netmask.s_addr = 0xFFFFFF00; /* 255.255.255.0 */
    device[0].network.s_addr = device[0].ifAddr.s_addr & device[0].netmask.s_addr;
  }

  /* Sanity check... */
  /*
    if((localHostAddress[0].s_addr & device[0].netmask) != device[0].localnet) {
    struct in_addr addr1;

    traceEvent(TRACE_WARNING, "WARNING: your IP address (%s), ", intoa(localHostAddress[0]));
    addr1.s_addr = netmask[0];
    traceEvent(TRACE_WARNING, "netmask %s", intoa(addr1));
    addr1.s_addr = device[0].localnet;
    traceEvent(TRACE_WARNING, ", network %s\ndo not match.\n", intoa(addr1));
    device[0].network = localHostAddress[0].s_addr & device[0].netmask;
    traceEvent(TRACE_WARNING, "ntop will use: IP address (%s), ",
    intoa(localHostAddress[0]));
    addr1.s_addr = netmask[0];
    traceEvent(TRACE_WARNING, "netmask %s", intoa(addr1));
    addr1.s_addr = device[0].localnet;
    traceEvent(TRACE_WARNING, ", network %s.\n", intoa(addr1));
    device[0].localnet = localHostAddress[0].s_addr & device[0].netmask;
    } */
#endif

  {
    int i;
    
    for(i=0; i<numDevices; i++) {
      int memlen;

#define MAX_SUBNET_HOSTS 1024

      if(device[i].netmask.s_addr == 0) {
	/* In this case we are using a dump file */
	device[i].netmask.s_addr = 0xFFFFFF00; /* dummy */	
      }

      device[i].numHosts = 0xFFFFFFFF - device[i].netmask.s_addr + 1;
      if(device[i].numHosts > MAX_SUBNET_HOSTS) {
	device[i].numHosts = MAX_SUBNET_HOSTS;	
	traceEvent(TRACE_WARNING, "Truncated network size to %d hosts (real netmask %s)", 
		   device[i].numHosts, intoa(device[i].netmask));  
      }

      memlen = sizeof(TrafficEntry*)*device[i].numHosts*device[i].numHosts;
      device[i].ipTrafficMatrix = (TrafficEntry**)calloc(device[i].numHosts*device[i].numHosts, 
							 sizeof(TrafficEntry*));
#ifdef DEBUG
      traceEvent(TRACE_WARNING, "ipTrafficMatrix memlen=%.1f Mbytes", 
		 (float)memlen/(float)(1024*1024));
#endif
      
      if(device[i].ipTrafficMatrix == NULL) {
	traceEvent(TRACE_ERROR, "FATAL error: malloc() failed (size %d bytes)", memlen);
	exit(-1);
      }
      
      memlen = sizeof(struct hostTraffic*)*device[i].numHosts;
      device[i].ipTrafficMatrixHosts = (struct hostTraffic**)calloc(sizeof(struct hostTraffic*), 
								    device[i].numHosts);

#ifdef DEBUG
      traceEvent(TRACE_WARNING, "ipTrafficMatrixHosts memlen=%.1f Mbytes", 
		 (float)memlen/(float)(1024*1024));
#endif

      if(device[i].ipTrafficMatrixHosts == NULL) {
	traceEvent(TRACE_ERROR, "FATAL error: malloc() failed (size %d bytes)", memlen);
	exit(-1);
      }
    }
  }
}

/* ******************************* */

void initDeviceDatalink(void) {
  int i;

  /* get datalink type */
#ifdef AIX
  /* This is a bug of libpcap on AIX */
  for(i=0; i<numDevices; i++) {
    if(!device[i].virtualDevice) {
      switch(device[i].name[0]) {
      case 't': /* TokenRing */
	device[i].datalink = DLT_IEEE802;
	break;
      case 'l': /* Loopback */
	device[i].datalink = DLT_NULL;
	break;
      default:
	device[i].datalink = DLT_EN10MB; /* Ethernet */
      }
    }
  }
#else

#if defined(__FreeBSD__)
  for(i=0; i<numDevices; i++)
    if(!device[i].virtualDevice) {
      if(strncmp(device[i].name, "tun", 3) == 0)
	device[i].datalink = DLT_PPP;
      else
	device[i].datalink = pcap_datalink(device[i].pcapPtr);
    }

#else
  for(i=0; i<numDevices; i++)
    if(!device[i].virtualDevice) {
      device[i].datalink = pcap_datalink(device[i].pcapPtr);
      if((device[i].name[0] == 'l') /* loopback check */
	 && (device[i].name[1] == 'o'))
	device[i].datalink = DLT_NULL;
    }
#endif
#endif
}

/* ******************************* */

void parseTrafficFilter(char *argv[], int optind) {
  /* Construct, compile and set filter */
  if(optind > 0) {
    currentFilterExpression = copy_argv(argv + optind);
    if(currentFilterExpression != NULL) {
      int i;
      struct bpf_program fcode;

      for(i=0; i<numDevices; i++) {
	if(!device[i].virtualDevice) {
	  if((pcap_compile(device[i].pcapPtr, &fcode, currentFilterExpression, 1,
			   device[i].netmask.s_addr) < 0)
	     || (pcap_setfilter(device[i].pcapPtr, &fcode) < 0)) {
	    traceEvent(TRACE_ERROR,
		   "FATAL ERROR: wrong filter '%s' (%s) on interface %s\n",
		   currentFilterExpression,
		   pcap_geterr(device[i].pcapPtr), 
	       device[i].name[0] == '0' ? "<pcap file>" : device[i].name);
	    exit(-1);
	  } else
	    traceEvent(TRACE_INFO, "Set filter \"%s\" on device %s.", 
	      currentFilterExpression, device[i].name);
	}
      }
    } else
    currentFilterExpression = strdup("");	/* so that it isn't NULL! */
  }  else
  currentFilterExpression = strdup("");	/* so that it isn't NULL! */  
}

/* *************************** */

#ifndef WIN32
static void ignoreThisSignal(int signalId) {
  setsignal(signalId, ignoreThisSignal);
}
#endif


/* ******************************* */

void initSignals(void) {
/*
    The handler below has been restored due 
    to compatibility problems:
    Courtesy of Martin Lucina <mato@kotelna.sk>
  */
#ifndef WIN32
/* setsignal(SIGCHLD, handleDiedChild); */
   setsignal(SIGCHLD, SIG_IGN);
#endif

#ifndef WIN32
  /* Setup signal handlers */
  setsignal(SIGTERM, cleanup);
  setsignal(SIGINT,  cleanup);
  setsignal(SIGHUP,  handleSigHup);
  setsignal(SIGPIPE, ignoreThisSignal);
  setsignal(SIGABRT, ignoreThisSignal);
#endif
}

/* ***************************** */

void startSniffer(void) {
  int i;

#ifdef MULTITHREADED
  for(i=0; i<numDevices; i++)
    if(!device[i].virtualDevice) {
      /*
       * (8) - NPS - Network Packet Sniffer (main thread)
       */
      createThread(&device[i].pcapDispatchThreadId, pcapDispatch, (char*)i);
      traceEvent (TRACE_INFO, "Started thread (%ld) for network packet sniffing on %s.\n",
		  device[i].pcapDispatchThreadId, device[i].name);
    }
#endif
}
