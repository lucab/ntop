/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
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


/* ******************************* */

void initIPServices(void) {
  FILE* fd;
  int idx, i;

  memset(device, 0, sizeof(device));

  memset(protoIPTrafficInfos, 0, sizeof(protoIPTrafficInfos));
  ipPortMapper = (int*)malloc(sizeof(int)*TOP_IP_PORT);

#ifdef WIN32
  initWinsock32();
#endif

  for(i=0; i<TOP_IP_PORT; i++) ipPortMapper[i] = -1;

  memset(udpSvc, 0, sizeof(udpSvc));
  memset(tcpSvc, 0, sizeof(tcpSvc));

  for(idx=0; configFileDirs[idx] != NULL; idx++) {
    char tmpStr[64];

    if(snprintf(tmpStr, sizeof(tmpStr), "%s/services", configFileDirs[idx]) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    fd = fopen(tmpStr, "r");

    if(fd != NULL) {
      char tmpStr[512];

      while(fgets(tmpStr, 512, fd))
	if((tmpStr[0] != '#') && (strlen(tmpStr) > 10)) {
	  /* discard  9/tcp sink null */
	  char name[64], proto[16];
	  int numPort;

	  /* Fix below courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */
	  if (3 == sscanf(tmpStr, "%63[^ \t] %d/%15s", name, &numPort, proto)) {	    
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
}
/* ******************************* */

void initCounters(int _mergeInterfaces) {
#ifndef WIN32
  char *p;
#endif
  int len, i;
  int actualHashSize = HASH_INITIAL_SIZE;
  static HostTraffic broadcastEntry;

  mergeInterfaces = _mergeInterfaces;

  /* (void)setsignal(SIGWINCH, windowSizeChanged);  */

#ifndef WIN32
  /*
   * The name of the local domain is now calculated properly
   * Kimmo Suominen <kim@tac.nyc.ny.us>
   */

  if(domainName[0] == '\0') {
    if((getdomainname(domainName, MAXHOSTNAMELEN) != 0)
       || (domainName[0] == '\0')
       || (strcmp(domainName, "(none)") == 0))
      {
	if ((gethostname(domainName, MAXHOSTNAMELEN) == 0)
	    && ((p = memchr(domainName, '.', MAXHOSTNAMELEN)) != NULL)) {
	  domainName[MAXHOSTNAMELEN - 1] = '\0';
	  /*
	   * Replaced memmove with memcpy
	   * Igor Schein <igor@txc.com>
	   */
	  memcpy(domainName, ++p, (MAXHOSTNAMELEN+domainName-p));

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

#ifndef HAVE_GDBM_H
  memset(hnametable, 0, sizeof(hnametable));
#endif

  for(i=0; i<numDevices; i++) {
    if((!mergeInterfaces)
       || (mergeInterfaces && (i == 0))) {
      device[i].actualHashSize = actualHashSize;
      device[i].hashThreshold = (unsigned int)(device[i].actualHashSize*0.5);
      device[i].topHashThreshold = (unsigned int)(device[i].actualHashSize*0.75);

      len = sizeof(HostTraffic*)*device[i].actualHashSize;
      device[i].hash_hostTraffic = malloc(len);
      memset(device[i].hash_hostTraffic, 0, len);
      
      device[i].lastTotalPkts = device[i].lastBroadcastPkts = 0;
      device[i].lastMulticastPkts = 0;
      device[i].lastEthernetBytes = device[i].lastIpBytes = 0;
      device[i].lastNonIpBytes = 0;
      
      device[i].tcpBytes = device[i].udpBytes = 0;
      device[i].icmpBytes = device[i].dlcBytes = 0;
      device[i].ipxBytes = device[i].netbiosBytes = 0;
      device[i].decnetBytes = device[i].arpRarpBytes = 0;
      device[i].atalkBytes = device[i].otherBytes = 0;
      device[i].otherIpBytes = 0;
      device[i].hostsno = 0;
    }
  }

  memset(tcpSession, 0, sizeof(tcpSession));
  memset(udpSession, 0, sizeof(udpSession));

  nextSessionTimeoutScan = time(NULL)+SESSION_SCAN_DELAY;
  thisZone = gmt2local(0);

  len = (size_t)numIpProtosToMonitor*sizeof(SimpleProtoTrafficInfo);
  ipProtoStats = (SimpleProtoTrafficInfo*)malloc(len);
  memset(ipProtoStats, 0, len);

  memset(&broadcastEntry, 0, sizeof(HostTraffic));
  /* Set address to FF:FF:FF:FF:FF:FF */
  for(i=0; i<ETHERNET_ADDRESS_LEN; i++)
    broadcastEntry.ethAddress[i] = 255;
  broadcastEntry.hostIpAddress.s_addr = 0xFFFFFFFF;
  strncpy(broadcastEntry.hostNumIpAddress, "broadcast", 
	 sizeof(broadcastEntry.hostNumIpAddress));
  strncpy(broadcastEntry.hostSymIpAddress, broadcastEntry.hostNumIpAddress, 
	  sizeof(broadcastEntry.hostSymIpAddress));
  FD_SET(SUBNET_LOCALHOST_FLAG, &broadcastEntry.flags);
  FD_SET(BROADCAST_HOST_FLAG, &broadcastEntry.flags);
  FD_SET(SUBNET_PSEUDO_LOCALHOST_FLAG, &broadcastEntry.flags);

  broadcastEntryIdx = 0;

  for(i=0; i<numDevices; i++) {
    if((!mergeInterfaces)
       || (mergeInterfaces && (i == 0))) {
      device[i].hash_hostTraffic[broadcastEntryIdx] = &broadcastEntry;
      memset(device[i].last60MinutesThpt, 0, sizeof(device[i].last60MinutesThpt));
      memset(device[i].last24HoursThpt, 0, sizeof(device[i].last24HoursThpt));
      memset(device[i].last30daysThpt, 0, sizeof(device[i].last30daysThpt));
      device[i].last60MinutesThptIdx=0, device[i].last24HoursThptIdx=0, 
	device[i].last30daysThptIdx=0;
      device[i].hostsno++; /* A new entry has just been added */  
    }
  }
  
  fragmentList = NULL;
 
  resetStats();
  createVendorTable();
  initialSniffTime = lastRefreshTime = time(NULL);
  capturePackets = 1;
  endNtop = 0;
}

/* ******************************* */

void resetStats(void) {
  int i, interfacesToCreate;

  traceEvent(TRACE_INFO, "Resetting traffic statistics...");
  
#ifdef MULTITHREADED
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
	freeHostInfo(i, j);
	device[i].hash_hostTraffic[j] = NULL;
      }

    device[i].ethernetPkts = 0, device[i].lastNumEthernetPkts = 0;
    device[i].ethernetBytes = 0;
    device[i].ipBytes = 0;
    device[i].broadcastPkts = 0;
    device[i].multicastPkts = 0;
    device[i].peakThroughput = 0, device[i].peakPacketThroughput = 0;
    device[i].throughput = 0;
    device[i].lastThptUpdate = device[i].lastMinThptUpdate =
      device[i].lastHourThptUpdate = device[i].lastFiveMinsThptUpdate = time(NULL);
    device[i].lastMinEthernetBytes = device[i].lastFiveMinsEthernetBytes = 0;
    device[i].hostsno = 0;
    memset(&device[i].tcpGlobalTrafficStats, 0, sizeof(SimpleProtoTrafficInfo));
    memset(&device[i].udpGlobalTrafficStats, 0, sizeof(SimpleProtoTrafficInfo));
    memset(&device[i].icmpGlobalTrafficStats, 0, sizeof(SimpleProtoTrafficInfo));
  }
  
  FD_ZERO(&ipTrafficMatrixPromiscHosts);

  for(i=0; i<HASHNAMESIZE; i++) {
    if(tcpSession[i] != NULL) {
      free(tcpSession[i]);
      tcpSession[i] = NULL;
    }

    if(udpSession[i] != NULL) {
      free(udpSession[i]);
      udpSession[i] = NULL;
    }
  }

 #ifdef MULTITHREADED
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
  init_ssl();
#endif  

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
  int firstTime=1;

#ifdef HAVE_GDBM_H
  /* Courtesy of Andreas Pfaller <a.pfaller@pop.gun.de>. */
  if(snprintf(tmpBuf, sizeof(tmpBuf), "%s/dnsCache.db", dbPath) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  gdbm_file = gdbm_open (tmpBuf, 0, GDBM_WRCREAT, 00664, NULL);

 RETRY_INIT_GDBM:
  if(gdbm_file == NULL) {
    traceEvent(TRACE_ERROR, "Database '%s' open failed: %s\n", 
	       tmpBuf, gdbm_strerror(gdbm_errno));

#ifdef FALLBACK
    if(firstTime) {
      firstTime = 0;
      strcpy(dbPath, "/tmp");
      if(snprintf(tmpBuf, sizeof(tmpBuf), "%s/dnsCache.db", dbPath) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      gdbm_file = gdbm_open (tmpBuf, 0, GDBM_WRCREAT, 00664, NULL);
      traceEvent(TRACE_ERROR, "Fallback solution: reverting to /tmp for the database directory\n");
      goto RETRY_INIT_GDBM;
    } else
#else
      traceEvent(TRACE_ERROR, "Possible solution: please use '-P <directory>'\n");
#endif
      exit(-1);
  } else {
    /* Let's remove from the database entries that were not
       yet resolved in (i.e. those such as "*132.23.45.2*")
    */
    datum data_data, key_data, return_data = gdbm_firstkey (gdbm_file);
    u_int numDbEntries = 0;

    while(return_data.dptr != NULL) {
      numDbEntries++;
      key_data = return_data;
      return_data = gdbm_nextkey(gdbm_file, key_data);
      data_data = gdbm_fetch(gdbm_file, key_data);
      if((data_data.dptr != NULL) && (data_data.dptr[0] == '*')) {
	gdbm_delete(gdbm_file, key_data);
#ifdef DEBUG
	traceEvent(TRACE_INFO, "Deleted '%s' entry.\n", data_data.dptr);
#endif
	numDbEntries--;
      }

      if(data_data.dptr != NULL) free(data_data.dptr);
      free(key_data.dptr);
    }

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

#ifdef HAVE_GDBM_H
#ifdef MULTITHREADED
  createMutex(&gdbmMutex);
#endif
#endif

#ifdef MULTITHREADED
  packetQueueLen = maxPacketQueueLen = packetQueueHead = packetQueueTail = 0;
  device[actualDeviceId].droppedPackets = 0;
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
  traceEvent (TRACE_INFO, "Thread %d for Network Packet Capturing started (_main_ thread).\n",
	      dequeueThreadId);

  /*
   * (2) - HTS - Host Traffic Statistics
   */
  createThread(&hostTrafficStatsThreadId, updateHostTrafficStatsThptLoop, NULL);
  traceEvent (TRACE_INFO, "Thread %d for Host Traffic Statistics started.\n",
	      hostTrafficStatsThreadId);

  /*
   * (3) - TU - Throughput Update - optional
   */
  if (enableThUpdate) {
    createThread(&thptUpdateThreadId, updateThptLoop, NULL);
    traceEvent (TRACE_INFO, "Thread %d for Throughput Update started.\n", thptUpdateThreadId);
  }

  /*
   * (4) - SIH - Scan Idle Hosts - optional
   */
  if (enableIdleHosts) {
    createThread(&scanIdleThreadId, scanIdleLoop, NULL);
    traceEvent (TRACE_INFO, "Thread %d for Scan Idle Host started.\n", scanIdleThreadId);
  }

  /*
   * (5) - DBU - DB Update - optional
   */
  if (enableDBsupport) {
    createThread(&dbUpdateThreadId, updateDBHostsTrafficLoop, NULL);
    traceEvent (TRACE_INFO, "Thread %d for DB Update started.\n", dbUpdateThreadId);
  }

#ifdef ASYNC_ADDRESS_RESOLUTION
  if(numericFlag == 0) {
    memset(addressQueue, 0, sizeof(addressQueue));
    createMutex(&addressQueueMutex);
    /*
     * (6) - DNSAR - DNS Address Resolution - optional
     */
    createThread(&dequeueAddressThreadId, dequeueAddress, NULL);
    traceEvent (TRACE_INFO, "Thread %d for DNS Address Resolution started.\n", dequeueAddressThreadId);
  }
#endif
#endif
}

/* ******************************* */

void initApps(void) {
  if(isLsofPresent) {
#ifdef MULTITHREADED
    updateLsof = 1;
    memset(localPorts, 0, sizeof(localPorts)); /* localPorts is used by lsof */
    /*
     * (7) - LSOF - optional
     */
    createThread(&lsofThreadId, periodicLsofLoop, NULL);
    traceEvent (TRACE_INFO, "Thread %d for  LSOF support started.\n", lsofThreadId);
#else
    if(isLsofPresent) readLsofInfo();
    if(isNepedPresent) readNepedInfo();
#endif
  }
}

/* ******************************* */

void initDevices(char* devices) {
  char ebuf[PCAP_ERRBUF_SIZE];
  int i, j;

  memset(device, 0, sizeof(device));

  /* Determine the device name if not specified */
  ebuf[0] = '\0';

  if (devices == NULL) {
    char *tmpDev = pcap_lookupdev(ebuf);

    if(tmpDev == NULL) {
      traceEvent(TRACE_INFO, "Unable to locate default interface (%s)\n", ebuf);
      exit(-1);
    } else {
#ifdef WIN32
      if(isWinNT())
	{
	  static char tmpString[128];
	  int i, j;

	  for(j=0, i=0; !((tmpDev[i] == 0) && (tmpDev[i+1] == 0)); i++) {
	    if(tmpDev[i] != 0)
	      tmpString[j++] = tmpDev[i];
	  }

	  tmpString[j++] = 0;
	  tmpDev = tmpString;
	} else { /* WIN95/98 */
	  if(strncmp(tmpDev, "PPP", 3) == 0) {
	    /* Ethernet is the only handled interface
	       at the moment */
	    tmpDev = &tmpDev[strlen(tmpDev)+1];
	  }
	}
#endif
      device[0].name = strdup(tmpDev);
      numDevices=1;
    }
  } else {
    char *strtokState, *tmpDev;
    int i, found;

    tmpDev = strtok_r(devices, ",", &strtokState);
    numDevices = 0;

    while(tmpDev != NULL) {
      char *nwInterface;

      deviceSanityCheck(tmpDev);

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

      device[numDevices++].name = strdup(tmpDev);

      tmpDev = strtok_r(NULL, ",", &strtokState);
#ifndef MULTITHREADED
      if(tmpDev != NULL) {
	traceEvent(TRACE_WARNING, "WARNING: ntop can handle multiple interfaces only\n"
	       "         if thread support is enabled. Only interface\n"
	       "         '%s' will be used.\n", device[0].name);
	break;
      }
#endif
    }
  }


  /* ******************************************* */


  /* When sniffing from a multihomed interface
     it is necessary to add all the virtual interfaces
     because ntop has to know all the local addresses */
  for(i=0, j=numDevices; i<j; i++) {
    getLocalHostAddress(&device[i].ifAddr, device[i].name);

    if(strncmp(device[i].name, "lo", 3)) { /* Do not care of virtual loopback interfaces */
      int k;
      char tmpDevice[16];
      struct in_addr myLocalHostAddress;

      if(numDevices < MAX_NUM_DEVICES) {
	for(k=0; k<8; k++) {
	  if(snprintf(tmpDevice, sizeof(tmpDevice), "%s:%d", device[i].name, k) < 0) 
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  if(getLocalHostAddress(&myLocalHostAddress, tmpDevice) == 0) {
	    /* The virtual interface exists */
	    device[numDevices].ifAddr.s_addr = myLocalHostAddress.s_addr;
	    if(myLocalHostAddress.s_addr == device[i].ifAddr.s_addr)
	      continue; /* No virtual Interfaces */
	    device[numDevices++].name = strdup(tmpDevice);
#ifdef DEBUG
	    traceEvent(TRACE_INFO, "Added: %s\n", tmpDevice);
#endif
	  } else
	    break; /* No virtual interface */
	}
      }
    }
  }

  for(i=0; i<numDevices; i++) {
    getLocalHostAddress(&device[i].network, device[i].name);
  }
}


/* ******************************* */

static void initRules(char *rulesFile) {
  if(rulesFile[0] != '\0') {
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

      /* Support for virtual devices */
      char *column = strchr(device[i].name, ':');

      /*
	The timeout below for packet capture 
	has been set to 100ms.

	Courtesy of: Nicolai Petri <Nicolai@atomic.dk> 
      */
      if(column == NULL)
	device[i].pcapPtr = pcap_open_live(device[i].name, DEFAULT_SNAPLEN, 1,
					   100 /* ms */, ebuf);
      else {
	column[0] = 0;
	device[i].pcapPtr = pcap_open_live(device[i].name, DEFAULT_SNAPLEN, 1, 
					   100 /* ms */, ebuf);
	column[0] = ':';
      }

      if(device[i].pcapPtr == NULL) {
	traceEvent(TRACE_INFO, ebuf);
	exit(-1);
      }
    }

    for(i=0; i<numDevices; i++) {
      if (pcap_lookupnet(device[i].name, &device[i].network.s_addr, 
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
}

/* ******************************* */

void initDeviceDatalink(void) {
  int i;

  /* get datalink type */
#ifdef AIX
  /* This is a bug of libpcap on AIX */
  for(i=0; i<numDevices; i++) {
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
#else

#if defined(__FreeBSD__)
  for(i=0; i<numDevices; i++) {
    if(strncmp(device[i].name, "tun", 3) == 0)
      device[i].datalink = DLT_PPP;
    else
      device[i].datalink = pcap_datalink(device[i].pcapPtr);
  }

#else
  for(i=0; i<numDevices; i++) {
    device[i].datalink = pcap_datalink(device[i].pcapPtr);
  }
#endif
#endif
}

/* ******************************* */

void parseTrafficFilter(char *argv[], int optind) {
  /* Construct, compile and set filter */
  if(optind > 0) {
    char *expression;

    expression = copy_argv(argv + optind);
    if(expression != NULL) {
      int i;
      struct bpf_program fcode;

      for(i=0; i<numDevices; i++) {
	if((pcap_compile(device[i].pcapPtr, &fcode, expression, 1,
			 device[i].netmask.s_addr) < 0)
	   || (pcap_setfilter(device[i].pcapPtr, &fcode) < 0)) {
	  traceEvent(TRACE_ERROR,
		     "FATAL ERROR: wrong filter '%s' (%s) on interface %s\n",
		 expression, pcap_geterr(device[i].pcapPtr), device[i].name);
	  exit(-1);
	}
      }
    }
  }
}

/* ******************************* */

void initSignals(void) {
#ifndef WIN32
/*  RETSIGTYPE (*oldhandler)(int); */
#endif

#ifndef WIN32
    (void)setsignal(SIGALRM, dontFreeze);
#endif
    /*
      The handler below has been restored due to compatibility
      problems with om:
      Courtesy of Martin Lucina <mato@kotelna.sk>
    */
#ifndef WIN32
    (void)setsignal(SIGCHLD, handleDiedChild);
    /* signal(SIGCHLD, SIG_IGN); */
#endif

#ifndef WIN32
  /* Setup signal handlers */
  (void)setsignal(SIGTERM, cleanup);
  (void)setsignal(SIGINT,  cleanup);
  (void)setsignal(SIGHUP,  handleSigHup);

  /* Cooperate with nohup(1) */
/*
  if ((oldhandler = setsignal(SIGHUP, cleanup)) != SIG_DFL)
    (void)setsignal(SIGHUP, oldhandler);
*/
#endif
}

/* ***************************** */

void startSniffer(void) {
  int i; 

#ifdef MULTITHREADED
  for(i=0; i<numDevices; i++) {
    /*
     * (8) - NPS - Network Packet Sniffer (main thread)
     */
    createThread(&device[i].pcapDispatchThreadId, pcapDispatch, (char*)i);
    traceEvent (TRACE_INFO, "Thread %d for Network Packet Sniffing started (_main_ thread).\n",
		device[i].pcapDispatchThreadId);
  }
#endif
}
