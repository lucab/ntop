/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          HutuBttp://www.ntop.org
 *
 * Copyright (C) 1998-2011 Luca Deri <deri@ntop.org>
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
#include "globals-report.h"

/*
 * calculate the domain name for this host
 */
static void setDomainName(void) {
  int len;

#ifndef WIN32
  char *p;

  /*
   * The name of the local domain is now calculated properly
   * Kimmo Suominen <kim@tac.nyc.ny.us>
   */
  if(myGlobals.runningPref.domainName[0] == '\0') {
    if((getdomainname(myGlobals.runningPref.domainName, MAXHOSTNAMELEN) != 0)
       || (myGlobals.runningPref.domainName[0] == '\0')
       || (strcmp(myGlobals.runningPref.domainName, "(none)") == 0)) {
      if((gethostname(myGlobals.runningPref.domainName, MAXHOSTNAMELEN) == 0)
	 && ((p = memchr(myGlobals.runningPref.domainName, '.', MAXHOSTNAMELEN)) != NULL)) {
	myGlobals.runningPref.domainName[MAXHOSTNAMELEN - 1] = '\0';
	++p;
	memmove(myGlobals.runningPref.domainName, p, (MAXHOSTNAMELEN+myGlobals.runningPref.domainName-p));
      } else
	myGlobals.runningPref.domainName[0] = '\0';
    }

    /*
     * Still unresolved! Try again
     */
    if(myGlobals.runningPref.domainName[0] == '\0') {
      char szLclHost[64];
      struct hostent *lpstHostent;
      struct in_addr stLclAddr;

      gethostname(szLclHost, 64);
      lpstHostent = gethostbyname(szLclHost);
      if(lpstHostent) {
	struct hostent *hp;

	stLclAddr.s_addr = ntohl(*(lpstHostent->h_addr));

	hp = (struct hostent*)gethostbyaddr((char*)lpstHostent->h_addr, 4, AF_INET);

	if(hp && (hp->h_name)) {
	  char *dotp = (char*) hp->h_name;
	  int i;

	  for(i=0; (dotp[i] != '\0') && (dotp[i] != '.'); i++)
	    ;

	  if(dotp[i] == '.')
	    strncpy(myGlobals.runningPref.domainName, &dotp[i+1], MAXHOSTNAMELEN);
	}
      }
    }

    if(myGlobals.runningPref.domainName[0] == '\0') {
      /* Last chance.... */
      /* strncpy(myGlobals.runningPref.domainName, "please_set_your_local_domain.org", MAXHOSTNAMELEN); */
      ;
    }
  }
#endif

  len = strlen(myGlobals.runningPref.domainName)-1;

  while((len > 0) && (myGlobals.runningPref.domainName[len] != '.'))
    len--;

  if((len > 0) 
     && ((len+1) <  strlen(myGlobals.runningPref.domainName)))
    myGlobals.shortDomainName = strdup(&myGlobals.runningPref.domainName[len+1]);
  else
    myGlobals.shortDomainName = strdup(myGlobals.runningPref.domainName);
}

/* ------------------------------------------------------------ */

/*
 * Initialize memory/data for the protocols being monitored
 * looking at local or system wide "services" files
 */
void initIPServices(void) {
  FILE* fd;
  int idx, numSlots, len;

  traceEvent(CONST_TRACE_NOISY, "Initializing IP services");

  /* Let's count the entries first */
  numSlots = 0;
  for(idx=0; myGlobals.configFileDirs[idx] != NULL; idx++) {
    char tmpStr[256];

    safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "%s/services", myGlobals.configFileDirs[idx]);
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

  if(numSlots == 0) numSlots = CONST_HASH_INITIAL_SIZE;

  myGlobals.numActServices = 2*numSlots; /* Double the hash */

  /* ************************************* */

  len = sizeof(ServiceEntry*)*myGlobals.numActServices;
  myGlobals.udpSvc = (ServiceEntry**)malloc(len);
  memset(myGlobals.udpSvc, 0, len);
  myGlobals.tcpSvc = (ServiceEntry**)malloc(len);
  memset(myGlobals.tcpSvc, 0, len);

  for(idx=0; myGlobals.configFileDirs[idx] != NULL; idx++) {
    char tmpStr[256];

    safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "%s/services", myGlobals.configFileDirs[idx]);
    fd = fopen(tmpStr, "r");

    if(fd != NULL) {
      char tmpLine[512];

      while(fgets(tmpLine, 512, fd))
	if((tmpLine[0] != '#') && (strlen(tmpLine) > 10)) {
	  /* discard  9/tcp sink null */
	  char name[64], proto[16];
	  int numPort;

	  /* Fix below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
	  if(3 == sscanf(tmpLine, "%63[^ \t] %d/%15s", name, &numPort, proto)) {
	    /* traceEvent(CONST_TRACE_INFO, "'%s' - '%s' - '%d'", name, proto, numPort); */

	    if(strcmp(proto, "tcp") == 0)
	      addPortHashEntry(myGlobals.tcpSvc, numPort, name);
	    else
	      addPortHashEntry(myGlobals.udpSvc, numPort, name);
	  }
	}
      fclose(fd);
      break;
    }
  }

  /* Add some basic services, just in case they
     are not included in /etc/services */
  addPortHashEntry(myGlobals.tcpSvc, 21,  "ftp");
  addPortHashEntry(myGlobals.tcpSvc, 20,  "ftp-data");
  addPortHashEntry(myGlobals.tcpSvc, 23,  "telnet");
  addPortHashEntry(myGlobals.tcpSvc, 42,  "name");
  addPortHashEntry(myGlobals.tcpSvc, 80,  "http");
  addPortHashEntry(myGlobals.tcpSvc, 443, "https");

  addPortHashEntry(myGlobals.udpSvc, 137, "netbios-ns");
  addPortHashEntry(myGlobals.tcpSvc, 137, "netbios-ns");
  addPortHashEntry(myGlobals.udpSvc, 138, "netbios-dgm");
  addPortHashEntry(myGlobals.tcpSvc, 138, "netbios-dgm");
  addPortHashEntry(myGlobals.udpSvc, 139, "netbios-ssn");
  addPortHashEntry(myGlobals.tcpSvc, 139, "netbios-ssn");

  addPortHashEntry(myGlobals.tcpSvc, 109, "pop-2");
  addPortHashEntry(myGlobals.tcpSvc, 110, "pop-3");
  addPortHashEntry(myGlobals.tcpSvc, 1109,"kpop");

  addPortHashEntry(myGlobals.udpSvc, 161, "snmp");
  addPortHashEntry(myGlobals.udpSvc, 162, "snmp-trap");
  addPortHashEntry(myGlobals.udpSvc, 635, "mount");
  addPortHashEntry(myGlobals.udpSvc, 640, "pcnfs");
  addPortHashEntry(myGlobals.udpSvc, 650, "bwnfs");
  addPortHashEntry(myGlobals.udpSvc, 2049,"nfsd");
  addPortHashEntry(myGlobals.udpSvc, 1110,"nfsd-status");
}

/* ******************************* */

void createDeviceIpProtosList(int devIdx) {
  size_t len = (size_t)myGlobals.numIpProtosList*sizeof(TrafficCounter);

  if(len > 0) {
    if(myGlobals.device[devIdx].ipProtosList != NULL)
      free(myGlobals.device[devIdx].ipProtosList);
    if((myGlobals.device[devIdx].ipProtosList = (TrafficCounter*)malloc(len)) == NULL)
      return;
    memset(myGlobals.device[devIdx].ipProtosList, 0, len);
  }
}

/* ******************************* */

/*
  Function below courtesy of
  Eric Dumazet <dada1@cosmosbay.com>
*/
void resetDevice(int devIdx, short fullReset) {
  int len;
  void *ptr;

  if(myGlobals.device[devIdx].dummyDevice) return;

  myGlobals.device[devIdx].actualHashSize = CONST_HASH_INITIAL_SIZE;

  len = CONST_HASH_INITIAL_SIZE * sizeof(HostTraffic*);
  if(myGlobals.device[devIdx].hash_hostTraffic == NULL) {
    ptr = calloc(CONST_HASH_INITIAL_SIZE, sizeof(HostTraffic*));
    myGlobals.device[devIdx].hash_hostTraffic = ptr;
  }

  memset(myGlobals.device[devIdx].hash_hostTraffic, 0, len);

  resetTrafficCounter(&myGlobals.device[devIdx].receivedPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].droppedPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].ethernetPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].broadcastPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].multicastPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].ipPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].ethernetBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].ipv4Bytes);
  resetTrafficCounter(&myGlobals.device[devIdx].fragmentedIpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].tcpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].udpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].otherIpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].icmpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].dlcBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].stpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].ipsecBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].netbiosBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].arpRarpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].egpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].greBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].ipv6Bytes);
  resetTrafficCounter(&myGlobals.device[devIdx].otherBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].lastMinEthernetBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].lastFiveMinsEthernetBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].lastMinEthernetPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].lastFiveMinsEthernetPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].lastNumEthernetPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].lastEthernetPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].lastTotalPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].lastBroadcastPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].lastMulticastPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].lastEthernetBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].lastIpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].lastNonIpBytes);
  memset(&myGlobals.device[devIdx].rcvdPktStats, 0, sizeof(PacketStats));
  memset(&myGlobals.device[devIdx].rcvdPktTTLStats, 0, sizeof(TTLstats));
  myGlobals.device[devIdx].peakThroughput = 0;
  myGlobals.device[devIdx].actualThpt = 0;
  myGlobals.device[devIdx].lastMinThpt = 0;
  myGlobals.device[devIdx].lastFiveMinsThpt = 0;
  myGlobals.device[devIdx].peakPacketThroughput = 0;
  myGlobals.device[devIdx].actualPktsThpt = 0;
  myGlobals.device[devIdx].lastMinPktsThpt = 0;
  myGlobals.device[devIdx].lastFiveMinsPktsThpt = 0;
  myGlobals.device[devIdx].lastThptUpdate = 0;
  myGlobals.device[devIdx].lastMinThptUpdate = 0;
  myGlobals.device[devIdx].lastHourThptUpdate = 0;
  myGlobals.device[devIdx].lastFiveMinsThptUpdate = 0;
  myGlobals.device[devIdx].throughput = 0;
  myGlobals.device[devIdx].packetThroughput = 0;
  myGlobals.device[devIdx].numThptSamples = 0;
  myGlobals.device[devIdx].last60MinutesThptIdx = 0;
  myGlobals.device[devIdx].last24HoursThptIdx = 0;
  myGlobals.device[devIdx].last30daysThptIdx = 0;

  if(myGlobals.pcap_file_list == NULL) {
    myGlobals.device[devIdx].lastThptUpdate = myGlobals.device[devIdx].lastMinThptUpdate =
      myGlobals.device[devIdx].lastHourThptUpdate = myGlobals.device[devIdx].lastFiveMinsThptUpdate = time(NULL);
  }
  resetTrafficCounter(&myGlobals.device[devIdx].lastMinEthernetBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].lastFiveMinsEthernetBytes);
  memset(&myGlobals.device[devIdx].tcpGlobalTrafficStats, 0, sizeof(SimpleProtoTrafficInfo));
  memset(&myGlobals.device[devIdx].udpGlobalTrafficStats, 0, sizeof(SimpleProtoTrafficInfo));
  memset(&myGlobals.device[devIdx].icmpGlobalTrafficStats, 0, sizeof(SimpleProtoTrafficInfo));
  memset(myGlobals.device[devIdx].last60MinutesThpt, 0, sizeof(myGlobals.device[devIdx].last60MinutesThpt));
  memset(myGlobals.device[devIdx].last24HoursThpt, 0, sizeof(myGlobals.device[devIdx].last24HoursThpt));
  memset(myGlobals.device[devIdx].last30daysThpt, 0, sizeof(myGlobals.device[devIdx].last30daysThpt));
  myGlobals.device[devIdx].last60MinutesThptIdx=0, myGlobals.device[devIdx].last24HoursThptIdx=0,
    myGlobals.device[devIdx].last30daysThptIdx=0;
  myGlobals.device[devIdx].hostsno = 1; /* Broadcast entry */

  if(fullReset) {
    if(myGlobals.device[devIdx].netflowGlobals != NULL)
      free(myGlobals.device[devIdx].netflowGlobals);
    myGlobals.device[devIdx].netflowGlobals = NULL;
    
    if(myGlobals.device[devIdx].sflowGlobals != NULL)
      free(myGlobals.device[devIdx].sflowGlobals);
    myGlobals.device[devIdx].sflowGlobals = NULL;
  }
  
  len = (size_t)myGlobals.numIpProtosToMonitor*sizeof(SimpleProtoTrafficInfo);

  if(myGlobals.device[devIdx].ipProtoStats == NULL)
    myGlobals.device[devIdx].ipProtoStats = (SimpleProtoTrafficInfo*)malloc(len);

  memset(myGlobals.device[devIdx].ipProtoStats, 0, len);

  if(myGlobals.device[devIdx].ipProtosList != NULL) {
    free(myGlobals.device[devIdx].ipProtosList);
    myGlobals.device[devIdx].ipProtosList = NULL;
  }

  createDeviceIpProtosList(devIdx);
}

/* ******************************************* */

void initCounters(void) {
  int len, i;

  setDomainName();

  _in6addr_linklocal_allnodes.s6_addr[0] = 0xff;
  _in6addr_linklocal_allnodes.s6_addr[1] = 0x02;
  _in6addr_linklocal_allnodes.s6_addr[2] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[3] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[4] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[5] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[6] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[7] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[8] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[9] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[10] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[11] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[12] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[13] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[14] = 0x00;
  _in6addr_linklocal_allnodes.s6_addr[15] = 0x01;

  memset(myGlobals.transTimeHash, 0, sizeof(myGlobals.transTimeHash));
  memset(myGlobals.dummyEthAddress, 0, LEN_ETHERNET_ADDRESS);

  for(len=0; len<LEN_ETHERNET_ADDRESS; len++)
    myGlobals.dummyEthAddress[len] = len;

  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.runningPref.enableSessionHandling) {
      len = sizeof(IPSession*)*MAX_TOT_NUM_SESSIONS;
      myGlobals.device[i].tcpSession = (IPSession**)malloc(len);
      memset(myGlobals.device[i].tcpSession, 0, len);
    } else {
      myGlobals.device[i].tcpSession     = NULL;
    }

    myGlobals.device[i].fragmentList = NULL;
  }

  myGlobals.hashCollisionsLookup     = 0;

  if(myGlobals.pcap_file_list == NULL)
    myGlobals.initialSniffTime = myGlobals.lastRefreshTime = time(NULL);  
  else
    myGlobals.initialSniffTime = 0; /* We set the start when first pkt is
                                       * read */  

/* TODO why here AND in globals-core.c? */
  myGlobals.numHandledSIGPIPEerrors = 0;
  for (i=0; i<=1; i++) {
    myGlobals.numHandledRequests[i] = 0;
    myGlobals.numHandledBadrequests[i] = 0;
    myGlobals.numSuccessfulRequests[i] = 0;
    myGlobals.numUnsuccessfulInvalidrequests[i] = 0;
    myGlobals.numUnsuccessfulInvalidmethod[i] = 0;
    myGlobals.numUnsuccessfulInvalidversion[i] = 0;
    myGlobals.numUnsuccessfulTimeout[i] = 0;
    myGlobals.numUnsuccessfulNotfound[i] = 0;
    myGlobals.numUnsuccessfulDenied[i] = 0;
    myGlobals.numUnsuccessfulForbidden[i] = 0;
  }
  myGlobals.numSSIRequests = 0;
  myGlobals.numBadSSIRequests = 0;
  myGlobals.numHandledSSIRequests = 0;

  myGlobals.webServerRequestQueueLength = DEFAULT_WEBSERVER_REQUEST_QUEUE_LEN;

  myGlobals.hostsCacheLen = 0;
  myGlobals.hostsCacheLenMax = 0;
  myGlobals.hostsCacheReused = 0;
#ifdef PARM_USE_SESSIONS_CACHE
  myGlobals.sessionsCacheLen = 0;
  myGlobals.sessionsCacheLenMax = 0;
  myGlobals.sessionsCacheReused = 0;
#endif

}

/* ******************************* */

void resetStats(int deviceId) {
  u_int j;

  traceEvent(CONST_TRACE_INFO, "Resetting traffic statistics for device %s",
	     myGlobals.device[deviceId].humanFriendlyName);

  if(myGlobals.purgeMutex.isInitialized)
    accessMutex(&myGlobals.purgeMutex, "resetStats");

  for(j=FIRST_HOSTS_ENTRY; j<myGlobals.device[deviceId].actualHashSize; j++) {
    HostTraffic *el = myGlobals.device[deviceId].hash_hostTraffic[j], *elNext;

    if(el) lockExclusiveHostsHashMutex(el, "resetStats");

    while(el != NULL) {
      elNext = el->next;

      if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry)) {
	unlockExclusiveHostsHashMutex(el);
	freeHostInfo(el, deviceId);
	if(elNext) lockExclusiveHostsHashMutex(elNext, "resetStats");
      } else {
	if(!elNext) 
	  unlockExclusiveHostsHashMutex(el);
      }

      el = elNext;
    }

    myGlobals.device[deviceId].hash_hostTraffic[j] = NULL;
  }

  resetDevice(deviceId, 0);

  if(myGlobals.device[deviceId].tcpSession != NULL) {
    for(j=0; j<MAX_TOT_NUM_SESSIONS; j++)
      if(myGlobals.device[deviceId].tcpSession[j] != NULL) {
	free(myGlobals.device[deviceId].tcpSession[j]);
	myGlobals.device[deviceId].tcpSession[j] = NULL;
      }
  }
  
  myGlobals.device[deviceId].hash_hostTraffic[BROADCAST_HOSTS_ENTRY] = myGlobals.broadcastEntry;
  myGlobals.broadcastEntry->hostSerial.serialType = SERIAL_IPV4;
  myGlobals.broadcastEntry->hostSerial.value.ipSerial.ipAddress.Ip4Address.s_addr = -1;
  myGlobals.broadcastEntry->next = NULL;
  setHostFlag(FLAG_BROADCAST_HOST, myGlobals.broadcastEntry);

  if(myGlobals.otherHostEntry != myGlobals.broadcastEntry) {
    myGlobals.device[deviceId].hash_hostTraffic[OTHER_HOSTS_ENTRY] = myGlobals.otherHostEntry;
    /* Dirty trick */
    myGlobals.otherHostEntry->hostSerial.serialType = SERIAL_IPV4;
    myGlobals.otherHostEntry->hostSerial.value.ipSerial.ipAddress.Ip4Address.s_addr = -1;
    myGlobals.otherHostEntry->next = NULL;
  }

  if(myGlobals.purgeMutex.isInitialized)
    releaseMutex(&myGlobals.purgeMutex);
}

/* ******************************* */

void initSingleGdbm(GDBM_FILE *database,
		    char *dbName, char *directory,
		    int doUnlink, struct stat *statbuf) {
  char tmpBuf[200], theDate[48];
  time_t st_time, now;
  struct tm t;
  int d;

  /* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au>. */
  memset(&tmpBuf, 0, sizeof(tmpBuf));
 
#ifdef WIN32
  {
    unsigned long driveSerial;
  
    get_serial(&driveSerial);

    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%s/%u",
		  directory != NULL ? directory : myGlobals.dbPath, driveSerial);

    mkdir_p("DB", tmpBuf, 0x777);

    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%s/%u/%s",
		  directory != NULL ? directory : myGlobals.dbPath, driveSerial,
		  dbName);
  }
#else
  safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%s/%s",
	      directory != NULL ? directory : myGlobals.dbPath,
	      dbName);
#endif

  if(statbuf) {
    if(stat(tmpBuf, statbuf) == 0) {
      /* File already exists */
      if((doUnlink != TRUE) && (doUnlink != FALSE)) {

	traceEvent(CONST_TRACE_INFO, "Checking age of database %s", tmpBuf);

	/* Some systems or mounts don't maintain atime so fox 'em */
	if (statbuf->st_atime > 0)
	  st_time = statbuf->st_atime;
	else
	  st_time = 0;
	if((statbuf->st_mtime) && (statbuf->st_mtime > st_time))
	  st_time = statbuf->st_mtime;
	if((statbuf->st_ctime) && (statbuf->st_ctime > st_time))
	  st_time = statbuf->st_ctime;

	strftime(theDate, sizeof(theDate)-1, CONST_LOCALE_TIMESPEC, localtime_r(&st_time, &t));
	theDate[sizeof(theDate)-1] = '\0';
	now  = time(NULL);
	traceEvent(CONST_TRACE_NOISY,
		   "...last create/modify/access was %s, %d second(s) ago",
		   theDate,
		   d = difftime(now, st_time));

	if(d > (15 * 60)) {
	  traceEvent(CONST_TRACE_INFO, "...older, will recreate it");
	  doUnlink = TRUE;
	} else {
	  traceEvent(CONST_TRACE_INFO, "...new enough, will not recreate it");
	  doUnlink = FALSE; /* New enough */
	}
      }
    } else {
      memset(statbuf, 0, sizeof(struct stat));
    }
  }

  if(doUnlink == TRUE)
    unlink(tmpBuf); /* Delete the old one (if present) */

  traceEvent(CONST_TRACE_NOISY, "%s database '%s'",
	     doUnlink == TRUE ? "Creating" : "Opening",
	     tmpBuf);
  *database = gdbm_open (tmpBuf, 0, GDBM_WRCREAT, 00640, NULL);

  if(*database == NULL) {
    traceEvent(CONST_TRACE_ERROR, "....open of %s failed: %s",
	       tmpBuf,
#if defined(WIN32) && defined(__GNUC__)
	       "unknown gdbm errno"
#else
	       gdbm_strerror(gdbm_errno)
#endif
	       );

    if(directory == NULL)
      traceEvent(CONST_TRACE_INFO, "Possible solution: please use '-P <directory>'");
    else {
      traceEvent(CONST_TRACE_INFO, "1. Is another instance of ntop running?");
      traceEvent(CONST_TRACE_INFO, "2. Make sure that the user you specified can write in the target directory");
    }
    traceEvent(CONST_TRACE_FATALERROR, "GDBM open failed, ntop shutting down...");
    exit(7); /* Just in case */
  }
}

/* ************************************************************ */

#ifdef HAVE_PTHREAD_ATFORK
void reinitMutexes (void) {
  int i;

/*
 * Although the fork()ed child gets a copy of the storage for the mutexes,
 * in fact, these are invalid copies and the mutex must be cleared and
 * reinitialized.  Read man pthread_atfork for lots more...
 *
 * Note that once this reinit happens, THEY ARE NOT THE SAME MUTEX.
 * They have the same 'name', but are different blocks of (unshared) storage.
 *
 * Although the ntop 2.2 code has the ILLUSION that the resources are protected
 * they are not!  The code is wrong, but a real fix will have to be in 2.3...
 * (BMS 06-2003, ntop 2.2c)
 *
 * NOTE: For the logViewMutex, we must use the native calls, not the enhanced ones
 *       in util.c - otherwise the calls to traceEvent() cause deadlocks!
 */
  createMutex(&myGlobals.logViewMutex);
  createMutex(&myGlobals.gdbmMutex);        /* data to synchronize thread access to db files */
  createMutex(&myGlobals.portsMutex);       /* Avoid race conditions while handling ports */

  for(i=0; i<NUM_SESSION_MUTEXES; i++)
    createMutex(&myGlobals.tcpSessionsMutex[i]); /* data to synchronize TCP sessions access */

    createMutex(&myGlobals.purgePortsMutex);  /* data to synchronize port purge access */
  createMutex(&myGlobals.purgePortsMutex);  /* data to synchronize port purge access */

  for(i=0; i<CONST_HASH_INITIAL_SIZE; i++) {
    createMutex(&myGlobals.hostsHashMutex[i]);
    myGlobals.hostsHashMutexNumLocks[i] = 0;
  }

  createMutex(&myGlobals.securityItemsMutex);
  createMutex(&myGlobals.hostsHashLockMutex);
}
#endif /* HAVE_PTHREAD_ATFORK */

/*
 * Initialize all the threads used by ntop to:
 * a) sniff packets from NICs and push them in internal data structures
 * b) pop and decode packets
 * c) collect data
 * d) display/emit information
 */
void initThreads(void) {
  int i;

  /*
   * Create the thread (3) - SFP - Scan Fingerprints
   */
  createThread(&myGlobals.scanFingerprintsThreadId, scanFingerprintLoop, NULL);
  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: SFP: Started thread for fingerprinting",
	     (long)myGlobals.scanFingerprintsThreadId);

  /*
   * Create the thread (4) - SIH - Scan Idle Hosts - optional
   */
  createThread(&myGlobals.scanIdleThreadId, scanIdleLoop, NULL);
  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: SIH: Started thread for idle hosts detection",
             (long)myGlobals.scanIdleThreadId);

  if(myGlobals.runningPref.numericFlag != noDnsResolution) {
    createMutex(&myGlobals.addressResolutionMutex);
 
#if defined(HAVE_GETHOSTBYADDR_R)
    myGlobals.numDequeueAddressThreads = MAX_NUM_DEQUEUE_ADDRESS_THREADS;
#else
    myGlobals.numDequeueAddressThreads = 1;
#endif

    initAddressResolution();
   
    /*
     * Create the thread (5) - DNSAR - DNS Address Resolution - optional
     */  
    for(i=0; i<myGlobals.numDequeueAddressThreads; i++) {
      createThread(&myGlobals.dequeueAddressThreadId[i], dequeueAddress, (char*)((long)i));
      traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: DNSAR(%d): Started thread for DNS address resolution",
		 (long)myGlobals.dequeueAddressThreadId[i], i+1);
    }
  }
}

/*
 * Initialize helper applications
 */
void initApps(void) {
  traceEvent(CONST_TRACE_INFO, "Initializing external applications");
  /* Nothing to do at the moment */
}

/* ******************************* */

void initDeviceSemaphores(int deviceId) {
  traceEvent(CONST_TRACE_INFO, "Initializing device %s (%d)",
	     myGlobals.device[deviceId].name, deviceId);
    
  createMutex(&myGlobals.device[deviceId].counterMutex);
  createMutex(&myGlobals.device[deviceId].asMutex);
  createMutex(&myGlobals.device[deviceId].packetProcessMutex);
  createMutex(&myGlobals.device[deviceId].packetQueueMutex);
  if(myGlobals.device[deviceId].packetQueue) 
    memset(myGlobals.device[deviceId].packetQueue, 0,
	   sizeof(PacketInformation) * (CONST_PACKET_QUEUE_LENGTH+1));
  myGlobals.device[deviceId].packetQueueLen           = 0;
  myGlobals.device[deviceId].maxPacketQueueLen        = 0;
  myGlobals.device[deviceId].packetQueueHead          = 0;
  myGlobals.device[deviceId].packetQueueTail          = 0;

  createCondvar(&myGlobals.device[deviceId].queueCondvar);
}

/* ******************************* */

void allocDeviceMemory(int deviceId) {
  if(!myGlobals.device[deviceId].ipPorts)
    myGlobals.device[deviceId].ipPorts = 
      (PortCounter**)calloc(sizeof(PortCounter*), MAX_IP_PORT);
  
  if(!myGlobals.device[deviceId].packetQueue)
    myGlobals.device[deviceId].packetQueue = 
      (PacketInformation*)calloc(sizeof(PacketInformation), (CONST_PACKET_QUEUE_LENGTH+1));
}

/* ******************************* */

/*
 * Initialize the table of NICs enabled for packet sniffing
 *
 * Unless we are reading data from a file:
 *
 * 1. find a suitable interface, if none ws not specified one
 *    using pcap_lookupdev()
 * 2. get the interface network number and its mask
 *    using pcap_lookupnet()
 * 3. get the type of the underlying network and the data-link encapsulation method
 *    using pcap_datalink()
 *
 * if device is "none" it adds a dummy interface
 */
void addDevice(char* deviceName, char* deviceDescr) {
  int i, deviceId, mallocLen;
  char *workDevices = NULL;
  char myName[255], *column = NULL, ebuf[CONST_SIZE_PCAP_ERR_BUF], tmpStr[64];

  ebuf[0] = '\0', myName[0] = '\0';

  if(deviceName == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Attempt to add a NULL device");
    return;
  }

  /* Remove unwanted characters */
  sanitizeIfName(deviceName);

  traceEvent(CONST_TRACE_NOISY, "Adding network device %s", deviceName);

  if((deviceName != NULL) && (strcmp(deviceName, "none") == 0)) {
    deviceId = createDummyInterface("none");
    traceEvent(CONST_TRACE_INFO, "-i none, so initialized only a dummy device");
  } else {
    deviceId = myGlobals.numDevices;

    safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "device.name.%s", deviceName);
    if(fetchPrefsValue(tmpStr, ebuf, sizeof(ebuf)) != -1)
      myGlobals.device[deviceId].humanFriendlyName = strdup(ebuf);
    else
      myGlobals.device[deviceId].humanFriendlyName = strdup(deviceDescr);

    allocDeviceMemory(deviceId);

    myGlobals.device[deviceId].name         = strdup(deviceName);
    myGlobals.device[deviceId].samplingRate =  myGlobals.runningPref.samplingRate;
    calculateUniqueInterfaceName(deviceId);
    myGlobals.numDevices++;

    if(myGlobals.numDevices >= MAX_NUM_DEVICES) {
      static u_char msgSent = 0;

      if(!msgSent) {
	traceEvent(CONST_TRACE_WARNING, "ntop can handle up to %d interfaces",
		   myGlobals.numDevices);
	traceEvent(CONST_TRACE_NOISY, "Additional interfaces will be ignored");
	msgSent = 1;
      }
    }

    /* ********************************************* */

#ifndef WIN32
    column = strchr(myGlobals.device[deviceId].name, ':');
#endif

    /*
      The timeout below for packet capture
      has been set to 100ms.

      Courtesy of: Nicolai Petri <Nicolai@atomic.dk>
    */
    if((!myGlobals.device[deviceId].dummyDevice)
       && (!myGlobals.device[deviceId].virtualDevice)
       && (column == NULL)) {
#ifdef WIN32
      if(strncmp(myGlobals.device[deviceId].name, "rpcap:", 6) != 0) {

	/*
	   The code below has been disabled because it seems
	   that with some network adapters, although there are no
	   errors at all, the stack memory is corrupted and this
	   will cause troubles later on
	*/
#if 0
	NetType adapter;

	LPADAPTER a = PacketOpenAdapter((LPTSTR)myGlobals.device[deviceId].name);

	if(a == NULL) {
	  traceEvent(CONST_TRACE_FATALERROR, "Unable to open device '%s' (invalid name?)",
		     myGlobals.device[deviceId].name);
	  exit(8); /* Just in case */
	}
	if(PacketGetNetType (a,&adapter)) {
	  myGlobals.device[deviceId].deviceSpeed = adapter.LinkSpeed;
	} else
	  PacketCloseAdapter((LPTSTR)myGlobals.device[deviceId].name);
#endif
      }
#else /* not WIN32 */
    if(setuid(0) == -1) {
      traceEvent(CONST_TRACE_FATALERROR, "Unable to become root");
      exit(9); /* Just in case */
    }
#endif

    
    myGlobals.device[deviceId].pcapPtr =
      pcap_open_live(myGlobals.device[deviceId].name,
		     MAX_PACKET_LEN,
		     myGlobals.runningPref.disablePromiscuousMode == 1 ? 0 : 1,
		     1000 /* ms */, ebuf);    

      if(myGlobals.device[deviceId].pcapPtr == NULL) {
	traceEvent(CONST_TRACE_ERROR, "pcap_open_live(): '%s'", ebuf);
	if(myGlobals.runningPref.disablePromiscuousMode == 1)
	  traceEvent(CONST_TRACE_INFO,
		     "Sorry, but on this system, even with -s, it appears "
		     "that ntop must be started as root");
	traceEvent(CONST_TRACE_INFO, "Please correct the problem or select "
		   "a different interface using the -i flag");
	traceEvent(CONST_TRACE_FATALERROR, "Not root, ntop shutting down...");
        exit(10); /* Just in case */
      }

      if(myGlobals.runningPref.pcapLog != NULL) {
	if(strlen(myGlobals.runningPref.pcapLog) > 64)
	  myGlobals.runningPref.pcapLog[64] = '\0';
        safe_snprintf(__FILE__, __LINE__, myName, sizeof(myName), "%s%c%s.%s.pcap",
		      myGlobals.runningPref.pcapLogBasePath, /* Added by Ola Lundqvist <opal@debian.org> */
		      CONST_PATH_SEP, myGlobals.runningPref.pcapLog,
		      myGlobals.device[deviceId].uniqueIfName != NULL ?
		      myGlobals.device[deviceId].uniqueIfName :
		      myGlobals.device[deviceId].name);

	myGlobals.device[deviceId].pcapDumper = pcap_dump_open(myGlobals.device[deviceId].pcapPtr, myName);

	if(myGlobals.device[deviceId].pcapDumper == NULL) {
          traceEvent(CONST_TRACE_FATALERROR, "pcap_dump_open(..., '%s') failed", myName);
	  exit(11); /* Just in case */
	}

	traceEvent(CONST_TRACE_NOISY, "Saving packets into file %s", myName);
      }

    if(myGlobals.runningPref.enableSuspiciousPacketDump) {
        if(myGlobals.pcap_file_list == NULL)
	  safe_snprintf(__FILE__, __LINE__, myName, sizeof(myName), "%s%cntop-suspicious-pkts.dev%s.pcap",
			myGlobals.runningPref.pcapLogBasePath, /* Added by Ola Lundqvist <opal@debian.org> */
			CONST_PATH_SEP,
			myGlobals.device[deviceId].uniqueIfName != NULL ?
			myGlobals.device[deviceId].uniqueIfName :
			myGlobals.device[deviceId].name);
	else
	  safe_snprintf(__FILE__, __LINE__, myName, sizeof(myName), "%s%cntop-suspicious-pkts.pcap",
			myGlobals.pcap_file_list,
			CONST_PATH_SEP);

	myGlobals.device[deviceId].pcapErrDumper = pcap_dump_open(myGlobals.device[deviceId].pcapPtr, myName);

	if(myGlobals.device[deviceId].pcapErrDumper == NULL) {
          myGlobals.runningPref.enableSuspiciousPacketDump = 0;
	  traceEvent(CONST_TRACE_ERROR, "pcap_dump_open(..., '%s') failed (suspicious packets)", myName);
	  traceEvent(CONST_TRACE_INFO, "Continuing without suspicious packet dump");
        } else
	  traceEvent(CONST_TRACE_NOISY, "Saving packets into file %s", myName);
      }

      if(myGlobals.runningPref.enableOtherPacketDump) {
        safe_snprintf(__FILE__, __LINE__, myName, sizeof(myName), "%s%cntop-other-pkts.%s.pcap",
		      myGlobals.runningPref.pcapLogBasePath,
		      CONST_PATH_SEP,
		      myGlobals.device[deviceId].uniqueIfName != NULL ?
		      myGlobals.device[deviceId].uniqueIfName :
		      myGlobals.device[deviceId].name);

	myGlobals.device[deviceId].pcapOtherDumper = pcap_dump_open(myGlobals.device[deviceId].pcapPtr, myName);

	if(myGlobals.device[deviceId].pcapOtherDumper == NULL) {
          myGlobals.runningPref.enableOtherPacketDump = 0;
	  traceEvent(CONST_TRACE_ERROR, "pcap_dump_open(..., '%s') failed (other (unknown) packets)", myName);
	  traceEvent(CONST_TRACE_INFO, "Continuing without other (unknown) packet dump");
        } else
	  traceEvent(CONST_TRACE_NOISY, "Saving packets into file %s", myName);
      }
    } else {
      myGlobals.device[deviceId].virtualDevice = 1;
      if(column != NULL) column[0] = ':';
    }

    if((!myGlobals.device[deviceId].virtualDevice)
       && (pcap_lookupnet(myGlobals.device[deviceId].name,
			  (bpf_u_int32*)&myGlobals.device[deviceId].network.s_addr,
			  (bpf_u_int32*)&myGlobals.device[deviceId].netmask.s_addr, ebuf) < 0)) {
      /* Fix for IP-less interfaces (e.g. bridge)
	 Courtesy of Diana Eichert <deicher@sandia.gov>
      */
      myGlobals.device[deviceId].network.s_addr = htonl(0);
      myGlobals.device[deviceId].netmask.s_addr = htonl(0xFFFFFFFF);
    } else {
      myGlobals.device[deviceId].network.s_addr = htonl(myGlobals.device[deviceId].network.s_addr);
      myGlobals.device[deviceId].netmask.s_addr = htonl(myGlobals.device[deviceId].netmask.s_addr);
    }

    /* ******************************************* */

    if(myGlobals.device[deviceId].netmask.s_addr == 0) {
      /* In this case we are using a dump file */
      myGlobals.device[deviceId].netmask.s_addr = 0xFFFFFF00; /* dummy */
    }

    addDeviceNetworkToKnownSubnetList(&myGlobals.device[deviceId]);

    if((myGlobals.device[deviceId].network.s_addr == 0) &&
       (myGlobals.device[deviceId].netmask.s_addr == 0xFFFFFFFF) ) {
      /* Unnumbered interface... */
      myGlobals.device[deviceId].numHosts = MAX_SUBNET_HOSTS;
    } else {
      myGlobals.device[deviceId].numHosts = 0xFFFFFFFF - myGlobals.device[deviceId].netmask.s_addr + 1;

      /* Add some room for multicast hosts
       * This is an arbitrary guess.
       * We use the log function to limit growth for large networks, while the factor of 50
       * is designed to ensure a certain minimal # even for smaller networks
       */
      myGlobals.device[deviceId].numHosts +=
	ceil(log((double)(0xFFFFFFFF - myGlobals.device[deviceId].netmask.s_addr + 1))+1.0)*50;
    }

    if(myGlobals.device[deviceId].numHosts > MAX_SUBNET_HOSTS) {
      myGlobals.device[deviceId].numHosts = MAX_SUBNET_HOSTS;
      traceEvent(CONST_TRACE_WARNING, "Truncated network size (device %s) to %d hosts (real netmask %s)",
		 myGlobals.device[deviceId].name, myGlobals.device[deviceId].numHosts,
		 intoa(myGlobals.device[deviceId].netmask));
    } else {
      traceEvent(CONST_TRACE_NOISY, "Interface '%s' (netmask %s) computed network size is %d hosts",
		 myGlobals.device[deviceId].name,
		 intoa(myGlobals.device[deviceId].netmask),
		 myGlobals.device[deviceId].numHosts);
    }
  }

  /* ********************************************* */

  if(!(myGlobals.device[deviceId].dummyDevice || myGlobals.device[deviceId].virtualDevice)) {
    u_int8_t netmask_v6;
    
    getLocalHostAddress(&myGlobals.device[deviceId].ifAddr, &netmask_v6, myGlobals.device[deviceId].name);
    myGlobals.device[deviceId].v6Addrs = getLocalHostAddressv6(myGlobals.device[deviceId].v6Addrs, 
							       myGlobals.device[deviceId].name);
	if(myGlobals.device[deviceId].network.s_addr == 0) {
		myGlobals.device[deviceId].netmask.s_addr = 0xFFFFFF00;/* /24 */
		myGlobals.device[deviceId].network.s_addr = myGlobals.device[deviceId].ifAddr.s_addr 
		  & myGlobals.device[deviceId].netmask.s_addr;
	}
  }

  mallocLen = 2;
  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.device[i].name != NULL)
      mallocLen += strlen(myGlobals.device[i].name) + 2;
  }

  workDevices = calloc(mallocLen+1, 1);
  if(workDevices == NULL)
    return;
  else

  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.device[i].name != NULL) {
      int len = strlen(workDevices);
      safe_snprintf(__FILE__, __LINE__, 
		    &workDevices[len], mallocLen-len, 
		    "%s%s", (i > 0) ? ", " : "",
		    myGlobals.device[i].name);
    }
  }

  if(myGlobals.runningPref.devices != NULL)
    free(myGlobals.runningPref.devices);

  myGlobals.runningPref.devices = workDevices;

  /* ********************************************** */

#ifndef WIN32
  if(strncmp(myGlobals.device[deviceId].name, "lo", 2)) {
    /* Do not care of virtual loopback interfaces */
    int k;
    char tmpDeviceName[64];
    struct in_addr myLocalHostAddress;


    if((myGlobals.numDevices < (MAX_NUM_DEVICES-1))
       && strcmp(myGlobals.device[deviceId].name, "none")) {
      traceEvent(CONST_TRACE_INFO, "Checking %s for additional devices", myGlobals.device[deviceId].name);
      for(k=0; k<=MAX_NUM_DEVICES_VIRTUAL; k++) {
	u_int8_t netmask_v6;
	
	safe_snprintf(__FILE__, __LINE__, tmpDeviceName, sizeof(tmpDeviceName), "%s:%d", myGlobals.device[deviceId].name, k);

	traceEvent(CONST_TRACE_NOISY, "Checking %s", tmpDeviceName);
	if(getLocalHostAddress(&myLocalHostAddress, &netmask_v6, tmpDeviceName) == 0) {
	  /* The virtual interface exists */
	  myGlobals.device[myGlobals.numDevices].ifAddr.s_addr = myLocalHostAddress.s_addr;
	  if(myLocalHostAddress.s_addr == myGlobals.device[deviceId].ifAddr.s_addr)
	    continue; /* No virtual Interfaces */
	 myGlobals.device[myGlobals.numDevices].virtualDevice = 1;
	 myGlobals.device[myGlobals.numDevices].activeDevice = 1;
	 myGlobals.device[myGlobals.numDevices].humanFriendlyName = strdup(tmpDeviceName);
	 myGlobals.device[myGlobals.numDevices].name = strdup(tmpDeviceName);
	 calculateUniqueInterfaceName(myGlobals.numDevices);
	 myGlobals.numDevices++;
	 traceEvent(CONST_TRACE_INFO, "Added virtual interface: '%s'", tmpDeviceName);
	 if(myGlobals.numDevices >= MAX_NUM_DEVICES) {
	   traceEvent(CONST_TRACE_WARNING, "Stopping scan - no room for additional (virtual) interfaces");
	   break;
	 }
	}
      }
    }
  }
#endif /* WIN32 */

  resetStats(deviceId);
  initDeviceDatalink(deviceId);

  if((myGlobals.actualReportDeviceId == 0) && myGlobals.device[0].dummyDevice)
    myGlobals.actualReportDeviceId = deviceId;  
}

/* ******************************* */

int validInterface(char *name) {
  if(name && 
     (strstr(name, "PPP") /* Avoid to use the PPP interface */
      || strstr(name, "dialup")  /* Avoid to use the dialup interface */
      || strstr(name, "ICSHARE")  /* Avoid to use the internet sharing interface */
      || strstr(name, "NdisWan"))) { /* Avoid to use the internet sharing interface */
    return(0);
  }
  
  return(1);
}

#define MAX_IF_NAME    256

/*
 * If device is NULL, this function adds the default interface
 * if device is "none" it adds a dummy interface
 */
void initDevices(char* devices) {
  char *tmpDev=NULL, *tmpDescr=NULL;
  pcap_if_t *devpointer;
  char intNames[32][MAX_IF_NAME], intDescr[32][MAX_IF_NAME];
  int ifIdx = 0;
  int defaultIdx = -1;
  int found = 0, intfc;
  char ebuf[CONST_SIZE_PCAP_ERR_BUF];
  char myName[255];

  ebuf[0] = '\0', myName[0] = '\0';

  traceEvent(CONST_TRACE_NOISY, "Initializing network devices [%s]", devices ? devices : "");

  if(myGlobals.pcap_file_list != NULL) {
    createDummyInterface("none");
    myGlobals.device[0].dummyDevice = 0;
    myGlobals.device[0].pcapPtr  = myGlobals.pcap_file_list->pcapPtr;

    if(myGlobals.device[0].humanFriendlyName != NULL) free(myGlobals.device[0].humanFriendlyName);
    myGlobals.device[0].humanFriendlyName = strdup(myGlobals.pcap_file_list->fileName);
    calculateUniqueInterfaceName(0);

    resetStats(0);
    initDeviceDatalink(0);

    if(myGlobals.runningPref.enableSuspiciousPacketDump) {
      if(myGlobals.pcap_file_list == NULL)
	safe_snprintf(__FILE__, __LINE__, myName, sizeof(myName), "%s%cntop-suspicious-pkts.%s.pcap",
		      myGlobals.runningPref.pcapLogBasePath, /* Added by Ola Lundqvist <opal@debian.org> */
		      CONST_PATH_SEP,
		      myGlobals.device[0].uniqueIfName != NULL ?
		      myGlobals.device[0].uniqueIfName :
		      myGlobals.device[0].name);
      else
	safe_snprintf(__FILE__, __LINE__, myName, sizeof(myName), "%s%cntop-suspicious-pkts.pcap",
		      myGlobals.runningPref.pcapLogBasePath,    /* Added by David Moore */
		      CONST_PATH_SEP);

        myGlobals.device[0].pcapErrDumper = pcap_dump_open(myGlobals.device[0].pcapPtr, myName);

        if(myGlobals.device[0].pcapErrDumper == NULL)
	  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "pcap_dump_open() for suspicious packets: '%s'", ebuf);
	else
	  traceEvent(CONST_TRACE_NOISY, "Saving packets into file %s", myName);
    }

    free(myGlobals.device[0].name);
    myGlobals.device[0].name = strdup("pcap-file");
    myGlobals.numDevices = 1;
    return;
  }

  if(pcap_findalldevs(&devpointer, ebuf) < 0) {
    traceEvent(CONST_TRACE_ERROR, "pcap_findalldevs() call failed [%s]", ebuf);
    traceEvent(CONST_TRACE_ERROR, "Have you installed libpcap/winpcap properly?");
    return;
  } else {
    int i;

    myGlobals.allDevs = devpointer; /* save listhead for later use */
    for(i = 0; devpointer != 0; i++) {
      traceEvent(CONST_TRACE_NOISY, "Found interface [index=%d] '%s'", ifIdx, devpointer->name);

      if(tmpDev == NULL) {
	tmpDev = devpointer->name;
	tmpDescr = devpointer->description;
      }

      if(ifIdx < 32) {
	char *descr;

	if(validInterface(devpointer->description)) {
	descr = devpointer->description;

	if(descr != NULL) {
	  /* Sanitize the interface name */
	  for(i=0; i<strlen(descr); i++)
	    if(descr[i] == '(') {
	      descr[i] = '\0';
	      break;
	    }

	  while(descr[strlen(descr)-1] == ' ')
	    descr[strlen(descr)-1] = '\0';

	  safe_snprintf(__FILE__, __LINE__, intDescr[ifIdx], MAX_IF_NAME, "%s_%d", descr, ifIdx);
	} else
	  safe_snprintf(__FILE__, __LINE__, intDescr[ifIdx], MAX_IF_NAME, "%s", devpointer->name);

	strncpy(intNames[ifIdx], devpointer->name, MAX_IF_NAME);

	if(defaultIdx == -1) {
		defaultIdx = ifIdx;
		tmpDev = devpointer->name;
		tmpDescr = devpointer->description;
	}

	ifIdx++;
      }
	  }

      devpointer = devpointer->next;
    }
  }

  if(devices != NULL) {
    /* User has specified devices in the parameter list */
    char *workDevices = strdup(devices), *strtokState = NULL;
    int warnedVirtual = 0;

    tmpDev = strtok_r(workDevices, ",", &strtokState);

    while(tmpDev != NULL) {
#ifndef WIN32
      char *nwInterface;
      deviceSanityCheck(tmpDev); /* These checks do not apply to Win32 */

      traceEvent(CONST_TRACE_NOISY, "Checking requested device '%s'", tmpDev);

      if(((nwInterface = strchr(tmpDev, ':')) != NULL) 
	 && (!strstr(tmpDev, "dag")) /* Endace DAG cards are valid (e.g. dag0:0) */
	 )
	{
 	/* This is a virtual nwInterface */
        char *requestedDev;

        /* Copy (unaltered) for traceEvent() messages */
        requestedDev = strdup(tmpDev);

        if(!warnedVirtual) {
          warnedVirtual = 1;
          traceEvent(CONST_TRACE_WARNING, "Virtual device(s), e.g. %s, specified on "
		     "-i | --interface parameter are ignored", tmpDev);
        }

 	nwInterface[0] = 0;
        /* tmpDev is now just the base name */

 	for(intfc=0; intfc<myGlobals.numDevices; intfc++) {
 	  if(myGlobals.device[intfc].name && (strcmp(myGlobals.device[intfc].name, tmpDev) == 0)) {
 	    found = 1;
            traceEvent(CONST_TRACE_INFO,
                       "NOTE: Virual device '%s' is already implied from a prior base device",
                       requestedDev);
 	    break;
 	  }
 	}

 	if(found) {
 	  tmpDev = strtok_r(NULL, ",", &strtokState);
          free(requestedDev);
 	  continue;
 	}

        traceEvent(CONST_TRACE_INFO, "Using base device %s in place of requested %s",
                   tmpDev, requestedDev);

        free(requestedDev);
      }
#else /* WIN32 */
      if(isdigit(tmpDev[0])) {
	if(atoi(tmpDev) < ifIdx) {
	  tmpDescr = intDescr[atoi(tmpDev)];
	  tmpDev   = intNames[atoi(tmpDev)];
	} else {
	  traceEvent(CONST_TRACE_ERROR, "Interface index '%d' is out of range [0..%d]", 
		  atoi(tmpDev), ifIdx > 0 ? (ifIdx -1) : 0);
	  return;
	}
      } else {
	/* Nothing to do: the user has specified an interface name */
	int i;

	tmpDescr = NULL;
	for(i=0; i<ifIdx; i++) {
	  if(!strcmp(intNames[i], devices)) {
	    tmpDescr = intDescr[i];
	    break;
	  }
	}
      }
#endif

      for(intfc=0; intfc<myGlobals.numDevices; intfc++) {
        if(myGlobals.device[intfc].name && (strcmp(myGlobals.device[intfc].name, tmpDev) == 0)) {
          found = 1;
          break;
        }
      }

      if(found)
        traceEvent(CONST_TRACE_WARNING,
                   "Device '%s' is already specified/implied - ignoring it", tmpDev);
      else
        addDevice(tmpDev, tmpDescr == NULL ? tmpDev : tmpDescr);

      tmpDev = strtok_r(NULL, ",", &strtokState);
    } /* while */

    free(workDevices);
  } else if(defaultIdx != -1) {
    /* Default interface found */
    traceEvent(CONST_TRACE_INFO, "No default device configured. Using %s", intNames[defaultIdx]);
    processStrPref(NTOP_PREF_DEVICES, intNames[defaultIdx], &myGlobals.runningPref.devices, TRUE);
    processStrPref(NTOP_PREF_DEVICES, intNames[defaultIdx], &myGlobals.savedPref.devices, TRUE);
    addDevice(intNames[defaultIdx], intDescr[defaultIdx]);
  }
}

/* ******************************* */

void initDeviceDatalink(int deviceId) {
  if(myGlobals.device[deviceId].dummyDevice) return;
  myGlobals.device[deviceId].activeDevice = 1;
  initDeviceSemaphores(deviceId);
  if(myGlobals.device[deviceId].virtualDevice) return;

  /* get datalink type */
#if defined(__FreeBSD__)
  if(strncmp(myGlobals.device[deviceId].name, "tun", 3) == 0) {
    myGlobals.device[deviceId].datalink = DLT_PPP;
    traceEvent(CONST_TRACE_NOISY, "DLT: Device %d [%s] is \"tun\", treating as DLT_PPP",
	       deviceId,
	       myGlobals.device[deviceId].name);
  } else
#else /* Not FreeBSD */
  if((myGlobals.device[deviceId].name[0] == 'l') /* loopback check */
     && (myGlobals.device[deviceId].name[1] == 'o')) {
    myGlobals.device[deviceId].datalink = DLT_NULL;
    traceEvent(CONST_TRACE_NOISY, "DLT: Device %d [%s] is loopback, treating as DLT_NULL",
	       deviceId,
	       myGlobals.device[deviceId].name);
  } else
#endif
  /* Other OSes have SOME issues, but if we don't recognize the special device,
   * use libpcap */
    myGlobals.device[deviceId].datalink = pcap_datalink(myGlobals.device[deviceId].pcapPtr);

  if(myGlobals.device[deviceId].datalink > MAX_DLT_ARRAY) {
    traceEvent(CONST_TRACE_WARNING,
               "DLT: Device %d [%s] DLT_ value, %d, exceeds highest known value(%d)",
               deviceId,
               myGlobals.device[deviceId].name,
               myGlobals.device[deviceId].datalink,
               MAX_DLT_ARRAY);
    traceEvent(CONST_TRACE_WARNING, "DLT: Please report above message to the ntop-dev list.");
    traceEvent(CONST_TRACE_WARNING, "DLT: Processing continues OK");
    myGlobals.device[deviceId].mtuSize    = CONST_UNKNOWN_MTU;
    myGlobals.device[deviceId].headerSize = 0;
  } else {
    myGlobals.device[deviceId].mtuSize    = myGlobals.mtuSize[myGlobals.device[deviceId].datalink];
    myGlobals.device[deviceId].headerSize = myGlobals.headerSize[myGlobals.device[deviceId].datalink];

    if((myGlobals.device[deviceId].mtuSize == 0) ||
       (myGlobals.device[deviceId].mtuSize == CONST_UNKNOWN_MTU) ) {
      traceEvent(CONST_TRACE_WARNING, "DLT: Device %d [%s] MTU value unknown",
                 deviceId,
                 myGlobals.device[deviceId].name);
      if(myGlobals.device[deviceId].datalink != DLT_RAW)
        traceEvent(CONST_TRACE_NOISY, "DLT: Please report your DLT and MTU values (e.g. ifconfig) to the ntop-dev list");
      traceEvent(CONST_TRACE_WARNING, "DLT: Processing continues OK");
    }
  }

  traceEvent(CONST_TRACE_INFO, "DLT: Device %d [%s] is %d, mtu %d, header %d",
	       deviceId,
	       myGlobals.device[deviceId].name,
	       myGlobals.device[deviceId].datalink,
	       myGlobals.device[deviceId].mtuSize,
	       myGlobals.device[deviceId].headerSize);
}

/* ******************************* */

void parseTrafficFilter(void) {
  /* Construct, compile and set filter */
  if(myGlobals.runningPref.currentFilterExpression != NULL) {
    int i;

    for(i=0; i<myGlobals.numDevices; i++)
      setPcapFilter(myGlobals.runningPref.currentFilterExpression, i);
  } else
    myGlobals.runningPref.currentFilterExpression = strdup("");	/* so that it isn't NULL! */
}

/* *************************** */

#ifndef WIN32
static void ignoreThisSignal(int signalId) {
  signal(signalId, ignoreThisSignal);
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
  signal(SIGCHLD, handleDiedChild);
#endif

#ifndef WIN32
  /* Setup signal handlers */
  signal(SIGTERM, cleanup);
  signal(SIGINT,  cleanup);
  signal(SIGHUP,  handleSigHup);
  signal(SIGPIPE, ignoreThisSignal);
  signal(SIGABRT, ignoreThisSignal);
#if 0
  if(myGlobals.runningPref.debugMode) {
    /* Activate backtrace trap on -K flag */
    signal(SIGSEGV, cleanup);
  }
#endif
#endif
}

/* ***************************** */

void startSniffer(void) {
  int i;

  if((myGlobals.ntopRunState != FLAG_NTOPSTATE_INIT) &&
     (myGlobals.ntopRunState != FLAG_NTOPSTATE_INITNONROOT)) {
    traceEvent(CONST_TRACE_ERROR, "Unable to start sniffer - not in INIT state");
//TODO Should above be FATALERROR???
    return;
  }

  setRunState(FLAG_NTOPSTATE_RUN);

  for(i=0; i<myGlobals.numDevices; i++)
    if((!myGlobals.device[i].virtualDevice)
       && (!myGlobals.device[i].dummyDevice)
       && (myGlobals.device[i].pcapPtr != NULL)) {
      /*
       * (8) - NPS - Network Packet Sniffer (main thread)
       */
      createThread(&myGlobals.device[i].pcapDispatchThreadId, pcapDispatch, (char*)((long)i));
      traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: NPS(%d): Started thread for network packet sniffing [%s]",
		 (long)myGlobals.device[i].pcapDispatchThreadId, i+1, myGlobals.device[i].name);
    }
}

/* ***************************** */

u_int createDummyInterface(char *ifName) {
#ifdef NOT_YET
  u_int mallocLen;
#endif
  u_int deviceId = myGlobals.numDevices;
  int i;

  traceEvent(CONST_TRACE_INFO, "Creating dummy interface, '%s'", ifName);

  if(myGlobals.numDevices >= (MAX_NUM_DEVICES-1)) {
    traceEvent(CONST_TRACE_WARNING, "Too many devices: device '%s' can't be created", ifName);
  } else
    myGlobals.numDevices++;

  memset(&myGlobals.device[deviceId], 0, sizeof(NtopInterface));

  resetDevice(deviceId, 1);
  myGlobals.device[deviceId].network.s_addr = 0xFFFFFFFF;
  myGlobals.device[deviceId].netmask.s_addr = 0xFFFFFFFF;
  myGlobals.device[deviceId].numHosts = myGlobals.device[0].numHosts;
  myGlobals.device[deviceId].name = strdup(ifName);
  myGlobals.device[deviceId].humanFriendlyName = strdup(ifName);
  myGlobals.device[deviceId].datalink = DLT_EN10MB;
  myGlobals.device[deviceId].hash_hostTraffic[BROADCAST_HOSTS_ENTRY] = myGlobals.broadcastEntry;
  myGlobals.broadcastEntry->next = NULL;
  myGlobals.device[deviceId].dummyDevice   = 1; /* This is basically a fake device */
  myGlobals.device[deviceId].virtualDevice = 0;
  myGlobals.device[deviceId].activeDevice  = 0;
  myGlobals.device[deviceId].samplingRate =  myGlobals.runningPref.samplingRate;
  calculateUniqueInterfaceName(deviceId); 

  if(myGlobals.otherHostEntry != NULL) {
    myGlobals.device[deviceId].hash_hostTraffic[OTHER_HOSTS_ENTRY] = myGlobals.otherHostEntry;
    myGlobals.otherHostEntry->next = NULL;
  }

  /* Allocate memory for dhcp stats */
  for(i=0; i<myGlobals.numKnownSubnets; i++) {
    myGlobals.device[deviceId].networkHost[i].protocolInfo = calloc(1, sizeof(ProtocolInfo));
    myGlobals.device[deviceId].networkHost[i].protocolInfo->dnsStats = calloc(1, sizeof(ServiceStats));
    myGlobals.device[deviceId].networkHost[i].protocolInfo->httpStats = calloc(1, sizeof(ServiceStats));
    myGlobals.device[deviceId].networkHost[i].protocolInfo->dhcpStats = calloc(1, sizeof(DHCPStats));
  }

  return(deviceId);
}
