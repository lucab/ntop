/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
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

static void initIPCountryTable(void); /* Forward */

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
  if(myGlobals.domainName[0] == '\0') {
    if((getdomainname(myGlobals.domainName, MAXHOSTNAMELEN) != 0)
       || (myGlobals.domainName[0] == '\0')
       || (strcmp(myGlobals.domainName, "(none)") == 0)) {
      if((gethostname(myGlobals.domainName, MAXHOSTNAMELEN) == 0)
	 && ((p = memchr(myGlobals.domainName, '.', MAXHOSTNAMELEN)) != NULL)) {
	myGlobals.domainName[MAXHOSTNAMELEN - 1] = '\0';
	/*
	 * Replaced memmove with memcpy
	 * Igor Schein <igor@txc.com>
	 */
	++p;
	memcpy(myGlobals.domainName, p, (MAXHOSTNAMELEN+myGlobals.domainName-p));
      } else
	myGlobals.domainName[0] = '\0';
    }

    /*
     * Still unresolved! Try again
     */
    if(myGlobals.domainName[0] == '\0') {
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
	  char *dotp = (char*) hp->h_name;
	  int i;

	  for(i=0; (dotp[i] != '\0') && (dotp[i] != '.'); i++)
	    ;

	  if(dotp[i] == '.')
	    strncpy(myGlobals.domainName, &dotp[i+1], MAXHOSTNAMELEN);
	}
      }
    }

    if(myGlobals.domainName[0] == '\0') {
      /* Last chance.... */
      /* strncpy(myGlobals.domainName, "please_set_your_local_domain.org", MAXHOSTNAMELEN); */
      ;
    }
  }
#endif

  len = strlen(myGlobals.domainName)-1;

  while((len > 0) && (myGlobals.domainName[len] != '.'))
    len--;

  if(len == 0)
    myGlobals.shortDomainName = myGlobals.domainName;
  else
    myGlobals.shortDomainName = &myGlobals.domainName[len+1];
}


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
    char tmpStr[64];

    if(snprintf(tmpStr, sizeof(tmpStr), "%s/services", myGlobals.configFileDirs[idx]) < 0)
      BufferTooShort();
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
    char tmpStr[64];

    if(snprintf(tmpStr, sizeof(tmpStr), "%s/services", myGlobals.configFileDirs[idx]) < 0)
      BufferTooShort();
    fd = fopen(tmpStr, "r");

    if(fd != NULL) {
      char tmpLine[512];

      while(fgets(tmpLine, 512, fd))
	if((tmpLine[0] != '#') && (strlen(tmpLine) > 10)) {
	  /* discard  9/tcp sink null */
	  char name[64], proto[16];
	  int numPort;

	  /* Fix below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
	  if (3 == sscanf(tmpLine, "%63[^ \t] %d/%15s", name, &numPort, proto)) {
	    /* traceEvent(CONST_TRACE_INFO, "'%s' - '%s' - '%d'\n", name, proto, numPort); */

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

static void initIPCountryTable(void) {
  int idx, rc;
  struct stat statBuf;
  
  traceEvent(CONST_TRACE_INFO, "IP2CC: Looking for IP address <-> Country code mapping file");

  myGlobals.ipCountryCount = 0;
  if((myGlobals.countryFlagHead=malloc(sizeof(IPNode))) == NULL) {
    traceEvent(CONST_TRACE_FATALERROR, "IP2CC: Unable to allocate table memory. Quitting...");
    exit(1);
  }
  myGlobals.ipCountryMem += sizeof(IPNode);

  strcpy(myGlobals.countryFlagHead->cc, "***");

  myGlobals.countryFlagHead->b[0]=NULL;
  myGlobals.countryFlagHead->b[1]=NULL;  

  for(idx=0; myGlobals.configFileDirs[idx] != NULL; idx++) {
    char tmpStr[256];
    FILE *fd;

    snprintf(tmpStr, sizeof(tmpStr), "%s/p2c.opt.table", myGlobals.configFileDirs[idx]);
    traceEvent(CONST_TRACE_NOISY, "IP2CC: ...looking for file %s", tmpStr);

    rc = stat(tmpStr, &statBuf);
    if (rc == 0) {
        fd = fopen(tmpStr, "r");

        if (fd!=NULL) {
            char buff[256];
            char *strtokState, *cc, *ip, *prefix;
            int recordsRead=0;

            traceEvent(CONST_TRACE_NOISY, "IP2CC: ...found - reading data");

            while (fgets(buff, sizeof(buff), fd) != NULL) {

                if ((cc=strtok_r(buff, ":", &strtokState))==NULL)
                    continue;
                if ((ip=strtok_r(NULL, "/", &strtokState))==NULL)
                    continue;
                if ((prefix=strtok_r(NULL, "\n", &strtokState))==NULL)
                    continue;

                strtolower(cc);
        
                addNodeInternal(xaton(ip), atoi(prefix), cc);
                recordsRead++;
            }
            myGlobals.ipCountryCount += recordsRead;

            if (!feof(fd)) {
                traceEvent(CONST_TRACE_ERROR, "IP2CC: reading file '%s'", tmpStr);
                traceEvent(CONST_TRACE_ERROR, "IP2CC: problem is %s(%d)", strerror(errno), errno);
                traceEvent(CONST_TRACE_INFO,
                           "IP2CC: ntop continues OK, but with %s data from file",
                           recordsRead == 0 ? "no" : "partial");
            }

            fclose(fd);
            traceEvent(CONST_TRACE_NOISY, "IP2CC: ......%d records read", recordsRead);
        } else 
            traceEvent(CONST_TRACE_WARNING, "IP2CC: unable to open file at %s", tmpStr);
    } else 
        traceEvent(CONST_TRACE_NOISY, "IP2CC: ...does not exist");
  }
  if (myGlobals.ipCountryCount == 0) {
      traceEvent(CONST_TRACE_WARNING, 
                 "IP2CC: Unable to read IP address <-> Country code mapping file (non-existant or no data).\n");
      traceEvent(CONST_TRACE_INFO, 
                 "IP2CC: ntop will perform correctly but without this minor feature.\n");
  } else 
      traceEvent(CONST_TRACE_INFO, "IP2CC: %d records read", myGlobals.ipCountryCount);
}

/* ******************************* */

/*
   Function below courtesy of
   Eric Dumazet <dada1@cosmosbay.com>
*/
void resetDevice(int devIdx) {
  int len;
  void *ptr;

  myGlobals.device[devIdx].actualHashSize = CONST_HASH_INITIAL_SIZE;

  ptr = calloc(CONST_HASH_INITIAL_SIZE, sizeof(HostTraffic*));
  len = CONST_HASH_INITIAL_SIZE * sizeof(HostTraffic*);
  memset(ptr, 0, len);
  myGlobals.device[devIdx].hash_hostTraffic = ptr;

  len = sizeof(struct HashList*)*myGlobals.hashListSize;
  /* printf("sizeof(u_int16_t)=%d /size=%u/len=%d\n",
     sizeof(u_int16_t), myGlobals.hashListSize, len); */
  myGlobals.device[devIdx].hashList = (HashList**)malloc(len);
  memset(myGlobals.device[devIdx].hashList, 0, len);
  myGlobals.device[devIdx].insertIdx = 0;

  resetTrafficCounter(&myGlobals.device[devIdx].droppedPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].ethernetPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].broadcastPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].multicastPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].ipPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].ethernetBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].ipBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].fragmentedIpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].tcpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].udpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].otherIpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].icmpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].dlcBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].ipxBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].stpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].decnetBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].netbiosBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].arpRarpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].atalkBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].ospfBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].egpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].igmpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].osiBytes);
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
  resetTrafficCounter(&myGlobals.device[devIdx].numEstablishedTCPConnections);
  myGlobals.device[devIdx].hostsno = 0;
  myGlobals.device[devIdx].insertIdx = 0;

  myGlobals.device[devIdx].lastThptUpdate = myGlobals.device[devIdx].lastMinThptUpdate =
    myGlobals.device[devIdx].lastHourThptUpdate = myGlobals.device[devIdx].lastFiveMinsThptUpdate = time(NULL);
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

  len = (size_t)myGlobals.numIpProtosToMonitor*sizeof(SimpleProtoTrafficInfo);

  if(myGlobals.device[devIdx].ipProtoStats == NULL)
    myGlobals.device[devIdx].ipProtoStats = (SimpleProtoTrafficInfo*)malloc(len);

  memset(myGlobals.device[devIdx].ipProtoStats, 0, len);
}


/* ******************************* */

static void allocateOtherHosts() {
    myGlobals.otherHostEntry = (HostTraffic*)malloc(sizeof(HostTraffic));
    memset(myGlobals.otherHostEntry, 0, sizeof(HostTraffic));

    myGlobals.otherHostEntry->hostIpAddress.s_addr = 0x00112233;
    strncpy(myGlobals.otherHostEntry->hostNumIpAddress, "&nbsp;",
	    sizeof(myGlobals.otherHostEntry->hostNumIpAddress));
    strncpy(myGlobals.otherHostEntry->hostSymIpAddress, "Remaining Host(s)",
	    sizeof(myGlobals.otherHostEntry->hostSymIpAddress));
    strcpy(myGlobals.otherHostEntry->ethAddressString, "00:00:00:00:00:00");
    myGlobals.otherHostEntryIdx = myGlobals.broadcastEntryIdx+1;
    myGlobals.otherHostEntry->hostSerial = myGlobals.otherHostEntryIdx;
    myGlobals.otherHostEntry->portsUsage = (PortUsage**)calloc(sizeof(PortUsage*), 
							       MAX_ASSIGNED_IP_PORTS);
}

/* ******************************************* */

void initCounters(void) {
  int len, i;
  FILE *fd = NULL;
  int configFileFound = 0;
  char buf[256];
#ifdef MAKE_WITH_I18N
  char *workLanguage;
 #ifdef HAVE_DIRENT_H
  struct dirent **dirList;
  int j, iLang, nLang, found;
  DIR *testDirEnt;
  char *tmpStr;
  char* realLocale;
 #endif
#endif

  myGlobals.hashListSize = MAX_PER_DEVICE_HASH_LIST;
  myGlobals.numPurgedHosts = myGlobals.numTerminatedSessions = 0;
  myGlobals.maximumHostsToPurgePerCycle = DEFAULT_MAXIMUM_HOSTS_PURGE_PER_CYCLE;

  setDomainName();

#ifdef MAKE_WITH_XMLDUMP
  if (gethostname(myGlobals.hostName, MAXHOSTNAMELEN) != 0)
      strncpy(myGlobals.hostName, "127.0.0.1", MAXHOSTNAMELEN);
  else {
     traceEvent(CONST_TRACE_NOISY, "On this system, gethostname() returned '%s'", myGlobals.hostName);

     if (strcmp(myGlobals.hostName, myGlobals.domainName) == 0) {
         /* The returned hostName doesn't appear to have the domainName in it... */
         traceEvent(CONST_TRACE_NOISY, "Appending the domain name, '%s'", myGlobals.domainName);
         sprintf(myGlobals.hostName, "%s.%s", myGlobals.hostName, myGlobals.domainName);
     }
  }
#endif

  memset(myGlobals.transTimeHash, 0, sizeof(myGlobals.transTimeHash));
  memset(myGlobals.dummyEthAddress, 0, LEN_ETHERNET_ADDRESS);

  for(len=0; len<LEN_ETHERNET_ADDRESS; len++)
    myGlobals.dummyEthAddress[len] = len;

  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.enableSessionHandling) {
      myGlobals.device[i].numTotSessions = myGlobals.hashListSize;
      len = sizeof(IPSession*)*myGlobals.device[i].numTotSessions;
      myGlobals.device[i].tcpSession = (IPSession**)malloc(len);
      memset(myGlobals.device[i].tcpSession, 0, len);
    } else {
      myGlobals.device[i].numTotSessions = 0;
      myGlobals.device[i].tcpSession     = NULL;
    }

    myGlobals.device[i].fragmentList = NULL;
  }

  myGlobals.broadcastEntry = (HostTraffic*)malloc(sizeof(HostTraffic));
  memset(myGlobals.broadcastEntry, 0, sizeof(HostTraffic));
  resetHostsVariables(myGlobals.broadcastEntry);

  /* Set address to FF:FF:FF:FF:FF:FF */
  for(i=0; i<LEN_ETHERNET_ADDRESS; i++)
    myGlobals.broadcastEntry->ethAddress[i] = 0xFF;

  myGlobals.broadcastEntry->hostIpAddress.s_addr = 0xFFFFFFFF;
  strncpy(myGlobals.broadcastEntry->hostNumIpAddress, "broadcast",
	  sizeof(myGlobals.broadcastEntry->hostNumIpAddress));
  strncpy(myGlobals.broadcastEntry->hostSymIpAddress, myGlobals.broadcastEntry->hostNumIpAddress,
	  sizeof(myGlobals.broadcastEntry->hostSymIpAddress));
  strcpy(myGlobals.broadcastEntry->ethAddressString, "FF:FF:FF:FF:FF:FF");
  FD_SET(FLAG_SUBNET_LOCALHOST, &myGlobals.broadcastEntry->flags);
  FD_SET(FLAG_BROADCAST_HOST, &myGlobals.broadcastEntry->flags);
  FD_SET(FLAG_SUBNET_PSEUDO_LOCALHOST, &myGlobals.broadcastEntry->flags);
  myGlobals.broadcastEntry->hostSerial = 0;

  myGlobals.broadcastEntryIdx = 0;

  allocateOtherHosts();

  myGlobals.numProcesses = 0;

  resetStats();

  myGlobals.ipxsapHashLoadCollisions = 0;
  myGlobals.hashCollisionsLookup     = 0;

  myGlobals.numVendorLookupRead = 0;
  myGlobals.numVendorLookupAdded = 0;
  myGlobals.numVendorLookupAddedSpecial = 0;
  myGlobals.numVendorLookupCalls = 0;
  myGlobals.numVendorLookupSpecialCalls = 0;
  myGlobals.numVendorLookupFound48bit = 0;
  myGlobals.numVendorLookupFound24bit = 0;
  myGlobals.numVendorLookupFoundMulticast = 0;
  myGlobals.numVendorLookupFoundLAA = 0;

  createVendorTable();
  myGlobals.initialSniffTime = myGlobals.lastRefreshTime = time(NULL);
  myGlobals.capturePackets = FLAG_NTOPSTATE_RUN;

  myGlobals.numHandledSIGPIPEerrors = 0;
  myGlobals.numHandledHTTPrequests = 0;

  myGlobals.hostsCacheLen = 0;
  myGlobals.hostsCacheLenMax = 0;
  myGlobals.hostsCacheReused = 0;
#ifdef PARM_USE_SESSIONS_CACHE
  myGlobals.sessionsCacheLen = 0;
  myGlobals.sessionsCacheLenMax = 0;
  myGlobals.sessionsCacheReused = 0;
#endif

  /*
   * Check if the ettercap passive file exists - warn if not.
   */
  traceEvent(CONST_TRACE_NOISY, "OSFP: Looking for OS fingerprint file, %s\n", CONST_OSFINGERPRINT_FILE);

  for(i=0; myGlobals.configFileDirs[i] != NULL; i++) {

    snprintf(buf, sizeof(buf), "%s/%s", myGlobals.configFileDirs[i], CONST_OSFINGERPRINT_FILE);
    
    traceEvent(CONST_TRACE_NOISY, "OSFP: Checking '%s'\n", buf);
    fd = fopen(buf, "r");

    if(fd) {
      traceEvent(CONST_TRACE_NOISY, "OSFP: ...found!\n");
      configFileFound = 1;
      fclose(fd);
      break;
    }
  }
  if (configFileFound == 0) {
      traceEvent(CONST_TRACE_WARNING, "OSFP: Unable to open file '%s'.\n", CONST_OSFINGERPRINT_FILE);
      traceEvent(CONST_TRACE_NOISY, "OSFP: ntop continues ok, but without OS fingerprinting.\n");
      traceEvent(CONST_TRACE_NOISY, "OSFP: If the file 'magically' appears, OS fingerprinting will automatically be enabled.\n");
  }

  /* i18n */
#ifdef MAKE_WITH_I18N
  /*
   *  Obtain - from the os - the default locale.
   */
  workLanguage = setlocale(LC_ALL, "");
  if (workLanguage != NULL ) {
#ifdef I18N_DEBUG
      traceEvent(CONST_TRACE_NOISY,
                 "I18N: Default language (from ntop host) is '%s' (raw)\n", 
                 workLanguage);
#endif
      myGlobals.defaultLanguage = i18n_xvert_locale2common(workLanguage);
      traceEvent(CONST_TRACE_INFO,
                 "I18N: Default language (from ntop host) is '%s'\n", 
                 myGlobals.defaultLanguage);
  } else {
      traceEvent(CONST_TRACE_INFO,
                 "I18N: Default language (from ntop host) is unspecified\n"); 
      myGlobals.defaultLanguage = NULL;
  }

  /*
   *  We initialize the array, myGlobals.supportedLanguages[] as follows...
   *    We scan the directory entries in LOCALDIR, fix 'em up and then
   *    see if the ntop html directory /html_cc[_XX]) exists?
   *
   *  Those that do, up to the limit, are loaded in the list...
   *
   *  We do not load an empty or artificial en - the logic in http.c will
   *  present the default page (in .../html) if no language specific one is found.
   *
   *  We strip because we're not ready to support multiple char sets.  We're pretty
   *  much just UTF-8
   *
   */

 #ifdef HAVE_DIRENT_H
  nLang = scandir(locale_dir, &dirList, NULL, alphasort);
  if (nLang < 0) {
      traceEvent(CONST_TRACE_WARNING,
                 "I18N: Error obtaining locale list, scandir(%s,...) errno is %d\n", 
                 locale_dir,
                 errno);
      traceEvent(CONST_TRACE_NOISY, "continues without multiple language support");
  } else {
      traceEvent(CONST_TRACE_NOISY, "I18N: scandir(%s,...) returned %d\n", locale_dir, nLang);
      for (iLang=0; (iLang<nLang) && (myGlobals.maxSupportedLanguages < MAX_LANGUAGES_SUPPORTED); iLang++) {
  #ifdef I18N_DEBUG
          traceEvent(CONST_TRACE_NOISY, "I18N_DEBUG: %2d. '%s'\n", iLang, dirList[iLang]->d_name);
  #endif
          if (dirList[iLang]->d_name[0] == '.') {
              /* skip parent/self directory entries */
              continue;
          }

          if ( (dirList[iLang]->d_type == DT_DIR) ||
               (dirList[iLang]->d_type == DT_LNK) ) {
              tmpStr = i18n_xvert_locale2common(dirList[iLang]->d_name);

              if (!strcmp(myGlobals.defaultLanguage, tmpStr)) {
                  /* skip default language */
              traceEvent(CONST_TRACE_NOISY,
                         "I18N_DEBUG: Skipping default language '%s' ('%s' raw)\n",
                         tmpStr,
                         dirList[iLang]->d_name);
  #ifdef I18N_DEBUG
  #endif
                  free(tmpStr);
                  continue;
              }

              found=0;
              for (i=0; (!found) && i<myGlobals.maxSupportedLanguages; i++) {
                  if (!strcmp(tmpStr, myGlobals.supportedLanguages[i])) {
                      traceEvent(CONST_TRACE_NOISY, 
                                 "I18N_DEBUG: Skipping already supported language, '%s'\n",
                                 dirList[iLang]->d_name);
  #ifdef I18N_DEBUG
  #endif
                      found=1;
                      break;
                  }
              }
              if (!found) {
                  traceEvent(CONST_TRACE_NOISY, 
                             "I18N: Testing locale '%s' (from '%s')\n",
                             tmpStr,
                             dirList[iLang]->d_name);
                  for(i=0; (!found) && (myGlobals.dataFileDirs[i] != NULL); i++) {

    	              if (snprintf(buf, sizeof(buf), "%s/html_%s",
                                   myGlobals.dataFileDirs[i],
                                   tmpStr) < 0)
    	                BufferTooShort();
   #ifdef WIN32
                      j=0;
                      while (buf[j] != '\0') {
                          if (buf[j] == '/') buf[j] = '\\';
                          j++;
                      }
   #endif

  #ifdef I18N_DEBUG
                      traceEvent(CONST_TRACE_NOISY, 
                                 "I18N_DEBUG: Looking for directory '%s'\n",
                                 buf);
  #endif
                      testDirEnt = opendir(buf);
                      if (testDirEnt != NULL) {
                          closedir(testDirEnt);

                          realLocale = strdup(setlocale(LC_ALL, NULL));
                          setlocale(LC_ALL, tmpStr);
                          myGlobals.strftimeFormat[myGlobals.maxSupportedLanguages] = nl_langinfo(D_T_FMT);
                          setlocale(LC_ALL, realLocale);
                          free(realLocale);

                          myGlobals.supportedLanguages[myGlobals.maxSupportedLanguages++] = strdup(tmpStr);
                          found=1;
                          traceEvent(CONST_TRACE_INFO,
                                     "I18N: '%s' ntop language files found, is supported.\n",
                                     tmpStr);
                      }
                  }

                  if (!found) {
                      traceEvent(CONST_TRACE_NOISY,
                                 "I18N: '%s' ntop language files not found, may not be supported.\n",
                                 tmpStr);
                  }

                  free(tmpStr);

   #ifdef I18N_DEBUG
              } else {
                  traceEvent(CONST_TRACE_NOISY, 
                             "I18N_DEBUG: Skipping duplicate locale '%s'\n",
                             dirList[iLang]->d_name);
   #endif
              }

  #ifdef I18N_DEBUG
          } else {
              traceEvent(CONST_TRACE_NOISY, "I18N_DEBUG: Skipping file '%s' (type %d)\n", 
                         dirList[iLang]->d_name,
                         dirList[iLang]->d_type);
  #endif
          }
      }
      for (iLang=0; iLang<nLang; iLang++) {
          free(dirList[iLang]);
      }
      free(dirList);
  }

 #else
  traceEvent(CONST_TRACE_WARNING, 
             "I18N: Unable to scan locales (missing dirent.h at compile time) - ntop continues\n");
 #endif /* HAVE_DIRENT_H */

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, 
             "I18N: This instance of ntop supports %d additional language(s)\n",
             myGlobals.maxSupportedLanguages);
#else
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, 
             "I18N: This instance of ntop does not support multiple languages\n");
#endif /* MAKE_WITH_I18N */

  initIPCountryTable();
}


/* ******************************* */

void resetStats(void) {
  int i, interfacesToCreate;

  traceEvent(CONST_TRACE_INFO, "Resetting traffic statistics...");

#ifdef CFG_MULTITHREADED
  if(myGlobals.hostsHashMutexInitialized != 0)
    accessMutex(&myGlobals.hostsHashMutex, "resetStats");
#endif

  /*
    We create the hash anyway in case the plugins (that are loaded
    later) will tweak the value of myGlobals.mergeInterfaces
  */
  
  interfacesToCreate = myGlobals.numDevices;

  /* Do not reset the first entry (myGlobals.broadcastEntry) */
  for(i=0; i<interfacesToCreate; i++) {
    u_int j;

    for(j=1; j<myGlobals.device[i].actualHashSize; j++)
      if(myGlobals.device[i].hash_hostTraffic[j] != NULL) {
	freeHostInfo(i, myGlobals.device[i].hash_hostTraffic[j], i); /* ** */
	myGlobals.device[i].hash_hostTraffic[j] = NULL;
      }

    resetDevice(i);

    for(j=0; j<myGlobals.device[i].numTotSessions; j++)
      if(myGlobals.device[i].tcpSession[j] != NULL) {
	free(myGlobals.device[i].tcpSession[j]);
	myGlobals.device[i].tcpSession[j] = NULL;
      }

    myGlobals.device[i].numTcpSessions = 0;

    myGlobals.device[i].hash_hostTraffic[myGlobals.broadcastEntryIdx] = myGlobals.broadcastEntry;
    if(myGlobals.otherHostEntryIdx != myGlobals.broadcastEntryIdx) {
      allocateOtherHosts(); /* Freed by ** */
      myGlobals.device[i].hash_hostTraffic[myGlobals.otherHostEntryIdx] = myGlobals.otherHostEntry;
    }
  }

#ifdef CFG_MULTITHREADED
  if(myGlobals.hostsHashMutexInitialized != 0)
    releaseMutex(&myGlobals.hostsHashMutex);
#endif
}

/* ******************************* */

int initGlobalValues(void) {

#ifdef CFG_MULTITHREADED
    myGlobals.numDequeueThreads = MAX_NUM_DEQUEUE_THREADS;
#endif

  if(myGlobals.enableSessionHandling)
    initPassiveSessions();

  myGlobals.netFlowDeviceId = -1;
  myGlobals.sflowDeviceId   = -1;
  
  return(0);
}

/* ******************************* */

void initSingleGdbm(GDBM_FILE *database, char *dbName, char *directory, int doUnlink) {
  char tmpBuf[200];

  /* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au>. */
  /* directory is used by intop to specify where to open the files.
     If called with NULL, use the myGlobals.dbPath value instead
     (Minor fix for intop - Burton Strauss (BStrauss@acm.org) - Apr2002)
  */  

  if (snprintf(tmpBuf, sizeof(tmpBuf), "%s/%s", 
               directory != NULL ? directory : myGlobals.dbPath,
               dbName) < 0)
      BufferTooShort();

  if (doUnlink == TRUE) {
      unlink(tmpBuf); /* Delete the old one (if present) */
  }

  traceEvent(CONST_TRACE_NOISY, "%s database '%s'",
                                doUnlink == TRUE ? "creating" : "opening",
                                tmpBuf);
  *database = gdbm_open (tmpBuf, 0, GDBM_WRCREAT, 00664, NULL);

  if(*database == NULL) {
      traceEvent(CONST_TRACE_FATALERROR, "....open of %s failed: %s",
                 tmpBuf,
#if defined(WIN32) && defined(__GNUC__)
                 "unknown gdbm errno"
#else
                 gdbm_strerror(gdbm_errno)
#endif
                );

      if (directory == NULL) {
          traceEvent(CONST_TRACE_FATALERROR, "Possible solution: please use '-P <directory>'\n");
      }
      exit(-1);
  }
}

void initGdbm(char *directory) {
  traceEvent(CONST_TRACE_INFO, "Initializing gdbm databases");

  initSingleGdbm(&myGlobals.addressQueueFile, "addressQueue.db", directory, TRUE);
  initSingleGdbm(&myGlobals.prefsFile,        "prefsCache.db",   directory, FALSE);
  initSingleGdbm(&myGlobals.dnsCacheFile,     "dnsCache.db",     directory, TRUE);
  initSingleGdbm(&myGlobals.pwFile,           "ntop_pw.db",      directory, FALSE);
  initSingleGdbm(&myGlobals.hostsInfoFile,    "hostsInfo.db",    directory, FALSE);
  initSingleGdbm(&myGlobals.macPrefixFile,    "macPrefix.db",    directory, TRUE);
}

/* ************************************************************ */

/*
 * Initialize all the threads used by ntop to:
 * a) sniff packets from NICs and push them in internal data structures
 * b) pop and decode packets
 * c) collect data
 * d) display/emit information
 */
void initThreads(void) {
  int i;

#ifdef CFG_MULTITHREADED

  /*
   * Create two variables (semaphores) used by functions in pbuf.c to queue packets
   */
#ifdef MAKE_WITH_SEMAPHORES

  createSem(&myGlobals.queueSem, 0);

#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  createSem(&myGlobals.queueAddressSem, 0);
#endif

#else

  createCondvar(&myGlobals.queueCondvar);

#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  createCondvar(&myGlobals.queueAddressCondvar);
#endif

#endif

  createMutex(&myGlobals.gdbmMutex);        /* data to synchronize thread access to db files */
  createMutex(&myGlobals.graphMutex);       /* data to synchronize thread access to graph generation */
  createMutex(&myGlobals.tcpSessionsMutex); /* data to synchronize TCP sessions access */

  /*
   * Create the thread (1) - NPA - Network Packet Analyzer (main thread)
   */
  createMutex(&myGlobals.packetQueueMutex);
  createThread(&myGlobals.dequeueThreadId, dequeuePacket, NULL);
  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Started thread (%ld) for network packet analyser",
	     myGlobals.dequeueThreadId);

  /*
   * Create the thread (2) - HTS - Host Traffic Statistics
   */
  createMutex(&myGlobals.hostsHashMutex);

  /*
   * Create the thread (4) - SIH - Scan Idle Hosts - optional
   */
  if (myGlobals.enableIdleHosts && (myGlobals.rFileName == NULL)) {
    createThread(&myGlobals.scanIdleThreadId, scanIdleLoop, NULL);
    traceEvent(CONST_TRACE_INFO, "THREADMGMT: Started thread (%ld) for idle hosts detection",
	       myGlobals.scanIdleThreadId);
  }

#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  if(myGlobals.numericFlag == 0) {
    createMutex(&myGlobals.addressResolutionMutex);

    /*
     * Create the thread (6) - DNSAR - DNS Address Resolution - optional
     */
    for(i=0; i<myGlobals.numDequeueThreads; i++) {
      createThread(&myGlobals.dequeueAddressThreadId[i], dequeueAddress, NULL);
      traceEvent(CONST_TRACE_INFO, "THREADMGMT: Started thread (%ld) for DNS address resolution",
		 myGlobals.dequeueAddressThreadId[i]);
    }
  }
#endif

#endif /* CFG_MULTITHREADED */

#ifdef MAKE_WITH_SSLWATCHDOG
 #ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  if (myGlobals.useSSLwatchdog == 1)
 #endif
  {
      traceEvent(CONST_TRACE_NOISY, "Initializing Condvar for ssl watchdog.");
      createCondvar(&myGlobals.sslwatchdogCondvar);
      myGlobals.sslwatchdogCondvar.predicate = FLAG_SSLWATCHDOG_UNINIT;
  }
#endif

#ifdef CFG_MULTITHREADED
  myGlobals.hostsHashMutexInitialized = 1;
#endif /* CFG_MULTITHREADED */
}


/*
 * Initialize helper applications (e.g. ntop uses 'lsof' to list open connections)
 */
void initApps(void) {
  if(myGlobals.isLsofPresent) {

#ifdef CFG_MULTITHREADED
#ifndef WIN32
    myGlobals.updateLsof = 1;
    memset(myGlobals.localPorts, 0, sizeof(myGlobals.localPorts)); /* myGlobals.localPorts is used by lsof */
    /*
     * (8) - LSOF - optional
     */
    createMutex(&myGlobals.lsofMutex);
    createThread(&myGlobals.lsofThreadId, periodicLsofLoop, NULL);
    traceEvent(CONST_TRACE_INFO, "THREADMGMT: Started thread (%ld) for lsof support", myGlobals.lsofThreadId);
#endif /* WIN32 */

#else
    readLsofInfo();
    if (myGlobals.numProcesses == 0) {
        traceEvent(CONST_TRACE_WARNING, "LSOF: 1st run found nothing - check if lsof is suid root?\n");
    }
#endif
  }
}


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
 */
void initDevices(char* devices) {
  char ebuf[CONST_SIZE_PCAP_ERR_BUF];
  char *workDevices;
  int i, j, mallocLen;
  NtopInterface *tmpDevice;
  char *tmpDev;
#ifdef WIN32
#define MAX_IF_NAME    256
  pcap_if_t *devpointer;
  char intNames[32][MAX_IF_NAME], intDescr[32][MAX_IF_NAME], *tmpDescr=NULL;
  int ifIdx = 0;
  int defaultIdx = -1;
#endif

  traceEvent(CONST_TRACE_NOISY, "Initializing network devices");

  if((devices != NULL) && (strcmp(devices, "none") == 0)) {
    /* Creating dummy device */
    mallocLen = sizeof(NtopInterface)*(myGlobals.numDevices+1);
    tmpDevice = (NtopInterface*)malloc(mallocLen);
    memset(tmpDevice, 0, mallocLen);
    tmpDevice->virtualDevice = 1;
    tmpDevice->datalink = DLT_EN10MB;
    tmpDevice->name = strdup("none (dummy device)");
    tmpDevice->pcapPtr = pcap_open_dead(DLT_EN10MB, 100);
    myGlobals.device = tmpDevice;
    myGlobals.numDevices = 1;
    traceEvent(CONST_TRACE_INFO, "-i none, so initialized only a dummy device");
    return;
  }

  /* Determine the device name if not specified */
  ebuf[0] = '\0';

	
  /* ******************************************** */

#ifdef WIN32
  if(pcap_findalldevs(&devpointer, ebuf) < 0) {
    traceEvent(CONST_TRACE_FATALERROR, "FATAL ERROR: pcap_findalldevs() call failed [%s]", ebuf);
    traceEvent(CONST_TRACE_FATALERROR, "FATAL ERROR: Have you instaled winpcap properly?");
    exit(-1);
  } else {
    for (i = 0; devpointer != 0; i++) {
      traceEvent(CONST_TRACE_NOISY, "Found interface [index=%d] '%s'", ifIdx, devpointer->name);

	  if(tmpDev == NULL) {
		tmpDev = devpointer->name;
		tmpDescr = devpointer->description;
	  }

      if(ifIdx < 32) {
		char *descr;

  	    descr = devpointer->description;
		/* Sanitize the interface name */
		for(i=0; i<strlen(descr); i++)
			if(descr[i] == '(') {
				descr[i] = '\0';
				break;
			}	
		while(descr[strlen(descr)-1] == ' ')
			descr[strlen(descr)-1] = '\0';

		strncpy(intNames[ifIdx], devpointer->name, MAX_IF_NAME);
		strncpy(intDescr[ifIdx], descr, MAX_IF_NAME);

		if(defaultIdx == -1) {
		  if((!strstr(intNames[ifIdx], "PPP")) /* Avoid to use the PPP interface */
			 && (!strstr(intNames[ifIdx], "ICSHARE"))  /* Avoid to use the internet sharing interface */
			 && (!strstr(intNames[ifIdx], "NdisWan"))) { /* Avoid to use the internet sharing interface */
			defaultIdx = ifIdx;
			tmpDev = devpointer->name;
			tmpDescr = devpointer->description;
		  }
		}

		ifIdx++;
      }

      devpointer = devpointer->next;
    } /* for */
  } /* else */
#endif

  if (devices == NULL) {
    /* No default device selected */

#ifndef WIN32
    tmpDev = pcap_lookupdev(ebuf);

    if(tmpDev == NULL) {
      traceEvent(CONST_TRACE_FATALERROR, "Unable to locate default interface (%s)", ebuf);
      exit(-1);
    }
#endif

    myGlobals.device = (NtopInterface*)calloc(1, sizeof(NtopInterface));
#ifndef WIN32
    myGlobals.device[0].humanFriendlyName = strdup(tmpDev);
#else
    myGlobals.device[0].humanFriendlyName = strdup(tmpDescr);
#endif
    myGlobals.device[0].name = strdup(tmpDev);
    myGlobals.numDevices = 1;
  } else {
    char *strtokState;

    workDevices = strdup(devices);

    tmpDev = strtok_r(workDevices, ",", &strtokState);
    myGlobals.numDevices = 0;

    while(tmpDev != NULL) {
#ifndef WIN32
      char *nwInterface;
      deviceSanityCheck(tmpDev); /* These checks do not apply to Win32 */

      if((nwInterface = strchr(tmpDev, ':')) != NULL) {
 	/* This is a virtual nwInterface */
 	int intfc, found=0;

 	nwInterface[0] = 0;

 	for(intfc=0; intfc<myGlobals.numDevices; intfc++)
 	  if(myGlobals.device[intfc].name && (strcmp(myGlobals.device[intfc].name, tmpDev) == 0)) {
 	    found = 1;
 	    break;
 	  }

 	if(found) {
 	  tmpDev = strtok_r(NULL, ",", &strtokState);
 	  continue;
 	}
      }
#else /* WIN32 */
      if(atoi(tmpDev) < ifIdx) {
	tmpDescr = intDescr[atoi(tmpDev)];
	tmpDev   = intNames[atoi(tmpDev)];
      } else {
	traceEvent(CONST_TRACE_FATALERROR, "Interface index '%d' is out of range [0..%d]", atoi(tmpDev), ifIdx);
	exit(-1);
      }

#endif

      mallocLen = sizeof(NtopInterface)*(myGlobals.numDevices+1);
      tmpDevice = (NtopInterface*)malloc(mallocLen);
      memset(tmpDevice, 0, mallocLen);

      /* Fix courtesy of Marius <marius@tbs.co.za> */
      if(myGlobals.numDevices > 0) {
	memcpy(tmpDevice, myGlobals.device, sizeof(NtopInterface)*myGlobals.numDevices);
	free(myGlobals.device);
      }

      myGlobals.device = tmpDevice;
#ifndef WIN32
      myGlobals.device[myGlobals.numDevices].humanFriendlyName = strdup(tmpDev);
#else
      myGlobals.device[myGlobals.numDevices].humanFriendlyName = strdup(tmpDescr);
#endif
      myGlobals.device[myGlobals.numDevices++].name = strdup(tmpDev);
      tmpDev = strtok_r(NULL, ",", &strtokState);

#ifndef CFG_MULTITHREADED
      if(tmpDev != NULL) {
	traceEvent(CONST_TRACE_WARNING, "ntop can handle multiple interfaces only if thread support is enabled");
	traceEvent(CONST_TRACE_NOISY, "Only interface '%s' will be used", myGlobals.device[0].name);
	break;
      }
#endif

      if(myGlobals.numDevices >= MAX_NUM_DEVICES) {
	traceEvent(CONST_TRACE_WARNING, "ntop can handle up to %d interfaces",
		   myGlobals.numDevices);
	traceEvent(CONST_TRACE_NOISY, "Additional interfaces will be ignored");
	break;
      }
    }

    free(workDevices);

  }


  /* ******************************************* */

  if(myGlobals.rFileName == NULL) {
    /* When sniffing from a multihomed interface
       it is necessary to add all the virtual interfaces
       because ntop has to know all the local addresses */
    for(i=0, j=myGlobals.numDevices; i<j; i++) {
      getLocalHostAddress(&myGlobals.device[i].ifAddr, myGlobals.device[i].name);

      if(strncmp(myGlobals.device[i].name, "lo", 2)) { /* Do not care of virtual loopback interfaces */
	int k;
	char tmpDeviceName[64];
	struct in_addr myLocalHostAddress;

	if(myGlobals.numDevices < MAX_NUM_DEVICES) {
	  for(k=0; k<8; k++) {
	    if(snprintf(tmpDeviceName, sizeof(tmpDeviceName), "%s:%d", myGlobals.device[i].name, k) < 0)
	      BufferTooShort();
	    if(getLocalHostAddress(&myLocalHostAddress, tmpDeviceName) == 0) {
	      /* The virtual interface exists */

	      mallocLen = sizeof(NtopInterface)*(myGlobals.numDevices+1);
	      tmpDevice = (NtopInterface*)malloc(mallocLen);
	      memset(tmpDevice, 0, mallocLen);
	      memcpy(tmpDevice, myGlobals.device, sizeof(NtopInterface)*myGlobals.numDevices);
	      free(myGlobals.device);
	      myGlobals.device = tmpDevice;

	      myGlobals.device[myGlobals.numDevices].ifAddr.s_addr = myLocalHostAddress.s_addr;
	      if(myLocalHostAddress.s_addr == myGlobals.device[i].ifAddr.s_addr)
		continue; /* No virtual Interfaces */
#ifndef WIN32
	      myGlobals.device[myGlobals.numDevices].humanFriendlyName = strdup(tmpDeviceName);
#endif
	      myGlobals.device[myGlobals.numDevices++].name = strdup(tmpDeviceName);
#ifdef DEBUG
	      traceEvent(CONST_TRACE_INFO, "Added: %s\n", tmpDeviceName);
#endif
	    } else
	      break; /* No virtual interface */
	  }
	}
      }
    }
  }

  mallocLen = 2;
  for(i=0; i<myGlobals.numDevices; i++) {
      if (myGlobals.device[i].name != NULL)
          mallocLen += strlen(myGlobals.device[i].name) + 2;
  }
  workDevices = malloc(mallocLen);
  memset(workDevices, 0, mallocLen);    

  for(i=0; i<myGlobals.numDevices; i++) {
    getLocalHostAddress(&myGlobals.device[i].network, myGlobals.device[i].name);
    if (myGlobals.device[i].name != NULL) {
        if (i>0) {
            strcat(workDevices, ", ");
        }
        strcat(workDevices, myGlobals.device[i].name);
    }
  }
  
  if(myGlobals.devices != NULL) free(myGlobals.devices);
  myGlobals.devices = workDevices;
}

/* ******************************* */

void initLibpcap(void) {
  char ebuf[CONST_SIZE_PCAP_ERR_BUF];

  if(myGlobals.rFileName == NULL) {
    int i;

    for(i=0; i<myGlobals.numDevices; i++) {
      /* Fire up libpcap for each specified device */
      char myName[80];

      /* Support for virtual devices */
      char *column = strchr(myGlobals.device[i].name, ':');

      /*
	The timeout below for packet capture
	has been set to 100ms.

	Courtesy of: Nicolai Petri <Nicolai@atomic.dk>
      */
      if((!myGlobals.device[i].virtualDevice) && (column == NULL)) {
#ifdef WIN32
		  NetType adapter;

			LPADAPTER a = PacketOpenAdapter((LPTSTR)myGlobals.device[i].name);
			if(PacketGetNetType (a,&adapter)) {
				myGlobals.device[i].deviceSpeed = adapter.LinkSpeed;
			} else
			PacketCloseAdapter((LPTSTR)myGlobals.device[i].name);
#endif

	myGlobals.device[i].pcapPtr =
	  pcap_open_live(myGlobals.device[i].name,
			 myGlobals.enablePacketDecoding == 0 ? 68 : DEFAULT_SNAPLEN, 
			 myGlobals.disablePromiscuousMode == 1 ? 0 : 1, 
			 100 /* ms */, ebuf);

	if(myGlobals.device[i].pcapPtr == NULL) {
	  traceEvent(CONST_TRACE_FATALERROR, "pcap_open_live(): '%s'", ebuf);
          if (myGlobals.disablePromiscuousMode == 1)
              traceEvent(CONST_TRACE_INFO, 
                         "Sorry, but on this system, even with -s, it appears that ntop must be started as root");
          traceEvent(CONST_TRACE_INFO, "Please correct the problem or select a different interface using the -i flag");
	  exit(-1);
	}

	if(myGlobals.pcapLog != NULL) {
	  if(strlen(myGlobals.pcapLog) > 64)
	    myGlobals.pcapLog[64] = '\0';
#ifdef WIN32
	  sprintf(myName, "%s/%s.pcap", 
		  myGlobals.pcapLogBasePath, /* Added by Ola Lundqvist <opal@debian.org> */
		  myGlobals.pcapLog);
#else
	  sprintf(myName, "%s/%s.%s.pcap", 
		  myGlobals.pcapLogBasePath, /* Added by Ola Lundqvist <opal@debian.org> */
		  myGlobals.pcapLog, myGlobals.device[i].name);
#endif
	  myGlobals.device[i].pcapDumper = pcap_dump_open(myGlobals.device[i].pcapPtr, myName);

	  if(myGlobals.device[i].pcapDumper == NULL) {
            traceEvent(CONST_TRACE_FATALERROR, "pcap_dump_open(): '%s'", ebuf);
	    exit(-1);
	  } else
		traceEvent(CONST_TRACE_NOISY, "Saving packets into file %s", myName);	
	}

	if(myGlobals.enableSuspiciousPacketDump) {
	  sprintf(myName, "%s/ntop-suspicious-pkts.%s.pcap", 
		  myGlobals.pcapLogBasePath, /* Added by Ola Lundqvist <opal@debian.org> */
		  myGlobals.device[i].name);
	  myGlobals.device[i].pcapErrDumper = pcap_dump_open(myGlobals.device[i].pcapPtr, myName);

	  if(myGlobals.device[i].pcapErrDumper == NULL)
	    traceEvent(CONST_TRACE_FATALERROR, "pcap_dump_open() for suspicious packets: '%s'", ebuf);
	}
      } else {
	myGlobals.device[i].virtualDevice = 1;
	if(column != NULL) column[0] = ':';
      }
    }

    for(i=0; i<myGlobals.numDevices; i++) {
      if((!myGlobals.device[i].virtualDevice)
	 && (pcap_lookupnet(myGlobals.device[i].name,
			    (bpf_u_int32*)&myGlobals.device[i].network.s_addr,
			    (bpf_u_int32*)&myGlobals.device[i].netmask.s_addr, ebuf) < 0)) {
	/* Fix for IP-less interfaces (e.g. bridge)
	   Courtesy of Diana Eichert <deicher@sandia.gov>
	*/
	myGlobals.device[i].network.s_addr = htonl(0);
	myGlobals.device[i].netmask.s_addr = htonl(0xFFFFFFFF);
      } else {
	myGlobals.device[i].network.s_addr = htonl(myGlobals.device[i].network.s_addr);
	myGlobals.device[i].netmask.s_addr = htonl(myGlobals.device[i].netmask.s_addr);
      }
    }
  } else {
    myGlobals.device[0].pcapPtr = pcap_open_offline(myGlobals.rFileName, ebuf);
    strcpy(myGlobals.device[0].name, "pcap-file");
    myGlobals.numDevices = 1;

    if(myGlobals.device[0].pcapPtr == NULL) {
      traceEvent(CONST_TRACE_FATALERROR, "pcap_open_offline(): '%s'", ebuf);
      exit(-1);
    }
  }

#ifdef DEBUG
  {
    struct in_addr addr1;

    addr1.s_addr = myGlobals.device[0].network.s_addr;
    traceEvent(CONST_TRACE_NOISY, "network %s", intoa(addr1));
    addr1.s_addr = myGlobals.device[0].netmask.s_addr;
    traceEvent(CONST_TRACE_NOISY, ", netmask %s.\n", intoa(addr1));
  }
#endif

#ifdef WIN32
  /* This looks like a Win32 libpcap open issue... */
  {
    struct hostent* h;
    char szBuff[80];

    gethostname(szBuff, 79);
    h=gethostbyname(szBuff);
    myGlobals.device[0].netmask.s_addr = 0xFFFFFF00; /* 255.255.255.0 */
    myGlobals.device[0].network.s_addr = myGlobals.device[0].ifAddr.s_addr & myGlobals.device[0].netmask.s_addr;
  }

  /* Sanity check... */
  /*
    if((localHostAddress[0].s_addr & myGlobals.device[0].netmask) != myGlobals.device[0].localnet) {
    struct in_addr addr1, addr2;

    addr1.s_addr = netmask[0];
    addr2.s_addr = myGlobals.device[0].localnet;
    traceEvent(CONST_TRACE_WARNING, "Your IP address %s and netmask %s and local network %s do not match",
                                    intoa(localHostAddress[0]),
                                    intoa(addr1),
                                    intoa(addr2));
    myGlobals.device[0].network = localHostAddress[0].s_addr & myGlobals.device[0].netmask;
    addr1.s_addr = netmask[0];
    addr2.s_addr = myGlobals.device[0].localnet;
    traceEvent(CONST_TRACE_NOISY, "Will use: IP address %s, netmask %s and local network %s",
                                    intoa(localHostAddress[0]),
                                    intoa(addr1),
                                    intoa(addr2));
    myGlobals.device[0].localnet = localHostAddress[0].s_addr & myGlobals.device[0].netmask;
    } */
#endif

  {
    int i;

    for(i=0; i<myGlobals.numDevices; i++) {
      int memlen;

      if(myGlobals.device[i].netmask.s_addr == 0) {
	/* In this case we are using a dump file */
	myGlobals.device[i].netmask.s_addr = 0xFFFFFF00; /* dummy */
      }

      if ( (myGlobals.device[i].network.s_addr == 0) &&
           (myGlobals.device[i].netmask.s_addr == 0xFFFFFFFF) ) { /* Unnumbered interface... */
          myGlobals.device[i].numHosts = MAX_SUBNET_HOSTS;
      } else {
          myGlobals.device[i].numHosts = 0xFFFFFFFF - myGlobals.device[i].netmask.s_addr + 1;

          /* Add some room for multicast hosts in the ipTrafficMatrix
           * This is an arbitrary guess.
           * We use the log function to limit growth for large networks, while the factor of 50
           * is designed to ensure a certain minimal # even for smaller networks 
           */
          myGlobals.device[i].numHosts +=
            ceil(log((double)(0xFFFFFFFF - myGlobals.device[i].netmask.s_addr + 1))+1.0)*50;
      }

      if(myGlobals.device[i].numHosts > MAX_SUBNET_HOSTS) {
	myGlobals.device[i].numHosts = MAX_SUBNET_HOSTS;
	traceEvent(CONST_TRACE_WARNING, "Truncated network size (device %s) to %d hosts (real netmask %s)",
		   myGlobals.device[i].name, myGlobals.device[i].numHosts, intoa(myGlobals.device[i].netmask));
      } else {
	traceEvent(CONST_TRACE_NOISY, "Interface '%s' (netmask %s) computed network size is %d hosts",
		   myGlobals.device[i].name,
                   intoa(myGlobals.device[i].netmask),
                   myGlobals.device[i].numHosts);
      }

      memlen = sizeof(TrafficEntry*)*myGlobals.device[i].numHosts*myGlobals.device[i].numHosts;
      myGlobals.device[i].ipTrafficMatrix = (TrafficEntry**)calloc(myGlobals.device[i].numHosts*myGlobals.device[i].numHosts,
								   sizeof(TrafficEntry*));
      if(myGlobals.device[i].ipTrafficMatrix == NULL) {
	traceEvent(CONST_TRACE_FATALERROR, "Memory allocation (%d bytes) for ipTraffixMatrix failed", memlen);
	exit(-1);
      }

      traceEvent(CONST_TRACE_NOISY, "MEMORY: ipTrafficMatrix base (no TrafficEntry) for interface '%s' is %5.2fMB",
                                   myGlobals.device[i].name,
                                   ((float)(memlen)/(float)(1024.0*1024.0))+0.05);
      myGlobals.ipTrafficMatrixMemoryUsage += memlen;

      memlen = sizeof(struct hostTraffic*)*myGlobals.device[i].numHosts;
      myGlobals.device[i].ipTrafficMatrixHosts = (struct hostTraffic**)calloc(sizeof(struct hostTraffic*),
									      myGlobals.device[i].numHosts);

      if(myGlobals.device[i].ipTrafficMatrixHosts == NULL) {
	traceEvent(CONST_TRACE_FATALERROR, "Memory allocation (%d bytes) for ipTraffixMatrixHosts failed", memlen);
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
  for(i=0; i<myGlobals.numDevices; i++) {
    myGlobals.device[i].activeDevice = 1;
    if(!myGlobals.device[i].virtualDevice) {
      switch(myGlobals.device[i].name[0]) {
      case 't': /* TokenRing */
	myGlobals.device[i].datalink = DLT_IEEE802;
        traceEvent(CONST_TRACE_NOISY, "DLT: Device %d(%s) is \"t...\", treating as DLT_IEEE802 (TokenRing)", 
                               i,
                               myGlobals.device[i].name);
	break;
      case 'l': /* Loopback */
	myGlobals.device[i].datalink = DLT_NULL;
        traceEvent(CONST_TRACE_NOISY, "DLT: Device %d(%s) is loopback, treating as DLT_NULL", 
                               i,
                               myGlobals.device[i].name);
	break;
      default:
	myGlobals.device[i].datalink = DLT_EN10MB; /* Ethernet */
        traceEvent(CONST_TRACE_NOISY, "DLT: Device %d(%s), treating as DLT_EN10MB (10/100/1000 Ethernet)", 
                               i,
                               myGlobals.device[i].name);
      }
    }
  }
#else /* Not AIX */
  for(i=0; i<myGlobals.numDevices; i++) {
    myGlobals.device[i].activeDevice = 1;
    if(!myGlobals.device[i].virtualDevice) {
#if defined(__FreeBSD__)
      if(strncmp(myGlobals.device[i].name, "tun", 3) == 0) {
	myGlobals.device[i].datalink = DLT_PPP;
        traceEvent(CONST_TRACE_NOISY, "DLT: Device %d(%s) is \"tun\", treating as DLT_PPP", 
                               i,
                               myGlobals.device[i].name);
#else /* Not FreeBSD */
      if((myGlobals.device[i].name[0] == 'l') /* loopback check */
	 && (myGlobals.device[i].name[1] == 'o')) {
	myGlobals.device[i].datalink = DLT_NULL;
        traceEvent(CONST_TRACE_NOISY, "DLT: Device %d(%s) is loopback, treating as DLT_NULL", 
                               i,
                               myGlobals.device[i].name);
#endif /* FreeBSD */
      } else {
	myGlobals.device[i].datalink = pcap_datalink(myGlobals.device[i].pcapPtr);
        if (myGlobals.device[i].datalink > MAX_DLT_ARRAY) {
            traceEvent(CONST_TRACE_WARNING, "DLT: Device %d(%s) DLT_ value, %d, exceeds highest known value",
                                      i,
                                      myGlobals.device[i].name,
                                      myGlobals.device[i].datalink);
            traceEvent(CONST_TRACE_NOISY, "DLT: Processing continues OK");
            traceEvent(CONST_TRACE_NOISY, "DLT: Please report this to the ntop-dev list.");
        } else {
#ifdef DEBUG
	  traceEvent(CONST_TRACE_NOISY, "DLT: Device %d(%s) DLT_ is %d, assuming mtu %d, header %d", 
                                   i,
                                   myGlobals.device[i].name,
                                   myGlobals.device[i].datalink,
                                   myGlobals.mtuSize[myGlobals.device[i].datalink],
                                   myGlobals.headerSize[myGlobals.device[i].datalink]);
#endif
	  if ( (myGlobals.mtuSize[myGlobals.device[i].datalink] == 0) ||
	       (myGlobals.mtuSize[myGlobals.device[i].datalink] == CONST_UNKNOWN_MTU) ) {
	    traceEvent(CONST_TRACE_WARNING, "DLT: MTU value for DLT_  %d, is zero or unknown",
		       myGlobals.device[i].datalink);
            traceEvent(CONST_TRACE_NOISY, "DLT: Processing continues OK");
            traceEvent(CONST_TRACE_NOISY, "DLT: Please report your MTU values (e.g. ifconfig) to the ntop-dev list");
	  }
	  if (myGlobals.headerSize[myGlobals.device[i].datalink] == 0) {
	    traceEvent(CONST_TRACE_ERROR, "DLT: Header value for DLT_  %d, is zero",
		       myGlobals.device[i].datalink);
            traceEvent(CONST_TRACE_NOISY, "DLT: Processing continues OK - don't use the nfs plugin");
            traceEvent(CONST_TRACE_NOISY, "DLT: Please report this to the ntop-dev list");
	  }
        }
      }
      }
    }
#endif /* AIX */
}

/* ******************************* */

void parseTrafficFilter(void) {
  /* Construct, compile and set filter */
  if(myGlobals.currentFilterExpression != NULL) {
    int i;
    struct bpf_program fcode;

    for(i=0; i<myGlobals.numDevices; i++) {
      if(myGlobals.device[i].pcapPtr && (!myGlobals.device[i].virtualDevice)) {
	if((pcap_compile(myGlobals.device[i].pcapPtr, &fcode, myGlobals.currentFilterExpression, 1,
			 myGlobals.device[i].netmask.s_addr) < 0)
	   || (pcap_setfilter(myGlobals.device[i].pcapPtr, &fcode) < 0)) {
	  traceEvent(CONST_TRACE_FATALERROR,
		     "Wrong filter '%s' (%s) on interface %s",
		     myGlobals.currentFilterExpression,
		     pcap_geterr(myGlobals.device[i].pcapPtr),
		     myGlobals.device[i].name[0] == '0' ? "<pcap file>" : myGlobals.device[i].name);
	  exit(-1);
	} else
	  traceEvent(CONST_TRACE_NOISY, "Setting filter to \"%s\" on device %s.",
		     myGlobals.currentFilterExpression, myGlobals.device[i].name);
#ifdef HAVE_PCAP_FREECODE
          pcap_freecode(&fcode);
#endif
      }
    }
  } else
    myGlobals.currentFilterExpression = strdup("");	/* so that it isn't NULL! */
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
  /* signal(SIGCHLD, handleDiedChild); */
  signal(SIGCHLD, SIG_IGN);
#endif

#ifndef WIN32
  /* Setup signal handlers */
  signal(SIGTERM, cleanup);
  signal(SIGINT,  cleanup);
  signal(SIGHUP,  handleSigHup);
  signal(SIGPIPE, ignoreThisSignal);
  signal(SIGABRT, ignoreThisSignal);
  if(myGlobals.debugMode) { 
    /* Activate backtrace trap on -K flag */
    signal(SIGSEGV, cleanup);
  }
#endif
}

/* ***************************** */

void startSniffer(void) {
  int i;

#ifdef CFG_MULTITHREADED
  for(i=0; i<myGlobals.numDevices; i++)
    if((!myGlobals.device[i].virtualDevice)
       && (myGlobals.device[i].pcapPtr != NULL)) {
      /*
       * (8) - NPS - Network Packet Sniffer (main thread)
       */
      createThread(&myGlobals.device[i].pcapDispatchThreadId, pcapDispatch, (char*)i);
      traceEvent(CONST_TRACE_INFO, "THREADMGMT: Started thread (%ld) for network packet sniffing on %s",
		 myGlobals.device[i].pcapDispatchThreadId, myGlobals.device[i].name);
    }
#endif
}

/* ***************************** */

u_int createDummyInterface(char *ifName) {
  u_int mallocLen, deviceId = myGlobals.numDevices;
  NtopInterface *tmpDevice;
  
  mallocLen = sizeof(NtopInterface)*(myGlobals.numDevices+1);
  tmpDevice = (NtopInterface*)malloc(mallocLen);
  memset(tmpDevice, 0, mallocLen);    
  if(myGlobals.numDevices > 0) {
    memcpy(tmpDevice, myGlobals.device, 
	   sizeof(NtopInterface)*myGlobals.numDevices);
    free(myGlobals.device);
  }
  
  myGlobals.device = tmpDevice;    
  myGlobals.numDevices++;
  memset(&myGlobals.device[deviceId], 0, sizeof(NtopInterface));

  resetDevice(deviceId);
  myGlobals.device[deviceId].network.s_addr = 0xFFFFFFFF;
  myGlobals.device[deviceId].netmask.s_addr = 0xFFFFFFFF;
  myGlobals.device[deviceId].numHosts = myGlobals.device[0].numHosts;
  myGlobals.device[deviceId].name = strdup(ifName);
  myGlobals.device[deviceId].humanFriendlyName = strdup(ifName);
  myGlobals.device[deviceId].virtualDevice = 0;
  myGlobals.device[deviceId].datalink = DLT_EN10MB;
  myGlobals.device[deviceId].hash_hostTraffic[myGlobals.broadcastEntryIdx] = myGlobals.broadcastEntry;
  myGlobals.device[deviceId].dummyDevice  = 1; /* This is basically a fake device */
  myGlobals.device[deviceId].activeDevice = 1;

  if(myGlobals.otherHostEntry != NULL)
    myGlobals.device[deviceId].hash_hostTraffic[myGlobals.otherHostEntryIdx] = myGlobals.otherHostEntry;    

  return(deviceId);
}
