/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
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
	++p;
	memmove(myGlobals.domainName, p, (MAXHOSTNAMELEN+myGlobals.domainName-p));
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

static void initIPCountryTable(void) {
  int idx, rc;
  u_char compressedFormat;
  struct stat statBuf;
  char buf[LEN_GENERAL_WORK_BUFFER];
  FILE* fd;

  myGlobals.ipCountryCount = 0;
  if((myGlobals.countryFlagHead = malloc(sizeof(IPNode))) == NULL) {
    traceEvent(CONST_TRACE_FATALERROR, "IP2CC: Unable to allocate table memory. Quitting...");
    exit(1);
  }
  myGlobals.ipCountryMem += sizeof(IPNode);

  strcpy(myGlobals.countryFlagHead->node.cc, "***");

  myGlobals.countryFlagHead->b[0]=NULL;
  myGlobals.countryFlagHead->b[1]=NULL;

  fd=checkForInputFile("IP2CC",
                       "IP address <-> Country Code mapping",
                       CONST_P2C_FILE,
                       NULL,
                       &compressedFormat);
  if(fd != NULL) {
      char *strtokState, *cc, *ip, *prefix;
      int numRead=0;

      while(readInputFile(fd,
                          "IP2CC",
                          FALSE,
                          compressedFormat,
                          10000,
                          buf, sizeof(buf),
                          &numRead) == 0) {
	  if((cc=strtok_r(buf, ":", &strtokState))==NULL)       continue;
	  if((ip=strtok_r(NULL, "/", &strtokState))==NULL)      continue;
	  if((prefix=strtok_r(NULL, "\n", &strtokState))==NULL) continue;

	  strtolower(cc);

	  addNodeInternal(xaton(ip), atoi(prefix), cc, 0);
      }
      myGlobals.ipCountryCount += numRead;

  } else {
    traceEvent(CONST_TRACE_WARNING,
               "IP2CC: Unable to read IP address <-> Country code mapping file (non-existant or no data)");
    traceEvent(CONST_TRACE_INFO,
               "IP2CC: ntop will perform correctly but without this minor feature");
  }
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
void resetDevice(int devIdx) {
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
  resetTrafficCounter(&myGlobals.device[devIdx].egpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].osiBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].ipv6Bytes);
  resetTrafficCounter(&myGlobals.device[devIdx].otherBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].fcBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].fragmentedFcBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].fcFcpBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].fcFiconBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].fcIpfcBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].fcSwilsBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].fcDnsBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].fcElsBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].otherFcBytes);
  resetTrafficCounter(&myGlobals.device[devIdx].class2Bytes);
  resetTrafficCounter(&myGlobals.device[devIdx].class3Bytes);
  resetTrafficCounter(&myGlobals.device[devIdx].classFBytes);
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
  resetTrafficCounter(&myGlobals.device[devIdx].fcPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].fcEofaPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].fcEofAbnormalPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].fcAbnormalPkts);
  resetTrafficCounter(&myGlobals.device[devIdx].fcBroadcastPkts);
  memset(&myGlobals.device[devIdx].rcvdPktStats, 0, sizeof(PacketStats));
  memset(&myGlobals.device[devIdx].rcvdFcPktStats, 0, sizeof(FcPacketStats));
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
  myGlobals.device[devIdx].hostsno = 0;

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
  
  if(myGlobals.device[devIdx].ipProtosList != NULL) {
    free(myGlobals.device[devIdx].ipProtosList); 
    myGlobals.device[devIdx].ipProtosList = NULL;
  }

  createDeviceIpProtosList(devIdx);
}

/* ******************************************* */

void initCounters(void) {
  int len, i, rc;
  FILE* fd;
  int numRead = 0;
  u_char compressedFormat;
  char buf[LEN_GENERAL_WORK_BUFFER];
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

  setDomainName();

#ifdef INET6
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
#endif

  memset(myGlobals.transTimeHash, 0, sizeof(myGlobals.transTimeHash));
  memset(myGlobals.dummyEthAddress, 0, LEN_ETHERNET_ADDRESS);

  for(len=0; len<LEN_ETHERNET_ADDRESS; len++)
    myGlobals.dummyEthAddress[len] = len;

  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.enableSessionHandling) {
      len = sizeof(IPSession*)*MAX_TOT_NUM_SESSIONS;
      myGlobals.device[i].tcpSession = (IPSession**)malloc(len);
      memset(myGlobals.device[i].tcpSession, 0, len);

      len = sizeof(FCSession *)*MAX_TOT_NUM_SESSIONS;
      myGlobals.device[i].fcSession = (FCSession **)malloc(len);
      memset(myGlobals.device[i].fcSession, 0, len);
    } else {
      myGlobals.device[i].tcpSession     = NULL;
      myGlobals.device[i].fcSession      = NULL;
    }

    myGlobals.device[i].fragmentList = NULL;
  }

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

  if (myGlobals.rFileName == NULL) {
      myGlobals.initialSniffTime = myGlobals.lastRefreshTime = time(NULL);
  }
  else {
      myGlobals.initialSniffTime = 0; /* We set the start when first pkt is
                                       * read */ 
  }
  myGlobals.capturePackets = FLAG_NTOPSTATE_RUN;

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

  myGlobals.webServerRequestQueueLength = DEFAULT_WEBSERVER_REQUEST_QUEUE_LEN;

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
   *   Note we're only checking here, so we forceClose...
   */
  fd=checkForInputFile("OSFP",
                       "OS fingerprint table",
                       CONST_OSFINGERPRINT_FILE,
                       NULL,
                       &compressedFormat);
  if(fd != NULL) {
      readInputFile(fd,
                    "OSFP",  
                    TRUE,
                    compressedFormat,
                    0,
                    NULL, 0,
                    &numRead);

  } else {
      traceEvent(CONST_TRACE_NOISY, "OSFP: ntop continues ok, but without OS fingerprinting.");
      traceEvent(CONST_TRACE_NOISY, "OSFP: If the file 'magically' appears, OS fingerprinting will automatically be enabled.");
  }

  /*
   * Process ASN file
   */
  numRead=0;
  fd=checkForInputFile("ASN",
                       "Autonomous System Number table",
                       CONST_ASLIST_FILE,
                       NULL,
                       &compressedFormat);
  if(fd != NULL) {
      char *strtokState, *as, *ip, *prefix;

      memset(&buf, 0, sizeof(buf));

      myGlobals.asHead = malloc(sizeof(IPNode));
      memset(myGlobals.asHead, 0, sizeof(IPNode));
      myGlobals.asHead->node.as = 0;
      myGlobals.asMem += sizeof(IPNode);
    
      while(readInputFile(fd,
                          "ASN",
                          FALSE,
                          compressedFormat,
                          25000,
                          buf, sizeof(buf),
                          &numRead) == 0) {

        if((as = strtok_r(buf, ":", &strtokState)) == NULL)  continue;
        if((ip = strtok_r(NULL, "/", &strtokState)) == NULL)  continue;
        if((prefix = strtok_r(NULL, "\n", &strtokState)) == NULL)  continue;

        addNodeInternal(xaton(ip), atoi(prefix), NULL, atoi(as));
        myGlobals.asCount++;
      }
      traceEvent(CONST_TRACE_INFO, "ASN: ....Used %d KB of memory (%d per entry)",
                 ((myGlobals.asMem+512)/1024), sizeof(IPNode));
  } else {
    traceEvent(CONST_TRACE_NOISY, "ASN: ntop continues ok, but without ASN information.");
  }

  /* i18n */
#ifdef MAKE_WITH_I18N
  /*
   *  Obtain - from the os - the default locale.
   */
  workLanguage = setlocale(LC_ALL, "");
  if(workLanguage != NULL ) {
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
  if(nLang < 0) {
    traceEvent(CONST_TRACE_WARNING,
	       "I18N: Error obtaining locale list, scandir(%s,...) errno is %d\n",
	       locale_dir,
	       errno);
    traceEvent(CONST_TRACE_NOISY, "continues without multiple language support");
  } else {
    traceEvent(CONST_TRACE_NOISY, "I18N: scandir(%s,...) returned %d", locale_dir, nLang);
    for (iLang=0; (iLang<nLang) && (myGlobals.maxSupportedLanguages < MAX_LANGUAGES_SUPPORTED); iLang++) {
#ifdef I18N_DEBUG
      traceEvent(CONST_TRACE_NOISY, "I18N_DEBUG: %2d. '%s'", iLang, dirList[iLang]->d_name);
#endif
      if(dirList[iLang]->d_name[0] == '.') {
	/* skip parent/self directory entries */
	continue;
      }

      if( (dirList[iLang]->d_type == DT_DIR) ||
	  (dirList[iLang]->d_type == DT_LNK) ) {
	tmpStr = i18n_xvert_locale2common(dirList[iLang]->d_name);

	if(!strcmp(myGlobals.defaultLanguage, tmpStr)) {
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
	  if(!strcmp(tmpStr, myGlobals.supportedLanguages[i])) {
	    traceEvent(CONST_TRACE_NOISY,
		       "I18N_DEBUG: Skipping already supported language, '%s'\n",
		       dirList[iLang]->d_name);
#ifdef I18N_DEBUG
#endif
	    found=1;
	    break;
	  }
	}
	if(!found) {
	  traceEvent(CONST_TRACE_NOISY,
		     "I18N: Testing locale '%s' (from '%s')\n",
		     tmpStr,
		     dirList[iLang]->d_name);
	  for(i=0; (!found) && (myGlobals.dataFileDirs[i] != NULL); i++) {

	    if(snprintf(buf, sizeof(buf), "%s/html_%s",
			myGlobals.dataFileDirs[i],
			tmpStr) < 0)
	      BufferTooShort();
#ifdef WIN32
	    j=0;
	    while (buf[j] != '\0') {
	      if(buf[j] == '/') buf[j] = '\\';
	      j++;
	    }
#endif

#ifdef I18N_DEBUG
	    traceEvent(CONST_TRACE_NOISY,
		       "I18N_DEBUG: Looking for directory '%s'\n",
		       buf);
#endif
	    testDirEnt = opendir(buf);
	    if(testDirEnt != NULL) {
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

	  if(!found) {
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
	traceEvent(CONST_TRACE_NOISY, "I18N_DEBUG: Skipping file '%s' (type %d)",
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

  /*
   * Guess at the version of gd.  Since there's no gdVersion() function, we do
   * this in an ugly way - we load the .so library and look for the entry point
   * of functions that have been added along the way.
   */
  traceEvent(CONST_TRACE_INFO, "GDVERCHK: Guessing at libgd version");
  myGlobals.gdVersionGuess = strdup(gdVersionGuess());
  if(myGlobals.gdVersionGuess != NULL)
    traceEvent(CONST_TRACE_INFO, "GDVERCHK: ... as %s", myGlobals.gdVersionGuess);

}


/* ******************************* */

void resetStats(int deviceId) {
  u_int j, i;
  FCSession *session;

  traceEvent(CONST_TRACE_INFO, "Resetting traffic statistics for device %s",
	     myGlobals.device[deviceId].humanFriendlyName);

#ifdef CFG_MULTITHREADED
  if(myGlobals.purgeMutex.isInitialized != 0)
    accessMutex(&myGlobals.purgeMutex, "resetStats");
#endif

#ifdef CFG_MULTITHREADED
  if(myGlobals.hostsHashMutex.isInitialized != 0)
    accessMutex(&myGlobals.hostsHashMutex, "resetStats");
#endif

  for(j=FIRST_HOSTS_ENTRY; j<myGlobals.device[deviceId].actualHashSize; j++) {
    HostTraffic *el = myGlobals.device[deviceId].hash_hostTraffic[j], *elNext;

    while(el != NULL) {
      elNext = el->next;

      if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry))
	freeHostInfo(el, deviceId);

      el = elNext;
    }

    myGlobals.device[deviceId].hash_hostTraffic[j] = NULL;
  }

  resetDevice(deviceId);

  if(myGlobals.device[deviceId].tcpSession != NULL) {
    for(j=0; j<MAX_TOT_NUM_SESSIONS; j++)
      if(myGlobals.device[deviceId].tcpSession[j] != NULL) {
	free(myGlobals.device[deviceId].tcpSession[j]);
	myGlobals.device[deviceId].tcpSession[j] = NULL;
      }
  }

  if(myGlobals.device[deviceId].fcSession != NULL) {
    for(j=0; j<MAX_TOT_NUM_SESSIONS; j++)
      if((session = myGlobals.device[deviceId].fcSession[j]) != NULL) {
          for (i = 0; i < MAX_LUNS_SUPPORTED; i++) {
              if (session->activeLuns[i] != NULL) {
                  free (session->activeLuns[i]);
              }
          }
          free(session);
          myGlobals.device[deviceId].fcSession[j] = NULL;
      }
  }

  /* Free VSAN Hash */
  if (myGlobals.device[deviceId].vsanHash != NULL) {
      free (myGlobals.device[deviceId].vsanHash);
      myGlobals.device[deviceId].vsanHash = NULL;
  }

  myGlobals.device[deviceId].hash_hostTraffic[BROADCAST_HOSTS_ENTRY] = myGlobals.broadcastEntry;
  myGlobals.broadcastEntry->hostSerial.serialType = SERIAL_IPV4;
  myGlobals.broadcastEntry->hostSerial.value.ipAddress.Ip4Address.s_addr = -1;
  myGlobals.broadcastEntry->next = NULL;
  FD_SET(FLAG_BROADCAST_HOST, &(myGlobals.broadcastEntry->flags));

  if(myGlobals.otherHostEntry != myGlobals.broadcastEntry) {
    myGlobals.device[deviceId].hash_hostTraffic[OTHER_HOSTS_ENTRY] = myGlobals.otherHostEntry;
    /* Dirty trick */
    myGlobals.otherHostEntry->hostSerial.serialType = SERIAL_IPV4;
    myGlobals.otherHostEntry->hostSerial.value.ipAddress.Ip4Address.s_addr = -1;
    myGlobals.otherHostEntry->next = NULL;
    FD_SET(FLAG_BROADCAST_HOST, &(myGlobals.broadcastEntry->flags));
    myGlobals.otherHostEntry->next = NULL;
  }

#ifdef CFG_MULTITHREADED
  if(myGlobals.hostsHashMutex.isInitialized != 0)
    releaseMutex(&myGlobals.hostsHashMutex);
#endif

#ifdef CFG_MULTITHREADED
  if(myGlobals.purgeMutex.isInitialized)
    releaseMutex(&myGlobals.purgeMutex);
#endif
}

/* ******************************* */

void initSingleGdbm(GDBM_FILE *database, char *dbName, char *directory,
		    int doUnlink, struct stat *statbuf) {
  char tmpBuf[200], theDate[48];
  time_t        st_time, now;
  struct tm t;
  int d;

  /* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au>. */
  /* directory is used by intop to specify where to open the files.
     If called with NULL, use the myGlobals.dbPath value instead
     (Minor fix for intop - Burton Strauss (BStrauss@acm.org) - Apr2002)
  */

  if(snprintf(tmpBuf, sizeof(tmpBuf), "%s/%s",
	      directory != NULL ? directory : myGlobals.dbPath,
	      dbName) < 0)
    BufferTooShort();

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

	/* Use universal format: 01 Jan 2003 hh:mm:ss */
	strftime(theDate, sizeof(theDate)-1, "%d %b %Y %H:%M:%S", localtime_r(&st_time, &t));
	theDate[sizeof(theDate)-1] = '\0';
	now  = time(NULL);
	traceEvent(CONST_TRACE_NOISY,
		   "...last create/modify/access was %s, %d second(s) ago",
		   theDate,
		   d = difftime(now, st_time));

	if(d > CONST_DNSCACHE_PERMITTED_AGE) {
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
       
    if(directory == NULL)
      traceEvent(CONST_TRACE_INFO, "Possible solution: please use '-P <directory>'");
    else {
      traceEvent(CONST_TRACE_INFO, "1. Is another instance of ntop running?");
      traceEvent(CONST_TRACE_INFO, "2. Make sure that the use you specified can write in the target directory"); 
    }
    exit(-1);
  }
}

/* ************************************************************ */

#if defined(CFG_MULTITHREADED) && defined(HAVE_PTHREAD_ATFORK)
void reinitMutexes (void) {

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
  createMutex(&myGlobals.tcpSessionsMutex); /* data to synchronize TCP sessions
                                             * access */
  createMutex(&myGlobals.fcSessionsMutex);
  createMutex(&myGlobals.purgePortsMutex);  /* data to synchronize port purge access */
  createMutex(&myGlobals.packetQueueMutex);
  createMutex(&myGlobals.packetProcessMutex);
  createMutex(&myGlobals.hostsHashMutex);
  createMutex(&myGlobals.securityItemsMutex);

 #ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  if(myGlobals.numericFlag == 0) {
    createMutex(&myGlobals.addressResolutionMutex);
  }
 #endif
}
#endif /* CFG_MULTITHREADED */

/*
 * Initialize all the threads used by ntop to:
 * a) sniff packets from NICs and push them in internal data structures
 * b) pop and decode packets
 * c) collect data
 * d) display/emit information
 */
void initThreads(void) {
  int i;

  traceEvent(CONST_TRACE_INFO, "Initializing semaphores, mutexes and threads");

#ifdef CFG_MULTITHREADED
 #ifdef HAVE_PTHREAD_ATFORK
  i = pthread_atfork(NULL, NULL, &reinitMutexes);
  traceEvent(CONST_TRACE_INFO, "NOTE: atfork() handler registered for mutexes, rc %d", i);
 #endif

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
  createMutex(&myGlobals.tcpSessionsMutex); /* data to synchronize TCP sessions access */
  createMutex(&myGlobals.fcSessionsMutex); /* data to synchronize TCP sessions access */
  createMutex(&myGlobals.purgePortsMutex);  /* data to synchronize port purge access */
  createMutex(&myGlobals.purgeMutex);       /* synchronize purging */
  createMutex(&myGlobals.securityItemsMutex);

  /*
   * Create the thread (1) - NPA - Network Packet Analyzer (main thread)
   */
  createMutex(&myGlobals.packetProcessMutex);
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
  if(myGlobals.rFileName == NULL) {
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
  if(myGlobals.useSSLwatchdog == 1)
#endif
    {
      traceEvent(CONST_TRACE_NOISY, "Initializing Condvar for ssl watchdog");
      createCondvar(&myGlobals.sslwatchdogCondvar);
      myGlobals.sslwatchdogCondvar.predicate = FLAG_SSLWATCHDOG_UNINIT;
    }
#endif
}


/*
 * Initialize helper applications
 */
void initApps(void) {
  traceEvent(CONST_TRACE_INFO, "Initializing external applications");
  /* Nothing to do at the moment */
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
 * if device is "none" it adds a dummy interface
 */
void addDevice(char* deviceName, char* deviceDescr) {
  int i, deviceId, mallocLen, memlen;
  NtopInterface *tmpDevice, *oldDevice;
  char *workDevices = NULL;
  char myName[80], *column = NULL;
  char ebuf[CONST_SIZE_PCAP_ERR_BUF];
  
  if(deviceName == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Attempt to add a NULL device");
    return;
  }

  /* Remove unwanted characters */
  for(i=0; i<strlen(deviceDescr); i++)
    switch(deviceDescr[i]) {
    case ':':
    case '/':
    case '\\':
      deviceDescr[i] = '_';
    }

  traceEvent(CONST_TRACE_NOISY, "Adding network device %s", deviceName);

  if((deviceName != NULL) && (strcmp(deviceName, "none") == 0)) {
    deviceId = createDummyInterface("none");
    traceEvent(CONST_TRACE_INFO, "-i none, so initialized only a dummy device");
  } else {
    mallocLen = sizeof(NtopInterface)*(myGlobals.numDevices+1);
    tmpDevice = (NtopInterface*)malloc(mallocLen);
    memset(tmpDevice, 0, mallocLen);
    memcpy(tmpDevice, myGlobals.device, sizeof(NtopInterface)*(myGlobals.numDevices));
    oldDevice = myGlobals.device;
    myGlobals.device = tmpDevice;
    if (oldDevice != NULL) free(oldDevice);
    deviceId = myGlobals.numDevices;
    myGlobals.device[deviceId].humanFriendlyName = strdup(deviceDescr);
    myGlobals.device[deviceId].name = strdup(deviceName);
    myGlobals.numDevices++, myGlobals.numRealDevices++;

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
	NetType adapter;

	LPADAPTER a = PacketOpenAdapter((LPTSTR)myGlobals.device[deviceId].name);

	if(a == NULL) {
	  traceEvent(CONST_TRACE_FATALERROR, "Unable to open device '%s' (invalid name?)",
		     myGlobals.device[deviceId].name);
	  exit(-1);
	}
	if(PacketGetNetType (a,&adapter)) {
	  myGlobals.device[deviceId].deviceSpeed = adapter.LinkSpeed;
	} else
	  PacketCloseAdapter((LPTSTR)myGlobals.device[deviceId].name);
      }
#else
    if(setuid(0) == -1) {
      traceEvent(CONST_TRACE_FATALERROR, "Unable to become root");
    }
#endif

    if (myGlobals.noFc) {
      myGlobals.device[deviceId].pcapPtr =
	pcap_open_live(myGlobals.device[deviceId].name,
		       myGlobals.enablePacketDecoding == 0 ? 68 : DEFAULT_SNAPLEN,
		       myGlobals.disablePromiscuousMode == 1 ? 0 : 1,
		       100 /* ms */, ebuf);
    }
    else {
        myGlobals.device[deviceId].pcapPtr =
	pcap_open_live(myGlobals.device[deviceId].name,
		       MAX_PACKET_LEN,
		       myGlobals.disablePromiscuousMode == 1 ? 0 : 1,
		       100 /* ms */, ebuf);
    }

      if(myGlobals.device[deviceId].pcapPtr == NULL) {
	traceEvent(CONST_TRACE_FATALERROR, "pcap_open_live(): '%s'", ebuf);
	if(myGlobals.disablePromiscuousMode == 1)
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
		deviceId);
#else
	sprintf(myName, "%s/%s.%s.pcap",
		myGlobals.pcapLogBasePath, /* Added by Ola Lundqvist <opal@debian.org> */
		myGlobals.pcapLog, myGlobals.device[deviceId].name);
#endif
	myGlobals.device[deviceId].pcapDumper = pcap_dump_open(myGlobals.device[deviceId].pcapPtr, myName);

	if(myGlobals.device[deviceId].pcapDumper == NULL) {
          traceEvent(CONST_TRACE_FATALERROR, "pcap_dump_open(..., '%s') failed", myName);
	  exit(-1);
	} else
	  traceEvent(CONST_TRACE_NOISY, "Saving packets into file %s", myName);
      }

    if(myGlobals.enableSuspiciousPacketDump) {
#ifdef WIN32        
	sprintf(myName, "%s/ntop-suspicious-pkts.dev%d.pcap",
		myGlobals.pcapLogBasePath, /* Added by Ola Lundqvist <opal@debian.org> */
		deviceId);
#else
	sprintf(myName, "%s/ntop-suspicious-pkts.%s.pcap",
		myGlobals.pcapLogBasePath, /* Added by Ola Lundqvist <opal@debian.org> */
		myGlobals.device[deviceId].name);
#endif        
	myGlobals.device[deviceId].pcapErrDumper = pcap_dump_open(myGlobals.device[deviceId].pcapPtr, myName);

	if(myGlobals.device[deviceId].pcapErrDumper == NULL) {
          myGlobals.enableSuspiciousPacketDump = 0;
	  traceEvent(CONST_TRACE_ERROR, "pcap_dump_open(..., '%s') failed (suspicious packets)", myName);
	  traceEvent(CONST_TRACE_INFO, "Continuing without suspicious packet dump");
        }
      }

      if(myGlobals.enableOtherPacketDump) {
	sprintf(myName, "%s/ntop-other-pkts.%s.pcap",
		myGlobals.pcapLogBasePath,
		myGlobals.device[deviceId].name);
	myGlobals.device[deviceId].pcapOtherDumper = pcap_dump_open(myGlobals.device[deviceId].pcapPtr, myName);

	if(myGlobals.device[deviceId].pcapOtherDumper == NULL) {
          myGlobals.enableOtherPacketDump = 0;
	  traceEvent(CONST_TRACE_ERROR, "pcap_dump_open(..., '%s') failed (other (unknown) packets)", myName);
	  traceEvent(CONST_TRACE_INFO, "Continuing without other (unknown) packet dump");
        }
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

    if((myGlobals.device[deviceId].network.s_addr == 0) &&
       (myGlobals.device[deviceId].netmask.s_addr == 0xFFFFFFFF) ) { /* Unnumbered interface... */
      myGlobals.device[deviceId].numHosts = MAX_SUBNET_HOSTS;
    } else {
      myGlobals.device[deviceId].numHosts = 0xFFFFFFFF - myGlobals.device[deviceId].netmask.s_addr + 1;

      /* Add some room for multicast hosts in the ipTrafficMatrix
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

    memlen = sizeof(TrafficEntry*)*myGlobals.device[deviceId].numHosts*myGlobals.device[deviceId].numHosts;
    myGlobals.device[deviceId].ipTrafficMatrix = (TrafficEntry**)calloc(myGlobals.device[deviceId].numHosts
									*myGlobals.device[deviceId].numHosts,
									sizeof(TrafficEntry*));
    if(myGlobals.device[deviceId].ipTrafficMatrix == NULL) {
      traceEvent(CONST_TRACE_FATALERROR, "Memory allocation (%d bytes) for ipTraffixMatrix failed", memlen);
      exit(-1);
    }

    traceEvent(CONST_TRACE_NOISY, "MEMORY: ipTrafficMatrix base (no TrafficEntry) for interface '%s' is %5.2fMB",
	       myGlobals.device[deviceId].name,
	       ((float)(memlen)/(float)(1024.0*1024.0))+0.05);
    myGlobals.ipTrafficMatrixMemoryUsage += memlen;

    memlen = sizeof(struct hostTraffic*)*myGlobals.device[deviceId].numHosts;
    myGlobals.device[deviceId].ipTrafficMatrixHosts = (struct hostTraffic**)calloc(sizeof(struct hostTraffic*),
										   myGlobals.device[deviceId].numHosts);

    if(myGlobals.device[deviceId].ipTrafficMatrixHosts == NULL) {
      traceEvent(CONST_TRACE_FATALERROR, "Memory allocation (%d bytes) for ipTraffixMatrixHosts failed", memlen);
      exit(-1);
    }

    /* Allocate FC Traffic Matrices */
#ifdef NOT_YET    
    if (!myGlobals.noFc) {
        memlen = sizeof(TrafficEntry*)*myGlobals.device[deviceId].numHosts*myGlobals.device[deviceId].numHosts;
        myGlobals.device[deviceId].fcTrafficMatrix = (TrafficEntry**)calloc(myGlobals.device[deviceId].numHosts
                                                                            *myGlobals.device[deviceId].numHosts,
                                                                            sizeof(TrafficEntry*));
        if(myGlobals.device[deviceId].fcTrafficMatrix == NULL) {
            traceEvent(CONST_TRACE_FATALERROR, "Memory allocation (%d bytes) for fcTraffixMatrix failed", memlen);
            exit(-1);
        }
        myGlobals.fcTrafficMatrixMemoryUsage += memlen;

        memlen = sizeof(struct hostTraffic*)*myGlobals.device[deviceId].numHosts;
        myGlobals.device[deviceId].fcTrafficMatrixHosts = (struct hostTraffic**)calloc(sizeof(struct hostTraffic*),
                                                                                       myGlobals.device[deviceId].numHosts);
    }
#endif    
  }

  /* ********************************************* */

  if(!(myGlobals.device[deviceId].dummyDevice || myGlobals.device[deviceId].virtualDevice)){
    getLocalHostAddress(&myGlobals.device[deviceId].ifAddr, myGlobals.device[deviceId].name);
#ifdef INET6
    myGlobals.device[deviceId].v6Addrs = getLocalHostAddressv6(myGlobals.device[deviceId].v6Addrs, myGlobals.device[deviceId].name);
#endif
  }

  mallocLen = 2;
  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.device[i].name != NULL)
      mallocLen += strlen(myGlobals.device[i].name) + 2;
  }
  workDevices = malloc(mallocLen);
  memset(workDevices, 0, mallocLen);

  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.device[i].name != NULL) {
      if(i>0) strcat(workDevices, ", ");
      strcat(workDevices, myGlobals.device[i].name);
    }
  }
  
  if(myGlobals.devices != NULL) free(myGlobals.devices);
  myGlobals.devices = workDevices;

  /* ********************************************** */

#ifndef WIN32
  if(strncmp(myGlobals.device[deviceId].name, "lo", 2)) {
    /* Do not care of virtual loopback interfaces */
    int k;
    char tmpDeviceName[64];
    struct in_addr myLocalHostAddress;
    

    if(myGlobals.numDevices < MAX_NUM_DEVICES) {
      traceEvent(CONST_TRACE_INFO, "Checking %s for additional devices", myGlobals.device[deviceId].name);
      for(k=0; k<=MAX_NUM_DEVICES_VIRTUAL; k++) {
	if(snprintf(tmpDeviceName, sizeof(tmpDeviceName), "%s:%d", myGlobals.device[deviceId].name, k) < 0)
	  BufferTooShort();

	traceEvent(CONST_TRACE_NOISY, "Checking %s", tmpDeviceName);
	if(getLocalHostAddress(&myLocalHostAddress, tmpDeviceName) == 0) {
	  /* The virtual interface exists */

	  mallocLen = sizeof(NtopInterface)*(myGlobals.numDevices+1);
	  tmpDevice = (NtopInterface*)malloc(mallocLen);
	  memset(tmpDevice, 0, mallocLen);
	  memcpy(tmpDevice, myGlobals.device, sizeof(NtopInterface)*myGlobals.numDevices);
	  free(myGlobals.device);
	  myGlobals.device = tmpDevice;

	  myGlobals.device[myGlobals.numDevices].ifAddr.s_addr = myLocalHostAddress.s_addr;
	  if(myLocalHostAddress.s_addr == myGlobals.device[deviceId].ifAddr.s_addr)
	    continue; /* No virtual Interfaces */
	 myGlobals.device[myGlobals.numDevices].virtualDevice = 1;
	 myGlobals.device[myGlobals.numDevices].activeDevice = 1;
	 myGlobals.device[myGlobals.numDevices].humanFriendlyName = strdup(tmpDeviceName);
	  myGlobals.device[myGlobals.numDevices++].name = strdup(tmpDeviceName);
	  traceEvent(CONST_TRACE_INFO, "Added virtual interface: '%s'", tmpDeviceName);
          if(myGlobals.numDevices < MAX_NUM_DEVICES) {
	    traceEvent(CONST_TRACE_WARNING, "Stopping scan - no room for additional (virtual) interfaces");
	    break;
          }
	} else
	  break; /* No virtual interface */
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

/*
 * If device is NULL, this function adds the default interface
 * if device is "none" it adds a dummy interface
 */
void initDevices(char* devices) {
  char *tmpDev=NULL, *tmpDescr=NULL;
#ifdef WIN32
#define MAX_IF_NAME    256
  pcap_if_t *devpointer;
  char intNames[32][MAX_IF_NAME], intDescr[32][MAX_IF_NAME];
  int ifIdx = 0;
  int defaultIdx = -1;
#endif
  int found=0, intfc;
  char ebuf[CONST_SIZE_PCAP_ERR_BUF];
  char myName[80];

  ebuf[0] = '\0';

  traceEvent(CONST_TRACE_NOISY, "Initializing network devices");

  if(myGlobals.rFileName != NULL) {
    createDummyInterface("none");
    myGlobals.device[0].dummyDevice = 0;
    myGlobals.device[0].pcapPtr  = pcap_open_offline(myGlobals.rFileName, ebuf);

    if(myGlobals.device[0].pcapPtr == NULL) {
      traceEvent(CONST_TRACE_FATALERROR, "pcap_open_offline(): '%s'", ebuf);
      exit(-1);
    }

    resetStats(0);
    initDeviceDatalink(0);

    if(myGlobals.enableSuspiciousPacketDump) {
        sprintf(myName, "%s/ntop-suspicious-pkts.%s.pcap",
                myGlobals.pcapLogBasePath, /* Added by Ola Lundqvist <opal@debian.org> */
                myGlobals.device[0].name);
        myGlobals.device[0].pcapErrDumper = pcap_dump_open(myGlobals.device[0].pcapPtr, myName);
        
        if(myGlobals.device[0].pcapErrDumper == NULL)
            traceEvent(CONST_TRACE_ALWAYSDISPLAY, "pcap_dump_open() for suspicious packets: '%s'", ebuf);
    }
  
    free(myGlobals.device[0].name);
    myGlobals.device[0].name = strdup("pcap-file");
    myGlobals.numDevices = 1;

    return;
  }

#ifdef WIN32
  if(pcap_findalldevs(&devpointer, ebuf) < 0) {
    traceEvent(CONST_TRACE_FATALERROR, "pcap_findalldevs() call failed [%s]", ebuf);
    traceEvent(CONST_TRACE_FATALERROR, "Have you instaled winpcap properly?");
    exit(-1);
  } else {
    int i;

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

  if(devices == NULL) {
    /* Searching the default device */
#ifdef WIN32
    /*
      Nothing to do as the previous #ifdef WIN32 branch
      did the job already
    */
#else
    tmpDev = pcap_lookupdev(ebuf);

    if(tmpDev == NULL) {
      traceEvent(CONST_TRACE_FATALERROR, "Unable to locate default interface (%s)", ebuf);
      exit(-1);
    }

    tmpDescr = tmpDev;    
    traceEvent(CONST_TRACE_NOISY, "Default device is '%s'", tmpDescr);
#endif

    addDevice(tmpDev, tmpDescr);
  } else {
    /* User has specified devices in the parameter list */
    char *workDevices = strdup(devices), *strtokState;
    int warnedVirtual = 0;

    tmpDev = strtok_r(workDevices, ",", &strtokState);

    while(tmpDev != NULL) {
#ifndef WIN32
      char *nwInterface;
      deviceSanityCheck(tmpDev); /* These checks do not apply to Win32 */

      traceEvent(CONST_TRACE_NOISY, "Checking requested device '%s'", tmpDev);

      if((nwInterface = strchr(tmpDev, ':')) != NULL) {
 	/* This is a virtual nwInterface */
        char *requestedDev;

        /* Copy (unaltered) for traceEvent() messages */
        requestedDev = strdup(tmpDev);

        if(!warnedVirtual) {
          warnedVirtual = 1;
          traceEvent(CONST_TRACE_WARNING, "Virtual device(s), e.g. %s, specified on -i | --interface parameter are ignored", tmpDev);
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
	traceEvent(CONST_TRACE_FATALERROR, "Interface index '%d' is out of range [0..%d]", atoi(tmpDev), ifIdx);
	exit(-1);
      }
	  } else {
		/* Nothing to do: the user has specified an interface name */
		tmpDescr = NULL;
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
  }
}

/* ******************************* */

void initDeviceDatalink(int deviceId) {
  if(myGlobals.device[deviceId].dummyDevice) return;
  myGlobals.device[deviceId].activeDevice = 1;
  if(myGlobals.device[deviceId].virtualDevice) return;

  /* get datalink type */
#ifdef AIX
  /* This is a bug of libpcap on AIX - so we totally ignore libpcap */
  switch(myGlobals.device[deviceId].name[0]) {
  case 't': /* TokenRing */
    myGlobals.device[deviceId].datalink = DLT_IEEE802;
    traceEvent(CONST_TRACE_NOISY, "DLT: Device %d [%s] is \"t...\", treating as DLT_IEEE802 (TokenRing)",
	      deviceId,
	       myGlobals.device[deviceId].name);
    break;
  case 'l': /* Loopback */
    myGlobals.device[deviceId].datalink = DLT_NULL;
    traceEvent(CONST_TRACE_NOISY, "DLT: Device %d [%s] is loopback, treating as DLT_NULL",
	       deviceId,
	       myGlobals.device[deviceId].name);
    break;
  default:
    myGlobals.device[deviceId].datalink = DLT_EN10MB; /* Ethernet */
    traceEvent(CONST_TRACE_NOISY, "DLT: Device %d [%s], treating as DLT_EN10MB (10/100/1000 Ethernet)",
	       deviceId,
	       myGlobals.device[deviceId].name);
  }
#else
  /* Other OSes have SOME issues, but if we don't recognize the special device,
   * use libpcap */
 #if defined(__FreeBSD__)
  if(strncmp(myGlobals.device[deviceId].name, "tun", 3) == 0) {
    myGlobals.device[deviceId].datalink = DLT_PPP;
    traceEvent(CONST_TRACE_NOISY, "DLT: Device %d [%s] is \"tun\", treating as DLT_PPP",
	       deviceId,
	       myGlobals.device[deviceId].name);
  } else
 #else /* Not AIX or FreeBSD */
  if((myGlobals.device[deviceId].name[0] == 'l') /* loopback check */
     && (myGlobals.device[deviceId].name[1] == 'o')) {
    myGlobals.device[deviceId].datalink = DLT_NULL;
    traceEvent(CONST_TRACE_NOISY, "DLT: Device %d [%s] is loopback, treating as DLT_NULL",
	       deviceId,
	       myGlobals.device[deviceId].name);
  } else
 #endif

    myGlobals.device[deviceId].datalink = pcap_datalink(myGlobals.device[deviceId].pcapPtr);

#endif

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

// create-suspicious-packets",        no_argument,       NULL, 'q'
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

#ifdef HANDLE_DIED_CHILD
extern RETSIGTYPE handleDiedChild(int sig _UNUSED_); /*FreeBSD hack: to remove */
#endif

void initSignals(void) {
  /*
    The handler below has been restored due
    to compatibility problems:
    Courtesy of Martin Lucina <mato@kotelna.sk>
  */
#ifndef WIN32
#ifdef HANDLE_DIED_CHILD
  signal(SIGCHLD, handleDiedChild);
#else
  signal(SIGCHLD, SIG_IGN);
#endif
#endif

#ifndef WIN32
  /* Setup signal handlers */
  signal(SIGTERM, cleanup);
  signal(SIGINT,  cleanup);
  signal(SIGHUP,  handleSigHup);
  signal(SIGPIPE, ignoreThisSignal);
  signal(SIGABRT, ignoreThisSignal);
#if 0
  if(myGlobals.debugMode) {
    /* Activate backtrace trap on -K flag */
    signal(SIGSEGV, cleanup);
  }
#endif
#endif
}

/* ***************************** */

void startSniffer(void) {
  int i;

#ifdef CFG_MULTITHREADED
  for(i=0; i<myGlobals.numDevices; i++)
    if((!myGlobals.device[i].virtualDevice)
       && (!myGlobals.device[i].dummyDevice)
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

  traceEvent(CONST_TRACE_INFO, "Creating dummy interface, '%s'", ifName);

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
  myGlobals.device[deviceId].datalink = DLT_EN10MB;
  myGlobals.device[deviceId].hash_hostTraffic[BROADCAST_HOSTS_ENTRY] = myGlobals.broadcastEntry;
  myGlobals.broadcastEntry->next = NULL;
  myGlobals.device[deviceId].dummyDevice   = 1; /* This is basically a fake device */
  myGlobals.device[deviceId].virtualDevice = 0;
  myGlobals.device[deviceId].activeDevice  = 0;

  if(myGlobals.otherHostEntry != NULL) {
    myGlobals.device[deviceId].hash_hostTraffic[OTHER_HOSTS_ENTRY] = myGlobals.otherHostEntry;
    myGlobals.otherHostEntry->next = NULL;
  }

#ifdef NOT_YET  
  mallocLen = sizeof(TrafficEntry*)*myGlobals.device[deviceId].numHosts*myGlobals.device[deviceId].numHosts;
  myGlobals.device[deviceId].fcTrafficMatrix = (TrafficEntry**)calloc(myGlobals.device[deviceId].numHosts
                                                                      *myGlobals.device[deviceId].numHosts,
                                                                      sizeof(TrafficEntry*));
  if(myGlobals.device[deviceId].fcTrafficMatrix == NULL) {
      traceEvent(CONST_TRACE_FATALERROR, "Memory allocation (%d bytes) for fcTraffixMatrix failed", mallocLen);
      exit(-1);
  }
  
  mallocLen = sizeof(struct hostTraffic*)*myGlobals.device[deviceId].numHosts;
  myGlobals.device[deviceId].fcTrafficMatrixHosts = (struct hostTraffic**)calloc(sizeof(struct hostTraffic*),
                                                                                 myGlobals.device[deviceId].numHosts);

  if(myGlobals.device[deviceId].fcTrafficMatrixHosts == NULL) {
      traceEvent(CONST_TRACE_FATALERROR, "Memory allocation (%d bytes) for fcTrafficMatrixHosts failed", mallocLen);
      exit(-1);
  }
#endif 

  return(deviceId);
}
