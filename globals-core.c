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
#include "globals-report.h"

NtopGlobals myGlobals;


#ifdef WIN32
char *version, *osName, *author, *buildDate;
#endif

static u_short _mtuSize[] = {
  8232,   	/* no link-layer encapsulation */
  /* 1500 + 14 bytes header
     Courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */
  1500+sizeof(struct ether_header),   /* Ethernet (10Mb) */
  UNKNOWN_MTU,  /* Experimental Ethernet (3Mb) */
  UNKNOWN_MTU,  /* Amateur Radio AX.25 */
  17914,	/* Proteon ProNET Token Ring */
  UNKNOWN_MTU,  /* Chaos */
  4096+sizeof(struct tokenRing_header),	        /* IEEE 802 Networks */
  UNKNOWN_MTU,  /* ARCNET */
  UNKNOWN_MTU,  /* Serial Line IP */
  UNKNOWN_MTU,  /* Point-to-point Protocol */
  4470,	        /* FDDI - Courtesy of Richard Parvass <Richard.Parvass@ReckittBenckiser.com> */
  9180,         /* LLC/SNAP encapsulated atm */
  UNKNOWN_MTU,  /* raw IP */
  UNKNOWN_MTU,  /* BSD/OS Serial Line IP */
  UNKNOWN_MTU	/* BSD/OS Point-to-point Protocol */
};


static u_short _headerSize[] = {
  NULL_HDRLEN,  /* no link-layer encapsulation */
  sizeof(struct ether_header),	        /* Ethernet (10Mb) */
  UNKNOWN_MTU,  /* Experimental Ethernet (3Mb) */
  UNKNOWN_MTU,  /* Amateur Rdio AX.25 */
  sizeof(struct tokenRing_header),	/* Proteon ProNET Token Ring */
  UNKNOWN_MTU,  /* Chaos */
  1492,	        /* IEEE 802 Networks */
  UNKNOWN_MTU,  /* ARCNET */
  UNKNOWN_MTU,  /* Serial Line IP */
  PPP_HDRLEN,   /* Point-to-point Protocol */
  sizeof(struct fddi_header),	        /* FDDI */
  0,            /* LLC/SNAP encapsulated atm */
  0,            /* raw IP */
  UNKNOWN_MTU,  /* BSD/OS Serial Line IP */
  UNKNOWN_MTU	/* BSD/OS Point-to-point Protocol */
};


static char *_dataFileDirs[]   = { ".", DATAFILE_DIR, NULL };
static char *_pluginDirs[]     = { "./plugins", PLUGIN_DIR, NULL };
static char *_configFileDirs[] = { ".", CONFIGFILE_DIR, "/etc", NULL };


/*
 * Initialize all global run-time parameters to default (reasonable!!!) values
 */
void initNtopGlobals(int argc, char * argv[]) {
  int i;

  memset(&myGlobals, 0, sizeof(myGlobals));

  /*
   * Notice the program name
   */
  myGlobals.program_name = strrchr(argv[0], PATH_SEP);
  myGlobals.program_name =
    (!myGlobals.program_name || !myGlobals.program_name[0]) ? (argv[0]) : (++myGlobals.program_name);

  /*
   * save command line parameters
   */
  myGlobals.ntop_argc = argc;
  myGlobals.ntop_argv = argv;

  myGlobals.accessLogPath = NULL;    /* access log filename disabled by default */
  myGlobals.stickyHosts = 0;

  myGlobals.daemonMode = 0;
  if (strcmp(myGlobals.program_name, "ntopd") == 0) {
    myGlobals.daemonMode++;
  }

  myGlobals.rFileName = NULL;
  myGlobals.devices = NULL;
  myGlobals.borderSnifferMode = 0;
  myGlobals.filterExpressionInExtraFrame = 0;
  myGlobals.pcapLog = NULL;
  myGlobals.numericFlag = 0;
  myGlobals.enableSuspiciousPacketDump = 0;
  myGlobals.traceLevel = DEFAULT_TRACE_LEVEL;
    myGlobals.currentFilterExpression = NULL;
  myGlobals.domainName[0] = '\0';
  myGlobals.isLsofPresent = 0;

#ifndef WIN32
  myGlobals.debugMode = 0;
  myGlobals.useSyslog = 0;
#endif

  myGlobals.mergeInterfaces = 1;     /* by default ntop will merge network interfaces */
  myGlobals.isNmapPresent = 0;
  myGlobals.usePersistentStorage = 0;
  myGlobals.mapperURL = NULL;

#ifdef HAVE_GDCHART
  myGlobals.throughput_chart_type = GDC_AREA;
#endif

  /* Other flags (to be set via command line options one day) */
  myGlobals.enableSessionHandling = 0;
  myGlobals.enablePacketDecoding = 0;
  myGlobals.enableFragmentHandling = 0;
  myGlobals.trackOnlyLocalHosts = 0;

  /* Search paths */
  myGlobals.dataFileDirs    = _dataFileDirs;
  myGlobals.pluginDirs      = _pluginDirs;
  myGlobals.configFileDirs  = _configFileDirs;
  myGlobals.pcapLogBasePath = strdup(DBFILE_DIR);   /* a NULL pointer will break the logic */
  myGlobals.dbPath          = strdup(DBFILE_DIR);   /* a NULL pointer will break the logic */

  /* the table of enabled NICs */
  myGlobals.numDevices = 0;
  myGlobals.device = NULL;

  /* Databases */
  myGlobals.gdbm_file = NULL;
  myGlobals.pwFile = NULL;
  myGlobals.hostsInfoFile = NULL;
  myGlobals.addressCache = NULL;

  /* the table of broadcast entries */
  myGlobals.broadcastEntryIdx = 0;
  myGlobals.broadcastEntry = NULL;

  /* the table of other hosts entries */
  myGlobals.otherHostEntryIdx = 0;
  myGlobals.otherHostEntry = NULL;

  /* administrative */
  myGlobals.shortDomainName = NULL;

#ifdef MULTITHREADED
  myGlobals.numThreads = 0;            /* # of running threads */

  myGlobals.numDequeueThreads = 1;

#ifdef ASYNC_ADDRESS_RESOLUTION
  for (i = 0; i < MAX_NUM_DEQUEUE_THREADS; i ++)
    myGlobals.dequeueAddressThreadId[i] = (pthread_t)-1;
  myGlobals.droppedAddresses = 0;
#endif

#endif /* MULTITHREADED */

#ifdef HAVE_OPENSSL
  myGlobals.sslInitialized = 0;
  myGlobals.sslPort = 0;           /* Disabled by default: it can enabled using -W <SSL port> */
#endif

  myGlobals.webPort = 3000;

  /* Termination flags */
  myGlobals.capturePackets = 1;    /* By default data are collected into internal variables */
  myGlobals.endNtop = 0;

  myGlobals.processes = NULL;
  myGlobals.numProcesses = 0;

  /* lsof support */
  if(myGlobals.isLsofPresent)
    myGlobals.updateLsof = 1;
  else
    myGlobals.updateLsof = 0;
  for (i = 0; i < TOP_IP_PORT; i ++)
    myGlobals.localPorts[i] = NULL;       /* myGlobals.localPorts is used by lsof */

#if defined(ASYNC_ADDRESS_RESOLUTION)
  myGlobals.addressQueueLen = 0;
  myGlobals.maxAddressQueueLen = 0;
#endif

  /* Address Resolution counters */
  myGlobals.numResolvedWithDNSAddresses = 0;
  myGlobals.numKeptNumericAddresses = 0;
  myGlobals.numResolvedOnCacheAddresses = 0;

  /* Misc */
  myGlobals.separator = "&nbsp;";

  myGlobals.thisZone = gmt2local(0);      /* seconds offset from gmt to local time */
  myGlobals.numPurgedHosts = 0;
  myGlobals.numTerminatedSessions = 0;

  /* Time */
  myGlobals.actTime = time(NULL);
  myGlobals.initialSniffTime = 0;
  myGlobals.lastRefreshTime = 0;
  myGlobals.nextSessionTimeoutScan = 0;
  myGlobals.lastPktTime.tv_sec = 0;
  myGlobals.lastPktTime.tv_usec = 0;

  /* Monitored Protocols */
  myGlobals.numActServices = 0;
  myGlobals.udpSvc = NULL;
  myGlobals.tcpSvc = NULL;

  myGlobals.protoIPTrafficInfos = NULL;
  myGlobals.numIpProtosToMonitor = 0;
  myGlobals.numIpPortsToHandle = 0;
  myGlobals.ipPortMapper = NULL;
  myGlobals.numIpPortMapperSlots = 0;
  myGlobals.numHandledHTTPrequests = 0;

  /* Packet Capture */
#if defined(MULTITHREADED)
  for (i = 0; i <= PACKET_QUEUE_LENGTH; i ++)
    memset(&myGlobals.packetQueue[i], 0, sizeof(PacketInformation));

  myGlobals.packetQueueLen = 0;
  myGlobals.maxPacketQueueLen = 0;
  myGlobals.packetQueueHead = 0;
  myGlobals.packetQueueTail = 0;
#endif

  for (i = 0; i < NUM_TRANSACTION_ENTRIES; i ++)
    memset(&myGlobals.transTimeHash[i], 0, sizeof(TransactionTime));

  myGlobals.dummyEthAddress[0] = '\0';

  myGlobals.mtuSize        = _mtuSize;
  myGlobals.headerSize     = _headerSize;

#ifdef MEMORY_DEBUG
  myGlobals.allocatedMemory = 0;
#endif

  myGlobals.enableThUpdate  = 1;
  myGlobals.enableIdleHosts = 1;

  myGlobals.netFlowInSocket = -1;  
  myGlobals.netFlowOutSocket = -1;  
  myGlobals.globalFlowSequence = myGlobals.globalFlowPktCount = 0;
}
