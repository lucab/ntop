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
void initNtopGlobals(int argc, char * argv[])
{
  int i;

  memset(&myGlobals, 0, sizeof(myGlobals));

  /*
   * Notice the program name
   */
  myGlobals.program_name = strrchr(argv[0], PATH_SEP);
  myGlobals.program_name =
    (!myGlobals.program_name || !myGlobals.program_name[0]) ? (argv[0]) : (++myGlobals.program_name);


  myGlobals.domainName[0] = '\0';
  myGlobals.shortDomainName = '\0';
  myGlobals.broadcastEntry = NULL;
  myGlobals.otherHostEntry = NULL;
  myGlobals.ntop_argc = argc;
  myGlobals.ntop_argv = argv;

#ifdef HAVE_GDCHART
  myGlobals.throughput_chart_type = GDC_AREA;
#endif

 myGlobals.noAdminPasswordHint = 0;

  /* command line options */
  myGlobals.traceLevel = DEFAULT_TRACE_LEVEL;
  myGlobals.debugMode = 0;

#ifndef WIN32
  myGlobals.useSyslog = 0;
#endif

  myGlobals.accuracyLevel = HIGH_ACCURACY_LEVEL;
  myGlobals.enableSessionHandling = 0;
  myGlobals.enablePacketDecoding = 0;
  myGlobals.enableFragmentHandling = 0;

  myGlobals.stickyHosts = 0;
  myGlobals.enableSuspiciousPacketDump = 0;
  myGlobals.trackOnlyLocalHosts = 0;

  strncpy(myGlobals.dbPath, DBFILE_DIR, sizeof(myGlobals.dbPath));

#ifdef HAVE_GDCHART
  myGlobals.throughput_chart_type = GDC_AREA;
#endif

  snprintf(myGlobals.accessLogPath, sizeof(myGlobals.accessLogPath), "%s/%s",
	   myGlobals.dbPath, DETAIL_ACCESS_LOG_FILE_PATH);

  myGlobals.rFileName = NULL;
  myGlobals.pcapLog = '\0';

  /*
   * If you need a good mapper look at this
   * http://jake.ntop.org/cgi-bin/mapper.pl
   */
  myGlobals.mapperURL[0] = '\0';

  myGlobals.maxHashSize = MAX_HASH_SIZE;
  myGlobals.topHashSize = 0;
  myGlobals.enableNetFlowSupport = 0;
  myGlobals.usePersistentStorage = 0;
  myGlobals.numericFlag = 0;
  myGlobals.logTimeout = 0;

  myGlobals.daemonMode = 0;
  if (strcmp(myGlobals.program_name, "ntopd") == 0) {
    myGlobals.daemonMode++;
  }

  myGlobals.mergeInterfaces = 0;

  /* Search paths */
  myGlobals.dataFileDirs   = _dataFileDirs;
  myGlobals.pluginDirs     = _pluginDirs;
  myGlobals.configFileDirs = _configFileDirs;

  /* Debug */
  myGlobals.allocatedMemory = 0;

#ifdef HAVE_OPENSSL
  myGlobals.sslInitialized = 0;
  myGlobals.sslPort = 0;           /* Disabled by default: it can enabled using -W <SSL port> */
#endif

  /* Logging */
  myGlobals.nextLogTime = 0;

  /* Flags */
  myGlobals.isLsofPresent = 0;
  myGlobals.isNmapPresent = 0;
  myGlobals.filterExpressionInExtraFrame = 0;
  myGlobals.capturePackets = 0;
  myGlobals.endNtop = 0;
  myGlobals.borderSnifferMode = 0;

  /* Multithreading */
#ifdef MULTITHREADED
  myGlobals.numThreads = 0;
  myGlobals.numDequeueThreads = 0;

  /* the following code needs a major revision */
#if (0)
  memset(&myGlobals.packetQueueMutex.mutex, 0, sizeof(pthread_mutex_t));
  myGlobals.packetQueueMutex.isLocked = 0;
  myGlobals.packetQueueMutex.isInitialized = 0;
  myGlobals.packetQueueMutex.lockFile[0] = '\0';
  myGlobals.packetQueueMutex.lockLine = 0;
  myGlobals.packetQueueMutex.unlockFile[0] = '\0';
  myGlobals.packetQueueMutex.unlockLine = 0;
  myGlobals.packetQueueMutex.numLocks = 0;
  myGlobals.packetQueueMutex.numReleases = 0;
  myGlobals.packetQueueMutex.lockTime = 0;
  myGlobals.packetQueueMutex.maxLockedDurationUnlockFile[0] = '\0';
  myGlobals.packetQueueMutex.maxLockedDurationUnlockLine = 0;
  myGlobals.packetQueueMutex.maxLockedDuration = 0;

  memset(&myGlobals.hostsHashMutex.mutex, 0, sizeof(pthread_mutex_t));
  myGlobals.hostsHashMutex.isLocked = 0;
  myGlobals.hostsHashMutex.isInitialized = 0;
  myGlobals.hostsHashMutex.lockFile[0] = '\0';
  myGlobals.hostsHashMutex.lockLine = 0;
  myGlobals.hostsHashMutex.unlockFile[0] = '\0';
  myGlobals.hostsHashMutex.unlockLine = 0;
  myGlobals.hostsHashMutex.numLocks = 0;
  myGlobals.hostsHashMutex.numReleases = 0;
  myGlobals.hostsHashMutex.lockTime = 0;
  myGlobals.hostsHashMutex.maxLockedDurationUnlockFile[0] = '\0';
  myGlobals.hostsHashMutex.maxLockedDurationUnlockLine = 0;
  myGlobals.hostsHashMutex.maxLockedDuration = 0;

  memset(&myGlobals.graphMutex.mutex, 0, sizeof(pthread_mutex_t));
  myGlobals.graphMutex.isLocked = 0;
  myGlobals.graphMutex.isInitialized = 0;
  myGlobals.graphMutex.lockFile[0] = '\0';
  myGlobals.graphMutex.lockLine = 0;
  myGlobals.graphMutex.unlockFile[0] = '\0';
  myGlobals.graphMutex.unlockLine = 0;
  myGlobals.graphMutex.numLocks = 0;
  myGlobals.graphMutex.numReleases = 0;
  myGlobals.graphMutex.lockTime = 0;
  myGlobals.graphMutex.maxLockedDurationUnlockFile[0] = '\0';
  myGlobals.graphMutex.maxLockedDurationUnlockLine = 0;
  myGlobals.graphMutex.maxLockedDuration = 0;

  memset(&myGlobals.lsofMutex.mutex, 0, sizeof(pthread_mutex_t));
  myGlobals.lsofMutex.isLocked = 0;
  myGlobals.lsofMutex.isInitialized = 0;
  myGlobals.lsofMutex.lockFile[0] = '\0';
  myGlobals.lsofMutex.lockLine = 0;
  myGlobals.lsofMutex.unlockFile[0] = '\0';
  myGlobals.lsofMutex.unlockLine = 0;
  myGlobals.lsofMutex.numLocks = 0;
  myGlobals.lsofMutex.numReleases = 0;
  myGlobals.lsofMutex.lockTime = 0;
  myGlobals.lsofMutex.maxLockedDurationUnlockFile[0] = '\0';
  myGlobals.lsofMutex.maxLockedDurationUnlockLine = 0;
  myGlobals.lsofMutex.maxLockedDuration = 0;

  memset(&myGlobals.addressResolutionMutex.mutex, 0, sizeof(pthread_mutex_t));
  myGlobals.addressResolutionMutex.isLocked = 0;
  myGlobals.addressResolutionMutex.isInitialized = 0;
  myGlobals.addressResolutionMutex.lockFile[0] = '\0';
  myGlobals.addressResolutionMutex.lockLine = 0;
  myGlobals.addressResolutionMutex.unlockFile[0] = '\0';
  myGlobals.addressResolutionMutex.unlockLine = 0;
  myGlobals.addressResolutionMutex.numLocks = 0;
  myGlobals.addressResolutionMutex.numReleases = 0;
  myGlobals.addressResolutionMutex.lockTime = 0;
  myGlobals.addressResolutionMutex.maxLockedDurationUnlockFile[0] = '\0';
  myGlobals.addressResolutionMutex.maxLockedDurationUnlockLine = 0;
  myGlobals.addressResolutionMutex.maxLockedDuration = 0;

  memset(&myGlobals.hashResizeMutex.mutex, 0, sizeof(pthread_mutex_t));
  myGlobals.hashResizeMutex.isLocked = 0;
  myGlobals.hashResizeMutex.isInitialized = 0;
  myGlobals.hashResizeMutex.lockFile[0] = '\0';
  myGlobals.hashResizeMutex.lockLine = 0;
  myGlobals.hashResizeMutex.unlockFile[0] = '\0';
  myGlobals.hashResizeMutex.unlockLine = 0;
  myGlobals.hashResizeMutex.numLocks = 0;
  myGlobals.hashResizeMutex.numReleases = 0;
  myGlobals.hashResizeMutex.lockTime = 0;
  myGlobals.hashResizeMutex.maxLockedDurationUnlockFile[0] = '\0';
  myGlobals.hashResizeMutex.maxLockedDurationUnlockLine = 0;
  myGlobals.hashResizeMutex.maxLockedDuration = 0;

  myGlobals.dequeueThreadId = 0;
  myGlobals.handleWebConnectionsThreadId = 0;
  myGlobals.thptUpdateThreadId = 0;
  myGlobals.scanIdleThreadId = 0;
  myGlobals.hostTrafficStatsThreadId = 0;
  myGlobals.dbUpdateThreadId = 0;
  myGlobals.lsofThreadId = 0;
  myGlobals.purgeAddressThreadId = 0;

  memset(&myGlobals.gdbmMutex.mutex, 0, sizeof(pthread_mutex_t));
  myGlobals.gdbmMutex.isLocked = 0;
  myGlobals.gdbmMutex.isInitialized = 0;
  myGlobals.gdbmMutex.lockFile[0] = '\0';
  myGlobals.gdbmMutex.lockLine = 0;
  myGlobals.gdbmMutex.unlockFile[0] = '\0';
  myGlobals.gdbmMutex.unlockLine = 0;
  myGlobals.gdbmMutex.numLocks = 0;
  myGlobals.gdbmMutex.numReleases = 0;
  myGlobals.gdbmMutex.lockTime = 0;
  myGlobals.gdbmMutex.maxLockedDurationUnlockFile[0] = '\0';
  myGlobals.gdbmMutex.maxLockedDurationUnlockLine = 0;
  myGlobals.gdbmMutex.maxLockedDuration = 0;

#ifdef USE_SEMAPHORES
  memset(&myGlobals.queueSem, 0, sizeof(sem_t));
# ifdef ASYNC_ADDRESS_RESOLUTION
  memset(&myGlobals.queueAddressSem, 0, sizeof(sem_t));
# endif /* ASYNC_ADDRESS_RESOLUTION */

#else /* USE_SEMAPHORES */

  memset(&myGlobals.queueCondvar, 0, sizeof(ConditionalVariable));
# ifdef ASYNC_ADDRESS_RESOLUTION
  memset(&myGlobals.queueAddressCondvar, 0, sizeof(ConditionalVariable));
# endif /* USE_SEMAPHORES */
#endif


#endif /* 0 */


#ifdef ASYNC_ADDRESS_RESOLUTION
  for (i = 0; i < MAX_NUM_DEQUEUE_THREADS; i ++)
    myGlobals.dequeueAddressThreadId[i] = 0;
  myGlobals.droppedAddresses = 0;
#endif
#endif

  /* Database */
  myGlobals.gdbm_file = NULL;
  myGlobals.pwFile = NULL;
  myGlobals.eventFile = NULL;
  myGlobals.hostsInfoFile = NULL;
  myGlobals.addressCache = NULL;

  /* lsof support */
  myGlobals.updateLsof = 0;
  myGlobals.processes = NULL;
  myGlobals.numProcesses = 0;
  for (i = 0; i < TOP_IP_PORT; i ++)
    myGlobals.localPorts[i] = NULL;

  /* Filter Chains */
  myGlobals.handleRules = 0;
  myGlobals.flowsList = NULL;
  myGlobals.tcpChain = NULL;
  myGlobals.udpChain = NULL;
  myGlobals.icmpChain = NULL;

  myGlobals.ruleSerialIdentifier=1; /* 0 will break the logic */

  for (i = 0; i < MAX_NUM_RULES; i ++)
    myGlobals.filterRulesList[i] = NULL;

  /* Address Resolution */
#if defined(ASYNC_ADDRESS_RESOLUTION)
  myGlobals.addressQueueLen = 0;
  myGlobals.maxAddressQueueLen = 0;
#endif
  myGlobals.numResolvedWithDNSAddresses = 0;
  myGlobals.numKeptNumericAddresses = 0;
  myGlobals.numResolvedOnCacheAddresses = 0;

  /* Misc */
  myGlobals.separator = "&nbsp;";
  myGlobals.thisZone = 0;                 /* seconds offset from gmt to local time */
  myGlobals.numPurgedHosts = 0;
  myGlobals.numTerminatedSessions = 0;

  /* Time */
  myGlobals.actTime = time(NULL);
  myGlobals.initialSniffTime = 0;
  myGlobals.lastRefreshTime = 0;
  myGlobals.nextSessionTimeoutScan = 0;
  myGlobals.lastPktTime.tv_sec = 0;
  myGlobals.lastPktTime.tv_usec = 0;

  /* NICs */
  myGlobals.numDevices = 0;
  myGlobals.device = NULL;

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

  myGlobals.broadcastEntryIdx = 0;
  myGlobals.otherHostEntryIdx = 0;
  myGlobals.dummyEthAddress[0] = '\0';

#ifdef ENABLE_NAPSTER
  for (i = 0; i < MAX_NUM_NAPSTER_SERVER; i ++)
    memset(&myGlobals.napsterSvr[i], 0, sizeof(NapsterServer));
#endif

  myGlobals.currentFilterExpression = NULL;

  myGlobals.mtuSize        = _mtuSize;
  myGlobals.headerSize     = _headerSize;
}
