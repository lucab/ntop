/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
 *
 *		 	    http://www.ntop.org/
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

/* general */
#ifdef WIN32
char *version, *osName, *author, *buildDate;
#endif
char *program_name;
char domainName[MAXHOSTNAMELEN], *shortDomainName;
HostTraffic *broadcastEntry, *otherHostEntry;
int ntop_argc;
char **ntop_argv;

/* command line options */
u_short traceLevel, debugMode, useSyslog, accuracyLevel;
u_char enableSessionHandling, enablePacketDecoding, enableFragmentHandling;
u_char stickyHosts, enableSuspiciousPacketDump;
char dbPath[200], accessLogPath[200], *rFileName, *pcapLog;
char mapperURL[256];     /* URL of the mapper CGI */
u_int maxHashSize, topHashSize;
u_int enableNetFlowSupport;
short usePersistentStorage;
int numericFlag, logTimeout, daemonMode, mergeInterfaces;


/* Search paths */
char *dataFileDirs[]   = { ".", DATAFILE_DIR, NULL };
char *pluginDirs[]     = { "./plugins", PLUGIN_DIR, NULL };
char *configFileDirs[] = { ".", CONFIGFILE_DIR, "/etc", NULL };

/* Debug */
size_t allocatedMemory;

/* SSL */
#ifdef HAVE_OPENSSL
int sslInitialized, sslPort;
#endif

/* Logging */
time_t nextLogTime;

/* Flags */
int isLsofPresent, isNmapPresent, filterExpressionInExtraFrame;
short capturePackets, endNtop, borderSnifferMode;


/* Multithreading */
#ifdef MULTITHREADED
unsigned short numThreads, numDequeueThreads;
PthreadMutex packetQueueMutex, hostsHashMutex, graphMutex;
PthreadMutex lsofMutex, addressResolutionMutex, hashResizeMutex;
pthread_t dequeueThreadId[MAX_NUM_DEQUEUE_THREADS], handleWebConnectionsThreadId;
pthread_t thptUpdateThreadId, scanIdleThreadId, scanIdleSessionsThreadId;
pthread_t hostTrafficStatsThreadId, dbUpdateThreadId, lsofThreadId;
pthread_t purgeAddressThreadId;
#ifdef HAVE_GDBM_H
PthreadMutex gdbmMutex;
#endif /* HAVE_GDBM_H */
#ifdef USE_SEMAPHORES
sem_t queueSem;
#ifdef ASYNC_ADDRESS_RESOLUTION
sem_t queueAddressSem;
#endif /* ASYNC_ADDRESS_RESOLUTION */
#else /* USE_SEMAPHORES */
ConditionalVariable queueCondvar;
#ifdef ASYNC_ADDRESS_RESOLUTION
ConditionalVariable queueAddressCondvar;
#endif /* USE_SEMAPHORES */
#endif 
#ifdef ASYNC_ADDRESS_RESOLUTION
pthread_t dequeueAddressThreadId;
TrafficCounter droppedAddresses;
#endif
#endif

/* Database */
#ifdef HAVE_GDBM_H
GDBM_FILE gdbm_file, pwFile, eventFile, hostsInfoFile, addressCache;
#endif

/* lsof support */
u_short updateLsof;
ProcessInfo **processes;
u_short numProcesses;
ProcessInfoList *localPorts[TOP_IP_PORT];


/* Filter Chains */
u_short handleRules;
FlowFilterList *flowsList;
FilterRuleChain *tcpChain, *udpChain, *icmpChain;
u_short ruleSerialIdentifier;
FilterRule* filterRulesList[MAX_NUM_RULES];

/* Address Resolution */
#if defined(ASYNC_ADDRESS_RESOLUTION)
u_int addressQueueLen, maxAddressQueueLen;
#endif
u_long numResolvedWithDNSAddresses, numKeptNumericAddresses, numResolvedOnCacheAddresses;

/* Misc */
char *separator = "&nbsp;";
int32_t thisZone; /* seconds offset from gmt to local time */
u_long numPurgedHosts, numTerminatedSessions;

/* Time */
time_t actTime, initialSniffTime, lastRefreshTime;
time_t nextSessionTimeoutScan;
struct timeval lastPktTime;

/* NICs */
int deviceId; /* Set by processPacket() */
int numDevices, actualDeviceId;
NtopInterface *device;

/* Monitored Protocols */
char **protoIPTrafficInfos;
u_short numIpProtosToMonitor, numIpPortsToHandle;
PortMapper *ipPortMapper;
int numActServices, numIpPortMapperSlots;
unsigned long numHandledHTTPrequests;
ServiceEntry **udpSvc, **tcpSvc;

/* Packet Capture */
#if defined(MULTITHREADED)
PacketInformation packetQueue[PACKET_QUEUE_LENGTH+1];
u_int packetQueueLen, maxPacketQueueLen, packetQueueHead, packetQueueTail;
#endif

TransactionTime transTimeHash[NUM_TRANSACTION_ENTRIES];

u_int broadcastEntryIdx, otherHostEntryIdx;
u_char dummyEthAddress[ETHERNET_ADDRESS_LEN];

u_short mtuSize[] = {
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

u_short headerSize[] = {
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

#ifdef ENABLE_NAPSTER
NapsterServer napsterSvr[MAX_NUM_NAPSTER_SERVER];
#endif

char *currentFilterExpression;
