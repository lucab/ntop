/*
 *  Copyright (C) 2002      Rocco Carbone <rocco@ntop.org>
 *                          Luca Deri <deri@ntop.org>
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

#ifndef GLOBALS_H
#define GLOBALS_H

#if !defined(PATH_SEP)
# if !defined(WIN32)
#  define PATH_SEP '/'
# else
#  define PATH_SEP '\\'
# endif
#endif

/*
 * default configuration parameters
 */
#define NTOP_DEFAULT_CONFFILE    "ntop.conf"
#define NTOP_DEFAULT_PIDFILE     "ntop.pid"
#define NTOP_DEFAULT_LOGFILE     "ntop.log"
#define NTOP_DEFAULT_ACCESSFILE  "ntop.last"

#define NTOP_DEFAULT_DEBUG        0          /* that means debug disabled */
#define NTOP_DEFAULT_SYSLOG       0          /* that means syslog disabled */
#define NTOP_DEFAULT_WEB_PORT     3000

#define NOW ((time_t) time ((time_t *) 0))

/*
 * used to drive the ntop's behaviour via command line options
 */
typedef struct ntopGlobals {
  /* general */
  char *program_name;
  char domainName[MAXHOSTNAMELEN], *shortDomainName;
  HostTraffic *broadcastEntry, *otherHostEntry;
  int ntop_argc;
  char **ntop_argv;

/* command line options */
  u_short traceLevel, debugMode, useSyslog, accuracyLevel;
  u_char enableSessionHandling, enablePacketDecoding, enableFragmentHandling;
  u_char stickyHosts, enableSuspiciousPacketDump, trackOnlyLocalHosts;
  char dbPath[200], accessLogPath[200], *rFileName, *pcapLog;
  char mapperURL[256];     /* URL of the mapper CGI */
  u_int maxHashSize, topHashSize;
  u_int enableNetFlowSupport;
  short usePersistentStorage;
  int numericFlag, logTimeout, daemonMode, mergeInterfaces;

  /* Search paths */
  char **dataFileDirs;
  char **pluginDirs;
  char **configFileDirs;

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
  pthread_t dequeueThreadId, handleWebConnectionsThreadId;
  pthread_t thptUpdateThreadId, scanIdleThreadId, scanIdleSessionsThreadId;
  pthread_t hostTrafficStatsThreadId, dbUpdateThreadId, lsofThreadId;
  pthread_t purgeAddressThreadId;
  PthreadMutex gdbmMutex;
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
  pthread_t dequeueAddressThreadId[MAX_NUM_DEQUEUE_THREADS];
  TrafficCounter droppedAddresses;
#endif
#endif

  /* Database */
  GDBM_FILE gdbm_file, pwFile, eventFile, hostsInfoFile, addressCache;

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
  char *separator;
  int32_t thisZone; /* seconds offset from gmt to local time */
  u_long numPurgedHosts, numTerminatedSessions;

  /* Time */
  time_t actTime, initialSniffTime, lastRefreshTime;
  time_t nextSessionTimeoutScan;
  struct timeval lastPktTime;

  /* NICs */
  int numDevices;
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

  u_short *mtuSize;

  u_short *headerSize;

#ifdef ENABLE_NAPSTER
  NapsterServer napsterSvr[MAX_NUM_NAPSTER_SERVER];
#endif

  char *currentFilterExpression;
} NtopGlobals;

#endif /* GLOBALS_H */
