/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 2002   Luca Deri <deri@ntop.org>
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

#define MAX_NUM_BAD_IP_ADDRESSES         3

/*
 * used to drive the ntop's behaviour at run-time
 */
typedef struct ntopGlobals {

  /* general */
  char *program_name;           /* The name the program was run with, stripped of any leading path */
  int ntop_argc;                /* # of command line arguments */
  char **ntop_argv;             /* vector of command line arguments */

  /* command line options */

  char *accessLogPath;               /* 'a' */
  u_char stickyHosts;                /* 'c' */
  int daemonMode;                    /* 'd' */
  char *rFileName;                   /* 'f' */
  char *devices;                     /* 'i' */
  short borderSnifferMode;           /* 'j' */
  int filterExpressionInExtraFrame;  /* 'k' */
  char *pcapLog;                     /* 'l' */
  int numericFlag;                   /* 'n' */
  u_char enableSuspiciousPacketDump; /* 'q' */
  u_int maxHashSize;                 /* 's' */
  u_short traceLevel;                /* 't' */
  char *currentFilterExpression;     /* 'B' */
  char domainName[MAXHOSTNAMELEN];   /* 'D' */
  int isLsofPresent;                 /* 'E' */

#ifndef WIN32
  u_short debugMode;                 /* 'K' */
  int useSyslog;                     /* 'L' */
#endif

  int mergeInterfaces;               /* 'M' */
  int isNmapPresent;                 /* 'N' */
  char *pcapLogBasePath;             /* 'O' */ /* Added by Ola Lundqvist <opal@debian.org>. */
  char *dbPath;                      /* 'P' */
  short usePersistentStorage;        /* 'S' */
  char *mapperURL;                   /* 'U' */


#ifdef HAVE_GDCHART
  int throughput_chart_type;         /* '129' */
#endif

  /* Other flags (these could set via command line options one day) */
  u_char enableSessionHandling;
  u_char enablePacketDecoding;
  u_char enableFragmentHandling;
  u_char trackOnlyLocalHosts;
  u_char disablePromiscuousMode;

  /* Search paths */
  char **dataFileDirs;
  char **pluginDirs;
  char **configFileDirs;

  /* NICs */
  int numDevices;          /* # of Network interfaces enabled for sniffing */
  NtopInterface *device;   /* pointer to the table of Network interfaces */

  /* Database */
  GDBM_FILE gdbm_file, pwFile, eventFile, hostsInfoFile, addressCache, prefsFile;

  /* the table of broadcast entries */
  u_int broadcastEntryIdx;
  HostTraffic *broadcastEntry;
  
  /* the table of other hosts entries */
  u_int otherHostEntryIdx;
  HostTraffic *otherHostEntry;
  HostSerial  serialCounter;

  /* Administrative */
  char *shortDomainName;
  struct in_addr weDontWantToTalkWithYou[MAX_NUM_BAD_IP_ADDRESSES];

#ifdef MULTITHREADED
  unsigned short numThreads;           /* # of running threads */

#ifdef USE_SEMAPHORES
  sem_t queueSem;

#ifdef ASYNC_ADDRESS_RESOLUTION
  sem_t queueAddressSem;
#endif /* ASYNC_ADDRESS_RESOLUTION */

#else /* ! USE_SEMAPHORES */

  ConditionalVariable queueCondvar;

#ifdef ASYNC_ADDRESS_RESOLUTION
  ConditionalVariable queueAddressCondvar;
#endif /* USE_SEMAPHORES */

#endif /* ! USE_SEMAPHORES */

  /*
   * NPA - Network Packet Analyzer (main thread)
   */
  PthreadMutex packetQueueMutex;
  pthread_t dequeueThreadId;

  /*
   * HTS - Host Traffic Statistics
   */
  PthreadMutex hostsHashMutex;
  pthread_t hostTrafficStatsThreadId;

  pthread_t scanIdleThreadId;

  /*
   * DBU - DB Update - optional
   */
  pthread_t dbUpdateThreadId;

  /*
   * AR - Address Resolution - optional
   */
#ifdef ASYNC_ADDRESS_RESOLUTION
  PthreadMutex addressResolutionMutex;
  pthread_t dequeueAddressThreadId[MAX_NUM_DEQUEUE_THREADS];
#endif

  /*
   * Purge idle host - optional
   */
  pthread_t purgeAddressThreadId;

  /*
   * Helper application lsof - optional
   */
  PthreadMutex lsofMutex;
  pthread_t lsofThreadId;

  unsigned short numDequeueThreads;

  PthreadMutex gdbmMutex;
  PthreadMutex hashResizeMutex;
  PthreadMutex graphMutex;
#ifdef MEMORY_DEBUG 
  PthreadMutex leaksMutex;
#endif

  pthread_t handleWebConnectionsThreadId;

#ifdef ASYNC_ADDRESS_RESOLUTION
  TrafficCounter droppedAddresses;
#endif
#endif /* MULTITHREADED */

  /* SSL support */
#ifdef HAVE_OPENSSL
  int sslInitialized, sslPort;
#endif

  /* Termination flags */
  short capturePackets;      /* tells to ntop if data are to be collected */
  short endNtop;             /* graceful shutdown ntop */

  /* lsof support */
  u_short updateLsof;
  ProcessInfo **processes;
  u_short numProcesses;
  ProcessInfoList *localPorts[TOP_IP_PORT];

  /* Filter Chains */
  u_short handleRules;
  FlowFilterList *flowsList;

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

  /* Monitored Protocols */
  int numActServices;                /* # of protocols being monitored (as stated by the protocol file) */
  ServiceEntry **udpSvc, **tcpSvc;   /* the pointers to the tables of TCP/UDP Protocols to monitor */

  char **protoIPTrafficInfos;

  u_short numIpProtosToMonitor, numIpPortsToHandle;
  PortMapper *ipPortMapper;
  int numIpPortMapperSlots;
  unsigned long numHandledHTTPrequests;

  /* Packet Capture */
#if defined(MULTITHREADED)
  PacketInformation packetQueue[PACKET_QUEUE_LENGTH+1];
  u_int packetQueueLen, maxPacketQueueLen, packetQueueHead, packetQueueTail;
#endif

  TransactionTime transTimeHash[NUM_TRANSACTION_ENTRIES];

  u_char dummyEthAddress[ETHERNET_ADDRESS_LEN];
  u_short *mtuSize;
  u_short *headerSize;

#ifdef MEMORY_DEBUG
  size_t allocatedMemory;
#endif

  /*
   * local variables
   */
  int enableDBsupport;   /* Database support disabled by default             */
  int enableIdleHosts;   /* Purging of idle hosts support enabled by default */
  
  char *localAddresses, *protoSpecs;
  
#ifndef WIN32
  int userId, groupId;
#endif
  
  char *webAddr, *flowSpecs, *sslAddr;  

#ifndef MICRO_NTOP
  int maxNumLines, sortSendMode;
  
  /* TCP Wrappers */
#ifdef HAVE_LIBWRAP
  int allow_severity, deny_severity;
#endif /* HAVE_LIBWRAP */
  
#endif /* MICRO_NTOP */  

  int webPort, refreshRate, localAddrFlag, actualReportDeviceId;
  short columnSort, reportKind, sortFilter;
  int sock, newSock;
#ifdef HAVE_OPENSSL
  int sock_ssl;
#endif

  int numChildren;

  /* NetFlow */
  /* Flow emission */
  int netFlowOutSocket;
  u_int32_t globalFlowSequence, globalFlowPktCount;
  NetFlow5Record theRecord;
  struct sockaddr_in netFlowDest;
  /* Flow reception */
  int netFlowInSocket, netFlowDeviceId;
  u_short netFlowInPort;
  
  /* sFlow */
  int sflowOutSocket, sflowInSocket, sflowDeviceId;
  u_short sflowInPort; 
  u_long numSamplesReceived, initialPool, lastSample;
  u_int32_t flowSampleSeqNo, numSamplesToGo;
  struct sockaddr_in sflowDest;

  /* http.c */
  FILE *accessLogFd;

  /*  ****************** */
  HostTraffic *hostsCache[MAX_HOSTS_CACHE_LEN];
  u_short      hostsCacheLen;
} NtopGlobals;

#endif /* GLOBALS_H */
