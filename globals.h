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

#define NTOP_DEFAULT_ACCESS_LOG_PATH      NULL      /* -a */
#define NTOP_DEFAULT_DB_SUPPORT           0         /* -b */
                                                        /* access log disabled by default */
#define NTOP_DEFAULT_STICKY_HOSTS         0         /* -c */
#define NTOP_DEFAULT_DAEMON_MODE          0         /* -d */

#define NTOP_DEFAULT_TRAFFICDUMP_FILENAME NULL      /* -f */

#define NTOP_DEFAULT_DEVICES              NULL      /* -i */
#define NTOP_DEFAULT_BORDER_SNIFFER_MODE  0         /* -j */
#define NTOP_DEFAULT_FILTER_IN_FRAME      0         /* -k */
#define NTOP_DEFAULT_PCAP_LOG_FILENAME    NULL      /* -l */
#define NTOP_DEFAULT_LOCAL_SUBNETS        NULL      /* -m */
#define NTOP_DEFAULT_NUMERIC_IP_ADDRESSES 0         /* -n */
#define NTOP_DEFAULT_SUSPICIOUS_PKT_DUMP  0         /* -q */
#define NTOP_DEFAULT_DISABLE_PROMISCUOUS  0         /* -s */

#define NTOP_DEFAULT_WEB_ADDR             NULL      /* -w */ /* e.g. all interfaces & addresses */
#define NTOP_DEFAULT_WEB_PORT             3000

#define NTOP_DEFAULT_FILTER_EXPRESSION    NULL      /* -B */

#define NTOP_DEFAULT_DOMAIN_NAME          ""        /* -D */
                                   /* Note: don't use null, as this isn't a char*, its a char[] */
#define NTOP_DEFAULT_EXTERNAL_TOOLS_ENABLE 0        /* -E */
#define NTOP_DEFAULT_FLOW_SPECS           NULL      /* -F */

#define NTOP_DEFAULT_DEBUG_MODE           0         /* -K */

#define NTOP_DEFAULT_DEBUG                0              /* that means debug disabled */
#define NTOP_SYSLOG_NONE                  -1
#define NTOP_DEFAULT_SYSLOG       NTOP_SYSLOG_NONE /* -L */
#define NTOP_DEFAULT_MERGE_INTERFACES     1        /* -M */
#define NTOP_DEFAULT_NMAP_PRESENT         0        /* -N */

/* -O and -P are special, see globals-core.h */

#define NTOP_DEFAULT_PERSISTENT_STORAGE   0        /* -S */

#define NTOP_DEFAULT_MAPPER_URL           NULL     /* -U */

#define NTOP_DEFAULT_SSL_ADDR             NULL     /* -W */ /* e.g. all interfaces & addresses */
#define NTOP_DEFAULT_SSL_PORT             0                 /* e.g. inactive */

#define NTOP_DEFAULT_CHART_TYPE           GDC_AREA /* --throughput-chart-type */

#define NOW ((time_t) time ((time_t *) 0))

#define MAX_NUM_BAD_IP_ADDRESSES         3
#define NTOP_DEFAULT_BAD_ACCESS_TIMEOUT  5*60  /* 5 minutes */

#define NTOP_DEFAULT_DONT_TRUST_MAC_ADDR 0

/*
 * Other sizes and limits...
 */
#define URL_MAX_LEN                      512 /* used in http.c */

#define MAX_DEVICE_NAME_LEN               64 /* used in util.c */


/*
 * TCP Wrappers
 */
#ifdef HAVE_LIBWRAP

#ifdef USE_SYSLOG

#define NTOP_DEFAULT_TCPWRAP_ALLOW   LOG_AUTHPRIV|LOG_INFO
#define NTOP_DEFAULT_TCPWRAP_DENY    LOG_AUTHPRIV|LOG_WARNING

#else /* USE_SYSLOG */

#define NTOP_DEFAULT_TCPWRAP_ALLOW   0
#define NTOP_DEFAULT_TCPWRAP_DENY    0

#endif /* USE_SYSLOG */

#endif /* HAVE_LIBWRAP */

/*
 * External URLs...
 */
#define LSOF_URL        "http://freshmeat.net/projects/lsof/"
#define LSOF_URL_ALT    "lsof home page at freshmeat.net"
#define NMAP_URL        "http://www.insecure.org/nmap"
#define NMAP_URL_ALT    "nmap home page at insecure.org"
#define GDCHART_URL     "http://www.fred.net/brv/chart/"
#define GDCHART_URL_ALT "GDChart home page"
#define OPENSSL_URL     "http://www.openssl.org/"
#define OPENSSL_URL_ALT "OpenSSL home page"

/*
 * Controlling switches...
 */
#undef  USE_COLOR      /* Define to enable alternating row colors on many tables */
#define USE_CGI        /* Define to allow processing of CGI scripts */

/*
  On FreeBSD gethostbyaddr() sometimes loops
  and uses all the available memory. Hence this
  patch is needed.
 */
#if defined(__FreeBSD__)
#define USE_HOST
#endif

/*
  On some Linux versions gethostbyaddr() is bugged and
  it tends to exaust all available file descriptors. If
  you want to check this try "lsof -i |grep ntop". If this
  is the case please do  '#define USE_HOST' (see below)
  in order to overcome this flaw.

*/
/* #define USE_HOST */

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
  char *sqlHostName;                 /* 'b' */
  int  sqlPortNumber;
  u_char stickyHosts;                /* 'c' */
  int daemonMode;                    /* 'd' */
#ifndef MICRO_NTOP
  int maxNumLines;                   /* 'e' */
#endif
  char *rFileName;                   /* 'f' */
  char *devices;                     /* 'i' */
  short borderSnifferMode;           /* 'j' */
  short dontTrustMACaddr;            /* internal */
  int filterExpressionInExtraFrame;  /* 'k' */
  char *pcapLog;                     /* 'l' */
  int numericFlag;                   /* 'n' */
  u_char enableSuspiciousPacketDump; /* 'q' */
  int refreshRate;                   /* 'r' */
  u_char disablePromiscuousMode;     /* 's' */
  u_short traceLevel;                /* 't' */
  char *mySQLhostName;               /* 'v' */
  char *mySQLuser;
   /* password is NOT stored in globals */
  char *mySQLdatabase;

  char *webAddr;                     /* 'w' */
  int webPort;


  char *currentFilterExpression;     /* 'B' */
  char domainName[MAXHOSTNAMELEN];   /* 'D' */
  int isLsofPresent;                 /* 'E' */
  u_char enableExternalTools;        /* 'E' */

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

#ifdef HAVE_OPENSSL
  char *sslAddr;                     /* 'W' */
  int sslPort;
#endif

#ifdef HAVE_GDCHART
  int throughput_chart_type;         /* '129' */
#endif

#ifndef YES_IGNORE_SIGPIPE
  int ignoreSIGPIPE;                 /* '132' */
#endif

#ifdef PARM_SSLWATCHDOG
  int useSSLwatchdog;                /* '133' */
#endif

  /* Other flags (these could set via command line options one day) */
  u_char enableSessionHandling;
  u_char enablePacketDecoding;
  u_char enableFragmentHandling;
  u_char trackOnlyLocalHosts;

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
#if defined(MAX_NUM_BAD_IP_ADDRESSES) && (MAX_NUM_BAD_IP_ADDRESSES > 0)
  BadGuysAddr weDontWantToTalkWithYou[MAX_NUM_BAD_IP_ADDRESSES];
#endif

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
  u_char hostsHashMutexInitialized;

  /*
   * SIH - Scan Idle Hosts - optional
   */
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
  int sslInitialized;

  SSL_CTX* ctx;
  SSL_connection ssl[MAX_SSL_CONNECTIONS];

#if defined(USE_SSLWATCHDOG) || defined(PARM_SSLWATCHDOG)
  /* sslwatchdog stuff... */
  ConditionalVariable sslwatchdogCondvar;
  pthread_t sslwatchdogChildThreadId;
#endif /* USE_SSLWATCHDOG || PARM_SSLWATCHDOG */

#endif /* HAVE_OPENSSL */

  /* Termination flags */
  short capturePackets;      /* tells to ntop if data are to be collected */
  short endNtop;             /* graceful shutdown ntop */

  /* lsof support */
  u_short updateLsof;
  ProcessInfo **processes;
  u_short numProcesses;
  ProcessInfoList *localPorts[TOP_IP_PORT];

  /* Filter Chains */
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
  volatile unsigned long numHandledSIGPIPEerrors;
  unsigned long numHandledHTTPrequests;
#if defined(USE_SSLWATCHDOG) || defined(PARM_SSLWATCHDOG)
  unsigned long numHTTPSrequestTimeouts;
#endif /* USE_SSL_WATCHDOG || PARM_SSLWATCHDOG */

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
  char * effectiveUserName;
#endif
  
  char *flowSpecs;  

#ifndef MICRO_NTOP
  int sortSendMode;
  
#endif /* MICRO_NTOP */  

  int actualReportDeviceId;
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

  /* Memory cache */
  HostTraffic *hostsCache[MAX_HOSTS_CACHE_LEN];
  u_short      hostsCacheLen;

  IPSession   *sessionsCache[MAX_SESSIONS_CACHE_LEN];
  u_short      sessionsCacheLen;


} NtopGlobals;


  /*
   *  ** TCP Wrappers
   *
   *      Because of limits in the way libwrap.a does things, these MUST
   *      be open global values.
   *
   */
#ifdef HAVE_LIBWRAP
  int allow_severity, deny_severity;
#endif /* HAVE_LIBWRAP */

#endif /* GLOBALS_H */
