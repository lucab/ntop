/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 *		  	  Centro SERRA, University of Pisa
 *		 	  http://www.ntop.org/
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

unsigned long allocatedMemory, maxHashSize;

/* Database */
char dbPath[200];
char accessLogPath[200]; /* Apache-like access log */
short usePersistentStorage, grabSessionInformation, capturePackets, endNtop;

/* Time */
time_t actTime, initialSniffTime, lastRefreshTime;
int32_t thisZone; /* seconds offset from gmt to local time */

/* NICs */
int numDevices, mergeInterfaces, actualDeviceId;

ntopInterface_t device[MAX_NUM_DEVICES];


/* Throughput */

/* Traffic Statistics */
SimpleProtoTrafficInfo *ipProtoStats;

/* Periodic Updates */
u_short updateLsof;


/* Monitored Protocols */
char *protoIPTrafficInfos[MAX_NUM_HANDLED_IP_PROTOCOLS]; /* array 0-numIpProtosToMonitor */
u_short numIpProtosToMonitor=0, numIpPortsToHandle=0;
int* ipPortMapper;


/* Rules */
u_short handleRules=0;
char* rFileName;
FilterRuleChain *tcpChain, *udpChain, *icmpChain;
u_short ruleSerialIdentifier;
FilterRule* filterRulesList[MAX_NUM_RULES];

/* Threads */
#ifdef MULTITHREADED
pthread_mutex_t packetQueueMutex, hostsHashMutex, graphMutex;
pthread_mutex_t lsofMutex, addressResolutionMutex, hashResizeMutex;
pthread_t dequeueThreadId, handleWebConnectionsThreadId,
  thptUpdateThreadId,
  scanIdleThreadId, dbUpdateThreadId;
pthread_t lsofThreadId;

#ifdef USE_SEMAPHORES
sem_t queueSem;
#ifdef ASYNC_ADDRESS_RESOLUTION
sem_t queueAddressSem;
#endif
#else
ConditionalVariable queueCondvar;
#ifdef ASYNC_ADDRESS_RESOLUTION
ConditionalVariable queueAddressCondvar;
#endif
#endif
#ifdef ASYNC_ADDRESS_RESOLUTION
pthread_t dequeueAddressThreadId;
TrafficCounter droppedAddresses;
pthread_mutex_t addressQueueMutex;
#endif
#endif

#ifdef HAVE_OPENSSL
int sslInitialized, sslPort;
#endif

/* Libwrap */
#ifdef HAVE_LIBWRAP
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
#endif /* HAVE_LIBWRAP */


/* GDBM */
#ifdef HAVE_GDBM_H
GDBM_FILE gdbm_file, pwFile, eventFile;
#ifdef MULTITHREADED
pthread_mutex_t gdbmMutex;
#endif
#endif

/* Addressing */
#if defined(ASYNC_ADDRESS_RESOLUTION)
unsigned int addressQueueLen, maxAddressQueueLen, addressQueueHead, addressQueueTail;
struct hnamemem *addressQueue[ADDRESS_QUEUE_LENGTH+1];
#endif
char domainName[MAXHOSTNAMELEN], *shortDomainName;


/* Global application parameters */
int numericFlag, daemonMode;
char *program_name;

/* Logging */
int logTimeout;
time_t nextLogTime=0;
FILE *logd;

/* Flows */
FlowFilterList *flowsList;

/* External Applications */
int isLsofPresent=1, isNepedPresent=1, isNmapPresent=1;


/* Packet queue (multithread mode) */
#ifdef MULTITHREADED
PacketInformation packetQueue[PACKET_QUEUE_LENGTH+1];
unsigned int packetQueueLen, maxPacketQueueLen, packetQueueHead, packetQueueTail;
#endif

TransactionTime transTimeHash[NUM_TRANSACTION_ENTRIES];

#ifndef HAVE_GDBM_H
struct hnamemem* hnametable[HASHNAMESIZE];
#endif
IpFragment *fragmentList;
IPSession *tcpSession[HASHNAMESIZE]; /* TCP sessions */
IPSession *udpSession[HASHNAMESIZE]; /* UDP sessions */
u_short numTcpSessions=0, numUdpSessions=0;
char *separator;
ServiceEntry *udpSvc[SERVICE_HASH_SIZE], *tcpSvc[SERVICE_HASH_SIZE];
TrafficEntry ipTrafficMatrix[256][256]; /* Subnet traffic Matrix */
HostTraffic* ipTrafficMatrixHosts[256]; /* Subnet traffic Matrix Hosts */
fd_set ipTrafficMatrixPromiscHosts;


u_char dummyEthAddress[ETHERNET_ADDRESS_LEN];
short sortSendMode=0;
int lastNumLines, lastNumCols;
time_t nextSessionTimeoutScan;
struct timeval lastPktTime;
u_int broadcastEntryIdx;
unsigned short alternateColor = 0, maxNameLen;
int deviceId; /* Set by processPacket() */

#ifdef WIN32
char* version;
char* osName;
char* author;
#endif

char *dirs[] = { 
  dbPath,                /* Courtesy of Ralf Amandi <ralf.amandi@accordata.net> */
#ifdef WIN32
  ".",                   /* Local   */
#else
  "/usr/local/bin",      /* Default (when compiled from sources) */
  "/etc/ntop",           /* Default (a suggestion for packagers) */
  "/opt/ntop/etc/ntop",  /* Solaris */
  "/usr/local/etc/ntop", /* BSD     */
  "/usr/lib/ntop",       /* Suse    */
  "/usr/share/ntop",     /* Suse    */
  "/usr/local/share",   
  ".",                   /* Local   */
#endif
  NULL };


ProcessInfo *processes[MAX_NUM_PROCESSES];
u_short numProcesses;
ProcessInfoList *localPorts[TOP_IP_PORT];


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
  4352,	        /* FDDI */
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

u_short traceLevel;
