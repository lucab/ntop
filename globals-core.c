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

/* general */
#ifdef WIN32
char *version, *osName, *author, *buildDate;
#endif
char *program_name;
char domainName[MAXHOSTNAMELEN], *shortDomainName;

/* command line options */
u_short traceLevel;
char dbPath[200], accessLogPath[200], *rFileName;
u_int maxHashSize;
short usePersistentStorage, grabSessionInformation;
int numericFlag, logTimeout, daemonMode, mergeInterfaces;

/* Search paths */
const char *dataFileDirs[]   = {".", DATAFILE_DIR, NULL};
const char *pluginDirs[]     = {"./plugins", PLUGIN_DIR, NULL};
const char *configFileDirs[] = {".", CONFIGFILE_DIR, "/etc", NULL};

/* Debug */
extern size_t allocatedMemory;

/* SSL */
#ifdef HAVE_OPENSSL
int sslInitialized, sslPort;
#endif

/* Logging */
time_t nextLogTime;
FILE *logd;

/* Flags */
int isLsofPresent=1, isNepedPresent=1, isNmapPresent=1;
short capturePackets;
short endNtop;


/* Multithreading */
#ifdef MULTITHREADED
pthread_mutex_t packetQueueMutex, hostsHashMutex, graphMutex;
pthread_mutex_t lsofMutex, addressResolutionMutex, hashResizeMutex;

pthread_t dequeueThreadId, handleWebConnectionsThreadId;
pthread_t thptUpdateThreadId, scanIdleThreadId, logFileLoopThreadId;
pthread_t dbUpdateThreadId, lsofThreadId;
#ifdef HAVE_GDBM_H
pthread_mutex_t gdbmMutex;
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
pthread_mutex_t addressQueueMutex;
#endif
#endif

/* Database */
#ifdef HAVE_GDBM_H
GDBM_FILE gdbm_file, pwFile, eventFile, hostsInfoFile;
#endif

/* lsof support */
u_short updateLsof;
ProcessInfo *processes[MAX_NUM_PROCESSES];
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
u_int addressQueueHead, addressQueueTail;
struct hnamemem *addressQueue[ADDRESS_QUEUE_LENGTH+1];
#endif
#ifndef HAVE_GDBM_H
struct hnamemem* hnametable[HASHNAMESIZE];
#endif

/* Misc */
char *separator = "&nbsp;";
int32_t thisZone; /* seconds offset from gmt to local time */

/* Time */
time_t actTime, initialSniffTime, lastRefreshTime;
time_t nextSessionTimeoutScan;
struct timeval lastPktTime;

/* NICs */
int deviceId; /* Set by processPacket() */
int numDevices, actualDeviceId;
ntopInterface_t device[MAX_NUM_DEVICES];


/* Monitored Protocols */
char *protoIPTrafficInfos[MAX_NUM_HANDLED_IP_PROTOCOLS];
u_short numIpProtosToMonitor, numIpPortsToHandle;
int* ipPortMapper;


/* Packet Capture */
#if defined(MULTITHREADED)
PacketInformation packetQueue[PACKET_QUEUE_LENGTH+1];
u_int packetQueueLen, maxPacketQueueLen, packetQueueHead, packetQueueTail;
#endif

TransactionTime transTimeHash[NUM_TRANSACTION_ENTRIES];

u_int broadcastEntryIdx;
HostTraffic broadcastEntry;
u_char dummyEthAddress[ETHERNET_ADDRESS_LEN];
IpFragment *fragmentList;
IPSession *tcpSession[HASHNAMESIZE]; /* TCP sessions */
IPSession *udpSession[HASHNAMESIZE]; /* UDP sessions */
u_short numTcpSessions, numUdpSessions;
ServiceEntry *udpSvc[SERVICE_HASH_SIZE], *tcpSvc[SERVICE_HASH_SIZE];
TrafficEntry ipTrafficMatrix[256][256]; /* Subnet traffic Matrix */
HostTraffic* ipTrafficMatrixHosts[256]; /* Subnet traffic Matrix Hosts */
fd_set ipTrafficMatrixPromiscHosts;

SimpleProtoTrafficInfo *ipProtoStats;

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
