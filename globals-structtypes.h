/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 1998-2007 Luca Deri <deri@ntop.org>
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

/* *******************************

Some nice links:

http://www.sockets.com/protocol.htm
http://www.iana.org/assignments/protocol-numbers

Courtesy of Helmut Schneider <jumper99@gmx.de>

******************************* */

/*
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  This file, included from ntop.h, contains the structure and typedef definitions.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * fallbacks for essential typedefs
 */
#ifdef WIN32
#ifndef __GNUC__
typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   u_int;
typedef unsigned long  u_long;
#endif
#if !defined(HAVE_UINT8_T)
typedef u_char  uint8_t;
#endif
#if !defined(HAVE_UINT16_T)
typedef u_short uint16_t;
#endif
#if !defined(HAVE_UINT32_T)
typedef u_int   uint32_t;
#endif
#endif /* WIN32 */

#if !defined(HAVE_U_INT64_T)
#if defined(WIN32)
/* typedef _int64 u_int64_t; */
#else
#if defined(HAVE_UINT64_T)
#define u_int64_t uint64_t
#else
#error "Sorry, I'm unable to define u_int64_t on your platform"
#endif
#endif
#endif

#if !defined(HAVE_U_INT32_T)
typedef unsigned int u_int32_t;
#endif

#if !defined(HAVE_U_INT16_T)
typedef unsigned short u_int16_t;
#endif

#if !defined(HAVE_U_INT8_T)
typedef unsigned char u_int8_t;
#endif

#if !defined(HAVE_INT32_T)
typedef int int32_t;
#endif

#if !defined(HAVE_INT16_T)
typedef short int16_t;
#endif

#if !defined(HAVE_INT8_T)
typedef char int8_t;
#endif

typedef unsigned char bool;

#include "fcUtils.h"
#include "scsiUtils.h"

typedef struct ether80211q {
  u_int16_t vlanId;
  u_int16_t protoType;
} Ether80211q;

typedef struct _mac_t {
    u_int8_t mact_octet[6];
} mac_t;

typedef struct fcAddr {
    u_int8_t domain;
    u_int8_t area;
    u_int8_t port;
} FcAddress;

typedef struct _fcSerial {
    FcAddress fcAddress;
    u_short vsanId;
} FcSerial;

typedef union wwn_ {
  u_int8_t str[8];
#ifdef CFG_LITTLE_ENDIAN
  struct {
    unsigned naa            :4;
    unsigned reserved       :12;
    mac_t    mac;
  } wwn_format1;

  struct {
    unsigned naa            :4;
    unsigned vendor_specific:12;
    mac_t    mac;
  } wwn_format2;

  struct {
    unsigned naa:4;
    u_int64_t   vendor_specific:60;
  } wwn_format3;

  struct {
    unsigned  naa           :4;
    unsigned  reserved      :28;
    u_int32_t ip_addr;
  } wwn_format4;

  struct {
    unsigned naa            :4;
    unsigned ieee_company_id:24;
    u_int64_t   vsid        :36; /* vendor specific ID */
  } wwn_format5;
#else
  struct {
    mac_t    mac;
    unsigned reserved       :12;
    unsigned naa            :4;
  } wwn_format1;

  struct {
    mac_t    mac;
    unsigned vendor_specific:12;
    unsigned naa            :4;
  } wwn_format2;

  struct {
    u_int64_t   vendor_specific:60;
    unsigned naa:4;
  } wwn_format3;

  struct {
    u_int32_t ip_addr;
    unsigned  reserved      :28;
    unsigned  naa           :4;
  } wwn_format4;

  struct {
    u_int64_t   vsid        :36;
    unsigned ieee_company_id:24;
    unsigned naa            :4;
  } wwn_format5;
#endif
  u_int64_t num;
} wwn_t;

typedef struct hostAddr {
  u_int    hostFamily; /* AF_INET AF_INET6 */
  union {
    struct in_addr  _hostIp4Address;
#ifdef INET6
    struct in6_addr _hostIp6Address;
#endif
  } addr;
} HostAddr;

#define Ip4Address addr._hostIp4Address

#ifdef INET6
#define Ip6Address addr._hostIp6Address
#define SIZEOF_HOSTSERIAL   8
#endif

#define SERIAL_NONE         0
#define SERIAL_MAC          1
#define SERIAL_IPV4         2
#define SERIAL_IPV6         3
#define SERIAL_FC           4

typedef struct _ethSerial {
  u_char  ethAddress[LEN_ETHERNET_ADDRESS];
  u_int16_t vlanId;
} EthSerial;

typedef struct _ipSerial {
  HostAddr ipAddress;
  u_int16_t  vlanId;
} IpSerial;

typedef struct hostSerial {
  u_char serialType;     /* 0 == empty */
  union {
    EthSerial ethSerial; /* hostSerial == SERIAL_MAC */
    IpSerial  ipSerial;  /* hostSerial == SERIAL_IPV4/SERIAL_IPV6 */
    FcSerial  fcSerial;
  } value;
} HostSerial;

#ifdef WIN32
#define pid_t unsigned int
#ifndef RETSIGTYPE
#define RETSIGTYPE void
#endif
#endif

#ifdef MAKE_WITH_SYSLOG
/* Now, if we don't have gcc, we haven't created the facilitynames table, so do it
 * manually
 */
typedef struct my_code {
  char    *c_name;
  int     c_val;
} MYCODE;
#endif

#ifdef HAVE_OPENSSL
typedef struct ssl_connection {
  SSL* ctx;
  int  socketId;
} SSL_connection;
#endif /* HAVE_OPENSSL */

#ifdef MAKE_NTOP_PACKETSZ_DECLARATIONS /* Missing declarations */
typedef struct {
  unsigned	id :16;		/* query identification number */
  /* fields in third byte */
  unsigned	rd :1;		/* recursion desired */
  unsigned	tc :1;		/* truncated message */
  unsigned	aa :1;		/* authoritive answer */
  unsigned	opcode :4;	/* purpose of message */
  unsigned	qr :1;		/* response flag */
  /* fields in fourth byte */
  unsigned	rcode :4;	/* response code */
  unsigned	unused :3;	/* unused bits (MBZ as of 4.9.3a3) */
  unsigned	ra :1;		/* recursion available */
  /* remaining bytes */
  unsigned	qdcount :16;	/* number of question entries */
  unsigned	ancount :16;	/* number of answer entries */
  unsigned	nscount :16;	/* number of authority entries */
  unsigned	arcount :16;	/* number of resource entries */
} HEADER;
#endif /* MAKE_NTOP_PACKETSZ_DECLARATIONS */

typedef struct portProtoMapper {
  u_int portProto;       /* Port/proto to map */
  u_int mappedPortProto; /* Mapped port/proto */
  u_char dummyEntry;     /* Set to 1 if this entry is dummy */
} PortProtoMapper;

typedef struct portProtoMapperHandler {
  u_short numElements; /* numIpPortsToHandle */
  int numSlots;/* numIpPortMapperSlots */
  PortProtoMapper *theMapper;
} PortProtoMapperHandler;

typedef struct protocolsList {
  char *protocolName;
  u_int16_t protocolId, protocolIdAlias; /* I know it's ugly however this
					    should be enough for most of
					    the situations
					 */
  struct protocolsList *next;
} ProtocolsList;

#ifndef WIN32

typedef struct conditionalVariable {
  pthread_mutex_t mutex;
  pthread_cond_t  condvar;
  int predicate;
} ConditionalVariable;

#else

#define pthread_t              HANDLE
#define pthread_mutex_t        HANDLE
#define pthread_cond_t         HANDLE

typedef struct conditionalVariable {
  HANDLE condVar;
  CRITICAL_SECTION criticalSection;
} ConditionalVariable;

extern int  pthread_create(pthread_t *threadId, void* notUsed, void *(*__start_routine) (void *), char* userParm);
extern void pthread_detach(pthread_t *threadId);
extern int  pthread_mutex_init(pthread_mutex_t *mutex, char* notused);
extern void pthread_mutex_destroy(pthread_mutex_t *mutex);
extern int  pthread_mutex_lock(pthread_mutex_t *mutex);
extern int  pthread_mutex_trylock(pthread_mutex_t *mutex);
extern int  pthread_mutex_unlock(pthread_mutex_t *mutex);


#endif /* WIN32 */

typedef struct holder {
  struct timeval time;
  pid_t  pid;
  pthread_t thread;
  int    line;
  char   file[5];
} Holder;

typedef struct pthreadMutex {
  pthread_mutex_t mutex, statedatamutex;
  char   isLocked, isInitialized;
  u_int  numLocks, numReleases;
  Holder attempt,
         lock,
         unlock,
         max;
  float  maxLockedDuration;
} PthreadMutex;

typedef struct packetInformation {
  unsigned short deviceId;
  struct pcap_pkthdr h;
  u_char p[MAX_PACKET_LEN];
} PacketInformation;

typedef struct hash_list {
  u_int16_t idx;          /* Index of this entry in hostTraffic */
  struct hash_list *next;
} HashList;

#ifdef WIN32
typedef __int64 Counter;
#else
typedef unsigned long long Counter;
#endif

typedef struct trafficCounter {
  Counter value;
  u_char modified;
} TrafficCounter;

/* ************* Types Definition ********************* */

typedef struct thptEntry {
  float trafficValue;
  /* ****** */
  HostSerial topHostSentSerial, secondHostSentSerial, thirdHostSentSerial;
  TrafficCounter topSentTraffic, secondSentTraffic, thirdSentTraffic;
  /* ****** */
  HostSerial topHostRcvdSerial, secondHostRcvdSerial, thirdHostRcvdSerial;
  TrafficCounter topRcvdTraffic, secondRcvdTraffic, thirdRcvdTraffic;
} ThptEntry;

/* *********************** */

typedef struct packetStats {
  TrafficCounter upTo64, upTo128, upTo256;
  TrafficCounter upTo512, upTo1024, upTo1518;
#ifdef MAKE_WITH_JUMBO_FRAMES
  TrafficCounter upTo2500, upTo6500, upTo9000, above9000;
#else
  TrafficCounter above1518;
#endif
  TrafficCounter shortest, longest;
  TrafficCounter badChecksum, tooLong;
} PacketStats;

typedef struct fcPacketStats {
  TrafficCounter upTo36, upTo48, upTo52, upTo68, upTo104;
  TrafficCounter upTo548, upTo1060, upTo2136, above2136;
  TrafficCounter shortest, longest;
  TrafficCounter badCRC, tooLong;
} FcPacketStats;

/* *********************** */

typedef struct ttlStats {
  TrafficCounter upTo32, upTo64, upTo96;
  TrafficCounter upTo128, upTo160, upTo192, upTo224, upTo255;
} TTLstats;

/* *********************** */

typedef struct simpleProtoTrafficInfo {
  TrafficCounter local, local2remote, remote, remote2local;
  TrafficCounter totalFlows;
} SimpleProtoTrafficInfo;

/* *********************** */

typedef struct usageCounter {
  TrafficCounter value;
  HostSerial peersSerials[MAX_NUM_CONTACTED_PEERS]; /* host serial */
} UsageCounter;

/* *********************** */

typedef struct routingCounter {
  TrafficCounter routedPkts, routedBytes;
} RoutingCounter;

/* *********************** */

/* NOTE: anything added here must be also added in the SecurityDeviceProbes structure */
typedef struct securityHostProbes {
  UsageCounter synPktsSent, rstPktsSent, rstAckPktsSent,
    synFinPktsSent, finPushUrgPktsSent, nullPktsSent;
  UsageCounter synPktsRcvd, rstPktsRcvd, rstAckPktsRcvd,
    synFinPktsRcvd, finPushUrgPktsRcvd, nullPktsRcvd;
  UsageCounter ackXmasFinSynNullScanSent, ackXmasFinSynNullScanRcvd;
  UsageCounter rejectedTCPConnSent, rejectedTCPConnRcvd;
  UsageCounter establishedTCPConnSent, establishedTCPConnRcvd;
  UsageCounter terminatedTCPConnServer, terminatedTCPConnClient;
  /* ********* */
  UsageCounter udpToClosedPortSent, udpToClosedPortRcvd;

  UsageCounter udpToDiagnosticPortSent, udpToDiagnosticPortRcvd,
    tcpToDiagnosticPortSent, tcpToDiagnosticPortRcvd;
  UsageCounter tinyFragmentSent,        tinyFragmentRcvd;
  UsageCounter icmpFragmentSent,        icmpFragmentRcvd;
  UsageCounter overlappingFragmentSent, overlappingFragmentRcvd;
  UsageCounter closedEmptyTCPConnSent,  closedEmptyTCPConnRcvd;
  UsageCounter icmpPortUnreachSent,     icmpPortUnreachRcvd;
  UsageCounter icmpHostNetUnreachSent,  icmpHostNetUnreachRcvd;
  UsageCounter icmpProtocolUnreachSent, icmpProtocolUnreachRcvd;
  UsageCounter icmpAdminProhibitedSent, icmpAdminProhibitedRcvd;
  UsageCounter malformedPktsSent,       malformedPktsRcvd;
} SecurityHostProbes;

/* NOTE: anything added here must be also added in the SecurityHostProbes structure */
typedef struct securityDeviceProbes {
  TrafficCounter synPkts, rstPkts, rstAckPkts,
    synFinPkts, finPushUrgPkts, nullPkts;
  TrafficCounter rejectedTCPConn;
  TrafficCounter establishedTCPConn;
  TrafficCounter terminatedTCPConn;
  TrafficCounter ackXmasFinSynNullScan;
  /* ********* */
  TrafficCounter udpToClosedPort;
  TrafficCounter udpToDiagnosticPort, tcpToDiagnosticPort;
  TrafficCounter tinyFragment;
  TrafficCounter icmpFragment;
  TrafficCounter overlappingFragment;
  TrafficCounter closedEmptyTCPConn;
  TrafficCounter malformedPkts;
  TrafficCounter icmpPortUnreach;
  TrafficCounter icmpHostNetUnreach;
  TrafficCounter icmpProtocolUnreach;
  TrafficCounter icmpAdminProhibited;
} SecurityDeviceProbes;

typedef struct sapType {
  u_char dsap, ssap;
} SapType;

typedef struct unknownProto {
  u_char protoType; /* 0=notUsed, 1=Ethernet, 2=SAP, 3=IP */
  union {
    u_int16_t ethType;
    SapType   sapType;
    u_int16_t ipType;
  } proto;
} UnknownProto;

typedef struct nonIPTraffic {
  /* NetBIOS */
  char             nbNodeType, *nbHostName, *nbAccountName, *nbDomainName, *nbDescr;

  /* AppleTalk*/
  u_short          atNetwork;
  u_char           atNode;
  char             *atNodeName, *atNodeType[MAX_NODE_TYPES];

  /* IPX */
  char             *ipxHostName;
  u_short          numIpxNodeTypes, ipxNodeType[MAX_NODE_TYPES];

  /* Non IP */
  TrafficCounter   stpSent, stpRcvd; /* Spanning Tree */
  TrafficCounter   ipxSent, ipxRcvd;
  TrafficCounter   osiSent, osiRcvd;
  TrafficCounter   dlcSent, dlcRcvd;
  TrafficCounter   arp_rarpSent, arp_rarpRcvd;
  TrafficCounter   arpReqPktsSent, arpReplyPktsSent, arpReplyPktsRcvd;
  TrafficCounter   decnetSent, decnetRcvd;
  TrafficCounter   appletalkSent, appletalkRcvd;
  TrafficCounter   netbiosSent, netbiosRcvd;
  TrafficCounter   otherSent, otherRcvd; /* Other traffic we cannot classify */
  UnknownProto     *unknownProtoSent, *unknownProtoRcvd; /* List of MAX_NUM_UNKNOWN_PROTOS elements */
} NonIPTraffic;

typedef struct trafficDistribution {
  TrafficCounter lastCounterBytesSent, last24HoursBytesSent[25], lastDayBytesSent;
  TrafficCounter lastCounterBytesRcvd, last24HoursBytesRcvd[25], lastDayBytesRcvd;
} TrafficDistribution;

typedef struct portUsage {
  u_short        port, clientUses, serverUses;
  HostSerial     clientUsesLastPeer, serverUsesLastPeer;
  TrafficCounter clientTraffic, serverTraffic;
  struct portUsage *next;
} PortUsage;

typedef struct virtualHostList {
  char *virtualHostName;
  TrafficCounter bytesSent, bytesRcvd; /* ... by the virtual host */
  struct virtualHostList *next;
} VirtualHostList;

typedef struct userList {
  char *userName;
  fd_set userFlags;
  struct userList *next;
} UserList;

typedef struct fileList {
  char *fileName;
  fd_set fileFlags;
  struct fileList *next;
} FileList;

typedef struct storedAddress {
  char   symAddress[MAX_LEN_SYM_HOST_NAME];
  time_t recordCreationTime;
  short  symAddressType;
  char   pad; /* Quiet valgrind */
} StoredAddress;

typedef struct macInfo {
  u_char isSpecial;
  char   vendorName[MAX_LEN_VENDOR_NAME];
} MACInfo;

typedef struct serviceStats {
  TrafficCounter numLocalReqSent, numRemReqSent;
  TrafficCounter numPositiveReplSent, numNegativeReplSent;
  TrafficCounter numLocalReqRcvd, numRemReqRcvd;
  TrafficCounter numPositiveReplRcvd, numNegativeReplRcvd;
  time_t fastestMicrosecLocalReqMade, slowestMicrosecLocalReqMade;
  time_t fastestMicrosecLocalReqServed, slowestMicrosecLocalReqServed;
  time_t fastestMicrosecRemReqMade, slowestMicrosecRemReqMade;
  time_t fastestMicrosecRemReqServed, slowestMicrosecRemReqServed;
} ServiceStats;


typedef struct dhcpStats {
  struct in_addr dhcpServerIpAddress;  /* DHCP server that assigned the address */
  struct in_addr previousIpAddress;    /* Previous IP address is any */
  time_t assignTime;                   /* when the address was assigned */
  time_t renewalTime;                  /* when the address has to be renewed */
  time_t leaseTime;                    /* when the address lease will expire */
  TrafficCounter dhcpMsgSent[MAX_NUM_DHCP_MSG + 1], dhcpMsgRcvd[MAX_NUM_DHCP_MSG + 1];
} DHCPStats;

/* *********************** */

#ifndef ICMP6_MAXTYPE
#define ICMP6_MAXTYPE 142
#endif

typedef struct icmpHostInfo {
  TrafficCounter icmpMsgSent[ICMP6_MAXTYPE+1];
  TrafficCounter icmpMsgRcvd[ICMP6_MAXTYPE+1];
  time_t        lastUpdated;
} IcmpHostInfo;

typedef struct protocolInfo {
  /* HTTP */
  VirtualHostList *httpVirtualHosts;
  /* POP3/SMTP... */
  UserList *userList;
  /* P2P */
  FileList *fileList;
  ServiceStats     *dnsStats, *httpStats;
  DHCPStats        *dhcpStats;
} ProtocolInfo;

typedef struct shortProtoTrafficInfo {
  TrafficCounter sent, rcvd;
} ShortProtoTrafficInfo;

typedef struct protoTrafficInfo {
  TrafficCounter sentLoc, sentRem;
  TrafficCounter rcvdLoc, rcvdFromRem;
  TrafficCounter totalFlows;
} ProtoTrafficInfo;

#define MAX_NUM_NON_IP_PROTO_TRAFFIC_INFO   8

typedef struct nonIpProtoTrafficInfo {
  u_int16_t protocolId;
  TrafficCounter sentBytes, rcvdBytes;
  TrafficCounter sentPkts, rcvdPkts;
  struct nonIpProtoTrafficInfo *next;
} NonIpProtoTrafficInfo;

/* ************************************* */
/*         SCSI-specific structures      */
/* ************************************* */


typedef struct scsiLunTrafficInfo {
    struct timeval firstSeen;         /* time when the session has been initiated   */
    struct timeval lastSeen;          /* time when the session has been closed      */
    u_long pktSent, pktRcvd;
    TrafficCounter bytesSent, bytesRcvd; /* This includes FC header + FCP + SCSI */
    TrafficCounter numScsiRdCmd, numScsiWrCmd, numScsiOtCmd;
    /* The following 3 counters are only FCP_DATA payload bytes */
    TrafficCounter scsiRdBytes, scsiWrBytes, scsiOtBytes;
    u_int32_t maxXferRdySize, minXferRdySize;
    u_int32_t maxRdSize, minRdSize, maxWrSize, minWrSize;
    u_int32_t numFailedCmds;
    u_int32_t chkCondCnt, busyCnt, resvConflictCnt;
    u_int32_t taskSetFullCnt, taskAbrtCnt, otherStatusCnt;
    u_int32_t abrtTaskSetCnt, clearTaskSetCnt, tgtRstCnt, lunRstCnt, clearAcaCnt;
    time_t lastTgtRstTime, lastLunRstTime;
    u_int16_t lastOxid;         /* used to track data with LUN if host issues
                                 * commands to multiple LUNs simultaneously */
    u_char lastScsiCmd, invalidLun;
    u_char frstRdDataRcvd, frstWrDataRcvd;
    u_int32_t cmdsFromLastIops;
    struct timeval reqTime, lastIopsTime;
    struct timeval minXfrRdyRTT, maxXfrRdyRTT;
    struct timeval minWrFrstDataRTT, maxWrFrstDataRTT;
    struct timeval minRdFrstDataRTT, maxRdFrstDataRTT;
    struct timeval minRTT, maxRTT;
    float minIops, maxIops, aveIops;
} ScsiLunTrafficInfo;

/* This is used to sort the LUN entries */
typedef struct lunStatsSortEntry {
    u_short lun;
    ScsiLunTrafficInfo *stats;
} LunStatsSortedEntry;

/* ************************************* */
/*         FC-specific structures        */
/* ************************************* */

typedef struct fcDomainStats {
    TrafficCounter sentBytes, rcvdBytes;
    TrafficCounter scsiReadSentBytes, scsiReadRcvdBytes;
    TrafficCounter scsiWriteSentBytes, scsiWriteRcvdBytes;
    TrafficCounter scsiOtherSentBytes, scsiOtherRcvdBytes;
} FcDomainStats;

typedef struct fcDomainList {
    /* This is basically the structure of Domain ID list in EFP */
    /* It maybe inefficient, but it is simple to maintain */
    u_char recordType;          /* This is always 1 */
    u_char domainId;
    u_char pad[6];
    wwn_t  switchWWN;
} FcDomainList;

typedef struct sortedFcDomainStatsEntry {
    u_char domainId;
    FcDomainStats *stats;
} SortedFcDomainStatsEntry;

typedef struct fcFabricElementHash {
    u_int16_t vsanId;
    TrafficCounter totBytes, totPkts;
    TrafficCounter dmBytes, dmPkts;
    TrafficCounter fspfBytes, fspfPkts, hloPkts;
    TrafficCounter lsuBytes, lsuPkts, lsaBytes, lsaPkts;
    TrafficCounter zsBytes, zsPkts;
    TrafficCounter nsBytes, nsPkts;
    TrafficCounter rscnBytes, rscnPkts;
    TrafficCounter fcsBytes, fcsPkts;
    TrafficCounter otherCtlBytes, otherCtlPkts;
    TrafficCounter fcFcpBytes, fcFiconBytes, fcElsBytes;
    TrafficCounter fcDnsBytes, fcIpfcBytes, fcSwilsBytes, otherFcBytes;
    double maxTimeZoneConf, minTimeZoneConf;
    time_t zoneConfStartTime;
    u_int32_t numBF, numRCF, numZoneConf;
    time_t fabricConfStartTime; /* for computing fabric conf time */
    double maxTimeFabricConf, minTimeFabricConf;
    double aveTimeFabricConf;
    FcDomainStats domainStats[MAX_FC_DOMAINS];
    wwn_t principalSwitch;
    u_short domainListLen;
    FcDomainList  *domainList;
    struct fcFabricElementHash *next;
} FcFabricElementHash;

typedef struct fcNameServerCache {
    u_int16_t hashIdx;
    u_int16_t vsanId;
    FcAddress    fcAddress;
    wwn_t     pWWN;
    wwn_t     nWWN;
    char      alias[MAX_LEN_SYM_HOST_NAME];
    u_int16_t tgtType;
    struct fcNameServerCache *next;
} FcNameServerCacheEntry;

typedef struct fcScsiCounters {
  /* FC-Specific stuff */
  FcAddress        hostFcAddress;
  short            vsanId;           /* VSAN Id (0 if not set) */
  char             hostNumFcAddress[LEN_FC_ADDRESS_DISPLAY];

  /* FC/SCSI Info */
  wwn_t            pWWN, nWWN;
  u_short          fcRecvSize, scsiTarget, lunsGt256;
  u_char           reportedLuns[MAX_LUNS_SUPPORTED];
  u_char           devType;
  char             vendorId[SCSI_VENDOR_ID_LEN];
  char             productId[SCSI_VENDOR_ID_LEN];
  char             productRev[4];
  ScsiLunTrafficInfo *activeLuns[MAX_LUNS_SUPPORTED];
  time_t           lastOnlineTime, lastOfflineTime;
  TrafficCounter   numOffline;

  /* FC Counters */
  TrafficCounter   class2Sent, class2Rcvd, class3Sent, class3Rcvd;
  TrafficCounter   classFSent, classFRcvd;
  TrafficCounter   fcPktsSent, fcPktsRcvd;
  TrafficCounter   fcBytesSent, fcBytesRcvd;
  TrafficCounter   fcFcpPktsSent, fcFcpPktsRcvd;
  TrafficCounter   fcFcpBytesSent, fcFcpBytesRcvd;
  TrafficCounter   fcFiconPktsSent, fcFiconPktsRcvd;
  TrafficCounter   fcFiconBytesSent, fcFiconBytesRcvd;
  TrafficCounter   fcIpfcPktsSent, fcIpfcPktsRcvd;
  TrafficCounter   fcIpfcBytesSent, fcIpfcBytesRcvd;
  TrafficCounter   fcElsPktsSent, fcElsPktsRcvd;
  TrafficCounter   fcElsBytesSent, fcElsBytesRcvd;
  TrafficCounter   fcDnsPktsSent, fcDnsPktsRcvd;
  TrafficCounter   fcDnsBytesSent, fcDnsBytesRcvd;
  TrafficCounter   fcSwilsPktsSent, fcSwilsPktsRcvd;
  TrafficCounter   fcSwilsBytesSent, fcSwilsBytesRcvd;
  TrafficCounter   fcOtherFcPktsSent, fcOtherFcPktsRcvd;
  TrafficCounter   otherFcBytesSent, otherFcBytesRcvd;
  TrafficCounter   fcRscnsRcvd;

  /* SCSI Counters */
  TrafficCounter   scsiReadBytes, scsiWriteBytes, scsiOtherBytes;
} FcScsiCounters;

/* **************************** */

#define hostIp4Address hostIpAddress.Ip4Address
#define hostIp6Address hostIpAddress.Ip6Address


/* Host Traffic */
typedef struct hostTraffic {
  u_int8_t         to_be_deleted; /* 1 = the host will be deleted in the next purge loop */
  u_short          magic;
  u_short          l2Family;    /* 0 = Ethernet, 1 = Fibre Channel (FC) */
  u_int            hostTrafficBucket; /* Index in the **hash_hostTraffic list */
  u_int            originalHostTrafficBucket; /* REMOVE */
  u_short          refCount;         /* Reference counter */
  HostSerial       hostSerial;
  HostAddr         hostIpAddress;
  u_int16_t        vlanId;           /* VLAN Id (-1 if not set) */
  u_int16_t        ifId;            /* Interface Id [e.g. for NetFlow] (-1 if not set) */
  u_int16_t        hostAS;           /* AS to which the host belongs to */
  time_t           firstSeen, lastSeen; /* time when this host has sent/rcvd some data  */
  u_char           ethAddress[LEN_ETHERNET_ADDRESS];
  u_char           lastEthAddress[LEN_ETHERNET_ADDRESS]; /* used for remote addresses */
  char             ethAddressString[LEN_ETHERNET_ADDRESS_DISPLAY];
  char             hostNumIpAddress[20] /* xxx.xxx.xxx.xxx */, *dnsDomainValue, *dnsTLDValue;
  u_char           network_mask; /* IPv6 notation e.g. /24 */
  char             *hwModel, *description, *community;
  char             *ip2ccValue, *fingerprint;
  char             hostResolvedName[MAX_LEN_SYM_HOST_NAME];
  short            hostResolvedNameType;
  u_short          minTTL, maxTTL; /* IP TTL (Time-To-Live) */
  struct timeval   minLatency, maxLatency;

  NonIPTraffic     *nonIPTraffic;
  NonIpProtoTrafficInfo *nonIpProtoTrafficInfos; /* Info about further non IP protos */

  fd_set           flags;
  TrafficCounter   pktSent, pktRcvd, pktSentSession, pktRcvdSession,
    pktDuplicatedAckSent, pktDuplicatedAckRcvd;
  TrafficCounter   lastPktSent, lastPktRcvd;
  TrafficCounter   pktBroadcastSent, bytesBroadcastSent;
  TrafficCounter   pktMulticastSent, bytesMulticastSent,
    pktMulticastRcvd, bytesMulticastRcvd;
  TrafficCounter   lastBytesSent, lastHourBytesSent,
    bytesSent, bytesSentLoc, bytesSentRem, bytesSentSession;
  TrafficCounter   lastBytesRcvd, lastHourBytesRcvd, bytesRcvd,
    bytesRcvdLoc, bytesRcvdFromRem, bytesRcvdSession;
  float            actualRcvdThpt, lastHourRcvdThpt, averageRcvdThpt, peakRcvdThpt,
    actualSentThpt, lastHourSentThpt, averageSentThpt, peakSentThpt,
    actualTThpt, averageTThpt, peakTThpt;
  float            actualRcvdPktThpt, averageRcvdPktThpt, peakRcvdPktThpt,
    actualSentPktThpt, averageSentPktThpt, peakSentPktThpt,
    actualTPktThpt, averageTPktThpt, peakTPktThpt;
  unsigned short   actBandwidthUsage, actBandwidthUsageS, actBandwidthUsageR;
  TrafficDistribution *trafficDistribution;
  u_int32_t        numHostSessions;

  /* Routing */
  RoutingCounter   *routedTraffic;

  /* IP */
  PortUsage        *portsUsage; /* 0...MAX_ASSIGNED_IP_PORTS */

  /* Don't change the recentl... to unsigned ! */
  int              recentlyUsedClientPorts[MAX_NUM_RECENT_PORTS], recentlyUsedServerPorts[MAX_NUM_RECENT_PORTS];
  int              otherIpPortsRcvd[MAX_NUM_RECENT_PORTS], otherIpPortsSent[MAX_NUM_RECENT_PORTS];
  TrafficCounter   ipBytesSent, ipBytesRcvd, ipv6Sent, ipv6Rcvd;
  TrafficCounter   tcpSentLoc, tcpSentRem, udpSentLoc, udpSentRem, icmpSent,icmp6Sent;
  TrafficCounter   tcpRcvdLoc, tcpRcvdFromRem, udpRcvdLoc, udpRcvdFromRem, icmpRcvd, icmp6Rcvd;

  TrafficCounter   tcpFragmentsSent,  tcpFragmentsRcvd,
    udpFragmentsSent, udpFragmentsRcvd,
    icmpFragmentsSent, icmpFragmentsRcvd,
    icmp6FragmentsSent, icmp6FragmentsRcvd;

  /* Protocol decoders */
  ProtocolInfo     *protocolInfo;

  /* Interesting Packets */
  SecurityHostProbes *secHostPkts;
  IcmpHostInfo       *icmpInfo;

  ShortProtoTrafficInfo **ipProtosList;        /* List of myGlobals.numIpProtosList entries */
  ProtoTrafficInfo      **protoIPTrafficInfos; /* Info about IP traffic generated/rcvd by this host */

  /* Fiber Channel/SCSI */
  FcScsiCounters   *fcCounters;

  Counter          totContactedSentPeers, totContactedRcvdPeers; /* # of different contacted peers */
  UsageCounter     contactedSentPeers;   /* peers that talked with this host */
  UsageCounter     contactedRcvdPeers;   /* peers that talked with this host */
  UsageCounter     contactedRouters;     /* routers contacted by this host */
  struct hostTraffic *next;              /* pointer to the next element */
} HostTraffic;

/* **************************** */

typedef struct domainStats {
  HostTraffic *domainHost; /* ptr to a host that belongs to the domain */
  char *clusterName;
  TrafficCounter bytesSent, bytesRcvd;
  TrafficCounter tcpSent, udpSent;
  TrafficCounter icmpSent,icmp6Sent;
  TrafficCounter tcpRcvd, udpRcvd;
  TrafficCounter icmpRcvd,icmp6Rcvd;
} DomainStats;

/* *********************** */

typedef struct ipFragment {
  struct hostTraffic *src, *dest;
  char fragmentOrder;
  u_int fragmentId, lastOffset, lastDataLength;
  u_int totalDataLength, expectedDataLength;
  u_int totalPacketLength;
  u_short sport, dport;
  time_t firstSeen;
  struct ipFragment *prev, *next;
} IpFragment;

/* **************************** */

typedef struct trafficEntry {
  TrafficCounter pktsSent, bytesSent;
  TrafficCounter pktsRcvd, bytesRcvd;
  u_short vsanId;
} TrafficEntry;

typedef struct serviceEntry {
  u_short port;
  char* name;
} ServiceEntry;

typedef struct portCounter {
  u_short port;
  Counter sent, rcvd;
} PortCounter;

/* IP Session Information */
typedef struct ipSession {
  u_short magic;
  u_char isP2P;                     /* Set to 1 if this is a P2P session          */
  HostTraffic* initiator;           /* initiator address                          */
  HostAddr initiatorRealIp;         /* Real IP address (if masqueraded and known) */
  u_short sport;                    /* initiator address (port)                   */
  HostTraffic *remotePeer;          /* remote peer address                        */
  HostAddr remotePeerRealIp;        /* Real IP address (if masqueraded and known) */
  char *virtualPeerName;            /* Name of a virtual host (e.g. HTTP virtual host) */
  u_short dport;                    /* remote peer address (port)                       */
  time_t firstSeen;                 /* time when the session has been initiated         */
  time_t lastSeen;                  /* time when the session has been closed            */
  u_long pktSent, pktRcvd;
  TrafficCounter bytesSent;         /* # bytes sent (initiator -> peer) [IP]            */
  TrafficCounter bytesRcvd;         /* # bytes rcvd (peer -> initiator)[IP]     */
  TrafficCounter bytesProtoSent;    /* # bytes sent (Protocol [e.g. HTTP])      */
  TrafficCounter bytesProtoRcvd;    /* # bytes rcvd (Protocol [e.g. HTTP])      */
  TrafficCounter bytesFragmentedSent;     /* IP Fragments                       */
  TrafficCounter bytesFragmentedRcvd;     /* IP Fragments                       */
  u_int minWindow, maxWindow;       /* TCP window size                          */
  struct timeval nwLatency;         /* Network Latency                          */
  u_short numFin;                   /* # FIN pkts rcvd                          */
  u_short numFinAcked;              /* # ACK pkts rcvd                          */
  u_int32_t lastAckIdI2R;           /* ID of the last ACK rcvd                  */
  u_int32_t lastAckIdR2I;           /* ID of the last ACK rcvd                  */
  u_short numDuplicatedAckI2R;      /* # duplicated ACKs                        */
  u_short numDuplicatedAckR2I;      /* # duplicated ACKs                        */
  TrafficCounter bytesRetranI2R;    /* # bytes retransmitted (due to duplicated ACKs) */
  TrafficCounter bytesRetranR2I;    /* # bytes retransmitted (due to duplicated ACKs) */
  u_int32_t finId[MAX_NUM_FIN];     /* ACK ids we're waiting for                */
  u_long lastFlags;                 /* flags of the last TCP packet             */
  u_int32_t lastCSAck, lastSCAck;   /* they store the last ACK ids C->S/S->C    */
  u_int32_t lastCSFin, lastSCFin;   /* they store the last FIN ids C->S/S->C    */
  u_char lastInitiator2RemFlags[MAX_NUM_STORED_FLAGS]; /* TCP flags             */
  u_char lastRem2InitiatorFlags[MAX_NUM_STORED_FLAGS]; /* TCP flags             */
  u_char sessionState;              /* actual session state                     */
  u_char  passiveFtpSession;        /* checked if this is a passive FTP session */
  u_char  voipSession;              /* checked if this is a VoIP session */
  char *session_info;               /* Info about this session (if any) */
  char *guessed_protocol;
  struct ipSession *next;
} IPSession;

/* ************************************* */

/* FC Session Information */
typedef struct fcSession {
  u_short magic;
  u_short lunMax;                      /* max LUN accessed by this sesssion */
  HostTraffic *initiator;
  FcAddress initiatorAddr;             /* initiator FC address */
  HostTraffic *remotePeer;
  FcAddress remotePeerAddr;            /* remote peer FC address */
  int deviceId;
  struct timeval firstSeen;         /* time when the session has been initiated   */
  struct timeval lastSeen;          /* time when the session has been closed      */
  u_long pktSent, pktRcvd;
  TrafficCounter bytesSent, bytesRcvd;
  TrafficCounter numScsiRdCmd, numScsiWrCmd, numScsiOtCmd;
  TrafficCounter fcpBytesSent, fcpBytesRcvd;
  TrafficCounter ficonRdBytes, ficonWrBytes, ficonOtBytes;
  TrafficCounter ipfcBytesSent, ipfcBytesRcvd;
  TrafficCounter fcElsBytesSent, fcElsBytesRcvd;
  TrafficCounter fcDnsBytesSent, fcDnsBytesRcvd;
  TrafficCounter fcSwilsBytesSent, fcSwilsBytesRcvd;
  TrafficCounter otherBytesSent, otherBytesRcvd;
  TrafficCounter unknownLunBytesSent, unknownLunBytesRcvd;
  TrafficCounter bytesFragmentedSent;     /* FC Fragments                       */
  TrafficCounter bytesFragmentedRcvd;     /* FC Fragments                       */
  TrafficCounter acksSent, acksRcvd;      /* Num of ACK1 frames; Class F/2      */
  TrafficCounter class2BytesSent, class2BytesRcvd;
  TrafficCounter class3BytesSent, class3BytesRcvd;
  u_char lastRctlRcvd, lastRctlSent;
  u_char lastTypeRcvd, lastTypeSent;
  u_short lastOxidSent, lastOxidRcvd;
  u_short lastScsiOxid, lastElsOxid, lastSwilsOxid, lastLun;
  u_char  lastScsiCmd, lastElsCmd, lastSwilsCmd;
  u_char sessionState;              /* actual session state                     */
  ScsiLunTrafficInfo *activeLuns[MAX_LUNS_SUPPORTED];
  struct fcSession *next;
} FCSession;

typedef struct scsiSessionSortEntry {
    HostTraffic *initiator, *target;
    u_short lun;
    ScsiLunTrafficInfo *stats;
} ScsiSessionSortEntry;

typedef struct ntopIfaceAddrInet {
  struct in_addr ifAddr;
  struct in_addr network;
  struct in_addr netmask;
} NtopIfaceAddrInet;

#ifdef INET6
typedef struct ntopIfaceAddrInet6 {
  struct in6_addr ifAddr;
  int             prefixlen;
} NtopIfaceAddrInet6;
#endif

typedef struct ntopIfaceaddr{
  int family;
  struct ntopIfaceaddr *next;
  union {
    NtopIfaceAddrInet  inet;
#ifdef INET6
    NtopIfaceAddrInet6 inet6;
#endif
  }af;
} NtopIfaceAddr;

/* ************************************* */

/* Flow aggregation */
typedef enum {
  noAggregation = 0,
  portAggregation,
  hostAggregation,
  protocolAggregation,
  asAggregation
} AggregationType;

typedef struct probeInfo {
  struct in_addr probeAddr;
  u_int32_t      pkts;
} ProbeInfo;

/* *************************** */

#define CONST_FLOW_VERSION_1		    1
#define CONST_V1FLOWS_PER_PAK		    30

#define CONST_FLOW_VERSION_5		    5
#define CONST_V5FLOWS_PER_PAK		    30

#define CONST_FLOW_VERSION_7		    7
#define CONST_V7FLOWS_PER_PAK		    28

/*
  For more info see:

  http://www.cisco.com/warp/public/cc/pd/iosw/ioft/neflct/tech/napps_wp.htm

  ftp://ftp.net.ohio-state.edu/users/maf/cisco/
*/

/* ********************************* */

struct flow_ver1_hdr {
  u_int16_t version;         /* Current version = 1*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
};

struct flow_ver1_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration */
  u_int32_t dOctets;    /* Octets sent in Duration */
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t pad;        /* pad to word boundary */
  u_int8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int8_t  pad2[7];    /* pad to word boundary */
};

typedef struct single_flow_ver1_rec {
  struct flow_ver1_hdr flowHeader;
  struct flow_ver1_rec flowRecord[CONST_V1FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow1Record;

/* ********************************* */

struct flow_ver5_hdr {
  u_int16_t version;         /* Current version=5*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int8_t  engine_type;     /* Type of flow switching engine (RP,VIP,etc.)*/
  u_int8_t  engine_id;       /* Slot number of the flow switching engine */
};

struct flow_ver5_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration (milliseconds between 1st
			   & last packet in this flow)*/
  u_int32_t dOctets;    /* Octets sent in Duration (milliseconds between 1st
			   & last packet in  this flow)*/
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t  pad1;       /* pad to word boundary */
  u_int8_t  tcp_flags;  /* Cumulative OR of tcp flags */
  u_int8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int8_t  src_mask;   /* source route's mask bits */
  u_int8_t  dst_mask;   /* destination route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
};

typedef struct single_flow_ver5_rec {
  struct flow_ver5_hdr flowHeader;
  struct flow_ver5_rec flowRecord[CONST_V5FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow5Record;

/* ********************************* */

struct flow_ver7_hdr {
  u_int16_t version;         /* Current version=7*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int32_t reserved;
};

struct flow_ver7_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration */
  u_int32_t dOctets;    /* Octets sent in Duration */
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t  flags;      /* Shortcut mode(dest only,src only,full flows*/
  u_int8_t  tcp_flags;  /* Cumulative OR of tcp flags */
  u_int8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int8_t  dst_mask;   /* destination route's mask bits */
  u_int8_t  src_mask;   /* source route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
  u_int32_t router_sc;  /* Router which is shortcut by switch */
};

typedef struct single_flow_ver7_rec {
  struct flow_ver7_hdr flowHeader;
  struct flow_ver7_rec flowRecord[CONST_V7FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow7Record;

/* ************************************ */

/* NetFlow v9/IPFIX */

typedef struct flow_ver9_hdr {
  u_int16_t version;         /* Current version=9*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int32_t sourceId;        /* Source id */
} V9FlowHeader;

typedef struct flow_ver9_template_field {
  u_int16_t fieldType;
  u_int16_t fieldLen;
} V9TemplateField;

typedef struct flow_ver9_template {
  u_int16_t templateFlowset; /* = 0 */
  u_int16_t flowsetLen;
  u_int16_t templateId;
  u_int16_t fieldCount;
} V9Template;

typedef struct flow_ver9_flow_set {
  u_int16_t templateId;
  u_int16_t flowsetLen;
} V9FlowSet;

typedef struct flow_ver9_templateids {
  u_int16_t templateId;
  u_int16_t templateLen;
  char      *templateDescr;
} V9TemplateId;

/* ******************************************* */

#define NUM_TEMPLATES 88

typedef struct flowSetV9 {
  V9Template templateInfo;
  V9TemplateField *fields;
  struct flowSetV9 *next;
} FlowSetV9;

typedef struct interfaceStats {
  u_int32_t netflow_device_ip;
  u_short interface_id;
  char interface_name[32];
  TrafficCounter inBytes, outBytes, inPkts, outPkts;
  TrafficCounter selfBytes, selfPkts;
  struct interfaceStats *next;
} InterfaceStats;

/* AS statistics */
typedef struct astats {
  u_short as_id;
  time_t lastUpdate;
  Counter totPktsSinceLastRRDDump;
  TrafficCounter inBytes, outBytes, inPkts, outPkts;
  TrafficCounter selfBytes, selfPkts;
  struct astats *next;
} AsStats;

#define MAX_INTERFACE_STATS_QUEUE_LEN  32

typedef struct netFlowGlobals {
  u_char netFlowDebug;

  /* Flow Storage */
  char *dumpPath;
  u_short dumpInterval;
  time_t dumpFdCreationTime;
  FILE *dumpFd;

  /* Flow reception */
  AggregationType netFlowAggregation;
  int netFlowInSocket, netFlowDeviceId;
#ifdef HAVE_SCTP
  int netFlowInSctpSocket;
#endif
  u_char netFlowAssumeFTP, saveFlowsIntoDB, enableSessionHandling;
  u_short netFlowInPort;
  struct in_addr netFlowIfAddress, netFlowIfMask;
  char *netFlowWhiteList, *netFlowBlackList;
  u_long numNetFlowsPktsRcvd, numNetFlowsV5Rcvd;
  u_long numNetFlowsV1Rcvd, numNetFlowsV7Rcvd, numNetFlowsV9Rcvd, numNetFlowsProcessed;
  u_long numNetFlowsRcvd, lastNumNetFlowsRcvd;
  u_long totalNetFlowsTCPSize, totalNetFlowsUDPSize, totalNetFlowsICMPSize, totalNetFlowsOtherSize;
  u_long numNetFlowsTCPRcvd, numNetFlowsUDPRcvd, numNetFlowsICMPRcvd, numNetFlowsOtherRcvd;
  u_long numBadNetFlowsVersionsRcvd, numBadFlowPkts, numBadFlowBytes, numBadFlowReality;
  u_long numSrcNetFlowsEntryFailedBlackList, numSrcNetFlowsEntryFailedWhiteList,
    numSrcNetFlowsEntryAccepted,
    numDstNetFlowsEntryFailedBlackList, numDstNetFlowsEntryFailedWhiteList,
    numDstNetFlowsEntryAccepted;
  u_long numNetFlowsV9TemplRcvd, numNetFlowsV9BadTemplRcvd, numNetFlowsV9UnknTemplRcvd;

  /* Stats */
  ProbeInfo probeList[MAX_NUM_PROBES];
  InterfaceStats *ifStats;
  u_int32_t whiteNetworks[MAX_NUM_NETWORKS][4], blackNetworks[MAX_NUM_NETWORKS][4];
  u_short numWhiteNets, numBlackNets;
  u_int32_t flowProcessed;
  Counter flowProcessedBytes;
  HostTraffic *dummyHost;
  FlowSetV9 *templates;

  pthread_t netFlowThread;
  int threadActive;
  PthreadMutex whiteblackListMutex, ifStatsMutex;

#ifdef HAVE_SNMP
  pthread_t netFlowUtilsThread;
  InterfaceStats *ifStatsQueue[MAX_INTERFACE_STATS_QUEUE_LEN];
  u_short ifStatsQueue_len;
  PthreadMutex ifStatsQueueMutex;
  ConditionalVariable ifStatsQueueCondvar;
#endif

} NetFlowGlobals;

/* *********************************** */

#define MAX_NUM_SFLOW_INTERFACES      4096

typedef struct ifCounters {
  u_int32_t ifIndex;
  u_int32_t ifType;
  u_int64_t ifSpeed;
  u_int32_t ifDirection;        /* Derived from MAU MIB (RFC 2668)
				   0 = unknown, 1 = full-duplex,
				   2 = half-duplex, 3 = in, 4 = out */
  u_int32_t ifStatus;           /* bit field with the following bits assigned:
				   bit 0 = ifAdminStatus (0 = down, 1 = up)
				   bit 1 = ifOperStatus (0 = down, 1 = up) */
  u_int64_t ifInOctets;
  u_int32_t ifInUcastPkts;
  u_int32_t ifInMulticastPkts;
  u_int32_t ifInBroadcastPkts;
  u_int32_t ifInDiscards;
  u_int32_t ifInErrors;
  u_int32_t ifInUnknownProtos;
  u_int64_t ifOutOctets;
  u_int32_t ifOutUcastPkts;
  u_int32_t ifOutMulticastPkts;
  u_int32_t ifOutBroadcastPkts;
  u_int32_t ifOutDiscards;
  u_int32_t ifOutErrors;
  u_int32_t ifPromiscuousMode;
  struct ifCounters *next;
} IfCounters;


typedef struct sFlowGlobals {
  u_char sflowDebug;

  /* Flow reception */
  AggregationType sflowAggregation;
  int sflowInSocket, sflowDeviceId;
  u_char sflowAssumeFTP;
  u_short sflowInPort;
  struct in_addr sflowIfAddress, sflowIfMask;
  char *sflowWhiteList, *sflowBlackList;
  u_long numsFlowsPktsRcvd;
  u_long numsFlowsV2Rcvd, numsFlowsV4Rcvd, numsFlowsV5Rcvd, numsFlowsProcessed;
  u_long numsFlowsSamples, numsFlowCounterUpdates;
  u_long numBadsFlowsVersionsRcvd, numBadFlowReality;
  u_long numSrcsFlowsEntryFailedBlackList, numSrcsFlowsEntryFailedWhiteList,
    numSrcsFlowsEntryAccepted,
    numDstsFlowsEntryFailedBlackList, numDstsFlowsEntryFailedWhiteList,
    numDstsFlowsEntryAccepted;

  /* Stats */
  ProbeInfo probeList[MAX_NUM_PROBES];
  u_int32_t whiteNetworks[MAX_NUM_NETWORKS][4], blackNetworks[MAX_NUM_NETWORKS][4];
  u_short numWhiteNets, numBlackNets;
  u_int32_t flowProcessed;
  Counter flowProcessedBytes;
  HostTraffic *dummyHost;

  pthread_t sflowThread;
  int threadActive;
  PthreadMutex whiteblackListMutex;

  u_long numSamplesReceived, initialPool, lastSample;
  u_int32_t flowSampleSeqNo, numSamplesToGo;
  IfCounters *ifCounters;
} SflowGlobals;

/* *********************************** */

typedef struct ntopInterface {
  char *name;                    /* Interface name (e.g. eth0) */
  char *uniqueIfName;            /* Unique interface name used to save data on disk */
  char *humanFriendlyName;       /* Human friendly name of the interface (needed under WinNT and above) */
  int flags;                     /* the status of the interface as viewed by ntop */

  u_int32_t addr;                /* Internet address (four bytes notation) */
  char *ipdot;                   /* IP address (dot notation) */
  char *fqdn;                    /* FQDN (resolved for humans) */

  struct in_addr network;        /* network number associated to this interface */
  struct in_addr netmask;        /* netmask associated to this interface */
  u_int          numHosts;       /* # hosts of the subnet */
  struct in_addr ifAddr;         /* network number associated to this interface */
#ifdef INET6
  NtopIfaceAddr  *v6Addrs;
#endif
  time_t started;                /* time the interface was enabled to look at pkts */
  time_t firstpkt;               /* time first packet was captured */
  time_t lastpkt;                /* time last packet was captured */

  pcap_t *pcapPtr;               /* LBNL pcap handler */
  pcap_dumper_t *pcapDumper;     /* LBNL pcap dumper  - enabled using the 'l' flag */
  pcap_dumper_t *pcapErrDumper;  /* LBNL pcap dumper - all suspicious packets are logged */
  pcap_dumper_t *pcapOtherDumper;/* LBNL pcap dumper - all "other" (unknown Ethernet and IP) packets are logged */

  char virtualDevice;            /* set to 1 for virtual devices (e.g. eth0:1) */
  char activeDevice;             /* Is the interface active (useful for virtual interfaces) */
  char dummyDevice;              /* set to 1 for 'artificial' devices (e.g. sFlow-device) */
  bool hasVLANs;                 /* Have we seen 802.1q stuff */
  u_int32_t deviceSpeed;         /* Device speed (0 if speed is unknown) */
  int snaplen;                   /* maximum # of bytes to capture foreach pkt */
                                 /* read timeout in milliseconds */
  int datalink;                  /* data-link encapsulation type (see DLT_* in net/bph.h) */
  u_short samplingRate;          /* default = 1 */
  u_short droppedSamples;        /* Number of packets dropped due to sampling, since the last processed pkt */
  u_short mtuSize,               /* MTU and header, derived from DLT and table in globals-core.c */
          headerSize;

  char *filter;                  /* user defined filter expression (if any) */

  int fd;                        /* unique identifier (Unix file descriptor) */

  PthreadMutex asMutex;
  AsStats *asStats;

  /*
   * NPA - Network Packet Analyzer (main thread)
   */
  PthreadMutex packetQueueMutex;
  PthreadMutex packetProcessMutex;
  PacketInformation *packetQueue; /* [CONST_PACKET_QUEUE_LENGTH+1]; */
  u_int packetQueueLen, maxPacketQueueLen, packetQueueHead, packetQueueTail;
  ConditionalVariable queueCondvar;
  pthread_t dequeuePacketThreadId;

  /*
   * The packets section
   */
  TrafficCounter receivedPkts;    /* # of pkts recevied by the application */
  TrafficCounter droppedPkts;     /* # of pkts dropped by the application */
  TrafficCounter pcapDroppedPkts; /* # of pkts dropped by libpcap */
  TrafficCounter initialPcapDroppedPkts; /* # of pkts dropped by libpcap at startup */
  TrafficCounter ethernetPkts;    /* # of Ethernet pkts captured by the application */
  TrafficCounter broadcastPkts;   /* # of broadcast pkts captured by the application */
  TrafficCounter multicastPkts;   /* # of multicast pkts captured by the application */
  TrafficCounter ipPkts;          /* # of IP pkts captured by the application */

  TrafficCounter fcPkts;
  TrafficCounter fcEofaPkts;
  TrafficCounter fcEofAbnormalPkts;
  TrafficCounter fcAbnormalPkts;
  TrafficCounter fcBroadcastPkts;

  /*
   * The bytes section
   */
  TrafficCounter ethernetBytes;  /* # bytes captured */
  TrafficCounter ipBytes;
  TrafficCounter fragmentedIpBytes;
  TrafficCounter tcpBytes;
  TrafficCounter udpBytes;
  TrafficCounter otherIpBytes;

  TrafficCounter icmpBytes;
  TrafficCounter dlcBytes;
  TrafficCounter ipxBytes;
  TrafficCounter stpBytes;        /* Spanning Tree */
  TrafficCounter decnetBytes;
  TrafficCounter netbiosBytes;
  TrafficCounter arpRarpBytes;
  TrafficCounter atalkBytes;
  TrafficCounter egpBytes;
  TrafficCounter osiBytes;
  TrafficCounter ipv6Bytes;
  TrafficCounter icmp6Bytes;
  TrafficCounter otherBytes;
  TrafficCounter *ipProtosList;        /* List of myGlobals.numIpProtosList entries */

  TrafficCounter fcBytes;
  TrafficCounter fragmentedFcBytes;
  TrafficCounter fcFcpBytes;
  TrafficCounter fcFiconBytes;
  TrafficCounter fcIpfcBytes;
  TrafficCounter fcSwilsBytes;
  TrafficCounter fcDnsBytes;
  TrafficCounter fcElsBytes;
  TrafficCounter otherFcBytes;
  TrafficCounter fcBroadcastBytes;
  TrafficCounter class2Bytes, class3Bytes, classFBytes;

  PortCounter    **ipPorts; /* [MAX_IP_PORT] */

  TrafficCounter lastMinEthernetBytes;
  TrafficCounter lastFiveMinsEthernetBytes;

  TrafficCounter lastMinEthernetPkts;
  TrafficCounter lastFiveMinsEthernetPkts;
  TrafficCounter lastNumEthernetPkts;

  TrafficCounter lastEthernetPkts;
  TrafficCounter lastTotalPkts;

  TrafficCounter lastBroadcastPkts;
  TrafficCounter lastMulticastPkts;

  TrafficCounter lastEthernetBytes;
  TrafficCounter lastIpBytes;
  TrafficCounter lastNonIpBytes;

  PacketStats rcvdPktStats; /* statistics from start of the run to time of call */
  FcPacketStats rcvdFcPktStats; /* statistics from start of the run to time of call */
  TTLstats    rcvdPktTTLStats;

  float peakThroughput, actualThpt, lastMinThpt, lastFiveMinsThpt;
  float peakPacketThroughput, actualPktsThpt, lastMinPktsThpt, lastFiveMinsPktsThpt;

  time_t lastThptUpdate, lastMinThptUpdate;
  time_t lastHourThptUpdate, lastFiveMinsThptUpdate;
  float  throughput;
  float  packetThroughput;

  unsigned long numThptSamples;
  ThptEntry last60MinutesThpt[60], last24HoursThpt[24];
  float last30daysThpt[30];
  u_short last60MinutesThptIdx, last24HoursThptIdx, last30daysThptIdx;

  SimpleProtoTrafficInfo tcpGlobalTrafficStats, udpGlobalTrafficStats, icmpGlobalTrafficStats;
  SimpleProtoTrafficInfo *ipProtoStats;
  SecurityDeviceProbes securityPkts;

  TrafficCounter numEstablishedTCPConnections; /* = # really established connections */

  pthread_t pcapDispatchThreadId;

  u_int  hostsno;        /* # of valid entries in the following table */
  u_int  actualHashSize;
  struct hostTraffic **hash_hostTraffic;

  u_short hashListMaxLookups;

  FcFabricElementHash **vsanHash;

  /* ************************** */

  IpFragment *fragmentList;
  IPSession **tcpSession;
  u_short numTcpSessions, maxNumTcpSessions;
  TrafficEntry** ipTrafficMatrix; /* Subnet traffic Matrix */
  struct hostTraffic** ipTrafficMatrixHosts; /* Subnet traffic Matrix Hosts */
  fd_set ipTrafficMatrixPromiscHosts;

  /* ************************** */

  struct fcSession **fcSession;
  u_short numFcSessions, maxNumFcSessions;
  TrafficEntry** fcTrafficMatrix; /* Subnet traffic Matrix */
  struct hostTraffic** fcTrafficMatrixHosts; /* Subnet traffic Matrix Hosts */

  NetFlowGlobals *netflowGlobals;  /* NetFlow */
  SflowGlobals *sflowGlobals;      /* sFlow */
} NtopInterface;

/* *********************************** */

typedef struct processInfo {
  char marker; /* internal use only */
  char *command, *user;
  time_t firstSeen, lastSeen;
  int pid;
  TrafficCounter bytesSent, bytesRcvd;
  /* peers that talked with this process */
  HostSerial contactedIpPeersSerials[MAX_NUM_CONTACTED_PEERS];
  u_int contactedIpPeersIdx;
} ProcessInfo;

/* *********************************** */

typedef struct processInfoList {
  ProcessInfo            *element;
  struct processInfoList *next;
} ProcessInfoList;

typedef union {
  HEADER qb1;
  u_char qb2[PACKETSZ];
} querybuf;

typedef struct {
  char      queryName[MAXDNAME];           /* original name queried */
  int       queryType;                     /* type of original query */
  char      name[MAXDNAME];                /* official name of host */
  char      aliases[MAX_ALIASES][MAXDNAME]; /* alias list */
  u_int32_t addrList[MAX_ADDRESSES]; /* list of addresses from name server */
  int       addrType;   /* host address type */
  int       addrLen;    /* length of address */
} DNSHostInfo;

/* ******************************

NOTE:

Most of the code below has been
borrowed from tcpdump.

****************************** */

/* RFC 951 */
typedef struct bootProtocol {
  unsigned char	    bp_op;	    /* packet opcode/message type.
				       1 = BOOTREQUEST, 2 = BOOTREPLY */
  unsigned char	    bp_htype;	    /* hardware addr type - RFC 826 */
  unsigned char	    bp_hlen;	    /* hardware addr length (6 for 10Mb Ethernet) */
  unsigned char	    bp_hops;	    /* gateway hops (server set) */
  u_int32_t	    bp_xid;	    /* transaction ID (random) */
  unsigned short    bp_secs;	    /* seconds elapsed since
				       client started trying to boot */
  unsigned short    bp_flags;	    /* flags (not much used): 0x8000 is broadcast */
  struct in_addr    bp_ciaddr;	    /* client IP address */
  struct in_addr    bp_yiaddr;	    /* 'your' (client) IP address */
  struct in_addr    bp_siaddr;	    /* server IP address */
  struct in_addr    bp_giaddr;	    /* relay IP address */
  unsigned char	    bp_chaddr[16];  /* client hardware address (optional) */
  unsigned char	    bp_sname[64];   /* server host name */
  unsigned char	    bp_file[128];   /* boot file name */
  unsigned char	    bp_vend[256];   /* vendor-specific area - RFC 1048 */
} BootProtocol;

/* ******************************************* */

/*
 * The definitions below have been copied
 * from llc.h that's part of tcpdump
 *
 */

struct llc {
  u_char dsap;
  u_char ssap;
  union {
    u_char u_ctl;
    u_short is_ctl;
    struct {
      u_char snap_ui;
      u_char snap_pi[5];
    } snap;
    struct {
      u_char snap_ui;
      u_char snap_orgcode[3];
      u_char snap_ethertype[2];
    } snap_ether;
  } ctl;
};

/* ******************************* */

typedef struct {
  u_int16_t checksum, length;
  u_int8_t  hops, packetType;
  u_char    destNw[4], destNode[6];
  u_int16_t dstSocket;
  u_char    srcNw[4], srcNode[6];
  u_int16_t srcSocket;
} IPXpacket;

struct enamemem {
  u_short e_addr0;
  u_short e_addr1;
  u_short e_addr2;
  char   *e_name;
  u_char *e_nsap;  /* used only for nsaptable[] */
  struct enamemem *e_nxt;
};

/* **************** Plugin **************** */

typedef void(*VoidFunct)(u_char /* 0=term plugin, 1=term ntop */);
typedef int(*IntFunct)(void);
typedef void(*PluginFunct)(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p);
typedef void(*PluginHTTPFunct)(char* url);
typedef void(*PluginCreateDeleteFunct)(HostTraffic*, u_short, u_char);

typedef struct extraPage {
  /* url and description of extra page (if any) for a plugin */
  char *icon;
  char *url;
  char *descr;
} ExtraPage;

typedef enum {
  NoViewNoConfigure = 0,
  ViewOnly,
  ConfigureOnly,
  ViewConfigure
} PluginViewConfigure;

typedef struct pluginInfo {
  /* Plugin Info */
  char *pluginNtopVersion;   /* Version of ntop for which the plugin was compiled */
  char *pluginName;          /* Short plugin name (e.g. icmpPlugin) */
  char *pluginDescr;         /* Long plugin description */
  char *pluginVersion;
  char *pluginAuthor;
  char *pluginURLname;       /* Set it to NULL if the plugin doesn't speak HTTP */
  char activeByDefault;      /* Set it to 1 if this plugin is active by default */
  PluginViewConfigure viewConfigureFlag;
  char inactiveSetup;        /* Set it to 1 if this plugin can be called inactive for setup */
  IntFunct startFunct;
  VoidFunct termFunct;
  PluginFunct pluginFunct;   /* Initialize here all the plugin structs... */
  PluginHTTPFunct httpFunct; /* Set it to NULL if the plugin doesn't speak HTTP */
  PluginCreateDeleteFunct crtDltFunct; /* Called whenever a host is created/deleted */
  char* bpfFilter;           /* BPF filter for selecting packets that
				will be routed to the plugin */
  char *pluginStatusMessage;
  ExtraPage *extraPages;     /* other pages this responds to */
} PluginInfo;

typedef struct pluginStatus {
  PluginInfo *pluginPtr;
  void       *pluginMemoryPtr; /* ptr returned by dlopen() */
  char        activePlugin;
} PluginStatus;

/* Flow Filter List */
typedef struct flowFilterList {
  char* flowName;
  struct bpf_program *fcode;     /* compiled filter code one for each device  */
  struct flowFilterList *next;   /* next element (linked list) */
  TrafficCounter bytes, packets;
  PluginStatus pluginStatus;
} FlowFilterList;

typedef struct sessionInfo {
  HostAddr  sessionHost;
  u_short   sessionPort;
  time_t    creationTime;
  char     *session_info;
} SessionInfo;

typedef struct hostAddress {
  unsigned int numAddr;
  char* symAddr;
} HostAddress;

/* *********************** */

/* Appletalk Datagram Delivery Protocol */
typedef struct atDDPheader {
  u_int16_t       datagramLength, ddpChecksum;
  u_int16_t       dstNet, srcNet;
  u_char          dstNode, srcNode;
  u_char          dstSocket, srcSocket;
  u_char          ddpType;
} AtDDPheader;

/* Appletalk Name Binding Protocol */
typedef struct atNBPheader {
  u_char          function, nbpId;
} AtNBPheader;

/* *********************** */

typedef struct usersTraffic {
  char*  userName;
  Counter bytesSent, bytesRcvd;
} UsersTraffic;

/* **************************** */

typedef struct transactionTime {
  u_int16_t transactionId;
  struct timeval theTime;
} TransactionTime;

/* **************************** */

/* Packet buffer */
struct pbuf {
  struct pcap_pkthdr h;
  u_char b[sizeof(unsigned int)];	/* actual size depend on snaplen */
};

/* **************************** */

typedef struct badGuysAddr {
  HostAddr       addr;
  time_t         lastBadAccess;
  u_int16_t      count;
} BadGuysAddr;

/* ******** Token Ring ************ */

#if defined(WIN32) && !defined (__GNUC__)
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
#endif /* WIN32 */

struct tokenRing_header {
  u_int8_t  trn_ac;             /* access control field */
  u_int8_t  trn_fc;             /* field control field  */
  u_int8_t  trn_dhost[6];       /* destination host     */
  u_int8_t  trn_shost[6];       /* source host          */
  u_int16_t trn_rcf;            /* route control field  */
  u_int16_t trn_rseg[8];        /* routing registers    */
};

struct tokenRing_llc {
  u_int8_t  dsap;		/* destination SAP   */
  u_int8_t  ssap;		/* source SAP        */
  u_int8_t  llc;		/* LLC control field */
  u_int8_t  protid[3];		/* protocol id       */
  u_int16_t ethType;		/* ethertype field   */
};

/* ******** ANY ************ */

typedef struct anyHeader {
  u_int16_t  pktType;
  u_int16_t  llcAddressType;
  u_int16_t  llcAddressLen;
  u_char     ethAddress[LEN_ETHERNET_ADDRESS];
  u_int16_t  pad;
  u_int16_t  protoType;
} AnyHeader;

/* ******** FDDI ************ */

typedef struct fddi_header {
  u_char  fc;	    /* frame control    */
  u_char  dhost[6]; /* destination host */
  u_char  shost[6]; /* source host      */
} FDDI_header;
#define FDDI_HDRLEN (sizeof(struct fddi_header))

/* ************ GRE (Generic Routing Encapsulation) ************* */

typedef struct greTunnel {
  u_int16_t	flags,     protocol;
  u_int16_t	payload,   callId;
  u_int32_t	seqAckNumber;
} GreTunnel;

/* ************ PPP ************* */

typedef struct pppTunnelHeader {
  u_int16_t	unused, protocol;
} PPPTunnelHeader;

/* ************ Fibre Channel *********** */
typedef struct fcHeader {
#ifdef CFG_BIG_ENDIAN
    u_int32_t d_id:24;
    u_int32_t r_ctl:8;
    u_int32_t s_id:24;
    u_int32_t cs_ctl:8;
    u_int32_t f_ctl:24;
    u_int32_t type:8;
#else
    u_int32_t r_ctl:8;
    u_int32_t d_id:24;
    u_int32_t cs_ctl:8;
    u_int32_t s_id:24;
    u_int32_t type:8;
    u_int32_t f_ctl:24;
#endif
    u_int8_t  seq_id;
    u_int8_t  df_ctl;
    u_int16_t seq_cnt;
    u_int16_t oxid;
    u_int16_t rxid;
    u_int32_t parameter;
} FcHeader;

typedef struct fcHeader_align {
    /* This structure is used to correctly endian the FC header */
    u_int32_t fld1;
    u_int32_t fld2;
    u_int32_t fld3;
    u_int8_t  seq_id;
    u_int8_t  df_ctl;
    u_int16_t seq_cnt;
    u_int16_t oxid;
    u_int16_t rxid;
    u_int32_t parameter;
} FcHeaderAlign;

/* ******** Cisco ISL ************ */

typedef struct islHeader {
  u_char     dstEthAddress[LEN_ETHERNET_ADDRESS];
  u_char     srcEthAddress[LEN_ETHERNET_ADDRESS];
  u_int16_t  len;
  u_int8_t   dap, ssap, control;
  u_char     hsa[3];
  u_int16_t  vlanId, idx, notUsed;
} IslHeader;

/* ******************************** */

typedef struct serialCacheEntry {
  char isMAC;
  char data[17];
  u_long creationTime;
} SerialCacheEntry;

#ifndef HAVE_GETOPT_H
struct option
{
  char *name;
  int has_arg;
  int *flag;
  int val;
};
#endif /* HAVE_GETOPT_H */

/* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
typedef struct IPNode {
  struct IPNode *b[2];
  union {
    char cc[4]; /* Country */
    u_short as; /* AS */
  } node;
} IPNode;

/* *************************************************************** */

typedef enum {
  showAllHosts = 0,
  showOnlyLocalHosts,
  showOnlyRemoteHosts
} HostsDisplayPolicy;

/* *************************************************************** */

typedef enum {
  showSentReceived = 0,
  showOnlySent,
  showOnlyReceived
} LocalityDisplayPolicy;

/* *************************************************************** */

typedef enum {
  showHostMainPage = 0,
  showHostLunStats,
  showHostLunGraphs,
  showHostScsiSessionBytes,
  showHostScsiSessionTimes,
  showHostScsiSessionStatus,
  showHostScsiSessionTMInfo,
  showHostFcSessions
} FcHostsDisplayPolicy;

/* *************************************************************** */

typedef enum {
  showPrefBasicPref = 1,
  showPrefDisplayPref,
  showPrefIPPref,
  showPrefFCPref,
  showPrefAdvPref,
  showPrefDbgPref,
  showPrefDBPref
} UserPrefDisplayPage;

/* *********************************** */

#ifdef WIN32
#define mode_t int
#endif

#ifdef WIN32
#define ntop_mkdir(a, b) _mkdir(a)
#else
#define ntop_mkdir(a, b) mkdir(a, b)
#endif


#define BROADCAST_HOSTS_ENTRY    0
#define OTHER_HOSTS_ENTRY        1
#define FIRST_HOSTS_ENTRY        2 /* first available host entry */

/*
 * Preferences settable by a user, from the web page & cmd line
 *
 */

typedef struct _userPref {
  char *accessLogFile;          /* -a |--access-log-file */
  bool enablePacketDecoding;    /* -b | --disable-decoders */
  bool stickyHosts;             /* -c | --sticky-hosts */
  bool daemonMode;              /* -d | --daemon */
  int  maxNumLines;             /* -e | --max-table-rows */
  char *rFileName;              /* -f | --traffic-dump-file */
  bool trackOnlyLocalHosts;     /* -g | --track-local-hosts */
  char *devices;                /* -i | --interface */
  bool enableOtherPacketDump;   /* -j | --create-other-packets */
  char *pcapLog;                /* -l | --pcap-log */
  char *localAddresses;         /* -m | --local-subnets */
  bool numericFlag;             /* -n | --numeric-ip-addresses */
  bool dontTrustMACaddr;        /* -o | --no-mac */
  char *protoSpecs;             /* -p | --protocols */
  bool enableSuspiciousPacketDump; /* -q | --create-suspicious-packets */
  int  refreshRate;             /* -r | --refresh-time */
  bool disablePromiscuousMode;  /* -s | --no-promiscuous */
  int  traceLevel;              /* -t | --trace-level */
  char *mapperURL;              /* -U | --disable-mapper */
  u_int     maxNumHashEntries;  /* -x */
  u_int     maxNumSessions;     /* -X */

  /* SQL Database */
  char    sqlDbConfig[64];
  u_int   sqlRecDaysLifetime;
  bool    saveRecordsIntoDb, saveSessionsIntoDb;

  u_int16_t defaultVsan;        /* -v | --default-vsan */
  char      *webAddr;           /* -w | --http-serveraddress[:port] */
  int       webPort;
  int       ipv4or6;            /* -6 -4 */
  bool      enableSessionHandling; /* -z | --disable-sessions */

  char *currentFilterExpression;/* -B | --filter-expression */
  u_short samplingRate;         /* -C | --sampling-rate */
  char domainName[MAXHOSTNAMELEN]; /* -D | --domain */
  char *flowSpecs;              /* -F | --flow-spec */

  bool debugMode;               /* -K | --enable-debug */
#ifndef WIN32
  int  useSyslog;               /* -L | --use-syslog*/
#endif

  bool mergeInterfaces;         /* -M | --no-interface-merge */
  bool enableL7;                /* Enable/disable l7 protocol pattern matching */
  char *pcapLogBasePath;        /* -O | --pcap-file-path */ /* Added by Ola Lundqvist <opal@debian.org>. */
  char *fcNSCacheFile;          /* -N | --wwn-map */

#ifdef HAVE_OPENSSL
  char *sslAddr;                /* -W | --https-serveraddress[:port] */
  int  sslPort;
#endif

#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  bool useSSLwatchdog;          /* --ssl-watchdog '133' */
#endif

#ifdef MAKE_WITH_SCHED_YIELD
  bool disableSchedYield;       /* --disable-schedyield '134' */
#endif

  bool w3c;                     /* --w3c '136' */

  char *P3Pcp;                  /* --p3p-cp '137' */
  char *P3Puri;                 /* --p3p-uri '138' */

  char *instance;               /* --instance '140' */
  char *logo;

  bool disableStopcap;          /* --disable-stopcap '142' */

  bool disableInstantSessionPurge; /* --disable-instantsessionpurge '144' */
  bool printFcOnly;             /* --fc-only '147' */
  bool printIpOnly;             /* --no-fc '148' */
  bool noInvalidLunDisplay;     /* --no-invalid-lun '149' */
  bool disableMutexExtraInfo;   /* --disable-mutexextrainfo '145' */

  bool skipVersionCheck;        /* --skip-version-check '150' */

  char *knownSubnets;         /* --known-subnets */
} UserPref;

typedef struct ntopGlobals {

  /* How is ntop run? */

  char *program_name;      /* The name the program was run with, stripped of any leading path */
  int basentoppid;         /* Used for writing to /var/run/ntop.pid (or whatever) */

  int childntoppid;        /* Zero unless we're in a child */

#ifndef WIN32
  char pidFileName[NAME_MAX];
#endif

  char *startedAs;         /* ACTUAL starting line, not the resolved one */

  int ntop_argc;           /* # of command line arguments */
  char **ntop_argv;        /* vector of command line arguments */

  /* search paths - set in globals-core.c from CFG_ constants set in ./configure */
  char **dataFileDirs;
  char **pluginDirs;
  char **configFileDirs;

  /* User-configurable parameters via the command line and the web page. */
  UserPref savedPref;         /* this is what is saved */
  UserPref runningPref;       /* this is what is currently used */
#ifndef WIN32
  char *effectiveUserName;
  int  userId, groupId;         /* 'u' */
#else
  u_char useU3;                 /* --U3 */
#endif
  char *dbPath;                 /* 'P' */
  char *spoolPath;              /* 'Q' */

  /* Other flags (these could set via command line options one day) */
  bool enableFragmentHandling;

  HostsDisplayPolicy hostsDisplayPolicy;
  LocalityDisplayPolicy localityDisplayPolicy;
  int securityItemsLoaded;
  char *securityItems[MAX_NUM_PWFILE_ENTRIES];

  /* Results flags - something we've learned */
  bool haveASN, haveVLANs;

  /* Physical and Logical network interfaces */

  u_short numDevices;      /* total network interfaces */
  NtopInterface *device;   /* pointer to the table of Network interfaces */

  /* Database */
  GDBM_FILE dnsCacheFile, pwFile, addressQueueFile, prefsFile, macPrefixFile, fingerprintFile;

  /* the table of broadcast entries */
  HostTraffic *broadcastEntry;

  /* the table of other hosts entries */
  HostTraffic *otherHostEntry;

  /* Administrative */
  char *shortDomainName;
#if defined(MAX_NUM_BAD_IP_ADDRESSES) && (MAX_NUM_BAD_IP_ADDRESSES > 0)
  BadGuysAddr weDontWantToTalkWithYou[MAX_NUM_BAD_IP_ADDRESSES];
#endif

  /* Multi-thread related */
  unsigned short numThreads;       /* # of running threads */

  ConditionalVariable queueAddressCondvar;
  PthreadMutex queueAddressMutex;

  pthread_t mainThreadId;

  /*
   * Purge database
   */
  pthread_t purgeDbThreadId;

  /*
   * HTS - Hash Purge
   */
  PthreadMutex purgeMutex;

  /*
   * HTS - Host Traffic Statistics
   */
  PthreadMutex hostsHashLockMutex;
  PthreadMutex hostsHashMutex[CONST_HASH_INITIAL_SIZE];
  volatile u_short hostsHashMutexNumLocks[CONST_HASH_INITIAL_SIZE];

  /*
   * SIH - Scan Idle Hosts - optional
   */
  pthread_t scanIdleThreadId;

  /*
   * SFP - Scan Fingerprints
   */
  pthread_t scanFingerprintsThreadId;
  time_t nextFingerprintScan;


  /*
   * DNSAR - DNS Address Resolution - optional
   */
  PthreadMutex addressResolutionMutex;
  u_int numDequeueAddressThreads;
  pthread_t dequeueAddressThreadId[MAX_NUM_DEQUEUE_ADDRESS_THREADS];

  /*
   * Control mutexes
   */
  PthreadMutex gdbmMutex;
  PthreadMutex tcpSessionsMutex;
  PthreadMutex fcSessionsMutex;
  PthreadMutex purgePortsMutex;
  PthreadMutex securityItemsMutex;
#ifdef FORPRENPTL
  PthreadMutex preNPTLlogMutex;
#endif

  pthread_t handleWebConnectionsThreadId;

  /* SSL support */

#ifdef HAVE_OPENSSL
  int sslInitialized;

  SSL_CTX* ctx;
  SSL_connection ssl[MAX_SSL_CONNECTIONS];

#ifdef MAKE_WITH_SSLWATCHDOG
  /* sslwatchdog stuff... */
  ConditionalVariable sslwatchdogCondvar;
  pthread_t sslwatchdogChildThreadId;
#endif

#endif /* HAVE_OPENSSL */

  /* ntop state - see flags in globals-defines.h */
  short ntopRunState;

  u_char resetHashNow;       /* used for hash reset */

  /* Filter Chains */
  FlowFilterList *flowsList;

  /* Address Resolution */
  u_long dnsSniffCount,
    dnsSniffRequestCount,
    dnsSniffFailedCount,
    dnsSniffARPACount,
    dnsSniffStoredInCache;

  u_long addressQueuedCount;
  u_int addressQueuedDup, addressQueuedCurrent, addressQueuedMax;

  /*
   *  We count calls to ipaddr2str()
   *       {numipaddr2strCalls}
   *    These are/are not resolved from cache.
   *       {numFetchAddressFromCacheCalls}
   *       {numFetchAddressFromCacheCallsOK}
   *       {numFetchAddressFromCacheCallsFAIL}
   *       {numFetchAddressFromCacheCallsSTALE}
   *    Unfetched end up in resolveAddress() directly or via the queue if we have ASYNC
   *       {numResolveAddressCalls}
   *    In resolveAddress(), we have
   *       {numResolveNoCacheDB} - i.e. ntop is shutting down
   *    Otherwise we look it up (again) in the database
   *       {numResolveCacheDBLookups}
   *       {numResolvedFromCache} - these were basically sniffed while in queue!
   *
   *    Gives calls to the dns resolver:
   *       {numResolvedFromHostAddresses} - /etc/hosts file (if we use it)
   */
  u_long numipaddr2strCalls,
    numFetchAddressFromCacheCalls,
    numFetchAddressFromCacheCallsOK,
    numFetchAddressFromCacheCallsFAIL,
    numFetchAddressFromCacheCallsSTALE,
    numResolveAddressCalls,
    numResolveNoCacheDB,
    numResolveCacheDBLookups,
    numResolvedFromCache,
    dnsCacheStoredLookup,
    numAttemptingResolutionWithDNS,
    numResolvedWithDNSAddresses,
    numDNSErrorHostNotFound,
    numDNSErrorNoData,
    numDNSErrorNoRecovery,
    numDNSErrorTryAgain,
    numDNSErrorOther,
    numKeptNumericAddresses;
#ifdef PARM_USE_HOST
  u_long  numResolvedFromHostAddresses;
#endif

  /* Misc */
  char *separator;         /* html separator */
  volatile unsigned long numHandledSIGPIPEerrors;
  u_short checkVersionStatus;
  time_t checkVersionStatusAgain;

  /* Purge */
  Counter numPurgedHosts, numTerminatedSessions;

  /* Time */
  int32_t thisZone;        /* seconds offset from gmt to local time */
  time_t actTime, initialSniffTime, lastRefreshTime;
  struct timeval lastPktTime;

  /* Monitored Protocols */
  int numActServices;                /* # of protocols being monitored (as stated by the protocol file) */
  ServiceEntry **udpSvc, **tcpSvc;   /* the pointers to the tables of TCP/UDP Protocols to monitor */

  u_short numIpProtosToMonitor;
  char **ipTrafficProtosNames;

  /* Protocols */
  u_short numIpProtosList;
  ProtocolsList *ipProtosList;

  u_short numFcProtosToMonitor;

  /* IP Ports */
  PortProtoMapperHandler ipPortMapper;

  /* Packet Capture */
  Counter receivedPackets, receivedPacketsProcessed, receivedPacketsQueued, receivedPacketsLostQ;

  TransactionTime transTimeHash[CONST_NUM_TRANSACTION_ENTRIES];

  u_char dummyEthAddress[LEN_ETHERNET_ADDRESS];
  u_short *mtuSize, *headerSize;

  /* (Pseudo) Local Networks */
  u_int32_t localNetworks[MAX_NUM_NETWORKS][4]; /* [0]=network, [1]=mask, [2]=broadcast, [3]=mask_v6 */
  u_short numLocalNetworks;

  /* All known Networks */
  u_int32_t knownSubnets[MAX_NUM_NETWORKS][4]; /* [0]=network, [1]=mask, [2]=broadcast, [3]=mask_v6 */
  u_short numKnownSubnets;

#if defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 3)
  size_t allocatedMemory;
#endif

  u_int ipTrafficMatrixMemoryUsage;
  u_int fcTrafficMatrixMemoryUsage;
  u_char webInterfaceDisabled;
  int enableIdleHosts;   /* Purging of idle hosts support enabled by default */
  int actualReportDeviceId;
  short columnSort, reportKind, sortFilter;
  int sock, newSock;
#ifdef HAVE_OPENSSL
  int sock_ssl;
#endif

  int numChildren;

  /* rrd */
  char *rrdPath;
  mode_t rrdDirectoryPermissions, rrdUmask;

  /* http.c */
  FILE *accessLogFd;
  unsigned long numHandledRequests[2];
  unsigned long numHandledBadrequests[2];
  unsigned long numSuccessfulRequests[2];
  unsigned long numUnsuccessfulInvalidrequests[2];
  unsigned long numUnsuccessfulInvalidmethod[2];
  unsigned long numUnsuccessfulInvalidversion[2];
  unsigned long numUnsuccessfulTimeout[2];
  unsigned long numUnsuccessfulNotfound[2];
  unsigned long numUnsuccessfulDenied[2];
  unsigned long numUnsuccessfulForbidden[2];
#ifdef MAKE_WITH_SSLWATCHDOG
  unsigned long numHTTPSrequestTimeouts;
#endif
  unsigned long numSSIRequests,
                numBadSSIRequests,
                numHandledSSIRequests;
  u_short webServerRequestQueueLength;

  /* Memory cache */
  HostTraffic *hostsCache[MAX_HOSTS_CACHE_LEN];
  u_short      hostsCacheLen, hostsCacheLenMax;
  int          hostsCacheReused;

#ifdef PARM_USE_SESSIONS_CACHE
  IPSession   *sessionsCache[MAX_SESSIONS_CACHE_LEN];
  FCSession   *fcSessionsCache[MAX_SESSIONS_CACHE_LEN];
  u_short      sessionsCacheLen, sessionsCacheLenMax;
  int          sessionsCacheReused;
#endif

  /* Peer2Peer Protocol Indexes */
  u_short GnutellaIdx, KazaaIdx, WinMXIdx, DirectConnectIdx, FTPIdx, EdonkeyIdx, BitTorrentIdx, VoipIdx;

  /* Hash table collisions - counted during load */
  int ipxsapHashLoadCollisions;
  /* Hash table sizes - counted during load */
  int ipxsapHashLoadSize;
  /* Hash table collisions - counted during use */
  int hashCollisionsLookup;

  /* Vendor lookup file */
  int numVendorLookupRead,
    numVendorLookupAdded,
    numVendorLookupAddedSpecial,
    numVendorLookupCalls,
    numVendorLookupSpecialCalls,
    numVendorLookupFound48bit,
    numVendorLookupFound24bit,
    numVendorLookupFoundMulticast,
    numVendorLookupFoundLAA;

  /* i18n */
#ifdef MAKE_WITH_I18N
  char *defaultLanguage;
  int  maxSupportedLanguages;
  char *supportedLanguages[MAX_LANGUAGES_SUPPORTED];
  char *strftimeFormat[MAX_LANGUAGES_SUPPORTED];
#endif

  /* Country flags */
  IPNode *countryFlagHead;
  int  ipCountryMem, ipCountryCount;

  /* AS */
  IPNode *asHead;
  int    asMem, asCount;

  /* Memory usage */
  int piMem, ippmtmMem;

  /* LogView */
  char ** logView;         /* vector of log messages */
  int logViewNext;
  PthreadMutex logViewMutex;

  /* SCSI */
  char scsiDefaultDevType;
  char displayOption;
  FcNameServerCacheEntry **fcnsCacheHash;
  u_int32_t fcMatrixHashCollisions, fcMatrixHashUnresCollisions;

  int multipleVLANedHostCount;

#ifdef MAX_PROCESS_BUFFER
  float queueBuffer[MAX_PROCESS_BUFFER],
        processBuffer[MAX_PROCESS_BUFFER];
  int queueBufferInit,
      queueBufferCount,
      processBufferInit,
      processBufferCount;
  float qmaxDelay,
        pmaxDelay;
#endif

#ifdef PARM_ENABLE_EXPERIMENTAL
  u_short experimentalFlagSet;  /* Is the 'experimental' flag set? */
#endif

} NtopGlobals;

