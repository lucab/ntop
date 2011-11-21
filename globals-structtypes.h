/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 *         Copyright (C) 1998-2011 Luca Deri <deri@ntop.org>
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
#if !defined(HAVE_u_int8_T)
typedef u_char  u_int8_t;
#endif
#if !defined(HAVE_u_int16_T)
typedef u_short u_int16_t;
#endif
#if !defined(HAVE_u_int32_T)
typedef u_int   u_int32_t;
#endif
#endif /* WIN32 */

#if !defined(HAVE_U_INT64_T)
#if defined(WIN32)
/* typedef _int64 u_int64_t; */
#else
#if defined(HAVE_u_int64_T)
#define u_int64_t u_int64_t
#else
#if defined(HAVE_UINT64_T)
#define u_int64_t uint64_t
#else
#error "Sorry, I'm unable to define u_int64_t on your platform"
#endif
#endif
#endif
#endif

#if !defined(HAVE_U_INT32_T)
#if defined(HAVE_UINT32_T)
#define u_int32_t uint32_t
#else
typedef unsigned int u_int32_t;
#endif
#endif

#if !defined(HAVE_U_INT16_T)
#if defined(HAVE_UINT16_T)
#define u_int16_t uint16_t
#else
typedef unsigned short u_int16_t;
#endif
#endif

#if !defined(HAVE_U_INT8_T)
#if defined(HAVE_UINT8_T)
#define u_int8_t uint8_t
#else
typedef unsigned char u_int8_t;
#endif
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

#ifndef bool
#define bool u_int8_t
#endif

typedef struct ether80211q {
  u_int16_t vlanId;
  u_int16_t protoType;
} Ether80211q;

/* PPPoE - Courtesy of Andreas Pfaller Feb2003 */
#ifdef HAVE_LINUX_IF_PPPOX_H
#include <linux/if_pppox.h>
#else
/* Extracted and modified from the Linux header for other systems - BMS Mar2003 */
/* And for Linux systems without if_pppox.h - BMS Apr2003 */
struct pppoe_tag {
  u_int16_t tag_type;
  u_int16_t tag_len;
  char tag_data;
};

struct pppoe_hdr {
#ifdef CFG_LITTLE_ENDIAN
  u_int8_t ver : 4;
  u_int8_t type : 4;
#else
  u_int8_t type : 4;
  u_int8_t ver : 4;
#endif
  u_int8_t code;
  u_int16_t sid;
  u_int16_t length;
  struct pppoe_tag tag;
};
#endif

typedef struct _mac_t {
    u_int8_t mact_octet[6];
} mac_t;

typedef struct hostAddr {
  u_int    hostFamily; /* AF_INET AF_INET6 */
  union {
    struct in_addr  _hostIp4Address;
    struct in6_addr _hostIp6Address;
  } addr;
} HostAddr;

#define Ip4Address addr._hostIp4Address

#define Ip6Address addr._hostIp6Address
#define SIZEOF_HOSTSERIAL    8

#define UNKNOWN_SERIAL_INDEX 0

#define SERIAL_NONE          0
#define SERIAL_MAC           1
#define SERIAL_IPV4          2
#define SERIAL_IPV6          3 

typedef struct _ethSerial {
  u_char  ethAddress[LEN_ETHERNET_ADDRESS];
  u_int16_t vlanId;
} EthSerial;

typedef struct _ipSerial {
  HostAddr ipAddress;
  u_int16_t  vlanId;
} IpSerial;

typedef struct hostSerial {
  u_int8_t serialType;     /* 0 == empty */
  union {
    EthSerial ethSerial; /* hostSerial == SERIAL_MAC */
    IpSerial  ipSerial;  /* hostSerial == SERIAL_IPV4/SERIAL_IPV6 */
  } value;
} HostSerial;

typedef u_int32_t HostSerialIndex;

typedef struct {
  time_t dump_date;
  HostSerialIndex idx;
} HostSerialIndexDump;

typedef struct {
  time_t dump_date;
  HostSerial serial;
} HostSerialDump;

/*
  extern int emptySerial(HostSerialIndex *a);
  extern int cmpSerial(HostSerialIndex *a, HostSerialIndex *b);
  extern int copySerial(HostSerialIndex *a, HostSerialIndex *b);
*/
#define emptySerial(a)    (*a == UNKNOWN_SERIAL_INDEX)
#define cmpSerial(a, b)   (*a == *b)
#define copySerial(a, b)  { *a = *b; }
#define setEmptySerial(a) { *a = UNKNOWN_SERIAL_INDEX; }

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

#ifndef HAVE_RW_LOCK
#ifndef WIN32
#define pthread_rwlock_t         pthread_mutex_t
#define pthread_rwlock_init      pthread_mutex_init
#define pthread_rwlock_wrlock    pthread_mutex_lock
#define pthread_rwlock_unlock    pthread_mutex_unlock
#define pthread_rwlock_destroy   pthread_mutex_destroy
#ifdef SOLARIS
#define pthread_rwlock_trywrlock pthread_mutex_trylock
#else /* SOLARIS */
#define pthread_rwlock_trywrlock pthread_mutex_trywrlock
#endif /* SOLARIS */
#endif
#endif

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
#define pthread_rwlock_t       HANDLE

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
  u_int8_t isInitialized;

#ifdef MUTEX_DEBUG
  pthread_mutex_t mutex, statedatamutex;
  u_int8_t isLocked;
  u_int  numLocks, numReleases;
  Holder attempt, lock, unlock, max;
  float  maxLockedDuration;
#else
  pthread_rwlock_t mutex;
#endif
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

/* ******************************** */

inline static void incrementTrafficCounter(TrafficCounter *ctr, Counter value) { if(value > 0) ctr->value += value, ctr->modified = 1; }
inline static void resetTrafficCounter(TrafficCounter *ctr) { ctr->value = 0, ctr->modified = 0; }

/* ************* Types Definition ********************* */

typedef struct thptEntry {
  float trafficValue;
  /* ****** */
  HostSerialIndex topHostSentSerial, secondHostSentSerial, thirdHostSentSerial;
  TrafficCounter topSentTraffic, secondSentTraffic, thirdSentTraffic;
  /* ****** */
  HostSerialIndex topHostRcvdSerial, secondHostRcvdSerial, thirdHostRcvdSerial;
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
  TrafficCounter tooLong;
} PacketStats;

/* *********************** */

typedef struct ttlStats {
  TrafficCounter upTo32, upTo64, upTo96;
  TrafficCounter upTo128, upTo160, upTo192, upTo224, upTo255;
} TTLstats;

/* *********************** */

typedef struct simpleProtoTrafficInfo {
  TrafficCounter local, local2remote, remote, remote2local; /* Bytes */
  TrafficCounter totalFlows;
} SimpleProtoTrafficInfo;

/* *********************** */

typedef struct usageCounter {
  TrafficCounter value;
  HostSerialIndex peersSerials[MAX_NUM_CONTACTED_PEERS]; /* host serial */
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

/* *********************** */

typedef struct sapType {
  u_char dsap, ssap;
} SapType;
\
/* *********************** */

typedef struct unknownProto {
  u_char protoType; /* 0=notUsed, 1=Ethernet, 2=SAP, 3=IP */
  union {
    u_int16_t ethType;
    SapType   sapType;
    u_int16_t ipType;
  } proto;
} UnknownProto;

/* *********************** */

typedef struct nonIPTraffic {
  /* NetBIOS */
  char             nbNodeType, *nbHostName, *nbAccountName, *nbDomainName, *nbDescr;

  /* Non IP */
  TrafficCounter   stpSent, stpRcvd; /* Spanning Tree */
  TrafficCounter   dlcSent, dlcRcvd;
  TrafficCounter   arp_rarpSent, arp_rarpRcvd;
  TrafficCounter   arpReqPktsSent, arpReplyPktsSent, arpReplyPktsRcvd;
  TrafficCounter   netbiosSent, netbiosRcvd;
  TrafficCounter   otherSent, otherRcvd; /* Other traffic we cannot classify */
  UnknownProto     *unknownProtoSent, *unknownProtoRcvd; /* List of MAX_NUM_UNKNOWN_PROTOS elements */
} NonIPTraffic;

/* *********************** */

typedef struct trafficDistribution {
  TrafficCounter lastCounterBytesSent, last24HoursBytesSent[25], lastDayBytesSent;
  TrafficCounter lastCounterBytesRcvd, last24HoursBytesRcvd[25], lastDayBytesRcvd;
} TrafficDistribution;

/* *********************** */

typedef struct portUsage {
  u_short         port, clientUses, serverUses;
  HostSerialIndex clientUsesLastPeer, serverUsesLastPeer;
  TrafficCounter clientTraffic, serverTraffic;
  struct portUsage *next;
} PortUsage;

/* *********************** */

typedef struct hostTalker {
  HostSerialIndex hostSerial;
  float bps /* bytes/sec */;
} HostTalker;

/* *********************** */

typedef struct hostTalkerSeries {
  HostSerialIndex hostSerial;
  float total_bps /* bytes/sec */;
  float bps_series[60 /* 1 x minute */];
} HostTalkerSeries;

/* *********************** */

typedef struct topTalkers {
  time_t when;
  HostTalker senders[MAX_NUM_TOP_TALKERS], receivers[MAX_NUM_TOP_TALKERS];
} TopTalkers;

/* *********************** */

typedef struct virtualHostList {
  char *virtualHostName;
  TrafficCounter bytesSent, bytesRcvd; /* ... by the virtual host */
  struct virtualHostList *next;
} VirtualHostList;

/* *********************** */

typedef struct userList {
  char *userName;
  fd_set userFlags;
  struct userList *next;
} UserList;

/* *********************** */

typedef struct fileList {
  pcap_t *pcapPtr;
  char *fileName;
  fd_set fileFlags;
  struct fileList *next;
} FileList;

/* *********************** */

typedef struct storedAddress {
  char   symAddress[MAX_LEN_SYM_HOST_NAME];
  time_t recordCreationTime;
  short  symAddressType;
  char   pad; /* Quiet valgrind */
} StoredAddress;

/* *********************** */

typedef struct macInfo {
  u_char isSpecial;
  char   vendorName[MAX_LEN_VENDOR_NAME];
} MACInfo;

/* *********************** */

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

/* *********************** */

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

/* *********************** */

typedef struct icmpHostInfo {
  TrafficCounter icmpMsgSent[ICMP6_MAXTYPE+1];
  TrafficCounter icmpMsgRcvd[ICMP6_MAXTYPE+1];
  time_t        lastUpdated;
} IcmpHostInfo;

/* *********************** */

typedef struct protocolInfo {
  /* HTTP */
  VirtualHostList *httpVirtualHosts;
  /* POP3/SMTP... */
  UserList *userList;

  ServiceStats     *dnsStats, *httpStats;
  DHCPStats        *dhcpStats;
} ProtocolInfo;

/* *********************** */

typedef struct shortProtoTrafficInfo {
  TrafficCounter sent, rcvd; /* Bytes */
} ShortProtoTrafficInfo;

/* *********************** */

typedef struct protoTrafficInfo {
  TrafficCounter sentLoc, sentRem;
  TrafficCounter rcvdLoc, rcvdFromRem;
  TrafficCounter pktSent, pktRcvd;
  TrafficCounter totalFlows;
} ProtoTrafficInfo;

/* *********************** */

#define MAX_NUM_NON_IP_PROTO_TRAFFIC_INFO   8

typedef struct nonIpProtoTrafficInfo {
  u_int16_t protocolId;
  TrafficCounter sentBytes, rcvdBytes;
  TrafficCounter sentPkts, rcvdPkts;
  struct nonIpProtoTrafficInfo *next;
} NonIpProtoTrafficInfo;

/* **************************** */

typedef struct networkDelay {
  struct timeval last_update;
  u_long min_nw_delay, max_nw_delay;
  u_int num_samples;
  double total_delay;
  u_int16_t peer_port;
  HostSerialIndex last_peer;
} NetworkDelay;

/* **************************** */

typedef struct {
  Counter bytesSent, bytesRcvd;
} ProtoTraffic;

#define hostIp4Address hostIpAddress.Ip4Address
#define hostIp6Address hostIpAddress.Ip6Address

/* Host Traffic */
typedef struct hostTraffic {
  u_int8_t         to_be_deleted; /* 1 = the host will be deleted in the next purge loop */
  u_short          magic;
  u_int8_t         l2Host;    /* 1 = Ethernet, 0 = IP and above */
  u_int            hostTrafficBucket; /* Index in the **hash_hostTraffic list */
  u_short          refCount;         /* Reference counter */
  HostSerial       hostSerial;
  HostSerialIndex  serialHostIndex;  /* Stored in myGlobals.serialFile and valid until ntop restart */
  HostAddr         hostIpAddress;
  u_int16_t        vlanId;          /* VLAN Id (-1 if not set) */
  u_int16_t        ifId;            /* Interface Id [e.g. for NetFlow] (-1 if not set) */
  u_int16_t        hostAS;          /* AS to which the host belongs to */
  char             *hostASDescr;    /* Description of the host AS */
  time_t           firstSeen, lastSeen; /* time when this host has sent/rcvd some data  */
  u_char           ethAddress[LEN_ETHERNET_ADDRESS];
  u_char           lastEthAddress[LEN_ETHERNET_ADDRESS]; /* used for remote addresses */
  char             ethAddressString[LEN_ETHERNET_ADDRESS_DISPLAY];
  char             hostNumIpAddress[20] /* xxx.xxx.xxx.xxx */, *dnsDomainValue, *dnsTLDValue;
  u_int8_t         network_mask;    /* IPv6 notation e.g. /24 */
  int8_t           known_subnet_id; /* UNKNOWN_SUBNET_ID if the host does not belong to a known subnet */
  char             *hwModel, *description, *community, *fingerprint;
  char             hostResolvedName[MAX_LEN_SYM_HOST_NAME];
  short            hostResolvedNameType;
  u_short          minTTL, maxTTL; /* IP TTL (Time-To-Live) */
  struct timeval   minLatency, maxLatency;
  GeoIPRecord      *geo_ip;

  TrafficCounter   greSent, greRcvd, grePktSent, grePktRcvd, lastGrePktSent, lastGrePktRcvd;
  TrafficCounter   ipsecSent, ipsecRcvd, ipsecPktSent, ipsecPktRcvd, lastIpsecPktSent, lastIpsecPktRcvd;

  /* Sketches */
  CM_type          *sent_to_matrix, *recv_from_matrix;

  NonIPTraffic     *nonIPTraffic;
  NonIpProtoTrafficInfo *nonIpProtoTrafficInfos; /* Info about further non IP protos */

  fd_set           flags;
  TrafficCounter   pktsSent, pktsRcvd, pktsSentSession, pktsRcvdSession;
  TrafficCounter   pktsDuplicatedAckSent, pktsDuplicatedAckRcvd;
  TrafficCounter   pktsBroadcastSent, bytesBroadcastSent;
  TrafficCounter   pktsMulticastSent, bytesMulticastSent;
  TrafficCounter   pktsMulticastRcvd, bytesMulticastRcvd;
  TrafficCounter   lastBytesSent, lastHourBytesSent;
  TrafficCounter   bytesSent, bytesSentLoc, bytesSentRem, bytesSentSession;
  TrafficCounter   lastBytesRcvd, lastHourBytesRcvd, bytesRcvd;
  TrafficCounter   bytesRcvdLoc, bytesRcvdFromRem, bytesRcvdSession;
  float            actualRcvdThpt, lastHourRcvdThpt, averageRcvdThpt, peakRcvdThpt;
  float            actualSentThpt, lastHourSentThpt, averageSentThpt, peakSentThpt;
  float            actualThpt, averageThpt /* REMOVE */, peakThpt;
  unsigned short   actBandwidthUsage, actBandwidthUsageS, actBandwidthUsageR;
  TrafficDistribution *trafficDistribution;
  u_int32_t        numHostSessions;

  /* Routing */
  RoutingCounter   *routedTraffic;

  /* IP */
  PortUsage        *portsUsage; /* 0...MAX_ASSIGNED_IP_PORTS */

  /* NetworkDelay Stats */
  NetworkDelay *clientDelay /* 0..MAX_NUM_NET_DELAY_STATS-1 */, *serverDelay /* 0 ..MAX_NUM_NET_DELAY_STATS-1 */;

  /* Don't change the recentl... to unsigned ! */
  int              recentlyUsedClientPorts[MAX_NUM_RECENT_PORTS], recentlyUsedServerPorts[MAX_NUM_RECENT_PORTS];
  int              otherIpPortsRcvd[MAX_NUM_RECENT_PORTS], otherIpPortsSent[MAX_NUM_RECENT_PORTS];
  TrafficCounter   ipv4BytesSent, ipv4BytesRcvd, ipv6BytesSent, ipv6BytesRcvd;
  TrafficCounter   tcpSentLoc, tcpSentRem, udpSentLoc, udpSentRem, icmpSent,icmp6Sent;
  TrafficCounter   tcpRcvdLoc, tcpRcvdFromRem, udpRcvdLoc, udpRcvdFromRem, icmpRcvd, icmp6Rcvd;

  TrafficCounter   tcpFragmentsSent,  tcpFragmentsRcvd, udpFragmentsSent, udpFragmentsRcvd,
    icmpFragmentsSent, icmpFragmentsRcvd, icmp6FragmentsSent, icmp6FragmentsRcvd;

  /* Protocol decoders */
  ProtocolInfo     *protocolInfo;

  /* Interesting Packets */
  SecurityHostProbes *secHostPkts;
  IcmpHostInfo       *icmpInfo;

  ShortProtoTrafficInfo **ipProtosList;        /* List of myGlobals.numIpProtosList entries */
  Counter                 totContactedSentPeers, totContactedRcvdPeers; /* # of different contacted peers */
  struct hostTraffic *next;              /* pointer to the next element */

  struct {
    ProtoTraffic *traffic;
  } l7;
} HostTraffic;

/* **************************** */

typedef struct domainStats {
  HostTraffic *domainHost; /* ptr to a host that belongs to the domain */
  char *communityName;
  int8_t known_subnet_id;
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
  u_int8_t proto;                   /* IPPROTO_TCP / IPPROTO_UDP                  */
  u_char isP2P;                     /* Set to 1 if this is a P2P session          */
  u_int8_t knownProtocolIdx;        /* Mark this as a special protocol session    */
  HostTraffic* initiator;           /* initiator address                          */
  HostAddr initiatorRealIp;         /* Real IP address (if masqueraded and known) */
  u_short sport;                    /* initiator address (port)                   */
  HostTraffic *remotePeer;          /* remote peer address                        */
  HostAddr remotePeerRealIp;        /* Real IP address (if masqueraded and known) */
  char *virtualPeerName;            /* Name of a virtual host (e.g. HTTP virtual host) */
  u_short dport;                    /* remote peer address (port)               */
  time_t firstSeen;                 /* time when the session has been initiated */
  time_t lastSeen;                  /* time when the session has been closed    */
  u_long pktSent, pktRcvd;
  TrafficCounter bytesSent;         /* # bytes sent (initiator -> peer) [IP]    */
  TrafficCounter bytesRcvd;         /* # bytes rcvd (peer -> initiator)[IP]     */
  TrafficCounter bytesProtoSent;    /* # bytes sent (Protocol [e.g. HTTP])      */
  TrafficCounter bytesProtoRcvd;    /* # bytes rcvd (Protocol [e.g. HTTP])      */
  u_int minWindow, maxWindow;       /* TCP window size                          */
  struct timeval synTime, synAckTime, ackTime; /* Used to calcolate nw delay */
  struct timeval clientNwDelay, serverNwDelay; /* Network Delay/Latency         */
  u_short numFin;                   /* # FIN pkts rcvd                          */
  u_short numFinAcked;              /* # ACK pkts rcvd                          */
  u_int32_t lastAckIdI2R;           /* ID of the last ACK rcvd                  */
  u_int32_t lastAckIdR2I;           /* ID of the last ACK rcvd                  */
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
  struct {
    u_int16_t major_proto;
    struct ipoque_flow_struct *flow;
    struct ipoque_id_struct *src, *dst;
  } l7;
} IPSession;

/* ************************************* */

typedef struct ntopIfaceAddrInet {
  struct in_addr ifAddr;
  struct in_addr network;
  struct in_addr netmask;
} NtopIfaceAddrInet;

typedef struct ntopIfaceAddrInet6 {
  struct in6_addr ifAddr;
  int             prefixlen;
} NtopIfaceAddrInet6;

typedef struct ntopIfaceaddr{
  int family;
  struct ntopIfaceaddr *next;
  union {
    NtopIfaceAddrInet  inet;
    NtopIfaceAddrInet6 inet6;
  } af;
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

typedef enum {
  noDnsResolution = 0,
  dnsResolutionForLocalHostsOnly = 1,
  dnsResolutionForLocalRemoteOnly = 2,
  dnsResolutionForAll = 3
} DnsResolutionMode;

typedef struct probeInfo {
  struct in_addr probeAddr;
  u_int16_t probePort;
  u_int32_t      pkts;
  u_int32_t lastSequenceNumber, lowestSequenceNumber, highestSequenceNumber, totNumFlows;
  u_int32_t lostFlows;
} ProbeInfo;

/* Flow aggregation */
typedef enum {
  hostCreation = 1,
  hostDeletion = 1 << 2,
  sessionCreation = 1 << 3,
  sessionDeletion = 1 << 4,
  hostFlagged = 1 << 5,
  hostUnflagged  = 1 << 6
} EventType;

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

typedef struct flow_set {
  u_int16_t templateId;
  u_int16_t fieldCount;
} FlowSet;

typedef struct flow_ipfix_template_field {
  u_int16_t fieldType;
  u_int16_t fieldLen;
  u_int8_t  isPenField;
} V9V10TemplateField;

typedef struct flow_ver9_hdr {
  u_int16_t version;         /* Current version=9 */
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int32_t sourceId;        /* Source id */
} V9FlowHeader;

typedef struct flow_ipfix_hdr {
  u_int16_t version;         /* Current version=10 */
  u_int16_t length;          /* The flow length (bytes) */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int32_t domainId;        /* Observation domain id */
} IPFIXFlowHeader;

typedef struct flow_ver9_template_field {
  u_int16_t fieldType;
  u_int16_t fieldLen;
} V9TemplateField;

typedef struct flow_ver9_template_header {
  u_int16_t templateFlowset; /* = 0 */
  u_int16_t flowsetLen;
} V9TemplateHeader;

typedef struct flow_ver9_template_def {
  u_int16_t templateId;
  u_int16_t fieldCount;
} V9TemplateDef;

typedef struct flow_ver9_template {
  /* V9TemplateHeader */
  u_int16_t flowsetLen;
  /* V9TemplateDef */
  u_int16_t templateId;
  u_int16_t fieldCount;
} V9SimpleTemplate;

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
  V9SimpleTemplate templateInfo;
  u_int16_t flowLen; /* Real flow length */
  V9V10TemplateField *fields;
  struct flowSetV9 *next;
} FlowSetV9;

typedef struct interfaceStats {
  u_int32_t netflow_device_ip;
  u_int16_t netflow_device_port;
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

typedef struct {
  u_int32_t address[4]; /* [0]=network, [1]=mask, [2]=broadcast, [3]=mask_v6 */    
} NetworkStats;

#define MAX_INTERFACE_STATS_QUEUE_LEN  32

typedef struct optionTemplate {
  u_int16_t templateId;
  struct optionTemplate *next;
} OptionTemplate;

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
  u_char enableSessionHandling;
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
  u_long numNetFlowsV9TemplRcvd, numNetFlowsV9BadTemplRcvd, numNetFlowsV9UnknTemplRcvd,
    numNetFlowsV9OptionFlowsRcvd;

  /* Stats */
  ProbeInfo probeList[MAX_NUM_PROBES];
  InterfaceStats *ifStats;
  NetworkStats whiteNetworks[MAX_NUM_NETWORKS], blackNetworks[MAX_NUM_NETWORKS];
  u_short numWhiteNets, numBlackNets;
  u_int32_t flowProcessed;
  Counter flowProcessedBytes;
  HostTraffic *dummyHost;
  FlowSetV9 *templates;
  OptionTemplate *optionTemplates;

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

typedef struct cpacket_counter {
  char *name;
  u_long bytes, packets;
  struct cpacket_counter *next;
} cPacketCounter;

typedef struct cpacket_globals {
  u_char cpacketDebug;

  /* Flow reception */
  int cpacketInSocket, cpacketDeviceId;
  u_short cpacketInPort;
  u_long numPktsRcvd;

  /* Stats */
  ProbeInfo deviceList[MAX_NUM_PROBES];
  u_int32_t statsProcessed;
  
  /* Counters */
  cPacketCounter *counter_list_head, *last_head;

  pthread_t cpacketThread;
  int threadActive;
} cPacketGlobals;

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
  NetworkStats whiteNetworks[MAX_NUM_NETWORKS], blackNetworks[MAX_NUM_NETWORKS];
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

typedef struct {
  u_int  hostsno;        /* # of valid entries in the following table */
  u_int  actualHashSize;
  struct hostTraffic **hash_hostTraffic;
  u_short hashListMaxLookups;
} HostsHashInfo;

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

  PthreadMutex asMutex, counterMutex;
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

  /*
   * The bytes section
   */
  TrafficCounter ethernetBytes;  /* # bytes captured */
  TrafficCounter ipv4Bytes;
  TrafficCounter fragmentedIpBytes;
  TrafficCounter tcpBytes;
  TrafficCounter udpBytes;
  TrafficCounter otherIpBytes;

  TrafficCounter icmpBytes;
  TrafficCounter dlcBytes;
  TrafficCounter ipxBytes;
  TrafficCounter stpBytes;        /* Spanning Tree */
  TrafficCounter ipsecBytes;
  TrafficCounter netbiosBytes;
  TrafficCounter arpRarpBytes;
  TrafficCounter egpBytes;
  TrafficCounter greBytes;
  TrafficCounter ipv6Bytes;
  TrafficCounter icmp6Bytes;
  TrafficCounter otherBytes;
  TrafficCounter *ipProtosList;        /* List of myGlobals.numIpProtosList entries */

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
  TTLstats    rcvdPktTTLStats;

  float peakThroughput, actualThpt, lastMinThpt, lastFiveMinsThpt;
  float peakPacketThroughput, actualPktsThpt, lastMinPktsThpt, lastFiveMinsPktsThpt;

  time_t lastThptUpdate, lastMinThptUpdate;
  time_t lastHourThptUpdate, lastFiveMinsThptUpdate;
  float  throughput;
  float  packetThroughput;

  unsigned long numThptSamples;
  TopTalkers last60MinTopTalkers[60], last24HoursTopTalkers[24];

  SimpleProtoTrafficInfo tcpGlobalTrafficStats, udpGlobalTrafficStats, icmpGlobalTrafficStats;
  SecurityDeviceProbes securityPkts;

  TrafficCounter numEstablishedTCPConnections; /* = # really established connections */

  pthread_t pcapDispatchThreadId;

  HostsHashInfo hosts;

  /* ************************** */

  IpFragment *fragmentList;
  IPSession **tcpSession;
  u_short numTcpSessions, maxNumTcpSessions;

  /* ************************** */

  NetFlowGlobals *netflowGlobals;  /* NetFlow */
  SflowGlobals   *sflowGlobals;    /* sFlow */
  cPacketGlobals *cpacketGlobals;  /* cPacket */

  /* ********************* */
  
  struct {
    Counter *protoTraffic;
  } l7;
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
  showPrefBasicPref = 1,
  showPrefDisplayPref,
  showPrefIPPref,
  showPrefAdvPref,
  showPrefDbgPref,
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
  char *accessLogFile;           /* -a |--access-log-file */
  bool enablePacketDecoding;     /* -b | --disable-decoders */
  bool stickyHosts;              /* -c | --sticky-hosts */
  bool daemonMode;               /* -d | --daemon */
  int  maxNumLines;              /* -e | --max-table-rows */
  bool trackOnlyLocalHosts;      /* -g | --track-local-hosts */
  char *devices;                 /* -i | --interface */
  bool enableOtherPacketDump;    /* -j | --create-other-packets */
  char *pcapLog;                 /* -l | --pcap-log */
  char *localAddresses;          /* -m | --local-subnets */
  DnsResolutionMode numericFlag; /* -n | --numeric-ip-addresses */
  char *protoSpecs;              /* -p | --protocols */
  bool enableSuspiciousPacketDump;  /* -q | --create-suspicious-packets */
  int  refreshRate;              /* -r | --refresh-time */
  bool disablePromiscuousMode;   /* -s | --no-promiscuous */
  int  traceLevel;               /* -t | --trace-level */
  char *mapperURL;               /* -U | --disable-mapper */
  u_int     maxNumHashEntries;   /* -x */
  u_int     maxNumSessions;      /* -X */
  char      *webAddr;            /* -w | --http-serveraddress[:port] */
  int       webPort;
  int       ipv4or6;             /* -6 -4 */
  bool      enableSessionHandling;  /* -z | --disable-sessions */

  char *currentFilterExpression; /* -B | --filter-expression */
  u_short samplingRate;          /* -C | --sampling-rate */
  char domainName[MAXHOSTNAMELEN];  /* -D | --domain */
  char *flowSpecs;               /* -F | --flow-spec */

  bool debugMode;                /* -K | --enable-debug */
#ifndef WIN32
  int  useSyslog;                /* -L | --use-syslog*/
#endif

  bool mergeInterfaces;          /* -M | --no-interface-merge */
  bool enableL7;                 /* Enable/disable l7 protocol pattern matching */
  char *pcapLogBasePath;         /* -O | --pcap-file-path */  /* Added by Ola Lundqvist <opal@debian.org>. */

#ifdef HAVE_OPENSSL
  char *sslAddr;                 /* -W | --https-serveraddress[:port] */
  int  sslPort;
#endif

  bool w3c;                      /* --w3c '136' */

  char *P3Pcp;                   /* --p3p-cp '137' */
  char *P3Puri;                  /* --p3p-uri '138' */

  char *instance;                /* --instance '140' */
  char *logo;
  bool disableStopcap;           /* --disable-stopcap '142' */

  bool disableMutexExtraInfo;    /* --disable-mutexextrainfo '145' */
  bool skipVersionCheck;         /* --skip-version-check '150' */
  char *knownSubnets;            /* --known-subnets '151' */
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
  struct fileList *pcap_file_list; /* --pcap-file-list */
  /* Other flags (these could set via command line options one day) */
  bool enableFragmentHandling;

  HostsDisplayPolicy hostsDisplayPolicy;
  LocalityDisplayPolicy localityDisplayPolicy;
  int securityItemsLoaded;
  char *securityItems[MAX_NUM_PWFILE_ENTRIES];

  /* Results flags - something we've learned */
  bool haveASN, haveVLANs;

  /* Physical and Logical network interfaces */
  pcap_if_t *allDevs;      /* all devices available for pcap_open */
  u_short numDevices;      /* total network interfaces */
  NtopInterface *device;   /* pointer to the network interfaces table */

  /* Database */
  GDBM_FILE pwFile, prefsFile, macPrefixFile, fingerprintFile, serialFile, topTalkersFile, resolverCacheFile;

  /* the table of broadcast entries */
  HostTraffic *broadcastEntry;

  /* the table of other hosts entries */
  HostTraffic *otherHostEntry;

  /* Host serial */
  u_int32_t hostSerialCounter;

  /* Administrative */
  char *shortDomainName;
#if defined(MAX_NUM_BAD_IP_ADDRESSES) && (MAX_NUM_BAD_IP_ADDRESSES > 0)
  BadGuysAddr weDontWantToTalkWithYou[MAX_NUM_BAD_IP_ADDRESSES];
#endif

  /* Multi-thread related */
  unsigned short numThreads;       /* # of running threads */

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

  /* Host Serial */
  PthreadMutex serialLockMutex;

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
  ConditionalVariable queueAddressCondvar;

  /*
   * Control mutexes
   */
  PthreadMutex gdbmMutex, portsMutex;
  PthreadMutex tcpSessionsMutex[NUM_SESSION_MUTEXES];
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

  u_int addressQueuedCurrent, addressQueuedMax, addressUnresolvedDrops, resolvedAddresses, failedResolvedAddresses;

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

  /* IP Ports */
  PortProtoMapperHandler ipPortMapper;

  /* Packet Capture */
  Counter receivedPackets, receivedPacketsProcessed, receivedPacketsQueued, receivedPacketsLostQ;

  TransactionTime transTimeHash[CONST_NUM_TRANSACTION_ENTRIES];

  u_char dummyEthAddress[LEN_ETHERNET_ADDRESS];
  u_short *mtuSize, *headerSize;

  /* (Pseudo) Local Networks */
  NetworkStats localNetworks[MAX_NUM_NETWORKS];
  u_short numLocalNetworks;

  /* All known Networks */
  NetworkStats subnetStats[MAX_NUM_INTERFACE_NETWORKS];
  u_short numKnownSubnets;  

#if defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 3)
  size_t allocatedMemory;
#endif

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
  char *rrdPath, *rrdVolatilePath;
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
  unsigned long numSSIRequests,
                numBadSSIRequests,
                numHandledSSIRequests;
  u_short webServerRequestQueueLength;

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

  /* Memory usage */
  int piMem, ippmtmMem;

  /* LogView */
  char ** logView;         /* vector of log messages */
  int logViewNext;
  PthreadMutex logViewMutex;

  int multipleVLANedHostCount;

#ifdef MAX_PROCESS_BUFFER
  float queueBuffer[MAX_PROCESS_BUFFER],
        processBuffer[MAX_PROCESS_BUFFER];
  int queueBufferInit,
      queueBufferCount,
      processBufferInit,
      processBufferCount;
  float qmaxDelay, pmaxDelay;
#endif

#ifdef PARM_ENABLE_EXPERIMENTAL
  u_short experimentalFlagSet;  /* Is the 'experimental' flag set? */
#endif

  /* If the traffic is divided in cells (e.g. ATM, cell payload is 47 bytes) this is the cell lenght */
  u_int16_t cellLength; 

  /* GeoIP */
  GeoIP *geo_ip_db, *geo_ip_asn_db;
  PthreadMutex geolocalizationMutex;

  /* Event Handling */
  u_int32_t event_mask;
  char *event_log;

  /* RRD */
  time_t rrdTime;
  
  /* Message display */
  u_char lowMemoryMsgShown;

  struct {
    u_short numSupportedProtocols;
    u_int16_t flow_struct_size, proto_size;
    struct ipoque_detection_module_struct *l7handler;
  } l7;
} NtopGlobals;
