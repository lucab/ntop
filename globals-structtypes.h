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
 typedef unsigned int   tcp_seq;
 typedef u_char  uint8_t;
 typedef u_short uint16_t;
 typedef u_int   uint32_t;
#endif /* WIN32 */

#if !defined(HAVE_U_INT64_T)
#if defined(WIN32) && defined(__GNUC__)
typedef unsigned long long u_int64_t; /* on mingw unsigned long is 32 bits */
#else 
#if defined(WIN32)
typedef _int64 u_int64_t;
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

typedef struct ether80211q {
  u_int16_t vlanId;
  u_int16_t protoType;
} Ether80211q;

#define HostSerial u_int64_t

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

typedef struct portMapper {
  int port;       /* Port to map */
  int mappedPort; /* Mapped port */
} PortMapper;

#ifdef CFG_MULTITHREADED

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

#endif /* WIN32 */

typedef struct pthreadMutex {
  pthread_mutex_t mutex;
  char   isLocked, isInitialized;
  char   lockFile[64];
  int    lockLine;
  pid_t  lockPid;
  char   unlockFile[64];
  int    unlockLine;
  pid_t  unlockPid;
  u_int  numLocks, numReleases;

  time_t lockTime;
  char   maxLockedDurationUnlockFile[64];
  int    maxLockedDurationUnlockLine;
  int    maxLockedDuration;

  char   where[64];
  char   lockAttemptFile[64];
  int    lockAttemptLine;
  pid_t  lockAttemptPid;
} PthreadMutex;

typedef struct packetInformation {
  unsigned short deviceId;
  struct pcap_pkthdr h;
  u_char p[2*DEFAULT_SNAPLEN+1]; /* NOTE:
                                    Remove 2* as soon as we are sure
                                    that ntop does not go beyond boundaries
                                    TODO (ASAP!) **/
} PacketInformation;

#endif /* CFG_MULTITHREADED */


typedef struct hash_list {
  u_int16_t idx;          /* Index of this entry in hostTraffic */
  struct hash_list *next;
} HashList;

#ifdef WIN32
typedef float Counter;
#else
typedef unsigned long long Counter;
#endif

typedef struct trafficCounter {
  Counter value;
  u_char modified;
} TrafficCounter;

typedef struct elementHash {
  u_short id;
  TrafficCounter bytesSent, pktsSent;
  TrafficCounter bytesRcvd, pktsRcvd;  
  struct elementHash *next;
} ElementHash;

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
  TrafficCounter upTo512, upTo1024, upTo1518, above1518;
  TrafficCounter shortest, longest;
  TrafficCounter badChecksum, tooLong;
} PacketStats;

/* *********************** */

typedef struct ttlStats {
  TrafficCounter upTo32, upTo64, upTo96;
  TrafficCounter upTo128, upTo160, upTo192, upTo224, upTo255;
} TTLstats;

/* *********************** */

typedef struct simpleProtoTrafficInfo {
  TrafficCounter local, local2remote, remote, remote2local;
  TrafficCounter lastLocal, lastLocal2remote, lastRem, lastRem2local;
} SimpleProtoTrafficInfo;

/* *********************** */

typedef struct usageCounter {
  TrafficCounter value;
  HostSerial peersIndexes[MAX_NUM_CONTACTED_PEERS]; /* host serial */
} UsageCounter;

/* *********************** */

typedef struct routingCounter {
  TrafficCounter routedPkts, routedBytes;
} RoutingCounter;

/* *********************** */

typedef struct securityHostProbes {
  UsageCounter synPktsSent, rstPktsSent, rstAckPktsSent,
               synFinPktsSent, finPushUrgPktsSent, nullPktsSent;
  UsageCounter synPktsRcvd, rstPktsRcvd, rstAckPktsRcvd,
               synFinPktsRcvd, finPushUrgPktsRcvd, nullPktsRcvd;
  UsageCounter ackScanSent, ackScanRcvd;
  UsageCounter xmasScanSent, xmasScanRcvd;
  UsageCounter finScanSent, finScanRcvd;
  UsageCounter nullScanSent, nullScanRcvd;
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
} NonIPTraffic;

typedef struct trafficDistribution {
  TrafficCounter lastCounterBytesSent, last24HoursBytesSent[25], lastDayBytesSent;
  TrafficCounter lastCounterBytesRcvd, last24HoursBytesRcvd[25], lastDayBytesRcvd;
} TrafficDistribution; 

typedef struct portUsage {
  u_short        clientUses, serverUses;
  u_int          clientUsesLastPeer, serverUsesLastPeer;
  TrafficCounter clientTraffic, serverTraffic;
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
} StoredAddress;

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

typedef struct icmpHostInfo {
  TrafficCounter icmpMsgSent[ICMP_MAXTYPE+1];
  TrafficCounter icmpMsgRcvd[ICMP_MAXTYPE+1];
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

typedef struct protoTrafficInfo {
  TrafficCounter sentLoc, sentRem;
  TrafficCounter rcvdLoc, rcvdFromRem;
} ProtoTrafficInfo;

typedef struct ipGlobalSession {
  u_short magic;
  u_short port;                    /* port (either client or server)           */
  u_char initiator;                /* FLAG_CLIENT_ROLE/FLAG_SERVER_ROLE                  */
  time_t firstSeen;                /* time when the session has been initiated */
  time_t lastSeen;                 /* time when the session has been closed    */
  u_short sessionCounter;          /* # of sessions we've observed             */
  TrafficCounter bytesSent;        /* # bytes sent     (peer -> initiator)     */
  TrafficCounter bytesRcvd;        /* # bytes rcvd (peer -> initiator)         */
  TrafficCounter bytesFragmentedSent, bytesFragmentedRcvd; /* IP Fragments     */
  UsageCounter peers;              /* session peers */
  struct ipGlobalSession  *next;   /* next element (linked list)               */
} IpGlobalSession;

/* **************************** */

/* Host Traffic */
typedef struct hostTraffic {
  u_short          hostTrafficBucket /* Index in the **hash_hostTraffic list */;
  u_short          hashListBucket    /* Index in the **hashList         list */;
  u_short          refCount;         /* Reference counter */
  HostSerial       hostSerial;
  struct in_addr   hostIpAddress;
  short            vlanId;           /* VLAN Id (-1 if not set) */
  u_int16_t        hostAS;           /* AS to which the host belongs to */
  time_t           firstSeen;
  time_t           lastSeen;     /* time when this host has sent/rcvd some data  */
  u_char           ethAddress[LEN_ETHERNET_ADDRESS];
  u_char           lastEthAddress[LEN_ETHERNET_ADDRESS]; /* used for remote addresses */
  char             ethAddressString[18];
  char             hostNumIpAddress[17], *fullDomainName;
  char             *dotDomainName, hostSymIpAddress[MAX_LEN_SYM_HOST_NAME], *osName;
  u_short          minTTL, maxTTL; /* IP TTL (Time-To-Live) */
  struct timeval   minLatency, maxLatency;

  NonIPTraffic     *nonIPTraffic;

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
  unsigned short   actBandwidthUsage;
  TrafficDistribution *trafficDistribution;

  /* Routing */
  RoutingCounter   *routedTraffic;

  /* IP */
  PortUsage        **portsUsage; /* 0...MAX_ASSIGNED_IP_PORTS */
  u_short          recentlyUsedClientPorts[MAX_NUM_RECENT_PORTS], recentlyUsedServerPorts[MAX_NUM_RECENT_PORTS];
  TrafficCounter   ipBytesSent, ipBytesRcvd;
  TrafficCounter   tcpSentLoc, tcpSentRem, udpSentLoc,
                   udpSentRem, icmpSent, ospfSent, igmpSent;
  TrafficCounter   tcpRcvdLoc, tcpRcvdFromRem, udpRcvdLoc,
                   udpRcvdFromRem, icmpRcvd, ospfRcvd, igmpRcvd;

  TrafficCounter   tcpFragmentsSent,  tcpFragmentsRcvd,
                   udpFragmentsSent,  udpFragmentsRcvd,
                   icmpFragmentsSent, icmpFragmentsRcvd;

  /* Protocol decoders */
  ProtocolInfo     *protocolInfo;

  /* Interesting Packets */
  SecurityHostProbes *secHostPkts;
  IcmpHostInfo       *icmpInfo;

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
  TrafficCounter   ipv6Sent, ipv6Rcvd;
  TrafficCounter   otherSent, otherRcvd;
  
  ProtoTrafficInfo *protoIPTrafficInfos; /* info about IP traffic generated/rcvd by this host */
  IpGlobalSession  *tcpSessionList, *udpSessionList; /* list of sessions initiated/rcvd by this host */
  Counter          totContactedSentPeers, totContactedRcvdPeers; /* # of different contacted peers */
  UsageCounter     contactedSentPeers;   /* peers that talked with this host */
  UsageCounter     contactedRcvdPeers;   /* peers that talked with this host */
  UsageCounter     contactedRouters;     /* routers contacted by this host */

  /* *************** IMPORTANT ***************

     If you add a pointer to this struct please
     go to resetHostsVariables() and
     add a NULL to each pointer you added in the
     newly resurrected.

     *************** IMPORTANT *************** */
} HostTraffic;

/* **************************** */

typedef struct domainStats {
  HostTraffic *domainHost; /* ptr to a host that belongs to the domain */
  TrafficCounter bytesSent, bytesRcvd;
  TrafficCounter tcpSent, udpSent;
  TrafficCounter icmpSent, ospfSent, igmpSent;
  TrafficCounter tcpRcvd, udpRcvd;
  TrafficCounter icmpRcvd, ospfRcvd, igmpRcvd;
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
  u_int initiatorIdx;               /* initiator address   (IP address)           */
  struct in_addr initiatorRealIp;   /* Real IP address (if masqueraded and known) */
  u_short sport;                    /* initiator address   (port)                 */
  u_int remotePeerIdx;              /* remote peer address (IP address)           */
  struct in_addr remotePeerRealIp;  /* Real IP address (if masqueraded and known) */
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
  tcp_seq lastAckIdI2R;             /* ID of the last ACK rcvd                  */
  tcp_seq lastAckIdR2I;             /* ID of the last ACK rcvd                  */
  u_short numDuplicatedAckI2R;      /* # duplicated ACKs                        */
  u_short numDuplicatedAckR2I;      /* # duplicated ACKs                        */
  TrafficCounter bytesRetranI2R;    /* # bytes retransmitted (due to duplicated ACKs) */
  TrafficCounter bytesRetranR2I;    /* # bytes retransmitted (due to duplicated ACKs) */
  tcp_seq finId[MAX_NUM_FIN];       /* ACK ids we're waiting for                */
  u_long lastFlags;                 /* flags of the last TCP packet             */
  u_int32_t lastCSAck, lastSCAck;   /* they store the last ACK ids C->S/S->C    */
  u_int32_t lastCSFin, lastSCFin;   /* they store the last FIN ids C->S/S->C    */
  u_char lastInitiator2RemFlags[MAX_NUM_STORED_FLAGS]; /* TCP flags             */
  u_char lastRem2InitiatorFlags[MAX_NUM_STORED_FLAGS]; /* TCP flags             */
  u_char sessionState;              /* actual session state                     */
  u_char  passiveFtpSession;        /* checked if this is a passive FTP session */
  struct ipSession *next;
} IPSession;

/* ************************************* */

typedef struct ntopInterface {
  char *name;                    /* unique interface name */
  char *humanFriendlyName;       /* Human friendly name of the interface (needed under WinNT and above) */
  int flags;                     /* the status of the interface as viewed by ntop */

  u_int32_t addr;                /* Internet address (four bytes notation) */
  char *ipdot;                   /* IP address (dot notation) */
  char *fqdn;                    /* FQDN (resolved for humans) */

  struct in_addr network;        /* network number associated to this interface */
  struct in_addr netmask;        /* netmask associated to this interface */
  u_int          numHosts;       /* # hosts of the subnet */
  struct in_addr ifAddr;         /* network number associated to this interface */
                                 /* local domainname */
  time_t started;                /* time the interface was enabled to look at pkts */
  time_t firstpkt;               /* time first packet was captured */
  time_t lastpkt;                /* time last packet was captured */

  pcap_t *pcapPtr;               /* LBNL pcap handler */
  pcap_dumper_t *pcapDumper;     /* LBNL pcap dumper  - enabled using the 'l' flag */
  pcap_dumper_t *pcapErrDumper;  /* LBNL pcap dumper - all suspicious packets are logged */

  char virtualDevice;            /* set to 1 for virtual devices (e.g. eth0:1) */
  char dummyDevice;              /* set to 1 for 'artificial' devices (e.g. sFlow-device) */
  int snaplen;                   /* maximum # of bytes to capture foreach pkt */
                                 /* read timeout in milliseconds */
  int datalink;                  /* data-link encapsulation type (see DLT_* in net/bph.h) */

  char *filter;                  /* user defined filter expression (if any) */

  int fd;                        /* unique identifier (Unix file descriptor) */

  FILE *fdv;                     /* verbosity file descriptor */
  int hashing;                   /* hashing while sniffing */
  int ethv;                      /* print ethernet header */
  int ipv;                       /* print IP header */
  int tcpv;                      /* print TCP header */

  /*
   * The packets section
   */
  TrafficCounter droppedPkts;    /* # of pkts dropped by the application */
  TrafficCounter ethernetPkts;   /* # of Ethernet pkts captured by the application */
  TrafficCounter broadcastPkts;  /* # of broadcast pkts captured by the application */
  TrafficCounter multicastPkts;  /* # of multicast pkts captured by the application */
  TrafficCounter ipPkts;         /* # of IP pkts captured by the application */
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
  TrafficCounter ospfBytes;
  TrafficCounter egpBytes;
  TrafficCounter igmpBytes;
  TrafficCounter osiBytes;
  TrafficCounter ipv6Bytes;
  TrafficCounter otherBytes;

  PortCounter    *ipPorts[MAX_IP_PORT];

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
  ThptEntry last60MinutesThpt[60], last24HoursThpt[24];
  float last30daysThpt[30];
  u_short last60MinutesThptIdx, last24HoursThptIdx, last30daysThptIdx;

  SimpleProtoTrafficInfo tcpGlobalTrafficStats, udpGlobalTrafficStats, icmpGlobalTrafficStats;
  SimpleProtoTrafficInfo *ipProtoStats;

  TrafficCounter numEstablishedTCPConnections; /* = # really established connections */

#ifdef CFG_MULTITHREADED
  pthread_t pcapDispatchThreadId;
#endif

  u_int  hostsno;        /* # of valid entries in the following table */
  u_int  actualHashSize, hashThreshold, topHashThreshold;
  struct hostTraffic **hash_hostTraffic;
  u_int16_t  insertIdx;
  HashList** hashList;

  ElementHash **asHash;   /* Autonomous System */
  ElementHash **vlanHash; /* VLAN - Virtual LAN */

  /* ************************** */

  IpFragment *fragmentList;
  struct ipSession **tcpSession;
  u_short numTotSessions, numTcpSessions, maxNumTcpSessions;
  TrafficEntry** ipTrafficMatrix; /* Subnet traffic Matrix */
  struct hostTraffic** ipTrafficMatrixHosts; /* Subnet traffic Matrix Hosts */
  fd_set ipTrafficMatrixPromiscHosts;

  /* ************************** */

  u_char exportNetFlow; /* NETFLOW_EXPORT_... */

} NtopInterface;

typedef struct processInfo {
  char marker; /* internal use only */
  char *command, *user;
  time_t firstSeen, lastSeen;
  int pid;
  TrafficCounter bytesSent, bytesRcvd;
  /* peers that talked with this process */
  u_int contactedIpPeersIndexes[MAX_NUM_CONTACTED_PEERS];
  u_int contactedIpPeersIdx;
} ProcessInfo;

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

typedef void(*VoidFunc)(void);
typedef void(*PluginFunc)(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p);
typedef void(*PluginHTTPFunc)(char* url);
#ifdef SESSION_PLUGIN
typedef void(*PluginSessionFunc)(IPSession *sessionToPurge, int actualDeviceId);
#endif

typedef struct pluginInfo {
  /* Plugin Info */
  char *pluginName;         /* Short plugin name (e.g. icmpPlugin) */
  char *pluginDescr;        /* Long plugin description */
  char *pluginVersion;
  char *pluginAuthor;
  char *pluginURLname;      /* Set it to NULL if the plugin doesn't speak HTTP */
  char activeByDefault;     /* Set it to 1 if this plugin is active by default */
  char inactiveSetup;       /* Set it to 1 if this plugin can be called inactive for setup */
  VoidFunc startFunc, termFunc;
  PluginFunc pluginFunc;    /* Initialize here all the plugin structs... */
  PluginHTTPFunc httpFunct; /* Set it to NULL if the plugin doesn't speak HTTP */
#ifdef SESSION_PLUGIN
  PluginSessionFunc sessionFunct; /* Set it to NULL if the plugin doesn't care of terminated sessions */
#endif
  char* bpfFilter;          /* BPF filter for selecting packets that
       		               will be routed to the plugin  */
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
  struct in_addr sessionHost;
  u_short sessionPort;
  time_t  creationTime;
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
  struct in_addr addr;
  time_t         lastBadAccess;
} BadGuysAddr;

/* *************************** */

/*
  For more info see:

  http://www.cisco.com/warp/public/cc/pd/iosw/ioft/neflct/tech/napps_wp.htm

  ftp://ftp.net.ohio-state.edu/users/maf/cisco/
*/

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
   u_int32_t First;      /* SysUptime at start of flow */
   u_int32_t Last;       /* and of last packet of the flow */
   u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
   u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
   u_int8_t pad1;        /* pad to word boundary */
   u_int8_t tcp_flags;   /* Cumulative OR of tcp flags */
   u_int8_t prot;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
   u_int8_t tos;         /* IP Type-of-Service */
   u_int16_t dst_as;     /* dst peer/origin Autonomous System */
   u_int16_t src_as;     /* source peer/origin Autonomous System */
   u_int8_t dst_mask;    /* destination route's mask bits */
   u_int8_t src_mask;    /* source route's mask bits */
   u_int16_t pad2;       /* pad to word boundary */
};

typedef struct single_flow_ver5_rec {
  struct flow_ver5_hdr flowHeader;
  struct flow_ver5_rec flowRecord[CONST_V5FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow5Record;

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
   u_int32_t First;      /* SysUptime at start of flow */
   u_int32_t Last;       /* and of last packet of the flow */
   u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
   u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
   u_int8_t flags;       /* Shortcut mode(dest only,src only,full flows*/
   u_int8_t tcp_flags;   /* Cumulative OR of tcp flags */
   u_int8_t prot;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
   u_int8_t tos;         /* IP Type-of-Service */
   u_int16_t dst_as;     /* dst peer/origin Autonomous System */
   u_int16_t src_as;     /* source peer/origin Autonomous System */
   u_int8_t dst_mask;    /* destination route's mask bits */
   u_int8_t src_mask;    /* source route's mask bits */
   u_int16_t pad2;       /* pad to word boundary */
   u_int32_t router_sc;  /* Router which is shortcut by switch */
};

typedef struct single_flow_ver7_rec {
  struct flow_ver7_hdr flowHeader;
  struct flow_ver7_rec flowRecord[CONST_V7FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow7Record;

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

/* ******************************** */

typedef struct serialCacheEntry {
  char isMAC;
  char data[17];
  u_long creationTime;
} SerialCacheEntry;

typedef struct probeInfo {
  struct in_addr probeAddr;
  u_int32_t      pkts;
} ProbeInfo;


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

/*

    Declaration of POSIX directory browsing functions and types for Win32.

    Kevlin Henney (mailto:kevlin@acm.org), March 1997.

    Copyright Kevlin Henney, 1997. All rights reserved.

    Permission to use, copy, modify, and distribute this software and its
    documentation for any purpose is hereby granted without fee, provided
    that this copyright and permissions notice appear in all copies and
    derivatives, and that no charge may be made for the software and its
    documentation except to cover cost of distribution.
    
*/

#ifdef WIN32
 #ifndef DIRENT_INCLUDED
  #define DIRENT_INCLUDED

struct dirent
{
    char *d_name;
};


typedef struct DIR
{
    long                handle; /* -1 for failed rewind */
    struct _finddata_t  info;
    struct dirent       result; /* d_name null iff first time */
    char                *name;  /* NTBS */
} DIR;

DIR           *opendir(const char *);
int           closedir(DIR *);
struct dirent *readdir(DIR *);
void          rewinddir(DIR *);

 #endif
#endif /* WIN32 */

/* *************************************************************** */

/*
 * used to drive the ntop's behaviour at run-time
 */
typedef struct ntopGlobals {

  /* general */
  char *program_name;           /* The name the program was run with, stripped of any leading path */
  int ntop_argc;                /* # of command line arguments */
  char **ntop_argv;             /* vector of command line arguments */
  char *startedAs;              /* ACTUAL starting line, not the resolved one */

  /* command line options */

  char *accessLogPath;               /* 'a' */
  u_char enablePacketDecoding;       /* 'b' */
  u_char stickyHosts;                /* 'c' */
  int daemonMode;                    /* 'd' */
#ifndef MAKE_MICRO_NTOP
  int maxNumLines;                   /* 'e' */
#endif
  char *rFileName;                   /* 'f' */
  u_char trackOnlyLocalHosts;        /* 'g' */
  char *devices;                     /* 'i' */
  int filterExpressionInExtraFrame;  /* 'k' */
  char *pcapLog;                     /* 'l' */
  char *localAddresses;              /* 'm' */
  int numericFlag;                   /* 'n' */
  short dontTrustMACaddr;            /* 'o' */
  char *protoSpecs;                  /* 'p' */
  u_char enableSuspiciousPacketDump; /* 'q' */
  int refreshRate;                   /* 'r' */
  u_char disablePromiscuousMode;     /* 's' */
  u_short traceLevel;                /* 't' */
#ifndef WIN32
  int userId, groupId;               /* 'u' */
  char * effectiveUserName;
#endif
  char *webAddr;                     /* 'w' */
  int webPort;
  u_char enableSessionHandling;      /* 'z' */

  char *currentFilterExpression;     /* 'B' */
  u_char largeNetwork;               /* 'C' */
  char domainName[MAXHOSTNAMELEN];   /* 'D' */
  int isLsofPresent;                 /* 'E' */
  u_char enableExternalTools;        /* 'E' */
  char *flowSpecs;                   /* 'F' */

#ifndef WIN32
  u_short debugMode;                 /* 'K' */
  int useSyslog;                     /* 'L' */
#endif

  int mergeInterfaces;               /* 'M' */
  int isNmapPresent;                 /* 'N' */
  char *pcapLogBasePath;             /* 'O' */ /* Added by Ola Lundqvist <opal@debian.org>. */
  char *dbPath;                      /* 'P' */
  char *mapperURL;                   /* 'U' */

#ifdef HAVE_OPENSSL
  char *sslAddr;                     /* 'W' */
  int sslPort;
#endif

#ifdef HAVE_GDCHART
  int throughput_chart_type;         /* '129' */
#endif

#ifndef MAKE_WITH_IGNORE_SIGPIPE
  int ignoreSIGPIPE;                 /* '132' */
#endif

#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  int useSSLwatchdog;                /* '133' */
#endif

  int dynamicPurgeLimits;            /* '134' */

  int reuseRRDgraphics;              /* '136' */

  char *P3Pcp;                       /* '137' */
  char *P3Puri;                      /* '138' */

  /* Other flags (these could set via command line options one day) */
  u_char enableFragmentHandling;

  u_int16_t hashListSize; /* Please don't change the type */

  /* Search paths */
  char **dataFileDirs;
  char **pluginDirs;
  char **configFileDirs;

  int basentoppid;         /* Used for writing to /var/run/ntop.pid (or whatever) */

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

  /* Administrative */
  char *shortDomainName;
#if defined(MAX_NUM_BAD_IP_ADDRESSES) && (MAX_NUM_BAD_IP_ADDRESSES > 0)
  BadGuysAddr weDontWantToTalkWithYou[MAX_NUM_BAD_IP_ADDRESSES];
#endif

#ifdef CFG_MULTITHREADED
  unsigned short numThreads;           /* # of running threads */

#ifdef MAKE_WITH_SEMAPHORES
  sem_t queueSem;

#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  sem_t queueAddressSem;
#endif /* MAKE_ASYNC_ADDRESS_RESOLUTION */

#else /* ! MAKE_WITH_SEMAPHORES */

  ConditionalVariable queueCondvar;

#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  ConditionalVariable queueAddressCondvar;
#endif /* MAKE_WITH_SEMAPHORES */

#endif /* ! MAKE_WITH_SEMAPHORES */

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
   * AR - Address Resolution - optional
   */
#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  PthreadMutex addressResolutionMutex;
  pthread_t dequeueAddressThreadId[MAX_NUM_DEQUEUE_THREADS];
#endif

  /*
   * Helper application lsof - optional
   */
  PthreadMutex lsofMutex;
  pthread_t lsofThreadId;

  unsigned short numDequeueThreads;

  PthreadMutex gdbmMutex;
  PthreadMutex graphMutex;
  PthreadMutex tcpSessionsMutex;

#ifdef MEMORY_DEBUG
  PthreadMutex leaksMutex;
#endif

  pthread_t handleWebConnectionsThreadId;

#endif /* CFG_MULTITHREADED */

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

  /* Termination flags */
  short capturePackets;      /* tells to ntop if data are to be collected */
  short endNtop;             /* graceful shutdown ntop */

  /* lsof support */
  u_short updateLsof;
  ProcessInfo **processes;
  u_short numProcesses;
  ProcessInfoList *localPorts[MAX_IP_PORT];

  /* Filter Chains */
  FlowFilterList *flowsList;

  /* Address Resolution */
  u_long dnsSniffedCount;
#if defined(MAKE_ASYNC_ADDRESS_RESOLUTION)
  u_long addressQueueCount;
  u_int addressQueueLen, maxAddressQueueLen;
#endif

  u_long numResolvedWithDNSAddresses, numKeptNumericAddresses, numResolvedOnCacheAddresses;

  /* Misc */
  char *separator;

  int32_t thisZone; /* seconds offset from gmt to local time */
  u_long numPurgedHosts, numTerminatedSessions;
  int    maximumHostsToPurgePerCycle;

  /* Time */
  time_t actTime, initialSniffTime, lastRefreshTime;
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
#ifdef MAKE_WITH_SSLWATCHDOG
  unsigned long numHTTPSrequestTimeouts;
#endif /* USE_SSL_WATCHDOG || MAKE_WITH_SSLWATCHDOG_RUNTIME */

  /* Packet Capture */
#if defined(CFG_MULTITHREADED)
  PacketInformation packetQueue[CONST_PACKET_QUEUE_LENGTH+1];
  u_int packetQueueLen, maxPacketQueueLen, packetQueueHead, packetQueueTail;
#endif

  TransactionTime transTimeHash[CONST_NUM_TRANSACTION_ENTRIES];

  u_char dummyEthAddress[LEN_ETHERNET_ADDRESS];
  u_short *mtuSize;
  u_short *headerSize;

#ifdef MEMORY_DEBUG
  size_t allocatedMemory;
#endif

  /*
   * local variables
   */
  int enableIdleHosts;   /* Purging of idle hosts support enabled by default */

#ifndef MAKE_MICRO_NTOP
  int sortSendMode;

#endif /* MAKE_MICRO_NTOP */

  int actualReportDeviceId;
  short columnSort, reportKind, sortFilter;
  int sock, newSock;
#ifdef HAVE_OPENSSL
  int sock_ssl;
#endif

  int numChildren;

  /* NetFlow */
  /* Flow emission */
  u_char netFlowDebug;
  int netFlowOutSocket;
  u_int32_t globalFlowSequence, globalFlowPktCount;
  NetFlow5Record theRecord;
  struct sockaddr_in netFlowDest;
  /* Flow reception */
  int netFlowInSocket, netFlowDeviceId;
  u_short netFlowInPort;
  u_long numNetFlowsPktsRcvd, numNetFlowsPktsSent, numNetFlowsRcvd, numBadFlowsVersionsRcvd;

  /* sFlow */
  int sflowOutSocket, sflowInSocket, sflowDeviceId;
  u_short sflowInPort;
  u_long numSamplesReceived, initialPool, lastSample;
  u_int32_t flowSampleSeqNo, numSamplesToGo;
  struct sockaddr_in sflowDest;

  /* rrd */
  char *rrdPath;

  /* http.c */
  FILE *accessLogFd;

  /* Memory cache */
  HostTraffic *hostsCache[MAX_HOSTS_CACHE_LEN];
  u_short      hostsCacheLen, hostsCacheLenMax;
  int          hostsCacheReused;

#ifdef PARM_USE_SESSIONS_CACHE
  IPSession   *sessionsCache[MAX_SESSIONS_CACHE_LEN];
  u_short      sessionsCacheLen, sessionsCacheLenMax;
  int          sessionsCacheReused;
#endif

  u_char      resetHashNow; /* used for hash reset */

#ifdef PARM_SHOW_NTOP_HEARTBEAT
  u_long heartbeatCounter;
#endif

  /* Peer2Peer Protocol Indexes */
  u_short GnutellaIdx, KazaaIdx, WinMXIdx, DirectConnectIdx, FTPIdx;

  /* Hash table collisions - counted during load */
  int hashCollisionsLookup, 
      vendorHashLoadCollisions,
      specialHashLoadCollisions,
      ipxsapHashLoadCollisions;

} NtopGlobals;

