/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 *                          http://www.ntop.org/
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

#ifndef NTOP_H
#define NTOP_H

/*
   On some systems these defines make reentrant library
   routines available.

   Courtesy of Andreas Pfaller <a.pfaller@pop.gun.de>.
*/
#define _REENTRANT
#define _THREAD_SAFE

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

/*
 * fallbacks for essential typedefs
 */
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

#ifdef WIN32
#include "ntop_win32.h"
#define HAVE_GDBM_H
#define strncasecmp(a, b, c) strnicmp(a, b, c)
#endif

#if defined(linux) || defined(__linux__)
/*
 * This allows to hide the (minimal) differences between linux and BSD
 */
#define __FAVOR_BSD
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#endif /* linux || __linux__ */

#ifdef __GNUC__
#define _UNUSED_ __attribute__((unused))
#else
#define _UNUSED_
#define __attribute__(a)
#endif

/*
 * operating system essential headers
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#ifndef WIN32
#include <unistd.h>
#endif

#if defined(NEED_GETDOMAINNAME)
int getdomainname(char *name, size_t len);
#endif

#include <string.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>

#ifndef WIN32
#include <strings.h>
#endif

#include <limits.h>
#include <float.h>
#include <math.h>
#include <sys/types.h>

#ifndef WIN32
#include <sys/time.h>
#endif

#ifndef WIN32
#include <sys/wait.h>
#endif

#include <sys/stat.h>

#ifndef WIN32
#include <sys/ioctl.h>
#endif

#if defined(HAVE_SYS_SELECT_H)
#include <sys/select.h>      /* AIX has it */
#endif

#if defined(HAVE_SYS_LDR_H)
#include <sys/ldr.h>         /* AIX has it */
#endif

#if defined(HAVE_SYS_SOCKIO_H)
#include <sys/sockio.h>
#endif

#if defined(HAVE_DL_H)
#include <dl.h>              /* HPUX has it */
#endif

#if defined(HAVE_DIRENT_H)
#include <dirent.h>
#endif

#if defined(HAVE_DLFCN_H)
#include <dlfcn.h>
#endif

/* 
   Courtesy of  
   Brent L. Bates <blbates@vigyan.com>
*/
#ifdef HAVE_STANDARDS_H
#include <standards.h>
#endif

#if defined(HAVE_CRYPT_H)
/* Fix courtesy of Charles M. Gagnon <charlesg@unixrealm.com> */
# if defined(HAVE_OPENSSL)
#  define des_encrypt MOVE_AWAY_des_encrypt
#  include <crypt.h>
#  undef des_encrypt
# else
#  include <crypt.h>
# endif
#endif

/*
 * gdbm management
 */
#if defined(HAVE_GDBM_H)
#include <gdbm.h>
#endif


/*
 * thread management
 */
#if defined(HAVE_SCHED_H)
# if defined(linux) || defined(__linux__)
#  undef HAVE_SCHED_H      /* Linux doesn't seem to really like it */
# else
#  include <sched.h>
# endif
#endif

#if defined(HAVE_SYS_SCHED_H)
#include <sys/sched.h>
#endif

#if defined(HAVE_SEMAPHORE_H)
#include <semaphore.h>
/* Courtesy of Fabrice Bellet <Fabrice.Bellet@creatis.insa-lyon.fr> */
#define USE_SEMAPHORES   1
#else
#undef USE_SEMAPHORES
#endif

#if defined(HAVE_PTHREAD_H)
#include <pthread.h>
# if !defined(_THREAD_SAFE)
#  define _THREAD_SAFE
# endif
#endif


#ifndef WIN32
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#endif

#if defined(HAVE_OPENSSL)
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif /* HAVE_OPENSSL */


/*
 * universal headers for network programming code
 */
#ifndef WIN32
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#ifndef WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#endif

#if defined(HAVE_NETINET_IF_ETHER_H)
#include <netinet/if_ether.h>
#endif

# if defined(ETHER_HEADER_HAS_EA)
#  define ESRC(ep) ((ep)->ether_shost.ether_addr_octet)
#  define EDST(ep) ((ep)->ether_dhost.ether_addr_octet)
# else
#  define ESRC(ep) ((ep)->ether_shost)
#  define EDST(ep) ((ep)->ether_dhost)
# endif


#if defined(HAVE_ARPA_NAMESER_H)
#include <arpa/nameser.h>
#endif

/*
 * Export from linux
 */
#ifndef INT16SZ
#define HFIXEDSZ      12              /* #/bytes of fixed data in header */
#define INT32SZ       4               /* for systems without 32-bit ints */
#define INT16SZ       2               /* for systems without 16-bit ints */
#define INADDRSZ      4               /* IPv4 T_A */
#define IN6ADDRSZ     16              /* IPv6 T_AAAA */
#endif /* INT16SZ */


#if defined(HAVE_NET_ETHERNET_H)
#include <net/ethernet.h>
#endif

#if defined(HAVE_ETHERTYPE_H)
#include <ethertype.h>
#else
# ifndef ETHERTYPE_IP
#  define ETHERTYPE_IP        0x0800
# endif
# ifndef ETHERTYPE_NS
#  define ETHERTYPE_NS        0x0600
# endif
# ifndef ETHERTYPE_SPRITE
#  define ETHERTYPE_SPRITE    0x0500
# endif
# ifndef ETHERTYPE_TRAIL
#  define ETHERTYPE_TRAIL     0x1000
# endif
# ifndef ETHERTYPE_MOPDL
#  define ETHERTYPE_MOPDL     0x6001
# endif
# ifndef ETHERTYPE_MOPRC
#  define ETHERTYPE_MOPRC     0x6002
# endif
# ifndef ETHERTYPE_DN
#  define ETHERTYPE_DN        0x6003
# endif
# ifndef ETHERTYPE_ARP
#  define ETHERTYPE_ARP       0x0806
# endif
# ifndef ETHERTYPE_LAT
#  define ETHERTYPE_LAT       0x6004
# endif
# ifndef ETHERTYPE_SCA
#  define ETHERTYPE_SCA       0x6007
# endif
# ifndef ETHERTYPE_REVARP
#  define ETHERTYPE_REVARP    0x8035
# endif
# ifndef ETHERTYPE_LANBRIDGE
#  define ETHERTYPE_LANBRIDGE 0x8038
# endif
# ifndef ETHERTYPE_DECDNS
#  define ETHERTYPE_DECDNS    0x803c
# endif
# ifndef ETHERTYPE_DECDTS
#  define ETHERTYPE_DECDTS    0x803e
# endif
# ifndef ETHERTYPE_VEXP
#  define ETHERTYPE_VEXP      0x805b
# endif
# ifndef ETHERTYPE_VPROD
#  define ETHERTYPE_VPROD     0x805c
# endif
# ifndef ETHERTYPE_ATALK
#  define ETHERTYPE_ATALK     0x809b
# endif
# ifndef ETHERTYPE_AARP
#  define ETHERTYPE_AARP      0x80f3
# endif
# ifndef ETHERTYPE_LOOPBACK
#  define ETHERTYPE_LOOPBACK  0x9000
# endif
#endif /* HAVE_ETHERTYPE_H */

/*
  Leave it here as some OS (e.g. RedHat 7.0)
  do not define it 
*/

# ifndef ETHERTYPE_QNX
#  define ETHERTYPE_QNX       0x8203
# endif
# ifndef ETHERTYPE_IPv6
#  define ETHERTYPE_IPv6        0x86DD
# endif

#ifndef ETHERMTU
#define ETHERMTU  1500
#endif

#define UNKNOWN_MTU 1500

#if defined(HAVE_IF_H)
#include "if.h"              /* OSF1 has it */
#endif

/*
 * #ifdef below courtesy of
 * "David Masterson" <David.Masterson@kla-tencor.com>
 */
#if defined(HAVE_NET_BPF_H)
#include <net/bpf.h>
#endif


/*
 * Libwrap support
 * courtesy of Georg Schwarz <schwarz@itp4.physik.TU-Berlin.DE>
 */
#if defined(HAVE_TCPD_H)

#include <tcpd.h>
#include <syslog.h>
# ifndef SYSLOG_FACILITY
#  define SYSLOG_FACILITY LOG_DAEMON   /* default value, if not specified otherwise */
# endif
# ifndef DAEMONNAME
#  define DAEMONNAME      "ntop"       /* for /etc/hosts.allow, /etc/hosts.deny */
# endif

#endif /* HAVE_TCPD_H */


/*
 * Packet Capture Library by Lawrence Berkeley National Laboratory - Network Research Group
 */
#include "pcap.h"

/*
 * ntop header file(s)
 */
#include "regex.h"
#include "rules.h"

#ifndef WIN32
#define closesocket(a) close(a)

#ifndef RETSIGTYPE
#define RETSIGTYPE void
#endif

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

#if defined(WIN32)
/*#include "ntop_win32.h"*/
#define n_short short
#define n_time time_t

#define HAVE_GDBM_H
#include <gdbmerrno.h>
extern const char *gdbm_strerror (int);
#define strncasecmp(a, b, c) strnicmp(a, b, c)
#endif

#ifdef WIN32
#define MAX_NUM_DEVICES 1
#else
#define MAX_NUM_DEVICES 32       /* NIC devices */
#endif
#define MAX_NUM_ROUTERS 512

#define DEFAULT_SNAPLEN  384 /* 68 (default) is not enough for DNS packets */
#define DEFAULT_COUNT    500

#define DUMMY_SOCKET_VALUE -999
#define MULTIPLY_FACTORY   0.75

/* ********************************************* */

#ifndef PACKETSZ /* Missing declarations */

/*
 * Define constants based on rfc883
 */
#define PACKETSZ	512		/* maximum packet size */
#define MAXDNAME	256		/* maximum domain name */
#define MAXCDNAME	255		/* maximum compressed domain name */
#define MAXLABEL	63		/* maximum length of domain label */
#define	HFIXEDSZ	12		/* #/bytes of fixed data in header */
#define QFIXEDSZ	4		/* #/bytes of fixed data in query */
#define RRFIXEDSZ	10		/* #/bytes of fixed data in r record */
#define	INT32SZ		4		/* for systems without 32-bit ints */
#define	INT16SZ		2		/* for systems without 16-bit ints */
#define	INADDRSZ	4		/* for sizeof(struct inaddr) != 4 */

/*
 * Type values for resources and queries
 */
#define T_A		1		/* host address */
#define T_NS		2		/* authoritative server */
#define T_MD		3		/* mail destination */
#define T_MF		4		/* mail forwarder */
#define T_CNAME		5		/* canonical name */
#define T_SOA		6		/* start of authority zone */
#define T_MB		7		/* mailbox domain name */
#define T_MG		8		/* mail group member */
#define T_MR		9		/* mail rename name */
#define T_NULL		10		/* null resource record */
#define T_WKS		11		/* well known service */
#define T_PTR		12		/* domain name pointer */
#define T_HINFO		13		/* host information */
#define T_MINFO		14		/* mailbox information */
#define T_MX		15		/* mail routing information */
#define T_TXT		16		/* text strings */
#define	T_RP		17		/* responsible person */
#define T_AFSDB		18		/* AFS cell database */
#define T_X25		19		/* X_25 calling address */
#define T_ISDN		20		/* ISDN calling address */
#define T_RT		21		/* router */
#define T_NSAP		22		/* NSAP address */
#define T_NSAP_PTR	23		/* reverse NSAP lookup (deprecated) */
#define	T_SIG		24		/* security signature */
#define	T_KEY		25		/* security key */
#define	T_PX		26		/* X.400 mail mapping */
#define	T_GPOS		27		/* geographical position (withdrawn) */
#define	T_AAAA		28		/* IP6 Address */
#define	T_LOC		29		/* Location Information */
	/* non standard */
#define T_UINFO		100		/* user (finger) information */
#define T_UID		101		/* user ID */
#define T_GID		102		/* group ID */
#define T_UNSPEC	103		/* Unspecified format (binary data) */
	/* Query type values which do not appear in resource records */
#define T_AXFR		252		/* transfer zone of authority */
#define T_MAILB		253		/* transfer mailbox records */
#define T_MAILA		254		/* transfer mail agent records */
#define T_ANY		255		/* wildcard match */

/*
 * Values for class field
 */

#define C_IN		1		/* the arpa internet */
#define C_CHAOS		3		/* for chaos net (MIT) */
#define C_HS		4		/* for Hesiod name server (MIT) (XXX) */
	/* Query class values which do not appear in resource records */
#define C_ANY		255		/* wildcard match */

#ifndef EMSGSIZE
#define EMSGSIZE    97 /* Inappropriate message buffer length */
#endif /* EMSGSIZE */

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
#endif /* PACKETSZ */


/*
  Code below courtesy of 
  Roberto F. De Luca <deluca@tandar.cnea.gov.ar>
*/

#define HTTP_TYPE_NONE	0
#define HTTP_TYPE_HTML	1
#define HTTP_TYPE_GIF	2
#define HTTP_TYPE_JPEG	3
#define HTTP_TYPE_PNG	4
#define HTTP_TYPE_CSS	5
#define HTTP_TYPE_TEXT	6

#define HTTP_FLAG_IS_CACHEABLE		(1<<0)
#define HTTP_FLAG_NO_CACHE_CONTROL	(1<<1)
#define HTTP_FLAG_KEEP_OPEN		(1<<2)
#define HTTP_FLAG_NEED_AUTHENTICATION	(1<<3)
#define HTTP_FLAG_MORE_FIELDS		(1<<4)
 
#define HTML_FLAG_NO_REFRESH		(1<<0)
#define HTML_FLAG_NO_STYLESHEET		(1<<1)
#define HTML_FLAG_NO_BODY		(1<<2)
#define HTML_FLAG_NO_HEADING		(1<<3)
  
#define ALARM_TIME                3
#define MIN_ALARM_TIME            1
#define THROUGHPUT_REFRESH_TIME   30
#define REFRESH_TIME              120
#define MIN_REFRESH_TIME          15


#if defined(MULTITHREADED)
# ifndef WIN32
#  if defined(HAVE_SYS_SCHED_H)
#   include <sys/sched.h>
#  endif

#  if defined(HAVE_SCHED_H)
#   include <sched.h>
#  endif

/*
 * Switched pthread with semaphore.
 * Courtesy of
 * Wayne Roberts <wroberts1@cx983858-b.orng1.occa.home.com>
 */
#  include <pthread.h>

#  if defined(HAVE_SEMAPHORE_H)
#   include <semaphore.h>
#  else
#   undef USE_SEMAPHORES
#  endif

typedef struct conditionalVariable {
  pthread_mutex_t mutex;
  pthread_cond_t  condvar;
  int predicate;
} ConditionalVariable;
# endif /* WIN32 */


typedef struct packetInformation {
  unsigned short deviceId;
  struct pcap_pkthdr h;
  u_char p[2*DEFAULT_SNAPLEN+1];
} PacketInformation;

# if defined(HAVE_OPENSSL)
#  define THREAD_MODE "MT (SSL)"
# else
#  define THREAD_MODE "MT"
# endif

#else /* ! MULTITHREADED */

#if defined(HAVE_OPENSSL)
#define THREAD_MODE "ST (SSL)"
#else
#define THREAD_MODE "ST"
#endif

/*
 * Comment out the line below if asynchronous
 * numeric -> symbolic address resolution
 * has problems on your system
 */
#ifndef ASYNC_ADDRESS_RESOLUTION
#define ASYNC_ADDRESS_RESOLUTION
#endif  /* ASYNC_ADDRESS_RESOLUTION */

#endif /* ! MULTITHREADED */


#define PACKET_QUEUE_LENGTH     2048
#define ADDRESS_QUEUE_LENGTH    512

#ifdef WIN32
typedef float TrafficCounter;
#else
typedef unsigned long long TrafficCounter;
#endif

#define PCAP_NW_INTERFACE         "pcap file"
#define MAX_NUM_CONTACTED_PEERS   8
#define SENT_PEERS                2
#define RCVD_PEERS                2
#define NO_PEER                   UINT_MAX


/* ************* Types Definition ********************* */

struct hostTraffic; /* IP Session global information */

/* *********************** */

typedef struct thptEntry {
  float trafficValue;
  /* ****** */
  u_int topHostSentIdx, secondHostSentIdx, thirdHostSentIdx;
  TrafficCounter topSentTraffic, secondSentTraffic, thirdSentTraffic;
  /* ****** */
  u_int topHostRcvdIdx, secondHostRcvdIdx, thirdHostRcvdIdx;
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

typedef struct simpleProtoTrafficInfo {
  TrafficCounter local, local2remote, remote, remote2local;
  TrafficCounter lastLocal, lastLocal2remote, lastRemote, lastRemote2local;
} SimpleProtoTrafficInfo;

/* *********************** */

typedef struct securityProbes {
  TrafficCounter synPkts, rstPkts, rstAckPkts, synFinPkts, finPushUrgPkts, nullPkts;
  TrafficCounter ackScanSent, ackScanRcvd;
  TrafficCounter xmasScanSent, xmasScanRcvd;
  TrafficCounter finScanSent, finScanRcvd;
  TrafficCounter nullScanSent, nullScanRcvd;
  TrafficCounter udpToClosedPortSent, udpToClosedPortRcvd;
} SecurityProbes;

/* *********************** */

typedef struct usageCounter {
  TrafficCounter value;
  u_int peersIndexes[MAX_NUM_CONTACTED_PEERS];
} UsageCounter;

/* *******************************
   
   NOTE

   Do not forget to MAP all the
   peersIndexes [call mapIdx()]

   ******************************* */

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
  /* ********* */
  UsageCounter udpToClosedPortSent, udpToClosedPortRcvd;
} SecurityHostProbes;

/* **************************** */

struct hostTraffic;

#define UNKNOWN_FRAGMENT_ORDER       0
#define INCREASING_FRAGMENT_ORDER    1
#define DECREASING_FRAGMENT_ORDER    2

typedef struct ipFragment {
  struct hostTraffic *src, *dest;
  char fragmentOrder;
  u_int fragmentId, lastOffset;
  u_int totalDataLength, expectedDataLength;
  u_int totalPacketLength;
  u_short sport, dport;
  time_t firstSeen;
  struct ipFragment *prev, *next;
} IpFragment;

/* **************************** */

/*
 * Interface's flags.
 */
#define INTERFACE_DOWN      0   /* not yet enabled via LBNL */
#define INTERFACE_READY     1   /* ready for packet sniffing */
#define INTERFACE_ENABLED   2   /* packet capturing currently active */

/* The constant below is so large due to the
   huge service table that Doug Royer <doug@royer.com>
   has to handle. I have no clue what's inside such /etc/services
   file. However, all this is quite interesting....
*/
#define SERVICE_HASH_SIZE     50000

/* Forward */
struct ipSession;
struct hostTraffic;

typedef struct trafficEntry {
  TrafficCounter bytesSent, bytesReceived;
} TrafficEntry;

typedef struct serviceEntry {
  u_short port;
  char* name;
} ServiceEntry;

/* ************************************* */

typedef struct {
  char *name;                    /* unique interface name */
  int flags;                     /* the status of the interface as viewed by ntop */

  u_int32_t addr;                /* Internet address (four bytes notation) */
  char *ipdot;                   /* IP address (dot notation) */
  char *fqdn;                    /* FQDN (resolved for humans) */

  struct in_addr network;        /* network number associated to this interface */
  struct in_addr netmask;        /* netmask associated to this interface */

  struct in_addr ifAddr;         /* network number associated to this interface */
                                 /* local domainname */

  time_t started;                /* time the interface was enabled to look at pkts */
  time_t firstpkt;               /* time first packet was captured */
  time_t lastpkt;                /* time last packet was captured */

  pcap_t *pcapPtr;               /* LBNL pcap handler */
  pcap_dumper_t *pcapDumper;     /* LBNL pcap dumper  - enabled using the 'l' flag */
  pcap_dumper_t *pcapErrDumper;  /* LBNL pcap dumper - all suspicious packets are logged */

  char virtualDevice;            /* set to 1 for virtual devices (e.g. eth0:1) */
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
  TrafficCounter droppedPackets; /* # of pkts dropped by the application */
  TrafficCounter ethernetPkts;   /* # of Ethernet pkts captured by the application */
  TrafficCounter broadcastPkts;  /* # of broadcast pkts captured by the application */
  TrafficCounter multicastPkts;  /* # of multicast pkts captured by the application */

  /*
   * The bytes section
   */
  TrafficCounter ethernetBytes;  /* # bytes captured */
  TrafficCounter ipBytes;
  TrafficCounter tcpBytes;
  TrafficCounter udpBytes;
  TrafficCounter otherIpBytes;

  TrafficCounter icmpBytes;
  TrafficCounter dlcBytes;
  TrafficCounter ipxBytes;
  TrafficCounter stpBytes; /* Spanning Tree */
  TrafficCounter decnetBytes;
  TrafficCounter netbiosBytes;
  TrafficCounter arpRarpBytes;
  TrafficCounter atalkBytes;
  TrafficCounter ospfBytes;
  TrafficCounter egpBytes;
  TrafficCounter igmpBytes;
  TrafficCounter osiBytes;
  TrafficCounter qnxBytes;
  TrafficCounter otherBytes;
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

  PacketStats rcvdPktStats;      /* statistics from start of the run to time of call */

  float peakThroughput, actualThpt, lastMinThpt, lastFiveMinsThpt;
  float peakPacketThroughput, actualPktsThpt, lastMinPktsThpt, lastFiveMinsPktsThpt;

  time_t lastThptUpdate, lastMinThptUpdate;
  time_t lastHourThptUpdate, lastFiveMinsThptUpdate;
  TrafficCounter throughput;
  float packetThroughput;

  unsigned long numThptSamples;
  ThptEntry last60MinutesThpt[60], last24HoursThpt[24];
  float last30daysThpt[30];
  u_short last60MinutesThptIdx, last24HoursThptIdx, last30daysThptIdx;

  SimpleProtoTrafficInfo tcpGlobalTrafficStats, udpGlobalTrafficStats, icmpGlobalTrafficStats;
  SimpleProtoTrafficInfo *ipProtoStats;
  
  SecurityProbes securityPkts;
  TrafficCounter numEstablishedTCPConnections; /* = # really established connections */

#ifdef MULTITHREADED
  pthread_t pcapDispatchThreadId;
#endif

  u_int  hostsno;        /* # of valid entries in the following table */
  u_int  actualHashSize, hashThreshold, topHashThreshold;
  struct hostTraffic **hash_hostTraffic;

  /* ************************** */

  IpFragment *fragmentList;
  struct ipSession **tcpSession;
  u_short numTotSessions, numTcpSessions;
  TrafficEntry ipTrafficMatrix[256][256]; /* Subnet traffic Matrix */
  struct hostTraffic* ipTrafficMatrixHosts[256]; /* Subnet traffic Matrix Hosts */
  fd_set ipTrafficMatrixPromiscHosts;
} ntopInterface_t;

typedef struct processInfo {
  char marker; /* internal use only */
  char *command, *user;
  time_t firstSeen, lastSeen;
  int pid;
  TrafficCounter bytesSent, bytesReceived;
  /* peers that talked with this process */
  u_int contactedIpPeersIndexes[MAX_NUM_CONTACTED_PEERS];
  u_int contactedIpPeersIdx;
} ProcessInfo;

typedef struct processInfoList {
  ProcessInfo            *element;
  struct processInfoList *next;
} ProcessInfoList;


#define MAX_NUM_SHARED_PORTS         16
#define MAX_NUM_PROCESSES          1024
#define MAX_NUM_LSOF_ENTRIES        512
#define MAX_NUM_EVENTS              512
#define MAX_NUM_EVENTS_TO_DISPLAY    32
#define MIN_NUM_FREED_BUCKETS       128

#define TOP_IP_PORT           65534 /* IP ports range from 0 to 65535 */
#define TOP_ASSIGNED_IP_PORTS  1024

#define ETHERNET_ADDRESS_LEN 6

#define NTOP_DEFAULT_WEB_PORT 3000

typedef union {
  HEADER qb1;
  u_char qb2[PACKETSZ];
} querybuf;


#ifndef MAXALIASES
#define MAXALIASES       35
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN  256
#endif

#ifndef MAXADDRS
#define MAXADDRS         35
#endif

#ifndef NS_CMPRSFLGS
#define NS_CMPRSFLGS    0xc0
#endif

#ifndef NS_MAXCDNAME
#define NS_MAXCDNAME     255
#endif

typedef struct {
  char      name[MAXDNAME];                /* official name of host */
  char      aliases[MAXALIASES][MAXDNAME]; /* alias list */
  u_int32_t addrList[MAXADDRS]; /* list of addresses from name server */
  int       addrType;   /* host address type */
  int       addrLen;    /* length of address */
} DNSHostInfo;

/* ******************************

   NOTE:

   Most of the code below has been
   borrowed from tcpdump.

   ****************************** */


/* rfc1700 */
#ifndef ICMP_UNREACH_NET_UNKNOWN
#define ICMP_UNREACH_NET_UNKNOWN	6	/* destination net unknown */
#endif
#ifndef ICMP_UNREACH_HOST_UNKNOWN
#define ICMP_UNREACH_HOST_UNKNOWN	7	/* destination host unknown */
#endif
#ifndef ICMP_UNREACH_ISOLATED
#define ICMP_UNREACH_ISOLATED		8	/* source host isolated */
#endif
#ifndef ICMP_UNREACH_NET_PROHIB
#define ICMP_UNREACH_NET_PROHIB		9	/* admin prohibited net */
#endif
#ifndef ICMP_UNREACH_HOST_PROHIB
#define ICMP_UNREACH_HOST_PROHIB	10	/* admin prohibited host */
#endif
#ifndef ICMP_UNREACH_TOSNET
#define ICMP_UNREACH_TOSNET		11	/* tos prohibited net */
#endif
#ifndef ICMP_UNREACH_TOSHOST
#define ICMP_UNREACH_TOSHOST		12	/* tos prohibited host */
#endif

/* rfc1716 */
#ifndef ICMP_UNREACH_FILTER_PROHIB
#define ICMP_UNREACH_FILTER_PROHIB	13	/* admin prohibited filter */
#endif
#ifndef ICMP_UNREACH_HOST_PRECEDENCE
#define ICMP_UNREACH_HOST_PRECEDENCE	14	/* host precedence violation */
#endif
#ifndef ICMP_UNREACH_PRECEDENCE_CUTOFF
#define ICMP_UNREACH_PRECEDENCE_CUTOFF	15	/* precedence cutoff */
#endif

/* rfc1256 */
#ifndef ICMP_ROUTERADVERT
#define ICMP_ROUTERADVERT		9	/* router advertisement */
#endif
#ifndef ICMP_ROUTERSOLICIT
#define ICMP_ROUTERSOLICIT		10	/* router solicitation */
#endif

#ifndef ICMP_INFO_REQUEST
#define ICMP_INFO_REQUEST               15      /* Information Request          */
#endif

#ifndef ICMP_DEST_UNREACHABLE
#define	ICMP_DEST_UNREACHABLE		3       /* Destination Unreachable */
#endif

#ifndef ICMP_INFO_REPLY
#define ICMP_INFO_REPLY                 16      /* Information Reply            */
#endif

#ifndef ICMP_SOURCE_QUENCH
#define ICMP_SOURCE_QUENCH               4      /* Source Quench: packet lost, slow down */
#endif

#ifndef ICMP_TIMESTAMP
#define ICMP_TIMESTAMP                   13      /* Timestamp Request            */
#endif

#ifndef ICMP_TIMESTAMPREPLY
#define ICMP_TIMESTAMPREPLY              14      /* Timestamp Reply            */
#endif


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

#define llcui		ctl.snap.snap_ui
#define llcpi		ctl.snap.snap_pi
#define orgcode		ctl.snap_ether.snap_orgcode
#define ethertype	ctl.snap_ether.snap_ethertype
#define llcis		ctl.is_ctl
#define llcu		ctl.u_ctl

#define LLC_U_FMT	3
#define LLC_GSAP	1
#define LLC_S_FMT	1

#define LLC_U_POLL	0x10
#define LLC_IS_POLL	0x0001
#define LLC_XID_FI	0x81

#define LLC_U_CMD(u)	((u) & 0xef)
#define LLC_UI		0x03
#define	LLC_UA		0x63
#define	LLC_DISC	0x43
#define	LLC_DM		0x0f
#define	LLC_SABME	0x6f
#define	LLC_TEST	0xe3
#define	LLC_XID		0xaf
#define	LLC_FRMR	0x87

#define	LLC_S_CMD(is)	(((is) >> 10) & 0x03)
#define	LLC_RR		0x0100
#define	LLC_RNR		0x0500
#define	LLC_REJ		0x0900

#define LLC_IS_NR(is)	(((is) >> 1) & 0x7f)
#define LLC_I_NS(is)	(((is) >> 9) & 0x7f)

#ifndef LLCSAP_NULL
#define	LLCSAP_NULL		0x00
#endif

#ifndef LLCSAP_GLOBAL
#define	LLCSAP_GLOBAL		0xff
#endif

#ifndef LLCSAP_8021B
#define	LLCSAP_8021B_I		0x02
#endif

#ifndef LLCSAP_8021B
#define	LLCSAP_8021B_G		0x03
#endif

#ifndef LLCSAP_IP
#define	LLCSAP_IP		0x06
#endif

#ifndef LLCSAP_PROWAYNM
#define	LLCSAP_PROWAYNM		0x0e
#endif

#ifndef LLCSAP_8021D
#define	LLCSAP_8021D		0x42
#endif

#ifndef LLCSAP_RS511
#define	LLCSAP_RS511		0x4e
#endif

#ifndef LLCSAP_ISO8208
#define	LLCSAP_ISO8208		0x7e
#endif

#ifndef LLCSAP_PROWAY
#define	LLCSAP_PROWAY		0x8e
#endif

#ifndef LLCSAP_SNAP
#define	LLCSAP_SNAP		0xaa
#endif

#ifndef LLCSAP_ISONS
#define	LLCSAP_ISONS		0xfe
#endif

#ifndef LLCSAP_NETBIOS
#define	LLCSAP_NETBIOS		0xf0
#endif

#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF              89
#endif

#ifndef IPPROTO_IGMP
#define IPPROTO_IGMP               2  /* Internet Group Management Protocol */
#endif

/* ******************************* */

#if !defined(min)
#define min(a,b) ((a) > (b) ? (b) : (a))
#endif

#if !defined(max)
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

typedef struct {
  u_int16_t checksum, length;
  u_int8_t  hops, packetType;
  u_char    destNw[4], destNode[6];
  u_int16_t dstSocket;
  u_char    srcNw[4], srcNode[6];
  u_int16_t srcSocket;
} IPXpacket;



/*
 * SunOS 4.x, at least, doesn't have a CLOCKS_PER_SEC.
 * I got this value from Solaris--who knows.
 * Paul D. Smith <psmith@baynetworks.com>
 */
#ifndef CLOCKS_PER_SEC
#define CLOCKS_PER_SEC 1000000
#endif

#ifndef NTOHL
#define NTOHL(x)    (x) = ntohl(x)
#endif

#define DB_TIMEOUT_REFRESH_TIME      30 /* seconds */
#define DEFAULT_DB_UPDATE_TIME       60 /* seconds */
#define HASHNAMESIZE               4096
#define MAX_HASH_SIZE              32768

/*
 * 75% is the threshold for the hash table: it's time to
 * free up some space
 */
#define HASHNAMETHRESHOLDSIZE  (HASHNAMESIZE*0.75) /* 75% */

#define SHORTHASHNAMESIZE  1024
#define VENDORHASHNAMESIZE (3*HASHNAMESIZE)

/* Stefano Suin <stefano@ntop.org> */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN  64
#endif

/*
 * Max number of screen switchable using
 * the space bar (interactive mode only).
*/
#define MAX_NUM_SCREENS  6

/*
 * Max number of TCP sessions that can be
 * recorded per host
 */
#define MAX_NUM_TCP_SESSIONS  32

#define NULL_HDRLEN 4

#define SHORT_REPORT        1
#define LONG_REPORT         2


#define MAX_NUM_SESSION_PEERS 5
#define MAX_NUM_HOST_ROUTERS  5

#define CLIENT_TO_SERVER       1
#define CLIENT_FROM_SERVER     2
#define SERVER_TO_CLIENT       3
#define SERVER_FROM_CLIENT     4


#define CLIENT_ROLE            1
#define SERVER_ROLE            2

#define REMOTE_TO_LOCAL_ACCOUNTING   1
#define LOCAL_TO_REMOTE_ACCOUNTING   2
#define LOCAL_TO_LOCAL_ACCOUNTING    3

#define MAX_NUM_HANDLED_IP_PROTOCOLS      32

#define MAX_NUM_PROTOS_SCREENS 5

#define MAX_HOST_NAME_LEN 26

struct enamemem {
  u_short e_addr0;
  u_short e_addr1;
  u_short e_addr2;
  char   *e_name;
  u_char *e_nsap;  /* used only for nsaptable[] */
  struct enamemem *e_nxt;
};

typedef struct protoTrafficInfo {
  TrafficCounter sentLocally, sentRemotely;
  TrafficCounter receivedLocally, receivedFromRemote;
} ProtoTrafficInfo;

typedef struct ipGlobalSession {
  u_short magic;
  u_short port;                    /* port (either client or server)           */
  u_char initiator;                /* CLIENT_ROLE/SERVER_ROLE                  */
  time_t firstSeen;                /* time when the session has been initiated */
  time_t lastSeen;                 /* time when the session has been closed    */
  u_short sessionCounter;          /* # of sessions we've observed             */
  TrafficCounter bytesSent;        /* # bytes sent     (peer -> initiator)     */
  TrafficCounter bytesReceived;    /* # bytes received (peer -> initiator)     */
  TrafficCounter bytesFragmentedSent, bytesFragmentedReceived; /* IP Fragments */
  u_int lastPeer;                  /* idx of the last peer added to the list   */
  u_int peersIdx[MAX_NUM_SESSION_PEERS]; /* session peers idx          */
  struct ipGlobalSession  *next;   /* next element (linked list)               */
} IpGlobalSession;

#define MAX_NUM_FIN          4

/* **************** Plugin **************** */

typedef void(*VoidFunc)(void);
typedef void(*PluginFunc)(const struct pcap_pkthdr *h, const u_char *p);
typedef void(*HashResizePluginFunc)(u_int oldSize, u_int newSize, int* mappings);
typedef void(*PluginHTTPFunc)(char* url);

typedef struct pluginInfo {
  /* Plugin Info */
  char *pluginName;         /* Short plugin name (e.g. arpPlugin) */
  char *pluginDescr;        /* Long plugin description */
  char *pluginVersion;
  char *pluginAuthor;
  char *pluginURLname;      /* Set it to NULL if the plugin doesn't speak HTTP */
  char activeByDefault;     /* Set it to 1 if this plugin is active by default */
  VoidFunc startFunc, termFunc;
  PluginFunc pluginFunc;    /* Initialize here all the plugin structs... */
  PluginHTTPFunc httpFunct; /* Set it to NULL if the plugin doesn't speak HTTP */
  HashResizePluginFunc resizeFunct; /* Function called when the main hash is resized */
  char* bpfFilter;          /* BPF filter for selecting packets that
       		               will be routed to the plugin  */
} PluginInfo;


typedef struct pluginStatus {
  PluginInfo *pluginPtr;
  char activePlugin;
} PluginStatus;

#define PLUGIN_EXTENSION                  ".so"
#define PLUGIN_ENTRY_FCTN_NAME "PluginEntryFctn"

/* Flow Filter List */
typedef struct flowFilterList {
  char* flowName;
  struct bpf_program fcode[MAX_NUM_DEVICES]; /* compiled filter code       */
  struct flowFilterList *next;               /* next element (linked list) */
  TrafficCounter bytes, packets;
  PluginStatus pluginStatus;
} FlowFilterList;

#define MAGIC_NUMBER                1968 /* Magic year actually */
#define MAX_NUM_STORED_FLAGS           4

typedef struct sessionInfo {
  struct in_addr sessionHost;
  u_short sessionPort;
} SessionInfo;

/* IP Session Information */
typedef struct ipSession {
  u_short magic;
  u_int initiatorIdx;               /* initiator address   (IP address)         */
  struct in_addr initiatorRealIp;   /* Real IP address (if masqueraded and known) */
  u_short sport;                    /* initiator address   (port)               */
  u_int remotePeerIdx;              /* remote peer address (IP address)         */
  struct in_addr remotePeerRealIp;  /* Real IP address (if masqueraded and known) */
  u_short dport;                    /* remote peer address (port)               */
  time_t firstSeen;                 /* time when the session has been initiated */
  time_t lastSeen;                  /* time when the session has been closed    */
  TrafficCounter bytesSent;         /* # bytes sent (initiator -> peer) [IP]    */
  TrafficCounter bytesReceived;     /* # bytes received (peer -> initiator)[IP] */
  TrafficCounter bytesProtoSent;    /* # bytes sent (Protocol [e.g. HTTP])      */
  TrafficCounter bytesProtoRcvd;    /* # bytes rcvd (Protocol [e.g. HTTP])      */
  TrafficCounter bytesFragmentedSent;     /* IP Fragments                       */
  TrafficCounter bytesFragmentedReceived; /* IP Fragments                       */
  u_int minWindow, maxWindow;       /* TCP window size                          */
  struct timeval nwLatency;         /* Network Latency                          */
  u_short numFin;                   /* # FIN pkts received                      */
  u_short numFinAcked;              /* # ACK pkts received                      */
  tcp_seq lastAckIdI2R;             /* ID of the last ACK received              */
  tcp_seq lastAckIdR2I;             /* ID of the last ACK received              */
  u_short numDuplicatedAckI2R;      /* # duplicated ACKs                        */
  u_short numDuplicatedAckR2I;      /* # duplicated ACKs                        */
  TrafficCounter bytesRetranI2R;    /* # bytes retransmitted (due to duplicated ACKs) */
  TrafficCounter bytesRetranR2I;    /* # bytes retransmitted (due to duplicated ACKs) */
  tcp_seq finId[MAX_NUM_FIN];       /* ACK ids we're waiting for                */
  TrafficCounter lastFlags;         /* flags of the last TCP packet             */
  u_int32_t lastCSAck, lastSCAck;   /* they store the last ACK ids C->S/S->C    */
  u_int32_t lastCSFin, lastSCFin;   /* they store the last FIN ids C->S/S->C    */
  u_char lastInitiator2RemoteFlags[MAX_NUM_STORED_FLAGS]; /* TCP flags          */
  u_char lastRemote2InitiatorFlags[MAX_NUM_STORED_FLAGS]; /* TCP flags          */
  u_short sessionState;             /* actual session state                     */
  u_char  napsterSession;           /* checked if this is a Napster session     */
  u_char  passiveFtpSession;        /* checked if this is a passive FTP session */
} IPSession;


#define MAX_NUM_TABLE_ROWS      384

typedef struct hostAddress {
  unsigned int numAddr;
  char* symAddr;
} HostAddress;

typedef struct portUsage {
  u_short        clientUses, serverUses;
  u_int          clientUsesLastPeer, serverUsesLastPeer;
  TrafficCounter clientTraffic, serverTraffic;
} PortUsage;

#define THE_DOMAIN_HAS_BEEN_COMPUTED_FLAG 1
#define SUBNET_LOCALHOST_FLAG             3 /* indicates whether the host is either local or remote */
#define BROADCAST_HOST_FLAG               4 /* indicates whether this is a broadcast address */
#define MULTICAST_HOST_FLAG               5 /* indicates whether this is a multicast address */
#define GATEWAY_HOST_FLAG                 6 /* indicates whether this is used as a gateway */
#define NAME_SERVER_HOST_FLAG             7 /* indicates whether this is used as a name server (e.g. DNS) */
#define SUBNET_PSEUDO_LOCALHOST_FLAG      8 /* indicates whether the host is local
                      			       (with respect to the specified subnets) */
/* Host Type */
#define HOST_TYPE_SERVER				  9
#define HOST_TYPE_WORKSTATION			         10
#define HOST_TYPE_PRINTER				 11
/* Host provided services */
#define HOST_SVC_SMTP					 12
#define HOST_SVC_POP					 13
#define HOST_SVC_IMAP					 14
#define HOST_SVC_DIRECTORY				 15 /* e.g.IMAP, Novell Directory server */
#define HOST_SVC_FTP					 16
#define HOST_SVC_HTTP					 17
#define HOST_SVC_WINS					 18
#define HOST_SVC_BRIDGE					 19
#define HOST_SVC_NAPSTER_REDIRECTOR			 20
#define HOST_SVC_NAPSTER_SERVER			         21
#define HOST_SVC_NAPSTER_CLIENT			         22
#define HOST_SVC_DHCP_CLIENT			         23
#define HOST_SVC_DHCP_SERVER			         24
#define HOST_TYPE_MASTER_BROWSER			 25

/* Macros */
#define theDomainHasBeenComputed(a) FD_ISSET(THE_DOMAIN_HAS_BEEN_COMPUTED_FLAG, &(a->flags))
#define subnetLocalHost(a)          ((a != NULL) && FD_ISSET(SUBNET_LOCALHOST_FLAG, &(a->flags)))
#define broadcastHost(a)            ((a != NULL) && FD_ISSET(BROADCAST_HOST_FLAG, &(a->flags)))
#define multicastHost(a)            ((a != NULL) && FD_ISSET(MULTICAST_HOST_FLAG, &(a->flags)))
#define gatewayHost(a)              ((a != NULL) && FD_ISSET(GATEWAY_HOST_FLAG, &(a->flags)))
#define nameServerHost(a)           ((a != NULL) && FD_ISSET(NAME_SERVER_HOST_FLAG, &(a->flags)))
#define subnetPseudoLocalHost(a)    ((a != NULL) && FD_ISSET(SUBNET_PSEUDO_LOCALHOST_FLAG, &(a->flags)))

#define isServer(a)		    ((a != NULL) && FD_ISSET(HOST_TYPE_SERVER, &(a->flags)))
#define isWorkstation(a)	    ((a != NULL) && FD_ISSET(HOST_TYPE_WORKSTATION, &(a->flags)))
#define isMasterBrowser(a)	    ((a != NULL) && FD_ISSET(HOST_TYPE_MASTER_BROWSER, &(a->flags)))
#define isPrinter(a)		    ((a != NULL) && FD_ISSET(HOST_TYPE_PRINTER, &(a->flags)))

#define isSMTPhost(a)		    ((a != NULL) && FD_ISSET(HOST_SVC_SMTP, &(a->flags)))
#define isPOPhost(a)		    ((a != NULL) && FD_ISSET(HOST_SVC_POP, &(a->flags)))
#define isIMAPhost(a)		    ((a != NULL) && FD_ISSET(HOST_SVC_IMAP, &(a->flags)))
#define isDirectoryHost(a)	    ((a != NULL) && FD_ISSET(HOST_SVC_DIRECTORY, &(a->flags)))
#define isFTPhost(a)		    ((a != NULL) && FD_ISSET(HOST_SVC_FTP, &(a->flags)))
#define isHTTPhost(a)		    ((a != NULL) && FD_ISSET(HOST_SVC_HTTP, &(a->flags)))
#define isWINShost(a)		    ((a != NULL) && FD_ISSET(HOST_SVC_WINS, &(a->flags)))
#define isBridgeHost(a)		    ((a != NULL) && FD_ISSET(HOST_SVC_BRIDGE, &(a->flags)))
#define isNapsterRedirector(a)	    ((a != NULL) && FD_ISSET(HOST_SVC_NAPSTER_REDIRECTOR, &(a->flags)))
#define isNapsterServer(a)	    ((a != NULL) && FD_ISSET(HOST_SVC_NAPSTER_SERVER, &(a->flags)))
#define isNapsterClient(a)	    ((a != NULL) && FD_ISSET(HOST_SVC_NAPSTER_CLIENT, &(a->flags)))
#define isDHCPClient(a)	            ((a != NULL) && FD_ISSET(HOST_SVC_DHCP_CLIENT, &(a->flags)))
#define isDHCPServer(a)	            ((a != NULL) && FD_ISSET(HOST_SVC_DHCP_SERVER, &(a->flags)))


/* ******** Napster *************** */

/* Cache of Napster Servers */
#define MAX_NUM_NAPSTER_SERVER  32

typedef struct napsterServer {
  struct in_addr serverAddress;
  u_short serverPort;
} NapsterServer;

NapsterServer napsterSvr[MAX_NUM_NAPSTER_SERVER];

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

typedef struct serviceStats {
  TrafficCounter numLocalReqSent, numRemoteReqSent;
  TrafficCounter numPositiveReplSent, numNegativeReplSent;
  TrafficCounter numLocalReqRcvd, numRemoteReqRcvd;
  TrafficCounter numPositiveReplRcvd, numNegativeReplRcvd;
  time_t fastestMicrosecLocalReqMade, slowestMicrosecLocalReqMade;
  time_t fastestMicrosecLocalReqServed, slowestMicrosecLocalReqServed;
  time_t fastestMicrosecRemoteReqMade, slowestMicrosecRemoteReqMade;
  time_t fastestMicrosecRemoteReqServed, slowestMicrosecRemoteReqServed;
} ServiceStats;

/* *********************** */

typedef struct napsterStats {
  TrafficCounter numConnectionsRequested, numConnectionsServed;
  TrafficCounter numSearchSent, numSearchRcvd;
  TrafficCounter numDownloadsRequested, numDownloadsServed;
  TrafficCounter bytesSent, bytesRcvd;
} NapsterStats;

/* *********************** */

#define DHCP_UNKNOWN_MSG    0
#define DHCP_DISCOVER_MSG   1
#define DHCP_OFFER_MSG      2
#define DHCP_REQUEST_MSG    3
#define DHCP_DECLINE_MSG    4
#define DHCP_ACK_MSG        5
#define DHCP_NACK_MSG       6
#define DHCP_RELEASE_MSG    7
#define DHCP_INFORM_MSG     8
#define NUM_DHCP_MSG        9 /* 9 messages in total */

typedef struct dhcpStats { 
  struct in_addr dhcpServerIpAddress;  /* DHCP server that assigned the address */
  struct in_addr previousIpAddress;    /* Previous IP address is any */
  time_t assignTime;                   /* when the address was assigned */
  time_t renewalTime;                  /* when the address has to be renewed */
  time_t leaseTime;                    /* when the address lease will expire */
  unsigned long dhcpMsgSent[NUM_DHCP_MSG], dhcpMsgRcvd[NUM_DHCP_MSG];
} DHCPStats;

/* *********************** */

#ifndef ICMP_MAXTYPE
#define ICMP_MAXTYPE            18
#endif


typedef struct icmpHostInfo {
  unsigned long icmpMsgSent[ICMP_MAXTYPE+1];
  unsigned long icmpMsgRcvd[ICMP_MAXTYPE+1];
  time_t        lastUpdated;
} IcmpHostInfo;

/* *********************** */

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__

#define DEFAULT_TRACE_LEVEL          3
#define DETAIL_TRACE_LEVEL           5

#define DETAIL_ACCESS_LOG_FILE_PATH  "ntop.access.log"

/* *********************** */

#define HASH_INITIAL_SIZE         32
#define MAX_MULTIHOMING_ADDRESSES 16
#define MAX_HOST_SYM_NAME_LEN     64
#define MAX_NODE_TYPES             8

/* Host Traffic */
typedef struct hostTraffic {
  struct in_addr hostIpAddress;
  time_t         firstSeen;
  time_t         lastSeen; /* time when this host has sent/received some data  */
  time_t         nextDBupdate; /* next time when the DB entry
				  for this host will be updated */
  u_char         ethAddress[ETHERNET_ADDRESS_LEN];
  u_char         lastEthAddress[ETHERNET_ADDRESS_LEN]; /* used for remote addresses */
  u_char         instanceInUse; /* If so, this instance cannot be purged */
  char           ethAddressString[18];
  char           hostNumIpAddress[17], *fullDomainName;
  char           *dotDomainName, hostSymIpAddress[MAX_HOST_SYM_NAME_LEN], *osName;
  struct in_addr hostIpAddresses[MAX_MULTIHOMING_ADDRESSES];
  u_short        minTTL, maxTTL; /* IP TTL (Time-To-Live) */

  /* NetBIOS */
  char           nbNodeType, *nbHostName, *nbDomainName, *nbDescr;

  /* AppleTalk*/
  u_short        atNetwork;
  u_char         atNode;
  char           *atNodeName, *atNodeType[MAX_NODE_TYPES];

  /* IPX */
  char           *ipxHostName;
  u_short        numIpxNodeTypes, ipxNodeType[MAX_NODE_TYPES];

  fd_set         flags;
  TrafficCounter pktSent, pktReceived,
    pktDuplicatedAckSent, pktDuplicatedAckRcvd;
  TrafficCounter lastPktSent, lastPktReceived;
  TrafficCounter pktBroadcastSent, bytesBroadcastSent;
  TrafficCounter pktMulticastSent, bytesMulticastSent,
                 pktMulticastRcvd, bytesMulticastRcvd;
  TrafficCounter lastBytesSent, lastHourBytesSent,
    bytesSent, bytesSentLocally, bytesSentRemotely;
  TrafficCounter lastBytesReceived, lastHourBytesReceived, bytesReceived,
                 bytesReceivedLocally, bytesReceivedFromRemote;
  float          actualRcvdThpt, lastHourRcvdThpt, averageRcvdThpt, peakRcvdThpt,
                 actualSentThpt, lastHourSentThpt, averageSentThpt, peakSentThpt;
  float          actualRcvdPktThpt, averageRcvdPktThpt, peakRcvdPktThpt,
                 actualSentPktThpt, averageSentPktThpt, peakSentPktThpt;
  unsigned short actBandwidthUsage;
  TrafficCounter lastCounterBytesSent, last24HoursBytesSent[25], lastDayBytesSent,
                 lastCounterBytesRcvd, last24HoursBytesRcvd[25], lastDayBytesRcvd;

  /* IP */
  PortUsage      *portsUsage[TOP_ASSIGNED_IP_PORTS];
  TrafficCounter tcpSentLocally, tcpSentRemotely, udpSentLocally,
                 udpSentRemotely, icmpSent, ospfSent, igmpSent;
  TrafficCounter tcpReceivedLocally, tcpReceivedFromRemote, udpReceivedLocally,
                 udpReceivedFromRemote, icmpReceived, ospfReceived, igmpReceived;

  /* Interesting Packets */  
  SecurityHostProbes securityHostPkts;  

  /* non IP */
  IcmpHostInfo    *icmpInfo;
  TrafficCounter  stpSent, stpReceived; /* Spanning Tree */
  TrafficCounter  ipxSent, ipxReceived;
  TrafficCounter  osiSent, osiReceived;
  TrafficCounter  dlcSent, dlcReceived;
  TrafficCounter  arp_rarpSent, arp_rarpReceived;
  TrafficCounter  arpReqPktsSent, arpReplyPktsSent, arpReplyPktsRcvd;
  TrafficCounter  decnetSent, decnetReceived;
  TrafficCounter  appletalkSent, appletalkReceived;
  TrafficCounter  netbiosSent, netbiosReceived;
  TrafficCounter  qnxSent, qnxReceived;
  TrafficCounter  otherSent, otherReceived;
  ProtoTrafficInfo *protoIPTrafficInfos; /* info about IP traffic generated/received by this host */
  IpGlobalSession *tcpSessionList, *udpSessionList; /* list of sessions initiated/received by this host */
  u_int contactedSentPeersIndexes[MAX_NUM_CONTACTED_PEERS]; /* peers that talked with this host */
  u_int contactedSentPeersIdx;
  u_int contactedRcvdPeersIndexes[MAX_NUM_CONTACTED_PEERS]; /* peers that talked with this host */
  u_int contactedRcvdPeersIdx;
  u_int contactedRouters[MAX_NUM_HOST_ROUTERS]; /* routers contacted by this host */
  ServiceStats *dnsStats, *httpStats;
  NapsterStats *napsterStats;
  DHCPStats    *dhcpStats;

  /* *************** IMPORTANT ***************

     If you add a pointer to this struct please
     go to resurrectHostTrafficInstance() and
     add a NULL to each pointer you added in the
     newly resurrected.

     *************** IMPORTANT *************** */
} HostTraffic;

/* **************************** */

struct hnamemem {
  HostTraffic *instance;
  struct in_addr addr;
  char *name;
};

/* **************************** */

typedef struct domainStats {
  HostTraffic *domainHost; /* ptr to a host that belongs to the domain */
  TrafficCounter bytesSent, bytesRcvd;
  TrafficCounter tcpSent, udpSent;
  TrafficCounter icmpSent, ospfSent, igmpSent;
  TrafficCounter tcpRcvd, udpRcvd;
  TrafficCounter icmpRcvd, ospfRcvd, igmpRcvd;
} DomainStats;

/* **************************** */

typedef struct usersTraffic {
  char* userName;
  TrafficCounter bytesSent, bytesReceived;
} UsersTraffic;

/* **************************** */

#define NUM_TRANSACTION_ENTRIES   256

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

#define MULTICAST_MASK 0xE0000000 /* 224.X.Y.Z */

/* **************************** */

#define CRYPT_SALT "99" /* 2 char string */

/* **************************** */

#define LONG_FORMAT    1
#define SHORT_FORMAT   2

/* **************************** */

#define DELETE_FRAGMENT 1
#define KEEP_FRAGMENT   2

/* **************************** */

/* TCP Session State Transition */

#define STATE_SYN                    0
#define STATE_SYN_ACK                1
#define STATE_ACK                    2
#define STATE_ACTIVE         STATE_ACK
#define STATE_BEGIN       STATE_ACTIVE
#define STATE_FIN1_ACK0              3
#define STATE_FIN1_ACK1              4
#define STATE_FIN2_ACK0              5
#define STATE_FIN2_ACK1              6
#define STATE_FIN2_ACK2              7
#define STATE_TIMEOUT                8
#define STATE_END                    9

/* **************************** */

/* Timedout sessions are scanned each SESSION_SCAN_DELAY seconds */
#define SESSION_SCAN_DELAY        30     /* 30 secs   */

/* This is the 2MSL timeout as defined in the TCP standard (RFC 761) */
#define TWO_MSL_TIMEOUT          120     /* 2 minutes */
#define DOUBLE_TWO_MSL_TIMEOUT   (2*TWO_MSL_TIMEOUT)

#define IDLE_HOST_PURGE_TIMEOUT  1*60*60    /*  1 hours   */
#define IDLE_SESSION_TIMEOUT     30*60      /* 30 minutes */
#define PIPE_READ_TIMEOUT        15         /* seconds    */

/* **************************** */

#define NTOP_INFORMATION_MSG     (u_short)0
#define NTOP_WARNING_MSG         (u_short)1
#define NTOP_ERROR_MSG           (u_short)2

#define MESSAGE_MAX_LEN    255

typedef struct logMessage {
  u_short severity;
  char message[MESSAGE_MAX_LEN+1];
} LogMessage;

/* *************************** */

#define COLOR_1               "#CCCCFF"
#define COLOR_2               "#FFCCCC"
#define COLOR_3               "#EEEECC"
#define COLOR_4               "#FF0000"

#define BUF_SIZE               1024

#define DUMMY_IDX_VALUE         999

#define HOST_DUMMY_IDX_VALUE     99
#define HOST_DUMMY_IDX_STR      "99"

#define DOMAIN_DUMMY_IDX_VALUE  98
#define DOMAIN_DUMMY_IDX_STR    "98"

/* **************************** */

#ifndef WNOHANG
#define WNOHANG 1
#endif

/* **************************** */

/* The #ifdef below are nnede for some BSD systems
 * Courtesy of Kimmo Suominen <kim@tac.nyc.ny.us>
 */
#ifndef ETHERTYPE_DN
#define ETHERTYPE_DN           0x6003
#endif
#ifndef ETHERTYPE_ATALK
#define ETHERTYPE_ATALK        0x809b
#endif

/* ******** Token Ring ************ */

#if defined(WIN32)
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


#define TRMTU                      2000   /* 2000 bytes            */

#define TR_RII                     0x80
#define TR_RCF_DIR_BIT             0x80
#define TR_RCF_LEN_MASK            0x1f00
#define TR_RCF_BROADCAST           0x8000 /* all-routes broadcast   */
#define TR_RCF_LIMITED_BROADCAST   0xC000 /* single-route broadcast */
#define TR_RCF_FRAME2K             0x20
#define TR_RCF_BROADCAST_MASK      0xC000

/* ******** FDDI ************ */

#if defined(LBL_ALIGN)
#define EXTRACT_16BITS(p) \
	((u_short)*((u_char *)(p) + 0) << 8 | \
	(u_short)*((u_char *)(p) + 1))
#define EXTRACT_32BITS(p) \
	((u_int32_t)*((u_char *)(p) + 0) << 24 | \
	(u_int32_t)*((u_char *)(p) + 1) << 16 | \
	(u_int32_t)*((u_char *)(p) + 2) << 8 | \
	(u_int32_t)*((u_char *)(p) + 3))
#else
#define EXTRACT_16BITS(p) \
	((u_short)ntohs(*(u_short *)(p)))
#define EXTRACT_32BITS(p) \
	((u_int32_t)ntohl(*(u_int32_t *)(p)))
#endif

#define EXTRACT_24BITS(p) \
	((u_int32_t)*((u_char *)(p) + 0) << 16 | \
	(u_int32_t)*((u_char *)(p) + 1) << 8 | \
	(u_int32_t)*((u_char *)(p) + 2))


typedef struct fddi_header {
  u_char  fc;	    /* frame control    */
  u_char  dhost[6]; /* destination host */
  u_char  shost[6]; /* source host      */
} FDDI_header;

#define FDDI_HDRLEN (sizeof(struct fddi_header))

/*
 * FDDI Frame Control bits
 */
#define	FDDIFC_C		0x80		/* Class bit */
#define	FDDIFC_L		0x40		/* Address length bit */
#define	FDDIFC_F		0x30		/* Frame format bits */
#define	FDDIFC_Z		0x0f		/* Control bits */

/*
 * FDDI Frame Control values. (48-bit addressing only).
 */
#define	FDDIFC_VOID		0x40		/* Void frame */
#define	FDDIFC_NRT		0x80		/* Nonrestricted token */
#define	FDDIFC_RT		0xc0		/* Restricted token */
#define	FDDIFC_SMT_INFO		0x41		/* SMT Info */
#define	FDDIFC_SMT_NSA		0x4F		/* SMT Next station adrs */
#define	FDDIFC_MAC_BEACON	0xc2		/* MAC Beacon frame */
#define	FDDIFC_MAC_CLAIM	0xc3		/* MAC Claim frame */
#define	FDDIFC_LLC_ASYNC	0x50		/* Async. LLC frame */
#define	FDDIFC_LLC_SYNC		0xd0		/* Sync. LLC frame */
#define	FDDIFC_IMP_ASYNC	0x60		/* Implementor Async. */
#define	FDDIFC_IMP_SYNC		0xe0		/* Implementor Synch. */
#define FDDIFC_SMT		0x40		/* SMT frame */
#define FDDIFC_MAC		0xc0		/* MAC frame */

#define	FDDIFC_CLFF		0xF0		/* Class/Length/Format bits */
#define	FDDIFC_ZZZZ		0x0F		/* Control bits */

/* ************ GRE (Generic Routing Encapsulation) ************* */

#define GRE_PROTOCOL_TYPE  0x2F

typedef struct greTunnel {
  u_int16_t	flags,     protocol;
  u_int16_t	payload,   callId;
  u_int32_t	seqAckNumber;
} GreTunnel;

#define PPP_PROTOCOL_TYPE  0x880b

typedef struct pppTunnelHeader {
  u_int16_t	unused, protocol;
} PPPTunnelHeader;

/* ************ PPP ************* */

#define PPP_HDRLEN  4

/* ******************************** */
#ifndef DLT_RAW
#define DLT_RAW		12	/* raw IP */
#endif

#ifndef DLT_SLIP_BSDOS
#define DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#endif

#ifndef DLT_PPP_BSDOS
#define DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */
#endif

/* ******************************** */

#ifndef NAME_MAX
#define NAME_MAX 255
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

/* ******************************** */

#ifdef _AIX
#define AIX
#endif

#include "globals-core.h"

#ifndef SEC_POPEN
#define sec_popen(a,b) popen(a,b)
#endif

#endif /* NTOP_H */
