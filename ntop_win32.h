/*
 *  Copyright (C) 1998-99 Luca Deri <deri@ntop.org>
 *                        Portions by Stefano Suin <stefano@ntop.org>
 *                      
 *  			  http://www.ntop.org/
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


#include <winsock2.h> /* winsock.h is included automatically */

#define HAVE_GDBM_H
#define HAVE_GDCHART
#define MULTITHREADED
#define ASYNC_ADDRESS_RESOLUTION

#define STATIC_PLUGIN

#define sleep(a /* sec */) Sleep(1000*a /* ms */)

#define DATAFILE_DIR	"."
#define PLUGIN_DIR		"."
#define CONFIGFILE_DIR	"."
#define DBFILE_DIR      "."

/* ndis.h */
typedef int NDIS_STATUS, *PNDIS_STATUS; 

/* ******************* */

/* typedef ULONGLONG TrafficCounter; */
/* typedef unsigned long TrafficCounter; */
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
typedef unsigned int tcp_seq;
/*
typedef unsigned long u_int32, u_int32_t;
typedef long int32_t;
*/

#define strcasecmp _stricmp

extern int getopt(int num, char *const *argv, const char *opts);
extern int gettimeofday(struct timeval*, struct timezone*);

extern ULONG GetHostIPAddr();

#define RETSIGTYPE void


#define	ETHERMTU	1500

#define DLT_NULL	0	/* no link-layer encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#define DLT_AX25	3	/* Amateur Radio AX.25 */
#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define DLT_CHAOS	5	/* Chaos */
#define DLT_IEEE802	6	/* IEEE 802 Networks */
#define DLT_ARCNET	7	/* ARCNET */
#define DLT_SLIP	8	/* Serial Line IP */
#define DLT_PPP		9	/* Point-to-point Protocol */
#define DLT_FDDI	10	/* FDDI */
#define DLT_ATM_RFC1483	11	/* LLC/SNAP encapsulated atm */
#define DLT_RAW		12	/* raw IP */
#define DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#define DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */

/*
 * Ethernet address - 6 octets
 */
struct ether_addr {
	u_char	ether_addr_octet[6];
};

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct	ether_header {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	u_short	ether_type;
};

#define	ETHERTYPE_PUP		0x0200	/* PUP protocol */
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#define ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */


/************************************************************************/

typedef	u_int	tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
	u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	tcp_seq	th_seq;			/* sequence number */
	tcp_seq	th_ack;			/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	th_x2:4,		/* (unused) */
		th_off:4;		/* data offset */
#else
	u_char	th_off:4,		/* data offset */
		th_x2:4;		/* (unused) */
#endif
	u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
};

/* ********************************************* */

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
#else
	u_char	ip_v:4,			/* version */
		ip_hl:4;		/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	short	ip_off;			/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

/* ********************************************* */

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udphdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};

/* ********************************************* */

typedef struct _FRAMEETH
{
	BYTE DestAddr[6];   // Indirizzo ethernet destinazione
	BYTE SrcAddr[6];	// Indirizzo ethernet sorgente

	BYTE Type[2];		// Tipo di pacchetto (o lunghezza per IEEE 802.3)
						// il valore deve essere letto con la relazione:
						//      256 * Type[0] + Type[1]
						// e non semplicemente con un cast esplicito ad 
						// uno short, altrimenti (su una macchina INTEL) 
						// i byte pi¸ e meno significativi risultano
						// scambiati

	BYTE Dati[1500];	// Dati contenuti nel pacchetto
}  FRAMEETH, *PFRAMEETH;

/* ********************************************* */

struct icmp_ra_addr
{
  u_int32_t ira_addr;
  u_int32_t ira_preference;
};

struct icmp
{
  u_int8_t  icmp_type;	/* type of message, see below */
  u_int8_t  icmp_code;	/* type sub code */
  u_int16_t icmp_cksum;	/* ones complement checksum of struct */
  union
  {
    u_char ih_pptr;		/* ICMP_PARAMPROB */
    struct in_addr ih_gwaddr;	/* gateway address */
    struct ih_idseq		/* echo datagram */
    {
      u_int16_t icd_id;
      u_int16_t icd_seq;
    } ih_idseq;
    u_int32_t ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    struct ih_pmtu
    {
      u_int16_t ipm_void;
      u_int16_t ipm_nextmtu;
    } ih_pmtu;

    struct ih_rtradv
    {
      u_int8_t irt_num_addrs;
      u_int8_t irt_wpa;
      u_int16_t irt_lifetime;
    } ih_rtradv;
  } icmp_hun;
#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
#define	icmp_pmvoid	icmp_hun.ih_pmtu.ipm_void
#define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
#define	icmp_num_addrs	icmp_hun.ih_rtradv.irt_num_addrs
#define	icmp_wpa	icmp_hun.ih_rtradv.irt_wpa
#define	icmp_lifetime	icmp_hun.ih_rtradv.irt_lifetime
  union
  {
    struct
    {
      u_int32_t its_otime;
      u_int32_t its_rtime;
      u_int32_t its_ttime;
    } id_ts;
    struct
    {
      struct ip idi_ip;
      /* options and then 64 bits of data */
    } id_ip;
    struct icmp_ra_addr id_radv;
    u_int32_t   id_mask;
    u_int8_t    id_data[1];
  } icmp_dun;
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_radv	icmp_dun.id_radv
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data
};

/*
 * Definition of type and code field values.
 */
#define	ICMP_ECHOREPLY		0		/* echo reply */
#define	ICMP_UNREACH		3		/* dest unreachable, codes: */
#define	ICMP_UNREACH_NET	0		/* bad net */
#define	ICMP_UNREACH_HOST	1		/* bad host */
#define	ICMP_UNREACH_PROTOCOL	2		/* bad protocol */
#define	ICMP_UNREACH_PORT	3		/* bad port */
#define	ICMP_UNREACH_NEEDFRAG	4		/* IP_DF caused drop */
#define	ICMP_UNREACH_SRCFAIL	5		/* src route failed */
#define	ICMP_SOURCEQUENCH	4		/* packet lost, slow down */
#define	ICMP_REDIRECT		5		/* shorter route, codes: */
#define	ICMP_REDIRECT_NET	0		/* for network */
#define	ICMP_REDIRECT_HOST	1		/* for host */
#define	ICMP_REDIRECT_TOSNET	2		/* for tos and net */
#define	ICMP_REDIRECT_TOSHOST	3		/* for tos and host */
#define	ICMP_ECHO		8		/* echo service */
#define	ICMP_TIMXCEED		11		/* time exceeded, code: */
#define	ICMP_TIMXCEED_INTRANS	0		/* ttl==0 in transit */
#define	ICMP_TIMXCEED_REASS	1		/* ttl==0 in reass */
#define	ICMP_PARAMPROB		12		/* ip header bad */
#define	ICMP_TSTAMP		13		/* timestamp request */
#define	ICMP_TSTAMPREPLY	14		/* timestamp reply */
#define	ICMP_IREQ		15		/* information request */
#define	ICMP_IREQREPLY		16		/* information reply */
#define	ICMP_MASKREQ		17		/* address mask request */
#define	ICMP_MASKREPLY		18		/* address mask reply */

#define	ICMP_MAXTYPE		18

/* ********************************************* */

/*
 * Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  ARP packets are variable
 * in size; the arphdr structure defines the fixed-length portion.
 * Protocol type values are the same as those for 10 Mb/s Ethernet.
 * It is followed by the variable-sized fields ar_sha, arp_spa,
 * arp_tha and arp_tpa in that order, according to the lengths
 * specified.  Field names used correspond to RFC 826.
 */
struct	arphdr {
	u_short ar_hrd;	/* format of hardware address */
#define	ARPHRD_ETHER 	1	/* ethernet hardware address */
	u_short ar_pro;	/* format of protocol address */
	u_char	ar_hln;		/* length of hardware address */
	u_char	ar_pln;		/* length of protocol address */
	u_short ar_op;		/* one of: */
#define	ARPOP_REQUEST	1	/* request to resolve address */
#define	ARPOP_REPLY	2	/* response to previous request */
#define	REVARP_REQUEST	3	/* Reverse ARP request */
#define	REVARP_REPLY	4	/* Reverse ARP reply */
	/*
	 * The remaining fields are variable in size,
	 * according to the sizes above, and are defined
	 * as appropriate for specific hardware/protocol
	 * combinations.  (E.g., see <netinet/if_ether.h>.)
	 */
#ifdef	notdef
	uchar_t	ar_sha[];	/* sender hardware address */
	uchar_t	ar_spa[];	/* sender protocol address */
	uchar_t	ar_tha[];	/* target hardware address */
	uchar_t	ar_tpa[];	/* target protocol address */
#endif	/* notdef */
};

#define ETH_ALEN  6

struct	ether_arp {
	struct	arphdr ea_hdr;		/* fixed-size header */
	u_int8_t arp_sha[ETH_ALEN];	/* sender hardware address */
	u_int8_t arp_spa[4];		/* sender protocol address */
	u_int8_t arp_tha[ETH_ALEN];	/* target hardware address */
	u_int8_t arp_tpa[4];		/* target protocol address */
};
#define	arp_hrd	ea_hdr.ar_hrd
#define	arp_pro	ea_hdr.ar_pro
#define	arp_hln	ea_hdr.ar_hln
#define	arp_pln	ea_hdr.ar_pln
#define	arp_op	ea_hdr.ar_op

/* ********************************************* */

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

#define EMSGSIZE    97 /* Inappropriate message buffer length */

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

/* ********************************************* */

extern void initWinsock32();
extern void termWinsock32();
extern void sniffSinglePacket(void(*pbuf_process)(u_char *unused, 
		  const struct pcap_pkthdr *h, 
		  const u_char *p));

#define close(fd) closesocket(fd)

/* ********* MULTITHREAD STUFF ********* */

#define pthread_t              HANDLE
#define pthread_mutex_t        HANDLE
#define pthread_cond_t         HANDLE


typedef struct conditionalVariable {
	HANDLE condVar;
	CRITICAL_SECTION criticalSection;
} ConditionalVariable;

/* ********************************************* */

// Max number of packets handled by the public version
#define MAX_NUM_PACKETS   1000

extern short isWinNT();
extern int SIZE_BUF;

/* #define WIN32_DEMO */
