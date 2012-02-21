/*
 *  Copyright (C) 1998-2012 Luca Deri <deri@ntop.org>
 *                      
 *  			    http://www.ntop.org/
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
#include <direct.h>

#if defined(WIN32)
#include "Packet32.h"

#if defined(__GNUC__)
/* on mingw, the definitions we need are in pcap.h - Scott Renfro <scott@renfro.org> */
#include "pcap.h"
#endif
#include "dirent.h"

#ifndef EADDRINUSE
#define EADDRINUSE              WSAEADDRINUSE
#endif

#ifndef ENOTSOCK
#define ENOTSOCK                WSAENOTSOCK
#endif

#ifndef EOPNOTSUPP
#define EOPNOTSUPP              WSAEOPNOTSUPP
#endif

#ifndef NS_INT16SZ
#define NS_INT16SZ	2
#endif

#ifndef NS_CMPRSFLGS
#define NS_CMPRSFLGS	0xc0
#endif

#ifndef NS_MAXCDNAME
#define NS_MAXCDNAME	255
#endif

/* Courtesy of Wies-Software <wies@wiessoft.de> */
extern char* getadminpass(const char *prompt);
extern unsigned long waitForNextEvent(unsigned long ulDelay /* ms */);
extern u_char isNtopAservice;

extern char _wdir[], VERSION[];

#ifndef CFG_DATAFILE_DIR
#define CFG_DATAFILE_DIR	_wdir
#endif

/* ndis.h */
typedef int NDIS_STATUS, *PNDIS_STATUS; 

/* ******************* */

#define socklen_t int
#define strcasecmp _stricmp
#define snprintf _snprintf

#define HAVE_GETOPT_LONG

extern int getopt(int num, char *const *argv, const char *opts);
#define getopt getopt____
#define putenv _putenv
#define unlink(a) _unlink(a)
#define close(a) _close(a)

/* USed by dup2() */
#define STDIN_FILENO    0
#define STDOUT_FILENO   1

#if defined(__GNUC__)
/* on mingw, struct timezone isn't defined so s/struct timezone/void/ - Scott Renfro <scott@renfro.org> */
extern int gettimeofday(struct timeval*, void*);
#else
extern int gettimeofday(struct timeval*, struct timezone*);
#endif
extern unsigned long waitForNextEvent(unsigned long ulDelay /* ms */);

extern int getopt_long (int argc, char *const *argv, const char *options,
						const struct option *long_options, int *opt_index);

extern void printAvailableInterfaces();
extern char* getpass(const char *prompt);
extern ULONG GetHostIPAddr();

#define MAKE_WITH_ZLIB
#define HAVE_DIRENT_H
#define HAVE_PCAP_FREEALLDEVS
#define HAVE_PYTHON 1
#define HAVE_GEOIP

#if !defined(__GNUC__)
#define in6_addr in_addr6
#endif

#define pthread_self GetCurrentThreadId

#define SHUT_RDWR SD_BOTH
#define in_addr_t u_int32_t 

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

#if defined(WIN32) && defined(__GNUC__) && !defined(__MINGW32__)
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
fstruct dirent *readdir(DIR *);
void          rewinddir(DIR *);

#endif


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

/*
 * Ethernet address - 6 octets
 */
struct ether_addr {
  u_char ether_addr_octet[6];
};

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct	ether_header {
  u_char	ether_dhost[6];
  u_char	ether_shost[6];
  u_short	ether_type;
};

#define	ETHeRTYPE_PUP		0x0200	/* PUP protocol */
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#define ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */


/************************************************************************/

/* on mingw, tcp_seq is defined - Scott Renfro <scott@renfro.org> */
#if defined (WIN32) && !defined (tcp_seq)
typedef	u_int	tcp_seq;
#endif

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
						// i byte pi¹ e meno significativi risultano
						// scambiati

	BYTE Dati[1500];	// Dati contenuti nel pacchetto
}  FRAMEETH, *PFRAMEETH;

/* ********************************************* */

struct icmp_ra_addr
{
  u_int32_t ira_addr;
  u_int32_t ira_preference;
};

/*                                                                                                                                                                        
 * Structure of an icmp header.                                                                                                                                           
 */
struct icmp
{
  u_int8_t  icmp_type;  /* type of message, see below */
  u_int8_t  icmp_code;  /* type sub code */
  u_int16_t icmp_cksum; /* ones complement checksum of struct */
  union
  {
    u_char ih_pptr;             /* ICMP_PARAMPROB */
    struct in_addr ih_gwaddr;   /* gateway address */
    struct ih_idseq             /* echo datagram */
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
#define icmp_pptr       icmp_hun.ih_pptr
#define icmp_gwaddr     icmp_hun.ih_gwaddr
#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void       icmp_hun.ih_void
#define icmp_pmvoid     icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa        icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
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
#define icmp_otime      icmp_dun.id_ts.its_otime
#define icmp_rtime      icmp_dun.id_ts.its_rtime
#define icmp_ttime      icmp_dun.id_ts.its_ttime
#define icmp_ip         icmp_dun.id_ip.idi_ip
#define icmp_radv       icmp_dun.id_radv
#define icmp_mask       icmp_dun.id_mask
#define icmp_data       icmp_dun.id_data
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

extern void initWinsock32();
extern void termWinsock32();
extern void sniffSinglePacket(void(*pbuf_process)(u_char *unused, 
		  const struct pcap_pkthdr *h, 
		  const u_char *p));

extern char* strptime(const char *buf, const char *fmt, struct tm *tm);

/* ********************************************* */

// Max number of packets handled by the public version
#define MAX_NUM_PACKETS   2000

extern short isWinNT();
extern void get_serial(unsigned long *driveSerial);

//#define WIN32_DEMO
#endif
