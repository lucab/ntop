/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 2003      Abdelkader Lahmadi <Abdelkader.Lahmadi@loria.fr>
 *                         Olivier Festor <Olivier.Festor@loria.fr>
 * Copyright (C) 2003-12   Luca Deri <deri@ntop.org>
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

#ifndef _IFACE_H_
#define _IFACE_H_

/* ******************************** */

#ifdef WIN32
struct icmp6_hdr
  {
    u_int8_t     icmp6_type;   /* type field */
    u_int8_t     icmp6_code;   /* code field */
    u_int16_t    icmp6_cksum;  /* checksum field */
    union
      {
        u_int32_t  icmp6_un_data32[1]; /* type-specific field */
        u_int16_t  icmp6_un_data16[2]; /* type-specific field */
        u_int8_t   icmp6_un_data8[4];  /* type-specific field */
      } icmp6_dataun;
  };
#endif

#ifndef ICMP6_NI_REPLY 
#define ICMP6_NI_REPLY 140
#endif

#ifndef ICMP6_ECHO_REPLY
#define ICMP6_ECHO_REPLY 129
#endif

#ifndef ICMP6_ECHO_REQUEST
#define ICMP6_ECHO_REQUEST 128
#endif

#ifndef ICMP6_DST_UNREACH
#define ICMP6_DST_UNREACH 1
#endif

#ifndef ICMP6_TIME_EXCEEDED
#define ICMP6_TIME_EXCEEDED 3
#endif

#ifndef ICMP6_PARAM_PROB
#define ICMP6_PARAM_PROB 4
#endif

#ifndef ICMP6_NI_QUERY
#define ICMP6_NI_QUERY 139
#endif

#ifndef ICMP6_NI_REPLY
#define ICMP6_NI_REPLY 140
#endif

#ifndef ICMP6_DST_UNREACH
#define ICMP6_DST_UNREACH 1
#endif

#ifndef ICMP6_DST_UNREACH_NOPORT
#define ICMP6_DST_UNREACH_NOPORT 4
#endif

#ifndef ICMP6_DST_UNREACH_NOROUTE
#define ICMP6_DST_UNREACH_NOROUTE 0
#endif

#ifndef ICMP6_DST_UNREACH_ADDR
#define ICMP6_DST_UNREACH_ADDR 3
#endif

#ifndef ICMP6_DST_UNREACH_ADMIN
#define ICMP6_DST_UNREACH_ADMIN 1
#endif

#ifndef ND_ROUTER_SOLICIT
#define ND_ROUTER_SOLICIT 133
#endif

#ifndef ND_ROUTER_ADVERT
#define ND_ROUTER_ADVERT 134
#endif

#ifndef ND_NEIGHBOR_SOLICIT
#define ND_NEIGHBOR_SOLICIT 135
#endif

#ifndef ND_NEIGHBOR_ADVERT
#define ND_NEIGHBOR_ADVERT 136
#endif

#ifndef ND_REDIRECT
#define ND_REDIRECT 137
#endif

/* ******************************** */

#define IFACE_TYPE_ALL		0x00
#define IFACE_TYPE_UNKNOWN	0x00

#define	IFACE_TYPE_ETHER	0x06		/* Ethernet CSMACD */
#define	IFACE_TYPE_FDDI		0x0f
#define	IFACE_TYPE_LAPB		0x10
#define	IFACE_TYPE_SDLC		0x11
#define	IFACE_TYPE_ISDNBASIC	0x14
#define	IFACE_TYPE_ISDNPRIMARY	0x15
#define	IFACE_TYPE_PPP		0x17		/* RFC 1331 */
#define	IFACE_TYPE_LOOP		0x18		/* loopback */
#define	IFACE_TYPE_SLIP		0x1c		/* IP over generic TTY */
#define	IFACE_TYPE_RS232	0x21
#define	IFACE_TYPE_PARA		0x22		/* parallel-port */
#define	IFACE_TYPE_ATM		0x25		/* ATM cells */
#define	IFACE_TYPE_SONET	0x27		/* SONET or SDH */
#define	IFACE_TYPE_MODEM	0x30		/* Generic Modem */
#define	IFACE_TYPE_SONETPATH	0x32
#define	IFACE_TYPE_SONETVT	0x33

#define	IFACE_TYPE_GIF		0x37		/*0xf0*/
#define	IFACE_TYPE_FAITH	0x38		/*0xf2*/
#define	IFACE_TYPE_STF		0x39		/*0xf3*/
#define	IFACE_TYPE_L2VLAN	0x87		/* Layer 2 VLAN using 802.1Q */
#define	IFACE_TYPE_IEEE1394	0x90		/* IEEE1394 SerialBus */


#define IFACE_INFO_UP		0x01
#define IFACE_INFO_LOOPBACK	0x02
#define IFACE_INFO_P2P		0x04
#define IFACE_INFO_BROADCAST	0x08
#define IFACE_INFO_MULTICAST	0x10
#define IFACE_INFO_PROMISC	0x20
#define IFACE_INFO_SIMPLEX	0x40

#define _IFACE_ADDR_INET
#define _IFACE_ADDR_INET6

/* ******************************** */

#ifdef WIN32
/* Fragment header */
struct ip6_frag
  {
    u_int8_t   ip6f_nxt;       /* next header */
    u_int8_t   ip6f_reserved;  /* reserved field */
    u_int16_t  ip6f_offlg;     /* offset, reserved, and flag */
    u_int32_t  ip6f_ident;     /* identification */
  };
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN  46
#endif

#if defined _IFACE_ADDR_INET
struct iface_addr_inet {
  struct in_addr	addr;
  struct in_addr	bcast;
  int			mask;
};
#endif

#if defined _IFACE_ADDR_INET6
struct iface_addr_inet6 {
  struct in6_addr	addr;
  int			prefixlen;
};
#endif

#ifndef IFF_SIMPLEX
#define IFF_SIMPLEX 0x0
#endif

struct iface_addr {
  int			 family;
  struct iface_if	*ifi;
  struct iface_addr	*next;
  union {
    struct iface_addr_inet	inet;
    struct iface_addr_inet6	inet6;
  } af;
};

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

struct iface_if {
  int			 index;
  int			 info;
  char		 name[IFNAMSIZ];
  int			 type;
  struct {
    char	*addr;
    int	 size;
  }			 phys;
  struct iface_addr	*addrs;
  struct iface_if	*next;
};



struct iface_handler {
  char *buf;
  struct iface_if *if_list;
  int if_count;
  struct iface_addr *addr_list;
  int addr_count;
  struct rt_addrinfo *addrinfo;
};


/**
 * @brief Retrieve a list of interfaces supporting IPv6.
 * @param idx array where to store interface index.
 * @param size size of the @c idx array.
 * @return number of interfaces retrieved.
 *
 * @deprecated you should look by yourself using the iface_* functions
 *
 * The list retrieve are all the interfaces which:
 *  - are UP
 *  - have at least one IPv6 address (even link local)
 *  - are not the loopback interface
 *
 * If <code>idx</code> is set to <code>NULL</code>, the total number of 
 *	interfaces available will be returned.
 */
int iface6(int *idx, int size);


/**
 * @brief Create a new iface handler holding all the
 *	information about the interfaces at the time it was called.
 * @return iface handler
 */
struct iface_handler *iface_new(void);

/**
 * @brief Destroy iface handler.
 * @param hdlr iface handler
 */
void iface_destroy(struct iface_handler *hdlr);

/**
 * @brief Get the number of addresses associated.
 * @param hdlr  iface handler.
 * @return total number of addresses
 */
int iface_addrcount(struct iface_handler *hdlr);


/**
 * @brief Get the number of interfaces.
 * @param hdlr  iface handler.
 * @return number of interfaces.
 */
int iface_ifcount(struct iface_handler *hdlr);


/**
 * @brief Get the first interface.
 * @param hdlr iface handler.
 * @return an interface descriptor.
 */
struct iface_if *iface_getif_first(struct iface_handler *hdlr);


/**
 * @brief Get the next interface.
 * @param ii interface descriptor.
 * @return an interface descriptor or <code>NULL<code> 
 *	if <code>ii==NULL</code>.
 */
struct iface_if *iface_getif_next(struct iface_if *ii);


/**
 * @brief Give the number of addresses associated to an interface.
 * @param ii interface descriptor.
 * @param family family address to count, if 0 all addresses are counted.
 * @return number of addresses.
 */
int iface_if_addrcount(struct iface_if *ii, int family);


/**
 * @brief Retrieve interface by its index number.
 * @param hdlr iface handler.
 * @param index interface index.
 * @return interface descriptor
 */
struct iface_if *iface_getif_byindex(struct iface_handler *hdlr, int idx);


/**
 * @brief Retrieve interface by its name.
 * @param hdlr iface handler.
 * @param name interface name.
 * @return interface descriptor
 */
struct iface_if *iface_getif_byname(struct iface_handler *hdlr, char *name);


/**
 * @brief Converts interface index to readable interface name.
 * @param ii  interface descriptor
 * @param name  buffer where to write interface name.
 * @param size  size of the buffer.
 * @return <code>name</code>
 *
 * @note To check if there was enough room when writing the
 *	interface name you could test <code>name[size-1]</code>,
 *	or use <code>IFNAMSIZ</code> for size (see net/if.h)
 *
 * @note It is possible to use <code>NULL</code> instead of 
 *	passing a buffer for the interface name,
 *	in this case an allocated string will be returned, and
 *	should be freed using <code>free</code>.
 *	If allocation had failed <code>NULL</code> wil be returned.
 */
char *iface_if_getname(struct iface_if *ii, char *name, int size);


/**
 * @brief Return interface index.
 * @param ii  interface descriptor
 * @return interface index.
 */
int iface_if_getindex(struct iface_if *ii);


/**
 * @brief Return information flags about the interface
 * @param ii interface descriptor.
 * @return information flags as defined by IFACE_INFO_*.
 */
int iface_if_getinfo(struct iface_if *ii);


/**
 * @brief Return interface type.
 * @param ii interface descriptor.
 * @return the interface type as defined by IFACE_TYPE_*.
 */
int iface_if_gettype(struct iface_if *ii);


/**
 * @brief Retrieve the physical address of an interface.
 * @param ii interface descriptor.
 * @param type a pointer where will be stored the interface type
 *	or <code>NULL</code>
 * @param addr a pointer where to store the physical address
 *	or <code>NULL</code>
 * @param addrlen the available size for <code>addr</code>
 *	or <code>NULL</code> if<code>addr</code> is <code>NULL</code> 
 * @return the real address size when successful, <code>0</code>
 *	if the interface doesn't have a physical address.
 *
 * After returning, the copied addresse size will be stored in
 *	<code>addrsize</code>.
 *
 * @note when retrieving the physical addresse of an interface,
 *	you could call <code>iface_getphys</code> once for
 *	retriving type and addresse size and another time 
 *	for retrieving the physical address.
 */
int iface_if_getphys(struct iface_if *ii, int *type, char *addr, int *addrsize);


/**
 * @brief get the first address assiociated with the interface.
 * @param ii interface descriptor.
 * @param family family of the address wanted (<code>AF_*</code>) 
 *	or <code>0</code> as a wildcard.
 * @return an address descriptor.
 */
struct iface_addr *iface_getaddr_first(struct iface_if *ii, int family);

/**
 * @brief get the next address assiociated with the interface.
 * @param ia  address descripor
 * @param family family of the address wanted (<code>AF_*</code>) 
 *	or <code>0</code> as a wildcard.
 * @return an address descriptor or <code>NULL<code> if <code>ia==NULL</code>.
 *
 * @note you should not change <code>family</code> between calls to
 *	iface_getaddr_first or iface_getaddr_next
 */
struct iface_addr *iface_getaddr_next(struct iface_addr *ia, int family);


/**
 * @brief Get the address family.
 * @param ahdlr  address descripor
 * @return address family
 */
int iface_addr_getfamily(struct iface_addr *ia);


/**
 * @brief Get the interface index on which the address is associated
 * @param ahdlr  address descripor
 * @return interface index
 */
int iface_addr_ifindex(struct iface_addr *ia);


/**
 * @brief return information about the address.
 * @param ahdlr  address descripor
 * @return <code>infobuf</code> or <code>NULL</code> on error.
 *
 * The <code>infobuf</code> is one of the iface_addr_* structures
 * and should be coherent with the address family, to have 
 * the structure defined you should define the constant _IFACE_ADDR_*
 * before the inclusion of the iface header.
 */
void *iface_addr_getinfo(struct iface_addr *ia, void *infobuf);

#endif /* _IFACE_H_ */

extern void calculateUniqueInterfaceName(int deviceId);
extern void sanitizeIfName(char *deviceDescr);

#ifdef HAVE_SNMP
extern char* getIfName(char *hostname, char *community, int ifIdx,
		       char *ifName_buf, u_short ifName_buflen);
#endif
