/**
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
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
#include <stdarg.h>

/* #define ADDRESS_DEBUG */

#ifdef MEMORY_DEBUG
#include "leaks.h"
#endif

#ifdef DARWIN
extern void* perl_alloc();
extern void* perl_parse();
extern void* perl_get_hv();
extern void* perl_get_av();
extern void* perl_run();
extern void* perl_construct();
extern void* perl_destruct();
extern void* perl_free();
#endif

#ifdef CFG_MULTITHREADED
static char stateChangeMutexInitialized = 0;
static pthread_mutex_t stateChangeMutex;
#endif

static SessionInfo *passiveSessions;
static u_short passiveSessionsLen;

static char *versionSite[]   = { 
  CONST_VERSIONCHECK_SITE,
  CONST_VERSIONCHECK_BACKUP_SITE,
  NULL };

/* ************************************ */

static HostTraffic* _getFirstHost(u_int actualDeviceId, u_int beginIdx) {
  u_int idx;

  for(idx=beginIdx; idx<myGlobals.device[actualDeviceId].actualHashSize; idx++) {
    HostTraffic *el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];

    if(el != NULL) {
      if(el->magic != CONST_MAGIC_NUMBER) {
	traceEvent(CONST_TRACE_WARNING, "Error: bad magic number (expected=%d/real=%d)",
		   CONST_MAGIC_NUMBER, el->magic);
      }

      return(el);
    }
  }

  return(NULL);
}

/* ************************************ */

HostTraffic* getFirstHost(u_int actualDeviceId) {
  return(_getFirstHost(actualDeviceId, FIRST_HOSTS_ENTRY));
}

/* ************************************ */

HostTraffic* getNextHost(u_int actualDeviceId, HostTraffic *host) {
  if(host == NULL) return(NULL);

  if(host->next != NULL) {
    if(host->next->magic != CONST_MAGIC_NUMBER) {
      traceEvent(CONST_TRACE_WARNING, "Error: bad magic number (expected=%d/real=%d)",
		 CONST_MAGIC_NUMBER, host->next->magic);
    }

    return(host->next);
  } else {
    u_int nextIdx = host->hostTrafficBucket+1;

    if(nextIdx < myGlobals.device[actualDeviceId].actualHashSize)
      return(_getFirstHost(actualDeviceId, nextIdx));
    else
      return(NULL);
  }
}

/* ************************************ */

HostTraffic* findHostByNumIP(HostAddr hostIpAddress, u_int actualDeviceId) {
  HostTraffic *el;
  short dummyShort=1;
  u_int idx = hashHost(&hostIpAddress, NULL, &dummyShort, &el, actualDeviceId);

  if(el != NULL)
    return(el); /* Found */
  else if(idx == FLAG_NO_PEER)
    return(NULL);
  else
    el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];

  for(; el != NULL; el = el->next) {
    if((el->hostNumIpAddress != NULL) && (addrcmp(&el->hostIpAddress,&hostIpAddress) == 0))
      return(el);
  }

  if(el == NULL) {
    /*
      Fallback:
      probably a local host has been searched using an IP
      address (we should have used a MAC)
    */

    for(idx=0; idx<myGlobals.device[actualDeviceId].actualHashSize; idx++) {
      el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];

      for(; el != NULL; el = el->next) {
	if((el->hostNumIpAddress != NULL) && (addrcmp(&el->hostIpAddress,&hostIpAddress) == 0))
	  return(el);
      }
    }  }

#ifdef DEBUG
  {
    char buf[48];

    traceEvent(CONST_TRACE_NOISY, "==>>> Unable to locate host %s",
	       _intoa(hostIpAddress, buf, sizeof(buf)));
  }
#endif

  return(NULL);
}

/* ************************************ */

HostTraffic* findHostBySerial(HostSerial theSerial, u_int actualDeviceId) {
  if(theSerial.serialType == SERIAL_IPV4 || theSerial.serialType == SERIAL_IPV6) {
    return(findHostByNumIP(theSerial.value.ipAddress, actualDeviceId));
  } else {
    /* MAC */
    return(findHostByMAC(theSerial.value.ethAddress, actualDeviceId));
  }
}

/* ************************************ */

HostTraffic* findHostByMAC(char* macAddr, u_int actualDeviceId) {
  HostTraffic *el;
  short dummyShort = 0;
  u_int idx = hashHost(NULL, macAddr, &dummyShort, &el, actualDeviceId);

  if(el != NULL)
    return(el); /* Found */
  else if(idx == FLAG_NO_PEER)
    return(NULL);
  else
    el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];

  for(; el != NULL; el = el->next) {
    if((el->ethAddress[0] != '\0') && (!strncmp(el->ethAddress, macAddr, LEN_ETHERNET_ADDRESS)))
      return(el);
  }

  return(NULL);
}

/* *****************************************************/

#ifdef INET6
unsigned long in6_hash(struct in6_addr *addr) {
  return
    (addr->s6_addr[13]      ) | (addr->s6_addr[15] << 8) |
    (addr->s6_addr[14] << 16) | (addr->s6_addr[11] << 24);

}
#endif

/* *************************************** */

unsigned short computeIdx(HostAddr *srcAddr, HostAddr *dstAddr, int sport, int dport) {

  unsigned short idx;
  if (srcAddr->hostFamily != dstAddr->hostFamily)
    return -1;
  switch (srcAddr->hostFamily){
  case AF_INET:
    /*
     * The hash key has to be calculated in a specular
     * way: its value has to be the same regardless
     * of the flow direction.
     *
     * Patch on the line below courtesy of
     * Paul Chapman <pchapman@fury.bio.dfo.ca>
     */
    idx = (u_int)(dstAddr->Ip4Address.s_addr+srcAddr->Ip4Address.s_addr+sport+dport) ;
    break;
#ifdef INET6
  case AF_INET6:
    idx = (u_int)(dstAddr->Ip6Address.s6_addr[0] +
		  dstAddr->Ip6Address.s6_addr[0] +
		  srcAddr->Ip6Address.s6_addr[0] +
		  srcAddr->Ip6Address.s6_addr[0] + sport +! dport);
    break;
#endif
  }
  return idx;
}

/* ******************************************** */

u_int16_t computeTransId(HostAddr *srcAddr, HostAddr *dstAddr, int sport, int dport) {
  u_int16_t transactionId;
  if (srcAddr->hostFamily != dstAddr->hostFamily)
    return -1;
  switch (srcAddr->hostFamily){
  case AF_INET:
    transactionId = (u_int16_t)(3*srcAddr->Ip4Address.s_addr+
				dstAddr->Ip4Address.s_addr+5*dport+7*sport);
    break;
#ifdef INET6
  case AF_INET6:
    transactionId = (u_int16_t)(3*srcAddr->Ip6Address.s6_addr[0]+
				dstAddr->Ip6Address.s6_addr[0]+5*dport+7*sport);
    break;
#endif
  }
  return transactionId;
}

/* ***************************** */

#ifdef INET6
int in6_isglobal(struct in6_addr *addr) {
  return (addr->s6_addr[0] & 0xe0) == 0x20;
}
#endif

/* ***************************** */

short addrcmp(HostAddr *addr1, HostAddr *addr2) {

  if(addr1 == NULL)
    if(addr2 == NULL)
      return 0;
    else
      return 1;
  else if(addr2 == NULL)
    return -1;

  if(addr1->hostFamily == 0)
    if(addr2->hostFamily == 0)
      return 0;
    else
      return 1;
  else if(addr2->hostFamily == 0)
    return -1;

  if(addr1->hostFamily != addr2->hostFamily)
    if(addr1->hostFamily > addr2->hostFamily)
      return 1;
    else
      return -1;

  switch (addr1->hostFamily){
  case AF_INET:
    if (addr1->Ip4Address.s_addr > addr2->Ip4Address.s_addr)
      return (1);
    else if (addr1->Ip4Address.s_addr < addr2->Ip4Address.s_addr)
      return (-1);
    else
      return (0);
    /*return (addr1->Ip4Address.s_addr != addr2->Ip4Address.s_addr);*/

#ifdef INET6
  case AF_INET6:
    if(memcmp(&addr1->Ip6Address,&addr2->Ip6Address,sizeof(struct in6_addr)) > 0)
      return (1);
    else if (memcmp(&addr1->Ip6Address,&addr2->Ip6Address,sizeof(struct in6_addr)) <0)
      return (-1);
    else
      return (0);
    break;
#endif
  default:
    return 1;
  }
}

/* ****************************************** */

HostAddr *addrcpy(HostAddr *dst, HostAddr *src) {
  dst->hostFamily = src->hostFamily;
  switch (src->hostFamily){
  case AF_INET:
    return memcpy(&dst->Ip4Address,&src->Ip4Address,sizeof(struct in_addr));
#ifdef INET6
  case AF_INET6:
    return memcpy(&dst->Ip6Address,&src->Ip6Address,sizeof(struct in6_addr));
#endif

  default:
    return NULL;
  }
}

/* ****************************************** */

int addrinit(HostAddr *addr) {
  addr->hostFamily = AF_INET;
  addr->Ip4Address.s_addr = 0;
  return(0);
}

/* ****************************************** */

unsigned short addrget(HostAddr *Haddr,void *addr, int *family , int *size) {
  struct in_addr v4addr;

  *family = Haddr->hostFamily;
  switch(Haddr->hostFamily){
  case AF_INET:
    v4addr.s_addr = ntohl(Haddr->Ip4Address.s_addr);
    memcpy((struct in_addr *)addr,&v4addr,sizeof(struct in_addr));
    *size = sizeof(struct in_addr);
    break;
#ifdef INET6
  case AF_INET6:
    memcpy((struct in6_addr *)addr,&Haddr->Ip6Address, sizeof(struct in6_addr));
    *size = sizeof(struct in6_addr);
    break;
#endif
  }
  return 1;
}

/* ****************************************** */

unsigned short addrput(int family, HostAddr *dst, void *src) {
  if (dst == NULL)
    return -1;
  dst->hostFamily = family;
  switch (family){
  case AF_INET:
    memcpy(&dst->Ip4Address, (struct in_addr *)src,sizeof(struct in_addr));
    break;
#ifdef INET6
  case AF_INET6:
    memcpy(&dst->Ip6Address, (struct in6_addr *)src, sizeof(struct in6_addr));
    break;
#endif
  }
  return(1);
}

/* ****************************************** */

unsigned short addrnull(HostAddr *addr) {
  switch(addr->hostFamily){
  case AF_INET:
    return (addr->Ip4Address.s_addr == 0x0);
#ifdef INET6
  case AF_INET6:
    return (addr->Ip6Address.s6_addr[0] == 0x0);
#endif
  default:
    return(1);
  }
}

/* ****************************************** */

unsigned short addrfull(HostAddr *addr) {
  switch(addr->hostFamily){
  case AF_INET:
    return (addr->Ip4Address.s_addr == 0xffffffff);
#ifdef INET6
  case AF_INET6:
    return(0);
#endif
  default: return 0;
  }
}

/* ****************************************** */

#ifdef INET6
unsigned short prefixlookup(struct in6_addr *addr, NtopIfaceAddr *addrs, int size) {
  int found = 0;
  NtopIfaceAddr *it;

  for (it = addrs ; it != NULL; it = it->next){
    if (size == 0)
      size = it->af.inet6.prefixlen / 8;
#if DEBUG
    {
      char buf[47], buf1[47];
      traceEvent(CONST_TRACE_INFO, "DEBUG: comparing [%s/%s]: %d",
		 _intop(addr, buf, INET6_ADDRSTRLEN),
		 _intop(&it->af.inet6.ifAddr, buf1, INET6_ADDRSTRLEN), found);
    }
#endif
    if (memcmp(&it->af.inet6.ifAddr,addr,size) == 0){
      found = 1;
      break;
    }
  }

  return found;
}
#endif

/* ****************************************** */

#ifdef INET6
unsigned short addrlookup(struct in6_addr *addr,  NtopIfaceAddr *addrs) {
  return (prefixlookup(addr,addrs, sizeof(struct in6_addr)));
}
#endif

/* ****************************************** */

#ifdef INET6
NtopIfaceAddr *getLocalHostAddressv6(NtopIfaceAddr *addrs, char* device) {
  struct iface_handler        *ih;
  struct iface_if             *ii;
  struct iface_addr           *ia;
  NtopIfaceAddr               *tmp = NULL;
  int count, addr_pos;

  if(!(ih = iface_new()))
    return NULL;

  for(ii = iface_getif_first(ih) ; ii ; ii = iface_getif_next(ii))
    if(!strcmp(ii->name,device))
      if(iface_if_getinfo(ii) & IFACE_INFO_UP) {
	/* Allocate memory for IPv6 addresses*/
	count = iface_if_addrcount(ii, AF_INET6);
	addrs = (NtopIfaceAddr *)calloc(count, sizeof(NtopIfaceAddr));
	addr_pos = 0;
	for(ia = iface_getaddr_first(ii, AF_INET6) ; ia ;
	    ia = iface_getaddr_next(ia, AF_INET6)) {
	  struct iface_addr_inet6 i6;
	  iface_addr_getinfo(ia, &i6);
	  if(in6_isglobal(&i6.addr)&& (addr_pos < count)) {
	    tmp = &addrs[addr_pos];
	    tmp->family = AF_INET6;
	    memcpy(&tmp->af.inet6.ifAddr, &i6.addr,sizeof(struct in6_addr));
	    tmp->af.inet6.prefixlen = ia->af.inet6.prefixlen;
	    tmp->next = &addrs[addr_pos+1];
	    addr_pos++;
	  }
	}
      }

  if(tmp != NULL) tmp->next = NULL;
  iface_destroy(ih);
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Local address is: %s", intop(hostAddress));
#endif
  return addrs;

}
#endif

/*******************************************/
/*
 * Copy arg vector into a new buffer, concatenating arguments with spaces.
 */
char* copy_argv(register char **argv) {
  register char **p;
  register u_int len = 0;
  char *buf;
  char *src, *dst;

  p = argv;
  if(*p == 0)
    return 0;

  while (*p)
    len += strlen(*p++) + 1;

  buf = (char*)malloc(len);
  if(buf == NULL) {
    traceEvent(CONST_TRACE_FATALERROR, "Insufficient memory for copy_argv");
    exit(-1);
  }

  p = argv;
  dst = buf;
  while ((src = *p++) != NULL) {
    while ((*dst++ = *src++) != '\0')
      ;
    dst[-1] = ' ';
  }
  dst[-1] = '\0';

  return buf;
}

/**************************************/

#ifdef INET6
unsigned short isLinkLocalAddress(struct in6_addr *addr) {
  int i;

  if(addr == NULL)
    return 1;
  else if(addr->s6_addr == 0x0)
    return 0; /* IP-less myGlobals.device (is it trying to boot via DHCP/BOOTP ?) */
  else {
    for(i=0; i<myGlobals.numDevices; i++)
      if(IN6_IS_ADDR_LINKLOCAL(addr)) {
#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "DEBUG: %s is a linklocal address", intop(addr));
#endif
	return 1;
      }
    return 0;
  }
}
#endif

/*******************************************/

#ifdef INET6
unsigned short in6_isMulticastAddress(struct in6_addr *addr) {
  if(IN6_IS_ADDR_MULTICAST(addr)) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: %s is multicast [%X/%X]",
	       intop(addr));
#endif
    return 1;
  } else
    return 0;
}
#endif

/*******************************************/

#ifdef INET6
unsigned short in6_isLocalAddress(struct in6_addr *addr, u_int deviceId) {
  if(deviceId >= myGlobals.numDevices) {
    traceEvent(CONST_TRACE_WARNING, "Index %u out of range [0..%u] - address treated as remote",
	       deviceId, myGlobals.numDevices);
    return(0);
  }

  if(addrlookup(addr,myGlobals.device[deviceId].v6Addrs) == 1) {
#ifdef ADDRESS_DEBUG
    traceEvent(CONST_TRACE_INFO, "ADDRESS_DEBUG: %s is local", intop(addr));
#endif
    return 1;
  }

  if(myGlobals.trackOnlyLocalHosts)
    return(0);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: %s is %s", intop(addr));
#endif
  /* Link Local Addresses are local */
  return(isLinkLocalAddress(addr));
}

/* ******************************************* */

unsigned short in6_isPrivateAddress(struct in6_addr *addr) {
  /* IPv6 have private addresses ?*/
  return(0);
}
#endif

/* ********************************* */

unsigned short in_isBroadcastAddress(struct in_addr *addr) {
  int i;

  if(addr == NULL)
    return 1;
  else if(addr->s_addr == 0x0)
    return 0; /* IP-less myGlobals.device (is it trying to boot via DHCP/BOOTP ?) */
  else {
    for(i=0; i<myGlobals.numDevices; i++) {
      if(!myGlobals.device[i].virtualDevice) {
	if(myGlobals.device[i].netmask.s_addr == 0xFFFFFFFF) /* PPP */
	  return 0;
	else if(((addr->s_addr | myGlobals.device[i].netmask.s_addr) ==  addr->s_addr)
		|| ((addr->s_addr & 0x000000FF) == 0x000000FF)
		|| ((addr->s_addr & 0x000000FF) == 0x00000000) /* Network address */
		) {
#ifdef DEBUG
	  traceEvent(CONST_TRACE_INFO, "DEBUG: %s is a broadcast address", intoa(*addr));
#endif
	  return 1;
	}
      }
    }

    return(in_isPseudoBroadcastAddress(addr));
  }
}

/* ********************************* */

unsigned short in_isMulticastAddress(struct in_addr *addr) {
  if((addr->s_addr & CONST_MULTICAST_MASK) == CONST_MULTICAST_MASK) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: %s is multicast [%X/%X]",
	       intoa(*addr),
	       ((unsigned long)(addr->s_addr) & CONST_MULTICAST_MASK),
	       CONST_MULTICAST_MASK
	       );
#endif
    return 1;
  } else
    return 0;
}

/* ********************************* */

unsigned short in_isLocalAddress(struct in_addr *addr, u_int deviceId) {
  if(deviceId >= myGlobals.numDevices) {
    traceEvent(CONST_TRACE_WARNING, "Index %u out of range [0..%u] - address treated as remote",
	       deviceId, myGlobals.numDevices);
    return(0);
  }

#ifdef ADDRESS_DEBUG
  traceEvent(CONST_TRACE_INFO, "Address: %s", intoa(*addr));
  traceEvent(CONST_TRACE_INFO, "Network: %s", intoa(myGlobals.device[deviceId].network));
  traceEvent(CONST_TRACE_INFO, "NetMask: %s", intoa(myGlobals.device[deviceId].netmask));
#endif

  if(addr == NULL) return(0);

  if(!myGlobals.mergeInterfaces) {
    if((addr->s_addr & myGlobals.device[deviceId].netmask.s_addr) == myGlobals.device[deviceId].network.s_addr) {
#ifdef ADDRESS_DEBUG
      traceEvent(CONST_TRACE_INFO, "ADDRESS_DEBUG: %s is local", intoa(*addr));
#endif
      return 1;
    }
  } else {
    int i;

    for(i=0; i<myGlobals.numDevices; i++)
      if((addr->s_addr & myGlobals.device[i].netmask.s_addr) == myGlobals.device[i].network.s_addr) {
#ifdef ADDRESS_DEBUG
	traceEvent(CONST_TRACE_INFO, "ADDRESS_DEBUG: %s is local", intoa(*addr));
#endif
	return 1;
      }
  }

  if(myGlobals.trackOnlyLocalHosts)
    return(0);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: %s is %s", intoa(*addr),
	     isBroadcastAddress(addr) ? "pseudolocal" : "remote");
#endif
  /* Broadcast is considered a local address */
  return(in_isBroadcastAddress(addr));
}

/* ********************************* */

unsigned short in_isPrivateAddress(struct in_addr *addr) {
  /* See http://www.isi.edu/in-notes/rfc1918.txt */

  /* Fixes below courtesy of Wies-Software <wies@wiessoft.de> */
  if(((addr->s_addr & 0xFF000000) == 0x0A000000)    /* 10/8      */
     || ((addr->s_addr & 0xFFF00000) == 0xAC100000) /* 172.16/12  */
     || ((addr->s_addr & 0xFFFF0000) == 0xC0A80000) /* 192.168/16 */
     )
    return(1);
  else
    return(0);
}

/***************************************/

unsigned short isBroadcastAddress(HostAddr *addr){
  switch(addr->hostFamily){
  case AF_INET:
    return (in_isBroadcastAddress(&addr->Ip4Address));
#ifdef INET6
  case AF_INET6:
    return (isLinkLocalAddress(&addr->Ip6Address));
#endif
  default: return(0);
  }
}

/* ******************************************** */

unsigned short isMulticastAddress(HostAddr *addr){
  switch(addr->hostFamily){
  case AF_INET:
    return (in_isMulticastAddress(&addr->Ip4Address));
#ifdef INET6
  case AF_INET6:
    return (in6_isMulticastAddress(&addr->Ip6Address));
#endif
  default: return(0);
  }
}

/* ************************************************* */

unsigned short isLocalAddress(HostAddr *addr, u_int deviceId) {
  switch(addr->hostFamily){
  case AF_INET:
    return (in_isLocalAddress(&addr->Ip4Address, deviceId));
#ifdef INET6
  case AF_INET6:
    return (in6_isLocalAddress(&addr->Ip6Address, deviceId));
#endif
  default: return(0);
  }
}

/* ************************************************** */

unsigned short isPrivateAddress(HostAddr *addr) {
  switch(addr->hostFamily){
  case AF_INET:
    return (in_isPrivateAddress(&addr->Ip4Address));
#ifdef INET6
  case AF_INET6:
    return (in6_isPrivateAddress(&addr->Ip6Address));
#endif
  default: return(0);
  }
}


/* **********************************************
 *
 * Description:
 *
 *  It converts an integer in the range
 *  from  0 to 255 in number of bits
 *  useful for netmask  calculation.
 *  The conmyGlobals.version is  valid if there
 *  is an uninterrupted sequence of
 *  bits set to 1 at the most signi-
 *  ficant positions. Example:
 *
 *     1111 1000 -> valid
 *     1110 1000 -> invalid
 *
 * Return values:
 *     0 - 8 (number of subsequent
 *            bits set to 1)
 *    -1     (CONST_INVALIDNETMASK)
 *
 *
 * Courtesy of Antonello Maiorca <marty@tai.it>
 *
 *********************************************** */

static int int2bits(int number) {
  int bits = 8;
  int test;

  if((number > 255) || (number < 0))
    {
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: int2bits (%3d) = %d", number, CONST_INVALIDNETMASK);
#endif
      return(CONST_INVALIDNETMASK);
    }
  else
    {
      test = ~number & 0xff;
      while (test & 0x1)
	{
	  bits --;
	  test = test >> 1;
	}
      if(number != ((~(0xff >> bits)) & 0xff))
	{
#ifdef DEBUG
	  traceEvent(CONST_TRACE_INFO, "DEBUG: int2bits (%3d) = %d", number, CONST_INVALIDNETMASK);
#endif
	  return(CONST_INVALIDNETMASK);
	}
      else
	{
#ifdef DEBUG
	  traceEvent(CONST_TRACE_INFO, "DEBUG: int2bits (%3d) = %d", number, bits);
#endif
	  return(bits);
	}
    }
}

/* ***********************************************
 *
 * Description:
 *
 *  Converts a dotted quad notation
 *  netmask  specification  to  the
 *  equivalent number of bits.
 *  from  0 to 255 in number of bits
 *  useful for netmask  calculation.
 *  The converion is  valid if there
 *  is an  uninterrupted sequence of
 *  bits set to 1 at the most signi-
 *  ficant positions. Example:
 *
 *     1111 1000 -> valid
 *     1110 1000 -> invalid
 *
 * Return values:
 *     0 - 32 (number of subsequent
 *             bits set to 1)
 *    -1      (CONST_INVALIDNETMASK)
 *
 *
 * Courtesy of Antonello Maiorca <marty@tai.it>
 *
 *********************************************** */

int dotted2bits(char *mask) {
  int		fields[4];
  int		fields_num, field_bits;
  int		bits = 0;
  int		i;

  fields_num = sscanf(mask, "%d.%d.%d.%d",
		      &fields[0], &fields[1], &fields[2], &fields[3]);
  if((fields_num == 1) && (fields[0] <= 32) && (fields[0] >= 0))
    {
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: dotted2bits (%s) = %d", mask, fields[0]);
#endif
      return(fields[0]);
    }
  for (i=0; i < fields_num; i++)
    {
      /* We are in a dotted quad notation. */
      field_bits = int2bits (fields[i]);
      switch (field_bits)
	{
	case CONST_INVALIDNETMASK:
	  return(CONST_INVALIDNETMASK);

	case 0:
	  /* whenever a 0 bits field is reached there are no more */
	  /* fields to scan                                       */
#ifdef DEBUG
	  traceEvent(CONST_TRACE_INFO, "DEBUG: dotted2bits (%15s) = %d", mask, bits);
#endif
	  /* In this case we are in a bits (not dotted quad) notation */
	  return(bits /* fields[0] - L.Deri 08/2001 */);

	default:
	  bits += field_bits;
	}
    }
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: dotted2bits (%15s) = %d", mask, bits);
#endif
  return(bits);
}

/* ********************************* */

/* Example: "131.114.0.0/16,193.43.104.0/255.255.255.0" */

void handleAddressLists(char* addresses, u_int32_t theNetworks[MAX_NUM_NETWORKS][3],
			u_short *numNetworks, char *localAddresses,
			int localAddressesLen, int flagWhat) {
  char *strtokState, *address;
  int  laBufferPosition = 0, laBufferUsed = 0, i;

  if((addresses == NULL) || (addresses[0] == '\0'))
    return;

  traceEvent(CONST_TRACE_NOISY,
             "Processing %s parameter '%s'",
             flagWhat == CONST_HANDLEADDRESSLISTS_MAIN ? "-m | --local-subnets"  :
	     flagWhat == CONST_HANDLEADDRESSLISTS_RRD ? "RRD" :
	     flagWhat == CONST_HANDLEADDRESSLISTS_NETFLOW ? "Netflow white/black list" : "unknown",
             addresses);

  memset(localAddresses, 0, localAddressesLen);

  address = strtok_r(addresses, ",", &strtokState);

  while(address != NULL) {
    char *mask = strchr(address, '/');

    if(mask == NULL) {
      if (flagWhat == CONST_HANDLEADDRESSLISTS_MAIN)
        traceEvent(CONST_TRACE_WARNING, "-m: Empty mask '%s' - ignoring entry", address);
    } else {
      u_int32_t network, networkMask, broadcast;
      int bits, a, b, c, d;

      mask[0] = '\0';
      mask++;
      bits = dotted2bits (mask);

      if(sscanf(address, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        traceEvent(CONST_TRACE_WARNING, "%s: Bad format '%s' - ignoring entry",
		   flagWhat == CONST_HANDLEADDRESSLISTS_MAIN ? "-m"  :
		   flagWhat == CONST_HANDLEADDRESSLISTS_RRD ? "RRD" :
		   flagWhat == CONST_HANDLEADDRESSLISTS_NETFLOW ? "Netflow" : "unknown",
		   address);
	address = strtok_r(NULL, ",", &strtokState);
	continue;
      }

      if(bits == CONST_INVALIDNETMASK) {
	/* malformed netmask specification */
        traceEvent(CONST_TRACE_WARNING, "%s: Net mask '%s' not valid - ignoring entry",
		   flagWhat == CONST_HANDLEADDRESSLISTS_MAIN ? "-m | --local-subnets"  :
		   flagWhat == CONST_HANDLEADDRESSLISTS_RRD ? "RRD" :
		   flagWhat == CONST_HANDLEADDRESSLISTS_NETFLOW ? "Netflow white/black list" : "unknown",
		   mask);
	address = strtok_r(NULL, ",", &strtokState);
	continue;
      }

      network     = ((a & 0xff) << 24) + ((b & 0xff) << 16) + ((c & 0xff) << 8) + (d & 0xff);
      /* Special case the /32 mask - yeah, we could probably do it with some fancy
         u long long stuff, but this is simpler...
         Burton Strauss <Burton@ntopsupport.com> Jun2002
      */
      if (bits == 32) {
	networkMask = 0xffffffff;
      } else {
	networkMask = 0xffffffff >> bits;
	networkMask = ~networkMask;
      }

#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: Nw=%08X - Mask: %08X [%08X]",
		 network, networkMask, (network & networkMask));
#endif

      if((networkMask >= 0xFFFFFF00) /* Courtesy of Roy-Magne Mo <romo@interpost.no> */
	 && ((network & networkMask) != network))  {
	/* malformed network specification */
	traceEvent(CONST_TRACE_WARNING, "%s: %d.%d.%d.%d/%d is not a valid network - correcting mask",
                   flagWhat == CONST_HANDLEADDRESSLISTS_MAIN ? "-m | --local-subnets"  :
		   flagWhat == CONST_HANDLEADDRESSLISTS_RRD ? "RRD" :
		   flagWhat == CONST_HANDLEADDRESSLISTS_NETFLOW ? "Netflow white/black list" : "unknown",
                   a, b, c, d, bits);

	/* correcting network numbers as specified in the netmask */
	network &= networkMask;

	a = (int) ((network >> 24) & 0xff);
	b = (int) ((network >> 16) & 0xff);
	c = (int) ((network >>  8) & 0xff);
	d = (int) ((network >>  0) & 0xff);

	traceEvent(CONST_TRACE_NOISY, "Assuming %d.%d.%d.%d/%d [0x%08x/0x%08x]",
		   a, b, c, d, bits, network, networkMask);
      }
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: %d.%d.%d.%d/%d [0x%08x/0x%08x]",
		 a, b, c, d, bits, network, networkMask);
#endif

      broadcast = network | (~networkMask);

#ifdef DEBUG
      a = (int) ((broadcast >> 24) & 0xff);
      b = (int) ((broadcast >> 16) & 0xff);
      c = (int) ((broadcast >>  8) & 0xff);
      d = (int) ((broadcast >>  0) & 0xff);

      traceEvent(CONST_TRACE_INFO, "DEBUG: Broadcast: [net=0x%08x] [broadcast=%d.%d.%d.%d]",
		 network, a, b, c, d);
#endif

      if((*numNetworks) < MAX_NUM_NETWORKS) {
        int found = 0;
        /* If this is the real list, we check against the actual network addresses
         * and warn the user of superfluous entries - for the other lists, rrd and netflow
         * the local address is valid, it's NOT assumed.
         */
        if (flagWhat == CONST_HANDLEADDRESSLISTS_MAIN) {
          for(i=0; i<myGlobals.numDevices; i++) {
            if((network == myGlobals.device[i].network.s_addr) &&
               (myGlobals.device[i].netmask.s_addr == networkMask)) {
              a = (int) ((network >> 24) & 0xff);
              b = (int) ((network >> 16) & 0xff);
              c = (int) ((network >>  8) & 0xff);
              d = (int) ((network >>  0) & 0xff);

              traceEvent(CONST_TRACE_INFO,
                         "-m: Discarded unnecessary parameter %d.%d.%d.%d/%d - this is the local network",
		         a, b, c, d, bits);
              found = 1;
            }
          }
        }

	if(found == 0) {
          theNetworks[(*numNetworks)][CONST_NETWORK_ENTRY]   = network;
          theNetworks[(*numNetworks)][CONST_NETMASK_ENTRY]   = networkMask;
          theNetworks[(*numNetworks)][CONST_BROADCAST_ENTRY] = broadcast;

          a = (int) ((network >> 24) & 0xff);
          b = (int) ((network >> 16) & 0xff);
          c = (int) ((network >>  8) & 0xff);
          d = (int) ((network >>  0) & 0xff);

          if ((laBufferUsed = snprintf(&localAddresses[laBufferPosition],
                                       localAddressesLen,
                                       "%s%d.%d.%d.%d/%d",
                                       (*numNetworks) == 0 ? "" : ", ",
                                       a, b, c, d,
                                       bits)) < 0)
            BufferTooShort();

          laBufferPosition  += laBufferUsed;
          localAddressesLen -= laBufferUsed;

          (*numNetworks)++;

        }
      } else {
        a = (int) ((network >> 24) & 0xff);
        b = (int) ((network >> 16) & 0xff);
        c = (int) ((network >>  8) & 0xff);
        d = (int) ((network >>  0) & 0xff);

        traceEvent(CONST_TRACE_ERROR, "%s: %d.%d.%d.%d/%d - Too many networks (limit %d) - discarded",
                   flagWhat == CONST_HANDLEADDRESSLISTS_MAIN ? "-m"  :
		   flagWhat == CONST_HANDLEADDRESSLISTS_RRD ? "RRD" :
		   flagWhat == CONST_HANDLEADDRESSLISTS_NETFLOW ? "Netflow" : "unknown",
                   a, b, c, d, bits,
                   MAX_NUM_NETWORKS);
      }
    }

    address = strtok_r(NULL, ",", &strtokState);
  }
}

/* ********************************* */

void handleLocalAddresses(char* addresses) {
  char localAddresses[1024];

  localAddresses[0] = '\0';

  handleAddressLists(addresses, myGlobals.localNetworks, &myGlobals.numLocalNetworks,
                     localAddresses, sizeof(localAddresses), CONST_HANDLEADDRESSLISTS_MAIN);

  /* Not used anymore */
  if(myGlobals.localAddresses != NULL) free(myGlobals.localAddresses);
  
  if(localAddresses[0]  != '\0')
    myGlobals.localAddresses = strdup(localAddresses);
}

/* ********************************* */

#ifdef INET6
unsigned short in6_pseudoLocalAddress(struct in6_addr *addr) {
  int i;

  for(i=0; i<myGlobals.numDevices; i++) {
    if (prefixlookup(addr,myGlobals.device[i].v6Addrs,0) == 1)
      return (1);

  }
  return(0);
}
#endif

unsigned short __pseudoLocalAddress(struct in_addr *addr,
				    u_int32_t theNetworks[MAX_NUM_NETWORKS][3],
				    u_short numNetworks) {
  int i;

  for(i=0; i<numNetworks; i++) {
#ifdef ADDRESS_DEBUG
    char buf[32], buf1[32], buf2[32];
    struct in_addr addr1, addr2;

    addr1.s_addr = theNetworks[i][CONST_NETWORK_ENTRY];
    addr2.s_addr = theNetworks[i][CONST_NETMASK_ENTRY];

    traceEvent(CONST_TRACE_INFO, "DEBUG: %s comparing [%s/%s]",
	       _intoa(*addr, buf, sizeof(buf)),
	       _intoa(addr1, buf1, sizeof(buf1)),
	       _intoa(addr2, buf2, sizeof(buf2)));
#endif
    if((addr->s_addr & theNetworks[i][CONST_NETMASK_ENTRY]) == theNetworks[i][CONST_NETWORK_ENTRY]) {
#ifdef ADDRESS_DEBUG
      traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is pseudolocal", intoa(*addr));
#endif
      return 1;
    } else {
#ifdef ADDRESS_DEBUG
      traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is NOT pseudolocal", intoa(*addr));
#endif
    }
  }

  return(0);
}

/* ********************************* */

unsigned short in_pseudoLocalAddress(struct in_addr *addr) {
  return(__pseudoLocalAddress(addr, myGlobals.localNetworks, myGlobals.numLocalNetworks));
}

/* ********************************* */

#ifdef INET6
unsigned short in6_deviceLocalAddress(struct in6_addr *addr, u_int deviceId) {
  int rc;

  if(addrlookup(addr,myGlobals.device[deviceId].v6Addrs))
    rc = 1;
  else
    rc = 0;

  return(rc);
}
#endif

/* ********************************* */

unsigned short in_deviceLocalAddress(struct in_addr *addr, u_int deviceId) {
  int rc;

  if((addr->s_addr & myGlobals.device[deviceId].netmask.s_addr) == myGlobals.device[deviceId].network.s_addr)
    rc = 1;
  else
    rc = 0;

#if DEBUG
  {
    char buf[32], buf1[32];
    traceEvent(CONST_TRACE_INFO, "DEBUG: comparing [%s/%s]: %d",
	       _intoa(*addr, buf, sizeof(buf)),
	       _intoa(myGlobals.device[deviceId].network, buf1, sizeof(buf1)), rc);
  }
#endif

  return(rc);
}

/* ********************************* */

#ifdef INET6
unsigned short in6_isPseudoLocalAddress(struct in6_addr *addr, u_int deviceId) {
  int i;

  i = in6_isLocalAddress(addr, deviceId);

  if(i == 1) {
#ifdef ADDRESS_DEBUG
    traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is local", intop(addr));
#endif

    return 1; /* This is a real local address */
  }

  if(in6_pseudoLocalAddress(addr))
    return 1;

  /*
    We don't check for broadcast as this check has been
    performed already by isLocalAddress() just called
  */

#ifdef ADDRESS_DEBUG
  traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is remote", intop(addr));
#endif

  return(0);
}
#endif

/* ******************************************** */

/* This function returns true when a host is considered local
   as specified using the 'm' flag */
unsigned short in_isPseudoLocalAddress(struct in_addr *addr, u_int deviceId) {
  int i;

  i = in_isLocalAddress(addr, deviceId);

  if(i == 1) {
#ifdef ADDRESS_DEBUG
    traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is local", intoa(*addr));
#endif

    return 1; /* This is a real local address */
  }

  if(in_pseudoLocalAddress(addr))
    return 1;

  /*
    We don't check for broadcast as this check has been
    performed already by isLocalAddress() just called
  */

#ifdef ADDRESS_DEBUG
  traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s [deviceId=%d] is remote",
	     intoa(*addr), deviceId);
#endif

  return(0);
}

/* ********************************* */

/* This function returns true when an address is the broadcast
   for the specified (-m flag subnets */

unsigned short in_isPseudoBroadcastAddress(struct in_addr *addr) {
  int i;

#ifdef ADDRESS_DEBUG
  traceEvent(CONST_TRACE_WARNING, "DEBUG: Checking %8X (pseudo broadcast)", addr->s_addr);
#endif

  for(i=0; i<myGlobals.numLocalNetworks; i++) {
    if(addr->s_addr == myGlobals.localNetworks[i][CONST_BROADCAST_ENTRY]) {
#ifdef ADDRESS_DEBUG
      traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: --> %8X is pseudo broadcast", addr->s_addr);
#endif
      return 1;
    }
#ifdef ADDRESS_DEBUG
    else
      traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %8X is NOT pseudo broadcast", addr->s_addr);
#endif
  }

  return(0);
}

/*************************************/

unsigned short deviceLocalAddress(HostAddr *addr, u_int deviceId) {
  switch(addr->hostFamily){
  case AF_INET:
    return (in_deviceLocalAddress(&addr->Ip4Address, deviceId));
#ifdef INET6
  case AF_INET6:
    return (in6_deviceLocalAddress(&addr->Ip6Address, deviceId));
#endif
  default: return(0);
  }
}

/* ********************************* */

unsigned short isPseudoLocalAddress(HostAddr *addr, u_int deviceId) {
  switch(addr->hostFamily){
  case AF_INET:
    return (in_isPseudoLocalAddress(&addr->Ip4Address, deviceId));
#ifdef INET6
  case AF_INET6:
    return (in6_isPseudoLocalAddress(&addr->Ip6Address, deviceId));
#endif
  default: return(0);
  }
}

/* ********************************* */

unsigned short isPseudoBroadcastAddress(HostAddr *addr) {
  switch(addr->hostFamily){
  case AF_INET:
    return (in_isPseudoBroadcastAddress(&addr->Ip4Address));
#ifdef INET6
  case AF_INET6:
    return 0;
#endif
  default: return(0);
  }
}

/* ********************************* */

unsigned short _pseudoLocalAddress(HostAddr *addr) {
  switch(addr->hostFamily){
  case AF_INET:
    return (in_pseudoLocalAddress(&addr->Ip4Address));
#ifdef INET6
  case AF_INET6:
    return (in6_pseudoLocalAddress(&addr->Ip6Address));
#endif
  default: return(0);
  }
}

/* ********************************* */

/*
 * Returns the difference between gmt and local time in seconds.
 * Use gmtime() and localtime() to keep things simple.
 * [Borrowed from tcpdump]
 */
int32_t gmt2local(time_t t) {
  int dt, dir;
  struct tm *gmt, *myloc;
  struct tm loc;

  if(t == 0)
    t = time(NULL);

  gmt = gmtime(&t);
  myloc = localtime_r(&t, &loc);

  dt = (myloc->tm_hour - gmt->tm_hour)*60*60+(myloc->tm_min - gmt->tm_min)*60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = myloc->tm_year - gmt->tm_year;
  if(dir == 0)
    dir = myloc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return(dt);
}

/* ********************************* */

char *dotToSlash(char *name) {
  /*
   *  Convert a dotted quad ip address name a.b.c.d to a/b/c/d or a\b\c\d
   */
  char* localBuffer;
  int i;

  localBuffer = strdup(name);

  for (i=0; i<strlen(localBuffer); i++) {
    if((localBuffer[i] == '.') || (localBuffer[i] == ':'))
#ifdef WIN32
      localBuffer[i]='\\';
#else
    localBuffer[i]='/';
#endif
  }

  localBuffer[i]='\0';
  return localBuffer;
}

/* ********************************* */

/* Example: "flow1='host jake',flow2='dst host born2run'" */
void handleFlowsSpecs(void) {
  FILE *fd;
  char *flow, *buffer=NULL, *strtokState, *flows;

  flows = myGlobals.flowSpecs;

  if((!flows) || (!flows[0]))
    return;

  fd = fopen(flows, "rb");

  if(fd == NULL)
    flow = strtok_r(flows, ",", &strtokState);
  else {
    struct stat buf;
    int len, i;

    if(stat(flows, &buf) != 0) {
      fclose(fd);
      traceEvent(CONST_TRACE_INFO, "Error while stat() of %s", flows);

      /* Not used anymore */
      free(myGlobals.flowSpecs);
      myGlobals.flowSpecs = strdup("Error reading file");
      return;
    }

    buffer = (char*)malloc(buf.st_size+8) /* just to be safe */;

    for(i=0;i<buf.st_size;) {
      len = fread(&buffer[i], sizeof(char), buf.st_size-i, fd);
      if(len <= 0) break;
      i += len;
    }

    fclose(fd);

    /* remove trailing carriage return */
    if(buffer[strlen(buffer)-1] == '\n')
      buffer[strlen(buffer)-1] = 0;

    flow = strtok_r(buffer, ",", &strtokState);
  }

  while(flow != NULL) {
    char *flowSpec = strchr(flow, '=');

    if(flowSpec == NULL)
      traceEvent(CONST_TRACE_INFO, "Missing flow spec '%s'. It has been ignored.", flow);
    else {
      struct bpf_program fcode;
      int rc, len;
      char *flowName = flow;

      flowSpec[0] = '\0';
      flowSpec++;
      /* flowSpec should now point to 'host jake' */
      len = strlen(flowSpec);

      if((len <= 2)
	 || (flowSpec[0] != '\'')
	 || (flowSpec[len-1] != '\''))
	traceEvent(CONST_TRACE_WARNING, "Wrong flow specification \"%s\" (missing \'). "
		   "It has been ignored.", flowSpec);
      else {
	flowSpec[len-1] = '\0';
        flowSpec++;

        traceEvent(CONST_TRACE_NOISY, "Compiling flow specification '%s'", flowSpec);

        rc = pcap_compile(myGlobals.device[0].pcapPtr, &fcode, flowSpec, 1, myGlobals.device[0].netmask.s_addr);

        if(rc < 0)
          traceEvent(CONST_TRACE_WARNING, "Wrong flow specification \"%s\" (syntax error). "
                     "It has been ignored.", flowSpec);
        else {
          FlowFilterList *newFlow;

#ifdef HAVE_PCAP_FREECODE
          pcap_freecode(&fcode);
#endif
          newFlow = (FlowFilterList*)calloc(1, sizeof(FlowFilterList));

          if(newFlow == NULL) {
            traceEvent(CONST_TRACE_INFO, "Fatal error: not enough memory. Bye!");
            if(buffer != NULL) free(buffer);
            exit(-1);
          } else {
            int i;

	    newFlow->fcode = (struct bpf_program*)calloc(myGlobals.numDevices, sizeof(struct bpf_program));

            for(i=0; i<myGlobals.numDevices; i++) {
              rc = pcap_compile(myGlobals.device[i].pcapPtr, &newFlow->fcode[i],
                                flowSpec, 1, myGlobals.device[i].netmask.s_addr);

              if(rc < 0) {
                traceEvent(CONST_TRACE_WARNING, "Wrong flow specification \"%s\" (syntax error). "
			   "It has been ignored.", flowSpec);
                free(newFlow);

		/* Not used anymore */
		free(myGlobals.flowSpecs);
		myGlobals.flowSpecs = strdup("Error, wrong flow specification");
                return;
              }
            }

            newFlow->flowName = strdup(flowName);
            newFlow->pluginStatus.activePlugin = 1;
            newFlow->pluginStatus.pluginPtr = NULL; /* Added by Jacques Le Rest <jlerest@ifremer.fr> */
            newFlow->next = myGlobals.flowsList;
            myGlobals.flowsList = newFlow;
          }
        }
      }
    }

    flow = strtok_r(NULL, ",", &strtokState);
  }

  if(buffer != NULL)
    free(buffer);

}

/* ********************************* */

int getLocalHostAddress(struct in_addr *hostAddress, char* device) {
  int rc = 0;
#ifdef WIN32
  hostAddress->s_addr = GetHostIPAddr();
  return(0);
#else
  int fd;
  struct sockaddr_in *sinAddr;
  struct ifreq ifr;
#ifdef DEBUG
  int a, b, c, d;
#endif

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd < 0) {
    traceEvent(CONST_TRACE_INFO, "socket error: %d", errno);
    return(-1);
  }

  memset(&ifr, 0, sizeof(ifr));

#ifdef LINUX
  /* XXX Work around Linux kernel bug */
  ifr.ifr_addr.sa_family = AF_INET;
#endif
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
  if(ioctl(fd, SIOCGIFADDR, (char*)&ifr) < 0) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: SIOCGIFADDR error: %s/errno=%d", device, errno);
#endif
    rc = -1;
  } else {
    sinAddr = (struct sockaddr_in *)&ifr.ifr_addr;

    if((hostAddress->s_addr = ntohl(sinAddr->sin_addr.s_addr)) == 0)
      rc = -1;
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Local address is: %s", intoa(*hostAddress));
#endif

  /* ******************************* */

#ifdef DEBUG
  {
    int numHosts;

    if(ioctl(fd, SIOCGIFNETMASK, (char*)&ifr) >= 0) {
      sinAddr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
      numHosts = 0xFFFFFFFF - ntohl(sinAddr->sin_addr.s_addr)+1;
    } else
      numHosts = 256; /* default C class */

    traceEvent(CONST_TRACE_INFO, "DEBUG: Num subnet hosts: %d", numHosts);
  }
#endif

  /* ******************************* */

  close(fd);
#endif

  return(rc);
}

/* ********************************* */

#ifndef WIN32
#ifdef CFG_MULTITHREADED

/* *********** MULTITHREAD STUFF *********** */

int createThread(pthread_t *threadId,
		 void *(*__start_routine) (void *),
		 char* userParm) {
  int rc;

  rc = pthread_create(threadId, NULL, __start_routine, userParm);

  if(rc != 0)
    traceEvent(CONST_TRACE_NOISY, "createThread(0x%x), rc = %s(%d)",
	       threadId, strerror(rc), rc);
  myGlobals.numThreads++;
  return(rc);
}

/* ************************************ */

int killThread(pthread_t *threadId) {
  int rc;
  rc = pthread_detach(*threadId);

  if(rc != 0)
    traceEvent(CONST_TRACE_NOISY, "killThread(0x%x), rc = %s(%d)",
	       threadId, strerror(rc), rc);

  myGlobals.numThreads--;
  return(rc);
}

/* ************************************ */

int _createMutex(PthreadMutex *mutexId, char* fileName, int fileLine) {
  int rc;

  if(!stateChangeMutexInitialized) {
    pthread_mutex_init(&stateChangeMutex, NULL);
    stateChangeMutexInitialized = 1;
  }

  memset(mutexId, 0, sizeof(PthreadMutex));

  rc = pthread_mutex_init(&(mutexId->mutex), NULL);

  if (rc != 0) {
    traceEvent(CONST_TRACE_ERROR,
               "createMutex() call returned %d(%d) [%s:%d]",
               rc, errno, fileName, fileLine);
  } else {
    mutexId->isInitialized = 1;
#ifdef SEMAPHORE_DEBUG
    traceEvent(CONST_TRACE_INFO, "SEMAPHORE_DEBUG: createMutex() succeeded [0x%X@%s:%d]",
               (void*)&(mutexId->mutex), fileName, fileLine);
#endif
  }

  return(rc);
}

/* ************************************ */

void _deleteMutex(PthreadMutex *mutexId, char* fileName, int fileLine) {
  int rc;

  if(mutexId == NULL) {
    if(myGlobals.endNtop == 0)
      traceEvent(CONST_TRACE_ERROR,
                 "deleteMutex() called with a NULL mutex [%s:%d]",
                 fileName, fileLine);
    return;
  }

  if(!mutexId->isInitialized) {
    if(myGlobals.endNtop == 0)
      traceEvent(CONST_TRACE_ERROR,
                 "deleteMutex() called with an UN-INITIALIZED mutex [0x%X@%s:%d]",
                 (void*)&(mutexId->mutex), fileName, fileLine);
    return;
  }

  rc = pthread_mutex_unlock(&(mutexId->mutex));
#ifdef SEMAPHORE_DEBUG
  traceEvent(CONST_TRACE_INFO, "SEMAPHORE_DEBUG: deleteMutex() unlock (rc=%d) [0x%X@%s:%d]",
             rc, (void*)&(mutexId->mutex), fileName, fileLine);
#endif
  rc = pthread_mutex_destroy(&(mutexId->mutex));
#ifdef SEMAPHORE_DEBUG
  traceEvent(CONST_TRACE_INFO, "SEMAPHORE_DEBUG: deleteMutex() destroy (rc=%d) [0x%X@%s:%d]",
             rc, (void*)&(mutexId->mutex), fileName, fileLine);
#endif

  memset(mutexId, 0, sizeof(PthreadMutex));
}

/* ************************************ */

int _accessMutex(PthreadMutex *mutexId, char* where,
		 char* fileName, int fileLine) {
  int rc;
  pid_t myPid;

  if(mutexId == NULL) {
    if(myGlobals.endNtop == 0)
      traceEvent(CONST_TRACE_ERROR,
                 "accessMutex() called with a NULL mutex [%s:%d]",
                 fileName, fileLine);
    return(-1);
  }

  if(!mutexId->isInitialized) {
    if(myGlobals.endNtop == 0)
      traceEvent(CONST_TRACE_ERROR,
                 "accessMutex() called '%s' with an UN-INITIALIZED mutex [0x%X@%s:%d]",
                 where, (void*)&(mutexId->mutex), fileName, fileLine);
    return(-1);
  }

#ifdef SEMAPHORE_DEBUG
  /* Do not move this code below -
   * we want to keep the unprotected field updates
   * as close to the trylock as possible!
   */
  traceEvent(CONST_TRACE_INFO, "SEMAPHORE_DEBUG: accessMutex() called '%s' [0x%X@%s:%d]",
             where, (void*)&(mutexId->mutex), fileName, fileLine);
#endif

  if(!myGlobals.disableMutexExtraInfo) {
    myPid=getpid();
    if(mutexId->isLocked) {
      if((fileLine == mutexId->lockLine)
         && (strcmp(fileName, mutexId->lockFile) == 0)
         && (myPid == mutexId->lockPid)
         && (pthread_equal(mutexId->lockThread, pthread_self()))) {
        traceEvent(CONST_TRACE_WARNING,
                   "accessMutex() called '%s' with a self-LOCKED mutex [0x%X@%s:%d]",
                   where, (void*)&(mutexId->mutex), fileName, fileLine);
      }
    }

    strcpy(mutexId->lockAttemptFile, fileName);
    mutexId->lockAttemptLine=fileLine;
    mutexId->lockAttemptPid=myPid;
  }

  rc = pthread_mutex_lock(&(mutexId->mutex));

  pthread_mutex_lock(&stateChangeMutex);
  if(!myGlobals.disableMutexExtraInfo) {
    mutexId->lockAttemptFile[0] = '\0';
    mutexId->lockAttemptLine=0;
    mutexId->lockAttemptPid=(pid_t) 0;
    mutexId->lockThread=pthread_self();
  }

  if(rc != 0)
    traceEvent(CONST_TRACE_ERROR, "accessMutex() call '%s' failed (rc=%d) [0x%X@%s:%d]",
               where, rc, (void*)&(mutexId->mutex), fileName, fileLine);
  else {

#ifdef SEMAPHORE_DEBUG
    traceEvent(CONST_TRACE_INFO, "SEMAPHORE_DEBUG: accessMutex() call '%s' succeeded [0x%X@%s:%d]",
	       where, (void*)&(mutexId->mutex), fileName, fileLine);
#endif

    mutexId->numLocks++;
    mutexId->isLocked = 1;
    if(!myGlobals.disableMutexExtraInfo) {
      mutexId->lockTime = time(NULL);
      mutexId->lockPid  = myPid;
      if(fileName != NULL) {
        strcpy(mutexId->lockFile, fileName);
        mutexId->lockLine = fileLine;
      }
      if(where != NULL) {
        strcpy(mutexId->where, where);
      }
    }
  }
  pthread_mutex_unlock(&stateChangeMutex);

  return(rc);
}

/* ************************************ */

int _tryLockMutex(PthreadMutex *mutexId, char* where,
		  char* fileName, int fileLine) {
  int rc;
  pid_t myPid;

  if(mutexId == NULL) {
    if(myGlobals.endNtop == 0)
      traceEvent(CONST_TRACE_ERROR,
                 "tryLockMutex() called '%s' with a NULL mutex [%s:%d]",
                 where, fileName, fileLine);
    return(-1);
  }

  if(!mutexId->isInitialized) {
    if(myGlobals.endNtop == 0)
      traceEvent(CONST_TRACE_ERROR,
                 "tryLockMutex() called '%s' with an UN-INITIALIZED mutex [0x%X@%s:%d]",
                 where, (void*)&(mutexId->mutex), fileName, fileLine);
    return(-1);
  }

#ifdef SEMAPHORE_DEBUG
  /* Do not move this code below -
   * we want to keep the unprotected field updates
   * as close to the trylock as possible!
   */
  traceEvent(CONST_TRACE_INFO, "SEMAPHORE_DEBUG: tryLockMutex() call '%s' called [0x%X@%s:%d]",
             where, (void*)&(mutexId->mutex), fileName, fileLine);
#endif

  if(!myGlobals.disableMutexExtraInfo) {
    myPid = getpid();
    if(mutexId->isLocked) {
      if((strcmp(fileName, mutexId->lockFile) == 0)
         && (fileLine == mutexId->lockLine)
         && (myPid == mutexId->lockPid)
         && (pthread_equal(mutexId->lockThread, pthread_self()))
         ) {
        traceEvent(CONST_TRACE_WARNING,
		   "tryLockMutex() called '%s' with a self-LOCKED mutex [0x%X@%s:%d]",
		   where, (void*)&(mutexId->mutex), fileName, fileLine);
      }
    }

    strcpy(mutexId->lockAttemptFile, fileName);
    mutexId->lockAttemptLine=fileLine;
    mutexId->lockAttemptPid=myPid;

  }

  /*
    Return code:

    0:    lock succesful
    EBUSY (mutex already locked)
  */
  rc = pthread_mutex_trylock(&(mutexId->mutex));
  pthread_mutex_lock(&stateChangeMutex);
  if(!myGlobals.disableMutexExtraInfo) {
    mutexId->lockAttemptFile[0] = '\0';
    mutexId->lockAttemptLine = 0;
    mutexId->lockAttemptPid = (pid_t) 0;
  }

  if(rc != 0)  {
#ifdef SEMAPHORE_DEBUG
    traceEvent(CONST_TRACE_INFO, "SEMAPHORE_DEBUG: tryLockMutex() call '%s' failed (rc=%d) [0x%X@%s:%d]",
               where, rc, (void*)&(mutexId->mutex), fileName, fileLine);
#endif
  } else {
#ifdef SEMAPHORE_DEBUG
    traceEvent(CONST_TRACE_INFO, "SEMAPHORE_DEBUG: tryLockMutex() call '%s' succeeded [0x%X@%s:%d]",
               where, (void*)&(mutexId->mutex), fileName, fileLine);
#endif

    mutexId->numLocks++;
    mutexId->isLocked = 1;
    if(!myGlobals.disableMutexExtraInfo) {
      mutexId->lockTime = time(NULL);
      mutexId->lockPid = myPid;
      mutexId->lockThread = pthread_self();

      if(fileName != NULL) {
        strcpy(mutexId->lockFile, fileName);
        mutexId->lockLine = fileLine;
      }

      if(where != NULL) strcpy(mutexId->where, where);
    }
  }

  pthread_mutex_unlock(&stateChangeMutex);
  return(rc);
}

/* ************************************ */

int _isMutexLocked(PthreadMutex *mutexId, char* fileName, int fileLine) {
  int rc;

  if(mutexId == NULL) {
    if(myGlobals.endNtop == 0)
      traceEvent(CONST_TRACE_ERROR,
                 "isMutexLocked() called with a NULL mutex [%s:%d]",
                 fileName, fileLine);
    return(-1);
  }

  if(!mutexId->isInitialized) {
    if(myGlobals.endNtop == 0)
      traceEvent(CONST_TRACE_ERROR,
                 "isMutexLocked() called with an UN-INITIALIZED mutex [0x%X@%s:%d]",
                 (void*)&(mutexId->mutex), fileName, fileLine);
    return(-1);
  }

#ifdef SEMAPHORE_DEBUG
  traceEvent(CONST_TRACE_INFO, "SEMAPHORE_DEBUG: isMutexLocked() testing [0x%X@%s:%d]",
             (void*)&(mutexId->mutex), fileName, fileLine);
#endif

  rc = pthread_mutex_trylock(&(mutexId->mutex));

  /*
    Return code:

    0:    lock succesful
    EBUSY (mutex already locked)
  */

  if(rc == 0) {
    pthread_mutex_unlock(&(mutexId->mutex));
    return(0);
  } else
    return(1);
}

/* ************************************ */

int _releaseMutex(PthreadMutex *mutexId,
		  char* fileName, int fileLine) {
  int rc;

  if(mutexId == NULL) {
    if(myGlobals.endNtop == 0)
      traceEvent(CONST_TRACE_ERROR,
                 "releaseMutex() called with a NULL mutex [%s:%d]",
                 fileName, fileLine);
    return(-1);
  }

  if(!mutexId->isInitialized) {
    if(myGlobals.endNtop == 0)
      traceEvent(CONST_TRACE_ERROR,
                 "releaseMutex() called with an UN-INITIALIZED mutex [0x%X@%s:%d]",
                 (void*)&(mutexId->mutex), fileName, fileLine);
    return(-1);
  }

  pthread_mutex_lock(&stateChangeMutex);

  if(!mutexId->isLocked) {
    traceEvent(CONST_TRACE_WARNING,
	       "releaseMutex() called with an UN-LOCKED mutex [0x%X@%s:%d] last unlock [pid %d, %s:%d]",
	       (void*)&(mutexId->mutex), fileName, fileLine,
               mutexId->unlockPid, mutexId->unlockFile, mutexId->unlockLine);

  }

#ifdef SEMAPHORE_DEBUG
  traceEvent(CONST_TRACE_INFO, "SEMAPHORE_DEBUG: releaseMutex() releasing [0x%X@%s:%d]",
             (void*)&(mutexId->mutex), fileName, fileLine);
#endif
  rc = pthread_mutex_unlock(&(mutexId->mutex));

  if(rc != 0)
    traceEvent(CONST_TRACE_ERROR, "releaseMutex() failed (rc=%d) [0x%X@%s:%d]",
               rc, (void*)&(mutexId->mutex), fileName, fileLine);
  else {
    if(!myGlobals.disableMutexExtraInfo) {
      time_t lockDuration = time(NULL) - mutexId->lockTime;

      if((mutexId->maxLockedDuration < lockDuration)
         || (mutexId->maxLockedDurationUnlockLine == 0 /* Never set */)) {
        mutexId->maxLockedDuration = lockDuration;

        if(fileName != NULL) {
	  strcpy(mutexId->maxLockedDurationUnlockFile, fileName);
	  mutexId->maxLockedDurationUnlockLine = fileLine;
        }

#ifdef SEMAPHORE_DEBUG
        if(mutexId->maxLockedDuration > 0) {
          traceEvent(CONST_TRACE_INFO,
                     "SEMAPHORE_DEBUG: releaseMutex() was locked for maximum, %d secs [0x%X@%s:%d]",
                     mutexId->maxLockedDuration,
                     (void*)&(mutexId->mutex),
                     fileName, fileLine);
        }
#endif
      }
    }

    mutexId->isLocked = 0;
    mutexId->numReleases++;
    if(!myGlobals.disableMutexExtraInfo) {
      mutexId->unlockPid=getpid();
      if(fileName != NULL) {
        strcpy(mutexId->unlockFile, fileName);
        mutexId->unlockLine = fileLine;
      }
    }
  }

  pthread_mutex_unlock(&stateChangeMutex);

#ifdef SEMAPHORE_DEBUG
  if (rc != 0)
    traceEvent(CONST_TRACE_WARNING, "SEMAPHORE_DEBUG: releaseMutex() failed (rc=%d) [0x%X@%s:%d]",
               (void*)&(mutexId->mutex), rc, fileName, fileLine);
  else
    traceEvent(CONST_TRACE_INFO, "SEMAPHORE_DEBUG: releaseMutex() succeeded [0x%X@%s:%d]",
               (void*)&(mutexId->mutex), fileName, fileLine);
#endif
  return(rc);
}

/* ************************************ */

int createCondvar(ConditionalVariable *condvarId) {
  int rc;

  rc = pthread_mutex_init(&condvarId->mutex, NULL);
  rc = pthread_cond_init(&condvarId->condvar, NULL);
  condvarId->predicate = 0;

  return(rc);
}

/* ************************************ */

void deleteCondvar(ConditionalVariable *condvarId) {
  pthread_mutex_destroy(&condvarId->mutex);
  pthread_cond_destroy(&condvarId->condvar);
}

/* ************************************ */

int waitCondvar(ConditionalVariable *condvarId) {
  int rc;

  if((rc = pthread_mutex_lock(&condvarId->mutex)) != 0)
    return rc;

  while(condvarId->predicate <= 0) {
    rc = pthread_cond_wait(&condvarId->condvar, &condvarId->mutex);
  }

  condvarId->predicate--;

  rc = pthread_mutex_unlock(&condvarId->mutex);

  return rc;
}

/* ************************************ */

int timedwaitCondvar(ConditionalVariable *condvarId, struct timespec *expiration) {
  int rc;

  if((rc = pthread_mutex_lock(&condvarId->mutex)) != 0)
    return rc;

  while(condvarId->predicate <= 0) {
    rc = pthread_cond_timedwait(&condvarId->condvar, &condvarId->mutex, expiration);
    if (rc == ETIMEDOUT) {
      return rc;
    }
  }

  condvarId->predicate--;

  rc = pthread_mutex_unlock(&condvarId->mutex);

  return rc;
}

/* ************************************ */

int signalCondvar(ConditionalVariable *condvarId) {
  int rc;

  rc = pthread_mutex_lock(&condvarId->mutex);

  condvarId->predicate++;

  rc = pthread_mutex_unlock(&condvarId->mutex);
  rc = pthread_cond_signal(&condvarId->condvar);

  return rc;
}

/* ************************************ */

#ifdef HAVE_SEMAPHORE_H

int createSem(sem_t *semId, int initialValue) {
  int rc;

  rc = sem_init(semId, 0, initialValue);
  return(rc);
}

/* ************************************ */

void waitSem(sem_t *semId) {
  int rc = sem_wait(semId);

  if((rc != 0) && (errno != 4 /* Interrupted system call */))
    traceEvent(CONST_TRACE_INFO, "waitSem failed [errno=%d/%s]", errno, strerror(errno));
}

/* ************************************ */

int incrementSem(sem_t *semId) {
  return(sem_post(semId));
}

/* ************************************ */
/*
 * WARNING: Enabling semaphors will probably cause bugs!
 */

int decrementSem(sem_t *semId) {
  return(sem_trywait(semId));
}

/* ************************************ */

int deleteSem(sem_t *semId) {
  return(sem_destroy(semId));
}
#endif

#endif /* CFG_MULTITHREADED */
#endif /* WIN32 */

/* ************************************ */

int checkCommand(char* commandName) {
#ifdef WIN32
  return(0);
#else
  char buf[256], *workBuf;
  struct stat statBuf;
  int rc, ecode=0;
  FILE* fd = popen(commandName, "r");

  if(fd == NULL) {
    traceEvent(CONST_TRACE_ERROR,
               "External tool test failed(code=%d). Disabling %s function (popen failed).",
               errno,
               commandName);
    return 0;
  }

  rc = fgetc(fd);
  pclose(fd);

  if(rc == EOF) {
    traceEvent(CONST_TRACE_ERROR,
               "External tool test failed(code=%d20). Disabling %s function (tool won't run).",
               rc,
               commandName);
    return(0);
  }

  /* ok, it can be run ... is it suid? */
  if (snprintf(buf,
               sizeof(buf),
               "which %s 2>/dev/null",
               commandName) < 0) {
    BufferTooShort();
    return(0);
  }
  rc=0;
  fd = popen(buf, "r");
  if (errno == 0) {
    workBuf = fgets(buf, sizeof(buf), fd);
    pclose(fd);
    if(workBuf != NULL) {
      workBuf = strchr(buf, '\n');
      if(workBuf != NULL) workBuf[0] = '\0';
      rc = stat(buf, &statBuf);
      if (rc == 0) {
	if ((statBuf.st_mode & (S_IROTH | S_IXOTH) ) == (S_IROTH | S_IXOTH) ) {
	  if ((statBuf.st_mode & (S_ISUID | S_ISGID) ) != 0) {
	    traceEvent(CONST_TRACE_ERROR,
		       "External tool %s is suid root. FYI: This is good for ntop, but could be dangerous for the system!",
		       commandName);
	    return(1);
	  } else {
	    ecode=7;
	  }
	} else {
	  ecode=6;
	}
      } else {
	ecode=5;
      }
    } else {
      ecode=4;
    }
  } else {
    pclose(fd);
    ecode=3;
  }
  /* test failed ... */
  traceEvent(CONST_TRACE_ERROR,
             "External tool test failed(code=%d%d%d). Disabling %s function%s.",
             rc,
             ecode,
             errno,
             commandName,
             ecode == 7 ? " (tool exists but is not suid root)" : "");
  return(0);

#endif
}

/* ************************************ */

char* decodeNBstring(char* theString, char *theBuffer) {
  int i=0, j = 0, len=strlen(theString);

  while((i<len) && (theString[i] != '\0')) {
    char encodedChar, decodedChar;

    encodedChar =  theString[i++];
    if((encodedChar < 'A') || (encodedChar > 'Z')) break; /* Wrong character */

    encodedChar -= 'A';
    decodedChar = encodedChar << 4;

    encodedChar =  theString[i++];
    if((encodedChar < 'A') || (encodedChar > 'Z')) break; /* Wrong character */

    encodedChar -= 'A';
    decodedChar |= encodedChar;

    theBuffer[j++] = decodedChar;
  }

  theBuffer[j] = '\0';

  for(i=0; i<j; i++)
    theBuffer[i] = (char)tolower(theBuffer[i]);

  return(theBuffer);
}

/* ************************************ */

char* savestr(const char *str)
{
  u_int size;
  char *p;
  static char *strptr = NULL;
  static u_int strsize = 0;

  size = strlen(str) + 1;
  if(size > strsize) {
    strsize = 1024;
    if(strsize < size)
      strsize = size;
    strptr = (char*)malloc(strsize);
    if(strptr == NULL) {
      fprintf(stderr, "savestr: malloc\n");
      exit(1);
    }
  }
  (void)strncpy(strptr, str, strsize);
  p = strptr;
  strptr += size;
  strsize -= size;
  return(p);
}


/* ************************************ */

/* The function below has been inherited by tcpdump */


int name_interpret(char *in, char *out, int numBytes) {
  int ret, len;
  char *b;

  if(numBytes <= 0) {
    /* traceEvent(CONST_TRACE_WARNING, "name_interpret error (numBytes=%d)", numBytes); */
    return(-1);
  }

  len = (*in++)/2;
  b  = out;
  *out=0;

  if(len > 30 || len < 1) {
    /* traceEvent(CONST_TRACE_WARNING, "name_interpret error (numBytes=%d)", numBytes); */
    return(-1);
  }

  while (len--) {
    if(in[0] < 'A' || in[0] > 'P' || in[1] < 'A' || in[1] > 'P') {
      *out = 0;
      return(-1);
    }

    *out = ((in[0]-'A')<<4) + (in[1]-'A');
    in += 2;
    out++;
  }
  ret = *(--out);
  *out = 0;

  /* Courtesy of Roberto F. De Luca <deluca@tandar.cnea.gov.ar> */
  /* Trim trailing whitespace from the returned string */
  for(out--; out>=b && *out==' '; out--) *out = '\0';

  return(ret);
}


/* ******************************* */

char* getNwInterfaceType(int i) {
  switch(myGlobals.device[i].datalink) {
  case DLT_NULL:	return("No&nbsp;link-layer&nbsp;encapsulation");
  case DLT_EN10MB:	return("Ethernet");
  case DLT_EN3MB:	return("Experimental&nbsp;Ethernet&nbsp;(3Mb)");
  case DLT_AX25:	return("Amateur&nbsp;Radio&nbsp;AX.25");
  case DLT_PRONET:	return("Proteon&nbsp;ProNET&nbsp;Token&nbsp;Ring");
  case DLT_CHAOS: 	return("Chaos");
  case DLT_IEEE802:	return("IEEE&nbsp;802&nbsp;Networks");
  case DLT_ARCNET:	return("ARCNET");
  case DLT_SLIP:	return("SLIP");
  case DLT_PPP:         return("PPP");
  case DLT_FDDI:	return("FDDI");
  case DLT_ATM_RFC1483:	return("LLC/SNAP&nbsp;encapsulated&nbsp;ATM");
  case DLT_RAW:  	return("Raw&nbsp;IP");
  case DLT_SLIP_BSDOS:	return("BSD/OS&nbsp;SLIP");
  case DLT_PPP_BSDOS:	return("BSD/OS&nbsp;PPP");
  }

  return(""); /* NOTREACHED (I hope) */
}

/* ************************************ */

int getActualInterface(u_int deviceId) {
  if(myGlobals.mergeInterfaces) {
    return(myGlobals.device[0].dummyDevice == 0 ? 0 : deviceId);
  } else
    return(deviceId);
}

/* ************************************ */

void resetHostsVariables(HostTraffic* el) {
  FD_ZERO(&(el->flags));

  el->totContactedSentPeers = el->totContactedRcvdPeers = 0;
  resetUsageCounter(&el->contactedSentPeers);
  resetUsageCounter(&el->contactedRcvdPeers);
  resetUsageCounter(&el->contactedRouters);

  el->vlanId = -1;
  el->hostAS = 0;
  if (el->dnsDomainValue != NULL)      free(el->dnsDomainValue);
  el->dnsDomainValue = NULL;
  if (el->dnsTLDValue != NULL)      free(el->dnsTLDValue);
  el->dnsTLDValue = NULL;
  if (el->ip2ccValue != NULL)       free(el->ip2ccValue);
  el->ip2ccValue = NULL;
  el->hostResolvedName[0] = '\0';
  el->hostResolvedNameType = FLAG_HOST_SYM_ADDR_TYPE_NONE;
  if (el->fingerprint != NULL)         free(el->fingerprint);
  el->fingerprint = NULL;
  if (el->nonIPTraffic != NULL)        free(el->nonIPTraffic);
  el->nonIPTraffic = NULL;
  if (el->routedTraffic != NULL)       free(el->routedTraffic);
  el->routedTraffic = NULL;
  if (el->portsUsage != NULL)          free(el->portsUsage);
  el->portsUsage = NULL;
  if (el->protoIPTrafficInfos != NULL) free(el->protoIPTrafficInfos);
  el->protoIPTrafficInfos = NULL;
  if (el->icmpInfo != NULL)            free(el->icmpInfo);
  el->icmpInfo = NULL;
  if (el->protocolInfo != NULL)        free(el->protocolInfo);
  el->protocolInfo = NULL;

  el->vsanId = -1;
  resetUsageCounter(&el->contactedSentPeers);
  resetUsageCounter(&el->contactedRcvdPeers);
  resetUsageCounter(&el->contactedRouters);

  memset(el->recentlyUsedClientPorts, -1, sizeof(int)*MAX_NUM_RECENT_PORTS);
  memset(el->recentlyUsedServerPorts, -1, sizeof(int)*MAX_NUM_RECENT_PORTS);
  memset(el->otherIpPortsRcvd, -1, sizeof(int)*MAX_NUM_RECENT_PORTS);
  memset(el->otherIpPortsSent, -1, sizeof(int)*MAX_NUM_RECENT_PORTS);

  if (el->secHostPkts != NULL)         free(el->secHostPkts);
  el->secHostPkts = NULL;
}

/* ************************************
 *
 * [Borrowed from tcpdump]
 *
 */
u_short in_cksum(const u_short *addr, int len, u_short csum) {
  int nleft = len;
  const u_short *w = addr;
  u_short answer;
  int sum = csum;

  /*
   *  Our algorithm is simple, using a 32 bit accumulator (sum),
   *  we add sequential 16 bit words to it, and at the end, fold
   *  back all the carry bits from the top 16 bits into the lower
   *  16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }
  if(nleft == 1)
    sum += htons(*(u_char *)w<<8);

  /*
   * add back carry outs from top 16 bits to low 16 bits
   */
  sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
  sum += (sum >> 16);			/* add carry */
  answer = ~sum;			/* truncate to 16 bits */
  return(answer);
}

/* ****************** */

void addTimeMapping(u_int16_t transactionId,
		    struct timeval theTime) {

  u_int idx = transactionId % CONST_NUM_TRANSACTION_ENTRIES;
  int i=0;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: addTimeMapping(0x%X)", transactionId);
#endif
  for(i=0; i<CONST_NUM_TRANSACTION_ENTRIES; i++) {
    if(myGlobals.transTimeHash[idx].transactionId == 0) {
      myGlobals.transTimeHash[idx].transactionId = transactionId;
      myGlobals.transTimeHash[idx].theTime = theTime;
      return;
    } else if(myGlobals.transTimeHash[idx].transactionId == transactionId) {
      myGlobals.transTimeHash[idx].theTime = theTime;
      return;
    }

    idx = (idx+1) % CONST_NUM_TRANSACTION_ENTRIES;
  }
}

/* ****************** */

/*
 * The time difference in microseconds
 */
long delta_time (struct timeval * now,
		 struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }

  return((delta_seconds * 1000000) + delta_microseconds);
}

/* ****************** */

time_t getTimeMapping(u_int16_t transactionId,
		      struct timeval theTime) {

  u_int idx = transactionId % CONST_NUM_TRANSACTION_ENTRIES;
  int i=0;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: getTimeMapping(0x%X)", transactionId);
#endif

  /* ****************************************

  As  Andreas Pfaller <apfaller@yahoo.com.au>
  pointed out, the hash code needs to be optimised.
  Actually the hash is scanned completely
  if (unlikely but possible) the searched entry
  is not present into the table.

  **************************************** */

  for(i=0; i<CONST_NUM_TRANSACTION_ENTRIES; i++) {
    if(myGlobals.transTimeHash[idx].transactionId == transactionId) {
      time_t msDiff = (time_t)delta_time(&theTime, &myGlobals.transTimeHash[idx].theTime);
      myGlobals.transTimeHash[idx].transactionId = 0; /* Free bucket */
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: getTimeMapping(0x%X) [diff=%d]",
		 transactionId, (unsigned long)msDiff);
#endif
      return(msDiff);
    }

    idx = (idx+1) % CONST_NUM_TRANSACTION_ENTRIES;
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: getTimeMapping(0x%X) [not found]", transactionId);
#endif
  return(0); /* Not found */
}

/* ********************************** */

void traceEvent(int eventTraceLevel, char* file,
		int line, char * format, ...) {
  va_list va_ap;
  va_start (va_ap, format);

  /* Fix courtesy of "Burton M. Strauss III" <BStrauss@acm.org> */
  if(eventTraceLevel <= myGlobals.traceLevel) {
    time_t theTime = time(NULL);
    struct tm t;
    char bufTime[LEN_TIMEFORMAT_BUFFER];
    char buf[LEN_GENERAL_WORK_BUFFER];
    char bufMsg[LEN_GENERAL_WORK_BUFFER];
    char bufMsgID[LEN_MEDIUM_WORK_BUFFER];
    char bufLineID[LEN_MEDIUM_WORK_BUFFER];

    int beginFileIdx=0;
    char *mFile = NULL;

    /* First we prepare the various fields */

    /* Message time, used for printf() - remember, syslog() does it's own time stamp */
    memset(bufTime, 0, sizeof(bufTime));
    strftime(bufTime, sizeof(bufTime), CONST_LOCALE_TIMESPEC, localtime_r(&theTime, &t));

    /* The file/line or 'MSGID' tag, depends on logExtra */
    memset(bufMsgID, 0, sizeof(bufMsgID));

    if(myGlobals.traceLevel > CONST_NOISY_TRACE_LEVEL) {
      mFile = strdup(file);

      for(beginFileIdx=strlen(mFile)-1; beginFileIdx>0; beginFileIdx--) {
	if(mFile[beginFileIdx] == '.') mFile[beginFileIdx] = '\0'; /* Strip off .c */
#if defined(WIN32)
	if(mFile[beginFileIdx-1] == '\\') break;  /* Start after \ (Win32)  */
#else
	if(mFile[beginFileIdx-1] == '/') break;   /* Start after / (!Win32) */
#endif
      }

      if(myGlobals.traceLevel >= CONST_DETAIL_TRACE_LEVEL) {
        unsigned int messageid = 0;
        int i;

        if(snprintf(bufLineID, sizeof(bufLineID), "[%s:%d] ", &mFile[beginFileIdx], line) < 0)
          BufferTooShort();
	
        /* Hash the message format into an id */
        for (i=0; i<=strlen(format); i++) {
	  messageid = (messageid << 1) ^ max(0,format[i]-32);
        }
	
        /* 1st chars of file name for uniqueness */
        messageid += (file[0]-32) * 256 + file[1]-32;
        if(snprintf(bufMsgID, sizeof(bufMsgID), "[MSGID%07d]", (messageid & 0x8fffff)) < 0)
          BufferTooShort();
      }
      
      free(mFile);
    }

    /* Now we use the variable functions to 'print' the user's message */
    memset(bufMsg, 0, sizeof(bufMsg));
    vsnprintf(bufMsg, sizeof(bufMsg), format, va_ap);
    /* Strip a trailing return from bufMsg */
    if(bufMsg[strlen(bufMsg)-1] == '\n')
      bufMsg[strlen(bufMsg)-1] = 0;

    /* Second we prepare the complete log message into buf
     */
    memset(buf, 0, sizeof(buf));
    if(snprintf(buf, sizeof(buf), "%s %s %s%s%s",
		bufTime,
		(myGlobals.traceLevel >= CONST_DETAIL_TRACE_LEVEL) ? bufMsgID : "",
		(myGlobals.traceLevel > CONST_DETAIL_TRACE_LEVEL) ? bufLineID : "",
		eventTraceLevel == CONST_FATALERROR_TRACE_LEVEL  ? "**FATAL_ERROR** " :
		eventTraceLevel == CONST_ERROR_TRACE_LEVEL   ? "**ERROR** " :
		eventTraceLevel == CONST_WARNING_TRACE_LEVEL ? "**WARNING** " : "",
		bufMsg
		) < 0)
      BufferTooShort();

    /* Finished preparing message fields */

    /* So, (INFO & above only) - post it to logView buffer. */
    if ((eventTraceLevel <= CONST_INFO_TRACE_LEVEL) &&
        (myGlobals.logView != NULL)) {

#ifdef CFG_MULTITHREADED
#ifndef WIN32
      if(myGlobals.logViewMutex.isInitialized)
	pthread_mutex_lock(&myGlobals.logViewMutex.mutex);
#endif
#endif

      if (myGlobals.logView[myGlobals.logViewNext] != NULL)
	free(myGlobals.logView[myGlobals.logViewNext]);

      myGlobals.logView[myGlobals.logViewNext] = strdup(buf);

      myGlobals.logViewNext = (myGlobals.logViewNext + 1) % CONST_LOG_VIEW_BUFFER_SIZE;

#ifdef CFG_MULTITHREADED
#ifndef WIN32
      if(myGlobals.logViewMutex.isInitialized)
	pthread_mutex_unlock(&myGlobals.logViewMutex.mutex);
#endif
#endif

    }

    /* If ntop is a Win32 service, we're done - we don't (yet) write to the
     * windows event logs and there's no console...
     */
#ifdef WIN32
    if(isNtopAservice) return;
#endif

    /* Otherwise, we have two paths -
     *   Win32/no syslog headers/syslog not enabled via -L run time switch
     *      use: printf()
     *   Not Win32, Have syslog headers and enabled via -L run time switch
     *      use: syslog -
     */

#ifdef MAKE_WITH_SYSLOG
    if(myGlobals.useSyslog == FLAG_SYSLOG_NONE) {
#endif

      printf("%s\n", buf);
      fflush(stdout);

#ifdef MAKE_WITH_SYSLOG
    } else {
      /* Skip over time - syslog() adds it automatically) */
      char *bufLog = &buf[strlen(bufTime)];

      /* SYSLOG and set */
      openlog("ntop", LOG_PID, myGlobals.useSyslog);

      /* syslog(..) call fix courtesy of Peter Suschlik <peter@zilium.de> */
#ifdef MAKE_WITH_LOG_XXXXXX
      switch(myGlobals.traceLevel) {
      case CONST_FATALERROR_TRACE_LEVEL:
      case CONST_ERROR_TRACE_LEVEL:
	syslog(LOG_ERR, "%s", bufLog);
	break;
      case CONST_WARNING_TRACE_LEVEL:
	syslog(LOG_WARNING, "%s", bufLog);
	break;
      case CONST_ALWAYSDISPLAY_TRACE_LEVEL:
	syslog(LOG_NOTICE, "%s", bufLog);
	break;
      default:
	syslog(LOG_INFO, "%s", bufLog);
	break;
      }
#else
      syslog(LOG_ERR, "%s", bufLog);
#endif
      closelog();
    }
#endif /* MAKE_WITH_SYSLOG */

  }

  va_end (va_ap);
}

/* ******************************************** */

char* _strncpy(char *dest, const char *src, size_t n) {
  size_t len = strlen(src);

  if(len > (n-1))
    len = n-1;

  memcpy(dest, src, len);
  dest[len] = '\0';
  return(dest);
}

/* ******************************************** */

/* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
#ifndef HAVE_STRTOK_R
/* Reentrant string tokenizer.  Generic myGlobals.version.

Slightly modified from: glibc 2.1.3

Copyright (C) 1991, 1996, 1997, 1998, 1999 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If not,
write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

char *strtok_r(char *s, const char *delim, char **save_ptr) {
  char *token;

  if (s == NULL)
    s = *save_ptr;

  /* Scan leading delimiters.  */
  s += strspn (s, delim);
  if (*s == '\0')
    return NULL;

  /* Find the end of the token.  */
  token = s;
  s = strpbrk (token, delim);
  if (s == NULL)
    /* This token finishes the string.  */
    *save_ptr = "";
  else {
    /* Terminate the token and make *SAVE_PTR point past it.  */
    *s = '\0';
    *save_ptr = s + 1;
  }

  return token;
}
#endif

/* ********************************** */

/* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */

int getSniffedDNSName(char *hostNumIpAddress,
		      char *name, int maxNameLen) {
  int found = 0;

  name[0] = 0;

  if((hostNumIpAddress[0] != '\0') && myGlobals.dnsCacheFile) {
    datum key;
    datum data;

    key.dptr = hostNumIpAddress;
    key.dsize = strlen(key.dptr)+1;

    data = gdbm_fetch(myGlobals.dnsCacheFile, key);

    if(data.dptr != NULL) {
      xstrncpy(name, data.dptr, maxNameLen);
      free(data.dptr);
      found = 1;
    }
  }

  return(found);
}

/* ******************************** */

char *strtolower(char *s) {
  while (*s) {
    *s=tolower(*s);
    s++;
  }

  return(s);
}

/* ******************************** */
/*
 *  xstrncpy() - similar to strncpy(3) but terminates string always with
 * '\0' if (n != 0 and dst != NULL),  and doesn't do padding
 */
char *xstrncpy(char *dest, const char *src, size_t n) {
  char *r = dest;
  if (!n || !dest)
    return dest;
  if (src)
    while (--n != 0 && *src != '\0')
      *dest++ = *src++;
  *dest = '\0';
  return r;
}

/* *************************************** */

int strOnlyDigits(const char *s) {

  if((*s) == '\0')
    return 0;

  while ((*s) != '\0') {
    if(!isdigit(*s))
      return 0;
    s++;
  }

  return(1);
}

/* ****************************************************** */

FILE* getNewRandomFile(char* fileName, int len) {
  FILE* fd;

#ifndef WIN32
#if 0
  int tmpfd;

  /* Patch courtesy of Thomas Biege <thomas@suse.de> */
  if(((tmpfd = mkstemp(fileName)) < 0)
     || (fchmod(tmpfd, 0600) < 0)
     || ((fd = fdopen(tmpfd, "wb")) == NULL))
    fd = NULL;
#else
  char tmpFileName[NAME_MAX];

  strcpy(tmpFileName, fileName);
  if(snprintf(fileName, sizeof(fileName), "%s-%lu", tmpFileName,
          myGlobals.numHandledRequests[0]+myGlobals.numHandledRequests[1]) < 0)
    BufferTooShort();
  fd = fopen(fileName, "wb");
#endif /* 0 */
#else
  tmpnam(fileName);
  fd = fopen(fileName, "wb");
#endif

  if(fd == NULL)
    traceEvent(CONST_TRACE_WARNING, "Unable to create temp. file (%s). ", fileName);

  return(fd);
}

/* ****************************************************** */

/*
  Function added in order to catch invalid
  strings passed on the command line.

  Thanks to Bailleux Christophe <cb@grolier.fr> for
  pointing out the finger at the problem.
*/

void stringSanityCheck(char* string) {
  int i, j;

  if(string == NULL)  {
    traceEvent(CONST_TRACE_FATALERROR, "Invalid string specified.");
    exit(-1);
  }

  for(i=0, j=1; i<strlen(string); i++) {
    switch(string[i]) {
    case '%':
    case '\\':
      j=0;
      break;
    }
  }

  if(j == 0) {
    traceEvent(CONST_TRACE_FATALERROR, "Invalid string '%s' specified.",
	       string);
    exit(-1);
  }

  if((string[strlen(string)-1] == '/') ||
     (string[strlen(string)-1] == '\\')) {
    traceEvent(CONST_TRACE_WARNING, "Trailing slash removed from argument '%s'", string);
    string[strlen(string)-1] = '\0';
  }
}

/* ****************************************************** */

/*
  Function added in order to catch invalid (too long)
  myGlobals.device names specified on the command line.

  Thanks to Bailleux Christophe <cb@grolier.fr> for
  pointing out the finger at the problem.
*/

void deviceSanityCheck(char* string) {
  int i, j;

  if(strlen(string) > MAX_DEVICE_NAME_LEN)
    j = 0;
  else {
    for(i=0, j=1; i<strlen(string); i++) {
      switch(string[i]) {
      case ' ':
      case ',':
	j=0;
	break;
      }
    }
  }

  if(j == 0) {
    traceEvent(CONST_TRACE_FATALERROR, "Invalid device specified");
    exit(-1);
  }
}

/* ****************************************************** */

#ifndef HAVE_SNPRINTF
int snprintf(char *string, size_t maxlen, const char *format, ...) {
  int ret=0;
  va_list args;

  va_start(args, format);
  vsprintf(string,format,args);
  va_end(args);
  return ret;
}
#endif

/* ************************ */

void fillDomainName(HostTraffic *el) {
  u_int i;
  char *ip2cc;

  if(theDomainHasBeenComputed(el))
    return;

  accessAddrResMutex("fillDomainName");

  /* Reset values... */
  if(el->dnsDomainValue != NULL) free(el->dnsDomainValue);
  el->dnsDomainValue = NULL;
  if(el->dnsTLDValue != NULL) free(el->dnsTLDValue);
  el->dnsTLDValue = NULL;
  if(el->ip2ccValue != NULL) free(el->ip2ccValue);
  el->ip2ccValue = NULL;

  if((el->hostResolvedNameType != FLAG_HOST_SYM_ADDR_TYPE_NAME) ||
     (el->hostResolvedName    == NULL) ||
     (el->hostResolvedName[0] == '\0')) {
    /* Do NOT set FLAG_THE_DOMAIN_HAS_BEEN_COMPUTED - we still might learn the DNS Name later */
    releaseAddrResMutex();
    return;
  }

  ip2cc = ip2CountryCode(el->hostIpAddress);

  if((ip2cc == NULL) || (strcmp(ip2cc, "***") == 0)) {
    /* We are unable to associate a domain with this IP address. */
    el->ip2ccValue = NULL;
  } else {
    el->ip2ccValue = strdup(ip2cc);
  }

  /* Walk back to the last . */
  i = strlen(el->hostResolvedName)-1;
  while(i > 0)
    if(el->hostResolvedName[i] == '.')
      break;
    else
      i--;

  /* If we have it (.), use it, otherwise use the shortDomainName set at startup
   * last choice, leave it null from above
   */
  if(i > 0)
    el->dnsTLDValue = strdup(&el->hostResolvedName[i+1]);
  else if (myGlobals.shortDomainName != NULL) {
    /* Walk back to the last . */
    i = strlen(el->hostResolvedName)-1;
    while(i > 0)
      if(myGlobals.shortDomainName[i] == '.')
        break;
      else
        i--;
    if(i > 0)
      el->dnsTLDValue = strdup(&(myGlobals.shortDomainName[i+1]));
  }


  /* Walk Forwards to the first . */
  for(i=0; i<strlen(el->hostResolvedName)-1; i++) {
    if(el->hostResolvedName[i] == '.')
      break;
  }

  /* If we have it (.), use it, otherwise use the shortDomainName set at startup
   * last choice, leave it null from above
   */
  if(i < strlen(el->hostResolvedName)-1)
    el->dnsDomainValue = strdup(&el->hostResolvedName[i+1]);
  else if (myGlobals.shortDomainName != NULL)
    el->dnsDomainValue = strdup(myGlobals.shortDomainName);

  FD_SET(FLAG_THE_DOMAIN_HAS_BEEN_COMPUTED, &el->flags);

  releaseAddrResMutex();
  return;
}

/* ********************************* */

/* similar to Java.String.trim() */
void trimString(char* str) {
  int len = strlen(str), i, idx;
  char *out = (char *) malloc(sizeof(char) * (len+1));

  if(out == NULL) {
    str = NULL;
    return;
  }

  for(i=0, idx=0; i<len; i++)
    {
      switch(str[i])
	{
	case ' ':
	case '\t':
	  if((idx > 0)
	     && (out[idx-1] != ' ')
	     && (out[idx-1] != '\t'))
	    out[idx++] = str[i];
	  break;
	default:
	  out[idx++] = str[i];
	  break;
	}
    }

  out[idx] = '\0';
  strncpy(str, out, len);
  free(out);
}

/* ****************************** */

void setNBnodeNameType(HostTraffic *theHost, char nodeType,
		       char isQuery, char* nbName) {
  trimString(nbName);

  if((nbName == NULL) || (strlen(nbName) == 0))
    return;

  if(strlen(nbName) >= (MAX_LEN_SYM_HOST_NAME-1)) /* (**) */
    nbName[MAX_LEN_SYM_HOST_NAME-2] = '\0';

  if(theHost->nonIPTraffic == NULL) theHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));

  theHost->nonIPTraffic->nbNodeType = (char)nodeType;
  /* Courtesy of Roberto F. De Luca <deluca@tandar.cnea.gov.ar> */

  theHost->nonIPTraffic->nbNodeType = (char)nodeType;

  switch(nodeType) {
  case 0x0:  /* Workstation */
  case 0x20: /* Server/Messenger/Main name */
    if(!isQuery) {
      if(theHost->nonIPTraffic->nbHostName == NULL) {
	theHost->nonIPTraffic->nbHostName = strdup(nbName);
	updateHostName(theHost);

	if(theHost->hostResolvedName[0] == '\0') {
	  int i;

	  for(i=0; i<strlen(nbName); i++) if(isupper(nbName[i])) tolower(nbName[i]);
          setResolvedName(theHost, nbName, FLAG_HOST_SYM_ADDR_TYPE_NETBIOS);
	}

#ifdef DEBUG
	printf("DEBUG: nbHostName=%s [0x%X]\n", nbName, nodeType);
#endif
      }
    }
    break;
  case 0x1C: /* Domain Controller */
  case 0x1E: /* Domain */
  case 0x1B: /* Domain */
  case 0x1D: /* Workgroup (I think) */
    if(theHost->nonIPTraffic->nbDomainName == NULL) {
      if(strcmp(nbName, "__MSBROWSE__") && strncmp(&nbName[2], "__", 2)) {
	theHost->nonIPTraffic->nbDomainName = strdup(nbName);
      }
      break;
    }
  }

  if(!isQuery) {
    switch(nodeType) {
    case 0x0:  /* Workstation */
      FD_SET(FLAG_HOST_TYPE_WORKSTATION, &theHost->flags);
    case 0x20: /* Server */
      FD_SET(FLAG_HOST_TYPE_SERVER, &theHost->flags);
    case 0x1B: /* Master Browser */
      FD_SET(FLAG_HOST_TYPE_MASTER_BROWSER, &theHost->flags);
    }
  }
}

/* ******************************************* */

void addPassiveSessionInfo(HostAddr *theHost, u_short thePort) {
  int i;
  time_t timeoutTime = myGlobals.actTime - PARM_PASSIVE_SESSION_MINIMUM_IDLE;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Adding %ld:%d", theHost, thePort);
#endif

  for(i=0; i<passiveSessionsLen; i++) {
    if((passiveSessions[i].sessionPort == 0)
       || (passiveSessions[i].creationTime < timeoutTime)) {
      addrcpy(&passiveSessions[i].sessionHost,theHost),
	passiveSessions[i].sessionPort = thePort,
	passiveSessions[i].creationTime = myGlobals.actTime;
      break;
    }
  }

  if(i == passiveSessionsLen) {
    /* Slot Not found */
    traceEvent(CONST_TRACE_INFO, "Info: passiveSessions[size=%d] is full", passiveSessionsLen);

    /* Shift table entries */
    for(i=1; i<passiveSessionsLen; i++) {
      passiveSessions[i-1].sessionHost = passiveSessions[i].sessionHost,
	passiveSessions[i-1].sessionPort = passiveSessions[i].sessionPort;
    }
    addrcpy(&passiveSessions[passiveSessionsLen-1].sessionHost,theHost),
      passiveSessions[passiveSessionsLen-1].sessionPort = thePort;
  }
}

/* ******************************************* */

int isPassiveSession(HostAddr *theHost, u_short thePort) {
  int i;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Searching for %ld:%d",
	     theHost, thePort);
#endif

  for(i=0; i<passiveSessionsLen; i++) {
    if((addrcmp(&passiveSessions[i].sessionHost,theHost) == 0)
       && (passiveSessions[i].sessionPort == thePort)) {
      addrinit(&passiveSessions[i].sessionHost),
	passiveSessions[i].sessionPort = 0,
	passiveSessions[i].creationTime = 0;
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: Found passive FTP session");
#endif
      return(1);
    }
  }

  return(0);
}

/* ******************************************* */

void initPassiveSessions(void) {
  int len;

  len = sizeof(SessionInfo)*MAX_PASSIVE_FTP_SESSION_TRACKER;
  passiveSessions = (SessionInfo*)malloc(len);
  memset(passiveSessions, 0, len);
  passiveSessionsLen = MAX_PASSIVE_FTP_SESSION_TRACKER;
}

/* ******************************* */

void termPassiveSessions(void) {
  if(myGlobals.enableSessionHandling)
    free(passiveSessions);
}

/* ******************************* */

int getPortByName(ServiceEntry **theSvc, char* portName) {
  int idx;

  for(idx=0; idx<myGlobals.numActServices; idx++) {

#ifdef DEBUG
    if(theSvc[idx] != NULL)
      traceEvent(CONST_TRACE_INFO, "DEBUG: %d/%s [%s]",
		 theSvc[idx]->port,
		 theSvc[idx]->name, portName);
#endif

    if((theSvc[idx] != NULL)
       && (strcmp(theSvc[idx]->name, portName) == 0))
      return(theSvc[idx]->port);
  }

  return(-1);
}

/* ******************************* */

char* getPortByNumber(ServiceEntry **theSvc, int port) {
  int idx = port % myGlobals.numActServices;
  ServiceEntry *scan;

  for(;;) {
    scan = theSvc[idx];

    if((scan != NULL) && (scan->port == port))
      return(scan->name);
    else if(scan == NULL)
      return(NULL);
    else
      idx = (idx+1) % myGlobals.numActServices;
  }
}

/* ******************************* */

char* getPortByNum(int port, int type) {
  char* rsp;

  if(type == IPPROTO_TCP) {
    rsp = getPortByNumber(myGlobals.tcpSvc, port);
  } else {
    rsp = getPortByNumber(myGlobals.udpSvc, port);
  }

  return(rsp);
}

/* ******************************* */

char* getAllPortByNum(int port, char *outBuf, int outBufLen) {
  char* rsp;

  rsp = getPortByNumber(myGlobals.tcpSvc, port); /* Try TCP first... */
  if(rsp == NULL)
    rsp = getPortByNumber(myGlobals.udpSvc, port);  /* ...then UDP */

  if(rsp != NULL)
    return(rsp);
  else {
    if(snprintf(outBuf, outBufLen, "%d", port) < 0)
      BufferTooShort();
    return(outBuf);
  }
}

/* ******************************* */

int getAllPortByName(char* portName) {
  int rsp;

  rsp = getPortByName(myGlobals.tcpSvc, portName); /* Try TCP first... */
  if(rsp == -1)
    rsp = getPortByName(myGlobals.udpSvc, portName);  /* ...then UDP */

  return(rsp);
}


/* ******************************* */

void addPortHashEntry(ServiceEntry **theSvc, int port, char* name) {
  int idx = port % myGlobals.numActServices;
  ServiceEntry *scan;

  for(;;) {
    scan = theSvc[idx];

    if(scan == NULL) {
      theSvc[idx] = (ServiceEntry*)malloc(sizeof(ServiceEntry));
      theSvc[idx]->port = (u_short)port;
      theSvc[idx]->name = strdup(name);
      break;
    } else if(scan->port == port) {
      break; /* Already there */
    } else
      idx = (idx+1) % myGlobals.numActServices;
  }
}

/* ******************************* */

void resetUsageCounter(UsageCounter *counter) {
  int i;

  memset(counter, 0, sizeof(UsageCounter));

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
    setEmptySerial(&counter->peersSerials[i]);
}

/* ************************************ */

/*
  This function has to be used to reset (i.e. initialize to
  empty values in the correct range) HostTraffic
  instances.
*/

void resetSecurityHostTraffic(HostTraffic *el) {

  if(el->secHostPkts == NULL) return;

  resetUsageCounter(&el->secHostPkts->synPktsSent);
  resetUsageCounter(&el->secHostPkts->rstPktsSent);
  resetUsageCounter(&el->secHostPkts->rstAckPktsSent);
  resetUsageCounter(&el->secHostPkts->synFinPktsSent);
  resetUsageCounter(&el->secHostPkts->finPushUrgPktsSent);
  resetUsageCounter(&el->secHostPkts->nullPktsSent);
  resetUsageCounter(&el->secHostPkts->ackXmasFinSynNullScanSent);
  resetUsageCounter(&el->secHostPkts->rejectedTCPConnSent);
  resetUsageCounter(&el->secHostPkts->establishedTCPConnSent);
  resetUsageCounter(&el->secHostPkts->terminatedTCPConnServer);
  resetUsageCounter(&el->secHostPkts->terminatedTCPConnClient);
  resetUsageCounter(&el->secHostPkts->udpToClosedPortSent);
  resetUsageCounter(&el->secHostPkts->udpToDiagnosticPortSent);
  resetUsageCounter(&el->secHostPkts->tcpToDiagnosticPortSent);
  resetUsageCounter(&el->secHostPkts->tinyFragmentSent);
  resetUsageCounter(&el->secHostPkts->icmpFragmentSent);
  resetUsageCounter(&el->secHostPkts->overlappingFragmentSent);
  resetUsageCounter(&el->secHostPkts->closedEmptyTCPConnSent);
  resetUsageCounter(&el->secHostPkts->icmpPortUnreachSent);
  resetUsageCounter(&el->secHostPkts->icmpHostNetUnreachSent);
  resetUsageCounter(&el->secHostPkts->icmpProtocolUnreachSent);
  resetUsageCounter(&el->secHostPkts->icmpAdminProhibitedSent);
  resetUsageCounter(&el->secHostPkts->malformedPktsSent);

  /* ************* */

  resetUsageCounter(&el->contactedRcvdPeers);

  resetUsageCounter(&el->secHostPkts->synPktsRcvd);
  resetUsageCounter(&el->secHostPkts->rstPktsRcvd);
  resetUsageCounter(&el->secHostPkts->rstAckPktsRcvd);
  resetUsageCounter(&el->secHostPkts->synFinPktsRcvd);
  resetUsageCounter(&el->secHostPkts->finPushUrgPktsRcvd);
  resetUsageCounter(&el->secHostPkts->nullPktsRcvd);
  resetUsageCounter(&el->secHostPkts->ackXmasFinSynNullScanRcvd);
  resetUsageCounter(&el->secHostPkts->rejectedTCPConnRcvd);
  resetUsageCounter(&el->secHostPkts->establishedTCPConnRcvd);
  resetUsageCounter(&el->secHostPkts->udpToClosedPortRcvd);
  resetUsageCounter(&el->secHostPkts->udpToDiagnosticPortRcvd);
  resetUsageCounter(&el->secHostPkts->tcpToDiagnosticPortRcvd);
  resetUsageCounter(&el->secHostPkts->tinyFragmentRcvd);
  resetUsageCounter(&el->secHostPkts->icmpFragmentRcvd);
  resetUsageCounter(&el->secHostPkts->overlappingFragmentRcvd);
  resetUsageCounter(&el->secHostPkts->closedEmptyTCPConnRcvd);
  resetUsageCounter(&el->secHostPkts->icmpPortUnreachRcvd);
  resetUsageCounter(&el->secHostPkts->icmpHostNetUnreachRcvd);
  resetUsageCounter(&el->secHostPkts->icmpProtocolUnreachRcvd);
  resetUsageCounter(&el->secHostPkts->icmpAdminProhibitedRcvd);
  resetUsageCounter(&el->secHostPkts->malformedPktsRcvd);

  resetUsageCounter(&el->contactedSentPeers);
  resetUsageCounter(&el->contactedRcvdPeers);
  resetUsageCounter(&el->contactedRouters);
}

/* ********************************************* */

char* mapIcmpType(int icmpType) {
  static char icmpString[4];

  icmpType %= ICMP_MAXTYPE; /* Just to be safe... */

  switch(icmpType) {
  case 0: return("ECHOREPLY");
  case 3: return("UNREACH");
  case 4: return("SOURCEQUENCH");
  case 5: return("REDIRECT");
  case 8: return("ECHO");
  case 9: return("ROUTERADVERT");
  case 10: return("ROUTERSOLICI");
  case 11: return("TIMXCEED");
  case 12: return("PARAMPROB");
  case 13: return("TIMESTAMP");
  case 14: return("TIMESTAMPREPLY");
  case 15: return("INFOREQ");
  case 16: return("INFOREQREPLY");
  case 17: return("MASKREQ");
  case 18: return("MASKREPLY");
  default:
    if(snprintf(icmpString, sizeof(icmpString), "%d", icmpType) < 0)
      BufferTooShort();
    return(icmpString);
  }
}

/* ************************************ */

/* Do not delete this line! */
#undef incrementUsageCounter

int _incrementUsageCounter(UsageCounter *counter,
			   HostTraffic *theHost, int actualDeviceId,
			   char* file, int line) {
  u_int i, found=0;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: incrementUsageCounter(%u) @ %s:%d",
	     peerIdx, file, line);
#endif

  if(theHost == NULL) return(0);

  counter->value.value++;

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
    if(emptySerial(&counter->peersSerials[i])) {
      copySerial(&counter->peersSerials[i], &theHost->hostSerial);
      return(1);
      break;
    } else if(cmpSerial(&counter->peersSerials[i], &theHost->hostSerial)) {
      found = 1;
      break;
    }
  }

  if(!found) {
    for(i=0; i<MAX_NUM_CONTACTED_PEERS-1; i++)
      copySerial(&counter->peersSerials[i], &counter->peersSerials[i+1]);

    /* Add host serial and not it's index */
    copySerial(&counter->peersSerials[MAX_NUM_CONTACTED_PEERS-1], &theHost->hostSerial);
    return(1); /* New entry added */
  }

  return(0);
}

/* ******************************** */

int fetchPrefsValue(char *key, char *value, int valueLen) {
  datum key_data;
  datum data_data;

  if((value == NULL) || (myGlobals.capturePackets == FLAG_NTOPSTATE_TERM)) return(-1);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Entering fetchPrefValue()");
#endif
  value[0] = '\0';

  key_data.dptr  = key;
  key_data.dsize = strlen(key_data.dptr);

  if(myGlobals.prefsFile == NULL) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Leaving fetchPrefValue()");
#endif
    return(-1); /* ntop is quitting... */
  }

  data_data = gdbm_fetch(myGlobals.prefsFile, key_data);

  memset(value, 0, valueLen);

  if(data_data.dptr != NULL) {
    int len = min(valueLen,data_data.dsize);
    strncpy(value, data_data.dptr, len);
    value[len] = '\0';
    free(data_data.dptr);
    /* traceEvent(CONST_TRACE_INFO, "Read %s=%s.", key, value); */
    return(0);
  } else
    return(-1);
}

/* ******************************** */

void storePrefsValue(char *key, char *value) {
  datum key_data;
  datum data_data;

  if((value == NULL) || (myGlobals.capturePackets == FLAG_NTOPSTATE_TERM)) return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG:DEBUG:  Entering storePrefsValue()");
#endif

  memset(&key_data, 0, sizeof(key_data));
  key_data.dptr   = key;
  key_data.dsize  = strlen(key_data.dptr);

  memset(&data_data, 0, sizeof(data_data));
  data_data.dptr  = value;
  data_data.dsize = strlen(value);

  if(myGlobals.prefsFile == NULL) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Leaving storePrefsValue()");
#endif
    ; /* ntop is quitting... */
  }

  if(gdbm_store(myGlobals.prefsFile, key_data, data_data, GDBM_REPLACE) != 0)
    traceEvent(CONST_TRACE_ERROR, "While adding %s=%s.", key, value);
  else {
    /* traceEvent(CONST_TRACE_INFO, "Storing %s=%s.", key, value); */
  }
}

/* ******************************** */

#ifndef HAVE_LOCALTIME_R
#undef localtime

#ifdef CFG_MULTITHREADED
static PthreadMutex localtimeMutex;
static char localtimeMutexInitialized = 0;
#endif

struct tm *localtime_r(const time_t *t, struct tm *tp) {
  struct tm *theTime;

#if defined(CFG_MULTITHREADED)
  if(!localtimeMutexInitialized) {
    createMutex(&localtimeMutex);
    localtimeMutexInitialized = 1;
  }
  accessMutex(&localtimeMutex, "localtime_r");
#endif

  theTime = localtime(t);

  if(theTime != NULL)
    memcpy(tp, theTime, sizeof(struct tm));
  else
    memset(tp, 0, sizeof(struct tm)); /* What shall I do ? */

#if defined(CFG_MULTITHREADED)
  releaseMutex(&localtimeMutex);
#endif

  return(tp);
}
#endif

/* ************************************ */

int guessHops(HostTraffic *el) {
  int numHops = 0;

  if(subnetPseudoLocalHost(el) || (el->minTTL == 0)) numHops = 0;
  else if(el->minTTL <= 8)   numHops = el->minTTL-1;
  else if(el->minTTL <= 32)  numHops = 32 - el->minTTL;
  else if(el->minTTL <= 64)  numHops = 64 - el->minTTL;
  else if(el->minTTL <= 128) numHops = 128 - el->minTTL;
  else if(el->minTTL <= 256) numHops = 255 - el->minTTL;

  return(numHops);
}

/* ************************************ */

#ifndef WIN32
#undef sleep

unsigned int ntop_sleep(unsigned int secs) {
  unsigned int unsleptTime = secs, rest;

  while((rest = sleep(unsleptTime)) > 0)
    unsleptTime = rest;

  return(secs);
}
#endif

/* *************************************** */

void unescape(char *dest, int destLen, char *url) {
  int i, len, at;
  unsigned int val;
  char hex[3] = {0};

  len = strlen(url);
  at = 0;
  memset(dest, 0, destLen);
  for (i = 0; i < len && at < destLen; i++) {
    if (url[i] == '%' && i+2 < len) {
      val = 0;
      hex[0] = url[i+1];
      hex[1] = url[i+2];
      hex[2] = 0;
      sscanf(hex, "%02x", &val);
      i += 2;

      dest[at++] = val & 0xFF;
    } else if(url[i] == '+') {
      dest[at++] = ' ';
    } else
      dest[at++] = url[i];
  }
}

/* ******************************** */

void incrementTrafficCounter(TrafficCounter *ctr, Counter value) {
  ctr->value += value, ctr->modified = 1;
}

/* ******************************** */

void resetTrafficCounter(TrafficCounter *ctr) {
  ctr->value = 0, ctr->modified = 0;
}

/* ******************************** */

void allocateElementHash(int deviceId, u_short hashType) {
  int fcmemLen = sizeof(FcFabricElementHash*)*MAX_ELEMENT_HASH;

  switch(hashType) {
  case 2: /* VSAN */
    if(myGlobals.device[deviceId].vsanHash == NULL) {
      myGlobals.device[deviceId].vsanHash = (FcFabricElementHash**)malloc(fcmemLen);
      memset(myGlobals.device[deviceId].vsanHash, 0, fcmemLen);
    }
    break;
  }
}

/* *************************************************** */

u_int numActiveSenders(u_int deviceId) {
  u_int numSenders = 0;
  HostTraffic *el;

  for(el=getFirstHost(deviceId);
      el != NULL; el = getNextHost(deviceId, el)) {
    if(broadcastHost(el) || (el->pktSent.value == 0))
      continue;
    else if (isFcHost (el) && (el->hostFcAddress.domain == FC_ID_SYSTEM_DOMAIN))
      continue;
    else
      numSenders++;
  }

  return(numSenders);
}

/* *************************************************** */
u_int numActiveVsans(u_int deviceId)
{
  u_int numVsans = 0, i;
  FcFabricElementHash **theHash;

  if ((theHash = myGlobals.device[deviceId].vsanHash) == NULL) {
    return (numVsans);
  }

  for (i=0; i<MAX_ELEMENT_HASH; i++) {
    if((theHash[i] != NULL) && (theHash[i]->vsanId < MAX_HASHDUMP_ENTRY) &&
       (theHash[i]->vsanId < MAX_USER_VSAN)) {
      if (theHash[i]->totBytes.value)
	numVsans++;
    }
  }

  return (numVsans);
}



/* *************************************************** */

/* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */

u_int32_t xaton(char *s) {
  u_int32_t a, b, c, d;

  if(4!=sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d))
    return 0;
  return((a&0xFF)<<24)|((b&0xFF)<<16)|((c&0xFF)<<8)|(d&0xFF);
}

/* ******************************************************************* */

void addNodeInternal(u_int32_t ip, int prefix, char *country, int as) {
  IPNode *p1 = NULL, *p2 = NULL;
  int i, b;

  if(country)
    p1 = myGlobals.countryFlagHead;
  else
    p1 = myGlobals.asHead;

  for(i=0; i<prefix; i++) {
    b=(ip>>(31-i)) & 0x1;
    if(!p1->b[b]) {
      if(!(p2=malloc(sizeof(IPNode))))
        exit(1);
      memset(p2, 0, sizeof(IPNode));

      if(country != NULL)
	myGlobals.ipCountryMem += sizeof(IPNode);
      else
	myGlobals.asMem += sizeof(IPNode);
      p1->b[b]=p2;
    }
    else
      p2=p1->b[b];

    p1=p2;
  }

  if(country != NULL) {
    if(p2->node.cc[0] == 0)
      strncpy(p2->node.cc, country, sizeof(p2->node.cc));
  } else {
    if(p2->node.as == 0)
      p2->node.as = as;
  }
}

/* ******************************************************************* */

char *ip2CountryCode(HostAddr ip) {
  IPNode *p = myGlobals.countryFlagHead;
  int i, b;
  char *cc = "";
  u_int32_t addr;

  if (ip.hostFamily == AF_INET6)
    return NULL;
  addr  = ip.Ip4Address.s_addr;
  i = 0;
  while(p != NULL) {
    if(p->node.cc[0] != 0)
      cc = p->node.cc;
    b = (addr >>(31-i)) & 0x1;
    p = p->b[b];
    i++;
  }

  return(cc);
}

/* ******************************************************** */

#ifdef PARM_SHOW_NTOP_HEARTBEAT
void _HEARTBEAT(int beatLevel, char* file, int line, char * format, ...) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  va_list va_ap;

  myGlobals.heartbeatCounter++;

  if((format != NULL) && (PARM_SHOW_NTOP_HEARTBEAT >= beatLevel) ) {
    memset(buf, 0, LEN_GENERAL_WORK_BUFFER);
    va_start(va_ap, format);
    vsnprintf(buf, LEN_GENERAL_WORK_BUFFER-1, format, va_ap);
    va_end(va_ap);

    traceEvent(CONST_TRACE_INFO, "HEARTBEAT(%09u)[%s:%d]: %s", myGlobals.heartbeatCounter, file, line, buf);
  }
}
#endif

#ifdef MAKE_WITH_I18N
char *i18n_xvert_locale2common(const char *input) {
  /*
   *  locales are                  ll[_XX][.char][@modifier]
   *
   *  Fix it up to our common format(ll_XX), stripped of char and modifier.
   *
   *    NB: We picked this common format because it's usable in a directory
   *       (html_ll_XX) where the Accept-Language version(ll-XX) wouldn't always be.
   *
   */
  char *output, *work;

  output = strdup(input);

  work = strchr(output, '.');
  if(work != NULL) {
    work[0] = '\0';
  }
  work = strchr(output, '@');
  if(work != NULL) {
    work[0] = '\0';
  }
  return output;
}

char *i18n_xvert_acceptlanguage2common(const char *input) {
  /*
   *  Accept-Language: headers are ll[-XX] or ll-*
   *
   *  Fix it up to our common format(ll_XX), with the - swapped for a _
   *
   *    NB: We picked this common format because it's usable in a directory
   *       (html_ll_XX) where the Accept-Language version(ll-XX) wouldn't always be.
   *
   */
  char *output, *work;

  output = strdup(input);

  work = strchr(output, '*');
  if(work != NULL) {
    /* Backup to erase the - of the -* combo */
    work--;
    work[0] = '\0';
  }
  work = strchr(output, '-');
  if(work != NULL) {
    work[0] = '_';
  }
  work = strchr(output, '_');
  if(work != NULL) {
    while(work[0] != '\0') {
      work[0] = toupper(work[0]);
      work++;
    }
  }
  return output;
}
#endif /* MAKE_WITH_I18N */

/* *************************************** */

void setHostFingerprint(HostTraffic *srcHost) {
  FILE *fd = NULL;
  char *WIN, *MSS, *WSS, *ttl, *flags, *work;
  int S, N, D, T, done = 0;
  char fingerprint[32];
  char *strtokState;
  u_char compressedFormat;

#ifdef FINGERPRINT_DEBUG
  traceEvent(CONST_TRACE_INFO, "FINGERPRINT_DEBUG: setHostFingerprint(0x%08x)", srcHost);
#endif

  if(srcHost->fingerprint == NULL) {
    /* No fingerprint yet    */
#ifdef FINGERPRINT_DEBUG
    traceEvent(CONST_TRACE_INFO, "FINGERPRINT_DEBUG: setHostFingerprint() failed test 1");
#endif
    return;
}

#ifdef FINGERPRINT_DEBUG
  traceEvent(CONST_TRACE_INFO, "FINGERPRINT_DEBUG: setHostFingerprint() '%s'(%d)",
             srcHost->fingerprint, strlen(srcHost->fingerprint));
#endif

  if(srcHost->fingerprint[0] == ':') {
    /* OS already calculated */
#ifdef FINGERPRINT_DEBUG
    traceEvent(CONST_TRACE_INFO, "FINGERPRINT_DEBUG: setHostFingerprint() failed test 2");
#endif
    return;
}
  if(strlen(srcHost->fingerprint) < 28) {
#ifdef FINGERPRINT_DEBUG
    traceEvent(CONST_TRACE_INFO, "FINGERPRINT_DEBUG: setHostFingerprint() failed test 3");
#endif
    return;
}

  if(myGlobals.childntoppid != 0) {
#ifdef FINGERPRINT_DEBUG
    traceEvent(CONST_TRACE_INFO, "FINGERPRINT_DEBUG: setHostFingerprint() failed test 4");
#endif
    return; /* Reporting fork()ed child, don't update! */
  }

  accessAddrResMutex("setHostFingerprint");

  if(snprintf(fingerprint, sizeof(fingerprint)-1, "%s", srcHost->fingerprint) < 0)
    BufferTooShort();
  strtokState = NULL;
  WIN = strtok_r(fingerprint, ":", &strtokState); if(!WIN) goto unknownFingerprint;
  MSS = strtok_r(NULL, ":", &strtokState);     if(!MSS)    goto unknownFingerprint;
  ttl = strtok_r(NULL, ":", &strtokState);     if(!ttl)    goto unknownFingerprint;
  WSS = strtok_r(NULL, ":", &strtokState);     if(!WSS)    goto unknownFingerprint;
  work = strtok_r(NULL, ":", &strtokState);    if(!work)   goto unknownFingerprint;
  S = atoi(work);
  work = strtok_r(NULL, ":", &strtokState);    if(!work)   goto unknownFingerprint;
  N = atoi(work);
  work = strtok_r(NULL, ":", &strtokState);    if(!work)   goto unknownFingerprint;
  D = atoi(work);
  work = strtok_r(NULL, ":", &strtokState);    if(!work)   goto unknownFingerprint;
  T = atoi(work);
  flags = strtok_r(NULL, ":", &strtokState);   if(!flags)  goto unknownFingerprint;

#ifdef FINGERPRINT_DEBUG
  traceEvent(CONST_TRACE_INFO, "FINGERPRINT_DEBUG: WIN%s MSS%s ttl%s WSS%s S%d N%d D%d T%s FLAGS%s",
             WIN, MSS, ttl, WSS, S, N, D, T, flags);
#endif

  fd=checkForInputFile(NULL, NULL, CONST_OSFINGERPRINT_FILE, NULL, &compressedFormat);

  if(fd != NULL) {
      char line[384];
      char *b, *d, *ptr;
      int numLoaded=0;
      while(readInputFile(fd, NULL, FALSE, compressedFormat, 0, 
            line, sizeof(line), &numLoaded) == 0) {

	if((line[0] == '\0') || (line[0] == '#') || (strlen(line) < 30)) continue;
	line[strlen(line)-1] = '\0';

	strtokState = NULL;
	ptr = strtok_r(line, ":", &strtokState); if(ptr == NULL) continue;
	if(strcmp(ptr, WIN)) continue;
	b = strtok_r(NULL, ":", &strtokState); if(b == NULL) continue;
	if(strcmp(MSS, "_MSS") != 0) {
	  if(strcmp(b, "_MSS") != 0) {
	    if(strcmp(b, MSS)) continue;
	  }
	}

	ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
	if(strcmp(ptr, ttl)) continue;

	d = strtok_r(NULL, ":", &strtokState); if(d == NULL) continue;
	if(strcmp(WSS, "WS") != 0) {
	  if(strcmp(d, "WS") != 0) {
	    if(strcmp(d, WSS)) continue;
	  }
	}

	ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
	if(atoi(ptr) != S) continue;
	ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
	if(atoi(ptr) != N) continue;
	ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
	if(atoi(ptr) != D) continue;
	ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
	if(atoi(ptr) != T) continue;
	ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
	if(strcmp(ptr, flags)) continue;

	/* NOTE
	   strlen(srcHost->fingerprint) is 29 as the fingerprint length is so
	   Example: 0212:_MSS:80:WS:0:1:0:0:A:LT
	*/

	if(srcHost->fingerprint) free(srcHost->fingerprint);
	srcHost->fingerprint = strdup(&line[28]);

	done = 1;

        readInputFile(fd, NULL, TRUE, compressedFormat, 0, NULL, 0, &numLoaded);

        break;

      } /* while ! eof */
  }
#ifdef FINGERPRINT_DEBUG
    else 
      traceEvent(CONST_TRACE_INFO, "FINGERPRINT_DEBUG: Unable to open file");
#endif


  if(!done) {
    /* Unknown fingerprint */
  unknownFingerprint: /* Empty OS name */
    srcHost->fingerprint[0] = ':', srcHost->fingerprint[1] = '\0';
  }
#ifdef FINGERPRINT_DEBUG
    else 
      traceEvent(CONST_TRACE_INFO, "FINGERPRINT_DEBUG: match! %s", srcHost->fingerprint);
#endif

  releaseAddrResMutex();
}

/* ************************************************ */

#ifndef MEMORY_DEBUG
#undef gdbm_firstkey
#undef gdbm_nextkey
#undef gdbm_fetch
#undef gdbm_delete
#undef gdbm_store
#undef gdbm_close

int ntop_gdbm_delete(GDBM_FILE g, datum d) {
  int rc;

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "ntop_gdbm_delete");
#endif

  rc = gdbm_delete(g, d);

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);
#endif

  return(rc);
}

/* ****************************************** */

datum ntop_gdbm_firstkey(GDBM_FILE g) {
  datum theData;

  memset(&theData, 0, sizeof(theData));

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "ntop_gdbm_firstkey");
#endif

  theData = gdbm_firstkey(g);

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);
#endif

  return(theData);
}

/* ****************************************** */

void ntop_gdbm_close(GDBM_FILE g) {
#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "ntop_gdbm_close");
#endif

  gdbm_close(g);

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);
#endif
}

/* ******************************************* */

datum ntop_gdbm_nextkey(GDBM_FILE g, datum d) {
  datum theData;

  memset(&theData, 0, sizeof(theData));

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "ntop_gdbm_nextkey");
#endif

  theData = gdbm_nextkey(g, d);

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);
#endif

  return(theData);
}

/* ******************************************* */

datum ntop_gdbm_fetch(GDBM_FILE g, datum d) {
  datum theData;

  memset(&theData, 0, sizeof(theData));

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "ntop_gdbm_fetch");
#endif

  theData = gdbm_fetch(g, d);

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);
#endif

  return(theData);
}

/* ******************************************* */

int ntop_gdbm_store(GDBM_FILE g, datum d, datum v, int r) {
  int rc;

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "ntop_gdbm_store");
#endif

  rc = gdbm_store(g, d, v, r);

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);
#endif

  return(rc);
}
#endif /* MEMORY_DEBUG */

/* ******************************************* */

void handleWhiteBlackListAddresses(char* addresses,
                                   u_int32_t theNetworks[MAX_NUM_NETWORKS][3],
                                   u_short *numNets,
                                   char* outAddresses,
                                   int outAddressesLen) {

  *numNets = 0;
  if((addresses == NULL) ||(strlen(addresses) == 0) ) {
    /* No list - return with numNets = 0 */
    outAddresses[0]='\0';
    return;
  }

  handleAddressLists(addresses, theNetworks,
                     numNets, outAddresses,
                     outAddressesLen,
		     CONST_HANDLEADDRESSLISTS_NETFLOW);
}

/* ****************************** */

/* This function checks if a host is OK to save
 * i.e. specified in the white list and NOT specified in the blacklist
 *
 *   We return 1 or 2 - DO NOT SAVE
 *                        (1 means failed white list,
 *                          2 means matched black list)
 *             0      - SAVE
 *
 * We use the routines from util.c ...
 *  For them, 1=PseudoLocal, which means it's in the set
 *  So we have to flip the whitelist code
 */
unsigned short isOKtoSave(u_int32_t addr,
			  u_int32_t whiteNetworks[MAX_NUM_NETWORKS][3],
			  u_int32_t blackNetworks[MAX_NUM_NETWORKS][3],
			  u_short numWhiteNets, u_short numBlackNets) {
  int rc;
  struct in_addr workAddr;

  workAddr.s_addr = addr;

  if(numBlackNets > 0) {
    rc = __pseudoLocalAddress(&workAddr, blackNetworks, numBlackNets);
    if(rc == 1)
      return 2;
  }

  if(numWhiteNets > 0) {
    rc = __pseudoLocalAddress(&workAddr, whiteNetworks, numWhiteNets);
    return(1 - rc);
  }

  return(0 /* SAVE */);
}

#ifndef HAVE_PCAP_OPEN_DEAD

struct pcap_sf {
  FILE *rfile;
  int swapped;
  int hdrsize;
  int version_major;
  int version_minor;
  u_char *base;
};

struct pcap_md {
  struct pcap_stat stat;
  /*XXX*/
  int use_bpf;		/* using kernel filter */
  u_long	TotPkts;	/* can't oflow for 79 hrs on ether */
  u_long	TotAccepted;	/* count accepted by filter */
  u_long	TotDrops;	/* count of dropped packets */
  long	TotMissed;	/* missed by i/f during this run */
  long	OrigMissed;	/* missed by i/f before this run */
#ifdef linux
  int	sock_packet;	/* using Linux 2.0 compatible interface */
  int	timeout;	/* timeout specified to pcap_open_live */
  int	clear_promisc;	/* must clear promiscuous mode when we close */
  int	cooked;		/* using SOCK_DGRAM rather than SOCK_RAW */
  int	lo_ifindex;	/* interface index of the loopback device */
  char 	*device;	/* device name */
  struct pcap *next;	/* list of open promiscuous sock_packet pcaps */
#endif
};

struct pcap {
  int fd;
  int snapshot;
  int linktype;
  int tzoff;		/* timezone offset */
  int offset;		/* offset for proper alignment */

  struct pcap_sf sf;
  struct pcap_md md;

  /*
   * Read buffer.
   */
  int bufsize;
  u_char *buffer;
  u_char *bp;
  int cc;

  /*
   * Place holder for pcap_next().
   */
  u_char *pkt;


  /*
   * Placeholder for filter code if bpf not in kernel.
   */
  struct bpf_program fcode;

  char errbuf[PCAP_ERRBUF_SIZE];
};

pcap_t *pcap_open_dead(int linktype, int snaplen)
{
  pcap_t *p;

  p = malloc(sizeof(*p));
  if (p == NULL)
    return NULL;
  memset (p, 0, sizeof(*p));
  p->fd = -1;
  p->snapshot = snaplen;
  p->linktype = linktype;
  return p;
}
#endif

/* ******************************** */

int setSpecifiedUser(void) {
#ifndef WIN32
  /*
   * set user to be as inoffensive as possible
   */
  /* user id specified on commandline */
  if((setgid(myGlobals.groupId) != 0) || (setuid(myGlobals.userId) != 0)) {
    traceEvent(CONST_TRACE_FATALERROR, "Unable to change user ID");
    exit(-1);
  }
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Now running as requested user '%s' (%d:%d)",
             myGlobals.effectiveUserName, myGlobals.userId, myGlobals.groupId);

  if((myGlobals.userId != 0) || (myGlobals.groupId != 0)) {
#if defined(DARWIN) || defined(FREEBSD)
    unsigned long p;

    /*
      This is dead code but it's necessary under OSX. In fact the linker
      notices that the RRD stuff is not used in the main code so it is
      ignored. At runtime when the RRD plugin comes up, the dynamic linker
      failes because the rrd_* are not found.
    */

    p =  (unsigned long)rrd_fetch;
    p += (unsigned long)rrd_graph;
    p += (unsigned long)rrd_create;
    p += (unsigned long)rrd_last;
    p += (unsigned long)rrd_update;
    p += (unsigned long)rrd_test_error;
    p += (unsigned long)rrd_get_error;
    p += (unsigned long)rrd_clear_error;
    return(p);
#else
    return(1);
#endif
  } else
    return(0);
#else
  return(0);
#endif
}

/* ******************************************************************* */

u_short ip2AS(HostAddr ip) {
  IPNode *p;
  int i, b;
  u_short as=0;
  u_int32_t addr;

  if (ip.hostFamily == AF_INET6)
    return 0;

  addr = ip.Ip4Address.s_addr;

  p = myGlobals.asHead;

  i=0;
  while(p!=NULL) {
    if(p->node.as !=0 )
      as = p->node.as;
    b=(addr>>(31-i)) & 0x1;
    p=p->b[b];
    i++;
  }


#ifdef DEBUG
  {
    char buf[64];

    traceEvent(CONST_TRACE_INFO, "%s: %d AS", _intoa(&addr, buf, sizeof(buf)), as);
  }
#endif

  return as;
}

/* ************************************ */

u_int16_t getHostAS(HostTraffic *el) {
  return(el->hostAS || (el->hostAS = ip2AS(el->hostIpAddress)));
}

/* ************************************ */

int emptySerial(HostSerial *a) {
  return(a->serialType == 0);
}

/* ********************************** */

int cmpSerial(HostSerial *a, HostSerial *b) {
  return(!memcmp(a, b, sizeof(HostSerial)));
}

/* ********************************** */

int copySerial(HostSerial *a, HostSerial *b) {
  return(!memcpy(a, b, sizeof(HostSerial)));
}

/* ********************************** */

void setEmptySerial(HostSerial *a) {
  memset(a, 0, sizeof(HostSerial));
}

/* ********************************* */

void addPortToList(HostTraffic *host, int *thePorts /* 0...MAX_NUM_RECENT_PORTS */, u_short port) {
  u_short i, found;

  if(port == 0)
    FD_SET(FLAG_HOST_IP_ZERO_PORT_TRAFFIC, &host->flags);

  for(i = 0, found = 0; i<MAX_NUM_RECENT_PORTS; i++)
    if(thePorts[i] == port) {
      found = 1;
      break;
    }

  if(!found) {
    for(i = 0; i<(MAX_NUM_RECENT_PORTS-1); i++)
      thePorts[i] =  thePorts[i+1];

    thePorts[MAX_NUM_RECENT_PORTS-1] = port;
  }
}

/* ************************************ */

#ifndef WIN32

void saveNtopPid(void) {
  char pidFileName[NAME_MAX];
  FILE *fd;

  myGlobals.basentoppid = getpid();
  if(snprintf(pidFileName, sizeof(pidFileName), "%s/%s",
          getuid() ?
	  /* We're not root */ myGlobals.dbPath :
	  /* We are root */ DEFAULT_NTOP_PID_DIRECTORY,
          DEFAULT_NTOP_PIDFILE) < 0)
    BufferTooShort();
  fd = fopen(pidFileName, "wb");

  if(fd == NULL) {
    traceEvent(CONST_TRACE_WARNING, "INIT: Unable to create pid file (%s)", pidFileName);
  } else {
    fprintf(fd, "%d\n", myGlobals.basentoppid);
    fclose(fd);
    traceEvent(CONST_TRACE_INFO, "INIT: Created pid file (%s)", pidFileName);
  }
}

/* ********************************** */

void removeNtopPid(void) {
  char pidFileName[NAME_MAX];
  int rc;

  if(snprintf(pidFileName, sizeof(pidFileName), "%s/%s",
          getuid() ?
	  /* We're not root */ myGlobals.dbPath :
	  /* We are root */ DEFAULT_NTOP_PID_DIRECTORY,
          DEFAULT_NTOP_PIDFILE) < 0)
    BufferTooShort();
  rc = unlink(pidFileName);
  if (rc == 0) {
    traceEvent(CONST_TRACE_INFO, "TERM: Removed pid file (%s)", pidFileName);
  } else {
    traceEvent(CONST_TRACE_WARNING, "TERM: Unable to remove pid file (%s)", pidFileName);
  }
}

#endif

/* ************************************ */

/* The following two routines have been extracted from Ethereal */
static char *
bytestring_to_str(const u_int8_t *ad, u_int32_t len, char punct) {
  static char  str[3][32];
  static char *cur;
  char        *p;
  int          i;
  u_int32_t   octet;
  /* At least one version of Apple's C compiler/linker is buggy, causing
     a complaint from the linker about the "literal C string section"
     not ending with '\0' if we initialize a 16-element "char" array with
     a 16-character string, the fact that initializing such an array with
     such a string is perfectly legitimate ANSI C nonwithstanding, the 17th
     '\0' byte in the string nonwithstanding. */
  static const char hex_digits[16] =
    { '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

  if (len < 0) {
    return "";
  }

  len--;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {
    cur = &str[2][0];
  } else {
    cur = &str[0][0];
  }
  p = &cur[18];
  *--p = '\0';
  i = len;
  for (;;) {
    octet = ad[i];
    *--p = hex_digits[octet&0xF];
    octet >>= 4;
    *--p = hex_digits[octet&0xF];
    if (i == 0)
      break;
    if (punct)
      *--p = punct;
    i--;
  }
  return p;
}

char *
fc_to_str(const u_int8_t *ad)
{
  return bytestring_to_str (ad, 3, '.');
}

char *
fcwwn_to_str (const u_int8_t *ad)
{
  u_int8_t zero_wwn[LEN_WWN_ADDRESS] = {0,0,0,0,0,0,0,0};

  if (!memcmp (ad, zero_wwn, LEN_WWN_ADDRESS)) {
    return ("N/A");
  }

  return bytestring_to_str (ad, 8, ':');
}

/* ************************************ */

#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)

#undef sched_yield

/* BStrauss - August 2003 - Check the flag and skip the call... */
extern int ntop_sched_yield(char *file, int line) {

#ifdef DEBUG
  static int firstTime=0;

  if(firstTime) {
    traceEvent(CONST_TRACE_INFO, "DEBUG: firstTime in ntop_sched_yield()");
    firstTime = 1;
  }
#endif

  if(!myGlobals.disableSchedYield) {
    sched_yield();
#ifdef DEBUG
  } else {
    traceEvent(CONST_TRACE_INFO, "DEBUG: skipping sched_yield()");
#endif
  }
}

#endif

#ifdef EMBEDDED
extern char *crypt (__const char *__key, __const char *__salt) {
  return(__key);
}
#endif

/* ********************************* */

#ifdef WIN32

static const char *
inet_ntop4(src, dst, size)
     const u_char *src;
     char *dst;
     size_t size;
{
  static const char fmt[] = "%u.%u.%u.%u";
  char tmp[sizeof "255.255.255.255"];
  int nprinted;

  nprinted = snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
  if (nprinted < 0)
    return (NULL);  /* we assume "errno" was set by "snprintf()" */
  if ((size_t)nprinted > size) {
    errno = ENOSPC;
    return (NULL);
  }
  strcpy(dst, tmp);
  return (dst);
}

#define NS_IN6ADDRSZ 16

static const char *inet_ntop6(const u_char *src, char *dst, size_t size) {
  /*
   * Note that int32_t and int16_t need only be "at least" large enough
   * to contain a value of the specified size.  On some systems, like
   * Crays, there is no such thing as an integer variable with 16 bits.
   * Keep this in mind if you think this function should have been coded
   * to use pointer overlays.  All the world's not a VAX.
   */
  char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
  struct { int base, len; } best, cur;
  u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
  int i;

  /*
   * Preprocess:
   *      Copy the input (bytewise) array into a wordwise array.
   *      Find the longest run of 0x00's in src[] for :: shorthanding.
   */
  memset(words, '\0', sizeof words);
  for (i = 0; i < NS_IN6ADDRSZ; i++)
    words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
  best.base = -1;
  cur.base = -1;
  for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
    if (words[i] == 0) {
      if (cur.base == -1)
	cur.base = i, cur.len = 1;
      else
	cur.len++;
    } else {
      if (cur.base != -1) {
	if (best.base == -1 || cur.len > best.len)
	  best = cur;
	cur.base = -1;
      }
    }
  }
  if (cur.base != -1) {

    if (best.base == -1 || cur.len > best.len)
      best = cur;
  }
  if (best.base != -1 && best.len < 2)
    best.base = -1;

  /*
   * Format the result.
   */
  tp = tmp;
  for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
    /* Are we inside the best run of 0x00's? */
    if (best.base != -1 && i >= best.base &&
	i < (best.base + best.len)) {
      if (i == best.base)
	*tp++ = ':';
      continue;
    }
    /* Are we following an initial run of 0x00s or any real hex? */
    if (i != 0)
      *tp++ = ':';
    /* Is this address an encapsulated IPv4? */
    if (i == 6 && best.base == 0 &&
	(best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
      if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
	return (NULL);
      tp += strlen(tp);
      break;
    }
    tp += sprintf(tp, "%x", words[i]);
  }
  /* Was it a trailing run of 0x00's? */
  if (best.base != -1 && (best.base + best.len) ==
      (NS_IN6ADDRSZ / NS_INT16SZ))
    *tp++ = ':';
  *tp++ = '\0';

  /*
   * Check for overflow, copy, and we're done.
   */
  if ((size_t)(tp - tmp) > size) {
    errno = ENOSPC;
    return (NULL);
  }
  strcpy(dst, tmp);
  return (dst);
}

const char *inet_ntop(int af, const void *src, char *dst, size_t size) {
  switch (af) {
  case AF_INET:
    return (inet_ntop4(src, dst, size));
  case AF_INET6:
    return (inet_ntop6(src, dst, size));
  default:
    errno = -1;
    return (NULL);
  }
  /* NOTREACHED */
}

#endif

/* *************************************************** */

u_int numActiveNxPorts (u_int deviceId) {
  u_int numSenders = 0;
  HostTraffic *el;

  for(el=getFirstHost(deviceId);
      el != NULL; el = getNextHost(deviceId, el)) {
    if (isFcHost (el) && (el->hostFcAddress.domain == FC_ID_SYSTEM_DOMAIN))
      continue;
    else
      numSenders++;
  }

  return(numSenders);
}

/* *************************************** */

#if 0 /* Not used */
HostTraffic* findHostByFcAddr(FcAddress *fcAddr, u_short vsanId, u_int actualDeviceId) {
  HostTraffic *el;
  u_int idx = hashFcHost(fcAddr, vsanId, &el, actualDeviceId);

  if(el != NULL)
    return(el); /* Found */
  else if(idx == FLAG_NO_PEER)
    return(NULL);
  else
    el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];

  for(; el != NULL; el = el->next) {
    if((el->hostFcAddress.domain != 0) && (!memcmp(&el->hostFcAddress, &fcAddr, LEN_FC_ADDRESS)))
      return(el);
  }

  return(NULL);
}
#endif

/* *************************************** */

FcNameServerCacheEntry *findFcHostNSCacheEntry(FcAddress *fcAddr, u_short vsanId) {
  FcNameServerCacheEntry *entry = NULL;
  HostTraffic *el = NULL;
  u_int hashIdx = hashFcHost(fcAddr, vsanId, &el, -1);

  entry = myGlobals.fcnsCacheHash[hashIdx];

  while (entry != NULL) {
    if ((entry->vsanId == vsanId) &&
	(memcmp ((u_int8_t *)fcAddr, (u_int8_t *)&entry->fcAddress,
		 LEN_FC_ADDRESS) == 0))
      return (entry);

    entry = entry->next;
  }

  return (NULL);
}

/* ************************************ */


/* HTTP version file retrieval loosely based on wget from FSF
 *
 * Retrieve a document through HTTP protocol.
 *
 *    <ntopversion>
 *      <site>www.ntop.org</site>
 *      <stable>2.2c</stable>
 *      <development>2.2.97</development>
 *      <unsupported>2.2</unsupported>
 *    </ntopversion>
 *
 *  However, this is very unsopisticated.  If there's any problem, something
 *  we don't expect, etc., just report it and move on...
 *
 */

/* ********************************** */

/* First a bunch of helper functions to keep the main checkVersion() routine
 * even slightly understandable...
 */

unsigned int convertNtopVersionToNumber(char *versionString) {
  /* This one is purely an arbitrary conversion.
   *
   * But it knows about the version # schemes we've used in the past
   *  e.g. 2.2c, 2.2.50, 2.2.97, 3.0pre1, 3.0rc1 etc. so that the number truly is relative
   * for numeric testing.
   *
   *  The goal is to get the following converted to ascending numeric order:
   *
   *   1.3 2.1 2.1.2 2.1.3 2.1.50 2.1.90 2.2 2.2a 2.2b 2.2c 2.2.50 2.2.97 3.0pre1 3.0rc1 3.0
   *
   * e.g.:
   *
   *   1.3     103000000
   *   2.1     201000000
   *   2.1.1   201000001
   *   2.1.2   201000002
   *   2.1.3   201000003
   *   2.1.50  201050000
   *   2.1.90  201090000
   *   2.2     202000000
   *   2.2a    202000100
   *   2.2b    202000200
   *   2.2c    202000300
   *   2.2.50  202050000
   *   2.2.90  202090000
   *   3.0pre1 299998001
   *   3.0rc1  299999001
   *   3.0rc2  299999002
   *   3.0     300000000
   *
   * n.m   -> nmm000000
   * n.m.x -> nmmyyy0xx  (if x>=50 yyy=x else xx=x)
   * n.ml  -> nmm000l00 (where a=1, b=2, etc.)
   */
  unsigned int f, n=0, m=0, x=0, y=0, c=0, prerc=0;
  unsigned char l[4];

  if (versionString == NULL) {
    return 999999999;
  }

  memset(&l, 0, sizeof(l));

  f = sscanf(versionString, "%u.%upre%u", &n, &m, &x);
  if(f>=3) {
    prerc=2;
  } else {
    f = sscanf(versionString, "%u.%urc%u", &n, &m, &x);
    if(f>=3) {
      prerc=1;
    } else {
      f = sscanf(versionString, "%u.%u%1[a-z].%u", &n, &m, &l, &x);
      if(f>=3) {
	if(l[0]>0)
	  l[0] = tolower(l[0]) - 'a' + 1;
      } else {
        memset(&l, 0, sizeof(l));
	f = sscanf(versionString, "%u.%u.%u", &n, &m, &x);
	if (f<=0) {
	  return 999999999;
	}
      }
    }
  }
  if (x>=50) {
    y=x;
    x=0;
  }
#ifdef CHKVER_DEBUG
  traceEvent(CONST_TRACE_INFO, "CHKVER_DEBUG: %s is n%u m%u y%u l%u x%u prerc%u f=%u",
	     versionString, n, m, y, l[0], x, prerc, f);
#endif
  return n*100000000 + m*1000000 + y*1000 + l[0]*100 + x - 1000*prerc;
}

/* ********************************** */

void displayPrivacyNotice(void) {
  char value[8];

  /* globals.displayPrivacyNotice:
   *
   * 0 (or not present) means display one-time
   * 1                  means already displayed
   * 2                  means display every time
   */
  if(fetchPrefsValue("globals.displayPrivacyNotice", value, sizeof(value)) == -1) {
    value[0]='0';
    value[1]='\0';
  }
  switch (value[0]) {
  case '0':
    storePrefsValue("globals.displayPrivacyNotice", "1");
    /* NO BREAK HERE... fall into next case so we do the one-time display */
  case '2':
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: **********************PRIVACY**NOTICE**********************");
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: * ntop instances may record individually identifiable     *");
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: * information on a remote system as part of the version   *");
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: * check.                                                  *");
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: *                                                         *");
    if(myGlobals.skipVersionCheck == TRUE) {
      traceEvent(CONST_TRACE_ALWAYSDISPLAY,
		 "CHKVER: * You have requested - via the --skip-version-check       *");
      traceEvent(CONST_TRACE_ALWAYSDISPLAY,
		 "CHKVER: * option that this check be skipped and so no             *");
      traceEvent(CONST_TRACE_ALWAYSDISPLAY,
		 "CHKVER: * individually identifiable information will be recorded. *");
    } else {
      traceEvent(CONST_TRACE_ALWAYSDISPLAY,
		 "CHKVER: * You may request - via the --skip-version-check option   *");
      traceEvent(CONST_TRACE_ALWAYSDISPLAY,
		 "CHKVER: * that this check be skipped and that no individually     *");
      traceEvent(CONST_TRACE_ALWAYSDISPLAY,
		 "CHKVER: * identifiable information be recorded.                   *");
    }
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: *                                                         *");
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: * In general, we ask you to permit this check because it  *");
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: * benefits both the users and developers of ntop.         *");
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: *                                                         *");
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: * Review the man ntop page for more information.          *");
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: *                                                         *");
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: **********************PRIVACY**NOTICE**********************");
  }

#if (0)
    // Enable this only if you suspect the conversion is hosed, to collect
    // information for the ntop-dev mailing list.
    // Normally you would enable this, run ntop, collect the values and
    // then shut ntop down.
#define cNV2N(a, b) \
{ \
  unsigned int vv; \
  vv = convertNtopVersionToNumber(a); \
  if (vv != b) \
    traceEvent(CONST_TRACE_INFO, "CHKVER_TEST: cNV2N %-10s -> %10u expected %10u", a, vv, b); \
  else \
    traceEvent(CONST_TRACE_INFO, "CHKVER_TEST: cNV2N %-10s -> %10u OK", a, vv); \
}

    cNV2N("1.3",     103000000);
    cNV2N("2.1",     201000000);
    cNV2N("2.1.1",   201000001);
    cNV2N("2.1.2",   201000002);
    cNV2N("2.1.3",   201000003);
    cNV2N("2.1.50",  201050000);
    cNV2N("2.1.90",  201090000);
    cNV2N("2.2",     202000000);
    cNV2N("2.2a",    202000100);
    cNV2N("2.2b",    202000200);
    cNV2N("2.2c",    202000300);
    cNV2N("2.2c.1",  202000301);
    cNV2N("2.2.50",  202050000);
    cNV2N("2.2.90",  202090000);
    cNV2N("3.0pre1", 299998001);
    cNV2N("3.0pre10",299998010);
    cNV2N("3.0rc1",  299999001);
    cNV2N("3.0rc2",  299999002);
    cNV2N("3.0rc14", 299999014);
    cNV2N("3.0",     300000000);
#endif    
}

/* ********************************** */

/* Externally exposed function to turn the code into words... */
char *reportNtopVersionCheck(void) {
  switch(myGlobals.checkVersionStatus) {
  case FLAG_CHECKVERSION_NOTCHECKED:
    return "was not checked";
  case FLAG_CHECKVERSION_OBSOLETE:
    return "an OBSOLETE and UNSUPPORTED version - please upgrade";
  case FLAG_CHECKVERSION_UNSUPPORTED:
    return "an UNSUPPORTED version - please upgrade";
  case FLAG_CHECKVERSION_NOTCURRENT:
    return "a minimally supported but OLDER version - please upgrade";
  case FLAG_CHECKVERSION_CURRENT:
    return "the CURRENT stable version";
  case FLAG_CHECKVERSION_OLDDEVELOPMENT:
    return "an unsupported old DEVELOPMENT version - upgrade";
  case FLAG_CHECKVERSION_DEVELOPMENT:
    return "the current DEVELOPMENT version - Expect the unexpected!";
  case FLAG_CHECKVERSION_NEWDEVELOPMENT:
    return "a new DEVELOPMENT version - Be careful!";
  default:
    return "is UNKNOWN...";
  }
}

/* ********************************** */

/* pseudo-function to use stringification to find the xml tag */
#define xmlextract(a) { \
       a = strstr(next, "<" #a ">"); \
       if (a != NULL) { \
           a += sizeof( #a ) + 1; \
           if (strchr(a, '<') != NULL) \
               strchr(a, '<')[0] = '\0'; \
       } \
}

/* ********************************** */

void tokenizeCleanupAndAppend(char *userAgent, int userAgentLen,
			      char *title, char *input) {
  char *work, *token;
  int i, j, tCount=0;

  work=strdup(input);

  strncat(userAgent, " ", (userAgentLen - strlen(userAgent) - 1));
  strncat(userAgent, title, (userAgentLen - strlen(userAgent) - 1));
  strncat(userAgent, "(", (userAgentLen - strlen(userAgent) - 1));

  token = strtok(work, " \t\n");
  while (token != NULL) {

    /* No -? then it's a data value - skip */
    if(token[0] != '-') {
      token = strtok(NULL, " \t\n");
      continue;
    }

    /* Skip -s, end at = */
    for(j=i=0; i<strlen(token); i++) {
      if(token[i] == '=') {
	token[j++] = token[i]; /* we preserve the = so we know it was used,
				  but drop the data value */
	break;
      } else if(token[i] != '-')
	token[j++] = token[i];
    }
    token[j]='\0';

    if(strncmp(token, "without", strlen("without")) == 0)
      token += strlen("without");
    if(strncmp(token, "with", strlen("with")) == 0)
      token += strlen("with");
    if(strncmp(token, "disable", strlen("disable")) == 0)
      token += strlen("disable");
    if(strncmp(token, "enable", strlen("enable")) == 0)
      token += strlen("enable");

    if((strncmp(token, "prefix", strlen("prefix")) != 0) &&
       (strncmp(token, "sysconfdir", strlen("sysconfdir")) != 0) &&
       (strncmp(token, "norecursion", strlen("norecursion")) != 0)) {
      if(++tCount > 1)
	strncat(userAgent, "; ", (userAgentLen - strlen(userAgent) - 1));
      strncat(userAgent, token, (userAgentLen - strlen(userAgent) - 1));
    }

    token = strtok(NULL, " \t\n");
  }
  strncat(userAgent, ")", (userAgentLen - strlen(userAgent) - 1));

  free(work);
}

/* ********************************** */

void extractAndAppend(char *userAgent, int userAgentLen,
		      char *title, char *input) {
  char *work;
  int i, j, dFlag=FALSE;

  work=strdup(input);

  for(j=i=0; i<strlen(work); i++) {
    if (dFlag == TRUE) {
      if((work[i] == ' ') ||
	 (work[i] == ',') ) {
	break;
      }
      work[j++]=work[i];
    } else if (isdigit(work[i])) {
      dFlag = TRUE;
      work[j++]=work[i];
    }
  }
  work[j]='\0';

  strncat(userAgent, " ", (userAgentLen - strlen(userAgent) - 1));
  strncat(userAgent, title, (userAgentLen - strlen(userAgent) - 1));
  strncat(userAgent, "/", (userAgentLen - strlen(userAgent) - 1));
  strncat(userAgent, work, (userAgentLen - strlen(userAgent) - 1));

  free(work);
  return;
}

/* ********************************** */

/* ===== ===== retrieve url ===== ===== */

int retrieveVersionFile(char *versSite, char *versionFile, char *buf, int bufLen) {
  struct hostent *hptr;
  char *userAgent, *space;
  int rc, sock;
  struct sockaddr_in addr;
#ifdef HAVE_SYS_UTSNAME_H
  struct utsname unameData;
#endif

  /* Establish the connection */
  hptr = gethostbyname(versSite);
  if (!hptr) {
    traceEvent(CONST_TRACE_ERROR, "CHKVER: Unable to resolve site %s", versSite);
    return 1;
  }
#ifdef CHKVER_DEBUG
  traceEvent(CONST_TRACE_INFO, "CHKVER_DEBUG: Site resolved to %u.%u.%u.%u",
	     (hptr->h_addr)[0] & 0xff,
	     (hptr->h_addr)[1] & 0xff,
	     (hptr->h_addr)[2] & 0xff,
	     (hptr->h_addr)[3] & 0xff);
#endif

  /* Create socket for http GET */
  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) {
    traceEvent(CONST_TRACE_ERROR,
	       "CHKVER: Unable to create socket: %s(%d)", strerror(errno), errno);
    return 1;
  }
#ifdef CHKVER_DEBUG
  traceEvent(CONST_TRACE_INFO, "CHKVER_DEBUG: Socket is %d", sock);
#endif

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(80);
  memcpy((char *) &addr.sin_addr.s_addr, hptr->h_addr_list[0], hptr->h_length);

  /* Connect the socket to the remote host.  */
  rc = connect(sock, (struct sockaddr*)&addr, (socklen_t) sizeof(addr));
  if (rc != 0) {
    traceEvent(CONST_TRACE_ERROR,
	       "CHKVER: Unable to connect socket: %s(%d)", strerror(errno), errno);
    close(sock);
    return 1;
  }
#ifdef CHKVER_DEBUG
  traceEvent(CONST_TRACE_INFO, "CHKVER_DEBUG: Connected");
#endif

  userAgent=malloc(LEN_GENERAL_WORK_BUFFER);
  memset(userAgent, 0, LEN_GENERAL_WORK_BUFFER);
  if(snprintf(userAgent, LEN_GENERAL_WORK_BUFFER, "ntop/%s", version) < 0)
    BufferTooShort();

  /* Convert any spaces in the version to +s
   *   e.g. 2.2.98 0300 -> 2.2.98+0300
   */
  while ((space=strchr(userAgent, ' ')) != NULL) {
    space[0]='+';
  }

  strncat(userAgent, " host/", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
  strncat(userAgent, osName, (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));

  if((distro != NULL) && (strcmp(distro, "") != 0)) {
    strncat(userAgent, " distro/", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
    strncat(userAgent, distro, (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
  }

  if((release != NULL) && (strcmp(release, "") != 0) && (strcmp(release, "unknown") != 0)) {
    strncat(userAgent, " release/", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
    strncat(userAgent, release, (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
  }

#ifdef HAVE_SYS_UTSNAME_H
  if (uname(&unameData) == 0) {
    strncat(userAgent, " kernrlse/", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
    strncat(userAgent, unameData.release, (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
  }
#endif

#ifdef __GNUC__
  /* Macros to kludge around stringing of parameters */
#define xstr(s) str(s)
#define str(s) #s

#if defined(__GNUC_PATCHLEVEL__)
#define GCC_VERSION __GNUC__.__GNUC_MINOR__.__GNUC_PATCHLEVEL__
#else
#define GCC_VERSION __GNUC__.__GNUC_MINOR__
#endif
  strncat(userAgent, " GCC/" xstr(GCC_VERSION) , (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));

#undef str
#undef xstr
#endif

  tokenizeCleanupAndAppend(userAgent, LEN_GENERAL_WORK_BUFFER, "config", configure_parameters);
  tokenizeCleanupAndAppend(userAgent, LEN_GENERAL_WORK_BUFFER, "run", myGlobals.startedAs);

#ifdef HAVE_PCAP_LIB_VERSION
  extractAndAppend(userAgent, LEN_GENERAL_WORK_BUFFER, "libpcap", (char*)pcap_lib_version());
#endif

#if defined(WIN32) && defined(__GNUC__)
  /* on mingw, gdbm_version not exported by library */
#else
  extractAndAppend(userAgent, LEN_GENERAL_WORK_BUFFER, "gdbm", gdbm_version);
#endif

  /*
   * If we've guessed at the gd version, report it
   */
  if(myGlobals.gdVersionGuessValue != NULL)
    extractAndAppend(userAgent, LEN_GENERAL_WORK_BUFFER, "gd", myGlobals.gdVersionGuessValue);

#ifdef HAVE_OPENSSL
  extractAndAppend(userAgent, LEN_GENERAL_WORK_BUFFER, "openssl", (char*)SSLeay_version(0));
#endif

  extractAndAppend(userAgent, LEN_GENERAL_WORK_BUFFER, "zlib", (char*)zlibVersion());

  /* Special case for webPort+sslPort... */
  strncat(userAgent, " access/", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
#ifdef HAVE_OPENSSL
  if (myGlobals.sslPort != 0) {
    if(myGlobals.webPort != 0)
      strncat(userAgent, "both", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
    else
      strncat(userAgent, "https", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
  } else
#endif
    if(myGlobals.webPort != 0)
      strncat(userAgent, "http", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
    else
      strncat(userAgent, "none", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));

  /* Special case for interfaces */
  strncat(userAgent, " interfaces(", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
  if(myGlobals.devices != NULL) {
    strncat(userAgent, myGlobals.devices, (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
  } else {
    strncat(userAgent, "null", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
  }
  strncat(userAgent, ")", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));

  if(snprintf(buf, bufLen, "GET /%s HTTP/1.0\r\n"
	      "Host: %s\r\n"
	      "User-Agent: %s\r\n"
	      "Accept: %s\r\n"
	      "\r\n",
	      versionFile,
	      versSite,
	      userAgent,
	      CONST_HTTP_ACCEPT_ALL) < 0)
    BufferTooShort();

  free(userAgent);

  /* Send the request to server.  */
  traceEvent(CONST_TRACE_NOISY, "CHKVER: Sending request: %s", buf);
  rc = send(sock, buf, strlen(buf), 0);
  if (rc < 0) {
    traceEvent(CONST_TRACE_ERROR,
	       "CHKVER: Unable to send http request: %s(%d)", strerror(errno), errno);
    close(sock);
    return 1;
  }

  /* Pickup the response -
   * remember, buf/bufLen better be big enough to handle the whole response
   */
  memset(buf, 0, bufLen);
  rc = recv(sock, buf, bufLen, 
#ifdef WIN32
	  0
#else
	  MSG_WAITALL
#endif
	  );
  if (rc < 0) {
    traceEvent(CONST_TRACE_ERROR,
	       "CHKVER: Unable to receive http response: %s(%d)", strerror(errno), errno);
    close(sock);
    return 1;
  }
  if(rc >= bufLen) {
    traceEvent(CONST_TRACE_ERROR,
	       "CHKVER: Unable to receive entire http response (%d/%d)- skipping",
	       rc,
	       bufLen);
    close(sock);
    return 1;
  }

#ifdef CHKVER_DEBUG
  traceEvent(CONST_TRACE_INFO, "CHKVER_DEBUG: Received %d bytes '%s'", rc, buf);
#endif

  return 0;
}

/* ********************************** */

int processVersionFile(char *buf, int bufLen) {
  /* Process the returned data
   *   We march through the big buffer,
   *   with hdr pointing at a C string for each header
   *   and next pointing at the next character we pick up with.
   */

  int i, j, k, rc, hcount=0;
  unsigned int sNumber, dNumber, uNumber, oNumber, vNumber;
  char *hdr, *next, *site, *date, *development, *stable, *unsupported, *obsolete;

  next=hdr=buf;
  while (1) {

    ++hcount;
    hdr=next;

    for (i=0; 1; i++) {
      if (--bufLen <= 0) {
	traceEvent(CONST_TRACE_ERROR, "CHKVER: Past end processing http response");
	return(0);
      }
      /* Cleanup whitespace */
      if (hdr[i] == '\r' ||
	  hdr[i] == '\f' ||
	  hdr[i] == '\v') {
	hdr[i] = ' ';
	continue;
      }
      if(hdr[i] == '\n') {
	hdr[i]=' ';

	/* Check for header continuation (not allowed on the 1st header)
	 * by looking at the character ahead.
	 */
	if((hcount > 1) &&
	   (hdr[i+1] == '\t' || hdr[i+1] == ' ')) {
	  continue;
	}

	/* Otherwise, set next... */
	next=&(hdr[i+1]);

	/* Clear trailing whitespace... */
	hdr[i--]='\0';
	while((i>=0) && (hdr[i]==' ')) hdr[i--]='\0';

	break;
      }
    }

#ifdef CHKVER_DEBUG
    traceEvent(CONST_TRACE_INFO, "CHKVER_DEBUG: %3d. (%3d) '%s'", hcount, strlen(hdr), hdr);
#endif

    /* Check for rc line.  */
    if (hcount == 1) {
      /* Parse the first line of server response */
      if (hdr[0] == '\0') {
	traceEvent(CONST_TRACE_ERROR, "CHKVER: http response: Nothing");
	return 1;
      }
      /*
       * Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
       */
      rc=-1;
      while(hdr[0] != '\0') {
	if(hdr[0] == ' ')
	  rc=0;
	else if(rc == 0)
	  break;
	hdr++;
      }
      while((hdr[0] != '\0') &&
	    (hdr[0] != ' ')) {
	rc = 10*rc + hdr[0] - '0';
	hdr++;
      }
      if(rc != 200) {
	traceEvent(CONST_TRACE_WARNING,
		   "CHKVER: http response: %d - skipping check", rc);
	return 1;
      }
      traceEvent(CONST_TRACE_NOISY, "CHKVER: http response: %d", rc);
    }

    /* Empty?  Done with the headers...  */
    if (hdr[0] == '\0') {
      break;
    }
  }

#ifdef CHKVER_DEBUG
  traceEvent(CONST_TRACE_INFO, "CHKVER_DEBUG: raw version file is %s", next);
#endif

  /* Cleanup whitespace */
  for (j=i=0; i<strlen(next); i++) {
    if(next[i] == '<' &&
       next[i+1] == '!' &&
       next[i+2] == '-' &&
       next[i+3] == '-') {
      for(k=i+4; k<strlen(next)-3; k++) {
	if(next[k] == '-' &&
	   next[k+1] == '-' &&
	   next[k+2] == '>') {
	  i=k+2;
	  break;
	}
      }
      if(k<strlen(next)-3)
	continue;
      /* Otherwise, we never found the close... so we ignore the 'comment' */
    }
    if(next[i] == '\n' ||
       next[i] == '\r' ||
       next[i] == '\f' ||
       next[i] == '\v' ||
       next[i] == '\t' ||
       next[i] == ' ') {
    } else {
      next[j++] = next[i];
    }
  }
  next[j]='\0';

#ifdef CHKVER_DEBUG
  traceEvent(CONST_TRACE_INFO, "CHKVER_DEBUG: cleaned version file is %s", next);
#endif

  /* parse - in reverse order so we can do it cheesy using \0s */
  xmlextract(development);
  xmlextract(stable);
  xmlextract(unsupported);
  xmlextract(obsolete);
  xmlextract(date);
  xmlextract(site);

  vNumber = convertNtopVersionToNumber(version);
  oNumber = convertNtopVersionToNumber(obsolete);
  uNumber = convertNtopVersionToNumber(unsupported);
  sNumber = convertNtopVersionToNumber(stable);
  dNumber = convertNtopVersionToNumber(development);
  if((oNumber == 999999999) ||
     (uNumber == 999999999) ||
     (sNumber == 999999999) ||
     (dNumber == 999999999) ||
     (vNumber == 999999999) ||
     (oNumber >  uNumber)   ||
     (uNumber >  sNumber)   ||
     (sNumber >  dNumber)) {
    traceEvent(CONST_TRACE_WARNING,
	       "CHKVER: version file INVALID - ignoring version check");
    traceEvent(CONST_TRACE_WARNING,
	       "CHKVER: Please report to ntop mailing list, codes (%u,%u,%u,%u,%u)",
	       oNumber, uNumber, sNumber, dNumber, vNumber);
    return 1;
  }

  traceEvent(CONST_TRACE_INFO, "CHKVER: Version file is from '%s'", site);
  traceEvent(CONST_TRACE_INFO, "CHKVER: as of date is '%s'", date);

  traceEvent(CONST_TRACE_NOISY, "CHKVER: obsolete is    '%-10s' (%9u)", obsolete,    oNumber);
  traceEvent(CONST_TRACE_NOISY, "CHKVER: unsupported is '%-10s' (%9u)", unsupported, uNumber);
  traceEvent(CONST_TRACE_NOISY, "CHKVER: stable is      '%-10s' (%9u)", stable,      sNumber);
  traceEvent(CONST_TRACE_NOISY, "CHKVER: development is '%-10s' (%9u)", development, dNumber);
  traceEvent(CONST_TRACE_NOISY, "CHKVER: version is     '%-10s' (%9u)", version,     vNumber);

  /* Check values - set status flag */
  if(vNumber < oNumber) {
    myGlobals.checkVersionStatus = FLAG_CHECKVERSION_OBSOLETE;
  } else if(vNumber < uNumber) {
    myGlobals.checkVersionStatus = FLAG_CHECKVERSION_UNSUPPORTED;
  } else if(vNumber < sNumber) {
    myGlobals.checkVersionStatus = FLAG_CHECKVERSION_NOTCURRENT;
  } else if(vNumber == sNumber) {
    myGlobals.checkVersionStatus = FLAG_CHECKVERSION_CURRENT;
  } else if(vNumber < dNumber) {
    myGlobals.checkVersionStatus = FLAG_CHECKVERSION_OLDDEVELOPMENT;
  } else if(vNumber == dNumber) {
    myGlobals.checkVersionStatus = FLAG_CHECKVERSION_DEVELOPMENT;
  } else {
    myGlobals.checkVersionStatus = FLAG_CHECKVERSION_NEWDEVELOPMENT;
  }

  return 0;
}

/* ********************************** */

void* checkVersion(void* notUsed _UNUSED_) {
  /* The work buffer is a big boy so we can eat the entire XML file all at once
   * and avoid making this logic any more complex!
   */
  char buf[LEN_CHECKVERSION_BUFFER];
  int rc=0, idx = 0;  

  displayPrivacyNotice();

  for(idx = 0; versionSite[idx] != NULL; idx++) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: Checking current ntop version at %s/%s", versionSite[idx], CONST_VERSIONCHECK_DOCUMENT);
  
#ifdef CHKVER_DEBUG
    traceEvent(CONST_TRACE_INFO, "CHKVER_DEBUG: '%s' '%s'", versionSite[idx], CONST_VERSIONCHECK_DOCUMENT);
#endif

    memset(buf, 0, sizeof(buf));
  
    rc = retrieveVersionFile(versionSite[idx], CONST_VERSIONCHECK_DOCUMENT, buf, sizeof(buf));
    
    if(rc == 0) break;
  }

  if (rc == 0) {
    rc = processVersionFile(buf, min(sizeof(buf), strlen(buf)));
    
    if (rc == 0) {
      traceEvent(CONST_TRACE_INFO,
		 "CHKVER: This version of ntop is %s", reportNtopVersionCheck());
    }
  }

  if(myGlobals.checkVersionStatus != FLAG_CHECKVERSION_NEWDEVELOPMENT)
    /* If it was new development at the 1st check, it's not magically going
     * to become anything else... so don't report a recheck time
     */
    myGlobals.checkVersionStatusAgain = time(NULL) + CONST_VERSIONRECHECK_INTERVAL;
  else
    myGlobals.checkVersionStatusAgain = 0;

  return(NULL);
}

/* ********************************** */

int readInputFile(FILE* fd,
                    char* logTag,
                    u_char forceClose,
                    u_char compressedFormat,
                    int countPer,
                    char* buf,
                    int bufLen,
                    int* recordsRead) {

  /*
   * This is a common routine to return the records from a data file, compressed or 
   * not, which was checked for via checkForInputFile.
   *
   *    It returns -1 if an eof occured or zero otherwise.
   *    The record is returned in buf.
   *
   * Call with forceClose TRUE to force the file to be closed...
   */

  char* getValue;

  if((fd != NULL) && (forceClose == FALSE) && (buf != NULL) && (bufLen > 0)) {
#ifdef MAKE_WITH_ZLIB
      if(compressedFormat)
        getValue = gzgets(fd, buf, bufLen);
      else
#endif
        getValue = fgets(buf, bufLen, fd);

      if(getValue != NULL) {
        (*recordsRead)++;
        if((logTag != NULL) && (countPer > 0) && ((*recordsRead) % countPer == 0))
          traceEvent(CONST_TRACE_NOISY, "%s: ....%6d records read", logTag, (*recordsRead));
        return(0);
      }
  }

  /* Either EOF or forceClose */
  if(logTag != NULL) 
    traceEvent(CONST_TRACE_NOISY, "%s: Closing file", logTag);

  if(fd != NULL) 
#ifdef MAKE_WITH_ZLIB
    if(compressedFormat)
      gzclose(fd);
    else
#endif
      fclose(fd);

  if((logTag != NULL) && (*recordsRead > 0))
    traceEvent(CONST_TRACE_INFO, "%s: ...found %d lines", logTag, *recordsRead);

  return(-1);
}

/* ********************************** */

FILE* checkForInputFile(char* logTag,
                      char* descr,
                      char* fileName,
                      struct stat *dbStat,
                      u_char* compressedFormat) {

  int configFileFound=FALSE, idx;
  char tmpFile[LEN_GENERAL_WORK_BUFFER];
  FILE* fd;
  struct tm t;
  char bufTime[LEN_TIMEFORMAT_BUFFER], bufTime2[LEN_TIMEFORMAT_BUFFER];

  /*
   * This is a common routine to look for a data file, compressed or not,
   * in the various locations ntop looks for them.
   *
   *    It returns fd if a file was found.  Returned value compressedFormat tells the tale
   *
   *    It returns NULL if the file was not found.
   *
   * If you only want to reload the file if it is newer, then pass
   * a populated stat structure in as dbStat, and it will be checked.
   *
   *    External to this you will not be able to tell the difference
   *    between a NULL for not found and NULL for not newer - let this routine's
   *    messages be enough for the user.
   */
  if(logTag != NULL) traceEvent(CONST_TRACE_INFO, "%s: Checking for %s file", logTag, descr);
  for(idx=0; myGlobals.configFileDirs[idx] != NULL; idx++) {

#ifdef MAKE_WITH_ZLIB
      *compressedFormat = 1;
      if(snprintf(tmpFile, sizeof(tmpFile),
                  "%s%c%s.gz",
                  myGlobals.configFileDirs[idx], CONST_PATH_SEP, fileName) < 0)
        BufferTooShort();
      if(logTag != NULL) traceEvent(CONST_TRACE_NOISY, "%s: Checking '%s'", logTag, tmpFile);
      fd = gzopen(tmpFile, "r");
      /* Note, if this code is inactive, fd is NULL from above, avoids fancy ifdefs */
#endif

      if(fd == NULL) {
	*compressedFormat = 0;
	if(snprintf(tmpFile, sizeof(tmpFile),
                    "%s%c%s",
                    myGlobals.configFileDirs[idx], CONST_PATH_SEP, fileName) < 0)
          BufferTooShort();
        if(logTag != NULL) traceEvent(CONST_TRACE_NOISY, "%s: Checking '%s'", logTag, tmpFile);
	fd = fopen(tmpFile, "r");
      }

      if(fd != NULL) {
	configFileFound = TRUE;
        if(logTag != NULL) traceEvent(CONST_TRACE_NOISY, "%s: ...Found", logTag);
        break;
      }
  } /* for */

  if (configFileFound != TRUE) {
      if(logTag != NULL)
        traceEvent(CONST_TRACE_WARNING, "%s: Unable to open file '%s'", logTag, fileName);
      return(NULL);
  }

  if(dbStat) {
      struct stat checkStat;

      if(logTag != NULL) {
        memset(bufTime, 0, sizeof(bufTime));
        memset(bufTime2, 0, sizeof(bufTime2));
        strftime(bufTime, sizeof(bufTime), CONST_LOCALE_TIMESPEC,
                 localtime_r(&(dbStat->st_ctime), &t));
        strftime(bufTime2, sizeof(bufTime2), CONST_LOCALE_TIMESPEC,
                 localtime_r(&(dbStat->st_mtime), &t));
        traceEvent(CONST_TRACE_NOISY, "%s: Database created %s, last modified %s", logTag, bufTime, bufTime2);
      }

      /* Check time stamps... */
      if(!stat(tmpFile, &checkStat)) {
        time_t compareTime;
        /* Pick the later - so if you copy/move a file we know it */
        compareTime = max(checkStat.st_ctime, checkStat.st_mtime);
        if(logTag != NULL) {
          memset(bufTime, 0, sizeof(bufTime));
          strftime(bufTime, sizeof(bufTime), CONST_LOCALE_TIMESPEC, 
                   localtime_r(&compareTime, &t));
          traceEvent(CONST_TRACE_NOISY, "%s: Input file created/last modified %s", logTag, bufTime);
        }
        if(dbStat->st_mtime >= compareTime) {
          if(logTag != NULL)
            traceEvent(CONST_TRACE_INFO,"%s: File '%s' does not need to be reloaded", logTag, tmpFile);
#ifdef MAKE_WITH_ZLIB
          if(*compressedFormat)
            gzclose(fd);
          else
#endif
            fclose(fd);
          return(NULL);
        } else {
          if(logTag != NULL)
            traceEvent(CONST_TRACE_INFO, "%s: Loading newer file '%s'", logTag, tmpFile);
        }
      } else {
        if(logTag != NULL) {
          traceEvent(CONST_TRACE_WARNING,
                     "%s: Unable to check file age %s(%d)",
                     logTag, strerror(errno), errno);
          traceEvent(CONST_TRACE_INFO, "%s: File '%s' loading", logTag, tmpFile);
        }
      }
  } else {
    if(logTag != NULL)
      traceEvent(CONST_TRACE_INFO, "%s: Loading file '%s'", logTag, tmpFile);
  }
  return(fd);
}

/* ******************************************** */
/* Fixup routines for ethernet addresses */

void urlFixupFromRFC1945Inplace(char* url) {

/* Do an in-place fixup of a rfc1945 URL back to the internal name,
   that is convert _s back to :s
 */
  int i;

  for(i=0; url[i] != '\0'; i++)
    if(url[i] == '_')
      url[i] = ':';

}
 
void urlFixupToRFC1945Inplace(char* url) {

/* Do an in-place fixup of an internal name to a RFC1945 URL, 
   that is convert :s to _s
 */
  int i;

  for(i=0; url[i] != '\0'; i++)
    if(url[i] == ':')
      url[i] = '_';

}

/* ********************************************* */

void _setResolvedName(HostTraffic *el, char *updateValue, short updateType, char* file, int line) {
  int i;

  if(updateValue[0] == '\0') return;

  /* Only update if this is a MORE important type */
  if(updateType > el->hostResolvedNameType) {

#ifndef CMPFCTN_DEBUG
    if(myGlobals.debugMode == 1)
#endif
      traceEvent(CONST_TRACE_INFO,
                 "CMPFCTN_DEBUG: setResolvedName(0x%08x) %d %s -> %d %s - %s(%d)", 
                 el,
                 el->hostResolvedNameType,
                 el->hostResolvedName,
                 updateType,
                 updateValue,
                 file, line);

    strncpy(el->hostResolvedName, updateValue, MAX_LEN_SYM_HOST_NAME-1);
    // el->hostResolvedName[MAX_LEN_SYM_HOST_NAME-1] = '\0';
    for(i=0; el->hostResolvedName[i] != '\0'; i++)
      el->hostResolvedName[i] = tolower(el->hostResolvedName[i]);

    el->hostResolvedNameType = updateType;
  }
}

/* ********************************************* */
/* ********************************************* */
/*       hostResolvedName compare function       */
/* ********************************************* */

int cmpFctnResolvedName(const void *_a, const void *_b) {

/* This function is ugly, but critical, so bare with...

    It takes two HostTraffic entries and performs a standardized compare
    of the hostResolvedName fields, reaching into OTHER fields as necessary.

    The SOLE goal is to provide a stable comparison.

    Hopefully the results are PREDICTABLE and EXPLAINABLE, but that's totally
    secondary.

    Why?  Because sorts don't handle non-transitive compares very well.

    If  A>B but B !< A, the sort will probably CHOKE.

    Since the hostResolvedName field contains something like six or nine
    possible types of 'names' for a host, a simple alphabetic compare
    won't cut it.  Especially as hostResolvedName may not be valued
    at the time of the compare...

    We also can't simply just use the next valued field in the
    sets, because we run the risk of intransitive compares,
    where

                    primary(a) > primary(b)

            but

                    secondary(a) < secondary(b)

    and if we have say primary for a and c, but not b, risk that
    just because a<b and b<c a !< c... this completely hoses the
    sort.


    So instead in this routine, we practice a gracefull, explicit fallback:

    1. If the HostTraffic pointers are NULL, we return equality.

       1A. If one of the HostTraffic pointers is NULL, we return THAT entry as <

    2. If both of the hostResolvedName fields are NOT NULL,
       and both of the hostResolvedNameType fields are NONE, we:

       2A. Check the hostResolvedNameType fields for both A and B.

           2A1. If they are identical, we perform the approprate 
                apples to apples compare.  

                    For example using hostNumIpAddress for a meaningful
                    IP address sort (where 9.0.0.0 < 10.0.0.0).

           2A2. If the hostResolvedNameType fields are NOT identical, we 
                do the sort on the hostResolvedNameType field itself.


             2A1+2A2 means that we sort all of the NAMES alphabetically, 
             followed by all of the IP addresses sorted NUMERICALLY, followed by...

    3A. If precisely ONE of the hostResolvedName fields is NULL or precisely ONE
        of the hostResolvedNameType fields is NONE, we return the
        valued field < the unvalued one (so unresolved things fall to the
        end of the sort).

    3B. If both of the hostResolvedName fields are NULL, we fall back
       gracefully, seeking - in the order of the _TYPE flags, a field which
       is valued in BOTH a and b.

    4. Finally if nothing matches, we return a=b.

   */

    HostTraffic **a = (HostTraffic **)_a;
    HostTraffic **b = (HostTraffic **)_b;
    int rc;
    char *name1, *name2;
#ifdef CMPFCTN_DEBUG
    char debugCmpFctn[128];
    memset(debugCmpFctn, 0, sizeof(debugCmpFctn));
#endif

    /* 1, 1A */
    if((a == NULL) && (b == NULL)) {
      return(0);
    } else if(a == NULL) {
      return(-1);
    } else if(b == NULL) {
      return(1);
    }

    if((*a == NULL) && (*b == NULL)) {
      return(0);
    } else if(*a == NULL) {
      return(-1);
    } else if(*b == NULL) {
      return(1);
    }

    accessAddrResMutex("cmpFctnResolvedName");

    if(((*a)->hostResolvedName != NULL) &&
       ((*a)->hostResolvedNameType != FLAG_HOST_SYM_ADDR_TYPE_NONE) &&
       ((*b)->hostResolvedName != NULL) &&
       ((*b)->hostResolvedNameType != FLAG_HOST_SYM_ADDR_TYPE_NONE)) {

#ifdef CMPFCTN_DEBUG
      traceEvent(CONST_TRACE_INFO, "CMPFCTN_DEBUG: cmpFctn(0x%08x, 0x%08x): %d %s vs %d %s",
                 (*a),
                 (*b),
                 (*a)->hostResolvedNameType,
                 (*a)->hostResolvedName,
                 (*b)->hostResolvedNameType,
                 (*b)->hostResolvedName);
#endif

      /* 2 - valid hostResolvedName */
      if((*a)->hostResolvedNameType == (*b)->hostResolvedNameType) {
          /* 2A1 */

             /* Remember, order of the cases is important don't change
              * But also remember, we're comparing only the values of the 
              * same type stored in hostResolvedName so MOST can be 
              * a straight string compare.
              */

          if((*a)->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_NAME) {
              name1 = (*a)->hostResolvedName;
              name2 = (*b)->hostResolvedName;
              rc = strcasecmp(name1, name2);
#ifdef CMPFCTN_DEBUG
              strncpy(debugCmpFctn, "2A1-NAME", sizeof(debugCmpFctn));
#endif
          } else if((*a)->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_IP) {
              rc = addrcmp(&((*a)->hostIpAddress), &((*b)->hostIpAddress));
#ifdef CMPFCTN_DEBUG
              strncpy(debugCmpFctn, "2A1-IP", sizeof(debugCmpFctn));
#endif
          } else if((*a)->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_MAC) {
              /*
               * Remember - the MAC value in hostResolvedName, is proabably the 
               * translated MAC, e.g. 3COM CORPORATION:E2:DB:06 and not the
               * 48bit value.  But, if we don't recognize the vendor, then it's the
               * 17 character form (xx:xx:xx:xx:xx:xx).  The special case is to
               * sort xx: form AFTER the recognized ones.
               * We use strncasecmp so 3Com and 3COM sort together
               */
              name1 = (*a)->hostResolvedName;
              name2 = (*b)->hostResolvedName;
              if(((name1[2] == ':') && (name2[2] != ':')) ||
                 ((name1[2] != ':') && (name2[2] == ':'))) {
                /* One : one recognized */
                if(name1[2] == ':') {
                  rc=1; /* name1 (unrecognized) > name2 (recognized) */
#ifdef CMPFCTN_DEBUG
                  strncpy(debugCmpFctn, "2A1-MAC-1:", sizeof(debugCmpFctn));
#endif
                } else {
                  rc=-1;  /* name1 (recognized) > name2 (unrecognized) */
#ifdef CMPFCTN_DEBUG
                  strncpy(debugCmpFctn, "2A1-MAC-2:", sizeof(debugCmpFctn));
#endif
                }
              } else {
                rc = strcasecmp(name1, name2);
#ifdef CMPFCTN_DEBUG
                strncpy(debugCmpFctn, "2A1-MAC", sizeof(debugCmpFctn));
#endif
              }
          } else if(((*a)->hostResolvedNameType != FLAG_HOST_SYM_ADDR_TYPE_FC) &&
                    ((*a)->hostResolvedNameType != FLAG_HOST_SYM_ADDR_TYPE_FAKE)) {
            /* For most of the rest of the tests, we just compare the names we 
             * have - since they're always the same type, a strncasecmp test 
             * IS meaningful.
             */
            name1 = (*a)->hostResolvedName;
            name2 = (*b)->hostResolvedName;
            rc = strcasecmp(name1, name2);
#ifdef CMPFCTN_DEBUG
            strncpy(debugCmpFctn, "2A1-!FC!FAKE", sizeof(debugCmpFctn));
#endif
          } else if((*a)->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_FC) {
            name1 = (*a)->hostResolvedName;
            name2 = (*b)->hostResolvedName;
            rc = strcasecmp(name1, name2);
#ifdef CMPFCTN_DEBUG
            strncpy(debugCmpFctn, "2A1-FC", sizeof(debugCmpFctn));
#endif
          } else { /* FAKE */
            name1 = (*a)->hostResolvedName;
            name2 = (*b)->hostResolvedName;
            rc = strcasecmp(name1, name2);
#ifdef CMPFCTN_DEBUG
            strncpy(debugCmpFctn, "2A1-FAKE", sizeof(debugCmpFctn));
#endif
          }
      } else {
          /* 2A2 - unequal types, so just compare the Type field */
          if((*a)->hostResolvedNameType > (*b)->hostResolvedNameType)
            rc = -1; /* Higher type before lower */
          else
            rc = 1;
#ifdef CMPFCTN_DEBUG
          strncpy(debugCmpFctn, "2A2!=", sizeof(debugCmpFctn));
#endif
      }
    } else {
      /* If only one is not NULL/NONE, so let's do 3A */
      if(((*a)->hostResolvedNameType != FLAG_HOST_SYM_ADDR_TYPE_NONE) &&
         ((*b)->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_NONE)) {
        /* a not NULL so return a<b */
        rc = -1; 
#ifdef CMPFCTN_DEBUG
        strncpy(debugCmpFctn, "3A-a!", sizeof(debugCmpFctn));
#endif
      } else if(((*a)->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_NONE) &&
                ((*b)->hostResolvedNameType != FLAG_HOST_SYM_ADDR_TYPE_NONE)) {
        /* b not NULL so return a>b */
        rc = 1;
#ifdef CMPFCTN_DEBUG
        strncpy(debugCmpFctn, "3A-b!", sizeof(debugCmpFctn));
#endif
      } else {
        /* 3B - hostResolvedName not set - graceful fallback using the raw fields! */
        char nullEthAddress[LEN_ETHERNET_ADDRESS];
        memset(&nullEthAddress, 0, LEN_ETHERNET_ADDRESS);

        /* Do we have a non 0.0.0.0 IP?  Yes: Compare it */
        if(!addrnull(&(*a)->hostIpAddress) && 
           !addrnull(&(*b)->hostIpAddress)) {
          rc = addrcmp(&((*a)->hostIpAddress), &((*b)->hostIpAddress));
#ifdef CMPFCTN_DEBUG
          strncpy(debugCmpFctn, "3B-IP", sizeof(debugCmpFctn));
#endif

        } else if((memcmp((*a)->ethAddress, nullEthAddress, LEN_ETHERNET_ADDRESS) != 0) && 
                  (memcmp((*b)->ethAddress, nullEthAddress, LEN_ETHERNET_ADDRESS) != 0)) {
          /* We have a non zero MAC - compare it */
          rc = memcmp(((*a)->ethAddress), ((*b)->ethAddress), LEN_ETHERNET_ADDRESS);
#ifdef CMPFCTN_DEBUG
          strncpy(debugCmpFctn, "3B-MAC", sizeof(debugCmpFctn));
#endif
//TODO FC??
        } else if(((*a)->nonIPTraffic != NULL) && ((*b)->nonIPTraffic != NULL)) {
          /* Neither a nor b are null, so we can compare the fields in nonIPTraffic... 
           *  NetBIOS, IPX then Appletalk, if we have 'em */
          if(((*a)->nonIPTraffic->nbHostName != NULL) &&
             ((*b)->nonIPTraffic->nbHostName != NULL)) {
            rc=strcasecmp((*a)->nonIPTraffic->nbHostName, (*b)->nonIPTraffic->nbHostName);
#ifdef CMPFCTN_DEBUG
            strncpy(debugCmpFctn, "3B-NB", sizeof(debugCmpFctn));
#endif
          } else if(((*a)->nonIPTraffic->ipxHostName != NULL) &&
             ((*b)->nonIPTraffic->ipxHostName != NULL)) {
            rc=strcasecmp((*a)->nonIPTraffic->ipxHostName, (*b)->nonIPTraffic->ipxHostName);
#ifdef CMPFCTN_DEBUG
            strncpy(debugCmpFctn, "3B-IPX", sizeof(debugCmpFctn));
#endif
          } else if(((*a)->nonIPTraffic->atNodeName != NULL) &&
             ((*b)->nonIPTraffic->atNodeName != NULL)) {
            rc=strcasecmp((*a)->nonIPTraffic->atNodeName, (*b)->nonIPTraffic->atNodeName);
#ifdef CMPFCTN_DEBUG
            strncpy(debugCmpFctn, "3B-ATALK", sizeof(debugCmpFctn));
#endif
          } else {
            rc=0;  /* can't tell 'em apart... trouble */
#ifdef CMPFCTN_DEBUG
            strncpy(debugCmpFctn, "3B-0", sizeof(debugCmpFctn));
#endif
          }
        } else if(((*a)->nonIPTraffic == NULL) && ((*b)->nonIPTraffic != NULL)) {
          /* a null, b not so return a>b */
          rc=1;
#ifdef CMPFCTN_DEBUG
          strncpy(debugCmpFctn, "3B-b!", sizeof(debugCmpFctn));
#endif
        } else if(((*a)->nonIPTraffic != NULL) && ((*b)->nonIPTraffic == NULL)) {
          /* b null, a not so return a>b */
          rc=1; 
#ifdef CMPFCTN_DEBUG
          strncpy(debugCmpFctn, "3B-a!", sizeof(debugCmpFctn));
#endif
        } else {
          rc=0; /* nothing we can compare */
#ifdef CMPFCTN_DEBUG
          strncpy(debugCmpFctn, "3B-null", sizeof(debugCmpFctn));
#endif
        }
      }
    }

    releaseAddrResMutex();

#ifdef CMPFCTN_DEBUG
    traceEvent(CONST_TRACE_INFO, "CMPFCTN_DEBUG: cmpFctn(): %s rc=%d", debugCmpFctn, rc);
#endif

    return(rc); 
}

/* ********************************************* */
/* ********************************************* */
/*       Location code compare function          */
/* ********************************************* */

int cmpFctnLocationName(const void *_a, const void *_b) {

/* This function takes two HostTraffic entries and performs a 
   standardized compare of the location, either the ip2ccValue field
   or the fallback dnsTLDValue fields, handling unvalued
   situations to provide a stable comparison.

   We translate 'loc' (rfc1918 addresses) to sort next to last
   and unvalued items to sort last.

   Equal valued names are sorted based first on full domain name, then
   on hostResolvedName as the tie breakers.
 */

    HostTraffic **a = (HostTraffic **)_a;
    HostTraffic **b = (HostTraffic **)_b;
    int rc;
    char *nameA, *nameB;

    rc=0;

    if((*a)->ip2ccValue == NULL) {
        nameA = "\xFF\xFF";
    } else if(strcasecmp((*a)->ip2ccValue, "loc") == 0) {
        nameA = "\xFF\xFE";
    } else {
        nameA = (*a)->ip2ccValue;
    }
    if((*b)->ip2ccValue == NULL) {
        nameB = "\xFF\xFF";
    } else if(strcasecmp((*b)->ip2ccValue, "loc") == 0) {
        nameB = "\xFF\xFE";
    } else {
        nameB = (*b)->ip2ccValue;
    }

    rc = strcasecmp(nameA, nameB);
    if(rc==0) {
      if((*a)->dnsTLDValue == NULL) {
        nameA = "\xFF\xFF";
      } else {
        nameA = (*a)->dnsTLDValue;
      }
      if((*b)->dnsTLDValue == NULL) {
        nameB = "\xFF\xFF";
      } else {
        nameB = (*b)->ip2ccValue;
      }
      rc = strcasecmp(nameA, nameB);
    }

    if(rc==0) {
      rc=cmpFctnResolvedName(a, b);
    }

    return(rc);
}

/* ************************************ */
