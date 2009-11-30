/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *                          http://www.ntop.org
 *
 *           Copyright (C) 1998-2009 Luca Deri <deri@ntop.org>
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

#ifndef WIN32
#include <syslog.h>
#endif

#ifndef HAVE_GETOPT_LONG
#include "./utils/getopt/getopt.c"
#include "./utils/getopt/getopt1.c"
#endif

/* #define ADDRESS_DEBUG */
/* #define FINGERPRINT_DEBUG */

/* FTP */
static SessionInfo *passiveSessions = NULL;
static u_short passiveSessionsLen;

/* VoIP */
static SessionInfo *voipSessions = NULL;
static u_short voipSessionsLen;


static char *versionSite[]   = {
  CONST_VERSIONCHECK_SITE,
  NULL 
};

/* ************************************ */

static HostTraffic* __getFirstHost(u_int actualDeviceId, u_int beginIdx, char *file, int line) {
  u_int idx;

  accessMutex(&myGlobals.hostsHashLockMutex, "__getFirstHost");

  for(idx=beginIdx; idx<myGlobals.device[actualDeviceId].actualHashSize; idx++) {
    HostTraffic *el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];

    while(el != NULL) {
      if(broadcastHost(el) || (el == myGlobals.otherHostEntry)) {
	el = el->next;
      } else {
	if(el->magic != CONST_MAGIC_NUMBER) {
	  traceEvent(CONST_TRACE_ERROR,
		     "Bad magic number [expected=%d/real=%d][deviceId=%d] getFirstHost()[%s/%d]",
		     CONST_MAGIC_NUMBER, el->magic, actualDeviceId, file, line);
	  releaseMutex(&myGlobals.hostsHashLockMutex);
	  return(NULL);
	}

	if(!is_host_ready_to_purge(actualDeviceId, el, time(NULL))) {
	  /* Do not return hosts that will soon be purged off memory */
	  releaseMutex(&myGlobals.hostsHashLockMutex);
	  return(el);
	} else {
	  el = el->next;
	}
      }
    }
  }

  releaseMutex(&myGlobals.hostsHashLockMutex);
  return(NULL);
}

/* ************************************ */

HostTraffic* _getFirstHost(u_int actualDeviceId, char *file, int line) {
  return(__getFirstHost(actualDeviceId, 0 /* FIRST_HOSTS_ENTRY */, file, line));
}

/* ************************************ */

HostTraffic* _getNextHost(u_int actualDeviceId, HostTraffic *host, char *file, int line) {
  u_int nextIdx;
  time_t now = time(NULL);

  accessMutex(&myGlobals.hostsHashLockMutex, "getNextHost");

  if((host == NULL) || (host->magic != CONST_MAGIC_NUMBER)) {
    releaseMutex(&myGlobals.hostsHashLockMutex);
    return(NULL);
  }

  nextIdx = host->hostTrafficBucket+1;

  while(host->next != NULL) {
    if(host->next->magic != CONST_MAGIC_NUMBER) {
      traceEvent(CONST_TRACE_ERROR, "Bad magic number (expected=%d/real=%d) getNextHost()[%s/%d]",
		 CONST_MAGIC_NUMBER, host->next->magic, file, line);
      releaseMutex(&myGlobals.hostsHashLockMutex);
      return(NULL);
    }

    if(!is_host_ready_to_purge(actualDeviceId, host->next, now)) {
      releaseMutex(&myGlobals.hostsHashLockMutex);
      return(host->next);
    } else
      host = host->next;
  }

  /* No host has been found: move to next bucket */
  releaseMutex(&myGlobals.hostsHashLockMutex);
  if(nextIdx < myGlobals.device[actualDeviceId].actualHashSize)
    return(__getFirstHost(actualDeviceId, nextIdx, file, line));
  else
    return(NULL);
}

/* ************************************ */

HostTraffic* findHostByNumIP(HostAddr hostIpAddress, short vlanId, u_int actualDeviceId) {
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
    if((el->hostNumIpAddress != NULL) && (addrcmp(&el->hostIpAddress,&hostIpAddress) == 0)) {
      if((vlanId > 0) && (el->vlanId != vlanId)) continue;
      return(el);
    }
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
	if((el->hostNumIpAddress != NULL) && (addrcmp(&el->hostIpAddress,&hostIpAddress) == 0)) {
	  if((vlanId > 0) && (el->vlanId != vlanId)) continue;
	  return(el);
	}
      }
    }
  }

  return(NULL);
}

/* ************************************ */

char* serial2str(HostSerial theSerial, char *buf, int buf_len) {
  buf[0] = '\0';

  if(buf_len >= 2*sizeof(HostSerial)) {
    int i;
    char tmpStr[16];
    char *ptr = (char*)&theSerial;

    for(i=0; i<sizeof(HostSerial); i++) {
      snprintf(tmpStr, sizeof(tmpStr), "%02X", ptr[i] & 0xFF);
      strcat(buf, tmpStr);
    }
  }

  return(buf);
}

/* ************************************ */

void str2serial(HostSerial *theSerial, char *buf, int buf_len) {
  if(buf_len >= 2*sizeof(HostSerial)) {
    int i, j;
    char tmpStr[16];
    u_char *ptr = (u_char*)theSerial;

    for(i=0, j=0; j<sizeof(HostSerial); j++) {
	  u_int c;

      tmpStr[0] = buf[i++];
      tmpStr[1] = buf[i++];
      tmpStr[2] = '\0';
      sscanf(tmpStr, "%02X", &c);
	  ptr[j] = c & 0xFF;

	  /*
	   ptr[j] = ((u_int8_t)buf[i]) * 16 + ((u_int8_t)buf[i+1]);
	   i += 2;
	   */
    }
  }
}

/* ************************************ */

HostTraffic* findHostBySerial(HostSerial theSerial, u_int actualDeviceId) {
  if(emptySerial(&theSerial)) return(NULL);
  if(theSerial.serialType == SERIAL_IPV4 || theSerial.serialType == SERIAL_IPV6) {
    return(findHostByNumIP(theSerial.value.ipSerial.ipAddress,
			   theSerial.value.ipSerial.vlanId,
			   actualDeviceId));
  } else if(theSerial.serialType == SERIAL_FC) {
    return(findHostByFcAddress(&theSerial.value.fcSerial.fcAddress,
				 theSerial.value.fcSerial.vsanId,
				 actualDeviceId));
  }
  else {
    /* MAC */
    return(findHostByMAC((char*)theSerial.value.ethSerial.ethAddress,
			 theSerial.value.ethSerial.vlanId,
			 actualDeviceId));
  }
}

/* ************************************ */

HostTraffic* findHostByMAC(char* macAddr, short vlanId, u_int actualDeviceId) {
  HostTraffic *el;
  short dummyShort = 0;
  u_int idx = hashHost(NULL, (u_char*)macAddr, &dummyShort, &el, actualDeviceId);

  if(el != NULL)
    return(el); /* Found */
  else if(idx == FLAG_NO_PEER)
    return(NULL);
  else
    el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];

  for(; el != NULL; el = el->next) {
    if(!memcmp((char*)el->ethAddress, macAddr, LEN_ETHERNET_ADDRESS)) {
      if((vlanId > 0) && (el->vlanId != vlanId))
	continue;
      else
	return(el);
    }
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
  unsigned short idx = 0;

  if (srcAddr->hostFamily != dstAddr->hostFamily)
    return -1;
  switch (srcAddr->hostFamily) {
  case AF_INET:
    /*
     * The hash key has to be calculated in a specular
     * way: its value has to be the same regardless
     * of the flow direction.
     *
     * Patch on the line below courtesy of
     * Paul Chapman <pchapman@fury.bio.dfo.ca>
     */
    idx = (u_int)(dstAddr->Ip4Address.s_addr+srcAddr->Ip4Address.s_addr+sport+dport);
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
  u_int16_t transactionId = 0;

  if (srcAddr->hostFamily != dstAddr->hostFamily)
    return -1;
  switch (srcAddr->hostFamily) {
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

  if(addr1->hostFamily != addr2->hostFamily) {
    if(addr1->hostFamily > addr2->hostFamily)
      return 1;
    else
      return -1;
  }

  switch (addr1->hostFamily) {
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
  switch (src->hostFamily) {
  case AF_INET:
    memcpy(&dst->Ip4Address,&src->Ip4Address,sizeof(struct in_addr));
    return(dst);
#ifdef INET6
  case AF_INET6:
    memcpy(&dst->Ip6Address,&src->Ip6Address,sizeof(struct in6_addr));
    return(dst);
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
  switch(Haddr->hostFamily) {
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
  switch (family) {
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
  switch(addr->hostFamily) {
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
  switch(addr->hostFamily) {
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

  for (it = addrs ; it != NULL; it = it->next) {
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
    if (memcmp(&it->af.inet6.ifAddr,addr,size) == 0) {
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
	if(count == 0) break;
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

  return(addrs);

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
    exit(20); /* Just in case */
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
unsigned short isLinkLocalAddress(struct in6_addr *addr,
				  u_int32_t *the_local_network,
				  u_int32_t *the_local_network_mask) {
  int i;

  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

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
unsigned short in6_isMulticastAddress(struct in6_addr *addr,
				      u_int32_t *the_local_network,
				      u_int32_t *the_local_network_mask) {

  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

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
unsigned short in6_isLocalAddress(struct in6_addr *addr, u_int deviceId,
				  u_int32_t *the_local_network,
				  u_int32_t *the_local_network_mask) {

  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

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

  if(myGlobals.runningPref.trackOnlyLocalHosts)
    return(0);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: %s is %s", intop(addr));
#endif
  /* Link Local Addresses are local */
  return(isLinkLocalAddress(addr, the_local_network, the_local_network_mask));
}

/* ******************************************* */

unsigned short in6_isPrivateAddress(struct in6_addr *addr,
				    u_int32_t *the_local_network,
				    u_int32_t *the_local_network_mask) {
  /* IPv6 have private addresses ?*/

  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

  return(0);
}
#endif

/* ********************************* */

unsigned short in_isBroadcastAddress(struct in_addr *addr,
				     u_int32_t *the_local_network,
				     u_int32_t *the_local_network_mask) {
  int i;

  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

  if(addr == NULL)
    return 1;
  else if(addr->s_addr == 0x0)
    return 0; /* IP-less myGlobals.device (is it trying to boot via DHCP/BOOTP ?) */
  else {
    for(i=0; i<myGlobals.numDevices; i++) {
      if(!myGlobals.device[i].virtualDevice) {

        if(myGlobals.device[i].netmask.s_addr == 0xFFFFFFFF) /* PPP */
          return 0;

        if((addr->s_addr | myGlobals.device[i].netmask.s_addr) ==  addr->s_addr) {
#ifdef DEBUG
          traceEvent(CONST_TRACE_INFO, "DEBUG: %s is a broadcast address", intoa(*addr));
#endif
          return 1;
        }

        if((addr->s_addr & ~myGlobals.device[i].netmask.s_addr) ==  ~myGlobals.device[i].netmask.s_addr) {
#ifdef DEBUG
          traceEvent(CONST_TRACE_INFO, "DEBUG: %s is a network address", intoa(*addr));
#endif
          return 1;
        }

      }
    }

    return(in_isPseudoBroadcastAddress(addr, the_local_network, the_local_network_mask));
  }
}

/* ********************************* */

unsigned short in_isMulticastAddress(struct in_addr *addr,
				     u_int32_t *the_local_network,
				     u_int32_t *the_local_network_mask) {

  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

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

u_int8_t num_network_bits(u_int32_t addr) {
  u_int8_t i, j, bits = 0, fields[4];

  memcpy(fields, &addr, 4);

  for(i = 8; i <= 8; i--)
    for(j=0; j<4; j++)
      if ((fields[j] & (1 << i)) != 0) bits++;

    return(bits);
}

/* ********************************* */

unsigned short in_isLocalAddress(struct in_addr *addr, u_int deviceId,
				 u_int32_t *the_local_network,
				 u_int32_t *the_local_network_mask) {

  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

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

  if(!myGlobals.runningPref.mergeInterfaces) {
    if((addr->s_addr & myGlobals.device[deviceId].netmask.s_addr) == myGlobals.device[deviceId].network.s_addr) {
#ifdef ADDRESS_DEBUG
      traceEvent(CONST_TRACE_INFO, "ADDRESS_DEBUG: %s is local", intoa(*addr));
#endif

      if(the_local_network && the_local_network_mask)
	(*the_local_network) = myGlobals.device[deviceId].network.s_addr,
	  (*the_local_network_mask) = num_network_bits(myGlobals.device[deviceId].netmask.s_addr);
      return 1;
    }
  } else {
    int i;

    for(i=0; i<myGlobals.numDevices; i++)
      if((addr->s_addr & myGlobals.device[i].netmask.s_addr) == myGlobals.device[i].network.s_addr) {
#ifdef ADDRESS_DEBUG
	traceEvent(CONST_TRACE_INFO, "ADDRESS_DEBUG: %s is local", intoa(*addr));
#endif
	if(the_local_network && the_local_network_mask)
	  (*the_local_network) = myGlobals.device[i].network.s_addr,
	    (*the_local_network_mask) = num_network_bits(myGlobals.device[deviceId].netmask.s_addr);
	return 1;
      }
  }

  if(myGlobals.runningPref.trackOnlyLocalHosts)
    return(0);

  /* Broadcast is considered a local address */
  return(in_isBroadcastAddress(addr, the_local_network, the_local_network_mask));
}

/* ********************************* */

unsigned short in_isPrivateAddress(struct in_addr *addr,
				   u_int32_t *the_local_network,
				   u_int32_t *the_local_network_mask) {
  /* See http://www.isi.edu/in-notes/rfc1918.txt */

  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

  /* Fixes below courtesy of Wies-Software <wies@wiessoft.de> */
  if(   ((addr->s_addr & 0xFF000000) == 0x0A000000) /* 10.0.0.0/8  */
	|| ((addr->s_addr & 0xFFF00000) == 0xAC100000) /* 172.16/12   */
	|| ((addr->s_addr & 0xFFFF0000) == 0xC0A80000) /* 192.168/16  */
	|| ((addr->s_addr & 0xFF000000) == 0x7F000000) /* 127.0.0.0/8 */
	)
    return(1);
  else
    return(0);
}

/***************************************/

unsigned short isBroadcastAddress(HostAddr *addr,
				  u_int32_t *the_local_network,
				  u_int32_t *the_local_network_mask) {
  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

  switch(addr->hostFamily) {
  case AF_INET:
    return (in_isBroadcastAddress(&addr->Ip4Address, the_local_network, the_local_network_mask));
#ifdef INET6
  case AF_INET6:
    return (isLinkLocalAddress(&addr->Ip6Address, NULL, NULL));
#endif
  default: return(0);
  }
}

/* ******************************************** */

unsigned short isMulticastAddress(HostAddr *addr,
				  u_int32_t *the_local_network,
				  u_int32_t *the_local_network_mask) {
  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

  switch(addr->hostFamily) {
  case AF_INET:
    return (in_isMulticastAddress(&addr->Ip4Address, the_local_network, the_local_network_mask));
#ifdef INET6
  case AF_INET6:
    return (in6_isMulticastAddress(&addr->Ip6Address, NULL, NULL));
#endif
  default: return(0);
  }
}

/* ************************************************* */

unsigned short isLocalAddress(HostAddr *addr, u_int deviceId,
			      u_int32_t *the_local_network,
			      u_int32_t *the_local_network_mask) {
  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

  switch(addr->hostFamily) {
  case AF_INET:
    return (in_isLocalAddress(&addr->Ip4Address, deviceId, the_local_network, the_local_network_mask));
#ifdef INET6
  case AF_INET6:
    return (in6_isLocalAddress(&addr->Ip6Address, deviceId, NULL, NULL));
#endif
  default: return(0);
  }
}

/* ************************************************** */

unsigned short isPrivateAddress(HostAddr *addr,
				u_int32_t *the_local_network,
				u_int32_t *the_local_network_mask) {
  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

  switch(addr->hostFamily) {
  case AF_INET:
    return (in_isPrivateAddress(&addr->Ip4Address, the_local_network, the_local_network_mask));
#ifdef INET6
  case AF_INET6:
    return (in6_isPrivateAddress(&addr->Ip6Address, NULL, NULL));
#endif
  default: return(0);
  }
}

/* ************************************************ */

int dotted2bits(char *mask) {
  int fields[4], fields_num;

  fields_num = sscanf(mask, "%d.%d.%d.%d",
		      &fields[0], &fields[1], &fields[2], &fields[3]);

  if(fields_num != 4) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: dotted2bits (%s) = %d", mask, fields[0]);
#endif
    return(atoi(mask));
  } else
    return(num_network_bits(((fields[0] & 0xff) << 24)
			    + ((fields[1] & 0xff) << 16)
			    + ((fields[2] & 0xff) << 8)
			    + (fields[3] & 0xff)));
}

/* ********************************* */

/* Example: "131.114.0.0/16,193.43.104.0/255.255.255.0" */

void handleAddressLists(char* addresses, NetworkStats theNetworks[MAX_NUM_NETWORKS],
			u_short *numNetworks, char *localAddresses,
			int localAddressesLen, int flagWhat) {
  char *strtokState, *address;
  int  laBufferPosition = 0, laBufferUsed = 0, i;

  if((addresses == NULL) || (addresses[0] == '\0'))
    return;

  if(0) traceEvent(CONST_TRACE_NOISY,
		   "Processing %s parameter '%s'",
		   flagWhat == CONST_HANDLEADDRESSLISTS_MAIN ? "-m | --local-subnets"  :
		   flagWhat == CONST_HANDLEADDRESSLISTS_RRD ? "RRD" :
		   flagWhat == CONST_HANDLEADDRESSLISTS_NETFLOW ? "Netflow white/black list" :
		   flagWhat == CONST_HANDLEADDRESSLISTS_COMMUNITIES ? "community" : "unknown",
		   addresses);

  memset(localAddresses, 0, localAddressesLen);

  address = strtok_r(addresses, ",", &strtokState);

  while(address != NULL) {
    u_int32_t network, networkMask, broadcast;
    int bits, a, b, c, d;
    char *mask = strchr(address, '/');
    char *equal = strchr(address, '=');

    if(equal != NULL) {
      char key[64];
      equal[0] = '\0';
      safe_snprintf(__FILE__, __LINE__, key, sizeof(key), "subnet.name.%s", address);
      storePrefsValue(key, &equal[1]);
    }

    if(mask == NULL) {
      bits = 32;
    } else {
      mask[0] = '\0';
      mask++;
      bits = dotted2bits(mask);
    }

    if(sscanf(address, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
      traceEvent(CONST_TRACE_WARNING, "Bad format '%s' - ignoring entry",
		 address);
      address = strtok_r(NULL, ",", &strtokState);
      continue;
    }

    if(bits == CONST_INVALIDNETMASK) {
      /* malformed netmask specification */
      traceEvent(CONST_TRACE_WARNING, "Net mask '%s' not valid - ignoring entry",
		 mask);
      address = strtok_r(NULL, ",", &strtokState);
      continue;
    }

    network = ((a & 0xff) << 24) + ((b & 0xff) << 16) + ((c & 0xff) << 8) + (d & 0xff);
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
      traceEvent(CONST_TRACE_WARNING, "%d.%d.%d.%d/%d is not a valid network - correcting mask",
		 a, b, c, d, bits);

      /* correcting network numbers as specified in the netmask */
      network &= networkMask;

      a = (int)((network >> 24) & 0xff);
      b = (int)((network >> 16) & 0xff);
      c = (int)((network >>  8) & 0xff);
      d = (int)((network >>  0) & 0xff);

      traceEvent(CONST_TRACE_NOISY, "Assuming %d.%d.%d.%d/%d [0x%08x/0x%08x]",
		 a, b, c, d, bits, network, networkMask);
    }
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: %d.%d.%d.%d/%d [0x%08x/0x%08x]",
	       a, b, c, d, bits, network, networkMask);
#endif

    broadcast = network | (~networkMask);

#ifdef DEBUG
    a = (int)((broadcast >> 24) & 0xff);
    b = (int)((broadcast >> 16) & 0xff);
    c = (int)((broadcast >>  8) & 0xff);
    d = (int)((broadcast >>  0) & 0xff);

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
	for(i = 0; i < myGlobals.numDevices; i++) {
	  if((network == myGlobals.device[i].network.s_addr) &&
	     (myGlobals.device[i].netmask.s_addr == networkMask)) {
	    a = (int)((network >> 24) & 0xff);
	    b = (int)((network >> 16) & 0xff);
	    c = (int)((network >>  8) & 0xff);
	    d = (int)((network >>  0) & 0xff);

	    traceEvent(CONST_TRACE_INFO,
		       "Discarded unnecessary parameter %d.%d.%d.%d/%d - this is the local network",
		       a, b, c, d, bits);
	    found = 1;
	  }
	}
      } else {
	for(i=0; i<myGlobals.numKnownSubnets; i++) {
	  if((network == myGlobals.subnetStats[i].address[CONST_NETWORK_ENTRY])
	     && (networkMask == myGlobals.subnetStats[i].address[CONST_NETMASK_ENTRY])) {
	    found = 1;
	    break; /* Already present */
	  }
	}
      }

      if(found == 0) {
	theNetworks[(*numNetworks)].address[CONST_NETWORK_ENTRY]    = network;
	theNetworks[(*numNetworks)].address[CONST_NETMASK_ENTRY]    = networkMask;
	theNetworks[(*numNetworks)].address[CONST_NETMASK_V6_ENTRY] = bits;
	theNetworks[(*numNetworks)].address[CONST_BROADCAST_ENTRY]  = broadcast;

	a = (int)((network >> 24) & 0xff);
	b = (int)((network >> 16) & 0xff);
	c = (int)((network >>  8) & 0xff);
	d = (int)((network >>  0) & 0xff);

	laBufferUsed = safe_snprintf(__FILE__, __LINE__,
				     &localAddresses[laBufferPosition],
				     localAddressesLen,
				     "%s%d.%d.%d.%d/%d",
				     (*numNetworks) == 0 ? "" : ", ",
				     a, b, c, d,
				     bits);
	if(laBufferUsed > 0) {
	  laBufferPosition  += laBufferUsed;
	  localAddressesLen -= laBufferUsed;
	}

	(*numNetworks)++;

      }
    } else {
      a = (int)((network >> 24) & 0xff);
      b = (int)((network >> 16) & 0xff);
      c = (int)((network >>  8) & 0xff);
      d = (int)((network >>  0) & 0xff);

      traceEvent(CONST_TRACE_ERROR,
		 "%s: %d.%d.%d.%d/%d - Too many networks (limit %d) - discarded",
		 flagWhat == CONST_HANDLEADDRESSLISTS_MAIN ? "-m"  :
		 flagWhat == CONST_HANDLEADDRESSLISTS_RRD ? "RRD" :
		 flagWhat == CONST_HANDLEADDRESSLISTS_NETFLOW ? "Netflow" :
		 flagWhat == CONST_HANDLEADDRESSLISTS_COMMUNITIES ? "community" : "unknown",
		 a, b, c, d, bits,
		 MAX_NUM_NETWORKS);
    }

    address = strtok_r(NULL, ",", &strtokState);
  }
}

/* ********************************* */

void handleLocalAddresses(char* addresses) {
  char localAddresses[2048];

  localAddresses[0] = '\0';

  if(addresses != NULL) {
    char *addresses_copy = strdup(addresses);

    handleAddressLists(addresses_copy, myGlobals.localNetworks, &myGlobals.numLocalNetworks,
		       localAddresses, sizeof(localAddresses), CONST_HANDLEADDRESSLISTS_MAIN);

    free(addresses_copy);
  }

  /* Not used anymore */
  if(myGlobals.runningPref.localAddresses != NULL) free(myGlobals.runningPref.localAddresses);

  if(localAddresses[0]  != '\0')
    myGlobals.runningPref.localAddresses = strdup(localAddresses);
}

/* ********************************* */

char* read_file(char* path, char* buf, u_int buf_len) {
  FILE *fd = fopen(&path[1], "r");

  if(fd == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Unable to read file %s", path);
    return(NULL);
  } else {
    char line[256];
    int idx = 0;

    while(!feof(fd) && (fgets(line, sizeof(line), fd) != NULL)) {
      if((line[0] == '#') || (line[0] == '\n')) continue;
      while(strlen(line) && (line[strlen(line)-1] == '\n')) {
	line[strlen(line)-1] = '\0';
      }

      safe_snprintf(__FILE__, __LINE__, &buf[idx], buf_len-idx-2, "%s%s", (idx > 0) ? "," : "", line);
      idx = strlen(buf);
    }

    fclose(fd);
    return(buf);
  }
}

/* ********************************* */

void handleKnownAddresses(char* addresses) {
  char knownSubnets[2048];

  knownSubnets[0] = '\0';

  if(addresses != NULL) {
    char *addresses_copy;
    char buf[2048];

    if(addresses[0] == '@') {
      /* This is a file */
      addresses_copy = read_file(addresses, buf, sizeof(buf));
      if(addresses_copy)
	addresses_copy = strdup(buf);
    } else
      addresses_copy = strdup(addresses);

    if(addresses_copy) {
      handleAddressLists(addresses_copy, myGlobals.subnetStats, &myGlobals.numKnownSubnets,
			 knownSubnets, sizeof(knownSubnets), CONST_HANDLEADDRESSLISTS_MAIN);

      free(addresses_copy);
    }
  }

  /* Not used anymore */
  if(myGlobals.runningPref.knownSubnets != NULL) free(myGlobals.runningPref.knownSubnets);

  if(knownSubnets[0]  != '\0')
    myGlobals.runningPref.knownSubnets = strdup(knownSubnets);
}

/* ********************************* */

#ifdef INET6
unsigned short in6_pseudoLocalAddress(struct in6_addr *addr,
				      u_int32_t *the_local_network,
				      u_int32_t *the_local_network_mask) {
  int i;

  for(i=0; i<myGlobals.numDevices; i++) {
    if (prefixlookup(addr,myGlobals.device[i].v6Addrs,0) == 1)
      return(1);

  }
  return(0);
}
#endif

/* ******************************************************* */

unsigned short __pseudoLocalAddress(struct in_addr *addr,
				    NetworkStats theNetworks[MAX_NUM_NETWORKS],
				    u_short numNetworks,
				    u_int32_t *the_local_network,
				    u_int32_t *the_local_network_mask) {
  int i;

  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

  for(i=0; i<numNetworks; i++) {
#ifdef ADDRESS_DEBUG
    char buf[32], buf1[32], buf2[32];
    struct in_addr addr1, addr2;

    addr1.s_addr = theNetworks[i].address[CONST_NETWORK_ENTRY];
    addr2.s_addr = theNetworks[i].address[CONST_NETMASK_ENTRY];

    traceEvent(CONST_TRACE_INFO, "DEBUG: %s comparing [%s/%s]",
	       _intoa(*addr, buf, sizeof(buf)),
	       _intoa(addr1, buf1, sizeof(buf1)),
	       _intoa(addr2, buf2, sizeof(buf2)));
#endif
    if((addr->s_addr & theNetworks[i].address[CONST_NETMASK_ENTRY]) == theNetworks[i].address[CONST_NETWORK_ENTRY]) {
#ifdef ADDRESS_DEBUG
      traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is pseudolocal", intoa(*addr));
#endif
      if(the_local_network && the_local_network_mask) {
	(*the_local_network)      = theNetworks[i].address[CONST_NETWORK_ENTRY];
	(*the_local_network_mask) = theNetworks[i].address[CONST_NETMASK_V6_ENTRY];
      }
      return(1);
    } else {
#ifdef ADDRESS_DEBUG
      traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is NOT pseudolocal", intoa(*addr));
#endif
    }
  }

  return(0);
}

/* ********************************* */

unsigned short in_pseudoLocalAddress(struct in_addr *addr,
				     u_int32_t *the_local_network,
				     u_int32_t *the_local_network_mask) {
  return(__pseudoLocalAddress(addr, myGlobals.localNetworks, myGlobals.numLocalNetworks,
			      the_local_network, the_local_network_mask));
}

/* ********************************* */

#ifdef INET6
unsigned short in6_deviceLocalAddress(struct in6_addr *addr, u_int deviceId,
				      u_int32_t *the_local_network,
				      u_int32_t *the_local_network_mask) {
  int rc;

  if(addrlookup(addr,myGlobals.device[deviceId].v6Addrs))
    rc = 1;
  else
    rc = 0;

  return(rc);
}
#endif

/* ********************************* */

unsigned short in_deviceLocalAddress(struct in_addr *addr, u_int deviceId,
				     u_int32_t *the_local_network,
				     u_int32_t *the_local_network_mask) {
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
unsigned short in6_isPseudoLocalAddress(struct in6_addr *addr, u_int deviceId,
					u_int32_t *the_local_network,
					u_int32_t *the_local_network_mask) {
  int i;

  i = in6_isLocalAddress(addr, deviceId, the_local_network, the_local_network_mask);

  if(i == 1) {
#ifdef ADDRESS_DEBUG
    traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is local", intop(addr));
#endif

    return 1; /* This is a real local address */
  }

  if(in6_pseudoLocalAddress(addr, the_local_network, the_local_network_mask))
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

/* #define ADDRESS_DEBUG */

/* This function returns true when a host is considered local
   as specified using the 'm' flag */
unsigned short in_isPseudoLocalAddress(struct in_addr *addr, u_int deviceId,
				       u_int32_t *the_local_network,
				       u_int32_t *the_local_network_mask) {
  int i;

  /* FIX */
  i = in_isLocalAddress(addr, deviceId, the_local_network, the_local_network_mask);

  if(i == 1) {
#ifdef ADDRESS_DEBUG
    traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is local", intoa(*addr));
#endif

    return 1; /* This is a real local address */
  }

  if(in_pseudoLocalAddress(addr, the_local_network, the_local_network_mask))
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

/* #undef ADDRESS_DEBUG */

/* ********************************* */

/* This function returns true when an address is the broadcast
   for the specified (-m flag subnets */

unsigned short in_isPseudoBroadcastAddress(struct in_addr *addr,
					   u_int32_t *the_local_network,
					   u_int32_t *the_local_network_mask) {
  int i;

#ifdef ADDRESS_DEBUG
  traceEvent(CONST_TRACE_WARNING, "DEBUG: Checking %8X (pseudo broadcast)", addr->s_addr);
#endif

  for(i=0; i<myGlobals.numLocalNetworks; i++) {
    if(addr->s_addr == myGlobals.localNetworks[i].address[CONST_BROADCAST_ENTRY]) {
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

unsigned short deviceLocalAddress(HostAddr *addr, u_int deviceId,
				  u_int32_t *the_local_network,
				  u_int32_t *the_local_network_mask) {
  switch(addr->hostFamily) {
  case AF_INET:
    return (in_deviceLocalAddress(&addr->Ip4Address, deviceId, the_local_network, the_local_network_mask));
#ifdef INET6
  case AF_INET6:
    return (in6_deviceLocalAddress(&addr->Ip6Address, deviceId, NULL, NULL));
#endif
  default: return(0);
  }
}

/* ********************************* */

unsigned short isPseudoLocalAddress(HostAddr *addr, u_int deviceId,
				    u_int32_t *the_local_network,
				    u_int32_t *the_local_network_mask) {

  if(the_local_network && the_local_network_mask)
    (*the_local_network) = 0,  (*the_local_network_mask) = 0;

  switch(addr->hostFamily) {
  case AF_INET:
    return (in_isPseudoLocalAddress(&addr->Ip4Address, deviceId, the_local_network, the_local_network_mask));
#ifdef INET6
  case AF_INET6:
    return (in6_isPseudoLocalAddress(&addr->Ip6Address, deviceId, NULL, NULL));
#endif
  default: return(0);
  }
}

/* ********************************* */

unsigned short isPseudoBroadcastAddress(HostAddr *addr,
					u_int32_t *the_local_network,
					u_int32_t *the_local_network_mask) {
  switch(addr->hostFamily) {
  case AF_INET:
    return (in_isPseudoBroadcastAddress(&addr->Ip4Address, the_local_network, the_local_network_mask));
#ifdef INET6
  case AF_INET6:
    return 0;
#endif
  default: return(0);
  }
}

/* ********************************* */

unsigned short _pseudoLocalAddress(HostAddr *addr,
				   u_int32_t *the_local_network,
				   u_int32_t *the_local_network_mask) {
  switch(addr->hostFamily) {
  case AF_INET:
    return (in_pseudoLocalAddress(&addr->Ip4Address, the_local_network, the_local_network_mask));
#ifdef INET6
  case AF_INET6:
    return (in6_pseudoLocalAddress(&addr->Ip6Address, NULL, NULL));
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

char *dotToSlash(char *name, char *buf, int buf_len ) {
  /*
   *  Convert a dotted quad ip address name a.b.c.d to a/b/c/d or a\b\c\d
   */
  char* localBuffer;
  int i;

  safe_snprintf(__FILE__, __LINE__, buf, buf_len, "%s", name);
  localBuffer = buf;

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
  char *flow, *buffer=NULL, *strtokState = NULL, *flows;

  flows = myGlobals.runningPref.flowSpecs;

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
      free(myGlobals.runningPref.flowSpecs);
      myGlobals.runningPref.flowSpecs = strdup("Error reading file");
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

          pcap_freecode(&fcode);
          newFlow = (FlowFilterList*)calloc(1, sizeof(FlowFilterList));

          if(newFlow == NULL) {
            if(buffer != NULL) free(buffer);
            traceEvent(CONST_TRACE_FATALERROR, "Fatal error: not enough memory. Bye!");
            exit(21); /* Just in case */
          } else {
            int i;

	    newFlow->fcode = (struct bpf_program*)calloc(myGlobals.numDevices, sizeof(struct bpf_program));

            for(i=0; i<myGlobals.numDevices; i++) {
              if(myGlobals.device[i].pcapPtr
		 && (!myGlobals.device[i].virtualDevice)
		 /* Fix courtesy of David Fabel <david.fabel@sudop.cz> */
		 ) {
		rc = pcap_compile(myGlobals.device[i].pcapPtr, &newFlow->fcode[i],
				  flowSpec, 1, myGlobals.device[i].netmask.s_addr);

		if(rc < 0) {
		  traceEvent(CONST_TRACE_WARNING, "Wrong flow specification \"%s\" (syntax error). "
			     "It has been ignored.", flowSpec);
		  free(newFlow);

		  /* Not used anymore */
		  free(myGlobals.runningPref.flowSpecs);
		  myGlobals.runningPref.flowSpecs = strdup("Error, wrong flow specification");
		  return;
		}
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

int getLocalHostAddress(struct in_addr *hostAddress, u_int8_t *netmask_v6, char* device) {
  int rc = 0;
#ifdef WIN32
  hostAddress->s_addr = GetHostIPAddr();
  return(0);
#else
  int fd, numHosts;
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

  if(ioctl(fd, SIOCGIFNETMASK, (char*)&ifr) >= 0) {
    sinAddr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    numHosts = 0xFFFFFFFF - ntohl(sinAddr->sin_addr.s_addr)+1;
  } else
    numHosts = 256; /* default C class */

  (*netmask_v6) = 0;

  while(numHosts > 0) {
    numHosts = numHosts >> 1;
    (*netmask_v6)++;
  }

  // traceEvent(CONST_TRACE_INFO, "DEBUG: Num subnet hosts: %d", numHosts);

  /* ******************************* */

  close(fd);
#endif

  return(rc);
}

/* ********************************* */

void maximize_socket_buffer(int sock_fd, int buf_type)  {
  int rcv_buffsize_base, rcv_buffsize, max_buf_size = 1024 * 2 * 1024 /* 2 MB */;
  socklen_t len = sizeof(rcv_buffsize_base);
  int i;

  if(getsockopt(sock_fd, SOL_SOCKET, buf_type, &rcv_buffsize_base, &len) < 0) {
    return;
  }
  for(i=2;; i++) {
    rcv_buffsize = i * rcv_buffsize_base;
    if(rcv_buffsize > max_buf_size) break;

    if(setsockopt(sock_fd, SOL_SOCKET, buf_type, &rcv_buffsize, sizeof(rcv_buffsize)) < 0) {
      break;
    }
  }
}

/* ********************************* */

#ifndef WIN32

/* *********** MULTITHREAD STUFF *********** */

int createThread(pthread_t *threadId,
		 void *(*__start_routine)(void *),
		 char* userParm) {
  int rc;

  rc = pthread_create(threadId, NULL, __start_routine, userParm);

  if(rc != 0)
    traceEvent(CONST_TRACE_NOISY, "THREADMGMT[t%lu]: pthread_create(), rc = %s(%d)",
	       (long unsigned int)threadId, strerror(rc), rc);
  myGlobals.numThreads++;
  return(rc);
}

/* ************************************ */

#undef _killThread
int _killThread(char *file, int line, pthread_t *threadId) {
  int rc;

  if(*threadId == 0) {
    traceEvent(CONST_NOISY_TRACE_LEVEL, file, line, "THREADMGMT: killThread(0) call...ignored");
    return(ESRCH);
  }

  if((rc = pthread_detach(*threadId)) != 0) {
    traceEvent(CONST_TRACE_NOISY, "THREADMGMT[t%lu]: pthread_detach(), rc = %s(%d)",
	       (long unsigned int)threadId, strerror(rc), rc);
  }

  myGlobals.numThreads--;
  return(rc);
}

/* ************************************ */

#undef _joinThread
int _joinThread(char *file, int line, pthread_t *threadId) {
  int rc;

  if(*threadId == 0) {
    /* traceEvent(CONST_NOISY_TRACE_LEVEL, file, line, "THREADMGMT: joinThread(0) call...ignored"); */
    return(0);
  }

  if((rc = pthread_join(*threadId, NULL)) != 0) {
    traceEvent(CONST_TRACE_NOISY, "THREADMGMT[t%lu]: pthread_join(), rc = %s(%d)",
	       (long unsigned int)threadId, strerror(rc), rc);
  }

  return(rc);
}

/* ************************************ */

#undef _createMutex
int _createMutex(PthreadMutex *mutexId, char* fileName, int fileLine) {
  int rc;

  memset(mutexId, 0, sizeof(PthreadMutex));

  if((rc = pthread_mutex_init(&(mutexId->mutex), NULL)) != 0) {
    traceEvent(CONST_TRACE_ERROR, "createMutex() call returned %s(%d) [t%lu m%p @%s:%d]",
               strerror(rc), rc, (long unsigned int)pthread_self(), 
	       (void*)&(mutexId->mutex), fileName, fileLine);
  } else if((rc = pthread_mutex_init(&(mutexId->statedatamutex), NULL)) != 0) {
    traceEvent(CONST_TRACE_ERROR, "createMutex() call2 returned %s(%d) [t%lu m%p @%s:%d]",
               strerror(rc), rc, (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
  } else {
    mutexId->isInitialized = 1;
#ifdef MUTEX_DEBUG
    traceEvent(CONST_TRACE_INFO, "MUTEX_DEBUG: createMutex() succeeded [t%lu m%p @%s:%d]",
               (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
#endif
  }

  return(rc);
}

/* ************************************ */

#undef _deleteMutex
void _deleteMutex(PthreadMutex *mutexId, char* fileName, int fileLine) {
  int rc;

  if(mutexId == NULL) {
    if(myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN)
      traceEvent(CONST_TRACE_ERROR, "deleteMutex() called with a NULL mutex [t%lu mNULL @%s:%d]",
                 (long unsigned int)pthread_self(), fileName, fileLine);
    return;
  }

  if(!mutexId->isInitialized) {
    if(myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN)
      traceEvent(CONST_TRACE_ERROR,
                 "deleteMutex() called with an UN-INITIALIZED mutex [t%lu m%p @%s:%d]",
                 (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
    return;
  }

  mutexId->isInitialized = 0;

  rc = pthread_mutex_unlock(&(mutexId->mutex));
#ifdef MUTEX_DEBUG
  traceEvent(CONST_TRACE_INFO, "MUTEX_DEBUG: deleteMutex() unlock (rc=%d) [t%lu m%p @%s:%d]",
             rc, (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
#endif
  rc = pthread_mutex_destroy(&(mutexId->mutex));
#ifdef MUTEX_DEBUG
  traceEvent(CONST_TRACE_INFO, "MUTEX_DEBUG: deleteMutex() destroy (rc=%d) [t%lu m%p @%s:%d]",
             rc, (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
#endif
  rc = pthread_mutex_unlock(&(mutexId->statedatamutex));
#ifdef MUTEX_DEBUG
  traceEvent(CONST_TRACE_INFO, "MUTEX_DEBUG: deleteMutex() #2 unlock (rc=%d) [t%lu m%p @%s:%d]",
             rc, (long unsigned int)pthread_self(), (void*)&(mutexId->statedatamutex), fileName, fileLine);
#endif
  rc = pthread_mutex_destroy(&(mutexId->statedatamutex));
#ifdef MUTEX_DEBUG
  traceEvent(CONST_TRACE_INFO, "MUTEX_DEBUG: deleteMutex() #2 destroy (rc=%d) [t%lu m%p @%s:%d]",
             rc, (long unsigned int)pthread_self(), (void*)&(mutexId->statedatamutex), fileName, fileLine);
#endif

  memset(mutexId, 0, sizeof(PthreadMutex));
}

/* ************************************ */

#undef _accessMutex
int _accessMutex(PthreadMutex *mutexId, char* where, char* fileName, int fileLine) {
  int rc;

  if(mutexId == NULL) {
    if(myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN)
      traceEvent(CONST_TRACE_ERROR,
                 "accessMutex() called '%s' with a NULL mutex [t%lu mNULL @%s:%d]",
                 where, (long unsigned int)pthread_self(), fileName, fileLine);
    return(-1);
  }

  pthread_mutex_lock(&(mutexId->statedatamutex));

  if(!mutexId->isInitialized) {
    pthread_mutex_unlock(&(mutexId->statedatamutex));
    if(myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN)
      traceEvent(CONST_TRACE_ERROR,
                 "accessMutex() called '%s' with an UN-INITIALIZED mutex [t%lu m%p @%s:%d]",
                 where, (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
    return(-1);
  }

#ifdef MUTEX_DEBUG
  traceEvent(CONST_TRACE_INFO, "MUTEX_DEBUG: accessMutex() called '%s' [t%lu m%p @%s:%d]",
             where, (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
#endif

  if(!myGlobals.runningPref.disableMutexExtraInfo) {
    if(mutexId->isLocked) {
      if((fileLine == mutexId->lock.line)
         && (strcmp(fileName, mutexId->lock.file) == 0)
         && (getpid() == mutexId->lock.pid)
         && (pthread_equal(mutexId->lock.thread, pthread_self()))) {
        traceEvent(CONST_TRACE_WARNING,
                   "accessMutex() called '%s' with a self-LOCKED mutex [t%lu m%p @%s:%d]",
                   where, (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
      }
    }
    setHolder(mutexId->attempt);
  }

  /* Do the try first so we can free the statedatamutex if we're going to lock */
  if((rc = pthread_mutex_trylock(&(mutexId->mutex))) == EBUSY) {
    pthread_mutex_unlock(&(mutexId->statedatamutex));
    rc = pthread_mutex_lock(&(mutexId->mutex));
    pthread_mutex_lock(&(mutexId->statedatamutex));
  }

  if(rc != 0) {
    traceEvent(CONST_TRACE_ERROR, "accessMutex() call '%s' failed (rc=%d/%s) [%p@%s:%d]",
               where, rc, strerror(rc), (void*)&(mutexId->mutex), fileName, fileLine);
  } else {

#ifdef MUTEX_DEBUG
    traceEvent(CONST_TRACE_INFO, "MUTEX_DEBUG: accessMutex() call '%s' succeeded [%p@%s:%d]",
	       where, (void*)&(mutexId->mutex), fileName, fileLine);
#endif

    mutexId->numLocks++;
    mutexId->isLocked = 1;
    if(!myGlobals.runningPref.disableMutexExtraInfo) {
      memcpy(&(mutexId->lock), &(mutexId->attempt), sizeof(Holder));
      memset(&(mutexId->attempt), 0, sizeof(Holder));
    }
  }

  pthread_mutex_unlock(&(mutexId->statedatamutex));

  return(rc);
}

/* ************************************ */

#undef _tryLockMutex
int _tryLockMutex(PthreadMutex *mutexId, char* where, char* fileName, int fileLine) {
  int rc;

  if(mutexId == NULL) {
    if(myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN)
      traceEvent(CONST_TRACE_ERROR,
                 "tryLockMutex() called '%s' with a NULL mutex [t%lu mNULL @%s:%d]",
                 where, (long unsigned int)pthread_self(), fileName, fileLine);
    return(-1);
  }

  pthread_mutex_lock(&(mutexId->statedatamutex));

  if(!mutexId->isInitialized) {
    pthread_mutex_unlock(&(mutexId->statedatamutex));
    if(myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN)
      traceEvent(CONST_TRACE_ERROR,
                 "tryLockMutex() called '%s' with an UN-INITIALIZED mutex [t%lu m%p @%s:%d]",
                 where, (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
    return(-1);
  }

#ifdef MUTEX_DEBUG
  traceEvent(CONST_TRACE_INFO, "MUTEX_DEBUG: tryLockMutex() called '%s' [t%lu m%p @%s:%d]",
             where, (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
#endif

  if(!myGlobals.runningPref.disableMutexExtraInfo) {
    if(mutexId->isLocked) {
      if((strcmp(fileName, mutexId->lock.file) == 0)
         && (fileLine == mutexId->lock.line)
         && (getpid() == mutexId->lock.pid)
         && (pthread_equal(mutexId->lock.thread, pthread_self()))
         ) {
        traceEvent(CONST_TRACE_WARNING,
                   "accessMutex() called '%s' with a self-LOCKED mutex [t%lu m%p @%s:%d]",
                   where, (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
      }
    }

    setHolder(mutexId->attempt);
  }

  /*
    Return code:

    0:    lock succesful
    EBUSY (mutex already locked)
  */
  rc = pthread_mutex_trylock(&(mutexId->mutex));

  if(rc == 0)  {
    mutexId->numLocks++;
    mutexId->isLocked = 1;
    if(!myGlobals.runningPref.disableMutexExtraInfo) {
      memcpy(&(mutexId->lock), &(mutexId->attempt), sizeof(Holder));
      memset(&(mutexId->attempt), 0, sizeof(Holder));
    }
  }

  pthread_mutex_unlock(&(mutexId->statedatamutex));

  return(rc);
}

/* ************************************ */

#undef _releaseMutex
int _releaseMutex(PthreadMutex *mutexId, char* fileName, int fileLine) {
  int rc;
  float lockDuration;

  if(mutexId == NULL) {
    if(myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN)
      traceEvent(CONST_TRACE_ERROR, "releaseMutex() called with a NULL mutex [t%lu mNULL @%s:%d]]",
                 (long unsigned int)pthread_self(), fileName, fileLine);
    return(-1);
  }

  pthread_mutex_lock(&(mutexId->statedatamutex));

  if(!mutexId->isInitialized) {

    pthread_mutex_unlock(&(mutexId->statedatamutex));

    if(myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN)
      traceEvent(CONST_TRACE_ERROR, "releaseMutex() called with an UN-INITIALIZED mutex [t%lu m%p @%s:%d]",
                 (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
    return(-1);
  }

  if(!mutexId->isLocked) {
    traceEvent(CONST_TRACE_WARNING, "releaseMutex() called with an UN-LOCKED mutex [t%lu m%p @%s:%d] last unlock [t%lu m%u @%s:%d]",
	       (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine,
               (long unsigned int)mutexId->unlock.thread, (int)mutexId->unlock.pid,
	       mutexId->unlock.file, mutexId->unlock.line);

  }

#ifdef MUTEX_DEBUG
  traceEvent(CONST_TRACE_INFO, "MUTEX_DEBUG: releaseMutex() releasing [t%lu m%p, @%s:%d]",
             (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
#endif
  rc = pthread_mutex_unlock(&(mutexId->mutex));

  if(rc != 0)
    traceEvent(CONST_TRACE_ERROR, "releaseMutex() failed (rc=%d/%s) [t%lu m%p, @%s:%d]",
               rc, strerror(rc), (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
  else {
    mutexId->isLocked = 0;
    mutexId->numReleases++;

    if(!myGlobals.runningPref.disableMutexExtraInfo) {

      setHolder(mutexId->unlock);
      lockDuration = timeval_subtract(mutexId->unlock.time, mutexId->lock.time);

      if((mutexId->maxLockedDuration < lockDuration)
         || (mutexId->max.line == 0 /* Never set */)) {
        memcpy(&(mutexId->max), &(mutexId->lock), sizeof(Holder));
        mutexId->maxLockedDuration = lockDuration;
      }
    }
  }


  pthread_mutex_unlock(&(mutexId->statedatamutex));

#ifdef MUTEX_DEBUG
  if (rc != 0)
    traceEvent(CONST_TRACE_WARNING, "MUTEX_DEBUG: releaseMutex() failed (rc=%d) [t%lu m%p @%s:%d]",
               (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), rc, fileName, fileLine);
  else
    traceEvent(CONST_TRACE_INFO, "MUTEX_DEBUG: releaseMutex() succeeded [t%lu m%p @%s:%d]",
               (long unsigned int)pthread_self(), (void*)&(mutexId->mutex), fileName, fileLine);
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

#endif /* WIN32 */

/* ************************************ */

#undef _lockExclusiveHostsHashMutex
int _lockExclusiveHostsHashMutex(HostTraffic *host, char *where, char *file, int line) {
  while(1) {
    _accessMutex(&myGlobals.hostsHashMutex[host->hostTrafficBucket], where, file, line);
    if(myGlobals.hostsHashMutexNumLocks[host->hostTrafficBucket] == 0)
      return(0);
    else
      _releaseMutex(&myGlobals.hostsHashMutex[host->hostTrafficBucket], file, line);

    sleep(1); /* Wait a bit */
  }

  return(0);
}

/* ************************************ */

#undef _unlockExclusiveHostsHashMutex
int _unlockExclusiveHostsHashMutex(HostTraffic *host, char *file, int line) {
  return(_releaseMutex(&myGlobals.hostsHashMutex[host->hostTrafficBucket], file, line));
}

/* ************************************ */

#undef _lockHostsHashMutex
int _lockHostsHashMutex(HostTraffic *host, char *where, char *file, int line) {
  int rc = 0;

  if(host) {
#if 0
    if(0)
      traceEvent(CONST_TRACE_INFO, "==> lockHostsHashMutex(idx=%d) [%s:%d]",
		 host->hostTrafficBucket, file, line);

    _accessMutex(&myGlobals.hostsHashLockMutex, "lockHostsHashMutex", file, line);

    if(myGlobals.hostsHashMutexNumLocks[host->hostTrafficBucket] == 0) {
      myGlobals.hostsHashMutexNumLocks[host->hostTrafficBucket]++;
      _accessMutex(&myGlobals.hostsHashMutex[host->hostTrafficBucket], where, file, line);
    } else {
      /* Already locked */
      myGlobals.hostsHashMutexNumLocks[host->hostTrafficBucket]++;
    }

    _releaseMutex(&myGlobals.hostsHashLockMutex, file, line);
#else
    _accessMutex(&myGlobals.hostsHashMutex[host->hostTrafficBucket], "_lockHostsHashMutex", file, line);
    myGlobals.hostsHashMutexNumLocks[host->hostTrafficBucket]++;
    _releaseMutex(&myGlobals.hostsHashMutex[host->hostTrafficBucket], file, line);
#endif
  } else {
    rc = -1;
  }

  return(rc);
}

/* ************************************ */

#undef _unlockHostsHashMutex
int _unlockHostsHashMutex(HostTraffic *host, char *file, int line) {
  int rc = 0;

  if(host) {
#if 0
    if(0)
      traceEvent(CONST_TRACE_INFO, "==> unlockHostsHashMutex(idx=%d) [%s:%d]",
		 host->hostTrafficBucket, file, line);

    accessMutex(&myGlobals.hostsHashLockMutex, "unlockHostsHashMutex");

    if(myGlobals.hostsHashMutexNumLocks[host->hostTrafficBucket] > 1) {
      myGlobals.hostsHashMutexNumLocks[host->hostTrafficBucket]--;
      rc = 0;
    } else if(myGlobals.hostsHashMutexNumLocks[host->hostTrafficBucket] == 1) {
      myGlobals.hostsHashMutexNumLocks[host->hostTrafficBucket]--;
      rc = releaseMutex(&myGlobals.hostsHashMutex[host->hostTrafficBucket]);
    } else {
      /* myGlobals.hostsHashMutexNumLocks[host->hostTrafficBucket] == 0 */
      traceEvent(CONST_TRACE_WARNING, "Error: attempting to unlock an unlocked mutex from %s:%d",
                 file, line);
      rc = 0;
    }

    releaseMutex(&myGlobals.hostsHashLockMutex);
#else
    _accessMutex(&myGlobals.hostsHashMutex[host->hostTrafficBucket], "_unlockHostsHashMutex", file, line);
    myGlobals.hostsHashMutexNumLocks[host->hostTrafficBucket]--;
    _releaseMutex(&myGlobals.hostsHashMutex[host->hostTrafficBucket], file, line);
#endif
  } else {
    rc = -1;
  }

  return(rc);
}

/* ************************************ */

int checkCommand(char* commandName) {
#ifndef WIN32
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
  rc = safe_snprintf(__FILE__, __LINE__, buf,
		     sizeof(buf),
		     "which %s 2>/dev/null",
		     commandName);
  if(rc < 0)
    return(0);

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

#endif

  return(0);

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
  return((char*)pcap_datalink_val_to_description(myGlobals.device[i].datalink));
}

/* ************************************ */

int getActualInterface(u_int deviceId) {
  if(myGlobals.runningPref.mergeInterfaces) {
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

  el->vlanId          = NO_VLAN;
  el->ifId            = NO_INTERFACE;
  el->known_subnet_id = UNKNOWN_SUBNET_ID;

  el->hostAS = 0;
  if (el->dnsDomainValue != NULL)      free(el->dnsDomainValue);
  el->dnsDomainValue = NULL;
  if (el->dnsTLDValue != NULL)         free(el->dnsTLDValue);
  el->dnsTLDValue = NULL;
  el->hostResolvedName[0] = '\0';
  el->hostResolvedNameType = FLAG_HOST_SYM_ADDR_TYPE_NONE;
  if (el->fingerprint != NULL)         free(el->fingerprint);
  el->fingerprint = NULL;
  if (el->nonIPTraffic != NULL)        free(el->nonIPTraffic);
  el->nonIPTraffic = NULL;
  if (el->routedTraffic != NULL)       free(el->routedTraffic);
  el->routedTraffic = NULL;
  if (el->portsUsage != NULL)          freePortsUsage(el);
  if (el->geo_ip)                      GeoIPRecord_delete(el->geo_ip);

  if (el->protoIPTrafficInfos != NULL) {
    int i;

    for(i=0; i<myGlobals.numIpProtosToMonitor; i++)
      if(el->protoIPTrafficInfos[i]) free(el->protoIPTrafficInfos[i]);

    free(el->protoIPTrafficInfos);
  }
  el->protoIPTrafficInfos = NULL;
  if (el->icmpInfo != NULL)            free(el->icmpInfo);
  el->icmpInfo = NULL;
  if (el->protocolInfo != NULL)        free(el->protocolInfo);
  el->protocolInfo = NULL;
  if(el->fcCounters != NULL) free(el->fcCounters);
  el->fcCounters = NULL;

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

  return((long)((delta_seconds * 1000000) + delta_microseconds));
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
  if(eventTraceLevel <= myGlobals.runningPref.traceLevel) {
    time_t theTime = time(NULL);
    struct tm t;
    char bufTime[LEN_TIMEFORMAT_BUFFER];
    char buf[LEN_HUGE_WORK_BUFFER];
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

    if(myGlobals.runningPref.traceLevel > CONST_NOISY_TRACE_LEVEL) {
      mFile = strdup(file);

      if(mFile) {
#ifdef WIN32
	for(beginFileIdx=strlen(mFile)-1; beginFileIdx>0; beginFileIdx--) {
	  // if(mFile[beginFileIdx] == '.') mFile[beginFileIdx] = '\0'; /* Strip off .c */
#if defined(WIN32)
	  if(mFile[beginFileIdx-1] == '\\') break;  /* Start after \ (Win32)  */
#else
	  if(mFile[beginFileIdx-1] == '/') break;   /* Start after / (!Win32) */
#endif
	}
#endif

	if(myGlobals.runningPref.traceLevel >= CONST_DETAIL_TRACE_LEVEL) {
#ifdef LONG_FORMAT
	  safe_snprintf(__FILE__, __LINE__, bufLineID, sizeof(bufLineID), "[t%lu %s:%d] ",
			(long unsigned int)pthread_self(), &mFile[beginFileIdx], line);
#else
	  safe_snprintf(__FILE__, __LINE__, bufLineID, sizeof(bufLineID), "[%s:%d] ",
			&mFile[beginFileIdx], line);
#endif

#if 0
	  /* Hash the message format into an id */
	  for (i=0; i<=strlen(format); i++) {
	    messageid = (messageid << 1) ^ max(0,format[i]-32);
	  }

	  /* 1st chars of file name for uniqueness */
	  messageid += (file[0]-32) * 256 + file[1]-32;
	  safe_snprintf(__FILE__, __LINE__, bufMsgID, sizeof(bufMsgID), "[MSGID%07d]", (messageid & 0x8fffff));
#endif
	}

	free(mFile);
      }
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
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s %s %s%s%s",
		  bufTime,
		  (myGlobals.runningPref.traceLevel >= CONST_DETAIL_TRACE_LEVEL) ? bufMsgID : "",
		  (myGlobals.runningPref.traceLevel > CONST_DETAIL_TRACE_LEVEL) ? bufLineID : "",
		  eventTraceLevel == CONST_FATALERROR_TRACE_LEVEL  ? "**FATAL_ERROR** " :
		  eventTraceLevel == CONST_ERROR_TRACE_LEVEL   ? "**ERROR** " :
		  eventTraceLevel == CONST_WARNING_TRACE_LEVEL ? "**WARNING** " : "",
		  bufMsg);

    /* Finished preparing message fields */

    if(myGlobals.ntopRunState < FLAG_NTOPSTATE_SHUTDOWN) {
      /* So, (INFO & above only) - post it to logView buffer. */
      if ((eventTraceLevel <= CONST_INFO_TRACE_LEVEL) &&
	  (myGlobals.logView != NULL)) {

	if(myGlobals.logViewMutex.isInitialized) {
#ifdef WIN32
	  WaitForSingleObject(myGlobals.logViewMutex.mutex, INFINITE);
#else
	  pthread_mutex_lock(&myGlobals.logViewMutex.mutex);
#endif
	}

	if (myGlobals.logView[myGlobals.logViewNext] != NULL)
	  free(myGlobals.logView[myGlobals.logViewNext]);

	myGlobals.logView[myGlobals.logViewNext] = strdup(buf);

	myGlobals.logViewNext = (myGlobals.logViewNext + 1) % CONST_LOG_VIEW_BUFFER_SIZE;

	if(myGlobals.logViewMutex.isInitialized) {
#ifdef WIN32
	  ReleaseMutex(myGlobals.logViewMutex.mutex);
#else
	  pthread_mutex_unlock(&myGlobals.logViewMutex.mutex);
#endif
	}
      }
    }

#ifdef WIN32
    /* If ntop is a Win32 service, we're done - we don't (yet) write to the
     * windows event logs and there's no console...
     *
     * If it's fatal, die, otherwise just return...
     *
     */
    if(eventTraceLevel == CONST_FATALERROR_TRACE_LEVEL)
      raise(SIGINT);
    if(isNtopAservice) return;
#endif

    /* Otherwise, we have two paths -
     *   Win32/no syslog headers/syslog not enabled via -L run time switch
     *      use: printf()
     *   Not Win32, Have syslog headers and enabled via -L run time switch
     *      use: syslog -
     */

#ifdef MAKE_WITH_SYSLOG
    if(myGlobals.runningPref.useSyslog == FLAG_SYSLOG_NONE) {
#endif

      printf("%s\n", buf);
      fflush(stdout);

#ifdef MAKE_WITH_SYSLOG
    } else {
      /* Skip over time - syslog() adds it automatically) */
      char *bufLog = &buf[strlen(bufTime)];

#ifdef FORPRENPTL
      accessMutex(&myGlobals.preNPTLlogMutex, "message");
#endif

      /* SYSLOG and set */
      if(myGlobals.runningPref.instance != NULL)
        openlog(myGlobals.runningPref.instance, LOG_PID, myGlobals.runningPref.useSyslog);
      else
        openlog(CONST_DAEMONNAME, LOG_PID, myGlobals.runningPref.useSyslog);

      /* syslog(..) call fix courtesy of Peter Suschlik <peter@zilium.de> */
#ifdef MAKE_WITH_LOG_XXXXXX
      switch(myGlobals.runningPref.traceLevel) {
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

#ifdef FORPRENPTL
      releaseMutex(&myGlobals.preNPTLlogMutex);
#endif

    }
#endif /* MAKE_WITH_SYSLOG */

  }

  va_end (va_ap);

  /* If it's fatal, die */
  if(eventTraceLevel == CONST_FATALERROR_TRACE_LEVEL)
    raise(SIGINT);

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

#ifndef WIN32
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
#endif

/* ********************************** */

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
  char tmpFileName[NAME_MAX];

  strcpy(tmpFileName, fileName);
  safe_snprintf(__FILE__, __LINE__, fileName, len, "%s-%lu", tmpFileName,
		myGlobals.numHandledRequests[0]+myGlobals.numHandledRequests[1]);
#else
  tmpnam(fileName);
#endif

  fd = fopen(fileName, "wb");

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

void stringSanityCheck(char* string, char* parm) {
  int i, j;

  if(string == NULL)  {
    traceEvent(CONST_TRACE_FATALERROR, "Invalid (empty) string specified for option %s", parm);
    exit(22); /* Just in case */
  }

  for(i=0, j=1; i<strlen(string); i++) {
    switch(string[i]) {
    case '%':
    case '\\':
      string[i]='.';
      j=0;
      break;
    }
  }

  if(j == 0) {
    if(strlen(string) > 20) string[20] = '\0';
    traceEvent(CONST_TRACE_ERROR, "Invalid string specified for option %s", parm);
    traceEvent(CONST_TRACE_INFO, "Sanitized value is '%s'", string);
    traceEvent(CONST_TRACE_FATALERROR, "Invalid option string, ntop shutting down...");
    exit(23); /* Just in case */
  }

  if((string[strlen(string)-1] == '/') ||
     (string[strlen(string)-1] == '\\')) {
    traceEvent(CONST_TRACE_WARNING, "Trailing slash removed from argument for option %s", parm);
    string[strlen(string)-1] = '\0';
  }
}

/* ************************** */

void uriSanityCheck(char* string, char* parm, int allowParms) {
  int i, j;

  //      Our reduced BNF is:
  //            relativeURI    = ["/" ] fsegment *( "/" segment )
  //            fsegment       = 1*pchar
  //            segment        = *pchar
  //
  //            pchar          = unreserved | ":" | "@" | "&" | "=" | "+"
  //            unreserved     = ALPHA | DIGIT | safe | extra | national
  //
  //            reserved       = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+"
  //                                    ^--- is legal character as segment sep.
  //            extra          = "!" | "*" | "'" | "(" | ")" | ","
  //            safe           = "$" | "-" | "_" | "."
  //            unsafe         = CTL | SP | <"> | "#" | "%" | "<" | ">"
  //            national       = <any OCTET excluding ALPHA, DIGIT,
  //                             reserved, extra, safe, and unsafe>
  //      And we look for reserved or unsafe chars.

  // If this is a URI which we allow parms in, then we add ? & to the valid chars
  // We add : as legal for Port specification

  if(string == NULL)  {
    traceEvent(CONST_TRACE_FATALERROR, "Invalid (empty) uri specified for option %s", parm);
    exit(24); /* Just in case */
  }

  for(i=0, j=1; i<strlen(string); i++) {
    if(string[i] <= ' ') {
      /* CTL | SP */
      string[i]='.';
      j = 0;
    } else switch(string[i]) {
    case ';':
    case '@':
    case '+':
    case '"':
    case '#':
    case '%':
    case '<':
    case '>':
    case '\\':  /* Add this one for directory traversal */
      string[i]='.';
      j=0;
      break;
    case '=':
    case '?':
    case '&':
      if(allowParms == FALSE) {
	string[i]='.';
	j=0;
      }
      break;
    }
  }

  if(j == 0) {
    if(strlen(string) > 40) string[40] = '\0';
    traceEvent(CONST_TRACE_ERROR, "Invalid uri specified for option %s", parm);
    traceEvent(CONST_TRACE_INFO, "Sanitized value is '%s'", string);
    traceEvent(CONST_TRACE_FATALERROR, "Invalid uri, ntop shutting down...");
    exit(25); /* Just in case */
  }
}

/* ************************** */

void pathSanityCheck(char* string, char* parm) {
  int i, j, k;

  static char paChar[256];

  // Common:
  //     Upper and lower case letters:  A - Z and a - z
  //     Numbers  0 - 9
  //     Period, underscore, hyphen  . _ -

  // Unix:
  //     Slash
  //     Comma

  // Win
  //     Backslash
  //     Colon, quotes, space

  if(string == NULL)  {
    traceEvent(CONST_TRACE_FATALERROR, "Invalid (empty) path specified for option %s", parm);
    exit(26); /* Just in case */
  }

  /* one time load of table */
  if(paChar['a'] != 1) {
    memset(&paChar, 0, sizeof(paChar));
    for(i='0'; i<='9'; i++) paChar[i]=1;
    for(i='A'; i<='Z'; i++) paChar[i]=1;
    for(i='a'; i<='z'; i++) paChar[i]=1;
    paChar['.']=1;
    paChar['_']=1;
    paChar['-']=1;
#ifdef WIN32
    paChar[' ']=1;
    paChar['\\']=1;
    paChar[':']=1;
#else
    paChar[',']=1;
    paChar['/']=1;
#endif
  }

  k=0;
#ifdef WIN32
  /* Strip "ed string for test */
  if((string[0] != '"') || (string[strlen(string)-1] != '"') )
    k=1;

	revertSlashIfWIN32(string, 0);
#endif


  for(i=k, j=1; i<strlen(string)-k; i++) {
    int idx = string[i];

    if(paChar[idx] == 0) {
      string[i]='.';
      j = 0;
    }
  }

  if(j == 0) {
    if(strlen(string) > 40) string[40] = '\0';
    traceEvent(CONST_TRACE_ERROR, "Invalid path/filename specified for option %s", parm);
    traceEvent(CONST_TRACE_INFO, "Sanitized value is '%s'", string);
    traceEvent(CONST_TRACE_FATALERROR, "Invalid path/filename, ntop shutting down...");
    exit(27); /* Just in case */
  }
}

/* ************************** */

void sanitize_rrd_string(char* name) {
  int i;

  /* Sanitize name for RRD */
  for(i=0; i<strlen(name); i++) {
    switch(name[i]) {
    case ' ':
    case ':':
      name[i] = '_';
    }
  }
}

/* ************************** */

int fileSanityCheck(char* string, char* parm, int nonFatal) {
  int i, j, k;

  static char fnChar[256];

  // Common:
  //     Upper and lower case letters:  A - Z and a - z
  //     Numbers  0 - 9
  //     Period, underscore, hyphen  . _ -

  // Unix:
  //     Comma

  // Win
  //     Colon, quotes, space

  if(string == NULL)  {
    if(nonFatal == 1) return(-1);

    traceEvent(CONST_TRACE_ERROR, "Invalid (empty) filename specified for option %s", parm);
    exit(28); /* Just in case */
  }

  /* one time load of table */
  if(fnChar['a'] != 1) {
    memset(&fnChar, 0, sizeof(fnChar));
    for(i='0'; i<='9'; i++) fnChar[i]=1;
    for(i='A'; i<='Z'; i++) fnChar[i]=1;
    for(i='a'; i<='z'; i++) fnChar[i]=1;
    fnChar['.']=1;
    fnChar['_']=1;
    fnChar['-']=1;
    fnChar['+']=1;
#ifdef WIN32
    fnChar[' ']=1;
    fnChar[':']=1;
#else
    fnChar[',']=1;
#endif
  }

  k=0;

  if(strlen(string) > 0) {
#ifdef WIN32
    /* Strip "ed string for test */
    if((string[0] != '"') || (string[strlen(string)-1] != '"') )
      k=1;
#endif

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Sanitizing string '%s'", string);
#endif

    for(i=k, j=1; i<strlen(string)-k; i++) {
      int idx = string[i];

      if(fnChar[idx] == 0) {
#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "Sanitized invalid char '%c'", idx);
#endif
	string[i]='.';
	j = 0;
      }
    }
  } else
    j = 0;

  if(j == 0) {
    if(strlen(string) > 40) string[40] = '\0';

    traceEvent(CONST_TRACE_ERROR, "Invalid filename specified for option %s", parm);
    traceEvent(CONST_TRACE_INFO, "Sanitized value is '%s'", string);
    if(nonFatal == 1) return(-1);
    exit(29); /* Just in case */
  }

  return(0);
}

/* ************************** */

int ipSanityCheck(char* string, char* parm, int nonFatal) {
  int i, j;
  static char ipChar[256];

  // Common:
  //     Numbers  0 - 9
  //     .
  //
  // INET6
  //     Upper and lower case letters:  A - Z and a - z
  //     :

  if(string == NULL)  {
    traceEvent(CONST_TRACE_WARNING, "Invalid (empty) path specified for option %s", parm);
    if(nonFatal == 1) return(-1);
    return(-1); /* LDE */
  }

  /* one time load of table */
  if(ipChar['0'] != 1) {
    memset(&ipChar, 0, sizeof(ipChar));
    for(i='0'; i<='9'; i++) ipChar[i]=1;
    ipChar['.']=1;
#ifdef INET6
    for(i='A'; i<='Z'; i++) ipChar[i]=1;
    for(i='a'; i<='z'; i++) ipChar[i]=1;
    ipChar[':']=1;
#endif
  }

  for(i=0, j=1; i<strlen(string); i++) {
    int idx = string[i];

    if(ipChar[idx] == 0) {
      string[i]='x';
      j = 0;
    }
  }

  if(j == 0) {
    if(strlen(string) > 40) string[40] = '\0';

    if(nonFatal == 1) return(-1);

    traceEvent(CONST_TRACE_ERROR, "Invalid ip address specified for option %s", parm);
    traceEvent(CONST_TRACE_INFO, "Sanitized value is '%s'", string);
    exit(30); /* Just in case */
  }

  return(0);
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
    exit(32); /* Just in case */
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

/* Development of the following routine was partly sponsored by an anonymous
 * multi-national corporation
 */

// ===============================================================================
// Better 'n the usual safe_snprintf(__FILE__, __LINE__, ) < 0) BufferTooShort() crud...

//    safe_snprintf(__FILE__, __LINE__, xxxxxFile, sizeof(xxxxxFile),
//                  "%s/xxxxx-%s",
//                  outputDirectory,
//                  timestamp);

int safe_snprintf(char* file, int line,
		  char* buf, size_t sizeofbuf,
		  char* format, ...) {
  va_list va_ap;
  int rc;

  va_start (va_ap, format);

  rc = vsnprintf(buf, sizeofbuf, format, va_ap);
  if(rc < 0)
    traceEvent(CONST_TRACE_ERROR, "Buffer too short @ %s:%d", file, line);
  else if(rc >= sizeofbuf) {
    traceEvent(CONST_TRACE_ERROR, "Buffer too short @ %s:%d (increase to at least %d)",
               file, line, rc);
    rc = 0 - rc;
  }

  va_end (va_ap);
  return(rc);
}

/* ******************************************************************************** */

// One that works like people expect it to
//  int strncat(char *dest, const char *src, size_t n);
//  Where it returns the final string length (-n if it won't fit) and
//  n is the size of the dest
int _safe_strncat(char* file, int line,
		  char* dest, size_t sizeofdest,
		  char* src) {
  int rc = strlen(dest) + strlen(src) + 1;

  if(rc > sizeofdest) {
    traceEvent(CONST_TRACE_ERROR, "strncat buffer too short @ %s:%d (increase to at least %d)",
               file, line, rc);
    return(0 - rc);
  }

  strncat(dest, src, (sizeofdest - strlen(dest) - 1));
  return(strlen(dest));
}


/* ************************ */

void fillDomainName(HostTraffic *el) {
  u_int i;

  if(theDomainHasBeenComputed(el))
    return;

  /* Reset values... */
  if(el->dnsDomainValue != NULL) free(el->dnsDomainValue);
  el->dnsDomainValue = NULL;
  if(el->dnsTLDValue != NULL) free(el->dnsTLDValue);
  el->dnsTLDValue = NULL;

  if((el->hostResolvedNameType != FLAG_HOST_SYM_ADDR_TYPE_NAME) ||
     (el->hostResolvedName    == NULL) ||
     (el->hostResolvedName[0] == '\0')) {
    /* Do NOT set FLAG_THE_DOMAIN_HAS_BEEN_COMPUTED - we still might learn the DNS Name later */
    return;
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
  else if((myGlobals.shortDomainName != NULL)
	  && (myGlobals.shortDomainName[0] != '\0')) {
    /* Walk back to the last . */
    i = strlen(myGlobals.shortDomainName)-1;
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

  setHostFlag(FLAG_THE_DOMAIN_HAS_BEEN_COMPUTED, el);

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

	  for(i=0; i<strlen(nbName); i++) {
	    if(isupper(nbName[i]))
	      nbName[i] = tolower(nbName[i]);
	  }

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
      setHostFlag(FLAG_HOST_TYPE_WORKSTATION, theHost);
    case 0x20: /* Server */
      setHostFlag(FLAG_HOST_TYPE_SERVER, theHost);
    case 0x1B: /* Master Browser */
      setHostFlag(FLAG_HOST_TYPE_MASTER_BROWSER, theHost);
    }
  }
}

/* ******************************************* */

static void addSessionInfo(SessionInfo *ptr, u_short ptr_len, HostAddr *theHost,
			   u_short thePort, char *notes) {
  int i;
  time_t timeoutTime = myGlobals.actTime - PARM_PASSIVE_SESSION_MINIMUM_IDLE;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Adding %ld:%d", theHost, thePort);
#endif

  if(ptr != NULL) {
    for(i=0; i<ptr_len; i++) {
      if((ptr[i].sessionPort == 0)
	 || (ptr[i].creationTime < timeoutTime)) {
	/* Autopurge */
	addrcpy(&ptr[i].sessionHost,theHost),
	  ptr[i].sessionPort = thePort,
	  ptr[i].creationTime = myGlobals.actTime;

	if(ptr[i].session_info != NULL) free(ptr[i].session_info);
	if(notes)
	  ptr[i].session_info = strdup(notes);
	else
	  ptr[i].session_info = NULL;
	break;
      }
    }

    if(i == ptr_len) {
      /* Slot Not found */
      static u_char is_hash_full = 0;

      if(!is_hash_full) {
	traceEvent(CONST_TRACE_INFO, "addSessionInfo: hash full [size=%d]", ptr_len);
	is_hash_full = 1;
      }
    }
  }
}

/* ******************************************* */

void addPassiveSessionInfo(HostAddr *theHost, u_short thePort, char *notes) {
  addSessionInfo(passiveSessions, passiveSessionsLen, theHost, thePort, notes);
}

/* ******************************************* */

void addVoIPSessionInfo(HostAddr *theHost, u_short thePort, char *notes) {
#ifdef DEBUG_VOIP
  traceEvent(CONST_TRACE_INFO, "DEBUG: addVoIPSessionInfo(%s:%d) [%s]",
	     addrtostr(theHost), thePort, notes);
#endif
  addSessionInfo(voipSessions, voipSessionsLen, theHost, thePort, notes);
}

/* ******************************************* */

static int isKnownSession(SessionInfo *ptr, u_short ptr_len,
			  HostAddr *theHost, u_short thePort, char **notes) {
  int i;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Searching for %ld:%d", theHost, thePort);
#endif

  (*notes) = NULL;

  if(ptr != NULL) {
    for(i=0; i<ptr_len; i++) {
      if((addrcmp(&ptr[i].sessionHost,theHost) == 0)
	 && (ptr[i].sessionPort == thePort)) {
	addrinit(&ptr[i].sessionHost);
	ptr[i].sessionPort = 0, ptr[i].creationTime = 0;
	(*notes) = ptr[i].session_info;

	/* NOTE: this memory will be freed by freeSessionInfo */
	ptr[i].session_info = NULL;

#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "DEBUG: Found session");
#endif
	return(1);
      }
    }
  }

  return(0);
}

/* ******************************************* */

int isPassiveSession(HostAddr *theHost, u_short thePort, char **notes) {
  return(isKnownSession(passiveSessions, passiveSessionsLen, theHost, thePort, notes));
}

/* ******************************************* */

int isVoIPSession(HostAddr *theHost, u_short thePort, char **notes) {
  int rc = isKnownSession(voipSessions, voipSessionsLen, theHost, thePort, notes);

#ifdef DEBUG_VOIP
  traceEvent(CONST_TRACE_INFO, "DEBUG: isVoipSession(%s:%d)=%d", addrtostr(theHost), thePort, rc);
#endif
  return(rc);
}

/* ******************************************* */

static void initSessionInfo(SessionInfo **ptr, u_short *ptr_len) {
  int len = sizeof(SessionInfo)*MAX_PASSIVE_FTP_SESSION_TRACKER;
  *ptr = (SessionInfo*)malloc(len);
  memset(*ptr, 0, len);
  *ptr_len = MAX_PASSIVE_FTP_SESSION_TRACKER;
}

/* ******************************************* */

void initPassiveSessions(void) {
  initSessionInfo(&passiveSessions, &passiveSessionsLen);
  initSessionInfo(&voipSessions, &voipSessionsLen);
}

/* ******************************* */

void termPassiveSessions(void) {
  if(passiveSessions) {
    free(passiveSessions);
    passiveSessions = NULL;
  }

  if(voipSessions) {
    free(voipSessions);
    voipSessions = NULL;
  }
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
  char* rsp = NULL;

  if(type == IPPROTO_TCP) {
    rsp = getPortByNumber(myGlobals.tcpSvc, port);
  } else {
    rsp = getPortByNumber(myGlobals.udpSvc, port);
  }

  return(rsp);
}

/* ******************************* */

char* getAllPortByNum(int port, char *outBuf, int outBufLen) {
  char* rsp = NULL;

  rsp = getPortByNumber(myGlobals.tcpSvc, port); /* Try TCP first... */
  if(rsp == NULL)
    rsp = getPortByNumber(myGlobals.udpSvc, port);  /* ...then UDP */

  if(rsp != NULL)
    return(rsp);
  else {
    safe_snprintf(__FILE__, __LINE__, outBuf, outBufLen, "%d", port);
    return(outBuf);
  }
}

/* ******************************* */

int getAllPortByName(char* portName) {
  int rsp = 0;

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
    safe_snprintf(__FILE__, __LINE__, icmpString, sizeof(icmpString), "%d", icmpType);
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
  traceEvent(CONST_TRACE_INFO, "DEBUG: incrementUsageCounter() @ %s:%d", file, line);
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

/* **************************************************** */

void checkUserIdentity(int userSpecified) {
  /*
    Code fragment below courtesy of
    Andreas Pfaller <apfaller@yahoo.com.au>
  */
#ifndef WIN32
  if((getuid() != geteuid()) || (getgid() != getegid())) {
    /* setuid binary, drop privileges */
    if((setgid(getgid()) != 0) || (setuid(getuid()) != 0)) {
      traceEvent(CONST_TRACE_FATALERROR, "Unable to drop privileges");
      exit(33); /* Just in case */
    }
  }

  /*
   * set user to be as inoffensive as possible
   */
  if(!setSpecifiedUser()) {
    if(userSpecified) {
      /* User located */
      if((myGlobals.userId != 0) || (myGlobals.groupId != 0)) {
	if((setgid(myGlobals.groupId) != 0) || (setuid(myGlobals.userId) != 0)) {
	  traceEvent(CONST_TRACE_FATALERROR, "Unable to change user");
	  exit(34); /* Just in case */
	}
      }
    } else {
      if((geteuid() == 0) || (getegid() == 0)) {
	if(!userSpecified) {
	  traceEvent(CONST_TRACE_ERROR, "For security reasons you cannot run ntop as root - aborting");
	  traceEvent(CONST_TRACE_INFO, "Unless you really, really, know what you're doing");
	  traceEvent(CONST_TRACE_INFO, "Please specify the user name using the -u option!");
	  traceEvent(CONST_TRACE_FATALERROR, "ntop shutting down for security reasons...");
	  exit(35); /* Just in case */
	} else {
	  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "For security reasons you should not run ntop as root (-u)!");
	}
      } else {
        setRunState(FLAG_NTOPSTATE_INITNONROOT);
	traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Now running as requested user... continuing with initialization");
      }
    }
  }
#endif
}

/* ******************************** */

#ifndef WIN32
#ifndef HAVE_LOCALTIME_R
#undef localtime

static PthreadMutex localtimeMutex;
static char localtimeMutexInitialized = 0;

struct tm *localtime_r(const time_t *t, struct tm *tp) {
  struct tm *theTime;

  if(!localtimeMutexInitialized) {
    createMutex(&localtimeMutex);
    localtimeMutexInitialized = 1;
  }
  accessMutex(&localtimeMutex, "localtime_r");

  theTime = localtime(t);

  if(theTime != NULL)
    memcpy(tp, theTime, sizeof(struct tm));
  else
    memset(tp, 0, sizeof(struct tm)); /* What shall I do ? */

  releaseMutex(&localtimeMutex);

  return(tp);
}
#endif
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

/* Based on the original Win32 code from  Wies-Software <wies@wiessoft.de> */

unsigned long _ntopSleepMSWhileSameState(char *file, int line, unsigned long ulDelay) {
  unsigned long ulSlice;
  short ntopRunStateSave;

  /* This probably isn't necessary -
   *  But: It keeps the responsiveness of the Win32 version in that environment
   *  And: Puts less load on non Win32 systems
   */
#ifdef WIN32
  ulSlice = 1000L; /* 1 Second */
#else
  ulSlice = 1000L * PARM_SLEEP_LIMIT;
#endif

  ntopRunStateSave = myGlobals.ntopRunState;

  traceEvent(CONST_BEYONDNOISY_TRACE_LEVEL, file, line, "ntopSleepMS(%lu)", ulDelay);

  while(ulDelay > 0L) {
    if(ulDelay < ulSlice)
      ulSlice = ulDelay;

#ifdef WIN32
    Sleep(ulSlice);
#else
    {
      struct timespec sleepAmount, remAmount;
      memset(&sleepAmount, 0, sizeof(sleepAmount));
      remAmount.tv_sec = (int)(ulSlice / 1000);
      remAmount.tv_nsec = (ulSlice - remAmount.tv_sec * 1000) * 1000L;
      while((remAmount.tv_sec > 0) || (remAmount.tv_nsec > 0)) {
        memcpy(&sleepAmount, &remAmount, sizeof(sleepAmount));
        memset(&remAmount, 0, sizeof(remAmount));

        traceEvent(CONST_BEYONDNOISY_TRACE_LEVEL, file, line,
		   "nanosleep({%d, %d}, )",
		   (int)sleepAmount.tv_sec,
		   (int)sleepAmount.tv_nsec);

        if((nanosleep(&sleepAmount, &remAmount) != 0) && (errno == EINTR)) {
          if(ntopRunStateSave != myGlobals.ntopRunState) {
            ulDelay = ulDelay - ulSlice + remAmount.tv_sec * 1000L + remAmount.tv_nsec / 1000L;
            traceEvent(CONST_BEYONDNOISY_TRACE_LEVEL, file, line, "ntopSleepMS() terminating due to runstate %lu remained", ulDelay);
            return(ulDelay);
          }

          continue;
        }
      }
    }
#endif /* WIN32 */

    ulDelay -= ulSlice;

    if(ntopRunStateSave != myGlobals.ntopRunState) {
      traceEvent(CONST_BEYONDNOISY_TRACE_LEVEL, file, line, "ntopSleepMS() terminating due to runstate %lu remained", ulDelay);
      break;
    }
  }

  return(ulDelay);
}

/* ----- */

unsigned int _ntopSleepWhileSameState(char *file, int line, unsigned int secs) {
  unsigned int rc;
  rc = _ntopSleepMSWhileSameState(file, line, 1000L*secs) / 1000L;
  return(rc);
}

/* ---------- */

void ntopSleepUntilStateRUN(void) {
  traceEvent(CONST_TRACE_BEYONDNOISY, "WAIT[t%lu]: for ntopState RUN", 
	     (long unsigned int)pthread_self());

  while(myGlobals.ntopRunState < FLAG_NTOPSTATE_RUN) {
#ifdef WIN32
    Sleep(250 /* ms */);
#else
    {
      struct timespec sleepAmount;
      memset(&sleepAmount, 0, sizeof(sleepAmount));
      sleepAmount.tv_sec = 0;
      sleepAmount.tv_nsec = 250000 /* ns */;
      nanosleep(&sleepAmount, NULL);
    }
#endif /* WIN32 */
  }

  traceEvent(CONST_TRACE_BEYONDNOISY, "WAIT[t%lu]: ntopState is RUN", 
	     (long unsigned int)pthread_self());
}

/* ---------- */


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

void escape(char *dest, int destLen, char *src) {
  int srcIdx, destIdx, len;

  memset(dest, 0, destLen);
  len = strlen(src);
  for (srcIdx = 0, destIdx = 0; srcIdx < len && destIdx < destLen; src++) {
    switch (src[srcIdx]) {
    case ' ':
      dest[destIdx++] = '+';
      break;
    default:
      dest[destIdx++] = src[srcIdx];
    }
  }
}

/* ******************************** */

void incrementTrafficCounter(TrafficCounter *ctr, Counter value) {
  if(value > 0)
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
    if(broadcastHost(el)
       || ((myGlobals.actTime-el->lastSeen) > PARM_HOST_PURGE_MINIMUM_IDLE_NOACTVSES))
      continue;
    else if (isFcHost (el) && (el->fcCounters->hostFcAddress.domain == FC_ID_SYSTEM_DOMAIN))
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


/* *************************************** */

void setHostFingerprint(HostTraffic *srcHost) {
  char *WIN, *MSS, *WSS, *ttl, *flags, *work;
  int S, N, D, T, done = 0, numEntries=0;
  char fingerprint[32];
  char *strtokState;

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

  safe_snprintf(__FILE__, __LINE__, fingerprint, sizeof(fingerprint)-1, "%s", srcHost->fingerprint);
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
  traceEvent(CONST_TRACE_INFO, "FINGERPRINT_DEBUG: WIN%s MSS%s ttl%s WSS%s S%d N%d D%d T%d FLAGS%s",
             WIN, MSS, ttl, WSS, S, N, D, T, flags);
#endif

  while(1) {
    char line[384], lineKey[8];
    char *b, *d, *ptr;
    datum key_data;
    datum data_data;

    safe_snprintf(__FILE__, __LINE__, lineKey, sizeof(lineKey), "%d", numEntries++);
    memset(&key_data, 0, sizeof(key_data));
    key_data.dptr = lineKey; key_data.dsize = strlen(key_data.dptr);

    data_data = gdbm_fetch(myGlobals.fingerprintFile, key_data);

    if(data_data.dptr != NULL) {
      if(data_data.dsize > sizeof(line)) data_data.dsize = sizeof(line);
      strncpy(line, data_data.dptr, data_data.dsize); line[data_data.dsize] = '\0';
      free(data_data.dptr);
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
      break;
    } else
      break; /* No more signatures */
  }

  if(!done) {
    /* Unknown fingerprint */
  unknownFingerprint: /* Empty OS name */
    srcHost->fingerprint[0] = ':', srcHost->fingerprint[1] = '\0';
  }
#ifdef FINGERPRINT_DEBUG
  else
    traceEvent(CONST_TRACE_INFO, "FINGERPRINT_DEBUG: match! %s [%d runs]",
	       srcHost->fingerprint, numEntries);
#endif
}

/* ******************************************
 *        For ntop_gdbm_xxxx see leaks.c
 * ****************************************** */

void handleWhiteBlackListAddresses(char* addresses,
                                   NetworkStats theNetworks[MAX_NUM_NETWORKS],
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
			  NetworkStats whiteNetworks[MAX_NUM_NETWORKS],
			  NetworkStats blackNetworks[MAX_NUM_NETWORKS],
			  u_short numWhiteNets, u_short numBlackNets) {
  int rc;
  struct in_addr workAddr;

  workAddr.s_addr = addr;

  if(numBlackNets > 0) {
    rc = __pseudoLocalAddress(&workAddr, blackNetworks, numBlackNets, NULL, NULL);
    if(rc == 1)
      return 2;
  }

  if(numWhiteNets > 0) {
    rc = __pseudoLocalAddress(&workAddr, whiteNetworks, numWhiteNets, NULL, NULL);
    return(1 - rc);
  }

  return(0 /* SAVE */);
}

/* ******************************** */

int setSpecifiedUser(void) {
#ifndef WIN32
  /*
   * set user to be as inoffensive as possible
   */
  /* user id specified on commandline */
  if((setgid(myGlobals.groupId) != 0) || (setuid(myGlobals.userId) != 0)) {
    traceEvent(CONST_TRACE_FATALERROR, "Unable to change user ID");
    exit(36); /* Just in case */
  }

  if((myGlobals.userId != 0) && (myGlobals.groupId != 0))
    setRunState(FLAG_NTOPSTATE_INITNONROOT);

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Now running as requested user '%s' (%d:%d)",
             myGlobals.effectiveUserName ? myGlobals.effectiveUserName : "<unknown>",
	     myGlobals.userId, myGlobals.groupId);

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

/* ************************************ */

u_int16_t getHostAS(HostTraffic *el) {
  return (el->hostAS);
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
  memcpy(a, b, sizeof(HostSerial));
  return(!a);
}

/* ********************************** */

void setEmptySerial(HostSerial *a) {
  memset(a, 0, sizeof(HostSerial));
}

/* ********************************* */

void addPortToList(HostTraffic *host, int *thePorts /* 0...MAX_NUM_RECENT_PORTS */, u_short port) {
  u_short i, found;

  if(port == 0)
    setHostFlag(FLAG_HOST_IP_ZERO_PORT_TRAFFIC, host);

  for(i = 0, found = 0; i<MAX_NUM_RECENT_PORTS; i++)
    if(thePorts[i] == port) {
      found = 1;
      break;
    }

  if(!found) {
    for(i = 0; i<(MAX_NUM_RECENT_PORTS-2); i++)
      thePorts[i] = thePorts[i+1];

    thePorts[MAX_NUM_RECENT_PORTS-1] = port;
  }
}

/* ************************************ */

#ifndef WIN32

void saveNtopPid(void) {
  FILE *fd;

  memset(&myGlobals.pidFileName, 0, sizeof(myGlobals.pidFileName));
  myGlobals.basentoppid = getpid();
  safe_snprintf(__FILE__, __LINE__, myGlobals.pidFileName, sizeof(myGlobals.pidFileName), "%s/%s",
		getuid() ?
		/* We're not root */ myGlobals.dbPath :
		/* We are root */ DEFAULT_NTOP_PID_DIRECTORY,
		DEFAULT_NTOP_PIDFILE);
  fd = fopen(myGlobals.pidFileName, "wb");

  if(fd == NULL) {
    traceEvent(CONST_TRACE_WARNING, "INIT: Unable to create pid file (%s)", myGlobals.pidFileName);
  } else {
    fprintf(fd, "%d\n", myGlobals.basentoppid);
    fclose(fd);
    traceEvent(CONST_TRACE_INFO, "INIT: Created pid file (%s)", myGlobals.pidFileName);
  }
}

/* ********************************** */

void removeNtopPid(void) {
  int rc;

  if(myGlobals.pidFileName[0] != '\0') {
    if((rc = unlink(myGlobals.pidFileName)) == 0) {
      traceEvent(CONST_TRACE_INFO, "TERM: Removed pid file (%s)", myGlobals.pidFileName);
    } else {
      traceEvent(CONST_TRACE_WARNING, "TERM: Unable to remove pid file (%s)", myGlobals.pidFileName);
    }
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


/* BStrauss - August 2003 - Check the flag and skip the call... */
int ntop_conditional_sched_yield(void) {

#ifdef MAKE_WITH_SCHED_YIELD
  if(!myGlobals.runningPref.disableSchedYield) {
    return(sched_yield());
  }
#endif

  return(0);
}

/* *************************************************** */

u_int numActiveNxPorts (u_int deviceId) {
  u_int numSenders = 0;
  HostTraffic *el;

  for(el=getFirstHost(deviceId);
      el != NULL; el = getNextHost(deviceId, el)) {
    if (isFcHost (el) && (el->fcCounters->hostFcAddress.domain == FC_ID_SYSTEM_DOMAIN))
      continue;
    else
      numSenders++;
  }

  return(numSenders);
}

/* *************************************** */

HostTraffic* findHostByFcAddress (FcAddress *fcAddr, u_short vsanId, u_int actualDeviceId) {
  HostTraffic *el;
  u_int idx = hashFcHost(fcAddr, vsanId, &el, actualDeviceId);

  if(el != NULL)
    return(el); /* Found */
  else if(idx == FLAG_NO_PEER)
    return(NULL);
  else
    el = myGlobals.device[actualDeviceId].hash_hostTraffic[idx];

  for(; el != NULL; el = el->next) {
    if (el->fcCounters != NULL) {
      if ((el->fcCounters->hostFcAddress.domain != 0) &&
	  (!memcmp(&el->fcCounters->hostFcAddress, fcAddr, LEN_FC_ADDRESS)) &&
	  (el->fcCounters->vsanId == vsanId))
	return(el);
    }
  }

  return(NULL);
}

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
  unsigned int f, n=0, m=0, x=0, y=0, prerc=0;
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
      f = sscanf(versionString, "%u.%u%1[a-z].%u", &n, &m, (char*)&l, &x);
      if(f >= 3) {
	if(l[0] > 0)
	  l[0] = tolower(l[0]) - 'a' + 1;
      } else {
        memset(&l, 0, sizeof(l));
	f = sscanf(versionString, "%u.%u.%u", &n, &m, &x);
	if (f <= 0) {
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
    if(myGlobals.runningPref.skipVersionCheck == TRUE) {
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
#define cNV2N(a, b)							\
  {									\
    unsigned int vv;							\
    vv = convertNtopVersionToNumber(a);					\
    if (vv != b)							\
      traceEvent(CONST_TRACE_INFO, "CHKVER_TEST: cNV2N %-10s -> %10u expected %10u", a, vv, b); \
    else								\
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
#define xmlextract(a) {				\
    a = strstr(next, "<" #a ">");		\
    if (a != NULL) {				\
      a += sizeof( #a ) + 1;			\
      if (strchr(a, '<') != NULL)		\
	strchr(a, '<')[0] = '\0';		\
    }						\
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
    closesocket(sock);
    return 1;
  }
#ifdef CHKVER_DEBUG
  traceEvent(CONST_TRACE_INFO, "CHKVER_DEBUG: Connected");
#endif

  userAgent=malloc(LEN_GENERAL_WORK_BUFFER);
  memset(userAgent, 0, LEN_GENERAL_WORK_BUFFER);
  safe_snprintf(__FILE__, __LINE__, userAgent, LEN_GENERAL_WORK_BUFFER, "ntop/%s", version);

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

  extractAndAppend(userAgent, LEN_GENERAL_WORK_BUFFER, "libpcap", (char*)pcap_lib_version());

#if defined(WIN32) && defined(__GNUC__)
  /* on mingw, gdbm_version not exported by library */
#else
  extractAndAppend(userAgent, LEN_GENERAL_WORK_BUFFER, "gdbm", gdbm_version);
#endif

#ifdef HAVE_OPENSSL
  extractAndAppend(userAgent, LEN_GENERAL_WORK_BUFFER, "openssl", (char*)SSLeay_version(0));
#endif

  extractAndAppend(userAgent, LEN_GENERAL_WORK_BUFFER, "zlib", (char*)zlibVersion());

  /* Special case for webPort+sslPort... */
  strncat(userAgent, " access/", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
#ifdef HAVE_OPENSSL
  if (myGlobals.runningPref.sslPort != 0) {
    if(myGlobals.runningPref.webPort != 0)
      strncat(userAgent, "both", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
    else
      strncat(userAgent, "https", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
  } else
#endif
    if(myGlobals.runningPref.webPort != 0)
      strncat(userAgent, "http", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
    else
      strncat(userAgent, "none", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));

  /* Special case for interfaces */
  strncat(userAgent, " interfaces(", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
  if(myGlobals.runningPref.devices != NULL) {
    strncat(userAgent, myGlobals.runningPref.devices,
            (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
  } else {
    strncat(userAgent, "null", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));
  }
  strncat(userAgent, ")", (LEN_GENERAL_WORK_BUFFER - strlen(userAgent) - 1));

  /* Not the 1st time?  Send uptime too */
  if((myGlobals.checkVersionStatusAgain > 0) &&
     (myGlobals.pcap_file_list == NULL)) {
    char small_buf[LEN_SMALL_WORK_BUFFER];

    memset(&small_buf, 0, sizeof(small_buf));
    safe_snprintf(__FILE__, __LINE__, small_buf,
		  LEN_SMALL_WORK_BUFFER, " uptime(%d)",
		  time(NULL)-myGlobals.initialSniffTime);

    strncat(userAgent, buf, (LEN_SMALL_WORK_BUFFER - strlen(userAgent) - 1));
  }

  safe_snprintf(__FILE__, __LINE__, buf, bufLen, "GET /%s HTTP/1.0\r\n"
		"Host: %s\r\n"
		"User-Agent: %s\r\n"
		"Accept: %s\r\n"
		"\r\n",
		versionFile,
		versSite,
		userAgent,
		CONST_HTTP_ACCEPT_ALL);

  free(userAgent);

  /* Send the request to server.  */
  traceEvent(CONST_TRACE_NOISY, "CHKVER: Sending request: %s", buf);
  rc = send(sock, buf, strlen(buf), 0);
  if (rc < 0) {
    traceEvent(CONST_TRACE_ERROR,
	       "CHKVER: Unable to send http request: %s(%d)", strerror(errno), errno);
    closesocket(sock);
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
    closesocket(sock);
    return 1;
  }

  if(rc >= bufLen) {
    traceEvent(CONST_TRACE_ERROR,
	       "CHKVER: Unable to receive entire http response (%d/%d)- skipping",
	       rc,
	       bufLen);
    closesocket(sock);
    return 1;
  }

#ifdef CHKVER_DEBUG
  traceEvent(CONST_TRACE_INFO, "CHKVER_DEBUG: Received %d bytes '%s'", rc, buf);
#endif

  closesocket(sock);
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
  char buf[LEN_HUGE_WORK_BUFFER];
  int rc=0, idx = 0;

  displayPrivacyNotice();

  for(idx = 0; versionSite[idx] != NULL; idx++) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	       "CHKVER: Checking current ntop version at %s/%s", 
	       versionSite[idx], CONST_VERSIONCHECK_DOCUMENT);
    
#ifdef CHKVER_DEBUG
    traceEvent(CONST_TRACE_INFO, "CHKVER_DEBUG: '%s' '%s'", 
	       versionSite[idx], CONST_VERSIONCHECK_DOCUMENT);
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

  if(fd != NULL) {
#ifdef MAKE_WITH_ZLIB
    if(compressedFormat)
      gzclose(fd);
    else
#endif
      fclose(fd);
  }

  if((logTag != NULL) && (*recordsRead > 0))
    traceEvent(CONST_TRACE_INFO, "%s: ...found %d lines", logTag, *recordsRead);

  return(-1);
}

/* ********************************** */

FILE* checkForInputFile(char* logTag, char* descr,
			char* fileName,	struct stat *dbStat,
			u_char* compressedFormat) {

  int configFileFound=FALSE, idx;
  char tmpFile[LEN_GENERAL_WORK_BUFFER];
  FILE* fd;
  struct tm t;
  char bufTime[LEN_TIMEFORMAT_BUFFER];

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
    safe_snprintf(__FILE__, __LINE__, tmpFile, sizeof(tmpFile),
		  "%s%c%s.gz",
		  myGlobals.configFileDirs[idx], CONST_PATH_SEP, fileName);
    if(logTag != NULL) traceEvent(CONST_TRACE_NOISY, "%s: Checking '%s'", logTag, tmpFile);
    fd = gzopen(tmpFile, "r");
    /* Note, if this code is inactive, fd is NULL from above, avoids fancy ifdefs */
#endif

    if(fd == NULL) {
      *compressedFormat = 0;
      safe_snprintf(__FILE__, __LINE__, tmpFile, sizeof(tmpFile),
		    "%s%c%s",
		    myGlobals.configFileDirs[idx], CONST_PATH_SEP, fileName);
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
      if(dbStat->st_ctime > dbStat->st_mtime)
        strftime(bufTime, sizeof(bufTime), CONST_LOCALE_TIMESPEC,
	         localtime_r(&(dbStat->st_ctime), &t));
      else
        strftime(bufTime, sizeof(bufTime), CONST_LOCALE_TIMESPEC,
  	         localtime_r(&(dbStat->st_mtime), &t));
      traceEvent(CONST_TRACE_NOISY, "%s: Database %s created/last modified %s", 
		 logTag, fileName, bufTime);
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

/* ************************************ */

static void updateGeoIP(HostTraffic *el) {
  if(el->hostNumIpAddress[0] != '\0') {
    if((el->geo_ip == NULL) && (myGlobals.geo_ip_db != NULL)) {
      accessMutex(&myGlobals.geolocalizationMutex, "GeoIP_record_by_addr");
      el->geo_ip = GeoIP_record_by_addr(myGlobals.geo_ip_db, el->hostNumIpAddress);
      releaseMutex(&myGlobals.geolocalizationMutex);

      if((el->hostAS == 0) && (myGlobals.geo_ip_asn_db != NULL)) {
	char *rsp = NULL;

	accessMutex(&myGlobals.geolocalizationMutex, "GeoIP_name_by_ipnum/v6");
	if(el->hostIpAddress.hostFamily == AF_INET)
	  rsp = GeoIP_name_by_ipnum(myGlobals.geo_ip_asn_db, el->hostIpAddress.Ip4Address.s_addr);
	else {
#ifdef INET6
#ifndef WIN32
	  rsp = GeoIP_name_by_ipnum_v6(myGlobals.geo_ip_asn_db, el->hostIpAddress.Ip6Address);
#endif
#endif
	}
	releaseMutex(&myGlobals.geolocalizationMutex);

	if(rsp != NULL) {
	  /* Example: AS20959 This AS Number will be used by the Datacom Network. */
	  char *name;

	  name = strchr(rsp, ' ');
	  el->hostAS = atoi(&rsp[2]);
	  if(name) el->hostASDescr = strdup(&name[1]);
	  free(rsp);
	}
      }
    }
  }
}

/* ********************************************* */

void _setResolvedName(HostTraffic *el, char *updateValue, short updateType, char* file, int line) {
  int i;

  updateGeoIP(el);

  if(updateValue[0] == '\0') return;

  /* Do not update 0 -> DNS */
  if((updateType == FLAG_HOST_SYM_ADDR_TYPE_NAME) &&
     (el->hostResolvedNameType == 0))
    return;

  /* Only update if this is a MORE important type */
  if(updateType > el->hostResolvedNameType) {

#ifdef CMPFCTN_DEBUG
    if(myGlobals.runningPref.debugMode == 1)
      traceEvent(CONST_TRACE_INFO,
                 "CMPFCTN_DEBUG: setResolvedName(0x%08x) %d %s -> %d %s - %s(%d)",
                 el,
                 el->hostResolvedNameType,
                 el->hostResolvedName,
                 updateType,
                 updateValue,
                 file, line);
#endif

    if (updateType == FLAG_HOST_SYM_ADDR_TYPE_FC_WWN) {
      safe_snprintf(__FILE__, __LINE__, el->hostResolvedName,
		    sizeof(el->hostResolvedName),
		    fcwwn_to_str ((u_int8_t*)updateValue));
      el->hostResolvedName[LEN_WWN_ADDRESS_DISPLAY] = '\0';
    } else {
      safe_snprintf(__FILE__, __LINE__, el->hostResolvedName, 
		    sizeof(el->hostResolvedName), "%s", updateValue);
    }

    // el->hostResolvedName[MAX_LEN_SYM_HOST_NAME-1] = '\0';
    /* Really needed ? */
    for(i=0; el->hostResolvedName[i] != '\0'; i++)
      el->hostResolvedName[i] = tolower(el->hostResolvedName[i]);

    el->hostResolvedNameType = updateType;
  }

  setHostCommunity(el);
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
      } else if(((*a)->hostResolvedNameType != FLAG_HOST_SYM_ADDR_TYPE_FCID)
		&& ((*a)->hostResolvedNameType != FLAG_HOST_SYM_ADDR_TYPE_FC_WWN)
		&& ((*a)->hostResolvedNameType != FLAG_HOST_SYM_ADDR_TYPE_FC_ALIAS)
		&& ((*a)->hostResolvedNameType != FLAG_HOST_SYM_ADDR_TYPE_FAKE)) {
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
      } else if ((((*a)->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_FCID)
		  || ((*a)->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_FC_WWN)
		  || ((*a)->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_FC_ALIAS))) {
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

#ifdef CMPFCTN_DEBUG
  traceEvent(CONST_TRACE_INFO, "CMPFCTN_DEBUG: cmpFctn(): %s rc=%d", debugCmpFctn, rc);
#endif

  return(rc);
}
/* ************************************ */

static char x2c(char *what) {
  char digit;

  digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
  digit *= 16;
  digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
  return(digit);
}

/* ******************************* */

void unescape_url(char *url) {
  int x,y;

  for(x=0, y=0; url[y]; ++x, ++y) {
    if((url[x] = url[y]) == '%') {
      url[x] = x2c(&url[y+1]);
      y += 2;
    } else if(url[x] == '+')
      url[x] = ' ';
  }

  url[x] = '\0';
}

/* ******************************************* */

void revertSlashIfWIN32(char *str, int mode) {
#ifdef WIN32
  int i;

  for(i=0; str[i] != '\0'; i++)
    switch(mode) {
    case 0:
      if(str[i] == '/') str[i] = '\\';
      //else if(str[i] == ' ') str[i] = '_';
      break;
    case 1:
      if(str[i] == '\\') str[i] = '/';
      break;
    }
#endif
}

/* ******************************************* */

void revertDoubleColumnIfWIN32(char *str) {
#ifdef WIN32
  int i, j;
  char str1[512];

  for(i=0, j=0; str[i] != '\0'; i++) {
    if(str[i] == ':') {
      str1[j++] = '\\';
      str1[j++] = str[i];
    } else {
      str1[j++] = str[i];
    }
  }

  str1[j] = '\0';
  strcpy(str, str1);
#endif
}


/* ******************************************* */

/* Subtract the `struct timeval' values X and Y */

float timeval_subtract (struct timeval x, struct timeval y) {
  return((float)((long int) x.tv_sec * 1000000 +
		 (long int) x.tv_usec -
		 (long int) y.tv_sec * 1000000 -
		 (long int) y.tv_usec) / 1000000.0);
}

/* ************************************ */

void freePortsUsage(HostTraffic *el) {
  PortUsage *act, *next;

  if(el->portsUsage == NULL) return;

  act = el->portsUsage;
  while(act) {
    next = act->next;
    free(act);
    act = next;
  }
  el->portsUsage = NULL;
}

/* ************************************ */

static PortUsage* allocatePortUsage(void) {
  PortUsage *ptr;

#ifdef DEBUG
  printf("DEBUG: allocatePortUsage() called\n");
#endif

  ptr = (PortUsage*)calloc(1, sizeof(PortUsage));
  
  if(ptr)
    setEmptySerial(&ptr->clientUsesLastPeer), setEmptySerial(&ptr->serverUsesLastPeer);

  return(ptr);
}

/* ************************************ */

/* Chain looks like this:
 *     el(portsUsage) -> PortUsage -> PortUsage -> NULL
 *
 * Here, we:
 * 1. Scan list upto found/end/port > what we care about
 * 2. (not found and createIfNecessary), allocate new one and insert
 *    into chain, thus keeping the list sorted.
 */
PortUsage* getPortsUsage(HostTraffic *el, u_int portIdx, int createIfNecessary) {
  PortUsage *ports, *prev = NULL, *newPort;

  accessMutex(&myGlobals.portsMutex, "getPortsUsage");

  ports = el->portsUsage;

  while((ports != NULL) && (ports->port < portIdx)) {
    prev = ports;
    ports = ports->next;
  }

  if(ports && (ports->port == portIdx)) {
    releaseMutex(&myGlobals.portsMutex);
    return(ports); /* Found */
  }
  
  if(!createIfNecessary) {
    releaseMutex(&myGlobals.portsMutex);
    return(NULL);
  }

  newPort = allocatePortUsage();
  newPort->port = portIdx;

  if(el->portsUsage == NULL) {
    /* Previously empty chain */
    el->portsUsage = newPort;
  } else if (ports == el->portsUsage) {
    /* 1st in chain */
    newPort->next = el->portsUsage;
    el->portsUsage = newPort;
  } else {
    /* Insert in chain */
    newPort->next = prev->next;
    prev->next = newPort;
  }

  releaseMutex(&myGlobals.portsMutex);
  return(newPort);
}

/* *************************************************** */

void setHostFlag(int flag_value, HostTraffic *host) {
  if(!FD_ISSET(flag_value, &host->flags)) {
    FD_SET(flag_value, &host->flags);
    notifyEvent(hostFlagged, host, NULL, flag_value);
  }
}

/* *************************************************** */

void clearHostFlag(int flag_value, HostTraffic *host) {
  if(FD_ISSET(flag_value, &host->flags)) {
    FD_CLR(flag_value, &host->flags);
    notifyEvent(hostUnflagged, host, NULL, flag_value);
  }
}

/* *************************************************** */

char* vlan2name(u_int16_t vlanId, char *buf, int buf_len) {
  char key[64];

  snprintf(key, sizeof(key), "vlan.%d", vlanId);

  if(fetchPrefsValue(key, buf, buf_len) == -1) {
    snprintf(buf, sizeof(buf), "%d", vlanId);
  }

  return(buf);
}

/* ******************************************* */

void mkdir_p(char *tag, char *path, int permission) {
  int i, rc = 0;

  if(path == NULL) {
    traceEvent(CONST_TRACE_ERROR, "%s: mkdir(null) skipped", tag);
    return;
  }

  revertSlashIfWIN32(path, 0);

  /* Start at 1 to skip the root */
  for(i=1; path[i] != '\0'; i++)
    if(path[i] == CONST_PATH_SEP) {
#ifdef WIN32
      /* Do not create devices directory */
      if((i > 1) && (path[i-1] == ':')) continue;
#endif

      path[i] = '\0';
#if RRD_DEBUG >= 3
      if(strcmp(tag, "RRD") == 0)
        traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: calling mkdir(%s)", path);
#endif
      rc = ntop_mkdir(path, permission);
      if((rc != 0) && (errno != EEXIST) )
	traceEvent(CONST_TRACE_WARNING, "RRD: [path=%s][error=%d/%s]",
		   path,
		   errno,
		   strerror(errno));
      path[i] = CONST_PATH_SEP;
    }

#if RRD_DEBUG >= 2
  if(strcmp(tag, "RRD") == 0)
    traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: calling mkdir(%s)", path);
#endif
  ntop_mkdir(path, permission);

  if((rc != 0) && (errno != EEXIST) )
    traceEvent(CONST_TRACE_WARNING, "%s: mkdir(%s), error %d %s",
               tag,
	       path,
	       errno,
	       strerror(errno));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* * * * * * * * * * * * * * * * * * */

#if !defined(WIN32)
// Use our version instead of the sometimes available GNU extension...
char *ntop_strsignal(int sig) {
  return(sig == SIGHUP ? "SIGHUP"
         : sig == SIGINT ? "SIGINT"
         : sig == SIGQUIT ? "SIGQUIT"
         : sig == SIGILL ? "SIGILL"
         : sig == SIGABRT ? "SIGABRT"
         : sig == SIGFPE ? "SIGFPE"
         : sig == SIGKILL ? "SIGKILL"
         : sig == SIGSEGV ? "SIGSEGV"
         : sig == SIGPIPE ? "SIGPIPE"
         : sig == SIGALRM ? "SIGALRM"
         : sig == SIGTERM ? "SIGTERM"
         : sig == SIGUSR1 ? "SIGUSR1"
         : sig == SIGUSR2 ? "SIGUSR2"
         : sig == SIGCHLD ? "SIGCHLD"
#ifdef SIGCONT
         : sig == SIGCONT ? "SIGCONT"
#endif
#ifdef SIGSTOP
         : sig == SIGSTOP ? "SIGSTOP"
#endif
#ifdef SIGBUS
         : sig == SIGBUS ? "SIGBUS"
#endif
#ifdef SIGSYS
         : sig == SIGSYS ? "SIGSYS"
#endif
#ifdef SIGXCPU
         : sig == SIGXCPU ? "SIGXCPU"
#endif
#ifdef SIGXFSZ
         : sig == SIGXFSZ ? "SIGXFSZ"
#endif
	 : "unable to determine");
}
#endif


#ifndef HAVE_STRCASESTR
char *
strcasestr (char *haystack, char *needle)
{
  char *p, *startn = 0, *np = 0;

  for (p = haystack; *p; p++) {
    if (np) {
      if (toupper(*p) == toupper(*np)) {
	if (!*++np)
	  return startn;
      } else
	np = 0;
    } else if (toupper(*p) == toupper(*needle)) {
      np = needle + 1;
      startn = p;
    }
  }

  return 0;
}
#endif
