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

#include "ntop.h"

/* Global */
static char hex[] = "0123456789ABCDEF";

/* Forward */
static u_int _ns_get16(const u_char *src);
static int _ns_name_ntop(const u_char *src,
			 char *dst, size_t dstsiz);
static int _dn_skipname(const u_char *ptr, const u_char *eom); /* forward */
static int _ns_name_uncompress(const u_char *msg,
			       const u_char *eom, const u_char *src,
			       char *dst, size_t dstsiz);
static int _ns_name_unpack(const u_char *msg,
			  const u_char *eom, const u_char *src,
			  u_char *dst, size_t dstsiz);
static void updateDeviceHostNameInfo(HostAddr addr, char* symbolic, int actualDeviceId, int type);
static void updateHostNameInfo(HostAddr addr, char* symbolic, int type);

/* #define DNS_DEBUG */
/* #define MDNS_DEBUG  */

typedef struct hostAddrList {
  HostAddr addr;
  struct hostAddrList *next, *prev;
} HostAddrList;

static HostAddrList *hostAddrList_head = NULL, *hostAddrList_tail = NULL;

typedef struct {
  time_t dump_date;
  char hostname[MAX_LEN_SYM_HOST_NAME];
} HostNameCache;

/* **************************************************** */

void cacheHostName(HostAddr *addr, char* symbolic) {
  HostNameCache name;
  datum data_data, key_data;

  accessMutex(&myGlobals.serialLockMutex, "cacheHostName");

  name.dump_date = myGlobals.actTime;
  safe_snprintf(__FILE__, __LINE__, name.hostname, sizeof(name.hostname), "%s", symbolic);

  key_data.dptr = (char*)addr, key_data.dsize = sizeof(HostAddr);
  data_data.dptr = (char*)&name, data_data.dsize = (int)(strlen(name.hostname)+sizeof(name.dump_date)+1);

  if(gdbm_store(myGlobals.resolverCacheFile, key_data, data_data, GDBM_REPLACE) != 0)
    traceEvent(CONST_TRACE_ERROR, "While adding host name %s", symbolic);

  // traceEvent(CONST_TRACE_INFO, "Cached host name %s", symbolic);

  releaseMutex(&myGlobals.serialLockMutex);
}

/* **************************************************** */

char* getHostNameFromCache(HostAddr *addr, char *buf, u_int buf_len) {
  char *ret;
  datum return_data, key_data;

  accessMutex(&myGlobals.serialLockMutex, "getHostNameFromCache");

  key_data.dptr = (char*)addr, key_data.dsize = sizeof(HostAddr);
  return_data = gdbm_fetch(myGlobals.resolverCacheFile, key_data);

  if(return_data.dptr != NULL) {
    HostNameCache *dump = (HostNameCache*)return_data.dptr;

    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "%s", dump->hostname);
    free(return_data.dptr);
    ret = buf;
  } else {
    /* Not found */
    ret = NULL;
  }

  releaseMutex(&myGlobals.serialLockMutex);

  // traceEvent(CONST_TRACE_INFO, "Resolved %s", ret ? ret : "<none>");

  return(ret);
}

/* **************************************** */

void initAddressResolution(void) {
  createCondvar(&myGlobals.queueAddressCondvar);
}

/* **************************************** */

static void updateDeviceHostNameInfo(HostAddr addr, char* symbolic, int actualDeviceId, int type) {
  HostTraffic *el;

  if(myGlobals.ntopRunState > FLAG_NTOPSTATE_RUN) return;

  /* Search the instance and update its name */

  for(el=getFirstHost(actualDeviceId); el != NULL; el = getNextHost(actualDeviceId, el)) {
    if(addrcmp(&el->hostIpAddress, &addr) == 0) {
      accessAddrResMutex("updateHostNameInfo");

      if(el != NULL) {
	unsigned short i;

	if(strlen(symbolic) >= (MAX_LEN_SYM_HOST_NAME-1))
	  symbolic[MAX_LEN_SYM_HOST_NAME-2] = '\0';

	/* Really needed ? */
	for(i=0; i<strlen(symbolic); i++) symbolic[i] = tolower(symbolic[i]);

	/* traceEvent(CONST_TRACE_INFO, "[%s] --> %s", el->hostResolvedName, symbolic); */

	setResolvedName(el, symbolic, type);
      }

      releaseAddrResMutex();
    }
  }
}

/* **************************************** */

static void updateHostNameInfo(HostAddr addr, char* symbolic, int type) {
  int i;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "updateDeviceHostNameInfo(%s <--> %s)", symbolic, addrtostr(&addr));
#endif

  cacheHostName(&addr, symbolic);

  for(i=0; i<myGlobals.numDevices; i++) {
    if(!myGlobals.device[i].virtualDevice)
      updateDeviceHostNameInfo(addr, symbolic, i, type);
  }
}

/* ************************************ */

static void queueAddress(HostAddr elem) {
  HostAddrList *cloned = NULL;

  if(myGlobals.runningPref.numericFlag == noDnsResolution) return;
  if(_pseudoLocalAddress(&elem, NULL, NULL)) {
    /* Local Host */
    if(myGlobals.runningPref.trackOnlyLocalHosts) return;
    else if(myGlobals.runningPref.numericFlag == dnsResolutionForLocalRemoteOnly) return;
  } else {
    /* Remote Host */
    if(myGlobals.runningPref.numericFlag == dnsResolutionForLocalHostsOnly) return;
  }

  accessAddrResMutex("queueAddress");

  if(myGlobals.addressQueuedCurrent > 16384) {
    myGlobals.addressUnresolvedDrops++;
  } else {
    /* First check if the address we want to resolve is already in queue 
       waiting to be resolved */
    HostAddrList *head = hostAddrList_head;

    while(head != NULL) {
      if(memcmp(&head->addr, &elem, sizeof(elem)) == 0) {
	releaseAddrResMutex();
	return;
      }

      head = head->next;
    }

#ifdef DEBUG
    traceEvent(CONST_TRACE_ERROR, "queueAddress(%s)", addrtostr(&elem));
#endif

    if((cloned = (HostAddrList*)calloc(1, sizeof(HostAddrList))) != NULL) {
      memcpy(&cloned->addr, &elem, sizeof(HostAddr));
      if(hostAddrList_head) hostAddrList_head->prev = cloned;
      cloned->next = hostAddrList_head, cloned->prev = NULL;
      hostAddrList_head = cloned;

      if(hostAddrList_tail == NULL)
	hostAddrList_tail = cloned; /* First element of the list */

      signalCondvar(&myGlobals.queueAddressCondvar, 0);
      myGlobals.addressQueuedCurrent++;
      if(myGlobals.addressQueuedCurrent > myGlobals.addressQueuedMax)
	myGlobals.addressQueuedMax = myGlobals.addressQueuedCurrent;
    }
  }

  releaseAddrResMutex();
}

/* ************************************ */

static void processAddressResRequest(HostAddrList *elem) {
  if(elem) {
    struct hostent *he = NULL;
    int family, size;
    char theAddr[64];
#if defined(HAVE_GETHOSTBYADDR_R)
    struct hostent _hp, *__hp;
    char buffer[4096]; /* It MUST be 4096 as otherwise on Linux will fail */
#endif

    memset(theAddr, 0, sizeof(theAddr));
    addrget(&elem->addr, theAddr, &family, &size);

#if defined(HAVE_GETHOSTBYADDR_R)
#ifdef SOLARIS
    he = gethostbyaddr_r((const char*)theAddr, size,
			 family, &_hp,
			 buffer, sizeof(buffer),
			 &h_errno);
#else
#if 0
    traceEvent(CONST_TRACE_INFO, "About to resolve %s [family=%d][size=%d]", addrtostr(&elem->addr), family, size);
#endif
    if(gethostbyaddr_r((const char*)theAddr, size,
		       family, &_hp,
		       buffer, sizeof(buffer),
		       &__hp, &h_errno) == 0) {

      if(h_errno == 0)
	he = &_hp;
      else
	he = NULL;
    } else
      he = NULL;
#endif
#else
    he = gethostbyaddr(theAddr, size, family);
#endif

    if((he != NULL) && (he->h_name != NULL)) {
      updateHostNameInfo(elem->addr, he->h_name, FLAG_HOST_SYM_ADDR_TYPE_NAME);
      accessAddrResMutex("dequeueAddress"); myGlobals.resolvedAddresses++; releaseAddrResMutex();
    } else {
#if 0
      traceEvent(CONST_TRACE_ERROR, "Address resolution failure [%d][%s]", h_errno, hstrerror(h_errno));
#endif
      accessAddrResMutex("dequeueAddress"); myGlobals.failedResolvedAddresses++; releaseAddrResMutex();
    }

    memset(elem, 0, sizeof(HostAddr));
    free(elem);
  }
}

/* ************************************ */

static void* dequeueNextAddress(void) {
  HostAddrList *elem;

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Waiting for address to resolve...");
#endif

    while(hostAddrList_tail == NULL) {
      if(myGlobals.ntopRunState > FLAG_NTOPSTATE_RUN) break;
      waitCondvar(&myGlobals.queueAddressCondvar);
    }

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Address resolution started...");
#endif

    accessAddrResMutex("dequeueAddress");

    if(hostAddrList_tail != NULL) {
      elem = hostAddrList_tail;
      hostAddrList_tail = hostAddrList_tail->prev;

      if(hostAddrList_head == elem)
	hostAddrList_head = NULL;

      if(elem->prev != NULL)
	elem->prev->next = NULL;

      if(myGlobals.addressQueuedCurrent > 0) myGlobals.addressQueuedCurrent--;
    } else
      elem = NULL;

    releaseAddrResMutex();

    return(elem);
}

/* ************************************ */

void* dequeueAddress(void *_i) {
  int dqaIndex = (int)((long)_i);
  HostAddrList *elem;

  traceEvent(CONST_TRACE_INFO,
	     "THREADMGMT[t%lu]: DNSAR(%d): Address resolution thread running",
             (long unsigned int)pthread_self(), dqaIndex+1);

  while(myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN) {
    elem = dequeueNextAddress();
    processAddressResRequest(elem);
  } /* endless loop */

  myGlobals.dequeueAddressThreadId[dqaIndex] = 0;

  /* We're shutting down so let'e empty the queue */
  do {    
    elem = dequeueNextAddress();
    
    if(elem != NULL)
      free(elem);
  } while(elem != NULL);
  
  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: DNSAR(%d): Address resolution thread terminated [p%d]",
             (long unsigned int)pthread_self(), dqaIndex+1,
#ifndef WIN32
	     getpid()
#else
	     0
#endif
	     );

  return(NULL);
}

/* ************************************ */

void cleanupAddressQueue(void) {
  /* Nothing to do */
}

/* ************************************ */

char* _intop(struct in6_addr *addr, char *buf, u_short buflen) {
  char *ret = (char *)inet_ntop(AF_INET6, addr, buf, buflen);
  return(ret);
}

/* ************************************ */

char* intop(struct in6_addr *addr) {
  static char  ntop_buf[INET6_ADDRSTRLEN+1];

  memset(ntop_buf, 0, INET6_ADDRSTRLEN);
  return (char *)_intop(addr, ntop_buf,sizeof(ntop_buf));
}

/* ************************************ */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoa(struct in_addr addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr.s_addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr.s_addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ************************************ */

char* intoa(struct in_addr addr) {
  static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

  return(_intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

char* addrtostr(HostAddr *addr) {
  if (addr == NULL)
    return NULL;
  switch(addr->hostFamily) {
  case AF_INET:
    return(char *)(intoa(addr->Ip4Address));
  case AF_INET6:
    return(char *)(intop(&addr->Ip6Address));
  default: return("???");
  }
}

/* ************************************ */

char * _addrtostr(HostAddr *addr, char* buf, u_short bufLen) {
  if (addr == NULL)
    return NULL;
  switch(addr->hostFamily) {
  case AF_INET:
    return (_intoa(addr->Ip4Address,buf,bufLen));
  case AF_INET6:
    return (_intop(&addr->Ip6Address,buf,bufLen));
  default: return("???");
  }
}

/* ************************************ */

char * _addrtonum(HostAddr *addr, char* buf, u_short bufLen) {
  if((addr == NULL) || (buf == NULL))
    return NULL;

  switch(addr->hostFamily) {
  case AF_INET:
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "%u", addr->Ip4Address.s_addr);
    break;
  case AF_INET6:
    if(_intop(&addr->Ip6Address, buf, bufLen) == NULL)
      BufferTooSmall(buf, bufLen);
    break;
  default:
    return("???");
  }

  return(buf);
}

/* ******************************* */

/* This function automatically updates the instance name */
void ipaddr2str(HostTraffic *el, HostAddr hostIpAddress,
		short vlanId, u_int actualDeviceId) {
  HostTraffic *h;

  if(((hostIpAddress.hostFamily == AF_INET) && (hostIpAddress.addr._hostIp4Address.s_addr == 0))
     || (el->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_NAME))
    return;

  h = findHostByNumIP(hostIpAddress, vlanId, actualDeviceId);

  if((el != NULL) && (h != NULL)
     /* && (el != h) */
     && (h->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_NAME)
     && (h->hostNumIpAddress[0] != '\0')
     && strcmp(h->hostNumIpAddress, h->hostResolvedName)
     && strcmp(h->hostResolvedName, "0.0.0.0")) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_ERROR, "Recycling %s = %s ", addrtostr(&hostIpAddress), el->hostResolvedName);
#endif
    strcpy(el->hostResolvedName, h->hostResolvedName), el->hostResolvedNameType = h->hostResolvedNameType;
  } else if(getHostNameFromCache(&el->hostIpAddress, el->hostResolvedName, sizeof(el->hostResolvedName)) != NULL) {
    el->hostResolvedNameType = FLAG_HOST_SYM_ADDR_TYPE_NAME;
  } else
    queueAddress(hostIpAddress);
}

/* ************************************ */

char* etheraddr_string(const u_char *ep, char *buf) {
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
	  ep[0] & 0xFF, ep[1] & 0xFF,
	  ep[2] & 0xFF, ep[3] & 0xFF,
	  ep[4] & 0xFF, ep[5] & 0xFF);
  return (buf);
}

/* ************************************ */

char* llcsap_string(u_char sap) {
  char *cp;
  static char buf[sizeof("sap 00")];

  cp = buf;
  strncpy(cp, "sap ", sizeof(buf));
  cp += strlen(cp);
  *cp++ = hex[sap >> 4 & 0xf];
  *cp++ = hex[sap & 0xf];
  *cp++ = '\0';

  /* traceEvent(CONST_TRACE_INFO, "%s", buf); */
  return(buf);
}

/* ************************************ */

/*
  The FDDI code below has been grabbed from
  tcpdump
*/

static u_char fddi_bit_swap[] = {
  0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
  0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
  0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
  0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
  0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4,
  0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
  0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec,
  0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
  0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
  0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
  0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea,
  0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
  0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6,
  0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
  0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
  0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
  0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1,
  0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
  0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9,
  0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
  0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
  0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
  0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed,
  0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
  0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3,
  0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
  0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
  0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
  0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7,
  0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
  0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef,
  0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff,
};

void extract_fddi_addrs(struct fddi_header *fddip, char *fsrc, char *fdst)
{
  int i;

  for (i = 0; i < 6; ++i)
    fdst[i] = fddi_bit_swap[fddip->dhost[i]];
  for (i = 0; i < 6; ++i)
    fsrc[i] = fddi_bit_swap[fddip->shost[i]];
}

/* ************************************ */

static u_int _ns_get16(const u_char *src) {
  u_int dst;

  NS_GET16(dst, src);
  return (dst);
}

/* ************************************ */

int printable(int ch) {
  return (ch > 0x20 && ch < 0x7f);
}

/* ************************************ */

static int special(int ch) {
  switch (ch) {
  case 0x22: /* '"' */
  case 0x2E: /* '.' */
  case 0x3B: /* ';' */
  case 0x5C: /* '\\' */
    /* Special modifiers in zone files. */
  case 0x40: /* '@' */
  case 0x24: /* '$' */
    return (1);
  default:
    return (0);
  }
}

/* ************************************ */

static int _ns_name_ntop(const u_char *src,
			 char *dst, size_t dstsiz) {
  const u_char *cp;
  char *dn, *eom;
  u_char c;
  u_int n;
  static char digits[] = "0123456789";

  cp = src;
  dn = dst;
  eom = dst + dstsiz;

  while ((n = *cp++) != 0) {
    if ((n & NS_CMPRSFLGS) != 0) {
      /* Some kind of compression pointer. */
      errno = EMSGSIZE;
      return (-1);
    }
    if (dn != dst) {
      if (dn >= eom) {
	errno = EMSGSIZE;
	return (-1);
      }
      *dn++ = '.';
    }
    if (dn + n >= eom) {
      errno = EMSGSIZE;
      return (-1);
    }
    for (; n > 0; n--) {
      c = *cp++;
      if (special(c)) {
	if (dn + 1 >= eom) {
	  errno = EMSGSIZE;
	  return (-1);
	}
	*dn++ = '\\';
	*dn++ = (char)c;
      } else if (!printable(c)) {
	if (dn + 3 >= eom) {
	  errno = EMSGSIZE;
	  return (-1);
	}
	*dn++ = '\\';
	*dn++ = digits[c / 100];
	*dn++ = digits[(c % 100) / 10];
	*dn++ = digits[c % 10];
      } else {
	if (dn >= eom) {
	  errno = EMSGSIZE;
	  return (-1);
	}
	*dn++ = (char)c;
      }
    }
  }
  if (dn == dst) {
    if (dn >= eom) {
      errno = EMSGSIZE;
      return (-1);
    }
    *dn++ = '.';
  }
  if (dn >= eom) {
    errno = EMSGSIZE;
    return (-1);
  }
  *dn++ = '\0';
  return((int)(dn - dst));
}

/* ************************************ */

static char* _res_skip_rr(char *cp, char *eom) {
  int tmp;
  int dlen;

  if ((tmp = _dn_skipname((u_char *)cp, (u_char *)eom)) == -1)
    return (NULL);			/* compression error */
  cp += tmp;
  if ((cp + RRFIXEDSZ) > eom)
    return (NULL);
  cp += INT16SZ;	/* 	type 	*/
  cp += INT16SZ;	/* 	class 	*/
  cp += INT32SZ;	/* 	ttl 	*/
  dlen = _ns_get16((u_char*)cp);
  cp += INT16SZ;	/* 	dlen 	*/
  cp += dlen;
  if (cp > eom)
    return (NULL);
  return (cp);
}

/* ************************************ */

static int dn_expand_(const u_char *msg, const u_char *eom, const u_char *src,
		      char *dst, int dstsiz) {
  int n = _ns_name_uncompress(msg, eom, src, dst, (size_t)dstsiz);

  if (n > 0 && dst[0] == '.')
    dst[0] = '\0';
  return (n);
}

/* ************************************ */

static int _ns_name_unpack(const u_char *msg,
			  const u_char *eom, const u_char *src,
			  u_char *dst, size_t dstsiz) {
  const u_char *srcp, *dstlim;
  u_char *dstp;
  int n, len, checked;

  len = -1;
  checked = 0;
  dstp = dst;
  srcp = src;
  dstlim = dst + dstsiz;
  if (srcp < msg || srcp >= eom) {
    errno = EMSGSIZE;
    return (-1);
  }
  /* Fetch next label in domain name. */
  while ((n = *srcp++) != 0) {
    /* Check for indirection. */
    switch (n & NS_CMPRSFLGS) {
    case 0:
      /* Limit checks. */
      if (dstp + n + 1 >= dstlim || srcp + n >= eom) {
	errno = EMSGSIZE;
	return (-1);
      }
      checked += n + 1;
      *dstp++ = n;
      memcpy(dstp, srcp, n);
      dstp += n;
      srcp += n;
      break;

    case NS_CMPRSFLGS:
      if (srcp >= eom) {
	errno = EMSGSIZE;
	return (-1);
      }

      if (len < 0)
	len = (int)(srcp - src + 1);
      srcp = msg + (((n & 0x3f) << 8) | (*srcp & 0xff));
      if (srcp < msg || srcp >= eom) {  /* Out of range. */
	errno = EMSGSIZE;
	return (-1);
      }
      checked += 2;
      /*
       * Check for loops in the compressed name;
       * if we've looked at the whole message,
       * there must be a loop.
       */
      if (checked >= eom - msg) {
	errno = EMSGSIZE;
	return (-1);
      }
      break;

    default:
      errno = EMSGSIZE;
      return (-1); /* flag error */
    }
  }
  *dstp = '\0';
  if (len < 0)
    len = (int)(srcp - src);
  return (len);
}

/* ************************************ */

static int _ns_name_uncompress(const u_char *msg,
			      const u_char *eom, const u_char *src,
			      char *dst, size_t dstsiz) {
  u_char tmp[NS_MAXCDNAME];
  int n;

  if ((n = _ns_name_unpack(msg, eom, src, tmp, sizeof tmp)) == -1)
    return (-1);
  if (_ns_name_ntop(tmp, dst, dstsiz) == -1)
    return (-1);
  return (n);
}

/* ************************************ */

static int _ns_name_skip(const u_char **ptrptr, const u_char *eom) {
  const u_char *cp;
  u_int n;

  cp = *ptrptr;
  while (cp < eom && (n = *cp++) != 0) {
    /* Check for indirection. */
    switch (n & NS_CMPRSFLGS) {
    case 0:			/* normal case, n == len */
      cp += n;
      continue;
    case NS_CMPRSFLGS:	/* indirection */
      cp++;
      break;
    default:		/* illegal type */
      errno = EMSGSIZE;
      return (-1);
    }
    break;
  }
  if (cp > eom) {
    errno = EMSGSIZE;
    return (-1);
  }
  *ptrptr = cp;
  return (0);
}

/* ************************************ */

static int _dn_skipname(const u_char *ptr, const u_char *eom) {
  const u_char *saveptr = ptr;

  if (_ns_name_skip(&ptr, eom) == -1)
    return (-1);
  return((int)(ptr - saveptr));
}

/* ************************************ */

static void msdns_filter_name(char *msg) {
  int i, j, max = (int)strlen(msg);

  for(i=0, j=0; i<max; i++) {
#ifdef MDNS_DEBUG
    if(0) traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: [i=%d][%c][%d]", i, msg[i], msg[i]);
#endif

    if(msg[i] != '\\') {
      if(msg[i] > 0) /* FIX: can we do better? */
	msg[j++] = msg[i];
    } else {
      char tmpStr[8], tmpStr2[8];
      int id;

      if((msg[i+1] >= '0') && (msg[i+1] <= '9')) {
#ifdef MDNS_DEBUG
	if(0){
	  traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: [i=%d][%c][%d]", i+1, msg[i+1], msg[i+1]);
	  traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: [i=%d][%c][%d]", i+2, msg[i+2], msg[i+2]);
	  traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: [i=%d][%c][%d]", i+3, msg[i+3], msg[i+3]);
	}
#endif

	tmpStr[0] = msg[i+1];
	tmpStr[1] = msg[i+2];
	tmpStr[2] = msg[i+3];
	tmpStr[3] = '\0';

	id = atoi(tmpStr);

	if(id == 128)
	  msg[j++] = '\'';
	else if(id < 128) {
	  safe_snprintf(__FILE__, __LINE__, tmpStr2, sizeof(tmpStr2), "%c", id);
	  msg[j++] = tmpStr2[0];
	}

	i += 3;
      } else {
	i++;
	msg[j++] = msg[i];
      }
    }
  }

  msg[j] = '\0';
}

/* ************************************ */

static char* _res_skip(char *msg,
		      int numFieldsToSkip,
		      char *eom) {
  char *cp;
  HEADER *hp;
  int tmp;
  int n;

  /*
   * Skip the header fields.
   */
  hp = (HEADER *)msg;
  cp = msg + HFIXEDSZ;

  /*
   * skip question records.
   */
  n = (int)ntohs((unsigned short int)hp->qdcount);
  if (n > 0) {
    while (--n >= 0 && cp < eom) {
      tmp = _dn_skipname((u_char *)cp, (u_char *)eom);
      if (tmp == -1) return(NULL);
      cp += tmp;
      cp += INT16SZ;	/* type 	*/
      cp += INT16SZ;	/* class 	*/
    }
  }
  if (--numFieldsToSkip <= 0) return(cp);

  /*
   * skip myGlobals.authoritative answer records
   */
  n = (int)ntohs((unsigned short int)hp->ancount);
  if (n > 0) {
    while (--n >= 0 && cp < eom) {
      cp = _res_skip_rr(cp, eom);
      if (cp == NULL) return(NULL);
    }
  }
  if (--numFieldsToSkip == 0) return(cp);

  /*
   * skip name server records
   */
  n = (int)ntohs((unsigned short int)hp->nscount);
  if (n > 0) {
    while (--n >= 0 && cp < eom) {
      cp = _res_skip_rr(cp, eom);
      if (cp == NULL) return(NULL);
    }
  }
  if (--numFieldsToSkip == 0) return(cp);

  /*
   * skip additional records
   */
  n = (int)ntohs((unsigned short int)hp->arcount);
  if (n > 0) {
    while (--n >= 0 && cp < eom) {
      cp = _res_skip_rr(cp, eom);
      if (cp == NULL) return(NULL);
    }
  }

  return(cp);
}

/* ************************************ */

void setHostName(HostTraffic *srcHost, char *name) {
  u_short tmpStrLen = min(strlen(name), MAX_LEN_SYM_HOST_NAME);
  strncpy(srcHost->hostResolvedName, name, tmpStrLen);
  srcHost->hostResolvedName[tmpStrLen] = '\0';
}

/* ************************************ */

//#define MDNS_DEBUG

static void handleMdnsName(HostTraffic *srcHost, u_short sport, u_char *mdns_name) {
  char *mdnsStrtokState, *name = NULL, *appl = NULL, *proto = NULL, *domain = NULL;
  char *tmpStr = strdup((char*)mdns_name);

  if(tmpStr != NULL) {
    msdns_filter_name(tmpStr);
    /* S's Music._daap._tcp.localcal */

#ifdef MDNS_DEBUG
    traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: (1) [%s]", tmpStr);
#endif

    name = strtok_r(tmpStr, "._", &mdnsStrtokState);
    if(name) {
      appl = strtok_r(NULL, "._", &mdnsStrtokState);
      if(appl) {
	proto = strtok_r(NULL, "._", &mdnsStrtokState);
	if(proto) {
	  domain = strtok_r(NULL, "._", &mdnsStrtokState);
	}
      }
    }

    if((domain != NULL)
       && ((!strcmp(domain, "local"))
	   || (!strcmp(domain, "localafpovertcp"))
	   )) {

#ifdef MDNS_DEBUG
    traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: (2) [%s] [%s][%s][%s][%s]",
	       srcHost->hostNumIpAddress,
	       name, appl, proto, domain);
#endif

      if((!strcmp(appl, "ipp")) || (!strcmp(appl, "printer"))) {
	/* Printer */
	setHostFlag(FLAG_HOST_TYPE_PRINTER, srcHost);
	setHostName(srcHost, name);
      } else if(!strcmp(appl, "afpovertcp")) {
	/* Sharing name under MacOS */
	setHostName(srcHost, name);
      } else if(!strcmp(appl, "workstation")) {
	/* Host name under MacOS */
	setHostName(srcHost, strtok(name, "["));
      } else if(!strcmp(appl, "http")) {
	/* HTTP server */
	setHostFlag(FLAG_HOST_TYPE_SVC_HTTP, srcHost);
      } else if(!strcmp(appl, "daap")) {
	/* Digital Audio Access Protocol (daap.sourceforge.net) */
	updateHostUsers(name, BITFLAG_DAAP_USER, srcHost);
      }
    } else if(name && appl && (!strcmp(appl, "local"))) {
      setHostName(srcHost, name);
    }

     free(tmpStr);
  }
}

/* ************************************ */
/*
   This function needs to be rewritten from scratch
   as it does not check boundaries (see ** below)
*/

u_int16_t handleDNSpacket(HostTraffic *srcHost, u_short sport,
			  const u_char *ipPtr,
			  DNSHostInfo *hostPtr,
			  short length,
			  short *isRequest,
			  short *positiveReply) {
  querybuf      answer;
  u_char	*cp = NULL;
  char		**aliasPtr;
  u_char	*eom = NULL, *bp;
  char		**addrPtr;
  int		type=0, class, queryType = T_A;
  int		qdcount, ancount, arcount, nscount=0, buflen;
  int		origClass=0;
  int		numAliases = 0;
  int		numAddresses = 0;
  int		i;
  int		len;
  int		dlen;
  char		haveAnswer;
  short     addr_list_idx=0;
  char		printedAnswers = FALSE;
  char *host_aliases[MAX_ALIASES];
  int   host_aliases_len[MAX_ALIASES], n;
  u_char  hostbuf[4096];
  char *addr_list[MAX_ADDRESSES + 1];
  u_int16_t transactionId, flags;

  /* Never forget to copy the buffer !!!!! */
  cp = (u_char*)(ipPtr);
  memcpy(&transactionId, cp, 2); transactionId = ntohs(transactionId);
  memcpy(&flags, &cp[2], 2); flags = ntohs(flags);

  /* reset variables */
  memset(host_aliases, 0, sizeof(host_aliases));
  memset(host_aliases_len, 0, sizeof(host_aliases_len));
  memset(hostbuf, 0, sizeof(hostbuf));
  memset(addr_list, 0, sizeof(addr_list));

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "id=0x%X - flags=0x%X", transactionId, flags);
#endif

  if(length > sizeof(answer))
    length = sizeof(answer);

  memset(&answer, 0, sizeof(answer));
  memcpy(&answer, ipPtr, length);

  *isRequest = (short)!(flags & 0x8000);
  *positiveReply = (short)!(flags & 0x0002);

  if(answer.qb1.rcode != 0 /* NOERROR */) {
    return(transactionId);
  }

  /*
    Don't change it to eom = (u_char *)(&answer+length);
    unless you want to core dump !
  */
#if 0
  eom = (u_char *)(ipPtr+length);
#else
  eom = (u_char *) &answer + length;
#endif

  qdcount = (int)ntohs((unsigned short int)answer.qb1.qdcount);
  ancount = (int)ntohs((unsigned short int)answer.qb1.ancount);
  arcount = (int)ntohs((unsigned short int)answer.qb1.arcount);
  nscount = (int)ntohs((unsigned short int)answer.qb1.nscount);

  /*
   * If there are no answer, n.s. or additional records
   * then return with an error.
   */
  if (ancount == 0 && nscount == 0 && arcount == 0) {
    return(transactionId);
  }

  bp	   = hostbuf;
  buflen   = sizeof(hostbuf);
  cp	   = (u_char *) &answer+HFIXEDSZ;

  /* Process first question section. */
  if (qdcount-- > 0) {
    n = (short)dn_expand_(answer.qb2, eom, cp, hostPtr->queryName, MAXDNAME);
    if (n<0)
      return(transactionId);
    cp += n;
    if (cp + INT16SZ >eom)
      return(transactionId);
    hostPtr->queryType = GetShort(cp);
    cp += INT16SZ;
    if (cp > eom)
      return(transactionId);
  }

  /* Skip over rest of question section. */
  while (qdcount-- > 0) {
    n = (short)_dn_skipname(cp, eom);
    if (n < 0)
      return(transactionId);
    cp += n + QFIXEDSZ;
    if (cp > eom)
      return(transactionId);
  }

  aliasPtr	= host_aliases;
  addrPtr	= addr_list;
  haveAnswer	= FALSE;

  while (--ancount >= 0 && cp < eom) {
    n = (short)dn_expand_(answer.qb2, eom, cp, (char *)bp, buflen);
    if (n < 0)
      return(transactionId);
    cp += n;
    if (cp + 3 * INT16SZ + INT32SZ > eom)
      return(transactionId);
    type  = GetShort(cp);
    class = GetShort(cp);
    cp   += INT32SZ;	/* skip TTL */
    dlen  = GetShort(cp);
    if (cp + dlen > eom)
      return(transactionId);
    if (type == T_CNAME) {
      /*
       * Found an alias.
       */
      cp += dlen;
      if (aliasPtr >= &host_aliases[MAX_ALIASES-1]) {
		continue;
      }
      *aliasPtr++ = (char *)bp;
      n = (short)strlen((char *)bp) + 1;
      host_aliases_len[numAliases] = n;
      numAliases++;
      bp += n;
      buflen -= n;
      continue;
    } else if (type == T_PTR) {
      /*
       * Found a "pointer" to the real name.
       *
       * E.g. : 89.10.67.213.in-addr.arpa
       *
       */
      char *a, *b, *c, *d, dnsBuf[128], *strtokState = NULL;
      unsigned long theDNSaddr;

      len = (int)strlen((char*)bp);

      if(bp[0] == '_') {
	/* Multicast DNS */

	n = (short)dn_expand_(answer.qb2, eom, cp, (char *)bp, buflen);
	if (n < 0) {
	  cp += n;
	  continue;
	}

	cp += n;

	handleMdnsName(srcHost, sport, bp);
	haveAnswer = TRUE;
	continue;
      } else {
	if(len >= (sizeof(dnsBuf)-1)) len = sizeof(dnsBuf)-2;
	xstrncpy(dnsBuf, (char*)bp, len);

	d = strtok_r(dnsBuf, ".", &strtokState);
	c = strtok_r(NULL, ".", &strtokState);
	b = strtok_r(NULL, ".", &strtokState);
	a = strtok_r(NULL, ".", &strtokState);

	if(a && b && c && d) {
	  theDNSaddr = htonl(atoi(a)*(256*256*256)+atoi(b)*(256*256)+atoi(c)*256+atoi(d));
	  if(addr_list_idx >= MAX_ADDRESSES) break; /* Further check */
	  memcpy(&addr_list[addr_list_idx++], (char*)&theDNSaddr, sizeof(char*));
	  hostPtr->addrLen = INADDRSZ;
	  hostPtr->addrList[0] = (u_int32_t) theDNSaddr;

	  n = (short)dn_expand_(answer.qb2, eom, cp, (char *)bp, buflen);
	  if (n < 0) {
	    cp += n;
	    continue;
	  }
	  cp += n;
	  len = (int)(strlen((char *)bp) + 1);
	  memcpy(hostPtr->name, bp, len);
	  haveAnswer = TRUE;
	}
      }
      break;
    } else if (type != T_A) {
      cp += dlen;
      continue;
    }
    if (dlen != INADDRSZ)
      return(transactionId);
    if (haveAnswer) {
      /*
       * If we've already got 1 address, we aren't interested
       * in addresses with a different length or class.
       */
      if (dlen != hostPtr->addrLen) {
	cp += dlen;
	continue;
      }
      if (class != origClass) {
	cp += dlen;
	continue;
      }
    } else {
      /*
       * First address: record its length and class so we
       * only save additonal ones with the same attributes.
       */
      hostPtr->addrLen = dlen;
      origClass = class;
      hostPtr->addrType = (class == C_IN) ? AF_INET : AF_UNSPEC;
      len = (int)(strlen((char *)bp) + 1);
      memcpy(hostPtr->name, bp, len);
    }

/* Align bp on u_int32_t boundary */
#if 0
    bp += (((u_int32_t)bp) % sizeof(u_int32_t));
#else
    {
      u_int32_t     padding;

      padding = (u_int32_t)(((long)bp) % sizeof(u_int32_t));
      bp += padding;
      buflen -= padding;
    }
#endif

    if (bp + dlen >= &hostbuf[sizeof(hostbuf)]) {
      break;
    }
    if (numAddresses >= MAX_ADDRESSES) {
      cp += dlen;
      continue;
    }
    memcpy(*addrPtr++ = (char *)bp, cp, dlen);
    bp += dlen;
    cp += dlen;
    buflen -= dlen;
    numAddresses++;
    haveAnswer = TRUE;
  }

  if ((queryType == T_A || queryType == T_PTR) && haveAnswer) {
    if(sport == 53 /* DNS */) {
      /*
       *  Go through the alias and address lists and return them
       *  in the hostPtr variable.
       */
      if (numAliases > 0) {
	for (i = 0; i < numAliases; i++) {
	  if(host_aliases[i] != NULL)
	    memcpy(hostPtr->aliases[i], host_aliases[i], host_aliases_len[i]);
	  else break;
	}
	hostPtr->aliases[i][0] = '\0';
      }

      if (numAddresses > 0) {
	for (i = 0; i < numAddresses; i++) {
	  if(addr_list[i] != NULL)
	    memcpy(&hostPtr->addrList[i], addr_list[i], hostPtr->addrLen);
	  else break;
	}
	hostPtr->addrList[i] = 0;
      }
    }

    return(transactionId);
  }

  /*
   * At this point, for the T_A query type, only empty answers remain.
   * For other query types, additional information might be found
   * in the additional resource records part.
   */

  if (!answer.qb1.aa && (queryType != T_A) && (nscount > 0 || arcount > 0)) {
    if (printedAnswers) {
      putchar('\n');
    }
  }

  cp = (u_char *)_res_skip((char *)&answer, 2, (char *)eom);

  while ((--nscount >= 0) && (cp < eom)) {
    /*
     *  Go through the NS records and retrieve the names of hosts
     *  that serve the requested domain.
     */

    n = (short)dn_expand_(answer.qb2, eom, cp, (char *)bp, buflen);
    if (n < 0) {
      return(transactionId);
    }

    if(sport == 5353 /* mDNS */)
      handleMdnsName(srcHost, sport, bp);

    cp += n;
    len = (int)(strlen((char *)bp) + 1);

    if (cp + 3 * INT16SZ + INT32SZ > eom)
      return(transactionId);
    type  = GetShort(cp);
    class = GetShort(cp);
    cp   += INT32SZ;	/* skip TTL */
    dlen  = GetShort(cp);
    if (cp + dlen > eom)
      return(transactionId);

    if (type != T_NS) {
      cp += dlen;
    }
  }

  return(transactionId);
}

/* **************************************** */

void checkSpoofing(HostTraffic *hostToCheck, int actualDeviceId, const struct pcap_pkthdr *h, const u_char *p) {
  HostTraffic *el;

  for(el=getFirstHost(actualDeviceId);
      el != NULL; el = getNextHost(actualDeviceId, el)) {
    if((!addrnull(&el->hostIpAddress))
       && (addrcmp(&el->hostIpAddress,&hostToCheck->hostIpAddress) == 0)) {
      /* Spoofing detected */
      if((!hasDuplicatedMac(el))
	 && (!hasDuplicatedMac(hostToCheck))) {
	setHostFlag(FLAG_HOST_DUPLICATED_MAC, hostToCheck);
	setHostFlag(FLAG_HOST_DUPLICATED_MAC, el);

	if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	  traceEvent(CONST_TRACE_WARNING,
		     "Two MAC addresses found for the same IP address %s: [%s/%s] (spoofing detected?)",
		     el->hostNumIpAddress, hostToCheck->ethAddressString, el->ethAddressString);
	  dumpSuspiciousPacket(actualDeviceId, h, p);
	}
      }
    }
  }
}

/* **************************************** */

char* subnetId2networkName(int8_t known_subnet_id, char *buf, u_short buf_len) {
  struct in_addr addr;
  char buf1[64];

  if((known_subnet_id == UNKNOWN_SUBNET_ID)
     || (known_subnet_id < 0)
     || (known_subnet_id >= myGlobals.numKnownSubnets))
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "0.0.0.0/0");
  else {
    addr.s_addr = myGlobals.subnetStats[known_subnet_id].address[CONST_NETWORK_ENTRY];

    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "%s/%d",
		  _intoa(addr, buf1, sizeof(buf1)),
		  myGlobals.subnetStats[known_subnet_id].address[CONST_NETMASK_V6_ENTRY]);
  }

  return(buf);
}

/* **************************************** */

char* host2networkName(HostTraffic *el, char *buf, u_short buf_len) {
  buf[0] = '\0';

  if(el != NULL) {
    if(el->known_subnet_id != UNKNOWN_SUBNET_ID)
      return(subnetId2networkName(el->known_subnet_id, buf, buf_len));
    else if((el->network_mask > 0) && (el->hostIpAddress.hostFamily == AF_INET)) {
      struct in_addr addr;
      char buf1[32];

      addr.s_addr = el->hostIpAddress.Ip4Address.s_addr & (~(0xFFFFFFFF >> el->network_mask));

      safe_snprintf(__FILE__, __LINE__, buf, buf_len, "%s/%d",
		    _intoa(addr, buf1, sizeof(buf1)),
		    el->network_mask);
    }
  }

  return(buf);
}

/* **************************************** */

void addDeviceNetworkToKnownSubnetList(NtopInterface *device) {
  int i;

  if(device->network.s_addr == 0) return;

  for(i=0; i<myGlobals.numKnownSubnets; i++) {
    if((device->network.s_addr == myGlobals.subnetStats[i].address[CONST_NETWORK_ENTRY])
       && (device->netmask.s_addr == myGlobals.subnetStats[i].address[CONST_NETMASK_ENTRY]))
       return; /* Already present */
  }

  /* Not present: we add it to the list */
  if(myGlobals.numKnownSubnets >= (MAX_NUM_NETWORKS-1)) {
    traceEvent(CONST_TRACE_WARNING, "Too many known subnets defined (%d)",
	       myGlobals.numKnownSubnets);
    return;
  } else {
    i = myGlobals.numKnownSubnets;
    myGlobals.subnetStats[i].address[CONST_NETWORK_ENTRY]    = device->network.s_addr;
    myGlobals.subnetStats[i].address[CONST_NETMASK_ENTRY]    = device->netmask.s_addr;
    myGlobals.subnetStats[i].address[CONST_NETMASK_V6_ENTRY] = num_network_bits(device->netmask.s_addr);
    myGlobals.subnetStats[i].address[CONST_BROADCAST_ENTRY]  = device->network.s_addr | (~device->netmask.s_addr);
    myGlobals.numKnownSubnets++;
  }
}

/* **************************************** */

void updateHostKnownSubnet(HostTraffic *el) {
  int i;

  if((myGlobals.numKnownSubnets == 0)
     || (el->hostIpAddress.hostFamily != AF_INET /* v4 */))
    return;

  for(i=0; i<myGlobals.numKnownSubnets; i++) {
    if((el->hostIpAddress.addr._hostIp4Address.s_addr & myGlobals.subnetStats[i].address[CONST_NETMASK_ENTRY])
       == myGlobals.subnetStats[i].address[CONST_NETWORK_ENTRY]) {
      el->known_subnet_id = i;
      // setHostFlag(FLAG_SUBNET_LOCALHOST, el);
      setHostFlag(FLAG_SUBNET_PSEUDO_LOCALHOST, el);
      return;
    }
  }

  el->known_subnet_id = UNKNOWN_SUBNET_ID;
}
