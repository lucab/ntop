/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
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

/* #define DEBUG */

/* #define GDBM_DEBUG */

/* Global */
static char hex[] = "0123456789ABCDEF";

#if !defined(WIN32) && !defined(AIX)
extern int h_errno; /* netdb.h */
#endif

/* #define DNS_DEBUG */

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

/*
  On FreeBSD gethostbyaddr() sometimes loops
  and uses all the available memory. Hence this
  patch is needed.

  On some Linux versions gethostbyaddr() is bugged and
  it tends to exaust all available file descriptors. If
  you want to check this try "lsof -i |grep ntop". If this
  is the case please do  '#define USE_HOST' (see below)
  in order to overcome this flaw.

*/
#if defined(__FreeBSD__)
#define USE_HOST
#endif

/* #define USE_HOST */

/* ************************************ */

static void resolveAddress(struct in_addr *hostAddr, short keepAddressNumeric) {
  char symAddr[MAX_HOST_SYM_NAME_LEN];
  StoredAddress storedAddress;
  int addr, i;
  struct hostent *hp = NULL;
  char* res;
  char keyBuf[16];
  char tmpBuf[96];
#ifdef HAVE_GDBM_H
  datum key_data;
  datum data_data;
#endif

  if(!capturePackets) return;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Entering resolveAddress()");
#endif
  addr = hostAddr->s_addr;

#ifdef HAVE_GDBM_H
  if(snprintf(keyBuf, sizeof(keyBuf), "%u", addr) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  key_data.dptr = keyBuf;
  key_data.dsize = strlen(keyBuf)+1;

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "resolveAddress");
#endif

  if(gdbm_file == NULL) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Leaving resolveAddress()");
#endif
    return; /* ntop is quitting... */
  }
  data_data = gdbm_fetch(gdbm_file, key_data);

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif

  /* First check whether the address we search for is cached... */
  if((data_data.dptr != NULL)
     && (data_data.dsize == (sizeof(StoredAddress)+1))) {
    StoredAddress *retrievedAddress;

    retrievedAddress = (StoredAddress*)data_data.dptr;
#ifdef DNS_DEBUG
    traceEvent(TRACE_INFO, "Fetched data (2): '%s' [%s]\n",
	       retrievedAddress->symAddress, keyBuf);
#endif

    /* Sanity check */
    if(strlen(retrievedAddress->symAddress) > MAX_HOST_SYM_NAME_LEN) {
      strncpy(symAddr, retrievedAddress->symAddress, MAX_HOST_SYM_NAME_LEN-3);
      symAddr[MAX_HOST_SYM_NAME_LEN] = '\0';
      symAddr[MAX_HOST_SYM_NAME_LEN-1] = '.';
      symAddr[MAX_HOST_SYM_NAME_LEN-2] = '.';
      symAddr[MAX_HOST_SYM_NAME_LEN-3] = '.';
    } else
      strncpy(symAddr, retrievedAddress->symAddress, MAX_HOST_SYM_NAME_LEN);

    updateHostNameInfo(addr, retrievedAddress->symAddress);
    numResolvedOnCacheAddresses++;
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Leaving resolveAddress()");
#endif
     free(data_data.dptr);
     return;
  } else {
#ifdef GDBM_DEBUG
    if(data_data.dptr != NULL)
      traceEvent(TRACE_ERROR, "Dropped data for %s [wrong data size]", keyBuf);
    else
      traceEvent(TRACE_ERROR, "Unable to retrieve %s", keyBuf);
#endif

    /* It might be that the size of the retieved data is wrong */
    if(data_data.dptr != NULL) free(data_data.dptr);
  }
#endif

  if((!keepAddressNumeric) && capturePackets) {
    struct in_addr theAddr;
#ifdef HAVE_GETIPNODEBYADDR
    int error_num;
#endif

#ifdef DNS_DEBUG
    traceEvent(TRACE_INFO, "Resolving %s...", intoa(*hostAddr));
#endif
    theAddr.s_addr = ntohl(hostAddr->s_addr); /* big/little endian crap */

#if !defined(WIN32) &&  !defined(AIX)
    h_errno = NETDB_SUCCESS;
#endif

#ifdef USE_HOST
    {
      FILE* fd;
      char buffer[64];
      struct in_addr myAddr;
      int i, len;

      myAddr.s_addr = hostAddr->s_addr;
      if(snprintf(buffer, sizeof(buffer),
		  "/usr/bin/host %s",
		  intoa(myAddr)) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");

      fd = sec_popen(buffer, "r");

      if(fd == NULL) {
	tmpBuf[0] = '\0';
      } else {
	char *rspStr;

	memset(tmpBuf, 0, sizeof(tmpBuf));
	rspStr = fgets(tmpBuf, sizeof(tmpBuf), fd);
	pclose(fd);
	if(rspStr == NULL)
	  tmpBuf[0] = '\0';
      }

      /*
	# host 131.114.21.9
	9.21.114.131.IN-ADDR.ARPA domain name pointer faeta.unipi.it
	#
      */

      len = strlen(tmpBuf);
      if(len > 0) {
	tmpBuf[--len] = '\0';

	for(i=len; i>0; i--)
	  if(tmpBuf[i] == ' ')
	    break;
      }

      if((len > 0) && (i > 0) && (tmpBuf[i] == ' ')) {
	res = &tmpBuf[i+1];
	numResolvedWithDNSAddresses++;
      } else {
	res = _intoa(*hostAddr, tmpBuf, sizeof(tmpBuf));
	numKeptNumericAddresses++;
      }

#ifdef DNS_DEBUG
      traceEvent(TRACE_INFO, "Resolved to %s.", res);
#endif
    }
#else /* USE_HOST */

#ifdef HAVE_GETIPNODEBYADDR
    hp  = getipnodebyaddr((const void*)&theAddr,
			  sizeof(struct in_addr), AF_INET,
			  &error_num);
#else /* default */
    hp = (struct hostent*)gethostbyaddr((char*)&theAddr,
					sizeof(struct in_addr),
					AF_INET);
#endif

    if (
#if !defined(WIN32) &&  !defined(AIX)
	(h_errno == NETDB_SUCCESS) &&
#endif
	(hp != NULL) && (hp->h_name != NULL)) {
      char *dotp = (char*)hp->h_name;

#ifdef DNS_DEBUG
      traceEvent(TRACE_INFO, "Resolved to %s.", dotp);
#endif
      strncpy(tmpBuf, dotp, sizeof(tmpBuf));

      if(domainName[0] != '\0') {
	int len = strlen(tmpBuf)-strlen(domainName);

	if((len > 0) && (!strcmp(&tmpBuf[len], domainName))) {
	  int i=0, foundDot=0;

	  for(i=0; i<len-1; i++)
	    if(tmpBuf[i] == '.') {
	      foundDot = 1;
	      break;
	    }

	  if(!foundDot)
	    tmpBuf[len-1] = '\0';
	}
      }
      res = tmpBuf;
      numResolvedWithDNSAddresses++;
    } else {
      numKeptNumericAddresses++;
      res = _intoa(*hostAddr, tmpBuf , sizeof(tmpBuf));
#ifdef DNS_DEBUG
      traceEvent(TRACE_INFO, "Unable to resolve %s", res);
#endif
    }
#endif /* USE_HOST */
  } else {
    numKeptNumericAddresses++;
#ifdef DNS_DEBUG
      traceEvent(TRACE_INFO, "Unable to resolve %s", res);
#endif
    res = _intoa(*hostAddr, tmpBuf, sizeof(tmpBuf));
  }

#ifdef HAVE_GETIPNODEBYADDR
  if(hp != NULL)
    freehostent(hp);
#endif

  if(strlen(res) > MAX_HOST_SYM_NAME_LEN) {
    strncpy(symAddr, res, MAX_HOST_SYM_NAME_LEN-3);
    symAddr[MAX_HOST_SYM_NAME_LEN] = '\0';
    symAddr[MAX_HOST_SYM_NAME_LEN-1] = '.';
    symAddr[MAX_HOST_SYM_NAME_LEN-2] = '.';
    symAddr[MAX_HOST_SYM_NAME_LEN-3] = '.';
  } else
    strncpy(symAddr, res, MAX_HOST_SYM_NAME_LEN-1);

  for(i=0; symAddr[i] != '\0'; i++)
    symAddr[i] = (char)tolower(symAddr[i]);

  memset(storedAddress.symAddress, 0, sizeof(storedAddress.symAddress));
  strcpy(storedAddress.symAddress, symAddr);
  storedAddress.recordCreationTime = actTime;

  /* key_data has been set already */
  data_data.dptr = (void*)&storedAddress;
  data_data.dsize = sizeof(storedAddress)+1;

  updateHostNameInfo(addr, symAddr);

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "resolveAddress-4");
#endif

  if(gdbm_file == NULL) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Leaving resolveAddress()");
#endif
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif
    return; /* ntop is quitting... */
  }
  if(gdbm_store(gdbm_file, key_data, data_data, GDBM_REPLACE) != 0)
    traceEvent(TRACE_ERROR, "Error while adding '%s'\n.\n", symAddr);
  else {
#ifdef GDBM_DEBUG
    traceEvent(TRACE_INFO, "Added data: '%s' [%s]\n", symAddr, keyBuf);
#endif
  }

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Leaving Resolveaddress()");
#endif
}

/* *************************** */

#if defined(MULTITHREADED) && defined(ASYNC_ADDRESS_RESOLUTION)

static void queueAddress(struct in_addr elem) {
#ifdef HAVE_GDBM_H
  datum key_data, data_data;
#endif
  char tmpBuf[32];

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "queueAddress");
#endif

  sprintf(tmpBuf, "%u", elem.s_addr);
  key_data.dptr = tmpBuf;
  key_data.dsize = strlen(tmpBuf)+1;

  data_data = gdbm_fetch(gdbm_file, key_data);

  if(data_data.dptr == NULL) {
    data_data.dptr = tmpBuf;
    data_data.dsize = strlen(tmpBuf)+1;

  if(gdbm_store(addressCache, key_data, data_data, GDBM_REPLACE) != 0)
    printf("Error while adding address '%s'\n", tmpBuf);

  addressQueueLen++;
  if(addressQueueLen > maxAddressQueueLen) maxAddressQueueLen = addressQueueLen;

#ifdef DNS_DEBUG
   traceEvent(TRACE_INFO, "Queued address '%s' [addr queue=%d/max=%d]\n",
	      tmpBuf, addressQueueLen, maxAddressQueueLen);
#endif
  } else {
    /* Address already in queue */
    free(data_data.dptr);
  }
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif

#ifdef USE_SEMAPHORES
    incrementSem(&queueAddressSem);
#else
    signalCondvar(&queueAddressCondvar);
#endif
}

/* ************************************ */

void cleanupAddressQueue(void) {
  /* Nothing to do */
}

/* ************************************ */

#ifdef MULTITHREADED

void* dequeueAddress(void* notUsed _UNUSED_) {
  struct in_addr addr;
#ifdef HAVE_GDBM_H
  datum key_data, data_data;
#endif

  key_data.dptr = NULL;

  while(capturePackets) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Waiting for address...\n");
#endif

    while((addressQueueLen == 0)
	  && (capturePackets) /* Courtesy of Wies-Software <wies@wiessoft.de> */
	  ) {
#ifdef USE_SEMAPHORES
      waitSem(&queueAddressSem);
#else
      waitCondvar(&queueAddressCondvar);
#endif
      key_data.dptr = NULL;
    }

    if(!capturePackets) break;

#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "queueAddress");
#endif

    if(key_data.dptr == NULL) {
	data_data = gdbm_firstkey(addressCache);
    } else {
	data_data = gdbm_nextkey(addressCache, key_data);
	free(key_data.dptr);
    }

    key_data = data_data;

  if(data_data.dptr != NULL) {
      addressQueueLen--;

      addr.s_addr = atol(data_data.dptr);

#ifdef DNS_DEBUG
      traceEvent(TRACE_INFO, "Dequeued address... [%u] (#addr=%d)\n",
		 addr.s_addr, addressQueueLen);
#endif

      gdbm_delete(addressCache, data_data);
    } else
      addr.s_addr = 0;

#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif

    if(addr.s_addr != 0) {
      resolveAddress(&addr, 0);

#ifdef DNS_DEBUG
      traceEvent(TRACE_INFO, "Resolved address %u\n", addr.s_addr);
#endif
    }
  } /* endless loop */

  traceEvent(TRACE_INFO, "Address resultion terminated...");
  return(NULL); /* NOTREACHED */
}

#endif /* defined(MULTITHREADED) && defined(ASYNC_ADDRESS_RESOLUTION) */
#endif

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

/* ******************************* */

/* This function automatically updated the instance name */

void ipaddr2str(struct in_addr hostIpAddress) {
  unsigned int addr = hostIpAddress.s_addr;
  char buf[32];
#ifdef HAVE_GDBM_H
  char tmpBuf[32];
  datum key_data;
  datum data_data;
#endif

  if((addr == INADDR_BROADCAST) || (addr == 0x0)) {
    updateHostNameInfo(hostIpAddress.s_addr, _intoa(hostIpAddress, buf, sizeof(buf)));
    return;
  }

  if(snprintf(tmpBuf, sizeof(tmpBuf), "%u", (unsigned) hostIpAddress.s_addr) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");

  key_data.dptr = tmpBuf;
  key_data.dsize = strlen(key_data.dptr)+1;

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "ipaddr2str");
#endif

  if(gdbm_file == NULL) return; /* ntop is quitting... */
  data_data = gdbm_fetch(gdbm_file, key_data);

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif

  if((data_data.dptr != NULL)
     && (data_data.dsize == (sizeof(StoredAddress)+1))) {
    StoredAddress *retrievedAddress;

    retrievedAddress = (StoredAddress*)data_data.dptr;

#ifdef GDBM_DEBUG
    traceEvent(TRACE_INFO, "Fetched data (1): %s [%s]", retrievedAddress->symAddress, tmpBuf);
#endif
    updateHostNameInfo(hostIpAddress.s_addr, retrievedAddress->symAddress);
    free(data_data.dptr);
  } else {
#ifdef GDBM_DEBUG
    if(data_data.dptr != NULL)
      traceEvent(TRACE_ERROR, "Dropped data for %s [wrong data size]", tmpBuf);
    else
      traceEvent(TRACE_ERROR, "Unable to retrieve %s", tmpBuf);
#endif

    /* It might be that the size of the retieved data is wrong */
    if(data_data.dptr != NULL) free(data_data.dptr);

#ifndef MULTITHREADED
    resolveAddress(&hostIpAddress, 0);
#else
    queueAddress(hostIpAddress);
#endif
  }
}

/* ************************************ */

char* etheraddr_string(const u_char *ep) {
  static char buf[sizeof("00:00:00:00:00:00")];
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';

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

  /* traceEvent(TRACE_INFO, "%s\n", buf); */
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

/* *************************************

   Code "inherited" from nslookup

   ************************************* */

#define NS_INT16SZ      2       /* #/bytes of data in a u_int16_t */

#ifndef NS_GET16
#define NS_GET16(s, cp) { \
        u_char *t_cp = (u_char *)(cp); \
        (s) = ((u_int16_t)t_cp[0] << 8) \
            | ((u_int16_t)t_cp[1]) \
            ; \
        (cp) += NS_INT16SZ; \
}
#endif

/* ************************************ */

static u_int _ns_get16(const u_char *src) {
  u_int dst;

  NS_GET16(dst, src);
  return (dst);
}

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
  return (dn - dst);
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
	len = srcp - src + 1;
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
    len = srcp - src;
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
  return (ptr - saveptr);
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
   * skip authoritative answer records
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

#define GetShort(cp)	_ns_get16(cp); cp += INT16SZ;

/* ************************************ */
/*
   This function needs to be rewritten from scratch
   as it does not check boundaries (see ** below)
*/

u_int16_t handleDNSpacket(const u_char *ipPtr,
			  DNSHostInfo *hostPtr,
			  short length,
			  short *isRequest,
			  short *positiveReply) {
  querybuf      answer;
  u_char	*cp;
  char		**aliasPtr;
  u_char	*eom, *bp;
  char		**addrPtr;
  int		type, class, queryType = T_A;
  int		qdcount, ancount, arcount, nscount, buflen;
  int		origClass=0;
  int		numAliases = 0;
  int		numAddresses = 0;
  int		i;
  int		len;
  int		dlen;
  char		haveAnswer;
  short     addr_list_idx=0;
  char		printedAnswers = FALSE;
  char *host_aliases[MAXALIASES];
  int   host_aliases_len[MAXALIASES], n;
  u_char  hostbuf[MAXDNAME];
  char *addr_list[MAXADDRS + 1];
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
  traceEvent(TRACE_INFO, "id=0x%X - flags=0x%X\n", transactionId, flags);
#endif

  memset(&answer, 0, sizeof(answer));
  memcpy(&answer, ipPtr, length);

  *isRequest = (short)!(flags & 0x8000);
  *positiveReply = (short)!(flags & 0x0002);

  if(answer.qb1.rcode != NOERROR) {
    return(transactionId);
  }

  eom = (u_char *)(ipPtr+length);

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
  buflen = sizeof(hostbuf);
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
      if (aliasPtr >= &host_aliases[MAXALIASES-1]) {
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
      char *a, *b, *c, *d, dnsBuf[48];
      int len;
      unsigned long theDNSaddr;

      len = strlen(bp); if(len >= (sizeof(dnsBuf)-1)) len = sizeof(dnsBuf)-2;
      memset(dnsBuf, 0, sizeof(dnsBuf));
      strncpy(dnsBuf, bp, len);

      d = strtok(dnsBuf, ".");
      c = strtok(NULL, ".");
      b = strtok(NULL, ".");
      a = strtok(NULL, ".");

      if(a && b && c && d) {
	theDNSaddr = htonl(atoi(a)*(256*256*256)+atoi(b)*(256*256)+atoi(c)*256+atoi(d));
	memcpy(&addr_list[addr_list_idx++], (char*)&theDNSaddr, sizeof(char*));
	hostPtr->addrLen = INADDRSZ;
	hostPtr->addrList[0] = theDNSaddr;

	n = (short)dn_expand_(answer.qb2, eom, cp, (char *)bp, buflen);
	if (n < 0) {
	  cp += n;
	  continue;
	}
	cp += n;
	len = strlen((char *)bp) + 1;
	memcpy(hostPtr->name, bp, len);
	haveAnswer = TRUE;
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
      len = strlen((char *)bp) + 1;
      memcpy(hostPtr->name, bp, len);
    }
    bp += (((u_int32_t)bp) % sizeof(u_int32_t));

    if (bp + dlen >= &hostbuf[sizeof(hostbuf)]) {
      break;
    }
    if (numAddresses >= MAXADDRS) {
      cp += dlen;
      continue;
    }
    memcpy(*addrPtr++ = (char *)bp, cp, dlen);
    bp += dlen;
    cp += dlen;
    numAddresses++;
    haveAnswer = TRUE;
  }

  if ((queryType == T_A || queryType == T_PTR) && haveAnswer) {

    /*
     *  Go through the alias and address lists and return them
     *  in the hostPtr variable.
     */

    if (numAliases > 0) {
      for (i = 0; i < numAliases; i++) {
	memcpy(hostPtr->aliases[i], host_aliases[i],
	       host_aliases_len[i]);
      }
      hostPtr->aliases[i][0] = '\0';
    }
    if (numAddresses > 0) {
      for (i = 0; i < numAddresses; i++) {
	memcpy(&hostPtr->addrList[i], addr_list[i], hostPtr->addrLen);
      }
      hostPtr->addrList[i] = 0;
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

  while (--nscount >= 0 && cp < eom) {
    /*
     *  Go through the NS records and retrieve the names of hosts
     *  that serve the requested domain.
     */

    n = (short)dn_expand_(answer.qb2, eom, cp, (char *)bp, buflen);
    if (n < 0) {
      return(transactionId);
    }
    cp += n;
    len = strlen((char *)bp) + 1;

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

void checkSpoofing(u_int idxToCheck) {
  u_int i;
  HostTraffic *el;

  for(i=1; i<device[actualDeviceId].actualHashSize; i++) {
    if((i != idxToCheck)
       && ((el = device[actualDeviceId].hash_hostTraffic[i]) != NULL)) {
      if((el->hostIpAddress.s_addr != 0x0)
	 && (el->hostIpAddress.s_addr ==
	     device[actualDeviceId].hash_hostTraffic[idxToCheck]->hostIpAddress.s_addr)) {
	/* Spoofing detected */
	FilterRule spoofing;


	if((!hasDuplicatedMac(el))
	   && (!hasDuplicatedMac(device[actualDeviceId].hash_hostTraffic[idxToCheck]))) {
	  FD_SET(HOST_DUPLICATED_MAC, &device[actualDeviceId].hash_hostTraffic[idxToCheck]->flags);
	  FD_SET(HOST_DUPLICATED_MAC, &el->flags);

	  memset(&spoofing, 0, sizeof(FilterRule));
	  spoofing.ruleId     = 999;
	  spoofing.ruleLabel  = "spoofing";
	  spoofing.actionType = ACTION_ALARM;

	  emitEvent(&spoofing, el, i,
		    device[actualDeviceId].hash_hostTraffic[idxToCheck],
		    idxToCheck, -1, 0, 0);

	  if(enableSuspiciousPacketDump) {
	    traceEvent(TRACE_WARNING,
		       "Two MAC addresses found for the same IP address %s: [%s/%s] (spoofing detected?)",
		       el->hostNumIpAddress,
		       device[actualDeviceId].hash_hostTraffic[idxToCheck]->ethAddressString,
		       el->ethAddressString);
	    dumpSuspiciousPacket();
	  }
	}
      }
    }
  }
}



/* ****************************************** */

/*
  Let's remove from the database those entries that
  have been added a while ago
*/

#define ADDRESS_PURGE_TIMEOUT 12*60*60 /* 12 hours */

void cleanupHostEntries() {
  datum data_data, key_data, return_data;
  u_int numDbEntries = 0;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Entering cleanupHostEntries()");
#endif

#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "cleanupHostEntries");
#endif
  return_data = gdbm_firstkey(gdbm_file);
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif

  while(return_data.dptr != NULL) {
    numDbEntries++;
    key_data = return_data;
#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "cleanupHostEntries");
#endif
    return_data = gdbm_nextkey(gdbm_file, key_data);
    data_data = gdbm_fetch(gdbm_file, key_data);

    if(data_data.dptr != NULL) {
      if((data_data.dsize == (sizeof(StoredAddress)+1))
	 || ((((StoredAddress*)data_data.dptr)->recordCreationTime+ADDRESS_PURGE_TIMEOUT) < actTime)) {
	gdbm_delete(gdbm_file, key_data);
#ifdef DEBUG
	traceEvent(TRACE_INFO, "Deleted '%s' entry.\n", data_data.dptr);
#endif
	numDbEntries--;
      }
    }
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#ifdef HAVE_SCHED_H
    sched_yield(); /* Allow other threads to run */
#endif
#endif

    if(data_data.dptr != NULL) free(data_data.dptr);
    free(key_data.dptr);
  }
}

