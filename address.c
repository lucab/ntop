/*
 *  Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
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

/* **************************************** */

static void updateDeviceHostNameInfo(HostAddr addr, char* symbolic, int actualDeviceId, int type) {
  HostTraffic *el;

  if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN) return;

  /* Search the instance and update its name */
    
  if(myGlobals.device[actualDeviceId].virtualDevice) return;

  for(el=getFirstHost(actualDeviceId); el != NULL; el = getNextHost(actualDeviceId, el)) {
    if((el->hostNumIpAddress != NULL) && (addrcmp(&el->hostIpAddress, &addr) == 0)) {
      accessAddrResMutex("updateHostNameInfo");
      
      if(el != NULL) {    
	unsigned short i;
	
	if(strlen(symbolic) >= (MAX_LEN_SYM_HOST_NAME-1)) 
	  symbolic[MAX_LEN_SYM_HOST_NAME-2] = '\0';
	
	for(i=0; i<strlen(symbolic); i++)
	  if(isupper(symbolic[i])) tolower(symbolic[i]);
	
	setResolvedName(el, symbolic, type);
      }
      
      releaseAddrResMutex();
    }
  }
}

/* **************************************** */

  static void updateHostNameInfo(HostAddr addr, char* symbolic, int type) {
  int i; 

  for(i=0; i<myGlobals.numDevices; i++)
    updateDeviceHostNameInfo(addr, symbolic, i, type);
}

/* ************************************ */

static int validDNSChar(char c) {  
  if((c == '-') || (c == '_') || (c == '.')) return(1);
  if((c >= '0') && (c <= '9')) return(1);
  if((c >= 'a') && (c <= 'z')) return(1);
  if((c >= 'A') && (c <= 'Z')) return(1);

  return(0);
}

/* ************************************ */

static int validDNSName(char *name) {
  int i, len;

  if(name == NULL) 
    return(0); 
  else 
    len = strlen(name);
  
  for(i=0; i<len; i++)
    if(!validDNSChar(name[i]))
      return(0);
  
  return(1);
}

/* ************************************ */

static void resolveAddress(HostAddr *hostAddr, short keepAddressNumeric) {
  char symAddr[MAX_LEN_SYM_HOST_NAME];
  short symAddrType=FLAG_HOST_SYM_ADDR_TYPE_NONE;
  StoredAddress storedAddress;
  int i, addToCacheFlag=0, updateRecord=0;
  struct hostent *hp = NULL;
  char* resolvedAddress;
  char keyBuf[LEN_ADDRESS_BUFFER];
  char dataBuf[sizeof(StoredAddress)+4];
  datum key_data;
  datum data_data;
  static int reportedFreaky = FALSE;

  if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN) return;

  myGlobals.numResolveAddressCalls++;

#ifdef DNS_DEBUG
  traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Entering resolveAddress()");
#endif

  memset(&keyBuf, 0, sizeof(keyBuf));
  memset(&dataBuf, 0, sizeof(dataBuf));
  memset(&storedAddress, 0, sizeof(storedAddress));

  key_data.dptr = _addrtonum(hostAddr, keyBuf, sizeof(keyBuf));
  key_data.dsize = strlen(keyBuf)+1;
  
  if(myGlobals.dnsCacheFile == NULL) {
#ifdef DNS_DEBUG
    traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Leaving resolveAddress(), dnsCacheFile NULL");
#endif
    myGlobals.numResolveNoCacheDB++;
    return; /* ntop is quitting... */
  }

  data_data = gdbm_fetch(myGlobals.dnsCacheFile, key_data);

  myGlobals.numResolveCacheDBLookups++;
  /* First check whether the address we search for is cached... */
  if((data_data.dptr != NULL) &&
     (data_data.dsize == (sizeof(StoredAddress)+1)) &&
     (myGlobals.actTime - ((StoredAddress*)data_data.dptr)->recordCreationTime < CONST_DNSCACHE_LIFETIME) ) {
    StoredAddress *retrievedAddress;

    retrievedAddress = (StoredAddress*)data_data.dptr;
#ifdef DNS_DEBUG
    traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Fetched '%s' from cache for [%s]",
	       retrievedAddress->symAddress, keyBuf);
#endif

    /* Sanity check */
    if(strlen(retrievedAddress->symAddress) > MAX_LEN_SYM_HOST_NAME) {
      strncpy(symAddr, retrievedAddress->symAddress, MAX_LEN_SYM_HOST_NAME-4);
      symAddr[MAX_LEN_SYM_HOST_NAME-1] = '\0';
      symAddr[MAX_LEN_SYM_HOST_NAME-2] = '.';
      symAddr[MAX_LEN_SYM_HOST_NAME-3] = '.';
      symAddr[MAX_LEN_SYM_HOST_NAME-4] = '.';
    } else
      strncpy(symAddr, retrievedAddress->symAddress, MAX_LEN_SYM_HOST_NAME-1);

    symAddrType = retrievedAddress->symAddressType;

    myGlobals.numResolvedFromCache++;
    updateHostNameInfo(*hostAddr, retrievedAddress->symAddress, retrievedAddress->symAddressType);

    free(data_data.dptr);
#ifdef DNS_DEBUG
    traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Leaving resolveAddress() - resolved from cache");
#endif
    return;
  } else {
    if(data_data.dptr != NULL) {
#ifdef GDBM_DEBUG
      if (data_data.dsize == (sizeof(StoredAddress)+1))
        traceEvent(CONST_TRACE_INFO, "GDBM_DEBUG: Dropped data for %s [wrong data size]", keyBuf);
      else
        traceEvent(CONST_TRACE_INFO, "GDBM_DEBUG: Ignored old record for %s", keyBuf);
#endif
      free(data_data.dptr);
#ifdef GDBM_DEBUG
    } else {
      traceEvent(CONST_TRACE_INFO, "GDBM_DEBUG: Unable to retrieve %s", keyBuf);
#endif
    }

  }

  if((!keepAddressNumeric) && (myGlobals.capturePackets == FLAG_NTOPSTATE_RUN)) {
    char theAddr[17];
    int family, size;
    
#ifdef HAVE_GETIPNODEBYADDR
    int error_num;
#endif

#ifdef DNS_DEBUG
    traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Resolving %s...", addrtostr(hostAddr));
#endif
    addrget(hostAddr,theAddr,&family,&size);
#ifdef HAVE_NETDB_H
    h_errno = NETDB_SUCCESS;
#endif

#ifdef PARM_USE_HOST
    {
      FILE* fd;
      char buffer[64];
      int i, len;
      
      if (hostAddr->hostFamily == AF_INET)
	cwd = "/usr/bin/host";
      else (hostAddr->hostFamily == AF_INET6)
	cwd = "/usr/bin/host -t aaaa";
      safe_snprintf(__FILE__, __LINE__, buffer, sizeof(buffer),
		  "%s %s",
		  cwd,theAddr);
      
      fd = popen(buffer, "r");

      if(fd == NULL) {
	dataBuf[0] = '\0';
      } else {
	char *rspStr;

	memset(dataBuf, 0, sizeof(dataBuf));
	rspStr = fgets(dataBuf, sizeof(dataBuf), fd);
	pclose(fd);
	if(rspStr == NULL)
	  dataBuf[0] = '\0';
      }

      /*
	# host 131.114.21.9
	9.21.114.131.IN-ADDR.ARPA domain name pointer faeta.unipi.it
	#
      */

      len = strlen(dataBuf);
      if(len > 0) {
	dataBuf[--len] = '\0';

	for(i=len; i>0; i--)
	  if(dataBuf[i] == ' ')
	    break;
      }

      if((len > 0) && (i > 0) && (dataBuf[i] == ' ')) {
	res = &dataBuf[i+1];
	myGlobals.numResolvedFromHostAddresses++;
        symAddrType=FLAG_HOST_SYM_ADDR_TYPE_NAME;
      } else {
	res = _addrtostr(hostAddr, dataBuf, sizeof(dataBuf));
	myGlobals.numKeptNumericAddresses++;
        symAddrType=FLAG_HOST_SYM_ADDR_TYPE_IP;
      }

#ifdef DNS_DEBUG
      traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Resolved to %s from hosts file.", res);
#endif
    }
#else /* PARM_USE_HOST */

    myGlobals.numAttemptingResolutionWithDNS++;
    addToCacheFlag = 0 /* Assume we'll get something, so we do want to add it later on */;

#ifdef HAVE_GETIPNODEBYADDR
    hp  = getipnodebyaddr((const void*)theAddr,
			  size,family,
			  &error_num);
#ifdef DNS_DEBUG
    traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Called getipnodebyaddr(): RC=%d 0x%X [%s]",      error_num,
	       hp, hp != NULL ? (char*)hp->h_name : "");
#endif
    
#else /* default */
#if defined(HAVE_GETHOSTBYADDR_R) && !defined(LINUX)
    /* Linux seems to ha some problems with gethostbyaddr_r */
#ifdef SOLARIS
    {
   struct hostent _hp, *__hp;
   char buffer[512];
  
  hp = gethostbyaddr_r((const char*)theAddr, size, 
			 family,
                         &_hp,
                         buffer, sizeof(buffer),
                         &h_errnop);
#ifdef DNS_DEBUG
    traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Called gethostbyaddr_r(): RC=%d 0x%X [%s]", 
               h_errnop,
	       hp, hp != NULL ? (char*)hp->h_name : "");
#endif

#else /* SOLARIS */
    hp = gethostbyaddr_r((const char*)theAddr, size,
                         family,
                         &_hp,
                         buffer, sizeof(buffer),
                         &__hp,
                         &h_errnop);
#ifdef DNS_DEBUG
    traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Called gethostbyaddr_r(): RC=%d 0x%X [%s]", 
               h_errnop,
	       hp, hp != NULL ? (char*)hp->h_name : "");
#endif /* DNS_DEBUG */
#endif  /* SOLARIS */
 }
#else
    hp = (struct hostent*)gethostbyaddr((char*)theAddr,size,family);
#ifdef DNS_DEBUG
    traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Called gethostbyaddr(): RC=%d 0x%X [%s]", 
               h_errno,
	       hp, hp != NULL ? (char*)hp->h_name : "not meaningful, hp is null");
#endif
//
#endif
#endif
    
    if (
#ifdef HAVE_NETDB_H
	(h_errno == NETDB_SUCCESS) &&
#endif
#ifdef WIN32
	(WSAGetLastError() == 0 /* OK */) &&
#endif
	(hp != NULL) && 
        (hp->h_name != NULL) &&
	validDNSName(hp->h_name) &&
        (strcmp(hp->h_name, addrtostr(hostAddr)) != 0)) {
      char *dotp = (char*)hp->h_name;

      updateRecord = 1;

#ifdef DNS_DEBUG
      traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Resolved to %s.", dotp);
#endif
      strncpy(dataBuf, dotp, sizeof(dataBuf));

      if(myGlobals.runningPref.domainName[0] != '\0') {
	int dataLen = strlen(dataBuf)-strlen(myGlobals.runningPref.domainName);

	if((dataLen > 0) && (!strcmp(&dataBuf[dataLen], myGlobals.runningPref.domainName))) {
	  int foundDot=0;

	  for(i=0; i<dataLen-1; i++)
	    if(dataBuf[i] == '.') {
	      foundDot = 1;
	      break;
	    }

	  if(!foundDot)
	    dataBuf[dataLen-1] = '\0';
	}
      }
      resolvedAddress = dataBuf;
      myGlobals.numResolvedWithDNSAddresses++;
      symAddrType=FLAG_HOST_SYM_ADDR_TYPE_NAME;
    } else {
      myGlobals.numKeptNumericAddresses++;
      symAddrType=FLAG_HOST_SYM_ADDR_TYPE_IP;
      /* Failed, but why? */
      switch (
#ifdef HAVE_NETDB_H
              h_errno
#elif HAVE_GETIPNODEBYADDR
              error_num
#else
              h_errno
#endif
             ) {
      case NETDB_SUCCESS:
	/* This is the freaky one - it returned NULL (nothing) which tells you to look
	 * at the error code, but the error code says SUCCESS.
	 *
             * Treat as NOT FOUND, but use reportedFreaky to put out one message per run.
             * Known to happen under Linux, other OSes uncertain...
             */
	if (reportedFreaky == FALSE) {
                reportedFreaky = TRUE;
		traceEvent(CONST_TRACE_NOISY, "gethost... call returned NULL/NETDB_SUCCESS - "
			   "this is odd, but apparently normal");
	}
	myGlobals.numDNSErrorHostNotFound++;
	break;
      case HOST_NOT_FOUND:
	myGlobals.numDNSErrorHostNotFound++;
	  break;
      case NO_DATA:
	myGlobals.numDNSErrorNoData++;
            break;
      case NO_RECOVERY:
	myGlobals.numDNSErrorNoRecovery++;
	  break;
      case TRY_AGAIN:
	myGlobals.numDNSErrorTryAgain++;
	addToCacheFlag = 1 /* Don't add this */;
	break;
        default:
	  myGlobals.numDNSErrorOther++;
	  addToCacheFlag = 1 /* Don't add this */;
	  traceEvent(CONST_TRACE_ERROR, "gethost... call, returned unknown error code %d",
#ifdef HAVE_NETDB_H
                  h_errno
#elif HAVE_GETIPNODEBYADDR
                  error_num
#else
                  h_errno
#endif
            );
      }
      resolvedAddress = _addrtostr(hostAddr, dataBuf , sizeof(dataBuf));
#ifdef DNS_DEBUG
      traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Unable to resolve %s", resolvedAddress);
#endif
    }
#endif /* PARM_USE_HOST */
  } else {
    myGlobals.numKeptNumericAddresses++;
#ifdef DNS_DEBUG
    traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Unable to resolve %s", resolvedAddress);
#endif
    resolvedAddress = _addrtostr(hostAddr, dataBuf, sizeof(dataBuf));
  }
  
#ifdef HAVE_GETIPNODEBYADDR
  if(hp != NULL)
    freehostent(hp);
#endif

  if (addToCacheFlag == 0) {
      if(strlen(resolvedAddress) > MAX_LEN_SYM_HOST_NAME) {
        strncpy(symAddr, resolvedAddress, MAX_LEN_SYM_HOST_NAME-4);
        symAddr[MAX_LEN_SYM_HOST_NAME-1] = '\0';
        symAddr[MAX_LEN_SYM_HOST_NAME-2] = '.';
        symAddr[MAX_LEN_SYM_HOST_NAME-3] = '.';
        symAddr[MAX_LEN_SYM_HOST_NAME-4] = '.';
      } else
        strncpy(symAddr, resolvedAddress, MAX_LEN_SYM_HOST_NAME-1);

      for(i=0; symAddr[i] != '\0'; i++)
        symAddr[i] = (char)tolower(symAddr[i]);

      memset(storedAddress.symAddress, 0, sizeof(storedAddress.symAddress));
      strcpy(storedAddress.symAddress, symAddr);
      storedAddress.recordCreationTime = myGlobals.actTime;
      storedAddress.symAddressType = symAddrType;

      /* key_data has been set already */
      data_data.dptr = (void*)&storedAddress;
      data_data.dsize = sizeof(storedAddress)+1;

      if(updateRecord) {
	updateHostNameInfo(*hostAddr, symAddr, symAddrType);
#ifdef DNS_DEBUG
	traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Updating %s", symAddr);
#endif
      } else {
#ifdef DNS_DEBUG
	traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: NOT updating %s", symAddr);
#endif
      }

      if(myGlobals.dnsCacheFile == NULL) {
#ifdef DNS_DEBUG
        traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Leaving resolveAddress()");
#endif
        return; /* ntop is quitting... */
      }

      if(gdbm_store(myGlobals.dnsCacheFile, key_data, data_data, GDBM_REPLACE) != 0)
        traceEvent(CONST_TRACE_ERROR, "dnsCache error adding '%s', %s", symAddr,
#if defined(WIN32) && defined(__GNUC__)
                       "no additional information available"
#else
                        gdbm_strerror(gdbm_errno)
#endif
                  );
      else {
        myGlobals.dnsCacheStoredLookup++;

#ifdef DNS_DEBUG
        traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Added data: '%s'='%s'(%d)",
                   key_data.dptr,
                   ((StoredAddress*)data_data.dptr)->symAddress,
                   ((StoredAddress*)data_data.dptr)->symAddressType);
#endif
      }

#ifdef DNS_DEBUG
      traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Leaving Resolveaddress()");
#endif
  }
}

/* *************************** */

#if defined(CFG_MULTITHREADED) && defined(MAKE_ASYNC_ADDRESS_RESOLUTION)

static void queueAddress(HostAddr elem, int forceResolution) {
  datum key_data, data_data;
  char dataBuf[sizeof(StoredAddress)+4];
  int rc;

  if((!forceResolution)
     && myGlobals.runningPref.trackOnlyLocalHosts 
     && (!_pseudoLocalAddress(&elem)))
    return;

  /*
    The address queue is far too long. This is usefult for
    avoiding problems due to DOS applications
  */
  if(myGlobals.addressQueuedCurrent > MAX_NUM_QUEUED_ADDRESSES) {
    static char shownMsg = 0;

    if(!shownMsg) {
      shownMsg = 1;
      traceEvent(CONST_TRACE_WARNING, "Address resolution queue is full [%u slots]", 
		 MAX_NUM_QUEUED_ADDRESSES);
      traceEvent(CONST_TRACE_INFO, "Addresses in excess won't be resolved - ntop continues");
    }
    return;
  }

  /* Fix - Burton Strauss (BStrauss@acm.org) 2002-04-04
           Make sure dataBuf has a value and
           Prevent increment of queue length on failure (i.e. add of existing value)
           Incidentally, speed this up by eliminating the fetch/store sequence in favor of
           a single store.
  */
  if (elem.hostFamily == AF_INET) {
    key_data.dptr = (void*)&elem.Ip4Address.s_addr;
    key_data.dsize = 4;
  }
#ifdef INET6
  else if (elem.hostFamily == AF_INET6) {
    key_data.dptr = (void*)&elem.Ip6Address.s6_addr;
    key_data.dsize = 16;
  }
#endif

  safe_snprintf(__FILE__, __LINE__, dataBuf, sizeof(dataBuf), "%s", addrtostr(&elem));
  data_data.dptr = dataBuf;
  data_data.dsize = strlen(dataBuf)+1;

  rc = gdbm_store(myGlobals.addressQueueFile, key_data, data_data, GDBM_INSERT);

  if (rc == 0) {
    myGlobals.addressQueuedCurrent++, myGlobals.addressQueuedCount++;
    if (myGlobals.addressQueuedCurrent > myGlobals.addressQueuedMax)
      myGlobals.addressQueuedMax = myGlobals.addressQueuedCurrent;
    
#ifdef DNS_DEBUG
    traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Queued address '%s' [addr queue=%d/max=%d]",
	       dataBuf, myGlobals.addressQueuedCurrent, myGlobals.addressQueuedMax);
#endif
  } else {
    /* rc = 1 is duplicate key, which is fine.  Other codes are problems... */
    if (rc != 1) {
      traceEvent(CONST_TRACE_ERROR, "Queue of address '%s' failed, code %d [addr queue=%d/max=%d]",
		 dataBuf, rc, myGlobals.addressQueuedCurrent, myGlobals.addressQueuedMax);
      traceEvent(CONST_TRACE_INFO, "ntop processing continues, address will not be resolved");
    } else {
      myGlobals.addressQueuedDup++;
#ifdef DNS_DEBUG
      traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Duplicate queue of address '%s' ignored",
		 dataBuf);
#endif
    }
  }

#ifdef MAKE_WITH_SEMAPHORES
  incrementSem(&myGlobals.queueAddressSem);
#else
  signalCondvar(&myGlobals.queueAddressCondvar);
#endif
}

/* ************************************ */

void cleanupAddressQueue(void) {
  /* Nothing to do */
}

/* ************************************ */

#ifdef CFG_MULTITHREADED

void* dequeueAddress(void *_i) {
  int dqaIndex = (int)_i;

  HostAddr addr;
  datum key_data, data_data;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Address resolution(%d) thread running [p%d, t%lu]...",
             dqaIndex+1, getpid(), pthread_self());

  while(myGlobals.capturePackets == FLAG_NTOPSTATE_RUN) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Waiting for address to resolve...");
#endif

#ifdef MAKE_WITH_SEMAPHORES
    waitSem(&myGlobals.queueAddressSem);
#else
    waitCondvar(&myGlobals.queueAddressCondvar);
#endif

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Address resolution started...");
#endif

    data_data = gdbm_firstkey(myGlobals.addressQueueFile);

    while(data_data.dptr != NULL) {
      int size = data_data.dsize;
      if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN) return(NULL);
      if (size == sizeof(struct in_addr)) {
	/*addrput(AF_INET, &addr, data_data.dptr);*/
	addr.hostFamily = AF_INET;
	memcpy(&addr.Ip4Address.s_addr, data_data.dptr, size);
      }
#ifdef INET6
      else if (size == sizeof(struct in6_addr)) {
	addr.hostFamily = AF_INET6;
	memcpy(&addr.Ip6Address.s6_addr, data_data.dptr, size);
      }
#endif

      HEARTBEAT(2, "dequeueAddress()", NULL);

#ifdef DNS_DEBUG
      traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Dequeued address... [%s][key=%s] (#addr=%d)",
		 addrtostr(&addr), key_data.dptr == NULL ? "<>" : key_data.dptr,
		 myGlobals.addressQueuedCurrent);
#endif

      resolveAddress(&addr, 0);

#ifdef DNS_DEBUG
      traceEvent(CONST_TRACE_INFO, "DNS_DEBUG: Resolved address %s", addrtostr(&addr));
#endif

      myGlobals.addressQueuedCurrent--;
      gdbm_delete(myGlobals.addressQueueFile, data_data);
      key_data = data_data;
      data_data = gdbm_nextkey(myGlobals.addressQueueFile, key_data);
      free(key_data.dptr); /* Free the 'formed' data_data */
    }
  } /* endless loop */

  myGlobals.dequeueAddressThreadId[dqaIndex] = 0;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Address resolution(%d) thread terminated [p%d, t%lu]...",
             dqaIndex+1, getpid(), pthread_self());
  return(NULL); /* NOTREACHED */
}

#endif /* defined(CFG_MULTITHREADED) && defined(MAKE_ASYNC_ADDRESS_RESOLUTION) */
#endif

#ifdef INET6

/* ************************************ */

char* _intop(struct in6_addr *addr, char *buf, u_short buflen) {  
  return (char *)inet_ntop(AF_INET6, addr, buf, buflen); 
}

/* ************************************ */

char* intop(struct in6_addr *addr) {
  static char  ntop_buf[INET6_ADDRSTRLEN+1];
  
  memset(ntop_buf, 0, INET6_ADDRSTRLEN);
  return (char *)_intop(addr, ntop_buf,sizeof(ntop_buf)); 
}

#endif /*INET6 */

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
#ifdef INET6
  case AF_INET6:
    return(char *)(intop(&addr->Ip6Address));
#endif
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
#ifdef INET6
  case AF_INET6:
    return (_intop(&addr->Ip6Address,buf,bufLen));
#endif
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
#ifdef INET6
  case AF_INET6:
    if(_intop(&addr->Ip6Address, buf, bufLen) == NULL)
      BufferTooSmall(buf, bufLen);
    break;
#endif
  default:
    return("???");
  }

  return(buf);
}

/* ******************************* */

int fetchAddressFromCache(HostAddr hostIpAddress, char *buffer, int *type) {
  char keyBuf[LEN_ADDRESS_BUFFER];
  datum key_data;
  datum data_data;

  if(buffer == NULL) return(0);

  memset(&keyBuf, 0, sizeof(keyBuf));

  myGlobals.numFetchAddressFromCacheCalls++;

  if(addrfull(&hostIpAddress) || addrnull(&hostIpAddress)) {
    strcpy(buffer, "0.0.0.0");
    *type = FLAG_HOST_SYM_ADDR_TYPE_IP;
    return(0);
  }
     
  key_data.dptr = _addrtonum(&hostIpAddress,keyBuf, sizeof(keyBuf));
  key_data.dsize = strlen(key_data.dptr)+1;

  if(myGlobals.dnsCacheFile == NULL) return(0); /* ntop is quitting... */
  
  data_data = gdbm_fetch(myGlobals.dnsCacheFile, key_data);

  if((data_data.dptr != NULL) && (data_data.dsize == (sizeof(StoredAddress)+1)) ) {
    StoredAddress *retrievedAddress;
    
    retrievedAddress = (StoredAddress*)data_data.dptr;
    *type = retrievedAddress->symAddressType;

#ifdef GDBM_DEBUG
    traceEvent(CONST_TRACE_INFO, "GDBM_DEBUG: gdbm_fetch(..., {%s, %d}) = %s, age %d",
               key_data.dptr, key_data.dsize, 
               retrievedAddress->symAddress,
               myGlobals.actTime - retrievedAddress->recordCreationTime);
#endif

    if (myGlobals.actTime - retrievedAddress->recordCreationTime < CONST_DNSCACHE_LIFETIME) {
        myGlobals.numFetchAddressFromCacheCallsOK++;
        safe_snprintf(__FILE__, __LINE__, buffer, MAX_LEN_SYM_HOST_NAME, "%s", retrievedAddress->symAddress);
    } else {
        myGlobals.numFetchAddressFromCacheCallsSTALE++;
        buffer[0] = '\0';
    }

    free(data_data.dptr);
  } else {
    myGlobals.numFetchAddressFromCacheCallsFAIL++;
#ifdef GDBM_DEBUG
    if(data_data.dptr != NULL)
      traceEvent(CONST_TRACE_WARNING, "GDBM_DEBUG: Dropped data for %s [wrong data size]", keyBuf);
    else
      traceEvent(CONST_TRACE_WARNING, "GDBM_DEBUG: Unable to retrieve %s", keyBuf);
#endif

    buffer[0] = '\0';
    *type = FLAG_HOST_SYM_ADDR_TYPE_IP;
    /* It might be that the size of the retrieved data is wrong */
    if(data_data.dptr != NULL) free(data_data.dptr);
  }

#ifdef DEBUG
  {
    char buf[LEN_ADDRESS_BUFFER];
    traceEvent(CONST_TRACE_INFO, "fetchAddressFromCache(%s) returned '%s'",
               _addrtostr(&hostIpAddress, buf, sizeof(buf)), buffer);
  }
#endif

  return(1);
}

/* ******************************* */

/* This function automatically updates the instance name */

void ipaddr2str(HostAddr hostIpAddress, int updateHost) {
  char buf[MAX_LEN_SYM_HOST_NAME+1];
  int type;

  myGlobals.numipaddr2strCalls++;

  if(fetchAddressFromCache(hostIpAddress, buf, &type)  && (buf[0] != '\0')) {
    if(updateHost) updateHostNameInfo(hostIpAddress, buf, type);
  } else {
#if defined(CFG_MULTITHREADED) && defined(MAKE_ASYNC_ADDRESS_RESOLUTION)
    queueAddress(hostIpAddress, !updateHost);
#else
    resolveAddress(&hostIpAddress, 0);
#endif
  }
}

/* ************************************ */

char* etheraddr_string(const u_char *ep, char *buf) {
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
      char *a, *b, *c, *d, dnsBuf[48], *strtokState;
      unsigned long theDNSaddr;

      len = strlen((char*)bp); 
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

/* Align bp on u_int32_t boundary */
#if 0
    bp += (((u_int32_t)bp) % sizeof(u_int32_t));
#else
    {
      u_int32_t     padding;

      padding=((u_int32_t)bp) % sizeof(u_int32_t);
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

void checkSpoofing(HostTraffic *hostToCheck, int actualDeviceId) {
  HostTraffic *el;

  for(el=getFirstHost(actualDeviceId); 
      el != NULL; el = getNextHost(actualDeviceId, el)) {
    if((!addrnull(&el->hostIpAddress))
       && (addrcmp(&el->hostIpAddress,&hostToCheck->hostIpAddress) == 0)) {
      /* Spoofing detected */
      if((!hasDuplicatedMac(el))
	 && (!hasDuplicatedMac(hostToCheck))) {
	FD_SET(FLAG_HOST_DUPLICATED_MAC, &hostToCheck->flags);
	FD_SET(FLAG_HOST_DUPLICATED_MAC, &el->flags);

	if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	  traceEvent(CONST_TRACE_WARNING,
		     "Two MAC addresses found for the same IP address %s: [%s/%s] (spoofing detected?)",
		     el->hostNumIpAddress, hostToCheck->ethAddressString, el->ethAddressString);
	  dumpSuspiciousPacket(actualDeviceId);
	}
      }
    }
  }

}

