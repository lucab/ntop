/**
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


#include "ntop.h"
#include <stdarg.h>

#ifdef MEMORY_DEBUG
#include "leaks.h"
#endif

#ifdef CFG_MULTITHREADED
static char stateChangeMutexInitialized = 0;
static pthread_mutex_t stateChangeMutex;
#endif


static SessionInfo *passiveSessions;
static u_short numLocalNets=0, passiveSessionsLen;

/* [0]=network, [1]=mask, [2]=broadcast */
static u_int32_t networks[MAX_NUM_NETWORKS][3];

/* ************************************ */

u_int findHostIdxByNumIP(struct in_addr hostIpAddress, int actualDeviceId) {
  u_int idx;

  for(idx=1; idx<myGlobals.device[actualDeviceId].actualHashSize; idx++)
    if((myGlobals.device[actualDeviceId].hash_hostTraffic[idx] != NULL)
       && (myGlobals.device[actualDeviceId].hash_hostTraffic[idx]->hostNumIpAddress != NULL)
       && (myGlobals.device[actualDeviceId].hash_hostTraffic[idx]->hostIpAddress.s_addr == hostIpAddress.s_addr))
      return(idx);

  return(FLAG_NO_PEER);
}

/* ************************************ */

HostTraffic* findHostByNumIP(char* numIPaddr, int actualDeviceId) {
  u_int idx;

  for(idx=1; idx<myGlobals.device[actualDeviceId].actualHashSize; idx++)
    if((myGlobals.device[actualDeviceId].hash_hostTraffic[idx] != NULL)
       && (myGlobals.device[actualDeviceId].hash_hostTraffic[idx]->hostNumIpAddress != NULL)
       && (!strcmp(myGlobals.device[actualDeviceId].hash_hostTraffic[idx]->hostNumIpAddress, numIPaddr)))
      return(myGlobals.device[actualDeviceId].hash_hostTraffic[idx]);

  return(NULL);
}

/* ************************************ */

HostTraffic* findHostByMAC(char* macAddr, int actualDeviceId) {
  u_int idx;

  for(idx=1; idx<myGlobals.device[actualDeviceId].actualHashSize; idx++)
    if(myGlobals.device[actualDeviceId].hash_hostTraffic[idx]
       && myGlobals.device[actualDeviceId].hash_hostTraffic[idx]->hostNumIpAddress
       && (!strcmp(myGlobals.device[actualDeviceId].hash_hostTraffic[idx]->ethAddressString, macAddr)))
      return(myGlobals.device[actualDeviceId].hash_hostTraffic[idx]);

  return(NULL);
}

/* ************************************ */

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
    traceEvent(CONST_TRACE_INFO, "copy_argv: malloc");
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

/* ********************************* */

unsigned short isBroadcastAddress(struct in_addr *addr) {
  int i;

  if(addr == NULL)
    return 1;
  else if(addr->s_addr == 0x0)
    return 0; /* IP-less myGlobals.device (is it trying to boot via DHCP/BOOTP ?) */
  else {
    for(i=0; i<myGlobals.numDevices; i++)
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

    return(isPseudoBroadcastAddress(addr));
  }
}

/* ********************************* */

unsigned short isMulticastAddress(struct in_addr *addr) {
  if((addr->s_addr & CONST_MULTICAST_MASK) == CONST_MULTICAST_MASK) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: %s is multicast [%X/%X]\n",
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

unsigned short isLocalAddress(struct in_addr *addr) {
  int i;

  for(i=0; i<myGlobals.numDevices; i++)
    if((addr->s_addr & myGlobals.device[i].netmask.s_addr) == myGlobals.device[i].network.s_addr) {
#ifdef ADDRESS_DEBUG
      traceEvent(CONST_TRACE_INFO, "ADDRESS_DEBUG: %s is local\n", intoa(*addr));
#endif
      return 1;
    }

  if(myGlobals.trackOnlyLocalHosts)
    return(0);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: %s is %s\n", intoa(*addr),
	     isLocalAddress (addr) ? "pseudolocal" : "remote");
#endif
  /* Broadcast is considered a local address */
  return(isBroadcastAddress(addr));
}

/* ********************************* */

unsigned short isPrivateAddress(struct in_addr *addr) {

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
      traceEvent(CONST_TRACE_ERROR, "DEBUG: int2bits (%3d) = %d\n", number, CONST_INVALIDNETMASK);
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
	  traceEvent(CONST_TRACE_ERROR, "DEBUG: int2bits (%3d) = %d\n", number, CONST_INVALIDNETMASK);
#endif
	  return(CONST_INVALIDNETMASK);
	}
      else
	{
#ifdef DEBUG
	  traceEvent(CONST_TRACE_ERROR, "DEBUG: int2bits (%3d) = %d\n", number, bits);
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
      traceEvent(CONST_TRACE_ERROR, "DEBUG: dotted2bits (%s) = %d\n", mask, fields[0]);
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
	  traceEvent(CONST_TRACE_ERROR, "DEBUG: dotted2bits (%15s) = %d\n", mask, bits);
#endif
	  /* In this case we are in a bits (not dotted quad) notation */
	  return(bits /* fields[0] - L.Deri 08/2001 */);

	default:
	  bits += field_bits;
	}
    }
#ifdef DEBUG
  traceEvent(CONST_TRACE_ERROR, "DEBUG: dotted2bits (%15s) = %d\n", mask, bits);
#endif
  return(bits);
}

/* ********************************* */

/* Example: "131.114.0.0/16,193.43.104.0/255.255.255.0" */

void handleAddressLists(char* addresses, u_int32_t theNetworks[MAX_NUM_NETWORKS][3],
			u_short *numNetworks, char *localAddresses, int localAddressesLen) {
  char *strtokState, *address;
  int  laBufferPosition = 0, laBufferUsed = 0, i;

  if(addresses == NULL)
    return;

  memset(localAddresses, 0, localAddressesLen);

  address = strtok_r(addresses, ",", &strtokState);

  while(address != NULL) {
    char *mask = strchr(address, '/');

    if(mask == NULL)
      traceEvent(CONST_TRACE_INFO, "Unknown network '%s' (empty mask!). It has been ignored.\n",
		 address);
    else {
      u_int32_t network, networkMask, broadcast;
      int bits, a, b, c, d;

      mask[0] = '\0';
      mask++;
      bits = dotted2bits (mask);

      if(sscanf(address, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
	traceEvent(CONST_TRACE_ERROR, "Unknown network '%s' .. skipping. Check network numbers.\n",
		   address);
	address = strtok_r(NULL, ",", &strtokState);
	continue;
      }

      if(bits == CONST_INVALIDNETMASK) {
	/* malformed netmask specification */
	traceEvent(CONST_TRACE_ERROR,
		   "The specified netmask %s is not valid. Skipping it..\n",
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
      traceEvent(CONST_TRACE_INFO, "DEBUG: Nw=%08X - Mask: %08X [%08X]\n",
		 network, networkMask, (network & networkMask));
#endif

      if((networkMask >= 0xFFFFFF00) /* Courtesy of Roy-Magne Mo <romo@interpost.no> */
	 && ((network & networkMask) != network))  {
	/* malformed network specification */
	traceEvent(CONST_TRACE_ERROR, "WARNING: %d.%d.%d.%d/%d is not a valid network number\n",
		   a, b, c, d, bits);

	/* correcting network numbers as specified in the netmask */
	network &= networkMask;

	a = (int) ((network >> 24) & 0xff);
	b = (int) ((network >> 16) & 0xff);
	c = (int) ((network >>  8) & 0xff);
	d = (int) ((network >>  0) & 0xff);

	traceEvent(CONST_TRACE_ERROR, "Assuming %d.%d.%d.%d/%d [0x%08x/0x%08x]\n\n",
		   a, b, c, d, bits, network, networkMask);
      }
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: %d.%d.%d.%d/%d [0x%08x/0x%08x]\n",
		 a, b, c, d, bits, network, networkMask);
#endif

      broadcast = network | (~networkMask);

#ifdef DEBUG
      a = (int) ((broadcast >> 24) & 0xff);
      b = (int) ((broadcast >> 16) & 0xff);
      c = (int) ((broadcast >>  8) & 0xff);
      d = (int) ((broadcast >>  0) & 0xff);

      traceEvent(CONST_TRACE_INFO, "DEBUG: Broadcast: [net=0x%08x] [broadcast=%d.%d.%d.%d]\n",
		 network, a, b, c, d);
#endif

      if((*numNetworks) < MAX_NUM_NETWORKS) {
	int found = 0;

	for(i=0; i<myGlobals.numDevices; i++)
	  if((network == myGlobals.device[i].network.s_addr)
	     && (myGlobals.device[i].netmask.s_addr == networkMask)) {
	    a = (int) ((network >> 24) & 0xff);
	    b = (int) ((network >> 16) & 0xff);
	    c = (int) ((network >>  8) & 0xff);
	    d = (int) ((network >>  0) & 0xff);

	    traceEvent(CONST_TRACE_WARNING, "WARNING: Discarded network %d.%d.%d.%d/%d: "
		       "this is the local network.\n",
		       a, b, c, d, bits);
	    found = 1;
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
      } else
	traceEvent(CONST_TRACE_WARNING, "Unable to handle network (too many entries!).\n");
    }

    address = strtok_r(NULL, ",", &strtokState);
  }
}

/* ********************************* */

void handleLocalAddresses(char* addresses) {
  char localAddresses[1024];

  localAddresses[0] = '\0';

  handleAddressLists(addresses, networks, &numLocalNets,
		     localAddresses, sizeof(localAddresses));

  /* Not used anymore */
  if(myGlobals.localAddresses != NULL) free(myGlobals.localAddresses);
  myGlobals.localAddresses = strdup(localAddresses);
}

/* ********************************* */

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

    traceEvent(CONST_TRACE_INFO, "DEBUG: %s comparing [%s/%s]\n",
	       _intoa(*addr, buf, sizeof(buf)),
	       _intoa(addr1, buf1, sizeof(buf1)),
	       _intoa(addr2, buf2, sizeof(buf2)));
#endif
    if((addr->s_addr & theNetworks[i][CONST_NETMASK_ENTRY]) == theNetworks[i][CONST_NETWORK_ENTRY]) {
#ifdef ADDRESS_DEBUG
      traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is pseudolocal\n", intoa(*addr));
#endif
      return 1;
    } else {
#ifdef ADDRESS_DEBUG
      traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is NOT pseudolocal\n", intoa(*addr));
#endif
    }
  }

  return(0);
}

/* ********************************* */

unsigned short _pseudoLocalAddress(struct in_addr *addr) {
  return(__pseudoLocalAddress(addr, networks, numLocalNets));
}

/* ********************************* */

/* This function returns true when a host is considered local
   as specified using the 'm' flag */
unsigned short isPseudoLocalAddress(struct in_addr *addr) {
  int i;

  i = isLocalAddress(addr);

  if(i == 1) {
#ifdef ADDRESS_DEBUG
    traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is local\n", intoa(*addr));
#endif

    return 1; /* This is a real local address */
  }

  if(_pseudoLocalAddress(addr))
    return 1;

  /*
     We don't check for broadcast as this check has been
     performed already by isLocalAddress() just called
  */

#ifdef ADDRESS_DEBUG
    traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %s is remote\n", intoa(*addr));
#endif

  return(0);
}

/* ********************************* */

/* This function returns true when an address is the broadcast
   for the specified (-m flag subnets */

unsigned short isPseudoBroadcastAddress(struct in_addr *addr) {
  int i;

#ifdef ADDRESS_DEBUG
  traceEvent(CONST_TRACE_WARNING, "DEBUG: Checking %8X (pseudo broadcast)\n", addr->s_addr);
#endif

  for(i=0; i<numLocalNets; i++) {
    if(addr->s_addr == networks[i][CONST_BROADCAST_ENTRY]) {
#ifdef ADDRESS_DEBUG
      traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: --> %8X is pseudo broadcast\n", addr->s_addr);
#endif
      return 1;
    }
#ifdef ADDRESS_DEBUG
    else
      traceEvent(CONST_TRACE_WARNING, "ADDRESS_DEBUG: %8X/%8X is NOT pseudo broadcast\n", addr->s_addr, networks[i][CONST_BROADCAST_ENTRY]);
#endif
  }

  return(0);
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

/* Example: "flow1='host jake',flow2='dst host born2run'" */
void handleFlowsSpecs() {
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
      traceEvent(CONST_TRACE_INFO, "Error while stat() of %s\n", flows);

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
      traceEvent(CONST_TRACE_INFO, "Missing flow spec '%s'. It has been ignored.\n", flow);
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
		   "It has been ignored.\n", flowSpec);
      else {
	flowSpec[len-1] = '\0';
        flowSpec++;

        rc = pcap_compile(myGlobals.device[0].pcapPtr, &fcode, flowSpec, 1, myGlobals.device[0].netmask.s_addr);

        if(rc < 0)
          traceEvent(CONST_TRACE_INFO, "Wrong flow specification \"%s\" (syntax error). "
                     "It has been ignored.\n", flowSpec);
        else {
          FlowFilterList *newFlow;

          newFlow = (FlowFilterList*)calloc(1, sizeof(FlowFilterList));

          if(newFlow == NULL) {
            traceEvent(CONST_TRACE_INFO, "Fatal error: not enough memory. Bye!\n");
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
			   "It has been ignored.\n", flowSpec);
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
  traceEvent(CONST_TRACE_INFO, "DEBUG: Local address is: %s\n", intoa(*hostAddress));
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

    traceEvent(CONST_TRACE_INFO, "DEBUG: Num subnet hosts: %d\n", numHosts);
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
  myGlobals.numThreads++;
  return(rc);
}

/* ************************************ */

void killThread(pthread_t *threadId) {
  pthread_detach(*threadId);
  myGlobals.numThreads--;
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
               "ERROR: createMutex() call returned %d(%d) [%s:%d]\n",
               rc, errno, fileName, fileLine);
  } else {

      mutexId->isInitialized = 1;

  }

  return(rc);
}

/* ************************************ */

void _deleteMutex(PthreadMutex *mutexId, char* fileName, int fileLine) {

  if(mutexId == NULL) {
    traceEvent(CONST_TRACE_ERROR,
	       "ERROR: deleteMutex() call with a NULL mutex [%s:%d]\n",
	       fileName, fileLine);
    return;
  }

  if(!mutexId->isInitialized) {
    traceEvent(CONST_TRACE_ERROR,
	       "ERROR: deleteMutex() call with an UN-INITIALIZED mutex [%s:%d]\n",
	       fileName, fileLine);
    return;
  }

  pthread_mutex_unlock(&(mutexId->mutex));
  pthread_mutex_destroy(&(mutexId->mutex));

  memset(mutexId, 0, sizeof(PthreadMutex));
}

/* ************************************ */

int _accessMutex(PthreadMutex *mutexId, char* where,
		 char* fileName, int fileLine) {
  int rc;
  pid_t myPid;

  if(mutexId == NULL) {
    traceEvent(CONST_TRACE_ERROR,
	       "ERROR: accessMutex() call with a NULL mutex [%s:%d]\n",
	       fileName, fileLine);
    return(-1);
  }

  if(!mutexId->isInitialized) {
    traceEvent(CONST_TRACE_ERROR,
	       "ERROR: accessMutex() call with an UN-INITIALIZED mutex [%s:%d]\n",
	       fileName, fileLine);
    return(-1);
  }

#ifdef SEMAPHORE_DEBUG
  traceEvent(CONST_TRACE_INFO, "Locking 0x%X @ %s [%s:%d]\n",
	     &(mutexId->mutex), where, fileName, fileLine);
#endif
  myPid=getpid();
  if(mutexId->isLocked) {
    if((fileLine == mutexId->lockLine)       
       && (strcmp(fileName, mutexId->lockFile) == 0)
       && (myPid == mutexId->lockPid)) {
      traceEvent(CONST_TRACE_WARNING,
		 "WARNING: accessMutex() call with a self-LOCKED mutex [from %d at %s:%d %s]\n",
		 myPid, fileName, fileLine, where);
    }
  }

  strcpy(mutexId->lockAttemptFile, fileName);
  mutexId->lockAttemptLine=fileLine;
  mutexId->lockAttemptPid=myPid;

  rc = pthread_mutex_lock(&(mutexId->mutex));

  mutexId->lockAttemptFile[0] = '\0';
  mutexId->lockAttemptLine=0;
  mutexId->lockAttemptPid=(pid_t) 0;

  if(rc != 0)
    traceEvent(CONST_TRACE_ERROR, "ERROR: lock failed 0x%X [%s:%d] (rc=%d)\n",
	       (void*)&(mutexId->mutex), fileName, fileLine, rc);
  else {

#ifdef SEMAPHORE_DEBUG
    traceEvent(CONST_TRACE_INFO, "Locked 0x%X @ %s [%s:%d]\n",
               &(mutexId->mutex), where, fileName, fileLine);
#endif

    mutexId->numLocks++;
    pthread_mutex_lock(&stateChangeMutex);
    mutexId->isLocked = 1;
    mutexId->lockTime = time(NULL);
    mutexId->lockPid  = myPid;
    if(fileName != NULL) {
      strcpy(mutexId->lockFile, fileName);
      mutexId->lockLine = fileLine;
    }
    pthread_mutex_unlock(&stateChangeMutex);
    if(where != NULL) {
      strcpy(mutexId->where, where);
    }
  }

  return(rc);
}

/* ************************************ */

int _tryLockMutex(PthreadMutex *mutexId, char* where,
		  char* fileName, int fileLine) {
  int rc;
  pid_t myPid;

  if(mutexId == NULL) {
    traceEvent(CONST_TRACE_ERROR,
	       "ERROR: tryLockMutex() call with a NULL mutex [%s:%d]\n",
	       fileName, fileLine);
    return(-1);
  }

  if(!mutexId->isInitialized) {
    traceEvent(CONST_TRACE_ERROR,
	       "ERROR: tryLockMutex() call with an UN-INITIALIZED mutex [%s:%d]\n",
	       fileName, fileLine);
    return(-1);
  }

#ifdef SEMAPHORE_DEBUG
  traceEvent(CONST_TRACE_INFO, "Try to Lock 0x%X @ %s [%s:%d]\n",
	     mutexId, where, fileName, fileLine);
#endif

  myPid=getpid();
  if(mutexId->isLocked) {
      if ( (strcmp(fileName, mutexId->lockFile) == 0) && 
           (fileLine == mutexId->lockLine) &&
           (myPid == mutexId->lockPid) ) {
          traceEvent(CONST_TRACE_WARNING,
                     "WARNING: tryLockMutex() call with a self-LOCKED mutex [from %d at %s:%d %s]\n",
                     myPid, fileName, fileLine, where);
      }
  }

  strcpy(mutexId->lockAttemptFile, fileName);
  mutexId->lockAttemptLine=fileLine;
  mutexId->lockAttemptPid=myPid;

  /*
     Return code:

     0:    lock succesful
     EBUSY (mutex already locked)
  */
  rc = pthread_mutex_trylock(&(mutexId->mutex));

  mutexId->lockAttemptFile[0] = '\0';
  mutexId->lockAttemptLine=0;
  mutexId->lockAttemptPid=(pid_t) 0;

  if(rc != 0)
    traceEvent(CONST_TRACE_ERROR, "ERROR: tryLockMutex failed 0x%X [%s:%d] (rc=%d)\n",
	       (void*)&(mutexId->mutex), fileName, fileLine, rc);
  else {

#ifdef SEMAPHORE_DEBUG
    traceEvent(CONST_TRACE_INFO, "Locked 0x%X @ %s [%s:%d]\n",
               &(mutexId->mutex), where, fileName, fileLine);
#endif

    mutexId->numLocks++;
    pthread_mutex_lock(&stateChangeMutex);
    mutexId->isLocked = 1;
    pthread_mutex_unlock(&stateChangeMutex);
    mutexId->lockTime = time(NULL);
    mutexId->lockPid=myPid;
    if(fileName != NULL) {
      strcpy(mutexId->lockFile, fileName);
      mutexId->lockLine = fileLine;
    }
    if(where != NULL) {
      strcpy(mutexId->where, where);
    }
  }

  return(rc);
}

/* ************************************ */

int _isMutexLocked(PthreadMutex *mutexId, char* fileName, int fileLine) {
  int rc;

  if(mutexId == NULL) {
    traceEvent(CONST_TRACE_ERROR,
	       "ERROR: isMutexLocked() call with a NULL mutex [%s:%d]\n",
	       fileName, fileLine);
    return(-1);
  }

  if(!mutexId->isInitialized) {
    traceEvent(CONST_TRACE_ERROR,
	       "ERROR: isMutexLocked() call with an UN-INITIALIZED mutex [%s:%d]\n",
	       fileName, fileLine);
    return(-1);
  }

#ifdef SEMAPHORE_DEBUG
  traceEvent(CONST_TRACE_INFO, "Checking whether 0x%X is locked [%s:%d]\n",
	     &(mutexId->mutex), fileName, fileLine);
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
    traceEvent(CONST_TRACE_ERROR,
	       "ERROR: releaseMutex() call with a NULL mutex [%s:%d]\n",
	       fileName, fileLine);
    return(-1);
  }

  if(!mutexId->isInitialized) {
    traceEvent(CONST_TRACE_ERROR,
	       "ERROR: releaseMutex() call with an UN-INITIALIZED mutex [%s:%d]\n",
	       fileName, fileLine);
    return(-1);
  }

  pthread_mutex_lock(&stateChangeMutex);

  if(!mutexId->isLocked) {
    traceEvent(CONST_TRACE_WARNING,
	       "WARNING: releaseMutex() call with an UN-LOCKED mutex [%s:%d]\n",
	       fileName, fileLine);
  }

#ifdef SEMAPHORE_DEBUG
  traceEvent(CONST_TRACE_INFO, "Unlocking 0x%X [%s:%d]\n", &(mutexId->mutex), fileName, fileLine);
#endif
  rc = pthread_mutex_unlock(&(mutexId->mutex));
  pthread_mutex_unlock(&stateChangeMutex);

  if(rc != 0)
    traceEvent(CONST_TRACE_ERROR, "ERROR: unlock failed 0x%X [%s:%d]\n",
	       (void*)&(mutexId->mutex), fileName, fileLine);
  else {
    time_t lockDuration = time(NULL) - mutexId->lockTime;

    if((mutexId->maxLockedDuration < lockDuration)
       || (mutexId->maxLockedDurationUnlockLine == 0 /* Never set */)) {
      mutexId->maxLockedDuration = lockDuration;

      if(fileName != NULL) {
	strcpy(mutexId->maxLockedDurationUnlockFile, fileName);
	mutexId->maxLockedDurationUnlockLine = fileLine;
      }

#ifdef DEBUG
      if(mutexId->maxLockedDuration > 0) {
	traceEvent(CONST_TRACE_INFO, "DEBUG: semaphore 0x%X [%s:%d] locked for %d secs\n",
		   (void*)&(mutexId->mutex), fileName, fileLine,
		   mutexId->maxLockedDuration);
      }
#endif
   }

    /* traceEvent(CONST_TRACE_ERROR, "UNLOCKED 0x%X", &(mutexId->mutex));  */
    pthread_mutex_lock(&stateChangeMutex);
    mutexId->isLocked = 0;
    mutexId->lockLine = 0;
    pthread_mutex_unlock(&stateChangeMutex);
    mutexId->numReleases++;
    mutexId->unlockPid=getpid();
    if(fileName != NULL) {
      strcpy(mutexId->unlockFile, fileName);
      mutexId->unlockLine = fileLine;
    }
  }

#ifdef SEMAPHORE_DEBUG
  traceEvent(CONST_TRACE_INFO, "Unlocked 0x%X [%s:%d]\n",
	     &(mutexId->mutex), fileName, fileLine);
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

  if(rc != 0)
    traceEvent(CONST_TRACE_INFO, "waitSem failed [errno=%d]", errno);
}

/* ************************************ */

int incrementSem(sem_t *semId) {
  return(sem_post(semId));
}

/* ************************************ */
/* NOTE: As of 2.0.99RC2, this was determined to be dead code.
 *        It has been retained in the source for future use.
 *
 *        WARNING: The other semaphore routines - e.g. increment,
 *                 wait and delete ARE referenced?!
 *             Enabling semaphors will probably cause bugs!
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
               "External tool test failed(code=%d1%d). Disabling %s function (popen failed).\n",
               rc,
               errno,
               commandName);
    return 0;
  }

  rc = fgetc(fd);
  pclose(fd);

  if(rc == EOF) {
    traceEvent(CONST_TRACE_ERROR,
               "External tool test failed(code=%d20). Disabling %s function (tool won't run).\n",
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
                                 "External tool %s is suid root. FYI: This is good for ntop, but could be dangerous for the system!\n",
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
             "External tool test failed(code=%d%d%d). Disabling %s function%s.\n",
             rc,
             ecode,
             errno,
             commandName,
             ecode == 7 ? " (tool exists but is not suid root)" : "");
  return(0);

#endif
}

/* ************************************ */

void readLsofInfo(void) {
#ifdef WIN32
  ;
#else
  char line[384];
  FILE *fd;
  int i, j, found, portNumber, idx, processesIdx;
  int numLines, processSize, numRetries;
  unsigned int fdFileno;
  ProcessInfoList *listElement;
  ProcessInfo **tmpProcesses;
  fd_set mask;
  struct timeval wait_time;
  char fileName[NAME_MAX] = "/tmp/lsof-XXXXXX";
  FILE *fd1;
  time_t startTime = time(NULL);

  fd1 = getNewRandomFile(fileName, NAME_MAX);

  if(fd1 == NULL) {
    /* The warning message is returned by getNewRandomFile() */
    return;
  }

  fd = popen("lsof -i -n -w", "r");
#ifdef LSOF_DEBUG
  traceEvent(CONST_TRACE_INFO, "LSOF_DEBUG: Call to lsof returned %s\n", fd == NULL ? "error" : "ok");
#endif

  if(fd == NULL) {
    fclose(fd);
    myGlobals.isLsofPresent = 0;
    return;
  }

  numRetries = numLines = 0;
  fdFileno = fileno(fd);
  wait_time.tv_sec = 30, wait_time.tv_usec = 0;

  while(1) {
    FD_ZERO(&mask);
    FD_SET(fdFileno, &mask);

    if((i = select(fdFileno+1, &mask, 0, 0, &wait_time)) == 1) {
      if(fgets(line, 383, fd) != NULL) {
	numLines++;
	fprintf(fd1, "%s", line);
      } else
	break;
    } else {

      if((errno == 4 /* Interrupted system call */)
	 && (numRetries < 3) /* Avoid to loop */) {
	numRetries++;
      } else {
	traceEvent(CONST_TRACE_WARNING,
		   "WARNING: lsof() timeout (select=%d)(errno=%d: %s)",
		   i, errno, strerror(errno));
	pclose(fd);
	fclose(fd1);
	unlink(fileName);
	return;
      }
    }
  } /* while */

  pclose(fd);
  fclose(fd1);

  numLines--;

  if(numLines <= 0)
    return; /* No myGlobals.processes */

  fd = fopen(fileName, "r");
  if(fd == NULL) {
    traceEvent(CONST_TRACE_WARNING, "WARNING: unable to read lsof dump file");
    unlink(fileName);
    return;
  }

  /* ****************************************** */

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.lsofMutex, "readLsofInfo");
#endif

  for(i=0; i<myGlobals.numProcesses; i++)
    myGlobals.processes[i]->marker = 0;

  for(idx=0; idx<MAX_IP_PORT; idx++) {
    while(myGlobals.localPorts[idx] != NULL) {
      listElement = myGlobals.localPorts[idx]->next;
      free(myGlobals.localPorts[idx]);
      myGlobals.localPorts[idx] = listElement;
    }
  }

  memset(myGlobals.localPorts, 0, sizeof(myGlobals.localPorts)); /* Just to be sure... */

  fgets(line, 383, fd); /* Ignore 1st line */

  while(fgets(line, 383, fd) != NULL) {
    int pid;
    char command[32], user[32], *portNr;
    char *trailer, *thePort, *strtokState;

    /*traceEvent(CONST_TRACE_INFO, "%s\n", line); */

    /* Fix below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
    if(3 != sscanf(line, "%31[^ \t] %d %31[^ \t]", command, &pid, user))
      continue;

    if(strcmp(command, "lsof") == 0)
      continue;

    /* Either UDP or TCP */
    for(i=10; (line[i] != '\0'); i++)
      if((line[i] == 'P') && (line[i+1] == ' '))
	break;

    if(line[i] == '\0')
      continue;
    else
      trailer = &line[i+2];

    portNr = (char*)strtok_r(trailer, ":", &strtokState);

    if(portNr[0] == '*')
      portNr = &portNr[2];
    else
      portNr = (char*)strtok_r(NULL, "-", &strtokState);

    if((portNr == NULL) || (portNr[0] == '*'))
      continue;

    for(i=0, found = 0; i<myGlobals.numProcesses; i++) {
      if(myGlobals.processes[i]->pid == pid) {
	found = 1;
	myGlobals.processes[i]->marker = 1;
	break;
      }
    }

    thePort = strtok_r(portNr, " ", &strtokState);

    for(j=0; portNr[j] != '\0'; j++)
      if(!isalnum(portNr[j]) && portNr[j]!='-') {
	portNr[j] = '\0';
	break;
      }

    if(isdigit(portNr[0])) {
      portNumber = atoi(thePort);
    } else {
      portNumber = getAllPortByName(thePort);
    }

#ifdef LSOF_DEBUG
    traceEvent(CONST_TRACE_INFO, "LSOF_DEBUG: %s - %s - %s (%s/%d)\n",
	       command, user, thePort, portNr, portNumber);
#endif

    if(portNumber == -1)
      continue;

    if(!found) {
      int floater;

      if(myGlobals.numProcesses < MAX_NUM_PROCESSES_READLSOFINFO) {
	ProcessInfo **swapProcesses;

	swapProcesses = (ProcessInfo**)malloc((myGlobals.numProcesses+1)*sizeof(ProcessInfo*));
	if(myGlobals.numProcesses > 0)
	  memcpy(swapProcesses, myGlobals.processes, myGlobals.numProcesses*sizeof(ProcessInfo*));
	if(myGlobals.processes != NULL) free(myGlobals.processes);
	myGlobals.processes = swapProcesses;

#ifdef LSOF_DEBUG
	traceEvent(CONST_TRACE_INFO, "LSOF_DEBUG: %3d) %s %s %s/%d\n",
		   myGlobals.numProcesses, command, user, portNr, portNumber);
#endif
	myGlobals.processes[myGlobals.numProcesses] = (ProcessInfo*)malloc(sizeof(ProcessInfo));
	myGlobals.processes[myGlobals.numProcesses]->command             = strdup(command);
	myGlobals.processes[myGlobals.numProcesses]->user                = strdup(user);
	myGlobals.processes[myGlobals.numProcesses]->pid                 = pid;
	myGlobals.processes[myGlobals.numProcesses]->firstSeen           = myGlobals.actTime;
	myGlobals.processes[myGlobals.numProcesses]->lastSeen            = myGlobals.actTime;
	myGlobals.processes[myGlobals.numProcesses]->marker              = 1;
	resetTrafficCounter(&myGlobals.processes[myGlobals.numProcesses]->bytesSent);
	resetTrafficCounter(&myGlobals.processes[myGlobals.numProcesses]->bytesRcvd);
	myGlobals.processes[myGlobals.numProcesses]->contactedIpPeersIdx = 0;

	for(floater=0; floater<MAX_NUM_CONTACTED_PEERS; floater++)
	  myGlobals.processes[myGlobals.numProcesses]->contactedIpPeersIndexes[floater] = FLAG_NO_PEER;
      }

      idx = myGlobals.numProcesses;
      myGlobals.numProcesses++;
    } else
      idx = i;

    listElement = (ProcessInfoList*)malloc(sizeof(ProcessInfoList));
    listElement->element = myGlobals.processes[idx];
    listElement->next = myGlobals.localPorts[portNumber];
    myGlobals.localPorts[portNumber] = listElement;
  }

  fclose(fd);
  unlink(fileName);

  processSize = sizeof(ProcessInfo*)*myGlobals.numProcesses;
  tmpProcesses = (ProcessInfo**)malloc(processSize);

  memcpy(tmpProcesses, myGlobals.processes, processSize);
  memset(myGlobals.processes, 0, processSize);

  for(i=0, processesIdx=0; i<myGlobals.numProcesses; i++) {
    if(tmpProcesses[i]->marker == 0) {
      /* Free the process */
      free(tmpProcesses[i]->command);
      free(tmpProcesses[i]->user);
      free(tmpProcesses[i]);
    } else {
      myGlobals.processes[processesIdx++] = tmpProcesses[i];
    }
  }

  myGlobals.numProcesses = processesIdx;
  myGlobals.updateLsof = 0;

#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.lsofMutex);
#endif

  free(tmpProcesses);
#ifdef LSOF_DEBUG
  traceEvent(CONST_TRACE_INFO, "LSOF_DEBUG: readLsofInfo completed (%d sec).", (int)(time(NULL)-startTime));
#endif
#endif /* WIN32 */
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

char* getHostOS(char* ipAddr, int port _UNUSED_, char* additionalInfo) {
#ifdef WIN32
  return(NULL);
#else
  FILE *fd;
  char line[384], *operatingSystem=NULL;
  static char staticOsName[96];
  int len, found=0, sockFd;
  fd_set mask;
  struct timeval wait_time;

  if((!myGlobals.isNmapPresent) || (ipAddr[0] == '\0')) {
    return(NULL);
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: getHostOS(%s:%d)\n", ipAddr, port);
  traceEvent(CONST_TRACE_INFO, "DEBUG: Guessing OS of %s...\n", ipAddr);
#endif

  /* 548 is the AFP (Apple Filing Protocol) */
 if(snprintf(line, sizeof(line), "nmap -p 23,21,80,138,139,548 -O %s", ipAddr) < 0)
   BufferTooShort();

 fd = popen(line, "r");

  if(fd == NULL) {
    myGlobals.isNmapPresent = 0;
    return(NULL);
  } else
    sockFd = fileno(fd);

  if(additionalInfo != NULL) additionalInfo[0]='\0';

  while(1) {
    FD_ZERO(&mask);
    FD_SET(sockFd, &mask);
    wait_time.tv_sec = PARM_PIPE_READ_TIMEOUT, wait_time.tv_usec = 0;

    if(select(sockFd+1, &mask, 0, 0, &wait_time) == 0) {
      break; /* Timeout */
    }

    if((operatingSystem = fgets(line, sizeof(line)-1, fd)) == NULL)
      break;

    len = strlen(operatingSystem);
    if ((operatingSystem[len-1] == '\n') || (operatingSystem[len-1] == '\r'))
      operatingSystem[len-1] = '\0';	/* strip NL or CR from end-of-line */

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: '%s'\n", line);
#endif

    if(strncmp(operatingSystem, CONST_OS_GUESS, strlen(CONST_OS_GUESS)) == 0) {
      operatingSystem = &operatingSystem[strlen(CONST_OS_GUESS)];
      found = 1;
      break;
    }

    /* Patches below courtesy of
       Valeri V. Parchine <valeri@com-con.com> */

    if((!found) &&
       (strncmp(operatingSystem, CONST_OS_GUESS_1, strlen(CONST_OS_GUESS_1)) == 0)) {
      operatingSystem = &operatingSystem[strlen(CONST_OS_GUESS_1)];
      found = 1;
      break;
    }

    if((!found) &&
       (strncmp(operatingSystem, CONST_OS_GUESS_2, strlen(CONST_OS_GUESS_2)) == 0)) {
      operatingSystem = &operatingSystem[strlen(CONST_OS_GUESS_2)];
      found = 1;
      break;
    }

    if(additionalInfo != NULL) {
      if(isdigit(operatingSystem[0])) {
	strcat(additionalInfo, operatingSystem);
	strcat(additionalInfo, "<BR>\n");
      }

      /*traceEvent(CONST_TRACE_INFO, "> %s\n", operatingSystem); */
    }
  }

  memset(staticOsName, 0, sizeof(staticOsName));

  if(found) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: OS is: '%s'\n", operatingSystem);
#endif
    len = strlen(operatingSystem);
    strncpy(staticOsName, operatingSystem, len-1);
  }

   memset(staticOsName, 0, sizeof(staticOsName));
   if(found) {
     len = strlen(operatingSystem);
     strncpy(staticOsName, operatingSystem, len);
     staticOsName[sizeof(staticOsName)-1] = '\0';
#ifdef DEBUG
     traceEvent(CONST_TRACE_INFO, "DEBUG: OS is: '%s'\n", operatingSystem);
#endif
   }

  /* Read remaining data (if any) */
  while(1) {
    FD_ZERO(&mask);
    FD_SET(sockFd, &mask);
    wait_time.tv_sec = PARM_PIPE_READ_TIMEOUT; wait_time.tv_usec = 0;

    if(select(sockFd+1, &mask, 0, 0, &wait_time) == 0) {
      break; /* Timeout */
    }

    if(fgets(line, sizeof(line)-1, fd) == NULL)
      break;
#ifdef DEBUG
    else printf("DEBUG: Garbage: '%s'\n",  line);
#endif
  }
  pclose(fd);

  return(staticOsName);
#endif /* WIN32 */
}

/* ************************************* */

void closeNwSocket(int *sockId) {
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Closing socket %d...\n", *sockId);
#endif

  if(*sockId == FLAG_DUMMY_SOCKET)
    return;

#ifdef HAVE_OPENSSL
  if(*sockId < 0)
    term_ssl_connection(-(*sockId));
  else
    closesocket(*sockId);
#else
  closesocket(*sockId);
#endif

  *sockId = FLAG_DUMMY_SOCKET;
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
    traceEvent(CONST_TRACE_WARNING, "WARNING: name_interpret error (numBytes=%d)", numBytes);
    return(-1);
  }

  len = (*in++)/2;
  b  = out;
  *out=0;

  if(len > 30 || len < 1) {
    traceEvent(CONST_TRACE_WARNING, "WARNING: name_interpret error (numBytes=%d)", numBytes);
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

char* formatTime(time_t *theTime, short encodeString) {
  static char outStr[2][LEN_TIMEFORMAT_BUFFER];
  static short timeBufIdx=0;
  struct tm *locTime;
  struct tm myLocTime;

  locTime = localtime_r(theTime, &myLocTime);

  timeBufIdx = (timeBufIdx+1)%2;

  if(encodeString)
    strftime(outStr[timeBufIdx], LEN_TIMEFORMAT_BUFFER, "%x&nbsp;%X", locTime);
  else
    strftime(outStr[timeBufIdx], LEN_TIMEFORMAT_BUFFER, "%x %X", locTime);

  return(outStr[timeBufIdx]);
}

/* ************************************ */

int getActualInterface(int deviceId) {
  if(myGlobals.mergeInterfaces)
    return(0);
  else
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
  el->fullDomainName = NULL;
  el->dotDomainName = NULL;
  el->hostSymIpAddress[0] = '\0';
  el->osName = NULL;
  el->nonIPTraffic = NULL;
  el->routedTraffic = NULL;
  el->portsUsage = NULL;
  el->protoIPTrafficInfos = NULL;
  el->tcpSessionList = NULL;
  el->udpSessionList = NULL;
  el->icmpInfo = NULL;
  el->protocolInfo = NULL;

  resetUsageCounter(&el->contactedSentPeers);
  resetUsageCounter(&el->contactedRcvdPeers);
  resetUsageCounter(&el->contactedRouters);

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
  traceEvent(CONST_TRACE_INFO, "DEBUG: addTimeMapping(0x%X)\n", transactionId);
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
  traceEvent(CONST_TRACE_INFO, "DEBUG: getTimeMapping(0x%X)\n", transactionId);
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
      traceEvent(CONST_TRACE_INFO, "DEBUG: getTimeMapping(0x%X) [diff=%d]\n",
		 transactionId, (unsigned long)msDiff);
#endif
      return(msDiff);
    }

    idx = (idx+1) % CONST_NUM_TRANSACTION_ENTRIES;
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: getTimeMapping(0x%X) [not found]\n", transactionId);
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
    char theDate[32];
    char buf[LEN_GENERAL_WORK_BUFFER];
    time_t theTime = time(NULL);
    struct tm t;

/* We have two paths - one if we're logging, one if we aren't
 *   Note that the no-log case is those systems which don't support it (WIN32),
 *                                those without the headers !defined(MAKE_WITH_SYSLOG)
 *                                those where it's parametrically off...
 */

        memset(buf, 0, LEN_GENERAL_WORK_BUFFER);

#if defined(WIN32) || !defined(MAKE_WITH_SYSLOG)

        strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime, &t));
        if(myGlobals.traceLevel == CONST_DETAIL_TRACE_LEVEL) {
                printf("%s [%s:%d] ", theDate, file, line);
        } else {
                printf("%s ", theDate);
        }

#if defined(WIN32)
        /* Windows lacks vsnprintf */
        vsprintf(buf, format, va_ap);
#else /* WIN32 - vsnprintf */
        vsnprintf(buf, LEN_GENERAL_WORK_BUFFER-1, format, va_ap);
#endif /* WIN32 - vsnprintf */

	printf("%s%s", buf, (format[strlen(format)-1] != '\n') ? "\n" : "");
	fflush(stdout);

#else /* WIN32 || !MAKE_WITH_SYSLOG */

       	vsnprintf(buf, LEN_GENERAL_WORK_BUFFER-1, format, va_ap);

	if(myGlobals.useSyslog != FLAG_SYSLOG_NONE) {

		openlog("ntop", LOG_PID, myGlobals.useSyslog);

		/* syslog(..) call fix courtesy of Peter Suschlik <peter@zilium.de> */
	    #if (0)
		switch(myGlobals.traceLevel) {
		  case 0:
			syslog(LOG_ERR, "%s", buf);
			break;
		  case 1:
			syslog(LOG_WARNING, "%s", buf);
			break;
		  case 2:
			syslog(LOG_NOTICE, "%s", buf);
			break;
		  default:
			syslog(LOG_INFO, "%s", buf);
			break;
		}
	    #else
		syslog(LOG_ERR, "%s", buf);
	    #endif
		closelog();

	} else {

        	strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime, &t));
	        if(myGlobals.traceLevel == CONST_DETAIL_TRACE_LEVEL) {
        	        printf("%s [%s:%d] ", theDate, file, line);
	        } else {
        	        printf("%s ", theDate);
	        }

		printf("%s%s", buf, (format[strlen(format)-1] != '\n') ? "\n" : "");
		fflush(stdout);

	}
#endif /* WIN32 || !MAKE_WITH_SYSLOG */

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

#ifdef HAVE_GDBM_H
  if((hostNumIpAddress[0] != '\0') && myGlobals.gdbm_file) {
    datum key;
    datum data;

    key.dptr = hostNumIpAddress;
    key.dsize = strlen(key.dptr)+1;

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.gdbmMutex, "getSniffedDNSName");
#endif
    data = gdbm_fetch(myGlobals.gdbm_file, key);
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.gdbmMutex);
#endif

    if(data.dptr != NULL) {
      xstrncpy(name, data.dptr, maxNameLen);
      free(data.dptr);
      found = 1;
    }
  }
#endif
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
  sprintf(fileName, "%s-%lu", tmpFileName, myGlobals.numHandledHTTPrequests);
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
    traceEvent(CONST_TRACE_ERROR, "FATAL ERROR: Invalid string specified.");
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
    traceEvent(CONST_TRACE_ERROR, "FATAL ERROR: Invalid string '%s' specified.",
	       string);
    exit(-1);
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
    traceEvent(CONST_TRACE_ERROR, "FATAL ERROR: Invalid device specified.");
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

  if(theDomainHasBeenComputed(el)
     || (el->hostSymIpAddress    == NULL)
     || (el->hostSymIpAddress[0] == '\0'))
    return;

#if defined(CFG_MULTITHREADED) && defined(MAKE_ASYNC_ADDRESS_RESOLUTION)
  if(myGlobals.numericFlag == 0)
    accessMutex(&myGlobals.addressResolutionMutex, "fillDomainName");
#endif

  if((el->hostSymIpAddress[0] == '*')
     || (el->hostNumIpAddress[0] == '\0')
     || (isdigit(el->hostSymIpAddress[strlen(el->hostSymIpAddress)-1]) &&
	 isdigit(el->hostSymIpAddress[0]))) {
    /* NOTE: theDomainHasBeenComputed(el) = 0 */
    el->fullDomainName = el->dotDomainName = "";
#if defined(CFG_MULTITHREADED) && defined(MAKE_ASYNC_ADDRESS_RESOLUTION)
    if(myGlobals.numericFlag == 0)
      releaseMutex(&myGlobals.addressResolutionMutex);
#endif
    return;
  }

  FD_SET(FLAG_THE_DOMAIN_HAS_BEEN_COMPUTED, &el->flags);
  el->fullDomainName = el->dotDomainName = ""; /* Reset values... */

  i = strlen(el->hostSymIpAddress)-1;

  while(i > 0)
    if(el->hostSymIpAddress[i] == '.')
      break;
    else
      i--;

  if((i > 0)
     && strcmp(el->hostSymIpAddress, el->hostNumIpAddress)
     && (strlen(el->hostSymIpAddress) > (i+1)))
    el->dotDomainName = &el->hostSymIpAddress[i+1];
  else {
    /* Let's use the local domain name */
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: '%s' [%s/%s]\n",
	   el->hostSymIpAddress, myGlobals.domainName, myGlobals.shortDomainName);
#endif
    if((myGlobals.domainName[0] != '\0')
       && (strcmp(el->hostSymIpAddress, el->hostNumIpAddress))) {
      int len  = strlen(el->hostSymIpAddress);
      int len1 = strlen(myGlobals.domainName);

      /* traceEvent(CONST_TRACE_INFO, "%s [%s]\n",
	 el->hostSymIpAddress, &el->hostSymIpAddress[len-len1]); */

      if((len > len1)
	 && (strcmp(&el->hostSymIpAddress[len-len1-1], myGlobals.domainName) == 0))
	el->hostSymIpAddress[len-len1-1] = '\0';

      el->fullDomainName = myGlobals.domainName;
      el->dotDomainName = myGlobals.shortDomainName;
    } else {
      el->fullDomainName = el->dotDomainName = "";
    }

#if defined(CFG_MULTITHREADED) && defined(MAKE_ASYNC_ADDRESS_RESOLUTION)
    if(myGlobals.numericFlag == 0)
      releaseMutex(&myGlobals.addressResolutionMutex);
#endif
    return;
  }

  for(i=0; el->hostSymIpAddress[i] != '\0'; i++)
    el->hostSymIpAddress[i] = tolower(el->hostSymIpAddress[i]);

  i = 0;
  while(el->hostSymIpAddress[i] != '\0')
    if(el->hostSymIpAddress[i] == '.')
      break;
    else
      i++;

  if((el->hostSymIpAddress[i] == '.')
	 && (strlen(el->hostSymIpAddress) > (i+1)))
    el->fullDomainName = &el->hostSymIpAddress[i+1];

  /* traceEvent(CONST_TRACE_INFO, "'%s'\n", el->domainName); */

#if defined(CFG_MULTITHREADED) && defined(MAKE_ASYNC_ADDRESS_RESOLUTION)
  if(myGlobals.numericFlag == 0)
    releaseMutex(&myGlobals.addressResolutionMutex);
#endif
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

void setNBnodeNameType(HostTraffic *theHost,
		       char nodeType, char* nbName) {
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
  case 0x20: /* Server */
    if(theHost->nonIPTraffic->nbHostName == NULL) {
      theHost->nonIPTraffic->nbHostName = strdup(nbName);
      updateHostName(theHost);

      if(theHost->hostSymIpAddress[0] == '\0')
	strcpy(theHost->hostSymIpAddress, nbName); /* See up (**) */

#ifdef DEBUG
      printf("DEBUG: nbHostName=%s [0x%X]\n", nbName, nodeType);
#endif
    }
    break;
  case 0x1C: /* Domain Controller */
  case 0x1E: /* Domain */
  case 0x1D: /* Workgroup (I think) */
    if(theHost->nonIPTraffic->nbDomainName == NULL) {
      if(strcmp(nbName, "__MSBROWSE__") && strncmp(&nbName[2], "__", 2)) {
	theHost->nonIPTraffic->nbDomainName = strdup(nbName);
      }
      break;
    }
  }

  switch(nodeType) {
  case 0x0:  /* Workstation */
    FD_SET(FLAG_HOST_TYPE_WORKSTATION, &theHost->flags);
  case 0x20: /* Server */
    FD_SET(FLAG_HOST_TYPE_SERVER, &theHost->flags);
  case 0x1B: /* Master Browser */
    FD_SET(FLAG_HOST_TYPE_MASTER_BROWSER, &theHost->flags);
  }
}

/* ******************************************* */

void addPassiveSessionInfo(u_long theHost, u_short thePort) {
  int i;
  time_t timeoutTime = myGlobals.actTime - PARM_PASSIVE_SESSION_MINIMUM_IDLE;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Adding %ld:%d", theHost, thePort);
#endif

  for(i=0; i<passiveSessionsLen; i++) {
    if((passiveSessions[i].sessionPort == 0)
       || (passiveSessions[i].creationTime < timeoutTime)) {
      passiveSessions[i].sessionHost.s_addr = theHost,
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
    passiveSessions[passiveSessionsLen-1].sessionHost.s_addr = theHost,
      passiveSessions[passiveSessionsLen-1].sessionPort = thePort;
  }
}

/* ******************************************* */

int isPassiveSession(u_long theHost, u_short thePort) {
  int i;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Searching for %ld:%d",
	     theHost, thePort);
#endif

  for(i=0; i<passiveSessionsLen; i++) {
    if((passiveSessions[i].sessionHost.s_addr == theHost)
       && (passiveSessions[i].sessionPort == thePort)) {
      passiveSessions[i].sessionHost.s_addr = 0,
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

void initPassiveSessions() {
  int len;

  len = sizeof(SessionInfo)*MAX_PASSIVE_FTP_SESSION_TRACKER;
  passiveSessions = (SessionInfo*)malloc(len);
  memset(passiveSessions, 0, len);
  passiveSessionsLen = MAX_PASSIVE_FTP_SESSION_TRACKER;
}

/* ******************************* */

void termPassiveSessions() {
  if(myGlobals.enableSessionHandling)
    free(passiveSessions);
}

/* ******************************* */

int getPortByName(ServiceEntry **theSvc, char* portName) {
  int idx;

  for(idx=0; idx<myGlobals.numActServices; idx++) {

#ifdef DEBUG
    if(theSvc[idx] != NULL)
      traceEvent(CONST_TRACE_INFO, "DEBUG: %d/%s [%s]\n",
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

char* getAllPortByNum(int port) {
  char* rsp;
  static char staticBuffer[2][16];
  static short portBufIdx=0;

  rsp = getPortByNumber(myGlobals.tcpSvc, port); /* Try TCP first... */
  if(rsp == NULL)
    rsp = getPortByNumber(myGlobals.udpSvc, port);  /* ...then UDP */

  if(rsp != NULL)
    return(rsp);
  else {
    portBufIdx = (short)((portBufIdx+1)%2);
    if(snprintf(staticBuffer[portBufIdx], 16, "%d", port) < 0)
      BufferTooShort();
    return(staticBuffer[portBufIdx]);
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
    } else
      idx = (idx+1) % myGlobals.numActServices;
  }
}

/* ******************************* */

void resetUsageCounter(UsageCounter *counter) {
  int i;

  memset(counter, 0, sizeof(UsageCounter));

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
    counter->peersIndexes[i] = FLAG_NO_PEER;
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
  resetUsageCounter(&el->secHostPkts->ackScanSent);
  resetUsageCounter(&el->secHostPkts->xmasScanSent);
  resetUsageCounter(&el->secHostPkts->finScanSent);
  resetUsageCounter(&el->secHostPkts->nullScanSent);
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
  resetUsageCounter(&el->secHostPkts->ackScanRcvd);
  resetUsageCounter(&el->secHostPkts->xmasScanRcvd);
  resetUsageCounter(&el->secHostPkts->finScanRcvd);
  resetUsageCounter(&el->secHostPkts->nullScanRcvd);
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
    sprintf(icmpString, "%d", icmpType);
    return(icmpString);
  }
}

/* ************************************ */

void updateOSName(HostTraffic *el) {
  datum key_data, data_data;

  if(el->osName == NULL) {
    char *theName = NULL, tmpBuf[256];

    if(el->hostNumIpAddress[0] == '\0') {
      el->osName = strdup("");
      return;
    }

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: updateOSName(%s)\n", el->hostNumIpAddress);
#endif

    if(snprintf(tmpBuf, sizeof(tmpBuf), "@%s", el->hostNumIpAddress) < 0)
      BufferTooShort();
    key_data.dptr = tmpBuf;
    key_data.dsize = strlen(tmpBuf)+1;

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.gdbmMutex, "updateOSName");
#endif

    if(myGlobals.gdbm_file == NULL) {
#ifdef CFG_MULTITHREADED
      releaseMutex(&myGlobals.gdbmMutex);
#endif
      return; /* ntop is quitting... */
    }

    data_data = gdbm_fetch(myGlobals.gdbm_file, key_data);

#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.gdbmMutex);
#endif

    if(data_data.dptr != NULL) {
      strncpy(tmpBuf, data_data.dptr, sizeof(tmpBuf));
      free(data_data.dptr);
      theName = tmpBuf;
    }

    if((theName == NULL)
       && (subnetPseudoLocalHost(el)) /* Courtesy of Jan Johansson <j2@mupp.net> */)
      theName = getHostOS(el->hostNumIpAddress, -1, NULL);

    if(theName == NULL)
      el->osName = strdup("");
    else {
      el->osName = strdup(theName);

      if(snprintf(tmpBuf, sizeof(tmpBuf), "@%s", el->hostNumIpAddress) < 0)
	BufferTooShort();
      key_data.dptr = tmpBuf;
      key_data.dsize = strlen(tmpBuf)+1;
      data_data.dptr = el->osName;
      data_data.dsize = strlen(el->osName)+1;

      if(myGlobals.gdbm_file == NULL) return; /* ntop is quitting... */

#ifdef CFG_MULTITHREADED
      accessMutex(&myGlobals.gdbmMutex, "updateOSName");
#endif
      if(gdbm_store(myGlobals.gdbm_file, key_data, data_data, GDBM_REPLACE) != 0)
	printf("Error while adding myGlobals.osName for '%s'\n.\n", el->hostNumIpAddress);
      else {
#ifdef GDBM_DEBUG
	printf("GDBM_DEBUG: Added data: %s [%s]\n", tmpBuf, el->osName);
#endif
      }

#ifdef CFG_MULTITHREADED
      releaseMutex(&myGlobals.gdbmMutex);
#endif
    }
  }
}

/* ************************************ */

/* Do not delete this line! */
#undef incrementUsageCounter

int _incrementUsageCounter(UsageCounter *counter,
			   u_int peerIdx, int actualDeviceId,
			   char* file, int line) {
  u_int i, found=0;
  HostTraffic *theHost;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: incrementUsageCounter(%u) @ %s:%d",
	     peerIdx, file, line);
#endif

  if(peerIdx == FLAG_NO_PEER) return(0);

  if(peerIdx >= myGlobals.device[actualDeviceId].actualHashSize) {
    traceEvent(CONST_TRACE_WARNING, "WARNING: Index %u out of range [0..%u] @ %s:%d",
	       peerIdx, myGlobals.device[actualDeviceId].actualHashSize-1, file, line);
    return(0);
  }

  if((peerIdx == myGlobals.broadcastEntryIdx)
     || (peerIdx == myGlobals.otherHostEntryIdx)) {
    return(0);
  }

 if((theHost = myGlobals.device[actualDeviceId].
     hash_hostTraffic[checkSessionIdx(peerIdx)]) == NULL) {
    traceEvent(CONST_TRACE_WARNING, "WARNING: wrong Index %u @ %s:%d",
	       peerIdx, file, line);
    return(0);
 }

 counter->value.value++;

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
    if(counter->peersIndexes[i] == FLAG_NO_PEER) {
      counter->peersIndexes[i] = theHost->hostSerial;
      return(1);
      break;
    } else if(counter->peersIndexes[i] == theHost->hostSerial) {
      found = 1;
      break;
    }
  }

  if(!found) {
    for(i=0; i<MAX_NUM_CONTACTED_PEERS-1; i++)
      counter->peersIndexes[i] = counter->peersIndexes[i+1];

    /* Add host serial and not it's index */
    counter->peersIndexes[MAX_NUM_CONTACTED_PEERS-1] = theHost->hostSerial;
    return(1); /* New entry added */
  }

  return(0);
}

/* ******************************** */

int fetchPrefsValue(char *key, char *value, int valueLen) {
  datum key_data;
  datum data_data;

  if((value == NULL) || (!myGlobals.capturePackets)) return(-1);

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

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "fetchPrefValue");
#endif

  data_data = gdbm_fetch(myGlobals.prefsFile, key_data);

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1)
    releaseMutex(&myGlobals.gdbmMutex);
#endif

  memset(value, 0, valueLen);

  if(data_data.dptr != NULL) {
    if(snprintf(value, valueLen, "%s", data_data.dptr) < 0)
      BufferTooShort();
    if(data_data.dsize < valueLen) value[data_data.dsize] = '\0';
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

  if((value == NULL) || (!myGlobals.capturePackets)) return;

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

#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "storePrefsValue");
#endif

  if(gdbm_store(myGlobals.prefsFile, key_data, data_data, GDBM_REPLACE) != 0)
    traceEvent(CONST_TRACE_ERROR, "Error while adding %s=%s.", key, value);
  else {
    /* traceEvent(CONST_TRACE_INFO, "Storing %s=%s.", key, value); */
  }
#ifdef CFG_MULTITHREADED
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);
#endif
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

int ntop_sleep(int secs) {
  int unsleptTime = secs;

  while((unsleptTime = sleep(unsleptTime)) > 0)
    ;

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

static void updateElementHashItem(ElementHash **theHash,
		       u_short srcId, u_short dstId,
		       u_int32_t numPkts, u_int32_t numBytes, u_char dataSent) {
  u_int myIdx = 0, idx = srcId % MAX_ELEMENT_HASH;
  ElementHash *hash, *prev;

  while(1) {
    if((theHash[idx] == NULL) || (theHash[idx]->id == srcId))
      break;

    idx = (idx+1) % MAX_ELEMENT_HASH;
    if(++myIdx == MAX_ELEMENT_HASH) {
      traceEvent(CONST_TRACE_WARNING, "updateElementHash(): hash full!");
      return;
    }
  }

  if(theHash[idx] == NULL) {
    theHash[idx] = (ElementHash*)calloc(1, sizeof(ElementHash));
    theHash[idx]->id = srcId;
  }

  /* ************************** */

  hash = theHash[idx]->next, prev = theHash[idx];

  while(hash != NULL) {
    /* Keep the list sorted */
    if(hash->id >= dstId) {
      break;
    } else {
      prev = hash;
      hash = hash->next;
    }
  }

  if((hash == NULL) || (hash->id != dstId)) {
    ElementHash *bucket = (ElementHash*)calloc(1, sizeof(ElementHash));
    bucket->id = dstId;

    if(hash == NULL) {
      bucket->next = prev->next;
    } else {
      bucket->next = hash;
    }

    prev->next = bucket;
    hash = bucket;
  }

  if(dataSent) {
    incrementTrafficCounter(&theHash[idx]->bytesSent, numBytes);
    incrementTrafficCounter(&theHash[idx]->pktsSent,  numPkts);
    incrementTrafficCounter(&hash->bytesSent, numBytes);
    incrementTrafficCounter(&hash->pktsSent,  numPkts);
  }

  if((!dataSent)
     || (dataSent && (srcId == dstId) /* sender and receiver are the same */)) {
    incrementTrafficCounter(&theHash[idx]->bytesRcvd, numBytes);
    incrementTrafficCounter(&theHash[idx]->pktsRcvd,  numPkts);
    incrementTrafficCounter(&hash->bytesRcvd, numBytes);
    incrementTrafficCounter(&hash->pktsRcvd,  numPkts);
  }
}

/* ********************************** */

void updateElementHash(ElementHash **theHash,
		       u_short srcId, u_short dstId,
		       u_int32_t numPkts, u_int32_t numBytes) {

  if(srcId <= dstId)
    updateElementHashItem(theHash, srcId, dstId, numPkts, numBytes, 1);
  else
    updateElementHashItem(theHash, dstId, srcId, numPkts, numBytes, 0);
}

/* ********************************** */

void allocateElementHash(int deviceId, u_short hashType) {
  int memLen = sizeof(ElementHash*)*MAX_ELEMENT_HASH;

  switch(hashType) {
  case 0: /* AS */
    if(myGlobals.device[deviceId].asHash == NULL) {
      myGlobals.device[deviceId].asHash = (ElementHash**)malloc(memLen);
      memset(myGlobals.device[deviceId].asHash, 0, memLen);
    }
    break;
  case 1: /* VLAN */
    if(myGlobals.device[deviceId].vlanHash == NULL) {
      myGlobals.device[deviceId].vlanHash = (ElementHash**)malloc(memLen);
      memset(myGlobals.device[deviceId].vlanHash, 0, memLen);
    }
    break;
  }
}

/* *************************************************** */

u_int numActiveSenders(int deviceId) {
  u_int numSenders = 0;
  int i;

  for(i=1; i<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; i++) {
    HostTraffic *el;

    if((i == myGlobals.otherHostEntryIdx) || (i == myGlobals.broadcastEntryIdx)
       || ((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i]) == NULL)
       || broadcastHost(el)
       || (el->pktSent.value == 0))
      continue;
    numSenders++;
  }

  return(numSenders);
}

#ifndef WIN32

/* ********************************************************
 *  The following code is taken from GNU's gcc libiberty,
 *  a collection of extension and replacement routines
 *  designed to provide a more standard c library
 *  across multiple platforms.
 *
 *  gcc documentation is available online at
 *
 *       http://gcc.gnu.org/onlinedocs/
 *
 *  With libiberty's manual at
 *
 *  The copyright notice for libiberty is reproduced below.
 */

/*
         This file is part of the libiberty library.
         Libiberty is free software; you can redistribute it and/or
         modify it under the terms of the GNU Library General Public
         License as published by the Free Software Foundation; either
         version 2 of the License, or (at your option) any later version.

         Libiberty is distributed in the hope that it will be useful,
         but WITHOUT ANY WARRANTY; without even the implied warranty of
         MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
         Library General Public License for more details.

         You should have received a copy of the GNU Library General Public
         License along with libiberty; see the file COPYING.LIB.  If
         not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
         Boston, MA 02111-1307, USA.
 */

/*
 *  Specifically,
 *
 *     The getopt_long routine is from libiberty's getopt.c and getopt1.c
 *
            NOTE: This source is derived from an old version taken from the GNU C
            Library (glibc).
 *
 *     The argv[] routines are from libiberty's argv.c
 *
            Copyright (C) 1992, 2001 Free Software Foundation, Inc.
            Written by Fred Fish @ Cygnus Support
 *
 */

#ifndef HAVE_GETOPT_LONG

/*
 * If the OS doesn't have this, we define it and provide it - code from GNU libiberty
 *  (an optional part of gcc)
 */

# define SWAP_FLAGS(ch1, ch2)

#ifndef DARWIN
char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = '?';
#endif
int __getopt_initialized = 0;
static char *nextchar;


static enum
{
  REQUIRE_ORDER, PERMUTE, RETURN_IN_ORDER
} ordering;

/* Value of POSIXLY_CORRECT environment variable.  */
static char *posixly_correct;

static int first_nonopt;
static int last_nonopt;

static char *my_index (const char *str, int chr) {
  while (*str) {
      if (*str == chr)
          return (char *) str;
      str++;
  }
  return 0;
}

static void exchange (char **argv) {
  int bottom = first_nonopt;
  int middle = last_nonopt;
  int top = optind;
  char *tem;

  /* Exchange the shorter segment with the far end of the longer segment.
     That puts the shorter segment into the right place.
     It leaves the longer segment in the right place overall,
     but it consists of two parts that need to be swapped next.  */

  while (top > middle && middle > bottom)
    {
      if (top - middle > middle - bottom)
        {
          /* Bottom segment is the short one.  */
          int len = middle - bottom;
          register int i;

          /* Swap it with the top part of the top segment.  */
          for (i = 0; i < len; i++)
            {
              tem = argv[bottom + i];
              argv[bottom + i] = argv[top - (middle - bottom) + i];
              argv[top - (middle - bottom) + i] = tem;
              SWAP_FLAGS (bottom + i, top - (middle - bottom) + i);
            }
          /* Exclude the moved bottom segment from further swapping.  */
          top -= len;
        }
      else
        {
          /* Top segment is the short one.  */
          int len = top - middle;
          register int i;

          /* Swap it with the bottom part of the bottom segment.  */
          for (i = 0; i < len; i++)
            {
              tem = argv[bottom + i];
              argv[bottom + i] = argv[middle + i];
              argv[middle + i] = tem;
              SWAP_FLAGS (bottom + i, middle + i);
            }
          /* Exclude the moved top segment from further swapping.  */
          bottom += len;
        }
    }

  /* Update records for the slots the non-options now occupy.  */

  first_nonopt += (optind - last_nonopt);
  last_nonopt = optind;
}

/* Initialize the internal data when the first call is made.  */

static const char *_getopt_initialize (int argv, char *const *argc, const char *optstring) {
  /* Start processing options with ARGV-element 1 (since ARGV-element 0
     is the program name); the sequence of previously skipped
     non-option ARGV-elements is empty.  */

  first_nonopt = last_nonopt = optind;

  nextchar = NULL;

  posixly_correct = getenv ("POSIXLY_CORRECT");

  /* Determine how to handle the ordering of options and nonoptions.  */

  if (optstring[0] == '-')
    {
      ordering = RETURN_IN_ORDER;
      ++optstring;
    }
  else if (optstring[0] == '+')
    {
      ordering = REQUIRE_ORDER;
      ++optstring;
    }
  else if (posixly_correct != NULL)
    ordering = REQUIRE_ORDER;
  else
    ordering = PERMUTE;

  return optstring;
}

int _getopt_internal (argc, argv, optstring, longopts, longind, long_only)
     int argc;
     char *const *argv;
     const char *optstring;
     const struct option *longopts;
     int *longind;
     int long_only;
{
  optarg = NULL;

  if (optind == 0 || !__getopt_initialized)
    {
      if (optind == 0)
	optind = 1;	/* Don't scan ARGV[0], the program name.  */
      optstring = _getopt_initialize (argc, argv, optstring);
      __getopt_initialized = 1;
    }

# define NONOPTION_P (argv[optind][0] != '-' || argv[optind][1] == '\0')

  if (nextchar == NULL || *nextchar == '\0')
    {
      /* Advance to the next ARGV-element.  */

      /* Give FIRST_NONOPT & LAST_NONOPT rational values if OPTIND has been
	 moved back by the user (who may also have changed the arguments).  */
      if (last_nonopt > optind)
	last_nonopt = optind;
      if (first_nonopt > optind)
	first_nonopt = optind;

      if (ordering == PERMUTE)
	{
	  /* If we have just processed some options following some non-options,
	     exchange them so that the options come first.  */

	  if (first_nonopt != last_nonopt && last_nonopt != optind)
	    exchange ((char **) argv);
	  else if (last_nonopt != optind)
	    first_nonopt = optind;

	  /* Skip any additional non-options
	     and extend the range of non-options previously skipped.  */

	  while (optind < argc && NONOPTION_P)
	    optind++;
	  last_nonopt = optind;
	}

      /* The special ARGV-element `--' means premature end of options.
	 Skip it like a null option,
	 then exchange with previous non-options as if it were an option,
	 then skip everything else like a non-option.  */

      if (optind != argc && !strcmp (argv[optind], "--"))
	{
	  optind++;

	  if (first_nonopt != last_nonopt && last_nonopt != optind)
	    exchange ((char **) argv);
	  else if (first_nonopt == last_nonopt)
	    first_nonopt = optind;
	  last_nonopt = argc;

	  optind = argc;
	}

      /* If we have done all the ARGV-elements, stop the scan
	 and back over any non-options that we skipped and permuted.  */

      if (optind == argc)
	{
	  /* Set the next-arg-index to point at the non-options
	     that we previously skipped, so the caller will digest them.  */
	  if (first_nonopt != last_nonopt)
	    optind = first_nonopt;
	  return -1;
	}

      /* If we have come to a non-option and did not permute it,
	 either stop the scan or describe it to the caller and pass it by.  */

      if (NONOPTION_P)
	{
	  if (ordering == REQUIRE_ORDER)
	    return -1;
	  optarg = argv[optind++];
	  return 1;
	}

      /* We have found another option-ARGV-element.
	 Skip the initial punctuation.  */

      nextchar = (argv[optind] + 1
		  + (longopts != NULL && argv[optind][1] == '-'));
    }

  /* Decode the current option-ARGV-element.  */

  /* Check whether the ARGV-element is a long option.

     If long_only and the ARGV-element has the form "-f", where f is
     a valid short option, don't consider it an abbreviated form of
     a long option that starts with f.  Otherwise there would be no
     way to give the -f short option.

     On the other hand, if there's a long option "fubar" and
     the ARGV-element is "-fu", do consider that an abbreviation of
     the long option, just like "--fu", and not "-f" with arg "u".

     This distinction seems to be the most useful approach.  */

  if (longopts != NULL
      && (argv[optind][1] == '-'
	  || (long_only && (argv[optind][2] || !my_index (optstring, argv[optind][1])))))
    {
      char *nameend;
      const struct option *p;
      const struct option *pfound = NULL;
      int exact = 0;
      int ambig = 0;
      int indfound = -1;
      int option_index;

      for (nameend = nextchar; *nameend && *nameend != '='; nameend++)
	/* Do nothing.  */ ;

      /* Test all long options for either exact match
	 or abbreviated matches.  */
      for (p = longopts, option_index = 0; p->name; p++, option_index++)
	if (!strncmp (p->name, nextchar, nameend - nextchar))
	  {
	    if ((unsigned int) (nameend - nextchar)
		== (unsigned int) strlen (p->name))
	      {
		/* Exact match found.  */
		pfound = p;
		indfound = option_index;
		exact = 1;
		break;
	      }
	    else if (pfound == NULL)
	      {
		/* First nonexact match found.  */
		pfound = p;
		indfound = option_index;
	      }
	    else
	      /* Second or later nonexact match found.  */
	      ambig = 1;
	  }

      if (ambig && !exact)
	{
	  if (opterr)
	    fprintf (stderr, "%s: option `%s' is ambiguous\n",
		     argv[0], argv[optind]);
	  nextchar += strlen (nextchar);
	  optind++;
	  optopt = 0;
	  return '?';
	}

      if (pfound != NULL)
	{
	  option_index = indfound;
	  optind++;
	  if (*nameend)
	    {
	      /* Don't test has_arg with >, because some C compilers don't
		 allow it to be used on enums.  */
	      if (pfound->has_arg)
		optarg = nameend + 1;
	      else
		{
		  if (opterr)
		    {
		      if (argv[optind - 1][1] == '-')
			/* --option */
			fprintf (stderr,
				 "%s: option `--%s' doesn't allow an argument\n",
				 argv[0], pfound->name);
		      else
			/* +option or -option */
			fprintf (stderr,
				 "%s: option `%c%s' doesn't allow an argument\n",
				 argv[0], argv[optind - 1][0], pfound->name);

		      nextchar += strlen (nextchar);

		      optopt = pfound->val;
		      return '?';
		    }
		}
	    }
	  else if (pfound->has_arg == 1)
	    {
	      if (optind < argc)
		optarg = argv[optind++];
	      else
		{
		  if (opterr)
		    fprintf (stderr,
			   "%s: option `%s' requires an argument\n",
			   argv[0], argv[optind - 1]);
		  nextchar += strlen (nextchar);
		  optopt = pfound->val;
		  return optstring[0] == ':' ? ':' : '?';
		}
	    }
	  nextchar += strlen (nextchar);
	  if (longind != NULL)
	    *longind = option_index;
	  if (pfound->flag)
	    {
	      *(pfound->flag) = pfound->val;
	      return 0;
	    }
	  return pfound->val;
	}

      /* Can't find it as a long option.  If this is not getopt_long_only,
	 or the option starts with '--' or is not a valid short
	 option, then it's an error.
	 Otherwise interpret it as a short option.  */
      if (!long_only || argv[optind][1] == '-'
	  || my_index (optstring, *nextchar) == NULL)
	{
	  if (opterr)
	    {
	      if (argv[optind][1] == '-')
		/* --option */
		fprintf (stderr, "%s: unrecognized option `--%s'\n",
			 argv[0], nextchar);
	      else
		/* +option or -option */
		fprintf (stderr, "%s: unrecognized option `%c%s'\n",
			 argv[0], argv[optind][0], nextchar);
	    }
	  nextchar = (char *) "";
	  optind++;
	  optopt = 0;
	  return '?';
	}
    }

  /* Look at and handle the next short option-character.  */

  {
    char c = *nextchar++;
    char *temp = my_index (optstring, c);

    /* Increment `optind' when we start to process its last character.  */
    if (*nextchar == '\0')
      ++optind;

    if (temp == NULL || c == ':')
      {
	if (opterr)
	  {
	    if (posixly_correct)
	      /* 1003.2 specifies the format of this message.  */
	      fprintf (stderr, "%s: illegal option -- %c\n",
		       argv[0], c);
	    else
	      fprintf (stderr, "%s: invalid option -- %c\n",
		       argv[0], c);
	  }
	optopt = c;
	return '?';
      }
    /* Convenience. Treat POSIX -W foo same as long option --foo */
    if (temp[0] == 'W' && temp[1] == ';')
      {
	char *nameend;
	const struct option *p;
	const struct option *pfound = NULL;
	int exact = 0;
	int ambig = 0;
	int indfound = 0;
	int option_index;

	/* This is an option that requires an argument.  */
	if (*nextchar != '\0')
	  {
	    optarg = nextchar;
	    /* If we end this ARGV-element by taking the rest as an arg,
	       we must advance to the next element now.  */
	    optind++;
	  }
	else if (optind == argc)
	  {
	    if (opterr)
	      {
		/* 1003.2 specifies the format of this message.  */
		fprintf (stderr, "%s: option requires an argument -- %c\n",
			 argv[0], c);
	      }
	    optopt = c;
	    if (optstring[0] == ':')
	      c = ':';
	    else
	      c = '?';
	    return c;
	  }
	else
	  /* We already incremented `optind' once;
	     increment it again when taking next ARGV-elt as argument.  */
	  optarg = argv[optind++];

	/* optarg is now the argument, see if it's in the
	   table of longopts.  */

	for (nextchar = nameend = optarg; *nameend && *nameend != '='; nameend++)
	  /* Do nothing.  */ ;

	/* Test all long options for either exact match
	   or abbreviated matches.  */
	for (p = longopts, option_index = 0; p->name; p++, option_index++)
	  if (!strncmp (p->name, nextchar, nameend - nextchar))
	    {
	      if ((unsigned int) (nameend - nextchar) == strlen (p->name))
		{
		  /* Exact match found.  */
		  pfound = p;
		  indfound = option_index;
		  exact = 1;
		  break;
		}
	      else if (pfound == NULL)
		{
		  /* First nonexact match found.  */
		  pfound = p;
		  indfound = option_index;
		}
	      else
		/* Second or later nonexact match found.  */
		ambig = 1;
	    }
	if (ambig && !exact)
	  {
	    if (opterr)
	      fprintf (stderr, "%s: option `-W %s' is ambiguous\n",
		       argv[0], argv[optind]);
	    nextchar += strlen (nextchar);
	    optind++;
	    return '?';
	  }
	if (pfound != NULL)
	  {
	    option_index = indfound;
	    if (*nameend)
	      {
		/* Don't test has_arg with >, because some C compilers don't
		   allow it to be used on enums.  */
		if (pfound->has_arg)
		  optarg = nameend + 1;
		else
		  {
		    if (opterr)
		      fprintf (stderr, "%s: option `-W %s' doesn't allow an argument\n",
			       argv[0], pfound->name);

		    nextchar += strlen (nextchar);
		    return '?';
		  }
	      }
	    else if (pfound->has_arg == 1)
	      {
		if (optind < argc)
		  optarg = argv[optind++];
		else
		  {
		    if (opterr)
		      fprintf (stderr,
			       "%s: option `%s' requires an argument\n",
			       argv[0], argv[optind - 1]);
		    nextchar += strlen (nextchar);
		    return optstring[0] == ':' ? ':' : '?';
		  }
	      }
	    nextchar += strlen (nextchar);
	    if (longind != NULL)
	      *longind = option_index;
	    if (pfound->flag)
	      {
		*(pfound->flag) = pfound->val;
		return 0;
	      }
	    return pfound->val;
	  }
	  nextchar = NULL;
	  return 'W';	/* Let the application handle it.   */
      }
    if (temp[1] == ':')
      {
	if (temp[2] == ':')
	  {
	    /* This is an option that accepts an argument optionally.  */
	    if (*nextchar != '\0')
	      {
		optarg = nextchar;
		optind++;
	      }
	    else
	      optarg = NULL;
	    nextchar = NULL;
	  }
	else
	  {
	    /* This is an option that requires an argument.  */
	    if (*nextchar != '\0')
	      {
		optarg = nextchar;
		/* If we end this ARGV-element by taking the rest as an arg,
		   we must advance to the next element now.  */
		optind++;
	      }
	    else if (optind == argc)
	      {
		if (opterr)
		  {
		    /* 1003.2 specifies the format of this message.  */
		    fprintf (stderr,
			   "%s: option requires an argument -- %c\n",
			   argv[0], c);
		  }
		optopt = c;
		if (optstring[0] == ':')
		  c = ':';
		else
		  c = '?';
	      }
	    else
	      /* We already incremented `optind' once;
		 increment it again when taking next ARGV-elt as argument.  */
	      optarg = argv[optind++];
	    nextchar = NULL;
	  }
      }
    return c;
  }
}

int
getopt_long (int argc,
             char *const *argv,
             const char *options,
             const struct option *long_options,
             int *opt_index)
{
  return _getopt_internal (argc, argv, options, long_options, opt_index, 0);
}

#endif /* HAVE_GETOPT_LONG */

/*  Create and destroy argument vectors.  An argument vector is simply an
    array of string pointers, terminated by a NULL pointer. */


#ifndef HAVE_FREEARGV

/*
Free an argument vector that was built using buildargv.  Simply
scans through vector, freeing the memory for each argument until
the terminating NULL is found, and then frees vector
itself.
*/

void freeargv (char **vector) {
  register char **scan;

  if (vector != NULL)
    {
      for (scan = vector; *scan != NULL; scan++)
	{
	  free (*scan);
	}
      free (vector);
    }
}

#endif /* HAVE_FREEARGV */

#ifndef HAVE_BUILDARGV

/*
Given a pointer to a string, parse the string extracting fields
separated by whitespace and optionally enclosed within either single
or double quotes (which are stripped off), and build a vector of
pointers to copies of the string for each field.  The input string
remains unchanged.  The last element of the vector is followed by a
NULL element.

All of the memory for the pointer array and copies of the string
is obtained from malloc.  All of the memory can be returned to the
system with the single function call freeargv, which takes the
returned result of buildargv, as it's argument.

Returns a pointer to the argument vector if successful.  Returns
NULL if sp is NULL or if there is insufficient memory to complete
 building the argument vector. If the input is a null string (as
opposed to a NULL pointer), then buildarg returns an argument
vector that has one arg, a null string.

The memory for the argv array is dynamically expanded as necessary.

In order to provide a working buffer for extracting arguments into,
with appropriate stripping of quotes and translation of backslash
sequences, we allocate a working buffer at least as long as the input
string.  This ensures that we always have enough space in which to
work, since the extracted arg is never larger than the input string.

The argument vector is always kept terminated with a NULL arg
pointer, so it can be passed to freeargv at any time, or
returned, as appropriate.

*/

char **buildargv (const char *input) {
  char *arg;
  char *copybuf;
  int squote = 0;
  int dquote = 0;
  int bsquote = 0;
  int argc = 0;
  int maxargc = 0;
  char **argv = NULL;
  char **nargv;

  if (input != NULL)
    {
      copybuf = (char *) alloca (strlen (input) + 1);
      /* Is a do{}while to always execute the loop once.  Always return an
	 argv, even for null strings.  See NOTES above, test case below. */
      do
	{
	  /* Pick off argv[argc] */
	  while (ISBLANK (*input))
	    {
	      input++;
	    }
	  if ((maxargc == 0) || (argc >= (maxargc - 1)))
	    {
	      /* argv needs initialization, or expansion */
	      if (argv == NULL)
		{
		  maxargc = CONST_INITIAL_MAXARGC;
		  nargv = (char **) malloc (maxargc * sizeof (char *));
		}
	      else
		{
		  maxargc *= 2;
		  nargv = (char **) realloc (argv, maxargc * sizeof (char *));
		}
	      if (nargv == NULL)
		{
		  if (argv != NULL)
		    {
		      freeargv (argv);
		      argv = NULL;
		    }
		  break;
		}
	      argv = nargv;
	      argv[argc] = NULL;
	    }
	  /* Begin scanning arg */
	  arg = copybuf;
	  while (*input != '\0')
	    {
	      if (ISBLANK (*input) && !squote && !dquote && !bsquote)
		{
		  break;
		}
	      else
		{
		  if (bsquote)
		    {
		      bsquote = 0;
		      *arg++ = *input;
		    }
		  else if (*input == '\\')
		    {
			  bsquote = 1;
		    }
		  else if (squote)
		    {
		      if (*input == '\'')
			{
			  squote = 0;
			}
		      else
			{
			  *arg++ = *input;
			}
		    }
		  else if (dquote)
		    {
		      if (*input == '"')
			{
			  dquote = 0;
			}
		      else
			{
			  *arg++ = *input;
			}
		    }
		  else
		    {
		      if (*input == '\'')
			{
			  squote = 1;
			}
		      else if (*input == '"')
			{
			  dquote = 1;
			}
		      else
			{
			  *arg++ = *input;
			}
		    }
		  input++;
		}
	    }
	  *arg = '\0';
	  argv[argc] = strdup (copybuf);
	  if (argv[argc] == NULL)
	    {
	      freeargv (argv);
	      argv = NULL;
	      break;
	    }
	  argc++;
	  argv[argc] = NULL;

	  while (ISBLANK (*input))
	    {
	      input++;
	    }
	}
      while (*input != '\0');
    }
  return (argv);
}

#endif /* HAVE_BUILDARGV */

#endif /* WIN32*/

#ifdef PARM_SHOW_NTOP_HEARTBEAT
void _HEARTBEAT(int beatLevel, char* file, int line, char * format, ...) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  va_list va_ap;

  myGlobals.heartbeatCounter++;

  if ( (format != NULL) && (PARM_SHOW_NTOP_HEARTBEAT >= beatLevel) ) {
      memset(buf, 0, LEN_GENERAL_WORK_BUFFER);
      va_start (va_ap, format);
#if defined(WIN32)
      /* Windows lacks vsnprintf */
      vsprintf(buf, format, va_ap);
#else /* WIN32 - vsnprintf */
      vsnprintf(buf, LEN_GENERAL_WORK_BUFFER-1, format, va_ap);
#endif /* WIN32 - vsnprintf */
      va_end (va_ap);

      traceEvent(CONST_TRACE_INFO, "HEARTBEAT(%09u)[%s:%d]: %s\n", myGlobals.heartbeatCounter, file, line, buf);
  }
}
#endif
