/*
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

/* PPPoE - Courtesy of Andreas Pfaller Feb2003 */
#ifdef LINUX
 #include <linux/if_pppox.h>
#else
 /* Extracted and modified from the Linux header for other systems - BMS Mar2003 */
 struct pppoe_tag {
         u_int16_t tag_type;
         u_int16_t tag_len;
         char tag_data;
 };

 struct pppoe_hdr {
 #ifdef CFG_LITTLE_ENDIAN
         u_int8_t ver : 4;
         u_int8_t type : 4;
 #else
         u_int8_t type : 4;
         u_int8_t ver : 4;
 #endif
         u_int8_t code;
         u_int16_t sid;
         u_int16_t length;
         struct pppoe_tag tag;
 };
#endif

static const struct pcap_pkthdr *h_save;
static const u_char *p_save;
static u_char ethBroadcast[] = { 255, 255, 255, 255, 255, 255 };

/* ******************************* */

void allocateSecurityHostPkts(HostTraffic *srcHost) {
  if(srcHost->secHostPkts == NULL) {
    if ( (srcHost->secHostPkts = (SecurityHostProbes*)malloc(sizeof(SecurityHostProbes))) == NULL) return;
    resetSecurityHostTraffic(srcHost);
  }
}

/* ************************************ */

static void updateRoutedTraffic(HostTraffic *router) {
  if(router != NULL) {
    if(router->routedTraffic == NULL) {
      int mallocLen = sizeof(RoutingCounter);

      router->routedTraffic = (RoutingCounter*)malloc(mallocLen);
      memset(router->routedTraffic, 0, mallocLen);
    }

    if(router->routedTraffic != NULL) { /* malloc() didn't fail */
      incrementTrafficCounter(&router->routedTraffic->routedPkts, 1);
      incrementTrafficCounter(&router->routedTraffic->routedBytes, 
		  (Counter)(h_save->len - sizeof(struct ether_header)));
    }
  }
}

/* ************************************ */

int handleIP(u_short port,
	     HostTraffic *srcHost, HostTraffic *dstHost,
	     u_int _length,  u_short isPassiveSess,
	     u_short p2pSessionIdx,
	     int actualDeviceId) {
  int idx;
  Counter length = (Counter)_length;

  if((srcHost == NULL) || (dstHost == NULL)) {
    traceEvent(CONST_TRACE_ERROR, "Sanity check failed (4) [Low memory?]");
    return(-1);
  }

  if(isPassiveSess) {
    /* Emulate non passive session */
    idx = myGlobals.FTPIdx;
  } else {
    if(p2pSessionIdx) {
      switch(p2pSessionIdx) {
      case FLAG_P2P_GNUTELLA:
	idx = myGlobals.GnutellaIdx;
	break;
      case FLAG_P2P_KAZAA:
	idx = myGlobals.KazaaIdx;
	break;
      case FLAG_P2P_WINMX:
	idx = myGlobals.WinMXIdx;
	break;
      case FLAG_P2P_DIRECTCONNECT:
	idx = myGlobals.DirectConnectIdx;
	break;
      default:
	idx = -1;
	break;
      }
    } else 
      idx = mapGlobalToLocalIdx(port);
  }

  if(idx == -1)
    return(-1); /* Unable to locate requested index */
  else if (idx >= myGlobals.numIpProtosToMonitor) {
    traceEvent(CONST_TRACE_ERROR, "Discarding idx=%d for port=%d", idx, port);    
    return(-1);
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "port=%d - isPassiveSess=%d - p2pSessionIdx=%d - idx=%d", 
	     port, isPassiveSess, p2pSessionIdx, idx);
#endif

  if(idx != FLAG_NO_PEER) {
    if(subnetPseudoLocalHost(srcHost)) {
      if(subnetPseudoLocalHost(dstHost)) {
	if((!broadcastHost(srcHost)) && (srcHost->protoIPTrafficInfos != NULL))
	  incrementTrafficCounter(&srcHost->protoIPTrafficInfos[idx].sentLoc, length);
	if((!broadcastHost(dstHost)) && (dstHost->protoIPTrafficInfos != NULL))
	  incrementTrafficCounter(&dstHost->protoIPTrafficInfos[idx].rcvdLoc, length);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipProtoStats[idx].local, length);
      } else {
	if((!broadcastHost(srcHost)) && (srcHost->protoIPTrafficInfos != NULL))
	  incrementTrafficCounter(&srcHost->protoIPTrafficInfos[idx].sentRem, length);
	if((!broadcastHost(dstHost)) && (dstHost->protoIPTrafficInfos != NULL)) 
	  incrementTrafficCounter(&dstHost->protoIPTrafficInfos[idx].rcvdLoc, length);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipProtoStats[idx].local2remote, length);
      }
    } else {
      /* srcHost is remote */
      if(subnetPseudoLocalHost(dstHost)) {
	if((!broadcastHost(srcHost)) && (srcHost->protoIPTrafficInfos != NULL)) 
	  incrementTrafficCounter(&srcHost->protoIPTrafficInfos[idx].sentLoc, length);
	if((!broadcastHost(dstHost)) && (dstHost->protoIPTrafficInfos != NULL)) 
	  incrementTrafficCounter(&dstHost->protoIPTrafficInfos[idx].rcvdFromRem, length);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipProtoStats[idx].remote2local, length);
      } else {
	if((!broadcastHost(srcHost)) && (srcHost->protoIPTrafficInfos != NULL))
	  incrementTrafficCounter(&srcHost->protoIPTrafficInfos[idx].sentRem, length);
	if((!broadcastHost(dstHost)) && (dstHost->protoIPTrafficInfos != NULL))
	  incrementTrafficCounter(&dstHost->protoIPTrafficInfos[idx].rcvdFromRem, length);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipProtoStats[idx].remote, length);
      }
    }
  }

  return(idx);
}

/* ************************************ */

static void addContactedPeers(HostTraffic *sender, HostTraffic *receiver,
			      int actualDeviceId) {
  if((sender == NULL)
     || (receiver == NULL)
     || (sender->hostTrafficBucket == receiver->hostTrafficBucket)) {
    if((sender != NULL) && (sender->hostTrafficBucket == 0)) return; /* This is not a problem */
    traceEvent(CONST_TRACE_ERROR, "Sanity check failed @ addContactedPeers (0x%X, 0x%X)", sender, receiver);
    return;
  }
  
  if((!broadcastHost(sender))   
     && (sender->hostTrafficBucket != myGlobals.otherHostEntryIdx)
     && !broadcastHost(receiver)
     && (receiver->hostTrafficBucket != myGlobals.otherHostEntryIdx)) {
    sender->totContactedSentPeers += incrementUsageCounter(&sender->contactedSentPeers, 
							   receiver->hostTrafficBucket, actualDeviceId);
    receiver->totContactedRcvdPeers += incrementUsageCounter(&receiver->contactedRcvdPeers, 
							     sender->hostTrafficBucket, actualDeviceId);
  }
}

/* *****************************************
 *
 * Fragment handling code courtesy of
 * Andreas Pfaller <apfaller@yahoo.com.au>
 *
 * NOTE:
 * the code below has a small (neglictable) limitation
 * as described below.
 *
 * Subject: ntop 1.3.2: Fragment handling
 * Date:    Mon, 7 Aug 2000 16:05:45 +0200
 * From:    a.pfaller@pop.gun.de (Andreas Pfaller)
 *   To:    l.deri@tecsiel.it (Luca Deri)
 *
 * I have also had a look at the code you added to handle
 * overlapping  fragments. It again assumes specific package
 * ordering (either 1,2,..,n  or  n,n-1,..,1) which the IP protocol
 * does not guarantee. The above assumptions are probably true
 * for most users but in some setups they are nearly never true.
 * Consider two host connected by multiple network cards
 *
 * e.g.:
 *      +--------+ eth0         eth0 +--------+
 *      |        |-------------------|        |
 *      | HOST A |                   | HOST B |
 *      |        |-------------------|        |
 *      +--------+ eth1         eth1 +--------+
 *
 * which distribute traffic on this interfaces to achive better
 * throughput (Called bonding in Linux, Etherchannel by Cisco or
 * trunking by Sun). A simple algorithm simple uses the interfaces
 * in a cyclic way. Since packets are not always the same length
 * or the interfaces my have different speeds more complicated
 * ones use other methods to try to achive maximum throughput.
 * In such an environment you have very high probability for
 * out of order packets.
 *
 * ***************************************** */

#ifdef FRAGMENT_DEBUG
static void dumpFragmentData(IpFragment *fragment) {
  printf("FRAGMENT_DEBUG: IPFragment: (%p)\n", fragment);
  printf("                            %s:%d->%s:%d\n",
         fragment->src->hostSymIpAddress, fragment->sport,
         fragment->dest->hostSymIpAddress, fragment->dport);
  printf("                            FragmentId=%d\n", fragment->fragmentId);
  printf("                            lastOffset=%d, totalPacketLength=%d\n",
         fragment->lastOffset, fragment->totalPacketLength);
  printf("                             totalDataLength=%d, expectedDataLength=%d\n",
         fragment->totalDataLength, fragment->expectedDataLength);
  fflush(stdout);
}
#endif

/* ************************************ */

static IpFragment *searchFragment(HostTraffic *srcHost,
				  HostTraffic *dstHost,
				  u_int fragmentId,
				  int actualDeviceId) {
  IpFragment *fragment = myGlobals.device[actualDeviceId].fragmentList;

  while ((fragment != NULL)
         && ((fragment->src != srcHost)
	     || (fragment->dest != dstHost)
	     || (fragment->fragmentId != fragmentId)))
    fragment = fragment->next;

  return(fragment);
}

/* ************************************ */

void deleteFragment(IpFragment *fragment, int actualDeviceId) {

  if (fragment->prev == NULL)
    myGlobals.device[actualDeviceId].fragmentList = fragment->next;
  else
    fragment->prev->next = fragment->next;

  free(fragment);
}

/* ************************************ */

/* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
static void checkFragmentOverlap(u_int srcHostIdx,
                                 u_int dstHostIdx,
                                 IpFragment *fragment,
                                 u_int fragmentOffset,
                                 u_int dataLength,
				 int actualDeviceId) {
  if (fragment->fragmentOrder == FLAG_UNKNOWN_FRAGMENT_ORDER) {
    if(fragment->lastOffset > fragmentOffset)
      fragment->fragmentOrder = FLAG_DECREASING_FRAGMENT_ORDER;
    else
      fragment->fragmentOrder = FLAG_INCREASING_FRAGMENT_ORDER;
  }

  if ((fragment->fragmentOrder == FLAG_INCREASING_FRAGMENT_ORDER
       && fragment->lastOffset+fragment->lastDataLength > fragmentOffset)
      ||
      (fragment->fragmentOrder == FLAG_DECREASING_FRAGMENT_ORDER
       && fragment->lastOffset < fragmentOffset+dataLength)) {
    if(myGlobals.enableSuspiciousPacketDump) {
      char buf[LEN_GENERAL_WORK_BUFFER];
      snprintf(buf, LEN_GENERAL_WORK_BUFFER, "Detected overlapping packet fragment [%s->%s]: "
               "fragment id=%d, actual offset=%d, previous offset=%d\n",
               fragment->src->hostSymIpAddress,
               fragment->dest->hostSymIpAddress,
               fragment->fragmentId, fragmentOffset,
               fragment->lastOffset);

      dumpSuspiciousPacket(actualDeviceId);
    }

    allocateSecurityHostPkts(fragment->src); allocateSecurityHostPkts(fragment->dest);
    incrementUsageCounter(&fragment->src->secHostPkts->overlappingFragmentSent,
			  dstHostIdx, actualDeviceId);
    incrementUsageCounter(&fragment->dest->secHostPkts->overlappingFragmentRcvd,
			  srcHostIdx, actualDeviceId);
  }
}

/* ************************************ */

static u_int handleFragment(HostTraffic *srcHost,
			    u_int srcHostIdx,
                            HostTraffic *dstHost,
			    u_int dstHostIdx,
                            u_short *sport,
                            u_short *dport,
                            u_int fragmentId,
                            u_int off,
                            u_int packetLength,
                            u_int dataLength,
			    int actualDeviceId) {
  IpFragment *fragment;
  u_int fragmentOffset, length;

  if(!myGlobals.enableFragmentHandling)
    return(0);

  fragmentOffset = (off & 0x1FFF)*8;

  fragment = searchFragment(srcHost, dstHost, fragmentId, actualDeviceId);

  if (fragment == NULL) {
    /* new fragment */
    fragment = (IpFragment*) malloc(sizeof(IpFragment));
    if (fragment == NULL)
      return(0); /* out of memory, not much we can do */
    memset(fragment, 0, sizeof(IpFragment));
    fragment->src = srcHost;
    fragment->dest = dstHost;
    fragment->fragmentId = fragmentId;
    fragment->firstSeen = myGlobals.actTime;
    fragment->fragmentOrder = FLAG_UNKNOWN_FRAGMENT_ORDER;
    fragment->next = myGlobals.device[actualDeviceId].fragmentList;
    fragment->prev = NULL;
    myGlobals.device[actualDeviceId].fragmentList = fragment;
  } else
    checkFragmentOverlap(srcHostIdx, dstHostIdx, fragment,
			 fragmentOffset, dataLength, actualDeviceId);

  fragment->lastOffset = fragmentOffset;
  fragment->totalPacketLength += packetLength;
  fragment->totalDataLength += dataLength;
  fragment->lastDataLength = dataLength;

  if (fragmentOffset == 0) {
    /* first fragment contains port numbers */
    fragment->sport = *sport;
    fragment->dport = *dport;
  } else if (!(off & IP_MF)) /* last fragment->we know the total data size */
    fragment->expectedDataLength = fragmentOffset+dataLength;

#ifdef FRAGMENT_DEBUG
  dumpFragmentData(fragment);
#endif

  /* Now check if we have all the data needed for the statistics */
  if ((fragment->sport != 0) && (fragment->dport != 0) /* first fragment rcvd */
      /* last fragment rcvd */
      && (fragment->expectedDataLength != 0)
      /* probably all fragments rcvd */
      && (fragment->totalDataLength >= fragment->expectedDataLength)) {
    *sport = fragment->sport;
    *dport = fragment->dport;
    length = fragment->totalPacketLength;
    deleteFragment(fragment, actualDeviceId);
  } else {
    *sport = 0;
    *dport = 0;
    length = 0;
  }

  return length;
}

/* ************************************ */

void purgeOldFragmentEntries(int actualDeviceId) {
  IpFragment *fragment, *next;
  u_int fragcnt=0, expcnt=0;

  fragment = myGlobals.device[actualDeviceId].fragmentList;

  while(fragment != NULL) {
    fragcnt++;
    next = fragment->next;
    if((fragment->firstSeen + CONST_DOUBLE_TWO_MSL_TIMEOUT) < myGlobals.actTime) {
      expcnt++;
#ifdef FRAGMENT_DEBUG
      dumpFragmentData(fragment);
#endif
      deleteFragment(fragment, actualDeviceId);
    }
    fragment=next;
  }

#ifdef FRAGMENT_DEBUG
  if(fragcnt) {
    printf("FRAGMENT_DEBUG: fragcnt=%d, expcnt=%d\n", fragcnt, expcnt);
    fflush(stdout);
  }
#endif
}

/* ************************************ */

static void checkNetworkRouter(HostTraffic *srcHost,
			       HostTraffic *dstHost,
			       u_char *ether_dst, int actualDeviceId) {

  if((subnetLocalHost(srcHost) && (!subnetLocalHost(dstHost))
      && (!broadcastHost(dstHost)) && (!multicastHost(dstHost)))
     || (subnetLocalHost(dstHost) && (!subnetLocalHost(srcHost))
	 && (!broadcastHost(srcHost)) && (!multicastHost(srcHost)))) {
    HostSerial routerIdx;
    HostTraffic *router;

    routerIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);

    router = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(routerIdx)];

    if(((router->hostNumIpAddress[0] != '\0')
	&& (broadcastHost(router)
	    || multicastHost(router)
	    || (!subnetLocalHost(router)) /* No IP: is this a special Multicast address ? */))
       || (router->hostIpAddress.s_addr == dstHost->hostIpAddress.s_addr)
       || (memcmp(router->ethAddress, dstHost->ethAddress, LEN_ETHERNET_ADDRESS) == 0)
       )
      return;

    incrementUsageCounter(&srcHost->contactedRouters, router->hostTrafficBucket, actualDeviceId);

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "(%s/%s/%s) -> (%s/%s/%s) routed by [idx=%d/%s/%s/%s]",
	       srcHost->ethAddressString, srcHost->hostNumIpAddress, srcHost->hostSymIpAddress,
	       dstHost->ethAddressString, dstHost->hostNumIpAddress, dstHost->hostSymIpAddress,
	       routerIdx,
	       router->ethAddressString,
	       router->hostNumIpAddress,
	       router->hostSymIpAddress);

#endif
    FD_SET(FLAG_GATEWAY_HOST, &router->flags);
    updateRoutedTraffic(router);
  }
}

/* ************************************ */

void updatePacketCount(HostTraffic *srcHost, HostTraffic *dstHost,
		       TrafficCounter length, Counter numPkts, int actualDeviceId) {
  unsigned short hourId;
  struct tm t, *thisTime;

  if((srcHost == NULL) || (dstHost == NULL)) {
    traceEvent(CONST_TRACE_ERROR, "NULL host detected");
    return;
  }

  if((srcHost == dstHost)
     || ((srcHost->hostTrafficBucket == myGlobals.otherHostEntryIdx)
	 && (dstHost->hostTrafficBucket == myGlobals.otherHostEntryIdx)))
    return;

  thisTime = localtime_r(&myGlobals.actTime, &t);
  hourId = thisTime->tm_hour % 24 /* just in case... */;;

  incrementTrafficCounter(&srcHost->pktSent, numPkts);
  incrementTrafficCounter(&srcHost->pktSentSession, numPkts);

  if(!myGlobals.largeNetwork) {
    if(srcHost->trafficDistribution == NULL) srcHost->trafficDistribution = calloc(1, sizeof(TrafficDistribution));
    if(dstHost->trafficDistribution == NULL) dstHost->trafficDistribution = calloc(1, sizeof(TrafficDistribution));
    incrementTrafficCounter(&srcHost->trafficDistribution->last24HoursBytesSent[hourId], length.value);
    incrementTrafficCounter(&dstHost->trafficDistribution->last24HoursBytesRcvd[hourId], length.value);
  }

  if(broadcastHost(dstHost)) {
    incrementTrafficCounter(&srcHost->pktBroadcastSent, numPkts);
    incrementTrafficCounter(&srcHost->bytesBroadcastSent, length.value);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].broadcastPkts, numPkts);
  } else if(isMulticastAddress(&(dstHost->hostIpAddress))) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "%s->%s\n",
	       srcHost->hostSymIpAddress, dstHost->hostSymIpAddress);
#endif
    incrementTrafficCounter(&srcHost->pktMulticastSent, numPkts);
    incrementTrafficCounter(&srcHost->bytesMulticastSent, length.value);
    incrementTrafficCounter(&dstHost->pktMulticastRcvd, numPkts);
    incrementTrafficCounter(&dstHost->bytesMulticastRcvd, length.value);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].multicastPkts, numPkts);
  }

  incrementTrafficCounter(&srcHost->bytesSent, length.value);
  incrementTrafficCounter(&srcHost->bytesSentSession, length.value);
  if(dstHost != NULL) {
      incrementTrafficCounter(&dstHost->bytesRcvd, length.value);
      incrementTrafficCounter(&dstHost->bytesRcvdSession, length.value);
      incrementTrafficCounter(&dstHost->pktRcvd, numPkts);
      incrementTrafficCounter(&dstHost->pktRcvdSession, numPkts);
  }

  if((dstHost != NULL) /*&& (!broadcastHost(dstHost))*/)
    addContactedPeers(srcHost, dstHost, actualDeviceId);
}

/* ************************************ */

void updateHostName(HostTraffic *el) {

  if((el->hostNumIpAddress[0] == '\0')
     || (el->hostSymIpAddress == NULL)
     || strcmp(el->hostSymIpAddress, el->hostNumIpAddress) == 0) {
    int i;

    if(el->nonIPTraffic == NULL) el->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));

    if(el->nonIPTraffic->nbHostName != NULL) {
      /*
	Use NetBIOS name (when available) if the
	IP address has not been resolved.
      */
      memset(el->hostSymIpAddress, 0, sizeof(el->hostSymIpAddress));
      strcpy(el->hostSymIpAddress, el->nonIPTraffic->nbHostName);
    } else if(el->nonIPTraffic->ipxHostName != NULL)
      strcpy(el->hostSymIpAddress, el->nonIPTraffic->ipxHostName);
    else if(el->nonIPTraffic->atNodeName != NULL)
      strcpy(el->hostSymIpAddress, el->nonIPTraffic->atNodeName);

    if(el->hostSymIpAddress[0] != '\0')
      for(i=0; el->hostSymIpAddress[i] != '\0'; i++)
	el->hostSymIpAddress[i] = (char)tolower(el->hostSymIpAddress[i]);
  }
}

/* ************************************ */

static void updateDevicePacketTTLStats(u_int ttl, int actualDeviceId) {
  if(ttl < 32)       incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo32, 1);
  else if(ttl < 64)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo64, 1);
  else if(ttl < 96)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo96, 1);
  else if(ttl < 128) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo128, 1);
  else if(ttl < 160) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo160, 1);
  else if(ttl < 192) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo192, 1);
  else if(ttl < 224) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo224, 1);
  else               incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo255, 1);
}

/* ************************************ */

void updateInterfacePorts(int actualDeviceId, u_short sport, u_short dport, u_int length) {

  if((sport >= MAX_IP_PORT) || (dport >= MAX_IP_PORT)) 
    return;

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.gdbmMutex, "updateInterfacePorts");
#endif

  if(myGlobals.device[actualDeviceId].ipPorts[sport] == NULL) {
    myGlobals.device[actualDeviceId].ipPorts[sport] = (PortCounter*)malloc(sizeof(PortCounter));
    myGlobals.device[actualDeviceId].ipPorts[sport]->port = sport;
    myGlobals.device[actualDeviceId].ipPorts[sport]->sent = 0;
    myGlobals.device[actualDeviceId].ipPorts[sport]->rcvd = 0;
  }

  if(myGlobals.device[actualDeviceId].ipPorts[dport] == NULL) {
    myGlobals.device[actualDeviceId].ipPorts[dport] = (PortCounter*)malloc(sizeof(PortCounter));
    myGlobals.device[actualDeviceId].ipPorts[dport]->port = dport;
    myGlobals.device[actualDeviceId].ipPorts[dport]->sent = 0;
    myGlobals.device[actualDeviceId].ipPorts[dport]->rcvd = 0;
  }

  myGlobals.device[actualDeviceId].ipPorts[sport]->sent += length;
  myGlobals.device[actualDeviceId].ipPorts[dport]->rcvd += length;

#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.gdbmMutex);
#endif
}

/* ************************************ */

/*
  Fingerprint code courtesy of ettercap
  http://ettercap.sourceforge.net
*/
static u_char TTL_PREDICTOR(u_char x)		/* coded by awgn <awgn@antifork.org> */
{						/* round the TTL to the nearest power of 2 (ceiling) */
  register u_char i = x;
  register u_char j = 1;
  register u_char c = 0;
  
  do {
    c += i & 1;
    j <<= 1;
  } while ( i >>= 1 );
   
  if ( c == 1 )
    return x;
  else
    return ( j ? j : 0xff );
}

/* ************************************ */

static void processIpPkt(const u_char *bp,
			 const struct pcap_pkthdr *h,
			 u_int length,
			 u_char *ether_src,
			 u_char *ether_dst,
			 int actualDeviceId,
			 int vlanId) {
  u_short sport, dport;
  struct ip ip;
  struct tcphdr tp;
  struct udphdr up;
  struct icmp icmpPkt;
  u_int hlen, tcpDataLength, udpDataLength, off, tcpUdpLen;
  char *proto;
  u_int srcHostIdx, dstHostIdx;
  HostTraffic *srcHost=NULL, *dstHost=NULL;
  u_char forceUsingIPaddress = 0;
  struct timeval tvstrct;
  u_char *theData;
  TrafficCounter ctr;

  /* Need to copy this over in case bp isn't properly aligned.
   * This occurs on SunOS 4.x at least.
   * Paul D. Smith <psmith@baynetworks.com>
   */
  memcpy(&ip, bp, sizeof(struct ip));
  hlen = (u_int)ip.ip_hl * 4;

  if(vlanId != -1) {
    allocateElementHash(actualDeviceId, 1 /* VLAN hash */);
    updateElementHash(myGlobals.device[actualDeviceId].vlanHash, 
		      vlanId, vlanId,  1 /* 1 packet */, length);
  }

  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipPkts, 1);

  if((bp != NULL) && (in_cksum((const u_short *)bp, hlen, 0) != 0)) {
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.badChecksum, 1);
    return;
  }

  /*
     Fix below courtesy of
     Christian Hammers <ch@westend.com>
  */
  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipBytes, ntohs(ip.ip_len));

  if(ip.ip_p == CONST_GRE_PROTOCOL_TYPE) {
    /*
      Cisco GRE (Generic Routing Encapsulation) Tunnels (RFC 1701, 1702)
    */
    GreTunnel tunnel;
    PPPTunnelHeader pppTHeader;

    memcpy(&tunnel, bp+hlen, sizeof(GreTunnel));

    switch(ntohs(tunnel.protocol)) {
    case CONST_PPP_PROTOCOL_TYPE:
      memcpy(&pppTHeader, bp+hlen+sizeof(GreTunnel), sizeof(PPPTunnelHeader));
      
      if(ntohs(pppTHeader.protocol) == 0x21 /* IP */) {	
	memcpy(&ip, bp+hlen+sizeof(GreTunnel)+sizeof(PPPTunnelHeader), sizeof(struct ip));
	hlen = (u_int)ip.ip_hl * 4;
	ether_src = NULL, ether_dst = NULL;
      }
      break;
    case ETHERTYPE_IP:
      memcpy(&ip, bp+hlen+4 /* 4 is the size of the GRE header */, sizeof(struct ip));
      hlen = (u_int)ip.ip_hl * 4;
      ether_src = NULL, ether_dst = NULL;      
      break;
    }
  }

  if((ether_src == NULL) && (ether_dst == NULL)) {
    /* Ethernet-less protocols (e.g. PPP/RAW IP) */
    forceUsingIPaddress = 1;
  }

  NTOHL(ip.ip_dst.s_addr); NTOHL(ip.ip_src.s_addr);

  if((!myGlobals.dontTrustMACaddr)
     && isBroadcastAddress(&ip.ip_dst)
     && (memcmp(ether_dst, ethBroadcast, 6) != 0)) {
    /* forceUsingIPaddress = 1; */

    srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
    srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
    if(srcHost != NULL) {
      if(vlanId != -1) srcHost->vlanId = vlanId;
      if(myGlobals.enableSuspiciousPacketDump && (!hasWrongNetmask(srcHost))) {
	/* Dump the first packet only */

	traceEvent(CONST_TRACE_WARNING, "Host %s has a wrong netmask",
		   etheraddr_string(ether_src));
	dumpSuspiciousPacket(actualDeviceId);
      }
      FD_SET(FLAG_HOST_WRONG_NETMASK, &srcHost->flags);
    }
  }

  /*
    IMPORTANT:
    do NOT change the order of the lines below (see isBroadcastAddress call)
  */
  dstHostIdx = getHostInfo(&ip.ip_dst, ether_dst, 1, 0, actualDeviceId);
  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];

  srcHostIdx = getHostInfo(&ip.ip_src, ether_src,
			   /*
			     Don't check for multihoming when
			     the destination address is a broadcast address
			   */
			   (!isBroadcastAddress(&dstHost->hostIpAddress)),
			   forceUsingIPaddress, actualDeviceId);
  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];

  if(srcHost == NULL) {
    /* Sanity check */
    traceEvent(CONST_TRACE_ERROR, "Sanity check failed (1) [Low memory?] (idx=%d)", srcHostIdx);
    return; /* It might be that there's not enough memory that that
	       dstHostIdx = getHostInfo(&ip.ip_dst, ether_dst) caused
	       srcHost to be freed */
  }

  if(dstHost == NULL) {
    /* Sanity check */
    traceEvent(CONST_TRACE_ERROR, "Sanity check failed (2) [Low memory?]");
    return;
  }

  if(vlanId != -1) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }

#ifdef DEBUG
  if(myGlobals.rFileName != NULL) {
    static int numPkt=1;

    traceEvent(CONST_TRACE_INFO, "%d) %s -> %s",
	       numPkt++,
	       srcHost->hostNumIpAddress,
	       dstHost->hostNumIpAddress);
    fflush(stdout);
  }
#endif

  updateDevicePacketTTLStats(ip.ip_ttl, actualDeviceId);

  if(ip.ip_ttl != 255) {
    /*
      TTL can be calculated only when the packet
      is originated by the sender
    */
    if((srcHost->minTTL == 0) || (ip.ip_ttl < srcHost->minTTL)) srcHost->minTTL = ip.ip_ttl;
    if((ip.ip_ttl > srcHost->maxTTL)) srcHost->maxTTL = ip.ip_ttl;
  }

  ctr.value = h->len;
  updatePacketCount(srcHost, dstHost, ctr, 1, actualDeviceId);

  if((!myGlobals.dontTrustMACaddr) && (!myGlobals.device[actualDeviceId].dummyDevice)) {
    checkNetworkRouter(srcHost, dstHost, ether_dst, actualDeviceId);
    ctr.value = length;
    updateTrafficMatrix(srcHost, dstHost, ctr, actualDeviceId);
  }

  incrementTrafficCounter(&srcHost->ipBytesSent, length),
    incrementTrafficCounter(&dstHost->ipBytesRcvd, length);

  if(subnetPseudoLocalHost(srcHost)) {
    if(subnetPseudoLocalHost(dstHost)) {
      incrementTrafficCounter(&srcHost->bytesSentLoc, length);
      incrementTrafficCounter(&dstHost->bytesRcvdLoc, length);
    } else {
      incrementTrafficCounter(&srcHost->bytesSentRem, length);
      incrementTrafficCounter(&dstHost->bytesRcvdLoc, length);
    }
  } else {
    /* srcHost is remote */
    if(subnetPseudoLocalHost(dstHost)) {
      incrementTrafficCounter(&srcHost->bytesSentLoc, length);
      incrementTrafficCounter(&dstHost->bytesRcvdFromRem, length);
    } else {
      incrementTrafficCounter(&srcHost->bytesSentRem, length);
      incrementTrafficCounter(&dstHost->bytesRcvdFromRem, length);
    }
  }

#if PACKET_DEBUG
  /*
   * Time to show the IP Packet Header (when enabled).
   */
  if (fd && myGlobals.device [actualDeviceId] . ipv)
      fprintf (fd, "PACKET_DEBUG: IP:     ----- IP Header -----\n\n"),
      fprintf (fd, "                      Packet %ld arrived at %s\n", myGlobals.device [actualDeviceId] ,
	       timestamp (& myGlobals.lastPktTime, FLAG_TIMESTAMP_FMT_ABS)),
      fprintf (fd, "                      Total size  = %d : header = %d : data = %d\n",
	       ip_size, ip_hlen, ip_size - ip_hlen),
      fprintf (fd, "                      Source      = %s\n", inet_ntoa (ip->ip_src)),
      fprintf (fd, "                      Destination = %s\n", inet_ntoa (ip->ip_dst)),
      fflush (fd);
#endif

  off = ntohs(ip.ip_off);

  if (off & 0x3fff) {
    /*
      This is a fragment: fragment handling is handled by handleFragment()
      called below.

      Courtesy of Andreas Pfaller
    */
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].fragmentedIpBytes, length);

    switch(ip.ip_p) {
    case IPPROTO_TCP:
      incrementTrafficCounter(&srcHost->tcpFragmentsSent, length),
	incrementTrafficCounter(&dstHost->tcpFragmentsRcvd, length);
      break;
    case IPPROTO_UDP:
      incrementTrafficCounter(&srcHost->udpFragmentsSent, length), 
	incrementTrafficCounter(&dstHost->udpFragmentsRcvd, length);
      break;
    case IPPROTO_ICMP:
      incrementTrafficCounter(&srcHost->icmpFragmentsSent, length),
	incrementTrafficCounter(&dstHost->icmpFragmentsRcvd, length);
      break;
    }
  }

  tcpUdpLen = ntohs(ip.ip_len) - hlen;

  switch(ip.ip_p) {
  case IPPROTO_TCP:
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpBytes, tcpUdpLen);

    if(tcpUdpLen < sizeof(struct tcphdr)) {
      if(myGlobals.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING, "Malformed TCP pkt %s->%s detected (packet too short)",
		   srcHost->hostSymIpAddress,
		   dstHost->hostSymIpAddress);
	dumpSuspiciousPacket(actualDeviceId);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHostIdx, actualDeviceId);
      }
    } else {
      proto = "TCP";
      memcpy(&tp, bp+hlen, sizeof(struct tcphdr));

      /* Sanity check */
      if(tcpUdpLen >= (tp.th_off * 4)) {
	tcpDataLength = tcpUdpLen - (tp.th_off * 4);
	theData = (u_char*)(bp+hlen+(tp.th_off * 4));
      } else {
	tcpDataLength = 0;
	theData = NULL;
      }

      sport = ntohs(tp.th_sport);
      dport = ntohs(tp.th_dport);

      /*
	Don't move this code on top as it is supposed to stay here
	as it modifies sport/sport

	Courtesy of Andreas Pfaller
      */
      if(myGlobals.enableFragmentHandling && (off & 0x3fff)) {
	/* Handle fragmented packets */
	length = handleFragment(srcHost, srcHostIdx, dstHost, dstHostIdx,
				&sport, &dport,
				ntohs(ip.ip_id), off, length,
				ntohs(ip.ip_len) - hlen, actualDeviceId);
      }

     if(srcHost->fingerprint == NULL) {
	char fingerprint[64];
	int WIN=0, MSS=-1, WS=-1, S=0, N=0, D=0, T=0;
	int ttl;
	char WSS[3], _MSS[5];
	struct tcphdr *tcp = bp+hlen;
	u_char *tcp_opt = (u_char *)(tcp + 1);
	u_char *tcp_data = (u_char *)((int)tcp + tcp->th_off * 4);

	if (tcp->th_flags & TH_SYN)   /* only SYN or SYN-2ACK packets */
	  {
	    if (tcpUdpLen > 0) {

	      if(ntohs(ip.ip_off) & IP_DF) D = 1;   /* don't fragment bit is set */

	      WIN = ntohs(tcp->th_win);  /* TCP window size */

	      if (tcp_data != tcp_opt) /* there are some tcp_option to be parsed */
		{
		  u_char *opt_ptr = tcp_opt;

		  while(opt_ptr < tcp_data)
		    {
		      switch(*opt_ptr)
			{
			case TCPOPT_EOL:        /* end option: exit */
			  opt_ptr = tcp_data;
			  break;
			case TCPOPT_NOP:
			  N = 1;
			  opt_ptr++;
			  break;
			case TCPOPT_SACKOK:
			  S = 1;
			  opt_ptr += 2;
			  break;
			case TCPOPT_MAXSEG:
			  opt_ptr += 2;
			  MSS = ntohs(ptohs(opt_ptr));
			  opt_ptr += 2;
			  break;
			case TCPOPT_WSCALE:
			  opt_ptr += 2;
			  WS = *opt_ptr;
			  opt_ptr++;
			  break;
			case TCPOPT_TIMESTAMP:
			  T = 1;
			  opt_ptr++;
			  opt_ptr += (*opt_ptr - 1);
			  break;
			default:
			  opt_ptr++;
			  opt_ptr += (*opt_ptr - 1);
			  break;
			}
		    }
		}

	      if (WS == -1) sprintf(WSS, "WS");
	      else snprintf(WSS, sizeof(WSS), "%02d", WS);

	      if (MSS == -1) sprintf(_MSS, "_MSS");
	      else snprintf(_MSS, sizeof(_MSS), "%04X", MSS);
                  
	      snprintf(fingerprint, sizeof(fingerprint),
		       "%04X:%s:%02X:%s:%d:%d:%d:%d:%c:%02X",
		       WIN, _MSS, ttl = TTL_PREDICTOR(ip.ip_ttl), WSS , S, N, D, T, 
		       (tcp->th_flags & TH_ACK) ? 'A' : 'S', tcpUdpLen);

#if 0
	      traceEvent(CONST_TRACE_INFO, "[%s][%s]", srcHost->hostNumIpAddress, fingerprint);
#endif
	      accessAddrResMutex("processIpPkt");
	      srcHost->fingerprint = strdup(fingerprint);
	      releaseAddrResMutex();
	    }
	  }
      }

      if((sport > 0) && (dport > 0)) {
	IPSession *theSession = NULL;
	u_short isPassiveSess = 0, nonFullyRemoteSession = 1;
	int sportIdx, dportIdx;

	/* It might be that tcpDataLength is 0 when
	   the rcvd packet is fragmented and the main
	   packet has not yet been rcvd */

	updateInterfacePorts(actualDeviceId, sport, dport, length);
	updateUsedPorts(srcHost, dstHost, sport, dport, tcpDataLength);

	if(subnetPseudoLocalHost(srcHost)) {
	  if(subnetPseudoLocalHost(dstHost)) {
	    incrementTrafficCounter(&srcHost->tcpSentLoc, length);
	    incrementTrafficCounter(&dstHost->tcpRcvdLoc, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.local, length);
	  } else {
	    incrementTrafficCounter(&srcHost->tcpSentRem, length);
	    incrementTrafficCounter(&dstHost->tcpRcvdLoc, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.local2remote, length);
	  }
	} else {
	  /* srcHost is remote */
	  if(subnetPseudoLocalHost(dstHost)) {
	    incrementTrafficCounter(&srcHost->tcpSentLoc, length);
	    incrementTrafficCounter(&dstHost->tcpRcvdFromRem, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.remote2local, length);
	  } else {
	    incrementTrafficCounter(&srcHost->tcpSentRem, length);
	    incrementTrafficCounter(&dstHost->tcpRcvdFromRem, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.remote, length);
	    nonFullyRemoteSession = 0;
	  }
	}

	if(nonFullyRemoteSession) {
	  theSession = handleTCPSession(h, (off & 0x3fff), tp.th_win,
					srcHostIdx, sport, dstHostIdx,
					dport, ntohs(ip.ip_len), &tp, tcpDataLength,
					theData, actualDeviceId);
	  if(theSession == NULL)
	    isPassiveSess = 0;
	  else
	    isPassiveSess = theSession->passiveFtpSession;
	}

	/* choose most likely port for protocol traffic accounting
	 * by trying lower number port first. This is based
	 * on the assumption that lower port numbers are more likely
	 * to be the servers and clients usually dont use ports <1024
	 * This is only relevant if both port numbers are used to
	 * gather service statistics.
	 * e.g. traffic between port 2049 (nfsd) and 113 (nntp) will
	 * be counted as nntp traffic in all directions by this heuristic
	 * and not as nntp in one direction and nfs in the return direction.
	 *
	 * Courtesy of Andreas Pfaller <apfaller@yahoo.com.au>
	 */
	
	sportIdx = mapGlobalToLocalIdx(sport), dportIdx = mapGlobalToLocalIdx(dport);

	if((dport < sport) && (! ((sportIdx != -1) && (dportIdx == -1)))
	    || ((sportIdx == -1) && (dportIdx != -1))) {
	  /* traceEvent(CONST_TRACE_INFO, "[1] sportIdx(%d)=%d - dportIdx(%d)=%d", sport, sportIdx, dport, dportIdx); */

	  if(handleIP(dport, srcHost, dstHost, length, isPassiveSess, 
		      theSession != NULL ? theSession->isP2P : 0, actualDeviceId) == -1)
	    handleIP(sport, srcHost, dstHost, length, isPassiveSess, 
		     theSession != NULL ? theSession->isP2P : 0, actualDeviceId);
	} else {
	  /* traceEvent(CONST_TRACE_INFO, "[2] sportIdx(%d)=%d - dportIdx(%d)=%d", sport, sportIdx, dport, dportIdx); */
	  
	  if(handleIP(sport, srcHost, dstHost, length, isPassiveSess, 
		      theSession != NULL ? theSession->isP2P : 0, actualDeviceId) == -1)
	    handleIP(dport, srcHost, dstHost, length, isPassiveSess, 
		     theSession != NULL ? theSession->isP2P : 0, actualDeviceId);
	}
      }
    }
    break;

  case IPPROTO_UDP:
    proto = "UDP";
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpBytes, tcpUdpLen);

    if(tcpUdpLen < sizeof(struct udphdr)) {
      if(myGlobals.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING, "Malformed UDP pkt %s->%s detected (packet too short)",
		   srcHost->hostSymIpAddress,
		   dstHost->hostSymIpAddress);
	dumpSuspiciousPacket(actualDeviceId);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHostIdx, actualDeviceId);
      }
    } else {
      udpDataLength = tcpUdpLen - sizeof(struct udphdr);
      memcpy(&up, bp+hlen, sizeof(struct udphdr));

      sport = ntohs(up.uh_sport);
      dport = ntohs(up.uh_dport);

      updateInterfacePorts(actualDeviceId, sport, dport, udpDataLength);
      updateUsedPorts(srcHost, dstHost, sport, dport, udpDataLength);

      if(!(off & 0x3fff)) {
	if(((sport == 53) || (dport == 53) /* domain */)) {
	  short isRequest = 0, positiveReply = 0;
	  u_int16_t transactionId = 0;

	  if(myGlobals.enablePacketDecoding
	     && (bp != NULL) /* packet long enough */) {
	    /* The DNS chain will be checked here */
	    transactionId = processDNSPacket(bp+hlen+sizeof(struct udphdr),
					     udpDataLength, &isRequest, &positiveReply);

#ifdef DNS_SNIFF_DEBUG
	    traceEvent(CONST_TRACE_INFO, "DNS_SNIFF_DEBUG: %s:%d->%s:%d [request: %d][positive reply: %d]\n",
		       srcHost->hostSymIpAddress, sport,
		       dstHost->hostSymIpAddress, dport,
		       isRequest, positiveReply);
#endif

	    if(srcHost->protocolInfo == NULL) srcHost->protocolInfo = calloc(1, sizeof(ProtocolInfo));
	    if(dstHost->protocolInfo == NULL) dstHost->protocolInfo = calloc(1, sizeof(ProtocolInfo));

	    if(srcHost->protocolInfo->dnsStats == NULL) {
	      srcHost->protocolInfo->dnsStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	      memset(srcHost->protocolInfo->dnsStats, 0, sizeof(ServiceStats));
	    }

	    if(dstHost->protocolInfo->dnsStats == NULL) {
	      dstHost->protocolInfo->dnsStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	      memset(dstHost->protocolInfo->dnsStats, 0, sizeof(ServiceStats));
	    }

	    if(isRequest) {
	      /* to be 64bit-proof we have to copy the elements */
	      tvstrct.tv_sec = h->ts.tv_sec;
	      tvstrct.tv_usec = h->ts.tv_usec;
	      addTimeMapping(transactionId, tvstrct);

	      if(subnetLocalHost(dstHost))
		incrementTrafficCounter(&srcHost->protocolInfo->dnsStats->numLocalReqSent, 1);
	      else
		incrementTrafficCounter(&srcHost->protocolInfo->dnsStats->numRemReqSent, 1);

	      if(subnetLocalHost(srcHost))
		incrementTrafficCounter(&dstHost->protocolInfo->dnsStats->numLocalReqRcvd, 1);
	      else
		incrementTrafficCounter(&dstHost->protocolInfo->dnsStats->numRemReqRcvd, 1);
	    } else {
	      time_t microSecTimeDiff;

	      /* to be 64bit-safe we have to copy the elements */
	      tvstrct.tv_sec = h->ts.tv_sec;
	      tvstrct.tv_usec = h->ts.tv_usec;
	      microSecTimeDiff = getTimeMapping(transactionId, tvstrct);

	      if(microSecTimeDiff > 0) {
#ifdef DEBUG
		traceEvent(CONST_TRACE_INFO, "TransactionId=0x%X [%.1f ms]\n",
			   transactionId, ((float)microSecTimeDiff)/1000);
#endif

		if(microSecTimeDiff > 0) {
		  if(subnetLocalHost(dstHost)) {
		    if((srcHost->protocolInfo->dnsStats->fastestMicrosecLocalReqServed == 0)
		       || (microSecTimeDiff < srcHost->protocolInfo->dnsStats->fastestMicrosecLocalReqServed))
		      srcHost->protocolInfo->dnsStats->fastestMicrosecLocalReqServed = microSecTimeDiff;
		    if(microSecTimeDiff > srcHost->protocolInfo->dnsStats->slowestMicrosecLocalReqServed)
		      srcHost->protocolInfo->dnsStats->slowestMicrosecLocalReqServed = microSecTimeDiff;
		  } else {
		    if((srcHost->protocolInfo->dnsStats->fastestMicrosecRemReqServed == 0)
		       || (microSecTimeDiff < srcHost->protocolInfo->dnsStats->fastestMicrosecRemReqServed))
		      srcHost->protocolInfo->dnsStats->fastestMicrosecRemReqServed = microSecTimeDiff;
		    if(microSecTimeDiff > srcHost->protocolInfo->dnsStats->slowestMicrosecRemReqServed)
		      srcHost->protocolInfo->dnsStats->slowestMicrosecRemReqServed = microSecTimeDiff;
		  }

		  if(subnetLocalHost(srcHost)) {
		    if((dstHost->protocolInfo->dnsStats->fastestMicrosecLocalReqMade == 0)
		       || (microSecTimeDiff < dstHost->protocolInfo->dnsStats->fastestMicrosecLocalReqMade))
		      dstHost->protocolInfo->dnsStats->fastestMicrosecLocalReqMade = microSecTimeDiff;
		    if(microSecTimeDiff > dstHost->protocolInfo->dnsStats->slowestMicrosecLocalReqMade)
		      dstHost->protocolInfo->dnsStats->slowestMicrosecLocalReqMade = microSecTimeDiff;
		  } else {
		    if((dstHost->protocolInfo->dnsStats->fastestMicrosecRemReqMade == 0)
		       || (microSecTimeDiff < dstHost->protocolInfo->dnsStats->fastestMicrosecRemReqMade))
		      dstHost->protocolInfo->dnsStats->fastestMicrosecRemReqMade = microSecTimeDiff;
		    if(microSecTimeDiff > dstHost->protocolInfo->dnsStats->slowestMicrosecRemReqMade)
		      dstHost->protocolInfo->dnsStats->slowestMicrosecRemReqMade = microSecTimeDiff;
		  }
		} else {
#ifdef DEBUG
		  traceEvent(CONST_TRACE_INFO, "getTimeMapping(0x%X) failed for DNS",
			     transactionId);
#endif
		}
	      }

	      /* Courtesy of Roberto F. De Luca <deluca@tandar.cnea.gov.ar> */
	      FD_SET(FLAG_NAME_SERVER_HOST, &srcHost->flags);

	      if(positiveReply) {
		incrementTrafficCounter(&srcHost->protocolInfo->dnsStats->numPositiveReplSent, 1);
		incrementTrafficCounter(&dstHost->protocolInfo->dnsStats->numPositiveReplRcvd, 1);
	      } else {
		incrementTrafficCounter(&srcHost->protocolInfo->dnsStats->numNegativeReplSent, 1);
		incrementTrafficCounter(&dstHost->protocolInfo->dnsStats->numNegativeReplRcvd, 1);
	      }
	    }
	  } else {
	    /* no packet decoding (let's speculate a bit) */
	    FD_SET(FLAG_NAME_SERVER_HOST, &srcHost->flags);
	  }
	} else {
	  if(myGlobals.enablePacketDecoding)
	    handleNetbios(srcHost, dstHost, sport, dport,
			  udpDataLength, bp,
			  length, hlen);
	}
      }

      /*
	Don't move this code on top as it is supposed to stay here
	as it modifies sport/sport

	Courtesy of Andreas Pfaller
      */
      if(myGlobals.enableFragmentHandling && (off & 0x3fff)) {
	/* Handle fragmented packets */
	length = handleFragment(srcHost, srcHostIdx, dstHost, dstHostIdx,
				&sport, &dport,
				ntohs(ip.ip_id), off, length,
				ntohs(ip.ip_len) - hlen, actualDeviceId);
      }

      if((sport > 0) && (dport > 0)) {
	u_short nonFullyRemoteSession = 1;

	/* It might be that udpBytes is 0 when
	   the rcvd packet is fragmented and the main
	   packet has not yet been rcvd */

	if(subnetPseudoLocalHost(srcHost)) {
	  if(subnetPseudoLocalHost(dstHost)) {
	    incrementTrafficCounter(&srcHost->udpSentLoc, length);
	    incrementTrafficCounter(&dstHost->udpRcvdLoc, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.local, length);
	  } else {
	    incrementTrafficCounter(&srcHost->udpSentRem, length);
	    incrementTrafficCounter(&dstHost->udpRcvdLoc, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.local2remote, length);
	  }
	} else {
	  /* srcHost is remote */
	  if(subnetPseudoLocalHost(dstHost)) {
	    incrementTrafficCounter(&srcHost->udpSentLoc, length);
	    incrementTrafficCounter(&dstHost->udpRcvdFromRem, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.remote2local, length);
	  } else {
	    incrementTrafficCounter(&srcHost->udpSentRem, length);
	    incrementTrafficCounter(&dstHost->udpRcvdFromRem, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.remote, length);
	    nonFullyRemoteSession = 0;
	  }
	}

        /* Handle UDP traffic like TCP, above -
	   That is: if we know about the lower# port, even if it's the destination,
	   classify the traffic that way.
	   (BMS 12-2001)
	*/
        if (dport < sport) {
	  if (handleIP(dport, srcHost, dstHost, length, 0, 0, actualDeviceId) == -1)
	    handleIP(sport, srcHost, dstHost, length, 0, 0, actualDeviceId);
        } else {
	  if (handleIP(sport, srcHost, dstHost, length, 0, 0, actualDeviceId) == -1)
	    handleIP(dport, srcHost, dstHost, length, 0, 0, actualDeviceId);
        }

	if(nonFullyRemoteSession)
	  handleUDPSession(h, (off & 0x3fff),
			   srcHostIdx, sport, dstHostIdx,
			   dport, udpDataLength,
			   (u_char*)(bp+hlen+sizeof(struct udphdr)), actualDeviceId);
	sendUDPflow(srcHost, dstHost, sport, dport, ntohs(ip.ip_len), actualDeviceId);
      }
    }
    break;

  case IPPROTO_ICMP:
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].icmpBytes, length);

    if(tcpUdpLen < sizeof(struct icmp)) {
      if(myGlobals.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING, "Malformed ICMP pkt %s->%s detected (packet too short)",
		   srcHost->hostSymIpAddress,
		   dstHost->hostSymIpAddress);
	dumpSuspiciousPacket(actualDeviceId);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHostIdx, actualDeviceId);
      }
    } else {
      proto = "ICMP";
      memcpy(&icmpPkt, bp+hlen, sizeof(struct icmp));

      incrementTrafficCounter(&srcHost->icmpSent, length);
      incrementTrafficCounter(&dstHost->icmpRcvd, length);

      if(off & 0x3fff) {
	char *fmt = "Detected ICMP fragment [%s -> %s] (network attack attempt?)";

	incrementTrafficCounter(&srcHost->icmpFragmentsSent, length), 
	  incrementTrafficCounter(&dstHost->icmpFragmentsRcvd, length);
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->icmpFragmentSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->icmpFragmentRcvd, srcHostIdx, actualDeviceId);
	if(myGlobals.enableSuspiciousPacketDump) {
	  traceEvent(CONST_TRACE_WARNING, fmt,
		     srcHost->hostSymIpAddress, dstHost->hostSymIpAddress);
	  dumpSuspiciousPacket(actualDeviceId);
	}
      }

      /* ************************************************************* */

      if(icmpPkt.icmp_type <= ICMP_MAXTYPE) {
	short dumpPacket = 1;
	if(srcHost->icmpInfo == NULL) {
	  if ( (srcHost->icmpInfo = (IcmpHostInfo*)malloc(sizeof(IcmpHostInfo))) == NULL) return;
	  memset(srcHost->icmpInfo, 0, sizeof(IcmpHostInfo));
	}

	incrementTrafficCounter(&srcHost->icmpInfo->icmpMsgSent[icmpPkt.icmp_type], 1);

	if(dstHost->icmpInfo == NULL) {
	  if ( (dstHost->icmpInfo = (IcmpHostInfo*)malloc(sizeof(IcmpHostInfo))) == NULL) return;
	  memset(dstHost->icmpInfo, 0, sizeof(IcmpHostInfo));
	}

	incrementTrafficCounter(&dstHost->icmpInfo->icmpMsgRcvd[icmpPkt.icmp_type], 1);

	switch (icmpPkt.icmp_type) {
	case ICMP_ECHOREPLY:
	case ICMP_ECHO:
	  /* Do not log anything */
	  dumpPacket = 0;
	  break;

	case ICMP_UNREACH:
	case ICMP_REDIRECT:
	case ICMP_ROUTERADVERT:
	case ICMP_TIMXCEED:
	case ICMP_PARAMPROB:
	case ICMP_MASKREPLY:
	case ICMP_MASKREQ:
	case ICMP_INFO_REQUEST:
	case ICMP_INFO_REPLY:
	case ICMP_TIMESTAMP:
	case ICMP_TIMESTAMPREPLY:
	case ICMP_SOURCE_QUENCH:
	  if(myGlobals.enableSuspiciousPacketDump) {
	    dumpSuspiciousPacket(actualDeviceId);
	  }
	  break;
	}

	if(myGlobals.enableSuspiciousPacketDump && dumpPacket) {
	  if(!((icmpPkt.icmp_type == 3) && (icmpPkt.icmp_code == 3))) {
	    /*
	      Avoid to print twice the same message:
 	      - Detected ICMP msg (type=3/code=3) from lhost -> ahost
	      - Host [ahost] sent UDP data to a closed port of host [lhost:10001]
	      (scan attempt?)
	    */

	    traceEvent(CONST_TRACE_INFO, "Detected ICMP msg [type=%s/code=%d] %s->%s",
		       mapIcmpType(icmpPkt.icmp_type), icmpPkt.icmp_code,
		       srcHost->hostSymIpAddress, dstHost->hostSymIpAddress);
	  }
	}
      }

      /* ************************************************************* */

      if(subnetPseudoLocalHost(srcHost))
	if(subnetPseudoLocalHost(dstHost))
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.local, length);
	else
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.local2remote, length);
      else /* srcHost is remote */
	if(subnetPseudoLocalHost(dstHost))
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.remote2local, length);
	else
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.remote, length);

      if(myGlobals.enableSuspiciousPacketDump
	 && (icmpPkt.icmp_type == ICMP_ECHO)
	 && (broadcastHost(dstHost) || multicastHost(dstHost))) {
	traceEvent(CONST_TRACE_WARNING, "Smurf packet detected for host [%s->%s]",
		   srcHost->hostSymIpAddress, dstHost->hostSymIpAddress);
      } else if(icmpPkt.icmp_type == ICMP_DEST_UNREACHABLE /* Destination Unreachable */) {
	struct ip *oip = &icmpPkt.icmp_ip;

	switch(icmpPkt.icmp_code) {
	case ICMP_UNREACH_PORT: /* Port Unreachable */
	  memcpy(&dport, ((u_char *)bp+hlen+30), sizeof(dport));
	  dport = ntohs(dport);
	  switch (oip->ip_p) {
	  case IPPROTO_TCP:
	    if(myGlobals.enableSuspiciousPacketDump)
	      traceEvent(CONST_TRACE_WARNING,
			 "Host [%s] sent TCP data to a closed port of host [%s:%d] (scan attempt?)",
			 dstHost->hostSymIpAddress, srcHost->hostSymIpAddress, dport);
	    /* Simulation of rejected TCP connection */
	    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	    incrementUsageCounter(&srcHost->secHostPkts->rejectedTCPConnSent, dstHostIdx, actualDeviceId);
	    incrementUsageCounter(&dstHost->secHostPkts->rejectedTCPConnRcvd, srcHostIdx, actualDeviceId);
	    break;

	  case IPPROTO_UDP:
	    if(myGlobals.enableSuspiciousPacketDump)
	      traceEvent(CONST_TRACE_WARNING,
			 "Host [%s] sent UDP data to a closed port of host [%s:%d] (scan attempt?)",
			 dstHost->hostSymIpAddress, srcHost->hostSymIpAddress, dport);
	    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	    incrementUsageCounter(&dstHost->secHostPkts->udpToClosedPortSent, srcHostIdx, actualDeviceId);
	    incrementUsageCounter(&srcHost->secHostPkts->udpToClosedPortRcvd, dstHostIdx, actualDeviceId);
	    break;
	  }
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpPortUnreachSent, dstHostIdx, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpPortUnreachRcvd, srcHostIdx, actualDeviceId);
	  break;

	case ICMP_UNREACH_NET:
	case ICMP_UNREACH_HOST:
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpHostNetUnreachSent, dstHostIdx, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpHostNetUnreachRcvd, srcHostIdx, actualDeviceId);
	  break;

	case ICMP_UNREACH_PROTOCOL: /* Protocol Unreachable */
	  if(myGlobals.enableSuspiciousPacketDump)
	    traceEvent(CONST_TRACE_WARNING, /* See http://www.packetfactory.net/firewalk/ */
		       "Host [%s] rcvd a ICMP protocol Unreachable from host [%s]"
		       " (Firewalking scan attempt?)",
		       dstHost->hostSymIpAddress,
		       srcHost->hostSymIpAddress);
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpProtocolUnreachSent, dstHostIdx, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpProtocolUnreachRcvd, srcHostIdx, actualDeviceId);
	  break;
	case ICMP_UNREACH_NET_PROHIB:    /* Net Administratively Prohibited */
	case ICMP_UNREACH_HOST_PROHIB:   /* Host Administratively Prohibited */
	case ICMP_UNREACH_FILTER_PROHIB: /* Access Administratively Prohibited */
	  if(myGlobals.enableSuspiciousPacketDump)
	    traceEvent(CONST_TRACE_WARNING, /* See http://www.packetfactory.net/firewalk/ */
		       "Host [%s] sent ICMP Administratively Prohibited packet to host [%s]"
		       " (Firewalking scan attempt?)",
		       dstHost->hostSymIpAddress, srcHost->hostSymIpAddress);
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpAdminProhibitedSent, dstHostIdx, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpAdminProhibitedRcvd, srcHostIdx, actualDeviceId);
	  break;
	}
	if(myGlobals.enableSuspiciousPacketDump) dumpSuspiciousPacket(actualDeviceId);
      }

      sendICMPflow(srcHost, dstHost, ntohs(ip.ip_len), actualDeviceId);
    }
    break;

  case IPPROTO_OSPF:
    proto = "OSPF";
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].ospfBytes, length);
    incrementTrafficCounter(&srcHost->ospfSent, length);
    incrementTrafficCounter(&dstHost->ospfRcvd, length);
    sendOTHERflow(srcHost, dstHost, ip.ip_p, ntohs(ip.ip_len), actualDeviceId);
    break;

  case IPPROTO_IGMP:
    proto = "IGMP";
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].igmpBytes, length);
    incrementTrafficCounter(&srcHost->igmpSent, length);
    incrementTrafficCounter(&dstHost->igmpRcvd, length);
    sendOTHERflow(srcHost, dstHost, ip.ip_p, ntohs(ip.ip_len), actualDeviceId);
    break;

  default:
    proto = "IP (Other)";
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherIpBytes, length);
    sport = dport = 0;
    incrementTrafficCounter(&srcHost->otherSent, length);
    incrementTrafficCounter(&dstHost->otherRcvd, length);
    sendOTHERflow(srcHost, dstHost, ip.ip_p, ntohs(ip.ip_len), actualDeviceId);
    break;
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "IP=%d TCP=%d UDP=%d ICMP=%d (len=%d)\n",
	     (int)myGlobals.device[actualDeviceId].ipBytes,
	     (int)myGlobals.device[actualDeviceId].tcpBytes,
	     (int)myGlobals.device[actualDeviceId].udpBytes,
	     (int)myGlobals.device[actualDeviceId].icmpBytes, length);
#endif
}

/* ************************************ */

#ifdef CFG_MULTITHREADED
void queuePacket(u_char * _deviceId,
		 const struct pcap_pkthdr *h,
		 const u_char *p) {
  int len;

  /* ***************************
     - If the queue is full then wait until a slot is freed

     - If the queue is getting full then periodically wait
     until a slot is freed
     **************************** */

#ifdef WIN32_DEMO
  static int numQueuedPackets=0;

  if(numQueuedPackets++ >= MAX_NUM_PACKETS)
    return;
#endif

  if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN) return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Got packet from %s (%d)\n", myGlobals.device[*_deviceId].name, *_deviceId);
#endif

  if(myGlobals.packetQueueLen >= CONST_PACKET_QUEUE_LENGTH) {
    int deviceId;
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Dropping packet!!! [packet queue=%d/max=%d]\n",
	       myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

#ifdef WIN32
    deviceId = 0;
#else
    deviceId = (int)_deviceId;
#endif

    incrementTrafficCounter(&myGlobals.device[getActualInterface(deviceId)].droppedPkts, 1);

#ifdef MAKE_WITH_SCHED_YIELD
    sched_yield(); /* Allow other threads (dequeue) to run */
#endif
    HEARTBEAT(0, "queuePacket() drop, sleep(1)...", NULL);
    sleep(1);
    HEARTBEAT(0, "queuePacket() drop, sleep(1)...woke", NULL);
  } else {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "About to queue packet... \n");
#endif
    accessMutex(&myGlobals.packetQueueMutex, "queuePacket");
    memcpy(&myGlobals.packetQueue[myGlobals.packetQueueHead].h, h, sizeof(struct pcap_pkthdr));
    memset(myGlobals.packetQueue[myGlobals.packetQueueHead].p, 0, sizeof(myGlobals.packetQueue[myGlobals.packetQueueHead].p));
    /* Just to be safe */
    len = h->caplen;
    if(len >= DEFAULT_SNAPLEN) len = DEFAULT_SNAPLEN-1;
    memcpy(myGlobals.packetQueue[myGlobals.packetQueueHead].p, p, len);
    myGlobals.packetQueue[myGlobals.packetQueueHead].h.caplen = len;
    myGlobals.packetQueue[myGlobals.packetQueueHead].deviceId = (int)((void*)_deviceId);
    myGlobals.packetQueueHead = (myGlobals.packetQueueHead+1) % CONST_PACKET_QUEUE_LENGTH;
    myGlobals.packetQueueLen++;
    if(myGlobals.packetQueueLen > myGlobals.maxPacketQueueLen)
      myGlobals.maxPacketQueueLen = myGlobals.packetQueueLen;
    releaseMutex(&myGlobals.packetQueueMutex);
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Queued packet... [packet queue=%d/max=%d]\n",
	       myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

#ifdef DEBUG_THREADS
    traceEvent(CONST_TRACE_INFO, "+ [packet queue=%d/max=%d]\n", myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif
  }

#ifdef MAKE_WITH_SEMAPHORES
  incrementSem(&myGlobals.queueSem);
#else
  signalCondvar(&myGlobals.queueCondvar);
#endif
#ifdef MAKE_WITH_SCHED_YIELD
  sched_yield(); /* Allow other threads (dequeue) to run */
#endif
}

/* ************************************ */

void cleanupPacketQueue(void) {
  ; /* Nothing to do */
}

/* ************************************ */

#define MAX_PACKET_LEN          8232 /* _mtuSize[DLT_NULL] */


void* dequeuePacket(void* notUsed _UNUSED_) {
  PacketInformation pktInfo;
  unsigned short deviceId;
  struct pcap_pkthdr h;
  u_char p[MAX_PACKET_LEN];

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Packet processor thread (%ld) started...\n", myGlobals.dequeueThreadId);

  while(myGlobals.capturePackets == FLAG_NTOPSTATE_RUN) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Waiting for packet...\n");
#endif

    while((myGlobals.packetQueueLen == 0)
	  && (myGlobals.capturePackets == FLAG_NTOPSTATE_RUN) /* Courtesy of Wies-Software <wies@wiessoft.de> */) {
#ifdef MAKE_WITH_SEMAPHORES
      waitSem(&myGlobals.queueSem);
#else
      waitCondvar(&myGlobals.queueCondvar);
#endif
    }

    if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN) break;

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Got packet...\n");
#endif
    accessMutex(&myGlobals.packetQueueMutex, "dequeuePacket");
    memcpy(&h, &myGlobals.packetQueue[myGlobals.packetQueueTail].h,
	   sizeof(struct pcap_pkthdr));
    
    /* This code should be changed ASAP. It is a bad trick that avoids ntop to
       go beyond packet boundaries (L.Deri 17/03/2003)
       
       1. h->len is truncated
       2. MAX_PACKET_LEN should probably be removed
       3. all the functions must check that they are not going beyond packet boundaries
    */
    memcpy(p, myGlobals.packetQueue[myGlobals.packetQueueTail].p, DEFAULT_SNAPLEN);
    if(h.len > MAX_PACKET_LEN) {
      traceEvent(CONST_TRACE_WARNING, "WARNING: packet truncated (%d->%d)", h.len, MAX_PACKET_LEN);
      h.len = MAX_PACKET_LEN;
    }
    
    deviceId = myGlobals.packetQueue[myGlobals.packetQueueTail].deviceId;
    myGlobals.packetQueueTail = (myGlobals.packetQueueTail+1) % CONST_PACKET_QUEUE_LENGTH;
    myGlobals.packetQueueLen--;
    releaseMutex(&myGlobals.packetQueueMutex);
#ifdef DEBUG_THREADS
    traceEvent(CONST_TRACE_INFO, "- [packet queue=%d/max=%d]\n", myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Processing packet... [packet queue=%d/max=%d]\n",
	       myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

    HEARTBEAT(9, "dequeuePacket()...processing...", NULL);
    myGlobals.actTime = time(NULL);
    processPacket((u_char*)((long)deviceId), &h, p);
  }

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Packet Processor thread (%ld) terminated...\n", myGlobals.dequeueThreadId);
  return(NULL); 
}

#endif /* CFG_MULTITHREADED */


/* ************************************ */

static void flowsProcess(const struct pcap_pkthdr *h, const u_char *p, int deviceId) {
  FlowFilterList *list = myGlobals.flowsList;

  while(list != NULL) {
    if((list->pluginStatus.activePlugin)
       && (list->fcode[deviceId].bf_insns != NULL)
       && (bpf_filter(list->fcode[deviceId].bf_insns,
		      (u_char*)p, h->len, h->caplen))) {
      incrementTrafficCounter(&list->bytes, h->len);
      incrementTrafficCounter(&list->packets, 1);
      if(list->pluginStatus.pluginPtr != NULL) {
	void(*pluginFunc)(u_char*, const struct pcap_pkthdr*, const u_char*);

	pluginFunc = (void(*)(u_char *_deviceId, const struct pcap_pkthdr*,
			      const u_char*))list->pluginStatus.pluginPtr->pluginFunc;
	pluginFunc((u_char*)&deviceId, h, p);
#ifdef DEBUG
	printf("Match on %s for '%s'\n", myGlobals.device[deviceId].name,
	       list->flowName);
#endif
      }
    } else {
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "No match on %s for '%s'\n", myGlobals.device[deviceId].name,
		 list->flowName);
#endif
    }

    list = list->next;
  }
}

/* ************************************ */


struct timeval current_pkt = {0,0};
struct timeval first_pkt = {0,0};
struct timeval last_pkt = {0,0};

#if PACKET_DEBUG
/*
 * The time difference in milliseconds.
 *
 * Rocco Carbone <rocco@ntop.org>
 */
static time_t delta_time_in_milliseconds (struct timeval * now,
					  struct timeval * before) {
  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  time_t delta_seconds = now->tv_sec - before->tv_sec;
  time_t delta_milliseconds = (now->tv_usec - before->tv_usec) / 1000;

  if (delta_milliseconds < 0)
    { /* manually carry a one from the seconds field */
      delta_milliseconds += 1000; 		/* 1e3 */
      -- delta_seconds;
    }
  return ((delta_seconds * 1000) + delta_milliseconds);
}
#endif

/* ************************************************ */

#if PACKET_DEBUG
/*
 * Return a well formatted timestamp.
 */
static char* timestamp(const struct timeval* t, int fmt) {
  static char buf [16] = {0};

  time_t now = time((time_t*) 0);
  struct tm *tm, myTm;

  tm = localtime_r(&now, &myTm);

  gettimeofday(&current_pkt, NULL);

  switch(fmt)
    {
    default:
    case FLAG_TIMESTAMP_FMT_DELTA:
      /*
       * calculate the difference in milliseconds since
       * the previous packet was displayed
       */
      if(snprintf(buf, 16, "%10ld ms",
		  delta_time_in_milliseconds(&current_pkt, &last_pkt)) < 0)
	BufferTooShort();
      break;

    case FLAG_TIMESTAMP_FMT_ABS:
      if(snprintf(buf, 16, "%02d:%02d:%02d.%06d",
		  tm->tm_hour, tm->tm_min, tm->tm_sec, (int)t->tv_usec) < 0)
	BufferTooShort();
      break;

    case FLAG_TIMESTAMP_FMT_RELATIVE:
      /*
       * calculate the difference in milliseconds
       * since the previous packet was displayed
       */
      if(snprintf(buf, 16, "%10ld ms",
		  delta_time_in_milliseconds(&current_pkt, &first_pkt)) < 0)
	BufferTooShort();
      break;
    }

  return (buf);
}
#endif

/* ************************************ */

void updateDevicePacketStats(u_int length, int actualDeviceId) {
  if(length < 64)        incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo64, 1);
  else if(length < 128)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo128, 1);
  else if(length < 256)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo256, 1);
  else if(length < 512)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo512, 1);
  else if(length < 1024) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo1024, 1);
  else if(length < 1518) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo1518, 1);
  else                   incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.above1518, 1);

  if((myGlobals.device[actualDeviceId].rcvdPktStats.shortest.value == 0)
     || (myGlobals.device[actualDeviceId].rcvdPktStats.shortest.value > length))
    myGlobals.device[actualDeviceId].rcvdPktStats.shortest.value = length;

  if(myGlobals.device[actualDeviceId].rcvdPktStats.longest.value < length)
    myGlobals.device[actualDeviceId].rcvdPktStats.longest.value = length;
}

/* ***************************************************** */

void dumpSuspiciousPacket(int actualDeviceId) {
  if(myGlobals.device[actualDeviceId].pcapErrDumper != NULL)
    pcap_dump((u_char*)myGlobals.device[actualDeviceId].pcapErrDumper, h_save, p_save);
}

/* ***************************************************** */

/*
 * This is the top level routine of the printer.  'p' is the points
 * to the ether header of the packet, 'tvp' is the timestamp,
 * 'length' is the length of the packet off the wire, and 'caplen'
 * is the number of bytes actually captured.
 */

void processPacket(u_char *_deviceId,
		   const struct pcap_pkthdr *h,
		   const u_char *p) {
  struct ether_header ehdr;
  struct tokenRing_header *trp;
  struct fddi_header *fddip;
  u_int hlen, caplen = h->caplen;
  u_int headerDisplacement = 0, length = h->len;
  const u_char *orig_p = p, *p1;
  u_char *ether_src=NULL, *ether_dst=NULL;
  unsigned short eth_type=0;
  /* Token-Ring Strings */
  struct tokenRing_llc *trllc;
  FILE * fd;
  unsigned char ipxBuffer[128];
  int deviceId, actualDeviceId, vlanId=-1;


#ifdef MEMORY_DEBUG
  {
    static long numPkt=0;

    /* traceEvent(CONST_TRACE_INFO, "%ld (%ld)\n", numPkt, length); */

    if(numPkt ==  /* 10000 */ 1000000) {
      cleanup(2);
    } else
      numPkt++;

    /*
      if(numPkt=100000) {
      int i;

      for(i=0; i<myGlobals.numDevices; i++)
      freeHostInstances(i);
      }
    */
  }
#endif

  if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN)
    return;

  h_save = h, p_save = p;

#ifdef DEBUG
  if(myGlobals.rFileName != NULL) {
    traceEvent(CONST_TRACE_INFO, ".");
    fflush(stdout);
  }
#endif

  /*
    This allows me to fetch the time from
    the captured packet instead of calling
    time(NULL).
  */
  myGlobals.actTime = h->ts.tv_sec;

#ifdef WIN32
  deviceId = 0;
#else
  deviceId = (int)_deviceId;
#endif

  actualDeviceId = getActualInterface(deviceId);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "deviceId=%d - actualDeviceId=%ld\n", deviceId, actualDeviceId);
#endif

  updateDevicePacketStats(length, actualDeviceId);

  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ethernetPkts, 1);
  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ethernetBytes, h->len);

  if(myGlobals.device[actualDeviceId].pcapDumper != NULL)
    pcap_dump((u_char*)myGlobals.device[actualDeviceId].pcapDumper, h, p);

  if ( (myGlobals.device[deviceId].datalink < MAX_DLT_ARRAY) &&
       (length > myGlobals.mtuSize[myGlobals.device[deviceId].datalink]) ) {
    /* Sanity check */
    if(myGlobals.enableSuspiciousPacketDump) {
      traceEvent(CONST_TRACE_WARNING, "Packet # %u too long (len = %u)!\n",
		 (unsigned int)myGlobals.device[deviceId].ethernetPkts.value,
		 (unsigned int)length);
      dumpSuspiciousPacket(actualDeviceId);
    }

    /* Fix below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
    length = myGlobals.mtuSize[myGlobals.device[deviceId].datalink];
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.tooLong, 1);
  }

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.hostsHashMutex, "processPacket");
#endif

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "actualDeviceId = %d\n", actualDeviceId);
#endif

  hlen = (myGlobals.device[deviceId].datalink == DLT_NULL) ? CONST_NULL_HDRLEN : sizeof(struct ether_header);

  memcpy(&myGlobals.lastPktTime, &h->ts, sizeof(myGlobals.lastPktTime));

  fd = myGlobals.device[deviceId].fdv;

  /*
   * Show a hash character for each packet captured
   */
  if(fd && myGlobals.device[deviceId].hashing) {
    fprintf (fd, "#");
    fflush(fd);
  }

  /* ethernet assumed */
  if(caplen >= hlen) {
    HostTraffic *srcHost=NULL, *dstHost=NULL;
    u_int srcHostIdx, dstHostIdx;

    memcpy(&ehdr, p, sizeof(struct ether_header));

    switch(myGlobals.device[deviceId].datalink) {
    case DLT_FDDI:
      fddip = (struct fddi_header *)p;
      length -= FDDI_HDRLEN;
      p += FDDI_HDRLEN;
      caplen -= FDDI_HDRLEN;

      extract_fddi_addrs(fddip, (char *)ESRC(&ehdr), (char *)EDST(&ehdr));
      ether_src = (u_char*)ESRC(&ehdr), ether_dst = (u_char*)EDST(&ehdr);

      if((fddip->fc & CONST_FDDIFC_CLFF) == CONST_FDDIFC_CONST_LLC_ASYNC) {
	struct llc llc;

	/*
	  Info on SNAP/LLC:
	  http://www.erg.abdn.ac.uk/users/gorry/course/lan-pages/llc.html
	  http://www.ece.wpi.edu/courses/ee535/hwk96/hwk3cd96/li/li.html
	  http://www.ece.wpi.edu/courses/ee535/hwk96/hwk3cd96/li/li.html
	*/
	memcpy((char *)&llc, (char *)p, min(caplen, sizeof(llc)));
	if(llc.ssap == LLCSAP_SNAP && llc.dsap == LLCSAP_SNAP
	   && llc.ctl.snap.snap_ui == CONST_LLC_UI) {
	  if(caplen >= sizeof(llc)) {
	    caplen -= sizeof(llc);
	    length -= sizeof(llc);
	    p += sizeof(llc);

	    if(EXTRACT_16BITS(&llc.ctl.snap_ether.snap_ethertype[0]) == ETHERTYPE_IP) {
	      /* encapsulated IP packet */
	      processIpPkt(p, h, length, ether_src, ether_dst, actualDeviceId, vlanId);
	      /*
		Patch below courtesy of
		Fabrice Bellet <Fabrice.Bellet@creatis.insa-lyon.fr>
	      */
#ifdef CFG_MULTITHREADED
	      releaseMutex(&myGlobals.hostsHashMutex);
#endif
	      return;
	    }
	  }
	}
      }
      break;

    case DLT_NULL: /* loopaback interface */
      /*
	Support for ethernet headerless interfaces (e.g. lo0)
	Courtesy of Martin Kammerhofer <dada@sbox.tu-graz.ac.at>
      */

      length -= CONST_NULL_HDRLEN; /* don't count nullhdr */

      /* All this crap is due to the old little/big endian story... */
      if((p[0] == 0) && (p[1] == 0) && (p[2] == 8) && (p[3] == 0))
	eth_type = ETHERTYPE_IP;
      else if((p[0] == 0) && (p[1] == 0) && (p[2] == 0x86) && (p[3] == 0xdd))
	eth_type = ETHERTYPE_IPv6;
      ether_src = ether_dst = myGlobals.dummyEthAddress;
      break;

    case DLT_PPP:
      headerDisplacement = CONST_PPP_HDRLEN;
      /*
	PPP is like RAW IP. The only difference is that PPP
	has a header that's not present in RAW IP.

	IMPORTANT: DO NOT PUT A break BELOW this comment
      */

    case DLT_RAW: /* RAW IP (no ethernet header) */
      length -= headerDisplacement; /* don't count PPP header */
      ether_src = ether_dst = NULL;
      processIpPkt(p+headerDisplacement, h, length, NULL, NULL, actualDeviceId, vlanId);
      break;

      /* PPPoE patch courtesy of Stefano Picerno <stefanopp@libero.it> */
#ifdef LINUX
    case DLT_LINUX_SLL: /* Linux capture interface */
      length = h->len;
      length -= SLL_HDR_LEN;
      ether_src = ether_dst = NULL;
      processIpPkt(p+ SLL_HDR_LEN , h, length, ether_src, ether_dst, actualDeviceId, vlanId);
      break;
#endif

    case DLT_IEEE802: /* Token Ring */
      trp = (struct tokenRing_header*)p;
      ether_src = (u_char*)trp->trn_shost, ether_dst = (u_char*)trp->trn_dhost;

      hlen = sizeof(struct tokenRing_header) - 18;

      if(trp->trn_shost[0] & CONST_TR_RII) /* Source Routed Packet */
	hlen += ((ntohs(trp->trn_rcf) & CONST_TR_RCF_LEN_MASK) >> 8);

      length -= hlen, caplen -= hlen;

      p += hlen;
      trllc = (struct tokenRing_llc *)p;

      if(trllc->dsap == 0xAA && trllc->ssap == 0xAA)
	hlen = sizeof(struct tokenRing_llc);
      else
	hlen = sizeof(struct tokenRing_llc) - 5;

      length -= hlen, caplen -= hlen;

      p += hlen;

      if(hlen == sizeof(struct tokenRing_llc))
	eth_type = ntohs(trllc->ethType);
      else
	eth_type = 0;
      break;

    default:
      eth_type = ntohs(ehdr.ether_type);
      /*
	NOTE:
	eth_type is a 32 bit integer (eg. 0x0800). If the first
	byte is NOT null (08 in the example below) then this is
	a Ethernet II frame, otherwise is a IEEE 802.3 Ethernet
	frame.
      */
      ether_src = ESRC(&ehdr), ether_dst = EDST(&ehdr);

      if(eth_type == ETHERTYPE_802_1Q) /* VLAN */ {
	Ether80211q qType;
	
	memcpy(&qType, p+sizeof(struct ether_header), sizeof(Ether80211q));
	vlanId = ntohs(qType.vlanId) & 0xFFF;
#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "VLAN Id: %d", vlanId);
#endif
	eth_type = ntohs(qType.protoType);
      }
    } /* switch(myGlobals.device[deviceId].datalink) */

#if PACKET_DEBUG
    /*
     * Time to show the Ethernet Packet Header (when enabled).
     */
    if(fd && myGlobals.device [deviceId].ethv)
        fprintf (fd, "PACKET_DEBUG: ETHER:  ----- Ether Header -----\n\n"),
	fprintf (fd, "                      Packet %ld arrived at %s\n",
		 myGlobals.device [actualDeviceId].ethernetPkts, timestamp (& h->ts, FLAG_TIMESTAMP_FMT_ABS)),
	fprintf (fd, "                      Total size  = %d : header = %d : data = %d\n",
		 length, hlen, length - hlen),
	fprintf (fd, "                      Source      = %s\n", etheraddr_string (ether_src)),
	fprintf (fd, "                      Destination = %s\n", etheraddr_string (ether_dst));
    fflush (fd);
#endif

    if((myGlobals.device[deviceId].datalink != DLT_PPP)
       && (myGlobals.device[deviceId].datalink != DLT_RAW)
#ifdef LINUX
       && (myGlobals.device[deviceId].datalink != DLT_LINUX_SLL)  
#endif
       ) {
      if((!myGlobals.dontTrustMACaddr) && (eth_type == 0x8137)) {
	/* IPX */
	IPXpacket ipxPkt;

	srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	if(srcHost == NULL) {
	  /* Sanity check */
	  traceEvent(CONST_TRACE_ERROR, "Sanity check failed (5) [Low memory?]");
	  return;
	}

	dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
	dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	if(dstHost == NULL) {
	  /* Sanity check */
	  traceEvent(CONST_TRACE_ERROR, "Sanity check failed (6) [Low memory?]");
	  return;
	}

	if(vlanId != -1) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }

	memcpy((char *)&ipxPkt, (char *)p+sizeof(struct ether_header), sizeof(IPXpacket));

	if(ntohs(ipxPkt.dstSocket) == 0x0452) {
	  /* SAP */
	  int displ = sizeof(struct ether_header);
	  p1 = p+displ;
	  length -= displ;
	  goto handleIPX;
	} else {
	  TrafficCounter ctr;
	  
	  incrementTrafficCounter(&srcHost->ipxSent, length), incrementTrafficCounter(&dstHost->ipxRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipxBytes, length);

	  ctr.value = length;
	  updatePacketCount(srcHost, dstHost, ctr, 1, actualDeviceId);
	}
      } else if((myGlobals.device[deviceId].datalink == DLT_IEEE802) && (eth_type < ETHERMTU)) {
	TrafficCounter ctr;

	trp = (struct tokenRing_header*)orig_p;
	ether_src = (u_char*)trp->trn_shost, ether_dst = (u_char*)trp->trn_dhost;
	srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	if(srcHost == NULL) {
	  /* Sanity check */
	  traceEvent(CONST_TRACE_ERROR, "Sanity check failed (7) [Low memory?]");
	  return;
	}

	dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
	dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	if(dstHost == NULL) {
	  /* Sanity check */
	  traceEvent(CONST_TRACE_ERROR, "Sanity check failed (8) [Low memory?]");
	  return;
	}

	if(vlanId != -1) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }
	incrementTrafficCounter(&srcHost->otherSent, length);
	incrementTrafficCounter(&dstHost->otherRcvd, length);
	ctr.value = length;

	updatePacketCount(srcHost, dstHost, ctr, 1, actualDeviceId);
      } else if((myGlobals.device[deviceId].datalink != DLT_IEEE802)
		&& (eth_type <= ETHERMTU) && (length > 3)) {
	/* The code below has been taken from tcpdump */
	u_char sap_type;
	struct llc llcHeader;

	if((ether_dst != NULL)
	   && (!myGlobals.dontTrustMACaddr)
	   && (strcmp(etheraddr_string(ether_dst), "FF:FF:FF:FF:FF:FF") == 0)
	   && (p[sizeof(struct ether_header)] == 0xff)
	   && (p[sizeof(struct ether_header)+1] == 0xff)
	   && (p[sizeof(struct ether_header)+4] == 0x0)) {
	  /* IPX */

	  srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	  if(srcHost == NULL) {
	    /* Sanity check */
	    traceEvent(CONST_TRACE_ERROR, "Sanity check failed (9) [Low memory?]");
	    return;
	  }

	  dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
	  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	  if(dstHost == NULL) {
	    /* Sanity check */
	    traceEvent(CONST_TRACE_ERROR, "Sanity check failed (10) [Low memory?]");
	    return;
	  }

	  if(vlanId != -1) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }
	  incrementTrafficCounter(&srcHost->ipxSent, length), incrementTrafficCounter(&dstHost->ipxRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipxBytes, length);
	} else if(!myGlobals.dontTrustMACaddr) {
	  /* MAC addresses are meaningful here */
	  srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	  dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);

	  if((srcHostIdx != FLAG_NO_PEER) && (dstHostIdx != FLAG_NO_PEER)) {
	    TrafficCounter ctr;

	    srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	    dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];

	    if((srcHost == NULL) || (dstHost == NULL)) {
	      traceEvent(CONST_TRACE_ERROR, "Sanity check failed (13) [Low memory?]");
	      return;
	    }

	    if(vlanId != -1) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }
	    p1 = (u_char*)(p+hlen);

	    /* Watch out for possible alignment problems */
	    memcpy(&llcHeader, (char*)p1, min(length, sizeof(llcHeader)));

	    sap_type = llcHeader.ssap & ~CONST_LLC_GSAP;
	    llcsap_string(sap_type);

	    if(sap_type == 0x42) {
	      /* Spanning Tree */
	      incrementTrafficCounter(&srcHost->stpSent, length), incrementTrafficCounter(&dstHost->stpRcvd, length);
	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].stpBytes, length);
	    } else if(myGlobals.enablePacketDecoding && (sap_type == 0xE0)) {
	      /* NetWare */
	      if(!(llcHeader.ssap == LLCSAP_GLOBAL && llcHeader.dsap == LLCSAP_GLOBAL)) {
		p1 += 3; /* LLC Header (short myGlobals.version) */
	      }

	    handleIPX:
	      /* IPX packet beginning */
	      if(length > 128)
		memcpy(ipxBuffer, p1, 128);
	      else
		memcpy(ipxBuffer, p1, length);
	      if((ipxBuffer[16] == 0x04)    /* SAP (Service Advertising Protocol) (byte 0) */
		 && (ipxBuffer[17] == 0x52) /* SAP (Service Advertising Protocol) (byte 1) */
		 && (ipxBuffer[30] == 0x0)  /* SAP Response (byte 0) */
		 && (ipxBuffer[31] == 0x02) /* SAP Response (byte 1) */) {
		u_int16_t serverType;
		char serverName[57];
		int i, found;

		memcpy(&serverType, &ipxBuffer[32], 2);

		serverType = ntohs(serverType);

		memcpy(serverName, &ipxBuffer[34], 56); serverName[56] = '\0';
		for(i=0; i<56; i++)
		  if(serverName[i] == '!') {
		    serverName[i] = '\0';
		    break;
		  }

		if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
		for(i=0, found=0; i<srcHost->nonIPTraffic->numIpxNodeTypes; i++)
		  if(srcHost->nonIPTraffic->ipxNodeType[i] == serverType) {
		    found = 1;
		    break;
		  }

		if((!found) && (srcHost->nonIPTraffic->numIpxNodeTypes < MAX_NODE_TYPES)) {
		  srcHost->nonIPTraffic->ipxNodeType[srcHost->nonIPTraffic->numIpxNodeTypes] = serverType;
		  srcHost->nonIPTraffic->numIpxNodeTypes++;

		  switch(serverType) {
		  case 0x0007: /* Print server */
		  case 0x0003: /* Print Queue */
		  case 0x8002: /* Intel NetPort Print Server */
		  case 0x030c: /* HP LaserJet / Quick Silver */
		    FD_SET(FLAG_HOST_TYPE_PRINTER, &srcHost->flags);
		    break;

		  case 0x0027: /* TCP/IP gateway */
		  case 0x0021: /* NAS SNA gateway */
		  case 0x055d: /* Attachmate SNA gateway */
		    FD_SET(FLAG_GATEWAY_HOST, &srcHost->flags);
		    /* ==> updateRoutedTraffic(srcHost);
		       is not needed as there are no routed packets */
		    break;

		  case 0x0004: /* File server */
		  case 0x0005: /* Job server */
		  case 0x0008: /* Archive server */
		  case 0x0009: /* Archive server */
		  case 0x002e: /* Archive Server Dynamic SAP */
		  case 0x0098: /* NetWare access server */
		  case 0x009a: /* Named Pipes server */
		  case 0x0111: /* Test server */
		  case 0x03e1: /* UnixWare Application Server */
		  case 0x0810: /* ELAN License Server Demo */
		    FD_SET(FLAG_HOST_TYPE_SERVER, &srcHost->flags);
		    break;

		  case 0x0278: /* NetWare Directory server */
		    FD_SET(FLAG_HOST_TYPE_SVC_DIRECTORY, &srcHost->flags);
		    break;

		  case 0x0024: /* Rem bridge */
		  case 0x0026: /* Bridge server */
		    FD_SET(FLAG_HOST_TYPE_SVC_BRIDGE, &srcHost->flags);
		    break;

		  case 0x0640: /* NT Server-RPC/GW for NW/Win95 User Level Sec */
		  case 0x064e: /* NT Server-IIS */
		    FD_SET(FLAG_HOST_TYPE_SERVER, &srcHost->flags);
		    break;

		  case 0x0133: /* NetWare Name Service */
		    FD_SET(FLAG_NAME_SERVER_HOST, &srcHost->flags);
		    break;
		  }
		}

		if(srcHost->nonIPTraffic->ipxHostName == NULL) {
		  for(i=1; i<strlen(serverName); i++)
		    if((serverName[i] == '_') && (serverName[i-1] == '_')) {
		      serverName[i-1] = '\0'; /* Avoid weird names */
		      break;
		    }

		  if(strlen(serverName) >= (MAX_LEN_SYM_HOST_NAME-1))
		    serverName[MAX_LEN_SYM_HOST_NAME-2] = '\0';
		  srcHost->nonIPTraffic->ipxHostName = strdup(serverName);
		  for(i=0; srcHost->nonIPTraffic->ipxHostName[i] != '\0'; i++)
		    srcHost->nonIPTraffic->ipxHostName[i] = tolower(srcHost->nonIPTraffic->ipxHostName[i]);

		  updateHostName(srcHost);
		}
#ifdef DEBUG
		traceEvent(CONST_TRACE_INFO, "%s [%s][%x]\n", serverName,
			   getSAPInfo(serverType, 0), serverType);
#endif
	      }

	      incrementTrafficCounter(&srcHost->ipxSent, length), incrementTrafficCounter(&dstHost->ipxRcvd, length);
	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipxBytes, length);
	    } else if((llcHeader.ssap == LLCSAP_NETBIOS)
		      && (llcHeader.dsap == LLCSAP_NETBIOS)) {
	      /* Netbios */
	      if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	      if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	      incrementTrafficCounter(&srcHost->netbiosSent, length);
	      incrementTrafficCounter(&dstHost->netbiosRcvd, length);
	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].netbiosBytes, length);
	    } else if((sap_type == 0xF0)
		      || (sap_type == 0xB4)
		      || (sap_type == 0xC4)
		      || (sap_type == 0xF8)) {
	      /* DLC (protocol used for printers) */
	      incrementTrafficCounter(&srcHost->dlcSent, length);
	      incrementTrafficCounter(&dstHost->dlcRcvd, length);
	      FD_SET(FLAG_HOST_TYPE_PRINTER, &dstHost->flags);
	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].dlcBytes, length);
	    } else if(sap_type == 0xAA /* SNAP */) {
	      u_int16_t snapType;

	      p1 = (u_char*)(p1+sizeof(llcHeader));
	      memcpy(&snapType, p1, sizeof(snapType));

	      snapType = ntohs(snapType);
	      /*
		See section
		"ETHERNET NUMBERS OF INTEREST" in RFC 1060

		http://www.faqs.org/rfcs/rfc1060.html
	      */
	      if(myGlobals.enablePacketDecoding
		 && ((snapType == 0x809B) || (snapType == 0x80F3))) {
		/* Appletalk */
		AtDDPheader ddpHeader;

		memcpy(&ddpHeader, (char*)p1, sizeof(AtDDPheader));
		
		if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
		if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));

		srcHost->nonIPTraffic->atNetwork = ntohs(ddpHeader.srcNet), srcHost->nonIPTraffic->atNode = ddpHeader.srcNode;
		dstHost->nonIPTraffic->atNetwork = ntohs(ddpHeader.dstNet), dstHost->nonIPTraffic->atNode = ddpHeader.dstNode;

		if(ddpHeader.ddpType == 2) {
		  /* Appletalk NBP (Name Binding Protocol) */
		  AtNBPheader nbpHeader;
		  int numTuples, i;

		  p1 = (u_char*)(p1+13);
		  memcpy(&nbpHeader, (char*)p1, sizeof(AtNBPheader));
		  numTuples = nbpHeader.function & 0x0F;

		  if((nbpHeader.function == 0x21) && (numTuples == 1)) {
		    char nodeName[256];
		    int displ;

		    p1 = (u_char*)(p1+2);

		    if(p1[6] == '=')
		      displ = 2;
		    else
		      displ = 0;

		    memcpy(nodeName, &p1[6+displ], p1[5+displ]);
		    nodeName[p1[5+displ]] = '\0';

		    if(strlen(nodeName) >= (MAX_LEN_SYM_HOST_NAME-1))
		      nodeName[MAX_LEN_SYM_HOST_NAME-2] = '\0';

		    if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
		    srcHost->nonIPTraffic->atNodeName = strdup(nodeName);
		    updateHostName(srcHost);

		    memcpy(nodeName, &p1[7+p1[5+displ]+displ], p1[6+p1[5+displ]+displ]);
		    nodeName[p1[6+p1[5+displ]]] = '\0';

		    for(i=0; i<MAX_NODE_TYPES; i++)
		      if((srcHost->nonIPTraffic->atNodeType[i] == NULL)
			 || (strcmp(srcHost->nonIPTraffic->atNodeType[i], nodeName) == 0))
			break;

		    if(srcHost->nonIPTraffic->atNodeType[i] == NULL)
		      srcHost->nonIPTraffic->atNodeType[i] = strdup(nodeName);
		  }
		}

		incrementTrafficCounter(&srcHost->appletalkSent, length);
		incrementTrafficCounter(&dstHost->appletalkRcvd, length);
		incrementTrafficCounter(&myGlobals.device[actualDeviceId].atalkBytes, length);
	      } else {
		if((llcHeader.ctl.snap_ether.snap_orgcode[0] == 0x0)
		   && (llcHeader.ctl.snap_ether.snap_orgcode[1] == 0x0)
		   && (llcHeader.ctl.snap_ether.snap_orgcode[2] == 0x0C) /* Cisco */) {
		  /* NOTE:
		     If llcHeader.ctl.snap_ether.snap_ethertype[0] == 0x20
		     && llcHeader.ctl.snap_ether.snap_ethertype[1] == 0x0
		     this is Cisco Discovery Protocol
		  */

		  FD_SET(FLAG_GATEWAY_HOST, &srcHost->flags);
		}

		incrementTrafficCounter(&srcHost->otherSent, length);
		incrementTrafficCounter(&dstHost->otherRcvd, length);
		incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherBytes, length);
	      }
	    } else if(myGlobals.enablePacketDecoding
		      && ((sap_type == 0x06)
			  || (sap_type == 0xFE)
			  || (sap_type == 0xFC))) {  /* OSI */
	      incrementTrafficCounter(&srcHost->osiSent, length);
	      incrementTrafficCounter(&dstHost->osiRcvd, length);
	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].osiBytes, length);
	    } else {
	      /* Unknown Protocol */
#ifdef UNKNOWN_PACKET_DEBUG
	      traceEvent(CONST_TRACE_INFO, "UNKNOWN_PACKET_DEBUG: [%u] [%x] %s %s > %s\n", 
			 (u_short)sap_type,(u_short)sap_type,
			 etheraddr_string(ether_src),
			 llcsap_string(llcHeader.ssap & ~CONST_LLC_GSAP),
			 etheraddr_string(ether_dst));
#endif
	      incrementTrafficCounter(&srcHost->otherSent, length);
	      incrementTrafficCounter(&dstHost->otherRcvd, length);
	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherBytes, length);
	    }

	    ctr.value = length;
	    updatePacketCount(srcHost, dstHost, ctr, 1, actualDeviceId);
	  }
	}
      } else if(eth_type == ETHERTYPE_IP) {
	if((myGlobals.device[deviceId].datalink == DLT_IEEE802) && (eth_type > ETHERMTU))
	  processIpPkt(p, h, length, ether_src, ether_dst, actualDeviceId, vlanId);
	else
	  processIpPkt(p+hlen, h, length, ether_src, ether_dst, actualDeviceId, vlanId);
      } else if (eth_type == 0x8864) /* PPPOE */ {
        /* PPPoE - Courtesy of Andreas Pfaller Feb2003
         *   This strips the PPPoE encapsulation for traffic transiting the network.
         */
        struct pppoe_hdr *pppoe_hdr=(struct pppoe_hdr *) (p+hlen);
        int protocol=ntohs(*((int *) (p+hlen+6)));

        if (pppoe_hdr->ver==1 && pppoe_hdr->type==1 && pppoe_hdr->code==0 &&
            protocol==0x0021) {
          hlen+=8; /* length of pppoe header */
	  processIpPkt(p+hlen, h, length, NULL, NULL, actualDeviceId, vlanId);
        }
      } else  /* Non IP */ if(!myGlobals.dontTrustMACaddr) {
	/* MAC addresses are meaningful here */
	struct ether_arp arpHdr;
	struct in_addr addr;
	TrafficCounter ctr;

	if(length > hlen)
	  length -= hlen;
	else
	  length = 0;

	srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	if(srcHost == NULL) {
	  /* Sanity check */
	  traceEvent(CONST_TRACE_ERROR, "Sanity check failed (11) [Low memory?]");
	  return;
	}

	dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
	dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	if(dstHost == NULL) {
	  /* Sanity check */
	  traceEvent(CONST_TRACE_ERROR, "Sanity check failed (12) [Low memory?]");
	  return;
	}

	if(vlanId != -1) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }

	switch(eth_type) {
	case ETHERTYPE_ARP: /* ARP - Address resolution Protocol */
	  memcpy(&arpHdr, p+hlen, sizeof(arpHdr));
	  if(EXTRACT_16BITS(&arpHdr.arp_pro) == ETHERTYPE_IP) {
	    int arpOp = EXTRACT_16BITS(&arpHdr.arp_op);

	    switch(arpOp) {
	    case ARPOP_REPLY: /* ARP REPLY */
	      memcpy(&addr.s_addr, arpHdr.arp_tpa, sizeof(addr.s_addr));
	      addr.s_addr = ntohl(addr.s_addr);
	      dstHostIdx = getHostInfo(&addr, (u_char*)&arpHdr.arp_tha, 0, 0, actualDeviceId);
	      dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	      memcpy(&addr.s_addr, arpHdr.arp_spa, sizeof(addr.s_addr));
	      addr.s_addr = ntohl(addr.s_addr);
	      srcHostIdx = getHostInfo(&addr, (u_char*)&arpHdr.arp_sha, 0, 0, actualDeviceId);
	      srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	      if(srcHost != NULL) incrementTrafficCounter(&srcHost->arpReplyPktsSent, 1);
	      if(dstHost != NULL) incrementTrafficCounter(&dstHost->arpReplyPktsRcvd, 1);
	      /* DO NOT ADD A break ABOVE ! */
	    case ARPOP_REQUEST: /* ARP request */
	      memcpy(&addr.s_addr, arpHdr.arp_spa, sizeof(addr.s_addr));
	      addr.s_addr = ntohl(addr.s_addr);
	      srcHostIdx = getHostInfo(&addr, (u_char*)&arpHdr.arp_sha, 0, 0, actualDeviceId);
	      srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	      if((arpOp == ARPOP_REQUEST) && (srcHost != NULL)) incrementTrafficCounter(&srcHost->arpReqPktsSent, 1);
	    }
	  }
	  /* DO NOT ADD A break ABOVE ! */
	case ETHERTYPE_REVARP: /* Reverse ARP */
	  if(srcHost != NULL) incrementTrafficCounter(&srcHost->arp_rarpSent, length);
	  if(dstHost != NULL) incrementTrafficCounter(&dstHost->arp_rarpRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].arpRarpBytes, length);
	  break;
	case ETHERTYPE_DN: /* Decnet */
	  incrementTrafficCounter(&srcHost->decnetSent, length);
	  incrementTrafficCounter(&dstHost->decnetRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].decnetBytes, length);
	  break;
	case ETHERTYPE_ATALK: /* AppleTalk */
	case ETHERTYPE_AARP:
	  incrementTrafficCounter(&srcHost->appletalkSent, length);
	  incrementTrafficCounter(&dstHost->appletalkRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].atalkBytes, length);
	  break;
	case ETHERTYPE_IPv6:
	  incrementTrafficCounter(&srcHost->ipv6Sent, length);
	  incrementTrafficCounter(&dstHost->ipv6Rcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipv6Bytes, length);
	  break;
	default:
#ifdef UNKNOWN_PACKET_DEBUG
	  traceEvent(CONST_TRACE_INFO, "UNKNOWN_PACKET_DEBUG: %s/%s->%s/%s [eth type %d (0x%x)]\n",
		     srcHost->hostNumIpAddress, srcHost->ethAddressString,
		     dstHost->hostNumIpAddress, dstHost->ethAddressString,
		     eth_type, eth_type);
#endif
	  incrementTrafficCounter(&srcHost->otherSent, length);
	  incrementTrafficCounter(&dstHost->otherRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherBytes, length);
	  break;
	}

	ctr.value = length;
	updatePacketCount(srcHost, dstHost, ctr, 1, actualDeviceId);
      }
    }
  }

  if(myGlobals.flowsList != NULL) /* Handle flows last */
    flowsProcess(h, p, deviceId);
  
#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.hostsHashMutex);
#endif

  if(myGlobals.resetHashNow == 1) {
    traceEvent(CONST_TRACE_INFO, "Resetting stats");
    resetStats();
    myGlobals.resetHashNow = 0;
  }
}

