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


/*
  #define DNS_SNIFF_DEBUG
  #define DNS_DEBUG
  #define GDBM_DEBUG
  #define FREE_HOST_INFO
  #define PURGE_DEBUG
  #define PACKET_DEBUG
  #define FRAGMENT_DEBUG
*/

/* #define HASH_DEBUG */

/* #define TRACE_TRAFFIC_INFO */

/* #define PRINT_UNKNOWN_PACKETS */
/* #define MAPPING_DEBUG */


#include "ntop.h"

static const struct pcap_pkthdr *h_save;
static const u_char *p_save;
static u_char ethBroadcast[] = { 255, 255, 255, 255, 255, 255 };

#ifdef HASH_DEBUG
static void dumpHash(); /* Forward */
#endif

/* ******************************* */

u_int findHostInfo(struct in_addr *hostIpAddress, int actualDeviceId) {
  u_int i;

  for(i=0; i<myGlobals.device[actualDeviceId].actualHashSize; i++)
    if(myGlobals.device[actualDeviceId].hash_hostTraffic[i] != NULL)
      if(myGlobals.device[actualDeviceId].hash_hostTraffic[i]->hostIpAddress.s_addr
	 == hostIpAddress->s_addr)
	return i;

  return(NO_PEER);
}

/* ************************************ */

char* getNamedPort(int port) {
  static char outStr[2][8];
  static short portBufIdx=0;
  char* svcName;

  portBufIdx = (portBufIdx+1)%2;

  svcName = getPortByNum(port, IPPROTO_TCP);
  if(svcName == NULL)
    svcName = getPortByNum(port, IPPROTO_UDP);

  if(svcName == NULL) {
    if(snprintf(outStr[portBufIdx], 8, "%d", port) < 0)
      BufferOverflow();
  } else {
    strncpy(outStr[portBufIdx], svcName, 8);
  }

  return(outStr[portBufIdx]);
}

/* ************************************ */

void allocateSecurityHostPkts(HostTraffic *srcHost) {
  if(srcHost->secHostPkts == NULL) {
    srcHost->secHostPkts = (SecurityHostProbes*)malloc(sizeof(SecurityHostProbes));
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
      router->routedTraffic->routedPkts++;
      router->routedTraffic->routedBytes += h_save->len - sizeof(struct ether_header);
    }
  }
}

/* ************************************ */

static int handleIP(u_short port,
		    u_int srcHostIdx,
		    u_int dstHostIdx,
		    u_int length,
		    u_short isPassiveSession,
		    int actualDeviceId) {
  int idx;
  HostTraffic *srcHost, *dstHost;

  if(isPassiveSession) {
    /* Emulate non passive session */
    idx = mapGlobalToLocalIdx(20 /* ftp-data */);
  } else
    idx = mapGlobalToLocalIdx(port);

  if(idx == -1)
    return(-1); /* Unable to locate requested index */

  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];

  if((srcHost == NULL) || (dstHost == NULL)) {
    traceEvent(TRACE_INFO, "Sanity check failed (4) [Low memory?]");
    return(-1);
  }

  if(idx != NO_PEER) {
    if(subnetPseudoLocalHost(srcHost)) {
      if(subnetPseudoLocalHost(dstHost)) {
	if((srcHostIdx != myGlobals.broadcastEntryIdx) 
	   && (srcHostIdx != myGlobals.otherHostEntryIdx) 
	   && (!broadcastHost(srcHost)))
	  srcHost->protoIPTrafficInfos[idx].sentLoc += length;
	if((dstHostIdx != myGlobals.broadcastEntryIdx) 
	   && (dstHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(dstHost)))
	  dstHost->protoIPTrafficInfos[idx].rcvdLoc += length;
	myGlobals.device[actualDeviceId].ipProtoStats[idx].local += length;
      } else {
	if((srcHostIdx != myGlobals.broadcastEntryIdx) 
	   && (srcHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(srcHost)))
	  srcHost->protoIPTrafficInfos[idx].sentRem += length;
	if((dstHostIdx != myGlobals.broadcastEntryIdx) 
	   && (dstHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(dstHost)))
	  dstHost->protoIPTrafficInfos[idx].rcvdLoc += length;
	myGlobals.device[actualDeviceId].ipProtoStats[idx].local2remote += length;
      }
    } else {
      /* srcHost is remote */
      if(subnetPseudoLocalHost(dstHost)) {
	if((srcHostIdx != myGlobals.broadcastEntryIdx) 
	   && (srcHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(srcHost)))
	  srcHost->protoIPTrafficInfos[idx].sentLoc += length;
	if((dstHostIdx != myGlobals.broadcastEntryIdx) 
	   && (dstHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(dstHost)))
	  dstHost->protoIPTrafficInfos[idx].rcvdFromRem += length;
	myGlobals.device[actualDeviceId].ipProtoStats[idx].remote2local += length;
      } else {
	if((srcHostIdx != myGlobals.broadcastEntryIdx) 
	   && (srcHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(srcHost)))
	  srcHost->protoIPTrafficInfos[idx].sentRem += length;
	if((dstHostIdx != myGlobals.broadcastEntryIdx)
	   && (dstHostIdx != myGlobals.otherHostEntryIdx)
	   && (!broadcastHost(dstHost)))
	  dstHost->protoIPTrafficInfos[idx].rcvdFromRem += length;
	myGlobals.device[actualDeviceId].ipProtoStats[idx].remote += length;
      }
    }
  }

  return(idx);
}

/* ************************************ */

static void addContactedPeers(u_int senderIdx, u_int receiverIdx, int actualDeviceId) {
  short i, found;
  HostTraffic *sender, *receiver;

  if(senderIdx == receiverIdx)
    return;

  sender = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(senderIdx)];
  receiver = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(receiverIdx)];

  /* ******************************* */

  if((senderIdx != myGlobals.broadcastEntryIdx) 
     && (senderIdx != myGlobals.otherHostEntryIdx)) {
    if(sender != NULL) {
      for(found=0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	if(sender->contactedSentPeers.peersIndexes[i] != NO_PEER) {
	  if((sender->contactedSentPeers.peersIndexes[i] == receiverIdx)
	     || (((receiverIdx == myGlobals.broadcastEntryIdx) 
		  || (receiverIdx == myGlobals.otherHostEntryIdx)
		  || broadcastHost(receiver))
		 && broadcastHost(myGlobals.device[actualDeviceId].hash_hostTraffic
				  [checkSessionIdx(sender->contactedSentPeers.peersIndexes[i])]))) {
	    found = 1;
	    break;
	  }
	}

      if(found == 0)
	incrementUsageCounter(&sender->contactedSentPeers, receiverIdx, actualDeviceId);
    }
  }

  /* ******************************* */
  if((receiverIdx != myGlobals.broadcastEntryIdx) 
     && (receiverIdx != myGlobals.otherHostEntryIdx)) {
    if(receiver != NULL) {
      for(found=0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	if(receiver->contactedRcvdPeers.peersIndexes[i] != NO_PEER) {
	  if((receiver->contactedRcvdPeers.peersIndexes[i] == senderIdx)
	     || (((senderIdx == myGlobals.broadcastEntryIdx) 
		  || (senderIdx == myGlobals.otherHostEntryIdx)
		  || broadcastHost(sender))
		 && broadcastHost(myGlobals.device[actualDeviceId].
				  hash_hostTraffic[checkSessionIdx(receiver->contactedRcvdPeers.peersIndexes[i])]))) {
	    found = 1;
	    break;
	  }
	}

      if(found == 0)
	incrementUsageCounter(&receiver->contactedRcvdPeers, senderIdx, actualDeviceId);
    }
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
  printf("IPFragment (%p)\n", fragment);
  printf("  %s:%d->%s:%d\n",
         fragment->src->hostSymIpAddress, fragment->sport,
         fragment->dest->hostSymIpAddress, fragment->dport);
  printf("  FragmentId=%d\n", fragment->fragmentId);
  printf("  lastOffset=%d, totalPacketLength=%d\n",
         fragment->lastOffset, fragment->totalPacketLength);
  printf("  totalDataLength=%d, expectedDataLength=%d\n",
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
  if (fragment->fragmentOrder == UNKNOWN_FRAGMENT_ORDER) {
    if(fragment->lastOffset > fragmentOffset)
      fragment->fragmentOrder = DECREASING_FRAGMENT_ORDER;
    else
      fragment->fragmentOrder = INCREASING_FRAGMENT_ORDER;
  }

  if ( (fragment->fragmentOrder == INCREASING_FRAGMENT_ORDER
        && fragment->lastOffset+fragment->lastDataLength > fragmentOffset)
       ||
       (fragment->fragmentOrder == DECREASING_FRAGMENT_ORDER
        && fragment->lastOffset < fragmentOffset+dataLength)) {
    if(myGlobals.enableSuspiciousPacketDump) {
      char buf[BUF_SIZE];
      snprintf(buf, BUF_SIZE, "Detected overlapping packet fragment [%s->%s]: "
               "fragment id=%d, actual offset=%d, previous offset=%d\n",
               fragment->src->hostSymIpAddress,
               fragment->dest->hostSymIpAddress,
               fragment->fragmentId, fragmentOffset,
               fragment->lastOffset);

      logMessage(buf, NTOP_WARNING_MSG);
      dumpSuspiciousPacket(actualDeviceId);
    }

    allocateSecurityHostPkts(fragment->src); allocateSecurityHostPkts(fragment->dest);
    incrementUsageCounter(&fragment->src->secHostPkts->overlappingFragmentSent, dstHostIdx, actualDeviceId);
    incrementUsageCounter(&fragment->dest->secHostPkts->overlappingFragmentRcvd, srcHostIdx, actualDeviceId);
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
    fragment->fragmentOrder = UNKNOWN_FRAGMENT_ORDER;
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
    if((fragment->firstSeen + DOUBLE_TWO_MSL_TIMEOUT) < myGlobals.actTime) {
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
    printf("fragcnt=%d, expcnt=%d\n", fragcnt, expcnt);
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
    u_int routerIdx, j;
    HostTraffic *router;

    routerIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
    
    router = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(routerIdx)];
    
    if(((router->hostNumIpAddress[0] != '\0')
       && (broadcastHost(router)
	   || multicastHost(router)
	   || (!subnetLocalHost(router)) /* No IP: is this a special Multicast address ? */))
       || (router->hostIpAddress.s_addr == dstHost->hostIpAddress.s_addr)
       || (memcmp(router->ethAddress, dstHost->ethAddress, ETHERNET_ADDRESS_LEN) == 0)
       )
      return;

    for(j=0; j<MAX_NUM_CONTACTED_PEERS; j++) {
      if(srcHost->contactedRouters.peersIndexes[j] == routerIdx)
	break;
      else if(srcHost->contactedRouters.peersIndexes[j] == NO_PEER) {
	srcHost->contactedRouters.peersIndexes[j] = routerIdx;
	break;
      }
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, "(%s/%s/%s) -> (%s/%s/%s) routed by [idx=%d/%s/%s/%s]",
	       srcHost->ethAddressString, srcHost->hostNumIpAddress, srcHost->hostSymIpAddress, 
	       dstHost->ethAddressString, dstHost->hostNumIpAddress, dstHost->hostSymIpAddress, 
	       routerIdx,
	       router->ethAddressString,
	       router->hostNumIpAddress,
	       router->hostSymIpAddress);

#endif
    FD_SET(GATEWAY_HOST_FLAG, &router->flags);
    updateRoutedTraffic(router);
  }
}

/* ************************************ */

static void updatePacketCount(u_int srcHostIdx, u_int dstHostIdx,
                              TrafficCounter length, int actualDeviceId) {
  
  HostTraffic *srcHost, *dstHost;
  unsigned short hourId;
  struct tm t, *thisTime;

  if(/* (srcHostIdx == dstHostIdx) || */
     (srcHostIdx == NO_PEER) || (dstHostIdx == NO_PEER))
    return; /* It looks there's something wrong here */

  thisTime = localtime_r(&myGlobals.actTime, &t);
  hourId = thisTime->tm_hour % 24 /* just in case... */;;

  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];

  if((srcHost == NULL) || (dstHost == NULL))
    return;

  srcHost->pktSent++;

  srcHost->last24HoursBytesSent[hourId] += length,
    dstHost->last24HoursBytesRcvd[hourId] += length;

  if((dstHostIdx == myGlobals.broadcastEntryIdx)
     || broadcastHost(dstHost)) {
    srcHost->pktBroadcastSent++;
    srcHost->bytesBroadcastSent += length;
    myGlobals.device[actualDeviceId].broadcastPkts++;
  } else if(isMulticastAddress(&(dstHost->hostIpAddress))) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "%s->%s\n",
	       srcHost->hostSymIpAddress, dstHost->hostSymIpAddress);
#endif
    srcHost->pktMulticastSent++;
    srcHost->bytesMulticastSent += length;
    dstHost->pktMulticastRcvd++;
    dstHost->bytesMulticastRcvd += length;
    myGlobals.device[actualDeviceId].multicastPkts++;
  }

  srcHost->bytesSent += length;
  if(dstHost != NULL) dstHost->bytesRcvd += length;

  dstHost->pktRcvd++;

  if((dstHost != NULL) /*&& (!broadcastHost(dstHost))*/)
    addContactedPeers(srcHostIdx, dstHostIdx, actualDeviceId);
}

/* ************************************ */

void updateHostName(HostTraffic *el) {

  if((el->hostNumIpAddress[0] == '\0')
     || (el->hostSymIpAddress == NULL)
     || strcmp(el->hostSymIpAddress, el->hostNumIpAddress) == 0) {
    int i;

    if(el->nbHostName != NULL) {
      /*
	Use NetBIOS name (when available) if the
	IP address has not been resolved.
      */
      memset(el->hostSymIpAddress, 0, sizeof(el->hostSymIpAddress));
      strcpy(el->hostSymIpAddress, el->nbHostName);
    } else if(el->ipxHostName != NULL)
      strcpy(el->hostSymIpAddress, el->ipxHostName);
    else if(el->atNodeName != NULL)
      strcpy(el->hostSymIpAddress, el->atNodeName);

    if(el->hostSymIpAddress[0] != '\0')
      for(i=0; el->hostSymIpAddress[i] != '\0'; i++)
	el->hostSymIpAddress[i] = (char)tolower(el->hostSymIpAddress[i]);
  }
}

/* ************************************ */

static void updateDevicePacketTTLStats(u_int ttl, int actualDeviceId) {
  if(ttl < 32) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo32++;
  else if(ttl < 64) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo64++;
  else if(ttl < 96) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo96++;
  else if(ttl < 128) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo128++;
  else if(ttl < 160) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo160++;
  else if(ttl < 192) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo192++;
  else if(ttl < 224) myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo224++;
  else myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo255++;
}

/* ************************************ */

static void processIpPkt(const u_char *bp,
			 const struct pcap_pkthdr *h,
			 u_int length,
			 u_char *ether_src,
			 u_char *ether_dst, 
			 int actualDeviceId) {
  u_short sport, dport;
  struct ip ip;
  struct tcphdr tp;
  struct udphdr up;
  struct icmp icmpPkt;
  u_int hlen, tcpDataLength, udpDataLength, off, tcpUdpLen;
  char *proto;
  u_int srcHostIdx, dstHostIdx;
  HostTraffic *srcHost=NULL, *dstHost=NULL;
  u_char etherAddrSrc[ETHERNET_ADDRESS_LEN+1],
    etherAddrDst[ETHERNET_ADDRESS_LEN+1], forceUsingIPaddress = 0;
  struct timeval tvstrct;
  u_char *theData;

  myGlobals.device[actualDeviceId].ipBytes += length; myGlobals.device[actualDeviceId].ipPkts++;

  /* Need to copy this over in case bp isn't properly aligned.
   * This occurs on SunOS 4.x at least.
   * Paul D. Smith <psmith@baynetworks.com>
   */
  memcpy(&ip, bp, sizeof(struct ip));
  hlen = (u_int)ip.ip_hl * 4;

  if(in_cksum((const u_short *)bp, hlen, 0) != 0) {
    myGlobals.device[actualDeviceId].rcvdPktStats.badChecksum++;
  }

  if(ip.ip_p == GRE_PROTOCOL_TYPE) {
    /*
      Cisco GRE (Generic Routing Encapsulation)
      Tunnels (RFC 1701, 1702)
    */
    GreTunnel tunnel;

    memcpy(&tunnel, bp+hlen, sizeof(GreTunnel));

    if(ntohs(tunnel.protocol) == PPP_PROTOCOL_TYPE) {
      PPPTunnelHeader pppTHeader;

      memcpy(&pppTHeader, bp+hlen+sizeof(GreTunnel), sizeof(PPPTunnelHeader));

      if(ntohs(pppTHeader.protocol) == 0x21 /* IP */) {

	memcpy(&ip, bp+hlen+sizeof(GreTunnel)+sizeof(PPPTunnelHeader), sizeof(struct ip));
	hlen = (u_int)ip.ip_hl * 4;
	ether_src = NULL, ether_dst = NULL;
      }
    }
  }

  if((ether_src == NULL) && (ether_dst == NULL)) {
    /* Ethernet-less protocols (e.g. PPP/RAW IP) */

    memcpy(etherAddrSrc, &(ip.ip_src.s_addr), sizeof(ip.ip_src.s_addr));
    etherAddrSrc[ETHERNET_ADDRESS_LEN] = '\0';
    ether_src = etherAddrSrc;

    memcpy(etherAddrDst, &(ip.ip_dst.s_addr), sizeof(ip.ip_dst.s_addr));
    etherAddrDst[ETHERNET_ADDRESS_LEN] = '\0';
    ether_dst = etherAddrDst;
  }

  NTOHL(ip.ip_dst.s_addr); NTOHL(ip.ip_src.s_addr);

  if((!myGlobals.borderSnifferMode) 
     && isBroadcastAddress(&ip.ip_dst) 
     && (memcmp(ether_dst, ethBroadcast, 6) != 0)) {
    /* forceUsingIPaddress = 1; */

    srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
    srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
    if(srcHost != NULL) {
      if(myGlobals.enableSuspiciousPacketDump && (!hasWrongNetmask(srcHost))) {
	/* Dump the first packet only */

	traceEvent(TRACE_WARNING, "Host %s has a wrong netmask",
		   etheraddr_string(ether_src));
	dumpSuspiciousPacket(actualDeviceId);
      }
      FD_SET(HOST_WRONG_NETMASK, &srcHost->flags);
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
    traceEvent(TRACE_INFO, "Sanity check failed (1) [Low memory?] (idx=%d)", srcHostIdx);
    return; /* It might be that there's not enough memory that that
	       dstHostIdx = getHostInfo(&ip.ip_dst, ether_dst) caused
	       srcHost to be freed */
  } else {
    /* Lock the instance so that the next call
       to getHostInfo won't purge it */
    srcHost->instanceInUse++;
  }

  if(dstHost == NULL) {
    /* Sanity check */
    traceEvent(TRACE_INFO, "Sanity check failed (2) [Low memory?]");
    return;
  } else {
    /* Lock the instance so that the next call
       to getHostInfo won't purge it */
    dstHost->instanceInUse++;
  }

#ifdef DEBUG
  if(myGlobals.rFileName != NULL) {
    static int numPkt=1;

    traceEvent(TRACE_INFO, "%d) %s -> %s",
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

  if(!myGlobals.borderSnifferMode) checkNetworkRouter(srcHost, dstHost, ether_dst, actualDeviceId);
  updatePacketCount(srcHostIdx, dstHostIdx, (TrafficCounter)h->len, actualDeviceId);
  updateTrafficMatrix(srcHost, dstHost, (TrafficCounter)length, actualDeviceId);

  srcHost->ipBytesSent += length, dstHost->ipBytesRcvd += length;

  if(subnetPseudoLocalHost(srcHost)) {
    if(subnetPseudoLocalHost(dstHost)) {
      srcHost->bytesSentLoc += length;
      dstHost->bytesRcvdLoc += length;
    } else {
      srcHost->bytesSentRem += length;
      dstHost->bytesRcvdLoc += length;
    }
  } else {
    /* srcHost is remote */
    if(subnetPseudoLocalHost(dstHost)) {
      srcHost->bytesSentLoc += length;
      dstHost->bytesRcvdFromRem += length;
    } else {
      srcHost->bytesSentRem += length;
      dstHost->bytesRcvdFromRem += length;
    }
  }

#if PACKET_DEBUG
  /*
   * Time to show the IP Packet Header (when enabled).
   */
  if (fd && myGlobals.device [actualDeviceId] . ipv)
    fprintf (fd, "IP:     ----- IP Header -----\n"),
      fprintf (fd, "IP:\n"),
      fprintf (fd, "IP:     Packet %ld arrived at %s\n", myGlobals.device [actualDeviceId] ,
	       timestamp (& myGlobals.lastPktTime, ABS_FMT)),
      fprintf (fd, "IP:     Total size  = %d : header = %d : data = %d\n",
	       ip_size, ip_hlen, ip_size - ip_hlen),
      fprintf (fd, "IP:     Source      = %s\n", inet_ntoa (ip->ip_src)),
      fprintf (fd, "IP:     Destination = %s\n", inet_ntoa (ip->ip_dst)),
      fflush (fd);
#endif

  off = ntohs(ip.ip_off);

  if (off & 0x3fff) {
    /* 
       This is a fragment: fragment handling is handled by handleFragment()
       called below.

       Courtesy of Andreas Pfaller
     */
    myGlobals.device[actualDeviceId].fragmentedIpBytes += length;
    
    switch(ip.ip_p) {
    case IPPROTO_TCP:
      srcHost->tcpFragmentsSent += length, dstHost->tcpFragmentsRcvd += length;
      break;
    case IPPROTO_UDP:
      srcHost->udpFragmentsSent += length, dstHost->udpFragmentsRcvd += length;
      break;
    case IPPROTO_ICMP:
      srcHost->icmpFragmentsSent += length, dstHost->icmpFragmentsRcvd += length;
      break;
    }
  }
  
  tcpUdpLen = ntohs(ip.ip_len) - hlen;

  switch(ip.ip_p) {
  case IPPROTO_TCP:
    myGlobals.device[actualDeviceId].tcpBytes += tcpUdpLen;

    if(tcpUdpLen < sizeof(struct tcphdr)) {
      if(myGlobals.enableSuspiciousPacketDump) {
	traceEvent(TRACE_WARNING, "WARNING: Malformed TCP pkt %s->%s detected (packet too short)",
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

      if(myGlobals.tcpChain) {
	u_int displ;

	if(off & 0x3fff)
	  displ = 0; /* Fragment */
	else
	  displ = tp.th_off * 4;

	checkFilterChain(srcHost, srcHostIdx,
			 dstHost, dstHostIdx,
			 sport, dport,
			 tcpDataLength, /* packet length */
			 displ+sizeof(struct tcphdr), /* offset from packet header */
			 tp.th_flags, /* TCP flags */
			 IPPROTO_TCP,
			 (u_char)(off & 0x3fff), /* 1 = fragment, 0 = packet */
			 bp, /* pointer to packet content */
			 myGlobals.tcpChain, TCP_RULE, actualDeviceId);
      }

      /*
	Don't move this code on top as it is supposed to stay here
	as it modifies sport/sport 
	
	Courtesy of Andreas Pfaller
      */
      if(off & 0x3fff) {
	/* Handle fragmented packets */
	length = handleFragment(srcHost, srcHostIdx, dstHost, dstHostIdx,
				&sport, &dport,
				ntohs(ip.ip_id), off, length,
				ntohs(ip.ip_len) - hlen, actualDeviceId);       
      }
      
      if((sport > 0) && (dport > 0)) {
	IPSession *theSession;
	u_short isPassiveSession = 0, nonFullyRemoteSession = 1;

	/* It might be that tcpDataLength is 0 when
	   the rcvd packet is fragmented and the main
	   packet has not yet been rcvd */

	if(subnetPseudoLocalHost(srcHost)) {
	  if(subnetPseudoLocalHost(dstHost)) {
	    srcHost->tcpSentLoc += length;
	    dstHost->tcpRcvdLoc += length;
	    myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.local += length;
	  } else {
	    srcHost->tcpSentRem += length;
	    dstHost->tcpRcvdLoc += length;
	    myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.local2remote += length;
	  }
	} else {
	  /* srcHost is remote */
	  if(subnetPseudoLocalHost(dstHost)) {
	    srcHost->tcpSentLoc += length;
	    dstHost->tcpRcvdFromRem += length;
	    myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.remote2local += length;
	  } else {
	    srcHost->tcpSentRem += length;
	    dstHost->tcpRcvdFromRem += length;
	    myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.remote += length;
	    nonFullyRemoteSession = 0;
	  }
	}

	if((!myGlobals.borderSnifferMode) || nonFullyRemoteSession) {
	  theSession = handleTCPSession(h, (off & 0x3fff), tp.th_win,
					srcHostIdx, sport, dstHostIdx,
					dport, length, &tp, tcpDataLength,
					theData, actualDeviceId);
	  if(theSession == NULL)
	    isPassiveSession = 0;
	  else
	    isPassiveSession = theSession->passiveFtpSession;
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
	if(dport < sport) {
	  if(handleIP(dport, srcHostIdx, dstHostIdx, length, isPassiveSession, actualDeviceId) == -1)
	    handleIP(sport, srcHostIdx, dstHostIdx, length, isPassiveSession, actualDeviceId);
	} else {
	  if(handleIP(sport, srcHostIdx, dstHostIdx, length, isPassiveSession, actualDeviceId) == -1)
	    handleIP(dport, srcHostIdx, dstHostIdx, length, isPassiveSession, actualDeviceId);
	}
      }
    }
    break;

  case IPPROTO_UDP:
    proto = "UDP";
    myGlobals.device[actualDeviceId].udpBytes += tcpUdpLen;

    if(tcpUdpLen < sizeof(struct udphdr)) {
      if(myGlobals.enableSuspiciousPacketDump) {
	traceEvent(TRACE_WARNING, "WARNING: Malformed UDP pkt %s->%s detected (packet too short)",
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

#ifdef SLACKWARE
      sport = ntohs(up.source);
      dport = ntohs(up.dest);
#else
      sport = ntohs(up.uh_sport);
      dport = ntohs(up.uh_dport);
#endif

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
	    traceEvent(TRACE_INFO, "%s:%d->%s:%d [request: %d][positive reply: %d]\n",
		       srcHost->hostSymIpAddress, sport,
		       dstHost->hostSymIpAddress, dport,
		       isRequest, positiveReply);
#endif

	    if(srcHost->dnsStats == NULL) {
	      srcHost->dnsStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	      memset(srcHost->dnsStats, 0, sizeof(ServiceStats));
	    }

	    if(dstHost->dnsStats == NULL) {
	      dstHost->dnsStats = (ServiceStats*)malloc(sizeof(ServiceStats));
	      memset(dstHost->dnsStats, 0, sizeof(ServiceStats));
	    }

	    if(isRequest) {
	      /* to be 64bit-proof we have to copy the elements */
	      tvstrct.tv_sec = h->ts.tv_sec;
	      tvstrct.tv_usec = h->ts.tv_usec;
	      addTimeMapping(transactionId, tvstrct);

	      if(subnetLocalHost(dstHost))
		srcHost->dnsStats->numLocalReqSent++;
	      else
		srcHost->dnsStats->numRemReqSent++;

	      if(subnetLocalHost(srcHost))
		dstHost->dnsStats->numLocalReqRcvd++;
	      else
		dstHost->dnsStats->numRemReqRcvd++;
	    } else {
	      time_t microSecTimeDiff;

	    /* to be 64bit-safe we have to copy the elements */
	      tvstrct.tv_sec = h->ts.tv_sec;
	      tvstrct.tv_usec = h->ts.tv_usec;
	      microSecTimeDiff = getTimeMapping(transactionId, tvstrct);

	      if(microSecTimeDiff > 0) {
#ifdef DEBUG
		traceEvent(TRACE_INFO, "TransactionId=0x%X [%.1f ms]\n",
			   transactionId, ((float)microSecTimeDiff)/1000);
#endif

		if(microSecTimeDiff > 0) {
		  if(subnetLocalHost(dstHost)) {
		    if((srcHost->dnsStats->fastestMicrosecLocalReqServed == 0)
		       || (microSecTimeDiff < srcHost->dnsStats->fastestMicrosecLocalReqServed))
		      srcHost->dnsStats->fastestMicrosecLocalReqServed = microSecTimeDiff;
		    if(microSecTimeDiff > srcHost->dnsStats->slowestMicrosecLocalReqServed)
		      srcHost->dnsStats->slowestMicrosecLocalReqServed = microSecTimeDiff;
		  } else {
		    if((srcHost->dnsStats->fastestMicrosecRemReqServed == 0)
		       || (microSecTimeDiff < srcHost->dnsStats->fastestMicrosecRemReqServed))
		      srcHost->dnsStats->fastestMicrosecRemReqServed = microSecTimeDiff;
		    if(microSecTimeDiff > srcHost->dnsStats->slowestMicrosecRemReqServed)
		      srcHost->dnsStats->slowestMicrosecRemReqServed = microSecTimeDiff;
		  }

		  if(subnetLocalHost(srcHost)) {
		    if((dstHost->dnsStats->fastestMicrosecLocalReqMade == 0)
		       || (microSecTimeDiff < dstHost->dnsStats->fastestMicrosecLocalReqMade))
		      dstHost->dnsStats->fastestMicrosecLocalReqMade = microSecTimeDiff;
		    if(microSecTimeDiff > dstHost->dnsStats->slowestMicrosecLocalReqMade)
		      dstHost->dnsStats->slowestMicrosecLocalReqMade = microSecTimeDiff;
		  } else {
		    if((dstHost->dnsStats->fastestMicrosecRemReqMade == 0)
		       || (microSecTimeDiff < dstHost->dnsStats->fastestMicrosecRemReqMade))
		      dstHost->dnsStats->fastestMicrosecRemReqMade = microSecTimeDiff;
		    if(microSecTimeDiff > dstHost->dnsStats->slowestMicrosecRemReqMade)
		      dstHost->dnsStats->slowestMicrosecRemReqMade = microSecTimeDiff;
		  }
		} else {
#ifdef DEBUG
		  traceEvent(TRACE_INFO, "getTimeMapping(0x%X) failed for DNS",
			     transactionId);
#endif
		}
	      }

	      /* Courtesy of Roberto F. De Luca <deluca@tandar.cnea.gov.ar> */
	      FD_SET(NAME_SERVER_HOST_FLAG, &srcHost->flags);

	      if(positiveReply) {
		srcHost->dnsStats->numPositiveReplSent++;
		dstHost->dnsStats->numPositiveReplRcvd++;
	      } else {
		srcHost->dnsStats->numNegativeReplSent++;
		dstHost->dnsStats->numNegativeReplRcvd++;
	      }
	    }
	  } else {
	    /* no packet decoding (let's speculate a bit) */
	    FD_SET(NAME_SERVER_HOST_FLAG, &srcHost->flags);
	  } 
	} else {
	  if(myGlobals.enablePacketDecoding) 
	    handleNetbios(srcHost, dstHost, sport, dport,
			  udpDataLength, bp,
			  length, hlen);
	}
      }

      if(myGlobals.udpChain) {
	u_int displ;

	if (off & 0x3fff)
	  displ = 0; /* Fragment */
	else
	  displ = sizeof(struct udphdr);

	checkFilterChain(srcHost, srcHostIdx,
			 dstHost, dstHostIdx,
			 sport, dport,
			 udpDataLength, /* packet length */
			 hlen,   /* offset from packet header */
			 0,	   /* there are no UDP flags :-( */
			 IPPROTO_UDP,
			 (u_char)(off & 0x3fff), /* 1 = fragment, 0 = packet */
			 bp, /* pointer to packet content */
			 myGlobals.udpChain, UDP_RULE, actualDeviceId);
      }

      /*
	Don't move this code on top as it is supposed to stay here
	as it modifies sport/sport 
	
	Courtesy of Andreas Pfaller
      */
      if(off & 0x3fff) {
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
	    srcHost->udpSentLoc += length;
	    dstHost->udpRcvdLoc += length;
	    myGlobals.device[actualDeviceId].udpGlobalTrafficStats.local += length;
	  } else {
	    srcHost->udpSentRem += length;
	    dstHost->udpRcvdLoc += length;
	    myGlobals.device[actualDeviceId].udpGlobalTrafficStats.local2remote += length;
	  }
	} else {
	  /* srcHost is remote */
	  if(subnetPseudoLocalHost(dstHost)) {
	    srcHost->udpSentLoc += length;
	    dstHost->udpRcvdFromRem += length;
	    myGlobals.device[actualDeviceId].udpGlobalTrafficStats.remote2local += length;
	  } else {
	    srcHost->udpSentRem += length;
	    dstHost->udpRcvdFromRem += length;
	    myGlobals.device[actualDeviceId].udpGlobalTrafficStats.remote += length;
	    nonFullyRemoteSession = 0;
	  }
	}
  
        /* Handle UDP traffic like TCP, above - 
	   That is: if we know about the lower# port, even if it's the destination,
	   classify the traffic that way.
	   (BMS 12-2001)
	*/
        if (dport < sport) {
	  if (handleIP(dport, srcHostIdx, dstHostIdx, length, 0, actualDeviceId) == -1)
	    handleIP(sport, srcHostIdx, dstHostIdx, length, 0, actualDeviceId);
        } else {
	  if (handleIP(sport, srcHostIdx, dstHostIdx, length, 0, actualDeviceId) == -1)
	    handleIP(dport, srcHostIdx, dstHostIdx, length, 0, actualDeviceId);
        }

	if(nonFullyRemoteSession)
	  handleUDPSession(h, (off & 0x3fff),
			   srcHostIdx, sport, dstHostIdx,
			   dport, udpDataLength,
			   (u_char*)(bp+hlen+sizeof(struct udphdr)), actualDeviceId);
	
	if(myGlobals.enableNetFlowSupport) sendUDPflow(srcHost, dstHost, sport, dport, length);	
      }
    }
    break;

  case IPPROTO_ICMP:
    myGlobals.device[actualDeviceId].icmpBytes += length;

    if(tcpUdpLen < sizeof(struct icmp)) {
      if(myGlobals.enableSuspiciousPacketDump) {
	traceEvent(TRACE_WARNING, "WARNING: Malformed ICMP pkt %s->%s detected (packet too short)",
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

      srcHost->icmpSent += length;
      dstHost->icmpRcvd += length;

      if(off & 0x3fff) {
	char *fmt = "WARNING: detected ICMP fragment [%s -> %s] (network attack attempt?)";

	srcHost->icmpFragmentsSent += length, dstHost->icmpFragmentsRcvd += length;
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->icmpFragmentSent, dstHostIdx, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->icmpFragmentRcvd, srcHostIdx, actualDeviceId);
	if(myGlobals.enableSuspiciousPacketDump) {
	  traceEvent(TRACE_WARNING, fmt,
		     srcHost->hostSymIpAddress, dstHost->hostSymIpAddress);
	  dumpSuspiciousPacket(actualDeviceId);
	}
      }

      /* ************************************************************* */

      if(icmpPkt.icmp_type <= ICMP_MAXTYPE) {
	short dumpPacket = 1;
	if(srcHost->icmpInfo == NULL) {
	  srcHost->icmpInfo = (IcmpHostInfo*)malloc(sizeof(IcmpHostInfo));
	  memset(srcHost->icmpInfo, 0, sizeof(IcmpHostInfo));
	}

	srcHost->icmpInfo->icmpMsgSent[icmpPkt.icmp_type]++;

	if(dstHost->icmpInfo == NULL) {
	  dstHost->icmpInfo = (IcmpHostInfo*)malloc(sizeof(IcmpHostInfo));
	  memset(dstHost->icmpInfo, 0, sizeof(IcmpHostInfo));
	}

	dstHost->icmpInfo->icmpMsgRcvd[icmpPkt.icmp_type]++;

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

	    traceEvent(TRACE_INFO, "Detected ICMP msg [type=%s/code=%d] %s->%s",
		       mapIcmpType(icmpPkt.icmp_type), icmpPkt.icmp_code,
		       srcHost->hostSymIpAddress, dstHost->hostSymIpAddress);
	  }
	}
      }

      /* ************************************************************* */

      if(subnetPseudoLocalHost(srcHost))
	if(subnetPseudoLocalHost(dstHost))
	  myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.local += length;
	else
	  myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.local2remote += length;
      else /* srcHost is remote */
	if(subnetPseudoLocalHost(dstHost))
	  myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.remote2local += length;
	else
	  myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.remote += length;

      if(myGlobals.icmpChain)
	checkFilterChain(srcHost, srcHostIdx,
			 dstHost, dstHostIdx,
			 0 /* sport */, 0 /* dport */,
			 length, /* packet length */
			 0,   /* offset from packet header */
			 icmpPkt.icmp_type,
			 IPPROTO_ICMP,
			 0, /* 1 = fragment, 0 = packet */
			 bp+hlen, /* pointer to packet content */
			 myGlobals.icmpChain, ICMP_RULE, actualDeviceId);

      if((icmpPkt.icmp_type == ICMP_ECHO)
	 && (broadcastHost(dstHost) || multicastHost(dstHost)))
	smurfAlert(srcHostIdx, dstHostIdx, actualDeviceId);
      else if(icmpPkt.icmp_type == ICMP_DEST_UNREACHABLE /* Destination Unreachable */) {
	u_int16_t dport;
	struct ip *oip = &icmpPkt.icmp_ip;

	switch(icmpPkt.icmp_code) {
	case ICMP_UNREACH_PORT: /* Port Unreachable */
	  memcpy(&dport, ((u_char *)bp+hlen+30), sizeof(dport));
	  dport = ntohs(dport);
	  switch (oip->ip_p) {
	  case IPPROTO_TCP:
	    if(myGlobals.enableSuspiciousPacketDump)
	      traceEvent(TRACE_WARNING,
			 "Host [%s] sent TCP data to a closed port of host [%s:%d] (scan attempt?)",
			 dstHost->hostSymIpAddress, srcHost->hostSymIpAddress, dport);
	    /* Simulation of rejected TCP connection */
	    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	    incrementUsageCounter(&srcHost->secHostPkts->rejectedTCPConnSent, dstHostIdx, actualDeviceId);
	    incrementUsageCounter(&dstHost->secHostPkts->rejectedTCPConnRcvd, srcHostIdx, actualDeviceId);
	    break;

	  case IPPROTO_UDP:
	    if(myGlobals.enableSuspiciousPacketDump)
	      traceEvent(TRACE_WARNING,
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
	    traceEvent(TRACE_WARNING, /* See http://www.packetfactory.net/firewalk/ */
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
	    traceEvent(TRACE_WARNING, /* See http://www.packetfactory.net/firewalk/ */
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
      sendICMPflow(srcHost, dstHost, length);
    }
    break;

  case IPPROTO_OSPF:
    proto = "OSPF";
    myGlobals.device[actualDeviceId].ospfBytes += length;
    srcHost->ospfSent += length;
    dstHost->ospfRcvd += length;
    break;

  case IPPROTO_IGMP:
    proto = "IGMP";
    myGlobals.device[actualDeviceId].igmpBytes += length;
    srcHost->igmpSent += length;
    dstHost->igmpRcvd += length;
    break;

  default:
    proto = "IP (Other)";
    myGlobals.device[actualDeviceId].otherIpBytes += length;
    sport = dport = 0;
    srcHost->otherSent += length;
    dstHost->otherRcvd += length;
    break;
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "IP=%d TCP=%d UDP=%d ICMP=%d (len=%d)\n",
	     (int)myGlobals.device[actualDeviceId].ipBytes,
	     (int)myGlobals.device[actualDeviceId].tcpBytes,
	     (int)myGlobals.device[actualDeviceId].udpBytes,
	     (int)myGlobals.device[actualDeviceId].icmpBytes, length);
#endif

  /* Unlock the instance */
  srcHost->instanceInUse--, dstHost->instanceInUse--;
}

/* ************************************ */

#ifdef MULTITHREADED
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

  if(!myGlobals.capturePackets) return;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Got packet from %s (%d)\n", myGlobals.device[*_deviceId].name, *_deviceId);
#endif

  if(myGlobals.packetQueueLen >= PACKET_QUEUE_LENGTH) {
    int deviceId;
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Dropping packet!!! [packet queue=%d/max=%d]\n",
		 myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif
    
#ifdef WIN32
    deviceId = 0;
#else
    deviceId = (int)_deviceId;
#endif
    
    myGlobals.device[getActualInterface(deviceId)].droppedPkts++;
    
#ifdef HAVE_SCHED_H
    sched_yield(); /* Allow other threads (dequeue) to run */
#endif
    sleep(1);
  } else {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "About to queue packet... \n");
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
    myGlobals.packetQueueHead = (myGlobals.packetQueueHead+1) % PACKET_QUEUE_LENGTH;
    myGlobals.packetQueueLen++;
    if(myGlobals.packetQueueLen > myGlobals.maxPacketQueueLen)
      myGlobals.maxPacketQueueLen = myGlobals.packetQueueLen;
    releaseMutex(&myGlobals.packetQueueMutex);
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Queued packet... [packet queue=%d/max=%d]\n",
	       myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

#ifdef DEBUG_THREADS
    traceEvent(TRACE_INFO, "+ [packet queue=%d/max=%d]\n", myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif
  }

#ifdef USE_SEMAPHORES
  incrementSem(&myGlobals.queueSem);
#else
  signalCondvar(&myGlobals.queueCondvar);
#endif
#ifdef HAVE_SCHED_H
  sched_yield(); /* Allow other threads (dequeue) to run */
#endif
}

/* ************************************ */

void cleanupPacketQueue(void) {
  ; /* Nothing to do */
}

/* ************************************ */

void* dequeuePacket(void* notUsed _UNUSED_) {
  PacketInformation pktInfo;

  while(myGlobals.capturePackets) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Waiting for packet...\n");
#endif
    
    while((myGlobals.packetQueueLen == 0)
	  && (myGlobals.capturePackets) /* Courtesy of Wies-Software <wies@wiessoft.de> */) {
#ifdef USE_SEMAPHORES
      waitSem(&myGlobals.queueSem);
#else
      waitCondvar(&myGlobals.queueCondvar);
#endif
    }
    
    if(!myGlobals.capturePackets) break;

#ifdef DEBUG
    traceEvent(TRACE_INFO, "Got packet...\n");
#endif
    accessMutex(&myGlobals.packetQueueMutex, "dequeuePacket");
    memcpy(&pktInfo.h, &myGlobals.packetQueue[myGlobals.packetQueueTail].h,
	   sizeof(struct pcap_pkthdr));
    memcpy(pktInfo.p, myGlobals.packetQueue[myGlobals.packetQueueTail].p, DEFAULT_SNAPLEN);
    pktInfo.deviceId = myGlobals.packetQueue[myGlobals.packetQueueTail].deviceId;
    myGlobals.packetQueueTail = (myGlobals.packetQueueTail+1) % PACKET_QUEUE_LENGTH;
    myGlobals.packetQueueLen--;
    releaseMutex(&myGlobals.packetQueueMutex);
#ifdef DEBUG_THREADS
    traceEvent(TRACE_INFO, "- [packet queue=%d/max=%d]\n", myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

#ifdef DEBUG
    traceEvent(TRACE_INFO, "Processing packet... [packet queue=%d/max=%d]\n",
	       myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

    myGlobals.actTime = time(NULL);
    processPacket((u_char*)((long)pktInfo.deviceId), &pktInfo.h, pktInfo.p);
  }

  return(NULL); /* NOTREACHED */
}

#endif /* MULTITHREADED */


/* ************************************ */

static void flowsProcess(const struct pcap_pkthdr *h, const u_char *p, int deviceId) {
  FlowFilterList *list = myGlobals.flowsList;

  while(list != NULL) {
    if((list->pluginStatus.activePlugin)
       && (list->fcode[deviceId].bf_insns != NULL)
       && (bpf_filter(list->fcode[deviceId].bf_insns,
		      (u_char*)p, h->len, h->caplen))) {
      list->bytes += h->len;
      list->packets++;
      if(list->pluginStatus.pluginPtr != NULL) {
	void(*pluginFunc)(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p);

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
      traceEvent(TRACE_INFO, "No match on %s for '%s'\n", myGlobals.device[deviceId].name,
		 list->flowName);
#endif
    }

    list = list->next;
  }
}

/* ************************************ */

/*
 * time stamp presentation formats
 */
#define DELTA_FMT      1   /* the time since receiving the previous packet */
#define ABS_FMT        2   /* the current time */
#define RELATIVE_FMT   3   /* the time relative to the first packet rcvd */


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
    case DELTA_FMT:
      /*
       * calculate the difference in milliseconds since
       * the previous packet was displayed
       */
      if(snprintf(buf, 16, "%10ld ms",
		  delta_time_in_milliseconds(&current_pkt, &last_pkt)) < 0)
	BufferOverflow();
      break;

    case ABS_FMT:
      if(snprintf(buf, 16, "%02d:%02d:%02d.%06d",
		  tm->tm_hour, tm->tm_min, tm->tm_sec, (int)t->tv_usec) < 0)
	BufferOverflow();
      break;

    case RELATIVE_FMT:
      /*
       * calculate the difference in milliseconds
       * since the previous packet was displayed
       */
      if(snprintf(buf, 16, "%10ld ms",
		  delta_time_in_milliseconds(&current_pkt, &first_pkt)) < 0)
	BufferOverflow();
      break;
    }

  return (buf);
}
#endif

/* ************************************ */

static void updateDevicePacketStats(u_int length, int actualDeviceId) {
  if(length < 64) myGlobals.device[actualDeviceId].rcvdPktStats.upTo64++;
  else if(length < 128) myGlobals.device[actualDeviceId].rcvdPktStats.upTo128++;
  else if(length < 256) myGlobals.device[actualDeviceId].rcvdPktStats.upTo256++;
  else if(length < 512) myGlobals.device[actualDeviceId].rcvdPktStats.upTo512++;
  else if(length < 1024) myGlobals.device[actualDeviceId].rcvdPktStats.upTo1024++;
  else if(length < 1518) myGlobals.device[actualDeviceId].rcvdPktStats.upTo1518++;
  else myGlobals.device[actualDeviceId].rcvdPktStats.above1518++;

  if((myGlobals.device[actualDeviceId].rcvdPktStats.shortest == 0)
     || (myGlobals.device[actualDeviceId].rcvdPktStats.shortest > length))
    myGlobals.device[actualDeviceId].rcvdPktStats.shortest = length;

  if(myGlobals.device[actualDeviceId].rcvdPktStats.longest < length)
    myGlobals.device[actualDeviceId].rcvdPktStats.longest = length;
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
  int deviceId, actualDeviceId;

#ifdef DEBUG
  {
      static long numPkt=0;

      traceEvent(TRACE_INFO, "%ld (%ld)\n", numPkt++, length);

      /* 
      if(numPkt=100000) {
	int i;

	for(i=0; i<myGlobals.numDevices; i++)
	  freeHostInstances(i);
      }
      */
  }
#endif

  if(!myGlobals.capturePackets)
    return;

  h_save = h, p_save = p;

#ifdef DEBUG
  if(myGlobals.rFileName != NULL) {
    traceEvent(TRACE_INFO, ".");
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
  traceEvent(TRACE_INFO, "deviceId=%d - actualDeviceId=%ld\n", deviceId, actualDeviceId);
#endif

  updateDevicePacketStats(length, actualDeviceId);

  myGlobals.device[actualDeviceId].ethernetPkts++;
  myGlobals.device[actualDeviceId].ethernetBytes += h->len;

  if(myGlobals.device[actualDeviceId].pcapDumper != NULL)
    pcap_dump((u_char*)myGlobals.device[actualDeviceId].pcapDumper, h, p);

  if(length > myGlobals.mtuSize[myGlobals.device[deviceId].datalink]) {
    /* Sanity check */
    if(myGlobals.enableSuspiciousPacketDump) {
      traceEvent(TRACE_INFO, "Packet # %u too long (len = %u)!\n", 
		 (unsigned int)myGlobals.device[deviceId].ethernetPkts, 
		 (unsigned int)length);
      dumpSuspiciousPacket(actualDeviceId);
    }

    /* Fix below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
    length = myGlobals.mtuSize[myGlobals.device[deviceId].datalink];
    myGlobals.device[actualDeviceId].rcvdPktStats.tooLong++;
  }

#ifdef MULTITHREADED
  accessMutex(&myGlobals.hostsHashMutex, "processPacket");
#endif

#ifdef DEBUG
  traceEvent(TRACE_INFO, "actualDeviceId = %d\n", actualDeviceId);
#endif

  hlen = (myGlobals.device[deviceId].datalink == DLT_NULL) ? NULL_HDRLEN : sizeof(struct ether_header);

#ifndef MULTITHREADED
  /*
   * Let's check whether it's time to free up
   * some space before to continue....
   */
  if(myGlobals.device[actualDeviceId].hostsno > myGlobals.device[actualDeviceId].topHashThreshold)
    purgeIdleHosts(0 /* Delete only idle hosts */, actualDeviceId);
#endif

  memcpy(&myGlobals.lastPktTime, &h->ts, sizeof(myGlobals.lastPktTime));

  fd = myGlobals.device[deviceId].fdv;

  /*
   * Show a hash character for each packet captured
   */
  if (fd && myGlobals.device[deviceId].hashing) {
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

      if((fddip->fc & FDDIFC_CLFF) == FDDIFC_LLC_ASYNC) {
	struct llc llc;

	/*
	  Info on SNAP/LLC:
	  http://www.erg.abdn.ac.uk/users/gorry/course/lan-pages/llc.html
	  http://www.ece.wpi.edu/courses/ee535/hwk96/hwk3cd96/li/li.html
	  http://www.ece.wpi.edu/courses/ee535/hwk96/hwk3cd96/li/li.html
	*/
	memcpy((char *)&llc, (char *)p, min(caplen, sizeof(llc)));
	if(llc.ssap == LLCSAP_SNAP && llc.dsap == LLCSAP_SNAP
	    && llc.llcui == LLC_UI) {
	  if(caplen >= sizeof(llc)) {
	    caplen -= sizeof(llc);
	    length -= sizeof(llc);
	    p += sizeof(llc);

	    if(EXTRACT_16BITS(&llc.ethertype[0]) == ETHERTYPE_IP) {
	      /* encapsulated IP packet */
	      processIpPkt(p, h, length, ether_src, ether_dst, actualDeviceId);
	      /*
		Patch below courtesy of
		Fabrice Bellet <Fabrice.Bellet@creatis.insa-lyon.fr>
	      */
#ifdef MULTITHREADED
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

      length -= NULL_HDRLEN; /* don't count nullhdr */

      /* All this crap is due to the old little/big endian story... */
      if((p[0] == 0) && (p[1] == 0) && (p[2] == 8) && (p[3] == 0))
	eth_type = ETHERTYPE_IP;
      else if((p[0] == 0) && (p[1] == 0) && (p[2] == 0x86) && (p[3] == 0xdd))
	eth_type = ETHERTYPE_IPv6;
      ether_src = ether_dst = myGlobals.dummyEthAddress;
      break;

    case DLT_PPP:
      headerDisplacement = PPP_HDRLEN;
      /*
	PPP is like RAW IP. The only difference is that PPP
	has a header that's not present in RAW IP.

	IMPORTANT: DO NOT PUT A break BELOW this comment
      */

    case DLT_RAW: /* RAW IP (no ethernet header) */
      length -= headerDisplacement; /* don't count PPP header */
      ether_src = ether_dst = NULL;
      processIpPkt(p+headerDisplacement, h, length, NULL, NULL, actualDeviceId);
      break;

    case DLT_IEEE802: /* Token Ring */
      trp = (struct tokenRing_header*)p;
      ether_src = (u_char*)trp->trn_shost, ether_dst = (u_char*)trp->trn_dhost;

      hlen = sizeof(struct tokenRing_header) - 18;

      if(trp->trn_shost[0] & TR_RII) /* Source Routed Packet */
	hlen += ((ntohs(trp->trn_rcf) & TR_RCF_LEN_MASK) >> 8);

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
    } /* switch(myGlobals.device[deviceId].datalink) */

#if PACKET_DEBUG
    /*
     * Time to show the Ethernet Packet Header (when enabled).
     */
    if(fd && myGlobals.device [deviceId].ethv)
      fprintf (fd, "ETHER:  ----- Ether Header -----\n"),
	fprintf (fd, "ETHER:\n"),
	fprintf (fd, "ETHER:  Packet %ld arrived at %s\n",
		 myGlobals.device [actualDeviceId].ethernetPkts, timestamp (& h->ts, ABS_FMT)),
	fprintf (fd, "ETHER:  Total size  = %d : header = %d : data = %d\n",
		 length, hlen, length - hlen),
	fprintf (fd, "ETHER:  Source      = %s\n", etheraddr_string (ether_src)),
	fprintf (fd, "ETHER:  Destination = %s\n", etheraddr_string (ether_dst));
    fflush (fd);
#endif

    if((myGlobals.device[deviceId].datalink != DLT_PPP) 
       && (myGlobals.device[deviceId].datalink != DLT_RAW)) {
      if((!myGlobals.borderSnifferMode) && (eth_type == 0x8137)) {
	/* IPX */
	IPXpacket ipxPkt;

	srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	if(srcHost == NULL) {
	  /* Sanity check */
	  traceEvent(TRACE_INFO, "Sanity check failed (5) [Low memory?]");
	} else {
	  /* Lock the instance so that the next call
	     to getHostInfo won't purge it */
	  srcHost->instanceInUse++;
	}

	dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
	dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	if(dstHost == NULL) {
	  /* Sanity check */
	  traceEvent(TRACE_INFO, "Sanity check failed (6) [Low memory?]");
	} else {
	  /* Lock the instance so that the next call
	     to getHostInfo won't purge it */
	  dstHost->instanceInUse++;
	}
	memcpy((char *)&ipxPkt, (char *)p+sizeof(struct ether_header), sizeof(IPXpacket));

	if(ntohs(ipxPkt.dstSocket) == 0x0452) {
	  /* SAP */
	  int displ = sizeof(struct ether_header);
	  p1 = p+displ;
	  length -= displ;
	  goto handleIPX;
	} else {
	  srcHost->ipxSent += length, dstHost->ipxRcvd += length;
	  myGlobals.device[actualDeviceId].ipxBytes += length;
	  updatePacketCount(srcHostIdx, dstHostIdx, (TrafficCounter)length, actualDeviceId);
	}
      } else if((myGlobals.device[deviceId].datalink == DLT_IEEE802) && (eth_type < ETHERMTU)) {
	trp = (struct tokenRing_header*)orig_p;
	ether_src = (u_char*)trp->trn_shost, ether_dst = (u_char*)trp->trn_dhost;
	srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	if(srcHost == NULL) {
	  /* Sanity check */
	  traceEvent(TRACE_INFO, "Sanity check failed (7) [Low memory?]");
	} else {
	  /* Lock the instance so that the next call
	     to getHostInfo won't purge it */
	  srcHost->instanceInUse++;
	}

	dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
	dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	if(dstHost == NULL) {
	  /* Sanity check */
	  traceEvent(TRACE_INFO, "Sanity check failed (8) [Low memory?]");
	} else {
	  /* Lock the instance so that the next call
	     to getHostInfo won't purge it */
	  dstHost->instanceInUse++;
	}

	srcHost->otherSent += length;
	dstHost->otherRcvd += length;
	updatePacketCount(srcHostIdx, dstHostIdx, (TrafficCounter)length, actualDeviceId);
      } else if((myGlobals.device[deviceId].datalink != DLT_IEEE802)
		&& (eth_type <= ETHERMTU) && (length > 3)) {
	/* The code below has been taken from tcpdump */
	u_char sap_type;
	struct llc llcHeader;

	if((ether_dst != NULL)
	   && (!myGlobals.borderSnifferMode)
	   && (strcmp(etheraddr_string(ether_dst), "FF:FF:FF:FF:FF:FF") == 0)
	   && (p[sizeof(struct ether_header)] == 0xff)
	   && (p[sizeof(struct ether_header)+1] == 0xff)
	   && (p[sizeof(struct ether_header)+4] == 0x0)) {
	  /* IPX */

	  srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	  if(srcHost == NULL) {
	    /* Sanity check */
	    traceEvent(TRACE_INFO, "Sanity check failed (9) [Low memory?]");
	  } else {
	    /* Lock the instance so that the next call
	       to getHostInfo won't purge it */
	    srcHost->instanceInUse++;
	  }

	  dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
	  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	  if(dstHost == NULL) {
	    /* Sanity check */
	    traceEvent(TRACE_INFO, "Sanity check failed (10) [Low memory?]");
	  } else {
	    /* Lock the instance so that the next call
	       to getHostInfo won't purge it */
	    dstHost->instanceInUse++;
	  }

	  srcHost->ipxSent += length, dstHost->ipxRcvd += length;
	  myGlobals.device[actualDeviceId].ipxBytes += length;
	} else if(!myGlobals.borderSnifferMode) {
	    /* MAC addresses are meaningful here */
	  srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	  dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);

	  if((srcHostIdx != NO_PEER) && (dstHostIdx != NO_PEER)) {
	  srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	  dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];

	  if((srcHost == NULL) || (dstHost == NULL)) {
	    traceEvent(TRACE_INFO, "Sanity check failed (13) [Low memory?]");
	    return;
	  }
	  
	  p1 = (u_char*)(p+hlen);

	  /* Watch out for possible alignment problems */
	  memcpy(&llcHeader, (char*)p1, min(length, sizeof(llcHeader)));

	  sap_type = llcHeader.ssap & ~LLC_GSAP;
	  llcsap_string(sap_type);

	  if(sap_type == 0x42) {
	    /* Spanning Tree */
	    srcHost->stpSent += length, dstHost->stpRcvd += length;
	    myGlobals.device[actualDeviceId].stpBytes += length;
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
	      char serverName[56];
	      int i, found;

	      memcpy(&serverType, &ipxBuffer[32], 2);

	      serverType = ntohs(serverType);

	      memcpy(serverName, &ipxBuffer[34], 56); serverName[56] = '\0';
	      for(i=0; i<56; i++)
		if(serverName[i] == '!') {
		  serverName[i] = '\0';
		  break;
		}

	      for(i=0, found=0; i<srcHost->numIpxNodeTypes; i++)
		if(srcHost->ipxNodeType[i] == serverType) {
		  found = 1;
		  break;
		}

	      if((!found) && (srcHost->numIpxNodeTypes < MAX_NODE_TYPES)) {
		srcHost->ipxNodeType[srcHost->numIpxNodeTypes] = serverType;
		srcHost->numIpxNodeTypes++;

		switch(serverType) {
		case 0x0007: /* Print server */
		case 0x0003: /* Print Queue */
		case 0x8002: /* Intel NetPort Print Server */
		case 0x030c: /* HP LaserJet / Quick Silver */
		  FD_SET(HOST_TYPE_PRINTER, &srcHost->flags);
		  break;

		case 0x0027: /* TCP/IP gateway */
		case 0x0021: /* NAS SNA gateway */
		case 0x055d: /* Attachmate SNA gateway */
		  FD_SET(GATEWAY_HOST_FLAG, &srcHost->flags);
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
		  FD_SET(HOST_TYPE_SERVER, &srcHost->flags);
		  break;

		case 0x0278: /* NetWare Directory server */
		  FD_SET(HOST_SVC_DIRECTORY, &srcHost->flags);
		  break;

		case 0x0024: /* Rem bridge */
		case 0x0026: /* Bridge server */
		  FD_SET(HOST_SVC_BRIDGE, &srcHost->flags);
		  break;

		case 0x0640: /* NT Server-RPC/GW for NW/Win95 User Level Sec */
		case 0x064e: /* NT Server-IIS */
		  FD_SET(HOST_TYPE_SERVER, &srcHost->flags);
		  break;

		case 0x0133: /* NetWare Name Service */
		  FD_SET(NAME_SERVER_HOST_FLAG, &srcHost->flags);
		  break;
		}
	      }

	      if(srcHost->ipxHostName == NULL) {
		int i;

		for(i=1; i<strlen(serverName); i++)
		  if((serverName[i] == '_') && (serverName[i-1] == '_')) {
		    serverName[i-1] = '\0'; /* Avoid weird names */
		    break;
		  }

		if(strlen(serverName) >= (MAX_HOST_SYM_NAME_LEN-1)) 
		  serverName[MAX_HOST_SYM_NAME_LEN-2] = '\0';
		srcHost->ipxHostName = strdup(serverName);
		for(i=0; srcHost->ipxHostName[i] != '\0'; i++)
		  srcHost->ipxHostName[i] = tolower(srcHost->ipxHostName[i]);

		updateHostName(srcHost);
	      }
#ifdef DEBUG
	      traceEvent(TRACE_INFO, "%s [%s][%x]\n", serverName,
			 getSAPInfo(serverType, 0), serverType);
#endif
	    }

	    srcHost->ipxSent += length, dstHost->ipxRcvd += length;
	    myGlobals.device[actualDeviceId].ipxBytes += length;
	  } else if((llcHeader.ssap == LLCSAP_NETBIOS)
		    && (llcHeader.dsap == LLCSAP_NETBIOS)) {
	    /* Netbios */
	    srcHost->netbiosSent += length;
	    dstHost->netbiosRcvd += length;
	    myGlobals.device[actualDeviceId].netbiosBytes += length;
	  } else if((sap_type == 0xF0) 
		    || (sap_type == 0xB4)
		    || (sap_type == 0xC4)
		    || (sap_type == 0xF8)) {
	    /* DLC (protocol used for printers) */
	    srcHost->dlcSent += length;
	    dstHost->dlcRcvd += length; 
	    FD_SET(HOST_TYPE_PRINTER, &dstHost->flags);
	    myGlobals.device[actualDeviceId].dlcBytes += length;
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

	      srcHost->atNetwork = ntohs(ddpHeader.srcNet), srcHost->atNode = ddpHeader.srcNode;
	      dstHost->atNetwork = ntohs(ddpHeader.dstNet), dstHost->atNode = ddpHeader.dstNode;

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

		  if(strlen(nodeName) >= (MAX_HOST_SYM_NAME_LEN-1)) 
		    nodeName[MAX_HOST_SYM_NAME_LEN-2] = '\0';
		  srcHost->atNodeName = strdup(nodeName);
		  updateHostName(srcHost);

		  memcpy(nodeName, &p1[7+p1[5+displ]+displ], p1[6+p1[5+displ]+displ]);
		  nodeName[p1[6+p1[5+displ]]] = '\0';

		  for(i=0; i<MAX_NODE_TYPES; i++)
		    if((srcHost->atNodeType[i] == NULL)
		       || (strcmp(srcHost->atNodeType[i], nodeName) == 0))
		      break;

		  if(srcHost->atNodeType[i] == NULL)
		    srcHost->atNodeType[i] = strdup(nodeName);
		}
	      }

	      srcHost->appletalkSent += length;
	      dstHost->appletalkRcvd += length;
	      myGlobals.device[actualDeviceId].atalkBytes += length;
	    } else {
	      if((llcHeader.ctl.snap_ether.snap_orgcode[0] == 0x0)
		 && (llcHeader.ctl.snap_ether.snap_orgcode[1] == 0x0)
		 && (llcHeader.ctl.snap_ether.snap_orgcode[2] == 0x0C) /* Cisco */) {
		/* NOTE:
		   If llcHeader.ctl.snap_ether.snap_ethertype[0] == 0x20
		   && llcHeader.ctl.snap_ether.snap_ethertype[1] == 0x0
		   this is Cisco Discovery Protocol
		*/

		FD_SET(GATEWAY_HOST_FLAG, &srcHost->flags);
	      }

	      srcHost->otherSent += length;
	      dstHost->otherRcvd += length;
	      myGlobals.device[actualDeviceId].otherBytes += length;
	    }
	  } else if(myGlobals.enablePacketDecoding
		    && ((sap_type == 0x06)
			|| (sap_type == 0xFE)
			|| (sap_type == 0xFC))) {  /* OSI */
	    srcHost->osiSent += length;
	    dstHost->osiRcvd += length;
	    myGlobals.device[actualDeviceId].osiBytes += length;
	  } else {
	    /* Unknown Protocol */
#ifdef PRINT_UNKNOWN_PACKETS
	    traceEvent(TRACE_INFO, "[%u] [%x] %s %s > %s\n", (u_short)sap_type,(u_short)sap_type,
		       etheraddr_string(ether_src),
		       llcsap_string(llcHeader.ssap & ~LLC_GSAP),
		       etheraddr_string(ether_dst));
#endif
	    srcHost->otherSent += length;
	    dstHost->otherRcvd += length;
	    myGlobals.device[actualDeviceId].otherBytes += length;
	  }
	  updatePacketCount(srcHostIdx, dstHostIdx, (TrafficCounter)length, actualDeviceId);
	  }
	}
      } else if(eth_type == ETHERTYPE_IP) {
	if((myGlobals.device[deviceId].datalink == DLT_IEEE802) && (eth_type > ETHERMTU))
	  processIpPkt(p, h, length, ether_src, ether_dst, actualDeviceId);
	else
	  processIpPkt(p+hlen, h, length, ether_src, ether_dst, actualDeviceId);
      } else  /* Non IP */ if(!myGlobals.borderSnifferMode) {
	    /* MAC addresses are meaningful here */
	struct ether_arp arpHdr;
	struct in_addr addr;

	if(eth_type == ETHERTYPE_IPv6) {
	  static int firstTimeIpv6=1;

	  if(firstTimeIpv6) {
	    traceEvent(TRACE_WARNING, "IPv6 is unsupported: assuming raw."); /* To Do */
	    firstTimeIpv6 = 0;
	  }
	}

	if(length > hlen)
	  length -= hlen;
	else
	  length = 0;

	srcHostIdx = getHostInfo(NULL, ether_src, 0, 0, actualDeviceId);
	srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	if(srcHost == NULL) {
	  /* Sanity check */
	  traceEvent(TRACE_INFO, "Sanity check failed (11) [Low memory?]");
	} else {
	  /* Lock the instance so that the next call
	     to getHostInfo won't purge it */
	  srcHost->instanceInUse++;
	}

	dstHostIdx = getHostInfo(NULL, ether_dst, 0, 0, actualDeviceId);
	dstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(dstHostIdx)];
	if(dstHost == NULL) {
	  /* Sanity check */
	  traceEvent(TRACE_INFO, "Sanity check failed (12) [Low memory?]");
	} else {
	  /* Lock the instance so that the next call
	     to getHostInfo won't purge it */
	  dstHost->instanceInUse++;
	}

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
	      if(srcHost != NULL) srcHost->arpReplyPktsSent++;
	      if(dstHost != NULL) dstHost->arpReplyPktsRcvd++;
	      /* DO NOT ADD A break ABOVE ! */
	    case ARPOP_REQUEST: /* ARP request */
	      memcpy(&addr.s_addr, arpHdr.arp_spa, sizeof(addr.s_addr));
	      addr.s_addr = ntohl(addr.s_addr);
	      srcHostIdx = getHostInfo(&addr, (u_char*)&arpHdr.arp_sha, 0, 0, actualDeviceId);
	      srcHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(srcHostIdx)];
	      if((arpOp == ARPOP_REQUEST) && (srcHost != NULL)) srcHost->arpReqPktsSent++;
	    }
	  }
	  /* DO NOT ADD A break ABOVE ! */
	case ETHERTYPE_REVARP: /* Reverse ARP */
	  if(srcHost != NULL) srcHost->arp_rarpSent += length;
	  if(dstHost != NULL) dstHost->arp_rarpRcvd += length;
	  myGlobals.device[actualDeviceId].arpRarpBytes += length;
	  break;
	case ETHERTYPE_DN: /* Decnet */
	  srcHost->decnetSent += length;
	  dstHost->decnetRcvd += length;
	  myGlobals.device[actualDeviceId].decnetBytes += length;
	  break;
	case ETHERTYPE_ATALK: /* AppleTalk */
	case ETHERTYPE_AARP:
	  srcHost->appletalkSent += length;
	  dstHost->appletalkRcvd += length;
	  myGlobals.device[actualDeviceId].atalkBytes += length;
	  break;
	case ETHERTYPE_QNX:
	  srcHost->qnxSent += length;
	  dstHost->qnxRcvd += length;
	  myGlobals.device[actualDeviceId].qnxBytes += length;
	  break;
	default:
#ifdef PRINT_UNKNOWN_PACKETS
	  traceEvent(TRACE_INFO, "%s/%s->%s/%s [eth type %d (0x%x)]\n",
		     srcHost->hostNumIpAddress, srcHost->ethAddressString,
		     dstHost->hostNumIpAddress, dstHost->ethAddressString,
		     eth_type, eth_type);
#endif
	  srcHost->otherSent += length;
	  dstHost->otherRcvd += length;
	  myGlobals.device[actualDeviceId].otherBytes += length;
	  break;
	}

	updatePacketCount(srcHostIdx, dstHostIdx, (TrafficCounter)length, actualDeviceId);
      }
    }

    /* Unlock the instances */
    if(srcHost != NULL) srcHost->instanceInUse--;
    if(dstHost != NULL) dstHost->instanceInUse--;
  }

  if(myGlobals.flowsList != NULL) /* Handle flows last */
    flowsProcess(h, p, deviceId);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.hostsHashMutex);
#endif
}

/* ************************************ */

#ifdef HASH_DEBUG
/* Debug only */
static void dumpHash() {
  int i;
  
  for(i=1; i<myGlobals.device[0].actualHashSize; i++) {
    HostTraffic *el = myGlobals.device[0].hash_hostTraffic[i];
  
    if(el != NULL) {
      traceEvent(TRACE_INFO, "(%3d) %s / %s", 
		 i,
		 el->ethAddressString,
		 el->hostNumIpAddress);
    }
  }
}
#endif /* DEBUG */
