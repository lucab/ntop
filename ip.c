/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *                          http://www.ntop.org
 *
 *          Copyright (C) 1998-2011 Luca Deri <deri@ntop.org>
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

/* ***************************************** */

static u_char ethBroadcast[] = { 255, 255, 255, 255, 255, 255 };

/* ***************************************** */

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
         fragment->src->hostResolvedName, fragment->sport,
         fragment->dest->hostResolvedName, fragment->dport);
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

  if(fragment->prev == NULL)
    myGlobals.device[actualDeviceId].fragmentList = fragment->next;
  else
    fragment->prev->next = fragment->next;

  free(fragment);
}

/* ************************************ */

/* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
static void checkFragmentOverlap(HostTraffic *srcHost,
                                 HostTraffic *dstHost,
                                 IpFragment *fragment,
                                 u_int fragmentOffset,
                                 u_int dataLength,
				 int actualDeviceId,
				 const struct pcap_pkthdr *h, const u_char *p) {
  if(fragment->fragmentOrder == FLAG_UNKNOWN_FRAGMENT_ORDER) {
    if(fragment->lastOffset > fragmentOffset)
      fragment->fragmentOrder = FLAG_DECREASING_FRAGMENT_ORDER;
    else
      fragment->fragmentOrder = FLAG_INCREASING_FRAGMENT_ORDER;
  }

  if((fragment->fragmentOrder == FLAG_INCREASING_FRAGMENT_ORDER
      && fragment->lastOffset+fragment->lastDataLength > fragmentOffset)
     ||
     (fragment->fragmentOrder == FLAG_DECREASING_FRAGMENT_ORDER
      && fragment->lastOffset < fragmentOffset+dataLength)) {
    if(myGlobals.runningPref.enableSuspiciousPacketDump) {
      char buf[LEN_GENERAL_WORK_BUFFER];
      safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER,
		    "Detected overlapping packet fragment [%s->%s]: "
		    "fragment id=%d, actual offset=%d, previous offset=%d\n",
		    fragment->src->hostResolvedName,
		    fragment->dest->hostResolvedName,
		    fragment->fragmentId, fragmentOffset,
		    fragment->lastOffset);

      dumpSuspiciousPacket(actualDeviceId, h, p);
    }

    allocateSecurityHostPkts(fragment->src); allocateSecurityHostPkts(fragment->dest);
    incrementUsageCounter(&fragment->src->secHostPkts->overlappingFragmentSent,
			  dstHost, actualDeviceId);
    incrementUsageCounter(&fragment->dest->secHostPkts->overlappingFragmentRcvd,
			  srcHost, actualDeviceId);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.overlappingFragment, 1);
  }
}

/* ************************************ */

static u_int handleFragment(HostTraffic *srcHost,
                            HostTraffic *dstHost,
                            u_short *sport,
                            u_short *dport,
                            u_int fragmentId,
                            u_int off,
                            u_int packetLength,
                            u_int dataLength,
			    int actualDeviceId,
			    const struct pcap_pkthdr *h, const u_char *p) {
  IpFragment *fragment;
  u_int fragmentOffset, length;

  if(!myGlobals.enableFragmentHandling)
    return(0);

  fragmentOffset = (off & 0x1FFF)*8;

  fragment = searchFragment(srcHost, dstHost, fragmentId, actualDeviceId);

  if(fragment == NULL) {
    /* new fragment */
    fragment = (IpFragment*) malloc(sizeof(IpFragment));
    if(fragment == NULL) return(0); /* out of memory, not much we can do */
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
    checkFragmentOverlap(srcHost, dstHost, fragment,
			 fragmentOffset, dataLength, actualDeviceId,
			 h, p);

  fragment->lastOffset = fragmentOffset;
  fragment->totalPacketLength += packetLength;
  fragment->totalDataLength += dataLength;
  fragment->lastDataLength = dataLength;

  if(fragmentOffset == 0) {
    /* first fragment contains port numbers */
    fragment->sport = *sport;
    fragment->dport = *dport;
  } else if(!(off & IP_MF)) /* last fragment->we know the total data size */
    fragment->expectedDataLength = fragmentOffset+dataLength;

#ifdef FRAGMENT_DEBUG
  dumpFragmentData(fragment);
#endif

  /* Now check if we have all the data needed for the statistics */
  if((fragment->sport != 0) && (fragment->dport != 0) /* first fragment rcvd */
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

  if( c == 1 )
    return x;
  else
    return ( j ? j : 0xff );
}

/* ************************************ */

static void updateRoutedTraffic(HostTraffic *router, Counter bytes) {
  if(router != NULL) {
    if(router->routedTraffic == NULL) {
      int mallocLen = sizeof(RoutingCounter);

      router->routedTraffic = (RoutingCounter*)malloc(mallocLen);
      if(router->routedTraffic == NULL) return;
      memset(router->routedTraffic, 0, mallocLen);
    }

    if(router->routedTraffic != NULL) { /* malloc() didn't fail */
      incrementTrafficCounter(&router->routedTraffic->routedPkts, 1);
      incrementTrafficCounter(&router->routedTraffic->routedBytes, bytes);      
    }
  }
}

/* ************************************ */

static void updateDevicePacketTTLStats(u_int ttl, int actualDeviceId) {
  if(ttl <= 32)       incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo32, 1);
  else if(ttl <= 64)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo64, 1);
  else if(ttl <= 96)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo96, 1);
  else if(ttl <= 128) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo128, 1);
  else if(ttl <= 160) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo160, 1);
  else if(ttl <= 192) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo192, 1);
  else if(ttl <= 224) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo224, 1);
  else                incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo255, 1);
}

/* ************************************ */

static void checkNetworkRouter(HostTraffic *srcHost, HostTraffic *dstHost,
			       u_char *ether_dst, int actualDeviceId,
			       Counter bytes,
			       const struct pcap_pkthdr *h, const u_char *p) {
  if((subnetLocalHost(srcHost) && (!subnetLocalHost(dstHost))
      && (!broadcastHost(dstHost)) && (!multicastHost(dstHost)))
     || (subnetLocalHost(dstHost) && (!subnetLocalHost(srcHost))
	 && (!broadcastHost(srcHost)) && (!multicastHost(srcHost)))) {
    HostTraffic *router = lookupHost(NULL, ether_dst, srcHost->vlanId, 0, 0, actualDeviceId, h, p);

    if(router == NULL) return;

    if(((router->hostNumIpAddress[0] != '\0')
	&& (broadcastHost(router)
	    || multicastHost(router)
	    || (!subnetLocalHost(router)) /* No IP: is this a special Multicast address ? */))
       || (addrcmp(&router->hostIpAddress,&dstHost->hostIpAddress) == 0)
       || (memcmp(router->ethAddress, dstHost->ethAddress, LEN_ETHERNET_ADDRESS) == 0)
       )
      return;

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "(%s/%s/%s) -> (%s/%s/%s) routed by [%s/%s/%s]",
	       srcHost->ethAddressString, srcHost->hostNumIpAddress, srcHost->hostResolvedName,
	       dstHost->ethAddressString, dstHost->hostNumIpAddress, dstHost->hostResolvedName,
	       router->ethAddressString,
	       router->hostNumIpAddress,
	       router->hostResolvedName);

#endif

    setHostFlag(FLAG_GATEWAY_HOST, router);
    updateRoutedTraffic(router, bytes);
  }
}

/* ************************************ */

void processIpPkt(const u_char *bp, /* Pointer to IP */
		  const struct pcap_pkthdr *h,
		  const u_char *p, /* Original packet */
		  u_int ip_offset, u_int length,
		  u_char *ether_src,
		  u_char *ether_dst,
		  int actualDeviceId,
		  int vlanId) {
  u_short sport=0, dport=0;
  int sportIdx, dportIdx;
  struct ip ip;
  struct ip6_hdr *ip6;
  struct icmp6_hdr icmp6Pkt;
  u_int advance = 0;
  u_char *cp = NULL;
  u_char *snapend = NULL;
  u_int icmp6len = 0;
  u_int nh;
  int fragmented = 0;
  struct tcphdr tp;
  struct udphdr up;
  struct icmp icmpPkt;
  u_int hlen, ip_len, tcpDataLength, udpDataLength, off=0, tcpUdpLen, idx;
  HostTraffic *srcHost=NULL, *dstHost=NULL;
  HostAddr srcAddr, dstAddr; /* Protocol Independent addresses */
  u_char forceUsingIPaddress = 0;
  struct timeval tvstrct;
  u_char *theData, found = 0;
  TrafficCounter ctr;
  ProtocolsList *protoList;
  u_short newSession = 0;
  u_short nonFullyRemoteSession = 1;

  /* Need to copy this over in case bp isn't properly aligned.
   * This occurs on SunOS 4.x at least.
   *
   * Paul D. Smith <psmith@baynetworks.com>
   */
  memcpy(&ip, bp, sizeof(struct ip));
  /* TODO: isipv6 = (ip.ip_v == 6)?1:0; */
  if(ip.ip_v == 6) {
    /* handle IPv6 packets */
    ip6 = (struct ip6_hdr *)bp;
  } else
    ip6 = NULL;

  if(ip6)
    hlen = sizeof(struct ip6_hdr);
  else
    hlen = (u_int)ip.ip_hl * 4;

  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipPkts, 1);

  /*
    Fix below courtesy of Christian Hammers <ch@westend.com>
  */
  if(ip6)
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipv6Bytes, length /* ntohs(ip.ip_len) */);
  else
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipv4Bytes, length /* ntohs(ip.ip_len) */);

  if(ip6 == NULL) {
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
  }

  if((ether_src == NULL) && (ether_dst == NULL)) {
    /* Ethernet-less protocols (e.g. PPP/RAW IP) */
    forceUsingIPaddress = 1;
  }

  if(ip6) {
    addrput(AF_INET6, &srcAddr, &ip6->ip6_src);
    addrput(AF_INET6, &dstAddr, &ip6->ip6_dst);
  } else {
    NTOHL(ip.ip_dst.s_addr); NTOHL(ip.ip_src.s_addr);
    addrput(AF_INET, &srcAddr,&ip.ip_src.s_addr);
    addrput(AF_INET, &dstAddr,&ip.ip_dst.s_addr);
  }

  if(ip6 == NULL) {
    if(isBroadcastAddress(&dstAddr, NULL, NULL)
       && (ether_src != NULL) && (ether_dst != NULL) /* PPP has no ethernet */
       && (memcmp(ether_dst, ethBroadcast, 6) != 0)) {
      /* forceUsingIPaddress = 1; */

      srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId, h, p);
      if(srcHost != NULL) {
	if(vlanId != NO_VLAN) srcHost->vlanId = vlanId;
	if(myGlobals.runningPref.enableSuspiciousPacketDump && (!hasWrongNetmask(srcHost))) {
	  /* Dump the first packet only */
	  char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

	  traceEvent(CONST_TRACE_WARNING, "Host %s has a wrong netmask",
		     etheraddr_string(ether_src, etherbuf));
	  dumpSuspiciousPacket(actualDeviceId, h, p);
	}

	setHostFlag(FLAG_HOST_WRONG_NETMASK, srcHost);
      }
    }
  }

  /*
    IMPORTANT:
    do NOT change the order of the lines below (see isBroadcastAddress call)
  */
  dstHost = lookupHost(&dstAddr, ether_dst, vlanId, 1 , 0, actualDeviceId, h, p);
  if(dstHost == NULL) {
    /* Sanity check */
    lowMemory();
    return;
  }
  srcHost = lookupHost(&srcAddr, ether_src, vlanId,
		       /*
			 Don't check for multihoming when
			 the destination address is a broadcast address
		       */
		       (!isBroadcastAddress(&dstAddr, NULL, NULL)),
		       forceUsingIPaddress, actualDeviceId, h, p);

  if(srcHost == NULL) {
    /* Sanity check */
    lowMemory();
    return; /* It might be that there's not enough memory that that
	       dstHost = lookupHost(&ip.ip_dst, ether_dst) caused
	       srcHost to be freed */
  }

  if(vlanId != NO_VLAN) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }

#ifdef DEBUG
  if(myGlobals.runningPref.rFileName != NULL) {
    static int numPkt=1;

    traceEvent(CONST_TRACE_INFO, "%d) %s -> %s",
	       numPkt++,
	       srcHost->hostNumIpAddress,
	       dstHost->hostNumIpAddress);
    fflush(stdout);
  }
#endif

  /* ****************** */

  if(ip6) {
    updateDevicePacketTTLStats(ip6->ip6_hlim, actualDeviceId);

    if(ip6->ip6_hlim != 255) {
      if((srcHost->minTTL == 0) || (ip6->ip6_hlim < srcHost->minTTL)) srcHost->minTTL = ip6->ip6_hlim;
      if((ip6->ip6_hlim > srcHost->maxTTL)) srcHost->maxTTL = ip6->ip6_hlim;
    }

  } else {
    updateDevicePacketTTLStats(ip.ip_ttl, actualDeviceId);

    if(ip.ip_ttl != 255) {
      /*
	TTL can be calculated only when the packet
	is originated by the sender
      */
      if((srcHost->minTTL == 0) || (ip.ip_ttl < srcHost->minTTL)) srcHost->minTTL = ip.ip_ttl;
      if((ip.ip_ttl > srcHost->maxTTL)) srcHost->maxTTL = ip.ip_ttl;
    }
  }

  ctr.value = h->len;
  updatePacketCount(srcHost, dstHost, ctr, 1, actualDeviceId);

  if(!myGlobals.device[actualDeviceId].dummyDevice) {
    checkNetworkRouter(srcHost, dstHost, ether_dst, actualDeviceId, length, h, p);
    ctr.value = length;
  }

  if(ip6) {
    incrementHostTrafficCounter(srcHost, ipv6BytesSent, length);
    incrementHostTrafficCounter(dstHost, ipv6BytesRcvd, length);
  } else {
    incrementHostTrafficCounter(srcHost, ipv4BytesSent, length);
    incrementHostTrafficCounter(dstHost, ipv4BytesRcvd, length);
  }

  if(subnetPseudoLocalHost(srcHost)) {
    if(subnetPseudoLocalHost(dstHost)) {
      incrementHostTrafficCounter(srcHost, bytesSentLoc, length);
      incrementHostTrafficCounter(dstHost, bytesRcvdLoc, length);
    } else {
      incrementHostTrafficCounter(srcHost, bytesSentRem, length);
      incrementHostTrafficCounter(dstHost, bytesRcvdLoc, length);
    }
  } else {
    /* srcHost is remote */
    if(subnetPseudoLocalHost(dstHost)) {
      incrementHostTrafficCounter(srcHost, bytesSentLoc, length);
      incrementHostTrafficCounter(dstHost, bytesRcvdFromRem, length);
    } else {
      incrementHostTrafficCounter(srcHost, bytesSentRem, length);
      incrementHostTrafficCounter(dstHost, bytesRcvdFromRem, length);
    }
  }

  if(ip6) {
    if(ip6->ip6_nxt == IPPROTO_FRAGMENT) {
      fragmented = 1;
      nh = ip6->ip6_nxt;
    }
  } else {
    off = ntohs(ip.ip_off);
    if(off & 0x3fff) {
      fragmented = 1;
      nh = ip.ip_p;
    }
  }

  /*
    This is a fragment: fragment handling is handled by handleFragment()
    called below.

    Courtesy of Andreas Pfaller
  */
  if(fragmented) {
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].fragmentedIpBytes, length);

    switch(nh) {
    case IPPROTO_TCP:
      incrementHostTrafficCounter(srcHost, tcpFragmentsSent, length);
      incrementHostTrafficCounter(dstHost, tcpFragmentsRcvd, length);
      break;

    case IPPROTO_UDP:
      incrementHostTrafficCounter(srcHost, udpFragmentsSent, length);
      incrementHostTrafficCounter(dstHost, udpFragmentsRcvd, length);
      break;

    case IPPROTO_ICMP:
      incrementHostTrafficCounter(srcHost, icmpFragmentsSent, length);
      incrementHostTrafficCounter(dstHost, icmpFragmentsRcvd, length);
      break;

    case IPPROTO_GRE:
      incrementHostTrafficCounter(srcHost, greSent, length);
      incrementHostTrafficCounter(dstHost, greRcvd, length);
      incrementTrafficCounter(&myGlobals.device[actualDeviceId].greBytes, length);
      break;

    case IPPROTO_IPSEC_ESP:
    case IPPROTO_IPSEC_AH:
      incrementHostTrafficCounter(srcHost, ipsecSent, length);
      incrementHostTrafficCounter(dstHost, ipsecRcvd, length);
      incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipsecBytes, length);
      break;

    case IPPROTO_ICMPV6:
      incrementHostTrafficCounter(srcHost, icmp6FragmentsSent, length);
      incrementHostTrafficCounter(dstHost, icmp6FragmentsRcvd, length);
      break;
    }
  }

  if(ip6) {
    advance = sizeof(struct ip6_hdr);
    cp = (unsigned char *) ip6;
    snapend = (unsigned char *)(bp+length);
    nh = ip6->ip6_nxt;
    ip_len =  ntohs(ip6->ip6_plen);
    tcpUdpLen = ip_len;
  } else {
    nh = ip.ip_p;
    ip_len = ntohs(ip.ip_len);
    tcpUdpLen = ip_len - hlen;
  }

 loop:
  if(ip6)
    cp +=advance;

  switch(nh) {
  case IPPROTO_FRAGMENT:
    if(ip6) {
      advance = sizeof(struct ip6_frag);
      if(snapend <= cp+advance) goto end;
      nh = *cp;
      goto loop;
    }
    /* If it's no IPv6 we continue */

  case IPPROTO_TCP:
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpBytes, length);

    if(tcpUdpLen < sizeof(struct tcphdr)) {
      if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING, "Malformed TCP pkt %s->%s detected (packet too short)",
		   srcHost->hostResolvedName,
		   dstHost->hostResolvedName);
	dumpSuspiciousPacket(actualDeviceId, h, p);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.malformedPkts, 1);
      }
    } else {
      memcpy(&tp, bp+hlen, sizeof(struct tcphdr));

      /* Sanity check */
      if(tcpUdpLen >= (tp.th_off * 4)) {
	int diff;

	/* Real lenght if we captured the full packet */
	tcpDataLength = tcpUdpLen - (tp.th_off * 4);

	/* Actual lenght scaled with caplen */
	diff = h->caplen - (h->len - tcpDataLength);

	if(diff > 0) {
	  tcpDataLength = diff;
	  theData = (u_char*)(bp+hlen+(tp.th_off * 4));
	} else {
	  tcpDataLength = 0;
	  theData = NULL;
	}
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
      if(myGlobals.enableFragmentHandling && (fragmented)) {
	/* Handle fragmented packets */
	if(ip6)
	  length = handleFragment(srcHost, dstHost, &sport,&dport,
				  (u_short)(ip6->ip6_flow & 0xffff),fragmented,
				  length,ntohs(ip6->ip6_plen),
				  actualDeviceId, h, p);
	else
	  length = handleFragment(srcHost, dstHost, &sport, &dport,
				  ntohs(ip.ip_id), off, length,
				  ip_len - hlen, actualDeviceId, h, p);
      }

      if(srcHost->fingerprint == NULL) {
	char fingerprint[64] = { 0 } ;
	int WIN=0, MSS=-1, WS=-1, S=0, N=0, D=0, T=0;
	int ttl;
	char WSS[3] = { 0 }, _MSS[5] = { 0 };
	struct tcphdr *tcp = (struct tcphdr*)(bp+hlen);
	u_char *tcp_opt = (u_char *)(tcp + 1);
        u_char *tcp_data = (u_char *)(tcp + tp.th_off * 4);

	if(tcp->th_flags & TH_SYN) {   /* only SYN or SYN-2ACK packets */
	  if(tcpUdpLen > 0) {
	    if(ip6) {
	      if(!fragmented) D = 1;
	    } else
	      if(ntohs(ip.ip_off) & IP_DF) D = 1;   /* don't fragment bit is set */

	    WIN = ntohs(tcp->th_win);  /* TCP window size */

	    if(tcp_data != tcp_opt) { /* there are some tcp_option to be parsed */
	      u_char *opt_start = tcp_opt, *opt_end = tcp_data;
	      u_short num_loops = 0;

	      while(opt_start < opt_end) {
		switch(opt_start[0]) {
		case TCPOPT_EOL:        /* end option: exit */
		  opt_start = opt_end;
		  break;
		case TCPOPT_NOP:
		  N = 1;
		  opt_start++;
		  break;
		case TCPOPT_SACKOK:
		  S = 1;
		  opt_start += 2;
		  break;
		case TCPOPT_MAXSEG:
		  opt_start += 2;
		  MSS = ntohs(ptohs(opt_start));
		  opt_start += 2;
		  break;
		case TCPOPT_WSCALE:
		  opt_start += 2;
		  WS = *opt_start;
		  opt_start++;
		  break;
		case TCPOPT_TIMESTAMP:
		  T = 1;
		  opt_start++;
		  opt_start += (*opt_start - 1);
		  break;
		default:
		  opt_start++;
		  if(*opt_start > 0)
		    opt_start += (*opt_start - 1);
		  break;
		}

		num_loops++;
		if(num_loops > 16) {
		  /* Suspicious packet: maybe the TCP options are wrong */
		  break;
		}
	      }
	    }

	    if(WS == -1)
	      safe_snprintf(__FILE__, __LINE__, WSS, sizeof(WSS), "WS");
	    else
	      safe_snprintf(__FILE__, __LINE__, WSS, sizeof(WSS), "%02X", WS & 0xFFFF);

	    if(MSS == -1)
	      safe_snprintf(__FILE__, __LINE__, _MSS, sizeof(_MSS), "_MSS");
	    else
	      safe_snprintf(__FILE__, __LINE__, _MSS, sizeof(_MSS), "%04X", MSS & 0xFFFFFFFF);

	    safe_snprintf(__FILE__, __LINE__, fingerprint, sizeof(fingerprint),
			  "%04X:%s:%02X:%s:%d:%d:%d:%d:%c:%02X",
			  WIN, _MSS, ttl = TTL_PREDICTOR(ip.ip_ttl), WSS , S, N, D, T,
			  (tcp->th_flags & TH_ACK) ? 'A' : 'S', tcpUdpLen);

#if 0
	    traceEvent(CONST_TRACE_INFO, "[%s][%s]", srcHost->hostNumIpAddress, fingerprint);
#endif
	    srcHost->fingerprint = strdup(fingerprint);
	  }
	}
      }

      if((sport > 0) || (dport > 0)) {
	/* It might be that tcpDataLength is 0 when
	   the rcvd packet is fragmented and the main
	   packet has not yet been rcvd */

	updateInterfacePorts(actualDeviceId, sport, dport, length);
	if(tcpDataLength > 0) /* Don't update ports for all packets */
	  updateUsedPorts(srcHost, dstHost, sport, dport, tcpDataLength);

	if(subnetPseudoLocalHost(srcHost)) {
	  if(subnetPseudoLocalHost(dstHost)) {
	    incrementHostTrafficCounter(srcHost, tcpSentLoc, length);
	    incrementHostTrafficCounter(dstHost, tcpRcvdLoc, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.local,
				    length);
	  } else {
	    incrementHostTrafficCounter(srcHost, tcpSentRem, length);
	    incrementHostTrafficCounter(dstHost, tcpRcvdLoc, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.local2remote,
				    length);
	  }
	} else {
	  /* srcHost is remote */
	  if(subnetPseudoLocalHost(dstHost)) {
	    incrementHostTrafficCounter(srcHost, tcpSentLoc, length);
	    incrementHostTrafficCounter(dstHost, tcpRcvdFromRem, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.remote2local,
				    length);
	  } else {
	    incrementHostTrafficCounter(srcHost, tcpSentRem, length);
	    incrementHostTrafficCounter(dstHost, tcpRcvdFromRem, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.remote,
				    length);
	    nonFullyRemoteSession = 0;
	  }
	}

	if(nonFullyRemoteSession) {
	  if(ip6)
	    handleSession(h, p, fragmented, tp.th_win,
			  srcHost, sport, dstHost,
			  dport, ntohs(ip6->ip6_plen), 0, 
			  ip_offset, &tp, tcpDataLength,
			  theData, actualDeviceId, &newSession, 
			  IPOQUE_PROTOCOL_UNKNOWN, 1);
	  else
	    handleSession(h, p, (off & 0x3fff), tp.th_win,
			  srcHost, sport, dstHost,
			  dport, ip_len, 0, 
			  ip_offset, &tp, tcpDataLength,
			  theData, actualDeviceId, &newSession, 
			  IPOQUE_PROTOCOL_UNKNOWN, 1);
	}
      }
    }

    if(ip6)
      goto end;
    else
      break;

  case IPPROTO_UDP:
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpBytes, length);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.totalFlows, 1);

    if(tcpUdpLen < sizeof(struct udphdr)) {
      if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING, "Malformed UDP pkt %s->%s detected (packet too short)",
		   srcHost->hostResolvedName,
		   dstHost->hostResolvedName);
	dumpSuspiciousPacket(actualDeviceId, h, p);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.malformedPkts, 1);
      }
    } else {
      udpDataLength = (u_int)(tcpUdpLen - sizeof(struct udphdr));
      memcpy(&up, bp+hlen, sizeof(struct udphdr));

      sport = ntohs(up.uh_sport);
      dport = ntohs(up.uh_dport);

      if(!(fragmented)) {
	/* Not fragmented */
	if(((sport == 53) || (dport == 53) /* domain */)
	   || ((sport == 5353) && (dport == 5353)) /* Multicast DNS */) {
	  short isRequest = 0, positiveReply = 0;
	  u_int16_t transactionId = 0;

	  if(myGlobals.runningPref.enablePacketDecoding
	     && (bp != NULL) /* packet long enough */) {
	    /* The DNS chain will be checked here */
	    transactionId = processDNSPacket(srcHost, sport, bp+hlen+sizeof(struct udphdr),
					     udpDataLength, &isRequest, &positiveReply);

#ifdef DNS_SNIFF_DEBUG
	    traceEvent(CONST_TRACE_INFO, "DNS_SNIFF_DEBUG: %s:%d->%s:%d [request: %d][positive reply: %d]",
		       srcHost->hostResolvedName, sport,
		       dstHost->hostResolvedName, dport,
		       isRequest, positiveReply);
#endif

	    allocHostTrafficCounterMemory(srcHost, protocolInfo, sizeof(ProtocolInfo));
	    allocHostTrafficCounterMemory(dstHost, protocolInfo, sizeof(ProtocolInfo));
	    if((srcHost->protocolInfo == NULL) || (dstHost->protocolInfo == NULL)) return;

	    allocHostTrafficCounterMemory(srcHost, protocolInfo->dnsStats, sizeof(ServiceStats));
	    if(srcHost->protocolInfo->dnsStats == NULL) return;
	    allocHostTrafficCounterMemory(dstHost, protocolInfo->dnsStats, sizeof(ServiceStats));
	    if(dstHost->protocolInfo->dnsStats == NULL) return;

	    allocHostTrafficCounterMemory(srcHost, protocolInfo, sizeof(ProtocolInfo));
	    allocHostTrafficCounterMemory(srcHost, protocolInfo->dnsStats, sizeof(ServiceStats));

	    allocHostTrafficCounterMemory(dstHost, protocolInfo, sizeof(ProtocolInfo));
	    allocHostTrafficCounterMemory(dstHost, protocolInfo->dnsStats, sizeof(ServiceStats));

	    if(isRequest) {
	      /* to be 64bit-proof we have to copy the elements */
	      tvstrct.tv_sec = h->ts.tv_sec;
	      tvstrct.tv_usec = h->ts.tv_usec;
	      addTimeMapping(transactionId, tvstrct);

	      if(subnetLocalHost(dstHost)) {
		incrementHostTrafficCounter(srcHost, protocolInfo->dnsStats->numLocalReqSent, 1);
	      } else {
		incrementHostTrafficCounter(srcHost, protocolInfo->dnsStats->numRemReqSent, 1);
	      }

	      if(subnetLocalHost(srcHost)) {
		incrementHostTrafficCounter(dstHost, protocolInfo->dnsStats->numLocalReqRcvd, 1);
	      } else {
		incrementHostTrafficCounter(dstHost, protocolInfo->dnsStats->numRemReqRcvd, 1);
	      }
	    } else {
	      time_t microSecTimeDiff;

	      /* to be 64bit-safe we have to copy the elements */
	      tvstrct.tv_sec = h->ts.tv_sec;
	      tvstrct.tv_usec = h->ts.tv_usec;
	      microSecTimeDiff = getTimeMapping(transactionId, tvstrct);

	      if(microSecTimeDiff > 0) {
#ifdef DEBUG
		traceEvent(CONST_TRACE_INFO, "TransactionId=0x%X [%.1f ms]",
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
	      if(sport != 5353) setHostFlag(FLAG_NAME_SERVER_HOST, srcHost);

	      if(positiveReply) {
		incrementHostTrafficCounter(srcHost, protocolInfo->dnsStats->numPositiveReplSent, 1);
		incrementHostTrafficCounter(dstHost, protocolInfo->dnsStats->numPositiveReplRcvd, 1);
	      } else {
		incrementHostTrafficCounter(srcHost, protocolInfo->dnsStats->numNegativeReplSent, 1);
		incrementHostTrafficCounter(dstHost, protocolInfo->dnsStats->numNegativeReplRcvd, 1);
	      }
	    }
	  } else {
	    /* no packet decoding (let's speculate a bit) */
	    if(sport != 5353) setHostFlag(FLAG_NAME_SERVER_HOST, srcHost);
	  }
	} else if(sport == 123) /* NTP */ {
	  if(myGlobals.runningPref.enablePacketDecoding) {
	    char *ntpPktPtr = (char*)bp+hlen+sizeof(struct udphdr);
	    u_char ntpRole = ntpPktPtr[0] & 0x07;

	    if(ntpRole ==  4 /* NTP Server */)
	      setHostFlag(FLAG_HOST_TYPE_SVC_NTP_SERVER, srcHost);
	  }
	} else if(sport == 500) /* IPSEC IKE */ {
	  incrementHostTrafficCounter(srcHost, ipsecSent, length);
	  incrementHostTrafficCounter(dstHost, ipsecRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipsecBytes, length);
	} else {
	  if(myGlobals.runningPref.enablePacketDecoding)
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
      if(myGlobals.enableFragmentHandling && (fragmented)) {
	/* Handle fragmented packets */
	if(ip6)
	  length = handleFragment(srcHost, dstHost, &sport, &dport,
				  (u_short)(ip6->ip6_flow & 0xffff), fragmented, length,
				  ntohs(ip6->ip6_plen), actualDeviceId, h, p);
	else
	  length = handleFragment(srcHost, dstHost, &sport, &dport,
				  ntohs(ip.ip_id), off, length,
				  ip_len - hlen, actualDeviceId, h, p);
      }

      if((sport > 0) || (dport > 0)) {
	updateInterfacePorts(actualDeviceId, sport, dport, length);
	updateUsedPorts(srcHost, dstHost, sport, dport, udpDataLength);

	/* It might be that udpBytes is 0 when
	   the rcvd packet is fragmented and the main
	   packet has not yet been rcvd */

	if(subnetPseudoLocalHost(srcHost)) {
	  if(subnetPseudoLocalHost(dstHost)) {
	    incrementHostTrafficCounter(srcHost, udpSentLoc, length);
	    incrementHostTrafficCounter(dstHost, udpRcvdLoc, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.local, length);
	  } else {
	    incrementHostTrafficCounter(srcHost, udpSentRem, length);
	    incrementHostTrafficCounter(dstHost, udpRcvdLoc, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.local2remote, length);
	  }
	} else {
	  /* srcHost is remote */
	  if(subnetPseudoLocalHost(dstHost)) {
	    incrementHostTrafficCounter(srcHost, udpSentLoc, length);
	    incrementHostTrafficCounter(dstHost, udpRcvdFromRem, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.remote2local, length);
	  } else {
	    incrementHostTrafficCounter(srcHost, udpSentRem, length);
	    incrementHostTrafficCounter(dstHost, udpRcvdFromRem, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.remote, length);
	    nonFullyRemoteSession = 0;
	  }
	}

	/* if(nonFullyRemoteSession) */ {
	  /* There is no session structure returned for UDP sessions */
	  if(ip6)
	    handleSession(h, p, fragmented, 0,
			  srcHost, sport, dstHost,
			  dport, ntohs(ip6->ip6_plen), 0, 
			  ip_offset, NULL, udpDataLength,
			  (u_char*)(bp+hlen+sizeof(struct udphdr)),
			  actualDeviceId, &newSession, 
			  IPOQUE_PROTOCOL_UNKNOWN, 1);
	  else
	    handleSession(h, p, (off & 0x3fff), 0,
			  srcHost, sport, dstHost,
			  dport, ip_len, 0, ip_offset, 
			  NULL, udpDataLength,
			  (u_char*)(bp+hlen+sizeof(struct udphdr)),
			  actualDeviceId, &newSession, 
			  IPOQUE_PROTOCOL_UNKNOWN, 1);
	}

	newSession = 1; /* Trick to account flows anyway */
      }
    }

    if(ip6)
      goto end;
    else
      break;

  case IPPROTO_ICMP:
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].icmpBytes, length);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].icmpGlobalTrafficStats.totalFlows, 1);

    if(tcpUdpLen < sizeof(struct icmp)) {
      if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING, "Malformed ICMP pkt %s->%s detected (packet too short)",
		   srcHost->hostResolvedName,
		   dstHost->hostResolvedName);
	dumpSuspiciousPacket(actualDeviceId, h, p);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.malformedPkts, 1);
      }
    } else {
      memcpy(&icmpPkt, bp+hlen, sizeof(struct icmp));

      incrementHostTrafficCounter(srcHost, icmpSent, length);
      incrementHostTrafficCounter(dstHost, icmpRcvd, length);

      if(off & 0x3fff) {
	char *fmt = "Detected ICMP fragment [%s -> %s] (network attack attempt?)";

	incrementHostTrafficCounter(srcHost, icmpFragmentsSent, length);
	incrementHostTrafficCounter(dstHost, icmpFragmentsRcvd, length);
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->icmpFragmentSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->icmpFragmentRcvd, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.icmpFragment, 1);
	if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	  traceEvent(CONST_TRACE_WARNING, fmt,
		     srcHost->hostResolvedName, dstHost->hostResolvedName);
	  dumpSuspiciousPacket(actualDeviceId, h, p);
	}
      }

      /* ************************************************************* */

      if(icmpPkt.icmp_type <= ICMP_MAXTYPE) {
	short dumpPacket = 1;

	allocHostTrafficCounterMemory(srcHost, icmpInfo, sizeof(IcmpHostInfo));
	if(srcHost->icmpInfo == NULL) return;
	incrementHostTrafficCounter(srcHost, icmpInfo->icmpMsgSent[icmpPkt.icmp_type], 1);

	allocHostTrafficCounterMemory(dstHost, icmpInfo, sizeof(IcmpHostInfo));
	if(dstHost->icmpInfo == NULL) return;
	incrementHostTrafficCounter(dstHost, icmpInfo->icmpMsgRcvd[icmpPkt.icmp_type], 1);

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
	  if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	    dumpSuspiciousPacket(actualDeviceId, h, p);
	  }
	  break;
	}

	if(myGlobals.runningPref.enableSuspiciousPacketDump && dumpPacket) {
	  if(!((icmpPkt.icmp_type == 3) && (icmpPkt.icmp_code == 3))) {
	    /*
	      Avoid to print twice the same message:
 	      - Detected ICMP msg (type=3/code=3) from lhost -> ahost
	      - Host [ahost] sent UDP data to a closed port of host [lhost:10001]
	      (scan attempt?)
	    */

	    traceEvent(CONST_TRACE_INFO, "Detected ICMP msg [type=%s/code=%d] %s->%s",
		       mapIcmpType(icmpPkt.icmp_type), icmpPkt.icmp_code,
		       srcHost->hostResolvedName, dstHost->hostResolvedName);
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

      if(myGlobals.runningPref.enableSuspiciousPacketDump
	 && (icmpPkt.icmp_type == ICMP_ECHO)
	 && (broadcastHost(dstHost) || multicastHost(dstHost))) {
	traceEvent(CONST_TRACE_WARNING, "Smurf packet detected for host [%s->%s]",
		   srcHost->hostResolvedName, dstHost->hostResolvedName);
      } else if(icmpPkt.icmp_type == ICMP_DEST_UNREACHABLE /* Destination Unreachable */) {
	struct ip *oip = &icmpPkt.icmp_ip;

	switch(icmpPkt.icmp_code) {
	case ICMP_UNREACH_PORT: /* Port Unreachable */
	  memcpy(&dport, ((u_char *)bp+hlen+30), sizeof(dport));
	  dport = ntohs(dport);
	  switch (oip->ip_p) {
	  case IPPROTO_TCP:
	    if(myGlobals.runningPref.enableSuspiciousPacketDump)
	      traceEvent(CONST_TRACE_WARNING,
			 "Host [%s] sent TCP data to a closed port of host [%s:%d] (scan attempt?)",
			 dstHost->hostResolvedName, srcHost->hostResolvedName, dport);
	    /* Simulation of rejected TCP connection */
	    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	    incrementUsageCounter(&srcHost->secHostPkts->rejectedTCPConnSent, dstHost, actualDeviceId);
	    incrementUsageCounter(&dstHost->secHostPkts->rejectedTCPConnRcvd, srcHost, actualDeviceId);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.rejectedTCPConn, 1);
	    break;

	  case IPPROTO_UDP:
	    if(myGlobals.runningPref.enableSuspiciousPacketDump)
	      traceEvent(CONST_TRACE_WARNING,
			 "Host [%s] sent UDP data to a closed port of host [%s:%d] (scan attempt?)",
			 dstHost->hostResolvedName, srcHost->hostResolvedName, dport);
	    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	    incrementUsageCounter(&dstHost->secHostPkts->udpToClosedPortSent, srcHost, actualDeviceId);
	    incrementUsageCounter(&srcHost->secHostPkts->udpToClosedPortRcvd, dstHost, actualDeviceId);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.udpToClosedPort, 1);
	    break;
	  }
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpPortUnreachSent, dstHost, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpPortUnreachRcvd, srcHost, actualDeviceId);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.icmpPortUnreach, 1);
	  break;

	case ICMP_UNREACH_NET:
	case ICMP_UNREACH_HOST:
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpHostNetUnreachSent, dstHost, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpHostNetUnreachRcvd, srcHost, actualDeviceId);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.icmpHostNetUnreach, 1);
	  break;

	case ICMP_UNREACH_PROTOCOL: /* Protocol Unreachable */
	  if(myGlobals.runningPref.enableSuspiciousPacketDump)
	    traceEvent(CONST_TRACE_WARNING, /* See http://www.packetfactory.net/firewalk/ */
		       "Host [%s] rcvd a ICMP protocol Unreachable from host [%s]"
		       " (Firewalking scan attempt?)",
		       dstHost->hostResolvedName,
		       srcHost->hostResolvedName);
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpProtocolUnreachSent, dstHost, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpProtocolUnreachRcvd, srcHost, actualDeviceId);
	  break;
	case ICMP_UNREACH_NET_PROHIB:    /* Net Administratively Prohibited */
	case ICMP_UNREACH_HOST_PROHIB:   /* Host Administratively Prohibited */
	case ICMP_UNREACH_FILTER_PROHIB: /* Access Administratively Prohibited */
	  if(myGlobals.runningPref.enableSuspiciousPacketDump)
	    traceEvent(CONST_TRACE_WARNING, /* See http://www.packetfactory.net/firewalk/ */
		       "Host [%s] sent ICMP Administratively Prohibited packet to host [%s]"
		       " (Firewalking scan attempt?)",
		       dstHost->hostResolvedName, srcHost->hostResolvedName);
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpAdminProhibitedSent, dstHost, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpAdminProhibitedRcvd, srcHost, actualDeviceId);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.icmpAdminProhibited, 1);
	  break;
	}
	if(myGlobals.runningPref.enableSuspiciousPacketDump) dumpSuspiciousPacket(actualDeviceId, h, p);
      }
    }
    break;

  case IPPROTO_ICMPV6:
    if(ip6 == NULL) {
      if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING,"Protocol violation: ICMPv6 protocol in IPv4 packet: %s->%s",
		   srcHost->hostResolvedName,
		   dstHost->hostResolvedName);
	dumpSuspiciousPacket(actualDeviceId, h, p);
      }
      goto end;
    }
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].icmp6Bytes, length);
    if(ip6->ip6_plen)
      icmp6len = ntohs(ip6->ip6_plen); /* TODO: considering the pointers cp et bp*/
    if(icmp6len < sizeof(struct icmp6_hdr)) {
      if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING, "Malformed ICMPv6 pkt %s->%s detected (packet too short)",
		   srcHost->hostResolvedName,
		   dstHost->hostResolvedName);
	dumpSuspiciousPacket(actualDeviceId, h, p);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHost, actualDeviceId);
      }
    } else {
      memcpy(&icmp6Pkt, bp+hlen, sizeof(struct icmp6_hdr));
      incrementHostTrafficCounter(srcHost, icmp6Sent, length);
      incrementHostTrafficCounter(dstHost, icmp6Rcvd, length);

      if(fragmented) {
	char *fmt = "Detected ICMPv6 fragment [%s -> %s] (network attack attempt?)";

	incrementHostTrafficCounter(srcHost, icmp6FragmentsSent, length);
	incrementHostTrafficCounter(dstHost, icmp6FragmentsRcvd, length);
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->icmpFragmentSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->icmpFragmentRcvd, srcHost, actualDeviceId);
	if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	  traceEvent(CONST_TRACE_WARNING, fmt,
		     srcHost->hostResolvedName, dstHost->hostResolvedName);
	  dumpSuspiciousPacket(actualDeviceId, h, p);
	}
      }

      /* ************************************************************* */

      if(icmp6Pkt.icmp6_type <= ICMP6_MAXTYPE) {
	allocHostTrafficCounterMemory(srcHost, icmpInfo, sizeof(IcmpHostInfo));
	if(srcHost->icmpInfo == NULL) return;

	incrementHostTrafficCounter(srcHost, icmpInfo->icmpMsgSent[icmp6Pkt.icmp6_type], 1);

	allocHostTrafficCounterMemory(dstHost, icmpInfo, sizeof(IcmpHostInfo));
	if(dstHost->icmpInfo == NULL) return;

	incrementHostTrafficCounter(dstHost, icmpInfo->icmpMsgRcvd[icmp6Pkt.icmp6_type], 1);
	switch (icmp6Pkt.icmp6_type) {
	case ICMP6_ECHO_REPLY:
	case ICMP6_ECHO_REQUEST:
	  /* Do not log anything */
	  break;
	case ICMP6_DST_UNREACH:
	case ND_REDIRECT:
	case ICMP6_TIME_EXCEEDED:
	case ICMP6_PARAM_PROB:
	case ICMP6_NI_QUERY:
	case ICMP6_NI_REPLY:
	  if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	    dumpSuspiciousPacket(actualDeviceId, h, p);
	  }

	  break;
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

      if(icmp6Pkt.icmp6_type == ND_ROUTER_ADVERT) {
	HostTraffic *router = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId, h, p);
	if(router != NULL) setHostFlag(FLAG_GATEWAY_HOST, router);
      }

      if(icmp6Pkt.icmp6_type == ICMP6_DST_UNREACH /* Destination Unreachable */) {
	struct ip6_hdr *oip = (struct ip6_hdr *)&icmp6Pkt+1;

	switch(icmp6Pkt.icmp6_code) {
	case ICMP6_DST_UNREACH_NOPORT: /* Port Unreachable */
	  memcpy(&dport, ((u_char *)bp+hlen+30), sizeof(dport));
	  dport = ntohs(dport);
	  switch (oip->ip6_nxt) {
	  case IPPROTO_TCP:
	    if(myGlobals.runningPref.enableSuspiciousPacketDump)
	      traceEvent(CONST_TRACE_WARNING,
			 "Host [%s] sent TCP data to a closed port of host [%s:%d] (scan attempt?)",
			 dstHost->hostResolvedName, srcHost->hostResolvedName, dport);
	    /* Simulation of rejected TCP connection */
	    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	    incrementUsageCounter(&srcHost->secHostPkts->rejectedTCPConnSent, dstHost, actualDeviceId);
	    incrementUsageCounter(&dstHost->secHostPkts->rejectedTCPConnRcvd, srcHost, actualDeviceId);
	    break;

	  case IPPROTO_UDP:
	    if(myGlobals.runningPref.enableSuspiciousPacketDump)
	      traceEvent(CONST_TRACE_WARNING,
			 "Host [%s] sent UDP data to a closed port of host [%s:%d] (scan attempt?)",
			 dstHost->hostResolvedName, srcHost->hostResolvedName, dport);
	    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	    incrementUsageCounter(&dstHost->secHostPkts->udpToClosedPortSent, srcHost, actualDeviceId);
	    incrementUsageCounter(&srcHost->secHostPkts->udpToClosedPortRcvd, dstHost, actualDeviceId);
	    break;
	  }
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpPortUnreachSent, dstHost, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpPortUnreachRcvd, srcHost, actualDeviceId);
	  break;

	case ICMP6_DST_UNREACH_NOROUTE:
	case ICMP6_DST_UNREACH_ADDR:
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpHostNetUnreachSent, dstHost, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpHostNetUnreachRcvd, srcHost, actualDeviceId);
	  break;

	case ICMP6_DST_UNREACH_ADMIN:    /* Administratively Prohibited */
	  if(myGlobals.runningPref.enableSuspiciousPacketDump)
	    traceEvent(CONST_TRACE_WARNING, /* See http://www.packetfactory.net/firewalk/ */
		       "Host [%s] sent ICMPv6 Administratively Prohibited packet to host [%s]"
		       " (Firewalking scan attempt?)",
		       dstHost->hostResolvedName, srcHost->hostResolvedName);
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpAdminProhibitedSent, dstHost, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpAdminProhibitedRcvd, srcHost, actualDeviceId);
	  break;
	}
	if(myGlobals.runningPref.enableSuspiciousPacketDump) dumpSuspiciousPacket(actualDeviceId, h, p);
      }
    }
    break;

  default:
    if(srcHost->ipProtosList != NULL) {
      protoList = myGlobals.ipProtosList;
      idx = 0;

      while(protoList != NULL) {
	if((protoList->protocolId == nh)
	   || ((protoList->protocolIdAlias != 0) && (protoList->protocolIdAlias == nh))) {

	  allocHostTrafficCounterMemory(srcHost, ipProtosList, (size_t)(myGlobals.numIpProtosToMonitor*sizeof(ProtoTrafficInfo**)));
	  if(srcHost->ipProtosList) {
	    allocHostTrafficCounterMemory(srcHost, ipProtosList[idx], sizeof(ShortProtoTrafficInfo));
	    if(srcHost->ipProtosList[idx] == NULL) return;
	    incrementHostTrafficCounter(srcHost, ipProtosList[idx]->sent, length);
	  }

	  allocHostTrafficCounterMemory(dstHost, ipProtosList, (size_t)myGlobals.numIpProtosToMonitor*sizeof(ProtoTrafficInfo**));
	  if(dstHost->ipProtosList) {
	    allocHostTrafficCounterMemory(dstHost, ipProtosList[idx], sizeof(ShortProtoTrafficInfo));
	    if(dstHost->ipProtosList[idx] == NULL) return;
	    incrementHostTrafficCounter(dstHost, ipProtosList[idx]->rcvd, length);
	  }

	  if(myGlobals.device[actualDeviceId].ipProtosList)
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipProtosList[idx], length);
	  found = 1;
	  break;
	}

	idx++, protoList = protoList->next;
      }
    }

    if(!found) {
      incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherIpBytes, length);
      sport = dport = 0;

      allocHostTrafficCounterMemory(srcHost, nonIPTraffic, sizeof(NonIPTraffic));
      allocHostTrafficCounterMemory(dstHost, nonIPTraffic, sizeof(NonIPTraffic));
      if((srcHost->nonIPTraffic == NULL) || (dstHost->nonIPTraffic == NULL)) return;

      incrementHostTrafficCounter(srcHost, nonIPTraffic->otherSent, length);
      incrementUnknownProto(srcHost, 0 /* sent */, 0 /* eth */, 0 /* dsap */, 0 /* ssap */, nh);
      incrementHostTrafficCounter(dstHost, nonIPTraffic->otherRcvd, length);
      incrementUnknownProto(dstHost, 1 /* rcvd */, 0 /* eth */, 0 /* dsap */, 0 /* ssap */, nh);
    }
    break;
  }

 end:
  ; /* Needed by some compilers */

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "IP=%d TCP=%d UDP=%d ICMP=%d (len=%d)",
	     (int)myGlobals.device[actualDeviceId].ipBytes.value,
	     (int)myGlobals.device[actualDeviceId].tcpBytes.value,
	     (int)myGlobals.device[actualDeviceId].udpBytes.value,
	     (int)myGlobals.device[actualDeviceId].icmpBytes.value,
	     length);
#endif
}

