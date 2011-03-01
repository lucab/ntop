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

/* PPPoE - Courtesy of Andreas Pfaller Feb2003 */
#ifdef HAVE_LINUX_IF_PPPOX_H
#include <linux/if_pppox.h>
#else
/* Extracted and modified from the Linux header for other systems - BMS Mar2003 */
/* And for Linux systems without if_pppox.h - BMS Apr2003 */
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
static u_char lowMemoryMsgShown = 0;

static void updateASTraffic(int actualDeviceId, u_int16_t src_as_id,
			    u_int16_t dst_as_id, u_int octets);

/* ******************************* */

void allocateSecurityHostPkts(HostTraffic *srcHost) {
  if(srcHost->secHostPkts == NULL) {
    if((srcHost->secHostPkts = (SecurityHostProbes*)malloc(sizeof(SecurityHostProbes))) == NULL) return;
    resetSecurityHostTraffic(srcHost);
  }
}

/* ************************************ */

static void updateRoutedTraffic(HostTraffic *router) {
  if(router != NULL) {
    if(router->routedTraffic == NULL) {
      int mallocLen = sizeof(RoutingCounter);

      router->routedTraffic = (RoutingCounter*)malloc(mallocLen);
      if(router->routedTraffic == NULL) return;
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

u_int computeEfficiency(u_int pktLen) {
  u_int pktEfficiency;

  if(myGlobals.cellLength == 0)
    pktEfficiency = 0;
  else
    pktEfficiency = 100 - (((pktLen % myGlobals.cellLength) * 100) / myGlobals.cellLength);

  // traceEvent(CONST_TRACE_WARNING, "[len=%d][efficiency=%d]", pktLen, pktEfficiency);
  return(pktEfficiency);
}

/* ************************************ */

int handleIP(u_short port, HostTraffic *srcHost, HostTraffic *dstHost,
	     const u_int numPkts, const u_int _length, u_short isPassiveSess,
	     u_short isVoipSess,
	     u_short p2pSessionIdx,
	     u_short httpSessionIdx,
	     int actualDeviceId,
	     u_short newSession) {
  int idx;
  Counter length = (Counter)_length;

  if((srcHost == NULL) || (dstHost == NULL)) {
    if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (4) [Low memory?]");
    lowMemoryMsgShown = 1;
    return(-1);
  }

  if(isPassiveSess) {
    /* Emulate non passive session */
    idx = myGlobals.FTPIdx;
  } else if(isVoipSess || (port == 54045 /* Skype default port */)) {
    /* Emulate VoIP session */
    idx = myGlobals.VoipIdx;
  } else if(httpSessionIdx != 0) {
    switch(httpSessionIdx) {
    case FLAG_FACEBOOK: idx =  myGlobals.FacebookIdx; break;
    case FLAG_TWITTER: idx =  myGlobals.TwitterIdx; break;
    case FLAG_YOUTUBE: idx =  myGlobals.YouTubeIdx; break;
    default: idx = -1; break;
    }
  } else {
    if(p2pSessionIdx) {
      switch(p2pSessionIdx) {
      case FLAG_P2P_EDONKEY:
	idx = myGlobals.EdonkeyIdx;
	break;
      case FLAG_P2P_KAZAA:
	idx = myGlobals.KazaaIdx;
	break;
      case FLAG_P2P_BITTORRENT:
	idx = myGlobals.BitTorrentIdx;
	break;
      default:
	idx = -1;
	break;
      }
    } else
      idx = mapGlobalToLocalIdx(port);
  }

  if(idx == -1) {
    return(-1); /* Unable to locate requested index */
  } else if(idx >= myGlobals.numIpProtosToMonitor) {
    traceEvent(CONST_TRACE_ERROR, "Discarding idx=%d for port=%d", idx, port);
    return(-1);
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "port=%d - isPassiveSess=%d - isVoipSess=%d - p2pSessionIdx=%d - idx=%d",
	     port, isPassiveSess, isVoipSess, p2pSessionIdx, idx);
#endif

  if(idx != FLAG_NO_PEER) {
    if(newSession)
      incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipProtoStats[idx].totalFlows, 1);

    if((!myGlobals.runningPref.trackOnlyLocalHosts)
       || (myGlobals.runningPref.trackOnlyLocalHosts && subnetPseudoLocalHost(srcHost))) {
      allocHostTrafficCounterMemory(srcHost, protoIPTrafficInfos, myGlobals.numIpProtosToMonitor*sizeof(ProtoTrafficInfo**));
      allocHostTrafficCounterMemory(srcHost, protoIPTrafficInfos[idx], sizeof(ProtoTrafficInfo));
    }

    if((!myGlobals.runningPref.trackOnlyLocalHosts)
       || (myGlobals.runningPref.trackOnlyLocalHosts && subnetPseudoLocalHost(dstHost))) {
      allocHostTrafficCounterMemory(dstHost, protoIPTrafficInfos, myGlobals.numIpProtosToMonitor*sizeof(ProtoTrafficInfo**));
      allocHostTrafficCounterMemory(dstHost, protoIPTrafficInfos[idx], sizeof(ProtoTrafficInfo));
    }

    if(subnetPseudoLocalHost(srcHost)) {
      if(subnetPseudoLocalHost(dstHost)) {
	if((!broadcastHost(srcHost)) && (srcHost->protoIPTrafficInfos != NULL)) {
	  incrementHostTrafficCounter(srcHost, protoIPTrafficInfos[idx]->sentLoc, length);

	  if(newSession)
	    incrementHostTrafficCounter(srcHost, protoIPTrafficInfos[idx]->totalFlows, 1);
	}

	if((!broadcastHost(dstHost)) && (dstHost->protoIPTrafficInfos != NULL)) {
	  incrementHostTrafficCounter(dstHost, protoIPTrafficInfos[idx]->rcvdLoc, length);

	  if(newSession)
	    incrementHostTrafficCounter(dstHost, protoIPTrafficInfos[idx]->totalFlows, 1);
	}

	incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipProtoStats[idx].local, length);
      } else {
	if((!broadcastHost(srcHost)) && (srcHost->protoIPTrafficInfos != NULL)) {
	  incrementHostTrafficCounter(srcHost, protoIPTrafficInfos[idx]->sentRem, length);

	  if(newSession)
	    incrementHostTrafficCounter(srcHost, protoIPTrafficInfos[idx]->totalFlows, 1);
	}

	if((!broadcastHost(dstHost)) && (dstHost->protoIPTrafficInfos != NULL)) {
	  incrementHostTrafficCounter(dstHost, protoIPTrafficInfos[idx]->rcvdLoc, length);

	  if(newSession)
	    incrementHostTrafficCounter(dstHost, protoIPTrafficInfos[idx]->totalFlows, 1);
	}

	incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipProtoStats[idx].local2remote, length);
      }
    } else {
      /* srcHost is remote */
      if(subnetPseudoLocalHost(dstHost)) {
	if((!broadcastHost(srcHost)) && (srcHost->protoIPTrafficInfos != NULL)) {
	  if(newSession)
	    incrementHostTrafficCounter(srcHost, protoIPTrafficInfos[idx]->totalFlows, 1);

	  incrementHostTrafficCounter(srcHost, protoIPTrafficInfos[idx]->sentLoc, length);
	}

	if((!broadcastHost(dstHost)) && (dstHost->protoIPTrafficInfos != NULL)) {
	  if(newSession)
	    incrementHostTrafficCounter(dstHost, protoIPTrafficInfos[idx]->totalFlows, 1);

	  incrementHostTrafficCounter(dstHost, protoIPTrafficInfos[idx]->rcvdFromRem, length);
	}

	incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipProtoStats[idx].remote2local, length);
      } else {
	if((!broadcastHost(srcHost)) && (srcHost->protoIPTrafficInfos != NULL)) {
	  if(newSession)
	    incrementHostTrafficCounter(srcHost, protoIPTrafficInfos[idx]->totalFlows, 1);

	  incrementHostTrafficCounter(srcHost, protoIPTrafficInfos[idx]->sentRem, length);
	}

	if((!broadcastHost(dstHost)) && (dstHost->protoIPTrafficInfos != NULL)) {
	  if(newSession)
	    incrementHostTrafficCounter(dstHost, protoIPTrafficInfos[idx]->totalFlows, 1);

	  incrementHostTrafficCounter(dstHost, protoIPTrafficInfos[idx]->rcvdFromRem, length);
	}

	incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipProtoStats[idx].remote, length);
      }
    }

    if(srcHost->protoIPTrafficInfos) incrementHostTrafficCounter(srcHost, protoIPTrafficInfos[idx]->pktSent, numPkts);
    if(dstHost->protoIPTrafficInfos) incrementHostTrafficCounter(dstHost, protoIPTrafficInfos[idx]->pktRcvd, numPkts);
  }

  return(idx);
}

/* ************************************ */

static void addContactedPeers(HostTraffic *sender, HostAddr *srcAddr,
			      HostTraffic *receiver, HostAddr *dstAddr,
			      int actualDeviceId) {
  if((sender == NULL) || (receiver == NULL) || (sender == receiver)) {
    if((sender != NULL) && (sender->l2Family == FLAG_HOST_TRAFFIC_AF_FC)) {
      /* This is normal. Return without warning */
      return;
    }
    traceEvent(CONST_TRACE_ERROR, "Sanity check failed @ addContactedPeers (%p, %p)",
	       sender, receiver);
    return;
  }

  if((sender != myGlobals.otherHostEntry) && (receiver != myGlobals.otherHostEntry)) {
    /* The statements below have no effect if the serial has been already computed */
    setHostSerial(sender); setHostSerial(receiver);

    sender->totContactedSentPeers +=
      incrementUsageCounter(&sender->contactedSentPeers, receiver, actualDeviceId);
    receiver->totContactedRcvdPeers +=
      incrementUsageCounter(&receiver->contactedRcvdPeers, sender, actualDeviceId);
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
				 int actualDeviceId) {
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

      dumpSuspiciousPacket(actualDeviceId);
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
			    int actualDeviceId) {
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
			 fragmentOffset, dataLength, actualDeviceId);

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

static void checkNetworkRouter(HostTraffic *srcHost, HostTraffic *dstHost,
			       u_char *ether_dst, int actualDeviceId) {
  if((subnetLocalHost(srcHost) && (!subnetLocalHost(dstHost))
      && (!broadcastHost(dstHost)) && (!multicastHost(dstHost)))
     || (subnetLocalHost(dstHost) && (!subnetLocalHost(srcHost))
	 && (!broadcastHost(srcHost)) && (!multicastHost(srcHost)))) {
    HostTraffic *router = lookupHost(NULL, ether_dst, srcHost->vlanId, 0, 0, actualDeviceId);

    if(router == NULL) return;

    if(((router->hostNumIpAddress[0] != '\0')
	&& (broadcastHost(router)
	    || multicastHost(router)
	    || (!subnetLocalHost(router)) /* No IP: is this a special Multicast address ? */))
       || (addrcmp(&router->hostIpAddress,&dstHost->hostIpAddress) == 0)
       || (memcmp(router->ethAddress, dstHost->ethAddress, LEN_ETHERNET_ADDRESS) == 0)
       )
      return;

    incrementUsageCounter(&srcHost->contactedRouters, router, actualDeviceId);

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "(%s/%s/%s) -> (%s/%s/%s) routed by [%s/%s/%s]",
	       srcHost->ethAddressString, srcHost->hostNumIpAddress, srcHost->hostResolvedName,
	       dstHost->ethAddressString, dstHost->hostNumIpAddress, dstHost->hostResolvedName,
	       router->ethAddressString,
	       router->hostNumIpAddress,
	       router->hostResolvedName);

#endif

    setHostFlag(FLAG_GATEWAY_HOST, router);
    updateRoutedTraffic(router);
  }
}

/* ************************************ */

/* Reset the traffic at every hour */
static void resetHourTraffic(u_short hourId) {
  int i;

  for(i=0; i<myGlobals.numDevices; i++) {
    HostTraffic *el;

    for(el=getFirstHost(i); el != NULL; el = getNextHost(i, el)) {
      if(el->trafficDistribution != NULL) {
	resetTrafficCounter(&el->trafficDistribution->last24HoursBytesSent[hourId]);
	resetTrafficCounter(&el->trafficDistribution->last24HoursBytesRcvd[hourId]);
      }
    }
  }
}

/* ************************************ */

void updatePacketCount(HostTraffic *srcHost, HostAddr *srcAddr,
		       HostTraffic *dstHost, HostAddr *dstAddr,
		       TrafficCounter bytes, Counter numPkts,
		       int actualDeviceId) {
  static u_short lastHourId=0;
  u_short hourId;
  struct tm t, *thisTime;

  if(numPkts == 0) return;

  if((srcHost == NULL) || (dstHost == NULL)) {
    traceEvent(CONST_TRACE_ERROR, "NULL host detected");
    return;
  }

  updateASTraffic(actualDeviceId, srcHost->hostAS, dstHost->hostAS, bytes.value);

  if(srcHost == dstHost) {
    return;
  } else if((srcHost == myGlobals.otherHostEntry)
	    && (dstHost == myGlobals.otherHostEntry)) {
    return;
  }

  thisTime = localtime_r(&myGlobals.actTime, &t);
  hourId = thisTime->tm_hour % 24 /* just in case... */;;

  if(lastHourId != hourId) {
    resetHourTraffic(hourId);
    lastHourId = hourId;
  }

  if(srcHost != myGlobals.otherHostEntry) {
    incrementHostTrafficCounter(srcHost, pktSent, numPkts);
    incrementHostTrafficCounter(srcHost, pktSentSession, numPkts);

    allocHostTrafficCounterMemory(srcHost, trafficDistribution, sizeof(TrafficDistribution));
    if(srcHost->trafficDistribution == NULL) return;
    incrementHostTrafficCounter(srcHost, trafficDistribution->last24HoursBytesSent[hourId], bytes.value);
    incrementHostTrafficCounter(srcHost, bytesSent, bytes.value);
    incrementHostTrafficCounter(srcHost, bytesSentSession, bytes.value);
  }

  if(dstHost != myGlobals.otherHostEntry) {
    incrementHostTrafficCounter(dstHost, pktRcvd, numPkts);
    incrementHostTrafficCounter(dstHost, pktRcvdSession, numPkts);

    allocHostTrafficCounterMemory(dstHost, trafficDistribution, sizeof(TrafficDistribution));
    if(dstHost->trafficDistribution == NULL) return;
    incrementHostTrafficCounter(dstHost, trafficDistribution->last24HoursBytesRcvd[hourId], bytes.value);
    incrementHostTrafficCounter(dstHost, bytesRcvd, bytes.value);
    incrementHostTrafficCounter(dstHost, bytesRcvdSession, bytes.value);
  }

  if(broadcastHost(dstHost)) {
    if(srcHost != myGlobals.otherHostEntry) {
      incrementHostTrafficCounter(srcHost, pktBroadcastSent, numPkts);
      incrementHostTrafficCounter(srcHost, bytesBroadcastSent, bytes.value);
    }
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].broadcastPkts, numPkts);
  } else if(isMulticastAddress(&(dstHost->hostIpAddress), NULL, NULL)) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "%s->%s",
	       srcHost->hostResolvedName, dstHost->hostResolvedName);
#endif
    if(srcHost != myGlobals.otherHostEntry) {
      incrementHostTrafficCounter(srcHost, pktMulticastSent, numPkts);
      incrementHostTrafficCounter(srcHost, bytesMulticastSent, bytes.value);
    }

    if(dstHost != myGlobals.otherHostEntry) {
      incrementHostTrafficCounter(dstHost, pktMulticastRcvd, numPkts);
      incrementHostTrafficCounter(dstHost, bytesMulticastRcvd, bytes.value);
    }
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].multicastPkts, numPkts);
  }

  if((dstHost != NULL) /*&& (!broadcastHost(dstHost))*/)
    addContactedPeers(srcHost, srcAddr, dstHost, dstAddr, actualDeviceId);
}

/* ************************************ */

void updateHostName(HostTraffic *el) {
  if((el->hostNumIpAddress[0] == '\0')
     || (el->hostResolvedName == NULL)
     || (el->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_NONE)
     || strcmp(el->hostResolvedName, el->hostNumIpAddress) == 0) {
    int i;

    if(el->nonIPTraffic == NULL) {
      el->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
      if(el->nonIPTraffic == NULL) return; /* Not enough memory */
    }

    if(el->nonIPTraffic->nbHostName != NULL) {
      /*
	Use NetBIOS name (when available) if the
	IP address has not been resolved.
      */
      memset(el->hostResolvedName, 0, sizeof(el->hostResolvedName));
      setResolvedName(el, el->nonIPTraffic->nbHostName, FLAG_HOST_SYM_ADDR_TYPE_NETBIOS);
    } else if(el->nonIPTraffic->ipxHostName != NULL) {
      setResolvedName(el, el->nonIPTraffic->ipxHostName, FLAG_HOST_SYM_ADDR_TYPE_IPX);
    } else if(el->nonIPTraffic->atNodeName != NULL) {
      setResolvedName(el, el->nonIPTraffic->atNodeName, FLAG_HOST_SYM_ADDR_TYPE_ATALK);
    }

    if(el->hostResolvedName[0] != '\0')
      for(i=0; el->hostResolvedName[i] != '\0'; i++)
	el->hostResolvedName[i] = (char)tolower(el->hostResolvedName[i]);
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
  else               incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktTTLStats.upTo255, 1);
}

/* ************************************ */

void updateInterfacePorts(int actualDeviceId, u_short sport, u_short dport, u_int length) {
  if((sport >= MAX_IP_PORT) || (dport >= MAX_IP_PORT) || (length == 0))
    return;

  accessMutex(&myGlobals.purgePortsMutex, "updateInterfacePorts");

  if(myGlobals.device[actualDeviceId].ipPorts == NULL)
    allocDeviceMemory(actualDeviceId);

  if(myGlobals.device[actualDeviceId].ipPorts[sport] == NULL) {
    myGlobals.device[actualDeviceId].ipPorts[sport] = (PortCounter*)malloc(sizeof(PortCounter));
    if(myGlobals.device[actualDeviceId].ipPorts[sport] == NULL) {
      releaseMutex(&myGlobals.purgePortsMutex);
      return;
    }
    myGlobals.device[actualDeviceId].ipPorts[sport]->port = sport;
    myGlobals.device[actualDeviceId].ipPorts[sport]->sent = 0;
    myGlobals.device[actualDeviceId].ipPorts[sport]->rcvd = 0;
  }

  if(myGlobals.device[actualDeviceId].ipPorts[dport] == NULL) {
    myGlobals.device[actualDeviceId].ipPorts[dport] = (PortCounter*)malloc(sizeof(PortCounter));
    if(myGlobals.device[actualDeviceId].ipPorts[dport] == NULL) {
      releaseMutex(&myGlobals.purgePortsMutex);
      return;
    }
    myGlobals.device[actualDeviceId].ipPorts[dport]->port = dport;
    myGlobals.device[actualDeviceId].ipPorts[dport]->sent = 0;
    myGlobals.device[actualDeviceId].ipPorts[dport]->rcvd = 0;
  }

  myGlobals.device[actualDeviceId].ipPorts[sport]->sent += length;
  myGlobals.device[actualDeviceId].ipPorts[dport]->rcvd += length;

  releaseMutex(&myGlobals.purgePortsMutex);
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

void incrementUnknownProto(HostTraffic *host,
			   int direction,
			   u_int16_t eth_type,
			   u_int16_t dsap,  u_int16_t ssap,
			   u_int16_t ipProto) {
  int i;

  if(host->nonIPTraffic == NULL) {
    host->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
    if(host->nonIPTraffic == NULL) return;
  }

  if(direction == 0) {
    /* Sent */
    if(host->nonIPTraffic->unknownProtoSent == NULL) {
      host->nonIPTraffic->unknownProtoSent = (UnknownProto*)malloc(sizeof(UnknownProto)*
								   MAX_NUM_UNKNOWN_PROTOS);
      if(host->nonIPTraffic->unknownProtoSent == NULL) return;
      memset(host->nonIPTraffic->unknownProtoSent, 0, sizeof(UnknownProto)*MAX_NUM_UNKNOWN_PROTOS);
    }

    for(i=0; i<MAX_NUM_UNKNOWN_PROTOS; i++) {
      if(host->nonIPTraffic->unknownProtoSent[i].protoType == 0) break;
      if((host->nonIPTraffic->unknownProtoSent[i].protoType == 1) && eth_type) {
	if(host->nonIPTraffic->unknownProtoSent[i].proto.ethType == eth_type) { return; }
      } else if((host->nonIPTraffic->unknownProtoSent[i].protoType == 2) && (dsap || ssap)) {
	if((host->nonIPTraffic->unknownProtoSent[i].proto.sapType.dsap == dsap)
	   && (host->nonIPTraffic->unknownProtoSent[i].proto.sapType.ssap == ssap)) { return; }
      } else if((host->nonIPTraffic->unknownProtoSent[i].protoType == 3) && ipProto) {
	if(host->nonIPTraffic->unknownProtoSent[i].proto.ipType == ipProto) { return; }
      }
    }

    if(i<MAX_NUM_UNKNOWN_PROTOS) {
      if(eth_type) {
	host->nonIPTraffic->unknownProtoSent[i].protoType = 1;
	host->nonIPTraffic->unknownProtoSent[i].proto.ethType = eth_type;
      } else if(dsap || ssap) {
	host->nonIPTraffic->unknownProtoSent[i].protoType = 2;
	host->nonIPTraffic->unknownProtoSent[i].proto.sapType.dsap = dsap;
	host->nonIPTraffic->unknownProtoSent[i].proto.sapType.ssap = ssap;
      } else {
	host->nonIPTraffic->unknownProtoSent[i].protoType = 3;
	host->nonIPTraffic->unknownProtoSent[i].proto.ipType = ipProto;
      }
    }
  } else {
    /* Rcvd */
    if(host->nonIPTraffic->unknownProtoRcvd == NULL) {
      host->nonIPTraffic->unknownProtoRcvd = (UnknownProto*)malloc(sizeof(UnknownProto)*
								   MAX_NUM_UNKNOWN_PROTOS);
      if(host->nonIPTraffic->unknownProtoRcvd == NULL) return;
      memset(host->nonIPTraffic->unknownProtoRcvd, 0, sizeof(UnknownProto)*MAX_NUM_UNKNOWN_PROTOS);
    }
    for(i=0; i<MAX_NUM_UNKNOWN_PROTOS; i++) {
      if(host->nonIPTraffic->unknownProtoRcvd[i].protoType == 0) break;
      if((host->nonIPTraffic->unknownProtoRcvd[i].protoType == 1) && eth_type) {
	if(host->nonIPTraffic->unknownProtoRcvd[i].proto.ethType == eth_type) { return; }
      } else if((host->nonIPTraffic->unknownProtoRcvd[i].protoType == 2) && (dsap || ssap)) {
	if((host->nonIPTraffic->unknownProtoRcvd[i].proto.sapType.dsap == dsap)
	   && (host->nonIPTraffic->unknownProtoRcvd[i].proto.sapType.ssap == ssap)) { return; }
      } else if((host->nonIPTraffic->unknownProtoRcvd[i].protoType == 3) && ipProto) {
	if(host->nonIPTraffic->unknownProtoRcvd[i].proto.ipType == ipProto) { return; }
      }
    }

    if(i<MAX_NUM_UNKNOWN_PROTOS) {
      if(eth_type) {
	host->nonIPTraffic->unknownProtoRcvd[i].protoType = 1;
	host->nonIPTraffic->unknownProtoRcvd[i].proto.ethType = eth_type;
      } else if(dsap || ssap) {
	host->nonIPTraffic->unknownProtoRcvd[i].protoType = 2;
	host->nonIPTraffic->unknownProtoRcvd[i].proto.sapType.dsap = dsap;
	host->nonIPTraffic->unknownProtoRcvd[i].proto.sapType.ssap = ssap;
      } else {
	host->nonIPTraffic->unknownProtoRcvd[i].protoType = 3;
	host->nonIPTraffic->unknownProtoRcvd[i].proto.ipType = ipProto;
      }
    }
  }
}

/* ************************************ */

static AsStats* allocASStats(u_int16_t as_id) {
  AsStats *asStats = (AsStats*)malloc(sizeof(AsStats));

  if(0) traceEvent(CONST_TRACE_WARNING, "Allocating stats for AS %d", as_id);

  if(asStats != NULL) {
    memset(asStats, 0, sizeof(AsStats));
    asStats->as_id = as_id;
    resetTrafficCounter(&asStats->outBytes);
    resetTrafficCounter(&asStats->outPkts);
    resetTrafficCounter(&asStats->inBytes);
    resetTrafficCounter(&asStats->inPkts);
    resetTrafficCounter(&asStats->selfBytes);
    resetTrafficCounter(&asStats->selfPkts);
  }

  return(asStats);
}

/* ************************************ */

static void updateASTraffic(int actualDeviceId, u_int16_t src_as_id,
			    u_int16_t dst_as_id, u_int octets) {
  AsStats *stats, *prev_stats = NULL;
  u_char found_src = 0, found_dst = 0;

  if(0)
    traceEvent(CONST_TRACE_INFO, "updateASTraffic(actualDeviceId=%d, src_as_id=%d, dst_as_id=%d, octets=%d)",
	       actualDeviceId, src_as_id, dst_as_id, octets);

  if((src_as_id == 0) && (dst_as_id == 0))
    return;

  accessMutex(&myGlobals.device[actualDeviceId].asMutex, "updateASTraffic");

  stats = myGlobals.device[actualDeviceId].asStats;

  while(stats) {
    if(stats->as_id == src_as_id) {
      stats->lastUpdate = myGlobals.actTime;
      incrementTrafficCounter(&stats->outBytes, octets), incrementTrafficCounter(&stats->outPkts, 1), stats->totPktsSinceLastRRDDump++;
      if(src_as_id == dst_as_id) {
	incrementTrafficCounter(&stats->selfBytes, octets), incrementTrafficCounter(&stats->selfPkts, 1);
	releaseMutex(&myGlobals.device[actualDeviceId].asMutex);
	return;
      }

      if(dst_as_id == 0) {
	releaseMutex(&myGlobals.device[actualDeviceId].asMutex);
	return;
      } else
	found_src = 1;

    } else if(stats->as_id == dst_as_id) {
      stats->lastUpdate = myGlobals.actTime;
      incrementTrafficCounter(&stats->inBytes, octets), incrementTrafficCounter(&stats->inPkts, 1), stats->totPktsSinceLastRRDDump++;
      if(src_as_id == dst_as_id) {
	incrementTrafficCounter(&stats->selfBytes, octets), incrementTrafficCounter(&stats->selfPkts, 1);
	releaseMutex(&myGlobals.device[actualDeviceId].asMutex);
	return;
      }

      if(src_as_id == 0) {
	releaseMutex(&myGlobals.device[actualDeviceId].asMutex);
	return;
      } else
	found_dst = 1;
    }

    if(found_src && found_dst) {
      releaseMutex(&myGlobals.device[actualDeviceId].asMutex);
      return;
    }

    if((myGlobals.actTime-stats->lastUpdate) > PARM_AS_MAXIMUM_IDLE) {
      AsStats *next = stats->next;

      if(0) traceEvent(CONST_TRACE_INFO, "Purging stats about AS %d", stats->as_id);
      if(prev_stats == NULL)
	myGlobals.device[actualDeviceId].asStats = next;
      else
	prev_stats->next = next;

      free(stats);
      stats = next;
    } else {
      prev_stats = stats;
      stats = stats->next;
    }
  } /* while */

  /* One (or both) ASs are missing */
  if((src_as_id != 0) && (!found_src)) {
    stats = allocASStats(src_as_id);
    stats->next = myGlobals.device[actualDeviceId].asStats;
    stats->lastUpdate = myGlobals.actTime;
    myGlobals.device[actualDeviceId].asStats = stats;
  }

  if((dst_as_id != 0) && (dst_as_id != src_as_id) && (!found_dst)) {
    stats = allocASStats(dst_as_id);
    stats->next = myGlobals.device[actualDeviceId].asStats;
    stats->lastUpdate = myGlobals.actTime;
    myGlobals.device[actualDeviceId].asStats = stats;
  }

  releaseMutex(&myGlobals.device[actualDeviceId].asMutex);

  /* We created the AS entry so we now need to update the AS information */
  updateASTraffic(actualDeviceId, src_as_id, dst_as_id, octets);
}

/* ************************************ */

static void processIpPkt(const u_char *bp,
			 const struct pcap_pkthdr *h,
			 u_int length,
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
  u_int hlen, ip_len,tcpDataLength, udpDataLength, off=0, tcpUdpLen, idx;
  char *proto;
  HostTraffic *srcHost=NULL, *dstHost=NULL;
  HostAddr srcAddr, dstAddr; /* Protocol Independent addresses */
  u_char forceUsingIPaddress = 0;
  struct timeval tvstrct;
  u_char *theData, found = 0;
  TrafficCounter ctr;
  ProtocolsList *protoList;
  u_short newSession = 0;
  IPSession *theSession = NULL;
  u_short isPassiveSess = 0, nonFullyRemoteSession = 1, isVoipSess = 0;

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

  if(ip6 == NULL)
    if((bp != NULL)
       && (myGlobals.device[actualDeviceId].datalink != DLT_NULL)
       && (in_cksum((const u_short *)bp, hlen, 0) != 0)
       ) {
      incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.badChecksum, 1);
      return;
    }

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
    if((!myGlobals.runningPref.dontTrustMACaddr)
       && isBroadcastAddress(&dstAddr, NULL, NULL)
       && (ether_src != NULL) && (ether_dst != NULL) /* PPP has no ethernet */
       && (memcmp(ether_dst, ethBroadcast, 6) != 0)) {
      /* forceUsingIPaddress = 1; */

      srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId);
      if(srcHost != NULL) {
	if(vlanId != NO_VLAN) srcHost->vlanId = vlanId;
	if(myGlobals.runningPref.enableSuspiciousPacketDump && (!hasWrongNetmask(srcHost))) {
	  /* Dump the first packet only */
	  char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

	  traceEvent(CONST_TRACE_WARNING, "Host %s has a wrong netmask",
		     etheraddr_string(ether_src, etherbuf));
	  dumpSuspiciousPacket(actualDeviceId);
	}

	setHostFlag(FLAG_HOST_WRONG_NETMASK, srcHost);
      }
    }
  }

  /* ******************************************************************* */
  /* ******************************************************************* */

  /*
    IMPORTANT:
    do NOT change the order of the lines below (see isBroadcastAddress call)
  */
  dstHost = lookupHost(&dstAddr, ether_dst, vlanId, 1 , 0, actualDeviceId);
  if(dstHost == NULL) {
    /* Sanity check */
    if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (2) [Low memory?]");
    lowMemoryMsgShown = 1;
    return;
  }
  srcHost = lookupHost(&srcAddr, ether_src, vlanId,
		       /*
			 Don't check for multihoming when
			 the destination address is a broadcast address
		       */
		       (!isBroadcastAddress(&dstAddr, NULL, NULL)),
		       forceUsingIPaddress, actualDeviceId);

  if(srcHost == NULL) {
    /* Sanity check */
    if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (1) [Low memory?]");
    lowMemoryMsgShown = 1;
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
  updatePacketCount(srcHost, &srcAddr, dstHost, &dstAddr, ctr, 1, actualDeviceId);

  if((!myGlobals.runningPref.dontTrustMACaddr)
     && (!myGlobals.device[actualDeviceId].dummyDevice)) {
    checkNetworkRouter(srcHost, dstHost, ether_dst, actualDeviceId);
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
	dumpSuspiciousPacket(actualDeviceId);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.malformedPkts, 1);
      }
    } else {
      proto = "TCP";
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
				  actualDeviceId);
	else
	  length = handleFragment(srcHost, dstHost, &sport, &dport,
				  ntohs(ip.ip_id), off, length,
				  ip_len - hlen, actualDeviceId);
      }

      if(srcHost->fingerprint == NULL) {
	char fingerprint[64];
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
		switch(*opt_start) {
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
	    theSession = handleSession(h, fragmented, tp.th_win,
				       srcHost, sport, dstHost,
				       dport, ntohs(ip6->ip6_plen), 0, &tp,
				       tcpDataLength,
				       theData, actualDeviceId, &newSession, 1);
	  else
	    theSession = handleSession(h, (off & 0x3fff), tp.th_win,
				       srcHost, sport, dstHost,
				       dport, ip_len, 0, &tp,
				       tcpDataLength,
				       theData, actualDeviceId, &newSession, 1);
	  if(theSession == NULL)
	    isPassiveSess = isVoipSess = 0;
	  else {
	    isPassiveSess = theSession->passiveFtpSession;
	    isVoipSess    = theSession->voipSession;
	  }
	}

	sportIdx = mapGlobalToLocalIdx(sport), dportIdx = mapGlobalToLocalIdx(dport);

	if((myGlobals.runningPref.enableOtherPacketDump) &&
	   ((sportIdx == -1) && (dportIdx == -1))) {
	  /*
	    Both source & destination port are unknown. The packet will be counted to
	    "Other TCP/UDP prot." : We dump the packet if requested
	  */
	  dumpOtherPacket(actualDeviceId);
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

	if((dport < sport)
	   && ((!((sportIdx != -1) && (dportIdx == -1)))
	       || ((sportIdx == -1) && (dportIdx != -1)))) {
	  /* traceEvent(CONST_TRACE_INFO, "[1] sportIdx(%d)=%d - dportIdx(%d)=%d", sport,
	     sportIdx, dport, dportIdx); */

	  if(handleIP(dport, srcHost, dstHost, 1, length, isPassiveSess, isVoipSess,
		      theSession != NULL ? theSession->isP2P : 0,
		      theSession != NULL ? theSession->specialHttpSession : 0,
		      actualDeviceId, newSession) == -1)
	    handleIP(sport, srcHost, dstHost, 1, length, isPassiveSess, isVoipSess,
		     theSession != NULL ? theSession->isP2P : 0,
		     theSession != NULL ? theSession->specialHttpSession : 0,
		     actualDeviceId, newSession);
	} else {
	  /*
	    traceEvent(CONST_TRACE_INFO, "[2] sportIdx(%d)=%d - dportIdx(%d)=%d",
	    sport, sportIdx, dport, dportIdx); */

	  if(handleIP(sport, srcHost, dstHost, 1, length, isPassiveSess, isVoipSess,
		      theSession != NULL ? theSession->isP2P : 0,
		      theSession != NULL ? theSession->specialHttpSession : 0,
		      actualDeviceId, newSession) == -1)
	    handleIP(dport, srcHost, dstHost, 1, length, isPassiveSess, isVoipSess,
		     theSession != NULL ? theSession->isP2P : 0,
		     theSession != NULL ? theSession->specialHttpSession : 0,
		     actualDeviceId, newSession);
	}
      }
    }

    if(ip6)
      goto end;
    else
      break;

  case IPPROTO_UDP:
    proto = "UDP";
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpBytes, length);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.totalFlows, 1);

    if(tcpUdpLen < sizeof(struct udphdr)) {
      if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING, "Malformed UDP pkt %s->%s detected (packet too short)",
		   srcHost->hostResolvedName,
		   dstHost->hostResolvedName);
	dumpSuspiciousPacket(actualDeviceId);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.malformedPkts, 1);
      }
    } else {
      udpDataLength = tcpUdpLen - sizeof(struct udphdr);
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
				  ntohs(ip6->ip6_plen), actualDeviceId);
	else
	  length = handleFragment(srcHost, dstHost, &sport, &dport,
				  ntohs(ip.ip_id), off, length,
				  ip_len - hlen, actualDeviceId);
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

        sportIdx = mapGlobalToLocalIdx(sport), dportIdx = mapGlobalToLocalIdx(dport);

        if((myGlobals.runningPref.enableOtherPacketDump) && ((sportIdx == -1) && (dportIdx == -1))) {
	  /*
	    Both source & destination port are unknown.
	    The packet will be counted to "Other TCP/UDP prot.".
	    We dump the packet if requested */
	  dumpOtherPacket(actualDeviceId);
	}

	if(nonFullyRemoteSession) {
	  /* There is no session structure returned for UDP sessions */
	  if(ip6)
	    theSession =  handleSession(h, fragmented, 0,
					srcHost, sport, dstHost,
					dport, ntohs(ip6->ip6_plen), 0, NULL,
					udpDataLength,
					(u_char*)(bp+hlen+sizeof(struct udphdr)),
					actualDeviceId, &newSession, 1);
	  else
	    theSession =  handleSession(h, (off & 0x3fff), 0,
					srcHost, sport, dstHost,
					dport, ip_len, 0, NULL, udpDataLength,
					(u_char*)(bp+hlen+sizeof(struct udphdr)),
					actualDeviceId, &newSession, 1);
	}

	isPassiveSess = 0;

	if(theSession == NULL)
	  isVoipSess = 0;
	else
	  isVoipSess = theSession->voipSession;

	newSession = 1; /* Trick to account flows anyway */

	if((sport == IP_TCP_PORT_SKYPE) || (dport == IP_TCP_PORT_SKYPE)) {
	  if(theSession) theSession->voipSession = 1;
	  isVoipSess = 1;

	  setHostFlag(FLAG_HOST_TYPE_SVC_VOIP_CLIENT, srcHost);
	  setHostFlag(FLAG_HOST_TYPE_SVC_VOIP_CLIENT, dstHost);
	}

        /* Handle UDP traffic like TCP, above -
	   That is: if we know about the lower# port, even if it's the destination,
	   classify the traffic that way.
	   (BMS 12-2001)
	*/
        if(dport < sport) {
	  if(handleIP(dport, srcHost, dstHost, 1, length, isPassiveSess, isVoipSess,
		      0, 0, actualDeviceId, newSession) == -1)
	    handleIP(sport, srcHost, dstHost, 1, length, isPassiveSess, isVoipSess,
		     0, 0, actualDeviceId, newSession);
        } else {
	  if(handleIP(sport, srcHost, dstHost, 1, length, isPassiveSess, isVoipSess,
		      0, 0, actualDeviceId, newSession) == -1)
	    handleIP(dport, srcHost, dstHost, 1, length, isPassiveSess, isVoipSess,
		     0, 0, actualDeviceId, newSession);
        }
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
	dumpSuspiciousPacket(actualDeviceId);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.malformedPkts, 1);
      }
    } else {
      proto = "ICMP";
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
	  dumpSuspiciousPacket(actualDeviceId);
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
	    dumpSuspiciousPacket(actualDeviceId);
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
	if(myGlobals.runningPref.enableSuspiciousPacketDump) dumpSuspiciousPacket(actualDeviceId);
      }
    }
    break;

  case IPPROTO_ICMPV6:
    if(ip6 == NULL) {
      if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	traceEvent(CONST_TRACE_WARNING,"Protocol violation: ICMPv6 protocol in IPv4 packet: %s->%s",
		   srcHost->hostResolvedName,
		   dstHost->hostResolvedName);
	dumpSuspiciousPacket(actualDeviceId);
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
	dumpSuspiciousPacket(actualDeviceId);

	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->malformedPktsSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->malformedPktsRcvd, srcHost, actualDeviceId);
      }
    } else {
      proto = "ICMPv6";
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
	  dumpSuspiciousPacket(actualDeviceId);
	}
      }

      /* ************************************************************* */

      if(icmp6Pkt.icmp6_type <= ICMP6_MAXTYPE) {
	short dumpPacket = 1;

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
	  dumpPacket = 0;
	  break;
	case ICMP6_DST_UNREACH:
	case ND_REDIRECT:
	case ICMP6_TIME_EXCEEDED:
	case ICMP6_PARAM_PROB:
	case ICMP6_NI_QUERY:
	case ICMP6_NI_REPLY:
	  if(myGlobals.runningPref.enableSuspiciousPacketDump) {
	    dumpSuspiciousPacket(actualDeviceId);
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
	HostTraffic *router = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId);
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
	if(myGlobals.runningPref.enableSuspiciousPacketDump) dumpSuspiciousPacket(actualDeviceId);
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

	  allocHostTrafficCounterMemory(srcHost, ipProtosList, (size_t)myGlobals.numIpProtosToMonitor*sizeof(ProtoTrafficInfo**));
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
      proto = "IP (Other)";
      incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherIpBytes, length);
      sport = dport = 0;
      if(myGlobals.runningPref.enableOtherPacketDump)
	dumpOtherPacket(actualDeviceId);

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

/* ************************************ */

#undef DEBUG

void queuePacket(u_char *_deviceId,
		 const struct pcap_pkthdr *h,
		 const u_char *p) {
  int len, deviceId, actDeviceId;

  /* ***************************
     - If the queue is full then wait until a slot is freed

     - If the queue is getting full then periodically wait
     until a slot is freed
     **************************** */

#ifdef MAX_PROCESS_BUFFER
  if(myGlobals.queueBufferInit == 0) {
    myGlobals.queueBufferCount = 0;
    myGlobals.queueBufferInit = 1;
    memset(&myGlobals.queueBuffer, 0, sizeof(myGlobals.queueBuffer));
  }
#endif

  myGlobals.receivedPackets++;

  if((p == NULL) || (h == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "Invalid packet received. Skipped.");
  }

#ifdef WIN32_DEMO
  if(myGlobals.receivedPackets >= MAX_NUM_PACKETS)
    return;
#endif

  if(myGlobals.ntopRunState > FLAG_NTOPSTATE_RUN) return;

  deviceId = (int)((long)_deviceId);
  actDeviceId = getActualInterface(deviceId);
  incrementTrafficCounter(&myGlobals.device[actDeviceId].receivedPkts, 1);

  /* We assume that if there's a packet to queue for the sFlow interface
     then this has been queued by the sFlow plugins, while it was
     probably handling a queued packet */

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "queuePacket: got packet from %s (%d)",
	     myGlobals.device[deviceId].name, deviceId);
#endif

  /* We don't sample on sFlow sampled interfaces */
  if(myGlobals.device[deviceId].sflowGlobals == NULL) {
    if(myGlobals.device[actDeviceId].samplingRate > 1) {
      if(myGlobals.device[actDeviceId].droppedSamples < myGlobals.device[actDeviceId].samplingRate) {
	myGlobals.device[actDeviceId].droppedSamples++;
	return; /* Not enough samples received */
      } else
	myGlobals.device[actDeviceId].droppedSamples = 0;
    }
  }

  if(myGlobals.runningPref.dontTrustMACaddr && (h->len < 60)) {
    /* Filter out noise */
    updateDevicePacketStats(h->len, actDeviceId);
    return;
  }

  if(tryLockMutex(&myGlobals.device[deviceId].packetProcessMutex, "queuePacket") == 0) {
    /* Locked so we can process the packet now */
    u_char p1[MAX_PACKET_LEN];

    myGlobals.receivedPacketsProcessed++;

    len = h->caplen;

    if(h->caplen >= MAX_PACKET_LEN) {
      if(h->caplen > myGlobals.device[deviceId].mtuSize) {
#ifndef WIN32
	traceEvent(CONST_TRACE_WARNING, "packet truncated (%d->%d)",
		   h->len, MAX_PACKET_LEN);
#endif
      }

      ((struct pcap_pkthdr*)h)->caplen = len = MAX_PACKET_LEN-1;
    }

    memcpy(p1, p, len);

    processPacket(_deviceId, h, p1);
    releaseMutex(&myGlobals.device[deviceId].packetProcessMutex);
    return;
  }

  /*
    If we reach this point it means that somebody was already
    processing a packet so we need to queue it.
  */
  if(myGlobals.device[deviceId].packetQueueLen >= CONST_PACKET_QUEUE_LENGTH) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Dropping packet [packet queue=%d/max=%d][id=%d]",
	       myGlobals.device[deviceId].packetQueueLen, myGlobals.maxPacketQueueLen, deviceId);
#endif

    myGlobals.receivedPacketsLostQ++;
    incrementTrafficCounter(&myGlobals.device[getActualInterface(deviceId)].droppedPkts, 1);
    ntop_conditional_sched_yield(); /* Allow other threads (dequeue) to run */
    sleep(1);
  } else {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "About to queue packet... ");
#endif
    accessMutex(&myGlobals.device[deviceId].packetQueueMutex, "queuePacket");
    myGlobals.receivedPacketsQueued++;
    memcpy(&myGlobals.device[deviceId].packetQueue[myGlobals.device[deviceId].packetQueueHead].h,
	   h, sizeof(struct pcap_pkthdr));
    memset(myGlobals.device[deviceId].packetQueue[myGlobals.device[deviceId].packetQueueHead].p, 0,
	   sizeof(myGlobals.device[deviceId].packetQueue[myGlobals.device[deviceId].packetQueueHead].p));
    /* Just to be safe */
    len = h->caplen;
    memcpy(myGlobals.device[deviceId].packetQueue[myGlobals.device[deviceId].packetQueueHead].p, p, len);
    myGlobals.device[deviceId].packetQueue[myGlobals.device[deviceId].packetQueueHead].h.caplen = len;

    myGlobals.device[deviceId].packetQueue[myGlobals.device[deviceId].packetQueueHead].deviceId =
      (int)((long)((void*)_deviceId));
    myGlobals.device[deviceId].packetQueueHead = (myGlobals.device[deviceId].packetQueueHead+1)
      % CONST_PACKET_QUEUE_LENGTH;
    myGlobals.device[deviceId].packetQueueLen++;
    if(myGlobals.device[deviceId].packetQueueLen > myGlobals.device[deviceId].maxPacketQueueLen)
      myGlobals.device[deviceId].maxPacketQueueLen = myGlobals.device[deviceId].packetQueueLen;
    releaseMutex(&myGlobals.device[deviceId].packetQueueMutex);
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Queued packet... [packet queue=%d/max=%d]",
	       myGlobals.device[deviceId].packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

#ifdef DEBUG_THREADS
    traceEvent(CONST_TRACE_INFO, "+ [packet queue=%d/max=%d]",
	       myGlobals.device[deviceId].packetQueueLen, myGlobals.maxPacketQueueLen);
#endif
  }

  signalCondvar(&myGlobals.device[deviceId].queueCondvar);

  ntop_conditional_sched_yield(); /* Allow other threads (dequeue) to run */
}

/* ************************************ */

void cleanupPacketQueue(void) {
  ; /* Nothing to do */
}

/* ************************************ */

void* dequeuePacket(void* _deviceId) {
  u_int deviceId = (u_int)((long)_deviceId);
  struct pcap_pkthdr h;
  u_char p[MAX_PACKET_LEN];

  traceEvent(CONST_TRACE_INFO,
             "THREADMGMT[t%lu]: NPA: network packet analyzer (packet processor) thread running [p%d]",
             (long unsigned int)pthread_self(), getpid());

  /* Don't bother stalling until RUN, start grabbing packets NOW ... */

  while(myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Waiting for packet...");
#endif

    while((myGlobals.device[deviceId].packetQueueLen == 0) &&
	  (myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN) /* Courtesy of Wies-Software <wies@wiessoft.de> */) {
      waitCondvar(&myGlobals.device[deviceId].queueCondvar);
    }

    if(myGlobals.ntopRunState > FLAG_NTOPSTATE_RUN) break;

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Got packet...");
#endif
    accessMutex(&myGlobals.device[deviceId].packetQueueMutex, "dequeuePacket");
    memcpy(&h, &myGlobals.device[deviceId].packetQueue[myGlobals.device[deviceId].packetQueueTail].h,
	   sizeof(struct pcap_pkthdr));

    deviceId = myGlobals.device[deviceId].packetQueue[myGlobals.device[deviceId].packetQueueTail].deviceId;

    /* This code should be changed ASAP. It is a bad trick that avoids ntop to
       go beyond packet boundaries (L.Deri 17/03/2003)

       1. h->len is truncated
       2. MAX_PACKET_LEN should probably be removed
       3. all the functions must check that they are not going beyond packet boundaries
    */
    if((h.caplen != h.len)
       && (myGlobals.device[deviceId].sflowGlobals == NULL) /* This warning is normal for sFlow */
       && (myGlobals.runningPref.enablePacketDecoding /* Courtesy of Ken Beaty <ken@ait.com> */))
      traceEvent (CONST_TRACE_WARNING, "dequeuePacket: caplen %d != len %d\n", h.caplen, h.len);

    memcpy(p, myGlobals.device[deviceId].packetQueue[myGlobals.device[deviceId].packetQueueTail].p, MAX_PACKET_LEN);

    if(h.len > MAX_PACKET_LEN) {
      traceEvent(CONST_TRACE_WARNING, "packet truncated (%d->%d)", h.len, MAX_PACKET_LEN);
      h.len = MAX_PACKET_LEN;
    }

    myGlobals.device[deviceId].packetQueueTail = (myGlobals.device[deviceId].packetQueueTail+1) % CONST_PACKET_QUEUE_LENGTH;
    myGlobals.device[deviceId].packetQueueLen--;
    releaseMutex(&myGlobals.device[deviceId].packetQueueMutex);
#ifdef DEBUG_THREADS
    traceEvent(CONST_TRACE_INFO, "- [packet queue=%d/max=%d]", myGlobals.device[deviceId].packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Processing packet... [packet queue=%d/max=%d][id=%d]",
	       myGlobals.device[deviceId].packetQueueLen, myGlobals.maxPacketQueueLen, deviceId);
#endif

    myGlobals.actTime = time(NULL);
    accessMutex(&myGlobals.device[deviceId].packetProcessMutex, "dequeuePacket");
    processPacket((u_char*)((long)deviceId), &h, p);
    releaseMutex(&myGlobals.device[deviceId].packetProcessMutex);
  }

  myGlobals.device[deviceId].dequeuePacketThreadId = 0;

  traceEvent(CONST_TRACE_INFO,
             "THREADMGMT[t%lu]: NPA: network packet analyzer (%s) thread terminated [p%d]",
             (long unsigned int)pthread_self(),
	     myGlobals.device[deviceId].humanFriendlyName, getpid());

  return(NULL);
}

/* ************************************ */

static void flowsProcess(const struct pcap_pkthdr *h, const u_char *p, int deviceId) {
  FlowFilterList *list = myGlobals.flowsList;

  while(list != NULL) {
#ifdef DEBUG
    if(!list->pluginStatus.activePlugin)
      traceEvent(CONST_TRACE_NOISY, "%s inactive", list->flowName);
    else if(list->fcode[deviceId].bf_insns == NULL)
      traceEvent(CONST_TRACE_NOISY, "%s no filter", list->flowName);
#endif

    if((list->pluginStatus.activePlugin) &&
       (list->fcode[deviceId].bf_insns != NULL)) {
#ifdef DEBUG
      {
        struct ether_header *ep;
        u_int16_t et=0, et8021q=0;
        ep = (struct ether_header *)p;
        et = ntohs(ep->ether_type);
        if(et == ETHERTYPE_802_1Q) {
          et8021q = et;
          ep = (struct ether_header *)(p+4);
          et = ntohs(ep->ether_type);
        }
        traceEvent(CONST_TRACE_NOISY, "%smatch on %s for '%s' %s0x%04x-%s-%d/%d",
                   bpf_filter(list->fcode[deviceId].bf_insns, (u_char*)p, h->len, h->caplen) ?
		   "" : "No ",
                   myGlobals.device[deviceId].name,
                   list->flowName,
                   et8021q == ETHERTYPE_802_1Q ? "(802.1q) " : "",
                   et,
                   et == ETHERTYPE_IP ? "IPv4" :
		   et == ETHERTYPE_IPv6 ? "IPv6" :
		   et == ETHERTYPE_ARP ? "ARP" :
		   et == ETHERTYPE_REVARP ? "RARP" :
		   "other",
                   h->len, h->caplen);
      }
#endif
      if(bpf_filter(list->fcode[deviceId].bf_insns, (u_char*)p, h->len, h->caplen)) {
        incrementTrafficCounter(&list->bytes, h->len);
        incrementTrafficCounter(&list->packets, 1);
        if(list->pluginStatus.pluginPtr != NULL) {
          void(*pluginFunct)(u_char*, const struct pcap_pkthdr*, const u_char*);

	  pluginFunct = (void(*)(u_char *_deviceId, const struct pcap_pkthdr*,
				 const u_char*))list->pluginStatus.pluginPtr->pluginFunct;
	  pluginFunct((u_char*)&deviceId, h, p);
        }
      }
    }

    list = list->next;
  }
}

/* ************************************ */

static void addNonIpTrafficInfo(HostTraffic *el, u_int16_t proto,
				u_short len, u_int direction) {
  NonIpProtoTrafficInfo *nonIp;
  int numIterations;

  if(el->nonIpProtoTrafficInfos == NULL)
    goto  notFoundProto;
  else
    nonIp = el->nonIpProtoTrafficInfos;

  numIterations = 0;

  while(nonIp != NULL) {
    if(nonIp->protocolId == proto)
      break;

    numIterations++;

    if(numIterations == MAX_NUM_NON_IP_PROTO_TRAFFIC_INFO)
      return; /* Too many protocols */

    nonIp = nonIp->next;
  }

  if(nonIp == NULL) {
  notFoundProto:
    /* Protocol not found */
    nonIp = (NonIpProtoTrafficInfo*)calloc(1, sizeof(NonIpProtoTrafficInfo));
    if(nonIp == NULL) return;
    nonIp->next = el->nonIpProtoTrafficInfos;
    el->nonIpProtoTrafficInfos = nonIp;
    nonIp->protocolId = proto;
  }

  if(direction == 0)
    incrementTrafficCounter(&nonIp->sentPkts, 1), incrementTrafficCounter(&nonIp->sentBytes, len);
  else
    incrementTrafficCounter(&nonIp->rcvdPkts, 1), incrementTrafficCounter(&nonIp->rcvdBytes, len);
}

/* ************************************ */

void updateDevicePacketStats(u_int length, int actualDeviceId) {
  if(length <= 64)        incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo64, 1);
  else if(length <= 128)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo128, 1);
  else if(length <= 256)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo256, 1);
  else if(length <= 512)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo512, 1);
  else if(length <= 1024) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo1024, 1);
  else if(length <= 1518) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo1518, 1);
#ifdef MAKE_WITH_JUMBO_FRAMES
  else if(length <= 2500) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo2500, 1);
  else if(length <= 6500) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo6500, 1);
  else if(length <= 9000) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.upTo9000, 1);
  else                   incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.above9000, 1);
#else
  else                   incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.above1518, 1);
#endif

  if((myGlobals.device[actualDeviceId].rcvdPktStats.shortest.value == 0)
     || (myGlobals.device[actualDeviceId].rcvdPktStats.shortest.value > length))
    myGlobals.device[actualDeviceId].rcvdPktStats.shortest.value = length;

  if(myGlobals.device[actualDeviceId].rcvdPktStats.longest.value < length)
    myGlobals.device[actualDeviceId].rcvdPktStats.longest.value = length;
}

/* ***************************************************** */

void dumpSuspiciousPacket(int actualDeviceId) {
  if(myGlobals.device[actualDeviceId].pcapErrDumper != NULL) {
    pcap_dump((u_char*)myGlobals.device[actualDeviceId].pcapErrDumper, h_save, p_save);
    traceEvent(CONST_TRACE_INFO, "Dumped %d bytes suspicious packet", h_save->caplen);
  }
}

/* ***************************************************** */

void dumpOtherPacket(int actualDeviceId) {
  if(myGlobals.device[actualDeviceId].pcapOtherDumper != NULL)
    pcap_dump((u_char*)myGlobals.device[actualDeviceId].pcapOtherDumper, h_save, p_save);
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
  u_short eth_type=0;
  /* Token-Ring Strings */
  struct tokenRing_llc *trllc;
  unsigned char ipxBuffer[128];
  int deviceId, actualDeviceId;
  u_int16_t vlanId=NO_VLAN;
  static time_t lastUpdateThptTime = 0;
#ifdef LINUX
  AnyHeader *anyHeader;
#endif
#ifdef MAX_PROCESS_BUFFER
  struct timeval pktStartOfProcessing,
    pktEndOfProcessing;
#endif

#ifdef MEMORY_DEBUG
#ifdef MEMORY_DEBUG_UNLIMITED
#warning MEMORY_DEBUG defined for UNLIMITED usage!
#else

#ifdef MEMORY_DEBUG_PACKETS
  {
    static long numPkt=0;
    if(++numPkt >= MEMORY_DEBUG_PACKETS) {
      traceEvent(CONST_TRACE_ALWAYSDISPLAY,
		 "NOTE: ntop shutting down - memory debug packet limit (%d) reached",
		 MEMORY_DEBUG_PACKETS);
      cleanup(1);
    }
  }
#endif /* MEMORY_DEBUG_PACKETS */

#ifdef MEMORY_DEBUG_SECONDS
  {
    static time_t memoryDebugAbortTime=0;
    if(memoryDebugAbortTime == 0) {
      memoryDebugAbortTime = time(NULL) + MEMORY_DEBUG_SECONDS;
    } else if(time(NULL) > memoryDebugAbortTime) {
      traceEvent(CONST_TRACE_ALWAYSDISPLAY,
		 "NOTE: ntop shutting down - memory debug abort time reached");
      cleanup(1);
    }
  }
#endif /* MEMORY_DEBUG_SECONDS */

#endif /* MEMORY_DEBUG_UNLIMITED */
#endif /* MEMORY_DEBUG */

  if(myGlobals.ntopRunState > FLAG_NTOPSTATE_RUN)
    return;

  /*
    This allows me to fetch the time from
    the captured packet instead of calling
    time(NULL).
  */
  myGlobals.actTime = h->ts.tv_sec;

  deviceId = (int)((long)_deviceId);

  actualDeviceId = getActualInterface(deviceId);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "deviceId=%d - actualDeviceId=%ld", deviceId, actualDeviceId);
#endif

#ifdef MAX_PROCESS_BUFFER
  {
    float elapsed;
    gettimeofday(&pktStartOfProcessing, NULL);
    elapsed = timeval_subtract(pktStartOfProcessing, h->ts);
    if(elapsed < 0) elapsed = 0;
    myGlobals.queueBuffer[++myGlobals.queueBufferCount & (MAX_PROCESS_BUFFER - 1)] = elapsed;
    if((myGlobals.device[actualDeviceId].ethernetPkts.value > 100) && (elapsed > myGlobals.qmaxDelay))
      myGlobals.qmaxDelay = elapsed;
  }
#endif

  h_save = h, p_save = p;

#ifdef DEBUG
  if(myGlobals.pcap_file_list != NULL) {
    traceEvent(CONST_TRACE_INFO, ".");
    fflush(stdout);
  }
#endif

  updateDevicePacketStats(length, actualDeviceId);

  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ethernetPkts, 1);
  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ethernetBytes, h->len);

  if(myGlobals.runningPref.mergeInterfaces && actualDeviceId != deviceId)
    incrementTrafficCounter(&myGlobals.device[deviceId].ethernetPkts, 1);

  if(myGlobals.device[actualDeviceId].pcapDumper != NULL)
    pcap_dump((u_char*)myGlobals.device[actualDeviceId].pcapDumper, h, p);

  if((myGlobals.device[deviceId].mtuSize != CONST_UNKNOWN_MTU) &&
     (length > myGlobals.device[deviceId].mtuSize) ) {
    /* Sanity check */
    if(myGlobals.runningPref.enableSuspiciousPacketDump) {
      traceEvent(CONST_TRACE_WARNING, "Packet # %u too long (len = %u)!",
		 (unsigned int)myGlobals.device[deviceId].ethernetPkts.value,
		 (unsigned int)length);
      dumpSuspiciousPacket(actualDeviceId);
    }

    /* Fix below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
    length = myGlobals.device[deviceId].mtuSize;
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.tooLong, 1);
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "actualDeviceId = %d", actualDeviceId);
#endif

  /* Note: The code below starts by assuming that if we haven't captured at
   * least an Ethernet frame header's worth of bytes we drop the packet.
   * This might be a bad assumption - why aren't we using the DLT_ derived fields?
   * e.g.: hlen = myGlobals.device[deviceId].headerSize;
   * Also, we probably should account for these runt packets - both count the
   * # of packets and the associated # of bytes.
   */

  hlen = (myGlobals.device[deviceId].datalink == DLT_NULL) ? CONST_NULL_HDRLEN : sizeof(struct ether_header);

  if(!myGlobals.initialSniffTime && (myGlobals.pcap_file_list != NULL)) {
    myGlobals.initialSniffTime = h->ts.tv_sec;
    myGlobals.device[deviceId].lastThptUpdate = myGlobals.device[deviceId].lastMinThptUpdate =
      myGlobals.device[deviceId].lastHourThptUpdate = myGlobals.device[deviceId].lastFiveMinsThptUpdate = myGlobals.initialSniffTime;
  }

  memcpy(&myGlobals.lastPktTime, &h->ts, sizeof(myGlobals.lastPktTime));

  if(caplen >= hlen) {
    HostTraffic *srcHost=NULL, *dstHost=NULL;

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
	      return;
	    }
	  }
	}
      }
      break;

#ifdef LINUX
    case DLT_ANY:  /* Linux 'any' device */
      anyHeader = (AnyHeader*)p;
      length -= sizeof(AnyHeader); /* don't count nullhdr */
      eth_type = ntohs(anyHeader->protoType);
#if PACKET_DEBUG
      printf("pktType:        0x%x\n", ntohs(anyHeader->pktType));
      printf("llcAddressType: 0x%x\n", ntohs(anyHeader->llcAddressType));
      printf("llcAddressLen:  0x%x\n", ntohs(anyHeader->llcAddressLen));
      printf("eth_type:       0x%x\n", eth_type);
#endif
      ether_src = ether_dst = myGlobals.dummyEthAddress;
      processIpPkt(p+sizeof(AnyHeader), h, length, ether_src, ether_dst, actualDeviceId, vlanId);
      break;
#endif

    case DLT_NULL: /* loopaback interface */
      /*
	Support for ethernet headerless interfaces (e.g. lo0)
	Courtesy of Martin Kammerhofer <dada@sbox.tu-graz.ac.at>
      */

      length -= CONST_NULL_HDRLEN; /* don't count nullhdr */

      /* All this crap is due to the old little/big endian story... */
      if(((p[0] == 0) && (p[1] == 0) && (p[2] == 8) && (p[3] == 0))
	 || ((p[0] == 2) && (p[1] == 0) && (p[2] == 0) && (p[3] == 0)) /* OSX */)
	eth_type = ETHERTYPE_IP;
      else if(((p[0] == 0) && (p[1] == 0) && (p[2] == 0x86) && (p[3] == 0xdd))
	      || ((p[0] == 0x1E) && (p[1] == 0) && (p[2] == 0) && (p[3] == 0)) /* OSX */)
	eth_type = ETHERTYPE_IPv6;
      else {
	// traceEvent(CONST_TRACE_INFO, "[%d][%d][%d][%d]", p[0], p[1], p[2], p[3]);
      }
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

#if 0 /* Handled by DLT_ANY */
      /* PPPoE patch courtesy of Stefano Picerno <stefanopp@libero.it> */
#ifdef LINUX
    case DLT_LINUX_SLL: /* Linux capture interface */
      length = h->len;
      length -= SLL_HDR_LEN;
      ether_src = ether_dst = NULL;
      processIpPkt(p+ SLL_HDR_LEN , h, length, ether_src, ether_dst, actualDeviceId, vlanId);
      break;
#endif
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
	hlen += 4; /* Skip the 802.1q header */

        if(myGlobals.device[deviceId].hasVLANs != TRUE) {
          myGlobals.device[deviceId].hasVLANs = TRUE;
          myGlobals.haveVLANs = TRUE;
#ifndef MAKE_WITH_JUMBO_FRAMES
          traceEvent(CONST_TRACE_NOISY,
                     "Device %s(%d) MTU adjusted for 802.1q VLAN",
                     myGlobals.device[deviceId].name,
                     deviceId);
          extend8021Qmtu();
          myGlobals.device[deviceId].rcvdPktStats.tooLong.value = 0l;
#endif
        }
      } else if(eth_type == ETHERTYPE_MPLS) /* MPLS */ {
	char bos; /* bottom_of_stack */
	u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN];
	int numMplsLabels = 0;

	memset(mplsLabels, 0, sizeof(mplsLabels));
	bos = 0;
	while(bos == 0) {
	  memcpy(&mplsLabels[numMplsLabels], p+hlen, MPLS_LABEL_LEN);

	  bos = (mplsLabels[numMplsLabels][2] & 0x1), hlen += 4, numMplsLabels++;
	  if((hlen > caplen) || (numMplsLabels >= MAX_NUM_MPLS_LABELS))
	    return; /* bad packet */
	}

	eth_type = ETHERTYPE_IP;
      } else if((ether_dst[0] == 0x01)    && (ether_dst[1] == 0x00)
		&& (ether_dst[2] == 0x0C) && (ether_dst[3] == 0x00)
		&& (ether_dst[4] == 0x00) && (ether_dst[5] == 0x00)) {
	/*
	  Cisco InterSwitch Link (ISL) Protocol

	  This is basically the Cisco proprietary VLAN tagging (vs. the standard 802.1q)
	  http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm
	*/
	IslHeader islHdr;

	memcpy(&islHdr, p, sizeof(IslHeader));
	vlanId = ntohs(islHdr.vlanId);
	hlen = sizeof(IslHeader); /* Skip the ISL header */
	memcpy(&ehdr, p+hlen, sizeof(struct ether_header));
	hlen += sizeof(struct ether_header);
	ether_src = ESRC(&ehdr), ether_dst = EDST(&ehdr);
	eth_type = ntohs(ehdr.ether_type);
      }
    } /* switch(myGlobals.device[deviceId].datalink) */

    if((myGlobals.device[deviceId].datalink != DLT_PPP)
       && (myGlobals.device[deviceId].datalink != DLT_RAW)
       && (myGlobals.device[deviceId].datalink != DLT_ANY)) {
      if((!myGlobals.runningPref.dontTrustMACaddr) && (eth_type == 0x8137)) {
	/* IPX */
	IPXpacket ipxPkt;

	srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId);
	if(srcHost == NULL) {
	  /* Sanity check */
	  if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (5) [Low memory?]");
	  lowMemoryMsgShown = 1;
	  return;
	} else {
	  lockHostsHashMutex(srcHost, "processPacket-src");
	}

	dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId);
	if(dstHost == NULL) {
	  /* Sanity check */
	  if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (6) [Low memory?]");
	  unlockHostsHashMutex(srcHost);
	  lowMemoryMsgShown = 1;
	  return;
	} else {
	  lockHostsHashMutex(dstHost, "processPacket-dst");
	}

	if(vlanId != NO_VLAN) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }

	memcpy((char *)&ipxPkt, (char *)p+sizeof(struct ether_header), sizeof(IPXpacket));

	allocHostTrafficCounterMemory(srcHost, nonIPTraffic, sizeof(NonIPTraffic));
	allocHostTrafficCounterMemory(dstHost, nonIPTraffic, sizeof(NonIPTraffic));

	if(ntohs(ipxPkt.dstSocket) == 0x0452) {
	  /* SAP */
	  int displ = sizeof(struct ether_header);
	  p1 = p+displ;
	  length -= displ;
	  goto handleIPX;
	} else {
	  TrafficCounter ctr;

	  if((srcHost->nonIPTraffic == NULL) || (dstHost->nonIPTraffic == NULL)) return;

	  incrementHostTrafficCounter(srcHost, nonIPTraffic->ipxSent, length);
	  incrementHostTrafficCounter(dstHost, nonIPTraffic->ipxRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipxBytes, length);

	  ctr.value = length;
	  /*
	    Even if this is IPX (i.e. no IP) the hostIpAddress field is
	    fine because it is not used in this special case and I need
	    a placeholder here.
	  */
	  updatePacketCount(srcHost, &srcHost->hostIpAddress, dstHost, &dstHost->hostIpAddress, ctr, 1, actualDeviceId);
	}
      } else if((myGlobals.device[deviceId].datalink == DLT_IEEE802) && (eth_type < ETHERMTU)) {
	TrafficCounter ctr;

	trp = (struct tokenRing_header*)orig_p;
	ether_src = (u_char*)trp->trn_shost, ether_dst = (u_char*)trp->trn_dhost;
	srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId);
	if(srcHost == NULL) {
	  /* Sanity check */
	  if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (7) [Low memory?]");
	  lowMemoryMsgShown = 1;
	  return;
	} else {
	  lockHostsHashMutex(srcHost, "processPacket-src-2");
	}

	dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId);
	if(dstHost == NULL) {
	  /* Sanity check */
	  if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (8) [Low memory?]");
	  unlockHostsHashMutex(srcHost);
	  lowMemoryMsgShown = 1;
	  return;
	} else {
	  lockHostsHashMutex(dstHost, "processPacket-dst-2");
	}

	if(vlanId != NO_VLAN) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }

	allocHostTrafficCounterMemory(srcHost, nonIPTraffic, sizeof(NonIPTraffic));
	allocHostTrafficCounterMemory(dstHost, nonIPTraffic, sizeof(NonIPTraffic));
	if((srcHost->nonIPTraffic == NULL) || (dstHost->nonIPTraffic == NULL)) return;

	incrementHostTrafficCounter(srcHost, nonIPTraffic->otherSent, length);
	incrementHostTrafficCounter(dstHost, nonIPTraffic->otherRcvd, length);
	incrementUnknownProto(srcHost, 0 /* sent */, eth_type /* eth */, 0 /* dsap */, 0 /* ssap */, 0 /* ip */);
	incrementUnknownProto(dstHost, 1 /* rcvd */, eth_type /* eth */, 0 /* dsap */, 0 /* ssap */, 0 /* ip */);
	if(myGlobals.runningPref.enableOtherPacketDump)
	  dumpOtherPacket(actualDeviceId);

	ctr.value = length;

	/*
	  Even if this is probably not IP the hostIpAddress field is
	  fine because it is not used in this special case and I need
	  a placeholder here.
	*/
	updatePacketCount(srcHost, &srcHost->hostIpAddress, dstHost,
			  &dstHost->hostIpAddress, ctr, 1, actualDeviceId);
      } else if((myGlobals.device[deviceId].datalink != DLT_IEEE802)
		&& (eth_type <= ETHERMTU) && (length > 3)) {
	/* The code below has been taken from tcpdump */
	u_char sap_type;
	struct llc llcHeader;
	char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

	if((ether_dst != NULL)
	   && (!myGlobals.runningPref.dontTrustMACaddr)
	   && (strcmp(etheraddr_string(ether_dst, etherbuf), "FF:FF:FF:FF:FF:FF") == 0)
	   && (p[sizeof(struct ether_header)] == 0xff)
	   && (p[sizeof(struct ether_header)+1] == 0xff)
	   && (p[sizeof(struct ether_header)+4] == 0x0)) {
	  /* IPX */

	  srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId);
	  if(srcHost == NULL) {
	    /* Sanity check */
	    if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (9) [Low memory?]");
	    lowMemoryMsgShown = 1;
	    return;
	  } else {
	    lockHostsHashMutex(srcHost, "processPacket-src-3");
	  }

	  dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId);
	  if(dstHost == NULL) {
	    /* Sanity check */
	    if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (10) [Low memory?]");
	    unlockHostsHashMutex(srcHost);
	    lowMemoryMsgShown = 1;
	    return;
	  } else {
	    lockHostsHashMutex(dstHost, "processPacket-dst-3");
	  }

	  if(vlanId != NO_VLAN) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }

	  allocHostTrafficCounterMemory(srcHost, nonIPTraffic, sizeof(NonIPTraffic));
	  allocHostTrafficCounterMemory(dstHost, nonIPTraffic, sizeof(NonIPTraffic));
	  if((srcHost->nonIPTraffic == NULL) || (dstHost->nonIPTraffic == NULL)) return;

	  incrementHostTrafficCounter(srcHost, nonIPTraffic->ipxSent, length);
	  incrementHostTrafficCounter(dstHost, nonIPTraffic->ipxRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipxBytes, length);
	} else if(!myGlobals.runningPref.dontTrustMACaddr) {
	  /* MAC addresses are meaningful here */
	  srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId);
	  dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId);

	  if((srcHost == NULL) || (dstHost == NULL)) return;

	  allocHostTrafficCounterMemory(srcHost, nonIPTraffic, sizeof(NonIPTraffic));
	  allocHostTrafficCounterMemory(dstHost, nonIPTraffic, sizeof(NonIPTraffic));
	  if((srcHost->nonIPTraffic == NULL) || (dstHost->nonIPTraffic == NULL)) return;

	  if((srcHost != NULL) && (dstHost != NULL)) {
	    TrafficCounter ctr;
	    int llcLen;
	    lockHostsHashMutex(srcHost, "processPacket-src-4");
	    lockHostsHashMutex(dstHost, "processPacket-dst-4");
	    if(vlanId != NO_VLAN) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }
	    p1 = (u_char*)(p+hlen);

	    /* Watch out for possible alignment problems */
	    memcpy(&llcHeader, (char*)p1, (llcLen = min(length, sizeof(llcHeader))));

	    sap_type = llcHeader.ssap & ~CONST_LLC_GSAP;
	    llcsap_string(sap_type);

	    if((sap_type == 0xAA /* SNAP */)
	       && (llcHeader.ctl.snap_ether.snap_orgcode[0] == 0x0)
	       && (llcHeader.ctl.snap_ether.snap_orgcode[1] == 0x0)
	       && (llcHeader.ctl.snap_ether.snap_orgcode[2] == 0xc) /* 0x00000C = Cisco */
	       && (llcHeader.ctl.snap_ether.snap_ethertype[0] == 0x20)
	       && (llcHeader.ctl.snap_ether.snap_ethertype[1] == 0x00) /* 0x2000 Cisco Discovery Protocol */
	       ) {
	      u_char *cdp;
	      int cdp_idx = 0;

	      cdp = (u_char*)(p+hlen+llcLen);

	      if(cdp[cdp_idx] == 0x02) {
		/* CDP v2 */
		struct cdp_element {
		  u_int16_t cdp_type;
		  u_int16_t cdp_len;
		  // u_char cdp_content[255];
		};

		cdp_idx = 4;
		while((cdp_idx+sizeof(struct cdp_element)) < (length-(hlen+llcLen))) {
		  struct cdp_element element;

  		  memcpy(&element, &cdp[cdp_idx], sizeof(struct cdp_element));

		  cdp_idx += sizeof(struct cdp_element);
		  element.cdp_len  = ntohs(element.cdp_len);
		  element.cdp_type  = ntohs(element.cdp_type);
		  if(element.cdp_len == 0) break; /* Sanity check */

		  switch(element.cdp_type) {
		  case 0x0001: /* Device Id */
		    if((srcHost->hostResolvedName[0] == '\0')
		       || (strcmp(srcHost->hostResolvedName, srcHost->hostNumIpAddress))) {
		      u_short tmpStrLen = min(element.cdp_len-4, MAX_LEN_SYM_HOST_NAME-1);
		      strncpy(srcHost->hostResolvedName, (char*)&cdp[cdp_idx], tmpStrLen);
		      srcHost->hostResolvedName[tmpStrLen] = '\0';
		    }
		    break;
		  case 0x0002: /* Addresses */
		    break;
		  case 0x0003: /* Port Id */
		    break;
		  case 0x0004: /* Capabilities */
		    break;
		  case 0x0005: /* Sw Version */
		    if(srcHost->description == NULL) {
		      char *tmpStr;
		      u_short tmpStrLen = min(element.cdp_len-4, 255)+1;

		      tmpStr = (char*)malloc(tmpStrLen);
		      memcpy(tmpStr, &cdp[cdp_idx], tmpStrLen-2);
		      tmpStr[tmpStrLen-1] = '\0';
		      srcHost->description = tmpStr;
		    }
		    break;
		  case 0x0006: /* Platform */
		    if(srcHost->fingerprint == NULL) {
		      char *tmpStr;
		      u_short tmpStrLen = min(element.cdp_len-4, 64)+2;

		      tmpStr = (char*)malloc(tmpStrLen);
		      tmpStr[0] = ':';
		      memcpy(&tmpStr[1], &cdp[cdp_idx], tmpStrLen-2);
		      tmpStr[tmpStrLen-1] = '\0';
		      srcHost->fingerprint = tmpStr;
		      srcHost->hwModel = strdup(&tmpStr[1]);
		    }
		    break;
		  case 0x0008: /* Cluster Management */
		    break;
		  case 0x0009: /* VTP Management Domain */
		    break;
		  }

		  cdp_idx += (element.cdp_len-sizeof(struct cdp_element));
		}


		if(srcHost->fingerprint == NULL)
		  srcHost->fingerprint = strdup(":Cisco"); /* Default */
	      }
	    }

	    if(sap_type != 0x42 /* !STP */) {
	      addNonIpTrafficInfo(srcHost, sap_type, length, 0 /* sent */);
	      addNonIpTrafficInfo(dstHost, sap_type, length, 1 /* rcvd */);
	    }

	    if(sap_type == 0x42 /* STP */) {
	      /* Spanning Tree */

	      incrementHostTrafficCounter(srcHost, nonIPTraffic->stpSent, length);
	      incrementHostTrafficCounter(dstHost, nonIPTraffic->stpRcvd, length);
	      setHostFlag(FLAG_HOST_TYPE_SVC_BRIDGE, srcHost);
	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].stpBytes, length);
	    } else if(myGlobals.runningPref.enablePacketDecoding && (sap_type == 0xE0)) {
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
		char serverName[MAX_LEN_SYM_HOST_NAME];
		int i, found;

		memcpy(&serverType, &ipxBuffer[32], 2);
		serverType = ntohs(serverType);

		memcpy(serverName, &ipxBuffer[34], 56); serverName[56] = '\0';
		for(i=0; i<56; i++)
		  if(serverName[i] == '!') {
		    serverName[i] = '\0';
		    break;
		  }

		incrementHostTrafficCounter(srcHost, nonIPTraffic->ipxSent, length);
		incrementHostTrafficCounter(dstHost, nonIPTraffic->ipxRcvd, length);

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
		    setHostFlag(FLAG_HOST_TYPE_PRINTER, srcHost);
		    break;

		  case 0x0027: /* TCP/IP gateway */
		  case 0x0021: /* NAS SNA gateway */
		  case 0x055d: /* Attachmate SNA gateway */
		    setHostFlag(FLAG_GATEWAY_HOST, srcHost);
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
		    setHostFlag(FLAG_HOST_TYPE_SERVER, srcHost);
		    break;

		  case 0x0278: /* NetWare Directory server */
		    setHostFlag(FLAG_HOST_TYPE_SVC_DIRECTORY, srcHost);
		    break;

		  case 0x0024: /* Rem bridge */
		  case 0x0026: /* Bridge server */
		    setHostFlag(FLAG_HOST_TYPE_SVC_BRIDGE, srcHost);
		    break;

		  case 0x0640: /* NT Server-RPC/GW for NW/Win95 User Level Sec */
		  case 0x064e: /* NT Server-IIS */
		    setHostFlag(FLAG_HOST_TYPE_SERVER, srcHost);
		    break;

		  case 0x0133: /* NetWare Name Service */
		    setHostFlag(FLAG_NAME_SERVER_HOST, srcHost);
		    break;
		  }
		}

		if(srcHost->nonIPTraffic->ipxHostName == NULL) {
		  int begin = 1;

		  for(i=1; i<strlen(serverName); i++)
		    if((serverName[i] == '_') && (serverName[i-1] == '_')) {
		      serverName[i-1] = '\0'; /* Avoid weird names */
		      break;
		    }

		  if(serverName[0] == '\0') begin = 1; else begin = 0;
		  if(strlen(serverName) >= (MAX_LEN_SYM_HOST_NAME-1))
		    serverName[MAX_LEN_SYM_HOST_NAME-2] = '\0';
		  srcHost->nonIPTraffic->ipxHostName = strdup(&serverName[begin]);
		  for(i=0; srcHost->nonIPTraffic->ipxHostName[i] != '\0'; i++)
		    srcHost->nonIPTraffic->ipxHostName[i] = tolower(srcHost->nonIPTraffic->ipxHostName[i]);

		  updateHostName(srcHost);
		}
#ifdef DEBUG
		traceEvent(CONST_TRACE_INFO, "%s [%s][%x]", serverName,
			   getSAPInfo(serverType, 0), serverType);
#endif
	      }

	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipxBytes, length);
	    } else if((llcHeader.ssap == LLCSAP_NETBIOS) && (llcHeader.dsap == LLCSAP_NETBIOS)) {
	      /* Netbios */
	      incrementHostTrafficCounter(srcHost, nonIPTraffic->netbiosSent, length);
	      incrementHostTrafficCounter(dstHost, nonIPTraffic->netbiosRcvd, length);
	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].netbiosBytes, length);
	    } else if((sap_type == 0xF0)
		      || (sap_type == 0xB4)
		      || (sap_type == 0xC4)
		      || (sap_type == 0xF8)) {
	      /* DLC (protocol used for printers) */
	      incrementHostTrafficCounter(srcHost, nonIPTraffic->dlcSent, length);
	      incrementHostTrafficCounter(dstHost, nonIPTraffic->dlcRcvd, length);
	      setHostFlag(FLAG_HOST_TYPE_PRINTER, dstHost);
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
	      if(myGlobals.runningPref.enablePacketDecoding
		 && ((snapType == 0x809B) || (snapType == 0x80F3))) {
		/* Appletalk */
		AtDDPheader ddpHeader;

		memcpy(&ddpHeader, (char*)p1, sizeof(AtDDPheader));

		srcHost->nonIPTraffic->atNetwork = ntohs(ddpHeader.srcNet),
		  srcHost->nonIPTraffic->atNode = ddpHeader.srcNode;
		dstHost->nonIPTraffic->atNetwork = ntohs(ddpHeader.dstNet),
		  dstHost->nonIPTraffic->atNode = ddpHeader.dstNode;

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

		    if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1,
												    sizeof(NonIPTraffic));
		    if(srcHost->nonIPTraffic == NULL) return;

		    srcHost->nonIPTraffic->atNodeName = strdup(nodeName);
		    updateHostName(srcHost);

		    memcpy(nodeName, &p1[7+p1[5+displ]+displ], p1[6+p1[5+displ]+displ]);
		    nodeName[p1[6+p1[5+displ]]] = '\0';

		    for(i=0; i<MAX_NODE_TYPES; i++)
		      if((srcHost->nonIPTraffic->atNodeType[i] == NULL)
			 || (strcmp(srcHost->nonIPTraffic->atNodeType[i], nodeName) == 0))
			break;

		    if((i < MAX_NODE_TYPES) && (srcHost->nonIPTraffic->atNodeType[i] == NULL))
		      srcHost->nonIPTraffic->atNodeType[i] = strdup(nodeName);
		  }
		}

		incrementHostTrafficCounter(srcHost, nonIPTraffic->appletalkSent, length);
		incrementHostTrafficCounter(dstHost, nonIPTraffic->appletalkRcvd, length);
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

		  setHostFlag(FLAG_GATEWAY_HOST, srcHost);
		}

		incrementHostTrafficCounter(srcHost, nonIPTraffic->otherSent, length);
		incrementHostTrafficCounter(dstHost, nonIPTraffic->otherRcvd, length);
		incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherBytes, length);

		incrementUnknownProto(srcHost, 0 /* sent */, 0 /* eth */, llcHeader.dsap /* dsap */,
				      llcHeader.ssap /* ssap */, 0 /* ip */);
		incrementUnknownProto(dstHost, 1 /* rcvd */, 0 /* eth */, llcHeader.dsap /* dsap */,
				      llcHeader.ssap /* ssap */, 0 /* ip */);
		if(myGlobals.runningPref.enableOtherPacketDump)
		  dumpOtherPacket(actualDeviceId);
	      }
	    } else {
	      /* Unknown Protocol */
#ifdef UNKNOWN_PACKET_DEBUG
	      traceEvent(CONST_TRACE_INFO, "UNKNOWN_PACKET_DEBUG: [%u] [%x] %s %s > %s",
			 (u_short)sap_type,(u_short)sap_type,
			 etheraddr_string(ether_src, etherbuf),
			 llcsap_string(llcHeader.ssap & ~CONST_LLC_GSAP),
			 etheraddr_string(ether_dst, etherbuf));
#endif

	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherBytes, length);
	      incrementUnknownProto(srcHost, 0 /* sent */, 0 /* eth */, llcHeader.dsap /* dsap */,
				    llcHeader.ssap /* ssap */, 0 /* ip */);
	      incrementUnknownProto(dstHost, 1 /* rcvd */, 0 /* eth */, llcHeader.dsap /* dsap */,
				    llcHeader.ssap /* ssap */, 0 /* ip */);
	      if(myGlobals.runningPref.enableOtherPacketDump)
		dumpOtherPacket(actualDeviceId);
	    }

	    ctr.value = length;
	    /*
	      Even if this is not IP the hostIpAddress field is
	      fine because it is not used in this special case and I need
	      a placeholder here.
	    */
	    updatePacketCount(srcHost, &srcHost->hostIpAddress, dstHost,
			      &dstHost->hostIpAddress, ctr, 1, actualDeviceId);
	  }
	}
      } else if((eth_type == ETHERTYPE_IP) || (eth_type == ETHERTYPE_IPv6)) {
	if((myGlobals.device[deviceId].datalink == DLT_IEEE802) && (eth_type > ETHERMTU)) {
	  processIpPkt(p, h, length, ether_src, ether_dst, actualDeviceId, vlanId);
	} else {
	  processIpPkt(p+hlen, h, length, ether_src, ether_dst, actualDeviceId, vlanId);
	}
      } else if(eth_type == 0x8864) /* PPPOE */ {
        /* PPPoE - Courtesy of Andreas Pfaller Feb20032
         *   This strips the PPPoE encapsulation for traffic transiting the network.
         */
        struct pppoe_hdr *pppoe_hdr=(struct pppoe_hdr *) (p+hlen);
        int protocol=ntohs(*((int *) (p+hlen+6)));

        if(pppoe_hdr->ver==1 && pppoe_hdr->type==1 && pppoe_hdr->code==0 &&
	   protocol==0x0021) {
          hlen+=8; /* length of pppoe header */
	  processIpPkt(p+hlen, h, length, NULL, NULL, actualDeviceId, vlanId);
        }
      } else  /* Non IP */ if(!myGlobals.runningPref.dontTrustMACaddr) {
	  /* MAC addresses are meaningful here */
	  struct ether_arp arpHdr;
	  HostAddr addr;
	  TrafficCounter ctr;

	  if(length > hlen)
	    length -= hlen;
	  else
	    length = 0;

	  srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId);
	  if(srcHost == NULL) {
	    /* Sanity check */
	    if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (11) [Low memory?]");
	    lowMemoryMsgShown = 1;
	    return;
	  } else {
	    lockHostsHashMutex(srcHost, "processPacket-src-5");
	    allocHostTrafficCounterMemory(srcHost, nonIPTraffic, sizeof(NonIPTraffic));
	    if(srcHost->nonIPTraffic == NULL) {
	      unlockHostsHashMutex(srcHost);
	      return;
	    }
	  }

	  dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId);
	  if(dstHost == NULL) {
	    /* Sanity check */
	    if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (12) [Low memory?]");
	    unlockHostsHashMutex(srcHost);
	    lowMemoryMsgShown = 1;
	    return;
	  } else {
	    /* traceEvent(CONST_TRACE_INFO, "lockHostsHashMutex()"); */
	    lockHostsHashMutex(dstHost, "processPacket-src-5");
	    allocHostTrafficCounterMemory(dstHost, nonIPTraffic, sizeof(NonIPTraffic));
	    if(dstHost->nonIPTraffic == NULL) {
	      unlockHostsHashMutex(srcHost), unlockHostsHashMutex(dstHost);
	      return;
	    }
	  }

	  if(vlanId != NO_VLAN) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }

	  switch(eth_type) {
	  case ETHERTYPE_ARP: /* ARP - Address resolution Protocol */
	    memcpy(&arpHdr, p+hlen, sizeof(arpHdr));

	    if(EXTRACT_16BITS(&arpHdr.arp_pro) == ETHERTYPE_IP) {
	      int arpOp = EXTRACT_16BITS(&arpHdr.arp_op);

	      switch(arpOp) {
	      case ARPOP_REPLY: /* ARP REPLY */
		addr.hostFamily = AF_INET;
		memcpy(&addr.Ip4Address.s_addr, &arpHdr.arp_tpa, sizeof(struct in_addr));
		addr.Ip4Address.s_addr = ntohl(addr.Ip4Address.s_addr);
		unlockHostsHashMutex(srcHost), unlockHostsHashMutex(dstHost);

		dstHost = lookupHost(&addr, (u_char*)&arpHdr.arp_tha, vlanId, 0, 0, actualDeviceId);
		memcpy(&addr.Ip4Address.s_addr, &arpHdr.arp_spa, sizeof(struct in_addr));
		addr.Ip4Address.s_addr = ntohl(addr.Ip4Address.s_addr);
		if(dstHost != NULL) {
		  lockHostsHashMutex(dstHost, "processPacket-dst-6");
		  allocHostTrafficCounterMemory(dstHost, nonIPTraffic, sizeof(NonIPTraffic));
		  incrementHostTrafficCounter(dstHost, nonIPTraffic->arpReplyPktsRcvd, 1);
		}

		srcHost = lookupHost(&addr, (u_char*)&arpHdr.arp_sha, vlanId, 0, 0, actualDeviceId);
		if(srcHost != NULL) {
		  lockHostsHashMutex(srcHost, "processPacket-src-6");
		  allocHostTrafficCounterMemory(srcHost, nonIPTraffic, sizeof(NonIPTraffic));
		  incrementHostTrafficCounter(srcHost, nonIPTraffic->arpReplyPktsSent, 1);
		}
	      }
	    }
	    /* DO NOT ADD A break ABOVE ! */

	  case ETHERTYPE_REVARP: /* Reverse ARP */
	    if(srcHost != NULL) {
	      incrementHostTrafficCounter(srcHost, nonIPTraffic->arp_rarpSent, length);
	    }

	    if(dstHost != NULL) {

	      incrementHostTrafficCounter(dstHost, nonIPTraffic->arp_rarpRcvd, length);
	    }
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].arpRarpBytes, length);
	    break;

	  case ETHERTYPE_ATALK: /* AppleTalk */
	  case ETHERTYPE_AARP:
	    incrementHostTrafficCounter(srcHost, nonIPTraffic->appletalkSent, length);
	    incrementHostTrafficCounter(dstHost, nonIPTraffic->appletalkRcvd, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].atalkBytes, length);
	    break;

	  case ETHERTYPE_IPv6:
	    processIpPkt(p+hlen, h, length, ether_src, ether_dst, actualDeviceId, vlanId);
	    incrementHostTrafficCounter(srcHost, ipv6BytesSent, length);
	    incrementHostTrafficCounter(dstHost, ipv6BytesRcvd, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipv6Bytes, length);
	    break;

	  default:
#ifdef UNKNOWN_PACKET_DEBUG
	    traceEvent(CONST_TRACE_INFO, "UNKNOWN_PACKET_DEBUG: %s/%s->%s/%s [eth type %d (0x%x)]",
		       srcHost->hostNumIpAddress, srcHost->ethAddressString,
		       dstHost->hostNumIpAddress, dstHost->ethAddressString,
		       eth_type, eth_type);
#endif
	    incrementHostTrafficCounter(srcHost, nonIPTraffic->otherSent, length);
	    incrementHostTrafficCounter(dstHost, nonIPTraffic->otherRcvd, length);
	    incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherBytes, length);
	    incrementUnknownProto(srcHost, 0 /* sent */, eth_type /* eth */, 0 /* dsap */,
				  0 /* ssap */, 0 /* ip */);
	    incrementUnknownProto(dstHost, 1 /* rcvd */, eth_type /* eth */, 0 /* dsap */,
				  0 /* ssap */, 0 /* ip */);
	    if(myGlobals.runningPref.enableOtherPacketDump)
	      dumpOtherPacket(actualDeviceId);
	    break;
	  }

	  ctr.value = length;
	  /*
	    Even if this is not IP the hostIpAddress field is
	    fine because it is not used in this special case and I need
	    a placeholder here.
	  */
	  updatePacketCount(srcHost, &srcHost->hostIpAddress, dstHost,
			    &dstHost->hostIpAddress, ctr, 1, actualDeviceId);
	}
    }

    if(srcHost) unlockHostsHashMutex(srcHost);
    if(dstHost) unlockHostsHashMutex(dstHost);
  } else {
    /*  count runts somehow? */
  }

  if(myGlobals.flowsList != NULL) /* Handle flows last */
    flowsProcess(h, p, deviceId);


#ifdef MAX_PROCESS_BUFFER
  {
    float elapsed;
    gettimeofday(&pktEndOfProcessing, NULL);
    elapsed = timeval_subtract(pktEndOfProcessing, pktStartOfProcessing);
    myGlobals.processBuffer[++myGlobals.processBufferCount & (MAX_PROCESS_BUFFER - 1)] = elapsed;
    if(elapsed > myGlobals.pmaxDelay)
      myGlobals.pmaxDelay = elapsed;
  }
#endif

  if(myGlobals.pcap_file_list != NULL) {
    if(myGlobals.actTime > (lastUpdateThptTime + PARM_THROUGHPUT_REFRESH_INTERVAL)) {
      updateThpt (1);
      lastUpdateThptTime = myGlobals.actTime;
    }
  }

  if(myGlobals.resetHashNow == 1) {
    int i;

    traceEvent(CONST_TRACE_INFO, "Resetting stats on user request...");
    for(i=0; i<myGlobals.numDevices; i++) resetStats(i);
    traceEvent(CONST_TRACE_INFO, "User requested stats reset complete");
    myGlobals.resetHashNow = 0;
  }
}

/* ************************************ */

