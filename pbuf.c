/*
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

static void processFcPkt(const u_char *bp, const struct pcap_pkthdr *h,
			 u_int16_t ethertype, int actualDeviceId);

static char *fcProtocolStrings[] = {
    "", "SW_ILS", "IP", "SCSI", "BLS", "ELS", "FCCT", "LinkData",
    "Video", "LinkCtl", "SWILS_RSP", "FICON", "Undefined"
};

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

/* ******************************* */

static u_int32_t getFcProtocol (u_int8_t r_ctl, u_int8_t type)
{
    switch (r_ctl & 0xF0) {
    case FC_RCTL_DEV_DATA:
        switch (type) {
        case FC_TYPE_SWILS:
            if ((r_ctl == 0x2) || (r_ctl == 0x3))
                return FC_FTYPE_SWILS;
            else
                return FC_FTYPE_UNDEF;
        case FC_TYPE_IP:
            return FC_FTYPE_IP;
        case FC_TYPE_SCSI:
            return FC_FTYPE_SCSI;
        case FC_TYPE_FCCT:
            return FC_FTYPE_FCCT;
        case FC_TYPE_SB_FROM_CU:
        case FC_TYPE_SB_TO_CU:
            return FC_FTYPE_SBCCS;
        default:
            return FC_FTYPE_UNDEF;
        }
        break;
    case FC_RCTL_ELS:
        if (((r_ctl & 0x0F) == 0x2) || ((r_ctl & 0x0F) == 0x3))
            return FC_FTYPE_ELS;
        else
            return FC_FTYPE_UNDEF;
        break;
    case FC_RCTL_LINK_DATA:
        return FC_FTYPE_LINKDATA;
        break;
    case FC_RCTL_VIDEO:
        return FC_FTYPE_VDO;
        break;
    case FC_RCTL_BLS:
        if (type == 0)
            return FC_FTYPE_BLS;
        else
            return FC_FTYPE_UNDEF;
        break;
    case FC_RCTL_LINK_CTL:
        return FC_FTYPE_LINKCTL;
        break;
    default:
        return FC_FTYPE_UNDEF;
        break;
    }
}

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

int handleIP(u_short port, HostTraffic *srcHost, HostTraffic *dstHost,
	     const u_int _length,  u_short isPassiveSess,
	     u_short p2pSessionIdx, int actualDeviceId) {
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

  if(idx == -1) {
    return(-1); /* Unable to locate requested index */
  } else if(idx >= myGlobals.numIpProtosToMonitor) {
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

static void addContactedPeers(HostTraffic *sender, HostAddr *srcAddr,
			      HostTraffic *receiver, HostAddr *dstAddr,
			      int actualDeviceId) {
  if((sender == NULL) || (receiver == NULL) || (sender == receiver)) {
    if ((sender != NULL) && (sender->l2Family == FLAG_HOST_TRAFFIC_AF_FC) &&
	(strncasecmp (sender->fcCounters->hostNumFcAddress, FC_FAB_CTLR_ADDR,
		      strlen (FC_FAB_CTLR_ADDR)) == 0)) {
      /* This is normal. Return without warning */
      return;
    }
    traceEvent(CONST_TRACE_ERROR, "Sanity check failed @ addContactedPeers (0x%X, 0x%X)",
	       sender, receiver);
    return;
  }

  if((sender != myGlobals.otherHostEntry) && (receiver != myGlobals.otherHostEntry)) {
    /* The statements below have no effect if the serial has been already computed */
    setHostSerial(sender); setHostSerial(receiver);
    
    sender->totContactedSentPeers   += incrementUsageCounter(&sender->contactedSentPeers, receiver, actualDeviceId);
    receiver->totContactedRcvdPeers += incrementUsageCounter(&receiver->contactedRcvdPeers, sender, actualDeviceId);
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
    if(myGlobals.enableSuspiciousPacketDump) {
      char buf[LEN_GENERAL_WORK_BUFFER];
      safe_snprintf(buf, LEN_GENERAL_WORK_BUFFER, "Detected overlapping packet fragment [%s->%s]: "
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
    if(fragment == NULL)
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
    traceEvent(CONST_TRACE_INFO, "(%s/%s/%s) -> (%s/%s/%s) routed by [idx=%d/%s/%s/%s]",
	       srcHost->ethAddressString, srcHost->hostNumIpAddress, srcHost->hostResolvedName,
	       dstHost->ethAddressString, dstHost->hostNumIpAddress, dstHost->hostResolvedName,
	       routerIdx,
	       router->ethAddressString,
	       router->hostNumIpAddress,
	       router->hostResolvedName);

#endif
    FD_SET(FLAG_GATEWAY_HOST, &router->flags);
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
		       TrafficCounter length, Counter numPkts,
		       int actualDeviceId) {
  static u_short lastHourId=0;
  u_short hourId;
  struct tm t, *thisTime;

  if((srcHost == NULL) || (dstHost == NULL)) {
    traceEvent(CONST_TRACE_ERROR, "NULL host detected");
    return;
  }

  if (!myGlobals.noFc) {
      if (srcHost == dstHost) {
          /* Fabric controllers exchange link messages where the S_ID & D_ID
           * are equal. A lot of control traffic is exchanged using these
           * addresses and so we must track this as an exception to the case of
           * S_ID == D_ID.
           */
          if (srcHost->l2Family == FLAG_HOST_TRAFFIC_AF_FC) {
              if (strncasecmp (srcHost->fcCounters->hostNumFcAddress, FC_FAB_CTLR_ADDR,
                               strlen (FC_FAB_CTLR_ADDR)) != 0) {
                  return;
              }
          }
          else {
              return;
          }
      }
      else if ((srcHost == myGlobals.otherHostEntry)
               && (dstHost == myGlobals.otherHostEntry)) {
          return;
      }
  }
  else if (srcHost == dstHost)
      return;


  thisTime = localtime_r(&myGlobals.actTime, &t);
  hourId = thisTime->tm_hour % 24 /* just in case... */;;

  if(lastHourId != hourId) {
    resetHourTraffic(hourId);
    lastHourId = hourId;
  }

  if(srcHost != myGlobals.otherHostEntry) {
    incrementTrafficCounter(&srcHost->pktSent, numPkts);
    incrementTrafficCounter(&srcHost->pktSentSession, numPkts);
    if(srcHost->trafficDistribution == NULL) srcHost->trafficDistribution = calloc(1, sizeof(TrafficDistribution));
    incrementTrafficCounter(&srcHost->trafficDistribution->last24HoursBytesSent[hourId], length.value);
    incrementTrafficCounter(&srcHost->bytesSent, length.value);
    incrementTrafficCounter(&srcHost->bytesSentSession, length.value);
  }

  if(dstHost != myGlobals.otherHostEntry) {
    if(dstHost->trafficDistribution == NULL) dstHost->trafficDistribution = calloc(1, sizeof(TrafficDistribution));
    incrementTrafficCounter(&dstHost->trafficDistribution->last24HoursBytesRcvd[hourId], length.value);
    incrementTrafficCounter(&dstHost->bytesRcvd, length.value);
    incrementTrafficCounter(&dstHost->bytesRcvdSession, length.value);
    incrementTrafficCounter(&dstHost->pktRcvd, numPkts);
    incrementTrafficCounter(&dstHost->pktRcvdSession, numPkts);
  }

  if(broadcastHost(dstHost)) {
    if(srcHost != myGlobals.otherHostEntry) {
      incrementTrafficCounter(&srcHost->pktBroadcastSent, numPkts);
      incrementTrafficCounter(&srcHost->bytesBroadcastSent, length.value);
    }
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].broadcastPkts, numPkts);
  } else if(isMulticastAddress(&(dstHost->hostIpAddress))) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "%s->%s",
	       srcHost->hostResolvedName, dstHost->hostResolvedName);
#endif
    if(srcHost != myGlobals.otherHostEntry) {
      incrementTrafficCounter(&srcHost->pktMulticastSent, numPkts);
      incrementTrafficCounter(&srcHost->bytesMulticastSent, length.value);
    }

    if(dstHost != myGlobals.otherHostEntry) {
      incrementTrafficCounter(&dstHost->pktMulticastRcvd, numPkts);
      incrementTrafficCounter(&dstHost->bytesMulticastRcvd, length.value);
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

    if(el->nonIPTraffic == NULL) el->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));

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
  accessMutex(&myGlobals.purgePortsMutex, "updateInterfacePorts");
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
  releaseMutex(&myGlobals.purgePortsMutex);
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

void incrementUnknownProto(HostTraffic *host,
			   int direction,
			   u_int16_t eth_type,
			   u_int16_t dsap,  u_int16_t ssap,
			   u_int16_t ipProto) {
  int i;
  
  if(host->nonIPTraffic == NULL) host->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));

  if(direction == 0) {
    /* Sent */
    if(host->nonIPTraffic->unknownProtoSent == NULL) {
      host->nonIPTraffic->unknownProtoSent = (UnknownProto*)malloc(sizeof(UnknownProto)*MAX_NUM_UNKNOWN_PROTOS);
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
      host->nonIPTraffic->unknownProtoRcvd = (UnknownProto*)malloc(sizeof(UnknownProto)*MAX_NUM_UNKNOWN_PROTOS);
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
#ifdef INET6
  struct ip6_hdr *ip6;
  struct icmp6_hdr icmp6Pkt;
  u_int advance;
  u_char *cp;
  u_char *snapend;
  u_int icmp6len;
#endif
  u_int nh;
  int fragmented = 0;
  struct tcphdr tp;
  struct udphdr up;
  struct icmp icmpPkt;
  u_int hlen, ip_len,tcpDataLength, udpDataLength, off, tcpUdpLen, idx;
  char *proto;
  HostTraffic *srcHost=NULL, *dstHost=NULL;
  HostAddr srcAddr, dstAddr; /* Protocol Independent addresses */
  u_char forceUsingIPaddress = 0;
  struct timeval tvstrct;
  u_char *theData, found = 0;
  TrafficCounter ctr;
  ProtocolsList *protoList;

  /* Need to copy this over in case bp isn't properly aligned.
   * This occurs on SunOS 4.x at least.
   * Paul D. Smith <psmith@baynetworks.com>
   */

  memcpy(&ip, bp, sizeof(struct ip));
#ifdef INET6
  /* TODO: isipv6 = (ip.ip_v == 6)?1:0; */
  if(ip.ip_v == 6) {
    /* handle IPv6 packets */
    ip6 = (struct ip6_hdr *)bp;
  } else
    ip6 = NULL;
#endif

#ifdef INET6
  if(ip6)
    hlen = sizeof(struct ip6_hdr);
  else
#endif
    hlen = (u_int)ip.ip_hl * 4;

  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipPkts, 1);
#ifdef INET6
  if(ip6 == NULL)
#endif
    if((bp != NULL) && (in_cksum((const u_short *)bp, hlen, 0) != 0)) {
      incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.badChecksum, 1);
      return;
    }

  /*
    Fix below courtesy of
    Christian Hammers <ch@westend.com>
  */
#ifdef INET6
  if(ip6)
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipv6Bytes, length /* ntohs(ip.ip_len) */);
  else
#endif
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipBytes, length /* ntohs(ip.ip_len) */);

#ifdef INET6
  if(ip6 == NULL) {
#endif
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
#ifdef INET6
  }
#endif

  if((ether_src == NULL) && (ether_dst == NULL)) {
    /* Ethernet-less protocols (e.g. PPP/RAW IP) */
    forceUsingIPaddress = 1;
  }

#ifdef INET6
  if(ip6) {
    addrput(AF_INET6, &srcAddr, &ip6->ip6_src);
    addrput(AF_INET6, &dstAddr, &ip6->ip6_dst);
  } else
#endif
    {
      NTOHL(ip.ip_dst.s_addr); NTOHL(ip.ip_src.s_addr);
      addrput(AF_INET, &srcAddr,&ip.ip_src.s_addr);
      addrput(AF_INET, &dstAddr,&ip.ip_dst.s_addr);
    }

#ifdef INET6
  if(ip6 == NULL) {
#endif
    if((!myGlobals.dontTrustMACaddr)
       && isBroadcastAddress(&dstAddr)
       && (ether_src != NULL) && (ether_dst != NULL) /* PPP has no ethernet */
       && (memcmp(ether_dst, ethBroadcast, 6) != 0)) {
      /* forceUsingIPaddress = 1; */

      srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId);
      if(srcHost != NULL) {
	if(vlanId != -1) srcHost->vlanId = vlanId;
	if(myGlobals.enableSuspiciousPacketDump && (!hasWrongNetmask(srcHost))) {
	  /* Dump the first packet only */
	  char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

	  traceEvent(CONST_TRACE_WARNING, "Host %s has a wrong netmask",
		     etheraddr_string(ether_src, etherbuf));
	  dumpSuspiciousPacket(actualDeviceId);
	}

	FD_SET(FLAG_HOST_WRONG_NETMASK, &srcHost->flags);
      }
    }
#ifdef INET6
  }
#endif

  /*
    IMPORTANT:
    do NOT change the order of the lines below (see isBroadcastAddress call)
  */
  dstHost = lookupHost(&dstAddr, ether_dst, vlanId, 1 , 0 ,actualDeviceId);
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
		       (!isBroadcastAddress(&dstAddr)),
		       forceUsingIPaddress, actualDeviceId);

  if(srcHost == NULL) {
    /* Sanity check */
    if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (1) [Low memory?]");
    lowMemoryMsgShown = 1;
    return; /* It might be that there's not enough memory that that
	       dstHost = lookupHost(&ip.ip_dst, ether_dst) caused
	       srcHost to be freed */
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

  /* ****************** */

#ifdef INET6
  if(ip6) {
    updateDevicePacketTTLStats(ip6->ip6_hlim, actualDeviceId);

    if(ip6->ip6_hlim != 255) {
      if((srcHost->minTTL == 0) || (ip6->ip6_hlim < srcHost->minTTL)) srcHost->minTTL = ip6->ip6_hlim;
      if((ip6->ip6_hlim > srcHost->maxTTL)) srcHost->maxTTL = ip6->ip6_hlim;
    }

  } else
#endif
    {
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
  updatePacketCount(srcHost, &srcAddr, dstHost, &dstAddr,
		    ctr, 1, actualDeviceId);

  if((!myGlobals.dontTrustMACaddr) && (!myGlobals.device[actualDeviceId].dummyDevice)) {
    checkNetworkRouter(srcHost, dstHost, ether_dst, actualDeviceId);
    ctr.value = length;
    updateTrafficMatrix(srcHost, dstHost, ctr, actualDeviceId);
  }
#ifdef INET6
  if(ip6) {
    incrementTrafficCounter(&srcHost->ipv6Sent, length),
      incrementTrafficCounter(&dstHost->ipv6Rcvd, length);
  } else
#endif
    {
      incrementTrafficCounter(&srcHost->ipBytesSent, length),
	incrementTrafficCounter(&dstHost->ipBytesRcvd, length);
    }

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

#ifdef INET6
  if(ip6) {
    if(ip6->ip6_nxt == IPPROTO_FRAGMENT) {
      fragmented = 1;
      nh = ip6->ip6_nxt;
    }
  } else
#endif
    {
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
#ifdef INET6
    case IPPROTO_ICMPV6:
      incrementTrafficCounter(&srcHost->icmp6FragmentsSent, length),
	incrementTrafficCounter(&dstHost->icmp6FragmentsRcvd, length);
      break;
#endif
    }
  }

#ifdef INET6
  if(ip6) {
    advance = sizeof(struct ip6_hdr);
    cp = (unsigned char *) ip6;
    snapend = (unsigned char *)(bp+length);
    nh = ip6->ip6_nxt;
    ip_len =  ntohs(ip6->ip6_plen);
    tcpUdpLen = ip_len;
  } else
#endif
    {
      nh  = ip.ip_p;
      ip_len = ntohs(ip.ip_len);
      tcpUdpLen = ip_len - hlen;
    }

#ifdef INET6
 loop:
  if(ip6)
    cp +=advance;
#endif

  switch(nh) {
#ifdef INET6
  case IPPROTO_FRAGMENT:
    if(ip6) {
      advance = sizeof(struct ip6_frag);
      if(snapend <= cp+advance) goto end;
      nh = *cp;
      goto loop;
    }
    /* If it's no IPv6 we continue */
#endif
  case IPPROTO_TCP:
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpBytes, length);

    if(tcpUdpLen < sizeof(struct tcphdr)) {
      if(myGlobals.enableSuspiciousPacketDump) {
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
#ifdef INET6
	if(ip6)
	  length = handleFragment(srcHost, dstHost, &sport,&dport,
				  (u_short)(ip6->ip6_flow & 0xffff),fragmented,
				  length,ntohs(ip6->ip6_plen),
				  actualDeviceId);
	else
#endif
	  length = handleFragment(srcHost, dstHost, &sport, &dport,
				  ntohs(ip.ip_id), off, length,
				  ip_len - hlen, actualDeviceId);
      }

      if(srcHost->fingerprint == NULL) {
	char fingerprint[64];
	int WIN=0, MSS=-1, WS=-1, S=0, N=0, D=0, T=0;
	int ttl;
	char WSS[3], _MSS[5];
	struct tcphdr *tcp = (struct tcphdr*)(bp+hlen);
	u_char *tcp_opt = (u_char *)(tcp + 1);
        u_char *tcp_data = (u_char *)((int)tcp + tp.th_off * 4);

	if(tcp->th_flags & TH_SYN)   /* only SYN or SYN-2ACK packets */
	  {
	    if(tcpUdpLen > 0) {
#ifdef INET6
	      if(ip6) {
		if(!fragmented) D = 1;
	      } else
#endif
		if(ntohs(ip.ip_off) & IP_DF) D = 1;   /* don't fragment bit is set */

	      WIN = ntohs(tcp->th_win);  /* TCP window size */

	      if(tcp_data != tcp_opt) /* there are some tcp_option to be parsed */
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
			  if(*opt_ptr > 0)
			    opt_ptr += (*opt_ptr - 1);
			  break;
			}
		    }
		}

	      if(WS == -1) { safe_snprintf(WSS, sizeof(WSS), "WS"); }
	      else { safe_snprintf(WSS, sizeof(WSS), "%02d", WS); }
	      
	      if(MSS == -1) { safe_snprintf(_MSS, sizeof(_MSS), "_MSS"); }
	      else { safe_snprintf(_MSS, sizeof(_MSS), "%04X", MSS); }

	      safe_snprintf(fingerprint, sizeof(fingerprint),
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

      if((sport > 0) || (dport > 0)) {
	IPSession *theSession = NULL;
	u_short isPassiveSess = 0, nonFullyRemoteSession = 1;

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
#ifdef INET6
	  if(ip6)
	    theSession = handleTCPSession(h, fragmented, tp.th_win,
					  srcHost, sport, dstHost,
					  dport, ntohs(ip6->ip6_plen), &tp, tcpDataLength,
					  theData, actualDeviceId);
	  else
#endif
	    theSession = handleTCPSession(h, (off & 0x3fff), tp.th_win,
					  srcHost, sport, dstHost,
					  dport, ip_len, &tp, tcpDataLength,
					  theData, actualDeviceId);
	  if(theSession == NULL)
	    isPassiveSess = 0;
	  else
	    isPassiveSess = theSession->passiveFtpSession;
	}

	sportIdx = mapGlobalToLocalIdx(sport), dportIdx = mapGlobalToLocalIdx(dport);

	if ((myGlobals.enableOtherPacketDump) && ((sportIdx == -1) && (dportIdx == -1)))
	  {
	    /* Both source & destination port are unknown. The packet will be counted to "Other TCP/UDP prot." : We dump the packet if requested */
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
#ifdef INET6
    if(ip6)
      goto end;
    else
#endif
      break;


  case IPPROTO_UDP:
    proto = "UDP";
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpBytes, length);

    if(tcpUdpLen < sizeof(struct udphdr)) {
      if(myGlobals.enableSuspiciousPacketDump) {
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
	if(((sport == 53) || (dport == 53) /* domain */)) {
	  short isRequest = 0, positiveReply = 0;
	  u_int16_t transactionId = 0;

	  if(myGlobals.enablePacketDecoding
	     && (bp != NULL) /* packet long enough */) {
	    /* The DNS chain will be checked here */
	    transactionId = processDNSPacket(bp+hlen+sizeof(struct udphdr),
					     udpDataLength, &isRequest, &positiveReply);

#ifdef DNS_SNIFF_DEBUG
	    traceEvent(CONST_TRACE_INFO, "DNS_SNIFF_DEBUG: %s:%d->%s:%d [request: %d][positive reply: %d]",
		       srcHost->hostResolvedName, sport,
		       dstHost->hostResolvedName, dport,
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
	} else if(sport == 123) /* NTP */ {
	  if(myGlobals.enablePacketDecoding) {
	    char *ntpPktPtr = (char*)bp+hlen+sizeof(struct udphdr);
	    u_char ntpRole = ntpPktPtr[0] & 0x07;

	    if(ntpRole ==  4 /* NTP Server */)
	      FD_SET(FLAG_HOST_TYPE_SVC_NTP_SERVER, &srcHost->flags);
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
      if(myGlobals.enableFragmentHandling && (fragmented)) {
	/* Handle fragmented packets */
#ifdef INET6
	if(ip6)
	  length = handleFragment(srcHost, dstHost, &sport, &dport,
				  (u_short)(ip6->ip6_flow & 0xffff), fragmented, length,
				  ntohs(ip6->ip6_plen), actualDeviceId);
	else
#endif
	  length = handleFragment(srcHost, dstHost, &sport, &dport,
				  ntohs(ip.ip_id), off, length,
				  ip_len - hlen, actualDeviceId);
      }

      if((sport > 0) || (dport > 0)) {
	u_short nonFullyRemoteSession = 1;

	updateInterfacePorts(actualDeviceId, sport, dport, length);
	updateUsedPorts(srcHost, dstHost, sport, dport, udpDataLength);

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

        sportIdx = mapGlobalToLocalIdx(sport), dportIdx = mapGlobalToLocalIdx(dport);

        if ((myGlobals.enableOtherPacketDump) && ((sportIdx == -1) && (dportIdx == -1)))
	  {
	    /* Both source & destination port are unknown. The packet will be counted to "Other TCP/UDP prot." : We dump the packet if requested */
	    dumpOtherPacket(actualDeviceId);
	  }


        /* Handle UDP traffic like TCP, above -
	   That is: if we know about the lower# port, even if it's the destination,
	   classify the traffic that way.
	   (BMS 12-2001)
	*/
        if(dport < sport) {
	  if(handleIP(dport, srcHost, dstHost, length, 0, 0, actualDeviceId) == -1)
	    handleIP(sport, srcHost, dstHost, length, 0, 0, actualDeviceId);
        } else {
	  if(handleIP(sport, srcHost, dstHost, length, 0, 0, actualDeviceId) == -1)
	    handleIP(dport, srcHost, dstHost, length, 0, 0, actualDeviceId);
        }

	if(nonFullyRemoteSession)
	  handleUDPSession(h, fragmented,
			   srcHost, sport, dstHost, dport, udpDataLength,
			   (u_char*)(bp+hlen+sizeof(struct udphdr)), actualDeviceId);
      }
    }
#ifdef INET6
    if(ip6)
      goto end;
    else
#endif
      break;

  case IPPROTO_ICMP:
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].icmpBytes, length);

    if(tcpUdpLen < sizeof(struct icmp)) {
      if(myGlobals.enableSuspiciousPacketDump) {
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

      incrementTrafficCounter(&srcHost->icmpSent, length);
      incrementTrafficCounter(&dstHost->icmpRcvd, length);

      if(off & 0x3fff) {
	char *fmt = "Detected ICMP fragment [%s -> %s] (network attack attempt?)";

	incrementTrafficCounter(&srcHost->icmpFragmentsSent, length),
	  incrementTrafficCounter(&dstHost->icmpFragmentsRcvd, length);
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->icmpFragmentSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->icmpFragmentRcvd, srcHost, actualDeviceId);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].securityPkts.icmpFragment, 1);
	if(myGlobals.enableSuspiciousPacketDump) {
	  traceEvent(CONST_TRACE_WARNING, fmt,
		     srcHost->hostResolvedName, dstHost->hostResolvedName);
	  dumpSuspiciousPacket(actualDeviceId);
	}
      }

      /* ************************************************************* */

      if(icmpPkt.icmp_type <= ICMP_MAXTYPE) {
	short dumpPacket = 1;
	if(srcHost->icmpInfo == NULL) {
	  if((srcHost->icmpInfo = (IcmpHostInfo*)malloc(sizeof(IcmpHostInfo))) == NULL) return;
	  memset(srcHost->icmpInfo, 0, sizeof(IcmpHostInfo));
	}

	incrementTrafficCounter(&srcHost->icmpInfo->icmpMsgSent[icmpPkt.icmp_type], 1);

	if(dstHost->icmpInfo == NULL) {
	  if( (dstHost->icmpInfo = (IcmpHostInfo*)malloc(sizeof(IcmpHostInfo))) == NULL) return;
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

      if(myGlobals.enableSuspiciousPacketDump
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
	    if(myGlobals.enableSuspiciousPacketDump)
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
	    if(myGlobals.enableSuspiciousPacketDump)
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
	  if(myGlobals.enableSuspiciousPacketDump)
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
	  if(myGlobals.enableSuspiciousPacketDump)
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
	if(myGlobals.enableSuspiciousPacketDump) dumpSuspiciousPacket(actualDeviceId);
      }
    }
    break;
#ifdef INET6
  case IPPROTO_ICMPV6:
    if(ip6 == NULL) {
      if(myGlobals.enableSuspiciousPacketDump) {
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
      if(myGlobals.enableSuspiciousPacketDump) {
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
      incrementTrafficCounter(&srcHost->icmp6Sent, length);
      incrementTrafficCounter(&dstHost->icmp6Rcvd, length);

      if(fragmented) {
	char *fmt = "Detected ICMPv6 fragment [%s -> %s] (network attack attempt?)";

	incrementTrafficCounter(&srcHost->icmp6FragmentsSent, length),
	  incrementTrafficCounter(&dstHost->icmp6FragmentsRcvd, length);
	allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	incrementUsageCounter(&srcHost->secHostPkts->icmpFragmentSent, dstHost, actualDeviceId);
	incrementUsageCounter(&dstHost->secHostPkts->icmpFragmentRcvd, srcHost, actualDeviceId);
	if(myGlobals.enableSuspiciousPacketDump) {
	  traceEvent(CONST_TRACE_WARNING, fmt,
		     srcHost->hostResolvedName, dstHost->hostResolvedName);
	  dumpSuspiciousPacket(actualDeviceId);
	}
      }

      /* ************************************************************* */

      if(icmp6Pkt.icmp6_type <= ICMP6_MAXTYPE) {
	short dumpPacket = 1;
	if(srcHost->icmpInfo == NULL) {
	  if( (srcHost->icmpInfo = (IcmpHostInfo*)malloc(sizeof(IcmpHostInfo))) == NULL) return;
	  memset(srcHost->icmpInfo, 0, sizeof(IcmpHostInfo));
	}

	incrementTrafficCounter(&srcHost->icmpInfo->icmpMsgSent[icmp6Pkt.icmp6_type], 1);
	if(dstHost->icmpInfo == NULL) {
	  if( (dstHost->icmpInfo = (IcmpHostInfo*)malloc(sizeof(IcmpHostInfo))) == NULL) return;
	  memset(dstHost->icmpInfo, 0, sizeof(IcmpHostInfo));
	}

	incrementTrafficCounter(&dstHost->icmpInfo->icmpMsgRcvd[icmp6Pkt.icmp6_type], 1);
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
	  if(myGlobals.enableSuspiciousPacketDump) {
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
	if(router != NULL) FD_SET(FLAG_GATEWAY_HOST, &router->flags);
      }

      if(icmp6Pkt.icmp6_type == ICMP6_DST_UNREACH /* Destination Unreachable */) {
	struct ip6_hdr *oip = (struct ip6_hdr *)&icmp6Pkt+1;

	switch(icmp6Pkt.icmp6_code) {
	case ICMP6_DST_UNREACH_NOPORT: /* Port Unreachable */
	  memcpy(&dport, ((u_char *)bp+hlen+30), sizeof(dport));
	  dport = ntohs(dport);
	  switch (oip->ip6_nxt) {
	  case IPPROTO_TCP:
	    if(myGlobals.enableSuspiciousPacketDump)
	      traceEvent(CONST_TRACE_WARNING,
			 "Host [%s] sent TCP data to a closed port of host [%s:%d] (scan attempt?)",
			 dstHost->hostResolvedName, srcHost->hostResolvedName, dport);
	    /* Simulation of rejected TCP connection */
	    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	    incrementUsageCounter(&srcHost->secHostPkts->rejectedTCPConnSent, dstHost, actualDeviceId);
	    incrementUsageCounter(&dstHost->secHostPkts->rejectedTCPConnRcvd, srcHost, actualDeviceId);
	    break;

	  case IPPROTO_UDP:
	    if(myGlobals.enableSuspiciousPacketDump)
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
	  if(myGlobals.enableSuspiciousPacketDump)
	    traceEvent(CONST_TRACE_WARNING, /* See http://www.packetfactory.net/firewalk/ */
		       "Host [%s] sent ICMPv6 Administratively Prohibited packet to host [%s]"
		       " (Firewalking scan attempt?)",
		       dstHost->hostResolvedName, srcHost->hostResolvedName);
	  allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
	  incrementUsageCounter(&srcHost->secHostPkts->icmpAdminProhibitedSent, dstHost, actualDeviceId);
	  incrementUsageCounter(&dstHost->secHostPkts->icmpAdminProhibitedRcvd, srcHost, actualDeviceId);
	  break;
	}
	if(myGlobals.enableSuspiciousPacketDump) dumpSuspiciousPacket(actualDeviceId);
      }
    }
    break;

#endif
  default:
    if(srcHost->ipProtosList != NULL) {
      protoList = myGlobals.ipProtosList;
      idx = 0;

      while(protoList != NULL) {
	if((protoList->protocolId == nh)
	   || ((protoList->protocolIdAlias != 0) && (protoList->protocolIdAlias == nh))) {
	  if(srcHost->ipProtosList) incrementTrafficCounter(&srcHost->ipProtosList[idx].sent, length);
	  if(dstHost->ipProtosList) incrementTrafficCounter(&dstHost->ipProtosList[idx].rcvd, length);
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
      if(myGlobals.enableOtherPacketDump) dumpOtherPacket(actualDeviceId);

      if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
      if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));

      incrementTrafficCounter(&srcHost->nonIPTraffic->otherSent, length);
      incrementUnknownProto(srcHost, 0 /* sent */, 0 /* eth */, 0 /* dsap */, 0 /* ssap */, nh);
      incrementTrafficCounter(&dstHost->nonIPTraffic->otherRcvd, length);
      incrementUnknownProto(dstHost, 1 /* rcvd */, 0 /* eth */, 0 /* dsap */, 0 /* ssap */, nh);
    }
    break;
  }

#ifdef INET6
 end:
  ; /* Needed by some compilers */
#endif

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

#ifdef CFG_MULTITHREADED

void queuePacket(u_char *_deviceId,
		 const struct pcap_pkthdr *h,
		 const u_char *p) {
  int len;
  int deviceId;

  /* ***************************
     - If the queue is full then wait until a slot is freed

     - If the queue is getting full then periodically wait
     until a slot is freed
     **************************** */

  myGlobals.receivedPackets++;

  if((p == NULL) || (h == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "Invalid packet received. Skipped.");
  }

#ifdef WIN32_DEMO
  if(myGlobals.receivedPackets >= MAX_NUM_PACKETS)
    return;
#endif

  if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN) return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Got packet from %s (%d)", myGlobals.device[*_deviceId].name, *_deviceId);
#endif

  deviceId = (int)_deviceId;

  incrementTrafficCounter(&myGlobals.device[getActualInterface(deviceId)].receivedPkts, 1);

  if(tryLockMutex(&myGlobals.packetProcessMutex, "queuePacket") == 0) {
    /* Locked so we can process the packet now */
    u_char p1[MAX_PACKET_LEN];

    myGlobals.receivedPacketsProcessed++;

    len = h->caplen;
    if (myGlobals.noFc) {
        /* When we do Fibre Channel, the end of the packet contains EOF
         * information and so truncating it isn't a good idea.
         */
        if(len >= DEFAULT_SNAPLEN) len = DEFAULT_SNAPLEN-1;
    }

    if(h->len >= MAX_PACKET_LEN) {
      traceEvent(CONST_TRACE_WARNING, "packet truncated (%d->%d)", h->len, MAX_PACKET_LEN);
      ((struct pcap_pkthdr*)h)->len = MAX_PACKET_LEN-1;
    }

    if(len >= MAX_PACKET_LEN) {
      bpf_u_int32 *caplen = (bpf_u_int32*)&(h->caplen);

      len = MAX_PACKET_LEN-1;
      /* 
	 Trick needed to avoid compilation errors
	 as caplen is defined as 'const'
      */
      (*caplen) = len;
    }

    memcpy(p1, p, len);

    processPacket(_deviceId, h, p1);
    releaseMutex(&myGlobals.packetProcessMutex);
    return;
  }

  /*
    If we reach this point it means that somebody was already processing
    a packet so we need to queue it
  */

  if(myGlobals.packetQueueLen >= CONST_PACKET_QUEUE_LENGTH) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Dropping packet!!! [packet queue=%d/max=%d]",
	       myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

    myGlobals.receivedPacketsLostQ++;

    incrementTrafficCounter(&myGlobals.device[getActualInterface(deviceId)].droppedPkts, 1);

#ifdef MAKE_WITH_SCHED_YIELD
    sched_yield(); /* Allow other threads (dequeue) to run */
#endif
    HEARTBEAT(0, "queuePacket() drop, sleep(1)...", NULL);
    sleep(1);
    HEARTBEAT(0, "queuePacket() drop, sleep(1)...woke", NULL);
  } else {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "About to queue packet... ");
#endif
    accessMutex(&myGlobals.packetQueueMutex, "queuePacket");
    myGlobals.receivedPacketsQueued++;
    memcpy(&myGlobals.packetQueue[myGlobals.packetQueueHead].h, h, sizeof(struct pcap_pkthdr));
    memset(myGlobals.packetQueue[myGlobals.packetQueueHead].p, 0, sizeof(myGlobals.packetQueue[myGlobals.packetQueueHead].p));
    /* Just to be safe */
    len = h->caplen;
    if (myGlobals.noFc) {
        if(len >= DEFAULT_SNAPLEN) len = DEFAULT_SNAPLEN-1;
        memcpy(myGlobals.packetQueue[myGlobals.packetQueueHead].p, p, len);
        myGlobals.packetQueue[myGlobals.packetQueueHead].h.caplen = len;
    }
    else {
        memcpy(myGlobals.packetQueue[myGlobals.packetQueueHead].p, p, len);
        myGlobals.packetQueue[myGlobals.packetQueueHead].h.caplen = len;
    }

    myGlobals.packetQueue[myGlobals.packetQueueHead].deviceId = (int)((void*)_deviceId);
    myGlobals.packetQueueHead = (myGlobals.packetQueueHead+1) % CONST_PACKET_QUEUE_LENGTH;
    myGlobals.packetQueueLen++;
    if(myGlobals.packetQueueLen > myGlobals.maxPacketQueueLen)
      myGlobals.maxPacketQueueLen = myGlobals.packetQueueLen;
    releaseMutex(&myGlobals.packetQueueMutex);
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Queued packet... [packet queue=%d/max=%d]",
	       myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

#ifdef DEBUG_THREADS
    traceEvent(CONST_TRACE_INFO, "+ [packet queue=%d/max=%d]", myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
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

void* dequeuePacket(void* notUsed _UNUSED_) {
  u_short deviceId;
  struct pcap_pkthdr h;
  u_char p[MAX_PACKET_LEN];

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Packet processor thread running...");

  while(myGlobals.capturePackets == FLAG_NTOPSTATE_RUN) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Waiting for packet...");
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
    traceEvent(CONST_TRACE_INFO, "Got packet...");
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
    if((h.caplen != h.len)
       && (myGlobals.enablePacketDecoding /* Courtesy of Ken Beaty <ken@ait.com> */)) {
      traceEvent (CONST_TRACE_WARNING, "dequeuePacket: caplen %d != len %d\n", h.caplen, h.len);
    }
    if (myGlobals.noFc) {
        memcpy(p, myGlobals.packetQueue[myGlobals.packetQueueTail].p, DEFAULT_SNAPLEN);
    }
    else {
        memcpy(p, myGlobals.packetQueue[myGlobals.packetQueueTail].p, MAX_PACKET_LEN);
    }
    if(h.len > MAX_PACKET_LEN) {
      traceEvent(CONST_TRACE_WARNING, "packet truncated (%d->%d)", h.len, MAX_PACKET_LEN);
      h.len = MAX_PACKET_LEN;
    }

    deviceId = myGlobals.packetQueue[myGlobals.packetQueueTail].deviceId;
    myGlobals.packetQueueTail = (myGlobals.packetQueueTail+1) % CONST_PACKET_QUEUE_LENGTH;
    myGlobals.packetQueueLen--;
    releaseMutex(&myGlobals.packetQueueMutex);
#ifdef DEBUG_THREADS
    traceEvent(CONST_TRACE_INFO, "- [packet queue=%d/max=%d]", myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Processing packet... [packet queue=%d/max=%d]",
	       myGlobals.packetQueueLen, myGlobals.maxPacketQueueLen);
#endif

    HEARTBEAT(9, "dequeuePacket()...processing...", NULL);
    myGlobals.actTime = time(NULL);
    accessMutex(&myGlobals.packetProcessMutex, "dequeuePacket");
    processPacket((u_char*)((long)deviceId), &h, p);
    releaseMutex(&myGlobals.packetProcessMutex);
  }

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Packet Processor thread (%ld) terminated...", myGlobals.dequeueThreadId);
  return(NULL);
}

#endif /* CFG_MULTITHREADED */


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
  int deviceId, actualDeviceId, vlanId=-1;
  static time_t lastUpdateThptTime = 0;
#ifdef LINUX
  AnyHeader *anyHeader;
#endif

#ifdef MEMORY_DEBUG
  if(0) {
    static long numPkt=0;

    /* traceEvent(CONST_TRACE_INFO, "%ld (%ld)", numPkt, length); */

    if(numPkt ==  /* 10000 */ 1000) {
      cleanup(2);
    } else
      numPkt++;
  } else {
    static time_t start=0;

    if(start == 0)
      start = time(NULL)+1*60; /* 15 minutes */
    else {
      if(time(NULL) > start)
	cleanup(2);
    }
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

  deviceId = (int)_deviceId;

  actualDeviceId = getActualInterface(deviceId);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "deviceId=%d - actualDeviceId=%ld", deviceId, actualDeviceId);
#endif

  updateDevicePacketStats(length, actualDeviceId);

  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ethernetPkts, 1);
  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ethernetBytes, h->len);

  if(myGlobals.mergeInterfaces && actualDeviceId != deviceId)
    incrementTrafficCounter(&myGlobals.device[deviceId].ethernetPkts, 1);

  if(myGlobals.device[actualDeviceId].pcapDumper != NULL)
    pcap_dump((u_char*)myGlobals.device[actualDeviceId].pcapDumper, h, p);

  if((myGlobals.device[deviceId].mtuSize != CONST_UNKNOWN_MTU) &&
     (length > myGlobals.device[deviceId].mtuSize) ) {
    /* Sanity check */
    if(myGlobals.enableSuspiciousPacketDump) {
      traceEvent(CONST_TRACE_WARNING, "Packet # %u too long (len = %u)!",
		 (unsigned int)myGlobals.device[deviceId].ethernetPkts.value,
		 (unsigned int)length);
      dumpSuspiciousPacket(actualDeviceId);
    }

    /* Fix below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
    length = myGlobals.device[deviceId].mtuSize;
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdPktStats.tooLong, 1);
  }

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.hostsHashMutex, "processPacket");
#endif

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

  if (!myGlobals.initialSniffTime && (myGlobals.rFileName != NULL)) {
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
#ifdef CFG_MULTITHREADED
	      releaseMutex(&myGlobals.hostsHashMutex);
#endif
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
      if((!myGlobals.dontTrustMACaddr) && (eth_type == 0x8137)) {
	/* IPX */
	IPXpacket ipxPkt;

	srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId);
	if(srcHost == NULL) {
	  /* Sanity check */
	  if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (5) [Low memory?]");
#ifdef CFG_MULTITHREADED
	  releaseMutex(&myGlobals.hostsHashMutex);
#endif
	  lowMemoryMsgShown = 1;
	  return;
	}

	dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId);
	if(dstHost == NULL) {
	  /* Sanity check */
	  if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (6) [Low memory?]");
#ifdef CFG_MULTITHREADED
	  releaseMutex(&myGlobals.hostsHashMutex);
#endif
	  lowMemoryMsgShown = 1;
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
	  
	  if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	  if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));

	  incrementTrafficCounter(&srcHost->nonIPTraffic->ipxSent, length), incrementTrafficCounter(&dstHost->nonIPTraffic->ipxRcvd, length);
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
#ifdef CFG_MULTITHREADED
	  releaseMutex(&myGlobals.hostsHashMutex);
#endif
	  lowMemoryMsgShown = 1;
	  return;
	}

	dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId);
	if(dstHost == NULL) {
	  /* Sanity check */
	  if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (8) [Low memory?]");
#ifdef CFG_MULTITHREADED
	  releaseMutex(&myGlobals.hostsHashMutex);
#endif
	  lowMemoryMsgShown = 1;
	  return;
	}

	if(vlanId != -1) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }

	if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	
	incrementTrafficCounter(&srcHost->nonIPTraffic->otherSent, length);
	incrementTrafficCounter(&dstHost->nonIPTraffic->otherRcvd, length);
	incrementUnknownProto(srcHost, 0 /* sent */, eth_type /* eth */, 0 /* dsap */, 0 /* ssap */, 0 /* ip */);
	incrementUnknownProto(dstHost, 1 /* rcvd */, eth_type /* eth */, 0 /* dsap */, 0 /* ssap */, 0 /* ip */);
	if(myGlobals.enableOtherPacketDump) dumpOtherPacket(actualDeviceId);

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
	   && (!myGlobals.dontTrustMACaddr)
	   && (strcmp(etheraddr_string(ether_dst, etherbuf), "FF:FF:FF:FF:FF:FF") == 0)
	   && (p[sizeof(struct ether_header)] == 0xff)
	   && (p[sizeof(struct ether_header)+1] == 0xff)
	   && (p[sizeof(struct ether_header)+4] == 0x0)) {
	  /* IPX */

	  srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId);
	  if(srcHost == NULL) {
	    /* Sanity check */
	    if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (9) [Low memory?]");
#ifdef CFG_MULTITHREADED
	    releaseMutex(&myGlobals.hostsHashMutex);
#endif
	    lowMemoryMsgShown = 1;
	    return;
	  }

	  dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId);
	  if(dstHost == NULL) {
	    /* Sanity check */
	    if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (10) [Low memory?]");
#ifdef CFG_MULTITHREADED
	    releaseMutex(&myGlobals.hostsHashMutex);
#endif
	    lowMemoryMsgShown = 1;
	    return;
	  }

	  if(vlanId != -1) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }

	  if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	  if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));	  
	  incrementTrafficCounter(&srcHost->nonIPTraffic->ipxSent, length);
	  incrementTrafficCounter(&dstHost->nonIPTraffic->ipxRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipxBytes, length);
	} else if(!myGlobals.dontTrustMACaddr) {
	  /* MAC addresses are meaningful here */
	  srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId);
	  dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId);
	  
	  if((srcHost != NULL) && (dstHost != NULL)) {
	    TrafficCounter ctr;

	    if(vlanId != -1) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }
	    p1 = (u_char*)(p+hlen);

	    /* Watch out for possible alignment problems */
	    memcpy(&llcHeader, (char*)p1, min(length, sizeof(llcHeader)));

	    sap_type = llcHeader.ssap & ~CONST_LLC_GSAP;
	    llcsap_string(sap_type);

	    if((sap_type == 0xAA /* SNAP */)
	       && (llcHeader.ctl.snap_ether.snap_orgcode[0] == 0x0)
	       && (llcHeader.ctl.snap_ether.snap_orgcode[1] == 0x0)
	       && (llcHeader.ctl.snap_ether.snap_orgcode[2] == 0xc) /* 0x00000C = Cisco */
	       && (llcHeader.ctl.snap_ether.snap_ethertype[0] == 0x20)
	       && (llcHeader.ctl.snap_ether.snap_ethertype[1] == 0x00) /* 0x2000 Cisco Discovery Protocol */
	       ) {
	      if(srcHost->fingerprint == NULL)
		srcHost->fingerprint = strdup(":Cisco");
	    }

	    if(sap_type != 0x42 /* !STP */) {
	      addNonIpTrafficInfo(srcHost, sap_type, length, 0 /* sent */);
	      addNonIpTrafficInfo(dstHost, sap_type, length, 1 /* rcvd */);
	    }

	    if(sap_type == 0x42 /* STP */) {
	      /* Spanning Tree */

	      if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	      if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	      incrementTrafficCounter(&srcHost->nonIPTraffic->stpSent, length), 
		 incrementTrafficCounter(&dstHost->nonIPTraffic->stpRcvd, length);
	      FD_SET(FLAG_HOST_TYPE_SVC_BRIDGE, &srcHost->flags);
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

	      if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	      if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));

	      incrementTrafficCounter(&srcHost->nonIPTraffic->ipxSent, length),
		incrementTrafficCounter(&dstHost->nonIPTraffic->ipxRcvd, length);
	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipxBytes, length);
	    } else if((llcHeader.ssap == LLCSAP_NETBIOS) && (llcHeader.dsap == LLCSAP_NETBIOS)) {
	      /* Netbios */
	      if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	      if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	      incrementTrafficCounter(&srcHost->nonIPTraffic->netbiosSent, length);
	      incrementTrafficCounter(&dstHost->nonIPTraffic->netbiosRcvd, length);
	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].netbiosBytes, length);
	    } else if((sap_type == 0xF0)
		      || (sap_type == 0xB4)
		      || (sap_type == 0xC4)
		      || (sap_type == 0xF8)) {
	      /* DLC (protocol used for printers) */
	      if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	      if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	      incrementTrafficCounter(&srcHost->nonIPTraffic->dlcSent, length);
	      incrementTrafficCounter(&dstHost->nonIPTraffic->dlcRcvd, length);
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

		if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
		if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
		
		incrementTrafficCounter(&srcHost->nonIPTraffic->appletalkSent, length);
		incrementTrafficCounter(&dstHost->nonIPTraffic->appletalkRcvd, length);
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

		if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
		if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
		
		incrementTrafficCounter(&srcHost->nonIPTraffic->otherSent, length);
		incrementTrafficCounter(&dstHost->nonIPTraffic->otherRcvd, length);
		incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherBytes, length);

		incrementUnknownProto(srcHost, 0 /* sent */, 0 /* eth */, llcHeader.dsap /* dsap */,
				      llcHeader.ssap /* ssap */, 0 /* ip */);
		incrementUnknownProto(dstHost, 1 /* rcvd */, 0 /* eth */, llcHeader.dsap /* dsap */,
				      llcHeader.ssap /* ssap */, 0 /* ip */);
		if(myGlobals.enableOtherPacketDump) dumpOtherPacket(actualDeviceId);
	      }
	    } else if(myGlobals.enablePacketDecoding
		      && ((sap_type == 0x06)
			  || (sap_type == 0xFE)
			  || (sap_type == 0xFC))) {  /* OSI */

	      if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	      if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	      
	      incrementTrafficCounter(&srcHost->nonIPTraffic->osiSent, length);
	      incrementTrafficCounter(&dstHost->nonIPTraffic->osiRcvd, length);
	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].osiBytes, length);
	    } else {
	      /* Unknown Protocol */
#ifdef UNKNOWN_PACKET_DEBUG
	      traceEvent(CONST_TRACE_INFO, "UNKNOWN_PACKET_DEBUG: [%u] [%x] %s %s > %s",
			 (u_short)sap_type,(u_short)sap_type,
			 etheraddr_string(ether_src, etherbuf),
			 llcsap_string(llcHeader.ssap & ~CONST_LLC_GSAP),
			 etheraddr_string(ether_dst, etherbuf));
#endif

	      if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	      if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));	      
	      incrementTrafficCounter(&srcHost->nonIPTraffic->otherSent, length);
	      incrementTrafficCounter(&dstHost->nonIPTraffic->otherRcvd, length);

	      incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherBytes, length);
	      incrementUnknownProto(srcHost, 0 /* sent */, 0 /* eth */, llcHeader.dsap /* dsap */,
				    llcHeader.ssap /* ssap */, 0 /* ip */);
	      incrementUnknownProto(dstHost, 1 /* rcvd */, 0 /* eth */, llcHeader.dsap /* dsap */,
				    llcHeader.ssap /* ssap */, 0 /* ip */);
	      if(myGlobals.enableOtherPacketDump) dumpOtherPacket(actualDeviceId);
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
      } else if (((eth_type == ETHERTYPE_MDSHDR) || (eth_type == ETHERTYPE_BRDWLK) ||
                  (eth_type == ETHERTYPE_UNKNOWN) || (eth_type == ETHERTYPE_BRDWLK_OLD)) &&
                 (!myGlobals.noFc)) {
          /* An FC packet can be captured as Ethernet for three different
           * Ethertypes.
           */
          processFcPkt (p, h, eth_type, actualDeviceId);
      } else if((eth_type == ETHERTYPE_IP) || (eth_type == ETHERTYPE_IPv6)) {
	if((myGlobals.device[deviceId].datalink == DLT_IEEE802) && (eth_type > ETHERMTU))
	  processIpPkt(p, h, length, ether_src, ether_dst, actualDeviceId, vlanId);
	else
	  processIpPkt(p+hlen, h, length, ether_src, ether_dst, actualDeviceId, vlanId);
      } else if(eth_type == 0x8864) /* PPPOE */ {
        /* PPPoE - Courtesy of Andreas Pfaller Feb2003
         *   This strips the PPPoE encapsulation for traffic transiting the network.
         */
        struct pppoe_hdr *pppoe_hdr=(struct pppoe_hdr *) (p+hlen);
        int protocol=ntohs(*((int *) (p+hlen+6)));

        if(pppoe_hdr->ver==1 && pppoe_hdr->type==1 && pppoe_hdr->code==0 &&
            protocol==0x0021) {
          hlen+=8; /* length of pppoe header */
	  processIpPkt(p+hlen, h, length, NULL, NULL, actualDeviceId, vlanId);
        }
      } else  /* Non IP */ if(!myGlobals.dontTrustMACaddr) {
	/* MAC addresses are meaningful here */
	struct ether_arp arpHdr;
	HostAddr addr;
	TrafficCounter ctr;
	char buf[32];

	if(length > hlen)
	  length -= hlen;
	else
	  length = 0;

	srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId);
	if(srcHost == NULL) {
	  /* Sanity check */
	  if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (11) [Low memory?]");
#ifdef CFG_MULTITHREADED
	  releaseMutex(&myGlobals.hostsHashMutex);
#endif
	  lowMemoryMsgShown = 1;
	  return;
	}

	dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId);
	if(dstHost == NULL) {
	  /* Sanity check */
	  if(!lowMemoryMsgShown) traceEvent(CONST_TRACE_ERROR, "Sanity check failed (12) [Low memory?]");
#ifdef CFG_MULTITHREADED
	  releaseMutex(&myGlobals.hostsHashMutex);
#endif
	  lowMemoryMsgShown = 1;
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
	      addr.hostFamily = AF_INET;
	      memcpy(&addr.Ip4Address.s_addr, &arpHdr.arp_tpa, sizeof(struct in_addr));
	      addr.Ip4Address.s_addr = ntohl(addr.Ip4Address.s_addr);
	      dstHost = lookupHost(&addr, (u_char*)&arpHdr.arp_tha, vlanId, 0, 0, actualDeviceId);
	      memcpy(&addr.Ip4Address.s_addr, &arpHdr.arp_spa, sizeof(struct in_addr));
	      addr.Ip4Address.s_addr = ntohl(addr.Ip4Address.s_addr);
	      srcHost = lookupHost(&addr, (u_char*)&arpHdr.arp_sha, vlanId, 0, 0, actualDeviceId);
	      if(srcHost != NULL) {
		if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
		incrementTrafficCounter(&srcHost->nonIPTraffic->arpReplyPktsSent, 1);
	      }

	      if(dstHost != NULL) {
		if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
		incrementTrafficCounter(&dstHost->nonIPTraffic->arpReplyPktsRcvd, 1);
	      }
	      /* DO NOT ADD A break ABOVE ! */
	    case ARPOP_REQUEST: /* ARP request */
	      if(srcHost != NULL) {
		srcHost->hostIpAddress.hostFamily = AF_INET;
		memcpy(&srcHost->hostIpAddress.Ip4Address.s_addr, arpHdr.arp_spa, sizeof(struct in_addr));
		srcHost->hostIpAddress.Ip4Address.s_addr = ntohl(srcHost->hostIpAddress.Ip4Address.s_addr);
		setHostSerial(srcHost);
		strncpy(srcHost->hostNumIpAddress,
			_addrtostr(&srcHost->hostIpAddress, buf, sizeof(buf)),
			sizeof(srcHost->hostNumIpAddress));
		setResolvedName(srcHost, srcHost->hostNumIpAddress, FLAG_HOST_SYM_ADDR_TYPE_IP);

		if(myGlobals.numericFlag == 0)
		  ipaddr2str(srcHost->hostIpAddress, 1);

		if(isPseudoLocalAddress(&srcHost->hostIpAddress, actualDeviceId)) {
		  FD_SET(FLAG_SUBNET_LOCALHOST, &srcHost->flags);
		  FD_SET(FLAG_SUBNET_PSEUDO_LOCALHOST, &srcHost->flags);
		} else {
		  FD_CLR(FLAG_SUBNET_LOCALHOST, &srcHost->flags);
		  FD_CLR(FLAG_SUBNET_PSEUDO_LOCALHOST, &srcHost->flags);
		}

		if((arpOp == ARPOP_REQUEST) && (srcHost != NULL)) {
		  if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
		  incrementTrafficCounter(&srcHost->nonIPTraffic->arpReqPktsSent, 1);
		}
	      }
	    }
	  }
	  /* DO NOT ADD A break ABOVE ! */
	case ETHERTYPE_REVARP: /* Reverse ARP */

	  if(srcHost != NULL) {
	    if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	    incrementTrafficCounter(&srcHost->nonIPTraffic->arp_rarpSent, length);
	  }
	  
	  if(dstHost != NULL) {
	    if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	    incrementTrafficCounter(&dstHost->nonIPTraffic->arp_rarpRcvd, length);
	  }
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].arpRarpBytes, length);
	  break;
	case ETHERTYPE_DN: /* Decnet */
	  if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	  if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));	      
	  
	  incrementTrafficCounter(&srcHost->nonIPTraffic->decnetSent, length);
	  incrementTrafficCounter(&dstHost->nonIPTraffic->decnetRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].decnetBytes, length);
	  break;
	case ETHERTYPE_ATALK: /* AppleTalk */
	case ETHERTYPE_AARP:
	  if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	  if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));	      
	  
	  incrementTrafficCounter(&srcHost->nonIPTraffic->appletalkSent, length);
	  incrementTrafficCounter(&dstHost->nonIPTraffic->appletalkRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].atalkBytes, length);
	  break;
	case ETHERTYPE_IPv6:
	  processIpPkt(p+hlen, h, length, ether_src, ether_dst, actualDeviceId, vlanId);
	  incrementTrafficCounter(&srcHost->ipv6Sent, length);
	  incrementTrafficCounter(&dstHost->ipv6Rcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipv6Bytes, length);
	  break;
	default:
#ifdef UNKNOWN_PACKET_DEBUG
	  traceEvent(CONST_TRACE_INFO, "UNKNOWN_PACKET_DEBUG: %s/%s->%s/%s [eth type %d (0x%x)]",
		     srcHost->hostNumIpAddress, srcHost->ethAddressString,
		     dstHost->hostNumIpAddress, dstHost->ethAddressString,
		     eth_type, eth_type);
#endif
	  if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	  if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));	      

	  incrementTrafficCounter(&srcHost->nonIPTraffic->otherSent, length);
	  incrementTrafficCounter(&dstHost->nonIPTraffic->otherRcvd, length);
	  incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherBytes, length);
	  incrementUnknownProto(srcHost, 0 /* sent */, eth_type /* eth */, 0 /* dsap */,
				0 /* ssap */, 0 /* ip */);
	  incrementUnknownProto(dstHost, 1 /* rcvd */, eth_type /* eth */, 0 /* dsap */,
				0 /* ssap */, 0 /* ip */);
	  if(myGlobals.enableOtherPacketDump) dumpOtherPacket(actualDeviceId);
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
  } else {
    /*  count runts somehow? */
  }

  if(myGlobals.flowsList != NULL) /* Handle flows last */
    flowsProcess(h, p, deviceId);

#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.hostsHashMutex);
#endif

  if (myGlobals.rFileName != NULL) {
      if (myGlobals.actTime > (lastUpdateThptTime + PARM_THROUGHPUT_REFRESH_INTERVAL)) {
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

void updateFcDevicePacketStats(u_int length, int actualDeviceId) {
  if(length <= 36)        incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdFcPktStats.upTo36, 1);
  else if(length <= 48)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdFcPktStats.upTo48, 1);
  else if(length <= 52)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdFcPktStats.upTo52, 1);
  else if(length <= 68)  incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdFcPktStats.upTo68, 1);
  else if(length <= 104) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdFcPktStats.upTo104, 1);
  else if(length <= 548) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdFcPktStats.upTo548, 1);
  else if(length <= 1048) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdFcPktStats.upTo1060, 1);
  else if(length <= 2136) incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdFcPktStats.upTo2136, 1);
  else incrementTrafficCounter(&myGlobals.device[actualDeviceId].rcvdFcPktStats.above2136, 1);

  if((myGlobals.device[actualDeviceId].rcvdFcPktStats.shortest.value == 0)
     || (myGlobals.device[actualDeviceId].rcvdFcPktStats.shortest.value > length))
    myGlobals.device[actualDeviceId].rcvdFcPktStats.shortest.value = length;

  if(myGlobals.device[actualDeviceId].rcvdFcPktStats.longest.value < length)
    myGlobals.device[actualDeviceId].rcvdFcPktStats.longest.value = length;
}

/* ************************************ */

static void processFcPkt(const u_char *bp,
			 const struct pcap_pkthdr *h,
			 u_int16_t ethertype,
			 int actualDeviceId)
{
    FcHeaderAlign *hdralign;
    FcHeader fchdr;
    FcAddress srcFcAddr, dstFcAddr;
    u_char *hdrBytes;
    u_int16_t payload_len = h->len - 14; /* FC length = pkt len - arpa hdr len */
    u_int16_t totlen = h->len;
    u_int16_t actLen = h->caplen; /* Used when pcap truncates frames  */
    char *proto;
    u_short protocol;
    HostTraffic *srcHost=NULL, *dstHost=NULL;
    TrafficCounter ctr;
    u_int32_t offset = 14;      /* start past the ethernet header */
    uint16_t vsanId = 0,
             fcFrameLen = 0;
    uint8_t sof = 0, eof = 0, error = 0;
#if CFG_LITTLE_ENDIAN
    uint16_t didx;        /* source & dest port indices on MDS */
#endif
    u_char isFirstFrame = FALSE,
           isLastFrame = FALSE,
           isFragment = FALSE;
    u_char gs_type, gs_stype, isXchgOrig;
    u_int16_t nsOpcode;

    /* Deal with Vegas Header or Boardwalk Header based on ethertype */
    if ((ethertype == ETHERTYPE_BRDWLK) ||
        (ethertype == ETHERTYPE_BRDWLK_OLD)) {
        sof = (bp[offset] & 0xF0) >> 4;
        vsanId = ntohs (*(u_int16_t *)&bp[offset]) & 0x0FFF;
        eof = bp[totlen-1];
        error = bp[totlen-2];
        offset += 2;            /* skip the brdwlk hdr field */

        if ((error & 0x8) && (error & 0x1)) {
            /* This indicates that Boardwalk carries the original FC
             * length even though the frame is truncated */
            payload_len = ntohl (*(u_int32_t *)&bp[payload_len+14-8]);
            payload_len *= 4;
        }
        /* If VSAN is not 0, there is an EISL header; skip it */
        if (vsanId) {
            offset += 8;
            payload_len -= 8;
        }

        if ((error & 0x8) && (error & 0x1)) {
            fcFrameLen = payload_len;
            /* Skip CRC incl payload len */
            payload_len -= (FC_HDR_SIZE + 4);
        }
        else {
            fcFrameLen = payload_len - 6; /* Brdwlk hdr + trlr */
            /* Skip Brdwlk header & trlr & CRC incl payload len */
            payload_len -= (FC_HDR_SIZE + 6); /* TBD: Handle optional headers */
        }
    }
    else if ((ethertype == ETHERTYPE_UNKNOWN) || (ethertype == ETHERTYPE_MDSHDR)) {
#if CFG_LITTLE_ENDIAN
        sof = (bp[offset+1] & 0x0F);
        fcFrameLen = ntohs (*((u_int16_t *)&bp[offset+2]));
        vsanId = ntohs (*(u_int16_t *)&bp[offset+14] & 0x0FFF);
        didx =   ntohs (*((u_int16_t *)&bp[offset+6]) & 0x1FF8) >> 3;
#else
        sof = bp[offset+1] & 0x0F;
        fcFrameLen = ntohs ((*(u_int16_t *)&bp[offset+3]) & 0x1FFF);
        vsanId = ntohs ((*(u_int16_t *)&bp[offset+14]) & 0x0FFF);
#endif
        eof = bp[offset+MDSHDR_HEADER_SIZE+fcFrameLen-MDSHDR_TRAILER_SIZE];

        offset += MDSHDR_HEADER_SIZE;
        payload_len -= (MDSHDR_HEADER_SIZE + MDSHDR_TRAILER_SIZE+FC_HDR_SIZE);
    }

    memcpy(&fchdr, bp+offset, sizeof(FcHeader));
    hdralign = (FcHeaderAlign *)&fchdr;
    hdrBytes = (u_char *)&fchdr;

#if CFG_LITTLE_ENDIAN
    memcpy (&srcFcAddr, &hdrBytes[5], 3);
    memcpy (&dstFcAddr, &hdrBytes[1], 3);
#else
    memcpy (&srcFcAddr, &hdrBytes[5], 3);
    memcpy (&dstFcAddr, &hdrBytes[1], 3);
#endif
    isFirstFrame = ((sof == MDSHDR_SOFi2) || (sof == MDSHDR_SOFi3) ||
                    ((sof == MDSHDR_SOFf) && (fchdr.seq_cnt == 0)));
    isLastFrame  = (eof != MDSHDR_EOFn);

    /* This is bit 23 of F_CTL which indicates whether the S_ID is the
     * originator of the exchange or the responder.
     */
    isXchgOrig = (bp[offset+9] & 0x80) ? 0 : 1;

    /* Unless a frame is truncated by libpcap, we should have valid EOF */
    if ((actLen == h->len) && (eof != MDSHDR_EOFn) && (eof != MDSHDR_EOFt)) {
        incrementTrafficCounter (&myGlobals.device[actualDeviceId].rcvdFcPktStats.badCRC, 1);
        if (myGlobals.enableSuspiciousPacketDump) {
            traceEvent(CONST_TRACE_WARNING, "Bad EOF Frame Received");
            dumpSuspiciousPacket(actualDeviceId);
        }
        if (eof == MDSHDR_EOFa) {
            incrementTrafficCounter(&myGlobals.device[actualDeviceId].fcEofaPkts, 1);
        }
        else {
            incrementTrafficCounter(&myGlobals.device[actualDeviceId].fcEofAbnormalPkts, 1);
        }
    }

    incrementTrafficCounter(&myGlobals.device[actualDeviceId].fcPkts, 1);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].fcBytes, fcFrameLen);

    dstHost = lookupFcHost (&dstFcAddr, vsanId, actualDeviceId);
    srcHost = lookupFcHost (&srcFcAddr, vsanId, actualDeviceId);

    if(srcHost == NULL) {
        /* Sanity check */
        traceEvent(CONST_TRACE_ERROR, "Sanity check failed (1) [Low memory?]");
        return; /* It might be that there's not enough memory that that
                   dstHostIdx = getHostInfo(&ip.ip_dst, ether_dst) caused
                   srcHost to be freed */
    }

    if(dstHost == NULL) {
        /* Sanity check */
        traceEvent(CONST_TRACE_ERROR, "Sanity check failed (2) [Low memory?]");
        return;
    }

    if (strncasecmp (dstHost->fcCounters->hostNumFcAddress, FC_BROADCAST_ADDR,
                     strlen (FC_BROADCAST_ADDR)) == 0) {
        incrementTrafficCounter(&myGlobals.device[actualDeviceId].fcBroadcastPkts, 1);
        incrementTrafficCounter(&myGlobals.device[actualDeviceId].fcBroadcastBytes, fcFrameLen);
    }

    updateFcDevicePacketStats(fcFrameLen, actualDeviceId);

    ctr.value = fcFrameLen;
    updatePacketCount(srcHost, NULL, dstHost, NULL, ctr, 1, actualDeviceId);

#ifdef NOT_YET
    updateTrafficMatrix (srcHost, dstHost, ctr, actualDeviceId);
#endif

    incrementTrafficCounter(&srcHost->fcCounters->fcBytesSent, fcFrameLen);
    incrementTrafficCounter(&dstHost->fcCounters->fcBytesRcvd, fcFrameLen);

    /* Class-Based Stats */
    if ((sof == MDSHDR_SOFi3) || (sof == MDSHDR_SOFn3)) {
      incrementTrafficCounter (&srcHost->fcCounters->class3Sent, fcFrameLen);
        incrementTrafficCounter (&dstHost->fcCounters->class3Rcvd, fcFrameLen);
        incrementTrafficCounter (&myGlobals.device[actualDeviceId].class2Bytes, fcFrameLen);
    }
    else if ((sof == MDSHDR_SOFi2) || (sof == MDSHDR_SOFn2)) {
        incrementTrafficCounter (&srcHost->fcCounters->class2Sent, fcFrameLen);
        incrementTrafficCounter (&dstHost->fcCounters->class2Rcvd, fcFrameLen);
        incrementTrafficCounter (&myGlobals.device[actualDeviceId].class3Bytes, fcFrameLen);
    }
    else if (sof == MDSHDR_SOFf) {
        incrementTrafficCounter (&srcHost->fcCounters->classFSent, fcFrameLen);
        incrementTrafficCounter (&dstHost->fcCounters->classFRcvd, fcFrameLen);
        incrementTrafficCounter (&myGlobals.device[actualDeviceId].classFBytes, fcFrameLen);
    }

    isFragment = isFirstFrame && !(isLastFrame);

    if (isFragment) {
        incrementTrafficCounter(&myGlobals.device[actualDeviceId].fragmentedFcBytes, fcFrameLen);
    }

    protocol = getFcProtocol (fchdr.r_ctl, fchdr.type);

    if (protocol <= FC_FTYPE_UNDEF) {
        proto = fcProtocolStrings[protocol];
    }

    switch (protocol) {
    case FC_FTYPE_SWILS:
    case FC_FTYPE_SWILS_RSP:
        incrementTrafficCounter (&srcHost->fcCounters->fcSwilsBytesSent, fcFrameLen);
        incrementTrafficCounter (&dstHost->fcCounters->fcSwilsBytesRcvd, fcFrameLen);
        incrementTrafficCounter (&myGlobals.device[actualDeviceId].fcSwilsBytes, fcFrameLen);
        break;
    case FC_FTYPE_IP:
        incrementTrafficCounter (&srcHost->fcCounters->fcIpfcBytesSent, fcFrameLen);
        incrementTrafficCounter (&dstHost->fcCounters->fcIpfcBytesRcvd, fcFrameLen);
        incrementTrafficCounter (&myGlobals.device[actualDeviceId].fcIpfcBytes, fcFrameLen);
        break;
    case FC_FTYPE_SCSI:
        incrementTrafficCounter (&srcHost->fcCounters->fcFcpBytesSent, fcFrameLen);
        incrementTrafficCounter (&dstHost->fcCounters->fcFcpBytesRcvd, fcFrameLen);
        incrementTrafficCounter (&myGlobals.device[actualDeviceId].fcFcpBytes, fcFrameLen);

        if ((fchdr.r_ctl & 0xF) == FCP_IU_CMD) {
            /* We deal with command frames only for now */
            fillFcpInfo (&bp[offset+24], srcHost, dstHost);
        }
        break;
    case FC_FTYPE_ELS:
        if (isPlogi (fchdr.r_ctl, fchdr.type, bp[offset+24])) {
            fillFcHostInfo (&bp[offset+24], srcHost);
        }
        incrementTrafficCounter (&srcHost->fcCounters->fcElsBytesSent, fcFrameLen);
        incrementTrafficCounter (&dstHost->fcCounters->fcElsBytesRcvd, fcFrameLen);
        incrementTrafficCounter (&myGlobals.device[actualDeviceId].fcElsBytes, fcFrameLen);

        /* Count RSCNs separately */
        if (isRscn (fchdr.r_ctl, fchdr.type, bp[offset+24])) {
            incrementTrafficCounter (&dstHost->fcCounters->fcRscnsRcvd, fcFrameLen);
        }

        break;
    case FC_FTYPE_FCCT:
        gs_type = bp[offset+24+4];
        gs_stype = bp[offset+24+5];

        if (((gs_type == FCCT_GSTYPE_DIRSVC) && (gs_stype == FCCT_GSSUBTYPE_DNS)) ||
            ((gs_type == FCCT_GSTYPE_MGMTSVC) && (gs_stype == FCCT_GSSUBTYPE_UNS))) {
            nsOpcode = ntohs (*(u_int16_t *)&bp[offset+24+8]);

            /* Use registration information to save more information about
             * device.
             */
            switch(nsOpcode) {
            case FCDNS_RNN_ID:
	      strncpy (srcHost->fcCounters->nWWN.str, &bp[offset+24+16+4], LEN_WWN_ADDRESS);
	      break;
            }

            incrementTrafficCounter (&srcHost->fcCounters->fcDnsBytesSent, fcFrameLen);
            incrementTrafficCounter (&dstHost->fcCounters->fcDnsBytesRcvd, fcFrameLen);
            incrementTrafficCounter (&myGlobals.device[actualDeviceId].fcDnsBytes, fcFrameLen);

        }
        else {
	  incrementTrafficCounter (&srcHost->fcCounters->otherFcBytesSent, fcFrameLen);
            incrementTrafficCounter (&dstHost->fcCounters->otherFcBytesRcvd, fcFrameLen);
            incrementTrafficCounter (&myGlobals.device[actualDeviceId].otherFcBytes, fcFrameLen);
        }
        break;
    case FC_FTYPE_SBCCS:
        incrementTrafficCounter (&srcHost->fcCounters->fcFiconBytesSent, fcFrameLen);
        incrementTrafficCounter (&dstHost->fcCounters->fcFiconBytesRcvd, fcFrameLen);
        incrementTrafficCounter (&myGlobals.device[actualDeviceId].fcFiconBytes, fcFrameLen);
        break;
    case FC_FTYPE_LINKDATA:
    case FC_FTYPE_VDO:
    case FC_FTYPE_LINKCTL:
    case FC_FTYPE_BLS:
    default:
        incrementTrafficCounter(&myGlobals.device[actualDeviceId].otherFcBytes, fcFrameLen);
        incrementTrafficCounter(&srcHost->fcCounters->otherFcBytesSent, fcFrameLen);
        incrementTrafficCounter(&dstHost->fcCounters->otherFcBytesRcvd, fcFrameLen);
        break;
    }

    /* Update VSAN-based stats */
    allocateElementHash(actualDeviceId, 2 /* VSAN hash */);
    updateFcFabricElementHash (myGlobals.device[actualDeviceId].vsanHash,
                               vsanId, &bp[offset+24], &srcFcAddr, &dstFcAddr,
                               protocol, fchdr.r_ctl, fcFrameLen);

    /* Update Session stats */
    handleFcSession (h, FALSE, srcHost, dstHost, fcFrameLen, payload_len,
                     ntohs(fchdr.oxid), ntohs (fchdr.rxid), protocol,
                     fchdr.r_ctl, isXchgOrig, &bp[offset+24], actualDeviceId);
}

/* ************************************ */

