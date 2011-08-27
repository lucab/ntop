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

static void addContactedPeers(HostTraffic *sender, HostAddr *srcAddr,
			      HostTraffic *receiver, HostAddr *dstAddr,
			      int actualDeviceId) {
  if((sender == NULL) || (receiver == NULL) || (sender == receiver)) {
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
    incrementHostTrafficCounter(srcHost, pktsSent, numPkts);
    incrementHostTrafficCounter(srcHost, pktsSentSession, numPkts);

    allocHostTrafficCounterMemory(srcHost, trafficDistribution, sizeof(TrafficDistribution));
    if(srcHost->trafficDistribution == NULL) return;
    incrementHostTrafficCounter(srcHost, trafficDistribution->last24HoursBytesSent[hourId], bytes.value);
    incrementHostTrafficCounter(srcHost, bytesSent, bytes.value);
    incrementHostTrafficCounter(srcHost, bytesSentSession, bytes.value);
  }

  if(dstHost != myGlobals.otherHostEntry) {
    incrementHostTrafficCounter(dstHost, pktsRcvd, numPkts);
    incrementHostTrafficCounter(dstHost, pktsRcvdSession, numPkts);

    allocHostTrafficCounterMemory(dstHost, trafficDistribution, sizeof(TrafficDistribution));
    if(dstHost->trafficDistribution == NULL) return;
    incrementHostTrafficCounter(dstHost, trafficDistribution->last24HoursBytesRcvd[hourId], bytes.value);
    incrementHostTrafficCounter(dstHost, bytesRcvd, bytes.value);
    incrementHostTrafficCounter(dstHost, bytesRcvdSession, bytes.value);
  }

  if(broadcastHost(dstHost)) {
    if(srcHost != myGlobals.otherHostEntry) {
      incrementHostTrafficCounter(srcHost, pktsBroadcastSent, numPkts);
      incrementHostTrafficCounter(srcHost, bytesBroadcastSent, bytes.value);
    }
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].broadcastPkts, numPkts);
  } else if(isMulticastAddress(&(dstHost->hostIpAddress), NULL, NULL)) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "%s->%s",
	       srcHost->hostResolvedName, dstHost->hostResolvedName);
#endif
    if(srcHost != myGlobals.otherHostEntry) {
      incrementHostTrafficCounter(srcHost, pktsMulticastSent, numPkts);
      incrementHostTrafficCounter(srcHost, bytesMulticastSent, bytes.value);
    }

    if(dstHost != myGlobals.otherHostEntry) {
      incrementHostTrafficCounter(dstHost, pktsMulticastRcvd, numPkts);
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
    }

    if(el->hostResolvedName[0] != '\0')
      for(i=0; el->hostResolvedName[i] != '\0'; i++)
	el->hostResolvedName[i] = (char)tolower(el->hostResolvedName[i]);
  }
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

void dumpSuspiciousPacket(int actualDeviceId, const struct pcap_pkthdr *h, const u_char *p) {
  if((p == NULL) || (h == NULL)) return;

  if(myGlobals.device[actualDeviceId].pcapErrDumper != NULL) {
    pcap_dump((u_char*)myGlobals.device[actualDeviceId].pcapErrDumper, h, p);
    traceEvent(CONST_TRACE_INFO, "Dumped %d bytes suspicious packet", h->caplen);
  }
}

/* ***************************************************** */

void dumpOtherPacket(int actualDeviceId, const struct pcap_pkthdr *h, const u_char *p) {
  if((p == NULL) || (h == NULL)) return;

  if(myGlobals.device[actualDeviceId].pcapOtherDumper != NULL)
    pcap_dump((u_char*)myGlobals.device[actualDeviceId].pcapOtherDumper, h, p);
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
  const u_char *p_orig = p;
  u_int hlen, caplen = h->caplen;
  u_int headerDisplacement = 0, length = h->len;
  const u_char *orig_p = p, *p1;
  u_char *ether_src=NULL, *ether_dst=NULL;
  u_short eth_type=0;
  /* Token-Ring Strings */
  struct tokenRing_llc *trllc;
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
      dumpSuspiciousPacket(actualDeviceId, h, p);
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
	      processIpPkt(p, h, p_orig, length, ether_src, ether_dst, actualDeviceId, vlanId);
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
      processIpPkt(p+headerDisplacement, h, p, length, NULL, NULL, actualDeviceId, vlanId);
      break;

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
      if((myGlobals.device[deviceId].datalink == DLT_IEEE802) && (eth_type < ETHERMTU)) {
	TrafficCounter ctr;

	trp = (struct tokenRing_header*)orig_p;
	ether_src = (u_char*)trp->trn_shost, ether_dst = (u_char*)trp->trn_dhost;
	srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId, h, p);
	if(srcHost == NULL) {
	  /* Sanity check */
	  lowMemory();
	  return;
	} else {
	  lockHostsHashMutex(srcHost, "processPacket-src-2");
	}

	dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId, h, p);
	if(dstHost == NULL) {
	  /* Sanity check */
	  lowMemory();
	  unlockHostsHashMutex(srcHost);
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
	  dumpOtherPacket(actualDeviceId, h, p);

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
	  srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId, h, p);
	  if(srcHost == NULL) {
	    /* Sanity check */
	    lowMemory();
	    return;
	  } else {
	    lockHostsHashMutex(srcHost, "processPacket-src-3");
	  }

	  dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId, h, p);
	  if(dstHost == NULL) {
	    /* Sanity check */
	    lowMemory();
	    unlockHostsHashMutex(srcHost);
	    return;
	  } else {
	    lockHostsHashMutex(dstHost, "processPacket-dst-3");
	  }

	  if(vlanId != NO_VLAN) { srcHost->vlanId = vlanId; dstHost->vlanId = vlanId; }

	  allocHostTrafficCounterMemory(srcHost, nonIPTraffic, sizeof(NonIPTraffic));
	  allocHostTrafficCounterMemory(dstHost, nonIPTraffic, sizeof(NonIPTraffic));
	  if((srcHost->nonIPTraffic == NULL) || (dstHost->nonIPTraffic == NULL)) return;
	} else if(!myGlobals.runningPref.dontTrustMACaddr) {
	  /* MAC addresses are meaningful here */
	  srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId, h, p);
	  dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId, h, p);

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
		dumpOtherPacket(actualDeviceId, h, p);
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
		dumpOtherPacket(actualDeviceId, h, p);
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
	  processIpPkt(p, h, orig_p, length, ether_src, ether_dst, actualDeviceId, vlanId);
	} else {
	  processIpPkt(p+hlen, h, orig_p, length, ether_src, ether_dst, actualDeviceId, vlanId);
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
	  processIpPkt(p+hlen, h, orig_p, length, NULL, NULL, actualDeviceId, vlanId);
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

	  srcHost = lookupHost(NULL, ether_src, vlanId, 0, 0, actualDeviceId, h, p);
	  if(srcHost == NULL) {
	    /* Sanity check */
	    lowMemory();
	    return;
	  } else {
	    lockHostsHashMutex(srcHost, "processPacket-src-5");
	    allocHostTrafficCounterMemory(srcHost, nonIPTraffic, sizeof(NonIPTraffic));
	    if(srcHost->nonIPTraffic == NULL) {
	      unlockHostsHashMutex(srcHost);
	      return;
	    }
	  }

	  dstHost = lookupHost(NULL, ether_dst, vlanId, 0, 0, actualDeviceId, h, p);
	  if(dstHost == NULL) {
	    /* Sanity check */
	    lowMemory();
	    unlockHostsHashMutex(srcHost);
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

		dstHost = lookupHost(&addr, (u_char*)&arpHdr.arp_tha, vlanId, 0, 0, actualDeviceId, h, p);
		memcpy(&addr.Ip4Address.s_addr, &arpHdr.arp_spa, sizeof(struct in_addr));
		addr.Ip4Address.s_addr = ntohl(addr.Ip4Address.s_addr);
		if(dstHost != NULL) {
		  lockHostsHashMutex(dstHost, "processPacket-dst-6");
		  allocHostTrafficCounterMemory(dstHost, nonIPTraffic, sizeof(NonIPTraffic));
		  incrementHostTrafficCounter(dstHost, nonIPTraffic->arpReplyPktsRcvd, 1);
		}

		srcHost = lookupHost(&addr, (u_char*)&arpHdr.arp_sha, vlanId, 0, 0, actualDeviceId, h, p);
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

	  case ETHERTYPE_IPv6:
	    processIpPkt(p+hlen, h, orig_p, length, ether_src, ether_dst, actualDeviceId, vlanId);
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
	      dumpOtherPacket(actualDeviceId, h, p);
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
      updateThpt(1);
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

