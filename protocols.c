/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
 *
 *  			    http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either myGlobals.version 2 of the License, or
 *  (at your option) any later myGlobals.version.
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

/*
 * Copyright (c) 1994, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "ntop.h"

#ifdef ENABLE_NAPSTER
static int numNapsterSvr = 0, myGlobals.napsterSvrInsertIdx = 0;
#endif

/* #define DNS_SNIFF_DEBUG */

/* ************************************************ */

void handleBootp(HostTraffic *srcHost,
		 HostTraffic *dstHost,
		 u_short sport,
		 u_short dport,
		 u_int packetDataLength,
		 u_char* packetData, 
		 int actualDeviceId) {
  BootProtocol bootProto = { 0 };
  int len;

  if((!myGlobals.enablePacketDecoding)
     || (packetData == NULL) /* packet too short ? */
     || (myGlobals.borderSnifferMode))
    return;

  switch(sport) {
  case 67: /* BOOTP/DHCP: server -> client*/
    FD_SET(HOST_SVC_DHCP_SERVER, &srcHost->flags);

#ifdef DHCP_DEBUG
    traceEvent(TRACE_INFO, "%s:%d->%s:%d",
	       srcHost->hostNumIpAddress, sport,
	       dstHost->hostNumIpAddress, dport);
#endif

    if(packetData != NULL) {
      char buf[32];

      /*
	This is a server BOOTP/DHCP response
	that could be decoded. Let's try.

	For more info see http://www.dhcp.org/
      */
      if(packetDataLength >= sizeof(BootProtocol))
	len = sizeof(BootProtocol);
      else
	len = packetDataLength;

      memcpy(&bootProto, packetData, len);

      if(bootProto.bp_op == 2) {
	/* BOOTREPLY */
	u_long dummyMac;

	memcpy(&dummyMac, bootProto.bp_chaddr, sizeof(u_long));
	if((bootProto.bp_yiaddr.s_addr != 0)
	   && (dummyMac != 0) /* MAC address <> 00:00:00:..:00 */
	   ) {
	  NTOHL(bootProto.bp_yiaddr.s_addr);
#ifdef DHCP_DEBUG
	  traceEvent(TRACE_INFO, "%s@%s",
		     intoa(bootProto.bp_yiaddr), etheraddr_string(bootProto.bp_chaddr));
#endif
	  /* Let's check whether this is a DHCP packet [DHCP magic cookie] */
	  if((bootProto.bp_vend[0] == 0x63)    && (bootProto.bp_vend[1] == 0x82)
	     && (bootProto.bp_vend[2] == 0x53) && (bootProto.bp_vend[3] == 0x63)) {
	    /*
	      RFC 1048 specifies a magic cookie
	      { 0x63 0x82 0x53 0x63 }
	      for recognising DHCP packets encapsulated
	      in BOOTP packets.
	    */
	    int idx = 4;
	    u_int hostIdx;
	    struct in_addr hostIpAddress;
	    HostTraffic *trafficHost, *realDstHost;

	    /*
	      This is the real address of the recipient because
	      dstHost is a broadcast address
	    */
	    realDstHost = findHostByMAC(etheraddr_string(bootProto.bp_chaddr), actualDeviceId);
	    if(realDstHost == NULL) {
	      u_int hostIdx = getHostInfo(/* &bootProto.bp_yiaddr */ NULL, 
					  bootProto.bp_chaddr, 0, 0, actualDeviceId);
#ifdef DHCP_DEBUG
	      traceEvent(TRACE_INFO, "=>> %d", hostIdx);
#endif
	      realDstHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(hostIdx)];
	    } else {
#ifdef DHCP_DEBUG
	      traceEvent(TRACE_INFO, "<<=>> %s (%d)",
			 realDstHost->hostSymIpAddress,
			 broadcastHost(realDstHost));
#endif
	    }

	    if(realDstHost != NULL) {
	      if(realDstHost->dhcpStats == NULL) {
		realDstHost->dhcpStats = (DHCPStats*)malloc(sizeof(DHCPStats));
		memset(realDstHost->dhcpStats, 0, sizeof(DHCPStats));
	      }

	      if(srcHost->dhcpStats == NULL) {
		srcHost->dhcpStats = (DHCPStats*)malloc(sizeof(DHCPStats));
		memset(srcHost->dhcpStats, 0, sizeof(DHCPStats));
	      }

	      FD_SET(HOST_SVC_DHCP_CLIENT, &realDstHost->flags);
	      realDstHost->dhcpStats->assignTime = myGlobals.actTime;
	      realDstHost->dhcpStats->dhcpServerIpAddress.s_addr = srcHost->hostIpAddress.s_addr;
	      realDstHost->dhcpStats->dhcpServerIpAddress.s_addr = srcHost->hostIpAddress.s_addr;

	      if(realDstHost->hostIpAddress.s_addr != bootProto.bp_yiaddr.s_addr) {
		/* The host address has changed */
#ifdef DHCP_DEBUG
		traceEvent(TRACE_INFO, "DHCP host address changed: %s->%s",
			   intoa(realDstHost->hostIpAddress),
			   _intoa(bootProto.bp_yiaddr, buf, sizeof(buf)));
#endif
		realDstHost->dhcpStats->previousIpAddress.s_addr = realDstHost->hostIpAddress.s_addr;
		realDstHost->hostIpAddress.s_addr = bootProto.bp_yiaddr.s_addr;
		strncpy(realDstHost->hostNumIpAddress,
			_intoa(realDstHost->hostIpAddress, buf, sizeof(buf)),
			sizeof(realDstHost->hostNumIpAddress));
		ipaddr2str(realDstHost->hostIpAddress, actualDeviceId);
		realDstHost->fullDomainName = realDstHost->dotDomainName = "";
		if(isBroadcastAddress(&realDstHost->hostIpAddress))
		  FD_SET(BROADCAST_HOST_FLAG, &realDstHost->flags);
		else
		  FD_CLR(BROADCAST_HOST_FLAG, &realDstHost->flags);
	      }

	      while(idx < 64 /* Length of the BOOTP vendor-specific area */) {
		u_char optionId = bootProto.bp_vend[idx++];
		u_long tmpUlong;

		if(optionId == 255) break; /* End of options */
		switch(optionId) { /* RFC 2132 */
		case 1: /* Netmask */
		  len = bootProto.bp_vend[idx++];
		  memcpy(&hostIpAddress.s_addr, &bootProto.bp_vend[idx], len);
		  NTOHL(hostIpAddress.s_addr);
#ifdef DHCP_DEBUG
		  traceEvent(TRACE_INFO, "Netmask: %s", intoa(hostIpAddress));
#endif
		  idx += len;
		  break;
		case 3: /* Gateway */
		  len = bootProto.bp_vend[idx++];
		  memcpy(&hostIpAddress.s_addr, &bootProto.bp_vend[idx], len);
		  NTOHL(hostIpAddress.s_addr);
#ifdef DHCP_DEBUG
		  traceEvent(TRACE_INFO, "Gateway: %s", _intoa(hostIpAddress, buf, sizeof(buf)));
#endif
		  /* *************** */

		  hostIdx = findHostIdxByNumIP(hostIpAddress, actualDeviceId);
		  if(hostIdx != NO_PEER) {
		    incrementUsageCounter(&realDstHost->contactedRouters, hostIdx, actualDeviceId);

		    trafficHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(hostIdx)];
		    if(trafficHost != NULL) {
		      FD_SET(GATEWAY_HOST_FLAG, &trafficHost->flags);
		    }
		  }

		  /* *************** */
		  idx += len;
		  break;
		case 12: /* Host name */
		  len = bootProto.bp_vend[idx++];
#ifdef DHCP_DEBUG
		  traceEvent(TRACE_INFO, "Host name: %s", &bootProto.bp_vend[idx]);
#endif
		  idx += len;
		  break;
		case 15: /* Domain name */
		  len = bootProto.bp_vend[idx++];
#ifdef DHCP_DEBUG
		  traceEvent(TRACE_INFO, "Domain name: %s", &bootProto.bp_vend[idx]);
#endif
		  if(strcmp(realDstHost->hostSymIpAddress, realDstHost->hostNumIpAddress)) {
		    char tmpName[2*MAX_HOST_SYM_NAME_LEN],
		      tmpHostName[MAX_HOST_SYM_NAME_LEN],
		      tmpDomainName[MAX_HOST_SYM_NAME_LEN];
		    int hostLen, i;

		    memset(tmpHostName, 0, sizeof(tmpHostName));
		    strncpy(tmpHostName, realDstHost->hostSymIpAddress, MAX_HOST_SYM_NAME_LEN);
		    for(i=0; i<strlen(tmpHostName); i++)
		      if(tmpHostName[i] == '.')
			break;

		    tmpHostName[i] = '\0';

		    strcpy(tmpDomainName, &bootProto.bp_vend[idx]);

		    if(strcmp(tmpHostName, tmpDomainName) != 0) {
		      if(snprintf(tmpName, sizeof(tmpName), "%s.%s",
				  tmpHostName, tmpDomainName) < 0)
			traceEvent(TRACE_ERROR, "Buffer overflow!");
		      else {
			hostLen = len;
			len = strlen(tmpName);

			if(len >= (MAX_HOST_SYM_NAME_LEN-1)) {
			  tmpName[MAX_HOST_SYM_NAME_LEN-2] = '\0';
			  len--;
			}

			strncpy(realDstHost->hostSymIpAddress, tmpName,
				len > MAX_HOST_SYM_NAME_LEN ? MAX_HOST_SYM_NAME_LEN: len);
				/*
				  realDstHost->fullDomainName = realDstHost->dotDomainName =
				  &realDstHost->hostSymIpAddress[hostLen];
				*/
			fillDomainName(realDstHost);
		      }
		    }
		  }

		  idx += len;
		  break;
		case 19: /* IP Forwarding */
		  len = bootProto.bp_vend[idx++];
#ifdef DHCP_DEBUG
		  traceEvent(TRACE_INFO, "IP Forwarding: %s", bootProto.bp_vend[idx]);
#endif
		  idx += len;
		  break;
		case 28: /* Broadcast Address */
		  len = bootProto.bp_vend[idx++];
		  memcpy(&hostIpAddress.s_addr, &bootProto.bp_vend[idx], len);
		  NTOHL(hostIpAddress.s_addr);
#ifdef DHCP_DEBUG
		  traceEvent(TRACE_INFO, "Broadcast Address: %s",
			     intoa(hostIpAddress));
#endif
		  idx += len;
		  break;
		case 44: /* WINS server */
		  len = bootProto.bp_vend[idx++];
		  memcpy(&hostIpAddress.s_addr, &bootProto.bp_vend[idx], len);
		  NTOHL(hostIpAddress.s_addr);
#ifdef DHCP_DEBUG
		  traceEvent(TRACE_INFO, "WINS server: %s",
			     intoa(hostIpAddress));
#endif
		  idx += len;
		  /* *************** */

		  hostIdx = findHostIdxByNumIP(hostIpAddress, actualDeviceId);
		  if(hostIdx != NO_PEER){
		    trafficHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(hostIdx)];
		    if(trafficHost != NULL)
		      FD_SET(HOST_SVC_WINS, &trafficHost->flags);
		  }

		  /* *************** */
		  break;

		case 51: /* Lease time */
		  len = bootProto.bp_vend[idx++];
		  if(len == 4) {
		    memcpy(&tmpUlong, &bootProto.bp_vend[idx], len);
		    NTOHL(tmpUlong);
#ifdef DHCP_DEBUG
		    traceEvent(TRACE_INFO, "Lease time: %u", tmpUlong);
#endif
		    realDstHost->dhcpStats->leaseTime = myGlobals.actTime+tmpUlong;
		  }
		  idx += len;
		  break;
		case 53: /* DHCP Message Type */
		  len = bootProto.bp_vend[idx++];
#ifdef DHCP_DEBUG
		  traceEvent(TRACE_INFO, "DHCP Message Type: %d", bootProto.bp_vend[idx]);
#endif
		  switch((int)bootProto.bp_vend[idx]) {
		  case DHCP_DISCOVER_MSG:
		    realDstHost->dhcpStats->dhcpMsgRcvd[DHCP_DISCOVER_MSG]++;
		    srcHost->dhcpStats->dhcpMsgSent[DHCP_DISCOVER_MSG]++;
		    break;
		  case DHCP_OFFER_MSG:
		    realDstHost->dhcpStats->dhcpMsgRcvd[DHCP_OFFER_MSG]++;
		    srcHost->dhcpStats->dhcpMsgSent[DHCP_OFFER_MSG]++;
		    break;
		  case DHCP_REQUEST_MSG:
		    realDstHost->dhcpStats->dhcpMsgRcvd[DHCP_REQUEST_MSG]++;
		    srcHost->dhcpStats->dhcpMsgSent[DHCP_REQUEST_MSG]++;
		    break;
		  case DHCP_DECLINE_MSG:
		    realDstHost->dhcpStats->dhcpMsgRcvd[DHCP_DECLINE_MSG]++;
		    srcHost->dhcpStats->dhcpMsgSent[DHCP_DECLINE_MSG]++;
		    break;
		  case DHCP_ACK_MSG:
		    realDstHost->dhcpStats->dhcpMsgRcvd[DHCP_ACK_MSG]++;
		    srcHost->dhcpStats->dhcpMsgSent[DHCP_ACK_MSG]++;
		    break;
		  case DHCP_NACK_MSG:
		    realDstHost->dhcpStats->dhcpMsgRcvd[DHCP_NACK_MSG]++;
		    srcHost->dhcpStats->dhcpMsgSent[DHCP_NACK_MSG]++;
		    break;
		  case DHCP_RELEASE_MSG:
		    realDstHost->dhcpStats->dhcpMsgRcvd[DHCP_RELEASE_MSG]++;
		    srcHost->dhcpStats->dhcpMsgSent[DHCP_RELEASE_MSG]++;
		    break;
		  case DHCP_INFORM_MSG:
		    realDstHost->dhcpStats->dhcpMsgRcvd[DHCP_INFORM_MSG]++;
		    srcHost->dhcpStats->dhcpMsgSent[DHCP_INFORM_MSG]++;
		    break;
		  case DHCP_UNKNOWN_MSG:
		  default:
		    realDstHost->dhcpStats->dhcpMsgRcvd[DHCP_UNKNOWN_MSG]++;
		    srcHost->dhcpStats->dhcpMsgSent[DHCP_UNKNOWN_MSG]++;
		    break;
		  }
		  idx += len;
		  break;
		case 58: /* Renewal time */
		  len = bootProto.bp_vend[idx++];
		  if(len == 4) {
		    memcpy(&tmpUlong, &bootProto.bp_vend[idx], len);
		    NTOHL(tmpUlong);
#ifdef DHCP_DEBUG
		    traceEvent(TRACE_INFO, "Renewal time: %u", tmpUlong);
#endif
		    realDstHost->dhcpStats->renewalTime = myGlobals.actTime+tmpUlong;
		  }
		  idx += len;
		  break;
		case 59: /* Rebinding time */
		  len = bootProto.bp_vend[idx++];
		  if(len == 4) {
		    memcpy(&tmpUlong, &bootProto.bp_vend[idx], len);
		    NTOHL(tmpUlong);
#ifdef DHCP_DEBUG
		    traceEvent(TRACE_INFO, "Rebinding time: %u", tmpUlong);
#endif
		  }
		  idx += len;
		  break;
		case 64: /* NIS+ Domain */
		  len = bootProto.bp_vend[idx++];
		  memcpy(&hostIpAddress.s_addr, &bootProto.bp_vend[idx], len);
		  NTOHL(hostIpAddress.s_addr);
#ifdef DHCP_DEBUG
		  traceEvent(TRACE_INFO, "NIS+ domain: %s", intoa(hostIpAddress));
#endif
		  idx += len;
		  break;
		default:
#ifdef DEBUG
		  traceEvent(TRACE_INFO, "Unknown DHCP option '%d'", (int)optionId);
#endif
		  len = bootProto.bp_vend[idx++];
		  idx += len;
		  break;
		}
	      }
	    } /* realDstHost != NULL */
	  }
	}
      }
    }
    break;

  case 68: /* BOOTP/DHCP: client -> server */
    if(packetData != NULL) {
      /*
	This is a server BOOTP/DHCP response
	that could be decoded. Let's try.

	For more info see http://www.dhcp.org/
      */

      FD_SET(HOST_SVC_DHCP_CLIENT, &srcHost->flags);
      FD_SET(HOST_SVC_DHCP_SERVER, &dstHost->flags);

      if(packetDataLength >= sizeof(BootProtocol))
	len = sizeof(BootProtocol);
      else
	len = packetDataLength;

      memcpy(&bootProto, packetData, len);

      if(bootProto.bp_op == 1) {
	/* BOOTREQUEST */
	u_long dummyMac;

	memcpy(&dummyMac, bootProto.bp_chaddr, sizeof(u_long));
	if((dummyMac != 0) /* MAC address <> 00:00:00:..:00 */) {
	  NTOHL(bootProto.bp_yiaddr.s_addr);
#ifdef DHCP_DEBUG
	  traceEvent(TRACE_INFO, "%s", etheraddr_string(bootProto.bp_chaddr));
#endif
	  /* Let's check whether this is a DHCP packet [DHCP magic cookie] */
	  if((bootProto.bp_vend[0] == 0x63)    && (bootProto.bp_vend[1] == 0x82)
	     && (bootProto.bp_vend[2] == 0x53) && (bootProto.bp_vend[3] == 0x63)) {
	    /*
	      RFC 1048 specifies a magic cookie
	      { 0x63 0x82 0x53 0x63 }
	      for recognising DHCP packets encapsulated
	      in BOOTP packets.
	    */
	    int idx = 4;
	    HostTraffic *realClientHost;

	    /*
	      This is the real address of the recipient because
	      dstHost is a broadcast address
	    */
	    realClientHost = findHostByMAC(etheraddr_string(bootProto.bp_chaddr), actualDeviceId);
	    if(realClientHost == NULL) {
	      u_int hostIdx = getHostInfo(/*&bootProto.bp_yiaddr*/ NULL, 
					  bootProto.bp_chaddr, 0, 0, actualDeviceId);
#ifdef DHCP_DEBUG
	      traceEvent(TRACE_INFO, "=>> %d", hostIdx);
#endif
	      realClientHost = myGlobals.device[actualDeviceId].hash_hostTraffic[checkSessionIdx(hostIdx)];
	    } else {
#ifdef DHCP_DEBUG
	      traceEvent(TRACE_INFO, "<<=>> %s (%d)",
			 realClientHost->hostSymIpAddress,
			 broadcastHost(realClientHost));
#endif
	    }

	    if(realClientHost != NULL) {
	      if(realClientHost->dhcpStats == NULL) {
		realClientHost->dhcpStats = (DHCPStats*)malloc(sizeof(DHCPStats));
		memset(realClientHost->dhcpStats, 0, sizeof(DHCPStats));
	      }

	      while(idx < 64 /* Length of the BOOTP vendor-specific area */) {
		u_char optionId = bootProto.bp_vend[idx++];

		if(optionId == 255) break; /* End of options */
		switch(optionId) { /* RFC 2132 */
		case 12: /* Host name */
		  len = bootProto.bp_vend[idx++];
#ifdef DHCP_DEBUG
		  traceEvent(TRACE_INFO, "Host name: %s", &bootProto.bp_vend[idx]);
#endif
		  if(len >= (MAX_HOST_SYM_NAME_LEN-1)) {
		    bootProto.bp_vend[idx+MAX_HOST_SYM_NAME_LEN-2] = '\0';
		    len--;
		  }

		  strncpy(realClientHost->hostSymIpAddress, &bootProto.bp_vend[idx],
			  len > MAX_HOST_SYM_NAME_LEN ? MAX_HOST_SYM_NAME_LEN: len);
		  idx += len;
		  break;
		case 53: /* DHCP Message Type */
		  len = bootProto.bp_vend[idx++];
#ifdef DHCP_DEBUG
		  traceEvent(TRACE_INFO, "DHCP Message Type: %d", bootProto.bp_vend[idx]);
#endif
		  switch((int)bootProto.bp_vend[idx]) {
		  case DHCP_DISCOVER_MSG:
		    realClientHost->dhcpStats->dhcpMsgSent[DHCP_DISCOVER_MSG]++;
		    break;
		  case DHCP_OFFER_MSG:
		    realClientHost->dhcpStats->dhcpMsgSent[DHCP_OFFER_MSG]++;
		    break;
		  case DHCP_REQUEST_MSG:
		    realClientHost->dhcpStats->dhcpMsgSent[DHCP_REQUEST_MSG]++;
		    break;
		  case DHCP_DECLINE_MSG:
		    realClientHost->dhcpStats->dhcpMsgSent[DHCP_DECLINE_MSG]++;
		    break;
		  case DHCP_ACK_MSG:
		    realClientHost->dhcpStats->dhcpMsgSent[DHCP_ACK_MSG]++;
		    break;
		  case DHCP_NACK_MSG:
		    realClientHost->dhcpStats->dhcpMsgSent[DHCP_NACK_MSG]++;
		    break;
		  case DHCP_RELEASE_MSG:
		    realClientHost->dhcpStats->dhcpMsgSent[DHCP_RELEASE_MSG]++;
		    break;
		  case DHCP_INFORM_MSG:
		    realClientHost->dhcpStats->dhcpMsgSent[DHCP_INFORM_MSG]++;
		    break;
		  case DHCP_UNKNOWN_MSG:
		  default:
		    realClientHost->dhcpStats->dhcpMsgSent[DHCP_UNKNOWN_MSG]++;
		    break;
		  }
		  idx += len;
		  break;
		default:
#ifdef DEBUG
		  traceEvent(TRACE_INFO, "Unknown DHCP option '%d'", (int)optionId);
#endif
		  len = bootProto.bp_vend[idx++];
		  idx += len;
		  break;
		}
	      }
	    }
	  }
	}
      }
    }
    break;
  }
}

/* ************************************ */

u_int16_t processDNSPacket(const u_char *packetData, 
			   u_int length, 
			   short *isRequest, 
			   short *positiveReply) {
  DNSHostInfo hostPtr;
  struct in_addr hostIpAddress;
  datum key_data, data_data;
  char tmpBuf[96];
  u_int16_t transactionId = 0;
  int i, queryNameLength;

  if((!myGlobals.enablePacketDecoding)
     ||(packetData == NULL) /* packet too short ? */)
    return(transactionId);

  memset(&hostPtr, 0, sizeof(DNSHostInfo));

  transactionId = handleDNSpacket(packetData, &hostPtr, length,
				  isRequest, positiveReply);

#ifdef DNS_SNIFF_DEBUG
  if((hostPtr.queryType == T_A)
     && (hostPtr.queryName[0] != '\0')
     && (hostPtr.addrList[0] != '\0')) {
    traceEvent(TRACE_INFO, "DNS %s for %s type %d\n", *isRequest ? "request" : "reply",
	       hostPtr.queryName, hostPtr.queryType);

    for(i=0; i<MAXALIASES; i++)
      if(hostPtr.aliases[i][0] != '\0') {
	traceEvent(TRACE_INFO, "%s is alias of %s\n", hostPtr.aliases[i], hostPtr.name);
      }
  }
#endif

  if((*isRequest) || (!*positiveReply))
    return(transactionId);
  if(myGlobals.gdbm_file == NULL) return(-1); /* ntop is quitting... */

  queryNameLength = strlen(hostPtr.queryName);
  strtolower(hostPtr.queryName);
  
  if((queryNameLength > 5)
     && (strncmp(&hostPtr.queryName[queryNameLength-5], ".arpa", 5) == 0))
    return(transactionId);

  for(i=0; i<MAXADDRS; i++) {
  	/* Symbolic => Numeric */

    if(hostPtr.addrList[i] != 0) {
      hostIpAddress.s_addr = ntohl(hostPtr.addrList[i]);
      key_data.dptr = _intoa(hostIpAddress, tmpBuf , sizeof(tmpBuf));
      key_data.dsize = strlen(key_data.dptr)+1;
      data_data.dptr = hostPtr.queryName;
      data_data.dsize = queryNameLength+1;

#ifdef DNS_SNIFF_DEBUG
      traceEvent(TRACE_INFO, "Sniffed DNS response: %s = %s", key_data.dptr, data_data.dptr);
#endif

      if(myGlobals.gdbm_file == NULL) return(-1); /* ntop is quitting... */
#ifdef MULTITHREADED
      accessMutex(&myGlobals.gdbmMutex, "processDNSPacket");
#endif
      gdbm_store(myGlobals.gdbm_file, key_data, data_data, GDBM_REPLACE);
#ifdef MULTITHREADED
      releaseMutex(&myGlobals.gdbmMutex);
#endif
    }
  }

  return(transactionId);
}

/* ************************************* */

#ifdef ENABLE_NAPSTER

void handleNapster(HostTraffic *srcHost,
		   HostTraffic *dstHost,
		   u_short sport,
		   u_short dport,
		   u_int packetDataLength,
		   u_char* packetData,
		   IPSession *theSession) {
#ifdef ENABLE_NAPSTER
  u_short napsterDownload = 0;
#endif

  if((!myGlobals.enablePacketDecoding)
     || (packetData == NULL) /* packet too short ? */)
    return(NULL);

  /* Let's check whether this is a Napster session */
  if(numNapsterSvr > 0) {
    for(i=0; i<MAX_NUM_NAPSTER_SERVER; i++) {
      if(((myGlobals.napsterSvr[i].serverPort == sport)
	  && (myGlobals.napsterSvr[i].serverAddress.s_addr == srcHost->hostIpAddress.s_addr))
	 || ((myGlobals.napsterSvr[i].serverPort == dport)
	     && (myGlobals.napsterSvr[i].serverAddress.s_addr == dstHost->hostIpAddress.s_addr))) {
	theSession->napsterSession = 1;
	myGlobals.napsterSvr[i].serverPort = 0; /* Free slot */
	numNapsterSvr--;
	FD_SET(HOST_SVC_NAPSTER_CLIENT, &srcHost->flags);
	FD_SET(HOST_SVC_NAPSTER_SERVER, &dstHost->flags);

#ifdef TRACE_TRAFFIC_INFO
	traceEvent(TRACE_INFO, "NAPSTER new download session: %s->%s\n",
		   srcHost->hostSymIpAddress,
		   dstHost->hostSymIpAddress);
#endif

	if(srcHost->napsterStats == NULL) {
	  srcHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
	  memset(srcHost->napsterStats, 0, sizeof(NapsterStats));
	}

	if(dstHost->napsterStats == NULL) {
	  dstHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
	  memset(dstHost->napsterStats, 0, sizeof(NapsterStats));
	}

	srcHost->napsterStats->numDownloadsRequested++,
	  dstHost->napsterStats->numDownloadsServed++;
      }
    }
  }

  if(!theSession->napsterSession)  {
    /* This session has not been recognized as a Napster
       session. It might be that ntop has been started
       after the session started, or that ntop has
       lost a few packets. Let's do a final check...
    */
#define NAPSTER_DOMAIN "napster.com"

    if(
       (((strlen(srcHost->hostSymIpAddress) > strlen(NAPSTER_DOMAIN))
	 && (strcmp(&srcHost->hostSymIpAddress[strlen(srcHost->hostSymIpAddress)-
					      strlen(NAPSTER_DOMAIN)],
		    NAPSTER_DOMAIN) == 0) && (sport == 8888)))
       ||
       (((strlen(dstHost->hostSymIpAddress) > strlen(NAPSTER_DOMAIN))
	 && (strcmp(&dstHost->hostSymIpAddress[strlen(dstHost->hostSymIpAddress)-
					      strlen(NAPSTER_DOMAIN)],
		    NAPSTER_DOMAIN) == 0)) && (dport == 8888))) {

      theSession->napsterSession = 1;

#ifdef TRACE_TRAFFIC_INFO
      traceEvent(TRACE_INFO, "NAPSTER new session: %s <->%s\n",
		 srcHost->hostSymIpAddress,
		 dstHost->hostSymIpAddress);
#endif

      if(srcHost->napsterStats == NULL) {
	srcHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
	memset(srcHost->napsterStats, 0, sizeof(NapsterStats));
      }

      if(dstHost->napsterStats == NULL) {
	dstHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
	memset(dstHost->napsterStats, 0, sizeof(NapsterStats));
      }

      if(sport == 8888) {
	FD_SET(HOST_SVC_NAPSTER_SERVER, &srcHost->flags);
	FD_SET(HOST_SVC_NAPSTER_CLIENT, &dstHost->flags);
	srcHost->napsterStats->numConnectionsServed++,
	  dstHost->napsterStats->numConnectionsRequested++;
      } else {
	FD_SET(HOST_SVC_NAPSTER_CLIENT, &srcHost->flags);
	FD_SET(HOST_SVC_NAPSTER_SERVER, &dstHost->flags);
	srcHost->napsterStats->numConnectionsRequested++,
	  dstHost->napsterStats->numConnectionsServed++;
      }
    }
  }

  if((sport == 8875 /* Napster Redirector */) && (packetDataLength > 5)) {
    char address[64] = { 0 };
    int i;

    FD_SET(HOST_SVC_NAPSTER_REDIRECTOR, &srcHost->flags);
    FD_SET(HOST_SVC_NAPSTER_CLIENT,     &dstHost->flags);

    if(packetDataLength >= sizeof(address))
      len = sizeof(address)-1;
    else
      len = packetDataLength;

    strncpy(address, packetData, len);
    address[len-2] = 0;

#ifdef TRACE_TRAFFIC_INFO
    traceEvent(TRACE_INFO, "NAPSTER: %s->%s [%s][len=%d]\n",
	       srcHost->hostSymIpAddress,
	       dstHost->hostSymIpAddress,
	       address, packetDataLength);
#endif

    for(i=1; i<len-2; i++)
      if(address[i] == ':') {
	address[i] = '\0';
	break;
      }

    myGlobals.napsterSvr[myGlobals.napsterSvrInsertIdx].serverAddress.s_addr = ntohl(inet_addr(address));
    myGlobals.napsterSvr[myGlobals.napsterSvrInsertIdx].serverPort = atoi(&address[i+1]);
    myGlobals.napsterSvrInsertIdx = (myGlobals.napsterSvrInsertIdx+1) % MAX_NUM_NAPSTER_SERVER;
    numNapsterSvr++;

    if(srcHost->napsterStats == NULL) {
      srcHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
      memset(srcHost->napsterStats, 0, sizeof(NapsterStats));
    }
    if(dstHost->napsterStats == NULL) {
      dstHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
      memset(dstHost->napsterStats, 0, sizeof(NapsterStats));
    }

    srcHost->napsterStats->numConnectionsServed++,
      dstHost->napsterStats->numConnectionsRequested++;
  }

  /* Let's decode some Napster packets */
  if((!theSession->napsterSession)
     && (packetData != NULL)
     && (packetDataLength == 1)
     && (theSession->bytesProtoRcvd == 0) /* This condition will not hold if you
					     move this line of code down this
					     function */
     ) {
    /*
	If this is a Napster Download then it should
	look like "0x31 GET username song ...."
      */

    if(packetData[0] == 0x31) {
      theSession->napsterSession = 1;
      napsterDownload = 1;
    }

    /*
      traceEvent(TRACE_INFO, "Session check: %s:%d->%s:%d [%x]\n",
      srcHost->hostSymIpAddress, sport,
      dstHost->hostSymIpAddress, dport, packetData[0]);
    */
  }

  if(theSession->napsterSession && (packetDataLength > 0) ) {
    if(srcHost->napsterStats == NULL) {
      srcHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
      memset(srcHost->napsterStats, 0, sizeof(NapsterStats));
    }

    if(dstHost->napsterStats == NULL) {
      dstHost->napsterStats = (NapsterStats*)malloc(sizeof(NapsterStats));
      memset(dstHost->napsterStats, 0, sizeof(NapsterStats));
    }

    srcHost->napsterStats->bytesSent += packetDataLength,
      dstHost->napsterStats->bytesRcvd += packetDataLength;

    if(napsterDownload) {
      FD_SET(HOST_SVC_NAPSTER_CLIENT, &srcHost->flags);
      FD_SET(HOST_SVC_NAPSTER_CLIENT, &dstHost->flags);

#ifdef TRACE_TRAFFIC_INFO
      traceEvent(TRACE_INFO, "NAPSTER new download session: %s->%s\n",
		 dstHost->hostSymIpAddress,
		 srcHost->hostSymIpAddress);
#endif
      dstHost->napsterStats->numDownloadsRequested++,
	srcHost->napsterStats->numDownloadsServed++;
    } else if((packetData != NULL) && (packetDataLength > 4)) {
      if((packetData[1] == 0x0) && (packetData[2] == 0xC8) && (packetData[3] == 0x00)) {
	srcHost->napsterStats->numSearchSent++, dstHost->napsterStats->numSearchRcvd++;

#ifdef TRACE_TRAFFIC_INFO
	traceEvent(TRACE_INFO, "NAPSTER search: %s->%s\n",
		   srcHost->hostSymIpAddress,
		   dstHost->hostSymIpAddress);
#endif
      } else if((packetData[1] == 0x0)
		&& (packetData[2] == 0xCC) && (packetData[3] == 0x00)) {
	char tmpBuf[64], *remoteHost, *remotePort, *strtokState;

	struct in_addr shost;

	srcHost->napsterStats->numDownloadsRequested++,
	  dstHost->napsterStats->numDownloadsServed++;

	/*
	  LEN 00 CC 00 <remote user name>
	  <remote user IP> <remote user port> <payload>
	*/

	memcpy(tmpBuf, &packetData[4], (packetDataLength<64) ? packetDataLength : 63);
	strtok_r(tmpBuf, " ", &strtokState); /* remote user */
	if((remoteHost = strtok_r(NULL, " ", &strtokState)) != NULL) {
	  if((remotePort = strtok_r(NULL, " ", &strtokState)) != NULL) {

	    myGlobals.napsterSvr[myGlobals.napsterSvrInsertIdx].serverPort = atoi(remotePort);
	    if(myGlobals.napsterSvr[myGlobals.napsterSvrInsertIdx].serverPort != 0) {
	      myGlobals.napsterSvr[myGlobals.napsterSvrInsertIdx].serverAddress.s_addr = inet_addr(remoteHost);
	      myGlobals.napsterSvrInsertIdx = (myGlobals.napsterSvrInsertIdx+1) % MAX_NUM_NAPSTER_SERVER;
	      numNapsterSvr++;
	      shost.s_addr = inet_addr(remoteHost);
#ifdef TRACE_TRAFFIC_INFO
	      traceEvent(TRACE_INFO, "NAPSTER: %s requested download from %s:%s",
			 srcHost->hostSymIpAddress, remoteHost, remotePort);
#endif
	    }
	  }
	}
      }
    }
  }
}

#endif /* ENABLE_NAPSTER */

/* ******************************** */

void handleNetbios(HostTraffic *srcHost,
		   HostTraffic *dstHost,
		   u_short sport,
		   u_short dport,
		   u_int packetDataLength,
		   const u_char* packetData,
		   u_int length,
		   u_int hlen) {
  u_char *name, nbName[64], domain[64], *data;
  int nodeType, i, udpDataLen;
  char *tmpdata = (char*)packetData + (hlen + sizeof(struct udphdr));
  u_char *p;
  int offset=0, displ, notEnoughData = 0;

  if((!myGlobals.enablePacketDecoding)
     || (!((srcHost->nbHostName == NULL) || (srcHost->nbDomainName == NULL))))
    return; /* Already set */

  if(packetData == NULL) /* packet too short ? */
    return;

  udpDataLen = length - (hlen + sizeof(struct udphdr));

  if(dport == 137 /*  NETBIOS */) {
    if(udpDataLen > 32) {
      /* 32 bytes or less is not enough */
      data = (char*)malloc(udpDataLen);
      memcpy(data, tmpdata, udpDataLen);

      name = data + 12;
      p = (u_char*)name;
      if ((*p & 0xC0) == 0xC0) {
	displ = p[1] + 255 * (p[0] & ~0xC0);
	if((displ + 14) >= udpDataLen)
	  notEnoughData = 1;
	else {
	  name = data + displ;
	  displ += 14;
	  offset = 2;
	}
      } else {
	displ = 14;

	while ((displ < udpDataLen) && (*p)) {
	  p += (*p)+1;
	  displ++;
	}

	if(displ < udpDataLen)
	  offset = ((char*)p - (char*)data) + 1;
	else
	  notEnoughData = 1;
      }

      if(!notEnoughData) {
	nodeType = name_interpret(name, nbName, udpDataLen-displ);

#ifdef DEBUG
	traceEvent(TRACE_INFO, "Found: %s", nbName);
#endif

	switch(nodeType) {	  
	case 0x1B: /* Domain Master Browser */
	case 0x1C: /* Domain Controller */
	case 0x1D: /* Local Master Browser */
	  /* Set the domain/workgroup only when needed */
	  setNBnodeNameType(srcHost, (char)nodeType, nbName);
	  break;
	}
      }

      free(data);
    }
  } else if(dport == 138 /*  NETBIOS */) {
    if(udpDataLen > 32) {
      /* 32 bytes or less is not enough */
      data = (char*)malloc(udpDataLen);
      memcpy(data, tmpdata, udpDataLen);

      name = data + 14;
      p = (u_char*)name;
      if ((*p & 0xC0) == 0xC0) {
	displ = p[1] + 255 * (p[0] & ~0xC0);
	if((displ + 14) >= udpDataLen)
	  notEnoughData = 1;
	else {
	  name = data + displ;
	  displ += 14;
	  offset = 2;
	}
      } else {
	displ = 14;

	while ((displ < udpDataLen) && (*p)) {
	  p += (*p)+1;
	  displ++;
	}

	if(displ < udpDataLen)
	  offset = ((char*)p - (char*)data) + 1;
	else
	  notEnoughData = 1;
      }

      if(!notEnoughData) {
	nodeType = name_interpret(name, nbName, udpDataLen-displ);

	if(nodeType != -1) {
	  setNBnodeNameType(srcHost, (char)nodeType, nbName);

	  displ += offset; /* see ** */

	  if(displ < udpDataLen) {
	    name = data + offset; /* ** */
	    p = (u_char*)name;
	    if ((*p & 0xC0) == 0xC0) {
	      displ = hlen + 8 + (p[1] + 255 * (p[0] & ~0xC0));

	      if(displ < length)
		name = ((char*)packetData+displ);
	      else
		notEnoughData = 1;
	    }

	    if(!notEnoughData) {
	      nodeType = name_interpret(name, domain, length-displ);

	      if(nodeType != -1) {
		for(i=0; domain[i] != '\0'; i++)
		  if(domain[i] == ' ') { domain[i] = '\0'; break; }

		setNBnodeNameType(dstHost, (char)nodeType, domain);

		if(udpDataLen > 200) {
		  char *tmpBuffer = &data[151];

		  /*
		    We'll check if this this is
		    a browser announcments so we can
		    know more about this host
		  */

		  if(strcmp(tmpBuffer, "\\MAILSLOT\\BROWSE") == 0) {
		    /* Good: this looks like a browser announcement */
		    if(((tmpBuffer[17] == 0x0F /* Local Master Announcement*/)
			|| (tmpBuffer[17] == 0x01 /* Host Announcement*/))
		       && (tmpBuffer[49] != '\0')) {

		      if(srcHost->nbDescr != NULL)
			free(srcHost->nbDescr);

		      if(tmpBuffer[17] == 0x0F)
			FD_SET(HOST_TYPE_MASTER_BROWSER, &srcHost->flags);

		      srcHost->nbDescr = strdup(&tmpBuffer[49]);
#ifdef DEBUG
		      traceEvent(TRACE_INFO, "Computer Info: '%s'", srcHost->nbDescr);
#endif
		    }
		  }
		}
	      }
	    }
	  }
	}
      }

      free(data);
    }
  } else if((sport == 139) || (dport == 139)) {

    if(udpDataLen > 32) {
      /* 32 bytes or less is not enough */
      data = (char*)malloc(udpDataLen);
      memcpy(data, tmpdata, udpDataLen);

      if(data[0] == 0x81) /* Session request */ {
	char decodedStr[64];
	int pos;

	pos = 5;
	decodeNBstring(&data[5], decodedStr);

	if((decodedStr[0] != '\0') && (dstHost->nbHostName == NULL))
	  dstHost->nbHostName = strdup(decodedStr); /* dst before src */

	pos = 5+(2*strlen(decodedStr))+2;
	decodeNBstring(&data[pos], decodedStr);

	if((decodedStr[0] != '\0') && (srcHost->nbHostName == NULL))
	  srcHost->nbHostName = strdup(decodedStr);
      } else if((data[0] == 0x0) /* Message type: Session message */
		&& (data[8] == 0x73) /* SMB Command: SMBsesssetupX */) {
	int i;

#ifdef DEBUG
	for(i=0; i<len; i++)
	  printf("0x%X (%d)\n", data[i], i);
#endif

	if(sport == 139) {
	  /* Response */
#ifdef DEBUG
	  printf("OS: %s\n", &data[45]);
#endif
	  if(srcHost->osName == NULL)
	    srcHost->osName = strdup(&data[45]);
	} else /* dport == 139 */ {
	  /* Request */
	  char len;

	  len = data[51]+data[53]; /* ANSI and UNICODE pw length */

	  i = 65+len;

	  if(srcHost->nbAccountName == NULL) srcHost->nbAccountName = strdup(&data[i]);
#ifdef DEBUG
	  printf("Account Name: %s\n", &data[i]);
#endif
	  while((data[i] != 0) && (i < sizeof(data))) i++;
	  i++;
#ifdef DEBUG
	  printf("Domain: %s\n", &data[i]);
#endif
	  if(srcHost->nbDomainName == NULL) srcHost->nbDomainName = strdup(&data[i]);
	  while((data[i] != 0) && (i < sizeof(data))) i++;
	  i++;
#ifdef DEBUG
	  printf("OS: %s\n", &data[i]);
#endif
	  if(srcHost->osName == NULL)
	    srcHost->osName = strdup(&data[i]);
	}
      }

      free(data);
    }
  }
}


