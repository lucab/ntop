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

/* ************************************************ */

void handleBootp(HostTraffic *srcHost,
		 HostTraffic *dstHost,
		 u_short sport,
		 u_short dport,
		 u_int packetDataLength,
		 u_char* packetData,
		 int actualDeviceId) {
  BootProtocol bootProto;
  u_int len;
  int rc;
  char savechar; /* Courtesy of
		    Axel Thimm <Axel.Thimm+ntop@physik.fu-berlin.de>
		 */

  if((!myGlobals.enablePacketDecoding)
     || (packetData == NULL) /* packet too short ? */
     || (myGlobals.dontTrustMACaddr))
    return;

  memset(&bootProto, 0, sizeof(BootProtocol));

  switch(sport) {
  case 67: /* BOOTP/DHCP: server -> client*/
    FD_SET(FLAG_HOST_TYPE_SVC_DHCP_SERVER, &srcHost->flags);

#ifdef DHCP_DEBUG
    traceEvent(CONST_TRACE_INFO, "%s:%d->%s:%d",
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
#ifdef DHCP_DEBUG
	  char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];
#endif

	  NTOHL(bootProto.bp_yiaddr.s_addr);
#ifdef DHCP_DEBUG
	  traceEvent(CONST_TRACE_INFO, "%s@%s",
		     intoa(bootProto.bp_yiaddr),
		     etheraddr_string(bootProto.bp_chaddr, etherbuf));
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
	    u_int idx = 4;
	    struct in_addr hostIpAddress;
	    HostTraffic *trafficHost, *realDstHost;
	    /*
	      This is the real address of the recipient because
	      dstHost is a broadcast address
	    */

	    realDstHost = findHostByMAC(bootProto.bp_chaddr, dstHost->vlanId, actualDeviceId);
	    if(realDstHost == NULL) {
	      realDstHost = lookupHost(/* &bootProto.bp_yiaddr */ NULL, bootProto.bp_chaddr, 
				       srcHost->vlanId, 0, 0, actualDeviceId);
	    } else {
#ifdef DHCP_DEBUG
	      traceEvent(CONST_TRACE_INFO, "<<=>> %s (%d)",
			 realDstHost->hostResolvedName,
			 broadcastHost(realDstHost));
#endif
	    }

	    if(realDstHost != NULL) {
	      if(realDstHost->protocolInfo == NULL) realDstHost->protocolInfo = calloc(1, sizeof(ProtocolInfo));

	      if(realDstHost->protocolInfo->dhcpStats == NULL) {
		realDstHost->protocolInfo->dhcpStats = (DHCPStats*)malloc(sizeof(DHCPStats));
		memset(realDstHost->protocolInfo->dhcpStats, 0, sizeof(DHCPStats));
	      }

	      if(srcHost->protocolInfo == NULL) srcHost->protocolInfo = calloc(1, sizeof(ProtocolInfo));
	      if(srcHost->protocolInfo->dhcpStats == NULL) {
		srcHost->protocolInfo->dhcpStats = (DHCPStats*)malloc(sizeof(DHCPStats));
		memset(srcHost->protocolInfo->dhcpStats, 0, sizeof(DHCPStats));
	      }

	      FD_SET(FLAG_HOST_TYPE_SVC_DHCP_CLIENT, &realDstHost->flags);
	      realDstHost->protocolInfo->dhcpStats->assignTime = myGlobals.actTime;
	      realDstHost->protocolInfo->dhcpStats->dhcpServerIpAddress.s_addr = srcHost->hostIp4Address.s_addr;
	      realDstHost->protocolInfo->dhcpStats->dhcpServerIpAddress.s_addr = srcHost->hostIp4Address.s_addr;

	      if(realDstHost->hostIp4Address.s_addr != bootProto.bp_yiaddr.s_addr) {
		/* The host address has changed */
#ifdef DHCP_DEBUG
		traceEvent(CONST_TRACE_INFO, "DHCP host address changed: %s->%s",
			   intoa(realDstHost->hostIp4Address),
			   _intoa(bootProto.bp_yiaddr, buf, sizeof(buf)));
#endif
		realDstHost->protocolInfo->dhcpStats->previousIpAddress.s_addr = realDstHost->hostIp4Address.s_addr;
		realDstHost->hostIp4Address.s_addr = bootProto.bp_yiaddr.s_addr;
		strncpy(realDstHost->hostNumIpAddress,
			_intoa(realDstHost->hostIp4Address, buf, sizeof(buf)),
			sizeof(realDstHost->hostNumIpAddress));
		if(myGlobals.numericFlag == 0) ipaddr2str(realDstHost->hostIpAddress, 1);
                if (realDstHost->dnsDomainValue != NULL) free(realDstHost->dnsDomainValue);
		realDstHost->dnsDomainValue = NULL;
                if (realDstHost->dnsTLDValue != NULL) free(realDstHost->dnsTLDValue);
		realDstHost->dnsTLDValue = NULL;
		if (realDstHost->ip2ccValue != NULL) free(realDstHost->ip2ccValue);
		realDstHost->ip2ccValue = NULL;
		if(isBroadcastAddress(&realDstHost->hostIpAddress))
		  FD_SET(FLAG_BROADCAST_HOST, &realDstHost->flags);
		else
		  FD_CLR(FLAG_BROADCAST_HOST, &realDstHost->flags);
	      }

	      while(idx < 64 /* Length of the BOOTP vendor-specific area */) {
		u_char optionId = bootProto.bp_vend[idx++];
		u_long tmpUlong;
		HostAddr addr;
		addr.hostFamily = AF_INET;

		if(optionId == 255) break; /* End of options */
		switch(optionId) { /* RFC 2132 */
		case 1: /* Netmask */
		  len = bootProto.bp_vend[idx++];
		  memcpy(&hostIpAddress.s_addr, &bootProto.bp_vend[idx], sizeof(hostIpAddress.s_addr));
		  NTOHL(hostIpAddress.s_addr);
#ifdef DHCP_DEBUG
		  traceEvent(CONST_TRACE_INFO, "Netmask: %s", intoa(hostIpAddress));
#endif
		  idx += len;
		  break;
		case 3: /* Gateway */
		  len = bootProto.bp_vend[idx++];
		  memcpy(&hostIpAddress.s_addr, &bootProto.bp_vend[idx], sizeof(hostIpAddress.s_addr));
		  NTOHL(hostIpAddress.s_addr);
#ifdef DHCP_DEBUG
		  traceEvent(CONST_TRACE_INFO, "Gateway: %s", _intoa(hostIpAddress, buf, sizeof(buf)));
#endif
		  /* *************** */
		  addr.Ip4Address.s_addr = hostIpAddress.s_addr;
		  trafficHost = findHostByNumIP(addr, srcHost->vlanId, actualDeviceId);
		  if(trafficHost != NULL) {
		    incrementUsageCounter(&realDstHost->contactedRouters, trafficHost, actualDeviceId);
		    FD_SET(FLAG_GATEWAY_HOST, &trafficHost->flags);
		  }

		  /* *************** */
		  idx += len;
		  break;
		case 12: /* Host name */
		  len = bootProto.bp_vend[idx++];
#ifdef DHCP_DEBUG
		  savechar = bootProto.bp_vend[idx+len];
		  bootProto.bp_vend[idx+len] = '\0';
 		  traceEvent(CONST_TRACE_INFO, "Host name: %s", &bootProto.bp_vend[idx]);
		  bootProto.bp_vend[idx+len] = savechar;
#endif
		  idx += len;
		  break;
		case 15: /* Domain name */
		  len = bootProto.bp_vend[idx++];
		  savechar = bootProto.bp_vend[idx+len];
		  bootProto.bp_vend[idx+len] = '\0';
#ifdef DHCP_DEBUG
		  traceEvent(CONST_TRACE_INFO, "Domain name: %s", &bootProto.bp_vend[idx]);
#endif
		  if(strcmp(realDstHost->hostResolvedName, realDstHost->hostNumIpAddress)) {
		    char tmpName[2*MAX_LEN_SYM_HOST_NAME],
		      tmpHostName[MAX_LEN_SYM_HOST_NAME],
		      tmpDomainName[MAX_LEN_SYM_HOST_NAME];
		    int hostLen, i;

		    memset(tmpHostName, 0, sizeof(tmpHostName));
		    strncpy(tmpHostName, realDstHost->hostResolvedName, MAX_LEN_SYM_HOST_NAME-1);
		    for(i=0; i<strlen(tmpHostName); i++)
		      if(tmpHostName[i] == '.')
			break;

		    tmpHostName[i] = '\0';

		    /* Fix courtesy of Christoph Zens <chris@topfen.homeip.net> */
		    strncpy(tmpDomainName, &bootProto.bp_vend[idx], len);
		    tmpDomainName[len] = '\0';

		    if(strcmp(tmpHostName, tmpDomainName) != 0) {
		      rc = safe_snprintf(__FILE__, __LINE__, tmpName, sizeof(tmpName), "%s.%s",
				  tmpHostName, tmpDomainName);
		      if (rc >= 0) {
			hostLen = len;
			len = strlen(tmpName);

			if(len >= (MAX_LEN_SYM_HOST_NAME-1)) {
			  tmpName[MAX_LEN_SYM_HOST_NAME-2] = '\0';
			  len--;
			}

			/* Fix courtesy of Christoph Zens <chris@topfen.homeip.net> */
			if(len >= MAX_LEN_SYM_HOST_NAME) len = MAX_LEN_SYM_HOST_NAME-1;
			tmpName[len] = '\0';
			for(i=0; i<strlen(tmpName); i++) if(isupper(tmpName[i])) tolower(tmpName[i]);
                        setResolvedName(realDstHost, tmpName, FLAG_HOST_SYM_ADDR_TYPE_NAME);
			fillDomainName(realDstHost);
		      }
		    }
		  }

		  bootProto.bp_vend[idx+len] = savechar;
		  idx += len;
		  break;
		case 19: /* IP Forwarding */
		  len = bootProto.bp_vend[idx++];
#ifdef DHCP_DEBUG
		  traceEvent(CONST_TRACE_INFO, "IP Forwarding: %s", bootProto.bp_vend[idx]);
#endif
		  idx += len;
		  break;
		case 28: /* Broadcast Address */
		  len = bootProto.bp_vend[idx++];
		  memcpy(&hostIpAddress.s_addr, &bootProto.bp_vend[idx], sizeof(hostIpAddress.s_addr));
		  NTOHL(hostIpAddress.s_addr);
#ifdef DHCP_DEBUG
		  traceEvent(CONST_TRACE_INFO, "Broadcast Address: %s",
			     intoa(hostIpAddress));
#endif
		  idx += len;
		  break;
		case 44: /* WINS server */
		  len = bootProto.bp_vend[idx++];
		  memcpy(&hostIpAddress.s_addr, &bootProto.bp_vend[idx], sizeof(hostIpAddress.s_addr));
		  NTOHL(hostIpAddress.s_addr);
#ifdef DHCP_DEBUG
		  traceEvent(CONST_TRACE_INFO, "WINS server: %s",
			     intoa(hostIpAddress));
#endif
		  idx += len;

		  /* *************** */
		  addr.Ip4Address.s_addr = hostIpAddress.s_addr;

		  trafficHost = findHostByNumIP(addr, srcHost->vlanId, actualDeviceId);
		  if(trafficHost != NULL) {
		    FD_SET(FLAG_HOST_TYPE_SVC_WINS, &trafficHost->flags);
		  }

		  /* *************** */
		  break;

		case 51: /* Lease time */
		  len = bootProto.bp_vend[idx++];
		  if(len == 4) {
		    memcpy(&tmpUlong, &bootProto.bp_vend[idx], sizeof(hostIpAddress.s_addr));
		    NTOHL(tmpUlong);
#ifdef DHCP_DEBUG
		    traceEvent(CONST_TRACE_INFO, "Lease time: %u", tmpUlong);
#endif
		    realDstHost->protocolInfo->dhcpStats->leaseTime = myGlobals.actTime+tmpUlong;
		  }
		  idx += len;
		  break;
		case 53: /* DHCP Message Type */
		  len = bootProto.bp_vend[idx++];
#ifdef DHCP_DEBUG
		  traceEvent(CONST_TRACE_INFO, "DHCP Message Type: %d", bootProto.bp_vend[idx]);
#endif
		  switch((int)bootProto.bp_vend[idx]) {
		  case FLAG_DHCP_DISCOVER_MSG:
		    incrementTrafficCounter(&realDstHost->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_DISCOVER_MSG], 1);
		    incrementTrafficCounter(&srcHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_DISCOVER_MSG], 1);
		    break;
		  case FLAG_DHCP_OFFER_MSG:
		    incrementTrafficCounter(&realDstHost->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_OFFER_MSG], 1);
		    incrementTrafficCounter(&srcHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_OFFER_MSG], 1);
		    break;
		  case FLAG_DHCP_REQUEST_MSG:
		    incrementTrafficCounter(&realDstHost->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_REQUEST_MSG], 1);
		    incrementTrafficCounter(&srcHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_REQUEST_MSG], 1);
		    break;
		  case FLAG_DHCP_DECLINE_MSG:
		    incrementTrafficCounter(&realDstHost->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_DECLINE_MSG], 1);
		    incrementTrafficCounter(&srcHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_DECLINE_MSG], 1);
		    break;
		  case FLAG_DHCP_ACK_MSG:
		    incrementTrafficCounter(&realDstHost->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_ACK_MSG], 1);
		    incrementTrafficCounter(&srcHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_ACK_MSG], 1);
		    break;
		  case FLAG_DHCP_NACK_MSG:
		    incrementTrafficCounter(&realDstHost->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_NACK_MSG], 1);
		    incrementTrafficCounter(&srcHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_NACK_MSG], 1);
		    break;
		  case FLAG_DHCP_RELEASE_MSG:
		    incrementTrafficCounter(&realDstHost->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_RELEASE_MSG], 1);
		    incrementTrafficCounter(&srcHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_RELEASE_MSG], 1);
		    break;
		  case FLAG_DHCP_INFORM_MSG:
		    incrementTrafficCounter(&realDstHost->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_INFORM_MSG], 1);
		    incrementTrafficCounter(&srcHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_INFORM_MSG], 1);
		    break;
		  case FLAG_DHCP_UNKNOWN_MSG:
		  default:
		    incrementTrafficCounter(&realDstHost->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_UNKNOWN_MSG], 1);
		    incrementTrafficCounter(&srcHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_UNKNOWN_MSG], 1);
		    break;
		  }
		  idx += len;
		  break;
		case 58: /* Renewal time */
		  len = bootProto.bp_vend[idx++];
		  if(len == 4) {
		    memcpy(&tmpUlong, &bootProto.bp_vend[idx], sizeof(hostIpAddress.s_addr));
		    NTOHL(tmpUlong);
#ifdef FLAG_DHCP_DEBUG
		    traceEvent(CONST_TRACE_INFO, "Renewal time: %u", tmpUlong);
#endif
		    realDstHost->protocolInfo->dhcpStats->renewalTime = myGlobals.actTime+tmpUlong;
		  }
		  idx += len;
		  break;
		case 59: /* Rebinding time */
		  len = bootProto.bp_vend[idx++];
		  if(len == 4) {
		    memcpy(&tmpUlong, &bootProto.bp_vend[idx], sizeof(hostIpAddress.s_addr));
		    NTOHL(tmpUlong);
#ifdef FLAG_DHCP_DEBUG
		    traceEvent(CONST_TRACE_INFO, "Rebinding time: %u", tmpUlong);
#endif
		  }
		  idx += len;
		  break;
		case 64: /* NIS+ Domain */
		  len = bootProto.bp_vend[idx++];
		  memcpy(&hostIpAddress.s_addr, &bootProto.bp_vend[idx], sizeof(hostIpAddress.s_addr));
		  NTOHL(hostIpAddress.s_addr);
#ifdef FLAG_DHCP_DEBUG
		  traceEvent(CONST_TRACE_INFO, "NIS+ domain: %s", intoa(hostIpAddress));
#endif
		  idx += len;
		  break;
		default:
#ifdef DEBUG
		  traceEvent(CONST_TRACE_INFO, "Unknown DHCP option '%d'", (int)optionId);
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

      FD_SET(FLAG_HOST_TYPE_SVC_DHCP_CLIENT, &srcHost->flags);
      FD_SET(FLAG_HOST_TYPE_SVC_DHCP_SERVER, &dstHost->flags);

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
#ifdef FLAG_DHCP_DEBUG
	  char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];
#endif

	  NTOHL(bootProto.bp_yiaddr.s_addr);
#ifdef FLAG_DHCP_DEBUG
	  traceEvent(CONST_TRACE_INFO, "%s", etheraddr_string(bootProto.bp_chaddr, etherbuf));
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

	    realClientHost = findHostByMAC(bootProto.bp_chaddr, srcHost->vlanId, actualDeviceId);
	    if(realClientHost == NULL) {
	      realClientHost = lookupHost(/*&bootProto.bp_yiaddr*/ NULL, bootProto.bp_chaddr,
					  srcHost->vlanId, 0, 0, actualDeviceId);
	    } else {
#ifdef FLAG_DHCP_DEBUG
	      traceEvent(CONST_TRACE_INFO, "<<=>> %s (%d)",
			 realClientHost->hostResolvedName,
			 broadcastHost(realClientHost));
#endif
	    }

	    if(realClientHost != NULL) {
	      if(realClientHost->protocolInfo == NULL) realClientHost->protocolInfo = calloc(1, sizeof(ProtocolInfo));

	      if(realClientHost->protocolInfo->dhcpStats == NULL) {
		realClientHost->protocolInfo->dhcpStats = (DHCPStats*)malloc(sizeof(DHCPStats));
		memset(realClientHost->protocolInfo->dhcpStats, 0, sizeof(DHCPStats));
	      }

	      while(idx < 64 /* Length of the BOOTP vendor-specific area */) {
		u_char optionId = bootProto.bp_vend[idx++];

		if(optionId == 255) break; /* End of options */
		switch(optionId) { /* RFC 2132 */
		case 12: /* Host name */
		  len = bootProto.bp_vend[idx++];
		  savechar = bootProto.bp_vend[idx+len];
		  bootProto.bp_vend[idx+len] = '\0';
#ifdef FLAG_DHCP_DEBUG
		  traceEvent(CONST_TRACE_INFO, "Host name: %s", &bootProto.bp_vend[idx]);
#endif
		  /* Fix courtesy of Christoph Zens <chris@topfen.homeip.net> */
		  if(len >= (MAX_LEN_SYM_HOST_NAME-1)) {
		    bootProto.bp_vend[idx+MAX_LEN_SYM_HOST_NAME-2] = '\0';
		    len = MAX_LEN_SYM_HOST_NAME-1;
		  }

                  setResolvedName(realClientHost, &bootProto.bp_vend[idx], FLAG_HOST_SYM_ADDR_TYPE_NAME);
		  realClientHost->hostResolvedName[len] = '\0';
		  bootProto.bp_vend[idx+len] = savechar;
		  idx += len;
		  break;
		case 53: /* DHCP Message Type */
		  len = bootProto.bp_vend[idx++];
#ifdef FLAG_DHCP_DEBUG
		  traceEvent(CONST_TRACE_INFO, "DHCP Message Type: %d", bootProto.bp_vend[idx]);
#endif
		  switch((int)bootProto.bp_vend[idx]) {
		  case FLAG_DHCP_DISCOVER_MSG:
		    incrementTrafficCounter(&realClientHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_DISCOVER_MSG], 1);
		    break;
		  case FLAG_DHCP_OFFER_MSG:
		    incrementTrafficCounter(&realClientHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_OFFER_MSG], 1);
		    break;
		  case FLAG_DHCP_REQUEST_MSG:
		    incrementTrafficCounter(&realClientHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_REQUEST_MSG], 1);
		    break;
		  case FLAG_DHCP_DECLINE_MSG:
		    incrementTrafficCounter(&realClientHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_DECLINE_MSG], 1);
		    break;
		  case FLAG_DHCP_ACK_MSG:
		    incrementTrafficCounter(&realClientHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_ACK_MSG], 1);
		    break;
		  case FLAG_DHCP_NACK_MSG:
		    incrementTrafficCounter(&realClientHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_NACK_MSG], 1);
		    break;
		  case FLAG_DHCP_RELEASE_MSG:
		    incrementTrafficCounter(&realClientHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_RELEASE_MSG], 1);
		    break;
		  case FLAG_DHCP_INFORM_MSG:
		    incrementTrafficCounter(&realClientHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_INFORM_MSG], 1);
		    break;
		  case FLAG_DHCP_UNKNOWN_MSG:
		  default:
		    incrementTrafficCounter(&realClientHost->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_UNKNOWN_MSG], 1);
		    break;
		  }
		  idx += len;
		  break;
		default:
#ifdef DEBUG
		  traceEvent(CONST_TRACE_INFO, "Unknown DHCP option '%d'", (int)optionId);
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
  datum key_data, data_data;
  char tmpBuf[96];
  u_int16_t transactionId = 0;
  int i, queryNameLength;

  memset(tmpBuf, 0, sizeof(tmpBuf)); /* quiet Valgrind */

  if(myGlobals.dnsCacheFile == NULL) return(-1); /* ntop is quitting... */

  if((!myGlobals.enablePacketDecoding)
     ||(packetData == NULL) /* packet too short ? */)
    return(transactionId);

  myGlobals.dnsSniffCount++;
  memset(&hostPtr, 0, sizeof(DNSHostInfo));

  transactionId = handleDNSpacket(packetData, &hostPtr, length,
				  isRequest, positiveReply);

#ifdef DNS_SNIFF_DEBUG
  if((hostPtr.queryType == T_A)
     && (hostPtr.queryName[0] != '\0')
     && (hostPtr.addrList[0] != '\0')) {
    traceEvent(CONST_TRACE_INFO, "DNS_SNIFF_DEBUG: DNS %s for %s type %d", *isRequest ? "request" : "reply",
	       hostPtr.queryName, hostPtr.queryType);

    for(i=0; i<MAX_ALIASES; i++)
      if(hostPtr.aliases[i][0] != '\0') {
	traceEvent(CONST_TRACE_INFO, "DNS_SNIFF_DEBUG: %s is alias %d of %s", hostPtr.aliases[i], i, hostPtr.name);
      }
  }
#endif

  if(*isRequest) {
    myGlobals.dnsSniffRequestCount++;
    return(transactionId);
  }
  if(!*positiveReply) {
    myGlobals.dnsSniffFailedCount++;
    return(transactionId);
  }

  queryNameLength = strlen(hostPtr.queryName);
  strtolower(hostPtr.queryName);

  if((queryNameLength > 5)
     && (strncmp(&hostPtr.queryName[queryNameLength-5], ".arpa", 5) == 0)) {
    myGlobals.dnsSniffARPACount++;
    return(transactionId);
  }

  for(i=0; i<MAX_ADDRESSES; i++) {
  	/* Symbolic => Numeric */

    if(hostPtr.addrList[i] != 0) {
      StoredAddress storedAddress;

      memset(&storedAddress, 0, sizeof(storedAddress));
      storedAddress.recordCreationTime = myGlobals.actTime;
      memcpy(&storedAddress.symAddress,
             hostPtr.queryName,
             min(MAX_LEN_SYM_HOST_NAME-1, strlen(hostPtr.queryName)));
      storedAddress.symAddressType=FLAG_HOST_SYM_ADDR_TYPE_NAME;

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%u", ntohl(hostPtr.addrList[i]));
      key_data.dptr = (void*)&tmpBuf;
      key_data.dsize = strlen(key_data.dptr)+1;
      data_data.dptr = (void*)&storedAddress;
      data_data.dsize = sizeof(storedAddress)+1;

#ifdef DNS_SNIFF_DEBUG
      traceEvent(CONST_TRACE_INFO, "DNS_SNIFF_DEBUG: Sniffed DNS response: %s(%d) = %s(t=%d)",
                 key_data.dptr, key_data.dsize,
                 ((StoredAddress *)data_data.dptr)->symAddress,
                 ((StoredAddress *)data_data.dptr)->recordCreationTime);
#endif

      if(myGlobals.dnsCacheFile == NULL) return(-1); /* ntop is quitting... */
      gdbm_store(myGlobals.dnsCacheFile, key_data, data_data, GDBM_REPLACE);
      myGlobals.dnsSniffStoredInCache++;
    }
  }

  return(transactionId);
}

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

  if((!myGlobals.enablePacketDecoding) || (srcHost->nonIPTraffic != NULL) /* Already set */
     || (packetData == NULL)) /* packet too short ? */
    return;
  
  udpDataLen = length - (hlen + sizeof(struct udphdr));
  
  if(dport == 137 /*  NetBIOS */) {
    if(udpDataLen > 32) {
      /* 32 bytes or less is not enough */
      u_int8_t opcode;

      opcode = (tmpdata[2] >> 3) & 0x0F;

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
	u_int8_t doDecode = 0;
	nodeType = name_interpret(name, nbName, udpDataLen-displ);

	switch(opcode) {
	case 0: /* Query */
	  switch(nodeType) {
	  case 0x1C: /* Domain Controller */
	  case 0x1E: /* Domain */
	  case 0x1B: /* Domain */
	  case 0x1D: /* Workgroup (I think) */
	    doDecode = 1;
	    break;
	  }
	  break;
	case 5: /* Registration */
	case 6: /* Release      */
	  doDecode = 1;
	  break;
	}
	
#ifdef DEBUG
	traceEvent(CONST_TRACE_INFO, "Found: %s", nbName);
#endif

	/* Set the domain/workgroup only when needed */
	setNBnodeNameType(srcHost, (char)nodeType, opcode == 0 ? 1 : 0, nbName);
      }

      free(data);      
    }
  } else if(dport == 138 /*  NetBIOS */) {
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
	  setNBnodeNameType(srcHost, (char)nodeType, 0, nbName);

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

		setNBnodeNameType(dstHost, (char)nodeType, 0, domain);

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

		      if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
		      if(srcHost->nonIPTraffic->nbDescr != NULL)
			free(srcHost->nonIPTraffic->nbDescr);

		      if(tmpBuffer[17] == 0x0F)
			FD_SET(FLAG_HOST_TYPE_MASTER_BROWSER, &srcHost->flags);

		      srcHost->nonIPTraffic->nbDescr = strdup(&tmpBuffer[49]);
#ifdef DEBUG
		      traceEvent(CONST_TRACE_INFO, "Computer Info: '%s'", srcHost->nonIPTraffic->nbDescr);
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

	if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	if(dstHost->nonIPTraffic == NULL) dstHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));

	if((decodedStr[0] != '\0') && (dstHost->nonIPTraffic->nbHostName == NULL))
	  dstHost->nonIPTraffic->nbHostName = strdup(decodedStr); /* dst before src */

	pos = 5+(2*strlen(decodedStr))+2;
	decodeNBstring(&data[pos], decodedStr);

	if((decodedStr[0] != '\0') && (srcHost->nonIPTraffic->nbHostName == NULL))
	  srcHost->nonIPTraffic->nbHostName = strdup(decodedStr);
      } else if((data[0] == 0x0) /* Message type: Session message */
		&& (data[8] == 0x73) /* SMB Command: SMBsesssetupX */) {
#ifdef DEBUG
	for(i=0; i<udpDataLen; i++)
	  printf("0x%X (%d)\n", data[i], i);
#endif

	if(sport == 139) {
	  /* Response */
#ifdef DEBUG
	  printf("OS: %s\n", &data[45]);
#endif

	  if(srcHost->fingerprint == NULL) {
	    char buffer[64];

	    safe_snprintf(__FILE__, __LINE__, buffer, sizeof(buffer), ":%s", &data[45]);
	    accessAddrResMutex("makeHostLink");
	    srcHost->fingerprint = strdup(buffer);
	    releaseAddrResMutex();
	  }
	} else /* dport == 139 */ {
	  /* Request */
	  char len;

	  len = data[51]+data[53]; /* ANSI and UNICODE pw length */

	  i = 65+len;

	  if(srcHost->nonIPTraffic == NULL) srcHost->nonIPTraffic = (NonIPTraffic*)calloc(1, sizeof(NonIPTraffic));
	  if(srcHost->nonIPTraffic->nbAccountName == NULL) srcHost->nonIPTraffic->nbAccountName = strdup(&data[i]);
#ifdef DEBUG
	  printf("Account Name: %s\n", &data[i]);
#endif
	  while((data[i] != 0) && (i < sizeof(data))) i++;
	  i++;
#ifdef DEBUG
	  printf("Domain: %s\n", &data[i]);
#endif
	  if(srcHost->nonIPTraffic->nbDomainName == NULL) srcHost->nonIPTraffic->nbDomainName = strdup(&data[i]);
	  while((data[i] != 0) && (i < sizeof(data))) i++;
	  i++;
#ifdef DEBUG
	  printf("OS: %s\n", &data[i]);
#endif


	  if(srcHost->fingerprint == NULL) {
	    char buffer[64];

	    safe_snprintf(__FILE__, __LINE__, buffer, sizeof(buffer), ":%s", &data[i]);
	    accessAddrResMutex("makeHostLink");
	    srcHost->fingerprint = strdup(buffer);
	    releaseAddrResMutex();
	  }
	}
      }

      free(data);
    }
  }
}


