/*
 *  Copyright (C) 2001 Luca Deri <deri@ntop.org>
 *
 *  		       http://www.ntop.org/
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
#include "globals-report.h"

#define PERL_LANGUAGE       1
#define PHP_LANGUAGE        2
#define DEFAULT_LANGUAGE    PHP_LANGUAGE


/* ********************************** */

void dumpNtopHashes(char* options) {
  char buf[256];
  int idx, numEntries=0, languageType=DEFAULT_LANGUAGE;
  HostTraffic *el;

  if((options != NULL) && (strlen(options) > 10)) {
    /* language=[perl|php] */
    
    if(strcmp(&options[9], "perl") == 0)
      languageType = PERL_LANGUAGE;
    else
      languageType = DEFAULT_LANGUAGE;
  }
    
  if(languageType == PERL_LANGUAGE)
    sendString("%hash = (\n");
  else
    sendString("$hash = array(\n");

  for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++) {
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && (broadcastHost(el) == 0)) {

      if(numEntries > 0) {
	if(languageType == PERL_LANGUAGE)
	  sendString("},\n\n");
	else
	  sendString("),\n\n");
      }

      if(languageType == PERL_LANGUAGE) {
	if(snprintf(buf, sizeof(buf), "'%s' => {\n",
		    el->hostNumIpAddress[0] != '\0' ? el->hostNumIpAddress : el->ethAddressString)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      } else {
	if(snprintf(buf, sizeof(buf), "'%s' => array(\n",
		    el->hostNumIpAddress[0] != '\0' ? el->hostNumIpAddress : el->ethAddressString)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      /* ************************ */

      if(el->hostNumIpAddress[0] != '\0') {
	if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "hostNumIpAddress",
		    el->hostNumIpAddress)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->hostSymIpAddress[0] != '\0') {
	if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "hostSymIpAddress",
		    el->hostSymIpAddress)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(snprintf(buf, sizeof(buf), "\t'%s' => %d,\n", "firstSeen", el->firstSeen)
	 < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);

      if(snprintf(buf, sizeof(buf), "\t'%s' => %d,\n", "lastSeen", el->lastSeen)
	 < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);

      if(snprintf(buf, sizeof(buf), "\t'%s' => %d,\n", "minTTL", el->minTTL)
	 < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);

      if(snprintf(buf, sizeof(buf), "\t'%s' => %d,\n", "maxTTL", el->maxTTL)
	 < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);

      if(el->nbHostName != NULL) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "nbHostName", el->nbHostName)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);

	if(el->nbDomainName != NULL) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "nbDomainName", el->nbDomainName)
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
	}

	if(snprintf(buf, sizeof(buf), "\t'%s' => %d,\n", "nbNodeType", el->nbNodeType)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
      }

      if(el->atNodeName != NULL) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "atNodeName", el->atNodeName)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);

	if(snprintf(buf, sizeof(buf), "\t'%s' => %d,\n", "atNetwork", el->atNetwork)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);

	if(snprintf(buf, sizeof(buf), "\t'%s' => %d,\n", "atNode", el->atNode)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
      }

      if(el->ipxHostName != NULL) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "ipxHostName", el->ipxHostName)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
      }

      if(el->pktSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", "pktSent", el->pktSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
      }

      if(el->pktReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "pktReceived", el->pktReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->pktDuplicatedAckSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "pktDuplicatedAckSent",
		    el->pktDuplicatedAckSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->pktDuplicatedAckRcvd > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "pktDuplicatedAckRcvd",
		    el->pktDuplicatedAckRcvd)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->pktBroadcastSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "pktBroadcastSent", el->pktBroadcastSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->bytesBroadcastSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "bytesBroadcastSent", el->bytesBroadcastSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->pktMulticastSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "pktMulticastSent", el->pktMulticastSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->bytesMulticastSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "bytesMulticastSent", el->bytesMulticastSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->pktMulticastRcvd > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "pktMulticastRcvd", el->pktMulticastRcvd)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->bytesSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "bytesSent", el->bytesSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->bytesSentLocally > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "bytesSentLocally", el->bytesSentLocally)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->bytesSentRemotely > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "bytesSentRemotely", el->bytesSentRemotely)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->bytesReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "bytesReceived", el->bytesReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->bytesReceivedLocally > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "bytesReceivedLocally", el->bytesReceivedLocally)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->bytesReceivedFromRemote > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "bytesReceivedFromRemote", 
		    el->bytesReceivedFromRemote)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->actualRcvdThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n", 
		    "actualRcvdThpt", el->actualRcvdThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->lastHourRcvdThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n", 
		    "lastHourRcvdThpt", el->lastHourRcvdThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->averageRcvdThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n", 
		    "averageRcvdThpt", el->averageRcvdThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->peakRcvdThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n",
		    "peakRcvdThpt", el->peakRcvdThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->actualSentThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n",
		    "actualSentThpt", el->actualSentThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->lastHourSentThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n", 
		    "lastHourSentThpt", el->lastHourSentThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->averageSentThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n", 
		    "averageSentThpt", el->averageSentThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->peakSentThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n",
		    "peakSentThpt", el->peakSentThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->actualRcvdPktThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n",
		    "actualRcvdPktThpt", el->actualRcvdPktThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->averageRcvdPktThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n", 
		    "averageRcvdPktThpt", el->averageRcvdPktThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->peakRcvdPktThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n", 
		    "peakRcvdPktThpt", el->peakRcvdPktThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->actualSentPktThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n", 
		    "actualSentPktThpt", el->actualSentPktThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->averageSentPktThpt > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %0.2f,\n", 
		    "averageSentPktThpt", el->averageSentPktThpt)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->tcpSentLocally > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "tcpSentLocally", el->tcpSentLocally)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->tcpSentRemotely > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "tcpSentRemotely", el->tcpSentRemotely)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->udpSentLocally > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "udpSentLocally", el->udpSentLocally)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->udpSentRemotely > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "udpSentRemotely", el->udpSentRemotely)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->icmpSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "icmpSent", el->icmpSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->ospfSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "ospfSent", el->ospfSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->igmpSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "igmpSent", el->igmpSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->tcpReceivedLocally > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "tcpReceivedLocally", el->tcpReceivedLocally)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->tcpReceivedFromRemote > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "tcpReceivedFromRemote", el->tcpReceivedFromRemote)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->udpReceivedLocally > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "udpReceivedLocally", el->udpReceivedLocally)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->udpReceivedFromRemote > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "udpReceivedFromRemote", 
		    el->udpReceivedFromRemote)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->icmpReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "icmpReceived", el->icmpReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->ospfReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "ospfReceived", el->ospfReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->igmpReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "igmpReceived", el->igmpReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->synPktsSent.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "synPktsSent", el->synPktsSent.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->rstPktsSent.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "rstPktsSent", el->rstPktsSent.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->synFinPktsSent.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "synFinPktsSent", el->synFinPktsSent.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->finPushUrgPktsSent.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "finPushUrgPktsSent", 
		    el->finPushUrgPktsSent.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->nullPktsSent.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "nullPktsSent", el->nullPktsSent.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->synPktsRcvd.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "synPktsRcvd", el->synPktsRcvd.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->rstPktsRcvd.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "rstPktsRcvd", el->rstPktsRcvd.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->synFinPktsRcvd.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "synFinPktsRcvd", el->synFinPktsRcvd.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->finPushUrgPktsRcvd.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "finPushUrgPktsRcvd", 
		    el->finPushUrgPktsRcvd.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->nullPktsRcvd.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "nullPktsRcvd", el->nullPktsRcvd.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->stpSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "stpSent", el->stpSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->stpRcvd > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "stpRcvd", el->stpRcvd)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->ipxSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "ipxSent", el->ipxSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->ipxReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "ipxReceived", el->ipxReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->osiSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "osiSent", el->osiSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->osiReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "osiReceived", el->osiReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->dlcSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "dlcSent", el->dlcSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->dlcReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "dlcReceived", el->dlcReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->arp_rarpSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "arp_rarpSent", el->arp_rarpSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->arp_rarpReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "arp_rarpReceived", el->arp_rarpReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->decnetSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "decnetSent", el->decnetSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->decnetReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "decnetReceived", el->decnetReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->appletalkSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "appletalkSent", el->appletalkSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->appletalkReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "appletalkReceived", el->appletalkReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->netbiosSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "netbiosSent", el->netbiosSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->netbiosReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "netbiosReceived", el->netbiosReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	sendString(buf);
      }

      if(el->qnxSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "qnxSent", el->qnxSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->qnxReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "qnxReceived", el->qnxReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->otherSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", "
otherSent", el->otherSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->otherReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		    "otherReceived", el->otherReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	sendString(buf);
      }

      if(el->icmpInfo != NULL) {
	int j;
	if(el->icmpInfo->icmpMsgSent[ICMP_ECHO] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "SENT_ICMP_ECHO",
		      el->icmpInfo->icmpMsgSent[ICMP_ECHO])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "SENT_ICMP_ECHOREPLY", 
		      el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_UNREACH] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "SENT_ICMP_UNREACH",
		      el->icmpInfo->icmpMsgSent[ICMP_UNREACH])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "SENT_ICMP_ROUTERADVERT", 
		      el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "SENT_ICMP_TIMXCEED", 
		      el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "SENT_ICMP_PARAMPROB",
		      el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "SENT_ICMP_MASKREPLY", 
		      el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_MASKREQ] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "SENT_ICMP_MASKREQ", 
		      el->icmpInfo->icmpMsgSent[ICMP_MASKREQ])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "SENT_ICMP_INFO_REQUEST:", 
		      el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		      "SENT_ICMP_INFO_REPLY", 
		      el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		      "SENT_ICMP_TIMESTAMP", 
		      el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "SENT_ICMP_TIMESTAMPREPLY", 
		      el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "SENT_ICMP_SOURCE_QUENCH", 
		      el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	  sendString(buf);
	}

	/* *********************************************** */
	if(el->icmpInfo->icmpMsgRcvd[ICMP_ECHO] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "RCVD_ICMP_ECHO", 
		      el->icmpInfo->icmpMsgRcvd[ICMP_ECHO])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "RCVD_ICMP_ECHOREPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "RCVD_ICMP_UNREACH", 
		      el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "RCVD_ICMP_ROUTERADVERT", 
		      el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "RCVD_ICMP_TIMXCEED", 
		      el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "ICMP_PARAMPROB", 
		      el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "RCVD_ICMP_MASKREPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "RCVD_ICMP_MASKREQ",
		      el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "RCVD_ICMP_INFO_REQUEST:", 
		      el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		      "RCVD_ICMP_INFO_REPLY", 
		      el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		      "RCVD_ICMP_TIMESTAMP", 
		      el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "RCVD_ICMP_TIMESTAMPREPLY", 
		      el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", 
		      "RCVD_ICMP_SOURCE_QUENCH", 
		      el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!"); 
	  sendString(buf);
	}
      } 

      if(el->ethAddressString[0] != '\0') {
	if(snprintf(buf, sizeof(buf), "\t'%s' => '%s'\n", "ethAddressString",
		    el->ethAddressString)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      numEntries++;
    }
  }

  if(languageType == PERL_LANGUAGE)
    sendString("}\n\n");
  else
    sendString(")\n\n");

  sendString(");\n");
}

