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
  char buf[256], key[64];
  int idx, numEntries=0, languageType=DEFAULT_LANGUAGE, j;
  HostTraffic *el;

  memset(key, 0, sizeof(key));

  if(options != NULL) {
    /* language=[perl|php] */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0;

      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcmp(tmpStr, "language") == 0) {
	  if(strcmp(&tmpStr[i+1], "perl") == 0)
	    languageType = PERL_LANGUAGE;
	  else
	    languageType = DEFAULT_LANGUAGE;
	} else if(strcmp(tmpStr, "key") == 0) {
	  strncpy(key, &tmpStr[i+1], sizeof(key));
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }

  if(languageType == PERL_LANGUAGE)
    sendString("%hash = (\n");
  else
    sendString("$hash = array(\n");

  for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++) {
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && (broadcastHost(el) == 0)) {
      char *hostKey;

      if(key[0] != '\0') {
	if(strcmp(el->hostNumIpAddress, key)
	   && strcmp(el->ethAddressString, key)
	   && strcmp(el->hostSymIpAddress, key))
	  continue;
	}

      if(el->hostNumIpAddress[0] != '\0')
	hostKey = el->hostNumIpAddress;
      else
	hostKey = el->ethAddressString;

      if(numEntries > 0) {
	if(languageType == PERL_LANGUAGE)
	  sendString("},\n\n");
	else
	  sendString("),\n\n");
      }

      if(languageType == PERL_LANGUAGE) {
	if(snprintf(buf, sizeof(buf), "'%s' => {\n", hostKey) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      } else {
	if(snprintf(buf, sizeof(buf), "'%s' => array(\n", hostKey) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      /* ************************ */

      if(snprintf(buf, sizeof(buf), "\t'%s' => %d,\n", "index", idx) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);

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

      if(snprintf(buf, sizeof(buf), "\t'%s' => %ld,\n", "firstSeen", el->firstSeen)
	 < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);

      if(snprintf(buf, sizeof(buf), "\t'%s' => %ld,\n", "lastSeen", el->lastSeen)
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

	if(el->nbAccountName != NULL) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "nbAccountName", el->nbAccountName)
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
	}

	if(el->nbDescr != NULL) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "nbDescr", el->nbDescr)
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
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n", "pktSent", el->pktSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
      }

      if(el->pktReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "pktReceived", el->pktReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->pktDuplicatedAckSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "pktDuplicatedAckSent",
		    el->pktDuplicatedAckSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->pktDuplicatedAckRcvd > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "pktDuplicatedAckRcvd",
		    el->pktDuplicatedAckRcvd)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->pktBroadcastSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "pktBroadcastSent", el->pktBroadcastSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->bytesBroadcastSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "bytesBroadcastSent", el->bytesBroadcastSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->pktMulticastSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "pktMulticastSent", el->pktMulticastSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->bytesMulticastSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "bytesMulticastSent", el->bytesMulticastSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->pktMulticastRcvd > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "pktMulticastRcvd", el->pktMulticastRcvd)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->bytesSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "bytesSent", el->bytesSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->bytesSentLocally > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "bytesSentLocally", el->bytesSentLocally)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->bytesSentRemotely > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "bytesSentRemotely", el->bytesSentRemotely)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->bytesReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "bytesReceived", el->bytesReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->bytesReceivedLocally > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "bytesReceivedLocally", el->bytesReceivedLocally)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->bytesReceivedFromRemote > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
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
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "tcpSentLocally", el->tcpSentLocally)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->tcpSentRemotely > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "tcpSentRemotely", el->tcpSentRemotely)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->udpSentLocally > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "udpSentLocally", el->udpSentLocally)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->udpSentRemotely > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "udpSentRemotely", el->udpSentRemotely)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->icmpSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "icmpSent", el->icmpSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->ospfSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "ospfSent", el->ospfSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->igmpSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "igmpSent", el->igmpSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->tcpReceivedLocally > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "tcpReceivedLocally", el->tcpReceivedLocally)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->tcpReceivedFromRemote > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "tcpReceivedFromRemote", el->tcpReceivedFromRemote)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->udpReceivedLocally > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "udpReceivedLocally", el->udpReceivedLocally)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->udpReceivedFromRemote > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "udpReceivedFromRemote",
		    el->udpReceivedFromRemote)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->icmpReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "icmpReceived", el->icmpReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->ospfReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "ospfReceived", el->ospfReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->igmpReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "igmpReceived", el->igmpReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      /* ***************************** */

      if(el->stpSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "stpSent", el->stpSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->stpReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "stpReceived", el->stpReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->ipxSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "ipxSent", el->ipxSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->ipxReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "ipxReceived", el->ipxReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->osiSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "osiSent", el->osiSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->osiReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "osiReceived", el->osiReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->dlcSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "dlcSent", el->dlcSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->dlcReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "dlcReceived", el->dlcReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->arp_rarpSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "arp_rarpSent", el->arp_rarpSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->arp_rarpReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "arp_rarpReceived", el->arp_rarpReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->arpReqPktsSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "arpReqPktsSent", el->arpReqPktsSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->arpReplyPktsSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "arpReplyPktsSent", el->arpReplyPktsSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->arpReplyPktsRcvd > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "arpReplyPktsRcvd", el->arpReplyPktsRcvd)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->decnetSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "decnetSent", el->decnetSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->decnetReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "decnetReceived", el->decnetReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->appletalkSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "appletalkSent", el->appletalkSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->appletalkReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "appletalkReceived", el->appletalkReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->netbiosSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "netbiosSent", el->netbiosSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->netbiosReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "netbiosReceived", el->netbiosReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->qnxSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "qnxSent", el->qnxSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->qnxReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "qnxReceived", el->qnxReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->otherSent > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n", "otherSent", el->otherSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->otherReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %llu,\n",
		    "otherReceived", el->otherReceived)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

          /* ********************************* */

    if(languageType == PERL_LANGUAGE) {
      if(snprintf(buf, sizeof(buf), "\t'%s' => {\n",
		  "IP") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    } else {
      if(snprintf(buf, sizeof(buf), "\t'%s' => array(\n",
		  "IP") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }

    for(j=0; j<numIpProtosToMonitor; j++) {
      if(j > 0) {
	if(languageType == PERL_LANGUAGE)
	  sendString("\t\t},\n\n");
	else
	  sendString("\t\t),\n\n");
      }

      if(languageType == PERL_LANGUAGE) {
	if(snprintf(buf, sizeof(buf), "\t\t'%s' => {\n",
		    protoIPTrafficInfos[j]) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      } else {
	if(snprintf(buf, sizeof(buf), "\t\t'%s' => array(\n",
		    protoIPTrafficInfos[j]) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(snprintf(buf, sizeof(buf), "\t\t\t'sentLocally' => '%llu',\n",
		  el->protoIPTrafficInfos[j].sentLocally) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
	sendString(buf);

      if(snprintf(buf, sizeof(buf), "\t\t\t'sentRemotely' => '%llu',\n",
		  el->protoIPTrafficInfos[j].sentRemotely) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
	sendString(buf);

      if(snprintf(buf, sizeof(buf), "\t\t\t'receivedLocally' => '%llu',\n",
		  el->protoIPTrafficInfos[j].receivedLocally) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
	sendString(buf);

      if(snprintf(buf, sizeof(buf), "\t\t\t'receivedFromRemote' => '%llu'\n",
		  el->protoIPTrafficInfos[j].receivedFromRemote) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
	sendString(buf);
    }

    if(languageType == PERL_LANGUAGE)
      sendString("\t\t}\n");
    else
      sendString("\t\t)\n");


    if(languageType == PERL_LANGUAGE)
      sendString("\t},\n\n");
    else
      sendString("\t),\n\n");

    /* ***************************************** */

      if(el->icmpInfo != NULL) {
	if(languageType == PERL_LANGUAGE) {
	  if(snprintf(buf, sizeof(buf), "\t'icmp' => {\n") < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	} else {
	  if(snprintf(buf, sizeof(buf), "\t'icmp' => array(\n") < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	}
	sendString(buf);

	if(el->icmpInfo->icmpMsgSent[ICMP_ECHO] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_ECHO",
		      el->icmpInfo->icmpMsgSent[ICMP_ECHO])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_ECHOREPLY",
		      el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_UNREACH] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_UNREACH",
		      el->icmpInfo->icmpMsgSent[ICMP_UNREACH])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_ROUTERADVERT",
		      el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_TIMXCEED",
		      el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_PARAMPROB",
		      el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_MASKREPLY",
		      el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_MASKREQ] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_MASKREQ",
		      el->icmpInfo->icmpMsgSent[ICMP_MASKREQ])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_INFO_REQUEST:",
		      el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_INFO_REPLY",
		      el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_TIMESTAMP",
		      el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_TIMESTAMPREPLY",
		      el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "SENT_SOURCE_QUENCH",
		      el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	/* *********************************************** */

	if(el->icmpInfo->icmpMsgRcvd[ICMP_ECHO] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "RCVD_ECHO",
		      el->icmpInfo->icmpMsgRcvd[ICMP_ECHO])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "RCVD_ECHOREPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "RCVD_UNREACH",
		      el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "RCVD_ROUTERADVERT",
		      el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "RCVD_TIMXCEED",
		      el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "ICMP_PARAMPROB",
		      el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "RCVD_MASKREPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "RCVD_MASKREQ",
		      el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "RCVD_INFO_REQUEST:",
		      el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "RCVD_INFO_REPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "RCVD_TIMESTAMP",
		      el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "RCVD_TIMESTAMPREPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH] > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => %ld,\n",
		      "RCVD_SOURCE_QUENCH",
		      el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH])
	     < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}
	if(languageType == PERL_LANGUAGE)
	  sendString("\t},\n\n");
	else
	  sendString("\t),\n\n");
      }

    /* ********************************* */

      if(el->securityHostPkts != NULL) {
	if(languageType == PERL_LANGUAGE) {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => {\n", "securityPkts") < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	} else {
	  if(snprintf(buf, sizeof(buf), "\t'%s' => array(\n","securityPkts") < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(el->securityHostPkts->synPktsSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "synPktsSent", el->securityHostPkts->synPktsSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->synPktsRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "synPktsRcvd", el->securityHostPkts->synPktsRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->rstPktsSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "rstPktsSent", el->securityHostPkts->rstPktsSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->rstPktsRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "rstPktsRcvd", el->securityHostPkts->rstPktsRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->rstAckPktsSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "rstAckPktsSent", el->securityHostPkts->rstAckPktsSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->rstAckPktsRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "rstAckPktsRcvd", el->securityHostPkts->rstAckPktsRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->synFinPktsSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "synFinPktsSent", el->securityHostPkts->synFinPktsSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->synFinPktsRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "synFinPktsRcvd", el->securityHostPkts->synFinPktsRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->finPushUrgPktsSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "finPushUrgPktsSent", el->securityHostPkts->finPushUrgPktsSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->finPushUrgPktsRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "finPushUrgPktsRcvd", el->securityHostPkts->finPushUrgPktsRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->nullPktsSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "nullPktsSent", el->securityHostPkts->nullPktsSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->nullPktsRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "nullPktsRcvd", el->securityHostPkts->nullPktsRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->ackScanSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "ackScanSent",
		      el->securityHostPkts->ackScanSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->ackScanRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "ackScanRcvd",
		      el->securityHostPkts->ackScanRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->xmasScanSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "xmasScanSent",
		      el->securityHostPkts->xmasScanSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->xmasScanRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "xmasScanRcvd",
		      el->securityHostPkts->xmasScanRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->finScanSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "finScanSent",
		      el->securityHostPkts->finScanSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->finScanRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "finScanRcvd",
		      el->securityHostPkts->finScanRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->nullScanSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "nullScanSent",
		      el->securityHostPkts->nullScanSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->nullScanRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "nullScanRcvd",
		      el->securityHostPkts->nullScanRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->rejectedTCPConnSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "rejectedTCPConnSent",
		      el->securityHostPkts->rejectedTCPConnSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->rejectedTCPConnRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "rejectedTCPConnRcvd",
		      el->securityHostPkts->rejectedTCPConnRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->establishedTCPConnSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "establishedTCPConnSent",
		      el->securityHostPkts->establishedTCPConnSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->establishedTCPConnRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "establishedTCPConnRcvd",
		      el->securityHostPkts->establishedTCPConnRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->udpToClosedPortSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "udpToClosedPortSent",
		      el->securityHostPkts->udpToClosedPortSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->udpToClosedPortRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "udpToClosedPortRcvd",
		      el->securityHostPkts->udpToClosedPortRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->udpToDiagnosticPortSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "udpToDiagnosticPortSent",
		      el->securityHostPkts->udpToDiagnosticPortSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->udpToDiagnosticPortRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "udpToDiagnosticPortRcvd",
		      el->securityHostPkts->udpToDiagnosticPortRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->tcpToDiagnosticPortSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "tcpToDiagnosticPortSent",
		      el->securityHostPkts->tcpToDiagnosticPortSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->tcpToDiagnosticPortRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "tcpToDiagnosticPortRcvd",
		      el->securityHostPkts->tcpToDiagnosticPortRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->tinyFragmentSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "tinyFragmentSent",
		      el->securityHostPkts->tinyFragmentSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->tinyFragmentRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "tinyFragmentRcvd",
		      el->securityHostPkts->tinyFragmentRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->icmpFragmentSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "icmpFragmentSent",
		      el->securityHostPkts->icmpFragmentSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->icmpFragmentRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "icmpFragmentRcvd",
		      el->securityHostPkts->icmpFragmentRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->overlappingFragmentSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "overlappingFragmentSent",
		      el->securityHostPkts->overlappingFragmentSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->overlappingFragmentRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "overlappingFragmentRcvd",
		      el->securityHostPkts->overlappingFragmentRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->closedEmptyTCPConnSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "closedEmptyTCPConnSent",
		      el->securityHostPkts->closedEmptyTCPConnSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->closedEmptyTCPConnRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "closedEmptyTCPConnRcvd",
		      el->securityHostPkts->closedEmptyTCPConnRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->icmpPortUnreachSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "icmpPortUnreachSent",
		      el->securityHostPkts->icmpPortUnreachSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->icmpPortUnreachRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "icmpPortUnreachRcvd",
		      el->securityHostPkts->icmpPortUnreachRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->icmpHostNetUnreachSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "icmpHostNetUnreachSent",
		      el->securityHostPkts->icmpHostNetUnreachSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->icmpHostNetUnreachRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "icmpHostNetUnreachRcvd",
		      el->securityHostPkts->icmpHostNetUnreachRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->icmpProtocolUnreachSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "icmpProtocolUnreachSent",
		      el->securityHostPkts->icmpProtocolUnreachSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->icmpProtocolUnreachRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "icmpProtocolUnreachRcvd",
		      el->securityHostPkts->icmpProtocolUnreachRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->icmpAdminProhibitedSent.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "icmpAdminProhibitedSent",
		      el->securityHostPkts->icmpAdminProhibitedSent.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(el->securityHostPkts->icmpAdminProhibitedRcvd.value > 0) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		      "icmpAdminProhibitedRcvd",
		      el->securityHostPkts->icmpAdminProhibitedRcvd.value) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  else
	    sendString(buf);
	}

	if(languageType == PERL_LANGUAGE)
	  sendString("\t},\n\n");
	else
	  sendString("\t),\n\n");
      }

    /* ***************************** */

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

/* ********************************** */

void dumpNtopHashIndexes(char* options) {
  char buf[256];
  int idx, numEntries=0, languageType=DEFAULT_LANGUAGE;
  HostTraffic *el;

  if(options != NULL) {
    /* language=[perl|php] */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0;

      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcmp(tmpStr, "language") == 0) {
	  if(strcmp(&tmpStr[i+1], "perl") == 0)
	    languageType = PERL_LANGUAGE;
	  else
	    languageType = DEFAULT_LANGUAGE;
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }

  if(languageType == PERL_LANGUAGE)
    sendString("%hash = (\n");
  else
    sendString("$hash = array(\n");

  for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++) {
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && (broadcastHost(el) == 0)) {
      char *hostKey;

      if(numEntries > 0)
	sendString(",\n");

      if(el->hostNumIpAddress[0] != '\0')
	hostKey = el->hostNumIpAddress;
      else
	hostKey = el->ethAddressString;

      if(snprintf(buf, sizeof(buf), "\t'%d' => '%s'", idx, hostKey) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      numEntries++;
    }
  }

  sendString("\n);\n");
}

/* ********************************** */

void dumpNtopTrafficInfo(char* options) {
  char buf[256], intoabuf[32], key[16];
  int languageType=DEFAULT_LANGUAGE, i;

   memset(key, 0, sizeof(key));

  if(options != NULL) {
    /* language=[perl|php] */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0;

      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcmp(tmpStr, "language") == 0) {
	  if(strcmp(&tmpStr[i+1], "perl") == 0)
	    languageType = PERL_LANGUAGE;
	  else
	    languageType = DEFAULT_LANGUAGE;
	} else if(strcmp(tmpStr, "key") == 0) {
	  strncpy(key, &tmpStr[i+1], sizeof(key));
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }

  if(languageType == PERL_LANGUAGE)
    sendString("%interfaces = (\n");
  else
    sendString("$interfaces = array(\n");

  for(i=0; i<numDevices; i++) {
    int j;

    if(device[i].virtualDevice) continue;

    if(i > 0) {
      if(languageType == PERL_LANGUAGE)
	sendString("},\n\n");
      else
	sendString("),\n\n");
    }

    if((key[0] != '\0') && (strcmp(key, device[i].name) != 0))
      continue;

    if(languageType == PERL_LANGUAGE) {
      if(snprintf(buf, sizeof(buf), "'%s' => {\n", device[i].name) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    } else {
      if(snprintf(buf, sizeof(buf), "'%s' => array(\n", device[i].name) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }

    if(device[i].ipdot != NULL) {
      if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "ipdot",
		  device[i].ipdot) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
	sendString(buf);
    }

    if(device[i].fqdn) {
      if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "fqdn", device[i].fqdn) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
	sendString(buf);
    }

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "network",
		_intoa(device[i].network, intoabuf, sizeof(intoabuf))) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "netmask",
		_intoa(device[i].netmask, intoabuf, sizeof(intoabuf))) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n", "ifAddr",
		_intoa(device[i].ifAddr, intoabuf, sizeof(intoabuf))) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%ld',\n",
		"started", device[i].started) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%ld',\n",
		"firstpkt", device[i].firstpkt) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%ld',\n",
		"lastpkt", device[i].lastpkt) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%d',\n",
		"virtualDevice",
		(int)device[i].virtualDevice) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%d',\n",
		"snaplen", device[i].snaplen) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%d',\n",
		"datalink", device[i].datalink) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%s',\n",
		"filter", device[i].filter ? device[i].filter : "") < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"droppedPackets", device[i].droppedPackets) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"ethernetPkts", device[i].ethernetPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"broadcastPkts", device[i].broadcastPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"multicastPkts", device[i].multicastPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"ethernetBytes", device[i].ethernetBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"ipBytes", device[i].ipBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"tcpBytes", device[i].tcpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"udpBytes", device[i].udpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"otherIpBytes", device[i].otherIpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"icmpBytes", device[i].icmpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"dlcBytes", device[i].dlcBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"ipxBytes", device[i].ipxBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"stpBytes", device[i].stpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"decnetBytes", device[i].decnetBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"netbiosBytes", device[i].netbiosBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"arpRarpBytes", device[i].arpRarpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"atalkBytes", device[i].atalkBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"ospfBytes", device[i].ospfBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"egpBytes", device[i].egpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"igmpBytes", device[i].igmpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"osiBytes", device[i].osiBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"qnxBytes", device[i].qnxBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"otherBytes", device[i].otherBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"lastMinEthernetBytes",
		device[i].lastMinEthernetBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"lastFiveMinsEthernetBytes",
		device[i].lastFiveMinsEthernetBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"lastMinEthernetPkts",
		device[i].lastMinEthernetPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"lastFiveMinsEthernetPkts",
		device[i].lastFiveMinsEthernetPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"upTo64", device[i].rcvdPktStats.upTo64) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"upTo128", device[i].rcvdPktStats.upTo128) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"upTo256", device[i].rcvdPktStats.upTo256) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"upTo512", device[i].rcvdPktStats.upTo512) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"upTo1024", device[i].rcvdPktStats.upTo1024) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"upTo1518", device[i].rcvdPktStats.upTo1518) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"above1518", device[i].rcvdPktStats.above1518) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"shortest",
		device[i].rcvdPktStats.shortest) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"longest",
		device[i].rcvdPktStats.longest) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"badChecksum",
		device[i].rcvdPktStats.badChecksum) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"tooLong",
		device[i].rcvdPktStats.tooLong) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%0.2f',\n",
		"peakThroughput", device[i].peakThroughput) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%0.2f',\n",
		"actualThpt", device[i].actualThpt) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%0.2f',\n",
		"lastMinThpt", device[i].lastMinThpt) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);


    if(snprintf(buf, sizeof(buf), "\t'%s' => '%0.2f',\n",
		"lastFiveMinsThpt", device[i].lastFiveMinsThpt) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%0.2f',\n",
		"peakPacketThroughput", device[i].peakPacketThroughput) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%0.2f',\n",
		"actualPktsThpt", device[i].actualPktsThpt) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%0.2f',\n",
		"lastMinPktsThpt", device[i].lastMinPktsThpt) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%0.2f',\n",
		"lastFiveMinsPktsThpt", device[i].lastFiveMinsPktsThpt) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n",
		"throughput", device[i].throughput) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%0.2f',\n",
		"packetThroughput",
		device[i].packetThroughput) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    /* ********************************* */

    if(languageType == PERL_LANGUAGE) {
      if(snprintf(buf, sizeof(buf), "\t'%s' => {\n",
		  "last60MinutesThpt") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    } else {
      if(snprintf(buf, sizeof(buf), "\t'%s' => array(\n",
		  "last60MinutesThpt") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }

    for(j=0; j<60; j++) {
      if(snprintf(buf, sizeof(buf), "\t\t'%d' => '%0.2f'",
		  j+1 , device[i].last60MinutesThpt[j].trafficValue) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
	sendString(buf);

      if(j < 59)
	sendString(",\n");
      else
	sendString("\n");
    }

    if(languageType == PERL_LANGUAGE)
      sendString("\t},\n\n");
    else
      sendString("\t),\n\n");

    /* ********************************* */

    if(languageType == PERL_LANGUAGE) {
      if(snprintf(buf, sizeof(buf), "\t'%s' => {\n",
		  "last24HoursThpt") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    } else {
      if(snprintf(buf, sizeof(buf), "\t'%s' => array(\n",
		  "last24HoursThpt") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }

    for(j=0; j<24; j++) {
      if(snprintf(buf, sizeof(buf), "\t\t'%d' => '%0.2f'",
		  j+1 , device[i].last24HoursThpt[j].trafficValue) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
	sendString(buf);

      if(j < 23)
	sendString(",\n");
      else
	sendString("\n");
    }

    if(languageType == PERL_LANGUAGE)
      sendString("\t},\n\n");
    else
      sendString("\t),\n\n");

    /* ********************************* */

    if(languageType == PERL_LANGUAGE) {
      if(snprintf(buf, sizeof(buf), "\t'%s' => {\n",
		  "last30daysThpt") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    } else {
      if(snprintf(buf, sizeof(buf), "\t'%s' => array(\n",
		  "last30daysThpt") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }

    for(j=0; j<30; j++) {
      if(snprintf(buf, sizeof(buf), "\t\t'%d' => '%0.2f'",
		  j+1 , device[i].last30daysThpt[j]) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
	sendString(buf);

      if(j < 29)
	sendString(",\n");
      else
	sendString("\n");
    }

    if(languageType == PERL_LANGUAGE)
      sendString("\t},\n\n");
    else
      sendString("\t),\n\n");

    /* ********************************* */

    if(device[i].ipProtoStats != NULL) {
      if(languageType == PERL_LANGUAGE) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => {\n",
		    "IP") < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      } else {
	if(snprintf(buf, sizeof(buf), "\t'%s' => array(\n",
		    "IP") < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      for(j=0; j<numIpProtosToMonitor; j++) {
	if(j > 0) {
	  if(languageType == PERL_LANGUAGE)
	    sendString("\t\t},\n\n");
	  else
	    sendString("\t\t),\n\n");
	}

	if(languageType == PERL_LANGUAGE) {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => {\n",
		      protoIPTrafficInfos[j]) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	} else {
	  if(snprintf(buf, sizeof(buf), "\t\t'%s' => array(\n",
		      protoIPTrafficInfos[j]) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}

	if(snprintf(buf, sizeof(buf), "\t\t\t'local' => '%llu',\n",
		    device[i].ipProtoStats[j].local) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	else
	  sendString(buf);

	if(snprintf(buf, sizeof(buf), "\t\t\t'local2remote' => '%llu',\n",
		    device[i].ipProtoStats[j].local2remote) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	else
	  sendString(buf);

	if(snprintf(buf, sizeof(buf), "\t\t\t'remote2local' => '%llu',\n",
		    device[i].ipProtoStats[j].remote2local) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	else
	  sendString(buf);

	if(snprintf(buf, sizeof(buf), "\t\t\t'remote' => '%llu'\n",
		    device[i].ipProtoStats[j].remote) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	else
	  sendString(buf);
      }

      if(languageType == PERL_LANGUAGE)
	sendString("\t\t}\n");
      else
	sendString("\t\t)\n");

      if(languageType == PERL_LANGUAGE)
	sendString("\t},\n\n");
      else
	sendString("\t),\n\n");
    }

    /* ********************************* */

    if(languageType == PERL_LANGUAGE) {
      if(snprintf(buf, sizeof(buf), "\t'%s' => {\n", "TCPflags") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    } else {
      if(snprintf(buf, sizeof(buf), "\t'%s' => array(\n","TCPflags") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }

    if(device[i].numEstablishedTCPConnections > 0) {
      if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%llu',\n",
		  "numEstablishedTCPConnections",
		  device[i].numEstablishedTCPConnections) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
      sendString(buf);
    }

    if(languageType == PERL_LANGUAGE)
      sendString("\t},\n\n");
    else
      sendString("\t),\n\n");

    /* ********************************* */

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n", "tcpLocal",
		device[i].tcpGlobalTrafficStats.local) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n", "tcpLocal2Remote",
		device[i].tcpGlobalTrafficStats.local2remote) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n", "tcpRemote",
		device[i].tcpGlobalTrafficStats.remote) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n", "tcpRemote2Local",
		device[i].tcpGlobalTrafficStats.remote2local) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    /* ********************************* */

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n", "udpLocal",
		device[i].udpGlobalTrafficStats.local) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n", "udpLocal2Remote",
		device[i].udpGlobalTrafficStats.local2remote) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n", "udpRemote",
		device[i].udpGlobalTrafficStats.remote) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n", "udpRemote2Local",
		device[i].udpGlobalTrafficStats.remote2local) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    /* ********************************* */

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n", "icmpLocal",
		device[i].icmpGlobalTrafficStats.local) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n", "icmpLocal2Remote",
		device[i].icmpGlobalTrafficStats.local2remote) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu',\n", "icmpRemote",
		device[i].icmpGlobalTrafficStats.remote) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%llu'\n", "icmpRemote2Local",
		device[i].icmpGlobalTrafficStats.remote2local) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
  }

  if(languageType == PERL_LANGUAGE)
    sendString("}\n\n");
  else
    sendString(")\n\n");

  sendString(");\n");
}
