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

      /* ***************************** */

      if(languageType == PERL_LANGUAGE) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => {\n", 
		    "securityHostPkts") < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      } else {
	if(snprintf(buf, sizeof(buf), "\t'%s' => array(\n", 
		    "securityHostPkts") < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->securityHostPkts.synPktsSent.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "synPktsSent", el->securityHostPkts.synPktsSent.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }
      
      /* Added by Andreas Pfaller <a.pfaller@pop.gun.de> */
      if(el->securityHostPkts.rstAckPktsSent.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "rstAckPktsSent",
		    el->securityHostPkts.rstAckPktsSent.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->securityHostPkts.rstPktsSent.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "rstPktsSent",
		    el->securityHostPkts.rstPktsSent.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->securityHostPkts.synFinPktsSent.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "synFinPktsSent", 
		    el->securityHostPkts.synFinPktsSent.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->securityHostPkts.finPushUrgPktsSent.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "finPushUrgPktsSent",
		    el->securityHostPkts.finPushUrgPktsSent.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->securityHostPkts.nullPktsSent.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "nullPktsSent", 
		    el->securityHostPkts.nullPktsSent.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->securityHostPkts.synPktsRcvd.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "synPktsRcvd", 
		    el->securityHostPkts.synPktsRcvd.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      /* Added by Andreas Pfaller <a.pfaller@pop.gun.de> */
      if(el->securityHostPkts.rstAckPktsRcvd.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "rstAckPktsRcvd", 
		    el->securityHostPkts.rstAckPktsRcvd.value)
 	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
 	sendString(buf);
      }

      if(el->securityHostPkts.rstPktsRcvd.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "rstPktsRcvd", 
		    el->securityHostPkts.rstPktsRcvd.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->securityHostPkts.synFinPktsRcvd.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "synFinPktsRcvd", 
		    el->securityHostPkts.synFinPktsRcvd.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->securityHostPkts.finPushUrgPktsRcvd.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "finPushUrgPktsRcvd",
		    el->securityHostPkts.finPushUrgPktsRcvd.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->securityHostPkts.nullPktsRcvd.value > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
		    "nullPktsRcvd", 
		    el->securityHostPkts.nullPktsRcvd.value)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(languageType == PERL_LANGUAGE)
	sendString("\t},\n\n");
      else
	sendString("\t),\n\n");
 
      /* ***************************** */

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
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n", "otherSent", el->otherSent)
	   < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(el->otherReceived > 0) {
	if(snprintf(buf, sizeof(buf), "\t'%s' => %lu,\n",
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

      if(snprintf(buf, sizeof(buf), "\t\t\t'sentLocally' => '%lu',\n",
		  el->protoIPTrafficInfos[j].sentLocally) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
	sendString(buf);

      if(snprintf(buf, sizeof(buf), "\t\t\t'sentRemotely' => '%lu',\n",
		  el->protoIPTrafficInfos[j].sentRemotely) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
	sendString(buf);

      if(snprintf(buf, sizeof(buf), "\t\t\t'receivedLocally' => '%lu',\n",
		  el->protoIPTrafficInfos[j].receivedLocally) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      else
	sendString(buf);

      if(snprintf(buf, sizeof(buf), "\t\t\t'receivedFromRemote' => '%lu'\n",
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

    /* ********************************* */
    
    if(languageType == PERL_LANGUAGE) {
      if(snprintf(buf, sizeof(buf), "\t'%s' => {\n", "securityPkts") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    } else {
      if(snprintf(buf, sizeof(buf), "\t'%s' => array(\n","securityPkts") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"synPktsSent", el->securityHostPkts.synPktsSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
    
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"synPktsRcvd", el->securityHostPkts.synPktsRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
    
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"rstPktsSent", el->securityHostPkts.rstPktsSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
    
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"rstPktsRcvd", el->securityHostPkts.rstPktsRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
    
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"rstAckPktsSent", el->securityHostPkts.rstAckPktsSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
    
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"rstAckPktsRcvd", el->securityHostPkts.rstAckPktsRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
    
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"synFinPktsSent", el->securityHostPkts.synFinPktsSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"synFinPktsRcvd", el->securityHostPkts.synFinPktsRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"finPushUrgPktsSent", el->securityHostPkts.finPushUrgPktsSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
    
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"finPushUrgPktsRcvd", el->securityHostPkts.finPushUrgPktsRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
    
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"nullPktsSent", el->securityHostPkts.nullPktsSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
   
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"nullPkts", el->securityHostPkts.nullPktsRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
   
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"ackScanSent", 
		el->securityHostPkts.ackScanSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"ackScanRcvd", 
		el->securityHostPkts.ackScanRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"xmasScanSent", 
		el->securityHostPkts.xmasScanSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"xmasScanRcvd", 
		el->securityHostPkts.xmasScanRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"finScanSent", 
		el->securityHostPkts.finScanSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"finScanRcvd", 
		el->securityHostPkts.finScanRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"nullScanSent", 
		el->securityHostPkts.nullScanSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"nullScanRcvd", 
		el->securityHostPkts.nullScanRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"rejectedTCPConnSent", 
		el->securityHostPkts.rejectedTCPConnSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"rejectedTCPConnRcvd", 
		el->securityHostPkts.rejectedTCPConnRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"establishedTCPConnSent", 
		el->securityHostPkts.establishedTCPConnSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"establishedTCPConnRcvd", 
		el->securityHostPkts.establishedTCPConnRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"udpToClosedPortSent", 
		el->securityHostPkts.udpToClosedPortSent) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"udpToClosedPortRcvd", 
		el->securityHostPkts.udpToClosedPortRcvd) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(languageType == PERL_LANGUAGE)
      sendString("\t},\n\n");
    else
      sendString("\t),\n\n");

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

void dumpNtopTrafficInfo(char* options) {
  char buf[256], intoabuf[32], key[16];
  int numEntries=0, languageType=DEFAULT_LANGUAGE, i;

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

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"started", device[i].started) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"firstpkt", device[i].firstpkt) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
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

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"droppedPackets", device[i].droppedPackets) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"ethernetPkts", device[i].ethernetPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"broadcastPkts", device[i].broadcastPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"multicastPkts", device[i].multicastPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"ethernetBytes", device[i].ethernetBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"ipBytes", device[i].ipBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"tcpBytes", device[i].tcpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"udpBytes", device[i].udpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"otherIpBytes", device[i].otherIpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"icmpBytes", device[i].icmpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"dlcBytes", device[i].dlcBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"ipxBytes", device[i].ipxBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"stpBytes", device[i].stpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"decnetBytes", device[i].decnetBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"netbiosBytes", device[i].netbiosBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"arpRarpBytes", device[i].arpRarpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"atalkBytes", device[i].atalkBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"ospfBytes", device[i].ospfBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"egpBytes", device[i].egpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"igmpBytes", device[i].igmpBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"osiBytes", device[i].osiBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"qnxBytes", device[i].qnxBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"otherBytes", device[i].otherBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"lastMinEthernetBytes",
		device[i].lastMinEthernetBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"lastFiveMinsEthernetBytes",
		device[i].lastFiveMinsEthernetBytes) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"lastMinEthernetPkts",
		device[i].lastMinEthernetPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"lastFiveMinsEthernetPkts",
		device[i].lastFiveMinsEthernetPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"upTo64", device[i].rcvdPktStats.upTo64) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"upTo128", device[i].rcvdPktStats.upTo128) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"upTo256", device[i].rcvdPktStats.upTo256) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"upTo512", device[i].rcvdPktStats.upTo512) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"upTo1024", device[i].rcvdPktStats.upTo1024) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"upTo1518", device[i].rcvdPktStats.upTo1518) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"above1518", device[i].rcvdPktStats.above1518) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"shortest",
		device[i].rcvdPktStats.shortest) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"longest",
		device[i].rcvdPktStats.longest) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
		"badChecksum",
		device[i].rcvdPktStats.badChecksum) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
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

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n",
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

	if(snprintf(buf, sizeof(buf), "\t\t\t'local' => '%lu',\n",
		    device[i].ipProtoStats[j].local) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	else
	  sendString(buf);

	if(snprintf(buf, sizeof(buf), "\t\t\t'local2remote' => '%lu',\n",
		    device[i].ipProtoStats[j].local2remote) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	else
	  sendString(buf);

	if(snprintf(buf, sizeof(buf), "\t\t\t'remote2local' => '%lu',\n",
		    device[i].ipProtoStats[j].remote2local) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	else
	  sendString(buf);

	if(snprintf(buf, sizeof(buf), "\t\t\t'remote' => '%lu'\n",
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

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"synPkts", device[i].securityPkts.synPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
    
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"rstPkts", device[i].securityPkts.rstPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
    
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"rstAckPkts", device[i].securityPkts.rstAckPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
    
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"synFinPkts", device[i].securityPkts.synFinPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"finPushUrgPkts", device[i].securityPkts.finPushUrgPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
    
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"nullPkts", device[i].securityPkts.nullPkts) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);
   
    if(snprintf(buf, sizeof(buf), "\t\t'%s' => '%lu',\n",
		"numEstablishedTCPConnections", 
		device[i].numEstablishedTCPConnections) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(languageType == PERL_LANGUAGE)
      sendString("\t},\n\n");
    else
      sendString("\t),\n\n");

    /* ********************************* */

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n", "tcpLocal",
		device[i].tcpGlobalTrafficStats.local) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n", "tcpLocal2Remote",
		device[i].tcpGlobalTrafficStats.local2remote) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n", "tcpRemote",
		device[i].tcpGlobalTrafficStats.remote) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n", "tcpRemote2Local",
		device[i].tcpGlobalTrafficStats.remote2local) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    /* ********************************* */

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n", "udpLocal",
		device[i].udpGlobalTrafficStats.local) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n", "udpLocal2Remote",
		device[i].udpGlobalTrafficStats.local2remote) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n", "udpRemote",
		device[i].udpGlobalTrafficStats.remote) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n", "udpRemote2Local",
		device[i].udpGlobalTrafficStats.remote2local) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    /* ********************************* */

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n", "icmpLocal",
		device[i].icmpGlobalTrafficStats.local) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n", "icmpLocal2Remote",
		device[i].icmpGlobalTrafficStats.local2remote) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu',\n", "icmpRemote",
		device[i].icmpGlobalTrafficStats.remote) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    else
      sendString(buf);

    if(snprintf(buf, sizeof(buf), "\t'%s' => '%lu'\n", "icmpRemote2Local",
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
