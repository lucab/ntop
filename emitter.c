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
#define NO_LANGUAGE         3
#define NB_LANGUAGES        3
#define DEFAULT_LANGUAGE    NO_LANGUAGE


/*
   This file has been significantly reworked
   by Philippe Bereski <Philippe.Bereski@ms.alcatel.fr>

   Many thanks Philippe!
*/
char *languages[] = {"", "perl", "php", "no" };
char buf[256];

/* *************************** */

void initWriteArray( int lang ) {
  switch(lang) {
  case PERL_LANGUAGE :
    sendString("%ntopHash =(\n");
    break ;
  case PHP_LANGUAGE :
    sendString("$ntopHash = array(\n");
    break ;
  case NO_LANGUAGE :
    break ;
  }
}

/* *************************** */

void endWriteArray(int lang) {
  switch(lang) {
  case PERL_LANGUAGE :
  case PHP_LANGUAGE :
    sendString(");\n");
    break ;
  case NO_LANGUAGE :
    sendString("\n");
    break ;
  }
}

/* *************************** */

void initWriteKey(int lang, char *indent, char *keyName) {
  switch(lang) {
  case PERL_LANGUAGE :
    if(snprintf(buf, sizeof(buf), "%s'%s' => {\n",indent, keyName) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
    break ;
  case PHP_LANGUAGE :
    if(snprintf(buf, sizeof(buf), "%s'%s' => array(\n",indent, keyName) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
    break ;
  case NO_LANGUAGE :

    break ;
  }
}

/* *************************** */

void endWriteKey(int lang, char *indent, char last) {
  /* If there is no indentation, this was the first level of key,
     hence the end of the list. Don't add a ',' at end.
  */
  switch(lang) {
  case PERL_LANGUAGE :
    if(snprintf(buf, sizeof(buf),"%s}%c\n",indent,last) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
    break ;
  case PHP_LANGUAGE :
    if(snprintf(buf, sizeof(buf),"%s)%c\n",indent,last) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
    break ;
  case NO_LANGUAGE :
    if( indent == "") sendString("\n");
    break ;
  }
}

/* *************************** */

void wrtStrItm(int lang, char *indent, char *name, char *value, char last) {
  switch(lang) {
  case PERL_LANGUAGE :
  case PHP_LANGUAGE :
    /* In the case of hostNumIpAddress and hostSymIpAddress,
       the pointer is not null, but the string is empty.
       In that case, don't create the key in the array.
    */
    if(( value != NULL ) &&( value[0] != '\0'))  {
      if(snprintf(buf, sizeof(buf), "%s'%s' => '%s'%c\n", indent,name,value,last) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
    }
    break ;
  case NO_LANGUAGE :
    if( value != NULL ) {
      if(snprintf(buf, sizeof(buf), "%s|",value) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
    } else {
      if(snprintf(buf, sizeof(buf), "%s|","") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
    }
    break ;
  }
}

/* *************************** */

void wrtIntItm(int lang, char *indent, char *name, int value, char last) {
  char buf[80];
  sprintf(buf,"%d",value);
  wrtStrItm(lang, indent, name,  buf, last);
}

/* *************************** */

void wrtIntStrItm(int lang, char *indent,int name, char *value, char useless) {
  char buf[80];
  sprintf(buf,"%d",name);
  wrtStrItm(lang, indent, buf,  value, ',');
}

/* *************************** */

void wrtUintItm(int lang, char *indent, char *name, unsigned int value, char useless) {
  char buf[80];
  sprintf(buf,"%d",value);
  wrtStrItm(lang, indent, name,  buf, ',');
}

/* *************************** */

void wrtUcharItm(int lang, char *indent, char *name, u_char value, char useless) {
  char buf[80];
  sprintf(buf,"%d",value);
  wrtStrItm(lang, indent, name,  buf, ',');
}

/* *************************** */

void wrtFloatItm(int lang, char *indent, char *name, float value, char last) {
  char buf[80];
  sprintf(buf,"%0.2f",value);
  wrtStrItm(lang, indent, name, buf, last);
}

/* *************************** */

void wrtIntFloatItm(int lang, char *indent, int name, float value, char last) {
  char buf[80];
  sprintf(buf,"%d",name);
  wrtFloatItm(lang, indent, buf, value, last);
}

/* *************************** */

void wrtUlongItm(int lang, char *indent, char *name, unsigned long value, char useless) {
  char buf[80];
  sprintf(buf,"%lu",value);
  wrtStrItm(lang, indent, name,  buf, ',');
}

/* *************************** */

void wrtLlongItm(int lang, char* indent, char* name, TrafficCounter value, char last) {
  char buf[80];
  sprintf(buf,"%llu",value);
  wrtStrItm(lang, indent, name, buf, last);
}

/* *************************** */

void wrtTime_tItm(int lang, char *indent, char *name, time_t value, char useless) {
  char buf[80];
  sprintf(buf,"%ld",value);
  wrtStrItm(lang, indent, name, buf, ',');
}

/* *************************** */

void wrtUshortItm(int lang, char *indent, char *name, u_short value, char useless) {
  char buf[80];
  sprintf(buf,"%d",value);
  wrtStrItm(lang, indent, name,  buf, ',');
}

/* ********************************** */

static int checkFilter(char* theFilter,
		       struct re_pattern_buffer *filterPattern,
		       char* strToMatch) {
  if((theFilter == NULL) || (theFilter[0] == '\0'))
    return(1);
  else if(strToMatch == NULL)
    return(0);
  else {
    int length = strlen(strToMatch);

    if(re_search(filterPattern, strToMatch, length, 0, length, 0) < 0)
      return(0); /* No Match */
    else
      return(1);
  }
}

/* ********************************** */

void dumpNtopHashes(char* options) {
  char key[64], filter[128];
  unsigned int idx, numEntries=0, lang=DEFAULT_LANGUAGE, j;
  HostTraffic *el;
  struct re_pattern_buffer filterPattern;

  memset(key, 0, sizeof(key));
  memset(filter, 0, sizeof(filter));

  if(options != NULL) {
    /* language now defined into "languages[]" */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0; int j;

      while((tmpStr[i] != '\0') &&(tmpStr[i] != '='))
	i++;

      /* If argument contains "language=something", then
	 look in the table "languages" of known language for
	 the choosen language.
      */

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcasecmp(tmpStr, "language") == 0) {
	  lang=DEFAULT_LANGUAGE;
	  for(j=1;j <= NB_LANGUAGES;j++) {
	    if(strcasecmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	} else if(strcmp(tmpStr, "key") == 0) {
	  strncpy(key, &tmpStr[i+1], sizeof(key));
	} else if(strcmp(tmpStr, "filter") == 0) {
	  strncpy(filter, &tmpStr[i+1], sizeof(filter));
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }

  if(filter[0] != '\0') {
    const char *re_err;

    memset(&filterPattern, 0, sizeof(struct re_pattern_buffer));

    re_err = (const char *)re_compile_pattern(filter, strlen(filter), &filterPattern);
    if(re_err) {
      /* Invalid pattern */
      filter[0] = '\0';
    } else {
      filterPattern.fastmap =(char*)malloc(256);

      if(re_compile_fastmap(&filterPattern)) {
	/* Invalid pattern */
	free(filterPattern.fastmap);
	filter[0] = '\0';
      }
    }
  }

  initWriteArray(lang);

  for(idx=0; idx<device[actualDeviceId].actualHashSize; idx++) {
    if((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL) {
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

      if(numEntries > 0) { endWriteKey(lang,"",','); }

      initWriteKey(lang, "", hostKey);

      /* ************************ */

      if(checkFilter(filter, &filterPattern, "index")) wrtUintItm(lang, "\t","index", idx,' ');

      if(checkFilter(filter, &filterPattern, "hostNumIpAddress")) wrtStrItm(lang, "\t", "hostNumIpAddress", el->hostNumIpAddress,',');
      if(checkFilter(filter, &filterPattern, "hostSymIpAddress")) wrtStrItm(lang, "\t", "hostSymIpAddress", el->hostSymIpAddress,',');

      if(checkFilter(filter, &filterPattern, "firstSeen")) wrtTime_tItm(lang, "\t", "firstSeen",   el->firstSeen,' ');
      if(checkFilter(filter, &filterPattern, "lastSeen")) wrtTime_tItm(lang, "\t", "lastSeen",    el->lastSeen,' ');
      if(checkFilter(filter, &filterPattern, "minTTL")) wrtUshortItm(lang, "\t", "minTTL",       el->minTTL,' ');
      if(checkFilter(filter, &filterPattern, "maxTTL")) wrtUshortItm(lang, "\t", "maxTTL",       el->maxTTL,' ');
      if(checkFilter(filter, &filterPattern, "nbHostName")) wrtStrItm(lang, "\t", "nbHostName",     el->nbHostName,',');
      if(checkFilter(filter, &filterPattern, "nbDomainName")) wrtStrItm(lang, "\t", "nbDomainName",   el->nbDomainName,',');
      if(checkFilter(filter, &filterPattern, "nbDescr")) wrtStrItm(lang, "\t", "nbDescr",        el->nbDescr,',');
      if(checkFilter(filter, &filterPattern, "nodeType")) wrtUcharItm (lang, "\t", "nodeType",    el->nbNodeType,' ');
      if(checkFilter(filter, &filterPattern, "atNodeName")) wrtStrItm(lang, "\t", "atNodeName",     el->atNodeName,',');
      if(checkFilter(filter, &filterPattern, "atNetwork")) wrtUshortItm(lang, "\t", "atNetwork",    el->atNetwork,' ');
      if(checkFilter(filter, &filterPattern, "atNode")) wrtUcharItm (lang, "\t", "atNode",      el->atNode,' ');
      if(checkFilter(filter, &filterPattern, "ipxHostName")) wrtStrItm(lang, "\t", "ipxHostName",    el->ipxHostName,',');
      if(checkFilter(filter, &filterPattern, "pktSent")) wrtLlongItm(lang, "\t", "pktSent",     el->pktSent,',');
      if(checkFilter(filter, &filterPattern, "pktReceived")) wrtLlongItm(lang, "\t", "pktReceived", el->pktReceived,',');
      if(checkFilter(filter, &filterPattern, "pktDuplicatedAckSent")) wrtLlongItm(lang, "\t", "pktDuplicatedAckSent",el->pktDuplicatedAckSent,',');
      if(checkFilter(filter, &filterPattern, "pktDuplicatedAckRcvd")) wrtLlongItm(lang, "\t", "pktDuplicatedAckRcvd",el->pktDuplicatedAckRcvd,',');
      if(checkFilter(filter, &filterPattern, "pktBroadcastSent")) wrtLlongItm(lang, "\t", "pktBroadcastSent",    el->pktBroadcastSent,',');
      if(checkFilter(filter, &filterPattern, "bytesMulticastSent")) wrtLlongItm(lang, "\t", "bytesMulticastSent",  el->bytesMulticastSent,',');
      if(checkFilter(filter, &filterPattern, "pktMulticastSent")) wrtLlongItm(lang, "\t", "pktMulticastSent",    el->pktMulticastSent,',');
      if(checkFilter(filter, &filterPattern, "bytesMulticastSent")) wrtLlongItm(lang, "\t", "bytesMulticastSent",  el->bytesMulticastSent,',');
      if(checkFilter(filter, &filterPattern, "pktMulticastRcvd")) wrtLlongItm(lang, "\t", "pktMulticastRcvd",    el->pktMulticastRcvd,',');
      if(checkFilter(filter, &filterPattern, "bytesSent")) wrtLlongItm(lang, "\t", "bytesSent",           el->bytesSent,',');
      if(checkFilter(filter, &filterPattern, "bytesSentLocally")) wrtLlongItm(lang, "\t", "bytesSentLocally",    el->bytesSentLocally,',');
      if(checkFilter(filter, &filterPattern, "bytesSentRemotely")) wrtLlongItm(lang, "\t", "bytesSentRemotely",   el->bytesSentRemotely,',');
      if(checkFilter(filter, &filterPattern, "bytesReceived")) wrtLlongItm(lang, "\t", "bytesReceived",       el->bytesReceived,',');
      if(checkFilter(filter, &filterPattern, "bytesReceivedLocally")) wrtLlongItm(lang, "\t", "bytesReceivedLocally", el->bytesReceivedLocally,',');
      if(checkFilter(filter, &filterPattern, "bytesReceivedFromRemote")) wrtLlongItm(lang, "\t", "bytesReceivedFromRemote",
							       el->bytesReceivedFromRemote,',');
      if(checkFilter(filter, &filterPattern, "actualRcvdThpt")) wrtFloatItm(lang, "\t", "actualRcvdThpt",    el->actualRcvdThpt,',');
      if(checkFilter(filter, &filterPattern, "lastHourRcvdThpt")) wrtFloatItm(lang, "\t", "lastHourRcvdThpt",  el->lastHourRcvdThpt,',');
      if(checkFilter(filter, &filterPattern, "averageRcvdThpt")) wrtFloatItm(lang, "\t", "averageRcvdThpt",   el->averageRcvdThpt,',');
      if(checkFilter(filter, &filterPattern, "peakRcvdThpt")) wrtFloatItm(lang, "\t", "peakRcvdThpt",      el->peakRcvdThpt,',');
      if(checkFilter(filter, &filterPattern, "actualSentThpt")) wrtFloatItm(lang, "\t", "actualSentThpt",    el->actualSentThpt,',');
      if(checkFilter(filter, &filterPattern, "lastHourSentThpt")) wrtFloatItm(lang, "\t", "lastHourSentThpt",  el->lastHourSentThpt,',');
      if(checkFilter(filter, &filterPattern, "averageSentThpt")) wrtFloatItm(lang, "\t", "averageSentThpt",   el->averageSentThpt,',');
      if(checkFilter(filter, &filterPattern, "peakSentThpt")) wrtFloatItm(lang, "\t", "peakSentThpt",      el->peakSentThpt,',');
      if(checkFilter(filter, &filterPattern, "actualRcvdPktThpt")) wrtFloatItm(lang, "\t", "actualRcvdPktThpt", el->actualRcvdPktThpt,',');
      if(checkFilter(filter, &filterPattern, "averageRcvdPktThpt")) wrtFloatItm(lang, "\t", "averageRcvdPktThpt",el->averageRcvdPktThpt,',');
      if(checkFilter(filter, &filterPattern, "peakRcvdPktThpt")) wrtFloatItm(lang, "\t", "peakRcvdPktThpt",   el->peakRcvdPktThpt,',');
      if(checkFilter(filter, &filterPattern, "actualSentPktThpt")) wrtFloatItm(lang, "\t", "actualSentPktThpt", el->actualSentPktThpt,',');
      if(checkFilter(filter, &filterPattern, "averageSentPktThpt")) wrtFloatItm(lang, "\t", "averageSentPktThpt",el->tcpSentLocally,',');
      if(checkFilter(filter, &filterPattern, "tcpSentRemotely")) wrtLlongItm(lang, "\t", "tcpSentRemotely",   el->tcpSentRemotely,',');
      if(checkFilter(filter, &filterPattern, "udpSentLocally")) wrtLlongItm(lang, "\t", "udpSentLocally",    el->udpSentLocally,',');
      if(checkFilter(filter, &filterPattern, "udpSentRemotely")) wrtLlongItm(lang, "\t", "udpSentRemotely",   el->udpSentRemotely,',');
      if(checkFilter(filter, &filterPattern, "icmpSent")) wrtLlongItm(lang, "\t", "icmpSent",          el->icmpSent,',');
      if(checkFilter(filter, &filterPattern, "ospfSent")) wrtLlongItm(lang, "\t", "ospfSent",          el->ospfSent,',');
      if(checkFilter(filter, &filterPattern, "igmpSent")) wrtLlongItm(lang, "\t", "igmpSent",          el->igmpSent,',');
      if(checkFilter(filter, &filterPattern, "tcpReceivedLocally")) wrtLlongItm(lang, "\t", "tcpReceivedLocally",el->tcpReceivedLocally,',');
      if(checkFilter(filter, &filterPattern, "tcpReceivedFromRemote")) wrtLlongItm(lang, "\t", "tcpReceivedFromRemote",el->tcpReceivedFromRemote,',');
      if(checkFilter(filter, &filterPattern, "udpReceivedLocally")) wrtLlongItm(lang, "\t", "udpReceivedLocally",el->udpReceivedLocally,',');
      if(checkFilter(filter, &filterPattern, "udpReceivedFromRemote")) wrtLlongItm(lang, "\t", "udpReceivedFromRemote",el->udpReceivedFromRemote,',');
      if(checkFilter(filter, &filterPattern, "icmpReceived")) wrtLlongItm(lang, "\t", "icmpReceived",      el->icmpReceived,',');
      if(checkFilter(filter, &filterPattern, "ospfReceived")) wrtLlongItm(lang, "\t", "ospfReceived",      el->ospfReceived,',');
      if(checkFilter(filter, &filterPattern, "igmpReceived")) wrtLlongItm(lang, "\t", "igmpReceived",      el->igmpReceived,',');

      /* ***************************** */

      if(checkFilter(filter, &filterPattern, "stpSent")) wrtLlongItm(lang, "\t", "stpSent",          el->stpSent,',');
      if(checkFilter(filter, &filterPattern, "stpReceived")) wrtLlongItm(lang, "\t", "stpReceived",      el->stpReceived,',');
      if(checkFilter(filter, &filterPattern, "ipxSent")) wrtLlongItm(lang, "\t", "ipxSent",          el->ipxSent,',');
      if(checkFilter(filter, &filterPattern, "ipxReceived")) wrtLlongItm(lang, "\t", "ipxReceived",      el->ipxReceived,',');
      if(checkFilter(filter, &filterPattern, "osiSent")) wrtLlongItm(lang, "\t", "osiSent",          el->osiSent,',');
      if(checkFilter(filter, &filterPattern, "osiReceived")) wrtLlongItm(lang, "\t", "osiReceived",      el->osiReceived,',');
      if(checkFilter(filter, &filterPattern, "dlcSent")) wrtLlongItm(lang, "\t", "dlcSent",          el->dlcSent,',');
      if(checkFilter(filter, &filterPattern, "dlcReceived")) wrtLlongItm(lang, "\t", "dlcReceived",      el->dlcReceived,',');
      if(checkFilter(filter, &filterPattern, "arp_rarpSent")) wrtLlongItm(lang, "\t", "arp_rarpSent",     el->arp_rarpSent,',');
      if(checkFilter(filter, &filterPattern, "arp_rarpReceived")) wrtLlongItm(lang, "\t", "arp_rarpReceived", el->arp_rarpReceived,',');
      if(checkFilter(filter, &filterPattern, "arpReqPktsSent")) wrtLlongItm(lang, "\t", "arpReqPktsSent",   el->arpReqPktsSent,',');
      if(checkFilter(filter, &filterPattern, "arpReplyPktsSent")) wrtLlongItm(lang, "\t", "arpReplyPktsSent", el->arpReplyPktsSent,',');
      if(checkFilter(filter, &filterPattern, "arpReplyPktsRcvd")) wrtLlongItm(lang, "\t", "arpReplyPktsRcvd", el->arpReplyPktsRcvd,',');
      if(checkFilter(filter, &filterPattern, "decnetSent")) wrtLlongItm(lang, "\t", "decnetSent",       el->decnetSent,',');
      if(checkFilter(filter, &filterPattern, "decnetReceived")) wrtLlongItm(lang, "\t", "decnetReceived",   el->decnetReceived,',');
      if(checkFilter(filter, &filterPattern, "appletalkSent")) wrtLlongItm(lang, "\t", "appletalkSent",    el->appletalkSent,',');
      if(checkFilter(filter, &filterPattern, "appletalkReceived")) wrtLlongItm(lang, "\t", "appletalkReceived",el->appletalkReceived,',');
      if(checkFilter(filter, &filterPattern, "netbiosSent")) wrtLlongItm(lang, "\t", "netbiosSent",      el->netbiosSent,',');
      if(checkFilter(filter, &filterPattern, "netbiosReceived")) wrtLlongItm(lang, "\t", "netbiosReceived",  el->netbiosReceived,',');
      if(checkFilter(filter, &filterPattern, "qnxSent")) wrtLlongItm(lang, "\t", "qnxSent",          el->qnxSent,',');
      if(checkFilter(filter, &filterPattern, "qnxReceived")) wrtLlongItm(lang, "\t", "qnxReceived",      el->qnxReceived,',');
      if(checkFilter(filter, &filterPattern, "otherSent")) wrtLlongItm(lang, "\t", "otherSent",        el->otherSent,',');
      if(checkFilter(filter, &filterPattern, "otherReceived")) wrtLlongItm(lang, "\t", "otherReceived",    el->otherReceived,',');

      /* ********************************* */

      if(el->routedTraffic && checkFilter(filter, &filterPattern, "RoutingCounter")) {
	initWriteKey(lang, "\t", "RoutingCounter");
	wrtLlongItm(lang,"\t\t", "routedPkts", el->routedTraffic->routedPkts,',');
	wrtLlongItm(lang,"\t\t", "routedBytes", el->routedTraffic->routedBytes,',');
	endWriteKey(lang,"\t",',');
      }

      if(el->protoIPTrafficInfos && checkFilter(filter, &filterPattern, "IP")) {
	initWriteKey(lang, "\t", "IP");

	for(j=0; j<numIpProtosToMonitor; j++) {

	  if(j > 0) { endWriteKey(lang,"\t\t",','); }

	  initWriteKey(lang, "\t\t", protoIPTrafficInfos[j]);
	  wrtLlongItm(lang,"\t\t\t","sentLocally",
		      el->protoIPTrafficInfos[j].sentLocally,',');
	  wrtLlongItm(lang,"\t\t\t","sentRemotely",
		      el->protoIPTrafficInfos[j].sentRemotely,',');
	  wrtLlongItm(lang,"\t\t\t","receivedLocally",
		      el->protoIPTrafficInfos[j].receivedLocally,',');
	  wrtLlongItm(lang,"\t\t\t","receivedFromRemote",
		      el->protoIPTrafficInfos[j].receivedFromRemote,' ');
	}
	endWriteKey(lang,"\t\t",',');
	endWriteKey(lang,"\t",',');
      }

      /* ***************************************** */

      if(el->icmpInfo && checkFilter(filter, &filterPattern, "ICMP")) {
	initWriteKey(lang, "\t", "ICMP");
	wrtUlongItm(lang,"\t\t","SENT_ECHO",
		    el->icmpInfo->icmpMsgSent[ICMP_ECHO],' ');
	wrtUlongItm(lang,"\t\t","SENT_ECHOREPLY",
		    el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY],' ');
	wrtUlongItm(lang,"\t\t","SENT_UNREACH",
		    el->icmpInfo->icmpMsgSent[ICMP_UNREACH],' ');
	wrtUlongItm(lang,"\t\t","SENT_ROUTERADVERT",
		    el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT],' ');
	wrtUlongItm(lang,"\t\t","SENT_TMXCEED",
		    el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED],' ');
	wrtUlongItm(lang,"\t\t","SENT_PARAMPROB",
		    el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB],' ');
	wrtUlongItm(lang,"\t\t","SENT_MASKREPLY",
		    el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY],' ');
	wrtUlongItm(lang,"\t\t","SENT_MASKREQ",
		    el->icmpInfo->icmpMsgSent[ICMP_MASKREQ],' ');
	wrtUlongItm(lang,"\t\t","SENT_INFO_REQUEST",
		    el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST],' ');
	wrtUlongItm(lang,"\t\t","SENT_INFO_REPLY",
		    el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY],' ');
	wrtUlongItm(lang,"\t\t","SENT_TIMESTAMP",
		    el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP],' ');
	wrtUlongItm(lang,"\t\t","SENT_TIMESTAMPREPLY",
		    el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY],' ');
	wrtUlongItm(lang,"\t\t","SENT_SOURCE_QUENCH",
		    el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH],' ');

	/* *********************************************** */

	wrtUlongItm(lang,"\t\t","RCVD_ECHO",
		    el->icmpInfo->icmpMsgRcvd[ICMP_ECHO],' ');
	wrtUlongItm(lang,"\t\t","RCVD_ECHOREPLY",
		    el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY],' ');
	wrtUlongItm(lang,"\t\t","RCVD_UNREACH",
		    el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH],' ');
	wrtUlongItm(lang,"\t\t","RCVD_ROUTERADVERT",
		    el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT],' ');
	wrtUlongItm(lang,"\t\t","RCVD_TMXCEED",
		    el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED],' ');
	wrtUlongItm(lang,"\t\t","RCVD_PARAMPROB",
		    el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB],' ');
	wrtUlongItm(lang,"\t\t","RCVD_MASKREPLY",
		    el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY],' ');
	wrtUlongItm(lang,"\t\t","RCVD_MASKREQ",
		    el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ],' ');
	wrtUlongItm(lang,"\t\t","RCVD_INFO_REQUEST",
		    el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST],' ');
	wrtUlongItm(lang,"\t\t","RCVD_INFO_REPLY",
		    el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY],' ');
	wrtUlongItm(lang,"\t\t","RCVD_TIMESTAMP",
		    el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP],' ');
	wrtUlongItm(lang,"\t\t","RCVD_TIMESTAMPREPLY",
		    el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY],' ');
	wrtUlongItm(lang,"\t\t","RCVD_SOURCE_QUENCH",
		    el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH],' ');

	endWriteKey(lang,"\t",',');
      }

      /* ********************************* */

      if(el->securityHostPkts && checkFilter(filter, &filterPattern, "securityPkts")) {
	initWriteKey(lang, "\t", "securityPkts");

	wrtLlongItm(lang,"\t\t","synPktsSent",
		    el->securityHostPkts->synPktsSent.value,',');
	wrtLlongItm(lang,"\t\t","synPktsRcvd",
		    el->securityHostPkts->synPktsRcvd.value,',');

	wrtLlongItm(lang,"\t\t","rstPktsSent",
		    el->securityHostPkts->rstPktsSent.value,',');
	wrtLlongItm(lang,"\t\t","rstPktsRcvd",
		    el->securityHostPkts->rstPktsRcvd.value,',');

	wrtLlongItm(lang,"\t\t","rstAckPktsSent",
		    el->securityHostPkts->rstAckPktsSent.value,',');
	wrtLlongItm(lang,"\t\t","rstAckPktsRcvd",
		    el->securityHostPkts->rstAckPktsRcvd.value,',');

	wrtLlongItm(lang,"\t\t","synFinPktsSent",
		    el->securityHostPkts->synFinPktsSent.value,',');
	wrtLlongItm(lang,"\t\t","synFinPktsRcvd",
		    el->securityHostPkts->synFinPktsRcvd.value,',');

	wrtLlongItm(lang,"\t\t","finPushUrgPktsSent",
		    el->securityHostPkts->finPushUrgPktsSent.value,',');
	wrtLlongItm(lang,"\t\t","finPushUrgPktsRcvd",
		    el->securityHostPkts->finPushUrgPktsRcvd.value,',');

	wrtLlongItm(lang,"\t\t","nullPktsSent",
		    el->securityHostPkts->nullPktsSent.value,',');
	wrtLlongItm(lang,"\t\t","nullPktsRcvd",
		    el->securityHostPkts->nullPktsRcvd.value,',');

	wrtLlongItm(lang,"\t\t","ackScanSent",
		    el->securityHostPkts->ackScanSent.value,',');
	wrtLlongItm(lang,"\t\t","ackScanRcvd",
		    el->securityHostPkts->ackScanRcvd.value,',');

	wrtLlongItm(lang,"\t\t","xmasScanSent",
		    el->securityHostPkts->xmasScanSent.value,',');
	wrtLlongItm(lang,"\t\t","xmasScanRcvd",
		    el->securityHostPkts->xmasScanRcvd.value,',');

	wrtLlongItm(lang,"\t\t","finScanSent",
		    el->securityHostPkts->finScanSent.value,',');
	wrtLlongItm(lang,"\t\t","finScanRcvd",
		    el->securityHostPkts->finScanRcvd.value,',');

	wrtLlongItm(lang,"\t\t","nullScanSent",
		    el->securityHostPkts->nullScanSent.value,',');
	wrtLlongItm(lang,"\t\t","nullScanRcvd",
		    el->securityHostPkts->nullScanRcvd.value,',');

	wrtLlongItm(lang,"\t\t","rejectedTCPConnSent",
		    el->securityHostPkts->rejectedTCPConnSent.value,',');
	wrtLlongItm(lang,"\t\t","rejectedTCPConnRcvd",
		    el->securityHostPkts->rejectedTCPConnRcvd.value,',');

	wrtLlongItm(lang,"\t\t","establishedTCPConnSent",
		    el->securityHostPkts->establishedTCPConnSent.value,',');
	wrtLlongItm(lang,"\t\t","establishedTCPConnRcvd",
		    el->securityHostPkts->establishedTCPConnRcvd.value,',');

	wrtLlongItm(lang,"\t\t","udpToClosedPortSent",
		    el->securityHostPkts->udpToClosedPortSent.value,',');
	wrtLlongItm(lang,"\t\t","udpToClosedPortRcvd",
		    el->securityHostPkts->udpToClosedPortRcvd.value,',');

	wrtLlongItm(lang,"\t\t","udpToDiagnosticPortSent",
		    el->securityHostPkts->udpToDiagnosticPortSent.value,',');
	wrtLlongItm(lang,"\t\t","udpToDiagnosticPortRcvd",
		    el->securityHostPkts->udpToDiagnosticPortRcvd.value,',');

	wrtLlongItm(lang,"\t\t","tcpToDiagnosticPortSent",
		    el->securityHostPkts->tcpToDiagnosticPortSent.value,',');
	wrtLlongItm(lang,"\t\t","tcpToDiagnosticPortRcvd",
		    el->securityHostPkts->tcpToDiagnosticPortRcvd.value,',');

	wrtLlongItm(lang,"\t\t","tinyFragmentSent",
		    el->securityHostPkts->tinyFragmentSent.value,',');
	wrtLlongItm(lang,"\t\t","tinyFragmentRcvd",
		    el->securityHostPkts->tinyFragmentRcvd.value,',');

	wrtLlongItm(lang,"\t\t","icmpFragmentSent",
		    el->securityHostPkts->icmpFragmentSent.value,',');
	wrtLlongItm(lang,"\t\t","icmpFragmentRcvd",
		    el->securityHostPkts->icmpFragmentRcvd.value,',');

	wrtLlongItm(lang,"\t\t","overlappingFragmentSent",
		    el->securityHostPkts->overlappingFragmentSent.value,',');
	wrtLlongItm(lang,"\t\t","overlappingFragmentRcvd",
		    el->securityHostPkts->overlappingFragmentRcvd.value,',');

	wrtLlongItm(lang,"\t\t","closedEmptyTCPConnSent",
		    el->securityHostPkts->closedEmptyTCPConnSent.value,',');
	wrtLlongItm(lang,"\t\t","closedEmptyTCPConnRcvd",
		    el->securityHostPkts->closedEmptyTCPConnRcvd.value,',');

	wrtLlongItm(lang,"\t\t","icmpPortUnreachSent",
		    el->securityHostPkts->icmpPortUnreachSent.value,',');
	wrtLlongItm(lang,"\t\t","icmpPortUnreachRcvd",
		    el->securityHostPkts->icmpPortUnreachRcvd.value,',');

	wrtLlongItm(lang,"\t\t","icmpHostNetUnreachSent",
		    el->securityHostPkts->icmpHostNetUnreachSent.value,',');
	wrtLlongItm(lang,"\t\t","icmpHostNetUnreachRcvd",
		    el->securityHostPkts->icmpHostNetUnreachRcvd.value,',');

	wrtLlongItm(lang,"\t\t","icmpProtocolUnreachSent",
		    el->securityHostPkts->icmpProtocolUnreachSent.value,',');
	wrtLlongItm(lang,"\t\t","icmpProtocolUnreachRcvd",
		    el->securityHostPkts->icmpProtocolUnreachRcvd.value,',');

	wrtLlongItm(lang,"\t\t","icmpAdminProhibitedSent",
		    el->securityHostPkts->icmpAdminProhibitedSent.value,',');
	wrtLlongItm(lang,"\t\t","icmpAdminProhibitedRcvd",
		    el->securityHostPkts->icmpAdminProhibitedRcvd.value,',');

	wrtLlongItm(lang,"\t\t","malformedPktsSent",
		    el->securityHostPkts->malformedPktsSent.value,',');
	wrtLlongItm(lang,"\t\t","malformedPktsRcvd",
		    el->securityHostPkts->malformedPktsRcvd.value,',');

	endWriteKey(lang,"\t",',');
      }

      /* ***************************** */

      if(checkFilter(filter, &filterPattern, "ethAddressString")) wrtStrItm(lang, "\t", "ethAddressString",el->ethAddressString,' ');

      numEntries++;
    }
  }

  endWriteKey(lang,"",' ');
  endWriteArray(lang);

  if(filterPattern.fastmap)
    free(filterPattern.fastmap);
}

/* ********************************** */

void dumpNtopHashIndexes(char* options) {
  unsigned int idx, numEntries=0, lang=DEFAULT_LANGUAGE;
  HostTraffic *el;

  if(options != NULL) {
    /* language=[perl|php] */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0; int j;

      while((tmpStr[i] != '\0') &&(tmpStr[i] != '='))
	i++;

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcmp(tmpStr, "language") == 0) {

	  lang=DEFAULT_LANGUAGE;
	  for(j=1;j <= NB_LANGUAGES;j++) {
	    if(strcmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }
  initWriteArray(lang);

  for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++) {
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       &&(broadcastHost(el) == 0)) {
      char *hostKey;

      if(el->hostNumIpAddress[0] != '\0')
	hostKey = el->hostNumIpAddress;
      else
	hostKey = el->ethAddressString;

      wrtIntStrItm( lang, "", idx, hostKey,'\n');

      numEntries++;
    }
  }

  endWriteArray(lang);
}

/* ********************************** */

void dumpNtopTrafficInfo(char* options) {
  char intoabuf[32], key[16], localbuf[32], filter[128];
  int lang=DEFAULT_LANGUAGE, i;
  struct re_pattern_buffer filterPattern;

  memset(key, 0, sizeof(key));

  if(options != NULL) {
    /* language=[perl|php] */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0; int j;

      while((tmpStr[i] != '\0') &&(tmpStr[i] != '='))
	i++;

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcmp(tmpStr, "language") == 0) {
	  lang=DEFAULT_LANGUAGE;
	  for(j=1;j <= NB_LANGUAGES;j++) {
	    if(strcmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	} else if(strcmp(tmpStr, "key") == 0) {
	  strncpy(key, &tmpStr[i+1], sizeof(key));
	} else if(strcmp(tmpStr, "filter") == 0) {
	  strncpy(filter, &tmpStr[i+1], sizeof(filter));
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }

  if(filter[0] != '\0') {
    const char *re_err;

    memset(&filterPattern, 0, sizeof(struct re_pattern_buffer));

    re_err = (const char *)re_compile_pattern(filter, strlen(filter), &filterPattern);
    if(re_err) {
      /* Invalid pattern */
      filter[0] = '\0';
    } else {
      filterPattern.fastmap =(char*)malloc(256);

      if(re_compile_fastmap(&filterPattern)) {
	/* Invalid pattern */
	free(filterPattern.fastmap);
	filter[0] = '\0';
      }
    }
  }

  initWriteArray(lang);

  for(i=0; i<numDevices; i++) {
    int j;

    if(device[i].virtualDevice) continue;


    if( i > 0) { endWriteKey(lang,"",','); }

    if((key[0] != '\0') &&(strcmp(key, device[i].name) != 0))
      continue;

    initWriteKey(lang, "", device[i].name);

    if(checkFilter(filter, &filterPattern, "ipdot")) wrtStrItm(lang, "\t", "ipdot", device[i].ipdot,',');
    if(checkFilter(filter, &filterPattern, "fqdn")) wrtStrItm(lang, "\t", "fqdn", device[i].fqdn,',');

    snprintf(localbuf, sizeof(localbuf), "%s",
	     _intoa(device[i].network, intoabuf, sizeof(intoabuf)));
    if(checkFilter(filter, &filterPattern, "network")) wrtStrItm(lang, "\t", "network",  localbuf,',');
    snprintf(localbuf, sizeof(localbuf), "%s",
	     _intoa(device[i].netmask, intoabuf, sizeof(intoabuf)));
    if(checkFilter(filter, &filterPattern, "netmask")) wrtStrItm(lang, "\t", "netmask", localbuf,',');
    snprintf(localbuf, sizeof(localbuf), "%s",
	     _intoa(device[i].ifAddr, intoabuf, sizeof(intoabuf)));
    if(checkFilter(filter, &filterPattern, "ifAddr")) wrtStrItm(lang, "\t", "ifAddr",  localbuf,',');

    if(checkFilter(filter, &filterPattern, "started")) wrtTime_tItm(lang, "\t", "started",  device[i].started,' ');
    if(checkFilter(filter, &filterPattern, "firstpkt")) wrtTime_tItm(lang, "\t", "firstpkt", device[i].firstpkt,' ');
    if(checkFilter(filter, &filterPattern, "lastpkt")) wrtTime_tItm(lang, "\t", "lastpkt",  device[i].lastpkt,' ');
    if(checkFilter(filter, &filterPattern, "virtualDevice")) wrtIntItm(lang, "\t", "virtualDevice",(int)device[i].virtualDevice,',');
    if(checkFilter(filter, &filterPattern, "snaplen")) wrtIntItm(lang, "\t", "snaplen",  device[i].snaplen,',');
    if(checkFilter(filter, &filterPattern, "datalink")) wrtIntItm(lang, "\t", "datalink", device[i].datalink,',');
    if(checkFilter(filter, &filterPattern, "filter")) wrtStrItm(lang, "\t", "filter",   device[i].filter ? device[i].filter : "",',');
    if(checkFilter(filter, &filterPattern, "droppedPkts")) wrtLlongItm(lang, "\t", "droppedPkts",device[i].droppedPkts,',');
    if(checkFilter(filter, &filterPattern, "ethernetPkts")) wrtLlongItm(lang, "\t", "ethernetPkts",device[i].ethernetPkts,',');
    if(checkFilter(filter, &filterPattern, "broadcastPkts")) wrtLlongItm(lang, "\t", "broadcastPkts",device[i].broadcastPkts,',');
    if(checkFilter(filter, &filterPattern, "multicastPkts")) wrtLlongItm(lang, "\t", "multicastPkts",device[i].multicastPkts,',');
    if(checkFilter(filter, &filterPattern, "ethernetBytes")) wrtLlongItm(lang, "\t", "ethernetBytes",device[i].ethernetBytes,',');
    if(checkFilter(filter, &filterPattern, "ipBytes")) wrtLlongItm(lang, "\t", "ipBytes",device[i].ipBytes,',');
    if(checkFilter(filter, &filterPattern, "tcpBytes")) wrtLlongItm(lang, "\t", "tcpBytes",device[i].tcpBytes,',');
    if(checkFilter(filter, &filterPattern, "udpBytes")) wrtLlongItm(lang, "\t", "udpBytes",device[i].udpBytes,',');
    if(checkFilter(filter, &filterPattern, "otherIpBytes")) wrtLlongItm(lang, "\t", "otherIpBytes",device[i].otherIpBytes,',');
    if(checkFilter(filter, &filterPattern, "icmpBytes")) wrtLlongItm(lang, "\t", "icmpBytes",device[i].icmpBytes,',');
    if(checkFilter(filter, &filterPattern, "dlcBytes")) wrtLlongItm(lang, "\t", "dlcBytes",device[i].dlcBytes,',');
    if(checkFilter(filter, &filterPattern, "ipxBytes")) wrtLlongItm(lang, "\t", "ipxBytes",device[i].ipxBytes,',');
    if(checkFilter(filter, &filterPattern, "stpBytes")) wrtLlongItm(lang, "\t", "stpBytes",device[i].stpBytes,',');
    if(checkFilter(filter, &filterPattern, "decnetBytes")) wrtLlongItm(lang, "\t", "decnetBytes",device[i].decnetBytes,',');
    if(checkFilter(filter, &filterPattern, "netbiosBytes")) wrtLlongItm(lang, "\t", "netbiosBytes",device[i].netbiosBytes,',');
    if(checkFilter(filter, &filterPattern, "arpRarpBytes")) wrtLlongItm(lang, "\t", "arpRarpBytes",device[i].arpRarpBytes,',');
    if(checkFilter(filter, &filterPattern, "atalkBytes")) wrtLlongItm(lang, "\t", "atalkBytes",device[i].atalkBytes,',');
    if(checkFilter(filter, &filterPattern, "ospfBytes")) wrtLlongItm(lang, "\t", "ospfBytes",device[i].ospfBytes,',');
    if(checkFilter(filter, &filterPattern, "egpBytes")) wrtLlongItm(lang, "\t", "egpBytes",device[i].egpBytes,',');
    if(checkFilter(filter, &filterPattern, "igmpBytes")) wrtLlongItm(lang, "\t", "igmpBytes",device[i].igmpBytes,',');
    if(checkFilter(filter, &filterPattern, "osiBytes")) wrtLlongItm(lang, "\t", "osiBytes",device[i].osiBytes,',');
    if(checkFilter(filter, &filterPattern, "qnxBytes")) wrtLlongItm(lang, "\t", "qnxBytes",device[i].qnxBytes,',');
    if(checkFilter(filter, &filterPattern, "otherBytes")) wrtLlongItm(lang, "\t", "otherBytes",device[i].otherBytes,',');
    if(checkFilter(filter, &filterPattern, "lastMinEthernetBytes")) wrtLlongItm(lang, "\t", "lastMinEthernetBytes",
							     device[i].lastMinEthernetBytes,',');
    if(checkFilter(filter, &filterPattern, "lastFiveMinsEthernetBytes")) wrtLlongItm(lang, "\t", "lastFiveMinsEthernetBytes",
							     device[i].lastFiveMinsEthernetBytes,',');
    if(checkFilter(filter, &filterPattern, "lastMinEthernetPkts")) wrtLlongItm(lang, "\t", "lastMinEthernetPkts",device[i].lastMinEthernetPkts,',');
    if(checkFilter(filter, &filterPattern, "lastFiveMinsEthernetPkts")) wrtLlongItm(lang, "\t", "lastFiveMinsEthernetPkts",
							     device[i].lastFiveMinsEthernetPkts,',');
    if(checkFilter(filter, &filterPattern, "upTo64")) wrtLlongItm(lang, "\t", "upTo64",device[i].rcvdPktStats.upTo64,',');
    if(checkFilter(filter, &filterPattern, "upTo128")) wrtLlongItm(lang, "\t", "upTo128",device[i].rcvdPktStats.upTo128,',');
    if(checkFilter(filter, &filterPattern, "upTo256")) wrtLlongItm(lang, "\t", "upTo256",device[i].rcvdPktStats.upTo256,',');
    if(checkFilter(filter, &filterPattern, "upTo512")) wrtLlongItm(lang, "\t", "upTo512",device[i].rcvdPktStats.upTo512,',');
    if(checkFilter(filter, &filterPattern, "upTo1024")) wrtLlongItm(lang, "\t", "upTo1024",device[i].rcvdPktStats.upTo1024,',');
    if(checkFilter(filter, &filterPattern, "upTo1518")) wrtLlongItm(lang, "\t", "upTo1518",device[i].rcvdPktStats.upTo1518,',');
    if(checkFilter(filter, &filterPattern, "above1518")) wrtLlongItm(lang, "\t", "above1518",device[i].rcvdPktStats.above1518,',');
    if(checkFilter(filter, &filterPattern, "shortest")) wrtLlongItm(lang, "\t", "shortest",device[i].rcvdPktStats.shortest,',');
    if(checkFilter(filter, &filterPattern, "longest")) wrtLlongItm(lang, "\t", "longest",device[i].rcvdPktStats.longest,',');
    if(checkFilter(filter, &filterPattern, "badChecksum")) wrtLlongItm(lang, "\t", "badChecksum",device[i].rcvdPktStats.badChecksum,',');
    if(checkFilter(filter, &filterPattern, "tooLong")) wrtLlongItm(lang, "\t", "tooLong",device[i].rcvdPktStats.tooLong,',');
    if(checkFilter(filter, &filterPattern, "peakThroughput")) wrtFloatItm(lang, "\t", "peakThroughput",device[i].peakThroughput,',');
    if(checkFilter(filter, &filterPattern, "actualThpt")) wrtFloatItm(lang, "\t", "actualThpt",device[i].actualThpt,',');
    if(checkFilter(filter, &filterPattern, "lastMinThpt")) wrtFloatItm(lang, "\t", "lastMinThpt",device[i].lastMinThpt,',');
    if(checkFilter(filter, &filterPattern, "lastFiveMinsThpt")) wrtFloatItm(lang, "\t", "lastFiveMinsThpt",device[i].lastFiveMinsThpt,',');
    if(checkFilter(filter, &filterPattern, "peakPacketThroughput")) wrtFloatItm(lang, "\t", "peakPacketThroughput",device[i].peakPacketThroughput,',');
    if(checkFilter(filter, &filterPattern, "actualPktsThpt")) wrtFloatItm(lang, "\t", "actualPktsThpt",device[i].actualPktsThpt,',');
    if(checkFilter(filter, &filterPattern, "lastMinPktsThpt")) wrtFloatItm(lang, "\t", "lastMinPktsThpt",device[i].lastMinPktsThpt,',');
    if(checkFilter(filter, &filterPattern, "lastFiveMinsPktsThpt")) wrtFloatItm(lang, "\t", "lastFiveMinsPktsThpt",device[i].lastFiveMinsPktsThpt,',');
    if(checkFilter(filter, &filterPattern, "throughput")) wrtLlongItm(lang, "\t", "throughput", device[i].throughput,',');
    if(checkFilter(filter, &filterPattern, "packetThroughput")) wrtFloatItm(lang, "\t", "packetThroughput",device[i].packetThroughput,',');

    /* ********************************* */

    if(checkFilter(filter, &filterPattern, "last60MinutesThpt")) {
      initWriteKey(lang, "\t", "last60MinutesThpt");

      for(j=0; j<59; j++) {
	wrtIntFloatItm(lang,"\t\t",j+1,device[i].last60MinutesThpt[j].trafficValue,',');
      }
      wrtIntFloatItm(lang,"\t\t",j+1, device[i].last60MinutesThpt[j].trafficValue,' ');
      endWriteKey(lang,"\t",',');
    }

    /* ********************************* */

    if(checkFilter(filter, &filterPattern, "last24HoursThpt")) {
      initWriteKey(lang, "\t", "last24HoursThpt");

      for(j=0; j<23; j++) {
	wrtIntFloatItm(lang, "\t\t", j+1, device[i].last24HoursThpt[j].trafficValue,',');
      }
      wrtIntFloatItm(lang,"\t\t",j+1,device[i].last24HoursThpt[j].trafficValue,' ');
      endWriteKey(lang,"\t",',');
    }
    /* ********************************* */

    if(checkFilter(filter, &filterPattern, "last30daysThpt")) {
      initWriteKey(lang, "\t", "last30daysThpt");

      for(j=0; j<29; j++) {
	wrtIntFloatItm(lang,"\t\t",j+1,device[i].last30daysThpt[j],',');
      }
      wrtIntFloatItm(lang,"\t\t",j+1,device[i].last30daysThpt[j],' ');
      endWriteKey(lang,"\t",',');
    }

    /* ********************************* */

    if(checkFilter(filter, &filterPattern, "IP")) {
      if(device[i].ipProtoStats != NULL) {
	initWriteKey(lang, "\t", "IP");

	for(j=0; j<numIpProtosToMonitor; j++) {
	  if(j > 0) endWriteKey(lang, "\t\t",',');
	  initWriteKey(lang, "\t\t", protoIPTrafficInfos[j]);
	  wrtLlongItm(lang,"\t\t\t","local",
		      device[i].ipProtoStats[j].local,',');
	  wrtLlongItm(lang,"\t\t\t","local2remote",
		      device[i].ipProtoStats[j].local2remote,',');
	  wrtLlongItm(lang,"\t\t\t","remote2local",
		      device[i].ipProtoStats[j].remote2local,',');
	  wrtLlongItm(lang,"\t\t\t","remote",
		      device[i].ipProtoStats[j].remote,' ');
	}
	endWriteKey(lang,"\t\t",',');
	endWriteKey(lang,"\t",',');
      }
    }

    /* ********************************* */

    if(checkFilter(filter, &filterPattern, "TCPflags")) {
      initWriteKey(lang, "\t", "TCPflags");

      wrtLlongItm(lang,"\t\t","numEstablishedTCPConnections",
		  device[i].numEstablishedTCPConnections,' ');

      endWriteKey(lang,"\t",',');
    }

    /* ********************************* */

    if(checkFilter(filter, &filterPattern, "tcpLocal")) wrtLlongItm(lang,"\t","tcpLocal",
							    device[i].tcpGlobalTrafficStats.local,',');
    if(checkFilter(filter, &filterPattern, "tcpLocal2Remote")) wrtLlongItm(lang,"\t","tcpLocal2Remote",
							    device[i].tcpGlobalTrafficStats.local2remote,',');
    if(checkFilter(filter, &filterPattern, "tcpRemote")) wrtLlongItm(lang,"\t","tcpRemote",
							    device[i].tcpGlobalTrafficStats.remote,',');
    if(checkFilter(filter, &filterPattern, "tcpRemote2Local")) wrtLlongItm(lang,"\t","tcpRemote2Local",
							    device[i].tcpGlobalTrafficStats.remote2local,',');

    /* ********************************* */

    if(checkFilter(filter, &filterPattern, "udpLocal")) wrtLlongItm(lang,"\t","udpLocal",
							    device[i].udpGlobalTrafficStats.local,',');
    if(checkFilter(filter, &filterPattern, "udpLocal2Remote")) wrtLlongItm(lang,"\t","udpLocal2Remote",
							    device[i].udpGlobalTrafficStats.local2remote,',');
    if(checkFilter(filter, &filterPattern, "udpRemote")) wrtLlongItm(lang,"\t","udpRemote",
							    device[i].udpGlobalTrafficStats.remote,',');
    if(checkFilter(filter, &filterPattern, "udpRemote2Local")) wrtLlongItm(lang,"\t","udpRemote2Local",
							    device[i].udpGlobalTrafficStats.remote2local,',');

    /* ********************************* */

    if(checkFilter(filter, &filterPattern, "icmpLocal")) wrtLlongItm(lang,"\t","icmpLocal",
							    device[i].icmpGlobalTrafficStats.local,',');
    if(checkFilter(filter, &filterPattern, "icmpLocal2Remote")) wrtLlongItm(lang,"\t","icmpLocal2Remote",
							    device[i].icmpGlobalTrafficStats.local2remote,',');
    if(checkFilter(filter, &filterPattern, "icmpRemote")) wrtLlongItm(lang,"\t","icmpRemote",
							    device[i].icmpGlobalTrafficStats.remote,',');
    if(checkFilter(filter, &filterPattern, "icmpRemote2Local")) wrtLlongItm(lang,"\t","icmpRemote2Local",
							    device[i].icmpGlobalTrafficStats.remote2local,' ');
  }

  endWriteKey(lang,"",' ');
  endWriteArray(lang);

  if(filterPattern.fastmap)
    free(filterPattern.fastmap);
}


