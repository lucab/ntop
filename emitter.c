/*
 *  Copyright (C) 2001-2002 Luca Deri <deri@ntop.org>
 *
 *     		            http://www.ntop.org/
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
  char buf[256];

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
    if(snprintf(buf, sizeof(buf), "%s|", keyName) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
    break ;
  }
}

/* *************************** */

void endWriteKey(int lang, char *indent, char last) {
  char buf[256];

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
  char buf[256];

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

void dumpNtopHashes(char* options, int actualDeviceId) {
  char key[64], filter[128];
  unsigned int idx, numEntries=0, lang=DEFAULT_LANGUAGE, j;
  HostTraffic *el;
  struct re_pattern_buffer filterPattern;
  unsigned char shortView = 0;

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
	} else if(strcmp(tmpStr, "view") == 0) {
	  if(strcmp(key, "short")) shortView = 1;
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

  for(idx=0; idx<myGlobals.device[actualDeviceId].actualHashSize; idx++) {
    if((el = myGlobals.device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL) {
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

      if(!shortView) {
      if(checkFilter(filter, &filterPattern, "index")) wrtUintItm(lang, "\t","index", idx,' ');

      if(checkFilter(filter, &filterPattern, "hostNumIpAddress")) wrtStrItm(lang, "\t", "hostNumIpAddress", el->hostNumIpAddress,',');
      }

      if(checkFilter(filter, &filterPattern, "hostSymIpAddress")) wrtStrItm(lang, "\t", "hostSymIpAddress", el->hostSymIpAddress,',');

      if(!shortView) {
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
	if(checkFilter(filter, &filterPattern, "pktRcvd")) wrtLlongItm(lang, "\t", "pktRcvd", el->pktRcvd,',');
	if(checkFilter(filter, &filterPattern, "pktDuplicatedAckSent")) wrtLlongItm(lang, "\t", "pktDuplicatedAckSent",el->pktDuplicatedAckSent,',');
	if(checkFilter(filter, &filterPattern, "pktDuplicatedAckRcvd")) wrtLlongItm(lang, "\t", "pktDuplicatedAckRcvd",el->pktDuplicatedAckRcvd,',');
	if(checkFilter(filter, &filterPattern, "pktBroadcastSent")) wrtLlongItm(lang, "\t", "pktBroadcastSent",    el->pktBroadcastSent,',');
	if(checkFilter(filter, &filterPattern, "bytesMulticastSent")) wrtLlongItm(lang, "\t", "bytesMulticastSent",  el->bytesMulticastSent,',');
	if(checkFilter(filter, &filterPattern, "pktMulticastSent")) wrtLlongItm(lang, "\t", "pktMulticastSent",    el->pktMulticastSent,',');
	if(checkFilter(filter, &filterPattern, "bytesMulticastSent")) wrtLlongItm(lang, "\t", "bytesMulticastSent",  el->bytesMulticastSent,',');
	if(checkFilter(filter, &filterPattern, "pktMulticastRcvd")) wrtLlongItm(lang, "\t", "pktMulticastRcvd",    el->pktMulticastRcvd,',');
      }
      if(checkFilter(filter, &filterPattern, "bytesSent")) wrtLlongItm(lang, "\t", "bytesSent",           el->bytesSent,',');
      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "bytesSentLoc")) wrtLlongItm(lang, "\t", "bytesSentLoc",    el->bytesSentLoc,',');
	if(checkFilter(filter, &filterPattern, "bytesSentRem")) wrtLlongItm(lang, "\t", "bytesSentRem",   el->bytesSentRem,',');
      }
      if(checkFilter(filter, &filterPattern, "bytesRcvd")) wrtLlongItm(lang, "\t", "bytesRcvd",       el->bytesRcvd,',');
      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "bytesRcvdLoc")) wrtLlongItm(lang, "\t", "bytesRcvdLoc", el->bytesRcvdLoc,',');
	if(checkFilter(filter, &filterPattern, "bytesRcvdFromRem")) wrtLlongItm(lang, "\t", "bytesRcvdFromRem",
										el->bytesRcvdFromRem,',');
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
	if(checkFilter(filter, &filterPattern, "averageSentPktThpt")) wrtFloatItm(lang, "\t", "averageSentPktThpt", el->averageSentPktThpt,',');
      }

      if(checkFilter(filter, &filterPattern, "ipBytesSent")) wrtLlongItm(lang, "\t", "ipBytesSent", el->ipBytesSent,',');
      if(checkFilter(filter, &filterPattern, "ipBytesRcvd")) wrtLlongItm(lang, "\t", "ipBytesRcvd", el->ipBytesRcvd,',');

      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "tcpSentRem")) wrtLlongItm(lang, "\t", "tcpSentRem", el->tcpSentRem,',');
	if(checkFilter(filter, &filterPattern, "udpSentLoc")) wrtLlongItm(lang, "\t", "udpSentLoc", el->udpSentLoc,',');
	if(checkFilter(filter, &filterPattern, "udpSentRem")) wrtLlongItm(lang, "\t", "udpSentRem", el->udpSentRem,',');

      if(checkFilter(filter, &filterPattern, "icmpSent")) wrtLlongItm(lang, "\t", "icmpSent",          el->icmpSent,',');      
	if(checkFilter(filter, &filterPattern, "ospfSent")) wrtLlongItm(lang, "\t", "ospfSent",          el->ospfSent,',');
	if(checkFilter(filter, &filterPattern, "igmpSent")) wrtLlongItm(lang, "\t", "igmpSent",          el->igmpSent,',');
	if(checkFilter(filter, &filterPattern, "tcpRcvdLoc")) wrtLlongItm(lang, "\t", "tcpRcvdLoc",el->tcpRcvdLoc,',');
	if(checkFilter(filter, &filterPattern, "tcpRcvdFromRem")) wrtLlongItm(lang, "\t", "tcpRcvdFromRem",el->tcpRcvdFromRem,',');
	if(checkFilter(filter, &filterPattern, "udpRcvdLoc")) wrtLlongItm(lang, "\t", "udpRcvdLoc",el->udpRcvdLoc,',');
	if(checkFilter(filter, &filterPattern, "udpRcvdFromRem")) wrtLlongItm(lang, "\t", "udpRcvdFromRem",el->udpRcvdFromRem,',');
	if(checkFilter(filter, &filterPattern, "icmpRcvd")) wrtLlongItm(lang, "\t", "icmpRcvd",      el->icmpRcvd,',');
	if(checkFilter(filter, &filterPattern, "ospfRcvd")) wrtLlongItm(lang, "\t", "ospfRcvd",      el->ospfRcvd,',');
	if(checkFilter(filter, &filterPattern, "igmpRcvd")) wrtLlongItm(lang, "\t", "igmpRcvd",      el->igmpRcvd,',');

      /* ***************************** */

	if(checkFilter(filter, &filterPattern, "tcpFragmentsSent")) wrtLlongItm(lang, "\t", "tcpFragmentsSent", el->tcpFragmentsSent,',');
	if(checkFilter(filter, &filterPattern, "tcpFragmentsRcvd")) wrtLlongItm(lang, "\t", "tcpFragmentsRcvd", el->tcpFragmentsRcvd,',');
	if(checkFilter(filter, &filterPattern, "udpFragmentsSent")) wrtLlongItm(lang, "\t", "udpFragmentsSent", el->udpFragmentsSent,',');
	if(checkFilter(filter, &filterPattern, "udpFragmentsRcvd")) wrtLlongItm(lang, "\t", "udpFragmentsRcvd", el->udpFragmentsRcvd,',');
	if(checkFilter(filter, &filterPattern, "icmpFragmentsSent")) wrtLlongItm(lang, "\t", "icmpFragmentsSent", el->icmpFragmentsSent,',');
	if(checkFilter(filter, &filterPattern, "icmpFragmentsRcvd")) wrtLlongItm(lang, "\t", "icmpFragmentsRcvd", el->icmpFragmentsRcvd,',');

	/* ***************************** */

	if(checkFilter(filter, &filterPattern, "stpSent")) wrtLlongItm(lang, "\t", "stpSent",          el->stpSent,',');
	if(checkFilter(filter, &filterPattern, "stpRcvd")) wrtLlongItm(lang, "\t", "stpRcvd",      el->stpRcvd,',');
	if(checkFilter(filter, &filterPattern, "ipxSent")) wrtLlongItm(lang, "\t", "ipxSent",          el->ipxSent,',');
	if(checkFilter(filter, &filterPattern, "ipxRcvd")) wrtLlongItm(lang, "\t", "ipxRcvd",      el->ipxRcvd,',');
	if(checkFilter(filter, &filterPattern, "osiSent")) wrtLlongItm(lang, "\t", "osiSent",          el->osiSent,',');
	if(checkFilter(filter, &filterPattern, "osiRcvd")) wrtLlongItm(lang, "\t", "osiRcvd",      el->osiRcvd,',');
	if(checkFilter(filter, &filterPattern, "dlcSent")) wrtLlongItm(lang, "\t", "dlcSent",          el->dlcSent,',');
	if(checkFilter(filter, &filterPattern, "dlcRcvd")) wrtLlongItm(lang, "\t", "dlcRcvd",      el->dlcRcvd,',');

	if(checkFilter(filter, &filterPattern, "arp_rarpSent")) wrtLlongItm(lang, "\t", "arp_rarpSent",     el->arp_rarpSent,',');
	if(checkFilter(filter, &filterPattern, "arp_rarpRcvd")) wrtLlongItm(lang, "\t", "arp_rarpRcvd", el->arp_rarpRcvd,',');
	if(checkFilter(filter, &filterPattern, "arpReqPktsSent")) wrtLlongItm(lang, "\t", "arpReqPktsSent",   el->arpReqPktsSent,',');
	if(checkFilter(filter, &filterPattern, "arpReplyPktsSent")) wrtLlongItm(lang, "\t", "arpReplyPktsSent", el->arpReplyPktsSent,',');
	if(checkFilter(filter, &filterPattern, "arpReplyPktsRcvd")) wrtLlongItm(lang, "\t", "arpReplyPktsRcvd", el->arpReplyPktsRcvd,',');
	if(checkFilter(filter, &filterPattern, "decnetSent")) wrtLlongItm(lang, "\t", "decnetSent",       el->decnetSent,',');
	if(checkFilter(filter, &filterPattern, "decnetRcvd")) wrtLlongItm(lang, "\t", "decnetRcvd",   el->decnetRcvd,',');
	if(checkFilter(filter, &filterPattern, "appletalkSent")) wrtLlongItm(lang, "\t", "appletalkSent",    el->appletalkSent,',');
	if(checkFilter(filter, &filterPattern, "appletalkRcvd")) wrtLlongItm(lang, "\t", "appletalkRcvd",el->appletalkRcvd,',');
	if(checkFilter(filter, &filterPattern, "netbiosSent")) wrtLlongItm(lang, "\t", "netbiosSent",      el->netbiosSent,',');
	if(checkFilter(filter, &filterPattern, "netbiosRcvd")) wrtLlongItm(lang, "\t", "netbiosRcvd",  el->netbiosRcvd,',');
	if(checkFilter(filter, &filterPattern, "qnxSent")) wrtLlongItm(lang, "\t", "qnxSent",          el->qnxSent,',');
	if(checkFilter(filter, &filterPattern, "qnxRcvd")) wrtLlongItm(lang, "\t", "qnxRcvd",      el->qnxRcvd,',');
	if(checkFilter(filter, &filterPattern, "otherSent")) wrtLlongItm(lang, "\t", "otherSent",        el->otherSent,',');
	if(checkFilter(filter, &filterPattern, "otherRcvd")) wrtLlongItm(lang, "\t", "otherRcvd",    el->otherRcvd,',');

      /* ********************************* */

	if(el->routedTraffic && checkFilter(filter, &filterPattern, "RoutingCounter")) {
	  initWriteKey(lang, "\t", "RoutingCounter");
	  wrtLlongItm(lang,"\t\t", "routedPkts", el->routedTraffic->routedPkts,',');
	  wrtLlongItm(lang,"\t\t", "routedBytes", el->routedTraffic->routedBytes,',');
	  endWriteKey(lang,"\t",',');
	}

	if(el->protoIPTrafficInfos && checkFilter(filter, &filterPattern, "IP")) {
	  initWriteKey(lang, "\t", "IP");

	  for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {

	    if(j > 0) { endWriteKey(lang,"\t\t",','); }

	    initWriteKey(lang, "\t\t", myGlobals.protoIPTrafficInfos[j]);
	    wrtLlongItm(lang,"\t\t\t","sentLoc",
			el->protoIPTrafficInfos[j].sentLoc,',');
	    wrtLlongItm(lang,"\t\t\t","sentRem",
			el->protoIPTrafficInfos[j].sentRem,',');
	    wrtLlongItm(lang,"\t\t\t","rcvdLoc",
			el->protoIPTrafficInfos[j].rcvdLoc,',');
	    wrtLlongItm(lang,"\t\t\t","rcvdFromRem",
			el->protoIPTrafficInfos[j].rcvdFromRem,' ');
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

	if(el->secHostPkts && checkFilter(filter, &filterPattern, "securityPkts")) {
	  initWriteKey(lang, "\t", "securityPkts");

	  wrtLlongItm(lang,"\t\t","synPktsSent",
		      el->secHostPkts->synPktsSent.value,',');
	  wrtLlongItm(lang,"\t\t","synPktsRcvd",
		      el->secHostPkts->synPktsRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","rstPktsSent",
		      el->secHostPkts->rstPktsSent.value,',');
	  wrtLlongItm(lang,"\t\t","rstPktsRcvd",
		      el->secHostPkts->rstPktsRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","rstAckPktsSent",
		      el->secHostPkts->rstAckPktsSent.value,',');
	  wrtLlongItm(lang,"\t\t","rstAckPktsRcvd",
		      el->secHostPkts->rstAckPktsRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","synFinPktsSent",
		      el->secHostPkts->synFinPktsSent.value,',');
	  wrtLlongItm(lang,"\t\t","synFinPktsRcvd",
		      el->secHostPkts->synFinPktsRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","finPushUrgPktsSent",
		      el->secHostPkts->finPushUrgPktsSent.value,',');
	  wrtLlongItm(lang,"\t\t","finPushUrgPktsRcvd",
		      el->secHostPkts->finPushUrgPktsRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","nullPktsSent",
		      el->secHostPkts->nullPktsSent.value,',');
	  wrtLlongItm(lang,"\t\t","nullPktsRcvd",
		      el->secHostPkts->nullPktsRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","ackScanSent",
		      el->secHostPkts->ackScanSent.value,',');
	  wrtLlongItm(lang,"\t\t","ackScanRcvd",
		      el->secHostPkts->ackScanRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","xmasScanSent",
		      el->secHostPkts->xmasScanSent.value,',');
	  wrtLlongItm(lang,"\t\t","xmasScanRcvd",
		      el->secHostPkts->xmasScanRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","finScanSent",
		      el->secHostPkts->finScanSent.value,',');
	  wrtLlongItm(lang,"\t\t","finScanRcvd",
		      el->secHostPkts->finScanRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","nullScanSent",
		      el->secHostPkts->nullScanSent.value,',');
	  wrtLlongItm(lang,"\t\t","nullScanRcvd",
		      el->secHostPkts->nullScanRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","rejectedTCPConnSent",
		      el->secHostPkts->rejectedTCPConnSent.value,',');
	  wrtLlongItm(lang,"\t\t","rejectedTCPConnRcvd",
		      el->secHostPkts->rejectedTCPConnRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","establishedTCPConnSent",
		      el->secHostPkts->establishedTCPConnSent.value,',');
	  wrtLlongItm(lang,"\t\t","establishedTCPConnRcvd",
		      el->secHostPkts->establishedTCPConnRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","udpToClosedPortSent",
		      el->secHostPkts->udpToClosedPortSent.value,',');
	  wrtLlongItm(lang,"\t\t","udpToClosedPortRcvd",
		      el->secHostPkts->udpToClosedPortRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","udpToDiagnosticPortSent",
		      el->secHostPkts->udpToDiagnosticPortSent.value,',');
	  wrtLlongItm(lang,"\t\t","udpToDiagnosticPortRcvd",
		      el->secHostPkts->udpToDiagnosticPortRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","tcpToDiagnosticPortSent",
		      el->secHostPkts->tcpToDiagnosticPortSent.value,',');
	  wrtLlongItm(lang,"\t\t","tcpToDiagnosticPortRcvd",
		      el->secHostPkts->tcpToDiagnosticPortRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","tinyFragmentSent",
		      el->secHostPkts->tinyFragmentSent.value,',');
	  wrtLlongItm(lang,"\t\t","tinyFragmentRcvd",
		      el->secHostPkts->tinyFragmentRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","icmpFragmentSent",
		      el->secHostPkts->icmpFragmentSent.value,',');
	  wrtLlongItm(lang,"\t\t","icmpFragmentRcvd",
		      el->secHostPkts->icmpFragmentRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","overlappingFragmentSent",
		      el->secHostPkts->overlappingFragmentSent.value,',');
	  wrtLlongItm(lang,"\t\t","overlappingFragmentRcvd",
		      el->secHostPkts->overlappingFragmentRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","closedEmptyTCPConnSent",
		      el->secHostPkts->closedEmptyTCPConnSent.value,',');
	  wrtLlongItm(lang,"\t\t","closedEmptyTCPConnRcvd",
		      el->secHostPkts->closedEmptyTCPConnRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","icmpPortUnreachSent",
		      el->secHostPkts->icmpPortUnreachSent.value,',');
	  wrtLlongItm(lang,"\t\t","icmpPortUnreachRcvd",
		      el->secHostPkts->icmpPortUnreachRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","icmpHostNetUnreachSent",
		      el->secHostPkts->icmpHostNetUnreachSent.value,',');
	  wrtLlongItm(lang,"\t\t","icmpHostNetUnreachRcvd",
		      el->secHostPkts->icmpHostNetUnreachRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","icmpProtocolUnreachSent",
		      el->secHostPkts->icmpProtocolUnreachSent.value,',');
	  wrtLlongItm(lang,"\t\t","icmpProtocolUnreachRcvd",
		      el->secHostPkts->icmpProtocolUnreachRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","icmpAdminProhibitedSent",
		      el->secHostPkts->icmpAdminProhibitedSent.value,',');
	  wrtLlongItm(lang,"\t\t","icmpAdminProhibitedRcvd",
		      el->secHostPkts->icmpAdminProhibitedRcvd.value,',');

	  wrtLlongItm(lang,"\t\t","malformedPktsSent",
		      el->secHostPkts->malformedPktsSent.value,',');
	  wrtLlongItm(lang,"\t\t","malformedPktsRcvd",
		      el->secHostPkts->malformedPktsRcvd.value,',');

	  endWriteKey(lang,"\t",',');
	}

      /* ***************************** */
	
	if(checkFilter(filter, &filterPattern, "ethAddressString"))
	  wrtStrItm(lang, "\t", "ethAddressString",el->ethAddressString,' ');
      } /* shortView */

      numEntries++;
    }
  }

  if(numEntries > 0) endWriteKey(lang,"",' ');

  endWriteArray(lang);

  if(filterPattern.fastmap)
    free(filterPattern.fastmap);
}

/* ********************************** */

void dumpNtopHashIndexes(char* options, int actualDeviceId) {
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

  for(idx=1; idx<myGlobals.device[actualDeviceId].actualHashSize; idx++) {
    if(((el = myGlobals.device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
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
  int lang=DEFAULT_LANGUAGE, i, num;
  struct re_pattern_buffer filterPattern;
  unsigned short shortView = 0;

  memset(key, 0, sizeof(key));
  memset(filter, 0, sizeof(filter));

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
	} else if(strcmp(tmpStr, "view") == 0) {
	  if(strcmp(key, "short")) shortView = 1;
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

  for(i=0, num=0; i<myGlobals.numDevices; i++) {
    int j;

    if(myGlobals.device[i].virtualDevice) continue;

    if((key[0] != '\0') &&(strcmp(key, myGlobals.device[i].name) != 0))
      continue;

    if(num > 0) { endWriteKey(lang,"",','); }

    initWriteKey(lang, "", myGlobals.device[i].name);

    if(!shortView) {
      if(checkFilter(filter, &filterPattern, "ipdot")) wrtStrItm(lang, "\t", "ipdot", myGlobals.device[i].ipdot,',');
      if(checkFilter(filter, &filterPattern, "fqdn")) wrtStrItm(lang, "\t", "fqdn", myGlobals.device[i].fqdn,',');

      snprintf(localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].network, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, &filterPattern, "network")) wrtStrItm(lang, "\t", "network",  localbuf,',');
      snprintf(localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].netmask, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, &filterPattern, "netmask")) wrtStrItm(lang, "\t", "netmask", localbuf,',');
      snprintf(localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].ifAddr, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, &filterPattern, "ifAddr")) wrtStrItm(lang, "\t", "ifAddr",  localbuf,',');

      if(checkFilter(filter, &filterPattern, "started")) wrtTime_tItm(lang, "\t", "started",  myGlobals.device[i].started,' ');
      if(checkFilter(filter, &filterPattern, "firstpkt")) wrtTime_tItm(lang, "\t", "firstpkt", myGlobals.device[i].firstpkt,' ');
      if(checkFilter(filter, &filterPattern, "lastpkt")) wrtTime_tItm(lang, "\t", "lastpkt",  myGlobals.device[i].lastpkt,' ');
      if(checkFilter(filter, &filterPattern, "virtualDevice")) wrtIntItm(lang, "\t", "virtualDevice",(int)myGlobals.device[i].virtualDevice,',');
      if(checkFilter(filter, &filterPattern, "snaplen")) wrtIntItm(lang, "\t", "snaplen",  myGlobals.device[i].snaplen,',');
      if(checkFilter(filter, &filterPattern, "datalink")) wrtIntItm(lang, "\t", "datalink", myGlobals.device[i].datalink,',');
      if(checkFilter(filter, &filterPattern, "filter")) wrtStrItm(lang, "\t", "filter",   myGlobals.device[i].filter ? myGlobals.device[i].filter : "",',');
      if(checkFilter(filter, &filterPattern, "droppedPkts")) wrtLlongItm(lang, "\t", "droppedPkts",myGlobals.device[i].droppedPkts,',');
    }

    if(checkFilter(filter, &filterPattern, "ethernetPkts")) wrtLlongItm(lang, "\t", "ethernetPkts",myGlobals.device[i].ethernetPkts,',');
    if(checkFilter(filter, &filterPattern, "broadcastPkts")) wrtLlongItm(lang, "\t", "broadcastPkts",myGlobals.device[i].broadcastPkts,',');
    if(checkFilter(filter, &filterPattern, "multicastPkts")) wrtLlongItm(lang, "\t", "multicastPkts",myGlobals.device[i].multicastPkts,',');
    if(checkFilter(filter, &filterPattern, "ethernetBytes")) wrtLlongItm(lang, "\t", "ethernetBytes",myGlobals.device[i].ethernetBytes,',');
    if(checkFilter(filter, &filterPattern, "ipBytes")) wrtLlongItm(lang, "\t", "ipBytes",myGlobals.device[i].ipBytes,',');
    if(!shortView) {
      if(checkFilter(filter, &filterPattern, "fragmentedIpBytes")) wrtLlongItm(lang, "\t", "fragmentedIpBytes",myGlobals.device[i].fragmentedIpBytes,',');
    }
    if(checkFilter(filter, &filterPattern, "tcpBytes")) wrtLlongItm(lang, "\t", "tcpBytes",myGlobals.device[i].tcpBytes,',');
    if(checkFilter(filter, &filterPattern, "udpBytes")) wrtLlongItm(lang, "\t", "udpBytes",myGlobals.device[i].udpBytes,',');
    if(checkFilter(filter, &filterPattern, "otherIpBytes")) wrtLlongItm(lang, "\t", "otherIpBytes",myGlobals.device[i].otherIpBytes,',');
    if(checkFilter(filter, &filterPattern, "icmpBytes")) wrtLlongItm(lang, "\t", "icmpBytes",myGlobals.device[i].icmpBytes,',');
    if(checkFilter(filter, &filterPattern, "dlcBytes")) wrtLlongItm(lang, "\t", "dlcBytes",myGlobals.device[i].dlcBytes,',');
    if(!shortView) {
      if(checkFilter(filter, &filterPattern, "ipxBytes")) wrtLlongItm(lang, "\t", "ipxBytes",myGlobals.device[i].ipxBytes,',');
      if(checkFilter(filter, &filterPattern, "stpBytes")) wrtLlongItm(lang, "\t", "stpBytes",myGlobals.device[i].stpBytes,',');
      if(checkFilter(filter, &filterPattern, "decnetBytes")) wrtLlongItm(lang, "\t", "decnetBytes",myGlobals.device[i].decnetBytes,',');
      if(checkFilter(filter, &filterPattern, "netbiosBytes")) wrtLlongItm(lang, "\t", "netbiosBytes",myGlobals.device[i].netbiosBytes,',');
      if(checkFilter(filter, &filterPattern, "arpRarpBytes")) wrtLlongItm(lang, "\t", "arpRarpBytes",myGlobals.device[i].arpRarpBytes,',');
      if(checkFilter(filter, &filterPattern, "atalkBytes")) wrtLlongItm(lang, "\t", "atalkBytes",myGlobals.device[i].atalkBytes,',');
      if(checkFilter(filter, &filterPattern, "ospfBytes")) wrtLlongItm(lang, "\t", "ospfBytes",myGlobals.device[i].ospfBytes,',');
      if(checkFilter(filter, &filterPattern, "egpBytes")) wrtLlongItm(lang, "\t", "egpBytes",myGlobals.device[i].egpBytes,',');
      if(checkFilter(filter, &filterPattern, "igmpBytes")) wrtLlongItm(lang, "\t", "igmpBytes",myGlobals.device[i].igmpBytes,',');
      if(checkFilter(filter, &filterPattern, "osiBytes")) wrtLlongItm(lang, "\t", "osiBytes",myGlobals.device[i].osiBytes,',');
      if(checkFilter(filter, &filterPattern, "qnxBytes")) wrtLlongItm(lang, "\t", "qnxBytes",myGlobals.device[i].qnxBytes,',');
      if(checkFilter(filter, &filterPattern, "otherBytes")) wrtLlongItm(lang, "\t", "otherBytes",myGlobals.device[i].otherBytes,',');
      if(checkFilter(filter, &filterPattern, "lastMinEthernetBytes")) wrtLlongItm(lang, "\t", "lastMinEthernetBytes",
										  myGlobals.device[i].lastMinEthernetBytes,',');
      if(checkFilter(filter, &filterPattern, "lastFiveMinsEthernetBytes")) wrtLlongItm(lang, "\t", "lastFiveMinsEthernetBytes",
										       myGlobals.device[i].lastFiveMinsEthernetBytes,',');
      if(checkFilter(filter, &filterPattern, "lastMinEthernetPkts")) wrtLlongItm(lang, "\t", "lastMinEthernetPkts",myGlobals.device[i].lastMinEthernetPkts,',');
      if(checkFilter(filter, &filterPattern, "lastFiveMinsEthernetPkts")) wrtLlongItm(lang, "\t", "lastFiveMinsEthernetPkts",
										      myGlobals.device[i].lastFiveMinsEthernetPkts,',');
      if(checkFilter(filter, &filterPattern, "upTo64")) wrtLlongItm(lang, "\t", "upTo64",myGlobals.device[i].rcvdPktStats.upTo64,',');
      if(checkFilter(filter, &filterPattern, "upTo128")) wrtLlongItm(lang, "\t", "upTo128",myGlobals.device[i].rcvdPktStats.upTo128,',');
      if(checkFilter(filter, &filterPattern, "upTo256")) wrtLlongItm(lang, "\t", "upTo256",myGlobals.device[i].rcvdPktStats.upTo256,',');
      if(checkFilter(filter, &filterPattern, "upTo512")) wrtLlongItm(lang, "\t", "upTo512",myGlobals.device[i].rcvdPktStats.upTo512,',');
      if(checkFilter(filter, &filterPattern, "upTo1024")) wrtLlongItm(lang, "\t", "upTo1024",myGlobals.device[i].rcvdPktStats.upTo1024,',');
      if(checkFilter(filter, &filterPattern, "upTo1518")) wrtLlongItm(lang, "\t", "upTo1518",myGlobals.device[i].rcvdPktStats.upTo1518,',');
      if(checkFilter(filter, &filterPattern, "above1518")) wrtLlongItm(lang, "\t", "above1518",myGlobals.device[i].rcvdPktStats.above1518,',');
      if(checkFilter(filter, &filterPattern, "shortest")) wrtLlongItm(lang, "\t", "shortest",myGlobals.device[i].rcvdPktStats.shortest,',');
      if(checkFilter(filter, &filterPattern, "longest")) wrtLlongItm(lang, "\t", "longest",myGlobals.device[i].rcvdPktStats.longest,',');
      if(checkFilter(filter, &filterPattern, "badChecksum")) wrtLlongItm(lang, "\t", "badChecksum",myGlobals.device[i].rcvdPktStats.badChecksum,',');
      if(checkFilter(filter, &filterPattern, "tooLong")) wrtLlongItm(lang, "\t", "tooLong",myGlobals.device[i].rcvdPktStats.tooLong,',');
      if(checkFilter(filter, &filterPattern, "peakThroughput")) wrtFloatItm(lang, "\t", "peakThroughput",myGlobals.device[i].peakThroughput,',');
      if(checkFilter(filter, &filterPattern, "actualThpt")) wrtFloatItm(lang, "\t", "actualThpt",myGlobals.device[i].actualThpt,',');
      if(checkFilter(filter, &filterPattern, "lastMinThpt")) wrtFloatItm(lang, "\t", "lastMinThpt",myGlobals.device[i].lastMinThpt,',');
      if(checkFilter(filter, &filterPattern, "lastFiveMinsThpt")) wrtFloatItm(lang, "\t", "lastFiveMinsThpt",myGlobals.device[i].lastFiveMinsThpt,',');
      if(checkFilter(filter, &filterPattern, "peakPacketThroughput")) wrtFloatItm(lang, "\t", "peakPacketThroughput",myGlobals.device[i].peakPacketThroughput,',');
      if(checkFilter(filter, &filterPattern, "actualPktsThpt")) wrtFloatItm(lang, "\t", "actualPktsThpt",myGlobals.device[i].actualPktsThpt,',');
      if(checkFilter(filter, &filterPattern, "lastMinPktsThpt")) wrtFloatItm(lang, "\t", "lastMinPktsThpt",myGlobals.device[i].lastMinPktsThpt,',');
      if(checkFilter(filter, &filterPattern, "lastFiveMinsPktsThpt")) wrtFloatItm(lang, "\t", "lastFiveMinsPktsThpt",myGlobals.device[i].lastFiveMinsPktsThpt,',');
      if(checkFilter(filter, &filterPattern, "throughput")) wrtLlongItm(lang, "\t", "throughput", myGlobals.device[i].throughput,',');
      if(checkFilter(filter, &filterPattern, "packetThroughput")) wrtFloatItm(lang, "\t", "packetThroughput",myGlobals.device[i].packetThroughput,',');

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "last60MinutesThpt")) {
	initWriteKey(lang, "\t", "last60MinutesThpt");

	for(j=0; j<59; j++) {
	  wrtIntFloatItm(lang,"\t\t",j+1,myGlobals.device[i].last60MinutesThpt[j].trafficValue,',');
	}
	wrtIntFloatItm(lang,"\t\t",j+1, myGlobals.device[i].last60MinutesThpt[j].trafficValue,' ');
	endWriteKey(lang,"\t",',');
      }

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "last24HoursThpt")) {
	initWriteKey(lang, "\t", "last24HoursThpt");

	for(j=0; j<23; j++) {
	  wrtIntFloatItm(lang, "\t\t", j+1, myGlobals.device[i].last24HoursThpt[j].trafficValue,',');
	}
	wrtIntFloatItm(lang,"\t\t",j+1,myGlobals.device[i].last24HoursThpt[j].trafficValue,' ');
	endWriteKey(lang,"\t",',');
      }
      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "last30daysThpt")) {
	initWriteKey(lang, "\t", "last30daysThpt");

	for(j=0; j<29; j++) {
	  wrtIntFloatItm(lang,"\t\t",j+1,myGlobals.device[i].last30daysThpt[j],',');
	}
	wrtIntFloatItm(lang,"\t\t",j+1,myGlobals.device[i].last30daysThpt[j],' ');
	endWriteKey(lang,"\t",',');
      }

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "IP")) {
	if(myGlobals.device[i].ipProtoStats != NULL) {
	  initWriteKey(lang, "\t", "IP");

	  for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {
	    if(j > 0) endWriteKey(lang, "\t\t",',');
	    initWriteKey(lang, "\t\t", myGlobals.protoIPTrafficInfos[j]);
	    wrtLlongItm(lang,"\t\t\t","local",
			myGlobals.device[i].ipProtoStats[j].local,',');
	    wrtLlongItm(lang,"\t\t\t","local2remote",
			myGlobals.device[i].ipProtoStats[j].local2remote,',');
	    wrtLlongItm(lang,"\t\t\t","remote2local",
			myGlobals.device[i].ipProtoStats[j].remote2local,',');
	    wrtLlongItm(lang,"\t\t\t","remote",
			myGlobals.device[i].ipProtoStats[j].remote,' ');
	  }
	  endWriteKey(lang,"\t\t",',');
	  endWriteKey(lang,"\t",',');
	}
      }

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "TCPflags")) {
	initWriteKey(lang, "\t", "TCPflags");

	wrtLlongItm(lang,"\t\t","numEstablishedTCPConnections",
		    myGlobals.device[i].numEstablishedTCPConnections,' ');

	endWriteKey(lang,"\t",',');
      }

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "tcpLocal")) wrtLlongItm(lang,"\t","tcpLocal",
								      myGlobals.device[i].tcpGlobalTrafficStats.local,',');
      if(checkFilter(filter, &filterPattern, "tcpLocal2Rem")) wrtLlongItm(lang,"\t","tcpLocal2Rem",
									  myGlobals.device[i].tcpGlobalTrafficStats.local2remote,',');
      if(checkFilter(filter, &filterPattern, "tcpRem")) wrtLlongItm(lang,"\t","tcpRem",
								    myGlobals.device[i].tcpGlobalTrafficStats.remote,',');
      if(checkFilter(filter, &filterPattern, "tcpRem2Local")) wrtLlongItm(lang,"\t","tcpRem2Local",
									  myGlobals.device[i].tcpGlobalTrafficStats.remote2local,',');

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "udpLocal")) wrtLlongItm(lang,"\t","udpLocal",
								      myGlobals.device[i].udpGlobalTrafficStats.local,',');
      if(checkFilter(filter, &filterPattern, "udpLocal2Rem")) wrtLlongItm(lang,"\t","udpLocal2Rem",
									  myGlobals.device[i].udpGlobalTrafficStats.local2remote,',');
      if(checkFilter(filter, &filterPattern, "udpRem")) wrtLlongItm(lang,"\t","udpRem",
								    myGlobals.device[i].udpGlobalTrafficStats.remote,',');
      if(checkFilter(filter, &filterPattern, "udpRem2Local")) wrtLlongItm(lang,"\t","udpRem2Local",
									  myGlobals.device[i].udpGlobalTrafficStats.remote2local,',');

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "icmpLocal")) wrtLlongItm(lang,"\t","icmpLocal",
								       myGlobals.device[i].icmpGlobalTrafficStats.local,',');
      if(checkFilter(filter, &filterPattern, "icmpLocal2Rem")) wrtLlongItm(lang,"\t","icmpLocal2Rem",
									   myGlobals.device[i].icmpGlobalTrafficStats.local2remote,',');
      if(checkFilter(filter, &filterPattern, "icmpRem")) wrtLlongItm(lang,"\t","icmpRem",
								     myGlobals.device[i].icmpGlobalTrafficStats.remote,',');
      if(checkFilter(filter, &filterPattern, "icmpRem2Local")) wrtLlongItm(lang,"\t","icmpRem2Local",
									   myGlobals.device[i].icmpGlobalTrafficStats.remote2local,' ');
    }
    num++;
  }

  if(num > 0) endWriteKey(lang,"",' ');
  endWriteArray(lang);

  if(filterPattern.fastmap)
    free(filterPattern.fastmap);
}


