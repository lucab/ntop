/*
 *  Copyright (C) 2001-2002 Luca Deri <deri@ntop.org>
 *
 *     		            http://www.ntop.org/
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
char *languages[] = { "", "perl", "php", "no" };


/* *************************** */

void initWriteArray(int lang) {
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

void initWriteKey(int lang, char *indent, char *keyName, int numEntriesSent) {
  char buf[256];

  switch(lang) {
  case PERL_LANGUAGE :
    if(snprintf(buf, sizeof(buf), "%s'%s' => {\n",indent, keyName) < 0)
      BufferOverflow();
    sendString(buf);
    break ;
  case PHP_LANGUAGE :
    if(snprintf(buf, sizeof(buf), "%s'%s' => array(\n",indent, keyName) < 0)
      BufferOverflow();
    sendString(buf);
    break ;
  case NO_LANGUAGE :
    if(snprintf(buf, sizeof(buf), "%s|", numEntriesSent == 0 ? "key" : keyName) < 0)
      BufferOverflow();
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
      BufferOverflow();
    sendString(buf);
    break ;
  case PHP_LANGUAGE :
    if(snprintf(buf, sizeof(buf),"%s)%c\n",indent,last) < 0)
      BufferOverflow();
    sendString(buf);
    break ;
  case NO_LANGUAGE :
    if( indent == "") sendString("\n");
    break ;
  }
}

/* *************************** */

void wrtStrItm(int lang, char *indent, char *name, char *value, char last, int numEntriesSent) {
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
	BufferOverflow();  sendString(buf);
    }
    break ;
  case NO_LANGUAGE :
    if( value != NULL ) {
      if(snprintf(buf, sizeof(buf), "%s|", numEntriesSent == 0 ? name : value) < 0)
	BufferOverflow();  sendString(buf);
    } else {
      if(snprintf(buf, sizeof(buf), "%s|", numEntriesSent == 0 ? name : "") < 0)
	BufferOverflow();  sendString(buf);
    }
    break ;
  }
}

/* *************************** */

void wrtIntItm(int lang, char *indent, char *name, int value, char last, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%d",value);
  wrtStrItm(lang, indent, name, buf, last, numEntriesSent);
}

/* *************************** */

void wrtIntStrItm(int lang, char *indent,int name, char *value, char useless, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%d",name);
  wrtStrItm(lang, indent, buf, value, ',', numEntriesSent);
}

/* *************************** */

void wrtUintItm(int lang, char *indent, char *name, unsigned int value, char useless, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%d",value);
  wrtStrItm(lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

void wrtUcharItm(int lang, char *indent, char *name, u_char value, char useless, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%d",value);
  wrtStrItm(lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

void wrtFloatItm(int lang, char *indent, char *name, float value, char last, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%0.2f",value);
  wrtStrItm(lang, indent, name, buf, last, numEntriesSent);
}

/* *************************** */

void wrtIntFloatItm(int lang, char *indent, int name, float value, char last, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%d",name);
  wrtFloatItm(lang, indent, buf, value, last, numEntriesSent);
}

/* *************************** */

void wrtUlongItm(int lang, char *indent, char *name, unsigned long value, char useless, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%lu",value);
  wrtStrItm(lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

void wrtLlongItm(int lang, char* indent, char* name, TrafficCounter value, char last, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%llu",value);
  wrtStrItm(lang, indent, name, buf, last, numEntriesSent);
}

/* *************************** */

void wrtTime_tItm(int lang, char *indent, char *name, time_t value, char useless, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%ld",value);
  wrtStrItm(lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

void wrtUshortItm(int lang, char *indent, char *name, u_short value, char useless, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%d",value);
  wrtStrItm(lang, indent, name, buf, ',', numEntriesSent);
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
    if((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) != NULL) {
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

  REPEAT_HOSTS:
      if(numEntries > 0) { endWriteKey(lang,"",','); }

      initWriteKey(lang, "", hostKey, numEntries);

      /* ************************ */

      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "index")) wrtUintItm(lang, "\t","index", idx, ' ', numEntries);

	if(checkFilter(filter, &filterPattern, "hostNumIpAddress"))
	  wrtStrItm(lang, "\t", "hostNumIpAddress", el->hostNumIpAddress,',', numEntries);
      }

      if(checkFilter(filter, &filterPattern, "hostSymIpAddress"))
	wrtStrItm(lang, "\t", "hostSymIpAddress", el->hostSymIpAddress,',', numEntries);

      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "firstSeen")) wrtTime_tItm(lang, "\t", "firstSeen", el->firstSeen, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "lastSeen")) wrtTime_tItm(lang, "\t", "lastSeen",  el->lastSeen, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "minTTL")) wrtUshortItm(lang, "\t", "minTTL",     el->minTTL, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "maxTTL")) wrtUshortItm(lang, "\t", "maxTTL",     el->maxTTL, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "nbHostName")) wrtStrItm(lang, "\t", "nbHostName",   el->nbHostName,',', numEntries);
	if(checkFilter(filter, &filterPattern, "nbDomainName")) wrtStrItm(lang, "\t", "nbDomainName", el->nbDomainName,',', numEntries);
	if(checkFilter(filter, &filterPattern, "nbDescr")) wrtStrItm(lang, "\t", "nbDescr",      el->nbDescr,',', numEntries);
	if(checkFilter(filter, &filterPattern, "nodeType")) wrtUcharItm (lang, "\t", "nodeType",  el->nbNodeType, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "atNodeName")) wrtStrItm(lang, "\t", "atNodeName",   el->atNodeName,',', numEntries);
	if(checkFilter(filter, &filterPattern, "atNetwork")) wrtUshortItm(lang, "\t", "atNetwork",  el->atNetwork, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "atNode")) wrtUcharItm (lang, "\t", "atNode",    el->atNode, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "ipxHostName")) wrtStrItm(lang, "\t", "ipxHostName",  el->ipxHostName,',', numEntries);
      }

	if(checkFilter(filter, &filterPattern, "pktSent")) wrtLlongItm(lang, "\t", "pktSent",   el->pktSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "pktRcvd")) wrtLlongItm(lang, "\t", "pktRcvd", el->pktRcvd,',', numEntries);

      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "pktDuplicatedAckSent")) wrtLlongItm(lang, "\t", "pktDuplicatedAckSent",el->pktDuplicatedAckSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "pktDuplicatedAckRcvd")) wrtLlongItm(lang, "\t", "pktDuplicatedAckRcvd",el->pktDuplicatedAckRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "pktBroadcastSent")) wrtLlongItm(lang, "\t", "pktBroadcastSent",  el->pktBroadcastSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "bytesMulticastSent")) wrtLlongItm(lang, "\t", "bytesMulticastSent", el->bytesMulticastSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "pktMulticastSent")) wrtLlongItm(lang, "\t", "pktMulticastSent",  el->pktMulticastSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "bytesMulticastSent")) wrtLlongItm(lang, "\t", "bytesMulticastSent", el->bytesMulticastSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "pktMulticastRcvd")) wrtLlongItm(lang, "\t", "pktMulticastRcvd",  el->pktMulticastRcvd,',', numEntries);
      }
    
      if(checkFilter(filter, &filterPattern, "bytesSent")) wrtLlongItm(lang, "\t", "bytesSent",         el->bytesSent,',', numEntries);

      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "bytesSentLoc")) wrtLlongItm(lang, "\t", "bytesSentLoc",  el->bytesSentLoc,',', numEntries);
	if(checkFilter(filter, &filterPattern, "bytesSentRem")) wrtLlongItm(lang, "\t", "bytesSentRem", el->bytesSentRem,',', numEntries);
      }

      if(checkFilter(filter, &filterPattern, "bytesRcvd")) wrtLlongItm(lang, "\t", "bytesRcvd",     el->bytesRcvd,',', numEntries);

      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "bytesRcvdLoc")) wrtLlongItm(lang, "\t", "bytesRcvdLoc", el->bytesRcvdLoc,',', numEntries);
	if(checkFilter(filter, &filterPattern, "bytesRcvdFromRem")) wrtLlongItm(lang, "\t", "bytesRcvdFromRem",
										el->bytesRcvdFromRem,',', numEntries);
	if(checkFilter(filter, &filterPattern, "actualRcvdThpt")) wrtFloatItm(lang, "\t", "actualRcvdThpt",  el->actualRcvdThpt,',', numEntries);
	if(checkFilter(filter, &filterPattern, "lastHourRcvdThpt")) wrtFloatItm(lang, "\t", "lastHourRcvdThpt", el->lastHourRcvdThpt,',', numEntries);
	if(checkFilter(filter, &filterPattern, "averageRcvdThpt")) wrtFloatItm(lang, "\t", "averageRcvdThpt", el->averageRcvdThpt,',', numEntries);
	if(checkFilter(filter, &filterPattern, "peakRcvdThpt")) wrtFloatItm(lang, "\t", "peakRcvdThpt",    el->peakRcvdThpt,',', numEntries);
	if(checkFilter(filter, &filterPattern, "actualSentThpt")) wrtFloatItm(lang, "\t", "actualSentThpt",  el->actualSentThpt,',', numEntries);
	if(checkFilter(filter, &filterPattern, "lastHourSentThpt")) wrtFloatItm(lang, "\t", "lastHourSentThpt", el->lastHourSentThpt,',', numEntries);
	if(checkFilter(filter, &filterPattern, "averageSentThpt")) wrtFloatItm(lang, "\t", "averageSentThpt", el->averageSentThpt,',', numEntries);
	if(checkFilter(filter, &filterPattern, "peakSentThpt")) wrtFloatItm(lang, "\t", "peakSentThpt",    el->peakSentThpt,',', numEntries);
	if(checkFilter(filter, &filterPattern, "actualRcvdPktThpt")) wrtFloatItm(lang, "\t", "actualRcvdPktThpt", el->actualRcvdPktThpt,',', numEntries);
	if(checkFilter(filter, &filterPattern, "averageRcvdPktThpt")) wrtFloatItm(lang, "\t", "averageRcvdPktThpt",el->averageRcvdPktThpt,',', numEntries);
	if(checkFilter(filter, &filterPattern, "peakRcvdPktThpt")) wrtFloatItm(lang, "\t", "peakRcvdPktThpt", el->peakRcvdPktThpt,',', numEntries);
	if(checkFilter(filter, &filterPattern, "actualSentPktThpt")) wrtFloatItm(lang, "\t", "actualSentPktThpt", el->actualSentPktThpt,',', numEntries);
	if(checkFilter(filter, &filterPattern, "averageSentPktThpt")) wrtFloatItm(lang, "\t", "averageSentPktThpt", el->averageSentPktThpt,',', numEntries);
      }

      if(checkFilter(filter, &filterPattern, "ipBytesSent")) wrtLlongItm(lang, "\t", "ipBytesSent", el->ipBytesSent,',', numEntries);
      if(checkFilter(filter, &filterPattern, "ipBytesRcvd")) wrtLlongItm(lang, "\t", "ipBytesRcvd", el->ipBytesRcvd,',', numEntries);

      if(checkFilter(filter, &filterPattern, "tcpBytesSent")) wrtLlongItm(lang, "\t", "tcpBytesSent", el->tcpSentLoc+el->tcpSentRem,',', numEntries);
      if(checkFilter(filter, &filterPattern, "tcpBytesRcvd")) wrtLlongItm(lang, "\t", "tcpBytesRcvd", el->tcpRcvdLoc+el->tcpRcvdFromRem,',', numEntries);

      if(checkFilter(filter, &filterPattern, "udpBytesSent")) wrtLlongItm(lang, "\t", "udpBytesSent", el->udpSentLoc+el->udpSentRem,',', numEntries);
      if(checkFilter(filter, &filterPattern, "udpBytesRcvd")) wrtLlongItm(lang, "\t", "udpBytesRcvd", el->udpRcvdLoc+el->udpRcvdFromRem,',', numEntries);

      if(checkFilter(filter, &filterPattern, "icmpSent")) wrtLlongItm(lang, "\t", "icmpSent",        el->icmpSent,',', numEntries);
      if(checkFilter(filter, &filterPattern, "icmpRcvd")) wrtLlongItm(lang, "\t", "icmpRcvd",    el->icmpRcvd,',', numEntries);


      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "tcpSentRem")) wrtLlongItm(lang, "\t", "tcpSentRem", el->tcpSentRem,',', numEntries);
	if(checkFilter(filter, &filterPattern, "udpSentLoc")) wrtLlongItm(lang, "\t", "udpSentLoc", el->udpSentLoc,',', numEntries);
	if(checkFilter(filter, &filterPattern, "udpSentRem")) wrtLlongItm(lang, "\t", "udpSentRem", el->udpSentRem,',', numEntries);

	if(checkFilter(filter, &filterPattern, "ospfSent")) wrtLlongItm(lang, "\t", "ospfSent",        el->ospfSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "igmpSent")) wrtLlongItm(lang, "\t", "igmpSent",        el->igmpSent,',', numEntries);

	if(checkFilter(filter, &filterPattern, "tcpRcvdLoc")) wrtLlongItm(lang, "\t", "tcpRcvdLoc",el->tcpRcvdLoc,',', numEntries);
	if(checkFilter(filter, &filterPattern, "tcpRcvdFromRem")) wrtLlongItm(lang, "\t", "tcpRcvdFromRem",el->tcpRcvdFromRem,',', numEntries);
	if(checkFilter(filter, &filterPattern, "udpRcvdLoc")) wrtLlongItm(lang, "\t", "udpRcvdLoc",el->udpRcvdLoc,',', numEntries);
	if(checkFilter(filter, &filterPattern, "udpRcvdFromRem")) wrtLlongItm(lang, "\t", "udpRcvdFromRem",el->udpRcvdFromRem,',', numEntries);
	if(checkFilter(filter, &filterPattern, "ospfRcvd")) wrtLlongItm(lang, "\t", "ospfRcvd",    el->ospfRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "igmpRcvd")) wrtLlongItm(lang, "\t", "igmpRcvd",    el->igmpRcvd,',', numEntries);

	/* ***************************** */

	if(checkFilter(filter, &filterPattern, "tcpFragmentsSent")) wrtLlongItm(lang, "\t", "tcpFragmentsSent", el->tcpFragmentsSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "tcpFragmentsRcvd")) wrtLlongItm(lang, "\t", "tcpFragmentsRcvd", el->tcpFragmentsRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "udpFragmentsSent")) wrtLlongItm(lang, "\t", "udpFragmentsSent", el->udpFragmentsSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "udpFragmentsRcvd")) wrtLlongItm(lang, "\t", "udpFragmentsRcvd", el->udpFragmentsRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "icmpFragmentsSent")) wrtLlongItm(lang, "\t", "icmpFragmentsSent", el->icmpFragmentsSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "icmpFragmentsRcvd")) wrtLlongItm(lang, "\t", "icmpFragmentsRcvd", el->icmpFragmentsRcvd,',', numEntries);

	/* ***************************** */

	if(checkFilter(filter, &filterPattern, "stpSent")) wrtLlongItm(lang, "\t", "stpSent",        el->stpSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "stpRcvd")) wrtLlongItm(lang, "\t", "stpRcvd",    el->stpRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "ipxSent")) wrtLlongItm(lang, "\t", "ipxSent",        el->ipxSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "ipxRcvd")) wrtLlongItm(lang, "\t", "ipxRcvd",    el->ipxRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "osiSent")) wrtLlongItm(lang, "\t", "osiSent",        el->osiSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "osiRcvd")) wrtLlongItm(lang, "\t", "osiRcvd",    el->osiRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "dlcSent")) wrtLlongItm(lang, "\t", "dlcSent",        el->dlcSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "dlcRcvd")) wrtLlongItm(lang, "\t", "dlcRcvd",    el->dlcRcvd,',', numEntries);

	if(checkFilter(filter, &filterPattern, "arp_rarpSent")) wrtLlongItm(lang, "\t", "arp_rarpSent",   el->arp_rarpSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "arp_rarpRcvd")) wrtLlongItm(lang, "\t", "arp_rarpRcvd", el->arp_rarpRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "arpReqPktsSent")) wrtLlongItm(lang, "\t", "arpReqPktsSent", el->arpReqPktsSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "arpReplyPktsSent")) wrtLlongItm(lang, "\t", "arpReplyPktsSent", el->arpReplyPktsSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "arpReplyPktsRcvd")) wrtLlongItm(lang, "\t", "arpReplyPktsRcvd", el->arpReplyPktsRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "decnetSent")) wrtLlongItm(lang, "\t", "decnetSent",     el->decnetSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "decnetRcvd")) wrtLlongItm(lang, "\t", "decnetRcvd", el->decnetRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "appletalkSent")) wrtLlongItm(lang, "\t", "appletalkSent",  el->appletalkSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "appletalkRcvd")) wrtLlongItm(lang, "\t", "appletalkRcvd",el->appletalkRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "netbiosSent")) wrtLlongItm(lang, "\t", "netbiosSent",    el->netbiosSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "netbiosRcvd")) wrtLlongItm(lang, "\t", "netbiosRcvd", el->netbiosRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "qnxSent")) wrtLlongItm(lang, "\t", "qnxSent",        el->qnxSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "qnxRcvd")) wrtLlongItm(lang, "\t", "qnxRcvd",    el->qnxRcvd,',', numEntries);
	if(checkFilter(filter, &filterPattern, "otherSent")) wrtLlongItm(lang, "\t", "otherSent",      el->otherSent,',', numEntries);
	if(checkFilter(filter, &filterPattern, "otherRcvd")) wrtLlongItm(lang, "\t", "otherRcvd",  el->otherRcvd,',', numEntries);

	/* ********************************* */

	if(el->routedTraffic && checkFilter(filter, &filterPattern, "RoutingCounter")) {
	  initWriteKey(lang, "\t", "RoutingCounter", numEntries);
	  wrtLlongItm(lang,"\t\t", "routedPkts", el->routedTraffic->routedPkts,',', numEntries);
	  wrtLlongItm(lang,"\t\t", "routedBytes", el->routedTraffic->routedBytes,',', numEntries);
	  endWriteKey(lang,"\t",',');
	}
      } /* shortView */

      if(el->protoIPTrafficInfos && checkFilter(filter, &filterPattern, "IP")) {
	initWriteKey(lang, "\t", "IP", numEntries);

	for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {

	  if(j > 0) { endWriteKey(lang,"\t\t",','); }

	  initWriteKey(lang, "\t\t", myGlobals.protoIPTrafficInfos[j], numEntries);
	  wrtLlongItm(lang,"\t\t\t","sentLoc",
		      el->protoIPTrafficInfos[j].sentLoc,',', numEntries);
	  wrtLlongItm(lang,"\t\t\t","sentRem",
		      el->protoIPTrafficInfos[j].sentRem,',', numEntries);
	  wrtLlongItm(lang,"\t\t\t","rcvdLoc",
		      el->protoIPTrafficInfos[j].rcvdLoc,',', numEntries);
	  wrtLlongItm(lang,"\t\t\t","rcvdFromRem",
		      el->protoIPTrafficInfos[j].rcvdFromRem, ' ', numEntries);
	}
	endWriteKey(lang,"\t\t",',');
	endWriteKey(lang,"\t",',');
      }

      /* ***************************************** */

      if(!shortView) {
	if(el->icmpInfo && checkFilter(filter, &filterPattern, "ICMP")) {
	  initWriteKey(lang, "\t", "ICMP", numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_ECHO",
		      el->icmpInfo->icmpMsgSent[ICMP_ECHO], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_ECHOREPLY",
		      el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_UNREACH",
		      el->icmpInfo->icmpMsgSent[ICMP_UNREACH], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_ROUTERADVERT",
		      el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_TMXCEED",
		      el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_PARAMPROB",
		      el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_MASKREPLY",
		      el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_MASKREQ",
		      el->icmpInfo->icmpMsgSent[ICMP_MASKREQ], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_INFO_REQUEST",
		      el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_INFO_REPLY",
		      el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_TIMESTAMP",
		      el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_TIMESTAMPREPLY",
		      el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","SENT_SOURCE_QUENCH",
		      el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH], ' ', numEntries);

	  /* *********************************************** */

	  wrtUlongItm(lang,"\t\t","RCVD_ECHO",
		      el->icmpInfo->icmpMsgRcvd[ICMP_ECHO], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","RCVD_ECHOREPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","RCVD_UNREACH",
		      el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","RCVD_ROUTERADVERT",
		      el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","RCVD_TMXCEED",
		      el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","RCVD_PARAMPROB",
		      el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","RCVD_MASKREPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","RCVD_MASKREQ",
		      el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","RCVD_INFO_REQUEST",
		      el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","RCVD_INFO_REPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","RCVD_TIMESTAMP",
		      el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","RCVD_TIMESTAMPREPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY], ' ', numEntries);
	  wrtUlongItm(lang,"\t\t","RCVD_SOURCE_QUENCH",
		      el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH], ' ', numEntries);

	  endWriteKey(lang,"\t",',');
	}

	/* ********************************* */

	if(el->secHostPkts && checkFilter(filter, &filterPattern, "securityPkts")) {
	  initWriteKey(lang, "\t", "securityPkts", numEntries);

	  wrtLlongItm(lang,"\t\t","synPktsSent",
		      el->secHostPkts->synPktsSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","synPktsRcvd",
		      el->secHostPkts->synPktsRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","rstPktsSent",
		      el->secHostPkts->rstPktsSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","rstPktsRcvd",
		      el->secHostPkts->rstPktsRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","rstAckPktsSent",
		      el->secHostPkts->rstAckPktsSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","rstAckPktsRcvd",
		      el->secHostPkts->rstAckPktsRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","synFinPktsSent",
		      el->secHostPkts->synFinPktsSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","synFinPktsRcvd",
		      el->secHostPkts->synFinPktsRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","finPushUrgPktsSent",
		      el->secHostPkts->finPushUrgPktsSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","finPushUrgPktsRcvd",
		      el->secHostPkts->finPushUrgPktsRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","nullPktsSent",
		      el->secHostPkts->nullPktsSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","nullPktsRcvd",
		      el->secHostPkts->nullPktsRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","ackScanSent",
		      el->secHostPkts->ackScanSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","ackScanRcvd",
		      el->secHostPkts->ackScanRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","xmasScanSent",
		      el->secHostPkts->xmasScanSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","xmasScanRcvd",
		      el->secHostPkts->xmasScanRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","finScanSent",
		      el->secHostPkts->finScanSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","finScanRcvd",
		      el->secHostPkts->finScanRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","nullScanSent",
		      el->secHostPkts->nullScanSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","nullScanRcvd",
		      el->secHostPkts->nullScanRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","rejectedTCPConnSent",
		      el->secHostPkts->rejectedTCPConnSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","rejectedTCPConnRcvd",
		      el->secHostPkts->rejectedTCPConnRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","establishedTCPConnSent",
		      el->secHostPkts->establishedTCPConnSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","establishedTCPConnRcvd",
		      el->secHostPkts->establishedTCPConnRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","terminatedTCPConnServer",
		      el->secHostPkts->terminatedTCPConnServer.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","terminatedTCPConnClient",
		      el->secHostPkts->terminatedTCPConnClient.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","udpToClosedPortSent",
		      el->secHostPkts->udpToClosedPortSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","udpToClosedPortRcvd",
		      el->secHostPkts->udpToClosedPortRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","udpToDiagnosticPortSent",
		      el->secHostPkts->udpToDiagnosticPortSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","udpToDiagnosticPortRcvd",
		      el->secHostPkts->udpToDiagnosticPortRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","tcpToDiagnosticPortSent",
		      el->secHostPkts->tcpToDiagnosticPortSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","tcpToDiagnosticPortRcvd",
		      el->secHostPkts->tcpToDiagnosticPortRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","tinyFragmentSent",
		      el->secHostPkts->tinyFragmentSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","tinyFragmentRcvd",
		      el->secHostPkts->tinyFragmentRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","icmpFragmentSent",
		      el->secHostPkts->icmpFragmentSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","icmpFragmentRcvd",
		      el->secHostPkts->icmpFragmentRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","overlappingFragmentSent",
		      el->secHostPkts->overlappingFragmentSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","overlappingFragmentRcvd",
		      el->secHostPkts->overlappingFragmentRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","closedEmptyTCPConnSent",
		      el->secHostPkts->closedEmptyTCPConnSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","closedEmptyTCPConnRcvd",
		      el->secHostPkts->closedEmptyTCPConnRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","icmpPortUnreachSent",
		      el->secHostPkts->icmpPortUnreachSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","icmpPortUnreachRcvd",
		      el->secHostPkts->icmpPortUnreachRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","icmpHostNetUnreachSent",
		      el->secHostPkts->icmpHostNetUnreachSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","icmpHostNetUnreachRcvd",
		      el->secHostPkts->icmpHostNetUnreachRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","icmpProtocolUnreachSent",
		      el->secHostPkts->icmpProtocolUnreachSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","icmpProtocolUnreachRcvd",
		      el->secHostPkts->icmpProtocolUnreachRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","icmpAdminProhibitedSent",
		      el->secHostPkts->icmpAdminProhibitedSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","icmpAdminProhibitedRcvd",
		      el->secHostPkts->icmpAdminProhibitedRcvd.value,',', numEntries);

	  wrtLlongItm(lang,"\t\t","malformedPktsSent",
		      el->secHostPkts->malformedPktsSent.value,',', numEntries);
	  wrtLlongItm(lang,"\t\t","malformedPktsRcvd",
		      el->secHostPkts->malformedPktsRcvd.value,',', numEntries);

	  endWriteKey(lang,"\t",',');
	}

	/* ***************************** */

	if(checkFilter(filter, &filterPattern, "ethAddressString"))
	  wrtStrItm(lang, "\t", "ethAddressString",el->ethAddressString, ' ', numEntries);
      } /* shortView */

      numEntries++;
      
      if(numEntries == 1) goto REPEAT_HOSTS;      
    }
  }

  if(numEntries > 0) endWriteKey(lang,"", ' ');

  endWriteArray(lang);

  if((filter[0] != '\0') && (filterPattern.fastmap))
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
    if(((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       &&(broadcastHost(el) == 0)) {
      char *hostKey;

      if(el->hostNumIpAddress[0] != '\0')
	hostKey = el->hostNumIpAddress;
      else
	hostKey = el->ethAddressString;

      wrtIntStrItm( lang, "", idx, hostKey,'\n', numEntries);

      numEntries++;
    }
  }

  endWriteArray(lang);
}

/* ********************************** */

void dumpNtopTrafficInfo(char* options) {
  char intoabuf[32], key[16], localbuf[32], filter[128];
  int lang=DEFAULT_LANGUAGE, i, numEntries;
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

  for(i=0, numEntries=0; i<myGlobals.numDevices; i++) {
    int j;

    if(myGlobals.device[i].virtualDevice) continue;

    if((key[0] != '\0') && (strcmp(key, myGlobals.device[i].name) != 0))
      continue;

  REPEAT:
    if(numEntries > 0) { endWriteKey(lang,"",','); }

    initWriteKey(lang, "", myGlobals.device[i].name, numEntries);

    if(!shortView) {
      if(checkFilter(filter, &filterPattern, "ipdot")) wrtStrItm(lang, "\t", "ipdot", myGlobals.device[i].ipdot,',', numEntries);
      if(checkFilter(filter, &filterPattern, "fqdn")) wrtStrItm(lang, "\t", "fqdn", myGlobals.device[i].fqdn,',', numEntries);

      snprintf(localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].network, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, &filterPattern, "network")) wrtStrItm(lang, "\t", "network", localbuf,',', numEntries);
      snprintf(localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].netmask, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, &filterPattern, "netmask")) wrtStrItm(lang, "\t", "netmask", localbuf,',', numEntries);
      snprintf(localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].ifAddr, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, &filterPattern, "ifAddr")) wrtStrItm(lang, "\t", "ifAddr", localbuf,',', numEntries);

      if(checkFilter(filter, &filterPattern, "started")) wrtTime_tItm(lang, "\t", "started", myGlobals.device[i].started, ' ', numEntries);
      if(checkFilter(filter, &filterPattern, "firstpkt")) wrtTime_tItm(lang, "\t", "firstpkt", myGlobals.device[i].firstpkt, ' ', numEntries);
      if(checkFilter(filter, &filterPattern, "lastpkt")) wrtTime_tItm(lang, "\t", "lastpkt", myGlobals.device[i].lastpkt, ' ', numEntries);
      if(checkFilter(filter, &filterPattern, "virtualDevice")) wrtIntItm(lang, "\t", "virtualDevice",(int)myGlobals.device[i].virtualDevice,',', numEntries);
      if(checkFilter(filter, &filterPattern, "snaplen")) wrtIntItm(lang, "\t", "snaplen", myGlobals.device[i].snaplen,',', numEntries);
      if(checkFilter(filter, &filterPattern, "datalink")) wrtIntItm(lang, "\t", "datalink", myGlobals.device[i].datalink,',', numEntries);
      if(checkFilter(filter, &filterPattern, "filter")) wrtStrItm(lang, "\t", "filter", myGlobals.device[i].filter ? myGlobals.device[i].filter : "",',', numEntries);
      if(checkFilter(filter, &filterPattern, "droppedPkts")) wrtLlongItm(lang, "\t", "droppedPkts",myGlobals.device[i].droppedPkts,',', numEntries);
    }

    if(checkFilter(filter, &filterPattern, "ethernetPkts")) wrtLlongItm(lang, "\t", "ethernetPkts",myGlobals.device[i].ethernetPkts,',', numEntries);
    if(checkFilter(filter, &filterPattern, "broadcastPkts")) wrtLlongItm(lang, "\t", "broadcastPkts",myGlobals.device[i].broadcastPkts,',', numEntries);
    if(checkFilter(filter, &filterPattern, "multicastPkts")) wrtLlongItm(lang, "\t", "multicastPkts",myGlobals.device[i].multicastPkts,',', numEntries);
    if(checkFilter(filter, &filterPattern, "ethernetBytes")) wrtLlongItm(lang, "\t", "ethernetBytes",myGlobals.device[i].ethernetBytes,',', numEntries);
    if(checkFilter(filter, &filterPattern, "ipBytes")) wrtLlongItm(lang, "\t", "ipBytes",myGlobals.device[i].ipBytes,',', numEntries);
    if(!shortView) {
      if(checkFilter(filter, &filterPattern, "fragmentedIpBytes")) wrtLlongItm(lang, "\t", "fragmentedIpBytes",myGlobals.device[i].fragmentedIpBytes,',', numEntries);
    }
    if(checkFilter(filter, &filterPattern, "tcpBytes")) wrtLlongItm(lang, "\t", "tcpBytes",myGlobals.device[i].tcpBytes,',', numEntries);
    if(checkFilter(filter, &filterPattern, "udpBytes")) wrtLlongItm(lang, "\t", "udpBytes",myGlobals.device[i].udpBytes,',', numEntries);
    if(checkFilter(filter, &filterPattern, "otherIpBytes")) wrtLlongItm(lang, "\t", "otherIpBytes",myGlobals.device[i].otherIpBytes,',', numEntries);
    if(checkFilter(filter, &filterPattern, "icmpBytes")) wrtLlongItm(lang, "\t", "icmpBytes",myGlobals.device[i].icmpBytes,',', numEntries);
    if(checkFilter(filter, &filterPattern, "dlcBytes")) wrtLlongItm(lang, "\t", "dlcBytes",myGlobals.device[i].dlcBytes,',', numEntries);
    if(!shortView) {
      if(checkFilter(filter, &filterPattern, "ipxBytes")) wrtLlongItm(lang, "\t", "ipxBytes",myGlobals.device[i].ipxBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "stpBytes")) wrtLlongItm(lang, "\t", "stpBytes",myGlobals.device[i].stpBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "decnetBytes")) wrtLlongItm(lang, "\t", "decnetBytes",myGlobals.device[i].decnetBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "netbiosBytes")) wrtLlongItm(lang, "\t", "netbiosBytes",myGlobals.device[i].netbiosBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "arpRarpBytes")) wrtLlongItm(lang, "\t", "arpRarpBytes",myGlobals.device[i].arpRarpBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "atalkBytes")) wrtLlongItm(lang, "\t", "atalkBytes",myGlobals.device[i].atalkBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "ospfBytes")) wrtLlongItm(lang, "\t", "ospfBytes",myGlobals.device[i].ospfBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "egpBytes")) wrtLlongItm(lang, "\t", "egpBytes",myGlobals.device[i].egpBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "igmpBytes")) wrtLlongItm(lang, "\t", "igmpBytes",myGlobals.device[i].igmpBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "osiBytes")) wrtLlongItm(lang, "\t", "osiBytes",myGlobals.device[i].osiBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "qnxBytes")) wrtLlongItm(lang, "\t", "qnxBytes",myGlobals.device[i].qnxBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "otherBytes")) wrtLlongItm(lang, "\t", "otherBytes",myGlobals.device[i].otherBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastMinEthernetBytes")) wrtLlongItm(lang, "\t", "lastMinEthernetBytes",
										  myGlobals.device[i].lastMinEthernetBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastFiveMinsEthernetBytes")) wrtLlongItm(lang, "\t", "lastFiveMinsEthernetBytes",
										       myGlobals.device[i].lastFiveMinsEthernetBytes,',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastMinEthernetPkts")) wrtLlongItm(lang, "\t", "lastMinEthernetPkts",myGlobals.device[i].lastMinEthernetPkts,',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastFiveMinsEthernetPkts")) wrtLlongItm(lang, "\t", "lastFiveMinsEthernetPkts",
										      myGlobals.device[i].lastFiveMinsEthernetPkts,',', numEntries);
      if(checkFilter(filter, &filterPattern, "upTo64")) wrtLlongItm(lang, "\t", "upTo64",myGlobals.device[i].rcvdPktStats.upTo64,',', numEntries);
      if(checkFilter(filter, &filterPattern, "upTo128")) wrtLlongItm(lang, "\t", "upTo128",myGlobals.device[i].rcvdPktStats.upTo128,',', numEntries);
      if(checkFilter(filter, &filterPattern, "upTo256")) wrtLlongItm(lang, "\t", "upTo256",myGlobals.device[i].rcvdPktStats.upTo256,',', numEntries);
      if(checkFilter(filter, &filterPattern, "upTo512")) wrtLlongItm(lang, "\t", "upTo512",myGlobals.device[i].rcvdPktStats.upTo512,',', numEntries);
      if(checkFilter(filter, &filterPattern, "upTo1024")) wrtLlongItm(lang, "\t", "upTo1024",myGlobals.device[i].rcvdPktStats.upTo1024,',', numEntries);
      if(checkFilter(filter, &filterPattern, "upTo1518")) wrtLlongItm(lang, "\t", "upTo1518",myGlobals.device[i].rcvdPktStats.upTo1518,',', numEntries);
      if(checkFilter(filter, &filterPattern, "above1518")) wrtLlongItm(lang, "\t", "above1518",myGlobals.device[i].rcvdPktStats.above1518,',', numEntries);
      if(checkFilter(filter, &filterPattern, "shortest")) wrtLlongItm(lang, "\t", "shortest",myGlobals.device[i].rcvdPktStats.shortest,',', numEntries);
      if(checkFilter(filter, &filterPattern, "longest")) wrtLlongItm(lang, "\t", "longest",myGlobals.device[i].rcvdPktStats.longest,',', numEntries);
      if(checkFilter(filter, &filterPattern, "badChecksum")) wrtLlongItm(lang, "\t", "badChecksum",myGlobals.device[i].rcvdPktStats.badChecksum,',', numEntries);
      if(checkFilter(filter, &filterPattern, "tooLong")) wrtLlongItm(lang, "\t", "tooLong",myGlobals.device[i].rcvdPktStats.tooLong,',', numEntries);
      if(checkFilter(filter, &filterPattern, "peakThroughput")) wrtFloatItm(lang, "\t", "peakThroughput",myGlobals.device[i].peakThroughput,',', numEntries);
      if(checkFilter(filter, &filterPattern, "actualThpt")) wrtFloatItm(lang, "\t", "actualThpt",myGlobals.device[i].actualThpt,',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastMinThpt")) wrtFloatItm(lang, "\t", "lastMinThpt",myGlobals.device[i].lastMinThpt,',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastFiveMinsThpt")) wrtFloatItm(lang, "\t", "lastFiveMinsThpt",myGlobals.device[i].lastFiveMinsThpt,',', numEntries);
      if(checkFilter(filter, &filterPattern, "peakPacketThroughput")) wrtFloatItm(lang, "\t", "peakPacketThroughput",myGlobals.device[i].peakPacketThroughput,',', numEntries);
      if(checkFilter(filter, &filterPattern, "actualPktsThpt")) wrtFloatItm(lang, "\t", "actualPktsThpt",myGlobals.device[i].actualPktsThpt,',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastMinPktsThpt")) wrtFloatItm(lang, "\t", "lastMinPktsThpt",myGlobals.device[i].lastMinPktsThpt,',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastFiveMinsPktsThpt")) wrtFloatItm(lang, "\t", "lastFiveMinsPktsThpt",myGlobals.device[i].lastFiveMinsPktsThpt,',', numEntries);
      if(checkFilter(filter, &filterPattern, "throughput")) wrtLlongItm(lang, "\t", "throughput", myGlobals.device[i].throughput,',', numEntries);
      if(checkFilter(filter, &filterPattern, "packetThroughput")) wrtFloatItm(lang, "\t", "packetThroughput",myGlobals.device[i].packetThroughput,',', numEntries);

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "last60MinutesThpt")) {
	initWriteKey(lang, "\t", "last60MinutesThpt", numEntries);

	for(j=0; j<59; j++) {
	  wrtIntFloatItm(lang,"\t\t",j+1,myGlobals.device[i].last60MinutesThpt[j].trafficValue,',', numEntries);
	}
	wrtIntFloatItm(lang,"\t\t",j+1, myGlobals.device[i].last60MinutesThpt[j].trafficValue, ' ', numEntries);
	endWriteKey(lang,"\t",',');
      }

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "last24HoursThpt")) {
	initWriteKey(lang, "\t", "last24HoursThpt", numEntries);

	for(j=0; j<23; j++) {
	  wrtIntFloatItm(lang, "\t\t", j+1, myGlobals.device[i].last24HoursThpt[j].trafficValue,',', numEntries);
	}
	wrtIntFloatItm(lang,"\t\t",j+1,myGlobals.device[i].last24HoursThpt[j].trafficValue, ' ', numEntries);
	endWriteKey(lang,"\t",',');
      }
      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "last30daysThpt")) {
	initWriteKey(lang, "\t", "last30daysThpt", numEntries);

	for(j=0; j<29; j++) {
	  wrtIntFloatItm(lang,"\t\t",j+1,myGlobals.device[i].last30daysThpt[j],',', numEntries);
	}
	wrtIntFloatItm(lang,"\t\t",j+1,myGlobals.device[i].last30daysThpt[j], ' ', numEntries);
	endWriteKey(lang,"\t",',');
      }

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "IP")) {
	if(myGlobals.device[i].ipProtoStats != NULL) {
	  initWriteKey(lang, "\t", "IP", numEntries);

	  for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {
	    if(j > 0) endWriteKey(lang, "\t\t",',');
	    initWriteKey(lang, "\t\t", myGlobals.protoIPTrafficInfos[j], numEntries);
	    wrtLlongItm(lang,"\t\t\t","local",
			myGlobals.device[i].ipProtoStats[j].local,',', numEntries);
	    wrtLlongItm(lang,"\t\t\t","local2remote",
			myGlobals.device[i].ipProtoStats[j].local2remote,',', numEntries);
	    wrtLlongItm(lang,"\t\t\t","remote2local",
			myGlobals.device[i].ipProtoStats[j].remote2local,',', numEntries);
	    wrtLlongItm(lang,"\t\t\t","remote",
			myGlobals.device[i].ipProtoStats[j].remote, ' ', numEntries);
	  }
	  endWriteKey(lang,"\t\t",',');
	  endWriteKey(lang,"\t",',');
	}
      }

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "TCPflags")) {
	initWriteKey(lang, "\t", "TCPflags", numEntries);

	wrtLlongItm(lang,"\t\t","numEstablishedTCPConnections",
		    myGlobals.device[i].numEstablishedTCPConnections, ' ', numEntries);

	endWriteKey(lang,"\t",',');
      }

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "tcpLocal")) wrtLlongItm(lang,"\t","tcpLocal",
								      myGlobals.device[i].tcpGlobalTrafficStats.local,',', numEntries);
      if(checkFilter(filter, &filterPattern, "tcpLocal2Rem")) wrtLlongItm(lang,"\t","tcpLocal2Rem",
									  myGlobals.device[i].tcpGlobalTrafficStats.local2remote,',', numEntries);
      if(checkFilter(filter, &filterPattern, "tcpRem")) wrtLlongItm(lang,"\t","tcpRem",
								    myGlobals.device[i].tcpGlobalTrafficStats.remote,',', numEntries);
      if(checkFilter(filter, &filterPattern, "tcpRem2Local")) wrtLlongItm(lang,"\t","tcpRem2Local",
									  myGlobals.device[i].tcpGlobalTrafficStats.remote2local,',', numEntries);

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "udpLocal")) wrtLlongItm(lang,"\t","udpLocal",
								      myGlobals.device[i].udpGlobalTrafficStats.local,',', numEntries);
      if(checkFilter(filter, &filterPattern, "udpLocal2Rem")) wrtLlongItm(lang,"\t","udpLocal2Rem",
									  myGlobals.device[i].udpGlobalTrafficStats.local2remote,',', numEntries);
      if(checkFilter(filter, &filterPattern, "udpRem")) wrtLlongItm(lang,"\t","udpRem",
								    myGlobals.device[i].udpGlobalTrafficStats.remote,',', numEntries);
      if(checkFilter(filter, &filterPattern, "udpRem2Local")) wrtLlongItm(lang,"\t","udpRem2Local",
									  myGlobals.device[i].udpGlobalTrafficStats.remote2local,',', numEntries);

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "icmpLocal")) wrtLlongItm(lang,"\t","icmpLocal",
								       myGlobals.device[i].icmpGlobalTrafficStats.local,',', numEntries);
      if(checkFilter(filter, &filterPattern, "icmpLocal2Rem")) wrtLlongItm(lang,"\t","icmpLocal2Rem",
									   myGlobals.device[i].icmpGlobalTrafficStats.local2remote,',', numEntries);
      if(checkFilter(filter, &filterPattern, "icmpRem")) wrtLlongItm(lang,"\t","icmpRem",
								     myGlobals.device[i].icmpGlobalTrafficStats.remote,',', numEntries);
      if(checkFilter(filter, &filterPattern, "icmpRem2Local")) wrtLlongItm(lang,"\t","icmpRem2Local",
									   myGlobals.device[i].icmpGlobalTrafficStats.remote2local, ' ', numEntries);
    }

    numEntries++;
    if(numEntries == 1) goto REPEAT;
  }

  if(numEntries > 0) endWriteKey(lang,"", ' ');
  endWriteArray(lang);

  if((filter[0] != '\0') && (filterPattern.fastmap))
      free(filterPattern.fastmap);
}


