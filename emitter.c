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
#define XML_LANGUAGE        3
#define NO_LANGUAGE         4
#define NB_LANGUAGES        4
#define DEFAULT_LANGUAGE    NO_LANGUAGE


/*
  This file has been significantly reworked
  by Philippe Bereski <Philippe.Bereski@ms.alcatel.fr>

  Many thanks Philippe!
*/
char *languages[] = { "", "perl", "php", "xml", "no" };

/* *************************** */

void sendEmitterString(FILE *fDescr, char *theString) {

#ifdef DEBUG
  traceEvent(TRACE_INFO, "sendEmitterString(%X, '%s')", fDescr, theString);
#endif

  if(fDescr == NULL)
    sendString(theString);
  else
    fprintf(fDescr, theString);
}

/* *************************** */

void initWriteArray(FILE *fDescr, int lang) {
  
  switch(fDescr, lang) {
  case PERL_LANGUAGE:
    sendEmitterString(fDescr, "%ntopHash =(\n");
    break ;
  case PHP_LANGUAGE:
    sendEmitterString(fDescr, "$ntopHash = array(\n");
    break ;
  case XML_LANGUAGE:
    sendEmitterString(fDescr, "<rpc-reply xmlns:ntop=\"http://www.ntop.org/ntop.dtd\">"
	       "\n<ntop-traffic-information>\n");
    break ;
  case NO_LANGUAGE:
    break ;
  }
}

/* *************************** */

void endWriteArray(FILE *fDescr, int lang) {
  switch(fDescr, lang) {
  case PERL_LANGUAGE:
  case PHP_LANGUAGE:
    sendEmitterString(fDescr, ");\n");
    break ;
  case XML_LANGUAGE:
    sendEmitterString(fDescr, "</ntop-traffic-information>\n</rpc-reply>\n");
    break ;
  case NO_LANGUAGE:
    sendEmitterString(fDescr, "\n");
    break ;
  }
}

/* *************************** */

static void validateString(char *name) {
  int i;

  if(name == NULL) return;
  
  for(i=0; i<strlen(name); i++)
    if(name[i] == '/') {
      name[i] = '_';
    }
}

/* *************************** */

void initWriteKey(FILE *fDescr, int lang, char *indent, 
		  char *keyName, int numEntriesSent) {
  char buf[256];

  if((indent == NULL) ||  (keyName == NULL)) return;

  validateString(keyName);

  switch(lang) {
  case PERL_LANGUAGE:
    if(snprintf(buf, sizeof(buf), "%s'%s' => {\n",indent, keyName) < 0)
      BufferTooShort();
    sendEmitterString(fDescr, buf);
    break ;
  case PHP_LANGUAGE:
    if(snprintf(buf, sizeof(buf), "%s'%s' => array(\n",indent, keyName) < 0)
      BufferTooShort();
    sendEmitterString(fDescr, buf);
    break ;
  case XML_LANGUAGE:
    if(snprintf(buf, sizeof(buf), "%s<%s>\n", indent, keyName) < 0)
      BufferTooShort();
    sendEmitterString(fDescr, buf);
    break ;
  case NO_LANGUAGE:
    if(snprintf(buf, sizeof(buf), "%s|", 
		numEntriesSent == 0 ? "key" : keyName) < 0)
      BufferTooShort();
    sendEmitterString(fDescr, buf);
    break ;
  }
}

/* *************************** */

void endWriteKey(FILE *fDescr, int lang, char *indent, char *keyName, char last) {
  char buf[256];

  /* If there is no indentation, this was the first level of key,
     hence the end of the list. Don't add a ',' at end.
  */

  if((indent == NULL) ||  (keyName == NULL)) return;
  
  validateString(keyName);
  switch(lang) {
  case PERL_LANGUAGE:
    if(snprintf(buf, sizeof(buf),"%s}%c\n",indent,last) < 0)
      BufferTooShort();
    sendEmitterString(fDescr, buf);
    break ;
  case PHP_LANGUAGE:
    if(snprintf(buf, sizeof(buf),"%s)%c\n",indent,last) < 0)
      BufferTooShort();
    sendEmitterString(fDescr, buf);
    break ;
  case XML_LANGUAGE:
    if(snprintf(buf, sizeof(buf), "%s</%s>\n",indent, keyName) < 0)
      BufferTooShort();
    sendEmitterString(fDescr, buf);
    break ;
  case NO_LANGUAGE:
    if(indent == "") sendEmitterString(fDescr, "\n");
    break ;
  }
}

/* *************************** */

void wrtStrItm(FILE *fDescr, int lang, char *indent, char *name, 
	       char *value, char last, int numEntriesSent) {
  char buf[256];

  validateString(name);

  switch(lang) {
  case PERL_LANGUAGE:
  case PHP_LANGUAGE:
    /* In the case of hostNumIpAddress and hostSymIpAddress,
       the pointer is not null, but the string is empty.
       In that case, don't create the key in the array.
    */
    if((value != NULL) && (value[0] != '\0'))  {
      if(snprintf(buf, sizeof(buf), "%s'%s' => '%s'%c\n", indent,name,value,last) < 0)
	BufferTooShort();  sendEmitterString(fDescr, buf);
    }
    break ;
  case XML_LANGUAGE:
    if((value != NULL) && (value[0] != '\0'))  {
      if(snprintf(buf, sizeof(buf), "%s<%s>%s</%s>\n", indent, name, value, name) < 0)
	BufferTooShort();  sendEmitterString(fDescr, buf);
    }
    break ;
  case NO_LANGUAGE:
    if(value != NULL) {
      if(snprintf(buf, sizeof(buf), "%s|", numEntriesSent == 0 ? name : value) < 0)
	BufferTooShort();  sendEmitterString(fDescr, buf);
    } else {
      if(snprintf(buf, sizeof(buf), "%s|", numEntriesSent == 0 ? name : "") < 0)
	BufferTooShort();  sendEmitterString(fDescr, buf);
    }
    break ;
  }
}

/* *************************** */

void wrtIntItm(FILE *fDescr, int lang, char *indent, char *name,
	       int value, char last, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%d",value);
  wrtStrItm(fDescr, lang, indent, name, buf, last, numEntriesSent);
}

/* *************************** */

void wrtIntStrItm(FILE *fDescr, int lang, char *indent,int name, 
		  char *value, char useless, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%d",name);
  wrtStrItm(fDescr, lang, indent, buf, value, ',', numEntriesSent);
}

/* *************************** */

void wrtUintItm(FILE *fDescr, int lang, char *indent, char *name, 
		unsigned int value, char useless, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%d",value);
  wrtStrItm(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

void wrtUcharItm(FILE *fDescr, int lang, char *indent, char *name,
		 u_char value, char useless, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%d",value);
  wrtStrItm(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

void wrtFloatItm(FILE *fDescr, int lang, char *indent, char *name, 
		 float value, char last, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%0.2f",value);
  wrtStrItm(fDescr, lang, indent, name, buf, last, numEntriesSent);
}

/* *************************** */

void wrtIntFloatItm(FILE *fDescr, int lang, char *indent, int name, 
		    float value, char last, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%d", name);
  wrtFloatItm(fDescr, lang, indent, (lang == XML_LANGUAGE) ? "number" : buf, 
	      value, last, numEntriesSent);
}

/* *************************** */

void wrtUlongItm(FILE *fDescr, int lang, char *indent, char *name, 
		 unsigned long value, char useless, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%lu",value);
  wrtStrItm(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

void wrtLlongItm(FILE *fDescr, int lang, char* indent, char* name, 
		 TrafficCounter value, char last, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%llu",value);
  wrtStrItm(fDescr, lang, indent, name, buf, last, numEntriesSent);
}

/* *************************** */

void wrtTime_tItm(FILE *fDescr, int lang, char *indent, char *name, 
		  time_t value, char useless, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%ld",value);
  wrtStrItm(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

void wrtUshortItm(FILE *fDescr, int lang, char *indent, char *name, 
		  u_short value, char useless, int numEntriesSent) {
  char buf[80];
  sprintf(buf,"%d",value);
  wrtStrItm(fDescr, lang, indent, name, buf, ',', numEntriesSent);
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

void dumpNtopHashes(FILE *fDescr, char* options, int actualDeviceId) {
  char key[64], filter[128], *hostKey;
  unsigned int idx, numEntries=0, lang=DEFAULT_LANGUAGE, j, localView=0;
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

      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      /* If argument contains "language=something", then
	 look in the table "languages" of known language for
	 the choosen language.
      */

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcasecmp(tmpStr, "language") == 0) {
	  lang = DEFAULT_LANGUAGE;
	  for(j=1;j <= NB_LANGUAGES;j++) {
	    if(strcasecmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	} else if(strcmp(tmpStr, "key") == 0) {
	  strncpy(key, &tmpStr[i+1], sizeof(key));
	} else if(strcmp(tmpStr, "view") == 0) {
	  if(strcmp(key, "short")) shortView = 1;
	} else if(strcmp(tmpStr, "restrict") == 0) {
	  if(strcmp(key, "local")) localView = 1;
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

  initWriteArray(fDescr, lang);

  for(idx=0; idx<myGlobals.device[actualDeviceId].actualHashSize; idx++) {
    if((idx != myGlobals.otherHostEntryIdx) && 
       ((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) != NULL)) {
      if(key[0] != '\0') {
	if(strcmp(el->hostNumIpAddress, key)
	   && strcmp(el->ethAddressString, key)
	   && strcmp(el->hostSymIpAddress, key))
	  continue;
      }

      if(el->hostNumIpAddress[0] != '\0') {
	hostKey = el->hostNumIpAddress;
	if(localView) {
	  if((!subnetPseudoLocalHost(el) || (el->numUses == 0)))
	    continue;
	}
      } else {
	if(localView) continue;
	hostKey = el->ethAddressString;
      }

    REPEAT_HOSTS:
      if(numEntries > 0)
	endWriteKey(fDescr, lang,"",  (lang == XML_LANGUAGE) ? "host-information" : hostKey, ','); 
      
      initWriteKey(fDescr, lang, "", (lang == XML_LANGUAGE) ? "host-information" : hostKey, numEntries);

      /* ************************ */

      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "index")) wrtUintItm(fDescr, lang, "\t","index", idx, ' ', numEntries);

	if(checkFilter(filter, &filterPattern, "hostNumIpAddress"))
	  wrtStrItm(fDescr, lang, "\t", "hostNumIpAddress", el->hostNumIpAddress, ',', numEntries);
      }

      if(checkFilter(filter, &filterPattern, "hostSymIpAddress"))
	wrtStrItm(fDescr, lang, "\t", "hostSymIpAddress", el->hostSymIpAddress, ',', numEntries);

      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "firstSeen")) wrtTime_tItm(fDescr, lang, "\t", "firstSeen", el->firstSeen, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "lastSeen")) wrtTime_tItm(fDescr, lang, "\t", "lastSeen",  el->lastSeen, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "minTTL")) wrtUshortItm(fDescr, lang, "\t", "minTTL",     el->minTTL, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "maxTTL")) wrtUshortItm(fDescr, lang, "\t", "maxTTL",     el->maxTTL, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "nbHostName")) wrtStrItm(fDescr, lang, "\t", "nbHostName",   el->nbHostName, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "nbDomainName")) wrtStrItm(fDescr, lang, "\t", "nbDomainName", el->nbDomainName, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "nbDescr")) wrtStrItm(fDescr, lang, "\t", "nbDescr",      el->nbDescr, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "nodeType")) wrtUcharItm (fDescr, lang, "\t", "nodeType",  el->nbNodeType, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "atNodeName")) wrtStrItm(fDescr, lang, "\t", "atNodeName",   el->atNodeName, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "atNetwork")) wrtUshortItm(fDescr, lang, "\t", "atNetwork",  el->atNetwork, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "atNode")) wrtUcharItm (fDescr, lang, "\t", "atNode",    el->atNode, ' ', numEntries);
	if(checkFilter(filter, &filterPattern, "ipxHostName")) wrtStrItm(fDescr, lang, "\t", "ipxHostName",  el->ipxHostName, ',', numEntries);
      }

      if(checkFilter(filter, &filterPattern, "pktSent")) wrtLlongItm(fDescr, lang, "\t", "pktSent",   el->pktSent, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "pktRcvd")) wrtLlongItm(fDescr, lang, "\t", "pktRcvd", el->pktRcvd, ',', numEntries);

      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "pktDuplicatedAckSent")) wrtLlongItm(fDescr, lang, "\t", "pktDuplicatedAckSent",el->pktDuplicatedAckSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "pktDuplicatedAckRcvd")) wrtLlongItm(fDescr, lang, "\t", "pktDuplicatedAckRcvd",el->pktDuplicatedAckRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "pktBroadcastSent")) wrtLlongItm(fDescr, lang, "\t", "pktBroadcastSent",  el->pktBroadcastSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "bytesMulticastSent")) wrtLlongItm(fDescr, lang, "\t", "bytesMulticastSent", el->bytesMulticastSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "pktMulticastSent")) wrtLlongItm(fDescr, lang, "\t", "pktMulticastSent",  el->pktMulticastSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "bytesMulticastSent")) wrtLlongItm(fDescr, lang, "\t", "bytesMulticastSent", el->bytesMulticastSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "pktMulticastRcvd")) wrtLlongItm(fDescr, lang, "\t", "pktMulticastRcvd",  el->pktMulticastRcvd, ',', numEntries);
      }

      if(checkFilter(filter, &filterPattern, "bytesSent")) wrtLlongItm(fDescr, lang, "\t", "bytesSent",         el->bytesSent, ',', numEntries);

      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "bytesSentLoc")) wrtLlongItm(fDescr, lang, "\t", "bytesSentLoc",  el->bytesSentLoc, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "bytesSentRem")) wrtLlongItm(fDescr, lang, "\t", "bytesSentRem", el->bytesSentRem, ',', numEntries);
      }

      if(checkFilter(filter, &filterPattern, "bytesRcvd")) wrtLlongItm(fDescr, lang, "\t", "bytesRcvd",     el->bytesRcvd, ',', numEntries);

      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "bytesRcvdLoc")) wrtLlongItm(fDescr, lang, "\t", "bytesRcvdLoc", el->bytesRcvdLoc, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "bytesRcvdFromRem")) wrtLlongItm(fDescr, lang, "\t", "bytesRcvdFromRem",
										el->bytesRcvdFromRem, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "actualRcvdThpt")) wrtFloatItm(fDescr, lang, "\t", "actualRcvdThpt",  el->actualRcvdThpt, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "lastHourRcvdThpt")) wrtFloatItm(fDescr, lang, "\t", "lastHourRcvdThpt", el->lastHourRcvdThpt, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "averageRcvdThpt")) wrtFloatItm(fDescr, lang, "\t", "averageRcvdThpt", el->averageRcvdThpt, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "peakRcvdThpt")) wrtFloatItm(fDescr, lang, "\t", "peakRcvdThpt",    el->peakRcvdThpt, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "actualSentThpt")) wrtFloatItm(fDescr, lang, "\t", "actualSentThpt",  el->actualSentThpt, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "lastHourSentThpt")) wrtFloatItm(fDescr, lang, "\t", "lastHourSentThpt", el->lastHourSentThpt, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "averageSentThpt")) wrtFloatItm(fDescr, lang, "\t", "averageSentThpt", el->averageSentThpt, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "peakSentThpt")) wrtFloatItm(fDescr, lang, "\t", "peakSentThpt",    el->peakSentThpt, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "actualRcvdPktThpt")) wrtFloatItm(fDescr, lang, "\t", "actualRcvdPktThpt", el->actualRcvdPktThpt, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "averageRcvdPktThpt")) wrtFloatItm(fDescr, lang, "\t", "averageRcvdPktThpt",el->averageRcvdPktThpt, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "peakRcvdPktThpt")) wrtFloatItm(fDescr, lang, "\t", "peakRcvdPktThpt", el->peakRcvdPktThpt, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "actualSentPktThpt")) wrtFloatItm(fDescr, lang, "\t", "actualSentPktThpt", el->actualSentPktThpt, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "averageSentPktThpt")) wrtFloatItm(fDescr, lang, "\t", "averageSentPktThpt", el->averageSentPktThpt, ',', numEntries);
      }

      if(checkFilter(filter, &filterPattern, "ipBytesSent")) wrtLlongItm(fDescr, lang, "\t", "ipBytesSent", el->ipBytesSent, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "ipBytesRcvd")) wrtLlongItm(fDescr, lang, "\t", "ipBytesRcvd", el->ipBytesRcvd, ',', numEntries);

      if(checkFilter(filter, &filterPattern, "tcpBytesSent")) wrtLlongItm(fDescr, lang, "\t", "tcpBytesSent", el->tcpSentLoc+el->tcpSentRem, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "tcpBytesRcvd")) wrtLlongItm(fDescr, lang, "\t", "tcpBytesRcvd", el->tcpRcvdLoc+el->tcpRcvdFromRem, ',', numEntries);

      if(checkFilter(filter, &filterPattern, "udpBytesSent")) wrtLlongItm(fDescr, lang, "\t", "udpBytesSent", el->udpSentLoc+el->udpSentRem, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "udpBytesRcvd")) wrtLlongItm(fDescr, lang, "\t", "udpBytesRcvd", el->udpRcvdLoc+el->udpRcvdFromRem, ',', numEntries);

      if(checkFilter(filter, &filterPattern, "icmpSent")) wrtLlongItm(fDescr, lang, "\t", "icmpSent",        el->icmpSent, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "icmpRcvd")) wrtLlongItm(fDescr, lang, "\t", "icmpRcvd",    el->icmpRcvd, ',', numEntries);


      if(!shortView) {
	if(checkFilter(filter, &filterPattern, "tcpSentRem")) wrtLlongItm(fDescr, lang, "\t", "tcpSentRem", el->tcpSentRem, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "udpSentLoc")) wrtLlongItm(fDescr, lang, "\t", "udpSentLoc", el->udpSentLoc, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "udpSentRem")) wrtLlongItm(fDescr, lang, "\t", "udpSentRem", el->udpSentRem, ',', numEntries);

	if(checkFilter(filter, &filterPattern, "ospfSent")) wrtLlongItm(fDescr, lang, "\t", "ospfSent",        el->ospfSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "igmpSent")) wrtLlongItm(fDescr, lang, "\t", "igmpSent",        el->igmpSent, ',', numEntries);

	if(checkFilter(filter, &filterPattern, "tcpRcvdLoc")) wrtLlongItm(fDescr, lang, "\t", "tcpRcvdLoc",el->tcpRcvdLoc, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "tcpRcvdFromRem")) wrtLlongItm(fDescr, lang, "\t", "tcpRcvdFromRem",el->tcpRcvdFromRem, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "udpRcvdLoc")) wrtLlongItm(fDescr, lang, "\t", "udpRcvdLoc",el->udpRcvdLoc, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "udpRcvdFromRem")) wrtLlongItm(fDescr, lang, "\t", "udpRcvdFromRem",el->udpRcvdFromRem, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "ospfRcvd")) wrtLlongItm(fDescr, lang, "\t", "ospfRcvd",    el->ospfRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "igmpRcvd")) wrtLlongItm(fDescr, lang, "\t", "igmpRcvd",    el->igmpRcvd, ',', numEntries);

	/* ***************************** */

	if(checkFilter(filter, &filterPattern, "tcpFragmentsSent")) wrtLlongItm(fDescr, lang, "\t", "tcpFragmentsSent", el->tcpFragmentsSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "tcpFragmentsRcvd")) wrtLlongItm(fDescr, lang, "\t", "tcpFragmentsRcvd", el->tcpFragmentsRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "udpFragmentsSent")) wrtLlongItm(fDescr, lang, "\t", "udpFragmentsSent", el->udpFragmentsSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "udpFragmentsRcvd")) wrtLlongItm(fDescr, lang, "\t", "udpFragmentsRcvd", el->udpFragmentsRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "icmpFragmentsSent")) wrtLlongItm(fDescr, lang, "\t", "icmpFragmentsSent", el->icmpFragmentsSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "icmpFragmentsRcvd")) wrtLlongItm(fDescr, lang, "\t", "icmpFragmentsRcvd", el->icmpFragmentsRcvd, ',', numEntries);

	/* ***************************** */

	if(checkFilter(filter, &filterPattern, "stpSent")) wrtLlongItm(fDescr, lang, "\t", "stpSent",        el->stpSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "stpRcvd")) wrtLlongItm(fDescr, lang, "\t", "stpRcvd",    el->stpRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "ipxSent")) wrtLlongItm(fDescr, lang, "\t", "ipxSent",        el->ipxSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "ipxRcvd")) wrtLlongItm(fDescr, lang, "\t", "ipxRcvd",    el->ipxRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "osiSent")) wrtLlongItm(fDescr, lang, "\t", "osiSent",        el->osiSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "osiRcvd")) wrtLlongItm(fDescr, lang, "\t", "osiRcvd",    el->osiRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "dlcSent")) wrtLlongItm(fDescr, lang, "\t", "dlcSent",        el->dlcSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "dlcRcvd")) wrtLlongItm(fDescr, lang, "\t", "dlcRcvd",    el->dlcRcvd, ',', numEntries);

	if(checkFilter(filter, &filterPattern, "arp_rarpSent")) wrtLlongItm(fDescr, lang, "\t", "arp_rarpSent",   el->arp_rarpSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "arp_rarpRcvd")) wrtLlongItm(fDescr, lang, "\t", "arp_rarpRcvd", el->arp_rarpRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "arpReqPktsSent")) wrtLlongItm(fDescr, lang, "\t", "arpReqPktsSent", el->arpReqPktsSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "arpReplyPktsSent")) wrtLlongItm(fDescr, lang, "\t", "arpReplyPktsSent", el->arpReplyPktsSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "arpReplyPktsRcvd")) wrtLlongItm(fDescr, lang, "\t", "arpReplyPktsRcvd", el->arpReplyPktsRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "decnetSent")) wrtLlongItm(fDescr, lang, "\t", "decnetSent",     el->decnetSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "decnetRcvd")) wrtLlongItm(fDescr, lang, "\t", "decnetRcvd", el->decnetRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "appletalkSent")) wrtLlongItm(fDescr, lang, "\t", "appletalkSent",  el->appletalkSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "appletalkRcvd")) wrtLlongItm(fDescr, lang, "\t", "appletalkRcvd",el->appletalkRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "netbiosSent")) wrtLlongItm(fDescr, lang, "\t", "netbiosSent",    el->netbiosSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "netbiosRcvd")) wrtLlongItm(fDescr, lang, "\t", "netbiosRcvd", el->netbiosRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "qnxSent")) wrtLlongItm(fDescr, lang, "\t", "qnxSent",        el->qnxSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "qnxRcvd")) wrtLlongItm(fDescr, lang, "\t", "qnxRcvd",    el->qnxRcvd, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "otherSent")) wrtLlongItm(fDescr, lang, "\t", "otherSent",      el->otherSent, ',', numEntries);
	if(checkFilter(filter, &filterPattern, "otherRcvd")) wrtLlongItm(fDescr, lang, "\t", "otherRcvd",  el->otherRcvd, ',', numEntries);

	/* ********************************* */

	if(el->routedTraffic && checkFilter(filter, &filterPattern, "RoutingCounter")) {
	  initWriteKey(fDescr, lang, "\t", "RoutingCounter", numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t", "routedPkts", el->routedTraffic->routedPkts, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t", "routedBytes", el->routedTraffic->routedBytes, ',', numEntries);
	  endWriteKey(fDescr, lang,"\t", "RoutingCounter", ',');
	}
      } /* shortView */

      if(shortView || (el->protoIPTrafficInfos && checkFilter(filter, &filterPattern, "IP"))) {
	char *lastKey = NULL;

	if(!shortView) { initWriteKey(fDescr, lang, "\t", "IP", numEntries); }

	for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {
	  if(!shortView) {
	    if(j > 0) { endWriteKey(fDescr, lang,"\t\t", lastKey, ','); }
	    
	    initWriteKey(fDescr, lang, "\t\t", (lastKey = myGlobals.protoIPTrafficInfos[j]), numEntries);
	    wrtLlongItm(fDescr, lang,"\t\t\t","sentLoc",
			el->protoIPTrafficInfos[j].sentLoc, ',', numEntries);
	    wrtLlongItm(fDescr, lang,"\t\t\t","sentRem",
			el->protoIPTrafficInfos[j].sentRem, ',', numEntries);
	    wrtLlongItm(fDescr, lang,"\t\t\t","rcvdLoc",
			el->protoIPTrafficInfos[j].rcvdLoc, ',', numEntries);
	    wrtLlongItm(fDescr, lang,"\t\t\t","rcvdFromRem",
			el->protoIPTrafficInfos[j].rcvdFromRem, ' ', numEntries);	    
	  } else {
	    char keyName[64];

	    sprintf(keyName, "%sSent", myGlobals.protoIPTrafficInfos[j]);
	    wrtLlongItm(fDescr, lang, "\t\t", keyName,
			(el->protoIPTrafficInfos == NULL) ? 0 : 
			(el->protoIPTrafficInfos[j].sentLoc+el->protoIPTrafficInfos[j].sentRem), 
			',', numEntries);

	    sprintf(keyName, "%sRcvd", myGlobals.protoIPTrafficInfos[j]);
	    wrtLlongItm(fDescr, lang,"\t\t", keyName,
			(el->protoIPTrafficInfos == NULL) ? 0 : 
			(el->protoIPTrafficInfos[j].rcvdLoc+el->protoIPTrafficInfos[j].rcvdFromRem), 
			',', numEntries);	    
	  }
	} /* for */

	if(!shortView) {
	  if(lastKey != NULL) { endWriteKey(fDescr, lang,"\t\t", lastKey, ','); }
	  endWriteKey(fDescr, lang,"\t", "IP", ',');
	}
      }

      /* ***************************************** */

    if(!shortView) {
	if(el->icmpInfo && checkFilter(filter, &filterPattern, "ICMP")) {
	  initWriteKey(fDescr, lang, "\t", "ICMP", numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_ECHO",
		      el->icmpInfo->icmpMsgSent[ICMP_ECHO], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_ECHOREPLY",
		      el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_UNREACH",
		      el->icmpInfo->icmpMsgSent[ICMP_UNREACH], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_ROUTERADVERT",
		      el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_TMXCEED",
		      el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_PARAMPROB",
		      el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_MASKREPLY",
		      el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_MASKREQ",
		      el->icmpInfo->icmpMsgSent[ICMP_MASKREQ], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_INFO_REQUEST",
		      el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_INFO_REPLY",
		      el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_TIMESTAMP",
		      el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_TIMESTAMPREPLY",
		      el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","SENT_SOURCE_QUENCH",
		      el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH], ' ', numEntries);

	  /* *********************************************** */

	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_ECHO",
		      el->icmpInfo->icmpMsgRcvd[ICMP_ECHO], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_ECHOREPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_UNREACH",
		      el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_ROUTERADVERT",
		      el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_TMXCEED",
		      el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_PARAMPROB",
		      el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_MASKREPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_MASKREQ",
		      el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_INFO_REQUEST",
		      el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_INFO_REPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_TIMESTAMP",
		      el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_TIMESTAMPREPLY",
		      el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY], ' ', numEntries);
	  wrtUlongItm(fDescr, lang,"\t\t","RCVD_SOURCE_QUENCH",
		      el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH], ' ', numEntries);

	  endWriteKey(fDescr, lang,"\t", "ICMP", ',');
	}

	/* ********************************* */

	if(el->secHostPkts && checkFilter(filter, &filterPattern, "securityPkts")) {
	  initWriteKey(fDescr, lang, "\t", "securityPkts", numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","synPktsSent",
		      el->secHostPkts->synPktsSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","synPktsRcvd",
		      el->secHostPkts->synPktsRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","rstPktsSent",
		      el->secHostPkts->rstPktsSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","rstPktsRcvd",
		      el->secHostPkts->rstPktsRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","rstAckPktsSent",
		      el->secHostPkts->rstAckPktsSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","rstAckPktsRcvd",
		      el->secHostPkts->rstAckPktsRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","synFinPktsSent",
		      el->secHostPkts->synFinPktsSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","synFinPktsRcvd",
		      el->secHostPkts->synFinPktsRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","finPushUrgPktsSent",
		      el->secHostPkts->finPushUrgPktsSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","finPushUrgPktsRcvd",
		      el->secHostPkts->finPushUrgPktsRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","nullPktsSent",
		      el->secHostPkts->nullPktsSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","nullPktsRcvd",
		      el->secHostPkts->nullPktsRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","ackScanSent",
		      el->secHostPkts->ackScanSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","ackScanRcvd",
		      el->secHostPkts->ackScanRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","xmasScanSent",
		      el->secHostPkts->xmasScanSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","xmasScanRcvd",
		      el->secHostPkts->xmasScanRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","finScanSent",
		      el->secHostPkts->finScanSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","finScanRcvd",
		      el->secHostPkts->finScanRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","nullScanSent",
		      el->secHostPkts->nullScanSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","nullScanRcvd",
		      el->secHostPkts->nullScanRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","rejectedTCPConnSent",
		      el->secHostPkts->rejectedTCPConnSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","rejectedTCPConnRcvd",
		      el->secHostPkts->rejectedTCPConnRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","establishedTCPConnSent",
		      el->secHostPkts->establishedTCPConnSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","establishedTCPConnRcvd",
		      el->secHostPkts->establishedTCPConnRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","terminatedTCPConnServer",
		      el->secHostPkts->terminatedTCPConnServer.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","terminatedTCPConnClient",
		      el->secHostPkts->terminatedTCPConnClient.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","udpToClosedPortSent",
		      el->secHostPkts->udpToClosedPortSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","udpToClosedPortRcvd",
		      el->secHostPkts->udpToClosedPortRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","udpToDiagnosticPortSent",
		      el->secHostPkts->udpToDiagnosticPortSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","udpToDiagnosticPortRcvd",
		      el->secHostPkts->udpToDiagnosticPortRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","tcpToDiagnosticPortSent",
		      el->secHostPkts->tcpToDiagnosticPortSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","tcpToDiagnosticPortRcvd",
		      el->secHostPkts->tcpToDiagnosticPortRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","tinyFragmentSent",
		      el->secHostPkts->tinyFragmentSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","tinyFragmentRcvd",
		      el->secHostPkts->tinyFragmentRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","icmpFragmentSent",
		      el->secHostPkts->icmpFragmentSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","icmpFragmentRcvd",
		      el->secHostPkts->icmpFragmentRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","overlappingFragmentSent",
		      el->secHostPkts->overlappingFragmentSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","overlappingFragmentRcvd",
		      el->secHostPkts->overlappingFragmentRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","closedEmptyTCPConnSent",
		      el->secHostPkts->closedEmptyTCPConnSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","closedEmptyTCPConnRcvd",
		      el->secHostPkts->closedEmptyTCPConnRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","icmpPortUnreachSent",
		      el->secHostPkts->icmpPortUnreachSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","icmpPortUnreachRcvd",
		      el->secHostPkts->icmpPortUnreachRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","icmpHostNetUnreachSent",
		      el->secHostPkts->icmpHostNetUnreachSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","icmpHostNetUnreachRcvd",
		      el->secHostPkts->icmpHostNetUnreachRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","icmpProtocolUnreachSent",
		      el->secHostPkts->icmpProtocolUnreachSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","icmpProtocolUnreachRcvd",
		      el->secHostPkts->icmpProtocolUnreachRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","icmpAdminProhibitedSent",
		      el->secHostPkts->icmpAdminProhibitedSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","icmpAdminProhibitedRcvd",
		      el->secHostPkts->icmpAdminProhibitedRcvd.value, ',', numEntries);

	  wrtLlongItm(fDescr, lang,"\t\t","malformedPktsSent",
		      el->secHostPkts->malformedPktsSent.value, ',', numEntries);
	  wrtLlongItm(fDescr, lang,"\t\t","malformedPktsRcvd",
		      el->secHostPkts->malformedPktsRcvd.value, ',', numEntries);

	  endWriteKey(fDescr, lang,"\t", "securityPkts", ',');
	}

	/* ***************************** */

	if(checkFilter(filter, &filterPattern, "ethAddressString"))
	  wrtStrItm(fDescr, lang, "\t", "ethAddressString",el->ethAddressString, ' ', numEntries);
      } /* shortView */

      numEntries++;

      if((lang == NO_LANGUAGE) && (numEntries == 1)) goto REPEAT_HOSTS;
    }
  }

  if(numEntries > 0) endWriteKey(fDescr, lang,"", (lang == XML_LANGUAGE) ? "host-information" : hostKey, ' ');

  endWriteArray(fDescr, lang);

  if((filter[0] != '\0') && filterPattern.fastmap)
    free(filterPattern.fastmap);
}

/* ********************************** */

void dumpNtopHashIndexes(FILE *fDescr, char* options, int actualDeviceId) {
  unsigned int idx, numEntries=0, lang=DEFAULT_LANGUAGE;
  HostTraffic *el;

  if(options != NULL) {
    /* language=[perl|php] */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0; int j;

      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcmp(tmpStr, "language") == 0) {

	  lang = DEFAULT_LANGUAGE;
	  for(j=1;j <= NB_LANGUAGES;j++) {
	    if(strcmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }

  initWriteArray(fDescr, lang);

  for(idx=1; idx<myGlobals.device[actualDeviceId].actualHashSize; idx++) {
    if(((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && (broadcastHost(el) == 0)) {
      char *hostKey;

      if(el->hostNumIpAddress[0] != '\0')
	hostKey = el->hostNumIpAddress;
      else
	hostKey = el->ethAddressString;

      wrtIntStrItm(fDescr, lang, "", idx, hostKey,'\n', numEntries);

      numEntries++;
    }
  }

  endWriteArray(fDescr, lang);
}

/* ********************************** */

void dumpNtopTrafficInfo(FILE *fDescr, char* options) {
  char intoabuf[32], key[16], localbuf[32], filter[128], *keyName;
  int lang=DEFAULT_LANGUAGE, i, numEntries, localView=0;
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

      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcmp(tmpStr, "language") == 0) {
	  lang = DEFAULT_LANGUAGE;
	  for(j=1;j <= NB_LANGUAGES;j++) {
	    if(strcmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	} else if(strcmp(tmpStr, "key") == 0) {
	  strncpy(key, &tmpStr[i+1], sizeof(key));
	} else if(strcmp(tmpStr, "view") == 0) {
	  if(strcmp(key, "short")) shortView = 1;
	} else if(strcmp(tmpStr, "restrict") == 0) {
	  if(strcmp(key, "local")) localView = 1; /* not yet used */
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

  initWriteArray(fDescr, lang);

  for(i=0, numEntries=0; i<myGlobals.numDevices; i++) {
    int j;

    if(myGlobals.device[i].virtualDevice) continue;

    if((key[0] != '\0') && (strcmp(key, myGlobals.device[i].name) != 0))
      continue;

  REPEAT:
    if(numEntries > 0) { endWriteKey(fDescr, lang,"", (lang == XML_LANGUAGE) ? "device-information" : keyName, ','); }

    keyName = myGlobals.device[i].name;
    
    initWriteKey(fDescr, lang, "", (lang == XML_LANGUAGE) ? "device-information" : keyName, numEntries);

    wrtStrItm(fDescr, lang, "\t", "name", myGlobals.device[i].name, ',', numEntries);

    if(!shortView) {
      if(checkFilter(filter, &filterPattern, "ipdot")) 
	wrtStrItm(fDescr, lang, "\t", "ipdot", myGlobals.device[i].ipdot, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "fqdn")) 
	wrtStrItm(fDescr, lang, "\t", "fqdn", myGlobals.device[i].fqdn, ',', numEntries);

      snprintf(localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].network, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, &filterPattern, "network")) 
	wrtStrItm(fDescr, lang, "\t", "network", localbuf, ',', numEntries);
      snprintf(localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].netmask, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, &filterPattern, "netmask")) 
	wrtStrItm(fDescr, lang, "\t", "netmask", localbuf, ',', numEntries);
      snprintf(localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].ifAddr, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, &filterPattern, "ifAddr"))
	wrtStrItm(fDescr, lang, "\t", "ifAddr", localbuf, ',', numEntries);

      if(checkFilter(filter, &filterPattern, "started")) 
	wrtTime_tItm(fDescr, lang, "\t", "started", myGlobals.device[i].started, ' ', numEntries);
      if(checkFilter(filter, &filterPattern, "firstpkt"))
	wrtTime_tItm(fDescr, lang, "\t", "firstpkt", myGlobals.device[i].firstpkt, ' ', numEntries);
      if(checkFilter(filter, &filterPattern, "lastpkt"))
	wrtTime_tItm(fDescr, lang, "\t", "lastpkt", myGlobals.device[i].lastpkt, ' ', numEntries);
      if(checkFilter(filter, &filterPattern, "virtualDevice")) 
	wrtIntItm(fDescr, lang, "\t", "virtualDevice",(int)myGlobals.device[i].virtualDevice, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "snaplen"))
	wrtIntItm(fDescr, lang, "\t", "snaplen", myGlobals.device[i].snaplen, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "datalink")) 
	wrtIntItm(fDescr, lang, "\t", "datalink", myGlobals.device[i].datalink, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "filter")) 
	wrtStrItm(fDescr, lang, "\t", "filter", myGlobals.device[i].filter ? myGlobals.device[i].filter : "", ',', numEntries);
      if(checkFilter(filter, &filterPattern, "droppedPkts")) 
	wrtLlongItm(fDescr, lang, "\t", "droppedPkts",myGlobals.device[i].droppedPkts, ',', numEntries);
    }

    if(checkFilter(filter, &filterPattern, "ethernetPkts")) 
      wrtLlongItm(fDescr, lang, "\t", "ethernetPkts",myGlobals.device[i].ethernetPkts, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "broadcastPkts"))
      wrtLlongItm(fDescr, lang, "\t", "broadcastPkts",myGlobals.device[i].broadcastPkts, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "multicastPkts")) 
      wrtLlongItm(fDescr, lang, "\t", "multicastPkts",myGlobals.device[i].multicastPkts, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "ethernetBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "ethernetBytes",myGlobals.device[i].ethernetBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "ipBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "ipBytes",myGlobals.device[i].ipBytes, ',', numEntries);

    if(!shortView) {
      if(checkFilter(filter, &filterPattern, "fragmentedIpBytes")) 
	wrtLlongItm(fDescr, lang, "\t", "fragmentedIpBytes",myGlobals.device[i].fragmentedIpBytes, ',', numEntries);
    }

    if(checkFilter(filter, &filterPattern, "tcpBytes"))
      wrtLlongItm(fDescr, lang, "\t", "tcpBytes",myGlobals.device[i].tcpBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "udpBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "udpBytes",myGlobals.device[i].udpBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "otherIpBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "otherIpBytes",myGlobals.device[i].otherIpBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "icmpBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "icmpBytes",myGlobals.device[i].icmpBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "dlcBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "dlcBytes",myGlobals.device[i].dlcBytes, ',', numEntries);

    if(checkFilter(filter, &filterPattern, "ipxBytes"))
      wrtLlongItm(fDescr, lang, "\t", "ipxBytes",myGlobals.device[i].ipxBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "stpBytes"))
      wrtLlongItm(fDescr, lang, "\t", "stpBytes",myGlobals.device[i].stpBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "decnetBytes"))
      wrtLlongItm(fDescr, lang, "\t", "decnetBytes",myGlobals.device[i].decnetBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "netbiosBytes"))
      wrtLlongItm(fDescr, lang, "\t", "netbiosBytes",myGlobals.device[i].netbiosBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "arpRarpBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "arpRarpBytes",myGlobals.device[i].arpRarpBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "atalkBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "atalkBytes",myGlobals.device[i].atalkBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "ospfBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "ospfBytes",myGlobals.device[i].ospfBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "egpBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "egpBytes",myGlobals.device[i].egpBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "igmpBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "igmpBytes",myGlobals.device[i].igmpBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "osiBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "osiBytes",myGlobals.device[i].osiBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "qnxBytes")) 
      wrtLlongItm(fDescr, lang, "\t", "qnxBytes",myGlobals.device[i].qnxBytes, ',', numEntries);
    if(checkFilter(filter, &filterPattern, "otherBytes"))
      wrtLlongItm(fDescr, lang, "\t", "otherBytes",myGlobals.device[i].otherBytes, ',', numEntries);

    if(!shortView) {
      if(checkFilter(filter, &filterPattern, "lastMinEthernetBytes"))
	wrtLlongItm(fDescr, lang, "\t", "lastMinEthernetBytes",
		    myGlobals.device[i].lastMinEthernetBytes, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastFiveMinsEthernetBytes"))
	wrtLlongItm(fDescr, lang, "\t", "lastFiveMinsEthernetBytes",
		    myGlobals.device[i].lastFiveMinsEthernetBytes, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastMinEthernetPkts")) 
	wrtLlongItm(fDescr, lang, "\t", "lastMinEthernetPkts",myGlobals.device[i].lastMinEthernetPkts, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastFiveMinsEthernetPkts")) 
	wrtLlongItm(fDescr, lang, "\t", "lastFiveMinsEthernetPkts",
		    myGlobals.device[i].lastFiveMinsEthernetPkts, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "upTo64")) 
	wrtLlongItm(fDescr, lang, "\t", "upTo64",myGlobals.device[i].rcvdPktStats.upTo64, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "upTo128"))
	wrtLlongItm(fDescr, lang, "\t", "upTo128",myGlobals.device[i].rcvdPktStats.upTo128, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "upTo256")) 
	wrtLlongItm(fDescr, lang, "\t", "upTo256",myGlobals.device[i].rcvdPktStats.upTo256, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "upTo512")) 
	wrtLlongItm(fDescr, lang, "\t", "upTo512",myGlobals.device[i].rcvdPktStats.upTo512, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "upTo1024"))
	wrtLlongItm(fDescr, lang, "\t", "upTo1024",myGlobals.device[i].rcvdPktStats.upTo1024, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "upTo1518"))
	wrtLlongItm(fDescr, lang, "\t", "upTo1518",myGlobals.device[i].rcvdPktStats.upTo1518, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "above1518"))
	wrtLlongItm(fDescr, lang, "\t", "above1518",myGlobals.device[i].rcvdPktStats.above1518, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "shortest"))
	wrtLlongItm(fDescr, lang, "\t", "shortest",myGlobals.device[i].rcvdPktStats.shortest, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "longest")) 
	wrtLlongItm(fDescr, lang, "\t", "longest",myGlobals.device[i].rcvdPktStats.longest, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "badChecksum")) 
	wrtLlongItm(fDescr, lang, "\t", "badChecksum",myGlobals.device[i].rcvdPktStats.badChecksum, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "tooLong")) 
	wrtLlongItm(fDescr, lang, "\t", "tooLong",myGlobals.device[i].rcvdPktStats.tooLong, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "peakThroughput")) 
	wrtFloatItm(fDescr, lang, "\t", "peakThroughput",myGlobals.device[i].peakThroughput, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "actualThpt")) 
	wrtFloatItm(fDescr, lang, "\t", "actualThpt",myGlobals.device[i].actualThpt, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastMinThpt")) 
	wrtFloatItm(fDescr, lang, "\t", "lastMinThpt",myGlobals.device[i].lastMinThpt, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastFiveMinsThpt"))
	wrtFloatItm(fDescr, lang, "\t", "lastFiveMinsThpt",myGlobals.device[i].lastFiveMinsThpt, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "peakPacketThroughput")) 
	wrtFloatItm(fDescr, lang, "\t", "peakPacketThroughput",myGlobals.device[i].peakPacketThroughput, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "actualPktsThpt")) 
	wrtFloatItm(fDescr, lang, "\t", "actualPktsThpt",myGlobals.device[i].actualPktsThpt, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastMinPktsThpt"))
	wrtFloatItm(fDescr, lang, "\t", "lastMinPktsThpt",myGlobals.device[i].lastMinPktsThpt, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "lastFiveMinsPktsThpt")) 
	wrtFloatItm(fDescr, lang, "\t", "lastFiveMinsPktsThpt",myGlobals.device[i].lastFiveMinsPktsThpt, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "throughput")) 
	wrtLlongItm(fDescr, lang, "\t", "throughput", myGlobals.device[i].throughput, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "packetThroughput"))
	wrtFloatItm(fDescr, lang, "\t", "packetThroughput",myGlobals.device[i].packetThroughput, ',', numEntries);

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "last60MinutesThpt")) {
	initWriteKey(fDescr, lang, "\t", "last60MinutesThpt", numEntries);

	for(j=0; j<59; j++) {
	  wrtIntFloatItm(fDescr, lang,"\t\t",j+1, myGlobals.device[i].last60MinutesThpt[j].trafficValue, ',', numEntries);
	}
	wrtIntFloatItm(fDescr, lang,"\t\t",j+1, myGlobals.device[i].last60MinutesThpt[j].trafficValue, ' ', numEntries);
	endWriteKey(fDescr, lang,"\t", "last60MinutesThpt", ',');
      }

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "last24HoursThpt")) {
	initWriteKey(fDescr, lang, "\t", "last24HoursThpt", numEntries);

	for(j=0; j<23; j++) {
	  wrtIntFloatItm(fDescr, lang, "\t\t", j+1, myGlobals.device[i].last24HoursThpt[j].trafficValue, ',', numEntries);
	}
	wrtIntFloatItm(fDescr, lang,"\t\t",j+1,myGlobals.device[i].last24HoursThpt[j].trafficValue, ' ', numEntries);
	endWriteKey(fDescr, lang,"\t", "last24HoursThpt", ',');
      }
      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "last30daysThpt")) {
	initWriteKey(fDescr, lang, "\t", "last30daysThpt", numEntries);

	for(j=0; j<29; j++) {
	  wrtIntFloatItm(fDescr, lang,"\t\t",j+1,myGlobals.device[i].last30daysThpt[j], ',', numEntries);
	}
	wrtIntFloatItm(fDescr, lang,"\t\t",j+1,myGlobals.device[i].last30daysThpt[j], ' ', numEntries);
	endWriteKey(fDescr, lang,"\t", "last30daysThpt", ',');
      }
    }

    /* ********************************* */

    if(checkFilter(filter, &filterPattern, "IP")) {
      char *hostKey = NULL;

      if(myGlobals.device[i].ipProtoStats != NULL) {
	if(!shortView) { initWriteKey(fDescr, lang, "\t", "IP", numEntries); }

	for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {
	  if(!shortView) {
	    if(j > 0) endWriteKey(fDescr, lang, "\t\t", hostKey, ',');
	    initWriteKey(fDescr, lang, "\t\t", (hostKey = myGlobals.protoIPTrafficInfos[j]), numEntries);
	    wrtLlongItm(fDescr, lang,"\t\t\t","local",
			myGlobals.device[i].ipProtoStats[j].local, ',', numEntries);
	    wrtLlongItm(fDescr, lang,"\t\t\t","local2remote",
			myGlobals.device[i].ipProtoStats[j].local2remote, ',', numEntries);
	    wrtLlongItm(fDescr, lang,"\t\t\t","remote2local",
			myGlobals.device[i].ipProtoStats[j].remote2local, ',', numEntries);
	    wrtLlongItm(fDescr, lang,"\t\t\t","remote",
			myGlobals.device[i].ipProtoStats[j].remote, ' ', numEntries);
	  } else {
	    wrtLlongItm(fDescr, lang, "\t",  myGlobals.protoIPTrafficInfos[j],
			myGlobals.device[i].ipProtoStats[j].local+
			myGlobals.device[i].ipProtoStats[j].local2remote+
			myGlobals.device[i].ipProtoStats[j].remote2local+
			myGlobals.device[i].ipProtoStats[j].remote,
			',', numEntries);
	  }
	}

	
	if(!shortView) { 
	  if(hostKey != NULL) endWriteKey(fDescr, lang,"\t\t", hostKey, ',');
	  endWriteKey(fDescr, lang,"\t", "IP", ','); 
	}
      }
    }

    /* ********************************* */

    if(!shortView) {
      if(checkFilter(filter, &filterPattern, "TCPflags")) {
	initWriteKey(fDescr, lang, "\t", "TCPflags", numEntries);

	wrtLlongItm(fDescr, lang,"\t\t","numEstablishedTCPConnections",
		    myGlobals.device[i].numEstablishedTCPConnections, ' ', numEntries);

	endWriteKey(fDescr, lang,"\t", "TCPflags", ',');
      }

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "tcpLocal")) 
	wrtLlongItm(fDescr, lang,"\t","tcpLocal",
		    myGlobals.device[i].tcpGlobalTrafficStats.local, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "tcpLocal2Rem")) 
	wrtLlongItm(fDescr, lang,"\t","tcpLocal2Rem",
		    myGlobals.device[i].tcpGlobalTrafficStats.local2remote, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "tcpRem")) 
	wrtLlongItm(fDescr, lang,"\t","tcpRem",
		    myGlobals.device[i].tcpGlobalTrafficStats.remote, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "tcpRem2Local")) 
	wrtLlongItm(fDescr, lang,"\t","tcpRem2Local",
		    myGlobals.device[i].tcpGlobalTrafficStats.remote2local, ',', numEntries);

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "udpLocal")) 
	wrtLlongItm(fDescr, lang,"\t","udpLocal",
		    myGlobals.device[i].udpGlobalTrafficStats.local, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "udpLocal2Rem"))
	wrtLlongItm(fDescr, lang,"\t","udpLocal2Rem",
		    myGlobals.device[i].udpGlobalTrafficStats.local2remote, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "udpRem"))
	wrtLlongItm(fDescr, lang,"\t","udpRem",
		    myGlobals.device[i].udpGlobalTrafficStats.remote, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "udpRem2Local"))
	wrtLlongItm(fDescr, lang,"\t","udpRem2Local",
		    myGlobals.device[i].udpGlobalTrafficStats.remote2local, ',', numEntries);

      /* ********************************* */

      if(checkFilter(filter, &filterPattern, "icmpLocal")) 
	wrtLlongItm(fDescr, lang,"\t","icmpLocal",
		    myGlobals.device[i].icmpGlobalTrafficStats.local, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "icmpLocal2Rem")) 
	wrtLlongItm(fDescr, lang,"\t","icmpLocal2Rem",
		    myGlobals.device[i].icmpGlobalTrafficStats.local2remote, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "icmpRem")) 
	wrtLlongItm(fDescr, lang,"\t","icmpRem",
		    myGlobals.device[i].icmpGlobalTrafficStats.remote, ',', numEntries);
      if(checkFilter(filter, &filterPattern, "icmpRem2Local")) 
	wrtLlongItm(fDescr, lang,"\t","icmpRem2Local",
		    myGlobals.device[i].icmpGlobalTrafficStats.remote2local, ' ', numEntries);
    }

    numEntries++;
    if((lang == NO_LANGUAGE) && (numEntries == 1)) goto REPEAT;
  }

  if(numEntries > 0) endWriteKey(fDescr, lang, "", (lang == XML_LANGUAGE) ? "device-information" : keyName, ' ');
  endWriteArray(fDescr, lang);

  if((filter[0] != '\0') && filterPattern.fastmap)
    free(filterPattern.fastmap);
}
