/*
 *  Copyright (C) 2001-04 Luca Deri <deri@ntop.org>
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

/* Python support courtesy of Nicola Larosa <n.larosa@araknos.it> */
/*
  This file has been significantly reworked
  by Philippe Bereski <Philippe.Bereski@ms.alcatel.fr>

  Many thanks Philippe!
*/
char *languages[] = { "", "perl", "php", "xml", "python", "no" };

/* *************************** */

static void sendEmitterString(FILE *fDescr, char *theString) {

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "sendEmitterString(%X, '%s')", fDescr, theString);
#endif

  if(fDescr == NULL)
    sendString(theString);
  else
    fprintf(fDescr, theString);
}

/* *************************** */

static void initWriteArray(FILE *fDescr, int lang) {

  switch(lang) {
  case FLAG_PERL_LANGUAGE:
    sendEmitterString(fDescr, "%ntopHash =(\n");
    break ;
  case FLAG_PHP_LANGUAGE:
    sendEmitterString(fDescr, "$ntopHash = array(\n");
    break ;
  case FLAG_PYTHON_LANGUAGE:
    sendEmitterString(fDescr, "ntopDict = {\n");
    break ;
  case FLAG_XML_LANGUAGE:
    sendEmitterString(fDescr, "<rpc-reply xmlns:ntop=\"http://www.ntop.org/ntop.dtd\">"
		      "\n<ntop-traffic-information>\n");
    break ;
  case FLAG_NO_LANGUAGE:
    break ;
  }
}

/* *************************** */

static void endWriteArray(FILE *fDescr, int lang) {
  switch(lang) {
  case FLAG_PERL_LANGUAGE:
  case FLAG_PHP_LANGUAGE:
    sendEmitterString(fDescr, ");\n");
    break ;
  case FLAG_PYTHON_LANGUAGE:
    sendEmitterString(fDescr, "}\n");
    break;
  case FLAG_XML_LANGUAGE:
    sendEmitterString(fDescr, "</ntop-traffic-information>\n</rpc-reply>\n");
    break ;
  case FLAG_NO_LANGUAGE:
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

static void initWriteKey(FILE *fDescr, int lang, char *indent,
		  char *keyName, int numEntriesSent) {
  char buf[256];

  if((indent == NULL) || (keyName == NULL))
    return;

  validateString(keyName);

  switch(lang) {
  case FLAG_PERL_LANGUAGE:
    safe_snprintf(buf, sizeof(buf), "%s'%s' => {\n",indent, keyName);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_PHP_LANGUAGE:
    safe_snprintf(buf, sizeof(buf), "%s'%s' => array(\n",indent, keyName);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_PYTHON_LANGUAGE:
    safe_snprintf(buf, sizeof(buf), "%s'%s': {\n",indent, keyName);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_XML_LANGUAGE:
    safe_snprintf(buf, sizeof(buf), "%s<%s>\n", indent, keyName);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_NO_LANGUAGE:
    safe_snprintf(buf, sizeof(buf), "%s|",
		numEntriesSent == 0 ? "key" : keyName);
    sendEmitterString(fDescr, buf);
    break ;
  }
}

/* *************************** */

static void endWriteKey(FILE *fDescr, int lang, char *indent, char *keyName, char last) {
  char buf[256];

  /* If there is no indentation, this was the first level of key,
     hence the end of the list. Don't add a ',' at end.
  */

  if((indent == NULL) ||  (keyName == NULL))
    return;

  validateString(keyName);
  switch(lang) {
  case FLAG_PERL_LANGUAGE:
    safe_snprintf(buf, sizeof(buf),"%s}%c\n",indent,last);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_PHP_LANGUAGE:
    safe_snprintf(buf, sizeof(buf),"%s)%c\n",indent,last);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_XML_LANGUAGE:
    safe_snprintf(buf, sizeof(buf), "%s</%s>\n",indent, keyName);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_PYTHON_LANGUAGE:
    safe_snprintf(buf, sizeof(buf),"%s}%c\n",indent,last);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_NO_LANGUAGE:
    if(strcmp(indent, "") == 0) sendEmitterString(fDescr, "\n");
    break ;
  }
}

/* *************************** */

static void wrtStrItm(FILE *fDescr, int lang, char *indent, char *name,
		      char *value, char last, int numEntriesSent) {
  char buf[256];

  validateString(name);

  switch(lang) {
  case FLAG_PERL_LANGUAGE:
  case FLAG_PHP_LANGUAGE:
    /* In the case of hostNumIpAddress and hostResolvedName,
       the pointer is not null, but the string is empty.
       In that case, don't create the key in the array.
    */
    if((value != NULL) && (value[0] != '\0'))
      {
	safe_snprintf(buf, sizeof(buf), "%s'%s' => '%s'%c\n", indent,name,value,last);
	sendEmitterString(fDescr, buf);
      }
    break ;
  case FLAG_XML_LANGUAGE:
    if((value != NULL) && (value[0] != '\0'))
      {
	safe_snprintf(buf, sizeof(buf), "%s<%s>%s</%s>\n", indent, name, value, name);
	sendEmitterString(fDescr, buf);
      }
    break ;
  case FLAG_PYTHON_LANGUAGE:
    if((value != NULL) && (value[0] != '\0'))
      {
	safe_snprintf(buf, sizeof(buf), "%s'%s': '%s'%c\n", indent,name,value,last);
 	sendEmitterString(fDescr, buf);
       }
     break ;
  case FLAG_NO_LANGUAGE:
    if(value != NULL) {
      safe_snprintf(buf, sizeof(buf), "%s|", numEntriesSent == 0 ? name : value);
      sendEmitterString(fDescr, buf);
    } else {
      safe_snprintf(buf, sizeof(buf), "%s|", numEntriesSent == 0 ? name : "");
      sendEmitterString(fDescr, buf);
    }
    break ;
  }
}

/* *************************** */

static void wrtIntItm(FILE *fDescr, int lang, char *indent, char *name,
		      int value, char last, int numEntriesSent) {
  char buf[80];
  safe_snprintf(buf, sizeof(buf), "%d",value);
  wrtStrItm(fDescr, lang, indent, name, buf, last, numEntriesSent);
}

/* *************************** */

static void wrtIntStrItm(FILE *fDescr, int lang, char *indent,int name,
			 char *value, char useless, int numEntriesSent) {
  char buf[80];
  safe_snprintf(buf, sizeof(buf), "%d",name);
  wrtStrItm(fDescr, lang, indent, buf, value, ',', numEntriesSent);
}

/* *************************** */

static void wrtUintItm(FILE *fDescr, int lang, char *indent, char *name,
		       unsigned int value, char useless, int numEntriesSent) {
  char buf[80];
  safe_snprintf(buf, sizeof(buf), "%d",value);
  wrtStrItm(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

static void wrtUcharItm(FILE *fDescr, int lang, char *indent, char *name,
			u_char value, char useless, int numEntriesSent) {
  char buf[80];
  safe_snprintf(buf, sizeof(buf), "%d",value);
  wrtStrItm(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

static void wrtFloatItm(FILE *fDescr, int lang, char *indent, char *name,
			float value, char last, int numEntriesSent) {
  char buf[80];
  safe_snprintf(buf, sizeof(buf), "%0.2f",value);
  wrtStrItm(fDescr, lang, indent, name, buf, last, numEntriesSent);
}

/* *************************** */

static void wrtIntFloatItm(FILE *fDescr, int lang, char *indent, int name,
			   float value, char last, int numEntriesSent) {
  char buf[80];
  safe_snprintf(buf, sizeof(buf), "%d", name);
  wrtFloatItm(fDescr, lang, indent, (lang == FLAG_XML_LANGUAGE) ? "number" : buf,
	      value, last, numEntriesSent);
}

/* *************************** */

static void wrtUlongItm(FILE *fDescr, int lang, char *indent, char *name,
			unsigned long value, char useless, int numEntriesSent) {
  char buf[80];

  safe_snprintf(buf, sizeof(buf), "%lu",value);
  wrtStrItm(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

static void wrtLlongItm(FILE *fDescr, int lang, char* indent, char* name,
			TrafficCounter value, char last, int numEntriesSent) {
  char buf[80];

  safe_snprintf(buf, sizeof(buf),  "%lu", (long unsigned int)value.value);
  wrtStrItm(fDescr, lang, indent, name, buf, last, numEntriesSent);
}

/* *************************** */

static void wrtTime_tItm(FILE *fDescr, int lang, char *indent, char *name,
			 time_t value, char useless, int numEntriesSent) {
  char buf[80];
  safe_snprintf(buf, sizeof(buf), "%ld",value);
  wrtStrItm(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

static void wrtUshortItm(FILE *fDescr, int lang, char *indent, char *name,
			 u_short value, char useless, int numEntriesSent) {
  char buf[80];
  safe_snprintf(buf, sizeof(buf), "%d",value);
  wrtStrItm(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* ********************************** */

static int checkFilter(char* theStr, char* strToMatch) {
  if((theStr == NULL) || (theStr[0] == '\0') || (strToMatch == NULL))
    return(1);
  else
    return(!strstr(theStr, strToMatch));
}

/* ********************************** */

void dumpNtopFlows(FILE *fDescr, char* options, int actualDeviceId) {
  char key[64], filter[128];
  unsigned int numEntries=0, lang=DEFAULT_FLAG_LANGUAGE;
  FlowFilterList *list = myGlobals.flowsList;

  memset(key, 0, sizeof(key));
  memset(filter, 0, sizeof(filter));

  if(options != NULL) {
    /* language now defined into "languages[]" */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0, j;

      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      /* If argument contains "language=something", then
	 look in the table "languages" of known language for
	 the choosen language.
      */

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcasecmp(tmpStr, "language") == 0) {
	  lang = DEFAULT_FLAG_LANGUAGE;
	  for(j=1;j <= MAX_FLAG_LANGUGE;j++) {
	    if(strcasecmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }

  if(list != NULL) {
    while(list != NULL) {
      if(list->pluginStatus.activePlugin) {
	if(numEntries == 0)
	  initWriteArray(fDescr, lang);
      REPEAT_FLOWS:
	initWriteKey(fDescr, lang,  "", list->flowName, numEntries);
	wrtLlongItm(fDescr, lang, "\t", "packets", list->packets,  ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "bytes",   list->bytes,    ',', numEntries);
	endWriteKey(fDescr, lang,   "", list->flowName, ',');
	numEntries++;

	if((lang == FLAG_NO_LANGUAGE) && (numEntries == 1))
	  goto REPEAT_FLOWS;
      }

      list = list->next;
    }
  }

  if(numEntries > 0) endWriteArray(fDescr, lang);
}

/* ********************************** */

void dumpNtopTrafficMatrix(FILE *fDescr, char* options, int actualDeviceId) {
  char key[64];
  unsigned int numEntries=0, lang=DEFAULT_FLAG_LANGUAGE;
  int i=0, j;
  char buf[LEN_GENERAL_WORK_BUFFER];

  memset(key, 0, sizeof(key));

  if(options != NULL) {
    /* language now defined into "languages[]" */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      /* If argument contains "language=something", then
	 look in the table "languages" of known language for
	 the choosen language.
      */

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcasecmp(tmpStr, "language") == 0) {
	  lang = DEFAULT_FLAG_LANGUAGE;
	  for(j=1;j <= MAX_FLAG_LANGUGE;j++) {
	    if(strcasecmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }

  /* *************************************** */

  for(i=0; i<myGlobals.device[myGlobals.actualReportDeviceId].numHosts; i++)
      for(j=0; j<myGlobals.device[myGlobals.actualReportDeviceId].numHosts; j++) {
	if(i != j) {
	  int idx = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts+j;

	  if(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx] == NULL)
	    continue;

	if(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value > 0) {
	    if(numEntries == 0) initWriteArray(fDescr, lang);

	    safe_snprintf(buf, sizeof(buf), "%s_%s",
			myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostNumIpAddress,
			myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostNumIpAddress);

	  REPEAT_MATRIX:
	    initWriteKey(fDescr, lang,  "", buf, numEntries);
	    wrtLlongItm(fDescr, lang, "\t", "pkts",
			myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsSent,
			',', numEntries);
	    wrtLlongItm(fDescr, lang, "\t", "bytes",
			myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent,
			',', numEntries);
	    endWriteKey(fDescr, lang,   "", buf, ',');
	    numEntries++;

	    if((lang == FLAG_NO_LANGUAGE) && (numEntries == 1))
	      goto REPEAT_MATRIX;

	    numEntries++;
	  }
	}
      }
    
    

  if(numEntries > 0) endWriteArray(fDescr, lang);
}

/* ********************************** */

static void decrementRefCount(HostTraffic *el) {
  if(el->refCount == 0) return;

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.hostsHashMutex, "dumpNtopHashes");
#endif
  el->refCount--;
#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.hostsHashMutex);
#endif
}

/* ********************************** */

void dumpNtopHashes(FILE *fDescr, char* options, int actualDeviceId) {
  char key[64], filter[128], *hostKey = NULL;
  unsigned int numEntries=0, lang=DEFAULT_FLAG_LANGUAGE, j, localView=0;
  HostTraffic *el;
  unsigned char shortView = 0;
  char workSymIpAddress[MAX_LEN_SYM_HOST_NAME_HTML];
  char * angleLocation;
  TrafficCounter ctr;

  memset(key, 0, sizeof(key));
  memset(filter, 0, sizeof(filter));

  if(options != NULL) {
    /* language now defined into "languages[]" */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0;

      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      /* If argument contains "language=something", then
	 look in the table "languages" of known language for
	 the choosen language.
      */

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcasecmp(tmpStr, "language") == 0) {
	  lang = DEFAULT_FLAG_LANGUAGE;
	  for(j=1;j <= MAX_FLAG_LANGUGE;j++) {
	    if(strcasecmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	} else if(strcmp(tmpStr, "key") == 0) {
	  strncpy(key, &tmpStr[i+1], sizeof(key));
	} else if(strcmp(tmpStr, "view") == 0) {
	  if(!strcmp(&tmpStr[i+1], "short"))
	    shortView = 1;
	} else if(strcmp(tmpStr, "restrict") == 0) {
	  if(!strcmp(key, "local")) localView = 1;
	} else if(strcmp(tmpStr, "filter") == 0) {
	  strncpy(filter, &tmpStr[i+1], sizeof(filter));
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }

  initWriteArray(fDescr, lang);

  for(el=getFirstHost(actualDeviceId); 
      el != NULL; el = getNextHost(actualDeviceId, el)) {

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.hostsHashMutex, "dumpNtopHashes");
#endif
    el->refCount++;
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.hostsHashMutex);
#endif

    strncpy(workSymIpAddress, el->hostResolvedName, MAX_LEN_SYM_HOST_NAME_HTML);
    if ((angleLocation = strchr(workSymIpAddress, '<')) != NULL) {
      angleLocation[0] = '\0';
    }

    if(key[0] != '\0') {
      if(strcmp(el->hostNumIpAddress, key)
	 && strcmp(el->ethAddressString, key)
	 && strcmp(workSymIpAddress, key)) {
	decrementRefCount(el);
	continue;
      }
    }

    if(el->hostNumIpAddress[0] != '\0') {
      hostKey = el->hostNumIpAddress;
      if(localView) {
	if(((!subnetPseudoLocalHost(el))
	    && (!multicastHost(el)))) {
	  decrementRefCount(el);
	  continue;
	}
      }
    } else {
      if(localView) { decrementRefCount(el); continue; }
      hostKey = el->ethAddressString;
    }

  REPEAT_HOSTS:
    if(numEntries > 0)
      endWriteKey(fDescr, lang,"",  (lang == FLAG_XML_LANGUAGE) ? "host-information" : hostKey, ',');

    initWriteKey(fDescr, lang, "", (lang == FLAG_XML_LANGUAGE) ? "host-information" : hostKey, numEntries);
    if(lang == FLAG_XML_LANGUAGE) wrtStrItm(fDescr, lang, "\t", "key", hostKey, ',', numEntries);

    /* ************************ */

    if(!shortView) {
      if(checkFilter(filter, "index"))
	wrtUintItm(fDescr, lang, "\t","index", 0, ' ', numEntries);

      if(checkFilter(filter, "hostNumIpAddress"))
	wrtStrItm(fDescr, lang, "\t", "hostNumIpAddress", el->hostNumIpAddress, ',', numEntries);
    }

    if(checkFilter(filter, "hostResolvedName"))
      wrtStrItm(fDescr, lang, "\t", "hostResolvedName", workSymIpAddress, ',', numEntries);

    if(!shortView) {
      if(checkFilter(filter, "firstSeen"))
	wrtTime_tItm(fDescr, lang, "\t", "firstSeen", el->firstSeen, ' ', numEntries);
      if(checkFilter(filter, "lastSeen"))
	wrtTime_tItm(fDescr, lang, "\t", "lastSeen",  el->lastSeen, ' ', numEntries);
      if(checkFilter(filter, "minTTL"))
	wrtUshortItm(fDescr, lang, "\t", "minTTL",     el->minTTL, ' ', numEntries);
      if(checkFilter(filter, "maxTTL"))
	wrtUshortItm(fDescr, lang, "\t", "maxTTL",     el->maxTTL, ' ', numEntries);

      if(el->nonIPTraffic != NULL) {
	if(checkFilter(filter, "nbHostName"))
	  wrtStrItm(fDescr, lang, "\t", "nbHostName",   el->nonIPTraffic->nbHostName, ',', numEntries);
	if(checkFilter(filter, "nbDomainName"))
	  wrtStrItm(fDescr, lang, "\t", "nbDomainName", el->nonIPTraffic->nbDomainName, ',', numEntries);
	if(checkFilter(filter, "nbDescr"))
	  wrtStrItm(fDescr, lang, "\t", "nbDescr",      el->nonIPTraffic->nbDescr, ',', numEntries);
	if(checkFilter(filter, "nodeType"))
	  wrtUcharItm (fDescr, lang, "\t", "nodeType",  el->nonIPTraffic->nbNodeType, ' ', numEntries);
	if(checkFilter(filter, "atNodeName"))
	  wrtStrItm(fDescr, lang, "\t", "atNodeName",   el->nonIPTraffic->atNodeName, ',', numEntries);
	if(checkFilter(filter, "atNetwork"))
	  wrtUshortItm(fDescr, lang, "\t", "atNetwork",  el->nonIPTraffic->atNetwork, ' ', numEntries);
	if(checkFilter(filter, "atNode"))
	  wrtUcharItm (fDescr, lang, "\t", "atNode",    el->nonIPTraffic->atNode, ' ', numEntries);
	if(checkFilter(filter, "ipxHostName"))
	  wrtStrItm(fDescr, lang, "\t", "ipxHostName",  el->nonIPTraffic->ipxHostName, ',', numEntries);
      }
    }

    if(checkFilter(filter, "pktSent"))
      wrtLlongItm(fDescr, lang, "\t", "pktSent",   el->pktSent, ',', numEntries);
    if(checkFilter(filter, "pktRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "pktRcvd", el->pktRcvd, ',', numEntries);

    if(checkFilter(filter, "ipBytesSent"))
      wrtLlongItm(fDescr, lang, "\t", "ipBytesSent", el->ipBytesSent, ',', numEntries);
    if(checkFilter(filter, "ipBytesRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "ipBytesRcvd", el->ipBytesRcvd, ',', numEntries);

    /* *************************************** */

    if(!shortView) {
      if(checkFilter(filter, "pktDuplicatedAckSent"))
	wrtLlongItm(fDescr, lang, "\t", "pktDuplicatedAckSent",el->pktDuplicatedAckSent, ',', numEntries);
      if(checkFilter(filter, "pktDuplicatedAckRcvd"))
	wrtLlongItm(fDescr, lang, "\t", "pktDuplicatedAckRcvd",el->pktDuplicatedAckRcvd, ',', numEntries);
      if(checkFilter(filter, "pktBroadcastSent"))
	wrtLlongItm(fDescr, lang, "\t", "pktBroadcastSent",  el->pktBroadcastSent, ',', numEntries);
    }

    if(checkFilter(filter, "bytesMulticastSent"))
      wrtLlongItm(fDescr, lang, "\t", "bytesMulticastSent", el->bytesMulticastSent, ',', numEntries);
    if(checkFilter(filter, "pktMulticastSent"))
      wrtLlongItm(fDescr, lang, "\t", "pktMulticastSent",  el->pktMulticastSent, ',', numEntries);

    if(checkFilter(filter, "bytesMulticastRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "bytesMulticastRcvd", el->bytesMulticastRcvd, ',', numEntries);
    if(checkFilter(filter, "pktMulticastRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "pktMulticastRcvd",  el->pktMulticastRcvd, ',', numEntries);

    /* *************************************** */

    if(checkFilter(filter, "bytesSent"))
      wrtLlongItm(fDescr, lang, "\t", "bytesSent",         el->bytesSent, ',', numEntries);

    if(!shortView) {
      if(checkFilter(filter, "bytesSentLoc"))
	wrtLlongItm(fDescr, lang, "\t", "bytesSentLoc",  el->bytesSentLoc, ',', numEntries);
      if(checkFilter(filter, "bytesSentRem"))

	wrtLlongItm(fDescr, lang, "\t", "bytesSentRem", el->bytesSentRem, ',', numEntries);
    }

    if(checkFilter(filter, "bytesRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "bytesRcvd",     el->bytesRcvd, ',', numEntries);

    if(!shortView) {
      if(checkFilter(filter, "bytesRcvdLoc"))
	wrtLlongItm(fDescr, lang, "\t", "bytesRcvdLoc", el->bytesRcvdLoc, ',', numEntries);
      if(checkFilter(filter, "bytesRcvdFromRem"))
	wrtLlongItm(fDescr, lang, "\t", "bytesRcvdFromRem",
		    el->bytesRcvdFromRem, ',', numEntries);
      if(checkFilter(filter, "actualRcvdThpt"))

	wrtFloatItm(fDescr, lang, "\t", "actualRcvdThpt",  el->actualRcvdThpt, ',', numEntries);
      if(checkFilter(filter, "lastHourRcvdThpt"))
	wrtFloatItm(fDescr, lang, "\t", "lastHourRcvdThpt", el->lastHourRcvdThpt, ',', numEntries);
      if(checkFilter(filter, "averageRcvdThpt"))

	wrtFloatItm(fDescr, lang, "\t", "averageRcvdThpt", el->averageRcvdThpt, ',', numEntries);
      if(checkFilter(filter, "peakRcvdThpt"))

	wrtFloatItm(fDescr, lang, "\t", "peakRcvdThpt",    el->peakRcvdThpt, ',', numEntries);
      if(checkFilter(filter, "actualSentThpt"))

	wrtFloatItm(fDescr, lang, "\t", "actualSentThpt",  el->actualSentThpt, ',', numEntries);
      if(checkFilter(filter, "lastHourSentThpt"))

	wrtFloatItm(fDescr, lang, "\t", "lastHourSentThpt", el->lastHourSentThpt, ',', numEntries);
      if(checkFilter(filter, "averageSentThpt"))
	wrtFloatItm(fDescr, lang, "\t", "averageSentThpt", el->averageSentThpt, ',', numEntries);
      if(checkFilter(filter, "peakSentThpt"))
	wrtFloatItm(fDescr, lang, "\t", "peakSentThpt",    el->peakSentThpt, ',', numEntries);

      if(checkFilter(filter, "actualTThpt"))
	wrtFloatItm(fDescr, lang, "\t", "actualTThpt",  el->actualTThpt, ',', numEntries);
      if(checkFilter(filter, "averageTThpt"))
	wrtFloatItm(fDescr, lang, "\t", "averageTThpt", el->averageTThpt, ',', numEntries);
      if(checkFilter(filter, "peakTThpt"))
	wrtFloatItm(fDescr, lang, "\t", "peakTThpt",    el->peakTThpt, ',', numEntries);

      if(checkFilter(filter, "actualRcvdPktThpt"))
	wrtFloatItm(fDescr, lang, "\t", "actualRcvdPktThpt", el->actualRcvdPktThpt, ',', numEntries);
      if(checkFilter(filter, "averageRcvdPktThpt"))
	wrtFloatItm(fDescr, lang, "\t", "averageRcvdPktThpt",el->averageRcvdPktThpt, ',', numEntries);
      if(checkFilter(filter, "peakRcvdPktThpt"))
	wrtFloatItm(fDescr, lang, "\t", "peakRcvdPktThpt", el->peakRcvdPktThpt, ',', numEntries);
      if(checkFilter(filter, "actualSentPktThpt"))
	wrtFloatItm(fDescr, lang, "\t", "actualSentPktThpt", el->actualSentPktThpt, ',', numEntries);
      if(checkFilter(filter, "averageSentPktThpt"))
	wrtFloatItm(fDescr, lang, "\t", "averageSentPktThpt", el->averageSentPktThpt, ',', numEntries);
      if(checkFilter(filter, "peakSentPktThpt"))
	wrtFloatItm(fDescr, lang, "\t", "peakSentPktThpt", el->peakSentPktThpt, ',', numEntries);

      if(checkFilter(filter, "actualTPktThpt"))
	wrtFloatItm(fDescr, lang, "\t", "actualTPktThpt", el->actualTPktThpt, ',', numEntries);
      if(checkFilter(filter, "averageTPktThpt"))
	wrtFloatItm(fDescr, lang, "\t", "averageTPktThpt",el->averageTPktThpt, ',', numEntries);
      if(checkFilter(filter, "peakTPktThpt"))
	wrtFloatItm(fDescr, lang, "\t", "peakTPktThpt", el->peakTPktThpt, ',', numEntries);

    }

    if(checkFilter(filter, "ipBytesSent"))
      wrtLlongItm(fDescr, lang, "\t", "ipBytesSent", el->ipBytesSent, ',', numEntries);
    if(checkFilter(filter, "ipBytesRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "ipBytesRcvd", el->ipBytesRcvd, ',', numEntries);
    
    if(checkFilter(filter, "ipv6Sent"))
      wrtLlongItm(fDescr, lang, "\t", "ipv6Sent", el->ipv6Sent, ',', numEntries);
    if(checkFilter(filter, "ipv6Rcvd"))
      wrtLlongItm(fDescr, lang, "\t", "ipv6Rcvd", el->ipv6Rcvd, ',', numEntries);
    
    ctr.value = el->tcpSentLoc.value+el->tcpSentRem.value;
    if(checkFilter(filter, "tcpBytesSent"))
      wrtLlongItm(fDescr, lang, "\t", "tcpBytesSent", ctr, ',', numEntries);
    ctr.value = el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value;
    if(checkFilter(filter, "tcpBytesRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "tcpBytesRcvd", ctr, ',', numEntries);

    ctr.value = el->udpSentLoc.value+el->udpSentRem.value;
    if(checkFilter(filter, "udpBytesSent"))
      wrtLlongItm(fDescr, lang, "\t", "udpBytesSent", ctr, ',', numEntries);
    ctr.value = el->udpRcvdLoc.value+el->udpRcvdFromRem.value;
    if(checkFilter(filter, "udpBytesRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "udpBytesRcvd", ctr, ',', numEntries);

    if(checkFilter(filter, "icmpSent"))
      wrtLlongItm(fDescr, lang, "\t", "icmpSent",        el->icmpSent, ',', numEntries);
    if(checkFilter(filter, "icmpRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "icmpRcvd",    el->icmpRcvd, ',', numEntries);


    if(!shortView) {
      if(checkFilter(filter, "tcpSentRem"))
	wrtLlongItm(fDescr, lang, "\t", "tcpSentRem", el->tcpSentRem, ',', numEntries);
      if(checkFilter(filter, "udpSentLoc"))
	wrtLlongItm(fDescr, lang, "\t", "udpSentLoc", el->udpSentLoc, ',', numEntries);
      if(checkFilter(filter, "udpSentRem"))
	wrtLlongItm(fDescr, lang, "\t", "udpSentRem", el->udpSentRem, ',', numEntries);

      if(checkFilter(filter, "tcpRcvdLoc"))
	wrtLlongItm(fDescr, lang, "\t", "tcpRcvdLoc",el->tcpRcvdLoc, ',', numEntries);
      if(checkFilter(filter, "tcpRcvdFromRem"))
	wrtLlongItm(fDescr, lang, "\t", "tcpRcvdFromRem",el->tcpRcvdFromRem, ',', numEntries);
      if(checkFilter(filter, "udpRcvdLoc"))
	wrtLlongItm(fDescr, lang, "\t", "udpRcvdLoc",el->udpRcvdLoc, ',', numEntries);
      if(checkFilter(filter, "udpRcvdFromRem"))
	wrtLlongItm(fDescr, lang, "\t", "udpRcvdFromRem",el->udpRcvdFromRem, ',', numEntries);

      /* ***************************** */

      if(checkFilter(filter, "tcpFragmentsSent"))
	wrtLlongItm(fDescr, lang, "\t", "tcpFragmentsSent", el->tcpFragmentsSent, ',', numEntries);
      if(checkFilter(filter, "tcpFragmentsRcvd"))
	wrtLlongItm(fDescr, lang, "\t", "tcpFragmentsRcvd", el->tcpFragmentsRcvd, ',', numEntries);
      if(checkFilter(filter, "udpFragmentsSent"))
	wrtLlongItm(fDescr, lang, "\t", "udpFragmentsSent", el->udpFragmentsSent, ',', numEntries);
      if(checkFilter(filter, "udpFragmentsRcvd"))
	wrtLlongItm(fDescr, lang, "\t", "udpFragmentsRcvd", el->udpFragmentsRcvd, ',', numEntries);
      if(checkFilter(filter, "icmpFragmentsSent"))
	wrtLlongItm(fDescr, lang, "\t", "icmpFragmentsSent", el->icmpFragmentsSent, ',', numEntries);
      if(checkFilter(filter, "icmpFragmentsRcvd"))
	wrtLlongItm(fDescr, lang, "\t", "icmpFragmentsRcvd", el->icmpFragmentsRcvd, ',', numEntries);

      /* ***************************** */
      
      if(el->nonIPTraffic != NULL) {
	if(checkFilter(filter, "stpSent"))
	  wrtLlongItm(fDescr, lang, "\t", "stpSent", el->nonIPTraffic->stpSent, ',', numEntries);
	if(checkFilter(filter, "stpRcvd"))
	  wrtLlongItm(fDescr, lang, "\t", "stpRcvd", el->nonIPTraffic->stpRcvd, ',', numEntries);
	if(checkFilter(filter, "ipxSent"))
	  wrtLlongItm(fDescr, lang, "\t", "ipxSent", el->nonIPTraffic->ipxSent, ',', numEntries);
	if(checkFilter(filter, "ipxRcvd"))
	  wrtLlongItm(fDescr, lang, "\t", "ipxRcvd", el->nonIPTraffic->ipxRcvd, ',', numEntries);
	if(checkFilter(filter, "osiSent"))
	  wrtLlongItm(fDescr, lang, "\t", "osiSent", el->nonIPTraffic->osiSent, ',', numEntries);
	if(checkFilter(filter, "osiRcvd"))
	  wrtLlongItm(fDescr, lang, "\t", "osiRcvd", el->nonIPTraffic->osiRcvd, ',', numEntries);
	if(checkFilter(filter, "dlcSent"))
	  wrtLlongItm(fDescr, lang, "\t", "dlcSent", el->nonIPTraffic->dlcSent, ',', numEntries);
	if(checkFilter(filter, "dlcRcvd"))
	  wrtLlongItm(fDescr, lang, "\t", "dlcRcvd", el->nonIPTraffic->dlcRcvd, ',', numEntries);

	if(checkFilter(filter, "arp_rarpSent"))
	  wrtLlongItm(fDescr, lang, "\t", "arp_rarpSent",el->nonIPTraffic->arp_rarpSent, ',', numEntries);
	if(checkFilter(filter, "arp_rarpRcvd"))
	  wrtLlongItm(fDescr, lang, "\t", "arp_rarpRcvd", el->nonIPTraffic->arp_rarpRcvd, ',', numEntries);
	if(checkFilter(filter, "arpReqPktsSent"))
	  wrtLlongItm(fDescr, lang, "\t", "arpReqPktsSent", el->nonIPTraffic->arpReqPktsSent, ',', numEntries);
	if(checkFilter(filter, "arpReplyPktsSent"))
	  wrtLlongItm(fDescr, lang, "\t", "arpReplyPktsSent", el->nonIPTraffic->arpReplyPktsSent, ',', numEntries);
	if(checkFilter(filter, "arpReplyPktsRcvd"))
	  wrtLlongItm(fDescr, lang, "\t", "arpReplyPktsRcvd", el->nonIPTraffic->arpReplyPktsRcvd, ',', numEntries);
	if(checkFilter(filter, "decnetSent"))
	  wrtLlongItm(fDescr, lang, "\t", "decnetSent", el->nonIPTraffic->decnetSent, ',', numEntries);
	if(checkFilter(filter, "decnetRcvd"))
	  wrtLlongItm(fDescr, lang, "\t", "decnetRcvd", el->nonIPTraffic->decnetRcvd, ',', numEntries);
	if(checkFilter(filter, "appletalkSent"))
	  wrtLlongItm(fDescr, lang, "\t", "appletalkSent", el->nonIPTraffic->appletalkSent, ',', numEntries);
	if(checkFilter(filter, "appletalkRcvd"))
	  wrtLlongItm(fDescr, lang, "\t", "appletalkRcvd", el->nonIPTraffic->appletalkRcvd, ',', numEntries);
	if(checkFilter(filter, "netbiosSent"))
	  wrtLlongItm(fDescr, lang, "\t", "netbiosSent", el->nonIPTraffic->netbiosSent, ',', numEntries);
	if(checkFilter(filter, "netbiosRcvd"))
	  wrtLlongItm(fDescr, lang, "\t", "netbiosRcvd", el->nonIPTraffic->netbiosRcvd, ',', numEntries);
	if(checkFilter(filter, "otherSent"))
	  wrtLlongItm(fDescr, lang, "\t", "otherSent", el->nonIPTraffic->otherSent, ',', numEntries);
	if(checkFilter(filter, "otherRcvd"))
	  wrtLlongItm(fDescr, lang, "\t", "otherRcvd", el->nonIPTraffic->otherRcvd, ',', numEntries);
      }

      /* ********************************* */

      if(el->routedTraffic && checkFilter(filter, "RoutingCounter")) {
	initWriteKey(fDescr, lang, "\t", "RoutingCounter", numEntries);
	wrtLlongItm(fDescr, lang,"\t\t", "routedPkts", el->routedTraffic->routedPkts, ',', numEntries);
	wrtLlongItm(fDescr, lang,"\t\t", "routedBytes", el->routedTraffic->routedBytes, ',', numEntries);
	endWriteKey(fDescr, lang,"\t", "RoutingCounter", ',');
      }
    } /* shortView */

    if((!shortView) && (el->protoIPTrafficInfos && checkFilter(filter, "IP"))) {
      char *lastKey = NULL;

      initWriteKey(fDescr, lang, "\t", "IP", numEntries);

      for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {
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
      } /* for */

      if(lastKey != NULL) { endWriteKey(fDescr, lang,"\t\t", lastKey, ','); }
      endWriteKey(fDescr, lang,"\t", "IP", ',');
    }

    /* ***************************************** */

    if(!shortView) {
      if(el->icmpInfo && checkFilter(filter, "ICMP")) {
	initWriteKey(fDescr, lang, "\t", "ICMP", numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_ECHO",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_ECHO].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_ECHOREPLY",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_UNREACH",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_UNREACH].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_ROUTERADVERT",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_TMXCEED",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_PARAMPROB",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_MASKREPLY",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_MASKREQ",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_MASKREQ].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_INFO_REQUEST",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_INFO_REPLY",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_TIMESTAMP",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_TIMESTAMPREPLY",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","SENT_SOURCE_QUENCH",
		    (unsigned long)el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH].value, ' ', numEntries);

	/* *********************************************** */

	wrtUlongItm(fDescr, lang,"\t\t","RCVD_ECHO",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","RCVD_ECHOREPLY",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","RCVD_UNREACH",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","RCVD_ROUTERADVERT",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","RCVD_TMXCEED",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","RCVD_PARAMPROB",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","RCVD_MASKREPLY",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","RCVD_MASKREQ",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","RCVD_INFO_REQUEST",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","RCVD_INFO_REPLY",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","RCVD_TIMESTAMP",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","RCVD_TIMESTAMPREPLY",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY].value, ' ', numEntries);
	wrtUlongItm(fDescr, lang,"\t\t","RCVD_SOURCE_QUENCH",
		    (unsigned long)el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH].value, ' ', numEntries);

	endWriteKey(fDescr, lang,"\t", "ICMP", ',');
      }

      /* ********************************* */

      if(el->secHostPkts && checkFilter(filter, "securityPkts")) {
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

	wrtLlongItm(fDescr, lang,"\t\t","ackXmasFinSynNullScanSent",
		    el->secHostPkts->ackXmasFinSynNullScanSent.value, ',', numEntries);
	wrtLlongItm(fDescr, lang,"\t\t","ackXmasFinSynNullScanRcvd",
		    el->secHostPkts->ackXmasFinSynNullScanRcvd.value, ',', numEntries);

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

      if(checkFilter(filter, "ethAddressString"))
	wrtStrItm(fDescr, lang, "\t", "ethAddressString",el->ethAddressString, ' ', numEntries);
    } /* shortView */

    numEntries++;

    if((lang == FLAG_NO_LANGUAGE) && (numEntries == 1)) goto REPEAT_HOSTS;

    decrementRefCount(el);    
  } /* for */

  if(numEntries > 0) endWriteKey(fDescr, lang,"", (lang == FLAG_XML_LANGUAGE) ? "host-information" : hostKey, ' ');

  endWriteArray(fDescr, lang);
}

/* ********************************** */

void dumpNtopHashIndexes(FILE *fDescr, char* options, int actualDeviceId) {
  unsigned int numEntries=0, lang=DEFAULT_FLAG_LANGUAGE;
  HostTraffic *el;

  if(options != NULL) {
    /* language=[perl|php] */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0, j;

      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcmp(tmpStr, "language") == 0) {

	  lang = DEFAULT_FLAG_LANGUAGE;
	  for(j=1;j <= MAX_FLAG_LANGUGE;j++) {
	    if(strcmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }

  initWriteArray(fDescr, lang);

  for(el=getFirstHost(actualDeviceId); 
      el != NULL; el = getNextHost(actualDeviceId, el)) {
    
#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.hostsHashMutex, "dumpNtopHashes");
#endif

    if(!broadcastHost(el)) {
      char *hostKey;
      
      if(el->hostNumIpAddress[0] != '\0')
	hostKey = el->hostNumIpAddress;
      else
	hostKey = el->ethAddressString;
      
      wrtIntStrItm(fDescr, lang, "", 0, hostKey,'\n', numEntries);
      
      numEntries++;
    }    

#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.hostsHashMutex);
#endif
  } /* for */

  endWriteArray(fDescr, lang);
}

/* ********************************** */

void dumpNtopTrafficInfo(FILE *fDescr, char* options) {
  char intoabuf[32], key[16], localbuf[32], filter[128], *keyName = NULL;
  int lang=DEFAULT_FLAG_LANGUAGE, i, numEntries, localView=0;
  unsigned short shortView = 0;

  memset(key, 0, sizeof(key));
  memset(filter, 0, sizeof(filter));

  if(options != NULL) {
    /* language=[perl|php] */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int j;

      i=0;
      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcmp(tmpStr, "language") == 0) {
	  lang = DEFAULT_FLAG_LANGUAGE;
	  for(j=1;j <= MAX_FLAG_LANGUGE;j++) {
	    if(strcmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	} else if(strcmp(tmpStr, "key") == 0) {
	  strncpy(key, &tmpStr[i+1], sizeof(key));
	} else if(strcmp(tmpStr, "view") == 0) {
	  if(!strcmp(&tmpStr[i+1], "short")) shortView = 1;
	} else if(strcmp(tmpStr, "restrict") == 0) {
	  if(!strcmp(key, "local")) localView = 1; /* not yet used */
	} else if(strcmp(tmpStr, "filter") == 0) {
	  strncpy(filter, &tmpStr[i+1], sizeof(filter));
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }

  initWriteArray(fDescr, lang);

  for(i=0, numEntries=0; i<myGlobals.numDevices; i++) {
    int j;

    if(myGlobals.device[i].virtualDevice) continue;

    if((key[0] != '\0') && (strcmp(key, myGlobals.device[i].name) != 0))
      continue;

  REPEAT:
    if(numEntries > 0) { endWriteKey(fDescr, lang,"", (lang == FLAG_XML_LANGUAGE) ? "device-information" : keyName, ','); }

    keyName = myGlobals.device[i].name;

    initWriteKey(fDescr, lang, "", (lang == FLAG_XML_LANGUAGE) ? "device-information" : keyName, numEntries);
    if(lang == FLAG_XML_LANGUAGE) wrtStrItm(fDescr, lang, "\t", "key", keyName, ',', numEntries);

    wrtStrItm(fDescr, lang, "\t", "name", myGlobals.device[i].name, ',', numEntries);

    if(!shortView) {
      if(checkFilter(filter, "ipdot"))
	wrtStrItm(fDescr, lang, "\t", "ipdot", myGlobals.device[i].ipdot, ',', numEntries);
      if(checkFilter(filter, "fqdn"))
	wrtStrItm(fDescr, lang, "\t", "fqdn", myGlobals.device[i].fqdn, ',', numEntries);

      safe_snprintf(localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].network, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, "network"))
	wrtStrItm(fDescr, lang, "\t", "network", localbuf, ',', numEntries);
      safe_snprintf(localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].netmask, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, "netmask"))
	wrtStrItm(fDescr, lang, "\t", "netmask", localbuf, ',', numEntries);
      safe_snprintf(localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].ifAddr, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, "ifAddr"))
	wrtStrItm(fDescr, lang, "\t", "ifAddr", localbuf, ',', numEntries);

      if(checkFilter(filter, "started"))
	wrtTime_tItm(fDescr, lang, "\t", "started", myGlobals.device[i].started, ' ', numEntries);
      if(checkFilter(filter, "firstpkt"))
	wrtTime_tItm(fDescr, lang, "\t", "firstpkt", myGlobals.device[i].firstpkt, ' ', numEntries);
      if(checkFilter(filter, "lastpkt"))
	wrtTime_tItm(fDescr, lang, "\t", "lastpkt", myGlobals.device[i].lastpkt, ' ', numEntries);
      if(checkFilter(filter, "virtualDevice"))
	wrtIntItm(fDescr, lang, "\t", "virtualDevice",(int)myGlobals.device[i].virtualDevice, ',', numEntries);
      if(checkFilter(filter, "snaplen"))
	wrtIntItm(fDescr, lang, "\t", "snaplen", myGlobals.device[i].snaplen, ',', numEntries);
      if(checkFilter(filter, "datalink"))
	wrtIntItm(fDescr, lang, "\t", "datalink", myGlobals.device[i].datalink, ',', numEntries);
      if(checkFilter(filter, "filter"))
	wrtStrItm(fDescr, lang, "\t", "filter", myGlobals.device[i].filter ? myGlobals.device[i].filter : "", ',', numEntries);
      if(checkFilter(filter, "droppedPkts"))
	wrtLlongItm(fDescr, lang, "\t", "droppedPkts",myGlobals.device[i].droppedPkts, ',', numEntries);
    }

    if(checkFilter(filter, "receivedPkts"))
      wrtLlongItm(fDescr, lang, "\t", "receivedPkts",myGlobals.device[i].receivedPkts, ',', numEntries);
    if(checkFilter(filter, "ethernetPkts"))
      wrtLlongItm(fDescr, lang, "\t", "ethernetPkts",myGlobals.device[i].ethernetPkts, ',', numEntries);
    if(checkFilter(filter, "broadcastPkts"))
      wrtLlongItm(fDescr, lang, "\t", "broadcastPkts",myGlobals.device[i].broadcastPkts, ',', numEntries);
    if(checkFilter(filter, "multicastPkts"))
      wrtLlongItm(fDescr, lang, "\t", "multicastPkts",myGlobals.device[i].multicastPkts, ',', numEntries);
    if(checkFilter(filter, "ethernetBytes"))
      wrtLlongItm(fDescr, lang, "\t", "ethernetBytes",myGlobals.device[i].ethernetBytes, ',', numEntries);
    if(checkFilter(filter, "ipBytes"))
      wrtLlongItm(fDescr, lang, "\t", "ipBytes",myGlobals.device[i].ipBytes, ',', numEntries);

    if(!shortView) {
      if(checkFilter(filter, "fragmentedIpBytes"))
	wrtLlongItm(fDescr, lang, "\t", "fragmentedIpBytes",myGlobals.device[i].fragmentedIpBytes, ',', numEntries);
    }

    if(checkFilter(filter, "tcpBytes"))
      wrtLlongItm(fDescr, lang, "\t", "tcpBytes",myGlobals.device[i].tcpBytes, ',', numEntries);
    if(checkFilter(filter, "udpBytes"))
      wrtLlongItm(fDescr, lang, "\t", "udpBytes",myGlobals.device[i].udpBytes, ',', numEntries);
    if(checkFilter(filter, "otherIpBytes"))
      wrtLlongItm(fDescr, lang, "\t", "otherIpBytes",myGlobals.device[i].otherIpBytes, ',', numEntries);
    if(checkFilter(filter, "icmpBytes"))
      wrtLlongItm(fDescr, lang, "\t", "icmpBytes",myGlobals.device[i].icmpBytes, ',', numEntries);
    if(checkFilter(filter, "dlcBytes"))
      wrtLlongItm(fDescr, lang, "\t", "dlcBytes",myGlobals.device[i].dlcBytes, ',', numEntries);

    if(checkFilter(filter, "ipxBytes"))
      wrtLlongItm(fDescr, lang, "\t", "ipxBytes",myGlobals.device[i].ipxBytes, ',', numEntries);
    if(checkFilter(filter, "stpBytes"))
      wrtLlongItm(fDescr, lang, "\t", "stpBytes",myGlobals.device[i].stpBytes, ',', numEntries);
    if(checkFilter(filter, "decnetBytes"))
      wrtLlongItm(fDescr, lang, "\t", "decnetBytes",myGlobals.device[i].decnetBytes, ',', numEntries);
    if(checkFilter(filter, "netbiosBytes"))
      wrtLlongItm(fDescr, lang, "\t", "netbiosBytes",myGlobals.device[i].netbiosBytes, ',', numEntries);
    if(checkFilter(filter, "arpRarpBytes"))
      wrtLlongItm(fDescr, lang, "\t", "arpRarpBytes",myGlobals.device[i].arpRarpBytes, ',', numEntries);
    if(checkFilter(filter, "atalkBytes"))
      wrtLlongItm(fDescr, lang, "\t", "atalkBytes",myGlobals.device[i].atalkBytes, ',', numEntries);
    if(checkFilter(filter, "egpBytes"))
      wrtLlongItm(fDescr, lang, "\t", "egpBytes",myGlobals.device[i].egpBytes, ',', numEntries);
    if(checkFilter(filter, "osiBytes"))
      wrtLlongItm(fDescr, lang, "\t", "osiBytes",myGlobals.device[i].osiBytes, ',', numEntries);
    if(checkFilter(filter, "ipv6Bytes"))
      wrtLlongItm(fDescr, lang, "\t", "ipv6Bytes",myGlobals.device[i].ipv6Bytes, ',', numEntries);
    if(checkFilter(filter, "otherBytes"))
      wrtLlongItm(fDescr, lang, "\t", "otherBytes",myGlobals.device[i].otherBytes, ',', numEntries);

    if(!shortView) {
      if(checkFilter(filter, "lastMinEthernetBytes"))
	wrtLlongItm(fDescr, lang, "\t", "lastMinEthernetBytes",
		    myGlobals.device[i].lastMinEthernetBytes, ',', numEntries);
      if(checkFilter(filter, "lastFiveMinsEthernetBytes"))
	wrtLlongItm(fDescr, lang, "\t", "lastFiveMinsEthernetBytes",
		    myGlobals.device[i].lastFiveMinsEthernetBytes, ',', numEntries);
      if(checkFilter(filter, "lastMinEthernetPkts"))
	wrtLlongItm(fDescr, lang, "\t", "lastMinEthernetPkts",myGlobals.device[i].lastMinEthernetPkts, ',', numEntries);
      if(checkFilter(filter, "lastFiveMinsEthernetPkts"))
	wrtLlongItm(fDescr, lang, "\t", "lastFiveMinsEthernetPkts",
		    myGlobals.device[i].lastFiveMinsEthernetPkts, ',', numEntries);
      if(checkFilter(filter, "upTo64"))
	wrtLlongItm(fDescr, lang, "\t", "upTo64",myGlobals.device[i].rcvdPktStats.upTo64, ',', numEntries);
      if(checkFilter(filter, "upTo128"))
	wrtLlongItm(fDescr, lang, "\t", "upTo128",myGlobals.device[i].rcvdPktStats.upTo128, ',', numEntries);
      if(checkFilter(filter, "upTo256"))
	wrtLlongItm(fDescr, lang, "\t", "upTo256",myGlobals.device[i].rcvdPktStats.upTo256, ',', numEntries);
      if(checkFilter(filter, "upTo512"))
	wrtLlongItm(fDescr, lang, "\t", "upTo512",myGlobals.device[i].rcvdPktStats.upTo512, ',', numEntries);
      if(checkFilter(filter, "upTo1024"))
	wrtLlongItm(fDescr, lang, "\t", "upTo1024",myGlobals.device[i].rcvdPktStats.upTo1024, ',', numEntries);
      if(checkFilter(filter, "upTo1518"))
	wrtLlongItm(fDescr, lang, "\t", "upTo1518",myGlobals.device[i].rcvdPktStats.upTo1518, ',', numEntries);
      if(checkFilter(filter, "above1518"))
	wrtLlongItm(fDescr, lang, "\t", "above1518",myGlobals.device[i].rcvdPktStats.above1518, ',', numEntries);
      if(checkFilter(filter, "shortest"))
	wrtLlongItm(fDescr, lang, "\t", "shortest",myGlobals.device[i].rcvdPktStats.shortest, ',', numEntries);
      if(checkFilter(filter, "longest"))
	wrtLlongItm(fDescr, lang, "\t", "longest",myGlobals.device[i].rcvdPktStats.longest, ',', numEntries);
      if(checkFilter(filter, "badChecksum"))
	wrtLlongItm(fDescr, lang, "\t", "badChecksum",myGlobals.device[i].rcvdPktStats.badChecksum, ',', numEntries);
      if(checkFilter(filter, "tooLong"))
	wrtLlongItm(fDescr, lang, "\t", "tooLong",myGlobals.device[i].rcvdPktStats.tooLong, ',', numEntries);
      if(checkFilter(filter, "peakThroughput"))
	wrtFloatItm(fDescr, lang, "\t", "peakThroughput",myGlobals.device[i].peakThroughput, ',', numEntries);
      if(checkFilter(filter, "actualThpt"))
	wrtFloatItm(fDescr, lang, "\t", "actualThpt",myGlobals.device[i].actualThpt, ',', numEntries);
      if(checkFilter(filter, "lastMinThpt"))
	wrtFloatItm(fDescr, lang, "\t", "lastMinThpt",myGlobals.device[i].lastMinThpt, ',', numEntries);
      if(checkFilter(filter, "lastFiveMinsThpt"))
	wrtFloatItm(fDescr, lang, "\t", "lastFiveMinsThpt",myGlobals.device[i].lastFiveMinsThpt, ',', numEntries);
      if(checkFilter(filter, "peakPacketThroughput"))
	wrtFloatItm(fDescr, lang, "\t", "peakPacketThroughput",myGlobals.device[i].peakPacketThroughput, ',', numEntries);
      if(checkFilter(filter, "actualPktsThpt"))
	wrtFloatItm(fDescr, lang, "\t", "actualPktsThpt",myGlobals.device[i].actualPktsThpt, ',', numEntries);
      if(checkFilter(filter, "lastMinPktsThpt"))
	wrtFloatItm(fDescr, lang, "\t", "lastMinPktsThpt",myGlobals.device[i].lastMinPktsThpt, ',', numEntries);
      if(checkFilter(filter, "lastFiveMinsPktsThpt"))
	wrtFloatItm(fDescr, lang, "\t", "lastFiveMinsPktsThpt",myGlobals.device[i].lastFiveMinsPktsThpt, ',', numEntries);
      if(checkFilter(filter, "throughput"))
	wrtFloatItm(fDescr, lang, "\t", "throughput", myGlobals.device[i].throughput, ',', numEntries);
      if(checkFilter(filter, "packetThroughput"))
	wrtFloatItm(fDescr, lang, "\t", "packetThroughput",myGlobals.device[i].packetThroughput, ',', numEntries);

      /* ********************************* */

      if(checkFilter(filter, "last60MinutesThpt")) {
	initWriteKey(fDescr, lang, "\t", "last60MinutesThpt", numEntries);

	for(j=0; j<59; j++) {
	  wrtIntFloatItm(fDescr, lang,"\t\t",j+1, myGlobals.device[i].last60MinutesThpt[j].trafficValue, ',', numEntries);
	}
	wrtIntFloatItm(fDescr, lang,"\t\t",j+1, myGlobals.device[i].last60MinutesThpt[j].trafficValue, ' ', numEntries);
	endWriteKey(fDescr, lang,"\t", "last60MinutesThpt", ',');
      }

      /* ********************************* */

      if(checkFilter(filter, "last24HoursThpt")) {
	initWriteKey(fDescr, lang, "\t", "last24HoursThpt", numEntries);

	for(j=0; j<23; j++) {
	  wrtIntFloatItm(fDescr, lang, "\t\t", j+1, myGlobals.device[i].last24HoursThpt[j].trafficValue, ',', numEntries);
	}
	wrtIntFloatItm(fDescr, lang,"\t\t",j+1,myGlobals.device[i].last24HoursThpt[j].trafficValue, ' ', numEntries);
	endWriteKey(fDescr, lang,"\t", "last24HoursThpt", ',');
      }
      /* ********************************* */

      if(checkFilter(filter, "last30daysThpt")) {
	initWriteKey(fDescr, lang, "\t", "last30daysThpt", numEntries);

	for(j=0; j<29; j++) {
	  wrtIntFloatItm(fDescr, lang,"\t\t",j+1,myGlobals.device[i].last30daysThpt[j], ',', numEntries);
	}
	wrtIntFloatItm(fDescr, lang,"\t\t",j+1,myGlobals.device[i].last30daysThpt[j], ' ', numEntries);
	endWriteKey(fDescr, lang,"\t", "last30daysThpt", ',');
      }
    }

    /* ********************************* */

    if(checkFilter(filter, "IP")) {
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
	    TrafficCounter ctr;

	    ctr.value =
	      myGlobals.device[i].ipProtoStats[j].local.value+
	      myGlobals.device[i].ipProtoStats[j].local2remote.value+
	      myGlobals.device[i].ipProtoStats[j].remote2local.value+
	      myGlobals.device[i].ipProtoStats[j].remote.value;

	    wrtLlongItm(fDescr, lang, "\t",  myGlobals.protoIPTrafficInfos[j],
			ctr, ',', numEntries);
	  }
	}


	if(!shortView) {
	  if(hostKey != NULL) endWriteKey(fDescr, lang,"\t\t", hostKey, ',');
	  endWriteKey(fDescr, lang,"\t", "IP", ',');
	}
      }
    }

    /* ********************************* */

    if(checkFilter(filter, "securityPkts")) {
	initWriteKey(fDescr, lang, "\t", "securityPkts", numEntries);
	wrtLlongItm(fDescr, lang, "\t", "synPkts", myGlobals.device[i].securityPkts.synPkts, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "rstPkts", myGlobals.device[i].securityPkts.rstPkts, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "rstAckPkts", myGlobals.device[i].securityPkts.rstAckPkts, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "synFinPkts", myGlobals.device[i].securityPkts.synFinPkts, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "finPushUrgPkts", myGlobals.device[i].securityPkts.finPushUrgPkts, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "nullPkts", myGlobals.device[i].securityPkts.nullPkts, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "ackXmasFinSynNullScan", myGlobals.device[i].securityPkts.ackXmasFinSynNullScan, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "rejectedTCPConn", myGlobals.device[i].securityPkts.rejectedTCPConn, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "establishedTCPConn", myGlobals.device[i].securityPkts.establishedTCPConn, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "terminatedTCPConn", myGlobals.device[i].securityPkts.terminatedTCPConn, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "udpToClosedPort", myGlobals.device[i].securityPkts.udpToClosedPort, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "udpToDiagnosticPort", myGlobals.device[i].securityPkts.udpToDiagnosticPort, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "tcpToDiagnosticPort", myGlobals.device[i].securityPkts.tcpToDiagnosticPort, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "tinyFragment", myGlobals.device[i].securityPkts.tinyFragment, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "icmpFragment", myGlobals.device[i].securityPkts.icmpFragment, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "overlappingFragment", myGlobals.device[i].securityPkts.overlappingFragment, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "closedEmptyTCPConn", myGlobals.device[i].securityPkts.closedEmptyTCPConn, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "icmpPortUnreach", myGlobals.device[i].securityPkts.icmpPortUnreach, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "icmpHostNetUnreach", myGlobals.device[i].securityPkts.icmpHostNetUnreach, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "icmpProtocolUnreach", myGlobals.device[i].securityPkts.icmpProtocolUnreach, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "icmpAdminProhibited", myGlobals.device[i].securityPkts.icmpAdminProhibited, ',', numEntries);
	wrtLlongItm(fDescr, lang, "\t", "malformedPkts", myGlobals.device[i].securityPkts.malformedPkts, ',', numEntries);
	endWriteKey(fDescr, lang,"\t", "securityPkts", ',');
    }

    /* ********************************* */

    if(!shortView) {
      if(checkFilter(filter, "tcpLocal"))
	wrtLlongItm(fDescr, lang,"\t","tcpLocal",
		    myGlobals.device[i].tcpGlobalTrafficStats.local, ',', numEntries);
      if(checkFilter(filter, "tcpLocal2Rem"))
	wrtLlongItm(fDescr, lang,"\t","tcpLocal2Rem",
		    myGlobals.device[i].tcpGlobalTrafficStats.local2remote, ',', numEntries);
      if(checkFilter(filter, "tcpRem"))
	wrtLlongItm(fDescr, lang,"\t","tcpRem",
		    myGlobals.device[i].tcpGlobalTrafficStats.remote, ',', numEntries);
      if(checkFilter(filter, "tcpRem2Local"))
	wrtLlongItm(fDescr, lang,"\t","tcpRem2Local",
		    myGlobals.device[i].tcpGlobalTrafficStats.remote2local, ',', numEntries);

      /* ********************************* */

      if(checkFilter(filter, "udpLocal"))
	wrtLlongItm(fDescr, lang,"\t","udpLocal",
		    myGlobals.device[i].udpGlobalTrafficStats.local, ',', numEntries);
      if(checkFilter(filter, "udpLocal2Rem"))
	wrtLlongItm(fDescr, lang,"\t","udpLocal2Rem",
		    myGlobals.device[i].udpGlobalTrafficStats.local2remote, ',', numEntries);
      if(checkFilter(filter, "udpRem"))
	wrtLlongItm(fDescr, lang,"\t","udpRem",
		    myGlobals.device[i].udpGlobalTrafficStats.remote, ',', numEntries);
      if(checkFilter(filter, "udpRem2Local"))
	wrtLlongItm(fDescr, lang,"\t","udpRem2Local",
		    myGlobals.device[i].udpGlobalTrafficStats.remote2local, ',', numEntries);

      /* ********************************* */

      if(checkFilter(filter, "icmpLocal"))
	wrtLlongItm(fDescr, lang,"\t","icmpLocal",
		    myGlobals.device[i].icmpGlobalTrafficStats.local, ',', numEntries);
      if(checkFilter(filter, "icmpLocal2Rem"))
	wrtLlongItm(fDescr, lang,"\t","icmpLocal2Rem",
		    myGlobals.device[i].icmpGlobalTrafficStats.local2remote, ',', numEntries);
      if(checkFilter(filter, "icmpRem"))
	wrtLlongItm(fDescr, lang,"\t","icmpRem",
		    myGlobals.device[i].icmpGlobalTrafficStats.remote, ',', numEntries);
      if(checkFilter(filter, "icmpRem2Local"))
	wrtLlongItm(fDescr, lang,"\t","icmpRem2Local",
		    myGlobals.device[i].icmpGlobalTrafficStats.remote2local, ' ', numEntries);
    }

    numEntries++;
    if((lang == FLAG_NO_LANGUAGE) && (numEntries == 1)) goto REPEAT;
  }

  if(numEntries > 0) endWriteKey(fDescr, lang, "", (lang == FLAG_XML_LANGUAGE) ? "device-information" : keyName, ' ');
  endWriteArray(fDescr, lang);
}
