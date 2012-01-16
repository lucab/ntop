/*
 *  Copyright (C) 2001-10 Luca Deri <deri@ntop.org>
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
char *languages[] = { "", "perl", "php", "xml", "python", "json", "no" };

/* *************************** */

static void sendEmitterString(FILE *fDescr, char *theString) {

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "sendEmitterString(%X, '%s')", fDescr, theString);
#endif

  if(fDescr == NULL)
    sendString(theString);
  else
    fprintf(fDescr, "%s", theString);
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
  case FLAG_JSON_LANGUAGE:
    sendEmitterString(fDescr, "{ \"ntop\": [");
    break;
  case FLAG_XML_LANGUAGE:
    sendEmitterString(fDescr, "<rpc-reply xmlns:ntop=\"http://www.ntop.org/ntop.dtd\">"
		      "\n<ntop-traffic-information>\n");
    break ;
  case FLAG_NO_LANGUAGE:
    break ;
  }
}

/* *************************** */

static void endWriteArray(FILE *fDescr, int lang, unsigned int numEntries) {
  char buf[256];

  switch(lang) {
  case FLAG_PERL_LANGUAGE:
  case FLAG_PHP_LANGUAGE:
    sendEmitterString(fDescr, ");\n");
    break ;
  case FLAG_PYTHON_LANGUAGE:
    sendEmitterString(fDescr, "}\n");
    break;
  case FLAG_JSON_LANGUAGE:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "], \"totalRecords\":%d\n}\n", numEntries);
    sendEmitterString(fDescr, buf);
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
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s'%s' => {\n",indent, keyName);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_PHP_LANGUAGE:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s'%s' => array(\n",indent, keyName);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_PYTHON_LANGUAGE:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s'%s': {\n",indent, keyName);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_JSON_LANGUAGE:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "{ \"host_key\": \"%s\",", keyName);
    sendEmitterString(fDescr, buf);
    break;
  case FLAG_XML_LANGUAGE:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s<%s>\n", indent, keyName);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_NO_LANGUAGE:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s|",
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
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),"%s}%c\n",indent,last);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_PHP_LANGUAGE:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),"%s)%c\n",indent,last);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_XML_LANGUAGE:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s</%s>\n",indent, keyName);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_PYTHON_LANGUAGE:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),"%s}%c\n",indent, last);
    sendEmitterString(fDescr, buf);
    break ;
  case FLAG_JSON_LANGUAGE:
    if(last) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf)," \"dummy\": 1");
      sendEmitterString(fDescr, buf);
    }

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),"}%c\n", last);
    sendEmitterString(fDescr, buf);
    break;
  case FLAG_NO_LANGUAGE:
    if(strcmp(indent, "") == 0) sendEmitterString(fDescr, "\n");
    break ;
  }
}

/* *************************** */

static char* sanitize(char *value, char *buf, int buf_len) {
  int i, j = 0;

  for(i=0, j; (i<strlen(value)) && (i<buf_len); i++) {
    switch(value[i]) {
    case '\'':
    case '\"':
      break;
    default:
      buf[j++] = value[i];
      break;
    }
  }

  buf[j] = '\0';
  return(buf);
}

/* *************************** */

static void wrtKV(FILE *fDescr, int lang, char *indent, char *name,
		      char *value, char last, int numEntriesSent) {
  char buf[256];

  validateString(name);

  switch(lang) {
  case FLAG_PERL_LANGUAGE:
  case FLAG_PHP_LANGUAGE:
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s'%s' => %s%c\n",
		      indent, name, value, last);
	sendEmitterString(fDescr, buf);
    break ;
  case FLAG_XML_LANGUAGE:
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s<%s>%s</%s>\n", 
		       indent, name, value, name);
	sendEmitterString(fDescr, buf);
    break ;
  case FLAG_PYTHON_LANGUAGE:
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s'%s': %s%c\n", 
		      indent, name, value, last);
 	sendEmitterString(fDescr, buf);
     break ;
  case FLAG_JSON_LANGUAGE:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), " \"%s\": %s,", 
		  name, value);
    sendEmitterString(fDescr, buf);
     break ;    
  case FLAG_NO_LANGUAGE:
    if(value != NULL) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s|", 
		    numEntriesSent == 0 ? name : value);
      sendEmitterString(fDescr, buf);
    } else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s|", 
		    numEntriesSent == 0 ? name : "");
      sendEmitterString(fDescr, buf);
    }
    break ;
  }
}

/* *************************** */

static void wrtStrItm(FILE *fDescr, int lang, char *indent, char *name,
              char *value, char last, int numEntriesSent) {
  char buf[256], buf1[256];
  if ((value != NULL) && (value[0] != '\0')) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  (lang == FLAG_XML_LANGUAGE) ? "%s" : ((lang == FLAG_JSON_LANGUAGE) ? "\"%s\"" : "'%s'"),
                sanitize(value, buf1, sizeof(buf1)));
    wrtKV(fDescr, lang, indent, name, buf, last, numEntriesSent);
  }
}

/* *************************** */

static void wrtIntItm(FILE *fDescr, int lang, char *indent, char *name,
		      int value, char last, int numEntriesSent) {
  char buf[80];
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",value);
  wrtKV(fDescr, lang, indent, name, buf, last, numEntriesSent);
}

/* *************************** */

#if 0
static void wrtIntStrItm(FILE *fDescr, int lang, char *indent,int name,
			 char *value, char useless, int numEntriesSent) {
  char buf[80];
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",name);
  wrtKV(fDescr, lang, indent, buf, value, ',', numEntriesSent);
}
#endif

/* *************************** */

static void wrtUintItm(FILE *fDescr, int lang, char *indent, char *name,
		       unsigned int value, char useless, int numEntriesSent) {
  char buf[80];
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",value);
  wrtKV(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

static void wrtUcharItm(FILE *fDescr, int lang, char *indent, char *name,
			u_char value, char useless, int numEntriesSent) {
  char buf[80];
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",value);
  wrtKV(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

static void wrtFloatItm(FILE *fDescr, int lang, char *indent, char *name,
			float value, char last, int numEntriesSent) {
  char buf[80];
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%0.2f",value);
  wrtKV(fDescr, lang, indent, name, buf, last, numEntriesSent);
}

/* *************************** */

#if 0
static void wrtIntFloatItm(FILE *fDescr, int lang, char *indent, int name,
			   float value, char last, int numEntriesSent) {
  char buf[80];
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", name);
  wrtFloatItm(fDescr, lang, indent, (lang == FLAG_XML_LANGUAGE) ? "number" : buf,
	      value, last, numEntriesSent);
}
#endif

/* *************************** */

static void wrtUlongItm(FILE *fDescr, int lang, char *indent, char *name,
			unsigned long value, char useless, int numEntriesSent) {
  char buf[80];

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%lu",value);
  wrtKV(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

static void wrtLlongItm(FILE *fDescr, int lang, char* indent, char* name,
			TrafficCounter value, char last, int numEntriesSent) {
  char buf[80];

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),  "%llu", value.value);
  wrtKV(fDescr, lang, indent, name, buf, last, numEntriesSent);
}

/* *************************** */

static void wrtTime_tItm(FILE *fDescr, int lang, char *indent, char *name,
			 time_t value, char useless, int numEntriesSent) {
  char buf[80];
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%ld",value);
  wrtKV(fDescr, lang, indent, name, buf, ',', numEntriesSent);
}

/* *************************** */

static void wrtUshortItm(FILE *fDescr, int lang, char *indent, char *name,
			 u_short value, char useless, int numEntriesSent) {
  char buf[80];
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",value);
  wrtKV(fDescr, lang, indent, name, buf, ',', numEntriesSent);
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
	  for(j=1;j < MAX_FLAG_LANGUGE;j++) {
	    if(strcasecmp(&tmpStr[i+1], languages[j]) == 0) {
	      lang = j;
	      break;
	    }
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

  if(numEntries > 0) endWriteArray(fDescr, lang, numEntries);
}

/* ********************************** */

static void updateRefCount(HostTraffic *el, int value) {
  if(el->refCount == 0) return;

  lockHostsHashMutex(el, "decrementRefCount");
  el->refCount += value;
  unlockHostsHashMutex(el);
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
	  for(j=1;j < MAX_FLAG_LANGUGE;j++) {
	    if(strcasecmp(&tmpStr[i+1], languages[j]) == 0) {
	      lang = j;
	      break;
	    }
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

    updateRefCount(el, 1);

    strncpy(workSymIpAddress, el->hostResolvedName, MAX_LEN_SYM_HOST_NAME_HTML);

    if((angleLocation = strchr(workSymIpAddress, '<')) != NULL)
      angleLocation[0] = '\0';

    if(key[0] != '\0') {
      if(strcmp(el->hostNumIpAddress, key)
	 && strcmp(el->ethAddressString, key)
	 && strcmp(workSymIpAddress, key)) {
	updateRefCount(el, -1);
	continue;
      }
    }

    if(el->hostNumIpAddress[0] != '\0') {
      hostKey = el->hostNumIpAddress;
      if(localView) {
	if(((!subnetPseudoLocalHost(el))
	    && (!multicastHost(el)))) {
	  updateRefCount(el, -1);
	  continue;
	}
      }
    } else {
      if(localView) { 	updateRefCount(el, -1); continue; }
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
      }
    }

    if(checkFilter(filter, "pktsSent"))
      wrtLlongItm(fDescr, lang, "\t", "pktsSent",   el->pktsSent, ',', numEntries);
    if(checkFilter(filter, "pktsRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "pktsRcvd", el->pktsRcvd, ',', numEntries);

    if(checkFilter(filter, "ipv4BytesSent"))
      wrtLlongItm(fDescr, lang, "\t", "ipv4BytesSent", el->ipv4BytesSent, ',', numEntries);
    if(checkFilter(filter, "ipv4BytesRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "ipv4BytesRcvd", el->ipv4BytesRcvd, ',', numEntries);

    /* *************************************** */

    if(!shortView) {
      if(checkFilter(filter, "pktsDuplicatedAckSent"))
	wrtLlongItm(fDescr, lang, "\t", "pktsDuplicatedAckSent",el->pktsDuplicatedAckSent, ',', numEntries);
      if(checkFilter(filter, "pktsDuplicatedAckRcvd"))
	wrtLlongItm(fDescr, lang, "\t", "pktsDuplicatedAckRcvd",el->pktsDuplicatedAckRcvd, ',', numEntries);
      if(checkFilter(filter, "pktsBroadcastSent"))
	wrtLlongItm(fDescr, lang, "\t", "pktsBroadcastSent",  el->pktsBroadcastSent, ',', numEntries);
    }

    if(checkFilter(filter, "bytesMulticastSent"))
      wrtLlongItm(fDescr, lang, "\t", "bytesMulticastSent", el->bytesMulticastSent, ',', numEntries);
    if(checkFilter(filter, "pktsMulticastSent"))
      wrtLlongItm(fDescr, lang, "\t", "pktsMulticastSent",  el->pktsMulticastSent, ',', numEntries);

    if(checkFilter(filter, "bytesMulticastRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "bytesMulticastRcvd", el->bytesMulticastRcvd, ',', numEntries);
    if(checkFilter(filter, "pktsMulticastRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "pktsMulticastRcvd",  el->pktsMulticastRcvd, ',', numEntries);

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

      if(checkFilter(filter, "actualThpt"))
	wrtFloatItm(fDescr, lang, "\t", "actualThpt",  el->actualThpt, ',', numEntries);
      if(checkFilter(filter, "averageThpt"))
	wrtFloatItm(fDescr, lang, "\t", "averageThpt", el->averageThpt, ',', numEntries);
      if(checkFilter(filter, "peakThpt"))
	wrtFloatItm(fDescr, lang, "\t", "peakThpt",    el->peakThpt, ',', numEntries);
    }

    if(checkFilter(filter, "ipv6BytesSent"))
      wrtLlongItm(fDescr, lang, "\t", "ipv6BytesSent", el->ipv6BytesSent, ',', numEntries);
    if(checkFilter(filter, "ipv6BytesRcvd"))
      wrtLlongItm(fDescr, lang, "\t", "ipv6BytesRcvd", el->ipv6BytesRcvd, ',', numEntries);

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
      if(checkFilter(filter, "greSent"))
	wrtLlongItm(fDescr, lang, "\t", "greSent", el->greSent, ',', numEntries);
      if(checkFilter(filter, "greRcvd"))
	wrtLlongItm(fDescr, lang, "\t", "greRcvd", el->greRcvd, ',', numEntries);
      if(checkFilter(filter, "ipsecSent"))
	wrtLlongItm(fDescr, lang, "\t", "ipsecSent", el->ipsecSent, ',', numEntries);
      if(checkFilter(filter, "ipsecRcvd"))
	wrtLlongItm(fDescr, lang, "\t", "ipsecRcvd", el->ipsecRcvd, ',', numEntries);
      
      /* ***************************** */

      if(el->nonIPTraffic != NULL) {
	if(checkFilter(filter, "stpSent"))
	  wrtLlongItm(fDescr, lang, "\t", "stpSent", el->nonIPTraffic->stpSent, ',', numEntries);
	if(checkFilter(filter, "stpRcvd"))
	  wrtLlongItm(fDescr, lang, "\t", "stpRcvd", el->nonIPTraffic->stpRcvd, ',', numEntries);
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

    updateRefCount(el, -1);
  } /* for */

  if(numEntries > 0) endWriteKey(fDescr, lang,"", (lang == FLAG_XML_LANGUAGE) ? "host-information" : hostKey, ' ');

  endWriteArray(fDescr, lang, numEntries);
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
	  for(j=1;j < MAX_FLAG_LANGUGE;j++) {
	    if(strcmp(&tmpStr[i+1], languages[j]) == 0) {
	      lang = j;
	      break;
	    }
	  }
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }

  initWriteArray(fDescr, lang);
  
  if (lang == FLAG_XML_LANGUAGE)
    sendEmitterString(fDescr, "<keys>\n");

  for(el=getFirstHost(actualDeviceId);
      el != NULL; el = getNextHost(actualDeviceId, el)) {

    lockHostsHashMutex(el, "dumpNtopHashes");

    if(!broadcastHost(el)) {
      char *hostKey;
      char *hostName = "Unknown";
      
      if(el->hostNumIpAddress[0] != '\0') {
        hostKey = el->hostNumIpAddress;
        if ((el->hostResolvedName != NULL) && (el->hostResolvedName[0] != '\0'))
          hostName = el->hostResolvedName;
      }
      else {
        hostKey = el->ethAddressString;
      }
      if (lang == FLAG_XML_LANGUAGE)
        wrtStrItm(fDescr, lang, "\t", "item", hostKey, '\n', numEntries);
      else
        wrtStrItm(fDescr, lang, "", hostKey, hostName, ',', numEntries);        

      numEntries++;
    }

    unlockHostsHashMutex(el);
  } /* for */
  
  if (lang == FLAG_XML_LANGUAGE)
    sendEmitterString(fDescr, "</keys>\n");

  endWriteArray(fDescr, lang, numEntries);
}

/* ********************************** */

void dumpNtopTrafficInfo(FILE *fDescr, char* options) {
  char intoabuf[32], key[16], localbuf[32], filter[128], *keyName = NULL;
  int lang=DEFAULT_FLAG_LANGUAGE, i, numEntries;
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
	  for(j=1;j < MAX_FLAG_LANGUGE;j++) {
	    if(strcmp(&tmpStr[i+1], languages[j]) == 0) {
	      lang = j;
	      break;
	    }
	  }
	} else if(strcmp(tmpStr, "key") == 0) {
	  strncpy(key, &tmpStr[i+1], sizeof(key));
	} else if(strcmp(tmpStr, "view") == 0) {
	  if(!strcmp(&tmpStr[i+1], "short")) shortView = 1;
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

      safe_snprintf(__FILE__, __LINE__, localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].network, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, "network"))
	wrtStrItm(fDescr, lang, "\t", "network", localbuf, ',', numEntries);
      safe_snprintf(__FILE__, __LINE__, localbuf, sizeof(localbuf), "%s",
	       _intoa(myGlobals.device[i].netmask, intoabuf, sizeof(intoabuf)));
      if(checkFilter(filter, "netmask"))
	wrtStrItm(fDescr, lang, "\t", "netmask", localbuf, ',', numEntries);
      safe_snprintf(__FILE__, __LINE__, localbuf, sizeof(localbuf), "%s",
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
    if(checkFilter(filter, "ipv4Bytes"))
      wrtLlongItm(fDescr, lang, "\t", "ipBytes",myGlobals.device[i].ipv4Bytes, ',', numEntries);

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

    if(checkFilter(filter, "stpBytes"))
      wrtLlongItm(fDescr, lang, "\t", "stpBytes",myGlobals.device[i].stpBytes, ',', numEntries);
    if(checkFilter(filter, "ipsecBytes"))
      wrtLlongItm(fDescr, lang, "\t", "ipsecBytes",myGlobals.device[i].ipsecBytes, ',', numEntries);
    if(checkFilter(filter, "netbiosBytes"))
      wrtLlongItm(fDescr, lang, "\t", "netbiosBytes",myGlobals.device[i].netbiosBytes, ',', numEntries);
    if(checkFilter(filter, "arpRarpBytes"))
      wrtLlongItm(fDescr, lang, "\t", "arpRarpBytes",myGlobals.device[i].arpRarpBytes, ',', numEntries);
    if(checkFilter(filter, "greBytes"))
      wrtLlongItm(fDescr, lang, "\t", "greBytes",myGlobals.device[i].greBytes, ',', numEntries);
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
#ifdef MAKE_WITH_JUMBO_FRAMES
      if(checkFilter(filter, "upTo2500"))
	wrtLlongItm(fDescr, lang, "\t", "upTo2500",myGlobals.device[i].rcvdPktStats.upTo2500, ',', numEntries);
      if(checkFilter(filter, "upTo6500"))
	wrtLlongItm(fDescr, lang, "\t", "upTo6500",myGlobals.device[i].rcvdPktStats.upTo6500, ',', numEntries);
      if(checkFilter(filter, "upTo9000"))
	wrtLlongItm(fDescr, lang, "\t", "upTo9000",myGlobals.device[i].rcvdPktStats.upTo9000, ',', numEntries);
      if(checkFilter(filter, "above9000"))
	wrtLlongItm(fDescr, lang, "\t", "above9000",myGlobals.device[i].rcvdPktStats.above9000, ',', numEntries);
#else
      if(checkFilter(filter, "above1518"))
	wrtLlongItm(fDescr, lang, "\t", "above1518",myGlobals.device[i].rcvdPktStats.above1518, ',', numEntries);
#endif
      if(checkFilter(filter, "shortest"))
	wrtLlongItm(fDescr, lang, "\t", "shortest",myGlobals.device[i].rcvdPktStats.shortest, ',', numEntries);
      if(checkFilter(filter, "longest"))
	wrtLlongItm(fDescr, lang, "\t", "longest",myGlobals.device[i].rcvdPktStats.longest, ',', numEntries);
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
    }

    /* ********************************* */

    if(checkFilter(filter, "IP")) {
      char *hostKey = NULL;

      if(!shortView) { initWriteKey(fDescr, lang, "\t", "IP", numEntries); }

      for(j=0; j<myGlobals.l7.numSupportedProtocols; j++) {
	if(!shortView) {
	  TrafficCounter tc;
	  
	  if(j > 0) endWriteKey(fDescr, lang, "\t\t", hostKey, ',');
	  initWriteKey(fDescr, lang, "\t\t", (hostKey = getProtoName(0, j)), numEntries);
	  tc.value = myGlobals.device[i].l7.protoTraffic[j];
	  wrtLlongItm(fDescr, lang, "\t\t\t", "bytes", tc, ',', numEntries);
	} else {
	  TrafficCounter ctr;

	  ctr.value = myGlobals.device[i].l7.protoTraffic[j];

	  wrtLlongItm(fDescr, lang, "\t", getProtoName(0, j), ctr, ',', numEntries);
	}
      }

      if(!shortView) {
	if(hostKey != NULL) endWriteKey(fDescr, lang,"\t\t", hostKey, ',');
	endWriteKey(fDescr, lang,"\t", "IP", ',');
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
  endWriteArray(fDescr, lang, numEntries);
}
