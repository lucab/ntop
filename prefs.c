/**
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "ntop.h"

/* ******************************** */

/* #define DEBUG */

int fetchPrefsValue(char *key, char *value, int valueLen) {
  datum key_data;
  datum data_data;

  if(value == NULL) return(-1);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Entering fetchPrefValue()");
#endif
  value[0] = '\0';

  key_data.dptr  = key;
  key_data.dsize = strlen(key_data.dptr)+1;

  if(myGlobals.prefsFile == NULL) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Leaving fetchPrefValue()");
#endif
    return(-1); /* ntop is quitting... */
  }

  data_data = gdbm_fetch(myGlobals.prefsFile, key_data);

  memset(value, 0, valueLen);

  if(data_data.dptr != NULL) {
    int len = min(valueLen,data_data.dsize);
    strncpy(value, data_data.dptr, len);
    value[len] = '\0';
    free(data_data.dptr);
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Read %s=%s.", key, value); 
#endif
    return(0);
  } else
    return(-1);
}

/* ******************************** */

void storePrefsValue(char *key, char *value) {
  datum key_data;
  datum data_data;

  if((value == NULL) || (myGlobals.capturePackets == FLAG_NTOPSTATE_TERM)) return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG:DEBUG:  Entering storePrefsValue()");
#endif

  memset(&key_data, 0, sizeof(key_data));
  key_data.dptr   = key;
  key_data.dsize  = strlen(key_data.dptr)+1;

  memset(&data_data, 0, sizeof(data_data));
  data_data.dptr  = value;
  data_data.dsize = strlen(value)+1;

  if(myGlobals.prefsFile == NULL) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Leaving storePrefsValue()");
#endif
    ; /* ntop is quitting... */
  }

  if(gdbm_store(myGlobals.prefsFile, key_data, data_data, GDBM_REPLACE) != 0)
    traceEvent(CONST_TRACE_ERROR, "While adding %s=%s.", key, value);
  else {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Storing %s=%s.", key, value); 
#endif
  }
}

/* ******************************** */

void delPrefsValue (char *key) {
  datum key_data;

  if((key == NULL) || (myGlobals.capturePackets == FLAG_NTOPSTATE_TERM)) return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG:DEBUG:  Entering storePrefsValue()");
#endif

  memset(&key_data, 0, sizeof(key_data));
  key_data.dptr   = key;
  key_data.dsize  = strlen(key_data.dptr)+1;

  if(myGlobals.prefsFile == NULL) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Leaving storePrefsValue()");
#endif
    ; /* ntop is quitting... */
  }

  if(gdbm_delete (myGlobals.prefsFile, key_data) != 0)
    traceEvent(CONST_TRACE_ERROR, "While deleting %s", key);
  else {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Deleted %s", key); 
#endif
  }
}

/* ******************************** */

void processStrPref (char *key, char *value, char **globalVar, bool savePref)
{
  if (key == NULL) return;

  if (strcmp (value, "") == 0) {
    /* If a value is specified as NULL but the current value is not, delete
     * the pref. This is assumed to be the way the user will change such a
     * pref. 
     */
    if (*globalVar != NULL) {
      free (*globalVar);
      *globalVar = NULL;
      if (savePref) {
	delPrefsValue (key);
      }
    }
  }
  else {
    if (savePref) {

      if((strcmp(key, NTOP_PREF_DEVICES) == 0) 
	 && (*globalVar && (*globalVar[0] != '\0'))) {	    
	/* Values can be concatenated */
	char tmpValue[256];

	safe_snprintf(__FILE__, __LINE__, tmpValue, sizeof(tmpValue), "%s,%s", *globalVar, value);
	storePrefsValue (key, tmpValue);
	free(*globalVar);
	*globalVar = strdup (tmpValue);
	return;
      } else
	storePrefsValue (key, value);
    }

    if (*globalVar)
      free (*globalVar);

    if((value == NULL) || (value[0] == '\0'))
      *globalVar = NULL;
    else
      *globalVar = strdup (value);
  }
}

/* ******************************** */

void processIntPref (char *key, char *value, int *globalVar, bool savePref)
{
  char buf[512];
    
  if ((key == NULL) || (value == NULL)) return;

  if (savePref) {
    safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf),
		   "%d", atoi (value));
    storePrefsValue (key, buf);
  }
    
  *globalVar = atoi (value);
}

/* ******************************** */

void processBoolPref (char *key, bool value, bool *globalVar, bool savePref)
{
  char buf[512];
    
  if (key == NULL) return;

  if (savePref) {
    safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf),
		   "%d", value);
    storePrefsValue (key, buf);
  }

  *globalVar = value;
}

/* ******************************** */

bool processNtopPref (char *key, char *value, bool savePref, UserPref *pref) {
  bool startCap = FALSE;
  char buf[16], *tmpStr = NULL;
  int tmpInt;

  if(value == NULL) value = ""; /* Safer */
    
  if (strcmp(key, NTOP_PREF_DEVICES) == 0) {
    if ((pref->devices != NULL) &&
	(strcmp (pref->devices, value))) {
      startCap = TRUE;
    }

    if((pref->devices == NULL) || (strstr(pref->devices, value) == NULL))
      processStrPref (NTOP_PREF_DEVICES, value, &pref->devices, savePref);
  }
  else if (strcmp (key, NTOP_PREF_CAPFILE) == 0) {
    if (((value != NULL) &&
	 (((pref->rFileName != NULL) && (strcmp (pref->rFileName, value)))))
	|| ((value != NULL) && ((pref->rFileName == NULL)))) {
      startCap = TRUE;
    }
    processStrPref (NTOP_PREF_CAPFILE, value, &pref->rFileName, savePref);
  }
  else if (strcmp (key, NTOP_PREF_FILTER) == 0) {
    processStrPref (NTOP_PREF_FILTER, value,
		    &pref->currentFilterExpression, savePref);
  }
  else if (strcmp (key, NTOP_PREF_WEBPORT) == 0) {
    if (value != NULL) {
      stringSanityCheck(value);
      if(!isdigit(*value)) {
	traceEvent (CONST_TRACE_ERROR, "flag -w expects a numeric argument.\n");
	return(startCap);
      }

      /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
      if((pref->webAddr = strchr(value,':'))) {
	/* DS: Search for : to find xxx.xxx.xxx.xxx:port */
	/* This code is to be able to bind to a particular interface */
	if (savePref) {
	  storePrefsValue (key, value);                    
	}
	*pref->webAddr = '\0';
	pref->webPort = atoi(pref->webAddr+1);
	pref->webAddr = strdup (value);
      } else {
	processIntPref (NTOP_PREF_WEBPORT, value, &pref->webPort, savePref);
      }
    }
    else {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     DEFAULT_NTOP_WEB_PORT);
      value = buf;
      processIntPref (NTOP_PREF_WEBPORT, value, &pref->webPort, savePref);
    }
  }
#ifdef HAVE_OPENSSL
  else if (strcmp (key, NTOP_PREF_SSLPORT) == 0) {
    if (value != NULL) {
      stringSanityCheck(value);
      if(!isdigit(*value)) {
	traceEvent (CONST_TRACE_ERROR, "flag -w expects a numeric argument.\n");
	return(startCap);
      }

      tmpStr = strdup (value);
      /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
      if((pref->sslAddr = strchr(tmpStr,':'))) {
	/* DS: Search for : to find xxx.xxx.xxx.xxx:port */
	/* This code is to be able to bind to a particular interface */
	if (savePref) {
	  storePrefsValue (key, value);                    
	}
	*pref->sslAddr = '\0';
	pref->sslPort = atoi(pref->sslAddr+1);
	pref->sslAddr = value;
      } else {
	processIntPref (NTOP_PREF_SSLPORT, value, &pref->sslPort, savePref);
      }
    }
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     DEFAULT_NTOP_WEB_PORT);
      value = buf;
      processIntPref (NTOP_PREF_SSLPORT, value, &pref->sslPort, savePref);
    }
  }
#endif    
  else if (strcmp (key, NTOP_PREF_EN_SESSION) == 0) {
    processBoolPref (NTOP_PREF_EN_SESSION, TRUE,
		     &pref->enableSessionHandling, savePref);
  }
  else if (strcmp (key, NTOP_PREF_EN_PROTO_DECODE) == 0) {
    processBoolPref (NTOP_PREF_EN_PROTO_DECODE, TRUE,
		     &pref->enablePacketDecoding, savePref);
  }
  else if (strcmp (key, NTOP_PREF_FLOWSPECS) == 0) {
    processStrPref (NTOP_PREF_FLOWSPECS, value, &pref->flowSpecs, savePref);
  }
  else if (strcmp (key, NTOP_PREF_LOCALADDR) == 0) {
    processStrPref (NTOP_PREF_LOCALADDR, value, &pref->localAddresses,
		    savePref);
  }
  else if (strcmp (key, NTOP_PREF_SPOOLPATH) == 0) {
    processStrPref (NTOP_PREF_SPOOLPATH, value, &pref->spoolPath, savePref);
  }
  else if (strcmp (key, NTOP_PREF_STICKY_HOSTS) == 0) {
    processBoolPref (NTOP_PREF_STICKY_HOSTS, TRUE, &pref->stickyHosts,
		     savePref);
  }
  else if (strcmp (key, NTOP_PREF_TRACK_LOCAL) == 0) {
    processBoolPref (NTOP_PREF_TRACK_LOCAL, TRUE,
		     &pref->trackOnlyLocalHosts, savePref);
  }
  else if (strcmp (key, NTOP_PREF_NO_PROMISC) == 0) {
    processBoolPref (NTOP_PREF_NO_PROMISC, TRUE,
		     &pref->disablePromiscuousMode, savePref);
  }
  else if (strcmp (key, NTOP_PREF_DAEMON) == 0) {
    processBoolPref (NTOP_PREF_DAEMON, TRUE, &pref->daemonMode,
		     savePref);
  }
  else if (strcmp (key, NTOP_PREF_REFRESH_RATE) == 0) {
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     DEFAULT_NTOP_AUTOREFRESH_INTERVAL);
      value = buf;
    }
    processIntPref (NTOP_PREF_REFRESH_RATE, value, &pref->refreshRate,
		    savePref);
  }
  else if (strcmp (key, NTOP_PREF_MAXLINES) == 0) {
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     CONST_NUM_TABLE_ROWS_PER_PAGE);
      value = buf;
    }
    processIntPref (NTOP_PREF_MAXLINES, value, &pref->maxNumLines,
		    savePref);
  }
  else if (strcmp (key, NTOP_PREF_PRINT_FCORIP) == 0) {
    tmpInt = atoi (value);
    if (tmpInt == NTOP_PREF_VALUE_PRINT_IPONLY) {
      pref->printIpOnly = TRUE, pref->printFcOnly = FALSE;
    }
    else if (tmpInt == NTOP_PREF_VALUE_PRINT_FCONLY) {
      pref->printIpOnly = FALSE, pref->printFcOnly = TRUE;
    }
    else {
      pref->printIpOnly = FALSE, pref->printFcOnly = FALSE;
    }

    processIntPref (NTOP_PREF_PRINT_FCORIP, value, &tmpInt, savePref);
  }
  else if (strcmp (key, NTOP_PREF_NO_INVLUN) == 0) {
    processBoolPref (NTOP_PREF_NO_INVLUN, TRUE,
		     &pref->noInvalidLunDisplay, savePref);
  }
  else if (strcmp (key, NTOP_PREF_FILTER_EXTRA_FRM) == 0) {
    processBoolPref (NTOP_PREF_FILTER_EXTRA_FRM, TRUE,
		     &pref->filterExpressionInExtraFrame, savePref);
  }
  else if (strcmp (key, NTOP_PREF_W3C) == 0) {
    processBoolPref (NTOP_PREF_W3C, TRUE, &pref->w3c, savePref);
  }
  else if (strcmp (key, NTOP_PREF_IPV4V6) == 0) {
    processIntPref (NTOP_PREF_IPV4V6, value, &pref->ipv4or6, savePref);
  }
  else if (strcmp (key, NTOP_PREF_DOMAINNAME) == 0) {
    processStrPref (NTOP_PREF_DOMAINNAME, value, &tmpStr,
		    savePref);
    if (tmpStr != NULL) {
      strncpy (pref->domainName, tmpStr, sizeof (pref->domainName));
      free (tmpStr);      /* alloc'd in processStrPref() */
    }
  }
  else if (strcmp (key, NTOP_PREF_NUMERIC_IP) == 0) {
    processBoolPref (NTOP_PREF_NUMERIC_IP, TRUE, &pref->numericFlag,
		     savePref);
  }
  else if (strcmp (key, NTOP_PREF_PROTOSPECS) == 0) {
    processStrPref (NTOP_PREF_PROTOSPECS, value, &pref->protoSpecs,
		    savePref);
  }
  else if (strcmp (key, NTOP_PREF_P3PCP) == 0) {
    processStrPref (NTOP_PREF_P3PCP, value, &pref->P3Pcp, savePref);
  }
  else if (strcmp (key, NTOP_PREF_P3PURI) == 0) {
    processStrPref (NTOP_PREF_P3PURI, value, &pref->P3Puri, savePref);
  }
  else if (strcmp (key, NTOP_PREF_MAPPERURL) == 0) {
    processStrPref (NTOP_PREF_MAPPERURL, value, &pref->mapperURL, savePref);
  }
  else if (strcmp (key, NTOP_PREF_WWN_MAP) == 0) {
    processStrPref (NTOP_PREF_WWN_MAP, value, &pref->fcNSCacheFile,
		    savePref);
  }
  else if (strcmp (key, NTOP_PREF_MAXHASH) == 0) {
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     -1);
      value = buf;
    }
    processIntPref (NTOP_PREF_MAXHASH, value,
		    &pref->maxNumHashEntries, savePref);
  }
  else if (strcmp (key, NTOP_PREF_MERGEIF) == 0) {
    processBoolPref (NTOP_PREF_MERGEIF, TRUE,
		     &pref->mergeInterfaces, savePref);
  }
  else if (strcmp (key, NTOP_PREF_NO_ISESS_PURGE) == 0) {
    processBoolPref (NTOP_PREF_NO_ISESS_PURGE, TRUE,
		     &pref->disableInstantSessionPurge, savePref);
  }
#if !defined(WIN32) && defined(HAVE_PCAP_SETNONBLOCK)                
  else if (strcmp (key, NTOP_PREF_NOBLOCK) == 0) {
    processBoolPref (NTOP_PREF_NOBLOCK, TRUE,
		     &pref->setNonBlocking, savePref);
  }
#endif                
  else if (strcmp (key, NTOP_PREF_NO_STOPCAP) == 0) {
    processBoolPref (NTOP_PREF_NO_STOPCAP, TRUE,
		     &pref->disableStopcap, savePref);
  }
  else if (strcmp (key, NTOP_PREF_NO_TRUST_MAC) == 0) {
    processBoolPref (NTOP_PREF_NO_TRUST_MAC, TRUE,
		     &pref->dontTrustMACaddr, savePref);
  }
  else if (strcmp (key, NTOP_PREF_PCAP_LOGBASE) == 0) {
    processStrPref (NTOP_PREF_PCAP_LOGBASE, value,
		    &pref->pcapLogBasePath, savePref);
  }
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME                
  else if (strcmp (key, NTOP_PREF_USE_SSLWATCH) == 0) {
    processBoolPref (NTOP_PREF_USE_SSLWATCH, TRUE,
		     &pref->useSSLwatchdog, savePref);
  }
#endif                
  else if (strcmp (key, NTOP_PREF_DBG_MODE) == 0) {
    processBoolPref (NTOP_PREF_DBG_MODE, TRUE, &pref->debugMode,
		     savePref);
  }
  else if (strcmp (key, NTOP_PREF_TRACE_LVL) == 0) {
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     DEFAULT_TRACE_LEVEL);
      value = buf;
    }
    processIntPref (NTOP_PREF_TRACE_LVL, value, &pref->traceLevel,
		    savePref);
  }
  else if (strcmp (key, NTOP_PREF_DUMP_OTHER) == 0) {
    processBoolPref (NTOP_PREF_DUMP_OTHER, TRUE,
		     &pref->enableOtherPacketDump, savePref);
  }
  else if (strcmp (key, NTOP_PREF_DUMP_SUSP) == 0) {
    processBoolPref (NTOP_PREF_DUMP_SUSP, TRUE,
		     &pref->enableSuspiciousPacketDump, savePref);
  }
  else if (strcmp (key, NTOP_PREF_ACCESS_LOG) == 0) {
    processStrPref (NTOP_PREF_ACCESS_LOG, value,
		    &pref->accessLogFile,
		    savePref);
  }
#ifndef WIN32                
  else if (strcmp (key, NTOP_PREF_USE_SYSLOG) == 0) {
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     DEFAULT_NTOP_SYSLOG);
      value = buf;
    }
    processIntPref (NTOP_PREF_USE_SYSLOG, value,
		    &pref->useSyslog, savePref);
  }
#endif                
  else if (strcmp (key, NTOP_PREF_PCAP_LOG) == 0) {
    processStrPref (NTOP_PREF_PCAP_LOG, value, &pref->pcapLog, savePref);
  }
  else if (strcmp (key, NTOP_PREF_NO_MUTEX_EXTRA) == 0) {
    processBoolPref (NTOP_PREF_NO_MUTEX_EXTRA, TRUE,
		     &pref->disableMutexExtraInfo, savePref);
  }
#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)                
  else if (strcmp (key, NTOP_PREF_NO_SCHEDYLD) == 0) {
    processBoolPref (NTOP_PREF_NO_SCHEDYLD, TRUE,
		     &pref->disableSchedYield, savePref);
  }
#endif
  else if (strncmp (key, "ntop.", strlen ("ntop.")) == 0) {
    traceEvent (CONST_TRACE_WARNING, "Unknown preference: %s, value = %s\n",
		key, (value == NULL) ? "(null)" : value);
  }

  return (startCap);
}

