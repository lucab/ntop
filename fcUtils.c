/**
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *                          http://www.ntop.org
 *
 * Copyright (C) 2003 Dinesh G. Dutt <ddutt@cisco.com>
 * Copyright (C) 2003-04 Luca Deri <deri@ntop.org>
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
#include <stdarg.h>
#include <assert.h>
#include "fcUtils.h"

#ifdef MEMORY_DEBUG
#include "leaks.h"
#endif

/* **************************************** */

int isFlogiAcc (FcAddress *fcAddress, u_int8_t r_ctl, u_int8_t type, u_int8_t cmd)
{
  if (((fcAddress->domain == 0xFF) && (fcAddress->area == 0xFF) && (fcAddress->port == 0xFE)) && 
      ((r_ctl & 0xF0) == FC_RCTL_ELS) && (type == FC_TYPE_ELS) &&
      (cmd == FC_ELS_CMD_ACC)) {
    return (TRUE);
  }
  else {
    return (FALSE);
  }
}

/* **************************************** */

/* Routine to extract WWN from FLOGI frame */
int fillFcHostInfo (const u_char *bp, HostTraffic *srcHost)
{
  assert (bp != NULL);

  srcHost->fcCounters->fcRecvSize = ntohs ((u_short)bp[10] & 0xFFF);
  memcpy (srcHost->fcCounters->pWWN.str, &bp[20], LEN_WWN_ADDRESS);
  memcpy (srcHost->fcCounters->nWWN.str, &bp[28], LEN_WWN_ADDRESS);

  setResolvedName(srcHost, (char*)srcHost->fcCounters->pWWN.str,
		  FLAG_HOST_SYM_ADDR_TYPE_FC_WWN);

  return (0);
}

/* **************************************** */

/* Routine to extract WWN from PLOGI frame */
int isPlogi (u_int8_t r_ctl, u_int8_t type, u_int8_t cmd)
{
  if (((r_ctl & 0xF0) == FC_RCTL_ELS) && (type == FC_TYPE_ELS) &&
      (cmd == FC_ELS_CMD_PLOGI)) {
    return (TRUE);
  }
  else {
    return (FALSE);
  }
}

/* **************************************** */

int isLogout (u_int8_t r_ctl, u_int8_t type, u_int8_t cmd)
{
  if (((r_ctl & 0xF0) == FC_RCTL_ELS) && (type == FC_TYPE_ELS) &&
      (cmd == FC_ELS_CMD_LOGO)) {
    return (TRUE);
  }
  else {
    return (FALSE);
  }
}

/* **************************************** */

int isRscn (u_int8_t r_ctl, u_int8_t type, u_int8_t cmd)
{
  if (((r_ctl & 0xF0) == FC_RCTL_ELS) && (type == FC_TYPE_ELS) &&
      (cmd == FC_ELS_CMD_RSCN)) {
    return (TRUE);
  }
  else {
    return (FALSE);
  }
}

/* **************************************** */

HostTraffic *allocFcScsiCounters(HostTraffic *host) {
  if(host->fcCounters == NULL) {
    host->fcCounters = malloc(sizeof(FcScsiCounters));
    if(host->fcCounters == NULL) 
      return(NULL); /* Out of memory */
    
    memset(host->fcCounters, 0, sizeof(FcScsiCounters));
    host->fcCounters->vsanId = -1;
  }

  return(host);
}

/* **************************************** */

int fillFcpInfo (const u_char *bp, HostTraffic *srcHost, HostTraffic *dstHost)
{
  int offset = 0;
  u_int32_t fcpDl;
    
  assert (bp != NULL);
  assert (srcHost != NULL);
  assert (dstHost != NULL);
    
  if (bp[offset] == 0) {
    /* This is a single-level LUN */
  }

  fcpDl = ntohl (*(u_int32_t *)&bp[offset+28]);

  if(allocFcScsiCounters(srcHost) == NULL) return(0);
  if(allocFcScsiCounters(dstHost) == NULL) return(0);

  if (bp[offset+11] & 0x1) {
    incrementTrafficCounter (&srcHost->fcCounters->scsiWriteBytes, fcpDl);
    incrementTrafficCounter (&dstHost->fcCounters->scsiWriteBytes, fcpDl);
  }
  else if (bp[offset+11] & 0x2) {
    incrementTrafficCounter (&srcHost->fcCounters->scsiReadBytes, fcpDl);
    incrementTrafficCounter (&dstHost->fcCounters->scsiReadBytes, fcpDl);
  }

  return (0);
}

/* **************************************** */

FcFabricElementHash *getFcFabricElementHash (u_short vsanId, int actualDeviceId)
{
  FcFabricElementHash **theHash;
  u_int myIdx = 0, idx;

  idx = vsanId % MAX_ELEMENT_HASH;
  theHash = myGlobals.device[actualDeviceId].vsanHash;    

  while(1) {
    if((theHash[idx] == NULL) || (theHash[idx]->vsanId == vsanId))
      break;

    idx = (idx+1) % MAX_ELEMENT_HASH;
    if(++myIdx == MAX_ELEMENT_HASH) {
      traceEvent(CONST_TRACE_WARNING, "updateElementHash(): hash full!");
      return (NULL);
    }
  }

  if(theHash[idx] == NULL) {
    theHash[idx] = (FcFabricElementHash*) calloc(1, sizeof(FcFabricElementHash));
    theHash[idx]->vsanId = vsanId;
  }

  return (theHash[idx]);
}

/* **************************************** */

int isValidFcNxPort (FcAddress *fcAddress)
{
  if (fcAddress != NULL) {
    if ((fcAddress->domain < MAX_FC_DOMAINS) && (fcAddress->domain))
      return (TRUE);
  }

  return (FALSE);
}

/* **************************************** */

int updateFcFabricElementHash (FcFabricElementHash **theHash, u_short vsanId,
                               const u_char *bp, FcAddress *srcAddr, FcAddress *dstAddr,
                               u_short protocol, u_char r_ctl, u_int32_t pktlen)
{
  u_int myIdx = 0, idx;
  FcFabricElementHash *hash;
  u_int8_t cmd, srcDomain, dstDomain;
  u_short payload_len;
  u_int8_t gs_type, gs_stype;

  idx = vsanId % MAX_ELEMENT_HASH;
    
  while(1) {
    if((theHash[idx] == NULL) || (theHash[idx]->vsanId == vsanId))
      break;

    idx = (idx+1) % MAX_ELEMENT_HASH;
    if(++myIdx == MAX_ELEMENT_HASH) {
      traceEvent(CONST_TRACE_WARNING, "updateElementHash(): hash full!");
      return (1);
    }
  }

  if(theHash[idx] == NULL) {
    theHash[idx] = (FcFabricElementHash*) calloc(1, sizeof(FcFabricElementHash));
    theHash[idx]->vsanId = vsanId;
  }

  /* ************************** */

  hash = theHash[idx];

  incrementTrafficCounter (&hash->totBytes, pktlen);
  incrementTrafficCounter (&hash->totPkts, 1);

#ifdef NOT_YET    
  if (protocol == FC_FTYPE_SWILS) {
    cmd = *bp;

    switch (cmd) {
    case FC_SWILS_ELP:
      incrementTrafficCounter (&hash->pmBytes, pktlen);
      incrementTrafficCounter (&hash->pmPkts, 1);
      hash->fabricConfStartTime = myGlobals.actTime;

      break;
    case FC_SWILS_ESC:
      incrementTrafficCounter (&hash->pmBytes, pktlen);
      incrementTrafficCounter (&hash->pmPkts, 1);
            
      break;
    case FC_SWILS_BF:
      incrementTrafficCounter (&hash->dmBytes, pktlen);
      incrementTrafficCounter (&hash->dmPkts, 1);
      incrementTrafficCounter (&hash->numBF, 1);
      hash->fabricConfStartTime = myGlobals.actTime;

      break;
    case FC_SWILS_RCF:
      incrementTrafficCounter (&hash->dmBytes, pktlen);
      incrementTrafficCounter (&hash->dmPkts, 1);
      incrementTrafficCounter (&hash->numRCF, 1);
      hash->fabricConfStartTime = myGlobals.actTime;
            
      break; 
    case FC_SWILS_EFP:
      incrementTrafficCounter (&hash->dmBytes, pktlen);
      incrementTrafficCounter (&hash->dmPkts, 1);

      /* Copy the latest EFP for the domain list */
      payload_len = ntohs (*(u_short *)&bp[2]);
      memcpy (hash->principalSwitch.str, &bp[8], sizeof (wwn_t));

      payload_len -= 16;
      payload_len = (payload_len > pktlen) ? pktlen : payload_len;
            
      hash->domainList = (FcDomainList *)malloc (payload_len);
      memcpy (hash->domainList, &bp[16], payload_len);

      hash->domainListLen = payload_len;

      break;
    case FC_SWILS_DIA:
      incrementTrafficCounter (&hash->dmBytes, pktlen);
      incrementTrafficCounter (&hash->dmPkts, 1);

      break;
    case FC_SWILS_RDI:
      incrementTrafficCounter (&hash->dmBytes, pktlen);
      incrementTrafficCounter (&hash->dmPkts, 1);
            
      break;
    case FC_SWILS_HLO:
      incrementTrafficCounter (&hash->fspfBytes, pktlen);
      incrementTrafficCounter (&hash->fspfPkts, 1);
      incrementTrafficCounter (&hash->hloPkts, 1);
            
      break;
    case FC_SWILS_LSU:
      incrementTrafficCounter (&hash->fspfBytes, pktlen);
      incrementTrafficCounter (&hash->fspfPkts, 1);
      incrementTrafficCounter (&hash->lsuBytes, pktlen);
      incrementTrafficCounter (&hash->lsuPkts, 1);
            
      break;
    case FC_SWILS_LSA:
      incrementTrafficCounter (&hash->fspfBytes, pktlen);
      incrementTrafficCounter (&hash->fspfPkts, 1);
      incrementTrafficCounter (&hash->lsaBytes, pktlen);
      incrementTrafficCounter (&hash->lsaPkts, 1);

      /* Check if fabric configuration is over */
      if (hash->fabricConfInProgress) {
	flags = bp[23];

	if (flags & 0x2) {
	  /* Compute duration of fabric configuration, avg */
	  confTime = difftime (myGlobals.actTime, hash->fabricConfStartTime);

	  if (hash->maxTimeFabricConf < confTime) {
	    hash->maxTimeFabricConf = confTime;
	  }

	  if (hash->minTimeFabricConf > confTime) {
	    hash->minTimeFabricConf = confTime;
	  }
	}
      }
            
      break;
    case FC_SWILS_RSCN:
      incrementTrafficCounter (&hash->rscnBytes, pktlen);
      incrementTrafficCounter (&hash->rscnPkts, 1);

      break;
    case FC_SWILS_DRLIR:
      break;
    case FC_SWILS_DSCN:
      break;
    case FC_SWILS_LOOPD:
      break;
            
    case FC_SWILS_MR:
      incrementTrafficCounter (&hash->zsBytes, pktlen);
      incrementTrafficCounter (&hash->zsPkts, 1);
            
      break;
    case FC_SWILS_ACA:
      incrementTrafficCounter (&hash->zsBytes, pktlen);
      incrementTrafficCounter (&hash->zsPkts, 1);

      hash->zoneConfStartTime = myGlobals.actTime;
      hash->zoneConfInProgress = TRUE;
            
      break;
    case FC_SWILS_RCA:
      incrementTrafficCounter (&hash->zsBytes, pktlen);
      incrementTrafficCounter (&hash->zsPkts, 1);

      /* We should in reality do this when we see the ACC for RCA */
      if (hash->zoneConfInProgress) {
	hash->zoneConfInProgress = FALSE;

	confTime = difftime (myGlobals.actTime, hash->zoneConfStartTime);
	if (hash->maxTimeZoneConf < confTime) {
	  hash->maxTimeZoneConf = confTime;
	}
                
	if (hash->minTimeZoneConf > confTime) {
	  hash->minTimeZoneConf = confTime;
	}
      }
      break;
    case FC_SWILS_SFC:
      incrementTrafficCounter (&hash->zsBytes, pktlen);
      incrementTrafficCounter (&hash->zsPkts, 1);
      incrementTrafficCounter (&hash->numZoneConf, 1);
            
      break;
    case FC_SWILS_UFC:
      incrementTrafficCounter (&hash->zsBytes, pktlen);
      incrementTrafficCounter (&hash->zsPkts, 1);
            
      break;
    case FC_SWILS_SWACC:
    case FC_SWILS_SWRJT:
      break;
    default:
      traceEvent (CONST_TRACE_ALWAYSDISPLAY, "updateFcFabricElementHash: Unknown SW_ILS command %d\n",
		  cmd);
      break;
    }
  }
  else {
  }
#else        
  if (protocol == FC_FTYPE_SWILS) {
    cmd = *bp;

    switch (cmd) {
    case FC_SWILS_ELP:
    case FC_SWILS_BF:
    case FC_SWILS_RCF:
      hash->fabricConfStartTime = myGlobals.actTime;
      break;
    case FC_SWILS_EFP:
      /* Copy the latest EFP for the domain list */
      payload_len = ntohs (*(u_short *)&bp[2]);
      memcpy (hash->principalSwitch.str, &bp[8], sizeof (wwn_t));

      payload_len -= 16;
      payload_len = (payload_len > pktlen) ? pktlen : payload_len;

      if (hash->domainList != NULL) {
	free (hash->domainList);
	hash->domainList = NULL;
      }
      hash->domainList = (FcDomainList *)malloc (payload_len);
      memcpy (hash->domainList, &bp[16], payload_len);

      hash->domainListLen = payload_len;

      break;
    case FC_SWILS_LSA:
      break;
            
    case FC_SWILS_ACA:
      hash->zoneConfStartTime = myGlobals.actTime;
      break;

    case FC_SWILS_RCA:
      break;
    }
  }
#endif
    
  /* Update Domain Stats */
  srcDomain = srcAddr->domain;
    
  if (srcDomain == FC_ID_SYSTEM_DOMAIN) {
    if (srcAddr->area == FC_ID_DOMCTLR_AREA) {
      srcDomain = srcAddr->port; /* This for addr of type FF.FC.<dom> */ 
    }
  }

  dstDomain = dstAddr->domain;
  if (dstDomain == FC_ID_SYSTEM_DOMAIN) {
    if (dstAddr->area == FC_ID_DOMCTLR_AREA) {
      dstDomain = dstAddr->port; /* This for addr of type FF.FC.<dom> */ 
    }
  }

  if (srcDomain != FC_ID_SYSTEM_DOMAIN) {
    incrementTrafficCounter (&hash->domainStats[srcDomain].sentBytes, pktlen);

    switch (protocol) {
    }
  }
    
  if (dstDomain != FC_ID_SYSTEM_DOMAIN) {
    incrementTrafficCounter (&hash->domainStats[dstDomain].rcvdBytes, pktlen);
        
    switch (protocol) {
    }
  }

  switch (protocol) {
  case FC_FTYPE_SWILS:
    incrementTrafficCounter (&hash->fcSwilsBytes, pktlen);
    break;
  case FC_FTYPE_SCSI:
    incrementTrafficCounter (&hash->fcFcpBytes, pktlen);
    break;
  case FC_FTYPE_SBCCS:
    incrementTrafficCounter (&hash->fcFiconBytes, pktlen);
    break;
  case FC_FTYPE_ELS:
    incrementTrafficCounter (&hash->fcElsBytes, pktlen);
    break;
  case FC_FTYPE_FCCT:
    gs_type = bp[4];
    gs_stype = bp[5];

    if ((gs_type == FCCT_GSTYPE_DIRSVC) && (gs_stype == FCCT_GSSUBTYPE_DNS)) {
      incrementTrafficCounter (&hash->fcDnsBytes, pktlen);
    }
    else {
      incrementTrafficCounter (&hash->otherFcBytes, pktlen);
    }
    break;
  case FC_FTYPE_IP:
    incrementTrafficCounter (&hash->fcIpfcBytes, pktlen);
    break;
        
  default:
    incrementTrafficCounter (&hash->otherFcBytes, pktlen);
    break;
  }

  return (0);
}

/* **************************************** */

void processFcNSCacheFile(char *filename) {
  char *token, *bufptr, *strtokState;
  FcNameServerCacheEntry *entry;
  HostTraffic *el;
  FcAddress fcid;
  u_int32_t vsanId, domain, area, port, tgtType, i, j;
  wwn_t pWWN, nWWN;
  char alias[MAX_LEN_SYM_HOST_NAME];
  FILE *fd;
  int id, hashIdx = 0, entryFound, hex;
  char buffer[256];

  if (filename == NULL) {
    return;
  }

  if (myGlobals.fcnsCacheHash == NULL) {
    /* We cannot use the file if the entry is NULL */
    return;
  }
    
  if ((fd = fopen (filename, "r")) == NULL) {
    traceEvent (CONST_TRACE_WARNING, "Unable to open FC WWN cache file %s"
		"error = %d\n", filename, errno);
    return;
  }

  traceEvent (CONST_TRACE_ALWAYSDISPLAY, "Processing FC NS file %s\n", filename);
  while (!feof (fd) && (fgets(buffer, 256, fd) != NULL)) {
    alias[0] = '\0';
    pWWN.str[0] = '\0';
    nWWN.str[0] = '\0';
        
    /* Ignore lines that start with '#' as comments */
    if (strrchr(buffer, '#') != NULL) {
      continue;
    }

    /*
     * The file is a CSV list of lines with a line format as follows:
     * VSAN, FC_ID, pWWN, nWWN, Alias, Target type
     *
     * FC_ID is specified as a 3-byte hex i.e. 0xFFFFFD
     * pWWN & nWWN are specified as octets separated by ':'
     * Alias is a comma-separated string of max 64 chars
     * Target type is a decimal returned by the INQUIRY command
     *
     * If a field is missing, it is represented by a null string i.e. two
     * consecutive commas.
     */
    id = 0;
    bufptr = buffer;
    token = strtok_r (buffer, ",", &strtokState);
    while (token != NULL) {
      if (token[0]  != '\0') {
	switch (id) {
	case FLAG_FC_NS_CASE_VSAN:
	  if (isxdigit (*token)) {
	    sscanf (token, "%d", &vsanId);
	  }
	  else {
	    /* Invalid input. Skip rest of line */
	    token = NULL;
	    continue;
	  }
	  break;
	case FLAG_FC_NS_CASE_FCID:
	  if (isxdigit (*token)) {
	    if (sscanf (token, "%02hx.%02hx.%02hx", &domain, &area, &port) == 3) {
	      fcid.domain = domain;
	      fcid.area = area;
	      fcid.port = port;
	    }
	    else {
	      /* Invalid input. Skip rest of line */
	      token = NULL;
	      continue;
	    }
	  }
	  else {
	    /* Invalid input. Skip rest of line */
	    token = NULL;
	    continue;
	  }
	  break;
	case FLAG_FC_NS_CASE_PWWN:
	  for (i = 0, j = 0; i < LEN_WWN_ADDRESS; i++) {
	    sscanf (&token[j], "%02x:", &hex);
	    pWWN.str[i] = (char)hex;
	    j += 3;
	  }
	  break;
	case FLAG_FC_NS_CASE_NWWN:
	  for (i = 0, j = 0; i < LEN_WWN_ADDRESS; i++) {
	    sscanf (&token[j], "%02x:", &hex);
	    nWWN.str[i] = (char)hex;
	    j += 3;
	  }
	  break;
	case FLAG_FC_NS_CASE_ALIAS:
	  sscanf (token, "%63s", alias);
	  break;
	case FLAG_FC_NS_CASE_TGTTYPE:
	  if (isxdigit (*token)) {
	    sscanf (token, "%d", &tgtType);
	  }
	  else {
	    /* Invalid input. Skip rest of line */
	    token = NULL;
	    continue;
	  }
	  break;
	default:
	  break;
	}
      }
      id++;

      token = strtok_r (NULL, ",", &strtokState);
    }

    /* Validate inputs */
    if (id < FLAG_FC_NS_CASE_NWWN) {
      continue;
    }

    /* Obtain hash index. We pass -1 for device ID since this file is
     * device-independent.
     */
    hashIdx = hashFcHost (&fcid, vsanId, &el, -1);
    entry = myGlobals.fcnsCacheHash[hashIdx];

    entryFound = 0;
    while (entry != NULL) {
      if (memcmp ((u_int8_t *)&(entry->fcAddress), (u_int8_t *)&fcid,
		  LEN_FC_ADDRESS) == 0) {
	entryFound = 1;
	break;
      }

      entry = entry->next;
    }

    if (!entryFound) {
      if ((entry = malloc (sizeof (FcNameServerCacheEntry))) == NULL) {
	traceEvent (CONST_TRACE_ERROR, "Unable to malloc entry for FcNameServerCache Entry\n");
	return;
      }

      memset (entry, 0, sizeof (FcNameServerCacheEntry));
      entry->hashIdx = hashIdx;
      entry->next = myGlobals.fcnsCacheHash[hashIdx];
      myGlobals.fcnsCacheHash[hashIdx] = entry;
    }

    entry->vsanId = vsanId;
    entry->fcAddress = fcid;
    memcpy (&entry->pWWN.str[0], &pWWN.str[0], LEN_WWN_ADDRESS);
    memcpy (&entry->nWWN.str[0], &nWWN.str[0], LEN_WWN_ADDRESS);
    strncpy (&entry->alias[0], alias, MAX_LEN_SYM_HOST_NAME);
    entry->alias[MAX_LEN_SYM_HOST_NAME] = '\0';
  }
}
