/**
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 2003 Dinesh G. Dutt <ddutt@cisco.com>
 * Copyright (C) 2003 Luca Deri <deri@ntop.org>
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

#ifdef CFG_MULTITHREADED
static char stateChangeMutexInitialized = 0;
static pthread_mutex_t stateChangeMutex;
#endif

static SessionInfo *passiveSessions;
static u_short passiveSessionsLen;

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

/* Routine to extract WWN from FLOGI frame */
int fillFcHostInfo (const u_char *bp, HostTraffic *srcHost)
{
    assert (bp != NULL);

    srcHost->fcRecvSize = ntohs ((u_short)bp[10] & 0xFFF);
    memcpy (srcHost->pWWN.str, &bp[20], LEN_WWN_ADDRESS);
    memcpy (srcHost->nWWN.str, &bp[28], LEN_WWN_ADDRESS);

    return (0);
}

/* Routine to extract WWN from RDI frame */

/* Routine to extract information from dNS registration messages */


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

    if (bp[offset+11] & 0x1) {
        incrementTrafficCounter (&srcHost->scsiWriteBytes, fcpDl);
        incrementTrafficCounter (&dstHost->scsiWriteBytes, fcpDl);
    }
    else if (bp[offset+11] & 0x2) {
        incrementTrafficCounter (&srcHost->scsiReadBytes, fcpDl);
        incrementTrafficCounter (&dstHost->scsiReadBytes, fcpDl);
    }

    return (0);
}

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

int isValidFcNxPort (FcAddress *fcAddress)
{
    if (fcAddress != NULL) {
        if ((fcAddress->domain < MAX_FC_DOMAINS) && (fcAddress->domain))
            return (TRUE);
    }

    return (FALSE);
}

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
