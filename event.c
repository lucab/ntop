/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 *  			    http://www.ntop.org/
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

static char *actions[] = {
  "ALARM",
  "INFO"
};

/* ****************************************** */

static char* icmpType2Str(short icmp_type) {
  switch(icmp_type) {
    case ICMP_ECHOREPLY:      return("ICMP_ECHOREPLY");
    case ICMP_ECHO:           return("ICMP_ECHO");
    case ICMP_UNREACH:        return("ICMP_UNREACH");
    case ICMP_REDIRECT:       return("ICMP_REDIRECT");
    case ICMP_ROUTERADVERT:   return("ICMP_ROUTERADVERT");
    case ICMP_TIMXCEED:       return("ICMP_TIMXCEED");
    case ICMP_PARAMPROB:      return("ICMP_PARAMPROB");
    case ICMP_MASKREPLY:      return("ICMP_MASKREPLY");
    case ICMP_MASKREQ:        return("ICMP_MASKREQ");
    case ICMP_INFO_REQUEST:   return("ICMP_INFO_REQUEST");
    case ICMP_INFO_REPLY:     return("ICMP_INFO_REPLY");
    case ICMP_TIMESTAMP:      return("ICMP_TIMESTAMP");
    case ICMP_TIMESTAMPREPLY: return("ICMP_TIMESTAMPREPLY");
    case ICMP_SOURCE_QUENCH:  return("ICMP_SOURCE_QUENCH");
    }

  return("??");
}

/* ****************************************** */

void emitEvent(FilterRule *rule,
	       HostTraffic *srcHost,
	       u_int srcHostIdx _UNUSED_,
	       HostTraffic *dstHost,
	       u_int dstHostIdx _UNUSED_,
	       short icmpType,
	       u_short sport,
	       u_short dport) {
  char ruleTime[32], msg[MAX_EVENT_MSG_SIZE], tmpStr[48];
  datum key_data, data_data;
  EventMsg theMsg;
#ifdef HAVE_LOCALTIME_R
  struct tm t;
#endif

  if(eventFile == NULL) return;

  strftime(ruleTime, 32, "%Y-%m-%d %H:%M:%S", localtime_r(&actTime, &t));

#ifdef MULTITHREADED
  accessMutex(&addressResolutionMutex, "emitEvent");
#endif

  if(icmpType == -1) {
    if(snprintf(msg, MAX_EVENT_MSG_SIZE, "%s %s %s %s:%s->%s:%s",
	    ruleTime, actions[rule->actionType],
	    rule->ruleLabel,
	    srcHost->hostSymIpAddress, getAllPortByNum(sport),
	    dstHost->hostSymIpAddress, getAllPortByNum(dport)) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  } else {
    if(snprintf(msg, MAX_EVENT_MSG_SIZE, "%s %s %s %s->%s [%s]",
	    ruleTime, actions[rule->actionType],
	    rule->ruleLabel,
	    srcHost->hostSymIpAddress,
	    dstHost->hostSymIpAddress, icmpType2Str(icmpType)) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  }
#ifdef MULTITHREADED
  releaseMutex(&addressResolutionMutex);
#endif

  if(snprintf(tmpStr, sizeof(tmpStr), "%lu %lu %lu",
	  (unsigned long)srcHost->hostIpAddress.s_addr,
	  (unsigned long)dstHost->hostIpAddress.s_addr,
	  (unsigned long)actTime) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");

  traceEvent(TRACE_INFO, "Event: %s\n", msg);

  key_data.dptr = tmpStr; key_data.dsize = strlen(tmpStr)+1;
  memset(&theMsg, 0, sizeof(theMsg));
  theMsg.eventTime = actTime;
  theMsg.sourceHost.s_addr = srcHost->hostIpAddress.s_addr;
  theMsg.destHost.s_addr   = dstHost->hostIpAddress.s_addr;
  theMsg.ruleId = rule->ruleId;
  theMsg.severity = rule->actionType;
  strncpy(theMsg.message, msg, MAX_EVENT_MSG_SIZE);
  data_data.dptr = (char*)&theMsg; data_data.dsize = sizeof(theMsg);

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "emitEvent-2");
#endif
  gdbm_store(eventFile, key_data, data_data, GDBM_REPLACE);
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif
}

/* ****************************************** */

static void scanExpiredRules(FilterRule *rule) {
  if((rule->numMatchedRules > 0) 
     && (rule->lastRuleCheck+MIN_SCAN_TIMEOUT < actTime)) {
    /* Let's check whether there are some expired rules */
    int i, rulesFound;

    for(i=0, rulesFound=0; (i<MAX_NUM_RULES) 
	  && (rulesFound < rule->numMatchedRules); i++)
      if(rule->queuedPacketRules[i] != NULL) {
	if(((rule->queuedPacketRules[i]->firstMatchTime+rule->expireTime)   < actTime)
	   && ((rule->queuedPacketRules[i]->firstMatchTime+rule->unitValue) < actTime)
	   && ((rule->queuedPacketRules[i]->lastMatchTime+rule->rearmTime)  < actTime)
	   ) {
	  /* This rule is expired */
	  u_short doEmitEvent = 0;

 	  if((rule->unitValue == 0) || (rule->pktComparisonType != PACKET_FRAGMENT_COUNT))
	    doEmitEvent = 1;
	  else {
	    /* If the rule clause has been satisfied then the rule is
	       emitted otherwise it's just deleted */
	    switch(rule->pktComparisonOperator) {
	    case COMPARISON_LESS_THAN:
	      if(rule->queuedPacketRules[i]->numMatches < rule->pktComparisonValue)
		doEmitEvent = 1;
	      break;
	    case COMPARISON_EQUAL_TO:
	      if(rule->queuedPacketRules[i]->numMatches == rule->pktComparisonValue)
		doEmitEvent = 1;
	      break;
	    case COMPARISON_MORE_THAN:
	      if(rule->queuedPacketRules[i]->numMatches > rule->pktComparisonValue)
		doEmitEvent = 1;
	      break;
	    }
	  }

	  if(doEmitEvent)
	    emitEvent(rule,
		      device[actualDeviceId].hash_hostTraffic[checkSessionIdx(rule->queuedPacketRules[i]->srcHostIdx)],
		      rule->queuedPacketRules[i]->srcHostIdx,
		      device[actualDeviceId].hash_hostTraffic[checkSessionIdx(rule->queuedPacketRules[i]->dstHostIdx)],
		      rule->queuedPacketRules[i]->dstHostIdx, -1,
		      rule->queuedPacketRules[i]->sport,
		      rule->queuedPacketRules[i]->dport);

#ifdef DEBUG
	 traceEvent(TRACE_INFO, "Packet rule [%s] free (1)\n", rule->ruleLabel);
#endif
	  free(rule->queuedPacketRules[i]);
	  rule->queuedPacketRules[i]=NULL;
	  rule->numMatchedRules--;
	} else
	  rulesFound++;
      }

    rule->lastRuleCheck = actTime;
  }
}

/* ****************************************** */

void scanAllTcpExpiredRules(void) {
  u_short i;

#ifdef DEBUG
 traceEvent(TRACE_INFO, "scanAllTcpExpiredRules() called....\n");
#endif

  for(i=0; i<ruleSerialIdentifier; i++)
    if(filterRulesList[i] != NULL)
      scanExpiredRules(filterRulesList[i]);
}

/* ****************************************** */

void fireEvent(FilterRule *rule,
	       HostTraffic *srcHost,
	       u_int srcHostIdx,
	       HostTraffic *dstHost,
	       u_int dstHostIdx,
	       short icmpType,
	       u_short sport,
	       u_short dport,
	       u_int length _UNUSED_) {
  int i, rulesFound;
  
#ifdef DEBUG
 traceEvent(TRACE_INFO, "fireTcpUdpEvent() called.\n");
#endif

  scanExpiredRules(rule);

    /* This is not a rule 'per se' but it is used to clear
       other events if marked before */
  if(rule->ruleIdCleared) {
    FilterRule *ruleToClear = filterRulesList[rule->ruleIdCleared];
    MatchedRule **queuedPacketRules = ruleToClear->queuedPacketRules;

    for(i=0, rulesFound=0; (i<MAX_NUM_RULES) && (rulesFound<ruleToClear->numMatchedRules); i++) {

      if(ruleToClear->queuedPacketRules[i] == NULL)
	continue;
      else
	rulesFound++;

      if((ruleToClear->revert
	  && (queuedPacketRules[i]->srcHostIdx == dstHostIdx)
	  && (queuedPacketRules[i]->dstHostIdx == srcHostIdx)
	  && (queuedPacketRules[i]->sport == dport)
	  && (queuedPacketRules[i]->dport == sport))
	 ||
	 ((!ruleToClear->revert)
	  && (queuedPacketRules[i]->srcHostIdx == srcHostIdx)
	  && (queuedPacketRules[i]->dstHostIdx == dstHostIdx)
	  && (queuedPacketRules[i]->sport == sport)
	  && (queuedPacketRules[i]->dport == dport))) {
	/* Rules match */
#ifdef DEBUG
#ifdef MULTITHREADED
	accessMutex(&addressResolutionMutex, "fireEvent");
#endif
	traceEvent(TRACE_INFO, "Rules matched %s %s/%s->%s/%s (len %d)\n",
	       ruleToClear->ruleLabel,
	       srcHost->hostSymIpAddress, getAllPortByNum(sport),
	       dstHost->hostSymIpAddress, getAllPortByNum(dport),
	       length);
#ifdef MULTITHREADED
	releaseMutex(&addressResolutionMutex);
#endif
	printf("Packet rule [%s] free (2)\n", rule->ruleLabel);
#endif

	  if(ruleToClear->rearmTime == 0) {
	    free(queuedPacketRules[i]);
	    queuedPacketRules[i] = NULL;
	  } else
	    queuedPacketRules[i]->numMatches = 0;

	  ruleToClear->numMatchedRules--;
	  if(!rule->clearAllRule)
	    return;
      }
    }
    return;
  }

  /* This is not a rule that clears other rules */
  if((rule->expireTime > 0) || (rule->unitValue > 0)) {
    /* Let's see whether there's a 'twin' rule already queued */

    for(i=0, rulesFound=0; (i<MAX_NUM_RULES) && (rulesFound<rule->numMatchedRules); i++) {
      if(rule->queuedPacketRules[i] == NULL)
	continue;
      else
	rulesFound++;

      if((rule->revert
	  && (rule->queuedPacketRules[i]->srcHostIdx == dstHostIdx)
	  && (rule->queuedPacketRules[i]->dstHostIdx == srcHostIdx)
	  && ((rule->sport == NOT_ANY_PORT) || (rule->queuedPacketRules[i]->sport == dport))
	  && ((rule->dport == NOT_ANY_PORT) || (rule->queuedPacketRules[i]->dport == sport)))
	 ||
	 ((!rule->revert)
	  && (rule->queuedPacketRules[i]->srcHostIdx == srcHostIdx)
	  && (rule->queuedPacketRules[i]->dstHostIdx == dstHostIdx)
	  && ((rule->sport == NOT_ANY_PORT) || (rule->queuedPacketRules[i]->sport == sport))
	  && ((rule->dport == NOT_ANY_PORT) || (rule->queuedPacketRules[i]->dport == dport)))) {
	/* Rules match */
	u_short purgeRule=0;

	if((rule->queuedPacketRules[i]->lastMatchTime+rule->rearmTime) > actTime) {
#ifdef DEBUG
	 traceEvent(TRACE_INFO, "Rule %s is disabled (%d more seconds)\n",
		    rule->ruleLabel,
		    ((rule->queuedPacketRules[i]->lastMatchTime+rule->rearmTime) - actTime));
#endif
	  /* This rule is disabled and not yet rearmed */
	  return;
	}

	rule->queuedPacketRules[i]->numMatches++;

	if((rule->unitValue == 0) || (rule->pktComparisonType != PACKET_FRAGMENT_COUNT)) {
	  if((rule->queuedPacketRules[i]->firstMatchTime+rule->expireTime) < actTime)
	    purgeRule = 1;
	} else {
	  /* If the rule clause has been satisfied then the rule is
	     emitted otherwise it's just deleted */
	  switch(rule->pktComparisonOperator) {
	  case COMPARISON_LESS_THAN:
	    if(rule->queuedPacketRules[i]->numMatches < rule->pktComparisonValue)
	      purgeRule = 1;
	    break;
	  case COMPARISON_EQUAL_TO:
	    if(rule->queuedPacketRules[i]->numMatches == rule->pktComparisonValue)
	      purgeRule = 1;
	    break;
	  case COMPARISON_MORE_THAN:
	    if(rule->queuedPacketRules[i]->numMatches > rule->pktComparisonValue)
	      purgeRule = 1;
	    break;
	  }
	}

	if(purgeRule) {
	  rule->queuedPacketRules[i]->lastMatchTime = actTime;
	  emitEvent(rule, srcHost,
		    rule->queuedPacketRules[i]->srcHostIdx,
		    dstHost,
		    rule->queuedPacketRules[i]->dstHostIdx, icmpType,
		    rule->queuedPacketRules[i]->sport,
		    rule->queuedPacketRules[i]->dport);

#ifdef DEBUG
	 traceEvent(TRACE_INFO, "Packet rule [%s] free (3)\n", rule->ruleLabel);
#endif

	  if(rule->rearmTime == 0) {
	    free(rule->queuedPacketRules[i]);
	    rule->queuedPacketRules[i] = NULL;
	  } else
	    rule->queuedPacketRules[i]->numMatches = 0;
	}

	return; /* Don't look any further */
      }
    } /* for */
  }

  if(rule->numMatchedRules == (MAX_NUM_RULES-1)) {
    /* All we can do is to immediately emit the event */
    emitEvent(rule, srcHost, srcHostIdx,
	      dstHost, dstHostIdx, icmpType,
	      sport, dport);
  } else {
    /* The event is queued for later processing */
    u_char entryFound = 0;

    if((rule->expireTime > 0) || (rule->unitValue > 0)) {

      for(i=0, rulesFound=0; (i<MAX_NUM_RULES) && (rulesFound<rule->numMatchedRules); i++) {
	if(rule->queuedPacketRules[i] == NULL)
	  continue;
	else
	  rulesFound++;

	if((rule->revert
	    && (rule->queuedPacketRules[i]->srcHostIdx == dstHostIdx)
	    && (rule->queuedPacketRules[i]->dstHostIdx == srcHostIdx)
	    && ((rule->sport == NOT_ANY_PORT) || (rule->queuedPacketRules[i]->sport == dport))
	    && ((rule->dport == NOT_ANY_PORT) || (rule->queuedPacketRules[i]->dport == sport)))
	   ||
	   ((!rule->revert)
	    && (rule->queuedPacketRules[i]->srcHostIdx == srcHostIdx)
	    && (rule->queuedPacketRules[i]->dstHostIdx == dstHostIdx)
	    && ((rule->sport == NOT_ANY_PORT) || (rule->queuedPacketRules[i]->sport == sport))
	    && ((rule->dport == NOT_ANY_PORT) || (rule->queuedPacketRules[i]->dport == dport)))) {
	  /* Match found */
	  u_short purgeRule=0;

	  entryFound++;

	  rule->queuedPacketRules[i]->numMatches++;

	  if(rule->pktComparisonType == PACKET_FRAGMENT_COUNT) {
	    /* If the rule clause has been satisfied then the rule is
	       emitted otherwise it's just deleted */
	    switch(rule->pktComparisonOperator) {
	    case COMPARISON_LESS_THAN:
	      if(rule->queuedPacketRules[i]->numMatches < rule->pktComparisonValue)
		purgeRule = 1;
	      break;
	    case COMPARISON_EQUAL_TO:
	      if(rule->queuedPacketRules[i]->numMatches == rule->pktComparisonValue)
		purgeRule = 1;
	      break;
	    case COMPARISON_MORE_THAN:
	      if(rule->queuedPacketRules[i]->numMatches > rule->pktComparisonValue)
		purgeRule = 1;
	      break;
	    }
	  }

	  if(purgeRule) {
	    rule->queuedPacketRules[i]->lastMatchTime = actTime;
	    emitEvent(rule, srcHost,
		      rule->queuedPacketRules[i]->srcHostIdx,
		      dstHost,
		      rule->queuedPacketRules[i]->dstHostIdx, icmpType,
		      rule->queuedPacketRules[i]->sport,
		      rule->queuedPacketRules[i]->dport);

#ifdef DEBUG
	   traceEvent(TRACE_INFO, "Packet rule [%s] free (4)\n", rule->ruleLabel);
#endif
	    if(rule->rearmTime == 0) {
	      free(rule->queuedPacketRules[i]);
	      rule->queuedPacketRules[i] = NULL;
	    } else
	      rule->queuedPacketRules[i]->numMatches = 0;

	      return;
	  }

	  return; /* That's enough for now... */
	}
      }

      if(!entryFound)
	for(i=0; (i<MAX_NUM_RULES); i++)
	  if(rule->queuedPacketRules[i] == NULL) {
#ifdef DEBUG
	   traceEvent(TRACE_INFO, "queueing event %s.\n", rule->ruleLabel);
#endif
	    rule->queuedPacketRules[i] = (MatchedRule*)malloc(sizeof(MatchedRule));
	    rule->queuedPacketRules[i]->srcHostIdx = srcHostIdx,
	      rule->queuedPacketRules[i]->sport = sport,
	      rule->queuedPacketRules[i]->dstHostIdx = dstHostIdx,
	      rule->queuedPacketRules[i]->dport = dport,
	      rule->queuedPacketRules[i]->firstMatchTime = actTime,
	      rule->queuedPacketRules[i]->lastMatchTime = 0,
	      rule->queuedPacketRules[i]->numMatches = 1;
	    rule->numMatchedRules++;
	    return;
	  }
    }
  }

  emitEvent(rule, srcHost, srcHostIdx,
	    dstHost, dstHostIdx, icmpType,
	    sport, dport);
}


/* **************************************** */

void smurfAlert(u_int srcHostIdx, u_int dstHostIdx) {
  FilterRule smurfing;

  memset(&smurfing, 0, sizeof(FilterRule));
  smurfing.ruleId = 999;
  smurfing.ruleLabel = "smurfing";
  smurfing.actionType = ACTION_ALARM;

  emitEvent(&smurfing,  device[actualDeviceId].hash_hostTraffic[srcHostIdx], srcHostIdx,
	    device[actualDeviceId].hash_hostTraffic[dstHostIdx],
	    dstHostIdx, ICMP_ECHO, 0, 0);

  if(enableSuspiciousPacketDump) {
    traceEvent(TRACE_INFO, "WARNING: smurfing detected (%s->%s)\n",
	       device[actualDeviceId].hash_hostTraffic[srcHostIdx]->hostSymIpAddress,
	       device[actualDeviceId].hash_hostTraffic[dstHostIdx]->hostSymIpAddress);
    dumpSuspiciousPacket();
  }
}
