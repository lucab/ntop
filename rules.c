/*
 *  Copyright (C) 2000 Luca Deri <deri@ntop.org>
 *                     Portions by Stefano Suin <stefano@ntop.org>
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


/* ************************** */

static void freeFilterRule(FilterRule *rule)  {
  if(rule->ruleLabel != NULL)   free(rule->ruleLabel);
  if(rule->pktContentPattern != NULL) {
    if(rule->pktContentPattern->fastmap != NULL) 
      free(rule->pktContentPattern->fastmap);
    free(rule->pktContentPattern);
  }

  free(rule);
}

/* ************************** */

static FilterRule* parseFilterRule(u_short ruleType, 
				   char* line, 
				   u_short lineNum) {
  FilterRule *rule;
  char *token, *strtokState;
  int i;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Parsing line %d (%s)\n", lineNum, line);
#endif

  rule = (FilterRule*)malloc(sizeof(FilterRule));
  memset(rule, 0, sizeof(FilterRule));

  token = strtok_r(line, " ", &strtokState); /* token = 'tcp/udp' */

  /* label */
  token = strtok_r(NULL, " ", &strtokState);
  if(token == NULL) {
    traceEvent(TRACE_INFO, "Skipping line %d (missing label)\n", lineNum);
    freeFilterRule(rule);
    return(NULL);
  } else 
    rule->ruleLabel = strdup(token);

  /* shost/sport */
  token = strtok_r(NULL, " ", &strtokState);
  if(token == NULL) {
    traceEvent(TRACE_INFO, "Skipping line %d (missing shost/sport)\n", lineNum);
    freeFilterRule(rule);
    return(NULL);
  } else {
    if(!strcmp(token, "revert")) {
      rule->revert = 1;
      token = strtok_r(NULL, " ", &strtokState);
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (missing shost/sport)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }    
    }

    for(i=0; (token[i] != '/') && (token[i] != 0); i++)
      ;

    if(token[i] != '/') {
      traceEvent(TRACE_INFO, "Skipping line %d (invalid shost/sport)\n", lineNum);
      freeFilterRule(rule);
      return(NULL);
    } else 
      token[i] = 0;

    if(!strcmp(token, "any")) rule->shostType = ANY_ADDRESS;
    else if(!strcmp(token, "broadcast")) rule->shostType = BROADCAST_ADDRESS;
    else if(!strcmp(token, "multicast")) rule->shostType = MULTICAST_ADDRESS;
    else if(!strcmp(token, "gateway")) rule->shostType = GATEWAY_ADDRESS;
    else if(!strcmp(token, "dns")) rule->shostType = DNS_ADDRESS;
    else if(!strcmp(token, "!broadcast")) rule->shostType = NOT_BROADCAST_ADDRESS;
    else if(!strcmp(token, "!multicast")) rule->shostType = NOT_MULTICAST_ADDRESS;
    else if(!strcmp(token, "!gateway")) rule->shostType = NOT_GATEWAY_ADDRESS;
    else if(!strcmp(token, "!dns")) rule->shostType = NOT_DNS_ADDRESS;
    else {
      traceEvent(TRACE_INFO, "Skipping line %d (unknown shost)\n", lineNum);
      freeFilterRule(rule);
      return(NULL);
    }
    
    if(isdigit(token[i+1]))
      rule->sport = atoi(&token[i+1]);
    else if(!strcmp(&token[i+1], "any")) rule->sport = ANY_PORT;
    else if(!strcmp(&token[i+1], "!any")) rule->sport = NOT_ANY_PORT;
    else if(!strcmp(&token[i+1], "usedport")) rule->sport = USED_PORT;
    else if(!strcmp(&token[i+1], "!usedport")) rule->sport = NOT_USED_PORT;
    else {
      if(ruleType == TCP_RULE)
	rule->sport = getPortByName(tcpSvc, &token[i+1]);
      else
	rule->sport = getPortByName(udpSvc, &token[i+1]);

      if(rule->sport > TOP_IP_PORT) {
	traceEvent(TRACE_INFO, "Skipping line %d (unknown sport)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }      
    }
  }

  /* dhost/dport */
  token = strtok_r(NULL, " ", &strtokState);
  if(token == NULL) {
    traceEvent(TRACE_INFO, "Skipping line %d (missing dhost/dport)\n", lineNum);
    freeFilterRule(rule);
    return(NULL);
  } else {
    for(i=0; (token[i] != '/') && (token[i] != 0); i++)
      ;

    if(token[i] != '/') {
      traceEvent(TRACE_INFO, "Skipping line %d (invalid dhost/dport)\n", lineNum);
      freeFilterRule(rule);
      return(NULL);
    } else 
      token[i] = 0;

    if(!strcmp(token, "any")) rule->dhostType = ANY_ADDRESS;
    else if(!strcmp(token, "broadcast")) rule->dhostType = BROADCAST_ADDRESS;
    else if(!strcmp(token, "multicast")) rule->dhostType = MULTICAST_ADDRESS;
    else if(!strcmp(token, "gateway")) rule->dhostType = GATEWAY_ADDRESS;
    else if(!strcmp(token, "dns")) rule->dhostType = DNS_ADDRESS;
    else if(!strcmp(token, "!broadcast")) rule->dhostType = NOT_BROADCAST_ADDRESS;
    else if(!strcmp(token, "!multicast")) rule->dhostType = NOT_MULTICAST_ADDRESS;
    else if(!strcmp(token, "!gateway")) rule->dhostType = NOT_GATEWAY_ADDRESS;
    else if(!strcmp(token, "!dns")) rule->dhostType = NOT_DNS_ADDRESS;
    else {
      traceEvent(TRACE_INFO, "Skipping line %d (unknown dhost)\n", lineNum);
      freeFilterRule(rule);
      return(NULL);
    }
    
    if(isdigit(token[i+1]))
      rule->dport = atoi(&token[i+1]);
    else if(!strcmp(&token[i+1], "any")) rule->dport = ANY_PORT;
    else if(!strcmp(&token[i+1], "!any")) rule->dport = NOT_ANY_PORT;
    else if(!strcmp(&token[i+1], "usedport")) rule->dport = USED_PORT;
    else if(!strcmp(&token[i+1], "!usedport")) rule->dport = NOT_USED_PORT;
    else {
      if(ruleType == TCP_RULE)
	rule->dport = getPortByName(tcpSvc, &token[i+1]);
      else
	rule->dport = getPortByName(udpSvc, &token[i+1]);

      if(rule->dport > TOP_IP_PORT) {
	traceEvent(TRACE_INFO, "Skipping line %d (unknown dport)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }      
    }
  }

  while((token = strtok_r(NULL, " ", &strtokState))) {
    if(!strcmp(token, "flags")) {
      token = strtok_r(NULL, " ", &strtokState);

      if(ruleType == UDP_RULE) {
	traceEvent(TRACE_INFO, "Skipping line %d (flags cannot be specified for UDP)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      } else if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid flags specification)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }

      for(i=0; (token[i] != 0); i++)
	switch(token[i]) {
	case 'S': /* SYN */
	  rule->flags |= TH_SYN;
	  break;
	case 'P': /* PUSH */
	  rule->flags |= TH_PUSH;
	  break;
	case 'F': /* FIN */
	  rule->flags |= TH_FIN;
	  break;
	case 'A': /* ACK */
	  rule->flags |= TH_ACK;
	  break;
	case 'R': /* RESET */
	  rule->flags |= TH_RST;
	  break;
	default:
	  traceEvent(TRACE_INFO, "Ignored flag '%c' on line %d (valid flags: S,P,F,A,R)\n", \
		     token[i], lineNum);
	}       
    } else if(!strcmp(token, "clears")) {
      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid rule to clear specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      } else  {
	FilterRuleChain *chainScan;

	rule->ruleIdCleared =0;
	
	if(ruleType == TCP_RULE)
	  chainScan = tcpChain;
	else
	  chainScan = udpChain;

	while(chainScan != NULL) {
	  if(!strcmp(chainScan->rule->ruleLabel, token)) {
	    rule->ruleIdCleared = chainScan->rule->ruleId;
	    break;
	  } else
	    chainScan = chainScan->nextRule;
	}
	
	if(rule->ruleIdCleared == 0) {
	  traceEvent(TRACE_INFO, "Skipping line %d (specified an unknown rule to clear)\n", lineNum);
	  freeFilterRule(rule);
	  return(NULL);
	} 
      }
    } else if(!strcmp(token, "rearm")) {
      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid rearm specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      } else
	rule->rearmTime = atoi(token);
    } else if(!strcmp(token, "unit")) {
      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid unit specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      } 

      if(rule->pktComparisonValue == COMPARISON_NONE)
	traceEvent(TRACE_INFO, "Skipping line %d (unit can be specified only comparisons)\n", lineNum);
      else
	rule->unitValue = atoi(token);
    } else if(!strcmp(token, "contains")) {
      char *matchString = strtok_r(NULL, "\"", &strtokState); /* Begin */
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid packet content specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }

      token = strtok_r(NULL, "\"", &strtokState); /* End */
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid packet content specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      } else {
	const char *re_err;
	char tmpString[256];
	
	rule->pktContentPattern = (struct re_pattern_buffer*)malloc(sizeof(struct re_pattern_buffer));
	memset(rule->pktContentPattern, 0, sizeof(struct re_pattern_buffer));

	strncpy(tmpString, matchString, sizeof(tmpString));
	re_err = (const char *) re_compile_pattern(tmpString, strlen(tmpString), rule->pktContentPattern);
	if (re_err) {
	  traceEvent(TRACE_INFO, "Skipping line %d (invalid pattern specified)\n", lineNum);
	  freeFilterRule(rule);
	  return(NULL);
	}

	rule->pktContentPattern->fastmap = (char*)malloc(256);
	if (re_compile_fastmap(rule->pktContentPattern)) {
	  traceEvent(TRACE_INFO, "Skipping line %d (invalid pattern specified, compile error)\n", lineNum);
	  freeFilterRule(rule);
	  return(NULL);
	}

      } 
    } else if((!strcmp(token, "pktcount")) 
	      || (!strcmp(token, "pktsize"))) {
      if(rule->pktComparisonType != COMPARISON_NONE) 
	traceEvent(TRACE_WARNING, "Warning: overriding previous specified packet comparison on line %d\n", 
		   lineNum);

      if(!strcmp(token, "pktcount")) rule->pktComparisonType = PACKET_FRAGMENT_COUNT;
      else rule->pktComparisonType = PACKET_FRAGMENT_SIZE;

      token = strtok_r(NULL, " ", &strtokState);
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid packet comparison specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }
      
      switch(token[0]) {
      case '=':
	rule->pktComparisonOperator = COMPARISON_EQUAL_TO;
	break;
      case '<':
	rule->pktComparisonOperator = COMPARISON_LESS_THAN;
	break;
      case '>':
	rule->pktComparisonOperator = COMPARISON_MORE_THAN;
	break;
      default:
	traceEvent(TRACE_INFO, "Ignored packet comparison criteria on line %d (valid criteria: =,>,<)\n", 
		   lineNum);
	rule->pktComparisonOperator = COMPARISON_NONE;
      }

      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid comparison value)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }
      rule->pktComparisonValue = atoi(token);
    } else if(!strcmp(token, "type")) {
      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid type specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }

      if(!strcmp(token, "fragment")) rule->dataType = DATA_FRAGMENT;
      else rule->dataType = DATA_PACKET; /* default */
    } else if(!strcmp(token, "action")) {
      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid action specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }
      
      if(!strcmp(token, "mark")) rule->actionType = ACTION_MARK;
      else rule->actionType = ACTION_ALARM;
    } else if(!strcmp(token, "expires")) {
      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid expires value specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }
      
      if(rule->actionType != ACTION_MARK) 
	traceEvent(TRACE_INFO, "Skipping line %d (expires can be specified only for 'mark' actions)\n", 
		   lineNum);
      else 
	rule->expireTime = atoi(token);
    } else if(!strcmp(token, "all")) {
      if(rule->ruleIdCleared == 0) 
	traceEvent(TRACE_INFO, "Skipping line %d (all specified without rule to clear)\n", lineNum);
      else 
	rule->clearAllRule = 1;
    } else {
      traceEvent(TRACE_INFO, "Skipping token '%s' on line %d (it's unknown)\n", token, lineNum);
    }
  }

  /* Sanity checks... */

  if((rule->sport > NOT_USED_PORT /* top value */)
     || (rule->dport > NOT_USED_PORT /* top value */)
     || ((rule->unitValue > 0) && rule->expireTime)
     ) {
    traceEvent(TRACE_INFO, "Skipping line %d (sanity check failed)\n", lineNum);
    freeFilterRule(rule);
    return(NULL);
  }

  if(ruleSerialIdentifier < (MAX_NUM_RULES-1)) {
    filterRulesList[ruleSerialIdentifier] = (void*)rule;
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Adding %d\n", ruleSerialIdentifier);
#endif
  } else  {
    traceEvent(TRACE_INFO, "Skipping rule at line %d (too many rules defined)\n", lineNum);
    freeFilterRule(rule);
    return(NULL);
  }

  /* The rule looks good */
  rule->ruleId = ruleSerialIdentifier++;

  return(rule);
}
/* ************************** */

static FilterRule* parseFilterICMPRule(char* line, u_short lineNum) {
  FilterRule *rule;
  char *token, *strtokState;
  int i;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Parsing line %d (%s)\n", lineNum, line);
#endif

  rule = (FilterRule*)malloc(sizeof(FilterRule));
  memset(rule, 0, sizeof(FilterRule));

  token = strtok_r(line, " ", &strtokState); /* token = 'tcp/udp' */

  /* label */
  token = strtok_r(NULL, " ", &strtokState);
  if(token == NULL) {
    traceEvent(TRACE_INFO, "Skipping line %d (missing label)\n", lineNum);
    freeFilterRule(rule);
    return(NULL);
  } else 
    rule->ruleLabel = strdup(token);

  /* ICMP type */
  token = strtok_r(NULL, " ", &strtokState);
  if(token == NULL) {
    traceEvent(TRACE_INFO, "Skipping line %d (missing label)\n", lineNum);
    freeFilterRule(rule);
    return(NULL);
  } else {
    if(!strcmp(token, "ICMP_ECHOREPLY")) rule->flags = ICMP_ECHOREPLY;
    else if(!strcmp(token, "ICMP_ECHO")) rule->flags = ICMP_ECHO;
    else if(!strcmp(token, "ICMP_UNREACH")) rule->flags = ICMP_UNREACH;
    else if(!strcmp(token, "ICMP_REDIRECT")) rule->flags = ICMP_REDIRECT;
    else if(!strcmp(token, "ICMP_ROUTERADVERT")) rule->flags = ICMP_ROUTERADVERT;
    else if(!strcmp(token, "ICMP_TIMXCEED")) rule->flags = ICMP_TIMXCEED;
    else if(!strcmp(token, "ICMP_PARAMPROB")) rule->flags = ICMP_PARAMPROB;
    else if(!strcmp(token, "ICMP_MASKREPLY")) rule->flags = ICMP_MASKREPLY;
    else if(!strcmp(token, "ICMP_MASKREQ")) rule->flags = ICMP_MASKREQ;
    else if(!strcmp(token, "ICMP_INFO_REQUEST")) rule->flags = ICMP_INFO_REQUEST;
    else if(!strcmp(token, "ICMP_INFO_REPLY")) rule->flags = ICMP_INFO_REPLY;
    else if(!strcmp(token, "ICMP_TIMESTAMP")) rule->flags = ICMP_TIMESTAMP;
    else if(!strcmp(token, "ICMP_TIMESTAMPREPLY")) rule->flags = ICMP_TIMESTAMPREPLY;
    else if(!strcmp(token, "ICMP_SOURCE_QUENCH")) rule->flags = ICMP_SOURCE_QUENCH;
    else {
      traceEvent(TRACE_INFO, "Skipping line %d (unknown ICMP type)\n", lineNum);
      freeFilterRule(rule);
      return(NULL);
    } 
  }

  /* shost/dhost */
  token = strtok_r(NULL, " ", &strtokState);
  if(token == NULL) {
    traceEvent(TRACE_INFO, "Skipping line %d (missing shost/dhost)\n", lineNum);
    freeFilterRule(rule);
    return(NULL);
  } else {
    for(i=0; (token[i] != '/') && (token[i] != 0); i++)
      ;

    if(token[i] != '/') {
      traceEvent(TRACE_INFO, "Skipping line %d (invalid shost/dhost)\n", lineNum);
      freeFilterRule(rule);
      return(NULL);
    } else 
      token[i] = 0;

    if(!strcmp(token, "any")) rule->shostType = ANY_ADDRESS;
    else if(!strcmp(token, "broadcast")) rule->shostType = BROADCAST_ADDRESS;
    else if(!strcmp(token, "multicast")) rule->shostType = MULTICAST_ADDRESS;
    else if(!strcmp(token, "gateway")) rule->shostType = GATEWAY_ADDRESS;
    else if(!strcmp(token, "dns")) rule->shostType = DNS_ADDRESS;
    else if(!strcmp(token, "!broadcast")) rule->shostType = NOT_BROADCAST_ADDRESS;
    else if(!strcmp(token, "!multicast")) rule->shostType = NOT_MULTICAST_ADDRESS;
    else if(!strcmp(token, "!gateway")) rule->shostType = NOT_GATEWAY_ADDRESS;
    else if(!strcmp(token, "!dns")) rule->shostType = NOT_DNS_ADDRESS;
    else {
      traceEvent(TRACE_INFO, "Skipping line %d (unknown shost)\n", lineNum);
      freeFilterRule(rule);
      return(NULL);
    }
    
    if(!strcmp(&token[i+1], "any")) rule->shostType = ANY_ADDRESS;
    else if(!strcmp(&token[i+1], "broadcast")) rule->shostType = BROADCAST_ADDRESS;
    else if(!strcmp(&token[i+1], "multicast")) rule->shostType = MULTICAST_ADDRESS;
    else if(!strcmp(&token[i+1], "gateway")) rule->shostType = GATEWAY_ADDRESS;
    else if(!strcmp(&token[i+1], "dns")) rule->shostType = DNS_ADDRESS;
    else if(!strcmp(&token[i+1], "!broadcast")) rule->shostType = NOT_BROADCAST_ADDRESS;
    else if(!strcmp(&token[i+1], "!multicast")) rule->shostType = NOT_MULTICAST_ADDRESS;
    else if(!strcmp(&token[i+1], "!gateway")) rule->shostType = NOT_GATEWAY_ADDRESS;
    else if(!strcmp(&token[i+1], "!dns")) rule->shostType = NOT_DNS_ADDRESS;
    else {
      traceEvent(TRACE_INFO, "Skipping line %d (unknown dhost)\n", lineNum);
      freeFilterRule(rule);
      return(NULL);
    }
  }

  while((token = strtok_r(NULL, " ", &strtokState)) != NULL) {
    if(!strcmp(token, "clears")) {
      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid rule to clear specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      } else  {
	FilterRuleChain *chainScan;

	rule->ruleIdCleared =0;	
	chainScan = icmpChain;

	while(chainScan != NULL) {
	  if(!strcmp(chainScan->rule->ruleLabel, token)) {
	    rule->ruleIdCleared = chainScan->rule->ruleId;
	    break;
	  } else
	    chainScan = chainScan->nextRule;
	}
	
	if(rule->ruleIdCleared == 0) {
	  traceEvent(TRACE_INFO, "Skipping line %d (specified an unknown rule to clear)\n", lineNum);
	  freeFilterRule(rule);
	  return(NULL);
	} 
      }
    } else if(!strcmp(token, "rearm")) {
      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid rearm specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      } else
	rule->rearmTime = atoi(token);
    } else if(!strcmp(token, "unit")) {
      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid unit specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      } 

      if(rule->pktComparisonValue == COMPARISON_NONE)
	traceEvent(TRACE_INFO, "Skipping line %d (unit can be specified only comparisons)\n", lineNum);
      else
	rule->unitValue = atoi(token);
    } else if(!strcmp(token, "contains")) {
      char *matchString = strtok_r(NULL, "\"", &strtokState); /* Begin */
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid packet content specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }

      token = strtok_r(NULL, "\"", &strtokState); /* End */
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid packet content specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      } else {
	const char *re_err;
	
	rule->pktContentPattern = (struct re_pattern_buffer*)malloc(sizeof(struct re_pattern_buffer));
	memset(rule->pktContentPattern, 0, sizeof(struct re_pattern_buffer));

	re_err = (const char *) re_compile_pattern(matchString, strlen(matchString), 
						   rule->pktContentPattern);
	if (re_err) {
	  traceEvent(TRACE_INFO, "Skipping line %d (invalid pattern specified)\n", lineNum);
	  freeFilterRule(rule);
	  return(NULL);
	}

	rule->pktContentPattern->fastmap = (char*)malloc(256);
	if (re_compile_fastmap(rule->pktContentPattern)) {
	  traceEvent(TRACE_INFO, "Skipping line %d (invalid pattern specified, compile error)\n",
		     lineNum);
	  freeFilterRule(rule);
	  return(NULL);
	}
      } 
    } else if((!strcmp(token, "pktcount")) 
	      || (!strcmp(token, "pktsize"))) {
      if(rule->pktComparisonType != COMPARISON_NONE) 
	traceEvent(TRACE_WARNING, 
		   "Warning: overriding previous specified packet comparison on line %d\n", 
		   lineNum);

      if(!strcmp(token, "pktcount")) rule->pktComparisonType = PACKET_FRAGMENT_COUNT;
      else rule->pktComparisonType = PACKET_FRAGMENT_SIZE;

      token = strtok_r(NULL, " ", &strtokState);
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid packet comparison specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }
      
      switch(token[0]) {
      case '=':
	rule->pktComparisonOperator = COMPARISON_EQUAL_TO;
	break;
      case '<':
	rule->pktComparisonOperator = COMPARISON_LESS_THAN;
	break;
      case '>':
	rule->pktComparisonOperator = COMPARISON_MORE_THAN;
	break;
      default:
	traceEvent(TRACE_INFO, "Ignored packet comparison criteria on line %d (valid criteria: =,>,<)\n",
		   lineNum);
	rule->pktComparisonOperator = COMPARISON_NONE;
      }

      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid comparison value)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }
      rule->pktComparisonValue = atoi(token);
    } else if(!strcmp(token, "type")) {
      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid type specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }

      if(!strcmp(token, "fragment")) rule->dataType = DATA_FRAGMENT;
      else rule->dataType = DATA_PACKET; /* default */
    } else if(!strcmp(token, "action")) {
      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid action specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }
      
      if(!strcmp(token, "mark")) rule->actionType = ACTION_MARK;
      else rule->actionType = ACTION_ALARM;
    } else if(!strcmp(token, "expires")) {
      token = strtok_r(NULL, " ", &strtokState);
      
      if(token == NULL) {
	traceEvent(TRACE_INFO, "Skipping line %d (invalid expires value specified)\n", lineNum);
	freeFilterRule(rule);
	return(NULL);
      }
      
      if(rule->actionType != ACTION_MARK) 
	traceEvent(TRACE_INFO, "Skipping line %d (expires can be specified only for 'mark' actions)\n", lineNum);
      else 
	rule->expireTime = atoi(token);
    } else if(!strcmp(token, "all")) {
      if(rule->ruleIdCleared == 0) 
	traceEvent(TRACE_INFO, "Skipping line %d (all specified without rule to clear)\n", lineNum);
      else 
	rule->clearAllRule = 1;
    } else {
      traceEvent(TRACE_INFO, "Skipping token '%s' on line %d (it's unknown)\n", token, lineNum);
    }
  }

  /* Sanity checks... */

  if((rule->sport > NOT_USED_PORT /* top value */)
     || (rule->dport > NOT_USED_PORT /* top value */)
     || ((rule->unitValue > 0) && rule->expireTime)
     ) {
    traceEvent(TRACE_INFO, "Skipping line %d (sanity check failed)\n", lineNum);
    freeFilterRule(rule);
    return(NULL);
  }

  if(ruleSerialIdentifier >= (MAX_NUM_RULES-1)) {
    traceEvent(TRACE_INFO, "Skipping rule at line %d (too many rules defined)\n", lineNum);
    freeFilterRule(rule);
    return(NULL);
  }

  /* The rule looks good */
  rule->ruleId = ruleSerialIdentifier++;

  return(rule);
}

/* ************************** */

static void parseDnsRule(char* line, u_short lineNum) {
  traceEvent(TRACE_INFO, "Skipping '%s' (line %d)\n", line, lineNum);
}

/* ************************** */

void parseRules(char* path) {
  FILE *fd = fopen(path, "rb");
  char line[512];
  u_short lineNum=1;
  FilterRule *filterRule;

  ruleSerialIdentifier=1; /* 0 will break the logic */
  memset(filterRulesList, 0, sizeof(filterRulesList));

  if(fd == NULL) {
    traceEvent(TRACE_INFO, "Unable to locate the specified rule file '%s'.\n"
	       "It has been ignored.\n", path);
    return;
  }

  while(fgets(line, 512, fd)) {
    if((line[0] != '#') && (strlen(line) > 10)) {
      line[strlen(line)-1] = 0; /* chop() */

      if(strncmp(line, "tcp", 3) == 0) {
	FilterRuleChain *newEntry;

	filterRule = parseFilterRule(TCP_RULE, line, lineNum);

	if(filterRule != NULL) {
	  newEntry = (FilterRuleChain*)malloc(sizeof(FilterRuleChain));
	  newEntry->nextRule = tcpChain;
	  newEntry->rule = filterRule;
	  tcpChain = newEntry;
	}
      } else if(strncmp(line, "udp", 3) == 0) {
	FilterRuleChain *newEntry;

	filterRule = parseFilterRule(UDP_RULE, line, lineNum);

	if(filterRule != NULL) {
	  newEntry = (FilterRuleChain*)malloc(sizeof(FilterRuleChain));
	  newEntry->nextRule = udpChain;
	  newEntry->rule = filterRule;
	  udpChain = newEntry;
	}
      } else if(strncmp(line, "icmp", 4) == 0) {
	FilterRuleChain *newEntry;

	filterRule = parseFilterICMPRule(line, lineNum);

	if(filterRule != NULL) {
	  newEntry = (FilterRuleChain*)malloc(sizeof(FilterRuleChain));
	  newEntry->nextRule = icmpChain;
	  newEntry->rule = filterRule;
	  icmpChain = newEntry;
	}
      } else if(strncmp(line, "dns", 3) == 0)
	parseDnsRule(line, lineNum);
      else 
	traceEvent(TRACE_INFO, "Found unknown rule at line %d\n", lineNum);
    }

    lineNum++;
  }

  fclose(fd);
}

/* ************************************ */

void checkFilterChain(HostTraffic *srcHost, 
		      u_int srcHostIdx, 
		      HostTraffic *dstHost,
		      u_int dstHostIdx,
		      u_short sport, 
		      u_short dport, 
		      u_int length,       /* packet length */
		      u_int hlen,         /* offset from packet header */
		      u_int8_t flags,     /* TCP flags or ICMP type */
		      u_char protocol,    /* Protocol */
		      u_char isFragment,  /* 1 = fragment, 0 = packet */
		      const u_char* bp,   /* pointer to packet content */
		      FilterRuleChain *selectedChain,
		      u_short packetType) {
  FilterRuleChain *chainScanner = selectedChain;
  u_short numRun = 0;
  short icmp_type;

  while(chainScanner != NULL) {    
    if(numRun++ > 0) {
      chainScanner = chainScanner->nextRule;
      if(chainScanner == NULL) break;
    }

    if(((chainScanner->rule->dataType == DATA_FRAGMENT) && (!isFragment))
       || ((chainScanner->rule->dataType == DATA_PACKET) && isFragment))
      continue;

    switch(chainScanner->rule->shostType) {
    case ANY_ADDRESS: /* Anything fits */
      break;
    case BROADCAST_ADDRESS:
      if(broadcastHost(srcHost)) continue;
      break;
    case MULTICAST_ADDRESS:
      if(multicastHost(srcHost)) continue;
      break;
    case GATEWAY_ADDRESS:
      if(gatewayHost(srcHost)) continue;
      break;
    case DNS_ADDRESS:
      if(nameServerHost(srcHost)) continue;
      break;
    case NOT_BROADCAST_ADDRESS:
      if(!broadcastHost(srcHost)) continue;
      break;
    case NOT_MULTICAST_ADDRESS:
      if(!multicastHost(srcHost)) continue;
      break;
    case NOT_GATEWAY_ADDRESS:
      if(!gatewayHost(srcHost)) continue;
      break;
    case NOT_DNS_ADDRESS:
      if(!nameServerHost(srcHost)) continue;
      break;      
    }

    if(packetType != ICMP_RULE) {
      switch(chainScanner->rule->sport) {
      case ANY_PORT:  /* Check delayed */
      case NOT_ANY_PORT:
	break;
      case USED_PORT:
	if(broadcastHost(srcHost) || multicastHost(srcHost)) 
	  /* This comparison doesn't make sense here */
	  continue;
	else if((packetType == TCP_RULE) 
		&& ((srcHost->portsUsage[sport] == NULL) 
		    || (srcHost->portsUsage[sport]->clientUses == 0))
		&& ((srcHost->portsUsage[sport] == NULL) 
		    || (srcHost->portsUsage[sport]->serverUses == 0)))
	  continue;
	break;
      case NOT_USED_PORT:
	if(broadcastHost(srcHost) || multicastHost(srcHost)) 
	  /* This comparison doesn't make sense here */
	  continue;
	else if((packetType == TCP_RULE) && (srcHost->portsUsage[sport] != NULL))
	  continue;
	break;
      default:
	if(chainScanner->rule->sport != sport)
	  continue;
      }
    }
    
    /* ************************************** */

    switch(chainScanner->rule->dhostType) {
    case ANY_ADDRESS: /* Anything fits */
      break;
    case BROADCAST_ADDRESS:
      if(broadcastHost(dstHost)) continue;
      break;
    case MULTICAST_ADDRESS:
      if(multicastHost(dstHost)) continue;
      break;
    case GATEWAY_ADDRESS:
      if(gatewayHost(dstHost)) continue;
      break;
    case DNS_ADDRESS:
      if(nameServerHost(dstHost)) continue;
      break;
    case NOT_BROADCAST_ADDRESS:
      if(!broadcastHost(dstHost)) continue;
      break;
    case NOT_MULTICAST_ADDRESS:
      if(!multicastHost(dstHost)) continue;
      break;
    case NOT_GATEWAY_ADDRESS:
      if(!gatewayHost(dstHost)) continue;
      break;
    case NOT_DNS_ADDRESS:
      if(!nameServerHost(dstHost)) continue;
      break;      
    }

    if(packetType != ICMP_RULE) {
      switch(chainScanner->rule->dport) {    
      case ANY_PORT:  /* Check delayed */
      case NOT_ANY_PORT:
	break;
      case USED_PORT:
	if((packetType == TCP_RULE) 
	   && ((srcHost->portsUsage[sport] == NULL) 
	       || (srcHost->portsUsage[sport]->clientUses == 0))
	   && ((srcHost->portsUsage[sport] == NULL) 
	       || (srcHost->portsUsage[sport]->serverUses == 0)))
	  continue;
	break;
      case NOT_USED_PORT:
	if((packetType == TCP_RULE) && (srcHost->portsUsage[sport] != NULL))
	  continue;
	break;
      default:
	if(chainScanner->rule->dport != dport)
	  continue;
      }
    }

    if(((packetType == TCP_RULE) && ((chainScanner->rule->flags & flags) != chainScanner->rule->flags))
       ||
       ((packetType == ICMP_RULE) && (chainScanner->rule->flags != flags)))
      continue;

    if(chainScanner->rule->pktContentPattern != NULL) {
      char *string = (char*)bp+hlen;

      string[length] = '\0';
#ifdef DEBUG
      traceEvent(TRACE_INFO, "%d) '%s'\n", length, string); 
#endif
      if(re_search(chainScanner->rule->pktContentPattern, string,
		   length, 0, length, 0) < 0)
	continue; /* No match */
    }

    if(chainScanner->rule->pktComparisonOperator != COMPARISON_NONE)
      if(chainScanner->rule->pktComparisonType == PACKET_FRAGMENT_SIZE /* compare pkt/fragement size */) {
	if((chainScanner->rule->pktComparisonOperator == COMPARISON_LESS_THAN)
	   && (length >= chainScanner->rule->pktComparisonValue))
	  continue;

	if((chainScanner->rule->pktComparisonOperator == COMPARISON_MORE_THAN)
	   && (length <= chainScanner->rule->pktComparisonValue))
	  continue;
	
	if((chainScanner->rule->pktComparisonOperator == COMPARISON_EQUAL_TO)
	   && (length != chainScanner->rule->pktComparisonValue))
	  continue;
      }
    
    icmp_type = (protocol == IPPROTO_ICMP) ? flags : -1;
    
    /* The event correlator will do the rest of the job... 
       (e.g. packet correlation) */
    fireEvent(chainScanner->rule,
	      srcHost, srcHostIdx, 
	      dstHost, dstHostIdx,
	      icmp_type,
	      sport, dport, 
	      length);

    chainScanner = chainScanner->nextRule;
  }
}
