/*
 *  Copyright (C) 2000-2002 Luca Deri <deri@ntop.org>
 *                      
 *  		            http://www.ntop.org/
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

#define ANY_ADDRESS              0
#define BROADCAST_ADDRESS        1
#define MULTICAST_ADDRESS        2
#define GATEWAY_ADDRESS          3
#define DNS_ADDRESS              4
#define NOT_BROADCAST_ADDRESS    5
#define NOT_MULTICAST_ADDRESS    6
#define NOT_GATEWAY_ADDRESS      7
#define NOT_DNS_ADDRESS          8

#define ANY_PORT       TOP_ASSIGNED_IP_PORTS
#define NOT_ANY_PORT   TOP_ASSIGNED_IP_PORTS+1 /* Any port of the target host no matter whether the target port
				      matches the port of the previous packet (this value can be
				      specified only for the 'clear' action) */
#define USED_PORT      TOP_ASSIGNED_IP_PORTS+2 /* Port on which we've seen traffic before */
#define NOT_USED_PORT  TOP_ASSIGNED_IP_PORTS+3 /* Port on which we've seen NO traffic before */

#define DATA_PACKET      0 /* The rule applies to packets (default) */
#define DATA_FRAGMENT    1 /* The rule applies to packet fragments  */

#define COMPARISON_NONE       0 /* no comparison */
#define COMPARISON_LESS_THAN  1 /* A < B  */
#define COMPARISON_EQUAL_TO   2 /* A == B */
#define COMPARISON_MORE_THAN  3 /* A > B  */

#define PACKET_FRAGMENT_SIZE   0 /* Compare the packet/fragment size */
#define PACKET_FRAGMENT_COUNT  1 /* Compare the packet/fragment number */

#define ACTION_ALARM  0
#define ACTION_MARK   1

#define MAX_NUM_RULES    128

#define MAX_EVENT_MSG_SIZE 128

/* Don't scan for expired rules within... */
#define MIN_SCAN_TIMEOUT 10

#define UDP_RULE   0
#define TCP_RULE   1
#define ICMP_RULE  2

typedef struct matchedRule {
  u_int srcHostIdx;
  u_short sport;
  u_int dstHostIdx;
  u_short dport;
  time_t firstMatchTime, lastMatchTime;
  u_short numMatches;
} MatchedRule;

typedef struct filterRule {
  u_short ruleId;
  char*   ruleLabel;
  u_char  revert;     /* This rule will match with shost/sport & dhost/dport reverted */
  u_char  dataType;   /* Either packet (default) or fragment */
  u_char  shostType;  /* Source type any/broadcast/... */
  u_char  dhostType;  /* Source type any/broadcast/... */
  u_int   sport;      /* Source port */
  u_int   dport;      /* Destination port */
  u_int8_t flags;     /* ACK,SYN,FIN... or ICMP code (for ICMP packets) */
  struct re_pattern_buffer *pktContentPattern; /* e.g. "230 User root logged in." */
  u_char  pktComparisonType;  /* # packets, packet size */
  u_char  pktComparisonOperator;  /* none, <, >, == for the field below */
  u_char  pktComparisonValue;
  u_short unitValue;       /* Time interval on which the match shall occour since the *first* match */
  u_char  actionType;      /* Alarm, mark... */
  u_short rearmTime;       /* # seconds after which the rule is operational again */
  u_short expireTime;      /* # seconds after which the marked rule is fired if not cleared before */
  u_short ruleIdCleared;   /* rule that is cleared by this rule */
  u_char  clearAllRule;    /* If specified this rule clears all the 'ruleCleared' specified */
  u_short numMatchedRules; /* # rules in the array below */
  time_t  lastRuleCheck;   /* last time the array below has been scanned */
  MatchedRule *queuedPacketRules[MAX_NUM_RULES];
} FilterRule;


/* ******************** */

typedef struct filterRuleChain {
  FilterRule *rule;
  struct filterRuleChain *nextRule;
} FilterRuleChain;

/* ******************** */

typedef struct eventMsg {
  time_t         eventTime;
  struct in_addr sourceHost;
  struct in_addr destHost;
  u_short        ruleId;
  u_char         severity;
  char           message[MAX_EVENT_MSG_SIZE];
} EventMsg;

/* ******************** */
