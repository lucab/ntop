/*
 *  Copyright (C) 2002-12 Luca Deri <deri@ntop.org>
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

/* This plugin works only with threads */

#include "ntop.h"
#include "globals-report.h"

static void* netflowMainLoop(void* _deviceId);
#ifdef HAVE_SNMP
static void* netflowUtilsLoop(void* _deviceId);
#endif

//#define DEBUG_FLOWS

#define CONST_NETFLOW_STATISTICS_HTML       "statistics.html"

#define NTOP_BASE_ID 57472

#define valueOf(a) (a == NULL ? "" : a)
#define isEmpty(a) ((a == NULL) || (a[0] == '\0') ? 1 : 0)

#define SWAP8(a,b)  { u_int8_t  c = a; a = b; b = c; }
#define SWAP16(a,b) { u_int16_t c = a; a = b; b = c; }
#define SWAP32(a,b) { u_int32_t c = a; a = b; b = c; }

/*
  Cisco ASA
  http://www.cisco.com/en/US/docs/security/asa/asa81/netflow/netflow.html#wp1028202
*/

/* ********************************* */

/* Forward */
static int setNetFlowInSocket(int);
static void setPluginStatus(char * status);
static int initNetFlowFunct(void);
static void termNetflowFunct(u_char termNtop /* 0=term plugin, 1=term ntop */);
static void termNetflowDevice(int deviceId);
static void initNetFlowDevice(int deviceId);
#ifdef DEBUG_FLOWS
static void handleNetFlowPacket(u_char *_deviceId,
				const struct pcap_pkthdr *h,
				const u_char *p);
#endif
static void handleNetflowHTTPrequest(char* url);
static void printNetFlowStatisticsRcvd(int deviceId);
static void printNetFlowConfiguration(int deviceId);
static int createNetFlowDevice(int netFlowDeviceId);
static int mapNetFlowDeviceToNtopDevice(int deviceId);

struct generic_netflow_record {
  /* v5 */
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t sentPkts, rcvdPkts;
  u_int32_t sentOctets, rcvdOctets;
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t  tcp_flags;  /* Cumulative OR of tcp flags */
  u_int8_t  proto;       /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int32_t dst_as;     /* dst peer/origin Autonomous System */
  u_int32_t src_as;     /* source peer/origin Autonomous System */
  u_int8_t  dst_mask;   /* destination route's mask bits */
  u_int8_t  src_mask;   /* source route's mask bits */

  /* v9 */
  char src_mac[LEN_ETHERNET_ADDRESS], src_mac_set, dst_mac[LEN_ETHERNET_ADDRESS], dst_mac_set;
  u_int16_t vlanId;
  /* IPv6 support courtesy of John_Poland@boces.monroe.edu */
  u_int8_t  srcaddr6[16];   /* Source IPv6 Address */
  u_int8_t  dstaddr6[16];   /* Destination IPv6 Address */


  /* L7 */
  u_int16_t l7_proto;

  /* Latency extensions */
  u_int32_t client_nw_latency_sec, client_nw_latency_usec;
  u_int32_t server_nw_latency_sec, server_nw_latency_usec;
  u_int32_t appl_latency_sec, appl_latency_usec;

  /* VoIP Extensions */
  char sip_call_id[50], sip_calling_party[50], sip_called_party[50];
};

/* ****************************** */

u_char static pluginActive = 0;

static ExtraPage netflowExtraPages[] = {
  { NULL, CONST_NETFLOW_STATISTICS_HTML, "Statistics" },
  { NULL, NULL, NULL }
};

static PluginInfo netflowPluginInfo[] = {
  {
    VERSION, /* current ntop version */
    "NetFlow",
    "This plugin is used to setup, activate and deactivate NetFlow support.<br>"
    "<b>ntop</b> can both collect and receive "
    "<A HREF=http://www.cisco.com/warp/public/cc/pd/iosw/ioft/neflct/tech/napps_wp.htm>NetFlow</A> "
    "V1/V5/V7/V9 and <A HREF=http://ipfix.doit.wisc.edu/>IPFIX</A> (draft) data.<br>"
    "<i>Received flow data is reported as a separate 'NIC' in the regular <b>ntop</b> "
    "reports.<br><em>Remember to <A HREF=/switch.html>switch</A> the reporting NIC.</em>",
    "4.4", /* version */
    "<a href=\"http://luca.ntop.org/\" alt=\"Luca's home page\">L.Deri</A>",
    "NetFlow", /* http://<host>:<port>/plugins/NetFlow */
    0, /* Active by default */
    ViewConfigure,
    1, /* Inactive setup */
    initNetFlowFunct, /* InitFunc */
    termNetflowFunct, /* TermFunc */
#ifdef DEBUG_FLOWS
    handleNetFlowPacket,
#else
    NULL, /* PluginFunc */
#endif
    handleNetflowHTTPrequest,
    NULL, /* no host creation/deletion handle */
#ifdef DEBUG_FLOWS
    "udp and (port 2055 or port 9996)",
#else
    NULL, /* no capture */
#endif
    NULL, /* no status */
    netflowExtraPages
  }
};

#ifdef MAX_NETFLOW_FLOW_BUFFER
static float netflowflowBuffer[MAX_NETFLOW_FLOW_BUFFER];
static int netflowflowBufferCount;
static float netflowfmaxTime;
#endif

#ifdef MAX_NETFLOW_PACKET_BUFFER
static float netflowpacketBuffer[MAX_NETFLOW_PACKET_BUFFER];
static int netflowpacketBufferCount;
static float netflowpmaxTime;
#endif

/* ****************************** */

static char* nfValue(int deviceId, char *name, int appendDeviceId) {
  static char buf[64];

  if(appendDeviceId) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "netflow.%d.%s",
		  myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId, name);
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "netflow.%s", name);
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "NETFLOW: nfValue=%s", buf);
#endif

  return(buf);
}

/* ************************************** */

static int setNetFlowInSocket(int deviceId) {
  struct sockaddr_in sockIn;
  int sockopt = 1;

  if(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket > 0) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Collector terminated");
    closeNwSocket(&myGlobals.device[deviceId].netflowGlobals->netFlowInSocket);
    shutdown(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket, SHUT_RDWR);
#ifdef HAVE_SCTP
    if(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket > 0) {
	closeNwSocket(&myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket);
	shutdown(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket, SHUT_RDWR);
	}
#endif
  }

  if(myGlobals.device[deviceId].netflowGlobals->netFlowInPort > 0) {
    errno = 0;
    myGlobals.device[deviceId].netflowGlobals->netFlowInSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if((myGlobals.device[deviceId].netflowGlobals->netFlowInSocket <= 0) || (errno != 0) ) {
      traceEvent(CONST_TRACE_INFO, "NETFLOW: Unable to create a UDP socket - returned %d, error is '%s'(%d)",
		 myGlobals.device[deviceId].netflowGlobals->netFlowInSocket, strerror(errno), errno);
      setPluginStatus("Disabled - Unable to create listening socket.");
      return(-1);
    }

#ifdef HAVE_SCTP
    myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);

    if((myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket <= 0) || (errno != 0)) {
      traceEvent(CONST_TRACE_INFO, "NETFLOW: Unable to create a SCTP socket - returned %d, error is '%s'(%d)",
		 myGlobals.device[deviceId].netflowGlobals->netFlowInSocket, strerror(errno), errno);
      /* setPluginStatus("SCTP disabled - Unable to create listening socket."); */
    }
#endif

    traceEvent(CONST_TRACE_INFO, "NETFLOW: Created a UDP socket (%d)",
	       myGlobals.device[deviceId].netflowGlobals->netFlowInSocket);
#ifdef HAVE_SCTP
    if(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket > 0)
      traceEvent(CONST_TRACE_INFO, "NETFLOW: Created a SCTP socket (%d)",
		 myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket);
#endif

    setsockopt(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket,
	       SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    sockIn.sin_family            = AF_INET;
    sockIn.sin_port              =(int)htons(myGlobals.device[deviceId].netflowGlobals->netFlowInPort);
    sockIn.sin_addr.s_addr       = INADDR_ANY;

    if((bind(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket,
	     (struct sockaddr *)&sockIn, sizeof(sockIn)) < 0)
#ifdef HAVE_SCTP
       || ((myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket > 0)
	   && (bind(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket,
		    (struct sockaddr *)&sockIn, sizeof(sockIn)) < 0))
#endif
       ) {
      traceEvent(CONST_TRACE_ERROR, "NETFLOW: Collector port %d already in use",
		 myGlobals.device[deviceId].netflowGlobals->netFlowInPort);
      closeNwSocket(&myGlobals.device[deviceId].netflowGlobals->netFlowInSocket);
      shutdown(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket, SHUT_RDWR);
      myGlobals.device[deviceId].netflowGlobals->netFlowInSocket = 0;
#ifdef HAVE_SCTP
      if(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket) {
	closeNwSocket(&myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket);
	shutdown(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket, SHUT_RDWR);
	}
      myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket = 0;
#endif
      return(0);
    }

#ifdef HAVE_SCTP
    if(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket > 0) {
      if(listen(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket, 100) == -1) {
	traceEvent(CONST_TRACE_ERROR, "NETFLOW: listen on SCTP socket failed [%s]",
		   strerror(errno));
      }
    }
#endif

    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Collector listening on port %d",
	       myGlobals.device[deviceId].netflowGlobals->netFlowInPort);
  }

  if((myGlobals.device[deviceId].netflowGlobals->netFlowInPort != 0)
     && (!myGlobals.device[deviceId].netflowGlobals->threadActive)) {
    /* This plugin works only with threads */
    createThread(&myGlobals.device[deviceId].netflowGlobals->netFlowThread,
		 netflowMainLoop, (void*)((long)deviceId));
#ifdef HAVE_SNMP
    createThread(&myGlobals.device[deviceId].netflowGlobals->netFlowUtilsThread,
		 netflowUtilsLoop, (void*)((long)deviceId));
#endif
    traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: NETFLOW: Started thread for receiving flows on port %d",
	       (long)myGlobals.device[deviceId].netflowGlobals->netFlowThread,
	       myGlobals.device[deviceId].netflowGlobals->netFlowInPort);
  }
  maximize_socket_buffer(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket, SO_RCVBUF);

  return(0);
}

/* *************************** */

#ifdef HAVE_SNMP
static void updateInterfaceName(InterfaceStats *ifStats) {
  char buf[32];
  struct in_addr addr;

  addr.s_addr = ifStats->netflow_device_ip;

  getIfName(_intoa(addr, buf, sizeof(buf)),
	    /* ifStats->netflow_device_port, */
	    "public", ifStats->interface_id,
	    ifStats->interface_name,
	    sizeof(ifStats->interface_name));
}
#endif

/* *************************** */

static void updateNetFlowIfStats(u_int32_t netflow_device_ip,
				 u_int16_t netflow_device_port,
				 int deviceId, u_int32_t ifId,
				 u_char selfUpdate, u_char sentStats,
				 u_int32_t _pkts, u_int32_t _octets) {
  if(_pkts == 0)
    return;
  else {
    u_char found = 0;
    InterfaceStats *ifStats, *prev = NULL;
    Counter pkts = (Counter)_pkts;
    Counter octets = (Counter)_octets;

    accessMutex(&myGlobals.device[deviceId].netflowGlobals->ifStatsMutex, "rrdPluginNetflow");

    ifStats = myGlobals.device[deviceId].netflowGlobals->ifStats;

    while(ifStats != NULL) {
      if((ifStats->interface_id == ifId)
	 && (ifStats->netflow_device_ip == netflow_device_ip)
	 && (ifStats->netflow_device_port == netflow_device_port)
	 ) {
	found = 1;
	break;
      } else if(ifStats->interface_id > ifId)
	break;
      else {
	prev    = ifStats;
	ifStats = ifStats->next;
      }
    }

    if(!found) {
      if((ifStats = (InterfaceStats*)malloc(sizeof(InterfaceStats))) == NULL) {
	traceEvent(CONST_TRACE_ERROR, "NETFLOW: not enough memory");
	releaseMutex(&myGlobals.device[deviceId].netflowGlobals->ifStatsMutex);
	return;
      }

      memset(ifStats, 0, sizeof(InterfaceStats));
      ifStats->netflow_device_ip = netflow_device_ip,
	ifStats->netflow_device_port = netflow_device_port,
	ifStats->interface_id = ifId;
      resetTrafficCounter(&ifStats->outBytes);
      resetTrafficCounter(&ifStats->outPkts);
      resetTrafficCounter(&ifStats->inBytes);
      resetTrafficCounter(&ifStats->inPkts);
      resetTrafficCounter(&ifStats->selfBytes);
      resetTrafficCounter(&ifStats->selfPkts);

      if(prev == NULL) {
	ifStats->next = myGlobals.device[deviceId].netflowGlobals->ifStats;
	myGlobals.device[deviceId].netflowGlobals->ifStats = ifStats;
      } else {
	ifStats->next = prev->next;
	prev->next = ifStats;
      }

#ifdef HAVE_SNMP
      accessMutex(&myGlobals.device[deviceId].netflowGlobals->ifStatsQueueMutex, "netflowUtilsLoop");
      if(myGlobals.device[deviceId].netflowGlobals->ifStatsQueue_len < (MAX_INTERFACE_STATS_QUEUE_LEN-1)) {
	myGlobals.device[deviceId].netflowGlobals->ifStatsQueue[myGlobals.device[deviceId].
								netflowGlobals->ifStatsQueue_len++] = ifStats;
	signalCondvar(&myGlobals.device[deviceId].netflowGlobals->ifStatsQueueCondvar, 0);
      }
      releaseMutex(&myGlobals.device[deviceId].netflowGlobals->ifStatsQueueMutex);
#else
      ifStats->interface_name[0] = '\0';
#endif
    }

    releaseMutex(&myGlobals.device[deviceId].netflowGlobals->ifStatsMutex);

    if(selfUpdate) {
      incrementTrafficCounter(&ifStats->selfBytes, octets);
      incrementTrafficCounter(&ifStats->selfPkts, pkts);
    } else {
      if(sentStats) {
	incrementTrafficCounter(&ifStats->outBytes, octets);
	incrementTrafficCounter(&ifStats->outPkts, pkts);
      } else {
	incrementTrafficCounter(&ifStats->inBytes, octets);
	incrementTrafficCounter(&ifStats->inPkts, pkts);
      }
    }
  }
}

/* *************************** */

static void updateInterfaceStats(u_int32_t netflow_device_ip,
				 u_int16_t netflow_device_port,
				 int deviceId, struct generic_netflow_record *record) {

  if((myGlobals.device[deviceId].netflowGlobals == NULL) || (record == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "NETFLOW: internal error, NULL interface stats");
    return;
  }

  if(0)
    traceEvent(CONST_TRACE_INFO, "NETFLOW: updateInterfaceStats(%d/%d) "
	       "[sent_pkts=%d][sent_bytes=%d][rcvd_pkts=%d][rcvd_bytes=%d]",
	       record->input, record->output,
	       record->sentPkts, record->sentOctets,
	       record->rcvdPkts, record->rcvdOctets);

  updateNetFlowIfStats(netflow_device_ip, netflow_device_port, deviceId, record->output, 0, 1,
		       record->sentPkts, record->sentOctets);

  if(record->input == record->output)
    updateNetFlowIfStats(netflow_device_ip, netflow_device_port,
			 deviceId, record->input,
			 1 /* self update */, 0, (2*record->sentPkts),
			 (2*record->sentOctets));
  else if(record->rcvdPkts != 0) {
    updateNetFlowIfStats(netflow_device_ip, netflow_device_port,
			 deviceId, record->input, 0, 0,
			 record->rcvdPkts, record->rcvdOctets);
  } else {
    /* pre v9 */
    updateNetFlowIfStats(netflow_device_ip, netflow_device_port,
			 deviceId, record->input, 0, 0,
			 record->sentPkts, record->sentOctets);
  }
}

/* *************************** */

static void de_endianFlow(struct generic_netflow_record *record) {
  NTOHL(record->srcaddr); NTOHL(record->dstaddr);
  NTOHL(record->nexthop);
  NTOHS(record->l7_proto);
  NTOHS(record->input); NTOHS(record->output);
  NTOHL(record->sentPkts); NTOHL(record->rcvdPkts);
  NTOHL(record->sentOctets); NTOHL(record->rcvdOctets);
  NTOHL(record->first); NTOHL(record->last);
  NTOHS(record->srcport); NTOHS(record->dstport);
  NTOHL(record->src_as); NTOHL(record->dst_as);
  NTOHS(record->vlanId);
  NTOHL(record->client_nw_latency_sec); NTOHL(record->client_nw_latency_usec);
  NTOHL(record->server_nw_latency_sec); NTOHL(record->server_nw_latency_usec);
  NTOHL(record->appl_latency_sec); NTOHL(record->appl_latency_usec);

  if(record->l7_proto >= IPOQUE_MAX_SUPPORTED_PROTOCOLS)
    record->l7_proto = IPOQUE_PROTOCOL_UNKNOWN; /* Just to be safe */
}

/* *************************** */

static inline int is_zero_timeval(struct timeval *tv) {
  return(((tv->tv_sec == 0) && (tv->tv_usec == 0)) ? 1 : 0);
}

/* *************************** */

static int handleGenericFlow(u_int32_t netflow_device_ip,
			     u_int16_t netflow_device_port,
			     time_t recordActTime, time_t recordSysUpTime,
			     struct generic_netflow_record *record,
			     int deviceId, time_t *firstSeen, time_t *lastSeen,
			     u_char deEndianize) {
  int actualDeviceId;
  char theFlags[256], srcPseudoLocal, dstPseudoLocal;
  u_int16_t srcAS, dstAS;
  struct in_addr a, b;
  struct in6_addr a6, b6;
  HostAddr addr1, addr2;
  HostTraffic *srcHost=NULL, *dstHost=NULL;
  u_short sport, dport, proto, newSession = 0;
  TrafficCounter ctr;
  int skipSRC=0, skipDST=0;
  struct pcap_pkthdr h;
  struct tcphdr tp;
  IPSession *session = NULL;
  time_t initTime;
  Counter total_pkts, total_bytes;
  u_int total_flows, ratio;
  u_int16_t major_proto;

#ifdef MAX_NETFLOW_FLOW_BUFFER
  float elapsed;
  struct timeval netflowStartOfFlowProcessing,
    netflowEndOfFlowProcessing;

  gettimeofday(&netflowStartOfFlowProcessing, NULL);
#endif

  if(deEndianize) de_endianFlow(record);

  major_proto = record->l7_proto;

  if(myGlobals.runningPref.debugMode)
    traceEvent(CONST_TRACE_INFO, ">>>> NETFLOW: handleGenericFlow() called");

  myGlobals.device[deviceId].netflowGlobals->numNetFlowsRcvd++;

  /* Bad flow(zero packets) */
  if((record->sentPkts == 0) && (record->rcvdPkts == 0)) {
    myGlobals.device[deviceId].netflowGlobals->numBadFlowPkts++;

    if(myGlobals.runningPref.debugMode)
      traceEvent(CONST_TRACE_INFO, ">>>> NETFLOW: handleGenericFlow(): discarded zero packets flow");

    return(0);
  }

  /* Bad flow(zero length) */
  if((record->sentOctets == 0) && (record->rcvdOctets == 0)) {
    myGlobals.device[deviceId].netflowGlobals->numBadFlowBytes++;

    if(myGlobals.runningPref.debugMode)
      traceEvent(CONST_TRACE_INFO, ">>>> NETFLOW: handleGenericFlow(): discarded zero length flow");

    return(0);
  }

  /* Bad flow(more packets than bytes) */
  if((record->sentPkts > record->sentOctets)
     || (record->rcvdPkts > record->rcvdOctets)) {
    myGlobals.device[deviceId].netflowGlobals->numBadFlowReality++;

    if(myGlobals.runningPref.debugMode)
      traceEvent(CONST_TRACE_INFO, ">>>> NETFLOW: handleGenericFlow(): discarded invalid packet/bytes ratio flow");
    return(0);
  }

  myGlobals.actTime = time(NULL);
  initTime = recordActTime-(recordSysUpTime/1000);

  *firstSeen = (record->first/1000) + initTime;
  *lastSeen  = (record->last/1000) + initTime;

  /* Sanity check */
  if(*lastSeen > myGlobals.actTime) *lastSeen = myGlobals.actTime;
  if(*firstSeen > *lastSeen) *firstSeen = *lastSeen;

  myGlobals.device[deviceId].netflowGlobals->numNetFlowsProcessed++;

  if ((record->srcaddr==0) && (record->dstaddr==0)) {
    memcpy(a6.s6_addr,record->srcaddr6,sizeof(a6.s6_addr));
    memcpy(b6.s6_addr,record->dstaddr6,sizeof(b6.s6_addr));
  } else {
    a.s_addr = record->srcaddr;
    b.s_addr = record->dstaddr;
  }
  sport    = record->srcport;
  dport    = record->dstport;
  proto    = record->proto;
  srcAS    = record->src_as;
  dstAS    = record->dst_as;

if(myGlobals.runningPref.debugMode) {
    char buf1[256], buf[256];

    traceEvent(CONST_TRACE_INFO,
	       "[%s:%d <-> %s:%d][sent pkt=%u/len=%u][rcvd pkt=%u/len=%u][sAS=%d/dAS=%d][proto=%d]",
	       _intoa(a, buf, sizeof(buf)), sport,
	       _intoa(b, buf1, sizeof(buf1)), dport,
	       record->sentPkts, record->sentOctets,
	       record->rcvdPkts, record->rcvdOctets,
	       srcAS, dstAS, proto);
  }

  switch(myGlobals.device[deviceId].netflowGlobals->netFlowAggregation) {
  case noAggregation:
    /* Nothing to do */
    break;
  case portAggregation:
    a.s_addr = b.s_addr = 0; /* 0.0.0.0 */
    memset(a6.s6_addr,0,sizeof(a6.s6_addr));
    memset(b6.s6_addr,0,sizeof(b6.s6_addr));
    break;
  case hostAggregation:
    sport = dport = 0;
    break;
  case protocolAggregation:
    skipDST = skipSRC = 1;
    a.s_addr = b.s_addr = 0; /* 0.0.0.0 */
    memset(a6.s6_addr,0,sizeof(a6.s6_addr));
    memset(b6.s6_addr,0,sizeof(b6.s6_addr));
    sport = dport = 0;
    srcAS = dstAS = 0;
    break;
  case asAggregation:
    skipDST = skipSRC = 1;
    a.s_addr = b.s_addr = 0; /* 0.0.0.0 */
    memset(a6.s6_addr,0,sizeof(a6.s6_addr));
    memset(b6.s6_addr,0,sizeof(b6.s6_addr));
    sport = dport = 0;
    proto = 17; /* UDP */
    break;
  }

  if(myGlobals.device[deviceId].netflowGlobals->netFlowDebug) {
    theFlags[0] = '\0';

    if(record->tcp_flags & TH_SYN)
      strncat(theFlags, "SYN ", (sizeof(theFlags) - strlen(theFlags) - 1));
    if(record->tcp_flags & TH_FIN)
      strncat(theFlags, "FIN ", (sizeof(theFlags) - strlen(theFlags) - 1));
    if(record->tcp_flags & TH_RST)
      strncat(theFlags, "RST ", (sizeof(theFlags) - strlen(theFlags) - 1));
    if(record->tcp_flags & TH_ACK)
      strncat(theFlags, "ACK ", (sizeof(theFlags) - strlen(theFlags) - 1));
    if(record->tcp_flags & TH_PUSH)
      strncat(theFlags, "PUSH", (sizeof(theFlags) - strlen(theFlags) - 1));
  }

  /* traceEvent(CONST_TRACE_INFO, "NETFLOW_DEBUG: a=%u", record->srcaddr); */

  actualDeviceId = deviceId;

  if((actualDeviceId == -1) ||(actualDeviceId >= myGlobals.numDevices)) {
    traceEvent(CONST_TRACE_ERROR, "NETFLOW: deviceId(%d) is out of range - ignored",
	       actualDeviceId);
    return(-1);
  }

  total_pkts  = record->sentPkts + record->rcvdPkts;
  total_bytes = record->sentOctets + record->rcvdOctets;
  total_flows = (record->sentPkts ? 1 : 0) + (record->rcvdPkts ? 1 : 0);
  ratio = (u_int)(total_bytes/total_pkts);

  myGlobals.device[actualDeviceId].receivedPkts.value += total_pkts;
  myGlobals.device[actualDeviceId].ethernetPkts.value += total_pkts;
  myGlobals.device[actualDeviceId].ipPkts.value       += total_pkts;

  /* Average number of packets */
  updateDevicePacketStats(ratio, actualDeviceId);

  myGlobals.device[actualDeviceId].ethernetBytes.value += total_bytes;
  if ((record->srcaddr==0) && (record->dstaddr==0)) {
    myGlobals.device[actualDeviceId].ipv6Bytes.value     += total_bytes;
  } else {
    myGlobals.device[actualDeviceId].ipv4Bytes.value     += total_bytes;
  }


  if (ratio > 0) {
    if(ratio <= 64)
      myGlobals.device[actualDeviceId].rcvdPktStats.upTo64.value += total_pkts;
    else if(ratio <= 128)
      myGlobals.device[actualDeviceId].rcvdPktStats.upTo128.value += total_pkts;
    else if(ratio <= 256)
      myGlobals.device[actualDeviceId].rcvdPktStats.upTo256.value += total_pkts;
    else if(ratio <= 512)
      myGlobals.device[actualDeviceId].rcvdPktStats.upTo512.value += total_pkts;
    else if(ratio <= 1024)
      myGlobals.device[actualDeviceId].rcvdPktStats.upTo1024.value += total_pkts;
    else if(ratio <= 1518)
      myGlobals.device[actualDeviceId].rcvdPktStats.upTo1518.value += total_pkts;
  }

  /* accessMutex(&myGlobals.hostsHashMutex, "processNetFlowPacket"); */

  updateInterfaceStats(netflow_device_ip, netflow_device_port, deviceId, record);

  if(!skipSRC) {
    switch((skipSRC = isOKtoSave(record->srcaddr,
				 myGlobals.device[deviceId].netflowGlobals->whiteNetworks,
				 myGlobals.device[deviceId].netflowGlobals->blackNetworks,
				 myGlobals.device[deviceId].netflowGlobals->numWhiteNets,
				 myGlobals.device[deviceId].netflowGlobals->numBlackNets)) ) {
    case 1:
      myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedWhiteList++;
      break;
    case 2:
      myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedBlackList++;
      break;
    default:
      myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryAccepted++;
      break;
    }
  }

  if(!skipDST) {
    switch((skipDST = isOKtoSave(record->dstaddr,
				 myGlobals.device[deviceId].netflowGlobals->whiteNetworks,
				 myGlobals.device[deviceId].netflowGlobals->blackNetworks,
				 myGlobals.device[deviceId].netflowGlobals->numWhiteNets,
				 myGlobals.device[deviceId].netflowGlobals->numBlackNets)) ) {
    case 1:
      myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedWhiteList++;
      break;
    case 2:
      myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedBlackList++;
      break;
    default:
      myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryAccepted++;
      break;
    }
  }

#ifdef DEBUG_FLOWS
  if(0) {
    traceEvent(CONST_TRACE_INFO, "DEBUG: isOKtoSave(%08x) - src - returned %s",
	       record->srcaddr,
	       skipSRC == 0 ? "OK" : skipSRC == 1 ? "failed White list" : "failed Black list");
    traceEvent(CONST_TRACE_INFO, "DEBUG: isOKtoSave(%08x) - dst - returned %s",
	       record->dstaddr,
	       skipDST == 0 ? "OK" : skipDST == 1 ? "failed White list" : "failed Black list");
  }
#endif

  if ((a.s_addr == 0) && (b.s_addr == 0)) {
     addrput(AF_INET6, &addr1, &b6);
     addrput(AF_INET6, &addr2, &a6);
  }
  else {
     addrput(AF_INET, &addr1, &b);
     addrput(AF_INET, &addr2, &a);
  }

  if(!skipDST)
    dstHost = lookupHost(&addr1, NULL, record->vlanId, 0, 1, deviceId, NULL, NULL);
  else
    dstHost = myGlobals.device[deviceId].netflowGlobals->dummyHost;

  if(!skipSRC)
    srcHost = lookupHost(&addr2, NULL, record->vlanId, 0, 1, deviceId, NULL, NULL);
  else
    srcHost = myGlobals.device[deviceId].netflowGlobals->dummyHost;

  if((srcHost == NULL) ||(dstHost == NULL)) {
#ifdef DEBUG_FLOWS
    if(myGlobals.runningPref.debugMode)
      traceEvent(CONST_TRACE_INFO, "DEBUG: srcHost=%p, dstHost=%p\n",
		 (void*)srcHost, (void*)dstHost);
#endif
    return(0);
  }

  /*
    All hosts with a netmask are assumed to be (pseudo)local
  */
  if((srcHost->network_mask == 0) && record->src_mask) {
    srcHost->network_mask = record->src_mask;
    FD_SET(FLAG_SUBNET_PSEUDO_LOCALHOST, &srcHost->flags);
    updateHostKnownSubnet(srcHost);
  }

  if((dstHost->network_mask == 0) && record->dst_mask) {
    dstHost->network_mask = record->dst_mask;
    FD_SET(FLAG_SUBNET_PSEUDO_LOCALHOST, &dstHost->flags);
    updateHostKnownSubnet(dstHost);
  }

  if(srcHost->firstSeen > *firstSeen) srcHost->firstSeen = *firstSeen;
  if(srcHost->lastSeen < *lastSeen)   srcHost->lastSeen = *lastSeen;
  if(dstHost->firstSeen > *firstSeen) dstHost->firstSeen = *firstSeen;
  if(dstHost->lastSeen < *lastSeen)   dstHost->lastSeen = *lastSeen;

#ifdef DEBUG_FLOWS
  if(myGlobals.runningPref.debugMode)
    traceEvent(CONST_TRACE_INFO, "DEBUG: %s:%d -> %s:%d [last=%u][first=%u][last-first=%d]",
	       srcHost->hostNumIpAddress, sport,
	       dstHost->hostNumIpAddress, dport, record->last, record->first,
	       (int)(*lastSeen - *firstSeen));
#endif

  /* Commented out ... already done in updatePacketCount()                         */
  /* srcHost->pktSent.value     += record->sentPkts, dstHost->pktRcvd.value     += record->sentPkts; */
  /* [NOTE: this has to be repeated for the reverse direction ]
     srcHost->bytesSent.value   += len,     dstHost->bytesRcvd.value   += len;
  */
  if (addr2.hostFamily==AF_INET6) {
    srcHost->ipv6BytesSent.value += record->sentOctets, dstHost->ipv6BytesRcvd.value += record->sentOctets;
    dstHost->ipv6BytesSent.value += record->rcvdOctets, srcHost->ipv6BytesRcvd.value += record->rcvdOctets;
  }
  else {
    srcHost->ipv4BytesSent.value += record->sentOctets, dstHost->ipv4BytesRcvd.value += record->sentOctets;
    dstHost->ipv4BytesSent.value += record->rcvdOctets, srcHost->ipv4BytesRcvd.value += record->rcvdOctets;
  }


  if(srcAS != 0) srcHost->hostAS = srcAS;
  if(dstAS != 0) dstHost->hostAS = dstAS;

  if(record->src_mac_set) {
    char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

    memcpy(srcHost->ethAddress, record->src_mac, LEN_ETHERNET_ADDRESS);
    strncpy(srcHost->ethAddressString,
	    etheraddr_string(srcHost->ethAddress, etherbuf),
	    sizeof(srcHost->ethAddressString));
  }

  if(record->dst_mac_set) {
    char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

    memcpy(dstHost->ethAddress, record->dst_mac, LEN_ETHERNET_ADDRESS);
    strncpy(dstHost->ethAddressString,
            etheraddr_string(dstHost->ethAddress, etherbuf),
            sizeof(dstHost->ethAddressString));

  }
  srcHost->ifId = record->input, dstHost->ifId = record->output;

#ifdef DEBUG_FLOWS
  if((srcAS == 13018) || (dstAS == 13018))
    traceEvent(CONST_TRACE_ERROR, "************* AS %d/%d", srcHost->hostAS, dstHost->hostAS);
#endif

  if(major_proto == IPOQUE_PROTOCOL_UNKNOWN)
    major_proto = ntop_guess_undetected_protocol(record->proto, 						 
						 record->srcaddr, record->srcport, 
						 record->dstaddr, record->dstport);

  memset(&h, 0, sizeof(h));
  h.len = record->sentOctets + record->rcvdOctets;
  handleSession((const struct pcap_pkthdr*)&h, NULL, 
		record->proto, 0, 0,
		srcHost, sport,
		dstHost, dport,
		record->sentOctets, record->rcvdOctets,
		0, NULL,
		0, NULL,
		actualDeviceId, &newSession,
		major_proto, 0);

  myGlobals.device[deviceId].netflowGlobals->flowProcessed++;
  myGlobals.device[deviceId].netflowGlobals->flowProcessedBytes += total_bytes;

  ctr.value = record->sentOctets;
  updatePacketCount(srcHost, dstHost, ctr, record->sentPkts, actualDeviceId);

  if(record->rcvdOctets > 0) {
    ctr.value = record->rcvdOctets;
    updatePacketCount(dstHost, srcHost, ctr, record->rcvdPkts, actualDeviceId);
  }

  srcPseudoLocal = subnetPseudoLocalHost(srcHost);
  dstPseudoLocal = subnetPseudoLocalHost(dstHost);

  if(srcPseudoLocal) {
    if(dstPseudoLocal) {
      incrementTrafficCounter(&srcHost->bytesSentLoc, record->sentOctets);
      incrementTrafficCounter(&dstHost->bytesRcvdLoc, record->sentOctets);
      if(record->rcvdOctets > 0) {
	incrementTrafficCounter(&srcHost->bytesRcvdLoc, record->rcvdOctets);
	incrementTrafficCounter(&dstHost->bytesSentLoc, record->rcvdOctets);
      }
    } else {
      incrementTrafficCounter(&srcHost->bytesSentRem, record->sentOctets);
      incrementTrafficCounter(&dstHost->bytesRcvdLoc, record->sentOctets);
      if(record->rcvdOctets > 0) {
	incrementTrafficCounter(&srcHost->bytesRcvdFromRem, record->rcvdOctets);
	incrementTrafficCounter(&dstHost->bytesSentLoc, record->rcvdOctets);
      }
    }
  } else {
    /* srcHost is remote */
    if(dstPseudoLocal) {
      incrementTrafficCounter(&srcHost->bytesSentLoc, record->sentOctets);
      incrementTrafficCounter(&dstHost->bytesRcvdFromRem, record->sentOctets);
      if(record->rcvdOctets > 0) {
	incrementTrafficCounter(&srcHost->bytesRcvdLoc, record->rcvdOctets);
	incrementTrafficCounter(&dstHost->bytesSentRem, record->rcvdOctets);
      }
    } else {
      incrementTrafficCounter(&srcHost->bytesSentRem, record->sentOctets);
      incrementTrafficCounter(&dstHost->bytesRcvdFromRem, record->sentOctets);
      if(record->rcvdOctets > 0) {
	incrementTrafficCounter(&srcHost->bytesRcvdFromRem, record->rcvdOctets);
	incrementTrafficCounter(&dstHost->bytesSentRem, record->rcvdOctets);
      }
    }
  }

  h.ts.tv_sec = recordActTime, h.ts.tv_usec = 0;

  switch(proto) {
  case IPPROTO_ICMP: /* ICMP */
    myGlobals.device[actualDeviceId].icmpBytes.value += total_bytes;
    incrementHostTrafficCounter(srcHost, icmpSent, record->sentOctets);
    incrementHostTrafficCounter(dstHost, icmpRcvd, record->sentOctets);
    if(record->rcvdOctets > 0) {
      incrementHostTrafficCounter(srcHost, icmpRcvd, record->rcvdOctets);
      incrementHostTrafficCounter(dstHost, icmpSent, record->rcvdOctets);
    }
    myGlobals.device[actualDeviceId].netflowGlobals->numNetFlowsICMPRcvd += total_flows,
      myGlobals.device[actualDeviceId].netflowGlobals->totalNetFlowsICMPSize += total_bytes;
    break;

  case IPPROTO_TCP: /* TCP */
    myGlobals.device[actualDeviceId].tcpBytes.value += total_bytes;
    myGlobals.device[actualDeviceId].netflowGlobals->numNetFlowsTCPRcvd += total_flows,
      myGlobals.device[actualDeviceId].netflowGlobals->totalNetFlowsTCPSize += total_bytes;

    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].
			    numEstablishedTCPConnections, 1);
    updateInterfacePorts(actualDeviceId, sport, dport, record->sentOctets);
    updateUsedPorts(srcHost, dstHost, sport, dport, record->sentOctets);
    if(record->rcvdOctets > 0) {
      updateInterfacePorts(actualDeviceId, dport, sport, record->rcvdOctets);
      updateUsedPorts(dstHost, srcHost, dport, sport, record->rcvdOctets);
    }

    if(srcPseudoLocal) {
      if(dstPseudoLocal) {
	incrementTrafficCounter(&srcHost->tcpSentLoc, record->sentOctets);
	incrementTrafficCounter(&dstHost->tcpRcvdLoc, record->sentOctets);
	if(record->rcvdOctets > 0) {
	  incrementTrafficCounter(&srcHost->tcpRcvdLoc, record->rcvdOctets);
	  incrementTrafficCounter(&dstHost->tcpSentLoc, record->rcvdOctets);
	}
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].
				tcpGlobalTrafficStats.local, total_bytes);
      } else {
	incrementTrafficCounter(&srcHost->tcpSentRem, record->sentOctets);
	incrementTrafficCounter(&dstHost->tcpRcvdLoc, record->sentOctets);
	if(record->rcvdOctets > 0) {
	  incrementTrafficCounter(&srcHost->tcpRcvdFromRem, record->rcvdOctets);
	  incrementTrafficCounter(&dstHost->tcpSentLoc, record->rcvdOctets);
	}
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].
				tcpGlobalTrafficStats.local2remote, total_bytes);
      }
    } else {
      /* srcHost is remote */
      if(dstPseudoLocal) {
	incrementTrafficCounter(&srcHost->tcpSentLoc, record->sentOctets);
	incrementTrafficCounter(&dstHost->tcpRcvdFromRem, record->sentOctets);
	if(record->rcvdOctets > 0) {
	  incrementTrafficCounter(&srcHost->tcpRcvdLoc, record->rcvdOctets);
	  incrementTrafficCounter(&dstHost->tcpSentRem, record->rcvdOctets);
	}
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].
				tcpGlobalTrafficStats.remote2local, total_bytes);
      } else {
	incrementTrafficCounter(&srcHost->tcpSentRem, record->sentOctets);
	incrementTrafficCounter(&dstHost->tcpRcvdFromRem, record->sentOctets);
	if(record->rcvdOctets > 0) {
	  incrementTrafficCounter(&srcHost->tcpRcvdFromRem, record->rcvdOctets);
	  incrementTrafficCounter(&dstHost->tcpSentRem, record->rcvdOctets);
	}
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].
				tcpGlobalTrafficStats.remote, total_bytes);
      }
    }

    tp.th_sport = htons(sport), tp.th_dport = htons(dport);
    tp.th_flags = record->tcp_flags;
#ifdef DEBUG_FLOWS
    /* traceEvent(CONST_TRACE_INFO, "handleSession(TCP)"); */
#endif

    session = handleSession(&h, NULL, record->proto,
			    0, 0, srcHost, sport, dstHost, dport,
			    record->sentOctets, record->rcvdOctets,
			    0, &tp, 0, NULL, actualDeviceId, &newSession,
			    major_proto, 1 /* FIX 0 */);
    break;

  case IPPROTO_UDP: /* UDP */
    myGlobals.device[actualDeviceId].netflowGlobals->numNetFlowsUDPRcvd += total_flows,
      myGlobals.device[actualDeviceId].netflowGlobals->totalNetFlowsUDPSize += total_bytes;

    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpBytes, total_bytes);
    updateInterfacePorts(actualDeviceId, sport, dport, record->sentOctets);
    updateUsedPorts(srcHost, dstHost, sport, dport, record->sentOctets);
    if(record->rcvdOctets > 0) {
      updateInterfacePorts(actualDeviceId, dport, sport, record->rcvdOctets);
      updateUsedPorts(dstHost, srcHost, dport, sport, record->rcvdOctets);
    }

    if(srcPseudoLocal) {
      if(dstPseudoLocal) {
	incrementTrafficCounter(&srcHost->udpSentLoc, record->sentOctets);
	incrementTrafficCounter(&dstHost->udpRcvdLoc, record->sentOctets);
	if(record->rcvdOctets > 0) {
	  incrementTrafficCounter(&srcHost->udpRcvdLoc, record->rcvdOctets);
	  incrementTrafficCounter(&dstHost->udpSentLoc, record->rcvdOctets);
	}
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].
				udpGlobalTrafficStats.local, total_bytes);
      } else {
	incrementTrafficCounter(&srcHost->udpSentRem, record->sentOctets);
	incrementTrafficCounter(&dstHost->udpRcvdLoc, record->sentOctets);
	if(record->rcvdOctets > 0) {
	  incrementTrafficCounter(&srcHost->udpRcvdFromRem, record->rcvdOctets);
	  incrementTrafficCounter(&dstHost->udpSentLoc, record->rcvdOctets);
	}
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].
				udpGlobalTrafficStats.local2remote, total_bytes);
      }
    } else {
      /* srcHost is remote */
      if(dstPseudoLocal) {
	incrementTrafficCounter(&srcHost->udpSentLoc, record->sentOctets);
	incrementTrafficCounter(&dstHost->udpRcvdFromRem, record->sentOctets);
	if(record->rcvdOctets > 0) {
	  incrementTrafficCounter(&srcHost->udpRcvdLoc, record->rcvdOctets);
	  incrementTrafficCounter(&dstHost->udpSentRem, record->rcvdOctets);
	}
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].
				udpGlobalTrafficStats.remote2local, total_bytes);
      } else {
	incrementTrafficCounter(&srcHost->udpSentRem, record->sentOctets);
	incrementTrafficCounter(&dstHost->udpRcvdFromRem, record->sentOctets);
	if(record->rcvdOctets > 0) {
	  incrementTrafficCounter(&srcHost->udpRcvdFromRem, record->rcvdOctets);
	  incrementTrafficCounter(&dstHost->udpSentRem, record->rcvdOctets);
	}
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].
				udpGlobalTrafficStats.remote, total_bytes);
      }
    }

#ifdef DEBUG_FLOWS
    /* traceEvent(CONST_TRACE_INFO, "handleSession(UDP)"); */
#endif

    session = handleSession(&h, NULL, record->proto,
			    0, 0, srcHost, sport, dstHost, dport,
			    record->sentOctets, record->rcvdOctets,
			    0, NULL, 0, NULL, actualDeviceId, &newSession,
			    major_proto, 0);
    break;

  case IPPROTO_GRE:
    incrementHostTrafficCounter(srcHost, greSent, record->sentOctets);
    incrementHostTrafficCounter(dstHost, greRcvd, record->sentOctets);
    if(record->rcvdOctets > 0) {
      incrementHostTrafficCounter(srcHost, greRcvd, record->rcvdOctets);
      incrementHostTrafficCounter(dstHost, greSent, record->rcvdOctets);
    }
    incrementHostTrafficCounter(srcHost, grePktSent, record->sentPkts);
    incrementHostTrafficCounter(dstHost, grePktRcvd, record->sentPkts);
    incrementHostTrafficCounter(srcHost, grePktRcvd, record->rcvdPkts);
    incrementHostTrafficCounter(dstHost, grePktSent, record->rcvdPkts);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].greBytes, total_bytes);
    break;

  case IPPROTO_IPSEC_ESP:
  case IPPROTO_IPSEC_AH:
    incrementHostTrafficCounter(srcHost, ipsecSent, record->sentOctets);
    incrementHostTrafficCounter(dstHost, ipsecRcvd, record->sentOctets);
    if(record->rcvdOctets > 0) {
      incrementHostTrafficCounter(srcHost, ipsecRcvd, record->rcvdOctets);
      incrementHostTrafficCounter(dstHost, ipsecSent, record->rcvdOctets);
    }
    incrementHostTrafficCounter(srcHost, ipsecPktSent, record->sentPkts);
    incrementHostTrafficCounter(dstHost, ipsecPktRcvd, record->sentPkts);
    incrementHostTrafficCounter(srcHost, ipsecPktRcvd, record->rcvdPkts);
    incrementHostTrafficCounter(dstHost, ipsecPktSent, record->rcvdPkts);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipsecBytes, total_bytes);
    break;

  default:
    myGlobals.device[actualDeviceId].netflowGlobals->numNetFlowsOtherRcvd += total_flows,
      myGlobals.device[actualDeviceId].netflowGlobals->totalNetFlowsOtherSize += total_bytes;
    break;
  }

  if(session) {
#ifdef DEBUG_FLOWS
    time_t timeDiff = recordActTime - (*lastSeen - *firstSeen);
#endif

    if(session->session_info == NULL) {
      if((!isEmpty(record->sip_call_id))
	 || (!isEmpty(record->sip_calling_party))
	 || (!isEmpty(record->sip_called_party))) {
	char tmpStr[256];

	safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
		      "Call Id: %s<br>"
		      "'%s' called '%s",
		      valueOf(record->sip_call_id),
		      valueOf(record->sip_calling_party),
		      valueOf(record->sip_called_party));

	traceEvent(CONST_TRACE_INFO, "DEBUG: ->>>>>>>> '%s'", tmpStr);
	session->session_info = strdup(tmpStr);
      }
    }

#ifdef DEBUG_FLOWS
    if(1) {
      unsigned int diff = *lastSeen - *firstSeen;

      traceEvent(CONST_TRACE_INFO, "DEBUG: %s:%d -> %s:%d [diff=%u]"
		 "[recordActTime=%d][last-first=%d]",
		 srcHost->hostNumIpAddress, sport,
		 dstHost->hostNumIpAddress, dport,
		 (unsigned int)timeDiff, (unsigned int)recordActTime,
		 diff);
    }
#endif

    if(
       ((record->client_nw_latency_sec > 0)
	|| (record->client_nw_latency_usec > 0)
	|| (record->server_nw_latency_sec > 0)
	|| (record->server_nw_latency_usec > 0))
       /* Avoid to update twice */
       && is_zero_timeval(&session->clientNwDelay)
       && is_zero_timeval(&session->serverNwDelay)
       && is_zero_timeval(&session->synAckTime)
       ) {
      gettimeofday(&session->synAckTime, NULL);
      memcpy(&session->synTime, &session->synAckTime, sizeof(struct timeval));
      memcpy(&session->ackTime, &session->synAckTime, sizeof(struct timeval));
      session->clientNwDelay.tv_sec = record->client_nw_latency_sec,
	session->clientNwDelay.tv_usec = record->client_nw_latency_usec;
      session->serverNwDelay.tv_sec = record->server_nw_latency_sec,
	session->serverNwDelay.tv_usec = record->server_nw_latency_usec;
      updateSessionDelayStats(session);
    }

    if(record->l7_proto == IPOQUE_PROTOCOL_UNKNOWN)
      session->l7.major_proto = 
	ntop_guess_undetected_protocol(proto, 
				       record->srcaddr, record->srcport, 
				       record->dstaddr, record->dstport);
    else
      session->l7.major_proto = record->l7_proto;

    /* traceEvent(CONST_TRACE_WARNING, "l7.major_proto=%d", session->l7.major_proto); */
  } else {
    /* The session has been discarded (e.g. the NetFlow plugins might has
       been configured to discard sessions) so in case we have network delay
       we need to handle it directly */
    struct timeval clientNwDelay, serverNwDelay, when;
    int port, port_idx;

    gettimeofday(&when, NULL);
    clientNwDelay.tv_sec = record->client_nw_latency_sec, clientNwDelay.tv_usec = record->client_nw_latency_usec;
    serverNwDelay.tv_sec = record->server_nw_latency_sec, serverNwDelay.tv_usec = record->server_nw_latency_usec;

    port = dport;
    if((port_idx = mapGlobalToLocalIdx(port)) == -1) {
      port = sport;
      if((port_idx = mapGlobalToLocalIdx(port)) == -1) {
	return(-1);
      }
    }

    updatePeersDelayStats(srcHost,
			  &dstHost->serialHostIndex,
			  port,
			  &clientNwDelay,
			  &when,
			  NULL, 1 /* client */, port_idx);

    updatePeersDelayStats(dstHost,
			  &srcHost->serialHostIndex,
			  port,
			  &serverNwDelay,
			  NULL,
			  &when,
			  0 /* server */, port_idx);
  }

  /* releaseMutex(&myGlobals.hostsHashMutex); */

#ifdef MAX_NETFLOW_FLOW_BUFFER
  gettimeofday(&netflowEndOfFlowProcessing, NULL);
  elapsed = timeval_subtract(netflowEndOfFlowProcessing, netflowStartOfFlowProcessing);
  netflowflowBuffer[++netflowflowBufferCount & (MAX_NETFLOW_FLOW_BUFFER - 1)] = elapsed;
  if(elapsed > netflowfmaxTime)
    netflowfmaxTime = elapsed;
#endif

  return(0);
}

/* *************************** */

static void dumpFlow(char *buffer, int bufferLen, int deviceId) {
  static char warningSent = 0;
  char nfDumpPath[512];

  /* traceEvent(CONST_TRACE_INFO, "DEBUG: Dumping flow (len=%d)", bufferLen); */

  /* Save flow on disk if configured */
  if(myGlobals.device[deviceId].netflowGlobals->dumpInterval > 0) {
    time_t now = time(NULL);

    if(myGlobals.device[deviceId].netflowGlobals->dumpFd
       && ((now-myGlobals.device[deviceId].netflowGlobals->dumpFdCreationTime)
	   > myGlobals.device[deviceId].netflowGlobals->dumpInterval)) {
      fclose(myGlobals.device[deviceId].netflowGlobals->dumpFd);
      myGlobals.device[deviceId].netflowGlobals->dumpFd = NULL;
    }

    if(myGlobals.device[deviceId].netflowGlobals->dumpFd == NULL) {
      /* Create the file */
      safe_snprintf(__FILE__, __LINE__, nfDumpPath, sizeof(nfDumpPath),
		    "%s/interfaces/%s/",
		    myGlobals.device[deviceId].netflowGlobals->dumpPath,
		    myGlobals.device[deviceId].uniqueIfName);
      mkdir_p("NETFLOW", nfDumpPath, 0700 /* CONST_RRD_D_PERMISSIONS_PRIVATE */);

      safe_snprintf(__FILE__, __LINE__, nfDumpPath, sizeof(nfDumpPath),
		    "%s/interfaces/%s/%u.flow",
		    myGlobals.device[deviceId].netflowGlobals->dumpPath,
		    myGlobals.device[deviceId].uniqueIfName, time(NULL));

      myGlobals.device[deviceId].netflowGlobals->dumpFd = fopen(nfDumpPath, "w+");
      if(myGlobals.device[deviceId].netflowGlobals->dumpFd == NULL) {
	if(!warningSent) {
	  warningSent = 1;
	  traceEvent(CONST_TRACE_WARNING, "NETFLOW: Cannot create file %s",
		     nfDumpPath);
	}
      } else {
	myGlobals.device[deviceId].netflowGlobals->dumpFdCreationTime = now;
	/* traceEvent(CONST_TRACE_WARNING, "NETFLOW: Created file @ %u", now); */
	warningSent = 0;
      }
    }

    if(myGlobals.device[deviceId].netflowGlobals->dumpFd != NULL) {
      fprintf(myGlobals.device[deviceId].netflowGlobals->dumpFd, "%04d", bufferLen);
      if(fwrite(buffer, bufferLen, 1, myGlobals.device[deviceId].
		netflowGlobals->dumpFd) != 1) {
	if(!warningSent) {
	  warningSent = 1;
	  traceEvent(CONST_TRACE_WARNING, "NETFLOW: Error while saving data into file %s",
		     nfDumpPath);
	}
      }
    }
  }
}

/* ********************************************************* */

/* #define DEBUG_FLOWS */

#ifdef DEBUG_FLOWS
/*
static char* nf_hex_dump(char *buf, u_short len) {
  static char staticbuf[256] = { 0 };
  int i;

  staticbuf[0] = '\0';

  for(i=0; i<len; i++) {
    sprintf(&staticbuf[strlen(staticbuf)], "%02X ", buf[i] & 0xFF);
  }

  return(staticbuf);
}
*/
#endif

/* ********************************************************* */

static void updateSenderFlowSequence(int deviceId, int probeId,
				     int numFlows, u_int32_t flowSequence, u_int32_t flowVersion) {

  /*with V5/7 totNumflows and lostFlows mean flows, in V9 mean packets*/
  int resetParam = 3;
  int reset = 0;

  if(0)
    traceEvent(CONST_TRACE_INFO,
	       "updateSenderFlowSequence(deviceId=%d, probeId=%d, numFlows=%d, flowSequence=%u, version=%u)",
	       deviceId, probeId, numFlows, flowSequence, flowVersion);

  if(flowVersion == 5) {
    if(((flowSequence +  (resetParam * CONST_V5FLOWS_PER_PAK)) < myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lowestSequenceNumber))
      reset = 1;
  }
  else if(flowVersion == 7) {
    if(((flowSequence +  (resetParam * CONST_V7FLOWS_PER_PAK)) < myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lowestSequenceNumber))
      reset = 1;
  }
  else if(flowVersion == 9) {
    if(((flowSequence +  resetParam) < myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lowestSequenceNumber))
      reset = 1;
  }

 do_reset:
  if(reset) {
    myGlobals.device[deviceId].netflowGlobals->probeList[probeId].pkts = 1;
    myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lastSequenceNumber = flowSequence;
    myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lowestSequenceNumber = flowSequence;
    myGlobals.device[deviceId].netflowGlobals->probeList[probeId].highestSequenceNumber = flowSequence;
    myGlobals.device[deviceId].netflowGlobals->probeList[probeId].totNumFlows = numFlows;
  } else {
    myGlobals.device[deviceId].netflowGlobals->probeList[probeId].totNumFlows += numFlows;
    myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lastSequenceNumber = flowSequence;
    if(flowSequence > myGlobals.device[deviceId].netflowGlobals->probeList[probeId].highestSequenceNumber)
      myGlobals.device[deviceId].netflowGlobals->probeList[probeId].highestSequenceNumber = flowSequence;
    if(flowSequence < myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lowestSequenceNumber)
      myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lowestSequenceNumber = flowSequence;

    /* check if the code is the same for v5/9 */
    myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lostFlows =
      (((myGlobals.device[deviceId].netflowGlobals->probeList[probeId].highestSequenceNumber -
	 myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lowestSequenceNumber) + numFlows) -
       myGlobals.device[deviceId].netflowGlobals->probeList[probeId].totNumFlows);

#ifdef DEBUG_FLOWS
    traceEvent(CONST_TRACE_WARNING, "[lostFlows=%u][sequenceNumber=%u-%u][totNumFlows=%u]",
	       myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lostFlows,
	       myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lowestSequenceNumber,
	       myGlobals.device[deviceId].netflowGlobals->probeList[probeId].highestSequenceNumber,
	       myGlobals.device[deviceId].netflowGlobals->probeList[probeId].totNumFlows);
#endif

    if(myGlobals.device[deviceId].netflowGlobals->probeList[probeId].lostFlows
       >  myGlobals.device[deviceId].netflowGlobals->probeList[probeId].totNumFlows) {
      reset = 1; /* Something wrong: let's reset */
      goto do_reset;
    }
  }
}

/* ********************************************************* */

static void dissectFlow(u_int32_t netflow_device_ip,
			u_int16_t netflow_device_port,
			int probeId,
			char *buffer, int bufferLen, int deviceId) {
  NetFlow5Record the5Record;
  int flowVersion, numFlows = 0;
  time_t recordActTime = 0, recordSysUpTime = 0;
  struct generic_netflow_record record;
  time_t firstSeen, lastSeen;
  u_int32_t flowSequence = 0;

  memcpy(&the5Record, buffer, bufferLen > sizeof(the5Record) ? sizeof(the5Record): bufferLen);
  flowVersion = ntohs(the5Record.flowHeader.version);

#ifdef DEBUG_FLOWS
  if(1)
    traceEvent(CONST_TRACE_INFO, "NETFLOW: +++++++ version=%d",  flowVersion);
#endif

  dumpFlow(buffer, bufferLen, deviceId);

  /*
    Convert V7 flows into V5 flows in order to make ntop
    able to handle V7 flows.

    Courtesy of Bernd Ziller <bziller@ba-stuttgart.de>
  */
  if((flowVersion == 1) || (flowVersion == 7)) {
    int i;
    NetFlow1Record the1Record;
    NetFlow7Record the7Record;

    if(flowVersion == 1) {
      memcpy(&the1Record, buffer, bufferLen > sizeof(the1Record) ?
	     sizeof(the1Record): bufferLen);
      numFlows = ntohs(the1Record.flowHeader.count);
      if(numFlows > CONST_V1FLOWS_PER_PAK) numFlows = CONST_V1FLOWS_PER_PAK;
      recordActTime   = ntohl(the1Record.flowHeader.unix_secs);
      recordSysUpTime = ntohl(the1Record.flowHeader.sysUptime);
    } else {
      memcpy(&the7Record, buffer, bufferLen > sizeof(the7Record) ?
	     sizeof(the7Record): bufferLen);
      numFlows = ntohs(the7Record.flowHeader.count);
      flowSequence = ntohl(the7Record.flowHeader.flow_sequence);
      if(numFlows > CONST_V7FLOWS_PER_PAK) numFlows = CONST_V7FLOWS_PER_PAK;
      recordActTime   = ntohl(the7Record.flowHeader.unix_secs);
      recordSysUpTime = ntohl(the7Record.flowHeader.sysUptime);
    }

#ifdef DEBUG_FLOWS
    if(1)
      traceEvent(CONST_TRACE_INFO, "NETFLOW: +++++++ flows=%d",  numFlows);
#endif

    the5Record.flowHeader.version = htons(5);
    the5Record.flowHeader.count = htons(numFlows);

    /* rest of flowHeader will not be used */
    for(i=0; i<numFlows; i++) {
      if(flowVersion == 7) {
	the5Record.flowRecord[i].srcaddr   = the7Record.flowRecord[i].srcaddr;
	the5Record.flowRecord[i].dstaddr   = the7Record.flowRecord[i].dstaddr;
	the5Record.flowRecord[i].srcport   = the7Record.flowRecord[i].srcport;
	the5Record.flowRecord[i].dstport   = the7Record.flowRecord[i].dstport;
	the5Record.flowRecord[i].dPkts     = the7Record.flowRecord[i].dPkts;
	the5Record.flowRecord[i].dOctets   = the7Record.flowRecord[i].dOctets;
	the5Record.flowRecord[i].proto     = the7Record.flowRecord[i].proto;
	the5Record.flowRecord[i].tos       = the7Record.flowRecord[i].tos;
	the5Record.flowRecord[i].first     = the7Record.flowRecord[i].first;
	the5Record.flowRecord[i].last      = the7Record.flowRecord[i].last;
	the5Record.flowRecord[i].tcp_flags = the7Record.flowRecord[i].tcp_flags;
	/* rest of flowRecord will not be used */
      } else {
	/*
	  Some NetFlow v1 implementations (e.g. Extreme Networks) are
	  limited and most of the NetFlow fields are empty. In particular
	  the following fields are empty:
	  - input
	  - output
	  - dOctets
	  - first
	  - last
	  - tos
	  - tcp_flags

	  In this case we add a patch for filling some of the fields
	  in order to let ntop digest this flow.
	*/

	the5Record.flowRecord[i].srcaddr   = the1Record.flowRecord[i].srcaddr;
	the5Record.flowRecord[i].dstaddr   = the1Record.flowRecord[i].dstaddr;
	the5Record.flowRecord[i].srcport   = the1Record.flowRecord[i].srcport;
	the5Record.flowRecord[i].dstport   = the1Record.flowRecord[i].dstport;
	the5Record.flowRecord[i].dPkts     = the1Record.flowRecord[i].dPkts;

	if(ntohl(the1Record.flowRecord[i].dOctets) == 0) {
	  /* We assume that all packets are 512 bytes long */
	  u_int32_t tmp = ntohl(the1Record.flowRecord[i].dPkts);
	  the5Record.flowRecord[i].dOctets = htonl(tmp*512);
	} else
	  the5Record.flowRecord[i].dOctets = the1Record.flowRecord[i].dOctets;

	the5Record.flowRecord[i].proto     = the1Record.flowRecord[i].proto;
	the5Record.flowRecord[i].tos       = the1Record.flowRecord[i].tos;
	the5Record.flowRecord[i].first     = the1Record.flowRecord[i].first;
	the5Record.flowRecord[i].last      = the1Record.flowRecord[i].last;
	/* rest of flowRecord will not be used */
      }
    }
  }  /* DON'T ADD a else here ! */

  if((the5Record.flowHeader.version == htons(9))
     || (the5Record.flowHeader.version == htons(10))) {
    /* NetFlowV9/IPFIX Record */
    u_char foundRecord = 0, done = 0;
    u_short numEntries, displ;
    V9SimpleTemplate template;
    int i;
    u_char handle_ipfix;
    V9V10TemplateField *fields = NULL;

    memset(&template, 0, sizeof(template));
    if(the5Record.flowHeader.version == htons(9)) {
      V9FlowHeader *v9_hdr = (V9FlowHeader*)&the5Record.flowHeader;
      flowSequence = ntohl(v9_hdr->flow_sequence);
      handle_ipfix = 0;
    } else {
      IPFIXFlowHeader *v10_hdr = (IPFIXFlowHeader*)&the5Record.flowHeader;
      flowSequence = ntohl(v10_hdr->flow_sequence);
      /* traceEvent(CONST_TRACE_INFO, "IPFIX Flow sequence: %u", flowSequence); */
      handle_ipfix = 1;
    }

    numFlows = 1;

    if(handle_ipfix) {
      numEntries = ntohs(the5Record.flowHeader.count), displ = sizeof(V9FlowHeader)-4; // FIX
#ifdef DEBUG_FLOWS
      traceEvent(CONST_TRACE_INFO, "IPFIX Length: %d", numEntries);
#endif
    } else {
      numEntries = ntohs(the5Record.flowHeader.count), displ = sizeof(V9FlowHeader);
    }

    recordActTime = ntohl(the5Record.flowHeader.unix_secs);
    recordSysUpTime = ntohl(the5Record.flowHeader.sysUptime);
    /*     NTOHL(recordActTime); NTOHL(recordSysUpTime); */

    for(i=0; (!done) && (displ < bufferLen) && (i < numEntries); i++) {
      u_char isOptionTemplate;
      int16_t stillToProcess; /* Do not change to uint: this way I can catch template length issues */

      /* 1st byte */
      if(myGlobals.runningPref.debugMode) {
	traceEvent(CONST_TRACE_INFO, "[displ=%d][%02X %02X %02X]",
		   displ, buffer[displ] & 0xFF,
		   buffer[displ+1] & 0xFF,
		   buffer[displ+2] & 0xFF);
      }

      if(buffer[displ] == 0) {
	isOptionTemplate = (u_char)buffer[displ+1];

	/* Template */
	if(myGlobals.runningPref.debugMode) {
	  traceEvent(CONST_TRACE_INFO, "Found Template [displ=%d]", displ);
	  traceEvent(CONST_TRACE_INFO, "Found Template Type: %d", isOptionTemplate);
	}

	myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9TemplRcvd++;

	if(handle_ipfix && (isOptionTemplate == 2)) isOptionTemplate = 0;

	if(bufferLen > (displ+sizeof(V9TemplateHeader))) {
	  V9TemplateHeader header;
	  u_int8_t templateDone = 0;

	  memcpy(&header, &buffer[displ], sizeof(V9TemplateHeader));
	  header.templateFlowset = ntohs(header.templateFlowset);
	  header.flowsetLen = ntohs(header.flowsetLen);
	  stillToProcess = header.flowsetLen-sizeof(V9TemplateHeader);
	  displ += sizeof(V9TemplateHeader);

	  while((bufferLen >= (displ+stillToProcess)) && (!templateDone)) {
	    V9TemplateDef templateDef;
	    FlowSetV9 *cursor = myGlobals.device[deviceId].netflowGlobals->templates;
	    u_char found = 0;
	    u_short len = 0, accumulatedLen = 0;
	    int fieldId;

	    memcpy(&templateDef, &buffer[displ], sizeof(V9TemplateDef));
	    templateDef.templateId = htons(templateDef.templateId), templateDef.fieldCount = htons(templateDef.fieldCount);
	    displ += sizeof(V9TemplateDef);

	    if(!isOptionTemplate) {
	      u_char goodTemplate = 0;

	      template.templateId = templateDef.templateId, template.fieldCount = templateDef.fieldCount;

	      if(handle_ipfix) {
		fields = (V9V10TemplateField*)malloc(templateDef.fieldCount * (int)sizeof(V9V10TemplateField));
		if(fields == NULL) {
		  traceEvent(CONST_TRACE_WARNING, "Not enough memory");
		  break;
		}

		if(((templateDef.fieldCount * 4) + sizeof(FlowSet) + 4 /* templateFlowSet + FlowsetLen */) >  header.flowsetLen) {
		  traceEvent(CONST_TRACE_WARNING, "Bad length [expected=%d][real=%u]",
			     templateDef.fieldCount * 4,
			     (unsigned int)(numEntries + sizeof(FlowSet)));
		} else {
		  goodTemplate = 1;

		  /* Check the template before to handle it */
		  for(fieldId=0; fieldId < template.fieldCount; fieldId++) {
		    u_int8_t pen_len = 0, is_enterprise_specific = (buffer[displ+len] & 0x80) ? 1 : 0;
		    V9FlowSet *set = (V9FlowSet*)&buffer[displ+len];

		    len += 4; /* Field Type (2) + Field Length (2) */

		    if(is_enterprise_specific)
		      pen_len = 4, len += 4; /* PEN (Private Enterprise Number) */

		    fields[fieldId].fieldType = htons(set->templateId) & 0x7F;
		    fields[fieldId].fieldLen = htons(set->flowsetLen);
		    fields[fieldId].isPenField = is_enterprise_specific;
		    accumulatedLen += fields[fieldId].fieldLen;

		    if(myGlobals.runningPref.debugMode) {
		      traceEvent(CONST_TRACE_INFO, "[%d] fieldType=%d/PEN=%d/len=%d [tot=%d]",
				 1+fieldId, fields[fieldId].fieldType,
				 is_enterprise_specific, pen_len+fields[fieldId].fieldLen, len);
		    }
		  }

		  template.flowsetLen = len;
		}
	      } else {
		/* NetFlow */
		fields = (V9V10TemplateField*)malloc(template.fieldCount * (int)sizeof(V9V10TemplateField));
		if(fields == NULL) {
		  traceEvent(CONST_TRACE_WARNING, "Not enough memory");
		  break;
		}

		if(myGlobals.runningPref.debugMode) {
		  traceEvent(CONST_TRACE_INFO, "Template [id=%d] fields: %d [len=%d]",
			     template.templateId, template.fieldCount, template.flowsetLen);
		}

		goodTemplate = 1;

		/* Check the template before handling it */
		for(fieldId=0; fieldId < template.fieldCount; fieldId++) {
		  V9FlowSet *set = (V9FlowSet*)&buffer[displ+len];

		  fields[fieldId].fieldType = htons(set->templateId);
		  fields[fieldId].fieldLen  = htons(set->flowsetLen);
		  fields[fieldId].isPenField = (fields[fieldId].fieldType >= NTOP_BASE_ID) ? 1 : 0;
		  len += 4; /* Field Type (2) + Field Length (2) */
		  accumulatedLen +=  fields[fieldId].fieldLen;

		  if(myGlobals.runningPref.debugMode) {
		    traceEvent(CONST_TRACE_INFO, "[%d] fieldType=%d/fieldLen=%d/totLen=%d [stillToProcess=%u]",
			       1+fieldId, fields[fieldId].fieldType, fields[fieldId].fieldLen,
			       accumulatedLen, stillToProcess);
		  }
		}
	      }

	      if(goodTemplate) {
		while(cursor != NULL) {
		  if(cursor->templateInfo.templateId == template.templateId) {
		    found = 1;
		    break;
		  } else
		    cursor = cursor->next;
		}

		if(found) {
		  if(myGlobals.runningPref.debugMode)
		    traceEvent(CONST_TRACE_INFO, ">>>>> Redefined existing template [id=%d]",
			       template.templateId);

		  free(cursor->fields);
		} else {
		  if(myGlobals.runningPref.debugMode)
		    traceEvent(CONST_TRACE_INFO, ">>>>> Found new flow template definition [id=%d]",
			       template.templateId);

		  cursor = (FlowSetV9*)malloc(sizeof(FlowSetV9));
		  cursor->next = myGlobals.device[deviceId].netflowGlobals->templates;
		  myGlobals.device[deviceId].netflowGlobals->templates = cursor;
		}

		cursor->templateInfo.flowsetLen = len + sizeof(header);
		cursor->templateInfo.templateId = templateDef.templateId;
		cursor->templateInfo.fieldCount = templateDef.fieldCount;
		cursor->flowLen                 = accumulatedLen;
		cursor->fields                  = fields;

		if(myGlobals.runningPref.debugMode)
		  traceEvent(CONST_TRACE_INFO, ">>>>> Defined flow template [id=%d][flowLen=%d][fieldCount=%d]",
			     cursor->templateInfo.templateId,
			     cursor->flowLen, cursor->templateInfo.fieldCount);
	      } else {
		if(myGlobals.runningPref.debugMode)
		  traceEvent(CONST_TRACE_INFO, ">>>>> Skipping bad template [id=%d]", template.templateId);
	      }
	    } else {
	      len = header.flowsetLen;
	      displ -= sizeof(V9TemplateDef)+sizeof(V9TemplateHeader) /* Bytes have been accounted already */;
	      if(len == 0) {
		traceEvent(CONST_TRACE_WARNING, "Flowset %d bytes long: discarding it", len);
		return;
	      }
	    }

	    displ += len, stillToProcess -= (len+sizeof(templateDef));

	    if(myGlobals.runningPref.debugMode)
	      traceEvent(CONST_TRACE_INFO, "Moving ahead of %d bytes: new offset is %d", len, displ);

	    if(stillToProcess <= 0) templateDone = 1;
	  }
	}
      } else {
	if(myGlobals.runningPref.debugMode)
	  traceEvent(CONST_TRACE_INFO, "Found FlowSet [displ=%d]", displ);

	foundRecord = 1;
      }

      if(foundRecord) {
	V9FlowSet fs;

	if(bufferLen > (displ+sizeof(V9FlowSet))) {
	  FlowSetV9 *cursor = myGlobals.device[deviceId].netflowGlobals->templates;
	  u_short tot_len = 4;  /* 4 bytes header */

	  memcpy(&fs, &buffer[displ], sizeof(V9FlowSet));

	  fs.flowsetLen = ntohs(fs.flowsetLen);
	  fs.templateId = ntohs(fs.templateId);

	  while(cursor != NULL) {
	    if(cursor->templateInfo.templateId == fs.templateId) {
	      break;
	    } else
	      cursor = cursor->next;
	  }

	  if(cursor != NULL) {
	    /* Template found */
	    int fieldId, init_displ;

	    fields = cursor->fields;
	    init_displ = displ;
	    displ += sizeof(V9FlowSet);

	    if(myGlobals.runningPref.debugMode)
	      traceEvent(CONST_TRACE_INFO, ">>>>> Rcvd flow with known template %d [%d...%d]",
			 fs.templateId, displ, fs.flowsetLen);

	    while(displ < (init_displ + fs.flowsetLen)) {
	      u_short accum_len = 0;

	      if(((init_displ + fs.flowsetLen)-displ) <= 4) break;

	      /* Defaults */
	      memset(&record, 0, sizeof(record));
	      record.vlanId = NO_VLAN; /* No VLAN */
	      record.l7_proto = IPOQUE_PROTOCOL_UNKNOWN;
	      record.client_nw_latency_sec = record.client_nw_latency_usec = htonl(0);
	      record.server_nw_latency_sec = record.server_nw_latency_usec = htonl(0);
	      record.appl_latency_sec = record.appl_latency_usec = htonl(0);

	      if(myGlobals.runningPref.debugMode)
		traceEvent(CONST_TRACE_INFO, ">>>>> Stats [%d...%d]", displ, (init_displ + fs.flowsetLen));

	      for(fieldId=0; fieldId<cursor->templateInfo.fieldCount; fieldId++) {
		if(!(displ < (init_displ + fs.flowsetLen))) break; /* Flow too short */

		if(myGlobals.runningPref.debugMode)
		  traceEvent(CONST_TRACE_INFO, ">>>>> Dissecting flow field "
			     "[displ=%d/%d][template=%d][fieldType=%d][fieldLen=%d][isPenField=%d][field=%d/%d] [%d...%d] [tot len=%d]" /* "[%s]" */,
			     displ, fs.flowsetLen,
			     fs.templateId, fields[fieldId].fieldType,
			     fields[fieldId].fieldLen,
			     fields[fieldId].isPenField,
			     fieldId, cursor->templateInfo.fieldCount,
			     displ, (init_displ + fs.flowsetLen), accum_len+fields[fieldId].fieldLen
			     /* ,nf_hex_dump(&buffer[displ], ntohs(fields[fieldId].fieldLen)) */);

		if(fields[fieldId].isPenField == 0) {
		  switch(fields[fieldId].fieldType) {
		  case 1: /* IN_BYTES */
		    memcpy(&record.rcvdOctets, &buffer[displ], 4);
		    break;
		  case 2: /* IN_PKTS */
		    memcpy(&record.rcvdPkts, &buffer[displ], 4);
		    break;
		  case 4: /* PROT */
		    memcpy(&record.proto, &buffer[displ], 1);
		    break;
		  case 5: /* TOS */
		    memcpy(&record.tos, &buffer[displ], 1);
		    break;
		  case 6: /* TCP_FLAGS */
		    memcpy(&record.tcp_flags, &buffer[displ], 1);
		    break;
		  case 7: /* L4_SRC_PORT */
		    memcpy(&record.srcport, &buffer[displ], 2);
		    break;
		  case 8: /* IP_SRC_ADDR */
		    memcpy(&record.srcaddr, &buffer[displ], 4);
		    break;
		  case 9: /* SRC_MASK */
		    memcpy(&record.src_mask, &buffer[displ], 1);
		    break;
		  case 10: /* INPUT SNMP */
		    memcpy(&record.input, &buffer[displ], 2);
		    break;
		  case 11: /* L4_DST_PORT */
		    memcpy(&record.dstport, &buffer[displ], 2);
		    break;
		  case 12: /* IP_DST_ADDR */
		    memcpy(&record.dstaddr, &buffer[displ], 4);
		    break;
		  case 13: /* DST_MASK */
		    memcpy(&record.dst_mask, &buffer[displ], 1);
		    break;
		  case 14: /* OUTPUT SNMP */
		    memcpy(&record.output, &buffer[displ], 2);
		    break;
		  case 15: /* IP_NEXT_HOP */
		    memcpy(&record.nexthop, &buffer[displ], 4);
		    break;
		  case 16: /* SRC_AS */
		    /* Fix for handling 16+32 AS numbers */
		    if(fields[fieldId].fieldLen == 2) {
		      u_int16_t sixteen;
		      u_int32_t thirtytwo;

		      memcpy(&sixteen, &buffer[displ], 2);
		      thirtytwo = ntohs(sixteen);
		      record.src_as = htonl(thirtytwo);
		    } else
		      memcpy(&record.src_as, &buffer[displ], 4);
		    break;
		  case 17: /* DST_AS */
		    /* Fix for handling 16+32 AS numbers */
		    if(fields[fieldId].fieldLen == 2) {
		      u_int16_t sixteen;
		      u_int32_t thirtytwo;

		      memcpy(&sixteen, &buffer[displ], 2);
		      thirtytwo = ntohs(sixteen);
		      record.src_as = htonl(thirtytwo);
		    } else
		      memcpy(&record.dst_as, &buffer[displ], 4);
		    break;
		  case 21: /* LAST_SWITCHED */
		    memcpy(&record.last, &buffer[displ], 4);
		    break;
		  case 22: /* FIRST SWITCHED */
		    memcpy(&record.first, &buffer[displ], 4);
		    break;
		  case 23: /* OUT_BYTES */
		  case 85: /* NF_F_FLOW_BYTES */
		    {
		      u_int32_t value32;
		      
		      if(fields[fieldId].fieldLen == 8) {
			/* Barracuda Networks: we ignore the first 32 bits */
			memcpy(&value32, &buffer[displ+4], 4);
		      } else {
			/* Cisco (4 bytes) 
			   http://www.cisco.com/en/US/docs/security/asa/asa82/netflow/netflow.pdf
			*/
			memcpy(&value32, &buffer[displ], 4);
		      }

		      if(record.sentOctets != 0) {
			/* In case the same field is sent twice it means that
			   it is the reverse direction
			*/

			record.rcvdOctets = value32;
			if(fields[fieldId].fieldType == 85) {
			  /* In ASA We don't have the number of packets so in order
			     to let ntop not discard this flow we need to put a reasonable
			     value there (avg 512 bytes packet)
			  */
			  record.rcvdPkts = htonl(1 + (ntohl(record.rcvdOctets)/512));
			}
		      } else {
			record.sentOctets = value32;
			if(fields[fieldId].fieldType == 85) {
			  /* In ASA We don't have the number of packets so in order
			     to let ntop not discard this flow we need to put a reasonable
			     value there (avg 512 bytes packet)
			  */
			  record.sentPkts = htonl(1 + (ntohl(record.sentOctets)/512));
			}
		      }
		    }
		    break;
		  case 24: /* OUT_PKTS */
		    memcpy(&record.sentPkts, &buffer[displ], 4);
		    break;
                  case 27: /* IPV6_SRC_ADDR */
                     memcpy(&record.srcaddr6, &buffer[displ], 16);
                     break;
                  case 28: /* IPV6_DST_ADDR */
                     memcpy(&record.dstaddr6, &buffer[displ], 16);
                     break;
		  case 56: /* IN_SRC_MAC */
		    memcpy(&record.src_mac, &buffer[displ], LEN_ETHERNET_ADDRESS), record.src_mac_set = 1;
		    break;

		  case 58: /* SRC_VLAN */
		  case 59: /* DST_VLAN */
		    memcpy(&record.vlanId, &buffer[displ], 2);
		    record.vlanId = ntohs(record.vlanId);
		    break;

		  case 80: /* OUT_DST_MAC */
		    memcpy(&record.dst_mac, &buffer[displ], LEN_ETHERNET_ADDRESS), record.dst_mac_set = 1;
		    break;
		  }
		} else {
		  /* PEN fields */
		  switch(fields[fieldId].fieldType) {
		    /* Barracuda Networks (PEN 12326)

		       -------------------------------------------------------------------------------
		       Enterprise ID Barracuda Networks: 12326
		       -------------------------------------------------------------------------------
		       Field ID  Length (octets)  Type     Name                Description
		       -------------------------------------------------------------------------------
		       1         4                Int      Timestamp           Seconds since epoch
		       13        variable         String   ServerAddress
		       14        4                Int      ResponseTime
		       15        variable         String   RequestedURL
		    */

		  case 13: 
		    {
		      char *dstAddress = &buffer[displ+1];
		      in_addr_t addr = inet_addr(dstAddress);

		      record.dstaddr = addr, record.dstport = htons(80), record.proto = IPPROTO_TCP;
		    }
		    break;
		    /* ntop */
		  case NTOP_BASE_ID+82: /* CLIENT_NW_LATENCY_SEC */
		    memcpy(&record.client_nw_latency_sec, &buffer[displ], 4);
		    break;
		  case NTOP_BASE_ID+83: /* CLIENT_NW_LATENCY_USEC */
		    memcpy(&record.client_nw_latency_usec, &buffer[displ], 4);
		    break;
		  case NTOP_BASE_ID+84: /* SERVER_NW_LATENCY_SEC */
		    memcpy(&record.server_nw_latency_sec, &buffer[displ], 4);
		    break;
		  case NTOP_BASE_ID+85: /* SERVER_NW_LATENCY_USEC */
		    memcpy(&record.server_nw_latency_usec, &buffer[displ], 4);
		    break;
		  case NTOP_BASE_ID+86: /* APPL_LATENCY_SEC */
		    memcpy(&record.appl_latency_sec, &buffer[displ], 4);
		    break;
		  case NTOP_BASE_ID+87: /* APPL_LATENCY_USEC */
		    memcpy(&record.appl_latency_usec, &buffer[displ], 4);
		    break;
		  case NTOP_BASE_ID+118: /* L7_PROTO */
		    memcpy(&record.l7_proto, &buffer[displ], 2);
		    break;

		    /* VoIP Extensions */
		  case NTOP_BASE_ID+130: /* SIP_CALL_ID */
		    memcpy(&record.sip_call_id, &buffer[displ], 50);
		    if(myGlobals.runningPref.debugMode)
		      traceEvent(CONST_TRACE_INFO, "SIP: sip_call_id=%s", record.sip_call_id);
		    break;
		  case NTOP_BASE_ID+131: /* SIP_CALLING_PARTY */
		    memcpy(&record.sip_calling_party, &buffer[displ], 50);
		    if(myGlobals.runningPref.debugMode)
		      traceEvent(CONST_TRACE_INFO, "SIP: sip_calling_party=%s", record.sip_calling_party);
		    break;
		  case NTOP_BASE_ID+132: /* SIP_CALLED_PARTY */
		    memcpy(&record.sip_called_party, &buffer[displ], 50);
		    if(myGlobals.runningPref.debugMode)
		      traceEvent(CONST_TRACE_INFO, "SIP: sip_called_party=%s", record.sip_called_party);
		    break;
		  }
		}

		if((handle_ipfix) && (fields[fieldId].fieldLen == 65535)) {
		  /* IPFIX Variable lenght field */
		  u_int8_t len8 = buffer[displ];

		  if(len8 < 255)
		    accum_len += len8+1, displ += len8+1;
		  else {
		    u_int16_t len16;

		    memcpy(&len16, &buffer[displ+1], 2);
		    len16 = ntohs(len16);
		    len16 += 1 /* 255 */ + 2 /* len */;
		    accum_len += len16, displ += len16;
		  }
		} else
		  accum_len += fields[fieldId].fieldLen, displ += fields[fieldId].fieldLen;
	      }

	      /*
		IMPORTANT NOTE

		handleGenericFlow handles monodirectional flows, whereas
		v9 flows and bidirectional. This means that if there's some
		bidirectional traffic, handleGenericFlow is called twice.
	      */
	      handleGenericFlow(netflow_device_ip, netflow_device_port, recordActTime,
				recordSysUpTime, &record, deviceId, &firstSeen, &lastSeen, 1);
	      myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9Rcvd++;

	      if(myGlobals.runningPref.debugMode)
		traceEvent(CONST_TRACE_INFO,
			   ">>>> NETFLOW: Calling insert_flow_record() [accum_len=%d][sent pkts=%d/bytes=%d][rcvd pkts=%d/bytes=%d]",
			   accum_len, record.sentPkts, record.sentOctets,record.rcvdPkts,record.rcvdOctets);

	      tot_len += accum_len;

	      if(record.rcvdPkts > 0) {
                u_int16_t tmpPort;
                u_int32_t tmpAS;
                u_int32_t tmpAddr;
                u_int8_t  tmp6[16];   

		record.sentPkts   = record.rcvdPkts;
		record.sentOctets = record.rcvdOctets;

                if ((record.srcaddr==0) && (record.dstaddr==0)) {
                      memcpy(tmp6,record.srcaddr6,sizeof(tmp6));
                      memcpy(record.srcaddr6,record.dstaddr6,sizeof(record.srcaddr6));
                      memcpy(record.dstaddr6,tmp6,sizeof(record.dstaddr6));
                }
                else {
                     tmpAddr = record.srcaddr;
                     record.srcaddr = record.dstaddr;
                     record.dstaddr = tmpAddr;
                }
                tmpPort = record.srcport;
                record.srcport = record.dstport;
                record.dstport = tmpPort;

                tmpAS = record.src_as;
                record.src_as = record.dst_as;
                record.dst_as = tmpAS;


		handleGenericFlow(netflow_device_ip, netflow_device_port, recordActTime, recordSysUpTime,
				  &record, deviceId, &firstSeen, &lastSeen, 0);
	      }
	    }

	    if(tot_len < fs.flowsetLen) {
	      u_short padding = fs.flowsetLen - tot_len;

	      if(padding > 4) {
		traceEvent(CONST_TRACE_WARNING, "Template len mismatch [tot_len=%d][flow_len=%d][padding=%d]",
			   tot_len, fs.flowsetLen, padding);
	      } else {
		if(myGlobals.runningPref.debugMode)
		  traceEvent(CONST_TRACE_INFO, ">>>>> %d bytes padding [tot_len=%d][flow_len=%d]",
			     padding, tot_len, fs.flowsetLen);

		displ += padding;
	      }
	    }
	  } else {
	    if(myGlobals.runningPref.debugMode)
	      traceEvent(CONST_TRACE_INFO, ">>>>> Rcvd flow with UNKNOWN template %d [displ=%d][len=%d]",
			 fs.templateId, displ, fs.flowsetLen);

	    displ += fs.flowsetLen;
	  }
	}
      }
    } /* for */
  } else if(the5Record.flowHeader.version == htons(5)) {
    int i;

    flowSequence = ntohl(the5Record.flowHeader.flow_sequence);
    numFlows = ntohs(the5Record.flowHeader.count);
    recordActTime   = ntohl(the5Record.flowHeader.unix_secs);
    recordSysUpTime = ntohl(the5Record.flowHeader.sysUptime);

    if(numFlows > CONST_V5FLOWS_PER_PAK) numFlows = CONST_V5FLOWS_PER_PAK;

    if(myGlobals.runningPref.debugMode)
      traceEvent(CONST_TRACE_INFO, "dissectNetFlow(%d flows)", numFlows);

    /* Lock white/black lists for duration of this flow packet */
    accessMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex, "flowPacket");

    /*
      Reset the record so that fields that are not contained
      into v5 records are set to zero
    */
    memset(&record, 0, sizeof(record));
    record.vlanId = NO_VLAN; /* No VLAN */
    record.client_nw_latency_sec = record.client_nw_latency_usec = htonl(0);
    record.server_nw_latency_sec = record.server_nw_latency_usec = htonl(0);
    record.appl_latency_sec = record.appl_latency_usec = htonl(0);

    for(i=0; i<numFlows; i++) {
      record.srcaddr    = the5Record.flowRecord[i].srcaddr;
      record.dstaddr    = the5Record.flowRecord[i].dstaddr;
      record.nexthop    = the5Record.flowRecord[i].nexthop;
      record.input      = the5Record.flowRecord[i].input;
      record.output     = the5Record.flowRecord[i].output;
      record.sentPkts   = the5Record.flowRecord[i].dPkts;
      record.sentOctets = the5Record.flowRecord[i].dOctets;
      record.first      = the5Record.flowRecord[i].first;
      record.last       = the5Record.flowRecord[i].last;
      record.srcport    = the5Record.flowRecord[i].srcport;
      record.dstport    = the5Record.flowRecord[i].dstport;
      record.tcp_flags  = the5Record.flowRecord[i].tcp_flags;
      record.proto      = the5Record.flowRecord[i].proto;
      record.dst_as     = htonl(ntohs(the5Record.flowRecord[i].dst_as));
      record.src_as     = htonl(ntohs(the5Record.flowRecord[i].src_as));
      record.dst_mask   = the5Record.flowRecord[i].dst_mask;
      record.src_mask   = the5Record.flowRecord[i].src_mask;

      handleGenericFlow(netflow_device_ip, netflow_device_port,
			recordActTime, recordSysUpTime, &record, deviceId, &firstSeen, &lastSeen, 1);
    }

    if(flowVersion == 5) /* Skip converted V1/V7 flows */
      myGlobals.device[deviceId].netflowGlobals->numNetFlowsV5Rcvd += numFlows;

    releaseMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
  } else
    myGlobals.device[deviceId].netflowGlobals->numBadNetFlowsVersionsRcvd++; /* CHANGE */

  if((flowVersion != 1) && (probeId != -1)) {
    /* NetFlow v1 does not have the flow sequence */
    updateSenderFlowSequence(deviceId, probeId, numFlows, flowSequence, flowVersion);
  }
}

/* ********************************************************* */

#ifdef MAKE_WITH_NETFLOWSIGTRAP
RETSIGTYPE netflowcleanup(int signo) {
  static int msgSent = 0;
  int i;
  void *array[20];
  size_t size;
  char **strings;

  if(msgSent<10) {
    traceEvent(CONST_TRACE_FATALERROR, "NETFLOW: caught signal %d %s", signo,
               signo == SIGHUP ? "SIGHUP" :
               signo == SIGINT ? "SIGINT" :
               signo == SIGQUIT ? "SIGQUIT" :
               signo == SIGILL ? "SIGILL" :
               signo == SIGABRT ? "SIGABRT" :
               signo == SIGFPE ? "SIGFPE" :
               signo == SIGKILL ? "SIGKILL" :
               signo == SIGSEGV ? "SIGSEGV" :
               signo == SIGPIPE ? "SIGPIPE" :
               signo == SIGALRM ? "SIGALRM" :
               signo == SIGTERM ? "SIGTERM" :
               signo == SIGUSR1 ? "SIGUSR1" :
               signo == SIGUSR2 ? "SIGUSR2" :
               signo == SIGCHLD ? "SIGCHLD" :
#ifdef SIGCONT
               signo == SIGCONT ? "SIGCONT" :
#endif
#ifdef SIGSTOP
               signo == SIGSTOP ? "SIGSTOP" :
#endif
#ifdef SIGBUS
               signo == SIGBUS ? "SIGBUS" :
#endif
#ifdef SIGSYS
               signo == SIGSYS ? "SIGSYS"
#endif
               : "other");
    msgSent++;
  }

  traceEvent(CONST_TRACE_FATALERROR, "NETFLOW: ntop shutting down...");
  exit(100);
}
#endif /* MAKE_WITH_NETFLOWSIGTRAP */

/* ****************************** */

#ifdef HAVE_SNMP
static void* netflowUtilsLoop(void* _deviceId) {
  int deviceId = (int)_deviceId;

  while(1) {
    if(myGlobals.device[deviceId].netflowGlobals->ifStatsQueue_len > 0) {
      InterfaceStats *iface;

      accessMutex(&myGlobals.device[deviceId].netflowGlobals->ifStatsQueueMutex, "netflowUtilsLoop");
      iface = myGlobals.device[deviceId].netflowGlobals->ifStatsQueue[--myGlobals.device[deviceId].netflowGlobals->ifStatsQueue_len];
      releaseMutex(&myGlobals.device[deviceId].netflowGlobals->ifStatsQueueMutex);
      updateInterfaceName(iface);
    } else {
      waitCondvar(&myGlobals.device[deviceId].netflowGlobals->ifStatsQueueCondvar);
    }
  }
}
#endif

/* ****************************** */

static void* netflowMainLoop(void* _deviceId) {
  fd_set netflowMask;
  int rc, len, deviceId, probeId = -1;
  u_char buffer[2048];
  struct sockaddr_in fromHost;

#ifdef MAX_NETFLOW_PACKET_BUFFER
  struct timeval netflowStartOfRecordProcessing,
    netflowEndOfRecordProcessing;
  float elapsed;
#endif

  deviceId = (int)((long)_deviceId);

  if(!(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket > 0)) return(NULL);

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: NETFLOW: thread starting [p%d]",
             (long unsigned int)pthread_self(), getpid());

#ifdef MAKE_WITH_NETFLOWSIGTRAP
  signal(SIGSEGV, netflowcleanup);
  signal(SIGHUP,  netflowcleanup);
  signal(SIGINT,  netflowcleanup);
  signal(SIGQUIT, netflowcleanup);
  signal(SIGILL,  netflowcleanup);
  signal(SIGABRT, netflowcleanup);
  signal(SIGFPE,  netflowcleanup);
  signal(SIGKILL, netflowcleanup);
  signal(SIGPIPE, netflowcleanup);
  signal(SIGALRM, netflowcleanup);
  signal(SIGTERM, netflowcleanup);
  signal(SIGUSR1, netflowcleanup);
  signal(SIGUSR2, netflowcleanup);
  /* signal(SIGCHLD, netflowcleanup); */
#ifdef SIGCONT
  signal(SIGCONT, netflowcleanup);
#endif
#ifdef SIGSTOP
  signal(SIGSTOP, netflowcleanup);
#endif
#ifdef SIGBUS
  signal(SIGBUS,  netflowcleanup);
#endif
#ifdef SIGSYS
  signal(SIGSYS,  netflowcleanup);
#endif
#endif /* MAKE_WITH_NETFLOWSIGTRAP */

  myGlobals.device[deviceId].activeDevice = 1;
  myGlobals.device[deviceId].netflowGlobals->threadActive = 1;

  ntopSleepUntilStateRUN();
  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: NETFLOW: (port %d) thread running [p%d]",
             (long unsigned int)pthread_self(), myGlobals.device[deviceId].netflowGlobals->netFlowInPort, getpid());

  for(;myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN;) {
    int maxSock = myGlobals.device[deviceId].netflowGlobals->netFlowInSocket;
    struct timeval wait_time;

    FD_ZERO(&netflowMask);
    FD_SET(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket, &netflowMask);

#ifdef HAVE_SCTP
    if(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket > 0) {
      FD_SET(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket, &netflowMask);
      if(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket > maxSock)
	maxSock = myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket;
    }
#endif

    if(!myGlobals.device[deviceId].activeDevice) break;
    wait_time.tv_sec = 3, wait_time.tv_usec = 0;
    rc = select(maxSock+1, &netflowMask, NULL, NULL, &wait_time);
    if(!myGlobals.device[deviceId].activeDevice) break;

    if(rc > 0) {
      if(FD_ISSET(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket, &netflowMask)){
	len = sizeof(fromHost);
	rc = (int)recvfrom(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket,
			   (char*)&buffer,
			   (size_t)sizeof(buffer),
			   (int)0,
			   (struct sockaddr*)&fromHost,
			   (socklen_t*)&len);
      }
#ifdef HAVE_SCTP
      else {
	struct msghdr msg;
	struct iovec iov[2];
	char controlVector[256];

	memset(controlVector, 0, sizeof(controlVector));
	iov[0].iov_base = buffer;
	iov[0].iov_len  = sizeof(buffer);
	iov[1].iov_base = NULL;
	iov[1].iov_len  = 0;
	msg.msg_name = (caddr_t)&fromHost;
	msg.msg_namelen = sizeof(fromHost);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (caddr_t)controlVector;
	msg.msg_controllen = sizeof(controlVector);

	rc = recvmsg(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket, &msg, 0);
      }
#endif


      if(myGlobals.runningPref.debugMode)
	traceEvent(CONST_TRACE_INFO, "NETFLOW_DEBUG: Received NetFlow packet(len=%d)(deviceId=%d)",
		   rc,  deviceId);

      if(rc > 0) {
	int i;

#ifdef MAX_NETFLOW_PACKET_BUFFER
        gettimeofday(&netflowStartOfRecordProcessing, NULL);
#endif

	myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd++;
	NTOHL(fromHost.sin_addr.s_addr);
	NTOHS(fromHost.sin_port);

	for(i=0; i<MAX_NUM_PROBES; i++) {
	  if(myGlobals.device[deviceId].netflowGlobals->probeList[i].probeAddr.s_addr == 0) {
	    myGlobals.device[deviceId].netflowGlobals->probeList[i].probeAddr.s_addr = fromHost.sin_addr.s_addr;
	    myGlobals.device[deviceId].netflowGlobals->probeList[i].probePort = fromHost.sin_port;
	    myGlobals.device[deviceId].netflowGlobals->probeList[i].pkts = 1;
	    myGlobals.device[deviceId].netflowGlobals->probeList[i].lastSequenceNumber = 0;
	    myGlobals.device[deviceId].netflowGlobals->probeList[i].lowestSequenceNumber = (u_int32_t)ULONG_MAX;
	    myGlobals.device[deviceId].netflowGlobals->probeList[i].highestSequenceNumber = 0;
	    myGlobals.device[deviceId].netflowGlobals->probeList[i].totNumFlows = 0;
	    probeId = i;
	    break;
	  } else if((myGlobals.device[deviceId].netflowGlobals->probeList[i].probeAddr.s_addr == fromHost.sin_addr.s_addr)
		    && (myGlobals.device[deviceId].netflowGlobals->probeList[i].probePort == fromHost.sin_port)) {
	    myGlobals.device[deviceId].netflowGlobals->probeList[i].pkts++;
	    probeId = i;
	    break;
	  }
	}

	dissectFlow(fromHost.sin_addr.s_addr,
		    fromHost.sin_port, probeId,
		    (char*)buffer, rc, deviceId);

#ifdef MAX_NETFLOW_PACKET_BUFFER
        gettimeofday(&netflowEndOfRecordProcessing, NULL);
        elapsed = timeval_subtract(netflowEndOfRecordProcessing, netflowStartOfRecordProcessing);
        netflowpacketBuffer[++netflowpacketBufferCount & (MAX_NETFLOW_PACKET_BUFFER - 1)] = elapsed;
        if(elapsed > netflowpmaxTime)
          netflowpmaxTime = elapsed;
#endif
      }
    } else {
      if((rc < 0) && (myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN) && (errno != EINTR /* Interrupted system call */)) {
	traceEvent(CONST_TRACE_ERROR, "NETFLOW: select() failed(%d, %s), terminating netFlow",
		   errno, strerror(errno));
	break;
      }
    }
  }

  if(myGlobals.device[deviceId].netflowGlobals != NULL) {
    myGlobals.device[deviceId].netflowGlobals->threadActive = 0;
    myGlobals.device[deviceId].netflowGlobals->netFlowThread = 0;
#ifdef HAVE_SNMP
    myGlobals.device[deviceId].netflowGlobals->netFlowUtilsThread = 0;
#endif
  }
  myGlobals.device[deviceId].activeDevice = 0;

  if(myGlobals.device[deviceId].netflowGlobals)
    traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: NETFLOW: thread terminated [p%d][netFlowDeviceId=%d]",
	       (long unsigned int)pthread_self(), getpid(),
	       myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId);

  return(NULL);
}

/* ****************************** */

static void initNetFlowDevice(int deviceId) {
  int a, b, c, d, a1, b1, c1, d1, rc;
  char value[1024], workList[1024];

  if(!pluginActive) return;

  traceEvent(CONST_TRACE_INFO, "NETFLOW: initializing deviceId=%d", deviceId);

  if(myGlobals.device[deviceId].netflowGlobals == NULL) {
    traceEvent(CONST_TRACE_ERROR, "NETFLOW: initNetFlowDevice internal error");
    return;
  }

  allocDeviceMemory(deviceId);

  setPluginStatus(NULL);

  myGlobals.device[deviceId].netflowGlobals->threadActive = 0;
  createMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
  createMutex(&myGlobals.device[deviceId].netflowGlobals->ifStatsMutex);

#ifdef HAVE_SNMP
  createMutex(&myGlobals.device[deviceId].netflowGlobals->ifStatsQueueMutex);
  createCondvar(&myGlobals.device[deviceId].netflowGlobals->ifStatsQueueCondvar);
#endif

  if(fetchPrefsValue(nfValue(deviceId, "netFlowInPort", 1), value, sizeof(value)) == -1)
    storePrefsValue(nfValue(deviceId, "netFlowInPort", 1), "0");
  else
    myGlobals.device[deviceId].netflowGlobals->netFlowInPort = atoi(value);

  if((fetchPrefsValue(nfValue(deviceId, "ifNetMask", 1), value, sizeof(value)) == -1)
     || (((rc = sscanf(value, "%d.%d.%d.%d/%d.%d.%d.%d", &a, &b, &c, &d, &a1, &b1, &c1, &d1)) != 8)
	 && ((rc = sscanf(value, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &a1)) != 5))) {
    storePrefsValue(nfValue(deviceId, "ifNetMask", 1), "192.168.0.0/255.255.255.0");
    myGlobals.device[deviceId].netflowGlobals->netFlowIfAddress.s_addr = 0xC0A80000;
    myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr    = 0xFFFFFF00;
  } else {
    myGlobals.device[deviceId].netflowGlobals->netFlowIfAddress.s_addr = (a << 24) +(b << 16) +(c << 8) + d;
    if(rc == 8)
      myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr = (a1 << 24) +(b1 << 16) +(c1 << 8) + d1;
    else {
      myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr = 0xffffffff >> a1;
      myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr =~
	myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr;
    }
  }

  if(fetchPrefsValue(nfValue(deviceId, "whiteList", 1), value, sizeof(value)) == -1) {
    storePrefsValue(nfValue(deviceId, "whiteList", 1), "");
    myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList = strdup("");
  } else
    myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList = strdup(value);

  accessMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex, "initNetFlowDevice");
  handleWhiteBlackListAddresses((char*)&value,
                                myGlobals.device[deviceId].netflowGlobals->whiteNetworks,
                                &myGlobals.device[deviceId].netflowGlobals->numWhiteNets,
				(char*)&workList,
                                sizeof(workList));
  if(myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList != NULL)
    free(myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList);
  myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList = strdup(workList);
  releaseMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
  traceEvent(CONST_TRACE_INFO, "NETFLOW: White list initialized to '%s'",
	     myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList);

  if(fetchPrefsValue(nfValue(deviceId, "blackList", 1), value, sizeof(value)) == -1) {
    storePrefsValue(nfValue(deviceId, "blackList", 1), "");
    myGlobals.device[deviceId].netflowGlobals->netFlowBlackList=strdup("");
  } else
    myGlobals.device[deviceId].netflowGlobals->netFlowBlackList=strdup(value);

  accessMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex, "initNetFlowDevice()");
  handleWhiteBlackListAddresses((char*)&value, myGlobals.device[deviceId].netflowGlobals->blackNetworks,
                                &myGlobals.device[deviceId].netflowGlobals->numBlackNets, (char*)&workList,
                                sizeof(workList));
  if(myGlobals.device[deviceId].netflowGlobals->netFlowBlackList != NULL)
    free(myGlobals.device[deviceId].netflowGlobals->netFlowBlackList);

  myGlobals.device[deviceId].netflowGlobals->netFlowBlackList = strdup(workList);
  releaseMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
  traceEvent(CONST_TRACE_INFO, "NETFLOW: Black list initialized to '%s'",
	     myGlobals.device[deviceId].netflowGlobals->netFlowBlackList);

  if(fetchPrefsValue(nfValue(deviceId, "netFlowAggregation", 1), value, sizeof(value)) == -1)
    storePrefsValue(nfValue(deviceId, "netFlowAggregation", 1), "0" /* noAggregation */);
  else
    myGlobals.device[deviceId].netflowGlobals->netFlowAggregation = atoi(value);

  if(fetchPrefsValue(nfValue(deviceId, "netFlowDumpInterval", 1), value, sizeof(value)) == -1) {
    storePrefsValue(nfValue(deviceId, "netFlowDumpInterval", 1), "0" /* no */);
    myGlobals.device[deviceId].netflowGlobals->dumpInterval = 0;
  } else
    myGlobals.device[deviceId].netflowGlobals->dumpInterval = atoi(value);

  if(fetchPrefsValue(nfValue(deviceId, "netFlowDumpPath", 1), value, sizeof(value)) == -1) {
    myGlobals.device[deviceId].netflowGlobals->dumpPath = strdup("./netflow-dump");
    storePrefsValue(nfValue(deviceId, "netFlowDumpPath", 1),
		    myGlobals.device[deviceId].netflowGlobals->dumpPath);
  } else
    myGlobals.device[deviceId].netflowGlobals->dumpPath = strdup(value);

  if(setNetFlowInSocket(deviceId) != 0)  return;

  if(fetchPrefsValue(nfValue(deviceId, "debug", 1), value, sizeof(value)) == -1) {
    storePrefsValue(nfValue(deviceId, "debug", 1), "0");
    myGlobals.device[deviceId].netflowGlobals->netFlowDebug = 1;
  } else {
    myGlobals.device[deviceId].netflowGlobals->netFlowDebug = atoi(value);
  }

  /* Allocate a pure dummy for white/black list use */
  myGlobals.device[deviceId].netflowGlobals->dummyHost = (HostTraffic*)malloc(sizeof(HostTraffic));
  memset(myGlobals.device[deviceId].netflowGlobals->dummyHost, 0, sizeof(HostTraffic));

  myGlobals.device[deviceId].netflowGlobals->dummyHost->hostIp4Address.s_addr = 0x00112233;
  strncpy(myGlobals.device[deviceId].netflowGlobals->dummyHost->hostNumIpAddress, "&nbsp;",
	  sizeof(myGlobals.device[deviceId].netflowGlobals->dummyHost->hostNumIpAddress));
  strncpy(myGlobals.device[deviceId].netflowGlobals->dummyHost->hostResolvedName, "white/black list dummy",
	  sizeof(myGlobals.device[deviceId].netflowGlobals->dummyHost->hostResolvedName));
  myGlobals.device[deviceId].netflowGlobals->dummyHost->hostResolvedNameType = FLAG_HOST_SYM_ADDR_TYPE_FAKE;
  strcpy(myGlobals.device[deviceId].netflowGlobals->dummyHost->ethAddressString, "00:00:00:00:00:00");
  setEmptySerial(&myGlobals.device[deviceId].netflowGlobals->dummyHost->serialHostIndex);
  myGlobals.device[deviceId].netflowGlobals->dummyHost->portsUsage = NULL;
  myGlobals.device[deviceId].activeDevice = 1;
  myGlobals.device[deviceId].samplingRate = 1;
  myGlobals.device[deviceId].mtuSize    = myGlobals.mtuSize[myGlobals.device[deviceId].datalink];
  myGlobals.device[deviceId].headerSize = myGlobals.headerSize[myGlobals.device[deviceId].datalink];
  initDeviceSemaphores(deviceId);
}

/* ****************************** */

static int initNetFlowFunct(void) {
  char value[128];

  traceEvent(CONST_TRACE_INFO, "NETFLOW: Welcome to the netFlow plugin");

  pluginActive = 1;
  myGlobals.runningPref.mergeInterfaces = 0; /* Use different devices */

#ifdef MAX_NETFLOW_FLOW_BUFFER
  memset(&netflowflowBuffer, 0, sizeof(netflowflowBuffer));
  netflowflowBufferCount = 0;
  netflowfmaxTime = 0.0;
#endif

#ifdef MAX_NETFLOW_PACKET_BUFFER
  memset(&netflowpacketBuffer, 0, sizeof(netflowpacketBuffer));
  netflowpacketBufferCount = 0;
  netflowpmaxTime = 0.0;
#endif

  if((fetchPrefsValue(nfValue(0, "knownDevices", 0), value, sizeof(value)) != -1)
     && (strlen(value) > 0)) {
    char *strtokState, *dev;

    traceEvent(CONST_TRACE_INFO, "NETFLOW: initializing '%s' devices", value);

    dev = strtok_r(value, ",", &strtokState);
    while(dev != NULL) {
      int deviceId = atoi(dev);

      if(deviceId > 0) {
	int initializedDeviceId;

	if((initializedDeviceId = createNetFlowDevice(deviceId)) == -1) {
	  pluginActive = 0;
	  return(-1);
	}
      }

      dev = strtok_r(NULL, ",", &strtokState);
    }
  } else
    traceEvent(CONST_TRACE_INFO, "NETFLOW: no devices to initialize");

  return(0);
}

/* ****************************** */

static void printNetFlowDeviceConfiguration(void) {
  char buf[512], value[128];
  int i = 0;

  sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");
  sendString("<tr><th "DARK_BG">Available NetFlow Devices</th></tr>\n");
  sendString("<tr><td align=left>\n");

  if((fetchPrefsValue(nfValue(0, "knownDevices", 0), value, sizeof(value)) != -1)
     && (strlen(value) > 0)) {
    char *strtokState, *dev;

    sendString("<FORM ACTION=\"/plugins/");
    sendString(netflowPluginInfo->pluginURLname);
    sendString("\" METHOD=GET>\n");

    dev = strtok_r(value, ",", &strtokState);
    while(dev != NULL) {
      int id = mapNetFlowDeviceToNtopDevice(atoi(dev));

      if(id == -1)
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=device VALUE=%s %s>%s.%s\n",
		      dev, i == 0 ? "CHECKED" : "", NETFLOW_DEVICE_NAME, dev);
      else
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=device VALUE=%s %s>%s\n",
		      dev, i == 0 ? "CHECKED" : "", myGlobals.device[id].humanFriendlyName);

      sendString(buf);

      if(pluginActive) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[ <A HREF=\"/plugins/%s?device=-%s\" "
		      "onClick=\"return confirmDelete()\">Delete</A> ]",
		      netflowPluginInfo->pluginURLname, dev);
	sendString(buf);
      }

      sendString("<br>\n");
      i++; dev = strtok_r(NULL, ",", &strtokState);
    }

    if(pluginActive)
      sendString("<p><INPUT TYPE=submit VALUE=\"Edit NetFlow Device\">&nbsp;"
		 "<INPUT TYPE=reset VALUE=Reset>\n</FORM><p>\n");
  }

  /* *********************** */

  if(pluginActive) {
    sendString("<FORM ACTION=\"/plugins/");
    sendString(netflowPluginInfo->pluginURLname);
    sendString("\" METHOD=GET>\n<input type=hidden name=device size=5 value=0>");
    sendString("<p align=center><INPUT TYPE=submit VALUE=\"Add NetFlow Device\">&nbsp;\n</FORM><p>\n");
  } else {
    sendString("<p>Please <A HREF=\"/"CONST_SHOW_PLUGINS_HTML"?");
    sendString(netflowPluginInfo->pluginURLname);
    sendString("=1\">enable</A> the NetFlow plugin first<br>\n");
  }

  sendString("</td></TR></TABLE></center>");

  printHTMLtrailer();
}


/* ****************************** */

static void printNetFlowStatistics(void) {
  char buf[1024];
  int i, printedStatistics=0;

#ifdef MAX_NETFLOW_PACKET_BUFFER
  float rminTime=99999.0, rmaxTime=0.0,
    /*stddev:*/ rM, rT, rQ, rR, rSD, rXBAR;
#endif
#ifdef MAX_NETFLOW_FLOW_BUFFER
  float fminTime=99999.0, fmaxTime=0.0,
    /*stddev:*/ fM, fT, fQ, fR, fSD, fXBAR;
#endif

  memset(&buf, 0, sizeof(buf));

  printHTMLheader("NetFlow Statistics", NULL, 0);

  for(i = 0; i<myGlobals.numDevices; i++) {
    if((myGlobals.device[i].netflowGlobals != NULL) &&
       (myGlobals.device[i].netflowGlobals->numNetFlowsPktsRcvd > 0)) {
      if(printedStatistics == 0) {
        sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");
        printedStatistics = 1;
      }
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "<tr><th colspan=\"5\">Device %d - %s</th></tr>\n",
                    i, myGlobals.device[i].humanFriendlyName);
      sendString(buf);
      printNetFlowStatisticsRcvd(i);
    }
  }
  if(printedStatistics == 1) {
    sendString("</table>\n</center>\n");
  } else {
    printNoDataYet();
  }

#if defined(MAX_NETFLOW_FLOW_BUFFER) || defined(MAX_NETFLOW_PACKET_BUFFER)
  printSectionTitle("netFlow Processing times");
  sendString("<center><table border=\"0\""TABLE_DEFAULTS">\n<tr><td width=\"500\">"
             "<p>These numbers are the elapsed time (in seconds) to process each netFlow "
             "packet and each individual flow.  The computations are based only on the most "
             "recent");

#ifdef MAX_NETFLOW_FLOW_BUFFER
  sendString(" " xstr(MAX_NETFLOW_FLOW_BUFFER) " flows");
#ifdef MAX_NETFLOW_PACKET_BUFFER
  sendString(" and");
#endif
#endif

#ifdef MAX_NETFLOW_PACKET_BUFFER
  sendString(" " xstr(MAX_NETFLOW_PACKET_BUFFER) " flow packets");
#endif

  sendString(" processed.</p>\n"
             "<p>Errors may cause processing to be abandoned and those flows (flow packets) "
             "are not counted in these values.</p>\n"
             "<p>Small averages are good, especially if the standard deviation is small "
             "(standard deviation is a measurement of the variability of the actual values "
             "around the average).</p>\n"
             "<p>&nbsp;</p>\n"
             "</td></tr></table></center>\n");
#endif /* MAX_NETFLOW_FLOW_BUFFER || MAX_NETFLOW_PACKET_BUFFER */

#ifdef MAX_NETFLOW_FLOW_BUFFER
  printSectionTitle("Individual Flows");

  if(netflowflowBufferCount >= MAX_NETFLOW_FLOW_BUFFER) {

    sendString("<center><table border=\"1\""TABLE_DEFAULTS">\n"
               "<tr><th align=\"center\" "DARK_BG">Item</th>"
               "<th align=\"center\" width=\"75\" "DARK_BG">Time</th></tr>\n");

    for(i=0; i<MAX_NETFLOW_FLOW_BUFFER; i++) {
      if(netflowflowBuffer[i] > fmaxTime) fmaxTime = netflowflowBuffer[i];
      if(netflowflowBuffer[i] < fminTime) fminTime = netflowflowBuffer[i];

      if(i==0) {
        fM = netflowflowBuffer[0];
        fT = 0.0;
      } else {
        fQ = netflowflowBuffer[i] - fM;
        fR = fQ / (float)(i+1);
        fM += fR;
        fT = fT + i * fQ * fR;
      }
    }
    fSD = sqrtf(fT / (MAX_NETFLOW_FLOW_BUFFER - 1));
    fXBAR /*average*/ = fM;

    sendString("<tr><th align=\"left\" "DARK_BG">Minimum</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", fminTime);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Average</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", fXBAR);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Maximum</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", fmaxTime);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Standard Deviation</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", fSD);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Maximum ever</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", netflowfmaxTime);
    sendString(buf);

    sendString("</table>\n</center>\n");

  } else {
    printNoDataYet();
  }
#ifdef MAX_NETFLOW_PACKET_BUFFER
  sendString("<p>&nbsp;</p>\n");
#endif
#endif /* MAX_NETFLOW_FLOW_BUFFER */

#ifdef MAX_NETFLOW_PACKET_BUFFER
  printSectionTitle("Flow Packets");

  if(netflowpacketBufferCount >= MAX_NETFLOW_PACKET_BUFFER) {

    sendString("<center><table border=\"1\""TABLE_DEFAULTS">\n"
               "<tr><th align=\"center\" "DARK_BG">Item</th>"
               "<th align=\"center\" width=\"75\" "DARK_BG">Time</th></tr>\n");

    for(i=0; i<MAX_NETFLOW_PACKET_BUFFER; i++) {
      if(netflowpacketBuffer[i] > rmaxTime) rmaxTime = netflowpacketBuffer[i];
      if(netflowpacketBuffer[i] < rminTime) rminTime = netflowpacketBuffer[i];

      if(i==0) {
        rM = netflowpacketBuffer[0];
        rT = 0.0;
      } else {
        rQ = netflowpacketBuffer[i] - rM;
        rR = rQ / (float)(i+1);
        rM += rR;
        rT = rT + i * rQ * rR;
      }
    }
    rSD = sqrtf(rT / (MAX_NETFLOW_PACKET_BUFFER - 1));
    rXBAR /*average*/ = rM;

    sendString("<tr><th align=\"left\" "DARK_BG">Minimum</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", rminTime);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Average</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", rXBAR);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Maximum</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", rmaxTime);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Standard Deviation</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", rSD);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Maximum ever</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", netflowpmaxTime);
    sendString(buf);

    sendString("</table>\n</center>\n");

  } else {
    printNoDataYet();
  }

#endif /* MAX_NETFLOW_PACKET_BUFFER */

  printPluginTrailer(NULL,
                     "NetFlow is a trademark of <a href=\"http://www.cisco.com/\" "
                     "title=\"Cisco home page\">Cisco Systems</a>");

}

/* ****************************** */

static void printNetFlowConfiguration(int deviceId) {
  char buf[512], buf1[32], buf2[32];

#ifdef HAVE_SCPT
#define UDPSLASHSCPT "UDP/SCTP"
#else
#define UDPSLASHSCPT "UDP"
#endif

  sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");
  sendString("<tr><th colspan=\"4\" "DARK_BG">Incoming Flows</th></tr>\n");

  sendString("<tr><th colspan=2 "DARK_BG">NetFlow Device</th>");

  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId);
  sendString(buf);

  sendString("<input name=\"name\" size=\"24\" value=\"");
  sendString(myGlobals.device[deviceId].humanFriendlyName);
  sendString("\"> <input type=\"submit\" value=\"Set Interface Name\">");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), " [ <A HREF=\"/plugins/%s\"/>List NetFlow Interfaces</A> ]</p>\n</form>",
		netflowPluginInfo->pluginName);
  sendString(buf);


  if(deviceId != myGlobals.actualReportDeviceId) {
    sendString("<p><font color=red><b>NOTE: Your web view is not set on this interface. "
	       "<A HREF=/"CONST_SWITCH_NIC_HTML">Click here</A> to switch NIC view</b></font>\n");
  }

  sendString("</td></tr>\n");

  sendString("<tr><th rowspan=\"2\" "DARK_BG">Flow<br>Collection</th>\n");

  sendString("<th "DARK_BG">Local<br>Collector<br>" UDPSLASHSCPT "<br>Port</th>\n");

  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId);
  sendString(buf);

  sendString("<input name=\"port\" size=\"5\" value=\"");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.device[deviceId].netflowGlobals->netFlowInPort);
  sendString(buf);

  sendString("\"> [ Use a port value of 0 to disable collection ] "
	     "<input type=\"submit\" value=\"Set Port\">"
	     "</p>\n</form>\n\n"
             "<p>If you want <b>ntop</b> to display NetFlow data it receives from other "
             "hosts, i.e. act as a collector, you must specify the " UDPSLASHSCPT
	     " port to listen to. "
             "The default port used for NetFlow is " DEFAULT_NETFLOW_PORT_STR ".</p>\n"
	     "<p align=\"right\"></p>\n");

  if(myGlobals.device[deviceId].netflowGlobals->netFlowInPort == 0)
    sendString("<p><font color=red>WARNING</font>: "
	       "The 'Local Collector " UDPSLASHSCPT  "Port' is zero (none). "
               "Even if this plugin is ACTIVE, you must still enter a port number for "
               "<b>ntop</b> to receive and process NetFlow data.</p>\n");

  sendString("</td></tr>\n");

  sendString("<tr><th "DARK_BG">Virtual<br>NetFlow<br>Interface<br>Network<br>Address</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId);
  sendString(buf);

  sendString(" <input name=\"ifNetMask\" size=\"32\" value=\"");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/%s",
		_intoa(myGlobals.device[deviceId].netflowGlobals->netFlowIfAddress, buf1, sizeof(buf1)),
		_intoa(myGlobals.device[deviceId].netflowGlobals->netFlowIfMask, buf2, sizeof(buf2)));
  sendString(buf);
  sendString("\"> ");
  sendString("<input type=\"submit\" value=\"Set Interface Address\"></p>\n</form>\n");

  sendString("<p>This value is in the form of a network address and mask on the "
             "network where the actual NetFlow probe is located. "
             "<b>ntop</b> uses this value to determine which TCP/IP addresses are "
             "local and which are remote.</p>\n"
             "<p>You may specify this in either format, &lt;network&gt;/&lt;mask&gt; or "
             "CIDR (&lt;network&gt;/&lt;bits&gt;). An existing value is displayed "
             "in &lt;network&gt;/&lt;mask&gt; format.</p>\n"
             "<p>If the NetFlow probe is monitoring only a single network, then "
             "this is all you need to set. If the NetFlow probe is monitoring "
             "multiple networks, then pick one of them for this setting and use "
             "the -m | --local-subnets parameter to specify the others.</p>\n"
             "<p>This interface is called 'virtual' because the <b>ntop</b> host "
             "is not really connected to the network you specify here.</p>\n"
             "</td></tr>\n");

  sendString("<tr><th colspan=\"2\" "DARK_BG">Flow Aggregation</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId);
  sendString(buf);

  sendString("<p><SELECT NAME=netFlowAggregation>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
		noAggregation,
		(myGlobals.device[deviceId].netflowGlobals->netFlowAggregation == noAggregation) ? " SELECTED" : "",
		"None (no aggregation)");
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
		portAggregation,
		(myGlobals.device[deviceId].netflowGlobals->netFlowAggregation == portAggregation) ? " SELECTED" : "",
		"TCP/UDP Port");
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
		hostAggregation,
		(myGlobals.device[deviceId].netflowGlobals->netFlowAggregation == hostAggregation) ? " SELECTED" : "",
		"Host");
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
		protocolAggregation,
		(myGlobals.device[deviceId].netflowGlobals->netFlowAggregation == protocolAggregation) ? " SELECTED" : "",
		"Protocol (TCP, UDP, ICMP)");
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
		asAggregation,
		(myGlobals.device[deviceId].netflowGlobals->netFlowAggregation == asAggregation) ? " SELECTED" : "",
		"AS");
  sendString(buf);

  sendString("</select>");

  sendString(" <input type=\"submit\" value=\"Set Aggregation Policy\"></p>\n"
             "</form><p><b>ntop</b> can aggregate (combine) NetFlow information based "
             "on a number of 'policies'.  The default is to store all NetFlow "
             "data (perform no addregation).  Other choices are:</p>\n"
             "<ul>\n"
             "<li><b>Port Aggregation</b>&nbsp;combines all traffic by port number, "
	     "regardless of source or destination address. For example, web "
	     "traffic to both 192.168.1.1 and 192.168.1.2 would be combined "
	     "into a single 'host'.</li>\n"
             "<li><b>Host Aggregation</b>&nbsp;combines all traffic to a host, "
	     "regardless of source or destination port number.  For example, "
	     "both web and ftp traffic to 192.168.1.1 would be combined into "
	     "a single 'port'.</li>\n"
             "<li><b>Protocol Aggregation</b>&nbsp;combines all traffic by TCP/IP "
	     "protocol (TCP, UDP or ICMP), regardless of source or destination "
	     "address or port. For example, all ICMP traffic would be combined, "
	     "regardless of origin or destination.</li>\n"
             "<li><b>AS Aggregation</b>&nbsp; combines all NetFlow data by AS "
	     "(Autonomous System) number, that is as if the source and destination "
	     "address and port were all zero. For more information on AS Numbers, "
	     "see <a href=\"http://www.faqs.org/rfcs/rfc1930.html\" "
	     "title=\"link to rfc 1930\">RFC 1930</a> and the high level "
	     "assignments at <a href=\"http://www.iana.org/assignments/as-numbers\" "
	     "title=\"link to iana assignments\">IANA</a></li>\n"
             "</ul>\n"
             "</td>\n");

  sendString("<tr><th rowspan=\"3\" "DARK_BG">Filtering</th>\n");

  sendString("<th "DARK_BG">White List</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId);
  sendString(buf);

  sendString("<input name=\"whiteList\" size=\"60\" value=\"");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
		myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList == NULL ?
		" " : myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList);
  sendString(buf);
  sendString("\"> <input type=\"submit\" value=\"Set White List\"></p>\n</form>\n"
             "<p>This is a list of one or more TCP/IP host(s)/network(s) which we will "
             "store data from when these host(s)/network(s) occur in the NetFlow records.</p>\n"
             "</td>\n</tr>\n");

  sendString("<tr><th "DARK_BG">Black List</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId);
  sendString(buf);

  sendString("<input name=\"blackList\" size=\"60\" value=\"");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
		myGlobals.device[deviceId].netflowGlobals->netFlowBlackList == NULL ? " " :
		myGlobals.device[deviceId].netflowGlobals->netFlowBlackList);
  sendString(buf);
  sendString("\"> <input type=\"submit\" value=\"Set Black List\"></p>\n</form>\n"
             "<p>This is a list of one or more TCP/IP host(s)/network(s) which we will "
             "exclude data from (i.e. not store it) when these host(s)/network(s) occur "
             "in the NetFlow records.</p>\n"
             "</td>\n</tr>\n");

  sendString("<tr><td colspan=\"3\"><ul>"
	     "<li><i>Changes to white / black lists take affect immediately, "
	     "but are NOT retro-active.</i></li>\n"
             "<li>Use a space to disable a list.</li>\n"
             "<li>Use a.b.c.d/32 for a single host in a list.</li>\n"
             "<li>The white / black lists accept both &lt;network&gt;/&lt;mask&gt; and "
             "CIDR &lt;network&gt;/&lt;bits&gt; format.  Both formats may be used in the "
             "same list. "
             "For example, 192.168.1.0/24 means all addresses with 24 bits of network and "
             "thus 8 bits of host, or the range from 192.168.1.0 to 192.168.1.255. "
             "Similarly, the list 192.168.1.0/24,192.168.2.0/255.255.255.0 means the range "
             "from 192.168.1.0 - 192.168.2.255.</li>\n"
             "<li>The white list and black interact this way:\n"
             "<ul><li>If present, the black list is processed FIRST. Data from any host "
             "matching the black list is simply thrown away.</li>\n"
             "<li>If no black list is specified, no hosts are excluded.</li>\n"
             "<li>If present, the white list is processed SECOND.  Data from any host "
             "NOT matching the white list is thrown away.</li>\n"
             "<li>If no white list is specified, the value 0.0.0.0/0 (ALL hosts) is used.</li>\n"
             "</ul>\n</li>\n</ul>\n"
             "</td></tr>\n");

  sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
             "<tr><th colspan=\"4\" "DARK_BG">General Options</th></tr>\n");

  /* ****************************************************** */

  sendString("<tr><th colspan=\"2\" "DARK_BG">Enable Session Handling</th>\n");

  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId);
  sendString(buf);

  /* ****************************************************** */

  sendString("<tr><th rowspan=\"3\" "DARK_BG">Flow Dump</th>\n");

  sendString("<th "DARK_BG">Dump Interval</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId);
  sendString(buf);
  sendString("<input name=\"netFlowDumpInterval\" size=\"5\" value=\"");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d",
		myGlobals.device[deviceId].netflowGlobals->dumpInterval);
  sendString(buf);
  sendString("\"> sec <input type=\"submit\" value=\"Set Dump Interval\"></p>\n</form>\n"
             "<p>Specifies how often data is stored permanently. "
	     "Set it to 0 (zero) to disable dumping</p>\n</td>\n</tr>\n");

  sendString("<tr><th "DARK_BG">Dump File Path</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId);
  sendString(buf);
  sendString("<input name=\"netFlowDumpPath\" size=\"60\" value=\"");
  sendString(myGlobals.device[deviceId].netflowGlobals->dumpPath == NULL ?
	     "./netflow-dump" : myGlobals.device[deviceId].netflowGlobals->dumpPath);
  sendString("\"> <input type=\"submit\" value=\"Set Dump File Path\"></p>\n</form>\n"
             "<p>Specifies the directory where dump files will be saved. Please make sure that "
	     "ntop has write access to the specified directory.</p>\n</td>\n</tr>\n");

  sendString("<tr><td colspan=\"3\">You can instrument ntop to save incoming flows on disk so"
	     " that you can use them for integration with other applications or for "
	     "historical purposes:<ul>"
	     "<li>Flows are stored on files whose name is &lt;time of the day&gt;.flow"
	     "<li>The file contents is [&lt;flow length (4 digits 0 padded)&gt;&lt;raw flow&gt;]*"
	     "</ul></td></tr>\n");


  /* ********************************************* */

  sendString("<tr><th colspan=\"2\" "DARK_BG">Debug</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId);
  sendString(buf);

  if(myGlobals.device[deviceId].netflowGlobals->netFlowDebug) {
    sendString("<input type=\"radio\" name=\"debug\" value=\"1\" checked>On");
    sendString("<input type=\"radio\" name=\"debug\" value=\"0\">Off");
  } else {
    sendString("<input type=\"radio\" name=\"debug\" value=\"1\">On");
    sendString("<input type=\"radio\" name=\"debug\" value=\"0\" checked>Off");
  }

  sendString(" <input type=\"submit\" value=\"Set Debug\"></p>\n");

  sendString("</form>\n"
             "<p>This option turns on debugging, which dumps a huge quantity of "
             "noise into the standard <b>ntop</b> log, all about what the NetFlow "
             "plugin is doing.  If you are doing development, this might be helpful, "
             "otherwise <i>leave it alone</i>!</p>\n"
	     "</td>\n</tr>\n");

  sendString("<tr><td colspan=4><font color=red><b>REMEMBER</b><br></font><ul><li>Regardless of settings here, "
             "the NetFlow plugin must be ACTIVE on the main plugin menu (click "
             "<a href=\"../" CONST_SHOW_PLUGINS_HTML "\">here</a> to go back) "
             "for <b>ntop</b> to receive and/or "
             "process NetFlow data.\n"
             "<li>Any option not indicated as taking effect immediately will require you "
             "to recycle (inactivate and then activate) the NetFlow plugin in order "
             "for the change to take affect.</ul></td></tr>\n");

  sendString("</table>\n</center>\n");
}
#undef UDPSLASHSCPT

/* ****************************** */

static void printNetFlowStatisticsRcvd(int deviceId) {
  char buf[512], formatBuf[32], formatBuf2[32], formatBuf3[32];
  u_int i, totFlows;
  InterfaceStats *ifStats = myGlobals.device[deviceId].netflowGlobals->ifStats;

  if(ifStats != NULL) {
    sendString("<tr " TR_ON ">\n"
	       "<th "DARK_BG">Interface Statistics</th>\n"
	       "<th "DARK_BG">NetFlow Device</th>"
	       "<th "DARK_BG">Interface Name/Id</th>"
	       "<th "DARK_BG">Pkts</th>"
	       "<th "DARK_BG">Bytes</th>"
	       "</tr>\n");

    while(ifStats != NULL) {
      struct stat statbuf;
      int found = 0;
      struct in_addr addr;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "%s/interfaces/%s/NetFlow/%d_%u_%u/ifInOctets.rrd",
		    myGlobals.rrdPath, myGlobals.device[deviceId].uniqueIfName,
		    ifStats->interface_id, ifStats->netflow_device_ip, ifStats->netflow_device_port);
      revertSlashIfWIN32(buf, 0);

      if(!stat(buf, &statbuf))
	found = 1;
      else {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/interfaces/%s/NetFlow/%d_%u_%u/ifOutOctets.rrd",
		      myGlobals.rrdPath, myGlobals.device[deviceId].uniqueIfName,
		      ifStats->interface_id, ifStats->netflow_device_ip, ifStats->netflow_device_port);
	revertSlashIfWIN32(buf, 0);
	if(!stat(buf, &statbuf)) found = 1;
      }

      if(!found) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TR " TR_ON ">\n<TH " TH_BG " ALIGN=\"LEFT\" "DARK_BG " NOWRAP>"
		      "Interface %d</th>\n",
		      ifStats->interface_id);
	sendString(buf);
      } else {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TR " TR_ON ">\n<TD " TD_BG " ALIGN=\"CENTER\">"
		      "<IMG SRC=\"/plugins/rrdPlugin?action=netflowIfSummary&key=%s/NetFlow/%d_%u_%u&graphId=0\">"
		      "<A HREF=\"/plugins/rrdPlugin?action=netflowIfSummary&key=%s/NetFlow/%d_%u_%u&graphId=0&mode=zoom\">"
		      "<IMG valign=middle class=tooltip SRC=/graph_zoom.gif border=0></A>"
		      "</td>\n",
		      myGlobals.device[deviceId].uniqueIfName, ifStats->interface_id, ifStats->netflow_device_ip, ifStats->netflow_device_port,
		      myGlobals.device[deviceId].uniqueIfName, ifStats->interface_id, ifStats->netflow_device_ip, ifStats->netflow_device_port);
	sendString(buf);
      }

      addr.s_addr = ifStats->netflow_device_ip;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=right>%s:%d</td>",
		    _intoa(addr, formatBuf, sizeof(formatBuf)),
		    ifStats->netflow_device_port);
      sendString(buf);

      if(ifStats->interface_name[0] != '\0') {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=right>%s</td>",
		      ifStats->interface_name);
	sendString(buf);
      } else {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=right>%d</td>",
		      ifStats->interface_id);
	sendString(buf);
      }

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=right nowrap>%s&nbsp;in<br>%s&nbsp;out</td>",
		    formatPkts(ifStats->inPkts.value, formatBuf, sizeof(formatBuf)),
		    formatPkts(ifStats->outPkts.value, formatBuf2, sizeof(formatBuf2)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=right nowrap>%s&nbsp;in<br>%s&nbsp;out</td>",
		    formatBytes(ifStats->inBytes.value, 1, formatBuf, sizeof(formatBuf)),
		    formatBytes(ifStats->outBytes.value, 1, formatBuf2, sizeof(formatBuf2)));
      sendString(buf);

      sendString("</td></tr>\n");

      ifStats = ifStats->next;
    }
  }

  /* ***************************************************************** */

  sendString("<tr " TR_ON ">\n"
             "<th colspan=\"5\" "DARK_BG">Received Flows</th>\n"
             "</tr>\n"
             "<tr " TR_ON ">\n"
             "<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Flow Senders</th>\n"
             "<td width=\"20%\" colspan=3>");

  sendString("<table border=\"1\" "TABLE_DEFAULTS" width=100% valign=top>");
  sendString("<tr><th " DARK_BG ">Sender</th><th " DARK_BG ">Pkts</th>"
	     "<th " DARK_BG ">Flows</th><th " DARK_BG ">Lost Flows</th></tr>");

  for(i=0; i<MAX_NUM_PROBES; i++) {
    if(myGlobals.device[deviceId].netflowGlobals->probeList[i].probeAddr.s_addr == 0) break;

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr><td align=right>%s:%d</td>"
		  "<td align=right>%s</td>"
		  "<td align=right>%s</td>"
		  "<td align=right>%s%s%s</td></tr>\n",
		  _intoa(myGlobals.device[deviceId].netflowGlobals->probeList[i].probeAddr, buf, sizeof(buf)),
		  myGlobals.device[deviceId].netflowGlobals->probeList[i].probePort,
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->probeList[i].pkts,
			     formatBuf, sizeof(formatBuf)),
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->probeList[i].totNumFlows,
			     formatBuf2, sizeof(formatBuf2)),
		  (myGlobals.device[deviceId].netflowGlobals->probeList[i].lostFlows > 0) ? "<b><FONT color=red>" : "",
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->probeList[i].lostFlows,
			     formatBuf3, sizeof(formatBuf3)),
		  (myGlobals.device[deviceId].netflowGlobals->probeList[i].lostFlows > 0) ? "</FONT></b>" : "");
    sendString(buf);
  }
  sendString("</table></td>\n</tr>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Packets Received</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Packets with Bad Version</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numBadNetFlowsVersionsRcvd,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Packets Processed</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd -
			   myGlobals.device[deviceId].netflowGlobals->numBadNetFlowsVersionsRcvd,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Valid Flows Received</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsRcvd,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  if(myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd > 0) {
    totFlows = (u_int)(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV5Rcvd +
		       myGlobals.device[deviceId].netflowGlobals->numNetFlowsV7Rcvd +
		       myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9Rcvd +
		       myGlobals.device[deviceId].netflowGlobals->numBadFlowPkts +
		       myGlobals.device[deviceId].netflowGlobals->numBadFlowBytes +
		       myGlobals.device[deviceId].netflowGlobals->numBadFlowReality +
		       myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9UnknTemplRcvd);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr " TR_ON ">\n"
		  "<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Average Number of Flows per Packet</th>\n"
		  "<td " TD_BG " align=\"right\" colspan=3>%.1f</td>\n"
		  "</tr>\n",
		  (float)totFlows/(float)myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd);
    sendString(buf);
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>V1 Flows Received</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV1Rcvd, formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>V5 Flows Received</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV5Rcvd, formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>V7 Flows Received</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV7Rcvd, formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>V9 Data Flows Received</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9Rcvd, formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>V9 Option Flows Received</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9OptionFlowsRcvd,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  if(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9TemplRcvd) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr " TR_ON ">\n"
		  "<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Total V9 Templates Received</th>\n"
		  "<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		  "</tr>\n",
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9TemplRcvd, formatBuf, sizeof(formatBuf)));
    sendString(buf);
  }

  if(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9BadTemplRcvd) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr " TR_ON ">\n"
		  "<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Bad V9 Templates Received</th>\n"
		  "<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		  "</tr>\n",
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9BadTemplRcvd, formatBuf, sizeof(formatBuf)));
    sendString(buf);
  }

  if(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9UnknTemplRcvd) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr " TR_ON ">\n"
		  "<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>V9 Flows with Unknown Templates Received</th>\n"
		  "<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		  "</tr>\n",
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9UnknTemplRcvd, formatBuf, sizeof(formatBuf)));
    sendString(buf);
  }

  sendString("<tr><td colspan=\"5\">&nbsp;</td></tr>\n"
             "<tr " TR_ON ">\n"
             "<th colspan=\"5\" "DARK_BG">Discarded Flows</th>\n"
             "</tr>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Flows with Zero Packet Count</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numBadFlowPkts,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Flows with Zero Byte Count</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numBadFlowBytes,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Flows with Bad Data</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numBadFlowReality,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Flows with Unknown Template</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9UnknTemplRcvd,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);


  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Total Number of Flows Processed</th>\n"
		"<td " TD_BG " align=\"right\" colspan=3>%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsProcessed,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  if((myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedWhiteList +
      myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedBlackList +
      myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedWhiteList +
      myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedBlackList) > 0) {

    sendString("<tr><td colspan=\"5\">&nbsp;</td></tr>\n"
               "<tr " TR_ON ">\n"
               "<th colspan=\"5\" "DARK_BG">Accepted/Rejected Flows</th>\n"
               "</tr>\n"
               "<tr " TR_ON ">\n"
               "<th " DARK_BG" colspan=2>&nbsp;</th>\n"
               "<th " DARK_BG" colspan=3>Source / Destination</th>\n"
               "</tr>\n");

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr " TR_ON ">\n"
		  "<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Rejected - Black list</th>\n"
		  "<td " TD_BG " colspan=3>%s&nbsp;/&nbsp;%s</td>\n"
		  "</tr>\n",
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedBlackList,
			     formatBuf, sizeof(formatBuf)),
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedBlackList,
			     formatBuf2, sizeof(formatBuf2)));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr " TR_ON ">\n"
		  "<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Rejected - White list</th>\n"
		  "<td " TD_BG " colspan=3>%s&nbsp;/&nbsp;%s</td>\n"
		  "</tr>\n",
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedWhiteList,
			     formatBuf, sizeof(formatBuf)),
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedWhiteList,
			     formatBuf2, sizeof(formatBuf2)));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr " TR_ON ">\n"
		  "<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Accepted</th>\n"
		  "<td " TD_BG " colspan=3>%s&nbsp;/&nbsp;%s</td>\n"
		  "</tr>\n",
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryAccepted,
			     formatBuf, sizeof(formatBuf)),
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryAccepted,
			     formatBuf2, sizeof(formatBuf2)));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr " TR_ON ">\n"
		  "<th " TH_BG " align=\"left\" "DARK_BG " colspan=2>Total</th>\n"
		  "<td " TD_BG " colspan=3>%s&nbsp;/&nbsp;%s</td>\n"
		  "</tr>\n",
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedBlackList +
			     myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedWhiteList +
			     myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryAccepted,
			     formatBuf, sizeof(formatBuf)),
		  formatPkts(myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedBlackList +
			     myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedWhiteList +
			     myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryAccepted,
			     formatBuf2, sizeof(formatBuf2)));
    sendString(buf);
  }
}

/* ****************************** */

static int createNetFlowDevice(int netFlowDeviceId) {
  int deviceId;
  char buf[32], value[128];

  /* traceEvent(CONST_TRACE_INFO, "NETFLOW: createNetFlowDevice(%d)", netFlowDeviceId); */

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s.%d", NETFLOW_DEVICE_NAME, netFlowDeviceId);
  deviceId = createDummyInterface(buf);

  if(deviceId != -1) {
    myGlobals.device[deviceId].netflowGlobals = (NetFlowGlobals*)malloc(sizeof(NetFlowGlobals));

    if(myGlobals.device[deviceId].netflowGlobals == NULL) {
      /* Not enough memory */
      traceEvent(CONST_TRACE_ERROR, "NETFLOW: not enough memory (netflowGlobals malloc)");
      return(-1);
    }

    memset(myGlobals.device[deviceId].netflowGlobals, 0, sizeof(NetFlowGlobals));

    myGlobals.device[deviceId].activeDevice = 1;
    myGlobals.device[deviceId].dummyDevice  = 0;
    myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId = netFlowDeviceId;
    initNetFlowDevice(deviceId);
    createDeviceIpProtosList(deviceId);

    if(fetchPrefsValue(nfValue(deviceId, "humanFriendlyName", 1),
		       value, sizeof(value)) != -1) {
      free(myGlobals.device[deviceId].humanFriendlyName);
      myGlobals.device[deviceId].humanFriendlyName = strdup(value);
      calculateUniqueInterfaceName(deviceId);
    }

    traceEvent(CONST_TRACE_INFO, "NETFLOW: createNetFlowDevice created device %d",
	       deviceId);
  } else
    traceEvent(CONST_TRACE_ERROR, "NETFLOW: createDummyInterface failed");

  return(deviceId);
}

/* ****************************** */

/* #define DEBUG_FLOWS */
static int mapNetFlowDeviceToNtopDevice(int netFlowDeviceId) {
  int i;

  for(i=0; i<myGlobals.numDevices; i++)
    if(myGlobals.device[i].netflowGlobals != NULL) {
      if(myGlobals.device[i].activeDevice
	 && (myGlobals.device[i].netflowGlobals->netFlowDeviceId == netFlowDeviceId)) {
#ifdef DEBUG_FLOWS
	traceEvent(CONST_TRACE_INFO, "NETFLOW: mapNetFlowDeviceToNtopDevice(%d) = %d",
		   netFlowDeviceId, i);
#endif
	return(i);
      } else {
#ifdef DEBUG_FLOWS
	traceEvent(CONST_TRACE_INFO, "NETFLOW: mapNetFlowDeviceToNtopDevice (id=%d) <=> (netFlowDeviceId=%d)",
		   i, myGlobals.device[i].netflowGlobals->netFlowDeviceId);
#endif
      }
    } else {
#ifdef DEBUG_FLOWS
      traceEvent(CONST_TRACE_INFO, "NETFLOW: netflowGlobals(%d)  = NULL\n", i);
#endif

    }

#ifdef DEBUG_FLOWS
  traceEvent(CONST_TRACE_INFO, "NETFLOW: mapNetFlowDeviceToNtopDevice(%d) failed\n",
	     netFlowDeviceId);
#endif

  return(-1); /* Not found */
}

/* #undef DEBUG_FLOWS */

/* ****************************** */

static void flushDevicePrefs(int deviceId) {
  if(deviceId >= myGlobals.numDevices) return;
  delPrefsValue(nfValue(deviceId, "netFlowInPort", 1));
  delPrefsValue(nfValue(deviceId, "ifNetMask", 1));
  delPrefsValue(nfValue(deviceId, "whiteList", 1));
  delPrefsValue(nfValue(deviceId, "netFlowDumpPath", 1));
  delPrefsValue(nfValue(deviceId, "netFlowDumpInterval", 1));
  delPrefsValue(nfValue(deviceId, "blackList", 1));
  delPrefsValue(nfValue(deviceId, "saveFlowsIntoDB", 1));
  delPrefsValue(nfValue(deviceId, "netFlowAssumeFTP", 1));
  delPrefsValue(nfValue(deviceId, "netFlowAggregation", 1));
  delPrefsValue(nfValue(deviceId, "debug", 1));
  delPrefsValue(nfValue(deviceId, "humanFriendlyName", 1));
}

/* ****************************** */

static void handleNetflowHTTPrequest(char* _url) {
  char workList[1024], *url;
  int deviceId = -1, originalId = -1;

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);

  /* ****************************
   * Process URL stuff          *
   ****************************** */

  if((_url != NULL) && pluginActive) {
    char *strtokState;

    if(strncasecmp(_url, CONST_NETFLOW_STATISTICS_HTML, strlen(CONST_NETFLOW_STATISTICS_HTML)) == 0) {
      printNetFlowStatistics();
      printHTMLtrailer();
      return;
    }

    url = strtok_r(_url, "&", &strtokState);

    while(url != NULL) {
      char *device, *_value = NULL;

      device = strtok(url, "=");
      if(device != NULL) _value = strtok(NULL, "="); else _value = NULL;

      if(_value == NULL) _value = "";

      if(_value && device) {
	char value[256];

	unescape(value, sizeof(value), _value);

	if(strcmp(device, "device") == 0) {
	  originalId = deviceId = atoi(value);

	  if((deviceId > 0) && ((deviceId = mapNetFlowDeviceToNtopDevice(deviceId)) == -1)) {
	    printHTMLheader("NetFlow Configuration Error", NULL, 0);
	    printFlagedWarning("<I>Unable to locate the specified device. Please activate the plugin first.</I>");
	    return;
	  }
	} else if(strcmp(device, "port") == 0) {
	  if(myGlobals.device[deviceId].netflowGlobals->netFlowInPort != atoi(value)) {
	    if(deviceId > 0) {
	      myGlobals.device[deviceId].netflowGlobals->netFlowInPort = atoi(value);
	      storePrefsValue(nfValue(deviceId, "netFlowInPort", 1), value);
	      setNetFlowInSocket(deviceId);
	    }
	  }
	} else if(strcmp(device, "name") == 0) {
	  char old_name[256], new_name[256];

	  sanitize_rrd_string(value);

	  safe_snprintf(__FILE__, __LINE__, old_name, sizeof(old_name),
			"%s/interfaces/%s", myGlobals.rrdPath,
			myGlobals.device[deviceId].uniqueIfName);
	  revertSlashIfWIN32(old_name, 0);

	  free(myGlobals.device[deviceId].humanFriendlyName);
	  web_sanitize(value);
	  myGlobals.device[deviceId].humanFriendlyName = strdup(value);
	  storePrefsValue(nfValue(deviceId, "humanFriendlyName", 1), value);
	  calculateUniqueInterfaceName(deviceId);

	  safe_snprintf(__FILE__, __LINE__, new_name, sizeof(new_name),
			"%s/interfaces/%s", myGlobals.rrdPath,
			myGlobals.device[deviceId].uniqueIfName);
	  revertSlashIfWIN32(new_name, 0);

	  if(rename(old_name, new_name) != 0)
	    traceEvent(CONST_TRACE_WARNING,
		       "Error while renaming %s -> %s [%s]",
		       old_name, new_name, strerror(errno));
	} else if(strcmp(device, "debug") == 0) {
	  if(deviceId > 0) {
	    myGlobals.device[deviceId].netflowGlobals->netFlowDebug = atoi(value);
	    storePrefsValue(nfValue(deviceId, "debug", 1), value);
	  }
	} else if(strcmp(device, "netFlowAggregation") == 0) {
	  if(deviceId > 0) {
	    myGlobals.device[deviceId].netflowGlobals->netFlowAggregation = atoi(value);
	    storePrefsValue(nfValue(deviceId, "netFlowAggregation", 1), value);
	  }
	} else if(strcmp(device, "ifNetMask") == 0) {
	  int a, b, c, d, a1, b1, c1, d1;

	  if(deviceId > 0) {
	    if(sscanf(value, "%d.%d.%d.%d/%d.%d.%d.%d",
		      &a, &b, &c, &d, &a1, &b1, &c1, &d1) == 8) {
	      myGlobals.device[deviceId].netflowGlobals->netFlowIfAddress.s_addr = (a << 24) +(b << 16) +(c << 8) + d;
	      myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr    = (a1 << 24) +(b1 << 16) +(c1 << 8) + d1;
	      storePrefsValue(nfValue(deviceId, "ifNetMask", 1), value);
	    } else if(sscanf(value, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &a1) == 5) {
	      myGlobals.device[deviceId].netflowGlobals->netFlowIfAddress.s_addr = (a << 24) +(b << 16) +(c << 8) + d;
	      myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr    = 0xffffffff >> a1;
	      myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr =~
		myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr;
	      storePrefsValue(nfValue(deviceId, "ifNetMask", 1), value);
	    } else
	      traceEvent(CONST_TRACE_ERROR, "NETFLOW: HTTP request netmask parse error (%s)", value);
	  }
	} else if(strcmp(device, "whiteList") == 0) {
	  /* Cleanup the http control char xform */
	  char *fPtr=value, *tPtr=value;

	  if(deviceId > 0) {
	    while(fPtr[0] != '\0') {
	      if((fPtr[0] == '%') && (fPtr[1] == '2')) {
		*tPtr++ = (fPtr[2] == 'C') ? ',' : '/';
		fPtr += 3;
	      } else {
		*tPtr++ = *fPtr++;
	      }
	    }
	    tPtr[0]='\0';

	    accessMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex,
			"handleNetflowHTTPrequest()w");
	    handleWhiteBlackListAddresses(value,
					  myGlobals.device[deviceId].netflowGlobals->whiteNetworks,
					  &myGlobals.device[deviceId].netflowGlobals->numWhiteNets,
					  (char*)&workList,
					  sizeof(workList));
	    if(myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList != NULL)
	      free(myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList);
	    myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList=strdup(workList);
	    releaseMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
	    storePrefsValue(nfValue(deviceId, "whiteList", 1),
			    myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList);
	  }
	} else if(strcmp(device, "blackList") == 0) {
	  /* Cleanup the http control char xform */
	  char *fPtr=value, *tPtr=value;

	  if(deviceId > 0) {
	    while(fPtr[0] != '\0') {
	      if((fPtr[0] == '%') && (fPtr[1] == '2')) {
		*tPtr++ = (fPtr[2] == 'C') ? ',' : '/';
		fPtr += 3;
	      } else {
		*tPtr++ = *fPtr++;
	      }
	    }
	    tPtr[0]='\0';

	    accessMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex,
			"handleNetflowHTTPrequest()b");
	    handleWhiteBlackListAddresses(value,
					  myGlobals.device[deviceId].netflowGlobals->blackNetworks,
					  &myGlobals.device[deviceId].netflowGlobals->numBlackNets,
					  (char*)&workList,
					  sizeof(workList));
	    if(myGlobals.device[deviceId].netflowGlobals->netFlowBlackList != NULL)
	      free(myGlobals.device[deviceId].netflowGlobals->netFlowBlackList);
	    myGlobals.device[deviceId].netflowGlobals->netFlowBlackList=strdup(workList);
	    releaseMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
	    storePrefsValue(nfValue(deviceId, "blackList", 1),
			    myGlobals.device[deviceId].netflowGlobals->netFlowBlackList);
	  }
	} else if(strcmp(device, "netFlowDumpInterval") == 0) {
	  if(deviceId > 0) {
	    myGlobals.device[deviceId].netflowGlobals->dumpInterval = atoi(value);
	    storePrefsValue(nfValue(deviceId, "netFlowDumpInterval", 1), value);
	  }
	} else if(strcmp(device, "netFlowDumpPath") == 0) {
	  if(deviceId > 0) {
	    myGlobals.device[deviceId].netflowGlobals->dumpPath = strdup(value);
	    storePrefsValue(nfValue(deviceId, "netFlowDumpPath", 1), value);
	  }
	}
      }

      url = strtok_r(NULL, "&", &strtokState);
    }
  }

#ifdef DEBUG_FLOWS
  traceEvent(CONST_TRACE_INFO, "NETFLOW: deviceId=%d", deviceId);
#endif

  if(deviceId == -1) {
    printHTMLheader("NetFlow Device Configuration", NULL, 0);
    printNetFlowDeviceConfiguration();
    return;
  } else if(deviceId < 0) {
    /* Delete an existing device */
    char value[128];
    int readDeviceId;

    deviceId = -deviceId;

    if((deviceId < 0) || ((readDeviceId = mapNetFlowDeviceToNtopDevice(deviceId)) == -1)) {
      printHTMLheader("NetFlow Configuration Error", NULL, 0);
      printFlagedWarning("<I>Unable to locate the specified device. Please activate the plugin first.</I>");
      return;
    }

    traceEvent(CONST_TRACE_INFO, "NETFLOW: Attempting to delete [deviceId=%d][NetFlow device=%d]",
	       deviceId, readDeviceId);

    if(fetchPrefsValue(nfValue(deviceId, "knownDevices", 0), value, sizeof(value)) != -1) {
      char *strtokState, *dev, value1[128];

      value1[0] = '\0';

      dev = strtok_r(value, ",", &strtokState);
      while(dev != NULL) {
	int _dev = atoi(dev);

	if(_dev != deviceId) {
	  if(value1[0] != '\0') strcat(value1, ",");
	  strcat(value1, dev);
	}

	dev = strtok_r(NULL, ",", &strtokState);
      }

      storePrefsValue(nfValue(deviceId, "knownDevices", 0), value1);
    }

    myGlobals.device[readDeviceId].activeDevice = 0; // Terminate thread

    flushDevicePrefs(readDeviceId);

    traceEvent(CONST_TRACE_INFO, "NETFLOW: Device [deviceId=%d][active=%d]",
	       readDeviceId, myGlobals.device[readDeviceId].activeDevice);

    // termNetflowDevice(readDeviceId);

    checkReportDevice();
    printHTMLheader("NetFlow Device Configuration", NULL, 0);
    printNetFlowDeviceConfiguration();
    return;
  } else if(deviceId == 0) {
    /* Add new device */
    char value[128];

    if((fetchPrefsValue(nfValue(deviceId, "knownDevices", 0), value, sizeof(value)) != -1)
       && (strlen(value) > 0)) {
      char *strtokState, *dev, value1[128], buf[256];

      /* traceEvent(CONST_TRACE_INFO, "NETFLOW: knownDevices=%s", value); */

      value1[0] = '\0';

      dev = strtok_r(value, ",", &strtokState);
      while(dev != NULL) {
	int _dev;

	if(strlen(dev) > 0) {
	  _dev = atoi(dev);

	  strcat(value1, ",");
	  strcat(value1, dev);

	  if(_dev >= deviceId)
	    deviceId = _dev+1;
	}

	dev = strtok_r(NULL, ",", &strtokState);
      }

      if(deviceId == 0) deviceId = 2;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s,%d", value1, deviceId);

      traceEvent(CONST_TRACE_INFO, "NETFLOW: knownDevices=%s", buf);
      storePrefsValue(nfValue(deviceId, "knownDevices", 0), buf);
    } else {
      deviceId = 2; /* 1 is reserved */
      traceEvent(CONST_TRACE_INFO, "NETFLOW: knownDevices=2");
      storePrefsValue(nfValue(deviceId, "knownDevices", 0), "2");
    }

    if((deviceId = createNetFlowDevice(deviceId)) <= 0) {
      printHTMLheader("NetFlow Configuration Error", NULL, 0);
      printFlagedWarning("<I>Unable to create a new NetFlow device</I>");
      return;
    }
  } else {
    /* Existing device */
  }

  if(deviceId > 0) {
    /* ****************************
     * Print Configuration stuff  *
     ****************************** */
    printHTMLheader("NetFlow Configuration", NULL, 0);

    printNetFlowConfiguration(deviceId);

    sendString("<br><hr><p>\n");

    if(myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd > 0) {
      /* ****************************
       * Print statistics           *
       ****************************** */
      printSectionTitle("Flow Statistics");

      sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");

      if(myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd > 0)
	printNetFlowStatisticsRcvd(deviceId);

      sendString("</table>\n</center>\n");

      sendString("<p><table border=\"0\"><tr><td width=\"25%\" valign=\"top\" align=\"right\">"
		 "<b>NOTES</b>:</td>\n"
		 "<td><ul>"
		 "<li>The virtual NIC, '" NETFLOW_DEVICE_NAME "' is activated only when incoming "
		 "flow capture is enabled.</li>\n"
		 "<li>Once the virtual NIC is activated, it will remain available for the "
		 "duration of the ntop run, even if you disable incoming flows.</li>\n"
		 "<li>NetFlow packets are associated with this separate, virtual device and are "
		 "not mixed with captured packets.</li>\n"
		 "<li>Activating incoming flows will override the command line -M | "
		 "--no-interface-merge parameter for the duration of the ntop run.</li>\n"
		 "<li>NetFlow activation may (rarely) require ntop restart.</li>\n"
		 "<li>You can switch the reporting device using Admin | Switch NIC, or this "
		 "<a href=\"/" CONST_SWITCH_NIC_HTML "\" title=\"Switch NIC\">link</a>.</li>\n"
		 "</ul></td>\n"
		 "<td width=\"25%\">&nbsp;</td>\n</tr>\n</table>\n");

#ifdef MUTEX_DEBUG
      if(myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex.isLocked) {
	sendString("<table><tr><td colspan=\"2\">&nbsp;</td></tr>\n"
		   "<tr " TR_ON ">\n"
		   "<th colspan=\"2\" "DARK_BG">Mutexes</th>\n"
		   "</tr>\n");

	sendString("<tr " TR_ON ">\n"
		   "<th>List Mutex</th>\n<td><table>");
	printMutexStatus(FALSE, &myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex,
			 "White/Black list mutex");
	printMutexStatus(FALSE, &myGlobals.device[deviceId].netflowGlobals->ifStatsMutex,
			 "Interface statistics mutex");
	sendString("</table><td></tr></table>\n");
      }
#endif
    }

    /* ******************************
     * Print closing              *
     ****************************** */

    sendString("<table border=\"0\"><tr><td width=\"10%\">&nbsp;</td>\n"
	       "<td><p>Please be aware that if you need a fast, light, memory savvy, "
	       "highly configurable NetFlow probe, you better give "
	       "<a href=\"http://www.ntop.org/nProbe.html\" title=\"nProbe page\"><b>nProbe</b></a> "
	       "a try.</p>\n"
	       "<p>If you are looking for a cheap, dedicated hardware NetFlow probe you "
	       "should look into "
	       "<a href=\"http://www.nmon.net/nBox_nmon.html\" "
	       "title=\"nBox86 page\"><b>nBox</b></a> "
	       "<img class=tooltip src=\"/nboxLogo.gif\" alt=\"nBox logo\">.</p>\n"
	       "</td>\n"
	       "<td width=\"10%\">&nbsp;</td>\n</tr>\n</table>\n");
  }

  safe_snprintf(__FILE__, __LINE__, workList, sizeof(workList), "%s?device=%d",
		netflowPluginInfo->pluginURLname, originalId);

  printPluginTrailer((myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd > 0) ?
		     workList : NULL,
                     "NetFlow is a trademark of <a href=\"http://www.cisco.com/\" "
                     "title=\"Cisco home page\">Cisco Systems</a>");

  printHTMLtrailer();
}

/* ****************************** */

static void termNetflowDevice(int deviceId) {
  traceEvent(CONST_TRACE_INFO, "NETFLOW: terminating device %s",
	     myGlobals.device[deviceId].humanFriendlyName);

  if(!pluginActive) return;

  if(myGlobals.device[deviceId].activeDevice == 0) {
    /* traceEvent(CONST_TRACE_WARNING, "NETFLOW: deviceId=%d terminated already", deviceId); */
    return;
  }

  if(myGlobals.device[deviceId].netflowGlobals == NULL) {
    traceEvent(CONST_TRACE_WARNING, "NETFLOW: deviceId=%d terminating a non-NetFlow device", deviceId);
    return;
  }

  if((deviceId >= 0) && (deviceId < myGlobals.numDevices)) {
    if(myGlobals.device[deviceId].netflowGlobals->threadActive) {
      killThread(&myGlobals.device[deviceId].netflowGlobals->netFlowThread);
#ifdef HAVE_SNMP
      killThread(&myGlobals.device[deviceId].netflowGlobals->netFlowUtilsThread);
#endif
      myGlobals.device[deviceId].netflowGlobals->threadActive = 0;
    }
    tryLockMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex, "termNetflow");
    deleteMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);

    if(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket > 0) {
	closeNwSocket(&myGlobals.device[deviceId].netflowGlobals->netFlowInSocket);
	shutdown(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket, SHUT_RDWR);
#ifdef HAVE_SCTP
      if(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket > 0) {
	closeNwSocket(&myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket);
	shutdown(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket, SHUT_RDWR);
	}
#endif
    }

    while(myGlobals.device[deviceId].netflowGlobals->templates != NULL) {
      FlowSetV9 *temp = myGlobals.device[deviceId].netflowGlobals->templates->next;

      free(myGlobals.device[deviceId].netflowGlobals->templates->fields);
      free(myGlobals.device[deviceId].netflowGlobals->templates);
      myGlobals.device[deviceId].netflowGlobals->templates = temp;
    }

    free(myGlobals.device[deviceId].netflowGlobals);
    myGlobals.device[deviceId].activeDevice = 0;
  } else
    traceEvent(CONST_TRACE_WARNING, "NETFLOW: requested invalid termination of deviceId=%d", deviceId);
}

/* **************************************** */

static void termNetflowFunct(u_char termNtop /* 0=term plugin, 1=term ntop */) {
  char value[128];

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Terminating NetFlow");

  if((fetchPrefsValue(nfValue(0, "knownDevices", 0), value, sizeof(value)) != -1) && (strlen(value) > 0)) {
    char *strtokState, *dev;

    dev = strtok_r(value, ",", &strtokState);
    while(dev != NULL) {
      int deviceId, theDeviceId = atoi(dev);

      if((theDeviceId > 0) && ((deviceId = mapNetFlowDeviceToNtopDevice(theDeviceId)) > 0)) {
	termNetflowDevice(deviceId);
      } else {
	traceEvent(CONST_TRACE_INFO, "NETFLOW: [netFlowDeviceId=%d] device thread terminated in the meantime", theDeviceId);
      }

      dev = strtok_r(NULL, ",", &strtokState);
    }
  } else
    traceEvent(CONST_TRACE_INFO, "NETFLOW: no devices to terminate (%s)", value);

  traceEvent(CONST_TRACE_INFO, "NETFLOW: Thanks for using ntop NetFlow");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Done");
  fflush(stdout);
  pluginActive = 0;
}

/* **************************************** */

#ifdef DEBUG_FLOWS

static void handleNetFlowPacket(u_char *_deviceId, const struct pcap_pkthdr *h,
				const u_char *p) {
  int deviceId;

  if(myGlobals.pcap_file_list != NULL) {
    /* ntop is reading packets from a file */
    struct ether_header ehdr;
    u_int caplen = h->caplen;
    u_int length = h->len;
    unsigned short eth_type;
    struct ip ip;

    deviceId = 1; /* Dummy value */

#ifdef DEBUG_FLOWS
    {
      static long numPkt=0;

      ++numPkt;

      if(myGlobals.runningPref.debugMode)
	traceEvent(CONST_TRACE_INFO, "Rcvd packet to dissect [caplen=%d][len=%d][num_pkt=%lu]",
		   caplen, length, numPkt);
    }
#endif

    if(caplen >= sizeof(struct ether_header)) {
      memcpy(&ehdr, p, sizeof(struct ether_header));
      eth_type = ntohs(ehdr.ether_type);

      if(eth_type == ETHERTYPE_IP) {
	u_int plen, hlen;

#ifdef DEBUG_FLOWS
	if(myGlobals.runningPref.debugMode)
	  traceEvent(CONST_TRACE_INFO, "Rcvd IP packet to dissect");
#endif

	memcpy(&ip, p+sizeof(struct ether_header), sizeof(struct ip));
	hlen =(u_int)ip.ip_hl * 4;
	NTOHL(ip.ip_dst.s_addr); NTOHL(ip.ip_src.s_addr);

	plen = length-sizeof(struct ether_header);

#ifdef DEBUG_FLOWS
	if(myGlobals.runningPref.debugMode)
	  traceEvent(CONST_TRACE_INFO, "Rcvd IP packet to dissect "
		     "[deviceId=%d][sender=%s][proto=%d][len=%d][hlen=%d]",
		     deviceId, intoa(ip.ip_src), ip.ip_p, plen, hlen);
#endif

	if(ip.ip_p == IPPROTO_UDP) {
	  if(plen >(hlen+sizeof(struct udphdr))) {
	    char* rawSample    =(void*)(p+sizeof(struct ether_header)+hlen+sizeof(struct udphdr));
	    int   rawSampleLen = h->caplen-(sizeof(struct ether_header)+hlen+sizeof(struct udphdr));

#ifdef DEBUG_FLOWS
	    if(myGlobals.runningPref.debugMode)
	      traceEvent(CONST_TRACE_INFO, "Rcvd from from %s", intoa(ip.ip_src));
#endif

	    myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd++;
	    dissectFlow(ip.ip_src.s_addr, 0 /* port */, 0 /* probeId */, rawSample, rawSampleLen, deviceId);
	  }
	}
      } else {
#ifdef DEBUG_FLOWS
	if(myGlobals.runningPref.debugMode)
	  traceEvent(CONST_TRACE_INFO, "Rcvd non-IP [0x%04X] packet to dissect", eth_type);
#endif
      }
    }
  }
}

#endif

/* ***************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGIN
PluginInfo* netflowPluginEntryFctn(void)
#else
PluginInfo* PluginEntryFctn(void)
#endif
{
  traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	     "NETFLOW: Welcome to %s.(C) 2002-12 by Luca Deri",
	     netflowPluginInfo->pluginName);

  return(netflowPluginInfo);
}

/* This must be here so it can access the struct PluginInfo, above */
static void setPluginStatus(char * status)
{
  if(netflowPluginInfo->pluginStatusMessage != NULL)
    free(netflowPluginInfo->pluginStatusMessage);
  if(status == NULL) {
    netflowPluginInfo->pluginStatusMessage = NULL;
  } else {
    netflowPluginInfo->pluginStatusMessage = strdup(status);
  }
}
