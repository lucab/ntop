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

#include "ntop.h"
#include "globals-report.h"

#include <rrd.h>

#define MAX_NETWORK_EXPANSION   24 /* /24 */
/*
 * Extra pages
 */
#define CONST_RRD_STATISTICS_HTML           "statistics.html"
#define CONST_RRD_ARBGRAPH_HTML             "arbgraph.html"

/*
 * Flags for rrd plugin settings...
 */
#define FLAG_RRD_DETAIL_LOW                 0
#define FLAG_RRD_DETAIL_MEDIUM              1
#define FLAG_RRD_DETAIL_HIGH                2
#define CONST_RRD_DETAIL_DEFAULT            FLAG_RRD_DETAIL_MEDIUM

#define FLAG_RRD_ACTION_NONE                0
#define FLAG_RRD_ACTION_GRAPH               1
#define FLAG_RRD_ACTION_LIST                2
#define FLAG_RRD_ACTION_GRAPH_SUMMARY       3
#define FLAG_RRD_ACTION_NF_SUMMARY          4
#define FLAG_RRD_ACTION_NF_IF_SUMMARY       5
#define FLAG_RRD_ACTION_IF_SUMMARY          6
#define FLAG_RRD_ACTION_ARBITRARY           7

#define CONST_RRD_PERMISSIONS_PRIVATE       0
#define CONST_RRD_PERMISSIONS_GROUP         1
#define CONST_RRD_PERMISSIONS_EVERYONE      2

#define DEFAULT_RRD_PERMISSIONS             CONST_RRD_PERMISSIONS_PRIVATE

/* Remember these are OCTAL constants and MUST have a leading 0 -
 * see man chmod but tricky because the apply to both files 
 * and directories - and rrd_create uses 0666 */
#define CONST_RRD_D_PERMISSIONS_PRIVATE     0700
#define CONST_RRD_D_PERMISSIONS_GROUP       0750
#define CONST_RRD_D_PERMISSIONS_EVERYONE    0755
#define CONST_RRD_UMASK_PRIVATE             0066
#define CONST_RRD_UMASK_GROUP               0026
#define CONST_RRD_UMASK_EVERYONE            0022

/*
 * How often should we update rrd statistics?  Overridden in rrd plugin
 */
#define DEFAULT_RRD_INTERVAL                300  /* seconds - rrd counter (default) interval */
#define DEFAULT_RRD_SHORT_INTERVAL          10   /* seconds - short rrd counter (default) interval */
#define DEFAULT_RRD_HOURS                   72   /* hours of interval by interval data (default) */
#define DEFAULT_RRD_DAYS                    90   /* days of hour by hour data (default) */
#define DEFAULT_RRD_MONTHS                  36   /* months of day by day data (default) */
#define DEFAULT_RRD_DUMP_DELAY              10   /* ms (default) */
#define DEFAULT_RRD_HEARTBEAT_MULTIPLIER     3   /* multiplier */
#define AS_RRD_DUMP_PKTS_THRESHOLD          10   /* packets */

/* ****************************************************** */

/*
 * Names for the arbitrary graph creation 
 *    - remember to keep the RRDREQUEST_ values unique in their 1st character
 */
#define CONST_ARBITRARY_RRDREQUEST          "arbreq"
#define CONST_ARBITRARY_RRDREQUEST_GRAPHME  "graph"
#define CONST_ARBITRARY_RRDREQUEST_SHOWME   "show"
#define CONST_ARBITRARY_RRDREQUEST_FETCHME  "fetch"
#define CONST_ARBITRARY_RRDREQUEST_FETCHMECSV "cvsfetch"
#define CONST_ARBITRARY_INTERFACE           "arbiface"
#define CONST_ARBITRARY_IP                  "arbip"
#define CONST_ARBITRARY_FILE                "arbfile"

/* If you add a new major rrd file, it should be added to this list
 */
static char *rrdNames[] = {
                "arpRarpBytes",
                "atalkBytes",
                "badChecksumPkts",
                "broadcastPkts",
                "bytes",
                "bytesBroadcastRcvd",
                "bytesBroadcastSent",
                "bytesRcvd",
                "bytesRcvdFromRem",
                "bytesRcvdLoc",
                "bytesSent",
                "bytesSentLoc",
                "bytesSentRem",
                "decnetBytes",
                "dlcBytes",
                "droppedPkts",
                "egpBytes",
                "ethernetBytes",
                "ethernetPkts",
                "fragmentedIpBytes",
                "icmp6Rcvd",
                "icmp6Sent",
                "icmpBytes",
                "icmpRcvd",
                "icmpSent",
                "ifInBroadcastPkts",
                "ifInDiscards",
                "ifInErrors",
                "ifInMulticastPkts",
                "ifInOctets",
                "ifInUcastPkts",
                "ifInUnknownProtos",
                "ifOutBroadcastPkts",
                "ifOutDiscards",
                "ifOutErrors",
                "ifOutMulticastPkts",
                "ifOutOctets",
                "ifOutUcastPkts",
                "ipBytes",
                "ipv6Bytes",
                "ipxBytes",
                "multicastPkts",
                "netbiosBytes",
                "NF_numDiscardedFlows",
                "NF_numFlowPkts",
                "NF_numFlows",
                "osiBytes",
                "otherBytes",
                "otherIpBytes",
                "packets",
                "pktBroadcastRcvd",
                "pktBroadcastSent",
                "pkts",
                "pktRcvd",
                "pktSent",
                "stpBytes",
                "tcpBytes",
                "tcpRcvd",
                "tcpRcvdFromRem",
                "tcpRcvdLoc",
                "tcpSent",
                "tcpSentLoc",
                "tcpSentRem",
                "tooLongPkts",
                "totContactedRcvdPeers",
                "totContactedSentPeers",
                "udpBytes",
                "udpRcvd",
                "udpRcvdFromRem",
                "udpRcvdLoc",
                "udpSent",
                "udpSentLoc",
                "udpSentRem",
                "upTo1024Pkts",
                "upTo128Pkts",
                "upTo1518Pkts",
                "upTo256Pkts",
                "upTo512Pkts",
                "upTo64Pkts",
                NULL
};

/* ****************************************************** */
/*
 * This flag turns on a signal trap in rrdPlugin.c.  If you're seeing
 * rrd simply and silently die, this might catch the signal and log
 * it for analysis.
 */
/* #define MAKE_WITH_RRDSIGTRAP */

/* RRD_DEBUG controls debug messages in rrdPlugin.c.  See the definition in globals-defines.h,
 * where you really should set it, so the util.c calls get enabled.
 */
//#define RRD_DEBUG 3
#undef RRD_DEBUG

/*
 * Optional: Set a default font for the rrd generated graphs
 *   Courtesy of Chris Turbeville
 */
/*
 #define CONST_RRD_DEFAULT_FONT_SIZE      "8"
 #define CONST_RRD_DEFAULT_FONT_PATH      "/usr/openwin/lib/X11/fonts/TrueType/"
 #define CONST_RRD_DEFAULT_FONT_NAME      "ArialNarrow-Bold.ttf"
*/


static const char *rrd_subdirs[] = {
  "graphics",    /* graphics sub directory - must be first */
  "flows",
  "interfaces",
};

static const char *rrd_colors[] = {
  "#EE0000",
  "#00DD00",
  "#1E90FF",
  "#FFFF00",
  "#0000FF",
  "#00FFFF",
  "#FF00FF",
  "#aa00aa",
  "#00aa00",
  "#550055",
  "#669999",
  "#ccff99",
  "#333333",
  "#0066ff",
  "#ff6633",
  "#999900",
  "#102255",
  "#208352",
  "#FF1493",
  "#FFD700",
  "#d5aad5",
  "#99ff33",
  "#ffcc99",
  "#0033cc",
  "#ffcc00",
  "#33cccc",
  "#339966",
  "#ff3333",
  "#ff0066",
  "#cc3333",
  "#9900ff",
  "#006666"
};
#define CONST_NUM_BAR_COLORS                (sizeof(rrd_colors)/sizeof(rrd_colors[0]))

static const char *rrd_summary_packets[] = { 
  "ethernetPkts",
  "broadcastPkts",
  "multicastPkts",
  "badChecksumPkts",
  NULL
};

struct nameLabel {
  char *name, *label;
};

static const struct nameLabel rrd_summary_traffic[] = { 
  { "ifInOctets", "Ingress" },
  { "ifOutOctets", "Egress" },
  { NULL, NULL }
};

static const struct nameLabel rrd_summary_new_flows[] = { 
  { "NF_numFlows", "Total Flows" },
  { "NF_numDiscardedFlows", "Discarded Flows" },
  { NULL, NULL }
};

static const struct nameLabel rrd_summary_new_nf_flows[] = { 
  { "NF_newTcpNetFlows", "TCP" },
  { "NF_newUdpNetFlows", "UDP" },
  { "NF_newIcmpNetFlows", "ICMP" },
  { "NF_newOtherNetFlows", "Other" },
  { NULL, NULL }
};

static const struct nameLabel rrd_summary_new_nf_flows_size[] = { 
  { "NF_avgTcpNewFlowSize", "TCP" },
  { "NF_avgUdpNewFlowSize", "UDP" },
  { "NF_avgICMPNewFlowSize", "ICMP" },
  { "NF_avgOtherNewFlowSize", "Other" },
  { NULL, NULL }
};

static const char *rrd_summary_proto_bytes[] = { 
  "arpRarpBytes",
  "atalkBytes",
  "fragmentedIpBytes",
  "ipBytes",
  "ipv6Bytes",
  "ipxBytes",
  "osiBytes",
  "otherBytes",
  "stpBytes",
  NULL
};

static const char *rrd_summary_ipproto_bytes[] = { 
  "tcpBytes",
  "udpBytes",
  "icmpBytes",
  "otherIpBytes",
  NULL
};


static const char *rrd_summary_packet_sizes[] = { 
  "upTo1518Pkts",
  "upTo1024Pkts",
  "upTo512Pkts",
  "upTo256Pkts",
  "upTo128Pkts",
  "upTo64Pkts",
  NULL
};

static const char *rrd_summary_local_remote_ip_bytes[] = {
  "ipLocalToLocalBytes",
  "ipLocalToRemoteBytes",
  "ipRemoteToLocalBytes",
  "ipRemoteToRemoteBytes",
  NULL
};

static const char *rrd_summary_host_sentRcvd_packets[] = { 
  "pktSent",
  "pktRcvd",
  NULL
};

static const char *rrd_summary_host_sentRcvd_bytes[] = { 
  "bytesSent",
  "bytesRcvd",
  NULL
};

static const char *rrd_summary_nf_if_octets[] = { 
  "ifInOctets",
  "ifOutOctets",
  "ifSelfOctets",
  NULL
};

static const char *rrd_summary_nf_if_pkts[] = { 
  "ifInPkts",
  "ifOutPkts",
  "ifSelfPkts",
 NULL
};

static const struct nameLabel rrd_filters[] = { 
  { "upTo", "Packet Size" },
  { "cast", "Broad/Multi-cast" },
  { "Flow", "Flows" },
  { "Efficiency", "Network Efficiency" },
  { "NF_", "NetFlow" },
  /* Generic matches go at the end */
  { "Sent", "Sent" },
  { "Rcvd", "Received" },
  { "Bytes", "Volume" },
  { "Pkts", "Packets" },
  { NULL, NULL }
};

#ifdef MAX_RRD_PROCESS_BUFFER
static float rrdprocessBuffer[MAX_RRD_PROCESS_BUFFER];
static int rrdprocessBufferInit,
           rrdprocessBufferCount;
static float rrdpmaxDelay;
#endif

#ifdef MAX_RRD_CYCLE_BUFFER
static float rrdcycleBuffer[MAX_RRD_CYCLE_BUFFER];
static int rrdcycleBufferInit,
           rrdcycleBufferCount;
static float rrdcmaxLength;
#endif

#define RRD_DEFAULT_SPACER_LEN    20
#define RRD_SHORT_SPACER_LEN      11
