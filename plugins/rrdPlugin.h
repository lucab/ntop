/*
 *  Copyright (C) 2002-04 Luca Deri <deri@ntop.org>
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

/*
 * Flags for rrd plugin settings...
 */
#define FLAG_RRD_DETAIL_LOW                 0
#define FLAG_RRD_DETAIL_MEDIUM              1
#define FLAG_RRD_DETAIL_HIGH                2
#define CONST_RRD_DETAIL_DEFAULT            FLAG_RRD_DETAIL_HIGH

#define FLAG_RRD_ACTION_NONE                0
#define FLAG_RRD_ACTION_GRAPH               1
#define FLAG_RRD_ACTION_LIST                2
#define FLAG_RRD_ACTION_GRAPH_SUMMARY       3

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

static const char *rrd_subdirs[] = {
  "graphics",    /* graphics sub directory - must be first */
  "flows",
  "interfaces",
};

static const char *rrd_colors[] = {
  "#1E90FF",
  "#FFFF00",
  "#FF0000",
  "#0000FF",
  "#00FFFF",
  "#FF00FF",
  "#00FF00",
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
  "#d5aad5"
};

static const char *rrd_summary_packets[] = { 
  "ethernetPkts",
  "broadcastPkts",
  "multicastPkts",
  "badChecksumPkts",
  NULL
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
