/*
 *  Copyright (C) 2002-12 Luca Deri <deri@ntop.org>
 *
 *  		       http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

/*
  ntop includes sFlow(TM), freely available from http://www.inmon.com/".

  Some code has been copied from the InMon sflowtool
*/

#include "ntop.h"
#include "globals-report.h"

static void* sflowMainLoop(void* _deviceId);

/* #define DEBUG_FLOWS */

/* ********************************* */

enum SFLAddress_type {
  SFLADDRESSTYPE_IP_V4 = 1,
  SFLADDRESSTYPE_IP_V6 = 2
};

typedef union _SFLAddress_value {
  struct in_addr ip_v4;
  struct in6_addr ip_v6;
} SFLAddress_value;

typedef struct _SFLAddress {
  u_int32_t type;           /* enum SFLAddress_type */
  SFLAddress_value address;
} SFLAddress;

/* Packet header data */

#define SFL_DEFAULT_HEADER_SIZE 128
#define SFL_DEFAULT_COLLECTOR_PORT 6343
#define SFL_DEFAULT_SAMPLING_RATE 400

/* The header protocol describes the format of the sampled header */
enum SFLHeader_protocol {
  SFLHEADER_ETHERNET_ISO8023     = 1,
  SFLHEADER_ISO88024_TOKENBUS    = 2,
  SFLHEADER_ISO88025_TOKENRING   = 3,
  SFLHEADER_FDDI                 = 4,
  SFLHEADER_FRAME_RELAY          = 5,
  SFLHEADER_X25                  = 6,
  SFLHEADER_PPP                  = 7,
  SFLHEADER_SMDS                 = 8,
  SFLHEADER_AAL5                 = 9,
  SFLHEADER_AAL5_IP              = 10, /* e.g. Cisco AAL5 mux */
  SFLHEADER_IPv4                 = 11,
  SFLHEADER_IPv6                 = 12,
  SFLHEADER_MPLS                 = 13
};

/* raw sampled header */

typedef struct _SFLSampled_header {
  u_int32_t header_protocol;            /* (enum SFLHeader_protocol) */
  u_int32_t frame_length;               /* Original length of packet before sampling */
  u_int32_t stripped;                   /* header/trailer bytes stripped by sender */
  u_int32_t header_length;              /* length of sampled header bytes to follow */
  u_int8_t *header_bytes;               /* Header bytes */
} SFLSampled_header;

/* decoded ethernet header */

typedef struct _SFLSampled_ethernet {
  u_int32_t eth_len;       /* The length of the MAC packet excluding
			      lower layer encapsulations */
  u_int8_t src_mac[8];    /* 6 bytes + 2 pad */
  u_int8_t dst_mac[8];
  u_int32_t eth_type;
} SFLSampled_ethernet;

/* decoded IP version 4 header */

typedef struct _SFLSampled_ipv4 {
  u_int32_t length;      /* The length of the IP packet
			    excluding lower layer encapsulations */
  u_int32_t protocol;    /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  struct in_addr src_ip; /* Source IP Address */
  struct in_addr dst_ip; /* Destination IP Address */
  u_int32_t src_port;    /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;    /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags;   /* TCP flags */
  u_int32_t tos;         /* IP type of service */
} SFLSampled_ipv4;

/* decoded IP version 6 data */
typedef struct _SFLSampled_ipv6 {
  u_int32_t length;       /* The length of the IP packet
			     excluding lower layer encapsulations */
  u_int32_t protocol;     /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  struct in6_addr src_ip; /* Source IP Address */
  struct in6_addr dst_ip; /* Destination IP Address */
  u_int32_t src_port;     /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;     /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags;    /* TCP flags */
  u_int32_t priority;     /* IP priority */
} SFLSampled_ipv6;

/* Extended data types */

/* Extended switch data */

typedef struct _SFLExtended_switch {
  u_int32_t src_vlan;       /* The 802.1Q VLAN id of incomming frame */
  u_int32_t src_priority;   /* The 802.1p priority */
  u_int32_t dst_vlan;       /* The 802.1Q VLAN id of outgoing frame */
  u_int32_t dst_priority;   /* The 802.1p priority */
} SFLExtended_switch;

/* Extended router data */

typedef struct _SFLExtended_router {
  SFLAddress nexthop;               /* IP address of next hop router */
  u_int32_t src_mask;               /* Source address prefix mask bits */
  u_int32_t dst_mask;               /* Destination address prefix mask bits */
} SFLExtended_router;

/* Extended gateway data */
enum SFLExtended_as_path_segment_type {
  SFLEXTENDED_AS_SET = 1,      /* Unordered set of ASs */
  SFLEXTENDED_AS_SEQUENCE = 2  /* Ordered sequence of ASs */
};

typedef struct _SFLExtended_as_path_segment {
  u_int32_t type;   /* enum SFLExtended_as_path_segment_type */
  u_int32_t length; /* number of AS numbers in set/sequence */
  union {
    u_int32_t *set;
    u_int32_t *seq;
  } as;
} SFLExtended_as_path_segment;

typedef struct _SFLExtended_gateway {
  SFLAddress nexthop;                       /* Address of the border router that should
                                               be used for the destination network */
  u_int32_t as;                             /* AS number for this gateway */
  u_int32_t src_as;                         /* AS number of source (origin) */
  u_int32_t src_peer_as;                    /* AS number of source peer */
  u_int32_t dst_as_path_segments;           /* number of segments in path */
  SFLExtended_as_path_segment *dst_as_path; /* list of seqs or sets */
  u_int32_t communities_length;             /* number of communities */
  u_int32_t *communities;                   /* set of communities */
  u_int32_t localpref;                      /* LocalPref associated with this route */
} SFLExtended_gateway;

typedef struct _SFLString {
  u_int32_t len;
  char *str;
} SFLString;

/* Extended user data */

typedef struct _SFLExtended_user {
  u_int32_t src_charset;  /* MIBEnum value of character set used to encode a string - See RFC 2978
			     Where possible UTF-8 encoding (MIBEnum=106) should be used. A value
			     of zero indicates an unknown encoding. */
  SFLString src_user;
  u_int32_t dst_charset;
  SFLString dst_user;
} SFLExtended_user;

/* Extended URL data */

enum SFLExtended_url_direction {
  SFLEXTENDED_URL_SRC = 1, /* URL is associated with source address */
  SFLEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _SFLExtended_url {
  u_int32_t direction;   /* enum SFLExtended_url_direction */
  SFLString url;         /* URL associated with the packet flow.
			    Must be URL encoded */
  SFLString host;        /* The host field from the HTTP header */
} SFLExtended_url;

/* Extended MPLS data */

typedef struct _SFLLabelStack {
  u_int32_t depth;
  u_int32_t *stack; /* first entry is top of stack - see RFC 3032 for encoding */
} SFLLabelStack;

typedef struct _SFLExtended_mpls {
  SFLAddress nextHop;        /* Address of the next hop */
  SFLLabelStack in_stack;
  SFLLabelStack out_stack;
} SFLExtended_mpls;

/* Extended NAT data
   Packet header records report addresses as seen at the sFlowDataSource.
   The extended_nat structure reports on translated source and/or destination
   addesses for this packet. If an address was not translated it should
   be equal to that reported for the header. */

typedef struct _SFLExtended_nat {
  SFLAddress src;    /* Source address */
  SFLAddress dst;    /* Destination address */
} SFLExtended_nat;

/* additional Extended MPLS stucts */

typedef struct _SFLExtended_mpls_tunnel {
  SFLString tunnel_lsp_name;  /* Tunnel name */
  u_int32_t tunnel_id;        /* Tunnel ID */
  u_int32_t tunnel_cos;       /* Tunnel COS value */
} SFLExtended_mpls_tunnel;

typedef struct _SFLExtended_mpls_vc {
  SFLString vc_instance_name; /* VC instance name */
  u_int32_t vll_vc_id;        /* VLL/VC instance ID */
  u_int32_t vc_label_cos;     /* VC Label COS value */
} SFLExtended_mpls_vc;

/* Extended MPLS FEC
   - Definitions from MPLS-FTN-STD-MIB mplsFTNTable */

typedef struct _SFLExtended_mpls_FTN {
  SFLString mplsFTNDescr;
  u_int32_t mplsFTNMask;
} SFLExtended_mpls_FTN;

/* Extended MPLS LVP FEC
   - Definition from MPLS-LDP-STD-MIB mplsFecTable
   Note: mplsFecAddrType, mplsFecAddr information available
   from packet header */

typedef struct _SFLExtended_mpls_LDP_FEC {
  u_int32_t mplsFecAddrPrefixLength;
} SFLExtended_mpls_LDP_FEC;

/* Extended VLAN tunnel information
   Record outer VLAN encapsulations that have
   been stripped. extended_vlantunnel information
   should only be reported if all the following conditions are satisfied:
   1. The packet has nested vlan tags, AND
   2. The reporting device is VLAN aware, AND
   3. One or more VLAN tags have been stripped, either
   because they represent proprietary encapsulations, or
   because switch hardware automatically strips the outer VLAN
   encapsulation.
   Reporting extended_vlantunnel information is not a substitute for
   reporting extended_switch information. extended_switch data must
   always be reported to describe the ingress/egress VLAN information
   for the packet. The extended_vlantunnel information only applies to
   nested VLAN tags, and then only when one or more tags has been
   stripped. */

typedef SFLLabelStack SFLVlanStack;
typedef struct _SFLExtended_vlan_tunnel {
  SFLVlanStack stack;  /* List of stripped 802.1Q TPID/TCI layers. Each
			  TPID,TCI pair is represented as a single 32 bit
			  integer. Layers listed from outermost to
			  innermost. */
} SFLExtended_vlan_tunnel;

enum SFLFlow_type_tag {
  /* enterprise = 0, format = ... */
  SFLFLOW_HEADER    = 1,      /* Packet headers are sampled */
  SFLFLOW_ETHERNET  = 2,      /* MAC layer information */
  SFLFLOW_IPV4      = 3,      /* IP version 4 data */
  SFLFLOW_IPV6      = 4,      /* IP version 6 data */
  SFLFLOW_EX_SWITCH    = 1001,      /* Extended switch information */
  SFLFLOW_EX_ROUTER    = 1002,      /* Extended router information */
  SFLFLOW_EX_GATEWAY   = 1003,      /* Extended gateway router information */
  SFLFLOW_EX_USER      = 1004,      /* Extended TACAS/RADIUS user information */
  SFLFLOW_EX_URL       = 1005,      /* Extended URL information */
  SFLFLOW_EX_MPLS      = 1006,      /* Extended MPLS information */
  SFLFLOW_EX_NAT       = 1007,      /* Extended NAT information */
  SFLFLOW_EX_MPLS_TUNNEL  = 1008,   /* additional MPLS information */
  SFLFLOW_EX_MPLS_VC      = 1009,
  SFLFLOW_EX_MPLS_FTN     = 1010,
  SFLFLOW_EX_MPLS_LDP_FEC = 1011,
  SFLFLOW_EX_VLAN_TUNNEL  = 1012,   /* VLAN stack */
};

typedef union _SFLFlow_type {
  SFLSampled_header header;
  SFLSampled_ethernet ethernet;
  SFLSampled_ipv4 ipv4;
  SFLSampled_ipv6 ipv6;
  SFLExtended_switch sw;
  SFLExtended_router router;
  SFLExtended_gateway gateway;
  SFLExtended_user user;
  SFLExtended_url url;
  SFLExtended_mpls mpls;
  SFLExtended_nat nat;
  SFLExtended_mpls_tunnel mpls_tunnel;
  SFLExtended_mpls_vc mpls_vc;
  SFLExtended_mpls_FTN mpls_ftn;
  SFLExtended_mpls_LDP_FEC mpls_ldp_fec;
  SFLExtended_vlan_tunnel vlan_tunnel;
} SFLFlow_type;

typedef struct _SFLFlow_sample_element {
  struct _SFLFlow_sample_element *nxt;
  u_int32_t tag;  /* SFLFlow_type_tag */
  u_int32_t length;
  SFLFlow_type flowType;
} SFLFlow_sample_element;

enum SFL_sample_tag {
  SFLFLOW_SAMPLE = 1,              /* enterprise = 0 : format = 1 */
  SFLCOUNTERS_SAMPLE = 2,          /* enterprise = 0 : format = 2 */
  SFLFLOW_SAMPLE_EXPANDED = 3,     /* enterprise = 0 : format = 3 */
  SFLCOUNTERS_SAMPLE_EXPANDED = 4  /* enterprise = 0 : format = 4 */
};

/* Format of a single flow sample */

typedef struct _SFLFlow_sample {
  /* u_int32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* u_int32_t length; */
  u_int32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  u_int32_t source_id;            /* fsSourceId */
  u_int32_t sampling_rate;        /* fsPacketSamplingRate */
  u_int32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  u_int32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  u_int32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  u_int32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known.
				     Set most significant bit to indicate
				     multiple destination interfaces
				     (i.e. in case of broadcast or multicast)
				     and set lower order bits to indicate
				     number of destination interfaces.
				     Examples:
				     0x00000002  indicates ifIndex = 2
				     0x00000000  ifIndex unknown.
				     0x80000007  indicates a packet sent
				     to 7 interfaces.
				     0x80000000  indicates a packet sent to
				     an unknown number of
				     interfaces greater than 1.*/
  u_int32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample;

/* same thing, but the expanded version (for full 32-bit ifIndex numbers) */

typedef struct _SFLFlow_sample_expanded {
  /* u_int32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* u_int32_t length; */
  u_int32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  u_int32_t ds_class;             /* EXPANDED */
  u_int32_t ds_index;             /* EXPANDED */
  u_int32_t sampling_rate;        /* fsPacketSamplingRate */
  u_int32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  u_int32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  u_int32_t inputFormat;          /* EXPANDED */
  u_int32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  u_int32_t outputFormat;         /* EXPANDED */
  u_int32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known. */
  u_int32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample_expanded;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _SFLIf_counters {
  u_int32_t ifIndex;
  u_int32_t ifType;
  u_int64_t ifSpeed;
  u_int32_t ifDirection;        /* Derived from MAU MIB (RFC 2668)
				   0 = unknown, 1 = full-duplex,
				   2 = half-duplex, 3 = in, 4 = out */
  u_int32_t ifStatus;           /* bit field with the following bits assigned:
				   bit 0 = ifAdminStatus (0 = down, 1 = up)
				   bit 1 = ifOperStatus (0 = down, 1 = up) */
  u_int64_t ifInOctets;
  u_int32_t ifInUcastPkts;
  u_int32_t ifInMulticastPkts;
  u_int32_t ifInBroadcastPkts;
  u_int32_t ifInDiscards;
  u_int32_t ifInErrors;
  u_int32_t ifInUnknownProtos;
  u_int64_t ifOutOctets;
  u_int32_t ifOutUcastPkts;
  u_int32_t ifOutMulticastPkts;
  u_int32_t ifOutBroadcastPkts;
  u_int32_t ifOutDiscards;
  u_int32_t ifOutErrors;
  u_int32_t ifPromiscuousMode;
} SFLIf_counters;

/* Ethernet interface counters - see RFC 2358 */
typedef struct _SFLEthernet_counters {
  u_int32_t dot3StatsAlignmentErrors;
  u_int32_t dot3StatsFCSErrors;
  u_int32_t dot3StatsSingleCollisionFrames;
  u_int32_t dot3StatsMultipleCollisionFrames;
  u_int32_t dot3StatsSQETestErrors;
  u_int32_t dot3StatsDeferredTransmissions;
  u_int32_t dot3StatsLateCollisions;
  u_int32_t dot3StatsExcessiveCollisions;
  u_int32_t dot3StatsInternalMacTransmitErrors;
  u_int32_t dot3StatsCarrierSenseErrors;
  u_int32_t dot3StatsFrameTooLongs;
  u_int32_t dot3StatsInternalMacReceiveErrors;
  u_int32_t dot3StatsSymbolErrors;
} SFLEthernet_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _SFLTokenring_counters {
  u_int32_t dot5StatsLineErrors;
  u_int32_t dot5StatsBurstErrors;
  u_int32_t dot5StatsACErrors;
  u_int32_t dot5StatsAbortTransErrors;
  u_int32_t dot5StatsInternalErrors;
  u_int32_t dot5StatsLostFrameErrors;
  u_int32_t dot5StatsReceiveCongestions;
  u_int32_t dot5StatsFrameCopiedErrors;
  u_int32_t dot5StatsTokenErrors;
  u_int32_t dot5StatsSoftErrors;
  u_int32_t dot5StatsHardErrors;
  u_int32_t dot5StatsSignalLoss;
  u_int32_t dot5StatsTransmitBeacons;
  u_int32_t dot5StatsRecoverys;
  u_int32_t dot5StatsLobeWires;
  u_int32_t dot5StatsRemoves;
  u_int32_t dot5StatsSingles;
  u_int32_t dot5StatsFreqErrors;
} SFLTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _SFLVg_counters {
  u_int32_t dot12InHighPriorityFrames;
  u_int64_t dot12InHighPriorityOctets;
  u_int32_t dot12InNormPriorityFrames;
  u_int64_t dot12InNormPriorityOctets;
  u_int32_t dot12InIPMErrors;
  u_int32_t dot12InOversizeFrameErrors;
  u_int32_t dot12InDataErrors;
  u_int32_t dot12InNullAddressedFrames;
  u_int32_t dot12OutHighPriorityFrames;
  u_int64_t dot12OutHighPriorityOctets;
  u_int32_t dot12TransitionIntoTrainings;
  u_int64_t dot12HCInHighPriorityOctets;
  u_int64_t dot12HCInNormPriorityOctets;
  u_int64_t dot12HCOutHighPriorityOctets;
} SFLVg_counters;

typedef struct _SFLVlan_counters {
  u_int32_t vlan_id;
  u_int64_t octets;
  u_int32_t ucastPkts;
  u_int32_t multicastPkts;
  u_int32_t broadcastPkts;
  u_int32_t discards;
} SFLVlan_counters;

/* Counters data */

enum SFLCounters_type_tag {
  /* enterprise = 0, format = ... */
  SFLCOUNTERS_GENERIC      = 1,
  SFLCOUNTERS_ETHERNET     = 2,
  SFLCOUNTERS_TOKENRING    = 3,
  SFLCOUNTERS_VG           = 4,
  SFLCOUNTERS_VLAN         = 5
};

typedef union _SFLCounters_type {
  SFLIf_counters generic;
  SFLEthernet_counters ethernet;
  SFLTokenring_counters tokenring;
  SFLVg_counters vg;
  SFLVlan_counters vlan;
} SFLCounters_type;

typedef struct _SFLCounters_sample_element {
  struct _SFLCounters_sample_element *nxt; /* linked list */
  u_int32_t tag; /* SFLCounters_type_tag */
  u_int32_t length;
  SFLCounters_type counterBlock;
} SFLCounters_sample_element;

typedef struct _SFLCounters_sample {
  /* u_int32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* u_int32_t length; */
  u_int32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  u_int32_t source_id;          /* fsSourceId */
  u_int32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample;

/* same thing, but the expanded version, so ds_index can be a full 32 bits */
typedef struct _SFLCounters_sample_expanded {
  /* u_int32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* u_int32_t length; */
  u_int32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  u_int32_t ds_class;           /* EXPANDED */
  u_int32_t ds_index;           /* EXPANDED */
  u_int32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample_expanded;

#define SFLADD_ELEMENT(_sm, _el) do { (_el)->nxt = (_sm)->elements; (_sm)->elements = (_el); } while(0)

/* Format of a sample datagram */

enum SFLDatagram_version {
  SFLDATAGRAM_VERSION2 = 2,
  SFLDATAGRAM_VERSION4 = 4,
  SFLDATAGRAM_VERSION5 = 5
};

typedef struct _SFLSample_datagram_hdr {
  u_int32_t datagram_version;      /* (enum SFLDatagram_version) = VERSION5 = 5 */
  SFLAddress agent_address;        /* IP address of sampling agent */
  u_int32_t sub_agent_id;          /* Used to distinguishing between datagram
                                      streams from separate agent sub entities
                                      within an device. */
  u_int32_t sequence_number;       /* Incremented with each sample datagram
				      generated */
  u_int32_t uptime;                /* Current time (in milliseconds since device
				      last booted). Should be set as close to
				      datagram transmission time as possible.*/
  u_int32_t num_records;           /* Number of tag-len-val flow/counter records to follow */
} SFLSample_datagram_hdr;

#define SFL_MAX_DATAGRAM_SIZE 1500
#define SFL_MIN_DATAGRAM_SIZE 200
#define SFL_DEFAULT_DATAGRAM_SIZE 1400

#define SFL_DATA_PAD 400

#define YES 1
#define NO  0



enum INMAddress_type {
  INMADDRESSTYPE_IP_V4 = 1,
  INMADDRESSTYPE_IP_V6 = 2
};

typedef union _INMAddress_value {
  struct in_addr ip_v4;
  struct in6_addr ip_v6;
} INMAddress_value;

typedef struct _INMAddress {
  u_int32_t type;           /* enum INMAddress_type */
  INMAddress_value address;
} INMAddress;

/* Packet header data */

#define INM_MAX_HEADER_SIZE 256   /* The maximum sampled header size. */
#define INM_DEFAULT_HEADER_SIZE 128
#define INM_DEFAULT_COLLECTOR_PORT 6343
#define INM_DEFAULT_SAMPLING_RATE 400

/* The header protocol describes the format of the sampled header */
enum INMHeader_protocol {
  INMHEADER_ETHERNET_ISO8023     = 1,
  INMHEADER_ISO88024_TOKENBUS    = 2,
  INMHEADER_ISO88025_TOKENRING   = 3,
  INMHEADER_FDDI                 = 4,
  INMHEADER_FRAME_RELAY          = 5,
  INMHEADER_X25                  = 6,
  INMHEADER_PPP                  = 7,
  INMHEADER_SMDS                 = 8,
  INMHEADER_AAL5                 = 9,
  INMHEADER_AAL5_IP              = 10, /* e.g. Cisco AAL5 mux */
  INMHEADER_IPv4                 = 11,
  INMHEADER_IPv6                 = 12
};

typedef struct _INMSampled_header {
  u_int32_t header_protocol;            /* (enum INMHeader_protocol) */
  u_int32_t frame_length;               /* Original length of packet before sampling */
  u_int32_t header_length;              /* length of sampled header bytes to follow */
  u_int8_t header[INM_MAX_HEADER_SIZE]; /* Header bytes */
} INMSampled_header;

/* Packet IP version 4 data */

typedef struct _INMSampled_ipv4 {
  u_int32_t length;      /* The length of the IP packet
			    excluding lower layer encapsulations */
  u_int32_t protocol;    /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  struct in_addr src_ip; /* Source IP Address */
  struct in_addr dst_ip; /* Destination IP Address */
  u_int32_t src_port;    /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;    /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags;   /* TCP flags */
  u_int32_t tos;         /* IP type of service */
} INMSampled_ipv4;

/* Packet IP version 6 data */
typedef struct _INMSampled_ipv6 {
  u_int32_t length;       /* The length of the IP packet
			     excluding lower layer encapsulations */
  u_int32_t protocol;     /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  struct in6_addr src_ip; /* Source IP Address */
  struct in6_addr dst_ip; /* Destination IP Address */
  u_int32_t src_port;     /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;     /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags;    /* TCP flags */
  u_int32_t tos;          /* IP type of service */
} INMSampled_ipv6;

/* Packet data */

enum INMPacket_information_type {
  INMPACKETTYPE_HEADER  = 1,      /* Packet headers are sampled */
  INMPACKETTYPE_IPV4    = 2,      /* IP version 4 data */
  INMPACKETTYPE_IPV6    = 3       /* IP version 4 data */
};

typedef union _INMPacket_data_type {
  INMSampled_header header;
  INMSampled_ipv4 ipv4;
  INMSampled_ipv6 ipv6;
} INMPacket_data_type;

/* Extended data types */

/* Extended switch data */

typedef struct _INMExtended_switch {
  u_int32_t src_vlan;       /* The 802.1Q VLAN id of incomming frame */
  u_int32_t src_priority;   /* The 802.1p priority */
  u_int32_t dst_vlan;       /* The 802.1Q VLAN id of outgoing frame */
  u_int32_t dst_priority;   /* The 802.1p priority */
} INMExtended_switch;

/* Extended router data */

typedef struct _INMExtended_router {
  INMAddress nexthop;               /* IP address of next hop router */
  u_int32_t src_mask;               /* Source address prefix mask bits */
  u_int32_t dst_mask;               /* Destination address prefix mask bits */
} INMExtended_router;

/* Extended gateway data */

enum INMExtended_as_path_segment_type {
  INMEXTENDED_AS_SET = 1,      /* Unordered set of ASs */
  INMEXTENDED_AS_SEQUENCE = 2  /* Ordered sequence of ASs */
};

typedef struct _INMExtended_as_path_segment {
  u_int32_t type;   /* enum INMExtended_as_path_segment_type */
  u_int32_t length; /* number of AS numbers in set/sequence */
  union {
    u_int32_t *set;
    u_int32_t *seq;
  } as;
} INMExtended_as_path_segment;

/* note: the INMExtended_gateway structure has changed between v2 and v4.
   Here is the old version first... */

typedef struct _INMExtended_gateway_v2 {
  u_int32_t as;                             /* AS number for this gateway */
  u_int32_t src_as;                         /* AS number of source (origin) */
  u_int32_t src_peer_as;                    /* AS number of source peer */
  u_int32_t dst_as_path_length;             /* number of AS numbers in path */
  u_int32_t *dst_as_path;
} INMExtended_gateway_v2;

/* now here is the new version... */

typedef struct _INMExtended_gateway_v4 {
  u_int32_t as;                             /* AS number for this gateway */
  u_int32_t src_as;                         /* AS number of source (origin) */
  u_int32_t src_peer_as;                    /* AS number of source peer */
  u_int32_t dst_as_path_segments;           /* number of segments in path */
  INMExtended_as_path_segment *dst_as_path; /* list of seqs or sets */
  u_int32_t communities_length;             /* number of communities */
  u_int32_t *communities;                   /* set of communities */
  u_int32_t localpref;                      /* LocalPref associated with this route */
} INMExtended_gateway_v4;

/* Extended user data */
typedef struct _INMExtended_user {
  u_int32_t src_user_len;
  char *src_user;
  u_int32_t dst_user_len;
  char *dst_user;
} INMExtended_user;
enum INMExtended_url_direction {
  INMEXTENDED_URL_SRC = 1, /* URL is associated with source address */
  INMEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _INMExtended_url {
  u_int32_t direction; /* enum INMExtended_url_direction */
  u_int32_t url_len;
  char *url;
} INMExtended_url;

/* Extended data */

enum INMExtended_information_type {
  INMEXTENDED_SWITCH    = 1,      /* Extended switch information */
  INMEXTENDED_ROUTER    = 2,      /* Extended router information */
  INMEXTENDED_GATEWAY   = 3,      /* Extended gateway router information */
  INMEXTENDED_USER      = 4,      /* Extended TACAS/RADIUS user information */
  INMEXTENDED_URL       = 5       /* Extended URL information */
};

/* Format of a single sample */

typedef struct _INMFlow_sample {
  u_int32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  u_int32_t source_id;            /* fsSourceId */
  u_int32_t sampling_rate;        /* fsPacketSamplingRate */
  u_int32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  u_int32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  u_int32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  u_int32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known.
				     Set most significant bit to indicate
				     multiple destination interfaces
				     (i.e. in case of broadcast or multicast)
				     and set lower order bits to indicate
				     number of destination interfaces.
				     Examples:
				     0x00000002  indicates ifIndex = 2
				     0x00000000  ifIndex unknown.
				     0x80000007  indicates a packet sent
				     to 7 interfaces.
				     0x80000000  indicates a packet sent to
				     an unknown number of
				     interfaces greater than 1.*/
  u_int32_t packet_data_tag;       /* enum INMPacket_information_type */
  INMPacket_data_type packet_data; /* Information about sampled packet */

  /* in the sFlow packet spec the next field is the number of extended objects
     followed by the data for each one (tagged with the type).  Here we just
     provide space for each one, and flags to enable them.  The correct format
     is then put together by the serialization code */
  int gotSwitch;
  INMExtended_switch switchDevice;
  int gotRouter;
  INMExtended_router router;
  int gotGateway;
  union {
    INMExtended_gateway_v2 v2;  /* make the version explicit so that there is */
    INMExtended_gateway_v4 v4;  /* less danger of mistakes when upgrading code */
  } gateway;
  int gotUser;
  INMExtended_user user;
  int gotUrl;
  INMExtended_url url;
} INMFlow_sample;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _INMIf_counters {
  u_int32_t ifIndex;
  u_int32_t ifType;
  u_int64_t ifSpeed;
  u_int32_t ifDirection;        /* Derived from MAU MIB (RFC 2239)
				   0 = unknown, 1 = full-duplex,
				   2 = half-duplex, 3 = in, 4 = out */
  u_int32_t ifStatus;           /* bit field with the following bits assigned:
				   bit 0 = ifAdminStatus (0 = down, 1 = up)
				   bit 1 = ifOperStatus (0 = down, 1 = up) */
  u_int64_t ifInOctets;
  u_int32_t ifInUcastPkts;
  u_int32_t ifInMulticastPkts;
  u_int32_t ifInBroadcastPkts;
  u_int32_t ifInDiscards;
  u_int32_t ifInErrors;
  u_int32_t ifInUnknownProtos;
  u_int64_t ifOutOctets;
  u_int32_t ifOutUcastPkts;
  u_int32_t ifOutMulticastPkts;
  u_int32_t ifOutBroadcastPkts;
  u_int32_t ifOutDiscards;
  u_int32_t ifOutErrors;
  u_int32_t ifPromiscuousMode;
} INMIf_counters;

/* Ethernet interface counters - see RFC 2358 */
typedef struct _INMEthernet_specific_counters {
  u_int32_t dot3StatsAlignmentErrors;
  u_int32_t dot3StatsFCSErrors;
  u_int32_t dot3StatsSingleCollisionFrames;
  u_int32_t dot3StatsMultipleCollisionFrames;
  u_int32_t dot3StatsSQETestErrors;
  u_int32_t dot3StatsDeferredTransmissions;
  u_int32_t dot3StatsLateCollisions;
  u_int32_t dot3StatsExcessiveCollisions;
  u_int32_t dot3StatsInternalMacTransmitErrors;
  u_int32_t dot3StatsCarrierSenseErrors;
  u_int32_t dot3StatsFrameTooLongs;
  u_int32_t dot3StatsInternalMacReceiveErrors;
  u_int32_t dot3StatsSymbolErrors;
} INMEthernet_specific_counters;

typedef struct _INMEthernet_counters {
  INMIf_counters generic;
  INMEthernet_specific_counters ethernet;
} INMEthernet_counters;

/* FDDI interface counters - see RFC 1512 */
typedef struct _INMFddi_counters {
  INMIf_counters generic;
} INMFddi_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _INMTokenring_specific_counters {
  u_int32_t dot5StatsLineErrors;
  u_int32_t dot5StatsBurstErrors;
  u_int32_t dot5StatsACErrors;
  u_int32_t dot5StatsAbortTransErrors;
  u_int32_t dot5StatsInternalErrors;
  u_int32_t dot5StatsLostFrameErrors;
  u_int32_t dot5StatsReceiveCongestions;
  u_int32_t dot5StatsFrameCopiedErrors;
  u_int32_t dot5StatsTokenErrors;
  u_int32_t dot5StatsSoftErrors;
  u_int32_t dot5StatsHardErrors;
  u_int32_t dot5StatsSignalLoss;
  u_int32_t dot5StatsTransmitBeacons;
  u_int32_t dot5StatsRecoverys;
  u_int32_t dot5StatsLobeWires;
  u_int32_t dot5StatsRemoves;
  u_int32_t dot5StatsSingles;
  u_int32_t dot5StatsFreqErrors;
} INMTokenring_specific_counters;

typedef struct _INMTokenring_counters {
  INMIf_counters generic;
  INMTokenring_specific_counters tokenring;
} INMTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _INMVg_specific_counters {
  u_int32_t dot12InHighPriorityFrames;
  u_int64_t dot12InHighPriorityOctets;
  u_int32_t dot12InNormPriorityFrames;
  u_int64_t dot12InNormPriorityOctets;
  u_int32_t dot12InIPMErrors;
  u_int32_t dot12InOversizeFrameErrors;
  u_int32_t dot12InDataErrors;
  u_int32_t dot12InNullAddressedFrames;
  u_int32_t dot12OutHighPriorityFrames;
  u_int64_t dot12OutHighPriorityOctets;
  u_int32_t dot12TransitionIntoTrainings;
  u_int64_t dot12HCInHighPriorityOctets;
  u_int64_t dot12HCInNormPriorityOctets;
  u_int64_t dot12HCOutHighPriorityOctets;
} INMVg_specific_counters;

typedef struct _INMVg_counters {
  INMIf_counters generic;
  INMVg_specific_counters vg;
} INMVg_counters;

/* WAN counters */

typedef struct _INMWan_counters {
  INMIf_counters generic;
} INMWan_counters;

typedef struct _INMVlan_counters {
  u_int32_t vlan_id;
  u_int64_t octets;
  u_int32_t ucastPkts;
  u_int32_t multicastPkts;
  u_int32_t broadcastPkts;
  u_int32_t discards;
} INMVlan_counters;

/* Counters data */

enum INMCounters_version {
  INMCOUNTERSVERSION_GENERIC      = 1,
  INMCOUNTERSVERSION_ETHERNET     = 2,
  INMCOUNTERSVERSION_TOKENRING    = 3,
  INMCOUNTERSVERSION_FDDI         = 4,
  INMCOUNTERSVERSION_VG           = 5,
  INMCOUNTERSVERSION_WAN          = 6,
  INMCOUNTERSVERSION_VLAN         = 7
};

typedef union _INMCounters_type {
  INMIf_counters generic;
  INMEthernet_counters ethernet;
  INMTokenring_counters tokenring;
  INMFddi_counters fddi;
  INMVg_counters vg;
  INMWan_counters wan;
  INMVlan_counters vlan;
} INMCounters_type;

typedef struct _INMCounters_sample_hdr {
  u_int32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  u_int32_t source_id;          /* fsSourceId */
  u_int32_t sampling_interval;  /* fsCounterSamplingInterval */
} INMCounters_sample_hdr;

typedef struct _INMCounters_sample {
  INMCounters_sample_hdr hdr;
  u_int32_t counters_type_tag;  /* Enum INMCounters_version */
  INMCounters_type counters;    /* Counter set for this interface type */
} INMCounters_sample;

enum INMSample_types {
  FLOWSAMPLE  = 1,
  COUNTERSSAMPLE = 2
};

typedef union _INMSample_type {
  INMFlow_sample flowsample;
  INMCounters_sample counterssample;
} INMSample_type;

/* Format of a sample datagram */

enum INMDatagram_version {
  INMDATAGRAM_VERSION2 = 2,
  INMDATAGRAM_VERSION4 = 4
};

typedef struct _INMSample_datagram_hdr {
  u_int32_t datagram_version;      /* (enum INMDatagram_version) = VERSION4 */
  INMAddress agent_address;        /* IP address of sampling agent */
  u_int32_t sequence_number;       /* Incremented with each sample datagram
				      generated */
  u_int32_t uptime;                /* Current time (in milliseconds since device
				      last booted). Should be set as close to
				      datagram transmission time as possible.*/
  u_int32_t num_samples;           /* Number of flow and counters samples to follow */
} INMSample_datagram_hdr;

#define INM_MAX_DATAGRAM_SIZE 1500
#define INM_MIN_DATAGRAM_SIZE 200
#define INM_DEFAULT_DATAGRAM_SIZE 1400

#define INM_DATA_PAD 400




/* define my own IP header struct - to ease portability */
struct myiphdr
{
  u_int8_t version_and_headerLen;
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
};

/* same for tcp */
struct mytcphdr
{
  u_int16_t th_sport;		/* source port */
  u_int16_t th_dport;		/* destination port */
  u_int32_t th_seq;		/* sequence number */
  u_int32_t th_ack;		/* acknowledgement number */
  u_int8_t th_off_and_unused;
  u_int8_t th_flags;
  u_int16_t th_win;		/* window */
  u_int16_t th_sum;		/* checksum */
  u_int16_t th_urp;		/* urgent pointer */
};

/* and UDP */
struct myudphdr {
  u_int16_t uh_sport;           /* source port */
  u_int16_t uh_dport;           /* destination port */
  u_int16_t uh_ulen;            /* udp length */
  u_int16_t uh_sum;             /* udp checksum */
};

/* and ICMP */
struct myicmphdr
{
  u_int8_t type;		/* message type */
  u_int8_t code;		/* type sub-code */
  /* ignore the rest */
};

#ifdef SPOOFSOURCE
#define SPOOFSOURCE_SENDPACKET_SIZE 2000
struct mySendPacket {
  struct myiphdr ip;
  struct myudphdr udp;
  u_char data[SPOOFSOURCE_SENDPACKET_SIZE];
};
#endif

typedef struct _SFConfig {
  /* sflow options */
  u_int16_t sFlowInputPort;
  /* netflow options */
  u_int16_t netFlowOutputPort;
  struct in_addr netFlowOutputIP;
  int netFlowOutputSocket;
  u_int16_t netFlowPeerAS;
  int disableNetFlowScale;
  /* tcpdump options */
  int tcpdumpFormat;
  u_int32_t tcpdumpHdrPad;
  u_char zeroPad[100];

#ifdef SPOOFSOURCE
  int spoofSource;
  u_int16_t ipid;
  struct mySendPacket sendPkt;
  u_int32_t packetLen;
#endif
} SFConfig;

/* make the options structure global to the program */

typedef struct _SFSample {
  struct in_addr sourceIP;
  SFLAddress agent_addr;
  u_int32_t agentSubId;

  /* the raw pdu */
  u_char *rawSample;
  u_int32_t rawSampleLen;
  u_char *endp;

  /* decode cursor */
#if 0
  u_int32_t *datap;
#else
  u_char *datap;
#endif

  u_int32_t datagramVersion;
  u_int32_t sampleType;
  u_int32_t ds_class;
  u_int32_t ds_index;

  /* interface info */
  u_int32_t ifIndex;
  u_int32_t networkType;
  u_int64_t ifSpeed;
  u_int32_t ifDirection;
  u_int32_t ifStatus;

  /* sample stream info */
  u_int32_t sysUpTime;
  u_int32_t sequenceNo;
  u_int32_t sampledPacketSize;
  u_int32_t samplesGenerated;
  u_int32_t meanSkipCount;
  u_int32_t samplePool;
  u_int32_t dropEvents;

  /* the sampled header */
  u_int32_t packet_data_tag;
  u_int32_t headerProtocol;
  u_char *header;
  int headerLen;
  u_int32_t stripped;

  /* header decode */
  int gotIPV4;
  int offsetToIPV4;
  struct in_addr dcd_srcIP;
  struct in_addr dcd_dstIP;
  u_int32_t dcd_ipProtocol;
  u_int32_t dcd_ipTos;
  u_int32_t dcd_ipTTL;
  u_int32_t dcd_sport;
  u_int32_t dcd_dport;
  u_int32_t dcd_tcpFlags;
  u_int32_t ip_fragmentOffset;
  u_int32_t udp_pduLen;

  /* ports */
  u_int32_t inputPortFormat;
  u_int32_t outputPortFormat;
  u_int32_t inputPort;
  u_int32_t outputPort;

  /* ethernet */
  u_int32_t eth_type;
  u_int32_t eth_len;
  u_char eth_src[8];
  u_char eth_dst[8];

  /* vlan */
  u_int32_t in_vlan;
  u_int32_t in_priority;
  u_int32_t internalPriority;
  u_int32_t out_vlan;
  u_int32_t out_priority;

  /* extended data fields */
  u_int32_t num_extended;
  u_int32_t extended_data_tag;
#define SASAMPLE_EXTENDED_DATA_SWITCH 1
#define SASAMPLE_EXTENDED_DATA_ROUTER 4
#define SASAMPLE_EXTENDED_DATA_GATEWAY 8
#define SASAMPLE_EXTENDED_DATA_USER 16
#define SASAMPLE_EXTENDED_DATA_URL 32
#define SASAMPLE_EXTENDED_DATA_MPLS 64
#define SASAMPLE_EXTENDED_DATA_NAT 128
#define SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL 256
#define SASAMPLE_EXTENDED_DATA_MPLS_VC 512
#define SASAMPLE_EXTENDED_DATA_MPLS_FTN 1024
#define SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC 2048
#define SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL 4096

  /* IP forwarding info */
  SFLAddress nextHop;
  u_int32_t srcMask;
  u_int32_t dstMask;

  /* BGP info */
  SFLAddress bgp_nextHop;
  u_int32_t my_as;
  u_int32_t src_as;
  u_int32_t src_peer_as;
  u_int32_t dst_as_path_len;
  u_int32_t *dst_as_path;
  /* note: version 4 dst as path segments just get printed, not stored here, however
   * the dst_peer and dst_as are filled in, since those are used for netflow encoding
   */
  u_int32_t dst_peer_as;
  u_int32_t dst_as;

  u_int32_t communities_len;
  u_int32_t *communities;
  u_int32_t localpref;

  /* user id */
#define SA_MAX_EXTENDED_USER_LEN 200
  u_int32_t src_user_charset;
  u_int32_t src_user_len;
  char src_user[SA_MAX_EXTENDED_USER_LEN+1];
  u_int32_t dst_user_charset;
  u_int32_t dst_user_len;
  char dst_user[SA_MAX_EXTENDED_USER_LEN+1];

  /* url */
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
  u_int32_t url_direction;
  u_int32_t url_len;
  char url[SA_MAX_EXTENDED_URL_LEN+1];
  u_int32_t host_len;
  char host[SA_MAX_EXTENDED_HOST_LEN+1];

  /* mpls */
  SFLAddress mpls_nextHop;

  /* nat */
  SFLAddress nat_src;
  SFLAddress nat_dst;

  /* counter blocks */
  u_int32_t statsSamplingInterval;
  u_int32_t counterBlockVersion;
} SFSample;

/* ********************************* */

#ifdef DEBUG_FLOWS
#define SFLOW_DEBUG(a) (1)
#else
#define SFLOW_DEBUG(a) ((a < myGlobals.numDevices) && myGlobals.device[a].sflowGlobals && myGlobals.device[a].sflowGlobals->sflowDebug)
#endif
/* ********************************* */

/* Forward */
static int setsFlowInSocket(int);
static void setPluginStatus(char * status);
static int initsFlowFunct(void);
static void termsFlowFunct(u_char termNtop /* 0=term plugin, 1=term ntop */);
static void termsFlowDevice(int deviceId);
static void initsFlowDevice(int deviceId);
#ifdef DEBUG_FLOWS
static void handlesFlowPacket(u_char *_deviceId,
			      const struct pcap_pkthdr *h,
			      const u_char *p);
#endif
static void handlesFlowHTTPrequest(char* url);
static void printsFlowStatisticsRcvd(int deviceId);
static void printsFlowConfiguration(int deviceId);
static int createsFlowDevice(int sflowDeviceId);
static int mapsFlowDeviceToNtopDevice(int deviceId);

/* ****************************** */

u_char static pluginActive = 0;

static PluginInfo sflowPluginInfo[] = {
  {
    VERSION, /* current ntop version */
    "sFlow",
    "This plugin is used to setup, activate and deactivate ntop's sFlow support.<br>"
    "<b>ntop</b> can both collect and receive <A HREF=http://www.sflow.org/>sFlow</A> data. "
    "Note that ntop.org is a member of the <A HREF=http://www.sflow.org/organization/>sFlow consortium</A>.<br>"
    "<i>Received flow data is reported as a separate 'NIC' in the regular <b>ntop</b> "
    "reports.<br><em>Remember to <A HREF=/switch.html>switch</A> the reporting NIC.</em>",
    "3.0", /* version */
    "<A HREF=\"http://luca.ntop.org/\" alt=\"Luca's home page\">L.Deri</A>",
    "sFlow", /* http://<host>:<port>/plugins/sFlow */
    0, /* Active by default */
    ViewConfigure,
    1, /* Inactive setup */
    initsFlowFunct, /* InitFunc */
    termsFlowFunct, /* TermFunc */
#ifdef DEBUG_FLOWS
    handlesFlowPacket,
#else
    NULL, /* PluginFunc */
#endif
    handlesFlowHTTPrequest,
    NULL, /* no host creation/deletion handle */
#ifdef DEBUG_FLOWS
    "udp and (port 6343 or port 9002)",
#else
    NULL, /* no capture */
#endif
    NULL, /* no status */
    NULL  /* no extra pages */
  }
};

/* ****************************** */

static char* sfValue(int deviceId, char *name, int appendDeviceId) {
  static char buf[64];

  if(appendDeviceId) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "sflow.%d.%s",
		  myGlobals.device[deviceId].sflowGlobals->sflowDeviceId, name);
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "sflow.%s", name);
  }

#ifdef DEBUG
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "SFLOW: sfValue=%s", buf);
#endif

  return(buf);
}

/* ************************************** */

static int setsFlowInSocket(int deviceId) {
  struct sockaddr_in sockIn;
  int sockopt = 1;

  if(myGlobals.device[deviceId].sflowGlobals->sflowInSocket > 0) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "SFLOW: Collector terminated");
	closeNwSocket(&myGlobals.device[deviceId].sflowGlobals->sflowInSocket);
	shutdown(myGlobals.device[deviceId].sflowGlobals->sflowInSocket, SHUT_RDWR);
  }

  if(myGlobals.device[deviceId].sflowGlobals->sflowInPort > 0) {
    errno = 0;
    myGlobals.device[deviceId].sflowGlobals->sflowInSocket = socket(AF_INET, SOCK_DGRAM, 0);

    if((myGlobals.device[deviceId].sflowGlobals->sflowInSocket <= 0)
       || (errno != 0) ) {
      traceEvent(CONST_TRACE_INFO, "SFLOW: Unable to create a socket - returned %d, error is '%s'(%d)",
		 myGlobals.device[deviceId].sflowGlobals->sflowInSocket, strerror(errno), errno);
      setPluginStatus("Disabled - Unable to create listening socket.");
      return(-1);
    }

    traceEvent(CONST_TRACE_INFO, "SFLOW: Created a UDP socket (%d)",
	       myGlobals.device[deviceId].sflowGlobals->sflowInSocket);

    setsockopt(myGlobals.device[deviceId].sflowGlobals->sflowInSocket,
	       SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    sockIn.sin_family            = AF_INET;
    sockIn.sin_port              =(int)htons(myGlobals.device[deviceId].sflowGlobals->sflowInPort);
    sockIn.sin_addr.s_addr       = INADDR_ANY;

    if((bind(myGlobals.device[deviceId].sflowGlobals->sflowInSocket,
	     (struct sockaddr *)&sockIn, sizeof(sockIn)) < 0)
       ) {
      traceEvent(CONST_TRACE_ERROR, "SFLOW: Collector port %d already in use",
		 myGlobals.device[deviceId].sflowGlobals->sflowInPort);
	closeNwSocket(&myGlobals.device[deviceId].sflowGlobals->sflowInSocket);
	shutdown(myGlobals.device[deviceId].sflowGlobals->sflowInSocket, SHUT_RDWR);
      myGlobals.device[deviceId].sflowGlobals->sflowInSocket = 0;
      return(0);
    }

    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "SFLOW: Collector listening on port %d",
	       myGlobals.device[deviceId].sflowGlobals->sflowInPort);
  }

  if((myGlobals.device[deviceId].sflowGlobals->sflowInPort != 0)
     && (!myGlobals.device[deviceId].sflowGlobals->threadActive)) {
    /* This plugin works only with threads */
    createThread(&myGlobals.device[deviceId].sflowGlobals->sflowThread,
		 sflowMainLoop, (void*)((long)deviceId));
    traceEvent(CONST_TRACE_INFO, "THREADMGMT: SFLOW: Started thread (%lu) for receiving flows on port %d",
	       (long)myGlobals.device[deviceId].sflowGlobals->sflowThread,
	       myGlobals.device[deviceId].sflowGlobals->sflowInPort);
  }
  maximize_socket_buffer(myGlobals.device[deviceId].sflowGlobals->sflowInSocket, SO_RCVBUF);

  return(0);
}

/* *************************** */

static void updateSflowInterfaceCounters(int deviceId, IfCounters *ifName) {
  IfCounters *counter, *prev_counter, *next;

  if(ifName == NULL) 
    return;
  else
    prev_counter = NULL, counter = myGlobals.device[deviceId].sflowGlobals->ifCounters;

  while(counter) {
    if(counter->ifIndex == ifName->ifIndex)
      break;
    else if(counter->ifIndex > ifName->ifIndex) {
      counter = NULL;
      break;
    } else {
      prev_counter = counter;
      counter = counter->next;
    }
  }

  if(counter == NULL) {
    counter = (IfCounters*)malloc(sizeof(IfCounters));
    if(!counter) return; /* Not enough memory */

    if(prev_counter == NULL) {
      counter->next = NULL;
      myGlobals.device[deviceId].sflowGlobals->ifCounters = counter;
    } else {
      counter->next = prev_counter->next;
      prev_counter->next = counter;
    }
  }

  /* Note: the ->next pointer is not overwritten */
  next = counter->next;
  memcpy(counter, ifName, sizeof(IfCounters));
  counter->next = next;
  myGlobals.device[deviceId].sflowGlobals->numsFlowCounterUpdates++;
}

/* =============================================================== */

static void handleSflowSample(SFSample *sample, int deviceId) {
  struct pcap_pkthdr pkthdr;
  bool oldVal = myGlobals.runningPref.disableMutexExtraInfo;

  pkthdr.ts.tv_sec = time(NULL);
  pkthdr.ts.tv_usec = 0;
  pkthdr.caplen = sample->headerLen;
  pkthdr.len = sample->sampledPacketSize*sample->meanSkipCount /* Scale data */;

  /* Needed to avoid silly (for sFlow) warning */
  myGlobals.runningPref.disableMutexExtraInfo = 1;
  queuePacket((u_char*)((long)deviceId), &pkthdr, sample->header); /* Pass the packet to ntop */
  myGlobals.runningPref.disableMutexExtraInfo = oldVal;
  myGlobals.device[deviceId].samplingRate = sample->meanSkipCount;
  myGlobals.device[deviceId].sflowGlobals->numsFlowsSamples++;

  /* Save flows on disk (debug) */
#ifdef DEBUG_FLOWS
  if(1) {
#define TCPDUMP_MAGIC 0xa1b2c3d4  /* from libpcap-0.5: savefile.c */
#define DLT_EN10MB	1	  /* from libpcap-0.5: net/bpf.h */
#define PCAP_VERSION_MAJOR 2      /* from libpcap-0.5: pcap.h */
#define PCAP_VERSION_MINOR 4      /* from libpcap-0.5: pcap.h */

    static FILE *fd = NULL;
    char buf[2048];
    int bytes = 0;
    struct pcap_file_header hdr;

    if(fd == NULL) {
      fd = fopen("/tmp/sflowpackets.pcap", "w+");

      if(fd) {
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = TCPDUMP_MAGIC;
	hdr.version_major = PCAP_VERSION_MAJOR;
	hdr.version_minor = PCAP_VERSION_MINOR;
	hdr.thiszone = 0;
	hdr.snaplen = 128;
	hdr.sigfigs = 0;
	hdr.linktype = DLT_EN10MB;
	if (fwrite((char *)&hdr, sizeof(hdr), 1, fd) != 1) {
	  fprintf(stderr, "failed to write tcpdump header: %s\n", strerror(errno));
	  exit(-1);
	}

	fflush(fd);
      }

      /* Save packet */
      // prepare the whole thing in a buffer first, in case we are piping the output
      // to another process and the reader expects it all to appear at once...
      memcpy(buf, &pkthdr, sizeof(pkthdr));

      bytes = sizeof(hdr);
      memcpy(buf+bytes, sample->header, sample->headerLen);
      bytes += sample->headerLen;

      if(fwrite(buf, bytes, 1, fd) != 1) {
	fprintf(stderr, "writePcapPacket: packet write failed: %s\n", strerror(errno));
	exit(-3);
      }
      fflush(fd);
    }
  }
#endif
}

/* =============================================================== */

/* Forward */
void SFABORT(SFSample *s, int r);
int printHex(const u_char *a, int len, u_char *buf, int bufLen, int marker, int bytesPerOutputLine);
char *IP_to_a(u_int32_t ipaddr, char *buf);

#define SF_ABORT_EOS 1
#define SF_ABORT_DECODE_ERROR 2
#define SF_ABORT_LENGTH_ERROR 3

void SFABORT(SFSample *s, int r) {
  printf("SFABORT: %d\n", r);
}



/*_________________---------------------------__________________
  _________________        printHex           __________________
  -----------------___________________________------------------
*/

static u_char bin2hex(int nib) { return (nib < 10) ? ('0' + nib) : ('A' - 10 + nib); }

int printHex(const u_char *a, int len, u_char *buf, int bufLen, int marker, int bytesPerOutputLine)
{
  int b = 0, i = 0;
  for(; i < len; i++) {
    u_char byte;
    if(b > (bufLen - 10)) break;
    if(marker > 0 && i == marker) {
      buf[b++] = '<';
      buf[b++] = '*';
      buf[b++] = '>';
      buf[b++] = '-';
    }
    byte = a[i];
    buf[b++] = bin2hex(byte >> 4);
    buf[b++] = bin2hex(byte & 0x0f);
    if(i > 0 && (i % bytesPerOutputLine) == 0) buf[b++] = '\n';
    else {
      // separate the bytes with a dash
      if (i < (len - 1)) buf[b++] = '-';
    }
  }
  buf[b] = '\0';
  return b;
}

/*_________________---------------------------__________________
  _________________      IP_to_a              __________________
  -----------------___________________________------------------
*/

char *IP_to_a(u_int32_t ipaddr, char *buf)
{
  u_char *ip = (u_char *)&ipaddr;
  sprintf(buf, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return buf;
}


/*_________________---------------------------__________________
  _________________    receiveError           __________________
  -----------------___________________________------------------
*/

static void receiveError(SFSample *sample, char *errm, int hexdump)
{
  char ipbuf[51];
  u_char scratch[6000];
  char *msg = "";
  char *hex = "";
  u_int32_t markOffset = (u_char *)sample->datap - sample->rawSample;
  if(errm) msg = errm;
  if(hexdump) {
    printHex(sample->rawSample, sample->rawSampleLen, scratch, 6000, markOffset, 16);
    hex = (char*)scratch;
  }
  fprintf(stderr, "%s (source IP = %s) %s\n", msg, IP_to_a(sample->sourceIP.s_addr, ipbuf), hex);

  SFABORT(sample, SF_ABORT_DECODE_ERROR);
}

static void skipBytes(SFSample *sample, int skip) {
#if 0
  int quads = (skip + 3) / 4;

  sample->datap += quads;
#else
  /* Luca's fix */  
  sample->datap += skip;
#endif
  if((u_char *)sample->datap > sample->endp) SFABORT(sample, SF_ABORT_EOS);
}

/*_________________---------------------------__________________
  _________________    lengthCheck            __________________
  -----------------___________________________------------------
*/

static void lengthCheck(SFSample *sample, char *description, u_char *start, int len) {
  u_int32_t actualLen = (u_char *)sample->datap - start;

  if(actualLen != len) 
  {
    fprintf(stderr, "%s length error (expected %d, found %d)\n", description, len, actualLen);
    SFABORT(sample, SF_ABORT_LENGTH_ERROR);
  }
}

/*_________________---------------------------__________________
  _________________     decodeLinkLayer       __________________
  -----------------___________________________------------------
  store the offset to the start of the ipv4 header in the sequence_number field
  or -1 if not found. Decode the 802.1d if it's there.
*/

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct myiphdr))

static void decodeLinkLayer(SFSample *sample, int deviceId)
{
  u_char *start = (u_char *)sample->header;
  u_char *end = start + sample->headerLen;
  u_char *ptr = start;
  u_int16_t type_len;

  /* assume not found */
  sample->gotIPV4 = NO;

  if(sample->headerLen < NFT_ETHHDR_SIZ) return; /* not enough for an Ethernet header */

  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dstMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
  ptr += 6;
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "srcMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
  ptr += 6;
  type_len = (ptr[0] << 8) + ptr[1];
  ptr += 2;

  if(type_len == 0x8100) {
    /* VLAN  - next two bytes */
    u_int32_t vlanData = (ptr[0] << 8) + ptr[1];
    u_int32_t vlan = vlanData & 0x0fff;
    u_int32_t priority = vlanData >> 13;
    ptr += 2;
    /*  _____________________________________ */
    /* |   pri  | c |         vlan-id        | */
    /*  ------------------------------------- */
    /* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "decodedVLAN %lu\n", (long unsigned int)vlan);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "decodedPriority %lu\n", (long unsigned int)priority);
    /* now get the type_len again (next two bytes) */
    type_len = (ptr[0] << 8) + ptr[1];
    ptr += 2;
  }

  /* now we're just looking for IP */
  if(sample->headerLen < NFT_MIN_SIZ) return; /* not enough for an IPv4 header */

  /* peek for IPX */
  if(type_len == 0x0200 || type_len == 0x0201 || type_len == 0x0600) {
#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
    int ipxChecksum = (ptr[0] == 0xff && ptr[1] == 0xff);
    int ipxLen = (ptr[2] << 8) + ptr[3];
    if(ipxChecksum &&
       ipxLen >= IPX_HDR_LEN &&
       ipxLen <= (IPX_HDR_LEN + IPX_MAX_DATA))
      /* we don't do anything with IPX here */
      return;
  }

  if(type_len <= NFT_MAX_8023_LEN) {
    /* assume 802.3+802.2 header */
    /* check for SNAP */
    if(ptr[0] == 0xAA &&
       ptr[1] == 0xAA &&
       ptr[2] == 0x03) {
      ptr += 3;
      if(ptr[0] != 0 ||
	 ptr[1] != 0 ||
	 ptr[2] != 0) {
	if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "VSNAP_OUI %02X-%02X-%02X\n", ptr[0], ptr[1], ptr[2]);
	return; /* no further decode for vendor-specific protocol */
      }
      ptr += 3;
      /* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
      type_len = (ptr[0] << 8) + ptr[1];
      ptr += 2;
    }
    else {
      if (ptr[0] == 0x06 &&
	  ptr[1] == 0x06 &&
	  (ptr[2] & 0x01)) {
	/* IP over 8022 */
	ptr += 3;
	/* force the type_len to be IP so we can inline the IP decode below */
	type_len = 0x0800;
      }
      else return;
    }
  }

  /* assume type_len is an ethernet-type now */

  if(type_len == 0x0800) {
    /* IPV4 */
    if((end - ptr) < sizeof(struct myiphdr)) return;
    /* look at first byte of header.... */
    /*  ___________________________ */
    /* |   version   |    hdrlen   | */
    /*  --------------------------- */
    if((*ptr >> 4) != 4) return; /* not version 4 */
    if((*ptr & 15) < 5) return; /* not IP (hdr len must be 5 quads or more) */
    /* survived all the tests - store the offset to the start of the ip header */
    sample->gotIPV4 = YES;
    sample->offsetToIPV4 = (ptr - start);
  }
}

/*_________________---------------------------__________________
  _________________     decodeIPV4            __________________
  -----------------___________________________------------------
*/

static void decodeIPV4(SFSample *sample, int deviceId)
{
  if(sample->gotIPV4) {
    char buf[51];
    u_char *ptr = sample->header + sample->offsetToIPV4;
    /* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
       platforms would core-dump if we tried that).  It's OK coz this probably performs just as well anyway. */
    struct myiphdr ip;
    memcpy(&ip, ptr, sizeof(ip));
    /* Value copy all ip elements into sample */
    sample->dcd_srcIP.s_addr = ip.saddr;
    sample->dcd_dstIP.s_addr = ip.daddr;
    sample->dcd_ipProtocol = ip.protocol;
    sample->dcd_ipTos = ip.tos;
    sample->dcd_ipTTL = ip.ttl;
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "ip.tot_len = %d\n", ntohs(ip.tot_len));
    /* Log out the decoded IP fields */
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "srcIP %s\n", IP_to_a(sample->dcd_srcIP.s_addr, buf));
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dstIP %s\n", IP_to_a(sample->dcd_dstIP.s_addr, buf));
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "IPProtocol %u\n", sample->dcd_ipProtocol);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "IPTOS %u\n", sample->dcd_ipTos);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "IPTTL %u\n", sample->dcd_ipTTL);
    /* check for fragments */
    sample->ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
    if(sample->ip_fragmentOffset > 0) {
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "IPFragmentOffset %u\n", sample->ip_fragmentOffset);
    }
    else {
      /* advance the pointer to the next protocol layer */
      /* ip headerLen is expressed as a number of quads */
      ptr += (ip.version_and_headerLen & 0x0f) * 4;

      switch(ip.protocol) {
      case 1: /* ICMP */
	{
	  struct myicmphdr icmp;
	  memcpy(&icmp, ptr, sizeof(icmp));
	  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "ICMPType %u\n", icmp.type);
	  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "ICMPCode %u\n", icmp.code);
	}
	break;
      case 6: /* TCP */
	{
	  struct mytcphdr tcp;
	  memcpy(&tcp, ptr, sizeof(tcp));
	  sample->dcd_sport = ntohs(tcp.th_sport);
	  sample->dcd_dport = ntohs(tcp.th_dport);
	  sample->dcd_tcpFlags = tcp.th_flags;
	  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "TCPSrcPort %u\n", sample->dcd_sport);
	  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "TCPDstPort %u\n",sample->dcd_dport);
	  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "TCPFlags %u\n", sample->dcd_tcpFlags);
	  if(sample->dcd_dport == 80) {
	    int headerBytes = (tcp.th_off_and_unused >> 4) * 4;
	    ptr += headerBytes;
	  }
	}
	break;
      case 17: /* UDP */
	{
	  struct myudphdr udp;
	  memcpy(&udp, ptr, sizeof(udp));
	  sample->dcd_sport = ntohs(udp.uh_sport);
	  sample->dcd_dport = ntohs(udp.uh_dport);
	  sample->udp_pduLen = ntohs(udp.uh_ulen);
	  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "UDPSrcPort %u\n", sample->dcd_sport);
	  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "UDPDstPort %u\n", sample->dcd_dport);
	  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "UDPBytes %u\n", sample->udp_pduLen);
	}
	break;
      default: /* some other protcol */
	break;
      }
    }
  }
}

#if 0
/*_________________---------------------------__________________
  _________________      in_checksum          __________________
  -----------------___________________________------------------
*/
static u_int16_t in_checksum(u_int16_t *addr, int len)
{
  int nleft = len;
  u_short *w = addr;
  u_short answer;
  int sum = 0;

  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) sum += *(u_char *)w;

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

#endif

/*_________________---------------------------__________________
  _________________   read data fns           __________________
  -----------------___________________________------------------
*/

static u_int32_t getData32(SFSample *sample, int deviceId) {
  u_int32_t *val;

  if((u_char *)sample->datap > sample->endp) SFABORT(sample, SF_ABORT_EOS);
  val = (u_int32_t*)sample->datap;
  skipBytes(sample, 4);

  return ntohl(*val);
}

static u_int32_t getData32_nobswap(SFSample *sample, int deviceId) {
  u_int32_t *val;

  if((u_char *)sample->datap > sample->endp) SFABORT(sample, SF_ABORT_EOS);

  val = (u_int32_t*)sample->datap;
  skipBytes(sample, 4);

  return *val;
}

static u_int64_t getData64(SFSample *sample, int deviceId) {
  u_int64_t tmpLo, tmpHi;
  tmpHi = getData32(sample, deviceId);
  tmpLo = getData32(sample, deviceId);
  return (tmpHi << 32) + tmpLo;
}

static u_int32_t sf_log_next32(SFSample *sample, char *fieldName, int deviceId) {
  u_int32_t val = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "%s %lu\n", fieldName, (long unsigned int)val);
  return(val);
}

static u_int64_t sf_log_next64(SFSample *sample, char *fieldName, int deviceId) {
  u_int64_t val = getData64(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "%s %llu\n", fieldName, (long long unsigned int)val);
  return(val);
}

static u_int32_t getString(SFSample *sample, char *buf, int bufLen, int deviceId) {
  u_int32_t len, read_len;
  len = getData32(sample, deviceId);
  // truncate if too long
  read_len = (len >= bufLen) ? (bufLen - 1) : len;
  memcpy(buf, sample->datap, read_len);
  buf[read_len] = '\0';   // null terminate
  skipBytes(sample, len);
  return len;
}

static u_int32_t getAddress(SFSample *sample, SFLAddress *address, int deviceId) {
  address->type = getData32(sample, deviceId);
  if(address->type == SFLADDRESSTYPE_IP_V4)
    address->address.ip_v4.s_addr = getData32_nobswap(sample, deviceId);
  else {
    memcpy(&address->address.ip_v6.s6_addr, sample->datap, 16);
    skipBytes(sample, 16);
  }

  return address->type;
}

static char *printAddress(SFLAddress *address, char *buf, int bufLen, int deviceId) {
  if(address->type == SFLADDRESSTYPE_IP_V4)
    IP_to_a(address->address.ip_v4.s_addr, buf);
  else {
    u_char *b = address->address.ip_v6.s6_addr;
    // should really be: snprintf(buf, buflen,...) but snprintf() is not always available
    sprintf(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	    b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
  }

  return buf;
}

static char *printTag(u_int32_t tag, char *buf, int bufLen, int deviceId) {
  // should really be: snprintf(buf, buflen,...) but snprintf() is not always available
  sprintf(buf, "%lu:%lu", (long unsigned int)(tag >> 12), (long unsigned int)(tag & 0x00000FFF));
  return buf;
}

static u_int32_t skipTLVRecord(SFSample *sample, u_int32_t tag, char *description, int deviceId) {
  char buf[51];
  u_int32_t len;
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "skipping unknown %s: %s\n", description, printTag(tag, buf, 50, deviceId));
  len = getData32(sample, deviceId);
  // sanity check
  if(len > sample->rawSampleLen) SFABORT(sample, SF_ABORT_EOS);
  else skipBytes(sample, len);
  return len;
}

/*_________________---------------------------__________________
  _________________    readExtendedSwitch     __________________
  -----------------___________________________------------------
*/

static void readExtendedSwitch(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "extendedType SWITCH\n");
  sample->in_vlan = getData32(sample, deviceId);
  sample->in_priority = getData32(sample, deviceId);
  sample->out_vlan = getData32(sample, deviceId);
  sample->out_priority = getData32(sample, deviceId);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;

  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "in_vlan %lu\n", (long unsigned int)sample->in_vlan);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "in_priority %lu\n", (long unsigned int)sample->in_priority);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "out_vlan %lu\n", (long unsigned int)sample->out_vlan);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "out_priority %lu\n", (long unsigned int)sample->out_priority);
}

/*_________________---------------------------__________________
  _________________    readExtendedRouter     __________________
  -----------------___________________________------------------
*/

static void readExtendedRouter(SFSample *sample, int deviceId)
{
  char buf[51];
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "extendedType ROUTER\n");
  getAddress(sample, &sample->nextHop, deviceId);
  sample->srcMask = getData32(sample, deviceId);
  sample->dstMask = getData32(sample, deviceId);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;

  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "nextHop %s\n",
				       printAddress(&sample->nextHop, buf, 50, deviceId));
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "srcSubnetMask %lu\n", (long unsigned int)sample->srcMask);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dstSubnetMask %lu\n", (long unsigned int)sample->dstMask);
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway_v2   __________________
  -----------------___________________________------------------
*/

static void readExtendedGateway_v2(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "extendedType GATEWAY\n");

  sample->my_as = getData32(sample, deviceId);
  sample->src_as = getData32(sample, deviceId);
  sample->src_peer_as = getData32(sample, deviceId);
  sample->dst_as_path_len = getData32(sample, deviceId);
  /* just point at the dst_as_path array */
  if(sample->dst_as_path_len > 0) {
    sample->dst_as_path = (u_int32_t*)sample->datap;
    /* and skip over it in the input */
    skipBytes(sample, sample->dst_as_path_len * 4);
    // fill in the dst and dst_peer fields too
    sample->dst_peer_as = ntohl(sample->dst_as_path[0]);
    sample->dst_as = ntohl(sample->dst_as_path[sample->dst_as_path_len - 1]);
  }

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;

  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "my_as %lu\n", 
				       (long unsigned int)sample->my_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "src_as %lu\n", 
				       (long unsigned int)sample->src_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "src_peer_as %lu\n", 
				       (long unsigned int)sample->src_peer_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dst_as %lu\n", 
				       (long unsigned int)sample->dst_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dst_peer_as %lu\n", 
				       (long unsigned int)sample->dst_peer_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dst_as_path_len %lu\n",
				       (long unsigned int)sample->dst_as_path_len);

  if(sample->dst_as_path_len > 0) {
    u_int32_t i = 0;
    for(; i < sample->dst_as_path_len; i++) {
      if(i == 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dst_as_path "); }
      else if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "-");
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "%lu", (long unsigned int)ntohl(sample->dst_as_path[i]));
    }
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "\n");
  }
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway      __________________
  -----------------___________________________------------------
*/

static void readExtendedGateway(SFSample *sample, int deviceId)
{
  u_int32_t segments;
  int seg;
  char buf[51];

  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "extendedType GATEWAY\n");

  if(sample->datagramVersion >= 5) {
    getAddress(sample, &sample->bgp_nextHop, deviceId);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "bgp_nexthop %s\n",
					 printAddress(&sample->bgp_nextHop, buf, 50, deviceId));
  }

  sample->my_as = getData32(sample, deviceId);
  sample->src_as = getData32(sample, deviceId);
  sample->src_peer_as = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "my_as %lu\n", (long unsigned int)sample->my_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "src_as %lu\n", (long unsigned int)sample->src_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "src_peer_as %lu\n", (long unsigned int)sample->src_peer_as);
  segments = getData32(sample, deviceId);
  if(segments > 0) {
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dst_as_path ");
    for(seg = 0; seg < segments; seg++) {
      u_int32_t seg_type;
      u_int32_t seg_len;
      int i;
      seg_type = getData32(sample, deviceId);
      seg_len = getData32(sample, deviceId);
      for(i = 0; i < seg_len; i++) {
	u_int32_t asNumber;
	asNumber = getData32(sample, deviceId);
	/* mark the first one as the dst_peer_as */
	if(i == 0 && seg == 0) sample->dst_peer_as = asNumber;
	else if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "-");
	/* make sure the AS sets are in parentheses */
	if(i == 0 && seg_type == SFLEXTENDED_AS_SET) if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "(");
	if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "%lu", (long unsigned int)asNumber);
	/* mark the last one as the dst_as */
	if(seg == (segments - 1) && i == (seg_len - 1)) sample->dst_as = asNumber;
      }
      if(seg_type == SFLEXTENDED_AS_SET) if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, ")");
    }
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "\n");
  }
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dst_as %lu\n", (long unsigned int)sample->dst_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dst_peer_as %lu\n", (long unsigned int)sample->dst_peer_as);

  sample->communities_len = getData32(sample, deviceId);
  /* just point at the communities array */
  if(sample->communities_len > 0) sample->communities = (u_int32_t*)sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, sample->communities_len * 4);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
  if(sample->communities_len > 0) {
    int j = 0;
    for(; j < sample->communities_len; j++) {
      if(j == 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "BGP_communities "); }
      else if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "-");
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "%lu", (long unsigned int)ntohl(sample->communities[j]));
    }
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "\n");
  }

  sample->localpref = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "BGP_localpref %lu\n", (long unsigned int)sample->localpref);

}

/*_________________---------------------------__________________
  _________________    readExtendedUser       __________________
  -----------------___________________________------------------
*/

static void readExtendedUser(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "extendedType USER\n");

  if(sample->datagramVersion >= 5) {
    sample->src_user_charset = getData32(sample, deviceId);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "src_user_charset %d\n", sample->src_user_charset);
  }

  sample->src_user_len = getString(sample, sample->src_user, SA_MAX_EXTENDED_USER_LEN, deviceId);

  if(sample->datagramVersion >= 5) {
    sample->dst_user_charset = getData32(sample, deviceId);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dst_user_charset %d\n", sample->dst_user_charset);
  }

  sample->dst_user_len = getString(sample, sample->dst_user, SA_MAX_EXTENDED_USER_LEN, deviceId);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_USER;

  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "src_user %s\n", sample->src_user);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dst_user %s\n", sample->dst_user);
}

/*_________________---------------------------__________________
  _________________    readExtendedUrl        __________________
  -----------------___________________________------------------
*/

static void readExtendedUrl(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "extendedType URL\n");

  sample->url_direction = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "url_direction %lu\n", (long unsigned int)sample->url_direction);
  sample->url_len = getString(sample, sample->url, SA_MAX_EXTENDED_URL_LEN, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "url %s\n", sample->url);
  if(sample->datagramVersion >= 5) {
    sample->host_len = getString(sample, sample->host, SA_MAX_EXTENDED_HOST_LEN, deviceId);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "host %s\n", sample->host);
  }
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_URL;
}


/*_________________---------------------------__________________
  _________________       mplsLabelStack      __________________
  -----------------___________________________------------------
*/

static void mplsLabelStack(SFSample *sample, char *fieldName, int deviceId)
{
  SFLLabelStack lstk;
  u_int32_t lab;
  lstk.depth = getData32(sample, deviceId);
  /* just point at the lablelstack array */
  if(lstk.depth > 0) 
    lstk.stack = (u_int32_t *)sample->datap;
  else
    return;

  /* and skip over it in the input */
  skipBytes(sample, lstk.depth * 4);

  if(lstk.depth > 0) {
    int j = 0;
    for(; j < lstk.depth; j++) {
      if(j == 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "%s ", fieldName); }
      else if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "-");
      lab = ntohl(lstk.stack[j]);
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "%lu.%lu.%lu.%lu",
					   (long unsigned int)(lab >> 12),     // label
					   (long unsigned int)(lab >> 9) & 7,  // experimental
					   (long unsigned int)(lab >> 8) & 1,  // bottom of stack
					   (long unsigned int)(lab &  255));   // TTL
    }
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "\n");
  }
}

/*_________________---------------------------__________________
  _________________    readExtendedMpls       __________________
  -----------------___________________________------------------
*/

static void readExtendedMpls(SFSample *sample, int deviceId)
{
  char buf[51];
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "extendedType MPLS\n");
  getAddress(sample, &sample->mpls_nextHop, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "mpls_nexthop %s\n", printAddress(&sample->mpls_nextHop, buf, 50, deviceId));

  mplsLabelStack(sample, "mpls_input_stack", deviceId);
  mplsLabelStack(sample, "mpls_output_stack", deviceId);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}

/*_________________---------------------------__________________
  _________________    readExtendedNat        __________________
  -----------------___________________________------------------
*/

static void readExtendedNat(SFSample *sample, int deviceId)
{
  char buf[51];
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "extendedType NAT\n");
  getAddress(sample, &sample->nat_src, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "nat_src %s\n", printAddress(&sample->nat_src, buf, 50, deviceId));
  getAddress(sample, &sample->nat_dst, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "nat_dst %s\n", printAddress(&sample->nat_dst, buf, 50, deviceId));
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}


/*_________________---------------------------__________________
  _________________    readExtendedMplsTunnel __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsTunnel(SFSample *sample, int deviceId)
{
#define SA_MAX_TUNNELNAME_LEN 100
  char tunnel_name[SA_MAX_TUNNELNAME_LEN+1];
  u_int32_t tunnel_id, tunnel_cos;

  if(getString(sample, tunnel_name, SA_MAX_TUNNELNAME_LEN, deviceId) > 0)
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "mpls_tunnel_lsp_name %s\n", tunnel_name);
  tunnel_id = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "mpls_tunnel_id %lu\n", (long unsigned int)tunnel_id);
  tunnel_cos = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "mpls_tunnel_cos %lu\n", (long unsigned int)tunnel_cos);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsVC     __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsVC(SFSample *sample, int deviceId)
{
#define SA_MAX_VCNAME_LEN 100
  char vc_name[SA_MAX_VCNAME_LEN+1];
  u_int32_t vll_vc_id, vc_cos;
  if(getString(sample, vc_name, SA_MAX_VCNAME_LEN, deviceId) > 0)
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "mpls_vc_name %s\n", vc_name);
  vll_vc_id = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "mpls_vll_vc_id %lu\n", (long unsigned int)vll_vc_id);
  vc_cos = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "mpls_vc_cos %lu\n", (long unsigned int)vc_cos);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_VC;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsFTN    __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsFTN(SFSample *sample, int deviceId)
{
#define SA_MAX_FTN_LEN 100
  char ftn_descr[SA_MAX_FTN_LEN+1];
  u_int32_t ftn_mask;
  if(getString(sample, ftn_descr, SA_MAX_FTN_LEN, deviceId) > 0)
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "mpls_ftn_descr %s\n", ftn_descr);
  ftn_mask = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "mpls_ftn_mask %lu\n", (long unsigned int)ftn_mask);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_FTN;
}

/*_________________---------------------------__________________
  _________________  readExtendedMplsLDP_FEC  __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsLDP_FEC(SFSample *sample, int deviceId)
{
  u_int32_t fec_addr_prefix_len = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "mpls_fec_addr_prefix_len %lu\n", 
				       (long unsigned int)fec_addr_prefix_len);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
}

/*_________________---------------------------__________________
  _________________  readExtendedVlanTunnel   __________________
  -----------------___________________________------------------
*/

static void readExtendedVlanTunnel(SFSample *sample, int deviceId)
{
  u_int32_t lab;
  SFLLabelStack lstk;

  memset(&lstk, 0, sizeof(lstk));
  lstk.depth = getData32(sample, deviceId);
  /* just point at the lablelstack array */
  if(lstk.depth > 0) lstk.stack = (u_int32_t *)sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, lstk.depth * 4);

  if(lstk.depth > 0) {
    int j = 0;
    for(; j < lstk.depth; j++) {
      if(j == 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "vlan_tunnel "); }
      else if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "-");
      lab = ntohl(lstk.stack[j]);
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "0x%04x.%lu.%lu.%lu",
					   (lab >> 16),       // TPI
					   (long unsigned int)(lab >> 13) & 7,   // priority
					   (long unsigned int)(lab >> 12) & 1,   // CFI
					   (long unsigned int)(lab & 4095));     // VLAN
    }
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "\n");
  }
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
}

/*_________________---------------------------__________________
  _________________  readFlowSample_header    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_header(SFSample *sample, int deviceId)
{
  u_int toSkip;

  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "flowSampleType HEADER\n");
  sample->headerProtocol = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "headerProtocol %lu\n", (long unsigned int)sample->headerProtocol);
  sample->sampledPacketSize = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sampledPacketSize %lu\n", (long unsigned int)sample->sampledPacketSize);
  if(sample->datagramVersion > 4) {
    // stripped count introduced in sFlow version 5
    sample->stripped = getData32(sample, deviceId);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "strippedBytes %lu\n", (long unsigned int)sample->stripped);
  }
  sample->headerLen = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "headerLen %lu\n", (long unsigned int)sample->headerLen);

  sample->header = (u_char *)sample->datap; /* just point at the header */

  toSkip = ((sample->headerLen + 3) / 4) * 4; /* L.Deri */
  skipBytes(sample, toSkip);
  {
    char scratch[2000];
    printHex(sample->header, sample->headerLen, (u_char*)scratch, 2000, 0, 2000);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "headerBytes %s\n", scratch);
  }

  switch(sample->headerProtocol) {
    /* the header protocol tells us where to jump into the decode */
  case SFLHEADER_ETHERNET_ISO8023:
    decodeLinkLayer(sample, deviceId);
    break;
  case SFLHEADER_IPv4:
    sample->gotIPV4 = YES;
    sample->offsetToIPV4 = 0;
    break;
  case SFLHEADER_ISO88024_TOKENBUS:
  case SFLHEADER_ISO88025_TOKENRING:
  case SFLHEADER_FDDI:
  case SFLHEADER_FRAME_RELAY:
  case SFLHEADER_X25:
  case SFLHEADER_PPP:
  case SFLHEADER_SMDS:
  case SFLHEADER_AAL5:
  case SFLHEADER_AAL5_IP:
  case SFLHEADER_IPv6:
  case SFLHEADER_MPLS:
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "NO_DECODE headerProtocol=%d\n", sample->headerProtocol);
    break;
  default:
    fprintf(stderr, "undefined headerProtocol = %d\n", sample->headerProtocol);
    exit(-12);
  }

  if(sample->gotIPV4) {
    // report the size of the original IPPdu (including the IP header)
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "IPSize %d\n",  sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4);
    decodeIPV4(sample, deviceId);
  }
}

/*_________________---------------------------__________________
  _________________  readFlowSample_ethernet  __________________
  -----------------___________________________------------------
*/

static void readFlowSample_ethernet(SFSample *sample, int deviceId)
{
  char *p;
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "flowSampleType ETHERNET\n");
  sample->eth_len = getData32(sample, deviceId);
  memcpy(sample->eth_src, sample->datap, 6);
  skipBytes(sample, 6);
  memcpy(sample->eth_dst, sample->datap, 6);
  skipBytes(sample, 6);
  sample->eth_type = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "ethernet_type %lu\n", (long unsigned int)sample->eth_type);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "ethernet_len %lu\n", (long unsigned int)sample->eth_len);
  p = (char*)sample->eth_src;
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "ethernet_src %02x%02x%02x%02x%02x%02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
  p = (char*)sample->eth_dst;
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "ethernet_dst %02x%02x%02x%02x%02x%02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
}


/*_________________---------------------------__________________
  _________________    readFlowSample_IPv4    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_IPv4(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "flowSampleType IPV4\n");
  sample->headerLen = sizeof(SFLSampled_ipv4);
  sample->header = (u_char *)sample->datap; /* just point at the header */
  skipBytes(sample, sample->headerLen);
  {
    char buf[51];
    SFLSampled_ipv4 nfKey;
    memcpy(&nfKey, sample->header, sizeof(nfKey));
    sample->sampledPacketSize = ntohl(nfKey.length);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sampledPacketSize %lu\n", (long unsigned int)sample->sampledPacketSize);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "IPSize %d\n",  sample->sampledPacketSize);
    sample->dcd_srcIP = nfKey.src_ip;
    sample->dcd_dstIP = nfKey.dst_ip;
    sample->dcd_ipProtocol = ntohl(nfKey.protocol);
    sample->dcd_ipTos = ntohl(nfKey.tos);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "srcIP %s\n", IP_to_a(sample->dcd_srcIP.s_addr, buf));
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dstIP %s\n", IP_to_a(sample->dcd_dstIP.s_addr, buf));
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "IPProtocol %u\n", sample->dcd_ipProtocol);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "IPTOS %u\n", sample->dcd_ipTos);
    sample->dcd_sport = ntohl(nfKey.src_port);
    sample->dcd_dport = ntohl(nfKey.dst_port);
    switch(sample->dcd_ipProtocol) {
    case 1: /* ICMP */
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "ICMPType %u\n", sample->dcd_dport);
      /* not sure about the dest port being icmp type
	 - might be that src port is icmp type and dest
	 port is icmp code.  Still, have seen some
	 implementations where src port is 0 and dst
	 port is the type, so it may be safer to
	 assume that the destination port has the type */
      break;
    case 6: /* TCP */
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "TCPSrcPort %u\n", sample->dcd_sport);
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "TCPDstPort %u\n", sample->dcd_dport);
      sample->dcd_tcpFlags = ntohl(nfKey.tcp_flags);
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "TCPFlags %u\n", sample->dcd_tcpFlags);
      break;
    case 17: /* UDP */
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "UDPSrcPort %u\n", sample->dcd_sport);
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "UDPDstPort %u\n", sample->dcd_dport);
      break;
    default: /* some other protcol */
      break;
    }
  }
}

/*_________________---------------------------__________________
  _________________    readFlowSample_IPv6    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_IPv6(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "flowSampleType IPV6\n");
  sample->header = (u_char *)sample->datap; /* just point at the header */
  sample->headerLen = sizeof(SFLSampled_ipv6);
  skipBytes(sample, sample->headerLen);
  {
    SFLSampled_ipv6 nfKey6;
    memcpy(&nfKey6, sample->header, sizeof(nfKey6));
    sample->sampledPacketSize = ntohl(nfKey6.length);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sampledPacketSize %lu\n", (long unsigned int)sample->sampledPacketSize);
  }
  /* bug: more decode to do here */
}

/*_________________---------------------------__________________
  _________________    readFlowSample_v2v4    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_v2v4(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sampleType FLOWSAMPLE\n");

  sample->samplesGenerated = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sampleSequenceNo %lu\n", (long unsigned int)sample->samplesGenerated);
  {
    u_int32_t samplerId = getData32(sample, deviceId);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
    if(SFLOW_DEBUG(deviceId)) 
      traceEvent(CONST_TRACE_INFO, "sourceId %lu:%lu\n", 
		 (long unsigned int)sample->ds_class, 
		 (long unsigned int)sample->ds_index);
  }

  sample->meanSkipCount = getData32(sample, deviceId);
  sample->samplePool = getData32(sample, deviceId);
  sample->dropEvents = getData32(sample, deviceId);
  sample->inputPort = getData32(sample, deviceId);
  sample->outputPort = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "meanSkipCount %lu\n", (long unsigned int)sample->meanSkipCount);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "samplePool %lu\n", (long unsigned int)sample->samplePool);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dropEvents %lu\n", (long unsigned int)sample->dropEvents);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "inputPort %lu\n", (long unsigned int)sample->inputPort);
  if(sample->outputPort & 0x80000000) {
    u_int32_t numOutputs = sample->outputPort & 0x7fffffff;
    if(numOutputs > 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "outputPort multiple %d\n", numOutputs); }
    else if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "outputPort multiple >1\n");
  }
  else if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "outputPort %lu\n", (long unsigned int)sample->outputPort);

  sample->packet_data_tag = getData32(sample, deviceId);

  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "packet_data_tag=%d",  sample->packet_data_tag);
  switch(sample->packet_data_tag) {
  case INMPACKETTYPE_HEADER: readFlowSample_header(sample, deviceId); break;
  case INMPACKETTYPE_IPV4: readFlowSample_IPv4(sample, deviceId); break;
  case INMPACKETTYPE_IPV6: readFlowSample_IPv6(sample, deviceId); break;
  default: receiveError(sample, "unexpected packet_data_tag", YES); break;
  }

  sample->extended_data_tag = 0;
  {
    u_int32_t x;
    sample->num_extended = getData32(sample, deviceId);
    for(x = 0; x < sample->num_extended; x++) {
      u_int32_t extended_tag;
      extended_tag = getData32(sample, deviceId);
      switch(extended_tag) {
      case INMEXTENDED_SWITCH: readExtendedSwitch(sample, deviceId); break;
      case INMEXTENDED_ROUTER: readExtendedRouter(sample, deviceId); break;
      case INMEXTENDED_GATEWAY:
	if(sample->datagramVersion == 2) readExtendedGateway_v2(sample, deviceId);
	else readExtendedGateway(sample, deviceId);
	break;
      case INMEXTENDED_USER: readExtendedUser(sample, deviceId); break;
      case INMEXTENDED_URL: readExtendedUrl(sample, deviceId); break;
      default: receiveError(sample, "unrecognized extended data tag", YES); break;
      }
    }
  }
}

/*_________________---------------------------__________________
  _________________    readFlowSample         __________________
  -----------------___________________________------------------
*/

static void readFlowSample(SFSample *sample, int expanded, int deviceId)
{
  u_int32_t num_elements, sampleLength;
  u_char *sampleStart;

  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sampleType FLOWSAMPLE\n");
  sampleLength = getData32(sample, deviceId);
  sampleStart = (u_char *)sample->datap;
  sample->samplesGenerated = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sampleSequenceNo %lu\n", (long unsigned int)sample->samplesGenerated);
  if(expanded) {
    sample->ds_class = getData32(sample, deviceId);
    sample->ds_index = getData32(sample, deviceId);
  }
  else {
    u_int32_t samplerId = getData32(sample, deviceId);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }
  if(SFLOW_DEBUG(deviceId)) 
    traceEvent(CONST_TRACE_INFO, "sourceId %lu:%lu\n", 
	       (long unsigned int)sample->ds_class,
	       (long unsigned int)sample->ds_index);

  sample->meanSkipCount = getData32(sample, deviceId);
  sample->samplePool = getData32(sample, deviceId);
  sample->dropEvents = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "meanSkipCount %lu\n", (long unsigned int)sample->meanSkipCount);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "samplePool %lu\n", (long unsigned int)sample->samplePool);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "dropEvents %lu\n", (long unsigned int)sample->dropEvents);
  if(expanded) {
    sample->inputPortFormat = getData32(sample, deviceId);
    sample->inputPort = getData32(sample, deviceId);
    sample->outputPortFormat = getData32(sample, deviceId);
    sample->outputPort = getData32(sample, deviceId);
  }
  else {
    u_int32_t inp, outp;
    inp = getData32(sample, deviceId);
    outp = getData32(sample, deviceId);
    sample->inputPortFormat = inp >> 30;
    sample->outputPortFormat = outp >> 30;
    sample->inputPort = inp & 0x3fffffff;
    sample->outputPort = outp & 0x3fffffff;
  }
  if(sample->inputPortFormat == 3) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "inputPort format==3 %lu\n", (long unsigned int)sample->inputPort); }
  else if(sample->inputPortFormat == 2) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "inputPort multiple %lu\n", (long unsigned int)sample->inputPort); }
  else if(sample->inputPortFormat == 1) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "inputPort dropCode %lu\n", (long unsigned int)sample->inputPort); }
  else if(sample->inputPortFormat == 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "inputPort %lu\n", (long unsigned int)sample->inputPort); }
  if(sample->outputPortFormat == 3) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "outputPort format==3 %lu\n", (long unsigned int)sample->outputPort); }
  else if(sample->outputPortFormat == 2) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "outputPort multiple %lu\n", (long unsigned int)sample->outputPort); }
  else if(sample->outputPortFormat == 1) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "outputPort dropCode %lu\n", (long unsigned int)sample->outputPort); }
  else if(sample->outputPortFormat == 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "outputPort %lu\n", (long unsigned int)sample->outputPort); }

  num_elements = getData32(sample, deviceId);
  {
    int el;
    for(el = 0; el < num_elements; el++) {
      u_int32_t tag, length;
      u_char *start;
      char buf[51];
      tag = getData32(sample, deviceId);
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "flowBlock_tag %s\n", printTag(tag, buf, 50, deviceId));
      length = getData32(sample, deviceId);
      start = (u_char *)sample->datap;

      switch(tag) {
      case SFLFLOW_HEADER:     readFlowSample_header(sample, deviceId); break;
      case SFLFLOW_ETHERNET:   readFlowSample_ethernet(sample, deviceId); break;
      case SFLFLOW_IPV4:       readFlowSample_IPv4(sample, deviceId); break;
      case SFLFLOW_IPV6:       readFlowSample_IPv6(sample, deviceId); break;
      case SFLFLOW_EX_SWITCH:  readExtendedSwitch(sample, deviceId); break;
      case SFLFLOW_EX_ROUTER:  readExtendedRouter(sample, deviceId); break;
      case SFLFLOW_EX_GATEWAY: readExtendedGateway(sample, deviceId); break;
      case SFLFLOW_EX_USER:    readExtendedUser(sample, deviceId); break;
      case SFLFLOW_EX_URL:     readExtendedUrl(sample, deviceId); break;
      case SFLFLOW_EX_MPLS:    readExtendedMpls(sample, deviceId); break;
      case SFLFLOW_EX_NAT:     readExtendedNat(sample, deviceId); break;
      case SFLFLOW_EX_MPLS_TUNNEL:  readExtendedMplsTunnel(sample, deviceId); break;
      case SFLFLOW_EX_MPLS_VC:      readExtendedMplsVC(sample, deviceId); break;
      case SFLFLOW_EX_MPLS_FTN:     readExtendedMplsFTN(sample, deviceId); break;
      case SFLFLOW_EX_MPLS_LDP_FEC: readExtendedMplsLDP_FEC(sample, deviceId); break;
      case SFLFLOW_EX_VLAN_TUNNEL:  readExtendedVlanTunnel(sample, deviceId); break;
      default: skipTLVRecord(sample, tag, "flow_sample_element", deviceId); break;
      }
      lengthCheck(sample, "flow_sample_element", start, length);
    }
  }

  lengthCheck(sample, "flow_sample", sampleStart, sampleLength);  
}

/*_________________---------------------------__________________
  _________________  readCounters_generic     __________________
  -----------------___________________________------------------
*/

static void readCounters_generic(SFSample *sample, int deviceId)
{
  IfCounters ifName;

  /* the first part of the generic counters block is really just more info about the interface. */
  sample->ifIndex = getData32(sample, deviceId);      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "ifIndex %lu\n", (long unsigned int)sample->ifIndex);
  sample->networkType = getData32(sample, deviceId);  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "networkType %lu\n", (long unsigned int)sample->networkType);
  sample->ifSpeed = getData64(sample, deviceId);      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "ifSpeed %llu\n", (long long unsigned int)sample->ifSpeed);
  sample->ifDirection = getData32(sample, deviceId);  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "ifDirection %lu\n", (long unsigned int)sample->ifDirection);
  sample->ifStatus = getData32(sample, deviceId);     if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "ifStatus %lu\n", (long unsigned int)sample->ifStatus);

  ifName.ifIndex = sample->ifIndex;
  ifName.ifType = sample->networkType;
  ifName.ifSpeed = sample->ifSpeed;
  ifName.ifDirection = sample->ifDirection;
  ifName.ifStatus = sample->ifStatus;

  /* the generic counters always come first */
  ifName.ifInOctets = sf_log_next64(sample, "ifInOctets", deviceId);
  ifName.ifInUcastPkts = sf_log_next32(sample, "ifInUcastPkts", deviceId);
  ifName.ifInMulticastPkts = sf_log_next32(sample, "ifInMulticastPkts", deviceId);
  ifName.ifInBroadcastPkts = sf_log_next32(sample, "ifInBroadcastPkts", deviceId);
  ifName.ifInDiscards = sf_log_next32(sample, "ifInDiscards", deviceId);
  ifName.ifInErrors = sf_log_next32(sample, "ifInErrors", deviceId);
  ifName.ifInUnknownProtos = sf_log_next32(sample, "ifInUnknownProtos", deviceId);
  ifName.ifOutOctets = sf_log_next64(sample, "ifOutOctets", deviceId);
  ifName.ifOutUcastPkts = sf_log_next32(sample, "ifOutUcastPkts", deviceId);
  ifName.ifOutMulticastPkts = sf_log_next32(sample, "ifOutMulticastPkts", deviceId);
  ifName.ifOutBroadcastPkts = sf_log_next32(sample, "ifOutBroadcastPkts", deviceId);
  ifName.ifOutDiscards = sf_log_next32(sample, "ifOutDiscards", deviceId);
  ifName.ifOutErrors = sf_log_next32(sample, "ifOutErrors", deviceId);
  ifName.ifPromiscuousMode = sf_log_next32(sample, "ifPromiscuousMode", deviceId);

  updateSflowInterfaceCounters(deviceId, &ifName);
}

/*_________________---------------------------__________________
  _________________  readCounters_ethernet    __________________
  -----------------___________________________------------------
*/

static  void readCounters_ethernet(SFSample *sample, int deviceId)
{
  sf_log_next32(sample, "dot3StatsAlignmentErrors", deviceId);
  sf_log_next32(sample, "dot3StatsFCSErrors", deviceId);
  sf_log_next32(sample, "dot3StatsSingleCollisionFrames", deviceId);
  sf_log_next32(sample, "dot3StatsMultipleCollisionFrames", deviceId);
  sf_log_next32(sample, "dot3StatsSQETestErrors", deviceId);
  sf_log_next32(sample, "dot3StatsDeferredTransmissions", deviceId);
  sf_log_next32(sample, "dot3StatsLateCollisions", deviceId);
  sf_log_next32(sample, "dot3StatsExcessiveCollisions", deviceId);
  sf_log_next32(sample, "dot3StatsInternalMacTransmitErrors", deviceId);
  sf_log_next32(sample, "dot3StatsCarrierSenseErrors", deviceId);
  sf_log_next32(sample, "dot3StatsFrameTooLongs", deviceId);
  sf_log_next32(sample, "dot3StatsInternalMacReceiveErrors", deviceId);
  sf_log_next32(sample, "dot3StatsSymbolErrors", deviceId);
}


/*_________________---------------------------__________________
  _________________  readCounters_tokenring   __________________
  -----------------___________________________------------------
*/

static void readCounters_tokenring(SFSample *sample, int deviceId)
{
  sf_log_next32(sample, "dot5StatsLineErrors", deviceId);
  sf_log_next32(sample, "dot5StatsBurstErrors", deviceId);
  sf_log_next32(sample, "dot5StatsACErrors", deviceId);
  sf_log_next32(sample, "dot5StatsAbortTransErrors", deviceId);
  sf_log_next32(sample, "dot5StatsInternalErrors", deviceId);
  sf_log_next32(sample, "dot5StatsLostFrameErrors", deviceId);
  sf_log_next32(sample, "dot5StatsReceiveCongestions", deviceId);
  sf_log_next32(sample, "dot5StatsFrameCopiedErrors", deviceId);
  sf_log_next32(sample, "dot5StatsTokenErrors", deviceId);
  sf_log_next32(sample, "dot5StatsSoftErrors", deviceId);
  sf_log_next32(sample, "dot5StatsHardErrors", deviceId);
  sf_log_next32(sample, "dot5StatsSignalLoss", deviceId);
  sf_log_next32(sample, "dot5StatsTransmitBeacons", deviceId);
  sf_log_next32(sample, "dot5StatsRecoverys", deviceId);
  sf_log_next32(sample, "dot5StatsLobeWires", deviceId);
  sf_log_next32(sample, "dot5StatsRemoves", deviceId);
  sf_log_next32(sample, "dot5StatsSingles", deviceId);
  sf_log_next32(sample, "dot5StatsFreqErrors", deviceId);
}


/*_________________---------------------------__________________
  _________________  readCounters_vg          __________________
  -----------------___________________________------------------
*/

static void readCounters_vg(SFSample *sample, int deviceId)
{
  sf_log_next32(sample, "dot12InHighPriorityFrames", deviceId);
  sf_log_next64(sample, "dot12InHighPriorityOctets", deviceId);
  sf_log_next32(sample, "dot12InNormPriorityFrames", deviceId);
  sf_log_next64(sample, "dot12InNormPriorityOctets", deviceId);
  sf_log_next32(sample, "dot12InIPMErrors", deviceId);
  sf_log_next32(sample, "dot12InOversizeFrameErrors", deviceId);
  sf_log_next32(sample, "dot12InDataErrors", deviceId);
  sf_log_next32(sample, "dot12InNullAddressedFrames", deviceId);
  sf_log_next32(sample, "dot12OutHighPriorityFrames", deviceId);
  sf_log_next64(sample, "dot12OutHighPriorityOctets", deviceId);
  sf_log_next32(sample, "dot12TransitionIntoTrainings", deviceId);
  sf_log_next64(sample, "dot12HCInHighPriorityOctets", deviceId);
  sf_log_next64(sample, "dot12HCInNormPriorityOctets", deviceId);
  sf_log_next64(sample, "dot12HCOutHighPriorityOctets", deviceId);
}



/*_________________---------------------------__________________
  _________________  readCounters_vlan        __________________
  -----------------___________________________------------------
*/

static void readCounters_vlan(SFSample *sample, int deviceId)
{
  sample->in_vlan = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "in_vlan %lu\n", (long unsigned int)sample->in_vlan);
  sf_log_next64(sample, "octets", deviceId);
  sf_log_next32(sample, "ucastPkts", deviceId);
  sf_log_next32(sample, "multicastPkts", deviceId);
  sf_log_next32(sample, "broadcastPkts", deviceId);
  sf_log_next32(sample, "discards", deviceId);
}

/*_________________---------------------------__________________
  _________________  readCountersSample_v2v4  __________________
  -----------------___________________________------------------
*/

static void readCountersSample_v2v4(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sampleType COUNTERSSAMPLE\n");
  sample->samplesGenerated = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sampleSequenceNo %lu\n", (long unsigned int)sample->samplesGenerated);
  {
    u_int32_t samplerId = getData32(sample, deviceId);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sourceId %lu:%lu\n", (long unsigned int)sample->ds_class, (long unsigned int)sample->ds_index);


  sample->statsSamplingInterval = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "statsSamplingInterval %lu\n", (long unsigned int)sample->statsSamplingInterval);
  /* now find out what sort of counter blocks we have here... */
  sample->counterBlockVersion = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "counterBlockVersion %lu\n", (long unsigned int)sample->counterBlockVersion);

  /* first see if we should read the generic stats */
  switch(sample->counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC:
  case INMCOUNTERSVERSION_ETHERNET:
  case INMCOUNTERSVERSION_TOKENRING:
  case INMCOUNTERSVERSION_FDDI:
  case INMCOUNTERSVERSION_VG:
  case INMCOUNTERSVERSION_WAN: readCounters_generic(sample, deviceId); break;
  case INMCOUNTERSVERSION_VLAN: break;
  default: receiveError(sample, "unknown stats version", YES); break;
  }

  /* now see if there are any specific counter blocks to add */
  switch(sample->counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC: /* nothing more */ break;
  case INMCOUNTERSVERSION_ETHERNET: readCounters_ethernet(sample, deviceId); break;
  case INMCOUNTERSVERSION_TOKENRING:readCounters_tokenring(sample, deviceId); break;
  case INMCOUNTERSVERSION_FDDI: break;
  case INMCOUNTERSVERSION_VG: readCounters_vg(sample, deviceId); break;
  case INMCOUNTERSVERSION_WAN: break;
  case INMCOUNTERSVERSION_VLAN: readCounters_vlan(sample, deviceId); break;
  default: receiveError(sample, "unknown INMCOUNTERSVERSION", YES); break;
  }
}

/*_________________---------------------------__________________
  _________________   readCountersSample      __________________
  -----------------___________________________------------------
*/

static void readCountersSample(SFSample *sample, int expanded, int deviceId)
{
  u_int32_t sampleLength;
  u_int32_t num_elements;
  char *sampleStart;
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sampleType COUNTERSSAMPLE\n");
  sampleLength = getData32(sample, deviceId);
  sampleStart = (char *)sample->datap;
  sample->samplesGenerated = getData32(sample, deviceId);

  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sampleSequenceNo %lu\n", (long unsigned int)sample->samplesGenerated);
  if(expanded) {
    sample->ds_class = getData32(sample, deviceId);
    sample->ds_index = getData32(sample, deviceId);
  }
  else {
    u_int32_t samplerId = getData32(sample, deviceId);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }

  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sourceId %lu:%lu\n", (long unsigned int)sample->ds_class, (long unsigned int)sample->ds_index);

  num_elements = getData32(sample, deviceId);
  {
    int el;
    for(el = 0; el < num_elements; el++) {
      u_int32_t tag, length;
      char *start;
      char buf[51];
      tag = getData32(sample, deviceId);
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "counterBlock_tag %s\n", printTag(tag, buf, 50, deviceId));
      length = getData32(sample, deviceId);
      start = (char *)sample->datap;

      switch(tag) {
      case SFLCOUNTERS_GENERIC: readCounters_generic(sample, deviceId); break;
      case SFLCOUNTERS_ETHERNET: readCounters_ethernet(sample, deviceId); break;
      case SFLCOUNTERS_TOKENRING:readCounters_tokenring(sample, deviceId); break;
      case SFLCOUNTERS_VG: readCounters_vg(sample, deviceId); break;
      case SFLCOUNTERS_VLAN: readCounters_vlan(sample, deviceId); break;
      default: skipTLVRecord(sample, tag, "counters_sample_element", deviceId); break;
      }
      
      lengthCheck(sample, "counters_sample_element", (u_char*)start, length);
    }
  }
  
  lengthCheck(sample, "counters_sample", (u_char*)sampleStart, sampleLength);
}

/*_________________---------------------------__________________
  _________________      readSFlowDatagram    __________________
  -----------------___________________________------------------
*/

static void readSFlowDatagram(SFSample *sample, int deviceId)
{
  u_int32_t samplesInPacket;
  struct timeval now;
  char buf[51];

  /* log some datagram info */
  now.tv_sec = time(NULL);
  now.tv_usec = 0;
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "datagramSourceIP %s\n", IP_to_a(sample->sourceIP.s_addr, buf));
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "datagramSize %lu\n", (long unsigned int)sample->rawSampleLen);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "unixSecondsUTC %lu\n", now.tv_sec);

  /* check the version */
  sample->datagramVersion = getData32(sample, deviceId);

  switch(sample->datagramVersion) {
  case 2:
    myGlobals.device[deviceId].sflowGlobals->numsFlowsV2Rcvd++;
    break;
  case 4:
    myGlobals.device[deviceId].sflowGlobals->numsFlowsV4Rcvd++;
    break;
  case 5:
    myGlobals.device[deviceId].sflowGlobals->numsFlowsV5Rcvd++;
    break;
  default:
    myGlobals.device[deviceId].sflowGlobals->numBadsFlowsVersionsRcvd++;
    break;
  }


  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "datagramVersion %d\n", sample->datagramVersion);
  if(sample->datagramVersion != 2 &&
     sample->datagramVersion != 4 &&
     sample->datagramVersion != 5) {
    receiveError(sample,  "unexpected datagram version number\n", YES);
  }

  /* get the agent address */
  getAddress(sample, &sample->agent_addr, deviceId);

  /* version 5 has an agent sub-id as well */
  if(sample->datagramVersion >= 5) {
    sample->agentSubId = getData32(sample, deviceId);
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "agentSubId %lu\n", (long unsigned int)sample->agentSubId);
  }

  sample->sequenceNo = getData32(sample, deviceId);  /* this is the packet sequence number */
  sample->sysUpTime = getData32(sample, deviceId);
  samplesInPacket = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "agent %s\n", printAddress(&sample->agent_addr, buf, 50, deviceId));
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "packetSequenceNo %lu\n", (long unsigned int)sample->sequenceNo);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sysUpTime %lu\n", (long unsigned int)sample->sysUpTime);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "samplesInPacket %lu\n", (long unsigned int)samplesInPacket);

  /* now iterate and pull out the flows and counters samples */
  {
    u_int32_t samp = 0;

    for(; samp < samplesInPacket; samp++) {
      // just read the tag, then call the approriate decode fn
      sample->sampleType = getData32(sample, deviceId);
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "startSample ----------------------\n");
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "sampleType_tag %s\n", printTag(sample->sampleType, buf, 50, deviceId));
      if(sample->datagramVersion >= 5) {
	switch(sample->sampleType) {
	case SFLFLOW_SAMPLE: readFlowSample(sample, NO, deviceId); break;
	case SFLCOUNTERS_SAMPLE: readCountersSample(sample, NO, deviceId); break;
	case SFLFLOW_SAMPLE_EXPANDED: readFlowSample(sample, YES, deviceId); break;
	case SFLCOUNTERS_SAMPLE_EXPANDED: readCountersSample(sample, YES, deviceId); break;
	default: skipTLVRecord(sample, sample->sampleType, "sample", deviceId); break;
	}
      } else {
	switch(sample->sampleType) {
	case FLOWSAMPLE: readFlowSample_v2v4(sample, deviceId); break;
	case COUNTERSSAMPLE: readCountersSample_v2v4(sample, deviceId); break;
	default: receiveError(sample, "unexpected sample type", YES); break;
	}
      }
     
      if(SFLOW_DEBUG(deviceId))
	traceEvent(CONST_TRACE_INFO, "endSample [%d]  ----------------------\n", sample->sampleType);
      
      // traceEvent(CONST_TRACE_INFO, "endSample [%d]  ----------------------\n", sample->sampleType);
      
      if((sample->sampleType == SFLFLOW_SAMPLE)
	 || (sample->sampleType == SFLFLOW_SAMPLE_EXPANDED)) {
	handleSflowSample(sample, deviceId);      
      }
    }
  }
}


/* =============================================================== */

/* *************************** */

static void dissectFlow(SFSample *sample, int deviceId) {
  readSFlowDatagram(sample, deviceId);
}

/* ****************************** */

#ifdef MAKE_WITH_SFLOWSIGTRAP
RETSIGTYPE sflowcleanup(int signo) {
  static int msgSent = 0;
  int i;
  void *array[20];
  size_t size;
  char **strings;

  if(msgSent<10) {
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_FATALERROR, "SFLOW: caught signal %d %s", signo,
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

  traceEvent(CONST_TRACE_FATALERROR, "SFLOW: ntop shutting down...");
  exit(102);
}
#endif /* MAKE_WITH_SFLOWSIGTRAP */

/* ****************************** */

static void* sflowMainLoop(void* _deviceId) {
  fd_set sflowMask;
  int rc, len, deviceId;
  u_char buffer[2048];
  struct sockaddr_in fromHost;

  deviceId = (int)((long)_deviceId);

  if(!(myGlobals.device[deviceId].sflowGlobals->sflowInSocket > 0)) return(NULL);

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: SFLOW: thread starting [p%d, t%lu]...",
             getpid(), (long unsigned int)pthread_self());

#ifdef MAKE_WITH_SFLOWSIGTRAP
  signal(SIGSEGV, sflowcleanup);
  signal(SIGHUP,  sflowcleanup);
  signal(SIGINT,  sflowcleanup);
  signal(SIGQUIT, sflowcleanup);
  signal(SIGILL,  sflowcleanup);
  signal(SIGABRT, sflowcleanup);
  signal(SIGFPE,  sflowcleanup);
  signal(SIGKILL, sflowcleanup);
  signal(SIGPIPE, sflowcleanup);
  signal(SIGALRM, sflowcleanup);
  signal(SIGTERM, sflowcleanup);
  signal(SIGUSR1, sflowcleanup);
  signal(SIGUSR2, sflowcleanup);
  /* signal(SIGCHLD, sflowcleanup); */
#ifdef SIGCONT
  signal(SIGCONT, sflowcleanup);
#endif
#ifdef SIGSTOP
  signal(SIGSTOP, sflowcleanup);
#endif
#ifdef SIGBUS
  signal(SIGBUS,  sflowcleanup);
#endif
#ifdef SIGSYS
  signal(SIGSYS,  sflowcleanup);
#endif
#endif /* MAKE_WITH_SFLOWSIGTRAP */

  myGlobals.device[deviceId].activeDevice = 1;
  myGlobals.device[deviceId].dummyDevice  = 0;
  myGlobals.device[deviceId].sflowGlobals->threadActive = 1;

  ntopSleepUntilStateRUN();

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: SFLOW: thread running [p%d, t%lu]...",
             getpid(), (long unsigned int)pthread_self());

  for(;myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN;) {
    int maxSock = myGlobals.device[deviceId].sflowGlobals->sflowInSocket;
    struct timeval wait_time;

    FD_ZERO(&sflowMask);
    FD_SET(myGlobals.device[deviceId].sflowGlobals->sflowInSocket, &sflowMask);

    wait_time.tv_sec = 3, wait_time.tv_usec = 0;
    if(!myGlobals.device[deviceId].activeDevice) break;
    rc = select(maxSock+1, &sflowMask, NULL, NULL, &wait_time);
    if(!myGlobals.device[deviceId].activeDevice) break;

    if(rc > 0) {
      if(FD_ISSET(myGlobals.device[deviceId].sflowGlobals->sflowInSocket, &sflowMask)){
	len = sizeof(fromHost);
	rc = recvfrom(myGlobals.device[deviceId].sflowGlobals->sflowInSocket,(char*)&buffer, sizeof(buffer),
		      0,(struct sockaddr*)&fromHost, (socklen_t*)&len);
      }

#ifdef DEBUG_FLOWS
      if(0)
	if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "SFLOW_DEBUG: Received sFlow packet(len=%d)(deviceId=%d)",
					     rc,  deviceId);
#endif

      if(rc > 0) {
	int i;
	SFSample sample;

	myGlobals.device[deviceId].sflowGlobals->numsFlowsPktsRcvd++;

	NTOHL(fromHost.sin_addr.s_addr);

	for(i=0; i<MAX_NUM_PROBES; i++) {
	  if(myGlobals.device[deviceId].sflowGlobals->probeList[i].probeAddr.s_addr == 0) {
	    myGlobals.device[deviceId].sflowGlobals->probeList[i].probeAddr.s_addr = fromHost.sin_addr.s_addr;
	    myGlobals.device[deviceId].sflowGlobals->probeList[i].pkts = 1;
	    break;
	  } else if(myGlobals.device[deviceId].sflowGlobals->probeList[i].probeAddr.s_addr == fromHost.sin_addr.s_addr) {
	    myGlobals.device[deviceId].sflowGlobals->probeList[i].pkts++;
	    break;
	  }
	}

	memset(&sample, 0, sizeof(sample));
	sample.rawSample = buffer;
	sample.rawSampleLen = rc;
	sample.sourceIP = fromHost.sin_addr;
	sample.datap = (u_char *)sample.rawSample;
	sample.endp = (u_char *)sample.rawSample + sample.rawSampleLen;

	dissectFlow(&sample, deviceId);
      }
    } else {
      if(rc < 0) {
	if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_ERROR, "SFLOW: select() failed(%d, %s), terminating sflow",
					     errno, strerror(errno));
	break;
      }
    }
  }

  myGlobals.device[deviceId].sflowGlobals->threadActive = 0;
  myGlobals.device[deviceId].sflowGlobals->sflowThread = 0;
  myGlobals.device[deviceId].activeDevice = 0;

  if(myGlobals.device[deviceId].sflowGlobals)
    traceEvent(CONST_TRACE_INFO, "THREADMGMT: SFLOW: thread terminated [p%d][sflowDeviceId=%d]",
	       getpid(), myGlobals.device[deviceId].sflowGlobals->sflowDeviceId);

  return(NULL);
}

/* ****************************** */

static void initsFlowDevice(int deviceId) {
  int a, b, c, d, a1, b1, c1, d1, rc;
  char value[1024], workList[1024];

  if(!pluginActive) return;

  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "SFLOW: initializing deviceId=%d", deviceId);

  if(myGlobals.device[deviceId].sflowGlobals == NULL) {
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_ERROR, "SFLOW: initsFlowDevice internal error");
    return;
  }

  setPluginStatus(NULL);
  allocDeviceMemory(deviceId);

  myGlobals.device[deviceId].sflowGlobals->threadActive = 0;
  createMutex(&myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex);

  if(fetchPrefsValue(sfValue(deviceId, "sflowInPort", 1), value, sizeof(value)) == -1)
    storePrefsValue(sfValue(deviceId, "sflowInPort", 1), "0");
  else
    myGlobals.device[deviceId].sflowGlobals->sflowInPort = atoi(value);

  if((fetchPrefsValue(sfValue(deviceId, "ifNetMask", 1), value, sizeof(value)) == -1)
     || (((rc = sscanf(value, "%d.%d.%d.%d/%d.%d.%d.%d", &a, &b, &c, &d, &a1, &b1, &c1, &d1)) != 8)
	 && ((rc = sscanf(value, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &a1)) != 5))) {
    storePrefsValue(sfValue(deviceId, "ifNetMask", 1), "192.168.0.0/255.255.255.0");
    myGlobals.device[deviceId].sflowGlobals->sflowIfAddress.s_addr = 0xC0A80000;
    myGlobals.device[deviceId].sflowGlobals->sflowIfMask.s_addr    = 0xFFFFFF00;
  } else {
    myGlobals.device[deviceId].sflowGlobals->sflowIfAddress.s_addr = (a << 24) +(b << 16) +(c << 8) + d;
    if(rc == 8)
      myGlobals.device[deviceId].sflowGlobals->sflowIfMask.s_addr = (a1 << 24) +(b1 << 16) +(c1 << 8) + d1;
    else {
      myGlobals.device[deviceId].sflowGlobals->sflowIfMask.s_addr = 0xffffffff >> a1;
      myGlobals.device[deviceId].sflowGlobals->sflowIfMask.s_addr =~
	myGlobals.device[deviceId].sflowGlobals->sflowIfMask.s_addr;
    }
  }

  if(fetchPrefsValue(sfValue(deviceId, "whiteList", 1), value, sizeof(value)) == -1) {
    storePrefsValue(sfValue(deviceId, "whiteList", 1), "");
    myGlobals.device[deviceId].sflowGlobals->sflowWhiteList = strdup("");
  } else
    myGlobals.device[deviceId].sflowGlobals->sflowWhiteList = strdup(value);

  accessMutex(&myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex, "initsFlowDevice");
  handleWhiteBlackListAddresses((char*)&value,
                                myGlobals.device[deviceId].sflowGlobals->whiteNetworks,
                                &myGlobals.device[deviceId].sflowGlobals->numWhiteNets,
				(char*)&workList,
                                sizeof(workList));
  if(myGlobals.device[deviceId].sflowGlobals->sflowWhiteList != NULL)
    free(myGlobals.device[deviceId].sflowGlobals->sflowWhiteList);
  myGlobals.device[deviceId].sflowGlobals->sflowWhiteList = strdup(workList);
  releaseMutex(&myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "SFLOW: White list initialized to '%s'",
				       myGlobals.device[deviceId].sflowGlobals->sflowWhiteList);

  if(fetchPrefsValue(sfValue(deviceId, "blackList", 1), value, sizeof(value)) == -1) {
    storePrefsValue(sfValue(deviceId, "blackList", 1), "");
    myGlobals.device[deviceId].sflowGlobals->sflowBlackList=strdup("");
  } else
    myGlobals.device[deviceId].sflowGlobals->sflowBlackList=strdup(value);

  accessMutex(&myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex, "initsFlowDevice()");
  handleWhiteBlackListAddresses((char*)&value, myGlobals.device[deviceId].sflowGlobals->blackNetworks,
                                &myGlobals.device[deviceId].sflowGlobals->numBlackNets, (char*)&workList,
                                sizeof(workList));
  if(myGlobals.device[deviceId].sflowGlobals->sflowBlackList != NULL)
    free(myGlobals.device[deviceId].sflowGlobals->sflowBlackList);

  myGlobals.device[deviceId].sflowGlobals->sflowBlackList = strdup(workList);
  releaseMutex(&myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex);
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "SFLOW: Black list initialized to '%s'",
				       myGlobals.device[deviceId].sflowGlobals->sflowBlackList);

  if(fetchPrefsValue(sfValue(deviceId, "sflowAggregation", 1), value, sizeof(value)) == -1)
    storePrefsValue(sfValue(deviceId, "sflowAggregation", 1), "0" /* noAggregation */);
  else
    myGlobals.device[deviceId].sflowGlobals->sflowAggregation = atoi(value);

  if(fetchPrefsValue(sfValue(deviceId, "sflowAssumeFTP", 1), value, sizeof(value)) == -1) {
    storePrefsValue(sfValue(deviceId, "sflowAssumeFTP", 1), "0" /* no */);
    myGlobals.device[deviceId].sflowGlobals->sflowAssumeFTP = 0;
  } else
    myGlobals.device[deviceId].sflowGlobals->sflowAssumeFTP = atoi(value);

  if(setsFlowInSocket(deviceId) != 0)  return;

  if(fetchPrefsValue(sfValue(deviceId, "debug", 1), value, sizeof(value)) == -1) {
    storePrefsValue(sfValue(deviceId, "debug", 1), "0");
    myGlobals.device[deviceId].sflowGlobals->sflowDebug = 0;
  } else {
    myGlobals.device[deviceId].sflowGlobals->sflowDebug = atoi(value);
  }

  /* Allocate a pure dummy for white/black list use */
  myGlobals.device[deviceId].sflowGlobals->dummyHost = (HostTraffic*)malloc(sizeof(HostTraffic));
  memset(myGlobals.device[deviceId].sflowGlobals->dummyHost, 0, sizeof(HostTraffic));

  myGlobals.device[deviceId].sflowGlobals->dummyHost->hostIp4Address.s_addr = 0x00112233;
  strncpy(myGlobals.device[deviceId].sflowGlobals->dummyHost->hostNumIpAddress, "&nbsp;",
	  sizeof(myGlobals.device[deviceId].sflowGlobals->dummyHost->hostNumIpAddress));
  strncpy(myGlobals.device[deviceId].sflowGlobals->dummyHost->hostResolvedName, "white/black list dummy",
	  sizeof(myGlobals.device[deviceId].sflowGlobals->dummyHost->hostResolvedName));
  myGlobals.device[deviceId].sflowGlobals->dummyHost->hostResolvedNameType = FLAG_HOST_SYM_ADDR_TYPE_FAKE;
  strcpy(myGlobals.device[deviceId].sflowGlobals->dummyHost->ethAddressString, "00:00:00:00:00:00");
  setEmptySerial(&myGlobals.device[deviceId].sflowGlobals->dummyHost->serialHostIndex);
  myGlobals.device[deviceId].sflowGlobals->dummyHost->portsUsage = NULL;

  myGlobals.device[deviceId].sflowGlobals->ifCounters = NULL;
  myGlobals.device[deviceId].activeDevice = 1;
  myGlobals.device[deviceId].samplingRate = 1;
  myGlobals.device[deviceId].mtuSize    = myGlobals.mtuSize[myGlobals.device[deviceId].datalink];
  myGlobals.device[deviceId].headerSize = myGlobals.headerSize[myGlobals.device[deviceId].datalink];
  initDeviceSemaphores(deviceId);
}

/* ****************************** */

static int initsFlowFunct(void) {
  char value[128];

  pluginActive = 1;
  myGlobals.runningPref.mergeInterfaces = 0; /* Use different devices */

  if((fetchPrefsValue(sfValue(0, "knownDevices", 0), value, sizeof(value)) != -1)
     && (strlen(value) > 0)) {
    char *strtokState, *dev;

    traceEvent(CONST_TRACE_INFO, "SFLOW: initializing '%s' devices", value);

    dev = strtok_r(value, ",", &strtokState);
    while(dev != NULL) {
      int deviceId = atoi(dev);

      if(deviceId > 0) {
	if((deviceId = createsFlowDevice(deviceId)) == -1) {
	  pluginActive = 0;
	  return(-1);
	}
      }

      dev = strtok_r(NULL, ",", &strtokState);
    }
  } else
    traceEvent(CONST_TRACE_INFO, "SFLOW: no devices to initialize");

  return(0);
}

/* ****************************** */

static void printsFlowDeviceConfiguration(void) {
  char buf[512], value[128];
  int i = 0;

  sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");
  sendString("<tr><th "DARK_BG">Available sFlow Devices</th></tr>\n");
  sendString("<tr><td align=left>\n");

  if((fetchPrefsValue(sfValue(0, "knownDevices", 0), value, sizeof(value)) != -1)
     && (strlen(value) > 0)) {
    char *strtokState, *dev;

    sendString("<FORM ACTION=\"/plugins/");
    sendString(sflowPluginInfo->pluginURLname);
    sendString("\" METHOD=GET>\n");

    dev = strtok_r(value, ",", &strtokState);
    while(dev != NULL) {
      int id = mapsFlowDeviceToNtopDevice(atoi(dev));
      
      if(id == -1)
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=device VALUE=%s %s>%s.%s\n",
		      dev, i == 0 ? "CHECKED" : "", SFLOW_DEVICE_NAME, dev);
      else
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=device VALUE=%s %s>%s\n",
		      dev, i == 0 ? "CHECKED" : "", myGlobals.device[id].humanFriendlyName);
      sendString(buf);

      if(pluginActive) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[ <A HREF=\"/plugins/%s?device=-%s\" "
		      "onClick=\"return confirmDelete()\">Delete</A> ]",
		      sflowPluginInfo->pluginURLname, dev);
	sendString(buf);
      }

      sendString("<br>\n");
      i++; dev = strtok_r(NULL, ",", &strtokState);
    }

    if(pluginActive)
      sendString("<p><INPUT TYPE=submit VALUE=\"Edit sFlow Device\">&nbsp;"
		 "<INPUT TYPE=reset VALUE=Reset>\n</FORM><p>\n");
  }

  /* *********************** */

  if(pluginActive) {
    sendString("<FORM ACTION=\"/plugins/");
    sendString(sflowPluginInfo->pluginURLname);
    sendString("\" METHOD=GET>\n<input type=hidden name=device size=5 value=0>");
    sendString("<p align=center><INPUT TYPE=submit VALUE=\"Add sFlow Device\">&nbsp;\n</FORM><p>\n");
  } else {
    sendString("<p>Please <A HREF=\"/"CONST_SHOW_PLUGINS_HTML"?");
    sendString(sflowPluginInfo->pluginURLname);
    sendString("=1\">enable</A> the sFlow plugin first<br>\n");
  }

  sendString("</td></TR></TABLE></center>");

  printHTMLtrailer();
}

/* ****************************** */

static void printsFlowConfiguration(int deviceId) {
  char buf[512], buf1[32], buf2[32];

  sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");
  sendString("<tr><th colspan=\"4\" "DARK_BG">Incoming Flows</th></tr>\n");

  sendString("<tr><th colspan=2 "DARK_BG">sFlow Device</th>");




  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(sflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");
  
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].sflowGlobals->sflowDeviceId);
  sendString(buf);
  
  sendString("<input name=\"name\" size=\"24\" value=\"");
  sendString(myGlobals.device[deviceId].humanFriendlyName);
  sendString("\"> <input type=\"submit\" value=\"Set Interface Name\">");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), " [ <A HREF=\"/plugins/%s\"/>List sFlow Interfaces</A> ]</p>\n</form>",
		sflowPluginInfo->pluginName);
  sendString(buf);
  sendString("</td></tr>\n");




  sendString("<tr><th rowspan=\"2\" "DARK_BG">Flow<br>Collection</th>\n");

  sendString("<th "DARK_BG">Local<br>Collector<br>UDP"
	     "<br>Port</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(sflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].sflowGlobals->sflowDeviceId);
  sendString(buf);

  sendString("<input name=\"port\" size=\"5\" value=\"");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.device[deviceId].sflowGlobals->sflowInPort);
  sendString(buf);

  sendString("\"> [ Use a port value of 0 to disable collection ] "
	     "<input type=\"submit\" value=\"Set Port\">"
	     "</p>\n</form>\n\n"
             "<p>If you want <b>ntop</b> to display sFlow data it receives from other "
             "hosts, i.e. act as a collector, you must specify the UDP"
	     " port to listen to. "
             "The default port used for sFlow is " DEFAULT_SFLOW_PORT_STR ".</p>\n"
	     "<p align=\"right\"></p>\n");

  if(myGlobals.device[deviceId].sflowGlobals->sflowInPort == 0)
    sendString("<p><font color=red>WARNING</font>: "
	       "The 'Local Collector UDP"
	       " Port' is zero (none). "
               "Even if this plugin is ACTIVE, you must still enter a port number for "
               "<b>ntop</b> to receive and process sFlow data.</p>\n");

  sendString("</td></tr>\n");

  sendString("<tr><th "DARK_BG">Virtual<br>sFlow<br>Interface<br>Network<br>Address</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(sflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].sflowGlobals->sflowDeviceId);
  sendString(buf);

  sendString(" <input name=\"ifNetMask\" size=\"32\" value=\"");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/%s",
		_intoa(myGlobals.device[deviceId].sflowGlobals->sflowIfAddress, buf1, sizeof(buf1)),
		_intoa(myGlobals.device[deviceId].sflowGlobals->sflowIfMask, buf2, sizeof(buf2)));
  sendString(buf);
  sendString("\"> ");
  sendString("<input type=\"submit\" value=\"Set Interface Address\"></p>\n</form>\n");

  sendString("<p>This value is in the form of a network address and mask on the "
             "network where the actual sFlow probe is located. "
             "<b>ntop</b> uses this value to determine which TCP/IP addresses are "
             "local and which are remote.</p>\n"
             "<p>You may specify this in either format, &lt;network&gt;/&lt;mask&gt; or "
             "CIDR (&lt;network&gt;/&lt;bits&gt;). An existing value is displayed "
             "in &lt;network&gt;/&lt;mask&gt; format.</p>\n"
             "<p>If the sFlow probe is monitoring only a single network, then "
             "this is all you need to set. If the sFlow probe is monitoring "
             "multiple networks, then pick one of them for this setting and use "
             "the -m | --local-subnets parameter to specify the others.</p>\n"
             "<p>This interface is called 'virtual' because the <b>ntop</b> host "
             "is not really connected to the network you specify here.</p>\n"
             "</td></tr>\n");

  sendString("<tr><th rowspan=\"3\" "DARK_BG">Filtering</th>\n");

  sendString("<th "DARK_BG">White List</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(sflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].sflowGlobals->sflowDeviceId);
  sendString(buf);

  sendString("<input name=\"whiteList\" size=\"60\" value=\"");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
		myGlobals.device[deviceId].sflowGlobals->sflowWhiteList == NULL ?
		" " : myGlobals.device[deviceId].sflowGlobals->sflowWhiteList);
  sendString(buf);
  sendString("\"> <input type=\"submit\" value=\"Set White List\"></p>\n</form>\n"
             "<p>This is a list of one or more TCP/IP host(s)/network(s) which we will "
             "store data from when these host(s)/network(s) occur in the sFlow records.</p>\n"
             "</td>\n</tr>\n");

  sendString("<tr><th "DARK_BG">Black List</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(sflowPluginInfo->pluginURLname);
  sendString("\" method=GET>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].sflowGlobals->sflowDeviceId);
  sendString(buf);

  sendString("<input name=\"blackList\" size=\"60\" value=\"");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s",
		myGlobals.device[deviceId].sflowGlobals->sflowBlackList == NULL ?
		" " : myGlobals.device[deviceId].sflowGlobals->sflowBlackList);
  sendString(buf);
  sendString("\"> <input type=\"submit\" value=\"Set Black List\"></p>\n</form>\n"
             "<p>This is a list of one or more TCP/IP host(s)/network(s) which we will "
             "exclude data from (i.e. not store it) when these host(s)/network(s) occur "
             "in the sFlow records.</p>\n"
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

  /* *************************************** */

  sendString("<tr><th colspan=\"2\" "DARK_BG">Debug</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(sflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].sflowGlobals->sflowDeviceId);
  sendString(buf);

  if(myGlobals.device[deviceId].sflowGlobals->sflowDebug) {
    sendString("<input type=\"radio\" name=\"debug\" value=\"1\" checked>On");
    sendString("<input type=\"radio\" name=\"debug\" value=\"0\">Off");
  } else {
    sendString("<input type=\"radio\" name=\"debug\" value=\"1\">On");
    sendString("<input type=\"radio\" name=\"debug\" value=\"0\" checked>Off");
  }

  sendString(" <input type=\"submit\" value=\"Set Debug\"></p>\n");

  sendString("</form>\n"
             "<p>This option turns on debugging, which dumps a huge quantity of "
             "noise into the standard <b>ntop</b> log, all about what the sFlow "
             "plugin is doing.  If you are doing development, this might be helpful, "
             "otherwise <i>leave it alone</i>!</p>\n"
	     "</td>\n</tr>\n");

  sendString("<tr><td colspan=4><font color=red><b>REMEMBER</b><br></font><ul><li>Regardless of settings here, "
             "the sFlow plugin must be ACTIVE on the main plugin menu (click "
             "<a href=\"../" CONST_SHOW_PLUGINS_HTML "\">here</a> to go back) "
             "for <b>ntop</b> to receive and/or "
             "process sFlow data.\n"
             "<li>Any option not indicated as taking effect immediately will require you "
             "to recycle (inactivate and then activate) the sFlow plugin in order "
             "for the change to take affect.</ul></td></tr>\n");

  sendString("</table>\n</center>\n");
}

/* ****************************** */

static void printsFlowStatisticsRcvd(int deviceId) {
  char buf[512], formatBuf[32], formatBuf2[32];
  u_int32_t i;

  sendString("<tr " TR_ON ">\n"
             "<th colspan=\"2\" "DARK_BG">Received Flows</th>\n"
             "</tr>\n"
             "<tr " TR_ON ">\n"
             "<th " TH_BG " align=\"left\" "DARK_BG ">Flow Senders</th>\n"
             "<td width=\"20%\">");

  for(i=0; i<MAX_NUM_PROBES; i++) {
    if(myGlobals.device[deviceId].sflowGlobals->probeList[i].probeAddr.s_addr == 0) break;

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s [%s pkts]<br>\n",
		  _intoa(myGlobals.device[deviceId].sflowGlobals->probeList[i].probeAddr, buf, sizeof(buf)),
		  formatPkts(myGlobals.device[deviceId].sflowGlobals->probeList[i].pkts, formatBuf, sizeof(formatBuf)));
    sendString(buf);
  }
  sendString("&nbsp;</td>\n</tr>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG ">Number of sFlow Packets Rcvd</th>\n"
		"<td " TD_BG " align=\"right\">%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].sflowGlobals->numsFlowsPktsRcvd, formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG ">Number of sFlow Packets with Bad Version</th>\n"
		"<td " TD_BG " align=\"right\">%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].sflowGlobals->numBadsFlowsVersionsRcvd, formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG ">Number of sFlow Packets Processed</th>\n"
		"<td " TD_BG " align=\"right\">%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].sflowGlobals->numsFlowsPktsRcvd -
			   myGlobals.device[deviceId].sflowGlobals->numBadsFlowsVersionsRcvd,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG ">Number of v2 Flows Rcvd</th>\n"
		"<td " TD_BG " align=\"right\">%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].sflowGlobals->numsFlowsV2Rcvd,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG ">Number of v4 Flows Rcvd</th>\n"
		"<td " TD_BG " align=\"right\">%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].sflowGlobals->numsFlowsV4Rcvd, 
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG ">Number of v5 Flows Rcvd</th>\n"
		"<td " TD_BG " align=\"right\">%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].sflowGlobals->numsFlowsV5Rcvd,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);
  

  sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
             "<tr " TR_ON ">\n"
             "<th colspan=\"2\" "DARK_BG">Discarded Flows</th>\n"
             "</tr>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG ">Number of Flows with Bad Data</th>\n"
		"<td " TD_BG " align=\"right\">%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].sflowGlobals->numBadFlowReality,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG ">Total Number of Flows Processed</th>\n"
		"<td " TD_BG " align=\"right\">%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].sflowGlobals->numsFlowsProcessed,
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  if((myGlobals.device[deviceId].sflowGlobals->numSrcsFlowsEntryFailedWhiteList +
      myGlobals.device[deviceId].sflowGlobals->numSrcsFlowsEntryFailedBlackList +
      myGlobals.device[deviceId].sflowGlobals->numDstsFlowsEntryFailedWhiteList +
      myGlobals.device[deviceId].sflowGlobals->numDstsFlowsEntryFailedBlackList) > 0) {

    sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
               "<tr " TR_ON ">\n"
               "<th colspan=\"2\" "DARK_BG">Accepted/Rejected Flows</th>\n"
               "</tr>\n"
               "<tr " TR_ON ">\n"
               "<th " DARK_BG">&nbsp;</th>\n"
               "<th " DARK_BG">Source / Destination</th>\n"
               "</tr>\n");

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr " TR_ON ">\n"
		  "<th " TH_BG " align=\"left\" "DARK_BG ">Rejected - Black list</th>\n"
		  "<td " TD_BG ">%s&nbsp;/&nbsp;%s</td>\n"
		  "</tr>\n",
		  formatPkts(myGlobals.device[deviceId].sflowGlobals->numSrcsFlowsEntryFailedBlackList,
			     formatBuf, sizeof(formatBuf)),
		  formatPkts(myGlobals.device[deviceId].sflowGlobals->numDstsFlowsEntryFailedBlackList,
			     formatBuf2, sizeof(formatBuf2)));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr " TR_ON ">\n"
		  "<th " TH_BG " align=\"left\" "DARK_BG ">Rejected - White list</th>\n"
		  "<td " TD_BG ">%s&nbsp;/&nbsp;%s</td>\n"
		  "</tr>\n",
		  formatPkts(myGlobals.device[deviceId].sflowGlobals->numSrcsFlowsEntryFailedWhiteList,
			     formatBuf, sizeof(formatBuf)),
		  formatPkts(myGlobals.device[deviceId].sflowGlobals->numDstsFlowsEntryFailedWhiteList,
			     formatBuf2, sizeof(formatBuf2)));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr " TR_ON ">\n"
		  "<th " TH_BG " align=\"left\" "DARK_BG ">Accepted</th>\n"
		  "<td " TD_BG ">%s&nbsp;/&nbsp;%s</td>\n"
		  "</tr>\n",
		  formatPkts(myGlobals.device[deviceId].sflowGlobals->numSrcsFlowsEntryAccepted,
			     formatBuf, sizeof(formatBuf)),
		  formatPkts(myGlobals.device[deviceId].sflowGlobals->numDstsFlowsEntryAccepted,
			     formatBuf2, sizeof(formatBuf2)));
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<tr " TR_ON ">\n"
		  "<th " TH_BG " align=\"left\" "DARK_BG ">Total</th>\n"
		  "<td " TD_BG ">%s&nbsp;/&nbsp;%s</td>\n"
		  "</tr>\n",
		  formatPkts(myGlobals.device[deviceId].sflowGlobals->numSrcsFlowsEntryFailedBlackList +
			     myGlobals.device[deviceId].sflowGlobals->numSrcsFlowsEntryFailedWhiteList +
			     myGlobals.device[deviceId].sflowGlobals->numSrcsFlowsEntryAccepted,
			     formatBuf, sizeof(formatBuf)),
		  formatPkts(myGlobals.device[deviceId].sflowGlobals->numDstsFlowsEntryFailedBlackList +
			     myGlobals.device[deviceId].sflowGlobals->numDstsFlowsEntryFailedWhiteList +
			     myGlobals.device[deviceId].sflowGlobals->numDstsFlowsEntryAccepted,
			     formatBuf2, sizeof(formatBuf2)));
    sendString(buf);
  }

  sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
             "<tr " TR_ON ">\n"
             "<th colspan=\"2\" "DARK_BG">Flow Analisys</th>\n"
             "</tr>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG ">Number of sFlow Samples Rcvd</th>\n"
		"<td " TD_BG " align=\"right\">%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].sflowGlobals->numsFlowsSamples, 
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG ">Number of sFlow Counter Updates Rcvd</th>\n"
		"<td " TD_BG " align=\"right\">%s</td>\n"
		"</tr>\n",
		formatPkts(myGlobals.device[deviceId].sflowGlobals->numsFlowCounterUpdates, 
			   formatBuf, sizeof(formatBuf)));
  sendString(buf);


#ifdef DEBUG
  sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
             "<tr " TR_ON ">\n"
             "<th colspan=\"2\" "DARK_BG">Debug></th>\n"
             "</tr>\n"
             "<tr " TR_ON ">\n"
             "<th " TH_BG " align=\"left\" "DARK_BG ">White net list</th>\n"
             "<td " TD_BG ">");

  if(myGlobals.device[deviceId].sflowGlobals->numWhiteNets == 0) {
    sendString("none");
  } else {
    sendString("Network&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
               "Netmask&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
               "Hostmask<br>\n");

    for(i=0; i<myGlobals.device[deviceId].sflowGlobals->numWhiteNets; i++) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<br>\n%3d.&nbsp;%08x(%3d.%3d.%3d.%3d)&nbsp;"
		    "%08x(%3d.%3d.%3d.%3d)&nbsp;%08x(%3d.%3d.%3d.%3d)",
		    i,
		    myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][0],
		    ((myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][0] >> 24) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][0] >> 16) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][0] >>  8) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][0]      ) & 0xff),
		    myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][1],
		    ((myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][1] >> 24) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][1] >> 16) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][1] >>  8) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][1]      ) & 0xff),
		    myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][2],
		    ((myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][2] >> 24) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][2] >> 16) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][2] >>  8) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->whiteNetworks[i][2]      ) & 0xff)
		    );
      sendString(buf);
      if(i<myGlobals.device[deviceId].sflowGlobals->numWhiteNets) sendString("<br>\n");
    }
  }

  sendString("</td>\n</tr>\n");

  sendString("<tr " TR_ON ">\n"
             "<th " TH_BG " align=\"left\" "DARK_BG ">Black net list</th>\n"
             "<td " TD_BG ">");

  if(myGlobals.device[deviceId].sflowGlobals->numBlackNets == 0) {
    sendString("none");
  } else {
    sendString("Network&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
               "Netmask&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
               "Hostmask<br>\n");

    for(i=0; i<myGlobals.device[deviceId].sflowGlobals->numBlackNets; i++) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<br>\n%3d.&nbsp;%08x(%3d.%3d.%3d.%3d)&nbsp;"
		    "%08x(%3d.%3d.%3d.%3d)&nbsp;%08x(%3d.%3d.%3d.%3d)",
		    i,
		    myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][0],
		    ((myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][0] >> 24) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][0] >> 16) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][0] >>  8) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][0]      ) & 0xff),
		    myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][1],
		    ((myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][1] >> 24) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][1] >> 16) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][1] >>  8) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][1]      ) & 0xff),
		    myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][2],
		    ((myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][2] >> 24) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][2] >> 16) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][2] >>  8) & 0xff),
		    ((myGlobals.device[deviceId].sflowGlobals->blackNetworks[i][2]      ) & 0xff)
		    );
      sendString(buf);
      if(i<myGlobals.device[deviceId].sflowGlobals->numBlackNets) sendString("<br>\n");
    }
  }

  sendString("</td>\n</tr>\n");

#endif
}

/* ****************************** */

static int createsFlowDevice(int sflowDeviceId) {
  int deviceId;
  char buf[32], value[128];

  traceEvent(CONST_TRACE_INFO, "SFLOW: createsFlowDevice(%d)", sflowDeviceId);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s.%d", SFLOW_DEVICE_NAME, sflowDeviceId);
  deviceId = createDummyInterface(buf);

  if(deviceId != -1) {
    myGlobals.device[deviceId].sflowGlobals = (SflowGlobals*)malloc(sizeof(SflowGlobals));

    if(myGlobals.device[deviceId].sflowGlobals == NULL) {
      /* Not enough memory */
      traceEvent(CONST_TRACE_ERROR, "SFLOW: not enough memory (sflowGlobals malloc)");
      return(-1);
    }

    memset(myGlobals.device[deviceId].sflowGlobals, 0, sizeof(SflowGlobals));

    myGlobals.device[deviceId].activeDevice = 1;
    myGlobals.device[deviceId].sflowGlobals->sflowDeviceId = sflowDeviceId;
    initsFlowDevice(deviceId);

    if(fetchPrefsValue(sfValue(deviceId, "humanFriendlyName", 1), value, sizeof(value)) != -1) {
      free(myGlobals.device[deviceId].humanFriendlyName);
      myGlobals.device[deviceId].humanFriendlyName = strdup(value);
      calculateUniqueInterfaceName(deviceId);
    }

    traceEvent(CONST_TRACE_INFO, "SFLOW: createsFlowDevice created device %d",
	       deviceId);
  } else
    traceEvent(CONST_TRACE_ERROR, "SFLOW: createDummyInterface failed");

  return(deviceId);
}

/* ****************************** */

static int mapsFlowDeviceToNtopDevice(int sflowDeviceId) {
  int i;

  for(i=0; i<myGlobals.numDevices; i++)
    if((myGlobals.device[i].sflowGlobals != NULL)
       && myGlobals.device[i].activeDevice
       && (myGlobals.device[i].sflowGlobals->sflowDeviceId == sflowDeviceId)) {
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "SFLOW: mapsFlowDeviceToNtopDevice(%d) = %d",
		 sflowDeviceId, i);
#endif
      return(i);
    } else if(myGlobals.device[i].sflowGlobals != NULL) {
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "SFLOW: mapsFlowDeviceToNtopDevice (id=%d) <=> (sflowDeviceId=%d)",
		 i, myGlobals.device[i].sflowGlobals->sflowDeviceId);
#endif
    }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "SFLOW: mapsFlowDeviceToNtopDevice(%d) failed\n",
	     sflowDeviceId);
#endif

  return(-1); /* Not found */
}

/* ****************************** */

static char *ifType(u_int32_t interface_type) {
  static char buf[8];

  switch(interface_type) {
  case 1: return("other");
  case 2: return("regular1822");
  case 3: return("hdh1822");
  case 4: return("ddn-x25");
  case 5: return("rfc877-x25");
  case 6: return("ethernet");
  case 7: return("iso88023-csmacd");
  case 8: return("iso88024-tokenBus");
  case 9: return("iso88025-tokenRing");
  case 10: return("iso88026-man");
  case 11: return("starLan");
  case 12: return("proteon-10Mbit");
  case 13: return("proteon-80Mbit");
  case 14: return("hyperchannel");
  case 15: return("fddi");
  case 16: return("lapb");
  case 17: return("sdlc");
  case 18: return("ds1");
  case 19: return("e1");
  case 20: return("basicISDN");
  case 21: return("primaryISDN");
  case 22: return("propPointToPointSerial");
  case 23: return("ppp");
  case 24: return("softwareLoopback");
  case 25: return("eon");
  case 26: return("ethernet-3Mbit");
  case 27: return("nsip");
  case 28: return("slip");
  case 29: return("ultra");
  case 30: return("ds3");
  case 31: return("sip");
  case 32: return("frame-relay");
  case 33: return("rs232");
  case 34: return("para");
  case 35: return("arcnet");
  case 36: return("arcnetPlus");
  case 37: return("atm");
  case 38: return("miox25");
  case 39: return("sonet");
  case 40: return("x25ple");
  case 41: return("iso88022llc");
  case 42: return("localTalk");
  case 43: return("smdsDxi");
  case 44: return("frameRelayService");
  case 45: return("v35");
  case 46: return("hssi");
  case 47: return("hippi");
  case 48: return("modem");
  case 49: return("aal5");
  case 50: return("sonetPath");
  case 51: return("sonetVT");
  case 52: return("smdsIcip");
  case 53: return("propVirtual");
  case 54: return("propMultiplexor");
  case 55: return("100BaseVG");
  case 56: return("Fibre Channel");
  case 57: return("HIPPI Interface");
  case 58: return("Obsolete for FrameRelay");
  case 59: return("ATM Emulation of 802.3 LAN");
  case 60: return("ATM Emulation of 802.5 LAN");
  case 61: return("ATM Emulation of a Circuit");
  case 62: return("FastEthernet (100BaseT)");
  case 63: return("ISDN &amp; X.25");
  case 64: return("CCITT V.11/X.21");
  case 65: return("CCITT V.36");
  case 66: return("CCITT G703 at 64Kbps");
  case 67: return("Obsolete G702 see DS1-MIB");
  case 68: return("SNA QLLC");
  case 69: return("Full Duplex Fast Ethernet (100BaseFX)");
  case 70: return("Channel");
  case 71: return("Radio Spread Spectrum (802.11)");
  case 72: return("IBM System 360/370 OEMI Channel");
  case 73: return("IBM Enterprise Systems Connection");
  case 74: return("Data Link Switching");
  case 75: return("ISDN S/T Interface");
  case 76: return("ISDN U Interface");
  case 77: return("Link Access Protocol D (LAPD)");
  case 78: return("IP Switching Opjects");
  case 79: return("Remote Source Route Bridging");
  case 80: return("ATM Logical Port");
  case 81: return("AT&amp;T DS0 Point (64 Kbps)");
  case 82: return("AT&amp;T Group of DS0 on a single DS1");
  case 83: return("BiSync Protocol (BSC)");
  case 84: return("Asynchronous Protocol");
  case 85: return("Combat Net Radio");
  case 86: return("ISO 802.5r DTR");
  case 87: return("Ext Pos Loc Report Sys");
  case 88: return("Apple Talk Remote Access Protocol");
  case 89: return("Proprietary Connectionless Protocol");
  case 90: return("CCITT-ITU X.29 PAD Protocol");
  case 91: return("CCITT-ITU X.3 PAD Facility");
  case 92: return("MultiProtocol Connection over Frame/Relay");
  case 93: return("CCITT-ITU X213");
  case 94: return("Asymetric Digitial Subscriber Loop (ADSL)");
  case 95: return("Rate-Adapt Digital Subscriber Loop (RDSL)");
  case 96: return("Symetric Digitial Subscriber Loop (SDSL)");
  case 97: return("Very High Speed Digitial Subscriber Loop (HDSL)");
  case 98: return("ISO 802.5 CRFP");
  case 99: return("Myricom Myrinet");
  case 100: return("Voice recEive and transMit (voiceEM)");
  case 101: return("Voice Foreign eXchange Office (voiceFXO)");
  case 102: return("Voice Foreign eXchange Station (voiceFXS)");
  case 103: return("Voice Encapulation");
  case 104: return("Voice Over IP Encapulation");
  case 105: return("ATM DXI");
  case 106: return("ATM FUNI");
  case 107: return("ATM IMA");
  case 108: return("PPP Multilink Bundle");
  case 109: return("IBM IP over CDLC");
  case 110: return("IBM Common Link Access to Workstation");
  case 111: return("IBM Stack to Stack");
  case 112: return("IBM Virtual IP Address (VIPA)");
  case 113: return("IBM Multi-Protocol Channel Support");
  case 114: return("IBM IP over ATM");
  case 115: return("ISO 802.5j Fiber Token Ring");
  case 116: return("IBM Twinaxial Data Link Control (TDLC)");
  case 117: return("Gigabit Ethernet");
  case 118: return("Higher Data Link Control (HDLC)");
  case 119: return("Link Access Protocol F (LAPF)");
  case 120: return("CCITT V.37");
  case 121: return("CCITT X.25 Multi-Link Protocol");
  case 122: return("CCITT X.25 Hunt Group");
  case 123: return("Transp HDLC");
  case 124: return("Interleave Channel");
  case 125: return("Fast Channel");
  case 126: return("IP (for APPN HPR in IP Networks)");
  case 127: return("CATV MAC Layer");
  case 128: return("CATV Downstream Interface");
  case 129: return("CATV Upstream Interface");
  case 130: return("Avalon Parallel Processor");
  case 131: return("Encapsulation Interface");
  case 132: return("Coffee Pot");
  case 133: return("Circuit Emulation Service");
  case 134: return("ATM Sub Interface");
  case 135: return("Layer 2 Virtual LAN using 802.1Q");
  case 136: return("Layer 3 Virtual LAN using IP");
  case 137: return("Layer 3 Virtual LAN using IPX");
  case 138: return("IP Over Power Lines");
  case 139: return("Multi-Media Mail over IP");
  case 140: return("Dynamic synchronous Transfer Mode (DTM)");
  case 141: return("Data Communications Network");
  case 142: return("IP Forwarding Interface");
  case 162: return("Cisco Express Forwarding Interface");
  default: 
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", interface_type);
    return(buf);
  }
}

/* ****************************** */

static char *ifDirection(u_int32_t interface_direction) {
  switch(interface_direction) {
  case 0: return("unknown");
  case 1: return("full-duplex");
  case 2: return("half-duplex");
  case 3: return("in");
  case 4: return("out");
  default: return("?");
  }
}

/* ****************************** */

static char *ifStatus(u_int32_t interface_status) {
  switch(interface_status) {
  case 0: return("<FONT COLOR=red>Administrative</FONT><br><FONT COLOR=red>Operational</FONT>");
  case 1: return("<FONT COLOR=green>Administrative</FONT><br><FONT COLOR=red>Operational</FONT>");
  case 2: return("<FONT COLOR=red>Administrative</FONT><br><FONT COLOR=green>Operational</FONT>");
  case 3: return("<FONT COLOR=green>Administrative</FONT><br><FONT COLOR=green>Operational</FONT>");
  default: return("?");
  }
}

/* ****************************** */

static void flushDevicePrefs(int deviceId) {
  if(deviceId >= myGlobals.numDevices) return;
  delPrefsValue(sfValue(deviceId, "ifNetMask", 1));
  delPrefsValue(sfValue(deviceId, "whiteList", 1));
  delPrefsValue(sfValue(deviceId, "sflowInPort", 1));
  delPrefsValue(sfValue(deviceId, "blackList", 1));
  delPrefsValue(sfValue(deviceId, "enableSessionHandling", 1));
  delPrefsValue(sfValue(deviceId, "sflowAssumeFTP", 1));
  delPrefsValue(sfValue(deviceId, "sflowAggregation", 1));
  delPrefsValue(sfValue(deviceId, "debug", 1));
  delPrefsValue(sfValue(deviceId, "humanFriendlyName", 1));
}

/* ****************************** */

static void handlesFlowHTTPrequest(char* _url) {
  char workList[1024], *url;
  int deviceId = -1, originalId = -1;

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);

  /* ****************************
   * Process URL stuff          *
   ****************************** */

  if((_url != NULL) && pluginActive) {
    char *strtokState;

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

	  if((deviceId > 0) && ((deviceId = mapsFlowDeviceToNtopDevice(deviceId)) == -1)) {
	    printHTMLheader("sFlow Configuration Error", NULL, 0);
	    printFlagedWarning("<I>Unable to locate the specified device. Please activate the plugin first.</I>");
	    return;
	  }
	} else if(strcmp(device, "port") == 0) {
	  if(myGlobals.device[deviceId].sflowGlobals->sflowInPort != atoi(value)) {
	    if(deviceId > 0) {
	      myGlobals.device[deviceId].sflowGlobals->sflowInPort = atoi(value);
	      storePrefsValue(sfValue(deviceId, "sflowInPort", 1), value);
	      setsFlowInSocket(deviceId);
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
	  storePrefsValue(sfValue(deviceId, "humanFriendlyName", 1), value);

	  calculateUniqueInterfaceName(deviceId);

	  safe_snprintf(__FILE__, __LINE__, new_name, sizeof(new_name),
			"%s/interfaces/%s", myGlobals.rrdPath, 
			myGlobals.device[deviceId].uniqueIfName);
	  revertSlashIfWIN32(new_name, 0);
	  
	  if(rename(old_name, new_name) != 0) {
	    traceEvent(CONST_TRACE_ERROR, 
		       "SFLOW: Error renaming %s -> %s", 
		       old_name, new_name);
	  }
	} else if(strcmp(device, "debug") == 0) {
	  if(deviceId > 0) {
	    myGlobals.device[deviceId].sflowGlobals->sflowDebug = atoi(value);
	    storePrefsValue(sfValue(deviceId, "debug", 1), value);
	  }
	} else if(strcmp(device, "ifNetMask") == 0) {
	  int a, b, c, d, a1, b1, c1, d1;

	  if(deviceId > 0) {
	    if(sscanf(value, "%d.%d.%d.%d/%d.%d.%d.%d",
		      &a, &b, &c, &d, &a1, &b1, &c1, &d1) == 8) {
	      myGlobals.device[deviceId].sflowGlobals->sflowIfAddress.s_addr = (a << 24) +(b << 16) +(c << 8) + d;
	      myGlobals.device[deviceId].sflowGlobals->sflowIfMask.s_addr    = (a1 << 24) +(b1 << 16) +(c1 << 8) + d1;
	      storePrefsValue(sfValue(deviceId, "ifNetMask", 1), value);
	    } else if(sscanf(value, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &a1) == 5) {
	      myGlobals.device[deviceId].sflowGlobals->sflowIfAddress.s_addr = (a << 24) +(b << 16) +(c << 8) + d;
	      myGlobals.device[deviceId].sflowGlobals->sflowIfMask.s_addr    = 0xffffffff >> a1;
	      myGlobals.device[deviceId].sflowGlobals->sflowIfMask.s_addr =~
		myGlobals.device[deviceId].sflowGlobals->sflowIfMask.s_addr;
	      storePrefsValue(sfValue(deviceId, "ifNetMask", 1), value);
	    } else
	      traceEvent(CONST_TRACE_ERROR, "SFLOW: HTTP request netmask parse error (%s)", value);
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

	    accessMutex(&myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex,
			"handlesFlowHTTPrequest()w");
	    handleWhiteBlackListAddresses(value,
					  myGlobals.device[deviceId].sflowGlobals->whiteNetworks,
					  &myGlobals.device[deviceId].sflowGlobals->numWhiteNets,
					  (char*)&workList,
					  sizeof(workList));
	    if(myGlobals.device[deviceId].sflowGlobals->sflowWhiteList != NULL)
	      free(myGlobals.device[deviceId].sflowGlobals->sflowWhiteList);
	    myGlobals.device[deviceId].sflowGlobals->sflowWhiteList=strdup(workList);
	    releaseMutex(&myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex);
	    storePrefsValue(sfValue(deviceId, "whiteList", 1),
			    myGlobals.device[deviceId].sflowGlobals->sflowWhiteList);
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

	    accessMutex(&myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex,
			"handlesFlowHTTPrequest()b");
	    handleWhiteBlackListAddresses(value,
					  myGlobals.device[deviceId].sflowGlobals->blackNetworks,
					  &myGlobals.device[deviceId].sflowGlobals->numBlackNets,
					  (char*)&workList,
					  sizeof(workList));
	    if(myGlobals.device[deviceId].sflowGlobals->sflowBlackList != NULL)
	      free(myGlobals.device[deviceId].sflowGlobals->sflowBlackList);
	    myGlobals.device[deviceId].sflowGlobals->sflowBlackList=strdup(workList);
	    releaseMutex(&myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex);
	    storePrefsValue(sfValue(deviceId, "blackList", 1),
			    myGlobals.device[deviceId].sflowGlobals->sflowBlackList);
	  }
	}
      }

      url = strtok_r(NULL, "&", &strtokState);
    }
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "SFLOW: deviceId=%d", deviceId);
#endif

  if(deviceId == -1) {
    printHTMLheader("sFlow Device Configuration", NULL, 0);

    printsFlowDeviceConfiguration();
    return;
  } else if(deviceId < 0) {
    /* Delete an existing device */
    char value[128];
    int readDeviceId;

    deviceId = -deviceId;

    if((deviceId < 0) || ((readDeviceId = mapsFlowDeviceToNtopDevice(deviceId)) == -1)) {
      printHTMLheader("sFlow Configuration Error", NULL, 0);
      printFlagedWarning("<I>Unable to locate the specified device. Please activate the plugin first.</I>");
      return;
    }

    if(SFLOW_DEBUG(deviceId)) 
      traceEvent(CONST_TRACE_INFO, "SFLOW: Attempting to delete [deviceId=%d][sFlow device=%d]",
		 deviceId, readDeviceId);

    if(fetchPrefsValue(sfValue(deviceId, "knownDevices", 0), value, sizeof(value)) != -1) {
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

      storePrefsValue(sfValue(deviceId, "knownDevices", 0), value1);
    }

    myGlobals.device[readDeviceId].activeDevice = 0; // Terminate thread
    flushDevicePrefs(readDeviceId);

    // termsFlowDevice(readDeviceId);

    checkReportDevice();
    printHTMLheader("sFlow Device Configuration", NULL, 0);
    printsFlowDeviceConfiguration();
    return;
  } else if(deviceId == 0) {
    /* Add new device */
    char value[128];

    if((fetchPrefsValue(sfValue(deviceId, "knownDevices", 0), value, sizeof(value)) != -1)
       && (strlen(value) > 0)) {
      char *strtokState, *dev, value1[128], buf[256];

      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "SFLOW: knownDevices=%s", value);

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

      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "SFLOW: knownDevices=%s", buf);
      storePrefsValue(sfValue(deviceId, "knownDevices", 0), buf);
    } else {
      deviceId = 2; /* 1 is reserved */
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "SFLOW: knownDevices=2");
      storePrefsValue(sfValue(deviceId, "knownDevices", 0), "2");
    }

    if((deviceId = createsFlowDevice(deviceId)) <= 0) {
      printHTMLheader("sFlow Configuration Error", NULL, 0);
      printFlagedWarning("<I>Unable to create a new sFlow device</I>");
      return;
    }
  } else {
    /* Existing device */
  }

  if(deviceId > 0) {
    /* ****************************
     * Print Configuration stuff  *
     ****************************** */
    printHTMLheader("sFlow Configuration", NULL, 0);
    printsFlowConfiguration(deviceId);

    if(myGlobals.device[deviceId].sflowGlobals->numsFlowsPktsRcvd > 0) {
      u_int headerSent = 0;
      IfCounters *ifName = myGlobals.device[deviceId].sflowGlobals->ifCounters;
      char buf[512], formatBuf[256], formatBuf1[256];

      sendString("<br><hr><p>\n");

      /* ****************************
       * Print interface statistics *
       ****************************** */

      while(ifName != NULL) {
	if(!headerSent) {
	  printSectionTitle("sFlow Interface Statistics");
	  sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");
	  sendString("<tr><th>Idx</th><th>Type</th><th>Speed</th><th>Direction</th><th>Status</th><th>Promisc</th>"
		     "<th>Octets</th><th>Unicasts<br>Packets</th><th>Multicasts<br>Packets</th><th>Broadcasts<br>Packets</th>"
		     "<th>Discards<br>Packets</th><th>Errors<br>Packets</th><th>Unkn Proto<br>Packets</th><th>&nbsp;</th></tr>\n");
	  headerSent = 1;
	}

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<tr><th>%u</th>",
		      ifName->ifIndex); sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%s</td>",
		      ifType(ifName->ifType)); sendString(buf);

	if(ifName->ifSpeed >= 10000000) {
	  u_int32_t speed = ifName->ifSpeed / 1000000;
	    
	  if(speed < 1000)
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%u&nbsp;Mbit</td>",
			  speed);
	  else
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%u&nbsp;Gbit</td>",
			  speed/1000);

	  sendString(buf);
	} else {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%u</td>",
			ifName->ifSpeed);
	  sendString(buf);
	}
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%s</td>",
		      ifDirection(ifName->ifDirection)); sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%s</td>",
		      ifStatus(ifName->ifStatus)); sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%u</td>",
		      ifName->ifPromiscuousMode); sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%s<br>%s</td>",
		      formatBytes(ifName->ifInOctets, 1, formatBuf, sizeof(formatBuf)),
		      formatBytes(ifName->ifOutOctets, 1, formatBuf1, sizeof(formatBuf1))); sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%s<br>%s</td>",
		      formatPkts(ifName->ifInUcastPkts, formatBuf, sizeof(formatBuf)),
		      formatPkts(ifName->ifOutUcastPkts, formatBuf1, sizeof(formatBuf1))); sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%s<br>%s</td>",
		      formatPkts(ifName->ifInMulticastPkts, formatBuf, sizeof(formatBuf)),
		      formatPkts(ifName->ifOutMulticastPkts, formatBuf1, sizeof(formatBuf1))); sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%s<br>%s</td>",
		      formatPkts(ifName->ifInBroadcastPkts, formatBuf, sizeof(formatBuf)),
		      formatPkts(ifName->ifOutBroadcastPkts, formatBuf1, sizeof(formatBuf1))); sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%s<br>%s</td>",
		      formatPkts(ifName->ifInDiscards, formatBuf, sizeof(formatBuf)),
		      formatPkts(ifName->ifOutDiscards, formatBuf1, sizeof(formatBuf1))); sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%s<br>%s</td>",
		      formatPkts(ifName->ifInErrors, formatBuf, sizeof(formatBuf)),
		      formatPkts(ifName->ifOutErrors, formatBuf, sizeof(formatBuf1))); sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center>%s</td>",
		      formatPkts(ifName->ifInUnknownProtos, formatBuf, sizeof(formatBuf))); sendString(buf);
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<td align=center><A HREF=\"/plugins/rrdPlugin?action=list&key="
		      "interfaces%s%s/sFlow/%u&title=Interface+Id+%u\">"
		      "<IMG SRC=/graph.gif BORDER=0></A></td></tr>",
		      (myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName[0] == '/') ? "" : "/",
		      myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
		      ifName->ifIndex, ifName->ifIndex,
		      formatPkts(ifName->ifInUnknownProtos, formatBuf, sizeof(formatBuf))); 
	sendString(buf);
	ifName = ifName->next;
      }

      if(headerSent) sendString("</table><p><table><tr><td>Note: Counters are represented as "
				"</td><td align=center>input value<br>output value</td></tr></table></center><p>\n");

      /* ****************************
       * Print statistics           *
       ****************************** */
      printSectionTitle("Flow Statistics");

      sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");

      if(myGlobals.device[deviceId].sflowGlobals->numsFlowsPktsRcvd > 0)
	printsFlowStatisticsRcvd(deviceId);

      sendString("</table>\n</center>\n");

      sendString("<p><table border=\"0\"><tr><td width=\"25%\" valign=\"top\" align=\"right\">"
		 "<b>NOTES</b>:</td>\n"
		 "<td><ul>"
		 "<li>The virtual NIC, '" SFLOW_DEVICE_NAME "' is activated only when incoming "
		 "flow capture is enabled.</li>\n"
		 "<li>Once the virtual NIC is activated, it will remain available for the "
		 "duration of the ntop run, even if you disable incoming flows.</li>\n"
		 "<li>sFlow packets are associated with this separate, virtual device and are "
		 "not mixed with captured packets.</li>\n"
		 "<li>Activating incoming flows will override the command line -M | "
		 "--no-interface-merge parameter for the duration of the ntop run.</li>\n"
		 "<li>sFlow activation may (rarely) require ntop restart.</li>\n"
		 "<li>You can switch the reporting device using Admin | Switch NIC, or this "
		 "<a href=\"/" CONST_SWITCH_NIC_HTML "\" title=\"Switch NIC\">link</a>.</li>\n"
		 "</ul></td>\n"
		 "<td width=\"25%\">&nbsp;</td>\n</tr>\n</table>\n");

#ifdef MUTEX_DEBUG
      if(myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex.isLocked) {
	sendString("<table><tr><td colspan=\"2\">&nbsp;</td></tr>\n"
		   "<tr " TR_ON ">\n"
		   "<th colspan=\"2\" "DARK_BG">Mutexes</th>\n"
		   "</tr>\n");

	sendString("<tr " TR_ON ">\n"
		   "<th>List Mutex</th>\n<td><table>");
	printMutexStatus(FALSE, &myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex,
			 "White/Black list mutex");
	sendString("</table><td></tr></table>\n");
      }
#endif
    }
  }

  safe_snprintf(__FILE__, __LINE__, workList, sizeof(workList), "%s?device=%d",
		sflowPluginInfo->pluginURLname, originalId);

  printPluginTrailer((myGlobals.device[deviceId].sflowGlobals->numsFlowsPktsRcvd > 0) ?
		     workList : NULL,
                     "sFlow is a trademark of <a href=\"http://www.inmon.com/\" "
                     "title=\"InMon home page\">InMon Corporation</a>");

  printHTMLtrailer();
}

/* ****************************** */

static void termsFlowDevice(int deviceId) {
  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "SFLOW: terminating deviceId=%d", deviceId);

  if(!pluginActive) return;

  if(myGlobals.device[deviceId].activeDevice == 0) {
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_WARNING, "SFLOW: deviceId=%d terminated already", deviceId);
    return;
  }

  if(myGlobals.device[deviceId].sflowGlobals == NULL) {
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_WARNING, "SFLOW: deviceId=%d terminating a non-sFlow device", deviceId);
    return;
  }

  if((deviceId >= 0) && (deviceId < myGlobals.numDevices)) {
    if(myGlobals.device[deviceId].sflowGlobals->threadActive) {
      killThread(&myGlobals.device[deviceId].sflowGlobals->sflowThread);
      myGlobals.device[deviceId].sflowGlobals->threadActive = 0;
    }
    tryLockMutex(&myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex, "termsFlow");
    deleteMutex(&myGlobals.device[deviceId].sflowGlobals->whiteblackListMutex);

    if(myGlobals.device[deviceId].sflowGlobals->sflowInSocket > 0) {
	closeNwSocket(&myGlobals.device[deviceId].sflowGlobals->sflowInSocket);
	shutdown(myGlobals.device[deviceId].sflowGlobals->sflowInSocket, SHUT_RDWR);
    }

    while(myGlobals.device[deviceId].sflowGlobals->ifCounters != NULL) {
      IfCounters *next = myGlobals.device[deviceId].sflowGlobals->ifCounters->next;
      free(myGlobals.device[deviceId].sflowGlobals->ifCounters);
      myGlobals.device[deviceId].sflowGlobals->ifCounters = next;
    }

    free(myGlobals.device[deviceId].sflowGlobals);
    myGlobals.device[deviceId].activeDevice = 0;
  } else
    if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_WARNING, "SFLOW: requested invalid termination of deviceId=%d", deviceId);
}

/* **************************************** */

static void termsFlowFunct(u_char termNtop /* 0=term plugin, 1=term ntop */) {
  char value[128];

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "SFLOW: Terminating sFlow");

  if((fetchPrefsValue(sfValue(0, "knownDevices", 0), value, sizeof(value)) != -1) && (strlen(value) > 0)) {
    char *strtokState, *dev;

    dev = strtok_r(value, ",", &strtokState);
    while(dev != NULL) {
      int deviceId, theDeviceId = atoi(dev);

      if((theDeviceId > 0) && ((deviceId = mapsFlowDeviceToNtopDevice(theDeviceId)) > 0)) {
	termsFlowDevice(deviceId);
      } else
	traceEvent(CONST_TRACE_INFO, "NETFLOW: [sflowDeviceId=%d] device thread terminated in the meantime", theDeviceId);

      dev = strtok_r(NULL, ",", &strtokState);
    }
  } else
    traceEvent(CONST_TRACE_INFO, "SFLOW: no devices to terminate (%s)", value);

  traceEvent(CONST_TRACE_INFO, "SFLOW: Thanks for using ntop sFlow");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "SFLOW: Done");
  fflush(stdout);
  pluginActive = 0;
}

/* **************************************** */

#ifdef DEBUG_FLOWS

static void handlesFlowPacket(u_char *_deviceId,
			      const struct pcap_pkthdr *h,
			      const u_char *p) {
  int deviceId;

  if(myGlobals.pcap_file_list->fileName != NULL) {
    /* ntop is reading packets from a file */
    struct ether_header ehdr;
    u_int32_t caplen = h->caplen;
    u_int32_t length = h->len;
    unsigned short eth_type;
    struct ip ip;

    deviceId = 1; /* Dummy value */

    if(myGlobals.device[deviceId].sflowGlobals == NULL)
      deviceId = 2;
    
    if(myGlobals.device[deviceId].sflowGlobals == NULL) {
      traceEvent(CONST_TRACE_INFO, "NULL device (%d)", deviceId);
      return;
    }

#ifdef DEBUG_FLOWS
    if(0)
      if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, 
					   "Rcvd packet to dissect [caplen=%d][len=%d]", 
					   caplen, length);
#endif

    if(caplen >= sizeof(struct ether_header)) {
      int displ = sizeof(struct ether_header);

      memcpy(&ehdr, p, displ);
      eth_type = ntohs(ehdr.ether_type);

#ifdef DEBUG_FLOWS
      /* 
	 Quick patch for files captures with 
	 Linux cooked capture (i.e. -i any)
      */

      if(eth_type != ETHERTYPE_IP) {
	eth_type = ETHERTYPE_IP, displ = 16;
      }
#endif

      if(eth_type == ETHERTYPE_IP) {
	u_int32_t plen, hlen;

#ifdef DEBUG_FLOWS
	if(0)
	  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "Rcvd IP packet to dissect");
#endif

	memcpy(&ip, p+displ, sizeof(struct ip));
	hlen =(u_int32_t)ip.ip_hl * 4;
	NTOHL(ip.ip_dst.s_addr); NTOHL(ip.ip_src.s_addr);

	plen = length-displ;

#ifdef DEBUG_FLOWS
	  if(SFLOW_DEBUG(deviceId)) 
	    traceEvent(CONST_TRACE_INFO, "Rcvd IP packet to dissect [deviceId=%d][sender=%s][proto=%d][len=%d][hlen=%d]",
		       deviceId, intoa(ip.ip_src), ip.ip_p, plen, hlen);
#endif

	if(ip.ip_p == IPPROTO_UDP) {
	  if(plen >(hlen+sizeof(struct udphdr))) {
	    SFSample sample;
	    char* rawSample    =(char*)(p+displ+hlen+sizeof(struct udphdr));
	    int   rawSampleLen = h->caplen-(displ+hlen+sizeof(struct udphdr));

#ifdef DEBUG_FLOWS
	      if(SFLOW_DEBUG(deviceId)) 
		traceEvent(CONST_TRACE_INFO, "Rcvd from from %s", 
			   intoa(ip.ip_src));
#endif

	    myGlobals.device[deviceId].sflowGlobals->numsFlowsPktsRcvd++;

	    memset(&sample, 0, sizeof(sample));
	    sample.rawSample    = (u_char*)rawSample;
	    sample.rawSampleLen = rawSampleLen;
	    sample.sourceIP     = ip.ip_src;
	    sample.datap        = (u_int32_t *)sample.rawSample;
	    sample.endp         = (u_char *)sample.rawSample + sample.rawSampleLen;

	    dissectFlow(&sample, deviceId);
	  }
	}
      } else {
#ifdef DEBUG_FLOWS
	if(0)
	  if(SFLOW_DEBUG(deviceId)) traceEvent(CONST_TRACE_INFO, "Rcvd non-IP [0x%04X] packet to dissect", eth_type);
#endif
      }
    }
  }
}

#endif

/* ***************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGIN
PluginInfo* sflowPluginEntryFctn(void)
#else
     PluginInfo* PluginEntryFctn(void)
#endif
{
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, 
	     "SFLOW: Welcome to %s.(C) 2002-12 by Luca Deri",
	     sflowPluginInfo->pluginName);

  return(sflowPluginInfo);
}

/* This must be here so it can access the struct PluginInfo, above */
static void setPluginStatus(char * status)
{
  if(sflowPluginInfo->pluginStatusMessage != NULL)
    free(sflowPluginInfo->pluginStatusMessage);
  if(status == NULL) {
    sflowPluginInfo->pluginStatusMessage = NULL;
  } else {
    sflowPluginInfo->pluginStatusMessage = strdup(status);
  }
}

/* ************************************************** */

