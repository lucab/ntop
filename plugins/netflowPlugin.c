/*
 *  Copyright(C) 2002-04 Luca Deri <deri@ntop.org>
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

/* This plugin works only with threads */

#include "ntop.h"
#include "globals-report.h"

/* *************************** */

#define CONST_FLOW_VERSION_1		    1
#define CONST_V1FLOWS_PER_PAK		    30

#define CONST_FLOW_VERSION_5		    5
#define CONST_V5FLOWS_PER_PAK		    30

#define CONST_FLOW_VERSION_7		    7
#define CONST_V7FLOWS_PER_PAK		    28

/*
  For more info see:

  http://www.cisco.com/warp/public/cc/pd/iosw/ioft/neflct/tech/napps_wp.htm

  ftp://ftp.net.ohio-state.edu/users/maf/cisco/
*/

/* ********************************* */

struct flow_ver1_hdr {
  u_int16_t version;         /* Current version = 1*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
};

struct flow_ver1_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration */
  u_int32_t dOctets;    /* Octets sent in Duration */
  u_int32_t First;      /* SysUptime at start of flow */
  u_int32_t Last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t pad;        /* pad to word boundary */
  u_int8_t  prot;       /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int8_t  pad2[7];    /* pad to word boundary */
};

typedef struct single_flow_ver1_rec {
  struct flow_ver1_hdr flowHeader;
  struct flow_ver1_rec flowRecord[CONST_V1FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow1Record;

/* ********************************* */

struct flow_ver5_hdr {
  u_int16_t version;         /* Current version=5*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int8_t  engine_type;     /* Type of flow switching engine (RP,VIP,etc.)*/
  u_int8_t  engine_id;       /* Slot number of the flow switching engine */
};

struct flow_ver5_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration (milliseconds between 1st
			   & last packet in this flow)*/
  u_int32_t dOctets;    /* Octets sent in Duration (milliseconds between 1st
			   & last packet in  this flow)*/
  u_int32_t First;      /* SysUptime at start of flow */
  u_int32_t Last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t  pad1;       /* pad to word boundary */
  u_int8_t  tcp_flags;  /* Cumulative OR of tcp flags */
  u_int8_t  prot;       /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int8_t  dst_mask;   /* destination route's mask bits */
  u_int8_t  src_mask;   /* source route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
};

typedef struct single_flow_ver5_rec {
  struct flow_ver5_hdr flowHeader;
  struct flow_ver5_rec flowRecord[CONST_V5FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow5Record;

/* ********************************* */

struct flow_ver7_hdr {
  u_int16_t version;         /* Current version=7*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int32_t reserved;
};

struct flow_ver7_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration */
  u_int32_t dOctets;    /* Octets sent in Duration */
  u_int32_t First;      /* SysUptime at start of flow */
  u_int32_t Last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t  flags;      /* Shortcut mode(dest only,src only,full flows*/
  u_int8_t  tcp_flags;  /* Cumulative OR of tcp flags */
  u_int8_t  prot;       /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int8_t  dst_mask;   /* destination route's mask bits */
  u_int8_t  src_mask;   /* source route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
  u_int32_t router_sc;  /* Router which is shortcut by switch */
};

typedef struct single_flow_ver7_rec {
  struct flow_ver7_hdr flowHeader;
  struct flow_ver7_rec flowRecord[CONST_V7FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow7Record;

/* ************************************ */

/* NetFlow v9/IPFIX */

typedef struct flow_ver9_hdr {
  u_int16_t version;         /* Current version=9*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int32_t sourceId;        /* Source id */
} V9FlowHeader;

typedef struct flow_ver9_template_field {
  u_int16_t fieldType;
  u_int16_t fieldLen;
} V9TemplateField;

typedef struct flow_ver9_template {
  u_int16_t templateFlowset; /* = 0 */
  u_int16_t flowsetLen;
  u_int16_t templateId;
  u_int16_t fieldCount;
} V9Template;

typedef struct flow_ver9_flow_set {
  u_int16_t templateId;
  u_int16_t flowsetLen;
} V9FlowSet;

typedef struct flow_ver9_templateids {
  u_int16_t templateId;
  u_int16_t templateLen;
  char      *templateDescr;
} V9TemplateId;

/* ******************************************* */

/* **************************************

   +------------------------------------+
   |           nFlow Header             |
   +------------------------------------+
   |           nFlow Flow 1             |
   +------------------------------------
   |           nFlow Flow 2             |
   +------------------------------------+
   ......................................
   +------------------------------------
   |           nFlow Flow n             |
   +------------------------------------+

   NOTE: nFlow records are sent in gzip format

   ************************************** */

#define NFLOW_SUM_LEN             16
#define NFLOW_SIZE_THRESHOLD    8192
#define MAX_PAYLOAD_LEN         1400
#define MAX_HASH_MUTEXES          32

/* nFlow Header */
typedef struct nflow_ver1_hdr_ext {
  /* NetFlow v5 header-like */
  u_int16_t version;         /* Current version=1 (nFlow v1) */
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  /* nFlow Extensions */
  u_int32_t sourceId;        /* Source id */
  u_int16_t sampleRate;      /* Sampling rate */
  u_int16_t pad;             /* Not Used */
  u_char    md5Sum[NFLOW_SUM_LEN];      /* MD5 summary */
} NflowV1Header;

typedef struct nflow_flow_item {
  u_int16_t fieldType;
  u_int16_t fieldLen;
  char      *flowData;
} NflowV1FlowItem;

/* nFlow Flow */
typedef struct nflow_flow {
  u_int16_t flowsetLen;
} NflowV1FlowRecord;

#define NFLOW_VERSION        24 /* nFlow 1.0 */

typedef struct flowTypes {
  u_int16_t templateId;
  u_int16_t templateLen;
  u_int16_t templateType; /* 0=number, 1=IPv4 */
  char      *templateDescr;
} FlowTypes;

#define NUM_TEMPLATES 88

/* ******************************************* */

#ifdef CFG_MULTITHREADED
static pthread_t netFlowThread;
static int threadActive;
static PthreadMutex whiteblackListMutex;
#endif

#ifdef HAVE_FILEDESCRIPTORBUG
static int tempNFFilesCreated=0;
static int  tempNFF[CONST_FILEDESCRIPTORBUG_COUNT], tempNFFpid;
static char tempNFFname[CONST_FILEDESCRIPTORBUG_COUNT][LEN_MEDIUM_WORK_BUFFER];
#endif

/* #define DEBUG_FLOWS */

static ProbeInfo probeList[MAX_NUM_PROBES];

static u_int32_t whiteNetworks[MAX_NUM_NETWORKS][3], blackNetworks[MAX_NUM_NETWORKS][3];
static u_short numWhiteNets, numBlackNets;
static u_int32_t flowIgnoredZeroPort, flowIgnoredNetFlow, flowProcessed;
static Counter flowIgnoredNetFlowBytes;
static Counter flowIgnoredZeroPortBytes, flowProcessedBytes;
static u_int flowIgnored[MAX_NUM_IGNOREDFLOWS][6]; /* src, sport, dst, dport, count, bytes */
static u_short nextFlowIgnored;
static HostTraffic *dummyHost;
static u_int dummyHostIdx;

/* ********************************* */

typedef struct flowSetV9 {
  V9Template templateInfo;
  V9TemplateField *fields;
  struct flowSetV9 *next;
} FlowSetV9;
static FlowSetV9 *templates = NULL;

/* ********************************* */

static u_int32_t flowIgnoredLowPort, flowIgnoredHighPort, flowAssumedFtpData;
static Counter flowIgnoredLowPortBytes, flowIgnoredHighPortBytes, flowAssumedFtpDataBytes;
static Counter nFlowTotCompressedSize = 0, nFlowTotUncompressedSize = 0;

/* Forward */
static int setNetFlowInSocket();
static void setNetFlowInterfaceMatrix();
static void freeNetFlowMatrixMemory();
static void setPluginStatus(char * status);
static void ignoreFlow(u_short* theNextFlowIgnored, u_int srcAddr, u_short sport,
		       u_int dstAddr, u_short dport, Counter len);
static int initNetFlowFunct(void);
static void termNetflowFunct(void);
#ifdef DEBUG_FLOWS
static void handleNetFlowPacket(u_char *_deviceId,
				const struct pcap_pkthdr *h,
				const u_char *p);
#endif
static void handleNetflowHTTPrequest(char* url);
static void printNetFlowStatisticsRcvd(void);
static void printNetFlowConfiguration(void);

/* ****************************** */

static PluginInfo netflowPluginInfo[] = {
  {
    VERSION, /* current ntop version */
    "NetFlow",
    "This plugin is used to setup, activate and deactivate nFlow/NetFlow support.<br>"
    "<b>ntop</b> can both collect and receive "
    "<a href=\"http://www.nflow.org/\" alt=\"link to nflow.org\">nFlow</A> "
    "and <A HREF=http://www.cisco.com/warp/public/cc/pd/iosw/ioft/neflct/tech/napps_wp.htm>NetFlow</A> "
    "V1/V5/V7/V9 data.<br>"
    "<i>Received flow data is reported as a separate 'NIC' in the regular <b>ntop</b> "
    "reports - <em>Remember to switch the reporting NIC via Admin | Switch NIC</em>.",
    "3.2", /* version */
    "<a href=\"http://luca.ntop.org/\" alt=\"Luca's home page\">L.Deri</A>",
    "NetFlow", /* http://<host>:<port>/plugins/NetFlow */
    0, /* Active by default */
    1, /* Inactive setup */
    initNetFlowFunct, /* InitFunc   */
    termNetflowFunct, /* TermFunc   */
#ifdef DEBUG_FLOWS
    handleNetFlowPacket,
#else
    NULL, /* PluginFunc */
#endif
    handleNetflowHTTPrequest,
#ifdef DEBUG_FLOWS
    "udp and (port 2055 or port 9995 or port 10234)",
#else
    NULL, /* no capture */
#endif
    NULL  /* no status */
  }
};

/* ****************************** */

#ifdef HAVE_FILEDESCRIPTORBUG

/* Burton - Aug2003
 *   Work-around for file descriptor bug (FreeBSD PR51535 et al)
 *   - burn some file descriptors so the socket() call doesn't get a dirty one.
 *   - it's not pretty, but it works...
 */

static void wasteFileDescriptors(void) {
  int i;

  if(tempNFFilesCreated == 0) {
    tempNFFilesCreated = 1;
    tempNFFpid=getpid();
    traceEvent(CONST_TRACE_INFO, "NETFLOW: FILEDESCRIPTORBUG: Work-around activated");
    for(i=0; i<CONST_FILEDESCRIPTORBUG_COUNT; i++) {
      tempNFF[i]=0;
      memset(&tempNFFname[i], 0, LEN_MEDIUM_WORK_BUFFER);

      if(snprintf(tempNFFname[i], LEN_MEDIUM_WORK_BUFFER, "/tmp/ntop-nf-%09u-%d", tempNFFpid, i) < 0)
        BufferTooShort();
      traceEvent(CONST_TRACE_NOISY, "NETFLOW: FILEDESCRIPTORBUG: Creating %d, '%s'", i, tempNFFname[i]);
      errno = 0;
      tempNFF[i]=open(tempNFFname[i], O_CREAT|O_TRUNC|O_RDWR);
      if(errno != 0) {
        traceEvent(CONST_TRACE_ERROR,
                   "NETFLOW: FILEDESCRIPTORBUG: Unable to create file - may cause problems later - '%s'(%d)",
                   strerror(errno), errno);
      } else {
        traceEvent(CONST_TRACE_NOISY,
                   "NETFLOW: FILEDESCRIPTORBUG: Created file %d - '%s'(%d)",
                   i, tempNFFname[i], tempNFF[i]);
      }
    }
  }
}

static void unwasteFileDescriptors(void) {
  int i;

  /* Close and delete the temporary - junk - files */
  traceEvent(CONST_TRACE_INFO, "NETFLOW: FILEDESCRIPTORBUG: Bug work-around cleanup");
  for(i=CONST_FILEDESCRIPTORBUG_COUNT-1; i>=0; i--) {
    if(tempNFF[i] >= 0) {
      traceEvent(CONST_TRACE_NOISY, "NETFLOW: FILEDESCRIPTORBUG: Removing %d, '%s'(%d)",
		 i, tempNFFname[i], tempNFF[i]);
      if(close(tempNFF[i])) {
        traceEvent(CONST_TRACE_ERROR,
                   "NETFLOW: FILEDESCRIPTORBUG: Unable to close file %d - '%s'(%d)",
                   i,
                   strerror(errno), errno);
      } else {
        if(unlink(tempNFFname[i]))
          traceEvent(CONST_TRACE_ERROR,
                     "NETFLOW: FILEDESCRIPTORBUG: Unable to delete file '%s' - '%s'(%d)",
                     tempNFFname[i],
                     strerror(errno), errno);
        else
          traceEvent(CONST_TRACE_NOISY,
                     "NETFLOW: FILEDESCRIPTORBUG: Removed file '%s'",
                     tempNFFname[i]);
      }
    }
  }
}

#endif

/* ****************************** */

static void freeNetFlowMatrixMemory() {
  /*
    NOTE: wee need to lock something here(TBD)
  */

  if((!myGlobals.device[myGlobals.netFlowDeviceId].activeDevice) ||(myGlobals.netFlowDeviceId == -1)) return;

  if(myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrix != NULL) {
    int j;

    /* Courtesy of Wies-Software <wies@wiessoft.de> */
    for(j=0; j<(myGlobals.device[myGlobals.netFlowDeviceId].numHosts *
		myGlobals.device[myGlobals.netFlowDeviceId].numHosts); j++)
      if(myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrix[j] != NULL)
	free(myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrix[j]);

    free(myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrix);
  }

  if(myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrixHosts != NULL)
    free(myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrixHosts);
}

/* ************************************************** */

static void setNetFlowInterfaceMatrix() {
  if((!myGlobals.device[myGlobals.netFlowDeviceId].activeDevice)
     || (myGlobals.netFlowDeviceId == -1))
    return;

  myGlobals.device[myGlobals.netFlowDeviceId].numHosts       = 0xFFFFFFFF - myGlobals.netFlowIfMask.s_addr+1;
  myGlobals.device[myGlobals.netFlowDeviceId].ifAddr.s_addr  = myGlobals.netFlowIfAddress.s_addr;
  myGlobals.device[myGlobals.netFlowDeviceId].network.s_addr = myGlobals.netFlowIfAddress.s_addr;
  myGlobals.device[myGlobals.netFlowDeviceId].netmask.s_addr = myGlobals.netFlowIfMask.s_addr;

  if(myGlobals.device[myGlobals.netFlowDeviceId].numHosts > MAX_SUBNET_HOSTS) {
    myGlobals.device[myGlobals.netFlowDeviceId].numHosts = MAX_SUBNET_HOSTS;
    traceEvent(CONST_TRACE_WARNING, "NETFLOW: Truncated network size(device %s) to %d hosts(real netmask %s).",
	       myGlobals.device[myGlobals.netFlowDeviceId].name, myGlobals.device[myGlobals.netFlowDeviceId].numHosts,
	       intoa(myGlobals.device[myGlobals.netFlowDeviceId].netmask));
  }

  myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrix =
    (TrafficEntry**)calloc(myGlobals.device[myGlobals.netFlowDeviceId].numHosts*
			   myGlobals.device[myGlobals.netFlowDeviceId].numHosts,
			   sizeof(TrafficEntry*));
  myGlobals.device[myGlobals.netFlowDeviceId].ipTrafficMatrixHosts =
    (struct hostTraffic**)calloc(sizeof(struct hostTraffic*),
				 myGlobals.device[myGlobals.netFlowDeviceId].numHosts);
}

/* ************************************** */

static int setNetFlowInSocket() {
  struct sockaddr_in sockIn;
  int sockopt = 1, i;

  if(myGlobals.netFlowInSocket > 0) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Collector terminated");
    closeNwSocket(&myGlobals.netFlowInSocket);
  }

  if(myGlobals.netFlowInPort > 0) {
    errno = 0;
    myGlobals.netFlowInSocket = socket(AF_INET, SOCK_DGRAM, 0);

    if((myGlobals.netFlowInSocket <= 0) || (errno != 0) ) {
      traceEvent(CONST_TRACE_INFO, "NETFLOW: Unable to create a socket - returned %d, error is '%s'(%d)",
		 myGlobals.netFlowInSocket, strerror(errno), errno);
      setPluginStatus("Disabled - Unable to create listening socket.");
      return(-1);
    }

    traceEvent(CONST_TRACE_INFO, "NETFLOW: Created a socket (%d)", myGlobals.netFlowInSocket);

    setsockopt(myGlobals.netFlowInSocket, SOL_SOCKET, SO_REUSEADDR,(char *)&sockopt, sizeof(sockopt));

    sockIn.sin_family            = AF_INET;
    sockIn.sin_port              =(int)htons(myGlobals.netFlowInPort);
    sockIn.sin_addr.s_addr       = INADDR_ANY;

    if(bind(myGlobals.netFlowInSocket,(struct sockaddr *)&sockIn, sizeof(sockIn)) < 0) {
      traceEvent(CONST_TRACE_ERROR, "NETFLOW: Collector port %d already in use",
		 myGlobals.netFlowInPort);
      closeNwSocket(&myGlobals.netFlowInSocket);
      myGlobals.netFlowInSocket = 0;
      return(0);
    }

    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Collector listening on port %d",
	       myGlobals.netFlowInPort);
  }

  if((myGlobals.netFlowInPort > 0) &&(myGlobals.netFlowDeviceId == -1)) {
    for(i=0; i<myGlobals.numDevices; i++) {
      if(!strcmp(myGlobals.device[i].name, NETFLOW_DEVICE_NAME)) {
        myGlobals.netFlowDeviceId = i;
        break;
      }
    }
    if(myGlobals.netFlowDeviceId > -1) {
      if(myGlobals.device[myGlobals.netFlowDeviceId].dummyDevice == 1) {
        if(myGlobals.device[myGlobals.netFlowDeviceId].activeDevice == 1) {
          traceEvent(CONST_TRACE_ERROR, NETFLOW_DEVICE_NAME " is already active - request ignored");
          return(0);
        }
        traceEvent(CONST_TRACE_INFO,
                   NETFLOW_DEVICE_NAME " reusing existing device, %d",
                   myGlobals.netFlowDeviceId);
      }
    } else
      myGlobals.netFlowDeviceId = createDummyInterface(NETFLOW_DEVICE_NAME);

    myGlobals.device[myGlobals.netFlowDeviceId].activeDevice = 1;
    setNetFlowInterfaceMatrix();
  }

  myGlobals.mergeInterfaces = 0; /* Use different devices */

  return(0);
}

/* *************************** */

static void ignoreFlow(u_short* theNextFlowIgnored, u_int srcAddr, u_short sport,
		       u_int dstAddr, u_short dport,
		       Counter len) {
  u_short lastFlowIgnored;

  lastFlowIgnored = (*theNextFlowIgnored-1+MAX_NUM_IGNOREDFLOWS) % MAX_NUM_IGNOREDFLOWS;
  if ( (flowIgnored[lastFlowIgnored][0] == srcAddr) &&
       (flowIgnored[lastFlowIgnored][1] == sport) &&
       (flowIgnored[lastFlowIgnored][2] == dstAddr) &&
       (flowIgnored[lastFlowIgnored][3] == dport) ) {
    flowIgnored[lastFlowIgnored][4]++;
    flowIgnored[lastFlowIgnored][5] += len;
  } else {
    flowIgnored[*theNextFlowIgnored][0] = srcAddr;
    flowIgnored[*theNextFlowIgnored][1] = sport;
    flowIgnored[*theNextFlowIgnored][2] = dstAddr;
    flowIgnored[*theNextFlowIgnored][3] = dport;
    flowIgnored[*theNextFlowIgnored][4] = 1;
    flowIgnored[*theNextFlowIgnored][5] = len;
    *theNextFlowIgnored = (*theNextFlowIgnored + 1) % MAX_NUM_IGNOREDFLOWS;
  }
}

/* ****************************** */

static int handleV5Flow(struct flow_ver5_rec *record)  {
  int actualDeviceId;
  Counter len;
  char theFlags[256];
  u_int16_t srcAS, dstAS;
  struct in_addr a, b;
  HostAddr addr1, addr2;
  u_int numPkts;
  HostTraffic *srcHost=NULL, *dstHost=NULL;
  u_short sport, dport, proto;
  TrafficCounter ctr;
  int skipSRC=0, skipDST=0;

  myGlobals.numNetFlowsRcvd++;

  numPkts  = ntohl(record->dPkts);
  len      = (Counter)ntohl(record->dOctets);

  /* Bad flow(zero packets) */
  if(numPkts == 0) {
    myGlobals.numBadFlowPkts++;
    return(0);
  }
  /* Bad flow(zero length) */
  if(len == 0) {
    myGlobals.numBadFlowBytes++;
    return(0);
  }
  /* Bad flow(more packets than bytes) */
  if(numPkts > len) {
    myGlobals.numBadFlowReality++;
    return(0);
  }

  myGlobals.numNetFlowsProcessed++;

  a.s_addr = ntohl(record->srcaddr);
  b.s_addr = ntohl(record->dstaddr);
  sport    = ntohs(record->srcport);
  dport    = ntohs(record->dstport);
  proto    = record->prot;
  srcAS    = ntohs(record->src_as);
  dstAS    = ntohs(record->dst_as);

#ifdef DEBUG
 {
   char buf1[256], buf[256];

   traceEvent(CONST_TRACE_INFO, "%s:%d <-> %s:%d pkt=%u/len=%u sAS=%d/dAS=%d (proto=%d)",
	      _intoa(a, buf, sizeof(buf)), sport,
	      _intoa(b, buf1, sizeof(buf1)), dport, numPkts, len,
	      srcAS, dstAS, proto);
 }
#endif

  switch(myGlobals.netFlowAggregation) {
  case noAggregation:
    /* Nothing to do */
    break;
  case portAggregation:
    a.s_addr = b.s_addr = 0; /* 0.0.0.0 */
    break;
  case hostAggregation:
    sport = dport = 0;
    break;
  case protocolAggregation:
    skipDST = skipSRC = 1;
    a.s_addr = b.s_addr = 0; /* 0.0.0.0 */
    sport = dport = 0;
    srcAS = dstAS = 0;
    break;
  case asAggregation:
    skipDST = skipSRC = 1;
    a.s_addr = b.s_addr = 0; /* 0.0.0.0 */
    sport = dport = 0;
    proto = 17; /* UDP */
    break;
  }

  if(myGlobals.netFlowDebug) {
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

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "%2d) %s:%d <-> %s:%d pkt=%u/len=%u sAS=%d/dAS=%d flags=[%s](proto=%d)",
	       i+1,
	       _intoa(a, buf, sizeof(buf)), sport,
	       _intoa(b, buf1, sizeof(buf1)), dport,
	       ntohl(record->dPkts), len,
	       srcAS, dstAS, theFlags, proto);
#endif
  }

  /* traceEvent(CONST_TRACE_INFO, "NETFLOW_DEBUG: a=%u", record->srcaddr); */

  actualDeviceId = myGlobals.netFlowDeviceId;

  if((actualDeviceId == -1) ||(actualDeviceId >= myGlobals.numDevices)) {
    traceEvent(CONST_TRACE_ERROR, "NETFLOW: deviceId(%d) is out of range - ignored", actualDeviceId);
    return(-1);
  }

  myGlobals.device[actualDeviceId].receivedPkts.value += numPkts;
  myGlobals.device[actualDeviceId].ethernetPkts.value += numPkts;
  myGlobals.device[actualDeviceId].ipPkts.value       += numPkts;
  updateDevicePacketStats((u_int)len, actualDeviceId);

  myGlobals.device[actualDeviceId].ethernetBytes.value += len;
  myGlobals.device[actualDeviceId].ipBytes.value       += len;

  if (numPkts > 0) {
    if (len/numPkts <= 64)
      myGlobals.device[actualDeviceId].rcvdPktStats.upTo64.value += numPkts;
    else if (len/numPkts <= 128)
      myGlobals.device[actualDeviceId].rcvdPktStats.upTo128.value += numPkts;
    else if (len/numPkts <= 256)
      myGlobals.device[actualDeviceId].rcvdPktStats.upTo256.value += numPkts;
    else if (len/numPkts <= 512)
      myGlobals.device[actualDeviceId].rcvdPktStats.upTo512.value += numPkts;
    else if (len/numPkts <= 1024)
      myGlobals.device[actualDeviceId].rcvdPktStats.upTo1024.value += numPkts;
    else if (len/numPkts <= 1518)
      myGlobals.device[actualDeviceId].rcvdPktStats.upTo1518.value += numPkts;
  }

#ifdef CFG_MULTITHREADED
  /* accessMutex(&myGlobals.hostsHashMutex, "processNetFlowPacket"); */
#endif


  if(!skipSRC) {
    switch((skipSRC = isOKtoSave(ntohl(record->srcaddr),
				 whiteNetworks, blackNetworks,
				 numWhiteNets, numBlackNets)) ) {
    case 1:
      myGlobals.numSrcNetFlowsEntryFailedWhiteList++;
      break;
    case 2:
      myGlobals.numSrcNetFlowsEntryFailedBlackList++;
      break;
    default:
      myGlobals.numSrcNetFlowsEntryAccepted++;
    }
  }

  if(!skipDST) {
    switch((skipDST = isOKtoSave(ntohl(record->dstaddr),
				 whiteNetworks, blackNetworks,
				 numWhiteNets, numBlackNets)) ) {
    case 1:
      myGlobals.numDstNetFlowsEntryFailedWhiteList++;
      break;
    case 2:
      myGlobals.numDstNetFlowsEntryFailedBlackList++;
      break;
    default:
      myGlobals.numDstNetFlowsEntryAccepted++;
    }
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: isOKtoSave(%08x) - src - returned %s",
	     ntohl(record->srcaddr),
	     skipSRC == 0 ? "OK" : skipSRC == 1 ? "failed White list" : "failed Black list");
  traceEvent(CONST_TRACE_INFO, "DEBUG: isOKtoSave(%08x) - dst - returned %s",
	     ntohl(record->dstaddr),
	     skipDST == 0 ? "OK" : skipDST == 1 ? "failed White list" : "failed Black list");
#endif
  addrput(AF_INET,&addr1,&b);
  addrput(AF_INET,&addr2,&a);
  if(!skipDST)
    dstHost = lookupHost(&addr1, NULL, 0, 1, myGlobals.netFlowDeviceId);
  else
    dstHost = dummyHost;

  if(!skipSRC)
    srcHost = lookupHost(&addr2, NULL, 0, 1, myGlobals.netFlowDeviceId);
  else
    srcHost = dummyHost;

  if((srcHost == NULL) ||(dstHost == NULL)) return(0);

  srcHost->lastSeen = dstHost->lastSeen = myGlobals.actTime;
  /* Commented out ... already done in updatePacketCount()                         */
  /* srcHost->pktSent.value     += numPkts, dstHost->pktRcvd.value     += numPkts; */
  /* srcHost->bytesSent.value   += len,     dstHost->bytesRcvd.value   += len;     */
  srcHost->ipBytesSent.value += len,     dstHost->ipBytesRcvd.value += len;

  if(srcAS != 0) srcHost->hostAS = srcAS;
  if(dstAS != 0) dstHost->hostAS = dstAS;

#ifdef DEBUG_FLOWS
  /* traceEvent(CONST_TRACE_INFO, "%d/%d", srcHost->hostAS, dstHost->hostAS); */
#endif

  if((sport != 0) && (dport != 0)) {
    if(dport < sport) {
      if(handleIP(dport, srcHost, dstHost, len, 0, 0, actualDeviceId) == -1) {
	if(handleIP(sport, srcHost, dstHost, len, 0, 0, actualDeviceId) == -1) {
	  if((dport == myGlobals.netFlowInPort) || (sport == myGlobals.netFlowInPort)) {
	    flowIgnoredNetFlow++;
	    flowIgnoredNetFlowBytes += len;
	  } else if(min(sport, dport) <= 1023) {
	    flowIgnoredLowPort++;
	    flowIgnoredLowPortBytes += len;
	    ignoreFlow(&nextFlowIgnored,
		       ntohl(record->srcaddr), sport,
		       ntohl(record->dstaddr), dport,
		       len);
	  } else if(myGlobals.netFlowAssumeFTP) {
	    /* If the user wants (via a run-time parm), as a last resort
	     * we assume it's ftp-data traffic
	     */
	    handleIP((u_short)CONST_FTPDATA, srcHost, dstHost, len, 0, 0, actualDeviceId);
	    flowAssumedFtpData++;
	    flowAssumedFtpDataBytes += len;
	  } else {
	    flowIgnoredHighPort++;
	    flowIgnoredHighPortBytes += len;
	    ignoreFlow(&nextFlowIgnored,
		       ntohl(record->srcaddr), sport,
		       ntohl(record->dstaddr), dport,
		       len);
	  }
	} else {
	  flowProcessed++;
	  flowProcessedBytes += len;
	}
      } else {
	flowProcessed++;
	flowProcessedBytes += len;
      }
    } else {
      if(handleIP(sport, srcHost, dstHost, len, 0, 0, actualDeviceId) == -1) {
	if(handleIP(dport, srcHost, dstHost, len, 0, 0, actualDeviceId) == -1) {
	  if((dport == myGlobals.netFlowInPort) || (sport == myGlobals.netFlowInPort)) {
	    flowIgnoredNetFlow++;
	  } else if(min(sport, dport) <= 1023) {
	    flowIgnoredLowPort++;
	    flowIgnoredLowPortBytes += len;
	    ignoreFlow(&nextFlowIgnored,
		       ntohl(record->srcaddr), sport,
		       ntohl(record->dstaddr), dport,
		       len);
	  } else if(myGlobals.netFlowAssumeFTP) {
	    /* If the user wants (via a run-time parm), as a last resort
	     * we assume it's ftp-data traffic
	     */
	    handleIP((u_short)CONST_FTPDATA, srcHost, dstHost, len, 0, 0, actualDeviceId);
	    flowAssumedFtpData++;
	    flowAssumedFtpDataBytes += len;
	  } else {
	    flowIgnoredHighPort++;
	    flowIgnoredHighPortBytes += len;
	    ignoreFlow(&nextFlowIgnored,
		       ntohl(record->srcaddr), sport,
		       ntohl(record->dstaddr), dport,
		       len);
	  }
	} else {
	  flowProcessed++;
	  flowProcessedBytes += len;
	}
      } else {
	flowProcessed++;
	flowProcessedBytes += len;
      }
    }
  } else {
    flowIgnoredZeroPort++;
    flowIgnoredZeroPortBytes += len;
    ignoreFlow(&nextFlowIgnored,
	       ntohl(record->srcaddr), sport,
	       ntohl(record->dstaddr), dport,
	       len);
  }

  ctr.value = len;
  updateTrafficMatrix(srcHost, dstHost, ctr, actualDeviceId);
  updatePacketCount(srcHost, &srcHost->hostIpAddress,
		    dstHost, &dstHost->hostIpAddress,
		    ctr, numPkts, actualDeviceId);

  if(subnetPseudoLocalHost(srcHost)) {
    if(subnetPseudoLocalHost(dstHost)) {
      incrementTrafficCounter(&srcHost->bytesSentLoc, len);
      incrementTrafficCounter(&dstHost->bytesRcvdLoc, len);
    } else {
      incrementTrafficCounter(&srcHost->bytesSentRem, len);
      incrementTrafficCounter(&dstHost->bytesRcvdLoc, len);
    }
  } else {
    /* srcHost is remote */
    if(subnetPseudoLocalHost(dstHost)) {
      incrementTrafficCounter(&srcHost->bytesSentLoc, len);
      incrementTrafficCounter(&dstHost->bytesRcvdFromRem, len);
    } else {
      incrementTrafficCounter(&srcHost->bytesSentRem, len);
      incrementTrafficCounter(&dstHost->bytesRcvdFromRem, len);
    }
  }

  switch(proto) {
  case 1: /* ICMP */
    myGlobals.device[actualDeviceId].icmpBytes.value += len;
    srcHost->icmpSent.value += len, dstHost->icmpRcvd.value += len;
    break;
  case 6: /* TCP */
    myGlobals.device[actualDeviceId].tcpBytes.value += len;
    allocateSecurityHostPkts(srcHost); allocateSecurityHostPkts(dstHost);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].numEstablishedTCPConnections, 1);
    updateInterfacePorts(actualDeviceId, sport, dport, len);
    updateUsedPorts(srcHost, dstHost, sport, dport, len);

    if(subnetPseudoLocalHost(srcHost)) {
      if(subnetPseudoLocalHost(dstHost)) {
	incrementTrafficCounter(&srcHost->tcpSentLoc, len);
	incrementTrafficCounter(&dstHost->tcpRcvdLoc, len);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.local, len);
      } else {
	incrementTrafficCounter(&srcHost->tcpSentRem, len);
	incrementTrafficCounter(&dstHost->tcpRcvdLoc, len);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.local2remote, len);
      }
    } else {
      /* srcHost is remote */
      if(subnetPseudoLocalHost(dstHost)) {
	incrementTrafficCounter(&srcHost->tcpSentLoc, len);
	incrementTrafficCounter(&dstHost->tcpRcvdFromRem, len);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.remote2local, len);
      } else {
	incrementTrafficCounter(&srcHost->tcpSentRem, len);
	incrementTrafficCounter(&dstHost->tcpRcvdFromRem, len);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].tcpGlobalTrafficStats.remote, len);
      }
    }
    break;

  case 17: /* UDP */
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpBytes, len);
    updateInterfacePorts(actualDeviceId, sport, dport, len);
    updateUsedPorts(srcHost, dstHost, sport, dport, len);

    if(subnetPseudoLocalHost(srcHost)) {
      if(subnetPseudoLocalHost(dstHost)) {
	incrementTrafficCounter(&srcHost->udpSentLoc, len);
	incrementTrafficCounter(&dstHost->udpRcvdLoc, len);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.local, len);
      } else {
	incrementTrafficCounter(&srcHost->udpSentRem, len);
	incrementTrafficCounter(&dstHost->udpRcvdLoc, len);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.local2remote, len);
      }
    } else {
      /* srcHost is remote */
      if(subnetPseudoLocalHost(dstHost)) {
	incrementTrafficCounter(&srcHost->udpSentLoc, len);
	incrementTrafficCounter(&dstHost->udpRcvdFromRem, len);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.remote2local, len);
      } else {
	incrementTrafficCounter(&srcHost->udpSentRem, len);
	incrementTrafficCounter(&dstHost->udpRcvdFromRem, len);
	incrementTrafficCounter(&myGlobals.device[actualDeviceId].udpGlobalTrafficStats.remote, len);
      }
    }
    break;
  }

#ifdef CFG_MULTITHREADED
  /* releaseMutex(&myGlobals.hostsHashMutex); */
#endif

  return(0);
}

/* *************************** */

static void dissectFlow(char *buffer, int bufferLen) {
  NetFlow5Record the5Record;
  int flowVersion;

#ifdef DEBUG
  char buf[LEN_SMALL_WORK_BUFFER], buf1[LEN_SMALL_WORK_BUFFER];
#endif

  memcpy(&the5Record, buffer, bufferLen > sizeof(the5Record) ? sizeof(the5Record): bufferLen);
  flowVersion = ntohs(the5Record.flowHeader.version);


#ifdef DEBUG_FLOWS
  traceEvent(CONST_TRACE_INFO, "NETFLOW: +++++++ version=%d",  flowVersion);
#endif

  /*
    Convert V7 flows into V5 flows in order to make ntop
    able to handle V7 flows.

    Courtesy of Bernd Ziller <bziller@ba-stuttgart.de>
  */
  if((flowVersion == 1) || (flowVersion == 7)) {
    int numFlows, i, j;
    NetFlow1Record the1Record;
    NetFlow7Record the7Record;

    if(flowVersion == 1) {
      memcpy(&the1Record, buffer, bufferLen > sizeof(the1Record) ? sizeof(the1Record): bufferLen);
      numFlows = ntohs(the1Record.flowHeader.count);
      if(numFlows > CONST_V1FLOWS_PER_PAK) numFlows = CONST_V1FLOWS_PER_PAK;
      myGlobals.numNetFlowsV1Rcvd += numFlows;
    } else {
      memcpy(&the7Record, buffer, bufferLen > sizeof(the7Record) ? sizeof(the7Record): bufferLen);
      numFlows = ntohs(the7Record.flowHeader.count);
      if(numFlows > CONST_V7FLOWS_PER_PAK) numFlows = CONST_V7FLOWS_PER_PAK;
      myGlobals.numNetFlowsV7Rcvd += numFlows;
    }

#ifdef DEBUG_FLOWS
  traceEvent(CONST_TRACE_INFO, "NETFLOW: +++++++ flows=%d",  numFlows);
#endif

    the5Record.flowHeader.version = htons(5);
    the5Record.flowHeader.count = htons(numFlows);
    /* rest of flowHeader will not be used */

    for(j=i=0; i<numFlows; i++) {
      if(flowVersion == 7) {
	the5Record.flowRecord[i].srcaddr   = the7Record.flowRecord[i].srcaddr;
	the5Record.flowRecord[i].dstaddr   = the7Record.flowRecord[i].dstaddr;
	the5Record.flowRecord[i].srcport   = the7Record.flowRecord[i].srcport;
	the5Record.flowRecord[i].dstport   = the7Record.flowRecord[i].dstport;
	the5Record.flowRecord[i].dPkts     = the7Record.flowRecord[i].dPkts;
	the5Record.flowRecord[i].dOctets   = the7Record.flowRecord[i].dOctets;
	the5Record.flowRecord[i].prot      = the7Record.flowRecord[i].prot;
	the5Record.flowRecord[i].tos       = the7Record.flowRecord[i].tos;
	the5Record.flowRecord[i].First     = the7Record.flowRecord[i].First;
	the5Record.flowRecord[i].Last      = the7Record.flowRecord[i].Last;
	the5Record.flowRecord[i].tcp_flags = the7Record.flowRecord[i].tcp_flags;
	/* rest of flowRecord will not be used */
      } else {
	the5Record.flowRecord[i].srcaddr   = the1Record.flowRecord[i].srcaddr;
	the5Record.flowRecord[i].dstaddr   = the1Record.flowRecord[i].dstaddr;
	the5Record.flowRecord[i].srcport   = the1Record.flowRecord[i].srcport;
	the5Record.flowRecord[i].dstport   = the1Record.flowRecord[i].dstport;
	the5Record.flowRecord[i].dPkts     = the1Record.flowRecord[i].dPkts;
	the5Record.flowRecord[i].dOctets   = the1Record.flowRecord[i].dOctets;
	the5Record.flowRecord[i].prot      = the1Record.flowRecord[i].prot;
	the5Record.flowRecord[i].tos       = the1Record.flowRecord[i].tos;
	the5Record.flowRecord[i].First     = the1Record.flowRecord[i].First;
	the5Record.flowRecord[i].Last      = the1Record.flowRecord[i].Last;
	/* rest of flowRecord will not be used */
      }
    }
  }  /* DON'T ADD a else here ! */

  if(the5Record.flowHeader.version == htons(9)) {
    /* NetFlowV9 Record */
    u_char foundRecord = 0, done = 0;
    u_short numEntries = ntohs(the5Record.flowHeader.count), displ = sizeof(V9FlowHeader);
    V9Template template;
    int i;

    for(i=0; (!done) && (displ < bufferLen) && (i < numEntries); i++) {
      /* 1st byte */
      if(buffer[displ] == 0) {
	/* Template */
#ifdef DEBUG_FLOWS
	traceEvent(CONST_TRACE_INFO, "Found Template [displ=%d]", displ);
#endif

	myGlobals.numNetFlowsV9TemplRcvd++;

	if(bufferLen > (displ+sizeof(V9Template))) {
	  FlowSetV9 *cursor = templates;
	  u_char found = 0;
	  u_short len = sizeof(V9Template);
	  int fieldId;

	  memcpy(&template, &buffer[displ], sizeof(V9Template));

	  template.templateId = ntohs(template.templateId);
	  template.fieldCount = ntohs(template.fieldCount);
	  template.flowsetLen = ntohs(template.flowsetLen);

#ifdef DEBUG_FLOWS
	  traceEvent(CONST_TRACE_INFO, "Template [id=%d] fields: %d",
		     template.templateId, template.fieldCount);
#endif

	  /* Check the template before to handle it */
	  for(fieldId=0; (fieldId<template.fieldCount)
		&& (len < template.flowsetLen); fieldId++) {
	    V9FlowSet *set = (V9FlowSet*)&buffer[displ+sizeof(V9Template)+fieldId*sizeof(V9FlowSet)];

	    len += htons(set->flowsetLen);
#ifdef DEBUG_FLOWS
	    traceEvent(CONST_TRACE_INFO, "[%d] fieldLen=%d/len=%d",
		       1+fieldId, htons(set->flowsetLen), len);
#endif
	  }

	  if(len > template.flowsetLen) {
	    traceEvent(CONST_TRACE_WARNING, "Template %d has wrong size [actual=%d/expected=%d]: skipped",
		       template.templateId, len, template.flowsetLen);
	    myGlobals.numNetFlowsV9BadTemplRcvd++;
	  } else {
	    while(cursor != NULL) {
	      if(cursor->templateInfo.templateId == template.templateId) {
		found = 1;
		break;
	      } else
		cursor = cursor->next;
	    }

	    if(found) {
#ifdef DEBUG_FLOWS
	      traceEvent(CONST_TRACE_INFO, ">>>>> Redefined existing template [id=%d]", template.templateId);
#endif

	      free(cursor->fields);
	    } else {
#ifdef DEBUG_FLOWS
	      traceEvent(CONST_TRACE_INFO, ">>>>> Found new flow template definition [id=%d]", template.templateId);
#endif

	      cursor = (FlowSetV9*)malloc(sizeof(FlowSetV9));
	      cursor->next = templates;
	      templates = cursor;
	    }

	    memcpy(&cursor->templateInfo, &buffer[displ], sizeof(V9Template));
	    cursor->templateInfo.flowsetLen = ntohs(cursor->templateInfo.flowsetLen);
	    cursor->templateInfo.templateId = ntohs(cursor->templateInfo.templateId);
	    cursor->templateInfo.fieldCount = ntohs(cursor->templateInfo.fieldCount);
	    cursor->fields = (V9TemplateField*)malloc(cursor->templateInfo.flowsetLen-sizeof(V9Template));
	    memcpy(cursor->fields, &buffer[displ+sizeof(V9Template)], cursor->templateInfo.flowsetLen-sizeof(V9Template));
	  }

	  /* Skip template definition */
	  displ += template.flowsetLen;
	} else {
	  done = 1;
	  myGlobals.numNetFlowsV9BadTemplRcvd++;
	}
      } else {
#ifdef DEBUG_FLOWS
	traceEvent(CONST_TRACE_INFO, "Found FlowSet [displ=%d]", displ);
#endif
	foundRecord = 1;
      }

      if(foundRecord) {
	V9FlowSet fs;

	if(bufferLen > (displ+sizeof(V9FlowSet))) {
	  FlowSetV9 *cursor = templates;
	  u_char found = 0;

	  memcpy(&fs, &buffer[displ], sizeof(V9FlowSet));

	  fs.flowsetLen = ntohs(fs.flowsetLen);
	  fs.templateId = ntohs(fs.templateId);

	  while(cursor != NULL) {
	    if(cursor->templateInfo.templateId == fs.templateId) {
	      break;
	    } else
	      cursor = cursor->next;
	  }

	  myGlobals.numNetFlowsV9Rcvd++;

	  if(cursor != NULL) {
	    /* Template found */
	    int fieldId;
	    V9TemplateField *fields = cursor->fields;
	    struct flow_ver5_rec record;

#ifdef DEBUG_FLOWS
	    traceEvent(CONST_TRACE_INFO, ">>>>> Rcvd flow with known template %d", fs.templateId);
#endif

	    displ += sizeof(V9FlowSet);

	    while(displ < fs.flowsetLen) {
#ifdef DEBUG_FLOWS
	      traceEvent(CONST_TRACE_INFO, ">>>>> Dissecting flow pdu [displ=%d][template=%d]",
			 displ, fs.templateId);
#endif

	      for(fieldId=0; fieldId<cursor->templateInfo.fieldCount; fieldId++) {
		switch(ntohs(fields[fieldId].fieldType)) {
		case 21: /* LAST_SWITCHED */
		  memcpy(&record.Last, &buffer[displ], 4); displ += 4;
		  break;
		case 22: /* FIRST SWITCHED */
		  memcpy(&record.First, &buffer[displ], 4); displ += 4;
		  break;
		case 1: /* BYTES */
		  memcpy(&record.dOctets, &buffer[displ], 4); displ += 4;
		  break;
		case 2: /* PKTS */
		  memcpy(&record.dPkts, &buffer[displ], 4); displ += 4;
		  break;
		case 10: /* INPUT SNMP */
		  memcpy(&record.input, &buffer[displ], 2); displ += 2;
		  break;
		case 14: /* OUTPUT SNMP */
		  memcpy(&record.output, &buffer[displ], 2); displ += 2;
		  break;
		case 8: /* IP_SRC_ADDR */
		  memcpy(&record.srcaddr, &buffer[displ], 4); displ += 4;
		  break;
		case 12: /* IP_DST_ADDR */
		  memcpy(&record.dstaddr, &buffer[displ], 4); displ += 4;
		  break;
		case 4: /* PROT */
		  memcpy(&record.prot, &buffer[displ], 1); displ += 1;
		  break;
		case 5: /* TOS */
		  memcpy(&record.tos, &buffer[displ], 1); displ += 1;
		  break;
		case 7: /* L4_SRC_PORT */
		  memcpy(&record.srcport, &buffer[displ], 2); displ += 2;
		  break;
		case 11: /* L4_DST_PORT */
		  memcpy(&record.dstport, &buffer[displ], 2); displ += 2;
		  break;
		case 15: /* IP_NEXT_HOP */
		  memcpy(&record.nexthop, &buffer[displ], 4); displ += 4;
		  break;
		case 13: /* DST_MASK */
		  memcpy(&record.dst_mask, &buffer[displ], 1); displ += 1;
		  break;
		case 9: /* SRC_MASK */
		  memcpy(&record.src_mask, &buffer[displ], 1); displ += 1;
		  break;
		case 6: /* TCP_FLAGS */
		  memcpy(&record.tcp_flags, &buffer[displ], 1); displ += 1;
		  break;
		case 17: /* DST_AS */
		  memcpy(&record.dst_as, &buffer[displ], 2); displ += 2;
		  break;
		case 16: /* SRC_AS */
		  memcpy(&record.dst_as, &buffer[displ], 2); displ += 2;
		  break;
		}
	      }
	      handleV5Flow(&record);
	    }
	  } else {
#ifdef DEBUG_FLOWS
	    traceEvent(CONST_TRACE_INFO, ">>>>> Rcvd flow with UNKNOWN template %d", fs.templateId);
#endif
	    myGlobals.numNetFlowsV9UnknTemplRcvd++;
	  }
	}
      }
    } /* for */
  } else if(the5Record.flowHeader.version == htons(5)) {
    int i, numFlows = ntohs(the5Record.flowHeader.count);

    if(numFlows > CONST_V5FLOWS_PER_PAK) numFlows = CONST_V5FLOWS_PER_PAK;

#ifdef DEBUG_FLOWS
    traceEvent(CONST_TRACE_INFO, "dissectFlow(%d flows)", numFlows);
#endif

#ifdef CFG_MULTITHREADED
    /* Lock white/black lists for duration of this flow packet */
    accessMutex(&whiteblackListMutex, "flowPacket");
#endif

    for(i=0; i<numFlows; i++)
      handleV5Flow(&the5Record.flowRecord[i]);

    if(flowVersion == 5) /* Skip converted V1/V7 flows */
      myGlobals.numNetFlowsV5Rcvd += numFlows;

#ifdef CFG_MULTITHREADED
    releaseMutex(&whiteblackListMutex);
#endif
  } else {
    /* Last attempt: is this nFlow ? */
    char uncompressBuf[1500], *rcvdBuf;
    uLongf uncompressLen = sizeof(uncompressBuf);
    NflowV1Header *header = (NflowV1Header*)buffer;
    int rc, i;

    /* First attempt: uncompressed flow */
    if(ntohs(header->version) != NFLOW_VERSION) {
      /* Second attempt: compressed flow */
      if((rc = uncompress(uncompressBuf, &uncompressLen, buffer, bufferLen)) == Z_OK) {
#ifdef DEBUG_FLOWS
	traceEvent(CONST_TRACE_INFO, "Received compressed flow: %d -> %d [+%.1f %%]",
		   bufferLen, (int)uncompressLen, (float)(100*(int)uncompressLen)/(float)bufferLen-100);
#endif
	rc = uncompressLen;
	rcvdBuf = uncompressBuf;
	header = (NflowV1Header*)rcvdBuf;

	if(ntohs(header->version) != NFLOW_VERSION) {
	  myGlobals.numNflowFlowsBadVersRcvd++;
	} else {
	  int numRecords = 0, bufBegin, bufLen;

	  nFlowTotCompressedSize += bufferLen, nFlowTotUncompressedSize += uncompressLen;

#ifdef DEBUG_FLOWS
	  traceEvent(CONST_TRACE_INFO, "Header version: %d", ntohs(header->version));
	  traceEvent(CONST_TRACE_INFO, "count:          %d", ntohs(header->count));
	  traceEvent(CONST_TRACE_INFO, "sysUptime:      %d", ntohl(header->sysUptime));
	  traceEvent(CONST_TRACE_INFO, "flow_sequence:  %d", ntohl(header->flow_sequence));
	  traceEvent(CONST_TRACE_INFO, "sourceId:       %d", ntohl(header->sourceId));
	  traceEvent(CONST_TRACE_INFO, "sampleRate:     %d", ntohs(header->sampleRate));
	  traceEvent(CONST_TRACE_INFO, "md5Sum:        ");
	  for(i=0; i<NFLOW_SUM_LEN; i++) traceEvent(CONST_TRACE_INFO, "%02X", header->md5Sum[i]);
#endif

	  memset(&the5Record, 0, sizeof(the5Record));

	  /* Convert the nFlow record into a NetFlow V5 flow */
	  the5Record.flowHeader.version = htons(5);
	  the5Record.flowHeader.count = header->count;
	  the5Record.flowHeader.sysUptime = header->sysUptime;
	  the5Record.flowHeader.unix_secs = header->unix_secs;
	  the5Record.flowHeader.unix_nsecs = header->unix_nsecs;
	  the5Record.flowHeader.flow_sequence = header->flow_sequence;

	  bufBegin = sizeof(NflowV1Header);
	  bufLen = uncompressLen;

	  while(bufBegin < bufLen) {
	    u_int16_t flowLen;

	    memcpy(&flowLen, &rcvdBuf[bufBegin], 2);
	    flowLen = ntohs(flowLen);
	    bufBegin += 2, flowLen -= 2;
	    if(numRecords >= CONST_V5FLOWS_PER_PAK) break;

	    while(flowLen > 0) {
	      u_int8_t t8;
	      u_int16_t t16, len, templateId;
	      u_int32_t t32;

	      memcpy(&templateId, &rcvdBuf[bufBegin], 2); bufBegin += 2; flowLen -= 2; templateId = ntohs(templateId);
	      memcpy(&len, &rcvdBuf[bufBegin], 2); bufBegin += 2; flowLen -= 2; len = ntohs(len);

#ifdef DEBUG_FLOWS
	      traceEvent(CONST_TRACE_INFO, "Template: [id=%d][len=%d]", templateId, len);
#endif

	      if(len > 16 /* MAX LEN */) {
		myGlobals.numNflowFlowsBadTemplRcvd++;
		break;
	      }

	      switch(templateId) {
	      case 8:
		memcpy(&the5Record.flowRecord[numRecords].srcaddr, &rcvdBuf[bufBegin], len);
		break;
	      case 12:
		memcpy(&the5Record.flowRecord[numRecords].dstaddr, &rcvdBuf[bufBegin], len);
		break;
	      case 7:
		memcpy(&the5Record.flowRecord[numRecords].srcport, &rcvdBuf[bufBegin], len);
		break;
	      case 11:
		memcpy(&the5Record.flowRecord[numRecords].dstport, &rcvdBuf[bufBegin], len);
		break;
	      case 2:
		memcpy(&the5Record.flowRecord[numRecords].dPkts, &rcvdBuf[bufBegin], len);
		break;
	      case 1:
		memcpy(&the5Record.flowRecord[numRecords].dOctets, &rcvdBuf[bufBegin], len);
		break;
	      case 4:
		memcpy(&the5Record.flowRecord[numRecords].prot, &rcvdBuf[bufBegin], len);
		break;
	      case 5:
		memcpy(&the5Record.flowRecord[numRecords].tos, &rcvdBuf[bufBegin], len);
		break;
	      case 22:
		memcpy(&the5Record.flowRecord[numRecords].First, &rcvdBuf[bufBegin], len);
		break;
	      case 21:
		memcpy(&the5Record.flowRecord[numRecords].Last, &rcvdBuf[bufBegin], len);
		break;
	      case 6:
		memcpy(&the5Record.flowRecord[numRecords].tcp_flags, &rcvdBuf[bufBegin], len);
		break;
	      }

	      bufBegin += len, flowLen -= len;
	    }

	    numRecords++;
	  }

	  for(i=0; i<numRecords; i++) handleV5Flow(&the5Record.flowRecord[i]);
	  myGlobals.numNflowFlowsRcvd++;
	}
      } else {
#ifdef DEBUG_FLOWS
	traceEvent(CONST_TRACE_INFO, "Uncompress failed [rc=%d]. This is not an nFlow", rc);
#endif
      }
    } else
      myGlobals.numBadNetFlowsVersionsRcvd++; /* CHANGE */
  }
}

/* ****************************** */

#ifdef CFG_MULTITHREADED

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

#ifdef HAVE_BACKTRACE
  /* Don't double fault... */
  /* signal(signo, SIG_DFL); */

  /* Grab the backtrace before we do much else... */
  size = backtrace(array, 20);
  strings = (char**)backtrace_symbols(array, size);

  traceEvent(CONST_TRACE_FATALERROR, "NETFLOW: BACKTRACE:     backtrace is:");
  if (size < 2) {
    traceEvent(CONST_TRACE_FATALERROR, "NETFLOW: BACKTRACE:         **unavailable!");
  } else {
    /* Ignore the 0th entry, that's our cleanup() */
    for (i=1; i<size; i++) {
      traceEvent(CONST_TRACE_FATALERROR, "NETFLOW: BACKTRACE:          %2d. %s", i, strings[i]);
    }
  }
#endif /* HAVE_BACKTRACE */

  exit(0);
}
#endif /* MAKE_WITH_NETFLOWSIGTRAP */

/* ****************************** */

static void* netflowMainLoop(void* notUsed _UNUSED_) {
  fd_set netflowMask;
  int rc, len;
  u_char buffer[2048];
  struct sockaddr_in fromHost;

  if(!(myGlobals.netFlowInSocket > 0)) return(NULL);

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

  if(myGlobals.netFlowDeviceId != -1)
    myGlobals.device[myGlobals.netFlowDeviceId].activeDevice = 1;

  threadActive = 1;
  traceEvent(CONST_TRACE_INFO, "THREADMGMT: netFlow thread(%ld) started", netFlowThread);

  for(;myGlobals.capturePackets == FLAG_NTOPSTATE_RUN;) {
    FD_ZERO(&netflowMask);
    FD_SET(myGlobals.netFlowInSocket, &netflowMask);

    if((rc = select(myGlobals.netFlowInSocket+1, &netflowMask, NULL, NULL, NULL)) > 0) {
      len = sizeof(fromHost);
      rc = recvfrom(myGlobals.netFlowInSocket,(char*)&buffer, sizeof(buffer),
		    0,(struct sockaddr*)&fromHost, &len);

#ifdef DEBUG_FLOWS
      traceEvent(CONST_TRACE_INFO, "NETFLOW_DEBUG: Received NetFlow packet(len=%d)(deviceId=%d)",
		 rc,  myGlobals.netFlowDeviceId);
#endif

      if(rc > 0) {
	int i;

	myGlobals.numNetFlowsPktsRcvd++;

	NTOHL(fromHost.sin_addr.s_addr);

	for(i=0; i<MAX_NUM_PROBES; i++) {
	  if(probeList[i].probeAddr.s_addr == 0) {
	    probeList[i].probeAddr.s_addr = fromHost.sin_addr.s_addr;
	    probeList[i].pkts = 1;
	    break;
	  } else if(probeList[i].probeAddr.s_addr == fromHost.sin_addr.s_addr) {
	    probeList[i].pkts++;
	    break;
	  }
	}

	dissectFlow(buffer, rc);
      }
    } else {
      if(rc < 0) {
	traceEvent(CONST_TRACE_FATALERROR, "NETFLOW: select() failed(%d, %s), terminating netFlow",
		   errno, strerror(errno));
	break;
      }
    }
  }

  threadActive = 0;
  traceEvent(CONST_TRACE_WARNING, "THREADMGMT: netFlow thread(%ld) terminated", netFlowThread);

  if(myGlobals.netFlowDeviceId != -1)
    myGlobals.device[myGlobals.netFlowDeviceId].activeDevice = 0;

  return(NULL);
}

#endif

/* ****************************** */

static int initNetFlowFunct(void) {
  int i, a, b, c, d, a1, b1, c1, d1, rc;
  char key[256], value[1024], workList[1024];

  setPluginStatus(NULL);

  myGlobals.netFlowDeviceId = -1;

#ifdef CFG_MULTITHREADED
  threadActive = 0;
  createMutex(&whiteblackListMutex);
#else
  /* This plugin works only with threads */
  setPluginStatus("Disabled - requires POSIX thread support.");
  return(-1);
#endif

  memset(flowIgnored, 0, sizeof(flowIgnored));
  nextFlowIgnored = 0;

  if(fetchPrefsValue("netFlow.netFlowInPort", value, sizeof(value)) == -1)
    storePrefsValue("netFlow.netFlowInPort", "0");
  else
    myGlobals.netFlowInPort = atoi(value);

  if((fetchPrefsValue("netFlow.ifNetMask", value, sizeof(value)) == -1)
     || (((rc = sscanf(value, "%d.%d.%d.%d/%d.%d.%d.%d", &a, &b, &c, &d, &a1, &b1, &c1, &d1)) != 8)
	 && ((rc = sscanf(value, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &a1)) != 5))) {
    storePrefsValue("netFlow.ifNetMask", "192.168.0.0/255.255.255.0");
    myGlobals.netFlowIfAddress.s_addr = 0xC0A80000;
    myGlobals.netFlowIfMask.s_addr    = 0xFFFFFF00;
  } else {
    myGlobals.netFlowIfAddress.s_addr = (a << 24) +(b << 16) +(c << 8) + d;
    if(rc == 8)
      myGlobals.netFlowIfMask.s_addr = (a1 << 24) +(b1 << 16) +(c1 << 8) + d1;
    else {
      myGlobals.netFlowIfMask.s_addr = 0xffffffff >> a1;
      myGlobals.netFlowIfMask.s_addr =~ myGlobals.netFlowIfMask.s_addr;
    }
  }

  if(fetchPrefsValue("netFlow.whiteList", value, sizeof(value)) == -1) {
    storePrefsValue("netFlow.whiteList", "");
    myGlobals.netFlowWhiteList = strdup("");
  } else
    myGlobals.netFlowWhiteList = strdup(value);

  if(fetchPrefsValue("netFlow.netFlowAggregation", value, sizeof(value)) == -1)
    storePrefsValue("netFlow.netFlowAggregation", "0" /* noAggregation */);
  else
    myGlobals.netFlowAggregation = atoi(value);

  if(fetchPrefsValue("netFlow.netFlowAssumeFTP", value, sizeof(value)) == -1) {
    storePrefsValue("netFlow.netFlowAssumeFTP", "0" /* no */);
    myGlobals.netFlowAssumeFTP = 0;
  } else
    myGlobals.netFlowAssumeFTP = atoi(value);

#ifdef CFG_MULTITHREADED
  accessMutex(&whiteblackListMutex, "initNetFlowFunct()w");
#endif
  handleWhiteBlackListAddresses((char*)&value,
                                whiteNetworks,
                                &numWhiteNets,
				(char*)&workList,
                                sizeof(workList));
  if(myGlobals.netFlowWhiteList != NULL) free(myGlobals.netFlowWhiteList);
  myGlobals.netFlowWhiteList = strdup(workList);
#ifdef CFG_MULTITHREADED
  releaseMutex(&whiteblackListMutex);
#endif
  traceEvent(CONST_TRACE_INFO, "NETFLOW: White list initialized to '%s'", myGlobals.netFlowWhiteList);

  if(fetchPrefsValue("netFlow.blackList", value, sizeof(value)) == -1) {
    storePrefsValue("netFlow.blackList", "");
    myGlobals.netFlowBlackList=strdup("");
  } else
    myGlobals.netFlowBlackList=strdup(value);

#ifdef CFG_MULTITHREADED
  accessMutex(&whiteblackListMutex, "initNetFlowFunct()b");
#endif
  handleWhiteBlackListAddresses((char*)&value, blackNetworks,
                                &numBlackNets, (char*)&workList,
                                sizeof(workList));
  if(myGlobals.netFlowBlackList != NULL) free(myGlobals.netFlowBlackList);
  myGlobals.netFlowBlackList = strdup(workList);
#ifdef CFG_MULTITHREADED
  releaseMutex(&whiteblackListMutex);
#endif
  traceEvent(CONST_TRACE_INFO, "NETFLOW: Black list initialized to '%s'", myGlobals.netFlowBlackList);

#ifdef HAVE_FILEDESCRIPTORBUG
  wasteFileDescriptors();
#endif

  if(setNetFlowInSocket() != 0)  return(-1);

  if(fetchPrefsValue("netFlow.debug", value, sizeof(value)) == -1) {
    storePrefsValue("netFlow.debug", "0");
    myGlobals.netFlowDebug = 0;
  } else {
    myGlobals.netFlowDebug = atoi(value);
  }

  /* Allocate a pure dummy for white/black list use */
  dummyHost = (HostTraffic*)malloc(sizeof(HostTraffic));
  memset(dummyHost, 0, sizeof(HostTraffic));

  dummyHost->hostIp4Address.s_addr = 0x00112233;
  strncpy(dummyHost->hostNumIpAddress, "&nbsp;",
	  sizeof(dummyHost->hostNumIpAddress));
  strncpy(dummyHost->hostResolvedName, "white/black list dummy",
	  sizeof(dummyHost->hostResolvedName));
  dummyHost->hostResolvedNameType = FLAG_HOST_SYM_ADDR_TYPE_FAKE;
  strcpy(dummyHost->ethAddressString, "00:00:00:00:00:00");
  setEmptySerial(&dummyHost->hostSerial);
  dummyHost->portsUsage = (PortUsage**)calloc(sizeof(PortUsage*), MAX_ASSIGNED_IP_PORTS);

#ifdef CFG_MULTITHREADED
  if((myGlobals.netFlowInPort != 0) &&(!threadActive)) {
    /* This plugin works only with threads */
    createThread(&netFlowThread, netflowMainLoop, NULL);
  }
#endif
  return(0);
}

/* ****************************** */

static void printNetFlowConfiguration(void) {
  char buf[512], buf1[32], buf2[32];
  u_int i, numEnabled=0;
  struct in_addr theDest;

  sendString("<center><table width=\"80%\" border=\"1\" "TABLE_DEFAULTS">\n");
  sendString("<tr><th colspan=\"4\" "DARK_BG">Incoming Flows</th></tr>\n");
  sendString("<tr><th rowspan=\"2\" "DARK_BG">Flow<br>Collection</th>\n");

  sendString("<th "DARK_BG">Local<br>Collector<br>UDP Port</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p><input name=\"port\" size=\"5\" value=\"");
  if(snprintf(buf, sizeof(buf), "%d", myGlobals.netFlowInPort) < 0)
    BufferTooShort();
  sendString(buf);
  sendString("\"> "
	     "[ Use a port value of 0 to disable collection ] "
	     "<input type=\"submit\" value=\"Set Port\">"
	     "</p>\n</form>\n\n"
             "<p>If you want <b>ntop</b> to display NetFlow data it receives from other "
             "hosts, i.e. act as a collector, you must specify the UDP port to listen to. "
             "The default port used for NetFlow is " DEFAULT_NETFLOW_PORT_STR ".</p>\n"
	     "<p align=\"right\"></p>\n");

  if(myGlobals.netFlowInPort == 0)
    sendString("<p><font color=red>WARNING</font>: "
	       "The 'Local Collector UDP Port' is zero (none). "
               "Even if this plugin is ACTIVE, you must still enter a port number for "
               "<b>ntop</b> to receive and process NetFlow data.</p>\n");

  sendString("</td></tr>\n");

  sendString("<tr><th "DARK_BG">Virtual<br>NetFlow<br>Interface<br>Network<br>Address</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n"
             " <input name=\"ifNetMask\" size=\"32\" value=\"");
  if(snprintf(buf, sizeof(buf), "%s/%s",
	      _intoa(myGlobals.netFlowIfAddress, buf1, sizeof(buf1)),
	      _intoa(myGlobals.netFlowIfMask, buf2, sizeof(buf2))) < 0)
    BufferTooShort();
  sendString(buf);
  sendString("\"> <input type=\"submit\" value=\"Set Interface Address\"></p>\n</form>\n");

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
  sendString("\" method=GET>\n"
             "<p><SELECT NAME=netFlowAggregation>");

  if(snprintf(buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
              noAggregation,
              (myGlobals.netFlowAggregation == noAggregation) ? " SELECTED" : "",
              "None (no aggregation)") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
              portAggregation,
              (myGlobals.netFlowAggregation == portAggregation) ? " SELECTED" : "",
              "TCP/UDP Port") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
              hostAggregation,
              (myGlobals.netFlowAggregation == hostAggregation) ? " SELECTED" : "",
              "Host") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
              protocolAggregation,
              (myGlobals.netFlowAggregation == protocolAggregation) ? " SELECTED" : "",
              "Protocol (TCP, UDP, ICMP)") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
              asAggregation,
              (myGlobals.netFlowAggregation == asAggregation) ? " SELECTED" : "",
              "AS") < 0)
    BufferTooShort();
  sendString(buf);

  sendString("</select> <input type=\"submit\" value=\"Set Aggregation Policy\"></p>\n"
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
  sendString("\" method=GET>\n <input name=\"whiteList\" size=\"60\" value=\"");
  if(snprintf(buf, sizeof(buf), "%s",
              myGlobals.netFlowWhiteList == NULL ? " " : myGlobals.netFlowWhiteList) < 0)
    BufferTooShort();
  sendString(buf);
  sendString("\"> <input type=\"submit\" value=\"Set White List\"></p>\n</form>\n"
             "<p>This is a list of one or more TCP/IP host(s)/network(s) which we will "
             "store data from when these host(s)/network(s) occur in the NetFlow records.</p>\n"
             "</td>\n</tr>\n");

  sendString("<tr><th "DARK_BG">Black List</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET> <input name=\"blackList\" size=\"60\" value=\"");
  if(snprintf(buf, sizeof(buf), "%s",
              myGlobals.netFlowBlackList == NULL ? " " : myGlobals.netFlowBlackList) < 0)
    BufferTooShort();
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

  sendString("<tr><th colspan=\"2\" "DARK_BG">Assume FTP</th>\n");

  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");
  if(myGlobals.netFlowAssumeFTP) {
    sendString("<input type=\"radio\" name=\"netFlowAssumeFTP\" value=\"1\" checked>Yes\n"
               "<input type=\"radio\" name=\"netFlowAssumeFTP\" value=\"0\">No\n");
  } else {
    sendString("<input type=\"radio\" name=\"netFlowAssumeFTP\" value=\"1\">Yes\n"
               "<input type=\"radio\" name=\"netFlowAssumeFTP\" value=\"0\" checked>No\n");
  }
  sendString(" <input type=\"submit\" value=\"Set FTP Policy\"></p>\n"
             "</form>\n"
             "<p><b>ntop</b> handles the FTP protocol differently when using NetFlow data "
             "vs. the normal full protocol analysis. In the NetFlow data, <b>ntop</b> sees "
             "only the address and port number and so can not monitor the ftp control channel "
             "to detect which dynamically assigned ports are being used for ftp data.</p>\n"
             "<p>This option tells <b>ntop</b> to assume that data from an unknown high "
             "(&gt;1023) port to an unknown high port should be treated as FTP data.</p>\n"
             "<p><b>Use this only if you understand your data flows.</b></p>\n"
             "<p>For most situations this is not a good assumption - for example, "
             "peer-to-peer traffic also is high port to high port. "
             "However, in limited situations, this option enables you to obtain a more "
             "correct view of your traffic.</p>\n"
             "<p align=\"right\"><i>This option takes effect IMMEDIATELY</i></p>\n"
	     "</td>\n</tr>\n");

  /* *************************************** */

  sendString("<tr><th colspan=\"2\" "DARK_BG">Debug</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");

  if(myGlobals.netFlowDebug) {
    sendString("<input type=\"radio\" name=\"debug\" value=\"1\" checked>On");
    sendString("<input type=\"radio\" name=\"debug\" value=\"0\">Off");
  } else {
    sendString("<input type=\"radio\" name=\"debug\" value=\"1\">On");
    sendString("<input type=\"radio\" name=\"debug\" value=\"0\" checked>Off");
  }

  sendString(" <input type=\"submit\" value=\"Set Debug\"></p>\n</form>\n"
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

/* ****************************** */

static void printNetFlowStatisticsRcvd(void) {
  char buf[512], buf1[32], buf2[32], formatBuf[32], formatBuf2[32];
  u_int i, totFlows;

  sendString("<tr " TR_ON ">\n"
             "<th colspan=\"2\" "DARK_BG">Received Flows</th>\n"
             "</tr>\n"
             "<tr " TR_ON ">\n"
             "<th " TH_BG " align=\"left\" "DARK_BG ">Flow Senders</th>\n"
             "<td width=\"20%\">");

  for(i=0; i<MAX_NUM_PROBES; i++) {
    if(probeList[i].probeAddr.s_addr == 0) break;

    if(snprintf(buf, sizeof(buf), "%s [%s pkts]<br>\n",
                _intoa(probeList[i].probeAddr, buf, sizeof(buf)),
                formatPkts(probeList[i].pkts, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    sendString(buf);
  }
  sendString("&nbsp;</td>\n</tr>\n");

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Packets received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numNetFlowsPktsRcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Packets with bad version</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numBadNetFlowsVersionsRcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Packets processed</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numNetFlowsPktsRcvd -
                         myGlobals.numBadNetFlowsVersionsRcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Flows Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numNetFlowsRcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(myGlobals.numNetFlowsPktsRcvd > 0) {
    totFlows = myGlobals.numNetFlowsV5Rcvd +
      myGlobals.numNetFlowsV7Rcvd +
      myGlobals.numNetFlowsV9Rcvd +
      myGlobals.numNflowFlowsRcvd +
      myGlobals.numBadFlowPkts +
      myGlobals.numBadFlowBytes +
      myGlobals.numBadFlowReality +
      myGlobals.numNetFlowsV9UnknTemplRcvd;      

    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Average Number of Flows per Packet</th>\n"
                "<td " TD_BG " align=\"right\">%.1f</td>\n"
                "</tr>\n",
              (float)totFlows/(float)myGlobals.numNetFlowsPktsRcvd) < 0)
        BufferTooShort();
    sendString(buf);
  }

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of V1 Flows Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numNetFlowsV1Rcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of V5 Flows Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numNetFlowsV5Rcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of V7 Flows Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numNetFlowsV7Rcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of V9 Flows Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numNetFlowsV9Rcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(myGlobals.numNetFlowsV9TemplRcvd) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Total V9 Templates Received</th>\n"
                "<td " TD_BG " align=\"right\">%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.numNetFlowsV9TemplRcvd, formatBuf, sizeof(formatBuf))) < 0)
        BufferTooShort();
    sendString(buf);
  }

  if(myGlobals.numNetFlowsV9BadTemplRcvd) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Bad V9 Templates Received</th>\n"
                "<td " TD_BG " align=\"right\">%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.numNetFlowsV9BadTemplRcvd, formatBuf, sizeof(formatBuf))) < 0)
        BufferTooShort();
    sendString(buf);
  }

  if(myGlobals.numNetFlowsV9UnknTemplRcvd) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Number of V9 Flows with Unknown Templates Received</th>\n"
                "<td " TD_BG " align=\"right\">%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.numNetFlowsV9UnknTemplRcvd, formatBuf, sizeof(formatBuf))) < 0)
        BufferTooShort();
    sendString(buf);
  }

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of nFlows Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numNflowFlowsRcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(nFlowTotCompressedSize > 0) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Average nFlow Compression Savings</th>\n"
                "<td " TD_BG " align=\"right\">%.1f</td>\n"
                "</tr>\n",
                (float)(100*(int)nFlowTotUncompressedSize)/(float)nFlowTotCompressedSize-100) < 0)
        BufferTooShort();
    sendString(buf);
  }

  if(myGlobals.numNflowFlowsBadTemplRcvd > 0) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Number of nFlows with Unknown Templates Received</th>\n"
                "<td " TD_BG " align=\"right\">%s</td>\n"
                "</tr>\n",
              formatPkts(myGlobals.numNflowFlowsBadTemplRcvd, formatBuf, sizeof(formatBuf))) < 0)
        BufferTooShort();
    sendString(buf);
  }

  if(myGlobals.numNflowFlowsBadVersRcvd > 0) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Number of nFlows with Bad Version Received</th>\n"
                "<td " TD_BG " align=\"right\">%s</td>\n"
                "</tr>\n",
              formatPkts(myGlobals.numNflowFlowsBadVersRcvd, formatBuf, sizeof(formatBuf))) < 0)
        BufferTooShort();
    sendString(buf);
  }

  sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
             "<tr " TR_ON ">\n"
             "<th colspan=\"2\" "DARK_BG">Discarded Flows</th>\n"
             "</tr>\n");

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Flows with Zero Packet Count</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numBadFlowPkts, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Flows with Zero Byte Count</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numBadFlowBytes, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Flows with Bad Data</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numBadFlowReality, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Flows with Unknown Template</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numNetFlowsV9UnknTemplRcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Total Number of Flows Processed</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.numNetFlowsProcessed, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if((myGlobals.numSrcNetFlowsEntryFailedWhiteList +
      myGlobals.numSrcNetFlowsEntryFailedBlackList +
      myGlobals.numDstNetFlowsEntryFailedWhiteList +
      myGlobals.numDstNetFlowsEntryFailedBlackList) > 0) {

    sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
               "<tr " TR_ON ">\n"
               "<th colspan=\"2\" "DARK_BG">Accepted/Rejected Flows</th>\n"
               "</tr>\n"
               "<tr " TR_ON ">\n"
               "<th " DARK_BG">&nbsp;</th>\n"
               "<th " DARK_BG">Source / Destination</th>\n"
               "</tr>\n");

    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Rejected - Black list</th>\n"
                "<td " TD_BG ">%s&nbsp;/&nbsp;%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.numSrcNetFlowsEntryFailedBlackList,
                           formatBuf, sizeof(formatBuf)),
                formatPkts(myGlobals.numDstNetFlowsEntryFailedBlackList,
                           formatBuf2, sizeof(formatBuf2))) < 0)
        BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Rejected - White list</th>\n"
                "<td " TD_BG ">%s&nbsp;/&nbsp;%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.numSrcNetFlowsEntryFailedWhiteList,
                           formatBuf, sizeof(formatBuf)),
                formatPkts(myGlobals.numDstNetFlowsEntryFailedWhiteList,
                           formatBuf2, sizeof(formatBuf2))) < 0)
        BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Accepted</th>\n"
                "<td " TD_BG ">%s&nbsp;/&nbsp;%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.numSrcNetFlowsEntryAccepted,
                           formatBuf, sizeof(formatBuf)),
                formatPkts(myGlobals.numDstNetFlowsEntryAccepted,
                           formatBuf2, sizeof(formatBuf2))) < 0)
        BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                  "<th " TH_BG " align=\"left\" "DARK_BG ">Total</th>\n"
                "<td " TD_BG ">%s&nbsp;/&nbsp;%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.numSrcNetFlowsEntryFailedBlackList +
                           myGlobals.numSrcNetFlowsEntryFailedWhiteList +
                           myGlobals.numSrcNetFlowsEntryAccepted,
                           formatBuf, sizeof(formatBuf)),
                formatPkts(myGlobals.numDstNetFlowsEntryFailedBlackList +
                           myGlobals.numDstNetFlowsEntryFailedWhiteList +
                           myGlobals.numDstNetFlowsEntryAccepted,
                           formatBuf2, sizeof(formatBuf2))) < 0)
        BufferTooShort();
    sendString(buf);
  }

#ifdef DEBUG
  sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
             "<tr " TR_ON ">\n"
             "<th colspan=\"2\" "DARK_BG">Debug></th>\n"
             "</tr>\n"
             "<tr " TR_ON ">\n"
             "<th " TH_BG " align=\"left\" "DARK_BG ">White net list</th>\n"
             "<td " TD_BG ">");

  if(numWhiteNets == 0) {
    sendString("none");
  } else {
    sendString("Network&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
               "Netmask&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
               "Hostmask<br>\n");

    for(i=0; i<numWhiteNets; i++) {
      if(snprintf(buf, sizeof(buf),
                  "<br>\n%3d.&nbsp;%08x(%3d.%3d.%3d.%3d)&nbsp;"
                  "%08x(%3d.%3d.%3d.%3d)&nbsp;%08x(%3d.%3d.%3d.%3d)",
                  i,
                  whiteNetworks[i][0],
                  ((whiteNetworks[i][0] >> 24) & 0xff),
                  ((whiteNetworks[i][0] >> 16) & 0xff),
                  ((whiteNetworks[i][0] >>  8) & 0xff),
                  ((whiteNetworks[i][0]      ) & 0xff),
                  whiteNetworks[i][1],
                  ((whiteNetworks[i][1] >> 24) & 0xff),
                  ((whiteNetworks[i][1] >> 16) & 0xff),
                  ((whiteNetworks[i][1] >>  8) & 0xff),
                  ((whiteNetworks[i][1]      ) & 0xff),
                  whiteNetworks[i][2],
                  ((whiteNetworks[i][2] >> 24) & 0xff),
                  ((whiteNetworks[i][2] >> 16) & 0xff),
                  ((whiteNetworks[i][2] >>  8) & 0xff),
                  ((whiteNetworks[i][2]      ) & 0xff)
                  ) < 0)
        BufferTooShort();
      sendString(buf);
      if(i<numWhiteNets) sendString("<br>\n");
    }
  }

  sendString("</td>\n</tr>\n");

  sendString("<tr " TR_ON ">\n"
             "<th " TH_BG " align=\"left\" "DARK_BG ">Black net list</th>\n"
             "<td " TD_BG ">");

  if(numBlackNets == 0) {
    sendString("none");
  } else {
    sendString("Network&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
               "Netmask&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
               "Hostmask<br>\n");

    for(i=0; i<numBlackNets; i++) {
      if(snprintf(buf, sizeof(buf),
                  "<br>\n%3d.&nbsp;%08x(%3d.%3d.%3d.%3d)&nbsp;"
                  "%08x(%3d.%3d.%3d.%3d)&nbsp;%08x(%3d.%3d.%3d.%3d)",
                  i,
                  blackNetworks[i][0],
                  ((blackNetworks[i][0] >> 24) & 0xff),
                  ((blackNetworks[i][0] >> 16) & 0xff),
                  ((blackNetworks[i][0] >>  8) & 0xff),
                  ((blackNetworks[i][0]      ) & 0xff),
                  blackNetworks[i][1],
                  ((blackNetworks[i][1] >> 24) & 0xff),
                  ((blackNetworks[i][1] >> 16) & 0xff),
                  ((blackNetworks[i][1] >>  8) & 0xff),
                  ((blackNetworks[i][1]      ) & 0xff),
                  blackNetworks[i][2],
                  ((blackNetworks[i][2] >> 24) & 0xff),
                  ((blackNetworks[i][2] >> 16) & 0xff),
                  ((blackNetworks[i][2] >>  8) & 0xff),
                  ((blackNetworks[i][2]      ) & 0xff)
                  ) < 0)
        BufferTooShort();
      sendString(buf);
      if(i<numBlackNets) sendString("<br>\n");
    }
  }

  sendString("</td>\n</tr>\n");

#endif

  sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
             "<tr " TR_ON ">\n"
             "<th colspan=\"2\" "DARK_BG">Less: Ignored Flows</th>\n"
             "</tr>\n"
             "<tr " TR_ON ">\n"
             "<th " DARK_BG ">&nbsp;</th>\n"
             "<th><table width=\"100%\" border=\"0\" "TABLE_DEFAULTS">\n"
             "<tr><th " TH_BG " width=\"50%\" align=\"right\">Flows</th>\n"
                 "<th " TH_BG " width=\"50%\" align=\"right\">Bytes</th></tr>\n"
             "</table></th>\n"
             "</tr>\n");

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Port(s) zero (not tcp/ip)</th>\n"
              "<td><table width=\"100%\" border=\"0\" "TABLE_DEFAULTS">\n"
              "<tr><td width=\"50%\" " TD_BG " align=\"right\">%u</td>\n"
              "<td width=\"50%\" " TD_BG " align=\"right\">%s</td></tr>\n"
              "</table></td>\n"
              "</tr>\n",
              flowIgnoredZeroPort,
              formatBytes(flowIgnoredZeroPortBytes, 1, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">netFlow port</th>\n"
              "<td><table width=\"100%\" border=\"0\" "TABLE_DEFAULTS">\n"
              "<tr><td width=\"50%\" " TD_BG " align=\"right\">%u</td>\n"
              "<td width=\"50%\" " TD_BG " align=\"right\">%s</td></tr>\n"
              "</table></td>\n"
              "</tr>\n",
              flowIgnoredNetFlow,
              formatBytes(flowIgnoredNetFlowBytes, 1, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Unrecognized port &lt;= 1023</th>\n"
              "<td><table width=\"100%\" border=\"0\" "TABLE_DEFAULTS">\n"
              "<tr><td width=\"50%\" " TD_BG " align=\"right\">%u</td>\n"
              "<td width=\"50%\" " TD_BG " align=\"right\">%s</td></tr>\n"
              "</table></td>\n"
              "</tr>\n",
              flowIgnoredLowPort,
              formatBytes(flowIgnoredLowPortBytes, 1, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Unrecognized port &gt; 1023</th>\n"
              "<td><table width=\"100%\" border=\"0\" "TABLE_DEFAULTS">\n"
              "<tr><td width=\"50%\" " TD_BG " align=\"right\">%u</td>\n"
              "<td width=\"50%\" " TD_BG " align=\"right\">%s</td></tr>\n"
              "</table></td>\n"
              "</tr>\n",
              flowIgnoredHighPort,
              formatBytes(flowIgnoredHighPortBytes, 1, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);

  sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
             "<tr " TR_ON ">\n"
             "<th colspan=\"2\" "DARK_BG">Gives: Counted Flows</th>\n"
             "</tr>\n"
             "<tr " TR_ON ">\n"
             "<th " DARK_BG ">&nbsp;</th>\n"
             "<th><table width=\"100%\" border=\"0\" "TABLE_DEFAULTS">\n"
             "<tr><th " TH_BG " width=\"50%\" align=\"right\">Flows</th>\n"
                 "<th " TH_BG " width=\"50%\" align=\"right\">Bytes</th></tr>\n"
             "</table></th>\n"
             "</tr>\n");

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Processed</th>\n"
              "<td><table width=\"100%\" border=\"0\" "TABLE_DEFAULTS">\n"
              "<tr><td width=\"50%\" " TD_BG " align=\"right\">%u</td>\n"
              "<td width=\"50%\" " TD_BG " align=\"right\">%s</td></tr>\n"
              "</table></td>\n"
              "</tr>\n",
              flowProcessed,
              formatBytes(flowProcessedBytes, 1, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
  sendString(buf);


  if((flowAssumedFtpData>0) || (myGlobals.netFlowAssumeFTP)) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Assumed ftpdat</th>\n"
                "<td><table width=\"100%\" border=\"0\" "TABLE_DEFAULTS">\n"
                "<tr><td width=\"50%\" " TD_BG " align=\"right\">%u</td>\n"
                "<td width=\"50%\" " TD_BG " align=\"right\">%s</td></tr>\n"
                "</table></td>\n"
                "</tr>\n",
                flowAssumedFtpData,
                formatBytes(flowAssumedFtpDataBytes, 1, formatBuf, sizeof(formatBuf))) < 0)
        BufferTooShort();
    sendString(buf);
  }

  if(flowIgnoredNetFlow > 0) {
    sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
	       "<tr " TR_ON ">\n"
	       "<th colspan=\"2\" "DARK_BG">Most Recent Ignored Flows</th>\n"
	       "</tr>\n"
	       "<tr " TR_ON ">\n"
	       "<th colspan=\"2\"><table width=\"100%\" border=\"0\" "TABLE_DEFAULTS">"
	       "<tr><th colspan=\"2\">Flow</th>\n"
	       "<th>Bytes</th>\n"
	       "<th># Consecutive<br>Counts</th></tr>\n");

    for (i=nextFlowIgnored; i<nextFlowIgnored+MAX_NUM_IGNOREDFLOWS; i++) {
      if ((flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0] != 0) &&
	  (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2] != 0) ) {
	if(flowIgnored[i%MAX_NUM_IGNOREDFLOWS][4] > 1) {
	  if(snprintf(buf1, sizeof(buf1), "(%d) ", flowIgnored[i%MAX_NUM_IGNOREDFLOWS][4]) < 0)
	    BufferTooShort();
	} else {
	  if(snprintf(buf1, sizeof(buf1), "&nbsp;") < 0)
	    BufferTooShort();
	}
	if (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][5] > 1536*1024*1024 /* ~1.5GB */) {
	  if(snprintf(buf2, sizeof(buf2), "%.1fGB",
		      (float)flowIgnored[i%MAX_NUM_IGNOREDFLOWS][5] / (1024.0*1024.0*1024.0)) < 0)
	    BufferTooShort();
	} else if (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][4] > 1536*1024 /* ~1.5MB */) {
	  if(snprintf(buf2, sizeof(buf2), "%.1fMB",
		      (float)flowIgnored[i%MAX_NUM_IGNOREDFLOWS][5] / (1024.0*1024.0)) < 0)
	    BufferTooShort();
	} else {
	  if(snprintf(buf2, sizeof(buf2), "%u",
		      flowIgnored[i%MAX_NUM_IGNOREDFLOWS][5]) < 0)
	    BufferTooShort();
	}
	if(snprintf(buf, sizeof(buf),
		    "<tr><td align=\"right\">%d.%d.%d.%d:%d</td>"
		    "<td align=\"left\">-> %d.%d.%d.%d:%d</td>"
		    "<td align=\"right\">%s</td>"
		    "<td align=\"right\">%s</td></tr>\n",
		    (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0] >> 24) & 0xff,
		    (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0] >> 16) & 0xff,
		    (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0] >>  8) & 0xff,
		    (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0]      ) & 0xff,
		    flowIgnored[i%MAX_NUM_IGNOREDFLOWS][1],
		    (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2] >> 24) & 0xff,
		    (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2] >> 16) & 0xff,
		    (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2] >>  8) & 0xff,
		    (flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2]      ) & 0xff,
		    flowIgnored[i%MAX_NUM_IGNOREDFLOWS][3],
		    buf2, buf1) < 0)
	  BufferTooShort();
	sendString(buf);
      }
    }

    sendString("</table>");
  }
}

/* ****************************** */

static void handleNetflowHTTPrequest(char* url) {
  char buf[512], workList[1024];
  u_int i;

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);

  /* ****************************
   * Process URL stuff          *
   ****************************** */
  if(url != NULL) {
    char *device, *value = NULL;

    device = strtok(url, "=");
    if(device != NULL) value = strtok(NULL, "="); else value = NULL;

    if(value && device) {
      if(strcmp(device, "port") == 0) {
	myGlobals.netFlowInPort = atoi(value);
	storePrefsValue("netFlow.netFlowInPort", value);
	setNetFlowInSocket();
      } else if(strcmp(device, "debug") == 0) {
	myGlobals.netFlowDebug = atoi(value);
	storePrefsValue("netFlow.debug", value);
      } else if(strcmp(device, "netFlowAggregation") == 0) {
	myGlobals.netFlowAggregation = atoi(value);
	storePrefsValue("netFlow.netFlowAggregation", value);
      } else if(strcmp(device, "netFlowAssumeFTP") == 0) {
	myGlobals.netFlowAssumeFTP = atoi(value);
	storePrefsValue("netFlow.netFlowAssumeFTP", value);
      } else if(strcmp(device, "ifNetMask") == 0) {
	int a, b, c, d, a1, b1, c1, d1;

	if(sscanf(value, "%d.%d.%d.%d/%d.%d.%d.%d",
		  &a, &b, &c, &d, &a1, &b1, &c1, &d1) == 8) {
	  myGlobals.netFlowIfAddress.s_addr =(a << 24) +(b << 16) +(c << 8) + d;
	  myGlobals.netFlowIfMask.s_addr    =(a1 << 24) +(b1 << 16) +(c1 << 8) + d1;
	  storePrefsValue("netFlow.ifNetMask", value);
	  freeNetFlowMatrixMemory(); setNetFlowInterfaceMatrix();
	} else if(sscanf(value, "%d.%d.%d.%d/%d",
			 &a, &b, &c, &d, &a1) == 5) {
	  myGlobals.netFlowIfAddress.s_addr = (a << 24) +(b << 16) +(c << 8) + d;
	  myGlobals.netFlowIfMask.s_addr    = 0xffffffff >> a1;
	  myGlobals.netFlowIfMask.s_addr =~ myGlobals.netFlowIfMask.s_addr;
	  storePrefsValue("netFlow.ifNetMask", value);
	  freeNetFlowMatrixMemory(); setNetFlowInterfaceMatrix();
	} else
	  traceEvent(CONST_TRACE_ERROR, "NETFLOW: HTTP request netmask parse error (%s)", value);
      } else if(strcmp(device, "whiteList") == 0) {
	/* Cleanup the http control char xform */
	char *fPtr=value, *tPtr=value;
	while(fPtr[0] != '\0') {
	  if((fPtr[0] == '%') &&(fPtr[1] == '2')) {
	    *tPtr++ =(fPtr[2] == 'C') ? ',' : '/';
	    fPtr += 3;
	  } else {
	    *tPtr++ = *fPtr++;
	  }
	}
	tPtr[0]='\0';

#ifdef CFG_MULTITHREADED
	accessMutex(&whiteblackListMutex, "handleNetflowHTTPrequest()w");
#endif
	handleWhiteBlackListAddresses(value,
				      whiteNetworks,
				      &numWhiteNets,
				      (char*)&workList,
				      sizeof(workList));
	if(myGlobals.netFlowWhiteList != NULL) free(myGlobals.netFlowWhiteList);
	myGlobals.netFlowWhiteList=strdup(workList);
#ifdef CFG_MULTITHREADED
	releaseMutex(&whiteblackListMutex);
#endif
	storePrefsValue("netFlow.whiteList", myGlobals.netFlowWhiteList);
      } else if(strcmp(device, "blackList") == 0) {
	/* Cleanup the http control char xform */
	char *fPtr=value, *tPtr=value;
	while(fPtr[0] != '\0') {
	  if((fPtr[0] == '%') &&(fPtr[1] == '2')) {
	    *tPtr++ =(fPtr[2] == 'C') ? ',' : '/';
	    fPtr += 3;
	  } else {
	    *tPtr++ = *fPtr++;
	  }
	}
	tPtr[0]='\0';

#ifdef CFG_MULTITHREADED
	accessMutex(&whiteblackListMutex, "handleNetflowHTTPrequest()b");
#endif
	handleWhiteBlackListAddresses(value,
				      blackNetworks,
				      &numBlackNets,
				      (char*)&workList,
				      sizeof(workList));
	if(myGlobals.netFlowBlackList != NULL) free(myGlobals.netFlowBlackList);
	myGlobals.netFlowBlackList=strdup(workList);
#ifdef CFG_MULTITHREADED
	releaseMutex(&whiteblackListMutex);
#endif
	storePrefsValue("netFlow.blackList", myGlobals.netFlowBlackList);
      }
    }
  }

  /* ****************************
   * Print Configuration stuff  *
   ****************************** */
  printHTMLheader("NetFlow Configuration", NULL, 0);
  printNetFlowConfiguration();

  sendString("<br><hr><p>\n");

  if(myGlobals.numNetFlowsPktsRcvd > 0) {
    /* ****************************
     * Print statistics           *
     ****************************** */
    printSectionTitle("Flow Statistics");

    sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");

    if(myGlobals.numNetFlowsPktsRcvd > 0)
      printNetFlowStatisticsRcvd();

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

#ifdef CFG_MULTITHREADED
    if(whiteblackListMutex.isLocked) {
      sendString("<table><tr><td colspan=\"2\">&nbsp;</td></tr>\n"
		 "<tr " TR_ON ">\n"
		 "<th colspan=\"2\" "DARK_BG">Mutexes</th>\n"
		 "</tr>\n");

      sendString("<tr " TR_ON ">\n"
		 "<th>List Mutex</th>\n<td><table>");
      printMutexStatus(FALSE, &whiteblackListMutex, "White/Black list mutex");
      sendString("</table><td></tr></table>\n");
    }
#endif
  }

  /* ******************************
   * Print closing              *
   ****************************** */

  sendString("<table border=\"0\"><tr><td width=\"10%\">&nbsp;</td>\n"
             "<td><p>Please be aware that <b>ntop</b> is not the best solution if you "
	     "only need a NetFlow probe. If you need a fast, light, memory savvy, "
             "highly configurable NetFlow probe, you better give "
	     "<a href=\"http://www.ntop.org/nProbe.html\" title=\"nProbe page\"><b>nProbe</b></a> "
             "a try.</p>\n"
	     "<p>If you are looking for a cheap, dedicated hardware NetFlow probe you "
	     "should look into "
             "<a href=\"http://www.ntop.org/nBox86/\" "
	     "title=\"nBox86 page\"><b>nBox<sup>86</sup></b></a> "
	     "<img src=\"/nboxLogo.gif\" alt=\"nBox logo\">.</p>\n"
	     "</td>\n"
             "<td width=\"10%\">&nbsp;</td>\n</tr>\n</table>\n");

  printPluginTrailer((myGlobals.numNetFlowsPktsRcvd > 0) ?
		     netflowPluginInfo->pluginURLname : NULL,
                     "NetFlow is a trademark of <a href=\"http://www.cisco.com/\" "
                     "title=\"Cisco home page\">Cisco Systems</a>");

  printHTMLtrailer();
}

/* ****************************** */

static void termNetflowFunct(void) {
#ifdef CFG_MULTITHREADED
  if(threadActive) {
    killThread(&netFlowThread);
    threadActive = 0;
  }
  tryLockMutex(&whiteblackListMutex, "termNetflow");
  deleteMutex(&whiteblackListMutex);
#endif

  if(myGlobals.netFlowInSocket > 0) {
    closeNwSocket(&myGlobals.netFlowInSocket);
    myGlobals.device[myGlobals.netFlowDeviceId].activeDevice = 0;
  }

#ifdef HAVE_FILEDESCRIPTORBUG
  unwasteFileDescriptors();
#endif

  while(templates != NULL) {
    FlowSetV9 *temp = templates->next;

    free(templates->fields);
    free(templates);
    templates = temp;
  }

  traceEvent(CONST_TRACE_INFO, "NETFLOW: Thanks for using ntop NetFlow");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Done");
  fflush(stdout);
}

/* **************************************** */

#ifdef DEBUG_FLOWS

static void handleNetFlowPacket(u_char *_deviceId,
				const struct pcap_pkthdr *h,
				const u_char *p) {
  int sampledPacketSize;
  int deviceId, rc;

  if(myGlobals.rFileName != NULL) {
    /* ntop is reading packets from a file */
    struct ether_header ehdr;
    u_int caplen = h->caplen;
    u_int length = h->len;
    unsigned short eth_type;
    u_int8_t flags = 0;
    struct ip ip;

#ifdef DEBUG_FLOWS
    traceEvent(CONST_TRACE_INFO, "Rcvd packet to dissect [caplen=%d][len=%d]", caplen, length);
#endif

    if(caplen >= sizeof(struct ether_header)) {
      memcpy(&ehdr, p, sizeof(struct ether_header));
      eth_type = ntohs(ehdr.ether_type);

      if(eth_type == ETHERTYPE_IP) {
	u_int plen, hlen;
	u_short sport, dport;

#ifdef DEBUG_FLOWS
    traceEvent(CONST_TRACE_INFO, "Rcvd IP packet to dissect");
#endif

	memcpy(&ip, p+sizeof(struct ether_header), sizeof(struct ip));
	hlen =(u_int)ip.ip_hl * 4;
	NTOHL(ip.ip_dst.s_addr); NTOHL(ip.ip_src.s_addr);

	plen = length-sizeof(struct ether_header);

#ifdef DEBUG_FLOWS
	traceEvent(CONST_TRACE_INFO, "Rcvd IP packet to dissect [sender=%s][proto=%d][len=%d][hlen=%d]",
		   intoa(ip.ip_src), ip.ip_p, plen, hlen);
#endif

	if(ip.ip_p == IPPROTO_UDP) {
	  if(plen >(hlen+sizeof(struct udphdr))) {
	    char* rawSample    =(void*)(p+sizeof(struct ether_header)+hlen+sizeof(struct udphdr));
	    int   rawSampleLen = h->caplen-(sizeof(struct ether_header)+hlen+sizeof(struct udphdr));

#ifdef DEBUG_FLOWS
	    traceEvent(CONST_TRACE_INFO, "Rcvd from from %s", intoa(ip.ip_src));
#endif

	    myGlobals.numNetFlowsPktsRcvd++;
	    dissectFlow(rawSample, rawSampleLen);
	  }
	}
      } else {
#ifdef DEBUG_FLOWS
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
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Welcome to %s.(C) 2002-04 by Luca Deri",
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
