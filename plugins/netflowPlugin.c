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

#ifdef CFG_MULTITHREADED
static void* netflowMainLoop(void* _deviceId);
#endif

/* #define DEBUG_FLOWS */

/* ********************************* */

/* Forward */
static int setNetFlowInSocket(int);
static void setNetFlowInterfaceMatrix(int);
static void freeNetFlowMatrixMemory(int);
static void setPluginStatus(char * status);
static void ignoreFlow(u_short* theNextFlowIgnored, u_int srcAddr, u_short sport,
		       u_int dstAddr, u_short dport, Counter len, int deviceId);
static int initNetFlowFunct(void);
static void termNetflowFunct(void);
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

/* ****************************** */

static PluginInfo netflowPluginInfo[] = {
  {
    VERSION, /* current ntop version */
    "NetFlow",
    "This plugin is used to setup, activate and deactivate nFlow/NetFlow support.<br>"
    "<b>ntop</b> can both collect and receive "
    "<a href=\"http://www.ntop.org/nFlow/\" alt=\"link to nflow\">nFlow</A> "
    "and <A HREF=http://www.cisco.com/warp/public/cc/pd/iosw/ioft/neflct/tech/napps_wp.htm>NetFlow</A> "
    "V1/V5/V7/V9 data.<br>"
    "<i>Received flow data is reported as a separate 'NIC' in the regular <b>ntop</b> "
    "reports - <em>Remember to switch the reporting NIC via Admin | Switch NIC</em>.",
    "3.99", /* version */
    "<a href=\"http://luca.ntop.org/\" alt=\"Luca's home page\">L.Deri</A>",
    "NetFlow", /* http://<host>:<port>/plugins/NetFlow */
    0, /* Active by default */
    1, /* Inactive setup */
    initNetFlowFunct, /* InitFunc */
    termNetflowFunct, /* TermFunc */
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

static char* nfValue(int deviceId, char *name, int appendDeviceId) {
  static char buf[64];

  if(appendDeviceId) {
    if(snprintf(buf, sizeof(buf), "netflow.%d.%s",
		myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId, name) < 0)
      BufferTooShort();
  } else {
    if(snprintf(buf, sizeof(buf), "netflow.%s", name) < 0)
      BufferTooShort();
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "NETFLOW: nfValue=%s", buf);
#endif

  return(buf);
}

/* ****************************** */

#ifdef HAVE_FILEDESCRIPTORBUG

/* Burton - Aug2003
 *   Work-around for file descriptor bug (FreeBSD PR51535 et al)
 *   - burn some file descriptors so the socket() call doesn't get a dirty one.
 *   - it's not pretty, but it works...
 */

static void wasteFileDescriptors(int deviceId) {
  int i;

  if(myGlobals.device[deviceId].netflowGlobals->tempNFFilesCreated == 0) {
    myGlobals.device[deviceId].netflowGlobals->tempNFFilesCreated = 1;
    myGlobals.device[deviceId].netflowGlobals->tempNFFpid=getpid();
    traceEvent(CONST_TRACE_INFO, "NETFLOW: FILEDESCRIPTORBUG: Work-around activated");
    for(i=0; i<CONST_FILEDESCRIPTORBUG_COUNT; i++) {
      myGlobals.device[deviceId].netflowGlobals->tempNFF[i]=0;
      memset(&myGlobals.device[deviceId].netflowGlobals->tempNFFname[i], 0, LEN_MEDIUM_WORK_BUFFER);

      if(snprintf(myGlobals.device[deviceId].netflowGlobals->tempNFFname[i], LEN_MEDIUM_WORK_BUFFER, 
		  "/tmp/ntop-nf-%d-%09u-%d", deviceId, 
		  myGlobals.device[deviceId].netflowGlobals->tempNFFpid, i) < 0)
        BufferTooShort();
      traceEvent(CONST_TRACE_NOISY, "NETFLOW: FILEDESCRIPTORBUG: Creating %d, '%s'", i, 
		 myGlobals.device[deviceId].netflowGlobals->tempNFFname[i]);
      errno = 0;
      myGlobals.device[deviceId].netflowGlobals->tempNFF[i] =
	open(myGlobals.device[deviceId].netflowGlobals->tempNFFname[i],
	     O_CREAT|O_TRUNC|O_RDWR);
      if(errno != 0) {
        traceEvent(CONST_TRACE_ERROR,
                   "NETFLOW: FILEDESCRIPTORBUG: Unable to create file - may cause problems later - '%s'(%d)",
                   strerror(errno), errno);
      } else {
        traceEvent(CONST_TRACE_NOISY,
                   "NETFLOW: FILEDESCRIPTORBUG: Created file %d - '%s'(%d)",
                   i, myGlobals.device[deviceId].netflowGlobals->tempNFFname[i],
		   myGlobals.device[deviceId].netflowGlobals->tempNFF[i]);
      }
    }
  }
}

/* *********************************************** */

static void unwasteFileDescriptors(int deviceId) {
  int i;

  /* Close and delete the temporary - junk - files */
  traceEvent(CONST_TRACE_INFO, "NETFLOW: FILEDESCRIPTORBUG: Bug work-around cleanup");
  for(i=CONST_FILEDESCRIPTORBUG_COUNT-1; i>=0; i--) {
    if(myGlobals.device[deviceId].netflowGlobals->tempNFF[i] >= 0) {
      traceEvent(CONST_TRACE_NOISY, "NETFLOW: FILEDESCRIPTORBUG: Removing %d, '%s'(%d)",
		 i, myGlobals.device[deviceId].netflowGlobals->tempNFFname[i], 
		 myGlobals.device[deviceId].netflowGlobals->tempNFF[i]);
      if(close(myGlobals.device[deviceId].netflowGlobals->tempNFF[i])) {
        traceEvent(CONST_TRACE_ERROR,
                   "NETFLOW: FILEDESCRIPTORBUG: Unable to close file %d - '%s'(%d)",
                   i,
                   strerror(errno), errno);
      } else {
        if(unlink(myGlobals.device[deviceId].netflowGlobals->tempNFFname[i]))
          traceEvent(CONST_TRACE_ERROR,
                     "NETFLOW: FILEDESCRIPTORBUG: Unable to delete file '%s' - '%s'(%d)",
                     myGlobals.device[deviceId].netflowGlobals->tempNFFname[i],
                     strerror(errno), errno);
        else
          traceEvent(CONST_TRACE_NOISY,
                     "NETFLOW: FILEDESCRIPTORBUG: Removed file '%s'",
                     myGlobals.device[deviceId].netflowGlobals->tempNFFname[i]);
      }
    }
  }
}
#endif

/* ****************************** */

static void freeNetFlowMatrixMemory(int deviceId) {
  /*
    NOTE: wee need to lock something here(TBD)
  */

  if((!myGlobals.device[deviceId].activeDevice) ||(deviceId == -1)) return;

  if(myGlobals.device[deviceId].ipTrafficMatrix != NULL) {
    int j;

    /* Courtesy of Wies-Software <wies@wiessoft.de> */
    for(j=0; j<(myGlobals.device[deviceId].numHosts *
		myGlobals.device[deviceId].numHosts); j++)
      if(myGlobals.device[deviceId].ipTrafficMatrix[j] != NULL)
	free(myGlobals.device[deviceId].ipTrafficMatrix[j]);

    free(myGlobals.device[deviceId].ipTrafficMatrix);
  }

  if(myGlobals.device[deviceId].ipTrafficMatrixHosts != NULL)
    free(myGlobals.device[deviceId].ipTrafficMatrixHosts);
}

/* ************************************************** */

static void setNetFlowInterfaceMatrix(int deviceId) {
  if((!myGlobals.device[deviceId].activeDevice)
     || (deviceId == -1))
    return;

  myGlobals.device[deviceId].numHosts       = 0xFFFFFFFF - myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr+1;
  myGlobals.device[deviceId].ifAddr.s_addr  = myGlobals.device[deviceId].netflowGlobals->netFlowIfAddress.s_addr;
  myGlobals.device[deviceId].network.s_addr = myGlobals.device[deviceId].netflowGlobals->netFlowIfAddress.s_addr;
  myGlobals.device[deviceId].netmask.s_addr = myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr;

  if(myGlobals.device[deviceId].numHosts > MAX_SUBNET_HOSTS) {
    myGlobals.device[deviceId].numHosts = MAX_SUBNET_HOSTS;
    traceEvent(CONST_TRACE_WARNING, "NETFLOW: Truncated network size(device %s) to %d hosts(real netmask %s).",
	       myGlobals.device[deviceId].name, myGlobals.device[deviceId].numHosts,
	       intoa(myGlobals.device[deviceId].netmask));
  }

  myGlobals.device[deviceId].ipTrafficMatrix =
    (TrafficEntry**)calloc(myGlobals.device[deviceId].numHosts*
			   myGlobals.device[deviceId].numHosts,
			   sizeof(TrafficEntry*));
  myGlobals.device[deviceId].ipTrafficMatrixHosts =
    (struct hostTraffic**)calloc(sizeof(struct hostTraffic*),
				 myGlobals.device[deviceId].numHosts);
}

/* ************************************** */

static int setNetFlowInSocket(int deviceId) {
  struct sockaddr_in sockIn;
  int sockopt = 1;

  if(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket > 0) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Collector terminated");
    closeNwSocket(&myGlobals.device[deviceId].netflowGlobals->netFlowInSocket);
#ifdef HAVE_SCTP
    closeNwSocket(&myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket);
#endif
  }

  if(myGlobals.device[deviceId].netflowGlobals->netFlowInPort > 0) {
    errno = 0;
    myGlobals.device[deviceId].netflowGlobals->netFlowInSocket = socket(AF_INET, SOCK_DGRAM, 0);
#ifdef HAVE_SCTP
    myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
#endif

    if((myGlobals.device[deviceId].netflowGlobals->netFlowInSocket <= 0)
#ifdef HAVE_SCTP
       || (myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket <= 0)
#endif
       || (errno != 0) ) {
      traceEvent(CONST_TRACE_INFO, "NETFLOW: Unable to create a socket - returned %d, error is '%s'(%d)",
		 myGlobals.device[deviceId].netflowGlobals->netFlowInSocket, strerror(errno), errno);
      setPluginStatus("Disabled - Unable to create listening socket.");
      return(-1);
    }

    traceEvent(CONST_TRACE_INFO, "NETFLOW: Created a UDP socket (%d)",
	       myGlobals.device[deviceId].netflowGlobals->netFlowInSocket);
#ifdef HAVE_SCTP
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
       || (bind(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket,
		(struct sockaddr *)&sockIn, sizeof(sockIn)) < 0)
#endif
       ) {
      traceEvent(CONST_TRACE_ERROR, "NETFLOW: Collector port %d already in use",
		 myGlobals.device[deviceId].netflowGlobals->netFlowInPort);
      closeNwSocket(&myGlobals.device[deviceId].netflowGlobals->netFlowInSocket);
      myGlobals.device[deviceId].netflowGlobals->netFlowInSocket = 0;
#ifdef HAVE_SCTP
      closeNwSocket(&myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket);
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

#ifdef CFG_MULTITHREADED
  if((myGlobals.device[deviceId].netflowGlobals->netFlowInPort != 0)
     && (!myGlobals.device[deviceId].netflowGlobals->threadActive)) {
    /* This plugin works only with threads */
    createThread(&myGlobals.device[deviceId].netflowGlobals->netFlowThread,
		 netflowMainLoop, (void*)deviceId);
  }
#endif

  return(0);
}

/* *************************** */

static void ignoreFlow(u_short* theNextFlowIgnored, u_int srcAddr, u_short sport,
		       u_int dstAddr, u_short dport,
		       Counter len, int deviceId) {
  u_short lastFlowIgnored;

  lastFlowIgnored = (*theNextFlowIgnored-1+MAX_NUM_IGNOREDFLOWS) % MAX_NUM_IGNOREDFLOWS;
  if ( (myGlobals.device[deviceId].netflowGlobals->flowIgnored[lastFlowIgnored][0] == srcAddr) &&
       (myGlobals.device[deviceId].netflowGlobals->flowIgnored[lastFlowIgnored][1] == sport) &&
       (myGlobals.device[deviceId].netflowGlobals->flowIgnored[lastFlowIgnored][2] == dstAddr) &&
       (myGlobals.device[deviceId].netflowGlobals->flowIgnored[lastFlowIgnored][3] == dport) ) {
    myGlobals.device[deviceId].netflowGlobals->flowIgnored[lastFlowIgnored][4]++;
    myGlobals.device[deviceId].netflowGlobals->flowIgnored[lastFlowIgnored][5] += len;
  } else {
    myGlobals.device[deviceId].netflowGlobals->flowIgnored[*theNextFlowIgnored][0] = srcAddr;
    myGlobals.device[deviceId].netflowGlobals->flowIgnored[*theNextFlowIgnored][1] = sport;
    myGlobals.device[deviceId].netflowGlobals->flowIgnored[*theNextFlowIgnored][2] = dstAddr;
    myGlobals.device[deviceId].netflowGlobals->flowIgnored[*theNextFlowIgnored][3] = dport;
    myGlobals.device[deviceId].netflowGlobals->flowIgnored[*theNextFlowIgnored][4] = 1;
    myGlobals.device[deviceId].netflowGlobals->flowIgnored[*theNextFlowIgnored][5] = len;
    *theNextFlowIgnored = (*theNextFlowIgnored + 1) % MAX_NUM_IGNOREDFLOWS;
  }
}

/* ****************************** */

static int handleV5Flow(time_t recordActTime,
			time_t recordSysUpTime,
			struct flow_ver5_rec *record,
			int deviceId) {
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
  struct pcap_pkthdr h;
  struct tcphdr tp;
  IPSession *session = NULL;
  time_t firstSeen, lastSeen;

  myGlobals.device[deviceId].netflowGlobals->numNetFlowsRcvd++;

  numPkts  = ntohl(record->dPkts);
  len      = (Counter)ntohl(record->dOctets);

  /* Bad flow(zero packets) */
  if(numPkts == 0) {
    myGlobals.device[deviceId].netflowGlobals->numBadFlowPkts++;
    return(0);
  }
  /* Bad flow(zero length) */
  if(len == 0) {
    myGlobals.device[deviceId].netflowGlobals->numBadFlowBytes++;
    return(0);
  }
  /* Bad flow(more packets than bytes) */
  if(numPkts > len) {
    myGlobals.device[deviceId].netflowGlobals->numBadFlowReality++;
    return(0);
  }
  firstSeen = ntohl(record->First);
  lastSeen  = ntohl(record->Last);

  /* Sanity check */
  if(firstSeen > lastSeen)
    firstSeen = lastSeen;

  myGlobals.device[deviceId].netflowGlobals->numNetFlowsProcessed++;

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

  switch(myGlobals.device[deviceId].netflowGlobals->netFlowAggregation) {
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
    }
  }

  if(!skipDST) {
    switch((skipDST = isOKtoSave(ntohl(record->dstaddr),
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
    dstHost = lookupHost(&addr1, NULL, -1 /* no VLAN */, 0, 1, deviceId);
  else
    dstHost = myGlobals.device[deviceId].netflowGlobals->dummyHost;

  if(!skipSRC)
    srcHost = lookupHost(&addr2, NULL, -1 /* no VLAN */, 0, 1, deviceId);
  else
    srcHost = myGlobals.device[deviceId].netflowGlobals->dummyHost;

  if((srcHost == NULL) ||(dstHost == NULL)) return(0);

  recordActTime   = ntohl(recordActTime);
  recordSysUpTime = ntohl(recordSysUpTime);

  srcHost->lastSeen = dstHost->lastSeen = recordActTime;
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
	  if((dport == myGlobals.device[deviceId].netflowGlobals->netFlowInPort)
	     || (sport == myGlobals.device[deviceId].netflowGlobals->netFlowInPort)) {
	    myGlobals.device[deviceId].netflowGlobals->flowIgnoredNetFlow++;
	    myGlobals.device[deviceId].netflowGlobals->flowIgnoredNetFlowBytes += len;
	  } else if(min(sport, dport) <= 1023) {
	    myGlobals.device[deviceId].netflowGlobals->flowIgnoredLowPort++;
	    myGlobals.device[deviceId].netflowGlobals->flowIgnoredLowPortBytes += len;
	    ignoreFlow(&myGlobals.device[deviceId].netflowGlobals->nextFlowIgnored,
		       ntohl(record->srcaddr), sport,
		       ntohl(record->dstaddr), dport,
		       len, deviceId);
	  } else if(myGlobals.device[deviceId].netflowGlobals->netFlowAssumeFTP) {
	    /* If the user wants (via a run-time parm), as a last resort
	     * we assume it's ftp-data traffic
	     */
	    handleIP((u_short)CONST_FTPDATA, srcHost, dstHost, len, 0, 0, actualDeviceId);
	    myGlobals.device[deviceId].netflowGlobals->flowAssumedFtpData++;
	    myGlobals.device[deviceId].netflowGlobals->flowAssumedFtpDataBytes += len;
	  } else {
	    myGlobals.device[deviceId].netflowGlobals->flowIgnoredHighPort++;
	    myGlobals.device[deviceId].netflowGlobals->flowIgnoredHighPortBytes += len;
	    ignoreFlow(&myGlobals.device[deviceId].netflowGlobals->nextFlowIgnored,
		       ntohl(record->srcaddr), sport,
		       ntohl(record->dstaddr), dport,
		       len, deviceId);
	  }
	} else {
	  myGlobals.device[deviceId].netflowGlobals->flowProcessed++;
	  myGlobals.device[deviceId].netflowGlobals->flowProcessedBytes += len;
	}
      } else {
	myGlobals.device[deviceId].netflowGlobals->flowProcessed++;
	myGlobals.device[deviceId].netflowGlobals->flowProcessedBytes += len;
      }
    } else {
      if(handleIP(sport, srcHost, dstHost, len, 0, 0, actualDeviceId) == -1) {
	if(handleIP(dport, srcHost, dstHost, len, 0, 0, actualDeviceId) == -1) {
	  if((dport == myGlobals.device[deviceId].netflowGlobals->netFlowInPort)
	     || (sport == myGlobals.device[deviceId].netflowGlobals->netFlowInPort)) {
	    myGlobals.device[deviceId].netflowGlobals->flowIgnoredNetFlow++;
	  } else if(min(sport, dport) <= 1023) {
	    myGlobals.device[deviceId].netflowGlobals->flowIgnoredLowPort++;
	    myGlobals.device[deviceId].netflowGlobals->flowIgnoredLowPortBytes += len;
	    ignoreFlow(&myGlobals.device[deviceId].netflowGlobals->nextFlowIgnored,
		       ntohl(record->srcaddr), sport,
		       ntohl(record->dstaddr), dport,
		       len, deviceId);
	  } else if(myGlobals.device[deviceId].netflowGlobals->netFlowAssumeFTP) {
	    /* If the user wants (via a run-time parm), as a last resort
	     * we assume it's ftp-data traffic
	     */
	    handleIP((u_short)CONST_FTPDATA, srcHost, dstHost, len, 0, 0, actualDeviceId);
	    myGlobals.device[deviceId].netflowGlobals->flowAssumedFtpData++;
	    myGlobals.device[deviceId].netflowGlobals->flowAssumedFtpDataBytes += len;
	  } else {
	    myGlobals.device[deviceId].netflowGlobals->flowIgnoredHighPort++;
	    myGlobals.device[deviceId].netflowGlobals->flowIgnoredHighPortBytes += len;
	    ignoreFlow(&myGlobals.device[deviceId].netflowGlobals->nextFlowIgnored,
		       ntohl(record->srcaddr), sport,
		       ntohl(record->dstaddr), dport,
		       len, deviceId);
	  }
	} else {
	  myGlobals.device[deviceId].netflowGlobals->flowProcessed++;
	  myGlobals.device[deviceId].netflowGlobals->flowProcessedBytes += len;
	}
      } else {
	myGlobals.device[deviceId].netflowGlobals->flowProcessed++;
	myGlobals.device[deviceId].netflowGlobals->flowProcessedBytes += len;
      }
    }
  } else {
    myGlobals.device[deviceId].netflowGlobals->flowIgnoredZeroPort++;
    myGlobals.device[deviceId].netflowGlobals->flowIgnoredZeroPortBytes += len;
    ignoreFlow(&myGlobals.device[deviceId].netflowGlobals->nextFlowIgnored,
	       ntohl(record->srcaddr), sport,
	       ntohl(record->dstaddr), dport,
	       len, deviceId);
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

  h.ts.tv_sec = recordActTime, h.ts.tv_usec = 0;

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

    tp.th_sport = htons(sport), tp.th_dport = htons(dport);
    tp.th_flags = record->tcp_flags;
    session = handleTCPSession(&h, 0, 0, srcHost, sport, dstHost, dport, len, &tp, 0, NULL, actualDeviceId);
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

    session = handleTCPSession(&h, 0, 0, srcHost, sport, dstHost, dport, len, NULL, 0, NULL, actualDeviceId);
    break;
  }

  if(session) {
    time_t timeDiff = recordActTime - (lastSeen - firstSeen);

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: %s:%d -> %s:%d [diff=%d][recordActTime=%d][last-first=%d]",
	       srcHost->hostNumIpAddress, sport,
	       dstHost->hostNumIpAddress, dport,
	       timeDiff, recordActTime, (lastSeen - firstSeen));
#endif

    if(session->firstSeen > timeDiff)
      session->firstSeen = timeDiff;

    session->lastSeen = recordActTime;
  }

#ifdef CFG_MULTITHREADED
  /* releaseMutex(&myGlobals.hostsHashMutex); */
#endif

  return(0);
}

/* *************************** */

static void dissectFlow(char *buffer, int bufferLen, int deviceId) {
  NetFlow5Record the5Record;
  int flowVersion;
  time_t recordActTime = 0, recordSysUpTime = 0;

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
      myGlobals.device[deviceId].netflowGlobals->numNetFlowsV1Rcvd += numFlows;
      recordActTime   = the1Record.flowHeader.unix_secs;
      recordSysUpTime = the1Record.flowHeader.sysUptime;
    } else {
      memcpy(&the7Record, buffer, bufferLen > sizeof(the7Record) ? sizeof(the7Record): bufferLen);
      numFlows = ntohs(the7Record.flowHeader.count);
      if(numFlows > CONST_V7FLOWS_PER_PAK) numFlows = CONST_V7FLOWS_PER_PAK;
      myGlobals.device[deviceId].netflowGlobals->numNetFlowsV7Rcvd += numFlows;
      recordActTime   = the7Record.flowHeader.unix_secs;
      recordSysUpTime = the7Record.flowHeader.sysUptime;
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
	  the5Record.flowRecord[i].dOctets = htonl(ntohl(the1Record.flowRecord[i].dPkts)*512);
	} else
	  the5Record.flowRecord[i].dOctets = the1Record.flowRecord[i].dOctets;

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

    recordActTime = the5Record.flowHeader.unix_secs;
    recordSysUpTime = the5Record.flowHeader.sysUptime;

    for(i=0; (!done) && (displ < bufferLen) && (i < numEntries); i++) {
      /* 1st byte */
      if(buffer[displ] == 0) {
	/* Template */
#ifdef DEBUG_FLOWS
	traceEvent(CONST_TRACE_INFO, "Found Template [displ=%d]", displ);
#endif

	myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9TemplRcvd++;

	if(bufferLen > (displ+sizeof(V9Template))) {
	  FlowSetV9 *cursor = myGlobals.device[deviceId].netflowGlobals->templates;
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
	    myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9BadTemplRcvd++;
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
	      cursor->next = myGlobals.device[deviceId].netflowGlobals->templates;
	      myGlobals.device[deviceId].netflowGlobals->templates = cursor;
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
	  myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9BadTemplRcvd++;
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
	  FlowSetV9 *cursor = myGlobals.device[deviceId].netflowGlobals->templates;

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

	      handleV5Flow(recordActTime, recordSysUpTime, &record, deviceId);
	      myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9Rcvd++;
	    }
	  } else {
#ifdef DEBUG_FLOWS
	    traceEvent(CONST_TRACE_INFO, ">>>>> Rcvd flow with UNKNOWN template %d", fs.templateId);
#endif
	    myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9UnknTemplRcvd++;
	  }
	}
      }
    } /* for */
  } else if(the5Record.flowHeader.version == htons(5)) {
    int i, numFlows = ntohs(the5Record.flowHeader.count);

    recordActTime   = the5Record.flowHeader.unix_secs;
    recordSysUpTime = the5Record.flowHeader.sysUptime;

    if(numFlows > CONST_V5FLOWS_PER_PAK) numFlows = CONST_V5FLOWS_PER_PAK;

#ifdef DEBUG_FLOWS
    traceEvent(CONST_TRACE_INFO, "dissectFlow(%d flows)", numFlows);
#endif

#ifdef CFG_MULTITHREADED
    /* Lock white/black lists for duration of this flow packet */
    accessMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex, "flowPacket");
#endif

    for(i=0; i<numFlows; i++)
      handleV5Flow(recordActTime, recordSysUpTime, &the5Record.flowRecord[i], deviceId);

    if(flowVersion == 5) /* Skip converted V1/V7 flows */
      myGlobals.device[deviceId].netflowGlobals->numNetFlowsV5Rcvd += numFlows;

#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
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
	  myGlobals.device[deviceId].netflowGlobals->numNflowFlowsBadVersRcvd++;
	} else {
	  int numRecords = 0, bufBegin, bufLen;

	  myGlobals.device[deviceId].netflowGlobals->nFlowTotCompressedSize += bufferLen,
	    myGlobals.device[deviceId].netflowGlobals->nFlowTotUncompressedSize += uncompressLen;

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
	      u_int16_t len, templateId;

	      memcpy(&templateId, &rcvdBuf[bufBegin], 2); bufBegin += 2; flowLen -= 2; templateId = ntohs(templateId);
	      memcpy(&len, &rcvdBuf[bufBegin], 2); bufBegin += 2; flowLen -= 2; len = ntohs(len);

#ifdef DEBUG_FLOWS
	      traceEvent(CONST_TRACE_INFO, "Template: [id=%d][len=%d]", templateId, len);
#endif

	      if(len > 16 /* MAX LEN */) {
		myGlobals.device[deviceId].netflowGlobals->numNflowFlowsBadTemplRcvd++;
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

	  for(i=0; i<numRecords; i++)
	    handleV5Flow(recordActTime, recordSysUpTime, &the5Record.flowRecord[i], deviceId);
	  myGlobals.device[deviceId].netflowGlobals->numNflowFlowsRcvd++;
	}
      } else {
#ifdef DEBUG_FLOWS
	traceEvent(CONST_TRACE_INFO, "Uncompress failed [rc=%d]. This is not an nFlow", rc);
#endif
      }
    } else
      myGlobals.device[deviceId].netflowGlobals->numBadNetFlowsVersionsRcvd++; /* CHANGE */
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

static void* netflowMainLoop(void* _deviceId) {
  fd_set netflowMask;
  int rc, len, deviceId;
  u_char buffer[2048];
  struct sockaddr_in fromHost;

  deviceId = (int)_deviceId;

  if(!(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket > 0)) return(NULL);

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
  traceEvent(CONST_TRACE_INFO, "THREADMGMT: netFlow thread(%ld) started",
	     myGlobals.device[deviceId].netflowGlobals->netFlowThread);

  for(;myGlobals.capturePackets == FLAG_NTOPSTATE_RUN;) {
    int maxSock = myGlobals.device[deviceId].netflowGlobals->netFlowInSocket;

    FD_ZERO(&netflowMask);
    FD_SET(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket, &netflowMask);

#ifdef HAVE_SCTP
    FD_SET(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket, &netflowMask);
    if(myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket > maxSock)
      maxSock = myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket;
#endif

    if((rc = select(maxSock+1, &netflowMask, NULL, NULL, NULL)) > 0) {

      if(FD_ISSET(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket, &netflowMask)){
	len = sizeof(fromHost);
	rc = recvfrom(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket,(char*)&buffer, sizeof(buffer),
		      0,(struct sockaddr*)&fromHost, &len);
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

#ifdef DEBUG_FLOWS
      traceEvent(CONST_TRACE_INFO, "NETFLOW_DEBUG: Received NetFlow packet(len=%d)(deviceId=%d)",
		 rc,  deviceId);
#endif

      if(rc > 0) {
	int i;

	myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd++;

	NTOHL(fromHost.sin_addr.s_addr);

	for(i=0; i<MAX_NUM_PROBES; i++) {
	  if(myGlobals.device[deviceId].netflowGlobals->probeList[i].probeAddr.s_addr == 0) {
	    myGlobals.device[deviceId].netflowGlobals->probeList[i].probeAddr.s_addr = fromHost.sin_addr.s_addr;
	    myGlobals.device[deviceId].netflowGlobals->probeList[i].pkts = 1;
	    break;
	  } else if(myGlobals.device[deviceId].netflowGlobals->probeList[i].probeAddr.s_addr == fromHost.sin_addr.s_addr) {
	    myGlobals.device[deviceId].netflowGlobals->probeList[i].pkts++;
	    break;
	  }
	}

	dissectFlow(buffer, rc, deviceId);
      }
    } else {
      if(rc < 0) {
	traceEvent(CONST_TRACE_FATALERROR, "NETFLOW: select() failed(%d, %s), terminating netFlow",
		   errno, strerror(errno));
	break;
      }
    }
  }

  myGlobals.device[deviceId].netflowGlobals->threadActive = 0;
  traceEvent(CONST_TRACE_INFO, "THREADMGMT: netFlow thread(%ld) terminated",
	     myGlobals.device[deviceId].netflowGlobals->netFlowThread);
  
  myGlobals.device[deviceId].activeDevice = 0;
  return(NULL);
}

#endif

/* ****************************** */

static void initNetFlowDevice(int deviceId) {
  int a, b, c, d, a1, b1, c1, d1, rc;
  char value[1024], workList[1024];

  traceEvent(CONST_TRACE_WARNING, "NETFLOW: initializing deviceId=%d", deviceId);

  if(myGlobals.device[deviceId].netflowGlobals == NULL) {
    traceEvent(CONST_TRACE_ERROR, "NETFLOW: initNetFlowDevice internal error");
    return;
  }

  setPluginStatus(NULL);

#ifdef CFG_MULTITHREADED
  myGlobals.device[deviceId].netflowGlobals->threadActive = 0;
  createMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
#else
  /* This plugin works only with threads */
  setPluginStatus("Disabled - requires POSIX thread support.");
  return(-1);
#endif

  memset(myGlobals.device[deviceId].netflowGlobals->flowIgnored, 0,
	 sizeof(myGlobals.device[deviceId].netflowGlobals->flowIgnored));
  myGlobals.device[deviceId].netflowGlobals->nextFlowIgnored = 0;

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

  if(fetchPrefsValue(nfValue(deviceId, "netFlowAggregation", 1), value, sizeof(value)) == -1)
    storePrefsValue(nfValue(deviceId, "netFlowAggregation", 1), "0" /* noAggregation */);
  else
    myGlobals.device[deviceId].netflowGlobals->netFlowAggregation = atoi(value);

  if(fetchPrefsValue(nfValue(deviceId, "netFlowAssumeFTP", 1), value, sizeof(value)) == -1) {
    storePrefsValue(nfValue(deviceId, "netFlowAssumeFTP", 1), "0" /* no */);
    myGlobals.device[deviceId].netflowGlobals->netFlowAssumeFTP = 0;
  } else
    myGlobals.device[deviceId].netflowGlobals->netFlowAssumeFTP = atoi(value);

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex, "initNetFlowDevice");
#endif
  handleWhiteBlackListAddresses((char*)&value,
                                myGlobals.device[deviceId].netflowGlobals->whiteNetworks,
                                &myGlobals.device[deviceId].netflowGlobals->numWhiteNets,
				(char*)&workList,
                                sizeof(workList));
  if(myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList != NULL)
    free(myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList);
  myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList = strdup(workList);
#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
#endif
  traceEvent(CONST_TRACE_INFO, "NETFLOW: White list initialized to '%s'",
	     myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList);

  if(fetchPrefsValue(nfValue(deviceId, "blackList", 1), value, sizeof(value)) == -1) {
    storePrefsValue(nfValue(deviceId, "blackList", 1), "");
    myGlobals.device[deviceId].netflowGlobals->netFlowBlackList=strdup("");
  } else
    myGlobals.device[deviceId].netflowGlobals->netFlowBlackList=strdup(value);

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex, "initNetFlowDevice()");
#endif
  handleWhiteBlackListAddresses((char*)&value, myGlobals.device[deviceId].netflowGlobals->blackNetworks,
                                &myGlobals.device[deviceId].netflowGlobals->numBlackNets, (char*)&workList,
                                sizeof(workList));
  if(myGlobals.device[deviceId].netflowGlobals->netFlowBlackList != NULL) free(myGlobals.device[deviceId].netflowGlobals->netFlowBlackList);
  myGlobals.device[deviceId].netflowGlobals->netFlowBlackList = strdup(workList);
#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
#endif
  traceEvent(CONST_TRACE_INFO, "NETFLOW: Black list initialized to '%s'",
	     myGlobals.device[deviceId].netflowGlobals->netFlowBlackList);

#ifdef HAVE_FILEDESCRIPTORBUG
  wasteFileDescriptors(deviceId);
#endif

  if(setNetFlowInSocket(deviceId) != 0)  return;

  if(fetchPrefsValue(nfValue(deviceId, "debug", 1), value, sizeof(value)) == -1) {
    storePrefsValue(nfValue(deviceId, "debug", 1), "0");
    myGlobals.device[deviceId].netflowGlobals->netFlowDebug = 0;
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
  setEmptySerial(&myGlobals.device[deviceId].netflowGlobals->dummyHost->hostSerial);
  myGlobals.device[deviceId].netflowGlobals->dummyHost->portsUsage = (PortUsage**)calloc(sizeof(PortUsage*),
											 MAX_ASSIGNED_IP_PORTS);
}

/* ****************************** */

static int initNetFlowFunct(void) {
  char value[128];

  myGlobals.mergeInterfaces = 0; /* Use different devices */

  if((fetchPrefsValue(nfValue(0, "knownDevices", 0), value, sizeof(value)) != -1)
     && (strlen(value) > 0)) {
    char *strtokState, *dev;

    traceEvent(CONST_TRACE_INFO, "NETFLOW: initializing '%s' devices", value);

    dev = strtok_r(value, ",", &strtokState);
    while(dev != NULL) {
      int deviceId = atoi(dev);

      if(deviceId > 0) {
	if((deviceId = createNetFlowDevice(deviceId)) == -1)
	  return(-1);
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

  sendString("<center><table width=\"80%\" border=\"1\" "TABLE_DEFAULTS">\n");
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
      if(snprintf(buf, sizeof(buf), "<INPUT TYPE=radio NAME=device VALUE=%s %s>%s.%s\n",
		  dev, i == 0 ? "CHECKED" : "", NETFLOW_DEVICE_NAME, dev) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "[ <A HREF=/plugins/%s?device=-%s>Delete</A> ]<br>\n",
		  netflowPluginInfo->pluginURLname, dev) < 0)
	BufferTooShort();
      sendString(buf);

      i++;
      dev = strtok_r(NULL, ",", &strtokState);
    }

    sendString("<p><INPUT TYPE=submit VALUE=\"Edit NetFlow Device\">&nbsp;<INPUT TYPE=reset VALUE=Reset>\n</FORM><p>\n");
  }

  /* *********************** */

  sendString("<FORM ACTION=\"/plugins/");
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" METHOD=GET>\n<input type=hidden name=device size=5 value=0>");
  sendString("<p><INPUT TYPE=submit VALUE=\"Add NetFlow Device\">&nbsp;\n</FORM><p>\n");
  sendString("</td></TR></TABLE></center>");

  printHTMLtrailer();
}

/* ****************************** */

static void printNetFlowConfiguration(int deviceId) {
  char buf[512], buf1[32], buf2[32];

  sendString("<center><table width=\"80%\" border=\"1\" "TABLE_DEFAULTS">\n");
  sendString("<tr><th colspan=\"4\" "DARK_BG">Incoming Flows</th></tr>\n");

  sendString("<tr><th colspan=2 "DARK_BG">NetFlow Device</th><td align=right colspan=2>");

  if(snprintf(buf, sizeof(buf), "%s.%d [ <A HREF=\"/plugins/%s\"/>List</A> ]",
	      NETFLOW_DEVICE_NAME, myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId,
	      netflowPluginInfo->pluginName) < 0) BufferTooShort();
  sendString(buf);
  sendString("</td></tr>\n");

  sendString("<tr><th rowspan=\"2\" "DARK_BG">Flow<br>Collection</th>\n");

  sendString("<th "DARK_BG">Local<br>Collector<br>UDP"
#ifdef HAVE_SCTP
	     "/SCTP"
#endif
	     "<br>Port</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
	      myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("<input name=\"port\" size=\"5\" value=\"");
  if(snprintf(buf, sizeof(buf), "%d", myGlobals.device[deviceId].netflowGlobals->netFlowInPort) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("\"> [ Use a port value of 0 to disable collection ] "
	     "<input type=\"submit\" value=\"Set Port\">"
	     "</p>\n</form>\n\n"
             "<p>If you want <b>ntop</b> to display NetFlow data it receives from other "
             "hosts, i.e. act as a collector, you must specify the UDP"
#ifdef HAVE_SCTP
	     "/SCTP"
#endif
	     " port to listen to. "
             "The default port used for NetFlow is " DEFAULT_NETFLOW_PORT_STR ".</p>\n"
	     "<p align=\"right\"></p>\n");

  if(myGlobals.device[deviceId].netflowGlobals->netFlowInPort == 0)
    sendString("<p><font color=red>WARNING</font>: "
	       "The 'Local Collector UDP"
#ifdef HAVE_SCTP
	       "/SCTP"
#endif
	       " Port' is zero (none). "
               "Even if this plugin is ACTIVE, you must still enter a port number for "
               "<b>ntop</b> to receive and process NetFlow data.</p>\n");

  sendString("</td></tr>\n");

  sendString("<tr><th "DARK_BG">Virtual<br>NetFlow<br>Interface<br>Network<br>Address</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>\n");

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
	      myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId) < 0)
    BufferTooShort();
  sendString(buf);

  sendString(" <input name=\"ifNetMask\" size=\"32\" value=\"");
  if(snprintf(buf, sizeof(buf), "%s/%s",
	      _intoa(myGlobals.device[deviceId].netflowGlobals->netFlowIfAddress, buf1, sizeof(buf1)),
	      _intoa(myGlobals.device[deviceId].netflowGlobals->netFlowIfMask, buf2, sizeof(buf2))) < 0)
    BufferTooShort();
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

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
	      myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("<p><SELECT NAME=netFlowAggregation>");

  if(snprintf(buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
              noAggregation,
              (myGlobals.device[deviceId].netflowGlobals->netFlowAggregation == noAggregation) ? " SELECTED" : "",
              "None (no aggregation)") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
              portAggregation,
              (myGlobals.device[deviceId].netflowGlobals->netFlowAggregation == portAggregation) ? " SELECTED" : "",
              "TCP/UDP Port") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
              hostAggregation,
              (myGlobals.device[deviceId].netflowGlobals->netFlowAggregation == hostAggregation) ? " SELECTED" : "",
              "Host") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
              protocolAggregation,
              (myGlobals.device[deviceId].netflowGlobals->netFlowAggregation == protocolAggregation) ? " SELECTED" : "",
              "Protocol (TCP, UDP, ICMP)") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<option value=\"%d\"%s>%s</option>\n",
              asAggregation,
              (myGlobals.device[deviceId].netflowGlobals->netFlowAggregation == asAggregation) ? " SELECTED" : "",
              "AS") < 0)
    BufferTooShort();
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

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
	      myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("<input name=\"whiteList\" size=\"60\" value=\"");
  if(snprintf(buf, sizeof(buf), "%s",
              myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList == NULL ? " " : myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList) < 0)
    BufferTooShort();
  sendString(buf);
  sendString("\"> <input type=\"submit\" value=\"Set White List\"></p>\n</form>\n"
             "<p>This is a list of one or more TCP/IP host(s)/network(s) which we will "
             "store data from when these host(s)/network(s) occur in the NetFlow records.</p>\n"
             "</td>\n</tr>\n");

  sendString("<tr><th "DARK_BG">Black List</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(netflowPluginInfo->pluginURLname);
  sendString("\" method=GET>");

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
	      myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("<input name=\"blackList\" size=\"60\" value=\"");
  if(snprintf(buf, sizeof(buf), "%s",
              myGlobals.device[deviceId].netflowGlobals->netFlowBlackList == NULL ? " " : myGlobals.device[deviceId].netflowGlobals->netFlowBlackList) < 0)
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

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
	      myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId) < 0)
    BufferTooShort();
  sendString(buf);

  if(myGlobals.device[deviceId].netflowGlobals->netFlowAssumeFTP) {
    sendString("<input type=\"radio\" name=\"netFlowAssumeFTP\" value=\"1\" checked>Yes\n"
               "<input type=\"radio\" name=\"netFlowAssumeFTP\" value=\"0\">No\n");
  } else {
    sendString("<input type=\"radio\" name=\"netFlowAssumeFTP\" value=\"1\">Yes\n"
               "<input type=\"radio\" name=\"netFlowAssumeFTP\" value=\"0\" checked>No\n");
  }
  sendString(" <input type=\"submit\" value=\"Set FTP Policy\"></p>\n");

  sendString("</form>\n"
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

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
	      myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId) < 0)
    BufferTooShort();
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

/* ****************************** */

static void printNetFlowStatisticsRcvd(int deviceId) {
  char buf[512], buf1[32], buf2[32], formatBuf[32], formatBuf2[32];
  u_int i, totFlows;

  sendString("<tr " TR_ON ">\n"
             "<th colspan=\"2\" "DARK_BG">Received Flows</th>\n"
             "</tr>\n"
             "<tr " TR_ON ">\n"
             "<th " TH_BG " align=\"left\" "DARK_BG ">Flow Senders</th>\n"
             "<td width=\"20%\">");

  for(i=0; i<MAX_NUM_PROBES; i++) {
    if(myGlobals.device[deviceId].netflowGlobals->probeList[i].probeAddr.s_addr == 0) break;

    if(snprintf(buf, sizeof(buf), "%s [%s pkts]<br>\n",
                _intoa(myGlobals.device[deviceId].netflowGlobals->probeList[i].probeAddr, buf, sizeof(buf)),
                formatPkts(myGlobals.device[deviceId].netflowGlobals->probeList[i].pkts, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    sendString(buf);
  }
  sendString("&nbsp;</td>\n</tr>\n");

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Packets Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Packets with Bad Version</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numBadNetFlowsVersionsRcvd, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Packets Processed</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd -
                         myGlobals.device[deviceId].netflowGlobals->numBadNetFlowsVersionsRcvd, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Valid Flows Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsRcvd, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd > 0) {
    totFlows = myGlobals.device[deviceId].netflowGlobals->numNetFlowsV5Rcvd +
      myGlobals.device[deviceId].netflowGlobals->numNetFlowsV7Rcvd +
      myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9Rcvd +
      myGlobals.device[deviceId].netflowGlobals->numNflowFlowsRcvd +
      myGlobals.device[deviceId].netflowGlobals->numBadFlowPkts +
      myGlobals.device[deviceId].netflowGlobals->numBadFlowBytes +
      myGlobals.device[deviceId].netflowGlobals->numBadFlowReality +
      myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9UnknTemplRcvd;

    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Average Number of Flows per Packet</th>\n"
                "<td " TD_BG " align=\"right\">%.1f</td>\n"
                "</tr>\n",
		(float)totFlows/(float)myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of V1 Flows Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV1Rcvd, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of V5 Flows Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV5Rcvd, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of V7 Flows Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV7Rcvd, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of V9 Flows Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9Rcvd, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9TemplRcvd) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Total V9 Templates Received</th>\n"
                "<td " TD_BG " align=\"right\">%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9TemplRcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9BadTemplRcvd) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Bad V9 Templates Received</th>\n"
                "<td " TD_BG " align=\"right\">%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9BadTemplRcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9UnknTemplRcvd) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Number of V9 Flows with Unknown Templates Received</th>\n"
                "<td " TD_BG " align=\"right\">%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9UnknTemplRcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of nFlows Received</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numNflowFlowsRcvd, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(myGlobals.device[deviceId].netflowGlobals->nFlowTotCompressedSize > 0) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Average nFlow Compression Savings</th>\n"
                "<td " TD_BG " align=\"right\">%.1f</td>\n"
                "</tr>\n",
                (float)(100*(int)myGlobals.device[deviceId].netflowGlobals->nFlowTotUncompressedSize)
		/(float)myGlobals.device[deviceId].netflowGlobals->nFlowTotCompressedSize-100) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(myGlobals.device[deviceId].netflowGlobals->numNflowFlowsBadTemplRcvd > 0) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Number of nFlows with Unknown Templates Received</th>\n"
                "<td " TD_BG " align=\"right\">%s</td>\n"
                "</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numNflowFlowsBadTemplRcvd, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(myGlobals.device[deviceId].netflowGlobals->numNflowFlowsBadVersRcvd > 0) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Number of nFlows with Bad Version Received</th>\n"
                "<td " TD_BG " align=\"right\">%s</td>\n"
                "</tr>\n",
		formatPkts(myGlobals.device[deviceId].netflowGlobals->numNflowFlowsBadVersRcvd, formatBuf, sizeof(formatBuf))) < 0)
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
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numBadFlowPkts, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Flows with Zero Byte Count</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numBadFlowBytes, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Flows with Bad Data</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numBadFlowReality, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Number of Flows with Unknown Template</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsV9UnknTemplRcvd, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Total Number of Flows Processed</th>\n"
              "<td " TD_BG " align=\"right\">%s</td>\n"
              "</tr>\n",
              formatPkts(myGlobals.device[deviceId].netflowGlobals->numNetFlowsProcessed, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if((myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedWhiteList +
      myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedBlackList +
      myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedWhiteList +
      myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedBlackList) > 0) {

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
                formatPkts(myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedBlackList,
                           formatBuf, sizeof(formatBuf)),
                formatPkts(myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedBlackList,
                           formatBuf2, sizeof(formatBuf2))) < 0)
      BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Rejected - White list</th>\n"
                "<td " TD_BG ">%s&nbsp;/&nbsp;%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedWhiteList,
                           formatBuf, sizeof(formatBuf)),
                formatPkts(myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedWhiteList,
                           formatBuf2, sizeof(formatBuf2))) < 0)
      BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Accepted</th>\n"
                "<td " TD_BG ">%s&nbsp;/&nbsp;%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryAccepted,
                           formatBuf, sizeof(formatBuf)),
                formatPkts(myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryAccepted,
                           formatBuf2, sizeof(formatBuf2))) < 0)
      BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
		"<th " TH_BG " align=\"left\" "DARK_BG ">Total</th>\n"
                "<td " TD_BG ">%s&nbsp;/&nbsp;%s</td>\n"
                "</tr>\n",
                formatPkts(myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedBlackList +
                           myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryFailedWhiteList +
                           myGlobals.device[deviceId].netflowGlobals->numSrcNetFlowsEntryAccepted,
                           formatBuf, sizeof(formatBuf)),
                formatPkts(myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedBlackList +
                           myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryFailedWhiteList +
                           myGlobals.device[deviceId].netflowGlobals->numDstNetFlowsEntryAccepted,
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
              "<td><table width=\"100%%\" border=\"0\" "TABLE_DEFAULTS">\n"
              "<tr><td width=\"50%%\" " TD_BG " align=\"right\">%u</td>\n"
              "<td width=\"50%%\" " TD_BG " align=\"right\">%s</td></tr>\n"
              "</table></td>\n"
              "</tr>\n",
              myGlobals.device[deviceId].netflowGlobals->flowIgnoredZeroPort,
              formatBytes(myGlobals.device[deviceId].netflowGlobals->flowIgnoredZeroPortBytes, 1, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">netFlow port</th>\n"
              "<td><table width=\"100%%\" border=\"0\" "TABLE_DEFAULTS">\n"
              "<tr><td width=\"50%%\" " TD_BG " align=\"right\">%u</td>\n"
              "<td width=\"50%%\" " TD_BG " align=\"right\">%s</td></tr>\n"
              "</table></td>\n"
              "</tr>\n",
              myGlobals.device[deviceId].netflowGlobals->flowIgnoredNetFlow,
              formatBytes(myGlobals.device[deviceId].netflowGlobals->flowIgnoredNetFlowBytes, 1, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Unrecognized port &lt;= 1023</th>\n"
              "<td><table width=\"100%%\" border=\"0\" "TABLE_DEFAULTS">\n"
              "<tr><td width=\"50%%\" " TD_BG " align=\"right\">%u</td>\n"
              "<td width=\"50%%\" " TD_BG " align=\"right\">%s</td></tr>\n"
              "</table></td>\n"
              "</tr>\n",
              myGlobals.device[deviceId].netflowGlobals->flowIgnoredLowPort,
              formatBytes(myGlobals.device[deviceId].netflowGlobals->flowIgnoredLowPortBytes, 1, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf),
              "<tr " TR_ON ">\n"
              "<th " TH_BG " align=\"left\" "DARK_BG ">Unrecognized port &gt; 1023</th>\n"
              "<td><table width=\"100%%\" border=\"0\" "TABLE_DEFAULTS">\n"
              "<tr><td width=\"50%%\" " TD_BG " align=\"right\">%u</td>\n"
              "<td width=\"50%%\" " TD_BG " align=\"right\">%s</td></tr>\n"
              "</table></td>\n"
              "</tr>\n",
              myGlobals.device[deviceId].netflowGlobals->flowIgnoredHighPort,
              formatBytes(myGlobals.device[deviceId].netflowGlobals->flowIgnoredHighPortBytes, 1, formatBuf, sizeof(formatBuf))) < 0)
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
              "<td><table width=\"100%%\" border=\"0\" "TABLE_DEFAULTS">\n"
              "<tr><td width=\"50%%\" " TD_BG " align=\"right\">%u</td>\n"
              "<td width=\"50%%\" " TD_BG " align=\"right\">%s</td></tr>\n"
              "</table></td>\n"
              "</tr>\n",
              myGlobals.device[deviceId].netflowGlobals->flowProcessed,
              formatBytes(myGlobals.device[deviceId].netflowGlobals->flowProcessedBytes, 1, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);


  if((myGlobals.device[deviceId].netflowGlobals->flowAssumedFtpData>0) || (myGlobals.device[deviceId].netflowGlobals->netFlowAssumeFTP)) {
    if(snprintf(buf, sizeof(buf),
                "<tr " TR_ON ">\n"
                "<th " TH_BG " align=\"left\" "DARK_BG ">Assumed ftpdat</th>\n"
                "<td><table width=\"100%%\" border=\"0\" "TABLE_DEFAULTS">\n"
                "<tr><td width=\"50%%\" " TD_BG " align=\"right\">%u</td>\n"
                "<td width=\"50%%\" " TD_BG " align=\"right\">%s</td></tr>\n"
                "</table></td>\n"
                "</tr>\n",
                myGlobals.device[deviceId].netflowGlobals->flowAssumedFtpData,
                formatBytes(myGlobals.device[deviceId].netflowGlobals->flowAssumedFtpDataBytes, 1, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(myGlobals.device[deviceId].netflowGlobals->flowIgnoredNetFlow > 0) {
    sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
	       "<tr " TR_ON ">\n"
	       "<th colspan=\"2\" "DARK_BG">Most Recent Ignored Flows</th>\n"
	       "</tr>\n"
	       "<tr " TR_ON ">\n"
	       "<th colspan=\"2\"><table width=\"100%\" border=1 "TABLE_DEFAULTS">"
	       "<tr><th colspan=\"2\">Flow</th>\n"
	       "<th>Bytes</th>\n"
	       "<th># Consecutive<br>Counts</th></tr>\n");

    for (i=myGlobals.device[deviceId].netflowGlobals->nextFlowIgnored;
	 i<myGlobals.device[deviceId].netflowGlobals->nextFlowIgnored+MAX_NUM_IGNOREDFLOWS; i++) {
      if ((myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0] != 0) &&
	  (myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2] != 0) ) {
	if(myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][4] > 1) {
	  if(snprintf(buf1, sizeof(buf1), "(%d) ", myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][4]) < 0)
	    BufferTooShort();
	} else {
	  if(snprintf(buf1, sizeof(buf1), "&nbsp;") < 0)
	    BufferTooShort();
	}
	if (myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][5] > 1536*1024*1024 /* ~1.5GB */) {
	  if(snprintf(buf2, sizeof(buf2), "%.1fGB",
		      (float)myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][5] / (1024.0*1024.0*1024.0)) < 0)
	    BufferTooShort();
	} else if (myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][4] > 1536*1024 /* ~1.5MB */) {
	  if(snprintf(buf2, sizeof(buf2), "%.1fMB",
		      (float)myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][5] / (1024.0*1024.0)) < 0)
	    BufferTooShort();
	} else {
	  if(snprintf(buf2, sizeof(buf2), "%u",
		      myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][5]) < 0)
	    BufferTooShort();
	}
	if(snprintf(buf, sizeof(buf),
		    "<tr><td align=\"right\">%d.%d.%d.%d:%d</td>"
		    "<td align=\"left\">-> %d.%d.%d.%d:%d</td>"
		    "<td align=\"right\">%s</td>"
		    "<td align=\"right\">%s</td></tr>\n",
		    (myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0] >> 24) & 0xff,
		    (myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0] >> 16) & 0xff,
		    (myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0] >>  8) & 0xff,
		    (myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][0]      ) & 0xff,
		    myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][1],
		    (myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2] >> 24) & 0xff,
		    (myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2] >> 16) & 0xff,
		    (myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2] >>  8) & 0xff,
		    (myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][2]      ) & 0xff,
		    myGlobals.device[deviceId].netflowGlobals->flowIgnored[i%MAX_NUM_IGNOREDFLOWS][3],
		    buf2, buf1) < 0)
	  BufferTooShort();
	sendString(buf);
      }
    }

    sendString("</table>");
  }
}

/* ****************************** */

static int createNetFlowDevice(int netFlowDeviceId) {
  int deviceId;
  char buf[32];

  traceEvent(CONST_TRACE_INFO, "NETFLOW: createNetFlowDevice(%d)", netFlowDeviceId);

  if(snprintf(buf, sizeof(buf), "%s.%d", NETFLOW_DEVICE_NAME, netFlowDeviceId) < 0) BufferTooShort();
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
    myGlobals.device[deviceId].netflowGlobals->netFlowDeviceId = netFlowDeviceId;
    setNetFlowInterfaceMatrix(deviceId);
    initNetFlowDevice(deviceId);
  }

  traceEvent(CONST_TRACE_INFO, "NETFLOW: createNetFlowDevice created device %d",
	     deviceId);

  return(deviceId);
}

/* ****************************** */

static int mapNetFlowDeviceToNtopDevice(int netFlowDeviceId) {
  int i;

  for(i=0; i<myGlobals.numDevices; i++)
    if((myGlobals.device[i].netflowGlobals != NULL)
       && (myGlobals.device[i].netflowGlobals->netFlowDeviceId == netFlowDeviceId)) {
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "NETFLOW: mapNetFlowDeviceToNtopDevice(%d) = %d",
		 netFlowDeviceId, i);
#endif
      return(i);
    } else if(myGlobals.device[i].netflowGlobals != NULL) {
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "NETFLOW: mapNetFlowDeviceToNtopDevice (id=%d) <=> (netFlowDeviceId=%d)",
		 i, myGlobals.device[i].netflowGlobals->netFlowDeviceId);
#endif
    }
  
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "NETFLOW: mapNetFlowDeviceToNtopDevice(%d) failed\n", netFlowDeviceId);
#endif

  return(-1); /* Not found */
}

/* ****************************** */

static void handleNetflowHTTPrequest(char* _url) {
  char workList[1024], *url;
  int deviceId = -1;

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);

  /* ****************************
   * Process URL stuff          *
   ****************************** */

  if(_url != NULL) {
    char *strtokState;

    url = strtok_r(_url, "&", &strtokState);

    while(url != NULL) {
      char *device, *value = NULL;

      device = strtok(url, "=");
      if(device != NULL) value = strtok(NULL, "="); else value = NULL;

      if(value && device) {
	if(strcmp(device, "device") == 0) {
	  deviceId = atoi(value);

	  if((deviceId > 0)
	     && ((deviceId = mapNetFlowDeviceToNtopDevice(deviceId)) == -1)) {
	    printHTMLheader("NetFlow Configuration Error", NULL, 0);
	    printFlagedWarning("<I>Unable to locate the specified device. Please activate the plugin first.</I>");
	    return;
	  }
	} else if(strcmp(device, "port") == 0) {
	  if(deviceId > 0) {
	    myGlobals.device[deviceId].netflowGlobals->netFlowInPort = atoi(value);
	    storePrefsValue(nfValue(deviceId, "netFlowInPort", 1), value);
	    setNetFlowInSocket(deviceId);
	  }
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
	} else if(strcmp(device, "netFlowAssumeFTP") == 0) {
	  if(deviceId > 0) {
	    myGlobals.device[deviceId].netflowGlobals->netFlowAssumeFTP = atoi(value);
	    storePrefsValue(nfValue(deviceId, "netFlowAssumeFTP", 1), value);
	  }
	} else if(strcmp(device, "ifNetMask") == 0) {
	  int a, b, c, d, a1, b1, c1, d1;

	  if(deviceId > 0) {
	    if(sscanf(value, "%d.%d.%d.%d/%d.%d.%d.%d",
		      &a, &b, &c, &d, &a1, &b1, &c1, &d1) == 8) {
	      myGlobals.device[deviceId].netflowGlobals->netFlowIfAddress.s_addr =(a << 24) +(b << 16) +(c << 8) + d;
	      myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr    =(a1 << 24) +(b1 << 16) +(c1 << 8) + d1;
	      storePrefsValue(nfValue(deviceId, "ifNetMask", 1), value);
	      freeNetFlowMatrixMemory(deviceId);
	      setNetFlowInterfaceMatrix(deviceId);
	    } else if(sscanf(value, "%d.%d.%d.%d/%d",
			     &a, &b, &c, &d, &a1) == 5) {
	      myGlobals.device[deviceId].netflowGlobals->netFlowIfAddress.s_addr = (a << 24) +(b << 16) +(c << 8) + d;
	      myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr    = 0xffffffff >> a1;
	      myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr =~
		myGlobals.device[deviceId].netflowGlobals->netFlowIfMask.s_addr;
	      storePrefsValue(nfValue(deviceId, "ifNetMask", 1), value);
	      freeNetFlowMatrixMemory(deviceId);
	      setNetFlowInterfaceMatrix(deviceId);
	    } else
	      traceEvent(CONST_TRACE_ERROR, "NETFLOW: HTTP request netmask parse error (%s)", value);
	  }
	} else if(strcmp(device, "whiteList") == 0) {
	  /* Cleanup the http control char xform */
	  char *fPtr=value, *tPtr=value;

	  if(deviceId > 0) {
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
	    accessMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex,
			"handleNetflowHTTPrequest()w");
#endif
	    handleWhiteBlackListAddresses(value,
					  myGlobals.device[deviceId].netflowGlobals->whiteNetworks,
					  &myGlobals.device[deviceId].netflowGlobals->numWhiteNets,
					  (char*)&workList,
					  sizeof(workList));
	    if(myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList != NULL)
	      free(myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList);
	    myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList=strdup(workList);
#ifdef CFG_MULTITHREADED
	    releaseMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
#endif
	    storePrefsValue(nfValue(deviceId, "whiteList", 1),
			    myGlobals.device[deviceId].netflowGlobals->netFlowWhiteList);
	  }
	} else if(strcmp(device, "blackList") == 0) {
	  /* Cleanup the http control char xform */
	  char *fPtr=value, *tPtr=value;

	  if(deviceId > 0) {
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
	    accessMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex,
			"handleNetflowHTTPrequest()b");
#endif
	    handleWhiteBlackListAddresses(value,
					  myGlobals.device[deviceId].netflowGlobals->blackNetworks,
					  &myGlobals.device[deviceId].netflowGlobals->numBlackNets,
					  (char*)&workList,
					  sizeof(workList));
	    if(myGlobals.device[deviceId].netflowGlobals->netFlowBlackList != NULL)
	      free(myGlobals.device[deviceId].netflowGlobals->netFlowBlackList);
	    myGlobals.device[deviceId].netflowGlobals->netFlowBlackList=strdup(workList);
#ifdef CFG_MULTITHREADED
	    releaseMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
#endif
	    storePrefsValue(nfValue(deviceId, "blackList", 1),
			    myGlobals.device[deviceId].netflowGlobals->netFlowBlackList);
	  }
	}
      }

      url = strtok_r(NULL, "&", &strtokState);
    }
  }

#ifdef DEBUG
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

    if((deviceId > 0)
       && ((readDeviceId = mapNetFlowDeviceToNtopDevice(deviceId)) == -1)) {
      printHTMLheader("NetFlow Configuration Error", NULL, 0);
      printFlagedWarning("<I>Unable to locate the specified device. Please activate the plugin first.</I>");
      return;
    }

    deviceId = -deviceId;

    if(fetchPrefsValue(nfValue(deviceId, "knownDevices", 0), value, sizeof(value)) != -1) {
      char *strtokState, *dev, value1[128];

      value1[0] = '\0';

      dev = strtok_r(value, ",", &strtokState);
      while(dev != NULL) {
	int _dev = atoi(dev);

	if(_dev != deviceId) {
	  strcat(value1, ",");
	  strcat(value1, dev);
	}

	dev = strtok_r(NULL, ",", &strtokState);
      }

      storePrefsValue(nfValue(deviceId, "knownDevices", 0), value1);
    }

    termNetflowDevice(readDeviceId);

    printHTMLheader("NetFlow Device Configuration", NULL, 0);
    printNetFlowDeviceConfiguration();
    return;
  } else if(deviceId == 0) {
    /* Add new device */
    char value[128];

    if((fetchPrefsValue(nfValue(deviceId, "knownDevices", 0), value, sizeof(value)) != -1)
       && (strlen(value) > 0)) {
      char *strtokState, *dev, value1[128], buf[256];

      traceEvent(CONST_TRACE_INFO, "NETFLOW: knownDevices=%s", value);

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

      if(snprintf(buf, sizeof(buf), "%s,%d", value1, deviceId) < 0)
	BufferTooShort();

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

#ifdef CFG_MULTITHREADED
      if(myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex.isLocked) {
	sendString("<table><tr><td colspan=\"2\">&nbsp;</td></tr>\n"
		   "<tr " TR_ON ">\n"
		   "<th colspan=\"2\" "DARK_BG">Mutexes</th>\n"
		   "</tr>\n");

	sendString("<tr " TR_ON ">\n"
		   "<th>List Mutex</th>\n<td><table>");
	printMutexStatus(FALSE, &myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex,
			 "White/Black list mutex");
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
	       "<a href=\"http://www.ntop.org/nBox86/\" "
	       "title=\"nBox86 page\"><b>nBox<sup>86</sup></b></a> "
	       "<img src=\"/nboxLogo.gif\" alt=\"nBox logo\">.</p>\n"
	       "</td>\n"
	       "<td width=\"10%\">&nbsp;</td>\n</tr>\n</table>\n");
  }

  printPluginTrailer((myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd > 0) ?
		     netflowPluginInfo->pluginURLname : NULL,
                     "NetFlow is a trademark of <a href=\"http://www.cisco.com/\" "
                     "title=\"Cisco home page\">Cisco Systems</a>");

  printHTMLtrailer();
}

/* ****************************** */

static void termNetflowDevice(int deviceId) {

  traceEvent(CONST_TRACE_INFO, "NETFLOW: terminating deviceId=%d", deviceId);

  if((deviceId > 0) && (deviceId < myGlobals.numDevices)) {
#ifdef CFG_MULTITHREADED
    if(myGlobals.device[deviceId].netflowGlobals->threadActive) {
      killThread(&myGlobals.device[deviceId].netflowGlobals->netFlowThread);
      myGlobals.device[deviceId].netflowGlobals->threadActive = 0;
    }
    tryLockMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex, "termNetflow");
    deleteMutex(&myGlobals.device[deviceId].netflowGlobals->whiteblackListMutex);
#endif

    if(myGlobals.device[deviceId].netflowGlobals->netFlowInSocket > 0) {
      closeNwSocket(&myGlobals.device[deviceId].netflowGlobals->netFlowInSocket);
#ifdef HAVE_SCTP
      closeNwSocket(&myGlobals.device[deviceId].netflowGlobals->netFlowInSctpSocket);
#endif
      myGlobals.device[deviceId].activeDevice = 0;
    }

#ifdef HAVE_FILEDESCRIPTORBUG
    unwasteFileDescriptors(deviceId);
#endif

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

static void termNetflowFunct(void) {
  char value[128];

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NETFLOW: Terminating NetFlow");

  if((fetchPrefsValue(nfValue(0, "knownDevices", 0), value, sizeof(value)) != -1) && (strlen(value) > 0)) {
    char *strtokState, *dev;

    dev = strtok_r(value, ",", &strtokState);
    while(dev != NULL) {
      int deviceId = atoi(dev);

      if(deviceId > 0) {
	if((deviceId > 0) && ((deviceId = mapNetFlowDeviceToNtopDevice(deviceId)) > 0)) {
	  termNetflowDevice(deviceId);
	}
      } else
	traceEvent(CONST_TRACE_WARNING, "NETFLOW: requested invalid termination of deviceId=%d", deviceId);

      dev = strtok_r(NULL, ",", &strtokState);
    }
  } else
    traceEvent(CONST_TRACE_INFO, "NETFLOW: no devices to terminate (%s)", value);

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

	    myGlobals.device[deviceId].netflowGlobals->numNetFlowsPktsRcvd++;
	    dissectFlow(rawSample, rawSampleLen, deviceId);
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
