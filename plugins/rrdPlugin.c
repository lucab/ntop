/*
 *  Copyright (C) 2002 Luca Deri <deri@ntop.org>
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

/*

       Plugin History

       1.0     Initial release
       1.0.1   Added Flows
       1.0.2   Added Matrix

*/

#include "ntop.h"
#include "globals-report.h"

#if defined(HAVE_LIBRRD) || defined(HAVE_RRD_H)

static unsigned short initialized = 0, dumpInterval;
static char *hostsFilter;
static Counter numTotalRRDs = 0;

#ifdef MULTITHREADED
pthread_t rrdThread;
#endif

#define RRD_SLEEP    "300"       /* 5 minutes */

static u_short dumpFlows, dumpHosts, dumpInterfaces, dumpMatrix;
/* #define DEBUG */



/* ****************************************************** */

#include <rrd.h>

static char **calcpr=NULL;

static void calfree (void) {
  if (calcpr) {
    long i;
    for(i=0;calcpr[i];i++){
      if (calcpr[i]){
	free(calcpr[i]);
      }
    } 
    if (calcpr) {
      free(calcpr);
    }
  }
}

/* ******************************************* */

void graphCounter(char *rrdPath, char *rrdName, char *rrdTitle) {
  char path[512], *argv[16], cmd[64], buf[96], buf1[96];
  struct stat statbuf;
  int argc = 0, rc, x, y;

  sprintf(path, "%s/rrd/%s%s.rrd", myGlobals.dbPath, rrdPath, rrdName);

  if(stat(path, &statbuf) == 0) {
    char startStr[32], counterStr[64];

    argv[argc++] = "rrd_graph";
    argv[argc++] = "/tmp/rrd_graph.gif";
    argv[argc++] = "--start";
    argv[argc++] = "now-1d";
    snprintf(buf, sizeof(buf), "DEF:ctr=%s:counter:AVERAGE", path);
    argv[argc++] = buf;
    snprintf(buf1, sizeof(buf1), "AREA:ctr#00a000:%s", rrdTitle);
    argv[argc++] = buf1;

    optind=0; /* reset gnu getopt */
    opterr=0; /* no error messages */
    rc = rrd_graph(argc, argv, &calcpr, &x, &y);

    calfree();

    if(rc == 0) {
      /* traceEvent(TRACE_WARNING, "x=%d/y=%d", x, y); */
      sendHTTPHeader(HTTP_TYPE_GIF, 0);
      sendGraphFile("/tmp/rrd_graph.gif");
    } else {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printHTMLheader("RRD Graph", 0);  
      printFlagedWarning("<I>Error while building graph of the requested file.</I>");
      printf("ERROR: %s\n",rrd_get_error());
    }
  } else {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printHTMLheader("RRD Graph", 0);  
      printFlagedWarning("<I>Error while building graph of the requested file "
			 "(unknown RRD file)</I>");
  }
}

/* ******************************* */

void updateCounter(char *hostPath, char *key, Counter value) {
  char path[512], *argv[16], cmd[64];
  struct stat statbuf;
  int argc = 0, rc;

  if(value == 0) return;

  sprintf(path, "%s%s.rrd", hostPath, key);

  if(stat(path, &statbuf) != 0) {
    char startStr[32], counterStr[64];

    argv[argc++] = "rrd_create";
    argv[argc++] = path;
    argv[argc++] = "--start";
    snprintf(startStr, sizeof(startStr), "%u", myGlobals.actTime);
    argv[argc++] = startStr;
    snprintf(counterStr, sizeof(counterStr), "DS:counter:COUNTER:600:0:%d", 100000000 /* 100 Mbps */);
    argv[argc++] = counterStr;
    argv[argc++] = "RRA:AVERAGE:0.5:1:1200";
    argv[argc++] = "RRA:MIN:0.5:12:2400";
    argv[argc++] = "RRA:MAX:0.5:12:2400";

    optind=0; /* reset gnu getopt */
    opterr=0; /* no error messages */
    rc = rrd_create(argc, argv);

#ifdef DEBUG
    if(rc != 0)
      traceEvent(TRACE_WARNING, "rrd_create(%s, %s, %u)=%d", hostPath, key, value, rc);
#endif
  }

  sprintf(cmd, "%u:%u", myGlobals.actTime, value);

  argc = 0;
  argv[argc++] = "rrd_update";
  argv[argc++] = path;
  argv[argc++] = cmd;

  optind=0; /* reset gnu getopt */
  opterr=0; /* no error messages */
  rc = rrd_update(argc, argv);

  numTotalRRDs++;
#ifdef DEBUG
  if(rc != 0)
    traceEvent(TRACE_WARNING, "rrd_update(%s, %s, %u)=%d", hostPath, key, value, rc);
#endif
}

/* ******************************* */

char x2c(char *what) {
  char digit;

  digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
  digit *= 16;
  digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
  return(digit);
}

/* ******************************* */

void unescape_url(char *url) {
  register int x,y;

  for(x=0,y=0;url[y];++x,++y) {
    if((url[x] = url[y]) == '%') {
      url[x] = x2c(&url[y+1]);
      y+=2;
    }
  }
  url[x] = '\0';
}

/* ******************************* */

#define ACTION_NONE   0
#define ACTION_GRAPH  1

static void handleRRDHTTPrequest(char* url) {
  char buf[1024], *strtokState, *mainState, *urlPiece, rrdKey[64], rrdName[64], rrdTitle[64];
  u_char action = ACTION_NONE;
  if((url != NULL) && (url[0] != '\0')) {
    unescape_url(url);

    /* traceEvent(TRACE_INFO, "URL: %s", url); */

    urlPiece = strtok_r(url, "&", &mainState);
    dumpFlows = dumpHosts = dumpInterfaces = dumpMatrix = 0;

    while(urlPiece != NULL) {
      char *key, *value;

      key = strtok_r(urlPiece, "=", &strtokState);
      if(key != NULL) value = strtok_r(NULL, "=", &strtokState);

      /* traceEvent(TRACE_INFO, "%s=%s", key, value);  */

      if(value && key) {

	if(strcmp(key, "action") == 0) {
	  if(strcmp(value, "graph") == 0) action = ACTION_GRAPH;
	} else if(strcmp(key, "key") == 0) {
	  int len = strlen(value);
	  
	  if(len >= sizeof(rrdKey)) len = sizeof(rrdKey)-1;
	  strncpy(rrdKey, value, len);
	  rrdKey[len] = '\0';
	} else if(strcmp(key, "name") == 0) {
	  int len = strlen(value);
	  
	  if(len >= sizeof(rrdName)) len = sizeof(rrdName)-1;
	  strncpy(rrdName, value, len);
	  rrdName[len] = '\0';
	} else if(strcmp(key, "title") == 0) {
	  int len = strlen(value);
	  
	  if(len >= sizeof(rrdTitle)) len = sizeof(rrdTitle)-1;
	  strncpy(rrdTitle, value, len);
	  rrdTitle[len] = '\0';
	} else if(strcmp(key, "interval") == 0) {
	  if(dumpInterval != atoi(value)) {
	    dumpInterval = atoi(value);
	    storePrefsValue("rrd.dataDumpInterval", value);
	  }
	} else if(strcmp(key, "hostsFilter") == 0) {
	  if(hostsFilter != NULL) free(hostsFilter);
	  hostsFilter = strdup(value);
	  storePrefsValue("rrd.hostsFilter", hostsFilter);
	} else if(strcmp(key, "dumpFlows") == 0) {
	  dumpFlows = 1;
	} else if(strcmp(key, "dumpHosts") == 0) {
	  dumpHosts = 1;
	} else if(strcmp(key, "dumpInterfaces") == 0) {
	  dumpInterfaces = 1;
	} else if(strcmp(key, "dumpMatrix") == 0) {
	  dumpMatrix = 1;
	}
      }

      urlPiece = strtok_r(NULL, "&", &mainState);
    }

    if(action == ACTION_NONE) {    
      /* traceEvent(TRACE_INFO, "dumpFlows=%d", dumpFlows); */
      sprintf(buf, "%d", dumpFlows);      storePrefsValue("rrd.dumpFlows", buf);
      sprintf(buf, "%d", dumpHosts);      storePrefsValue("rrd.dumpHosts", buf);
      sprintf(buf, "%d", dumpInterfaces); storePrefsValue("rrd.dumpInterfaces", buf);
      sprintf(buf, "%d", dumpMatrix);     storePrefsValue("rrd.dumpMatrix", buf);
    }
  }

  if(action == ACTION_GRAPH) {    
    graphCounter(rrdKey, rrdName, rrdTitle);
    return;
  }

  sendHTTPHeader(HTTP_TYPE_HTML, 0);
  printHTMLheader("RRD Preferences", 0);

  sendString("<CENTER>\n");
  sendString("<TABLE BORDER>\n");
  sendString("<TR><TH>Dump Interval</TH><TD><FORM ACTION=/plugins/rrdPlugin METHOD=GET>"
	     "<INPUT NAME=interval SIZE=5 VALUE=");

  if(snprintf(buf, sizeof(buf), "%d", (int)dumpInterval) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("> seconds<br>It specifies how often data is stored permanently.</TD></tr>\n");

  sendString("<TR><TH>Data to Dump</TH><TD>");

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpFlows VALUE=1 %s> Flows<br>\n",
	      dumpFlows ? "CHECKED" : "" ) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpHosts VALUE=1 %s> Hosts<br>\n",
	      dumpHosts ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpInterfaces VALUE=1 %s> Interfaces<br>\n",
	      dumpInterfaces ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpMatrix VALUE=1 %s> Matrix<br>\n",
	      dumpMatrix ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);

  sendString("</TD></tr>\n");

  if(dumpHosts) {
    sendString("<TR><TH>Hosts Filter</TH><TD><FORM ACTION=/plugins/rrdPlugin METHOD=GET>"
	       "<INPUT NAME=hostsFilter VALUE=\"");

    sendString(hostsFilter);

    sendString("\" SIZE=80><br>A list of networks [e.g. 172.22.0.0/255.255.0.0,192.168.5.0/255.255.255.0]<br>"
	               "separated by commas to which hosts that will be<br>"
	               "saved must belong to. An empty list means that all the hosts will "
	       "be stored on disk</TD></tr>\n");
  }

  sendString("<TR><TH>RRD Files Path</TH><TD>");
  sendString(myGlobals.dbPath);
  sendString("/rrd/</TD></TR>\n");

  sendString("<TD COLSPAN=2 ALIGN=center><INPUT TYPE=submit VALUE=Set></td></FORM></tr>\n");
  sendString("</TABLE>\n<p></CENTER>\n");

  sendString("<p><H5><A HREF=http://www.rrdtool.org/>RRDtool</A> has been created by <A HREF=http://ee-staff.ethz.ch/~oetiker/>Tobi Oetiker</A>.</H5>\n");

  printHTMLtrailer();
}

/* ****************************** */

static void* rrdMainLoop(void* notUsed _UNUSED_) {
  char value[512 /* leave it big for hosts filter */];
  u_int32_t networks[32][3];
  u_short numLocalNets;
  int start_tm = 0, end_tm = 0, sleep_tm = 0;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "rrdMainLoop()");
#endif

  /* **************************** */

  if(fetchPrefsValue("rrd.dataDumpInterval", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dataDumpInterval", RRD_SLEEP);
    dumpInterval = atoi(RRD_SLEEP);
  } else {
    dumpInterval = atoi(value);
  }

  if(fetchPrefsValue("rrd.dataDumpInterval", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dataDumpInterval", RRD_SLEEP);
    dumpInterval = atoi(RRD_SLEEP);
  } else {
    dumpInterval = atoi(value);
  }

  if(fetchPrefsValue("rrd.dumpFlows", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dumpFlows", "1");
    dumpFlows = 1;
  } else {
    dumpFlows = atoi(value);
  }

  if(fetchPrefsValue("rrd.dumpHosts", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dumpHosts", "1");
    dumpHosts = 1;
  } else {
    dumpHosts = atoi(value);
  }

  if(fetchPrefsValue("rrd.dumpInterfaces", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dumpInterfaces", "1");
    dumpInterfaces = 1;
  } else {
    dumpInterfaces = atoi(value);
  }

  if(fetchPrefsValue("rrd.dumpMatrix", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dumpMatrix", "1");
    dumpMatrix = 1;
  } else {
    dumpMatrix = atoi(value);
  }

  if(fetchPrefsValue("rrd.hostsFilter", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.hostsFilter", "");
    hostsFilter  = strdup("");
  } else {
    hostsFilter  = strdup(value);
  }

  initialized = 1;

  for(;myGlobals.capturePackets == 1;) {
    char *hostKey, rrdPath[512], filePath[512];
    int i, j;
    Counter numRRDs = numTotalRRDs;
    char fileName[NAME_MAX], cmdName[NAME_MAX], tmpStr[16];
    FILE *fd;
#if 0 && defined(FORK_CHILD_PROCESS) && (!defined(WIN32))
    int childpid;
#endif

    if (start_tm != 0) end_tm = time(NULL);
    sleep_tm = dumpInterval - (end_tm - start_tm);

#ifdef DEBUG
    traceEvent(TRACE_INFO, "Sleeping for %d seconds", sleep_tm);
#endif
    sleep(sleep_tm);

    if(!myGlobals.capturePackets) return(NULL);

    /* ****************************************************** */

    numLocalNets = 0;
    strcpy(rrdPath, hostsFilter); /* It avoids strtok to blanks into hostsFilter */
    handleAddressLists(rrdPath, networks, &numLocalNets, value, sizeof(value));

    /* ****************************************************** */

    if(dumpHosts) {
      for(i=1; i<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; i++) {
	HostTraffic *el;

	if((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i]) == NULL) continue;
	/* if(((!subnetPseudoLocalHost(el)) && (!multicastHost(el))))                              continue; */

	if(el->bytesSent.value > 0) {
	  if(el->hostNumIpAddress[0] != '\0') {
	    hostKey = el->hostNumIpAddress;

	    if((numLocalNets > 0)
	       && (!__pseudoLocalAddress(&el->hostIpAddress, networks, numLocalNets))) continue;
	    
	  } else {
	    /* hostKey = el->ethAddressString; */
	    /* For the time being do not save IP-less hosts */
	    continue;
	  }

	  sprintf(rrdPath, "%s/rrd/hosts/%s/", myGlobals.dbPath, hostKey);
	  sprintf(filePath, "mkdir -p %s", rrdPath);
	  system(filePath);

	  updateCounter(rrdPath, "pktSent", el->pktSent.value);
	  updateCounter(rrdPath, "pktRcvd", el->pktRcvd.value);
	  updateCounter(rrdPath, "pktDuplicatedAckSent", el->pktDuplicatedAckSent.value);
	  updateCounter(rrdPath, "pktDuplicatedAckRcvd", el->pktDuplicatedAckRcvd.value);
	  updateCounter(rrdPath, "pktBroadcastSent", el->pktBroadcastSent.value);
	  updateCounter(rrdPath, "bytesBroadcastSent", el->bytesBroadcastSent.value);
	  updateCounter(rrdPath, "pktMulticastSent", el->pktMulticastSent.value);
	  updateCounter(rrdPath, "bytesMulticastSent", el->bytesMulticastSent.value);
	  updateCounter(rrdPath, "pktMulticastRcvd", el->pktMulticastRcvd.value);
	  updateCounter(rrdPath, "bytesMulticastRcvd", el->bytesMulticastRcvd.value);
	  updateCounter(rrdPath, "bytesSent", el->bytesSent.value);
	  updateCounter(rrdPath, "bytesSentLoc", el->bytesSentLoc.value);
	  updateCounter(rrdPath, "bytesSentRem", el->bytesSentRem.value);
	  updateCounter(rrdPath, "bytesRcvd", el->bytesRcvd.value);
	  updateCounter(rrdPath, "bytesRcvdLoc", el->bytesRcvdLoc.value);
	  updateCounter(rrdPath, "bytesRcvdFromRem", el->bytesRcvdFromRem.value);
	  updateCounter(rrdPath, "ipBytesSent", el->ipBytesSent.value);
	  updateCounter(rrdPath, "ipBytesRcvd", el->ipBytesRcvd.value);
	  updateCounter(rrdPath, "tcpSentLoc", el->tcpSentLoc.value);
	  updateCounter(rrdPath, "tcpSentRem", el->tcpSentRem.value);
	  updateCounter(rrdPath, "udpSentLoc", el->udpSentLoc.value);
	  updateCounter(rrdPath, "udpSentRem", el->udpSentRem.value);
	  updateCounter(rrdPath, "icmpSent", el->icmpSent.value);
	  updateCounter(rrdPath, "ospfSent", el->ospfSent.value);
	  updateCounter(rrdPath, "igmpSent", el->igmpSent.value);
	  updateCounter(rrdPath, "tcpRcvdLoc", el->tcpRcvdLoc.value);
	  updateCounter(rrdPath, "tcpRcvdFromRem", el->tcpRcvdFromRem.value);
	  updateCounter(rrdPath, "udpRcvdLoc", el->udpRcvdLoc.value);
	  updateCounter(rrdPath, "udpRcvdFromRem", el->udpRcvdFromRem.value);
	  updateCounter(rrdPath, "icmpRcvd", el->icmpRcvd.value);
	  updateCounter(rrdPath, "ospfRcvd", el->ospfRcvd.value);
	  updateCounter(rrdPath, "igmpRcvd", el->igmpRcvd.value);
	  updateCounter(rrdPath, "tcpFragmentsSent", el->tcpFragmentsSent.value);
	  updateCounter(rrdPath, "tcpFragmentsRcvd", el->tcpFragmentsRcvd.value);
	  updateCounter(rrdPath, "udpFragmentsSent", el->udpFragmentsSent.value);
	  updateCounter(rrdPath, "udpFragmentsRcvd", el->udpFragmentsRcvd.value);
	  updateCounter(rrdPath, "icmpFragmentsSent", el->icmpFragmentsSent.value);
	  updateCounter(rrdPath, "icmpFragmentsRcvd", el->icmpFragmentsRcvd.value);
	  updateCounter(rrdPath, "stpSent", el->stpSent.value);
	  updateCounter(rrdPath, "stpRcvd", el->stpRcvd.value);
	  updateCounter(rrdPath, "ipxSent", el->ipxSent.value);
	  updateCounter(rrdPath, "ipxRcvd", el->ipxRcvd.value);
	  updateCounter(rrdPath, "osiSent", el->osiSent.value);
	  updateCounter(rrdPath, "osiRcvd", el->osiRcvd.value);
	  updateCounter(rrdPath, "dlcSent", el->dlcSent.value);
	  updateCounter(rrdPath, "dlcRcvd", el->dlcRcvd.value);
	  updateCounter(rrdPath, "arp_rarpSent", el->arp_rarpSent.value);
	  updateCounter(rrdPath, "arp_rarpRcvd", el->arp_rarpRcvd.value);
	  updateCounter(rrdPath, "arpReqPktsSent", el->arpReqPktsSent.value);
	  updateCounter(rrdPath, "arpReplyPktsSent", el->arpReplyPktsSent.value);
	  updateCounter(rrdPath, "arpReplyPktsRcvd", el->arpReplyPktsRcvd.value);
	  updateCounter(rrdPath, "decnetSent", el->decnetSent.value);
	  updateCounter(rrdPath, "decnetRcvd", el->decnetRcvd.value);
	  updateCounter(rrdPath, "appletalkSent", el->appletalkSent.value);
	  updateCounter(rrdPath, "appletalkRcvd", el->appletalkRcvd.value);
	  updateCounter(rrdPath, "netbiosSent", el->netbiosSent.value);
	  updateCounter(rrdPath, "netbiosRcvd", el->netbiosRcvd.value);
	  updateCounter(rrdPath, "qnxSent", el->qnxSent.value);
	  updateCounter(rrdPath, "qnxRcvd", el->qnxRcvd.value);
	  updateCounter(rrdPath, "otherSent", el->otherSent.value);
	  updateCounter(rrdPath, "otherRcvd", el->otherRcvd.value);

	  if((hostKey == el->hostNumIpAddress) && el->protoIPTrafficInfos) {
#ifdef DEBUG
	    traceEvent(TRACE_INFO, "Updating host %s", hostKey);
#endif

	    sprintf(rrdPath, "%s/rrd/data/hosts/%s/IP.", myGlobals.dbPath, hostKey);

	    for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {
	      char key[128];
	      sprintf(key, "%sSent", myGlobals.protoIPTrafficInfos[j]);
	      updateCounter(rrdPath, key, el->protoIPTrafficInfos[j].sentLoc.value+
			    el->protoIPTrafficInfos[j].sentRem.value);

	      sprintf(key, "%sRcvd", myGlobals.protoIPTrafficInfos[j]);
	      updateCounter(rrdPath, key, el->protoIPTrafficInfos[j].rcvdLoc.value+
			    el->protoIPTrafficInfos[j].rcvdFromRem.value);
	    }
	  }
	}
      }
    }

    /* ************************** */

    if(dumpFlows) {
      FlowFilterList *list = myGlobals.flowsList;

      while(list != NULL) {
	if(list->pluginStatus.activePlugin) {
	  sprintf(rrdPath, "%s/rrd/flows/%s/", myGlobals.dbPath, list->flowName);
	  sprintf(filePath, "mkdir -p %s", rrdPath);
	  system(filePath);

	  updateCounter(rrdPath, "packets", list->packets.value);
	  updateCounter(rrdPath, "bytes",   list->bytes.value);
	}

	list = list->next;
      }
    }

    /* ************************** */

    if(dumpInterfaces) {
      for(i=0; i<myGlobals.numDevices; i++) {
	if(myGlobals.device[i].virtualDevice) continue;

	sprintf(rrdPath, "%s/rrd/interfaces/%s/", myGlobals.dbPath,  myGlobals.device[i].name);
	sprintf(filePath, "mkdir -p %s", rrdPath);
	system(filePath);

	updateCounter(rrdPath, "droppedPkts", myGlobals.device[i].droppedPkts.value);
	updateCounter(rrdPath, "ethernetPkts", myGlobals.device[i].ethernetPkts.value);
	updateCounter(rrdPath, "broadcastPkts", myGlobals.device[i].broadcastPkts.value);
	updateCounter(rrdPath, "multicastPkts", myGlobals.device[i].multicastPkts.value);
	updateCounter(rrdPath, "ethernetBytes", myGlobals.device[i].ethernetBytes.value);
	updateCounter(rrdPath, "ipBytes", myGlobals.device[i].ipBytes.value);
	updateCounter(rrdPath, "fragmentedIpBytes", myGlobals.device[i].fragmentedIpBytes.value);
	updateCounter(rrdPath, "tcpBytes", myGlobals.device[i].tcpBytes.value);
	updateCounter(rrdPath, "udpBytes", myGlobals.device[i].udpBytes.value);
	updateCounter(rrdPath, "otherIpBytes", myGlobals.device[i].otherIpBytes.value);
	updateCounter(rrdPath, "icmpBytes", myGlobals.device[i].icmpBytes.value);
	updateCounter(rrdPath, "dlcBytes", myGlobals.device[i].dlcBytes.value);
	updateCounter(rrdPath, "ipxBytes", myGlobals.device[i].ipxBytes.value);
	updateCounter(rrdPath, "stpBytes", myGlobals.device[i].stpBytes.value);
	updateCounter(rrdPath, "decnetBytes", myGlobals.device[i].decnetBytes.value);
	updateCounter(rrdPath, "netbiosBytes", myGlobals.device[i].netbiosBytes.value);
	updateCounter(rrdPath, "arpRarpBytes", myGlobals.device[i].arpRarpBytes.value);
	updateCounter(rrdPath, "atalkBytes", myGlobals.device[i].atalkBytes.value);
	updateCounter(rrdPath, "ospfBytes", myGlobals.device[i].ospfBytes.value);
	updateCounter(rrdPath, "egpBytes", myGlobals.device[i].egpBytes.value);
	updateCounter(rrdPath, "igmpBytes", myGlobals.device[i].igmpBytes.value);
	updateCounter(rrdPath, "osiBytes", myGlobals.device[i].osiBytes.value);
	updateCounter(rrdPath, "qnxBytes", myGlobals.device[i].qnxBytes.value);
	updateCounter(rrdPath, "otherBytes", myGlobals.device[i].otherBytes.value);
	updateCounter(rrdPath, "upTo64", myGlobals.device[i].rcvdPktStats.upTo64.value);
	updateCounter(rrdPath, "upTo128", myGlobals.device[i].rcvdPktStats.upTo128.value);
	updateCounter(rrdPath, "upTo256", myGlobals.device[i].rcvdPktStats.upTo256.value);
	updateCounter(rrdPath, "upTo512", myGlobals.device[i].rcvdPktStats.upTo512.value);
	updateCounter(rrdPath, "upTo1024", myGlobals.device[i].rcvdPktStats.upTo1024.value);
	updateCounter(rrdPath, "upTo1518", myGlobals.device[i].rcvdPktStats.upTo1518.value);
	updateCounter(rrdPath, "badChecksum", myGlobals.device[i].rcvdPktStats.badChecksum.value);
	updateCounter(rrdPath, "tooLong", myGlobals.device[i].rcvdPktStats.tooLong.value);

	if(myGlobals.device[i].ipProtoStats != NULL) {
	  sprintf(rrdPath, "%s/rrd/interfaces/%s/IP.", myGlobals.dbPath,  myGlobals.device[i].name);

	  for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {
	    TrafficCounter ctr;

	    ctr.value =
	      myGlobals.device[i].ipProtoStats[j].local.value+
	      myGlobals.device[i].ipProtoStats[j].local2remote.value+
	      myGlobals.device[i].ipProtoStats[j].remote2local.value+
	      myGlobals.device[i].ipProtoStats[j].remote.value;

	    updateCounter(rrdPath, myGlobals.protoIPTrafficInfos[j], ctr.value);
	  }
	}
      }
    }

    /* ************************** */

    if(dumpMatrix) {
      int k;
      
      for(k=0; k<myGlobals.numDevices; k++)
	for(i=1; i<myGlobals.device[k].numHosts; i++)
	  if(i != myGlobals.otherHostEntryIdx) {
	    for(j=1; j<myGlobals.device[k].numHosts; j++) {
	      if(i != j) {
		int idx = i*myGlobals.device[k].numHosts+j;

		if(idx == myGlobals.otherHostEntryIdx) continue;

		if(myGlobals.device[k].ipTrafficMatrix[idx] == NULL)
		  continue;

		if(myGlobals.device[k].ipTrafficMatrix[idx]->bytesSent.value > 0) {

		  sprintf(rrdPath, "%s/rrd/matrix/%s/%s/", myGlobals.dbPath,
			  myGlobals.device[k].ipTrafficMatrixHosts[i]->hostNumIpAddress,
			  myGlobals.device[k].ipTrafficMatrixHosts[j]->hostNumIpAddress);

		  sprintf(filePath, "mkdir -p %s", rrdPath);
		  system(filePath);

		  updateCounter(rrdPath, "pkts",
				myGlobals.device[k].ipTrafficMatrix[idx]->pktsSent.value);

		  updateCounter(rrdPath, "bytes",
				myGlobals.device[k].ipTrafficMatrix[idx]->bytesSent.value);		  
		}
	      }
	    }
	  }
    }

    traceEvent(TRACE_INFO, "%lu RRDs updated (%lu total updates)", 
	       (unsigned long)(numTotalRRDs-numRRDs), (unsigned long)numTotalRRDs);
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "rrdMainLoop() terminated.");
#endif

  return(0);
}

/* ****************************** */

static void initRrdFunct(void) {

#ifdef MULTITHREADED
  /* This plugin works only with threads */
  createThread(&rrdThread, rrdMainLoop, NULL);
#endif

  traceEvent(TRACE_INFO, "Welcome to the RRD plugin...");
  fflush(stdout);
  numTotalRRDs = 0;
}

/* ****************************** */

static void termRrdFunct(void) {
#ifdef MULTITHREADED
  if(initialized) killThread(&rrdThread);
#endif

  traceEvent(TRACE_INFO, "Thanks for using the rrdPlugin");
  traceEvent(TRACE_INFO, "Done.\n");
  fflush(stdout);
}

#else /* HAVE_LIBRRD */

static void initRrdFunct(void) { }
static void termRrdFunct(void) { }
static void handleRRDHTTPrequest(char* url) {
  sendHTTPHeader(HTTP_TYPE_HTML, 0);
  printHTMLheader("RRD Preferences", 0);
  printFlagedWarning("<I>This plugin is disabled as ntop has not been compiled with RRD support</I>");
}

#endif /* HAVE_LIBRRD */

/* ************************************* */

static PluginInfo rrdPluginInfo[] = {
  { "rrdPlugin",
    "This plugin handles RRD packets",
    "1.0.2", /* version */
    "<A HREF=http://luca.ntop.org/>L.Deri</A>",
    "rrdPlugin", /* http://<host>:<port>/plugins/rrdPlugin */
    0, /* Active */
    initRrdFunct, /* TermFunc   */
    termRrdFunct, /* TermFunc   */
    NULL, /* PluginFunc */
    handleRRDHTTPrequest,
    NULL /* no capture */
  }
};

/* ****************************** */

/* Plugin entry fctn */
#ifdef STATIC_PLUGIN
PluginInfo* rrdPluginEntryFctn(void)
#else
PluginInfo* PluginEntryFctn(void)
#endif
{
  traceEvent(TRACE_INFO, "Welcome to %s. (C) 2002 by Luca Deri.\n",
	     rrdPluginInfo->pluginName);

  return(rrdPluginInfo);
}

