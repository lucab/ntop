/*
 *  Copyright(C) 2008-11 Luca Deri <deri@ntop.org>
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

static void* cpacketMainLoop(void* _deviceId);

/* #define DEBUG_FLOWS */

#define CONST_CPACKET_STATISTICS_HTML       "statistics.html"

#define valueOf(a) (a == NULL ? "" : a)
#define isEmpty(a) ((a == NULL) || (a[0] == '\0') ? 1 : 0)


#define SWAP8(a,b)  { u_int8_t  c = a; a = b; b = c; }
#define SWAP16(a,b) { u_int16_t c = a; a = b; b = c; }
#define SWAP32(a,b) { u_int32_t c = a; a = b; b = c; }

/* ********************************* */

/* Forward */
static int setcPacketInSocket(int);
static void setPluginStatus(char * status);
static int initcPacketFunct(void);
static void termcPacketFunct(u_char termNtop /* 0=term plugin, 1=term ntop */);
static void termcPacketDevice(int deviceId);
static void initcPacketDevice(int deviceId);
#ifdef DEBUG_FLOWS
static void handlecPacketPacket(u_char *_deviceId,
				const struct pcap_pkthdr *h,
				const u_char *p);
#endif
static void handlecPacketHTTPrequest(char* url);
static void printcPacketConfiguration(int deviceId);
static int createcPacketDevice(int cpacketDeviceId);
static int mapcPacketDeviceToNtopDevice(int deviceId);
static void printcPacketStatistics(void);
static void printcPacketCounterStats(int deviceId, int page_header, int print_table);

/* ****************************** */

u_char static pluginActive = 0;

static ExtraPage cpacketExtraPages[] = {
  { NULL, CONST_CPACKET_STATISTICS_HTML, "Statistics" },
  { NULL, NULL, NULL }
};

static PluginInfo cpacketPluginInfo[] = {
  {
    VERSION, /* current ntop version */
    "cPacket",
    "This plugin is used collect traffic statistics emitted by <A HREF=http://www.cpacket.com>cPacket</A>'s cTap devices.<br>"
    "<i>Received flow data is reported as a separate 'NIC' in the regular <b>ntop</b> "
    "reports.<br><em>Remember to <A HREF=/switch.html>switch</A> the reporting NIC.</em>",
    "0.1", /* version */
    "<a href=\"http://luca.ntop.org/\" alt=\"Luca's home page\">L.Deri</A>",
    "cPacket", /* http://<host>:<port>/plugins/cPacket */
    0, /* Active by default */
    ViewConfigure,
    1, /* Inactive setup */
    initcPacketFunct, /* InitFunc */
    termcPacketFunct, /* TermFunc */
#ifdef DEBUG_FLOWS
    handlecPacketPacket,
#else
    NULL, /* PluginFunc */
#endif
    handlecPacketHTTPrequest,
    NULL, /* no host creation/deletion handle */
#ifdef DEBUG_FLOWS
    "udp and port 20167",
#else
    NULL, /* no capture */
#endif
    NULL, /* no status */
    cpacketExtraPages
  }
};

/* ************************************** */

static int setcPacketInSocket(int deviceId) {
  struct sockaddr_in sockIn;
  int sockopt = 1;

  if(myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket > 0) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "CPACKET: Collector terminated");
    closeNwSocket(&myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket);
  }

  if(myGlobals.device[deviceId].cpacketGlobals->cpacketInPort > 0) {
    errno = 0;
    myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if((myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket <= 0) || (errno != 0) ) {
      traceEvent(CONST_TRACE_INFO, "CPACKET: Unable to create a UDP socket - returned %d, error is '%s'(%d)",
		 myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket, strerror(errno), errno);
      setPluginStatus("Disabled - Unable to create listening socket.");
      return(-1);
    }

    traceEvent(CONST_TRACE_INFO, "CPACKET: Created a UDP socket (%d)",
	       myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket);

    setsockopt(myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket,
	       SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    sockIn.sin_family            = AF_INET;
    sockIn.sin_port              =(int)htons(myGlobals.device[deviceId].cpacketGlobals->cpacketInPort);
    sockIn.sin_addr.s_addr       = INADDR_ANY;

    if(bind(myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket,
	     (struct sockaddr *)&sockIn, sizeof(sockIn)) < 0) {
      traceEvent(CONST_TRACE_ERROR, "CPACKET: Collector port %d already in use",
		 myGlobals.device[deviceId].cpacketGlobals->cpacketInPort);
      closeNwSocket(&myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket);
      myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket = 0;
      return(0);
    }

    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "CPACKET: Collector listening on port %d",
	       myGlobals.device[deviceId].cpacketGlobals->cpacketInPort);
  }

  if((myGlobals.device[deviceId].cpacketGlobals->cpacketInPort != 0)
     && (!myGlobals.device[deviceId].cpacketGlobals->threadActive)) {
    /* This plugin works only with threads */
    createThread(&myGlobals.device[deviceId].cpacketGlobals->cpacketThread,
		 cpacketMainLoop, (void*)((long)deviceId));
    traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: CPACKET: Started thread for receiving flows on port %d",
	       (long)myGlobals.device[deviceId].cpacketGlobals->cpacketThread,
	       myGlobals.device[deviceId].cpacketGlobals->cpacketInPort);
  }

  return(0);
}

/* ********************************************************* */

static void updateCtapCounter(int deviceId, char *name,
			      u_long bytes, u_long packets) {
  cPacketCounter *prev, *entry;
  u_short debug = 0;

  if(debug) traceEvent(CONST_TRACE_ALWAYSDISPLAY, "[%s][%lu|%lu]", name, bytes, packets);

  if(myGlobals.device[deviceId].cpacketGlobals->last_head != NULL)
    prev = myGlobals.device[deviceId].cpacketGlobals->last_head;
  else
    prev = myGlobals.device[deviceId].cpacketGlobals->last_head
      = myGlobals.device[deviceId].cpacketGlobals->counter_list_head;

  while(myGlobals.device[deviceId].cpacketGlobals->last_head != NULL) {
    if(!strcmp(name, myGlobals.device[deviceId].cpacketGlobals->last_head->name)) {
      /* Update */
      entry = myGlobals.device[deviceId].cpacketGlobals->last_head;
      entry->bytes = bytes, entry->packets = packets;

      if(debug) traceEvent(CONST_TRACE_INFO, "Updated [%s][%lu|%lu]", name, bytes, packets);

      if(myGlobals.device[deviceId].cpacketGlobals->last_head->next)
	myGlobals.device[deviceId].cpacketGlobals->last_head =
	  myGlobals.device[deviceId].cpacketGlobals->last_head->next;
      else
	myGlobals.device[deviceId].cpacketGlobals->last_head =
	  myGlobals.device[deviceId].cpacketGlobals->counter_list_head;
      return;
    } else {
      prev = myGlobals.device[deviceId].cpacketGlobals->last_head;
      myGlobals.device[deviceId].cpacketGlobals->last_head =
	myGlobals.device[deviceId].cpacketGlobals->last_head->next;
    }
  }

  /* If we're here the counter has not been updated yet */
  entry = (cPacketCounter*)malloc(sizeof(cPacketCounter));
  if(entry) {
    entry->name = strdup(name), entry->bytes = bytes, entry->packets = packets, entry->next = NULL;

    if(myGlobals.device[deviceId].cpacketGlobals->counter_list_head == NULL)
      myGlobals.device[deviceId].cpacketGlobals->counter_list_head = entry;
    else
      prev->next = entry;

    myGlobals.device[deviceId].cpacketGlobals->last_head = NULL;
    if(debug) traceEvent(CONST_TRACE_INFO, "Added [%s][%lu|%lu]", name, bytes, packets);
  }
}

/* ********************************************************* */

static void dissectPacket(u_int32_t cpacket_device_ip,
			  char *buffer, int bufferLen, int deviceId) {
  char *tokbuf, *row;

  // printf("\n\n%s\n", buffer);

  row = strtok_r(buffer, "\n", &tokbuf); if(!row) return;
  row = strtok_r(NULL, "\n", &tokbuf);   if(!row) return;
  row = strtok_r(NULL, "\n", &tokbuf);

  while(row != NULL) {
    if(row[0] == '\"') {
      char *name, *value, *elem_buf;
      u_long bytes, pkts;

      name = strtok_r(row, " ", &elem_buf);  if(!name) break;
      name++; name++; name[strlen(name)-1] = '\0';
      value = strtok_r(NULL, " ", &elem_buf); if(!value) break;
      sscanf(value, "(%lu,%lu)", &bytes, &pkts);
      updateCtapCounter(deviceId, name, bytes, pkts);
    }

    row = strtok_r(NULL, "\n", &tokbuf);
  }
}

/* ****************************** */

#ifdef MAKE_WITH_CPACKETSIGTRAP
RETSIGTYPE cpacketcleanup(int signo) {
  static int msgSent = 0;
  int i;
  void *array[20];
  size_t size;
  char **strings;

  if(msgSent<10) {
    traceEvent(CONST_TRACE_FATALERROR, "CPACKET: caught signal %d %s", signo,
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

  traceEvent(CONST_TRACE_FATALERROR, "CPACKET: ntop shutting down...");
  exit(100);
}
#endif /* MAKE_WITH_CPACKETSIGTRAP */

/* ****************************** */

static void* cpacketMainLoop(void* _deviceId) {
  fd_set cpacketMask;
  int rc, len, deviceId;
  u_char buffer[2048];
  struct sockaddr_in fromHost;

  deviceId = (int)((long)_deviceId);

  if(!(myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket > 0)) return(NULL);

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: CPACKET: thread starting [p%d]",
             (long unsigned int)pthread_self(), getpid());

#ifdef MAKE_WITH_CPACKETSIGTRAP
  signal(SIGSEGV, cpacketcleanup);
  signal(SIGHUP,  cpacketcleanup);
  signal(SIGINT,  cpacketcleanup);
  signal(SIGQUIT, cpacketcleanup);
  signal(SIGILL,  cpacketcleanup);
  signal(SIGABRT, cpacketcleanup);
  signal(SIGFPE,  cpacketcleanup);
  signal(SIGKILL, cpacketcleanup);
  signal(SIGPIPE, cpacketcleanup);
  signal(SIGALRM, cpacketcleanup);
  signal(SIGTERM, cpacketcleanup);
  signal(SIGUSR1, cpacketcleanup);
  signal(SIGUSR2, cpacketcleanup);
  /* signal(SIGCHLD, cpacketcleanup); */
#ifdef SIGCONT
  signal(SIGCONT, cpacketcleanup);
#endif
#ifdef SIGSTOP
  signal(SIGSTOP, cpacketcleanup);
#endif
#ifdef SIGBUS
  signal(SIGBUS,  cpacketcleanup);
#endif
#ifdef SIGSYS
  signal(SIGSYS,  cpacketcleanup);
#endif
#endif /* MAKE_WITH_CPACKETSIGTRAP */

  myGlobals.device[deviceId].activeDevice = 1;
  myGlobals.device[deviceId].cpacketGlobals->threadActive = 1;

  ntopSleepUntilStateRUN();
  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: CPACKET: (port %d) thread running [p%d]",
             (long unsigned int)pthread_self(), myGlobals.device[deviceId].cpacketGlobals->cpacketInPort, getpid());

  for(;myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN;) {
    int maxSock = myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket;
    struct timeval wait_time;

    FD_ZERO(&cpacketMask);
    FD_SET(myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket, &cpacketMask);

    if(!myGlobals.device[deviceId].activeDevice) break;
    wait_time.tv_sec = 3, wait_time.tv_usec = 0;
    rc = select(maxSock+1, &cpacketMask, NULL, NULL, &wait_time);
    if(!myGlobals.device[deviceId].activeDevice) break;

    if(rc > 0) {
      if(FD_ISSET(myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket, &cpacketMask)){
	len = sizeof(fromHost);
	rc = recvfrom(myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket,
		      (char*)&buffer, sizeof(buffer),
		      0, (struct sockaddr*)&fromHost, (socklen_t*)&len);
      }

#ifdef DEBUG_FLOWS
      traceEvent(CONST_TRACE_INFO, "CPACKET_DEBUG: Received cPacket packet(len=%d)(deviceId=%d)",
		 rc,  deviceId);
#endif

      if(rc > 0) {
	int i;

	myGlobals.device[deviceId].cpacketGlobals->numPktsRcvd++;
	NTOHL(fromHost.sin_addr.s_addr);

	for(i=0; i<MAX_NUM_PROBES; i++) {
	  if(myGlobals.device[deviceId].cpacketGlobals->deviceList[i].probeAddr.s_addr == 0) {
	    myGlobals.device[deviceId].cpacketGlobals->deviceList[i].probeAddr.s_addr = fromHost.sin_addr.s_addr;
	    myGlobals.device[deviceId].cpacketGlobals->deviceList[i].pkts = 1;
	    break;
	  } else if(myGlobals.device[deviceId].cpacketGlobals->deviceList[i].probeAddr.s_addr == fromHost.sin_addr.s_addr) {
	    myGlobals.device[deviceId].cpacketGlobals->deviceList[i].pkts++;
	    break;
	  }
	}

	dissectPacket(fromHost.sin_addr.s_addr, (char*)buffer, rc, deviceId);
      }
    } else {
      if((rc < 0) && (myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN) && (errno != EINTR /* Interrupted system call */)) {
	traceEvent(CONST_TRACE_ERROR, "CPACKET: select() failed(%d, %s), terminating cpacket",
		   errno, strerror(errno));
	break;
      }
    }
  }

  if(myGlobals.device[deviceId].cpacketGlobals != NULL) {
    myGlobals.device[deviceId].cpacketGlobals->threadActive = 0;
    myGlobals.device[deviceId].cpacketGlobals->cpacketThread = 0;
  }
  myGlobals.device[deviceId].activeDevice = 0;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: CPACKET: thread terminated [p%d][cpacketDeviceId=%d]",
	     (long unsigned int)pthread_self(), getpid(), myGlobals.device[deviceId].cpacketGlobals->cpacketDeviceId);

  return(NULL);
}

/* ****************************** */

static char* cpValue(int deviceId, char *name, int appendDeviceId) {
  static char buf[64];

  if(appendDeviceId) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "cpacket.%d.%s",
		  myGlobals.device[deviceId].cpacketGlobals->cpacketDeviceId, name);
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "cpacket.%s", name);
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "CPACKET: cpValue=%s", buf);
#endif

  return(buf);
}

/* ****************************** */

static void initcPacketDevice(int deviceId) {
  char value[1024];

  if(!pluginActive) return;

  traceEvent(CONST_TRACE_INFO, "CPACKET: initializing deviceId=%d", deviceId);

  if(myGlobals.device[deviceId].cpacketGlobals == NULL) {
    traceEvent(CONST_TRACE_ERROR, "CPACKET: initcPacketDevice internal error");
    return;
  }

  allocDeviceMemory(deviceId);

  setPluginStatus(NULL);

  myGlobals.device[deviceId].cpacketGlobals->threadActive = 0;

  if(fetchPrefsValue(cpValue(deviceId, "cpacketInPort", 1), value, sizeof(value)) == -1)
    storePrefsValue(cpValue(deviceId, "cpacketInPort", 1), "0");
  else
    myGlobals.device[deviceId].cpacketGlobals->cpacketInPort = atoi(value);

  if(setcPacketInSocket(deviceId) != 0)  return;

  if(fetchPrefsValue(cpValue(deviceId, "debug", 1), value, sizeof(value)) == -1) {
    storePrefsValue(cpValue(deviceId, "debug", 1), "0");
    myGlobals.device[deviceId].cpacketGlobals->cpacketDebug = 1;
  } else {
    myGlobals.device[deviceId].cpacketGlobals->cpacketDebug = atoi(value);
  }

  initDeviceSemaphores(deviceId);
}

/* ****************************** */

static int initcPacketFunct(void) {
  char value[128];

  traceEvent(CONST_TRACE_INFO, "CPACKET: Welcome to the cpacket plugin");

  pluginActive = 1;
  myGlobals.runningPref.mergeInterfaces = 0; /* Use different devices */

#ifdef MAX_CPACKET_FLOW_BUFFER
  memset(&cpacketflowBuffer, 0, sizeof(cpacketflowBuffer));
  cpacketflowBufferCount = 0;
  cpacketfmaxTime = 0.0;
#endif

  if((fetchPrefsValue(cpValue(0, "knownDevices", 0), value, sizeof(value)) != -1)
     && (strlen(value) > 0)) {
    char *strtokState, *dev;

    traceEvent(CONST_TRACE_INFO, "CPACKET: initializing '%s' devices", value);

    dev = strtok_r(value, ",", &strtokState);
    while(dev != NULL) {
      int deviceId = atoi(dev);

      if(deviceId > 0) {
	int initializedDeviceId;

	if((initializedDeviceId = createcPacketDevice(deviceId)) == -1) {
	  pluginActive = 0;
	  return(-1);
	}
      }

      dev = strtok_r(NULL, ",", &strtokState);
    }
  } else
    traceEvent(CONST_TRACE_INFO, "CPACKET: no devices to initialize");

  return(0);
}

/* ****************************** */

static void printcPacketDeviceConfiguration(void) {
  char buf[512], value[128];
  int i = 0;

  sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");
  sendString("<tr><th "DARK_BG">Available cPacket Devices</th></tr>\n");
  sendString("<tr><td align=left>\n");

  if((fetchPrefsValue(cpValue(0, "knownDevices", 0), value, sizeof(value)) != -1)
     && (strlen(value) > 0)) {
    char *strtokState, *dev;

    sendString("<FORM ACTION=\"/plugins/");
    sendString(cpacketPluginInfo->pluginURLname);
    sendString("\" METHOD=GET>\n");

    dev = strtok_r(value, ",", &strtokState);
    while(dev != NULL) {
      int id = mapcPacketDeviceToNtopDevice(atoi(dev));

      if(id == -1)
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=device VALUE=%s %s>%s.%s\n",
		      dev, i == 0 ? "CHECKED" : "", CPACKET_DEVICE_NAME, dev);
      else
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=device VALUE=%s %s>%s\n",
		      dev, i == 0 ? "CHECKED" : "", myGlobals.device[id].humanFriendlyName);

      sendString(buf);

      if(pluginActive) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[ <A HREF=\"/plugins/%s?device=-%s\" "
		      "onClick=\"return confirmDelete()\">Delete</A> ]",
		      cpacketPluginInfo->pluginURLname, dev);
	sendString(buf);
      }

      sendString("<br>\n");
      i++; dev = strtok_r(NULL, ",", &strtokState);
    }

    if(pluginActive)
      sendString("<p><INPUT TYPE=submit VALUE=\"Edit cPacket Device\">&nbsp;"
		 "<INPUT TYPE=reset VALUE=Reset>\n</FORM><p>\n");
  }

  /* *********************** */

  if(pluginActive) {
    sendString("<FORM ACTION=\"/plugins/");
    sendString(cpacketPluginInfo->pluginURLname);
    sendString("\" METHOD=GET>\n<input type=hidden name=device size=5 value=0>");
    sendString("<p align=center><INPUT TYPE=submit VALUE=\"Add cPacket Device\">&nbsp;\n</FORM><p>\n");
  } else {
    sendString("<p>Please <A HREF=\"/"CONST_SHOW_PLUGINS_HTML"?");
    sendString(cpacketPluginInfo->pluginURLname);
    sendString("=1\">enable</A> the cPacket plugin first<br>\n");
  }

  sendString("</td></TR></TABLE></center>");

  printHTMLtrailer();
}

/* ****************************** */

static void printcPacketStatistics(void) {
  int i, printedStatistics = 0;
  char buf[1024], formatBuf[64];

  printHTMLheader("cTap Statistics", NULL, 0);

  for(i = 0; i<myGlobals.numDevices; i++) {
    if((myGlobals.device[i].cpacketGlobals != NULL) &&
       (myGlobals.device[i].cpacketGlobals->numPktsRcvd > 0)) {
      if(printedStatistics == 0) {
        sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");
        printedStatistics = 1;
      }
    
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "<tr><th colspan=5 "TH_BG" align=center>Device: %s</tr>\n",
                    myGlobals.device[i].humanFriendlyName);
      sendString(buf);

      sendString("<tr><th "TH_BG" "DARK_BG" colspan=5>Statistics</th></tr>\n");
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "<tr><th "TH_BG" align=left colspan=3>Stats Packets Received</th>"
		    "<td "TD_BG" align=right colspan=2>%s</td></tr>\n",
		    formatPkts(myGlobals.device[i].cpacketGlobals->numPktsRcvd, 
			       formatBuf, sizeof(formatBuf)));
      sendString(buf);
      printcPacketCounterStats(i, 0, 0);
    }
  }
  if(printedStatistics == 1) {
    sendString("</table>\n</center>\n");
  } else {
    printNoDataYet();
  }
}

/* ****************************** */

static void printcPacketCounterStats(int deviceId, int page_header, int print_table) {
  char buf[1024], *title = "cTap Counters";

  if((deviceId < 0) || (deviceId >myGlobals.numDevices)) return;
  
  if(page_header)
    printHTMLheader(title, NULL, 0);

  if(print_table) printSectionTitle(title);

  if(myGlobals.device[deviceId].cpacketGlobals->numPktsRcvd > 0) {
    cPacketCounter *elem;

    memset(&buf, 0, sizeof(buf));

    if(print_table) sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");
    sendString("<tr><th "TH_BG" "DARK_BG">Counter</th>"
	       "<th "TH_BG" "DARK_BG" colspan=2>Bytes</th>"
	       "<th "TH_BG" "DARK_BG" colspan=2>Packets</th>\n");

    elem = myGlobals.device[deviceId].cpacketGlobals->counter_list_head;
    
    while(elem != NULL) {
      char formatBuf[64], formatBuf1[64];

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<tr "TR_ON" ><th  "TH_BG" align=left>%s</th>"
		    "<td "TD_BG" align=right>%s</td>",
                    elem->name, formatBytes(elem->bytes, 1, formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		    "<TD "TD_BG" ALIGN=CENTER>"
		    "<A HREF=\"/plugins/rrdPlugin?action=arbreq&arbfile=bytes"
		    "&arbiface=%s/cTap/%s&start=%u&end=%u&counter=&title=%s&mode=zoom\">"
		    "<IMG valign=top class=tooltip SRC=/graph.gif border=0></A>"
		    "</TD>\n",
		    myGlobals.device[deviceId].uniqueIfName, 
		    elem->name,
		    (unsigned int)(myGlobals.actTime-3600),
		    (unsigned int)myGlobals.actTime, elem->name);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<td "TD_BG" align=right>%s</td>\n",
		    formatPkts(elem->packets, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		    "<TD "TD_BG" ALIGN=CENTER>"
		    "<A HREF=\"/plugins/rrdPlugin?action=arbreq&arbfile=pkts"
		    "&arbiface=%s/cTap/%s&start=%u&end=%u&counter=&title=%s&mode=zoom\">"
		    "<IMG valign=top class=tooltip SRC=/graph.gif border=0></A>"
		    "</TD></TR>\n",
		    myGlobals.device[deviceId].uniqueIfName, 
		    elem->name,
		    (unsigned int)(myGlobals.actTime-3600),
		    (unsigned int)myGlobals.actTime, elem->name);
      sendString(buf);


      elem = elem->next;
    }

    if(print_table) sendString("</table>\n</center>\n");
  } else {
    printNoDataYet();
  }
}

/* ****************************** */

static void printcPacketConfiguration(int deviceId) {
  char buf[512];

#define UDPSLASHSCPT "UDP"

  sendString("<center><table border=\"1\" "TABLE_DEFAULTS">\n");
  sendString("<tr><th colspan=\"4\" "DARK_BG">Incoming Flows</th></tr>\n");

  sendString("<tr><th colspan=2 "DARK_BG">cPacket Device</th>");

  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(cpacketPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].cpacketGlobals->cpacketDeviceId);
  sendString(buf);

  sendString("<input name=\"name\" size=\"24\" value=\"");
  sendString(myGlobals.device[deviceId].humanFriendlyName);
  sendString("\"> <input type=\"submit\" value=\"Set Interface Name\">");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), " [ <A HREF=\"/plugins/%s\"/>List cPacket Interfaces</A> ]</p>\n</form>",
		cpacketPluginInfo->pluginName);
  sendString(buf);
  sendString("</td></tr>\n");

  sendString("<tr><th rowspan=\"2\" "DARK_BG">Flow<br>Collection</th>\n");

  sendString("<th "DARK_BG">Local<br>Collector<br>" UDPSLASHSCPT "<br>Port</th>\n");

  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(cpacketPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].cpacketGlobals->cpacketDeviceId);
  sendString(buf);

  sendString("<input name=\"port\" size=\"5\" value=\"");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", myGlobals.device[deviceId].cpacketGlobals->cpacketInPort);
  sendString(buf);

  sendString("\"> [ Use a port value of 0 to disable collection ] "
	     "<input type=\"submit\" value=\"Set Port\">"
	     "</p>\n</form>\n\n"
             "<p>If you want <b>ntop</b> to display cPacket data it receives from other "
             "hosts, i.e. act as a collector, you must specify the " UDPSLASHSCPT
	     " port to listen to. "
             "The default port used for cPacket is " DEFAULT_CPACKET_PORT_STR ".</p>\n"
	     "<p align=\"right\"></p>\n");

  if(myGlobals.device[deviceId].cpacketGlobals->cpacketInPort == 0)
    sendString("<p><font color=red>WARNING</font>: "
	       "The 'Local Collector " UDPSLASHSCPT  "Port' is zero (none). "
               "Even if this plugin is ACTIVE, you must still enter a port number for "
               "<b>ntop</b> to receive and process cPacket data.</p>\n");

  sendString("</td></tr>\n");

   sendString("<tr><td colspan=\"4\">&nbsp;</td></tr>\n"
             "<tr><th colspan=\"4\" "DARK_BG">General Options</th></tr>\n");

   /* ********************************************* */

  sendString("<tr><th colspan=\"2\" "DARK_BG">Debug</th>\n");
  sendString("<td "TD_BG"><form action=\"/" CONST_PLUGINS_HEADER);
  sendString(cpacketPluginInfo->pluginURLname);
  sendString("\" method=GET>\n<p>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=hidden NAME=device VALUE=%d>",
		myGlobals.device[deviceId].cpacketGlobals->cpacketDeviceId);
  sendString(buf);

  if(myGlobals.device[deviceId].cpacketGlobals->cpacketDebug) {
    sendString("<input type=\"radio\" name=\"debug\" value=\"1\" checked>On");
    sendString("<input type=\"radio\" name=\"debug\" value=\"0\">Off");
  } else {
    sendString("<input type=\"radio\" name=\"debug\" value=\"1\">On");
    sendString("<input type=\"radio\" name=\"debug\" value=\"0\" checked>Off");
  }

  sendString(" <input type=\"submit\" value=\"Set Debug\"></p>\n");

  sendString("</form>\n"
             "<p>This option turns on debugging, which dumps a huge quantity of "
             "noise into the standard <b>ntop</b> log, all about what the cPacket "
             "plugin is doing.  If you are doing development, this might be helpful, "
             "otherwise <i>leave it alone</i>!</p>\n"
	     "</td>\n</tr>\n");

  sendString("<tr><td colspan=4><font color=red><b>REMEMBER</b><br></font><ul><li>Regardless of settings here, "
             "the cPacket plugin must be ACTIVE on the main plugin menu (click "
             "<a href=\"../" CONST_SHOW_PLUGINS_HTML "\">here</a> to go back) "
             "for <b>ntop</b> to receive and/or "
             "process cPacket data.\n"
             "<li>Any option not indicated as taking effect immediately will require you "
             "to recycle (inactivate and then activate) the cPacket plugin in order "
             "for the change to take affect.</ul></td></tr>\n");

  sendString("</table>\n</center>\n");
}
#undef UDPSLASHSCPT

/* ****************************** */

static int createcPacketDevice(int cpacketDeviceId) {
  int deviceId;
  char buf[32], value[128];

  traceEvent(CONST_TRACE_INFO, "CPACKET: createcPacketDevice(%d)", cpacketDeviceId);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s.%d", CPACKET_DEVICE_NAME, cpacketDeviceId);
  deviceId = createDummyInterface(buf);

  if(deviceId != -1) {
    myGlobals.device[deviceId].cpacketGlobals = (cPacketGlobals*)malloc(sizeof(cPacketGlobals));

    if(myGlobals.device[deviceId].cpacketGlobals == NULL) {
      /* Not enough memory */
      traceEvent(CONST_TRACE_ERROR, "CPACKET: not enough memory (cpacketGlobals malloc)");
      return(-1);
    }

    memset(myGlobals.device[deviceId].cpacketGlobals, 0, sizeof(cPacketGlobals));

    myGlobals.device[deviceId].activeDevice = 1;
    myGlobals.device[deviceId].dummyDevice  = 0;
    myGlobals.device[deviceId].cpacketGlobals->cpacketDeviceId = cpacketDeviceId;
    initcPacketDevice(deviceId);
    createDeviceIpProtosList(deviceId);

    if(fetchPrefsValue(cpValue(deviceId, "humanFriendlyName", 1),
		       value, sizeof(value)) != -1) {
      free(myGlobals.device[deviceId].humanFriendlyName);
      myGlobals.device[deviceId].humanFriendlyName = strdup(value);
      calculateUniqueInterfaceName(deviceId);
    }

    traceEvent(CONST_TRACE_INFO, "CPACKET: createcPacketDevice created device %d",
	       deviceId);
  } else
    traceEvent(CONST_TRACE_ERROR, "CPACKET: createDummyInterface failed");

  return(deviceId);
}

/* ****************************** */

/* #define DEBUG_FLOWS */
static int mapcPacketDeviceToNtopDevice(int cpacketDeviceId) {
  int i;

  for(i=0; i<myGlobals.numDevices; i++)
    if(myGlobals.device[i].cpacketGlobals != NULL) {
      if(myGlobals.device[i].activeDevice
	 && (myGlobals.device[i].cpacketGlobals->cpacketDeviceId == cpacketDeviceId)) {
#ifdef DEBUG_FLOWS
	traceEvent(CONST_TRACE_INFO, "CPACKET: mapcPacketDeviceToNtopDevice(%d) = %d",
		   cpacketDeviceId, i);
#endif
	return(i);
      } else {
#ifdef DEBUG_FLOWS
	traceEvent(CONST_TRACE_INFO, "CPACKET: mapcPacketDeviceToNtopDevice (id=%d) <=> (cpacketDeviceId=%d)",
		   i, myGlobals.device[i].cpacketGlobals->cpacketDeviceId);
#endif
      }
    } else {
#ifdef DEBUG_FLOWS
      traceEvent(CONST_TRACE_INFO, "CPACKET: cpacketGlobals(%d)  = NULL\n", i);
#endif

    }

#ifdef DEBUG_FLOWS
  traceEvent(CONST_TRACE_INFO, "CPACKET: mapcPacketDeviceToNtopDevice(%d) failed\n",
	     cpacketDeviceId);
#endif

  return(-1); /* Not found */
}

/* #undef DEBUG_FLOWS */

/* ****************************** */

static void flushDevicePrefs(int deviceId) {
  if(deviceId >= myGlobals.numDevices) return;
  delPrefsValue(cpValue(deviceId, "cpacketInPort", 1));
  delPrefsValue(cpValue(deviceId, "debug", 1));
  delPrefsValue(cpValue(deviceId, "humanFriendlyName", 1));
}

/* ****************************** */

static void handlecPacketHTTPrequest(char* _url) {
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

	  if((deviceId > 0) && ((deviceId = mapcPacketDeviceToNtopDevice(deviceId)) == -1)) {
	    printHTMLheader("cPacket Configuration Error", NULL, 0);
	    printFlagedWarning("<I>Unable to locate the specified device. Please activate the plugin first.</I>");
	    return;
	  }
	} else if(strcmp(device, "port") == 0) {
	  if(myGlobals.device[deviceId].cpacketGlobals->cpacketInPort != atoi(value)) {
	    if(deviceId > 0) {
	      myGlobals.device[deviceId].cpacketGlobals->cpacketInPort = atoi(value);
	      storePrefsValue(cpValue(deviceId, "cpacketInPort", 1), value);
	      setcPacketInSocket(deviceId);
	    }
	  }
	} else if(strcmp(device, "name") == 0) {
	  char old_name[256], new_name[256];
	  int rc;

	  sanitize_rrd_string(value);

	  safe_snprintf(__FILE__, __LINE__, old_name, sizeof(old_name),
			"%s/interfaces/%s", myGlobals.rrdPath,
			myGlobals.device[deviceId].uniqueIfName);
	  revertSlashIfWIN32(old_name, 0);

	  free(myGlobals.device[deviceId].humanFriendlyName);
	  myGlobals.device[deviceId].humanFriendlyName = strdup(value);
	  storePrefsValue(cpValue(deviceId, "humanFriendlyName", 1), value);
	  calculateUniqueInterfaceName(deviceId);

	  safe_snprintf(__FILE__, __LINE__, new_name, sizeof(new_name),
			"%s/interfaces/%s", myGlobals.rrdPath,
			myGlobals.device[deviceId].uniqueIfName);
	  revertSlashIfWIN32(new_name, 0);

	  rc = rename(old_name, new_name);
	} else if(strcmp(device, "debug") == 0) {
	  if(deviceId > 0) {
	    myGlobals.device[deviceId].cpacketGlobals->cpacketDebug = atoi(value);
	    storePrefsValue(cpValue(deviceId, "debug", 1), value);
	  }
	}

	url = strtok_r(NULL, "&", &strtokState);
      }
    }
    
    if(strncasecmp(_url, CONST_CPACKET_STATISTICS_HTML, strlen(CONST_CPACKET_STATISTICS_HTML)) == 0) {
      printcPacketStatistics();
      printHTMLtrailer();
      return;
    }

#ifdef DEBUG_FLOWS
    traceEvent(CONST_TRACE_INFO, "CPACKET: deviceId=%d", deviceId);
#endif

    if(deviceId == -1) {
      printHTMLheader("cPacket Device Configuration", NULL, 0);
      printcPacketDeviceConfiguration();
      return;
    } else if(deviceId < 0) {
      /* Delete an existing device */
      char value[128];
      int readDeviceId;

      deviceId = -deviceId;

      if((deviceId < 0) || ((readDeviceId = mapcPacketDeviceToNtopDevice(deviceId)) == -1)) {
	printHTMLheader("cPacket Configuration Error", NULL, 0);
	printFlagedWarning("<I>Unable to locate the specified device. Please activate the plugin first.</I>");
	return;
      }

      traceEvent(CONST_TRACE_INFO, "CPACKET: Attempting to delete [deviceId=%d][cPacket device=%d]",
		 deviceId, readDeviceId);

      if(fetchPrefsValue(cpValue(deviceId, "knownDevices", 0), value, sizeof(value)) != -1) {
	char *dev, value1[128];

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

	storePrefsValue(cpValue(deviceId, "knownDevices", 0), value1);
      }

      myGlobals.device[readDeviceId].activeDevice = 0; // Terminate thread

      flushDevicePrefs(readDeviceId);

      traceEvent(CONST_TRACE_INFO, "CPACKET: Device [deviceId=%d][active=%d]",
		 readDeviceId, myGlobals.device[readDeviceId].activeDevice);

      // termcPacketDevice(readDeviceId);

      checkReportDevice();
      printHTMLheader("cPacket Device Configuration", NULL, 0);
      printcPacketDeviceConfiguration();
      return;
    } else if(deviceId == 0) {
      /* Add new device */
      char value[128];

      if((fetchPrefsValue(cpValue(deviceId, "knownDevices", 0), value, sizeof(value)) != -1)
	 && (strlen(value) > 0)) {
	char *dev, value1[128], buf[256];

	traceEvent(CONST_TRACE_INFO, "CPACKET: knownDevices=%s", value);

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

	traceEvent(CONST_TRACE_INFO, "CPACKET: knownDevices=%s", buf);
	storePrefsValue(cpValue(deviceId, "knownDevices", 0), buf);
      } else {
	deviceId = 2; /* 1 is reserved */
	traceEvent(CONST_TRACE_INFO, "CPACKET: knownDevices=2");
	storePrefsValue(cpValue(deviceId, "knownDevices", 0), "2");
      }

      if((deviceId = createcPacketDevice(deviceId)) <= 0) {
	printHTMLheader("cPacket Configuration Error", NULL, 0);
	printFlagedWarning("<I>Unable to create a new cPacket device</I>");
	return;
      }
    } else {
      /* Existing device */
    }

    if(deviceId > 0) {
      /* ****************************
       * Print Configuration stuff  *
       ****************************** */
      printHTMLheader("cPacket Configuration", NULL, 0);
      printcPacketConfiguration(deviceId);

      sendString("<p>\n");

      if(myGlobals.device[deviceId].cpacketGlobals->numPktsRcvd > 0) {
	printcPacketCounterStats(deviceId, 0, 1);
      }
    }
  }

  safe_snprintf(__FILE__, __LINE__, workList, sizeof(workList), "%s?device=%d",
		cpacketPluginInfo->pluginURLname, originalId);

  printPluginTrailer((myGlobals.device[deviceId].cpacketGlobals->numPktsRcvd > 0) ?
		     workList : NULL,
                     "cTap is a trademark of <a href=\"http://www.cpacket.com/\" "
                     "title=\"cPacket home page\">cPacket Inc</a>");

  printHTMLtrailer();
}

/* ****************************** */

static void termcPacketDevice(int deviceId) {
  traceEvent(CONST_TRACE_INFO, "CPACKET: terminating device %s",
	     myGlobals.device[deviceId].humanFriendlyName);

  if(!pluginActive) return;

  if(myGlobals.device[deviceId].activeDevice == 0) {
    /* traceEvent(CONST_TRACE_WARNING, "CPACKET: deviceId=%d terminated already", deviceId); */
    return;
  }

  if(myGlobals.device[deviceId].cpacketGlobals == NULL) {
    traceEvent(CONST_TRACE_WARNING, "CPACKET: deviceId=%d terminating a non-cPacket device", deviceId);
    return;
  }

  if((deviceId >= 0) && (deviceId < myGlobals.numDevices)) {
    if(myGlobals.device[deviceId].cpacketGlobals->threadActive) {
      killThread(&myGlobals.device[deviceId].cpacketGlobals->cpacketThread);
      myGlobals.device[deviceId].cpacketGlobals->threadActive = 0;
    }

    if(myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket > 0) {
      closeNwSocket(&myGlobals.device[deviceId].cpacketGlobals->cpacketInSocket);
    }

    free(myGlobals.device[deviceId].cpacketGlobals);
    myGlobals.device[deviceId].activeDevice = 0;
  } else
    traceEvent(CONST_TRACE_WARNING, "CPACKET: requested invalid termination of deviceId=%d", deviceId);
}

/* **************************************** */

static void termcPacketFunct(u_char termNtop /* 0=term plugin, 1=term ntop */) {
  char value[128];

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "CPACKET: Terminating cPacket");

  if((fetchPrefsValue(cpValue(0, "knownDevices", 0), value, sizeof(value)) != -1) && (strlen(value) > 0)) {
    char *strtokState, *dev;

    dev = strtok_r(value, ",", &strtokState);
    while(dev != NULL) {
      int deviceId, theDeviceId = atoi(dev);

      if((theDeviceId > 0) && ((deviceId = mapcPacketDeviceToNtopDevice(theDeviceId)) > 0)) {
	termcPacketDevice(deviceId);
      } else {
	traceEvent(CONST_TRACE_INFO, "CPACKET: [cpacketDeviceId=%d] device thread terminated in the meantime", theDeviceId);
      }

      dev = strtok_r(NULL, ",", &strtokState);
    }
  } else
    traceEvent(CONST_TRACE_INFO, "CPACKET: no devices to terminate (%s)", value);

  traceEvent(CONST_TRACE_INFO, "CPACKET: Thanks for using ntop cPacket");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "CPACKET: Done");
  fflush(stdout);
  pluginActive = 0;
}

/* **************************************** */

#ifdef DEBUG_FLOWS

static void handlecPacketPacket(u_char *_deviceId, const struct pcap_pkthdr *h,
				const u_char *p) {
  int sampledPacketSize;
  int deviceId, rc;

  if(myGlobals.runningPref.rFileName != NULL) {
    /* ntop is reading packets from a file */
    struct ether_header ehdr;
    u_int caplen = h->caplen;
    u_int length = h->len;
    unsigned short eth_type;
    u_int8_t flags = 0, debug = 0;
    struct ip ip;

    deviceId = 1; /* Dummy value */

#ifdef DEBUG_FLOWS
 {
   static long numPkt=0;

   ++numPkt;

    if(debug)
      traceEvent(CONST_TRACE_INFO, "Rcvd packet to dissect [caplen=%d][len=%d][num_pkt=%d]",
		 caplen, length, numPkt);
 }
#endif

    if(caplen >= sizeof(struct ether_header)) {
      memcpy(&ehdr, p, sizeof(struct ether_header));
      eth_type = ntohs(ehdr.ether_type);

      if(eth_type == ETHERTYPE_IP) {
	u_int plen, hlen;
	u_short sport, dport;

#ifdef DEBUG_FLOWS
	if(debug)
	  traceEvent(CONST_TRACE_INFO, "Rcvd IP packet to dissect");
#endif

	memcpy(&ip, p+sizeof(struct ether_header), sizeof(struct ip));
	hlen =(u_int)ip.ip_hl * 4;
	NTOHL(ip.ip_dst.s_addr); NTOHL(ip.ip_src.s_addr);

	plen = length-sizeof(struct ether_header);

#ifdef DEBUG_FLOWS
	if(debug)
	  traceEvent(CONST_TRACE_INFO, "Rcvd IP packet to dissect "
		     "[deviceId=%d][sender=%s][proto=%d][len=%d][hlen=%d]",
		     deviceId, intoa(ip.ip_src), ip.ip_p, plen, hlen);
#endif

	if(ip.ip_p == IPPROTO_UDP) {
	  if(plen >(hlen+sizeof(struct udphdr))) {
	    char* rawSample    =(void*)(p+sizeof(struct ether_header)+hlen+sizeof(struct udphdr));
	    int   rawSampleLen = h->caplen-(sizeof(struct ether_header)+hlen+sizeof(struct udphdr));

#ifdef DEBUG_FLOWS
	    if(debug)
	      traceEvent(CONST_TRACE_INFO, "Rcvd from from %s [cpacketGlobals=%x]", intoa(ip.ip_src),
			 myGlobals.device[deviceId].cpacketGlobals);
#endif

	    myGlobals.device[deviceId].cpacketGlobals->numPktsRcvd++;
	    dissectFlow(ip.ip_src.s_addr, rawSample, rawSampleLen, deviceId);
	  }
	}
      } else {
#ifdef DEBUG_FLOWS
	if(debug)
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
PluginInfo* cpacketPluginEntryFctn(void)
#else
     PluginInfo* PluginEntryFctn(void)
#endif
{
  traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	     "CPACKET: Welcome to %s.(C) 2008 by Luca Deri",
	     cpacketPluginInfo->pluginName);

  return(cpacketPluginInfo);
}

/* This must be here so it can access the struct PluginInfo, above */
static void setPluginStatus(char * status)
{
  if(cpacketPluginInfo->pluginStatusMessage != NULL)
    free(cpacketPluginInfo->pluginStatusMessage);
  if(status == NULL) {
    cpacketPluginInfo->pluginStatusMessage = NULL;
  } else {
    cpacketPluginInfo->pluginStatusMessage = strdup(status);
  }
}
