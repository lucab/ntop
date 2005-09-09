/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "ntop.h"

#ifdef HAVE_BACKTRACE
extern size_t backtrace(void* thearray[], int thearraylen);
extern char** backtrace_symbols(void* thearray[], int thearraylen);
#endif

static int *servicesMapper = NULL; /* temporary value */

#if defined(FREEBSD) && defined(__FreeBSD_cc_version) && (__FreeBSD_cc_version < 500000) && defined(HAVE_PCAP_SETNONBLOCK)
#warning special code for freeBSD 4.x
static unsigned long long setNonBlockingSleepCount;
#endif

/* *************************** */

static void printMutexInfo(PthreadMutex *mutexId, char *mutexName) {

  traceEvent(CONST_TRACE_INFO, "%s is %s (last lock %s:%d) [max lock time %s:%d (%.6f sec)]",
	     mutexName,
	     mutexId->isLocked ? "*locked*" : "unlocked",
	     mutexId->lock.file, mutexId->lock.line,
	     mutexId->max.file,
	     mutexId->max.line,
	     mutexId->maxLockedDuration);
}

#ifndef WIN32
void handleSigHup(int signalId _UNUSED_) {
  traceEvent(CONST_TRACE_INFO, "========================================");
  printMutexInfo(&myGlobals.gdbmMutex, "myGlobals.gdbmMutex");
  printMutexInfo(&myGlobals.packetProcessMutex, "myGlobals.packetProcessMutex");
  printMutexInfo(&myGlobals.packetQueueMutex, "myGlobals.packetQueueMutex");

  if(myGlobals.runningPref.numericFlag == 0)
    printMutexInfo(&myGlobals.addressResolutionMutex, "myGlobals.addressResolutionMutex");

  traceEvent(CONST_TRACE_INFO, "========================================");

  (void)signal(SIGHUP,  handleSigHup);
}

#endif /* WIN32 */

/* *************************** */

void* pcapDispatch(void *_i) {
  int rc;
  int i = (int)_i;
  struct pcap_stat pcapStats;

#if defined(FREEBSD) && defined(__FreeBSD_cc_version) && (__FreeBSD_cc_version < 500000) && defined(HAVE_PCAP_SETNONBLOCK)
  setNonBlockingSleepCount = 0;
#endif

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: NPS(%d,%s): pcapDispatch thread starting [p%d]",
	     pthread_self(), i+1, myGlobals.device[i].humanFriendlyName, getpid());

  /* Reset stats before to start (needed by modern libpcap versions) */
  if(myGlobals.runningPref.rFileName == NULL) {
    pcap_stats(myGlobals.device[i].pcapPtr, &pcapStats);
    myGlobals.device[i].initialPcapDroppedPkts.value = pcapStats.ps_drop;
  }

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: NPS(%d,%s): pcapDispatch thread running [p%d]",
	     pthread_self(), i+1, myGlobals.device[i].humanFriendlyName, getpid());

  /* Skip ntopSleepUntilStateRUN(), just start processing packets as soon as this starts */

  for(;myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN;) {
#if defined(FREEBSD) && defined(__FreeBSD_cc_version) && (__FreeBSD_cc_version < 500000) && defined(HAVE_PCAP_SETNONBLOCK)
    rc = pcap_dispatch(myGlobals.device[i].pcapPtr, -1, queuePacket, (u_char*)_i);
#else
    rc = pcap_loop(myGlobals.device[i].pcapPtr, -1, queuePacket, (u_char*)_i);
#endif

    if(myGlobals.ntopRunState > FLAG_NTOPSTATE_RUN) break;

    if(rc == -1) {
      if(myGlobals.device[i].name != NULL) /* This is not a shutdown */
	traceEvent(CONST_TRACE_ERROR, "Reading packets on device %d (%s): '%s'",
		   i,
		   myGlobals.device[i].humanFriendlyName,
		   pcap_geterr(myGlobals.device[i].pcapPtr));
      break;
    } else if(rc == 0) {
      if(myGlobals.runningPref.rFileName != NULL) {
	traceEvent(CONST_TRACE_INFO, "pcap_loop (%s) returned %d [No more packets to read]",
		   myGlobals.device[i].humanFriendlyName, rc);
	break; /* No more packets to read */
      }
#if defined(FREEBSD) && defined(__FreeBSD_cc_version) && (__FreeBSD_cc_version < 500000) && defined(HAVE_PCAP_SETNONBLOCK)
      if(myGlobals.runningPref.setNonBlocking == TRUE) {
        /* select returned no data - either a signal or setNonBlock */
        struct timespec sleepAmount;
        sleepAmount.tv_sec = 0; sleepAmount.tv_nsec = CONST_PCAPNONBLOCKING_SLEEP_TIME;
        rc = nanosleep(&sleepAmount, NULL);
        ++setNonBlockingSleepCount;
        if(((setNonBlockingSleepCount < 1000) && (setNonBlockingSleepCount % 250 == 0))
	   || (setNonBlockingSleepCount % 100000 == 0) ){
          traceEvent(CONST_TRACE_NOISY, "NONBLOCK: Sleep count %s %llu",
                     myGlobals.device[i].humanFriendlyName,
                     setNonBlockingSleepCount);
        }
      }
      continue; /* Try again */
#endif
    }
  }

  myGlobals.device[i].pcapDispatchThreadId = 0;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: NPS(%d,%s): pcapDispatch thread terminated [p%d]",
	     pthread_self(), i+1, myGlobals.device[i].humanFriendlyName, getpid());

  return(NULL);
}

/* **************************************** */

#ifndef WIN32
#ifdef HANDLE_DIED_CHILD
RETSIGTYPE handleDiedChild(int sig _UNUSED_) {
  int status;
  pid_t pidId;

  while((pidId = waitpid(-1, &status, WNOHANG)) > 0) {
#ifdef DEBUG
    if(status == 0) {
      myGlobals.numChildren--;
      traceEvent(CONST_TRACE_INFO,
		 "A child has terminated [pid=%d status=%d children=%d]",
		 pidId, status, myGlobals.numChildren);
    }
#endif
  }

#ifdef HANDLE_DIED_CHILD
  signal(SIGCHLD, handleDiedChild);
#endif
}
#endif
#endif

/* **************************************** */


void daemonizeUnderUnix(void) {

#ifndef WIN32
  int childpid;

  signal(SIGHUP, SIG_IGN);
#ifdef HANDLE_DIED_CHILD
  signal(SIGCHLD, handleDiedChild);
#else
  signal(SIGCHLD, SIG_IGN);
#endif
  signal(SIGQUIT, SIG_IGN);

  if((childpid=fork()) < 0)
    traceEvent(CONST_TRACE_ERROR, "INIT: Occurred while daemonizing (errno=%d)", errno);
  else {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: after fork() in %s (%d)",
	       childpid ? "parent" : "child", childpid);
#endif
    if(!childpid) { /* child */
      traceEvent(CONST_TRACE_INFO, "INIT: Bye bye: I'm becoming a daemon...");
      detachFromTerminalUnderUnix(1);
    } else { /* father */
      traceEvent(CONST_TRACE_INFO, "INIT: Parent process is exiting (this is normal)");
      exit(0);
    }
  }

  myGlobals.mainThreadId = pthread_self();
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "THREADMGMT[t%lu]: Now running as a daemon", myGlobals.mainThreadId);

#endif
}

/* **************************************** */

void detachFromTerminalUnderUnix(int doChdir) {

#ifndef WIN32
#ifdef MAKE_WITH_SYSLOG
  /* Child processes must log to syslog.
   * If no facility was set through -L | --use-syslog=facility
   * then force the default
   */
  if(myGlobals.runningPref.useSyslog == FLAG_SYSLOG_NONE)
    myGlobals.runningPref.useSyslog = DEFAULT_SYSLOG_FACILITY;
#endif /* MAKE_WITH_SYSLOG */

  if(doChdir) chdir("/");
  setsid();  /* detach from the terminal */

  fclose(stdin);
  fclose(stdout);
  /* fclose(stderr); */

  /*
   * clear any inherited file mode creation mask
   */
  umask (0);

  /*
   * Use line buffered stdout
   */
  /* setlinebuf (stdout); */
  setvbuf(stdout, (char *)NULL, _IOLBF, 0);

#endif /* WIN32 */

}

/* **************************************** */

static short handleProtocol(char* protoName, char *protocol) {
  int i, idx, lowProtoPort, highProtoPort;
  short printWarnings = 0;
  u_char dummyEntry = 0;

  if(protocol[0] == '\0')
    return(-1);
  else if(isdigit(protocol[0]) || (protocol[0] == '-')) {
    /* numeric protocol port handling */
    lowProtoPort = highProtoPort = 0;
    sscanf(protocol, "%d-%d", &lowProtoPort, &highProtoPort);
    if(highProtoPort < lowProtoPort)
      highProtoPort = lowProtoPort;

    if(lowProtoPort < 0) { lowProtoPort = 0; dummyEntry = 1; /* Dummy entry */ }
    if(highProtoPort >= MAX_IP_PORT) highProtoPort = MAX_IP_PORT-1;

    for(idx=lowProtoPort; idx<= highProtoPort; idx++) {
      if(servicesMapper[idx] == -1) {
	myGlobals.ipPortMapper.numElements++;

#ifdef DEBUG
	printf("[%d] '%s' [port=%d]\n", myGlobals.numIpProtosToMonitor, protoName, idx);
#endif

	if(dummyEntry)
	  servicesMapper[idx] = -myGlobals.numIpProtosToMonitor;
	else
	  servicesMapper[idx] = myGlobals.numIpProtosToMonitor;
      } else if(printWarnings)
	traceEvent(CONST_TRACE_WARNING,
                   "INIT: IP port %d (%s) has been discarded (multiple instances)",
                   idx,
                   protoName);
    }

    return(idx);
  }

  for(i=1; i<myGlobals.numActServices; i++) {
    idx = -1;

    if((myGlobals.udpSvc[i] != NULL) && (strcmp(myGlobals.udpSvc[i]->name, protocol) == 0))
      idx = myGlobals.udpSvc[i]->port;
    else if((myGlobals.tcpSvc[i] != NULL) && (strcmp(myGlobals.tcpSvc[i]->name, protocol) == 0))
      idx = myGlobals.tcpSvc[i]->port;

    if(idx != -1) {
      if(servicesMapper[idx] == -1) {
	myGlobals.ipPortMapper.numElements++;

#ifdef DEBUG
	printf("[%d] '%s' [%s:%d]\n", myGlobals.numIpProtosToMonitor, protoName, protocol, idx);
#endif
	servicesMapper[idx] = myGlobals.numIpProtosToMonitor;
      } else if(printWarnings)
	traceEvent(CONST_TRACE_WARNING, "INIT: Protocol '%s' has been discarded (multiple instances)",
		   protocol);
      return(idx);
    }
  }

  if(printWarnings)
    traceEvent(CONST_TRACE_WARNING, "INIT: Unknown protocol '%s' - it has been ignored",
	       protocol);

  return(-1);
}

/* **************************************** */

static int handleProtocolList(char* protoName, char *protocolList) {
  char tmpStr[255];
  char* lastEntry, *protoEntry;
  int increment=0, rc=0;

  if(servicesMapper == NULL) {
    servicesMapper = (int*)malloc(sizeof(int)*MAX_IP_PORT);
    memset(servicesMapper, -1, sizeof(int)*MAX_IP_PORT);
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "%s - %s", protoName, protocolList);
#endif

  /* The trick below is used to avoid to modify static
     memory like in the case where this function is
     called by addDefaultProtocols()
  */
  lastEntry = strncpy(tmpStr, protocolList, sizeof(tmpStr));

  while((protoEntry  = strchr(lastEntry, '|')) != NULL) {
    protoEntry[0] = '\0';
    rc = handleProtocol(protoName, lastEntry);

    if(rc != -1)
      increment = 1;

    lastEntry = &protoEntry[1];
  }

  if(increment == 1) {
    if(myGlobals.numIpProtosToMonitor == 0)
      myGlobals.ipTrafficProtosNames = (char**)malloc(sizeof(char*));
    else
      myGlobals.ipTrafficProtosNames = (char**)realloc(myGlobals.ipTrafficProtosNames,
						       sizeof(char*)*(myGlobals.numIpProtosToMonitor+1));

    rc = myGlobals.numIpProtosToMonitor;
    myGlobals.ipTrafficProtosNames[myGlobals.numIpProtosToMonitor] = strdup(protoName);
    myGlobals.numIpProtosToMonitor++;
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "%d) %s - %s",
	       myGlobals.numIpProtosToMonitor, protoName, protocolList);
#endif
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "handleProtocolList(%s) = %d", protoName, rc);
#endif

  return(rc);
}

/* **************************************** */

void addNewIpProtocolToHandle(char* name, u_int16_t id, u_int16_t idAlias) {
  ProtocolsList *proto = myGlobals.ipProtosList;
  int i;

  while(proto != NULL) {
    if(proto->protocolId == id) return; /* Already there */
    proto = proto->next;
  }

  proto = calloc(1, sizeof(ProtocolsList));
  proto->next = myGlobals.ipProtosList;
  proto->protocolName = strdup(name);
  proto->protocolId = id, proto->protocolIdAlias = idAlias;
  myGlobals.ipProtosList = proto;
  myGlobals.numIpProtosList++;

  for(i=0; i<myGlobals.numDevices; i++)
    createDeviceIpProtosList(i);
}

/* **************************************** */

void createPortHash(void) {
  int theSize, i;

  /*
    At this point in time servicesMapper contains all
    the port data hence we can transform it from
    an array to a hash table.
  */
  myGlobals.ipPortMapper.numSlots = 2*myGlobals.ipPortMapper.numElements;
  theSize = sizeof(PortProtoMapper)*2*myGlobals.ipPortMapper.numSlots;
  myGlobals.ipPortMapper.theMapper = (PortProtoMapper*)malloc(theSize);
  memset(myGlobals.ipPortMapper.theMapper, 0, theSize);
  for(i=0; i<myGlobals.ipPortMapper.numSlots; i++) myGlobals.ipPortMapper.theMapper[i].portProto = -1;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Allocating %d slots", myGlobals.ipPortMapper.numSlots);
#endif

  for(i=0; i<MAX_IP_PORT; i++) {
    if(servicesMapper[i] != -1) {
      int slotId = (3*i) % myGlobals.ipPortMapper.numSlots;

      while(myGlobals.ipPortMapper.theMapper[slotId].portProto != -1)
	slotId = (slotId+1) % myGlobals.ipPortMapper.numSlots;

#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "Mapping port %d to slotId %d", i, slotId);
#endif

      if(servicesMapper[i] < 0) {
	servicesMapper[i] = -servicesMapper[i];
	myGlobals.ipPortMapper.theMapper[slotId].dummyEntry = 1;
      } else
	myGlobals.ipPortMapper.theMapper[slotId].dummyEntry = 0;

      myGlobals.ipPortMapper.theMapper[slotId].portProto = i;
      myGlobals.ipPortMapper.theMapper[slotId].mappedPortProto = servicesMapper[i];
    }
  }

  free(servicesMapper);
}

/* **************************************** */

void handleProtocols(void) {
  char *proto, *buffer=NULL, *strtokState, *bufferCurrent, *bufferWork;
  FILE *fd;

  /* myGlobals.protoSpecs is either
     1) a list in the form proto=port[|port][,...]
     2) the name of a file containing a list in the same format.
     Modification:  Allow the file to have multiple lines, each in
     the "standard" format.
     Also, ignore standard Linux comments...
  */

  if((!myGlobals.runningPref.protoSpecs)
     || (!myGlobals.runningPref.protoSpecs[0]))
    return;

  fd = fopen(myGlobals.runningPref.protoSpecs, "rb");

  if(fd == NULL) {
    traceEvent(CONST_TRACE_INFO, "PROTO_INIT: Processing protocol list: '%s'", myGlobals.runningPref.protoSpecs);
    proto = strtok_r(myGlobals.runningPref.protoSpecs, ",", &strtokState);
  } else {
    struct stat buf;

    if(stat(myGlobals.runningPref.protoSpecs, &buf) != 0) {
      fclose(fd);
      traceEvent(CONST_TRACE_ERROR, "PROTO_INIT: Unable to get information about file '%s'",
		 myGlobals.runningPref.protoSpecs);
      return;
    }

    bufferCurrent = buffer = (char*)malloc(buf.st_size+8) /* just to be safe */;

    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "PROTO_INIT: Processing protocol file: '%s', size: %ld",
	       myGlobals.runningPref.protoSpecs, (long)(buf.st_size+8));

    for (;;) {
      bufferCurrent = fgets(bufferCurrent, buf.st_size, fd);
      /* On EOF, we're finished */
      if(bufferCurrent == NULL) {
	break;
      }

      /* otherwise, bufferCurrent points to the just read line in the file,
	 of the form:
	 [protocol=protocol[|protocol][,]] [# comment]
      */

      /* Strip out any comments */
      bufferWork = strchr(bufferCurrent, '#');
      if(bufferWork != NULL) {
	bufferWork[0] = '\n';
	bufferWork[1] = '\0';
      }

      /*
	Replace the \n by a comma, so at the end the buffer will
	look indistinguishable from a single line file...
      */
      bufferWork = strchr(bufferCurrent, '\n');
      if(bufferWork != NULL) {
	bufferWork[0] = ',';
	bufferWork[1] = '\0';
      }

      /* Move pointer to end-of-string for read of next line */
      bufferCurrent = strchr(bufferCurrent, '\0');
    }

    fclose(fd);

    /* remove trailing carriage return */
    if(buffer[strlen(buffer)-1] == '\n')
      buffer[strlen(buffer)-1] = 0;

    proto = strtok_r(buffer, ",", &strtokState);
  }

  while(proto != NULL) {
    char* protoName = strchr(proto, '=');

    if(protoName == NULL)
      traceEvent(CONST_TRACE_INFO,
		 "PROTO_INIT: Unknown protocol '%s'. It has been ignored",
		 proto);
    else {
      char tmpStr[255];
      int len;

      protoName[0] = '\0';
      memset(tmpStr, 0, sizeof(tmpStr));
      strncpy(tmpStr, &protoName[1], sizeof(tmpStr));
      len = strlen(tmpStr);

      if(tmpStr[len-1] != '|') {
	/* Make sure that the string ends with '|' */
	tmpStr[len] = '|';
	tmpStr[len+1] = '\0';
      }

#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "          %30s %s", proto, tmpStr);
#endif

      handleProtocolList(proto, tmpStr);

    }
    proto = strtok_r(NULL, ",", &strtokState);
  }

  if(buffer !=NULL)
    free(buffer);
}

/* **************************************** */

void addDefaultProtocols(void) {
  myGlobals.FTPIdx = handleProtocolList("FTP",      "ftp|ftp-data|");
  handleProtocolList("HTTP",     "http|www|https|3128|"); /* 3128 is HTTP cache */
  handleProtocolList("DNS",      "name|domain|");
  handleProtocolList("Telnet",   "telnet|login|");
  handleProtocolList("NBios-IP", "netbios-ns|netbios-dgm|netbios-ssn|");
  handleProtocolList("Mail",     "pop-2|pop-3|pop3|kpop|smtp|imap|imap2|");
  handleProtocolList("DHCP-BOOTP", "67-68|");
  handleProtocolList("SNMP",     "snmp|snmp-trap|");
  handleProtocolList("NNTP",     "nntp|");
  handleProtocolList("NFS/AFS",      "mount|pcnfs|bwnfs|nfsd|nfs|nfsd-status|7000-7009");
  myGlobals.VoipIdx = handleProtocolList("VoIP", "5060|2000|54045|"); /* 54045 = Skype default port */
  handleProtocolList("X11",      "6000-6010|");
  /* 22 == ssh (just to make sure the port is defined) */
  handleProtocolList("SSH",      "22|");

  /* Peer-to-Peer Protocols */
  myGlobals.GnutellaIdx = handleProtocolList("Gnutella", "6346|6347|6348|");
  myGlobals.KazaaIdx = handleProtocolList("Kazaa",       "1214|");
  myGlobals.WinMXIdx = handleProtocolList("WinMX",       "6699|7730|");
  myGlobals.DirectConnectIdx = handleProtocolList("DC++", "-1|"); /* Dummy port as this is a pure P2P protocol */
  myGlobals.EdonkeyIdx = handleProtocolList("eDonkey", "4661-4665|");
  myGlobals.BitTorrentIdx = handleProtocolList("BitTorrent", "6881-6999|6969|"); /* http://www.dessent.net/btfaq/#ports */
  handleProtocolList("Messenger", "1863|5000|5001|5190-5193|");
}

/* **************************************** */

int mapGlobalToLocalIdx(int port) {
  if((port < 0) || (port >= MAX_IP_PORT))
    return(-1);
  else {
    int j, found, slotId = (3*port) % myGlobals.ipPortMapper.numSlots;

    for(j=0, found=0; j<myGlobals.ipPortMapper.numSlots; j++) {
      if(myGlobals.ipPortMapper.theMapper[slotId].dummyEntry == 0) {
	if(myGlobals.ipPortMapper.theMapper[slotId].portProto == -1)
	  break;
	else if(myGlobals.ipPortMapper.theMapper[slotId].portProto == port) {
	  found = 1;
	  break;
	}
      }

      slotId = (slotId+1) % myGlobals.ipPortMapper.numSlots;
    }

    if(found)
      return(myGlobals.ipPortMapper.theMapper[slotId].mappedPortProto);
    else
      return(-1);
  }
}

/* **************************************** */

static void purgeIpPorts(int theDevice) {
  int i;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Calling purgeIpPorts(%d)", theDevice);
#endif

  if(myGlobals.device[myGlobals.actualReportDeviceId].numHosts == 0) return;

  accessMutex(&myGlobals.purgePortsMutex, "purgeIpPorts");

  for(i=1; i<MAX_IP_PORT; i++) {
    if(myGlobals.device[theDevice].ipPorts[i] != NULL) {
      free(myGlobals.device[theDevice].ipPorts[i]);
      myGlobals.device[theDevice].ipPorts[i] = NULL;
    }
  }

  releaseMutex(&myGlobals.purgePortsMutex);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "purgeIpPorts(%d) completed", theDevice);
#endif
}

/* **************************************** */


void* scanIdleLoop(void* notUsed _UNUSED_) {

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: SIH: Idle host scan thread starting [p%d]",
             pthread_self(), getpid());

  ntopSleepUntilStateRUN();
 
  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: SIH: Idle host scan thread running [p%d]",
             pthread_self(), getpid());

  for(;;) {
    int i, purged=0;

    ntopSleepWhileSameState(60 /* do not change */);
    if(myGlobals.ntopRunState > FLAG_NTOPSTATE_RUN) break;

    if(myGlobals.runningPref.rFileName == NULL)
      myGlobals.actTime = time(NULL);

    for(i=0; i<myGlobals.numDevices; i++)
      if(!myGlobals.device[i].virtualDevice) {
        if(!myGlobals.runningPref.stickyHosts) purged += purgeIdleHosts(i);
#if !defined(__FreeBSD__)
	purgeIpPorts(i);
#endif

	ntop_conditional_sched_yield(); /* Allow other threads to run */
      }

    updateThpt(1);
  }

  myGlobals.scanIdleThreadId = 0;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: SIH: Idle host scan thread terminated [p%d]",
             pthread_self(), getpid());

  return(NULL);
}

/* **************************************** */

void* scanFingerprintLoop(void* notUsed _UNUSED_) {
  HostTraffic *el;
  int deviceId, countScan, countResolved, countCycle;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: SFP: Fingerprint scan thread starting [p%d]",
             pthread_self(), getpid());

  countCycle=0;

  ntopSleepUntilStateRUN();

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: SFP: Fingerprint scan thread running [p%d]",
             pthread_self(), getpid());

  for(;;) {
    countScan=0;
    countResolved=0;

    myGlobals.nextFingerprintScan = time(NULL) + CONST_FINGERPRINT_LOOP_INTERVAL;

    ntopSleepWhileSameState(CONST_FINGERPRINT_LOOP_INTERVAL);
    if(myGlobals.ntopRunState > FLAG_NTOPSTATE_RUN) break;
    
    if(myGlobals.runningPref.rFileName == NULL)
      myGlobals.actTime = time(NULL);
    countCycle++;
#ifdef FINGERPRINT_DEBUG
    traceEvent(CONST_TRACE_NOISY, "FINGERPRINT_DEBUG: starting cycle %d", countCycle);
#endif

    for(deviceId=0; deviceId<myGlobals.numDevices; deviceId++) {
      for(el=getFirstHost(deviceId); el != NULL; el = getNextHost(deviceId, el)) {
        if(el->fingerprint == NULL) continue;
        if(el->fingerprint[0] == ':') continue;
        if(addrnull(&el->hostIpAddress)) continue;
        if(el->hostNumIpAddress[0] == '\0') continue;
        countScan++;
        setHostFingerprint(el);
        if((el->fingerprint[0] == ':') && (el->fingerprint[0] != '\0')) countResolved++;
      }

      ntop_conditional_sched_yield(); /* Allow other threads to run */

    }

    if(countScan > 0)
      traceEvent(CONST_TRACE_NOISY, "SFP: Ending fingerprint scan cycle %d - checked %d, resolved %d",
                 countCycle, countScan, countResolved);

  }

  myGlobals.nextFingerprintScan = 0;
  myGlobals.scanFingerprintsThreadId = 0;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: SFP: Fingerprint scan thread terminated [p%d]",
             pthread_self(), getpid());

  return(NULL);
}

/* **************************************** */

static void cleanupThreadIs(char *buf, int sizeofbuf) {
  int i;

  buf[0]='\0';

  if(pthread_self() == myGlobals.mainThreadId)
    strncpy(buf, "MAIN", sizeofbuf);
  else if(pthread_self() == myGlobals.dequeueThreadId)
    strncpy(buf, "NPA", sizeofbuf);
  else if(pthread_self() == myGlobals.scanFingerprintsThreadId)
    strncpy(buf, "SFP", sizeofbuf);
  else if(pthread_self() == myGlobals.scanIdleThreadId)
    strncpy(buf, "SIH", sizeofbuf);
  else if(pthread_self() == myGlobals.handleWebConnectionsThreadId)
    strncpy(buf, "WEB", sizeofbuf);

#if defined(HAVE_OPENSSL) && defined(MAKE_WITH_SSLWATCHDOG)
  else if(pthread_self() == myGlobals.sslwatchdogChildThreadId)
    strncpy(buf, "SSL", sizeofbuf);
#endif

  else
    for(i=0; i<myGlobals.numDequeueThreads; i++) {
      if(pthread_self() == myGlobals.dequeueAddressThreadId[i]) {
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "DNSAR%d", i+1);
        break;
      }
    }

  if(buf[0] == '\0') {
    for(i=0; i<myGlobals.numDevices; i++) {
      if(pthread_self() == myGlobals.device[i].pcapDispatchThreadId) {
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "NPS%d", i+1);
        break;
      }
    }
  }

  if(buf[0] == '\0') {
    for(i=0; i<myGlobals.numDevices; i++) {
      if((myGlobals.device[i].netflowGlobals != NULL) &&
         (pthread_self() == myGlobals.device[i].netflowGlobals->netFlowThread)) {
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "NF%d", i);
        break;
      }
    }
  }

  if(buf[0] == '\0') {
    for(i=0; i<myGlobals.numDevices; i++) {
      if((myGlobals.device[i].sflowGlobals != NULL) &&
         (pthread_self() == myGlobals.device[i].sflowGlobals->sflowThread)) {
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "SF%d", i);
        break;
      }
    }
  }

  if(buf[0] == '\0') {
    strncpy(buf, "unknown", sizeofbuf);
  }
}

/* *************************** */

void runningThreads(char *buf, int sizeofbuf, int do_join) {
  char buf2[LEN_SMALL_WORK_BUFFER];
  int i;

  if(!do_join) {
    memset(&buf2, 0, sizeof(buf2));
    
#if defined(HAVE_OPENSSL) && defined(MAKE_WITH_SSLWATCHDOG)
    safe_snprintf(__FILE__, __LINE__, buf, sizeofbuf, "%s%s%s%s%s", 
		  myGlobals.dequeueThreadId != 0 ? " NPA" : "",
		  myGlobals.scanFingerprintsThreadId != 0 ? " SFP" : "",
		  myGlobals.scanIdleThreadId != 0 ? " SIH" : "",
		  myGlobals.handleWebConnectionsThreadId != 0 ? " WEB" : "",
		  myGlobals.sslwatchdogChildThreadId != 0 ? " SSL" : "");
#else
    safe_snprintf(__FILE__, __LINE__, buf, sizeofbuf, "%s%s%s%s", 
		  myGlobals.dequeueThreadId != 0 ? " NPA" : "",
		  myGlobals.scanFingerprintsThreadId != 0 ? " SFP" : "",
		  myGlobals.scanIdleThreadId != 0 ? " SIH" : "",
		  myGlobals.handleWebConnectionsThreadId != 0 ? " WEB" : "");
#endif

  }

  for(i=0; i<myGlobals.numDequeueThreads; i++) {
    if((myGlobals.dequeueAddressThreadId[i] != 0) 
       && (myGlobals.dequeueAddressThreadId[i] != (pthread_t)-1)) {
      if(!do_join) {
	safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), " DNSAR%d", i+1);
	safe_strncat(buf, sizeofbuf, buf2);
      } else {
	/* Wake up thread */
	signalCondvar(&myGlobals.queueCondvar);
	signalCondvar(&myGlobals.queueAddressCondvar);
	if(joinThread(&myGlobals.dequeueAddressThreadId[i]) != 0)
	  traceEvent(CONST_TRACE_INFO, "joinThread() returned %s", strerror(errno));
      }
    }
  }

  if(myGlobals.device != NULL) {
    for(i=0; i<myGlobals.numDevices; i++) {
      if((myGlobals.device[i].pcapDispatchThreadId != 0) &&
         (!myGlobals.device[i].virtualDevice) &&
         (!myGlobals.device[i].dummyDevice) &&
         (myGlobals.device[i].pcapPtr != NULL)) {
	if(!do_join) {
	  safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), " NPS%d", i+1);
	  safe_strncat(buf, sizeofbuf, buf2);
	} else {
	  struct pcap_stat pcapStats;

	  if(pcap_stats(myGlobals.device[i].pcapPtr, &pcapStats) >= 0) {
	    traceEvent(CONST_TRACE_INFO, "STATS: %s packets received by filter on %s",
		       formatPkts((Counter)pcapStats.ps_recv, buf2, sizeof(buf2)), myGlobals.device[i].name);
	    
	    traceEvent(CONST_TRACE_INFO, "STATS: %s packets dropped (according to libpcap)",
		       formatPkts((Counter)pcapStats.ps_drop, buf2, sizeof(buf2)));
	  }
	  traceEvent(CONST_TRACE_INFO, "STATS: %s packets dropped (by ntop)",
		     formatPkts(myGlobals.device[i].droppedPkts.value, buf2, sizeof(buf2)));	
	  
	  pcap_close(myGlobals.device[i].pcapPtr);
	  if(joinThread(&myGlobals.device[i].pcapDispatchThreadId) != 0)
	    traceEvent(CONST_TRACE_INFO, "joinThread() returned %s", strerror(errno));
	}
      }
    }

    for(i=0; i<myGlobals.numDevices; i++) {
      if((myGlobals.device[i].netflowGlobals != NULL) &&
         (myGlobals.device[i].netflowGlobals->netFlowThread != 0)) {
        if(!do_join) {
	  safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), " NF%d", i);
	  safe_strncat(buf, sizeofbuf, buf2);
	} else {
	  if(joinThread(&myGlobals.device[i].netflowGlobals->netFlowThread) != 0)
	    traceEvent(CONST_TRACE_INFO, "joinThread() returned %s", strerror(errno));
	}
      }
    }

    for(i=0; i<myGlobals.numDevices; i++) {
      if((myGlobals.device[i].sflowGlobals != NULL) &&
         (myGlobals.device[i].sflowGlobals->sflowThread != 0)) {
        if(!do_join) {
	  safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), " SF%d", i);
	  safe_strncat(buf, sizeofbuf, buf2);
	} else {
	  if(joinThread(&myGlobals.device[i].sflowGlobals->sflowThread) != 0)
	    traceEvent(CONST_TRACE_INFO, "joinThread() returned %s", strerror(errno));
	}
      }
    }
  }
}

/* **************************************** */

/* Report statistics and write out the raw packet file */
RETSIGTYPE cleanup(int signo) {
  struct pcap_stat pcapStats;
  int i, j;
  char buf[128];
  
  if(myGlobals.ntopRunState <= FLAG_NTOPSTATE_SHUTDOWN) {
    traceEvent(CONST_TRACE_INFO, "CLEANUP[t%lu]: ntop caught signal %d", pthread_self(), signo);
  }

#ifdef HAVE_BACKTRACE
  if(signo == SIGSEGV) {
    void *array[20];
    size_t size;
    char **strings;

    /* Don't double fault... */
    signal(SIGSEGV, SIG_DFL);

    /* Grab the backtrace before we do much else... */
    size = backtrace(array, 20);
    strings = (char**)backtrace_symbols(array, size);

    traceEvent(CONST_TRACE_ERROR, "BACKTRACE: *****ntop error: Signal(%d)", signo);

    traceEvent(CONST_TRACE_ERROR, "BACKTRACE:     backtrace is:");
    if(size < 2) {
      traceEvent(CONST_TRACE_ERROR, "BACKTRACE:         **unavailable!");
    } else {
      /* Ignore the 0th entry, that's our cleanup() */
      for (i=1; i<size; i++) {
	traceEvent(CONST_TRACE_ERROR, "BACKTRACE:          %2d. %s", i, strings[i]);
      }
    }
  }
#endif /* HAVE_BACKTRACE */

  if(myGlobals.ntopRunState >= FLAG_NTOPSTATE_SHUTDOWN) {
    return;
  }

  if(myGlobals.ntopRunState != FLAG_NTOPSTATE_SHUTDOWNREQ) {
    /* TODO
     * If the web server didn't start this, how do we kill it?
     * It's sitting there in select() waiting for input!
     */
  }

  setRunState(FLAG_NTOPSTATE_SHUTDOWN);


  cleanupThreadIs(buf, sizeof(buf));
  traceEvent(CONST_TRACE_INFO, "CLEANUP[t%lu] catching thread is %s", pthread_self(), buf);

  runningThreads(buf, sizeof(buf), 0);
  traceEvent(CONST_TRACE_INFO, "CLEANUP: Running threads%s", buf);
  runningThreads(buf, sizeof(buf), 1);

#ifndef WIN32

#ifdef MAKE_WITH_SSLWATCHDOG
  if(myGlobals.sslwatchdogChildThreadId != 0) {
    killThread(&myGlobals.sslwatchdogChildThreadId);
  }
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  if(myGlobals.runningPref.useSSLwatchdog == 1)
#endif
    {
      deleteCondvar(&myGlobals.sslwatchdogCondvar);
    }
#endif

#endif /* #ifndef WIN32 */

  killThread(&myGlobals.handleWebConnectionsThreadId);
  killThread(&myGlobals.scanIdleThreadId);
  killThread(&myGlobals.scanFingerprintsThreadId);

  /* Prevents the web interface from running */
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "CLEANUP: Locking purge mutex (may block for a little while)");
  accessMutex(&myGlobals.purgeMutex, "cleanup");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "CLEANUP: Locked purge mutex, continuing shutdown");

  runningThreads(buf, sizeof(buf), 0);
  traceEvent(CONST_TRACE_INFO, "CLEANUP: Continues%s%s%s", 
             buf[0] == '\0' ? "" : " (still running",
             buf,
             buf[0] == '\0' ? "" : ")");

  for(i=0; i<myGlobals.numDevices; i++) {
    freeHostInstances(i);

    while(myGlobals.device[i].fragmentList != NULL) {
      IpFragment *fragment = myGlobals.device[i].fragmentList->next;
      free(myGlobals.device[i].fragmentList);
      myGlobals.device[i].fragmentList = fragment;
    }
  }

  for(i=0; i<myGlobals.hostsCacheLen; i++)
    free(myGlobals.hostsCache[i]);
  myGlobals.hostsCacheLen = 0;

  unloadPlugins();

  (void)fflush(stdout);

  termIPServices();
  termIPSessions();
  termPassiveSessions();

#ifndef WIN32
  endservent();
#endif

  tryLockMutex(&myGlobals.packetProcessMutex, "cleanup");
  deleteMutex(&myGlobals.packetProcessMutex);
  tryLockMutex(&myGlobals.packetQueueMutex, "cleanup");
  deleteMutex(&myGlobals.packetQueueMutex);
  if(myGlobals.runningPref.numericFlag == 0) {
    tryLockMutex(&myGlobals.addressResolutionMutex, "cleanup");
    deleteMutex(&myGlobals.addressResolutionMutex);
  }
  
  for(i=0; i<CONST_HASH_INITIAL_SIZE; i++) {
    tryLockMutex(&myGlobals.hostsHashMutex[i], "cleanup");
    deleteMutex(&myGlobals.hostsHashMutex[i]);
  }

  deleteCondvar(&myGlobals.queueCondvar);
  deleteCondvar(&myGlobals.queueAddressCondvar);

  termGdbm();

  tryLockMutex(&myGlobals.gdbmMutex, "cleanup");
  deleteMutex(&myGlobals.gdbmMutex);
  tryLockMutex(&myGlobals.purgeMutex, "cleanup");
  deleteMutex(&myGlobals.purgeMutex);

  for(i=0; i<myGlobals.numDevices; i++) {

    traceEvent(CONST_TRACE_INFO, "CLEANUP: Freeing device %s (idx=%d)", myGlobals.device[i].name, i);

    if(myGlobals.device[i].ipTrafficMatrix != NULL) {
      /* Courtesy of Wies-Software <wies@wiessoft.de> */
      for(j=0; j<(myGlobals.device[i].numHosts*myGlobals.device[i].numHosts); j++)
        if(myGlobals.device[i].ipTrafficMatrix[j] != NULL)
	  free(myGlobals.device[i].ipTrafficMatrix[j]);

      free(myGlobals.device[i].ipTrafficMatrix);
    }

    if(myGlobals.device[i].ipTrafficMatrixHosts != NULL)
      free(myGlobals.device[i].ipTrafficMatrixHosts);

    if(myGlobals.device[i].ipProtoStats != NULL)
      free(myGlobals.device[i].ipProtoStats);

    if(myGlobals.device[i].ipProtosList != NULL)
      free(myGlobals.device[i].ipProtosList);

    if(myGlobals.device[i].hash_hostTraffic != NULL)
      free(myGlobals.device[i].hash_hostTraffic);

    if(myGlobals.device[i].ipPorts != NULL) {
      int port;

      for(port=0; port<MAX_IP_PORT; port++)
	if(myGlobals.device[i].ipPorts[port] != NULL)
	  free(myGlobals.device[i].ipPorts[port]);
    }


    accessMutex(&myGlobals.tcpSessionsMutex, "cleanup");
    if(myGlobals.device[i].tcpSession != NULL)
      free(myGlobals.device[i].tcpSession);
    releaseMutex(&myGlobals.tcpSessionsMutex);

    free(myGlobals.device[i].humanFriendlyName);
    free(myGlobals.device[i].name);

    if(myGlobals.device[i].pcapDumper != NULL)
      pcap_dump_close(myGlobals.device[i].pcapDumper);

    if(myGlobals.device[i].pcapErrDumper != NULL)
      pcap_dump_close(myGlobals.device[i].pcapErrDumper);

    if(myGlobals.device[i].pcapOtherDumper != NULL)
      pcap_dump_close(myGlobals.device[i].pcapOtherDumper);

#ifdef INET6
    {
      NtopIfaceAddr * tmp;
      while(myGlobals.device[i].v6Addrs) {
        tmp=myGlobals.device[i].v6Addrs;
        myGlobals.device[i].v6Addrs=myGlobals.device[i].v6Addrs->next;
        free(tmp);
      }
    }
#endif

  }

  if(myGlobals.device)
    free(myGlobals.device);

  if(myGlobals.broadcastEntry != NULL) free(myGlobals.broadcastEntry);
  if(myGlobals.otherHostEntry != NULL) {
    if(myGlobals.otherHostEntry->portsUsage != NULL) 
      freePortsUsage(myGlobals.otherHostEntry);
    myGlobals.otherHostEntry->portsUsage = NULL;
    free(myGlobals.otherHostEntry);
  }

  if(myGlobals.startedAs != NULL) free(myGlobals.startedAs);

  tryLockMutex(&myGlobals.tcpSessionsMutex, "cleanup");
  deleteMutex(&myGlobals.tcpSessionsMutex);
  tryLockMutex(&myGlobals.purgePortsMutex, "cleanup");
  deleteMutex(&myGlobals.purgePortsMutex);
  tryLockMutex(&myGlobals.securityItemsMutex, "cleanup");
  deleteMutex(&myGlobals.securityItemsMutex);
  /* DO NOT DO deleteMutex(&myGlobals.logViewMutex); - need it for the last traceEvent()s */

  if(myGlobals.logView != NULL) {
    for(i=0; i<CONST_LOG_VIEW_BUFFER_SIZE; i++)
      if(myGlobals.logView[i] != NULL)
	free(myGlobals.logView[i]);
    free(myGlobals.logView);
  }

#ifdef WIN32
  termWinsock32();
#endif

  for(i=0; i<myGlobals.numIpProtosToMonitor; i++)
    free(myGlobals.ipTrafficProtosNames[i]);

  if(myGlobals.ipTrafficProtosNames) free(myGlobals.ipTrafficProtosNames);
  if(myGlobals.ipPortMapper.theMapper) free(myGlobals.ipPortMapper.theMapper);

  if(myGlobals.runningPref.currentFilterExpression != NULL)
    free(myGlobals.runningPref.currentFilterExpression);

  if(myGlobals.runningPref.localAddresses != NULL)
    free(myGlobals.runningPref.localAddresses);
#ifndef WIN32
  if(myGlobals.effectiveUserName != NULL) free(myGlobals.effectiveUserName);
#endif
  if(myGlobals.runningPref.devices != NULL) free(myGlobals.runningPref.devices);

  /* One day we should free myGlobals.countryFlagHead */

  free(myGlobals.runningPref.pcapLogBasePath);
  /* free(myGlobals.dbPath); -- later, need this to remove pid */
  if(myGlobals.spoolPath) free(myGlobals.spoolPath);
  if(myGlobals.rrdPath != NULL)
    free(myGlobals.rrdPath);
  
  if(myGlobals.gdVersionGuessValue != NULL)
    free(myGlobals.gdVersionGuessValue);
  
#if defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 1)
  traceEvent(CONST_TRACE_INFO, "===================================");
  muntrace();
  traceEvent(CONST_TRACE_INFO, "===================================");
#elif defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 3)
  traceEvent(CONST_TRACE_INFO, "===================================");
  termLeaks();
  traceEvent(CONST_TRACE_INFO, "===================================");
#endif

#ifndef WIN32
  removeNtopPid();
#endif
  free(myGlobals.dbPath);

  traceEvent(CONST_TRACE_INFO, "CLEANUP: Clean up complete");
  setRunState(FLAG_NTOPSTATE_TERM);
  /* Above should be enough to let main.c routine finish us off ... but just in case */

  memset(&buf, 0, sizeof(buf));
  runningThreads(buf, sizeof(buf), 0);
  if(buf[0] != '\0') 
    traceEvent(CONST_TRACE_INFO, "CLEANUP[t%lu]: Still running threads%s", pthread_self(), buf);

  traceEvent(CONST_TRACE_INFO, "===================================");
  traceEvent(CONST_TRACE_INFO, "        ntop is shutdown...        ");
  traceEvent(CONST_TRACE_INFO, "===================================");

  exit(0);
}

