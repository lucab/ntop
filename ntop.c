/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
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


static int *servicesMapper = NULL; /* temporary value */

/* *************************** */

#ifdef CFG_MULTITHREADED
static void printMutexInfo(PthreadMutex *mutexId, char *mutexName) {

  traceEvent(CONST_TRACE_INFO, "%s is %s (last lock %s:%d) [max lock time %s:%d (%d sec)]",
	     mutexName,
	     mutexId->isLocked ? "*locked*" : "unlocked",
	     mutexId->lockFile, mutexId->lockLine,
	     mutexId->maxLockedDurationUnlockFile,
	     mutexId->maxLockedDurationUnlockLine,
	     mutexId->maxLockedDuration);
}
#endif

#ifndef WIN32
void handleSigHup(int signalId _UNUSED_) {
#ifdef CFG_MULTITHREADED
  traceEvent(CONST_TRACE_INFO, "========================================");
   printMutexInfo(&myGlobals.gdbmMutex, "myGlobals.gdbmMutex");
   printMutexInfo(&myGlobals.packetProcessMutex, "myGlobals.packetProcessMutex");
   printMutexInfo(&myGlobals.packetQueueMutex, "myGlobals.packetQueueMutex");

#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
   if(myGlobals.numericFlag == 0)
     printMutexInfo(&myGlobals.addressResolutionMutex, "myGlobals.addressResolutionMutex");
#endif

   printMutexInfo(&myGlobals.hostsHashMutex, "myGlobals.hostsHashMutex");
  traceEvent(CONST_TRACE_INFO, "========================================");
#endif /* CFG_MULTITHREADED */

  (void)signal(SIGHUP,  handleSigHup);
}

#endif /* WIN32 */

/* *************************** */

#ifdef CFG_MULTITHREADED
void* pcapDispatch(void *_i) {
  int rc;
  int i = (int)_i;
  struct pcap_stat pcapStats;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: pcap dispatch thread running...");

  /* Reset stats before to start */
  pcap_stats(myGlobals.device[i].pcapPtr, &pcapStats);

  for(;myGlobals.capturePackets == FLAG_NTOPSTATE_RUN;) {
    HEARTBEAT(2, "pcapDispatch()", NULL);
    rc = pcap_dispatch(myGlobals.device[i].pcapPtr, 1, queuePacket, (u_char*)_i);
    
    if(rc == -1) {
      traceEvent(CONST_TRACE_ERROR, "Reading packets on device %d(%s): '%s'",
		 i,
		 myGlobals.device[i].name,
		 pcap_geterr(myGlobals.device[i].pcapPtr));
      break;
    } else if((rc == 0) && (myGlobals.rFileName != NULL)) {
      traceEvent(CONST_TRACE_INFO, "pcap_dispatch returned %d [No more packets to read]", rc);
      break; /* No more packets to read */
    } else {
    }
  }

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: pcap dispatch thread terminated...");
  return(NULL); 
}
#endif /* CFG_MULTITHREADED */

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

#ifndef WIN32

void daemonize(void) {
  int childpid;

  signal(SIGHUP, SIG_IGN);
#ifndef WIN32
#ifdef HANDLE_DIED_CHILD
  signal(SIGCHLD, handleDiedChild);
#else
  signal(SIGCHLD, SIG_IGN);
#endif
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
      detachFromTerminal(1);
    } else { /* father */
      traceEvent(CONST_TRACE_INFO, "INIT: Parent process is exiting (this is normal)");
      exit(0);
    }
  }
}

/* **************************************** */

void detachFromTerminal(int doChdir) {
#ifndef CFG_MULTITHREADED
  alarm(120); /* Don't freeze */
#endif

#if !defined(WIN32) && defined(MAKE_WITH_SYSLOG)
  /* Child processes must log to syslog.
   * If no facility was set through -L | --use-syslog=facility
   * then force the default
   */
  if(myGlobals.useSyslog == FLAG_SYSLOG_NONE)
    myGlobals.useSyslog = DEFAULT_SYSLOG_FACILITY;
#endif

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
   * Use linebuffered stdout
   */
  /* setlinebuf (stdout); */
  setvbuf(stdout, (char *)NULL, _IOLBF, 0);

}
#endif /* WIN32 */

/* **************************************** */

static short handleProtocol(char* protoName, char *protocol) {
  int i, idx, lowProtoPort, highProtoPort;
  short printWarnings = 0;

  if(protocol[0] == '\0')
    return(-1);
  else if(isdigit(protocol[0])) {
    /* numeric protocol port handling */
    lowProtoPort = highProtoPort = 0;
    sscanf(protocol, "%d-%d", &lowProtoPort, &highProtoPort);
    if(highProtoPort < lowProtoPort)
      highProtoPort = lowProtoPort;

    if(lowProtoPort < 0) lowProtoPort = 0;
    if(highProtoPort >= MAX_IP_PORT) highProtoPort = MAX_IP_PORT-1;

    for(idx=lowProtoPort; idx<= highProtoPort; idx++) {
      if(servicesMapper[idx] == -1) {
	myGlobals.ipPortMapper.numElements++;

#ifdef DEBUG
	printf("[%d] '%s' [port=%d]\n", myGlobals.numIpProtosToMonitor, protoName, idx);
#endif
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
	  myGlobals.protoIPTrafficInfos = (char**)malloc(sizeof(char*));
      else
	  myGlobals.protoIPTrafficInfos = (char**)realloc(myGlobals.protoIPTrafficInfos, 
							  sizeof(char*)*(myGlobals.numIpProtosToMonitor+1));
      
      rc = myGlobals.numIpProtosToMonitor;
      myGlobals.protoIPTrafficInfos[myGlobals.numIpProtosToMonitor] = strdup(protoName);
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

void addNewIpProtocolToHandle(char* name, 
			      u_int16_t id, 
			      u_int16_t idAlias) {
  ProtocolsList *proto = myGlobals.ipProtosList;
  int i;

  while(proto != NULL) {
    if(proto->protocolId == id) return; /* Already there */
    proto = proto->next;
  }

  proto = malloc(sizeof(ProtocolsList));
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

  if((!myGlobals.protoSpecs)
      || (!myGlobals.protoSpecs[0]))
    return;

  fd = fopen(myGlobals.protoSpecs, "rb");

  if(fd == NULL) {
    traceEvent(CONST_TRACE_INFO, "PROTO_INIT: Processing protocol list: '%s'", myGlobals.protoSpecs);
    proto = strtok_r(myGlobals.protoSpecs, ",", &strtokState);
  } else {
    struct stat buf;

    if(stat(myGlobals.protoSpecs, &buf) != 0) {
      fclose(fd);
      traceEvent(CONST_TRACE_ERROR, "PROTO_INIT: Unable to get information about file '%s'", 
		 myGlobals.protoSpecs);
      return;
    }

    bufferCurrent = buffer = (char*)malloc(buf.st_size+8) /* just to be safe */;

    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "PROTO_INIT: Processing protocol file: '%s', size: %ld",
	       myGlobals.protoSpecs, buf.st_size+8);

    for (;;) {
      bufferCurrent = fgets(bufferCurrent, buf.st_size, fd);
      /* On EOF, we're finished */
      if (bufferCurrent == NULL) {
	break;
      }

      /* otherwise, bufferCurrent points to the just read line in the file,
	 of the form:
	 [protocol=protocol[|protocol][,]] [# comment]
      */

      /* Strip out any comments */
      bufferWork = strchr(bufferCurrent, '#');
      if (bufferWork != NULL) {
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
  handleProtocolList("X11",      "6000-6010|");
  /* 22 == ssh (just to make sure the port is defined) */
  handleProtocolList("SSH",      "22|");

  /* Peer-to-Peer Protocols */
  myGlobals.GnutellaIdx = handleProtocolList("Gnutella", "6346|6347|6348|");
  myGlobals.KazaaIdx = handleProtocolList("Kazaa",       "1214|");
  myGlobals.WinMXIdx = handleProtocolList("WinMX",       "6699|7730|");
  myGlobals.DirectConnectIdx = handleProtocolList("DC++",    "0|"); /* Dummy port as this is a pure P2P protocol */
  handleProtocolList("eDonkey",    "4661-4665|");

  handleProtocolList("Messenger", "1863|5000|5001|5190-5193|");
}

/* **************************************** */

int mapGlobalToLocalIdx(int port) {
  if((port < 0) || (port >= MAX_IP_PORT))
   return(-1);
  else {
    int j, found, slotId = (3*port) % myGlobals.ipPortMapper.numSlots;

    for(j=0, found=0; j<myGlobals.ipPortMapper.numSlots; j++) {
      if(myGlobals.ipPortMapper.theMapper[slotId].portProto == -1)
	break;
      else if(myGlobals.ipPortMapper.theMapper[slotId].portProto == port) {
	found = 1;
	break;
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

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.purgePortsMutex, "purgeIpPorts");
#endif
  
  for(i=1; i<MAX_IP_PORT; i++) {
    if(myGlobals.device[theDevice].ipPorts[i] != NULL) {
      free(myGlobals.device[theDevice].ipPorts[i]);
      myGlobals.device[theDevice].ipPorts[i] = NULL;
    }
  }
  
#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.purgePortsMutex);
#endif

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "purgeIpPorts(%d) completed", theDevice);
#endif  
}

/* **************************************** */

#ifdef CFG_MULTITHREADED

void* scanIdleLoop(void* notUsed _UNUSED_) {

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Idle host scan thread running...");

  for(;;) {
    int i;

    HEARTBEAT(0, "scanIdleLoop(), sleep(60)...", NULL);
    sleep(60 /* do not change */);

    if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN) break;
    HEARTBEAT(0, "scanIdleLoop(), sleep(60)...woke", NULL);
    myGlobals.actTime = time(NULL);

    for(i=0; i<myGlobals.numDevices; i++)
      if(!myGlobals.device[i].virtualDevice) {
        if(!myGlobals.stickyHosts) purgeIdleHosts(i);
#if !defined(__FreeBSD__)
	purgeIpPorts(i);
#endif
	
#ifdef MAKE_WITH_SCHED_YIELD
	sched_yield(); /* Allow other threads to run */
#endif
      }

    updateThpt(1);
  }

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Idle Scan thread (%ld) terminated", 
	     myGlobals.scanIdleThreadId);
  return(NULL); 
}
#endif

/* **************************************** */

#ifndef CFG_MULTITHREADED
void packetCaptureLoop(time_t *lastTime, int refreshRate) {
  int numPkts=0, pcap_fd = pcap_fileno(myGlobals.device[0].pcapPtr);
  fd_set readMask;
  struct timeval timeout;

  if((pcap_fd == -1) && (myGlobals.rFileName != NULL)) {
    /*
      This is a patch to overcome a bug of libpcap
      while reading from a traffic file instead
      of sniffying live from a NIC.
    */
    struct mypcap {
      int fd, snapshot, linktype, tzoff, offset;
      FILE *rfile;

      /* Other fields have been skipped. Please refer
	 to pcap-int.h for the full datatype.
      */
    };

    pcap_fd = fileno(((struct mypcap *)(myGlobals.device[0].pcapPtr))->rfile);
  }

  for(;;) {
    short loopItem = -1;
    int rc;

    if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN) break;

    FD_ZERO(&readMask);
    if(pcap_fd != -1) FD_SET(pcap_fd, &readMask);

    timeout.tv_sec  = 5 /* seconds */;
    timeout.tv_usec = 0;

    if(select(pcap_fd+1, &readMask, NULL, NULL, &timeout) > 0) {
      rc = pcap_dispatch(myGlobals.device[0].pcapPtr, 1, processPacket, NULL);

      if(rc == -1) {
	traceEvent(CONST_TRACE_ERROR, "Reading packets: '%s'",
		   pcap_geterr(myGlobals.device[0].pcapPtr));
	continue;
      } else if((rc == 0) && (myGlobals.rFileName != NULL)) {
	traceEvent(CONST_TRACE_INFO, "pcap_dispatch returned %d "
		   "[No more packets to read]", rc);
	pcap_fd = -1;
      }
    }

    myGlobals.actTime = time(NULL);

    if(myGlobals.actTime > (*lastTime)) {
      /* So, the clock has ticked... approximately 30 seconds (depends on traffic, the select
	 above could delay 5s

	 Let's purge one of the devices...
      */
      loopItem++;
      if (loopItem >= myGlobals.numDevices) {
	loopItem = 0;
      }

      updateThpt(1); /* Update Throughput */
      (*lastTime) = myGlobals.actTime + PARM_THROUGHPUT_REFRESH_INTERVAL;
    }

    handleWebConnections(NULL);
  } /* for(;;) */
}
#endif

/* **************************************** */

/* Report statistics and write out the raw packet file */
RETSIGTYPE cleanup(int signo) {
  static int unloaded = 0, msgSent = 0;
  struct pcap_stat pcapStat;
  int i;

  if(!msgSent) {
    traceEvent(CONST_TRACE_INFO, "CLEANUP: ntop caught signal %d", signo);
    msgSent = 1;
  }

#ifdef HAVE_BACKTRACE
  if (signo == SIGSEGV) {
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
    if (size < 2) {
      traceEvent(CONST_TRACE_ERROR, "BACKTRACE:         **unavailable!");
    } else {
      /* Ignore the 0th entry, that's our cleanup() */
      for (i=1; i<size; i++) {
	traceEvent(CONST_TRACE_ERROR, "BACKTRACE:          %2d. %s", i, strings[i]);
      }
    }
  }
#endif /* HAVE_BACKTRACE */

  if(unloaded)
    return;
  else
    unloaded = 1;

  traceEvent(CONST_TRACE_INFO, "CLEANUP: Cleaning up, set FLAG_NTOPSTATE_TERM");

  myGlobals.capturePackets = FLAG_NTOPSTATE_TERM;

#ifndef WIN32
 #ifdef CFG_MULTITHREADED

  killThread(&myGlobals.dequeueThreadId);

  #ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  if(myGlobals.numericFlag == 0) {
    for(i=0; i<myGlobals.numDequeueThreads; i++)
      killThread(&myGlobals.dequeueAddressThreadId[i]);
  }
  #endif

  killThread(&myGlobals.handleWebConnectionsThreadId);

  #ifdef MAKE_WITH_SSLWATCHDOG
  if (myGlobals.sslwatchdogChildThreadId != 0) {
      killThread(&myGlobals.sslwatchdogChildThreadId);
  }
   #ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  if (myGlobals.useSSLwatchdog == 1)
   #endif
  {
      deleteCondvar(&myGlobals.sslwatchdogCondvar);
  }
  #endif

 #endif

#else /* #ifndef WIN32 */

  /*
    TW 06.11.2001
    Wies-Software <wies@wiessoft.de>

    #else clause added to force dequeue threads to terminate
    MAKE_WITH_SEMAPHORES is *NOT* tested!!!
  */
 #ifdef CFG_MULTITHREADED
  #ifdef MAKE_WITH_SEMAPHORES
  incrementSem(&myGlobals.queueSem);
   #ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  incrementSem(&myGlobals.queueAddressSem);
   #endif
  #else
  signalCondvar(&myGlobals.queueCondvar);
   #ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  signalCondvar(&myGlobals.queueAddressCondvar);
   #endif
  #endif
 #endif /* MULTITREADED */
#endif /* #ifndef WIN32 */

#ifdef HAVE_FILEDESCRIPTORBUG
    /* Close and delete the temporary - junk - files */
    traceEvent(CONST_TRACE_INFO, "FILEDESCRIPTORBUG: Bug work-around cleanup");
    for(i=CONST_FILEDESCRIPTORBUG_COUNT-1; i>=0; i--) {
      if(myGlobals.tempF[i] >= 0) {
        traceEvent(CONST_TRACE_NOISY, "FILEDESCRIPTORBUG: Removing %d, '%s'(%d)", i, myGlobals.tempFname[i], myGlobals.tempF[i]);
        if(close(myGlobals.tempF[i])) {
          traceEvent(CONST_TRACE_ERROR,
                     "FILEDESCRIPTORBUG: Unable to close file %d - '%s'(%d)",
                     i,
                     strerror(errno), errno);
        } else {
          if(unlink(myGlobals.tempFname[i]))
            traceEvent(CONST_TRACE_ERROR,
                       "FILEDESCRIPTORBUG: Unable to delete file '%s' - '%s'(%d)",
                       myGlobals.tempFname[i],
                       strerror(errno), errno);
          else
            traceEvent(CONST_TRACE_NOISY,
                       "FILEDESCRIPTORBUG: Removed file '%s'",
                       myGlobals.tempFname[i]);
        }
      }
    }
#endif /* FILEDESCRIPTORBUG */

#if 0
#ifdef CFG_MULTITHREADED
  traceEvent(CONST_TRACE_INFO, "CLEANUP: Waiting until threads terminate");
  sleep(3); /* Just to wait until threads complete */
#endif
#endif

#ifdef CFG_MULTITHREADED
  /* Prevents the web interface from running */
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "CLEANUP: Locking purge mutex (may block for a little while)");
  accessMutex(&myGlobals.purgeMutex, "cleanup");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "CLEANUP: Locked purge mutex, continuing shutdown");
#endif

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
  termNetFlowExporter();
  termPassiveSessions();

#ifndef WIN32
  endservent();
#endif

#ifdef CFG_MULTITHREADED
  deleteMutex(&myGlobals.packetProcessMutex);
  deleteMutex(&myGlobals.packetQueueMutex);
#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  if(myGlobals.numericFlag == 0)
    deleteMutex(&myGlobals.addressResolutionMutex);
#endif
  deleteMutex(&myGlobals.hostsHashMutex);

#ifdef MAKE_WITH_SEMAPHORES
  deleteSem(&myGlobals.queueSem);
#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  deleteSem(&myGlobals.queueAddressSem);
#endif
#else
  deleteCondvar(&myGlobals.queueCondvar);
#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  deleteCondvar(&myGlobals.queueAddressCondvar);
#endif
#endif
#endif

  termGdbm();

#ifdef CFG_MULTITHREADED
  deleteMutex(&myGlobals.gdbmMutex);
  deleteMutex(&myGlobals.purgeMutex);
#endif

  for(i=0; i<myGlobals.numDevices; i++) {
    int j;

    traceEvent(CONST_TRACE_INFO, "CLEANUP: Freeing device %s (idx=%d)", myGlobals.device[i].name, i);

    if(myGlobals.device[i].pcapPtr && (!myGlobals.device[i].virtualDevice)) {
      if (pcap_stats(myGlobals.device[i].pcapPtr, &pcapStat) >= 0) {
	traceEvent(CONST_TRACE_INFO, "STATS: %s packets received by filter on %s",
		   formatPkts((Counter)pcapStat.ps_recv), myGlobals.device[i].name);

	traceEvent(CONST_TRACE_INFO, "STATS: %s packets dropped by kernel", formatPkts((Counter)pcapStat.ps_drop));
#ifdef CFG_MULTITHREADED
	traceEvent(CONST_TRACE_INFO, "STATS: %s packets dropped by ntop",
		   formatPkts(myGlobals.device[i].droppedPkts.value));
#endif
      }
    }

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
    

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.tcpSessionsMutex, "purgeIdleHosts");
#endif
    if(myGlobals.device[i].tcpSession != NULL)
      free(myGlobals.device[i].tcpSession);
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.tcpSessionsMutex);
#endif

    free(myGlobals.device[i].humanFriendlyName);
    free(myGlobals.device[i].name);

    if(myGlobals.device[i].pcapDumper != NULL)
      pcap_dump_close(myGlobals.device[i].pcapDumper);

    if(myGlobals.device[i].pcapErrDumper != NULL)
      pcap_dump_close(myGlobals.device[i].pcapErrDumper);

    if(myGlobals.device[i].pcapPtr != NULL) {
      pcap_close(myGlobals.device[i].pcapPtr);
      /*
	Do not call free(myGlobals.device[i].pcapPtr)
	as the pointer has been freed already by
	pcap_close
      */
      myGlobals.device[i].pcapPtr = NULL;
    }
  }
  
  free(myGlobals.device);

#ifdef CFG_MULTITHREADED
  deleteMutex(&myGlobals.tcpSessionsMutex);
  deleteMutex(&myGlobals.purgePortsMutex);
  deleteMutex(&myGlobals.securityItemsMutex);
  /* DO NOT DO deleteMutex(&myGlobals.logViewMutex); - need it for the last traceEvent()s */
#endif

  if (myGlobals.logView != NULL) {
    for(i=0; i<CONST_LOG_VIEW_BUFFER_SIZE; i++)
      if (myGlobals.logView[i] != NULL) 
	free(myGlobals.logView[i]);
    free(myGlobals.logView);
  }

#ifdef WIN32
  termWinsock32();
#endif

  for(i=0; i<myGlobals.numIpProtosToMonitor; i++)
    free(myGlobals.protoIPTrafficInfos[i]);

  free(myGlobals.protoIPTrafficInfos);
  free(myGlobals.ipPortMapper.theMapper);

  if(myGlobals.currentFilterExpression != NULL)
    free(myGlobals.currentFilterExpression);

  if(myGlobals.localAddresses != NULL) free(myGlobals.localAddresses);
  if(myGlobals.effectiveUserName != NULL) free(myGlobals.effectiveUserName);
  if(myGlobals.devices != NULL) free(myGlobals.devices);

  /* One day we should free myGlobals.countryFlagHead */

  free(myGlobals.pcapLogBasePath);
  /* free(myGlobals.dbPath); -- later, need this to remove pid */
  free(myGlobals.spoolPath);
  if (myGlobals.rrdPath != NULL)
      free(myGlobals.rrdPath);

  myGlobals.endNtop = 1;

#ifdef MEMORY_DEBUG
  traceEvent(CONST_TRACE_INFO, "===================================");
  termLeaks();
  traceEvent(CONST_TRACE_INFO, "===================================");
#endif

#ifdef MTRACE
  muntrace();
#endif

#ifndef WIN32
  removeNtopPid();
#endif
  free(myGlobals.dbPath);

  traceEvent(CONST_TRACE_INFO, "===================================");
  traceEvent(CONST_TRACE_INFO, "        ntop is shutdown...        ");
  traceEvent(CONST_TRACE_INFO, "===================================");

  exit(0);
}
