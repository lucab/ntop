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
   printMutexInfo(&myGlobals.packetQueueMutex, "myGlobals.packetQueueMutex");

#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
   if(myGlobals.numericFlag == 0)
     printMutexInfo(&myGlobals.addressResolutionMutex, "myGlobals.addressResolutionMutex");
#endif

  if(myGlobals.isLsofPresent)
     printMutexInfo(&myGlobals.lsofMutex, "myGlobals.lsofMutex");
   printMutexInfo(&myGlobals.hostsHashMutex, "myGlobals.hostsHashMutex");
   printMutexInfo(&myGlobals.graphMutex, "myGlobals.graphMutex");
  traceEvent(CONST_TRACE_INFO, "========================================");
#endif /* CFG_MULTITHREADED */

  (void)signal(SIGHUP,  handleSigHup);
}

#endif /* WIN32 */

/* *************************** */

#ifdef CFG_MULTITHREADED
#if !defined(WIN32) && !defined(DARWIN)
void* pcapDispatch(void *_i) {
  int rc;
  int i = (int)_i;
  int pcap_fd;
  fd_set readMask;
  struct timeval timeout;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: pcap dispatch thread started...\n");

  pcap_fd = pcap_fileno(myGlobals.device[i].pcapPtr);

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

    pcap_fd = fileno(((struct mypcap *)(myGlobals.device[i].pcapPtr))->rfile);
  }

  for(;myGlobals.capturePackets == FLAG_NTOPSTATE_RUN;) {
    FD_ZERO(&readMask);
    FD_SET(pcap_fd, &readMask);

    /* timeout.tv_sec  = 5, timeout.tv_usec = 0; */

    if(select(pcap_fd+1, &readMask, NULL, NULL, NULL /* &timeout */ ) > 0) {
      /* printf("dispatch myGlobals.device %s\n", myGlobals.device[i].name);*/
      if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN) return(NULL);
      HEARTBEAT(2, "pcapDispatch()", NULL);
      rc = pcap_dispatch(myGlobals.device[i].pcapPtr, 1, processPacket, (u_char*)_i);

      if(rc == -1) {
	traceEvent(CONST_TRACE_ERROR, "Error while reading packets: %s.\n",
		   pcap_geterr(myGlobals.device[i].pcapPtr));
	break;
      } else if((rc == 0) && (myGlobals.rFileName != NULL)) {
	traceEvent(CONST_TRACE_INFO, "pcap_dispatch returned %d "
		   "[No more packets to read]", rc);
	break; /* No more packets to read */
      }
      /* else
	 traceEvent(CONST_TRACE_INFO, "1) %d\n", numPkts++);
      */
    }
  }

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: pcap dispatch thread terminated...\n");
  return(NULL); 

}
#else /* WIN32 */
void* pcapDispatch(void *_i) {
  int rc;
  int i = (int)_i;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: pcap dispatch thread started...\n");

  for(;myGlobals.capturePackets == FLAG_NTOPSTATE_RUN;) {
    rc = pcap_dispatch(myGlobals.device[i].pcapPtr, 1, queuePacket, (u_char*)_i);
    if(rc == -1) {
      traceEvent(CONST_TRACE_ERROR, "Error while reading packets: %s.\n",
		 pcap_geterr(myGlobals.device[i].pcapPtr));
      break;
    } /* else
	 traceEvent(CONST_TRACE_INFO, "1) %d\n", numPkts++);
      */
    HEARTBEAT(2, "pcapDispatch()", NULL);
  }

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: pcap dispatch thread terminated...\n");
  return(NULL); 

}
#endif
#endif

/* **************************************** */

#ifndef WIN32
RETSIGTYPE handleDiedChild(int sig _UNUSED_) {
  int status;
  pid_t pidId;

  while((pidId = waitpid(-1, &status, WNOHANG)) > 0) {
#ifdef DEBUG
    if(status == 0) {
      myGlobals.numChildren--;
      traceEvent(CONST_TRACE_INFO,
		 "A child has terminated [pid=%d status=%d children=%d]\n",
		 pidId, status, myGlobals.numChildren);
    }
#endif
  }

  /* signal(SIGCHLD, handleDiedChild); */
}
#endif


/* **************************************** */

#ifndef WIN32

void daemonize(void) {
  int childpid;
  FILE *fd;
  char pidFileName[NAME_MAX];

  signal(SIGHUP, SIG_IGN);
#ifndef WIN32
  /* signal(SIGCHLD, handleDiedChild); */
     signal(SIGCHLD, SIG_IGN);
#endif
  signal(SIGQUIT, SIG_IGN);

  if((childpid=fork()) < 0)
    traceEvent(CONST_TRACE_ERROR, "An error occurred while daemonizing ntop (errno=%d)...\n", errno);
  else {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Note: after fork() in %s (%d)\n", 
                           childpid ? "parent" : "child",
                           childpid);
#endif
    if(!childpid) { /* child */

      myGlobals.basentoppid = getpid();
      sprintf(pidFileName, "%s/%s", DEFAULT_NTOP_PID_DIRECTORY, DEFAULT_NTOP_PIDFILE);
      fd = fopen(pidFileName, "wb");

      if(fd == NULL) {
          traceEvent(CONST_TRACE_WARNING, "Unable to create pid file (%s). ", pidFileName);
      } else {
          fprintf(fd, "%d\n", myGlobals.basentoppid);
          fclose(fd);
          traceEvent(CONST_TRACE_INFO, "Created pid file (%s). ", pidFileName);
      }

      traceEvent(CONST_TRACE_INFO, "Bye bye: I'm becoming a daemon...\n");
      detachFromTerminal(1);
    } else { /* father */
      traceEvent(CONST_TRACE_INFO, "Note: Parent process is exiting (this is normal)\n");
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
	myGlobals.numIpPortsToHandle++;

#ifdef DEBUG
	printf("[%d] '%s' [port=%d]\n", myGlobals.numIpProtosToMonitor, protoName, idx);
#endif
	servicesMapper[idx] = myGlobals.numIpProtosToMonitor;
      } else if(printWarnings)
	printf("WARNING: IP port %d (%s) has been discarded (multiple instances).\n",
	       idx, protoName);
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
	myGlobals.numIpPortsToHandle++;

#ifdef DEBUG
	printf("[%d] '%s' [%s:%d]\n", myGlobals.numIpProtosToMonitor, protoName, protocol, idx);
#endif
	servicesMapper[idx] = myGlobals.numIpProtosToMonitor;
      } else if(printWarnings)
	printf("WARNING: protocol '%s' has been discarded (multiple instances).\n",
	       protocol);
      return(idx);
    }
  }

  if(printWarnings)
    traceEvent(CONST_TRACE_WARNING, "WARNING: unknown protocol '%s'. It has been ignored.\n",
	       protocol);

  return(-1);
}

/* **************************************** */

static int handleProtocolList(char* protoName,
			       char *protocolList) {
  char tmpStr[255];
  char* lastEntry, *protoEntry;
  int increment=0, rc=0;

  if(servicesMapper == NULL) {
    servicesMapper = (int*)malloc(sizeof(int)*MAX_IP_PORT);
    memset(servicesMapper, -1, sizeof(int)*MAX_IP_PORT);
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "%s - %s\n", protoName, protocolList);
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
      myGlobals.protoIPTrafficInfos = (char**)realloc(myGlobals.protoIPTrafficInfos, sizeof(char*)*(myGlobals.numIpProtosToMonitor+1));

    rc = myGlobals.numIpProtosToMonitor;
    myGlobals.protoIPTrafficInfos[myGlobals.numIpProtosToMonitor] = strdup(protoName);
    myGlobals.numIpProtosToMonitor++;
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "%d) %s - %s\n",
	       myGlobals.numIpProtosToMonitor, protoName, protocolList);
#endif
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "handleProtocolList(%s) = %d", protoName, rc);
#endif

  return(rc);
}

/* **************************************** */

void createPortHash() {
  int theSize, i;

  /*
     At this point in time servicesMapper contains all
     the port data hence we can transform it from
     an array to a hash table.
  */
  myGlobals.numIpPortMapperSlots = 2*myGlobals.numIpPortsToHandle;
  theSize = sizeof(PortMapper)*2*myGlobals.numIpPortMapperSlots;
  myGlobals.ipPortMapper = (PortMapper*)malloc(theSize);
  for(i=0; i<myGlobals.numIpPortMapperSlots; i++) myGlobals.ipPortMapper[i].port = -1;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Allocating %d slots", myGlobals.numIpPortMapperSlots);
#endif

  for(i=0; i<MAX_IP_PORT; i++) {
    if(servicesMapper[i] != -1) {
      int slotId = (3*i) % myGlobals.numIpPortMapperSlots;

      while(myGlobals.ipPortMapper[slotId].port != -1)
	slotId = (slotId+1) % myGlobals.numIpPortMapperSlots;

#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "Mapping port %d to slotId %d", i, slotId);
#endif
      myGlobals.ipPortMapper[slotId].port = i, myGlobals.ipPortMapper[slotId].mappedPort = servicesMapper[i];
    }
  }

  free(servicesMapper);
}

/* **************************************** */

void handleProtocols() {
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
    traceEvent(CONST_TRACE_INFO, "Processing protocol list: '%s'", myGlobals.protoSpecs);
    proto = strtok_r(myGlobals.protoSpecs, ",", &strtokState);
  } else {
    struct stat buf;

    if(stat(myGlobals.protoSpecs, &buf) != 0) {
      fclose(fd);
      traceEvent(CONST_TRACE_ERROR, "Error while stat() of %s\n", myGlobals.protoSpecs);
      return;
    }

    bufferCurrent = buffer = (char*)malloc(buf.st_size+8) /* just to be safe */;

    traceEvent(CONST_TRACE_INFO, "Processing protocol file: '%s', size: %ld",
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
		 "Unknown protocol '%s'. It has been ignored.\n",
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
  handleProtocolList("NFS",      "mount|pcnfs|bwnfs|nfsd|nfsd-status|");
  handleProtocolList("X11",      "6000-6010|");
  /* 22 == ssh (just to make sure the port is defined) */
  handleProtocolList("SSH",      "22|");

  /* Peer-to-Peer Protocols */
  myGlobals.GnutellaIdx = handleProtocolList("Gnutella", "6346|6347|6348|");
  myGlobals.KazaaIdx = handleProtocolList("Kazaa",       "1214|");
  myGlobals.WinMXIdx = handleProtocolList("WinMX",       "6699|7730|");
  myGlobals.DirectConnectIdx = handleProtocolList("DirectConnect",    "0|"); /* Dummy port as this is a pure P2P protocol */
  handleProtocolList("eDonkey",    "4661-4665|");

  handleProtocolList("Messenger", "1863|5000|5001|5190-5193|");
}

/* **************************************** */

int mapGlobalToLocalIdx(int port) {
  if((port < 0) || (port >= MAX_IP_PORT))
   return(-1);
  else {
    int j, found, slotId = (3*port) % myGlobals.numIpPortMapperSlots;

    for(j=0, found=0; j<myGlobals.numIpPortMapperSlots; j++) {
      if(myGlobals.ipPortMapper[slotId].port == -1)
	break;
      else if(myGlobals.ipPortMapper[slotId].port == port) {
	found = 1;
	break;
      }

      slotId = (slotId+1) % myGlobals.numIpPortMapperSlots;
    }

    if(found)
      return(myGlobals.ipPortMapper[slotId].mappedPort);
    else
      return(-1);
  }
}

/* **************************************** */

static void purgeIpPorts(int theDevice) {
  char *marker;
  HostTraffic *el;
  int i;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Calling purgeIpPorts(%d)", theDevice);
#endif
  
  if(myGlobals.device[myGlobals.actualReportDeviceId].numHosts == 0) return;

  /* **********************************

  marker used to be defined ad char marker[MAX_IP_PORT];
  Unfortunately under FreeBSD this caused a core dump.
  Probably because the amount of memory allocated on the
  heap was too much. With dynamic memory allocation
  the problem is gone.

  ********************************** */

  marker = (char*)calloc(1, MAX_IP_PORT);
  
  for(i=1; i<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; i++) {
    int k;

    if(i == myGlobals.otherHostEntryIdx)
      continue;

    if((el = myGlobals.device[theDevice].hash_hostTraffic[i]) == NULL) continue;   
    
    for(k=0; i<MAX_NUM_RECENT_PORTS; i++) {
      marker[el->recentlyUsedServerPorts[k]] = 1;
      marker[el->recentlyUsedClientPorts[k]] = 1;
    }
  }

  /* 
     I know that this semaphore has been designed for other tasks
     however it allows me to save memory/time... 
  */
#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.gdbmMutex, "purgeIpPorts");
#endif
  
  for(i=1; i<MAX_IP_PORT; i++) {
    if((marker[i] == 0) && (myGlobals.device[theDevice].ipPorts[i] != NULL)) {
      free(myGlobals.device[theDevice].ipPorts[i]);
      myGlobals.device[theDevice].ipPorts[i] = NULL;
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "Purging ipPorts(%d)", i);
#endif
    }
  }
  
#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.gdbmMutex);
#endif

  free(marker);
}

/* **************************************** */

void* scanIdleLoop(void* notUsed _UNUSED_) {

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Idle Scan thread (%ld) started...\n", myGlobals.scanIdleThreadId);

  for(;;) {
    int i;

    HEARTBEAT(0, "scanIdleLoop(), sleep(60)...", NULL);
    sleep(60 /* do not change */);

    if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN) break;
    HEARTBEAT(0, "scanIdleLoop(), sleep(60)...woke", NULL);
    myGlobals.actTime = time(NULL);

    for(i=0; i<myGlobals.numDevices; i++)
      if(!myGlobals.device[i].virtualDevice) {
        purgeIdleHosts(i);
#if !defined(__FreeBSD__)
	purgeIpPorts(i);
#endif
#ifdef HAVE_SCHED_H
	sched_yield(); /* Allow other threads to run */
#endif
      }
  }

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: Idle Scan thread (%ld) terminated...\n", myGlobals.scanIdleThreadId);
  return(NULL); 
}

/* **************************************** */
#ifndef WIN32
#ifdef CFG_MULTITHREADED
void* periodicLsofLoop(void* notUsed _UNUSED_) {
  long loopCount=0;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: lsof loop thread (%ld) started...\n", myGlobals.lsofThreadId);

  for(;;) {
    /*
      refresh process list each minute
      if needed
    */

    if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN) break;

    if(myGlobals.updateLsof) {
    HEARTBEAT(0, "periodicLsofLoop()", NULL);
#ifdef LSOF_DEBUG
      traceEvent(CONST_TRACE_INFO, "LSOF_DEBUG: Wait please: reading lsof information...\n");
#endif
      if(myGlobals.isLsofPresent) readLsofInfo();
      if ( (++loopCount == 1) && (myGlobals.numProcesses == 0) ) {
          traceEvent(CONST_TRACE_WARNING, "LSOF: 1st run found nothing - check if lsof is suid root?\n");
      }
#ifdef LSOF_DEBUG
      traceEvent(CONST_TRACE_INFO, "LSOF_DEBUG: Done with lsof.\n");
#endif
    }
    HEARTBEAT(0, "periodicLsofLoop(), sleep(60)...", NULL);
    sleep(60);
    HEARTBEAT(0, "periodicLsofLoop(), sleep(60)...woke", NULL);
  }

  traceEvent(CONST_TRACE_INFO, "THREADMGMT: lsof loop thread (%ld) terminated...\n", myGlobals.lsofThreadId);
  return(NULL); 

}
#endif
#endif /* WIN32 */

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
	traceEvent(CONST_TRACE_ERROR, "Error while reading packets: %s.\n",
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

      updateThpt(); /* Update Throughput */
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
    traceEvent(CONST_TRACE_INFO, "ntop caught signal %d", signo);
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

    traceEvent(CONST_TRACE_ERROR, "\n\n\n*****ntop error: Signal(%d)\n", signo);

    traceEvent(CONST_TRACE_ERROR, "\n     backtrace is:\n");
    if (size < 2) {
      traceEvent(CONST_TRACE_ERROR, "         **unavailable!\n");
    } else {
      /* Ignore the 0th entry, that's our cleanup() */
      for (i=1; i<size; i++) {
	traceEvent(CONST_TRACE_ERROR, "          %2d. %s\n", i, strings[i]);
      }
    }
  }
#endif /* HAVE_BACKTRACE */

  if(unloaded)
    return;
  else
    unloaded = 1;

  traceEvent(CONST_TRACE_INFO, "Cleaning up...");

  myGlobals.capturePackets = FLAG_NTOPSTATE_TERM;

#ifndef WIN32
 #ifdef CFG_MULTITHREADED

  killThread(&myGlobals.dequeueThreadId);

  if(myGlobals.isLsofPresent)
    killThread(&myGlobals.lsofThreadId);

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

#ifdef CFG_MULTITHREADED
  traceEvent(CONST_TRACE_INFO, "Waiting until threads terminate...\n");
  sleep(3); /* Just to wait until threads complete */
#endif

  for(i=0; i<myGlobals.numDevices; i++) {
    freeHostInstances(i);

    if(myGlobals.broadcastEntry != NULL)
      freeHostInfo(i, myGlobals.broadcastEntry, i);
    if(myGlobals.otherHostEntry != NULL)
      freeHostInfo(i, myGlobals.otherHostEntry, i);

    while(myGlobals.device[i].fragmentList != NULL) {
      IpFragment *fragment = myGlobals.device[i].fragmentList->next;
      free(myGlobals.device[i].fragmentList);
      myGlobals.device[i].fragmentList = fragment;
    }
  }

  for(i=0; i<myGlobals.hostsCacheLen; i++)
    free(myGlobals.hostsCache[i]);
  myGlobals.hostsCacheLen = 0;

#ifndef MAKE_MICRO_NTOP
  unloadPlugins();
#endif

  (void)fflush(stdout);

  termIPServices();
  termIPSessions();
  termNetFlowExporter();
  termPassiveSessions();

#ifndef WIN32
  endservent();
#endif

#ifdef CFG_MULTITHREADED
  deleteMutex(&myGlobals.packetQueueMutex);
#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  if(myGlobals.numericFlag == 0)
    deleteMutex(&myGlobals.addressResolutionMutex);
#endif
  deleteMutex(&myGlobals.hostsHashMutex);
  deleteMutex(&myGlobals.graphMutex);

  if(myGlobals.isLsofPresent)
    deleteMutex(&myGlobals.lsofMutex);
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

#ifdef HAVE_GDBM_H
#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.gdbmMutex, "cleanup");
#endif
  gdbm_close(myGlobals.gdbm_file);    myGlobals.gdbm_file = NULL;
  gdbm_close(myGlobals.addressCache); myGlobals.addressCache = NULL;
  gdbm_close(myGlobals.pwFile);       myGlobals.pwFile = NULL;
  gdbm_close(myGlobals.prefsFile);    myGlobals.prefsFile = NULL;

  /* Courtesy of Wies-Software <wies@wiessoft.de> */
  gdbm_close(myGlobals.hostsInfoFile); myGlobals.hostsInfoFile = NULL;
  if(myGlobals.eventFile != NULL) {
    gdbm_close(myGlobals.eventFile);
    myGlobals.eventFile = NULL;
  }
#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.gdbmMutex);
#endif

#ifdef CFG_MULTITHREADED
  deleteMutex(&myGlobals.gdbmMutex);
#endif
#endif

  for(i=0; i<myGlobals.numDevices; i++) {
    int j;

    traceEvent(CONST_TRACE_INFO, "Freeing device %s (idx=%d)...", myGlobals.device[i].name, i);

    if(myGlobals.device[i].pcapPtr && (!myGlobals.device[i].virtualDevice)) {
      if (pcap_stats(myGlobals.device[i].pcapPtr, &pcapStat) >= 0) {
	traceEvent(CONST_TRACE_INFO, "%s packets received by filter on %s\n",
		   formatPkts((Counter)pcapStat.ps_recv), myGlobals.device[i].name);

	traceEvent(CONST_TRACE_INFO, "%s packets dropped by kernel\n", formatPkts((Counter)pcapStat.ps_drop));
#ifdef CFG_MULTITHREADED
	traceEvent(CONST_TRACE_INFO, "%s packets dropped by ntop\n",
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

    if(myGlobals.device[i].hash_hostTraffic != NULL)
      free(myGlobals.device[i].hash_hostTraffic);

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.tcpSessionsMutex, "purgeIdleHosts");
#endif
    if(myGlobals.device[i].tcpSession != NULL)
      free(myGlobals.device[i].tcpSession);
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.tcpSessionsMutex);
#endif

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

    free(myGlobals.device[i].hashList);
  }
  
  free(myGlobals.device);

#ifdef CFG_MULTITHREADED
  deleteMutex(&myGlobals.tcpSessionsMutex);
#endif

#ifdef WIN32
  termWinsock32();
#endif

  if(myGlobals.processes != NULL) {
    for(i=0; i<myGlobals.numProcesses; i++) {
      free(myGlobals.processes[i]->command);
      free(myGlobals.processes[i]->user);
      free(myGlobals.processes[i]);
    }
    
    free(myGlobals.processes);
  }

  if(myGlobals.localPorts != NULL) {
    for(i=0; i<MAX_IP_PORT; i++) {
      while(myGlobals.localPorts[i] != NULL) {
	ProcessInfoList *listElement = myGlobals.localPorts[i]->next;
	free(myGlobals.localPorts[i]);
	myGlobals.localPorts[i] = listElement;
      }
    }
  }

  for(i=0; i<myGlobals.numIpProtosToMonitor; i++)
    free(myGlobals.protoIPTrafficInfos[i]);

  free(myGlobals.protoIPTrafficInfos);
  free(myGlobals.ipPortMapper);

  if(myGlobals.currentFilterExpression != NULL)
    free(myGlobals.currentFilterExpression);

  free(myGlobals.pcapLogBasePath);
  free(myGlobals.dbPath);
  if (myGlobals.rrdPath != NULL)
      free(myGlobals.rrdPath);

  myGlobals.endNtop = 1;

#ifdef MEMORY_DEBUG
  traceEvent(CONST_TRACE_INFO, "===================================\n");
  termLeaks();
  traceEvent(CONST_TRACE_INFO, "===================================\n");
#endif

#ifdef MTRACE
  muntrace();
#endif

  traceEvent(CONST_TRACE_INFO, "===================================\n");
  traceEvent(CONST_TRACE_INFO, "        ntop is shutdown...        \n");
  traceEvent(CONST_TRACE_INFO, "===================================\n");

  exit(0);
}
