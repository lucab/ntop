/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 *		 	    http://www.ntop.org/
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
 * Copyright (c) 1994, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "ntop.h"


int numChildren = 0;

static int enableDBsupport=0;
static int *servicesMapper = NULL; /* temporary value */

/* *************************** */

#ifdef MULTITHREADED
static void printMutexInfo(PthreadMutex *mutexId, char *mutexName) {  

  traceEvent(TRACE_INFO, "%s is %s (last lock %s:%d) [max lock time %s:%d (%d sec)]", 
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
#ifdef MULTITHREADED
  traceEvent(TRACE_INFO, "========================================");
   printMutexInfo(&gdbmMutex, "gdbmMutex");
   printMutexInfo(&packetQueueMutex, "packetQueueMutex");
   printMutexInfo(&addressResolutionMutex, "addressResolutionMutex");
   printMutexInfo(&hashResizeMutex, "hashResizeMutex");

  if(isLsofPresent)
     printMutexInfo(&lsofMutex, "lsofMutex");
   printMutexInfo(&hostsHashMutex, "hostsHashMutex");
   printMutexInfo(&graphMutex, "graphMutex");
#ifdef ASYNC_ADDRESS_RESOLUTION
  if(numericFlag == 0)
     printMutexInfo(&addressQueueMutex, "addressQueueMutex");
#endif
  traceEvent(TRACE_INFO, "========================================");
#endif /* MULTITHREADED */

  (void)setsignal(SIGHUP,  handleSigHup);
}

#endif /* WIN32 */

/* *************************** */

#ifdef MULTITHREADED
#ifndef WIN32
void* pcapDispatch(void *_i) {
  int rc;
  int i = (int)_i;
  int pcap_fd = pcap_fileno(device[i].pcapPtr);
  fd_set readMask;
  struct timeval timeout;

  if((pcap_fd == -1) && (rFileName != NULL)) {
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

    pcap_fd = fileno(((struct mypcap *)(device[i].pcapPtr))->rfile);
  }

  for(;capturePackets == 1;) {
    FD_ZERO(&readMask);
    FD_SET(pcap_fd, &readMask);

    timeout.tv_sec  = 5 /* seconds */;
    timeout.tv_usec = 0;

    if(select(pcap_fd+1, &readMask, NULL, NULL, &timeout) > 0) {
      /* printf("dispatch device %s\n", device[i].name);*/
      if(!capturePackets) return(NULL);
      rc = pcap_dispatch(device[i].pcapPtr, 1, processPacket, (u_char*) _i);

      if(rc == -1) {
	traceEvent(TRACE_ERROR, "Error while reading packets: %s.\n",
		   pcap_geterr(device[i].pcapPtr));
	break;
      } else if((rc == 0) && (rFileName != NULL)) {
	traceEvent(TRACE_INFO, "pcap_dispatch returned %d "
		   "[No more packets to read]", rc);
	break; /* No more packets to read */
      }
      /* else 
	 traceEvent(TRACE_INFO, "1) %d\n", numPkts++); 
      */
    }
  }

  return(NULL);
}
#else
void* pcapDispatch(void *_i) {
  int rc;
  int i = (int)_i;

  for(;capturePackets == 1;) {
    rc = pcap_dispatch(device[i].pcapPtr, 1, queuePacket, (u_char*) _i);
    if(rc == -1) {
      traceEvent(TRACE_ERROR, "Error while reading packets: %s.\n",
		 pcap_geterr(device[i].pcapPtr));
      break;
    } /* elsetraceEvent(TRACE_INFO, "1) %d\n", numPkts++); */
  }

  return(NULL);
}
#endif
#endif

/* **************************************** */

#ifndef WIN32
RETSIGTYPE handleDiedChild(int signal _UNUSED_) {
  int status;
  pid_t pidId;

  while((pidId = waitpid(-1, &status, WNOHANG)) > 0) {
#ifdef DEBUG
    if(status == 0) {
      numChildren--;
      traceEvent(TRACE_INFO,
		 "A child has terminated [pid=%d status=%d children=%d]\n",
		 pidId, status, numChildren);
    }
#endif
  }

  /* setsignal(SIGCHLD, handleDiedChild); */
}
#endif


/* **************************************** */

#ifndef WIN32

void daemonize(void) { 
  int childpid;

  signal(SIGHUP, SIG_IGN);
#ifndef WIN32
  /* setsignal(SIGCHLD, handleDiedChild); */
     setsignal(SIGCHLD, SIG_IGN); 
#endif
  signal(SIGQUIT, SIG_IGN);

  if((childpid=fork()) < 0)
    traceEvent(TRACE_ERROR, "An error occurred while daemonizing ntop (errno=%d)...\n", errno);
  else {
    if(!childpid) { /* child */
      traceEvent(TRACE_INFO, "Bye bye: I'm becoming a daemon...\n");
      detachFromTerminal();
    } else { /* father */
      exit(0);
    }
  }
}

/* **************************************** */

void detachFromTerminal(void) {
#ifndef MULTITHREADED
  alarm(120); /* Don't freeze */
#endif
  
  chdir("/");
  setsid();  /* detach from the terminal */

#ifdef ORIGINAL_DETACH
  if (freopen("/dev/null", "r", stdin) == NULL) {
    traceEvent(TRACE_ERROR,
	       "ntop: unable to replace stdin with /dev/null: %s\n",
	       strerror(errno));
  }

  if (freopen("/dev/null", "w", stdout) == NULL) {
    traceEvent(TRACE_ERROR,
	       "ntop: unable to replace stdout with /dev/null: %s\n",
	       strerror(errno));
  }

  /*
    if (freopen("/dev/null", "w", stderr) == NULL) {
    traceEvent(TRACE_ERROR,
    "ntop: unable to replace stderr with /dev/null: %s\n",
    strerror(errno));
    }
  */
#else /* !ORIGINAL_DETACH */
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

#endif /* ORIGINAL_DETACH */
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
    if(highProtoPort >= TOP_IP_PORT) highProtoPort = TOP_IP_PORT-1;

    for(idx=lowProtoPort; idx<= highProtoPort; idx++) {
      if(servicesMapper[idx] == -1) {
	numIpPortsToHandle++;

#ifdef DEBUG
	printf("[%d] '%s' [port=%d]\n", numIpProtosToMonitor, protoName, idx);
#endif
	servicesMapper[idx] = numIpProtosToMonitor;
      } else if(printWarnings)
	printf("WARNING: IP port %d (%s) has been discarded (multiple instances).\n",
	       idx, protoName);
    }

    return(1);
  }

  for(i=1; i<numActServices; i++) {
    idx = -1;

    if((udpSvc[i] != NULL) && (strcmp(udpSvc[i]->name, protocol) == 0))
      idx = udpSvc[i]->port;
    else if((tcpSvc[i] != NULL) && (strcmp(tcpSvc[i]->name, protocol) == 0))
      idx = tcpSvc[i]->port;

    if(idx != -1) {
      if(servicesMapper[idx] == -1) {
	numIpPortsToHandle++;

#ifdef DEBUG
	printf("[%d] '%s' [%s:%d]\n", numIpProtosToMonitor, protoName, protocol, idx);
#endif
	servicesMapper[idx] = numIpProtosToMonitor;
      } else if(printWarnings)
	printf("WARNING: protocol '%s' has been discarded (multiple instances).\n",
	       protocol);
      return(1);
    }
  }

  if(printWarnings)
    traceEvent(TRACE_WARNING, "WARNING: unknown protocol '%s'. It has been ignored.\n",
	       protocol);

  return(-1);
}

/* **************************************** */

static void handleProtocolList(char* protoName,
			       char *protocolList) {
  char tmpStr[255];
  char* lastEntry, *protoEntry;
  int increment=0, rc;

  if(servicesMapper == NULL) {
    servicesMapper = (int*)malloc(sizeof(int)*TOP_IP_PORT);
    memset(servicesMapper, -1, sizeof(int)*TOP_IP_PORT);
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "%s - %s\n", protoName, protocolList);
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
      increment=1;

    lastEntry = &protoEntry[1];
  }

  if(increment == 1) {
    if(numIpProtosToMonitor == 0)
      protoIPTrafficInfos = (char**)malloc(sizeof(char*));
    else
      protoIPTrafficInfos = (char**)realloc(protoIPTrafficInfos, sizeof(char*)*(numIpProtosToMonitor+1));

    protoIPTrafficInfos[numIpProtosToMonitor] = strdup(protoName);
    numIpProtosToMonitor++;
#ifdef DEBUG
    traceEvent(TRACE_INFO, "%d) %s - %s\n",
	       numIpProtosToMonitor, protoName, protocolList);
#endif
  }
}

/* **************************************** */

void createPortHash() {
  int theSize, i;

  /* 
     At this point in time servicesMapper contains all
     the port data hence we can transform it from
     an array to a hash table.     
  */
  numIpPortMapperSlots = 2*numIpPortsToHandle;
  theSize = sizeof(PortMapper)*2*numIpPortMapperSlots;
  ipPortMapper = (PortMapper*)malloc(theSize);
  for(i=0; i<numIpPortMapperSlots; i++) ipPortMapper[i].port = -1;

#ifdef DEBUG  
  traceEvent(TRACE_INFO, "Allocating %d slots", numIpPortMapperSlots);
#endif

  for(i=0; i<TOP_IP_PORT; i++) {
    if(servicesMapper[i] != -1) {
      int slotId = (3*i) % numIpPortMapperSlots;

      while(ipPortMapper[slotId].port != -1)	
	slotId = (slotId+1) % numIpPortMapperSlots;

#ifdef DEBUG
      traceEvent(TRACE_INFO, "Mapping port %d to slotId %d", i, slotId);
#endif
      ipPortMapper[slotId].port = i, ipPortMapper[slotId].mappedPort = servicesMapper[i];
    }
  }

  free(servicesMapper);
}

/* **************************************** */

void handleProtocols(char *protos) {
  char *proto, *buffer=NULL, *strtokState;
  FILE *fd = fopen(protos, "rb");

  if(fd == NULL)
    proto = strtok_r(protos, ",", &strtokState);
  else {
    struct stat buf;
    int len, i;

    if(stat(protos, &buf) != 0) {
      traceEvent(TRACE_ERROR, "Error while stat() of %s\n", protos);
      return;
    }

    buffer = (char*)malloc(buf.st_size+8) /* just to be safe */;

    for(i=0;i<buf.st_size;) {
      len = fread(&buffer[i], sizeof(char), buf.st_size-i, fd);
      if(len <= 0) break;
      i += len;
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
      traceEvent(TRACE_INFO,
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

      handleProtocolList(proto, tmpStr);

    }
    proto = strtok_r(NULL, ",", &strtokState);
  }

  if(buffer !=NULL)
    free(buffer);

  createPortHash();
}

/* **************************************** */

void addDefaultProtocols(void) {
  handleProtocolList("FTP", "ftp|ftp-data|");
  handleProtocolList("HTTP", "http|www|https|");
  handleProtocolList("DNS", "name|domain|");
  handleProtocolList("Telnet", "telnet|login|");
  handleProtocolList("NBios-IP", "netbios-ns|netbios-dgm|netbios-ssn|");
  handleProtocolList("Mail", "pop-2|pop-3|pop3|kpop|smtp|imap|imap2|");
  handleProtocolList("SNMP", "snmp|snmp-trap|");
  handleProtocolList("NEWS", "nntp|");
  handleProtocolList("NFS", "mount|pcnfs|bwnfs|nfsd|nfsd-status|");
  handleProtocolList("X11", "6000-6010|");
  /* 22 == ssh (just to make sure the port is defined) */
  handleProtocolList("SSH", "22|");

  createPortHash();
}

/* **************************************** */

int mapGlobalToLocalIdx(int port) {
  if((port < 0) || (port >= TOP_IP_PORT))
   return(-1);
  else {
    int j, found, slotId = (3*port) % numIpPortMapperSlots;
    
    for(j=0, found=0; j<numIpPortMapperSlots; j++) {
      if(ipPortMapper[slotId].port == -1)
	break;
      else if(ipPortMapper[slotId].port == port) {
	found = 1;
	break;
      }
      
      slotId = (slotId+1) % numIpPortMapperSlots;
    }
    
    if(found)
      return(ipPortMapper[slotId].mappedPort);
    else
      return(-1);
  }
}

/* **************************************** */

#ifdef MULTITHREADED
void* updateThptLoop(void* notUsed _UNUSED_) {
  for(;;) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Sleeping for %d seconds\n",
	       THROUGHPUT_REFRESH_TIME);
#endif

    sleep(THROUGHPUT_REFRESH_TIME);

    if(!capturePackets) break;

#ifdef DEBUG
    traceEvent(TRACE_INFO, "Trying to update throughput\n");
#endif

    /* Don't update Thpt if the traffic is high */
    /* if(packetQueueLen < (PACKET_QUEUE_LENGTH/3)) */ {
      actTime = time(NULL);
      accessMutex(&hostsHashMutex, "updateThptLoop");
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Updating throughput\n");
#endif
      updateThpt(); /* Update Throughput */
      releaseMutex(&hostsHashMutex);
    }
  }

  return(NULL);
}
#endif

/* **************************************** */

#ifdef MULTITHREADED
void* updateHostTrafficStatsThptLoop(void* notUsed _UNUSED_) {
  time_t nextUpdate = actTime+3600;
  int hourId, minuteId, lastUpdatedHour=-1;
  char theDate[8];
  struct tm t;

  for(;;) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Sleeping for 60 seconds\n");
#endif

    if(!capturePackets) break; /* Before */

    sleep(60);

    if(!capturePackets) break; /* After */

#ifdef DEBUG
    traceEvent(TRACE_INFO, "Trying to update host traffic stats");
#endif

    actTime = time(NULL);
    strftime(theDate, 8, "%M", localtime_r(&actTime, &t));
    minuteId = atoi(theDate);
    strftime(theDate, 8, "%H", localtime_r(&actTime, &t));
    hourId = atoi(theDate);
    if((minuteId <= 1) && (hourId != lastUpdatedHour)) {
      lastUpdatedHour = hourId;
      accessMutex(&hostsHashMutex, "updateHostTrafficStatsThptLoop");
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Updating host traffic stats\n");
#endif
      updateHostTrafficStatsThpt(hourId); /* Update Throughput */
      releaseMutex(&hostsHashMutex);
      nextUpdate = actTime+3600;
    }
  }

  return(NULL);
}
#endif

/* **************************************** */

#ifdef MULTITHREADED
void* updateDBHostsTrafficLoop(void* notUsed _UNUSED_) {
  u_short updateTime = DEFAULT_DB_UPDATE_TIME; /* This should be user configurable */

  for(;;) {
    int i;

#ifdef DEBUG
    traceEvent(TRACE_INFO, "Sleeping for %d seconds\n", updateTime);
#endif

    sleep(updateTime);

    if(!capturePackets) break;

    for(i=0; i<numDevices; i++)
      if(!device[i].virtualDevice) {
#ifdef MULTITHREADED
	accessMutex(&hostsHashMutex, "updateDbHostsTraffic");
#endif /* MULTITHREADED */
	updateDbHostsTraffic(i);
#ifdef MULTITHREADED
	releaseMutex(&hostsHashMutex);
#endif /* MULTITHREADED */
      }
  }
  return(NULL);

}
#endif

/* **************************************** */

void* scanIdleLoop(void* notUsed _UNUSED_) {
  for(;;) {
    int i;

    sleep(SESSION_SCAN_DELAY);

    if(!capturePackets) break;
    actTime = time(NULL);
    
    for(i=0; i<numDevices; i++)
      if(!device[i].virtualDevice) {
	purgeIdleHosts(0 /* Delete only idle hosts */, i);
#ifdef HAVE_SCHED_H
	sched_yield(); /* Allow other threads to run */
#else
	sleep(1); /* leave some time to others */
#endif
      }
  }
  
  return(NULL);
}

/* **************************************** */

void* scanIdleSessionsLoop(void* notUsed _UNUSED_) {

  for(;;) {
    sleep(SESSION_SCAN_DELAY);

    if(!capturePackets) break;
    actTime = time(NULL);

#ifdef MULTITHREADED
    accessMutex(&hostsHashMutex, "scanIdleSessionsLoop-1");
#endif
    scanTimedoutTCPSessions();
#ifdef MULTITHREADED
    releaseMutex(&hostsHashMutex);
#endif

#ifdef HAVE_SCHED_H
    sched_yield(); /* Allow other threads to run */
#else
    sleep(1); /* leave some time to others */
#endif

#ifdef MULTITHREADED
    accessMutex(&hostsHashMutex, "scanIdleSessionsLoop-2");
#endif
    purgeOldFragmentEntries();
#ifdef MULTITHREADED
    releaseMutex(&hostsHashMutex);
#endif

    if(handleRules)
      scanAllTcpExpiredRules();
  }

  return(NULL);
}

/* **************************************** */

#ifdef MULTITHREADED
void* periodicLsofLoop(void* notUsed _UNUSED_) {
  for(;;) {
    /*
      refresh process list each minute
      if needed
    */

    if(!capturePackets) break;

    if(updateLsof) {
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Wait please: reading lsof information...\n");
#endif
      if(isLsofPresent) readLsofInfo();
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Done with lsof.\n");
#endif
    }
    sleep(60);
  }
  return(NULL);

}
#endif

/* **************************************** */

#ifndef MULTITHREADED
void packetCaptureLoop(time_t *lastTime, int refreshRate) {
  int numPkts=0, pcap_fd = pcap_fileno(device[0].pcapPtr);
  fd_set readMask;
  struct timeval timeout;

  if((pcap_fd == -1) && (rFileName != NULL)) {
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

    pcap_fd = fileno(((struct mypcap *)(device[0].pcapPtr))->rfile);
  }

  for(;;) {
    short justRefreshed;
    int rc;

    if(!capturePackets) break;

    FD_ZERO(&readMask);
    if(pcap_fd != -1) FD_SET(pcap_fd, &readMask);

    timeout.tv_sec  = 5 /* seconds */;
    timeout.tv_usec = 0;

    if(select(pcap_fd+1, &readMask, NULL, NULL, &timeout) > 0) {
      rc = pcap_dispatch(device[0].pcapPtr, 1, processPacket, NULL);

      if(rc == -1) {
	traceEvent(TRACE_ERROR, "Error while reading packets: %s.\n",
		   pcap_geterr(device[0].pcapPtr));
	continue;
      } else if((rc == 0) && (rFileName != NULL)) {
	traceEvent(TRACE_INFO, "pcap_dispatch returned %d "
		   "[No more packets to read]", rc);
	pcap_fd = -1;
      }
    }

    actTime = time(NULL);

    if(actTime > (*lastTime)) {
      if(nextSessionTimeoutScan < actTime) {
	/* It's time to check for timeout sessions */
	scanTimedoutTCPSessions();
	nextSessionTimeoutScan = actTime+SESSION_SCAN_DELAY;
      }

      if(handleRules)
	scanAllTcpExpiredRules();
      updateThpt(); /* Update Throughput */
      (*lastTime) = actTime + THROUGHPUT_REFRESH_TIME;
      justRefreshed=1;
    } else
      justRefreshed=0;

    handleWebConnections(NULL);
  } /* for(;;) */
}
#endif

/* **************************************** */

/* Report statistics and write out the raw packet file */
RETSIGTYPE cleanup(int signo) {
  static int unloaded = 0;
  struct pcap_stat stat;
  int i;

  if(unloaded)
    return;
  else
    unloaded = 1;

  traceEvent(TRACE_INFO, "Cleaning up...");
  
  capturePackets = 0;

#ifndef WIN32
#ifdef MULTITHREADED
  killThread(&dequeueThreadId);
  killThread(&thptUpdateThreadId);
  killThread(&hostTrafficStatsThreadId);
  killThread(&scanIdleThreadId);
  killThread(&scanIdleSessionsThreadId);
  
  if(enableDBsupport)
    killThread(&dbUpdateThreadId);
  
  if(isLsofPresent)
    killThread(&lsofThreadId);
  
#ifdef ASYNC_ADDRESS_RESOLUTION
  if(numericFlag == 0)
    killThread(&dequeueAddressThreadId);
#endif
  
  killThread(&handleWebConnectionsThreadId);
  
#ifdef FULL_MEMORY_FREE
  cleanupAddressQueue();
  cleanupPacketQueue();
#endif
#endif

#else /* #ifndef WIN32 */

  /*
    TW 06.11.2001 
    Wies-Software <wies@wiessoft.de>
    
    #else clause added to force dequeue threads to terminate
    USE_SEMAPHORES is *NOT* tested!!!
  */
#ifdef MULTITHREADED
#ifdef USE_SEMAPHORES
  incrementSem(&queueSem);
#ifdef ASYNC_ADDRESS_RESOLUTION
  incrementSem(&queueAddressSem);
#endif
#else
  signalCondvar(&queueCondvar);
#ifdef ASYNC_ADDRESS_RESOLUTION
  signalCondvar(&queueAddressCondvar);
#endif
#endif
#endif /* MULTITREADED */
#endif /* #ifndef WIN32 */
  
#ifdef MULTITHREADED
  traceEvent(TRACE_INFO, "Waiting until threads terminate...\n");
  sleep(3); /* Just to wait until threads complete */
#endif

/* #ifdef FULL_MEMORY_FREE */
  freeHostInstances();
/* #endif */

#ifndef MICRO_NTOP
  unloadPlugins();
#endif
  termLogger();
  (void)fflush(stdout);

  termIPServices();
  termIPSessions();
  termNetFlowExporter();
  termPassiveSessions();
  
#ifndef WIN32
  endservent();
#endif

#ifdef MULTITHREADED
  deleteMutex(&packetQueueMutex);
  deleteMutex(&addressResolutionMutex);
  deleteMutex(&hashResizeMutex);
  deleteMutex(&hostsHashMutex);
  deleteMutex(&graphMutex);
  if(isLsofPresent)
    deleteMutex(&lsofMutex);
#ifdef USE_SEMAPHORES
  deleteSem(&queueSem);
#ifdef ASYNC_ADDRESS_RESOLUTION
  deleteSem(&queueAddressSem);
#endif
#else
  deleteCondvar(&queueCondvar);
#ifdef ASYNC_ADDRESS_RESOLUTION
  deleteCondvar(&queueAddressCondvar);
#endif
#endif
#endif

#ifdef HAVE_GDBM_H
#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "cleanup");
#endif 
  gdbm_close(gdbm_file);     gdbm_file = NULL;
  gdbm_close(pwFile);        pwFile = NULL;
  /* Courtesy of Wies-Software <wies@wiessoft.de> */
  gdbm_close(hostsInfoFile); hostsInfoFile = NULL; 
  if(eventFile != NULL) {
    gdbm_close(eventFile);
    eventFile = NULL;
  }
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif

#ifdef MULTITHREADED
  deleteMutex(&gdbmMutex);
#endif
#endif
  
  for(i=0; i<numDevices; i++) {
    int j;
      
    traceEvent(TRACE_INFO, "Freeing device %s (idx=%d)...", device[i].name, i);

    if(!device[i].virtualDevice) {
      if (pcap_stats(device[i].pcapPtr, &stat) >= 0) {
	traceEvent(TRACE_INFO, "%s packets received by filter on %s\n",
		   formatPkts((TrafficCounter)stat.ps_recv), device[i].name);
	traceEvent(TRACE_INFO, "%s packets dropped by kernel\n",
		   formatPkts((TrafficCounter)(stat.ps_drop)));
#ifdef MULTITHREADED
	traceEvent(TRACE_INFO, "%s packets dropped by ntop\n",
		   formatPkts(device[i].droppedPkts));
#endif
      }
    }

    if(device[i].ipTrafficMatrix != NULL) {

      /* Courtesy of Wies-Software <wies@wiessoft.de> */
      for(j=0; j<(device[i].numHosts*device[i].numHosts); j++)
        if(device[i].ipTrafficMatrix[j] != NULL) 
	  free(device[i].ipTrafficMatrix[j]);
      
      free(device[i].ipTrafficMatrix);
    }
      
    if(device[i].ipTrafficMatrix != NULL) 
      free(device[i].ipTrafficMatrix);

    if(device[i].ipTrafficMatrixHosts != NULL) 
      free(device[i].ipTrafficMatrixHosts);

    if(device[i].ipProtoStats != NULL)
      free(device[i].ipProtoStats);
      
    if(device[i].hash_hostTraffic != NULL)
      free(device[i].hash_hostTraffic);
      
    if(device[i].tcpSession != NULL)
      free(device[i].tcpSession);

    free(device[i].name);

    if(device[i].pcapDumper != NULL)
      pcap_dump_close(device[i].pcapDumper);
      
    if(device[i].pcapErrDumper != NULL)
      pcap_dump_close(device[i].pcapErrDumper);
      
    /* 
       Wies-Software <wies@wiessoft.de> on 06/11/2001 says:
       device[i].pcapPtr seems to be already freed. further tests needed! 
    */
    if(device[i].pcapPtr != NULL)
      free(device[i].pcapPtr);
  }

  free(device);

  if(numProcesses > 0)
    free(processes);
  
  if(enableDBsupport) {
    closeSQLsocket(); /* *** SQL Engine *** */
#ifdef HAVE_MYSQL
    closemySQLsocket();
#endif
  }

#ifdef WIN32
  termWinsock32();
#endif

  endNtop = 1;

#ifdef MEMORY_DEBUG
  traceEvent(TRACE_INFO, "===================================\n");
  termLeaks();
  traceEvent(TRACE_INFO, "===================================\n");
#endif
  exit(0);
}
