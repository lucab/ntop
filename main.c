/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
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
#include "globals-report.h"

#if defined(WIN32) && defined(__GNUC__)	/* mingw compiler */
 /* we're using the winpcap getopt() implementation
  * which has the globals inside the dll, so a simple
  * extern declaration is insufficient on win32
  *
  * Scott Renfro <scott@renfro.org>
  *
  */
extern __attribute__((dllimport)) char *optarg;
#else  /* !WIN32 */
extern char *optarg;
#endif

#if defined(NEED_INET_ATON)
/*
 * Minimal implementation of inet_aton.
 * Cannot distinguish between failure and a local broadcast address.
 */

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif


static int inet_aton(const char *cp, struct in_addr *addr)
{
  addr->s_addr = inet_addr(cp);
  return (addr->s_addr == INADDR_NONE) ? 0 : 1;
}

#endif

/* That's the meat */
int main(int argc, char *argv[]) {
  int pflag, i, len;
#ifdef WIN32
  int optind=0;
#else
  int userId=0, groupId=0;
#endif
  int op, mergeInterfaces=1;
  int enableDBsupport=0;
  int enableThUpdate=1;
  int enableIdleHosts=1;
  char *cp, *localAddresses=NULL, *webAddr=NULL, *devices, *sslAddr=NULL;
  char *flowSpecs, *protoSpecs, rulesFile[128], ifStr[196], *theOpts;
  time_t lastTime;

  printf("Wait please: ntop is coming up...\n");

  ntop_argc = argc;
  ntop_argv = argv;

  currentFilterExpression = NULL;
  
#ifndef WIN32
  if (freopen("/dev/null", "w", stderr) == NULL) {
    traceEvent(TRACE_WARNING,
	       "ntop: unable to replace stderr with /dev/null: %s\n",
	       strerror(errno));
  }
#endif

#ifdef MEMORY_DEBUG
  initLeaks();
#endif

  webPort = NTOP_DEFAULT_WEB_PORT;
#ifdef HAVE_OPENSSL
  sslPort = 0; /* Disabled: it can enabled using -W <SSL port> */
#endif

  enableSuspiciousPacketDump = 0;
  usePersistentStorage = 0;
  stickyHosts = 0;
  enableNetFlowSupport = 0;

  /* Initialization of local variables */
  isLsofPresent = isNmapPresent = filterExpressionInExtraFrame = 0;

  rulesFile[0] = '\0';
  flowSpecs = NULL;
  protoSpecs = NULL;
  flowsList = NULL;
  localAddrFlag = 1;
  logTimeout = 0;
  tcpChain = NULL, udpChain = NULL, icmpChain = NULL;
  devices = NULL;
  daemonMode = pflag = numericFlag = debugMode = 0;

#ifndef WIN32
  useSyslog = 0;
#endif

  refreshRate = 0;
  rFileName = NULL;
  maxHashSize = MAX_HASH_SIZE;
  traceLevel = DEFAULT_TRACE_LEVEL;
  accuracyLevel = HIGH_ACCURACY_LEVEL;
  domainName[0] = '\0';
  /*
    If you need a good mapper look at this
    http://jake.ntop.org/cgi-bin/mapper.pl
  */
  mapperURL[0] = '\0';
  pcapLog = NULL;
  actTime = time(NULL);
  strncpy(dbPath, DBFILE_DIR, sizeof(dbPath));

  if ((cp = strrchr(argv[0], '/')) != NULL)
    program_name = cp + 1;
  else
    program_name = argv[0];

  if(strcmp(program_name, "ntopd") == 0) {
    daemonMode++;
  }

#ifdef WIN32
  theOpts = "ce:f:F:hr:p:i:nw:m:b:B:D:s:P:R:S:g:t:a:W:12l:qU:kA:jB:";
#else
  theOpts = "cIdEe:f:F:hr:i:p:nNw:m:b:v:D:s:P:R:MS:g:t:a:u:W:12l:qU:kKLA:jB:";
#endif

  while((op = getopt(argc, argv, theOpts)) != EOF) {
    switch (op) {
      /* Courtesy of Ralf Amandi <Ralf.Amandi@accordata.net> */

    case 'c': /* Sticky hosts = hosts that are not purged
		 when idle */
      stickyHosts = 1;
      break;

    case 'P': /* DB-Path */
      stringSanityCheck(optarg);
      strncpy(dbPath, optarg, sizeof(dbPath)-1)[sizeof(dbPath)-1] = '\0';
      break;

    case 'a': /* ntop access log path */
      stringSanityCheck(optarg);
      strncpy(accessLogPath, optarg,
	      sizeof(accessLogPath)-1)[sizeof(accessLogPath)-1] = '\0';
      break;

#ifndef WIN32
    case 'd':
      daemonMode=1;
      break;

    case 'I': /* Interactive mode */
      printf("intop provides you curses support. "
	     "ntop -I is no longer used.\n");
      return(-1);
#endif

    case 'q': /* allow ntop to save suspicious packets
		 in a file in pcap (tcpdump) format */
      enableSuspiciousPacketDump=1;
      break;

    case '1': /* disable throughput update */
      enableThUpdate=0;
      break;

    case '2': /* disable purging of idle hosts */
      enableIdleHosts=0;
      break;

    case 'l':
      stringSanityCheck(optarg);
      pcapLog = optarg;
      break;

    case 'b': /* host:port */
      stringSanityCheck(optarg);
      handleDbSupport(optarg, &enableDBsupport);
      break;

    case 'g': /* host:port */
      stringSanityCheck(optarg);
      handleNetFlowSupport(optarg);
      break;

#ifdef HAVE_MYSQL
    case 'v': /* username:password:dbname:host */
      stringSanityCheck(optarg);
      handlemySQLSupport(optarg, &enableDBsupport);
      break;
#endif

    case 'D': /* domain */
      stringSanityCheck(optarg);
      strncpy(domainName, optarg,
	      sizeof(domainName)-1)[sizeof(domainName)-1] = '\0';
      break;
	
    case 'f':
      isLsofPresent = 0; /* Don't make debugging too complex */
      rFileName = optarg;
      break;
	
    case 'r':
      if(!isdigit(optarg[0])) {
	printf("FATAL ERROR: flag -r expects a numeric argument.\n");
	exit(-1);
      }
      refreshRate = atoi(optarg);
      break;

#ifndef MICRO_NTOP
    case 'e':
      maxNumLines = atoi(optarg);
      break;
#endif

    case 'E':
      isLsofPresent  = checkCommand("lsof");
      isNmapPresent  = checkCommand("nmap");
      break;

    case 's':
      maxHashSize = atoi(optarg);
      if(maxHashSize < 64) {
	maxHashSize = 64;
	traceEvent(TRACE_INFO, "Max hash size set to 64 (minimum hash size)");
      }
      break;

    case 'i':
      stringSanityCheck(optarg);
      devices = optarg;
      break;

    case 'p':
      stringSanityCheck(optarg);
      len = strlen(optarg);
      if(len > 2048) len = 2048;
      protoSpecs = (char*)malloc(len+1);
      memset(protoSpecs, 0, len+1);
      strncpy(protoSpecs, optarg, len);
      break;

    case 'F':
      stringSanityCheck(optarg);
      len = strlen(optarg);
      if(len > 2048) len = 2048;
      flowSpecs = (char*)malloc(len+1);
      memset(flowSpecs, 0, len+1);
      strncpy(flowSpecs, optarg, len);
      break;

    case 'm':
      stringSanityCheck(optarg);
      localAddresses = strdup(optarg);
      break;

    case 'n':
      numericFlag++;
      break;

    case 'N':
      isNmapPresent = 0;
      break;

    case 'j':
      /*
	In this mode ntop sniffs from an interface on which
	 the traffic has been mirrored hence:
	 - MAC addresses are not used at all but just IP addresses
	 - ARP packets are not handled
      */
      borderSnifferMode = 1;
      break;

    case 'w':
      stringSanityCheck(optarg);
      if(!isdigit(optarg[0])) {
	printf("FATAL ERROR: flag -w expects a numeric argument.\n");
	exit(-1);
      }

      /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
      if ((webAddr = strchr(optarg,':'))) {
	/* DS: Search for : to find xxx.xxx.xxx.xxx:port */
	/* This code is to be able to bind to a particular interface */
	*webAddr = '\0';
	webPort = atoi(webAddr+1);
	webAddr = optarg;
      } else {
	webPort = atoi(optarg);
      }
      break;

#ifdef HAVE_OPENSSL
    case 'W':
      stringSanityCheck(optarg);
      if(!isdigit(optarg[0])) {
	printf("FATAL ERROR: flag -W expects a numeric argument.\n");
	exit(-1);
      }

      /*
	lets swipe the same address binding code from -w above
	Curtis Doty <Curtis@GreenKey.net>
      */
      if((sslAddr = strchr(optarg,':'))) {
	*sslAddr = '\0';
	sslPort = atoi(sslAddr+1);
	sslAddr = optarg;
      } else {
	sslPort = atoi(optarg);
      }

      break;
#endif

    case 'R':
      stringSanityCheck(optarg);
      strncpy(rulesFile, optarg,
	      sizeof(rulesFile)-1)[sizeof(rulesFile)-1] = '\0';
      break;

    case 'M':
      mergeInterfaces = 0;
      break;

    case 'S':
      /*
	Persitent storage only for 'local' machines
	Courtesy of Joel Crisp <jcrisp@dyn21-126.trilogy.com>

	0 = no storage
	1 = store all hosts
	2 = store only local hosts
      */
      usePersistentStorage = atoi(optarg);
      if((usePersistentStorage > 2)
	 || (usePersistentStorage < 0)){
	printf("FATAL ERROR: -S flag accepts value in the 0-2 range.\n");
	exit(-1);
      }
      break;

    case 't':
      /* Trace Level Initialization */
      traceLevel = atoi(optarg);
      if(traceLevel > DETAIL_TRACE_LEVEL)
	traceLevel = DETAIL_TRACE_LEVEL;
      break;

    case 'A':
      /* Accuracy Level */
      accuracyLevel = atoi(optarg);
      if(accuracyLevel > HIGH_ACCURACY_LEVEL)
	accuracyLevel = HIGH_ACCURACY_LEVEL;
      break;

#ifndef WIN32
    case 'u':
      stringSanityCheck(optarg);
      if(strOnlyDigits(optarg))
	userId = atoi(optarg);
      else {
	struct passwd *pw;
	pw = getpwnam(optarg);
	if(pw == NULL) {
	  printf("FATAL ERROR: Unknown user %s.\n", optarg);
	  exit(-1);
	}
	userId = pw->pw_uid;
	groupId = pw->pw_gid;
	endpwent();
      }
      break;
#endif /* WIN32 */

    case 'U': /* host:port */
      if(strlen(optarg) >= (sizeof(mapperURL)-1)) {
	strncpy(mapperURL, optarg, sizeof(mapperURL)-2);
	mapperURL[sizeof(mapperURL)-1] = '\0';
      } else
	strcpy(mapperURL, optarg);
      break;
	
    case 'k':
      /* update info of used kernel filter expression in extra frame */
      filterExpressionInExtraFrame=1;
      break;

#ifndef WIN32	
    case 'K':
      debugMode = 1;
      break;

    case 'L':
      useSyslog = 1;
      break;
#endif
      
    case 'B':
      stringSanityCheck(optarg);
      currentFilterExpression = (char*)malloc(strlen(optarg)+1);
      strcpy(currentFilterExpression, optarg);
      break;

    default:
      usage();
      exit(-1);
      /* NOTREACHED */
    }
  }  

  if(webPort == 0) {
#ifdef HAVE_OPENSSL
    if(sslPort == 0) {
      traceEvent(TRACE_ERROR,
		 "FATAL ERROR: both -W and -w can't be set to 0.\n");
      exit(-1);
    }
#else
    traceEvent(TRACE_ERROR,
	       "FATAL ERROR: -w can't be set to 0.\n");
    exit(-1);
#endif
  }

  /* ***************************** */

#ifdef HAVE_OPENSSL
  if(sslPort == 0)
    traceEvent(TRACE_INFO, "SSL is present but https is disabled: "
	       "use -W <https port> for enabling it\n");
#endif

  initIPServices();

  snprintf(accessLogPath, sizeof(accessLogPath), "%s/%s",
	   dbPath, DETAIL_ACCESS_LOG_FILE_PATH);

  initLogger(); /* Do not call this function before dbPath
		   is initialized */

  initGlobalValues();

#ifndef MICRO_NTOP
  reportValues(&lastTime);
#endif /* MICRO_NTOP */
  postCommandLineArgumentsInitialization(&lastTime);
  initGdbm();

  initDevices(devices);

  traceEvent(TRACE_INFO, "ntop v.%s %s [%s] (%s build)",
	     version, THREAD_MODE, osName, buildDate);

  ifStr[0] = '\0';
  if(rFileName != NULL)
    strncpy(ifStr, PCAP_NW_INTERFACE, sizeof(ifStr));
  else
    for(i=0; i<numDevices; i++) {
      char tmpBuf[48];

      if(i>0) {
	if(snprintf(tmpBuf, sizeof(tmpBuf), ",%s", device[i].name)  < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      } else {
	if(snprintf(tmpBuf, sizeof(tmpBuf), "%s", device[i].name) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      }
      strncat(ifStr, tmpBuf, sizeof(ifStr)-strlen(ifStr)-1)[sizeof(ifStr)-1] = '\0';
    }

  traceEvent(TRACE_INFO, "Listening on [%s]", ifStr);
  traceEvent(TRACE_INFO, "Copyright 1998-2002 by %s\n", author);
  traceEvent(TRACE_INFO, "Get the freshest ntop from http://www.ntop.org/\n");
  traceEvent(TRACE_INFO, "Initializing...\n");

  initLibpcap(rulesFile, numDevices);
#ifndef MICRO_NTOP
  loadPlugins();
#endif

  /*
    Code fragment below courtesy of
    Andreas Pfaller <a.pfaller@pop.gun.de>
  */

#ifndef WIN32
  if((getuid() != geteuid()) || (getgid() != getegid())) {
    /* setuid binary, drop privileges */
    if (setgid(getgid())!=0 || setuid(getuid())!=0) {
      traceEvent(TRACE_ERROR,
		 "FATAL ERROR: Unable to drop privileges.\n");
      exit(-1);
    }
  }

  if((userId != 0) || (groupId != 0)){
    /* user id specified on commandline */
    if ((setgid(groupId) != 0) || (setuid(userId) != 0)) {
      traceEvent(TRACE_ERROR, "FATAL ERROR: Unable to change user ID.\n");
      exit(-1);
    }
  }

  if((geteuid() == 0) || (getegid() == 0)) {
    traceEvent(TRACE_INFO, "WARNING: For security reasons it is STRONGLY recommended to");
    traceEvent(TRACE_INFO, "WARNING: run ntop as unprivileged user by using the -u option!");
  }
#endif

  if(localAddresses != NULL) {
    handleLocalAddresses(localAddresses);
    free(localAddresses);
    localAddresses = NULL;
  }

  initDeviceDatalink();
  if(currentFilterExpression != NULL)
    parseTrafficFilter();
  else
     currentFilterExpression = strdup(""); /* so that it isn't NULL! */

  /* Handle flows (if any) */
  if(flowSpecs != NULL) {
    if(flowSpecs[0] != '\0')
      handleFlowsSpecs(flowSpecs);
    free(flowSpecs);
  }

  /* Patch courtesy of Burton M. Strauss III <BStrauss3@attbi.com> */
  if(protoSpecs != NULL) {
    if(protoSpecs[0] != '\0')
      handleProtocols(protoSpecs);
    free(protoSpecs);
  }

  initCounters(mergeInterfaces);
  initApps();
  initSignals();

  initThreads(enableThUpdate, enableIdleHosts, enableDBsupport);
#ifndef MICRO_NTOP
  startPlugins();
#endif
  initWeb(webPort, webAddr, sslAddr);

  traceEvent(TRACE_INFO, "Sniffying...\n");

#ifdef MEMORY_DEBUG
  resetLeaks();
#endif

  /*
    In multithread mode, a separate thread handles
    packet sniffing
  */
#ifndef MULTITHREADED
  packetCaptureLoop(&lastTime, refreshRate);
#else
  startSniffer();
#endif

#ifndef WIN32
  pause();
#endif
  while(!endNtop) 
    sleep(30);

  return(0);
}
