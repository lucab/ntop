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
#include "globals-report.h"

extern char *optarg;


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
  int pflag, i;
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
  char flowSpecs[2048], rulesFile[128], ifStr[196], *theOpts;
  time_t lastTime;
  
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

  usePersistentStorage = 0;

  /* Initialization of local variables */
  isLsofPresent  = checkCommand("lsof");
  /* isLsofPresent = 0; */
  isNepedPresent = checkCommand("neped");
  isNmapPresent  = checkCommand("nmap");

  rulesFile[0] = '\0';
  flowSpecs[0] = '\0';
  flowsList = NULL;
  localAddrFlag = 1;
  logTimeout = 0;
  tcpChain = NULL, udpChain = NULL, icmpChain = NULL;
  devices = NULL;

  daemonMode = 0, pflag = 0, numericFlag=0;
  refreshRate = 0;
  rFileName = NULL, grabSessionInformation = 0;
  maxHashSize = MAX_HASH_SIZE;
  traceLevel = DEFAULT_TRACE_LEVEL;
  domainName[0] = '\0';

  actTime = time(NULL);
  strncpy(dbPath, DBFILE_DIR, sizeof(dbPath));

  if ((cp = strrchr(argv[0], '/')) != NULL)
    program_name = cp + 1;
  else
    program_name = argv[0];

  if(strcmp(program_name, "ntopd") == 0) {
    daemonMode++;
  }

  initIPServices();

#ifdef WIN32
  theOpts = "e:F:hr:p:i:nw:m:b:B:D:s:P:R:Sgt:a:W:12L";
#else
  theOpts = "Ide:f:F:hr:i:p:nNw:m:b:D:s:P:R:MSgt:a:u:W:12L";
#endif
  
  while((op = getopt(argc, argv, theOpts)) != EOF)
      switch (op) {
	/* Courtesy of Ralf Amandi <Ralf.Amandi@accordata.net> */
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
	traceEvent(TRACE_INFO, "intop provides you curses support. "
		   "ntop -I is no longer used.\n");
	return(-1);
#endif

#ifdef WIN32
      case 'B':
	SIZE_BUF=atoi(optarg)*1024;
	break;
#endif

      case '1': /* disable throughput update */
	enableThUpdate=0;
	break;

      case '2': /* disable purgin of idle hosts */
	enableIdleHosts=0;
	break;

      case 'b': /* host:port */
	stringSanityCheck(optarg);
	handleDbSupport(optarg, &enableDBsupport);
	break;

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
	  traceEvent(TRACE_ERROR, 
		     "FATAL ERROR: flag -r expects a numeric argument.\n");
	  exit(-1);
	}
	refreshRate = atoi(optarg);
	break;

#ifndef MICRO_NTOP
      case 'e':
	maxNumLines = atoi(optarg);
	break;
#endif

      case 's':
	maxHashSize = atoi(optarg);
	if(maxHashSize < 1024)
	  maxHashSize = 1024;
	break;

      case 'i':
	stringSanityCheck(optarg);
	devices = optarg;
	break;

      case 'p':
	stringSanityCheck(optarg);
	handleProtocols(optarg);
	break;

      case 'F':
	stringSanityCheck(optarg);
	strncpy(flowSpecs, optarg,
		sizeof(flowSpecs)-1)[sizeof(flowSpecs)-1] = '\0';
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

      case 'w':
	stringSanityCheck(optarg);
	if(!isdigit(optarg[0])) {
	  traceEvent(TRACE_ERROR, 
		     "FATAL ERROR: flag -w expects a numeric argument.\n");
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
	  traceEvent(TRACE_ERROR, 
		     "FATAL ERROR: flag -W expects a numeric argument.\n");
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
	usePersistentStorage = 1;
	break;

      case 'g':
	grabSessionInformation = 1;
	break;

      case 't':
	/* Trace Level Initialization */
	traceLevel = atoi(optarg);
	if(traceLevel > DETAIL_TRACE_LEVEL)
	  traceLevel = DETAIL_TRACE_LEVEL;
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
            traceEvent(TRACE_ERROR, "FATAL ERROR: Unkown user %s.\n",
                       optarg);
            exit(-1);
          }
          userId = pw->pw_uid;
          groupId = pw->pw_gid;
          endpwent();
        }
        break;
#endif /* WIN32 */

	
      case 'L':
	/* 
	   Persitent storage only for 'local' machines 
	   Courtesy of Joel Crisp <jcrisp@dyn21-126.trilogy.com>
	*/
	usePersistentStorage = 2;
	break;

      default:
	usage();
	exit(-1);
	/* NOTREACHED */
      }
 
  sprintf(accessLogPath, "%s/%s", dbPath, 
	  DETAIL_ACCESS_LOG_FILE_PATH, sizeof(accessLogPath));

  if(webPort == 0) {
#ifdef HAVE_OPENSSL
    if(sslPort == 0) {
      traceEvent(TRACE_ERROR, "FATAL ERROR: both -W and -w can't be set to 0.\n");
      exit(-1);
    }
#else
    traceEvent(TRACE_ERROR, "FATAL ERROR: -w can't be set to 0.\n");
    exit(-1);
#endif
  } 

  /* ***************************** */

#ifdef HAVE_OPENSSL
  if(sslPort == 0)
    traceEvent(TRACE_INFO, "SSL is present but https is disabled: "
	       "use -W <https port> for enabling it\n");
#endif

  initGlobalValues();
#ifndef MICRO_NTOP
  reportValues(&lastTime);
#endif /* MICRO_NTOP */
  postCommandLineArgumentsInitialization(&lastTime);
  initGdbm();
  initializeWeb();
  initReports();
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
  traceEvent(TRACE_INFO, "Copyright 1998-2001 by %s\n", author);
  traceEvent(TRACE_INFO, "Get the freshest ntop from http://www.ntop.org/\n");
  traceEvent(TRACE_INFO, "Initialising...\n");

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
    traceEvent(TRACE_INFO, "         run ntop as unprivileged user by using the -u option!");
  }
#endif

  if(localAddresses != NULL) {
    handleLocalAddresses(localAddresses);
    free(localAddresses);
    localAddresses = NULL;
  }

  initDeviceDatalink();
  parseTrafficFilter(argv, optind);

  /* Handle flows (if any) */
  if(flowSpecs[0] != '\0')
    handleFlowsSpecs(flowSpecs);

  initCounters(mergeInterfaces);
  initApps();
  initLogger();
  initSignals();

  initThreads(enableThUpdate, enableIdleHosts, enableDBsupport);
#ifndef MICRO_NTOP
  startPlugins();
#endif
  initWeb(webPort, webAddr, sslAddr);

  traceEvent(TRACE_INFO, "Sniffying...\n");
 
#ifdef MEMORY_DEBUG 
  ResetLeaks();
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
  while(!endNtop) sleep(1);

  return(0);
}
