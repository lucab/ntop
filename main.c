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

/*
  Ntop options list
  -- converted to getopts_long, Burton M. Strauss III (BStrauss@acm.org)
*/
#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif

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

void usage(void) {
  char buf[80];

  if(snprintf(buf, sizeof(buf), "%s v.%s %s [%s] (%s build)",
	      myGlobals.program_name, version, THREAD_MODE, osName, buildDate) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  traceEvent(TRACE_INFO, "%s\n", buf);

  traceEvent(TRACE_INFO, "Copyright 1998-2001 by %s\n", author);
  traceEvent(TRACE_INFO, "Get the freshest ntop from http://www.ntop.org/\n");
  if(snprintf(buf, sizeof(buf), "Written by %s.", author) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");

  traceEvent(TRACE_INFO, "%s\n", buf);

  if(snprintf(buf, sizeof(buf), "Usage: %s", myGlobals.program_name) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");

  traceEvent(TRACE_INFO, "%s\n", buf);

#ifdef HAVE_GETOPT_LONG
  traceEvent(TRACE_INFO, "    [-c | --sticky-hosts]                     idle hosts are not purged from hash\n");
#ifdef WIN32
  traceEvent(TRACE_INFO, "    [-r <number> | --refresh-time <number>]   refresh time in seconds, default is %d\n", REFRESH_TIME);
#else
  traceEvent(TRACE_INFO, "    [-r <number> | --refresh-time <number>]   refresh time in seconds, default is %d (interactive) or %d (web)\n",
 	     ALARM_TIME, REFRESH_TIME);
#endif
  traceEvent(TRACE_INFO, "    [-f <file> | --traffic-dump-file <file>]  traffic dump file (see tcpdump)\n");
#ifndef WIN32
  traceEvent(TRACE_INFO, "    [-E | --enable-external-tools]            enable lsof/nmap integration (if present)\n");
#endif
  traceEvent(TRACE_INFO, "    [-n | --numeric-ip-addresses]             numeric IP addresses - no DNS resolution\n");
  traceEvent(TRACE_INFO, "    [-p <list> | --protocols <list>]          List of IP protocols to monitor (see man page)\n");
#ifndef WIN32
  traceEvent(TRACE_INFO, "    [-i <name> | --interface <name>]          Interface name or names to monitor\n");
#else
  traceEvent(TRACE_INFO, "    [-i <number> | --interface <number>]      Interface index number to monitor\n");
#endif
  traceEvent(TRACE_INFO, "    [-S <number> | --store-mode <number>]     Persistant storage mode [0-none, 1-local, 2-all\n");
  traceEvent(TRACE_INFO, "    [-w <port> | --http-server]               Web server (http:) port (or address:port) to listen on\n");
#ifdef HAVE_OPENSSL
  traceEvent(TRACE_INFO, "    [-W <port> | --https-server]              Web server (https:) port (or address:port) to listen on\n");
#endif
  traceEvent(TRACE_INFO, "    [-D <name> | --domain <name>]             Internet domain name\n");
  traceEvent(TRACE_INFO, "    [-e <number> | --max-table-rows <number>] Maximum number of table rows to report\n");
#ifndef WIN32
  traceEvent(TRACE_INFO, "    [-d | --daemon ]                          Run ntop in daemon mode\n");
#endif
  traceEvent(TRACE_INFO, "    [-m <addresses> | --local-subnets <addresses>] Local subnetwork(s) (see man page)\n");
  traceEvent(TRACE_INFO, "    [-s <number> | --max-hash-size <number>]  Maximum hash table size, default = %d\n", MAX_HASH_SIZE);
  traceEvent(TRACE_INFO, "    [-F <spec> | --flow-spec <specs>]         Flow specs (see man page)\n");
  traceEvent(TRACE_INFO, "    [-b <host:port> | --sql-host <host:port>] SQL host for ntop database\n");
#ifdef HAVE_MYSQL
  traceEvent(TRACE_INFO, "    [-v <username:password:dbName> | --mysql-host <username:password:dbName>] MySQL host for ntop database\n");
#endif
  traceEvent(TRACE_INFO, "    [-R <file> | --filter-rule <file>]        matching rules file\n");
  traceEvent(TRACE_INFO, "    [-N | --no-nmap]                          don't use nmap even if installed\n");
  traceEvent(TRACE_INFO, "    [-M | --no-interface-merge]               don't merge network interfaces (see man page)\n");
  traceEvent(TRACE_INFO, "    [-q | --create-suspicious-packets         create file ntop-suspicious-pkts.XXX.pcap file\n");
  traceEvent(TRACE_INFO, "    [-l <path> | --pcap-log <path>            Dump packets captured to a file (debug only!)\n");
  traceEvent(TRACE_INFO, "    [-P <path> | --db-file-path <path>        Path for ntop internal database files\n");
  traceEvent(TRACE_INFO, "    [-a <path> | --access-log-path <path>     Path for ntop web server access log\n");
  traceEvent(TRACE_INFO, "    [-g <host:port> | --cisco-netflow-host <host:port>] Cisco NetFlow host and port\n");
  traceEvent(TRACE_INFO, "    [-t <number> | --trace-level <number>]    Trace level [0-5]\n");
  traceEvent(TRACE_INFO, "    [-A <number> | --accuracy-level <number>] Accuracy level [0-2]\n");
  traceEvent(TRACE_INFO, "    [-u <user> | --user <user>]               Userid/name to run ntop under (see man page)\n");
  traceEvent(TRACE_INFO, "    [-U <URL> | --mapper <URL>]               URL (mapper.pl) for displaying host location\n");
  traceEvent(TRACE_INFO, "    [-k | --filter-expression-in-extra-frame] Show kernel filter expression in extra frame\n");
  traceEvent(TRACE_INFO, "    [-j | --border-sniffer-mode]              Set ntop in border/gateway sniffing mode\n");
  traceEvent(TRACE_INFO, "    [-B <filter expression>]                  Packet filter expression, like tcpdump\n\n\n");

#else /* !HAVE_GETOPT_LONG */
  traceEvent(TRACE_INFO, "    %s\n",   "[-c <sticky hosts: idle hosts are not purged from hash>]");
#ifdef WIN32
  traceEvent(TRACE_INFO, "    [-r <refresh time (web = %d sec)>]\n", REFRESH_TIME);
#else
  traceEvent(TRACE_INFO, "    [-r <refresh time (interactive = %d sec/web = %d sec)>]\n",
	     ALARM_TIME, REFRESH_TIME);
#endif
  traceEvent(TRACE_INFO, "    %s\n",   "[-f <traffic dump file (see tcpdump)>]");
#ifndef WIN32
  traceEvent(TRACE_INFO, "    %s\n",   "[-E <enable lsof/nmap integration (if present)>]");
#endif
  traceEvent(TRACE_INFO, "    %s\n",   "[-n (numeric IP addresses)]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-p <IP protocols to monitor> (see man page)]");
#ifndef WIN32
  traceEvent(TRACE_INFO, "    %s\n",   "[-i <interface>]");
#else
  traceEvent(TRACE_INFO, "    %s\n",   "[-i <interface index>]");
#endif
  traceEvent(TRACE_INFO, "    %s\n",   "[-S <store mode> (store persistently host stats)]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-w <HTTP port>]");
#ifdef HAVE_OPENSSL
  traceEvent(TRACE_INFO, "    %s\n",   "[-W <HTTPS port>]");
#endif
  traceEvent(TRACE_INFO, "    %s\n",   "[-D <Internet domain name>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-e <max # table rows)]");
#ifndef WIN32
  traceEvent(TRACE_INFO, "    %s\n",   "[-d (run ntop in daemon mode)]");
#endif
  traceEvent(TRACE_INFO, "    %s\n",   "[-m <local addresses (see man page)>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-s <max hash size (default 32768)>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-F <flow specs (see man page)>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-b <client:port (ntop DB client)>]");
#ifdef HAVE_MYSQL
  traceEvent(TRACE_INFO, "    %s\n",   "[-v <username:password:dbName (ntop mySQL client)>]");
#endif
  traceEvent(TRACE_INFO, "    %s\n",   "[-R <matching rules file>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-N <don't use nmap if installed>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-M <don't merge network interfaces (see man page)>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-q <create file ntop-suspicious-pkts.XXX.pcap>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-l <path> (dump packets captured on a file: debug only!)]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-P <path for db-files>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-g <client:port (Cisco NetFlow client)>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-t (trace level [0-5])]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-A (accuracy level [0-2])]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-u <userid> | <username> (see man page)]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-U <mapper.pl URL> | \"\" for not displaying host location ]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-k <show kernel filter expression in extra frame>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-j (set ntop in border gateway sniffing mode)]");
#ifndef WIN32
  traceEvent(TRACE_INFO, "    %s\n",   "[-K <enable application debug (no fork() is used)>]");
  traceEvent(TRACE_INFO, "    %s\n",   "[-L <use syslog instead of stdout>]");
#endif
  traceEvent(TRACE_INFO, "    %s\n\n", "[-B <filter expression (like tcpdump)>]");
#endif /* HAVE_GETOPT_LONG */
}


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
#ifdef HAVE_GETOPT_LONG
  int getop_long_index;
  static struct option long_options[] = {
    /* Common options */
    {"access-log-path", required_argument, NULL, 'a'},
    {"accuracy-level", required_argument, NULL, 'A'},
    {"border-sniffer-mode", no_argument, NULL, 'j'},
    {"cisco-netflow-host", required_argument, NULL, 'g'},
    {"create-suspicious-packets", no_argument, NULL, 'q'},
    {"db-file-path", required_argument, NULL, 'P'},
    {"domain", required_argument, NULL, 'D'},
    {"filter-expression-in-extra-frame", no_argument, NULL, 'k'},
    {"filter-rule", required_argument, NULL, 'R'},
    {"flow-spec", required_argument, NULL, 'F'},
    {"help", no_argument, NULL, 'h'}, /* dummy, uses default case to print usage */
    {"http-server", required_argument, NULL, 'w'},
#ifdef HAVE_OPENSSL
    {"https-server", required_argument, NULL, 'W'},
#endif
    {"interface", required_argument, NULL, 'i'},
    {"local-subnets", required_argument, NULL, 'm'},
    {"mapper", required_argument, NULL, 'U'},
    {"max-hash-size", required_argument, NULL, 's'},
#ifndef MICRO_NTOP
    {"max-table-rows", required_argument, NULL, 'e'},
#endif
    {"no-idle-host-purge", no_argument, NULL, '2'},
    {"no-throughput-update", no_argument, NULL, '1'},
    {"numeric-ip-addresses", no_argument, NULL, 'n'},
    {"pcap-log", required_argument, NULL, 'l'},
    {"protocols", required_argument, NULL, 'p'},
    {"refresh-time", required_argument, NULL, 'r'},
    {"sql-host", required_argument, NULL, 'b'},
    {"sticky-hosts", no_argument, NULL, 'c'},
    {"store-mode", required_argument, NULL, 'S'},
    {"trace-level", required_argument, NULL, 't'},
    {"traffic-dump-file", required_argument, NULL, 'f'},
    /* long ONLY options - put these here with numeric arguments, 
       over 127 (i.e. > ascii max char)
       (since op is unsigned this is fine)
       add corresponding case nnn: below
    */
#ifdef HAVE_GDCHART
    {"throughput-bar-chart", no_argument, NULL, 129},
#endif
    {"B", required_argument, NULL, 'B'}, /* can't find this! */
#if !defined(WIN32)
    {"daemon", no_argument, NULL, 'd'},
    {"debug", no_argument, NULL, 'K'},
    {"enable-external-tools", no_argument, NULL, 'E'},
    {"interactive-mode", no_argument, NULL, 'I'}, /* interactive mode no longer used */
#ifdef HAVE_MYSQL
    {"mysql-host", required_argument, NULL, 'v'},
#endif
    {"no-interface-merge", no_argument, NULL, 'M'},
    {"no-merge", no_argument, NULL, 'M'},
    {"no-nmap", no_argument, NULL, 'N'},
    {"user", required_argument, NULL, 'u'},
    {"use-syslog", no_argument, NULL, 'L'},
#endif
    {0, 0, 0, 0}
  };  
#endif /* HAVE_GETOPT_LONG */

  printf("Wait please: ntop is coming up...\n");

  initNtopGlobals();
  myGlobals.ntop_argc = argc;
  myGlobals.ntop_argv = argv;

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
  myGlobals.sslPort = 0; /* Disabled: it can enabled using -W <SSL port> */
#endif

  myGlobals.enableSuspiciousPacketDump = 0;
  myGlobals.usePersistentStorage = 0;
  myGlobals.stickyHosts = 0;
  myGlobals.enableNetFlowSupport = 0;

  /* Initialization of local variables */
  myGlobals.isLsofPresent = myGlobals.isNmapPresent = myGlobals.filterExpressionInExtraFrame = 0;

  rulesFile[0] = '\0';
  flowSpecs = NULL;
  protoSpecs = NULL;
  myGlobals.flowsList = NULL;
  localAddrFlag = 1;
  myGlobals.logTimeout = 0;
  myGlobals.tcpChain = NULL, myGlobals.udpChain = NULL, myGlobals.icmpChain = NULL;
  devices = NULL;
  myGlobals.daemonMode = pflag = myGlobals.numericFlag = myGlobals.debugMode = 0;

#ifndef WIN32
  myGlobals.useSyslog = 0;
#endif

  refreshRate = 0;
  myGlobals.rFileName = NULL;
  myGlobals.maxHashSize = MAX_HASH_SIZE;
  myGlobals.traceLevel = DEFAULT_TRACE_LEVEL;
  myGlobals.accuracyLevel = HIGH_ACCURACY_LEVEL;
  myGlobals.domainName[0] = '\0';
  /*
    If you need a good mapper look at this
    http://jake.ntop.org/cgi-bin/mapper.pl
  */
  myGlobals.mapperURL[0] = '\0';
  myGlobals.pcapLog = NULL;
  myGlobals.actTime = time(NULL);
  strncpy(myGlobals.dbPath, DBFILE_DIR, sizeof(myGlobals.dbPath));

  if ((cp = strrchr(argv[0], '/')) != NULL)
    myGlobals.program_name = cp + 1;
  else
    myGlobals.program_name = argv[0];
  myGlobals.currentFilterExpression = NULL;
  
  if(strcmp(myGlobals.program_name, "ntopd") == 0) {
    myGlobals.daemonMode++;
  }

#ifdef WIN32
  theOpts = "ce:f:F:hr:p:i:nw:m:b:B:D:s:P:R:S:g:t:a:W:12l:qU:kA:jB:";
#else
  theOpts = "cIdEe:f:F:hr:i:p:nNw:m:b:v:D:s:P:R:MS:g:t:a:u:W:12l:qU:kKLA:jB:";
#endif

#ifdef HAVE_GETOPT_LONG
  while((op = getopt_long(argc, argv, theOpts, long_options, &getop_long_index)) != EOF) {
#else
  while((op = getopt(argc, argv, theOpts)) != EOF) {
#endif
    switch (op) {
      /* Courtesy of Ralf Amandi <Ralf.Amandi@accordata.net> */

    case 'c': /* Sticky hosts = hosts that are not purged
		 when idle */
      myGlobals.stickyHosts = 1;
      break;

    case 'P': /* DB-Path */
      stringSanityCheck(optarg);
      strncpy(myGlobals.dbPath, optarg, sizeof(myGlobals.dbPath)-1)[sizeof(myGlobals.dbPath)-1] = '\0';
      break;

    case 'a': /* ntop access log path */
      stringSanityCheck(optarg);
      strncpy(myGlobals.accessLogPath, optarg,
	      sizeof(myGlobals.accessLogPath)-1)[sizeof(myGlobals.accessLogPath)-1] = '\0';
      break;

#ifndef WIN32
    case 'd':
      myGlobals.daemonMode=1;
      break;

    case 'I': /* Interactive mode */
      printf("intop provides you curses support. "
	     "ntop -I is no longer used.\n");
      return(-1);
#endif

    case 'q': /* allow ntop to save suspicious packets
		 in a file in pcap (tcpdump) format */
      myGlobals.enableSuspiciousPacketDump=1;
      break;

    case '1': /* disable throughput update */
      enableThUpdate=0;
      break;

    case '2': /* disable purging of idle hosts */
      enableIdleHosts=0;
      break;

    case 'l':
      stringSanityCheck(optarg);
      myGlobals.pcapLog = optarg;
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
      strncpy(myGlobals.domainName, optarg,
	      sizeof(myGlobals.domainName)-1)[sizeof(myGlobals.domainName)-1] = '\0';
      break;
	
    case 'f':
      myGlobals.isLsofPresent = 0; /* Don't make debugging too complex */
      myGlobals.rFileName = optarg;
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
      myGlobals.isLsofPresent  = checkCommand("lsof");
      myGlobals.isNmapPresent  = checkCommand("nmap");
      break;

    case 's':
      myGlobals.maxHashSize = atoi(optarg);
      if(myGlobals.maxHashSize < 64) {
	myGlobals.maxHashSize = 64;
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
      myGlobals.numericFlag++;
      break;

    case 'N':
      myGlobals.isNmapPresent = 0;
      break;

    case 'j':
      /*
	In this mode ntop sniffs from an interface on which
	 the traffic has been mirrored hence:
	 - MAC addresses are not used at all but just IP addresses
	 - ARP packets are not handled
      */
      myGlobals.borderSnifferMode = 1;
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
	myGlobals.sslPort = atoi(sslAddr+1);
	sslAddr = optarg;
      } else {
	myGlobals.sslPort = atoi(optarg);
      }

      break;
#endif

    case 'R':
      stringSanityCheck(optarg);
      strncpy(rulesFile, optarg,
	      sizeof(rulesFile)-1)[sizeof(rulesFile)-1] = '\0';
      break;

    case 'M':
      myGlobals.mergeInterfaces = 0;
      break;

    case 'S':
      /*
	Persitent storage only for 'local' machines
	Courtesy of Joel Crisp <jcrisp@dyn21-126.trilogy.com>

	0 = no storage
	1 = store all hosts
	2 = store only local hosts
      */
      myGlobals.usePersistentStorage = atoi(optarg);
      if((myGlobals.usePersistentStorage > 2)
	 || (myGlobals.usePersistentStorage < 0)){
	printf("FATAL ERROR: -S flag accepts value in the 0-2 range.\n");
	exit(-1);
      }
      break;

    case 't':
      /* Trace Level Initialization */
      myGlobals.traceLevel = atoi(optarg);
      if(myGlobals.traceLevel > DETAIL_TRACE_LEVEL)
	myGlobals.traceLevel = DETAIL_TRACE_LEVEL;
      break;

    case 'A':
      /* Accuracy Level */
      myGlobals.accuracyLevel = atoi(optarg);
      if(myGlobals.accuracyLevel > HIGH_ACCURACY_LEVEL)
	myGlobals.accuracyLevel = HIGH_ACCURACY_LEVEL;
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
      if(strlen(optarg) >= (sizeof(myGlobals.mapperURL)-1)) {
	strncpy(myGlobals.mapperURL, optarg, sizeof(myGlobals.mapperURL)-2);
	myGlobals.mapperURL[sizeof(myGlobals.mapperURL)-1] = '\0';
      } else
	strcpy(myGlobals.mapperURL, optarg);
      break;
	
    case 'k':
      /* update info of used kernel filter expression in extra frame */
      myGlobals.filterExpressionInExtraFrame=1;
      break;

#ifndef WIN32	
    case 'K':
      myGlobals.debugMode = 1;
      break;

    case 'L':
      myGlobals.useSyslog = 1;
      break;
#endif

    case 'B':
      stringSanityCheck(optarg);
      myGlobals.currentFilterExpression = (char*)malloc(strlen(optarg)+1);
      strcpy(myGlobals.currentFilterExpression, optarg);
      break;

    default:
      usage();
      exit(-1);
      /* NOTREACHED */
    }
  }  

  if(webPort == 0) {
#ifdef HAVE_OPENSSL
    if(myGlobals.sslPort == 0) {
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
  if(myGlobals.sslPort == 0)
    traceEvent(TRACE_INFO, "SSL is present but https is disabled: "
	       "use -W <https port> for enabling it\n");
#endif

  initIPServices();

  snprintf(myGlobals.accessLogPath, sizeof(myGlobals.accessLogPath), "%s/%s",
	   myGlobals.dbPath, DETAIL_ACCESS_LOG_FILE_PATH);

  initLogger(); /* Do not call this function before myGlobals.dbPath
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
  if(myGlobals.rFileName != NULL)
    strncpy(ifStr, PCAP_NW_INTERFACE, sizeof(ifStr));
  else
    for(i=0; i<myGlobals.numDevices; i++) {
      char tmpBuf[48];

      if(i>0) {
	if(snprintf(tmpBuf, sizeof(tmpBuf), ",%s", myGlobals.device[i].name)  < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      } else {
	if(snprintf(tmpBuf, sizeof(tmpBuf), "%s", myGlobals.device[i].name) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      }
      strncat(ifStr, tmpBuf, sizeof(ifStr)-strlen(ifStr)-1)[sizeof(ifStr)-1] = '\0';
    }

  traceEvent(TRACE_INFO, "Listening on [%s]", ifStr);
  traceEvent(TRACE_INFO, "Copyright 1998-2002 by %s\n", author);
  traceEvent(TRACE_INFO, "Get the freshest ntop from http://www.ntop.org/\n");
  traceEvent(TRACE_INFO, "Initializing...\n");

  initLibpcap(rulesFile, myGlobals.numDevices);
#ifndef MICRO_NTOP
  loadPlugins();
#endif

  /*
    Code fragment below courtesy of
    Andreas Pfaller <apfaller@yahoo.com.au>
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
  if(myGlobals.currentFilterExpression != NULL)
    parseTrafficFilter();
  else
    myGlobals.currentFilterExpression = strdup(""); /* so that it isn't NULL! */
  
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
  
  /* 
     Moved from initialize.c (postCommandLineArgumentsInitialization) so that we
     don't add the defaults if the user has given us at least SOMETHING to monitor 

     Fix courtesy of Burton M. Strauss III <BStrauss3@attbi.com>
  */
  if(myGlobals.numIpProtosToMonitor == 0)
    addDefaultProtocols();

  initCounters(myGlobals.mergeInterfaces);
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
  while(!myGlobals.endNtop) 
    sleep(30);

  return(0);
}
