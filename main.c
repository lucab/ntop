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
#include "globals-report.h"
#include "scsiUtils.h"

/*
  Ntop options list
  -- converted to getopts_long, Burton M. Strauss III (BStrauss@acm.org)
  -- if getopt_long isn't provided by the compiler (glibc), we have our own version in util.c
*/

extern char *optarg;

static char __free__ []   =
"  This program is free software; you can redistribute it and/or modify\n\
  it under the terms of the GNU General Public License as published by\n\
  the Free Software Foundation; either version 2 of the License, or\n\
  (at your option) any later version.";
static char __notice__ [] =
"  This program is distributed in the hope that it will be useful,\n\
  but WITHOUT ANY WARRANTY; without even the implied warranty of\n\
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n\
  GNU General Public License for more details.";

static char __see__ []    =
"  You should have received a copy of the GNU General Public License\n\
  along with this program. If not, write to the Free Software\n\
  Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.";


  /*
   * Please keep the array sorted;
   * However, locating the preferences file and userID are done only via the
   * command line and processing of the configured preference (via the web) is
   * dependent on the values of user ('u') and location of the preference file
   * ('P' option) and so these are processed separately.
   */
#ifdef WIN32
static char*  short_options = "4:6:a:bce:f:ghi:jkl:m:nop:qr:st:w:x:zAB:BD:F:MN:O:P:Q:S:U:VX:W:";
#elif defined(MAKE_WITH_SYSLOG)
static char*  short_options = "4:6:a:bcde:f:ghi:jkl:m:nop:qr:st:u:w:x:zAB:D:F:IKLMN:O:P:Q:S:U:VX:W:";
#else
static char*  short_options = "4:6:a:bcde:f:ghi:jkl:m:nop:qr:st:u:w:x:zAB:D:F:IKMN:O:P:Q:S:U:VX:W:";
#endif

static struct option const long_options[] = {
  { "ipv4",                             no_argument,       NULL, '4' },
  { "ipv6",                             no_argument,       NULL, '6' },
  { "access-log-file",                  required_argument, NULL, 'a' },
  { "disable-decoders",                 no_argument,       NULL, 'b' },
  { "sticky-hosts",                     no_argument,       NULL, 'c' },

#ifndef WIN32
  { "daemon",                           no_argument,       NULL, 'd' },
#endif
  { "max-table-rows",                   required_argument, NULL, 'e' },
  { "traffic-dump-file",                required_argument, NULL, 'f' },
  { "track-local-hosts",                no_argument,       NULL, 'g' },
  { "help",                             no_argument,       NULL, 'h' },
  { "interface",                        required_argument, NULL, 'i' },
  { "create-other-packets",             no_argument,       NULL, 'j' },
  { "pcap-log",                         required_argument, NULL, 'l' },
  { "local-subnets",                    required_argument, NULL, 'm' },
  { "numeric-ip-addresses",             no_argument,       NULL, 'n' },
  { "no-mac",                           no_argument,       NULL, 'o' },
  { "filter-expression-in-extra-frame", no_argument,       NULL, 'k' },


  { "protocols",                        required_argument, NULL, 'p' },
  { "create-suspicious-packets",        no_argument,       NULL, 'q' },
  { "refresh-time",                     required_argument, NULL, 'r' },
  { "no-promiscuous",                   no_argument,       NULL, 's' },
  { "trace-level",                      required_argument, NULL, 't' },

#ifndef WIN32
  { "user",                             required_argument, NULL, 'u' },
#endif

  { "http-server",                      required_argument, NULL, 'w' },
  { "disable-sessions",                 no_argument,       NULL, 'z' },
  { "filter-expression",                required_argument, NULL, 'B' },
  { "domain",                           required_argument, NULL, 'D' },

  { "flow-spec",                        required_argument, NULL, 'F' },

#ifndef WIN32
  { "debug",                            no_argument,       NULL, 'K' },
#endif

  { "no-interface-merge",               no_argument,       NULL, 'M' },

  { "wwn-map",                          required_argument, NULL, 'N' },
  
  { "output-packet-path",               required_argument, NULL, 'O' },
  { "db-file-path",                     required_argument, NULL, 'P' },
  { "spool-file-path",                  required_argument, NULL, 'Q' },
  { "mapper",                           required_argument, NULL, 'U' },
  { "version",                          no_argument,       0,    'V' },

#ifdef HAVE_OPENSSL
  { "https-server",                     required_argument, NULL, 'W' },
#endif

  /*
   * long ONLY options - put these here with numeric arguments,
   *  over 127 (i.e. > ascii max char)
   * (since op is unsigned this is fine)
   *  add corresponding case nnn: below
   */
#if !defined(WIN32) && defined(MAKE_WITH_SYSLOG)
  { "use-syslog",                       optional_argument, NULL, 131 },
#endif

#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  { "ssl-watchdog",                     no_argument,       NULL, 133 },
#endif

#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)
  { "disable-schedyield",               optional_argument, NULL, 134 },
#endif

  { "set-admin-password",               optional_argument, NULL, 135 },

  { "w3c",                              no_argument,       NULL, 136 },

  { "p3p-cp",                           required_argument, NULL, 137 },
  { "p3p-uri",                          required_argument, NULL, 138 },

#ifndef WIN32
  { "set-pcap-nonblocking",             no_argument,       NULL, 139 },
#endif

  { "disable-stopcap",                  no_argument,       NULL, 142 },
  { "disable-instantsessionpurge",      no_argument,       NULL, 144 },
  { "disable-mutexextrainfo",           no_argument,       NULL, 145 },

  { "fc-only",                          no_argument,       NULL, 147 },
  { "no-fc",                            no_argument,       0, 148 },
  { "no-invalid-lun",                   no_argument,       0, 149 },

  { "skip-version-check",               no_argument,       NULL, 150 },

  {NULL, 0, NULL, 0}
};

/* Forward */
static void loadPrefs(int argc, char* argv []);

/*
 * Hello World! This is ntop speaking...
 */
static void welcome (FILE * fp)
{
  fprintf (fp, "%s v.%s %s (configured on %s, built on %s)\n",
	   myGlobals.program_name, version, THREAD_MODE, configureDate, buildDate);

  fprintf (fp, "Copyright 1998-2004 by %s.\n", author);
  fprintf (fp, "Get the freshest ntop from http://www.ntop.org/\n");
}


/*
 * Wrong. Please try again accordingly to ....
 */
void usage(FILE * fp) {
  char *newLine = "";
  
#ifdef WIN32
  newLine = "\n\t";
#endif

  welcome(fp);

  fprintf(fp, "\nUsage: %s [OPTION]\n", myGlobals.program_name);

  fprintf(fp, "    [-h             | --help]                             %sDisplay this help and exit\n", newLine);
#ifndef WIN32
  fprintf(fp, "    [-u <user>      | --user <user>]                      %sUserid/name to run ntop under (see man page)\n", newLine);
#endif /* WIN32 */
  fprintf(fp, "    [-t <number>    | --trace-level <number>]             %sTrace level [0-6]\n", newLine);
  fprintf(fp, "    [-P <path>      | --db-file-path <path>]              %sPath for ntop internal database files\n", newLine);

#if 0
  fprintf(fp, "    [-4             | --ipv4]                             %sUse IPv4 connections\n",newLine);
  fprintf(fp, "    [-6             | --ipv6]                             %sUse IPv6 connections\n",newLine);
  fprintf(fp, "    [-a <file>      | --access-log-file <file>]           %sFile for ntop web server access log\n", newLine);
  fprintf(fp, "    [-b             | --disable-decoders]                 %sDisable protocol decoders\n", newLine);
  fprintf(fp, "    [-c             | --sticky-hosts]                     %sIdle hosts are not purged from memory\n", newLine);

#ifndef WIN32
  fprintf(fp, "    [-d             | --daemon]                           %sRun ntop in daemon mode\n", newLine);
#endif
  fprintf(fp, "    [-e <number>    | --max-table-rows <number>]          %sMaximum number of table rows to report\n", newLine);
  fprintf(fp, "    [-f <file>      | --traffic-dump-file <file>]         %sTraffic dump file (see tcpdump)\n", newLine);
  fprintf(fp, "    [-g             | --track-local-hosts]                %sTrack only local hosts\n", newLine);


#ifndef WIN32
  fprintf(fp, "    [-i <name>      | --interface <name>]                 %sInterface name or names to monitor\n", newLine);
#else
  fprintf(fp, "    [-i <number>    | --interface <number|name>]          %sInterface index number (or name) to monitor\n", newLine);
#endif
  fprintf(fp, "    [-j             | --create-other-packets]	         %sCreate file ntop-other-pkts.XXX.pcap file\n", newLine);
  fprintf(fp, "    [-o             | --no-mac]                           %sntop will trust just IP addresses (no MACs)\n", newLine);
  fprintf(fp, "    [-k             | --filter-expression-in-extra-frame] %sShow kernel filter expression in extra frame\n", newLine);
  fprintf(fp, "    [-l <path>      | --pcap-log <path>]                  %sDump packets captured to a file (debug only!)\n", newLine);
  fprintf(fp, "    [-m <addresses> | --local-subnets <addresses>]        %sLocal subnetwork(s) (see man page)\n", newLine);
  fprintf(fp, "    [-n             | --numeric-ip-addresses]             %sNumeric IP addresses - no DNS resolution\n", newLine);
  fprintf(fp, "    [-p <list>      | --protocols <list>]                 %sList of IP protocols to monitor (see man page)\n", newLine);
  fprintf(fp, "    [-q             | --create-suspicious-packets]        %sCreate file ntop-suspicious-pkts.XXX.pcap file\n", newLine);
  fprintf(fp, "    [-r <number>    | --refresh-time <number>]            %sRefresh time in seconds, default is %d\n",
	  newLine, DEFAULT_NTOP_AUTOREFRESH_INTERVAL);
  fprintf(fp, "    [-s             | --no-promiscuous]                   %sDisable promiscuous mode\n", newLine);


  fprintf(fp, "    [-x <max num hash entries> ]                          %sMax num. hash entries ntop can handle (default %u)\n", 
	  newLine, myGlobals.runningPref.maxNumHashEntries);
  fprintf(fp, "    [-w <port>      | --http-server <port>]               %sWeb server (http:) port (or address:port) to listen on\n", newLine);
  fprintf(fp, "    [-z             | --disable-sessions]                 %sDisable TCP session tracking\n", newLine);
  fprintf(fp, "    [-A]                                                  %sAsk admin user password and exit\n", newLine);
  fprintf(fp, "    [               | --set-admin-password=<pass>]        %sSet password for the admin user to <pass>\n", newLine);
  fprintf(fp, "    [               | --w3c]                              %sAdd extra headers to make better html\n", newLine);
  fprintf(fp, "    [-B <filter>]   | --filter-expression                 %sPacket filter expression, like tcpdump\n", newLine);
  fprintf(fp, "    [-D <name>      | --domain <name>]                    %sInternet domain name\n", newLine);

  fprintf(fp, "    [-F <spec>      | --flow-spec <specs>]                %sFlow specs (see man page)\n", newLine);

#ifndef WIN32
  fprintf(fp, "    [-K             | --enable-debug]                     %sEnable debug mode\n", newLine);
#ifdef MAKE_WITH_SYSLOG
  fprintf(fp, "    [-L]                                                  %sDo logging via syslog\n", newLine);
  fprintf(fp, "    [               | --use-syslog=<facility>]            %sDo logging via syslog, facility ('=' is REQUIRED)\n",
	  newLine);
#endif /* MAKE_WITH_SYSLOG */
#endif

  fprintf(fp, "    [-M             | --no-interface-merge]               %sDon't merge network interfaces (see man page)\n",
	  newLine);
  fprintf(fp, "    [-N             | --wwn-map]                          %sMap file providing map of WWN to FCID/VSAN\n", newLine);
  fprintf(fp, "    [-O <path>      | --pcap-file-path <path>]            %sPath for log files in pcap format\n", newLine);
  fprintf(fp, "    [-U <URL>       | --mapper <URL>]                     %sURL (mapper.pl) for displaying host location\n", 
	  newLine);
  fprintf(fp, "    [-V             | --version]                          %sOutput version information and exit\n", newLine);
  fprintf(fp, "    [-X <max num TCP sessions> ]                          %sMax num. TCP sessions ntop can handle (default %u)\n", 
	  newLine, myGlobals.runningPref.maxNumSessions);

#ifdef HAVE_OPENSSL
  fprintf(fp, "    [-W <port>      | --https-server <port>]              %sWeb server (https:) port (or address:port) to listen on\n", newLine);
#endif

/*  Please keep long-only options alphabetically ordered */

  fprintf(fp, "    [--disable-instantsessionpurge]                       %sDisable instant FIN session purge\n", newLine);
  fprintf(fp, "    [--disable-mutexextrainfo]                            %sDisable extra mutex info\n", newLine);
#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)
  fprintf(fp, "    [--disable-schedyield]                                %sTurn off sched_yield() calls, if ntop is deadlocking on them\n", newLine);
#endif
  fprintf(fp, "    [--disable-stopcap]                                   %sCapture packets even if there's no memory left\n", newLine);
  fprintf(fp, "    [--fc-only]                                           %sDisplay only Fibre Channel statistics\n", newLine);
  fprintf(fp, "    [--no-fc]                                             %sDisable processing & Display of Fibre Channel\n", newLine);
  fprintf(fp, "    [--no-invalid-lun]                                    %sDon't display Invalid LUN information\n", newLine);
  fprintf(fp, "    [--p3p-cp]                                            %sSet return value for p3p compact policy, header\n", newLine);
  fprintf(fp, "    [--p3p-uri]                                           %sSet return value for p3p policyref header\n", newLine);
#ifndef WIN32
  fprintf(fp, "    [--set-pcap-nonblocking]                              %sCall pcap_setnonblock\n", newLine);
#endif
  fprintf(fp, "    [--skip-version-check]                                %sSkip ntop version check\n", newLine);
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  fprintf(fp, "    [--ssl-watchdog]                                      %sUse ssl watchdog (NS6 problem)\n", newLine);
#endif
#endif /* #if 0 */

 fprintf(fp, "\n"
	 "NOTE\n"
	 "You can configure further ntop options via the web\n"
	 "interface [Menu Admin -> Config]\n\n");
  
#ifdef WIN32
  printAvailableInterfaces();
#endif
}

/* ******************************** */

static void loadPrefs(int argc, char* argv []) {
  datum key, nextkey;
  char buf[1024];
  int opt_index, opt;
#ifdef WIN32
  int optind=0;
#else
  bool userSpecified = FALSE;
#endif
  
  traceEvent(CONST_TRACE_NOISY, "NOTE: Calling getopt_long to process parameters");
  while ((opt = getopt_long(argc, argv, short_options, long_options, &opt_index)) != EOF) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG:DEBUG:  Entering loadPrefs()");
#endif
    switch (opt) {
    case 'h':                                /* help */
      usage(stdout);
      exit(0);

#ifndef WIN32
    case 'u':
      stringSanityCheck(optarg);
      myGlobals.effectiveUserName = strdup(optarg);
      if(strOnlyDigits(optarg))
	myGlobals.userId = atoi(optarg);
      else {
	struct passwd *pw;
	pw = getpwnam(optarg);
	if(pw == NULL) {
	  printf("FATAL ERROR: Unknown user %s.\n", optarg);
	  exit(-1);
	}
	myGlobals.userId = pw->pw_uid;
	myGlobals.groupId = pw->pw_gid;
	endpwent();
      }
      userSpecified = TRUE;
      break;
#endif /* WIN32 */

    case 't':
      /* Trace Level Initialization */
      myGlobals.runningPref.traceLevel = min(max(1, atoi(optarg)),
					     CONST_VERY_DETAIL_TRACE_LEVEL);
      /* DETAILED is NOISY + FileLine stamp, unless already set */
      break;
	  
    case 'P':
      stringSanityCheck(optarg);
      if(myGlobals.dbPath != NULL)
	free(myGlobals.dbPath);

      myGlobals.dbPath = strdup(optarg);
      break;
    }
  }

  /* ******************************* */

  /* open/create all the databases */
  initGdbm(NULL, NULL, 1);
    
  if(myGlobals.prefsFile == NULL) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: No preferences file to read from()");
#endif
    return;
  }

  /* Read preferences and store them in memory */
  key = gdbm_firstkey (myGlobals.prefsFile);
  while (key.dptr) {
    if (fetchPrefsValue (key.dptr, buf, sizeof (buf)) == 0) {
      processNtopPref (key.dptr, buf, FALSE, &myGlobals.runningPref);
    }
      
    nextkey = gdbm_nextkey (myGlobals.prefsFile, key);
    free (key.dptr);
    key = nextkey;
  }

  myGlobals.savedPref = myGlobals.runningPref;
}

/* ***************************************************** */

/*
 * Parse the command line options
 */
static int parseOptions(int argc, char* argv []) {
  int setAdminPw = 0, opt, userSpecified = 0;
  int opt_index;
  char *adminPw = NULL;
#ifdef WIN32
  int optind;
#endif

  /* * * * * * * * * * */

  optind = 0; /* required to reparse command line after loadPrefs() */
  for(opt_index=0; opt_index<argc; opt_index++)
    traceEvent(CONST_TRACE_NOISY, "PARAM_DEBUG: argv[%d]: %s", opt_index, argv[opt_index]);

  /*
   * Parse command line options to the application via standard system calls
   */
  traceEvent(CONST_TRACE_NOISY, "NOTE: Calling getopt_long to process parameters");
  while((opt = getopt_long(argc, argv, short_options, long_options, &opt_index)) != EOF) {
#ifdef PARAM_DEBUG
    traceEvent(CONST_TRACE_INFO, "PARAM_DEBUG: getopt(%d/%c/%s)", opt, opt, optarg);
#endif

    switch (opt) {
    case '4':
      myGlobals.runningPref.ipv4or6 = AF_INET;
      break;
    case '6':
      myGlobals.runningPref.ipv4or6 = AF_INET6;
      break;
    case 'a': /* ntop access log path */
      stringSanityCheck(optarg);
      myGlobals.runningPref.accessLogFile = strdup(optarg);
      break;

    case 'b': /* Disable protocol decoders */
      myGlobals.runningPref.enablePacketDecoding = 0;
      break;

      /* Courtesy of Ralf Amandi <Ralf.Amandi@accordata.net> */
    case 'c': /* Sticky hosts = hosts that are not purged when idle */
      myGlobals.runningPref.stickyHosts = 1;
      break;

#ifndef WIN32
    case 'd':
      myGlobals.runningPref.daemonMode = 1;
      break;
#endif

    case 'e':
      myGlobals.runningPref.maxNumLines = atoi(optarg);
      break;

    case 'f':
      myGlobals.runningPref.rFileName = strdup(optarg);
      break;

    case 'g':
      myGlobals.runningPref.trackOnlyLocalHosts    = 1;
      break;

    case 'h':                                /* help */
      usage(stdout);
      exit(0);
      
    case 'i': /* More than one interface may be specified in a comma separated list */
#ifndef WIN32
      stringSanityCheck(optarg);
#endif
      myGlobals.runningPref.devices = strdup(optarg);
      break;

    case 'j':                          /* save other (unknown) packets in a file */
      myGlobals.runningPref.enableOtherPacketDump = 1;
      break;

    case 'k':                  /* update info of used kernel filter expression in extra frame */
      myGlobals.runningPref.filterExpressionInExtraFrame = 1;
      break;

    case 'l':
      stringSanityCheck(optarg);
      myGlobals.runningPref.pcapLog = strdup(optarg);
      break;

    case 'm':
      stringSanityCheck(optarg);
      myGlobals.runningPref.localAddresses = strdup(optarg);
      break;

    case 'n':
      myGlobals.runningPref.numericFlag = 1;
      break;

    case 'o':                          /* Do not trust MAC addresses */
      myGlobals.runningPref.dontTrustMACaddr = 1;
      break;

    case 'p':                     /* the TCP/UDP protocols being monitored */
      stringSanityCheck(optarg);
      myGlobals.runningPref.protoSpecs = strdup(optarg);
      break;

    case 'q': /* save suspicious packets in a file in pcap (tcpdump) format */
      myGlobals.runningPref.enableSuspiciousPacketDump = 1;
      break;

    case 'r':
      if(!isdigit(optarg[0])) {
	printf("FATAL ERROR: flag -r expects a numeric argument.\n");
	exit(-1);
      }
      myGlobals.runningPref.refreshRate = atoi(optarg);
      break;

    case 's':
      myGlobals.runningPref.disablePromiscuousMode = 1;
      break;

    case 't':
      /* Trace Level Initialization */
      myGlobals.runningPref.traceLevel = min(max(1, atoi(optarg)),
                                             CONST_VERY_DETAIL_TRACE_LEVEL);
      /* DETAILED is NOISY + FileLine stamp, unless already set */
      break;

#ifndef WIN32
    case 'u':
      stringSanityCheck(optarg);
      myGlobals.effectiveUserName = strdup(optarg);
      if(strOnlyDigits(optarg))
	myGlobals.userId = atoi(optarg);
      else {
	struct passwd *pw;
	pw = getpwnam(optarg);
	if(pw == NULL) {
	  printf("FATAL ERROR: Unknown user %s.\n", optarg);
	  exit(-1);
	}
	myGlobals.userId = pw->pw_uid;
	myGlobals.groupId = pw->pw_gid;
	endpwent();
      }
      userSpecified = 1;
      break;
#endif /* WIN32 */

    case 'w':
      stringSanityCheck(optarg);
      if(!isdigit(optarg[0])) {
	printf("FATAL ERROR: flag -w expects a numeric argument.\n");
	exit(-1);
      }

      /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
      if((myGlobals.runningPref.webAddr = strchr(optarg,':'))) {
	/* DS: Search for : to find xxx.xxx.xxx.xxx:port */
	/* This code is to be able to bind to a particular interface */
	*myGlobals.runningPref.webAddr = '\0';
	myGlobals.runningPref.webPort = atoi(myGlobals.runningPref.webAddr+1);
	myGlobals.runningPref.webAddr = optarg;
      } else
	myGlobals.runningPref.webPort = atoi(optarg);
      break;

    case 'x':
      myGlobals.runningPref.maxNumHashEntries = atoi(optarg);
      break;

    case 'z':
      myGlobals.runningPref.enableSessionHandling = 0;
      break;

    case 'A':
      setAdminPw = 1;
      break;

    case 'B':
      stringSanityCheck(optarg);
      myGlobals.runningPref.currentFilterExpression = strdup(optarg);
      break;

    case 'D':                                        /* domain */
      stringSanityCheck(optarg);
      strncpy(myGlobals.runningPref.domainName, optarg, MAXHOSTNAMELEN);
      break;

    case 'F':
      stringSanityCheck(optarg);
      myGlobals.runningPref.flowSpecs = strdup(optarg);
      break;

#ifndef WIN32
    case 'K':
      myGlobals.runningPref.debugMode = 1;
      break;
#endif

#if !defined(WIN32) && defined(MAKE_WITH_SYSLOG)
    case 'L':
      myGlobals.runningPref.useSyslog = DEFAULT_SYSLOG_FACILITY;
      break;
#endif

    case 'M':
      myGlobals.runningPref.mergeInterfaces = 0;
      break;

    case 'N':
      stringSanityCheck(optarg);
      if (myGlobals.runningPref.fcNSCacheFile != NULL)
	free (myGlobals.runningPref.fcNSCacheFile);
      myGlobals.runningPref.fcNSCacheFile = strdup (optarg);
      break;

    case 'O': /* pcap log path - Ola Lundqvist <opal@debian.org> */
      stringSanityCheck(optarg);
      if(myGlobals.runningPref.pcapLogBasePath != NULL)
	free(myGlobals.runningPref.pcapLogBasePath);
      myGlobals.runningPref.pcapLogBasePath = strdup(optarg);
      break;
      
    case 'P':
      stringSanityCheck(optarg);
      if(myGlobals.dbPath != NULL)
	free(myGlobals.dbPath);
      
      myGlobals.dbPath = strdup(optarg);
      break;
      
    case 'Q': /* Spool Path (ntop's spool directory) */
      stringSanityCheck(optarg);
      if(myGlobals.runningPref.spoolPath != NULL)
	free(myGlobals.runningPref.spoolPath);
      myGlobals.runningPref.spoolPath = strdup(optarg);
      break;

    case 'U': /* host:port - a good mapper is at http://jake.ntop.org/cgi-bin/mapper.pl */
      stringSanityCheck(optarg);
      myGlobals.runningPref.mapperURL = strdup(optarg);
      break;

    case 'V': /* version */
      welcome(stdout);
      fprintf(stdout, "\n");
      fprintf(stdout, "%s\n\n", __free__);
      fprintf(stdout, "%s\n\n", __notice__);
      fprintf(stdout, "%s\n\n", __see__);
      exit(0);

    case 'X':
      myGlobals.runningPref.maxNumSessions = atoi(optarg);
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
      if((myGlobals.runningPref.sslAddr = strchr(optarg,':'))) {
	*myGlobals.runningPref.sslAddr = '\0';
	myGlobals.runningPref.sslPort = atoi(myGlobals.runningPref.sslAddr+1);
	myGlobals.runningPref.sslAddr = optarg;
      } else {
	myGlobals.runningPref.sslPort = atoi(optarg);
      }

      break;
#endif

#if !defined(WIN32) && defined(MAKE_WITH_SYSLOG)
    case 131:
      /*
       * Burton Strauss (BStrauss@acm.org) allow --use-syslog <facility>
       *
       *   Note that the = is REQUIRED for optional-argument to work...
       *        If you don't have it, getopt invokes this case with optind=nil
       *        and throws away the argument.
       *         (While it's visable in the next entry of argv[], that's just to complex to code
       *          for all the possible cases).
       *
       *   Also, if short_options uses L: then there MUST be an argument. (L:: is an extension)
       *
       *   Accordingly the case 'L'/131 was split and:
       *     -L sets myGlobals.useSyslog to the default facility (DEFAULT_SYSLOG_FACILITY in ntop.h)
       *     --use-syslog requires a facility parameter (see /usr/include/sys/syslog.h)
       */
      if (optarg) {
	int i;

	stringSanityCheck(optarg);

	for (i=0; myFacilityNames[i].c_name != NULL; i++) {
	  if (strcmp(optarg, myFacilityNames[i].c_name) == 0) {
	    break;
	  }
	}

	if (myFacilityNames[i].c_name == NULL) {
	  printf("WARNING: --use-syslog=unknown log facility('%s'), using default value\n",
		 optarg);
	  myGlobals.runningPref.useSyslog = DEFAULT_SYSLOG_FACILITY;
	} else {
	  myGlobals.runningPref.useSyslog = myFacilityNames[i].c_val;
	}
      } else {
	printf("NOTE: --use-syslog, no facility specified, using default value.  Did you forget the =?\n");
	myGlobals.runningPref.useSyslog = DEFAULT_SYSLOG_FACILITY;
      }
      break;
#endif

#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
    case 133:
      /* Burton M. Strauss III - Jun 2002 */
      myGlobals.runningPref.useSSLwatchdog = 1;
      break;
#endif

#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)
    case 134: /* disable-schedyield */
      myGlobals.runningPref.disableSchedYield = TRUE;
      break;
#endif

    case 135:
      /* Dennis Schoen (dennis@cns.dnsalias.org) allow --set-admin-password=<password> */
      if (optarg) {
        stringSanityCheck(optarg);	
	adminPw = strdup(optarg);
      } else {
	printf("NOTE: --set-admin-password requested, no password.  Did you forget the =?\n");
      }
      
      setAdminPw = 1;      
      break;

    case 136:
      myGlobals.runningPref.w3c = TRUE;
      break;

    case 137:
      stringSanityCheck(optarg);
      if(myGlobals.runningPref.P3Pcp != NULL)
	free(myGlobals.runningPref.P3Pcp);
      myGlobals.runningPref.P3Pcp = strdup(optarg);
      break;

    case 138:
      stringSanityCheck(optarg);
      if(myGlobals.runningPref.P3Puri != NULL)
	free(myGlobals.runningPref.P3Puri);
      myGlobals.runningPref.P3Puri = strdup(optarg);
      break;

#ifndef WIN32
    case 139:
#ifdef HAVE_PCAP_SETNONBLOCK
      myGlobals.runningPref.setNonBlocking = TRUE;
#else
      printf("FATAL ERROR: --set-pcap-nonblocking invalid - pcap_setnonblock() unavailable\n");
      exit(-1);
#endif
      break;
#endif

    case 142: /* disable-stopcap */
      myGlobals.runningPref.disableStopcap = TRUE;
      break;

    case 144: /* disable-instantsessionpurge */
      myGlobals.runningPref.disableInstantSessionPurge = TRUE;
      break;

    case 145: /* disable-mutexextrainfo */
      myGlobals.runningPref.disableMutexExtraInfo = TRUE;
      break;

    case 147:
      myGlobals.runningPref.printFcOnly = TRUE;
      myGlobals.runningPref.stickyHosts = TRUE;
      break;
      
    case 148:
      myGlobals.runningPref.printIpOnly = TRUE;
      break;

    case 149:
      myGlobals.runningPref.noInvalidLunDisplay = TRUE;
      break;

    case 150:
      myGlobals.runningPref.skipVersionCheck = TRUE;
      break;

    default:
      printf("FATAL ERROR: unknown ntop option, '%c'\n", opt);
#ifdef DEBUG
      if(opt != '?')
	printf("             getopt return value is '%c', %d\n", opt, opt);
#endif
      usage(stdout);
      exit(-1);
    }
  }

  /* *********************** */

  if(setAdminPw) {
    setAdminPassword(adminPw);
    termGdbm();
    exit(0);
  }

#ifndef WIN32
  /* Handle any unrecognized options, such as a nested @filename */
  if(optind < argc) {
    int i;

    printf("FATAL ERROR: Unrecognized/unprocessed ntop options...\n     ");
    for(i=optind; i<argc; i++) {
      printf(" %s", argv[i]);
    }
    printf("\n\nrun %s --help for usage information\n\n", argv[0]);
    printf("    Common problems:\n");
    printf("        -B \"filter expressions\" (quotes are required)\n");
    printf("        --use-syslog=facilty (the = is required)\n\n");
    exit(-1);
  }
#endif /* WIN32 */


  /*  Note that for these critical messages we use both
   *  printf() and traceEvent() - gotta get the message out
   */

  /*
   * check for valid parameters
   */


  /* If not set we set it to the same directory of dbPath */
  if(myGlobals.runningPref.spoolPath[0] == '\0') {
    free(myGlobals.runningPref.spoolPath);
    myGlobals.runningPref.spoolPath = strdup(myGlobals.dbPath);
  }

#ifndef WIN32
  /*
    The user has not specified the uid using the -u flag.
    We try to locate a user with no privileges
  */

  if(!userSpecified) {
    struct passwd *pw = NULL;
        
    if(getuid() == 0) {
      /* We're root */
      char *user;

      pw = getpwnam(user = "nobody");
      if(pw == NULL) pw = getpwnam(user = "anonymous");
     
      if(pw != NULL) {
	myGlobals.userId  = pw->pw_uid;
	myGlobals.groupId = pw->pw_gid;
	myGlobals.effectiveUserName = strdup(user);
	traceEvent(CONST_TRACE_ALWAYSDISPLAY, "ntop will be started as user %s", user);
      }
    }
      
    if(pw == NULL) {
      myGlobals.userId  = getuid();
      myGlobals.groupId = getgid();
    }
  }
#endif   

  
  return(userSpecified);
}

/* *********************************** */

static int verifyOptions (void)
{
#ifdef HAVE_OPENSSL
    if((myGlobals.runningPref.webPort == 0) && (myGlobals.runningPref.sslPort == 0)) {
        printf("WARNING: both -W and -w are set to 0. The web interface will be disabled.\n");
#else
        if(myGlobals.runningPref.webPort == 0) {
            printf("WARNING: -w is set to 0. The web interface will be disabled.\n");
#endif

            traceEvent(CONST_TRACE_WARNING, "The web interface will be disabled");
            traceEvent(CONST_TRACE_INFO, "If enabled, the rrd plugin will collect data");
            traceEvent(CONST_TRACE_INFO, "If enabled, the NetFlow and/or sFlow plugins will collect and/or transmit data");
            traceEvent(CONST_TRACE_INFO, "This may or may not be what you want");
            traceEvent(CONST_TRACE_INFO, "but without the web interface you can't set plugin parameters");
            myGlobals.webInterfaceDisabled = 1;
            /* exit(-1); */
    }

    /*
     * Must start run as root since opening a network interface
     * in promiscuous mode is a privileged operation.
     * Verify we're running as root, unless we are reading data from a file
     */

    if (myGlobals.runningPref.rFileName != NULL) {
        return (FLAG_NTOPSTATE_RUN); /* Start capture immediately */
    }

#ifndef WIN32    
    if ((myGlobals.runningPref.disablePromiscuousMode != 1) &&
        getuid() /* We're not root */) {
        char *theRootPw, *correct, *encrypted;
        struct passwd *pw = getpwuid(0);

        myGlobals.userId  = getuid();
        myGlobals.groupId = getgid();

        traceEvent(CONST_TRACE_WARNING, "You need root capabilities to capture network packets.");

        if(strcmp(pw->pw_passwd, "x") == 0) {
#ifdef HAVE_SHADOW_H
            /* Use shadow passwords */
            struct spwd *spw;
      
            spw = getspnam("root");
            if(spw == NULL) {
                traceEvent(CONST_TRACE_INFO, "Unable to read shadow passwords. Become root first and start ntop again");
                exit (-1);
            } else
                correct = spw->sp_pwdp;
#else
            traceEvent(CONST_TRACE_ERROR, "Sorry: I cannot change user as your system uses and unsupported password storage mechanism.");
            traceEvent(CONST_TRACE_ERROR, "Please restart ntop with root capabilities");
            exit (-1);
#endif
        } else
            correct = pw->pw_passwd;

        theRootPw = getpass("Please enter the root password: ");
        encrypted = crypt(theRootPw, correct);

        if(strcmp(encrypted, correct) == 0) {
            traceEvent(CONST_TRACE_INFO, "The root password is correct");

            if(setuid(0) || setgid(0)) {
                traceEvent(CONST_TRACE_ERROR, "Sorry I'm unable to become root. Please check whether this application");
                traceEvent(CONST_TRACE_ERROR, "has the sticky bit set and the owner is %s. Otherwise",
#ifdef DARWIN
                           "root:wheel"
#else
                           "root:root"
#endif
                    );
                traceEvent(CONST_TRACE_ERROR, "please run ntop as root.");
                exit (-1);
            }
        } else {
            traceEvent(CONST_TRACE_ERROR, "The specified root password is not correct.");
            traceEvent(CONST_TRACE_ERROR, "Sorry, %s uses network interface(s) in promiscuous mode, "
                       "so it needs root permission to run.\n", myGlobals.program_name);
            exit(-1);
        }
    } else if (myGlobals.runningPref.disablePromiscuousMode == 1)
        traceEvent(CONST_TRACE_WARNING,
                   "-s set so will ATTEMPT to open interface w/o promisc mode "
                   "(this will probably fail below)");
#endif /* WIN32 */

    return (FLAG_NTOPSTATE_RUN);
}

/* ************************************ */

/* That's the meat */
#ifdef WIN32
int ntop_main(int argc, char *argv[]) {
#else
int main(int argc, char *argv[]) {
#endif
  int i, rc, userSpecified;
#ifndef WIN32
  int effective_argc;
  char **effective_argv;
#endif
  char ifStr[196] = {0};
  time_t lastTime;
  char *cmdLineBuffer, *readBuffer, *readBufferWork;
  FILE *fd;
  struct stat fileStat;


  if(0) {
    Counter c = 1410065408;
    formatPkts(c, ifStr, sizeof(ifStr));
    printf("%llu\n", c);
    return(0);
  }
  

  /* printf("Wait please: ntop is coming up...\n"); */

#ifdef MTRACE
  mtrace();
#endif

#ifdef MEMORY_DEBUG
  initLeaks(); /* Don't move this below nor above */
#endif

#ifdef WIN32
	initWinsock32(); /* Necessary for initializing globals */
#endif

  /* *********************** */

  cmdLineBuffer = (char*)malloc(LEN_CMDLINE_BUFFER) /* big just to be safe */;
  memset(cmdLineBuffer, 0, LEN_CMDLINE_BUFFER);

  readBuffer = (char*)malloc(LEN_FGETS_BUFFER) /* big just to be safe */;
  memset(readBuffer, 0, LEN_FGETS_BUFFER);

  safe_snprintf(__FILE__, __LINE__, cmdLineBuffer, LEN_CMDLINE_BUFFER, "%s ", argv[0]);

  /*
   * Prepend FORCE_RUNTIME_PARM from configureextra 
   */
  if((force_runtime != NULL) &&
     (force_runtime[0] != '\0')) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NOTE: Run time parameter %s forced via configureextra",
               force_runtime);
    strncat(cmdLineBuffer, force_runtime, (LEN_CMDLINE_BUFFER - strlen(cmdLineBuffer) - 1));
    strncat(cmdLineBuffer, " ", (LEN_CMDLINE_BUFFER - strlen(cmdLineBuffer) - 1));
  }

  /* Now we process the parameter list, looking for a @filename
   *   We have to special case a few things --- since the OS processing removes "s
   *     --filter-expression "host a.b.c.d" becomes
   *     --filter-expression host a.b.c.d
   *     --filter-expression="host a.b.c.d" becomes
   *     --filter-expression=host a.b.c.d
   *   This causes --filter-expression "host" and a bogus "a.b.c.d"
   */
  for(i=1; i<argc; i++) {
    if(argv[i][0] != '@') {
#ifdef PARAM_DEBUG
      printf("PARAM_DEBUG: Parameter %3d is '%s'\n", i, argv[i]);
#endif
      readBufferWork = strchr(argv[i], '=');
      if (readBufferWork != NULL) {
        readBufferWork[0] = '\0';
        safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, argv[i]);
        safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, "=\"");
        safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, &readBufferWork[1]);
        safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, "\" ");
      } else {
	readBufferWork = strchr(argv[i], ' ');
	if (readBufferWork != NULL) {
	  safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, "\"");
	  safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, argv[i]);
	  safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, "\" ");
	} else {
	  safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, argv[i]);
	  safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, " ");
	}
      }
    } else {

#ifdef PARAM_DEBUG
      printf("PARAM_DEBUG: Requested parameter file, '%s'\n", &argv[i][1]);
#endif

      rc = stat(&argv[i][1], &fileStat);
      if (rc != 0) {
	if (errno == ENOENT) {
	  printf("ERROR: Parameter file %s not found/unable to access\n", &argv[i][1]);
	} else {
	  printf("ERROR: %d in stat(%s, ...)\n", errno, &argv[i][1]);
	}
	return(-1);
      }

#ifdef PARAM_DEBUG
      printf("PARAM_DEBUG: File size %d\n", fileStat.st_size);
#endif

      fd = fopen(&argv[i][1], "rb");
      if (fd == NULL) {
	printf("ERROR: Unable to open parameter file '%s' (%d)...\n", &argv[i][1], errno);
	return(-1);
      }

      printf("   Processing file %s for parameters...\n", &argv[i][1]);

      for (;;) {
	readBufferWork = fgets(readBuffer, min(LEN_FGETS_BUFFER, fileStat.st_size), fd);
	/* On EOF, we're finished */
	if (readBufferWork == NULL) {
	  break;
	}
#ifdef PARAM_DEBUG
	printf("PARAM_DEBUG: fgets() '%s'\n", readBufferWork);
#endif

	/* Strip out any comments */
	readBufferWork = strchr(readBuffer, '#');
	if (readBufferWork != NULL) {
	  readBufferWork[0] = ' ';
	  readBufferWork[1] = '\0';
	}

	/* Replace the \n by a space, so at the end the buffer will
	 * look indistinguishable...
	 */
	readBufferWork = strchr(readBuffer, '\n');
	if(readBufferWork != NULL) {
	  readBufferWork[0] = ' ';
	  readBufferWork[1] = '\0';
	}

	readBufferWork = strchr(readBuffer, '@');
	if(readBufferWork != NULL) {
	  printf("FATAL ERROR: @command in file ... nesting is not permitted!\n\n");
	  exit(-1);
	}

#ifdef PARAM_DEBUG
	printf("PARAM_DEBUG:      -> '%s'\n", readBuffer);
#endif
	safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, " ");
	safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, readBuffer);
      }

      fclose(fd);

    }
  }

#ifdef PARAM_DEBUG
  printf("PARAM_DEBUG: effective cmd line: '%s'\n", cmdLineBuffer);
#endif

  /* Strip trailing spaces */
  while((strlen(cmdLineBuffer) > 1) && 
        (cmdLineBuffer[strlen(cmdLineBuffer)-1] == ' ')) {
      cmdLineBuffer[strlen(cmdLineBuffer)-1] = '\0';
  }

#ifndef WIN32
  effective_argv = buildargv(cmdLineBuffer); /* Build a new argv[] from the string */

 /* count effective_argv[] */
  effective_argc = 0;
  while (effective_argv[effective_argc] != NULL) {
      effective_argc++;
  }
#ifdef PARAM_DEBUG
  for(i=0; i<effective_argc; i++) {
      printf("PARAM_DEBUG:    %3d. '%s'\n", i, effective_argv[i]);
  }
#endif
  /*
   * Initialize all global run-time parameters to reasonable values
   */
  initNtopGlobals(effective_argc, effective_argv);
#else
  initNtopGlobals(argc, argv);
#endif

  free(cmdLineBuffer);
  free(readBuffer);

  /* Above here, the -L value wasn't set, so we use printf(). */
  /* Below here, we use our traceEvent() function to print or log as requested. */

 
  /*
   * Parse command line options to the application via standard system calls
   * Command-line options take precedence over saved preferences. 
   */
#ifndef WIN32
  loadPrefs(effective_argc, effective_argv);
  userSpecified = parseOptions(effective_argc, effective_argv);
#else
  loadPrefs(argc, argv);
  userSpecified = parseOptions(argc, argv);
#endif

  myGlobals.capturePackets = verifyOptions ();

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "ntop v.%s %s", version, THREAD_MODE);
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Configured on %s, built on %s.",
	     configureDate, buildDate);
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Copyright 1998-2004 by %s", author);
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Get the freshest ntop from http://www.ntop.org/");

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Initializing ntop");

  reportValues(&lastTime);

  if(myGlobals.runningPref.P3Pcp != NULL)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "P3P: Compact Policy is '%s'", myGlobals.runningPref.P3Pcp);

  if(myGlobals.runningPref.P3Puri != NULL)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "P3P: Policy reference uri is '%s'", myGlobals.runningPref.P3Puri);

  if (!myGlobals.runningPref.printIpOnly && (myGlobals.runningPref.fcNSCacheFile != NULL)) {
      processFcNSCacheFile (myGlobals.runningPref.fcNSCacheFile);
  }
  
  initNtop(myGlobals.runningPref.devices);

  /* create the main listener */
  if(!myGlobals.webInterfaceDisabled)
      initWeb();

  /* ******************************* */

  if(myGlobals.runningPref.rFileName != NULL)
    strncpy(ifStr, CONST_PCAP_NW_INTERFACE_FILE, sizeof(ifStr));
  else {
    ifStr[0] = '\0';

    for (i=0; i<myGlobals.numDevices; i++) {
      char tmpBuf[64];

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "%s%s", 
                  (i>0) ? "," : "",
                  (myGlobals.device[i].humanFriendlyName != NULL) ?
                      myGlobals.device[i].humanFriendlyName :
                      myGlobals.device[i].name);
      strncat(ifStr, tmpBuf, sizeof(ifStr)-strlen(ifStr)-1)[sizeof(ifStr)-1] = '\0';
    }
  }

  if((ifStr == NULL) || (ifStr[0] == '\0')) {
    traceEvent(CONST_TRACE_FATALERROR, "No interface has been selected. Capture not started...");
    createDummyInterface("none");
  } else
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Listening on [%s]", ifStr);

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Loading Plugins");
  loadPlugins();
  traceEvent(CONST_TRACE_NOISY, "Starting Plugins");
  startPlugins();
  traceEvent(CONST_TRACE_NOISY, "Plugins started... continuing with initialization");

  /* ******************************* */
  
  checkUserIdentity(userSpecified);

#ifndef WIN32
  saveNtopPid();
#endif

  /* ******************************* */

  initSignals();

#ifdef HAVE_OPENSSL
  init_ssl();
#endif
  
  addDefaultAdminUser();

  if (myGlobals.capturePackets != FLAG_NTOPSTATE_NOTINIT)
      initReports();

  /* If we can, set the base memory HERE */
#if defined(HAVE_MALLINFO_MALLOC_H) && defined(HAVE_MALLOC_H) && defined(__GNUC__)
  {
    struct mallinfo memStats;

    memStats = mallinfo();
    myGlobals.baseMemoryUsage = memStats.arena + memStats.hblkhd;

    traceEvent(CONST_TRACE_NOISY, "MEMORY: Base memory load is %.2fMB (%d+%d)",
	       xvertDOT00MB(myGlobals.baseMemoryUsage),
	       memStats.arena,
	       memStats.hblkhd);
  }
#endif
  traceEvent(CONST_TRACE_NOISY, "MEMORY: Base interface structure (no hashes loaded) is %.2fMB each",
	     xvertDOT00MB(sizeof(NtopInterface)));
  traceEvent(CONST_TRACE_NOISY, "MEMORY:     or %.2fMB for %d interfaces",
	     xvertDOT00MB(myGlobals.numDevices*sizeof(NtopInterface)),
	     myGlobals.numDevices);
  traceEvent(CONST_TRACE_NOISY, "MEMORY: ipTraffixMatrix structure (no TrafficEntry loaded) is %.2fMB",
	     xvertDOT00MB(myGlobals.ipTrafficMatrixMemoryUsage));

#ifdef NOT_YET  
  traceEvent(CONST_TRACE_NOISY, "MEMORY: fcTrafficMatrix structure (no TrafficEntry loaded) is %.2fMB",
	     xvertDOT00MB(myGlobals.fcTrafficMatrixMemoryUsage));
#endif  

  /*
   * In multithread mode, a separate thread handles packet sniffing
   */
#ifndef CFG_MULTITHREADED
  packetCaptureLoop(&lastTime, myGlobals.runningPref.refreshRate);
#else
  startSniffer();
#endif

#ifndef WIN32

  while(!myGlobals.endNtop) {
    HEARTBEAT(0, "main(), sleep()...", NULL);
    sleep(10);

    /* Periodic recheck of the version status */
    if((myGlobals.checkVersionStatusAgain > 0) && 
       (time(NULL) > myGlobals.checkVersionStatusAgain))
      checkVersion(NULL);

    HEARTBEAT(0, "main(), sleep()...woke", NULL);
  }
#endif

#ifndef WIN32
  freeargv(effective_argv);
#endif

  return(0);
}
