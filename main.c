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
#include "globals-report.h"

/*
  Ntop options list
  -- converted to getopts_long, Burton M. Strauss III (BStrauss@acm.org)
  -- if getopt_long isn't provided by the compiler (glibc), we have our own version in util.c
*/

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


static struct option const long_options[] = {

  { "access-log-path",                  required_argument, NULL, 'a' },
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

#ifndef WIN32
  { "enable-external-tools",            no_argument,       NULL, 'E' },
#endif

  { "flow-spec",                        required_argument, NULL, 'F' },

#ifndef WIN32
  { "debug",                            no_argument,       NULL, 'K' },
#endif

  { "no-interface-merge",               no_argument,       NULL, 'M' },

  { "output-packet-path",               required_argument, NULL, 'O' },
  { "db-file-path",                     required_argument, NULL, 'P' },
  { "spool-file-path",                  required_argument, NULL, 'Q' },
  { "mapper",                           required_argument, NULL, 'U' },
  { "version",                          no_argument,       0,    'V' },

#ifdef HAVE_OPENSSL
  { "https-server",                     required_argument, NULL, 'W' },
#endif

  { "no-idle-host-purge",               no_argument,       NULL, '2' },

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

  { "set-admin-password",               optional_argument, NULL, 135 },

#ifdef MAKE_WITH_XMLDUMP
  { "xmlfileout",                       required_argument, NULL, 139 },
  { "xmlfilesnap",                      required_argument, NULL, 140 },
  { "xmlfilein",                        required_argument, NULL, 141 },
#endif

  { "disable-stopcap",                  no_argument,       NULL, 142 },

  {NULL, 0, NULL, 0}
};

/*
 * Hello World! This is ntop speaking...
 */
static void welcome (FILE * fp)
{
#ifdef WIN32
	initWinsock32(); /* Necessary for initializing globals */
#endif

  fprintf (fp, "%s v.%s %s [%s] (%s build)\n",
	   myGlobals.program_name, version, THREAD_MODE, osName, buildDate);

  fprintf (fp, "Copyright 1998-2003 by %s.\n", author);
  fprintf (fp, "Get the freshest ntop from http://www.ntop.org/\n");
}


/*
 * Wrong. Please try again accordingly to ....
 */
void usage (FILE * fp) {
	char *newLine = "";

#ifdef WIN32
	newLine = "\n\t";
#endif

  welcome(fp);

  fprintf(fp, "\nUsage: %s [OPTION]\n", myGlobals.program_name);

  fprintf(fp, "    [-a <path>      | --access-log-path <path>]           %sPath for ntop web server access log\n", newLine);
  fprintf(fp, "    [-b             | --disable-decoders]                 %sDisable protocol decoders\n", newLine);
  fprintf(fp, "    [-c             | --sticky-hosts]                     %sIdle hosts are not purged from memory\n", newLine);

#ifndef WIN32
  fprintf(fp, "    [-d             | --daemon]                           %sRun ntop in daemon mode\n", newLine);
#endif
  fprintf(fp, "    [-e <number>    | --max-table-rows <number>]          %sMaximum number of table rows to report\n", newLine);
  fprintf(fp, "    [-f <file>      | --traffic-dump-file <file>]         %sTraffic dump file (see tcpdump)\n", newLine);
  fprintf(fp, "    [-g             | --track-local-hosts]                %sTrack only local hosts\n", newLine);

  fprintf(fp, "    [-h             | --help]                             %sDisplay this help and exit\n", newLine);

#ifndef WIN32
  fprintf(fp, "    [-i <name>      | --interface <name>]                 %sInterface name or names to monitor\n", newLine);
#else
  fprintf(fp, "    [-i <number>    | --interface <number|name>]          %sInterface index number (or name) to monitor\n", newLine);
#endif
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
  fprintf(fp, "    [-t <number>    | --trace-level <number>]             %sTrace level [0-5]\n", newLine);

#ifndef WIN32
  fprintf(fp, "    [-u <user>      | --user <user>]                      %sUserid/name to run ntop under (see man page)\n", newLine);
#endif /* WIN32 */

  fprintf(fp, "    [-w <port>      | --http-server <port>]               %sWeb server (http:) port (or address:port) to listen on\n", newLine);
  fprintf(fp, "    [-z             | --disable-sessions]                 %sDisable TCP session tracking\n", newLine);
  fprintf(fp, "    [-A]                                                  %sAsk admin user password and exit\n", newLine);
  fprintf(fp, "    [               | --set-admin-password=<pass>]        %sSet password for the admin user to <pass>\n", newLine);
  fprintf(fp, "    [-B <filter>]   | --filter-expression                 %sPacket filter expression, like tcpdump\n", newLine);
  fprintf(fp, "    [-D <name>      | --domain <name>]                    %sInternet domain name\n", newLine);

#ifndef WIN32
  fprintf(fp, "    [-E             | --enable-external-tools]            %sEnable lsof integration (if present)\n", newLine);
#endif

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
  fprintf(fp, "    [-O <path>      | --pcap-file-path <path>]            %sPath for log files in pcap format\n", newLine);
  fprintf(fp, "    [-P <path>      | --db-file-path <path>]              %sPath for ntop internal database files\n", newLine);
  fprintf(fp, "    [-U <URL>       | --mapper <URL>]                     %sURL (mapper.pl) for displaying host location\n", 
	  newLine);
  fprintf(fp, "    [-V             | --version]                          %sOutput version information and exit\n", newLine);

#ifdef HAVE_OPENSSL
  fprintf(fp, "    [-W <port>      | --https-server <port>]              %sWeb server (https:) port (or address:port) to listen on\n", newLine);
#endif

#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  fprintf(fp, "    [--ssl-watchdog]                                      %sUse ssl watchdog (NS6 problem)\n", newLine);
#endif

#ifdef MAKE_WITH_XMLDUMP
  fprintf(fp, "    [--xmlfileout]                                        %sFile name for saving internal data during shutdown (xml)\n", newLine);
  fprintf(fp, "    [--xmlfilesnap]                                       %sFile name for snapshot internal data save (xml)\n", newLine);
  fprintf(fp, "    [--xmlfilein]    ***FUTURE***                         %sFile name to reload ntop internal data from (xml)\n", newLine);
#endif

  fprintf(fp, "    [--disable-stopcap]                                   %sCapture packets even if there's no memory left\n", newLine);

#ifdef WIN32
  printAvailableInterfaces();
#endif
}

/* **************************************************** */

static void checkUserIdentity(int userSpecified) {
  /*
    Code fragment below courtesy of
    Andreas Pfaller <apfaller@yahoo.com.au>
  */
#ifndef WIN32
  if((getuid() != geteuid()) || (getgid() != getegid())) {
    /* setuid binary, drop privileges */
    if((setgid(getgid()) != 0) || (setuid(getuid()) != 0)) {
      traceEvent(CONST_TRACE_FATALERROR, "Unable to drop privileges");
      exit(-1);
    }
  }

  /*
   * set user to be as inoffensive as possible
   */
  if(!setSpecifiedUser()) {
    if(userSpecified) {
      /* User located */
      if((myGlobals.userId != 0) || (myGlobals.groupId != 0)) {
	if((setgid(myGlobals.groupId) != 0) || (setuid(myGlobals.userId) != 0)) {
	  traceEvent(CONST_TRACE_FATALERROR, "Unable to change user");
	  exit(-1);
	}
      }
    } else {
      if((geteuid() == 0) || (getegid() == 0)) {
	if(!userSpecified) {
	  traceEvent(CONST_TRACE_FATALERROR, "For security reasons you cannot run ntop as root - aborting");
	  traceEvent(CONST_TRACE_INFO, "Unless you really, really, know what you're doing");
	  traceEvent(CONST_TRACE_INFO, "Please specify the user name using the -u option!");
	  exit(0);
	} else {
	  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "For security reasons you should not run ntop as root (-u)!");
	}
      } else {
	traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Now running as requested user... continuing with initialization");
      }
    }
  }
#endif
}

/* ***************************************************** */

/*
 * Parse the command line options
 */
static int parseOptions(int argc, char* argv []) {
  int userSpecified = 0, setAdminPw = 0, opt, opt_index;
  char *theOpts, *adminPw = NULL;
#ifdef WIN32
  int optind=0;
#endif

  /*
   * Please keep the array sorted
   */
#ifdef WIN32
  theOpts = "a:bce:f:ghi:jkl:m:nop:qr:st:w:zAB:BD:F:MO:P:Q:S:U:VW:";
#elif defined(MAKE_WITH_SYSLOG)
  theOpts = "a:bcde:f:ghi:jkl:m:nop:qr:st:u:w:zAB:D:EF:IKLMO:P:Q:S:U:VW:";
#else
  theOpts = "a:bcde:f:ghi:jkl:m:nop:qr:st:u:w:zAB:D:EF:IKMO:P:Q:S:U:VW:";
#endif

  /* * * * * * * * * * */

  /*
   * Parse command line options to the application via standard system calls
   */
  while((opt = getopt_long(argc, argv, theOpts, long_options, &opt_index)) != EOF) {
    /* traceEvent(CONST_TRACE_INFO, "getopt(%d/%c/%s)", opt, opt, optarg); */
    switch (opt) {
    case 'a': /* ntop access log path */
      stringSanityCheck(optarg);
      myGlobals.accessLogPath = strdup(optarg);
      break;

    case 'b': /* Disable protocol decoders */
      myGlobals.enablePacketDecoding = 0;
      break;

      /* Courtesy of Ralf Amandi <Ralf.Amandi@accordata.net> */
    case 'c': /* Sticky hosts = hosts that are not purged when idle */
      myGlobals.stickyHosts = 1;
      break;

#ifndef WIN32
    case 'd':
      myGlobals.daemonMode = 1;
      break;
#endif

    case 'e':
      myGlobals.maxNumLines = atoi(optarg);
      break;

    case 'f':
      myGlobals.rFileName = strdup(optarg);
      myGlobals.isLsofPresent = 0;               /* Don't make debugging too complex */
      break;

    case 'g':
      myGlobals.trackOnlyLocalHosts    = 1;
      break;

    case 'h':                                /* help */
      usage(stdout);
      exit(0);

    case 'i':                          /* More than one interface may be specified in a comma separated list */
#ifndef WIN32
	  stringSanityCheck(optarg);
#endif
      myGlobals.devices = strdup(optarg);
      break;

    case 'o':                          /* Do not trust MAC addresses */
      myGlobals.dontTrustMACaddr = 1;
      break;

    case 'k':                  /* update info of used kernel filter expression in extra frame */
      myGlobals.filterExpressionInExtraFrame = 1;
      break;

    case 'l':
      stringSanityCheck(optarg);
      myGlobals.pcapLog = strdup(optarg);
      break;

    case 'm':
      stringSanityCheck(optarg);
      myGlobals.localAddresses = strdup(optarg);
      break;

    case 'n':
      myGlobals.numericFlag = 1;
      break;

    case 'p':                     /* the TCP/UDP protocols being monitored */
      stringSanityCheck(optarg);
      myGlobals.protoSpecs = strdup(optarg);
      break;

    case 'q': /* save suspicious packets in a file in pcap (tcpdump) format */
      myGlobals.enableSuspiciousPacketDump = 1;
      break;

    case 'r':
      if(!isdigit(optarg[0])) {
	printf("FATAL ERROR: flag -r expects a numeric argument.\n");
	exit(-1);
      }
      myGlobals.refreshRate = atoi(optarg);
      break;

    case 's':
      myGlobals.disablePromiscuousMode = 1;
      break;

    case 't':
      /* Trace Level Initialization */
      myGlobals.traceLevel = min(max(1, atoi(optarg)), CONST_DETAIL_TRACE_LEVEL);
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
      if((myGlobals.webAddr = strchr(optarg,':'))) {
	/* DS: Search for : to find xxx.xxx.xxx.xxx:port */
	/* This code is to be able to bind to a particular interface */
	*myGlobals.webAddr = '\0';
	myGlobals.webPort = atoi(myGlobals.webAddr+1);
	myGlobals.webAddr = optarg;
      } else
	myGlobals.webPort = atoi(optarg);
      break;

    case 'z':
       myGlobals.enableSessionHandling = 0;
       break;

     case 'A':
       setAdminPw = 1;
       break;

    case 'B':
      stringSanityCheck(optarg);
      myGlobals.currentFilterExpression = strdup(optarg);
      break;

    case 'D':                                        /* domain */
      stringSanityCheck(optarg);
      strncpy(myGlobals.domainName, optarg, MAXHOSTNAMELEN);
      break;

#ifndef WIN32
    case 'E':
      myGlobals.enableExternalTools = 1;
      myGlobals.isLsofPresent  = checkCommand("lsof");
      break;
#endif

    case 'F':
      stringSanityCheck(optarg);
      myGlobals.flowSpecs = strdup(optarg);
      break;

#ifndef WIN32
    case 'K':
      myGlobals.debugMode = 1;
      break;
#endif

#if !defined(WIN32) && defined(MAKE_WITH_SYSLOG)
    case 'L':
      myGlobals.useSyslog = DEFAULT_SYSLOG_FACILITY;
      break;
#endif

    case 'M':
      myGlobals.mergeInterfaces = 0;
      break;

    case 'O': /* pcap log path - Ola Lundqvist <opal@debian.org> */
      stringSanityCheck(optarg);
      if(myGlobals.pcapLogBasePath != NULL) free(myGlobals.pcapLogBasePath);
      myGlobals.pcapLogBasePath = strdup(optarg);
      break;

    case 'P': /* DB-Path (ntop's prefs/static info directory) */
      stringSanityCheck(optarg);
      if(myGlobals.dbPath != NULL) free(myGlobals.dbPath);
      myGlobals.dbPath = strdup(optarg);
      break;

    case 'Q': /* Spool Path (ntop's spool directory) */
      stringSanityCheck(optarg);
      if(myGlobals.spoolPath != NULL) free(myGlobals.spoolPath);
      myGlobals.spoolPath = strdup(optarg);
      break;

    case 'U': /* host:port - a good mapper is at http://jake.ntop.org/cgi-bin/mapper.pl */
      stringSanityCheck(optarg);
      myGlobals.mapperURL = strdup(optarg);
      break;

    case 'V': /* version */
      welcome(stdout);
      fprintf(stdout, "\n");
      fprintf(stdout, "%s\n\n", __free__);
      fprintf(stdout, "%s\n\n", __notice__);
      fprintf(stdout, "%s\n\n", __see__);
      exit(0);

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
      if((myGlobals.sslAddr = strchr(optarg,':'))) {
	*myGlobals.sslAddr = '\0';
	myGlobals.sslPort = atoi(myGlobals.sslAddr+1);
	myGlobals.sslAddr = optarg;
      } else {
	myGlobals.sslPort = atoi(optarg);
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
       *   Also, if theOpts uses L: then there MUST be an argument. (L:: is an extension)
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
	  myGlobals.useSyslog = DEFAULT_SYSLOG_FACILITY;
	} else {
	  myGlobals.useSyslog = myFacilityNames[i].c_val;
	}
      } else {
	printf("NOTE: --use-syslog, no facility specified, using default value.  Did you forget the =?\n");
	myGlobals.useSyslog = DEFAULT_SYSLOG_FACILITY;
      }
      break;
#endif

#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
    case 133:
      /* Burton M. Strauss III - Jun 2002 */
      myGlobals.useSSLwatchdog = 1;
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

    case 137:
      stringSanityCheck(optarg);
      if(myGlobals.P3Pcp != NULL) free(myGlobals.P3Pcp);
      myGlobals.P3Pcp = strdup(optarg);
      break;

    case 138:
      stringSanityCheck(optarg);
      if(myGlobals.P3Puri != NULL) free(myGlobals.P3Puri);
      myGlobals.P3Puri = strdup(optarg);
      break;

#ifdef MAKE_WITH_XMLDUMP
      /* --xmlfilexxxx options - Burton M. Strauss III (Burton@ntopsupport.com) Jan2003 */
    case 139: /* xmlfileout */
      myGlobals.xmlFileOut = strdup(optarg);
      break;

    case 140: /* xmlfilesnap */
      myGlobals.xmlFileSnap = strdup(optarg);
      break;

    case 141: /* xmlfilein */
      myGlobals.xmlFileIn = strdup(optarg);
      break;
#endif

    case 142: /* disable-stopcap */
      myGlobals.disableStopcap = TRUE;
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
      initGdbm(NULL, NULL, 1);
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
  if(myGlobals.spoolPath[0] == '\0') {
      free(myGlobals.spoolPath);
      myGlobals.spoolPath = strdup(myGlobals.dbPath);
  }

#ifdef HAVE_OPENSSL
  if((myGlobals.webPort == 0) && (myGlobals.sslPort == 0)) {
      printf("WARNING: both -W and -w are set to 0. The web interface will be disabled.\n");
#else
  if(myGlobals.webPort == 0) {
      printf("WARNING: -w is set to 0. The web interface will be disabled.\n");
#endif

      traceEvent(CONST_TRACE_WARNING, "The web interface will be disabled");
      traceEvent(CONST_TRACE_INFO, "If enabled, the rrd plugin will collect data");
      traceEvent(CONST_TRACE_INFO, "If enabled, the netFlow and/or sFlow plugins will collect and/or transmit data");
      traceEvent(CONST_TRACE_INFO, "This may or may not be what you want");
      traceEvent(CONST_TRACE_INFO, "but without the web interface you can't set plugin parameters");
      /* exit(-1); */
  }

#ifndef WIN32
  /*
    The user has not specified the uid using the -u flag.
    We try to locate a user with no privileges
  */

  if(!userSpecified) {
    if(getuid() == 0) {
      /* We're root */
      char *user;

      struct passwd *pw = getpwnam(user = "nobody");
      if(pw == NULL) pw = getpwnam(user = "anonymous");

      myGlobals.userId  = pw->pw_uid;
      myGlobals.groupId = pw->pw_gid;
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "ntop will be started as user %s", user);
    } else {
      myGlobals.userId  = getuid();
      myGlobals.groupId = getgid();
    }
  }

  /*
   * Must start run as root since opening a network interface
   * in promiscuous mode is a privileged operation.
   * Verify we're running as root, unless we are reading data from a file
   */

  if((!myGlobals.rFileName) &&  (myGlobals.disablePromiscuousMode != 1)
     && getuid() /* We're not root */) {
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
	  exit(-1);
      } else
	  correct = spw->sp_pwdp;
#else
      traceEvent(CONST_TRACE_ERROR, "Sorry: I cannot change user as your system uses and unsupported password storage mechanism.");
      traceEvent(CONST_TRACE_ERROR, "Please restart ntop with root capabilities");
      exit(-1);
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
	exit(-1);
      }
    } else {
      traceEvent(CONST_TRACE_ERROR, "The specified root password is not correct.");
      traceEvent(CONST_TRACE_ERROR, "Sorry, %s uses network interface(s) in promiscuous mode, "
	     "so it needs root permission to run.\n", myGlobals.program_name);
      exit(-1);
    }
  } else if (myGlobals.disablePromiscuousMode == 1)
    traceEvent(CONST_TRACE_WARNING,
               "-s set so will ATTEMPT to open interface w/o promisc mode "
               "(this will probably fail below)");
#endif

  /*
   * Perform here all the initialization steps required by the ntop engine to run
   */

#ifdef MAKE_WITH_XMLDUMP
  /* Here is where we place the divergent path for (FUTURE) xmlFileIn */
  if (myGlobals.xmlFileIn != NULL) {
      traceEvent(CONST_TRACE_NOISY, "XMLDUMP: Processing xml input file, %s", myGlobals.xmlFileIn);
      traceEvent(CONST_TRACE_ERROR, "XMLDUMP: SORRY, but that function does not yet exist. Continuing normally.");
   }
#endif

  return(userSpecified);
}

/* ************************************ */

#define MAX_NUM_OPTIONS 64

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
  /* printf("HostTraffic=%d\n", sizeof(HostTraffic)); return(-1); */

  /* printf("Wait please: ntop is coming up...\n"); */

#ifdef MTRACE
  mtrace();
#endif

#ifdef MEMORY_DEBUG
  initLeaks(); /* Don't move this below nor above */
#endif

  /* *********************** */

  cmdLineBuffer = (char*)malloc(LEN_CMDLINE_BUFFER) /* big just to be safe */;
  memset(cmdLineBuffer, 0, LEN_CMDLINE_BUFFER);

  readBuffer = (char*)malloc(LEN_FGETS_BUFFER) /* big just to be safe */;
  memset(readBuffer, 0, LEN_FGETS_BUFFER);

  if (snprintf(cmdLineBuffer, LEN_CMDLINE_BUFFER, "%s ", argv[0]) < 0)
      BufferTooShort();

  /* Now we process the parameter list, looking for a @filename
   *   We have to special case a few things --- since the OS processing removes "s
   *     --filter-expression "host a.b.c.d" becomes
   *     --filter-expression host a.b.c.d
   *     --filter-expression="host a.b.c.d" becomes
   *     --filter-expression=host a.b.c.d
   *   This causes --filter-expression "host" and a bogus "a.b.c.d"
   */
  for (i=1; i<argc; i++) {
    if (argv[i][0] != '@') {
#ifdef PARAM_DEBUG
      printf("PARAM_DEBUG: Parameter %3d is '%s'\n", i, argv[i]);
#endif
      readBufferWork = strchr(argv[i], '=');
      if (readBufferWork != NULL) {
	if (strlen(cmdLineBuffer) + strlen(argv[i]) + 5 >= LEN_CMDLINE_BUFFER) {
	  BufferTooShort();
	} else {
	  readBufferWork[0] = '\0';
	  strcat(cmdLineBuffer, argv[i]);
	  strcat(cmdLineBuffer, "=\"");
	  strcat(cmdLineBuffer, &readBufferWork[1]);
	  strcat(cmdLineBuffer, "\" ");
	}
      } else {
	readBufferWork = strchr(argv[i], ' ');
	if (readBufferWork != NULL) {
	  if (strlen(cmdLineBuffer) + strlen(argv[i]) + 4 < LEN_CMDLINE_BUFFER) {
	    strcat(cmdLineBuffer, "\"");
	    strcat(cmdLineBuffer, argv[i]);
	    strcat(cmdLineBuffer, "\" ");
	  } else {
	    BufferTooShort();
	  }
	} else {
	  if (strlen(cmdLineBuffer) + strlen(argv[i]) + 2 < LEN_CMDLINE_BUFFER) {
	    strcat(cmdLineBuffer, argv[i]);
	    strcat(cmdLineBuffer, " ");
	  } else {
	    BufferTooShort();
	  }
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
	if (strlen(cmdLineBuffer) + strlen(readBuffer) + 2 < LEN_CMDLINE_BUFFER) {
	  strcat(cmdLineBuffer, " ");
	  strcat(cmdLineBuffer, readBuffer);
	} else {
	  BufferTooShort();
	}
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
  effective_argv=buildargv(cmdLineBuffer); /* Build a new argv[] from the string */

 /* count effective_argv[] */
  effective_argc=0;
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

  /*
   * Parse command line options to the application via standard system calls
   */
#ifndef WIN32
  userSpecified = parseOptions(effective_argc, effective_argv);
#else
  userSpecified = parseOptions(argc, argv);
#endif

/* Above here, the -L value wasn't set, so we use printf(). */

/* create the logView stuff Mutex first... must be before the 1st traceEvent() call */
  createMutex(&myGlobals.logViewMutex);     /* synchronize logView buffer */
  myGlobals.logViewNext = 0;
  myGlobals.logView = calloc(sizeof(char*),
                             CONST_LOG_VIEW_BUFFER_SIZE);

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "ntop v.%s %s [%s] (%s build)",
	     version, THREAD_MODE, osName, buildDate);
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Copyright 1998-2003 by %s", author);
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Get the freshest ntop from http://www.ntop.org/");

/* Below here, we use our traceEvent() function to print or log as requested. */

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Initializing ntop");

  reportValues(&lastTime);

  initNtop(myGlobals.devices);

  /* ******************************* */

  if(myGlobals.rFileName != NULL)
    strncpy(ifStr, CONST_PCAP_NW_INTERFACE_FILE, sizeof(ifStr));
  else {
    ifStr[0] = '\0';

    for (i=0; i<myGlobals.numDevices; i++) {
      char tmpBuf[64];

      if(i>0) {
	if(snprintf(tmpBuf, sizeof(tmpBuf), ",%s", myGlobals.device[i].name)  < 0)
	  BufferTooShort();
      } else {
	if(snprintf(tmpBuf, sizeof(tmpBuf), "%s", myGlobals.device[i].name) < 0)
	  BufferTooShort();
      }

      strncat(ifStr, tmpBuf, sizeof(ifStr)-strlen(ifStr)-1)[sizeof(ifStr)-1] = '\0';
    }
  }

  if((ifStr == NULL) || (ifStr[0] == '\0')) {
    traceEvent(CONST_TRACE_FATALERROR, "FATAL ERROR: no interface has been selected. Quitting...");
    exit(-1);
  }

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Listening on [%s]", ifStr);

  /* ******************************* */

  checkUserIdentity(userSpecified);

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Loading Plugins");
  loadPlugins();
  traceEvent(CONST_TRACE_NOISY, "Starting Plugins");
  startPlugins();
  traceEvent(CONST_TRACE_NOISY, "Plugins started... continuing with initialization");

  initSignals();

#ifdef HAVE_OPENSSL
  init_ssl();
#endif

  /* create the main listener */
  traceEvent(CONST_TRACE_NOISY, "Starting web server");
  initWeb();
  traceEvent(CONST_TRACE_NOISY, "Web server started... continuing with initialization");

  addNewIpProtocolToHandle("IGMP", 2, 0 /* no proto */);
  addNewIpProtocolToHandle("OSPF", 89, 0 /* no proto */);
  addNewIpProtocolToHandle("IPSEC", 50, 51);

  /*
   * In multithread mode, a separate thread handles packet sniffing
   */
#ifndef CFG_MULTITHREADED
  packetCaptureLoop(&lastTime, myGlobals.refreshRate);
#else
  startSniffer();
#endif

#ifndef WIN32
  while(!myGlobals.endNtop) {
    HEARTBEAT(0, "main(), sleep(3000)...", NULL);
    sleep(10);
    HEARTBEAT(0, "main(), sleep(3000)...woke", NULL);
  }
#endif

#ifndef WIN32
  freeargv(effective_argv);
#endif

  return(0);
}
