/**
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
static char*  short_options = "4:6:a:bce:f:ghi:jkl:m:nop:qr:st:w:x:zAB:C:D:F:MN:O:P:Q:S:U:VX:W:";
#elif defined(MAKE_WITH_SYSLOG)
static char*  short_options = "4:6:a:bcde:f:ghi:jkl:m:nop:qr:st:u:w:x:zAB:C:D:F:IKLMN:O:P:Q:S:U:VX:W:";
#else
static char*  short_options = "4:6:a:bcde:f:ghi:jkl:m:nop:qr:st:u:w:x:zAB:C:D:F:IKMN:O:P:Q:S:U:VX:W:";
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
  { "sampling-rate",                    required_argument, NULL, 'C' },
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

/* ******************************** */

void loadPrefs(int argc, char* argv[]) {
  datum key, nextkey;
  char buf[1024];
  int opt_index, opt;
#ifndef WIN32
  bool userSpecified = FALSE;
#endif

  traceEvent(CONST_TRACE_NOISY, "NOTE: Calling getopt_long to process parameters");
  opt_index = 0, optind = 0;
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
  key = gdbm_firstkey(myGlobals.prefsFile);
  while (key.dptr) {
    if (fetchPrefsValue(key.dptr, buf, sizeof (buf)) == 0) {
      processNtopPref(key.dptr, buf, FALSE, &myGlobals.runningPref);
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
int parseOptions(int argc, char* argv[]) {
  int setAdminPw = 0, opt, userSpecified = 0;
  int opt_index;
  char *adminPw = NULL;

  /* * * * * * * * * * */

  for(opt_index=0; opt_index<argc; opt_index++)
    traceEvent(CONST_TRACE_NOISY, "PARAM_DEBUG: argv[%d]: %s", opt_index, argv[opt_index]);

  /*
   * Parse command line options to the application via standard system calls
   */
  traceEvent(CONST_TRACE_NOISY, "NOTE: Calling getopt_long to process parameters");
  opt_index = 0, optind = 0;
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

    case 'j': /* save other (unknown) packets in a file */
      myGlobals.runningPref.enableOtherPacketDump = 1;
      break;

    case 'k': /* update info of used kernel filter expression in extra frame */
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

    case 'o': /* Do not trust MAC addresses */
      myGlobals.runningPref.dontTrustMACaddr = 1;
      break;

    case 'p': /* the TCP/UDP protocols being monitored */
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

    case 'C': /* Sampling rate */
      stringSanityCheck(optarg);
      myGlobals.runningPref.samplingRate = (u_short)atoi(optarg);
      break;

    case 'D': /* domain */
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
      if(myGlobals.spoolPath != NULL)
	free(myGlobals.spoolPath);
      myGlobals.spoolPath = strdup(optarg);
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
  if(myGlobals.spoolPath == NULL)
    myGlobals.spoolPath = strdup(myGlobals.dbPath);

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

/* ******************************** */

int fetchPrefsValue(char *key, char *value, int valueLen) {
  datum key_data;
  datum data_data;

  if(value == NULL) return(-1);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Entering fetchPrefValue()");
#endif
  value[0] = '\0';

  key_data.dptr  = key;
  key_data.dsize = strlen(key_data.dptr)+1;

  if(myGlobals.prefsFile == NULL) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Leaving fetchPrefValue()");
#endif
    return(-1); /* ntop is quitting... */
  }

  data_data = gdbm_fetch(myGlobals.prefsFile, key_data);

  memset(value, 0, valueLen);

  if(data_data.dptr != NULL) {
    int len = min(valueLen,data_data.dsize);
    strncpy(value, data_data.dptr, len);
    value[len] = '\0';
    free(data_data.dptr);
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Read %s=%s.", key, value);
#endif
    return(0);
  } else
    return(-1);
}

/* ******************************** */

void storePrefsValue(char *key, char *value) {
  datum key_data;
  datum data_data;

  if((value == NULL) || (myGlobals.capturePackets == FLAG_NTOPSTATE_TERM)) return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG:DEBUG:  Entering storePrefsValue()");
#endif

  memset(&key_data, 0, sizeof(key_data));
  key_data.dptr   = key;
  key_data.dsize  = strlen(key_data.dptr)+1;

  memset(&data_data, 0, sizeof(data_data));
  data_data.dptr  = value;
  data_data.dsize = strlen(value)+1;

  if(myGlobals.prefsFile == NULL) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Leaving storePrefsValue()");
#endif
    ; /* ntop is quitting... */
  }

  if(gdbm_store(myGlobals.prefsFile, key_data, data_data, GDBM_REPLACE) != 0)
    traceEvent(CONST_TRACE_ERROR, "While adding %s=%s.", key, value);
  else {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Storing %s=%s.", key, value);
#endif
  }
}

/* ******************************** */

void delPrefsValue (char *key) {
  datum key_data;

  if((key == NULL) || (myGlobals.capturePackets == FLAG_NTOPSTATE_TERM)) return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG:DEBUG:  Entering storePrefsValue()");
#endif

  memset(&key_data, 0, sizeof(key_data));
  key_data.dptr   = key;
  key_data.dsize  = strlen(key_data.dptr)+1;

  if(myGlobals.prefsFile == NULL) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Leaving storePrefsValue()");
#endif
    ; /* ntop is quitting... */
  }

  if(gdbm_delete (myGlobals.prefsFile, key_data) != 0)
    traceEvent(CONST_TRACE_ERROR, "While deleting %s", key);
  else {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Deleted %s", key);
#endif
  }
}

/* ******************************** */

void processStrPref (char *key, char *value, char **globalVar, bool savePref)
{
  if (key == NULL) return;

  if (strcmp (value, "") == 0) {
    /* If a value is specified as NULL but the current value is not, delete
     * the pref. This is assumed to be the way the user will change such a
     * pref.
     */
    if (*globalVar != NULL) {
      free (*globalVar);
      *globalVar = NULL;
      if (savePref) {
	delPrefsValue (key);
      }
    }
  }
  else {
    if (savePref) {

      if((strcmp(key, NTOP_PREF_DEVICES) == 0)
	 && (*globalVar && (*globalVar[0] != '\0'))) {
	/* Values can be concatenated */
	char tmpValue[256];

	safe_snprintf(__FILE__, __LINE__, tmpValue, sizeof(tmpValue), "%s,%s", *globalVar, value);
	storePrefsValue (key, tmpValue);
	free(*globalVar);
	*globalVar = strdup (tmpValue);
	return;
      } else
	storePrefsValue (key, value);
    }

    if (*globalVar)
      free (*globalVar);

    if((value == NULL) || (value[0] == '\0'))
      *globalVar = NULL;
    else
      *globalVar = strdup (value);
  }
}

/* ******************************** */

void processIntPref (char *key, char *value, int *globalVar, bool savePref)
{
  char buf[512];

  if ((key == NULL) || (value == NULL)) return;

  if (savePref) {
    safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf),
		   "%d", atoi (value));
    storePrefsValue (key, buf);
  }

  *globalVar = atoi (value);
}

/* ******************************** */

void processBoolPref (char *key, bool value, bool *globalVar, bool savePref)
{
  char buf[512];

  if (key == NULL) return;

  if (savePref) {
    safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf),
		   "%d", value);
    storePrefsValue (key, buf);
  }

  *globalVar = value;
}

/* ******************************** */

bool processNtopPref (char *key, char *value, bool savePref, UserPref *pref) {
  bool startCap = FALSE;
  char buf[16], *tmpStr = NULL;
  int tmpInt;

  if(value == NULL) value = ""; /* Safer */

  if (strcmp(key, NTOP_PREF_DEVICES) == 0) {
    if ((pref->devices != NULL) &&
	(strcmp (pref->devices, value))) {
      startCap = TRUE;
    }

    if((pref->devices == NULL) || (strstr(pref->devices, value) == NULL))
      processStrPref (NTOP_PREF_DEVICES, value, &pref->devices, savePref);
  } else if(strcmp (key, NTOP_PREF_CAPFILE) == 0) {
    if (((value != NULL) &&
	 (((pref->rFileName != NULL) && (strcmp (pref->rFileName, value)))))
	|| ((value != NULL) && ((pref->rFileName == NULL)))) {
      startCap = TRUE;
    }
    processStrPref (NTOP_PREF_CAPFILE, value, &pref->rFileName, savePref);
  } else if(strcmp (key, NTOP_PREF_FILTER) == 0) {
    processStrPref (NTOP_PREF_FILTER, value, &pref->currentFilterExpression, savePref);
  } else if(strcmp (key, NTOP_PREF_SAMPLING) == 0) {
    int sampleRate;
    processIntPref (NTOP_PREF_SAMPLING, value, &sampleRate, savePref);
    pref->samplingRate = (u_short)sampleRate;
  } else if(strcmp (key, NTOP_PREF_WEBPORT) == 0) {
    if (value != NULL) {
      stringSanityCheck(value);
      if(!isdigit(*value)) {
	traceEvent (CONST_TRACE_ERROR, "flag -w expects a numeric argument.\n");
	return(startCap);
      }

      /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
      if((pref->webAddr = strchr(value,':'))) {
	/* DS: Search for : to find xxx.xxx.xxx.xxx:port */
	/* This code is to be able to bind to a particular interface */
	if (savePref) {
	  storePrefsValue (key, value);
	}
	*pref->webAddr = '\0';
	pref->webPort = atoi(pref->webAddr+1);
	pref->webAddr = strdup (value);
      }
      else {
	processIntPref (NTOP_PREF_WEBPORT, value, &pref->webPort, savePref);
      }
    }
    else {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     DEFAULT_NTOP_WEB_PORT);
      value = buf;
      processIntPref (NTOP_PREF_WEBPORT, value, &pref->webPort, savePref);
    }
  }
#ifdef HAVE_OPENSSL
  else if (strcmp (key, NTOP_PREF_SSLPORT) == 0) {
    if (value != NULL) {
      stringSanityCheck(value);
      if(!isdigit(*value)) {
	traceEvent (CONST_TRACE_ERROR, "flag -w expects a numeric argument.\n");
	return(startCap);
      }

      tmpStr = strdup (value);
      /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
      if((pref->sslAddr = strchr(tmpStr,':'))) {
	/* DS: Search for : to find xxx.xxx.xxx.xxx:port */
	/* This code is to be able to bind to a particular interface */
	if (savePref) {
	  storePrefsValue (key, value);
	}
	*pref->sslAddr = '\0';
	pref->sslPort = atoi(pref->sslAddr+1);
	pref->sslAddr = value;
      } else {
	processIntPref (NTOP_PREF_SSLPORT, value, &pref->sslPort, savePref);
      }
    }
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     DEFAULT_NTOP_WEB_PORT);
      value = buf;
      processIntPref (NTOP_PREF_SSLPORT, value, &pref->sslPort, savePref);
    }
  }
#endif
  else if (strcmp (key, NTOP_PREF_EN_SESSION) == 0) {
    processBoolPref (NTOP_PREF_EN_SESSION, TRUE,
		     &pref->enableSessionHandling, savePref);
  } else if(strcmp (key, NTOP_PREF_EN_PROTO_DECODE) == 0) {
    processBoolPref (NTOP_PREF_EN_PROTO_DECODE, TRUE,
		     &pref->enablePacketDecoding, savePref);
  } else if(strcmp (key, NTOP_PREF_FLOWSPECS) == 0) {
    processStrPref (NTOP_PREF_FLOWSPECS, value, &pref->flowSpecs, savePref);
  } else if(strcmp (key, NTOP_PREF_LOCALADDR) == 0) {
    processStrPref (NTOP_PREF_LOCALADDR, value, &pref->localAddresses,
		    savePref);
  } else if(strcmp (key, NTOP_PREF_STICKY_HOSTS) == 0) {
    processBoolPref (NTOP_PREF_STICKY_HOSTS, TRUE, &pref->stickyHosts,
		     savePref);
  } else if(strcmp (key, NTOP_PREF_TRACK_LOCAL) == 0) {
    processBoolPref (NTOP_PREF_TRACK_LOCAL, TRUE,
		     &pref->trackOnlyLocalHosts, savePref);
  } else if(strcmp (key, NTOP_PREF_NO_PROMISC) == 0) {
    processBoolPref (NTOP_PREF_NO_PROMISC, TRUE,
		     &pref->disablePromiscuousMode, savePref);
  } else if(strcmp (key, NTOP_PREF_DAEMON) == 0) {
    processBoolPref (NTOP_PREF_DAEMON, TRUE, &pref->daemonMode,
		     savePref);
  } else if(strcmp (key, NTOP_PREF_REFRESH_RATE) == 0) {
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     DEFAULT_NTOP_AUTOREFRESH_INTERVAL);
      value = buf;
    }
    processIntPref (NTOP_PREF_REFRESH_RATE, value, &pref->refreshRate,
		    savePref);
  } else if(strcmp (key, NTOP_PREF_MAXLINES) == 0) {
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     CONST_NUM_TABLE_ROWS_PER_PAGE);
      value = buf;
    }
    processIntPref (NTOP_PREF_MAXLINES, value, &pref->maxNumLines,
		    savePref);
  } else if(strcmp (key, NTOP_PREF_PRINT_FCORIP) == 0) {
    tmpInt = atoi (value);
    if (tmpInt == NTOP_PREF_VALUE_PRINT_IPONLY) {
      pref->printIpOnly = TRUE, pref->printFcOnly = FALSE;
    }
    else if (tmpInt == NTOP_PREF_VALUE_PRINT_FCONLY) {
      pref->printIpOnly = FALSE, pref->printFcOnly = TRUE;
    }
    else {
      pref->printIpOnly = FALSE, pref->printFcOnly = FALSE;
    }

    processIntPref (NTOP_PREF_PRINT_FCORIP, value, &tmpInt, savePref);
  } else if(strcmp (key, NTOP_PREF_NO_INVLUN) == 0) {
    processBoolPref (NTOP_PREF_NO_INVLUN, TRUE,
		     &pref->noInvalidLunDisplay, savePref);
  } else if(strcmp (key, NTOP_PREF_FILTER_EXTRA_FRM) == 0) {
    processBoolPref (NTOP_PREF_FILTER_EXTRA_FRM, TRUE,
		     &pref->filterExpressionInExtraFrame, savePref);
  } else if(strcmp (key, NTOP_PREF_W3C) == 0) {
    processBoolPref (NTOP_PREF_W3C, TRUE, &pref->w3c, savePref);
  } else if(strcmp (key, NTOP_PREF_IPV4V6) == 0) {
    processIntPref (NTOP_PREF_IPV4V6, value, &pref->ipv4or6, savePref);
  } else if(strcmp (key, NTOP_PREF_DOMAINNAME) == 0) {
    processStrPref (NTOP_PREF_DOMAINNAME, value, &tmpStr,
		    savePref);
    if (tmpStr != NULL) {
      strncpy (pref->domainName, tmpStr, sizeof (pref->domainName));
      free (tmpStr);      /* alloc'd in processStrPref() */
    }
  } else if(strcmp (key, NTOP_PREF_NUMERIC_IP) == 0) {
    processBoolPref (NTOP_PREF_NUMERIC_IP, TRUE, &pref->numericFlag,
		     savePref);
  } else if(strcmp (key, NTOP_PREF_PROTOSPECS) == 0) {
    processStrPref (NTOP_PREF_PROTOSPECS, value, &pref->protoSpecs,
		    savePref);
  } else if(strcmp (key, NTOP_PREF_P3PCP) == 0) {
    processStrPref (NTOP_PREF_P3PCP, value, &pref->P3Pcp, savePref);
  } else if(strcmp (key, NTOP_PREF_P3PURI) == 0) {
    processStrPref (NTOP_PREF_P3PURI, value, &pref->P3Puri, savePref);
  } else if(strcmp (key, NTOP_PREF_MAPPERURL) == 0) {
    processStrPref (NTOP_PREF_MAPPERURL, value, &pref->mapperURL, savePref);
  } else if(strcmp (key, NTOP_PREF_WWN_MAP) == 0) {
    processStrPref (NTOP_PREF_WWN_MAP, value, &pref->fcNSCacheFile,
		    savePref);
  } else if(strcmp (key, NTOP_PREF_MAXHASH) == 0) {
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     -1);
      value = buf;
    }
    processIntPref (NTOP_PREF_MAXHASH, value,
		    &pref->maxNumHashEntries, savePref);
  } else if(strcmp (key, NTOP_PREF_MAXSESSIONS) == 0) {
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     -1);
      value = buf;
    }
    processIntPref (NTOP_PREF_MAXSESSIONS, value,
		    &pref->maxNumSessions, savePref);
  } else if(strcmp (key, NTOP_PREF_MERGEIF) == 0) {
    processBoolPref (NTOP_PREF_MERGEIF, TRUE,
		     &pref->mergeInterfaces, savePref);
  } else if(strcmp (key, NTOP_PREF_NO_ISESS_PURGE) == 0) {
    processBoolPref (NTOP_PREF_NO_ISESS_PURGE, TRUE,
		     &pref->disableInstantSessionPurge, savePref);
  }
#if !defined(WIN32) && defined(HAVE_PCAP_SETNONBLOCK)
  else if (strcmp (key, NTOP_PREF_NOBLOCK) == 0) {
    processBoolPref (NTOP_PREF_NOBLOCK, TRUE,
		     &pref->setNonBlocking, savePref);
  }
#endif
  else if (strcmp (key, NTOP_PREF_NO_STOPCAP) == 0) {
    processBoolPref (NTOP_PREF_NO_STOPCAP, TRUE,
		     &pref->disableStopcap, savePref);
  } else if(strcmp (key, NTOP_PREF_NO_TRUST_MAC) == 0) {
    processBoolPref (NTOP_PREF_NO_TRUST_MAC, TRUE,
		     &pref->dontTrustMACaddr, savePref);
  } else if(strcmp (key, NTOP_PREF_PCAP_LOGBASE) == 0) {
    processStrPref (NTOP_PREF_PCAP_LOGBASE, value,
		    &pref->pcapLogBasePath, savePref);
  }
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
  else if (strcmp (key, NTOP_PREF_USE_SSLWATCH) == 0) {
    processBoolPref (NTOP_PREF_USE_SSLWATCH, TRUE,
		     &pref->useSSLwatchdog, savePref);
  }
#endif
  else if (strcmp (key, NTOP_PREF_DBG_MODE) == 0) {
    processBoolPref (NTOP_PREF_DBG_MODE, TRUE, &pref->debugMode,
		     savePref);
  } else if(strcmp (key, NTOP_PREF_TRACE_LVL) == 0) {
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     DEFAULT_TRACE_LEVEL);
      value = buf;
    }
    processIntPref (NTOP_PREF_TRACE_LVL, value, &pref->traceLevel,
		    savePref);
  } else if(strcmp (key, NTOP_PREF_DUMP_OTHER) == 0) {
    processBoolPref (NTOP_PREF_DUMP_OTHER, TRUE,
		     &pref->enableOtherPacketDump, savePref);
  } else if(strcmp (key, NTOP_PREF_DUMP_SUSP) == 0) {
    processBoolPref (NTOP_PREF_DUMP_SUSP, TRUE,
		     &pref->enableSuspiciousPacketDump, savePref);
  } else if(strcmp (key, NTOP_PREF_ACCESS_LOG) == 0) {
    processStrPref (NTOP_PREF_ACCESS_LOG, value,
		    &pref->accessLogFile,
		    savePref);
  }
#ifndef WIN32
  else if (strcmp (key, NTOP_PREF_USE_SYSLOG) == 0) {
    if (value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "%d",
		     DEFAULT_NTOP_SYSLOG);
      value = buf;
    }
    processIntPref (NTOP_PREF_USE_SYSLOG, value,
		    &pref->useSyslog, savePref);
  }
#endif
  else if (strcmp (key, NTOP_PREF_PCAP_LOG) == 0) {
    processStrPref (NTOP_PREF_PCAP_LOG, value, &pref->pcapLog, savePref);
  } else if(strcmp (key, NTOP_PREF_NO_MUTEX_EXTRA) == 0) {
    processBoolPref (NTOP_PREF_NO_MUTEX_EXTRA, TRUE,
		     &pref->disableMutexExtraInfo, savePref);
  }
#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)
  else if (strcmp (key, NTOP_PREF_NO_SCHEDYLD) == 0) {
    processBoolPref (NTOP_PREF_NO_SCHEDYLD, TRUE,
		     &pref->disableSchedYield, savePref);
  }
#endif
  else if (strncmp (key, "ntop.", strlen ("ntop.")) == 0) {
    traceEvent (CONST_TRACE_WARNING, "Unknown preference: %s, value = %s\n",
		key, (value == NULL) ? "(null)" : value);
  }

  return (startCap);
}

/* ************************************************* */

/*
 * Initialize all preferences to their default values
 */
void initUserPrefs (UserPref *pref)
{
  pref->accessLogFile = DEFAULT_NTOP_ACCESS_LOG_FILE;
  pref->enablePacketDecoding   = DEFAULT_NTOP_PACKET_DECODING;
  pref->stickyHosts = DEFAULT_NTOP_STICKY_HOSTS;
  pref->daemonMode = DEFAULT_NTOP_DAEMON_MODE;
  pref->rFileName = DEFAULT_NTOP_TRAFFICDUMP_FILENAME;
  pref->trackOnlyLocalHosts    = DEFAULT_NTOP_TRACK_ONLY_LOCAL;
  pref->devices = DEFAULT_NTOP_DEVICES;
  pref->enableOtherPacketDump = DEFAULT_NTOP_OTHER_PKT_DUMP;
  pref->filterExpressionInExtraFrame = DEFAULT_NTOP_FILTER_IN_FRAME;
  pref->pcapLog = DEFAULT_NTOP_PCAP_LOG_FILENAME;
  pref->localAddresses = DEFAULT_NTOP_LOCAL_SUBNETS;
  pref->numericFlag = DEFAULT_NTOP_NUMERIC_IP_ADDRESSES;
  pref->dontTrustMACaddr = DEFAULT_NTOP_DONT_TRUST_MAC_ADDR;
  pref->protoSpecs = DEFAULT_NTOP_PROTO_SPECS;
  pref->enableSuspiciousPacketDump = DEFAULT_NTOP_SUSPICIOUS_PKT_DUMP;
  pref->refreshRate = DEFAULT_NTOP_AUTOREFRESH_INTERVAL;
  pref->disablePromiscuousMode = DEFAULT_NTOP_DISABLE_PROMISCUOUS;
  pref->traceLevel = DEFAULT_TRACE_LEVEL;
  pref->maxNumHashEntries = DEFAULT_NTOP_MAX_HASH_ENTRIES;
  pref->maxNumSessions    = DEFAULT_NTOP_MAX_NUM_SESSIONS;
  pref->webAddr = DEFAULT_NTOP_WEB_ADDR;
  pref->webPort = DEFAULT_NTOP_WEB_PORT;
  pref->ipv4or6 = DEFAULT_NTOP_FAMILY;
  pref->samplingRate =  myGlobals.savedPref.samplingRate;
  pref->enableSessionHandling  = DEFAULT_NTOP_ENABLE_SESSIONHANDLE;
  pref->currentFilterExpression = DEFAULT_NTOP_FILTER_EXPRESSION;
  strncpy((char *) &pref->domainName, DEFAULT_NTOP_DOMAIN_NAME, sizeof(pref->domainName));
  pref->flowSpecs = DEFAULT_NTOP_FLOW_SPECS;
  pref->debugMode = DEFAULT_NTOP_DEBUG_MODE;
#ifndef WIN32
  pref->useSyslog = DEFAULT_NTOP_SYSLOG;
#endif
  pref->mergeInterfaces = DEFAULT_NTOP_MERGE_INTERFACES;
#ifdef WIN32
  pref->pcapLogBasePath = strdup(_wdir);     /* a NULL pointer will
					      * break the logic */
#else
  pref->pcapLogBasePath = strdup(CFG_DBFILE_DIR);
#endif
  pref->fcNSCacheFile   = DEFAULT_NTOP_FCNS_FILE;
  /* note that by default ntop will merge network interfaces */
  pref->mapperURL = DEFAULT_NTOP_MAPPER_URL;
#ifdef HAVE_OPENSSL
  pref->sslAddr = DEFAULT_NTOP_WEB_ADDR;
  pref->sslPort = DEFAULT_NTOP_WEB_PORT;
#endif
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
   pref->useSSLwatchdog = 0;
#endif

#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)
   pref->disableSchedYield = DEFAULT_NTOP_SCHED_YIELD;
#endif

   pref->w3c    = DEFAULT_NTOP_W3C;
   pref->P3Pcp  = DEFAULT_NTOP_P3PCP;
   pref->P3Puri = DEFAULT_NTOP_P3PURI;

#if !defined(WIN32) && defined(HAVE_PCAP_SETNONBLOCK)
   pref->setNonBlocking = DEFAULT_NTOP_SETNONBLOCK;
#endif
   pref->disableStopcap = DEFAULT_NTOP_DISABLE_STOPCAP;
   pref->disableInstantSessionPurge = DEFAULT_NTOP_DISABLE_IS_PURGE;
   pref->printIpOnly = DEFAULT_NTOP_PRINTIPONLY;
   pref->printFcOnly = DEFAULT_NTOP_PRINTFCONLY;
   pref->noInvalidLunDisplay = DEFAULT_NTOP_NO_INVLUN_DISPLAY;
   pref->disableMutexExtraInfo = DEFAULT_NTOP_DISABLE_MUTEXINFO;
   pref->skipVersionCheck = DEFAULT_NTOP_SKIP_VERSION_CHECK;
}


/* *******************************/
