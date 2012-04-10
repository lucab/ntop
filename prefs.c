/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *                          http://www.ntop.org
 *
 *             Copyright (C) 1998-2012 Luca Deri <deri@ntop.org>
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
static char*  short_options = "46a:bce:f:ghi:l:m:n:p:qr:st:w:x:zAB:C:D:F:M" 
#if defined(DARWIN) && (!defined(TIGER))
  "v"
#endif
  "O:P:Q:S:U:VX:W:";
#elif defined(MAKE_WITH_SYSLOG)
static char*  short_options = "46a:bcde:f:ghi:l:m:n:p:qr:st:u:w:x:zAB:C:D:F:IKLM" 
#if defined(DARWIN) && (!defined(TIGER))
  "v"
#endif
  "O:P:Q:S:U:VX:W:";
#else
static char*  short_options = "46a:bcde:f:ghi:l:m:n:p:qr:st:u:w:x:zAB:C:D:F:IKM"
#if defined(DARWIN) && (!defined(TIGER))
  "v"
#endif
  "O:P:Q:S:U:VX:W:";
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
  { "pcap-log",                         required_argument, NULL, 'l' },
  { "local-subnets",                    required_argument, NULL, 'm' },
  { "numeric-ip-addresses",             required_argument, NULL, 'n' },
  /* 'o' is free */

  { "protocols",                        required_argument, NULL, 'p' },
  { "create-suspicious-packets",        no_argument,       NULL, 'q' },
  { "refresh-time",                     required_argument, NULL, 'r' },
  { "no-promiscuous",                   no_argument,       NULL, 's' },
  { "trace-level",                      required_argument, NULL, 't' },

#ifndef WIN32
  { "user",                             required_argument, NULL, 'u' },
#endif

#if defined(DARWIN) && (!defined(TIGER))
  { "osx-daemon",                       no_argument,       NULL, 'v' },
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

  /* 132/133/134 are AVAILABLE */

  { "set-admin-password",               optional_argument, NULL, 135 },

  { "w3c",                              no_argument,       NULL, 136 },

  { "p3p-cp",                           required_argument, NULL, 137 },
  { "p3p-uri",                          required_argument, NULL, 138 },

  { "instance",                         required_argument, NULL, 140 },

  { "disable-stopcap",                  no_argument,       NULL, 142 },
  { "disable-instantsessionpurge",      no_argument,       NULL, 144 },
  { "disable-mutexextrainfo",           no_argument,       NULL, 145 },
  { "disable-ndpi",                     no_argument,       NULL, 146 },
  { "disable-python",                   no_argument,       NULL, 147 },
  
  { "skip-version-check",               required_argument, NULL, 150 },
  { "known-subnets",                    required_argument, NULL, 151 },

  {NULL, 0, NULL, 0}
};

/* ******************************** */

void loadPrefs(int argc, char* argv[]) {
  datum key, nextkey;
  char buf[1024];
  int opt_index, opt;
  bool mergeInterfacesSave = myGlobals.runningPref.mergeInterfaces;

  memset(&buf, 0, sizeof(buf));

  traceEvent(CONST_TRACE_NOISY, "NOTE: Processing parameters (pass1)");
  opt_index = 0, optind = 0;
    
  while ((opt = getopt_long(argc, argv, short_options, long_options, &opt_index)) != EOF) {
    switch (opt) {
    case 'h': /* help */
      usage(stdout);
      exit(0);

#ifndef WIN32
    case 'u':
      stringSanityCheck(optarg, "-u | --user");
      if(myGlobals.effectiveUserName != NULL) free(myGlobals.effectiveUserName);
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
      break;
#endif /* WIN32 */

    case 't':
      /* Trace Level Initialization */
      myGlobals.runningPref.traceLevel = min(max(1, atoi(optarg)),
					     CONST_BEYONDNOISY_TRACE_LEVEL);
      /* DETAILED is NOISY + FileLine stamp, unless already set */
      break;

    case 'P':
      stringSanityCheck(optarg, "-P | --db-file-path");
      if(myGlobals.dbPath != NULL) free(myGlobals.dbPath);

      myGlobals.dbPath = strdup(optarg);
      break;
    }
  }

  /* ******************************* */

  /* open/create all the databases */
  initGdbm(NULL, NULL, 1);

  if(myGlobals.prefsFile == NULL) {
    traceEvent(CONST_TRACE_NOISY, "NOTE: No preferences file to read from - continuing");
    return;
  }

  traceEvent(CONST_TRACE_NOISY, "NOTE: Reading preferences file entries");
  key = gdbm_firstkey(myGlobals.prefsFile);
  while (key.dptr) {
    /* Handle key w/o trailing \0 so valgrind is happy */
    zeroPadMallocString(key.dsize, key.dptr);

    if(fetchPrefsValue(key.dptr, buf, sizeof(buf)) == 0)
      processNtopPref(key.dptr, buf, FALSE, &myGlobals.runningPref);    

    nextkey = gdbm_nextkey (myGlobals.prefsFile, key);
    free (key.dptr);
    key = nextkey;
  }

  if(myGlobals.runningPref.mergeInterfaces != mergeInterfacesSave) {
    if(myGlobals.runningPref.mergeInterfaces == 0)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NOTE: Interface merge disabled from prefs file");
    else
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NOTE: Interface merge enabled from prefs file");
  }

  myGlobals.savedPref = myGlobals.runningPref;
}

/* ***************************************************** */

static void readPcapFileList(char * filenames) {
  char *line, ebuf[CONST_SIZE_PCAP_ERR_BUF];
  int idx;
  struct fileList *fl, *prev;

  line = strtok(filenames, ",");

  while(line != NULL) {
    if((line[0] != '#') && (line[0] != '\n')) {      
      while(strlen(line) && (line[strlen(line)-1] == '\n')) line[strlen(line)-1] = '\0';
      fl = (struct fileList*)malloc(sizeof(struct fileList));

      if(!fl) {
	traceEvent(CONST_TRACE_ERROR, "Not enough memory parsing -f argument");
	return;
      }

      idx = 0; while((line[idx] == ' ') && (line[idx] != '\0') && (line[idx] != ',')) idx++;
      fl->fileName = strdup(&line[idx]);
      traceEvent(CONST_TRACE_ERROR, "'%s'",  fl->fileName);

      if(!fl->fileName) {
	free(fl);
	traceEvent(CONST_TRACE_ERROR, "Not enough memory parsing -f argument");
	return;
      }

      fl->pcapPtr = pcap_open_offline(fl->fileName, ebuf);

      if(fl->pcapPtr == NULL) {
	traceEvent(CONST_TRACE_ERROR, "Skipping pcap file %s: '%s'", fl->fileName, ebuf);
	free(fl->fileName);
	free(fl);
      } else {	
	fl->next = NULL;      
	
	if(myGlobals.pcap_file_list != NULL) {
	  prev = myGlobals.pcap_file_list;
	  while(prev != NULL) {
	    if(prev->next)
	      prev = prev->next;
	    else
	      break;
	  }
	
	  prev->next = fl;
	} else
	  myGlobals.pcap_file_list = fl;
      }
    }

    line = strtok(NULL, ",");
  }
}

/* ***************************************************** */
/*	NOTE
	In the function below do NOT free myGlobals.runningPref.*
	as this value is used in myGlobals.savedPref.*
*/

/*
 * Parse the command line options
 */
int parseOptions(int argc, char* argv[]) {
  int setAdminPw = 0, opt, userSpecified = 0;
  int opt_index;
  char *adminPw = NULL;

  /* * * * * * * * * * */

#ifdef PARAM_DEBUG
  for(opt_index=0; opt_index<argc; opt_index++)
    traceEvent(CONST_TRACE_NOISY, "PARAM_DEBUG: argv[%d]: %s", opt_index, argv[opt_index]);
#endif

  /*
   * Parse command line options to the application via standard system calls
   */
  traceEvent(CONST_TRACE_NOISY, "NOTE: Processing parameters (pass2)");
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
      pathSanityCheck(optarg, "-a | --access-log-file");
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
      /* traceEvent(CONST_TRACE_ERROR, "++++ DEMON MODE=%d\n", myGlobals.runningPref.daemonMode); */
      break;
#endif

    case 'e':
      myGlobals.runningPref.maxNumLines = atoi(optarg);
      break;

    case 'f':
      readPcapFileList(optarg);
      break;

    case 'g':
      myGlobals.runningPref.trackOnlyLocalHosts    = 1;
      break;

    case 'h':                                /* help */
      usage(stdout);
      exit(0);

    case 'i': /* More than one interface may be specified in a comma separated list */
#ifndef WIN32
      stringSanityCheck(optarg, "-i | --interface");
#endif
      myGlobals.runningPref.devices = strdup(optarg);
      break;

    case 'l':
      pathSanityCheck(optarg, "-l | --pcap-log");
      myGlobals.runningPref.pcapLog = strdup(optarg);
      break;

    case 'm':
      stringSanityCheck(optarg, "-m | --local-subnets");
      myGlobals.runningPref.localAddresses = strdup(optarg);
      break;

    case 'n':
      myGlobals.runningPref.numericFlag = atoi(optarg);
      if(myGlobals.runningPref.numericFlag > dnsResolutionForAll) {
	traceEvent(CONST_TRACE_WARNING, "Invalid value for -n: setting it to 0");
	myGlobals.runningPref.numericFlag = noDnsResolution;
      }
      break;

    case 'p': /* the TCP/UDP protocols being monitored */
      stringSanityCheck(optarg, "-p | --protocols");
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
                                             CONST_BEYONDNOISY_TRACE_LEVEL);
      /* DETAILED is NOISY + FileLine stamp, unless already set */
      break;

#ifndef WIN32
    case 'u':
      stringSanityCheck(optarg, "-u | --user");
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

#if defined(DARWIN) && (!defined(TIGER))
    case 'v':
      myGlobals.runningPref.daemonMode = 1;
      break;
#endif

    case 'w':
      stringSanityCheck(optarg, "-w | --http-server");
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
      //myGlobals.runningPref.maxNumHashEntries = atoi(optarg);
      myGlobals.runningPref.maxNumHashEntries = strtoul(optarg, NULL, 0);
      break;

    case 'z':
      myGlobals.runningPref.enableSessionHandling = 0;
      break;

    case 'A':
      setAdminPw = 1;
      break;

    case 'B':
      stringSanityCheck(optarg, "-B | --filter-expression");
      if(myGlobals.runningPref.currentFilterExpression == NULL)
	myGlobals.runningPref.currentFilterExpression = strdup(optarg);
      break;

    case 'C': /* Sampling rate */
      stringSanityCheck(optarg, "-C | --sampling-rate");
      myGlobals.runningPref.samplingRate = (u_short)atoi(optarg);
      break;

    case 'D': /* domain */
      uriSanityCheck(optarg, "-D | --domain", FALSE);
      strncpy(myGlobals.runningPref.domainName, optarg, MAXHOSTNAMELEN);
      break;

    case 'F':
      stringSanityCheck(optarg, "-F | --flow-spec");
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
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NOTE: Interface merge disabled due to command line switch");
      break;

    case 'O': /* pcap log path - Ola Lundqvist <opal@debian.org> */
      pathSanityCheck(optarg, "-O | --output-packet-path");
       myGlobals.runningPref.pcapLogBasePath = strdup(optarg);
      break;

    case 'P':
      pathSanityCheck(optarg, "-P | --db-file-path");
      if(myGlobals.dbPath != NULL) free(myGlobals.dbPath);

      if(optarg[strlen(optarg)-1] == '/') optarg[strlen(optarg)-1] = '\0';
      mkdir_p("dbPath", optarg, 0777);
      myGlobals.dbPath = strdup(optarg);
      break;

    case 'Q': /* Spool Path (ntop's spool directory) */
      pathSanityCheck(optarg, "-Q | --spool-file-path" );
      if(myGlobals.spoolPath != NULL) free(myGlobals.spoolPath);
      if(optarg[strlen(optarg)-1] == '/') optarg[strlen(optarg)-1] = '\0';
      mkdir_p("spoolPath", optarg, 0777);
      myGlobals.spoolPath = strdup(optarg);
      break;

    case 'U': /* host:port - a good mapper is at http://jake.ntop.org/cgi-bin/mapper.pl */
      uriSanityCheck(optarg, "-U | --mapper", TRUE);
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
      //myGlobals.runningPref.maxNumSessions = atoi(optarg);
      myGlobals.runningPref.maxNumSessions = strtoul(optarg, NULL, 0);
      break;

#ifdef HAVE_OPENSSL
    case 'W':
      stringSanityCheck(optarg, "-W | --https-server");
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
      if(optarg) {
	int i;

	stringSanityCheck(optarg, "--use-syslog");

	for (i=0; myFacilityNames[i].c_name != NULL; i++) {
	  if(strcmp(optarg, myFacilityNames[i].c_name) == 0) {
	    break;
	  }
	}

	if(myFacilityNames[i].c_name == NULL) {
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

    case 135:
      /* Dennis Schoen (dennis@cns.dnsalias.org) allow --set-admin-password=<password> */
      if(optarg) {
        stringSanityCheck(optarg, "--set-admin-password");
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
      stringSanityCheck(optarg, "--p3pcp");
      myGlobals.runningPref.P3Pcp = strdup(optarg);
      break;

    case 138:
      uriSanityCheck(optarg, "--p3puri", FALSE);
      myGlobals.runningPref.P3Puri = strdup(optarg);
      break;

    case 140: /* instance */
    {
      int idx, found;
      struct stat statbuf;
      char fileName[64], tmpStr[512];
      FILE *fd;

      stringSanityCheck(optarg, "--instance");
      myGlobals.runningPref.instance = strdup(optarg);

      memset(&tmpStr, 0, sizeof(tmpStr));
      memset(&fileName, 0, sizeof(fileName));
      for(found=0, idx=0; (found != 1) && (myGlobals.dataFileDirs[idx] != NULL); idx++) {
        safe_snprintf(__FILE__, __LINE__, fileName, sizeof(fileName),
                      "%s_" CONST_NTOP_LOGO,
                      myGlobals.runningPref.instance);
        safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
                      "%s/html/%s",
                      myGlobals.dataFileDirs[idx],
                      fileName);
        revertSlashIfWIN32(tmpStr, 0);

        if((stat(tmpStr, &statbuf) == 0) && ((fd = fopen(tmpStr, "rb")) != NULL)) {
          found = 1;
          fclose(fd);
          myGlobals.runningPref.logo = strdup(fileName);
          break;
        }
      }

      if(found != 1)
        traceEvent(CONST_TRACE_WARNING, "Cannot find per-instance logo '%s', ignored...", fileName);

      break;
    }

    case 142: /* disable-stopcap */
      myGlobals.runningPref.disableStopcap = TRUE;
      break;

    case 145: /* disable-mutexextrainfo */
      myGlobals.runningPref.disableMutexExtraInfo = TRUE;
      break;

    case 146: /* disable-ndpi */
      myGlobals.runningPref.disablenDPI = TRUE;
      break;

    case 147:
      myGlobals.runningPref.disablePython = TRUE;
      break;

    case 150:
      myGlobals.runningPref.skipVersionCheck = TRUE;
      break;

    case 151:
      stringSanityCheck(optarg, "--known-subnets");
      myGlobals.runningPref.knownSubnets = strdup(optarg);
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

  if(myGlobals.runningPref.daemonMode) {
    /* 
       In order to avoid ntop fail to start when running in daemon mode
       we check if the admin password has been set and if not we set 
       the default password. This way we can avoid ntop startup fail 
    */
    setAdminPw = 1; /* NOTE: the password is not overwritten if already present */
    if(adminPw == NULL) adminPw = "admin";
  }

  if(setAdminPw) {
    setAdminPassword(adminPw);

    if(!myGlobals.runningPref.daemonMode) {
      termGdbm();
      exit(0);
    }
  }

#if defined(DARWIN) && (!defined(TIGER))
  /* Trick for OSX: search check_osx_daemonization */
  myGlobals.runningPref.daemonMode = 0;
#endif

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

static int fetchGdbmValue(GDBM_FILE gdbmfile, char *key, char *value, int valueLen) {
  datum key_data;
  datum data_data;

  if(value == NULL) return(-1);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: Entering fetchGdbmValue()");
#endif
  value[0] = '\0';

  key_data.dptr  = key;
  key_data.dsize = (int)(strlen(key_data.dptr)+1);

  if(gdbmfile == NULL) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Leaving fetchGdbmValue()");
#endif
    return(-1); /* ntop is quitting... */
  }

  data_data = gdbm_fetch(gdbmfile, key_data);

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

int fetchPrefsValue(char *key, char *value, int valueLen) {
  return(fetchGdbmValue(myGlobals.prefsFile, key, value, valueLen));
}

/* ******************************** */

int fetchPwValue(char *key, char *value, int valueLen) {
  return(fetchGdbmValue(myGlobals.pwFile, key, value, valueLen));
}

/* ******************************** */

static void storeGdbmValue(GDBM_FILE gdbmfile, char *key, char *value) {
  datum key_data;
  datum data_data;

  if((value == NULL) || (myGlobals.ntopRunState >= FLAG_NTOPSTATE_SHUTDOWN)) return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG:  Entering storePrefsValue()");
#endif

  memset(&key_data, 0, sizeof(key_data));
  key_data.dptr   = key;
  key_data.dsize  = (int)(strlen(key_data.dptr)+1);

  memset(&data_data, 0, sizeof(data_data));
  data_data.dptr  = value;
  data_data.dsize = (int)(strlen(value)+1);

  if(gdbmfile == NULL) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Leaving storePrefsValue()");
#endif
    ; /* ntop is quitting... */
  }

  if(gdbm_store(gdbmfile, key_data, data_data, GDBM_REPLACE) != 0)
    traceEvent(CONST_TRACE_ERROR, "While adding %s=%s.", key, value);
  else {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Storing %s=%s.", key, value);
#endif
  }
}

/* ******************************** */

void storePrefsValue(char *key, char *value) {
  storeGdbmValue(myGlobals.prefsFile, key, value);
  checkCommunities(); /* Check if communities are defined */
  readSessionPurgeParams(); /* Re-read if necessary */
}

/* ******************************** */

void storePwValue(char *key, char *value) {
  storeGdbmValue(myGlobals.pwFile, key, value);
}

/* ******************************** */

static void delGdbmValue(GDBM_FILE gdbmfile, char *key) {
  datum key_data;

  if((key == NULL) || (myGlobals.ntopRunState >= FLAG_NTOPSTATE_SHUTDOWN)) return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG:  Entering storePrefsValue()");
#endif

  memset(&key_data, 0, sizeof(key_data));
  key_data.dptr   = key;
  key_data.dsize  = (int)(strlen(key_data.dptr)+1);

  if(gdbmfile == NULL) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "DEBUG: Leaving storePrefsValue()");
#endif
    ; /* ntop is quitting... */
  }

  if(gdbm_delete(gdbmfile, key_data) != 0) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_ERROR, "While deleting %s: key not found", key);
#endif
  } else {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "Deleted %s", key);
#endif
  }
}

/* ******************************** */

void delPrefsValue(char *key) {
  delGdbmValue(myGlobals.prefsFile, key);
  checkCommunities(); /* Check if communities are defined */
}

/* ******************************** */

void delPwValue(char *key) {
  delGdbmValue(myGlobals.pwFile, key);
}

/* ******************************** */

void processStrPref(char *key, char *value, char **globalVar, bool savePref)
{
  if(key == NULL) return;

  if(strcmp(value, "") == 0) {
    /* If a value is specified as NULL but the current value is not, delete
     * the pref. This is assumed to be the way the user will change such a
     * pref.
     */
    if(*globalVar != NULL) {
      free (*globalVar);
      *globalVar = NULL;
    }
	
	 *globalVar = strdup(value);
     if(savePref) delPrefsValue (key);
  }
  else {
    if(savePref) {

      if((strcmp(key, NTOP_PREF_DEVICES) == 0)
	 && (*globalVar && (*globalVar[0] != '\0'))) {
	/* Values can be concatenated */
	char tmpValue[256];

	safe_snprintf(__FILE__, __LINE__, tmpValue, sizeof(tmpValue),
		      "%s,%s", *globalVar, value);
	storePrefsValue(key, tmpValue);
	free(*globalVar);
	*globalVar = strdup (tmpValue);
	return;
      } else
	storePrefsValue(key, value);
    }

    if(*globalVar)
      free (*globalVar);

    if((value == NULL) || (value[0] == '\0'))
      *globalVar = NULL;
    else
      *globalVar = strdup (value);
  }
}

/* ******************************** */

void processIntPref(char *key, char *value, int *globalVar, bool savePref)
{
  char buf[512];

  if((key == NULL) || (value == NULL)) return;

  *globalVar = atoi(value);

  if(savePref) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", *globalVar);
    storePrefsValue(key, buf);
  }
}

/* ******************************** */

void processUIntPref(char *key, char *value, u_int *globalVar, bool savePref)
{
  char buf[512];

  if((key == NULL) || (value == NULL)) return;

  *globalVar = strtoul(value, NULL, 0);

  if(savePref) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", *globalVar);
    storePrefsValue(key, buf);
  }
}

/* ******************************** */

void processBoolPref(char *key, bool value, bool *globalVar, bool savePref)
{
  char buf[512];

  if(key == NULL) return;

  if(savePref) {
    safe_snprintf (__FILE__, __LINE__, buf, sizeof(buf),
		   "%d", value);
    storePrefsValue(key, buf);
  }

  *globalVar = value;
}

/* ******************************** */

static bool value2bool(char* value) {
  if(value && (strcmp(value, "1") == 0))
    return(TRUE);
  else
    return(FALSE);
}

/* ******************************** */

bool processNtopPref(char *key, char *value, bool savePref, UserPref *pref) {
  bool startCap = FALSE;
  char buf[16], *tmpStr = NULL;

  if(value == NULL) value = ""; /* Safer */

  /* traceEvent(CONST_TRACE_ERROR, "==>> processNtopPref [%s][%s]", key, value); */
  
  if(strcmp(key, NTOP_PREF_DEVICES) == 0) {
    if((pref->devices != NULL) && (strcmp(pref->devices, value))) {
      startCap = TRUE;
    }

    if((pref->devices == NULL) || (strstr(pref->devices, value) == NULL))
      processStrPref(NTOP_PREF_DEVICES, value, &pref->devices, savePref);
  } else if(strcmp(key, NTOP_PREF_FILTER) == 0) {
    processStrPref(NTOP_PREF_FILTER, value, &pref->currentFilterExpression, savePref);
  } else if(strcmp(key, NTOP_PREF_SAMPLING) == 0) {
    int sampleRate;
    processIntPref(NTOP_PREF_SAMPLING, value, &sampleRate, savePref);
    pref->samplingRate = (u_short)sampleRate;
  } else if(strcmp(key, NTOP_PREF_WEBPORT) == 0) {
    if(value != NULL) {
      stringSanityCheck(value, "-w | --http-server");
      if(!isdigit(*value)) {
	traceEvent(CONST_TRACE_ERROR, "flag -w expects a numeric argument.\n");
	return(startCap);
      }

      /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
      if((pref->webAddr = strchr(value,':'))) {
	/* DS: Search for : to find xxx.xxx.xxx.xxx:port */
	/* This code is to be able to bind to a particular interface */
	if(savePref) {
	  storePrefsValue(key, value);
	}
	*pref->webAddr = '\0';
	pref->webPort = atoi(pref->webAddr+1);
	pref->webAddr = strdup (value);
      }
      else {
	processIntPref(NTOP_PREF_WEBPORT, value, &pref->webPort, savePref);
      }
    } else {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof(buf), "%d",
		     DEFAULT_NTOP_WEB_PORT);
      value = buf;
      processIntPref(NTOP_PREF_WEBPORT, value, &pref->webPort, savePref);
    }
  }
#ifdef HAVE_OPENSSL
  else if(strcmp(key, NTOP_PREF_SSLPORT) == 0) {
    if(value != NULL) {
      stringSanityCheck(value, "-W | --https-server");
      if(!isdigit(*value)) {
	traceEvent(CONST_TRACE_ERROR, "flag -W expects a numeric argument.\n");
	return(startCap);
      }

      tmpStr = strdup (value);
      /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
      if((pref->sslAddr = strchr(tmpStr,':'))) {
	/* DS: Search for : to find xxx.xxx.xxx.xxx:port */
	/* This code is to be able to bind to a particular interface */
	if(savePref)
	  storePrefsValue(key, value);
	
	*pref->sslAddr = '\0';
	pref->sslPort = atoi(pref->sslAddr+1);
	pref->sslAddr = value;
      } else {
	processIntPref(NTOP_PREF_SSLPORT, value, &pref->sslPort, savePref);
      }
      free(tmpStr);
    }
    if(value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof(buf), "%d",
		     DEFAULT_NTOP_WEB_PORT);
      value = buf;
      processIntPref(NTOP_PREF_SSLPORT, value, &pref->sslPort, savePref);
    }
  }
#endif
  else if(strcmp(key, NTOP_PREF_EN_SESSION) == 0) {
    processBoolPref(NTOP_PREF_EN_SESSION, value2bool(value),
		     &pref->enableSessionHandling, savePref);
  } else if(strcmp(key, NTOP_PREF_EN_PROTO_DECODE) == 0) {
    processBoolPref(NTOP_PREF_EN_PROTO_DECODE, value2bool(value),
		     &pref->enablePacketDecoding, savePref);
  } else if(strcmp(key, NTOP_PREF_FLOWSPECS) == 0) {
    processStrPref(NTOP_PREF_FLOWSPECS, value, &pref->flowSpecs, savePref);
  } else if(strcmp(key, NTOP_PREF_LOCALADDR) == 0) {
    processStrPref(NTOP_PREF_LOCALADDR, value, &pref->localAddresses,
		    savePref);
  } else if(strcmp(key, NTOP_PREF_KNOWNSUBNETS) == 0) {
    processStrPref(NTOP_PREF_KNOWNSUBNETS, value, &pref->knownSubnets,
		    savePref);
  } else if(strcmp(key, NTOP_PREF_STICKY_HOSTS) == 0) {
    processBoolPref(NTOP_PREF_STICKY_HOSTS, value2bool(value), &pref->stickyHosts,
		     savePref);
  } else if(strcmp(key, NTOP_PREF_TRACK_LOCAL) == 0) {
    processBoolPref(NTOP_PREF_TRACK_LOCAL, value2bool(value),
		     &pref->trackOnlyLocalHosts, savePref);
  } else if(strcmp(key, NTOP_PREF_NO_PROMISC) == 0) {
    processBoolPref(NTOP_PREF_NO_PROMISC, value2bool(value),
		     &pref->disablePromiscuousMode, savePref);
  } else if(strcmp(key, NTOP_PREF_DAEMON) == 0) {
    processBoolPref(NTOP_PREF_DAEMON, value2bool(value), &pref->daemonMode,
		     savePref);
  } else if(strcmp(key, NTOP_PREF_REFRESH_RATE) == 0) {
    if(value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof(buf), "%d",
		     DEFAULT_NTOP_AUTOREFRESH_INTERVAL);
      value = buf;
    }
    processIntPref(NTOP_PREF_REFRESH_RATE, value, &pref->refreshRate,
		    savePref);
  } else if(strcmp(key, NTOP_PREF_MAXLINES) == 0) {
    if(value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof(buf), "%d",
		     CONST_NUM_TABLE_ROWS_PER_PAGE);
      value = buf;
    }
    processIntPref(NTOP_PREF_MAXLINES, value, &pref->maxNumLines,
		    savePref);
  } else if(strcmp(key, NTOP_PREF_W3C) == 0) {
    processBoolPref(NTOP_PREF_W3C, value2bool(value), &pref->w3c, savePref);
  } else if(strcmp(key, NTOP_PREF_IPV4V6) == 0) {
    processIntPref(NTOP_PREF_IPV4V6, value, &pref->ipv4or6, savePref);
  } else if(strcmp(key, NTOP_PREF_DOMAINNAME) == 0) {
    processStrPref(NTOP_PREF_DOMAINNAME, value, &tmpStr,
		    savePref);
    if(tmpStr != NULL) {
      strncpy (pref->domainName, tmpStr, sizeof(pref->domainName));
      free (tmpStr);      /* alloc'd in processStrPref() */
    }
  } else if(strcmp(key, NTOP_PREF_NUMERIC_IP) == 0) {
    processIntPref(NTOP_PREF_NUMERIC_IP, value, (int*)&pref->numericFlag,
		     savePref);
  } else if(strcmp(key, NTOP_PREF_PROTOSPECS) == 0) {
    processStrPref(NTOP_PREF_PROTOSPECS, value, &pref->protoSpecs,
		    savePref);
  } else if(strcmp(key, NTOP_PREF_P3PCP) == 0) {
    processStrPref(NTOP_PREF_P3PCP, value, &pref->P3Pcp, savePref);
  } else if(strcmp(key, NTOP_PREF_P3PURI) == 0) {
    processStrPref(NTOP_PREF_P3PURI, value, &pref->P3Puri, savePref);
  } else if(strcmp(key, NTOP_PREF_MAXHASH) == 0) {
    if(value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof(buf), "%d",
		     -1);
      value = buf;
    }
    processUIntPref(NTOP_PREF_MAXHASH, value,
		   (u_int*)&pref->maxNumHashEntries, savePref);
  } else if(strcmp(key, NTOP_PREF_MAXSESSIONS) == 0) {
    if(value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof(buf), "%d",
		     -1);
      value = buf;
    }
    processUIntPref(NTOP_PREF_MAXSESSIONS, value,
		   (u_int*)&pref->maxNumSessions, savePref);
  } else if(strcmp(key, NTOP_PREF_MERGEIF) == 0) {
    processBoolPref(NTOP_PREF_MERGEIF, value2bool(value),
		     &pref->mergeInterfaces, savePref);
  } else if(strcmp(key, NTOP_PREF_MERGEIF) == 0) {
    processBoolPref(NTOP_PREF_MERGEIF, value2bool(value),
		     &pref->mergeInterfaces, savePref);
  } else if(strcmp(key, NTOP_PREF_ENABLE_L7PROTO) == 0) {
    processBoolPref(NTOP_PREF_ENABLE_L7PROTO, value2bool(value),
		     &pref->enableL7, savePref);
  } else if(strcmp(key, NTOP_PREF_PCAP_LOGBASE) == 0) {
    processStrPref(NTOP_PREF_PCAP_LOGBASE, value,
		    &pref->pcapLogBasePath, savePref);
  }
  else if(strcmp(key, NTOP_PREF_DBG_MODE) == 0) {
    processBoolPref(NTOP_PREF_DBG_MODE, value2bool(value), &pref->debugMode,
		     savePref);
  } else if(strcmp(key, NTOP_PREF_TRACE_LVL) == 0) {
    if(value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof(buf), "%d",
		     DEFAULT_TRACE_LEVEL);
      value = buf;
    }
    processIntPref(NTOP_PREF_TRACE_LVL, value, &pref->traceLevel,
		    savePref);
  } else if(strcmp(key, NTOP_PREF_DUMP_SUSP) == 0) {
    processBoolPref(NTOP_PREF_DUMP_SUSP, value2bool(value),
		     &pref->enableSuspiciousPacketDump, savePref);
  } else if(strcmp(key, NTOP_PREF_ACCESS_LOG) == 0) {
    processStrPref(NTOP_PREF_ACCESS_LOG, value,
		    &pref->accessLogFile,
		    savePref);
  }
#ifndef WIN32
  else if(strcmp(key, NTOP_PREF_USE_SYSLOG) == 0) {
    if(value == NULL) {
      safe_snprintf (__FILE__, __LINE__, buf, sizeof(buf), "%d",
		     DEFAULT_NTOP_SYSLOG);
      value = buf;
    }
    processIntPref(NTOP_PREF_USE_SYSLOG, value,
		    &pref->useSyslog, savePref);
  }
#endif
  else if(strcmp(key, NTOP_PREF_PCAP_LOG) == 0) {
    processStrPref(NTOP_PREF_PCAP_LOG, value, &pref->pcapLog, savePref);
  } else if(strcmp(key, NTOP_PREF_NO_MUTEX_EXTRA) == 0) {
    processBoolPref(NTOP_PREF_NO_MUTEX_EXTRA, value2bool(value),
		     &pref->disableMutexExtraInfo, savePref);
  }
  else if(strncmp (key, "ntop.", strlen ("ntop.")) == 0) {
    traceEvent(CONST_TRACE_WARNING, "Unknown preference: %s, value = %s\n",
		key, (value == NULL) ? "(null)" : value);
  }

  return (startCap);
}

/* ************************************************* */

/*
 * Initialize all preferences to their default values
 */
void initUserPrefs(UserPref *pref) {
  pref->accessLogFile = DEFAULT_NTOP_ACCESS_LOG_FILE;
  pref->enablePacketDecoding   = DEFAULT_NTOP_PACKET_DECODING;
  pref->stickyHosts = DEFAULT_NTOP_STICKY_HOSTS;
  pref->daemonMode = DEFAULT_NTOP_DAEMON_MODE;
  pref->trackOnlyLocalHosts    = DEFAULT_NTOP_TRACK_ONLY_LOCAL;
  pref->devices = DEFAULT_NTOP_DEVICES;
  pref->pcapLog = DEFAULT_NTOP_PCAP_LOG_FILENAME;
  pref->localAddresses = DEFAULT_NTOP_LOCAL_SUBNETS;
  pref->numericFlag = DEFAULT_NTOP_NUMERIC_IP_ADDRESSES;
  pref->protoSpecs = DEFAULT_NTOP_PROTO_SPECS;
  pref->enableSuspiciousPacketDump = DEFAULT_NTOP_SUSPICIOUS_PKT_DUMP;
  pref->refreshRate = DEFAULT_NTOP_AUTOREFRESH_INTERVAL;
  pref->disablePromiscuousMode = DEFAULT_NTOP_DISABLE_PROMISCUOUS;
  pref->traceLevel = DEFAULT_TRACE_LEVEL;
  pref->maxNumHashEntries  = DEFAULT_NTOP_MAX_HASH_ENTRIES;
  pref->maxNumSessions     = DEFAULT_NTOP_MAX_NUM_SESSIONS;
  pref->webAddr = DEFAULT_NTOP_WEB_ADDR;
  pref->webPort = DEFAULT_NTOP_WEB_PORT;
  pref->ipv4or6 = DEFAULT_NTOP_FAMILY;
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
  /* note that by default ntop will merge network interfaces */
  pref->mapperURL = DEFAULT_NTOP_MAPPER_URL;
// #ifdef HAVE_OPENSSL
//   pref->sslAddr = DEFAULT_NTOP_WEB_ADDR;
//   pref->sslPort = DEFAULT_NTOP_WEB_PORT+1;
// #endif

   pref->w3c    = DEFAULT_NTOP_W3C;
   pref->P3Pcp  = DEFAULT_NTOP_P3PCP;
   pref->P3Puri = DEFAULT_NTOP_P3PURI;

   pref->disableStopcap = DEFAULT_NTOP_DISABLE_STOPCAP;
   pref->disableMutexExtraInfo = DEFAULT_NTOP_DISABLE_MUTEXINFO;
   pref->skipVersionCheck      = DEFAULT_NTOP_SKIP_VERSION_CHECK;
}

/* *******************************/
