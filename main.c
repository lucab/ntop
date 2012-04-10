/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 *          Copyright (C) 1998-2012 Luca Deri <deri@ntop.org>
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

#if defined(DARWIN) && (!defined(TIGER))
#include <mach-o/dyld.h>
extern char ** environ;
#endif

#if defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 1)
#include <mcheck.h>
#endif

char static_ntop;

/*
 * Hello World! This is ntop speaking...
 */
void welcome (FILE * fp) {
  fprintf (fp, "Welcome to %s v.%s (%d bit)\n"
	   "[Configured on %s, built on %s]\n",
	   myGlobals.program_name, version, sizeof(long) == 8 ? 64 : 32,
	   configureDate, buildDate);

  fprintf (fp, "Copyright 1998-2012 by %s\n", ntop_author);
  fprintf (fp, "\nGet the freshest ntop from http://www.ntop.org/\n");
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

  fprintf(fp, "\nUsage: %s [OPTION]\n\n", myGlobals.program_name);
  fprintf(fp, "Basic options:\n");
  fprintf(fp, "    [-h             | --help]                             %sDisplay this help and exit\n", newLine);
#ifndef WIN32
  fprintf(fp, "    [-u <user>      | --user <user>]                      %sUserid/name to run ntop under (see man page)\n", newLine);
#endif /* WIN32 */
  fprintf(fp, "    [-t <number>    | --trace-level <number>]             %sTrace level [0-6]\n", newLine);
  fprintf(fp, "    [-P <path>      | --db-file-path <path>]              %sPath for ntop internal database files\n", newLine);
  fprintf(fp, "    [-Q <path>      | --spool-file-path <path>]           %sPath for ntop spool files\n", newLine);
  fprintf(fp, "    [-w <port>      | --http-server <port>]               %sWeb server (http:) port (or address:port) to listen on\n", newLine);
#ifdef HAVE_OPENSSL
  fprintf(fp, "    [-W <port>      | --https-server <port>]              %sWeb server (https:) port (or address:port) to listen on\n", newLine);
#endif


  fprintf(fp, "\nAdvanced options:\n");
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
  fprintf(fp, "    [-j             | --create-other-packets]             %sCreate file ntop-other-pkts.XXX.pcap file\n", newLine);
  fprintf(fp, "    [-l <path>      | --pcap-log <path>]                  %sDump packets captured to a file (debug only!)\n", newLine);
  fprintf(fp, "    [-m <addresses> | --local-subnets <addresses>]        %sLocal subnetwork(s) (see man page)\n", newLine);
  fprintf(fp, "    [-n <mode>      | --numeric-ip-addresses <mode>]      %sNumeric IP addresses DNS resolution mode:\n", newLine);
  fprintf(fp, "                                                          %s%d - %s\n", newLine, 0, "No DNS resolution at all");
  fprintf(fp, "                                                          %s%d - %s\n", newLine, 1, "DNS resolution for local hosts only");
  fprintf(fp, "                                                          %s%d - %s\n", newLine, 2, "DNS resolution for remote hosts only");
  fprintf(fp, "    [-p <list>      | --protocols <list>]                 %sList of IP protocols to monitor (see man page)\n", newLine);
  fprintf(fp, "    [-q             | --create-suspicious-packets]        %sCreate file ntop-suspicious-pkts.XXX.pcap file\n", newLine);
  fprintf(fp, "    [-r <number>    | --refresh-time <number>]            %sRefresh time in seconds, default is %d\n",
	  newLine, DEFAULT_NTOP_AUTOREFRESH_INTERVAL);
  fprintf(fp, "    [-s             | --no-promiscuous]                   %sDisable promiscuous mode\n", newLine);


  fprintf(fp, "    [-x <max num hash entries> ]                          %sMax num. hash entries ntop can handle (default %u)\n",
	  newLine, myGlobals.runningPref.maxNumHashEntries);
  fprintf(fp, "    [-z             | --disable-sessions]                 %sDisable TCP session tracking\n", newLine);
  fprintf(fp, "    [-A]                                                  %sAsk admin user password and exit\n", newLine);
  fprintf(fp, "    [               | --set-admin-password=<pass>]        %sSet password for the admin user to <pass>\n", newLine);
  fprintf(fp, "    [               | --w3c]                              %sAdd extra headers to make better html\n", newLine);
  fprintf(fp, "    [-B <filter>]   | --filter-expression                 %sPacket filter expression, like tcpdump (for all interfaces)\n", newLine);
  fprintf(fp, "                                                          %sYou can also set per-interface filter: \n", newLine);
  fprintf(fp, "                                                          %seth0=tcp,eth1=udp ....\n", newLine);
  fprintf(fp, "    [-C <rate>]     | --sampling-rate                     %sPacket capture sampling rate [default: 1 (no sampling)]\n", newLine);
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
  fprintf(fp, "    [-O <path>      | --pcap-file-path <path>]            %sPath for log files in pcap format\n", newLine);
  fprintf(fp, "    [-U <URL>       | --mapper <URL>]                     %sURL (mapper.pl) for displaying host location\n",
	  newLine);

  fprintf(fp, "    [-V             | --version]                          %sOutput version information and exit\n", newLine);
  fprintf(fp, "    [-X <max num TCP sessions> ]                          %sMax num. TCP sessions ntop can handle (default %u)\n",
	  newLine, myGlobals.runningPref.maxNumSessions);

/*  Please keep long-only options alphabetically ordered */
  fprintf(fp, "    [--disable-instantsessionpurge]                       %sDisable instant FIN session purge\n", newLine);
  fprintf(fp, "    [--disable-mutexextrainfo]                            %sDisable extra mutex info\n", newLine);
  fprintf(fp, "    [--disable-stopcap]                                   %sCapture packets even if there's no memory left\n", newLine);
  fprintf(fp, "    [--disable-ndpi]                                      %sDisable nDPI for protocol discovery\n", newLine);
  fprintf(fp, "    [--disable-python]                                    %sDisable Python interpreter\n", newLine);

  fprintf(fp, "    [--instance <name>]                                   %sSet log name for this ntop instance\n", newLine);
  fprintf(fp, "    [--p3p-cp]                                            %sSet return value for p3p compact policy, header\n", newLine);
  fprintf(fp, "    [--p3p-uri]                                           %sSet return value for p3p policyref header\n", newLine);
  fprintf(fp, "    [--skip-version-check]                                %sSkip ntop version check\n", newLine);
  fprintf(fp, "    [--known-subnets <networks>]                          %sList of known subnets (separated by ,)\n", newLine);
  fprintf(fp, "                                                          %sIf the argument starts with @ it is assumed it is a file path\n", newLine);
  fprintf(fp, "                                                          %sE.g. 192.168.0.0/14=home,172.16.0.0/16=private\n", newLine);

 fprintf(fp, "\n"
	 "NOTE\n"
	 "    * You can configure further ntop options via the web\n"
	 "      interface [Menu Admin -> Config].\n"
	 "    * The command line options are not permanent, i.e. they\n"
	 "      are not persistent across ntop initializations.\n"
	 "\n");

#ifdef WIN32
  printAvailableInterfaces();
#endif
}

/* *********************************** */

static void verifyOptions (void){

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
    }

    /*
     * Must start run as root since opening a network interface
     * in promiscuous mode is a privileged operation.
     * Verify we're running as root, unless we are reading data from a file
     */

    if(myGlobals.pcap_file_list != NULL) {
      return;
    }

#ifndef WIN32
    if ((myGlobals.runningPref.disablePromiscuousMode != 1)
	&& getuid() /* We're not root */
	&& myGlobals.runningPref.devices
	&& strcmp(myGlobals.runningPref.devices, "none")) {
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
	      traceEvent(CONST_TRACE_INFO, "or add -s to your startup parameters (you won't be able to capture");
	      traceEvent(CONST_TRACE_INFO, "from a NIC but you can via NetFlow/sFlow)");
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
                traceEvent(CONST_TRACE_FATALERROR, "please run ntop as root.");
                exit (18);
            }
        } else {
            traceEvent(CONST_TRACE_ERROR, "The specified root password is not correct.");
            traceEvent(CONST_TRACE_FATALERROR, "Sorry, %s uses network interface(s) in promiscuous mode, "
                       "so it needs root permission to run.\n", myGlobals.program_name);
            exit(19);
        }
    } else if (myGlobals.runningPref.disablePromiscuousMode == 1)
        traceEvent(CONST_TRACE_WARNING,
                   "-s set so will ATTEMPT to open interface w/o promisc mode "
                   "(this will probably fail below)");
#endif /* WIN32 */

    return;
}

/* ***************************************************** */

#if defined(DARWIN) && (!defined(TIGER))
      /* http://developer.apple.com/technotes/tn2005/tn2083.html#SECDAEMONVSFRAMEWORKS */

 static void check_osx_daemonization(int argc, char *argv[]) {
   int is_daemon = 0, j, i;

   if(0) {
     printf("--------------------\n");
     for(i=0; i<argc; i++) printf("%s\n", argv[i]);
     printf("--------------------\n");
   }

   for(i=1; i<argc; i++)
     if(!strcmp(argv[i], "-d")) {
       is_daemon = 1;
       break;
     }

   if(is_daemon) {
     char **     args;
     char        execPath[PATH_MAX];
     u_int32_t    execPathSize;
     static char *osx_daemon = "--osx-daemon";

     // ... process any pre-daemonization arguments ...

     // Calculate our new arguments, dropping any arguments that
     // have already been processed (that is, before optind) and
     // inserting the special flag that tells us that we've
     // already daemonized.
     //
     // Note that we allocate and copy one extra argument so that
     // args, like argv, is terminated by a NULL.
     //
     // We get the real path to our executable using
     // _NSGetExecutablePath because argv[0] might be a relative
     // path, and daemon chdirs to the root directory. In a real
     // product you could probably substitute a hard-wired absolute
     // path.

     execPathSize = sizeof(execPath);
     (void)_NSGetExecutablePath(execPath, &execPathSize);

     args = calloc(argc, sizeof(char *));
     args[0] = execPath;

     for(j = 1, i=1; i<argc; i++) {
       if(strcmp(argv[i], "-d"))
	 args[j++] = argv[i];
       else
	 args[j++] = osx_daemon;
     }

     if(0) {
       printf("--------------------\n");
       for(i=0; i<j; i++) printf("%s\n", args[i]);
       printf("--------------------\n");
     }

     // Daemonize ourself.
     (void)daemon(0, 0);

     // exec ourself.
     (void)execve(execPath, args, environ);
     exit(0);
   }
 }
#endif

/* ***************************************************** */

/* That's the meat */
#ifdef WIN32
int ntop_main(int argc, char *argv[]) {
#else
int main(int argc, char *argv[]) {
#endif
  int i, rc, userSpecified;
  char ifStr[196] = {0};
  time_t lastTime;
  char *cmdLineBuffer, *readBuffer, *readBufferWork;
  FILE *fd;
  struct stat fileStat;
  int effective_argc;
  char **effective_argv;
  time_t endTime;
  char main_buf[LEN_GENERAL_WORK_BUFFER];
  char lib[LEN_GENERAL_WORK_BUFFER],
       env[LEN_GENERAL_WORK_BUFFER],
       buf[LEN_GENERAL_WORK_BUFFER];

#if defined(DARWIN) && (!defined(TIGER))
  check_osx_daemonization(argc, argv);
#endif

/* Don't move this below nor above */
#if defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 1)
  mtrace();
#elif defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 3)
  initLeaks();
#elif defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 4)
  mcheck(abortfn);
  printf("MEMORY_DEBUG 4 - mcheck() - remember you need to run at the console, without -d | --daemon\n");
#endif

  if(strstr(argv[0], "ntops"))
    static_ntop = 1;
  else
    static_ntop = 0;

  /* printf("Wait please: ntop is coming up...\n"); */

  /* VERY FIRST THING is to clear myGlobals, so myGlobals.ntopRunState can be used */
  memset(&myGlobals, 0, sizeof(myGlobals));
  setRunState(FLAG_NTOPSTATE_PREINIT);

  myGlobals.mainThreadId = pthread_self();

  initSignals();

#ifdef WIN32
  initWinsock32(); /* Necessary for initializing globals */
#endif

  /* *********************** */

  setRunState(FLAG_NTOPSTATE_INIT);

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
        free(cmdLineBuffer);
	return(-1);
      }

#ifdef PARAM_DEBUG
      printf("PARAM_DEBUG: File size %d\n", fileStat.st_size);
#endif

      fd = fopen(&argv[i][1], "rb");
      if (fd == NULL) {
	printf("ERROR: Unable to open parameter file '%s' (%d)...\n", &argv[i][1], errno);
        free(cmdLineBuffer);
	return(-1);
      }
      
      printf("Processing file %s for parameters...\n", &argv[i][1]);

      if(i > 1)
	safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, " '");
      else
	safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, " ");

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
	  readBufferWork[0] = (i == 1) ? ' ' : ',';
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

      if(i > 1)
	safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, "' ");
      else
	safe_strncat(cmdLineBuffer, LEN_CMDLINE_BUFFER, " ");
    }
  }
  free(readBuffer);

  /* Strip trailing spaces */
  while((strlen(cmdLineBuffer) > 1) &&
        (cmdLineBuffer[strlen(cmdLineBuffer)-1] == ' ')) {
      cmdLineBuffer[strlen(cmdLineBuffer)-1] = '\0';
  }

#ifdef WIN32
  {
	int i;

	for(i=0; i<strlen(cmdLineBuffer); i++)
		if(cmdLineBuffer[i] == '\\') cmdLineBuffer[i] = '/';
  }
#endif

  effective_argv = buildargv(cmdLineBuffer); /* Build a new argv[] from the string */
  free(cmdLineBuffer);

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
  initNtopGlobals(effective_argc, effective_argv, argc, argv);

  /*
   * Parse command line options to the application via standard system calls
   * Command-line options take precedence over saved preferences.
   */
  loadPrefs(effective_argc, effective_argv);
  userSpecified = parseOptions(effective_argc, effective_argv);

  verifyOptions();

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "ntop v.%s (%d bit)", version, sizeof(long) == 8 ? 64 : 32);
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Configured on %s, built on %s.", configureDate, buildDate);
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Copyright 1998-2012 by %s", ntop_author);
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Get the freshest ntop from http://www.ntop.org/");

#ifndef WIN32
  if(getDynamicLoadPaths(main_buf, sizeof(main_buf), lib, sizeof(lib), env, sizeof(env)) == 0) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NOTE: ntop is running from '%s'", main_buf);
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NOTE: (but see warning on man page for the --instance parameter)");
    if(strcmp(main_buf, lib) != 0)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NOTE: ntop libraries are in '%s'", lib);
  } else {
    traceEvent(CONST_TRACE_NOISY, "NOTE: Unable to establish where ntop is running from");
  }
#endif

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Initializing ntop");

#ifdef HAVE_PYTHON
  init_python(effective_argc, effective_argv);
#endif

  reportValues(&lastTime);

  if(myGlobals.runningPref.P3Pcp != NULL)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "P3P: Compact Policy is '%s'",
		 myGlobals.runningPref.P3Pcp);

  if(myGlobals.runningPref.P3Puri != NULL)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "P3P: Policy reference uri is '%s'",
		 myGlobals.runningPref.P3Puri);

  initNtop(myGlobals.runningPref.devices);

  /* create the main listener */
#ifdef HAVE_OPENSSL
  init_ssl();
#endif

  if(!myGlobals.webInterfaceDisabled)
    initWeb();

  /* ******************************* */

  if(myGlobals.pcap_file_list != NULL)
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
    traceEvent(CONST_TRACE_ERROR, 
	       "No interface has been selected [%d defined interfaces]", myGlobals.numDevices);
    traceEvent(CONST_TRACE_NOISY, "Creating interface 'none'");
    createDummyInterface("none");
  } else
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Listening on [%s]", ifStr);

  if(!static_ntop) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Loading Plugins");
    loadPlugins();
    traceEvent(CONST_TRACE_NOISY, "Starting Plugins");
    startPlugins();
    traceEvent(CONST_TRACE_NOISY, "Plugins started... continuing with initialization");
  }

  checkUserIdentity(userSpecified);

  addDefaultAdminUser();
  readSessionPurgeParams();
  initReports();

  /* Sanity checks */
  if(myGlobals.actualReportDeviceId >= myGlobals.numDevices)
    myGlobals.actualReportDeviceId = myGlobals.numDevices;

  /*
    In case the initial device is "none" and there are other defined devices
    we switch to another device.
    
    TODO In the future we should remember the last value for 
         myGlobals.actualReportDeviceId and use it at next start
	 in case such device is still present
  */

  if((strcmp(myGlobals.device[myGlobals.actualReportDeviceId].name, "none") == 0)
     && ((myGlobals.actualReportDeviceId+1) < myGlobals.numDevices))
     myGlobals.actualReportDeviceId++;

  traceEvent(CONST_TRACE_NOISY, "MEMORY: Base interface structure (no hashes loaded) is %.2fMB each",
	     xvertDOT00MB(sizeof(NtopInterface)));
  traceEvent(CONST_TRACE_NOISY, "MEMORY:     or %.2fMB for %d interfaces",
	     xvertDOT00MB(myGlobals.numDevices*sizeof(NtopInterface)),
	     myGlobals.numDevices);

#ifndef WIN32
  saveNtopPid();
#endif

  /*
   * OK, ntop is up... if we have't failed during init, start running with the actual packet capture...
   *
   * A separate thread handles packet sniffing
   */
  startSniffer();

  while(myGlobals.ntopRunState == FLAG_NTOPSTATE_RUN) {
    // traceEvent(CONST_TRACE_ERROR, "event_loop() returned %d", rc);
    ntopSleepWhileSameState(5);

    /* Periodic recheck of the version status */
    if((myGlobals.checkVersionStatusAgain > 0) &&
       (time(NULL) > myGlobals.checkVersionStatusAgain) &&
       (myGlobals.ntopRunState == FLAG_NTOPSTATE_RUN))
      checkVersion(NULL);
  }

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: Main thread shutting down",
	     (long unsigned int)pthread_self());
  endTime = time(NULL) + PARM_SLEEP_LIMIT + 2;

  while((myGlobals.ntopRunState != FLAG_NTOPSTATE_TERM) &&
        (time(NULL) < endTime)) {
    sleep(1);
  }
  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: Main thread terminating", 
	     (long unsigned int)pthread_self());

  memset(&buf, 0, sizeof(buf));
  runningThreads(buf, sizeof(buf), 0);
  if(buf[0] != '\0')
    traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: Still running threads%s", 
	       (long unsigned int)pthread_self(), buf);

  traceEvent(CONST_TRACE_INFO, "===================================");
  traceEvent(CONST_TRACE_INFO, "        ntop is shutdown...        ");
  traceEvent(CONST_TRACE_INFO, "===================================");

  return(0);
}
