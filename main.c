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

/*
 * local variables
 */
static int enableDBsupport = 0;   /* Database support disabled by default */
static int enableThUpdate  = 1;   /* Throughput Update support enabled by default */
static int enableIdleHosts = 1;   /* Purging of idle hosts support enabled by default */

static char *localAddresses = NULL;
static char *protoSpecs = NULL;

#ifndef WIN32
static int userId=0;
static int groupId=0;
#endif

static char *webAddr = NULL;
static char *flowSpecs = NULL;
static char *rulesFile = NULL;
static char *sslAddr = NULL;

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


#ifdef HAVE_GETOPT_LONG

static struct option const long_options[] = {

  { "access-log-path",                  required_argument, NULL, 'a' },

#ifdef HAVE_MYSQL
  { "sql-host",                         required_argument, NULL, 'b' },
#endif

  { "sticky-hosts",                     no_argument,       NULL, 'c' },

#ifndef WIN32
  { "daemon",                           no_argument,       NULL, 'd' },
#endif

#ifndef MICRO_NTOP
  { "max-table-rows",                   required_argument, NULL, 'e' },
#endif

  { "traffic-dump-file",                required_argument, NULL, 'f' },
  { "cisco-netflow-host",               required_argument, NULL, 'g' },
  { "help",                             no_argument,       NULL, 'h' },
  { "interface",                        required_argument, NULL, 'i' },
  { "border-sniffer-mode",              no_argument,       NULL, 'j' },
  { "filter-expression-in-extra-frame", no_argument,       NULL, 'k' },
  { "pcap-log",                         required_argument, NULL, 'l' },
  { "local-subnets",                    required_argument, NULL, 'm' },
  { "numeric-ip-addresses",             no_argument,       NULL, 'n' },
  { "protocols",                        required_argument, NULL, 'p' },
  { "create-suspicious-packets",        no_argument,       NULL, 'q' },
  { "refresh-time",                     required_argument, NULL, 'r' },
  { "max-hash-size",                    required_argument, NULL, 's' },
  { "trace-level",                      required_argument, NULL, 't' },

#ifndef WIN32
  { "user",                             required_argument, NULL, 'u' },
#endif

#ifdef HAVE_MYSQL
  { "mysql-host",                       required_argument, NULL, 'v' },
#endif

  { "http-server",                      required_argument, NULL, 'w' },
  { "accuracy-level",                   required_argument, NULL, 'A' },
  { "filter-expression",                required_argument, NULL, 'B' },
  { "domain",                           required_argument, NULL, 'D' },

#ifndef WIN32
  { "enable-external-tools",            no_argument,       NULL, 'E' },
#endif

  { "flow-spec",                        required_argument, NULL, 'F' },

#ifndef WIN32
  { "interactive-mode",                 no_argument,       NULL, 'I' }, /* interactive mode no longer used */
  { "debug",                            no_argument,       NULL, 'K' },
  { "use-syslog",                       no_argument,       NULL, 'L' },
#endif

  { "no-interface-merge",               no_argument,       NULL, 'M' },

#ifndef WIN32
  { "no-nmap",                          no_argument,       NULL, 'N' },
#endif

  { "db-file-path",                     required_argument, NULL, 'P' },
  { "filter-rule",                      required_argument, NULL, 'R' },
  { "store-mode",                       required_argument, NULL, 'S' },
  { "mapper",                           required_argument, NULL, 'U' },
  { "version",                          no_argument,       0,    'V' },

#ifdef HAVE_OPENSSL
  { "https-server",                     required_argument, NULL, 'W' },
#endif

  { "no-throughput-update",             no_argument,       NULL, '1' },
  { "no-idle-host-purge",               no_argument,       NULL, '2' },

  /*
   * long ONLY options - put these here with numeric arguments,
   *  over 127 (i.e. > ascii max char)
   * (since op is unsigned this is fine)
   *  add corresponding case nnn: below
   */
#ifdef HAVE_GDCHART
  { "throughput-bar-chart",             no_argument,       NULL, 129 },
#endif
  {"no-admin-password-hint",            no_argument,       NULL, 130},

  {NULL, 0, NULL, 0}
};

#endif /* HAVE_GETOPT_LONG */


/*
 * Hello World! This is ntop speaking...
 */
static void welcome (FILE * fp)
{
  fprintf (fp, "%s v.%s %s [%s] (%s build)\n",
	   myGlobals.program_name, version, THREAD_MODE, osName, buildDate);

  fprintf (fp, "Copyright 1998-2002 by %s.\n", author);
  fprintf (fp, "Get the freshest ntop from http://www.ntop.org/\n");
}


/*
 * Wrong. Please try again accordingly to ....
 */
static void usage (FILE * fp)
{
  welcome(fp);

  fprintf(fp, "\nUsage: %s [OPTION]\n", myGlobals.program_name);

#ifdef HAVE_GETOPT_LONG

  fprintf(fp, "    [-a <path>      | --access-log-path <path>]           Path for ntop web server access log\n");

#ifdef HAVE_MYSQL
  fprintf(fp, "    [-b <host:port> | --sql-host <host:port>]             SQL host for ntop database\n");
#endif

  fprintf(fp, "    [-c             | --sticky-hosts]                     Idle hosts are not purged from hash\n");

#ifndef WIN32
  fprintf(fp, "    [-d             | --daemon]                           Run ntop in daemon mode\n");
#endif

#ifndef MICRO_NTOP
  fprintf(fp, "    [-e <number>    | --max-table-rows <number>]          Maximum number of table rows to report\n");
#endif

  fprintf(fp, "    [-f <file>      | --traffic-dump-file <file>]         Traffic dump file (see tcpdump)\n");
  fprintf(fp, "    [-g <host:port> | --cisco-netflow-host <host:port>]   Cisco NetFlow host and port\n");
  fprintf(fp, "    [-h             | --help]                             Display this help and exit\n");

#ifndef WIN32
  fprintf(fp, "    [-i <name>      | --interface <name>]                 Interface name or names to monitor\n");
#else
  fprintf(fp, "    [-i <number>    | --interface <number>]               Interface index number to monitor\n");
#endif

  fprintf(fp, "    [-j             | --border-sniffer-mode]              Set ntop in border/gateway sniffing mode\n");
  fprintf(fp, "    [-k             | --filter-expression-in-extra-frame] Show kernel filter expression in extra frame\n");
  fprintf(fp, "    [-l <path>      | --pcap-log <path>]                  Dump packets captured to a file (debug only!)\n");
  fprintf(fp, "    [-m <addresses> | --local-subnets <addresses>]        Local subnetwork(s) (see man page)\n");
  fprintf(fp, "    [-n             | --numeric-ip-addresses]             Numeric IP addresses - no DNS resolution\n");
  fprintf(fp, "    [-p <list>      | --protocols <list>]                 List of IP protocols to monitor (see man page)\n");
  fprintf(fp, "    [-q             | --create-suspicious-packets]        Create file ntop-suspicious-pkts.XXX.pcap file\n");
  fprintf(fp, "    [-r <number>    | --refresh-time <number>]            Refresh time in seconds, default is %d\n", REFRESH_TIME);
  fprintf(fp, "    [-s <number>    | --max-hash-size <number>]           Maximum hash table size, default = %d\n", MAX_HASH_SIZE);
  fprintf(fp, "    [-t <number>    | --trace-level <number>]             Trace level [0-5]\n");

#ifndef WIN32
  fprintf(fp, "    [-u <user>      | --user <user>]                      Userid/name to run ntop under (see man page)\n");
#endif /* WIN32 */

#ifdef HAVE_MYSQL
  fprintf(fp, "    [-v <username:password:dbName> | --mysql-host <username:password:dbName>] MySQL host for ntop database\n");
#endif

  fprintf(fp, "    [-w <port>      | --http-server <port>]               Web server (http:) port (or address:port) to listen on\n");
  fprintf(fp, "    [-A <number>    | --accuracy-level <number>]          Accuracy level [0-2]\n");
  fprintf(fp, "    [-B <filter>]   | --filter-expression                 Packet filter expression, like tcpdump\n");
  fprintf(fp, "    [-D <name>      | --domain <name>]                    Internet domain name\n");

#ifndef WIN32
  fprintf(fp, "    [-E             | --enable-external-tools]            Enable lsof/nmap integration (if present)\n");
#endif

  fprintf(fp, "    [-F <spec>      | --flow-spec <specs>]                Flow specs (see man page)\n");

#ifndef WIN32
  fprintf(fp, "    [-K             | --enable-debug]                     Enable debug mode\n");
  fprintf(fp, "    [-L             | --enable-syslog]                    Enable logging via syslog\n");
#endif

  fprintf(fp, "    [-M             | --no-interface-merge]               Don't merge network interfaces (see man page)\n");
  fprintf(fp, "    [-N             | --no-nmap]                          Don't use nmap even if installed\n");
  fprintf(fp, "    [-P <path>      | --db-file-path <path>]              Path for ntop internal database files\n");
  fprintf(fp, "    [-R <file>      | --filter-rule <file>]               Matching rules file\n");
  fprintf(fp, "    [-S <number>    | --store-mode <number>]              Persistent storage mode [0-none, 1-local, 2-all]\n");
  fprintf(fp, "    [-U <URL>       | --mapper <URL>]                     URL (mapper.pl) for displaying host location\n");
  fprintf(fp, "    [-V             | --version]                          Output version information and exit\n");

#ifdef HAVE_OPENSSL
  fprintf(fp, "    [-W <port>      | --https-server <port>]              Web server (https:) port (or address:port) to listen on\n");
#endif

  fprintf(fp, "    [-1             | --no-throughput-update>] \n");
  fprintf(fp, "    [-2             | --no-idle-hosts>] \n");


#else /* !HAVE_GETOPT_LONG */

  fprintf(fp, "    [-a <path> path for ntop web server access log]\n");

#ifdef HAVE_MYSQL
  fprintf(fp, "    [-b <client:port (ntop DB client)>]\n");
#endif

  fprintf(fp, "    [-c <sticky hosts: idle hosts are not purged from hash>]\n");

#ifndef WIN32
  fprintf(fp, "    [-d (run ntop in daemon mode)]\n");
#endif

#ifndef MICRO_NTOP
  fprintf(fp, "    [-e <max # table rows)]\n");
#endif

  fprintf(fp, "    [-f <traffic dump file (see tcpdump)>]\n");
  fprintf(fp, "    [-g <client:port (Cisco NetFlow client)>]\n");

#ifndef WIN32
  fprintf(fp, "    [-i <interface>]\n");
#else
  fprintf(fp, "    [-i <interface index>]\n");
#endif

  fprintf(fp, "    [-j (set ntop in border gateway sniffing mode)]\n");
  fprintf(fp, "    [-k <show kernel filter expression in extra frame>]\n");
  fprintf(fp, "    [-l <path> (dump packets captured on a file: debug only!)]\n");
  fprintf(fp, "    [-m <local addresses (see man page)>]\n");
  fprintf(fp, "    [-n (numeric IP addresses)]\n");
  fprintf(fp, "    [-p <IP protocols to monitor> (see man page)]\n");
  fprintf(fp, "    [-q <create file ntop-suspicious-pkts.XXX.pcap>]\n");

#ifdef WIN32
  fprintf(fp, "    [-r <refresh time (web = %d sec)>]\n", REFRESH_TIME);
#else
  fprintf(fp, "    [-r <refresh time (interactive = %d sec/web = %d sec)>]\n",
	   ALARM_TIME, REFRESH_TIME);
#endif

  fprintf(fp, "    [-t (trace level [0-5])]\n");

#ifndef WIN32
  fprintf(fp, "    [-u <userid> | <username> (see man page)]\n");
#endif

#ifdef HAVE_MYSQL
  fprintf(fp, "    [-v <username:password:dbName (ntop mySQL client)>]\n");
#endif

  fprintf(fp, "    [-w <HTTP port>]\n");

  fprintf(fp, "    [-A (accuracy level [0-2])]\n");
  fprintf(fp, "    [-B <filter expression (like tcpdump)>]\n");
  fprintf(fp, "    [-D <Internet domain name>]\n");

#ifndef WIN32
  fprintf(fp, "    [-E <enable lsof/nmap integration (if present)>]\n");
#endif

  fprintf(fp, "    [-F <flow specs (see man page)>]\n");

#ifndef WIN32
  fprintf(fp, "    [-K <enable application debug (no fork() is used)>]\n");
  fprintf(fp, "    [-L <use syslog instead of stdout>]\n");
#endif

  fprintf(fp, "    [-M <don't merge network interfaces (see man page)>]\n");
  fprintf(fp, "    [-N <don't use nmap if installed>]\n");
  fprintf(fp, "    [-P <path for db-files>]\n");
  fprintf(fp, "    [-R <matching rules file>]\n");
  fprintf(fp, "    [-S <store mode> (store persistently host stats)]\n");
  fprintf(fp, "    [-U <mapper.pl URL> | \"\" for not displaying host location]\n");

#ifdef HAVE_OPENSSL
  fprintf(fp, "    [-W <HTTPS port>]\n");
#endif

  fprintf(fp, "    [-1 <no throughput update>] \n");
  fprintf(fp, "    [-2 <no purge of idle hosts>] \n");

#endif /* HAVE_GETOPT_LONG */
}


/*
 * Parse the command line options
 */
static void parseOptions(int argc, char * argv []) {

#ifdef WIN32
  int optind=0;
#endif

  /*
   * Please keep the array sorted
   */
#ifdef WIN32
  char * theOpts = "a:ce:f:g:hi:jkl:m:np:qr:s:t:w:A:B:D:F:MP:R:S:U:VW:12";
#else
  char * theOpts = "a:b:cde:f:g:hi:jkl:m:np:qr:s:t:u:v:w:A:B:D:EF:IKLMNP:R:S:U:VW:12";
#endif
  int opt;

  /*
   * Parse command line options to the application via standard system calls
   */
#ifdef HAVE_GETOPT_LONG
  while((opt = getopt_long(argc, argv, theOpts, long_options, (int *) 0)) != EOF) {
#else
  while((opt = getopt(argc, argv, theOpts)) != EOF) {
#endif
    switch (opt) {

    case 'a':                                     /* ntop access log path */
      stringSanityCheck(optarg);
      myGlobals.accessLogPath = strdup(optarg);
      break;

    case 'b': /* host:port */
      stringSanityCheck(optarg);
      handleDbSupport(optarg, &enableDBsupport);
      break;

      /* Courtesy of Ralf Amandi <Ralf.Amandi@accordata.net> */
    case 'c':                                     /* Sticky hosts = hosts that are not purged when idle */
      myGlobals.stickyHosts = 1;
      break;

#ifndef WIN32
    case 'd':
      myGlobals.daemonMode = 1;
      break;
#endif

#ifndef MICRO_NTOP
    case 'e':
      maxNumLines = atoi(optarg);
      break;
#endif

    case 'f':
      myGlobals.rFileName = strdup(optarg);
      myGlobals.isLsofPresent = 0;               /* Don't make debugging too complex */
      break;

    case 'g': /* host:port */
      stringSanityCheck(optarg);
      handleNetFlowSupport(optarg);
      break;

    case 'h':                                /* help */
      usage(stdout);
      exit(0);

    case 'i':                          /* More than one interface may be specified in a comma separated list */
      stringSanityCheck(optarg);
      myGlobals.devices = strdup(optarg);
      break;

    case 'j':
      /*
       * In this mode ntop sniffs from an interface on which
       * the traffic has been mirrored hence:
       * - MAC addresses are not used at all but just IP addresses
       * - ARP packets are not handled
       */
      myGlobals.borderSnifferMode = 1;
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
      localAddresses = strdup(optarg);
      break;

    case 'n':
      myGlobals.numericFlag++;
      break;

    case 'p':                     /* the TCP/UDP protocols being monitored */
      stringSanityCheck(optarg);
      protoSpecs = strdup(optarg);
      break;

    case 'q': /* allow ntop to save suspicious packets in a file in pcap (tcpdump) format */
      myGlobals.enableSuspiciousPacketDump = 1;
      break;

    case 'r':
      if(!isdigit(optarg[0])) {
	printf("FATAL ERROR: flag -r expects a numeric argument.\n");
	exit(-1);
      }
      refreshRate = atoi(optarg);
      break;

    case 't':
      /* Trace Level Initialization */
      myGlobals.traceLevel = atoi(optarg);
      if(myGlobals.traceLevel > DETAIL_TRACE_LEVEL)
	myGlobals.traceLevel = DETAIL_TRACE_LEVEL;
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

#ifdef HAVE_MYSQL
    case 'v': /* username:password:dbname:host */
      stringSanityCheck(optarg);
      handlemySQLSupport(optarg, &enableDBsupport);
      break;
#endif

    case 'w':
      stringSanityCheck(optarg);
      if(!isdigit(optarg[0])) {
	printf("FATAL ERROR: flag -w expects a numeric argument.\n");
	exit(-1);
      }

      /* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
      if((webAddr = strchr(optarg,':'))) {
	/* DS: Search for : to find xxx.xxx.xxx.xxx:port */
	/* This code is to be able to bind to a particular interface */
	*webAddr = '\0';
	webPort = atoi(webAddr+1);
	webAddr = optarg;
      } else {
	webPort = atoi(optarg);
      }
      break;

    case 'A':
      /* Accuracy Level */
      myGlobals.accuracyLevel = atoi(optarg);
      if(myGlobals.accuracyLevel > HIGH_ACCURACY_LEVEL)
	myGlobals.accuracyLevel = HIGH_ACCURACY_LEVEL;
      break;

    case 'B':
      stringSanityCheck(optarg);
      myGlobals.currentFilterExpression = strdup(optarg);
      break;

    case 'D':                                        /* domain */
      stringSanityCheck(optarg);
      strncpy(myGlobals.domainName, optarg, MAXHOSTNAMELEN);
      break;

    case 'E':
      myGlobals.isLsofPresent  = checkCommand("lsof");
      myGlobals.isNmapPresent  = checkCommand("nmap");
      break;

    case 'F':
      stringSanityCheck(optarg);
      flowSpecs = strdup(optarg);
      break;

#ifndef WIN32
    case 'I':                                        /* Interactive mode */
      printf("intop provides you curses support. ntop -I is no longer used.\n");
      exit(-1);
#endif

#ifndef WIN32
    case 'K':
      myGlobals.debugMode = 1;
      break;

    case 'L':
      myGlobals.useSyslog = 1;
      break;
#endif

    case 'M':
      myGlobals.mergeInterfaces = 0;
      break;

    case 'N':
      myGlobals.isNmapPresent = 0;
      break;

    case 'P':                                       /* DB-Path (ntop's spool directory) */
      stringSanityCheck(optarg);
      myGlobals.dbPath = strdup(optarg);
      break;

    case 'R':
      stringSanityCheck(optarg);
      rulesFile = strdup(optarg);
      break;

    case 'S':
      /*
       * Persitent storage only for 'local' machines
       * Courtesy of Joel Crisp <jcrisp@dyn21-126.trilogy.com>
       *
       * 0 = no storage
       * 1 = store all hosts
       * 2 = store only local hosts
       */
      myGlobals.usePersistentStorage = atoi(optarg);
      if((myGlobals.usePersistentStorage > 2)
	 || (myGlobals.usePersistentStorage < 0)) {
	printf("FATAL ERROR: -S flag accepts value in the 0-2 range.\n");
	exit(-1);
      }
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
      if((sslAddr = strchr(optarg,':'))) {
	*sslAddr = '\0';
	myGlobals.sslPort = atoi(sslAddr+1);
	sslAddr = optarg;
      } else {
	myGlobals.sslPort = atoi(optarg);
      }

      break;
#endif

    case '1': /* disable throughput update */
      enableThUpdate = 0;
      break;

    case '2': /* disable purging of idle hosts */
      enableIdleHosts = 0;
      break;

#ifdef HAVE_GDCHART
    case 129:
      myGlobals.throughput_chart_type = GDC_BAR;
      break;
#endif

    case 130:
      /* Flag to remove userid/password hint from authorization dialogs (BMS 26Jan2002) */
      myGlobals.noAdminPasswordHint = 1;
      break;

    default:
      printf("FATAL ERROR: unknown ntop option, '%s'\n", argv[optind-1]);
#ifdef DEBUG
      if(op != '?')
	printf("             getopt return value is '%c', %d\n", op, op);
#endif
      usage(stdout);
      exit(-1);
    }
  }

#if(0)

  all other arguments could be used to specify a filter expression

    ROCCO TODO: ask luca if this can be an alternative to -B option

  if(argc > optind + 1)
    {
      fprintf (stdout, "\nWrong option(s): \" ");
      while (optind < argc)
	fprintf (stdout, "%s ", argv [optind ++]);
      fprintf (stdout, "\"\n");
      usage (stdout);
      exit (0);
    }
#endif
}



/* That's the meat */
int main(int argc, char *argv[]) {

  int i;
  char ifStr[196] = {0};
  time_t lastTime;

  /*
   * Initialize all global run-time parameters to reasonable values
   */
  initNtopGlobals(argc, argv);

  /*
   * Parse command line options to the application via standard system calls
   */
  parseOptions (argc, argv);

  /*
   * check for valid parameters
   */
  if(webPort == 0) {
#ifdef HAVE_OPENSSL
    if(myGlobals.sslPort == 0) {
      printf("FATAL ERROR: both -W and -w can't be set to 0.\n");
      exit(-1);
    }
#else
    printf("FATAL ERROR: -w can't be set to 0.\n");
    exit(-1);
#endif
  }

#ifndef WIN32

  /*
   * Must run as root since opening a network interface
   * in promiscuous mode is a privileged operation.
   * Verify we're running as root, unless we are reading data from a file
   */
  if(! myGlobals.rFileName && ((getuid () && geteuid ()) || setuid (0))) {
    printf ("Sorry, %s uses network interface(s) in promiscuous mode, so it needs root permission to run.\n",
	    myGlobals.program_name);
    exit (-1);
  }

#endif


  printf("Wait please: ntop is coming up...\n");


  /*
   * Perform here all the initialization steps required by the ntop engine to run
   */

#ifdef MEMORY_DEBUG
  initLeaks();
#endif

#ifdef WIN32
  initWinsock32();
#endif

  /*
   * Initialize memory and data for the protocols being monitored trying to access
   * 
   */
  initIPServices();

  initPassiveSessions();

  /*
   * Initialize the logging database
   */
  initLogger();

#ifdef HAVE_OPENSSL
  init_ssl();
#endif

  /*
   *
   */
  initGlobalValues();

#ifndef MICRO_NTOP
  reportValues(&lastTime);
#endif /* MICRO_NTOP */

  postCommandLineArgumentsInitialization(&lastTime);

  initGdbm();

  /*
   * initialize memory and data 
   */
  initDevices(myGlobals.devices);

  traceEvent(TRACE_INFO, "ntop v.%s %s [%s] (%s build)",
	     version, THREAD_MODE, osName, buildDate);

  if(myGlobals.rFileName != NULL)
    strncpy(ifStr, PCAP_NW_INTERFACE, sizeof(ifStr));
  else
    for (i=0; i<myGlobals.numDevices; i++) {
      char tmpBuf[48];

      if(i>0) {
	if(snprintf(tmpBuf, sizeof(tmpBuf), ",%s", myGlobals.device[i].name)  < 0)
	  BufferOverflow();
      } else {
	if(snprintf(tmpBuf, sizeof(tmpBuf), "%s", myGlobals.device[i].name) < 0)
	  BufferOverflow();
      }
      strncat(ifStr, tmpBuf, sizeof(ifStr)-strlen(ifStr)-1)[sizeof(ifStr)-1] = '\0';
    }

  traceEvent(TRACE_INFO, "Listening on [%s]", ifStr);
  traceEvent(TRACE_INFO, "Copyright 1998-2002 by %s\n", author);
  traceEvent(TRACE_INFO, "Get the freshest ntop from http://www.ntop.org/\n");
  traceEvent(TRACE_INFO, "Initializing...\n");

  /*
   * time to initialize the libpcap
   */
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
    if(setgid(getgid())!=0 || setuid(getuid())!=0) {
      traceEvent(TRACE_ERROR,
		 "FATAL ERROR: Unable to drop privileges.\n");
      exit(-1);
    }
  }

  /*
   * set user to be as inoffensive as possible
   */
  if((userId != 0) || (groupId != 0)){
    /* user id specified on commandline */
    if((setgid(groupId) != 0) || (setuid(userId) != 0)) {
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

  createPortHash();

  initCounters(myGlobals.mergeInterfaces);
  initApps();
  initSignals();

  initThreads(enableThUpdate, enableIdleHosts, enableDBsupport);

#ifndef MICRO_NTOP
  startPlugins();
#endif

  /* create the main listener */
  initWeb(webPort, webAddr, sslAddr);

  traceEvent(TRACE_INFO, "Sniffying...\n");

#ifdef MEMORY_DEBUG
  resetLeaks();
#endif

  /*
   * In multithread mode, a separate thread handles packet sniffing
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
