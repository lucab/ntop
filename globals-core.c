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

NtopGlobals myGlobals;

#if !defined(HAVE_GETOPT_H) && !defined(DARWIN)
char *optarg;
int optind;
int opterr;
int optopt;
#endif

#ifdef WIN32
char *version, *osName, *author, *buildDate,
            *configure_parameters,
            *host_system_type,
            *target_system_type,
            *compiler_cflags,
            *include_path,
            *system_libs,
            *install_path;
#endif

static u_short _mtuSize[MAX_DLT_ARRAY];
static u_short _headerSize[MAX_DLT_ARRAY];

#ifdef WIN32
extern char _wdir[];
#endif

static char *_dataFileDirs[]   = { ".", 
#ifdef WIN32
									_wdir,
#endif
									CFG_DATAFILE_DIR, NULL };
static char *_pluginDirs[]     = { "./plugins", CFG_PLUGIN_DIR, NULL };
static char *_configFileDirs[] = { ".", CFG_CONFIGFILE_DIR, "/etc", NULL };


/*
 *  ** TCP Wrappers
 *
 *      Because of limits in the way libwrap.a does things, these MUST
 *      be open global values.
 *
 */
#ifdef HAVE_LIBWRAP
  int allow_severity, deny_severity;
#endif /* HAVE_LIBWRAP */


/* ************************************ */

/*
 * Initialize all global run-time parameters to default (reasonable!!!) values
 */
void initNtopGlobals(int argc, char * argv[]) {
  int i;

  memset(&myGlobals, 0, sizeof(myGlobals));

#ifdef MEMORY_DEBUG
  myGlobals.allocatedMemory = 0;
  initLeaks(); /* Don't move this below nor above */
#endif 

  /*
   * Notice the program name
   */
  myGlobals.program_name = strrchr(argv[0], CONST_PATH_SEP);
  myGlobals.program_name =
    (!myGlobals.program_name || !myGlobals.program_name[0]) ? (argv[0]) : (++myGlobals.program_name);

  /*
   * save command line parameters
   */
  myGlobals.ntop_argc = argc;
  myGlobals.ntop_argv = argv;

  myGlobals.accessLogPath = DEFAULT_NTOP_ACCESS_LOG_PATH;
  myGlobals.stickyHosts = DEFAULT_NTOP_STICKY_HOSTS;

  myGlobals.daemonMode = DEFAULT_NTOP_DAEMON_MODE;
  if (strcmp(myGlobals.program_name, "ntopd") == 0) {
    myGlobals.daemonMode = 1;
  }

  myGlobals.rFileName = DEFAULT_NTOP_TRAFFICDUMP_FILENAME;
  myGlobals.devices = DEFAULT_NTOP_DEVICES;
  myGlobals.dontTrustMACaddr = DEFAULT_NTOP_DONT_TRUST_MAC_ADDR;
  myGlobals.trackOnlyLocalHosts    = DEFAULT_NTOP_TRACK_ONLY_LOCAL;
  myGlobals.enableSessionHandling  = DEFAULT_NTOP_ENABLE_SESSIONHANDLE;
  myGlobals.enablePacketDecoding   = DEFAULT_NTOP_PACKET_DECODING;
  myGlobals.filterExpressionInExtraFrame = DEFAULT_NTOP_FILTER_IN_FRAME;
  myGlobals.pcapLog = DEFAULT_NTOP_PCAP_LOG_FILENAME;
  myGlobals.numericFlag = DEFAULT_NTOP_NUMERIC_IP_ADDRESSES;
  myGlobals.localAddresses = DEFAULT_NTOP_LOCAL_SUBNETS;
  myGlobals.enableSuspiciousPacketDump = DEFAULT_NTOP_SUSPICIOUS_PKT_DUMP;
  myGlobals.disablePromiscuousMode = DEFAULT_NTOP_DISABLE_PROMISCUOUS;
  myGlobals.traceLevel = DEFAULT_TRACE_LEVEL;
  myGlobals.currentFilterExpression = DEFAULT_NTOP_FILTER_EXPRESSION;
  strncpy((char *) &myGlobals.domainName, DEFAULT_NTOP_DOMAIN_NAME, sizeof(myGlobals.domainName));
  myGlobals.enableExternalTools = DEFAULT_NTOP_EXTERNAL_TOOLS_ENABLE;
  myGlobals.isLsofPresent = 0;
  myGlobals.isNmapPresent = DEFAULT_NTOP_NMAP_PRESENT;
  myGlobals.flowSpecs = DEFAULT_NTOP_FLOW_SPECS;

#ifndef WIN32
  myGlobals.debugMode = DEFAULT_NTOP_DEBUG_MODE;
  myGlobals.useSyslog = DEFAULT_NTOP_SYSLOG;
#ifdef HAVE_LIBWRAP
  allow_severity = DEFAULT_TCPWRAP_ALLOW;
  deny_severity = DEFAULT_TCPWRAP_DENY;
#endif
#endif

  myGlobals.mergeInterfaces = DEFAULT_NTOP_MERGE_INTERFACES;
  /* note that by default ntop will merge network interfaces */
  myGlobals.mapperURL = DEFAULT_NTOP_MAPPER_URL;

#ifdef HAVE_GDCHART
  myGlobals.throughput_chart_type = DEFAULT_NTOP_CHART_TYPE;
#endif

#ifndef MAKE_WITH_IGNORE_SIGPIPE
   myGlobals.ignoreSIGPIPE = 0;
#endif

#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
   myGlobals.useSSLwatchdog = 0;
#endif

  myGlobals.dynamicPurgeLimits = 0;

#ifdef HAVE_RRD
  myGlobals.reuseRRDgraphics = 0;
#endif

  /* Other flags (to be set via command line options one day) */
  myGlobals.enableFragmentHandling = 1;

  /* Search paths */
  myGlobals.dataFileDirs    = _dataFileDirs;
  myGlobals.pluginDirs      = _pluginDirs;
  myGlobals.configFileDirs  = _configFileDirs;
  myGlobals.pcapLogBasePath = strdup(CFG_DBFILE_DIR);   /* a NULL pointer will break the logic */
  myGlobals.dbPath          = strdup(CFG_DBFILE_DIR);   /* a NULL pointer will break the logic */

  /* NB: we can't init rrdPath here, because initGdbm hasn't been run */

  /* the table of enabled NICs */
  myGlobals.numDevices = 0;
  myGlobals.device = NULL;

  /* Databases */
  myGlobals.gdbm_file = NULL;
  myGlobals.pwFile = NULL;
  myGlobals.hostsInfoFile = NULL;
  myGlobals.addressCache = NULL;

  /* the table of broadcast entries */
  myGlobals.broadcastEntryIdx = 0;
  myGlobals.broadcastEntry = NULL;

  /* the table of other hosts entries */
  myGlobals.otherHostEntryIdx = 0;
  myGlobals.otherHostEntry = NULL;

  /* administrative */
  myGlobals.shortDomainName = NULL;

#ifdef CFG_MULTITHREADED
  myGlobals.hostsHashMutexInitialized = 0;

  myGlobals.numThreads = 0;            /* # of running threads */

  myGlobals.numDequeueThreads = 1;

#ifdef MAKE_ASYNC_ADDRESS_RESOLUTION
  for (i = 0; i < MAX_NUM_DEQUEUE_THREADS; i ++)
    myGlobals.dequeueAddressThreadId[i] = (pthread_t)-1;
#endif

#endif /* CFG_MULTITHREADED */

#ifdef HAVE_OPENSSL
  myGlobals.sslInitialized = 0;
  myGlobals.sslPort = 0;           /* Disabled by default: it can enabled using -W <SSL port> */
#endif

  myGlobals.webAddr = DEFAULT_NTOP_WEB_ADDR;
  myGlobals.webPort = DEFAULT_NTOP_WEB_PORT;

  /* Termination flags */
  myGlobals.capturePackets = 1;    /* By default data are collected into internal variables */
  myGlobals.endNtop = 0;

  myGlobals.processes = NULL;
  myGlobals.numProcesses = 0;

  /* lsof support */
  if(myGlobals.isLsofPresent)
    myGlobals.updateLsof = 1;
  else
    myGlobals.updateLsof = 0;
  for (i = 0; i < MAX_IP_PORT; i ++)
    myGlobals.localPorts[i] = NULL;       /* myGlobals.localPorts is used by lsof */

#if defined(MAKE_ASYNC_ADDRESS_RESOLUTION)
  myGlobals.addressQueueLen = 0;
  myGlobals.maxAddressQueueLen = 0;
#endif

  /* Address Resolution counters */
  myGlobals.numResolvedWithDNSAddresses = 0;
  myGlobals.numKeptNumericAddresses = 0;
  myGlobals.numResolvedOnCacheAddresses = 0;

  /* Misc */
  myGlobals.separator = "&nbsp;";

  myGlobals.thisZone = gmt2local(0);      /* seconds offset from gmt to local time */
  myGlobals.numPurgedHosts = 0;
  myGlobals.numTerminatedSessions = 0;

  /* Time */
  myGlobals.actTime = time(NULL);
  myGlobals.initialSniffTime = 0;
  myGlobals.lastRefreshTime = 0;
  myGlobals.lastPktTime.tv_sec = 0;
  myGlobals.lastPktTime.tv_usec = 0;

  /* Monitored Protocols */
  myGlobals.numActServices = 0;
  myGlobals.udpSvc = NULL;
  myGlobals.tcpSvc = NULL;

  myGlobals.protoIPTrafficInfos = NULL;
  myGlobals.numIpProtosToMonitor = 0;
  myGlobals.numIpPortsToHandle = 0;
  myGlobals.ipPortMapper = NULL;
  myGlobals.numIpPortMapperSlots = 0;
  myGlobals.numHandledSIGPIPEerrors = 0;
  myGlobals.numHandledHTTPrequests = 0;

  /* Packet Capture */
#if defined(CFG_MULTITHREADED)
  for (i = 0; i <= CONST_PACKET_QUEUE_LENGTH; i ++)
    memset(&myGlobals.packetQueue[i], 0, sizeof(PacketInformation));

  myGlobals.packetQueueLen = 0;
  myGlobals.maxPacketQueueLen = 0;
  myGlobals.packetQueueHead = 0;
  myGlobals.packetQueueTail = 0;
#endif

  for (i = 0; i < CONST_NUM_TRANSACTION_ENTRIES; i ++)
    memset(&myGlobals.transTimeHash[i], 0, sizeof(TransactionTime));

  myGlobals.dummyEthAddress[0] = '\0';

      /*
       *  Setup the mtu and header size tables. 
       *
       *  We set only the ones we specifically know... anything else will 
       *  get mtu=CONST_UNKNOWN_MTU, header=0
       *
       *     If mtuSize is wrong, the only problem will be 1) erroneous-/mis-classification 
       *     of packets as "too long", 2) the suspicious packet file, if one, may have
       *     extra or missing entries, and 3) an erroneous line in the report.
       *
       *     If headerSize is wrong, the only problem will be in nfsPlugin.c, but this may
       *     cause problems, as it uses the value to strip off the header so it can analyze
       *     the nfs packet.
       *
       *  Remember that for most protocols, mtu isn't fixed - it's set by the routers
       *  and can be tuned by the sysadmin, isp, et al for "best results".
       *
       *  These do need to be periodically resynced with tcpdump.org and with user experience.
       *
       *  History:
       *      15Sep2002 - BStrauss
       *
       */

  { int ii;
    for (ii=0; ii<MAX_DLT_ARRAY; ii++) {
        _mtuSize[ii]    = CONST_UNKNOWN_MTU;
        _headerSize[ii] = 0;
    }
  }

  _mtuSize[DLT_NULL] = 8232                                    /* no link-layer encapsulation */;
  _headerSize[DLT_NULL] = CONST_NULL_HDRLEN;

      /* 1500 + 14 bytes header Courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */
  _mtuSize[DLT_EN10MB] = 1500+sizeof(struct ether_header)      /* Ethernet (10Mb) */;
  _headerSize[DLT_EN10MB] = sizeof(struct ether_header);

  _mtuSize[DLT_PRONET] = 17914                                 /* Proteon ProNET Token Ring */;
  _headerSize[DLT_PRONET] = sizeof(struct tokenRing_header);

  _mtuSize[DLT_IEEE802] = 4096+sizeof(struct tokenRing_header) /* IEEE 802 Networks */;
  _headerSize[DLT_IEEE802] = 1492;       /* NOTE: This has to be wrong... */

  /* _mtuSize[DLT_PPP] = ?                                        Point-to-point Protocol */
  _headerSize[DLT_PPP] = CONST_PPP_HDRLEN;

      /* Courtesy of Richard Parvass <Richard.Parvass@ReckittBenckiser.com> */
  _mtuSize[DLT_FDDI] = 4470                                    /* FDDI */;
  _headerSize[DLT_FDDI] = sizeof(struct fddi_header);

  _mtuSize[DLT_ATM_RFC1483] = 9180                             /* LLC/SNAP encapsulated atm */;
  _headerSize[DLT_ATM_RFC1483] = 0;

  /* _mtuSize[DLT_RAW] = ?                                        raw IP */
  _headerSize[DLT_RAW] = 0;

  /* Others defined in bpf.h at tcpdump.org as of the resync - it would be NICE
      to have values for these... */

  /* _mtuSize[DLT_EN3MB] = ?                                    Experimental Ethernet (3Mb) */
  /* _mtuSize[DLT_AX25] = ?                                     Amateur Radio AX.25 */
  /* _mtuSize[DLT_CHAOS] = ?                                    Chaos */
  /* _mtuSize[DLT_ARCNET] = ?                                   ARCNET */
  /* _mtuSize[DLT_SLIP] = ?                                     Serial Line IP */
  /* _mtuSize[DLT_SLIP_BSDOS] = ?                               BSD/OS Serial Line IP */
  /* _mtuSize[DLT_PPP_BSDOS] = ?                                BSD/OS Point-to-point Protocol */
  /* _mtuSize[DLT_ATM_CLIP] = ?                                 Linux Classical-IP over ATM */
  /* _mtuSize[DLT_PPP_SERIAL] = ?                               PPP over serial with HDLC encapsulation */
  /* _mtuSize[DLT_PPP_ETHER] = ?                                PPP over Ethernet */
  /* _mtuSize[DLT_C_HDLC] = ?                                   Cisco HDLC */
  /* _mtuSize[DLT_IEEE802_11] = ?                               IEEE 802.11 wireless */
  /* _mtuSize[DLT_FRELAY] = ?                                   */
  /* _mtuSize[DLT_LOOP] = ?                                     */
  /* _mtuSize[DLT_LINUX_SLL] = ?                                */
  /* _mtuSize[DLT_LTALK] = ?                                    */
  /* _mtuSize[DLT_ECONET] = ?                                   */
  /* _mtuSize[DLT_IPFILTER] = ?                                 */
  /* _mtuSize[DLT_PFLOG] = ?                                    */
  /* _mtuSize[DLT_CISCO_IOS] = ?                                */
  /* _mtuSize[DLT_PRISM_HEADER] = ?                             */
  /* _mtuSize[DLT_AIRONET_HEADER] = ?                           */
  /* _mtuSize[DLT_HHDLC] = ?                                    */
  /* _mtuSize[DLT_IP_OVER_FC] = ?                               */
  /* _mtuSize[DLT_SUNATM] = ?                                   Solaris+SunATM */

  myGlobals.mtuSize        = _mtuSize;
  myGlobals.headerSize     = _headerSize;

  myGlobals.enableIdleHosts = 1;

  myGlobals.netFlowInSocket = -1;  
  myGlobals.netFlowOutSocket = -1;  
  myGlobals.globalFlowSequence = myGlobals.globalFlowPktCount = 0;
}

/* ****************************** */

#ifdef MAKE_WITH_SYSLOG
/*
 * Create the table data.  If we have the headers, we use the values, which
 * is ripped from Linux's /usr/include/sys/syslog.h. If not, it's a table
 * with just a null entry.
 *
 * NOTE: if various systems add facilities we want to support, or change
 * the values, this has to be updated to be sensitive to the target system,
 * compiler, etc.
 */

MYCODE myFacilityNames[] =
  {
    { "auth", LOG_AUTH },
    { "cron", LOG_CRON },
    { "daemon", LOG_DAEMON },
    { "kern", LOG_KERN },
    { "lpr", LOG_LPR },
    { "mail", LOG_MAIL },
    { "news", LOG_NEWS },
    { "syslog", LOG_SYSLOG },
    { "user", LOG_USER },
    { "uucp", LOG_UUCP },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 },
    { NULL, -1 }                     /* Sentinal entry */
  };
#endif
