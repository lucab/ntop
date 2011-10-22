/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *                          http://www.ntop.org
 *
 *          Copyright (C) 1998-2011 Luca Deri <deri@ntop.org>
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
#include "globals-core.h"
#include "globals-report.h"

NtopGlobals myGlobals;

#if !defined(HAVE_GETOPT_H) && !defined(DARWIN)
char *optarg;
int optind;
int opterr;
int optopt;
#endif

#ifdef WIN32
char *version, *osName, *author, *buildDate, *configureDate,
  *configure_parameters,
  *host_system_type,
  *target_system_type,
  *compiler_cppflags,
  *compiler_cflags,
  *include_path,
  *system_libs,
  *install_path,
  *force_runtime;
#endif

static u_short _mtuSize[MAX_DLT_ARRAY];
static u_short _headerSize[MAX_DLT_ARRAY];

#ifdef WIN32
extern char _wdir[];
#endif

static char *_dataFileDirs[]   = {
  ".",
#ifdef WIN32
  _wdir,
#endif
  CFG_DATAFILE_DIR, DEFAULT_NTOP_HTML_INSTALL, NULL };
static char *_pluginDirs[]     = { "./plugins", CFG_PLUGIN_DIR, DEFAULT_NTOP_PLUGINS_INSTALL, NULL };
static char *_configFileDirs[] = { ".", CFG_CONFIGFILE_DIR, DEFAULT_NTOP_CFG_CONFIGFILE_DIR,
#ifdef WIN32
				   _wdir,
#else
				   "/etc",
#endif
				   NULL };

struct in6_addr _in6addr_linklocal_allnodes;

/* ************************************************************ */

void initGdbm(char *prefDirectory,  /* Directory with persistent files */
	      char *spoolDirectory, /* Directory with temporary files (that can be deleted when ntop is not running) */
	      int  initPrefsOnly) {
  struct stat statbuf;

  traceEvent(CONST_TRACE_INFO, "Initializing gdbm databases");

  if(initPrefsOnly) {
    initSingleGdbm(&myGlobals.prefsFile,        "prefsCache.db",   prefDirectory,  FALSE, NULL);
    initSingleGdbm(&myGlobals.pwFile,           "ntop_pw.db",      prefDirectory,  FALSE, NULL);
    return;
  }

  initSingleGdbm(&myGlobals.macPrefixFile,    "macPrefix.db",    spoolDirectory, FALSE,  &statbuf);
  initSingleGdbm(&myGlobals.fingerprintFile,  "fingerprint.db",  spoolDirectory, FALSE,  &statbuf);
  initSingleGdbm(&myGlobals.serialFile,       "hostSerials.db",  spoolDirectory, TRUE,   &statbuf);
  initSingleGdbm(&myGlobals.topTalkersFile,   "topTalkers.db",   spoolDirectory, FALSE,  &statbuf);

  createVendorTable(&statbuf);

  checkCommunities(); /* Check if communities are defined */
}

/* ******************************* */

static void allocateOtherHosts(void) {
  if(myGlobals.otherHostEntry != NULL) {
    traceEvent(CONST_TRACE_WARNING, "Attempting to call twice allocateOtherHosts()");
    return;
  }

  myGlobals.otherHostEntry = (HostTraffic*)malloc(sizeof(HostTraffic));
  memset(myGlobals.otherHostEntry, 0, sizeof(HostTraffic));

  myGlobals.otherHostEntry->hostIp4Address.s_addr = 0x00112233;
  strncpy(myGlobals.otherHostEntry->hostNumIpAddress, "&nbsp;",
	  sizeof(myGlobals.otherHostEntry->hostNumIpAddress));
  strncpy(myGlobals.otherHostEntry->hostResolvedName, "Remaining Host(s)",
	  sizeof(myGlobals.otherHostEntry->hostResolvedName));
  myGlobals.otherHostEntry->hostResolvedNameType = FLAG_HOST_SYM_ADDR_TYPE_FAKE;
  strcpy(myGlobals.otherHostEntry->ethAddressString, "00:00:00:00:00:00");
  myGlobals.otherHostEntry->portsUsage = NULL;

  myGlobals.otherHostEntry->serialHostIndex = ++myGlobals.hostSerialCounter; /* Start from 1 (0 = UNKNOWN_SERIAL_INDEX) */
}

/* ************************************ */

void extend8021Qmtu(void) {
#ifndef MAKE_WITH_JUMBO_FRAMES
  /* 1500 + 14 bytes header + 4 VLAN */
  _mtuSize[DLT_EN10MB] = 1500+sizeof(struct ether_header)+4;
#endif
}

/* ************************************ */

/*
 * Initialize all global run-time parameters to default (reasonable!!!) values
 */
void initNtopGlobals(int argc, char * argv[], int argc_started, char *argv_started[]) {
  int i, bufLen;
  char *startedAs, *defaultPath;

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

  initUserPrefs(&myGlobals.runningPref);

  /* Overrides for above */
  if (strcmp(myGlobals.program_name, "ntopd") == 0) {
    myGlobals.runningPref.daemonMode = 1;
  }

  /* note that by default ntop will merge network interfaces */
  if(myGlobals.runningPref.mergeInterfaces == 0)
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NOTE: Interface merge disabled by default");
  else
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "NOTE: Interface merge enabled by default");

  myGlobals.checkVersionStatus = FLAG_CHECKVERSION_NOTCHECKED;
  myGlobals.checkVersionStatusAgain = 1;

  /* Other flags (to be set via command line options one day) */
  myGlobals.enableFragmentHandling = 1;

  /* Search paths */
  myGlobals.dataFileDirs    = _dataFileDirs;
  myGlobals.pluginDirs      = _pluginDirs;
  myGlobals.configFileDirs  = _configFileDirs;

#ifdef WIN32
  defaultPath = _wdir;
#else
  defaultPath = CFG_DBFILE_DIR;
#endif
  myGlobals.dbPath          = strdup(defaultPath);     /* a NULL pointer will break the logic */

  /* NB: we can't init rrdPath here, because initGdbm hasn't been run */

  /* list of available NICs */
  myGlobals.allDevs = NULL;
  
  /* the table of enabled NICs */
  myGlobals.numDevices = 0;
  myGlobals.device = calloc(MAX_NUM_DEVICES, sizeof(NtopInterface));

  if(myGlobals.device == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Not enough memory :-(");
    exit(-1);
  }

  /* Databases */
  myGlobals.pwFile = NULL;

  /* the table of broadcast entries */
  myGlobals.broadcastEntry = NULL;

  /* the table of other hosts entries */
  myGlobals.otherHostEntry = NULL;

  /* administrative */
  myGlobals.shortDomainName = NULL;

  myGlobals.numThreads = 0;            /* # of running threads */
  
#ifdef HAVE_OPENSSL
  myGlobals.sslInitialized = 0;
  myGlobals.runningPref.sslPort = 0; /* Disabled by default: enabled via -W */
#endif

  myGlobals.dnsSniffCount = 0;
  myGlobals.dnsSniffRequestCount = 0;
  myGlobals.dnsSniffFailedCount = 0;
  myGlobals.dnsSniffARPACount = 0;
  myGlobals.dnsSniffStoredInCache = 0;

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

  myGlobals.ipTrafficProtosNames = NULL;
  myGlobals.numIpProtosToMonitor = 0;
  myGlobals.ipPortMapper.numElements = 0;
  myGlobals.ipPortMapper.theMapper = NULL;
  myGlobals.ipPortMapper.numSlots = 0;
  myGlobals.numHandledSIGPIPEerrors = 0;

  for(i=0; i<=1; i++) {
    myGlobals.numHandledRequests[i] = 0;
    myGlobals.numHandledBadrequests[i] = 0;
    myGlobals.numSuccessfulRequests[i] = 0;
    myGlobals.numUnsuccessfulInvalidrequests[i] = 0;
    myGlobals.numUnsuccessfulInvalidmethod[i] = 0;
    myGlobals.numUnsuccessfulInvalidversion[i] = 0;
    myGlobals.numUnsuccessfulTimeout[i] = 0;
    myGlobals.numUnsuccessfulNotfound[i] = 0;
    myGlobals.numUnsuccessfulDenied[i] = 0;
    myGlobals.numUnsuccessfulForbidden[i] = 0;
  }

  myGlobals.numSSIRequests = 0;
  myGlobals.numBadSSIRequests = 0;
  myGlobals.numHandledSSIRequests = 0;

  createMutex(&myGlobals.geolocalizationMutex); /* GeoIP mutex */

  /* create the logView stuff Mutex first... must be before the 1st traceEvent() call */
  createMutex(&myGlobals.logViewMutex);     /* synchronize logView buffer */
#ifdef FORPRENPTL
#warning Making version for Pre NPTL Thread Library...
  createMutex(&myGlobals.preNPTLlogMutex);     /* synchronize logView buffer */
#endif
  myGlobals.logViewNext = 0;
  myGlobals.logView = (char**)calloc(sizeof(char*),
				     CONST_LOG_VIEW_BUFFER_SIZE);

  /* traceEvent(CONST_TRACE_INFO, "Initializing semaphores, mutexes and threads"); */

  /* ============================================================
   * Create semaphores and mutexes associated with packet capture
   * ============================================================
   */
#ifdef HAVE_PTHREAD_ATFORK
  i = pthread_atfork(NULL, NULL, &reinitMutexes);
  /* traceEvent(CONST_TRACE_INFO, "NOTE: atfork() handler registered for mutexes, rc %d", i); */
#endif

  createMutex(&myGlobals.gdbmMutex);        /* data to synchronize thread access to db files */
  createMutex(&myGlobals.portsMutex);       /* Avoid race conditions while handling ports */

  for(i=0; i<NUM_SESSION_MUTEXES; i++)
    createMutex(&myGlobals.tcpSessionsMutex[i]); /* data to synchronize TCP sessions access */

  createMutex(&myGlobals.purgePortsMutex);  /* data to synchronize port purge access */
  createMutex(&myGlobals.purgeMutex);       /* synchronize purging */
  createMutex(&myGlobals.securityItemsMutex);
  createMutex(&myGlobals.hostsHashLockMutex);

  createMutex(&myGlobals.serialLockMutex);  /* Serial host locking */

  for(i=0; i<CONST_HASH_INITIAL_SIZE; i++) {
    createMutex(&myGlobals.hostsHashMutex[i]);
    myGlobals.hostsHashMutexNumLocks[i] = 0;
  }

  myGlobals.receivedPackets          = 0;
  myGlobals.receivedPacketsProcessed = 0;
  myGlobals.receivedPacketsQueued    = 0;
  myGlobals.receivedPacketsLostQ     = 0;

  /* NB: Log View is allocated in main.c so it's available for the very 1st traceEvent() */

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
   *     If headerSize is wrong, there are no known problems.
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

#ifdef MAKE_WITH_JUMBO_FRAMES
  _mtuSize[DLT_EN10MB] = 9000                                  /* Ethernet (1000Mb+ Jumbo Frames) */;
#else
  /* 1500 + 14 bytes header Courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */
  _mtuSize[DLT_EN10MB] = 1500+sizeof(struct ether_header)      /* Ethernet (10Mb) */;
#endif
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

  /* ********************************** */

  myGlobals.numPurgedHosts = myGlobals.numTerminatedSessions = 0;

  myGlobals.broadcastEntry = (HostTraffic*)malloc(sizeof(HostTraffic));
  memset(myGlobals.broadcastEntry, 0, sizeof(HostTraffic));
  resetHostsVariables(myGlobals.broadcastEntry);

  /* Set address to FF:FF:FF:FF:FF:FF */
  for(i=0; i<LEN_ETHERNET_ADDRESS; i++)
    myGlobals.broadcastEntry->ethAddress[i] = 0xFF;

  myGlobals.broadcastEntry->hostIp4Address.s_addr = 0xFFFFFFFF;
  strncpy(myGlobals.broadcastEntry->hostNumIpAddress, "broadcast",
	  sizeof(myGlobals.broadcastEntry->hostNumIpAddress));
  strncpy(myGlobals.broadcastEntry->hostResolvedName, myGlobals.broadcastEntry->hostNumIpAddress,
	  sizeof(myGlobals.broadcastEntry->hostNumIpAddress));
  myGlobals.broadcastEntry->hostResolvedNameType = FLAG_HOST_SYM_ADDR_TYPE_FAKE;
  strcpy(myGlobals.broadcastEntry->ethAddressString, "FF:FF:FF:FF:FF:FF");
  setHostFlag(FLAG_SUBNET_LOCALHOST, myGlobals.broadcastEntry);
  setHostFlag(FLAG_BROADCAST_HOST, myGlobals.broadcastEntry);
  setHostFlag(FLAG_SUBNET_PSEUDO_LOCALHOST, myGlobals.broadcastEntry);
  memset(&myGlobals.broadcastEntry->hostSerial, 0, sizeof(HostSerial));
  myGlobals.broadcastEntry->serialHostIndex = ++myGlobals.hostSerialCounter; /* Start from 1 (0 = UNKNOWN_SERIAL_INDEX) */
 
  allocateOtherHosts();

  /* ********************************** */

  bufLen = 0;
  for (i=0; i<argc_started; i++) {
    bufLen += (int)(2 + strlen(argv_started[i]));
  }

  startedAs = (char*)malloc(bufLen);
  memset(startedAs, 0, (size_t) bufLen);
  for (i=0; i<argc_started; i++) {
    if (argv_started[i] != NULL) {
      int displ = (int)strlen(startedAs);

      snprintf(&startedAs[displ], bufLen-displ, "%s ", argv_started[i]);
    }
  }

  myGlobals.startedAs = startedAs;

  /* 
     Efficiency is the ability to fill-up ATM cells so that they
     can be efficiently used by applications
  */
  myGlobals.cellLength = 47; /* FIX - this is valid only for ATM */
}

/* ********************************* */

static void loadGeoIP(void) {
  int i;
  struct stat statbuf;

  /* Initialize GeoIP databases */
  for(i=0; myGlobals.configFileDirs[i] != NULL; i++) {
    char path[256];
    
    safe_snprintf(__FILE__, __LINE__, path, sizeof(path),
		  "%s%c%s",
		  myGlobals.configFileDirs[i], 
		  CONST_PATH_SEP, GEO_IP_FILE);
    revertSlashIfWIN32(path, 0);

    if(stat(path, &statbuf) == 0) {
      if((myGlobals.geo_ip_db = GeoIP_open(path, GEOIP_CHECK_CACHE)) != NULL) {
	traceEvent(CONST_TRACE_INFO, "GeoIP: loaded config file %s", path);
	break;
      }
    }
  }
  
  if(myGlobals.geo_ip_db == NULL)
    traceEvent(CONST_TRACE_ERROR, "GeoIP: unable to load file %s", GEO_IP_FILE);
  
  /* *************************** */

  for(i=0; myGlobals.configFileDirs[i] != NULL; i++) {
    char path[256];
    
    safe_snprintf(__FILE__, __LINE__, path, sizeof(path),
		  "%s%c%s",
		  myGlobals.configFileDirs[i], 
		  CONST_PATH_SEP, GEO_IP_ASN_FILE);
    revertSlashIfWIN32(path, 0);

    if(stat(path, &statbuf) == 0) {
      if((myGlobals.geo_ip_asn_db = GeoIP_open(path, GEOIP_CHECK_CACHE)) != NULL) {
	traceEvent(CONST_TRACE_INFO, "GeoIP: loaded ASN config file %s", path);
	break;
      }
    }
  }
  
  if(myGlobals.geo_ip_asn_db == NULL)
    traceEvent(CONST_TRACE_ERROR, "GeoIP: unable to load ASN file %s", GEO_IP_ASN_FILE);  
}

/* ********************************* */

void initNtop(char *devices) {
  char value[32];

  revertSlashIfWIN32(myGlobals.dbPath, 0);
  revertSlashIfWIN32(myGlobals.spoolPath, 0);

  initIPServices();
  handleProtocols();

  if(myGlobals.numIpProtosToMonitor == 0)
    addDefaultProtocols();

  /*
   * initialize memory and data.
   */
  initDevices(devices);

  init_events();

  if(myGlobals.runningPref.enableSessionHandling)
    initPassiveSessions();

  /* ********************************** */

  initGdbm(myGlobals.dbPath, myGlobals.spoolPath, 0);

  /* We just initialized gdbm: let's now dump serials */
  dumpHostSerial(&myGlobals.broadcastEntry->hostSerial, myGlobals.broadcastEntry->serialHostIndex);
  dumpHostSerial(&myGlobals.otherHostEntry->hostSerial, myGlobals.otherHostEntry->serialHostIndex);

  if(myGlobals.runningPref.daemonMode) {
    /*
      Before bacoming a daemon we need o make sure that
      ntop has been installed properly and that all the
      html files are on the right place
    */

    int idx, found = 0;

    for(idx=0; (!found) && (myGlobals.dataFileDirs[idx] != NULL); idx++) {
      char tmpStr[256];
      struct stat statbuf;

      if(strcmp(myGlobals.dataFileDirs[idx], ".") /* ignore local paths */ ) {
	safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
		      "%s/html/%s",
		      myGlobals.dataFileDirs[idx],
		      "ntop.gif" /* This file must always exist */);

	if(stat(tmpStr, &statbuf) == 0) {
	  found = 1;
	  break;
	}
      }
    }

    if(!found) {
      traceEvent(CONST_TRACE_WARNING, "ntop will not become a daemon as it has not been");
      traceEvent(CONST_TRACE_WARNING, "installed properly (did you do 'make install')");
    } else
      daemonizeUnderUnix();
  }

  /* Handle local addresses (if any) */
  handleLocalAddresses(myGlobals.runningPref.localAddresses);

  /* Handle known subnetworks (if any) */
  handleKnownAddresses(myGlobals.runningPref.knownSubnets);

  if((myGlobals.pcap_file_list != NULL) 
     && (myGlobals.runningPref.localAddresses == NULL)) {
    char *any_net = "0.0.0.0/0";

    traceEvent(CONST_TRACE_WARNING,
	       "-m | local-subnets must be specified when the -f option is used"
	       "Assuming %s", any_net);
    myGlobals.runningPref.localAddresses = strdup(any_net);
  }

  if(myGlobals.runningPref.currentFilterExpression != NULL)
    parseTrafficFilter();
  else
    myGlobals.runningPref.currentFilterExpression = strdup(""); /* so that it isn't NULL! */

  /* Handle flows (if any) */
  handleFlowsSpecs();

  createPortHash();
  initCounters();
  initApps();
  initThreads();

#ifndef MAKE_MICRO_NTOP
  traceEvent(CONST_TRACE_NOISY, "Starting Plugins");
  startPlugins();
  traceEvent(CONST_TRACE_NOISY, "Plugins started... continuing with initialization");
#endif

#if defined(MEMORY_DEBUG) && defined(MAKE_WITH_SAFER_ROUTINES)
  resetLeaks();
#endif

  addNewIpProtocolToHandle("IGMP", 2, 0 /* no proto */);
  addNewIpProtocolToHandle("OSPF", 89, 0 /* no proto */);
  addNewIpProtocolToHandle("IPsec", 50, 51);

  init_maps();
  loadGeoIP();

  if(fetchPrefsValue("globals.displayPolicy", value, sizeof(value)) == -1) {
    myGlobals.hostsDisplayPolicy = showAllHosts /* 0 */;
    storePrefsValue("globals.displayPolicy", "0");
  } else {
    myGlobals.hostsDisplayPolicy = atoi(value);

    /* Out of range check */
    if((myGlobals.hostsDisplayPolicy < showAllHosts)
       || (myGlobals.hostsDisplayPolicy > showOnlyRemoteHosts))
      myGlobals.hostsDisplayPolicy = showAllHosts;
  }

  if(fetchPrefsValue("globals.localityPolicy", value, sizeof(value)) == -1) {
    myGlobals.localityDisplayPolicy = showSentReceived /* 0 */;
    storePrefsValue("globals.localityPolicy", "0");
  } else {
    myGlobals.localityDisplayPolicy = atoi(value);

    /* Out of range check */
    if((myGlobals.localityDisplayPolicy < showSentReceived)
       || (myGlobals.localityDisplayPolicy > showOnlyReceived))
      myGlobals.localityDisplayPolicy = showSentReceived;
  }

  if(myGlobals.runningPref.skipVersionCheck != TRUE) {
    pthread_t myThreadId;
    createThread(&myThreadId, checkVersion, NULL);
  }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* This routine enforces the state change rules
 *
 *
 * Valid state transitions:
 *   0->1           When ntop first starts up, after memset(myGlobals)
 *   1->2           After the basic system protective environment is up...
 *   2->3           When ntop gives up root
 *   3->4           When ntop finishes initialization
 *Or 2->4           When ntop finishes initialization on systems w/o root, e.g. Win32
 *   4->5, 6, 7     Stopcap to keep webserver up after a problem or Shutdown on user request
 *   5->6, 7        Shutdown requested
 *   6->7           Shutdown running
 *   7->8           Shutdown complete
 *   8->1 (restart) FUTURE...
 *
 */

short _setRunState(char *file, int line, short newRunState) {

  static short stateTransitionTable[FLAG_NTOPSTATE_TERM+1][FLAG_NTOPSTATE_TERM+1];
  static char *stateTransitionTableNames[FLAG_NTOPSTATE_TERM+1];
  static short stateTransitionTableLoaded=0;

  if(stateTransitionTableLoaded == 0) {
    /* One time load */
    int i;

    for(i=0; i<FLAG_NTOPSTATE_TERM; i++)
      stateTransitionTable[i][i] = 1;

    stateTransitionTable[FLAG_NTOPSTATE_NOTINIT][FLAG_NTOPSTATE_PREINIT] = 1;
    stateTransitionTable[FLAG_NTOPSTATE_PREINIT][FLAG_NTOPSTATE_INIT] = 1;
    stateTransitionTable[FLAG_NTOPSTATE_INIT][FLAG_NTOPSTATE_INITNONROOT] = 1;
    stateTransitionTable[FLAG_NTOPSTATE_INIT][FLAG_NTOPSTATE_SHUTDOWN] = 1; /* abort */
    stateTransitionTable[FLAG_NTOPSTATE_INITNONROOT][FLAG_NTOPSTATE_RUN] = 1;
    stateTransitionTable[FLAG_NTOPSTATE_INIT][FLAG_NTOPSTATE_RUN] = 1;
    stateTransitionTable[FLAG_NTOPSTATE_RUN][FLAG_NTOPSTATE_STOPCAP] = 1;
    stateTransitionTable[FLAG_NTOPSTATE_RUN][FLAG_NTOPSTATE_SHUTDOWNREQ] = 1;
    stateTransitionTable[FLAG_NTOPSTATE_RUN][FLAG_NTOPSTATE_SHUTDOWN] = 1;
    stateTransitionTable[FLAG_NTOPSTATE_STOPCAP][FLAG_NTOPSTATE_SHUTDOWNREQ] = 1;
    stateTransitionTable[FLAG_NTOPSTATE_STOPCAP][FLAG_NTOPSTATE_SHUTDOWN] = 1;

    for(i=FLAG_NTOPSTATE_PREINIT; i<FLAG_NTOPSTATE_SHUTDOWNREQ; i++)
      stateTransitionTable[i][FLAG_NTOPSTATE_SHUTDOWNREQ] = 1;

    stateTransitionTable[FLAG_NTOPSTATE_SHUTDOWNREQ][FLAG_NTOPSTATE_SHUTDOWN] = 1;
    stateTransitionTable[FLAG_NTOPSTATE_SHUTDOWN][FLAG_NTOPSTATE_TERM] = 1;

    stateTransitionTableNames[FLAG_NTOPSTATE_NOTINIT] = "NOTINIT";
    stateTransitionTableNames[FLAG_NTOPSTATE_PREINIT] = "PREINIT";
    stateTransitionTableNames[FLAG_NTOPSTATE_INIT] = "INIT";
    stateTransitionTableNames[FLAG_NTOPSTATE_INITNONROOT] = "INITNONROOT";
    stateTransitionTableNames[FLAG_NTOPSTATE_RUN] = "RUN";
    stateTransitionTableNames[FLAG_NTOPSTATE_STOPCAP] = "STOPCAP";
    stateTransitionTableNames[FLAG_NTOPSTATE_SHUTDOWNREQ] = "SHUTDOWNREQ";
    stateTransitionTableNames[FLAG_NTOPSTATE_SHUTDOWN] = "SHUTDOWN";
    stateTransitionTableNames[FLAG_NTOPSTATE_TERM] = "TERM";

    stateTransitionTableLoaded = 1;

  }

  if(stateTransitionTable[myGlobals.ntopRunState][newRunState] == 0) {
    traceEvent(CONST_FATALERROR_TRACE_LEVEL, file, line,
               "Invalid runState transition %d to %d",
               myGlobals.ntopRunState,
               newRunState);
    exit(99);
  }

  /* These are largely blueprints for the future */

  /* Take appropriate finishing action(s) for old state... */
  switch(newRunState) {
  case FLAG_NTOPSTATE_NOTINIT:
    break;
  case FLAG_NTOPSTATE_PREINIT:
    break;
  case FLAG_NTOPSTATE_INIT:
    break;
  case FLAG_NTOPSTATE_INITNONROOT:
    break;
  case FLAG_NTOPSTATE_RUN:
    break;
  case FLAG_NTOPSTATE_STOPCAP:
    break;
  case FLAG_NTOPSTATE_SHUTDOWNREQ:
    break;
  case FLAG_NTOPSTATE_SHUTDOWN:
    break;
  case FLAG_NTOPSTATE_TERM:
    break;
  }

  /* Take appropriate action(s) for new state... */
  switch(newRunState) {
  case FLAG_NTOPSTATE_NOTINIT:
    break;
  case FLAG_NTOPSTATE_PREINIT:
    break;
  case FLAG_NTOPSTATE_INIT:
    break;
  case FLAG_NTOPSTATE_INITNONROOT:
    break;
  case FLAG_NTOPSTATE_RUN:
    break;
  case FLAG_NTOPSTATE_STOPCAP:
    break;
  case FLAG_NTOPSTATE_SHUTDOWNREQ:
    break;
  case FLAG_NTOPSTATE_SHUTDOWN:
    break;
  case FLAG_NTOPSTATE_TERM:
    break;
  }

  myGlobals.ntopRunState = newRunState;
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "THREADMGMT[t%lu]: ntop RUNSTATE: %s(%d)",
             (long unsigned int)pthread_self(),
             stateTransitionTableNames[newRunState],
             newRunState);

  return(myGlobals.ntopRunState);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

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
