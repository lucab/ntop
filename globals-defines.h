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

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 *
 *  This file, included from ntop.h, contains ALL common #define statements.
 *
 *     Changes here affect how ntop compiles.  This includes features that are
 *     enabled, etc.
 *
 *  Names have at least one part that defines their "type".  Listed below in the order
 *  they are most frequently changed.
 *  
 *  PARM -- any "PARM" item is an internal tuning item, e.g. one that must be set at
 *  compile time and can not be overridden at run time.
 *
 *  MAKE -- MAKEs are like PARM, but set based on other factors like the os, absence
 *  of other values, etc.
 *
 *  DEBUG -- any "DEBUG" item is not normally set, but if #define(d) causes additional
 *  output fron ntop of a debugging nature.
 *  
 *  CONST, LEN and MAX - these are arbitrary values, limits and lengths of fields
 *  (buffer size, ethernet address, et al) and arrays.
 *
 *  FLAG and BITFLAG -- are various constants and flags.
 *           FLAG is a numeric/char value used to mean something
 *           BITFLAG is a value used to test/set a specific bit in a value
 *
 *  HTML -- an "HTML" item is the name of a page produced by the ntop web server.  Using
 *  these constants ensures that the same name is used for testing and for including in
 *  generated html.  Note that this includes the graphics we use (.jpg, .gif and .png)
 *  regardless of whether it's a generated "page" or just a static included image.
 *  
 *  CFG -- any "CFG" item is set in config.h by ./configure indicating that ntop was
 *  requested to be compiled with a particular configuration.  These are not defined in
 *  this file.
 *  
 *  HAVE -- any "HAVE" item is set in config.h by ./configure indicating that the .h and
 *  .a/.so tests found we have a particular file or library during the testing process.
 *  HAVE items are not defined in this file (they're in config.h).  However - 
 *  Note that we don't differentiate in the code between the automatically generated
 *  singular items (HAVE_SSL_H) and the composite ones (generated from a bunch of tests,
 *  HAVE_OPENSSL).  Forced and/or Composite items should be defined here.
 *  
 *  DEFAULT -- any "DEFAULT" item is the standard, default value of a global data item.
 *  This can be over-ridden (usually) by a command-line pararameter at run-time.
 *  These go pretty much last so they can use values from other classes.
 *  
 *  -- any MISSING or EXTERNALLY named item, obviously, has to have the proper missing
 *     or externally named name.  These are grouped after the ntop stuff...
 *  
 *  Note that with this initial version (01-2003), there is something less than 100%
 *  adherence to this.  Any corrections, comments, (hopefully) documentation would be
 *  greatly appreciated.
 *
 */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* P A R M  items                                                                  */
/*  These typically make MAJOR changes in how ntop's operates                      */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 * These cause features (debugging or ones that may have problems) to be enabled/disabled.
 */

/*
 * A general work-in-progress flag
 */
/* #define PARM_ENABLE_EXPERIMENTAL */

/*
 * Controls whether to make a fork() call in http.c and xmldump.c
 */
#define PARM_FORK_CHILD_PROCESS

/*
 * Cache sessions instead of purging them and reuse.
 */
/* #define PARM_USE_SESSIONS_CACHE */

/*
 * Define to enable alternating row colors on many tables.
 */
#undef  PARM_USE_COLOR

/*
 * Define to allow processing of CGI scripts.
 */
#define PARM_USE_CGI

/*
 * This causes the hash functions in vendor.c to invert the mac address #s when
 * computing the hash.  This allows a lot fewer entries in the hash table.
 */        
#define PARM_USE_MACHASH_INVERT

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 * These cause more data (perhaps controversial or experimental) to be reported.
 */

/* PARM_PRINT_ALL_SESSIONS causes report.c/reportUtils.c to include in reports
 * lines for sessions that are not "active".
 */
/* #define PARM_PRINT_ALL_SESSIONS */

/* PARM_PRINT_RETRANSMISSION_DATA causes report.c/reportUtils.c to include in reports
 * lines for sessions that are not "active".
 */
/* #define PARM_PRINT_RETRANSMISSION_DATA */

/* Define PARM_SHOW_NTOP_HEARTBEAT to see minimal status messages every cycle
 * from various timed processes
 */
/* #define PARM_SHOW_NTOP_HEARTBEAT 1 */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 *  Timeouts and intervals - in seconds (x*60 = x minutes)
 */

/*
 *  How long between runs of the idle host purge?
 */
#define PARM_HOST_PURGE_INTERVAL            5*60

/*
 *  How long must a host be idle to be considered for purge?
 */
#define PARM_HOST_PURGE_MINIMUM_IDLE        10*60

/*
 *  How long must a session be idle to be considered for purge?
 */
#define PARM_SESSION_PURGE_MINIMUM_IDLE     10*60

/*
 *  How long to wait for pipe reads (e.g. lsof)?
 */
#define PARM_PIPE_READ_TIMEOUT              15

/*
 *  How long before a passive ftp session timesout?
 */
#define PARM_PASSIVE_SESSION_MINIMUM_IDLE   60

/*
 *  How long to leave somebody in myGlobals.weDontWantToTalkWithYou[]
 */
#define PARM_WEDONTWANTTOTALKWITHYOU_INTERVAL 5*60     /* 5 minutes */

/*
 * How often should we update the throughput counters?
 */
#define PARM_THROUGHPUT_REFRESH_INTERVAL    30

/*
 * Minimum value for the auto refresh of web pages (those that can be auto refreshed).
 *   User set via the -r | --refresh-time parameter.
 */
#define PARM_MIN_WEBPAGE_AUTOREFRESH_TIME   15

/*
 * SSLWATCHDOG
 *
 * For PARM_SSLWATCHDOG_WAITWOKE_LIMIT and PARM_SSLWATCHDOG_WAIT_INTERVAL,
 * see below, after MAKE_WITH_SSLWATCHDOG is set
 */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* M A K E option items                                                              */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* Win32 - Force various things to make up for lack of ./configure process */
#ifdef WIN32

 #ifndef CFG_MULTITHREADED
  #define CFG_MULTITHREADED
 #endif

 #ifndef MAKE_ASYNC_ADDRESS_RESOLUTION
  #define MAKE_ASYNC_ADDRESS_RESOLUTION
 #endif

 #define MAKE_STATIC_PLUGIN

 #define CFG_LITTLE_ENDIAN                  1
 #undef  CFG_BIG_ENDIAN

 /* CFG_DATAFILE_DIR - see ntop_win32.h */

 #ifndef CFG_PLUGIN_DIR
  #define CFG_PLUGIN_DIR                    "."
 #endif

 #ifndef CFG_CONFIGFILE_DIR
  #define CFG_CONFIGFILE_DIR                "."
 #endif

 #ifndef CFG_DBFILE_DIR
  #define CFG_DBFILE_DIR                    "."
 #endif

#endif

#ifndef WIN32
#define MAKE_RMON_SUPPORT
#endif

/*
 *  Defined in (Linux) <arpa/nameser_compat.h> which is included from
 *                     <arpa/nameser.h>
 *    If - for whatever reason - they're not found... add them, based on the Linux definitions.
 */
#ifndef PACKETSZ
 #define MAKE_NTOP_PACKETSZ_DECLARATIONS
#endif

#ifdef CFG_MULTITHREADED
/*
 * Comment out the line below if asynchronous
 * numeric -> symbolic address resolution
 * has problems on your system
 */
 #ifndef MAKE_ASYNC_ADDRESS_RESOLUTION
  #define MAKE_ASYNC_ADDRESS_RESOLUTION
 #endif
#endif

/*
 * MAKE_WITH_SYSLOG is shorthand for defined(HAVE_SYS_SYSLOG_H) || defined(HAVE_SYSLOG_H)
 * Use that ifdef everywhere else for code dependent on the includes.
 */
#undef MAKE_WITH_SYSLOG

#ifdef HAVE_SYS_SYSLOG_H
#define MAKE_WITH_SYSLOG
#else
#ifdef HAVE_SYSLOG_H
#define MAKE_WITH_SYSLOG
#endif
#endif

/*
 * MAKE_WITH_SEMAPHORES is shorthand for defined(HAVE_SEMAPHORE_H) && !defined(DARWIN).
 */
/* Courtesy of Fabrice Bellet <Fabrice.Bellet@creatis.insa-lyon.fr> */
#if defined(HAVE_SEMAPHORE_H) && !defined(DARWIN)
#define MAKE_WITH_SEMAPHORES   1
#else
#undef MAKE_WITH_SEMAPHORES
#endif

/*
 * MAKE_WITH_SCHED_YIELD is shorthand
 */
#if ( defined(HAVE_SCHED_H) || defined(HAVE_SYS_SCHED_H) ) && defined(HAVE_SCHED_YIELD)
 #define MAKE_WITH_SCHED_YIELD
#else
 #undef MAKE_WITH_SCHED_YIELD
#endif

/*
 * MAKE_WITH_SCHED_YIELD is shorthand
 */
#if ( defined(HAVE_SCHED_H) || defined(HAVE_SYS_SCHED_H) ) && defined(HAVE_SCHED_YIELD)
 #define MAKE_WITH_SCHED_YIELD
#else
 #undef MAKE_WITH_SCHED_YIELD
#endif

/*
 * Do we have the stuff we need for XMLDUMP?
 *   ./configure sets MAKE_WITH_XMLDUMP - that's the reliable one
 */
#ifndef MAKE_WITH_XMLDUMP
 #undef HAVE_XMLVERSION_H
 #undef HAVE_LIBXML2
 #undef HAVE_GLIB_H
 #undef HAVE_GLIBCONFIG_H
 #undef HAVE_GDOME_H
 #undef HAVE_LIBGDOME
#endif
/*
 * Do we have the stuff we need for i18n?
 */
#ifdef MAKE_WITH_I18N
 #if !defined(HAVE_LOCALE_H) || !defined(HAVE_LANGINFO_H)
  #undef MAKE_WITH_I18N
 #endif
#endif

/*
 * This flag indicates that fork() is implemented with copy-on-write.
 * This means that the set of tables reported on in xmldump.c (and other
 * fork()ed processes) will be complete and unchanged as of the instant
 * of the fork.
 */
#if defined(LINUX)
 #define MAKE_WITH_FORK_COPYONWRITE
#else /* WIN32 OPENBSD FREEBSD et al */
 #undef MAKE_WITH_FORK_COPYONWRITE
#endif

/*
 * This flag turns on a signal trap in rrdPlugin.c.  If you're seeing
 * rrd simply and silently die, this might catch the signal and log
 * it for analysis.
 */
/* #define MAKE_WITH_RRDSIGTRAP */

/*
 * This flag turns on a signal trap in webInterface.c and in http.c for
 * the children.  If you're seeing pages simply and silently die, this
 * might catch the signal and log it for analysis.
 */
/* #define MAKE_WITH_HTTPSIGTRAP */

/* EXPERIMENTAL */
/* Define MAKE_WITH_LOG_XXXXXX if you want log messages to use more than just
 * LOG_ERR for ntop's messages. */
 
/* Define MAKE_WITH_LOG_XXXXXX if you want log messages to use more than just
 * LOG_ERR for ntop's messages.
 *
 * See util.c for the mappings from CONST_TRACE_xxxx_LEVEL to LOG_xxxxxx settings.
 *
 * If you do this, it's STRONGLY suggested - to prevent a large # of console
 * messages - that you:
 *     use --use-syslog=local3 or such
 *     add local3.none to a couple of places in /etc/syslog.conf
 * so ntop's LOG_ERROR messages don't flood the real console.
 */
/* #undef MAKE_WITH_LOG_XXXXXX */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* D E B U G  items                                                                */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 *    WARNING: Descriptions are APPROXIMATE.  Check the code before turning
 *             these on/off.  They can cause HUGE amounts of log messages,
 *             and/or slow ntop down so it can't keep up.
 *
 *             Debugging code has not been widely tested, is subject to change
 *             on a developers whim and should NOT be used on production systems!
 *
 *                   OK?  You've been warned!
 *
 *  If you add something here, remember to add it to the #ifdef and the 
 *  detailed reporting lines in webInterface.c
 *
 */

/*
 * Enable these to make MAJOR, debug-type changes in ntop's activities!
 *   These are usually lots and lots of log messages
 */

/* ADDRESS_DEBUG logs the activities in address.c related to testing for
 * local, pseudolocal and remote status for ip addresses.
 */
/* #define ADDRESS_DEBUG */

/* DNS_DEBUG logs the activites in address.c related to Name resolution.
 */
/* #define DNS_DEBUG */

/* DNS_SNIFF_DEBUG logs the activites in pbuf.c and sessions.c related to
 * DNS requests and replies sniffed out of the ntop monitored traffic.
 */
/* #define DNS_SNIFF_DEBUG */

/* FRAGMENT_DEBUG logs information about packet fragments nto receives.
 */
/* #define FRAGMENT_DEBUG */

/* FTP_DEBUG logs ftp control session information.
 */
/* #define FTP_DEBUG */

/* GDBM_DEBUG logs the activites in address.c related to gdbm */
/* #define GDBM_DEBUG */

/* HASH_DEBUG logs the adding of values to the hash.  It also enables
 * (a presently unused) routine, hashDump().
 */
/* #define HASH_DEBUG */

/* HOST_FREE_DEBUG logs the freeing of hash_hostTraffic by freeHostInfo() in hash.c
 */
/* #define HOST_FREE_DEBUG */

/* HTTP_DEBUG logs the http sessions.  It logs HTTP/1... from source port 80
 * and anything to destination port 80.  Also http headers, etc.
 */
/* #define HTTP_DEBUG */

/* IDLE_PURGE_DEBUG logs the purging of idle hosts
 */
/* #define IDLE_PURGE_DEBUG */

/* I18N_DEBUG logs the activities in and around internationalization (i18n).
 */
/* #define I18N_DEBUG */

/* LSOF_DEBUG logs information about ntop's use of lsof
 */
/* #define LSOF_DEBUG */

/* MEMORY_DEBUG turns on the code in leaks.c (ntop_safexxxx) which monitors
 *  memory allocations for leaks.
 *  WARNING: There is code in pbuf.c that will stop ntop after a specified
 *           number of packets.
 *           The size of the hash_list (later in ntop.h) is also restricted.
 */
/* #define MEMORY_DEBUG */

/* NETFLOW_DEBUG logs the netflow packets as they are sent from
 * sendNetFlow() in netflow.c
 */
/* #define NETFLOW_DEBUG */

/* PACKET_DEBUG writes the IP and ETHER packets received by ntop to
 * a file.  Major impact on performance...
 */
/* #define PACKET_DEBUG */

/* PARAM_DEBUG enabled debug messages during command line parameter
 * processing.
 */
/* #define PARAM_DEBUG */

/* PLUGIN_DEBUG enables debug messages during plugin start/stop.
 */
/* #define PLUGIN_DEBUG */

/* PROBLEMREPORTID_DEBUG enables debug messages showing the values used to create
 * the unique ProblemReport Id
 */
/* #define PROBLEMREPORTID_DEBUG */

/* P2P_DEBUG enables debug messages during p2p protocol processing.
 */
/* #define P2P_DEBUG 1 */

/* RRD_DEBUG controls debug messages in rrdPlugin.c.  Define it for some messages
 * or set it to 1 for more, 2 for lots of detail or 3 for huge (every rrd call)
 */
/* #define RRD_DEBUG */

 /*
  * SEMAPHORE_DEBUG causes util.c to log information about semaphore operations.
 */
/* #define SEMAPHORE_DEBUG */

/* SESSION_TRACE_DEBUG causes sessions.c to log the start and end of
 * tcp sessions.
 */
/* #define SESSION_TRACE_DEBUG */

/*
 * SSLWATCHDOG_DEBUG causes webInterface.c to log the activities of the
 * parent and child(watchdog) threads in exhaustive details.
 *
 *   Note the code below (in derived settings) to undef this if the MAKE_WITH_SSLWATCHDOG
 *        option isn't enabled.      Leave that alone!
 *
 */
/* #define SSLWATCHDOG_DEBUG */

/* STORAGE_DEBUG causes util.c to log the store/resurrection of host information,
 * i.e. the -S command line parameter.
 */
/* #define STORAGE_DEBUG */

/* UNKNOWN_PACKET_DEBUG causes pbuf.c to log packets that are
 * either from an unknown protocol or of an unknown ethernet type
 */
/* #define UNKNOWN_PACKET_DEBUG */

/* VENDOR_DEBUG debugs the vendor table stuff in vendor.c
 */
/* #define VENDOR_DEBUG */

/* XMLDUMP_DEBUG causes xmldump.c to output debug information.
     define it as 0 for the minimal - enter/exit routine
     define it as 1 a little more
     define it as 2 to enable the trap, plus put out bunches of info lines...
     define it as 3 ... even more stuff...
 */
#define XMLDUMP_DEBUG 1

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* SSLWATCHDOG - this crosses the line.                                            */
/*   If the required libraries exist (multithreaded, openSSL, pthreads and         */
/*     NOT WIN32, then the user can                                                */
/*                                                                                 */
/*          1) request it at ./configure time (which should really be a            */
/*             HAVE_, but PARM_ seems closer to what we're telling ntop to do).    */
/*          2) Build it for a run-time parameter (MAKE_)                           */
/*                                                                                 */
/*    SSLWATCHDOG_DEBUG is used in webInterface.c to determine if we               */
/*    report stuff, but it's also used in globals-core.h to make or not-make       */
/*    debuging code.                                                               */
/*                                                                                 */
/*  Who needs that complexity in multiple places, so we put it all here!           */
/*  (since we're potentially unsetting SSLWATCHDOG_DEBUG, it has to go after       */
/*   the place to uncomment it...)                                                 */
/*                                                                                 */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if defined(CFG_MULTITHREADED) && defined(HAVE_OPENSSL) && defined(HAVE_PTHREAD_H) && defined(HAVE_SETJMP_H) && !defined(WIN32)
 #define MAKE_WITH_SSLWATCHDOG
 #ifdef MAKE_WITH_SSLWATCHDOG_COMPILETIME
  /* Compile Time option */
  #undef  MAKE_WITH_SSLWATCHDOG_RUNTIME
 #else
  /* Run time option */
  #undef SSLWATCHDOG_DEBUG
  #define MAKE_WITH_SSLWATCHDOG_RUNTIME
 #endif
#else
 /* Neither - don't have the required headers */
 #undef MAKE_WITH_SSLWATCHDOG
 #undef MAKE_WITH_SSLWATCHDOG_COMPILETIME
 #undef MAKE_WITH_SSLWATCHDOG_RUNTIME
 #undef SSLWATCHDOG_DEBUG
#endif

/*
 *  PARM_SSLWATCHDOG_WAITWOKE_LIMIT
 *    This is the number of times we'll allow ourselves to be woken up
 *    (for reasons other than the expiration of the watchdog interval
 *    or completion of the ssl accept).
 *
 *  PARM_SSLWATCHDOG_WAIT_INTERVAL
 *    This is the number of seconds to wait in the watchdog for the
 *    ssl accept to finish.
 */
#ifdef MAKE_WITH_SSLWATCHDOG
 #define PARM_SSLWATCHDOG_WAITWOKE_LIMIT    5
 #define PARM_SSLWATCHDOG_WAIT_INTERVAL     3
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* L E N,  L I M,  M A X  items                                                    */
/*        Some are with the CONST_ items, below too                                */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *  Tunables - changing these should allow ntop to handle more or less of some thing.
 *                  Commonly changed ones are up front...
 */

/*
 * Number of entries in myGlobals.packetQueue[], which is the queue of 
 * received but unanalyzed packets.
 *
 * Keep an eye on myGlobals.maxPacketQueueLen - this can eat up a lot of memory.
 * Each entry is well over 2*DEFAULT_SNAPLEN bytes.
 */
#define CONST_PACKET_QUEUE_LENGTH           2048

/*
 * This is the size of the table that holds IP addresses we don't want to
 * talk to (due to sending an invalid - i.e. hostile) URL
 *
 * Valid values are 0 (disables) up to whatever.
 */
#define MAX_NUM_BAD_IP_ADDRESSES            3

/*
 * Number of (optional) "AR - Address Resolution" threads,
 *    i.e. dequeueAddressThreadId[] and numDequeueThreads in myGlobals.
 *
 *  You might increase this if you have really slow dns resolution and are running
 *  asyncronously.
 */
#define MAX_NUM_DEQUEUE_THREADS             1

/*
 * In readLsofInfo(), this is the maximum # of processes to report information about.
 *
 *  You might increase this on a busy system, if you don't mind paging through lots
 *  of output, and if lsof is fast enough (check PARM_PIPE_READ_TIMEOUT).
 */
#define MAX_NUM_PROCESSES_READLSOFINFO      1024

/* Hash size */
#define CONST_HASH_INITIAL_SIZE             4096

/*
 * These change the break points for the "Network Traffic: xxxx" reports
 * (e.g. dataHostTraffic.html et al).  See getBgPctgColor() in reportUtils.c
 */
#define CONST_PCTG_LOW                      25           /* % */
#define CONST_CONST_PCTG_LOW_COLOR          "BGCOLOR=#C6EEF7"
#define CONST_PCTG_MID                      75           /* % */
#define CONST_CONST_PCTG_MID_COLOR          "BGCOLOR=#C6EFC8"
#define CONST_PCTG_HIGH_COLOR               "BGCOLOR=#FF3118"

/*
 * How long should we use an entry in the dnsCache database.
 *  Default (in seconds) is 24 hours
 */
#define CONST_DNSCACHE_LIFETIME             24*3600

/*
 *  Tunables - changing these should allow ntop to handle more or less of some thing.
 *                  Uncommonly changed ones...
 */

/*
 * The number of entries in HostTrafic's  recentlyUsedClientPorts[] and
 *    recentlyUsedServerPorts[] - this is the "TCP/UDP Recently Used Ports"
 *    section of the "Info about host" report.
 */
#define MAX_NUM_RECENT_PORTS                5

/*
 * These are various html colors used in places throughout ntop.
 *
 * Change them if you want, remember there are also static .html pages and
 * .css style sheets to change too!
 */
#define CONST_COLOR_1                       "#CCCCFF"
#define CONST_COLOR_2                       "#FFCCCC"
#define CONST_COLOR_3                       "#EEEECC"
#define CONST_COLOR_4                       "#FF0000"

#ifdef MEMORY_DEBUG
#define MAX_PER_DEVICE_HASH_LIST           256
#else
#define MAX_PER_DEVICE_HASH_LIST           ((u_int16_t)-1) /* Static hash size */
#endif

#define MAX_TOT_NUM_SESSIONS MAX_PER_DEVICE_HASH_LIST

/*
 * This is the theoretical upper limit on "NIC"s.  This must be large enough to include
 *  the dummy device, other pseudo- devices (sFlow, netFlow) and all of the real and
 *  virtual network interface cards on the -i parameter.
 *
 * Note that because the big allocators are dynamic, reducing this will not save
 * much memory.  Still, 32 is absurd for MOST people.
 *
 * But, remember - when sniffing from a multihomed interface it is necessary to add
 * all the virtual interfaces because ntop has to know all the local addresses.
 *
 * This affects static allocations:
 *     in graph.c - for reporting
 *     in hash.c - for lastPurgeTime[] in purgeIdleHosts()
 *     in plugin.c - for the flow filters structure
 *
 * This affects dynamic allocations in initialize.c - if it's too small for the -i parameter,
 *  there is a warning message in initDevices().
 *
 */
#define MAX_NUM_DEVICES                     32

/*
 * This is an IPv4 convention - it's the upper port # that is "officially assigned" (reserved)
 * for a specific service.  This controls upto what port# ntop reports in various places,
 * such as the 'TCP/UDP Service/Port Usage' section in the "Info about host" page, the
 * 'TCP/UDP Protocol Subnet Usage' section in ipProtoUsage.html, etc.
 *
 * You could certainly make this larger if you are concerned about ports over 1024, but
 * it will cost you memory.
 */
#define MAX_ASSIGNED_IP_PORTS               1024
/*
 * Work table entries[] in dumpElementHash(), reportUtils.c
 */
#define MAX_HASHDUMP_ENTRY                  (u_short)-1

/*
 * Size of the AS and VLAN hashes, created by allocateElementHash() and dumped by
 * dumpElementHash().
 */
#define MAX_ELEMENT_HASH                    4096

/*
 * Size of the array of tcp ACK ids we are waiting to see (sessions.c).
 *  Note that this is a PER SESSION value.  See handleSession().
 */
#define MAX_NUM_FIN                         4

/*
 * This MUST be a little bigger than the number of entries in the array in vendor.c
 * Ideally, it would be prime and big enough to minimize the collisions
 *  (check IPX/SAP Hash Collisions in the configuration report).
 *
 * NOTE: The hashs can be optimized - look at the note in vendor.c
 *
 *   Don't kill yourself on this - it's not a LOT of storage - unused entries cost 
 *   only 8 bytes...  These values are pretty good for the table as of 01-2003.
 *
 * Based on the data as of 01-2003:
 *      normal: size 181   2 collisions
 *                   109   4 collisions
 *      invert: size 179   0 collisions 
 *                    93   2 collisions
 */
#ifdef PARM_USE_MACHASH_INVERT
 #define MAX_IPXSAP_NAME_HASH                179
#else
 #define MAX_IPXSAP_NAME_HASH                181
#endif

/*
 * Size of the nfs entries hash in plugins/nfsPlugin.c.
 */
#define MAX_NFS_NAME_HASH                   12288

/*
 * Limit of the table used to display hosts in the pda Plugin.
 */
#define MAX_PDA_HOST_TABLE                  4096

/*
 * Limit of the table used to display hosts in the lastSeen plugin.
 */
#define MAX_LASTSEEN_TABLE_SIZE             4096

/*
 * Maximum number of entries in the User Lists.
 *  See updateHTTPVirtualHosts(), updateFileList() and updateHostUsers().
 *  Note that these are singly linked lists, so this is the only limit 
 *  on their size.
 */
#define MAX_NUM_LIST_ENTRIES                32

/*
 * This is the maximum number of entries in the contacted peers tables,
 * peersSerials[] in UsageCounter, and contactedIpPeersIndexes[] in ProcessInfo.
 * These tables maintain the host to host contact information for various reports.
 */
#define MAX_NUM_CONTACTED_PEERS             8

/*
 * This is the maximum number of 'routers' to report in the "Local Subnet Routers" section
 * (that is localRoutersList.html).  It's a local array, routerList[] built in 
 * printLocalRoutersList(). It is built from a scan of all of the contacted peers data.
 */
#define MAX_NUM_ROUTERS                     512

/*
 * This defines the number of entries in util.c of the local structure networks[][3]
 *   (i.e. the network, mask, and broadcast).
 *
 * This array is set from the NICs and -m values and used to determine if an address
 * is pseudoLocal, see __pseudoLocalAddress().
 *
 * It MUST be big enough to hold all of the addresses assigned to each interface, plus
 * any additional values set by -m.  Don't be stingy - it's 3 32bit integers per entry.
 */
#define MAX_NUM_NETWORKS                    32

/*
 * This defines the # of entries in hostsCache[] in myGlobals.
 *
 * That is used as a holding tank of purged host entries for reuse, instead of
 * doing free/malloc sets.  The current value is reported as 'Host Memory Cache Size'
 * in the configuration report.
 *
 * On a busy network with lots of hosts coming and going, this MIGHT help - check the
 * info.html report and see if the MAX is this size.
 *
 * MAX_SESSIONS_CACHE_LEN defaults to the same, but it caches sessions and could
 * be different.
 */
#define MAX_HOSTS_CACHE_LEN                 512
#define MAX_SESSIONS_CACHE_LEN              MAX_HOSTS_CACHE_LEN

/*
 * Maximum number of protocols for graphs - hostIPTrafficDistrib()
 *   Probably don't want to change this - they get pretty unreadable even this big.
 */
#define MAX_NUM_PROTOS                      64

/*
 * Used in initialize.c to limit the size of myGlobals.device[].numHosts (you will see
 *  the message, Truncated network size (device xxx) to nnnn hosts (real netmask xxx).
 *
 * If you have a few devices but large networks (e.g. a single /16) you might want to
 * increase this to track more hosts.  But watch the memory usage.
 */
#define MAX_SUBNET_HOSTS                    1024

/*
 * Used in util.c - the number of entries in the (ftp) passiveSessions
 * tracking structure
 */
#define MAX_PASSIVE_FTP_SESSION_TRACKER     384

/*
 * Sets myGlobals.maxNumLines, which is used to determine how many rows (lines)
 * appear on each page of a multiple paged report
 */
#define CONST_NUM_TABLE_ROWS_PER_PAGE       128

/*
 * Values for dynamic adjustment of idle purge time...
 *
 *   The limit of hosts to purge per cycle will be adjusted (approximately)
 *   up or down until it falls between _MINIMUM and _MAXIMUM (in seconds).
 *
 *   The adjustment is down by ADJUST_FACTOR / (ADJUST_FACTOR + 1), eg 10/11ths
 *                    or up by (ADJUST_FACTOR + 1) / ADJUST_FACTOR, eg 11/10ths
 */
#define CONST_IDLE_PURGE_MINIMUM_TARGET_TIME 0.5
#define CONST_IDLE_PURGE_MAXIMUM_TARGET_TIME 5.0
#define CONST_IDLE_PURGE_ADJUST_FACTOR       10

/*
 * Determines how often to access/release mutexes in freeHostSessions()
 *   Do it every pow(2, CONST_MUTEX_FHS_GRANULARITY) - 1
 *                                  
 *  0 >= CONST_MUTEX_FHS_GRANULARITY >= 15
 */
#define CONST_MUTEX_FHS_GRANULARITY         6 
#define CONST_MUTEX_FHS_MASK                (max(0, min(65535, (1 << CONST_MUTEX_FHS_GRANULARITY) - 1)))

/*
 * Determines how often to access/release mutexes in purgeHostPorts()
 *   Do it every pow(2, CONST_MUTEX_PHP_GRANULARITY) - 1
 *                                  
 *  0 >= CONST_MUTEX_PHP_GRANULARITY >= 15
 */
#define CONST_MUTEX_PHP_GRANULARITY         6 
#define CONST_MUTEX_PHP_MASK                (max(0, min(65535, (1 << CONST_MUTEX_PHP_GRANULARITY) - 1)))

/*
 * Size of myGlobals.transTimeHash[], used to produce the "IP Service Stats"
 * in the "Info about host" report.  If you are monitoring a busy server
 * handling lots of long running requests, you might need to up this -
 * IF coding for other longer-running services is added.  The key structure
 * is   ServiceStats in ProtocolInfo.
 */ 
#define CONST_NUM_TRANSACTION_ENTRIES       256

/*
 * Number of entries in probeList[] in netFlowPlugin.c and sflowPlugin.c
 */
#define MAX_NUM_PROBES                      16

/*
 * Number of entries in flowIgnored[] in netFlowPlugin.c
 */ 
#define MAX_NUM_IGNOREDFLOWS                32

/*
 * This is used in URL security to put an upper limit on the URL we're willing to
 * deal with - it's then used in http.c as the size of a couple of static work buffers.
 */
#define MAX_LEN_URL                         512

/*
 * Number of tcp flags we'll store for an IP Session
 */
#define MAX_NUM_STORED_FLAGS                4

/*
 * Used during initialization and the mtu and header size tables in globals-core.c,
 * if we don't know.  This is a guess based on "normal" tcp/ip links.
 */
#define CONST_UNKNOWN_MTU                   1500

/*
 * OS Fingerprint file, from ettercap (http://ettercap.sourceforge.net/)
 */
#define CONST_OSFINGERPRINT_FILE            "etter.passive.os.fp.gz"

/*
 * OS Fingerprint file, from ettercap (http://ettercap.sourceforge.net/)
 */
#define CONST_ASLIST_FILE            "AS-list.txt.gz"

/*
 * openSSL (https://) stuff
 *
 *  MAX_SSL_CONNECTIONS
 *     This is the # of SSL_connection entries in ssl[] and thus the maximum number
 *     of simultaneous SSL connections ntop can support.
 *
 *  CONST_SSL_CERTF_FILENAME
 *     This is the name of the ssl certificate file ntop used, located in the 
 *     myGlobals.configFileDirs[] list of directories.
 */
#ifdef HAVE_OPENSSL
 #define MAX_SSL_CONNECTIONS                32
 #define CONST_SSL_CERTF_FILENAME           "ntop-cert.pem"
#endif

/*
 * dumpXML.c constants...
 *     <!DOCTYPE -name- SYSTEM \"-dtd-uri-\">
 *
 *  CONST_XML_DOCTYPE_NAME
 *     Is the name used in the <!DOCTYPE> line.
 *
 *  CONST_XML_DTD_NAME
 *     Is the name of the dtd in the <!DOCTYPE> line.
 *
 *  CONST_XML_TMP_NAME
 *     Is the prefix for a unique temp name used to dump the generated xml
 *
 *  CONST_XML_VERSION
 *     Is the value used in the <ntop_dump_header ... xml_version=n ...> tag.
 *     This MUST be incremented for each major (incompatible) change in the xml formats
 */
#define CONST_XML_DOCTYPE_NAME              "ntop_dump"
#define CONST_XML_DTD_NAME                  "ntopdump.dtd"
#define CONST_XML_TMP_NAME                  "/tmp/ntopxml"
#define CONST_XML_VERSION                   "0"

/*
 * Define the parm values for xmldump and the # of characters to test
 *  (e.g. with a TEST_LEN of 3, interference and interface both work)
 */
#define CONST_XMLDUMP_TEST_LEN              3
#define CONST_XMLDUMP_INVOKE                "invoke"
#define CONST_XMLDUMP_VERSION               "version"
#define CONST_XMLDUMP_INTERFACES            "interfaces"
#define CONST_XMLDUMP_TOFILE                "tofile"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *  Static - don't change unless you REALLY, REALLY, know what you are doing.
 */

/*
 * Lengths of various static sized buffers.
 */
#define LEN_TIMEFORMAT_BUFFER               48
#define LEN_CMDLINE_BUFFER                  4096
#define LEN_FGETS_BUFFER                    512
#define LEN_DATAFORMAT_BUFFER               24
#define LEN_TIME_STAMP_BUFFER               2
#define LEN_GENERAL_WORK_BUFFER             1024
#define LEN_MEDIUM_WORK_BUFFER              64
#define LEN_SMALL_WORK_BUFFER               16

/*
 * Static buffer used for pcap error messages in initialize.c and ntop_win32.c.
 */
#define CONST_SIZE_PCAP_ERR_BUF             512

/*
 * Number of u_char in an ethernet (mac) address, ethAddress[], lastEthAddress[] and
 *    dummyEthAddress[].
 */
#define LEN_ETHERNET_ADDRESS                6
#define LEN_ETHERNET_ADDRESS_DISPLAY        sizeof("00:00:00:00:00:00")
#define LEN_ETHERNET_VENDOR                 3
#define LEN_ETHERNET_VENDOR_DISPLAY         sizeof("00:00:00")

/*
 * Maximum number of addresses in a dns packet - see handleDNSpacket()
 */
#define MAX_ADDRESSES                       35

/*
 * Maximum number of aliases in a dns packet - see handleDNSpacket()
 */
#define MAX_ALIASES                         35

/*
 * 9 messages in total -- see #define FLAG_DHCP_ _MSG below
 */
#define MAX_NUM_DHCP_MSG                    8

/*
 * Symbolic host buffer name length (hostSymIpAddress, symAddress, etc.)
 * MAX_LEN_SYM_HOST_NAME_HTML is the fully tricked out html version (emitter.c and hash.c)
 */
#define MAX_LEN_SYM_HOST_NAME               64
#define MAX_LEN_SYM_HOST_NAME_HTML          256

/*
 * Maximum length of a name in the IEEE OUI file.
 */
#define MAX_LEN_VENDOR_NAME                 64

/*
 * i18n - maximum number of languages we'll support... and permit per request...
 */
#define MAX_LANGUAGES_REQUESTED             4
#define MAX_LANGUAGES_SUPPORTED             8

/*
 * Maximum number of node types (Appletalk, IPX) to record - see struct NonIPTraffic{}
 */
#define MAX_NODE_TYPES                      8

/*
 * This is basically an IPv4 limit - the number of ports is a 16 bit integer.
 *  Constant is used in NtopInterface to define the per-host ports structure, ipPorts[]
 *  And in NtopGlobals for the lsof populated structure localPorts[]
 */
#define MAX_IP_PORT                         65534 /* IP ports range from 0 to 65535 */

/*
 * This constant defines the size of the _mtuSize and _headerSize arrays (globals-core.c)
 * It needs to be at least as large as the largest value defined in bpf.h.  Remember, your
 * version of bpf.h isn't always everyone else's version.  For the latest & greatest (?)
 * see: http://cvs.tcpdump.org/cgi-bin/cvsweb/libpcap/bpf/net/bpf.h
 *    Last sync: Sep2002, BStrauss
 */
#define MAX_DLT_ARRAY                       123

/*
 * handleAddressLists() constants
 */
#define CONST_HANDLEADDRESSLISTS_MAIN       0
#define CONST_HANDLEADDRESSLISTS_RRD        1
#define CONST_HANDLEADDRESSLISTS_NETFLOW    2

/*
 * Protocol types
 */
#define CONST_GRE_PROTOCOL_TYPE             0x2F
#define CONST_PPP_PROTOCOL_TYPE             0x880b

/*
 * Various extensions used by ntop
 */
#define CONST_RRD_EXTENSION                 ".rrd"
#define CONST_PLUGIN_EXTENSION              ".so"

/* 
 * The (internal) name of the plugin function itself.
 * courtesy of Tanner Lovelace <lovelace@opennms.org>
 */
#if defined(DARWIN) || defined(OPENBSD)
#define CONST_PLUGIN_ENTRY_FCTN_NAME        "_PluginEntryFctn"
#else
#define CONST_PLUGIN_ENTRY_FCTN_NAME        "PluginEntryFctn"
#endif

/*
 * This is the 2MSL timeout as defined in the TCP standard (RFC 761).
 *  Used in sessions.c and pbuf.c
 */
#define CONST_TWO_MSL_TIMEOUT          120      /* 2 minutes */
#define CONST_DOUBLE_TWO_MSL_TIMEOUT   (2*CONST_TWO_MSL_TIMEOUT)

/*
 * File name used in setnetent()/getnetent() to retrieve the list of networks.
 */
#define CONST_WIN32_PATH_NETWORKS           "networks"

/*
 * Maximum number of aliases in a (win32) in a net_aliases packet - see getnetent()
 */
#define MAX_WIN32_NET_ALIASES               35

/*
 * Used in crypt() for ntop's passwords.
 *     Must be a 2 char string
 */
#define CONST_CRYPT_SALT                    "99"

/*
 * What's our 'name', for tcp wrappers (/etc/hosts.allow, /etc/hosts.deny)
 */
#define CONST_DAEMONNAME                    "ntop"

/*
 *    This list is derived from RFC1945 in sec 3.2 Uniform Resource Identifiers
 *    which defines the permitted characters in a URI/URL.  Specifically, the
 *    definitions of
 *
 *    reserved       = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+"
 *    unsafe         = CTL | SP | <"> | "#" | "%" | "<" | ">"
 *
 *    DO NOT put % here - it's special cased - it's too dangerous to handle the same...
 *    We allow "/" - most browsers do
 *
 *    Courtesy of "Burton M. Strauss III" <bstrauss@acm.org>
 */
#define CONST_URL_PROHIBITED_CHARACTERS     "\001\002\003\004\005\006" \
                                            "\010\011\012\013\014\015\016" \
                                            "\020\021\022\023\024\025\026" \
                                            "\030\031\032\033\034\035\036" \
                                            " \"#&+:;<=>?@\177"

/*
 * Used in deviceSanityCheck() in util.c to set an upper limit on the length
 * of a device name.  Remember, WIN32 names are long, but not that long!
 */
#define MAX_DEVICE_NAME_LEN                 64

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *  These are just useful things, shorthand, etc.  Don't change 'em
 */

/*
 * Unix vs. Windows path separator character.
 */
#if !defined(CONST_PATH_SEP)
 #if !defined(WIN32)
  #define CONST_PATH_SEP                    '/'
 #else
  #define CONST_PATH_SEP                    '\\'
 #endif
#endif

/*
 * These are the values for networks[] in util.c.  See MAX_NUM_NETWORKS, above...
 */
#define CONST_NETWORK_ENTRY                 0
#define CONST_NETMASK_ENTRY                 1
#define CONST_BROADCAST_ENTRY               2
#define CONST_INVALIDNETMASK                -1

/*
 * Used in traceEvent()
 */
#define CONST_ALWAYSDISPLAY_TRACE_LEVEL     -1
#define CONST_FATALERROR_TRACE_LEVEL        0
#define CONST_ERROR_TRACE_LEVEL             1
#define CONST_WARNING_TRACE_LEVEL           2
#define CONST_INFO_TRACE_LEVEL              3
#define CONST_NOISY_TRACE_LEVEL             4
    /*
     * Used as both the limiting value (http.c) and (util.c) to define which
     * traceEvent level gets the file/line info reported in addition to the date/time.
     */
#define CONST_DETAIL_TRACE_LEVEL            5

#define CONST_TRACE_ALWAYSDISPLAY           CONST_ALWAYSDISPLAY_TRACE_LEVEL, __FILE__, __LINE__
#define CONST_TRACE_FATALERROR              CONST_FATALERROR_TRACE_LEVEL, __FILE__, __LINE__
#define CONST_TRACE_ERROR                   CONST_ERROR_TRACE_LEVEL, __FILE__, __LINE__
#define CONST_TRACE_WARNING                 CONST_WARNING_TRACE_LEVEL, __FILE__, __LINE__
#define CONST_TRACE_INFO                    CONST_INFO_TRACE_LEVEL, __FILE__, __LINE__
#define CONST_TRACE_NOISY                   CONST_NOISY_TRACE_LEVEL, __FILE__, __LINE__
#define CONST_TRACE_DETAIL                  CONST_DETAIL_TRACE_LEVEL, __FILE__, __LINE__


/*
 * Used in sessions to make sure we don't step on the data area.  It doesn't mean
 * anything - just has to be consistent.
 */
#define CONST_MAGIC_NUMBER                  1968 /* Magic year actually */

/*
 * Number of args + NULL in initial argv, for buildargv() in util.c - that is, if we don't 
 * have it in libc.  Taken, but for the name change, from gcc libiberty - leave it alone.
 */
#define CONST_INITIAL_MAXARGC               8

/*
 *   Define the output flag values
 */
#define CONST_REPORT_ITS_DEFAULT            "(default)   "
#define CONST_REPORT_ITS_EFFECTIVE          "   (effective)"

/*
 * Text used for the "Listening on [...]" message.  Either this value or 
 * the name of the file being read is displayed.
 */
#define CONST_PCAP_NW_INTERFACE_FILE        "pcap file"

/*
 * 224.x.y.z
 */
#define CONST_MULTICAST_MASK                0xE0000000

/*
 * Header lengths were we can't pull it from the packet. Look in processPacket()
 * for the case DLT_XXXX: lines.
 */
#define CONST_NULL_HDRLEN                   4
#define CONST_PPP_HDRLEN                    4

/*
 * Token Ring control values
 */
#define CONST_TRMTU                      2000   /* 2000 bytes            */
#define CONST_TR_RII                     0x80
#define CONST_TR_RCF_DIR_BIT             0x80
#define CONST_TR_RCF_LEN_MASK            0x1f00
#define CONST_TR_RCF_BROADCAST           0x8000 /* all-routes broadcast   */
#define CONST_TR_RCF_LIMITED_BROADCAST   0xC000 /* single-route broadcast */
#define CONST_TR_RCF_FRAME2K             0x20
#define CONST_TR_RCF_BROADCAST_MASK      0xC000

/*
 * FDDI Frame Control bits
 */
#define	CONST_FDDIFC_C		0x80		/* Class bit */
#define	CONST_FDDIFC_L		0x40		/* Address length bit */
#define	CONST_FDDIFC_F		0x30		/* Frame format bits */
#define	CONST_FDDIFC_Z		0x0f		/* Control bits */

/*
 * FDDI Frame Control values. (48-bit addressing only).
 */
#define	CONST_FDDIFC_VOID	0x40		/* Void frame */
#define	CONST_FDDIFC_NRT	0x80		/* Nonrestricted token */
#define	CONST_FDDIFC_RT		0xc0		/* Restricted token */
#define	CONST_FDDIFC_SMT_INFO	0x41		/* SMT Info */
#define	CONST_FDDIFC_SMT_NSA	0x4F		/* SMT Next station adrs */
#define	CONST_FDDIFC_MAC_BEACON	0xc2		/* MAC Beacon frame */
#define	CONST_FDDIFC_MAC_CLAIM	0xc3		/* MAC Claim frame */
#define	CONST_FDDIFC_CONST_LLC_ASYNC 0x50	/* Async. LLC frame */
#define	CONST_FDDIFC_CONST_LLC_SYNC 0xd0	/* Sync. LLC frame */
#define	CONST_FDDIFC_IMP_ASYNC	0x60		/* Implementor Async. */
#define	CONST_FDDIFC_IMP_SYNC	0xe0		/* Implementor Synch. */
#define CONST_FDDIFC_SMT	0x40		/* SMT frame */
#define CONST_FDDIFC_MAC	0xc0		/* MAC frame */
#define	CONST_FDDIFC_CLFF	0xF0		/* Class/Length/Format bits */
#define	CONST_FDDIFC_ZZZZ	0x0F		/* Control bits */

/*
 * SNAP/LLC
 */
#define CONST_LLC_GSAP        1
#define CONST_LLC_S_FMT       1
#define CONST_LLC_U_POLL      0x10
#define CONST_LLC_IS_POLL     0x0001
#define CONST_LLC_XID_FI      0x81
#define CONST_LLC_UI          0x03
#define CONST_LLC_UA          0x63
#define CONST_LLC_DISC        0x43
#define CONST_LLC_DM          0x0f
#define CONST_LLC_SABME       0x6f
#define CONST_LLC_TEST        0xe3
#define CONST_LLC_XID         0xaf
#define CONST_LLC_FRMR        0x87
#define CONST_LLC_RR          0x0100
#define CONST_LLC_RNR         0x0500
#define CONST_LLC_REJ         0x0900

/*
 * NetFlow
 */
#define CONST_FLOW_VERSION_5		    5
#define CONST_V5FLOWS_PER_PAK		    30

#define CONST_FLOW_VERSION_7		    7
#define CONST_V7FLOWS_PER_PAK		    28

/* This is 'ftp-data' from /etc/services */
#define CONST_FTPDATA                       20

/*
 * sFlow header constants (what version of pcap are we claiming to be)...
 *       from libpcap-0.5: pcap.h
 */
#define CONST_SFLOW_TCPDUMP_MAGIC 0xa1b2c3d4
#define CONST_SFLOW_PCAP_VERSION_MAJOR 2
#define CONST_SFLOW_PCAP_VERSION_MINOR 4

/*
 * intop
 */
#define MAX_NUM_PROTOS_SCREENS              5
#define CONST_DUMMY_IDX                     999
#define MAX_TRAFFIC_TABLE                   4096

#define FLAG_INTERFACE_DOWN      0   /* not yet enabled via LBNL */
#define FLAG_INTERFACE_READY     1   /* ready for packet sniffing */
#define FLAG_INTERFACE_ENABLED   2   /* packet capturing currently active */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* F L A G  and  B I T F L A G  items                                              */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Flags for myGlobals.capturePackets
 */ 
#define FLAG_NTOPSTATE_RUN                  0
#define FLAG_NTOPSTATE_STOPCAP              1
#define FLAG_NTOPSTATE_TERM                 2

/*
 * When myGlobals.useSyslog is set to this, turns off the logging
 */
#define FLAG_SYSLOG_NONE                    -1




/*
 * Define for address resolution missing on Win32
 */
#ifndef NETDB_SUCCESS
#define NETDB_SUCCESS                       0
#endif

/*
 * Flags related to html and http types
 */

/*
 * Code below courtesy of Roberto F. De Luca <deluca@tandar.cnea.gov.ar>
 */
#define FLAG_HTTP_TYPE_NONE                 0
#define FLAG_HTTP_TYPE_HTML                 1
#define FLAG_HTTP_TYPE_GIF                  2
#define FLAG_HTTP_TYPE_JPEG                 3
#define FLAG_HTTP_TYPE_PNG                  4
#define FLAG_HTTP_TYPE_CSS                  5
#define FLAG_HTTP_TYPE_TEXT                 6
#define FLAG_HTTP_TYPE_ICO                  7
#define FLAG_HTTP_TYPE_JS                   8
#define FLAG_HTTP_TYPE_XML                  9
#define FLAG_HTTP_TYPE_P3P                  10
 
#define BITFLAG_HTTP_IS_CACHEABLE           (1<<0)
#define BITFLAG_HTTP_NO_CACHE_CONTROL       (1<<1)
#define BITFLAG_HTTP_KEEP_OPEN              (1<<2)
#define BITFLAG_HTTP_NEED_AUTHENTICATION    (1<<3)
#define BITFLAG_HTTP_MORE_FIELDS            (1<<4)

#define BITFLAG_HTML_NO_REFRESH             (1<<0)
#define BITFLAG_HTML_NO_STYLESHEET          (1<<1)
#define BITFLAG_HTML_NO_BODY                (1<<2)
#define BITFLAG_HTML_NO_HEADING             (1<<3)

#define FLAG_HTTP_INVALID_REQUEST           -2
#define FLAG_HTTP_INVALID_METHOD            -3
#define FLAG_HTTP_INVALID_VERSION           -4
#define FLAG_HTTP_REQUEST_TIMEOUT           -5
#define FLAG_HTTP_FORBIDDEN_PAGE            -6
#define FLAG_HTTP_INVALID_PAGE              -7

/*
 * Flags for fileFlags in typedef struct fileList {}
 */
#define FLAG_THE_DOMAIN_HAS_BEEN_COMPUTED   1
#define FLAG_PRIVATE_IP_ADDRESS             2 /* the IP address is private (192.168..) */
#define FLAG_SUBNET_LOCALHOST               3 /* the host is either local or remote */
#define FLAG_BROADCAST_HOST                 4 /* a broadcast address */
#define FLAG_MULTICAST_HOST                 5 /* a multicast address */
#define FLAG_GATEWAY_HOST                   6 /* used as a gateway */
#define FLAG_NAME_SERVER_HOST               7 /* used as a name server (e.g. DNS) */
#define FLAG_SUBNET_PSEUDO_LOCALHOST        8 /* local (with respect to the specified subnets) */

/* Host Type */
#define FLAG_HOST_TYPE_SERVER               9
#define FLAG_HOST_TYPE_WORKSTATION          10
#define FLAG_HOST_TYPE_PRINTER              11

/* Host provided services */
#define FLAG_HOST_TYPE_SVC_SMTP             12
#define FLAG_HOST_TYPE_SVC_POP              13
#define FLAG_HOST_TYPE_SVC_IMAP             14
#define FLAG_HOST_TYPE_SVC_DIRECTORY        15 /* e.g.IMAP, Novell Directory server */
#define FLAG_HOST_TYPE_SVC_FTP              16
#define FLAG_HOST_TYPE_SVC_HTTP             17
#define FLAG_HOST_TYPE_SVC_WINS             18
#define FLAG_HOST_TYPE_SVC_BRIDGE           19

#define FLAG_HOST_TYPE_SVC_DHCP_CLIENT      23
#define FLAG_HOST_TYPE_SVC_DHCP_SERVER      24
#define FLAG_HOST_TYPE_MASTER_BROWSER       25
#define FLAG_HOST_TYPE_MULTIHOMED           26

/* Flags for possible error codes */
#define FLAG_HOST_WRONG_NETMASK             65
#define FLAG_HOST_DUPLICATED_MAC            66

/*
 * ->userFlags settings
 * Flags for userFlags in typedef struct userList {}
 */
#define BITFLAG_POP_USER                    1
#define BITFLAG_IMAP_USER                   2
#define BITFLAG_SMTP_USER                   3
#define BITFLAG_P2P_USER                    4
#define BITFLAG_FTP_USER                    5
#define BITFLAG_MESSENGER_USER              6

#define BITFLAG_P2P_UPLOAD_MODE             1
#define BITFLAG_P2P_DOWNLOAD_MODE           2

/*
 * Some defines for the isP2P field of "struct ipSession"
 *     Over time, as one p2p system waxes or wanes, this list 
 *     will change. It is suggested that you DO NOT reuse old #s
 */
#define FLAG_P2P_GNUTELLA                   1
#define FLAG_P2P_KAZAA                      2
#define FLAG_P2P_WINMX                      3
#define FLAG_P2P_DIRECTCONNECT              4

#define FLAG_DHCP_UNKNOWN_MSG               0
#define FLAG_DHCP_DISCOVER_MSG              1
#define FLAG_DHCP_OFFER_MSG                 2
#define FLAG_DHCP_REQUEST_MSG               3
#define FLAG_DHCP_DECLINE_MSG               4
#define FLAG_DHCP_ACK_MSG                   5
#define FLAG_DHCP_NACK_MSG                  6
#define FLAG_DHCP_RELEASE_MSG               7
#define FLAG_DHCP_INFORM_MSG                8

/*
 * These are flags used to indicate that the sort for various reports should
 * be of the pseudo-column HOST or DOMAIN.
 */
#define FLAG_HOST_DUMMY_IDX                99
#define FLAG_HOST_DUMMY_IDX_STR            "99"

#define FLAG_DOMAIN_DUMMY_IDX              98
#define FLAG_DOMAIN_DUMMY_IDX_STR          "98"

/*
 *  Flag to makeHostLink() as to which type of link to create
 */
#define FLAG_HOSTLINK_HTML_FORMAT           1
#define FLAG_HOSTLINK_TEXT_FORMAT           2

/*
 * Used in http.c and util.c to flag that a socket is closed and should not be
 * reclosed - term_ssl_connection() nor closesocket().
 */
#define FLAG_DUMMY_SOCKET                  -999

/*
 * settings for myGlobals.device[].exportNetFlow
 */
#define FLAG_NETFLOW_EXPORT_UNKNOWN         0
#define FLAG_NETFLOW_EXPORT_DISABLED        1
#define FLAG_NETFLOW_EXPORT_ENABLED         2

/*
 * SSLWATCHDOG stuff
 */
#ifdef MAKE_WITH_SSLWATCHDOG

 #define FLAG_SSLWATCHDOG_PARENT            0
 #define FLAG_SSLWATCHDOG_CHILD             1
 #define FLAG_SSLWATCHDOG_BOTH              -1

 #define FLAG_SSLWATCHDOG_UNINIT            0  /* No child */
 #define FLAG_SSLWATCHDOG_WAITINGREQUEST    1  /* waiting for request */
 #define FLAG_SSLWATCHDOG_HTTPREQUEST       2  /* http request received */
 #define FLAG_SSLWATCHDOG_HTTPCOMPLETE      3  /* Parent done w/ http */
 #define FLAG_SSLWATCHDOG_FINISHED          9

 #define FLAG_SSLWATCHDOG_RETURN_LOCKED     1
 #define FLAG_SSLWATCHDOG_ENTER_LOCKED      2
#endif

/*
 * emitter.c language flags
 */
#define FLAG_PERL_LANGUAGE                  1
#define FLAG_PHP_LANGUAGE                   2
#define FLAG_XML_LANGUAGE                   3
#define FLAG_PYTHON_LANGUAGE                4
#define FLAG_NO_LANGUAGE                    5
#define MAX_FLAG_LANGUGE                    FLAG_NO_LANGUAGE

#define FLAG_NO_PEER                        UINT_MAX

/*
 * Flags for flowDirection in handleSession()
 */
#define FLAG_CLIENT_TO_SERVER               1
#define FLAG_CLIENT_FROM_SERVER             2
#define FLAG_SERVER_TO_CLIENT               3
#define FLAG_SERVER_FROM_CLIENT             4

/*
 * Flags for initiator in typedef struct ipGlobalSession {}
 */
#define FLAG_CLIENT_ROLE                    1
#define FLAG_SERVER_ROLE                    2

/*
 * Flags for printIpAccounting()
 */
#define FLAG_REMOTE_TO_LOCAL_ACCOUNTING     1
#define FLAG_LOCAL_TO_REMOTE_ACCOUNTING     2
#define FLAG_LOCAL_TO_LOCAL_ACCOUNTING      3
#define FLAG_REMOTE_TO_REMOTE_ACCOUNTING    4

/*
 * Flags for rrd plugin settings...
 */
#define FLAG_RRD_DETAIL_LOW                 0
#define FLAG_RRD_DETAIL_MEDIUM              1
#define FLAG_RRD_DETAIL_HIGH                2
#define CONST_RRD_DETIL_DEFAULT             FLAG_RRD_DETAIL_HIGH

#define FLAG_RRD_ACTION_NONE                0
#define FLAG_RRD_ACTION_GRAPH               1
#define FLAG_RRD_ACTION_LIST                2

/* **************************** */

/*
 * TCP Session State Transition
 *
 * Flags for sessionState in typedef struct ipSession {}
 */
#define FLAG_STATE_SYN                      0
#define FLAG_FLAG_STATE_SYN_ACK             1
#define FLAG_STATE_ACK                      2
#define FLAG_STATE_ACTIVE                   FLAG_STATE_ACK
#define FLAG_STATE_BEGIN                    FLAG_STATE_ACTIVE
#define FLAG_STATE_FIN1_ACK0                3
#define FLAG_STATE_FIN1_ACK1                4
#define FLAG_STATE_FIN2_ACK0                5
#define FLAG_STATE_FIN2_ACK1                6
#define FLAG_STATE_FIN2_ACK2                7
#define FLAG_STATE_TIMEOUT                  8
#define FLAG_STATE_END                      9

/*
 * Flags for fragmentOrder typedef struct ipFragment {}
 */
#define FLAG_UNKNOWN_FRAGMENT_ORDER         0
#define FLAG_INCREASING_FRAGMENT_ORDER      1
#define FLAG_DECREASING_FRAGMENT_ORDER      2

/*
 * PACKET_DEBUG timestamp() presentation formats
 */
#define FLAG_TIMESTAMP_FMT_DELTA           1   /* the time since receiving the previous packet */
#define FLAG_TIMESTAMP_FMT_ABS             2   /* the current time */
#define FLAG_TIMESTAMP_FMT_RELATIVE        3   /* the time relative to the first packet rcvd */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* H T M L  items                                                                  */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * File used to indicate to the user that an error occured in gdc_out.
 */
#define HTML_GDC_OUT_PIE_ERROR_FILE        "pie-error.png"

/*
 * External URLs...
 */
#define HTML_LSOF_URL                       "http://freshmeat.net/projects/lsof/"
#define CONST_HTML_LSOF_URL_ALT             "lsof home page at freshmeat.net"

#define HTML_OPENSSL_URL                    "http://www.openssl.org/"
#define CONST_HTML_OPENSSL_URL_ALT          "OpenSSL home page"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* H A V E  (derived) items                                                        */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* D E F A U L T  items                                                            */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * default file and directories
 */
#define DEFAULT_NTOP_CONFFILE               "ntop.conf"
#define DEFAULT_NTOP_PIDFILE                "ntop.pid"
#define DEFAULT_NTOP_LOGFILE                "ntop.log"
#define DEFAULT_NTOP_ACCESSFILE             "ntop.last"
#define DEFAULT_NTOP_PID_DIRECTORY          "/var/run"

/*
 * default configuration parameters  -- the comment gives the (short getopt) name
 *                                      which overrides this value.
 */
#define DEFAULT_NTOP_ACCESS_LOG_PATH        NULL      /* -a */
#define DEFAULT_NTOP_PACKET_DECODING        1         /* -b */
                                                          /* access log disabled by default */
#define DEFAULT_NTOP_STICKY_HOSTS           0         /* -c */
#define DEFAULT_NTOP_DAEMON_MODE            0         /* -d */

#define DEFAULT_NTOP_TRAFFICDUMP_FILENAME   NULL      /* -f */
#define DEFAULT_NTOP_TRACK_ONLY_LOCAL       0         /* -g */
#define DEFAULT_NTOP_DEVICES                NULL      /* -i */
#define DEFAULT_NTOP_BORDER_SNIFFER_MODE    0         /* -j */
#define DEFAULT_NTOP_FILTER_IN_FRAME        0         /* -k */
#define DEFAULT_NTOP_PCAP_LOG_FILENAME      NULL      /* -l */
#define DEFAULT_NTOP_LOCAL_SUBNETS          NULL      /* -m */
#define DEFAULT_NTOP_NUMERIC_IP_ADDRESSES   0         /* -n */
#define DEFAULT_NTOP_DONT_TRUST_MAC_ADDR    0         /* -o */
#define DEFAULT_NTOP_SUSPICIOUS_PKT_DUMP    0         /* -q */
#define DEFAULT_NTOP_AUTOREFRESH_INTERVAL   120       /* -r */

#define DEFAULT_NTOP_DISABLE_PROMISCUOUS    0         /* -s */

#define DEFAULT_NTOP_WEB_ADDR               NULL      /* -w */ /* e.g. all interfaces & addresses */
#define DEFAULT_NTOP_WEB_PORT               3000

#define DEFAULT_NTOP_ENABLE_SESSIONHANDLE   1         /* -z */

#define DEFAULT_NTOP_FILTER_EXPRESSION      NULL      /* -B */

#define DEFAULT_NTOP_DOMAIN_NAME            ""        /* -D */
                                   /* Note: don't use null, as this isn't a char*, its a char[] */
#define DEFAULT_NTOP_EXTERNAL_TOOLS_ENABLE  0         /* -E */
#define DEFAULT_NTOP_FLOW_SPECS             NULL      /* -F */

#define DEFAULT_NTOP_DEBUG_MODE             0         /* -K */

#define DEFAULT_NTOP_DEBUG                  0              /* that means debug disabled */
#define DEFAULT_NTOP_SYSLOG                 FLAG_SYSLOG_NONE /* -L */
#define DEFAULT_NTOP_MERGE_INTERFACES       1        /* -M */

/* -O and -P are special, see globals-core.h */

#define DEFAULT_NTOP_PERSISTENT_STORAGE     0        /* -S */

#define DEFAULT_NTOP_MAPPER_URL             NULL     /* -U */

#define DEFAULT_NTOP_SSL_ADDR               NULL     /* -W */ /* e.g. all interfaces & addresses */
#define DEFAULT_NTOP_SSL_PORT               0                 /* e.g. inactive */

/*
 * How often should we update rrd statistics?  Overridden in rrd plugin
 */
#define DEFAULT_RRD_INTERVAL                300  /* seconds - rrd counter (default) interval */
#define DEFAULT_RRD_HOURS                   72   /* hours of interval by interval data (default) */
#define DEFAULT_RRD_DAYS                    90   /* days of hour by hour data (default) */
#define DEFAULT_RRD_MONTHS                  36   /* months of day by day data (default) */

/*
 * What should we set tracing to unless we have a parameter?
 */
#define DEFAULT_TRACE_LEVEL                 3

/*
 * Bytes to save out of each packet - 
 *    remember, if we're decoding packets, 68 (the default) is not enough 
 *    for DNS packets.
 */
#define DEFAULT_SNAPLEN                     384

/* 
 * emitter.c default language is
 */
#define DEFAULT_FLAG_LANGUAGE               FLAG_NO_LANGUAGE

/*
 * Default log facility value, if not specified otherwise
 */
#if defined(MAKE_WITH_SYSLOG) && !defined(DEFAULT_SYSLOG_FACILITY)
 #define DEFAULT_SYSLOG_FACILITY LOG_DAEMON
#endif

/*
 * What is the default maximum number of hosts to purge (per device) per cycle?
 * This value can be dynamically adjusted, look for myGlobals.maximumHostsToPurgePerCycle
 */
#define DEFAULT_MAXIMUM_HOSTS_PURGE_PER_CYCLE 512

/*
 * TCP Wrapper defaults
 */
#ifdef HAVE_LIBWRAP
 #ifdef MAKE_WITH_SYSLOG
  #define DEFAULT_TCPWRAP_ALLOW             LOG_AUTHPRIV|LOG_INFO
  #define DEFAULT_TCPWRAP_DENY              LOG_AUTHPRIV|LOG_WARNING
 #else
  #define DEFAULT_TCPWRAP_ALLOW             0
  #define DEFAULT_TCPWRAP_DENY              0
 #endif
#endif

/*
 * Default port to use for netflow.
 */
#define DEFAULT_NETFLOW_PORT_STR            "2055"

/* 
 * Default port to use for sflow.
 */
#define DEFAULT_SFLOW_COLLECTOR_PORT_STR    "6343"
#define DEFAULT_SFLOW_COLLECTOR_PORT        atoi(DEFAULT_SFLOW_COLLECTOR_PORT_STR)

/*
 *  Sampling rate - sflow samples every n-th packet
 */
#define DEFAULT_SFLOW_SAMPLING_RATE  "400"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* MISSING items                                                                   */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*
 * These sets of ifndef ... define ... endifs
 *   are provided to define things that should already be in defined in the various
 *   header files.
 *
 *   However, there is a chance - on some systems - for these not to be defined.
 *
 *   So we provide the definitions here, usually swiped from the header files which 
 *   exist on Linux or Solaris or Darwin.
 */
#if !defined(HAVE_ETHERTYPE_H)
 #ifndef ETHERTYPE_IP
  #define ETHERTYPE_IP        0x0800
 #endif
 #ifndef ETHERTYPE_NS
  #define ETHERTYPE_NS        0x0600
 #endif
 #ifndef ETHERTYPE_SPRITE
  #define ETHERTYPE_SPRITE    0x0500
 #endif
 #ifndef ETHERTYPE_TRAIL
  #define ETHERTYPE_TRAIL     0x1000
 #endif
 #ifndef ETHERTYPE_MOPDL
  #define ETHERTYPE_MOPDL     0x6001
 #endif
 #ifndef ETHERTYPE_MOPRC
  #define ETHERTYPE_MOPRC     0x6002
 #endif
 #ifndef ETHERTYPE_DN
  #define ETHERTYPE_DN        0x6003
 #endif
 #ifndef ETHERTYPE_ARP
  #define ETHERTYPE_ARP       0x0806
 #endif
 #ifndef ETHERTYPE_LAT
  #define ETHERTYPE_LAT       0x6004
 #endif
 #ifndef ETHERTYPE_SCA
  #define ETHERTYPE_SCA       0x6007
 #endif
 #ifndef ETHERTYPE_REVARP
  #define ETHERTYPE_REVARP    0x8035
 #endif
 #ifndef ETHERTYPE_LANBRIDGE
  #define ETHERTYPE_LANBRIDGE 0x8038
 #endif
 #ifndef ETHERTYPE_DECDNS
  #define ETHERTYPE_DECDNS    0x803c
 #endif
 #ifndef ETHERTYPE_DECDTS
  #define ETHERTYPE_DECDTS    0x803e
 #endif
 #ifndef ETHERTYPE_VEXP
  #define ETHERTYPE_VEXP      0x805b
 #endif
 #ifndef ETHERTYPE_VPROD
  #define ETHERTYPE_VPROD     0x805c
 #endif
 #ifndef ETHERTYPE_ATALK
  #define ETHERTYPE_ATALK     0x809b
 #endif
 #ifndef ETHERTYPE_AARP
  #define ETHERTYPE_AARP      0x80f3
 #endif
 #ifndef ETHERTYPE_LOOPBACK
  #define ETHERTYPE_LOOPBACK  0x9000
 #endif
#endif /* HAVE_ETHERTYPE_H */

/*
 * The #ifdef below are needed for some BSD systems
 * Courtesy of Kimmo Suominen <kim@tac.nyc.ny.us>
 */
#ifndef ETHERTYPE_DN
 #define ETHERTYPE_DN         0x6003
#endif

#ifndef ETHERTYPE_ATALK
 #define ETHERTYPE_ATALK      0x809b
#endif

/*
 * On some OSes (e.g. Linux without patches),
 *  these ETHERTYPE_ constants aren't defined in <net/ethernet.h>
 */
#ifndef ETHERTYPE_IPv6
 #define ETHERTYPE_IPv6       0x86DD
#endif

#ifndef ETHERTYPE_802_1Q
 #define ETHERTYPE_802_1Q     0x8100
#endif

#ifndef ETHERMTU
 #define ETHERMTU             1500
#endif

/* ******************************
   NOTE: Most of the icmp code below has been borrowed from tcpdump.
   ****************************** */

/* rfc1700 */
#ifndef ICMP_UNREACH_NET_UNKNOWN
 #define ICMP_UNREACH_NET_UNKNOWN	6	/* destination net unknown */
#endif

#ifndef ICMP_UNREACH_HOST_UNKNOWN
 #define ICMP_UNREACH_HOST_UNKNOWN	7	/* destination host unknown */
#endif

#ifndef ICMP_UNREACH_ISOLATED
 #define ICMP_UNREACH_ISOLATED		8	/* source host isolated */
#endif

#ifndef ICMP_UNREACH_NET_PROHIB
 #define ICMP_UNREACH_NET_PROHIB	9	/* admin prohibited net */
#endif

#ifndef ICMP_UNREACH_HOST_PROHIB
 #define ICMP_UNREACH_HOST_PROHIB	10	/* admin prohibited host */
#endif

#ifndef ICMP_UNREACH_TOSNET
 #define ICMP_UNREACH_TOSNET		11	/* tos prohibited net */
#endif

#ifndef ICMP_UNREACH_TOSHOST
 #define ICMP_UNREACH_TOSHOST		12	/* tos prohibited host */
#endif

/* rfc1716 */
#ifndef ICMP_UNREACH_FILTER_PROHIB
 #define ICMP_UNREACH_FILTER_PROHIB	13	/* admin prohibited filter */
#endif

#ifndef ICMP_UNREACH_HOST_PRECEDENCE
 #define ICMP_UNREACH_HOST_PRECEDENCE	14	/* host precedence violation */
#endif

#ifndef ICMP_UNREACH_PRECEDENCE_CUTOFF
 #define ICMP_UNREACH_PRECEDENCE_CUTOFF	15	/* precedence cutoff */
#endif

/* rfc1256 */
#ifndef ICMP_ROUTERADVERT
 #define ICMP_ROUTERADVERT		9	/* router advertisement */
#endif

#ifndef ICMP_ROUTERSOLICIT
 #define ICMP_ROUTERSOLICIT		10	/* router solicitation */
#endif

#ifndef ICMP_INFO_REQUEST
 #define ICMP_INFO_REQUEST              15      /* Information Request          */
#endif

#ifndef ICMP_DEST_UNREACHABLE
 #define ICMP_DEST_UNREACHABLE		3       /* Destination Unreachable */
#endif

#ifndef ICMP_INFO_REPLY
 #define ICMP_INFO_REPLY                16      /* Information Reply            */
#endif

#ifndef ICMP_SOURCE_QUENCH
 #define ICMP_SOURCE_QUENCH             4      /* Source Quench: packet lost, slow down */
#endif

#ifndef ICMP_TIMESTAMP
 #define ICMP_TIMESTAMP                 13      /* Timestamp Request            */
#endif

#ifndef ICMP_TIMESTAMPREPLY
 #define ICMP_TIMESTAMPREPLY            14      /* Timestamp Reply            */
#endif

#ifndef ICMP_MAXTYPE
 #define ICMP_MAXTYPE                   18
#endif

/* ******************************* */

/*
 * These should be in <net/bpf.h>, but aren't always...
 */
#ifndef DLT_RAW
 #define DLT_RAW	12	/* raw IP */
#endif

#ifndef DLT_SLIP_BSDOS
 #define DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#endif

#ifndef DLT_PPP_BSDOS
 #define DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */
#endif

#ifndef DLT_ANY
#define DLT_ANY	        113	/* Linux 'any' device */
#endif

/* ******************************** */

/* PPPoE patch courtesy of Stefano Picerno <stefanopp@libero.it> */
#ifdef LINUX
 #ifndef SLL_HDR_LEN
  #define SLL_HDR_LEN                       16
 #endif
#endif

/* ******************************* */

/*
 * Should be in <netinet/in.h> or similar
 */
#ifndef INADDR_NONE
 #define INADDR_NONE 0xffffffff
#endif

/* ******************************* */

/*
 * Should be in <syslog.h> or <sys/syslog.h>
 */
#if defined(MAKE_WITH_SYSLOG) && !defined(LOG_AUTHPRIV)
 #define LOG_AUTHPRIV LOG_AUTH
#endif

/* ******************************* */

/*
 *  Defined in (Linux) <arpa/nameser_compat.h> which is included from
 *                     <arpa/nameser.h>
 *    If - for whatever reason - they're not found... add them, based on the Linux definitions.
 */
#ifdef MAKE_NTOP_PACKETSZ_DECLARATIONS

/*
 * Define constants based on RFC 883
 */
 #define PACKETSZ	512		/* maximum packet size */
 #define MAXDNAME	256		/* maximum domain name */
 #define MAXCDNAME	255		/* maximum compressed domain name */
 #define MAXLABEL	63		/* maximum length of domain label */
 #define HFIXEDSZ	12		/* #/bytes of fixed data in header */
 #define QFIXEDSZ	4		/* #/bytes of fixed data in query */
 #define RRFIXEDSZ	10		/* #/bytes of fixed data in r record */
 #define INT32SZ	4		/* for systems without 32-bit ints */
 #define INT16SZ	2		/* for systems without 16-bit ints */
 #define INADDRSZ	4		/* for sizeof(struct inaddr) != 4 */

/*
 * Type values for resources and queries
 */
 #define T_A		1		/* host address */
 #define T_NS		2		/* authoritative server */
 #define T_MD		3		/* mail destination */
 #define T_MF		4		/* mail forwarder */
 #define T_CNAME	5		/* canonical name */
 #define T_SOA		6		/* start of authority zone */
 #define T_MB		7		/* mailbox domain name */
 #define T_MG		8		/* mail group member */
 #define T_MR		9		/* mail rename name */
 #define T_NULL		10		/* null resource record */
 #define T_WKS		11		/* well known service */
 #define T_PTR		12		/* domain name pointer */
 #define T_HINFO	13		/* host information */
 #define T_MINFO	14		/* mailbox information */
 #define T_MX		15		/* mail routing information */
 #define T_TXT		16		/* text strings */
 #define T_RP		17		/* responsible person */
 #define T_AFSDB	18		/* AFS cell database */
 #define T_X25		19		/* X_25 calling address */

/*
 * Values for class field
 */

#define C_IN            1               /* the arpa internet */
#define C_CHAOS         3               /* for chaos net (MIT) */
#define C_HS            4               /* for Hesiod name server (MIT) (XXX) */
        /* Query class values which do not appear in resource records */
#define C_ANY           255             /* wildcard match */

#endif /* MAKE_NTOP_PACKETSZ_DECLARATIONS */

#ifndef INT16SZ
 #define HFIXEDSZ      12              /* #/bytes of fixed data in header */
 #define INT32SZ       4               /* for systems without 32-bit ints */
 #define INT16SZ       2               /* for systems without 16-bit ints */
 #define INADDRSZ      4               /* IPv4 T_A */
 #define IN6ADDRSZ     16              /* IPv6 T_AAAA */
#endif /* INT16SZ */

#ifndef NS_INT16SZ
 #define NS_INT16SZ                         sizeof(u_int16_t)  /* #/bytes of data in a u_int16_t */
#endif

#ifndef NS_CMPRSFLGS
 #define NS_CMPRSFLGS                       0xc0
#endif

#ifndef NS_MAXCDNAME
 #define NS_MAXCDNAME                       255
#endif

/* End the <arpa/nameser_compat.h> stuff */

/* ******************************* */

/*
 * This should be defined from something included by <sys/param.h>
 */
/* Stefano Suin <stefano@ntop.org> */
#ifndef MAXHOSTNAMELEN
 #define MAXHOSTNAMELEN  256
#endif

/* ******************************************* */

/*
 * The definitions below have been copied
 * from llc.h that's part of tcpdump
 *
 */

#ifndef LLCSAP_NULL
 #define LLCSAP_NULL		0x00
#endif

#ifndef LLCSAP_GLOBAL
 #define LLCSAP_GLOBAL		0xff
#endif

#ifndef LLCSAP_8021B
 #define LLCSAP_8021B_I		0x02
#endif

#ifndef LLCSAP_8021B
 #define LLCSAP_8021B_G		0x03
#endif

#ifndef LLCSAP_IP
 #define LLCSAP_IP		0x06
#endif

#ifndef LLCSAP_PROWAYNM
 #define LLCSAP_PROWAYNM		0x0e
#endif

#ifndef LLCSAP_8021D
 #define LLCSAP_8021D		0x42
#endif

#ifndef LLCSAP_RS511
 #define LLCSAP_RS511		0x4e
#endif

#ifndef LLCSAP_ISO8208
 #define LLCSAP_ISO8208		0x7e
#endif

#ifndef LLCSAP_PROWAY
 #define LLCSAP_PROWAY		0x8e
#endif

#ifndef LLCSAP_SNAP
 #define LLCSAP_SNAP		0xaa
#endif

#ifndef LLCSAP_ISONS
 #define LLCSAP_ISONS		0xfe
#endif

#ifndef LLCSAP_NETBIOS
 #define LLCSAP_NETBIOS		0xf0
#endif

/* Open Shortest Path */
#ifndef IPPROTO_OSPF
 #define IPPROTO_OSPF                       89
#endif

/* Internet Group Management Protocol */
#ifndef IPPROTO_IGMP
 #define IPPROTO_IGMP                       2
#endif

/* ******************************* */

/*
 * This should be defined from <stdlib.h>, which includes <bits/waitflags.h>
 */
#ifndef WNOHANG
#define WNOHANG                             1
#endif

/* ******************************** */

/*
 * This is POSIX, but might not be set - see <dirent.h>
 */
#ifndef NAME_MAX
 #define NAME_MAX                           255
#endif

/* ******************************** */

#ifndef FALSE
 #define FALSE                              0
#endif

#ifndef TRUE
 #define TRUE                               1
#endif

/* ******************************** */

#ifndef HAVE_GETOPT_H
 #define no_argument                        0
 #define required_argument                  1
 #define optional_argument                  2
#endif /* HAVE_GETOPT_H */

/*
 * Inappropriate message buffer length
 *   (In Linux this is in <asm/errno.h> which is ultimately included from <errno.h>)
 */
#ifndef EMSGSIZE
 #define EMSGSIZE                           97
#endif

/*
  Courtesy of http://ettercap.sourceforge.net/
*/
#define TCPOPT_EOL              0
#define TCPOPT_NOP              1
#define TCPOPT_MAXSEG           2
#define TCPOPT_WSCALE           3
#define TCPOPT_SACKOK           4
#define TCPOPT_TIMESTAMP        8

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Derived constants and values                                                    */
/*           these encapsulate complex definitions for simplicity                  */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifdef CFG_MULTITHREADED
 #if defined(HAVE_OPENSSL)
  #define THREAD_MODE "MT (SSL)"
 #else
  #define THREAD_MODE "MT"
 #endif

#else /* ! CFG_MULTITHREADED */

 #if defined(HAVE_OPENSSL)
  #define THREAD_MODE "ST (SSL)"
 #else
  #define THREAD_MODE "ST"
 #endif
#endif /* CFG_MULTITHREADED */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Other, OS specific stuff                                                        */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if defined(HAVE_NETDB_H) && defined(HPUX) && !defined(NETDB_SUCCESS)
 /* Handle HP-UX 10.20 and 11's retarded netdb.h */
 #define NETDB_SUCCESS h_NETDB_SUCCESS
#endif

/*
 * On FreeBSD gethostbyaddr() sometimes loops and uses all the available memory.
 * Hence this patch is needed.
 *
 *  BSD seems to have fixed the problem, at least for 4.6 and 4.7 ...
 */
#ifdef FREEBSD
 /* #define PARM_USE_HOST */
#endif

/*
 * On some Linux versions gethostbyaddr() is bugged and it tends to exaust all available 
 * file descriptors.
 *
 * If you want to check this try "lsof -i |grep ntop". If this fails, please uncomment
 * the '#define PARM_USE_HOST' (below) in order to overcome this flaw.
 */
#ifdef LINUX
 /* #define PARM_USE_HOST */
#endif

/*
 * Somehow, gcc under HPUX decides to build a c++ version of malloc.h
 *   Disable the malloc.h stuff.
 */
#ifdef HPUX
 #undef HAVE_MALLINFO_MALLOC_H
 #undef HAVE_MALLOC_H
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* Code below taken from ethercap */
#define	SAP_NULL		0x00
#define	SAP_LLC_SLMGMT		0x02
#define	SAP_SNA_PATHCTRL	0x04
#define	SAP_IP			0x06
#define	SAP_SNA1		0x08
#define	SAP_SNA2		0x0C
#define	SAP_PROWAY_NM_INIT	0x0E
#define	SAP_TI			0x18
#define	SAP_SNA3		0x40
#define	SAP_BPDU		0x42
#define	SAP_RS511		0x4E
#define	SAP_X25                 0x7E
#define	SAP_XNS			0x80
#define	SAP_BACNET		0x82
#define	SAP_NESTAR		0x86
#define	SAP_PROWAY_ASLM		0x8E
#define	SAP_ARP			0x98
#define	SAP_SNAP		0xAA
#define	SAP_ARP			0x98
#define	SAP_VINES1		0xBA
#define	SAP_VINES2		0xBC
#define	SAP_NETWARE		0xE0
#define	SAP_NETBIOS		0xF0
#define	SAP_IBMNM		0xF4
#define	SAP_HPEXT		0xF8
#define	SAP_UB			0xFA
#define	SAP_RPL			0xFC
#define	SAP_OSINL		0xFE
#define	SAP_GLOBAL		0xFF
