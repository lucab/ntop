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

/****** data declarations ***** */

/* globals-core.c */
extern NtopGlobals myGlobals;
#ifdef MAKE_WITH_SYSLOG
extern MYCODE myFacilityNames[];
#endif

/* Fix courtesy of Tim Gardner <timg@tpi.com> */
#if defined(MULTITHREADED) && defined(ASYNC_ADDRESS_RESOLUTION)
#define accessAddrResMutex(a) if(myGlobals.numericFlag == 0) accessMutex(&myGlobals.addressResolutionMutex,a)
#define releaseAddrResMutex() if(myGlobals.numericFlag == 0) releaseMutex(&myGlobals.addressResolutionMutex)
#else
#define accessAddrResMutex(a) 
#define releaseAddrResMutex() 
#endif

#ifdef HAVE_LIBWRAP
extern int allow_severity, deny_severity;
#endif

/* version.c */
extern char *version, *osName, *author, *buildDate,
            *configure_parameters,
            *host_system_type,
            *target_system_type,
            *compiler_cflags,
            *include_path,
            *system_libs,
#ifdef MAKE_WITH_I18N
            *locale_dir,
#endif
            *install_path;

/* util.c */
#ifndef HAVE_GETOPT_H
/* Our own, minimal extract from getopt.h */
extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;
#endif /* HAVE_GETOPT_H */

/****** function declarations ***** */

/* globals-core.c */
void initNtopGlobals(int argc, char * argv[]);
void initNtop(char *devices);

/* address.c */
extern int printable(int ch);
extern void cleanupAddressQueue(void);
extern void* dequeueAddress(void* notUsed);
extern char* _intoa(struct in_addr addr, char* buf, u_short bufLen);
extern char* intoa(struct in_addr addr);
extern void fetchAddressFromCache(struct in_addr hostIpAddress, char *buffer);
extern void ipaddr2str(struct in_addr hostIpAddress, int actualDeviceId);
extern char* etheraddr_string(const u_char *ep, char *buf);
extern char* llcsap_string(u_char sap);
extern void extract_fddi_addrs(struct fddi_header *fddip, char *fsrc,
                               char *fdst);
extern u_int16_t handleDNSpacket(const u_char *ipPtr, 
                                 DNSHostInfo *hostPtr, short length,
                                 short *isRequest, short *positiveReply);
extern void checkSpoofing(HostTraffic *el, int actualDeviceId);
extern void cleanupHostEntries();

/* admin.c */
extern void showUsers(void);
extern void addUser(char* user);
extern void deleteUser(char* user);
extern void doAddUser(int _len);
extern void showURLs(void);
extern void addURL(char* url);
extern void deleteURL(char* user);
extern void doAddURL(int _len);
extern int doChangeFilter(int len);
extern void changeFilter(void);
extern void setAdminPassword(char* pass);
extern void addDefaultAdminUser(void);

/* dataFormat.c */
extern char* formatKBytes(float numKBytes);
extern char* formatBytes(Counter numBytes, short encodeString);
extern char* formatAdapterSpeed(Counter numBits);
extern char* formatLatency(struct timeval tv, u_short sessionState);
extern char* formatSeconds(unsigned long sec);
extern char* formatMicroSeconds(unsigned long microsec);
extern char* formatThroughput(float numBytes);
extern char* formatTimeStamp(unsigned int ndays, unsigned int nhours,
                             unsigned int nminutes);
extern char* formatPkts(Counter pktNr);

/* hash.c */
extern void freeHostInfo(HostTraffic *host, int actualDeviceId);
extern void freeHostInstances(int actualDeviceId);
extern void purgeIdleHosts(int devId);

/* initialize.c */
extern void initIPServices(void);
extern void resetDevice(int devIdx);
extern void initCounters(void);
extern void resetStats(int);
extern void initThreads(void);
extern void initApps(void);
extern void initDevices(char* devices);
extern void initDeviceDatalink(int);
extern void parseTrafficFilter(void);
extern void initSignals(void);
extern void startSniffer(void);
extern void deviceSanityCheck(char* string);
extern u_int createDummyInterface(char *ifName);
extern void initSingleGdbm(GDBM_FILE *database, char *dbName, char *directory,
			   int doUnlink, struct stat *statbuf);
extern void initGdbm(char *prefDirectory, char *spoolDirectory);
extern void addDevice(char* deviceName, char* deviceDescr);

/* leaks.c */
extern void initLeaks(void);
extern void termLeaks(void);
extern void resetLeaks(void);

#ifndef MTRACE
#ifdef MEMORY_DEBUG 
#define gdbm_firstkey(a)     ntop_gdbm_firstkey(a, __FILE__, __LINE__)
#define gdbm_nextkey(a, b)   ntop_gdbm_nextkey(a, b, __FILE__, __LINE__)
#define gdbm_fetch(a, b)     ntop_gdbm_fetch(a, b, __FILE__, __LINE__)

#define malloc(a)     ntop_malloc((unsigned int)a, __FILE__, __LINE__)
#define calloc(a, b)  ntop_calloc((unsigned int)a, (unsigned int)b, __FILE__, __LINE__)
#define realloc(p, a) ntop_realloc((void*)p, (unsigned int)a,  __FILE__, __LINE__)
#undef strdup
#define strdup(a)     ntop_strdup((char*)a, __FILE__, __LINE__)
/* Fix to the free prototype courtesy of Tanner Lovelace <lovelace@opennms.org> */
#define free(a)       ntop_free((void**)&(a), __FILE__, __LINE__)
extern void*          ntop_malloc(unsigned int sz, char* file, int line);
extern void*          ntop_calloc(unsigned int c, unsigned int sz, char* file, int line);
extern void*          ntop_realloc(void* ptr, unsigned int sz, char* file, int line);
extern char*          ntop_strdup(char *str, char* file, int line);
extern void           ntop_free(void **ptr, char* file, int line);
extern datum          ntop_gdbm_firstkey(GDBM_FILE g, char* file, int line);
extern datum          ntop_gdbm_nextkey(GDBM_FILE g, datum d, char* file, int line);
extern datum          ntop_gdbm_fetch(GDBM_FILE g, datum d, char* file, int line);

#else
extern int   ntop_gdbm_delete(GDBM_FILE g, datum d);
extern datum ntop_gdbm_firstkey(GDBM_FILE g);
extern datum ntop_gdbm_nextkey(GDBM_FILE g, datum d);
extern datum ntop_gdbm_fetch(GDBM_FILE g, datum d);
extern int   ntop_gdbm_store(GDBM_FILE g, datum d, datum v, int r);
extern void  ntop_gdbm_close(GDBM_FILE g);

#define gdbm_firstkey(a)             ntop_gdbm_firstkey(a)
#define gdbm_nextkey(a, b)           ntop_gdbm_nextkey(a, b)
#define gdbm_fetch(a, b)             ntop_gdbm_fetch(a, b)
#define gdbm_delete(a, b)            ntop_gdbm_delete(a, b)
#define gdbm_store(a, b, c, d)       ntop_gdbm_store(a, b, c, d)
#define gdbm_close(a)                ntop_gdbm_close(a)

/* Fix to the free prototype courtesy of Tanner Lovelace <lovelace@opennms.org> */
#define free(a)       ntop_safefree((void**)&(a), __FILE__, __LINE__)
extern void           ntop_safefree(void **ptr, char* file, int line);
#define malloc(sz)    ntop_safemalloc(sz, __FILE__, __LINE__)
extern void*          ntop_safemalloc(unsigned int sz, char* file, int line);
#define calloc(c,sz)  ntop_safecalloc(c, sz, __FILE__, __LINE__)
extern void*          ntop_safecalloc(unsigned int c, unsigned int sz, char* file, int line);
#define realloc(p,sz) ntop_saferealloc(p, sz, __FILE__, __LINE__)
extern void*          ntop_saferealloc(void* ptr, unsigned int sz, char* file, int line);
#endif
extern char* ntop_safestrdup(char *ptr, char* file, int line);
#endif  /* MTRACE */

/* ntop.c */
extern void createPortHash();
extern void handleProtocols();
extern void handleSigHup(int signalId);
extern void *pcapDispatch(void *_i);
#ifdef HANDLE_DIED_CHILD
extern RETSIGTYPE handleDiedChild(int);
#endif
extern RETSIGTYPE dontFreeze(int signo);
extern void daemonize(void);
extern void detachFromTerminal(int);
extern void handleProtocols();
extern void addDefaultProtocols(void);
extern int mapGlobalToLocalIdx(int port);
extern void *updateDBHostsTrafficLoop(void* notUsed);
extern void *scanIdleLoop(void *notUsed);
extern void createPortHash();
#ifndef WIN32
extern void *periodicLsofLoop(void *notUsed);
#endif
extern void packetCaptureLoop(time_t *lastTime, int refreshRate);
extern RETSIGTYPE cleanup(int signo);
extern void* cleanupExpiredHostEntriesLoop(void*);
 
/* pbuf.c */
extern int handleIP(u_short port,
		    HostTraffic *srcHost, HostTraffic *dstHost,
		    const u_int _length,  u_short isPassiveSess,
		    u_short p2pSessionIdx, int actualDeviceId);
extern void updatePacketCount(HostTraffic *srcHost, HostTraffic *dstHost,
			      TrafficCounter length,
			      Counter pktCount,
			      int actualDeviceId);
extern HostTraffic* lookupHost(struct in_addr *hostIpAddress, u_char *ether_addr, 
			       u_char checkForMultihoming,
			       u_char forceUsingIPaddress, int actualDeviceId);
extern void deleteFragment(IpFragment *fragment, int actualDeviceId);
extern void purgeOldFragmentEntries(int actualDeviceId);
extern void queuePacket(u_char * _deviceId, const struct pcap_pkthdr *h,
                        const u_char *p);
extern void cleanupPacketQueue(void);
extern void allocateSecurityHostPkts(HostTraffic *srcHost);
extern void *dequeuePacket(void* notUsed);
extern void updateDevicePacketStats(u_int length, int actualDeviceId);
extern void dumpSuspiciousPacket(int actualDeviceId);
extern void processPacket(u_char *_deviceId, const struct pcap_pkthdr *h,
                          const u_char *p);
extern void updateHostName(HostTraffic *el);
extern void updateInterfacePorts(int actualDeviceId, u_short sport, u_short dport, u_int length);

/* protocols.c */
extern void handleBootp(HostTraffic *srcHost, HostTraffic *dstHost,
			u_short sport, u_short dport,
			u_int packetDataLength, u_char* packetData, int actualDeviceId);
extern u_int16_t processDNSPacket(const u_char *bp, u_int length,
				  short *isRequest, short *positiveReply);
extern void handleNetbios(HostTraffic *srcHost, HostTraffic *dstHost,
			  u_short sport, u_short dport,
			  u_int packetDataLength, const u_char* bp,
			  u_int length, u_int hlen);

/* plugin.c */
extern int handlePluginHTTPRequest(char* url);
extern void loadPlugins(void);
extern void startPlugins(void);
extern void unloadPlugins(void);

/* qsort.c */
/* typedef int (*compare_function_t) (const void *p1, const void *p2); */
extern void quicksort(void *a, size_t n, size_t es,
                      int (*compare_function) (const void *p1, const void *p2));

/* ssl.c */
#ifdef HAVE_OPENSSL
extern void ntop_ssl_error_report(char * whyMe);
extern int init_ssl(void);
extern int accept_ssl_connection(int fd);
extern SSL *getSSLsocket(int fd);
extern void term_ssl_connection(int fd);
extern void term_ssl(void);
#endif

/* main.c */
extern void usage (FILE * fp);

/* term.c */
extern void termIPServices(void);
extern void termIPSessions(void);

/* traffic.c */
extern void updateThpt(void);
extern int isMatrixHost(HostTraffic *host, int actualDeviceId);
extern unsigned int matrixHostHash(HostTraffic *host, int actualDeviceId);
extern void updateTrafficMatrix(HostTraffic *srcHost, HostTraffic *dstHost,
                                TrafficCounter length, int actualDeviceId);
extern void updateDbHostsTraffic(int deviceToUpdate);
extern int isInitialHttpData(char* packetData);
extern int isInitialSshData(char* packetData);
extern int isInitialFtpData(char* packetData);
extern void updateDeviceThpt(int deviceToUpdate);

/* util.c */
extern void handleAddressLists(char* addresses, u_int32_t theNetworks[MAX_NUM_NETWORKS][3],
			       u_short *numNetworks, char *localAddresses, 
			       int localAddressesLen, int flagWhat);
extern void handleFlowsSpecs();
extern void initPassiveSessions();
extern void termPassiveSessions();
extern void incrementTrafficCounter(TrafficCounter *ctr, Counter value);
extern void resetTrafficCounter(TrafficCounter *ctr);
extern int setSpecifiedUser();
extern u_short ip2AS(u_int32_t ip);
extern void readASs(FILE *fd);
extern u_int16_t getHostAS(HostTraffic *el);
extern HostTraffic* getFirstHost(u_int actualDeviceId);
extern HostTraffic* getNextHost(u_int actualDeviceId, HostTraffic *host);
extern HostTraffic* findHostByNumIP(struct in_addr hostIpAddress, u_int actualDeviceId);
extern HostTraffic* findHostBySerial(HostSerial serial, u_int actualDeviceId);
extern HostTraffic* findHostByMAC(char* macAddr, u_int actualDeviceId);
extern char* copy_argv(register char **argv);
extern unsigned short isPrivateAddress(struct in_addr *addr);
extern unsigned short isBroadcastAddress(struct in_addr *addr);
extern unsigned short isMulticastAddress(struct in_addr *addr);
extern unsigned short isLocalAddress(struct in_addr *addr, u_int actualDeviceId);
extern int dotted2bits(char *mask);
extern void handleFlowsSpecs();
extern void handleLocalAddresses(char* addresses);
extern unsigned short isPseudoLocalAddress(struct in_addr *addr, u_int actualDeviceId);
extern unsigned short _pseudoLocalAddress(struct in_addr *addr);
extern unsigned short __pseudoLocalAddress(struct in_addr *addr,
					   u_int32_t theNetworks[MAX_NUM_NETWORKS][3],
					   u_short numNetworks);
extern unsigned short deviceLocalAddress(struct in_addr *addr, u_int deviceId);
extern unsigned short isPseudoBroadcastAddress(struct in_addr *addr);
extern void printLogTime(void);
extern int32_t gmt2local(time_t t);
extern char *dotToSlash(char *name);
extern void handleFlowsSpecs();
extern int getLocalHostAddress(struct in_addr *hostAddress, char* device);
extern void fillDomainName(HostTraffic *el);
#ifdef CFG_MULTITHREADED
extern int createThread(pthread_t *threadId, void *(*__start_routine) (void *),
                        char* userParm);
extern void killThread(pthread_t *threadId);
extern int _createMutex(PthreadMutex *mutexId, char* fileName, int fileLine);
extern int _accessMutex(PthreadMutex *mutexId, char* where,
                        char* fileName, int fileLine);
extern void _deleteMutex(PthreadMutex *mutexId, char* fileName, int fileLine);
extern int _tryLockMutex(PthreadMutex *mutexId, char* where,
                         char* fileName, int fileLine);
extern int _isMutexLocked(PthreadMutex *mutexId,
                         char* fileName, int fileLine);
extern int _releaseMutex(PthreadMutex *mutexId,
                         char* fileName, int fileLine);
extern int createCondvar(ConditionalVariable *condvarId);
extern void deleteCondvar(ConditionalVariable *condvarId);
extern int waitCondvar(ConditionalVariable *condvarId);
extern int timedwaitCondvar(ConditionalVariable *condvarId, struct timespec *expiration);
extern int signalCondvar(ConditionalVariable *condvarId);
#define createMutex(a)     _createMutex(a, __FILE__, __LINE__)
#define accessMutex(a, b)  _accessMutex(a, b, __FILE__, __LINE__)
#define deleteMutex(a)     _deleteMutex(a, __FILE__, __LINE__)
#define tryLockMutex(a, b) _tryLockMutex(a, b, __FILE__, __LINE__)
#define isMutexLocked(a)   _isMutexLocked(a, __FILE__, __LINE__)
#define releaseMutex(a)    _releaseMutex(a, __FILE__, __LINE__)
#ifdef HAVE_SEMAPHORE_H
extern int createSem(sem_t *semId, int initialValue);
extern void waitSem(sem_t *semId);
extern int incrementSem(sem_t *semId);
extern int decrementSem(sem_t *semId);
extern int deleteSem(sem_t *semId);
#endif /* HAVE_SEMAPHORE_H */
#endif /* CFG_MULTITHREADED */
extern void setNBnodeNameType(HostTraffic *theHost, char nodeType, char* nbName);
extern void trimString(char*);
extern FILE* getNewRandomFile(char* fileName, int len);
extern void stringSanityCheck(char* string);
extern int checkCommand(char* commandName);
#ifndef WIN32
extern void readLsofInfo(void);
#endif
extern void setHostFingerprint(HostTraffic *srcHost);
extern char* decodeNBstring(char* theString, char *theBuffer);
extern void closeNwSocket(int *sockId);
extern char *savestr(const char *str);
extern int name_interpret(char *in, char *out, int in_len);

extern char *getNwInterfaceType(int i);
extern char *formatTime(time_t *theTime, short encodeString);
extern int getActualInterface(u_int);
extern void storeHostTrafficInstance(HostTraffic *el);
extern void resetHostsVariables(HostTraffic* el);
extern HostTraffic *resurrectHostTrafficInstance(char *key);
extern u_short in_cksum(const u_short *addr, int len, u_short csum);
extern void addTimeMapping(u_int16_t transactionId, struct timeval theTime);
extern long delta_time (struct timeval * now, struct timeval * before);
extern time_t getTimeMapping(u_int16_t transactionId,
                             struct timeval theTime);
extern void traceEvent(int eventTraceLevel, char* file,
                       int line, char * format, ...)
     __attribute__ ((format (printf, 4, 5))); 
     extern char *_strncpy(char *dest, const char *src, size_t n);
#ifndef HAVE_LOCALTIME_R
extern struct tm *localtime_r(const time_t *t, struct tm *tp);
#endif
#ifndef HAVE_STRTOK_R
extern char *strtok_r(char *s, const char *delim, char **save_ptr);
#endif
extern int getSniffedDNSName(char *hostNumIpAddress, char *name, int maxNameLen);
extern int strOnlyDigits(const char *s);
extern void addPassiveSessionInfo(u_long theHost, u_short thePort);
extern int isPassiveSession(u_long theHost, u_short thePort);
extern void initPassiveSessions();
extern void termPassiveSessions();
extern int getPortByName(ServiceEntry **theSvc, char* portName);
extern char *getPortByNumber(ServiceEntry **theSvc, int port);
extern char *getPortByNum(int port, int type);
extern char *getAllPortByNum(int port);
extern int getAllPortByName(char* portName);
extern void addPortHashEntry(ServiceEntry **theSvc, int port, char* name);
extern void resetUsageCounter(UsageCounter *counter);
extern void resetSecurityHostTraffic(HostTraffic *el);
extern char *mapIcmpType(int icmpType);
extern int _incrementUsageCounter(UsageCounter *counter,
				  HostTraffic *peer, int deviceId,
				  char* file, int line);
extern char *strtolower(char *s);
extern char *xstrncpy(char *dest, const char *src, size_t n);
extern int fetchPrefsValue(char *key, char *value, int valueLen);
extern void storePrefsValue(char *key, char *value);
extern int guessHops(HostTraffic *el);
extern unsigned int ntop_sleep(unsigned int secs);
extern void unescape(char *dest, int destLen, char *url);
extern u_int numActiveSenders(u_int deviceId);
extern u_int32_t xaton(char *s);
extern void addNodeInternal(u_int32_t ip, int prefix, char *country, int as);
extern char *ip2CountryCode(u_int32_t ip);

#ifdef MAKE_WITH_I18N
char *i18n_xvert_locale2common(const char *input);
char *i18n_xvert_acceptlanguage2common(const char *input);
#endif /* MAKE_WITH_I18N */ 

#if defined(AIX) || defined(WIN32)
extern int snprintf(char *str, size_t n, const char *fmt, ...);
#endif

#ifdef PARM_SHOW_NTOP_HEARTBEAT
    #define HEARTBEAT(a, b, ...)     _HEARTBEAT(a, __FILE__, __LINE__, b, __VA_ARGS__)
    extern void _HEARTBEAT(int beatLevel, char* file, int line, char * format, ...);
#else
    #define HEARTBEAT
#endif

/* pseudo- utility functions (i.e. #define only, but of utility nature) go here */

/*
  Courtesy of http://ettercap.sourceforge.net/
*/
#ifndef CFG_LITTLE_ENDIAN
#define ptohs(x) ( (u_int16_t)                       \
                      ((u_int16_t)*((u_int8_t *)x+1)<<8|  \
                      (u_int16_t)*((u_int8_t *)x+0)<<0)   \
                    )

#define ptohl(x) ( (u_int32)*((u_int8_t *)x+3)<<24|  \
                      (u_int32)*((u_int8_t *)x+2)<<16|  \
                      (u_int32)*((u_int8_t *)x+1)<<8|   \
                      (u_int32)*((u_int8_t *)x+0)<<0    \
                    )
#else
#define ptohs(x) *(u_int16_t *)(x)
#define ptohl(x) *(u_int32 *)(x)
#endif

/* Conditional utility functions - code in util.c, activated if it's not already in some library */

#ifdef HAVE_GETOPT_H
extern int getopt_long (int ___argc, char *const *___argv,
                        const char *__shortopts,
                        const struct option *__longopts, int *__longind);
extern int getopt_long_only ();
#endif /* HAVE_GETOPT_H */

#ifndef HAVE_BUILDARGV
extern char **buildargv(const char *argv);
#endif
#ifndef HAVE_FREEARGV
extern void freeargv(char **argv);
#endif
void handleWhiteBlackListAddresses(char* addresses, u_int32_t theNetworks[MAX_NUM_NETWORKS][3],
                                   u_short *numNets, char* outAddresses,
                                   int outAddressesLen);
unsigned short isOKtoSave(u_int32_t addr, 
			  u_int32_t whiteNetworks[MAX_NUM_NETWORKS][3], 
			  u_int32_t blackNetworks[MAX_NUM_NETWORKS][3],
			  u_short numWhiteNets, u_short numBlackNets);


/* Formatting for %.2f ... */
#define xvertDOT00MB(v) (((float)(v)/(float)(1024.0*1024.0))+0.005)
#define xvertDOT00KB(v) (((float)(v)/(float)(1024.0))+0.005)

/* vendor.c */
extern char* getVendorInfo(u_char* ethAddress, short encodeString);
extern char* getSAPInfo(u_int16_t sapInfo, short encodeString);
extern char* getSpecialMacInfo(HostTraffic* el, short encodeString);
extern void createVendorTable(struct stat *statbuf);

/* netflow.c */
extern void termNetFlowExporter();
extern void sendICMPflow(HostTraffic *srcHost, HostTraffic *dstHost, u_int length, u_int actualDeviceId);
extern void sendUDPflow(HostTraffic *srcHost, HostTraffic *dstHost, 
			u_int sport, u_int dport, u_int length, u_int actualDeviceId);
extern void sendTCPSessionFlow(IPSession *theSession, int actualDeviceId);
extern void sendOTHERflow(HostTraffic *srcHost, HostTraffic *dstHost, 
			  u_int8_t proto, u_int length, u_int actualDeviceId);

/* sessions.c */
#define checkSessionIdx(a) _checkSessionIdx(a, actualDeviceId, __FILE__, __LINE__)
extern u_int _checkSessionIdx(u_int idx, int actualDeviceId, char* file, int line);
extern void freeSession(IPSession *sessionToPurge, int actualDeviceId, u_char allocateMemoryIfNeeded, u_char lockMutex);
extern void scanTimedoutTCPSessions(int actualDeviceId);
extern void updateUsedPorts(HostTraffic *srcHost, HostTraffic *dstHost,
			    u_short sport, u_short dport, u_int length);

extern IPSession* handleTCPSession(const struct pcap_pkthdr *h,
				   u_short fragmentedData, u_int tcpWin,
				   HostTraffic *srcHost, u_short sport,
				   HostTraffic *dstHost, u_short dport,
				   u_int length, struct tcphdr *tp,
				   u_int tcpDataLength, u_char* packetData, 
				   int actualDeviceId);

extern IPSession* handleUDPSession(const struct pcap_pkthdr *h,
				   u_short fragmentedData, HostTraffic *srcHost,
				   u_short sport, HostTraffic *dstHost,
				   u_short dport, u_int length,
				   u_char* packetData, int actualDeviceId);
extern void handlePluginSessionTermination(IPSession *sessionToPurge, int actualDeviceId);

#ifdef HAVE_NETDB_H
extern int h_errno; /* netdb.h */
#endif

/* Pseudo-functions.
 *   We use these as if they were real functions, but they expand to
 *   reference other functions (ntop and/or system)...
 */

#if !defined(min)
#define min(a,b) ((a) > (b) ? (b) : (a))
#endif

#if !defined(max)
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef NTOHL
#define NTOHL(x)    (x) = ntohl(x)
#endif

#ifndef BufferTooShort
#define BufferTooShort()  traceEvent(CONST_TRACE_ERROR, "Buffer too short @ %s:%d", __FILE__, __LINE__)
#endif

#ifdef WIN32
#define strncasecmp(a, b, c) strnicmp(a, b, c)
#define sleep(a /* sec */) waitForNextEvent(1000*a /* ms */)
#else
#define sleep(a)  ntop_sleep(a)
#endif

#define NOW ((time_t) time ((time_t *) 0))

#if defined(CFG_NEED_GETDOMAINNAME)
int getdomainname(char *name, size_t len);
#endif

#if defined(LBL_ALIGN)
#define EXTRACT_16BITS(p) \
	((u_short)*((u_char *)(p) + 0) << 8 | \
	(u_short)*((u_char *)(p) + 1))
#define EXTRACT_32BITS(p) \
	((u_int32_t)*((u_char *)(p) + 0) << 24 | \
	(u_int32_t)*((u_char *)(p) + 1) << 16 | \
	(u_int32_t)*((u_char *)(p) + 2) << 8 | \
	(u_int32_t)*((u_char *)(p) + 3))
#else
#define EXTRACT_16BITS(p) \
	((u_short)ntohs(*(u_short *)(p)))
#define EXTRACT_32BITS(p) \
	((u_int32_t)ntohl(*(u_int32_t *)(p)))
#endif

#define EXTRACT_24BITS(p) \
	((u_int32_t)*((u_char *)(p) + 0) << 16 | \
	(u_int32_t)*((u_char *)(p) + 1) << 8 | \
	(u_int32_t)*((u_char *)(p) + 2))

#define incrementUsageCounter(a, b, c) _incrementUsageCounter(a, b, c, __FILE__, __LINE__)

#ifdef CFG_ETHER_HEADER_HAS_EA
#  define ESRC(ep) ((ep)->ether_shost.ether_addr_octet)
#  define EDST(ep) ((ep)->ether_dhost.ether_addr_octet)
#else
#  define ESRC(ep) ((ep)->ether_shost)
#  define EDST(ep) ((ep)->ether_dhost)
#endif

#ifndef WIN32
#define closesocket(a) close(a)
#endif

#ifdef PARM_SHOW_NTOP_HEARTBEAT
    #define HEARTBEAT(a, b, ...)     _HEARTBEAT(a, __FILE__, __LINE__, b, __VA_ARGS__)
#else
    #define HEARTBEAT
#endif

#define GetShort(cp)	_ns_get16(cp); cp += INT16SZ;

/* *************************************

   Code "inherited" from nslookup

   ************************************* */

#ifndef NS_GET16
#define NS_GET16(s, cp) { \
        u_char *t_cp = (u_char *)(cp); \
        (s) = ((u_int16_t)t_cp[0] << 8) \
            | ((u_int16_t)t_cp[1]) \
            ; \
        (cp) += NS_INT16SZ; \
}
#endif

/* Bit test macros */
#define theDomainHasBeenComputed(a) FD_ISSET(FLAG_THE_DOMAIN_HAS_BEEN_COMPUTED, &(a->flags))
#define subnetLocalHost(a)          ((a != NULL) && FD_ISSET(FLAG_SUBNET_LOCALHOST, &(a->flags)))
#define privateIPAddress(a)         ((a != NULL) && FD_ISSET(FLAG_PRIVATE_IP_ADDRESS, &(a->flags)))
#define broadcastHost(a)            ((a != NULL) && ((a->hostSerial == myGlobals.broadcastEntry->hostSerial) || FD_ISSET(FLAG_BROADCAST_HOST, &(a->flags))))
#define multicastHost(a)            ((a != NULL) && FD_ISSET(FLAG_MULTICAST_HOST, &(a->flags)))
#define gatewayHost(a)              ((a != NULL) && FD_ISSET(FLAG_GATEWAY_HOST, &(a->flags)))
#define nameServerHost(a)           ((a != NULL) && FD_ISSET(FLAG_NAME_SERVER_HOST, &(a->flags)))
#define subnetPseudoLocalHost(a)    ((a != NULL) && FD_ISSET(FLAG_SUBNET_PSEUDO_LOCALHOST, &(a->flags)))

#define isServer(a)                 ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_SERVER, &(a->flags)))
#define isWorkstation(a)            ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_WORKSTATION, &(a->flags)))
#define isMasterBrowser(a)          ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_MASTER_BROWSER, &(a->flags)))
#define isMultihomed(a)             ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_MULTIHOMED, &(a->flags)))

#define isPrinter(a)                ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_PRINTER, &(a->flags)))

#define isSMTPhost(a)               ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_SVC_SMTP, &(a->flags)))
#define isPOPhost(a)                ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_SVC_POP, &(a->flags)))
#define isIMAPhost(a)               ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_SVC_IMAP, &(a->flags)))
#define isDirectoryHost(a)          ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_SVC_DIRECTORY, &(a->flags)))
#define isFTPhost(a)                ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_SVC_FTP, &(a->flags)))
#define isHTTPhost(a)               ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_SVC_HTTP, &(a->flags)))
#define isWINShost(a)               ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_SVC_WINS, &(a->flags)))
#define isBridgeHost(a)             ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_SVC_BRIDGE, &(a->flags)))

#define isDHCPClient(a)             ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_SVC_DHCP_CLIENT, &(a->flags)))
#define isDHCPServer(a)             ((a != NULL) && FD_ISSET(FLAG_HOST_TYPE_SVC_DHCP_SERVER, &(a->flags)))

/* Host health */
#define hasWrongNetmask(a)          ((a != NULL) && FD_ISSET(FLAG_HOST_WRONG_NETMASK, &(a->flags)))
#define hasDuplicatedMac(a)         ((a != NULL) && FD_ISSET(FLAG_HOST_DUPLICATED_MAC, &(a->flags)))

#define ISBLANK(ch) ((ch) == ' ' || (ch) == '\t')

/* Shorthand, used in traffic.c */
/* #define getSerial(a) myGlobals.device[deviceToUpdate].hash_hostTraffic[a]->hostSerial */

#ifdef SSLWATCHDOG_DEBUG
#define sslwatchdogDebug(text, bpcFlag, note) { \
          traceEvent(CONST_TRACE_INFO, "SSLWDDEBUG: %1d %-10s %-15s %-15s %s\n", \
                                 myGlobals.sslwatchdogCondvar.predicate, \
                                 ((bpcFlag == FLAG_SSLWATCHDOG_BOTH) ? text : ""), \
                                 ((bpcFlag == FLAG_SSLWATCHDOG_PARENT) ? text : ""), \
                                 ((bpcFlag == FLAG_SSLWATCHDOG_CHILD) ? text : ""), \
                                 note); \
}
#define sslwatchdogDebugN(text, bpcFlag, note) { \
          traceEvent(CONST_TRACE_INFO, "SSLWDDEBUG: %1d %-10s %-15s %-15s %d\n", \
                                 myGlobals.sslwatchdogCondvar.predicate, \
                                 ((bpcFlag == FLAG_SSLWATCHDOG_BOTH) ? text : ""), \
                                 ((bpcFlag == FLAG_SSLWATCHDOG_PARENT) ? text : ""), \
                                 ((bpcFlag == FLAG_SSLWATCHDOG_CHILD) ? text : ""), \
                                 note); \
}
#define sslwatchdogError(text, bpcFlag, note) { \
          traceEvent(CONST_TRACE_INFO, "SSLWDERROR: %1d %-10s %-15s %-15s %s\n", \
                                 myGlobals.sslwatchdogCondvar.predicate, \
                                 ((bpcFlag == FLAG_SSLWATCHDOG_BOTH) ? text : ""), \
                                 ((bpcFlag == FLAG_SSLWATCHDOG_PARENT) ? text : ""), \
                                 ((bpcFlag == FLAG_SSLWATCHDOG_CHILD) ? text : ""), \
                                 note); \
}
#define sslwatchdogErrorN(text, bpcFlag, note) { \
          traceEvent(CONST_TRACE_INFO, "SSLWDERROR: %1d %-10s %-15s %-15s %d\n", \
                                 myGlobals.sslwatchdogCondvar.predicate, \
                                 ((bpcFlag == FLAG_SSLWATCHDOG_BOTH) ? text : ""), \
                                 ((bpcFlag == FLAG_SSLWATCHDOG_PARENT) ? text : ""), \
                                 ((bpcFlag == FLAG_SSLWATCHDOG_CHILD) ? text : ""), \
                                 note); \
}
#else
#define sslwatchdogDebug(text, bpcFlag, note) {}
#define sslwatchdogDebugN(text, bpcFlag, note) {}
#define sslwatchdogError(text, bpsFlag, note) {}
#define sslwatchdogErrorN(text, bpcFlag, note) {}
#endif

#define CONST_LLC_U_CMD(u)    ((u) & 0xef)
#define CONST_LLC_S_CMD(is)   (((is) >> 10) & 0x03)
#define CONST_LLC_IS_NR(is)   (((is) >> 1) & 0x7f)
#define CONST_LLC_I_NS(is)    (((is) >> 9) & 0x7f)

/* ********************************************************** 
   Used in all the prints flowing from printNtopConfigInfo...
   ********************************************************** */
#define texthtml(a, b) (textPrintFlag == TRUE ? a : b)

