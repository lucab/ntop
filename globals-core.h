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

extern NtopGlobals myGlobals;

/* version.c */
extern char *version, *osName, *author, *buildDate;

/****** function declarations ***** */

/* address.c */
extern void cleanupAddressQueue(void);
extern void* dequeueAddress(void* notUsed);
extern char* _intoa(struct in_addr addr, char* buf, u_short bufLen);
extern char* intoa(struct in_addr addr);
extern void fetchAddressFromCache(struct in_addr hostIpAddress, char *buffer);
extern void ipaddr2str(struct in_addr hostIpAddress, int actualDeviceId);
extern char* etheraddr_string(const u_char *ep);
extern char* llcsap_string(u_char sap);
extern void extract_fddi_addrs(struct fddi_header *fddip, char *fsrc,
                               char *fdst);
extern u_int16_t handleDNSpacket(const u_char *ipPtr, 
                                 DNSHostInfo *hostPtr, short length,
                                 short *isRequest, short *positiveReply);
extern void checkSpoofing(u_int idxToCheck, int actualDeviceId);
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
extern void addDefaultAdminUser(void);

/* dataFormat.c */
extern char* formatKBytes(float numKBytes);
extern char* formatBytes(TrafficCounter numBytes, short encodeString);
extern char* formatLatency(struct timeval tv, u_short sessionState);
extern char* formatSeconds(unsigned long sec);
extern char* formatMicroSeconds(unsigned long microsec);
extern char* formatThroughput(float numBytes);
extern char* formatTimeStamp(unsigned int ndays, unsigned int nhours,
                             unsigned int nminutes);
extern char* formatPkts(TrafficCounter pktNr);

/* emitter.c */
extern void dumpNtopHashes(char* options, int actualDeviceId);
extern void dumpNtopTrafficInfo(char* options);

/* event.c */
extern void emitEvent(FilterRule *rule, HostTraffic *srcHost,
                      u_int srcHostIdx, HostTraffic *dstHost,
                      u_int dstHostIdx, short icmpType,
                      u_short sport, u_short dport);
extern void scanAllTcpExpiredRules(int actualDeviceId);
extern void fireEvent(FilterRule *rule, HostTraffic *srcHost,
                      u_int srcHostIdx, HostTraffic *dstHost,
                      u_int dstHostIdx, short icmpType,
                      u_short sport, u_short dport,
                      u_int length, int actualDeviceId);
extern void smurfAlert(u_int srcHostIdx, u_int dstHostIdx, int actualDeviceId);

/* graph.c */
extern void hostTrafficDistrib(HostTraffic *theHost, short dataSent);
extern void hostIPTrafficDistrib(HostTraffic *theHost, short dataSent);
extern void hostFragmentDistrib(HostTraffic *theHost, short dataSent);
extern void hostTotalFragmentDistrib(HostTraffic *theHost, short dataSent);
extern void pktSizeDistribPie(void);
extern void pktTTLDistribPie(void);
extern void ipProtoDistribPie(void);
extern void interfaceTrafficPie(void);
extern void pktCastDistribPie(void);
extern void drawTrafficPie(void);
extern void drawThptGraph(int sortedColumn);
extern void drawGlobalProtoDistribution(void);
extern void drawGlobalIpProtoDistribution(void);

/* hash.c */
extern u_int computeInitialHashIdx(struct in_addr *hostIpAddress,
                                   u_char *ether_addr,
                                   short* useIPAddressForSearching, int actualDeviceId);
extern void freeHostInfo(int theDevice, HostTraffic *host, 
			 u_int hostIdx, int actualDeviceId);
extern void freeHostInstances(int actualDeviceId);
extern void purgeIdleHosts(int devId);
extern void purgeHostIdx(int theDevice, u_int hostIdx);

/* http.c */
extern void sendStringLen(char *theString, unsigned int len);
extern void sendString(char *theString);
extern void printHTTPheader(void);
extern void printHTTPtrailer(void);
extern void initAccessLog(void);
extern void termAccessLog(void);
extern void sendHTTPHeaderType(void);
extern void sendGIFHeaderType(void);
extern void sendHTTPProtoHeader(void);
extern void handleHTTPrequest(struct in_addr from);
extern void printHTMLheader(char *title, int  headerFlags);

/* initialize.c */
extern void initIPServices(void);
extern void initCounters(int _mergeInterfaces);
extern void resetStats(void);
extern int initGlobalValues(void);
extern void postCommandLineArgumentsInitialization(time_t *lastTime);
extern void initGdbm(void);
extern void initThreads();
extern void initApps(void);
extern void initDevices(char* devices);
extern void initLibpcap();
extern void initDeviceDatalink(void);
extern void parseTrafficFilter();
extern void initSignals(void);
extern void startSniffer(void);
extern void deviceSanityCheck(char* string);

/* leaks.c */
extern void initLeaks(void);
extern void termLeaks(void);
extern void resetLeaks(void);
#ifdef MEMORY_DEBUG 
#define malloc(a)     ntop_malloc((unsigned int)a, __FILE__, __LINE__)
#define calloc(a, b)  ntop_calloc((unsigned int)a, (unsigned int)b, __FILE__, __LINE__)
#define realloc(p, a) ntop_realloc((void*)p, (unsigned int)a,  __FILE__, __LINE__)
#define strdup(a)     ntop_strdup((char*)a, __FILE__, __LINE__)
#define free(a)       ntop_free((void*)&(a), __FILE__, __LINE__)
extern void*          ntop_malloc(unsigned int sz, char* file, int line);
extern void*          ntop_calloc(unsigned int c, unsigned int sz, char* file, int line);
extern void*          ntop_realloc(void* ptr, unsigned int sz, char* file, int line);
extern char*          ntop_strdup(char *str, char* file, int line);
extern void           ntop_free(void **ptr, char* file, int line);
#else
#define free(a)       ntop_safefree((void*)&(a), __FILE__, __LINE__)
extern void           ntop_safefree(void **ptr, char* file, int line);
#define malloc(sz)    ntop_safemalloc(sz, __FILE__, __LINE__)
extern void*          ntop_safemalloc(unsigned int sz, char* file, int line);
#define calloc(c,sz)  ntop_safecalloc(c, sz, __FILE__, __LINE__)
extern void*          ntop_safecalloc(unsigned int c, unsigned int sz, char* file, int line);
#define realloc(p,sz) ntop_saferealloc(p, sz, __FILE__, __LINE__)
extern void*          ntop_saferealloc(void* ptr, unsigned int sz, char* file, int line);
#endif


/* logger.c */
extern void initLogger(void);
extern void termLogger(void);
extern void logMessage(char* message, u_short severity);
extern void LogStatsToFile(void);
extern void* logFileLoop(void* notUsed);


/* ntop.c */
extern int numChildren;
extern void handleSigHup(int signalId);
extern void *pcapDispatch(void *_i);
extern RETSIGTYPE handleDiedChild(int signal);
extern RETSIGTYPE dontFreeze(int signo);
extern void daemonize(void);
extern void detachFromTerminal(void);
extern void handleProtocols(char *protos);
extern void addDefaultProtocols(void);
extern int mapGlobalToLocalIdx(int port);
extern void *updateThptLoop(void *notUsed);
extern void* updateHostTrafficStatsThptLoop(void* notUsed);
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
extern u_int findHostIdxByNumIP(struct in_addr hostIpAddress, int actualDeviceId);
extern u_int findHostInfo(struct in_addr *hostIpAddress, int actualDeviceId);
extern u_int getHostInfo(struct in_addr *hostIpAddress, u_char *ether_addr, 
			 u_char checkForMultihoming,
			 u_char forceUsingIPaddress, int actualDeviceId);
extern char *getNamedPort(int port);
extern void deleteFragment(IpFragment *fragment, int actualDeviceId);
extern void purgeOldFragmentEntries(int actualDeviceId);
extern void queuePacket(u_char * _deviceId, const struct pcap_pkthdr *h,
                        const u_char *p);
extern void cleanupPacketQueue(void);
extern void allocateSecurityHostPkts(HostTraffic *srcHost);
extern void *dequeuePacket(void* notUsed);
extern void dumpSuspiciousPacket(int actualDeviceId);
extern void processPacket(u_char *_deviceId, const struct pcap_pkthdr *h,
                          const u_char *p);
extern void updateHostName(HostTraffic *el);

/* protocols.c */
extern void handleBootp(HostTraffic *srcHost, HostTraffic *dstHost,
			u_short sport, u_short dport,
			u_int packetDataLength, u_char* packetData, int actualDeviceId);
extern u_int16_t processDNSPacket(const u_char *bp, u_int length,
				  short *isRequest, short *positiveReply);
#ifdef ENABLE_NAPSTER
extern void handleNapster(HostTraffic *srcHost, HostTraffic *dstHost,
			  u_short sport, u_short dport,
			  u_int packetDataLength, u_char* packetData,
			  IPSession *theSession);
#endif
extern void handleNetbios(HostTraffic *srcHost, HostTraffic *dstHost,
			  u_short sport, u_short dport,
			  u_int packetDataLength, const u_char* bp,
			  u_int length, u_int hlen);

/* plugin.c */
/* CHECK ME: THIS IS NOT CALLED YET! */
extern void notifyPluginsHashResize(int oldSize, int newSize,
                                    int* mappings);
extern int handlePluginHTTPRequest(char* url);
extern void loadPlugins(void);
extern void startPlugins(void);
extern void unloadPlugins(void);

/* qsort.c */
/* typedef int (*compare_function_t) (const void *p1, const void *p2); */
extern void quicksort(void *a, size_t n, size_t es,
                      int (*compare_function) (const void *p1, const void *p2));

/* rules.c */
extern void parseRules(char* path);
extern void checkFilterChain(HostTraffic *srcHost, u_int srcHostIdx, 
                             HostTraffic *dstHost, u_int dstHostIdx,
                             u_short sport, u_short dport, 
                             u_int length, u_int hlen, u_int8_t flags,     
                             u_char protocol, u_char isFragment,  
                             const u_char* bp, FilterRuleChain *selectedChain,
                             u_short packetType, int actualDeviceId);

/* sql.c */
extern void handleDbSupport(char* addr /* host:port */, int* enableDBsupport);
extern void closeSQLsocket(void);
extern void updateHostNameInfo(unsigned long numeric, char* symbolic, int actualDeviceId);
extern void updateHostTraffic(HostTraffic *el);
extern void notifyHostCreation(HostTraffic *el);
extern void notifyTCPSession(IPSession *session, int actualDeviceId);
extern void updateDBOSname(HostTraffic *el);

/* ssl.c */
#ifdef HAVE_OPENSSL
extern int init_ssl(void);
extern int accept_ssl_connection(int fd);
extern SSL *getSSLsocket(int fd);
extern void term_ssl_connection(int fd);
/* CHECK ME: THIS IS NOT CALLED YET! */
extern void term_ssl(void);
#endif

/* term.c */
extern void termIPServices(void);
extern void termIPSessions(void);

/* traffic.c */
extern void updateThpt(void);
extern void updateTrafficMatrix(HostTraffic *srcHost, HostTraffic *dstHost,
                                TrafficCounter length, int actualDeviceId);
extern void updateDbHostsTraffic(int deviceToUpdate);
extern void updateHostTrafficStatsThpt(int hourId);
extern int isInitialHttpData(char* packetData);
extern int isInitialSshData(char* packetData);
extern int isInitialFtpData(char* packetData);

/* util.c */
extern FILE *sec_popen(char *cmd, const char *type);
extern HostTraffic* findHostByNumIP(char* numIPaddr, int actualDeviceId);
extern HostTraffic* findHostByMAC(char* macAddr, int actualDeviceId);
extern char* copy_argv(register char **argv);
extern unsigned short isPrivateAddress(struct in_addr *addr);
extern unsigned short isBroadcastAddress(struct in_addr *addr);
extern unsigned short isMulticastAddress(struct in_addr *addr);
extern unsigned short isLocalAddress(struct in_addr *addr);
extern int dotted2bits(char *mask);
extern void handleLocalAddresses(char* addresses);
extern unsigned short isPseudoLocalAddress(struct in_addr *addr);
extern unsigned short _pseudoLocalAddress(struct in_addr *addr);
extern unsigned short isPseudoBroadcastAddress(struct in_addr *addr);
extern void printLogTime(void);
extern int32_t gmt2local(time_t t);
extern void handleFlowsSpecs(char* flows);
extern int getLocalHostAddress(struct in_addr *hostAddress, char* device);
extern void fillDomainName(HostTraffic *el);
#ifdef MULTITHREADED
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
#endif /* MULTITHREADED */
extern void setNBnodeNameType(HostTraffic *theHost, char nodeType, char* nbName);
extern void trimString(char*);
extern FILE* getNewRandomFile(char* fileName, int len);
extern void stringSanityCheck(char* string);
extern int checkCommand(char* commandName);
#ifndef WIN32
extern void readLsofInfo(void);
#endif
extern char *getHostOS(char* ipAddr, int port, char* additionalInfo);
extern char* decodeNBstring(char* theString, char *theBuffer);
extern void closeNwSocket(int *sockId);
extern char *savestr(const char *str);
extern int name_interpret(char *in, char *out, int in_len);

extern char *getNwInterfaceType(int i);
extern char *formatTime(time_t *theTime, short encodeString);
extern int getActualInterface(int);
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
extern void updateOSName(HostTraffic *el);
extern void _incrementUsageCounter(UsageCounter *counter,
				   u_int peerIdx, int deviceId,
				   char* file, int line);
extern char *strtolower(char *s);
extern char *xstrncpy(char *dest, const char *src, size_t n);

/* vendor.c */
extern char* getVendorInfo(u_char* ethAddress, short encodeString);
extern char* getSAPInfo(u_int16_t sapInfo, short encodeString);
extern char* getSpecialMacInfo(HostTraffic* el, short encodeString);
extern void createVendorTable(void);

#if defined(AIX) || defined(WIN32)
extern int snprintf(char *str, size_t n, const char *fmt, ...);
#endif
 

/* mysql.c */
#ifdef HAVE_MYSQL
extern void handlemySQLSupport(char* addr /* host:port */, int* enableDBsupport);
extern void closemySQLsocket(void);
extern void mySQLupdateHostNameInfo(unsigned long numeric, char* symbolic);
extern void mySQLupdateHostTraffic(HostTraffic *el);
extern void mySQLnotifyHostCreation(HostTraffic *el);
extern void mySQLnotifyTCPSession(IPSession *session, int actualDeviceId);
extern void mySQLupdateDBOSname(HostTraffic *el);
#endif /* HAVE_MYSQL */

#ifdef ENABLE_NAPSTER
extern NapsterServer napsterSvr[MAX_NUM_NAPSTER_SERVER];
#endif

/* netflow.c */
extern int handleNetFlowSupport(char* addr /* host:port */);
extern void termNetFlowExporter();
extern void sendICMPflow(HostTraffic *srcHost, HostTraffic *dstHost, u_int length);
extern void sendUDPflow(HostTraffic *srcHost, HostTraffic *dstHost, 
			u_int sport, u_int dport, u_int length);
extern void sendTCPSessionFlow(IPSession *theSession, int actualDeviceId);

/* globals-core.c */
void initNtopGlobals(int argc, char * argv[]);

/* sessions.c */
#define checkSessionIdx(a) _checkSessionIdx(a, actualDeviceId, __FILE__, __LINE__)
extern u_int _checkSessionIdx(u_int idx, int actualDeviceId, char* file, int line);
extern void freeSession(IPSession *sessionToPurge, int actualDeviceId);
#ifndef MULTITHREADED
extern void scanTimedoutTCPSessions(int actualDeviceId);
#endif

extern IPSession* handleTCPSession(const struct pcap_pkthdr *h,
				   u_short fragmentedData, u_int tcpWin,
				   u_int srcHostIdx, u_short sport,
				   u_int dstHostIdx, u_short dport,
				   u_int length, struct tcphdr *tp,
				   u_int tcpDataLength, u_char* packetData, 
				   int actualDeviceId);

extern IPSession* handleUDPSession(const struct pcap_pkthdr *h,
				   u_short fragmentedData, u_int srcHostIdx,
				   u_short sport, u_int dstHostIdx,
				   u_short dport, u_int length,
				   u_char* packetData, int actualDeviceId);
extern void handlePluginSessionTermination(IPSession *sessionToPurge, int actualDeviceId);
