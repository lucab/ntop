/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
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



/* General */
extern char *version, *osName, *author, *buildDate;
extern char *program_name;
extern char domainName[MAXHOSTNAMELEN], *shortDomainName;


/* command line options */
extern u_short traceLevel;
extern u_char stickyHosts;
extern char dbPath[200];
extern char accessLogPath[200]; /* Apache-like access log */
extern u_int maxHashSize;
extern short usePersistentStorage, grabSessionInformation;
extern char *rFileName;
extern int numericFlag, logTimeout, daemonMode, mergeInterfaces;
 
/* Search Paths */
extern char *dataFileDirs[], *pluginDirs[], *configFileDirs[];

/* Debug */
extern size_t allocatedMemory;

/* Logging */
extern time_t nextLogTime;

/* Flags */
extern int isLsofPresent, isNepedPresent, isNmapPresent;
extern short capturePackets, endNtop;
 
 
/* Multithreading */
#ifdef MULTITHREADED
extern unsigned short numThreads;
extern pthread_mutex_t packetQueueMutex, hostsHashMutex, graphMutex;
extern pthread_mutex_t lsofMutex, addressResolutionMutex, hashResizeMutex;
extern pthread_t dequeueThreadId, handleWebConnectionsThreadId;
extern pthread_t thptUpdateThreadId, scanIdleThreadId;
extern pthread_t hostTrafficStatsThreadId, dbUpdateThreadId, lsofThreadId;
#ifdef HAVE_GDBM_H
extern pthread_mutex_t gdbmMutex;
#endif

#ifdef USE_SEMAPHORES
extern sem_t queueSem;
#ifdef ASYNC_ADDRESS_RESOLUTION
extern sem_t queueAddressSem;
#endif
#else
extern ConditionalVariable queueCondvar;
#ifdef ASYNC_ADDRESS_RESOLUTION
extern ConditionalVariable queueAddressCondvar;
#endif
#endif
#ifdef ASYNC_ADDRESS_RESOLUTION
extern pthread_t dequeueAddressThreadId;
extern TrafficCounter droppedAddresses;
extern pthread_mutex_t addressQueueMutex;
#endif
#endif
extern u_long numResolvedWithDNSAddresses, numKeptNumericAddresses, 
  numResolvedOnCacheAddresses;

/* Database */
#ifdef HAVE_GDBM_H
extern GDBM_FILE gdbm_file, pwFile, eventFile, hostsInfoFile;
#endif

/* lsof support */
extern u_short updateLsof;
extern ProcessInfo *processes[MAX_NUM_PROCESSES];
extern u_short numProcesses;
extern ProcessInfoList *localPorts[TOP_IP_PORT];

/* TCP Wrappers */
#ifdef HAVE_LIBWRAP
extern int allow_severity, deny_severity;
#endif /* HAVE_LIBWRAP */
 

/* Filter Chains */
extern u_short handleRules;
extern FlowFilterList *flowsList;
extern FilterRuleChain *tcpChain, *udpChain, *icmpChain;
extern u_short ruleSerialIdentifier;
extern FilterRule* filterRulesList[MAX_NUM_RULES];

/* Address Resolution */
#if defined(ASYNC_ADDRESS_RESOLUTION)
extern u_int addressQueueLen, maxAddressQueueLen;
extern u_int addressQueueHead, addressQueueTail;
extern struct hnamemem *addressQueue[ADDRESS_QUEUE_LENGTH+1];
#endif
#ifndef HAVE_GDBM_H
extern struct hnamemem* hnametable[HASHNAMESIZE];
#endif

/* Misc */
extern char *separator;
extern int32_t thisZone; /* seconds offset from gmt to local time */

/* Time */
extern time_t actTime, initialSniffTime, lastRefreshTime;
extern time_t nextSessionTimeoutScan;
extern struct timeval lastPktTime;

/* NICs */
/* CHECK ME: if multiple Interfaces are handled by multiple
   threads deviceId is a bad idea */
extern int deviceId; /* Set by processPacket() */
extern int numDevices, actualDeviceId;
extern ntopInterface_t device[MAX_NUM_DEVICES];

/* Monitored Protocols */
extern char *protoIPTrafficInfos[MAX_NUM_HANDLED_IP_PROTOCOLS]; /* array 0-numIpProtosToMonitor */
extern u_short numIpProtosToMonitor, numIpPortsToHandle;
extern int* ipPortMapper;

/* Packet Capture */
#if defined(MULTITHREADED)
extern PacketInformation packetQueue[PACKET_QUEUE_LENGTH+1];
extern unsigned int packetQueueLen, maxPacketQueueLen, packetQueueHead, packetQueueTail;
#endif

extern TransactionTime transTimeHash[NUM_TRANSACTION_ENTRIES];
extern u_int broadcastEntryIdx;
extern HostTraffic broadcastEntry;
extern u_char dummyEthAddress[ETHERNET_ADDRESS_LEN];
extern u_short mtuSize[], headerSize[];
extern IpFragment *fragmentList;
extern IPSession *tcpSession[HASHNAMESIZE]; /* TCP sessions */
extern IPSession *udpSession[HASHNAMESIZE]; /* UDP sessions */
extern u_short numTcpSessions, numUdpSessions;
extern ServiceEntry *udpSvc[SERVICE_HASH_SIZE], *tcpSvc[SERVICE_HASH_SIZE];
extern TrafficEntry ipTrafficMatrix[256][256]; /* Subnet traffic Matrix */
extern HostTraffic* ipTrafficMatrixHosts[256]; /* Subnet traffic Matrix Hosts */
extern fd_set ipTrafficMatrixPromiscHosts;

/* function declaration ***************************************************** */

/* address.c */

extern void cleanupAddressQueue(void);
extern void* dequeueAddress(void* notUsed);
extern char* _intoa(struct in_addr addr, char* buf, u_short bufLen);
extern char* intoa(struct in_addr addr);
extern void ipaddr2str(struct in_addr hostIpAddress, char* outBuf,
                       int outBufLen);
extern char* etheraddr_string(const u_char *ep);
extern char* llcsap_string(u_char sap);
extern void extract_fddi_addrs(struct fddi_header *fddip, char *fsrc,
                               char *fdst);
extern u_int16_t handleDNSpacket(const u_char *ipPtr, u_short displ,
                                 DNSHostInfo *hostPtr, short n,
                                 short *isRequest, short *positiveReply);
extern void checkSpoofing(u_int idxToCheck);

/* admin.c */
extern void showUsers(void);
extern void addUser(char* user);
extern void deleteUser(char* user);
extern void doAddUser(int _len);
extern void showURLs(void);
extern void addURL(char* url);
extern void deleteURL(char* user);
extern void doAddURL(int _len);
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
extern void dumpNtopHashes(char* options);
extern void dumpNtopTrafficInfo(char* options);

/* event.c */
extern void emitEvent(FilterRule *rule, HostTraffic *srcHost,
                      u_int srcHostIdx, HostTraffic *dstHost,
                      u_int dstHostIdx, short icmpType,
                      u_short sport, u_short dport);
extern void scanAllTcpExpiredRules(void);
extern void fireEvent(FilterRule *rule, HostTraffic *srcHost,
                      u_int srcHostIdx, HostTraffic *dstHost,
                      u_int dstHostIdx, short icmpType,
                      u_short sport, u_short dport,
                      u_int length);
extern void smurfAlert(u_int srcHostIdx, u_int dstHostIdx);

/* graph.c */
extern void pktSizeDistribPie(void);
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
                                   short* useIPAddressForSearching);
extern void resizeHostHash(int deviceToExtend, float multiplier);
extern void freeHostInfo(int theDevice, u_int hostIdx);
extern void freeHostInstances(void);
extern void purgeIdleHosts(int ignoreIdleTime);

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
extern void initThreads(int enableThUpdate, int enableIdleHosts, int enableDBsupport);
extern void initApps(void);
extern void initDevices(char* devices);
extern void initLibpcap(char* rulesFile, int numDevices);
extern void initDeviceDatalink(void);
extern void parseTrafficFilter(char *argv[], int optind);
extern void initSignals(void);
extern void startSniffer(void);
extern void deviceSanityCheck(char* string);

/* leaks.c */
#ifdef MEMORY_DEBUG 
#define malloc(a) ntop_malloc((unsigned int)a, __FILE__, __LINE__)
#define strdup(a) ntop_strdup((char*)a, __FILE__, __LINE__)
#define free(a)   ntop_free((void*)a, __FILE__, __LINE__)
extern void* ntop_malloc(unsigned int sz, char* file, int line);
extern char* ntop_strdup(char *str, char* file, int line);
extern void  ntop_free(void *ptr, char* file, int line);
#endif

/* logger.c */
extern void initLogger(void);
extern void termLogger(void);
extern void logMessage(char* message, u_short severity);
extern void LogStatsToFile(void);
extern void* logFileLoop(void* notUsed);


/* ntop.c */
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
extern void *periodicLsofLoop(void *notUsed);
extern void packetCaptureLoop(time_t *lastTime, int refreshRate);
extern RETSIGTYPE cleanup(int signo);
 
/* pbuf.c */
#define checkSessionIdx(a) _checkSessionIdx(a, __FILE__, __LINE__)
extern u_int _checkSessionIdx(u_int idx, char* file, int line);
extern int getPortByName(ServiceEntry **theSvc, char* portName);
extern char *getPortByNumber(ServiceEntry **theSvc, int port);
extern char *getPortByNum(int port, int type);
extern char *getAllPortByNum(int port);
extern int getAllPortByName(char* portName);
extern void addPortHashEntry(ServiceEntry **theSvc, int port, char* name);
extern u_int findHostIdxByNumIP(struct in_addr hostIpAddress);
extern u_int findHostInfo(struct in_addr *hostIpAddress);
extern u_int getHostInfo(struct in_addr *hostIpAddress, u_char *ether_addr);
extern char *getNamedPort(int port);
extern void scanTimedoutTCPSessions(void);
extern void deleteFragment(IpFragment *fragment);
extern void purgeOldFragmentEntries(void);
extern void queuePacket(u_char * _deviceId, const struct pcap_pkthdr *h,
                        const u_char *p);
extern void cleanupPacketQueue(void);
extern void *dequeuePacket(void* notUsed);
extern void processPacket(u_char *_deviceId, const struct pcap_pkthdr *h,
                          const u_char *p);
extern void updateOSName(HostTraffic *el);

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
                             u_short packetType);

/* sql.c */
extern void handleDbSupport(char* addr /* host:port */, int* enableDBsupport);
extern void closeSQLsocket(void);
extern void updateHostNameInfo(unsigned long numeric, char* symbolic);
extern void updateHostTraffic(HostTraffic *el);
extern void notifyHostCreation(HostTraffic *el);
extern void notifyTCPSession(IPSession *session);
extern void updateDBOSname(HostTraffic *el);

/* ssl.c */
#ifdef HAVE_OPENSSL
extern int sslInitialized, sslPort;
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
                                TrafficCounter length);
extern void updateDbHostsTraffic(int deviceToUpdate);
extern void updateHostTrafficStatsThpt(int hourId);

/* util.c */
extern FILE *sec_popen(char *cmd, const char *type);
extern HostTraffic* findHostByNumIP(char* numIPaddr);
extern HostTraffic* findHostByMAC(char* macAddr);
extern char* copy_argv(register char **argv);
extern unsigned short isBroadcastAddress(struct in_addr *addr);
extern unsigned short isMulticastAddress(struct in_addr *addr);
extern unsigned short isLocalAddress(struct in_addr *addr);
extern int dotted2bits(char *mask);
extern void handleLocalAddresses(char* addresses);
extern unsigned short isPseudoLocalAddress(struct in_addr *addr);
extern unsigned short isPseudoBroadcastAddress(struct in_addr *addr);
extern void printLogTime(void);
extern int32_t gmt2local(time_t t);
extern void handleFlowsSpecs(char* flows);
extern int getLocalHostAddress(struct in_addr *hostAddress, char* device);
extern void fillDomainName(HostTraffic *el);
extern void writePidFile(char *path);

#ifdef MULTITHREADED
extern int createThread(pthread_t *threadId, void *(*__start_routine) (void *),
                        char* userParm);
extern void killThread(pthread_t *threadId);
extern int createMutex(pthread_mutex_t *mutexId);
extern void deleteMutex(pthread_mutex_t *mutexId);
extern int _accessMutex(pthread_mutex_t *mutexId, char* where,
                        char* fileName, int fileLine);
extern int _tryLockMutex(pthread_mutex_t *mutexId, char* where,
                         char* fileName, int fileLine);
extern int _releaseMutex(pthread_mutex_t *mutexId,
                         char* fileName, int fileLine);
extern int createCondvar(ConditionalVariable *condvarId);
extern void deleteCondvar(ConditionalVariable *condvarId);
extern int waitCondvar(ConditionalVariable *condvarId);
extern int signalCondvar(ConditionalVariable *condvarId);
#define accessMutex(a, b)  _accessMutex(a, b, __FILE__, __LINE__)
#define tryLockMutex(a, b) _tryLockMutex(a, b, __FILE__, __LINE__)
#define releaseMutex(a)    _releaseMutex(a, __FILE__, __LINE__)
#ifdef HAVE_SEMAPHORE_H
extern int createSem(sem_t *semId, int initialValue);
extern void waitSem(sem_t *semId);
extern int incrementSem(sem_t *semId);
extern int decrementSem(sem_t *semId);
extern int deleteSem(sem_t *semId);
#endif /* HAVE_SEMAPHORE_H */
#endif /* MULTITHREADED */

extern void stringSanityCheck(char* string);
extern int checkCommand(char* commandName);
extern void readLsofInfo(void);
extern void readNepedInfo(void);
extern char *getHostOS(char* ipAddr, int port, char* additionalInfo);
extern void closeNwSocket(int *sockId);
extern char *savestr(const char *str);
extern int name_interpret(char *in, char *out);

extern char *getNwInterfaceType(int i);
extern char *formatTime(time_t *theTime, short encodeString);
extern int getActualInterface(void);
extern void storeHostTrafficInstance(HostTraffic *el);

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
extern int strOnlyDigits(const char *s);

/* vendor.c */
extern char* getVendorInfo(u_char* ethAddress, short encodeString);
extern char* getSAPInfo(u_int16_t sapInfo, short encodeString);
extern char* getSpecialMacInfo(HostTraffic* el, short encodeString);
extern void createVendorTable(void);

#if defined(AIX) || defined(WIN32)
extern int snprintf(char *str, size_t n, const char *fmt, ...);
#endif
