/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 *		  	  Centro SERRA, University of Pisa
 *		 	  http://www.ntop.org/
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


extern unsigned long allocatedMemory, maxHashSize;

/* Database */
extern char dbPath[200];
extern char accessLogPath[200]; /* Apache-like access log */

extern short usePersistentStorage, grabSessionInformation, 
  capturePackets, endNtop;

/* Time */
extern time_t actTime, initialSniffTime, lastRefreshTime;
extern long delta_time (struct timeval * now, struct timeval * before);

/* NICs */
extern int numDevices, actualDeviceId;

/* a very import table for ntop engine */
extern ntopInterface_t device[MAX_NUM_DEVICES];

/* Throughput */

extern char *program_name;
extern TransactionTime transTimeHash[NUM_TRANSACTION_ENTRIES];

extern char *protoIPTrafficInfos[MAX_NUM_HANDLED_IP_PROTOCOLS]; /* array 0-numIpProtosToMonitor */
extern u_short numIpProtosToMonitor, numIpPortsToHandle, updateLsof, handleRules;
extern int* ipPortMapper;
extern char* rFileName;

extern HostTraffic broadcastEntry;


#ifdef MULTITHREADED
extern pthread_mutex_t packetQueueMutex, hostsHashMutex, graphMutex;
extern pthread_mutex_t lsofMutex, addressResolutionMutex, hashResizeMutex;
extern pthread_t dequeueThreadId, handleWebConnectionsThreadId,
  thptUpdateThreadId,
  scanIdleThreadId, logFileLoopThreadId,
  dbUpdateThreadId;
extern pthread_t lsofThreadId;

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

#ifdef HAVE_LIBWRAP
extern int allow_severity;
extern int deny_severity;
#endif /* HAVE_LIBWRAP */

#ifdef HAVE_GDBM_H
extern GDBM_FILE gdbm_file, pwFile, eventFile, hostsInfoFile;

#ifdef MULTITHREADED
extern pthread_mutex_t gdbmMutex;
#endif
#endif

extern int numericFlag;
extern int logTimeout;
extern int daemonMode;
extern time_t nextLogTime;
extern FILE *logd;
extern FlowFilterList *flowsList;

extern int isLsofPresent, isNepedPresent, isNmapPresent;

extern FilterRuleChain *tcpChain, *udpChain, *icmpChain;
extern u_short ruleSerialIdentifier;
extern FilterRule* filterRulesList[MAX_NUM_RULES];

#ifdef WIN32
extern int SIZE_BUF;
#endif

extern u_char dummyEthAddress[ETHERNET_ADDRESS_LEN];
extern short sortSendMode;
extern int lastNumLines, lastNumCols;
extern time_t nextSessionTimeoutScan;
extern struct timeval lastPktTime;
extern u_int broadcastEntryIdx;
extern unsigned short alternateColor, maxNameLen;
extern int deviceId, mergeInterfaces; /* Set by processPacket() */

extern char *dirs[];

extern ProcessInfo *processes[MAX_NUM_PROCESSES];
extern u_short numProcesses;
extern ProcessInfoList *localPorts[TOP_IP_PORT];


extern u_short mtuSize[];
extern u_short headerSize[];

#if defined(ASYNC_ADDRESS_RESOLUTION)
extern unsigned int addressQueueLen, maxAddressQueueLen, addressQueueHead, addressQueueTail;

extern struct hnamemem *addressQueue[ADDRESS_QUEUE_LENGTH+1];
#endif


#if defined(MULTITHREADED)
extern PacketInformation packetQueue[PACKET_QUEUE_LENGTH+1];
extern unsigned int packetQueueLen, maxPacketQueueLen, packetQueueHead, packetQueueTail;
#endif


extern char domainName[MAXHOSTNAMELEN], *shortDomainName;
#ifndef HAVE_GDBM_H
extern struct hnamemem* hnametable[HASHNAMESIZE];
#endif
extern IpFragment *fragmentList;
extern IPSession *tcpSession[HASHNAMESIZE]; /* TCP sessions */
extern IPSession *udpSession[HASHNAMESIZE]; /* UDP sessions */
extern u_short numTcpSessions, numUdpSessions;
extern char *separator;
extern ServiceEntry *udpSvc[SERVICE_HASH_SIZE], *tcpSvc[SERVICE_HASH_SIZE];
extern TrafficEntry ipTrafficMatrix[256][256]; /* Subnet traffic Matrix */
extern HostTraffic* ipTrafficMatrixHosts[256]; /* Subnet traffic Matrix Hosts */
extern fd_set ipTrafficMatrixPromiscHosts;
extern int32_t thisZone; /* seconds offset from gmt to local time */


extern SimpleProtoTrafficInfo *ipProtoStats;

/* function declaration */

/* address.c */
extern void upadateHostNameInfo(unsigned long numeric, char* symbolic);
extern unsigned short isLocalAddress(struct in_addr *addr);
extern unsigned short isBroadcastAddress(struct in_addr *addr);

/* admin.c */
char* intoa(struct in_addr addr);
char* _intoa(struct in_addr addr, char* buf, u_short bufLen);
char* savestr(const char *str);

/* event.c */
extern void sendHTTPProtoHeader();
extern void sendString(char *theString);
extern void printHTTPtrailer();

extern char* getRowColor();
extern char* getAllPortByNum(int port);
extern int getAllPortByName(char* portName);
extern void sendString(char *x);
extern void  quicksort(void *, size_t, size_t,
		       int (*)(const void *, const void *));
extern u_int checkSessionIdx(u_int idx);

extern void freeHostInfo(int theDevice, u_int hostIdx);

/* http.c */

extern void sendGIFHeaderType();
extern void sendGIFHeaderType();
extern void sendHTTPHeaderType();

#ifndef WIN32
extern void execCGI(char* cgiName);
#endif
extern void closeNwSocket(int *sockId);
extern void drawTrafficPie();
extern void pktCastDistribPie();
extern void pktSizeDistribPie();
extern void ipProtoDistribPie();
extern void interfaceTrafficPie();
extern void drawGlobalIpProtoDistribution();
extern void drawGlobalProtoDistribution();
extern void drawThptGraph(int sortedColumn);
extern int handlePluginHTTPRequest(char* url);
extern void printAllSessionsHTML(char* host);
extern void printMulticastStats(int, int);

extern void printHostsTraffic(int, int, int, int);

extern void printIpAccounting(int, int, int);
extern void printHostsInfo(int, int);
extern void printActiveTCPSessions();
extern void printIpProtocolDistribution(int mode, int);
extern void printIpTrafficMatrix();
extern void printIpProtocolUsage();
extern void printThptStats(int);
extern void printLocalRoutersList();
extern void printDomainStats(char*, int, int);
extern void showPluginsList(char* pluginName);
extern void listNetFlows();
extern void resetStats();
extern void shutdownNtop();
extern void printProtoTraffic();
extern void printLsofData(int mode);
extern void printProcessInfo(int processPid);
extern void printHostEvents(HostTraffic *theHost, int, int);
extern void printThptStatsMatrix(int sortedColumn);

#ifdef HAVE_OPENSSL
extern int init_ssl();
extern int accept_ssl_connection(int fd);
extern void term_ssl_connection(int idx);
extern void term_ssl();
extern SSL* getSSLsocket(int fd);
extern int sslInitialized, sslPort;
#endif

/* Forward */
#ifdef HAVE_GDBM_H
extern void showUsers();
extern void addUser(char*);
extern void deleteUser(char*);
extern void doAddUser(int);
extern void showURLs();
extern void addURL(char*);
extern void deleteURL(char*);
extern void doAddURL(int);
#endif

/* main.c */
extern void printHTTPheader();
extern void printNoDataYet();
extern void closeNwSocket(int *sockId);
extern void initLogger();
extern void termLogger();
extern char* intoa(struct in_addr addr);
extern void loadPlugins();
extern void unloadPlugins();
extern void addDefaultAdminUser();
extern void cleanup_curses();
extern int  checkKeyPressed();
extern void returnHTTPaccessDenied();
extern void printTCPSessions();
extern void printUDPSessions();
extern void printIPpkt();
extern void printTCPpkt();
extern void handleHTTPrequest(struct in_addr from);
extern void clrscr();
extern void scanAllTcpExpiredRules();
extern void scanTimedoutTCPSessions();
extern void initIPServices();
extern void parseRules(char* path);
extern RETSIGTYPE _printHostsTraffic(int signumber_ignored);
extern RETSIGTYPE printHostsTraffic(int signumber_ignored, int reportType,
				    int sortedColumn, int revertOrder);

/* initialize.c */
void initIPServices();
void initCounters(int _mergeInterfaces);
void resetStats();
int initGlobalValues();
void postCommandLineArgumentsInitialization(time_t *lastTime);
void initGdbm();
void initThreads(int enableDBsupport);
void initApps();
void initDevices(char* devices);
void initRules(char *rulesFile);
void initLibpcap(char* rulesFile, int numDevices);
void initDeviceDatalink();
void parseTrafficFilter(char *argv[], int optind);
void initSignals();
void startSniffer();

extern time_t nextSessionTimeoutScan;
extern char *optarg;

extern char *version, *osName, *author, *buildDate;

extern ServiceEntry *udpSvc[SERVICE_HASH_SIZE], *tcpSvc[SERVICE_HASH_SIZE];
extern void updateThpt();
extern void LogStatsToFile();
extern void printLogHeader();
extern char* formatPkts(TrafficCounter pktNr);
extern void handleLocalAddresses(char* addresses);
extern void resetStats();
extern void processPacket(u_char * Id,
			  const struct pcap_pkthdr *h,
			  const u_char *p);
extern int checkCommand(char* commandName);
#ifdef MULTITHREADED
void* updateDBHostsTrafficLoop(void* notUsed);
#endif

/* *** SQL Engine *** */
extern void openSQLsocket(char* dstHost, int dstPort);
extern void closeSQLsocket();
extern void updateDbHostsTraffic();
/* ****************** */

#ifndef WIN32
extern void handleSigHup(int signalId);
extern void ignoreSignal(int signalId);
#endif

#ifdef MULTITHREADED
extern void* pcapDispatch(void *_i);
#endif

extern void handleFlowsSpecs(char* flows);
extern void initCurses();

extern void* handleCursesRefresh(void* notUsed);
extern void readLsofInfo();
extern void readNepedInfo();
extern int getLocalHostAddress(struct in_addr *hostAddress, char* dev);
#ifdef WIN32
extern short isWinNT();
#endif

/* Forwards */
extern RETSIGTYPE cleanup(int);
extern RETSIGTYPE handleDiedChild(int);
extern RETSIGTYPE dontFreeze(int);
extern void detachFromTerminal();
extern void daemonize();
extern void handleProtocols(char*);
extern void addDefaultProtocols();
extern short handleProtocol(char* protoName, char *protocol);
extern void handleProtocolList(char* protoName, char *protocolList);
extern void* handleWebConnections(void*);
#ifdef MULTITHREADED
extern void* updateThptLoop(void* notUsed);
extern void* scanIdleLoop(void* notUsed);
extern void* logFileLoop(void* notUsed);
extern void* periodicLsofLoop(void* notUsed);
#endif


/* main.c */
extern void printHTTPheader();
extern void printNoDataYet();
extern void closeNwSocket(int *sockId);
extern void initLogger();
extern void termLogger();
extern char* intoa(struct in_addr addr);
extern void loadPlugins();
extern void unloadPlugins();
extern void addDefaultAdminUser();
extern void init_counters();
extern void cleanup_curses();
extern int  checkKeyPressed();
extern void returnHTTPaccessDenied();
extern int  checkHTTPpassword(char *requestedURL, int lenURL, char* pw, int lenPw);
extern void printTCPSessions();
extern void printUDPSessions();
extern void printIPpkt();
extern void printTCPpkt();
extern void handleHTTPrequest();
extern void clrscr();
extern void scanAllTcpExpiredRules();
extern void scanTimedoutTCPSessions();
extern void initIPServices();
extern void parseRules(char* path);

extern RETSIGTYPE printHostsTraffic(int signumber_ignored, int reportType,
 				                    int sortedColumn, int revertOrder);

extern void updateThpt();
extern void LogStatsToFile();
extern void printLogHeader();
extern char* formatPkts(TrafficCounter pktNr);
extern void handleLocalAddresses(char* addresses);
extern void resetStats();
extern void processPacket(u_char* Id,
			  const struct pcap_pkthdr *h,
			  const u_char *p);
extern int checkCommand(char* commandName);
#ifdef MULTITHREADED
void* updateDBHostsTrafficLoop(void* notUsed);
#endif

/* *** SQL Engine *** */
extern void openSQLsocket(char* dstHost, int dstPort);
extern void closeSQLsocket();
extern void updateDbHostsTraffic();
/* ****************** */
extern void handleFlowsSpecs(char* flows);
extern void init_curses();
#ifdef MULTITHREADED
extern void* dequeuePacket(void*);
#ifdef ASYNC_ADDRESS_RESOLUTION
extern void queueAddress(struct hnamemem* elem, int elemLen);
extern void* dequeueAddress(void*);
#endif

void queuePacket(u_char * _deviceId, const struct pcap_pkthdr *h, const u_char *p);

extern void* handleCursesRefresh(void* notUsed);
#endif
extern void readLsofInfo();
extern void readNepedInfo();
extern int getLocalHostAddress(struct in_addr *hostAddress, char* dev);
#ifdef WIN32
extern short isWinNT();
#endif

/* Forwards */
RETSIGTYPE cleanup(int);
RETSIGTYPE handleDiedChild(int);
RETSIGTYPE dontFreeze(int);
void detachFromTerminal();
void daemonize();
void handleProtocols(char*);
void addDefaultProtocols();
short handleProtocol(char* protoName, char *protocol);
void handleProtocolList(char* protoName, char *protocolList);
void* handleWebConnections(void*);
#ifdef MULTITHREADED
void* updateThptLoop(void* notUsed);
void* scanIdleLoop(void* notUsed);
void* logFileLoop(void* notUsed);
void* periodicLsofLoop(void* notUsed);
#endif

/* ntop.c */
extern void sendString(char *x);
extern void logMessage(char* message, u_short severity);
extern void createVendorTable();
extern RETSIGTYPE cleanup(int signo);
extern void checkFilterChain(HostTraffic *srcHost, u_int srcHostIdx,
			     HostTraffic *dstHost, u_int dstHostIdx,
			     u_short sport, u_short dport,
			     u_int length,       /* packet length */
			     u_int hlen,         /* offset from packet header */
			     u_int8_t flags,     /* TCP flags or ICMP type */
			     u_char protocol,    /* Protocol */
			     u_char isFragment, /* 1 = fragment, 0 = packet */
			     const u_char* bp,   /* pointer to packet content */
			     FilterRuleChain *selectedChain,
			     u_short packetType);
extern void printHeader(int reportType, int revertOrder, u_int column);
extern void printHelp();
extern u_int16_t handleDNSpacket(const u_char*, u_short, DNSHostInfo *hostPtr, 
				 short len, short *isRequest, 
				 short *positiveReply);
extern char* getSpecialMacInfo(HostTraffic* el, short encodeString);
extern void printSession(IPSession *theSession, u_short sessionType,
			 u_short sessionCounter);
extern unsigned short isLocalAddress(struct in_addr *addr);
extern unsigned short isPseudoLocalAddress(struct in_addr *addr);
extern unsigned short isBroadcastAddress(struct in_addr *addr);
extern char* getHostOS(char* os, int port, char* additionalInfo);
extern int32_t gmt2local(time_t t);
extern int mapGlobalToLocalIdx(int port);
extern unsigned short isMulticastAddress(struct in_addr *addr);
extern void updateHostNameInfo(unsigned long numeric, char* symbolic);

extern char* llcsap_string(u_char sap);
extern char* etheraddr_string(const u_char *ep);
extern void extract_fddi_addrs(struct fddi_header *fddip,
			       char *fsrc, char *fdst);

/* *** SQL Engine *** */
extern void updateHostTraffic(HostTraffic *el);
extern void notifyHostCreation(HostTraffic *el);
extern void updateDBOSname(HostTraffic *el);
extern void updateDbHostsTraffic();
extern void notifyTCPSession(IPSession *session);

extern char* intoa(struct in_addr addr);

extern void processPacket(u_char *_deviceId,
			  const struct pcap_pkthdr *h,
			  const u_char *p);
extern char* savestr(const char *str);

extern void updateThpt();
extern void purgeIdleHosts(int);
extern void updatePacketCount(u_int srcHost, u_int dstHost, 
			      TrafficCounter length);
extern void purgeOldFragmentEntries();
extern void deleteFragment(IpFragment *fragment);

/* plugin.c */
extern void sendString(char *theString);

extern void sendString(char *theString);
extern char* getRowColor();
extern void printHTTPheader();

#ifdef AIX
char* dlerror();
#endif /* AIX */

#ifdef STATIC_PLUGIN
extern PluginInfo* icmpPluginEntryFctn();
extern PluginInfo* arpPluginEntryFctn();
extern PluginInfo* nfsPluginEntryFctn();
#endif


/* pbuf.c */
extern int findHostInfo(struct in_addr *hostIpAddress);
extern HostTraffic* findHostByMAC(char* macAddr);

/* report.c */
extern char* makeHostLink(HostTraffic *el, short mode, 
			  short cutName, short addCountryFlag);
extern void printHostEvents(HostTraffic *theHost, int, int);
extern void sendString(char *x);
extern void createVendorTable();
extern char* getVendorInfo(u_char* ethAddress, short);
extern char* getSAPInfo(u_int16_t sapInfo, short encodeString);
extern RETSIGTYPE cleanup(int signo);

extern void updateOSName(HostTraffic *el);
extern void updateThpt();
extern void ipaddr2str(struct in_addr hostIpAddress, char* outBuf, int outBufLen);
extern char* getPortByNum(int port, int type);
extern char* getAllPortByNum(int port);
extern void clrscr();
extern void init_curses();
extern char* getRowColor();
extern char* getActualRowColor();
extern unsigned short isLocalAddress(struct in_addr *addr);
extern unsigned short isPseudoLocalAddress(struct in_addr *addr);
extern unsigned short isBroadcastAddress(struct in_addr *addr);
extern char* intoa(struct in_addr addr);
extern void  quicksort(void *, size_t, size_t,
		       int (*)(const void *, const void *));
extern void printLogTime();
extern void printHTTPtrailer();
extern void printHTTPheader();
extern int checkKeyPressed();
extern u_int checkSessionIdx(u_int idx);

extern char* formatThroughput(float numBytes);
extern char* getHostName(HostTraffic *el, short cutName);
extern char* formatSeconds(unsigned long sec);
extern char* formatMicroSeconds(unsigned long microsec);
extern time_t delta_time_in_milliseconds(struct timeval * now,
					 struct timeval * before);

/* Forward */
void printNoDataYet();
char* getHostCountryIconURL(HostTraffic *el);
void fillDomainName(HostTraffic *el);
char* getCountryIconURL(char* hostName);
void printIpProtocolDistribution(int mode, int);
void printTableEntryPercentage(char *buf, int bufLen, char *label, char* label_1, 
			       char* label_2, float total, float percentage);
void printTableDoubleEntry(char *buf, int bufLen, char *label, char* color, 
			   float totalS, float percentageS, 
			   float totalR, float percentageR);
void printTableEntry(char *buf, int bufLen, char *label, char* color, 
		     float total, float percentage);
char* formatPkts(TrafficCounter pktNr);
void printBar(char *buf, int bufLen, unsigned short percentage,
	      unsigned short maxPercentage, unsigned short ratio);


/* rules.c */
extern void fireEvent(FilterRule *rule, HostTraffic *srcHost,
		      u_int srcHostIdx, HostTraffic *dstHost,
		      u_int dstHostIdx, short icmpType, u_short sport,
		      u_short dport,  u_int length);

extern int re_search (struct re_pattern_buffer *bufp,
		      const char *string,
		      int size, int startpos,
		      int range,
		      struct re_registers *regs);
extern int getPortByName(ServiceEntry **theSvc, char* portName);


/* sql.c */
extern char* formatBytes(TrafficCounter numBytes, short encodeString);
extern char* formatTime(time_t *theTime, short encodeString);
extern char* intoa(struct in_addr addr);
extern char* getVendorInfo(u_char* ethAddress, short encodeString);
extern u_int checkSessionIdx(u_int idx);


/* ssl.c */

#ifdef HAVE_OPENSSL
int verify_callback(int ok, X509_STORE_CTX *ctx);
#endif


/* util.c */
extern char* intoa(struct in_addr addr);
extern int strOnlyDigits(const char *s);

#ifdef WIN32
extern ULONG GetHostIPAddr();
#endif

extern int getAllPortByName(char* portName);
/* Forward */
int32_t gmt2local(time_t t);
unsigned short isPseudoBroadcastAddress(struct in_addr *addr);
unsigned short isPseudoLocalAddress(struct in_addr *addr);


extern u_int getHostInfo(struct in_addr *hostIpAddress,u_char *ether_addr);
extern u_int _checkSessionIdx(u_int idx, char* file, int line);
extern u_int computeInitialHashIdx(struct in_addr *hostIpAddress,
			    u_char *ether_addr, short* useIPAddressForSearching);
extern void sendStringLen(char *theString, unsigned int len);

#if defined(MULTITHREADED)
extern int createThread(pthread_t *threadId, void *(*__start_routine) (void *), 
			char* userParm);
extern int createCondvar(ConditionalVariable *condvarId);
extern int createThread(pthread_t *threadId, void *(*__start_routine) (void *), 
			char* userParm);
extern int createMutex(pthread_mutex_t *mutexId);

extern int _accessMutex(pthread_mutex_t *mutexId, char* where, char* fileName, int fileLine);
extern int _tryLockMutex(pthread_mutex_t *mutexId, char* where, char* fileName, int fileLine);
extern int _releaseMutex(pthread_mutex_t *mutexId, char* fileName, int fileLine);

#define accessMutex(a, b)  _accessMutex(a, b, __FILE__, __LINE__)
#define tryLockMutex(a, b) _tryLockMutex(a, b, __FILE__, __LINE__)
#define releaseMutex(a)    _releaseMutex(a, __FILE__, __LINE__)

extern int signalCondvar(ConditionalVariable *condvarId);
extern int waitCondvar(ConditionalVariable *condvarId);

void killThread(pthread_t *threadId);
void deleteMutex(pthread_mutex_t *mutexId);
void deleteCondvar(ConditionalVariable *condvarId);

#endif

extern HostTraffic* findHostByNumIP(char* numIPaddr);

extern char *copy_argv(char **);
extern int name_interpret(char *in, char *out);

extern void postCommandLineArgumentsInitialization(time_t *lastTime);
extern void initGdbm();
extern void initThreads(int enableDBsupport);
extern void initApps();
extern void initDevices(char*);
extern void initLibpcap(char* rulesFile, int numDevices);
extern void initDeviceDatalink();

extern char* getRowColor();
extern char* getActualRowColor();

extern void initWeb(int webPort, char* webAddr);

extern void packetCaptureLoop(time_t*, int);
extern void startSniffer();

extern int getActualInterface();
extern void checkSpoofing(u_int idxToCheck);
extern void smurfAlert(u_int srcHostIdx, u_int dstHostIdx);

extern char* formatKBytes(float numKBytes);
extern char* formatBytes(TrafficCounter numBytes, short encodeString);
extern char* formatSeconds(unsigned long sec);
extern char* formatThroughput(float numBytes);
extern char  formatStatus(HostTraffic *el);
extern char* formatTimeStamp(unsigned int ndays,
			     unsigned int nhours,
			     unsigned int nminutes);
extern char* formatPkts(TrafficCounter pktNr);

extern char* getNwInterfaceType(int i);
extern char* calculateCellColor(TrafficCounter actualValue,
				TrafficCounter avgTrafficLow,
				TrafficCounter avgTrafficHigh);
extern void termReports();
extern void emitEvent(FilterRule *rule,
		      HostTraffic *srcHost,
		      u_int srcHostIdx, 
		      HostTraffic *dstHost,
		      u_int dstHostIdx,
		      short icmpType,
		      u_short sport,
		      u_short dport);
extern void addPortHashEntry(ServiceEntry **theSvc, int port, char* name);
extern void updateTrafficMatrix(HostTraffic *srcHost,
				HostTraffic *dstHost,
				TrafficCounter length);

extern void storeHostTrafficInstance(HostTraffic *el);
extern HostTraffic* resurrectHostTrafficInstance(char *key);
extern void freeHostInstances();
extern void purgeIdleHostSessions(u_int hostIdx, 
				  IpGlobalSession **sessionScanner);

extern void cleanupAddressQueue();
extern void cleanupPacketQueue();
extern void termIPSessions();
extern void termIPServices();

/* *********************************** */

extern u_short traceLevel;
extern void traceEvent(int eventTraceLevel, char* file, 
		       int line, char * format, ...);

/* *********************************** */

extern void* ntop_malloc(unsigned int sz, char* file, int line);
extern char* ntop_strdup(char *str, char* file, int line);
extern void  ntop_free(void *ptr, char* file, int line);

#ifdef MEMORY_DEBUG 
#define malloc(a) ntop_malloc((unsigned int)a, __FILE__, __LINE__)
#define strdup(a) ntop_strdup((char*)a, __FILE__, __LINE__)
#define free(a)   ntop_free((void*)a, __FILE__, __LINE__)
#endif

extern u_short in_cksum(const u_short *addr, int len, u_short csum); 

#define checkSessionIdx(a) _checkSessionIdx(a, __FILE__, __LINE__)
     
extern void addTimeMapping(u_int16_t transactionId, struct timeval theTime);
extern time_t getTimeMapping(u_int16_t transactionId, struct timeval theTime);
extern void resizeHostHash(int deviceToExtend, float multiplier);
extern void notifyPluginsHashResize(u_int oldSize, u_int newSize, u_int* mappings);

extern FILE *sec_popen(char *cmd, const char *type);
