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

#ifdef HAVE_RRD_H
#include "rrd.h"
#endif

extern NtopGlobals myGlobals;

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
            *install_path;

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
extern int handleIP(u_short port,
		    HostTraffic *srcHost, HostTraffic *dstHost,
		    u_int length,  u_short isPassiveSession,
		    int actualDeviceId);
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
extern void setAdminPassword(char* pass);
extern void addDefaultAdminUser(void);

/* dataFormat.c */
extern char* formatKBytes(float numKBytes);
extern char* formatBytes(Counter numBytes, short encodeString);
extern char* formatLatency(struct timeval tv, u_short sessionState);
extern char* formatSeconds(unsigned long sec);
extern char* formatMicroSeconds(unsigned long microsec);
extern char* formatThroughput(float numBytes);
extern char* formatTimeStamp(unsigned int ndays, unsigned int nhours,
                             unsigned int nminutes);
extern char* formatPkts(Counter pktNr);

/* hash.c */
extern int retrieveHost(HostSerial theSerial, HostTraffic *el);
extern u_int computeInitialHashIdx(struct in_addr *hostIpAddress,
                                   u_char *ether_addr,
                                   short* useIPAddressForSearching, int actualDeviceId);
extern void freeHostInfo(int theDevice, HostTraffic *host, int actualDeviceId);
extern void freeHostInstances(int actualDeviceId);
extern void purgeIdleHosts(int devId);

/* http.c */
extern void sendStringLen(char *theString, unsigned int len);
extern void sendString(char *theString);
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
extern void resetDevice(int devIdx);
extern void initCounters(void);
extern void resetStats(void);
extern int initGlobalValues(void);
extern void initGdbm(char *directory);
extern void initThreads(void);
extern void initApps(void);
extern void initDevices(char* devices);
extern void initLibpcap(void);
extern void initDeviceDatalink(void);
extern void parseTrafficFilter(void);
extern void initSignals(void);
extern void startSniffer(void);
extern void deviceSanityCheck(char* string);
extern u_int createDummyInterface(char *ifName);

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
extern void handleSigHup(int signalId);
extern void *pcapDispatch(void *_i);
extern RETSIGTYPE handleDiedChild(int);
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
extern u_int findHostIdxByNumIP(struct in_addr hostIpAddress, int actualDeviceId);
extern u_int getHostInfo(struct in_addr *hostIpAddress, u_char *ether_addr, 
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
extern void updateTrafficMatrix(HostTraffic *srcHost, HostTraffic *dstHost,
                                TrafficCounter length, int actualDeviceId);
extern void updateDbHostsTraffic(int deviceToUpdate);
extern int isInitialHttpData(char* packetData);
extern int isInitialSshData(char* packetData);
extern int isInitialFtpData(char* packetData);
extern void updateDeviceThpt(int deviceToUpdate);

/* util.c */
extern void incrementTrafficCounter(TrafficCounter *ctr, Counter value);
extern void resetTrafficCounter(TrafficCounter *ctr);
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
extern void handleFlowsSpecs();
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
extern int fetchPrefsValue(char *key, char *value, int valueLen);
extern void storePrefsValue(char *key, char *value);
extern int guessHops(HostTraffic *el);
extern int ntop_sleep(int secs);
extern void unescape(char *dest, int destLen, char *url);
extern void updateElementHash(ElementHash **list, u_short srcId, u_short dstId, 
			      u_int32_t numPkts, u_int32_t numBytes);
extern void allocateElementHash(int deviceId, u_short hashType);

/* vendor.c */
extern char* getVendorInfo(u_char* ethAddress, short encodeString);
extern char* getSAPInfo(u_int16_t sapInfo, short encodeString);
extern char* getSpecialMacInfo(HostTraffic* el, short encodeString);
extern void createVendorTable(void);

#if defined(AIX) || defined(WIN32)
extern int snprintf(char *str, size_t n, const char *fmt, ...);
#endif

/* netflow.c */
extern void termNetFlowExporter();
extern void sendICMPflow(HostTraffic *srcHost, HostTraffic *dstHost, u_int length, u_int actualDeviceId);
extern void sendUDPflow(HostTraffic *srcHost, HostTraffic *dstHost, 
			u_int sport, u_int dport, u_int length, u_int actualDeviceId);
extern void sendTCPSessionFlow(IPSession *theSession, int actualDeviceId);
extern void sendOTHERflow(HostTraffic *srcHost, HostTraffic *dstHost, 
			  u_int8_t proto, u_int length, u_int actualDeviceId);

/* globals-core.c */
void initNtopGlobals(int argc, char * argv[]);

/* sessions.c */
#define checkSessionIdx(a) _checkSessionIdx(a, actualDeviceId, __FILE__, __LINE__)
extern u_int _checkSessionIdx(u_int idx, int actualDeviceId, char* file, int line);
extern void freeSession(IPSession *sessionToPurge, int actualDeviceId, u_char allocateMemoryIfNeeded);
extern void scanTimedoutTCPSessions(int actualDeviceId);
extern void updateUsedPorts(HostTraffic *srcHost, HostTraffic *dstHost,
			    u_short sport, u_short dport, u_int length);

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

