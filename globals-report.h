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

#ifdef  PARM_ENABLE_EXPERIMENTAL
#define TABLE_ON  "<TABLE BGCOLOR=#999999 CELLSPACING=1 CELLPADDING=1 BORDER=0><TR><TD>"
#define TABLE_OFF "</TD></TR></TABLE>"
#define TH_BG     "BGCOLOR=#DDDDDD"
#define TD_BG     "BGCOLOR=#DDDDDD"
#define TR_ON     "onmouseover=\"setPointer(this, '#CCFFCC', '#DDDDDD')\" onmouseout=\"setPointer(this, '#DDDDDD', '#DDDDDD')\""
#else
#define TABLE_ON  ""
#define TABLE_OFF ""
#define TH_BG     ""
#define TD_BG     ""
#define TR_ON     ""
#endif

#ifdef WIN32
#define CHART_FORMAT ".gif"
#define MIME_TYPE_CHART_FORMAT FLAG_HTTP_TYPE_GIF
#else
#define CHART_FORMAT ".png"
#define MIME_TYPE_CHART_FORMAT FLAG_HTTP_TYPE_PNG
#endif

/*
  Courtesy of
  Peter Marquardt <wwwutz@mpimg-berlin-dahlem.mpg.de>
*/
#define SD(a,b) ((b)?((float)a)/(b):0)

/* reportUtils.c */
extern void formatUsageCounter(UsageCounter usageCtr, Counter maxValue, int actualDeviceId);
extern void printTableDoubleEntry(char *buf, int bufLen,
				  char *label, char* color,
				  float totalS, float percentageS,
				  float totalR, float percentageR);
extern void printTableEntryPercentage(char *buf, int bufLen,
				      char *label, char* label_1,
				      char* label_2, float total,
				      float percentage);
extern void printSectionTitle(char *text);
extern void printFlagedWarning(char *text);
extern void printHeader(int reportType, int revertOrder, u_int column);
extern void printFooterHostLink(void);
extern void printFooter(int reportType);
extern char* getOSFlag(HostTraffic *el, char *_osName, int showOsName, char *tmpStr, int tmpStrLen);
extern int sortHostFctn(const void *_a, const void *_b);
extern int cmpUsersTraffic(const void *_a, const void *_b);
extern int cmpProcesses(const void *_a, const void *_b);
extern int cmpFctn(const void *_a, const void *_b);
extern int cmpMulticastFctn(const void *_a, const void *_b);
extern void printHostThtpShort(HostTraffic *el, int reportType);
extern int cmpHostsFctn(const void *_a, const void *_b);
extern void printPacketStats(HostTraffic *el, int actualDeviceId);
extern void printHostTrafficStats(HostTraffic *el, int actualDeviceId);
extern void printHostFragmentStats(HostTraffic *el, int actualDeviceId);
extern void printTotalFragmentStats(HostTraffic *el, int actualDeviceId);
extern void printHostContactedPeers(HostTraffic *el, int actualDeviceId);
extern char *getSessionState(IPSession *session);
extern void printHostSessions(HostTraffic *el, u_int elIdx, int actualDeviceId);
extern u_short isHostHealthy(HostTraffic *el);
extern void printHostDetailedInfo(HostTraffic *el, int actualDeviceId);
extern void printServiceStats(char* svcName, ServiceStats* ss, short printSentStats);
extern void printHostUsedServices(HostTraffic *el, int actualDeviceId);
extern void printHostIcmpStats(HostTraffic *el);
extern void printTableEntry(char *buf, int bufLen,
			    char *label, char* color,
			    float total, float percentage);
extern char* buildHTMLBrowserWindowsLabel(int i, int j);
extern int cmpEventsFctn(const void *_a, const void *_b);
extern void printHostHourlyTrafficEntry(HostTraffic *el, int i,
					Counter tcSent, Counter tcRcvd);
extern char* getNbNodeType(char nodeType);
extern void dumpNtopFlows(FILE *fDescr, char* options, int actualDeviceId);
extern void dumpNtopHashes(FILE*, char*, int actualDeviceId);
extern void dumpNtopHashIndexes(FILE*, char* options, int actualDeviceId);
extern void dumpNtopTrafficInfo(FILE*, char* options);
extern void dumpNtopTrafficMatrix(FILE *fDescr, char* options, int actualDeviceId);
extern void checkHostProvidedServices(HostTraffic *el);
extern void dumpElementHash(ElementHash **theHash, char* label, u_char dumpLoopbackTraffic);
extern void printLocalHostsStats();
#ifdef CFG_MULTITHREADED
extern void printMutexStatus(int textPrintFlag, PthreadMutex *mutexId, char *mutexName);
#endif

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
#ifdef HAVE_OPENSSL
extern char* printSSLError(int errorId);
#endif /* HAVE_OPENSSL */
extern void returnHTTPbadRequest();
extern void returnHTTPaccessDenied();
extern void returnHTTPaccessForbidden();
extern void returnHTTPpageNotFound();
extern void returnHTTPpageGone();
extern void returnHTTPrequestTimedOut();
extern void returnHTTPnotImplemented();
extern void returnHTTPversionNotSupported();

/* report.c */
extern void initReports(void);
extern int reportValues(time_t *lastTime);
extern int haveTrafficHistory();
extern void printHostsTraffic(int reportType,
			      int sortedColumn, int revertOrder,
			      int pageNum, char* url);
extern void printMulticastStats(int sortedColumn /* ignored so far */,
                                int revertOrder, int pageNum);
extern void addPageIndicator(char *url, u_int beginIdx,
			     u_int numEntries, u_int linesPerPage,
			     int revertOrder, int numCol);
extern void printTrafficStatistics();
extern void printVLANList(unsigned int deviceId);
extern void printHostsInfo(int sortedColumn, int revertOrder, int pageNum);
extern void printAllSessionsHTML(char* host, int actualDeviceId);
extern void printLocalRoutersList(int actualDeviceId);
extern void printIpAccounting(int remoteToLocal, int sortedColumn,
			      int revertOrder, int pageNum);
extern void printHTMLtrailer(void);
extern void returnHTTPredirect(char* destination);
extern void printActiveTCPSessions(int actualDeviceId, int pageNum, HostTraffic *el);
extern void printIpProtocolUsage(void);
extern void printBar(char *buf, int bufLen, unsigned short percentage,
                     unsigned short maxPercentage, unsigned short ratio);
extern void printIpProtocolDistribution(int mode, int revertOrder);
extern void printProtoTraffic(void);
extern void printProcessInfo(int processPid, int actualReportDeviceId);
extern void printLsofData(int mode);
extern void printIpTrafficMatrix(void);
extern void printThptStatsMatrix(int sortedColumn);
extern void printThptStats(int sortedColumn);
extern void printDomainStats(char* domainName, int sortedColumn, int revertOrder, int pageNum);
extern void printNoDataYet(void);
extern void printNotAvailable(void);
extern void listNetFlows(void);
extern void fillDomainName(HostTraffic *el);
extern void printHostHTTPVirtualHosts(HostTraffic *el, int actualDeviceId);
extern void printASList(unsigned int deviceId);
extern void showPortTraffic(u_short portNr);

/* webInterface.c */
extern int execCGI(char* cgiName);
extern void showPluginsList(char* pluginName);
/* CHECK ME: loadPlugins() and unloadPlugins() should not be in webInterface.c */
extern void initWeb();
extern char *calculateCellColor(Counter actualValue, Counter avgTrafficLow, Counter avgTrafficHigh);
extern char *getCountryIconURL(char* domainName, u_short fullDomainNameIsFallback);
extern char *getHostCountryIconURL(HostTraffic *el);
extern char *getActualRowColor(void);
extern void switchNwInterface(int _interface);
extern void shutdownNtop(void);
extern void printHostHourlyTraffic(HostTraffic *el);
extern void printNtopConfigHInfo(int textPrintFlag);
extern void printNtopConfigInfo(int textPrintFlag);
extern void printNtopProblemReport(void);
#ifdef MAKE_WITH_SSLWATCHDOG
extern int sslwatchdogWaitFor(int stateValue, int parentchildFlag, int alreadyLockedFlag);
extern int sslwatchdogClearLock(int parentchildFlag);
extern int sslwatchdogGetLock(int parentchildFlag);
extern int sslwatchdogSignal(int parentchildFlag);
extern int sslwatchdogSetState(int stateNewValue, int parentchildFlag, int enterLockedFlag, int exitLockedFlag);
extern void sslwatchdogSighandler(int signum);
extern void* sslwatchdogChildThread(void* notUsed _UNUSED_);
#endif

/* **************************** */

#define TRAFFIC_STATS                   0
#define SORT_DATA_RECEIVED_PROTOS       1
#define SORT_DATA_RECEIVED_IP           2
#define SORT_DATA_RECEIVED_THPT         3
#define SORT_DATA_RCVD_HOST_TRAFFIC     4
#define SORT_DATA_SENT_PROTOS           5
#define SORT_DATA_SENT_IP               6
#define SORT_DATA_SENT_THPT             7
#define SORT_DATA_SENT_HOST_TRAFFIC     8
#define SORT_DATA_PROTOS                9
#define SORT_DATA_IP                    10
#define SORT_DATA_THPT                  11
#define SORT_DATA_HOST_TRAFFIC          12

#define STR_SORT_DATA_RECEIVED_PROTOS   "sortDataReceivedProtos.html"
#define STR_SORT_DATA_RECEIVED_IP       "sortDataReceivedIP.html"
#define STR_SORT_DATA_RECEIVED_THPT     "sortDataReceivedThpt.html"
#define STR_SORT_DATA_RCVD_HOST_TRAFFIC "dataRcvdHostTraffic.html"
#define STR_SORT_DATA_SENT_PROTOS       "sortDataSentProtos.html"
#define STR_SORT_DATA_SENT_IP           "sortDataSentIP.html"
#define STR_SORT_DATA_SENT_THPT         "sortDataSentThpt.html"
#define STR_SORT_DATA_SENT_HOST_TRAFFIC "dataSentHostTraffic.html"
#define STR_SORT_DATA_PROTOS            "sortDataProtos.html"
#define STR_SORT_DATA_IP                "sortDataIP.html"
#define STR_SORT_DATA_THPT              "sortDataThpt.html"
#define STR_SORT_DATA_HOST_TRAFFIC      "dataHostTraffic.html"

#define STR_SORT_DATA_THPT_STATS        "thptStats.html"
#define STR_THPT_STATS_MATRIX           "thptStatsMatrix.html"
#define STR_DOMAIN_STATS                "domainTrafficStats.html"
#define STR_MULTICAST_STATS             "multicastStats.html"
#define HOSTS_INFO_HTML                 "hostsInfo.html"
#define HOSTS_LOCAL_INFO_HTML           "localHostsInfo.html"
#define STR_LSOF_DATA                   "lsofData.html"
#define SHOW_PORT_TRAFFIC               "showPortTraffic.html"
#define PROCESS_INFO_HTML               "processInfo.html"
#define IP_R_2_L_HTML                   "IpR2L.html"
#define IP_L_2_R_HTML                   "IpL2R.html"
#define IP_L_2_L_HTML                   "IpL2L.html"
#define IP_R_2_R_HTML                   "IpR2R.html"
#define DOMAIN_INFO_HTML                "domainInfo"
#define CGI_HEADER                      "ntop-bin/"
#define STR_SHOW_PLUGINS                "showPlugins.html"
#define SHUTDOWN_NTOP_HTML              "shutdown.html"
#define INFO_NTOP_HTML                  "info.html"
#define TEXT_INFO_NTOP_HTML             "textinfo.html"
#define TRAFFIC_STATS_HTML              "trafficStats.html"
#define NW_EVENTS_HTML                  "networkEvents.html"
#define SWITCH_NIC_HTML                 "switch.html"
#define CHANGE_FILTER_HTML              "changeFilter.html"
#define FILTER_INFO_HTML                "filterInfo.html"
#define STR_PROBLEMRPT_HTML             "ntopProblemReport.html"

/* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
#define RESET_STATS_HTML              "resetStats.html"

#define STR_W3C_P3P_XML                 "w3c/p3p.xml"
#define STR_NTOP_P3P                    "ntop.p3p"

/* http.c */
extern void sendHTTPHeader(int mimeType, int headerFlags);
extern void returnHTTPbadRequest();
extern void returnHTTPaccessDenied();
extern void returnHTTPaccessForbidden();
extern void returnHTTPpageNotFound();
extern void returnHTTPpageGone();
extern void returnHTTPrequestTimedOut();
extern void returnHTTPnotImplemented();
extern void returnHTTPversionNotSupported();

#define STR_FAVICON_ICO                 "favicon.ico"
#define STR_INDEX_HTML                  "index.html"
#define PLUGINS_HEADER                  "plugins/"
#define DUMP_DATA_HTML                  "dumpData.html"
#define DUMP_TRAFFIC_DATA_HTML          "dumpTrafficData.html"
#define DUMP_HOSTS_INDEXES_HTML         "dumpDataIndexes.html"
#define DUMP_NTOP_FLOWS_HTML            "dumpFlows.html"
#define DUMP_NTOP_HOSTS_MATRIX_HTML     "dumpHostsMatrix.html"

#ifdef MAKE_WITH_XMLDUMP
 #define DUMP_NTOP_XML                  "dump.xml"
#endif

/* webInterface.c */
extern void *handleWebConnections(void* notUsed);
extern char *getRowColor(void);
extern char *makeHostLink(HostTraffic *el, short mode,
                          short cutName, short addCountryFlag);

extern char *getHostName(HostTraffic *el, short cutName);

/* graph.c */
extern void sendGraphFile(char* fileName, int doNotUnlink);
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
extern int  drawHostsDistanceGraph(int);
extern void drawGlobalIpProtoDistribution(void);
extern void drawBar(short width, short height, FILE* filepointer,
		    int   num_points, char  *labels[], float data[]);
extern void drawArea(short width, short height, FILE* filepointer,
		     int   num_points, char  *labels[], float data[]);
extern void drawPie(short width, short height, FILE* filepointer,
		    int   num_points, char  *labels[], float data[]);

/* xmldump.c */
extern int dumpXML(int dumpToFile, char * parms);
