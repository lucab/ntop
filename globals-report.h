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

#ifdef HAVE_GDCHART
#ifndef _GRAPH_C_
#define GDC_LIB
#endif
#include "gdc.h"
#include "gdchart.h"
#include "gdcpie.h"
#endif

#ifdef EXPERIMENTAL
#define TABLE_ON  "<TABLE BGCOLOR=#999999 CELLSPACING=1 CELLPADDING=1 BORDER=0><TR><TD>"
#define TABLE_OFF "</TD></TR></TABLE>"
#define TH_BG     "BGCOLOR=#FFFFFF"
#define TD_BG     "BGCOLOR=#FFFFFF"
#else
#define TABLE_ON  ""
#define TABLE_OFF ""
#define TH_BG     ""
#define TD_BG     ""
#endif

/*
  Courtesy of
  Peter Marquardt <wwwutz@mpimg-berlin-dahlem.mpg.de>
*/
#define SD(a,b) ((b)?((float)a)/(b):0)

/* #define PRINT_PKTS                 */
/* #define PRINT_ALL_ACTIVE_SESSIONS  */
/* #define PRINT_RETRANSMISSION_DATA  */

extern int maxNumLines, idleFlag, percentMode, localAddrFlag, refreshRate;
extern int webPort, actualReportDeviceId;
extern int sortSendMode, sortSendMode;
extern short sortFilter;

extern int sock, newSock;
#ifdef HAVE_OPENSSL
extern int sock_ssl;
#endif

extern short screenNumber, columnSort;

/* Threads */
#ifdef MULTITHREADED
extern pthread_t logFileLoopThreadId;
#endif

/* reportUtils.c */
extern void formatUsageCounter(UsageCounter usageCtr);
extern void printTableDoubleEntry(char *buf, int bufLen,
				  char *label, char* color,
				  float totalS, float percentageS,
				  float totalR, float percentageR);
extern void printTableEntryPercentage(char *buf, int bufLen,
				      char *label, char* label_1,
				      char* label_2, float total,
				      float percentage);
extern void printHeader(int reportType, int revertOrder, u_int column);
extern char* getOSFlag(char* osName, int showOsName);
extern int sortHostFctn(const void *_a, const void *_b);
extern int cmpUsersTraffic(const void *_a, const void *_b);
extern int cmpProcesses(const void *_a, const void *_b);
extern int cmpFctn(const void *_a, const void *_b);
extern int cmpMulticastFctn(const void *_a, const void *_b);
extern void getProtocolDataSent(TrafficCounter *c,
				TrafficCounter *d,
				TrafficCounter *e,
				HostTraffic *el);
extern void getProtocolDataReceived(TrafficCounter *c,
				    TrafficCounter *d,
				    TrafficCounter *e,
				    HostTraffic *el);
extern void printHostThtpShort(HostTraffic *el, short dataSent);
extern int cmpHostsFctn(const void *_a, const void *_b);
extern void printTCPflagsStats(HostTraffic *el);
extern void printHostTrafficStats(HostTraffic *el);
extern void printHostContactedPeers(HostTraffic *el);
extern char *getSessionState(IPSession *session);
extern void printHostSessions(HostTraffic *el, u_int elIdx);
extern void printHostDetailedInfo(HostTraffic *el);
extern void printServiceStats(char* svcName, ServiceStats* ss,
			      short printSentStats);
extern void printHostUsedServices(HostTraffic *el);
extern void printTableEntry(char *buf, int bufLen,
			    char *label, char* color,
			    float total, float percentage);
extern char* buildHTMLBrowserWindowsLabel(int i, int j);
extern int cmpEventsFctn(const void *_a, const void *_b);
extern char* getBgPctgColor(float pctg);
extern void printHostHourlyTrafficEntry(HostTraffic *el, int i,
					TrafficCounter tcSent, 
					TrafficCounter tcRcvd);
extern char* getNbNodeType(char nodeType);


/* report.c */
extern void initReports(void);
extern void termReports(void);
extern int reportValues(time_t *lastTime);
extern RETSIGTYPE printHostsTraffic(int signumber_ignored, int reportType,
                                    int sortedColumn, int revertOrder);
extern void printMulticastStats(int sortedColumn /* ignored so far */,
                                int revertOrder);
extern RETSIGTYPE printHostsInfo(int sortedColumn, int revertOrder);
extern void printAllSessionsHTML(char* host);
extern void printLocalRoutersList(void);
extern void printSession(IPSession *theSession, u_short sessionType,
                         u_short sessionCounter);
extern RETSIGTYPE printIpAccounting(int remoteToLocal, int sortedColumn,
                                    int revertOrder);
extern void printActiveTCPSessions(void);
extern void printIpProtocolUsage(void);
extern void printBar(char *buf, int bufLen, unsigned short percentage,
                     unsigned short maxPercentage, unsigned short ratio);
extern void printIpProtocolDistribution(int mode, int revertOrder);
extern void printProtoTraffic(void);
extern void printProcessInfo(int processPid);
extern void printLsofData(int mode);
extern void printIpTrafficMatrix(void);
extern void printThptStatsMatrix(int sortedColumn);
extern void printThptStats(int sortedColumn);
extern void printDomainStats(char* domainName, int sortedColumn, int revertOrder);
extern void printLogHeader(void);
extern void printNoDataYet(void);
extern void listNetFlows(void);
extern void printHostEvents(HostTraffic *theHost, int column, int revertOrder);
extern void fillDomainName(HostTraffic *el);
extern void printNtopConfigInfo(void);
extern void updateHostThpt(HostTraffic *el, int hourId, int fullUpdate);

/* webInterface.c */
extern void initializeWeb(void);
extern void *handleWebConnections(void* notUsed);
extern void execCGI(char* cgiName);
extern void showPluginsList(char* pluginName);
/* CHECK ME: loadPlugins() and unloadPlugins() should not be in webInterface.c */
extern void initWeb(int webPort, char* webAddr);
extern char *makeHostLink(HostTraffic *el, short mode,
                          short cutName, short addCountryFlag);
extern char *getHostName(HostTraffic *el, short cutName);
extern char *calculateCellColor(TrafficCounter actualValue,
                                TrafficCounter avgTrafficLow,
                                TrafficCounter avgTrafficHigh);
extern char *getCountryIconURL(char* domainName);
extern char *getHostCountryIconURL(HostTraffic *el);
extern char *getRowColor(void);
extern char *getActualRowColor(void);
extern void switchNwInterface(int _interface);
extern void usage(void);
extern void shutdownNtop(void);
extern void printHostHourlyTraffic(HostTraffic *el);

#ifdef HAVE_GDCHART

#ifndef _GLOBALS_REPORT_C_
#define GDC_LIB
#endif

#include "gdc.h"
#include "gdchart.h"

/*
  Fix courtesy of  
  Michael Wescott <wescott@crosstor.com>
*/
#ifndef _GLOBALS_CORE_C_
#undef clrallocate
#undef clrshdallocate
#endif

#include "gdcpie.h"


extern char GDC_yaxis;
extern char* GDC_ylabel_fmt;

extern int out_graph(short gifwidth,
		     short gifheight,
		     FILE  *gif_fptr,
		     GDC_CHART_T type,
		     int  num_points,
		     char *xlbl[],
		     int  num_sets,
		     ... );
#endif

extern FILE* getNewRandomFile(char* fileName, int len);

/* **************************** */

#define STR_INDEX_HTML                  "index.html"
#define STR_SORT_DATA_RECEIVED_PROTOS   "sortDataReceivedProtos.html"
#define STR_SORT_DATA_RECEIVED_IP       "sortDataReceivedIP.html"
#define STR_SORT_DATA_RECEIVED_THPT     "sortDataReceivedThpt.html"
#define STR_SORT_DATA_SENT_PROTOS       "sortDataSentProtos.html"
#define STR_SORT_DATA_SENT_IP           "sortDataSentIP.html"
#define STR_SORT_DATA_SENT_THPT         "sortDataSentThpt.html"
#define STR_SORT_DATA_THPT_STATS        "thptStats.html"
#define STR_THPT_STATS_MATRIX           "thptStatsMatrix.html"
#define STR_DOMAIN_STATS                "domainTrafficStats.html"
#define STR_MULTICAST_STATS             "multicastStats.html"
#define HOSTS_INFO_HTML                 "hostsInfo.html"
#define STR_LSOF_DATA                   "lsofData.html"
#define PROCESS_INFO_HTML               "processInfo.html"
#define IP_R_2_L_HTML                   "IpR2L.html"
#define IP_L_2_R_HTML                   "IpL2R.html"
#define IP_L_2_L_HTML                   "IpL2L.html"
#define DOMAIN_INFO_HTML                "domainInfo"
#define CGI_HEADER                      "cgi/"
#define PLUGINS_HEADER                  "plugins/"
#define STR_SHOW_PLUGINS                "showPlugins.html"
#define SHUTDOWN_NTOP_HTML              "shutdown.html"
#define INFO_NTOP_HTML                  "info.html"
#define TRAFFIC_STATS_HTML              "trafficStats.html"
#define NW_EVENTS_HTML                  "networkEvents.html"
#define STR_SORT_DATA_RCVD_HOST_TRAFFIC "dataRcvdHostTraffic.html"
#define STR_SORT_DATA_SENT_HOST_TRAFFIC "dataSentHostTraffic.html"

/* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
#define RESET_STATS_HTML              "resetStats.html"


