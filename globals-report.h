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

#ifdef HAVE_GDCHART
#ifndef _GRAPH_C_
#define GDC_LIB
#endif
#include "gdc.h"
#include "gdchart.h"
#include "gdcpie.h"
#endif

#ifdef HTML_EXPERIMENTAL
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

#ifdef WIN32
#define CHART_FORMAT ".gif"
#define MIME_TYPE_CHART_FORMAT HTTP_TYPE_GIF
#else
#define CHART_FORMAT ".png"
#define MIME_TYPE_CHART_FORMAT HTTP_TYPE_PNG
#endif

/*
  Courtesy of
  Peter Marquardt <wwwutz@mpimg-berlin-dahlem.mpg.de>
*/
#define SD(a,b) ((b)?((float)a)/(b):0)

#ifndef MICRO_NTOP

/* reportUtils.c */
extern int retrieveHost(HostSerial theSerial, HostTraffic *el);
extern void formatUsageCounter(UsageCounter usageCtr, TrafficCounter maxValue, int actualDeviceId);
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
extern char* getOSFlag(char* osName, int showOsName);
extern int sortHostFctn(const void *_a, const void *_b);
extern int cmpUsersTraffic(const void *_a, const void *_b);
extern int cmpProcesses(const void *_a, const void *_b);
extern int cmpFctn(const void *_a, const void *_b);
extern int cmpMulticastFctn(const void *_a, const void *_b);
extern void printHostThtpShort(HostTraffic *el, short dataSent);
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
extern void printServiceStats(char* svcName, ServiceStats* ss,
			      short printSentStats);
extern void printHostUsedServices(HostTraffic *el, int actualDeviceId);
extern void printTableEntry(char *buf, int bufLen,
			    char *label, char* color,
			    float total, float percentage);
extern char* buildHTMLBrowserWindowsLabel(int i, int j);
extern int cmpEventsFctn(const void *_a, const void *_b);
extern void printHostHourlyTrafficEntry(HostTraffic *el, int i,
					TrafficCounter tcSent, 
					TrafficCounter tcRcvd);
extern char* getNbNodeType(char nodeType);
extern void dumpNtopHashes(FILE*, char*, int actualDeviceId);
extern void dumpNtopHashIndexes(FILE*, char* options, int actualDeviceId);
extern void dumpNtopTrafficInfo(FILE*, char* options);

/* report.c */
extern void initReports(void);
extern int reportValues(time_t *lastTime);
extern void printHostsTraffic(int reportType,
			      int sortedColumn, int revertOrder,
			      int pageNum, char* url);
extern void printMulticastStats(int sortedColumn /* ignored so far */,
                                int revertOrder, int pageNum);
extern void addPageIndicator(char *url, u_int beginIdx,
			     u_int numEntries, u_int linesPerPage,
			     int revertOrder, int numCol);
extern void printTrafficStatistics();
extern void printHostsInfo(int sortedColumn, int revertOrder, int pageNum);
extern void printAllSessionsHTML(char* host, int actualDeviceId);
extern void printLocalRoutersList(int actualDeviceId);
extern void printIpAccounting(int remoteToLocal, int sortedColumn,
			      int revertOrder, int pageNum);
extern void printHTMLtrailer(void);
extern void returnHTTPredirect(char* destination);
extern void printActiveTCPSessions(int actualDeviceId, int pageNum);
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
extern void printNtopConfigInfo(void);
extern void updateHostThpt(HostTraffic *el, int hourId, int fullUpdate);

/* webInterface.c */
extern void execCGI(char* cgiName);
extern void showPluginsList(char* pluginName);
/* CHECK ME: loadPlugins() and unloadPlugins() should not be in webInterface.c */
extern void initWeb(int webPort, char* webAddr, char* sslAddr);
extern char *calculateCellColor(TrafficCounter actualValue,
                                TrafficCounter avgTrafficLow,
                                TrafficCounter avgTrafficHigh);
extern char *getCountryIconURL(char* domainName);
extern char *getHostCountryIconURL(HostTraffic *el);
extern char *getActualRowColor(void);
extern void switchNwInterface(int _interface);
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

/* **************************** */

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
#define CGI_HEADER                      "ntop-bin/"
#define STR_SHOW_PLUGINS                "showPlugins.html"
#define SHUTDOWN_NTOP_HTML              "shutdown.html"
#define INFO_NTOP_HTML                  "info.html"
#define TRAFFIC_STATS_HTML              "trafficStats.html"
#define NW_EVENTS_HTML                  "networkEvents.html"
#define STR_SORT_DATA_RCVD_HOST_TRAFFIC "dataRcvdHostTraffic.html"
#define STR_SORT_DATA_SENT_HOST_TRAFFIC "dataSentHostTraffic.html"
#define SWITCH_NIC_HTML                 "switch.html"
#define CHANGE_FILTER_HTML              "changeFilter.html"
#define FILTER_INFO_HTML                "filterInfo.html"

/* Courtesy of Daniel Savard <daniel.savard@gespro.com> */
#define RESET_STATS_HTML              "resetStats.html"
#endif

/* http.c */
extern void sendHTTPHeader(int mimeType, int headerFlags);

#define STR_INDEX_HTML                  "index.html"
#define PLUGINS_HEADER                  "plugins/"
#define DUMP_DATA_HTML                  "dumpData.html"
#define DUMP_TRAFFIC_DATA_HTML          "dumpTrafficData.html"
#define DUMP_HOSTS_INDEXES_HTML         "dumpDataIndexes.html"

/* webInterface.c */
extern void *handleWebConnections(void* notUsed);
extern char *getRowColor(void);
extern char *makeHostLink(HostTraffic *el, short mode,
                          short cutName, short addCountryFlag);

extern char *getHostName(HostTraffic *el, short cutName);
