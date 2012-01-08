/*
 *  Copyright (C) 2002-12 Luca Deri <deri@ntop.org>
 *
 *  		       http://www.ntop.org/
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

/*
  Aberrant RRD Behavior (http://cricket.sourceforge.net/aberrant/)
  patch courtesy of Dominique Karg <dk@ipsoluciones.com>
*/

#include "rrdPlugin.h"

#ifndef _GETOPT_H
#define _GETOPT_H
#endif

#define NTOP_WATERMARK "NTOP / LUCA DERI"

#define RRD_GRAPH_SIZE        16

#define MAX_NUM_ENTRIES   32
#define MAX_BUF_LEN       384

static u_char debug_rrd_graph = 0;
static char *rrdd_sock_path = NULL;
#ifdef WIN32
static char* rrdVolatilePath;
#endif

#if defined(RRD_DEBUG)
#define traceEventRRDebug(level, ...) { if(RRD_DEBUG >= level)				\
      traceEvent(CONST_TRACE_NOISY, "RRD_DEBUG: " __VA_ARGS__); 			\
  }

#define traceEventRRDebugARGV(level)  { if(RRD_DEBUG >= level) {			\
      int _iARGV;									\
      for(_iARGV=0; _iARGV<argc; _iARGV++) {						\
	traceEvent(CONST_TRACE_NOISY, "RRD_DEBUG: argv[%d] = %s", _iARGV, argv[_iARGV]); \
      }											\
    }											\
  }
#endif

/* ******************************************** */

#ifdef WIN32
int optind, opterr;
unsigned long driveSerial;
#else
static u_short dumpPermissions;
#endif

static PthreadMutex rrdMutex;
static pthread_t rrdThread, rrdTrafficThread;

static unsigned short initialized = 0, active = 0, colorWarn = 0, graphErrCount = 0,
  dumpInterval, dumpShortInterval, dumpDetail, dumpHeartbeatMultiplier;
static unsigned short dumpDays, dumpHours, dumpMonths, dumpDelay;
static char *hostsFilter = NULL;
static Counter numRRDUpdates = 0, numTotalRRDUpdates = 0;
static unsigned long numRuns = 0, numRRDerrors = 0, lastRRDupdateNum = 0,
  numRRDCycles=0;
static float rrdcmaxDuration = 0, lastRRDupdateDuration = 0, maxRRDupdateDuration = 0;
static time_t start_tm, end_tm;

static u_short dumpDomains, dumpFlows, dumpHosts,
  dumpInterfaces, dumpASs, enableAberrant, shownCreate=0;

static Counter rrdGraphicRequests=0;

/* forward */
static void setPluginStatus(char * status);
static int initRRDfunct(void);
static void arbitraryActionPage(void);
static void statisticsPage(void);
static void printRRDPluginTrailer(void);
static void handleRRDHTTPrequest(char* url);
static char* spacer(char* str, char *tmpStr, int tmpStrLen,
		    char *metric_name, int metric_name_len,
		    int max_spacer_len);
static int graphCounter(char *rrdPath, char *rrdName, char *rrdTitle, char *rrdCounter,
			char *startTime, char* endTime, char* rrdPrefix);
static void graphSummary(char *rrdPath, char *rrdName, int graphId, char *startTime, char* endTime, char* rrdPrefix, char *mode);
static void netflowSummary(char *rrdPath, int graphId, char *startTime, char* endTime, char* rrdPrefix, char *mode);
static void interfaceSummary(char *rrdPath, int graphId, char *startTime, char* endTime, char* rrdPrefix, char *mode);
static void updateTrafficCounter(char *hostPath, char *key, TrafficCounter *counter, char short_step);
char x2c(char *what);
static void termRRDfunct(u_char termNtop /* 0=term plugin, 1=term ntop */);
static void addRrdDelay(void);

#define MAX_NUM_RRDS 64
#define alloc_buf(a, b, c)  { for(i=0; i<b; i++) { a[i] = (char*)calloc(sizeof(char),c); if(a[i] == NULL) no_mem = 1; }}
#define free_buf(a, b)      { for(i=0; i<b; i++) { if(a[i] != NULL) free(a[i]); } }

/* ************************************* */

static ExtraPage rrdExtraPages[] = {
  { NULL /* icon */, CONST_RRD_STATISTICS_HTML /* url */, "Statistics" /* descr */},
  { "graph.gif", CONST_RRD_ARBGRAPH_HTML, "Arbitrary Graphs" },
  { NULL, NULL, NULL }
};

static PluginInfo rrdPluginInfo[] = {
  {
    VERSION, /* current ntop version */
    "Round-Robin Database",
    "This plugin is used to setup, activate and deactivate ntop's rrd support.<br>"
    "This plugin also produces the graphs of rrd data, available via a<br>"
    "link from the various 'Info about host xxxxx' reports.",
    "2.9", /* version */
    "<a HREF=\"http://luca.ntop.org/\" alt=\"Luca's home page\">L.Deri</A>",
    "rrdPlugin", /* http://<host>:<port>/plugins/rrdPlugin */
    1, /* Active by default */
    ConfigureOnly, /* use extra pages for the views */
    1, /* Inactive setup */
    initRRDfunct, /* TermFunc   */
    termRRDfunct, /* TermFunc   */
    NULL, /* PluginFunc */
    handleRRDHTTPrequest,
    NULL, /* no host creation/deletion handle */
    NULL, /* no capture */
    NULL, /* no status */
    rrdExtraPages  /* no extra pages */
  }
};

/* ****************************************************** */

static char **calcpr=NULL;

static void calfree (void) {
  if(calcpr) {
    long i;

    for(i=0; calcpr[i]; i++){
      if(calcpr[i])
	free(calcpr[i]);
    }

    if(calcpr)
      free(calcpr);
  }
}

/* ******************************************* */

static char* capitalizeInitial(char *str) {
  char c = toupper(str[0]);

  // traceEvent(CONST_TRACE_INFO, "RRD: (%s)", str);

  str[0] = c;

  return(str);
}

/* ******************************************* */

static void fillupArgv(int argc, int maxArgc, char *argv[]) {
  int i;

  for(i=argc; i<maxArgc; i++)
    argv[i] = "";

  optind = 1;
}

/* ******************************************* */

/* FIX: we need to handle MAC addresses/symbolic IP too */

static int validHostCommunity(char *host_ip /* 1.2.3.4 */) {
  char buf[64], *community;

  //traceEvent(CONST_TRACE_INFO, "RRD: validHostCommunity(%s)", host_ip);

  community = findHostCommunity(inet_addr(host_ip), buf, sizeof(buf));

  if(community && (!isAllowedCommunity(community)))
    return(0);

  return(1);
}

/* ******************************************* */

static void addRrdDelay(void) {
  static struct timeval lastSleep;
  struct timeval thisSleep;
  float deltaMs;

  if(dumpDelay == 0) return;

  gettimeofday(&thisSleep, NULL);

  deltaMs = (timeval_subtract(thisSleep, lastSleep) / 1000) - dumpDelay;

  if(deltaMs > 0) {
#ifdef WIN32
    Sleep((int)dumpDelay);
#else
    struct timespec sleepAmount;

    sleepAmount.tv_sec = 0; sleepAmount.tv_nsec = (int)dumpDelay * 1000;
    nanosleep(&sleepAmount, NULL);
#endif
  }

  gettimeofday(&lastSleep, NULL);
}

/* ******************************************* */

static void fetch_graph_size(char rrd_height[], char rrd_width[]) {
  if(fetchPrefsValue("rrd.height", rrd_height, RRD_GRAPH_SIZE) == -1) {
    snprintf(rrd_height, sizeof(rrd_height), "%d", 120);
    storePrefsValue("rrd.height", rrd_height);
  }

  if(fetchPrefsValue("rrd.width", rrd_width, RRD_GRAPH_SIZE) == -1) {
    snprintf(rrd_width, sizeof(rrd_width), "%d", 500);
    storePrefsValue("rrd.width", rrd_width);
  }
}

/* ******************************************* */

static int createMultihostGraph(char *rrdName,
				HostTraffic *rrdHosts[MAX_NUM_NETWORKS],
				u_int32_t numRrdHosts,
				char *startTime, char* endTime) {
  char buf[1024], hosts[512] = { '\0' };
  int i, maxRRDhosts = 10;
  char rrd_height[RRD_GRAPH_SIZE], rrd_width[RRD_GRAPH_SIZE];

  if((strncmp(rrdName, "IP_", 3) == 0)
     || (strncmp(rrdName, "other", 5) == 0)
     || strstr(rrdName, "Fragments")
     )
    return(0);

  fetch_graph_size(rrd_height, rrd_width);

  for(i=0; (i<numRrdHosts) && (i<MAX_NUM_NETWORKS) && (i < maxRRDhosts); i++) {
    char *host_ip;

    host_ip = (rrdHosts[i]->ethAddressString[0] != '\0') ? rrdHosts[i]->ethAddressString : rrdHosts[i]->hostNumIpAddress;

    if((strlen(hosts) + strlen(host_ip) + 2 + strlen(rrdHosts[i]->hostResolvedName)) < sizeof(hosts)) {
      if(i > 0) strcat(hosts, ",");
      /* Fix below courtesy of Alexandre Barros <abarros@abitecnologia.com.br> */
      strcat(hosts, dotToSlash(host_ip, buf, sizeof(buf)));
      strcat(hosts, "@");
      strcat(hosts, rrdHosts[i]->hostResolvedName);
    }
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"</td>&nbsp;<td  valign=top><IMG SRC=\"/" CONST_PLUGINS_HEADER "%s?graph_width=%s&graph_height=%s"
		"&action=graphSummary&graphId=98&name=%s&start=%s&end=%s&key=%s\"></td>\n",
		rrdPluginInfo->pluginURLname, rrd_width, rrd_height, rrdName, startTime, endTime, hosts);
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<td ><A HREF=\"/" CONST_PLUGINS_HEADER "%s?mode=zoom&graph_width=%s&graph_height=%s&action=graphSummary&graphId=98&name=%s&start=%s&end=%s&key=%s\">"
		"<IMG valign=top class=tooltip SRC=/graph_zoom.gif border=0></A>\n",
		rrdPluginInfo->pluginURLname, rrd_width, rrd_height, rrdName, startTime, endTime, hosts);
  sendString(buf);

  return(1);
}

/* ******************************************* */

static void expandRRDList(char *rrdName,
			  NetworkStats localNetworks[MAX_NUM_NETWORKS], /* [0]=network, [1]=mask, [2]=broadcast, [3]=mask_v6 */
			  u_short numLocalNetworks, char *startTime, char* endTime) {
  char path[256], rrdName_copy[64], debug=0;
  u_int32_t numRrdHosts = 0, i;
  HostTraffic *rrdHosts[MAX_NUM_NETWORKS];

  if(debug) traceEvent(CONST_TRACE_WARNING, "RRD: expandRRDList(%s)", rrdName);

  safe_snprintf(__FILE__, __LINE__, rrdName_copy, sizeof(rrdName_copy), "%s", rrdName);
  rrdName_copy[strlen(rrdName_copy)-strlen(CONST_RRD_EXTENSION)] = '\0';

  for(i=0; i<numLocalNetworks; i++) {
    struct stat statbuf;
    HostTraffic *el;
    HostAddr ha;
    u_int j, num_hosts, offset;
    char addr_buf[32], *str;

    ha.hostFamily = AF_INET;

    if(localNetworks[i].address[CONST_NETMASK_V6_ENTRY] < MAX_NETWORK_EXPANSION)
      localNetworks[i].address[CONST_NETMASK_V6_ENTRY] = MAX_NETWORK_EXPANSION;
    if(localNetworks[i].address[CONST_NETMASK_V6_ENTRY] > 32)
      localNetworks[i].address[CONST_NETMASK_V6_ENTRY] = 32; /* Sanity check */

    if(localNetworks[i].address[CONST_NETMASK_V6_ENTRY] == 32)
      num_hosts = 1;
    else
      num_hosts = (1 << (32 - localNetworks[i].address[CONST_NETMASK_V6_ENTRY])) - 1;

    for(offset = 0; offset<num_hosts; offset++) {
      ha.addr._hostIp4Address.s_addr = localNetworks[i].address[0] + offset;

      if((el = findHostByNumIP(ha, 0, myGlobals.actualReportDeviceId)) != NULL) {
	str = (el->ethAddressString[0] != '\0') ? el->ethAddressString : el->hostNumIpAddress;
	snprintf(addr_buf, sizeof(addr_buf), "%s", str);
      } else {
	continue;
      }

      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/interfaces/%s/hosts/%s",
		    myGlobals.rrdPath, myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, str);

      for(j=(int)(strlen(path)-strlen(str)); j<(int)strlen(path); j++)
	if((path[j] == '.') || (path[j] == ':')) path[j] = '/';

      revertSlashIfWIN32(path, 0);

      if(debug) traceEvent(CONST_TRACE_WARNING, "RRD: expandRRDList(%s): %s", rrdName, path);

      if(stat(path, &statbuf) == 0) {
	if(debug) traceEvent(CONST_TRACE_WARNING, "RRD: ---> %s [%u]",
			     path, num_network_bits(localNetworks[i].address[1]));
	rrdHosts[numRrdHosts++] = el;
      }
    }
  }

  if(numRrdHosts > 0)
    createMultihostGraph(rrdName_copy, rrdHosts, numRrdHosts, startTime, endTime);

  if(debug) traceEvent(CONST_TRACE_WARNING, "RRD: -------------------------");
}

/* ******************************************* */

static int cmpStrings(const void *_a, const void *_b)
{
  char **str_a = (char**)_a;
  char **str_b = (char**)_b;

  /* traceEvent(CONST_TRACE_WARNING, "RRD: [%s][%s]", *str_a, *str_b); */

  return(strcmp(*str_a, *str_b));
}

/* ******************************************* */

static void listResource(char *rrdPath, char *rrdTitle,
			 char *community, char *filterString,
			 char *startTime, char* endTime) {
  char path[512] = { '\0' }, url[512] = { '\0' }, hasNetFlow;
  char buf[512] = { '\0' }, filter[64] = { '\0' }, titleBuf[128] = { '\0' };
  char *default_str, rrd_filters_show[64] = { '\0' };
  DIR* directoryPointer = NULL;
  char rrd_height[RRD_GRAPH_SIZE], rrd_width[RRD_GRAPH_SIZE];
  struct dirent* dp;
  int i, debug = 0;
#if 0
  int numFailures = 0;
#endif
  time_t now = time(NULL);

  if(!validHostCommunity(rrdTitle)) {
    returnHTTPpageBadCommunity();
    return;
  }

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);

  safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%s", myGlobals.rrdPath, rrdPath);
  revertSlashIfWIN32(path, 0);

  if(community == NULL)
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Info about %s", rrdTitle);
  else
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Info about community %s", community);

  printHTMLheader(buf, NULL, 0);
  sendString("<p ALIGN=left>\n");

  escape(titleBuf, sizeof(titleBuf), rrdTitle);
  fetch_graph_size(rrd_height, rrd_width);

  if(filterString != NULL)
    safe_snprintf(__FILE__, __LINE__, filter, sizeof(filter), "&filter=%s", filterString);

  safe_snprintf(__FILE__, __LINE__, url, sizeof(url),
		"/" CONST_PLUGINS_HEADER "%s?graph_width=%s&graph_height=%s&action=list&key=%s&title=%s&end=%u&community=%s",
		rrdPluginInfo->pluginURLname, rrd_width, rrd_height,
		rrdPath, titleBuf, (unsigned long)now,
		community ? community : "");

  sendString("<script type=\"text/javascript\">\n"
	     "	function send(f)\n"
	     "	{\n"
	     "		var chosen;\n"
	     "		chosen=f.options[f.selectedIndex].value;\n"
	     "		self.location=chosen;\n"
	     "	}    \n"
	     "</script>\n");

  sendString("<tr align=left><table>\n<tr><td><form name=myform method=get>\n<b>Presets:</b></td><td align=left>\n"
	     "<select name=presets onchange=\"send(this)\">\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%s&start=%u%s\" selected>-----</option>\n", url, now - 86400, filter);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%s&start=%u%s\">Last Year</option>\n", url, now - 365*86400, filter);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%s&start=%u%s\">Last Month</option>\n", url, now - 30*86400, filter);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%s&start=%u%s\">Last Week</option>\n", url, now - 7*86400, filter);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%s&start=%u%s\">Last Day</option>\n", url, now - 86400, filter);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%s&start=%u%s\">Last 12h</option>\n", url, now - 12 * 3600, filter);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%s&start=%u%s\">Last 6h</option>\n", url, now - 6 * 3600, filter);
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%s&start=%u%s\">Last Hour</option>\n", url, now - 3600, filter);
  sendString(buf);
  sendString("</select></form></td></tr>\n");

  /* ************************************************* */

  sendString("<tr align=left><td><form name=myform method=get>\n<b>View:</b></td><td align=left>\n"
	     "<select name=view_presets onchange=\"send(this)\">\n");

  if(filterString == NULL) default_str = "selected"; else default_str = "";
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%s\" %s>-----</option>\n", url, default_str);
  sendString(buf);

  hasNetFlow = 0;

  /* Check what menu need to be shown up */
  if((directoryPointer = opendir(path)) != NULL) {
    while((dp = readdir(directoryPointer)) != NULL) {
      if(strncmp(dp->d_name, "NF_", 3) == 0) hasNetFlow = 1;

      for(i=0; rrd_filters[i].name != NULL; i++) {
	// traceEvent(CONST_TRACE_WARNING,  "[%s][%s]", dp->d_name, rrd_filters[i].name);
	if(strcasestr(dp->d_name, rrd_filters[i].name)) {
	  rrd_filters_show[i] = 1;
	  break;
	}
      }
    }

    closedir(directoryPointer);
  }

  for(i=0; rrd_filters[i].name != NULL; i++) {
    if(rrd_filters_show[i]) {
      if(filterString && (!strcmp(filterString, rrd_filters[i].name))) default_str = "selected"; else default_str = "";
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%s&filter=%s\" %s>%s</option>\n",
		    url, rrd_filters[i].name, default_str, rrd_filters[i].label);
      sendString(buf);
    }
  }

  sendString("</select></form></td></tr></table></tr>\n");

  /* ************************************************* */
  sendString("<center>\n<p>\n");

  sendString("<TABLE BORDER=0 "TABLE_DEFAULTS">\n");

  if(community == NULL) {
    if(hasNetFlow
       && ((filterString == NULL) || strcasestr(filterString, "flow"))) {
      for(i=1; i<=3; i++) {
	sendString("<TR><TD valign=top align=left>");

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<IMG SRC=\"/" CONST_PLUGINS_HEADER "%s?graph_width=%s&graph_height=%s&action=netflowSummary"
		      "&graphId=%d&key=%s/&start=%s&end=%s\">\n",
		      rrdPluginInfo->pluginURLname, rrd_width, rrd_height,
		      i, rrdPath, startTime, endTime);
	sendString(buf);

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "</td><td valign=middle><A HREF=\"/" CONST_PLUGINS_HEADER "%s?"
		      "mode=zoom&graph_width=%s&graph_height=%s&action=netflowIfSummary&graphId=%d&key=%s/&start=%s&end=%s\">\n"
		      "<IMG valign=top class=tooltip SRC=/graph_zoom.gif border=0></A>\n",
		      rrdPluginInfo->pluginURLname, rrd_width, rrd_height, i, rrdPath, startTime, endTime);
	sendString(buf);

	sendString("</TD></TR>\n");
      }
    }

    directoryPointer = opendir(path);

    if(directoryPointer == NULL) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Unable to read directory %s", path);
      printFlagedWarning(buf);
      sendString("</CENTER>");
      printHTMLtrailer();
      return;
    } else {
      // traceEvent(CONST_TRACE_WARNING, "RRD: reading directory %s", path); /* FIX */
    }

    while((dp = readdir(directoryPointer)) != NULL) {
      char *rsrcName;
      Counter total;
#if 0
      float  average;
#endif
      int rc, isGauge;

      if(dp->d_name[0] == '.') continue;
      else if(filterString && (!strcasestr(dp->d_name, filterString))) continue;
      else if(filterString && strcasecmp(filterString, "Efficiency") && strcasestr(dp->d_name, "Efficiency")) continue;
      else if(strncmp(dp->d_name, "NF_", 3) == 0) continue;
      else if(strlen(dp->d_name) < strlen(CONST_RRD_EXTENSION)+3)
	continue;

      rsrcName = &dp->d_name[strlen(dp->d_name)-strlen(CONST_RRD_EXTENSION)-3];
      if(strcmp(rsrcName, "Num"CONST_RRD_EXTENSION) == 0)
	isGauge = 1;
      else
	isGauge = 0;

      rsrcName = &dp->d_name[strlen(dp->d_name)-strlen(CONST_RRD_EXTENSION)];

      if(strcmp(rsrcName, CONST_RRD_EXTENSION))
	continue;

#if 0
      if(sumCounter(rrdPath, dp->d_name, "FAILURES", startTime, endTime, &total, &average) >= 0)
	numFailures += total;
#endif

#if DISPLAY_ONLY_IF_THERE_S_DATA
      rc = sumCounter(rrdPath, dp->d_name, "MAX", startTime, endTime, &total, &average);
#else
      rc = 1, total = 1;
#endif

      if(isGauge || ((rc >= 0) && (total > 0))) {
	rsrcName = dp->d_name;

	/* if(strcmp(rsrcName, "pktSent") || strcmp(rsrcName, "pktRcvd")) continue; */

	if(strncmp(rsrcName, "IP_", 3)
	   || strncmp(rsrcName, "tcp", 3)
	   || strncmp(rsrcName, "udp", 3)
	   ) {
	  u_char do_show = 1;
	  char *subname = strstr(rsrcName, "Rcvd");

	  // traceEvent(CONST_TRACE_WARNING, "RRD: [%s]", dp->d_name);

	  if(subname) {
	    DIR* directoryPointer1;
	    struct dirent* dp1;
	    char rsrcName1[64];

	    safe_snprintf(__FILE__, __LINE__, rsrcName1, sizeof(rsrcName1), "%s", rsrcName);
	    subname = strstr(rsrcName1, "Rcvd");
	    subname[0] = 'S';
	    subname[1] = 'e';
	    subname[2] = 'n';
	    subname[3] = 't';

	    // traceEvent(CONST_TRACE_WARNING, "RRD: -> (%s) [%s]", rsrcName1, path);

	    if((directoryPointer1 = opendir(path)) != NULL) {
	      while((dp1 = readdir(directoryPointer1)) != NULL) {
		// traceEvent(CONST_TRACE_WARNING, "RRD: (%s) (%s)", dp1->d_name, rsrcName1);
		if(strcmp(dp1->d_name, rsrcName1) == 0) {
		  do_show = 0;
		  break;
		}
	      }
	      closedir(directoryPointer1);
	    }
	  }

	  if(do_show) {
	    sendString("<TR><TD align=left>\n");

	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<img class=tooltip src=\"/" CONST_PLUGINS_HEADER "%s?"
			  "graph_width=%s&graph_height=%s&action=graphSummary&graphId=99&key=%s/&name=%s&title=%s&start=%s&end=%s\">\n",
			  rrdPluginInfo->pluginURLname, rrd_width, rrd_height,
			  rrdPath, rsrcName, rsrcName, startTime, endTime);
	    sendString(buf);

	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "</td><td align=right><A HREF=\"/" CONST_PLUGINS_HEADER "%s?"
			  "mode=zoom&graph_width=%s&graph_height=%s&action=graphSummary&graphId=99&key=%s/&name=%s&title=%s&start=%s&end=%s\">"
			  "<IMG valign=top class=tooltip SRC=/graph_zoom.gif border=0></A><p>\n",
			  rrdPluginInfo->pluginURLname, rrd_width, rrd_height, rrdPath, rsrcName, rsrcName, startTime, endTime);
	    sendString(buf);

	    sendString("</TD></TR>\n");
	  }
	}

      }
    } /* while */

    closedir(directoryPointer);
  } else {
    /* Community */
    char communityAddresses[256] = { '\0' }, localAddresses[1024] = { '\0' };
    NetworkStats localNetworks[MAX_NUM_NETWORKS]; /* [0]=network, [1]=mask, [2]=broadcast, [3]=mask_v6 */
    u_short numLocalNetworks = 0, found = 0, num_rrds = 0;
    char *keys[MAX_NUM_RRDS];
    int k;

    snprintf(buf, sizeof(buf), "community.%s", community);
    if(fetchPrefsValue(buf, communityAddresses, sizeof(communityAddresses)) != -1) {
      handleAddressLists(communityAddresses, localNetworks, &numLocalNetworks,
			 localAddresses, sizeof(localAddresses),
			 CONST_HANDLEADDRESSLISTS_COMMUNITIES);
    }

    for(i=0; i<numLocalNetworks; i++) {
      HostTraffic *el;
      HostAddr ha;
      u_int j, num_hosts, offset;
      char addr_buf[32], *str;

      ha.hostFamily = AF_INET;

      if(localNetworks[i].address[CONST_NETMASK_V6_ENTRY] < MAX_NETWORK_EXPANSION)
	localNetworks[i].address[CONST_NETMASK_V6_ENTRY] = MAX_NETWORK_EXPANSION;
      if(localNetworks[i].address[CONST_NETMASK_V6_ENTRY] > 32)
	localNetworks[i].address[CONST_NETMASK_V6_ENTRY] = 32; /* Sanity check */

      if(localNetworks[i].address[CONST_NETMASK_V6_ENTRY] == 32)
	num_hosts = 1;
      else
	num_hosts = (1 << (32 - localNetworks[i].address[CONST_NETMASK_V6_ENTRY])) - 1;

      for(offset = 0; offset<num_hosts; offset++) {
	ha.addr._hostIp4Address.s_addr = localNetworks[i].address[0] + offset;

	if((el = findHostByNumIP(ha, 0, myGlobals.actualReportDeviceId)) != NULL) {
	  str = (el->ethAddressString[0] != '\0') ? el->ethAddressString : el->hostNumIpAddress;
	  snprintf(addr_buf, sizeof(addr_buf), "%s", str);
	} else {
	  continue;
	}

	safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/interfaces/%s/hosts/%s",
		      myGlobals.rrdPath, myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName, str);

	for(j=(int)(strlen(path)-strlen(str)); j<(int)strlen(path); j++)
	  if((path[j] == '.') || (path[j] == ':')) path[j] = '/';

	revertSlashIfWIN32(path, 0);

	if((directoryPointer = opendir(path)) != NULL) {
	  if(debug) traceEvent(CONST_TRACE_INFO, "RRD: Found %s", path);

	  while((dp = readdir(directoryPointer)) != NULL) {
	    if((dp->d_name[0] == '.') /* || (!strstr(dp->d_name, "Sent")) */)
	      continue;
	    else {
	      int duplicated = 0;

	      if(community != NULL) {
		if(
		   strstr(dp->d_name, "bytes")
		   || strstr(dp->d_name, "pkts")
		   || strstr(dp->d_name, "tcp")
		   || strstr(dp->d_name, "udp")
		   || strstr(dp->d_name, "icmp")
		   ) {

		  if(strstr(dp->d_name, "other")
		     || strstr(dp->d_name, "Fragments")
		     )
		    continue;
		} else
		  continue;
	      }

	      found = 1;

	      for(k=0; k<num_rrds; k++)
		if(!strcmp(keys[k], dp->d_name)) {
		  duplicated = 1;
		  break;
		}

	      if((!duplicated) && (num_rrds < (MAX_NUM_RRDS-1))) {
		// traceEvent(CONST_TRACE_INFO, "RRD: -->  %s [%d].address[%s]", path, num_rrds, dp->d_name);
		keys[num_rrds++] = strdup(dp->d_name);
	      }
	    }
	  }

	  closedir(directoryPointer);
	} else
	  if(debug) traceEvent(CONST_TRACE_INFO, "RRD: NOT found %s", path);
      }
    }

    qsort(keys, num_rrds, sizeof(char*), cmpStrings);

    sendString("<table border=0>\n");

    for(k=0, i=0; k<num_rrds; k++) {
      sendString("\n<!-- XXX -->\n");

      if(i==0) sendString("<tr>");

      sendString("<td>");
      expandRRDList(keys[k], localNetworks, numLocalNetworks, startTime, endTime);
      sendString("</td>");
      i++;

      if(i == 2) sendString("</tr>\n"), i=0;
    }

    sendString("</table>");

    if(!found) {
      sendString("<tr><td valign=top>");
      printFlagedWarning("<I>No data (yet) for this community</I>");
      sendString("</td></tr>");
    }
  }

  sendString("</TABLE>\n</CENTER>");

  /*
    sendString("<br><b>NOTE: total and average values are NOT absolute but "
    "calculated on the specified time interval.</b>\n");
  */
  printHTMLtrailer();
}

/* ******************************************* */

static int endsWith(char* label, char* pattern) {
  size_t lenLabel, lenPattern;

  lenLabel   = strlen(label);
  lenPattern = strlen(pattern);

  if(lenPattern >= lenLabel)
    return(0);
  else
    return(!strcmp(&label[lenLabel-lenPattern], pattern));
}

/* ******************************* */

static char* sanitizeRrdPath(char *in_path) {
#ifdef WIN32
  if(in_path[1] == ':') {
    char *tmpStr;

    tmpStr = (char*)malloc(strlen(in_path)+2);
    if(tmpStr) {
      tmpStr[0] = in_path[0];
      tmpStr[1] = '\\';
      strcpy(&tmpStr[2], &in_path[1]);
      strcpy(in_path, tmpStr);
      free(tmpStr);
    }
  }
#endif
  return(in_path);
}

/* ********************************************************** */

static int graphCounter(char *rrdPath, char *rrdName, char *rrdTitle, char *rrdCounter,
			char *startTime, char* endTime, char *rrdPrefix) {
  char path[512], *argv[64], buf[384], buf1[384], buf2[384],
    fname[384], *label, tmpStr[32];
  char bufa1[384], bufa2[384], bufa3[384], show_trend = 1;
  struct stat statbuf;
  int argc = 0, rc, x, y;
  char rrd_height[RRD_GRAPH_SIZE], rrd_width[RRD_GRAPH_SIZE];
  double ymin,ymax;

  // if((!active) || (!initialized)) return(-1);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "graphCounter(%s, %s, %s, %s, %s, %s...)",
	     rrdPath, rrdName, rrdTitle, rrdCounter, startTime, endTime);
#endif

  memset(&buf, 0, sizeof(buf));
  memset(&buf1, 0, sizeof(buf1));
  memset(&buf2, 0, sizeof(buf2));
  memset(&bufa1, 0, sizeof(bufa1));
  memset(&bufa2, 0, sizeof(bufa2));
  memset(&bufa3, 0, sizeof(bufa3));

  if(strstr(rrdName, "/AS"))
    safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%s/AS/%s.rrd", myGlobals.rrdPath, rrdPath, rrdName);
  else {
    if(!strcmp(rrdName, "throughput")) {
#ifdef WIN32
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%u/%s%s.rrd",
		    myGlobals.rrdVolatilePath, driveSerial, rrdPath, rrdName);
#else
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%s%s.rrd",
		    myGlobals.rrdVolatilePath, rrdPath, rrdName);
#endif
    } else
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%s%s.rrd",
		    myGlobals.rrdPath, rrdPath, rrdName);
  }

  /* Check if the output directory has been deleted in the meantime */
  safe_snprintf(__FILE__, __LINE__, fname, sizeof(fname), "%s/%s",
		myGlobals.rrdPath, rrd_subdirs[0]);
  revertSlashIfWIN32(fname, 0);
  if(stat(fname, &statbuf) != 0) {
    /* The directory does not exist: better to create it */
    mkdir_p("RRD", fname, myGlobals.rrdDirectoryPermissions);
  }

  /* startTime[4] skips the 'now-' */
  safe_snprintf(__FILE__, __LINE__, fname, sizeof(fname), "%s/%s/%s-%s%s%s",
		myGlobals.rrdPath, rrd_subdirs[0], startTime, rrdPrefix, rrdName,
		CHART_FORMAT);

  revertSlashIfWIN32(path, 0);
  revertSlashIfWIN32(fname, 0);

  /* traceEvent(CONST_TRACE_INFO, "--> '%s'", path);  */

  if(endsWith(rrdName, "Bytes") || endsWith(rrdName, "Octets")) label = "Bytes/s";
  else if(endsWith(rrdName, "Pkts")) label = "Pkt/s";
  else if(strstr(rrdName, "knownHostsNum")) label = "Number of Peers";
  else label = capitalizeInitial(rrdName);

  fetch_graph_size(rrd_height, rrd_width);

  if((!strcmp(endTime, "now"))
     && (!strcmp(startTime, "now-600s")))
    show_trend = 0;

  rrdGraphicRequests++;

  if(stat(path, &statbuf) == 0) {
    char metric_name[32];

    if(isdigit(startTime[0]) && isdigit(endTime[0])) {
      unsigned long _startTime, _endTime;

      _startTime = atol(startTime);
      _endTime   = atol(endTime);

      if(_startTime >= _endTime) {
	char *tmp = startTime;

	startTime = endTime;
	endTime   = tmp;
      }
    }

    argv[argc++] = "rrd_graph";
    argv[argc++] = fname;
    argv[argc++] = "--lazy";
    argv[argc++] = "--imgformat";
    argv[argc++] = "PNG";
    argv[argc++] = "--vertical-label";
    argv[argc++] = label;
    argv[argc++] = "--watermark";
    argv[argc++] = NTOP_WATERMARK;

    if((rrdTitle != NULL) && (rrdTitle[0] != '\0')) {
      argv[argc++] = "--title";
      argv[argc++] = rrdTitle;
    }

    argv[argc++] = "--start";
    argv[argc++] = startTime;
    argv[argc++] = "--end";
    argv[argc++] = endTime;
    argv[argc++] = "--slope-mode";

    /* ********************* */

    argv[argc++] = "--rigid";
    argv[argc++] = "--base";
    argv[argc++] = "1024";
    argv[argc++] = "--height";
    argv[argc++] = rrd_height;
    argv[argc++] = "--width";
    argv[argc++] = rrd_width;
    argv[argc++] = "--alt-autoscale-max";
    argv[argc++] = "--lower-limit";
    argv[argc++] = "0";

    /* ********************* */

#ifdef CONST_RRD_DEFAULT_FONT_NAME
    argv[argc++] = "--font";
#ifdef CONST_RRD_DEFAULT_FONT_PATH
    argv[argc++] = "DEFAULT:" CONST_RRD_DEFAULT_FONT_SIZE ":" \
      CONST_RRD_DEFAULT_FONT_PATH CONST_RRD_DEFAULT_FONT_NAME;
#else
    argv[argc++] = "DEFAULT:" CONST_RRD_DEFAULT_FONT_SIZE ":" CONST_RRD_DEFAULT_FONT_NAME;
#endif
#endif
    revertDoubleColumnIfWIN32(path);
    sanitizeRrdPath(path);
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "DEF:ctr=%s:counter:AVERAGE", path);
    argv[argc++] = buf;
    safe_snprintf(__FILE__, __LINE__, buf1, sizeof(buf1), "AREA:ctr#00a000:%s",
		  spacer(capitalizeInitial(rrdCounter), tmpStr, sizeof(tmpStr),
			 metric_name, sizeof(metric_name), RRD_DEFAULT_SPACER_LEN));
    argv[argc++] = buf1;

    if(show_trend) argv[argc++] = "CDEF:smoothed=ctr,1800,TREND";

    // argv[argc++] = "GPRINT:ctr:MIN:Min\\: %3.1lf%s\\t";
    argv[argc++] = "GPRINT:ctr:MAX:Max\\: %3.1lf%s\\t";
    argv[argc++] = "GPRINT:ctr:AVERAGE:Avg\\: %3.1lf%s\\t";
    argv[argc++] = "GPRINT:ctr:LAST:Last\\: %3.1lf%s\\n";
    safe_snprintf(__FILE__, __LINE__, bufa1, sizeof(bufa1), "DEF:pred=%s:counter:HWPREDICT", path);
    argv[argc++] = bufa1;
    safe_snprintf(__FILE__, __LINE__, bufa2, sizeof(bufa2), "DEF:dev=%s:counter:DEVPREDICT", path);
    argv[argc++] = bufa2;
    safe_snprintf(__FILE__, __LINE__, bufa3, sizeof(bufa3), "DEF:fail=%s:counter:FAILURES", path);
    argv[argc++] = bufa3;

    if(enableAberrant) {
      argv[argc++] = "TICK:fail#ffffa0:1.0:Anomalia";
      argv[argc++] = "CDEF:upper=pred,dev,2,*,+";
      argv[argc++] = "CDEF:lower=pred,dev,2,*,-";
      argv[argc++] = "LINE1:upper#ff0000:Upper";
      argv[argc++] = "LINE2:lower#a0ffff:Lower";
    }

    if(show_trend) argv[argc++] = "LINE1:smoothed#0000FF:Trend (30 min)";

    /* 95th Percentile [http://en.wikipedia.org/wiki/Burstable_billing] */
    argv[argc++] = "VDEF:ninetyfive=ctr,95,PERCENT";
    argv[argc++] = "LINE1.2:ninetyfive#ff00ffBB:95th Percentile";

    if(debug_rrd_graph) {
      int j;

      for(j=0; j<argc; j++)
	traceEvent(CONST_TRACE_ERROR, "[%d] '%s'", j, argv[j]);
    }

    accessMutex(&rrdMutex, "rrd_graph");
    optind=0; /* reset gnu getopt */
    opterr=0; /* no error messages */

    fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);
    rrd_clear_error();
    addRrdDelay();
    rc = rrd_graph(argc, argv, &calcpr, &x, &y, NULL, &ymin, &ymax);

    calfree();

    if(rc == 0) {
      sendHTTPHeader(FLAG_HTTP_TYPE_PNG, 0, 1);
      sendFile(fname, 0);
      unlink(fname);
    } else {
#if defined(RRD_DEBUG)
      traceEventRRDebugARGV(0);
#endif

      if(++graphErrCount < 50) {
        traceEvent(CONST_TRACE_ERROR, "RRD: rrd_graph() call failed, rc %d, %s",
		   rc, rrd_get_error() ? rrd_get_error() : "");
        traceEvent(CONST_TRACE_INFO, "RRD: Failing file in graphCounter() is %s", path);
      }

      sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
      printHTMLheader("ntop RRD Graph", NULL, 0);
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path),
		    "<I>Error while building graph of the requested file. %s</I>",
		    rrd_get_error() ? rrd_get_error() : "");
      printFlagedWarning(path);
      rrd_clear_error();
    }

    releaseMutex(&rrdMutex);
  } else {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop RRD Graph", NULL, 0);
    printFlagedWarning("<I>Error while building graph of the requested file "
		       "(unknown RRD file)</I>");
    rc = -1;
  }

  return(rc);
}

/* ******************************************* */

#undef option_timespan
#define option_timespan(theStartTime, theLabel, selected)		\
  safe_snprintf(__FILE__, __LINE__, strbuf, sizeof(strbuf),		\
		"<option value=\"/" CONST_PLUGINS_HEADER "%s?graph_width=%s&graph_height=%s&action=netflowIfSummary" \
		"&key=%s"						\
		"&graphId=%d"						\
		"&start=%u"						\
		"&end=%u"						\
		"&mode=zoom&name=%s\" %s>%s</option>\n",		\
		"rrdPlugin", rrd_width, rrd_height, rrdInterface, graphId, (unsigned int)theStartTime, (unsigned int)the_time, \
		_rrdName, (selected == 1) ? "selected" : "", theLabel); sendString(strbuf);

/* ****************************** */

static void netflowSummary(char *rrdPath, int graphId, char *startTime,
			   char* endTime, char *rrdPrefix, char *mode) {
  char path[512], *argv[3*MAX_NUM_ENTRIES], buf[MAX_NUM_ENTRIES][MAX_BUF_LEN];
  char buf1[MAX_NUM_ENTRIES][MAX_BUF_LEN], tmpStr[32],
    buf2[MAX_NUM_ENTRIES][MAX_BUF_LEN], buf3[MAX_NUM_ENTRIES][MAX_BUF_LEN];
  char fname[384], *label = NULL, _rrdName[256], *title = NULL, *str;
  struct nameLabel *rrds = NULL;
  int argc = 0, rc, x, y, i, entryId = 0, pathIdx;
  double ymin, ymax;
  struct stat statbuf;
  char rrd_height[RRD_GRAPH_SIZE], rrd_width[RRD_GRAPH_SIZE];

  // if((!active) || (!initialized)) return;

  path[0] = '\0';
  fetch_graph_size(rrd_height, rrd_width);

  switch(graphId) {
  case 0: rrds = (struct nameLabel*)rrd_summary_traffic; label = "Bytes"; title = "Interface Statistics"; break;
  case 1: rrds = (struct nameLabel*)rrd_summary_new_flows; label = "Flows"; title = "Newly Created Flows: Statistics"; break;
  case 2: rrds = (struct nameLabel*)rrd_summary_new_nf_flows; label = "Flows"; title = "Newly Created Flows: Protocol Breakdown"; break;
  case 3: rrds = (struct nameLabel*)rrd_summary_new_nf_flows_size; label = "Bytes"; title = "Newly Created Flows: Average Size"; break;
  }

  /* Check if the output directory has been deleted in the meantime */
  safe_snprintf(__FILE__, __LINE__, fname, sizeof(fname), "%s/%s",
                myGlobals.rrdPath, rrd_subdirs[0]);
  revertSlashIfWIN32(fname, 0);
  if(stat(fname, &statbuf) != 0) {
    /* The directory does not exist: better to create it */
    mkdir_p("RRD", fname, myGlobals.rrdDirectoryPermissions);
  }

  /* startTime[4] skips the 'now-' */
  safe_snprintf(__FILE__, __LINE__, fname, sizeof(fname), "%s/%s/%s-%s%d%s",
		myGlobals.rrdPath, rrd_subdirs[0],
		startTime, rrdPrefix, graphId,
		CHART_FORMAT);

  safe_snprintf(__FILE__, __LINE__, _rrdName, sizeof(_rrdName), "%s", rrdPath);

  if(!strcmp(mode, "zoom")) {
    char strbuf[LEN_GENERAL_WORK_BUFFER];
    time_t the_time = time(NULL);
    char *rrdInterface = rrdPath;
    struct tm *the_tm;

    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop RRD Graph", NULL, 0);

    sendString("<center>\n");

    /* *************************************** */

    /*
      Graph time and zoom: code courtesy of
      the Cacti (http://www.cacti.net) project.
    */

    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/calendar.js\"></SCRIPT>\n");
    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/lang/calendar-en.js\"></SCRIPT>\n");
    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/calendar-setup.js\"></script>\n");
    sendString("<SCRIPT type\"text/javascript\" src=\"/jscalendar/calendar-load.js\"></script>\n");

    sendString("\n<p align=center>\n<form action=/plugins/rrdPlugin name=\"form_timespan_selector\" method=\"get\">\n"
	       "<TABLE width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\n<TBODY><TR><TD align=center class=\"textHeader\" nowrap=\"\">\n"
	       "<b>Presets</b>: <SELECT name=\"predefined_timespan\" onchange=\"window.location=document.form_timespan_selector."
	       "predefined_timespan.options[document.form_timespan_selector.predefined_timespan.selectedIndex].value\">\n");

    option_timespan(the_time-12*3600, "-----", 1);
    option_timespan(the_time-1800, "Last Half Hour", 0);
    option_timespan(the_time-3600, "Last Hour", 0);
    option_timespan(the_time-2*3600, "Last 2 Hours", 0);
    option_timespan(the_time-4*3600, "Last 4 Hours", 0);
    option_timespan(the_time-6*3600, "Last 6 Hours", 0);
    option_timespan(the_time-12*3600, "Last 12 Hours", 0);
    option_timespan(the_time-86400, "Last Day", 0);
    option_timespan(the_time-2*86400, "Last 2 Days", 0);
    option_timespan(the_time-4*86400, "Last 4 Days", 0);
    option_timespan(the_time-7*86400, "Last Week", 0);
    option_timespan(the_time-30*86400, "Last Month", 0);
    option_timespan(the_time-2*30*86400, "Last 2 Months", 0);
    option_timespan(the_time-4*30*86400, "Last 4 Months", 0);
    option_timespan(the_time-6*30*86400, "Last 6 Months", 0);
    option_timespan(the_time-12*30*86400, "Last Year", 0);

    sendString("</select>\n");

    safe_snprintf(__FILE__, __LINE__, strbuf, sizeof(strbuf),
		  "<input type=hidden name=action value=netflowIfSummary>\n"
		  "<input type=hidden name=graphId value=\"%d\">\n"
		  "<input type=hidden name=key value=\"%s\">\n"
		  "<input type=hidden name=name value=\"%s\">\n"
		  "<input type=hidden name=start value=\"%s\">\n"
		  "<input type=hidden name=end value=\"%s\">\n"
		  "<input type=hidden name=mode value=\"zoom\">\n",
		  graphId, _rrdName, rrdInterface, startTime, endTime);
    sendString(strbuf);

    sendString("&nbsp;<STRONG>From:</STRONG>\n<INPUT type=\"text\" name=\"date1\" id=\"date1\" size=\"16\" value=\"");

    the_time = atol(startTime); the_tm = localtime(&the_time);
    strftime(strbuf, sizeof(strbuf), "%Y-%m-%d %H:%M", the_tm); sendString(strbuf);

    sendString("\">\n<INPUT type=\"image\" src=\"/calendar.gif\" alt=\"Start date selector\" border=\"0\" align=\"absmiddle\" "
	       "onclick=\"return showCalendar('date1');\">\n");
    sendString("&nbsp;<strong>To:</strong>\n<INPUT type=\"text\" name=\"date2\" id=\"date2\" size=\"16\" value=\"");

    the_time = atol(endTime); the_tm = localtime(&the_time);
    strftime(strbuf, sizeof(strbuf), "%Y-%m-%d %H:%M", the_tm); sendString(strbuf);

    sendString("\">\n<INPUT type=\"image\" src=\"/calendar.gif\" alt=\"End date selector\" border=\"0\" align=\"absmiddle\" "
	       "onclick=\"return showCalendar('date2');\">\n"
	       "<INPUT type=\"submit\" value=\"Update Graph\">\n</FORM>\n</TD></TR></TBODY></TABLE>\n</p>\n");

    /* *************************************** */

    sendString("<SCRIPT type=\"text/javascript\" src=\"/zoom.js\"></SCRIPT>\n"
	       "<DIV id=\"zoomBox\" style=\"position: absolute; visibility: visible; background-image: initial; background-repeat: initial; "
	       "background-attachment: initial; background-position-x: initial; background-position-y: initial; background-color: orange; "
	       "opacity: 0.5;\"></DIV>\n");

    sendString("<DIV id=\"zoomSensitiveZone\" style=\"position:absolute; overflow:none; background-repeat: initial; "
	       "background-attachment: initial;  "
	       "background-position-x: initial; background-position-y: initial; visibility:visible; cursor:crosshair; background:blue; "
	       "filter:alpha(opacity=0); -moz-opacity:0; -khtml-opacity:0; opacity:0;\" oncontextmenu=\"return false\"></DIV>\n");

    /*
      NOTE:
      If the graph size changes, please update the zoom.js file (search for L.Deri)
    */
    safe_snprintf(__FILE__, __LINE__, strbuf, sizeof(strbuf),
                  "<img id=zoomGraphImage src=\"/" CONST_PLUGINS_HEADER "%s?graph_width=%s&graph_height=%s&action=netflowIfSummary"
		  "&graphId=%d&key=%s&name=%s&start=%s&end=%s"
		  "\" alt=\"graph image\" border=0></center>\n",
                  rrdPluginInfo->pluginURLname, rrd_width, rrd_height,
		  graphId,
		  rrdInterface, _rrdName,
                  startTime,
                  endTime);
    sendString(strbuf);

    sendString("\n<SCRIPT type=\"text/javascript\">\n\nvar cURLBase = \"/plugins/rrdPlugin?mode=zoom\";\n\n"
	       "// Global variables\nvar gZoomGraphName = \"zoomGraphImage\";\n"
	       "var gZoomGraphObj;\nvar gMouseObj;\nvar gUrlObj;\nvar gBrowserObj;\nvar gGraphWidth;\n"
	       "var gGraphHeight;\n\n\nwindow.onload = function () { initBonsai(); addReflections(); }\n\n</SCRIPT>\n");

    sendString("</center>\n");

    printHTMLtrailer();
    return;
  }

  revertSlashIfWIN32(fname, 0);

  if(rrds == NULL) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop RRD Graph Summary", NULL, 0);
    printFlagedWarning("<I>Error while building graph of the requested file "
		       "(unknown RRD files)</I>");
    return;
  }

  rrdGraphicRequests++;

  if(isdigit(startTime[0]) && isdigit(endTime[0])) {
    unsigned long _startTime, _endTime;

    _startTime = atol(startTime);
    _endTime   = atol(endTime);

    if(_startTime >= _endTime) {
      char *tmp = startTime;

      startTime = endTime;
      endTime   = tmp;
    }
  }

  argv[argc++] = "rrd_graph";
  argv[argc++] = fname;
  argv[argc++] = "--lazy";
  argv[argc++] = "--imgformat";
  argv[argc++] = "PNG";
  argv[argc++] = "--vertical-label";
  argv[argc++] = label;
  argv[argc++] = "--start";
  argv[argc++] = startTime;
  argv[argc++] = "--end";
  argv[argc++] = endTime;
  argv[argc++] = "--slope-mode";
  argv[argc++] = "--watermark";
  argv[argc++] = NTOP_WATERMARK;

#ifdef CONST_RRD_DEFAULT_FONT_NAME
  argv[argc++] = "--font";
#ifdef CONST_RRD_DEFAULT_FONT_PATH
  argv[argc++] = "DEFAULT:" CONST_RRD_DEFAULT_FONT_SIZE ":" \
    CONST_RRD_DEFAULT_FONT_PATH CONST_RRD_DEFAULT_FONT_NAME;
#else
  argv[argc++] = "DEFAULT:" CONST_RRD_DEFAULT_FONT_SIZE ":" CONST_RRD_DEFAULT_FONT_NAME;
#endif
#endif

  argv[argc++] = "--title";
  argv[argc++] = title;

  str = "interfaces/";
  i = (int)strlen(str);
  if(!strncmp(rrdPath, str, i))
    pathIdx = i;
  else
    pathIdx = 0;

  for(i=0, entryId=0; rrds[i].name != NULL; i++) {
    char metric_name[32];

    if(!strcmp(rrds[i].name, "throughput")) {
#ifdef WIN32
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%u/interfaces/%s/%s.rrd",
		    myGlobals.rrdVolatilePath, driveSerial, &rrdPath[pathIdx], rrds[i].name);
#else
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/interfaces/%s/%s.rrd",
		    myGlobals.rrdVolatilePath, rrdPath, rrds[i].name);
#endif
    } else
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/interfaces/%s/%s.rrd",
		    myGlobals.rrdPath, &rrdPath[pathIdx], rrds[i].name);

    revertSlashIfWIN32(path, 0);

    if(debug_rrd_graph) traceEvent(CONST_TRACE_WARNING,  "-- 3 --> (%s)", path);

    if(stat(path, &statbuf) == 0) {
      revertDoubleColumnIfWIN32(path);
      safe_snprintf(__FILE__, __LINE__, buf[entryId], MAX_BUF_LEN, "DEF:ctr%d=%s:counter:AVERAGE", entryId, path);
      argv[argc++] = buf[entryId];

      safe_snprintf(__FILE__, __LINE__, buf1[entryId], MAX_BUF_LEN, "%s:ctr%d%s:%s", entryId == 0 ? "AREA" : "STACK",
		    entryId, rrd_colors[entryId],
		    spacer(rrds[i].label, tmpStr, sizeof(tmpStr), metric_name, sizeof(metric_name), RRD_DEFAULT_SPACER_LEN));
      argv[argc++] = buf1[entryId];

      safe_snprintf(__FILE__, __LINE__, buf2[entryId], MAX_BUF_LEN, "GPRINT:ctr%d%s", entryId, ":AVERAGE:Avg\\: %3.1lf%s\\t");
      argv[argc++] = buf2[entryId];

      safe_snprintf(__FILE__, __LINE__, buf3[entryId], MAX_BUF_LEN, "GPRINT:ctr%d%s", entryId, ":LAST:Last\\: %3.1lf%s\\n");
      argv[argc++] = buf3[entryId];

      entryId++;

      if(entryId >= MAX_NUM_ENTRIES) break;

      if(entryId >= CONST_NUM_BAR_COLORS) {
	if(colorWarn == 0) {
	  traceEvent(CONST_TRACE_WARNING, "RRD: Number of defined bar colors less than max entries. Some graph(s) truncated");
	  colorWarn = 1;
	}

	break;

      } else {
	// traceEvent(CONST_TRACE_WARNING, "RRD: Unable to find file %s", path);
      }
    }
  }

  accessMutex(&rrdMutex, "rrd_graph");
  optind=0; /* reset gnu getopt */
  opterr=0; /* no error messages */

  fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);

  if(debug_rrd_graph) {
    int j;

    for(j=0; j<argc; j++)
      traceEvent(CONST_TRACE_ERROR, "[%d] '%s'", j, argv[j]);
  }

  rrd_clear_error();
  addRrdDelay();
  rc = rrd_graph(argc, argv, &calcpr, &x, &y, NULL, &ymin, &ymax);
  calfree();

  if(rc == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_PNG, 0, 1);
    sendFile(fname, 0);
    unlink(fname);
  } else {
#if defined(RRD_DEBUG)
    traceEventRRDebugARGV(3);
#endif

    if(++graphErrCount < 50) {
      traceEvent(CONST_TRACE_ERROR, "RRD: rrd_graph() call failed, rc %d, %s",
		 rc, rrd_get_error() ? rrd_get_error() : "");
      traceEvent(CONST_TRACE_INFO, "RRD: Failing file in netflowSummary() is %s", path);
    }

    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop RRD Graph Summary", NULL, 0);
    safe_snprintf(__FILE__, __LINE__, path, sizeof(path),
		  "<I>Error while building graph of the requested file. %s</I>",
		  rrd_get_error() ? rrd_get_error() : "");
    printFlagedWarning(path);
    rrd_clear_error();
  }

  releaseMutex(&rrdMutex);
}

/* ******************************************* */

#undef option_timespan
#define option_timespan(theStartTime, theLabel, selected)		\
  safe_snprintf(__FILE__, __LINE__, strbuf, sizeof(strbuf),		\
		"<option value=\"/" CONST_PLUGINS_HEADER "%s?graph_width=%s&graph_height=%s&action=netflowIfSummary" \
		"&key=%s"						\
		"&graphId=%d"						\
		"&start=%u"						\
		"&end=%u"						\
		"&mode=zoom&name=%s\" %s>%s</option>\n",		\
		"rrdPlugin", rrd_width, rrd_height, rrdInterface, graphId, (unsigned int)theStartTime, (unsigned int)the_time, \
		_rrdName, (selected == 1) ? "selected" : "", theLabel); sendString(strbuf);

/* ******************************************* */

static void interfaceSummary(char *rrdPath, int graphId, char *startTime,
			     char* endTime, char *rrdPrefix, char *mode) {
  char path[512], *argv[3*MAX_NUM_ENTRIES], *buf[MAX_NUM_ENTRIES], *buf0[MAX_NUM_ENTRIES], *buf1[MAX_NUM_ENTRIES];
  char *buf2[MAX_NUM_ENTRIES], *buf3[MAX_NUM_ENTRIES], *buf4[MAX_NUM_ENTRIES], tmpStr[32], metric_name[32];
  char fname[384], *label, title[64], _rrdName[256];
  char **rrds = NULL;
  int argc = 0, rc, x, y, i, entryId=0, no_mem = 0;
  double ymin, ymax;
  struct stat statbuf;
  char rrd_height[RRD_GRAPH_SIZE], rrd_width[RRD_GRAPH_SIZE];

  // if((!active) || (!initialized)) return;

  /* ******************** */
  alloc_buf(buf, MAX_NUM_ENTRIES, MAX_BUF_LEN);
  alloc_buf(buf0, MAX_NUM_ENTRIES, MAX_BUF_LEN);
  alloc_buf(buf1, MAX_NUM_ENTRIES, MAX_BUF_LEN);
  alloc_buf(buf2, MAX_NUM_ENTRIES, MAX_BUF_LEN);
  alloc_buf(buf3, MAX_NUM_ENTRIES, MAX_BUF_LEN);
  alloc_buf(buf4, MAX_NUM_ENTRIES, MAX_BUF_LEN);

  if(no_mem) {
    traceEvent(CONST_TRACE_WARNING, "RRD: Not enough memory");
    free_buf(buf0, MAX_NUM_ENTRIES);free_buf(buf1, MAX_NUM_ENTRIES);
    free_buf(buf2, MAX_NUM_ENTRIES);free_buf(buf3, MAX_NUM_ENTRIES);
    free_buf(buf4, MAX_NUM_ENTRIES);free_buf(buf, MAX_NUM_ENTRIES);
    return;
  }

  /* ******************** */

  path[0] = '\0';
  safe_snprintf(__FILE__, __LINE__, _rrdName, sizeof(_rrdName), "%s", rrdPath);

  switch(graphId) {
  case 0:  rrds = (char**)rrd_summary_nf_if_octets; label = "Bit/s"; break;
  default: rrds = (char**)rrd_summary_nf_if_pkts; label = "Pkt/s"; break;
  }

  fetch_graph_size(rrd_height, rrd_width);

  if(!strcmp(mode, "zoom")) {
    char strbuf[LEN_GENERAL_WORK_BUFFER];
    time_t the_time = time(NULL);
    char *rrdInterface = rrdPath;
    struct tm *the_tm;

    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop RRD Graph", NULL, 0);

    sendString("<center>\n");

    /* *************************************** */

    /*
      Graph time and zoom: code courtesy of
      the Cacti (http://www.cacti.net) project.
    */

    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/calendar.js\"></SCRIPT>\n");
    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/lang/calendar-en.js\"></SCRIPT>\n");
    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/calendar-setup.js\"></script>\n");
    sendString("<SCRIPT type\"text/javascript\" src=\"/jscalendar/calendar-load.js\"></script>\n");

    sendString("\n<p align=center>\n<form action=/plugins/rrdPlugin name=\"form_timespan_selector\" method=\"get\">\n<TABLE width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\n<TBODY><TR><TD align=center class=\"textHeader\" nowrap=\"\">\n<b>Presets</b>: <SELECT name=\"predefined_timespan\" onchange=\"window.location=document.form_timespan_selector.predefined_timespan.options[document.form_timespan_selector.predefined_timespan.selectedIndex].value\">\n");

    option_timespan(the_time-12*3600, "-----", 1);
    option_timespan(the_time-1800, "Last Half Hour", 0);
    option_timespan(the_time-3600, "Last Hour", 0);
    option_timespan(the_time-2*3600, "Last 2 Hours", 0);
    option_timespan(the_time-4*3600, "Last 4 Hours", 0);
    option_timespan(the_time-6*3600, "Last 6 Hours", 0);
    option_timespan(the_time-12*3600, "Last 12 Hours", 0);
    option_timespan(the_time-86400, "Last Day", 0);
    option_timespan(the_time-2*86400, "Last 2 Days", 0);
    option_timespan(the_time-4*86400, "Last 4 Days", 0);
    option_timespan(the_time-7*86400, "Last Week", 0);
    option_timespan(the_time-30*86400, "Last Month", 0);
    option_timespan(the_time-2*30*86400, "Last 2 Months", 0);
    option_timespan(the_time-4*30*86400, "Last 4 Months", 0);
    option_timespan(the_time-6*30*86400, "Last 6 Months", 0);
    option_timespan(the_time-12*30*86400, "Last Year", 0);

    sendString("</select>\n");

    safe_snprintf(__FILE__, __LINE__, strbuf, sizeof(strbuf),
		  "<input type=hidden name=action value=netflowIfSummary>\n"
		  "<input type=hidden name=graphId value=\"%d\">\n"
		  "<input type=hidden name=key value=\"%s\">\n"
		  "<input type=hidden name=name value=\"%s\">\n"
		  "<input type=hidden name=start value=\"%s\">\n"
		  "<input type=hidden name=end value=\"%s\">\n"
		  "<input type=hidden name=mode value=\"zoom\">\n",
		  graphId, _rrdName, rrdInterface, startTime, endTime);
    sendString(strbuf);

    sendString("&nbsp;<STRONG>From:</STRONG>\n<INPUT type=\"text\" name=\"date1\" id=\"date1\" size=\"16\" value=\"");

    the_time = atol(startTime); the_tm = localtime(&the_time);
    strftime(strbuf, sizeof(strbuf), "%Y-%m-%d %H:%M", the_tm); sendString(strbuf);

    sendString("\">\n<INPUT type=\"image\" src=\"/calendar.gif\" alt=\"Start date selector\" "
	       "border=\"0\" align=\"absmiddle\" onclick=\"return showCalendar('date1');\">\n");
    sendString("&nbsp;<strong>To:</strong>\n<INPUT type=\"text\" name=\"date2\" id=\"date2\" size=\"16\" value=\"");

    the_time = atol(endTime); the_tm = localtime(&the_time);
    strftime(strbuf, sizeof(strbuf), "%Y-%m-%d %H:%M", the_tm); sendString(strbuf);

    sendString("\">\n<INPUT type=\"image\" src=\"/calendar.gif\" alt=\"End date selector\" border=\"0\" "
	       "align=\"absmiddle\" onclick=\"return showCalendar('date2');\">\n"
	       "<INPUT type=\"submit\" value=\"Update Graph\">\n</FORM>\n</TD></TR></TBODY></TABLE>\n</p>\n");

    /* *************************************** */

    sendString("<SCRIPT type=\"text/javascript\" src=\"/zoom.js\"></SCRIPT>\n"
	       "<DIV id=\"zoomBox\" style=\"position: absolute; visibility: visible; background-image: initial; background-repeat: initial; "
	       "background-attachment: initial; background-position-x: initial; background-position-y: initial; background-color: orange; opacity: 0.5;\"></DIV>\n");

    sendString("<DIV id=\"zoomSensitiveZone\" style=\"position:absolute; overflow:none; background-repeat: initial; "
	       "background-attachment: initial;  background-position-x: initial; background-position-y: initial; visibility:visible; "
	       "cursor:crosshair; background:blue; filter:alpha(opacity=0); -moz-opacity:0; -khtml-opacity:0; opacity:0;"
	       "\" oncontextmenu=\"return false\"></DIV>\n");

    /*
      NOTE:
      If the graph size changes, please update the zoom.js file (search for L.Deri)
    */
    safe_snprintf(__FILE__, __LINE__, strbuf, sizeof(strbuf),
                  "<img id=zoomGraphImage src=\"/" CONST_PLUGINS_HEADER "%s?graph_width=%s&graph_height=%s&action=netflowIfSummary"
		  "&graphId=%d"
		  "&key=%s"
		  "&name=%s"
		  "&start=%s"
		  "&end=%s"
		  "\" alt=\"graph image\" border=0></center>\n",
                  rrdPluginInfo->pluginURLname, rrd_width, rrd_height,
		  graphId,
		  rrdInterface, _rrdName,
                  startTime,
                  endTime);
    sendString(strbuf);

    sendString("\n<SCRIPT type=\"text/javascript\">\n\nvar cURLBase = \"/plugins/rrdPlugin?mode=zoom\";\n\n"
	       "// Global variables\nvar gZoomGraphName = \"zoomGraphImage\";\n"
	       "var gZoomGraphObj;\nvar gMouseObj;\nvar gUrlObj;\nvar gBrowserObj;\nvar gGraphWidth;\n"
	       "var gGraphHeight;\n\n\nwindow.onload = function () { initBonsai(); addReflections(); }\n\n</SCRIPT>\n");

    sendString("</center>\n");

    printHTMLtrailer();
    free_buf(buf0, MAX_NUM_ENTRIES);free_buf(buf1, MAX_NUM_ENTRIES);
    free_buf(buf2, MAX_NUM_ENTRIES);free_buf(buf3, MAX_NUM_ENTRIES);
    free_buf(buf4, MAX_NUM_ENTRIES);free_buf(buf, MAX_NUM_ENTRIES);
    return;
  }

  /* startTime[4] skips the 'now-' */
  safe_snprintf(__FILE__, __LINE__, fname, sizeof(fname), "%s/%s/%s/%s-%s%d%s",
		myGlobals.rrdPath, rrd_subdirs[2], rrdPath,
		startTime, rrdPrefix, graphId,
		CHART_FORMAT);

  revertSlashIfWIN32(fname, 0);

  if(rrds == NULL) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop RRD Graph Summary", NULL, 0);
    printFlagedWarning("<I>Error while building graph of the requested file "
		       "(unknown RRD files)</I>");
    free_buf(buf0, MAX_NUM_ENTRIES);free_buf(buf1, MAX_NUM_ENTRIES);
    free_buf(buf2, MAX_NUM_ENTRIES);free_buf(buf3, MAX_NUM_ENTRIES);
    free_buf(buf4, MAX_NUM_ENTRIES);free_buf(buf, MAX_NUM_ENTRIES);
    return;
  }

  for(i=(int)strlen(rrdPath)-1; i>0; i--)
    if(rrdPath[i] == '/')
      break;

  if(strstr(rrdPath, "/AS/"))
    safe_snprintf(__FILE__, __LINE__, title, sizeof(title),
		  "AS %s", &rrdPath[i+1]);
  else
    safe_snprintf(__FILE__, __LINE__, title, sizeof(title),
		  "NetFlow Interface %s", &rrdPath[i+1]);

  rrdGraphicRequests++;

  if(isdigit(startTime[0]) && isdigit(endTime[0])) {
    unsigned long _startTime, _endTime;

    _startTime = atol(startTime);
    _endTime   = atol(endTime);

    if(_startTime >= _endTime) {
      char *tmp = startTime;

      startTime = endTime;
      endTime   = tmp;
    }
  }

  memset(argv, 0, sizeof(argv));

  argv[argc++] = "rrd_graph";
  argv[argc++] = fname;
  argv[argc++] = "--lazy";
  argv[argc++] = "--imgformat";
  argv[argc++] = "PNG";
  argv[argc++] = "--vertical-label";
  argv[argc++] = label;
  argv[argc++] = "--watermark";
  argv[argc++] = NTOP_WATERMARK;
  argv[argc++] = "--title";
  argv[argc++] = title;
  argv[argc++] = "--start";
  argv[argc++] = startTime;
  argv[argc++] = "--end";
  argv[argc++] = endTime;
  argv[argc++] = "--slope-mode";
  argv[argc++] = "--width";
  argv[argc++] = rrd_width;
  argv[argc++] = "--height";
  argv[argc++] = rrd_height;
  argv[argc++] = "--alt-autoscale-max";
  argv[argc++] = "--lower-limit";
  argv[argc++] = "0";

#ifdef CONST_RRD_DEFAULT_FONT_NAME
  argv[argc++] = "--font";
#ifdef CONST_RRD_DEFAULT_FONT_PATH
  argv[argc++] = "DEFAULT:" CONST_RRD_DEFAULT_FONT_SIZE ":" \
    CONST_RRD_DEFAULT_FONT_PATH CONST_RRD_DEFAULT_FONT_NAME;
#else
  argv[argc++] = "DEFAULT:" CONST_RRD_DEFAULT_FONT_SIZE ":" CONST_RRD_DEFAULT_FONT_NAME;
#endif
#endif

  for(i=0, entryId=0; rrds[i] != NULL; i++) {
    if(!strcmp(rrds[i], "throughput")) {
#ifdef WIN32
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%u/%s/%s/%s.rrd",
		    myGlobals.rrdVolatilePath, driveSerial, rrd_subdirs[2], rrdPath, rrds[i]);
#else
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%s/%s/%s.rrd",
		    myGlobals.rrdVolatilePath, rrd_subdirs[2], rrdPath, rrds[i]);
#endif
    } else
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%s/%s/%s.rrd",
		    myGlobals.rrdPath, rrd_subdirs[2], rrdPath, rrds[i]);

    revertSlashIfWIN32(path, 0);
    if(stat(path, &statbuf) == 0) {
      revertDoubleColumnIfWIN32(path);
      sanitizeRrdPath(path);
      safe_snprintf(__FILE__, __LINE__, buf[entryId], MAX_BUF_LEN, "DEF:bctr%d=%s:counter:AVERAGE", entryId, path);
      argv[argc++] = buf[entryId];

      safe_snprintf(__FILE__, __LINE__, buf0[entryId], MAX_BUF_LEN, "CDEF:ctr%d=bctr%d,8,*", entryId, entryId);
      argv[argc++] = buf0[entryId];

      safe_snprintf(__FILE__, __LINE__, buf1[entryId], MAX_BUF_LEN, "%s:ctr%d%s:%s", entryId == 0 ? "AREA" : "STACK",
		    entryId, rrd_colors[entryId], spacer(&rrds[i][2], tmpStr, sizeof(tmpStr), metric_name, sizeof(metric_name), RRD_DEFAULT_SPACER_LEN));
      argv[argc++] = buf1[entryId];

      safe_snprintf(__FILE__, __LINE__, buf2[entryId], MAX_BUF_LEN, "GPRINT:ctr%d%s", entryId, ":LAST:Last\\: %8.2lf %s\\t");
      argv[argc++] = buf2[entryId];
      safe_snprintf(__FILE__, __LINE__, buf3[entryId], MAX_BUF_LEN, "GPRINT:ctr%d%s", entryId, ":AVERAGE:Avg\\: %8.2lf %s\\t");
      argv[argc++] = buf3[entryId];
      safe_snprintf(__FILE__, __LINE__, buf4[entryId], MAX_BUF_LEN, "GPRINT:ctr%d%s", entryId, ":MAX:Max\\: %8.2lf %s\\n");
      argv[argc++] = buf4[entryId];

      entryId++;
    }

    if(entryId >= MAX_NUM_ENTRIES) break;

    if(entryId >= CONST_NUM_BAR_COLORS) {
      if(colorWarn == 0) {
        traceEvent(CONST_TRACE_WARNING, "RRD: Number of defined bar colors less than max entries. Some graph(s) truncated");
        colorWarn = 1;
      }
      break;
    }
  }

#if defined(RRD_DEBUG)
  traceEventRRDebugARGV(0);
#endif

  if(debug_rrd_graph) {
    int j;

    for(j=0; j<argc; j++)
      traceEvent(CONST_TRACE_ERROR, "[%d] '%s'", j, argv[j]);
  }

  accessMutex(&rrdMutex, "rrd_graph");
  optind=0; /* reset gnu getopt */
  opterr=0; /* no error messages */

  fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);
  rrd_clear_error();
  addRrdDelay();
  rc = rrd_graph(argc, argv, &calcpr, &x, &y, NULL, &ymin, &ymax);

#if defined(RRD_DEBUG)
  traceEventRRDebugARGV(3);
#endif

  calfree();

  if(rc == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_PNG, 0, 1);
    sendFile(fname, 0);
    unlink(fname);
  } else {
#if defined(RRD_DEBUG)
    traceEventRRDebugARGV(3);
#endif

    if(++graphErrCount < 50) {
      traceEvent(CONST_TRACE_ERROR, "RRD: rrd_graph() call failed, rc %d, %s", rc, rrd_get_error() ? rrd_get_error() : "");
      traceEvent(CONST_TRACE_INFO,  "RRD: Failing file in netflowSummary() is %s", path);
    }

    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop RRD Graph Summary", NULL, 0);
    safe_snprintf(__FILE__, __LINE__, path, sizeof(path),
		  "<I>Error while building graph of the requested file. %s</I>",
		  rrd_get_error() ? rrd_get_error() : "");
    printFlagedWarning(path);
    rrd_clear_error();
  }

  releaseMutex(&rrdMutex);

  free_buf(buf0, MAX_NUM_ENTRIES);free_buf(buf1, MAX_NUM_ENTRIES);
  free_buf(buf2, MAX_NUM_ENTRIES);free_buf(buf3, MAX_NUM_ENTRIES);
  free_buf(buf4, MAX_NUM_ENTRIES);free_buf(buf, MAX_NUM_ENTRIES);
}

/* ******************************* */

static char* spacer(char* str, char *tmpStr, int tmpStrLen,
		    char *metric_name, int metric_name_len,
		    int max_spacer_len) {
  int len = (int)strlen(str), i;
  char *token, *token_name, buf[128], debug = 0, *found, *key;

  if((strlen(str) > 3) && (!strncmp(str, "IP_", 3))) str += 3;

  if(debug) traceEvent(CONST_TRACE_WARNING,  "-- 0 --> (%s)", str);

  memset(tmpStr, 0, tmpStrLen);

  if((token = strstr(str, "Bytes")) != NULL)
    token_name = "Bytes";
  else if((token = strstr(str, "Octets")) != NULL)
    token_name = "Octets";
  else if((token = strstr(str, "Pkts")) != NULL)
    token_name = "Pkts";
  else if((token = strstr(str, "Flows")) != NULL)
    token_name = "Flows";
  else if((token = strstr(str, "AS")) != NULL)
    token_name = "AS";
  else if((token = strstr(str, "Num")) != NULL)
    token_name = "Num";
  else if((token = strcasestr(str, "Efficiency")) != NULL)
    token_name = "Efficiency";
  else
    token = NULL, token_name = NULL;

  if(debug) traceEvent(CONST_TRACE_WARNING,  "-- 000 --> (%s)", str);

  if(token) {
    char add_trailer;
    char save_char = token[0];

    if(strlen(token_name) == strlen(token)) add_trailer = 0; else add_trailer = 1;

    if(debug) traceEvent(CONST_TRACE_WARNING,  "-- 11 --> (%s)(%s) [add_trailer=%d]", token, token_name, add_trailer);

    if(add_trailer) {
      if(debug) traceEvent(CONST_TRACE_WARNING,  "-- 1 --> (%s)", str);
      token[0] = '\0';
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s%s", str, &token[strlen(token_name)]);
      token[0] = save_char;
    } else {
      if(debug) traceEvent(CONST_TRACE_WARNING,  "-- 2 --> (%s)", str);
      len = (int)(strlen(str)-strlen(token));
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s", str);
      buf[len] = '\0';
    }
  } else {
    if(debug) traceEvent(CONST_TRACE_WARNING,  "-- 3 --> (%s)", str);
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s", str);
  }

  if((found = strstr(buf, "Sent")) != NULL)
    key = "Sent";
  else if((found = strstr(buf, "Rcvd")) != NULL)
    key = "Rcvd";
  else if((found = strstr(buf, "Peers")) != NULL)
    key = "Peers";
  else
    found = NULL;

  if(found) {
    found[0] = ' ';

    for(i=1; i<(1+strlen(key)); i++) found[i] = key[i-1];

    found[i] = '\0';
  }

  len = (int)strlen(buf); if(len > max_spacer_len) len = max_spacer_len;
  snprintf(tmpStr, len+1, "%s", buf);

  for(i=len; i<max_spacer_len; i++) tmpStr[i] = ' ';
  tmpStr[max_spacer_len+1] = '\0';

  if(debug) traceEvent(CONST_TRACE_WARNING,  "-- 4 --> (%s)", tmpStr);

  // traceEvent(CONST_TRACE_WARNING,  "'%s' [len=%d]", tmpStr, strlen(tmpStr));

  if(token_name)
    safe_snprintf(__FILE__, __LINE__, metric_name, metric_name_len, "%s", token_name);
  else
    memset(metric_name, 0, metric_name_len);

  return(tmpStr);
}

/* ******************************* */

static char* formatTitle(char *str, char *buf, u_short buf_len) {
  int len, shift = 0, not_found = 0, done = 0;
  char *pos;

  if(buf_len <= (strlen(str) + 10))
    return(str); /* No much space */

  if(!strncmp(str, "IP_", 3)) shift = 3;

  // traceEvent(CONST_TRACE_WARNING,  "-- 4 --> (%s)", &str[shift]);

  if(!strncmp(&str[shift], "bytesBroadcast", strlen("bytesBroadcast"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Broadcast Traffic");
    done = 1;
  } else if(!strncmp(&str[shift], "bytesMulticast", strlen("bytesMulticast"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Multicast Traffic");
    done = 1;
  } else if(!strncmp(&str[shift], "bytesRem", strlen("bytesRem"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Total Traffic: Sent to Remote");
    done = 1;
  } else if(!strncmp(&str[shift], "bytesFromRem", strlen("bytesFromRem"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Total Traffic: Rcvd from Remote");
    done = 1;
  } else if(!strncmp(&str[shift], "bytesLocSent", strlen("bytesLocSent"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Total Traffic: Sent Locally");
    done = 1;
  } else if(!strncmp(&str[shift], "bytesLoc", strlen("bytesLoc"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Total Traffic: Local Traffic");
    done = 1;
  } else if(!strncmp(&str[shift], "other", strlen("other"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Unclassified Traffic");
    done = 1;
  } else if(!strncmp(&str[shift], "ipv6", strlen("ipv6"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "IPv6 Traffic");
    //done = 1;
  } else if(!strncmp(&str[shift], "ipsec", strlen("ipsec"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "IPsec Traffic");
    done = 1;
  } else if(!strncmp(&str[shift], "ip", strlen("ip"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "IP Traffic");
    //done = 1;
  } else if((!strncmp(&str[shift], "pktBroadcast", strlen("pktBroadcast")))
	    || (!strncmp(&str[shift], "broadcastPkts", strlen("broadcastPkts")))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Broadcast Packets");
  } else if((!strncmp(&str[shift], "pktMulticast", strlen("pktMulticast")))
	    || (!strncmp(&str[shift], "multicastPkts", strlen("multicastPkts")))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Multicast Packets");
  } else if(!strncmp(&str[shift], "activeHostSendersNum", strlen("activeHostSendersNum"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Total Number of Active Host Senders");
  } else if(!strncmp(&str[shift], "totPeers", strlen("totPeers"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Total Number of Peers");
  } else if(!strncmp(&str[shift], "udp", strlen("udp"))) {
    done = 2;
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "UDP Traffic");
  } else if(!strncmp(&str[shift], "tcp", strlen("tcp"))) {
    done = 2;
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "TCP Traffic");
  } else if(!strncmp(&str[shift], "icmp", strlen("icmp"))) {
    done = 2;
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "ICMP Traffic");
  } else if((!strncmp(&str[shift], "arp_rarp", strlen("arp_rarp")))
	    || (!strncmp(&str[shift], "arpRarp", strlen("arpRarp")))) {
    done = 1;
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "(R)ARP");
  } else if(!strncmp(&str[shift], "pkt", strlen("pkt"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Packets");
  } else if(!strncmp(&str[shift], "bytes", strlen("bytes"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Total Traffic");
  } else if((pos = strstr(&str[shift], "Pkts")) != NULL) {
    pos[0] = '\0';
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "%s Packets", &str[shift]);
  } else if(!strncmp(&str[shift], "efficiency", strlen("efficiency"))) {
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Overall Efficiency");
  } else if((pos = strstr(&str[shift], "Efficiency"))) {
    pos[0] = '\0';
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "%s Efficiency", &str[shift]);
  } else if((pos = strstr(&str[shift], "Flows"))) {
    pos[0] = '\0';
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "%s F%s", &str[shift], &pos[1]);
    buf[strlen(buf)-4] = '\0';
    done = 1;
  } else if(!strncmp(&str[shift], "upTo", strlen("upTo"))) {
    int num =  atoi(&str[shift+4]);

    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Packets Up To %d Bytes", num);
  } else if((pos = strstr(&str[shift], "Bytes"))) {
    pos[0] = '\0';
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "%s Traffic", &str[shift]);
    done = 1;
  } else if((pos = strstr(&str[shift], "knownHostsNum"))) {
    pos[0] = '\0';
    safe_snprintf(__FILE__, __LINE__, buf, buf_len, "Total Number of Known Hosts");
    done = 1;
  } else
    not_found = 1, safe_snprintf(__FILE__, __LINE__, buf, buf_len, "%s", &str[shift]);

  if(done == 2) {
    //traceEvent(CONST_TRACE_WARNING,  "-- 2 --> (%s)", &str[shift]);

    if(strstr(&str[shift], "LocSent"))
      safe_snprintf(__FILE__, __LINE__, &buf[strlen(buf)], buf_len-strlen(buf), ": Sent Locally");
    else if(strstr(&str[shift], "FromRemRcvd"))
      safe_snprintf(__FILE__, __LINE__, &buf[strlen(buf)], buf_len-strlen(buf), ": Rcvd from Remote");
    else if((strstr(&str[shift], "RemSent")) || (strstr(&str[shift], "Rem")))
      safe_snprintf(__FILE__, __LINE__, &buf[strlen(buf)], buf_len-strlen(buf), ": Sent Remotely");
    else if(strstr(&str[shift], "Loc"))
      safe_snprintf(__FILE__, __LINE__, &buf[strlen(buf)], buf_len-strlen(buf), ": Local Traffic");
    else if(strstr(&str[shift], "Fragments"))
      safe_snprintf(__FILE__, __LINE__, &buf[strlen(buf)], buf_len-strlen(buf), ": Fragmented Traffic");
  } else if(!done) {
    len = (int)strlen(str), buf_len = (int)strlen(buf);

    //traceEvent(CONST_TRACE_WARNING,  "-- ** --> (%s)", &str[2]);

    if(!strcmp(&str[len-7], "LocSent")) {
      if(not_found) buf[len-7] = '\0';
      strcat(buf, " Sent Locally");
    } else if(!strcmp(&str[len-9], "BytesSent")) {
      buf[buf_len-9] = '\0';
      strcat(buf, " Sent");
    } else if(!strcmp(&str[len-7], "RemSent")) {
      if(not_found) buf[len-7] = '\0';
      strcat(buf, " Sent to Remote Hosts");
    } else if(!strcmp(&str[len-4], "Sent")) {
      if(not_found) buf[len-4] = '\0';
      strcat(buf, " Sent");
    } else if(!strcmp(&str[len-9], "BytesRcvd")) {
      if(not_found) buf[len-9] = '\0';
      strcat(buf, " Received");
    } else if(strstr(&str[shift], "LocalToLocal")) {
      if(not_found) buf[len-7] = '\0';
      strcat(buf, " Local to Local");
    } else if(strstr(&str[shift], "LocalToRemote")) {
      if(not_found) buf[len-7] = '\0';
      strcat(buf, " Local to Remote");
    } else if(strstr(&str[shift], "RemoteToLocal")) {
      if(not_found) buf[len-7] = '\0';
      strcat(buf, " Remote to Local");
    } else if(strstr(&str[shift], "RemoteToRemote")) {
      if(not_found) buf[len-7] = '\0';
      strcat(buf, " Remote to Remote");
    } else if(!strcmp(&str[len-11], "FromRemRcvd")) {
      if(not_found) buf[len-11] = '\0';
      strcat(buf, " Rcvd From Remote Hosts");
    } else if(!strcmp(&str[len-4], "Rcvd")) {
      if(not_found) str[len-4] = '\0';
      strcat(buf, " Received");
    } else if(!strcmp(&str[len-19], "RemoteToRemoteBytes")) {
      buf[buf_len-19] = '\0';
      strcat(buf, " Remote to Remote");
    } else if(!strcmp(&str[len-5], "Bytes")) {
      if(strncmp(&buf[buf_len-5], "Bytes", strlen("Bytes")) == 0)
	buf[buf_len-5] = '\0';
      strcat(buf, " Volume");
    } else if(!strcmp(&str[len-5], "Flows")) {
      if(strncmp(&buf[buf_len-5], "Flows", strlen("Flows")) == 0)
	buf[buf_len-5] = '\0';
      strcat(buf, " Flows");
    }
  }

  buf[0] = toupper(buf[0]);

  return(buf);
}

/* ****************************** */

#undef option_timespan
#define option_timespan(theStartTime, theLabel, selected)		\
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),			\
		"<option value=\"/" CONST_PLUGINS_HEADER "%s?graph_width=%s&graph_height=%s&action=graphSummary" \
		"&key=%s"						\
		"&graphId=%d"						\
		"&start=%u"						\
		"&end=%u"						\
		"&mode=zoom&name=%s\" %s>%s</option>\n",		\
		"rrdPlugin", rrd_width, rrd_height, rrdInterface, graphId, (unsigned int)theStartTime, (unsigned int)the_time, \
		_rrdName, (selected == 1) ? "selected" : "", theLabel); sendString(buf);

/* ******************************* */

#define MAX_NUM_RRD_ENTRIES     3
#define MAX_NUM_RRD_HOSTS      32

static void graphSummary(char *rrdPath, char *rrdName, int graphId,
			 char *startTime, char* endTime, char *rrdPrefix, char *mode) {
  char path[512], *argv[32 /* base prefs */+6*MAX_NUM_ENTRIES /* rrd entries */];
  char tmpStr[32], fname[384], *label, rrdPath_copy[512];
  char *buf0[MAX_NUM_ENTRIES], *buf1[MAX_NUM_ENTRIES], *buf2[MAX_NUM_ENTRIES],
    *buf3[MAX_NUM_ENTRIES], *buf4[MAX_NUM_ENTRIES], *buf5[MAX_NUM_ENTRIES];
  char metric_name[32], title_buf[64], ip_buf[64];
  char _rrdName[256], *net_efficiency = NULL;
  char rrd_height[RRD_GRAPH_SIZE], rrd_width[RRD_GRAPH_SIZE];
  char **rrds = NULL, ipRRDs[MAX_NUM_ENTRIES][MAX_BUF_LEN], *myRRDs[MAX_NUM_ENTRIES];
  int argc = 0, rc, x, y, i, entryId=0, num_rrd_hosts_path = 0, j;
  DIR* directoryPointer;
  char *rrd_custom[MAX_NUM_RRD_ENTRIES], *rrd_hosts_path[MAX_NUM_RRD_HOSTS],
    *rrd_hosts[MAX_NUM_RRD_HOSTS], file_a[32], file_b[32], *upside;
  double ymin,ymax;
  u_int8_t upside_down = 0, no_mem = 0;
  u_char titleAlreadySent = 0;

  // if((!active) || (!initialized)) return;
  i = (int)strlen(rrdPath); if((i > 1) && (rrdPath[i-1] == '/')) rrdPath[i-1] = '\0';

  path[0] = '\0', label = "";
  safe_snprintf(__FILE__, __LINE__, _rrdName, sizeof(_rrdName), "%s", rrdName);

  alloc_buf(buf0, MAX_NUM_ENTRIES, (2*MAX_BUF_LEN));
  alloc_buf(buf1, MAX_NUM_ENTRIES, (2*MAX_BUF_LEN));
  alloc_buf(buf2, MAX_NUM_ENTRIES, (2*MAX_BUF_LEN));
  alloc_buf(buf3, MAX_NUM_ENTRIES, (2*MAX_BUF_LEN));
  alloc_buf(buf4, MAX_NUM_ENTRIES, (2*MAX_BUF_LEN));
  alloc_buf(buf5, MAX_NUM_ENTRIES, (2*MAX_BUF_LEN));

  if(no_mem) {
    traceEvent(CONST_TRACE_WARNING,  "Not enough memory");
    free_buf(buf0, MAX_NUM_ENTRIES);free_buf(buf1, MAX_NUM_ENTRIES);
    free_buf(buf2, MAX_NUM_ENTRIES);free_buf(buf3, MAX_NUM_ENTRIES);
    free_buf(buf4, MAX_NUM_ENTRIES);free_buf(buf5, MAX_NUM_ENTRIES);
    return;
  }

  fetch_graph_size(rrd_height, rrd_width);

  switch(graphId) {
  case 0: rrds = (char**)rrd_summary_packets;       label = "Pkt/s"; break;
  case 1: rrds = (char**)rrd_summary_packet_sizes;  label = "Pkt/s"; break;
  case 2: rrds = (char**)rrd_summary_proto_bytes;   label = "Bit/s"; break;
  case 3: rrds = (char**)rrd_summary_ipproto_bytes; label = "Bit/s"; break;
  case 4:
    safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%s", myGlobals.rrdPath, rrdPath);

    revertSlashIfWIN32(path, 0);

    directoryPointer = opendir(path);

    if(directoryPointer == NULL)
      rrds = NULL;
    else {
      struct dirent* dp;

      i = 0;

      while((dp = readdir(directoryPointer)) != NULL) {
	int len = (int)strlen(dp->d_name);

	if(dp->d_name[0] == '.') continue;
	else if(len < 7 /* IP_ + .rrd */ ) continue;
	else if(strncmp(dp->d_name, "IP_", 3)) continue;
	else if(strstr(dp->d_name, "Flows")) continue;

	len -= 4; if(len > MAX_BUF_LEN) len = MAX_BUF_LEN-1;
	dp->d_name[len] = '\0';
	safe_snprintf(__FILE__, __LINE__, ipRRDs[i], MAX_BUF_LEN, "%s", dp->d_name);
	myRRDs[i] = ipRRDs[i];
	i++; if(i >= (MAX_NUM_ENTRIES-1)) break;
      }

      myRRDs[i] = NULL;
      rrds = (char**)myRRDs;
      closedir(directoryPointer);
    }
    label = "Bit/s";
    break;
  case 5: rrds = (char**)rrd_summary_local_remote_ip_bytes; label = "Bit/s"; break;
  case 6: rrds = (char**)rrd_summary_host_sentRcvd_packets; label = "Pkt/s"; break;
  case 7: rrds = (char**)rrd_summary_host_sentRcvd_bytes; label = "Bit/s"; break;

  case 98:
    {
      char *host, *strTokPos;

      rrd_custom[0] = rrdName;
      rrd_custom[1] = NULL;
      rrds = (char**)rrd_custom;

      safe_snprintf(__FILE__, __LINE__, rrdPath_copy, sizeof(rrdPath_copy), "%s", rrdPath);
      host = strtok_r(rrdPath_copy, ",", &strTokPos);
      if(host) {
	char tmpPath[64];

	while(host != NULL) {
	  char *strTokPosHost, *the_host, *the_num_host;

	  if(num_rrd_hosts_path == MAX_NUM_RRD_HOSTS) break;

	  the_host     = strtok_r(host, "@", &strTokPosHost);
	  the_num_host = strtok_r(NULL, "@", &strTokPosHost);
	  if((the_num_host == NULL) || (the_num_host[0] == '\0')) the_num_host = "no_name";

	  rrd_hosts[num_rrd_hosts_path] = strdup(the_num_host);
	  for(y=0; y<(int)strlen(host); y++) if(host[y] == '.') host[y] = '/';

	  safe_snprintf(__FILE__, __LINE__, tmpPath, sizeof(tmpPath),
			"interfaces/%s/hosts/%s",
			myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
			the_host);

	  for(y=(int)strlen(tmpPath)-(int)strlen(the_host); y<(int)strlen(tmpPath); y++)
	    if((path[y] == '.') || (path[y] == ':')) path[y] = '/';

	  rrd_hosts_path[num_rrd_hosts_path++] = strdup(tmpPath);
	  host = strtok_r(NULL, ",", &strTokPos);
	}
      }
    }
    break;

  case 99:
    /* rrdName format can be IP_<proto><Rcvd|Sent><Bytes|Pkts|Flows> */
    {
      char *sent  = strstr(rrdName, "Sent");
      char *rcvd  = strstr(rrdName, "Rcvd");
      char *pkts  = strstr(rrdName, "Pkts");
      char *flows = strstr(rrdName, "Flows");

      net_efficiency = strcasestr(rrdName, "Efficiency");

      if(sent || rcvd) {
	if(sent) sent[0]  = '\0'; else rcvd[0] = '\0';

	snprintf(file_a, sizeof(file_a), "%sSent", rrdName);
	snprintf(file_b, sizeof(file_b), "%sRcvd", rrdName);

	rrd_custom[0] = file_a;
	rrd_custom[1] = file_b;
	rrd_custom[2] = NULL;
	rrds = (char**)rrd_custom;
	upside_down = 1;
	/* traceEvent(CONST_TRACE_WARNING, "RRD: [%s][%s]", file_a, file_b); */
      } else {
	snprintf(file_a, sizeof(file_a), "%s", rrdName);
	file_a[(int)strlen(file_a)-(int)strlen(CONST_RRD_EXTENSION)] = '\0';
	rrd_custom[0] = file_a;
	rrd_custom[1] = NULL;
	rrds = (char**)rrd_custom;

	/* traceEvent(CONST_TRACE_WARNING, "RRD: Not found [%s]", rrdName); */
      }

      if(pkts || strstr(rrdName, "pkt"))
	label = "Pkt/s";
      else if(strstr(rrdName, "Peers"))
	label = "Contacted Peers";
      else if(strstr(rrdName, "knownHosts"))
	label = "Hosts";
      else if(strstr(rrdName, "Senders"))
	label = "Peers";
      else if(net_efficiency)
	label = "Efficiency (%)";
      else if(flows)
	label = "Flows/s";
      else
	label = "Bit/s";
    }

    break;
  }

  if(!strcmp(mode, "zoom")) {
    char buf[LEN_GENERAL_WORK_BUFFER];
    time_t the_time = time(NULL);
    char *rrdInterface = rrdPath;
    struct tm *the_tm;

    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop RRD Graph", NULL, 0);

    sendString("<center>\n");

    /* *************************************** */

    /*
      Graph time and zoom: code courtesy of
      the Cacti (http://www.cacti.net) project.
    */

    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/calendar.js\"></SCRIPT>\n");
    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/lang/calendar-en.js\"></SCRIPT>\n");
    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/calendar-setup.js\"></script>\n");
    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/calendar-load.js\"></script>\n");

    sendString("\n<p align=center>\n<form action=/plugins/rrdPlugin name=\"form_timespan_selector\" method=\"get\">\n<TABLE width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\n<TBODY><TR><TD align=center class=\"textHeader\" nowrap=\"\">\n<b>Presets</b>: <SELECT name=\"predefined_timespan\" onchange=\"window.location=document.form_timespan_selector.predefined_timespan.options[document.form_timespan_selector.predefined_timespan.selectedIndex].value\">\n");
    option_timespan(the_time-12*3600, "-----", 1);
    option_timespan(the_time-1800, "Last Half Hour", 0);
    option_timespan(the_time-3600, "Last Hour", 0);
    option_timespan(the_time-2*3600, "Last 2 Hours", 0);
    option_timespan(the_time-4*3600, "Last 4 Hours", 0);
    option_timespan(the_time-6*3600, "Last 6 Hours", 0);
    option_timespan(the_time-12*3600, "Last 12 Hours", 0);
    option_timespan(the_time-86400, "Last Day", 0);
    option_timespan(the_time-2*86400, "Last 2 Days", 0);
    option_timespan(the_time-4*86400, "Last 4 Days", 0);
    option_timespan(the_time-7*86400, "Last Week", 0);
    option_timespan(the_time-30*86400, "Last Month", 0);
    option_timespan(the_time-2*30*86400, "Last 2 Months", 0);
    option_timespan(the_time-4*30*86400, "Last 4 Months", 0);
    option_timespan(the_time-6*30*86400, "Last 6 Months", 0);
    option_timespan(the_time-12*30*86400, "Last Year", 0);

    sendString("</select>\n");

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<input type=hidden name=action value=graphSummary>\n"
		  "<input type=hidden name=key value=\"%s\">\n"
		  "<input type=hidden name=graphId value=\"%d\">\n"
		  "<input type=hidden name=name value=\"%s\">\n"
		  "<input type=hidden name=start value=\"%s\">\n"
		  "<input type=hidden name=end value=\"%s\">\n"
		  "<input type=hidden name=mode value=\"zoom\">\n",
		  rrdInterface, graphId, _rrdName, startTime, endTime);
    sendString(buf);

    sendString("&nbsp;<STRONG>From:</STRONG>\n<INPUT type=\"text\" name=\"date1\" id=\"date1\" size=\"16\" value=\"");

    the_time = atol(startTime); the_tm = localtime(&the_time);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", the_tm); sendString(buf);

    sendString("\">\n<INPUT type=\"image\" src=\"/calendar.gif\" alt=\"Start date selector\" border=\"0\" "
	       "align=\"absmiddle\" onclick=\"return showCalendar('date1');\">\n");
    sendString("&nbsp;<strong>To:</strong>\n<INPUT type=\"text\" name=\"date2\" id=\"date2\" size=\"16\" value=\"");

    the_time = atol(endTime); the_tm = localtime(&the_time);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", the_tm); sendString(buf);

    sendString("\">\n<INPUT type=\"image\" src=\"/calendar.gif\" alt=\"End date selector\" border=\"0\" "
	       "align=\"absmiddle\" onclick=\"return showCalendar('date2');\">\n"
	       "<INPUT type=\"submit\" value=\"Update Graph\">\n</FORM>\n</TD></TR></TBODY></TABLE>\n</p>\n");

    /* *************************************** */

    sendString("<SCRIPT type=\"text/javascript\" src=\"/zoom.js\"></SCRIPT>\n"
	       "<DIV id=\"zoomBox\" style=\"position: absolute; visibility: visible; background-image: initial; background-repeat: initial; "
	       "background-attachment: initial; background-position-x: initial; background-position-y: initial; "
	       "background-color: orange; opacity: 0.5;\"></DIV>\n");

    sendString("<DIV id=\"zoomSensitiveZone\" style=\"position:absolute; overflow:none; background-repeat: initial; background-attachment: initial;  background-position-x: initial; background-position-y: initial; visibility:visible; cursor:crosshair; background:blue; filter:alpha(opacity=0); -moz-opacity:0; -khtml-opacity:0; opacity:0;\" oncontextmenu=\"return false\"></DIV>\n");

    /*
      NOTE:
      If the graph size changes, please update the zoom.js file (search for L.Deri)
    */
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                  "<img id=zoomGraphImage src=\"/" CONST_PLUGINS_HEADER "%s?graph_width=%s&graph_height=%s&action=graphSummary"
		  "&graphId=%d"
		  "&key=%s"
		  "&name=%s"
		  "&start=%s"
		  "&end=%s"
		  "\" alt=\"graph image\" border=0></center>\n",
                  rrdPluginInfo->pluginURLname, rrd_width, rrd_height,
		  graphId,
		  rrdInterface, _rrdName,
                  startTime,
                  endTime);
    sendString(buf);

    sendString("\n<SCRIPT type=\"text/javascript\">\n\nvar cURLBase = \"/plugins/rrdPlugin?mode=zoom\";\n\n"
	       "// Global variables\nvar gZoomGraphName = \"zoomGraphImage\";\n"
	       "var gZoomGraphObj;\nvar gMouseObj;\nvar gUrlObj;\nvar gBrowserObj;\nvar gGraphWidth;\n"
	       "var gGraphHeight;\n\n\nwindow.onload = function () { initBonsai(); addReflections(); }\n\n</SCRIPT>\n");

    sendString("</center>\n");

    printHTMLtrailer();

    free_buf(buf0, MAX_NUM_ENTRIES);free_buf(buf1, MAX_NUM_ENTRIES);
    free_buf(buf2, MAX_NUM_ENTRIES);free_buf(buf3, MAX_NUM_ENTRIES);
    free_buf(buf4, MAX_NUM_ENTRIES);free_buf(buf5, MAX_NUM_ENTRIES);
    return;
  }

  /* startTime[4] skips the 'now-' */
  safe_snprintf(__FILE__, __LINE__, fname, sizeof(fname), "%s/%s/%s-%s%d%s",
		myGlobals.rrdPath, rrd_subdirs[0],
		startTime, rrdPrefix, graphId,
		CHART_FORMAT);

  revertSlashIfWIN32(fname, 0);

  if(rrds == NULL) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop RRD Graph Summary", NULL, 0);
    printFlagedWarning("<I>Error while building graph of the requested file "
		       "(unknown RRD files)</I>");
    free_buf(buf0, MAX_NUM_ENTRIES);free_buf(buf1, MAX_NUM_ENTRIES);
    free_buf(buf2, MAX_NUM_ENTRIES);free_buf(buf3, MAX_NUM_ENTRIES);
    free_buf(buf4, MAX_NUM_ENTRIES);free_buf(buf5, MAX_NUM_ENTRIES);
    return;
  }

  if(isdigit(startTime[0]) && isdigit(endTime[0])) {
    unsigned long _startTime, _endTime;

    _startTime = atol(startTime);
    _endTime   = atol(endTime);

    if(_startTime >= _endTime) {
      char *tmp = startTime;

      startTime = endTime;
      endTime   = tmp;
    }
  }

  rrdGraphicRequests++;
  argv[argc++] = "rrd_graph";
  argv[argc++] = fname;
  argv[argc++] = "--lazy";
  argv[argc++] = "--imgformat";
  argv[argc++] = "PNG";
  argv[argc++] = "--vertical-label";
  argv[argc++] = label;
  argv[argc++] = "--watermark";
  argv[argc++] = NTOP_WATERMARK;
  argv[argc++] = "--start";
  argv[argc++] = startTime;
  argv[argc++] = "--end";
  argv[argc++] = endTime;
  argv[argc++] = "--slope-mode";
  argv[argc++] = "--width";
  argv[argc++] = rrd_width;
  argv[argc++] = "--height";
  argv[argc++] = rrd_height;
  argv[argc++] = "--alt-autoscale-max";
  argv[argc++] = "--lower-limit";
  argv[argc++] = "0";

  if((graphId == 98) || (graphId == 99)) {
    argv[argc++] = "--title";
    argv[argc++] = formatTitle(rrdName, title_buf, sizeof(title_buf));
    titleAlreadySent = 1;
  }

  if(net_efficiency) {
    argv[argc++] = "--lower-limit";
    argv[argc++] = "-100";
    argv[argc++] = "--upper-limit";
    argv[argc++] = "100";
  }

#ifdef CONST_RRD_DEFAULT_FONT_NAME
  argv[argc++] = "--font";
#ifdef CONST_RRD_DEFAULT_FONT_PATH
  argv[argc++] = "DEFAULT:" CONST_RRD_DEFAULT_FONT_SIZE ":" \
    CONST_RRD_DEFAULT_FONT_PATH CONST_RRD_DEFAULT_FONT_NAME;
#else
  argv[argc++] = "DEFAULT:" CONST_RRD_DEFAULT_FONT_SIZE ":" CONST_RRD_DEFAULT_FONT_NAME;
#endif
#endif
  revertDoubleColumnIfWIN32(path);

  if(graphId != 98) {
    rrd_hosts_path[num_rrd_hosts_path++] = strdup(rrdPath);
  }

  for(j=0, entryId=0; j<num_rrd_hosts_path; j++) {
    for(i=0; rrds[i] != NULL; i++) {
      struct stat statbuf;
      int is_efficiency;

      if(strcasestr(rrds[i], "Efficiency")) is_efficiency = 1; else is_efficiency = 0;

      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%s/%s%s",
		    myGlobals.rrdPath, rrd_hosts_path[j], rrds[i], CONST_RRD_EXTENSION);
      revertSlashIfWIN32(path, 0);

      // traceEvent(CONST_TRACE_WARNING,  "-- 4 --> (%s) [%d/%d]", path, j, num_rrd_hosts_path);

      if(stat(path, &statbuf) == 0) {
	char do_upside, *str, *filename;
	int multiplier = 1;

	filename = (graphId == 98) ? rrd_hosts[j] : rrds[i];

	if(strcasestr(filename, "Bytes") || strcasestr(filename, "Octets")) multiplier = 8;

	if(upside_down && (i == 1)) {
	  safe_snprintf(__FILE__, __LINE__, buf0[entryId], 2*MAX_BUF_LEN,
			"DEF:my_ctr%d=%s:counter:AVERAGE", entryId, sanitizeRrdPath(path));
	  argv[argc++] = buf0[entryId];
	  safe_snprintf(__FILE__, __LINE__, buf2[entryId], 2*MAX_BUF_LEN,
			"CDEF:ctr%d=my_ctr%d,%d,*", entryId, entryId, -1 * multiplier);
	  argv[argc++] = buf2[entryId];

	  str = spacer(filename, tmpStr, sizeof(tmpStr),
		       metric_name, sizeof(metric_name), RRD_DEFAULT_SPACER_LEN);

	  safe_snprintf(__FILE__, __LINE__, buf1[entryId], 2*MAX_BUF_LEN,
			"%s:ctr%d%s:%s\t", "AREA",
			entryId,
			((graphId == 99) && is_efficiency) ? "#EBEB00" : rrd_colors[1],
			(graphId == 99) ? "Rcvd" : str);

	  argv[argc++] = buf1[entryId];
	  do_upside = 1;
	} else {
	  str = spacer(filename, tmpStr, sizeof(tmpStr),
		       metric_name, sizeof(metric_name), RRD_DEFAULT_SPACER_LEN);

	  safe_snprintf(__FILE__, __LINE__, buf0[entryId], 2*MAX_BUF_LEN,
			"DEF:my_ctr%d=%s:counter:AVERAGE", entryId, sanitizeRrdPath(path));
	  argv[argc++] = buf0[entryId];

	  safe_snprintf(__FILE__, __LINE__, buf2[entryId], 2*MAX_BUF_LEN,
			"CDEF:ctr%d=my_ctr%d,%d,*", entryId, entryId, multiplier);
	  argv[argc++] = buf2[entryId];

	  safe_snprintf(__FILE__, __LINE__, buf1[entryId], 2*MAX_BUF_LEN,
			"%s:ctr%d%s:%s\t", entryId == 0 ? "AREA" : "STACK",
			entryId,
			((graphId == 99) && is_efficiency) ? "#B0E1B0" : rrd_colors[entryId],
			(graphId == 99) ? "Sent" : str);
	  argv[argc++] = buf1[entryId];
	  do_upside = 0;

	  safe_snprintf(__FILE__, __LINE__, ip_buf, sizeof(ip_buf),
			"%s", (!strncmp(rrdName, "IP_", 3)) ? &rrdName[3] : rrdName);
	  if((int)strlen(ip_buf) > (int)strlen(metric_name))
	    ip_buf[(int)strlen(ip_buf)-(int)strlen(metric_name)] = '\0';

	  if(!titleAlreadySent) {
	    titleAlreadySent = 1;

	    if(graphId == 99) {
	      argv[argc++] = "--title";
	      // traceEvent(CONST_TRACE_INFO, "RRD: --> (%s)", filename);
	      argv[argc++] = formatTitle(filename, title_buf, sizeof(title_buf));
	    } else if(graphId == 4) {
	      argv[argc++] = "--title";
	      argv[argc++] = "Protocols: Aggregated View";
	    }
	  }
	}

	if(do_upside) upside = "my_"; else upside = "";

	safe_snprintf(__FILE__, __LINE__, buf3[entryId], 2*MAX_BUF_LEN, "GPRINT:%sctr%d%s", upside, entryId, ":MAX:Max\\: %3.1lf%s\\t");
	argv[argc++] = buf3[entryId];

	safe_snprintf(__FILE__, __LINE__, buf4[entryId], 2*MAX_BUF_LEN, "GPRINT:%sctr%d%s", upside, entryId, ":AVERAGE:Avg\\: %3.1lf%s\\t");
	argv[argc++] = buf4[entryId];

	safe_snprintf(__FILE__, __LINE__, buf5[entryId], 2*MAX_BUF_LEN, "GPRINT:%sctr%d%s", upside, entryId, ":LAST:Last\\: %3.1lf%s\\n");
	argv[argc++] = buf5[entryId];

	entryId++;
      }

      if(entryId >= MAX_NUM_ENTRIES) break;

      if(entryId >= CONST_NUM_BAR_COLORS) {
	if(colorWarn == 0) {
	  traceEvent(CONST_TRACE_ERROR,
		     "RRD: Number of defined bar colors less than max entries.  Graphs may be truncated");
	  colorWarn = 1;
	}
	break;
      }
    }
  }

  if(debug_rrd_graph) {
    for(j=0; j<argc; j++)
      traceEvent(CONST_TRACE_ERROR, "[%d] '%s'", j, argv[j]);
  }

  accessMutex(&rrdMutex, "rrd_graph");
  optind = 0; /* reset gnu getopt */
  opterr = 0; /* no error messages */

  fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);
  rrd_clear_error();
  addRrdDelay();

  if(0) {
    traceEvent(CONST_TRACE_ERROR, "upside_down=%d", upside_down);

    for(j=0; j<argc; j++)
      traceEvent(CONST_TRACE_ERROR, "[%d] '%s'", j, argv[j]);
  }

  rc = rrd_graph(argc, argv, &calcpr, &x, &y, NULL, &ymin, &ymax);
  calfree();

  for(i=0; i<num_rrd_hosts_path; i++) {
    if(graphId == 98) free(rrd_hosts[i]);
    free(rrd_hosts_path[i]);
  }

  if(rc == 0) {
    sendHTTPHeader(FLAG_HTTP_TYPE_PNG, 0, 1);
    sendFile(fname, 0);
    unlink(fname);
  } else {
#if defined(RRD_DEBUG)
    traceEventRRDebugARGV(3);
#endif

    if(++graphErrCount < 50) {
      traceEvent(CONST_TRACE_ERROR, "RRD: rrd_graph() call failed, rc %d, %s", rc, rrd_get_error() ? rrd_get_error() : "");
      traceEvent(CONST_TRACE_INFO, "RRD: Failing file in graphSummary() is %s", path);
    }

    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop RRD Graph Summary", NULL, 0);
    safe_snprintf(__FILE__, __LINE__, path, sizeof(path),
		  "<I>Error while building graph of the requested file. %s</I>",
		  rrd_get_error() ? rrd_get_error() : "");
    printFlagedWarning(path);
    rrd_clear_error();
  }

  releaseMutex(&rrdMutex);

  free_buf(buf0, MAX_NUM_ENTRIES);free_buf(buf1, MAX_NUM_ENTRIES);
  free_buf(buf2, MAX_NUM_ENTRIES);free_buf(buf3, MAX_NUM_ENTRIES);
  free_buf(buf4, MAX_NUM_ENTRIES);free_buf(buf5, MAX_NUM_ENTRIES);
}

/* ******************************* */

static time_t checkLast(char *rrd) {
  time_t lastTime;
  char *argv[32];
  int argc = 0;

  // if((!active) || (!initialized)) return(0);

  argc = 0;
  argv[argc++] = "rrd_last";
  argv[argc++] = rrd;

  accessMutex(&rrdMutex, "rrd_last");
  optind=0; /* reset gnu getopt */
  opterr=0; /* no error messages */

  fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);
  rrd_clear_error();
  addRrdDelay();
  lastTime = rrd_last(argc, argv);

  releaseMutex(&rrdMutex);

  return(lastTime);
}

/* ******************************* */

static void deleteRRD(char *basePath, char *key) {
  char path[512];
  int i;

  safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s%s.rrd", basePath, key);

  /* Avoid path problems */
  for(i=(int)strlen(basePath); i<(int)strlen(path); i++)
    if(path[i] == '/') path[i]='_';

  revertSlashIfWIN32(path, 0);

  if(unlink(path) != 0)
    traceEvent(CONST_TRACE_WARNING,
	       "THREADMGMT[t%lu]: RRD: deleteRRD(%s) failed: %s",
	       (long unsigned int)pthread_self(), path, strerror(errno));
}

/* ******************************* */

static int updateRRD(char *hostPath, char *key, Counter value, int isCounter, char short_step) {
  char path[512], *argv[32], cmd[64];
  struct stat statbuf;
  int argc = 0, rc = 0, createdCounter = 0, i;
  struct timeval rrdStartOfProcessing, rrdEndOfProcessing;
  float elapsed;
  
    if(value == 0) return(0);

    gettimeofday(&rrdStartOfProcessing, NULL);

    safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s%s.rrd", hostPath, key);

    /* Avoid path problems */
    for(i=(int)strlen(hostPath); i<(int)strlen(path); i++)
      if(path[i] == '/') path[i]='_';

    revertSlashIfWIN32(path, 0);

    if(stat(path, &statbuf) != 0) {
      char startStr[32], stepStr[32], counterStr[64], intervalStr[32];
      char minStr[32], maxStr[32], daysStr[32], monthsStr[32];
      char tempStr[64];

      int step, heartbeat;
      int value1, value2, rrdDumpInterval;
      unsigned long topValue;

      rrdDumpInterval = short_step ? (2*dumpShortInterval) : dumpInterval;
      step = rrdDumpInterval;

      topValue = 1000000000 /* 1 Gbit/s */;

      if(strstr(key, "throughput")) {
	; /* Nothing to do as throughput is saved in Mbps */
      } else if(strncmp(key, "pkt", 3) == 0) {
	topValue /= 8*64 /* 64 bytes is the shortest packet we care of */;
      } else {
	topValue /= 8 /* 8 bytes */;
      }

      heartbeat = dumpHeartbeatMultiplier * step;
      argv[argc++] = "rrd_create";
      argv[argc++] = path;
      argv[argc++] = "--start";
      safe_snprintf(__FILE__, __LINE__, startStr, sizeof(startStr), "%u",
		    myGlobals.rrdTime-1 /* -1 avoids subsequent rrd_update call problems */);
      argv[argc++] = startStr;

      argv[argc++] = "--step";
      safe_snprintf(__FILE__, __LINE__, stepStr, sizeof(stepStr), "%u", rrdDumpInterval);
      argv[argc++] = stepStr;

      if(0) {
	int j;

	for(j=0; j<argc; j++)
	  traceEvent(CONST_TRACE_ERROR, "[%d] '%s'", j, argv[j]);
      }

      if(isCounter) {
	/*
	  The use of DERIVE should avoid spikes on graphs when
	  ntop is restarted.
	  Patch courtesy of Graeme Fowler <graeme@graemef.net>
	 */
	safe_snprintf(__FILE__, __LINE__, counterStr, sizeof(counterStr),
		      "DS:counter:%s:%d:0:%u",
		      "DERIVE" /* "COUNTER" */,
		      heartbeat, topValue);
      } else {
	/*
	  Unlimited (sort of)
	  Well I have decided to add a limit too in order to avoid crazy values.
	*/
	safe_snprintf(__FILE__, __LINE__, counterStr, sizeof(counterStr),
		      "DS:counter:GAUGE:%d:0:%u", heartbeat, topValue);
      }
      argv[argc++] = counterStr;

      /* rrdDumpInterval is in seconds.  There are 60m*60s = 3600s in an hour.
       * value1 is the # of rrdDumpIntervals per hour
       */
      value1 = (60*60 + rrdDumpInterval - 1) / rrdDumpInterval;
      /* value2 is the # of value1 (hours) for dumpHours hours */
      value2 = value1 * dumpHours;
      safe_snprintf(__FILE__, __LINE__, intervalStr, sizeof(intervalStr),
		    "RRA:AVERAGE:%.1f:1:%d", 0.5, value2);
      argv[argc++] = intervalStr;

      /* Store the MIN/MAX 5m value for a # of hours */
      safe_snprintf(__FILE__, __LINE__, minStr, sizeof(minStr), "RRA:MIN:%.1f:1:%d",
		    0.5, dumpHours > 0 ? dumpHours : DEFAULT_RRD_HOURS);
      argv[argc++] = minStr;
      safe_snprintf(__FILE__, __LINE__, maxStr, sizeof(maxStr), "RRA:MAX:%.1f:1:%d",
		    0.5, dumpHours > 0 ? dumpHours : DEFAULT_RRD_HOURS);
      argv[argc++] = maxStr;

      if(dumpDays > 0) {
	safe_snprintf(__FILE__, __LINE__, daysStr, sizeof(daysStr), "RRA:AVERAGE:%.1f:%d:%d",
		      0.5, value1, dumpDays * 24);
	argv[argc++] = daysStr;
      }

      /* Compute the rollup - how many rrdDumpInterval seconds interval are in a day */
      value1 = (24*60*60 + rrdDumpInterval - 1) / rrdDumpInterval;
      if(dumpMonths > 0) {
	safe_snprintf(__FILE__, __LINE__, monthsStr, sizeof(monthsStr),
		      "RRA:AVERAGE:%.1f:%d:%d",
		      0.5, value1, dumpMonths * 30);
	argv[argc++] = monthsStr;
      }

      safe_snprintf(__FILE__, __LINE__, tempStr, sizeof(tempStr),
		    "RRA:HWPREDICT:1440:0.1:0.0035:20");
      argv[argc++] = tempStr;

      if(0) {
	int j;

	for(j=0; j<argc; j++)
	  traceEvent(CONST_TRACE_ERROR, "[%d] '%s'", j, argv[j]);
      }

      accessMutex(&rrdMutex, "rrd_create");
      optind=0; /* reset gnu getopt */
      opterr=0; /* no error messages */

      fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);
      rrd_clear_error();
      addRrdDelay();
      rc = rrd_create(argc, argv);

      if(rrd_test_error()) {
	char *err = rrd_get_error();
#if defined(RRD_DEBUG)
	traceEventRRDebugARGV(3);
#endif

	traceEvent(CONST_TRACE_WARNING, "RRD: rrd_create(%s) error: %s",
		   path, err ? err : "");
	rrd_clear_error();
	numRRDerrors++;
      }

      releaseMutex(&rrdMutex);

      /* traceEventRRDebug("rrd_create(%s, %s)=%d", hostPath, key, rc); */
      createdCounter = 1;
    }

#if RRD_DEBUG
    {
      if(checkLast(path) >= myGlobals.rrdTime)
	traceEventRRDebug(0, "WARNING rrd_update not performed (RRD already updated)");
    }
#endif

    if(!createdCounter) {
      time_t now = time(NULL);

      /*
	traceEvent(CONST_TRACE_WARNING, "RRD: about to reset(%s) [last=%u][initial=%u][now-initial=%d][dumpInterval=%d]",
		 path, checkLast(path), myGlobals.initialSniffTime,
		 (now-myGlobals.initialSniffTime), dumpInterval);
      */

      /* Avoid peaks */
      if(((now-myGlobals.initialSniffTime) < 600 /* Don't check after the first 10 min */)
	 && (checkLast(path) < myGlobals.initialSniffTime)) {
	argc = 0;
	argv[argc++] = "rrd_update";

	if(rrdd_sock_path && (rrdd_sock_path[0] != '\0')) {
	  /* --daemon unix:/tmp/rrdd.sock  */
	  argv[argc++] = "--daemon";
	  argv[argc++] = rrdd_sock_path;
	}

	argv[argc++] = path;

	safe_snprintf(__FILE__, __LINE__, cmd, sizeof(cmd), "%u:NaN",
		      (unsigned int)myGlobals.initialSniffTime);
	argv[argc++] = cmd;

	accessMutex(&rrdMutex, "rrd_update");
	optind=0; /* reset gnu getopt */
	opterr=0; /* no error messages */

	fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);
	rrd_clear_error();
	/* Do not add any delay when using the rrdcached */
	if((rrdd_sock_path == NULL) || (rrdd_sock_path[0] == '\0')) addRrdDelay();
	rrd_update(argc, argv);
	numRRDUpdates++;
	numTotalRRDUpdates++;
	releaseMutex(&rrdMutex);

	// traceEvent(CONST_TRACE_WARNING, "RRD: reset(%s)", path);
      }
    }

    argc = 0;
    argv[argc++] = "rrd_update";
    
    if(rrdd_sock_path && (rrdd_sock_path[0] != '\0')) {
      /* --daemon unix:/tmp/rrdd.sock  */
      argv[argc++] = "--daemon";
      argv[argc++] = rrdd_sock_path;
    }
    
    argv[argc++] = path;

    safe_snprintf(__FILE__, __LINE__, cmd, sizeof(cmd), "%u:%llu",
		  (unsigned int)myGlobals.rrdTime, (unsigned long long)value);
    argv[argc++] = cmd;

    accessMutex(&rrdMutex, "rrd_update");
    optind=0; /* reset gnu getopt */
    opterr=0; /* no error messages */

    fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);
    rrd_clear_error();
    addRrdDelay();
    rc = rrd_update(argc, argv);

    numRRDUpdates++;
    numTotalRRDUpdates++;

    if(rrd_test_error()) {
      int x;
      char *rrdError;

#if defined(RRD_DEBUG)
      traceEventRRDebugARGV(3);
#endif

      numRRDerrors++;
      rrdError = rrd_get_error();
      if(rrdError != NULL) {
	traceEvent(CONST_TRACE_WARNING, "RRD: rrd_update(%s) error: %s", path, rrdError);
	traceEvent(CONST_TRACE_NOISY, "RRD: call stack (counter created: %d):", createdCounter);
	for (x = 0; x < argc; x++)
	  traceEvent(CONST_TRACE_NOISY, "RRD: argv[%d]: %s", x, argv[x]);

	if(!strcmp(rrdError, "error: illegal attempt to update using time")) {
	  char errTimeBuf1[32], errTimeBuf2[32], errTimeBuf3[32];
	  struct tm workT;
	  time_t rrdLast = checkLast(path);
	  strftime(errTimeBuf1, sizeof(errTimeBuf1), CONST_LOCALE_TIMESPEC, localtime_r(&myGlobals.actTime, &workT));
	  strftime(errTimeBuf2, sizeof(errTimeBuf2), CONST_LOCALE_TIMESPEC, localtime_r(&myGlobals.rrdTime, &workT));
	  strftime(errTimeBuf3, sizeof(errTimeBuf3), CONST_LOCALE_TIMESPEC, localtime_r(&rrdLast, &workT));
	  traceEvent(CONST_TRACE_WARNING,
		     "RRD: actTime = %d(%s), myGlobals.rrdTime %d(%s), lastUpd %d(%s)",
		     (int)myGlobals.actTime,
		     errTimeBuf1,
		     (int)myGlobals.rrdTime,
		     errTimeBuf2,
		     (int)rrdLast,
		     rrdLast == -1 ? "rrdlast ERROR" : errTimeBuf3);
	} else if(strstr(rrdError, "is not an RRD file") || strstr(rrdError, "read operation failed")) {
	  unlink(path);
	} else {
	  char do_delete = 0;

	  /* Delete empty RRD files */
	  if(stat(path, &statbuf) == 0) {
	    if(statbuf.st_size == 0) do_delete = 1;
	  } else
	    do_delete = 1;

	  if(do_delete) unlink(path);
	}

	rrd_clear_error();
      } else {
#if defined(RRD_DEBUG)
	traceEventRRDebug(0, "rrd_update(%s, %s, %s)=%d", hostPath, key, cmd, rc);
#endif
      }
    } else if(0) {

      unsigned long step, ds_cnt;
      rrd_value_t   *data,*datai, _total, _val;
      char          **ds_namv, time_buf[32];
      time_t        start,end;

      safe_snprintf(__FILE__, __LINE__, time_buf, sizeof(time_buf), "%u", myGlobals.rrdTime);

      argc = 0;
      argv[argc++] = "rrd_fetch";
      argv[argc++] = path;
      argv[argc++] = "FAILURES";
      argv[argc++] = "--start";
      argv[argc++] = time_buf;
      argv[argc++] = "--end";
      argv[argc++] = time_buf;

      accessMutex(&rrdMutex, "rrd_fetch");
      optind=0; /* reset gnu getopt */
      opterr=0; /* no error messages */

      fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);

      rrd_clear_error();
      addRrdDelay();
      rc = rrd_fetch(argc, argv, &start, &end, &step, &ds_cnt, &ds_namv, &data);

      releaseMutex(&rrdMutex);

      if(rc != -1) {
	datai  = data, _total = 0;

	for(i = (int)start; i <= (int)end; i += (int)step) {
	  _val = *(datai++);

	  if(_val > 0)
	    _total += _val;
	}

	for(i=0;i<ds_cnt;i++) free(ds_namv[i]);
	free(ds_namv);
	free(data);

	traceEvent(CONST_TRACE_WARNING, "Host %s: detected failure on key %s",
		   hostPath, key);
      }
    }

    releaseMutex(&rrdMutex);

    gettimeofday(&rrdEndOfProcessing, NULL);
    lastRRDupdateDuration = elapsed = timeval_subtract(rrdEndOfProcessing, rrdStartOfProcessing);
    if(lastRRDupdateDuration > maxRRDupdateDuration)
      maxRRDupdateDuration = lastRRDupdateDuration;


#ifdef MAX_RRD_PROCESS_BUFFER
    rrdprocessBuffer[++rrdprocessBufferCount & (MAX_RRD_PROCESS_BUFFER - 1)] = elapsed;
    if(elapsed > rrdpmaxDelay)
      rrdpmaxDelay = elapsed;
#endif

    return(rc);
}

/* ******************************* */

static void updateTrafficCounter(char *hostPath, char *key, TrafficCounter *counter, char short_step) {
  if(counter->modified) {
    updateCounter(hostPath, key, counter->value, short_step);
    counter->modified = 0;
  }
}

/* ******************************* */

#ifndef WIN32
static void setGlobalPermissions(int permissionsFlag) {
  switch (permissionsFlag) {
  case CONST_RRD_PERMISSIONS_GROUP:
    myGlobals.rrdDirectoryPermissions = CONST_RRD_D_PERMISSIONS_GROUP;
    myGlobals.rrdUmask = CONST_RRD_UMASK_GROUP;
    break;
  case CONST_RRD_PERMISSIONS_EVERYONE:
    myGlobals.rrdDirectoryPermissions = CONST_RRD_D_PERMISSIONS_EVERYONE;
    myGlobals.rrdUmask = CONST_RRD_UMASK_EVERYONE;
    break;
  default:
    myGlobals.rrdDirectoryPermissions = CONST_RRD_D_PERMISSIONS_PRIVATE;
    myGlobals.rrdUmask = CONST_RRD_UMASK_PRIVATE;
    break;
  }
}
#endif

/* ******************************* */

static void commonRRDinit(void) {
  char value[4096];

#ifdef WIN32
  get_serial(&driveSerial);
#endif

  shownCreate = 0;

#ifdef MAX_RRD_CYCLE_BUFFER
  if(rrdcycleBufferInit == 0) {
    rrdcycleBufferCount = 0;
    rrdcycleBufferInit = 1;
    memset(&rrdcycleBuffer, 0, sizeof(rrdcycleBuffer));
  }
#endif
#ifdef MAX_RRD_PROCESS_BUFFER
  if(rrdprocessBufferInit == 0) {
    rrdprocessBufferCount = 0;
    rrdprocessBufferInit = 1;
    memset(&rrdprocessBuffer, 0, sizeof(rrdprocessBuffer));
  }
#endif

  if(fetchPrefsValue("rrd.dumpHeartbeatMultiplier", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d",
		  DEFAULT_RRD_HEARTBEAT_MULTIPLIER);
    storePrefsValue("rrd.dumpHeartbeatMultiplier", value);
    dumpHeartbeatMultiplier = DEFAULT_RRD_HEARTBEAT_MULTIPLIER;
  } else {
    dumpHeartbeatMultiplier = atoi(value);
  }

  if(fetchPrefsValue("rrd.dataDumpInterval", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", DEFAULT_RRD_INTERVAL);
    storePrefsValue("rrd.dataDumpInterval", value);
    dumpInterval = DEFAULT_RRD_INTERVAL;
  } else {
    dumpInterval = atoi(value);
  }

  if(fetchPrefsValue("rrd.dumpShortInterval", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", DEFAULT_RRD_SHORT_INTERVAL);
    storePrefsValue("rrd.dumpShortInterval", value);
    dumpShortInterval = DEFAULT_RRD_SHORT_INTERVAL;
  } else {
    dumpShortInterval = atoi(value);
  }

  if(fetchPrefsValue("rrd.dataDumpHours", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", DEFAULT_RRD_HOURS);
    storePrefsValue("rrd.dataDumpHours", value);
    dumpHours = DEFAULT_RRD_HOURS;
  } else {
    dumpHours = atoi(value);
  }

  if(fetchPrefsValue("rrd.dataDumpDays", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", DEFAULT_RRD_DAYS);
    storePrefsValue("rrd.dataDumpDays", value);
    dumpDays = DEFAULT_RRD_DAYS;
  } else {
    dumpDays = atoi(value);
  }

  if(fetchPrefsValue("rrd.dataDumpMonths", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", DEFAULT_RRD_MONTHS);
    storePrefsValue("rrd.dataDumpMonths", value);
    dumpMonths = DEFAULT_RRD_MONTHS;
  } else {
    dumpMonths = atoi(value);
  }

  if(fetchPrefsValue("rrd.rrdDumpDelay", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", DEFAULT_RRD_DUMP_DELAY);
    storePrefsValue("rrd.rrdDumpDelay", value);
    dumpDelay = DEFAULT_RRD_DUMP_DELAY;
  } else
    dumpDelay = atoi(value);

  if(fetchPrefsValue("rrd.rrdcSockPath", value, sizeof(value)) == -1) {
    rrdd_sock_path = NULL;
  } else
    rrdd_sock_path = strdup(value);

  if(fetchPrefsValue("rrd.dataDumpDomains", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dataDumpDomains", "0");
    dumpDomains = 0;
  } else {
    dumpDomains = atoi(value);
  }

  if(fetchPrefsValue("rrd.dataDumpFlows", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dataDumpFlows", "0");
    dumpFlows = 0;
  } else {
    dumpFlows = atoi(value);
  }

  if(fetchPrefsValue("rrd.dataDumpHosts", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dataDumpHosts", "0");
    dumpHosts = 0;
  } else {
    dumpHosts = atoi(value);
  }

  if(fetchPrefsValue("rrd.dataDumpInterfaces", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dataDumpInterfaces", "1");
    dumpInterfaces = 1;
  } else {
    dumpInterfaces = atoi(value);
  }

  if(fetchPrefsValue("rrd.dumpASs", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dumpASs", "0");
    dumpASs = 0;
  } else {
    dumpASs = atoi(value);
  }

  if(fetchPrefsValue("rrd.enableAberrant", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.enableAberrant", "1");
    enableAberrant = 1;
  } else {
    enableAberrant = atoi(value);
  }

  if(hostsFilter != NULL) free(hostsFilter);
  if(fetchPrefsValue("rrd.hostsFilter", value, sizeof(value)) == -1) {
    int i;

    value[0] = '\0';
    for(i=0; i<myGlobals.numLocalNetworks; i++) {
      char buf[64];
      u_int32_t network = myGlobals.localNetworks[i].address[CONST_NETWORK_ENTRY];
      u_int32_t netmask = myGlobals.localNetworks[i].address[CONST_NETMASK_ENTRY];

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "%d.%d.%d.%d/%d.%d.%d.%d",
		    (int) ((network >> 24) & 0xff), (int) ((network >> 16) & 0xff),
		    (int) ((network >>  8) & 0xff), (int) ((network >>  0) & 0xff),
		    (int) ((netmask >> 24) & 0xff), (int) ((netmask >> 16) & 0xff),
		    (int) ((netmask >>  8) & 0xff), (int) ((netmask >>  0) & 0xff));

      if(value[0] != '\0') snprintf(&value[(int)strlen(value)], sizeof(value)-(int)strlen(value)-1, ",");
      snprintf(&value[(int)strlen(value)], sizeof(value)-(int)strlen(value)-1, "%s", buf);
    }

    hostsFilter = strdup(value);
    storePrefsValue("rrd.hostsFilter", hostsFilter);

    /*
      traceEvent(CONST_TRACE_INFO, "====> RRD: numLocalNetworks=%d [%s]",
      myGlobals.numLocalNetworks, value);
    */
  } else {
    hostsFilter  = strdup(value);
  }

  if(fetchPrefsValue("rrd.dataDumpDetail", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", CONST_RRD_DETAIL_DEFAULT);
    storePrefsValue("rrd.dataDumpDetail", value);
    dumpDetail = CONST_RRD_DETAIL_DEFAULT;
  } else {
    dumpDetail  = atoi(value);
  }

  if(fetchPrefsValue("rrd.rrdPath", value, sizeof(value)) == -1) {
    char *thePath = "/rrd";
    int len = (int)strlen(myGlobals.dbPath)+(int)strlen(thePath)+16, idx = 0;

    if(myGlobals.rrdPath) free(myGlobals.rrdPath);
    myGlobals.rrdPath = (char*)malloc(len);
#ifdef WIN32
    safe_snprintf(__FILE__, __LINE__, myGlobals.rrdPath, len,
		  "%s/%u%s", &myGlobals.dbPath[idx], driveSerial, thePath);
    revertSlashIfWIN32(myGlobals.rrdPath, 0);
#else
    safe_snprintf(__FILE__, __LINE__, myGlobals.rrdPath,
		  len, "%s%s", &myGlobals.dbPath[idx], thePath);
#endif

    len = (int)strlen(myGlobals.rrdPath);
    if(myGlobals.rrdPath[len-1] == '/') myGlobals.rrdPath[len-1] = '\0';
    storePrefsValue("rrd.rrdPath", myGlobals.rrdPath);
  } else {
    int vlen = (int)strlen(value)+1;

    myGlobals.rrdPath  = (char*)malloc(vlen);
    unescape(myGlobals.rrdPath, vlen, value);
  }

  if(fetchPrefsValue("rrd.rrdVolatilePath", value, sizeof(value)) == -1) {
    char *thePath = "/rrd";
    int len = (int)strlen(myGlobals.spoolPath)+(int)strlen(thePath)+16;

    if(myGlobals.rrdVolatilePath) free(myGlobals.rrdVolatilePath);
    myGlobals.rrdVolatilePath = (char*)malloc(len);

#ifdef WIN32
    safe_snprintf(__FILE__, __LINE__, myGlobals.rrdVolatilePath, len,
		  "%s/%u%s", myGlobals.spoolPath, driveSerial, thePath);
    revertSlashIfWIN32(myGlobals.rrdVolatilePath, 0);
#else
    safe_snprintf(__FILE__, __LINE__, myGlobals.rrdVolatilePath,
		  len, "%s%s", myGlobals.spoolPath, thePath);
#endif

    len = (int)strlen(myGlobals.rrdVolatilePath);
    if(myGlobals.rrdVolatilePath[len-1] == '/') myGlobals.rrdVolatilePath[len-1] = '\0';
    storePrefsValue("rrd.myGlobals.rrdVolatilePath", myGlobals.rrdVolatilePath);
  } else {
    int vlen = (int)strlen(value)+1;

    myGlobals.rrdVolatilePath  = (char*)malloc(vlen);
    unescape(myGlobals.rrdVolatilePath, vlen, value);
  }

#ifndef WIN32
  if(fetchPrefsValue("rrd.permissions", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", DEFAULT_RRD_PERMISSIONS);
    storePrefsValue("rrd.permissions", value);
    dumpPermissions = DEFAULT_RRD_PERMISSIONS;
  } else {
    dumpPermissions = atoi(value);
  }
  setGlobalPermissions(dumpPermissions);
  traceEvent(CONST_TRACE_INFO, "RRD: Mask for new directories is %04o",
             myGlobals.rrdDirectoryPermissions);
  umask(myGlobals.rrdUmask);
  traceEvent(CONST_TRACE_INFO, "RRD: Mask for new files is %04o",
             myGlobals.rrdUmask);
#endif

#ifdef RRD_DEBUG
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: Parameters:");
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpInterval %d seconds", dumpInterval);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpShortInterval %d seconds", dumpShortInterval);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpHours %d hours by %d seconds", dumpHours, dumpInterval);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpDays %d days by hour", dumpDays);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpMonths %d months by day", dumpMonths);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpDomains %s", dumpDomains == 0 ? "no" : "yes");
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpFlows %s", dumpFlows == 0 ? "no" : "yes");
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpHosts %s", dumpHosts == 0 ? "no" : "yes");
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpInterfaces %s", dumpInterfaces == 0 ? "no" : "yes");
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpASs %s", dumpASs == 0 ? "no" : "yes");
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpDetail %s",
	     dumpDetail == FLAG_RRD_DETAIL_HIGH ? "high" :
             (dumpDetail == FLAG_RRD_DETAIL_MEDIUM ? "medium" : "low"));
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     hostsFilter %s", hostsFilter);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     rrdPath %s [normal]", myGlobals.rrdPath);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     rrdPath %s [dynamic/volatile]", myGlobals.rrdVolatilePath);
#ifndef WIN32
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     umask %04o", myGlobals.rrdUmask);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     DirPerms %04o", myGlobals.rrdDirectoryPermissions);
#endif
#endif /* RRD_DEBUG */

  if (MAX_NUM_ENTRIES > CONST_NUM_BAR_COLORS)
    traceEvent(CONST_TRACE_WARNING,
	       "RRD: Too few colors defined in rrd_colors - graphs could be truncated");

  initialized = 1;
}

/* ****************************** */

#undef option_timespan
#define option_timespan(theStartTime, theLabel, selected)		\
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),			\
		"<option value=\"/" CONST_PLUGINS_HEADER "%s?graph_width=%s&graph_height=%s&action=" CONST_ARBITRARY_RRDREQUEST "&" CONST_ARBITRARY_IP "=%s" \
		"&" CONST_ARBITRARY_INTERFACE "=%s"			\
		"&" CONST_ARBITRARY_FILE "=%s"				\
		"&start=%u"						\
		"&end=%u"						\
		"&counter=%s"						\
		"&title=%s&mode=zoom\" %s>%s</option>\n",		\
		"rrdPlugin", rrd_width, rrd_height, rrdIP, rrdInterface, rrdName, (unsigned int)theStartTime, (unsigned int)the_time, buf1, buf2, \
		(selected == 1) ? "selected" : "", theLabel); sendString(buf);

/* ****************************** */

static void arbitraryAction(char *rrdName,
                            char *rrdInterface,
                            char *rrdIP,
                            char *_startTime,
                            char *_endTime,
                            char *rrdCounter,
                            char *rrdTitle,
                            char _which,
			    char *mode) {
  int i, len, rc=0, argc = 0, argc1 = 0, countOK=0, countZERO=0;
  char buf[LEN_GENERAL_WORK_BUFFER], rrdKey[256], *startTime, *endTime, time_buf[32];
  time_t the_time;
  struct tm *the_tm;
  char rrd_height[RRD_GRAPH_SIZE], rrd_width[RRD_GRAPH_SIZE];

  // if((!active) || (!initialized)) return;

  fetch_graph_size(rrd_height, rrd_width);
  startTime = _startTime, endTime = _endTime;

  if(atol(endTime) == 0) {
    snprintf(time_buf, sizeof(time_buf), "%u", (u_int)time(NULL));
    endTime = time_buf;
  }

  if(atol(startTime) > atol(endTime)) {
    startTime = endTime;
  }

  if(strstr(rrdName, "knownHostsNum") 
     || strstr(rrdName, "activeHostSenders")) {
    if(!dumpInterfaces) {
      sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
      printHTMLheader("ntop RRD Graph", NULL, 0);
      printFlagedWarning("<I>In order to graph this counter you need to enable Interfaces data dump on the <A HREF=\"/plugins/rrdPlugin\">RRD plugin</A>");
      return;
    }
  }

  if(!strcmp(mode, "zoom")) {
    char buf1[LEN_GENERAL_WORK_BUFFER], buf2[LEN_GENERAL_WORK_BUFFER];

    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop RRD Graph", NULL, 0);
    escape(buf1, sizeof(buf1), rrdCounter);
    escape(buf2, sizeof(buf2), rrdTitle);

    sendString("<center>\n");

    /* *************************************** */

    /*
      Graph time and zoom: code courtesy of
      the Cacti (http://www.cacti.net) project.
    */

    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/calendar.js\"></SCRIPT>\n");
    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/lang/calendar-en.js\"></SCRIPT>\n");
    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/calendar-setup.js\"></script>\n");
    sendString("<SCRIPT type=\"text/javascript\" src=\"/jscalendar/calendar-load.js\"></script>\n");

    sendString("\n<p align=center>\n<FORM action=/plugins/rrdPlugin name=\"form_timespan_selector\" method=\"get\">\n<TABLE width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\n<TBODY><TR><TD align=center class=\"textHeader\" nowrap=\"\">\n<b>Presets</b>: <SELECT name=\"predefined_timespan\" onchange=\"window.location=document.form_timespan_selector.predefined_timespan.options[document.form_timespan_selector.predefined_timespan.selectedIndex].value\">\n");

    the_time = time(NULL);
    
    option_timespan(the_time-12*3600, "-----", 1);
    option_timespan(the_time-1800, "Last Half Hour", 0);
    option_timespan(the_time-3600, "Last Hour", 0);
    option_timespan(the_time-2*3600, "Last 2 Hours", 0);
    option_timespan(the_time-4*3600, "Last 4 Hours", 0);
    option_timespan(the_time-6*3600, "Last 6 Hours", 0);
    option_timespan(the_time-12*3600, "Last 12 Hours", 0);
    option_timespan(the_time-86400, "Last Day", 0);
    option_timespan(the_time-2*86400, "Last 2 Days", 0);
    option_timespan(the_time-4*86400, "Last 4 Days", 0);
    option_timespan(the_time-7*86400, "Last Week", 0);
    option_timespan(the_time-30*86400, "Last Month", 0);
    option_timespan(the_time-2*30*86400, "Last 2 Months", 0);
    option_timespan(the_time-4*30*86400, "Last 4 Months", 0);
    option_timespan(the_time-6*30*86400, "Last 6 Months", 0);
    option_timespan(the_time-12*30*86400, "Last Year", 0);

    sendString("</select>\n");

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<input type=hidden name=action value=\"" CONST_ARBITRARY_RRDREQUEST "\">\n"
		  "<input type=hidden name="CONST_ARBITRARY_IP " value=\"%s\">\n"
		  "<input type=hidden name=" CONST_ARBITRARY_INTERFACE " value=\"%s\">\n"
		  "<input type=hidden name=" CONST_ARBITRARY_FILE " value=\"%s\">\n"
		  "<input type=hidden name=start value=\"%s\">\n"
		  "<input type=hidden name=end value=\"%s\">\n"
		  "<input type=hidden name=counter value=\"%s\">\n"
		  "<input type=hidden name=title value=\"%s\">\n"
		  "<input type=hidden name=mode value=\"zoom\">\n",
                  rrdIP, rrdInterface, rrdName, startTime, endTime, buf1, buf2);
    sendString(buf);


    sendString("&nbsp;<STRONG>From:</STRONG>\n<INPUT type=\"text\" name=\"date1\" id=\"date1\" size=\"16\" value=\"");

    the_time = atol(startTime); the_tm = localtime(&the_time);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", the_tm); sendString(buf);

    sendString("\">\n<INPUT type=\"image\" src=\"/calendar.gif\" alt=\"Start date selector\" border=\"0\" align=\"absmiddle\" onclick=\"return showCalendar('date1');\">\n");
    sendString("&nbsp;<strong>To:</strong>\n<INPUT type=\"text\" name=\"date2\" id=\"date2\" size=\"16\" value=\"");

    the_time = atol(endTime); the_tm = localtime(&the_time);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", the_tm); sendString(buf);

    sendString("\">\n<INPUT type=\"image\" src=\"/calendar.gif\" alt=\"End date selector\" border=\"0\" align=\"absmiddle\" onclick=\"return showCalendar('date2');\">\n"
	       "<INPUT type=\"submit\" value=\"Update Graph\">\n</FORM>\n</TD></TR></TBODY></TABLE>\n</p>\n");

    /* *************************************** */

    sendString("<SCRIPT type=\"text/javascript\" src=\"/zoom.js\"></SCRIPT>\n"
	       "<DIV id=\"zoomBox\" style=\"position: absolute; visibility: visible; background-image: initial; background-repeat: initial; "
	       "background-attachment: initial; background-position-x: initial; background-position-y: initial; background-color: orange; opacity: 0.5;\"></DIV>\n");

    sendString("<DIV id=\"zoomSensitiveZone\" style=\"position:absolute; overflow:none; background-repeat: initial; background-attachment: initial;  background-position-x: initial; background-position-y: initial; visibility:visible; cursor:crosshair; background:blue; filter:alpha(opacity=0); -moz-opacity:0; -khtml-opacity:0; opacity:0;\" oncontextmenu=\"return false\"></DIV>\n");

    /*
      NOTE:
      If the graph size changes, please update the zoom.js file (search for L.Deri)
    */
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                  "<img id=zoomGraphImage src=\"/" CONST_PLUGINS_HEADER "%s?graph_width=%s&graph_height=%s&action=" CONST_ARBITRARY_RRDREQUEST
		  "&" CONST_ARBITRARY_IP "=%s"
		  "&" CONST_ARBITRARY_INTERFACE "=%s"
		  "&" CONST_ARBITRARY_FILE "=%s"
		  "&start=%s"
		  "&end=%s"
		  "&counter=%s"
		  "&title=%s"
		  "\" alt=\"graph image\" border=0></center>\n",
                  rrdPluginInfo->pluginURLname, rrd_width, rrd_height,
                  rrdIP,
                  rrdInterface,
                  rrdName,
                  startTime,
                  endTime,
                  buf1,
                  buf2);
    sendString(buf);

    sendString("\n<SCRIPT type=\"text/javascript\">\n\nvar cURLBase = \"/plugins/rrdPlugin?mode=zoom\";\n\n// Global variables\nvar gZoomGraphName = \"zoomGraphImage\";\n"
	       "var gZoomGraphObj;\nvar gMouseObj;\nvar gUrlObj;\nvar gBrowserObj;\nvar gGraphWidth;\n"
	       "var gGraphHeight;\n\n\nwindow.onload = function () { initBonsai(); addReflections(); }\n\n</SCRIPT>\n");

    sendString("</center>\n");

    printHTMLtrailer();
    return;
  }

  memset(&buf, 0, sizeof(buf));
  memset(&rrdKey, 0, sizeof(rrdKey));

  if(strchr(rrdName, '.') || strchr(rrdName, '/')) {
    /* Security check... it's a file name */
    if(fileSanityCheck(rrdName, "arbitrary rrd request", 1) != 0) {
      traceEvent(CONST_TRACE_ERROR, "SECURITY: Invalid arbitrary rrd request(filename[%s])... ignored", rrdName);
      return;
    }
  }

  /*
    if(fileSanityCheck(rrdInterface, "arbitrary rrd request", 1) != 0) {
    traceEvent(CONST_TRACE_ERROR, "SECURITY: Invalid arbitrary rrd request(interface[%s])... ignored", rrdInterface);
    return;
    }
  */

  if(rrdIP[0] == '\0') {
    /* Interface level */
    safe_snprintf(__FILE__, __LINE__, rrdKey, sizeof(rrdKey), "interfaces/%s/", rrdInterface);
  } else {
    /* Security check... it's an ip - 0..9 a..f . and :   ONLY */
    if(ipSanityCheck(rrdIP, "arbitrary rrd request", 1) != 0) {
      traceEvent(CONST_TRACE_ERROR, "SECURITY: Invalid arbitrary rrd request(ip)... ignored (sanitized: %s)", rrdIP);
      return;
    }

    len=(int)strlen(rrdIP);
    for(i=0; i<len; i++) if(rrdIP[i] == '.') rrdIP[i] = CONST_PATH_SEP;
    safe_snprintf(__FILE__, __LINE__, rrdKey, sizeof(rrdKey), "interfaces/%s/hosts/%s/", rrdInterface, rrdIP);
  }

  if(!validHostCommunity(rrdIP)) {
    returnHTTPpageBadCommunity();
    return;
  }

  if(rrdCounter[0] == '\0')
    strcpy(rrdCounter, rrdName);

  if(_which == CONST_ARBITRARY_RRDREQUEST_SHOWME[0]) {
    char buf1[LEN_GENERAL_WORK_BUFFER],
      buf2[LEN_GENERAL_WORK_BUFFER];

    memset(&buf1, 0, sizeof(buf1));
    memset(&buf2, 0, sizeof(buf2));

    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("Arbitrary Graph URL", NULL, 0);
    escape(buf1, sizeof(buf1), rrdCounter);
    escape(buf2, sizeof(buf2), rrdTitle);
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                  "<p>/" CONST_PLUGINS_HEADER "%s?graph_width=%s&graph_height=%s&action=" CONST_ARBITRARY_RRDREQUEST
		  "&" CONST_ARBITRARY_IP "=%s"
		  "&" CONST_ARBITRARY_INTERFACE "=%s"
		  "&" CONST_ARBITRARY_FILE "=%s"
		  "&start=%s"
		  "&end=%s"
		  "&counter=%s"
		  "&title=%s</p>\n",
                  rrdPluginInfo->pluginURLname, rrd_width, rrd_height,
                  rrdIP,
                  rrdInterface,
                  rrdName,
                  startTime,
                  endTime,
                  buf1,
                  buf2);
    sendString(buf);
    printHTMLtrailer();
    return;
  }

  if((_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ||
     (_which == CONST_ARBITRARY_RRDREQUEST_FETCHMECSV[0])) {
    char *argv[32], *argv1[8], rptTime[32], startWorkTime[32], path[128], **ds_namv;
    time_t start=0,end=time(NULL)+1, startTimeFound = 0;
    unsigned long step=0, ds_cnt, ii;
    rrd_value_t   *data,*datai, _val;
    struct tm workT;

    memset(&path, 0, sizeof(path));
    memset(&rptTime, 0, sizeof(rptTime));
    memset(&startWorkTime, 0, sizeof(startWorkTime));

    if(!strcmp(rrdName, "throughput")) {
#ifdef WIN32
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%u/%s%s.rrd",
		    myGlobals.rrdVolatilePath, driveSerial, rrdKey, rrdName);
#else
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%s%s.rrd",
		    myGlobals.rrdVolatilePath, rrdKey, rrdName);
#endif
    } else
      safe_snprintf(__FILE__, __LINE__, path, sizeof(path), "%s/%s%s.rrd",
		    myGlobals.rrdPath, rrdKey, rrdName);

    if(_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) {
      sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
      printHTMLheader("ntop RRD data dump", NULL, 0);
      sendString("<h1>For:&nbsp;");
      sendString(path);
      sendString("</h1>");
    } else {
      sendHTTPHeader(FLAG_HTTP_TYPE_TEXT, 0, 1);
      sendString("\"file\",\"");
      sendString(path);
      sendString("\"\n\n");
    }

    argv[argc++] = "rrd_fetch";
    argv[argc++] = path;
    argv[argc++] = "AVERAGE";

    if((startTime != NULL) && (startTime[0] == '0') && (startTime[1] == '\0')) {
      argv1[argc1++] = "rrd_first";
      argv1[argc1++] = path;

      startTimeFound = rrd_first(argc1, argv1);
      if(startTimeFound != ((time_t)-1)) {
        safe_snprintf(__FILE__, __LINE__, startWorkTime, sizeof(startWorkTime), "%u", startTimeFound);
        argv[argc++] = "--start";
        argv[argc++] = startWorkTime;
      }
    } else if(startTime != NULL) {
      argv[argc++] = "--start";
      argv[argc++] = startTime;
    }

    if((endTime != NULL) && (endTime[0] != '\0')) {
      argv[argc++] = "--end";
      argv[argc++] = endTime;
    }

    optind=0; /* reset gnu getopt */
    opterr=0; /* no error messages */
    fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);
    rrd_clear_error();

    accessMutex(&rrdMutex, "arbitrary rrd_fetch");
    rc = rrd_fetch(argc, argv, &start, &end, &step, &ds_cnt, &ds_namv, &data);
    releaseMutex(&rrdMutex);

    if(rc == -1) {
#if defined(RRD_DEBUG)
      traceEventRRDebugARGV(3);
#endif

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "%sError retrieving rrd data, %s%s\n",
                    rrd_get_error() ? rrd_get_error() : "",
                    (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "<p>" : "",
                    (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "</p>" : "");
      sendString(buf);
      return;
    }

    if(_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) {
      sendString("<center>\n"
                 "<table border=\"1\""TABLE_DEFAULTS">\n"
                 "<tr><th align=\"center\" "DARK_BG" colspan=\"2\">Sample date/time</th>"
                 "<th align=\"center\" "DARK_BG" width=\"150\">Value</th></tr>\n");
    }

    datai = data;

    for(ii = start; ii <= end; ii += step) {
      _val = *(datai++);

      if(_val > 0) {
        countOK++;
        strftime(rptTime, sizeof(rptTime), CONST_LOCALE_TIMESPEC, localtime_r((time_t *)&ii, &workT));
        if(_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) {
          safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                        "<tr><td>%s</td><td align=\"right\">%u</td><td align=\"right\">%.6g</td></tr>\n",
                        rptTime, ii, _val);
        } else {
          safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                        "\"%s\",%u,%.6g\n",
                        rptTime, ii, _val);
        }
        sendString(buf);
      } else {
        countZERO++;
      }
    }

    for(i=0;i<ds_cnt;i++) if(ds_namv[i] != NULL) free(ds_namv[i]);
    if(ds_namv != NULL) free(ds_namv);
    if(data != NULL) free(data);

    if(_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) {
      sendString("</table>\n"
                 "</center>\n");
    }

    /* Closing comments... */
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                  "\n\n%sNotes%s\n"
                  "%s%d data points reported, %d skipped%s\n\n",
                  (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "<h2>" : "\"",
                  (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "</h2>\n<ul>" : "\"",
                  (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "<li>" : "\n\"",
                  countOK, countZERO,
                  (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "</li>" : "\"");
    sendString(buf);

    if(startTimeFound != ((time_t)-1)) {
      strftime(rptTime, sizeof(rptTime), CONST_LOCALE_TIMESPEC, localtime_r(&startTimeFound, &workT));
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "%sFound %s (%u) as the first (detail) data point%s\n",
                    (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "<li>" : "\"",
                    rptTime, startTimeFound,
                    (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "</li>" : "\"");
    } else if(start > 0) {
      strftime(rptTime, sizeof(rptTime), CONST_LOCALE_TIMESPEC, localtime_r(&start, &workT));
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "%sFetch found %s (%u) as the first %s data point%s\n",
                    (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "<li>" : "\"",
                    rptTime, start,
                    step <= dumpInterval ? "detail" : "summary",
                    (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "</li>" : "\"");
    }
    sendString(buf);

    strftime(rptTime, sizeof(rptTime), CONST_LOCALE_TIMESPEC, localtime_r(&end, &workT));
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                  "%sFetch found %s (%u) as the last data point%s\n",
                  (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "<li>" : "\"",
                  rptTime, end,
                  (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "</li>" : "\"");
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                  "%sStep is %u seconds%s\n",
                  (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "<li>" : "\"",
                  step,
                  (_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "</li>\n</ul>" : "\"");
    sendString(buf);

    sendString((_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "<p>" : "\"");
    sendString("This request is roughly equivalent to: ");
    sendString((_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "<b>" : "");
    sendString("rrdtool fetch");
    for(i=1; i<argc; i++) {
      sendString(" ");
      sendString(argv[i]);
    }
    sendString(" | grep -v nan");
    sendString((_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0]) ? "</b></p>" : "\"");

    if(_which == CONST_ARBITRARY_RRDREQUEST_FETCHME[0])
      printHTMLtrailer();

    return;
  }

  rc = graphCounter(rrdKey, rrdName, rrdTitle, rrdCounter, startTime, endTime, "arbitrary");
  return;
}

/* ****************************** */

static void statisticsPage(void) {
  char buf[1024];
#ifdef MAX_RRD_PROCESS_BUFFER
  float pminDelay=99999.0, pmaxDelay=0.0;
  int i;
  float  /*stddev:*/ pM, pT, pQ, pR, pSD;
#endif

  memset(&buf, 0, sizeof(buf));

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
  printHTMLheader("ntop RRD Statistics", NULL, 0);

  sendString("<center><table border=\"1\""TABLE_DEFAULTS">\n"
             "<tr><th align=\"center\" "DARK_BG" colspan=2>RRD Update</th></tr>\n");

  sendString("<tr><th align=\"left\" "DARK_BG">Cycles</th><td align=\"right\">");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%lu</td></tr>\n", (unsigned long)numRRDCycles);
  sendString(buf);

  sendString("<tr><th align=\"left\" "DARK_BG">Files Updated</th><td align=\"right\">");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%lu [%.1f updates/cycle]</td></tr>\n",
		(unsigned long)numTotalRRDUpdates,
		(numRRDCycles > 0) ? (float)numTotalRRDUpdates/(float)numRRDCycles : 0);
  sendString(buf);

  sendString("<tr><th align=\"left\" "DARK_BG">Errors</th><td align=\"right\">");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%lu</td></tr>\n", (unsigned long)numRRDerrors);
  sendString(buf);

  sendString("<tr><th align=\"left\" "DARK_BG">Cycle Duration</th><td align=\"right\">");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[last: %.2f sec][max: %.2f sec]</td></tr>\n",
		lastRRDupdateDuration, rrdcmaxDuration);
  sendString(buf);

  sendString("<tr><th align=\"left\" "DARK_BG">Single Update Duration</th><td align=\"right\">");
  if(lastRRDupdateNum == 0) lastRRDupdateNum = 1;
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[last: %.0f msec][max: %.0f msec]</td></tr>\n",
		lastRRDupdateDuration*1000, maxRRDupdateDuration*1000);
  sendString(buf);

  sendString("<tr><th align=\"center\" "DARK_BG" colspan=2>RRD Graph</th></tr>\n");
  sendString("<tr><th align=\"left\" "DARK_BG">Graphic Requests</th><td align=\"right\">");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%lu</td></tr>\n",
		(unsigned long)rrdGraphicRequests);
  sendString(buf);
  sendString("</table>\n</center>\n");

#ifdef MAX_RRD_PROCESS_BUFFER
  printSectionTitle("Per-RRD Processing times");
  sendString("<center><table border=\"0\""TABLE_DEFAULTS">\n<tr><td width=\"500\">"
             "<p>These numbers are the elapsed time (in seconds) per RRD update. "
             "The computations are based only on the most recent "
             xstr(MAX_RRD_PROCESS_BUFFER) " RRDs processed.</p>\n"
             "<p>'Processing' time is the elapsed time between starting and finishing "
             "updateRRD().  Errors may cause processing to be abandoned and those RRD "
             "updates are not counted in the 'processing' averages.</p>\n"
             "<p>If the RRD does not already exist, it will be created (along with any "
             "necessary directories), so the reported values may include a mix of "
             "short and long duration calls.</p>\n"
             "<p>Small averages are good, especially if the standard deviation is small "
             "(standard deviation is a measurement of the variability of the actual values "
             "around the average).</p>\n"
             "<p>&nbsp;</p>\n"
             "</td></tr></table></center>\n");

  if(rrdprocessBufferCount >= MAX_RRD_PROCESS_BUFFER) {

    sendString("<center><table border=\"1\""TABLE_DEFAULTS">\n"
               "<tr><th align=\"center\" "DARK_BG">Item</th>"
               "<th align=\"center\" width=\"75\" "DARK_BG">Time</th></tr>\n");

    for(i=0; i<MAX_RRD_PROCESS_BUFFER; i++) {
      if(rrdprocessBuffer[i] > pmaxDelay) pmaxDelay = rrdprocessBuffer[i];
      if(rrdprocessBuffer[i] < pminDelay) pminDelay = rrdprocessBuffer[i];

      if(i==0) {
        pM = rrdprocessBuffer[0];
        pT = 0.0;
      } else {
        pQ = rrdprocessBuffer[i] - pM;
        pR = pQ / (float)(i+1);
        pM += pR;
        pT = pT + i * pQ * pR;
      }
    }
    pSD = sqrtf(pT / (MAX_RRD_PROCESS_BUFFER - 1));
    pXBAR /*average*/ = pM;

    sendString("<tr><th align=\"left\" "DARK_BG">Minimum</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", pminDelay);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Average</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", pXBAR);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Maximum</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", pmaxDelay);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Standard Deviation</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", pSD);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Maximum ever</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", rrdpmaxDelay);
    sendString(buf);

    sendString("</table>\n</center>\n");

  } else {

    printNoDataYet();

  }

#endif /* MAX_RRD_PROCESS_BUFFER */

#ifdef MAX_RRD_CYCLE_BUFFER

  printSectionTitle("Per-Cycle Processing times");
  sendString("<center><table border=\"0\""TABLE_DEFAULTS">\n<tr><td width=\"500\">"
             "<p>These numbers are the elapsed time (in seconds) per RRD update cycle. "
             "The computations are based only on the most recent "
             xstr(MAX_RRD_CYCLE_BUFFER) " cycles executed.</p>\n"
             "<p>'Processing' time is the elapsed time between waking and returning to "
             "sleep in rrdMainLoop().  The currently executing cycle (if one) is not "
             "included.</p>"
             "<p>&nbsp;</p>\n"
             "</td></tr></table></center>\n");

  if(rrdcycleBufferCount >= MAX_RRD_CYCLE_BUFFER) {
    sendString("<center><table border=\"1\""TABLE_DEFAULTS">\n"
               "<tr><th align=\"center\" "DARK_BG">Item</th>"
               "<th align=\"center\" width=\"75\" "DARK_BG">Time</th></tr>\n");

    for(i=0; i<MAX_RRD_CYCLE_BUFFER; i++) {
      if(rrdcycleBuffer[i] > pmaxDelay) pmaxDelay = rrdcycleBuffer[i];
      if(rrdcycleBuffer[i] < pminDelay) pminDelay = rrdcycleBuffer[i];

      if(i==0) {
        pM = rrdcycleBuffer[0];
        pT = 0.0;
      } else {
        pQ = rrdcycleBuffer[i] - pM;
        pR = pQ / (float)(i+1);
        pM += pR;
        pT = pT + i * pQ * pR;
      }
    }
    pSD = sqrtf(pT / (MAX_RRD_CYCLE_BUFFER - 1));
    pXBAR /*average*/ = pM;

    sendString("<tr><th align=\"left\" "DARK_BG">Minimum</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", pminDelay);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Average</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", pXBAR);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Maximum</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", pmaxDelay);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Standard Deviation</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", pSD);
    sendString(buf);

    sendString("<tr><th align=\"left\" "DARK_BG">Maximum ever</th><td align=\"right\">");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.6f</td></tr>\n", rrdcmaxDuration);
    sendString(buf);

    sendString("</table>\n</center>\n");
  } else {
    printNoDataYet();
  }

#endif /* MAX_RRD_CYCLE_BUFFER */
}

/* ****************************** */

static void arbitraryActionPage(void) {
  int idx, count, rc;
  char buf[1024],
    dirPath[256],
    rrdPath[512],
    startTime[32],
    endTime[32];
  DIR* directoryPointer=NULL;
  struct dirent* dp;
  struct stat statBuf;
  time_t now = time(NULL);

  memset(&buf, 0, sizeof(buf));
  memset(&dirPath, 0, sizeof(dirPath));
  memset(&rrdPath, 0, sizeof(rrdPath));
  memset(&startTime, 0, sizeof(startTime));
  memset(&endTime, 0, sizeof(endTime));

  safe_snprintf(__FILE__, __LINE__, startTime, sizeof(startTime), "%u", now-12*3600);
  safe_snprintf(__FILE__, __LINE__, endTime, sizeof(endTime), "%u", now);

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
  printHTMLheader("Arbitrary RRD Actions", NULL, 0);

  safe_snprintf(__FILE__, __LINE__, dirPath, sizeof(dirPath), "%s/interfaces", myGlobals.rrdPath);
  revertSlashIfWIN32(dirPath, 0);
  directoryPointer = opendir(dirPath);

  if(directoryPointer == NULL) {
    sendString("<p>No rrds found - check configuration.</p>\n");
    return;
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                "<center>"
                "<p>This allows you to see and/or create a graph of an arbitrary rrd file.</p>\n"
                "<form action=\"/" CONST_PLUGINS_HEADER "%s\" method=GET>\n"
                "<input type=hidden name=action value=\"" CONST_ARBITRARY_RRDREQUEST "\">\n"
                "<table border=\"1\"  width=\"80%%\" "TABLE_DEFAULTS">\n"
                "<tr><th width=\"250\" align=\"left\" "DARK_BG">Action</th>\n"
                "<td align=\"left\">"
		"<input type=radio name=\"which\" value=\"" CONST_ARBITRARY_RRDREQUEST_GRAPHME "\" CHECKED>"
		"&nbsp;Create the graph - this is returned as a png file and will display ONLY the graph, "
		"without any html headings.<br>\n"
		"<input type=radio name=\"which\" value=\"" CONST_ARBITRARY_RRDREQUEST_SHOWME "\">"
		"&nbsp;Display the url to request the graph<br>\n"
		"<input type=radio name=\"which\" value=\"" CONST_ARBITRARY_RRDREQUEST_FETCHME "\">"
		"&nbsp;Retrieve rrd data in table form<br>\n"
		"<input type=radio name=\"which\" value=\"" CONST_ARBITRARY_RRDREQUEST_FETCHMECSV "\">"
		"&nbsp;Retrieve rrd data as CSV"
                "</td></tr>\n"
                "<tr><th align=\"left\" "DARK_BG">File</th>\n<td align=\"left\">"
                "<select name=\"" CONST_ARBITRARY_FILE "\">",
                rrdPluginInfo->pluginURLname);
  sendString(buf);

  for(idx=0; rrdNames[idx] != NULL; idx++) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<option value=\"%s\">%s</option>\n",
                  rrdNames[idx],
                  rrdNames[idx]);
    sendString(buf);
  }

  sendString("</select>"
             "<br>\n<p>Note: The drop down list shows all possible files - many (most) (all) "
             "of which may not be available for a specific host. Further, the list is "
             "based on the -p | --protocols parameter of this ntop run and may not "
             "include files created during ntop runs with other -p | --protocols "
             "parameter settings.</p>\n</td></tr>\n"
             "<tr><th align=\"left\" "DARK_BG">Interface</th>\n<td align=\"left\">");

  count = 0;
  while((dp = readdir(directoryPointer)) != NULL) {
    if(dp->d_name[0] != '.') {
      safe_snprintf(__FILE__, __LINE__, rrdPath, sizeof(rrdPath), "%s/interfaces/%s",
		    myGlobals.rrdPath, dp->d_name);
      rc = stat(rrdPath, &statBuf);
      if((rc == 0) && ((statBuf.st_mode & S_IFDIR) == S_IFDIR)) {
	count++;
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<input type=radio name=\"" CONST_ARBITRARY_INTERFACE "\" value=\"%s\" %s>%s<br>\n",
		      dp->d_name,
		      count == 1 ? "CHECKED" : "",
		      dp->d_name);
	sendString(buf);
      }
    }
  }

  if(count == 0) sendString("<b><font color=red>No RRD interface files available.</font></b>");

  closedir(directoryPointer);

  sendString("</td></tr>\n"
             "<tr><th width=\"250\" align=\"left\" "DARK_BG">Host IP address</th>\n<td align=\"left\">"
             "<input name=\"" CONST_ARBITRARY_IP "\" size=\"20\" value=\"\">"
             "&nbsp;&nbsp;Leave blank to create a per-interface graph.</td></tr>\n"
             "<tr><td align=\"left\"  colspan=\"2\">\n"
             "<p><i>A note about time specification</i>: You may specify time in a number of ways - please "
             "see \"AT-STYLE TIME SPECIFICATION\" in the rrdfetch man page for the full details. Here "
             "are some examples:</p>\n<ul>\n"
             "<li>Specific values: Most common formats are understood, including numerical and character "
             "date formats, such as Oct 12 - October 12th of "
             "the current year, 10/12/2005, etc.</li>\n"
             "<li>Relative time:  now-1d  (now minus one day) Several time units can be combined together, "
             "such as -5mon1w2d</li>\n"
             "<li>Seconds since epoch: 1110286800 (this specific value is equivalent to "
             "Tue 08 Mar 2005 07:00:00 AM CST</li>\n"
             "</ul>\n"
             "<p>Don't bother trying to break these - we just pass it through to rrdtool. If you want to "
             "play, there are a thousand lines in parsetime.c just waiting for you.</p>\n"
             "<p><i>A note about RRD files</i>: You may remember that the rrd file contains data stored "
             "at different resolutions - for ntop this is typically every 5 minutes, hourly, and daily. "
             "rrdfetch automatically picks the RRA (Round-Robin Archive) which provides the 'best' coverage "
             "of the time span you request.  Thus, if you request a start time which is before the number "
             "of 5 minute samples stored in RRA[0], you will 'magically' see the data from RRA[1], the "
             "hourly samples. Other than changing the start/end times, there is no way to force rrdfetch "
             "to select a specific RRA.</p>\n"
             "<p><i>Two notes for the fetch options</i>:</p>\n"
             "<p>Counter values are normalized to per-second rates. To get the (approximate) value of a "
             "counter for the entire interval, you need to multipy the per-second rate by the number of "
             "seconds in the interval (this is the step, reported at the bottom of the output page).</p>\n"
             "<p>If start time is left blank, the default is --start end-1d. To force a dump from the "
             "earliest detail point in the rrd, use the special value 0.</tr>\n"
             "<tr><th align=\"left\" "DARK_BG">Start</th>\n<td align=\"left\">"
             "<input name=\"start\" size=\"20\" value=\"");
  sendString(startTime);
  sendString("\"><br>\n"
             "<tr><th align=\"left\" "DARK_BG">End</th>\n<td align=\"left\">"
             "<input name=\"end\" size=\"20\" value=\"");
  sendString(endTime);
  sendString("\"></td></tr>\n"
             "<tr><th align=\"center\" "DARK_BG" colspan=\"2\">For graphs only</th></tr>\n"
             "<tr><th align=\"left\" "DARK_BG">Legend</th>\n<td align=\"left\">"
             "<input name=\"counter\" size=\"64\" value=\"\"><br>\n"
             "This is the 'name' of the counter being displayed, e.g. eth1 Mail bytes. "
             "It appears at the bottom left as the legend for the colored bars</td></tr>\n"
             "<tr><th align=\"left\" "DARK_BG">(optional) Title to appear above the graph</th>\n"
             "<td align=\"left\"><input name=\"title\" size=\"128\" value=\"\"></td></tr>\n"
             "<tr><td colspan=\"2\" align=\"center\">&nbsp;<br>");

  if(count > 0)
    sendString("<input type=submit value=\"Make Request\">");

  sendString("<br>&nbsp;</td></tr>\n</table>\n</form>\n</center>\n");
}

/* ****************************** */

static void printRRDPluginTrailer(void) {
  printPluginTrailer(NULL,
                     "<a href=\"http://www.rrdtool.org/\" title=\"rrd home page\">RRDtool</a> "
                     "was created by "
                     "<a href=\"http://ee-staff.ethz.ch/~oetiker/\" title=\"Tobi's home page\">"
                     "Tobi Oetiker</a>");

  printHTMLtrailer();
}

/* ****************************** */

static time_t parse_date(char* value) {
  /* 2006-07-11 10:06 */
  struct tm _tm;

  // traceEvent(CONST_TRACE_WARNING, "RRD: --> %s", value);

  memset(&_tm, 0, sizeof(_tm));
  if(sscanf(value, "%d-%d-%d %d:%d",
	    &_tm.tm_year, &_tm.tm_mon,
	    &_tm.tm_mday, &_tm.tm_hour, &_tm.tm_min) == 5) {
    --_tm.tm_mon, _tm.tm_year -= 1900, _tm.tm_hour--;
    return(mktime(&_tm));
  } else
    return(0);
}

/* ****************************** */

static void handleRRDHTTPrequest(char* url) {
  char buf[1024] = { '\0' }, *strtokState, *mainState, *urlPiece;
  char rrdKey[512] = { '\0' }, rrdName[64] = { '\0' }, rrdTitle[128] = { '\0' };
  char rrdCounter[64] = { '\0' }, startTime[32] = { '\0' }, endTime[32] = { '\0' };
  char rrdPrefix[32] = { '\0' }, rrdIP[32] = { '\0' }, rrdInterface[256] = { '\0' };
  char rrdPath[512] = { '\0' }, mode[32] = { '\0' }, community[32] = { '\0' }, filterString[64] = { '\0' };
  u_char action = FLAG_RRD_ACTION_NONE;
  char _which;
  int _dumpDomains, _dumpFlows, _dumpHosts, _dumpInterfaces, _dumpASs, _enableAberrant, _delay,
    _dumpDetail, _dumpInterval, _dumpShortInterval, _dumpHours, _dumpDays, _dumpMonths, graphId = 0,
    _heartbeat;
  int i, len, idx;
  time_t date1 = 0, date2 = 0;
  char * _hostsFilter;
#ifndef WIN32
  int _dumpPermissions;
#endif
  time_t now = time(NULL);
  char rrd_height[RRD_GRAPH_SIZE], rrd_width[RRD_GRAPH_SIZE];

  if(initialized == 0)
    commonRRDinit();

  /* Specialty pages */
  if(strncasecmp(url, CONST_RRD_STATISTICS_HTML, (int)strlen(CONST_RRD_STATISTICS_HTML)) == 0) {
    statisticsPage();
    printRRDPluginTrailer();
    return;
  } else if(strncasecmp(url, CONST_RRD_ARBGRAPH_HTML, (int)strlen(CONST_RRD_ARBGRAPH_HTML)) == 0) {
    arbitraryActionPage();
    printRRDPluginTrailer();
    return;
  }

  /* Initial values - remember, for checkboxes these need to be OFF (there's no html UNCHECKED option) */
  _dumpDomains=0;
  _dumpFlows=0;
  _dumpHosts=0;
  _dumpInterfaces=0;
  _dumpASs=0;
  _enableAberrant=0;
  _heartbeat = DEFAULT_RRD_HEARTBEAT_MULTIPLIER;
  _dumpDetail = CONST_RRD_DETAIL_DEFAULT;
  _dumpInterval = DEFAULT_RRD_INTERVAL;
  _dumpShortInterval = DEFAULT_RRD_SHORT_INTERVAL;
  _dumpHours = DEFAULT_RRD_HOURS;
  _dumpDays = DEFAULT_RRD_DAYS;
  _dumpMonths = DEFAULT_RRD_MONTHS;
  _hostsFilter = NULL;
#ifndef WIN32
  _dumpPermissions = DEFAULT_RRD_PERMISSIONS;
#endif
  _which=0;

  safe_snprintf(__FILE__, __LINE__, startTime, sizeof(startTime), "%u", now-12*3600);
  safe_snprintf(__FILE__, __LINE__, endTime, sizeof(endTime), "%u", now);

  if((url != NULL) && (url[0] != '\0')) {
    unescape_url(url);

    /* traceEvent(CONST_TRACE_INFO, "RRD: URL=%s", url);  */

    urlPiece = strtok_r(url, "&", &mainState);

    while(urlPiece != NULL) {
      char *key, *value;

      key = strtok_r(urlPiece, "=", &strtokState);
      if(key != NULL) value = strtok_r(NULL, "=", &strtokState); else value = NULL;
      if((!value) || (!strcmp(value, "(null)"))) value = "";

      /* traceEvent(CONST_TRACE_INFO, "RRD: key(%s)=%s", key, value);   */

      if(value && key) {
	if(strcmp(key, "action") == 0) {
	  if(strcmp(value, "graph") == 0)     action = FLAG_RRD_ACTION_GRAPH;
	  else if(strcmp(value, CONST_ARBITRARY_RRDREQUEST) == 0) action = FLAG_RRD_ACTION_ARBITRARY;
	  else if(strcmp(value, "graphSummary") == 0)             action = FLAG_RRD_ACTION_GRAPH_SUMMARY;
	  else if(strcmp(value, "netflowSummary") == 0)           action = FLAG_RRD_ACTION_NF_SUMMARY;
	  else if(strcmp(value, "interfaceSummary") == 0)         action = FLAG_RRD_ACTION_IF_SUMMARY;
	  else if(strcmp(value, "netflowIfSummary") == 0)         action = FLAG_RRD_ACTION_NF_IF_SUMMARY;
	  else if(strcmp(value, "list") == 0)                     action = FLAG_RRD_ACTION_LIST;
	} else if(strcmp(key, "community") == 0) {
	  safe_snprintf(__FILE__, __LINE__, community, sizeof(community), "%s", value);
	} else if(strcmp(key, "filter") == 0) {
	  safe_snprintf(__FILE__, __LINE__, filterString, sizeof(filterString), "%s", value);
	} else if(strcmp(key, "key") == 0) {
	  safe_snprintf(__FILE__, __LINE__, rrdKey, sizeof(rrdKey), "%s", value);
	  len = (int)strlen(rrdKey);
	  for(i=0; i<len; i++) if(rrdKey[i] == '+') rrdKey[i] = ' ';

	  if(strncmp(value, "hosts/", (int)strlen("hosts/")) == 0) {
	    int plen, ii;
	    safe_snprintf(__FILE__, __LINE__, rrdPrefix, sizeof(rrdPrefix), "ip_%s_", &value[6]);
	    plen=(int)strlen(rrdPrefix);
	    for (ii=0; ii<plen; ii++)
	      if( (rrdPrefix[ii] == '.') || (rrdPrefix[ii] == '/') )
		rrdPrefix[ii]='_';
	  } else {
	    rrdPrefix[0] = '\0';
	  }
	} else if(strcmp(key, CONST_ARBITRARY_IP) == 0) {
	  safe_snprintf(__FILE__, __LINE__, rrdIP, sizeof(rrdIP), "%s", value);
	} else if(strcmp(key, CONST_ARBITRARY_INTERFACE) == 0) {
	  safe_snprintf(__FILE__, __LINE__, rrdInterface, sizeof(rrdInterface), "%s", value);
	} else if(strcmp(key, CONST_ARBITRARY_FILE) == 0) {
	  safe_snprintf(__FILE__, __LINE__, rrdName, sizeof(rrdName), "%s", value);
	} else if(strcmp(key, "mode") == 0) {
	  safe_snprintf(__FILE__, __LINE__, mode, sizeof(mode), "%s", value);
	} else if(strcmp(key, "graphId") == 0) {
	  graphId = atoi(value);
	} else if(strcmp(key, "rrdcSockPath") == 0) {
	  if(rrdd_sock_path) free(rrdd_sock_path);
	  rrdd_sock_path = strdup(value);
	  storePrefsValue("rrd.rrdcSockPath", rrdd_sock_path);
	} else if(strcmp(key, "delay") == 0) {
	  _delay = atoi(value);
	  if(_delay < 0) _delay = 0;
	  dumpDelay = _delay;
	  safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", dumpDelay);
	  storePrefsValue("rrd.rrdDumpDelay", value);
	} else if(strcmp(key, "name") == 0) {
	  safe_snprintf(__FILE__, __LINE__, rrdName, sizeof(rrdName), "%s", value);
	  len = (int)strlen(rrdName);
	  for(i=0; i<len; i++) if(rrdName[i] == '+') rrdName[i] = ' ';
	} else if(strcmp(key, "counter") == 0) {
	  safe_snprintf(__FILE__, __LINE__, rrdCounter, sizeof(rrdCounter), "%s", value);
	  len = (int)strlen(rrdCounter);
	  for(i=0; i<len; i++) if(rrdCounter[i] == '+') rrdCounter[i] = ' ';
	} else if(strcmp(key, "title") == 0) {
	  unescape(rrdTitle, sizeof(rrdTitle), value);
	} else if(strcmp(key, "start") == 0) {
	  safe_snprintf(__FILE__, __LINE__, startTime, sizeof(startTime), "%s", value);
	} else if(strcmp(key, "end") == 0) {
	  safe_snprintf(__FILE__, __LINE__, endTime, sizeof(endTime), "%s", value);
	} else if(strcmp(key, "interval") == 0) {
	  _dumpInterval = atoi(value);
	  if(_dumpInterval < 1) _dumpInterval = 1 /* Min 1 second */;
	} else if(strcmp(key, "heartbeat") == 0) {
	  _heartbeat = atoi(value);
	  if(_heartbeat < 2) _heartbeat = 2 /* Min 2 second */;
	} else if(strcmp(key, "shortinterval") == 0) {
	  _dumpShortInterval = atoi(value);
	  if(_dumpShortInterval < 1) _dumpShortInterval = 1 /* Min 1 second */;
	} else if(strcmp(key, "days") == 0) {
	  _dumpDays = atoi(value);
	  if(_dumpDays < 0) _dumpDays = 0 /* Min none */;
	} else if(strcmp(key, "hours") == 0) {
	  _dumpHours = atoi(value);
	  if(_dumpHours < 0) _dumpHours = 0 /* Min none */;
	} else if(strcmp(key, "months") == 0) {
	  _dumpMonths = atoi(value);
	  if(_dumpMonths < 0) _dumpMonths = 0 /* Min none */;
	} else if(strcmp(key, "hostsFilter") == 0) {
	  _hostsFilter = strdup(value);
	} else if(strcmp(key, "rrdPath") == 0) {
	  int vlen = (int)strlen(value)+1;
	  idx = 0;
	  vlen -= idx;
	  if(myGlobals.rrdPath != NULL) free(myGlobals.rrdPath);
	  myGlobals.rrdPath  = (char*)malloc(vlen);
	  unescape(myGlobals.rrdPath, vlen, &value[idx]);
	  revertSlashIfWIN32(myGlobals.rrdPath, 0);
	  storePrefsValue("rrd.rrdPath", myGlobals.rrdPath);
	} else if(strcmp(key, "rrdVolatilePath") == 0) {
	  int vlen = (int)strlen(value)+1;
	  idx = 0;
	  vlen -= idx;
	  if(myGlobals.rrdVolatilePath != NULL) free(myGlobals.rrdVolatilePath);
	  myGlobals.rrdVolatilePath  = (char*)malloc(vlen);
	  unescape(myGlobals.rrdVolatilePath, vlen, &value[idx]);
	  revertSlashIfWIN32(myGlobals.rrdVolatilePath, 0);
	  storePrefsValue("rrd.rrdVolatilePath", myGlobals.rrdVolatilePath);
	} else if(strcmp(key, "dumpDomains") == 0) {
	  _dumpDomains = 1;
	} else if(strcmp(key, "dumpFlows") == 0) {
	  _dumpFlows = 1;
	} else if(strcmp(key, "dumpDetail") == 0) {
	  _dumpDetail = atoi(value);
	  if(_dumpDetail > FLAG_RRD_DETAIL_HIGH) _dumpDetail = FLAG_RRD_DETAIL_HIGH;
	  if(_dumpDetail < FLAG_RRD_DETAIL_LOW)  _dumpDetail = FLAG_RRD_DETAIL_LOW;
	} else if(strcmp(key, "dumpHosts") == 0) {
	  _dumpHosts = 1;
	} else if(strcmp(key, "dumpInterfaces") == 0) {
	  _dumpInterfaces = 1;
	} else if(strcmp(key, "dumpASs") == 0) {
	  _dumpASs = 1;
	} else if(strcmp(key, "enableAberrant") == 0) {
	  _enableAberrant = atoi(value);
#ifndef WIN32
	} else if(strcmp(key, "permissions") == 0) {
	  _dumpPermissions = atoi(value);
	  if((_dumpPermissions != CONST_RRD_PERMISSIONS_PRIVATE) &&
	     (_dumpPermissions != CONST_RRD_PERMISSIONS_GROUP) &&
	     (_dumpPermissions != CONST_RRD_PERMISSIONS_EVERYONE)) {
	    _dumpPermissions = DEFAULT_RRD_PERMISSIONS;
	  }
#endif
	} else if(strcmp(key, "which") == 0) {
	  _which = value[0];
	} else if(strcmp(key, "date1") == 0) {
	  date1 = parse_date(value);
	} else if(strcmp(key, "date2") == 0) {
	  date2 = parse_date(value);
	}
      }

      urlPiece = strtok_r(NULL, "&", &mainState);
    }

    if(date1 > 0) safe_snprintf(__FILE__, __LINE__, startTime, sizeof(startTime), "%d", date1);
    if(date2 > 0) safe_snprintf(__FILE__, __LINE__, endTime,   sizeof(endTime),   "%d", date2);

    if(action == FLAG_RRD_ACTION_NONE) {
      dumpInterval = _dumpInterval;


      if(dumpShortInterval != _dumpShortInterval) {
	int devIdx;

	dumpShortInterval = _dumpShortInterval;

	for(devIdx=0; devIdx<myGlobals.numDevices; devIdx++) {
	  if((myGlobals.device[devIdx].virtualDevice
	      && (!myGlobals.device[devIdx].sflowGlobals)
	      && (!myGlobals.device[devIdx].netflowGlobals)
	      )
	     || (!myGlobals.device[devIdx].activeDevice))
	    continue;

	  safe_snprintf(__FILE__, __LINE__, rrdPath, sizeof(rrdPath),
			"%s/interfaces/%s/", myGlobals.rrdVolatilePath,
			myGlobals.device[devIdx].uniqueIfName);
	  deleteRRD(rrdPath, "throughput");
	}
      }

      dumpHours = _dumpHours;
      dumpDays = _dumpDays;
      dumpMonths = _dumpMonths;
      dumpDomains = _dumpDomains;
      dumpFlows = _dumpFlows;
      dumpHosts = _dumpHosts;
      dumpInterfaces = _dumpInterfaces;
      dumpASs = _dumpASs;
      enableAberrant = _enableAberrant;
      dumpDetail = _dumpDetail;
#ifndef WIN32
      dumpPermissions = _dumpPermissions;
      setGlobalPermissions(_dumpPermissions);
#endif
      dumpHeartbeatMultiplier = _heartbeat;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpInterval);
      storePrefsValue("rrd.dataDumpInterval", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpShortInterval);
      storePrefsValue("rrd.dumpShortInterval", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpHours);
      storePrefsValue("rrd.dataDumpHours", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpDays);
      storePrefsValue("rrd.dataDumpDays", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpMonths);
      storePrefsValue("rrd.dataDumpMonths", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s", rrdd_sock_path ? rrdd_sock_path : "");
      storePrefsValue("rrd.rrdcSockPath", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpDomains);
      storePrefsValue("rrd.dataDumpDomains", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpFlows);
      storePrefsValue("rrd.dataDumpFlows", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpHosts);
      storePrefsValue("rrd.dataDumpHosts", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpInterfaces);
      storePrefsValue("rrd.dataDumpInterfaces", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpASs);
      storePrefsValue("rrd.dumpASs", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", enableAberrant);
      storePrefsValue("rrd.enableAberrant", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpDetail);
      storePrefsValue("rrd.dataDumpDetail", buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpHeartbeatMultiplier);
      storePrefsValue("rrd.dumpHeartbeatMultiplier", buf);

      if(_hostsFilter != NULL) {
	if(hostsFilter != NULL) free(hostsFilter);
	hostsFilter = _hostsFilter;
	_hostsFilter = NULL;
      }
      storePrefsValue("rrd.hostsFilter", hostsFilter);
#ifndef WIN32
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpPermissions);
      storePrefsValue("rrd.permissions", buf);
      umask(myGlobals.rrdUmask);
#ifdef RRD_DEBUG
      traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: Mask for new directories set to %04o",
		 myGlobals.rrdDirectoryPermissions);
      traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: Mask for new files set to %04o",
		 myGlobals.rrdUmask);
#endif
#endif
      shownCreate=0;
    }
  }

  /* traceEvent(CONST_TRACE_INFO, "RRD: graph_width=%s&graph_height=%s&action=%d", action); */

  if(action == FLAG_RRD_ACTION_GRAPH) {
    graphCounter(rrdKey, rrdName, NULL, rrdCounter, startTime, endTime, rrdPrefix);
    return;
  } else if(action == FLAG_RRD_ACTION_ARBITRARY) {
    arbitraryAction(rrdName, rrdInterface, rrdIP, startTime, endTime, rrdCounter, rrdTitle, _which, mode);
    return;
  } else if(action == FLAG_RRD_ACTION_GRAPH_SUMMARY) {
    graphSummary(rrdKey, rrdName, graphId, startTime, endTime, rrdPrefix, mode);
    return;
  } else if((action == FLAG_RRD_ACTION_NF_IF_SUMMARY) || (action == FLAG_RRD_ACTION_NF_SUMMARY)) {
    netflowSummary(rrdKey, graphId, startTime, endTime, rrdPrefix, mode);
    return;
  } else if(action == FLAG_RRD_ACTION_IF_SUMMARY) {
    interfaceSummary(rrdKey, graphId, startTime, endTime, rrdPrefix, mode);
    return;
  } else if(action == FLAG_RRD_ACTION_LIST) {
    listResource(rrdKey, rrdTitle, community[0] != '\0' ? community : NULL,
		 (filterString[0] == '\0') ? NULL : filterString, startTime, endTime);
    return;
  }

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
  printHTMLheader("ntop RRD Preferences", NULL, 0);

  if(active == 1)
    sendString("<p>You must restart the rrd plugin for changes here to take affect.</p>\n");
  else
    sendString("<p>Changes here will take effect when the plugin is started.</p>\n");

  sendString("<center>"
	     "<table border=\"1\"  width=\"80%%\" "TABLE_DEFAULTS">\n"
	     "<tr><th align=\"center\" "DARK_BG">Item</th>"
	     "<th align=\"center\" "DARK_BG">Description and Notes</th></tr>\n");

  fetch_graph_size(rrd_height, rrd_width);
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr><th align=\"left\" "DARK_BG">Graph Size</th><td>"
		"<form action=\"/" CONST_EDIT_PREFS "\" method=GET>\n"
		"<input name=key value=rrd.width type=hidden>"
		"<input name=val size=5 VALUE=%s><input type=submit value=Set></form>",
		rrd_width);
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<form action=\"/" CONST_EDIT_PREFS "\" method=GET>\n"
		"<input name=key value=rrd.height type=hidden>"
		"<input name=val size=5 VALUE=%s><input type=submit value=Set></form>"
		"Set the size of RRD graphs generated by ntop</td></tr>", rrd_height);
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<tr><th align=\"left\" "DARK_BG">Dump Interval</th><td>"
		"<form action=\"/" CONST_PLUGINS_HEADER "%s\" method=GET>\n"
		"<INPUT NAME=interval SIZE=5 VALUE=",
		rrdPluginInfo->pluginURLname);
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)dumpInterval);
  sendString(buf);
  sendString("> seconds<br>Specifies how often data is stored permanently.</td></tr>\n");

  sendString("<tr><th align=\"left\" "DARK_BG">Throughput Granularity</th><td>"
	     "<INPUT NAME=shortinterval SIZE=5 VALUE=");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)dumpShortInterval);
  sendString(buf);
  sendString("> seconds<br>Specifies how often <A HREF=/"CONST_SORT_DATA_THPT_STATS_HTML">throughput</A> data is stored permanently.<p>"
	     "<FONT COLOR=red><b>Note</b></FONT>: if you change this value the throughput stats will be <u>reset</u> "
	     "and past values will be <u>lost</u>. You've been warned!</td></tr>\n");

  sendString("<tr><th align=\"left\" "DARK_BG">Heartbeat</th><td>\n"
             "<SELECT NAME=heartbeat>\n");

  for(i=2; i<10; i++) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<OPTION VALUE=%d %s>%dx</option>\n",
		  i, (dumpHeartbeatMultiplier == i) ? "selected" : "", i);
  sendString(buf);
  }
  sendString("</select>\n<br>The heartbeat specifies the maximum amount of time between two RRD updates. In a nutshell every 'dump interval' seconds, ntop starts updating rrds. ntop must complete the update within 'dump interval' * heartbeat seconds. If not, even if an update arrives the value is considered unknown and you will see holes in your graph. Expecially on large networks with many rrds to save, this update process can take a lot of time. In this cases you must use large heartbeat values, in order to guarantee that the updates will happen within the specified boundaries. <p><font color=red><b>Note</b></font>: heartbeat is a <u>multiplier</u> of the 'dump interval' and <u>not</u> an absolute value.</td></tr>\n");

  sendString("<tr><th align=\"left\" "DARK_BG">Dump Hours</th><td>"
	     "<INPUT NAME=hours SIZE=5 VALUE=");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)dumpHours);
  sendString(buf);
  sendString("> hours<br>Specifies how many hours of 'interval' data is stored permanently.</td></tr>\n");

  sendString("<tr><th align=\"left\" "DARK_BG">Dump Days</th><td>"
	     "<INPUT NAME=days SIZE=5 VALUE=");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)dumpDays);
  sendString(buf);
  sendString("> days<br>Specifies how many days of hourly data is stored permanently.</td></tr>\n");

  sendString("<tr><th align=\"left\" "DARK_BG">Dump Months</th><td>"
	     "<INPUT NAME=months SIZE=5 VALUE=");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)dumpMonths);
  sendString(buf);
  sendString("> months<br>Specifies how many months (30 days) of daily data is stored permanently.</td></tr>\n");

  sendString("<tr><td align=\"center\" COLSPAN=2><B>WARNING:</B>&nbsp;"
	     "Changes to the above values will ONLY affect NEW rrds</td></tr>");

  sendString("<tr><th align=\"left\" "DARK_BG">RRDcached Path</th><td>"
	     "<INPUT NAME=rrdcSockPath SIZE=64 VALUE=");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s", rrdd_sock_path ? rrdd_sock_path : "");
  sendString(buf);

  sendString("><br>Example: unix:/tmp/rrdd.sock.<br>It specifies how to connect ntop to the rrdcached daemon. Format:"
	     "<ul> <li>unix:&lt;/path/to/unix.sock&gt;<li>/&lt;path/to/unix.sock&gt;"
	     "<li>&lt;hostname-or-ip&gt;<li>[&lt;hostname-or-ip&gt;]:&lt;port&gt;"
	     "<li>&lt;hostname-or-ipv4&gt;:&lt;port&gt;</ul>\n"
	     "The rrdcached needs to be already active prior to start ntop. Its usage "
	     "greatly enhances the update process and overloads ntop from RRD file update. "
	     "Please note that the use of rrdcached might introduce some little delay (see -w "
	     "parameter of rrdcached).</td></tr>\n");

  sendString("<tr><th align=\"left\" "DARK_BG">RRD Update Delay</th><td>"
	     "<INPUT NAME=delay SIZE=5 VALUE=");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", (int)dumpDelay);
  sendString(buf);

  sendString("> msec<br>Specifies how many ms to wait between two consecutive RRD updates. "
	     "Increase this value to distribute RRD load on I/O over the time.<br>"
	     "Note that a combination of large delays and many RRDs to update can "
	     "slow down the RRD plugin performance.<br>"
	     " This parameter is ignored when rrdcached is used.</td></tr>\n");

  sendString("<tr><th align=\"left\" "DARK_BG">Data to Dump</th><td>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpDomains VALUE=1 %s> Internet Domains<br>\n",
		dumpDomains ? "CHECKED" : "" );
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpFlows VALUE=1 %s> Flows<br>\n",
		dumpFlows ? "CHECKED" : "" );
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpHosts VALUE=1 %s> Hosts<br>\n",
		dumpHosts ? "CHECKED" : "");
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpInterfaces VALUE=1 %s> Interfaces<br>\n",
		dumpInterfaces ? "CHECKED" : "");
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpASs VALUE=1 %s> ASs<br>\n",
		dumpASs ? "CHECKED" : "");
  sendString(buf);

  sendString("</td></tr>\n");

  if(dumpHosts) {
    sendString("<tr><th align=\"left\" "DARK_BG">Hosts Filter</th><td>"
	       "<INPUT NAME=hostsFilter VALUE=\"");

    sendString(hostsFilter);

    sendString("\" SIZE=80><br>A list of networks [e.g. 172.22.0.0/255.255.0.0,192.168.5.0/255.255.255.0]<br>"
	       "separated by commas to which hosts that will be<br>"
	       "saved must belong to. An empty list means that all the hosts will "
	       "be stored on disk</td></tr>\n");
  }

  /* ******************************** */

  sendString("<tr><th align=\"left\" "DARK_BG">RRD Detail</th><td>");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=dumpDetail VALUE=%d %s>Low\n",
		FLAG_RRD_DETAIL_LOW, (dumpDetail == FLAG_RRD_DETAIL_LOW) ? "CHECKED" : "");
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=dumpDetail VALUE=%d %s>Medium\n",
		FLAG_RRD_DETAIL_MEDIUM, (dumpDetail == FLAG_RRD_DETAIL_MEDIUM) ? "CHECKED" : "");
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=dumpDetail VALUE=%d %s>Full\n",
		FLAG_RRD_DETAIL_HIGH, (dumpDetail == FLAG_RRD_DETAIL_HIGH) ? "CHECKED" : "");
  sendString(buf);
  sendString("</td></tr>\n");

  /* ******************************** */

  sendString("<tr><th align=\"left\" "DARK_BG">Detect Anomalies</th><td>");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=enableAberrant VALUE=1 %s>Yes\n",
		(enableAberrant == 1) ? "CHECKED" : "");
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=enableAberrant VALUE=0 %s>No\n",
		(enableAberrant == 0) ? "CHECKED" : "");
  sendString(buf);
  sendString("<br>Toggle RRD <A HREF=http://cricket.sourceforge.net/aberrant/rrd_hw.htm>Aberrant Behavior</A> support");
  sendString("</td></tr>\n");

  /* ******************************** */

  sendString("<tr><th align=\"left\" "DARK_BG">RRD Files Path</th><td>"
	     "<table border=0><tr><th align=left>Normal RRDs: </th><td align=left><INPUT NAME=rrdPath SIZE=50 VALUE=\"");
  sendString(myGlobals.rrdPath);
  sendString("\"></td></tr>");
  sendString("<tr><th align=left>Dynamic/Volatile RRDs: </th><td align=left><INPUT NAME=rrdVolatilePath SIZE=50 VALUE=\"");
  sendString(myGlobals.rrdVolatilePath);
  sendString("\"></td></tr></table>");

  sendString("<p>NOTE:<ul>"
	     "<li>Dynamic/volatile RRDs are those such as <A HREF=/"CONST_SORT_DATA_THPT_STATS_HTML">throughput</A> "
	     "RRDs that change very frequently and that some users "
	     " might want to save onto a separate directory (e.g. on a ramdisk). Normal RRDs are all the other RRDs.\n"
	     "<li>The rrd files will be in a subdirectory structure, e.g.\n");
#ifdef WIN32
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"%s\\interfaces\\interface-name\\12\\239\\98\\199\\xxxxx.rrd ",
		myGlobals.rrdPath);
#else
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"%s/interfaces/interface-name/12/239/98/199/xxxxx.rrd ",
		myGlobals.rrdPath);
#endif
  sendString(buf);
  sendString("to limit the number of files per subdirectory.");
  sendString("<li>Do not use the ':' character in the path as it is forbidded by rrd</ul></td></tr>\n");

#ifndef WIN32
  sendString("<tr><th align=\"left\" "DARK_BG">File/Directory Permissions</th><td>");
  sendString("<ul>\n");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<li><INPUT TYPE=radio NAME=permissions VALUE=%d %s>Private - ",
		CONST_RRD_PERMISSIONS_PRIVATE,
		(dumpPermissions == CONST_RRD_PERMISSIONS_PRIVATE) ? "CHECKED" : "");
  sendString(buf);
  sendString("means that ONLY the ntop userid will be able to view the files</li>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<li><INPUT TYPE=radio NAME=permissions VALUE=%d %s>Group - ",
		CONST_RRD_PERMISSIONS_GROUP,
		(dumpPermissions == CONST_RRD_PERMISSIONS_GROUP) ? "CHECKED" : "");
  sendString(buf);
  sendString("means that all users in the same group as the ntop userid will be able to view the rrd files.\n");
  sendString("<br><i>(this is a bad choice if ntop's group is 'nobody' along with many other service ids)</i></li>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<li><INPUT TYPE=radio NAME=permissions VALUE=%d %s>Everyone - ",
		CONST_RRD_PERMISSIONS_EVERYONE,
		(dumpPermissions == CONST_RRD_PERMISSIONS_EVERYONE) ? "CHECKED" : "");
  sendString(buf);
  sendString("means that everyone on the ntop host system will be able to view the rrd files.</li>\n");

  sendString("</ul><br>\n<B>WARNING</B>:&nbsp;Changing this setting affects only new files "
	     "and directories! "
	     "<i>Unless you go back and fixup existing file and directory permissions:</i><br>\n"
	     "<ul><li>Users will retain access to any rrd file or directory they currently have "
	     "access to even if you change to a more restrictive setting.</li>\n"
	     "<li>Users will not gain access to any rrd file or directory they currently do not "
	     "have access to even if you change to a less restrictive setting. Further, existing "
	     "directory permissions may prevent them from reading new files created in existing "
	     "directories.</li>\n"
	     "</ul>\n</td></tr>\n");
#endif

  sendString("<tr><td colspan=\"2\" align=\"center\">&nbsp;<br><input type=submit value=\"Save Preferences\"><br>&nbsp;</td></tr>\n"
	     "</table>\n</form>\n</center>\n");

  sendString("<hr>\n<p>Also:</p>\n<ul>");
  for(i=0; rrdExtraPages[i].url != NULL; i++) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<li><a href=\"/" CONST_PLUGINS_HEADER "%s/%s\">%s</a></li>\n",
		  rrdPluginInfo->pluginURLname, 
		  rrdExtraPages[i].url,		
		  rrdExtraPages[i].descr);
    sendString(buf);
  }
  sendString("</ul>\n");

  printRRDPluginTrailer();
}

/* ****************************** */
#ifdef MAKE_WITH_RRDSIGTRAP
RETSIGTYPE rrdcleanup(int signo) {
  static int msgSent = 0;
  int i;
  void *array[20];
  size_t size;
  char **strings;

  if(msgSent<10) {
    traceEvent(CONST_TRACE_FATALERROR, "RRD: caught signal %d %s", signo,
               signo == SIGHUP ? "SIGHUP" :
	       signo == SIGINT ? "SIGINT" :
	       signo == SIGQUIT ? "SIGQUIT" :
	       signo == SIGILL ? "SIGILL" :
	       signo == SIGABRT ? "SIGABRT" :
	       signo == SIGFPE ? "SIGFPE" :
	       signo == SIGKILL ? "SIGKILL" :
	       signo == SIGSEGV ? "SIGSEGV" :
	       signo == SIGPIPE ? "SIGPIPE" :
	       signo == SIGALRM ? "SIGALRM" :
	       signo == SIGTERM ? "SIGTERM" :
	       signo == SIGUSR1 ? "SIGUSR1" :
	       signo == SIGUSR2 ? "SIGUSR2" :
	       signo == SIGCHLD ? "SIGCHLD" :
#ifdef SIGCONT
	       signo == SIGCONT ? "SIGCONT" :
#endif
#ifdef SIGSTOP
	       signo == SIGSTOP ? "SIGSTOP" :
#endif
#ifdef SIGBUS
	       signo == SIGBUS ? "SIGBUS" :
#endif
#ifdef SIGSYS
	       signo == SIGSYS ? "SIGSYS"
#endif
               : "other");
    msgSent++;
  }

  traceEvent(CONST_TRACE_FATALERROR, "RRD: ntop shutting down...");
  exit(101);
}
#endif /* MAKE_WITH_RRDSIGTRAP */

/* ****************************** */

static void rrdUpdateIPHostStats(HostTraffic *el, int devIdx, u_int8_t is_subnet_host) {
  char value[512 /* leave it big for hosts filter */], subnet_buf[32], buf1[64];
  NetworkStats networks[32];
  u_short numLocalNets;
  int idx;
  char rrdPath[512];
  char *adjHostName;
  ProtocolsList *protoList;
  char *hostKey;
  int j;

  if(!is_subnet_host) {
    if((el == myGlobals.otherHostEntry) || (el == myGlobals.broadcastEntry)
       || broadcastHost(el)
       || (myGlobals.runningPref.trackOnlyLocalHosts && (!subnetPseudoLocalHost(el)))) {
      return;
    }
  }

  /* ********************************************* */

  numLocalNets = 0;

  if(!is_subnet_host) {
    /* Avoids strtok to blanks into hostsFilter */
    safe_snprintf(__FILE__, __LINE__, rrdPath, sizeof(rrdPath), "%s", hostsFilter);
    handleAddressLists(rrdPath, networks, &numLocalNets, value, sizeof(value), CONST_HANDLEADDRESSLISTS_RRD);
  }

  /* ********************************************* */

  if((el->bytesSent.value > 0) || (el->bytesRcvd.value > 0) || is_subnet_host) {
    if(!is_subnet_host) {
      if(el->hostNumIpAddress[0] != '\0') {
	hostKey = el->hostNumIpAddress;

	if((numLocalNets > 0)
	   && (el->hostIpAddress.hostFamily == AF_INET) /* IPv4 ONLY <-- FIX */
	   && (!__pseudoLocalAddress(&el->hostIpAddress.Ip4Address, networks, numLocalNets, NULL, NULL))) {
	  return;
	}

	if(subnetPseudoLocalHost(el) && (el->ethAddressString[0] != '\0'))
	  /*
	    NOTE:
	    MAC address is empty even for local hosts if this host has
	    been learnt on a virtual interface such as the NetFlow interface
	  */
	  hostKey = el->ethAddressString;
      } else {
	/* For the time being do not save IP-less hosts */

	return;
      }
    } else {
      hostKey = host2networkName(el, subnet_buf, sizeof(subnet_buf));
    }

    adjHostName = dotToSlash(hostKey, buf1, sizeof(buf1));

    safe_snprintf(__FILE__, __LINE__, rrdPath, sizeof(rrdPath), "%s/interfaces/%s/%s/%s/",
		  myGlobals.rrdPath, myGlobals.device[devIdx].uniqueIfName,
		  is_subnet_host ? "subnet" : "hosts",
		  adjHostName);
    mkdir_p("RRD", rrdPath, myGlobals.rrdDirectoryPermissions);

#if defined(RRD_DEBUG)
    traceEventRRDebug(2, "Updating %s [%s/%s]", hostKey, el->hostNumIpAddress, el->ethAddressString);
#endif

    updateTrafficCounter(rrdPath, "pktsSent", &el->pktsSent, 0);
    updateTrafficCounter(rrdPath, "pktsRcvd", &el->pktsRcvd, 0);
    updateTrafficCounter(rrdPath, "bytesSent", &el->bytesSent, 0);
    updateTrafficCounter(rrdPath, "bytesRcvd", &el->bytesRcvd, 0);

    if(dumpDetail >= FLAG_RRD_DETAIL_MEDIUM) {
      updateTrafficCounter(rrdPath, "pktsDuplicatedAckSent", &el->pktsDuplicatedAckSent, 0);
      updateTrafficCounter(rrdPath, "pktsDuplicatedAckRcvd", &el->pktsDuplicatedAckRcvd, 0);
      updateTrafficCounter(rrdPath, "pktsBroadcastSent", &el->pktsBroadcastSent, 0);
      updateTrafficCounter(rrdPath, "bytesBroadcastSent", &el->bytesBroadcastSent, 0);
      updateTrafficCounter(rrdPath, "pktsMulticastSent", &el->pktsMulticastSent, 0);
      updateTrafficCounter(rrdPath, "bytesMulticastSent", &el->bytesMulticastSent, 0);
      updateTrafficCounter(rrdPath, "pktsMulticastRcvd", &el->pktsMulticastRcvd, 0);
      updateTrafficCounter(rrdPath, "bytesMulticastRcvd", &el->bytesMulticastRcvd, 0);

      updateTrafficCounter(rrdPath, "bytesLocSent", &el->bytesSentLoc, 0);
      updateTrafficCounter(rrdPath, "bytesRemSent", &el->bytesSentRem, 0);
      updateTrafficCounter(rrdPath, "bytesLocRcvd", &el->bytesRcvdLoc, 0);
      updateTrafficCounter(rrdPath, "bytesFromRemRcvd", &el->bytesRcvdFromRem, 0);
      updateTrafficCounter(rrdPath, "ipv4BytesSent", &el->ipv4BytesSent, 0);
      updateTrafficCounter(rrdPath, "ipv4BytesRcvd", &el->ipv4BytesRcvd, 0);
      updateTrafficCounter(rrdPath, "tcpLocSent", &el->tcpSentLoc, 0);
      updateTrafficCounter(rrdPath, "tcpRemSent", &el->tcpSentRem, 0);
      updateTrafficCounter(rrdPath, "udpLocSent", &el->udpSentLoc, 0);
      updateTrafficCounter(rrdPath, "udpRemSent", &el->udpSentRem, 0);
      updateTrafficCounter(rrdPath, "icmpSent", &el->icmpSent, 0);
      updateTrafficCounter(rrdPath, "tcpLocRcvd", &el->tcpRcvdLoc, 0);
      updateTrafficCounter(rrdPath, "tcpFromRemRcvd", &el->tcpRcvdFromRem, 0);
      updateTrafficCounter(rrdPath, "udpLocRcvd", &el->udpRcvdLoc, 0);
      updateTrafficCounter(rrdPath, "udpFromRemRcvd", &el->udpRcvdFromRem, 0);
      updateTrafficCounter(rrdPath, "icmpRcvd", &el->icmpRcvd, 0);
      updateTrafficCounter(rrdPath, "tcpFragmentsSent", &el->tcpFragmentsSent, 0);
      updateTrafficCounter(rrdPath, "tcpFragmentsRcvd", &el->tcpFragmentsRcvd, 0);
      updateTrafficCounter(rrdPath, "udpFragmentsSent", &el->udpFragmentsSent, 0);
      updateTrafficCounter(rrdPath, "udpFragmentsRcvd", &el->udpFragmentsRcvd, 0);
      updateTrafficCounter(rrdPath, "icmpFragmentsSent", &el->icmpFragmentsSent, 0);
      updateTrafficCounter(rrdPath, "icmpFragmentsRcvd", &el->icmpFragmentsRcvd, 0);
      updateTrafficCounter(rrdPath, "ipv6BytesSent", &el->ipv6BytesSent, 0);
      updateTrafficCounter(rrdPath, "ipv6BytesRcvd", &el->ipv6BytesRcvd, 0);
      updateTrafficCounter(rrdPath, "greSent", &el->greSent, 0);
      updateTrafficCounter(rrdPath, "greRcvd", &el->greRcvd, 0);
      updateTrafficCounter(rrdPath, "ipsecSent", &el->ipsecSent, 0);
      updateTrafficCounter(rrdPath, "ipsecRcvd", &el->ipsecRcvd, 0);

      if(el->nonIPTraffic) {
	updateTrafficCounter(rrdPath, "stpSent", &el->nonIPTraffic->stpSent, 0);
	updateTrafficCounter(rrdPath, "stpRcvd", &el->nonIPTraffic->stpRcvd, 0);
	updateTrafficCounter(rrdPath, "arpRarpSent", &el->nonIPTraffic->arp_rarpSent, 0);
	updateTrafficCounter(rrdPath, "arpRarpRcvd", &el->nonIPTraffic->arp_rarpRcvd, 0);
	updateTrafficCounter(rrdPath, "arpReqPktsSent", &el->nonIPTraffic->arpReqPktsSent, 0);
	updateTrafficCounter(rrdPath, "arpReplyPktsSent", &el->nonIPTraffic->arpReplyPktsSent, 0);
	updateTrafficCounter(rrdPath, "arpReplyPktsRcvd", &el->nonIPTraffic->arpReplyPktsRcvd, 0);
	updateTrafficCounter(rrdPath, "netbiosSent", &el->nonIPTraffic->netbiosSent, 0);
	updateTrafficCounter(rrdPath, "netbiosRcvd", &el->nonIPTraffic->netbiosRcvd, 0);
	updateTrafficCounter(rrdPath, "otherSent", &el->nonIPTraffic->otherSent, 0);
	updateTrafficCounter(rrdPath, "otherRcvd", &el->nonIPTraffic->otherRcvd, 0);
      }

      if(el->ipProtosList != NULL) {
	protoList = myGlobals.ipProtosList, idx=0;
	while(protoList != NULL) {
	  char buf[64];

	  if(el->ipProtosList[idx] != NULL) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%sSent", protoList->protocolName);
	    updateTrafficCounter(rrdPath, buf, &el->ipProtosList[idx]->sent, 0);
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%sRcvd", protoList->protocolName);
	    updateTrafficCounter(rrdPath, buf, &el->ipProtosList[idx]->rcvd, 0);
	  }
	  idx++, protoList = protoList->next;
	}
      }
    }

    if(dumpDetail >= FLAG_RRD_DETAIL_MEDIUM) {
      updateCounter(rrdPath, "totPeersSent", el->totContactedSentPeers, 0);
      updateCounter(rrdPath, "totPeersRcvd", el->totContactedRcvdPeers, 0);

      safe_snprintf(__FILE__, __LINE__, rrdPath, sizeof(rrdPath), "%s/interfaces/%s/%s/%s/IP_",
		    myGlobals.rrdPath,
		    myGlobals.device[devIdx].uniqueIfName,
		    is_subnet_host ? "subnet" : "hosts",
		    adjHostName);

      for(j=0; j<IPOQUE_MAX_SUPPORTED_PROTOCOLS; j++) {
	char key[128];
	char *prot_long_str[] = { IPOQUE_PROTOCOL_LONG_STRING };

	if(el->l7.traffic[j].bytesSent) {
	  safe_snprintf(__FILE__, __LINE__, key, sizeof(key), "%sBytesSent", prot_long_str[j]);
	  updateCounter(rrdPath, key, el->l7.traffic[j].bytesSent, 0);
	}

	if(el->l7.traffic[j].bytesRcvd) {
	  safe_snprintf(__FILE__, __LINE__, key, sizeof(key), "%sBytesRcvd", prot_long_str[j]);
	  updateCounter(rrdPath, key, el->l7.traffic[j].bytesRcvd, 0);
	}
      }
    }
  }

  ntop_conditional_sched_yield(); /* Allow other threads to run */

  return;
}

/* ****************************** */

static void* rrdTrafficThreadLoop(void* notUsed _UNUSED_) {

  traceEvent(CONST_TRACE_INFO,
             "THREADMGMT[t%lu]: RRD: Throughput data collection: Thread starting [p%d]",
             (long unsigned int)pthread_self(), getpid());

  ntopSleepUntilStateRUN();

  traceEvent(CONST_TRACE_INFO,
             "THREADMGMT[t%lu]: RRD: Throughput data collection: Thread running [p%d]",
             (long unsigned int)pthread_self(), getpid());

  for(;myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN;) {
    int devIdx;
    char rrdPath[512];

    ntopSleepWhileSameState(dumpShortInterval);
    if(myGlobals.ntopRunState > FLAG_NTOPSTATE_RUN) {
      traceEvent(CONST_TRACE_INFO,
                 "THREADMGMT[t%lu]: RRD: Throughput data collection: Thread stopping [p%d] State>RUN",
                 (long unsigned int)pthread_self(), getpid());
      break;
    }

    myGlobals.rrdTime =  time(NULL);

    for(devIdx=0; devIdx<myGlobals.numDevices; devIdx++) {
      if((myGlobals.device[devIdx].virtualDevice
	  && (!myGlobals.device[devIdx].sflowGlobals)
	  && (!myGlobals.device[devIdx].netflowGlobals))
	 || (!myGlobals.device[devIdx].activeDevice))
	continue;

#ifdef WIN32
      safe_snprintf(__FILE__, __LINE__, rrdPath, sizeof(rrdPath), "%s/%u/interfaces/%s/",
		    myGlobals.rrdVolatilePath, driveSerial,
                    myGlobals.device[devIdx].uniqueIfName);
#else
      safe_snprintf(__FILE__, __LINE__, rrdPath, sizeof(rrdPath), "%s/interfaces/%s/",
		    myGlobals.rrdVolatilePath, myGlobals.device[devIdx].uniqueIfName);
#endif
      mkdir_p("RRD", rrdPath, myGlobals.rrdDirectoryPermissions);

      updateCounter(rrdPath, "throughput", myGlobals.device[devIdx].ethernetBytes.value*8, 1);
      /* traceEvent(CONST_TRACE_INFO, "RRD: [idx=%d][%lu]", devIdx, c); */
    }
  }

  rrdTrafficThread = 0;

  traceEvent(CONST_TRACE_INFO,
             "THREADMGMT[t%lu]: RRD: Throughput data collection: Thread terminated [p%d]",
             (long unsigned int)pthread_self(), getpid());
  return(NULL);
}

/* ****************************** */

static void* rrdMainLoop(void* notUsed _UNUSED_) {
  char value[512 /* leave it big for hosts filter */],
    rrdPath[4096],
    dname[256],
    endTime[32];
  int i, j, sleep_tm, devIdx, idx;
  NetworkStats networks[32];
  u_short numLocalNets;
  ProtocolsList *protoList;
  struct tm workT;
  struct timeval rrdStartOfCycle,
    rrdEndOfCycle;
  float elapsed;

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: RRD: Data collection thread starting [p%d]",
	     (long unsigned int)pthread_self(), getpid());

#ifdef MAKE_WITH_RRDSIGTRAP
  signal(SIGSEGV, rrdcleanup);
  signal(SIGHUP,  rrdcleanup);
  signal(SIGINT,  rrdcleanup);
  signal(SIGQUIT, rrdcleanup);
  signal(SIGILL,  rrdcleanup);
  signal(SIGABRT, rrdcleanup);
  signal(SIGFPE,  rrdcleanup);
  signal(SIGKILL, rrdcleanup);
  signal(SIGPIPE, rrdcleanup);
  signal(SIGALRM, rrdcleanup);
  signal(SIGTERM, rrdcleanup);
  signal(SIGUSR1, rrdcleanup);
  signal(SIGUSR2, rrdcleanup);
  /* signal(SIGCHLD, rrdcleanup); */
#ifdef SIGCONT
  signal(SIGCONT, rrdcleanup);
#endif
#ifdef SIGSTOP
  signal(SIGSTOP, rrdcleanup);
#endif
#ifdef SIGBUS
  signal(SIGBUS,  rrdcleanup);
#endif
#ifdef SIGSYS
  signal(SIGSYS,  rrdcleanup);
#endif
#endif /* MAKE_WITH_RRDSIGTRAP */

  /* Wait until the main thread changed privileges */
  sleep(10);

  active = 1; /* Show we are running */

  safe_snprintf(__FILE__, __LINE__, dname, sizeof(dname), "%s", myGlobals.rrdPath);
  if(ntop_mkdir(dname, myGlobals.rrdDirectoryPermissions) == -1) {
    if(errno != EEXIST) {
      traceEvent(CONST_TRACE_ERROR, "RRD: Disabled - unable to create base directory (err %d, %s)",
		 errno, dname);
      setPluginStatus("Disabled - unable to create rrd base directory.");
      /* Return w/o creating the rrd thread ... disabled */
      return(NULL);
    }
  } else {
    traceEvent(CONST_TRACE_INFO, "RRD: Created base directory (%s)", dname);
  }

  if ( sizeof(rrd_subdirs[0]) > 0 ) {
    for (i=0; i<sizeof(rrd_subdirs)/sizeof(rrd_subdirs[0]); i++) {
    safe_snprintf(__FILE__, __LINE__, dname, sizeof(dname), "%s/%s", myGlobals.rrdPath, rrd_subdirs[i]);
    revertSlashIfWIN32(dname, 0);

      if(ntop_mkdir(dname, myGlobals.rrdDirectoryPermissions) == -1) {
        if(errno != EEXIST) {
          traceEvent(CONST_TRACE_ERROR, "RRD: Disabled - unable to create directory (err %d, %s)", errno, dname);
          setPluginStatus("Disabled - unable to create rrd subdirectory.");
          /* Return w/o creating the rrd thread ... disabled */
          return(NULL);
        }
      } else {
        traceEvent(CONST_TRACE_INFO, "RRD: Created directory (%s)", dname);
      }
    }
  }

  if(initialized == 0)
    commonRRDinit();

  /* Initialize the "end" of the dummy interval just far enough back in time
     so that it expires once everything is up and running. */
  end_tm = myGlobals.actTime - dumpInterval + 15;

  createThread(&rrdTrafficThread, rrdTrafficThreadLoop, NULL);
  traceEvent(CONST_TRACE_INFO,
             "THREADMGMT[t%lu]: RRD: Started thread for throughput data collection",
             (long unsigned int)rrdTrafficThread);

  ntopSleepUntilStateRUN();

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: RRD: Data collection thread running [p%d]",
	     (long unsigned int)pthread_self(), getpid());

  for(;myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN;) {
    do {
      end_tm += dumpInterval;
    } while (end_tm < (start_tm = time(NULL)));

    sleep_tm = (int)(end_tm - start_tm);
    strftime(endTime, sizeof(endTime), CONST_LOCALE_TIMESPEC, localtime_r(&end_tm, &workT));

#if defined(RRD_DEBUG)
    traceEventRRDebug(0, "Sleeping for %d seconds (interval %d, end at %s)",
		      sleep_tm, dumpInterval, endTime);
#endif

    ntopSleepWhileSameState(sleep_tm);
    if(myGlobals.ntopRunState >= FLAG_NTOPSTATE_STOPCAP) {
      traceEvent(CONST_TRACE_INFO,
                 "THREADMGMT[t%lu]: RRD: Data collection thread stopping [p%d] %s",
                 (long unsigned int)pthread_self(),
                 getpid(),
                 myGlobals.ntopRunState > FLAG_NTOPSTATE_RUN ? "State>RUN" : "Plugin inactive");
      break;
    }
    /* Note, if this is stopcap, we run 1 more cycle and break out at the end so we don't lose data! */

    gettimeofday(&rrdStartOfCycle, NULL);

    numRRDUpdates = 0;
    numRuns++;
    myGlobals.rrdTime = time(NULL);

    /* ****************************************************** */

    numLocalNets = 0;
    /* Avoids strtok to blanks into hostsFilter */
    safe_snprintf(__FILE__, __LINE__, rrdPath, sizeof(rrdPath), "%s", hostsFilter);
    handleAddressLists(rrdPath, networks, &numLocalNets, value, sizeof(value),
		       CONST_HANDLEADDRESSLISTS_RRD);

    /* ****************************************************** */

    if(dumpDomains) {
      DomainStats **stats, *tmpStats, *statsEntry = NULL;
      u_int maxHosts = 0;
      Counter totBytesSent = 0;
      Counter totBytesRcvd = 0;
      HostTraffic *el;
      u_short keyValue=0;

      for(devIdx=0; devIdx<myGlobals.numDevices; devIdx++) {
        u_int numEntries = 0;


	if(!strcmp(myGlobals.device[devIdx].name, "pcap-file")) continue;
	if(!strcmp(myGlobals.device[devIdx].name, "none"))      continue;

	/* save this as it may change */
	maxHosts = myGlobals.device[devIdx].hosts.hostsno;
	tmpStats = (DomainStats*)mallocAndInitWithReportWarn((int)(maxHosts*sizeof(DomainStats)), "rrdMainLoop");

	if (tmpStats == NULL) {
          traceEvent(CONST_TRACE_WARNING, "RRD: Out of memory, skipping domain RRD dumps");
	  continue;
	}

	stats = (DomainStats**)mallocAndInitWithReportWarn((int)(maxHosts*sizeof(DomainStats*)),"rrdMainLoop(2)");

	if (stats == NULL) {
	  traceEvent(CONST_TRACE_WARNING, "RRD: Out of memory, skipping domain RRD dumps");
	  /* before continuing, also free the block of memory allocated a few lines up */
	  if (tmpStats != NULL) free(tmpStats);
	  continue;
	}

	/* walk through all hosts, getting their domain names and counting stats */
	for(el = getFirstHost(devIdx); el != NULL; el = getNextHost(devIdx, el)) {
	  fillDomainName(el);

	  /* if we didn't get a domain name, bail out */
	  if ((el->dnsDomainValue == NULL)
	      || (el->dnsDomainValue[0] == '\0')
	      || (el->hostResolvedName[0] == '\0')
	      || broadcastHost(el)
	      ) {
	    continue;
	  }

	  for(keyValue=0, idx=0; el->dnsDomainValue[idx] != '\0'; idx++)
	    keyValue += (idx+1)*(u_short)el->dnsDomainValue[idx];

	  keyValue %= maxHosts;

	  while((stats[keyValue] != NULL)
		&& (strcasecmp(stats[keyValue]->domainHost->dnsDomainValue,
			       el->dnsDomainValue) != 0))
	    keyValue = (keyValue+1) % maxHosts;

	  /* if we just start counting for this domain... */
	  if(stats[keyValue] != NULL)
	    statsEntry = stats[keyValue];
	  else {
	    statsEntry = &tmpStats[numEntries++];
	    memset(statsEntry, 0, sizeof(DomainStats));
	    statsEntry->domainHost = el;
	    stats[keyValue] = statsEntry;
#if defined(RRD_DEBUG)
	    traceEventRRDebug(2, "[%d] %s", numEntries, el->dnsDomainValue);
#endif
	  }

	  /* count this host's stats in the domain stats */
	  totBytesSent += el->bytesSent.value;
	  statsEntry->bytesSent.value += el->bytesSent.value;
	  statsEntry->bytesRcvd.value += el->bytesRcvd.value;
	  totBytesRcvd                += el->bytesRcvd.value;
	  statsEntry->tcpSent.value   += el->tcpSentLoc.value + el->tcpSentRem.value;
	  statsEntry->udpSent.value   += el->udpSentLoc.value + el->udpSentRem.value;
	  statsEntry->icmpSent.value  += el->icmpSent.value;
	  statsEntry->icmp6Sent.value += el->icmp6Sent.value;
	  statsEntry->tcpRcvd.value   += el->tcpRcvdLoc.value + el->tcpRcvdFromRem.value;
	  statsEntry->udpRcvd.value   += el->udpRcvdLoc.value + el->udpRcvdFromRem.value;
	  statsEntry->icmpRcvd.value  += el->icmpRcvd.value;
	  statsEntry->icmp6Rcvd.value  += el->icmp6Rcvd.value;

	  if(numEntries >= maxHosts) break;
	}

	/* if we didn't find a single domain, continue with the next interface */
	if (numEntries == 0) {
	  free(tmpStats); free(stats);
	  continue;
	}

	/* insert all domain data for this interface into the RRDs */
	for (idx=0; idx < numEntries; idx++) {
	  if(statsEntry->domainHost->dnsDomainValue != NULL) {
	    statsEntry = &tmpStats[idx];

	    safe_snprintf(__FILE__, __LINE__, rrdPath, sizeof(rrdPath), "%s/interfaces/%s/domains/%s/",
			  myGlobals.rrdPath, myGlobals.device[devIdx].uniqueIfName,
			  statsEntry->domainHost->dnsDomainValue);
	    mkdir_p("RRD", rrdPath, myGlobals.rrdDirectoryPermissions);

#if defined(RRD_DEBUG)
	    traceEventRRDebug(2, "Updating %s", rrdPath);
#endif
	    updateCounter(rrdPath, "bytesSent", statsEntry->bytesSent.value, 0);
	    updateCounter(rrdPath, "bytesRcvd", statsEntry->bytesRcvd.value, 0);

	    updateCounter(rrdPath, "tcpSent", statsEntry->tcpSent.value, 0);
	    updateCounter(rrdPath, "udpSent", statsEntry->udpSent.value, 0);
	    updateCounter(rrdPath, "icmpSent", statsEntry->icmpSent.value, 0);
	    updateCounter(rrdPath, "icmp6Sent", statsEntry->icmp6Sent.value, 0);

	    updateCounter(rrdPath, "tcpRcvd", statsEntry->tcpRcvd.value, 0);
	    updateCounter(rrdPath, "udpRcvd", statsEntry->udpRcvd.value, 0);
	    updateCounter(rrdPath, "icmpRcvd", statsEntry->icmpRcvd.value, 0);
	    updateCounter(rrdPath, "icmp6Rcvd", statsEntry->icmp6Rcvd.value, 0);
	  }
	} /* for */

	free(tmpStats); free(stats);
      }
    }

    /* ****************************************************** */

    if(dumpHosts) {
      for(devIdx=0; devIdx<myGlobals.numDevices; devIdx++) {
	HostTraffic *el;

	for(el = getFirstHost(devIdx); el != NULL; el = getNextHost(devIdx, el))
	  rrdUpdateIPHostStats(el, devIdx, 0);        
      }
    }

    /* ****************************************************** */

    if(dumpFlows) {
      FlowFilterList *list = myGlobals.flowsList;

      while(list != NULL) {
	if(list->pluginStatus.activePlugin) {
	  safe_snprintf(__FILE__, __LINE__, rrdPath, sizeof(rrdPath), "%s/flows/%s/",
			myGlobals.rrdPath, list->flowName);
	  mkdir_p("RRD", rrdPath, myGlobals.rrdDirectoryPermissions);

	  updateCounter(rrdPath, "packets", list->packets.value, 0);
	  updateCounter(rrdPath, "bytes",   list->bytes.value, 0);
	}

	list = list->next;
      }
    }

    /* ************************** */

    if(dumpInterfaces) {
      for(devIdx=0; devIdx<myGlobals.numDevices; devIdx++) {
	if((myGlobals.device[devIdx].virtualDevice
	    && (!myGlobals.device[devIdx].sflowGlobals)
	    && (!myGlobals.device[devIdx].netflowGlobals))
	   || (!myGlobals.device[devIdx].activeDevice))
	  continue;

	safe_snprintf(__FILE__, __LINE__, rrdPath, sizeof(rrdPath),
		      "%s/interfaces/%s/", myGlobals.rrdPath,
		      myGlobals.device[devIdx].uniqueIfName);
	mkdir_p("RRD", rrdPath, myGlobals.rrdDirectoryPermissions);

	updateCounter(rrdPath, "ethernetPkts",  myGlobals.device[devIdx].ethernetPkts.value, 0);
	updateCounter(rrdPath, "broadcastPkts", myGlobals.device[devIdx].broadcastPkts.value, 0);
	updateCounter(rrdPath, "multicastPkts", myGlobals.device[devIdx].multicastPkts.value, 0);
	updateCounter(rrdPath, "ethernetBytes", myGlobals.device[devIdx].ethernetBytes.value, 0);
	updateGauge(rrdPath,   "knownHostsNum", myGlobals.device[devIdx].hosts.hostsno, 0);
	updateGauge(rrdPath,   "activeHostSendersNum",  numActiveSenders(devIdx), 0);
	updateCounter(rrdPath, "ipv4Bytes",     myGlobals.device[devIdx].ipv4Bytes.value, 0);

	updateCounter(rrdPath, "ipLocalToLocalBytes",  myGlobals.device[devIdx].tcpGlobalTrafficStats.local.value +
		      myGlobals.device[devIdx].udpGlobalTrafficStats.local.value +
		      myGlobals.device[devIdx].icmpGlobalTrafficStats.local.value, 0);
	updateCounter(rrdPath, "ipLocalToRemoteBytes", myGlobals.device[devIdx].tcpGlobalTrafficStats.local2remote.value +
		      myGlobals.device[devIdx].udpGlobalTrafficStats.local2remote.value +
		      myGlobals.device[devIdx].icmpGlobalTrafficStats.local2remote.value, 0);
	updateCounter(rrdPath, "ipRemoteToLocalBytes", myGlobals.device[devIdx].tcpGlobalTrafficStats.remote2local.value +
		      myGlobals.device[devIdx].udpGlobalTrafficStats.remote2local.value +
		      myGlobals.device[devIdx].icmpGlobalTrafficStats.remote2local.value, 0);
	updateCounter(rrdPath, "ipRemoteToRemoteBytes", myGlobals.device[devIdx].tcpGlobalTrafficStats.remote.value +
		      myGlobals.device[devIdx].udpGlobalTrafficStats.remote.value +
		      myGlobals.device[devIdx].icmpGlobalTrafficStats.remote.value, 0);

	if(dumpDetail >= FLAG_RRD_DETAIL_MEDIUM) {
	  if(myGlobals.device[devIdx].netflowGlobals != NULL) {
	    updateCounter(rrdPath, "NF_numFlowPkts", myGlobals.device[devIdx].netflowGlobals->numNetFlowsPktsRcvd, 0);
	    updateCounter(rrdPath, "NF_numFlows", myGlobals.device[devIdx].netflowGlobals->numNetFlowsRcvd, 0);
	    updateCounter(rrdPath, "NF_numDiscardedFlows",
			  myGlobals.device[devIdx].netflowGlobals->numBadFlowPkts+
			  myGlobals.device[devIdx].netflowGlobals->numBadFlowBytes+
			  myGlobals.device[devIdx].netflowGlobals->numBadFlowReality+
			  myGlobals.device[devIdx].netflowGlobals->numNetFlowsV9UnknTemplRcvd, 0);

	    if(myGlobals.device[devIdx].netflowGlobals->numNetFlowsTCPRcvd > 0)
	      updateGauge(rrdPath, "NF_avgTcpNewFlowSize",
			  myGlobals.device[devIdx].netflowGlobals->totalNetFlowsTCPSize/
			  myGlobals.device[devIdx].netflowGlobals->numNetFlowsTCPRcvd, 0);

	    if(myGlobals.device[devIdx].netflowGlobals->numNetFlowsUDPRcvd > 0)
	      updateGauge(rrdPath, "NF_avgUdpNewFlowSize",
			  myGlobals.device[devIdx].netflowGlobals->totalNetFlowsUDPSize/
			  myGlobals.device[devIdx].netflowGlobals->numNetFlowsUDPRcvd, 0);

	    if(myGlobals.device[devIdx].netflowGlobals->numNetFlowsICMPRcvd > 0)
	      updateGauge(rrdPath, "NF_avgICMPNewFlowSize",
			  myGlobals.device[devIdx].netflowGlobals->totalNetFlowsICMPSize/
			  myGlobals.device[devIdx].netflowGlobals->numNetFlowsICMPRcvd, 0);

	    if(myGlobals.device[devIdx].netflowGlobals->numNetFlowsOtherRcvd > 0)
	      updateGauge(rrdPath, "NF_avgOtherFlowSize",
			  myGlobals.device[devIdx].netflowGlobals->totalNetFlowsOtherSize/
			  myGlobals.device[devIdx].netflowGlobals->numNetFlowsOtherRcvd, 0);

	    updateGauge(rrdPath, "NF_newTcpNetFlows",
			myGlobals.device[devIdx].netflowGlobals->numNetFlowsTCPRcvd, 0);
	    updateGauge(rrdPath, "NF_newUdpNetFlows",
			myGlobals.device[devIdx].netflowGlobals->numNetFlowsUDPRcvd, 0);
	    updateGauge(rrdPath, "NF_newIcmpNetFlows",
			myGlobals.device[devIdx].netflowGlobals->numNetFlowsICMPRcvd, 0);
	    updateGauge(rrdPath, "NF_newOtherNetFlows",
			myGlobals.device[devIdx].netflowGlobals->numNetFlowsOtherRcvd, 0);

	    updateGauge(rrdPath, "NF_numNetFlows",
			myGlobals.device[devIdx].netflowGlobals->numNetFlowsRcvd-
			myGlobals.device[devIdx].netflowGlobals->lastNumNetFlowsRcvd, 0);

	    /* Update Counters */
	    myGlobals.device[devIdx].netflowGlobals->lastNumNetFlowsRcvd =
	      myGlobals.device[devIdx].netflowGlobals->numNetFlowsRcvd;
	    myGlobals.device[devIdx].netflowGlobals->totalNetFlowsTCPSize = 0;
	    myGlobals.device[devIdx].netflowGlobals->totalNetFlowsUDPSize = 0;
	    myGlobals.device[devIdx].netflowGlobals->totalNetFlowsICMPSize = 0;
	    myGlobals.device[devIdx].netflowGlobals->totalNetFlowsOtherSize = 0;
	    myGlobals.device[devIdx].netflowGlobals->numNetFlowsTCPRcvd = 0;
	    myGlobals.device[devIdx].netflowGlobals->numNetFlowsUDPRcvd = 0;
	    myGlobals.device[devIdx].netflowGlobals->numNetFlowsICMPRcvd = 0;
	    myGlobals.device[devIdx].netflowGlobals->numNetFlowsOtherRcvd = 0;
	  }
	}

	if(dumpDetail >= FLAG_RRD_DETAIL_MEDIUM) {
	  updateCounter(rrdPath, "droppedPkts", myGlobals.device[devIdx].droppedPkts.value, 0);
	  updateCounter(rrdPath, "fragmentedIpBytes", myGlobals.device[devIdx].fragmentedIpBytes.value, 0);
	  updateCounter(rrdPath, "tcpBytes", myGlobals.device[devIdx].tcpBytes.value, 0);
	  updateCounter(rrdPath, "udpBytes", myGlobals.device[devIdx].udpBytes.value, 0);
	  updateCounter(rrdPath, "otherIpBytes", myGlobals.device[devIdx].otherIpBytes.value, 0);
	  updateCounter(rrdPath, "icmpBytes", myGlobals.device[devIdx].icmpBytes.value, 0);
	  updateCounter(rrdPath, "stpBytes", myGlobals.device[devIdx].stpBytes.value, 0);
	  updateCounter(rrdPath, "ipsecBytes", myGlobals.device[devIdx].ipsecBytes.value, 0);
	  updateCounter(rrdPath, "netbiosBytes", myGlobals.device[devIdx].netbiosBytes.value, 0);
	  updateCounter(rrdPath, "arpRarpBytes", myGlobals.device[devIdx].arpRarpBytes.value, 0);
	  updateCounter(rrdPath, "greBytes", myGlobals.device[devIdx].greBytes.value, 0);
	  updateCounter(rrdPath, "ipv6Bytes", myGlobals.device[devIdx].ipv6Bytes.value, 0);
	  updateCounter(rrdPath, "otherBytes", myGlobals.device[devIdx].otherBytes.value, 0);
	  updateCounter(rrdPath, "upTo64Pkts", myGlobals.device[devIdx].rcvdPktStats.upTo64.value, 0);
	  updateCounter(rrdPath, "upTo128Pkts", myGlobals.device[devIdx].rcvdPktStats.upTo128.value, 0);
	  updateCounter(rrdPath, "upTo256Pkts", myGlobals.device[devIdx].rcvdPktStats.upTo256.value, 0);
	  updateCounter(rrdPath, "upTo512Pkts", myGlobals.device[devIdx].rcvdPktStats.upTo512.value, 0);
	  updateCounter(rrdPath, "upTo1024Pkts", myGlobals.device[devIdx].rcvdPktStats.upTo1024.value, 0);
	  updateCounter(rrdPath, "upTo1518Pkts", myGlobals.device[devIdx].rcvdPktStats.upTo1518.value, 0);
	  updateCounter(rrdPath, "tooLongPkts", myGlobals.device[devIdx].rcvdPktStats.tooLong.value, 0);

	  if(myGlobals.device[devIdx].ipProtosList != NULL) {
	    protoList = myGlobals.ipProtosList, idx=0;
	    while(protoList != NULL) {
	      char protobuf[64];

	      Counter c = myGlobals.device[devIdx].ipProtosList[idx].value;

	      safe_snprintf(__FILE__, __LINE__, protobuf, sizeof(protobuf), "%sBytes", protoList->protocolName);
	      if(c > 0) updateCounter(rrdPath, protobuf, c, 0);
	      idx++, protoList = protoList->next;
	    }
	  }
	}

	if(dumpDetail >= FLAG_RRD_DETAIL_MEDIUM) {
	  char *prot_long_str[] = { IPOQUE_PROTOCOL_LONG_STRING };

	  safe_snprintf(__FILE__, __LINE__, rrdPath, sizeof(rrdPath), "%s/interfaces/%s/IP_",
			myGlobals.rrdPath,  myGlobals.device[devIdx].uniqueIfName);

	  for(j=0; j<IPOQUE_MAX_SUPPORTED_PROTOCOLS; j++) {
	    TrafficCounter ctr;
	    char tmpStr[128];

	    ctr.value = myGlobals.device[devIdx].l7.protoTraffic[j];
	    safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "%sBytes", prot_long_str[j]);
	    updateCounter(rrdPath, tmpStr, ctr.value, 0);
	  }	  
	}

	/* ******************************** */

	if(myGlobals.device[devIdx].asStats) {
	  AsStats *asStats;
	  u_int totAS = 0;
	  char rrdIfPath[512];

	  accessMutex(&myGlobals.device[devIdx].asMutex, "rrdPluginAS");

	  asStats = myGlobals.device[devIdx].asStats;

	  while(asStats) {
	    if(dumpASs) {
	      if(asStats->totPktsSinceLastRRDDump > AS_RRD_DUMP_PKTS_THRESHOLD) {
		safe_snprintf(__FILE__, __LINE__, rrdIfPath, sizeof(rrdIfPath),
			      "%s/interfaces/%s/AS/%d/", myGlobals.rrdPath,
			      myGlobals.device[devIdx].uniqueIfName,
			      asStats->as_id);
		mkdir_p("RRD", rrdIfPath, myGlobals.rrdDirectoryPermissions);

		updateCounter(rrdIfPath, "ifInOctets",   asStats->inBytes.value, 0);
		updateCounter(rrdIfPath, "ifInPkts",     asStats->inPkts.value, 0);
		updateCounter(rrdIfPath, "ifOutOctets",  asStats->outBytes.value, 0);
		updateCounter(rrdIfPath, "ifOutPkts",    asStats->outPkts.value, 0);
		updateCounter(rrdIfPath, "ifSelfOctets", asStats->selfBytes.value, 0);
		updateCounter(rrdIfPath, "ifSelfPkts",   asStats->selfPkts.value, 0);
	      }
	    }

	    asStats->totPktsSinceLastRRDDump = 0;

	    asStats = asStats->next;
	    totAS++;
	  }

	  releaseMutex(&myGlobals.device[devIdx].asMutex);

	  if(dumpASs) {
	    safe_snprintf(__FILE__, __LINE__, rrdIfPath, sizeof(rrdIfPath),
			  "%s/interfaces/%s/AS/", myGlobals.rrdPath,
			  myGlobals.device[devIdx].uniqueIfName);
	    mkdir_p("RRD", rrdIfPath, myGlobals.rrdDirectoryPermissions);
      safe_snprintf(__FILE__, __LINE__, rrdIfPath, sizeof(rrdIfPath),
        "%s/interfaces/%s/", myGlobals.rrdPath,
        myGlobals.device[devIdx].uniqueIfName);
	    updateGauge(rrdIfPath, "numAS", totAS, 0);
	    // traceEvent(CONST_TRACE_WARNING, "numAS=%d", totAS);
	  }
	}

	/* ******************************** */

	if(myGlobals.device[devIdx].netflowGlobals) {
	  InterfaceStats *ifStats;

	  accessMutex(&myGlobals.device[devIdx].netflowGlobals->ifStatsMutex, "rrdPluginNetflow");

	  ifStats = myGlobals.device[devIdx].netflowGlobals->ifStats;

	  while(ifStats != NULL) {
	    char rrdIfPath[512];

	    safe_snprintf(__FILE__, __LINE__, rrdIfPath, sizeof(rrdIfPath),
			  "%s/interfaces/%s/NetFlow/%d_%u_%u/", myGlobals.rrdPath,
			  myGlobals.device[devIdx].uniqueIfName, 
			  ifStats->interface_id, ifStats->netflow_device_ip, ifStats->netflow_device_port);
	    mkdir_p("RRD", rrdIfPath, myGlobals.rrdDirectoryPermissions);

	    updateCounter(rrdIfPath, "ifInOctets",   ifStats->inBytes.value, 0);
	    updateCounter(rrdIfPath, "ifInPkts",     ifStats->inPkts.value, 0);
	    updateCounter(rrdIfPath, "ifOutOctets",  ifStats->outBytes.value, 0);
	    updateCounter(rrdIfPath, "ifOutPkts",    ifStats->outPkts.value, 0);
	    updateCounter(rrdIfPath, "ifSelfOctets", ifStats->selfBytes.value, 0);
	    updateCounter(rrdIfPath, "ifSelfPkts",   ifStats->selfPkts.value, 0);

	    ifStats = ifStats->next;
	  }

	  releaseMutex(&myGlobals.device[devIdx].netflowGlobals->ifStatsMutex);
	}

	/* ******************************** */

	if(myGlobals.device[devIdx].sflowGlobals) {
	  IfCounters *ifName = myGlobals.device[devIdx].sflowGlobals->ifCounters;

	  while(ifName != NULL) {
	    char rrdIfPath[512];

	    safe_snprintf(__FILE__, __LINE__, rrdIfPath, sizeof(rrdIfPath),
			  "%s/interfaces/%s/sFlow/%u/", myGlobals.rrdPath,
			  myGlobals.device[devIdx].uniqueIfName, ifName->ifIndex);
	    mkdir_p("RRD", rrdIfPath, myGlobals.rrdDirectoryPermissions);

	    updateCounter(rrdIfPath, "ifInOctets", ifName->ifInOctets, 0);
	    updateCounter(rrdIfPath, "ifInUcastPkts", ifName->ifInUcastPkts, 0);
	    updateCounter(rrdIfPath, "ifInMulticastPkts", ifName->ifInMulticastPkts, 0);
	    updateCounter(rrdIfPath, "ifInBroadcastPkts", ifName->ifInBroadcastPkts, 0);
	    updateCounter(rrdIfPath, "ifInDiscards", ifName->ifInDiscards, 0);
	    updateCounter(rrdIfPath, "ifInErrors", ifName->ifInErrors, 0);
	    updateCounter(rrdIfPath, "ifInUnknownProtos", ifName->ifInUnknownProtos, 0);
	    updateCounter(rrdIfPath, "ifOutOctets", ifName->ifOutOctets, 0);
	    updateCounter(rrdIfPath, "ifOutUcastPkts", ifName->ifOutUcastPkts, 0);
	    updateCounter(rrdIfPath, "ifOutMulticastPkts", ifName->ifOutMulticastPkts, 0);
	    updateCounter(rrdIfPath, "ifOutBroadcastPkts", ifName->ifOutBroadcastPkts, 0);
	    updateCounter(rrdIfPath, "ifOutDiscards", ifName->ifOutDiscards, 0);
	    updateCounter(rrdIfPath, "ifOutErrors", ifName->ifOutErrors, 0);

	    ifName = ifName->next;
	  }
	}
      }
    }

    /* ************************** */

    gettimeofday(&rrdEndOfCycle, NULL);
    elapsed = timeval_subtract(rrdEndOfCycle, rrdStartOfCycle);
    if(elapsed == 0) elapsed = 1; /* Rounding */

#ifdef MAX_RRD_CYCLE_BUFFER
    rrdcycleBuffer[++rrdcycleBufferCount & (MAX_RRD_CYCLE_BUFFER - 1)] = elapsed;
#endif

    if(elapsed > rrdcmaxDuration)
      rrdcmaxDuration = elapsed;

    traceEvent(CONST_TRACE_NOISY, "RRD: Cycle %lu ended, %llu RRDs updated, %.3f seconds",
               numRRDCycles, numRRDUpdates, elapsed);

    lastRRDupdateDuration = elapsed;
    lastRRDupdateNum = numRRDUpdates;
    numRRDCycles++;

#if 0
    traceEvent(CONST_TRACE_WARNING, "numTotalRRDUpdates=%d, lastRRDupdateNum=%d, lastRRDupdateDuration=%.2f",
	       numTotalRRDUpdates, lastRRDupdateNum, lastRRDupdateDuration);
#endif

    /*
     * If it's FLAG_NTOPSTATE_STOPCAP, and we're still running, then this
     * is the 1st pass.  We just updated our data to save the counts, now
     * we kill the thread...
     */
    if(myGlobals.ntopRunState == FLAG_NTOPSTATE_STOPCAP) {
      traceEvent(CONST_TRACE_WARNING, "THREADMGMT[t%lu]: RRD: STOPCAP, ending rrd thread", (long unsigned int)pthread_self());
      break;
    }
  }

  rrdThread = 0;
  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: RRD: Data collection thread terminated [p%d]",
	     (long unsigned int)pthread_self(), getpid());

  return(0);
}

/* ****************************** */

static int initRRDfunct(void) {
  createMutex(&rrdMutex);

  setPluginStatus(NULL);

#if 0
  if (myGlobals.runningPref.rFileName != NULL) {
    /* Don't start RRD Plugin for capture files as it doesn't work */
    traceEvent(CONST_TRACE_INFO, "RRD: plugin disabled on capture files");

    active = 0;
    return (TRUE);            /* 0 indicates success */
  }
#endif

  traceEvent(CONST_TRACE_INFO, "RRD: Welcome to the RRD plugin");

  if(myGlobals.rrdPath == NULL)
    commonRRDinit();

  createThread(&rrdThread, rrdMainLoop, NULL);
  traceEvent(CONST_TRACE_INFO, "THREADMGMT: RRD: Started thread (t%lu) for data collection",
	     (long unsigned int)rrdThread);

  fflush(stdout);
  numTotalRRDUpdates = 0;
  setUpdateRRDCallback(updateRRD);

  return(0);
}

/* ****************************** */

static void termRRDfunct(u_char termNtop /* 0=term plugin, 1=term ntop */) {
  int count=0, rc;

  setUpdateRRDCallback(NULL);

  /* Hold until rrd is finished or 15s elapsed... */
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "RRD: Shutting down, locking mutex (may block for a little while)");

  while ((count++ < 5) && (tryLockMutex(&rrdMutex, "Termination") != 0)) {
    sleep(3);
  }

#ifdef MUTEX_DEBUG
  if(rrdMutex.isLocked) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "RRD: Locked mutex, continuing shutdown");
  } else {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "RRD: Unable to lock mutex, continuing shutdown anyway");
  }
#endif

  if(active) {
    if(rrdThread) {
      rc = killThread(&rrdThread);
      if (rc == 0)
        traceEvent(CONST_TRACE_INFO,
                   "THREADMGMT[t%lu]: RRD: killThread(rrdThread) succeeded",
                   (long unsigned int)pthread_self());
      else
        traceEvent(CONST_TRACE_ERROR,
                   "THREADMGMT[t%lu]: RRD: killThread(rrdThread) failed, rc %s(%d)",
                   (long unsigned int)pthread_self(), strerror(rc), rc);
    }

    if(rrdTrafficThread) {
      rc = killThread(&rrdTrafficThread);
      if (rc == 0)
	traceEvent(CONST_TRACE_INFO,
                   "THREADMGMT[t%lu]: RRD: killThread(rrdTrafficThread) succeeded",
                   (long unsigned int)pthread_self());
      else
	traceEvent(CONST_TRACE_ERROR,
                   "THREADMGMT[t%lu]: RRD: killThread(rrdTrafficThread) failed, rc %s(%d)",
                   (long unsigned int)pthread_self(), strerror(rc), rc);
    }

    /*
      if((rrdThread != 0) || (rrdTrafficThread != 0)) {
      traceEvent(CONST_TRACE_INFO,
      "THREADMGMT[t%lu]: RRD: Waiting %d seconds for threads to stop",
      (long unsigned int)pthread_self(), (PARM_SLEEP_LIMIT + 2));
      sleep(PARM_SLEEP_LIMIT + 2);
      }
    */
    traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: RRD: Plugin shutdown continuing",
	       (long unsigned int)pthread_self());
  }

  if(hostsFilter != NULL) free(hostsFilter);
  if(myGlobals.rrdPath != NULL) free(myGlobals.rrdPath);

  /*
     The line below is not needed as the mutex/rrd-plugin
     can be used (for drawing images for instance) even
     when the plugin is disabled
  */
  /* deleteMutex(&rrdMutex); */

  if(rrdd_sock_path != NULL) free(rrdd_sock_path);

  traceEvent(CONST_TRACE_INFO, "RRD: Thanks for using the rrdPlugin");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "RRD: Done");
  fflush(stdout);

  initialized = 0; /* Reinit on restart */
  active = 0;
}

/* ****************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGIN
PluginInfo* rrdPluginEntryFctn(void)
#else
     PluginInfo* PluginEntryFctn(void)
#endif
{
  traceEvent(CONST_TRACE_ALWAYSDISPLAY,
	     "RRD: Welcome to %s. (C) 2002-12 by Luca Deri.",
	     rrdPluginInfo->pluginName);

  return(rrdPluginInfo);
}

/* ************************************************ */

/* This must be here so it can access the struct PluginInfo, above */
static void setPluginStatus(char * status) {
  if(rrdPluginInfo->pluginStatusMessage != NULL)
    free(rrdPluginInfo->pluginStatusMessage);

  if(status == NULL) {
    rrdPluginInfo->pluginStatusMessage = NULL;
  } else {
    rrdPluginInfo->pluginStatusMessage = strdup(status);
  }
}
