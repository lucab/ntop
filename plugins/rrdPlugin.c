/*
 *  Copyright (C) 2002-04 Luca Deri <deri@ntop.org>
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

/* This plugin works only with threads */

/* #define RRD_DEBUG  8 */

/*

Plugin History

1.0     Initial release
1.0.1   Added Flows
1.0.2   Added Matrix
1.0.3
2.0     Rolled major version due to new interface parameter.
2.1     Added tests/creates for rrd and subdirectories, fixed timer,
        --reuse-rrd-graphics etc.
2.1.1   Fixed hosts / interface bug (Luca)
2.1.2   Added status message
2.2     Version roll (preparatory) for ntop 2.2
2.2a    Multiple RRAs
2.2b    Large rrd population option
2.3     Updates, fixes, etc ... for ntop 2.3

Remember, there are TWO paths into this - one is through the main loop,
if the plugin is active, the other is through the http function if the
plugin is NOT active.  So initialize stuff in BOTH places!


Aberrant RRD Behavior (http://cricket.sourceforge.net/aberrant/) 
patch courtesy of Dominique Karg <dk@ipsoluciones.com>

2.4     General cleanup
*/

#include "rrdPlugin.h"

static void setPluginStatus(char * status);
#ifdef CFG_MULTITHREADED
static PthreadMutex rrdMutex;
#endif

#ifdef WIN32
int optind, opterr;
#endif

static unsigned short initialized = 0, active = 0, dumpInterval, dumpDetail;
static unsigned short dumpDays, dumpHours, dumpMonths;
static char *hostsFilter = NULL;
static Counter numTotalRRDs = 0;
static unsigned long numRuns = 0, numRRDerrors = 0;
static time_t start_tm, end_tm, rrdTime;

#ifdef CFG_MULTITHREADED
pthread_t rrdThread;
#endif

static u_short dumpDomains, dumpFlows, dumpHosts, dumpInterfaces, dumpMatrix, shownCreate=0;
#ifndef WIN32
static u_short dumpPermissions;
#endif

static Counter rrdGraphicRequests=0;

#ifdef RRD_DEBUG
char startTimeBuf[32], endTimeBuf[32], fileTimeBuf[32];
#endif

/* forward */
int sumCounter(char *rrdPath, char *rrdFilePath,
	       char *startTime, char* endTime, Counter *total, float *average);
void graphCounter(char *rrdPath, char *rrdName, char *rrdTitle,
		  char *startTime, char* endTime, char* rrdPrefix);
void updateCounter(char *hostPath, char *key, Counter value);
void updateGauge(char *hostPath, char *key, Counter value);
void updateTrafficCounter(char *hostPath, char *key, TrafficCounter *counter);
char x2c(char *what);
void unescape_url(char *url);
void mkdir_p(char *path);
static int initRRDfunct(void);
static void termRRDfunct(void);
static void handleRRDHTTPrequest(char* url);

/* ************************************* */

static PluginInfo rrdPluginInfo[] = {
  {
    VERSION, /* current ntop version */
    "rrdPlugin",
    "This plugin is used to setup, activate and deactivate ntop's rrd support.<br>"
    "This plugin also produces the graphs of rrd data, available via a "
    "link from the various 'Info about host xxxxx' reports.",
    "2.4", /* version */
    "<a HREF=\"http://luca.ntop.org/\" alt=\"Luca's home page\">L.Deri</A>",
    "rrdPlugin", /* http://<host>:<port>/plugins/rrdPlugin */
    1, /* Active by default */
    1, /* Inactive setup */
    initRRDfunct, /* TermFunc   */
    termRRDfunct, /* TermFunc   */
    NULL, /* PluginFunc */
    handleRRDHTTPrequest,
    NULL, /* no capture */
    NULL /* no status */
  }
};

/* ****************************************************** */

static char **calcpr=NULL;

static void calfree (void) {
  if(calcpr) {
    long i;
    for(i=0;calcpr[i];i++){
      if(calcpr[i]){
	free(calcpr[i]);
      }
    }
    if(calcpr) {
      free(calcpr);
    }
  }
}

/* ******************************************* */

#ifdef WIN32
#define _mkdir(a) mkdir(a)
#else
#define _mkdir(a) mkdir(a, myGlobals.rrdDirectoryPermissions)
#endif

void mkdir_p(char *path) {
  int i, rc;

  if(path == NULL) {
    traceEvent(CONST_TRACE_NOISY, "RRD: mkdir(null) skipped");
    return;
  }

#ifdef WIN32
  revertSlash(path, 0);
#endif

  /* Start at 1 to skip the root */
  for(i=1; path[i] != '\0'; i++)
    if(path[i] == CONST_PATH_SEP) {
      path[i] = '\0';
#if RRD_DEBUG >= 3
      traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: calling mkdir(%s)", path);
#endif
      rc = _mkdir(path);
      if((rc != 0) && (errno != EEXIST) )
	traceEvent(CONST_TRACE_WARNING, "RRD: %s, error %d %s",
		   path,
		   errno,
		   strerror(errno));
      path[i] = CONST_PATH_SEP;
    }

#if RRD_DEBUG >= 2
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: calling mkdir(%s)", path);
#endif
  _mkdir(path);
  if((rc != 0) && (errno != EEXIST) )
    traceEvent(CONST_TRACE_WARNING, "RRD: %s, error %d %s",
	       path,
	       errno,
	       strerror(errno));
}

/* ******************************************* */

static void fillupArgv(int argc, int maxArgc, char *argv[]) {
  int i;

  for(i=argc; i<maxArgc; i++)
    argv[i] = "";

  optind = 1;
}

/* ******************************************* */

int sumCounter(char *rrdPath, char *rrdFilePath,
	       char *startTime, char* endTime, Counter *total, float *average) {
  char *argv[32], path[512];
  int argc = 0, rc;
  time_t        start,end;
  unsigned long step, ds_cnt,i;
  rrd_value_t   *data,*datai, _total, _val;
  char          **ds_namv;

  if(snprintf(path, sizeof(path), "%s/%s/%s",
	      myGlobals.rrdPath, rrdPath, rrdFilePath) < 0)
    BufferTooShort();

#ifdef WIN32
  revertSlash(path, 0);
#endif

  argv[argc++] = "rrd_fetch";
  argv[argc++] = path;
  argv[argc++] = "AVERAGE";
  argv[argc++] = "--start";
  argv[argc++] = startTime;
  argv[argc++] = "--end";
  argv[argc++] = endTime;

#ifdef CFG_MULTITHREADED
  accessMutex(&rrdMutex, "rrd_fetch");
#endif
  optind=0; /* reset gnu getopt */
  opterr=0; /* no error messages */

  fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);

  rrd_clear_error();
  rc = rrd_fetch(argc, argv, &start, &end, &step, &ds_cnt, &ds_namv, &data);

#ifdef CFG_MULTITHREADED
  releaseMutex(&rrdMutex);
#endif

  if(rc == -1) {
#if RRD_DEBUG >= 3
    int x;
    
    for (x = 0; x < argc; x++)
      traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: argv[%d] = %s", x, argv[x]);
#endif

    return(-1);
  }

  datai  = data, _total = 0;

  for(i = start; i <= end; i += step) {
    _val = *(datai++);

    if(_val > 0)
      _total += _val;
  }

  for(i=0;i<ds_cnt;i++) free(ds_namv[i]);
  free(ds_namv);
  free(data);

  (*total)   = _total*step;
  (*average) = (float)(*total)/(float)(end-start);
  return(0);
}

/* ******************************************* */

static void listResource(char *rrdPath, char *rrdTitle,
			 char *startTime, char* endTime) {
  char path[512], url[256], formatBuf[32];
  DIR* directoryPointer=NULL;
  struct dirent* dp;
  int numEntries = 0;

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);

  if(snprintf(path, sizeof(path), "%s/%s", myGlobals.rrdPath, rrdPath) < 0)
    BufferTooShort();

#ifdef WIN32
  revertSlash(path, 0);
#endif

  directoryPointer = opendir(path);

  if(directoryPointer == NULL) {
    char buf[256];
    if(snprintf(buf, sizeof(buf), "<I>Unable to read directory %s</I>", path) < 0)
      BufferTooShort();
    printFlagedWarning(buf);
    printHTMLtrailer();
    return;
  }

  if(snprintf(path, sizeof(path), "Info about %s", rrdTitle) < 0)
    BufferTooShort();

  printHTMLheader(path, NULL, 0);
  sendString("<CENTER>\n<p ALIGN=right>\n");

  if(snprintf(url, sizeof(url),
              "/plugins/rrdPlugin?action=list&key=%s&title=%s&end=now",
              rrdPath, rrdTitle) < 0)
      BufferTooShort();

  if(snprintf(path, sizeof(path), "<b>View:</b> [ <A HREF=\"%s&start=now-1y\">year</A> ]", url) < 0)
      BufferTooShort();
    sendString(path);
  if(snprintf(path, sizeof(path), "[ <A HREF=\"%s&start=now-1m\">month</A> ]", url) < 0)
      BufferTooShort();
    sendString(path);
  if(snprintf(path, sizeof(path), "[ <A HREF=\"%s&start=now-1w\">week</A> ]", url) < 0)
      BufferTooShort();
    sendString(path);
  if(snprintf(path, sizeof(path), "[ <A HREF=\"%s&start=now-1d\">day</A> ]", url) < 0)
      BufferTooShort();
    sendString(path);
  if(snprintf(path, sizeof(path), "[ <A HREF=\"%s&start=now-12h\">last 12h</A> ]\n", url) < 0)
      BufferTooShort();
    sendString(path);
  if(snprintf(path, sizeof(path), "[ <A HREF=\"%s&start=now-6h\">last 6h</A> ]\n", url) < 0)
      BufferTooShort();
    sendString(path);
  if(snprintf(path, sizeof(path), "[ <A HREF=\"%s&start=now-1h\">last hour</A> ]&nbsp;\n", url) < 0)
      BufferTooShort();
    sendString(path);

  sendString("</p>\n<p>\n<TABLE BORDER=1 "TABLE_DEFAULTS">\n");

  sendString("<TR><TH "DARK_BG">Graph</TH><TH "DARK_BG">Total</TH></TR>\n");

  while((dp = readdir(directoryPointer)) != NULL) {
    char *rsrcName;
    Counter total;
    float  average;
    int rc, isGauge;

    if(dp->d_name[0] == '.')
      continue;
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

    rc = sumCounter(rrdPath, dp->d_name, startTime, endTime, &total, &average);

    if(isGauge
       || ((rc >= 0) && (total > 0))) {
      rsrcName[0] = '\0';
      rsrcName = dp->d_name;

      sendString("<TR><TD>\n");

      if(snprintf(path, sizeof(path), "<IMG SRC=\"/plugins/rrdPlugin?action=graph&key=%s/&name=%s&title=%s&start=%s&end=%s\"><P>\n",
	       rrdPath, rsrcName, rsrcName, startTime, endTime) < 0)
        BufferTooShort();
      sendString(path);

      sendString("</TD><TD ALIGN=RIGHT>\n");

      /* printf("rsrcName: %s\n", rsrcName); */

      if(isGauge) {
	sendString("&nbsp;");
      } else {
	if((strncmp(rsrcName, "pkt", 3) == 0)
	   || ((strlen(rsrcName) > 4) && (strcmp(&rsrcName[strlen(rsrcName)-4], "Pkts") == 0))) {
	  if(snprintf(path, sizeof(path), "%s Pkt</TD>",
                      formatPkts(total, formatBuf, sizeof(formatBuf))) < 0)
            BufferTooShort();
	} else {
	  if(snprintf(path, sizeof(path), "%s",
                      formatBytes(total, 1, formatBuf, sizeof(formatBuf))) < 0)
            BufferTooShort();
	}
	sendString(path);
      }

      sendString("</TD></TR>\n");
      numEntries++;
    }
  } /* while */

  closedir(directoryPointer);

  /* if(numEntries > 0) */ {
    sendString("</TABLE>\n");
  }

  sendString("</CENTER>");
  sendString("<br><b>NOTE: total and average values are NOT absolute but calculated on the specified time interval.</b>\n");

  printHTMLtrailer();
}

/* ******************************************* */

static int endsWith(char* label, char* pattern) {
  int lenLabel, lenPattern;

  lenLabel   = strlen(label);
  lenPattern = strlen(pattern);

  if(lenPattern >= lenLabel)
    return(0);
  else
    return(!strcmp(&label[lenLabel-lenPattern], pattern));
}

/* ******************************************* */

void graphCounter(char *rrdPath, char *rrdName, char *rrdTitle,
		  char *startTime, char* endTime, char *rrdPrefix) {
  char path[512], *argv[32], buf[384], buf1[384], fname[384], *label;
#ifdef HAVE_RRD_ABERRANT_BEHAVIOR
  char buf2[384], buf3[384], buf4[384];
#endif
  struct stat statbuf;
  int argc = 0, rc, x, y;

  if(snprintf(path, sizeof(path), "%s/%s%s.rrd", myGlobals.rrdPath, rrdPath, rrdName) < 0)
    BufferTooShort();

  /* startTime[4] skips the 'now-' */
  if(snprintf(fname, sizeof(fname), "%s/%s/%s-%s%s%s",
	   myGlobals.rrdPath, rrd_subdirs[0], startTime, rrdPrefix, rrdName,
	   CHART_FORMAT) < 0)
    BufferTooShort();

#ifdef WIN32
  revertSlash(path, 0);
  revertSlash(fname, 0);
#endif

  if(endsWith(rrdName, "Bytes")) label = "Bytes/sec";
  else if(endsWith(rrdName, "Pkts")) label = "Packets/sec";
  else label = rrdName;

  rrdGraphicRequests++;

  if(stat(path, &statbuf) == 0) {
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
#ifdef CONST_RRD_DEFAULT_FONT_NAME
    argv[argc++] = "--font";
 #ifdef CONST_RRD_DEFAULT_FONT_PATH
    argv[argc++] = "DEFAULT:" CONST_RRD_DEFAULT_FONT_SIZE ":" \
                   CONST_RRD_DEFAULT_FONT_PATH CONST_RRD_DEFAULT_FONT_NAME; 
 #else
    argv[argc++] = "DEFAULT:" CONST_RRD_DEFAULT_FONT_SIZE ":" CONST_RRD_DEFAULT_FONT_NAME; 
 #endif
#endif
#ifdef WIN32
    revertDoubleColumn(path);
#endif
    if(snprintf(buf, sizeof(buf), "DEF:ctr=%s:counter:AVERAGE", path) < 0)
      BufferTooShort();
    argv[argc++] = buf;
    if(snprintf(buf1, sizeof(buf1), "AREA:ctr#00a000:%s", rrdTitle) < 0)
      BufferTooShort();
    argv[argc++] = buf1;
    argv[argc++] = "GPRINT:ctr:MIN:Min\\: %3.1lf%s";
    argv[argc++] = "GPRINT:ctr:MAX:Max\\: %3.1lf%s";
    argv[argc++] = "GPRINT:ctr:AVERAGE:Avg\\: %3.1lf%s";
    argv[argc++] = "GPRINT:ctr:LAST:Current\\: %3.1lf%s";
#ifdef HAVE_RRD_ABERRANT_BEHAVIOR
    if(snprintf(buf2, sizeof(buf2), "DEF:pred=%s:counter:HWPREDICT", path) < 0)
      BufferTooShort();
    argv[argc++] = buf2;
    if(snprintf(buf3, sizeof(buf3), "DEF:dev=%s:counter:DEVPREDICT", path) < 0)
      BufferTooShort();
    argv[argc++] = buf3;
    if(snprintf(buf4, sizeof(buf4), "DEF:fail=%s:counter:FAILURES", path) < 0)
      BufferTooShort();
    argv[argc++] = buf4;
    argv[argc++] = "TICK:fail#ffffa0:1.0:Anomalia";
    argv[argc++] = "CDEF:upper=pred,dev,2,*,+";
    argv[argc++] = "CDEF:lower=pred,dev,2,*,-";
    argv[argc++] = "LINE1:upper#ff0000:Upper";
    argv[argc++] = "LINE2:lower#ff0000:Lower";
#endif

#ifdef CFG_MULTITHREADED
    accessMutex(&rrdMutex, "rrd_graph");
#endif
    optind=0; /* reset gnu getopt */
    opterr=0; /* no error messages */

    fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);
    rrd_clear_error();
    rc = rrd_graph(argc, argv, &calcpr, &x, &y);

    calfree();

    if(rc == 0) {
      sendHTTPHeader(FLAG_HTTP_TYPE_PNG, 0, 1);
      sendGraphFile(fname, 0);
      unlink(fname);
    } else {
#if RRD_DEBUG >= 3
      for (x = 0; x < argc; x++)
	traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: argv[%d] = %s", x, argv[x]);
#endif
      
      sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
      printHTMLheader("RRD Graph", NULL, 0);
      if(snprintf(path, sizeof(path),
                  "<I>Error while building graph of the requested file. %s</I>",
	          rrd_get_error()) < 0)
        BufferTooShort();
      printFlagedWarning(path);
      rrd_clear_error();
    }

#ifdef CFG_MULTITHREADED
    releaseMutex(&rrdMutex);
#endif    
  } else {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("RRD Graph", NULL, 0);
    printFlagedWarning("<I>Error while building graph of the requested file "
		       "(unknown RRD file)</I>");
  }
}

/* ******************************* */

static void updateRRD(char *hostPath, char *key, Counter value, int isCounter) {
  char path[512], *argv[32], cmd[64];
  struct stat statbuf;
  int argc = 0, rc, createdCounter = 0, i;

  if(value == 0) return;

  if(snprintf(path, sizeof(path), "%s%s.rrd", hostPath, key) < 0)
    BufferTooShort();

  /* Avoid path problems */
  for(i=strlen(hostPath); i<strlen(path); i++)
    if(path[i] == '/') path[i]='_';

#ifdef WIN32
  revertSlash(path, 0);
#endif

  if(stat(path, &statbuf) != 0) {
    char startStr[32], stepStr[32], counterStr[64], intervalStr[32];
    char minStr[32], maxStr[32], daysStr[32], monthsStr[32];
#ifdef HAVE_RRD_ABERRANT_BEHAVIOR
    char tempStr[64];
#endif
    int step = dumpInterval;
    int value1, value2;
    unsigned long topValue;

    topValue = 1000000000 /* 1 Gbit/s */;

    if(strncmp(key, "pkt", 3) == 0) {
      topValue /= 8*64 /* 64 bytes is the shortest packet we care of */;
    } else {
      topValue /= 8 /* 8 bytes */;
    }

    argv[argc++] = "rrd_create";
    argv[argc++] = path;
    argv[argc++] = "--start";
    if(snprintf(startStr, sizeof(startStr), "%u",
	     rrdTime-1 /* -1 avoids subsequent rrd_update call problems */) < 0)
      BufferTooShort();
    argv[argc++] = startStr;

    argv[argc++] = "--step";
    if(snprintf(stepStr, sizeof(stepStr), "%u", dumpInterval) < 0)
      BufferTooShort();
    argv[argc++] = stepStr;

    if(isCounter) {
      if(snprintf(counterStr, sizeof(counterStr), "DS:counter:COUNTER:%d:0:%u", step, topValue) < 0)
        BufferTooShort();
    } else {
      /* Unlimited */
      if(snprintf(counterStr, sizeof(counterStr), "DS:counter:GAUGE:%d:0:U", step) < 0)
        BufferTooShort();
    }
    argv[argc++] = counterStr;

    /* dumpInterval is in seconds.  There are 60m*60s = 3600s in an hour.
     * value1 is the # of dumpIntervals per hour
     */
    value1 = (60*60 + dumpInterval - 1) / dumpInterval;
    /* value2 is the # of value1 (hours) for dumpHours hours */
    value2 = value1 * dumpHours;
    if(snprintf(intervalStr, sizeof(intervalStr), "RRA:AVERAGE:%.1f:1:%d", 0.5, value2) < 0)
      BufferTooShort();
    argv[argc++] = intervalStr;

    /* Store the MIN/MAX 5m value for a # of hours */
    if(snprintf(minStr, sizeof(minStr), "RRA:MIN:%.1f:1:%d",
                0.5, dumpHours > 0 ? dumpHours : DEFAULT_RRD_HOURS) < 0)
      BufferTooShort();
    argv[argc++] = minStr;
    if(snprintf(maxStr, sizeof(maxStr), "RRA:MAX:%.1f:1:%d",
               0.5, dumpHours > 0 ? dumpHours : DEFAULT_RRD_HOURS) < 0)
      BufferTooShort();
    argv[argc++] = maxStr;

    if(dumpDays > 0) {
      if(snprintf(daysStr, sizeof(daysStr), "RRA:AVERAGE:%.1f:%d:%d",
                  0.5, value1, dumpDays * 24) < 0)
        BufferTooShort();
      argv[argc++] = daysStr;
    }

    /* Compute the rollup - how many dumpInterval seconds interval are in a day */
    value1 = (24*60*60 + dumpInterval - 1) / dumpInterval;
    if(dumpMonths > 0) {
      if(snprintf(monthsStr, sizeof(monthsStr), "RRA:AVERAGE:%.1f:%d:%d",
                  0.5, value1, dumpMonths * 30) < 0)
        BufferTooShort();
      argv[argc++] = monthsStr;
    }

#ifdef HAVE_RRD_ABERRANT_BEHAVIOR
    if(snprintf(tempStr, sizeof(tempStr), "RRA:HWPREDICT:1440:0.1:0.0035:20") < 0)
      BufferTooShort();
    argv[argc++] = tempStr;
#endif

#if DEBUG
    if(shownCreate == 0) {
      char buf[LEN_GENERAL_WORK_BUFFER];
      int i;

      shownCreate=1;

      memset(buf, 0, sizeof(buf));

      if(snprintf(buf, sizeof(buf), "%s", argv[4]) < 0)
        BufferTooShort();

      for (i=5; i<argc; i++) {
	strncat(buf, " ", (sizeof(buf) - strlen(buf) - 1));
	strncat(buf, argv[i], (sizeof(buf) - strlen(buf) - 1));
      }

      traceEvent(CONST_TRACE_INFO, "RRD: rrdtool create --start now-1 file %s", buf);
    }
#endif

#ifdef CFG_MULTITHREADED
    accessMutex(&rrdMutex, "rrd_create");
#endif
    optind=0; /* reset gnu getopt */
    opterr=0; /* no error messages */

    fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);
    rrd_clear_error();
    rc = rrd_create(argc, argv);

    if(rrd_test_error()) {
#if RRD_DEBUG >= 3
      int x;
      
      for (x = 0; x < argc; x++)
	traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: argv[%d] = %s", x, argv[x]);
#endif
      
      traceEvent(CONST_TRACE_WARNING, "RRD: rrd_create(%s) error: %s", path, rrd_get_error());
      rrd_clear_error();
      numRRDerrors++;
    }

#ifdef CFG_MULTITHREADED
    releaseMutex(&rrdMutex);
#endif

#if RRD_DEBUG > 0
    traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: rrd_create(%s, %s, %u)=%d",
	       hostPath, key, (unsigned long)value, rc);
#endif
    createdCounter = 1;
  }

#if RRD_DEBUG > 0
  argc = 0;
  argv[argc++] = "rrd_last";
  argv[argc++] = path;

#ifdef CFG_MULTITHREADED
  accessMutex(&rrdMutex, "rrd_last");
#endif
  optind=0; /* reset gnu getopt */
  opterr=0; /* no error messages */

  fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);
  rrd_clear_error();
  if(rrd_last(argc, argv) >= rrdTime) {
    traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: WARNING rrd_update not performed (RRD already updated)");
  }

#ifdef CFG_MULTITHREADED
  releaseMutex(&rrdMutex);
#endif
#endif

  argc = 0;
  argv[argc++] = "rrd_update";
  argv[argc++] = path;

  if((!createdCounter) && (numRuns == 1)) {
    /* This is the first rrd update hence in order to avoid
       wrong traffic peaks we set the value for the counter on the previous
       interval to unknown

       # From: Alex van den Bogaerdt <alex@ergens.op.HET.NET>
       # Date: Fri, 12 Jul 2002 01:32:45 +0200 (CEST)
       # Subject: Re: [rrd-users] Re: To DERIVE or not to DERIVE

       [...]

       Oops.  OK, so the counter is unknown.  Indeed one needs to discard
       the first interval between reboot time and poll time in that case.

       [...]

       But this would also make the next interval unknown.  My suggestion:
       insert an unknown at that time minus one second, enter the fetched
       value at that time.

       cheers,
       --
       __________________________________________________________________
       / alex@slot.hollandcasino.nl                  alex@ergens.op.het.net \

    */

    if(snprintf(cmd, sizeof(cmd), "%u:u", rrdTime-10) < 0) /* u = undefined */
      BufferTooShort();
  } else {
    if(snprintf(cmd, sizeof(cmd), "%u:%u", rrdTime, (unsigned long)value) < 0)
      BufferTooShort();
  }

  argv[argc++] = cmd;

#ifdef CFG_MULTITHREADED
  accessMutex(&rrdMutex, "rrd_update");
#endif
  optind=0; /* reset gnu getopt */
  opterr=0; /* no error messages */

  fillupArgv(argc, sizeof(argv)/sizeof(char*), argv);
  rrd_clear_error();
  rc = rrd_update(argc, argv);

  numTotalRRDs++;

  if(rrd_test_error()) {
    int x;
    char *rrdError;

#if RRD_DEBUG >= 3
    for (x = 0; x < argc; x++)
      traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: argv[%d] = %s", x, argv[x]);
#endif

    numRRDerrors++;
    rrdError = rrd_get_error();
    if(rrdError != NULL) {
      traceEvent(CONST_TRACE_WARNING, "RRD: rrd_update(%s) error: %s", path, rrdError);
      traceEvent(CONST_TRACE_NOISY, "RRD: call stack (counter created: %d):", createdCounter);
      for (x = 0; x < argc; x++)
	traceEvent(CONST_TRACE_NOISY, "RRD:   argv[%d]: %s", x, argv[x]);

      if(!strcmp(rrdError, "error: illegal attempt to update using time")) {
	char errTimeBuf1[32], errTimeBuf2[32], errTimeBuf3[32];
	time_t rrdLast;
	struct tm workT;

	strftime(errTimeBuf1, sizeof(errTimeBuf1), CONST_LOCALE_TIMESPEC, localtime_r(&myGlobals.actTime, &workT));
	strftime(errTimeBuf2, sizeof(errTimeBuf2), CONST_LOCALE_TIMESPEC, localtime_r(&rrdTime, &workT));
	argc = 0;
	argv[argc++] = "rrd_last";
	argv[argc++] = path;

	rrdLast = rrd_last(argc, argv);
	strftime(errTimeBuf3, sizeof(errTimeBuf3), CONST_LOCALE_TIMESPEC, localtime_r(&rrdLast, &workT));
	traceEvent(CONST_TRACE_WARNING,
		   "RRD: actTime = %d(%s), rrdTime %d(%s), lastUpd %d(%s)",
		   myGlobals.actTime,
		   errTimeBuf1,
		   rrdTime,
		   errTimeBuf2,
		   rrdLast,
		   rrdLast == -1 ? "rrdlast ERROR" : errTimeBuf3);
      } else if(strstr(rrdError, "is not an RRD file")) {
	unlink(path);
      }

      rrd_clear_error();
    }
  }

#ifdef CFG_MULTITHREADED
  releaseMutex(&rrdMutex);
#endif
}

/* ******************************* */

void updateCounter(char *hostPath, char *key, Counter value) {
  updateRRD(hostPath, key, value, 1);
}

/* ******************************* */

void updateGauge(char *hostPath, char *key, Counter value) {
  updateRRD(hostPath, key, value, 0);
}

/* ******************************* */

void updateTrafficCounter(char *hostPath, char *key, TrafficCounter *counter) {
  if(counter->modified) {
    updateCounter(hostPath, key, counter->value);
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
  char value[1024];

  shownCreate=0;

  if(fetchPrefsValue("rrd.dataDumpInterval", value, sizeof(value)) == -1) {
    if(snprintf(value, sizeof(value), "%d", DEFAULT_RRD_INTERVAL) < 0)
      BufferTooShort();
    storePrefsValue("rrd.dataDumpInterval", value);
    dumpInterval = DEFAULT_RRD_INTERVAL;
  } else {
    dumpInterval = atoi(value);
  }

  if(fetchPrefsValue("rrd.dataDumpHours", value, sizeof(value)) == -1) {
    if(snprintf(value, sizeof(value), "%d", DEFAULT_RRD_HOURS) < 0)
      BufferTooShort();
    storePrefsValue("rrd.dataDumpHours", value);
    dumpHours = DEFAULT_RRD_HOURS;
  } else {
    dumpHours = atoi(value);
  }

  if(fetchPrefsValue("rrd.dataDumpDays", value, sizeof(value)) == -1) {
    if(snprintf(value, sizeof(value), "%d", DEFAULT_RRD_DAYS) < 0)
      BufferTooShort();
    storePrefsValue("rrd.dataDumpDays", value);
    dumpDays = DEFAULT_RRD_DAYS;
  } else {
    dumpDays = atoi(value);
  }

  if(fetchPrefsValue("rrd.dataDumpMonths", value, sizeof(value)) == -1) {
    if(snprintf(value, sizeof(value), "%d", DEFAULT_RRD_MONTHS) < 0)
      BufferTooShort();
    storePrefsValue("rrd.dataDumpMonths", value);
    dumpMonths = DEFAULT_RRD_MONTHS;
  } else {
    dumpMonths = atoi(value);
  }

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

  if(fetchPrefsValue("rrd.dataDumpMatrix", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dataDumpMatrix", "0");
    dumpMatrix = 0;
  } else {
    dumpMatrix = atoi(value);
  }

  if(hostsFilter != NULL) free(hostsFilter);
  if(fetchPrefsValue("rrd.hostsFilter", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.hostsFilter", "");
    hostsFilter  = strdup("");
  } else {
    hostsFilter  = strdup(value);
  }

  if(fetchPrefsValue("rrd.dataDumpDetail", value, sizeof(value)) == -1) {
    if(snprintf(value, sizeof(value), "%d", CONST_RRD_DETAIL_DEFAULT) < 0)
      BufferTooShort();
    storePrefsValue("rrd.dataDumpDetail", value);
    dumpDetail = CONST_RRD_DETAIL_DEFAULT;
  } else {
    dumpDetail  = atoi(value);
  }

  if(fetchPrefsValue("rrd.rrdPath", value, sizeof(value)) == -1) {
    char *thePath = "/rrd";
    int len = strlen(myGlobals.dbPath)+strlen(thePath)+1;

    if(myGlobals.rrdPath) free(myGlobals.rrdPath);
    myGlobals.rrdPath = (char*)malloc(len);
    if(snprintf(myGlobals.rrdPath, len, "%s%s", myGlobals.dbPath, thePath) < 0)
      BufferTooShort();
    storePrefsValue("rrd.rrdPath", myGlobals.rrdPath);
  } else {
    int vlen = strlen(value)+1;

    myGlobals.rrdPath  = (char*)malloc(vlen);
    unescape(myGlobals.rrdPath, vlen, value);
  }

#ifndef WIN32
  if(fetchPrefsValue("rrd.permissions", value, sizeof(value)) == -1) {
    if(snprintf(value, sizeof(value), "%d", DEFAULT_RRD_PERMISSIONS) < 0)
      BufferTooShort();
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
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpHours %d hours by %d seconds", dumpHours, dumpInterval);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpDays %d days by hour", dumpDays);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpMonths %d months by day", dumpMonths);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpDomains %s", dumpDomains == 0 ? "no" : "yes");
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpFlows %s", dumpFlows == 0 ? "no" : "yes");
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpHosts %s", dumpHosts == 0 ? "no" : "yes");
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpInterfaces %s", dumpInterfaces == 0 ? "no" : "yes");
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpMatrix %s", dumpMatrix == 0 ? "no" : "yes");
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     dumpDetail %s",
	     dumpDetail == FLAG_RRD_DETAIL_HIGH ? "high" :
             (dumpDetail == FLAG_RRD_DETAIL_MEDIUM ? "medium" : "low"));
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     hostsFilter %s", hostsFilter);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     rrdPath %s", myGlobals.rrdPath);
#ifndef WIN32
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     umask %04o", myGlobals.rrdUmask);
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG:     DirPerms %04o", myGlobals.rrdDirectoryPermissions);
#endif
#endif /* RRD_DEBUG */

  initialized = 1;
}

/* ****************************** */

static void handleRRDHTTPrequest(char* url) {
  char buf[1024], *strtokState, *mainState, *urlPiece,
    rrdKey[64], rrdName[64], rrdTitle[64], startTime[32], endTime[32], rrdPrefix[32];
  u_char action = FLAG_RRD_ACTION_NONE;
  int _dumpDomains, _dumpFlows, _dumpHosts, _dumpInterfaces, _dumpMatrix, _dumpDetail, _dumpInterval, _dumpHours, _dumpDays, _dumpMonths;
  char * _hostsFilter;
#ifndef WIN32
  int _dumpPermissions;
#endif

  if(initialized == 0)
    commonRRDinit();

  /* Initial values - remember, for checkboxes these need to be OFF (there's no html UNCHECKED option) */
  _dumpDomains=0;
  _dumpFlows=0;
  _dumpHosts=0;
  _dumpInterfaces=0;
  _dumpMatrix=0;
  _dumpDetail=CONST_RRD_DETAIL_DEFAULT;
  _dumpInterval=DEFAULT_RRD_INTERVAL;
  _dumpHours=DEFAULT_RRD_HOURS;
  _dumpDays=DEFAULT_RRD_DAYS;
  _dumpMonths=DEFAULT_RRD_MONTHS;
  _hostsFilter = NULL;
#ifndef WIN32
  _dumpPermissions = DEFAULT_RRD_PERMISSIONS;
#endif

  if((url != NULL) && (url[0] != '\0')) {
    unescape_url(url);

    /* traceEvent(CONST_TRACE_INFO, "RRD: URL=%s", url); */

    urlPiece = strtok_r(url, "&", &mainState);
    strcpy(startTime, "now-12h");
    strcpy(endTime, "now");

    while(urlPiece != NULL) {
      char *key, *value;

      key = strtok_r(urlPiece, "=", &strtokState);
      if(key != NULL) value = strtok_r(NULL, "=", &strtokState); else value = NULL;

      /* traceEvent(CONST_TRACE_INFO, "RRD: key(%s)=%s", key, value);  */

      if(value && key) {

	if(strcmp(key, "action") == 0) {
	  if(strcmp(value, "graph") == 0)     action = FLAG_RRD_ACTION_GRAPH;
	  else if(strcmp(value, "list") == 0) action = FLAG_RRD_ACTION_LIST;
	} else if(strcmp(key, "key") == 0) {
	  int len = strlen(value), i;

	  if(len >= sizeof(rrdKey)) len = sizeof(rrdKey)-1;
	  strncpy(rrdKey, value, len);
	  rrdKey[len] = '\0';
	  for(i=0; i<len; i++) if(rrdKey[i] == '+') rrdKey[i] = ' ';

          if(strncmp(value, "hosts/", strlen("hosts/")) == 0) {
	    int plen, ii;
	    if(snprintf(rrdPrefix, sizeof(rrdPrefix), "ip_%s_", &value[6]) < 0)
	      BufferTooShort();
	    plen=strlen(rrdPrefix);
	    for (ii=0; ii<plen; ii++)
	      if( (rrdPrefix[ii] == '.') || (rrdPrefix[ii] == '/') )
		rrdPrefix[ii]='_';
          } else {
	    rrdPrefix[0] = '\0';
          }
	} else if(strcmp(key, "name") == 0) {
	  int len = strlen(value), i;

	  if(len >= sizeof(rrdName)) len = sizeof(rrdName)-1;
	  strncpy(rrdName, value, len);
  	  for(i=0; i<len; i++) if(rrdName[i] == '+') rrdName[i] = ' ';

	  rrdName[len] = '\0';
	} else if(strcmp(key, "title") == 0) {
	  int len = strlen(value), i;

	  if(len >= sizeof(rrdTitle)) len = sizeof(rrdTitle)-1;
	  strncpy(rrdTitle, value, len);
  	  for(i=0; i<len; i++) if(rrdTitle[i] == '+') rrdTitle[i] = ' ';

	  rrdTitle[len] = '\0';
	} else if(strcmp(key, "start") == 0) {
	  int len = strlen(value);

	  if(len >= sizeof(startTime)) len = sizeof(startTime)-1;
	  strncpy(startTime, value, len); startTime[len] = '\0';
	} else if(strcmp(key, "end") == 0) {
	  int len = strlen(value);

	  if(len >= sizeof(endTime)) len = sizeof(endTime)-1;
	  strncpy(endTime, value, len); endTime[len] = '\0';
	} else if(strcmp(key, "interval") == 0) {
	  _dumpInterval = atoi(value);
          if(_dumpInterval < 1) _dumpInterval = 1 /* Min 1 second */;
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
	  int vlen = strlen(value)+1;

	  if(myGlobals.rrdPath != NULL) free(myGlobals.rrdPath);
	  myGlobals.rrdPath  = (char*)malloc(vlen);
	  unescape(myGlobals.rrdPath, vlen, value);
	  storePrefsValue("rrd.rrdPath", myGlobals.rrdPath);
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
	} else if(strcmp(key, "dumpMatrix") == 0) {
	  _dumpMatrix = 1;
#ifndef WIN32
	} else if(strcmp(key, "permissions") == 0) {
	  _dumpPermissions = atoi(value);
          if((_dumpPermissions != CONST_RRD_PERMISSIONS_PRIVATE) &&
             (_dumpPermissions != CONST_RRD_PERMISSIONS_GROUP) &&
             (_dumpPermissions != CONST_RRD_PERMISSIONS_EVERYONE)) {
            _dumpPermissions = DEFAULT_RRD_PERMISSIONS;
          }
#endif
	}
      }

      urlPiece = strtok_r(NULL, "&", &mainState);
    }

    if(action == FLAG_RRD_ACTION_NONE) {
      dumpInterval = _dumpInterval;
      dumpHours = _dumpHours;
      dumpDays = _dumpDays;
      dumpMonths = _dumpMonths;
      /* traceEvent(CONST_TRACE_INFO, "RRD: dumpFlows=%d", dumpFlows); */
      dumpDomains=_dumpDomains;
      dumpFlows=_dumpFlows;
      dumpHosts=_dumpHosts;
      dumpInterfaces=_dumpInterfaces;
      dumpMatrix=_dumpMatrix;
      dumpDetail = _dumpDetail;
#ifndef WIN32
      dumpPermissions = _dumpPermissions;
      setGlobalPermissions(_dumpPermissions);
#endif
      if(snprintf(buf, sizeof(buf), "%d", dumpInterval) < 0)
        BufferTooShort();
      storePrefsValue("rrd.dataDumpInterval", buf);
      if(snprintf(buf, sizeof(buf), "%d", dumpHours) < 0)
        BufferTooShort();
      storePrefsValue("rrd.dataDumpHours", buf);
      if(snprintf(buf, sizeof(buf), "%d", dumpDays) < 0)
        BufferTooShort();
      storePrefsValue("rrd.dataDumpDays", buf);
      if(snprintf(buf, sizeof(buf), "%d", dumpMonths) < 0)
        BufferTooShort();
      storePrefsValue("rrd.dataDumpMonths", buf);
      if(snprintf(buf, sizeof(buf), "%d", dumpDomains) < 0)
        BufferTooShort();
      storePrefsValue("rrd.dataDumpDomains", buf);
      if(snprintf(buf, sizeof(buf), "%d", dumpFlows) < 0)
        BufferTooShort();
      storePrefsValue("rrd.dataDumpFlows", buf);
      if(snprintf(buf, sizeof(buf), "%d", dumpHosts) < 0)
        BufferTooShort();
      storePrefsValue("rrd.dataDumpHosts", buf);
      if(snprintf(buf, sizeof(buf), "%d", dumpInterfaces) < 0)
        BufferTooShort();
      storePrefsValue("rrd.dataDumpInterfaces", buf);
      if(snprintf(buf, sizeof(buf), "%d", dumpMatrix) < 0)
        BufferTooShort();
      storePrefsValue("rrd.dataDumpMatrix", buf);
      if(snprintf(buf, sizeof(buf), "%d", dumpDetail) < 0)
        BufferTooShort();
      storePrefsValue("rrd.dataDumpDetail", buf);

      if(hostsFilter != NULL) free(hostsFilter);
      if(_hostsFilter == NULL) {
	hostsFilter  = strdup("");
      } else {
	hostsFilter = _hostsFilter;
	_hostsFilter = NULL;
      }
      storePrefsValue("rrd.hostsFilter", hostsFilter);
#ifndef WIN32
      if(snprintf(buf, sizeof(buf), "%d", dumpPermissions) < 0)
        BufferTooShort();
      storePrefsValue("rrd.permissions", buf);
      umask(myGlobals.rrdUmask);
#ifdef RRD_DEBUG
      traceEvent(CONST_TRACE_INFO, "RRD: Mask for new directories set to %04o",
                 myGlobals.rrdDirectoryPermissions);
      traceEvent(CONST_TRACE_INFO, "RRD: Mask for new files set to %04o",
                 myGlobals.rrdUmask);
#endif
#endif
      shownCreate=0;
    }
  }

  if(_hostsFilter != NULL) free(_hostsFilter);

  /* traceEvent(CONST_TRACE_INFO, "RRD: action=%d", action); */

  if(action == FLAG_RRD_ACTION_GRAPH) {
    graphCounter(rrdKey, rrdName, rrdTitle, startTime, endTime, rrdPrefix);
    return;
  } else if(action == FLAG_RRD_ACTION_LIST) {
    listResource(rrdKey, rrdTitle, startTime, endTime);
    return;
  }

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
  printHTMLheader("RRD Preferences", NULL, 0);

  if(active == 1)
    sendString("<p>You must restart the rrd plugin for changes here to take affect.</p>\n");
  else 
    sendString("<p>Changes here will take effect when the plugin is started.</p>\n");
 
  sendString("<center><form action=\"/plugins/rrdPlugin\" method=GET>\n"
             "<TABLE BORDER=1 "TABLE_DEFAULTS">\n"
             "<TR><TH ALIGN=CENTER "DARK_BG">Item</TH>"
                 "<TH ALIGN=CENTER "DARK_BG">Description and notes</TH></TR>\n"
             "<TR><TH ALIGN=LEFT "DARK_BG">Dump Interval</TH><TD>"
	     "<INPUT NAME=interval SIZE=5 VALUE=");
  if(snprintf(buf, sizeof(buf), "%d", (int)dumpInterval) < 0)
    BufferTooShort();
  sendString(buf);
  sendString("> seconds<br>Specifies how often data is stored permanently.</TD></tr>\n");

  sendString("<TR><TH ALIGN=LEFT "DARK_BG">Dump Hours</TH><TD>"
	     "<INPUT NAME=hours SIZE=5 VALUE=");
  if(snprintf(buf, sizeof(buf), "%d", (int)dumpHours) < 0)
    BufferTooShort();
  sendString(buf);
  sendString("><br>Specifies how many hours of 'interval' data is stored permanently.</TD></tr>\n");

  sendString("<TR><TH ALIGN=LEFT "DARK_BG">Dump Days</TH><TD>"
	     "<INPUT NAME=days SIZE=5 VALUE=");
  if(snprintf(buf, sizeof(buf), "%d", (int)dumpDays) < 0)
    BufferTooShort();
  sendString(buf);
  sendString("><br>Specifies how many days of hourly data is stored permanently.</TD></tr>\n");
  sendString("<TR><TH ALIGN=LEFT "DARK_BG">Dump Months</TH><TD>"
	     "<INPUT NAME=months SIZE=5 VALUE=");
  if(snprintf(buf, sizeof(buf), "%d", (int)dumpMonths) < 0)
    BufferTooShort();
  sendString(buf);
  sendString("><br>Specifies how many months of daily data is stored permanently.</TD></tr>\n");

  sendString("<TR><TD ALIGN=CENTER COLSPAN=2><B>WARNING:</B>&nbsp;"
	     "Changes to the above values will ONLY affect NEW rrds</TD></TR>");

  sendString("<TR><TH ALIGN=LEFT "DARK_BG">Data to Dump</TH><TD>");

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpDomains VALUE=1 %s> Domains<br>\n",
	      dumpDomains ? "CHECKED" : "" ) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpFlows VALUE=1 %s> Flows<br>\n",
	      dumpFlows ? "CHECKED" : "" ) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpHosts VALUE=1 %s> Hosts<br>\n",
	      dumpHosts ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpInterfaces VALUE=1 %s> Interfaces<br>\n",
	      dumpInterfaces ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=checkbox NAME=dumpMatrix VALUE=1 %s> Matrix<br>\n",
	      dumpMatrix ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);

  sendString("</TD></tr>\n");

  if(dumpHosts) {
    sendString("<TR><TH ALIGN=LEFT "DARK_BG">Hosts Filter</TH><TD>"
	       "<INPUT NAME=hostsFilter VALUE=\"");

    sendString(hostsFilter);

    sendString("\" SIZE=80><br>A list of networks [e.g. 172.22.0.0/255.255.0.0,192.168.5.0/255.255.255.0]<br>"
	       "separated by commas to which hosts that will be<br>"
	       "saved must belong to. An empty list means that all the hosts will "
	       "be stored on disk</TD></tr>\n");
  }

  sendString("<TR><TH ALIGN=LEFT "DARK_BG">RRD Detail</TH><TD>");
  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=radio NAME=dumpDetail VALUE=%d %s>Low\n",
	      FLAG_RRD_DETAIL_LOW, (dumpDetail == FLAG_RRD_DETAIL_LOW) ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=radio NAME=dumpDetail VALUE=%d %s>Medium\n",
	      FLAG_RRD_DETAIL_MEDIUM, (dumpDetail == FLAG_RRD_DETAIL_MEDIUM) ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=radio NAME=dumpDetail VALUE=%d %s>Full\n",
	      FLAG_RRD_DETAIL_HIGH, (dumpDetail == FLAG_RRD_DETAIL_HIGH) ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);
  sendString("</TD></TR>\n");

  sendString("<TR><TH ALIGN=LEFT "DARK_BG">RRD Files Path</TH><TD>"
             "<INPUT NAME=rrdPath SIZE=50 VALUE=\"");
  sendString(myGlobals.rrdPath);
  sendString("\">");
  sendString("<br>NOTE: The rrd files will be in a subdirectory structure, e.g.\n");
  if(snprintf(buf, sizeof(buf),
#ifdef WIN32
	       "%s\\interfaces\\interface-name\\12\\239\\98\\199\\xxxxx.rrd ",
#else
	       "%s/interfaces/interface-name/12/239/98/199/xxxxx.rrd ",
#endif
               myGlobals.rrdPath) < 0)
    BufferTooShort();
  sendString(buf);
  sendString("to limit the number of files per subdirectory.");
  sendString("</TD></tr>\n");

  sendString("<TR><TH ALIGN=LEFT "DARK_BG">RRD Updates</TH><TD>");
  if(snprintf(buf, sizeof(buf), "%lu RRD files updated</TD></TR>\n", (unsigned long)numTotalRRDs) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("<TR><TH ALIGN=LEFT "DARK_BG">RRD Update Errors</TH><TD>");
  if(snprintf(buf, sizeof(buf), "%lu RRD update errors</TD></TR>\n", (unsigned long)numRRDerrors) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("<TR><TH ALIGN=LEFT "DARK_BG">RRD Graphic Requests</TH><TD>");
  if(snprintf(buf, sizeof(buf), "%lu RRD graphics requested</TD></TR>\n",
	      (unsigned long)rrdGraphicRequests) < 0)
    BufferTooShort();
  sendString(buf);

#ifndef WIN32
  sendString("<TR><TH ALIGN=LEFT "DARK_BG">File/Directory Permissions</TH><TD>");
  sendString("<ul>\n");
  if(snprintf(buf, sizeof(buf), "<li><INPUT TYPE=radio NAME=permissions VALUE=%d %s>Private - ",
              CONST_RRD_PERMISSIONS_PRIVATE,
              (dumpPermissions == CONST_RRD_PERMISSIONS_PRIVATE) ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);
  sendString("means that ONLY the ntop userid will be able to view the files</li>\n");

  if(snprintf(buf, sizeof(buf), "<li><INPUT TYPE=radio NAME=permissions VALUE=%d %s>Group - ",
              CONST_RRD_PERMISSIONS_GROUP,
              (dumpPermissions == CONST_RRD_PERMISSIONS_GROUP) ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);
  sendString("means that all users in the same group as the ntop userid will be able to view the rrd files.\n");
  sendString("<br><i>(this is a bad choice if ntop's group is 'nobody' along with many other service ids)</i></li>\n");

  if(snprintf(buf, sizeof(buf), "<li><INPUT TYPE=radio NAME=permissions VALUE=%d %s>Everyone - ",
              CONST_RRD_PERMISSIONS_EVERYONE,
              (dumpPermissions == CONST_RRD_PERMISSIONS_EVERYONE) ? "CHECKED" : "") < 0)
    BufferTooShort();
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
             "</ul>\n</TD></TR>\n");
#endif

  sendString("<tr><td colspan=\"2\" align=\"center\">"
             "<input type=submit value=\"Save Preferences\"></td></tr></table>\n"
             "</form>\n<p></center>\n");


  printPluginTrailer(NULL,
                     "<a href=\"http://www.rrdtool.org/\" title=\"rrd home page\">RRDtool</a> "
                     "was created by "
                     "<a href=\"http://ee-staff.ethz.ch/~oetiker/\" title=\"Tobi's home page\">"
                     "Tobi Oetiker</a>");
 
  printHTMLtrailer();
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

#ifdef HAVE_BACKTRACE
  /* Don't double fault... */
  /* signal(signo, SIG_DFL); */

  /* Grab the backtrace before we do much else... */
  size = backtrace(array, 20);
  strings = (char**)backtrace_symbols(array, size);

  traceEvent(CONST_TRACE_FATALERROR, "RRD: BACKTRACE:     backtrace is:");
  if(size < 2) {
    traceEvent(CONST_TRACE_FATALERROR, "RRD: BACKTRACE:         **unavailable!");
  } else {
    /* Ignore the 0th entry, that's our cleanup() */
    for (i=1; i<size; i++) {
      traceEvent(CONST_TRACE_FATALERROR, "RRD: BACKTRACE:          %2d. %s", i, strings[i]);
    }
  }
#endif /* HAVE_BACKTRACE */

  exit(0);
}
#endif /* MAKE_WITH_RRDSIGTRAP */

/* ****************************** */

static void* rrdMainLoop(void* notUsed _UNUSED_) {
  char value[512 /* leave it big for hosts filter */];
  u_int32_t networks[32][3];
  u_short numLocalNets;
  int sleep_tm, devIdx, idx;
  char rrdPath[512];
  int cycleCount=0;
  char *adjHostName;
  ProtocolsList *protoList;

#ifdef CFG_MULTITHREADED
  traceEvent(CONST_TRACE_INFO, "THREADMGMT: rrd thread (%ld) started", rrdThread);
#else
#ifdef RRD_DEBUG
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: rrdMainLoop()");
#endif
#endif

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

  if(initialized == 0)
    commonRRDinit();

  /* Initialize the "end" of the dummy interval just far enough back in time
     so that it expires once everything is up and running. */
  end_tm = myGlobals.actTime - dumpInterval + 15;

  /* Show we're running */
  active = 1;

  for(;myGlobals.capturePackets != FLAG_NTOPSTATE_TERM;) {
    char *hostKey;
    int i, j;

#if RRD_DEBUG >= 1
    char endTime[32];
#endif

    cycleCount++;

    do {
      end_tm += dumpInterval;
      sleep_tm = end_tm - (start_tm = time(NULL));
    } while (sleep_tm < 0);

#if RRD_DEBUG >= 1
    {
      struct tm workT;
      strftime(endTime, sizeof(endTime), CONST_LOCALE_TIMESPEC, localtime_r(&end_tm, &workT));
      traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: Sleeping for %d seconds (interval %d, end at %s)",
		 sleep_tm,
		 dumpInterval,
		 endTime);
    }
#endif

    HEARTBEAT(0, "rrdMainLoop(), sleep(%d)...", sleep_tm);
    sleep(sleep_tm);
    HEARTBEAT(0, "rrdMainLoop(), sleep(%d)...woke", sleep_tm);
    if(myGlobals.capturePackets != FLAG_NTOPSTATE_RUN) return(NULL);

    numRuns++;
    rrdTime =  time(NULL);

    /* ****************************************************** */

    numLocalNets = 0;
    /* Avoids strtok to blanks into hostsFilter */
    if(snprintf(rrdPath, sizeof(rrdPath), "%s", hostsFilter) < 0)
      BufferTooShort();
    handleAddressLists(rrdPath, networks, &numLocalNets, value, sizeof(value), CONST_HANDLEADDRESSLISTS_RRD);

    /* ****************************************************** */

    if(dumpDomains) {

      DomainStats **stats, *tmpStats, *statsEntry;
      u_int maxHosts, len = 0;
      Counter totBytesSent = 0;
      Counter totBytesRcvd = 0;
      HostTraffic *el;
      u_short keyValue=0;

      for(devIdx=0; devIdx<myGlobals.numDevices; devIdx++) {
        u_int numEntries = 0;

	// save this as it may change
	maxHosts = myGlobals.device[devIdx].hostsno;
	len = sizeof(DomainStats)*maxHosts;
	tmpStats = (DomainStats*)malloc(len);
	memset(tmpStats, 0, len);

	len = sizeof(DomainStats**)*maxHosts;
	stats = (DomainStats**)malloc(len);
	memset(stats, 0, len);

	// walk through all hosts, getting their domain names and counting stats
	for (el = getFirstHost(devIdx);
	  el != NULL; el = getNextHost(devIdx, el)) {

	    fillDomainName(el);

	    // if we didn't get a domain name, bail out
	    if ((el->dnsDomainValue == NULL)
	       || (el->dnsDomainValue[0] == '\0')
	       || (el->ip2ccValue == NULL)
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

	    // if we just start counting for this domain...
	    if(stats[keyValue] != NULL)
	      statsEntry = stats[keyValue];
	    else {
	      statsEntry = &tmpStats[numEntries++];
	      memset(statsEntry, 0, sizeof(DomainStats));
	      statsEntry->domainHost = el;
	      stats[keyValue] = statsEntry;
#if RRD_DEBUG >= 2
	      traceEvent(CONST_TRACE_INFO, "RRD_DEBUG [%d] %s/%s", numEntries, el->dnsDomainValue, el->ip2ccValue);
#endif
	    }

	    // count this host's stats in the domain stats
	    totBytesSent += el->bytesSent.value;
	    statsEntry->bytesSent.value += el->bytesSent.value;
	    statsEntry->bytesRcvd.value += el->bytesRcvd.value;
	    totBytesRcvd          += el->bytesRcvd.value;
	    statsEntry->tcpSent.value   += el->tcpSentLoc.value + el->tcpSentRem.value;
	    statsEntry->udpSent.value   += el->udpSentLoc.value + el->udpSentRem.value;
	    statsEntry->icmpSent.value  += el->icmpSent.value;
	    statsEntry->icmp6Sent.value  += el->icmp6Sent.value;
	    statsEntry->tcpRcvd.value   += el->tcpRcvdLoc.value + el->tcpRcvdFromRem.value;
	    statsEntry->udpRcvd.value   += el->udpRcvdLoc.value + el->udpRcvdFromRem.value;
	    statsEntry->icmpRcvd.value  += el->icmpRcvd.value;
	    statsEntry->icmp6Rcvd.value  += el->icmp6Rcvd.value;

	    if(numEntries >= maxHosts) break;
	}

	// if we didn't find a single domain, continue with the next interface
	if (numEntries == 0) {
	    free(tmpStats); free(stats);
	    continue;
	}

	// insert all domain data for this interface into the RRDs
	for (idx=0; idx < numEntries; idx++) {
	    statsEntry = &tmpStats[idx];

	    if(snprintf(rrdPath, sizeof(rrdPath), "%s/interfaces/%s/domains/%s/",
		myGlobals.rrdPath, myGlobals.device[devIdx].humanFriendlyName,
		statsEntry->domainHost->dnsDomainValue) < 0)
              BufferTooShort();
	    mkdir_p(rrdPath);

#if RRD_DEBUG >= 2
	    traceEvent(CONST_TRACE_INFO, "RRD: Updating %s", rrdPath);
#endif
	    updateCounter(rrdPath, "bytesSent", statsEntry->bytesSent.value);
	    updateCounter(rrdPath, "bytesRcvd", statsEntry->bytesRcvd.value);

	    updateCounter(rrdPath, "tcpSent", statsEntry->tcpSent.value);
	    updateCounter(rrdPath, "udpSent", statsEntry->udpSent.value);
	    updateCounter(rrdPath, "icmpSent", statsEntry->icmpSent.value);
	    updateCounter(rrdPath, "icmp6Sent", statsEntry->icmp6Sent.value);

	    updateCounter(rrdPath, "tcpRcvd", statsEntry->tcpRcvd.value);
	    updateCounter(rrdPath, "udpRcvd", statsEntry->udpRcvd.value);
	    updateCounter(rrdPath, "icmpRcvd", statsEntry->icmpRcvd.value);
	    updateCounter(rrdPath, "icmp6Rcvd", statsEntry->icmp6Rcvd.value);
	}

	free(tmpStats); free(stats);
      }
    }

    /* ****************************************************** */

    if(dumpHosts) {
      for(devIdx=0; devIdx<myGlobals.numDevices; devIdx++) {
	for(i=1; i<myGlobals.device[devIdx].actualHashSize; i++) {
	  HostTraffic *el = myGlobals.device[devIdx].hash_hostTraffic[i];

	  while(el != NULL) {
	    if((el == myGlobals.otherHostEntry) || (el == myGlobals.broadcastEntry)
	       || broadcastHost(el) || (myGlobals.trackOnlyLocalHosts && (!subnetPseudoLocalHost(el)))) {
	      el = el->next;
	      continue;
	    }

#ifdef CFG_MULTITHREADED
	    accessMutex(&myGlobals.hostsHashMutex, "rrdDumpHosts");
#endif

	    if((el->bytesSent.value > 0) || (el->bytesRcvd.value > 0)) {
	      if(el->hostNumIpAddress[0] != '\0') {
		hostKey = el->hostNumIpAddress;

		if((numLocalNets > 0)
		   && (el->hostIpAddress.hostFamily == AF_INET) /* IPv4 ONLY <-- FIX */
		   && (!__pseudoLocalAddress(&el->hostIpAddress.Ip4Address, networks, numLocalNets))) {
	          el = el->next;
#ifdef CFG_MULTITHREADED
                  releaseMutex(&myGlobals.hostsHashMutex);
#endif
                  continue;
                } 

		if((!myGlobals.dontTrustMACaddr) 
		   && subnetPseudoLocalHost(el)
		   && (el->ethAddressString[0] != '\0')) /*
							   NOTE:
							   MAC address is empty even
							   for local hosts if this host has
							   been learnt on a virtual interface
							   such as the NetFlow interface
							 */
		    hostKey = el->ethAddressString;
	      } else {
		/* For the time being do not save IP-less hosts */
		el = el->next;

#ifdef CFG_MULTITHREADED
                releaseMutex(&myGlobals.hostsHashMutex);
#endif
		continue;
	      }

	      adjHostName = dotToSlash(hostKey);

	      if(snprintf(rrdPath, sizeof(rrdPath), "%s/interfaces/%s/hosts/%s/",
		       myGlobals.rrdPath, myGlobals.device[devIdx].humanFriendlyName,
		       adjHostName) < 0)
                BufferTooShort();
	      mkdir_p(rrdPath);
	      
#if RRD_DEBUG >= 2
	      traceEvent(CONST_TRACE_INFO, "RRD: Updating %s [%s/%s]", 
			 hostKey, el->hostNumIpAddress, el->ethAddressString);
#endif

	      updateTrafficCounter(rrdPath, "pktSent", &el->pktSent);
	      updateTrafficCounter(rrdPath, "pktRcvd", &el->pktRcvd);
	      updateTrafficCounter(rrdPath, "bytesSent", &el->bytesSent);
	      updateTrafficCounter(rrdPath, "bytesRcvd", &el->bytesRcvd);

	      if(dumpDetail >= FLAG_RRD_DETAIL_MEDIUM) {
		updateTrafficCounter(rrdPath, "pktDuplicatedAckSent", &el->pktDuplicatedAckSent);
		updateTrafficCounter(rrdPath, "pktDuplicatedAckRcvd", &el->pktDuplicatedAckRcvd);
		updateTrafficCounter(rrdPath, "pktBroadcastSent", &el->pktBroadcastSent);
		updateTrafficCounter(rrdPath, "bytesBroadcastSent", &el->bytesBroadcastSent);
		updateTrafficCounter(rrdPath, "pktMulticastSent", &el->pktMulticastSent);
		updateTrafficCounter(rrdPath, "bytesMulticastSent", &el->bytesMulticastSent);
		updateTrafficCounter(rrdPath, "pktMulticastRcvd", &el->pktMulticastRcvd);
		updateTrafficCounter(rrdPath, "bytesMulticastRcvd", &el->bytesMulticastRcvd);

		updateTrafficCounter(rrdPath, "bytesSentLoc", &el->bytesSentLoc);
		updateTrafficCounter(rrdPath, "bytesSentRem", &el->bytesSentRem);
		updateTrafficCounter(rrdPath, "bytesRcvdLoc", &el->bytesRcvdLoc);
		updateTrafficCounter(rrdPath, "bytesRcvdFromRem", &el->bytesRcvdFromRem);
		updateTrafficCounter(rrdPath, "ipBytesSent", &el->ipBytesSent);
		updateTrafficCounter(rrdPath, "ipBytesRcvd", &el->ipBytesRcvd);
		updateTrafficCounter(rrdPath, "tcpSentLoc", &el->tcpSentLoc);
		updateTrafficCounter(rrdPath, "tcpSentRem", &el->tcpSentRem);
		updateTrafficCounter(rrdPath, "udpSentLoc", &el->udpSentLoc);
		updateTrafficCounter(rrdPath, "udpSentRem", &el->udpSentRem);
		updateTrafficCounter(rrdPath, "icmpSent", &el->icmpSent);
		updateTrafficCounter(rrdPath, "tcpRcvdLoc", &el->tcpRcvdLoc);
		updateTrafficCounter(rrdPath, "tcpRcvdFromRem", &el->tcpRcvdFromRem);
		updateTrafficCounter(rrdPath, "udpRcvdLoc", &el->udpRcvdLoc);
		updateTrafficCounter(rrdPath, "udpRcvdFromRem", &el->udpRcvdFromRem);
		updateTrafficCounter(rrdPath, "icmpRcvd", &el->icmpRcvd);
		updateTrafficCounter(rrdPath, "tcpFragmentsSent", &el->tcpFragmentsSent);
		updateTrafficCounter(rrdPath, "tcpFragmentsRcvd", &el->tcpFragmentsRcvd);
		updateTrafficCounter(rrdPath, "udpFragmentsSent", &el->udpFragmentsSent);
		updateTrafficCounter(rrdPath, "udpFragmentsRcvd", &el->udpFragmentsRcvd);
		updateTrafficCounter(rrdPath, "icmpFragmentsSent", &el->icmpFragmentsSent);
		updateTrafficCounter(rrdPath, "icmpFragmentsRcvd", &el->icmpFragmentsRcvd);
		updateTrafficCounter(rrdPath, "stpSent", &el->stpSent);
		updateTrafficCounter(rrdPath, "stpRcvd", &el->stpRcvd);
		updateTrafficCounter(rrdPath, "ipxSent", &el->ipxSent);
		updateTrafficCounter(rrdPath, "ipxRcvd", &el->ipxRcvd);
		updateTrafficCounter(rrdPath, "osiSent", &el->osiSent);
		updateTrafficCounter(rrdPath, "osiRcvd", &el->osiRcvd);
		updateTrafficCounter(rrdPath, "dlcSent", &el->dlcSent);
		updateTrafficCounter(rrdPath, "dlcRcvd", &el->dlcRcvd);
		updateTrafficCounter(rrdPath, "arp_rarpSent", &el->arp_rarpSent);
		updateTrafficCounter(rrdPath, "arp_rarpRcvd", &el->arp_rarpRcvd);
		updateTrafficCounter(rrdPath, "arpReqPktsSent", &el->arpReqPktsSent);
		updateTrafficCounter(rrdPath, "arpReplyPktsSent", &el->arpReplyPktsSent);
		updateTrafficCounter(rrdPath, "arpReplyPktsRcvd", &el->arpReplyPktsRcvd);
		updateTrafficCounter(rrdPath, "decnetSent", &el->decnetSent);
		updateTrafficCounter(rrdPath, "decnetRcvd", &el->decnetRcvd);
		updateTrafficCounter(rrdPath, "appletalkSent", &el->appletalkSent);
		updateTrafficCounter(rrdPath, "appletalkRcvd", &el->appletalkRcvd);
		updateTrafficCounter(rrdPath, "netbiosSent", &el->netbiosSent);
		updateTrafficCounter(rrdPath, "netbiosRcvd", &el->netbiosRcvd);
		updateTrafficCounter(rrdPath, "ipv6Sent", &el->ipv6Sent);
		updateTrafficCounter(rrdPath, "ipv6Rcvd", &el->ipv6Rcvd);
		updateTrafficCounter(rrdPath, "otherSent", &el->otherSent);
		updateTrafficCounter(rrdPath, "otherRcvd", &el->otherRcvd);

		protoList = myGlobals.ipProtosList, idx=0;
		while(protoList != NULL) {
		  char buf[64];

		  if(snprintf(buf, sizeof(buf), "%sSent", protoList->protocolName) < 0) BufferTooShort();
		  updateTrafficCounter(rrdPath, buf, &el->ipProtosList[idx].sent);
		  if(snprintf(buf, sizeof(buf), "%sRcvd", protoList->protocolName) < 0) BufferTooShort();
		  updateTrafficCounter(rrdPath, buf, &el->ipProtosList[idx].rcvd);
		  idx++, protoList = protoList->next;
		}		
	      }

	      if(dumpDetail == FLAG_RRD_DETAIL_HIGH) {
		updateCounter(rrdPath, "totContactedSentPeers", el->totContactedSentPeers);
		updateCounter(rrdPath, "totContactedRcvdPeers", el->totContactedRcvdPeers);

		if((hostKey == el->hostNumIpAddress) && el->protoIPTrafficInfos) {
#ifdef RRD_DEBUG
		  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: Updating host %s", hostKey);
#endif

		  if(snprintf(rrdPath, sizeof(rrdPath), "%s/interfaces/%s/hosts/%s/IP_",
			   myGlobals.rrdPath,
			   myGlobals.device[devIdx].humanFriendlyName,
			   adjHostName
			   ) < 0)
                    BufferTooShort();

		  for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {
		    char key[128];
		    if(snprintf(key, sizeof(key), "%sSentBytes",
                                myGlobals.protoIPTrafficInfos[j]) < 0)
                      BufferTooShort();
		    updateCounter(rrdPath, key, el->protoIPTrafficInfos[j].sentLoc.value+
				  el->protoIPTrafficInfos[j].sentRem.value);

		    if(snprintf(key, sizeof(key), "%sRcvdBytes",
                                myGlobals.protoIPTrafficInfos[j]) < 0)
                      BufferTooShort();
		    updateCounter(rrdPath, key, el->protoIPTrafficInfos[j].rcvdLoc.value+
				  el->protoIPTrafficInfos[j].rcvdFromRem.value);
		  }
		}
	      }

              if(adjHostName != NULL)
                free(adjHostName);
	    }

#ifdef CFG_MULTITHREADED
	    releaseMutex(&myGlobals.hostsHashMutex);
#endif
#ifdef MAKE_WITH_SCHED_YIELD
	    sched_yield(); /* Allow other threads to run */
#endif
	    el = el->next;
	  }
	}
      } /* for(devIdx...) */
    }

    /* ************************** */

    if(dumpFlows) {
      FlowFilterList *list = myGlobals.flowsList;

      while(list != NULL) {
	if(list->pluginStatus.activePlugin) {
	  if(snprintf(rrdPath, sizeof(rrdPath), "%s/flows/%s/",
                      myGlobals.rrdPath, list->flowName) < 0)
            BufferTooShort();
	  mkdir_p(rrdPath);

	  updateCounter(rrdPath, "packets", list->packets.value);
	  updateCounter(rrdPath, "bytes",   list->bytes.value);
	}

	list = list->next;
      }
    }

    /* ************************** */

    if(dumpInterfaces) {
      for(devIdx=0; devIdx<myGlobals.numDevices; devIdx++) {

	if(myGlobals.device[devIdx].virtualDevice) continue;

	if(snprintf(rrdPath, sizeof(rrdPath), "%s/interfaces/%s/", myGlobals.rrdPath,
                    myGlobals.device[devIdx].humanFriendlyName) < 0)
            BufferTooShort();
	mkdir_p(rrdPath);

	updateCounter(rrdPath, "ethernetPkts",  myGlobals.device[devIdx].ethernetPkts.value);
	updateCounter(rrdPath, "broadcastPkts", myGlobals.device[devIdx].broadcastPkts.value);
	updateCounter(rrdPath, "multicastPkts", myGlobals.device[devIdx].multicastPkts.value);
	updateCounter(rrdPath, "ethernetBytes", myGlobals.device[devIdx].ethernetBytes.value);
	updateGauge(rrdPath,   "knownHostsNum", myGlobals.device[devIdx].hostsno);
	updateGauge(rrdPath,   "activeHostSendersNum",  numActiveSenders(devIdx));
	updateCounter(rrdPath, "ipBytes",       myGlobals.device[devIdx].ipBytes.value);

	if(dumpDetail >= FLAG_RRD_DETAIL_MEDIUM) {
	  updateCounter(rrdPath, "droppedPkts", myGlobals.device[devIdx].droppedPkts.value);
	  updateCounter(rrdPath, "fragmentedIpBytes", myGlobals.device[devIdx].fragmentedIpBytes.value);
	  updateCounter(rrdPath, "tcpBytes", myGlobals.device[devIdx].tcpBytes.value);
	  updateCounter(rrdPath, "udpBytes", myGlobals.device[devIdx].udpBytes.value);
	  updateCounter(rrdPath, "otherIpBytes", myGlobals.device[devIdx].otherIpBytes.value);
	  updateCounter(rrdPath, "icmpBytes", myGlobals.device[devIdx].icmpBytes.value);
	  updateCounter(rrdPath, "dlcBytes", myGlobals.device[devIdx].dlcBytes.value);
	  updateCounter(rrdPath, "ipxBytes", myGlobals.device[devIdx].ipxBytes.value);
	  updateCounter(rrdPath, "stpBytes", myGlobals.device[devIdx].stpBytes.value);
	  updateCounter(rrdPath, "decnetBytes", myGlobals.device[devIdx].decnetBytes.value);
	  updateCounter(rrdPath, "netbiosBytes", myGlobals.device[devIdx].netbiosBytes.value);
	  updateCounter(rrdPath, "arpRarpBytes", myGlobals.device[devIdx].arpRarpBytes.value);
	  updateCounter(rrdPath, "atalkBytes", myGlobals.device[devIdx].atalkBytes.value);
	  updateCounter(rrdPath, "egpBytes", myGlobals.device[devIdx].egpBytes.value);
	  updateCounter(rrdPath, "osiBytes", myGlobals.device[devIdx].osiBytes.value);
	  updateCounter(rrdPath, "ipv6Bytes", myGlobals.device[devIdx].ipv6Bytes.value);
	  updateCounter(rrdPath, "otherBytes", myGlobals.device[devIdx].otherBytes.value);
	  updateCounter(rrdPath, "upTo64Pkts", myGlobals.device[devIdx].rcvdPktStats.upTo64.value);
	  updateCounter(rrdPath, "upTo128Pkts", myGlobals.device[devIdx].rcvdPktStats.upTo128.value);
	  updateCounter(rrdPath, "upTo256Pkts", myGlobals.device[devIdx].rcvdPktStats.upTo256.value);
	  updateCounter(rrdPath, "upTo512Pkts", myGlobals.device[devIdx].rcvdPktStats.upTo512.value);
	  updateCounter(rrdPath, "upTo1024Pkts", myGlobals.device[devIdx].rcvdPktStats.upTo1024.value);
	  updateCounter(rrdPath, "upTo1518Pkts", myGlobals.device[devIdx].rcvdPktStats.upTo1518.value);
	  updateCounter(rrdPath, "badChecksumPkts", myGlobals.device[devIdx].rcvdPktStats.badChecksum.value);
	  updateCounter(rrdPath, "tooLongPkts", myGlobals.device[devIdx].rcvdPktStats.tooLong.value);

	  protoList = myGlobals.ipProtosList, idx=0;
	  while(protoList != NULL) {
	    updateCounter(rrdPath, protoList->protocolName, myGlobals.device[devIdx].ipProtosList[idx].value);	    
	    idx++, protoList = protoList->next;
	  }
	}

	if(dumpDetail == FLAG_RRD_DETAIL_HIGH) {
	  if(myGlobals.device[devIdx].ipProtoStats != NULL) {
	    if(snprintf(rrdPath, sizeof(rrdPath), "%s/interfaces/%s/IP_",
                       myGlobals.rrdPath,  myGlobals.device[devIdx].humanFriendlyName) < 0)
              BufferTooShort();

	    for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {
	      TrafficCounter ctr;
	      char tmpStr[128];

	      ctr.value =
		myGlobals.device[devIdx].ipProtoStats[j].local.value+
		myGlobals.device[devIdx].ipProtoStats[j].local2remote.value+
		myGlobals.device[devIdx].ipProtoStats[j].remote2local.value+
		myGlobals.device[devIdx].ipProtoStats[j].remote.value;

	      if(snprintf(tmpStr, sizeof(tmpStr), "%sBytes", myGlobals.protoIPTrafficInfos[j]) < 0)
                BufferTooShort();
	      updateCounter(rrdPath, tmpStr, ctr.value);
	    }
	  }
	}
      }
    }

    /* ************************** */

    if(dumpMatrix) {
      int k;

      for(k=0; k<myGlobals.numDevices; k++)
	for(i=1; i<myGlobals.device[k].numHosts; i++)
	  for(j=1; j<myGlobals.device[k].numHosts; j++) {
	    if(i != j) {
	      idx = i*myGlobals.device[k].numHosts+j;

	      if(myGlobals.device[k].ipTrafficMatrix == NULL)
		continue;
	      if(myGlobals.device[k].ipTrafficMatrix[idx] == NULL)
		continue;

	      if(myGlobals.device[k].ipTrafficMatrix[idx]->bytesSent.value > 0) {

		if(snprintf(rrdPath, sizeof(rrdPath), "%s/interfaces/%s/matrix/%s/%s/",
                         myGlobals.rrdPath,
			 myGlobals.device[k].humanFriendlyName,
			 myGlobals.device[k].ipTrafficMatrixHosts[i]->hostNumIpAddress,
			 myGlobals.device[k].ipTrafficMatrixHosts[j]->hostNumIpAddress) < 0)
                  BufferTooShort();
		mkdir_p(rrdPath);

		updateCounter(rrdPath, "pkts",
			      myGlobals.device[k].ipTrafficMatrix[idx]->pktsSent.value);

		updateCounter(rrdPath, "bytes",
			      myGlobals.device[k].ipTrafficMatrix[idx]->bytesSent.value);
	      }
	    }
	  }
    }

#ifdef RRD_DEBUG
    traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: %lu RRDs updated (%lu total updates)",
	       (unsigned long)(numTotalRRDs-numRRDs), (unsigned long)numTotalRRDs);
#endif

    /*
     * If it's FLAG_NTOPSTATE_STOPCAP, and we're still running, then this
     * is the 1st pass.  We just updated our data to save the counts, now
     * we kill the thread...
     */
    if(myGlobals.capturePackets == FLAG_NTOPSTATE_STOPCAP) {
      traceEvent(CONST_TRACE_WARNING, "RRD: STOPCAP, ending rrd thread");
      break;
    }
  }

#ifdef CFG_MULTITHREADED
  traceEvent(CONST_TRACE_WARNING, "THREADMGMT: rrd thread (%ld) terminated", rrdThread);
#else
#ifdef RRD_DEBUG
  traceEvent(CONST_TRACE_INFO, "RRD_DEBUG: rrdMainLoop() terminated.");
#endif
#endif

  return(0);
}

/* ****************************** */

static int initRRDfunct(void) {
  char dname[256];
  int i;

  traceEvent(CONST_TRACE_INFO, "RRD: Welcome to the RRD plugin");

#ifdef CFG_MULTITHREADED
  createMutex(&rrdMutex);
#endif

  setPluginStatus(NULL);

  if(myGlobals.rrdPath == NULL)
    commonRRDinit();

#ifndef CFG_MULTITHREADED
  /* This plugin works only with threads */
  setPluginStatus("Disabled - requires POSIX thread support.");
  return(-1);
#endif

  if(snprintf(dname, sizeof(dname), "%s", myGlobals.rrdPath) < 0)
    BufferTooShort();
  if(_mkdir(dname) == -1) {
    if(errno != EEXIST) {
      traceEvent(CONST_TRACE_ERROR, "RRD: Disabled - unable to create base directory (err %d, %s)", 
		 errno, dname);
      setPluginStatus("Disabled - unable to create rrd base directory.");
      /* Return w/o creating the rrd thread ... disabled */
      return(-1);
    }
  } else {
    traceEvent(CONST_TRACE_INFO, "RRD: Created base directory (%s)", dname);
  }

  for (i=0; i<sizeof(rrd_subdirs)/sizeof(rrd_subdirs[0]); i++) {

    if(snprintf(dname, sizeof(dname), "%s/%s", myGlobals.rrdPath, rrd_subdirs[i]) < 0)
      BufferTooShort();
    if(_mkdir(dname) == -1) {
      if(errno != EEXIST) {
	traceEvent(CONST_TRACE_ERROR, "RRD: Disabled - unable to create directory (err %d, %s)", errno, dname);
        setPluginStatus("Disabled - unable to create rrd subdirectory.");
	/* Return w/o creating the rrd thread ... disabled */
	return(-1);
      }
    } else {
      traceEvent(CONST_TRACE_INFO, "RRD: Created directory (%s)", dname);
    }
  }

#ifdef CFG_MULTITHREADED
  createThread(&rrdThread, rrdMainLoop, NULL);
  traceEvent(CONST_TRACE_INFO, "RRD: Started thread (%ld) for data collection.", rrdThread);
#endif

  fflush(stdout);
  numTotalRRDs = 0;
  return(0);
}

/* ****************************** */

static void termRRDfunct(void) {
#ifdef CFG_MULTITHREADED
  int count=0, rc;

  /* Hold until rrd is finished or 15s elapsed... */
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "RRD: Locking mutex (may block for a little while)");

  while ((count++ < 5) && (tryLockMutex(&rrdMutex, "Termination") != 0)) {
      sleep(3);
  }
  if(rrdMutex.isLocked) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "RRD: Locked mutex, continuing shutdown");
  } else {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "RRD: Unable to lock mutex, continuing shutdown anyway");
  }

  if(active) {
    rc = killThread(&rrdThread);
    if (rc == 0)
      traceEvent(CONST_TRACE_INFO, "RRD: killThread() succeeded");
    else 
      traceEvent(CONST_TRACE_ERROR, "RRD: killThread() failed, rc %s(%d)", strerror(rc), rc);
  }
#endif

  if(hostsFilter != NULL) free(hostsFilter);
  if(myGlobals.rrdPath != NULL) free(myGlobals.rrdPath);

#ifdef CFG_MULTITHREADED
  deleteMutex(&rrdMutex);
#endif

  traceEvent(CONST_TRACE_INFO, "RRD: Thanks for using the rrdPlugin");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "RRD: Done");
  fflush(stdout);

  initialized = 0; /* Reinit on restart */
}

/* ****************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGIN
PluginInfo* rrdPluginEntryFctn(void)
#else
     PluginInfo* PluginEntryFctn(void)
#endif
{
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "RRD: Welcome to %s. (C) 2002-04 by Luca Deri.",
	     rrdPluginInfo->pluginName);

  return(rrdPluginInfo);
}

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
