/*
 *  Copyright (C) 2002 Luca Deri <deri@ntop.org>
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

       Plugin History

       1.0     Initial release
       1.0.1   Added Flows
       1.0.2   Added Matrix
       1.0.3
       2.0     Rolled major version due to new interface parameter.
       2.1     Added tests/creates for rrd and subdirectories, fixed timer,
               --reuse-rrd-graphics etc.

   Remember, there are TWO paths into this - one is through the main loop,
   if the plugin is active, the other is through the http function if the 
   plugin is NOT active.  So initialize stuff in BOTH places!
*/

static const char *rrd_subdirs[] =
  { "graphics",    /* graphics sub directory - must be first */
    "flows",
    "hosts",
    "interfaces",
    "matrix"
  };

#include "ntop.h"
#include "globals-report.h"

#ifdef WIN32
#define HAVE_RRD
#endif

#ifdef HAVE_RRD

/* #define RRD_DEBUG 4 */

#include <dirent.h>

#ifdef WIN32
int optind, opterr;
#endif

#define DETAIL_LOW     0
#define DETAIL_MEDIUM  1
#define DETAIL_HIGH    2

static unsigned short initialized = 0, active = 0, dumpInterval, dumpDetail;
static char *hostsFilter;
static Counter numTotalRRDs = 0;
static unsigned long numRuns = 0;

static time_t start_tm, end_tm;

#ifdef MULTITHREADED
pthread_t rrdThread;
#endif

static u_short dumpFlows, dumpHosts, dumpInterfaces, dumpMatrix;

static Counter rrdGraphicRequests=0, rrdGraphicReuse=0;

static DIR * workDir;
static struct dirent *workDirent;

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

/* ****************************************************** */

#include <rrd.h>

static char **calcpr=NULL;

static void calfree (void) {
  if (calcpr) {
    long i;
    for(i=0;calcpr[i];i++){
      if (calcpr[i]){
	free(calcpr[i]);
      }
    }
    if (calcpr) {
      free(calcpr);
    }
  }
}


/* ******************************************* */

#ifdef WIN32
void revertSlash(char *str) {
	int i;

	for(i=0; str[i] != '\0'; i++)
		if(str[i] == '/')
			str[i] = '\\';
}
#endif

/* ******************************************* */

#ifdef WIN32
#define _mkdir(a) mkdir(a)
#define SEPARATOR '\\'
#else
#define _mkdir(a) mkdir(a, (mode_t)0700)
#define SEPARATOR '/'
#endif

void mkdir_p(char *path) {
  int i;

#ifdef WIN32
  revertSlash(path);
#endif

  for(i=0; path[i] != '\0'; i++)
    if(path[i] == SEPARATOR) {
      path[i] = '\0';
      _mkdir(path);
#if RRD_DEBUG >= 3
      /* traceEvent(TRACE_INFO, "RRD_DEBUG: mkdir(%s)", path); */
#endif
      path[i] = SEPARATOR;
    }

  _mkdir(path);
#if RRD_DEBUG >= 2
 /* traceEvent(TRACE_INFO, "RRD_DEBUG: mkdir(%s)", path); */
#endif
}

/* ******************************************* */

int sumCounter(char *rrdPath, char *rrdFilePath,
	       char *startTime, char* endTime, Counter *total, float *average) {
  char *argv[16], path[256];
  int argc = 0;
  time_t        start,end;
  unsigned long step, ds_cnt,i;
  rrd_value_t   *data,*datai, _total, _val;
  char          **ds_namv;

  sprintf(path, "%s/%s/%s", myGlobals.rrdPath, rrdPath, rrdFilePath);

#ifdef WIN32
  revertSlash(path);
#endif

  argv[argc++] = "rrd_fecth";
  argv[argc++] = path;
  argv[argc++] = "AVERAGE";
  argv[argc++] = "--start";
  argv[argc++] = startTime;
  argv[argc++] = "--end";
  argv[argc++] = endTime;

#if RRD_DEBUG >= 3
  {
	int x;

	  for (x = 0; x < argc; x++)
		traceEvent(TRACE_INFO, "RRD_DEBUG: argv[%d] = %s", x, argv[x]);
  }
#endif

  optind=0; /* reset gnu getopt */
  opterr=0; /* no error messages */

  if(rrd_fetch(argc, argv, &start, &end, &step, &ds_cnt, &ds_namv, &data) == -1)
    return(-1);

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
  char path[512], url[256];
  DIR* directoryPointer=NULL;
  struct dirent* dp;
  int numEntries = 0;

  sendHTTPHeader(HTTP_TYPE_HTML, 0);

  sprintf(path, "%s/%s", myGlobals.rrdPath, rrdPath);

#ifdef WIN32
  revertSlash(path);
#endif

  directoryPointer = opendir(path);

  if(directoryPointer == NULL) {
    char buf[256];
    snprintf(buf, sizeof(buf), "<I>Unable to read directory %s</I>", path);
    printFlagedWarning(buf);
    printHTMLtrailer();
    return;
  }

  if(snprintf(path, sizeof(path), "Info about %s", rrdTitle) < 0)
    BufferTooShort();

  printHTMLheader(path, 0);
  sendString("<CENTER>\n<p ALIGN=right>\n");

  snprintf(url, sizeof(url), "/plugins/rrdPlugin?action=list&key=%s&title=%s&end=now", rrdPath, rrdTitle);

  snprintf(path, sizeof(path), "<b>View:</b> [ <A HREF=\"%s&start=now-1y\">year</A> ]", url);  sendString(path);
  snprintf(path, sizeof(path), "[ <A HREF=\"%s&start=now-1m\">month</A> ]", url);  sendString(path);
  snprintf(path, sizeof(path), "[ <A HREF=\"%s&start=now-1w\">week</A> ]", url);  sendString(path);
  snprintf(path, sizeof(path), "[ <A HREF=\"%s&start=now-1d\">day</A> ]", url);  sendString(path);
  snprintf(path, sizeof(path), "[ <A HREF=\"%s&start=now-12h\">last 12h</A> ]\n", url);  sendString(path);
  snprintf(path, sizeof(path), "[ <A HREF=\"%s&start=now-6h\">last 6h</A> ]\n", url);  sendString(path);
  snprintf(path, sizeof(path), "[ <A HREF=\"%s&start=now-1h\">last hour</A> ]&nbsp;\n", url);  sendString(path);

  sendString("</p>\n<p>\n<TABLE BORDER>\n");

  sendString("<TR><TH>Graph</TH><TH>Total</TH></TR>\n");

  while((dp = readdir(directoryPointer)) != NULL) {
    char *rsrcName;
    Counter total;
    float  average;
    int rc, isGauge;

    if(dp->d_name[0] == '.')
      continue;
    else if(strlen(dp->d_name) < strlen(RRD_EXTENSION)+3)
      continue;

    rsrcName = &dp->d_name[strlen(dp->d_name)-strlen(RRD_EXTENSION)-3];
    if(strcmp(rsrcName, "Num"RRD_EXTENSION) == 0)
      isGauge = 1;
    else
      isGauge = 0;

    rsrcName = &dp->d_name[strlen(dp->d_name)-strlen(RRD_EXTENSION)];
    if(strcmp(rsrcName, RRD_EXTENSION))
      continue;

    rc = sumCounter(rrdPath, dp->d_name, startTime, endTime, &total, &average);

    if(isGauge
       || ((rc >= 0) && (total > 0))) {
      rsrcName[0] = '\0';
      rsrcName = dp->d_name;

      sendString("<TR><TD>\n");

      snprintf(path, sizeof(path), "<IMG SRC=\"/plugins/rrdPlugin?action=graph&key=%s/&name=%s&title=%s&start=%s&end=%s\"><P>\n",
	       rrdPath, rsrcName, rsrcName, startTime, endTime);
      sendString(path);

      sendString("</TD><TD ALIGN=RIGHT>\n");

      /* printf("rsrcName: %s\n", rsrcName); */

      if(isGauge) {
	sendString("&nbsp;");
      } else {
	if((strncmp(rsrcName, "pkt", 3) == 0)
	   || ((strlen(rsrcName) > 4) && (strcmp(&rsrcName[strlen(rsrcName)-4], "Pkts") == 0))) {
	  snprintf(path, sizeof(path), "%s Pkt</TD>", formatPkts(total));
	} else {
	  snprintf(path, sizeof(path), "%s", formatBytes(total, 1));
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

int endsWith(char* label, char* pattern) {
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
  char path[512], *argv[16], buf[96], buf1[96], fname[256], *label;
  struct stat statbuf;
  struct stat reusebuf;
  int argc = 0, rc, x, y;

  sprintf(path, "%s/%s%s.rrd", myGlobals.rrdPath, rrdPath, rrdName);
  /* startTime[4] skips the 'now-' */
  sprintf(fname, "%s/%s/%s-%s%s.%s", myGlobals.rrdPath, rrd_subdirs[0], startTime, rrdPrefix, rrdName,
#ifdef WIN32
                       "gif"
#else
                       "png"
#endif
         );

#ifdef WIN32
  revertSlash(path);
  revertSlash(fname);
#endif

  if(endsWith(rrdName, "Bytes")) label = "Bytes/sec";
  else if(endsWith(rrdName, "Pkts")) label = "Packets/sec";
  else label = "";

  rrdGraphicRequests++;

  if(stat(path, &statbuf) == 0) {

    rc = stat(fname, &reusebuf);

#if RRD_DEBUG >= 2
    strftime(startTimeBuf, sizeof(startTimeBuf), "%H:%M:%S", localtime_r(&start_tm, &t));
    strftime(endTimeBuf,   sizeof(endTimeBuf), "%H:%M:%S", localtime_r(&end_tm, &t));
    strftime(fileTimeBuf,  sizeof(fileTimeBuf), "%H:%M:%S", localtime_r(&reusebuf.st_mtime, &t));
    traceEvent(TRACE_INFO, "RRD_DEBUG: Reuse of '%s' (%s > %s > %s)? is %spossible...\n",
                               fname,
                               startTimeBuf,
                               fileTimeBuf,
                               endTimeBuf,
                               ( (reusebuf.st_mtime > start_tm) && (reusebuf.st_mtime < end_tm) ) ? "" : "NOT " );
#endif

    if (rc != 0) {
        if (errno != ENOENT)
            traceEvent(TRACE_INFO, "RRD: stat('%s') failed, %d...\n", fname, errno);
        reusebuf.st_mtime = 0;
    }

    if ( (reusebuf.st_mtime <= start_tm) || (reusebuf.st_mtime >= end_tm) ) {
        /* Recreate - delete existing and make a new one */
        if ( (unlink(fname) != 0) && (errno != ENOENT) ) {
            traceEvent(TRACE_ERROR, "RRD: ERROR: unlink('%s') failed, %d...\n", fname, errno);
        }
        argv[argc++] = "rrd_graph";
        argv[argc++] = fname;
        argv[argc++] = "--lazy";
        argv[argc++] = "--imgformat";
#ifdef WIN32
        argv[argc++] = "GIF";
#else
        argv[argc++] = "PNG";
#endif
        argv[argc++] = "--vertical-label";
        argv[argc++] = label;
        argv[argc++] = "--start";
        argv[argc++] = startTime;
        argv[argc++] = "--end";
        argv[argc++] = endTime;
        snprintf(buf, sizeof(buf), "DEF:ctr=%s:counter:AVERAGE", path);
        argv[argc++] = buf;
        snprintf(buf1, sizeof(buf1), "AREA:ctr#00a000:%s", rrdTitle);
        argv[argc++] = buf1;
        argv[argc++] = "GPRINT:ctr:MIN:Min\\: %3.1lf%s";
        argv[argc++] = "GPRINT:ctr:MAX:Max\\: %3.1lf%s";
        argv[argc++] = "GPRINT:ctr:AVERAGE:Avg\\: %3.1lf%s";
        argv[argc++] = "GPRINT:ctr:LAST:Current\\: %3.1lf%s";

#if RRD_DEBUG >= 3
        for (x = 0; x < argc; x++)
            traceEvent(TRACE_INFO, "RRD_DEBUG: argv[%d] = %s", x, argv[x]);
#endif

        optind=0; /* reset gnu getopt */
        opterr=0; /* no error messages */
        rc = rrd_graph(argc, argv, &calcpr, &x, &y);

        calfree();

    } else {

        /* Reuse, so we tell the code below that the "create" worked! */
        rrdGraphicReuse++;
        rc = 0;
    } 


    if(rc == 0) {
#ifdef WIN32
      sendHTTPHeader(HTTP_TYPE_GIF, 0);
#else
      sendHTTPHeader(HTTP_TYPE_PNG, 0);
#endif
      sendGraphFile(fname, myGlobals.reuseRRDgraphics /* Do we unlink? 0=yes, 1=no */);
    } else {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printHTMLheader("RRD Graph", 0);
      snprintf(path, sizeof(path), "<I>Error while building graph of the requested file. %s</I>",
			   rrd_get_error());
      printFlagedWarning(path);
      rrd_clear_error();
    }
  } else {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printHTMLheader("RRD Graph", 0);
      printFlagedWarning("<I>Error while building graph of the requested file "
			 "(unknown RRD file)</I>");
  }
}

/* ******************************* */

void updateRRD(char *hostPath, char *key, Counter value, int isCounter) {
  char path[512], *argv[16], cmd[64];
  struct stat statbuf;
  int argc = 0, rc, createdCounter = 0;

  if(value == 0) return;

  sprintf(path, "%s%s.rrd", hostPath, key);

#ifdef WIN32
  revertSlash(path);
#endif

  if(stat(path, &statbuf) != 0) {
    char startStr[32], counterStr[64];
    int step = dumpInterval;
    unsigned long topValue;

    topValue = 100000000 /* 100 Mbps */;

    if(strncmp(key, "pkt", 3) == 0) {
      topValue /= 8*64 /* 64 bytes is the shortest packet we care of */;
    } else {
      topValue /= 8 /* 8 bytes */;
    }

    argv[argc++] = "rrd_create";
    argv[argc++] = path;
    argv[argc++] = "--start";
    snprintf(startStr, sizeof(startStr), "%u", myGlobals.actTime-1 /* -1 avoids subsequent rrd_update call problems */);
    argv[argc++] = startStr;

    if(isCounter) {
      snprintf(counterStr, sizeof(counterStr), "DS:counter:COUNTER:%d:0:%u", step, topValue);
    } else {
      /* Unlimited */
      snprintf(counterStr, sizeof(counterStr), "DS:counter:GAUGE:%d:0:U", step);
    }

    argv[argc++] = counterStr;
    argv[argc++] = "RRA:AVERAGE:0.5:1:1200";
    argv[argc++] = "RRA:MIN:0.5:12:2400";
    argv[argc++] = "RRA:MAX:0.5:12:2400";

    optind=0; /* reset gnu getopt */
    opterr=0; /* no error messages */
    rc = rrd_create(argc, argv);

    if (rrd_test_error()) {
      traceEvent(TRACE_WARNING, "RRD: rrd_create(%s) error: %s\n", path, rrd_get_error());
      rrd_clear_error();
    }

#ifdef RRD_DEBUG > 0
    traceEvent(TRACE_INFO, "RRD_DEBUG: rrd_create(%s, %s, %u)=%d", hostPath, key, (unsigned long)value, rc);
#endif
    createdCounter = 1;
  }

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

    sprintf(cmd, "%u:u", myGlobals.actTime-10); /* u = undefined */
  } else {
    sprintf(cmd, "%u:%u", myGlobals.actTime, (unsigned long)value);
  }

  argv[argc++] = cmd;

  optind=0; /* reset gnu getopt */
  opterr=0; /* no error messages */
  rc = rrd_update(argc, argv);
  numTotalRRDs++;

  if (rrd_test_error()) {
    int x;

    traceEvent(TRACE_WARNING, "RRD: rrd_update(%s) error: %s\n", path, rrd_get_error());
    rrd_clear_error();

    traceEvent(TRACE_INFO, "RRD call stack:");
    for	(x = 0; x < argc; x++)
      traceEvent(TRACE_INFO, "argv[%d]: %s", x, argv[x]);
  }

#if RRD_DEBUG > 0
  traceEvent(TRACE_INFO, "RRD_DEBUG: rrd_update(%s, %u, %u)=%d", path, (unsigned long)value, rc);
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

char x2c(char *what) {
  char digit;

  digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
  digit *= 16;
  digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
  return(digit);
}

/* ******************************* */

void unescape_url(char *url) {
  register int x,y;

  for(x=0,y=0;url[y];++x,++y) {
    if((url[x] = url[y]) == '%') {
      url[x] = x2c(&url[y+1]);
      y+=2;
    }
  }
  url[x] = '\0';
}

/* ******************************* */

void commonRRDinit(void) {
  char value[64];

  /* **************************** */

  if(fetchPrefsValue("rrd.dataDumpInterval", value, sizeof(value)) == -1) {
    sprintf(value, "%d", RRD_DEFAULT_INTERVAL);
    storePrefsValue("rrd.dataDumpInterval", value);
    dumpInterval = RRD_DEFAULT_INTERVAL;
  } else {
    dumpInterval = atoi(value);
  }

  if(fetchPrefsValue("rrd.dumpHosts", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dumpHosts", "0");
    dumpHosts = 0;
  } else {
    dumpHosts = atoi(value);
  }

  if(fetchPrefsValue("rrd.dumpInterfaces", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dumpInterfaces", "1");
    dumpInterfaces = 1;
  } else {
    dumpInterfaces = atoi(value);
  }

  if(fetchPrefsValue("rrd.dumpMatrix", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dumpMatrix", "0");
    dumpMatrix = 0;
  } else {
    dumpMatrix = atoi(value);
  }

  if(fetchPrefsValue("rrd.hostsFilter", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.hostsFilter", "");
    hostsFilter  = strdup("");
  } else {
    hostsFilter  = strdup(value);
  }

  if(fetchPrefsValue("rrd.dumpDetail", value, sizeof(value)) == -1) {
    storePrefsValue("rrd.dumpDetail", "2" /* DETAIL_HIGH */);
    dumpDetail = DETAIL_HIGH;
  } else {
    dumpDetail  = atoi(value);
  }

  if(fetchPrefsValue("rrd.rrdPath", value, sizeof(value)) == -1) {
      myGlobals.rrdPath = strdup(myGlobals.dbPath);
      strcat(myGlobals.rrdPath, "/rrd");
      storePrefsValue("rrd.rrdPath", myGlobals.rrdPath);
  } else {
      myGlobals.rrdPath  = strdup(value);
  }

#ifdef RRD_DEBUG
  traceEvent(TRACE_INFO, "RRD_DEBUG: Parameters:\n");
  traceEvent(TRACE_INFO, "RRD_DEBUG:     dumpInterval %d seconds\n", dumpInterval);
  traceEvent(TRACE_INFO, "RRD_DEBUG:     dumpHosts %s\n", dumpHosts == 0 ? "no" : "yes");
  traceEvent(TRACE_INFO, "RRD_DEBUG:     dumpInterfaces %s\n", dumpInterfaces == 0 ? "no" : "yes");
  traceEvent(TRACE_INFO, "RRD_DEBUG:     dumpMatrix %s\n", dumpMatrix == 0 ? "no" : "yes");
  traceEvent(TRACE_INFO, "RRD_DEBUG:     dumpDetail %s\n",
         dumpDetail == DETAIL_HIGH ? "high" :
             (dumpDetail == DETAIL_MEDIUM ? "medium" : "low"));
  traceEvent(TRACE_INFO, "RRD_DEBUG:     hostsFilter %s\n", hostsFilter);
  traceEvent(TRACE_INFO, "RRD_DEBUG:     rrdPath %s\n", myGlobals.rrdPath);
#endif

  initialized = 1;
}

/* ****************************** */


#define ACTION_NONE   0
#define ACTION_GRAPH  1
#define ACTION_LIST   2

static void handleRRDHTTPrequest(char* url) {
  char buf[1024], *strtokState, *mainState, *urlPiece,
    rrdKey[64], rrdName[64], rrdTitle[64], startTime[32], endTime[32], rrdPrefix[32];
  u_char action = ACTION_NONE;
  int _dumpFlows=0, _dumpHosts=0, _dumpInterfaces=0, _dumpMatrix=0;

  if (initialized == 0)
      commonRRDinit();

  if((url != NULL) && (url[0] != '\0')) {
    unescape_url(url);

    /* traceEvent(TRACE_INFO, "RRD: URL=%s", url); */

    urlPiece = strtok_r(url, "&", &mainState);
    strcpy(startTime, "now-12h");
    strcpy(endTime, "now");

    while(urlPiece != NULL) {
      char *key, *value;

      key = strtok_r(urlPiece, "=", &strtokState);
      if(key != NULL) value = strtok_r(NULL, "=", &strtokState);

      /* traceEvent(TRACE_INFO, "RRD: key(%s)=%s", key, value);  */

      if(value && key) {

	if(strcmp(key, "action") == 0) {
	  if(strcmp(value, "graph") == 0)     action = ACTION_GRAPH;
	  else if(strcmp(value, "list") == 0) action = ACTION_LIST;
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
                  if ( (rrdPrefix[ii] == '.') || (rrdPrefix[ii] == '/') )
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
	  if(dumpInterval != atoi(value)) {
	    dumpInterval = atoi(value);
	    storePrefsValue("rrd.dataDumpInterval", value);
	  }
	} else if(strcmp(key, "hostsFilter") == 0) {
	  if(hostsFilter != NULL) free(hostsFilter);
	  hostsFilter = strdup(value);
	  storePrefsValue("rrd.hostsFilter", hostsFilter);
	} else if(strcmp(key, "rrdPath") == 0) {
	  if(myGlobals.rrdPath != NULL) free(myGlobals.rrdPath);
	  myGlobals.rrdPath = strdup(value);
	  storePrefsValue("rrd.rrdPath", myGlobals.rrdPath);
	} else if(strcmp(key, "dumpFlows") == 0) {
	  _dumpFlows = 1;
	} else if(strcmp(key, "dumpDetail") == 0) {
	  dumpDetail = atoi(value);
	  if(dumpDetail > DETAIL_HIGH) dumpDetail = DETAIL_HIGH;
	  snprintf(buf, sizeof(buf), "%d", dumpDetail);
	  storePrefsValue("rrd.dumpDetail", buf);
	} else if(strcmp(key, "dumpHosts") == 0) {
	  _dumpHosts = 1;
	} else if(strcmp(key, "dumpInterfaces") == 0) {
	  _dumpInterfaces = 1;
	} else if(strcmp(key, "dumpMatrix") == 0) {
	  _dumpMatrix = 1;
	}
      }

      urlPiece = strtok_r(NULL, "&", &mainState);
    }

    if(action == ACTION_NONE) {
      /* traceEvent(TRACE_INFO, "RRD: dumpFlows=%d", dumpFlows); */
      dumpFlows=_dumpFlows, dumpHosts=_dumpHosts,
      dumpInterfaces=_dumpInterfaces, dumpMatrix=_dumpMatrix;
      sprintf(buf, "%d", dumpFlows);      storePrefsValue("rrd.dumpFlows", buf);
      sprintf(buf, "%d", dumpHosts);      storePrefsValue("rrd.dumpHosts", buf);
      sprintf(buf, "%d", dumpInterfaces); storePrefsValue("rrd.dumpInterfaces", buf);
      sprintf(buf, "%d", dumpMatrix);     storePrefsValue("rrd.dumpMatrix", buf);
    }
  }

  /* traceEvent(TRACE_INFO, "RRD: action=%d", action); */

  if(action == ACTION_GRAPH) {
    graphCounter(rrdKey, rrdName, rrdTitle, startTime, endTime, rrdPrefix);
    return;
  } else if(action == ACTION_LIST) {
    listResource(rrdKey, rrdTitle, startTime, endTime);
    return;
  }

  sendHTTPHeader(HTTP_TYPE_HTML, 0);
  printHTMLheader("RRD Preferences", 0);

  sendString("<CENTER>\n");
  sendString("<TABLE BORDER>\n");
  sendString("<TR><TH ALIGN=LEFT>Dump Interval</TH><TD><FORM ACTION=/plugins/rrdPlugin METHOD=GET>"
	     "<INPUT NAME=interval SIZE=5 VALUE=");

  if(snprintf(buf, sizeof(buf), "%d", (int)dumpInterval) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("> seconds<br>It specifies how often data is stored permanently.</TD></tr>\n");

  sendString("<TR><TH ALIGN=LEFT>Data to Dump</TH><TD>");

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
    sendString("<TR><TH ALIGN=LEFT>Hosts Filter</TH><TD><FORM ACTION=/plugins/rrdPlugin METHOD=GET>"
	       "<INPUT NAME=hostsFilter VALUE=\"");

    sendString(hostsFilter);

    sendString("\" SIZE=80><br>A list of networks [e.g. 172.22.0.0/255.255.0.0,192.168.5.0/255.255.255.0]<br>"
	               "separated by commas to which hosts that will be<br>"
	               "saved must belong to. An empty list means that all the hosts will "
	       "be stored on disk</TD></tr>\n");
  }

  sendString("<TR><TH ALIGN=LEFT>RRD Detail</TH><TD>");
  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=radio NAME=dumpDetail VALUE=%d %s>Low\n",
	      DETAIL_LOW, (dumpDetail == DETAIL_LOW) ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=radio NAME=dumpDetail VALUE=%d %s>Medium\n",
	      DETAIL_MEDIUM, (dumpDetail == DETAIL_MEDIUM) ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<INPUT TYPE=radio NAME=dumpDetail VALUE=%d %s>Full\n",
	      DETAIL_HIGH, (dumpDetail == DETAIL_HIGH) ? "CHECKED" : "") < 0)
    BufferTooShort();
  sendString(buf);
  sendString("</TD></TR>\n");

  sendString("<TR><TH ALIGN=LEFT>RRD Files Path</TH><TD><FORM ACTION=/plugins/rrdPlugin METHOD=GET>"
             "<INPUT NAME=rrdPath SIZE=50 VALUE=\"");
  sendString(myGlobals.rrdPath);
  sendString("\"></TD></tr>\n");

  sendString("<TR><TH ALIGN=LEFT>RRD Updates</TH><TD>");
  if(snprintf(buf, sizeof(buf), "%lu RRD files updated</TD></TR>\n", (unsigned long)numTotalRRDs) < 0)
    BufferTooShort();
  sendString(buf);

  sendString("<TR><TH ALIGN=LEFT>RRD Graphic Requests</TH><TD>");
  if (myGlobals.reuseRRDgraphics) {
      if(snprintf(buf, sizeof(buf), "%lu RRD graphics requested (%lu reused)</TD></TR>\n",
                       (unsigned long)rrdGraphicRequests,
                       (unsigned long)rrdGraphicReuse) < 0)
        BufferTooShort();
  } else {
      if(snprintf(buf, sizeof(buf), "%lu RRD graphics requested</TD></TR>\n",
                       (unsigned long)rrdGraphicRequests) < 0) 
        BufferTooShort();
  }
  sendString(buf);

  sendString("<TD COLSPAN=2 ALIGN=center><INPUT TYPE=submit VALUE=Set></td></FORM></tr>\n");
  sendString("</TABLE>\n<p></CENTER>\n");

  sendString("<p><H5><A HREF=http://www.rrdtool.org/>RRDtool</A> has been created by <A HREF=http://ee-staff.ethz.ch/~oetiker/>Tobi Oetiker</A>.</H5>\n");

  if (active == 1) {
      sendString("<p><center>You must restart the rrd plugin - for changes here to take affect.</center></p>\n");
  } else {
      sendString("<p><center>Changes here will take effect when the plugin is started.</center></p>\n");
  }

  sendString("<p><center>Return to <a href=\"../" STR_SHOW_PLUGINS "\">plugins</a> menu</center></p>\n");
  printHTMLtrailer();
}

/* ****************************** */

static void* rrdMainLoop(void* notUsed _UNUSED_) {
  char value[512 /* leave it big for hosts filter */];
  u_int32_t networks[32][3];
  u_short numLocalNets;
  int sleep_tm;
  char rrdPath[512], fname[512];
  struct stat statbuf;
  int purgeCountFiles, purgeCountUnlink, purgeCountErrors;
  int cycleCount=0;

#ifdef RRD_DEBUG
  traceEvent(TRACE_INFO, "RRD_DEBUG: rrdMainLoop()");
#endif

  if (initialized == 0)
      commonRRDinit();

  /* Initialize the "end" of the dummy interval just far enough back in time 
     so that it expires once everything is up and running. */
  end_tm = myGlobals.actTime - dumpInterval + 15;

  /* Show we're running */
  active = 1;

  for(;myGlobals.capturePackets == 1;) {
    char *hostKey;
    int i, j;
    Counter numRRDs = numTotalRRDs;

#if RRD_DEBUG >= 1
    char endTime[32];
    struct tm t;
#endif
 
    cycleCount++;
 
    do {
        end_tm += dumpInterval;
        sleep_tm = end_tm - (start_tm = time(NULL));
    } while (sleep_tm < 0);

#if RRD_DEBUG >= 1
    strftime(endTime, sizeof(endTime), "%Y-%m-%d %H:%M:%S", localtime_r(&end_tm, &t));
    traceEvent(TRACE_INFO, "RRD_DEBUG: Sleeping for %d seconds (interval %d, end at %s)\n", 
                           sleep_tm, 
                           dumpInterval,
                           endTime);
#endif

    sleep(sleep_tm);

#if RRD_DEBUG >= 1
    traceEvent(TRACE_INFO, "RRD_DEBUG: Woke");
#endif

    if(!myGlobals.capturePackets) return(NULL);

    numRuns++;

    /* ****************************************************** */

    numLocalNets = 0;
    strcpy(rrdPath, hostsFilter); /* It avoids strtok to blanks into hostsFilter */
    handleAddressLists(rrdPath, networks, &numLocalNets, value, sizeof(value));

    /* ****************************************************** */

    if(dumpHosts) {
      for(i=1; i<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; i++) {
	HostTraffic *el;

	if((i == myGlobals.otherHostEntryIdx) || (i == myGlobals.broadcastEntryIdx)
	   || ((el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i]) == NULL)
	   || broadcastHost(el))
	  continue;

	/* if(((!subnetPseudoLocalHost(el)) && (!multicastHost(el)))) continue; */

	if(el->bytesSent.value > 0) {
	  if(el->hostNumIpAddress[0] != '\0') {
	    hostKey = el->hostNumIpAddress;

	    if((numLocalNets > 0)
	       && (!__pseudoLocalAddress(&el->hostIpAddress, networks, numLocalNets))) continue;

	  } else {
	    /* hostKey = el->ethAddressString; */
	    /* For the time being do not save IP-less hosts */
	    continue;
	  }

	  sprintf(rrdPath, "%s/hosts/%s/", myGlobals.rrdPath, hostKey);
	  mkdir_p(rrdPath);

	  updateTrafficCounter(rrdPath, "pktSent", &el->pktSent);
	  updateTrafficCounter(rrdPath, "pktRcvd", &el->pktRcvd);
	  updateTrafficCounter(rrdPath, "bytesSent", &el->bytesSent);
	  updateTrafficCounter(rrdPath, "bytesRcvd", &el->bytesRcvd);


	  if(dumpDetail >= DETAIL_MEDIUM) {
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
	    updateTrafficCounter(rrdPath, "ospfSent", &el->ospfSent);
	    updateTrafficCounter(rrdPath, "igmpSent", &el->igmpSent);
	    updateTrafficCounter(rrdPath, "tcpRcvdLoc", &el->tcpRcvdLoc);
	    updateTrafficCounter(rrdPath, "tcpRcvdFromRem", &el->tcpRcvdFromRem);
	    updateTrafficCounter(rrdPath, "udpRcvdLoc", &el->udpRcvdLoc);
	    updateTrafficCounter(rrdPath, "udpRcvdFromRem", &el->udpRcvdFromRem);
	    updateTrafficCounter(rrdPath, "icmpRcvd", &el->icmpRcvd);
	    updateTrafficCounter(rrdPath, "ospfRcvd", &el->ospfRcvd);
	    updateTrafficCounter(rrdPath, "igmpRcvd", &el->igmpRcvd);
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
	  }

	  if(dumpDetail == DETAIL_HIGH) {
	    if((hostKey == el->hostNumIpAddress) && el->protoIPTrafficInfos) {
#ifdef RRD_DEBUG
	      traceEvent(TRACE_INFO, "RRD_DEBUG: Updating host %s", hostKey);
#endif

	      sprintf(rrdPath, "%s/hosts/%s/IP_", myGlobals.rrdPath, hostKey);

	      for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {
		char key[128];
		sprintf(key, "%sSentBytes", myGlobals.protoIPTrafficInfos[j]);
		updateCounter(rrdPath, key, el->protoIPTrafficInfos[j].sentLoc.value+
			      el->protoIPTrafficInfos[j].sentRem.value);

		sprintf(key, "%sRcvdBytes", myGlobals.protoIPTrafficInfos[j]);
		updateCounter(rrdPath, key, el->protoIPTrafficInfos[j].rcvdLoc.value+
			      el->protoIPTrafficInfos[j].rcvdFromRem.value);
	      }
	    }
	  }
	}
      }
    }

    /* ************************** */

    if(dumpFlows) {
      FlowFilterList *list = myGlobals.flowsList;

      while(list != NULL) {
	if(list->pluginStatus.activePlugin) {
	  sprintf(rrdPath, "%s/flows/%s/", myGlobals.rrdPath, list->flowName);
	  mkdir_p(rrdPath);

	  updateCounter(rrdPath, "packets", list->packets.value);
	  updateCounter(rrdPath, "bytes",   list->bytes.value);
	}

	list = list->next;
      }
    }

    /* ************************** */

    if(dumpInterfaces) {
      for(i=0; i<myGlobals.numDevices; i++) {


	if(myGlobals.device[i].virtualDevice) continue;

	sprintf(rrdPath, "%s/interfaces/%s/", myGlobals.rrdPath,  myGlobals.device[i].humanFriendlyName);
	mkdir_p(rrdPath);

	updateCounter(rrdPath, "ethernetPkts",  myGlobals.device[i].ethernetPkts.value);
	updateCounter(rrdPath, "broadcastPkts", myGlobals.device[i].broadcastPkts.value);
	updateCounter(rrdPath, "multicastPkts", myGlobals.device[i].multicastPkts.value);
	updateCounter(rrdPath, "ethernetBytes", myGlobals.device[i].ethernetBytes.value);
	updateGauge(rrdPath,   "knownHostsNum", myGlobals.device[i].hostsno);
	updateGauge(rrdPath,   "activeHostSendersNum",  numActiveSenders(i));
	updateCounter(rrdPath, "ipBytes",       myGlobals.device[i].ipBytes.value);

	if(dumpDetail >= DETAIL_MEDIUM) {
	  updateCounter(rrdPath, "droppedPkts", myGlobals.device[i].droppedPkts.value);
	  updateCounter(rrdPath, "fragmentedIpBytes", myGlobals.device[i].fragmentedIpBytes.value);
	  updateCounter(rrdPath, "tcpBytes", myGlobals.device[i].tcpBytes.value);
	  updateCounter(rrdPath, "udpBytes", myGlobals.device[i].udpBytes.value);
	  updateCounter(rrdPath, "otherIpBytes", myGlobals.device[i].otherIpBytes.value);
	  updateCounter(rrdPath, "icmpBytes", myGlobals.device[i].icmpBytes.value);
	  updateCounter(rrdPath, "dlcBytes", myGlobals.device[i].dlcBytes.value);
	  updateCounter(rrdPath, "ipxBytes", myGlobals.device[i].ipxBytes.value);
	  updateCounter(rrdPath, "stpBytes", myGlobals.device[i].stpBytes.value);
	  updateCounter(rrdPath, "decnetBytes", myGlobals.device[i].decnetBytes.value);
	  updateCounter(rrdPath, "netbiosBytes", myGlobals.device[i].netbiosBytes.value);
	  updateCounter(rrdPath, "arpRarpBytes", myGlobals.device[i].arpRarpBytes.value);
	  updateCounter(rrdPath, "atalkBytes", myGlobals.device[i].atalkBytes.value);
	  updateCounter(rrdPath, "ospfBytes", myGlobals.device[i].ospfBytes.value);
	  updateCounter(rrdPath, "egpBytes", myGlobals.device[i].egpBytes.value);
	  updateCounter(rrdPath, "igmpBytes", myGlobals.device[i].igmpBytes.value);
	  updateCounter(rrdPath, "osiBytes", myGlobals.device[i].osiBytes.value);
	  updateCounter(rrdPath, "ipv6Bytes", myGlobals.device[i].ipv6Bytes.value);
	  updateCounter(rrdPath, "otherBytes", myGlobals.device[i].otherBytes.value);
	  updateCounter(rrdPath, "upTo64Pkts", myGlobals.device[i].rcvdPktStats.upTo64.value);
	  updateCounter(rrdPath, "upTo128Pkts", myGlobals.device[i].rcvdPktStats.upTo128.value);
	  updateCounter(rrdPath, "upTo256Pkts", myGlobals.device[i].rcvdPktStats.upTo256.value);
	  updateCounter(rrdPath, "upTo512Pkts", myGlobals.device[i].rcvdPktStats.upTo512.value);
	  updateCounter(rrdPath, "upTo1024Pkts", myGlobals.device[i].rcvdPktStats.upTo1024.value);
	  updateCounter(rrdPath, "upTo1518Pkts", myGlobals.device[i].rcvdPktStats.upTo1518.value);
	  updateCounter(rrdPath, "badChecksumPkts", myGlobals.device[i].rcvdPktStats.badChecksum.value);
	  updateCounter(rrdPath, "tooLongPkts", myGlobals.device[i].rcvdPktStats.tooLong.value);
	}

	if(dumpDetail == DETAIL_HIGH) {
	  if(myGlobals.device[i].ipProtoStats != NULL) {
	    snprintf(rrdPath, sizeof(rrdPath), "%s/interfaces/%s/IP_", myGlobals.rrdPath,  myGlobals.device[i].humanFriendlyName);

	    for(j=0; j<myGlobals.numIpProtosToMonitor; j++) {
	      TrafficCounter ctr;
	      char tmpStr[128];

	      ctr.value =
		myGlobals.device[i].ipProtoStats[j].local.value+
		myGlobals.device[i].ipProtoStats[j].local2remote.value+
		myGlobals.device[i].ipProtoStats[j].remote2local.value+
		myGlobals.device[i].ipProtoStats[j].remote.value;

	      snprintf(tmpStr, sizeof(tmpStr), "%sBytes", myGlobals.protoIPTrafficInfos[j]);
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
	  if(i != myGlobals.otherHostEntryIdx) {
	    for(j=1; j<myGlobals.device[k].numHosts; j++) {
	      if(i != j) {
		int idx = i*myGlobals.device[k].numHosts+j;

		if(idx == myGlobals.otherHostEntryIdx) continue;

		if(myGlobals.device[k].ipTrafficMatrix[idx] == NULL)
		  continue;

		if(myGlobals.device[k].ipTrafficMatrix[idx]->bytesSent.value > 0) {

		  sprintf(rrdPath, "%s/matrix/%s/%s/", myGlobals.rrdPath,
			  myGlobals.device[k].ipTrafficMatrixHosts[i]->hostNumIpAddress,
			  myGlobals.device[k].ipTrafficMatrixHosts[j]->hostNumIpAddress);
		  mkdir_p(rrdPath);

		  updateCounter(rrdPath, "pkts",
				myGlobals.device[k].ipTrafficMatrix[idx]->pktsSent.value);

		  updateCounter(rrdPath, "bytes",
				myGlobals.device[k].ipTrafficMatrix[idx]->bytesSent.value);
		}
	      }
	    }
	  }
    }

#ifdef SHOW_NTOP_HEARTBEAT
    traceEvent(TRACE_INFO, "RRD: %lu RRDs updated (%lu total updates)",
	       (unsigned long)(numTotalRRDs-numRRDs), (unsigned long)numTotalRRDs);
#endif

    /* If we're reusing, every 5th cycle (25m), purge the old graphics */
    if ( (!myGlobals.reuseRRDgraphics) || (cycleCount % 5 != 0) ) {
        continue;
    }

    purgeCountFiles=0;
    purgeCountUnlink=0;
    purgeCountErrors=0;

    sprintf(rrdPath, "%s/%s", myGlobals.rrdPath, rrd_subdirs[0]);
#ifdef SHOW_NTOP_HEARTBEAT
    traceEvent(TRACE_INFO, "RRD: beginning old file purge (%s).", rrdPath);
#endif

    workDir = opendir(rrdPath);
    if (workDir != NULL) {
        while((workDirent = readdir(workDir)) != NULL) {
            if(workDirent->d_name[0] != '.') {
                purgeCountFiles++;
                sprintf(fname, "%s/%s", rrdPath, workDirent->d_name);
                if(stat(fname, &statbuf) == 0) {
                    if (myGlobals.actTime - statbuf.st_mtime > 2 * dumpInterval) {
#ifdef RRD_DEBUG
                        strftime(fileTimeBuf, sizeof(fileTimeBuf), 
                                              "%H:%M:%S", 
                                              localtime_r(&statbuf.st_mtime, &t));
                        traceEvent(TRACE_INFO, "RRD_DEBUG: oldfilepurge %s, mod @ %s\n",
                                               fname,
                                               fileTimeBuf);
#endif
                        if ( (unlink(fname) != 0) && (errno != ENOENT) ) {
                            purgeCountErrors++;
                            traceEvent(TRACE_ERROR, "RRD: ERROR: unlink('%s') failed, %d...\n", fname, errno);
                        } else {
                            purgeCountUnlink++;
                        }
                    }
                }
            }
        }
#ifdef SHOW_NTOP_HEARTBEAT
        traceEvent(TRACE_INFO, "RRD: finished old file purge (%d files, %d deleted, %d errors).",
                               purgeCountFiles,
                               purgeCountUnlink,
                               purgeCountErrors);
#endif
    } else {
        traceEvent(TRACE_ERROR, "RRD: Unable to opendir(%s), errno=%d\n", rrdPath, errno);
    }
  }

#ifdef RRD_DEBUG
  traceEvent(TRACE_INFO, "RRD_DEBUG: rrdMainLoop() terminated.");
#endif

  return(0);
}

#undef RRD_DEBUG 

/* ****************************** */

static void initRrdFunct(void) {
  char dname[256];
  int i;

  traceEvent(TRACE_INFO, "Welcome to the RRD plugin...");

  if(myGlobals.rrdPath == NULL)
      commonRRDinit();

  sprintf(dname, "%s", myGlobals.rrdPath);
  if (_mkdir(dname) == -1) { 
      if (errno != EEXIST) {
          traceEvent(TRACE_ERROR, "RRD: ERROR: Disabled - unable to create base directory (err %d, %s)\n", errno, dname);
          /* Return w/o creating the rrd thread ... disabled */
          return;
      }
  } else {
      traceEvent(TRACE_INFO, "RRD: Created base directory (%s)\n", dname);
  }

  for (i=0; i<sizeof(rrd_subdirs)/sizeof(rrd_subdirs[0]); i++) {
      
      sprintf(dname, "%s/%s", myGlobals.rrdPath, rrd_subdirs[i]);
      if (_mkdir(dname) == -1) {
          if (errno != EEXIST) {
              traceEvent(TRACE_ERROR, "RRD: Disabled - unable to create directory (err %d, %s)\n", errno, dname);
              /* Return w/o creating the rrd thread ... disabled */
              return;
          }
      } else {
          traceEvent(TRACE_INFO, "RRD: Note: Created directory (%s)\n", dname);
      }
  } 

#ifdef MULTITHREADED
  /* This plugin works only with threads */
  createThread(&rrdThread, rrdMainLoop, NULL);
  traceEvent(TRACE_INFO, "RRD: Started thread (%ld) for data collection.", rrdThread);
#endif

  fflush(stdout);
  numTotalRRDs = 0;
}

/* ****************************** */

static void termRrdFunct(void) {
#ifdef MULTITHREADED
  if(active) killThread(&rrdThread);
#endif

  traceEvent(TRACE_INFO, "RRD: Thanks for using the rrdPlugin");
  traceEvent(TRACE_INFO, "RRD: Done.\n");
  fflush(stdout);
}

#else /* HAVE_RRD */

static void initRrdFunct(void) { }
static void termRrdFunct(void) { }
static void handleRRDHTTPrequest(char* url) {
  sendHTTPHeader(HTTP_TYPE_HTML, 0);
  printHTMLheader("RRD Preferences", 0);
  printFlagedWarning("<I>This plugin is disabled as ntop has not been compiled with RRD support</I>");
  sendString("<p><center>Return to <a href=\"../" STR_SHOW_PLUGINS "\">plugins</a> menu</center></p>\n");
}

#endif /* HAVE_RRD */

/* ************************************* */

static PluginInfo rrdPluginInfo[] = {
  { "rrdPlugin",
    "This plugin is used to setup, activate and deactivate ntop's rrd support.<br>"
      "This plugin also produces the graphs of rrd data, available via a"
      "link from the various 'Info about host xxxxx' reports.",
    "2.1", /* version */
    "<A HREF=http://luca.ntop.org/>L.Deri</A>",
    "rrdPlugin", /* http://<host>:<port>/plugins/rrdPlugin */
    1, /* Active by default */ 
    1, /* Inactive setup */
    initRrdFunct, /* TermFunc   */
    termRrdFunct, /* TermFunc   */
    NULL, /* PluginFunc */
    handleRRDHTTPrequest,
    NULL /* no capture */
  }
};

/* ****************************** */

/* Plugin entry fctn */
#ifdef STATIC_PLUGIN
PluginInfo* rrdPluginEntryFctn(void)
#else
PluginInfo* PluginEntryFctn(void)
#endif
{
  traceEvent(TRACE_INFO, "RRD: Welcome to %s. (C) 2002 by Luca Deri.\n",
	     rrdPluginInfo->pluginName);

  return(rrdPluginInfo);
}

