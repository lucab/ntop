/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
 *
 *  			    http://www.ntop.org/
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

#include "ntop.h"
#include "globals-report.h"

/* ****************************** */

static int icmpColumnSort = 0;

struct tok {
  int v;    /* value  */
  char *s;  /* string */
};

/* rfc1191 */
struct mtu_discovery {
  short unused;
  short nexthopmtu;
};

/* rfc1256 */
struct ih_rdiscovery {
  u_char ird_addrnum;
  u_char ird_addrsiz;
  u_short ird_lifetime;
};

struct id_rdiscovery {
  u_int32_t ird_addr;
  u_int32_t ird_pref;
};

/* ****************************** */

static int sortICMPhosts(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;
  int rc;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "WARNING (1)\n");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "WARNING (2)\n");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "WARNING (3)\n");
    return(0);
  }

  switch(icmpColumnSort) {
  case 2:
    n1 = (*a)->icmpSent.value, n2 = (*b)->icmpSent.value;
    break;

  case 3:
    n1 = (*a)->icmpRcvd.value, n2 = (*b)->icmpRcvd.value;
    break;

  case 4:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_ECHO].value + (*a)->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value;
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_ECHO].value + (*b)->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value;
    break;

  case 5:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_UNREACH].value + (*a)->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value;
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_UNREACH].value + (*b)->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value;
    break;

  case 6:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_REDIRECT].value + (*a)->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT].value;
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_REDIRECT].value + (*b)->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT].value;
    break;

  case 7:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value + (*a)->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value;
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value + (*b)->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value;
    break;

  case 8:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value + (*a)->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value;
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value + (*b)->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value;
    break;

  case 9:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_PARAMPROB].value + (*a)->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB].value;
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_PARAMPROB].value + (*b)->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB].value;
    break;

  case 10:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_MASKREQ].value + (*a)->icmpInfo->icmpMsgSent[ICMP_MASKREPLY].value +
      (*a)->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ].value+ (*a)->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY].value;
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_MASKREQ].value + (*b)->icmpInfo->icmpMsgSent[ICMP_MASKREPLY].value +
      (*b)->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ].value+ (*b)->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY].value;
    break;

  case 11:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH].value + (*a)->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH].value;
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH].value + (*b)->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH].value;
    break;

  case 12:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP].value + (*a)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY].value +
      (*a)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP].value+ (*a)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY].value;
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP].value + (*b)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY].value +
      (*b)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP].value+ (*b)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY].value;
    break;

  case 13:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST].value + (*a)->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY].value +
      (*a)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST].value+ (*a)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY].value;
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST].value + (*b)->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY].value +
      (*b)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST].value+ (*b)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY].value;
    break;

  case 14: /* Echo Reply */
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value + (*a)->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value;
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value + (*b)->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value;
    break;

  default:
    accessAddrResMutex("addressResolution");
    rc = strcasecmp((*a)->hostSymIpAddress, (*b)->hostSymIpAddress);
    releaseAddrResMutex();
    return(rc);
    break;
  }

  /* traceEvent(CONST_TRACE_INFO, "%d <-> %d", n1, n2); */
 
  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

 /* ******************************* */

static void formatSentRcvd(Counter sent, Counter rcvd) {
  char buf[128];
  
  if (sent + rcvd == 0) {
    strcpy(buf, "<TD "TD_BG" ALIGN=center>&nbsp;</TD>");
  } else if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=center>%s/%s</TD>",
		     formatPkts(sent), formatPkts(rcvd)) < 0)
    BufferTooShort();
  sendString(buf);
}

/* ******************************* */

static void handleIcmpWatchHTTPrequest(char* url) {
  char buf[1024], fileName[NAME_MAX] = "/tmp/ntop-icmpPlugin-XXXXXX";
  char *sign = "-";
  char *pluginName = "<A HREF=/plugins/icmpWatch";
  u_int i, revertOrder=0, num, printedEntries, tot = 0;
  int icmpId=-1;
  HostTraffic **hosts;
  struct in_addr hostIpAddress;
  char  **lbls, *strtokState;
  float *s, *r;
  FILE *fd;

  i = sizeof(float)*myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize;
  s = (float*)malloc(i); r = (float*)malloc(i);
  memset(s, 0, i); memset(r, 0, i);

  i = sizeof(char*)*myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize;
  lbls = malloc(i);
  memset(lbls, 0, i);  

  i = sizeof(HostTraffic*)*myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize;
  hosts = (HostTraffic**)malloc(i);

  for(i=0, num=0; i<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; i++)
    if((i != myGlobals.broadcastEntryIdx) 
       && (i != myGlobals.otherHostEntryIdx)
       && (myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i] != NULL)
       && (!broadcastHost(myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i]))
       && (myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i]->icmpInfo != NULL)) {
      hosts[num++] = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i];
    }

  hostIpAddress.s_addr = 0;

  if(url[0] == '\0')
    icmpColumnSort = 0;
  else if((url[0] == '-') || isdigit(url[0])) {
    if(url[0] == '-') {
      sign = "";
      revertOrder = 1;
      icmpColumnSort = atoi(&url[1]);
    } else
      icmpColumnSort = atoi(url);
  } else /* host=3240847503&icmp=3 */ {
    char *tmpStr;    

#ifdef MAKE_WITH_GDCHART
    if(strncmp(url, "chart", strlen("chart")) == 0) {
      unsigned long  sc[2] = { 0xf08080L, 0x4682b4L }; /* see clr[] in graph.c */

      GDC_BGColor   = 0xFFFFFFL;                  /* backgound color (white) */
      GDC_LineColor = 0x000000L;                  /* line color      (black) */
      GDC_SetColor  = &(sc[0]);                   /* assign set colors */
      GDC_ytitle = "Packets";

#ifndef MAKE_MICRO_NTOP
      /* Avoid to draw too many entries */
      if(num > myGlobals.maxNumLines) num = myGlobals.maxNumLines;
#endif

      quicksort(hosts, num, sizeof(HostTraffic **), sortICMPhosts);

      for(i=0; i<num; i++) {
	if(hosts[i] != NULL) {
	  int j;

	  s[tot] = 0, r[tot] = 0;

	  for(j=0; j<ICMP_MAXTYPE; j++) {
#ifdef DEBUG
	    traceEvent(CONST_TRACE_INFO, "idx=%d/type=%d: %d/%d\n", i, j, 
		       hosts[i]->icmpInfo->icmpMsgSent[j].value,
		       hosts[i]->icmpInfo->icmpMsgRcvd[j].value);
#endif
	    s[tot] += (float)(hosts[i]->icmpInfo->icmpMsgSent[j].value);
	    r[tot] += (float)(hosts[i]->icmpInfo->icmpMsgRcvd[j].value);
	  }

	  lbls[tot++] = hosts[i]->hostSymIpAddress;
	}
      }

      /* traceEvent(CONST_TRACE_INFO, "file=%s\n", fileName); */

      sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);

#ifdef CFG_MULTITHREADED
      accessMutex(&myGlobals.graphMutex, "icmpPlugin");
#endif

#ifndef WIN32
      fd = fdopen(abs(myGlobals.newSock), "ab");
#else
      fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

      GDC_title = "ICMP Host Traffic";
      /* The line below causes a crash on Solaris/SPARC (who knows why) */
      /* GDC_yaxis=1; */
      GDC_ylabel_fmt = NULL;
      out_graph(600, 450,           /* width, height           */
		fd,                 /* open FILE pointer       */
		GDC_3DBAR,          /* chart type              */
		tot,                /* num points per data set */
		lbls,               /* X labels array of char* */
		2,                  /* number of data sets     */
		s, r);              /* dataset 2               */

      fclose(fd);

#ifdef CFG_MULTITHREADED
      releaseMutex(&myGlobals.graphMutex);
#endif

#ifdef WIN32
      sendGraphFile(fileName, 0);
#endif
      return;
    }
#endif

    strtok_r(url, "=", &strtokState);

    tmpStr = strtok_r(NULL, "&", &strtokState);
    hostIpAddress.s_addr = strtoul(tmpStr, (char **)NULL, 10);
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "-> %s [%u]\n", tmpStr, hostIpAddress.s_addr);
#endif
    strtok_r(NULL, "=", &strtokState);
    icmpId = atoi(strtok_r(NULL, "&", &strtokState));
  }

  /* traceEvent(CONST_TRACE_INFO, "-> %s%d", sign, icmpColumnSort); */

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);  
  printHTMLheader("ICMP Statistics", 0);

  if(num == 0) {
    printNoDataYet();
    sendString("<p><center>Return to <a href=\"../" STR_SHOW_PLUGINS "\">plugins</a> menu</center></p>\n");
    printHTMLtrailer();
    return;
  }

#if 0 /* Not quite useful */
#ifdef MAKE_WITH_GDCHART
  if(hostIpAddress.s_addr == 0)
    sendString("<BR><CENTER><IMG SRC=\"/plugins/icmpWatch?chart\"></CENTER><P>\n");
#endif
#endif

  sendString("<CENTER>\n");
  sendString("<TABLE BORDER>\n");
  if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG">%s?%s1>Host</A><br>[Pkt&nbsp;Sent/Rcvd]</TH>"
	      "<TH "TH_BG">%s?%s2>Bytes Sent.value</A></TH>"
	      "<TH "TH_BG">%s?%s3>Bytes Rcvd.value</A></TH>"
	      "<TH "TH_BG">%s?%s4>Echo Req.</A></TH>"
	      "<TH "TH_BG">%s?%s14>Echo Reply</A></TH>"
	      "<TH "TH_BG">%s?%s5>Unreach</A></TH>"
	      "<TH "TH_BG">%s?%s6>Redirect</A></TH>"
	      "<TH "TH_BG">%s?%s7>Router<br>Advert.</A></TH>"
	      "<TH "TH_BG">%s?%s8>Time<br>Exceeded</A></TH>"
	      "<TH "TH_BG">%s?%s9>Param.<br>Problem</A></TH>"
	      "<TH "TH_BG">%s?%s10>Network<br>Mask</A></TH>"
	      "<TH "TH_BG">%s?%s11>Source<br>Quench</A></TH>"
	      "<TH "TH_BG">%s?%s12>Timestamp</A></TH>"
	      "<TH "TH_BG">%s?%s13>Info</A></TH>"
	      "</TR>\n",
	      pluginName, sign,
	      pluginName, sign,
	      pluginName, sign,
	      pluginName, sign,
	      pluginName, sign,
	      pluginName, sign,
	      pluginName, sign,
	      pluginName, sign,
	      pluginName, sign,
	      pluginName, sign,
	      pluginName, sign,
	      pluginName, sign,
	      pluginName, sign,
	      pluginName, sign) < 0) 
    BufferTooShort();
  sendString(buf);

  quicksort(hosts, num, sizeof(HostTraffic **), sortICMPhosts);

  for(i=0, printedEntries=0; i<num; i++)
    if(hosts[i] != NULL) {
      int idx;

      if(revertOrder)
	idx = num-i-1;
      else
	idx = i;

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s> %s",
		  getRowColor(),
		  makeHostLink(hosts[idx], FLAG_HOSTLINK_HTML_FORMAT, 0, 0)) < 0) 
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=center>%s</TD>", 
		  formatBytes(hosts[idx]->icmpSent.value, 1)) < 0)
	BufferTooShort();
      sendString(buf);
      
      if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=center>%s</TD>", 
		  formatBytes(hosts[idx]->icmpRcvd.value, 1)) < 0)
	BufferTooShort();
      sendString(buf);

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_ECHO].value),
				 (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value),
				 (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_UNREACH].value),
				 (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_REDIRECT].value),
				 (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value),
				 (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value),
				 (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_PARAMPROB].value),
				 (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_MASKREPLY].value),
				 (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH].value),
				 (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH].value));
      
      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY].value),
				 (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST].value
					   +hosts[idx]->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY].value),
				 (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST].value
					   +hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY].value));
      
      sendString("</TR>\n");

      /* Avoid huge tables */
#ifndef MAKE_MICRO_NTOP
      if(printedEntries++ > myGlobals.maxNumLines)
	break;
#endif
    }

  sendString("</TABLE>\n<p></CENTER>\n");

  sendString("<p><center>Return to <a href=\"../" STR_SHOW_PLUGINS "\">plugins</a> menu</center></p>\n");

  printHTMLtrailer();

  free(s);    free(r); 
  free(lbls); free(hosts); 
}

/* ****************************** */

static void termIcmpFunct(void) {
  traceEvent(CONST_TRACE_INFO, "Thanks for using icmpWatch..."); fflush(stdout);
  traceEvent(CONST_TRACE_INFO, "Done.\n"); fflush(stdout);
}

/* ****************************** */

static PluginInfo icmpPluginInfo[] = {
  { "icmpWatchPlugin",
    "This plugin produces a report about the ICMP packets that ntop has seen. "
       "The report includes each host, byte and per-type counts (send/received).",
    "2.0", /* version */
    "<A HREF=http://luca.ntop.org/>L.Deri</A>",
    "icmpWatch", /* http://<host>:<port>/plugins/icmpWatch */
    0, /* Active by default */
    0, /* Inactive setup */
    NULL, /* no special startup after init */
    termIcmpFunct, /* TermFunc   */
    NULL, /* PluginFunc */
    handleIcmpWatchHTTPrequest,
    NULL /* no capture */
  }
};

/* ***************************************** */

/* Plugin entry fctn */
#ifdef STATIC_PLUGIN
PluginInfo* icmpPluginEntryFctn(void) {
#else
  PluginInfo* PluginEntryFctn(void) {
#endif
    traceEvent(CONST_TRACE_INFO, "Welcome to %s. (C) 1999 by Luca Deri.\n",
	       icmpPluginInfo->pluginName);
    
    return(icmpPluginInfo);
  }
