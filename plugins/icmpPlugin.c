/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
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

/* Formats for most of the ICMP_UNREACH codes */
static struct tok unreach2str[] = {
  { ICMP_UNREACH_NET,		"net %s unreachable" },
  { ICMP_UNREACH_HOST,		"host %s unreachable" },
  { ICMP_UNREACH_SRCFAIL,       "%s unreachable - source route failed" },
  { ICMP_UNREACH_NET_UNKNOWN,	"net %s unreachable - unknown" },
  { ICMP_UNREACH_HOST_UNKNOWN,	"host %s unreachable - unknown" },
  { ICMP_UNREACH_ISOLATED,      "%s unreachable - source host isolated" },
  { ICMP_UNREACH_NET_PROHIB,    "net %s unreachable - admin prohibited" },
  { ICMP_UNREACH_HOST_PROHIB,   "host %s unreachable - admin prohibited" },
  { ICMP_UNREACH_TOSNET,        "net %s unreachable - tos prohibited" },
  { ICMP_UNREACH_TOSHOST,       "host %s unreachable - tos prohibited" },
  { ICMP_UNREACH_FILTER_PROHIB, "host %s unreachable - admin prohibited filter" },
  { ICMP_UNREACH_HOST_PRECEDENCE, "host %s unreachable - host precedence violation" },
  { ICMP_UNREACH_PRECEDENCE_CUTOFF, "host %s unreachable - precedence cutoff" },
  { 0,				NULL }
};

/* Formats for the ICMP_REDIRECT codes */
static struct tok type2str[] = {
  { ICMP_REDIRECT_NET,		"redirect %s to net %s" },
  { ICMP_REDIRECT_HOST,		"redirect %s to host %s" },
  { ICMP_REDIRECT_TOSNET,	"redirect-tos %s to net %s" },
  { ICMP_REDIRECT_TOSHOST,	"redirect-tos %s to net %s" },
  { 0,				NULL }
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

static char *tok2str(register const struct tok *lp,
		     register const char *fmt,
		     register int v) {
  static char buf[128];

  while (lp->s != NULL) {
    if (lp->v == v)
      return (lp->s);
    ++lp;
  }
  if (fmt == NULL)
    fmt = "#%d";

  if(snprintf(buf, sizeof(buf), fmt, v) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
  return (buf);
}

/* ****************************** */

static int sortICMPhosts(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  unsigned long n1, n2;
  int rc;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (1)\n");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (2)\n");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (3)\n");
    return(0);
  }

  switch(icmpColumnSort) {
  case 2:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_ECHO] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_ECHO];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_ECHO] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_ECHO];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 12: /* Echo Reply */
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 3:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_UNREACH] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_UNREACH];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_UNREACH] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_UNREACH];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 4:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_REDIRECT] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_REDIRECT] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 5:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 6:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_TIMXCEED] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_TIMXCEED] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 7:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_PARAMPROB] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_PARAMPROB] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 8:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_MASKREQ] + (*a)->icmpInfo->icmpMsgSent[ICMP_MASKREPLY] +
      (*a)->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ]+ (*a)->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_MASKREQ] + (*b)->icmpInfo->icmpMsgSent[ICMP_MASKREPLY] +
      (*b)->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ]+ (*b)->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;


  case 9:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 10:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP] + (*a)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY] +
      (*a)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP]+ (*a)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP] + (*b)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY] +
      (*b)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP]+ (*b)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 11:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST] + (*a)->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY] +
      (*a)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST]+ (*a)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST] + (*b)->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY] +
      (*b)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST]+ (*b)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  default:
#ifdef MULTITHREADED
    accessMutex(&addressResolutionMutex, "addressResolution");
#endif

    rc = strcasecmp((*a)->hostSymIpAddress, (*b)->hostSymIpAddress);

#ifdef MULTITHREADED
    releaseMutex(&addressResolutionMutex);
#endif
    return(rc);
    break;
  }
}

/* ******************************* */

static void handleIcmpWatchHTTPrequest(char* url) {
  char buf[1024], anchor[256], fileName[NAME_MAX] = "/tmp/ntop-icmpPlugin-XXXXXX";
  char *sign = "-";
  char *pluginName = "<A HREF=/plugins/icmpWatch";
  u_int i, revertOrder=0, num;
  int icmpId=-1;
  HostTraffic **hosts;
  struct in_addr hostIpAddress;
  char  **lbls, *strtokState;
  float *s, *r;
  FILE *fd;
  int tmpfd;

  i = sizeof(float)*device[actualReportDeviceId].actualHashSize;
  s = (float*)malloc(i); r = (float*)malloc(i);
  memset(s, 0, i); memset(r, 0, i);

  i = sizeof(char*)*device[actualReportDeviceId].actualHashSize;
  lbls = malloc(i);
  memset(lbls, 0, i);  

  i = sizeof(HostTraffic*)*device[actualReportDeviceId].actualHashSize;
  hosts = (HostTraffic**)malloc(i);

  for(i=0, num=0; i<device[actualReportDeviceId].actualHashSize; i++)
    if((device[actualReportDeviceId].hash_hostTraffic[i] != NULL)
       && (device[actualReportDeviceId].hash_hostTraffic[i]->icmpInfo != NULL)) {
      hosts[num++] = device[actualReportDeviceId].hash_hostTraffic[i];
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

#ifdef HAVE_GDCHART
    if(strncmp(url, "chart", strlen("chart")) == 0) {
      char tmpStr[256];
      u_int len, tot=0;
      unsigned long  sc[2] = { 0xFF0000, 0x8080FF };

      GDC_BGColor   = 0xFFFFFFL;                  /* backgound color (white) */
      GDC_LineColor = 0x000000L;                  /* line color      (black) */
      GDC_SetColor  = &(sc[0]);                   /* assign set colors */
      GDC_ytitle = "Packets";

      for(i=0; i<num; i++) {
	if(hosts[i] != NULL) {
	  int j;

	  s[tot] = 0, r[tot] = 0;

	  for(j=0; j<ICMP_MAXTYPE; j++) {
#ifdef DEBUG
	    traceEvent(TRACE_INFO, "idx=%d/type=%d: %d/%d\n", i, j, 
		       hosts[i]->icmpInfo->icmpMsgSent[j],
		       hosts[i]->icmpInfo->icmpMsgRcvd[j]);
#endif
	    s[tot] += (float)(hosts[i]->icmpInfo->icmpMsgSent[j]);
	    r[tot] += (float)(hosts[i]->icmpInfo->icmpMsgRcvd[j]);
	  }

	  lbls[tot++] = hosts[i]->hostSymIpAddress;
	}
      }

      /* traceEvent(TRACE_INFO, "file=%s\n", fileName); */

      fd = getNewRandomFile(fileName, NAME_MAX);

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

      sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);

      fd = fopen(fileName, "rb");
      for(;;) {
	len = fread(tmpStr, sizeof(char), 255, fd);
	if(len <= 0) break;
	sendStringLen(tmpStr, len);
      }

      fclose(fd);

      unlink(fileName);

      return;
    }
#endif

    strtok_r(url, "=", &strtokState);

    tmpStr = strtok_r(NULL, "&", &strtokState);
    hostIpAddress.s_addr = strtoul(tmpStr, (char **)NULL, 10);
#ifdef DEBUG
    traceEvent(TRACE_INFO, "-> %s [%u]\n", tmpStr, hostIpAddress.s_addr);
#endif
    strtok_r(NULL, "=", &strtokState);
    icmpId = atoi(strtok_r(NULL, "&", &strtokState));
  }

  sendHTTPHeader(HTTP_TYPE_HTML, 0);  
  printHTMLheader("ICMP Statistics", 0);

  if(num == 0) {
    printNoDataYet();
    printHTMLtrailer();
    return;
  }

#ifdef HAVE_GDCHART
  if(hostIpAddress.s_addr == 0)
    sendString("<BR><CENTER><IMG SRC=\"/plugins/icmpWatch?chart\"></CENTER><P>\n");
#endif

  sendString("<CENTER>\n");
  sendString("<TABLE BORDER>\n");
  if(snprintf(buf, sizeof(buf), "<TR><TH>%s?%s1>Host</A><br>[Pkt&nbsp;Sent/Rcvd]</TH>"
	      "<TH>%s?%s2>Echo Req.</A></TH>"
	      "<TH>%s?%s12>Echo Reply</A></TH>"
	      "<TH>%s?%s3>Unreach</A></TH>"
	      "<TH>%s?%s4>Redirect</A></TH>"
	      "<TH>%s?%s5>Router<br>Advert.</A></TH>"
	      "<TH>%s?%s6>Time<br>Exceeded</A></TH>"
	      "<TH>%s?%s7>Param.<br>Problem</A></TH>"
	      "<TH>%s?%s8>Network<br>Mask</A></TH>"
	      "<TH>%s?%s9>Source<br>Quench</A></TH>"
	      "<TH>%s?%s10>Timestamp</A></TH>"
	      "<TH>%s?%s11>Info</A></TH>"
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
	      pluginName, sign) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  quicksort(hosts, num, sizeof(HostTraffic **), sortICMPhosts);

  for(i=0; i<num; i++)
    if(hosts[i] != NULL) {
      unsigned long tot;
      char *postAnchor;
      int idx;

      if(revertOrder)
	idx = num-i-1;
      else
	idx = i;

      if(snprintf(buf, sizeof(buf), "<TR %s> %s",
		  getRowColor(),
		  makeHostLink(hosts[idx], LONG_FORMAT, 0, 0)) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s/%s</TD>",
		  formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_ECHO])),
		  formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_ECHO]))) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s/%s</TD>",
		  formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY])),
		  formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY]))) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);


      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_UNREACH]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_UNREACH];
      anchor[0] = '\0';
      postAnchor = "";

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>",
		  anchor,
		  formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			     icmpMsgSent[ICMP_UNREACH]),
		  formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			     icmpMsgRcvd[ICMP_UNREACH]),
		  postAnchor) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);


      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_REDIRECT]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT];

      anchor[0] = '\0';
      postAnchor = "";

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
		  formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			     icmpMsgSent[ICMP_REDIRECT]),
		  formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			     icmpMsgRcvd[ICMP_REDIRECT]),
		  postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT];
      anchor[0] = '\0';
      postAnchor = "";

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
		  formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			     icmpMsgSent[ICMP_ROUTERADVERT]),
		  formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			     icmpMsgRcvd[ICMP_ROUTERADVERT]),
		  postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_TIMXCEED]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED];
      anchor[0] = '\0';
      postAnchor = "";

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
		  formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			     icmpMsgSent[ICMP_TIMXCEED]),
		  formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			     icmpMsgRcvd[ICMP_TIMXCEED]),
		  postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_PARAMPROB]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB];
      anchor[0] = '\0';
      postAnchor = "";

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
		  formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			     icmpMsgSent[ICMP_PARAMPROB]),
		  formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			     icmpMsgRcvd[ICMP_PARAMPROB]),
		  postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_MASKREQ]+
	hosts[idx]->icmpInfo->icmpMsgSent[ICMP_MASKREPLY]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY];

      anchor[0] = '\0';
      postAnchor = "";

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
		  formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->
					      icmpMsgSent[ICMP_MASKREQ]+
					      hosts[idx]->icmpInfo->icmpMsgSent[ICMP_MASKREPLY])),
		  formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->
					      icmpMsgRcvd[ICMP_MASKREQ]+
					      hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY])),
		  postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH];
      anchor[0] = '\0';
      postAnchor = "";

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
		  formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			     icmpMsgSent[ICMP_SOURCE_QUENCH]),
		  formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			     icmpMsgRcvd[ICMP_SOURCE_QUENCH]),
		  postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP]+
	hosts[idx]->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY];
      anchor[0] = '\0';
      postAnchor = "";

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
		  formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->
					      icmpMsgSent[ICMP_TIMESTAMP]+
					      hosts[idx]->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY])),
		  formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->
					      icmpMsgRcvd[ICMP_TIMESTAMP]+
					      hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY])),
		  postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST]+
	hosts[idx]->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY];
      anchor[0] = '\0';
      postAnchor = "";

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
		  formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->
					      icmpMsgSent[ICMP_INFO_REQUEST]+
					      hosts[idx]->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY])),
		  formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->
					      icmpMsgRcvd[ICMP_INFO_REQUEST]+
					      hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY])),
		  postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      sendString("</TR>\n");
    }

  sendString("</TABLE>\n");

  sendString("<p></CENTER>\n");

  printHTMLtrailer();

  free(s);
  free(r); 
  free(lbls);
  free(hosts); 
}

/* ****************************** */

static void termIcmpFunct(void) {
  traceEvent(TRACE_INFO, "Thanks for using icmpWatch..."); fflush(stdout);
  traceEvent(TRACE_INFO, "Done.\n"); fflush(stdout);
}

/* ****************************** */

static PluginInfo icmpPluginInfo[] = {
  { "icmpWatchPlugin",
    "This plugin handles ICMP packets",
    "1.0", /* version */
    "<A HREF=http://luca.ntop.org/>L.Deri</A>",
    "icmpWatch", /* http://<host>:<port>/plugins/icmpWatch */
    1, /* Active */
    NULL, /* no special startup after init */
    termIcmpFunct, /* TermFunc   */
    NULL, /* PluginFunc */
    handleIcmpWatchHTTPrequest,
    NULL,
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
    traceEvent(TRACE_INFO, "Welcome to %s. (C) 1999 by Luca Deri.\n",
	       icmpPluginInfo->pluginName);
    
    return(icmpPluginInfo);
  }
