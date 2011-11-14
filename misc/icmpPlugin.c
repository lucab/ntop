/*
 *  Copyright (C) 1998-2011 Luca Deri <deri@ntop.org>
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

/* F o r w a r d */

static void termIcmpFunct(u_char);
static void handleIcmpWatchHTTPrequest(char* url);
static void printICMPdata(int icmpColumnSort, u_int revertOrder, u_int num, HostTraffic **hosts);


/* ******************************
   *     Plugin data block      *
   ****************************** */

static PluginInfo icmpPluginInfo[] = {
  { VERSION, /* current ntop version */
    "ICMPWatch",
    "This plugin produces a report about the ICMP packets that ntop has seen.<br>"
    "The report includes each host, byte and per-type counts (sent/received).",
    "2.4a", /* version */
    "<A HREF=\"http://luca.ntop.org/\" alt=\"Luca's home page\">L.Deri</A>",
    "icmpWatch", /* http://<host>:<port>/plugins/icmpWatch */
    0, /* Active by default */
    ViewOnly,
    0, /* Inactive setup */
    NULL, /* no special startup after init */
    termIcmpFunct, /* TermFunc   */
    NULL, /* PluginFunc */
    handleIcmpWatchHTTPrequest,
    NULL, /* no host creation/deletion handle */
    NULL /* no capture */,
    NULL, /* no status */
    NULL /* no extra pages */
  }
};

/* ******************************
   *  Sort (compare) functions  *
   ****************************** */

static int sortICMPhostsHost(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  int rc;

  rc = cmpFctnResolvedName(a, b);
  return(rc);
}

/* **************************************** */

static int sortICMPhostsSent(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsSent() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsSent() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsSent() (3)");
    return(0);
  }

  n1 = (*a)->icmpSent.value, n2 = (*b)->icmpSent.value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* **************************************** */

static int sortICMPhostsRcvd(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsRcvd() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsRcvd() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsRcvd() (3)");
    return(0);
  }

  n1 = (*a)->icmpRcvd.value, n2 = (*b)->icmpRcvd.value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* **************************************** */

static int sortICMPhostsEcho(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsEcho() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsEcho() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsEcho() (3)");
    return(0);
  }

  n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_ECHO].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value;
  n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_ECHO].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* **************************************** */

static int sortICMPhostsReply(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsReply() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsReply() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsReply() (3)");
    return(0);
  }

  n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value;
  n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* **************************************** */

static int sortICMPhostsUnreach(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsUnreach() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsUnreach() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsUnreach() (3)");
    return(0);
  }

  n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_UNREACH].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value;
  n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_UNREACH].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* **************************************** */

static int sortICMPhostsRedirect(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsRedirect() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsRedirect() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsRedirect() (3)");
    return(0);
  }

  n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_REDIRECT].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT].value;
  n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_REDIRECT].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT].value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* **************************************** */

static int sortICMPhostsAdvert(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsAdvert() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsAdvert() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsAdvert() (3)");
    return(0);
  }

  n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value;
  n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* **************************************** */

static int sortICMPhostsTimeout(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsTimeout() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsTimeout() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsTimeout() (3)");
    return(0);
  }

  n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value;
  n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* **************************************** */

static int sortICMPhostsBadParam(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsBadParam() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsBadParam() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsBadParam() (3)");
    return(0);
  }

  n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_PARAMPROB].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB].value;
  n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_PARAMPROB].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB].value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* **************************************** */

static int sortICMPhostsQuench(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsQuench() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsQuench() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsQuench() (3)");
    return(0);
  }

  n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH].value;
  n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH].value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* **************************************** */

static int sortICMPhostsTimestamp(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsTimestamp() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsTimestamp() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsTimestamp() (3)");
    return(0);
  }

  n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP].value +
       (*a)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY].value;
  n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP].value +
       (*b)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY].value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* **************************************** */

static int sortICMPhostsInfo(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsInfo() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsInfo() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsInfo() (3)");
    return(0);
  }

  n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST].value +
       (*a)->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY].value;
  n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST].value +
       (*b)->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY].value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* **************************************** */

static int sortICMPhostsNetmask(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter n1, n2;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsNetmask() (1)");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsNetmask() (2)");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortICMPhostsNetmask() (3)");
    return(0);
  }

  n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_MASKREQ].value +
       (*a)->icmpInfo->icmpMsgSent[ICMP_MASKREPLY].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ].value +
       (*a)->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY].value;
  n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_MASKREQ].value +
       (*b)->icmpInfo->icmpMsgSent[ICMP_MASKREPLY].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ].value +
       (*b)->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY].value;

  if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
}

/* ******************************
   *    Sort (compare) data     *
   ****************************** */

#define CONST_ICMP_SORT_HOST            0
#define CONST_ICMP_SORT_SENT            1
#define CONST_ICMP_SORT_RCVD            2
#define CONST_ICMP_SORT_ECHO            3
#define CONST_ICMP_SORT_REPLY           4
#define CONST_ICMP_SORT_TIMXCEED        5
#define CONST_ICMP_SORT_UNREACH         6
#define CONST_ICMP_SORT_REDIRECT        7
#define CONST_ICMP_SORT_ROUTERADVERT    8
#define CONST_ICMP_SORT_PARAMPROB       9
#define CONST_ICMP_SORT_QUENCH          10
#define CONST_ICMP_SORT_TIMESTAMP       11
#define CONST_ICMP_SORT_NETMASK         12
#define CONST_ICMP_SORT_INFO            13

static void* cmpFctnICMP[] = { sortICMPhostsHost,
                               sortICMPhostsSent,
                               sortICMPhostsRcvd,
                               sortICMPhostsEcho,
                               sortICMPhostsReply,
                               sortICMPhostsTimeout,
                               sortICMPhostsUnreach,
                               sortICMPhostsRedirect,
                               sortICMPhostsAdvert,
                               sortICMPhostsBadParam,
                               sortICMPhostsQuench,
                               sortICMPhostsTimestamp,
                               sortICMPhostsNetmask,
                               sortICMPhostsInfo };

static int cmpFctnICMPmax = sizeof(cmpFctnICMP) / sizeof(cmpFctnICMP[0]);

/* ***************************************** */
/* ***************************************** */

static void formatSentRcvd(Counter sent, Counter rcvd) {
  char buf[128], formatBuf[32], formatBuf1[32];

  if (sent + rcvd == 0) {
    strcpy(buf, "<TD "TD_BG" ALIGN=center>&nbsp;</TD>");
  } else safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=center>%s/%s</TD>",
		     formatPkts(sent, formatBuf, sizeof(formatBuf)),
		     formatPkts(rcvd, formatBuf1, sizeof(formatBuf1)));
  sendString(buf);
}

/* ******************************* */

static void printICMPdata(int icmpColumnSort, u_int revertOrder,
                   u_int num, HostTraffic **hosts) {

  char buf[1024], formatBuf[32];
  char *pluginName = "<A HREF=/plugins/icmpWatch";
  char *arrowGif, *arrow[15];
  u_int i;
  char *sign = "-";
  u_int printedEntries;

  if(icmpColumnSort<0) icmpColumnSort=0;
  if(icmpColumnSort>cmpFctnICMPmax) icmpColumnSort=0;

  if(!revertOrder) {
    arrowGif = "&nbsp;<IMG ALT=\"Ascending order, click to reverse\" SRC=/arrow_up.png BORDER=0>";
  } else {
    arrowGif = "&nbsp;<IMG ALT=\"Descending order, click to reverse\" SRC=/arrow_down.png BORDER=0>";
    sign = "";
  }

  for(i=0; i<=14; i++)
    if(abs(icmpColumnSort) == i) arrow[i] = arrowGif; else arrow[i] = "";

  sendString("<CENTER>\n<TABLE BORDER=1 "TABLE_DEFAULTS">\n");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" "DARK_BG">"
              "<TH "TH_BG" rowspan=\"2\" valign=\"bottom\">%s?%s%d>Host %s</A></TH>\n"
	      "<TH "TH_BG" colspan=\"2\">Bytes</TH>\n"
              "<TH "TH_BG" colspan=\"11\">Sent/Recived by ICMP Type</TH>\n"
	      "</TR>\n",
	      pluginName, sign, CONST_ICMP_SORT_HOST, arrow[CONST_ICMP_SORT_HOST]);
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" "DARK_BG">"
	      "<TH "TH_BG">%s?%s%d>Sent %s</A></TH>\n"
	      "<TH "TH_BG">%s?%s%d>Rcvd %s</A></TH>\n"
	      "<TH "TH_BG">%s?%s%d>Echo<br>Request %s</A></TH>\n"
	      "<TH "TH_BG">%s?%s%d>Echo<br>Reply %s</A></TH>\n"
	      "<TH "TH_BG">%s?%s%d>Time<br>Exceeded %s</A></TH>\n"
	      "<TH "TH_BG">%s?%s%d>Unreach %s</A></TH>\n"
	      "<TH "TH_BG">%s?%s%d>Redirect %s</A></TH>\n"
	      "<TH "TH_BG">%s?%s%d>Router<br>Advert. %s</A></TH>\n"
	      "<TH "TH_BG">%s?%s%d>Param.<br>Problem %s</A></TH>\n"
	      "<TH "TH_BG">%s?%s%d>Network<br>Mask %s</A></TH>\n"
	      "<TH "TH_BG">%s?%s%d>Source<br>Quench %s</A></TH>\n"
	      "<TH "TH_BG">%s?%s%d>Timestamp %s</A></TH>\n"
	      "<TH "TH_BG">%s?%s%d>Info %s</A></TH>\n"
	      "</TR>\n",
	      pluginName, sign, CONST_ICMP_SORT_SENT, arrow[CONST_ICMP_SORT_SENT],
	      pluginName, sign, CONST_ICMP_SORT_RCVD, arrow[CONST_ICMP_SORT_RCVD],
	      pluginName, sign, CONST_ICMP_SORT_ECHO, arrow[CONST_ICMP_SORT_ECHO],
	      pluginName, sign, CONST_ICMP_SORT_REPLY, arrow[CONST_ICMP_SORT_REPLY],
	      pluginName, sign, CONST_ICMP_SORT_TIMXCEED, arrow[CONST_ICMP_SORT_TIMXCEED],
	      pluginName, sign, CONST_ICMP_SORT_UNREACH, arrow[CONST_ICMP_SORT_UNREACH],
	      pluginName, sign, CONST_ICMP_SORT_REDIRECT, arrow[CONST_ICMP_SORT_REDIRECT],
	      pluginName, sign, CONST_ICMP_SORT_ROUTERADVERT, arrow[CONST_ICMP_SORT_ROUTERADVERT],
	      pluginName, sign, CONST_ICMP_SORT_PARAMPROB, arrow[CONST_ICMP_SORT_PARAMPROB],
	      pluginName, sign, CONST_ICMP_SORT_NETMASK, arrow[CONST_ICMP_SORT_NETMASK],
	      pluginName, sign, CONST_ICMP_SORT_QUENCH, arrow[CONST_ICMP_SORT_QUENCH],
	      pluginName, sign, CONST_ICMP_SORT_TIMESTAMP, arrow[CONST_ICMP_SORT_TIMESTAMP],
	      pluginName, sign, CONST_ICMP_SORT_INFO, arrow[CONST_ICMP_SORT_INFO]);
  sendString(buf);

  qsort(hosts, num, sizeof(HostTraffic **), cmpFctnICMP[icmpColumnSort]);

  for(i=0, printedEntries=0; i<num; i++)
    if(hosts[i] != NULL) {
      int idx;
      char hostLinkBuf[LEN_GENERAL_WORK_BUFFER];

      if(revertOrder)
	idx = num-i-1;
      else
	idx = i;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s> %s",
		  getRowColor(),
		  makeHostLink(hosts[idx], FLAG_HOSTLINK_HTML_FORMAT, 0, 0,
			       hostLinkBuf, sizeof(hostLinkBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=center>%s</TD>",
		  formatBytes(hosts[idx]->icmpSent.value, 1, formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=center>%s</TD>",
		  formatBytes(hosts[idx]->icmpRcvd.value, 1, formatBuf, sizeof(formatBuf)));
      sendString(buf);

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_ECHO].value),
		     (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value),
		     (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value),
		     (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_UNREACH].value),
		     (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_REDIRECT].value),
		     (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT].value));

      formatSentRcvd((Counter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value),
		     (Counter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value));

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
      if(printedEntries++ > (u_int)myGlobals.runningPref.maxNumLines)
	break;
    }

  sendString("</TABLE>\n<p></CENTER>\n");

}

/* ******************************* */

static void handleIcmpWatchHTTPrequest(char* url) {
  u_int i, revertOrder=0, num;
  HostTraffic **hosts;
  char  **lbls, *strtokState;
  float *s, *r;  
  int icmpColumnSort = 0;

  i = sizeof(float)*myGlobals.device[myGlobals.actualReportDeviceId].hosts.actualHashSize;
  s = (float*)malloc(i); r = (float*)malloc(i);
  memset(s, 0, i); memset(r, 0, i);

  i = sizeof(char*)*myGlobals.device[myGlobals.actualReportDeviceId].hosts.actualHashSize;
  lbls = malloc(i);
  memset(lbls, 0, i);

  i = sizeof(HostTraffic*)*myGlobals.device[myGlobals.actualReportDeviceId].hosts.actualHashSize;
  hosts = (HostTraffic**)malloc(i);

  for(i=0, num=0; i<myGlobals.device[myGlobals.actualReportDeviceId].hosts.actualHashSize; i++) {
    HostTraffic *el = myGlobals.device[myGlobals.actualReportDeviceId].hosts.hash_hostTraffic[i];

    while(el != NULL) {
      if((el != myGlobals.broadcastEntry)
	 && (el != myGlobals.otherHostEntry)
	 && (!broadcastHost(el))
	 && (el->icmpInfo != NULL)) {
	hosts[num++] = el;
      }

      el = el->next;
    }
  }

  if(url[0] == '\0')
    icmpColumnSort = 0;
  else if((url[0] == '-') || isdigit(url[0])) {
    if(url[0] == '-') {
      revertOrder = 1;
      icmpColumnSort = atoi(&url[1]);
    } else
      icmpColumnSort = atoi(url);

    if(icmpColumnSort<0) icmpColumnSort=0;
    if(icmpColumnSort>cmpFctnICMPmax) icmpColumnSort=0;

  } else /* host=3240847503&icmp=3 */ {
    char *tmpStr;

    strtok_r(url, "=", &strtokState);

    tmpStr = strtok_r(NULL, "&", &strtokState);
    strtok_r(NULL, "=", &strtokState);
  }

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
  printHTMLheader("ICMP Statistics", NULL, 0);

  if(num == 0) {
    printNoDataYet();
  } else {
    printICMPdata(icmpColumnSort, revertOrder, num, hosts);
  }

  printPluginTrailer(icmpPluginInfo->pluginURLname,
                     "See <a href=\"http://www.faqs.org/rfcs/rfc792.html\" "
                            "alt=\"link to rfc 792\">RFC 792</a> "
                     "for more information on ICMP");

  printHTMLtrailer();

  if(s != NULL)
    free(s);
  if(r != NULL)
    free(r);
  if(lbls != NULL)
    free(lbls);
  if(hosts != NULL)
    free(hosts);
}

/* ****************************** */

static void termIcmpFunct(u_char termNtop /* 0=term plugin, 1=term ntop */) {
  traceEvent(CONST_TRACE_INFO, "ICMP: Thanks for using icmpWatch"); fflush(stdout);
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "ICMP: Done"); fflush(stdout);
}

/* ***************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGIN
PluginInfo* icmpPluginEntryFctn(void) {
#else
  PluginInfo* PluginEntryFctn(void) {
#endif
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "ICMP: Welcome to %s. (C) 1999-2005 by Luca Deri",
	       icmpPluginInfo->pluginName);

    return(icmpPluginInfo);
}

