/*
 *  Copyright (C) 1998-2009 Luca Deri <deri@ntop.org>
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

typedef struct osInfo {
  char *name, *link;
} OsInfo;

typedef struct osNumInfo {
  char *name;
  unsigned short num;
} OsNumInfo;

static OsInfo osInfos[] = {
  { "Windows",       CONST_IMG_OS_WINDOWS },
  { "IRIX",          CONST_IMG_OS_IRIX },
  { "Linux",         CONST_IMG_OS_LINUX },
  { "SunOS",         CONST_IMG_OS_SUNOS },
  { "Solaris",       CONST_IMG_OS_SOLARIS },
  { "HP/JETdirect",  CONST_IMG_OS_HP_JETDIRET },
  { "Mac",           CONST_IMG_OS_MAC },
  { "Novell",        CONST_IMG_OS_NOVELL },
  { "BSD",           CONST_IMG_OS_BSD },
  { "Unix",          CONST_IMG_OS_UNIX },
  { "Berkeley",      CONST_IMG_OS_BERKELEY },
  { "HP-UX",         CONST_IMG_OS_HP_UX },
  { "AIX",           CONST_IMG_OS_AIX },
  { "Cisco",         CONST_IMG_OS_CISCO },
  { NULL, NULL }
};

/* ************************* */

void *mallocAndInitWithReportWarn(int sz, char *from) {
  void *tmpTable;

  tmpTable = malloc(sz);

  if (tmpTable == NULL) {
    traceEvent(CONST_TRACE_ERROR, "Unable to allocate temporary table (%d) for %s", sz, from);
    traceEvent(CONST_TRACE_INFO,  "User warned, continuing without generating report");
    printFlagedWarning("SORRY: <i>An internal error does not allow creation of this report.</i>");
  } else {
    memset (tmpTable, 0, sz);
  }

  return tmpTable;
}

/* ************************************ */

void formatUsageCounter(UsageCounter usageCtr,
			Counter topValue,
			/* If this value != 0 then a percentage is printed */
			int actualDeviceId) {
  char buf[LEN_GENERAL_WORK_BUFFER], formatBuf[32], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  int i, sendHeader=0;
  HostTraffic *el;

  if(topValue == 0) {
    /* No percentage is printed */
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		formatPkts(usageCtr.value.value, formatBuf, sizeof(formatBuf)));
    sendString(buf);
  } else {
    float pctg;

    pctg = ((float)usageCtr.value.value/(float)topValue)*100;

    if(pctg > 100) pctg = 100; /* This should not happen ! */

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;[%.0f&nbsp;%%]</TD>",
		formatPkts(usageCtr.value.value, formatBuf, sizeof(formatBuf)), pctg);
    sendString(buf);
  }

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
      HostTraffic tmpEl;

      if(!emptySerial(&usageCtr.peersSerials[i])) {
	  if((el = quickHostLink(usageCtr.peersSerials[i],
				 myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
 	if(!sendHeader) {
	  sendString("<TD "TD_BG" ALIGN=LEFT><ul>");
	  sendHeader = 1;
	}

	sendString("\n<li>");
	sendString(makeHostLink(el, 0, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)));
      } else
	  traceEvent(CONST_TRACE_WARNING, "Unable to find host serial - host skipped");
    }
  }

  if(sendHeader)
    sendString("</ul></TD>\n");
  else
    sendString("<TD "TD_BG">&nbsp;</TD>\n");
}

/* ********************************** */

void printTableDoubleEntry(char *buf, int bufLen,
			   char *label, char* color,
			   float totalS, float percentageS,
			   float totalR, float percentageR) {
  int int_perc;
  char formatBuf[32];

  if((totalS == 0) && (totalR == 0)) return;

  if(percentageS < 0.5) {
    int_perc = 0;
    percentageS = 0;
  } else if(percentageS > 99.5) {
    int_perc = 100;
    percentageS = 100;
  } else {
    int_perc = (int) percentageS + 0.5;
  }

  switch(int_perc) {
  case 0:
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TR "TR_ON" %s><TH WIDTH=100 "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
           "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
           "<TD WIDTH=100 "TD_BG">&nbsp;</TD>\n",
           getRowColor(), label, formatKBytes(totalS, formatBuf, sizeof(formatBuf)));
    break;
  case 100:
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TR "TR_ON" %s><TH WIDTH=100 "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		"<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100><IMG ALT=\"100%%\" ALIGN=MIDDLE SRC=\"/gauge.jpg\" WIDTH=100 HEIGHT=12></TD>\n",
		getRowColor(), label, formatKBytes(totalS, formatBuf, sizeof(formatBuf)));
    break;
  default:
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TR "TR_ON" %s><TH WIDTH=100 "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		"<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100 "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100\">"
		"<TR "TR_ON"><TD><IMG  ALT=\"%d%%\" ALIGN=MIDDLE SRC=\"/gauge.jpg\" WIDTH=\"%d\" HEIGHT=12></TD>"
		"<TD "TD_BG" ALIGN=CENTER WIDTH=\"%d\">"
		"<P>&nbsp;</TD></TR></TABLE>"TABLE_OFF"</TD>\n",
		getRowColor(), label, formatKBytes(totalS, formatBuf, sizeof(formatBuf)),
		int_perc, (100*int_perc)/100, (100*(100-int_perc))/100);
  }

  sendString(buf);

  /* ************************ */

  if(totalR == 0) percentageR = 0;

  if(percentageR < 0.5) {
    int_perc = 0;
    percentageR = 0;
  } else if(percentageR > 99.5) {
    int_perc = 100;
    percentageR = 100;
  } else {
    int_perc = (int) percentageR + 0.5;
  }

  switch(int_perc) {
  case 0:
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100 "TD_BG">&nbsp;</TD></TR>\n",
		formatKBytes(totalR, formatBuf, sizeof(formatBuf)));
    break;
  case 100:
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100><IMG ALIGN=MIDDLE ALT=\"100\" SRC=\"/gauge.jpg\" WIDTH=\"100\" HEIGHT=12></TD></TR>\n",
		formatKBytes(totalR, formatBuf, sizeof(formatBuf)));
    break;
  default:
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD  WIDTH=100 "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100\">"
		"<TR "TR_ON"><TD><IMG ALT=\"%d%%\" ALIGN=MIDDLE SRC=\"/gauge.jpg\" WIDTH=\"%d\" HEIGHT=12>"
		"</TD><TD "TD_BG" ALIGN=CENTER WIDTH=\"%d\">"
		"<P>&nbsp;</TD></TR></TABLE></TD></TR>\n",
		formatKBytes(totalR, formatBuf, sizeof(formatBuf)),
		int_perc, (100*int_perc)/100, (100*(100-int_perc))/100);
  }

  sendString(buf);
}

/* ********************************** */

void printTableEntryPercentage(char *buf, int bufLen,
			       char *label, char* label_1,
			       char* label_2, float total,
			       float percentage,
			       u_int showFlows, Counter flows) {
  int int_perc;
  char formatBuf[32], flowBuf[64], tmpBuf[32];

  if(percentage < 0.5)
    int_perc = 0;
  else if(percentage > 99.5)
    int_perc = 100;
  else
    int_perc = (int) (percentage + 0.5);

  if(showFlows == 0)
    flowBuf[0] = '\0';
  else
    safe_snprintf(__FILE__, __LINE__, flowBuf, sizeof(flowBuf), 
		  "</TD><TD "TD_BG" ALIGN=RIGHT WIDTH=50>%s", 
		  formatPkts(flows, tmpBuf, sizeof(tmpBuf)));

  switch(int_perc) {
  case 0:
    if(total == -1) {
      safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		    "<TD "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100%%\">"
		    "<TR>"
		    "<TD ALIGN=LEFT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 0&nbsp;%%</TD>"
		    "<TD><TABLE BORDER=1 CELLPADDING=1 CELLSPACING=0 WIDTH=\"100%%\"><TR>"
		    "<TD ALIGN=CENTER WIDTH=\"100%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
		    "</TR></TABLE></TD>"
		    "<TD ALIGN=RIGHT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 100&nbsp;%%</TD></TR></TABLE></TD></TR>\n",
		    getRowColor(), label, CONST_COLOR_1, flowBuf, /* label_1, */
		    CONST_COLOR_2, CONST_COLOR_2, label_2);
    } else {
      safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s %s</TD>"
		    "<TD "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100%%\">"
		    "<TR>"
		    "<TD ALIGN=LEFT WIDTH=\"10%%\"  BGCOLOR=\"%s\">%s 0&nbsp;%%</TD>"
		    "<TD><TABLE BORDER=1 CELLPADDING=1 CELLSPACING=0 WIDTH=\"100%%\"><TR>"
		    "<TD ALIGN=CENTER WIDTH=\"100%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
		    "</TR></TABLE></TD>"
		    "<TD ALIGN=RIGHT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 100&nbsp;%%</TD></TR></TABLE></TD></TR>\n",
		    getRowColor(), label,
		    formatKBytes(total, formatBuf, sizeof(formatBuf)), flowBuf,
		    CONST_COLOR_1, label_1, CONST_COLOR_2,
		    CONST_COLOR_1, label_2);
    }
    break;
  case 100:
    if(total == -1) {
      safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		    "<TD "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100%%\">"
		    "<TR>"
		    "<TD ALIGN=LEFT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 100&nbsp;%%</TD>"
		    "<TD><TABLE BORDER=1 CELLPADDING=1 CELLSPACING=0 WIDTH=\"100%%\"><TR>"
		    "<TD ALIGN=CENTER WIDTH=\"100%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
		    "</TR></TABLE></TD>"
		    "<TD ALIGN=RIGHT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 0&nbsp;%%</TD></TR></TABLE></TD></TR>\n",
		    getRowColor(), label,
		    CONST_COLOR_1, label_1,
		    CONST_COLOR_1,
		    CONST_COLOR_2, label_2);
    } else {
      safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s %s</TD>"
		    "<TD "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100%%\">"
		    "<TR>"
		    "<TD ALIGN=LEFT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 100&nbsp;%%</TD>"
		    "<TD><TABLE BORDER=1 CELLPADDING=1 CELLSPACING=0 WIDTH=\"100%%\"><TR>"
		    "<TD ALIGN=CENTER WIDTH=\"100%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
		    "</TR></TABLE></TD>"
		    "<TD ALIGN=RIGHT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 0&nbsp;%%</TD></TR></TABLE></TD></TR>\n",
		    getRowColor(), label,
		    formatKBytes(total, formatBuf, sizeof(formatBuf)), flowBuf,
		    CONST_COLOR_1, label_1,
		    CONST_COLOR_1,
		    CONST_COLOR_2, label_2);
    }
    break;
  default:
    if(total == -1) {
      safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		    "<TD "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100%%\">"
		    "<TR>"
		    "<TD ALIGN=LEFT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s %.1f&nbsp;%%</TD>"
		    "<TD><TABLE BORDER=1 CELLPADDING=1 CELLSPACING=0 WIDTH=\"100%%\"><TR>"
		    "<TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
		    "<TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
		    "</TR></TABLE></TD>"
		    "<TD ALIGN=RIGHT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s %.1f&nbsp;%%</TD></TR></TABLE></TD></TR>\n",
		    getRowColor(), label,
		    CONST_COLOR_1, label_1, percentage,
		    int_perc, CONST_COLOR_1,
		    (100-int_perc), CONST_COLOR_2,
		    CONST_COLOR_2, label_2, (100-percentage));
    } else {
      safe_snprintf(__FILE__, __LINE__, buf, bufLen,
		    "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>%s %s</TD>"
		    "<TD "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100%%\">"
		    "<TR><TD ALIGN=LEFT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s %.1f&nbsp;%%</TD>"
		    "<TD><TABLE BORDER=1 CELLPADDING=1 CELLSPACING=0 WIDTH=\"100%%\"><TR>"
		    "<TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
		    "<TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
		    "</TR></TABLE></TD>"
		    "<TD ALIGN=RIGHT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s %.1f&nbsp;%%</TD></TR></TABLE></TD></TR>\n",
		    getRowColor(), label, formatKBytes(total, formatBuf, sizeof(formatBuf)), flowBuf,
		    CONST_COLOR_1, label_1, percentage,
		    int_perc, CONST_COLOR_1,
		    (100-int_perc), CONST_COLOR_2,
		    CONST_COLOR_2, label_2, (100-percentage));
    }
  }

  sendString(buf);
}

/* ******************************* */

void printFooterHostLink(void) {
  ;
}

/* ******************************* */

static void printFooterTrafficPct(void) {
    char buf[LEN_GENERAL_WORK_BUFFER];

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                 "<P><TABLE BORDER=0 "TABLE_DEFAULTS">"
                   "<TR>"
                     "<TD COLSPAN=4>The percentage value is - for a given host - the traffic for that host "
                     "during that hour divided by the total traffic for that host for the last 24 hours.</TD>"
                   "</TR>"
                   "<TR>"
                     "<TD ALIGN=CENTER NOWRAP "TD_BG" WIDTH=20%%> 0%% </TD>"
                     "<TD ALIGN=CENTER NOWRAP "CONST_CONST_PCTG_LOW_COLOR" WIDTH=20%%>  0%% to %d%% </TD>"
                     "<TD ALIGN=CENTER NOWRAP "CONST_CONST_PCTG_MID_COLOR" WIDTH=20%%> %d%% to %d%% </TD>"
                     "<TD ALIGN=CENTER NOWRAP "CONST_PCTG_HIGH_COLOR" WIDTH=20%%> &gt;%d%% to 100%% </TD>"
                   "</TR>"
                 "</TABLE>\n",
                 CONST_PCTG_LOW, CONST_PCTG_LOW, CONST_PCTG_MID, CONST_PCTG_MID);
    sendString(buf);
}

/* ******************************* */

void printFooter(int reportType) {
  switch(reportType) {
    case TRAFFIC_STATS:
        break;
    case SORT_DATA_RECEIVED_PROTOS:
    case SORT_DATA_SENT_PROTOS:
    case SORT_DATA_PROTOS:
    case SORT_DATA_RECEIVED_IP:
    case SORT_DATA_SENT_IP:
    case SORT_DATA_IP:
    case SORT_DATA_RCVD_HOST_TRAFFIC:
    case SORT_DATA_SENT_HOST_TRAFFIC:
    case SORT_DATA_RECEIVED_THPT:
    case SORT_DATA_SENT_THPT:
    case SORT_DATA_THPT:
    case SORT_DATA_HOST_TRAFFIC:
      break;
  }

  sendString("<CENTER>\n");

  switch(reportType) {
    case TRAFFIC_STATS:
        break;
    case SORT_DATA_RECEIVED_PROTOS:
    case SORT_DATA_RECEIVED_IP:
    case SORT_DATA_SENT_PROTOS:
    case SORT_DATA_SENT_IP:
    case SORT_DATA_PROTOS:
    case SORT_DATA_IP:
        printFooterHostLink();
        break;

    case SORT_DATA_RCVD_HOST_TRAFFIC:
    case SORT_DATA_SENT_HOST_TRAFFIC:
    case SORT_DATA_HOST_TRAFFIC:
        printFooterHostLink();
        printFooterTrafficPct();
        break;

    case SORT_DATA_RECEIVED_THPT:
    case SORT_DATA_SENT_THPT:
    case SORT_DATA_THPT:
        printFooterHostLink();
        sendString("<i><P>Peak values are the maximum value for any 10 second interval."
		   "<br>Average values are recomputed each 60 seconds, using values "
		   "accumulated since this run of ntop was started.</P>\n");
        sendString("<P>Note: Both values are reset each time ntop is restarted.</P></i>\n");
        break;
  }

  sendString("</CENTER>\n");
}

/* ******************************* */

void printHeader(int reportType, int revertOrder, u_int column,
		 HostsDisplayPolicy showHostsMode,
		 LocalityDisplayPolicy showLocalityMode, 
		 char *vlanList, u_short vlanId) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  char *sign, *arrowGif, *arrow[128], *theAnchor[128], *url=NULL;
  int i, soFar=2, idx, j, hourId, useVlans = 0;
  char htmlAnchor[128], htmlAnchor1[128], theLink[128], theVlanLink[128];
  ProtocolsList *protoList;
  char theDate[8];
  struct tm t;
  char hours[][24] = {"12<BR>AM", "1<BR>AM", "2<BR>AM", "3<BR>AM", "4<BR>AM", "5<BR>AM", "6<BR>AM",
                      "7<BR>AM", "8<BR>AM", "9<BR>AM", "10<BR>AM", "11<BR>AM", "12<BR>PM", "1<BR>PM",
                      "2<BR>PM", "3<BR>PM", "4<BR>PM", "5<BR>PM", "6<BR>PM", "7<BR>PM", "8<BR>PM",
                      "9<BR>PM", "10<BR>PM", "11<BR>PM"};

  for(i=0; i<MAX_VLAN; i++)
    if(vlanList[i] == 1) {
      useVlans = 1;
      break;
    }

  /* printf("->%d<-\n",showHostsMode); */

  strftime(theDate, 8, CONST_TOD_HOUR_TIMESPEC, localtime_r(&myGlobals.actTime, &t));
  hourId = atoi(theDate);
  
  memset(arrow, 0, sizeof(arrow));
  memset(theAnchor, 0, sizeof(theAnchor));
  memset(htmlAnchor, 0, sizeof(htmlAnchor));
  memset(htmlAnchor1, 0, sizeof(htmlAnchor1));

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
  } else {
    sign = "-";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
  }

  memset(buf, 0, sizeof(buf));

  switch(reportType) {
  case TRAFFIC_STATS:               url = CONST_TRAFFIC_STATS_HTML;               break;
  case SORT_DATA_PROTOS:            url = CONST_SORT_DATA_PROTOS_HTML;            break;
  case SORT_DATA_IP:                url = CONST_SORT_DATA_IP_HTML;                break;
  case SORT_DATA_THPT:              url = CONST_SORT_DATA_THPT_HTML;              break;
  case SORT_DATA_HOST_TRAFFIC:      url = CONST_SORT_DATA_HOST_TRAFFIC_HTML;      break;
  }

  safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor),
              "<A HREF=\"/%s?showH=%d&amp;showL=%d&amp;col=%s",
              url, showHostsMode, showLocalityMode, sign);
  safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1),
              "<A HREF=\"/%s?showH=%d&amp;showL=%d&amp;col=",
              url, showHostsMode, showLocalityMode);

  if(abs(column) == FLAG_HOST_DUMMY_IDX)
    arrow[0] = arrowGif, theAnchor[0] = htmlAnchor;
    else
    arrow[0] = "", theAnchor[0] = htmlAnchor1;  

  if(abs(column) == FLAG_DOMAIN_DUMMY_IDX)
    arrow[1] = arrowGif, theAnchor[1] = htmlAnchor;
  else
    arrow[1] = "",  theAnchor[1] = htmlAnchor1;
  
  if(abs(column) == 0)
    arrow[2] = arrowGif, theAnchor[2] = htmlAnchor;
  else 
    arrow[2] = "", theAnchor[2] = htmlAnchor1;

  if((vlanId > 0) && (vlanId < MAX_VLAN))
    safe_snprintf(__FILE__, __LINE__, theLink, sizeof(theLink), "/%s?col=%s%d&amp;vlan=%d&amp;showL=%d&amp;showH=", url,
		  revertOrder ? "-" : "", column, vlanId, showLocalityMode);
  else
    safe_snprintf(__FILE__, __LINE__, theLink, sizeof(theLink), "/%s?col=%s%d&amp;showL=%d&amp;showH=", url,
		  revertOrder ? "-" : "", column, showLocalityMode);

  safe_snprintf(__FILE__, __LINE__, theVlanLink, sizeof(theVlanLink), "/%s?col=%s%d&amp;showL=%d&amp;showH=%d", url,
	   revertOrder ? "-" : "", column, showLocalityMode, showHostsMode);

  sendString("<CENTER><TABLE WIDTH=100%% BORDER=0 "TABLE_DEFAULTS"><TR><TD ALIGN=LEFT>");

  sendString("<p><form action=\"../\">\n<b>Hosts</b>:"
	     "<select onchange=\"window.open(this.options[this.selectedIndex].value,'_top')\">\n");
  
  switch(showHostsMode) {
  case showOnlyLocalHosts:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<option value=\"%s0\" >All</option>\n"
		  "<option value=\"%s1\" selected>Local Only</option>\n"
		  "<option value=\"%s2\" >Remote Only</option>\n"
		  "</select>\n",
		  theLink, theLink, theLink);
    break;
  case showOnlyRemoteHosts:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<option value=\"%s0\" >All</option>\n"
		  "<option value=\"%s1\" >Local Only</option>\n"
		  "<option value=\"%s2\" selected>Remote Only</option>\n"
		  "</select>\n",
		  theLink, theLink, theLink);
    break;
  default:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<option value=\"%s0\" selected>All</option>\n"
		  "<option value=\"%s1\" >Local Only</option>\n"
		  "<option value=\"%s2\" >Remote Only</option>\n"
		  "</select>\n",
		  theLink, theLink, theLink);
    break;
  }

  sendString(buf);

  if(useVlans) {
    u_char found = 0;

    sendString("<p><b>VLAN</b>: ");

    for(i=0; i<MAX_VLAN; i++)
      if(vlanList[i] == 1) {
	if(i == vlanId)
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[ <b>%d</b> ] ", i), found = 1;
	else
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[ <A HREF=\"%s&vlan=%d\">%d</A> ] ", theVlanLink, i, i);
	
	sendString(buf);
      }

    if(!found)
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[ <b>All</b> ] ");
    else
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[ <A HREF=\"%s\">All</A> ] ", theVlanLink);

    sendString(buf);
  }

  sendString("</TD>");

  if(reportType != TRAFFIC_STATS) {
    sendString("<TD ALIGN=right><form action=\"../\">\n<b>Data</b>:"
	       "<select onchange=\"window.open(this.options[this.selectedIndex].value,'_top')\">\n");

    switch(showLocalityMode) {
    case showSentReceived:
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		    "<option value=\"%s?col=%s%d&showH=%d&showL=0\" selected>All</option>\n"
		    "<option value=\"%s?col=%s%d&showH=%d&showL=1\">Sent Only</option>\n"
		    "<option value=\"%s?col=%s%d&showH=%d&showL=2\">Received Only</option>\n",
		    url, revertOrder ? "-" : "", column, showHostsMode,
		    url, revertOrder ? "-" : "", column, showHostsMode,
		    url, revertOrder ? "-" : "", column, showHostsMode);
      break;
    case showOnlySent:
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		    "<option value=\"%s?col=%s%d&showH=%d&showL=0\">All</option>\n"
		    "<option value=\"%s?col=%s%d&showH=%d&showL=1\" selected>Sent Only</option>\n"
		    "<option value=\"%s?col=%s%d&showH=%d&showL=2\">Received Only</option>\n",
		    url, revertOrder ? "-" : "", column, showHostsMode,
		    url, revertOrder ? "-" : "", column, showHostsMode,
		    url, revertOrder ? "-" : "", column, showHostsMode);
      break;
    default:
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		    "<option value=\"%s?col=%s%d&showH=%d&showL=0\">All</option>\n"
		    "<option value=\"%s?col=%s%d&showH=%d&showL=1\">Sent Only</option>\n"
		    "<option value=\"%s?col=%s%d&showH=%d&showL=2\" selected>Received Only</option>\n",
		    url, revertOrder ? "-" : "", column, showHostsMode,
		    url, revertOrder ? "-" : "", column, showHostsMode,
		    url, revertOrder ? "-" : "", column, showHostsMode);
      break;
    }

    sendString(buf);
    sendString("</TD></TR></TABLE></CENTER><p>");
  }

  switch(reportType) {
  case SORT_DATA_RECEIVED_PROTOS:
  case SORT_DATA_SENT_PROTOS:
  case SORT_DATA_PROTOS:
    sendString("<CENTER>\n");
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, 
		  ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON" "DARK_BG">"
		  "<TH "TH_BG">%s"FLAG_HOST_DUMMY_IDX_STR"\">Host%s</A></TH>\n"
		  "<TH "TH_BG">%s"FLAG_DOMAIN_DUMMY_IDX_STR"\">Location%s</A></TH>"
		  "<TH "TH_BG" COLSPAN=2>%s0\">Data%s</A></TH>\n",
		  theAnchor[0], arrow[0], theAnchor[1], arrow[1],
		  theAnchor[2], arrow[2]);
    sendString(buf);
    
    for(i=0; i<=15; i++)
      if(abs(column) == i+1) {
	arrow[i] = arrowGif; theAnchor[i] = htmlAnchor; 
      } else {
	arrow[i] = ""; theAnchor[i] = htmlAnchor1;  
      }

    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG">%s1\">TCP%s</A></TH>"
		  "<TH "TH_BG">%s2\">UDP%s</A></TH><TH "TH_BG">%s3\">ICMP%s</A></TH>"
		  "<TH "TH_BG">%s4\">ICMPv6%s</A></TH>"
		  "<TH "TH_BG">%s5\">DLC%s</A></TH><TH "TH_BG">%s6\">IPX%s</A>"
		  "</TH><TH "TH_BG">%s7\">IPsec%s</A></TH>"
		  "<TH "TH_BG">%s8\">(R)ARP%s</A></TH><TH "TH_BG">%s9\">AppleTalk%s</A></TH>",
		  theAnchor[0], arrow[0], theAnchor[1], arrow[1],
		  theAnchor[2], arrow[2], theAnchor[3], arrow[3],
		  theAnchor[4], arrow[4],
		  theAnchor[5], arrow[5], theAnchor[6], arrow[6],
		  theAnchor[7], arrow[7], theAnchor[8], arrow[8]);
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER,
		  "<TH "TH_BG">%s11\">NetBios%s</A></TH>"
		  "<TH "TH_BG">%s13\">GRE%s</A></TH>"
		  "<TH "TH_BG">%s14\">IPv6%s</A></TH>"
		  "<TH "TH_BG">%s15\">STP%s</A></TH>",
		  theAnchor[10], arrow[10],
		  theAnchor[12], arrow[12],
		  theAnchor[13], arrow[13],
		  theAnchor[14], arrow[14]);
    sendString(buf);

    protoList = myGlobals.ipProtosList, idx=0;
    while(protoList != NULL) {

      if(abs(column) == BASE_PROTOS_IDX+idx) {
	arrow[BASE_PROTOS_IDX+idx] = arrowGif;
	theAnchor[BASE_PROTOS_IDX+idx] = htmlAnchor;
      } else {
	arrow[BASE_PROTOS_IDX+idx] = "";
	theAnchor[BASE_PROTOS_IDX+idx] = htmlAnchor1;
      }

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TH "TH_BG">%s%d\">%s%s</A></TH>",
		  theAnchor[BASE_PROTOS_IDX+idx], BASE_PROTOS_IDX+idx,
		  protoList->protocolName, arrow[BASE_PROTOS_IDX+idx]);
      sendString(buf);

      idx++, protoList = protoList->next;
    }

    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER,
		"<TH "TH_BG">%s16\">Other%s</A></TH>",
		theAnchor[15], arrow[15]);
    sendString(buf);
    break;

  case SORT_DATA_RECEIVED_IP:
  case SORT_DATA_SENT_IP:
  case SORT_DATA_IP:
    sendString("<CENTER>\n");
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON" "DARK_BG">"
		"<TH "TH_BG">%s"FLAG_HOST_DUMMY_IDX_STR"\">Host%s</A></TH>\n"
		"<TH "TH_BG">%s"FLAG_DOMAIN_DUMMY_IDX_STR"\">Location%s</A></TH>"
		"<TH "TH_BG" COLSPAN=2>%s0\">Data%s</A></TH>\n",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1],
		theAnchor[2], arrow[2]);
    sendString(buf);
    if(abs(column) == 1) {
      arrow[0] = arrowGif;
      theAnchor[0] = htmlAnchor;
    } else {
      arrow[0] = "";
      theAnchor[0] = htmlAnchor1;
    }

    for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
      if(abs(column) == soFar) {
	arrow[0] = arrowGif;
	theAnchor[0] = htmlAnchor;
      } else {
	arrow[0] = "";
	theAnchor[0] = htmlAnchor1;
      }
      safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG">%s%d\">%s%s</A></TH>",
		  theAnchor[0], i+2, myGlobals.ipTrafficProtosNames[i], arrow[0]);
      sendString(buf);
      soFar++;
    }

    if(abs(column) == soFar) {
      arrow[0] = arrowGif; theAnchor[0] = htmlAnchor;
    } else {
      arrow[0] = "";  theAnchor[0] = htmlAnchor1;
    }
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG">%s%d\">Other&nbsp;IP%s</A></TH>",
		theAnchor[0], i+2, arrow[0]);
    sendString(buf);
    break;

  case SORT_DATA_RCVD_HOST_TRAFFIC:
  case SORT_DATA_SENT_HOST_TRAFFIC:
  case SORT_DATA_HOST_TRAFFIC:
    sendString("<CENTER>\n");
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "DARK_BG">"
		"<TH "TH_BG">%s"FLAG_HOST_DUMMY_IDX_STR"\">Host%s</A></TH>"
		"<TH "TH_BG">%s"FLAG_DOMAIN_DUMMY_IDX_STR"\">Location%s</A></TH>\n",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1]);
    sendString(buf);
    j = hourId;
    for (i = 0; i < 24; i++) {
        j = j % 24;
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TH "TH_BG">%s</TH>\n", hours[j]);
        sendString (buf);
        if (!j) {
            j = 23;
        }
        else {
            j--;
        }
    }
    break;
  case SORT_DATA_RECEIVED_THPT:
  case SORT_DATA_SENT_THPT:
  case SORT_DATA_THPT:
    sendString("<CENTER>\n");
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, ""TABLE_ON
		  "<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON" "DARK_BG">"
		  "<TH "TH_BG" ROWSPAN=\"2\">%s"FLAG_HOST_DUMMY_IDX_STR"\">Host%s</A></TH>"
		  "<TH "TH_BG" ROWSPAN=\"2\">%s"FLAG_DOMAIN_DUMMY_IDX_STR"\">Location%s</A></TH>\n\n",
		  theAnchor[0], arrow[0], theAnchor[1], arrow[1]);
    sendString(buf);

    updateThpt(0);
    if(abs(column) == 1) { arrow[0] = arrowGif; theAnchor[0] = htmlAnchor; }
    else { arrow[0] = ""; theAnchor[0] = htmlAnchor1;  }
    if(abs(column) == 2) { arrow[1] = arrowGif; theAnchor[1] = htmlAnchor; }
    else { arrow[1] = ""; theAnchor[1] = htmlAnchor1; }
    if(abs(column) == 3) { arrow[2] = arrowGif; theAnchor[2] = htmlAnchor; }
    else { arrow[2] = "";  theAnchor[2] = htmlAnchor1;}
    if(abs(column) == 4) { arrow[3] = arrowGif; theAnchor[3] = htmlAnchor; }
    else { arrow[3] = "";  theAnchor[3] = htmlAnchor1;}
    if(abs(column) == 5) { arrow[4] = arrowGif; theAnchor[4] = htmlAnchor; }
    else { arrow[4] = "";  theAnchor[4] = htmlAnchor1;}
    if(abs(column) == 6) { arrow[5] = arrowGif; theAnchor[5] = htmlAnchor; }
    else { arrow[5] = "";  theAnchor[5] = htmlAnchor1;}

    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG" COLSPAN=\"3\" ALIGN=CENTER>Data</TH>"
		"<TH "TH_BG" COLSPAN=\"3\" ALIGN=CENTER>Packets</TH>"
		"</TR><TR "TR_ON" "DARK_BG">");
    sendString(buf);
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG">%s1\">Current%s</A></TH>"
		"<TH "TH_BG">%s2\">Avg%s</A></TH>"
		"<TH "TH_BG">%s3\">Peak%s</A></TH>"
		"<TH "TH_BG">%s4\">Current%s</A></TH><TH "TH_BG">%s5\">Avg%s</A></TH>"
		"<TH "TH_BG">%s6\">Peak%s</A></TH>",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1], theAnchor[2], arrow[2],
		theAnchor[3], arrow[3], theAnchor[4], arrow[4], theAnchor[5], arrow[5]);
    sendString(buf);
    break;
  case TRAFFIC_STATS:
    sendString("<CENTER>\n");
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, 
		  ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON" "DARK_BG">"
		  "<TH "TH_BG">%s"FLAG_HOST_DUMMY_IDX_STR"\">Host%s</A></TH>"
		  "<TH "TH_BG">%s"FLAG_DOMAIN_DUMMY_IDX_STR"\">Location%s</A></TH>\n\n",
		  theAnchor[0], arrow[0], theAnchor[1], arrow[1]);
    sendString(buf);
    break;
  }

  sendString("</TR>\n");
}

/* ******************************* */

char* _getOSFlag(HostTraffic *el, char *elOsName, int showOsName, char *tmpStr, int tmpStrLen, char *file, int line) {
  /* Lengthen tmpString buffer - to handle long name given by nmap for Win2k
     Courtesy of Marcel Hauser <marcel_hauser@gmx.ch> */
  char *flagImg = "";
  char *theOsName;
  int i;

  if((el == NULL) && (elOsName == NULL)) return("");

  tmpStr[0] = '\0';

  if(elOsName != NULL)
    theOsName = elOsName;
  else {
    if(el->fingerprint == NULL)   return("");
    if(el->fingerprint[0] != ':') setHostFingerprint(el);
    if(el->fingerprint[0] != ':') return("");
    theOsName = &el->fingerprint[1];
  }

  if(theOsName[0] == '\0') return("");

  flagImg = NULL;

  for(i=0; osInfos[i].link != NULL; i++) {
    if(strstr(theOsName, osInfos[i].name) != NULL) {
      flagImg = osInfos[i].link;
      break;
    }
  }

  if(!showOsName) {
    if(flagImg != NULL) {
      safe_snprintf(file, line, tmpStr, tmpStrLen, "%s", flagImg);
    } else
      tmpStr[0] = '\0';
  } else {
    if(flagImg != NULL) {
      safe_snprintf(file, line, tmpStr, tmpStrLen, "%s&nbsp;[%s]", flagImg, theOsName);
    } else {
      safe_snprintf(file, line, tmpStr, tmpStrLen, "%s", theOsName);
    }
  }

  return(tmpStr);
}

/* ******************************* */

int sortHostFctn(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  int rc, n_a, n_b;
  char *nameA, *nameB, nameA_str[32], nameB_str[32];

  if((a == NULL) && (b != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortHostFctn() error (1)");
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortHostFctn() error (2)");
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "sortHostFctn() error (3)");
    return(0);
  }

  switch(myGlobals.columnSort) {
  case 1:
    rc=cmpFctnResolvedName(a, b);
    return(rc);
    break;
  case 2:
      if (isFcHost ((*a)) && isFcHost ((*b))) {
	if((*a)->fcCounters->hostFcAddress.domain > (*b)->fcCounters->hostFcAddress.domain)
              return(1);
          else if ((*a)->fcCounters->hostFcAddress.domain < (*b)->fcCounters->hostFcAddress.domain)
              return (-1);
          else {
              if ((*a)->fcCounters->hostFcAddress.area > (*b)->fcCounters->hostFcAddress.area)
                  return (1);
              else if ((*a)->fcCounters->hostFcAddress.area < (*b)->fcCounters->hostFcAddress.area)
                  return (-1);
              else {
                  if ((*a)->fcCounters->hostFcAddress.port > (*b)->fcCounters->hostFcAddress.port)
                      return (1);
                  else if ((*a)->fcCounters->hostFcAddress.port < (*b)->fcCounters->hostFcAddress.port)
                      return (-1);
                  else
                      return (0);
              }
          }
      }
      else {
          rc = addrcmp(&(*a)->hostIpAddress,&(*b)->hostIpAddress);
          return(rc);
      }
    break;
  case 3:
      if (isFcHost ((*a)) && isFcHost ((*b))) {
          n_a = (*a)->fcCounters->vsanId, n_b = (*b)->fcCounters->vsanId;
          return ((n_a < n_b) ? -1 : (n_a > n_b) ? 1 : 0);
      }
      else {
          return(strcasecmp((*a)->ethAddressString, (*b)->ethAddressString));
      }
  case 5:
      if (isFcHost ((*a)) && isFcHost ((*b))) {
	return(strcasecmp(getVendorInfo(&((*a)->fcCounters->pWWN.str[2]), 0),
			  getVendorInfo(&((*b)->fcCounters->pWWN.str[2]), 0)));
      }
      else {
          return(strcasecmp(getVendorInfo((*a)->ethAddress, 0),
                            getVendorInfo((*b)->ethAddress, 0)));
      }
      break;
  case 6:
    if((*a)->nonIPTraffic == NULL) {
      nameA = "";
    } else {
    if((*a)->nonIPTraffic->nbHostName != NULL)
      nameA = (*a)->nonIPTraffic->nbHostName;
    else if((*a)->nonIPTraffic->atNodeName != NULL)
      nameA = (*a)->nonIPTraffic->atNodeName;
    else if((*a)->nonIPTraffic->atNetwork != 0) {
      safe_snprintf(__FILE__, __LINE__, nameA_str, sizeof(nameA_str), "%d.%d",
		  (*a)->nonIPTraffic->atNetwork, (*a)->nonIPTraffic->atNode);
      nameA = nameA_str;
    } else if((*a)->nonIPTraffic->ipxHostName != NULL)
      nameA = (*a)->nonIPTraffic->ipxHostName;
    else
      nameA = "";
    }

    if((*b)->nonIPTraffic == NULL) {
      nameB = "";
    } else {
    if((*b)->nonIPTraffic->nbHostName != NULL)
      nameB = (*b)->nonIPTraffic->nbHostName;
    else if((*b)->nonIPTraffic->atNodeName != NULL)
      nameB = (*b)->nonIPTraffic->atNodeName;
    else if((*b)->nonIPTraffic->atNetwork != 0) {
      safe_snprintf(__FILE__, __LINE__, nameB_str, sizeof(nameB_str), "%d.%d",
		  (*b)->nonIPTraffic->atNetwork, (*b)->nonIPTraffic->atNode);
      nameB = nameB_str;
    } else if((*b)->nonIPTraffic->ipxHostName != NULL)
      nameB = (*b)->nonIPTraffic->ipxHostName;
    else
      nameB = "";
    }

    return(strcasecmp(nameA, nameB));
    break;
  case 7:
    n_a = guessHops(*a);
    n_b = guessHops(*b);

    if(n_a < n_b)
      return(1);
    else if(n_a > n_b)
      return(-1);
    else
      return(0);
    break;
  case 8:
    n_a = (*a)->totContactedSentPeers+(*a)->totContactedRcvdPeers;
    n_b = (*b)->totContactedSentPeers+(*b)->totContactedRcvdPeers;

    if(n_a < n_b)
      return(1);
    else if(n_a > n_b)
      return(-1);
    else
      return(0);
    break;
  case 9:
    n_a = (*a)->lastSeen-(*a)->firstSeen;
    n_b = (*b)->lastSeen-(*b)->firstSeen;

    if(n_a < n_b)
      return(1);
    else if(n_a > n_b)
      return(-1);
    else
      return(0);
    break;
  case 10:
    n_a = (*a)->hostAS, n_b = (*b)->hostAS;

    if(n_a < n_b)
      return(1);
    else if(n_a > n_b)
      return(-1);
    else
      return(0);
    break;
  case 11:
   return(strcasecmp((*a)->community ? (*a)->community : "",
		      (*b)->community ? (*b)->community : ""));
    break;
  case 12:
    return(memcmp(&(*a)->flags, &(*b)->flags, sizeof(fd_set)));
    break;

  case CONST_VLAN_COLUMN_SORT:
    n_a = (*a)->vlanId, n_b = (*b)->vlanId;

    if(n_a < n_b)
      return(1);
    else if(n_a > n_b)
      return(-1);
    else
      return(0);
    break;
  case FLAG_DOMAIN_DUMMY_IDX:
    rc = cmpFctnLocationName(a, b);
    return(rc);
    break;
  case 4:
  default:
    if((*a)->actBandwidthUsage < (*b)->actBandwidthUsage)
      return(1);
    else if ((*a)->actBandwidthUsage > (*b)->actBandwidthUsage)
      return(-1);
    else
      return(0);
    break;
  }
}

/* ******************************* */

int cmpUsersTraffic(const void *_a, const void *_b) {
  UsersTraffic **a = (UsersTraffic **)_a;
  UsersTraffic **b = (UsersTraffic **)_b;
  Counter sum_a, sum_b;

  if((a == NULL) && (b != NULL)) {
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    return(0);
  }

  sum_a = (*a)->bytesSent + (*a)->bytesRcvd;
  sum_b = (*b)->bytesSent + (*b)->bytesRcvd;

  if(sum_a > sum_b)
    return(-1);
  else if (sum_a == sum_b)
    return(0);
  else
    return(1);
}

/* ******************************* */

int cmpProcesses(const void *_a, const void *_b) {
  ProcessInfo **a = (ProcessInfo **)_a;
  ProcessInfo **b = (ProcessInfo **)_b;

  if((a == NULL) && (b != NULL)) {
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    return(0);
  }

  switch(myGlobals.columnSort) {
  case 2: /* PID */
    if((*a)->pid == (*b)->pid)
      return(0);
    else if((*a)->pid < (*b)->pid)
      return(1);
    else return(-1);
    break;
  case 3: /* User */
    return(strcasecmp((*a)->user, (*b)->user));
    break;
  case 4: /* Sent */
    if((*a)->bytesSent.value == (*b)->bytesSent.value)
      return(0);
    else if((*a)->bytesSent.value < (*b)->bytesSent.value)
      return(1);
    else return(-1);
    break;
  case 5: /* Rcvd */
    if((*a)->bytesRcvd.value == (*b)->bytesRcvd.value)
      return(0);
    else if((*a)->bytesRcvd.value < (*b)->bytesRcvd.value)
      return(1);
    else return(-1);
    break;
  default: /* Process name */
    return(strcasecmp((*a)->command, (*b)->command));
  }
}

/* ******************************* */

static int cmpOSFctn(const void *_a, const void *_b) {
  OsNumInfo *a = (OsNumInfo *)_a;
  OsNumInfo *b = (OsNumInfo *)_b;

  if(a->num < b->num)
    return(1);
  else
    return(-1);
}

/* ******************************* */

int cmpFctnLocationName(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  char *c_a = "", *c_b = "";

  if((a != NULL) && (*a != NULL)
     && (*a)->geo_ip && ((*a)->geo_ip->country_code != NULL))
    c_a = (*a)->geo_ip->country_code;

  if((b != NULL) && (*b != NULL) 
     && (*b)->geo_ip && ((*b)->geo_ip->country_code != NULL))
    c_b = (*b)->geo_ip->country_code;
  
  return(strcmp(c_a, c_b));
}

/* ******************************* */

int cmpFctn(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter a_=0, b_=0, a_val, b_val;
  float fa_=0, fb_=0;
  short floatCompare=0, columnProtoId;

  if((a == NULL) && (b != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpFctn() error (1)");
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpFctn() error (2)");
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpFctn() error (3)");
    return(0);
  } else if((*a == NULL) && (*b != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpFctn() error (4)");
    return(1);
  } else if((*a != NULL) && (*b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpFctn() error (5)");
    return(-1);
  } else if((*a == NULL) && (*b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpFctn() error (6)");
    return(0);
  }

  if(myGlobals.columnSort == FLAG_HOST_DUMMY_IDX) {
    return(cmpFctnResolvedName(a, b));
  } else if(myGlobals.columnSort == FLAG_DOMAIN_DUMMY_IDX) {
    int rc;

    fillDomainName(*a); fillDomainName(*b);

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "%s='%s'/'%s' - %s='%s'/'%s'",
	   (*a)->hostResolvedName,
	   (*a)->ip2ccValue, (*a)->dnsDomainValue,
	   (*b)->hostResolvedName,
	   (*b)->ip2ccValue, (*b)->dnsDomainValue
	   );
#endif

    rc = cmpFctnLocationName(a, b);
    return(rc);
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO,
	     "reportKind=%d/columnSort=%d/numIpProtosToMonitor=%d\n",
	     myGlobals.reportKind, myGlobals.columnSort,
	     myGlobals.numIpProtosToMonitor);
#endif

  switch(myGlobals.reportKind) {
  case SORT_DATA_RECEIVED_PROTOS:
    switch(myGlobals.columnSort) {
    case 0:
      a_ = (*a)->bytesRcvd.value, b_ = (*b)->bytesRcvd.value;
      break;
    case 1:
      a_ = (*a)->tcpRcvdLoc.value + (*a)->tcpRcvdFromRem.value;
      b_ = (*b)->tcpRcvdLoc.value + (*b)->tcpRcvdFromRem.value;
      break;
    case 2:
      a_ = (*a)->udpRcvdLoc.value + (*a)->udpRcvdFromRem.value;
      b_ = (*b)->udpRcvdLoc.value + (*b)->udpRcvdFromRem.value;
      break;
    case 3:
      a_ = (*a)->icmpRcvd.value, b_ = (*b)->icmpRcvd.value;
      break;
    case 4:
      a_ = (*a)->icmp6Rcvd.value, b_ = (*b)->icmp6Rcvd.value;
      break;
    case 5:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->dlcRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->dlcRcvd.value;
      break;
    case 6:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->ipxRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->ipxRcvd.value;
      break;
    case 7:
      a_ = (*a)->ipsecRcvd.value;
      b_ = (*b)->ipsecRcvd.value;
      break;
    case 8:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->arp_rarpRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->arp_rarpRcvd.value;
      break;
    case 9:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->appletalkRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->appletalkRcvd.value;
      break;
    case 11:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->netbiosRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->netbiosRcvd.value;
      break;
    case 13:
      a_ = (*a)->greRcvd.value;
      b_ = (*b)->greRcvd.value;
      break;
    case 14:
      a_ = (*a)->ipv6BytesRcvd.value, b_ = (*b)->ipv6BytesRcvd.value;
      break;
    case 15:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->stpRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->stpRcvd.value;
      break;
    case 16:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->otherRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->otherRcvd.value;
      break;
    default:
      if((myGlobals.columnSort >= BASE_PROTOS_IDX)
	 && (myGlobals.columnSort < (BASE_PROTOS_IDX+myGlobals.numIpProtosList))) {
	int idx = myGlobals.columnSort-BASE_PROTOS_IDX;

	if((*a)->ipProtosList && (*a)->ipProtosList[idx])
	  a_ = (*a)->ipProtosList[idx]->rcvd.value;
	else
	  a_ = 0;

	if((*b)->ipProtosList && (*b)->ipProtosList[idx])
	  b_ = (*b)->ipProtosList[idx]->rcvd.value;
	else
	  b_ = 0;
      }
      break;
    }
    break;
  case SORT_DATA_RECEIVED_IP:
    columnProtoId = myGlobals.columnSort - 1;
    if((columnProtoId != -1) && (columnProtoId <= myGlobals.numIpProtosToMonitor)) {
      if(columnProtoId <= 0) {
	a_ = b_ = 0;
      } else {
	if((*a)->protoIPTrafficInfos[columnProtoId-1])
	  a_ = (*a)->protoIPTrafficInfos[columnProtoId-1]->rcvdLoc.value+
	    (*a)->protoIPTrafficInfos[columnProtoId-1]->rcvdFromRem.value;
	else
	  a_ = 0;

	if((*b)->protoIPTrafficInfos[columnProtoId-1])
	  b_ = (*b)->protoIPTrafficInfos[columnProtoId-1]->rcvdLoc.value+
	    (*b)->protoIPTrafficInfos[columnProtoId-1]->rcvdFromRem.value;
	else
	  b_ = 0;
      }
    } else {
      a_ = (*a)->ipv4BytesRcvd.value, b_ = (*b)->ipv4BytesRcvd.value;

      if(myGlobals.numIpProtosToMonitor == (columnProtoId-1)) {
	/* other IP */
	int i;

	for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	  if((*a)->protoIPTrafficInfos[i])
	    a_val = ((*a)->protoIPTrafficInfos[i]->rcvdLoc.value
		     +(*a)->protoIPTrafficInfos[i]->rcvdFromRem.value);
	  else
	    a_val = 0;

	  if((*b)->protoIPTrafficInfos[i])
	    b_val = ((*b)->protoIPTrafficInfos[i]->rcvdLoc.value
		     +(*b)->protoIPTrafficInfos[i]->rcvdFromRem.value);
	  else
	    b_val = 0;

	  /* Better be safe... */
	  if(a_ > a_val) a_ -= a_val; else a_ = 0;
	  if(b_ > b_val) b_ -= b_val; else b_ = 0;
	}
      }
    }
    break;
  case SORT_DATA_RECEIVED_THPT:
    switch(myGlobals.columnSort) {
    case 1:
      fa_ = (*a)->actualRcvdThpt, fb_ = (*b)->actualRcvdThpt, floatCompare = 1;
      break;
    case 2:
      fa_ = (*a)->averageRcvdThpt, fb_ = (*b)->averageRcvdThpt, floatCompare = 1;
      break;
    case 3:
      fa_ = (*a)->peakRcvdThpt, fb_ = (*b)->peakRcvdThpt, floatCompare = 1;
      break;
    case 4:
      fa_ = (*a)->actualRcvdPktThpt, fb_ = (*b)->actualRcvdPktThpt, floatCompare = 1;
      break;
    case 5:
      fa_ = (*a)->averageRcvdPktThpt, fb_ = (*b)->averageRcvdPktThpt, floatCompare = 1;
      break;
    case 6:
      fa_ = (*a)->peakRcvdPktThpt, fb_ = (*b)->peakRcvdPktThpt, floatCompare = 1;
      break;
    }
    break;
  case SORT_DATA_RCVD_HOST_TRAFFIC:
  case SORT_DATA_SENT_HOST_TRAFFIC:
  case SORT_DATA_HOST_TRAFFIC:
    /* Nothing */
    break;
  case SORT_DATA_SENT_PROTOS:
    switch(myGlobals.columnSort) {
    case 0:
      a_ = (*a)->bytesSent.value, b_ = (*b)->bytesSent.value;
      break;
    case 1:
      a_ = (*a)->tcpSentLoc.value + (*a)->tcpSentRem.value;
      b_ = (*b)->tcpSentLoc.value + (*b)->tcpSentRem.value;
      break;
    case 2:
      a_ = (*a)->udpSentLoc.value + (*a)->udpSentRem.value;
      b_ = (*b)->udpSentLoc.value + (*b)->udpSentRem.value;
      break;
    case 3:
      a_ = (*a)->icmpSent.value, b_ = (*b)->icmpSent.value;
      break;
    case 4:
      a_ = (*a)->icmp6Sent.value, b_ = (*b)->icmp6Sent.value;
      break;
    case 5:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->dlcSent.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->dlcSent.value;
      break;
    case 6:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->ipxSent.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->ipxSent.value;
      break;
    case 7:
      a_ = (*a)->ipsecSent.value;
      b_ = (*b)->ipsecSent.value;
      break;
    case 8:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->arp_rarpSent.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->arp_rarpSent.value;
      break;
    case 9:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->appletalkSent.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->appletalkSent.value;
      break;
    case 11:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->netbiosSent.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->netbiosSent.value;
      break;
    case 13:
      a_ = (*a)->greSent.value;
      b_ = (*b)->greSent.value;
      break;
    case 14:
      a_ = (*a)->ipv6BytesSent.value, b_ = (*b)->ipv6BytesSent.value;
      break;
    case 15:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->stpSent.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->stpSent.value;
      break;
    case 16:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->otherSent.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->otherSent.value;
      break;
    default:
      if((myGlobals.columnSort >= BASE_PROTOS_IDX)
	 && (myGlobals.columnSort < (BASE_PROTOS_IDX+myGlobals.numIpProtosList))) {
	int idx = myGlobals.columnSort-BASE_PROTOS_IDX;

	if((*a)->ipProtosList && (*a)->ipProtosList[idx])
	  a_ = (*a)->ipProtosList[idx]->sent.value;
	else 
	  a_ = 0;
	
	if((*b)->ipProtosList && (*b)->ipProtosList[idx])
	  b_ = (*b)->ipProtosList[idx]->sent.value;
	else
	  b_ = 0;
      }
      break;
    }
    break;
  case SORT_DATA_SENT_IP:
    columnProtoId = myGlobals.columnSort - 1;
    if((columnProtoId != -1) && (columnProtoId <= myGlobals.numIpProtosToMonitor)) {
      if(columnProtoId <= 0) {
	a_ = b_ = 0;
      } else {
	if((*a)->protoIPTrafficInfos[columnProtoId-1])
	  a_ = (*a)->protoIPTrafficInfos[columnProtoId-1]->sentLoc.value
	    +(*a)->protoIPTrafficInfos[columnProtoId-1]->sentRem.value;
	else
	  a_ = 0;

	if((*b)->protoIPTrafficInfos[columnProtoId-1])
	  b_ = (*b)->protoIPTrafficInfos[columnProtoId-1]->sentLoc.value
	    +(*b)->protoIPTrafficInfos[columnProtoId-1]->sentRem.value;
	else
	  b_ = 0;
      }
    } else {
      a_ = (*a)->ipv4BytesSent.value, b_ = (*b)->ipv4BytesSent.value;

      if(myGlobals.numIpProtosToMonitor == (columnProtoId-1)) {
	/* other IP */
	int i;

	for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	  if((*a)->protoIPTrafficInfos[i])
	    a_val = ((*a)->protoIPTrafficInfos[i]->sentLoc.value
		     +(*a)->protoIPTrafficInfos[i]->sentRem.value);
	  else
	    a_val = 0;

	  if((*b)->protoIPTrafficInfos[i])
	    b_val = ((*b)->protoIPTrafficInfos[i]->sentLoc.value
		     +(*b)->protoIPTrafficInfos[i]->sentRem.value);
	  else
	    b_val = 0;

	  /* Better be safe... */
	  if(a_ > a_val) a_ -= a_val; else a_ = 0;
	  if(b_ > b_val) b_ -= b_val; else b_ = 0;
	}
      }
    }
    break;
  case SORT_DATA_SENT_THPT:
    switch(myGlobals.columnSort) {
    case 1:
      fa_ = (*a)->actualSentThpt, fb_ = (*b)->actualSentThpt, floatCompare = 1;
      break;
    case 2:
      fa_ = (*a)->averageSentThpt, fb_ = (*b)->averageSentThpt, floatCompare = 1;
      break;
    case 3:
      fa_ = (*a)->peakSentThpt, fb_ = (*b)->peakSentThpt, floatCompare = 1;
      break;
    case 4:
      fa_ = (*a)->actualSentPktThpt, fb_ = (*b)->actualSentPktThpt, floatCompare = 1;
      break;
    case 5:
      fa_ = (*a)->averageSentPktThpt, fb_ = (*b)->averageSentPktThpt, floatCompare = 1;
      break;
    case 6:
      fa_ = (*a)->peakSentPktThpt, fb_ = (*b)->peakSentPktThpt, floatCompare = 1;
      break;
    }
    break;
  case TRAFFIC_STATS:
    /* Nothing */
    break;
  case SORT_DATA_PROTOS:
    switch(myGlobals.columnSort) {
    case 0:
      a_ = (*a)->bytesRcvd.value+(*a)->bytesSent.value, b_ = (*b)->bytesRcvd.value+(*b)->bytesSent.value;
      break;
    case 1:
      a_ = (*a)->tcpRcvdLoc.value + (*a)->tcpRcvdFromRem.value +
           (*a)->tcpSentLoc.value + (*a)->tcpSentRem.value;
      b_ = (*b)->tcpRcvdLoc.value + (*b)->tcpRcvdFromRem.value +
           (*b)->tcpSentLoc.value + (*b)->tcpSentRem.value;
      break;
    case 2:
      a_ = (*a)->udpRcvdLoc.value + (*a)->udpRcvdFromRem.value +
           (*a)->udpSentLoc.value + (*a)->udpSentRem.value;
      b_ = (*b)->udpRcvdLoc.value + (*b)->udpRcvdFromRem.value +
           (*b)->udpSentLoc.value + (*b)->udpSentRem.value;
      break;
    case 3:
      a_ = (*a)->icmpRcvd.value+(*a)->icmpSent.value, b_ = (*b)->icmpRcvd.value+(*b)->icmpSent.value;
      break;
    case 4:
      a_ = (*a)->icmp6Rcvd.value+(*a)->icmp6Sent.value, b_ = (*b)->icmp6Rcvd.value+(*b)->icmp6Sent.value;
      break;
    case 5:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->stpSent.value+(*a)->nonIPTraffic->stpRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->stpSent.value+(*b)->nonIPTraffic->stpRcvd.value;
      break;
    case 6:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->ipxSent.value+(*a)->nonIPTraffic->ipxRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->ipxSent.value+(*b)->nonIPTraffic->ipxRcvd.value;
      break;
    case 7:
      a_ = (*a)->ipsecSent.value+(*a)->ipsecRcvd.value;
      b_ = (*b)->ipsecSent.value+(*b)->ipsecRcvd.value;
      break;
    case 8:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->arp_rarpSent.value+(*a)->nonIPTraffic->arp_rarpRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->arp_rarpSent.value+(*b)->nonIPTraffic->arp_rarpRcvd.value;
      break;
    case 9:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->appletalkSent.value+(*a)->nonIPTraffic->appletalkRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->appletalkSent.value+(*b)->nonIPTraffic->appletalkRcvd.value;
      break;
    case 11:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->netbiosSent.value+(*a)->nonIPTraffic->netbiosRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->netbiosSent.value+(*b)->nonIPTraffic->netbiosRcvd.value;
      break;
    case 13:
      a_ = (*a)->greSent.value + (*a)->greRcvd.value;
      b_ = (*b)->greSent.value + (*b)->greRcvd.value;
      break;
    case 14:
      a_ = (*a)->ipv6BytesRcvd.value+(*a)->ipv6BytesSent.value, b_ = (*b)->ipv6BytesRcvd.value+(*b)->ipv6BytesSent.value;
      break;
    case 15:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->stpSent.value+(*a)->nonIPTraffic->stpRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->stpSent.value+(*b)->nonIPTraffic->stpRcvd.value;
      break;
    case 16:
      a_ = (*a)->nonIPTraffic == NULL ? 0 : (*a)->nonIPTraffic->otherSent.value+(*a)->nonIPTraffic->otherRcvd.value;
      b_ = (*b)->nonIPTraffic == NULL ? 0 : (*b)->nonIPTraffic->otherSent.value+(*b)->nonIPTraffic->otherRcvd.value;
      break;
    default:
      if((myGlobals.columnSort >= BASE_PROTOS_IDX)
	 && (myGlobals.columnSort < (BASE_PROTOS_IDX+myGlobals.numIpProtosList))) {
	int idx = myGlobals.columnSort-BASE_PROTOS_IDX;

	if(((*a)->ipProtosList == NULL) && ((*b)->ipProtosList != NULL)) return(1);
	else if(((*a)->ipProtosList != NULL) && ((*b)->ipProtosList == NULL)) return(-1);

	if((*a)->ipProtosList && (*a)->ipProtosList[idx])
	  a_ = (*a)->ipProtosList[idx]->sent.value +(*a)->ipProtosList[idx]->rcvd.value;
	else
	  a_ = 0;
	
	if((*b)->ipProtosList && (*b)->ipProtosList[idx])
	  b_ = (*b)->ipProtosList[idx]->sent.value +(*b)->ipProtosList[idx]->rcvd.value;
	else
	  b_ = 0;
      }
      break;
    }
    break;
  case SORT_DATA_IP:
    columnProtoId = myGlobals.columnSort - 1;
    if(((*a)->protoIPTrafficInfos == NULL) && ((*b)->protoIPTrafficInfos != NULL)) return(1);
    else if(((*a)->protoIPTrafficInfos != NULL) && ((*b)->protoIPTrafficInfos == NULL)) return(-1);

    if((columnProtoId != -1) && (columnProtoId <= myGlobals.numIpProtosToMonitor)) {
      if(columnProtoId <= 0) {
        a_ = b_ = 0;
      } else {
	if((*a)->protoIPTrafficInfos[columnProtoId-1])
	  a_ = (*a)->protoIPTrafficInfos[columnProtoId-1]->rcvdLoc.value+
	    (*a)->protoIPTrafficInfos[columnProtoId-1]->rcvdFromRem.value+
	    (*a)->protoIPTrafficInfos[columnProtoId-1]->sentLoc.value+
	    (*a)->protoIPTrafficInfos[columnProtoId-1]->sentRem.value;
	else
	  a_ = 0;

	if((*b)->protoIPTrafficInfos[columnProtoId-1])
	  b_ = (*b)->protoIPTrafficInfos[columnProtoId-1]->rcvdLoc.value+
	    (*b)->protoIPTrafficInfos[columnProtoId-1]->rcvdFromRem.value+
	    (*b)->protoIPTrafficInfos[columnProtoId-1]->sentLoc.value+
	    (*b)->protoIPTrafficInfos[columnProtoId-1]->sentRem.value;
	else
	  b_ = 0;
      }
    } else {
      a_ = (*a)->ipv4BytesRcvd.value+(*a)->ipv4BytesSent.value;
      b_ = (*b)->ipv4BytesRcvd.value+(*b)->ipv4BytesSent.value;

      if(myGlobals.numIpProtosToMonitor == (columnProtoId-1)) {
        /* other IP */
        int i;

        for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	  if((*a)->protoIPTrafficInfos[i])
	    a_val = ((*a)->protoIPTrafficInfos[i]->rcvdLoc.value
		     +(*a)->protoIPTrafficInfos[i]->rcvdFromRem.value
		     +(*a)->protoIPTrafficInfos[i]->sentLoc.value
		     +(*a)->protoIPTrafficInfos[i]->sentRem.value);
	  else
	    a_val = 0;
	    
	  if((*b)->protoIPTrafficInfos[i])
	    b_val = ((*b)->protoIPTrafficInfos[i]->rcvdLoc.value
		     +(*b)->protoIPTrafficInfos[i]->rcvdFromRem.value
		     +(*b)->protoIPTrafficInfos[i]->sentLoc.value
		     +(*b)->protoIPTrafficInfos[i]->sentRem.value);
	  else
	    b_val = 0;

          /* Better be safe... */
          if(a_ > a_val) a_ -= a_val; else a_ = 0;
          if(b_ > b_val) b_ -= b_val; else b_ = 0;
        }
      }
    }
    break;
  case SORT_DATA_THPT:
    switch(myGlobals.columnSort) {
    case 1:
      fa_ = (*a)->actualTThpt;
      fb_ = (*b)->actualTThpt;
      floatCompare = 1;
      break;
    case 2:
      fa_ = (*a)->averageTThpt;
      fb_ = (*b)->averageTThpt;
      floatCompare = 1;
      break;
    case 3:
      fa_ = (*a)->peakTThpt;
      fb_ = (*b)->peakTThpt;
      floatCompare = 1;
      break;
    case 4:
      fa_ = (*a)->actualTPktThpt;
      fb_ = (*b)->actualTPktThpt;
      floatCompare = 1;
      break;
    case 5:
      fa_ = (*a)->averageTPktThpt;
      fb_ = (*b)->averageTPktThpt;
      floatCompare = 1;
      break;
    case 6:
      fa_ = (*a)->peakTPktThpt;
      fb_ = (*b)->peakTPktThpt;
      floatCompare = 1;
      break;
    }
    break;
  }

  /*
    traceEvent(CONST_TRACE_INFO, "%s=%u - %s=%u",
    (*a)->hostResolvedName, (unsigned long)a_,
    (*b)->hostResolvedName, (unsigned long)b_);
  */

  if(floatCompare == 0) {
    if(a_ < b_) {
      return(1);
    } else if (a_ > b_) {
      return(-1);
    } else {
      return(0);
    }
  } else {
    if(fa_ < fb_) {
      return(1);
    } else if (fa_ > fb_) {
      return(-1);
    } else {
      return(0);
    }
  }
}

/* ******************************* */

int cmpMulticastFctn(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  int rc;

  if((a == NULL) && (b != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpMulticastFctn() error (1)");
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpMulticastFctn() error (2)");
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpMulticastFctn() error (3)");
    return(0);
  }

  switch(myGlobals.columnSort) {
  case 2:
    if((*a)->pktMulticastSent.value < (*b)->pktMulticastSent.value)
      return(1);
    else if ((*a)->pktMulticastSent.value > (*b)->pktMulticastSent.value)
      return(-1);
    else
      return(0);
    break; /* NOTREACHED */
  case 3:
    if((*a)->bytesMulticastSent.value < (*b)->bytesMulticastSent.value)
      return(1);
    else if ((*a)->bytesMulticastSent.value > (*b)->bytesMulticastSent.value)
      return(-1);
    else
      return(0);
    break; /* NOTREACHED */
  case 4:
    if((*a)->pktMulticastRcvd.value < (*b)->pktMulticastRcvd.value)
      return(1);
    else if ((*a)->pktMulticastRcvd.value > (*b)->pktMulticastRcvd.value)
      return(-1);
    else
      return(0);
    break; /* NOTREACHED */
  case 5:
    if((*a)->bytesMulticastRcvd.value < (*b)->bytesMulticastRcvd.value)
      return(1);
    else if ((*a)->bytesMulticastRcvd.value > (*b)->bytesMulticastRcvd.value)
      return(-1);
    else
      return(0);
    break; /* NOTREACHED */

  default:
    rc=cmpFctnResolvedName(a, b);
    return(rc);
  }
}

/* *********************************** */

static char* getBgPctgColor(float pctg) {
  if(pctg == 0)
    return(TD_BG);
  else if(pctg <= CONST_PCTG_LOW)     /* < 25%       */
    return(CONST_CONST_PCTG_LOW_COLOR);
  else if(pctg <= CONST_PCTG_MID)     /* 25% <=> 75% */
    return(CONST_CONST_PCTG_MID_COLOR);
  else                          /* > 75%       */
    return(CONST_PCTG_HIGH_COLOR);
}

/* ******************************* */

void printHostThtpShort(HostTraffic *el, int reportType, u_int hourId)
{
  int i, j;
  Counter tc;
  char buf[64];

  if(el->trafficDistribution == NULL) return;

  for(i=0, tc=0; i<24; i++) {
    switch(reportType) {
        case SORT_DATA_RCVD_HOST_TRAFFIC:
	  tc += el->trafficDistribution->last24HoursBytesRcvd[i].value;
	  break;
    case SORT_DATA_SENT_HOST_TRAFFIC:
      tc += el->trafficDistribution->last24HoursBytesSent[i].value;
      break;
    case SORT_DATA_HOST_TRAFFIC:
    case TRAFFIC_STATS:
      tc += el->trafficDistribution->last24HoursBytesRcvd[i].value +
	el->trafficDistribution->last24HoursBytesSent[i].value;
      break;
    }
  }

  j = hourId;
  for(i=0; i<24; i++) {
    float pctg=0;

    j = j % 24;
    if(tc > 0) {
      switch(reportType) {
      case SORT_DATA_RCVD_HOST_TRAFFIC:
	pctg = (float)(el->trafficDistribution->last24HoursBytesRcvd[j].value*100)/(float)tc;
	break;
      case SORT_DATA_SENT_HOST_TRAFFIC:
	pctg = (float)(el->trafficDistribution->last24HoursBytesSent[j].value*100)/(float)tc;
	break;
      case SORT_DATA_HOST_TRAFFIC:
      case TRAFFIC_STATS:
	pctg = ( (float)(el->trafficDistribution->last24HoursBytesRcvd[j].value*100) +
		 (float)(el->trafficDistribution->last24HoursBytesSent[j].value*100) ) / (float)tc;
	break;
      }
    }

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT %s>&nbsp;</TD>",
		getBgPctgColor(pctg));
    sendString(buf);
    if (!j) {
        j = 23;
    }
    else {
        j--;
    }
  }
}

/* ******************************* */

int cmpHostsFctn(const void *_a, const void *_b) {
  struct hostTraffic **a = (struct hostTraffic **)_a;
  struct hostTraffic **b = (struct hostTraffic **)_b;
  Counter a_=0, b_=0;

  switch(myGlobals.columnSort) {
  case 2: /* IP Address */
    if(isFcHost((*a)) && isFcHost((*b))) {
      return(memcmp(((u_int8_t *)&(*a)->fcCounters->hostFcAddress), 
		    ((u_int8_t *)&(*b)->fcCounters->hostFcAddress),
		    LEN_FC_ADDRESS));
    }
    else
      return(addrcmp(&(*a)->hostIpAddress, &(*b)->hostIpAddress));
    break;

  case 3: /* Data Sent */
    if (isFcHost((*a)) && isFcHost((*b))) {
      a_ = (*a)->fcCounters->fcBytesSent.value;
      b_ = (*b)->fcCounters->fcBytesSent.value;
    }
    else {
      switch(myGlobals.sortFilter) {
      case FLAG_REMOTE_TO_LOCAL_ACCOUNTING:
	a_ = (*a)->bytesSentLoc.value;
	b_ = (*b)->bytesSentLoc.value;
	break;
      case FLAG_LOCAL_TO_REMOTE_ACCOUNTING:
	a_ = (*a)->bytesSentRem.value;
	b_ = (*b)->bytesSentRem.value;
	break;
      case FLAG_LOCAL_TO_LOCAL_ACCOUNTING:
	a_ = (*a)->bytesSentLoc.value;
	b_ = (*b)->bytesSentLoc.value;
	break;
      }
    }
    if(a_ < b_) return(1); else if (a_ > b_) return(-1); else return(0);
    break;

  case 4: /* Data Rcvd */
    if(isFcHost((*a)) && isFcHost((*b))) {
      a_ = (*a)->fcCounters->fcBytesRcvd.value;
      b_ = (*b)->fcCounters->fcBytesRcvd.value;
    }
    else {
      switch(myGlobals.sortFilter) {
      case FLAG_REMOTE_TO_LOCAL_ACCOUNTING:
	a_ = (*a)->bytesRcvdLoc.value;
	b_ = (*b)->bytesRcvdLoc.value;
	break;
      case FLAG_LOCAL_TO_REMOTE_ACCOUNTING:
	a_ = (*a)->bytesRcvdFromRem.value;
	b_ = (*b)->bytesRcvdFromRem.value;
	break;
      case FLAG_LOCAL_TO_LOCAL_ACCOUNTING:
	a_ = (*a)->bytesRcvdLoc.value;
	b_ = (*b)->bytesRcvdLoc.value;
	break;
      }
    }
    if(a_ < b_) return(1); else if (a_ > b_) return(-1); else return(0);
    break;

  case 5: /* VSAN */
    if(isFcHost((*a)) && isFcHost((*b))) {
      a_ = (*a)->fcCounters->vsanId, b_ = (*b)->fcCounters->vsanId;
      return((a_ < b_) ? -1 : (a_ > b_) ? 1 : 0);
    }
    break;
    
  default: /* Host Name */
    return(cmpFctnResolvedName(a, b));
  }
  
  return(-1);
}

/* ************************************ */

void printPacketStats(HostTraffic *el, int actualDeviceId) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  char formatBuf[32];
  int headerSent = 0;
  char *tableHeader = "<center><TABLE BORDER=0 "TABLE_DEFAULTS"><TR><TD>";

  /* *********************** */

  if(el->secHostPkts != NULL) {
    if(((el->secHostPkts->rejectedTCPConnSent.value.value+
	 el->secHostPkts->rejectedTCPConnRcvd.value.value+
	 el->secHostPkts->establishedTCPConnSent.value.value+
	 el->secHostPkts->establishedTCPConnRcvd.value.value+
	 el->secHostPkts->synPktsSent.value.value+
	 el->secHostPkts->synPktsRcvd.value.value) > 0)) {

      if(!headerSent) { printSectionTitle("Packet Statistics"); sendString(tableHeader); headerSent = 1; }

      sendString("<CENTER>\n"
		 ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>"
		 "<TR "TR_ON" "DARK_BG"><TH "TH_BG">TCP Connections</TH>"
		 "<TH "TH_BG" COLSPAN=2>Directed to</TH>"
		 "<TH "TH_BG" COLSPAN=2>Rcvd From</TH></TR>\n");

      if((el->secHostPkts->synPktsSent.value.value+el->secHostPkts->synPktsRcvd.value.value) > 0) {
	sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Attempted</TH>");
	formatUsageCounter(el->secHostPkts->synPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->synPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->establishedTCPConnSent.value.value+el->secHostPkts->establishedTCPConnRcvd.value.value) > 0) {
	sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Established</TH>");
	formatUsageCounter(el->secHostPkts->establishedTCPConnSent, el->secHostPkts->synPktsSent.value.value, actualDeviceId);
	formatUsageCounter(el->secHostPkts->establishedTCPConnRcvd, el->secHostPkts->synPktsRcvd.value.value, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->terminatedTCPConnServer.value.value + el->secHostPkts->terminatedTCPConnClient.value.value) > 0) {
	sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Terminated</TH>");
	formatUsageCounter(el->secHostPkts->terminatedTCPConnServer, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->terminatedTCPConnClient, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->rejectedTCPConnSent.value.value+el->secHostPkts->rejectedTCPConnRcvd.value.value) > 0) {
	sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">Rejected</TH>");
	formatUsageCounter(el->secHostPkts->rejectedTCPConnSent, el->secHostPkts->synPktsSent.value.value, actualDeviceId);
	formatUsageCounter(el->secHostPkts->rejectedTCPConnRcvd, el->secHostPkts->synPktsRcvd.value.value, actualDeviceId);
	sendString("</TR>\n");
      }

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }

    /* *********************** */

    if((el->secHostPkts->synPktsSent.value.value+el->secHostPkts->synPktsRcvd.value.value
	+el->secHostPkts->rstAckPktsSent.value.value+el->secHostPkts->rstAckPktsRcvd.value.value
	+el->secHostPkts->rstPktsSent.value.value+el->secHostPkts->rstPktsRcvd.value.value
	+el->secHostPkts->synFinPktsSent.value.value+el->secHostPkts->synFinPktsRcvd.value.value
	+el->secHostPkts->finPushUrgPktsSent.value.value+el->secHostPkts->finPushUrgPktsRcvd.value.value
	+el->secHostPkts->nullPktsSent.value.value+el->secHostPkts->nullPktsRcvd.value.value) > 0) {

      if(!headerSent) { printSectionTitle("Packet Statistics"); sendString(tableHeader); headerSent = 1; }

      sendString("<CENTER>\n"
		 ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%><TR "TR_ON" "DARK_BG"><TH "TH_BG">TCP Flags</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Sent</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Rcvd</TH></TR>\n");

      if((el->secHostPkts->synPktsSent.value.value+el->secHostPkts->synPktsRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">SYN</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->synPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->synPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->rstAckPktsSent.value.value+el->secHostPkts->rstAckPktsRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">RST|ACK</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->rstAckPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->rstAckPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->rstPktsSent.value.value+el->secHostPkts->rstPktsRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">RST</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->rstPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->rstPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->synFinPktsSent.value.value+el->secHostPkts->synFinPktsRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">SYN|FIN</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->synFinPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->synFinPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->finPushUrgPktsSent.value.value+el->secHostPkts->finPushUrgPktsRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">FIN|PUSH|URG</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->finPushUrgPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->finPushUrgPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->nullPktsSent.value.value+el->secHostPkts->nullPktsRcvd.value.value) > 0) {
	sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT "DARK_BG">NULL</TH>");
	formatUsageCounter(el->secHostPkts->nullPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->nullPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }

    /* *********************** */

    if(((el->secHostPkts->ackXmasFinSynNullScanSent.value.value+el->secHostPkts->ackXmasFinSynNullScanRcvd.value.value
	 +el->secHostPkts->udpToClosedPortSent.value.value
	 +el->secHostPkts->udpToClosedPortRcvd.value.value
	 +el->secHostPkts->udpToDiagnosticPortSent.value.value
	 +el->secHostPkts->udpToDiagnosticPortRcvd.value.value
	 +el->secHostPkts->tcpToDiagnosticPortSent.value.value
	 +el->secHostPkts->tcpToDiagnosticPortRcvd.value.value
	 +el->secHostPkts->tinyFragmentSent.value.value
	 +el->secHostPkts->tinyFragmentRcvd.value.value
	 +el->secHostPkts->icmpFragmentSent.value.value
	 +el->secHostPkts->icmpFragmentRcvd.value.value
	 +el->secHostPkts->overlappingFragmentSent.value.value
	 +el->secHostPkts->overlappingFragmentRcvd.value.value
	 +el->secHostPkts->closedEmptyTCPConnSent.value.value
	 +el->secHostPkts->closedEmptyTCPConnRcvd.value.value
	 +el->secHostPkts->icmpPortUnreachSent.value.value
	 +el->secHostPkts->icmpPortUnreachRcvd.value.value
	 +el->secHostPkts->icmpHostNetUnreachSent.value.value
	 +el->secHostPkts->icmpHostNetUnreachRcvd.value.value
	 +el->secHostPkts->icmpProtocolUnreachSent.value.value
	 +el->secHostPkts->icmpProtocolUnreachRcvd.value.value
	 +el->secHostPkts->icmpAdminProhibitedSent.value.value
	 +el->secHostPkts->icmpAdminProhibitedRcvd.value.value
	 +el->secHostPkts->malformedPktsSent.value.value
	 +el->secHostPkts->malformedPktsRcvd.value.value
	 ) > 0)) {

      if(!headerSent) { printSectionTitle("Packet Statistics"); sendString(tableHeader); headerSent = 1; }

      sendString("<CENTER>\n"
		 ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%><TR "TR_ON" "DARK_BG"><TH "TH_BG">Anomaly</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Sent&nbsp;to</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Rcvd&nbsp;from</TH>"
		 "</TR>\n");

      if((el->secHostPkts->ackXmasFinSynNullScanSent.value.value+el->secHostPkts->ackXmasFinSynNullScanRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">ACK/XMAS/SYN/FIN/NULL Scan</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->ackXmasFinSynNullScanSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->ackXmasFinSynNullScanRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->udpToClosedPortSent.value.value+
	  el->secHostPkts->udpToClosedPortRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">UDP Pkt to Closed Port</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->udpToClosedPortSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->udpToClosedPortRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->udpToDiagnosticPortSent.value.value+
	  el->secHostPkts->udpToDiagnosticPortRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">UDP Pkt Disgnostic Port</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->udpToDiagnosticPortSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->udpToDiagnosticPortRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->tcpToDiagnosticPortSent.value.value+
	  el->secHostPkts->tcpToDiagnosticPortRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">TCP Pkt Disgnostic Port</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->tcpToDiagnosticPortSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->tcpToDiagnosticPortRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->tinyFragmentSent.value.value+
	  el->secHostPkts->tinyFragmentRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">Tiny Fragments</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->tinyFragmentSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->tinyFragmentRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->icmpFragmentSent.value.value+
	  el->secHostPkts->icmpFragmentRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">ICMP Fragments</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->icmpFragmentSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->icmpFragmentRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->overlappingFragmentSent.value.value+
	  el->secHostPkts->overlappingFragmentRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">Overlapping Fragments</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->overlappingFragmentSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->overlappingFragmentRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->closedEmptyTCPConnSent.value.value+
	  el->secHostPkts->closedEmptyTCPConnRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">Closed Empty TCP Conn.</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->closedEmptyTCPConnSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->closedEmptyTCPConnRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }


      if((el->secHostPkts->icmpPortUnreachSent.value.value+
	  el->secHostPkts->icmpPortUnreachRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">ICMP Port Unreachable</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->icmpPortUnreachSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->icmpPortUnreachRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->icmpHostNetUnreachSent.value.value+
	  el->secHostPkts->icmpHostNetUnreachRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">ICMP Net Unreachable</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->icmpHostNetUnreachSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->icmpHostNetUnreachRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->icmpProtocolUnreachSent.value.value+
	  el->secHostPkts->icmpProtocolUnreachRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">ICMP Protocol Unreachable</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->icmpProtocolUnreachSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->icmpProtocolUnreachRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->icmpAdminProhibitedSent.value.value+
	  el->secHostPkts->icmpAdminProhibitedRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">ICMP Administratively Prohibited</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->icmpAdminProhibitedSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->icmpAdminProhibitedRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->malformedPktsSent.value.value+
	  el->secHostPkts->malformedPktsRcvd.value.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">Malformed Pkts</TH>",
		    getRowColor());
	sendString(buf);
	formatUsageCounter(el->secHostPkts->malformedPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->malformedPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }
  }

  if(el->nonIPTraffic) {
    if(el->nonIPTraffic->arpReqPktsSent.value+el->nonIPTraffic->arpReplyPktsSent.value+el->nonIPTraffic->arpReplyPktsRcvd.value > 0) {
      if(!headerSent) {
	printSectionTitle("Packet Statistics");
	sendString(tableHeader);
	headerSent = 1;
      }

      sendString("<CENTER>\n"
		 ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%><TR "TR_ON" "DARK_BG">"
		 "<TH "TH_BG">ARP</TH>"
		 "<TH "TH_BG">Packet</TH>"
		 "</TR>\n");

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Request Sent</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		    getRowColor(),
		    formatPkts(el->nonIPTraffic->arpReqPktsSent.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Reply Rcvd</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s (%.1f %%)</TD></TR>",
		    getRowColor(),
		    formatPkts(el->nonIPTraffic->arpReplyPktsRcvd.value, formatBuf, sizeof(formatBuf)),
		    ((el->nonIPTraffic->arpReqPktsSent.value > 0) ?
		     (float)((el->nonIPTraffic->arpReplyPktsRcvd.value*100)/(float)el->nonIPTraffic->arpReqPktsSent.value) : 0));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Reply Sent</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		    getRowColor(),
		    formatPkts(el->nonIPTraffic->arpReplyPktsSent.value, formatBuf, sizeof(formatBuf)));
      sendString(buf);

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }
  }

  if(headerSent) { sendString("</TD></TR></TABLE>"TABLE_OFF"</CENTER>"); }
}

/* ************************************ */

void printHostFragmentStats(HostTraffic *el, int actualDeviceId) {
  Counter totalSent, totalRcvd;
  char buf[LEN_GENERAL_WORK_BUFFER];
  char linkName[LEN_GENERAL_WORK_BUFFER/2], vlanStr[32];

  totalSent = el->tcpFragmentsSent.value + el->udpFragmentsSent.value + el->icmpFragmentsSent.value;
  totalRcvd = el->tcpFragmentsRcvd.value + el->udpFragmentsRcvd.value + el->icmpFragmentsRcvd.value;

 if((totalSent == 0) && (totalRcvd == 0))
    return;

  printSectionTitle("IP Fragments Distribution");

  sendString("<CENTER>\n"
	     ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "DARK_BG"><TH "TH_BG" WIDTH=100>Protocol</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Sent</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Rcvd</TH></TR>\n");

  printTableDoubleEntry(buf, sizeof(buf), "TCP", CONST_COLOR_1, (float)el->tcpFragmentsSent.value/1024,
			100*((float)SD(el->tcpFragmentsSent.value, totalSent)),
			(float)el->tcpFragmentsRcvd.value/1024,
			100*((float)SD(el->tcpFragmentsRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "UDP", CONST_COLOR_1, (float)el->udpFragmentsSent.value/1024,
			100*((float)SD(el->udpFragmentsSent.value, totalSent)),
			(float)el->udpFragmentsRcvd.value/1024,
			100*((float)SD(el->udpFragmentsRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "ICMP", CONST_COLOR_1, (float)el->icmpFragmentsSent.value/1024,
			100*((float)SD(el->icmpFragmentsSent.value, totalSent)),
			(float)el->icmpFragmentsRcvd.value/1024,
			100*((float)SD(el->icmpFragmentsRcvd.value, totalRcvd)));

  {
    if((totalSent > 0) || (totalRcvd > 0)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Fragment Distribution</TH>",
		  getRowColor());
      sendString(buf);

      if(el->hostNumIpAddress[0] != '\0') {
        strncpy(linkName, el->hostNumIpAddress, sizeof(linkName));
      } else {
        strncpy(linkName, el->ethAddressString, sizeof(linkName));
      }

      /* For Ethernet and IPv6 addresses */
      urlFixupToRFC1945Inplace(linkName);

      if(el->vlanId > 0) {
	safe_snprintf(__FILE__, __LINE__, vlanStr, sizeof(vlanStr), "-%d", el->vlanId);
      } else
	vlanStr[0] = '\0';
      
     if(totalSent > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 BGCOLOR=white>"
		    "<IMG SRC=\"hostFragmentDistrib-%s%s"CHART_FORMAT"?1\" ALT=\"Sent Fragment Distribution for %s%s\"></TD>",
		    linkName, vlanStr, 
		    el->hostNumIpAddress[0] == '\0' ?  el->ethAddressString : el->hostNumIpAddress, vlanStr);
	sendString(buf);
      } else {
	sendString("<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>&nbsp;</TD>");
      }

      if(totalRcvd > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 BGCOLOR=white>"
		      "<IMG SRC=\"hostFragmentDistrib-%s%s"CHART_FORMAT"\" ALT=\"Received Fragment Distribution for %s%s\"></TD>",
		      linkName, vlanStr,
		      el->hostNumIpAddress[0] == '\0' ?  el->ethAddressString : el->hostNumIpAddress, vlanStr);
	sendString(buf);
      } else {
	sendString("<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>&nbsp;</TD>");
      }
      
      sendString("</TD></TR>");

      /* ***************************************** */

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>IP Fragment Distribution</TH>",
		  getRowColor());
      sendString(buf);

      if(totalSent > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 BGCOLOR=white>"
		    "<IMG SRC=hostTotalFragmentDistrib-%s%s"CHART_FORMAT"?1 ALT=\"Sent IP Fragment Distribution for %s%s\"></TD>",
		    linkName, vlanStr,
		    el->hostNumIpAddress[0] == '\0' ?  el->ethAddressString : el->hostNumIpAddress, vlanStr);
	sendString(buf);
      } else {
	sendString("<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>&nbsp;</TD>");
      }

      if(totalRcvd > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 BGCOLOR=white>"
		    "<IMG SRC=hostTotalFragmentDistrib-%s%s"CHART_FORMAT" ALT=\"Received IP Fragment Distribution for %s%s\"></TD>",
		    linkName, vlanStr, 
		    el->hostNumIpAddress[0] == '\0' ?  el->ethAddressString : el->hostNumIpAddress, vlanStr);
	sendString(buf);
      } else {
	sendString("<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>&nbsp;</TD>");
      }

      sendString("</TD></TR>");
    }
  }

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");
}

/* ************************************ */

static char* sap2name(u_int16_t proto, char *sap, int sap_len) {
  switch(proto) {
  case SAP_NULL:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "NULL LSAP");
    break;
  case SAP_LLC_SLMGMT:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "LLC Sub-Layer Management");
    break;
  case SAP_SNA_PATHCTRL:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "SNA Path Control");
    break;
  case SAP_IP:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "TCP/IP");
    break;
  case SAP_SNA1:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "SNA");
    break;
  case SAP_SNA2:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "SNA");
    break;
  case SAP_PROWAY_NM_INIT:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "PROWAY (IEC955) Network Management and Initialization");
    break;
  case SAP_TI:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "Texas Instruments");
    break;
  case SAP_BPDU:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "Spanning Tree BPDU");
    break;
  case SAP_RS511:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "EIA RS-511 Manufacturing Message Service");
    break;
  case SAP_X25:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "ISO 8208 (X.25 over 802.2)");
    break;
  case 0x7F:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "ISO 802.2");
    break;
  case SAP_XNS:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "XNS");
    break;
  case SAP_BACNET:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "BACnet");
    break;
  case SAP_NESTAR:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "Nestar");
    break;
  case SAP_PROWAY_ASLM:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "PROWAY (IEC955) Active Station List Maintenance");
    break;
  case SAP_ARP:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "ARP");
    break;
  case SAP_SNAP:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "SNAP");
    break;
  case SAP_VINES1:
  case SAP_VINES2:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "Banyan Vines");
    break;
  case SAP_NETWARE:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "NetWare");
    break;
  case SAP_NETBIOS:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "NetBIOS");
    break;
  case SAP_IBMNM:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "IBM Net Management");
    break;
  case SAP_HPEXT:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "HP Extended LLC");
    break;
  case SAP_UB:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "Ungermann-Bass");
    break;
  case SAP_RPL:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "Remote Program Load");
    break;
  case SAP_OSINL:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "ISO Network Layer");
    break;
  case SAP_GLOBAL:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "Global LSAP");
    break;
  default:
    safe_snprintf(__FILE__, __LINE__, sap, sap_len, "0x%X", proto);
    break;
  }

  return(sap);
}

/* ************************************ */

static void printUnknownProto(UnknownProto proto) {
  char buf[64];

  switch(proto.protoType) {
  case 1:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<li>Ethernet Type: 0x%04X\n", proto.proto.ethType);
    break;
  case 2:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<li>SAP: DSAP=0x%02X/SSAP=0x%02X\n",
	     proto.proto.sapType.dsap, proto.proto.sapType.ssap);
    break;
  case 3:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<li>IP Protocol: 0x%d\n", proto.proto.ipType);
    break;
  default:
    return;
  }

  sendString(buf);
}

/* ************************************ */

void printHostTrafficStats(HostTraffic *el, int actualDeviceId) {
  Counter totalSent, totalRcvd;
  Counter actTotalSent, actTotalRcvd;
  char buf[LEN_GENERAL_WORK_BUFFER], vlanStr[32];
  char linkName[LEN_GENERAL_WORK_BUFFER/2];
  int i, idx;
  ProtocolsList *protoList;

  totalSent = el->tcpSentLoc.value+el->tcpSentRem.value+el->udpSentLoc.value+el->udpSentRem.value;
  totalSent += el->icmpSent.value+el->icmp6Sent.value+el->ipv6BytesSent.value;
  totalSent += el->greSent.value + el->ipsecSent.value;

  if(el->nonIPTraffic != NULL)
    totalSent += el->nonIPTraffic->ipxSent.value+el->nonIPTraffic->dlcSent.value+el->nonIPTraffic->arp_rarpSent.value +
      el->nonIPTraffic->appletalkSent.value+el->nonIPTraffic->netbiosSent.value+
      el->nonIPTraffic->stpSent.value+el->nonIPTraffic->otherSent.value;
  
  totalRcvd = el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value;
  totalRcvd += el->udpRcvdLoc.value+el->udpRcvdFromRem.value;
  totalRcvd += el->icmpRcvd.value+el->icmp6Rcvd.value+el->ipv6BytesRcvd.value;
  totalRcvd += el->greRcvd.value + el->ipsecRcvd.value;

  if(el->nonIPTraffic != NULL)
    totalRcvd += el->nonIPTraffic->ipxRcvd.value+el->nonIPTraffic->dlcRcvd.value+el->nonIPTraffic->arp_rarpRcvd.value +
      el->nonIPTraffic->appletalkRcvd.value +
      el->nonIPTraffic->netbiosRcvd.value+el->nonIPTraffic->stpRcvd.value+el->nonIPTraffic->otherRcvd.value;

  protoList = myGlobals.ipProtosList;
  idx = 0;

  while(protoList != NULL) {
    if(el->ipProtosList[idx] != NULL) {
      totalSent += el->ipProtosList[idx]->sent.value;
      totalRcvd += el->ipProtosList[idx]->rcvd.value;
    }
    idx++, protoList = protoList->next;
  }

  actTotalSent = el->tcpSentLoc.value+el->tcpSentRem.value;
  actTotalRcvd = el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value;

  printHostHourlyTraffic(el);
  printPacketStats(el, actualDeviceId);

  if((totalSent == 0) && (totalRcvd == 0))
    return;

  printSectionTitle("Protocol Distribution");

  sendString("<CENTER>\n"
	     ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=80%%><TR "DARK_BG"><TH "TH_BG" WIDTH=100>Protocol</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Sent</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Rcvd</TH></TR>\n");

  printTableDoubleEntry(buf, sizeof(buf), "TCP", CONST_COLOR_1, (float)actTotalSent/1024,
			100*((float)SD(actTotalSent, totalSent)),
			(float)actTotalRcvd/1024,
			100*((float)SD(actTotalRcvd, totalRcvd)));

  actTotalSent = el->udpSentLoc.value+el->udpSentRem.value;
  actTotalRcvd = el->udpRcvdLoc.value+el->udpRcvdFromRem.value;

  printTableDoubleEntry(buf, sizeof(buf), "UDP", CONST_COLOR_1, (float)actTotalSent/1024,
			100*((float)SD(actTotalSent, totalSent)),
			(float)actTotalRcvd/1024,
			100*((float)SD(actTotalRcvd, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "ICMP", CONST_COLOR_1, (float)el->icmpSent.value/1024,
			100*((float)SD(el->icmpSent.value, totalSent)),
			(float)el->icmpRcvd.value/1024,
			100*((float)SD(el->icmpRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "ICMPv6", CONST_COLOR_1, (float)el->icmp6Sent.value/1024,
                        100*((float)SD(el->icmp6Sent.value, totalSent)),
                        (float)el->icmp6Rcvd.value/1024,
                        100*((float)SD(el->icmp6Rcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "IPv6", CONST_COLOR_1, (float)el->ipv6BytesSent.value/1024,
			100*((float)SD(el->ipv6BytesSent.value, totalSent)),
			(float)el->ipv6BytesRcvd.value/1024,
			100*((float)SD(el->ipv6BytesRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "GRE", CONST_COLOR_1, (float)el->greSent.value/1024,
			100*((float)SD(el->greSent.value, totalSent)),
			(float)el->greRcvd.value/1024,
			100*((float)SD(el->greRcvd.value, totalRcvd)));
  
  printTableDoubleEntry(buf, sizeof(buf), "IPsec", CONST_COLOR_1, 
			(float)el->ipsecSent.value/1024,
			100*((float)SD(el->ipsecSent.value, totalSent)),
			(float)el->ipsecRcvd.value/1024,
			100*((float)SD(el->ipsecRcvd.value, totalRcvd)));
  
  if(el->nonIPTraffic != NULL) {
    printTableDoubleEntry(buf, sizeof(buf), "(R)ARP", CONST_COLOR_1, (float)el->nonIPTraffic->arp_rarpSent.value/1024,
			  100*((float)SD(el->nonIPTraffic->arp_rarpSent.value, totalSent)),
			  (float)el->nonIPTraffic->arp_rarpRcvd.value/1024,
			  100*((float)SD(el->nonIPTraffic->arp_rarpRcvd.value, totalRcvd)));

    printTableDoubleEntry(buf, sizeof(buf), "DLC", CONST_COLOR_1, (float)el->nonIPTraffic->dlcSent.value/1024,
			  100*((float)SD(el->nonIPTraffic->dlcSent.value, totalSent)),
			  (float)el->nonIPTraffic->dlcRcvd.value/1024,
			  100*((float)SD(el->nonIPTraffic->dlcRcvd.value, totalRcvd)));

    printTableDoubleEntry(buf, sizeof(buf), "IPX", CONST_COLOR_1, (float)el->nonIPTraffic->ipxSent.value/1024,
			  100*((float)SD(el->nonIPTraffic->ipxSent.value, totalSent)),
			  (float)el->nonIPTraffic->ipxRcvd.value/1024,
			  100*((float)SD(el->nonIPTraffic->ipxRcvd.value, totalRcvd)));

    printTableDoubleEntry(buf, sizeof(buf), "AppleTalk", CONST_COLOR_1, (float)el->nonIPTraffic->appletalkSent.value/1024,
			  100*((float)SD(el->nonIPTraffic->appletalkSent.value, totalSent)),
			  (float)el->nonIPTraffic->appletalkRcvd.value/1024,
			  100*((float)SD(el->nonIPTraffic->appletalkRcvd.value, totalRcvd)));

    printTableDoubleEntry(buf, sizeof(buf), "NetBios", CONST_COLOR_1, (float)el->nonIPTraffic->netbiosSent.value/1024,
			  100*((float)SD(el->nonIPTraffic->netbiosSent.value, totalSent)),
			  (float)el->nonIPTraffic->netbiosRcvd.value/1024,
			  100*((float)SD(el->nonIPTraffic->netbiosRcvd.value, totalRcvd)));

    printTableDoubleEntry(buf, sizeof(buf), "STP", CONST_COLOR_1, (float)el->nonIPTraffic->stpSent.value/1024,
			  100*((float)SD(el->nonIPTraffic->stpSent.value, totalSent)),
			  (float)el->nonIPTraffic->stpRcvd.value/1024,
			  100*((float)SD(el->nonIPTraffic->stpRcvd.value, totalRcvd)));

    printTableDoubleEntry(buf, sizeof(buf), "Other (Non IP)", CONST_COLOR_1, (float)el->nonIPTraffic->otherSent.value/1024,
			  100*((float)SD(el->nonIPTraffic->otherSent.value, totalSent)),
			  (float)el->nonIPTraffic->otherRcvd.value/1024,
			  100*((float)SD(el->nonIPTraffic->otherRcvd.value, totalRcvd)));
  }
  
  {
    protoList = myGlobals.ipProtosList;
    idx = 0;

    while(protoList != NULL) {
      printTableDoubleEntry(buf, sizeof(buf), protoList->protocolName, CONST_COLOR_1,
			    el->ipProtosList[idx] != NULL ? (float)el->ipProtosList[idx]->sent.value/1024 : 0,
			    el->ipProtosList[idx] != NULL ? 100*((float)SD(el->ipProtosList[idx]->sent.value, totalSent)) : 0,
			    el->ipProtosList[idx] != NULL ? (float)el->ipProtosList[idx]->rcvd.value/1024 : 0,
			    el->ipProtosList[idx] != NULL ? 100*((float)SD(el->ipProtosList[idx]->rcvd.value, totalRcvd)) : 0);
      idx++, protoList = protoList->next;
    }
  }

  {
    totalSent = el->tcpSentLoc.value+el->tcpSentRem.value+
      el->udpSentLoc.value+el->udpSentRem.value+
      el->icmpSent.value+el->icmp6Sent.value+el->ipv6BytesSent.value+
      el->greSent.value+el->ipsecSent.value;

    totalRcvd = el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value+
      el->udpRcvdLoc.value+el->udpRcvdFromRem.value+
      el->icmpRcvd.value+el->icmp6Rcvd.value+el->ipv6BytesRcvd.value+
      el->greRcvd.value+el->ipsecRcvd.value;

    if(el->nonIPTraffic) {
      totalSent += el->nonIPTraffic->stpSent.value+
	el->nonIPTraffic->ipxSent.value+el->nonIPTraffic->dlcSent.value+
	el->nonIPTraffic->arp_rarpSent.value+el->nonIPTraffic->appletalkSent.value+
	el->nonIPTraffic->netbiosSent.value+el->nonIPTraffic->otherSent.value;
      
      totalRcvd += el->nonIPTraffic->stpRcvd.value+
	el->nonIPTraffic->ipxRcvd.value+el->nonIPTraffic->dlcRcvd.value+
	el->nonIPTraffic->arp_rarpRcvd.value+el->nonIPTraffic->appletalkRcvd.value+
	el->nonIPTraffic->netbiosRcvd.value+el->nonIPTraffic->otherRcvd.value;
    }

    protoList = myGlobals.ipProtosList;
    idx = 0;

    while(protoList != NULL) {
      if(el->ipProtosList[idx] != NULL) {
	totalSent += el->ipProtosList[idx]->sent.value;
	totalRcvd += el->ipProtosList[idx]->rcvd.value;
      }
      idx++, protoList = protoList->next;
    }

    if((totalSent > 0) || (totalRcvd > 0)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">Protocol Distribution</TH>",
		  getRowColor());
      sendString(buf);

      if(el->hostNumIpAddress[0] != '\0') {
        strncpy(linkName, el->hostNumIpAddress, sizeof(linkName));
      } else {
        strncpy(linkName, el->ethAddressString, sizeof(linkName));
      }

      /* For Ethernet and Ipv6 addresses */
      urlFixupToRFC1945Inplace(linkName);

     if(el->vlanId > 0) {
	safe_snprintf(__FILE__, __LINE__, vlanStr, sizeof(vlanStr), "-%d", el->vlanId);
      } else
	vlanStr[0] = '\0';

     if(totalSent > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TD WIDTH=250 "TD_BG" ALIGN=RIGHT COLSPAN=2 BGCOLOR=white>"
		      "<iframe frameborder=0 SRC=\"hostTrafficDistrib-%s%s"CHART_FORMAT"?1\""
		      "  width=400 height=250></iframe></TD>",
		      linkName, vlanStr);
	sendString(buf);
      } else {
	sendString("<TD width=250 "TD_BG" ALIGN=RIGHT COLSPAN=2 WIDTH=250>&nbsp;</TD>");
      }

      if(totalRcvd > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		    "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 BGCOLOR=white><iframe frameborder=0 SRC=\"hostTrafficDistrib-"
		    "%s%s"CHART_FORMAT"\" width=400 height=250></iframe></TD>",
		      linkName, vlanStr);
	sendString(buf);
      } else {
	sendString("<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 WIDTH=250>&nbsp;</TD>");
      }

      sendString("</TD></TR>");

      if((el->tcpSentLoc.value+el->tcpSentRem.value+el->udpSentLoc.value+el->udpSentRem.value
	  +el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value+el->udpRcvdLoc.value+el->udpRcvdFromRem.value) > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">"
		      "IP Distribution</TH>",
		      getRowColor());
	sendString(buf);
	
	if((el->tcpSentLoc.value+el->tcpSentRem.value+el->udpSentLoc.value+el->udpSentRem.value) > 0) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 BGCOLOR=white>"
			"<iframe frameborder=0 SRC=\"hostIPTrafficDistrib-%s%s"CHART_FORMAT"?1\""
			"  width=400 height=250></iframe></TD>",
			linkName, vlanStr);
	  sendString(buf);
	} else
	  sendString("<TD "TD_BG" COLSPAN=2 WIDTH=250>&nbsp;</TD>");

	if((el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value+el->udpRcvdLoc.value+el->udpRcvdFromRem.value) > 0) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 BGCOLOR=white><iframe frameborder=0 SRC=hostIPTrafficDistrib-"
		      "%s%s"CHART_FORMAT"  width=400 height=250></iframe></TD></TR>",
		      linkName, vlanStr);
	  sendString(buf);
	} else
	  sendString("<TD "TD_BG" COLSPAN=2 WIDTH=250>&nbsp;</TD>");

	sendString("</TR>");
      }
    }
  }

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");

  /* ************************************** */

  if(el->nonIpProtoTrafficInfos != NULL) {
    NonIpProtoTrafficInfo *nonIp = el->nonIpProtoTrafficInfos;

    printSectionTitle("Non IP Protocol Distribution");

    sendString("<CENTER>\n"
	       ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "DARK_BG" "DARK_BG"><TH "TH_BG" WIDTH=100>Protocol</TH>"
	       "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Sent</TH>"
	       "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Rcvd</TH></TR>\n");

    while(nonIp != NULL) {
      char buf1[64];

      printTableDoubleEntry(buf, sizeof(buf), sap2name(nonIp->protocolId, buf1, sizeof(buf1)),
			    CONST_COLOR_1, (float)nonIp->sentBytes.value/1024,
			    100*((float)SD(nonIp->sentBytes.value, 
					   el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->otherSent.value)),
			    (float)nonIp->rcvdBytes.value/1024,
			    100*((float)SD(nonIp->rcvdBytes.value, 
					   el->nonIPTraffic == NULL ? 0 : el->nonIPTraffic->otherRcvd.value)));

      nonIp = nonIp->next;
    }

    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");
  }

 /* ************************************** */

  if(el->nonIPTraffic != NULL) {
    if(el->nonIPTraffic->unknownProtoSent || el->nonIPTraffic->unknownProtoRcvd) {
      printSectionTitle("Unknown Protocols");

      sendString("<CENTER>\n"
		 ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "DARK_BG">"
		 "<TH "TH_BG" WIDTH=200>Data&nbsp;Sent</TH>"
		 "<TH "TH_BG" WIDTH=200>Data&nbsp;Rcvd</TH></TR>\n");

      if(el->nonIPTraffic->unknownProtoSent == NULL) {
	sendString("<TR><TH "TH_BG">&nbsp;</TH>");
      } else {
	sendString("<TR><TH "TH_BG" ALIGN=LEFT>");
	for(i=0; i<MAX_NUM_UNKNOWN_PROTOS; i++)
	  printUnknownProto(el->nonIPTraffic->unknownProtoSent[i]);
	sendString("&nbsp;</TH>");
      }

      if(el->nonIPTraffic->unknownProtoRcvd == NULL) {
	sendString("<TH "TH_BG">&nbsp;</TH></TR>");
      } else {
	sendString("<TH "TH_BG" ALIGN=LEFT>");
	for(i=0; i<MAX_NUM_UNKNOWN_PROTOS; i++)
	  printUnknownProto(el->nonIPTraffic->unknownProtoRcvd[i]);
	sendString("&nbsp;</TH></TR>");
      }

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }
  }
}

/* ************************************ */

#ifdef INET6
void printIcmpv6Stats(HostTraffic *el) {
  char buf[LEN_GENERAL_WORK_BUFFER], formatBuf[32], formatBuf1[32];

  sendString("<CENTER>\n<H1>ICMPv6 Traffic</H1><p>\n");
  sendString("<TABLE BORDER=1 "TABLE_DEFAULTS">\n");
  sendString("<TR "TR_ON" "DARK_BG"><th>Type</th>"
             "<TH "TH_BG" ALIGN=LEFT>Pkt&nbsp;Sent</TH>"
             "<TH "TH_BG" ALIGN=LEFT>Pkt&nbsp;Rcvd</TH></TR>\n");

  if(el->icmpInfo->icmpMsgSent[ICMP6_ECHO_REQUEST].value+el->icmpInfo->icmpMsgRcvd[ICMP6_ECHO_REQUEST].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Echo Request</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ICMP6_ECHO_REQUEST].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP6_ECHO_REQUEST].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP6_ECHO_REPLY].value+el->icmpInfo->icmpMsgRcvd[ICMP6_ECHO_REPLY].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Echo Reply</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ICMP6_ECHO_REPLY].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP6_ECHO_REPLY].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP6_DST_UNREACH].value+el->icmpInfo->icmpMsgRcvd[ICMP6_DST_UNREACH].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Unreach</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ICMP6_DST_UNREACH].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP6_DST_UNREACH].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ND_REDIRECT].value+el->icmpInfo->icmpMsgRcvd[ND_REDIRECT].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Redirect</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ND_REDIRECT].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ND_REDIRECT].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ND_ROUTER_ADVERT].value+el->icmpInfo->icmpMsgRcvd[ND_ROUTER_ADVERT].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Router Advertisement</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ND_ROUTER_ADVERT].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ND_ROUTER_ADVERT].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ND_ROUTER_SOLICIT].value+el->icmpInfo->icmpMsgRcvd[ND_ROUTER_SOLICIT].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Router solicitation</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ND_ROUTER_SOLICIT].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ND_ROUTER_SOLICIT].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ND_NEIGHBOR_SOLICIT].value+el->icmpInfo->icmpMsgRcvd[ND_NEIGHBOR_SOLICIT].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Neighbor solicitation</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ND_NEIGHBOR_SOLICIT].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ND_NEIGHBOR_SOLICIT].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ND_NEIGHBOR_ADVERT].value+el->icmpInfo->icmpMsgRcvd[ND_NEIGHBOR_ADVERT].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Neighbor advertisment</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ND_NEIGHBOR_ADVERT].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ND_NEIGHBOR_ADVERT].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }
  sendString("</TABLE>"TABLE_OFF"</CENTER>\n");
}
#endif

/* ******************************************** */

void printIcmpv4Stats(HostTraffic *el) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  char formatBuf[32], formatBuf1[32];

  printSectionTitle("ICMP Traffic");
  sendString("<CENTER><TABLE BORDER=1 "TABLE_DEFAULTS">\n");
  sendString("<TR "TR_ON" "DARK_BG"><th>Type</th>"
	     "<TH "TH_BG" ALIGN=LEFT>Pkt&nbsp;Sent</TH>"
	     "<TH "TH_BG" ALIGN=LEFT>Pkt&nbsp;Rcvd</TH></TR>\n");

  if(el->icmpInfo->icmpMsgSent[ICMP_ECHO].value+el->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Echo Request</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_ECHO].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value+el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Echo Reply</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_UNREACH].value+el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Unreach</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_UNREACH].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_REDIRECT].value+el->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Redirect</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_REDIRECT].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

   if(el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value+el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Router Advertisement</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

   if(el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value+el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Time Exceeded</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB].value+el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Parameter Problem</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_MASKREQ].value+el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Network Mask Request</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_MASKREQ].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY].value+el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Network Mask Reply</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH].value+el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Source Quench</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP].value+el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Timestamp</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST].value+el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Info Request</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY].value+el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY].value > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Info Reply</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY].value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  /************ ICMPv6 info*********************/

  sendString("</TABLE>"TABLE_OFF"</CENTER>\n");
}

/* ************************************ */

void printHostIcmpStats(HostTraffic *el){
  int family;

  if(el->icmpInfo == NULL) return;
  family = el->hostIpAddress.hostFamily;
  if (family == AF_INET)
    printIcmpv4Stats(el);
#ifdef INET6
  else if (family == AF_INET6)
    printIcmpv6Stats(el);
#endif
}

/* ************************************ */

void printHostHTTPVirtualHosts(HostTraffic *el, int actualDeviceId) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  char formatBuf[32], formatBuf1[32];

  if((el->protocolInfo != NULL) && (el->protocolInfo->httpVirtualHosts != NULL)) {
    VirtualHostList *list = el->protocolInfo->httpVirtualHosts;

    printSectionTitle("HTTP Virtual Hosts Traffic");
    sendString("<CENTER>\n<TABLE BORDER=0 "TABLE_DEFAULTS"><TR><TD "TD_BG" VALIGN=TOP>\n");

    sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>"
	       "<TR "TR_ON" "DARK_BG"><TH "TH_BG">Virtual Host</TH>"
	       "<TH "TH_BG">Sent</TH><TH "TH_BG">Rcvd</TH></TR>\n");

    while(list != NULL) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=CENTER>%s&nbsp;</TD>"
		  "<TD "TD_BG" ALIGN=CENTER>%s&nbsp;</TD></TR>\n",
		  getRowColor(), list->virtualHostName,
		  formatBytes(list->bytesSent.value, 1, formatBuf, sizeof(formatBuf)),
		  formatBytes(list->bytesRcvd.value, 1, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);
      list = list->next;
    }
    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("<H5>NOTE: The above table is not updated in realtime but when connections are terminated.</H5>\n");
    sendString("</CENTER><P>\n");
  }
}

/* ************************************ */

HostTraffic* quickHostLink(HostSerial theSerial, int deviceId, HostTraffic *el) {
    FcNameServerCacheEntry *fcnsEntry;
  FcScsiCounters *tmp;
  HostTraffic *srcEl;
  
  if(cmpSerial(&theSerial, &myGlobals.broadcastEntry->hostSerial)) {
    memcpy(el, myGlobals.broadcastEntry, sizeof(HostTraffic));
    return(el);
  } else if(cmpSerial(&theSerial, &myGlobals.otherHostEntry->hostSerial)) {
    memcpy(el, myGlobals.otherHostEntry, sizeof(HostTraffic));
    return(0);
  }

  tmp = el->fcCounters;
  memset(el, 0, sizeof(HostTraffic));
  el->fcCounters = tmp;
  copySerial(&el->hostSerial, &theSerial);

  if((theSerial.serialType == SERIAL_IPV4) ||
     (theSerial.serialType == SERIAL_IPV6)){
    /* IP */
    char buf[LEN_GENERAL_WORK_BUFFER];

    addrcpy(&el->hostIpAddress,&theSerial.value.ipSerial.ipAddress);
    el->vlanId = theSerial.value.ipSerial.vlanId;

    strncpy(el->hostNumIpAddress,
	    _addrtostr(&el->hostIpAddress, buf, sizeof(buf)),
	    sizeof(el->hostNumIpAddress));

    // FIX -- Update address TODO
  } else if (theSerial.serialType == SERIAL_FC) {
    memcpy ((u_int8_t *)&el->fcCounters->hostFcAddress,
            (u_int8_t *)&theSerial.value.fcSerial.fcAddress,
            LEN_FC_ADDRESS);
    safe_snprintf (__FILE__, __LINE__, el->fcCounters->hostNumFcAddress, sizeof(el->fcCounters->hostNumFcAddress), 
		   "%02x.%02x.%02x", el->fcCounters->hostFcAddress.domain,
             el->fcCounters->hostFcAddress.area, el->fcCounters->hostFcAddress.port);
    setResolvedName(el, el->fcCounters->hostNumFcAddress, FLAG_HOST_SYM_ADDR_TYPE_FCID);

    el->fcCounters->vsanId = theSerial.value.fcSerial.vsanId;
    el->l2Family = FLAG_HOST_TRAFFIC_AF_FC;
    el->fcCounters->devType = SCSI_DEV_UNINIT;
    el->magic = CONST_MAGIC_NUMBER;
    
    if((srcEl = findHostBySerial (theSerial, deviceId)) != NULL) {
      strcpy (el->hostResolvedName, srcEl->hostResolvedName);
      el->hostResolvedNameType = srcEl->hostResolvedNameType;
    } else {
        fcnsEntry = findFcHostNSCacheEntry (&el->fcCounters->hostFcAddress, el->fcCounters->vsanId);
        if (fcnsEntry != NULL) {
	  if (fcnsEntry->alias != NULL) {
	    setResolvedName(el, fcnsEntry->alias, FLAG_HOST_SYM_ADDR_TYPE_FC_ALIAS);
	  }
	  else {
	    setResolvedName(el, (char*)fcnsEntry->pWWN.str, FLAG_HOST_SYM_ADDR_TYPE_FC_WWN);
	  }
	  memcpy((u_int8_t *)el->fcCounters->pWWN.str, (u_int8_t *)fcnsEntry->pWWN.str,
		  LEN_WWN_ADDRESS);
        }
    }
  } else {
    /* MAC */
    char *ethAddr;
    char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

    memcpy(el->ethAddress, theSerial.value.ethSerial.ethAddress, LEN_ETHERNET_ADDRESS);
    el->vlanId = theSerial.value.ethSerial.vlanId;
    ethAddr = etheraddr_string(el->ethAddress, etherbuf);
    strncpy(el->ethAddressString, ethAddr, sizeof(el->ethAddressString));
    if (el->hostIpAddress.hostFamily == AF_INET)
      el->hostIp4Address.s_addr = 0x1234; /* dummy */
  }

  return(el);
}

/* ************************************ */

void printHostContactedPeers(HostTraffic *el, int actualDeviceId) {
  u_int i, titleSent = 0;
  char buf[LEN_GENERAL_WORK_BUFFER], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  HostTraffic tmpEl;

  if (isFcHost (el)) {
      printFcHostContactedPeers (el, actualDeviceId);
      return;
  }
  
  if((el->pktSent.value != 0) || (el->pktRcvd.value != 0)) {
      int ok =0;

    for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
      if(((!emptySerial(&el->contactedSentPeers.peersSerials[i])
	   && (!cmpSerial(&el->contactedSentPeers.peersSerials[i], &myGlobals.otherHostEntry->hostSerial)))
	  || ((!emptySerial(&el->contactedRcvdPeers.peersSerials[i])
	       && (!cmpSerial(&el->contactedRcvdPeers.peersSerials[i], &myGlobals.otherHostEntry->hostSerial)))))) {
	ok = 1;
	break;
      }

    if(ok) {
      HostTraffic *el2;
      int numEntries;

      for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	  if(!emptySerial(&el->contactedSentPeers.peersSerials[i])
	     && (!cmpSerial(&el->contactedSentPeers.peersSerials[i], &myGlobals.otherHostEntry->hostSerial))) {
	      if((el2 = quickHostLink(el->contactedSentPeers.peersSerials[i],
				      myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
		  if(numEntries == 0) {
		      printSectionTitle("Last Contacted Peers");
		      titleSent = 1;
		      sendString("<CENTER>\n<TABLE BORDER=0 "TABLE_DEFAULTS"><TR><TD "TD_BG" VALIGN=TOP>\n");

		      sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>"
				 "<TR "TR_ON" "DARK_BG"><TH "TH_BG">Sent To</TH>"
				 "<TH "TH_BG">IP Address</TH></TR>\n");
		  }

		  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
			      "<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;</TD></TR>\n",
			      getRowColor(), makeHostLink(el2, 0, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			      el2->hostNumIpAddress);

		  sendString(buf);
		  numEntries++;
	      }
	  }

      if(numEntries > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">Total Contacts</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT "DARK_BG">%lu</TD></TR>\n",
		    getRowColor(), (unsigned long)el->totContactedSentPeers);
       sendString(buf);

       sendString("</TABLE>"TABLE_OFF"</TD><TD "TD_BG" VALIGN=TOP>\n");
      } else
	sendString("&nbsp;</TD><TD "TD_BG">\n");

      /* ***************************************************** */

      for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	  if((!emptySerial(&el->contactedRcvdPeers.peersSerials[i]))
	     && (!cmpSerial(&el->contactedRcvdPeers.peersSerials[i], &myGlobals.otherHostEntry->hostSerial))) {

	    if((el2 = quickHostLink(el->contactedRcvdPeers.peersSerials[i],
					myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	      if(numEntries == 0) {
		  if(!titleSent) printSectionTitle("Last Contacted Peers");
		sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">"
			   "<TR "TR_ON" "DARK_BG"><TH "TH_BG">Received From</TH>"
			   "<TH "TH_BG">IP Address</TH></TR>\n");
	      }

	      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
			  "<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;</TD></TR>\n",
			  getRowColor(), makeHostLink(el2, 0, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			  el2->hostNumIpAddress);

	      sendString(buf);
	      numEntries++;
	    }
	  }

      if(numEntries > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">Total Contacts</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT "DARK_BG">%lu</TD></TR>\n",
		    getRowColor(), (unsigned long)el->totContactedRcvdPeers);
	sendString(buf);

	sendString("</TABLE>"TABLE_OFF"\n");
      }

      sendString("</TD></TR></TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    } /* ok */
  }
}

/* ************************************ */

/* Function below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */

char *getSessionState(IPSession *session) {
  switch (session->sessionState) {
  case FLAG_STATE_SYN:
    return("Sent&nbsp;Syn");
  case FLAG_STATE_SYN_ACK:
    return("Rcvd&nbsp;Syn/Ack");
  case FLAG_STATE_ACTIVE:
    return("Active");
  case FLAG_STATE_FIN1_ACK0:
    return("Fin1&nbsp;Ack0");
  case FLAG_STATE_FIN1_ACK1:
    return("Fin1&nbsp;Ack1");
  case FLAG_STATE_FIN2_ACK0:
    return("Fin2&nbsp;Ack0");
  case FLAG_STATE_FIN2_ACK1:
    return("Fin2&nbsp;Ack1");
  case FLAG_STATE_FIN2_ACK2:
    return("Fin2&nbsp;Ack2");
  case FLAG_STATE_TIMEOUT:
    return("Timeout");
  case FLAG_STATE_END:
    return("End");
  }

 return("*Unknown*");
}

/* ************************************ */

void printHostSessions(HostTraffic *el, int actualDeviceId) {
  printActiveTCPSessions(actualDeviceId, 0, el);
}

/* ******************************* */
/*
   Return codes:

   OK          0
   Minor       1
   Warning     2
   Error       3!
*/

u_short isHostHealthy(HostTraffic *el) {
  if(((myGlobals.runningPref.dontTrustMACaddr == 0) && hasDuplicatedMac(el)) 
     || hasSentIpDataOnZeroPort(el))
    return(3);

  if(hasWrongNetmask(el))
    return(2);

  if((el->totContactedSentPeers > CONTACTED_PEERS_THRESHOLD)
     || (el->totContactedRcvdPeers > CONTACTED_PEERS_THRESHOLD)) {
    /* Mail/DNS/HTTP server usually touch many hosts */
    if(!(isSMTPhost(el) || nameServerHost(el) || isHTTPhost(el))) {
      return(2);
    }
  }

  if((el->secHostPkts != NULL)
     && ((el->secHostPkts->nullPktsSent.value.value > 0)
	 || (el->secHostPkts->synFinPktsSent.value.value > 0)
	 || (el->secHostPkts->ackXmasFinSynNullScanSent.value.value > 0)
	 || (el->secHostPkts->tinyFragmentSent.value.value > 0)
	 || (el->secHostPkts->icmpFragmentSent.value.value > 0)
	 || (el->secHostPkts->overlappingFragmentSent.value.value > 0)
	 || (el->secHostPkts->malformedPktsRcvd.value.value > 0))) {
    return(2);
  }

  if((el->secHostPkts != NULL)
     && ((el->secHostPkts->rstPktsRcvd.value.value > 0)
	 || (el->secHostPkts->rejectedTCPConnRcvd.value.value > 0)
	 || (el->secHostPkts->udpToClosedPortRcvd.value.value > 0)
	 || (el->secHostPkts->udpToDiagnosticPortSent.value.value > 0)
	 || (el->secHostPkts->closedEmptyTCPConnSent.value.value > 0)
	 || (el->secHostPkts->icmpPortUnreachRcvd.value.value > 0)
	 || (el->secHostPkts->icmpHostNetUnreachRcvd.value.value > 0)
	 || (el->secHostPkts->icmpProtocolUnreachRcvd.value.value > 0)
	 || (el->secHostPkts->icmpAdminProhibitedRcvd.value.value > 0))) {
    return(1);
  }

  return(0);
}

/* ************************************ */

static void checkHostHealthness(HostTraffic *el) {
  char buf[LEN_GENERAL_WORK_BUFFER];

  if(hasWrongNetmask(el)
     || hasDuplicatedMac(el)
     || hasSentIpDataOnZeroPort(el)
     || (el->totContactedSentPeers > CONTACTED_PEERS_THRESHOLD) || (el->totContactedRcvdPeers > CONTACTED_PEERS_THRESHOLD)
     || ((el->secHostPkts != NULL)
	 && ((el->secHostPkts->nullPktsSent.value.value > 0)
	     || (el->secHostPkts->synFinPktsSent.value.value > 0)
	     || (el->secHostPkts->rstPktsRcvd.value.value > 0)
	     || (el->secHostPkts->ackXmasFinSynNullScanSent.value.value > 0)
	     || (el->secHostPkts->rejectedTCPConnRcvd.value.value > 0)
	     || (el->secHostPkts->udpToClosedPortRcvd.value.value > 0)
	     || (el->secHostPkts->udpToDiagnosticPortSent.value.value > 0)
	     || (el->secHostPkts->tinyFragmentSent.value.value > 0)
	     || (el->secHostPkts->icmpFragmentSent.value.value > 0)
	     || (el->secHostPkts->overlappingFragmentSent.value.value > 0)
	     || (el->secHostPkts->closedEmptyTCPConnSent.value.value > 0)
	     || (el->secHostPkts->icmpPortUnreachRcvd.value.value > 0)
	     || (el->secHostPkts->icmpHostNetUnreachRcvd.value.value > 0)
	     || (el->secHostPkts->icmpProtocolUnreachRcvd.value.value > 0)
	     || (el->secHostPkts->icmpAdminProhibitedRcvd.value.value > 0)
	     || (el->secHostPkts->malformedPktsRcvd.value.value > 0)))) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s "
		CONST_IMG_HIGH_RISK 
		CONST_IMG_MEDIUM_RISK 
                CONST_IMG_LOW_RISK 
		"</TH><TD "TD_BG" ALIGN=RIGHT NOWRAP><OL>", getRowColor(),
		"Host Healthness (Risk Flags)");
    sendString(buf);

    if(hasDuplicatedMac(el))
      sendString("<LI>" CONST_IMG_HIGH_RISK "<A HREF=/" CONST_NTOP_HELP_HTML "#2>"
		 "Duplicated MAC found for this IP address (spoofing?)</A>\n");

    if(hasSentIpDataOnZeroPort(el))
      sendString("<LI>" CONST_IMG_HIGH_RISK "<A HREF=/" CONST_NTOP_HELP_HTML "#3>"
		 "Traffic on suspicious IP ports</A>\n");

    if(hasWrongNetmask(el))
      sendString("<LI>" CONST_IMG_MEDIUM_RISK "<A HREF=/" CONST_NTOP_HELP_HTML "#1>"
		 "Wrong network mask or bridging enabled</A>\n");

    if((el->totContactedSentPeers > CONTACTED_PEERS_THRESHOLD)
       || (el->totContactedRcvdPeers > CONTACTED_PEERS_THRESHOLD)) {
      sendString("<LI>" CONST_IMG_MEDIUM_RISK "<A HREF=/" CONST_NTOP_HELP_HTML "#4>"
		 "Suspicious activities: too many host contacts</A>\n");
    }

    if((el->secHostPkts != NULL)
       && ((el->secHostPkts->nullPktsSent.value.value > 0)
	   || (el->secHostPkts->synFinPktsSent.value.value > 0)
	   || (el->secHostPkts->ackXmasFinSynNullScanSent.value.value > 0)
	   || (el->secHostPkts->tinyFragmentSent.value.value > 0)
	   || (el->secHostPkts->icmpFragmentSent.value.value > 0)
	   || (el->secHostPkts->overlappingFragmentSent.value.value > 0)
	   || (el->secHostPkts->malformedPktsRcvd.value.value > 0))) {
      sendString("<LI>" CONST_IMG_MEDIUM_RISK "<A HREF=/" CONST_NTOP_HELP_HTML "#5>"
		 "Unexpected packets (e.g. traffic to closed port or connection reset)</A>:<br>\n");
      if(el->secHostPkts->synFinPktsSent.value.value > 0) sendString("[Sent: syn-fin]&nbsp;");
      if(el->secHostPkts->ackXmasFinSynNullScanSent.value.value > 0) sendString("[Sent: xmas]&nbsp;");
      if(el->secHostPkts->tinyFragmentSent.value.value > 0) sendString("[Sent: Tiny frag]&nbsp;");
      if(el->secHostPkts->icmpFragmentSent.value.value > 0) sendString("[Sent: icmp frag]&nbsp;");
      if(el->secHostPkts->overlappingFragmentSent.value.value > 0) sendString("[Sent: overlapfrag]&nbsp;");
      if(el->secHostPkts->malformedPktsRcvd.value.value > 0) sendString("[Rcvd: malformed]&nbsp;");
    }

    if((el->secHostPkts != NULL)
       && ((el->secHostPkts->rejectedTCPConnRcvd.value.value > 0)
	   || (el->secHostPkts->udpToClosedPortRcvd.value.value > 0)
	   || (el->secHostPkts->udpToDiagnosticPortSent.value.value > 0)
	   || (el->secHostPkts->rstPktsRcvd.value.value > 0)
	   || (el->secHostPkts->closedEmptyTCPConnSent.value.value > 0)
	   || (el->secHostPkts->icmpPortUnreachRcvd.value.value > 0)
	   || (el->secHostPkts->icmpHostNetUnreachRcvd.value.value > 0)
	   || (el->secHostPkts->icmpProtocolUnreachRcvd.value.value > 0)
	   || (el->secHostPkts->icmpAdminProhibitedRcvd.value.value > 0))) {
      sendString("<LI>" CONST_IMG_LOW_RISK "<A HREF=/" CONST_NTOP_HELP_HTML "#6>"
		 "Unexpected packets (e.g. traffic to closed port or connection reset)</A>:<br>\n");
      if(el->secHostPkts->rejectedTCPConnRcvd.value.value > 0) sendString("[Rcvd: rejected]&nbsp;");
      if(el->secHostPkts->udpToClosedPortRcvd.value.value > 0) sendString("[Sent: udp to closed]&nbsp;");
      if(el->secHostPkts->udpToDiagnosticPortSent.value.value > 0) sendString("[Sent: udp to diag]&nbsp;");
      if(el->secHostPkts->rstPktsRcvd.value.value > 0) sendString("[Rcvd: rst]&nbsp;");
      if(el->secHostPkts->closedEmptyTCPConnSent.value.value > 0) sendString("[Sent: closed-empty]&nbsp;");
      if(el->secHostPkts->icmpPortUnreachRcvd.value.value > 0) sendString("[Rcvd: port unreac]&nbsp;");
      if(el->secHostPkts->icmpHostNetUnreachRcvd.value.value > 0) sendString("[Rcvd: hostnet unreac]&nbsp;");
      if(el->secHostPkts->icmpProtocolUnreachRcvd.value.value > 0) sendString("[Rcvd: proto unreac]&nbsp;");
      if(el->secHostPkts->icmpAdminProhibitedRcvd.value.value > 0) sendString("[Rcvd: admin prohib]&nbsp;");
    }

    sendString("</OL></TD></TR>\n");
  }
}

/* ************************************ */

static void printUserList(HostTraffic *el) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  UserList *list = el->protocolInfo->userList;
  int num = 0;

  while(list != NULL) {
    if(num > 0) sendString("<br>");

    if(FD_ISSET(BITFLAG_SMTP_USER, &(list->userFlags))) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<A HREF=\"mailto:%s\">%s</A>&nbsp;[&nbsp;SMTP&nbsp;]\n", 
		    list->userName, list->userName); sendString(buf);
    } else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s&nbsp;[", list->userName); sendString(buf);
      
      if(FD_ISSET(BITFLAG_POP_USER, &(list->userFlags))) sendString("&nbsp;POP&nbsp;");
      if(FD_ISSET(BITFLAG_IMAP_USER, &(list->userFlags))) sendString("&nbsp;IMAP&nbsp;");
      if(FD_ISSET(BITFLAG_SMTP_USER, &(list->userFlags))) sendString("&nbsp;SMTP&nbsp;");
      if(FD_ISSET(BITFLAG_P2P_USER, &(list->userFlags))) sendString("&nbsp;P2P&nbsp;");
      if(FD_ISSET(BITFLAG_FTP_USER, &(list->userFlags))) sendString("&nbsp;FTP&nbsp;");
      if(FD_ISSET(BITFLAG_MESSENGER_USER, &(list->userFlags))) sendString("&nbsp;MSG&nbsp;");
      if(FD_ISSET(BITFLAG_VOIP_USER, &(list->userFlags))) sendString("&nbsp;VoIP&nbsp;");
      if(FD_ISSET(BITFLAG_DAAP_USER, &(list->userFlags))) sendString("&nbsp;DAAP&nbsp;");
      sendString("]\n");
    }

    list = list->next;
    num++;
  }
}

/* ************************************ */

void checkHostProvidedServices(HostTraffic *el) {
  char buf[LEN_GENERAL_WORK_BUFFER];

  if(isServer(el)
     || isWorkstation(el)
     || isMasterBrowser(el)
     || isPrinter(el)
     || isBridgeHost(el)
     || nameServerHost(el) || isNtpServer(el)
     || gatewayHost(el) || isVoIPHost(el)
     || isSMTPhost(el) || isIMAPhost(el) || isPOPhost(el)
     || isDirectoryHost(el)
     || isFTPhost(el)
     || isHTTPhost(el)
     || isWINShost(el)
     || isDHCPClient(el) || isDHCPServer(el)
     ) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>", getRowColor(), "Host Type");
    sendString(buf);

    if(isServer(el))           sendString("Server<BR>\n");
    if(isWorkstation(el))      sendString("Workstation<BR>\n");
    if(isMasterBrowser(el))    sendString("Master Browser<BR>\n");

    if(isPrinter(el))          sendString("Printer&nbsp;" CONST_IMG_PRINTER "<BR>\n");
    if(isBridgeHost(el))       sendString("Layer-2 Switch/Bridge&nbsp;" CONST_IMG_BRIDGE "<BR>\n");

    if(nameServerHost(el))     sendString("Name Server&nbsp;" CONST_IMG_DNS_SERVER "<BR>\n");
    if(isNtpServer(el))        sendString("NTP Server&nbsp;" CONST_IMG_NTP_SERVER "<BR>\n");
    if(gatewayHost(el))        sendString("<A HREF="CONST_LOCAL_ROUTERS_LIST_HTML">Gateway/Router</A>&nbsp;" CONST_IMG_ROUTER "<BR>\n");

    if(isVoIPGateway(el) && (!isVoIPClient(el)))  
      sendString("VoIP Gateway&nbsp;" CONST_IMG_VOIP_HOST "<BR>\n");
    else if(isVoIPClient(el))  
      sendString("VoIP Host&nbsp;" CONST_IMG_VOIP_HOST "<BR>\n");

    if(isSMTPhost(el))         sendString("SMTP (Mail) Server&nbsp;" CONST_IMG_SMTP_SERVER "<BR>\n");
    if(isPOPhost(el))          sendString("POP Server&nbsp;" CONST_IMG_POP_SERVER "<BR>\n");
    if(isIMAPhost(el))         sendString("IMAP Server&nbsp;" CONST_IMG_IMAP_SERVER "<BR>\n");
    if(isDirectoryHost(el))    sendString("Directory Server&nbsp;" CONST_IMG_DIRECTORY_SERVER " <BR>\n");
    if(isFTPhost(el))          sendString("FTP Server&nbsp;" CONST_IMG_FTP_SERVER "<BR>\n");
    if(isHTTPhost(el))         sendString("HTTP Server&nbsp;" CONST_IMG_HTTP_SERVER "<BR>\n");
    if(isWINShost(el))         sendString("WINS Server<BR>\n");

    if(isDHCPClient(el))       sendString("BOOTP/DHCP Client&nbsp;" CONST_IMG_DHCP_CLIENT "<BR>\n");
    if(isDHCPServer(el))       sendString("BOOTP/DHCP Server&nbsp;" CONST_IMG_DHCP_SERVER "<BR>\n");

    sendString("</TD></TR>");
  }
}

/* ************************************ */

void printHostDetailedInfo(HostTraffic *el, int actualDeviceId) {
  char buf[3*LEN_GENERAL_WORK_BUFFER], buf1[64], buf2[128], osBuf[512];
  float percentage;
  Counter total;
  int printedHeader, i;
  char *dynIp, *multihomed, *multivlaned;
  u_short as=0;
  HostTraffic *theHost, tmpEl;
  char formatBuf[LEN_TIMEFORMAT_BUFFER], formatBuf1[LEN_TIMEFORMAT_BUFFER], 
    formatBuf2[32], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER], custom_host_name[128];

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "hostname.%s",
		(el->hostNumIpAddress[0] != '\0') ? el->hostNumIpAddress : el->ethAddressString);
  
  if(fetchPrefsValue(buf, custom_host_name, sizeof(custom_host_name)) == -1) {
    custom_host_name[0] = '\0';
  }

  buf1[0]=0;

  if((el->hostResolvedName[0] != '\0') && (strcmp(el->hostResolvedName, el->hostNumIpAddress))) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Info about "
		" <A HREF=\"http://%s/\" TARGET=\"_blank\" "
		  "TITLE=\"Link to web server on host, if available\" class=external>%s</A>\n",
		  (custom_host_name[0] != '\0') ? custom_host_name : el->hostResolvedName,
		  (custom_host_name[0] != '\0') ? custom_host_name : el->hostResolvedName);

    safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "Info about %s", el->hostResolvedName);
  } else if(el->hostNumIpAddress[0] != '\0') {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Info about "
		  " <A HREF=\"http://%s%s%s/\" TARGET=\"_blank\" "
		  "TITLE=\"Link to web server on host, if available\" class=tooltip>%s</A>\n",
		  el->hostIpAddress.hostFamily == AF_INET6 ? "[" : "",
		  el->hostNumIpAddress,
		  el->hostIpAddress.hostFamily == AF_INET6 ? "]" : "",
		  (custom_host_name[0] != '\0') ? custom_host_name : el->hostNumIpAddress);

    safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "Info about %s", 
		  (custom_host_name[0] != '\0') ? custom_host_name : el->hostNumIpAddress);
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Info about %s", 
		  (custom_host_name[0] != '\0') ? custom_host_name : el->ethAddressString);

    safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "Info about %s", 
		  (custom_host_name[0] != '\0') ? custom_host_name : el->ethAddressString);
  }

  printHTMLheader(buf2, buf, 0);
  sendString("<CENTER>\n<P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=80%%>\n");

  if(el->hostNumIpAddress[0] != '\0') {
    char *hostType, tmpBuf[64];

    if(broadcastHost(el)) hostType = "broadcast";
    else if(multicastHost(el)) hostType = "multicast";
    else hostType = "unicast";

    if(isDHCPClient(el))
      dynIp = "/dynamic";
    else
      dynIp = "";

    if(isMultihomed(el) && (!broadcastHost(el)))
      multihomed = "&nbsp;-&nbsp;multihomed&nbsp;" CONST_IMG_MULTIHOMED;
    else
      multihomed = "";

    if(isMultivlaned(el) && (!broadcastHost(el)))
      multivlaned = "&nbsp;-&nbsp;multivlaned&nbsp;" CONST_IMG_MULTIVLANED;
    else
      multivlaned = "";

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;[%s%s%s%s]",
		  getRowColor(),
		  "IP&nbsp;Address", el->hostNumIpAddress,
		  hostType, dynIp, multihomed, multivlaned);
    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "&nbsp;[ <A title=\"Purge this host from ntop's memory\" class=tooltip "
		  "HREF=\"/"CONST_PURGE_HOST"?key=%s\">Purge Asset</A> <IMG SRC=/lock.png> ]",
		  serial2str(el->hostSerial, tmpBuf, sizeof(tmpBuf)));
    sendString(buf);
    
    sendString("</TD></TR>\n");
    
    if(isMultihomed(el) && (!broadcastHost(el))) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		    "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD ALIGN=RIGHT>&nbsp;<OL>",
		    getRowColor(), "Multihomed Addresses");
      sendString(buf);
      
      for(theHost=getFirstHost(actualDeviceId);
	  theHost != NULL; theHost = getNextHost(actualDeviceId, theHost)) {
	if((theHost != el)
	   && (memcmp(theHost->ethAddress, el->ethAddress, LEN_ETHERNET_ADDRESS) == 0)) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<LI><A HREF=/%s.html>%s</A>",
			theHost->hostNumIpAddress, theHost->hostNumIpAddress);
	  sendString(buf);
	}
      } /* for */
      
      sendString("</TD></TR>");
    }

    /* traceEvent(CONST_TRACE_INFO, "-> %d", el->network_mask); */

    if((el->network_mask > 0) && (el->network_mask != 32)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		    "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n", getRowColor(),
		    "Host&nbsp;Network", host2networkName(el, buf1, sizeof(buf1)));
      sendString(buf);
    }

    if((el->protocolInfo != NULL) && (el->protocolInfo->dhcpStats != NULL)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>",
		  getRowColor(), "DHCP Information");
      sendString(buf);

      sendString("<TD "TD_BG"><TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>\n");

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n", getRowColor(), "DHCP Server",
		  _intoa(el->protocolInfo->dhcpStats->dhcpServerIpAddress, buf1, sizeof(buf1)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n", getRowColor(), "Previous IP Address",
		  _intoa(el->protocolInfo->dhcpStats->previousIpAddress, buf1, sizeof(buf1)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n",
		  getRowColor(), "Address Assigned on",
		  formatTime(&(el->protocolInfo->dhcpStats->assignTime), formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n",
		  getRowColor(), "To be Renewed Before",
		  formatTime(&(el->protocolInfo->dhcpStats->renewalTime), formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n",
		  getRowColor(), "Lease Ends on",
		  formatTime(&(el->protocolInfo->dhcpStats->leaseTime), formatBuf, sizeof(formatBuf)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">DHCP Packets</TH>"
		  "<TH "TH_BG" ALIGN=CENTER "DARK_BG">Sent</TH><TH "TH_BG" ALIGN=RIGHT "DARK_BG">Rcvd</TH></TR>\n",
		  getRowColor());
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Discover",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_DISCOVER_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_DISCOVER_MSG].value, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Offer",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_OFFER_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_OFFER_MSG].value, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Request",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_REQUEST_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_REQUEST_MSG].value, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Decline",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_DECLINE_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_DECLINE_MSG].value, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Ack",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_ACK_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_ACK_MSG].value, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Nack",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_NACK_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_NACK_MSG].value, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Release",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_RELEASE_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_RELEASE_MSG].value, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Inform",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_INFORM_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_INFORM_MSG].value, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);


      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Unknown Msg",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_UNKNOWN_MSG].value, 
			     formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_UNKNOWN_MSG].value,
			     formatBuf1, sizeof(formatBuf1)));
      sendString(buf);

      sendString("</TABLE>"TABLE_OFF"</TD></TR>\n");
    }
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		"<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">Custom Host Name</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>"
		"<FORM METHOD=GET ACTION=/editPrefs.html>"
		"<INPUT TYPE=hidden name=key value=\"hostname.%s\">"
		"<input type=text name=val value=\"%s\">"
		"<INPUT TYPE=image src=/"CONST_EDIT_IMG" value=\"Submit\" alt=\"Set custom host name\"></TD></TR>\n",
		getRowColor(),
		(el->hostNumIpAddress[0] != '\0') ? el->hostNumIpAddress : el->ethAddressString,
		custom_host_name);
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
	      "<TD "TD_BG" ALIGN=RIGHT>"
	      "%s&nbsp;&nbsp;-&nbsp;&nbsp;%s&nbsp;[Inactive since %s]</TD></TR>\n",
	      getRowColor(),
	      "First/Last&nbsp;Seen",
	      formatTime(&(el->firstSeen), formatBuf, sizeof(formatBuf)),
	      formatTime(&(el->lastSeen), formatBuf1, sizeof(formatBuf1)),
	      formatSeconds(myGlobals.actTime-el->lastSeen, formatBuf2, sizeof(formatBuf2)));
  sendString(buf);


  if(el->hostAS != 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<A class=external HREF=\"http://ws.arin.net/cgi-bin/whois.pl?queryinput=AS%d\">%d</A>"
		  "&nbsp;[%s]</TD></TR>\n",
		  getRowColor(), "Autonomous System", 
		  el->hostAS, el->hostAS, (el->hostASDescr != NULL) ? el->hostASDescr : "No AS info");
    sendString(buf);
  }

  if((el->known_subnet_id != UNKNOWN_SUBNET_ID) 
     && (el->known_subnet_id < myGlobals.numKnownSubnets)) {
    char subnet_buf[48];

    host2networkName(el, subnet_buf, sizeof(subnet_buf));

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<A HREF=\""CONST_DOMAIN_STATS_HTML"?dom=%d&netmode=1\">%s</A></TD></TR>\n", getRowColor(),
		  "Subnet", el->known_subnet_id, subnet_buf);
    sendString(buf);
  }

  if(el->dnsDomainValue && (el->dnsDomainValue[0] != '\0')) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s</TD></TR>\n", getRowColor(),
		  "Domain", el->dnsDomainValue);
    sendString(buf);
  }

  if((el->ethAddressString[0] != '\0')
     && strcmp(el->ethAddressString, "00:00:00:00:00:00")
     && strcmp(el->ethAddressString, "00:01:02:03:04:05") /* dummy address */) {

    if(isMultihomed(el)) {
      char *symMacAddr, symLink[32];
      char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

      symMacAddr = etheraddr_string(el->ethAddress, etherbuf);
      strcpy(symLink, symMacAddr);
      urlFixupToRFC1945Inplace(symLink);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<A HREF=%s.html>%s</A>%s</TD></TR>\n",
		  getRowColor(), "Main Host MAC Address",
		  symLink, symMacAddr,
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
      sendString(buf);

    } else {
      char * vendorName = getVendorInfo(el->ethAddress, 1);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		    "%s %s%s%s%s</TD></TR>\n",
		    getRowColor(), "MAC&nbsp;Address <IMG ALT=\"Network Interface Card (NIC)\" SRC=/card.gif BORDER=0 "TABLE_DEFAULTS">",
		    el->ethAddressString,
		    myGlobals.separator /* it avoids empty cells not to be rendered */,
		    (vendorName[0] != '\0') ? "[" : "",
		    vendorName,
		    (vendorName[0] != '\0') ? "]" : "");
      sendString(buf);
    }
  }

  if(((el->lastEthAddress[0] != 0)
      || (el->lastEthAddress[1] != 0)
      || (el->lastEthAddress[2] != 0)
      || (el->lastEthAddress[3] != 0)
      || (el->lastEthAddress[4] != 0)
      || (el->lastEthAddress[5] != 0) /* The address isn't empty */)
     && (memcmp(el->lastEthAddress, el->ethAddress, LEN_ETHERNET_ADDRESS) != 0)) {
    /* Different MAC addresses */
    char *symMacAddr, symLink[32], shortBuf[64];
    char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];
    char *vendorName;

    symMacAddr = etheraddr_string(el->lastEthAddress, etherbuf);
    strcpy(symLink, symMacAddr);
    urlFixupToRFC1945Inplace(symLink);

    if(!myGlobals.runningPref.dontTrustMACaddr) {
      safe_snprintf(__FILE__, __LINE__, shortBuf, sizeof(shortBuf), "<A HREF=%s.html>%s</A>", symLink, symMacAddr);
    } else {
      strcpy(shortBuf, symMacAddr);
    }    

    vendorName = getVendorInfo(el->lastEthAddress, 1);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s %s%s%s%s"
		  "</TD></TR>\n",
		  getRowColor(),
		  "Last MAC Address/Router <IMG ALT=\"Network Interface Card (NIC)/Router\" SRC=/card.gif BORDER=0 "TABLE_DEFAULTS">",
		  shortBuf,
		  myGlobals.separator /* it avoids empty cells not to be rendered */,
		  (vendorName[0] != '\0') ? "[" : "",
		  vendorName,
		  (vendorName[0] != '\0') ? "]" : "");
    sendString(buf);
  }

  if(el->hostNumIpAddress[0] != '\0') {
    setHostFingerprint(el);

    if((el->fingerprint != NULL) && (el->fingerprint[0] == ':') && (strlen(el->fingerprint) > 2)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "OS&nbsp;Name",
		  getOSFlag(el, NULL, 1, osBuf, sizeof(osBuf)),
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
      sendString(buf);
    }
  }

  if((as = getHostAS(el)) != 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<A HREF=/%s?dom=%d&netmode=2>%d</A></TD></TR>\n", getRowColor(), "Origin&nbsp;AS", CONST_DOMAIN_STATS_HTML, as, as);
    sendString(buf);
  }

  if(el->vlanId != NO_VLAN) {
    char tmpBuf[64];

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s</TD></TR>\n", getRowColor(), "VLAN&nbsp;Id", vlan2name(el->vlanId, tmpBuf, sizeof(tmpBuf)));
    sendString(buf);
  }

  if(el->ifId != NO_INTERFACE) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%d</TD></TR>\n", getRowColor(), "Interface&nbsp;Id", el->ifId);
    sendString(buf);
  }

  if(el->nonIPTraffic) {
    if((el->nonIPTraffic->nbHostName != NULL) || (el->nonIPTraffic->nbDomainName != NULL)) {
      if(el->nonIPTraffic->nbAccountName) {
	if(el->nonIPTraffic->nbDomainName != NULL) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
			"%s@%s&nbsp;[domain %s] (%s) %s</TD></TR>\n",
			getRowColor(), "NetBios&nbsp;Name",
			el->nonIPTraffic->nbAccountName, el->nonIPTraffic->nbHostName, el->nonIPTraffic->nbDomainName,
			getNbNodeType(el->nonIPTraffic->nbNodeType),
			el->nonIPTraffic->nbDescr ? el->nonIPTraffic->nbDescr : "");
	} else {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		      "%s@%s (%s) %s</TD></TR>\n",
		      getRowColor(), "NetBios&nbsp;Name",
		      el->nonIPTraffic->nbAccountName, el->nonIPTraffic->nbHostName,
		      getNbNodeType(el->nonIPTraffic->nbNodeType),
		      el->nonIPTraffic->nbDescr ? el->nonIPTraffic->nbDescr : "");
	}
      } else {
	if(el->nonIPTraffic->nbDomainName != NULL) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		      "%s&nbsp;[domain %s] (%s) %s</TD></TR>\n",
		      getRowColor(), "NetBios&nbsp;Name",
		      el->nonIPTraffic->nbHostName != NULL ? el->nonIPTraffic->nbHostName : "",
		      el->nonIPTraffic->nbDomainName,
		      getNbNodeType(el->nonIPTraffic->nbNodeType),
		      el->nonIPTraffic->nbDescr ? el->nonIPTraffic->nbDescr : "");
	} else {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		      "%s (%s) %s</TD></TR>\n",
		      getRowColor(), "NetBios&nbsp;Name",
		      el->nonIPTraffic->nbHostName,
		      getNbNodeType(el->nonIPTraffic->nbNodeType),
		      el->nonIPTraffic->nbDescr ? el->nonIPTraffic->nbDescr : "");
	}
      }

      sendString(buf);
    } else if(el->nonIPTraffic->nbHostName != NULL) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s&nbsp;(%s) %s</TD></TR>\n",
		  getRowColor(), "NetBios&nbsp;Name",
		  el->nonIPTraffic->nbHostName, getNbNodeType(el->nonIPTraffic->nbNodeType),
		  el->nonIPTraffic->nbDescr ? el->nonIPTraffic->nbDescr : "");
      sendString(buf);
    }

    if(el->nonIPTraffic->atNetwork != 0) {
      char *nodeName = el->nonIPTraffic->atNodeName;

      if(nodeName == NULL) nodeName = "";

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s&nbsp;\n",
		  getRowColor(), "AppleTalk&nbsp;Name",
		  nodeName);
      sendString(buf);

      if(el->nonIPTraffic->atNodeType[0] != NULL) {
	sendString("(");
	for(i=0; i<MAX_NODE_TYPES; i++)
	  if(el->nonIPTraffic->atNodeType[i] == NULL)
	    break;
	  else {
	    if(i > 0) sendString("/");
	    sendString(el->nonIPTraffic->atNodeType[i]);
	  }

	sendString(")&nbsp;");
      }

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[%d.%d]</TD></TR>\n",
		  el->nonIPTraffic->atNetwork, el->nonIPTraffic->atNode);
      sendString(buf);
    }

    if(el->nonIPTraffic->ipxHostName != NULL) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>"
		  "%s&nbsp;[", getRowColor(), "IPX&nbsp;Name",
		  el->nonIPTraffic->ipxHostName);
      sendString(buf);

      for(i=0; i<el->nonIPTraffic->numIpxNodeTypes; i++) {
	if(i>0) sendString("/");
	sendString(getSAPInfo(el->nonIPTraffic->ipxNodeType[i], 1));
      }

      sendString("]</TD></TR>\n");
    }
  }

  if(!multicastHost(el)) {
    if(subnetPseudoLocalHost(el)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		    "%s</TD></TR>\n", getRowColor(),
		    "Host&nbsp;Location", 
		    "Local (inside specified/local subnet or known network list)");
    } else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		    "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		    "%s</TD></TR>\n", getRowColor(),
		    "Host&nbsp;Location",
		    "Remote (outside specified/local subnet)");
    }
    sendString(buf);
  }


  if(el->geo_ip) {
    char *countryIcon, buf3[512] = { '\0' };
    
    if(myGlobals.runningPref.mapperURL) buildMapLink(el, buf3, sizeof(buf3));
    countryIcon = getHostCountryIconURL(el);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s, %s %s&nbsp;%s&nbsp;</TD></TR>\n", getRowColor(), "Physical Location", 
		  el->geo_ip->city ? el->geo_ip->city : "Unknown city", el->geo_ip->country_name, countryIcon, buf3);
    sendString(buf);
  }

  if(el->community) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<A HREF=/"CONST_COMMUNITIES_STATS_HTML"?community=%s>%s</A>"
		  "</TD></TR>\n", getRowColor(), "Community", 
		  el->community, el->community);
    sendString(buf);
  }

  if(el->hwModel) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s</TD></TR>\n", getRowColor(), "Hardware Model", el->hwModel);
    sendString(buf);
  }

  if(el->description) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s</TD></TR>\n", getRowColor(), "Description", el->description);
    sendString(buf);
  }

  if(el->minTTL > 0) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%d:%d&nbsp;[~%d&nbsp;hop(s)]</TD></TR>\n",
		getRowColor(), "IP&nbsp;TTL&nbsp;(Time to Live)",
		el->minTTL, el->maxTTL, guessHops(el));
    sendString(buf);
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s"
	      "</TH><TD "TD_BG" ALIGN=RIGHT>"
	      "%s/%s Pkts/%s Retran. Pkts [%d%%]</TD></TR>\n",
	      getRowColor(), "Total&nbsp;Data&nbsp;Sent",
	      formatBytes(el->bytesSent.value, 1, formatBuf, sizeof(formatBuf)),
	      formatPkts(el->pktSent.value, formatBuf1, sizeof(formatBuf1)),
	      formatPkts(el->pktDuplicatedAckSent.value, formatBuf2, sizeof(formatBuf2)),
	      (int)(((float)el->pktDuplicatedAckSent.value*100)/(float)(el->pktSent.value+1))
	      );
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
	      "%s Pkts</TD></TR>\n",
	      getRowColor(), "Broadcast&nbsp;Pkts&nbsp;Sent",
	      formatPkts(el->pktBroadcastSent.value, formatBuf, sizeof(formatBuf)));
  sendString(buf);

  if(el->routedTraffic != NULL) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<TR  "TR_ON"%s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%s/%s Pkts</TD></TR>\n",
		getRowColor(), "Routed Traffic",
		formatBytes(el->routedTraffic->routedBytes.value, 1, formatBuf, sizeof(formatBuf)),
		formatPkts(el->routedTraffic->routedPkts.value, formatBuf1, sizeof(formatBuf1)));
    sendString(buf);
  }

  if((el->pktMulticastSent.value > 0) || (el->pktMulticastRcvd.value > 0)) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>",
		getRowColor(), "Multicast&nbsp;Traffic");
    sendString(buf);

    if(el->pktMulticastSent.value > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Sent&nbsp;%s/%s&nbsp;Pkts&nbsp;",
		  formatBytes(el->bytesMulticastSent.value, 1, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->pktMulticastSent.value, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);
    }

    if(el->pktMulticastRcvd.value > 0) {      
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%sRcvd&nbsp;%s/%s&nbsp;Pkts",
		    (el->pktMulticastSent.value > 0) ? " - " : "",
		    formatBytes(el->bytesMulticastRcvd.value, 1, formatBuf, sizeof(formatBuf)),
		    formatPkts(el->pktMulticastRcvd.value, formatBuf1, sizeof(formatBuf1)));
      sendString(buf);
    }

    sendString("</TD></TR>\n");
  }

  if(el->bytesSent.value == 0)
    percentage = 0;
  else
    percentage = 100 - (((float)el->bytesSentRem.value*100)/el->bytesSent.value);

  if(el->hostNumIpAddress[0] != '\0') {
    printTableEntryPercentage(buf, sizeof(buf), "Data&nbsp;Sent&nbsp;Stats",
			      "Local", "Rem", -1, percentage, 0, 0);

    if(el->bytesSent.value > 0) {
      percentage = (((float)el->ipv4BytesSent.value*100)/el->bytesSent.value);
      printTableEntryPercentage(buf, sizeof(buf), "IP&nbsp;vs.&nbsp;Non-IP&nbsp;Sent",
				"IP", "Non-IP", -1, percentage, 0, 0);
    }
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s"
	      "</TH><TD "TD_BG" ALIGN=RIGHT>"
	      "%s/%s Pkts/%s Retran. Pkts [%d%%]</TD></TR>\n",
	      getRowColor(), "Total&nbsp;Data&nbsp;Rcvd",
	      formatBytes(el->bytesRcvd.value, 1, formatBuf, sizeof(formatBuf)),
	      formatPkts(el->pktRcvd.value, formatBuf1, sizeof(formatBuf1)),
	      formatPkts(el->pktDuplicatedAckRcvd.value, formatBuf2, sizeof(formatBuf2)),
	      (int)((float)(el->pktDuplicatedAckRcvd.value*100)/(float)(el->pktRcvd.value+1)));
  sendString(buf);

  if(el->bytesRcvd.value == 0)
    percentage = 0;
  else
    percentage = 100 - (((float)el->bytesRcvdFromRem.value*100)/el->bytesRcvd.value);

    if(el->hostNumIpAddress[0] != '\0')
      printTableEntryPercentage(buf, sizeof(buf), "Data&nbsp;Rcvd&nbsp;Stats",
				"Local", "Rem", -1, percentage, 0, 0);

  if(el->bytesRcvd.value > 0) {
    percentage = (((float)el->ipv4BytesRcvd.value*100)/el->bytesRcvd.value);
    printTableEntryPercentage(buf, sizeof(buf), "IP&nbsp;vs.&nbsp;Non-IP&nbsp;Rcvd",
			      "IP", "Non-IP", -1, percentage, 0, 0);
  }

  total = el->pktSent.value+el->pktRcvd.value;
  if(total > 0) {
    percentage = ((float)el->pktSent.value*100)/((float)total);
    printTableEntryPercentage(buf, sizeof(buf), "Sent&nbsp;vs.&nbsp;Rcvd&nbsp;Pkts",
			      "Sent", "Rcvd", -1, percentage, 0, 0);
  }

  total = el->bytesSent.value+el->bytesRcvd.value;
  if(total > 0) {
    percentage = ((float)el->bytesSent.value*100)/((float)total);
    printTableEntryPercentage(buf, sizeof(buf), "Sent&nbsp;vs.&nbsp;Rcvd&nbsp;Data",
			      "Sent", "Rcvd", -1, percentage, 0, 0);
  }

  /* ******************** */

  printedHeader=0;
  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
    if(!emptySerial(&el->contactedRouters.peersSerials[i])) {
      HostSerial routerIdx = el->contactedRouters.peersSerials[i];

      if(!emptySerial(&routerIdx)) {
	HostTraffic *router = quickHostLink(routerIdx, myGlobals.actualReportDeviceId, &tmpEl);

	if(router != NULL) {
	  if(!printedHeader) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">"
			"Used&nbsp;Subnet&nbsp;Routers</TH><TD "TD_BG" ALIGN=RIGHT>\n",
			getRowColor());
	    sendString(buf);
	  }
	  printedHeader++;

	  if(printedHeader > 1) sendString("<BR>");

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s\n",
		      makeHostLink(router, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				   hostLinkBuf, sizeof(hostLinkBuf)));
	  sendString(buf);
	}
      }
    }
  }

  checkHostProvidedServices(el);

  /*
    Fix courtesy of
    Albert Chin-A-Young <china@thewrittenword.com>
  */
  if(printedHeader > 1)
    sendString("</OL></TD></TR>\n");

  /* **************************** */

  if((el->protocolInfo) && (el->protocolInfo->userList != NULL)) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">"
		"Known&nbsp;Users&nbsp;" CONST_IMG_HAS_USERS "</TH><TD "TD_BG" ALIGN=RIGHT>\n",
		getRowColor());
    sendString(buf);

    printUserList(el);
    sendString("<br>\n</TD></TR>\n");
  }

  /* **************************** */

  if((el->hostNumIpAddress[0] != '\0')
     && (!subnetPseudoLocalHost(el))
     && (!multicastHost(el))
     && (!privateIPAddress(el))) {

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">"
		  "%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "[ <A class=external HREF=\"http://ws.arin.net/cgi-bin/whois.pl?queryinput=%s\">Whois</A> ]\n",
		  getRowColor(), "Further Host Information", el->hostNumIpAddress);
    sendString(buf);
        
    sendString("</TD></TR>\n");
  }

  /* RRD */
  if(el->hostNumIpAddress[0] != '\0') {
    char rrdBuf[LEN_GENERAL_WORK_BUFFER];

    hostRRdGraphLink(el, NETWORK_VIEW, 0, rrdBuf, sizeof(rrdBuf));

    if(rrdBuf[0] != '\0') {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">Historical Data</TH>\n"
		    "<TD "TD_BG" ALIGN=\"right\">%s</TD></TR>\n",
		    getRowColor(), rrdBuf);
      sendString(buf);
    }
  }

  checkHostHealthness(el);

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");
}

/* ************************************ */

void printServiceStats(char* svcName, ServiceStats* ss,
		       short printSentStats) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  Counter tot, tot1;
  float f1, f2, f3, f4;
  char formatBuf[32], formatBuf1[32], formatBuf2[32], formatBuf3[32], formatBuf4[32],
    formatBuf5[32], formatBuf6[32], formatBuf7[32];

  if(ss != NULL) {
    if(printSentStats) {
      tot = ss->numLocalReqSent.value+ss->numRemReqSent.value;

      if(tot == 0)
	f1 = f2 = 0;
      else {
	f1 = (ss->numLocalReqSent.value*100)/tot;
	f2 = (ss->numRemReqSent.value*100)/tot;
      }

      tot1 = ss->numPositiveReplRcvd.value+ss->numNegativeReplRcvd.value;
      if(tot1 == 0)
	f3 = f4 = 0;
      else {
	f3 = (ss->numPositiveReplRcvd.value*100)/tot1;
	f4 = (ss->numNegativeReplRcvd.value*100)/tot1;
      }

      if((tot > 0) || (tot1 > 0)) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" "DARK_BG">%s</TH>"
		    "<TD "TD_BG" ALIGN=CENTER>%s</TD><TD "TD_BG" ALIGN=CENTER>%.1f%%</TD>"
		    "<TD "TD_BG" ALIGN=CENTER>%s</TD><TD "TD_BG" ALIGN=CENTER>%.1f%%</TD>"
		    "<TD "TD_BG" ALIGN=CENTER>%s</TD><TD "TD_BG" ALIGN=CENTER>%.1f%%</TD>"
		    "<TD "TD_BG" ALIGN=CENTER>%s</TD><TD "TD_BG" ALIGN=CENTER>%.1f%%</TD>"
		    "<TD "TD_BG" ALIGN=CENTER>%s - %s</TD><TD "TD_BG" ALIGN=CENTER>%s - %s</TD>"
		    "</TR>\n",
		    getRowColor(), svcName,
		    formatPkts(ss->numLocalReqSent.value, formatBuf, sizeof(formatBuf)), f1,
		    formatPkts(ss->numRemReqSent.value, formatBuf1, sizeof(formatBuf1)), f2,
		    formatPkts(ss->numPositiveReplRcvd.value, formatBuf2, sizeof(formatBuf2)), f3,
		    formatPkts(ss->numNegativeReplRcvd.value, formatBuf3, sizeof(formatBuf3)), f4,
		    formatMicroSeconds(ss->fastestMicrosecLocalReqMade, formatBuf4, sizeof(formatBuf4)),
		    formatMicroSeconds(ss->slowestMicrosecLocalReqMade, formatBuf5, sizeof(formatBuf5)),
		    formatMicroSeconds(ss->fastestMicrosecRemReqMade, formatBuf6, sizeof(formatBuf6)),
		    formatMicroSeconds(ss->slowestMicrosecRemReqMade, formatBuf7, sizeof(formatBuf7))
		    );
	sendString(buf);
      }
    } else {
      tot = ss->numLocalReqRcvd.value+ss->numRemReqRcvd.value;

      if(tot == 0)
	f1 = f2 = 0;
      else {
	f1 = (ss->numLocalReqRcvd.value*100)/tot;
	f2 = (ss->numRemReqRcvd.value*100)/tot;
      }

      tot1 = ss->numPositiveReplSent.value+ss->numNegativeReplSent.value;
      if(tot1 == 0)
	f3 = f4 = 0;
      else {
	f3 = (ss->numPositiveReplSent.value*100)/tot1;
	f4 = (ss->numNegativeReplSent.value*100)/tot1;
      }

      if((tot > 0) || (tot1 > 0)) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG">%s</TH>"
                "<TD "TD_BG" ALIGN=CENTER>%s</TD><TD "TD_BG" ALIGN=CENTER>%.1f%%</TD>"
		"<TD "TD_BG" ALIGN=CENTER>%s</TD><TD "TD_BG" ALIGN=CENTER>%.1f%%</TD>"
		"<TD "TD_BG" ALIGN=CENTER>%s</TD><TD "TD_BG" ALIGN=CENTER>%.1f%%</TD>"
		"<TD "TD_BG" ALIGN=CENTER>%s</TD><TD "TD_BG" ALIGN=CENTER>%.1f%%</TD>"
		"<TD "TD_BG" ALIGN=CENTER>%s - %s</TD><TD "TD_BG" ALIGN=CENTER>%s - %s</TD>"
		"</TR>\n",
		getRowColor(), svcName,
		formatPkts(ss->numLocalReqRcvd.value, formatBuf, sizeof(formatBuf)), f1,
		formatPkts(ss->numRemReqRcvd.value, formatBuf1, sizeof(formatBuf1)), f2,
		formatPkts(ss->numPositiveReplSent.value, formatBuf2, sizeof(formatBuf2)), f3,
		formatPkts(ss->numNegativeReplSent.value, formatBuf3, sizeof(formatBuf3)), f4,
		formatMicroSeconds(ss->fastestMicrosecLocalReqServed, formatBuf4, sizeof(formatBuf4)),
		formatMicroSeconds(ss->slowestMicrosecLocalReqServed, formatBuf5, sizeof(formatBuf5)),
		formatMicroSeconds(ss->fastestMicrosecRemReqServed, formatBuf6, sizeof(formatBuf6)),
		formatMicroSeconds(ss->slowestMicrosecRemReqServed, formatBuf7, sizeof(formatBuf7))
		);
	sendString(buf);
      }
    }
  }
}

/* ************************************ */

void printHostUsedServices(HostTraffic *el, int actualDeviceId) {
  Counter tot;

  if((el->protocolInfo == NULL)
     || ((el->protocolInfo->dnsStats == NULL) && (el->protocolInfo->httpStats == NULL)))
    return;

  tot = 0;

  if(el->protocolInfo->dnsStats)
    tot += el->protocolInfo->dnsStats->numLocalReqSent.value + el->protocolInfo->dnsStats->numRemReqSent.value;

  if(el->protocolInfo->httpStats)
    tot += el->protocolInfo->httpStats->numLocalReqSent.value + el->protocolInfo->httpStats->numRemReqSent.value;

  if(tot > 0) {
    printSectionTitle("IP&nbsp;Service&nbsp;Stats:&nbsp;Client&nbsp;Role");
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>\n<TR "TR_ON" "DARK_BG">"
	       "<TH "TH_BG">&nbsp;</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Loc.&nbsp;Req.&nbsp;Sent</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Rem.&nbsp;Req.&nbsp;Sent</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Pos.&nbsp;Reply&nbsp;Rcvd</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Neg.&nbsp;Reply&nbsp;Rcvd</TH>"
	       "<TH "TH_BG">Local&nbsp;RndTrip</TH>"
	       "<TH "TH_BG">Rem&nbsp;RndTrip</TH>"
	       "</TR>\n");

    if(el->protocolInfo->dnsStats)  printServiceStats("DNS", el->protocolInfo->dnsStats, 1);
    if(el->protocolInfo->httpStats) printServiceStats("HTTP", el->protocolInfo->httpStats, 1);

    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");
  }

  /* ************ */

  tot = 0;

  if(el->protocolInfo->dnsStats)
    tot += el->protocolInfo->dnsStats->numLocalReqRcvd.value+el->protocolInfo->dnsStats->numRemReqRcvd.value;

  if(el->protocolInfo->httpStats)
    tot += el->protocolInfo->httpStats->numLocalReqRcvd.value+el->protocolInfo->httpStats->numRemReqRcvd.value;

  if(tot > 0) {
    printSectionTitle("IP&nbsp;Service&nbsp;Stats:&nbsp;Server&nbsp;Role");
    sendString("<CENTER>\n");
    sendString("<P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>\n<TR "TR_ON" "DARK_BG">"
	       "<TH "TH_BG">&nbsp;</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Loc.&nbsp;Req.&nbsp;Rcvd</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Rem.&nbsp;Req.&nbsp;Rcvd</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Pos.&nbsp;Reply&nbsp;Sent</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Neg.&nbsp;Reply&nbsp;Sent</TH>"
	       "<TH "TH_BG">Local&nbsp;RndTrip</TH>"
	       "<TH "TH_BG">Rem&nbsp;RndTrip</TH>"
	       "</TR>\n");

    if(el->protocolInfo->dnsStats) printServiceStats("DNS", el->protocolInfo->dnsStats, 0);
    if(el->protocolInfo->httpStats) printServiceStats("HTTP", el->protocolInfo->httpStats, 0);

    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");
  }
}

/* ********************************** */

void printTableEntry(char *buf, int bufLen,
		     char *label, char* color,
		     float total, float percentage,
		     u_int showFlows, Counter flows,
		     u_int showRRD) {
  int int_perc;
  char formatBuf[32], flowBuf[64], tmpBuf[32], rrdBuf[768];
  struct stat statbuf;
  char _label[256];

  encodeString(label, _label, sizeof(_label));

  /* traceEvent(CONST_TRACE_INFO,  "'%s' -> '%s'", label, _label); */

  if(total == 0) return;

  int_perc = (int)percentage;

  /* This shouldn't happen */
  if(int_perc < 0) {
    int_perc = 0;
    percentage = 0;
  } else if(int_perc > 100) {
    int_perc = 100;
    percentage = 100;
  }

  if(!showFlows)
    flowBuf[0] = '\0';
  else
    safe_snprintf(__FILE__, __LINE__, flowBuf, sizeof(flowBuf), 
		  "</TD><TD "TD_BG" ALIGN=RIGHT WIDTH=50>%s", 
		  formatPkts(flows, tmpBuf, sizeof(tmpBuf)));

  if(!showRRD)
    rrdBuf[0] = '\0';
  else {
    safe_snprintf(__FILE__, __LINE__, rrdBuf, sizeof(rrdBuf), "%s/interfaces/%s/IP_%sBytes.rrd",
		  myGlobals.rrdPath != NULL ? myGlobals.rrdPath : ".",
		  myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
		  label);

    revertSlashIfWIN32(rrdBuf, 0);

    if(stat(rrdBuf, &statbuf) == 0) {      
      time_t now = time(NULL);

      safe_snprintf(__FILE__, __LINE__, rrdBuf, sizeof(rrdBuf), 
		    "<p><table border=0>"
		    "<tr><td align=left><IMG SRC=\"/plugins/rrdPlugin?action=arbreq&which=graph"
		    "&arbfile=IP_%sBytes&arbiface=%s&arbip=&start=now-12h&end=now&counter=&title=\" BORDER=0></td><td>"
		    "<A HREF=\"/plugins/rrdPlugin?mode=zoom&action=arbreq&which=graph&arbfile=IP_%sBytes&arbiface=%s&arbip=&start=%d&end=%d&counter=&title=\">"
		    "&nbsp;<IMG valign=top class=tooltip SRC=graph_zoom.gif border=0></A></td></tr></table>\n",
		    _label, myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
		    _label, myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
		    now-12*3600, now);
    } else {
      rrdBuf[0] = '\0';
      /* traceEvent(CONST_TRACE_INFO,  "-> Unable to find file '%s'", rrdBuf); */
    }
  }

  switch(int_perc) {
  case 0:
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT WIDTH=150 "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT WIDTH=50>%s %s</TD><TD "TD_BG" ALIGN=RIGHT WIDTH=50>0%%</TD>"
		  "<TD "TD_BG" WIDTH=260 nowrap>&nbsp;%s</TD></TR>\n",
		  getRowColor(), label, formatKBytes(total, formatBuf, sizeof(formatBuf)), flowBuf, rrdBuf);
    break;
  case 100:
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT WIDTH=150 "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT WIDTH=50>%s %s</TD><TD "TD_BG" ALIGN=RIGHT WIDTH=50>100%%</TD>"
		  "<TD "TD_BG" WIDTH=260 nowrap><IMG ALT=\"100%%\" ALIGN=MIDDLE SRC=\"/gauge.jpg\" WIDTH=260 HEIGHT=12>%s"
		  "</TD></TR>\n",
		  getRowColor(), label, formatKBytes(total, formatBuf, sizeof(formatBuf)), flowBuf, rrdBuf);
    break;
  default:
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT WIDTH=150 "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT WIDTH=50>%s %s</TD><TD "TD_BG" ALIGN=RIGHT WIDTH=50>%.1f%%</TD>"
		  "<TD "TD_BG" WIDTH=260 nowrap><TABLE BORDER=0 "TABLE_DEFAULTS" CELLPADDING=0 CELLSPACING=0>"
		  "<TR "TR_ON"><TD nowrap><IMG ALIGN=MIDDLE ALT=\"%.1f%%\" SRC=\"/gauge.jpg\" WIDTH=\"%d\" HEIGHT=12>%s"
		  "</TD><TD "TD_BG" nowrap ALIGN=CENTER WIDTH=\"%d\" %s>"
		  "<P>&nbsp;</TD></TR></TABLE>"TABLE_OFF"</TD></TR>\n",
		  getRowColor(), label, formatKBytes(total, formatBuf, sizeof(formatBuf)), 
		  flowBuf, percentage,
		  percentage, (260*int_perc)/100, rrdBuf,
		  (260*(100-int_perc))/100, getActualRowColor());
  }
  
  sendString(buf);
}

/* ************************ */

char* buildHTMLBrowserWindowsLabel(int i, int j, u_short forIpTraffic) {
  static char buf[LEN_GENERAL_WORK_BUFFER];
  int idx = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts + j;
  char formatBuf[32], formatBuf1[32], formatBuf2[32], formatBuf3[32];

  if((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx] == NULL)
     || ((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value == 0)
	 && (myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value == 0)))
    buf[0]='\0';
  else if ((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value > 0)
	   && (myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value == 0)) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "(%s->%s)=%s/%s Pkts",
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostResolvedName,
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostResolvedName,
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value, 1, formatBuf, sizeof(formatBuf)),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsSent.value, formatBuf1, sizeof(formatBuf1)));
  } else if ((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value == 0)
	     && (myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value > 0)) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "(%s->%s)=%s/%s Pkts",
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostResolvedName,
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostResolvedName,
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value, 1, formatBuf, sizeof(formatBuf)),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsRcvd.value, formatBuf1, sizeof(formatBuf1)));
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "(%s->%s)=%s/%s Pkts, (%s->%s)=%s/%s Pkts",
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostResolvedName,
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostResolvedName,
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value, 1, formatBuf, sizeof(formatBuf)),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsSent.value, formatBuf1, sizeof(formatBuf1)),
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostResolvedName,
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostResolvedName,
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value, 1, formatBuf2, sizeof(formatBuf2)),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsRcvd.value, formatBuf3, sizeof(formatBuf3)));
  }

  return(buf);
}

/* *********************************** */

void printHostHourlyTrafficEntry(HostTraffic *el, int i,
				 Counter tcSent, Counter tcRcvd) {
  float pctg;
  char buf[LEN_GENERAL_WORK_BUFFER], formatBuf[32];

  if(el->trafficDistribution == NULL) return;

  safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
	      formatBytes(el->trafficDistribution->last24HoursBytesSent[i].value, 0, formatBuf, sizeof(formatBuf)));
  sendString(buf);

  if(tcSent > 0)
    pctg = (float)(el->trafficDistribution->last24HoursBytesSent[i].value*100)/(float)tcSent;
  else
    pctg = 0;

  safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TD ALIGN=RIGHT %s>%.1f %%</TD>",
	   getBgPctgColor(pctg), pctg);
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
	   formatBytes(el->trafficDistribution->last24HoursBytesRcvd[i].value, 0, formatBuf, sizeof(formatBuf)));
  sendString(buf);

 if(tcRcvd > 0)
    pctg = (float)(el->trafficDistribution->last24HoursBytesRcvd[i].value*100)/(float)tcRcvd;
  else
    pctg = 0;

  safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TD ALIGN=RIGHT %s>%.1f %%</TD></TR>",
	      getBgPctgColor(pctg), pctg);
  sendString(buf);
}

/* ************************************ */

char* getNbNodeType(char nodeType) {

  switch(nodeType) {
  case 0x0:
    return("Workstation");
  case 0x20:
  default:
    return("Server");
  }

  return(""); /* NOTREACHED */
}

 /* ********************************** */

void printFlagedWarning(char *text) {
  char buf[LEN_GENERAL_WORK_BUFFER];

  safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER,
 	   "<center>\n"
		"<p><img class=tooltip alt=\"Warning\" src=\"/warning.gif\"></p>\n"
 	   "<p><font color=\"#FF0000\" size=\"+1\">%s</font></p>\n"
 	   "</center>\n", text);
  sendString(buf);
}

/* ********************************** */

void printPageTitle(char *text) {
  sendString("<p>&nbsp;</p>\n");
  switch (myGlobals.ntopRunState) {
      case FLAG_NTOPSTATE_RUN:
          break;

      case FLAG_NTOPSTATE_STOPCAP:
          sendString("<center><font face=\"Helvetica, Arial, Sans Serif\" size=\"+1\"><b>"
                     "Packet capture stopped"
                     "</b></font></center>\n");
          break;

      case FLAG_NTOPSTATE_SHUTDOWN:
          sendString("<center><font face=\"Helvetica, Arial, Sans Serif\" size=\"+1\"><b>"
                     "ntop shutting down"
                     "</b></font></center>\n");
          break;

      case FLAG_NTOPSTATE_TERM:
          sendString("<center><font face=\"Helvetica, Arial, Sans Serif\" size=\"+1\"><b>"
                     "ntop stopped"
                     "</b></font></center>\n");
          break;

  }

  sendString("<center>\n<H1><font face=\"Helvetica, Arial, Sans Serif\">");
  sendString(text);
  sendString("</font></H1>\n</center>\n");
}

/* ******************************** */

void printSectionTitle(char *text) {
  sendString("<p>&nbsp;</p>\n"
             "<center>\n<H2><font face=\"Helvetica, Arial, Sans Serif\">");
  sendString(text);
  sendString("</font></H2>\n</center>\n");
}

/* ******************************** */

void printHostsCharacterization(void) {
  u_int a=0, b=0, c=0, d=0, e=0, f=0, g=0, h=0, i=0, unhealthy=0, totHosts=0;
  HostTraffic *el;
  char buf[LEN_GENERAL_WORK_BUFFER], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER], headerSent = 0;

  printHTMLheader("Local Hosts Characterization", NULL, 0);

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if((broadcastHost(el) == 0) /* No broadcast addresses please */
       && (multicastHost(el) == 0) /* No multicast addresses please */
       && subnetPseudoLocalHost(el)) {
      totHosts++;

      if(el->community && (!isAllowedCommunity(el->community))) continue;

      if(isPrinter(el)
	 || isBridgeHost(el)
	 || nameServerHost(el) || isNtpServer(el)
	 || gatewayHost(el) || isVoIPHost(el)
	 || isSMTPhost(el) || isIMAPhost(el) || isPOPhost(el)
	 || isDirectoryHost(el)
	 || isFTPhost(el)
	 || isHTTPhost(el)
	 || isWINShost(el)
	 || isDHCPClient(el) || isDHCPServer(el)
	 || isP2P(el)
	 || (isHostHealthy(el) != 0)
	 ) {
	if(!headerSent) {
	  sendString("<center>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON" "DARK_BG"><TH "TH_BG">Host</TH>"
		     "<TH>Unhealthy<br>Host</TH>"
		     "<TH>L2 Switch<br>Bridge</TH>"
		     "<TH>Gateway</TH>"
		     "<TH>VoIP<br>Host</TH>"
		     "<TH>Printer</TH>"
		     "<TH>NTP/DNS<br>Server</TH>"
		     "<TH>SMTP/POP/IMAP<br>Server</TH>"
		     "<TH>Directory/FTP/HTTP<br>Server</TH>"
		     "<TH>DHCP/WINS<br>Server</TH>"
		     "<TH>DHCP<br>Client</TH>"
		     "<TH>P2P</TH>"
		     "</TR>\n"
		     );
	  headerSent = 1;
	}

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH ALIGN=LEFT>%s</TH>",
		    getRowColor(),
		    makeHostLink(el, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				 hostLinkBuf, sizeof(hostLinkBuf)));
	sendString(buf);

	if(isHostHealthy(el) != 0) { sendString("<TD ALIGN=CENTER>X</TD>"); unhealthy++; } else sendString("<TD>&nbsp;</TD>");
	if(isBridgeHost(el)) { sendString("<TD ALIGN=CENTER>X</TD>"); a++; } else sendString("<TD>&nbsp;</TD>");
	if(gatewayHost(el)) { sendString("<TD ALIGN=CENTER>X</TD>"); b++; } else sendString("<TD>&nbsp;</TD>");
	if(isVoIPHost(el)) { sendString("<TD ALIGN=CENTER>X</TD>"); b++; } else sendString("<TD>&nbsp;</TD>");
	if(isPrinter(el)) { sendString("<TD ALIGN=CENTER>X</TD>"); c++; } else sendString("<TD>&nbsp;</TD>");
	if(nameServerHost(el) || isNtpServer(el)) { sendString("<TD ALIGN=CENTER>X</TD>"); d++; } else sendString("<TD>&nbsp;</TD>");
	if(isSMTPhost(el) || isIMAPhost(el) || isPOPhost(el)) { sendString("<TD ALIGN=CENTER>X</TD>"); e++; } else sendString("<TD>&nbsp;</TD>");
	if(isDirectoryHost(el) || isFTPhost(el) || isHTTPhost(el)) { sendString("<TD ALIGN=CENTER>X</TD>"); f++; } else sendString("<TD>&nbsp;</TD>");
	if(isDHCPServer(el) || isWINShost(el)) { sendString("<TD ALIGN=CENTER>X</TD>"); g++; } else sendString("<TD>&nbsp;</TD>");
	if(isDHCPClient(el)) { sendString("<TD ALIGN=CENTER>X</TD>"); h++; } else sendString("<TD>&nbsp;</TD>");
	if(isP2P(el)) { sendString("<TD ALIGN=CENTER>X</TD>"); i++; } else sendString("<TD>&nbsp;</TD>");

	sendString("</TR>\n");
      }
    }
  }

  if(!headerSent) {
    printNoDataYet();
  } else {
    sendString("<TR "TR_ON"><TH>Total</TH>");
    if(unhealthy > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                  "<TD ALIGN=CENTER>%d [%.1f %%]</TD>",
                  unhealthy, (float)(unhealthy*100)/(float)totHosts);
      sendString(buf);
    } else
      sendString("<TD>&nbsp;</TD>");

    if(a > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", a);
      sendString(buf);
    } else
      sendString("<TD>&nbsp;</TD>");
    if(b > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", b);
      sendString(buf);
    } else
      sendString("<TD>&nbsp;</TD>");
    if(c > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", c);
      sendString(buf);
    } else
      sendString("<TD>&nbsp;</TD>");
    if(d > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", d);
      sendString(buf);
    } else
      sendString("<TD>&nbsp;</TD>");
    if(e > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", e);
      sendString(buf);
    } else
      sendString("<TD>&nbsp;</TD>");
    if(f > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", f);
      sendString(buf);
    } else
      sendString("<TD>&nbsp;</TD>");
    if(g > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", g);
      sendString(buf);
    } else
      sendString("<TD>&nbsp;</TD>");
    if(h > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", h);
      sendString(buf);
    } else
      sendString("<TD>&nbsp;</TD>");
    if(i > 0) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", i);
      sendString(buf);
    } else
      sendString("<TD>&nbsp;</TD>");
    sendString("</TABLE></CENTER>\n");
  }
}

/* ******************************** */

static void printFingerprintCounts(int countScanned, int countWithoutFP, int countBroadcast,
				   int countMulticast, int countRemote, int countNotIP,
				   int countUnknownFP, int unknownFPsEtc, int countCantResolve,
				   int fingerprintRemote,
				   char *unknownFPs) {  
  char buf[LEN_GENERAL_WORK_BUFFER];
  struct tm t;

  sendString("<p><hr><p>\n");

  printSectionTitle("Statistics");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
              "<center>\n<table border=1 "TABLE_DEFAULTS">\n"
              "<tr><th colspan=\"2\"><i>Scanned</i></th></tr>\n"
              "<tr><td>Hosts</td><td align=\"right\">%d</td></tr>\n"
              "<tr><th colspan=\"2\"><i>Less:</i></th></tr>\n"
              "<tr><td>No fingerprint</td><td align=\"right\">%d</td></tr>\n"
              "<tr><td>Broadcast</td><td align=\"right\">%d</td></tr>\n"
              "<tr><td>Multicast</td><td align=\"right\">%d</td></tr>\n",
              countScanned,
              countWithoutFP,
              countBroadcast,
              countMulticast);
  sendString(buf);

  if(fingerprintRemote != TRUE) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
                "<tr><td>Remote</td><td align=\"right\">%d</td></tr>\n",
                countRemote);
    sendString(buf);
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
              "<tr><td>Non IP host</td><td align=\"right\">%d</td></tr>\n"
              "<tr><th colspan=\"2\"><i>Gives:</i></th></tr>\n"
              "<tr><td>Possible to report</td><td align=\"right\">%d</td></tr>\n",
              countNotIP,
              countScanned - countWithoutFP - countBroadcast - countMulticast
                           - countRemote - countNotIP);
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
              "<tr><td>Less: Can not resolve<sup>*</sup></td>"
                  "<td align=\"right\">%d</td></tr>\n",
              countCantResolve);
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
              "<tr><td>Less: Unknown Fingerprint<sup>**</sup></td>"
                  "<td align=\"right\">%d</td></tr>\n",
              countUnknownFP);
  sendString(buf);

  sendString("</td></tr>\n</table>\n<p><table border=0 width=80%%>\n");

  sendString("<tr><td><sup>*</sup>&nbsp;<i>Can not resolve</i>&nbsp;means "
             "either the fingerprint was incomplete, or we tried to resolve "
             "it on a previous scan and it was not on file. "
             "No further action will occur for these hosts.</td></tr>\n");

  sendString("<tr><td><sup>**</sup>&nbsp;<i>Unknown Fingerprints</i>&nbsp;means "
             "we have not tried to resolve them yet.\n"
             "<ul>");

  if((myGlobals.nextFingerprintScan > 0) &&
     (countUnknownFP > 0) &&
     (myGlobals.runningPref.debugMode != 1)) {
        strftime(buf, sizeof(buf), 
                 CONST_LOCALE_TIMESPEC, localtime_r(&myGlobals.nextFingerprintScan, &t));
        sendString("<li>May be resolved during the next scan, scheduled for ");
        sendString(buf);
        sendString(" (approximately).</li>\n");
      }

  if(unknownFPs[0] != '\0') {
    unknownFPs[0]=' ';
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
              "<li>Are:</i>&nbsp;%s%s</li>\n",
              unknownFPs,
              unknownFPsEtc == 1 ? " ..." : "");
    sendString(buf);
  }

#ifdef CONST_ETTERCAP_HOMEPAGE
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
             "<li><p>Click "
		"<a href=\"%s\" class=tooltip alt=\"Ettercap page at SourceForge\">here</a> "
             "to visit Ettercap's home page at SourceForge. "
             "And, click "
		"<a href=\"%s%s\" class=tooltip alt=\"Ettercap fingerprint upload page\">here</a> "
             " to upload new fingerprints, or download additional (unverified) ones.</li>\n",
             CONST_ETTERCAP_HOMEPAGE,
             CONST_ETTERCAP_HOMEPAGE, CONST_ETTERCAP_FINGERPRINT);
  sendString(buf);
#endif

  sendString("<li><p>You can use the 'make dnetter' command, part of the ntop source distribution, "
             "to download the latest fingerprint file from the Ettercap cvs.</p></li>\n");

  if(fingerprintRemote != TRUE)
    sendString("<tr><td>Fingerprinting of non-local hosts may be erroneous "
               "- routers and intermediate hosts can alter the characteristics used to "
               "determine the operating system. Unfortunately, this can also occur because "
               "of entries not in the signature file, " CONST_OSFINGERPRINT_FILE "(.gz) - "
               "and there's no way to tell."
               "\n<br>That said, if you would like to see a page with ALL host fingerprints, "
               "local and remote, click <a href=\"" CONST_HOSTS_REMOTE_FINGERPRINT_HTML 
               "\"  class=tooltip title=\"All host fingerprints page\">here</a></td></tr>\n");

  sendString("</table></center>\n");
}

/* ******************************** */

void printHostsStats(int fingerprintRemote) {
  u_int idx, numEntries=0, maxHosts;
  HostTraffic *el, **tmpTable;
  OsNumInfo theOSs[MAX_NUM_OS];
  int i, 
      countScanned=0,
      countWithoutFP=0,
      countBroadcast=0,
      countMulticast=0,
      countRemote=0,
      countNotIP=0,
      countUnknownFP=0,
      countCantResolve=0;
  char buf[LEN_GENERAL_WORK_BUFFER], hostLinkBuf[3*LEN_GENERAL_WORK_BUFFER];
  char unknownFPs[LEN_GENERAL_WORK_BUFFER];
  int unknownFPsEtc=0;

  memset(theOSs, 0, sizeof(theOSs));
  memset(unknownFPs, 0, sizeof(unknownFPs));

  if(fingerprintRemote == 1)
    printHTMLheader("All Host Fingerprints (Local+Remote)", NULL, BITFLAG_HTML_NO_REFRESH);
  else
    printHTMLheader("Local Host Fingerprints", NULL, BITFLAG_HTML_NO_REFRESH);

  printSectionTitle("OS Summary");

  if(myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
    printFlagedWarning("<I>Host statistics (OS fingerprinting) are not available for virtual interfaces</I>");
    return;
  }

  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */
  tmpTable = (HostTraffic**)mallocAndInitWithReportWarn(maxHosts*sizeof(HostTraffic*), "printHostsStats");
  if(tmpTable == NULL)
    return;

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    countScanned++;

    if(el->community && (!isAllowedCommunity(el->community))) continue;

    if(el->fingerprint == NULL) {
      countWithoutFP++;
      continue;
    }
    if(broadcastHost(el)) {
      /* No broadcast addresses please */
      countBroadcast++;
      continue;
    }
    if(multicastHost(el)) {
      /* No multicast addresses please */
      countMulticast++;
      continue;
    }
    if((!subnetPseudoLocalHost(el)) &&
       (fingerprintRemote != TRUE)) {
      /* Local only */
      countRemote++;
      continue;
    }
    if((el->fingerprint[0] != ':') /* fingerprint has not been computed */ &&
       ((el->hostNumIpAddress[0] == '\0') ||
        (addrnull(&el->hostIpAddress)))) {
      countNotIP++;
      continue;
    }

    if(el->fingerprint[0] != ':') setHostFingerprint(el);
    if(el->fingerprint[0] != ':') {
      countUnknownFP++;
      if(strstr(unknownFPs, el->fingerprint) == NULL) {
          if(strlen(unknownFPs) + strlen(el->fingerprint) > (sizeof(unknownFPs) - 5)) {
            unknownFPsEtc=1;
          } else {
            strncat(unknownFPs, ", ", (sizeof(unknownFPs) - strlen(unknownFPs) - 1));
            strncat(unknownFPs, el->fingerprint, (sizeof(unknownFPs) - strlen(unknownFPs) - 1));
          }
      }
      continue;
    }

    if((el->fingerprint[0] == ':') && (el->fingerprint[1] == '\0')) {
      /* Too short */
      countCantResolve++;
      continue;
    }

    tmpTable[numEntries++] = el;

    for(i=0; i<MAX_NUM_OS; i++) {
      if(theOSs[i].name == NULL) break;
      if(strcmp(theOSs[i].name, &el->fingerprint[1]) == 0) {
	  theOSs[i].num++;
	  break;
      }
    }

    if(theOSs[i].name == NULL) {
      theOSs[i].name = strdup(&el->fingerprint[1]);
      theOSs[i].num++;
    }

    if(numEntries >= maxHosts)
      break;
  }

  if(numEntries <= 0) {
      printNoDataYet();

      free(tmpTable);

      printFingerprintCounts(countScanned, countWithoutFP, countBroadcast,
                             countMulticast, countRemote, countNotIP,
                             countUnknownFP, unknownFPsEtc, countCantResolve,
                             fingerprintRemote,
                             unknownFPs);

      return;
  }

  myGlobals.columnSort = 0;
  qsort(tmpTable, numEntries, sizeof(HostTraffic*), cmpFctn);

  sendString("<CENTER>\n");
  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON" "DARK_BG"><TH "TH_BG">Host</TH>");

  for(i=0; i<MAX_NUM_OS; i++) {
      if(theOSs[i].name == NULL)
	break;
      else {
        char *strtokState = NULL, *os, *word;
        int sentBR=0;

	sendString("<TH>");
        os = strdup(theOSs[i].name);

        word = strtok_r(os, " ", &strtokState);
        while(word != NULL) {
          if((sentBR++) > 0) sendString("<br>\n");
          sendString(word);
          word = strtok_r(NULL, " ", &strtokState);
        }

        free(os);
	sendString("</TH>");
      }
  }

  sendString("</TR>\n");

  for(idx=0; idx<numEntries; idx++) {
      el = tmpTable[idx];

      if(el != NULL) {
	char *tmpName1;
	tmpName1 = el->hostNumIpAddress;
	if((tmpName1[0] == '\0') || (strcmp(tmpName1, "0.0.0.0") == 0))
	  tmpName1 = myGlobals.separator;

	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH ALIGN=LEFT>%s</TH>",
		    getRowColor(),
		    makeHostLink(el, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)));
	sendString(buf);

	for(i=0; i<MAX_NUM_OS; i++) {
	  if(theOSs[i].name == NULL)
	    break;
	  else {
	    if(strcmp(theOSs[i].name, &el->fingerprint[1]) == 0) {
	      if((el->protocolInfo != NULL) && (el->protocolInfo->userList != NULL)) {
		sendString("<TD ALIGN=LEFT>");
		printUserList(el);
		sendString("<br>\n</TD>");
	      } else {
		if((el->nonIPTraffic != NULL) && (el->nonIPTraffic->nbDomainName != NULL)) {
		  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                              "<TD ALIGN=CENTER>[ %s ]</TD>",
                              el->nonIPTraffic->nbDomainName);
		  sendString(buf);
		} else
		  sendString("<TD ALIGN=CENTER>X</TD>");
	      }
	    } else
	      sendString("<TD>&nbsp;</TD>");
	  }
	} /* for */

	sendString("</TR>\n");
      }
  }

  sendString("</TABLE></center>\n<p>&nbsp;</p>");

  /* ********************************** */

  qsort(theOSs, MAX_NUM_OS, sizeof(OsNumInfo), cmpOSFctn);

  sendString("<center>" TABLE_ON "<table border=\"1\" " TABLE_DEFAULTS ">\n"
             "<tr "TR_ON" "DARK_BG"><th "TH_BG">OS</th>\n<th "TH_BG">Total</th></tr>\n");

  for(i=0; i<MAX_NUM_OS; i++) {
     if(theOSs[i].name != NULL) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "<tr><th align=\"left\">%s</th>\n"
                    "<td align=\"right\">%d</td></tr>\n", 
                    theOSs[i].name, theOSs[i].num);
	sendString(buf);
	free(theOSs[i].name);
      }
  }

  sendString("</table>\n</center>\n");

  free(tmpTable);

  printFingerprintCounts(countScanned, countWithoutFP, countBroadcast,
                         countMulticast, countRemote, countNotIP,
                         countUnknownFP, unknownFPsEtc, countCantResolve,
                         fingerprintRemote,
                         unknownFPs);
}

/* ******************************************************** */

void printMutexStatus(int textPrintFlag, PthreadMutex *mutexId, char *mutexName) {
  char buf[LEN_GENERAL_WORK_BUFFER], bufAttempt[64], bufLock[64], bufUnlock[64];
  struct tm t;

  if(mutexId->numLocks == 0) /* Mutex never used */
    return;
  memset(bufAttempt, 0, sizeof(bufAttempt));
  if(mutexId->attempt.time.tv_sec > 0) {
    strftime(bufAttempt, sizeof(bufAttempt), CONST_LOCALE_TIMESPEC, 
	     localtime_r((const time_t*)&mutexId->attempt.time.tv_sec, &t));
    strncat(bufAttempt, "<br>\n", (sizeof(bufAttempt) - strlen(bufAttempt) - 1));
  }
  memset(bufLock, 0, sizeof(bufLock));
  if(mutexId->lock.time.tv_sec > 0) {
    strftime(bufLock, sizeof(bufLock), CONST_LOCALE_TIMESPEC,
	     localtime_r((const time_t*)&mutexId->lock.time.tv_sec, &t));
    strncat(bufLock, "<br>\n", (sizeof(bufLock) - strlen(bufLock) - 1));
  }
  memset(bufUnlock, 0, sizeof(bufUnlock));
  if(mutexId->unlock.time.tv_sec > 0) {
    strftime(bufUnlock, sizeof(bufUnlock), CONST_LOCALE_TIMESPEC, 
	     localtime_r((const time_t*)&mutexId->unlock.time.tv_sec, &t));
    strncat(bufUnlock, "<br>\n", (sizeof(bufUnlock) - strlen(bufUnlock) - 1));
  }
  if(textPrintFlag == TRUE) {
    if(myGlobals.runningPref.disableMutexExtraInfo) {
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "Mutex %s is %s, locked: %u times.\n",
                    mutexName, mutexId->isLocked ? "locked" : "unlocked",
                    mutexId->numLocks);
        sendString(buf);
    } else if(mutexId->attempt.line > 0) {
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "Mutex %s is %s.\n"
                    "     locked: %u times, last was at %s %s:%d(%d %u)\n"
                    "     blocked: at %s:%d(%d %u)\n",
                    mutexName, mutexId->isLocked ? "locked" : "unlocked",
                    mutexId->numLocks,
                    bufLock,
                    mutexId->lock.file, mutexId->lock.line, mutexId->lock.pid, mutexId->lock.thread,
                    mutexId->attempt.file, mutexId->attempt.line, mutexId->attempt.pid, mutexId->attempt.thread);
		    sendString(buf);

        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "     unlocked: %u times, last was %s:%d(%d %u)\n"
                    "     longest: %.6f sec from %s:%d\n",
                    mutexId->numReleases, mutexId->unlock.file, mutexId->unlock.line, mutexId->unlock.pid, mutexId->unlock.thread,
                    mutexId->maxLockedDuration, mutexId->max.file,
		    mutexId->max.line);
        sendString(buf);
    } else {
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "Mutex %s, is %s.\n"
                    "     locked: %u times, last was at %s %s:%d(%d %u)\n"
                    "     unlocked: %u times, last was at %s %s:%d(%d %u)\n"
                    "     longest: %.6f sec from %s:%d\n",
                    mutexName,
                    mutexId->isLocked ? "locked" : "unlocked",
                    mutexId->numLocks,
                    bufLock,
                    mutexId->lock.file, mutexId->lock.line, mutexId->lock.pid, mutexId->lock.thread,
                    mutexId->numReleases,
                    bufUnlock,
                    mutexId->unlock.file, mutexId->unlock.line, mutexId->unlock.pid, mutexId->unlock.thread,
                    mutexId->maxLockedDuration,
                    mutexId->max.file,
                    mutexId->max.line);
        sendString(buf);
    }
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                  "<tr><th align=\"left\">%s</th>\n<td align=\"center\">%s</td>\n",
                  mutexName,
                  mutexId->isLocked ? "<font color=\"RED\">locked</font>" : "unlocked");
    sendString(buf);

    if(!myGlobals.runningPref.disableMutexExtraInfo) {

      if(mutexId->attempt.line == 0) {
        sendString("<td>&nbsp;</TD>\n");
      } else {
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                      "<td align=\"right\">%s, %s:%d p:%d t:%u</td>\n",
                      bufAttempt,
                      mutexId->attempt.file, mutexId->attempt.line, mutexId->attempt.pid, mutexId->attempt.thread);
        sendString(buf);
      }
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "<td align=\"right\">%s %s:%d p:%d t:%u</td>\n",
                    bufLock,
                    mutexId->lock.file, mutexId->lock.line, mutexId->lock.pid, mutexId->lock.thread);
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "<td align=\"right\">%s %s:%d p:%d t:%u</td>\n",
                    bufUnlock,
                    mutexId->unlock.file, mutexId->unlock.line, mutexId->unlock.pid, mutexId->unlock.thread);
      sendString(buf);
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                    "<td align=\"right\">%.6f seconds %s:%d</td>\n",
		    mutexId->maxLockedDuration, mutexId->max.file, mutexId->max.line);
      sendString(buf);

    }

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                  "<td align=\"right\">%u / %u</td></tr>\n",
                  mutexId->numLocks, mutexId->numReleases);
    sendString(buf);
  }
}

void printFcHeader(int reportType, int revertOrder, u_int column, u_int hourId, char *url) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  char *sign, *arrowGif, *arrow[48], *theAnchor[48];
  char htmlAnchor[64], htmlAnchor1[64];
  char hours[][24] = {"12<BR>AM", "1<BR>AM", "2<BR>AM", "3<BR>AM", "4<BR>AM", "5<BR>AM", "6<BR>AM",
                       "7<BR>AM", "8<BR>AM", "9<BR>AM", "10<BR>AM", "11<BR>AM", "12<BR>PM", "1<BR>PM",
                       "2<BR>PM", "3<BR>PM", "4<BR>PM", "5<BR>PM", "6<BR>PM", "7<BR>PM", "8<BR>PM",
                       "9<BR>PM", "10<BR>PM", "11<BR>PM"};
  int i, j;

  /* printf("->%d<-\n",screenNumber); */

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
  } else {
    sign = "-";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
  }

  memset(buf, 0, sizeof(buf));

  safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=\"%s?col=%s", url, sign);
  safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=\"%s?col=",  url);

  if(abs(column) == FLAG_HOST_DUMMY_IDX) {
    arrow[0] = arrowGif; theAnchor[0] = htmlAnchor;
  } else {
    arrow[0] = ""; theAnchor[0] = htmlAnchor1;
  }

  if(abs(column) == FLAG_DOMAIN_DUMMY_IDX) {
    arrow[1] = arrowGif; theAnchor[1] = htmlAnchor;
  } else {
    arrow[1] = "";  theAnchor[1] = htmlAnchor1;
  }

  if(abs(column) == 0) {
    arrow[2] = arrowGif; theAnchor[2] = htmlAnchor;
  } else {
    arrow[2] = ""; theAnchor[2] = htmlAnchor1;
  }

  switch(reportType) {
  case SORT_FC_DATA:
    sendString("<CENTER>\n");
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON">"
		"<TH "TH_BG" "DARK_BG">%s" FLAG_DOMAIN_DUMMY_IDX_STR "\">VSAN%s</A></TH>\n"
		"<TH "TH_BG" "DARK_BG">%s" FLAG_HOST_DUMMY_IDX_STR "\">FC_Port%s</A></TH>\n"
		"<TH "TH_BG" COLSPAN=2 "DARK_BG">%s0\">Total Bytes%s</A></TH>\n",
		theAnchor[1], arrow[1], theAnchor[0], arrow[0],
                theAnchor[2], arrow[2]);
    sendString(buf);

    if(abs(column) == 1)
      { arrow[0] = arrowGif; theAnchor[0] = htmlAnchor; }
    else { arrow[0] = ""; theAnchor[0] = htmlAnchor1;  }
    if(abs(column) == 2)
      { arrow[1] = arrowGif; theAnchor[1] = htmlAnchor;  }
    else { arrow[1] = "";  theAnchor[1] = htmlAnchor1;}
    if(abs(column) == 3)
      { arrow[2] = arrowGif; theAnchor[2] = htmlAnchor;  }
    else { arrow[2] = ""; theAnchor[2] = htmlAnchor1; }
    if(abs(column) == 4)
      { arrow[3] = arrowGif; theAnchor[3] = htmlAnchor;  }
    else { arrow[3] = ""; theAnchor[3] = htmlAnchor1; }
    if(abs(column) == 5)
      { arrow[4] = arrowGif; theAnchor[4] = htmlAnchor;  }
    else { arrow[4] = ""; theAnchor[4] = htmlAnchor1;  }
    if(abs(column) == 6)
      { arrow[5] = arrowGif; theAnchor[5] = htmlAnchor;  }
    else { arrow[5] = ""; theAnchor[5] = htmlAnchor1;  }
    if(abs(column) == 7)
      { arrow[6] = arrowGif; theAnchor[6] = htmlAnchor1;  }

    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG" "DARK_BG">%s1\">SCSI%s</A></TH>"
                "<TH "TH_BG" "DARK_BG">%s2\">ELS%s</A></TH><TH "TH_BG" "DARK_BG">%s3\">NS%s</A></TH>"
                "<TH "TH_BG" "DARK_BG">%s4\">IP/FC%s</A><TH "TH_BG" "DARK_BG">%s5\">SWILS%s</A></TH>"
                "<TH "TH_BG" "DARK_BG">%s6\">Other%s</A></TH>",
                theAnchor[0], arrow[0], theAnchor[1], arrow[1],
                theAnchor[2], arrow[2], theAnchor[3], arrow[3],
                theAnchor[4], arrow[4], theAnchor[5], arrow[5]);
    sendString(buf);
    break;

  case SORT_FC_ACTIVITY:
    sendString("<CENTER>\n");
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON" >"
		"<TH "TH_BG" "DARK_BG">%s" FLAG_DOMAIN_DUMMY_IDX_STR "\">VSAN%s</A></TH>"
		"<TH "TH_BG" "DARK_BG">%s" FLAG_HOST_DUMMY_IDX_STR "\">FC_Port%s</A></TH>\n",
		theAnchor[1], arrow[1], theAnchor[0], arrow[0]);
    sendString(buf);
    j = hourId;
    for (i = 0; i < 24; i++) {
        j = j % 24;
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TH "TH_BG" "DARK_BG">%s</TH>\n", hours[j]);
        sendString (buf);
        if (!j) {
            j = 23;
        }
        else {
            j--;
        }
    }
    break;
  case SORT_FC_THPT:
    sendString("<CENTER>\n");
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON">"
		"<TH "TH_BG" ROWSPAN=\"2\" "DARK_BG">%s" FLAG_DOMAIN_DUMMY_IDX_STR "\">VSAN%s</A></TH>"
		"<TH "TH_BG" ROWSPAN=\"2\" "DARK_BG">%s" FLAG_HOST_DUMMY_IDX_STR "\">FC_Port%s</A></TH>",
		theAnchor[1], arrow[1], theAnchor[0], arrow[0]);
    sendString(buf);
    updateThpt(0);
    if(abs(column) == 1) { arrow[0] = arrowGif; theAnchor[0] = htmlAnchor; }
    else { arrow[0] = ""; theAnchor[0] = htmlAnchor1;  }
    if(abs(column) == 2) { arrow[1] = arrowGif; theAnchor[1] = htmlAnchor; }
    else { arrow[1] = ""; theAnchor[1] = htmlAnchor1; }
    if(abs(column) == 3) { arrow[2] = arrowGif; theAnchor[2] = htmlAnchor; }
    else { arrow[2] = "";  theAnchor[2] = htmlAnchor1;}
    if(abs(column) == 4) { arrow[3] = arrowGif; theAnchor[3] = htmlAnchor; }
    else { arrow[3] = "";  theAnchor[3] = htmlAnchor1;}
    if(abs(column) == 5) { arrow[4] = arrowGif; theAnchor[4] = htmlAnchor; }
    else { arrow[4] = "";  theAnchor[4] = htmlAnchor1;}
    if(abs(column) == 6) { arrow[5] = arrowGif; theAnchor[5] = htmlAnchor; }
    else { arrow[5] = "";  theAnchor[5] = htmlAnchor1;}

    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG" COLSPAN=\"3\" ALIGN=\"CENTER\" "DARK_BG">Bytes</TH>"
	    "<TH "TH_BG" COLSPAN=\"3\" ALIGN=\"CENTER\" "DARK_BG">Packets</TH>"
            "</TR><TR "TR_ON">");
    sendString(buf);
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG" "DARK_BG">%s1\">Current%s</A></TH>"
	     "<TH "TH_BG" "DARK_BG">%s2\">Avg%s</A></TH>"
	     "<TH "TH_BG" "DARK_BG">%s3\">Peak%s</A></TH>"
	    "<TH "TH_BG" "DARK_BG">%s4\">Current%s</A></TH><TH "TH_BG" "DARK_BG">%s5\">Avg%s</A></TH>"
	     "<TH "TH_BG" "DARK_BG">%s6\">Peak%s</A></TH>",
	    theAnchor[0], arrow[0], theAnchor[1], arrow[1], theAnchor[2], arrow[2],
	    theAnchor[3], arrow[3], theAnchor[4], arrow[4], theAnchor[5], arrow[5]);
    sendString(buf);
    break;
  default:
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, 
                "<CENTER><p>ERROR: reportType=%d</p>\n",
                reportType);
    sendString(buf);
    safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON">"
		"<TH "TH_BG" "DARK_BG">%s" FLAG_DOMAIN_DUMMY_IDX_STR "\">VSAN%s</A></TH>"
		"<TH "TH_BG" "DARK_BG">%s" FLAG_HOST_DUMMY_IDX_STR "\">FC_Port%s</A></TH>",
		theAnchor[1], arrow[1], theAnchor[0], arrow[0]);
    sendString(buf);
    break;
  }

  sendString("</TR>\n");
}

/* ************************************ */

void printPluginTrailer(char *left, char *middle) {
  sendString("<br>\n<hr>\n<br>\n<table border=\"0\" width=100%><tr>");

  if(left != NULL) {
    sendString("<td width=\"20%\">[ <a href=\"../" CONST_PLUGINS_HEADER);
    sendString(left);
    sendString("\">Refresh this data</a> ]");
    sendString("&nbsp;</td>\n");  /* So there's at least something in to cell */
  }

  sendString("<td align=\"left\">");

  sendString("&nbsp;");
  if(middle != NULL) 
    sendString(middle);
  sendString("&nbsp;");

  sendString("</td>\n<td align=\"right\">"
             "&nbsp;[ Back to <a href=\"/" CONST_SHOW_PLUGINS_HTML "\">plugins</a> ]"
             "</td></tr></table>\n<br>\n");
}

/* ************************************ */

void buildMapLink(HostTraffic *el, char *buf, int buf_len) {
  if(privateIPAddress(el))
    buf[0] = '\0';
  else {
#if 0
    safe_snprintf(__FILE__, __LINE__, buf, buf_len,
		" <A class=external href=\"#\" title=\"Physical Host Location\" "
		  "onclick=\"window.open(\'%s?host=%s@%s\', "
		  "\'Host Map\', \'height=210, width=320,toolbar=nodirectories=no,status=no,"
		  "menubar=no,scrollbars=no,resizable=no\'); return false;\">"
		  "<IMG SRC=/marker.png border=0></A>\n",
		  myGlobals.runningPref.mapperURL,
		  el->hostResolvedName, el->hostNumIpAddress);
#else
    safe_snprintf(__FILE__, __LINE__, buf, buf_len,
		  " <A class=external href=\"#\" title=\"Physical Host Location\" "
		  "onclick=\"window.open(\'%s?host=%s&ip=%s\', "
		  "\'Host Map\', \'height=530, width=750,toolbar=nodirectories=no,status=no,"
		  "menubar=no,scrollbars=no,resizable=no\'); return false;\">"
		  "<IMG SRC=/marker.png border=0></A>\n",
		  myGlobals.runningPref.mapperURL,
		  el->hostResolvedName, el->hostNumIpAddress);
#endif
  }
}

/* ************************************ */
