/*
 *  Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
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
  { "Windows",      "<IMG ALT=\"OS: Windows\" ALIGN=MIDDLE SRC=/statsicons/os/windows.gif>" },
  { "IRIX",         "<IMG ALT=\"OS: Irix\" ALIGN=MIDDLE SRC=/statsicons/os/irix.gif>" },
  { "Linux",        "<IMG ALT=\"OS: Linux\" ALIGN=MIDDLE SRC=/statsicons/os/linux.gif>" },
  { "SunOS",        "<IMG  ALT=\"OS: SunOS\" ALIGN=MIDDLE SRC=/statsicons/os/sun.gif>" },
  { "Solaris",      "<IMG  ALT=\"OS: Solaris\" ALIGN=MIDDLE SRC=/statsicons/os/sun.gif>" },
  { "HP/JETdirect", "<IMG  ALT=\"OS: HP/JetDirect\" ALIGN=MIDDLE SRC=/statsicons/os/hp.gif>" },
  { "Mac",          "<IMG  ALT=\"OS: Apple Mac\" ALIGN=MIDDLE SRC=/statsicons/os/mac.gif>" },
  { "Novell",       "<IMG ALT=\"OS: Novell\" ALIGN=MIDDLE SRC=/statsicons/os/novell.gif>" },
  { "BSD",          "<IMG ALT=\"OS: BSD Unix\" ALIGN=MIDDLE SRC=/statsicons/os/bsd.gif>" },
  { "Unix",         "<IMG ALT=\"OS: BSD Unix\" ALIGN=MIDDLE SRC=/statsicons/os/bsd.gif>"},
  { "Berkeley",     "<IMG ALT=\"OS: BSD Unix\" ALIGN=MIDDLE SRC=/statsicons/os/bsd.gif>"},
  { "HP-UX",        "<IMG ALT=\"OS: HP-UX\" ALIGN=MIDDLE SRC=/statsicons/os/hp.gif>" },
  { "AIX",          "<IMG ALT=\"OS: AIX\" ALIGN=MIDDLE SRC=/statsicons/os/aix.gif>" },
  { "Cisco",        "<IMG ALT=\"OS: Cisco\" ALIGN=MIDDLE SRC=/statsicons/os/cisco.gif>" },
  NULL
};

/* ************************************ */

void formatUsageCounter(UsageCounter usageCtr,
			Counter topValue,
			/* If this value != 0 then a percentage is printed */
			int actualDeviceId) {
  char buf[LEN_GENERAL_WORK_BUFFER], formatBuf[32], hostLinkBuf[LEN_GENERAL_WORK_BUFFER];
  int i, sendHeader=0;
  HostTraffic *el;

  if(topValue == 0) {
    /* No percentage is printed */
    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		formatPkts(usageCtr.value.value, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    sendString(buf);
  } else {
    float pctg;

    pctg = ((float)usageCtr.value.value/(float)topValue)*100;

    if(pctg > 100) pctg = 100; /* This should not happen ! */

    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;[%.0f&nbsp;%%]</TD>",
		formatPkts(usageCtr.value.value, formatBuf, sizeof(formatBuf)), pctg) < 0)
      BufferTooShort();
    sendString(buf);
  }

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
      HostTraffic tmpEl;

      if(!emptySerial(&usageCtr.peersSerials[i])) {
	  if((el = quickHostLink(usageCtr.peersSerials[i], myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
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
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH WIDTH=100 "TH_BG" ALIGN=LEFT>%s</TH>"
           "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
           "<TD WIDTH=100 "TD_BG">&nbsp;</TD>\n",
           getRowColor(), label, formatKBytes(totalS, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    break;
  case 100:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH WIDTH=100 "TH_BG" ALIGN=LEFT>%s</TH>"
		"<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100><IMG ALT=\"100%%\"ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=100 HEIGHT=12></TD>\n",
		getRowColor(), label, formatKBytes(totalS, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    break;
  default:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH WIDTH=100 "TH_BG" ALIGN=LEFT>%s</TH>"
		"<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100 "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100\">"
		"<TR "TR_ON"><TD><IMG  ALT=\"%d%%\" ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=\"%d\" HEIGHT=12></TD>"
		"<TD "TD_BG" ALIGN=CENTER WIDTH=\"%d\">"
		"<P>&nbsp;</TD></TR></TABLE>"TABLE_OFF"</TD>\n",
		getRowColor(), label, formatKBytes(totalS, formatBuf, sizeof(formatBuf)),
		int_perc, (100*int_perc)/100, (100*(100-int_perc))/100) < 0)
      BufferTooShort();
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
    if(snprintf(buf, bufLen, "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100 "TD_BG">&nbsp;</TD></TR>\n",
		formatKBytes(totalR, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    break;
  case 100:
    if(snprintf(buf, bufLen, "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100><IMG ALIGN=MIDDLE ALT=\"100\" SRC=/gauge.jpg WIDTH=\"100\" HEIGHT=12></TD></TR>\n",
		formatKBytes(totalR, formatBuf, sizeof(formatBuf))) < 0) BufferTooShort();
    break;
  default:
    if(snprintf(buf, bufLen, "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD  WIDTH=100 "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100\">"
		"<TR "TR_ON"><TD><IMG ALT=\"%d%%\" ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=\"%d\" HEIGHT=12>"
		"</TD><TD "TD_BG" ALIGN=CENTER WIDTH=\"%d\">"
		"<P>&nbsp;</TD></TR></TABLE></TD></TR>\n",
		formatKBytes(totalR, formatBuf, sizeof(formatBuf)),
		int_perc, (100*int_perc)/100, (100*(100-int_perc))/100) < 0)
      BufferTooShort();
  }

  sendString(buf);
}

/* ********************************** */

void printTableEntryPercentage(char *buf, int bufLen,
			       char *label, char* label_1,
			       char* label_2, float total,
			       float percentage) {
  int int_perc;
  char formatBuf[32];

  if(percentage < 0.5)
    int_perc = 0;
  else if(percentage > 99.5)
    int_perc = 100;
  else
    int_perc = (int) (percentage + 0.5);

  switch(int_perc) {
  case 0:
    if(total == -1) {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
             "<TD "TD_BG"><TABLE BORDER=\"0\" CELLPADDING=\"0\" CELLSPACING=\"0\" WIDTH=\"100%%\">"
             "<TR>"
             "<TD ALIGN=LEFT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 0&nbsp;%%</TD>"
             "<TD><TABLE BORDER=\"1\" CELLPADDING=\"1\" CELLSPACING=\"0\" WIDTH=\"100%%\"><TR>"
             "<TD ALIGN=CENTER WIDTH=\"100%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
             "</TR></TABLE></TD>"
             "<TD ALIGN=RIGHT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 100&nbsp;%%</TD></TR></TABLE></TD></TR>\n",
             getRowColor(), label,
             CONST_COLOR_1, label_1,
             CONST_COLOR_2,
             CONST_COLOR_2, label_2) < 0)
        BufferTooShort();
    } else {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		  "<TD "TD_BG"><TABLE BORDER=\"0\" CELLPADDING=\"0\" CELLSPACING=\"0\" WIDTH=\"100%%\">"
		  "<TR>"
		  "<TD ALIGN=LEFT WIDTH=\"10%%\"  BGCOLOR=\"%s\">%s 0&nbsp;%%</TD>"
		  "<TD><TABLE BORDER=\"1\" CELLPADDING=\"1\" CELLSPACING=\"0\" WIDTH=\"100%%\"><TR>"
		  "<TD ALIGN=CENTER WIDTH=\"100%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
		  "</TR></TABLE></TD>"
		  "<TD ALIGN=RIGHT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 100&nbsp;%%</TD></TR></TABLE></TD></TR>\n",
		  getRowColor(), label,
		  formatKBytes(total, formatBuf, sizeof(formatBuf)),
		  CONST_COLOR_1, label_1,
		  CONST_COLOR_2,
		  CONST_COLOR_1, label_2) < 0)
        BufferTooShort();
    }
    break;
  case 100:
    if(total == -1) {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
             "<TD "TD_BG"><TABLE BORDER=\"0\" CELLPADDING=\"0\" CELLSPACING=\"0\" WIDTH=\"100%%\">"
             "<TR>"
             "<TD ALIGN=LEFT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 100&nbsp;%%</TD>"
             "<TD><TABLE BORDER=\"1\" CELLPADDING=\"1\" CELLSPACING=\"0\" WIDTH=\"100%%\"><TR>"
             "<TD ALIGN=CENTER WIDTH=\"100%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
             "</TR></TABLE></TD>"
             "<TD ALIGN=RIGHT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 0&nbsp;%%</TD></TR></TABLE></TD></TR>\n",
             getRowColor(), label,
             CONST_COLOR_1, label_1,
             CONST_COLOR_1,
             CONST_COLOR_2, label_2) < 0)
        BufferTooShort();
    } else {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		  "<TD "TD_BG"><TABLE BORDER=\"0\" CELLPADDING=\"0\" CELLSPACING=\"0\" WIDTH=\"100%%\">"
		  "<TR>"
		  "<TD ALIGN=LEFT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 100&nbsp;%%</TD>"
		  "<TD><TABLE BORDER=\"1\" CELLPADDING=\"1\" CELLSPACING=\"0\" WIDTH=\"100%%\"><TR>"
		  "<TD ALIGN=CENTER WIDTH=\"100%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
		  "</TR></TABLE></TD>"
		  "<TD ALIGN=RIGHT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s 0&nbsp;%%</TD></TR></TABLE></TD></TR>\n",
		  getRowColor(), label,
		  formatKBytes(total, formatBuf, sizeof(formatBuf)),
		  CONST_COLOR_1, label_1, CONST_COLOR_1,
		  CONST_COLOR_2, label_2) < 0)
        BufferTooShort();
    }
    break;
  default:
    if(total == -1) {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
             "<TD "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100%%\">"
             "<TR>"
             "<TD ALIGN=LEFT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s %.1f&nbsp;%%</TD>"
             "<TD><TABLE BORDER=\"1\" CELLPADDING=\"1\" CELLSPACING=\"0\" WIDTH=\"100%%\"><TR>"
             "<TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
             "<TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
             "</TR></TABLE></TD>"
             "<TD ALIGN=RIGHT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s %.1f&nbsp;%%</TD></TR></TABLE></TD></TR>\n",
             getRowColor(), label,
             CONST_COLOR_1, label_1, percentage,
             int_perc, CONST_COLOR_1,
             (100-int_perc), CONST_COLOR_2,
             CONST_COLOR_2, label_2, (100-percentage)) < 0)
         BufferTooShort();
    } else {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		  "<TD "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100%%\">"
		  "<TR><TD ALIGN=LEFT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s %.1f&nbsp;%%</TD>"
		  "<TD><TABLE BORDER=\"1\" CELLPADDING=\"1\" CELLSPACING=\"0\" WIDTH=\"100%%\"><TR>"
		  "<TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
		  "<TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">&nbsp;</TD>"
		  "</TR></TABLE></TD>"
		  "<TD ALIGN=RIGHT WIDTH=\"10%%\" BGCOLOR=\"%s\">%s %.1f&nbsp;%%</TD></TR></TABLE></TD></TR>\n",
		  getRowColor(), label, formatKBytes(total, formatBuf, sizeof(formatBuf)),
		  CONST_COLOR_1, label_1, percentage,
		  int_perc, CONST_COLOR_1,
		  (100-int_perc), CONST_COLOR_2,
		  CONST_COLOR_2, label_2, (100-percentage)) < 0)
	BufferTooShort();
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

    if (snprintf(buf, sizeof(buf),
                 "<P><TABLE BORDER=\"0\">"
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
                 CONST_PCTG_LOW, CONST_PCTG_LOW, CONST_PCTG_MID, CONST_PCTG_MID) < 0)

        BufferTooShort();
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
        sendString("<P>Peak values are the maximum value for any 10 second interval."
		   "<br>Average values are recomputed each 60 seconds, using values "
		   "accumulated since this run of ntop was started.</P>\n");
        sendString("<P>Note: Both values are reset each time ntop is restarted.</P>\n");
        break;
  }

  sendString("</CENTER>\n");
}

/* ******************************* */

void printHeader(int reportType, int revertOrder, u_int column,
		 HostsDisplayPolicy showHostsMode) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  char *sign, *arrowGif, *arrow[64], *theAnchor[64], *url=NULL;
  int i, soFar=2, idx;
  char htmlAnchor[64], htmlAnchor1[64], theLink[64];
  ProtocolsList *protoList;

  /* printf("->%d<-\n",showHostsMode); */

  memset(arrow, 0, sizeof(arrow));
  memset(theAnchor, 0, sizeof(theAnchor));
  memset(htmlAnchor, 0, sizeof(htmlAnchor));
  memset(htmlAnchor1, 0, sizeof(htmlAnchor1));

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG ALT=\"Ascending order, click to reverse\" SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG ALT=\"Descending order, click to reverse\" SRC=arrow_down.gif BORDER=0>";
  }

  memset(buf, 0, sizeof(buf));

  switch(reportType) {
  case SORT_DATA_RECEIVED_PROTOS:   url = CONST_SORT_DATA_RECEIVED_PROTOS_HTML;   break;
  case SORT_DATA_RECEIVED_IP:       url = CONST_SORT_DATA_RECEIVED_IP_HTML;       break;
  case SORT_DATA_RECEIVED_THPT:     url = CONST_SORT_DATA_RECEIVED_THPT_HTML;     break;
  case SORT_DATA_RCVD_HOST_TRAFFIC: url = CONST_SORT_DATA_RCVD_HOST_TRAFFIC_HTML; break;
  case SORT_DATA_SENT_HOST_TRAFFIC: url = CONST_SORT_DATA_SENT_HOST_TRAFFIC_HTML; break;
  case SORT_DATA_SENT_PROTOS:       url = CONST_SORT_DATA_SENT_PROTOS_HTML;       break;
  case SORT_DATA_SENT_IP:           url = CONST_SORT_DATA_SENT_IP_HTML;           break;
  case SORT_DATA_SENT_THPT:         url = CONST_SORT_DATA_SENT_THPT_HTML;         break;
  case TRAFFIC_STATS:               url = CONST_TRAFFIC_STATS_HTML;               break;
  case SORT_DATA_PROTOS:            url = CONST_SORT_DATA_PROTOS_HTML;            break;
  case SORT_DATA_IP:                url = CONST_SORT_DATA_IP_HTML;                break;
  case SORT_DATA_THPT:              url = CONST_SORT_DATA_THPT_HTML;              break;
  case SORT_DATA_HOST_TRAFFIC:      url = CONST_SORT_DATA_HOST_TRAFFIC_HTML;      break;
  }

  if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?showH=%d&col=%s", url, showHostsMode, sign) < 0)
    BufferTooShort();
  if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?showH=%d&col=", url, showHostsMode) < 0)
    BufferTooShort();

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

  snprintf(theLink, sizeof(theLink), "/%s?col=%s%d&showH=", url,
	   revertOrder ? "-" : "", column);

  switch(showHostsMode) {
  case showOnlyLocalHosts:
    snprintf(buf, sizeof(buf), "<P ALIGN=RIGHT>"
	     "[ <A HREF=%s0>All</A> ]&nbsp;"
	     "[<B> Local Only </B>]&nbsp;"
	     "[ <A HREF=%s2>Remote Only</A> ]&nbsp;</p>",
	     theLink, theLink);
    break;
  case showOnlyRemoteHosts:
    snprintf(buf, sizeof(buf), "<P ALIGN=RIGHT>"
	     "[ <A HREF=%s0>All</A> ]&nbsp;"
	     "[ <A HREF=%s1>Local Only</A> ]&nbsp;"
	     "[<B> Remote Only </B>]&nbsp;</p>",
	     theLink, theLink);
    break;
  default:
    snprintf(buf, sizeof(buf), "<P ALIGN=RIGHT>"
	     "[<B> All </B>]&nbsp;"
	     "[ <A HREF=%s1>Local Only</A> ]&nbsp;"
	     "[ <A HREF=%s2>Remote Only</A> ]&nbsp;</p>",
	     theLink, theLink);
    break;
  }
  sendString(buf);

  switch(reportType) {
  case SORT_DATA_RECEIVED_PROTOS:
  case SORT_DATA_SENT_PROTOS:
  case SORT_DATA_PROTOS:
    sendString("<CENTER>\n");
    if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, ""TABLE_ON"<TABLE BORDER=1><TR "TR_ON" "DARK_BG">"
		"<TH "TH_BG">%s"FLAG_HOST_DUMMY_IDX_STR">Host%s</A></TH>\n"
		"<TH "TH_BG">%s"FLAG_DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
		"<TH "TH_BG" COLSPAN=2>%s0>Data%s</A></TH>\n",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1],
		theAnchor[2], arrow[2]) < 0)
      BufferTooShort();
    sendString(buf);

    for(i=0; i<=15; i++)
      if(abs(column) == i+1)  { arrow[i] = arrowGif; theAnchor[i] = htmlAnchor; } else { arrow[i] = ""; theAnchor[i] = htmlAnchor1;  }

    if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG">%s1>TCP%s</A></TH>"
		"<TH "TH_BG">%s2>UDP%s</A></TH><TH "TH_BG">%s3>ICMP%s</A></TH>""<TH "TH_BG">%s4>ICMPv6%s</A></TH>"
		"<TH "TH_BG">%s5>DLC%s</A></TH><TH "TH_BG">%s6>IPX%s</A>"
		"</TH><TH "TH_BG">%s7>Decnet%s</A></TH>"
		"<TH "TH_BG">%s8>(R)ARP%s</A></TH><TH "TH_BG">%s9>AppleTalk%s</A></TH>",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1],
		theAnchor[2], arrow[2], theAnchor[3], arrow[3],
		theAnchor[4], arrow[4],
		theAnchor[5], arrow[5], theAnchor[6], arrow[6],
		theAnchor[7], arrow[7], theAnchor[8], arrow[8]) < 0)
      BufferTooShort();
    sendString(buf);

    if(snprintf(buf, LEN_GENERAL_WORK_BUFFER,
		"<TH "TH_BG">%s11>NetBios%s</A></TH>"
		"<TH "TH_BG">%s13>OSI%s</A></TH>"
		"<TH "TH_BG">%s14>IPv6%s</A></TH>"
		"<TH "TH_BG">%s15>STP%s</A></TH>",
		theAnchor[10], arrow[10],
		theAnchor[12], arrow[12],
		theAnchor[13], arrow[13],
		theAnchor[14], arrow[14]) < 0)
      BufferTooShort();
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

      if(snprintf(buf, sizeof(buf), "<TH "TH_BG">%s%d>%s%s</A></TH>",
		  theAnchor[BASE_PROTOS_IDX+idx], BASE_PROTOS_IDX+idx,
		  protoList->protocolName, arrow[BASE_PROTOS_IDX+idx]) < 0)
	BufferTooShort();
      sendString(buf);

      idx++, protoList = protoList->next;
    }

    if(snprintf(buf, LEN_GENERAL_WORK_BUFFER,
		"<TH "TH_BG">%s16>Other%s</A></TH>",
		theAnchor[15], arrow[15]) < 0)
      BufferTooShort();
    sendString(buf);
    break;

  case SORT_DATA_RECEIVED_IP:
  case SORT_DATA_SENT_IP:
  case SORT_DATA_IP:
    sendString("<CENTER>\n");
    if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, ""TABLE_ON"<TABLE BORDER=1><TR "TR_ON" "DARK_BG">"
		"<TH "TH_BG">%s"FLAG_HOST_DUMMY_IDX_STR">Host%s</A></TH>\n"
		"<TH "TH_BG">%s"FLAG_DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
		"<TH "TH_BG" COLSPAN=2>%s0>Data%s</A></TH>\n",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1],
		theAnchor[2], arrow[2]) < 0)
      BufferTooShort();
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
      if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG">%s%d>%s%s</A></TH>",
		  theAnchor[0], i+2, myGlobals.protoIPTrafficInfos[i], arrow[0]) < 0)
	BufferTooShort();
      sendString(buf);
      soFar++;
    }

    if(abs(column) == soFar) {
      arrow[0] = arrowGif; theAnchor[0] = htmlAnchor;
    } else {
      arrow[0] = "";  theAnchor[0] = htmlAnchor1;
    }
    if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG">%s%d>Other&nbsp;IP%s</A></TH>",
		theAnchor[0], i+2, arrow[0]) < 0)
      BufferTooShort();
    sendString(buf);
    break;

  case SORT_DATA_RCVD_HOST_TRAFFIC:
  case SORT_DATA_SENT_HOST_TRAFFIC:
  case SORT_DATA_HOST_TRAFFIC:
    sendString("<CENTER>\n");
    if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, ""TABLE_ON"<TABLE BORDER=1><TR "DARK_BG">"
		"<TH "TH_BG">%s"FLAG_HOST_DUMMY_IDX_STR">Host%s</A></TH>"
		"<TH "TH_BG">%s"FLAG_DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>\n",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1]) < 0)
      BufferTooShort();
    sendString(buf);
    sendString("<TH "TH_BG">0<BR>AM</TH><TH "TH_BG">1<BR>AM</TH>"
	       "<TH "TH_BG">2<BR>AM</TH><TH "TH_BG">3<BR>AM</TH>"
	       "<TH "TH_BG">4<BR>AM</TH><TH "TH_BG">5<BR>AM</TH><TH "TH_BG">6<BR>AM</TH>"
	       "<TH "TH_BG">7<BR>AM</TH><TH "TH_BG">8<BR>AM</TH><TH "TH_BG">9<BR>AM</TH>"
	       "<TH "TH_BG">10<BR>AM</TH><TH "TH_BG">11<BR>AM</TH><TH "TH_BG">12<BR>AM</TH>\n");
    sendString("<TH "TH_BG">1<BR>PM</TH><TH "TH_BG">2<BR>PM</TH><TH "TH_BG">3<BR>PM</TH>"
	       "<TH "TH_BG">4<BR>PM</TH><TH "TH_BG">5<BR>PM</TH><TH "TH_BG">6<BR>PM</TH>"
	       "<TH "TH_BG">7<BR>PM</TH><TH "TH_BG">8<BR>PM</TH><TH "TH_BG">9<BR>PM</TH>"
	       "<TH "TH_BG">10<BR>PM</TH><TH "TH_BG">11<BR>PM</TH>\n");
    break;
  case SORT_DATA_RECEIVED_THPT:
  case SORT_DATA_SENT_THPT:
  case SORT_DATA_THPT:
    sendString("<CENTER>\n");
    if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, ""TABLE_ON"<TABLE BORDER=1><TR "TR_ON" "DARK_BG">"
		"<TH "TH_BG" ROWSPAN=\"2\">%s"FLAG_HOST_DUMMY_IDX_STR">Host%s</A></TH>"
		"<TH "TH_BG" ROWSPAN=\"2\">%s"FLAG_DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>\n\n",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1]) < 0)
      BufferTooShort();
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

    if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG" COLSPAN=\"3\" ALIGN=CENTER>Data</TH>"
		"<TH "TH_BG" COLSPAN=\"3\" ALIGN=CENTER>Packets</TH>"
		"</TR><TR "TR_ON" "DARK_BG">") < 0)
      BufferTooShort();
    sendString(buf);
    if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, "<TH "TH_BG">%s1>Current%s</A></TH>"
		"<TH "TH_BG">%s2>Avg%s</A></TH>"
		"<TH "TH_BG">%s3>Peak%s</A></TH>"
		"<TH "TH_BG">%s4>Current%s</A></TH><TH "TH_BG">%s5>Avg%s</A></TH>"
		"<TH "TH_BG">%s6>Peak%s</A></TH>",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1], theAnchor[2], arrow[2],
		theAnchor[3], arrow[3], theAnchor[4], arrow[4], theAnchor[5], arrow[5]) < 0)
      BufferTooShort();
    sendString(buf);
    break;
  case TRAFFIC_STATS:
    sendString("<CENTER>\n");
    if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, ""TABLE_ON"<TABLE BORDER=1><TR "TR_ON" "DARK_BG">"
		"<TH "TH_BG">%s"FLAG_HOST_DUMMY_IDX_STR">Host%s</A></TH>"
		"<TH "TH_BG">%s"FLAG_DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>\n\n",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1]) < 0)
      BufferTooShort();
    sendString(buf);
    break;
  }

  sendString("</TR>\n");
}

/* ******************************* */

char* getOSFlag(HostTraffic *el, char *elOsName, int showOsName, char *tmpStr, int tmpStrLen) {
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
    if(flagImg != NULL)
      snprintf(tmpStr, tmpStrLen, "%s", flagImg);
    else
      tmpStr[0] = '\0';
  } else {
    if(flagImg != NULL) {
      if(snprintf(tmpStr, tmpStrLen, "%s&nbsp;[%s]", flagImg, theOsName) < 0)
	BufferTooShort();
    } else
      snprintf(tmpStr, tmpStrLen, "%s", theOsName);
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
    accessAddrResMutex( "sortHostFctn");
    rc = strcasecmp((*a)->hostSymIpAddress[0] != '\0' ? (*a)->hostSymIpAddress : (*a)->ethAddressString,
		    (*b)->hostSymIpAddress[0] != '\0' ? (*b)->hostSymIpAddress : (*b)->ethAddressString);
    releaseAddrResMutex();
    return(rc);
    break;
  case 2:
    /*if((*a)->hostIpAddress.s_addr > (*b)->hostIpAddress.s_addr)
      return(1);
      else if((*a)->hostIpAddress.s_addr < (*b)->hostIpAddress.s_addr)
      return(-1);
      else
      return(0);*/
    return addrcmp(&(*a)->hostIpAddress,&(*b)->hostIpAddress);
    /* return(strcasecmp((*a)->hostNumIpAddress, (*b)->hostNumIpAddress)); */
    break;
  case 3:
    return(strcasecmp((*a)->ethAddressString, (*b)->ethAddressString));
    break;
  case 5:
    return(strcasecmp(getVendorInfo((*a)->ethAddress, 0),
		      getVendorInfo((*b)->ethAddress, 0)));
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
      if(snprintf(nameA_str, sizeof(nameA_str), "%d.%d",
		  (*a)->nonIPTraffic->atNetwork, (*a)->nonIPTraffic->atNode) < 0)
	BufferTooShort();
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
      if(snprintf(nameB_str, sizeof(nameB_str), "%d.%d",
		  (*b)->nonIPTraffic->atNetwork, (*b)->nonIPTraffic->atNode) < 0)
	BufferTooShort();
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
    n_a = (*a)->vlanId, n_b = (*b)->vlanId;

    if(n_a < n_b)
      return(1);
    else if(n_a > n_b)
      return(-1);
    else
      return(0);
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
  }
  if((*a == NULL) && (*b != NULL)) {
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
    int rc;

    /* Host name */
    accessAddrResMutex("cmpFctn");

    if((*a)->hostSymIpAddress[0] != '\0') {
      char *name1, *name2;

      name1 = (*a)->hostSymIpAddress;
      name2 = (*b)->hostSymIpAddress;

      rc = strcasecmp(name1, name2);
    } else
      rc = strcasecmp((*a)->ethAddressString, (*b)->ethAddressString);

    releaseAddrResMutex();
    return(rc);
  } else if(myGlobals.columnSort == FLAG_DOMAIN_DUMMY_IDX) {
    int rc;

    fillDomainName(*a); fillDomainName(*b);

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "%s='%s'/'%s' - %s='%s'/'%s'",
	   (*a)->hostSymIpAddress,
	   (*a)->dotDomainName, (*a)->fullDomainName,
	   (*b)->hostSymIpAddress,
	   (*b)->dotDomainName, (*b)->fullDomainName
	   );
#endif
    if((*a)->dotDomainName == NULL) (*a)->dotDomainName = "";
    if((*b)->dotDomainName == NULL) (*b)->dotDomainName = "";

    rc = strcasecmp((*a)->dotDomainName, (*b)->dotDomainName);
    if(rc == 0)
      return(strcasecmp((*a)->fullDomainName, (*b)->fullDomainName));
    else
      return rc;
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
      a_ = (*a)->dlcRcvd.value, b_ = (*b)->dlcRcvd.value;
      break;
    case 6:
      a_ = (*a)->ipxRcvd.value, b_ = (*b)->ipxRcvd.value;
      break;
    case 7:
      a_ = (*a)->decnetRcvd.value, b_ = (*b)->decnetRcvd.value;
      break;
    case 8:
      a_ = (*a)->arp_rarpRcvd.value, b_ = (*b)->arp_rarpRcvd.value;
      break;
    case 9:
      a_ = (*a)->appletalkRcvd.value, b_ = (*b)->appletalkRcvd.value;
      break;
    case 11:
      a_ = (*a)->netbiosRcvd.value, b_ = (*b)->netbiosRcvd.value;
      break;
    case 13:
      a_ = (*a)->osiRcvd.value, b_ = (*b)->osiRcvd.value;
      break;
    case 14:
      a_ = (*a)->ipv6Rcvd.value, b_ = (*b)->ipv6Rcvd.value;
      break;
    case 15:
      a_ = (*a)->stpRcvd.value, b_ = (*b)->stpRcvd.value;
      break;
    case 16:
      a_ = (*a)->otherRcvd.value, b_ = (*b)->otherRcvd.value;
      break;
    default:
      if((myGlobals.columnSort >= BASE_PROTOS_IDX)
	 && (myGlobals.columnSort < (BASE_PROTOS_IDX+myGlobals.numIpProtosList))) {
	a_ = (*a)->ipProtosList[myGlobals.columnSort-BASE_PROTOS_IDX].rcvd.value,
	  b_ = (*b)->ipProtosList[myGlobals.columnSort-BASE_PROTOS_IDX].rcvd.value;
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
	a_ = (*a)->protoIPTrafficInfos[columnProtoId-1].rcvdLoc.value+
	  (*a)->protoIPTrafficInfos[columnProtoId-1].rcvdFromRem.value;
	b_ = (*b)->protoIPTrafficInfos[columnProtoId-1].rcvdLoc.value+
	  (*b)->protoIPTrafficInfos[columnProtoId-1].rcvdFromRem.value;
      }
    } else {
      a_ = (*a)->ipBytesRcvd.value, b_ = (*b)->ipBytesRcvd.value;

      if(myGlobals.numIpProtosToMonitor == (columnProtoId-1)) {
	/* other IP */
	int i;

	for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	  a_val = ((*a)->protoIPTrafficInfos[i].rcvdLoc.value
		   +(*a)->protoIPTrafficInfos[i].rcvdFromRem.value);
	  b_val = ((*b)->protoIPTrafficInfos[i].rcvdLoc.value
		   +(*b)->protoIPTrafficInfos[i].rcvdFromRem.value);

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
      a_ = (*a)->dlcSent.value, b_ = (*b)->dlcSent.value;
      break;
    case 6:
      a_ = (*a)->ipxSent.value, b_ = (*b)->ipxSent.value;
      break;
    case 7:
      a_ = (*a)->decnetSent.value, b_ = (*b)->decnetSent.value;
      break;
    case 8:
      a_ = (*a)->arp_rarpSent.value, b_ = (*b)->arp_rarpSent.value;
      break;
    case 9:
      a_ = (*a)->appletalkSent.value, b_ = (*b)->appletalkSent.value;
      break;
    case 11:
      a_ = (*a)->netbiosSent.value, b_ = (*b)->netbiosSent.value;
      break;
    case 13:
      a_ = (*a)->osiSent.value, b_ = (*b)->osiSent.value;
      break;
    case 14:
      a_ = (*a)->ipv6Sent.value, b_ = (*b)->ipv6Sent.value;
      break;
    case 15:
      a_ = (*a)->stpSent.value, b_ = (*b)->stpSent.value;
      break;
    case 16:
      a_ = (*a)->otherSent.value, b_ = (*b)->otherSent.value;
      break;
    default:
      if((myGlobals.columnSort >= BASE_PROTOS_IDX)
	 && (myGlobals.columnSort < (BASE_PROTOS_IDX+myGlobals.numIpProtosList))) {
	a_ = (*a)->ipProtosList[myGlobals.columnSort-BASE_PROTOS_IDX].sent.value,
	  b_ = (*b)->ipProtosList[myGlobals.columnSort-BASE_PROTOS_IDX].sent.value;
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
	a_ = (*a)->protoIPTrafficInfos[columnProtoId-1].sentLoc.value
	  +(*a)->protoIPTrafficInfos[columnProtoId-1].sentRem.value;
	b_ = (*b)->protoIPTrafficInfos[columnProtoId-1].sentLoc.value
	  +(*b)->protoIPTrafficInfos[columnProtoId-1].sentRem.value;
      }
    } else {
      a_ = (*a)->ipBytesSent.value, b_ = (*b)->ipBytesSent.value;

      if(myGlobals.numIpProtosToMonitor == (columnProtoId-1)) {
	/* other IP */
	int i;

	for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	  a_val = ((*a)->protoIPTrafficInfos[i].sentLoc.value
		   +(*a)->protoIPTrafficInfos[i].sentRem.value);
	  b_val = ((*b)->protoIPTrafficInfos[i].sentLoc.value
		   +(*b)->protoIPTrafficInfos[i].sentRem.value);

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
      a_ = (*a)->dlcRcvd.value+(*a)->dlcSent.value, b_ = (*b)->dlcRcvd.value+(*b)->dlcSent.value;
      break;
    case 6:
      a_ = (*a)->ipxRcvd.value+(*a)->ipxSent.value, b_ = (*b)->ipxRcvd.value+(*b)->ipxSent.value;
      break;
    case 7:
      a_ = (*a)->decnetRcvd.value+(*a)->decnetSent.value, b_ = (*b)->decnetRcvd.value+(*b)->decnetSent.value;
      break;
    case 8:
      a_ = (*a)->arp_rarpRcvd.value+(*a)->arp_rarpSent.value;
      b_ = (*b)->arp_rarpRcvd.value+(*b)->arp_rarpSent.value;
      break;
    case 9:
      a_ = (*a)->appletalkRcvd.value+(*a)->appletalkSent.value;
      b_ = (*b)->appletalkRcvd.value+(*b)->appletalkSent.value;
      break;
    case 11:
      a_ = (*a)->netbiosRcvd.value+(*a)->netbiosSent.value;
      b_ = (*b)->netbiosRcvd.value+(*b)->netbiosSent.value;
      break;
    case 13:
      a_ = (*a)->osiRcvd.value+(*a)->osiSent.value, b_ = (*b)->osiRcvd.value+(*b)->osiSent.value;
      break;
    case 14:
      a_ = (*a)->ipv6Rcvd.value+(*a)->ipv6Sent.value, b_ = (*b)->ipv6Rcvd.value+(*b)->ipv6Sent.value;
      break;
    case 15:
      a_ = (*a)->stpRcvd.value+(*a)->stpSent.value, b_ = (*b)->stpRcvd.value+(*b)->stpSent.value;
      break;
    case 16:
      a_ = (*a)->otherRcvd.value+(*a)->otherSent.value, b_ = (*b)->otherRcvd.value+(*b)->otherSent.value;
      break;
    default:
      if((myGlobals.columnSort >= BASE_PROTOS_IDX)
	 && (myGlobals.columnSort < (BASE_PROTOS_IDX+myGlobals.numIpProtosList))) {
	a_ = (*a)->ipProtosList[myGlobals.columnSort-BASE_PROTOS_IDX].sent.value
	  +(*a)->ipProtosList[myGlobals.columnSort-BASE_PROTOS_IDX].rcvd.value;
	b_ = (*b)->ipProtosList[myGlobals.columnSort-BASE_PROTOS_IDX].sent.value
	  +(*b)->ipProtosList[myGlobals.columnSort-BASE_PROTOS_IDX].rcvd.value;
      }
      break;
    }
    break;
  case SORT_DATA_IP:
    columnProtoId = myGlobals.columnSort - 1;
    if((columnProtoId != -1) && (columnProtoId <= myGlobals.numIpProtosToMonitor)) {
      if(columnProtoId <= 0) {
        a_ = b_ = 0;
      } else {
        a_ = (*a)->protoIPTrafficInfos[columnProtoId-1].rcvdLoc.value+
          (*a)->protoIPTrafficInfos[columnProtoId-1].rcvdFromRem.value+
          (*a)->protoIPTrafficInfos[columnProtoId-1].sentLoc.value+
          (*a)->protoIPTrafficInfos[columnProtoId-1].sentRem.value;
        b_ = (*b)->protoIPTrafficInfos[columnProtoId-1].rcvdLoc.value+
          (*b)->protoIPTrafficInfos[columnProtoId-1].rcvdFromRem.value+
          (*b)->protoIPTrafficInfos[columnProtoId-1].sentLoc.value+
          (*b)->protoIPTrafficInfos[columnProtoId-1].sentRem.value;
      }
    } else {
      a_ = (*a)->ipBytesRcvd.value+(*a)->ipBytesSent.value;
      b_ = (*b)->ipBytesRcvd.value+(*b)->ipBytesSent.value;

      if(myGlobals.numIpProtosToMonitor == (columnProtoId-1)) {
        /* other IP */
        int i;

        for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
          a_val = ((*a)->protoIPTrafficInfos[i].rcvdLoc.value
                   +(*a)->protoIPTrafficInfos[i].rcvdFromRem.value
                   +(*a)->protoIPTrafficInfos[i].sentLoc.value
                   +(*a)->protoIPTrafficInfos[i].sentRem.value);
          b_val = ((*b)->protoIPTrafficInfos[i].rcvdLoc.value
                   +(*b)->protoIPTrafficInfos[i].rcvdFromRem.value
                   +(*b)->protoIPTrafficInfos[i].sentLoc.value
                   +(*b)->protoIPTrafficInfos[i].sentRem.value);

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
    (*a)->hostSymIpAddress, (unsigned long)a_,
    (*b)->hostSymIpAddress, (unsigned long)b_);
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
    accessAddrResMutex("cmpMulticastFctn");
    rc = strcmp((*a)->hostSymIpAddress, /* Host name */
		(*b)->hostSymIpAddress);
    releaseAddrResMutex();
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

void printHostThtpShort(HostTraffic *el, int reportType) {
  int i;
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

  for(i=0; i<24; i++) {
    float pctg=0;

    if(tc > 0) {
      switch(reportType) {
      case SORT_DATA_RCVD_HOST_TRAFFIC:
	pctg = (float)(el->trafficDistribution->last24HoursBytesRcvd[i].value*100)/(float)tc;
	break;
      case SORT_DATA_SENT_HOST_TRAFFIC:
	pctg = (float)(el->trafficDistribution->last24HoursBytesSent[i].value*100)/(float)tc;
	break;
      case SORT_DATA_HOST_TRAFFIC:
      case TRAFFIC_STATS:
	pctg = ( (float)(el->trafficDistribution->last24HoursBytesRcvd[i].value*100) +
		 (float)(el->trafficDistribution->last24HoursBytesSent[i].value*100) ) / (float)tc;
	break;
      }
    }

    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT %s>&nbsp;</TD>",
		getBgPctgColor(pctg)) < 0) BufferTooShort();
    sendString(buf);
  }
}

/* ******************************* */

int cmpHostsFctn(const void *_a, const void *_b) {
  struct hostTraffic **a = (struct hostTraffic **)_a;
  struct hostTraffic **b = (struct hostTraffic **)_b;
  char *name_a, *name_b;
  Counter a_=0, b_=0;
  int rc;

  switch(myGlobals.columnSort) {
  case 2: /* IP Address */
    /*if((*a)->hostIpAddress.s_addr > (*b)->hostIpAddress.s_addr)
      return(1);
      else if((*a)->hostIpAddress.s_addr < (*b)->hostIpAddress.s_addr)
      return(-1);
      else
      return(0);*/
    return (addrcmp(&(*a)->hostIpAddress,&(*b)->hostIpAddress));
    break;

  case 3: /* Data Sent */
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
    if(a_ < b_) return(1); else if (a_ > b_) return(-1); else return(0);
    break;

  case 4: /* Data Rcvd */
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
    if(a_ < b_) return(1); else if (a_ > b_) return(-1); else return(0);
    break;

  default: /* Host Name */
    accessAddrResMutex("cmpHostsFctn");

    name_a = (*a)->hostSymIpAddress;

    if(name_a == NULL)
      traceEvent(CONST_TRACE_WARNING, "cmpHostsFctn() error (1)");
    if((name_a == NULL) || (strcmp(name_a, "0.0.0.0") == 0)) {
      name_a = (*a)->hostNumIpAddress;
      if((name_a == NULL) || (name_a[0] == '\0'))
	name_a = (*a)->ethAddressString;
    }

    name_b = (*b)->hostSymIpAddress;

    if(name_b == NULL)
      traceEvent(CONST_TRACE_WARNING, "cmpHostsFctn() error (2)");
    if((name_b == NULL) || (strcmp(name_b, "0.0.0.0") == 0)) {
      name_b = (*b)->hostNumIpAddress;
      if((name_b == NULL) || (name_b[0] == '\0'))
	name_b = (*b)->ethAddressString;
    }

    releaseAddrResMutex();
    rc = strcasecmp(name_a, name_b); /* case insensitive */

    return(rc);
  }
}

/* ************************************ */

void printPacketStats(HostTraffic *el, int actualDeviceId) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  char formatBuf[32];
  int headerSent = 0;
  char *tableHeader = "<center><TABLE BORDER=0><TR><TD>";

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
		 ""TABLE_ON"<TABLE BORDER=1 WIDTH=100%><TR "TR_ON" "DARK_BG"><TH "TH_BG">TCP Connections</TH>"
		 "<TH "TH_BG" COLSPAN=2>Directed to</TH>"
		 "<TH "TH_BG" COLSPAN=2>Rcvd From</TH></TR>\n");

      if((el->secHostPkts->synPktsSent.value.value+el->secHostPkts->synPktsRcvd.value.value) > 0) {
	sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Attempted</TH>");
	formatUsageCounter(el->secHostPkts->synPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->synPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->establishedTCPConnSent.value.value+el->secHostPkts->establishedTCPConnRcvd.value.value) > 0) {
	sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Established</TH>");
	formatUsageCounter(el->secHostPkts->establishedTCPConnSent, el->secHostPkts->synPktsSent.value.value, actualDeviceId);
	formatUsageCounter(el->secHostPkts->establishedTCPConnRcvd, el->secHostPkts->synPktsRcvd.value.value, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->terminatedTCPConnServer.value.value + el->secHostPkts->terminatedTCPConnClient.value.value) > 0) {
	sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Terminated</TH>");
	formatUsageCounter(el->secHostPkts->terminatedTCPConnServer, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->terminatedTCPConnClient, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->rejectedTCPConnSent.value.value+el->secHostPkts->rejectedTCPConnRcvd.value.value) > 0) {
	sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Rejected</TH>");
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
		 ""TABLE_ON"<TABLE BORDER=1 WIDTH=100%><TR "TR_ON" "DARK_BG"><TH "TH_BG">TCP Flags</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Sent</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Rcvd</TH></TR>\n");

      if((el->secHostPkts->synPktsSent.value.value+el->secHostPkts->synPktsRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>SYN</TH>",
		    getRowColor()) < 0)
	  BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->synPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->synPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->rstAckPktsSent.value.value+el->secHostPkts->rstAckPktsRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>RST|ACK</TH>",
		    getRowColor()) < 0)
	  BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->rstAckPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->rstAckPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->rstPktsSent.value.value+el->secHostPkts->rstPktsRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>RST</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->rstPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->rstPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->synFinPktsSent.value.value+el->secHostPkts->synFinPktsRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>SYN|FIN</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->synFinPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->synFinPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->finPushUrgPktsSent.value.value+el->secHostPkts->finPushUrgPktsRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>FIN|PUSH|URG</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->finPushUrgPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->finPushUrgPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->nullPktsSent.value.value+el->secHostPkts->nullPktsRcvd.value.value) > 0) {
	sendString("<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>NULL</TH>");
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
		 ""TABLE_ON"<TABLE BORDER=1 WIDTH=100%><TR "TR_ON" "DARK_BG"><TH "TH_BG">Anomaly</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Sent&nbsp;to</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Rcvd&nbsp;from</TH>"
		 "</TR>\n");

      if((el->secHostPkts->ackXmasFinSynNullScanSent.value.value+el->secHostPkts->ackXmasFinSynNullScanRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>ACK/XMAS/SYN/FIN/NULL Scan</TH>",
		    getRowColor()) < 0)
	  BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->ackXmasFinSynNullScanSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->ackXmasFinSynNullScanRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->udpToClosedPortSent.value.value+
	  el->secHostPkts->udpToClosedPortRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>UDP Pkt to Closed Port</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->udpToClosedPortSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->udpToClosedPortRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->udpToDiagnosticPortSent.value.value+
	  el->secHostPkts->udpToDiagnosticPortRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>UDP Pkt Disgnostic Port</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->udpToDiagnosticPortSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->udpToDiagnosticPortRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->tcpToDiagnosticPortSent.value.value+
	  el->secHostPkts->tcpToDiagnosticPortRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>TCP Pkt Disgnostic Port</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->tcpToDiagnosticPortSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->tcpToDiagnosticPortRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->tinyFragmentSent.value.value+
	  el->secHostPkts->tinyFragmentRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Tiny Fragments</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->tinyFragmentSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->tinyFragmentRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->icmpFragmentSent.value.value+
	  el->secHostPkts->icmpFragmentRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>ICMP Fragments</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->icmpFragmentSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->icmpFragmentRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->overlappingFragmentSent.value.value+
	  el->secHostPkts->overlappingFragmentRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Overlapping Fragments</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->overlappingFragmentSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->overlappingFragmentRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->closedEmptyTCPConnSent.value.value+
	  el->secHostPkts->closedEmptyTCPConnRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Closed Empty TCP Conn.</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->closedEmptyTCPConnSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->closedEmptyTCPConnRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }


      if((el->secHostPkts->icmpPortUnreachSent.value.value+
	  el->secHostPkts->icmpPortUnreachRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>ICMP Port Unreachable</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->icmpPortUnreachSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->icmpPortUnreachRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->icmpHostNetUnreachSent.value.value+
	  el->secHostPkts->icmpHostNetUnreachRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>ICMP Net Unreachable</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->icmpHostNetUnreachSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->icmpHostNetUnreachRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->icmpProtocolUnreachSent.value.value+
	  el->secHostPkts->icmpProtocolUnreachRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>ICMP Protocol Unreachable</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->icmpProtocolUnreachSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->icmpProtocolUnreachRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->icmpAdminProhibitedSent.value.value+
	  el->secHostPkts->icmpAdminProhibitedRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>ICMP Administratively Prohibited</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->icmpAdminProhibitedSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->icmpAdminProhibitedRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }






      if((el->secHostPkts->malformedPktsSent.value.value+
	  el->secHostPkts->malformedPktsRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Malformed Pkts</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->malformedPktsSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->malformedPktsRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }
  }

  if(el->arpReqPktsSent.value+el->arpReplyPktsSent.value+el->arpReplyPktsRcvd.value > 0) {
    if(!headerSent) {
      printSectionTitle("Packet Statistics");
      sendString(tableHeader);
      headerSent = 1;
    }

    sendString("<CENTER>\n"
	       ""TABLE_ON"<TABLE BORDER=1 WIDTH=100%><TR "TR_ON" "DARK_BG">"
	       "<TH "TH_BG">ARP</TH>"
	       "<TH "TH_BG">Packet</TH>"
	       "</TR>\n");

    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Request Sent</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		getRowColor(),
		formatPkts(el->arpReqPktsSent.value, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Reply Rcvd</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s (%.1f %%)</TD></TR>",
		getRowColor(),
		formatPkts(el->arpReplyPktsRcvd.value, formatBuf, sizeof(formatBuf)),
		((el->arpReqPktsSent.value > 0) ?
		(float)((el->arpReplyPktsRcvd.value*100)/(float)el->arpReqPktsSent.value) : 0)) < 0)
      BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Reply Sent</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		getRowColor(),
		formatPkts(el->arpReplyPktsSent.value, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    sendString(buf);

    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");
  }

  if(headerSent) { sendString("</TD></TR></TABLE>"TABLE_OFF"</CENTER>"); }
}

/* ************************************ */

void printHostFragmentStats(HostTraffic *el, int actualDeviceId) {
  Counter totalSent, totalRcvd;
  char buf[LEN_GENERAL_WORK_BUFFER];
  char linkName[LEN_GENERAL_WORK_BUFFER/2];
  int i;

  totalSent = el->tcpFragmentsSent.value + el->udpFragmentsSent.value + el->icmpFragmentsSent.value;
  totalRcvd = el->tcpFragmentsRcvd.value + el->udpFragmentsRcvd.value + el->icmpFragmentsRcvd.value;

 if((totalSent == 0) && (totalRcvd == 0))
    return;

  printSectionTitle("IP Fragments Distribution");

  sendString("<CENTER>\n"
	     ""TABLE_ON"<TABLE BORDER=1><TR "DARK_BG"><TH "TH_BG" WIDTH=100>Protocol</TH>"
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
      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Fragment Distribution</TH>",
		  getRowColor()) < 0)
	BufferTooShort();
      sendString(buf);

      if(el->hostNumIpAddress[0] != '\0') {
        strncpy(linkName, el->hostNumIpAddress, sizeof(linkName));
      } else {
        strncpy(linkName, el->ethAddressString, sizeof(linkName));
      }
      /* For Ethernet and IPv6 addresses */
      for(i=0; linkName[i] != '\0'; i++)
          if(linkName[i] == ':')
            linkName[i] = '_';  /* to avoid escaping chars */

      if(totalSent > 0) {
	if(snprintf(buf, sizeof(buf),
		    "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostFragmentDistrib-%s"CHART_FORMAT"?1 ALT=\"Sent Fragment Distribution for %s\"></TD>",
		    linkName,
                   el->hostNumIpAddress[0] == '\0' ?  el->ethAddressString : el->hostNumIpAddress) < 0)
	  BufferTooShort();
	sendString(buf);
      } else {
	sendString("<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>&nbsp;</TD>");
      }

      if(totalRcvd > 0) {
	if(snprintf(buf, sizeof(buf),
		    "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostFragmentDistrib-%s"CHART_FORMAT" ALT=\"Received Fragment Distribution for %s\"></TD>",
		    linkName,
                   el->hostNumIpAddress[0] == '\0' ?  el->ethAddressString : el->hostNumIpAddress) < 0)
	  BufferTooShort();
	sendString(buf);
      } else {
	sendString("<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>&nbsp;</TD>");
      }

      sendString("</TD></TR>");

      /* ***************************************** */

      if(snprintf(buf, sizeof(buf),
		  "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>IP Fragment Distribution</TH>",
		  getRowColor()) < 0)
	BufferTooShort();
      sendString(buf);

      if(totalSent > 0) {
	if(snprintf(buf, sizeof(buf),
		    "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostTotalFragmentDistrib-%s"CHART_FORMAT"?1 ALT=\"Sent IP Fragment Distribution for %s\"></TD>",
		    linkName,
                   el->hostNumIpAddress[0] == '\0' ?  el->ethAddressString : el->hostNumIpAddress) < 0)
	  BufferTooShort();
	sendString(buf);
      } else {
	sendString("<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>&nbsp;</TD>");
      }

      if(totalRcvd > 0) {
	if(snprintf(buf, sizeof(buf),
		    "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostTotalFragmentDistrib-%s"CHART_FORMAT" ALT=\"Received IP Fragment Distribution for %s\"></TD>",
		    linkName,
                   el->hostNumIpAddress[0] == '\0' ?  el->ethAddressString : el->hostNumIpAddress) < 0)
	  BufferTooShort();
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
  case SAP_NULL:           snprintf(sap, sap_len, "NULL LSAP"); break;
  case SAP_LLC_SLMGMT:     snprintf(sap, sap_len, "LLC Sub-Layer Management"); break;
  case SAP_SNA_PATHCTRL:   snprintf(sap, sap_len, "SNA Path Control"); break;
  case SAP_IP:             snprintf(sap, sap_len, "TCP/IP"); break;
  case SAP_SNA1:           snprintf(sap, sap_len, "SNA"); break;
  case SAP_SNA2:           snprintf(sap, sap_len, "SNA"); break;
  case SAP_PROWAY_NM_INIT: snprintf(sap, sap_len, "PROWAY (IEC955) Network Management and Initialization"); break;
  case SAP_TI:             snprintf(sap, sap_len, "Texas Instruments"); break;
  case SAP_BPDU:           snprintf(sap, sap_len, "Spanning Tree BPDU"); break;
  case SAP_RS511:          snprintf(sap, sap_len, "EIA RS-511 Manufacturing Message Service"); break;
  case SAP_X25:            snprintf(sap, sap_len, "ISO 8208 (X.25 over 802.2)"); break;
  case 0x7F:               snprintf(sap, sap_len, "ISO 802.2"); break;
  case SAP_XNS:            snprintf(sap, sap_len, "XNS"); break;
  case SAP_BACNET:         snprintf(sap, sap_len, "BACnet"); break;
  case SAP_NESTAR:         snprintf(sap, sap_len, "Nestar"); break;
  case SAP_PROWAY_ASLM:    snprintf(sap, sap_len, "PROWAY (IEC955) Active Station List Maintenance"); break;
  case SAP_ARP:            snprintf(sap, sap_len, "ARP"); break;
  case SAP_SNAP:           snprintf(sap, sap_len, "SNAP"); break;
  case SAP_VINES1:
  case SAP_VINES2:         snprintf(sap, sap_len, "Banyan Vines"); break;
  case SAP_NETWARE:        snprintf(sap, sap_len, "NetWare"); break;
  case SAP_NETBIOS:        snprintf(sap, sap_len, "NetBIOS"); break;
  case SAP_IBMNM:          snprintf(sap, sap_len, "IBM Net Management"); break;
  case SAP_HPEXT:          snprintf(sap, sap_len, "HP Extended LLC"); break;
  case SAP_UB:             snprintf(sap, sap_len, "Ungermann-Bass"); break;
  case SAP_RPL:            snprintf(sap, sap_len, "Remote Program Load"); break;
  case SAP_OSINL:          snprintf(sap, sap_len, "ISO Network Layer"); break;
  case SAP_GLOBAL:         snprintf(sap, sap_len, "Global LSAP"); break;
  default:                 snprintf(sap, sap_len, "0x%X", proto); break;
  }

  return(sap);
}

/* ************************************ */

static void printUnknownProto(UnknownProto proto) {
  char buf[64];

  switch(proto.protoType) {
  case 1:
    snprintf(buf, sizeof(buf), "<li>Ethernet Type: 0x%04X\n", proto.proto.ethType);
    break;
  case 2:
    snprintf(buf, sizeof(buf), "<li>SAP: DSAP=0x%02X/SSAP=0x%02X\n",
	     proto.proto.sapType.dsap, proto.proto.sapType.ssap);
     break;
  case 3:
    snprintf(buf, sizeof(buf), "<li>IP Protocol: 0x%d\n", proto.proto.ipType);
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
  char buf[LEN_GENERAL_WORK_BUFFER];
  char linkName[LEN_GENERAL_WORK_BUFFER/2];
  int i, idx;
  ProtocolsList *protoList;

  totalSent = el->tcpSentLoc.value+el->tcpSentRem.value+el->udpSentLoc.value+el->udpSentRem.value;
  totalSent += el->icmpSent.value+el->icmp6Sent.value+el->ipxSent.value+el->dlcSent.value+el->arp_rarpSent.value;
  totalSent +=  el->decnetSent.value+el->appletalkSent.value+el->netbiosSent.value+
    el->osiSent.value+el->ipv6Sent.value+el->stpSent.value+el->otherSent.value;

  totalRcvd = el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value;
  totalRcvd += el->udpRcvdLoc.value+el->udpRcvdFromRem.value;
  totalRcvd += el->icmpRcvd.value+el->icmp6Rcvd.value;
  totalRcvd += el->ipxRcvd.value+el->dlcRcvd.value+el->arp_rarpRcvd.value;
  totalRcvd += el->decnetRcvd.value+el->appletalkRcvd.value;
  totalRcvd += el->osiRcvd.value+el->netbiosRcvd.value+el->ipv6Rcvd.value
    +el->stpRcvd.value+el->otherRcvd.value;

  protoList = myGlobals.ipProtosList;
  idx = 0;

  while(protoList != NULL) {
    totalSent += el->ipProtosList[idx].sent.value;
    totalRcvd += el->ipProtosList[idx].rcvd.value;
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
	     ""TABLE_ON"<TABLE BORDER=1 WIDTH=80%%><TR "DARK_BG"><TH "TH_BG" WIDTH=100>Protocol</TH>"
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

  printTableDoubleEntry(buf, sizeof(buf), "(R)ARP", CONST_COLOR_1, (float)el->arp_rarpSent.value/1024,
			100*((float)SD(el->arp_rarpSent.value, totalSent)),
			(float)el->arp_rarpRcvd.value/1024,
			100*((float)SD(el->arp_rarpRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "DLC", CONST_COLOR_1, (float)el->dlcSent.value/1024,
			100*((float)SD(el->dlcSent.value, totalSent)),
			(float)el->dlcRcvd.value/1024,
			100*((float)SD(el->dlcRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "IPX", CONST_COLOR_1, (float)el->ipxSent.value/1024,
			100*((float)SD(el->ipxSent.value, totalSent)),
			(float)el->ipxRcvd.value/1024,
			100*((float)SD(el->ipxRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "Decnet", CONST_COLOR_1, (float)el->decnetSent.value/1024,
			100*((float)SD(el->decnetSent.value, totalSent)),
			(float)el->decnetRcvd.value/1024,
			100*((float)SD(el->decnetRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "AppleTalk", CONST_COLOR_1, (float)el->appletalkSent.value/1024,
			100*((float)SD(el->appletalkSent.value, totalSent)),
			(float)el->appletalkRcvd.value/1024,
			100*((float)SD(el->appletalkRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "NetBios", CONST_COLOR_1, (float)el->netbiosSent.value/1024,
			100*((float)SD(el->netbiosSent.value, totalSent)),
			(float)el->netbiosRcvd.value/1024,
			100*((float)SD(el->netbiosRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "OSI", CONST_COLOR_1, (float)el->osiSent.value/1024,
			100*((float)SD(el->osiSent.value, totalSent)),
			(float)el->osiRcvd.value/1024,
			100*((float)SD(el->osiRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "IPv6", CONST_COLOR_1, (float)el->ipv6Sent.value/1024,
			100*((float)SD(el->ipv6Sent.value, totalSent)),
			(float)el->ipv6Rcvd.value/1024,
			100*((float)SD(el->ipv6Rcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "STP", CONST_COLOR_1, (float)el->stpSent.value/1024,
			100*((float)SD(el->stpSent.value, totalSent)),
			(float)el->stpRcvd.value/1024,
			100*((float)SD(el->stpRcvd.value, totalRcvd)));

  {
    protoList = myGlobals.ipProtosList;
    idx = 0;

    while(protoList != NULL) {
      printTableDoubleEntry(buf, sizeof(buf), protoList->protocolName, CONST_COLOR_1,
			    (float)el->ipProtosList[idx].sent.value/1024,
			    100*((float)SD(el->ipProtosList[idx].sent.value, totalSent)),
			    (float)el->ipProtosList[idx].rcvd.value/1024,
			    100*((float)SD(el->ipProtosList[idx].rcvd.value, totalRcvd)));
      idx++, protoList = protoList->next;
    }
  }

  printTableDoubleEntry(buf, sizeof(buf), "Other (Non IP)", CONST_COLOR_1, (float)el->otherSent.value/1024,
			100*((float)SD(el->otherSent.value, totalSent)),
			(float)el->otherRcvd.value/1024,
			100*((float)SD(el->otherRcvd.value, totalRcvd)));

  {
    totalSent = el->tcpSentLoc.value+el->tcpSentRem.value+
      el->udpSentLoc.value+el->udpSentRem.value+
      el->icmpSent.value+el->icmp6Sent.value+el->stpSent.value+
      el->ipxSent.value+el->osiSent.value+el->dlcSent.value+
      el->arp_rarpSent.value+el->decnetSent.value+el->appletalkSent.value+
      el->netbiosSent.value+el->ipv6Sent.value+el->otherSent.value;

    totalRcvd = el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value+
      el->udpRcvdLoc.value+el->udpRcvdFromRem.value+
      el->icmpRcvd.value+el->icmp6Rcvd.value+el->stpRcvd.value+
      el->ipxRcvd.value+el->osiRcvd.value+el->dlcRcvd.value+
      el->arp_rarpRcvd.value+el->decnetRcvd.value+el->appletalkRcvd.value+
      el->netbiosRcvd.value+el->ipv6Rcvd.value+el->otherRcvd.value;

    protoList = myGlobals.ipProtosList;
    idx = 0;

    while(protoList != NULL) {
      totalSent += el->ipProtosList[idx].sent.value;
      totalRcvd += el->ipProtosList[idx].rcvd.value;
      idx++, protoList = protoList->next;
    }

    if((totalSent > 0) || (totalRcvd > 0)) {
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Protocol Distribution</TH>",
		  getRowColor()) < 0)
	BufferTooShort();
      sendString(buf);

      if(el->hostNumIpAddress[0] != '\0') {
        strncpy(linkName, el->hostNumIpAddress, sizeof(linkName));
      } else {
        strncpy(linkName, el->ethAddressString, sizeof(linkName));
      }
      /* For Ethernet and Ipv6 addresses */
      for(i=0; linkName[i] != '\0'; i++)
	if(linkName[i] == ':')
            linkName[i] = '_';  /* to avoid escaping chars */

      if(totalSent > 0) {
	if(snprintf(buf, sizeof(buf),
		    "<TD WIDTH=250 "TD_BG" ALIGN=RIGHT COLSPAN=2>"
		    "<IMG SRC=\"hostTrafficDistrib-%s"CHART_FORMAT"?1\" "
		    "ALT=\"Sent Traffic Distribution for %s\"></TD>",
                    linkName,
                    el->hostNumIpAddress[0] == '\0' ?  el->ethAddressString : el->hostNumIpAddress) < 0)
	  BufferTooShort();
	sendString(buf);
      } else {
	sendString("<TD width=250 "TD_BG" ALIGN=RIGHT COLSPAN=2 WIDTH=250>&nbsp;</TD>");
      }

      if(totalRcvd > 0) {
	if(snprintf(buf, sizeof(buf),
		    "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostTrafficDistrib-"
		    "%s"CHART_FORMAT" ALT=\"Received Traffic Distribution for %s\"></TD>",
		    linkName,
		    el->hostNumIpAddress[0] == '\0' ?  el->ethAddressString : el->hostNumIpAddress) < 0)
	  BufferTooShort();
	sendString(buf);
      } else {
	sendString("<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 WIDTH=250>&nbsp;</TD>");
      }

      sendString("</TD></TR>");

      if((el->tcpSentLoc.value+el->tcpSentRem.value+el->udpSentLoc.value+el->udpSentRem.value
	  +el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value+el->udpRcvdLoc.value+el->udpRcvdFromRem.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>IP Distribution</TH>",
		    getRowColor()) < 0)
	  BufferTooShort();
	sendString(buf);

	if((el->tcpSentLoc.value+el->tcpSentRem.value+el->udpSentLoc.value+el->udpSentRem.value) > 0) {
	  if(snprintf(buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=\"hostIPTrafficDistrib-%s"CHART_FORMAT"?1\" ALT=\"Sent IP Traffic Distribution for %s\"></TD>",
		      linkName, el->hostNumIpAddress) < 0)
	    BufferTooShort();
	  sendString(buf);
	} else
	  sendString("<TD "TD_BG" COLSPAN=2 WIDTH=250>&nbsp;</TD>");

	if((el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value+el->udpRcvdLoc.value+el->udpRcvdFromRem.value) > 0) {
	  if(snprintf(buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostIPTrafficDistrib-"
		      "%s"CHART_FORMAT" ALT=\"Received IP Traffic Distribution for %s\"></TD></TR>",
		      linkName, el->hostNumIpAddress) < 0)
	    BufferTooShort();
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
	       ""TABLE_ON"<TABLE BORDER=1><TR "DARK_BG" "DARK_BG"><TH "TH_BG" WIDTH=100>Protocol</TH>"
	       "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Sent</TH>"
	       "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Rcvd</TH></TR>\n");

    while(nonIp != NULL) {
      char buf1[64];

      printTableDoubleEntry(buf, sizeof(buf), sap2name(nonIp->protocolId, buf1, sizeof(buf1)),
			    CONST_COLOR_1, (float)nonIp->sentBytes.value/1024,
			    100*((float)SD(nonIp->sentBytes.value, el->otherSent.value)),
			    (float)nonIp->rcvdBytes.value/1024,
			    100*((float)SD(nonIp->rcvdBytes.value, el->otherRcvd.value)));

      nonIp = nonIp->next;
    }

    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");
  }

 /* ************************************** */

  if(el->unknownProtoSent || el->unknownProtoRcvd) {
    printSectionTitle("Unknown Protocols");

    sendString("<CENTER>\n"
	       ""TABLE_ON"<TABLE BORDER=1><TR "DARK_BG">"
	       "<TH "TH_BG" WIDTH=200>Data&nbsp;Sent</TH>"
	       "<TH "TH_BG" WIDTH=200>Data&nbsp;Rcvd</TH></TR>\n");

    if(el->unknownProtoSent == NULL) {
      sendString("<TR><TH "TH_BG">&nbsp;</TH>");
    } else {
      sendString("<TR><TH "TH_BG" ALIGN=LEFT>");
      for(i=0; i<MAX_NUM_UNKNOWN_PROTOS; i++)
	printUnknownProto(el->unknownProtoSent[i]);
      sendString("&nbsp;</TH>");
    }

    if(el->unknownProtoRcvd == NULL) {
      sendString("<TH "TH_BG">&nbsp;</TH></TR>");
    } else {
      sendString("<TH "TH_BG" ALIGN=LEFT>");
      for(i=0; i<MAX_NUM_UNKNOWN_PROTOS; i++)
	printUnknownProto(el->unknownProtoRcvd[i]);
      sendString("&nbsp;</TH></TR>");
    }

    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");
  }
}

/* ************************************ */

#ifdef INET6
void printIcmpv6Stats(HostTraffic *el) {
  char buf[LEN_GENERAL_WORK_BUFFER], formatBuf[32], formatBuf1[32];

  sendString("<CENTER>\n<H1>ICMPv6 Traffic</H1><p>\n");
  sendString("<TABLE BORDER>\n");
  sendString("<TR "TR_ON" "DARK_BG"><th>Type</th>"
             "<TH "TH_BG" ALIGN=LEFT>Pkt&nbsp;Sent</TH>"
             "<TH "TH_BG" ALIGN=LEFT>Pkt&nbsp;Rcvd</TH></TR>\n");

  if(el->icmpInfo->icmpMsgSent[ICMP6_ECHO_REQUEST].value+el->icmpInfo->icmpMsgRcvd[ICMP6_ECHO_REQUEST].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Echo Request</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ICMP6_ECHO_REQUEST].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP6_ECHO_REQUEST].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP6_ECHO_REPLY].value+el->icmpInfo->icmpMsgRcvd[ICMP6_ECHO_REPLY].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Echo Reply</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ICMP6_ECHO_REPLY].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP6_ECHO_REPLY].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP6_DST_UNREACH].value+el->icmpInfo->icmpMsgRcvd[ICMP6_DST_UNREACH].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Unreach</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ICMP6_DST_UNREACH].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP6_DST_UNREACH].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ND_REDIRECT].value+el->icmpInfo->icmpMsgRcvd[ND_REDIRECT].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Redirect</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ND_REDIRECT].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ND_REDIRECT].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ND_ROUTER_ADVERT].value+el->icmpInfo->icmpMsgRcvd[ND_ROUTER_ADVERT].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Router Advertisement</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ND_ROUTER_ADVERT].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ND_ROUTER_ADVERT].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ND_ROUTER_SOLICIT].value+el->icmpInfo->icmpMsgRcvd[ND_ROUTER_SOLICIT].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Router solicitation</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ND_ROUTER_SOLICIT].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ND_ROUTER_SOLICIT].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ND_NEIGHBOR_SOLICIT].value+el->icmpInfo->icmpMsgRcvd[ND_NEIGHBOR_SOLICIT].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Neighbor solicitation</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ND_NEIGHBOR_SOLICIT].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ND_NEIGHBOR_SOLICIT].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ND_NEIGHBOR_ADVERT].value+el->icmpInfo->icmpMsgRcvd[ND_NEIGHBOR_ADVERT].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Neighbor advertisment</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
                formatPkts(el->icmpInfo->icmpMsgSent[ND_NEIGHBOR_ADVERT].value, formatBuf, sizeof(formatBuf)),
                formatPkts(el->icmpInfo->icmpMsgRcvd[ND_NEIGHBOR_ADVERT].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }
  sendString("</TABLE>"TABLE_OFF"</CENTER>\n");
}
#endif

/* ******************************************** */

void printIcmpv4Stats(HostTraffic *el) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  char formatBuf[32], formatBuf1[32];

  sendString("<CENTER>\n<H1>ICMP Traffic</H1><p>\n");
  sendString("<TABLE BORDER>\n");
  sendString("<TR "TR_ON" "DARK_BG"><th>Type</th>"
	     "<TH "TH_BG" ALIGN=LEFT>Pkt&nbsp;Sent</TH>"
	     "<TH "TH_BG" ALIGN=LEFT>Pkt&nbsp;Rcvd</TH></TR>\n");

  if(el->icmpInfo->icmpMsgSent[ICMP_ECHO].value+el->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Echo Request</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_ECHO].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value+el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Echo Reply</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_UNREACH].value+el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Unreach</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_UNREACH].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_REDIRECT].value+el->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Redirect</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_REDIRECT].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

   if(el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value+el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Router Advertisement</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

   if(el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value+el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Time Exceeded</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB].value+el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Parameter Problem</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_MASKREQ].value+el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Network Mask Request</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_MASKREQ].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY].value+el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Network Mask Reply</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH].value+el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Source Quench</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP].value+el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Timestamp</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST].value+el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Info Request</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY].value+el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Info Reply</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY].value, formatBuf, sizeof(formatBuf)),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY].value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
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
    sendString("<CENTER>\n<TABLE BORDER=0><TR><TD "TD_BG" VALIGN=TOP>\n");

    sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=100%>"
	       "<TR "TR_ON" "DARK_BG"><TH "TH_BG">Virtual Host</TH>"
	       "<TH "TH_BG">Sent</TH><TH "TH_BG">Rcvd</TH></TR>\n");

    while(list != NULL) {
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=CENTER>%s&nbsp;</TD>"
		  "<TD "TD_BG" ALIGN=CENTER>%s&nbsp;</TD></TR>\n",
		  getRowColor(), list->virtualHostName,
		  formatBytes(list->bytesSent.value, 1, formatBuf, sizeof(formatBuf)),
		  formatBytes(list->bytesRcvd.value, 1, formatBuf1, sizeof(formatBuf1))) < 0)
	BufferTooShort();
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
  HostTraffic *theEntry = NULL;
  int found = 0;

  if(cmpSerial(&theSerial, &myGlobals.broadcastEntry->hostSerial)) {
    memcpy(el, myGlobals.broadcastEntry, sizeof(HostTraffic));
    return(el);
  } else if(cmpSerial(&theSerial, &myGlobals.otherHostEntry->hostSerial)) {
    memcpy(el, myGlobals.otherHostEntry, sizeof(HostTraffic));
    return(0);
  }

  memset(el, 0, sizeof(HostTraffic));
  copySerial(&el->hostSerial, &theSerial);

  if((theSerial.serialType == SERIAL_IPV4) ||
     (theSerial.serialType == SERIAL_IPV6)){
    /* IP */
    char sniffedName[MAXDNAME];
    char buf[LEN_GENERAL_WORK_BUFFER];

    addrcpy(&el->hostIpAddress,&theSerial.value.ipAddress);
    strncpy(el->hostNumIpAddress,
	    _addrtostr(&el->hostIpAddress, buf, sizeof(buf)),
	    sizeof(el->hostNumIpAddress));
    fetchAddressFromCache(el->hostIpAddress, el->hostSymIpAddress);

    if(strcmp(el->hostSymIpAddress, el->hostNumIpAddress) == 0) {
      if(getSniffedDNSName(el->hostNumIpAddress, sniffedName, sizeof(sniffedName))) {
	int i;

	for(i=0; i<strlen(sniffedName); i++) if(isupper(sniffedName[i])) tolower(sniffedName[i]);
	strcpy(el->hostSymIpAddress, sniffedName);
      }
    }
  } else {
    /* MAC */
    char *ethAddr;
    char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

    memcpy(el->ethAddress, theSerial.value.ethAddress, LEN_ETHERNET_ADDRESS);
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
  char buf[LEN_GENERAL_WORK_BUFFER], hostLinkBuf[LEN_GENERAL_WORK_BUFFER];
  HostTraffic tmpEl;

  if((el->pktSent.value != 0) || (el->pktRcvd.value != 0)) {
      int ok =0;

    for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	if((!emptySerial(&el->contactedSentPeers.peersSerials[i])
	    && (!cmpSerial(&el->contactedSentPeers.peersSerials[i], &myGlobals.otherHostEntry->hostSerial))
	   || (!emptySerial(&el->contactedRcvdPeers.peersSerials[i])
	       && (!cmpSerial(&el->contactedRcvdPeers.peersSerials[i], &myGlobals.otherHostEntry->hostSerial))))) {
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
		      sendString("<CENTER>\n<TABLE BORDER=0><TR><TD "TD_BG" VALIGN=TOP>\n");

		      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=100%>"
				 "<TR "TR_ON" "DARK_BG"><TH "TH_BG">Sent To</TH>"
				 "<TH "TH_BG">IP Address</TH></TR>\n");
		  }

		  if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
			      "<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;</TD></TR>\n",
			      getRowColor(), makeHostLink(el2, 0, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			      el2->hostNumIpAddress) < 0)
		      BufferTooShort();

		  sendString(buf);
		  numEntries++;
	      }
	  }

      if(numEntries > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Total Contacts</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%lu</TD></TR>\n",
		    getRowColor(), (unsigned long)el->totContactedSentPeers) < 0)
	  BufferTooShort();
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
		sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1>"
			   "<TR "TR_ON" "DARK_BG"><TH "TH_BG">Received From</TH>"
			   "<TH "TH_BG">IP Address</TH></TR>\n");
	      }

	      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
			  "<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;</TD></TR>\n",
			  getRowColor(), makeHostLink(el2, 0, 0, 0, hostLinkBuf, sizeof(hostLinkBuf)),
			  el2->hostNumIpAddress) < 0)
		BufferTooShort();

	      sendString(buf);
	      numEntries++;
	    }
	  }


      if(numEntries > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Total Contacts</TH>"
		    "<TD "TD_BG" ALIGN=RIGHT>%lu</TD></TR>\n",
		    getRowColor(), (unsigned long)el->totContactedRcvdPeers) < 0)
	  BufferTooShort();
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
  case FLAG_FLAG_STATE_SYN_ACK:
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
   Warning     1
   Error       2!
*/

u_short isHostHealthy(HostTraffic *el) {
  u_char riskFactor = 0;

  if(hasWrongNetmask(el)) {
    if(riskFactor < 1) riskFactor = 1;
  }

  if((el->totContactedSentPeers > CONTACTED_PEERS_THRESHOLD)
     || (el->totContactedRcvdPeers > CONTACTED_PEERS_THRESHOLD)) {
    /* Mail/DNS/HTTP server usually contact several hosts */
    if(!(isSMTPhost(el) || nameServerHost(el) || isHTTPhost(el))) {
      if(riskFactor < 1) riskFactor = 1;
    }
  }

  if(hasDuplicatedMac(el)) {
    if(riskFactor < 2) riskFactor = 2;
  }

  if(hasSentIpDataOnZeroPort(el)) {
    if(riskFactor < 2) riskFactor = 2;
  }

  if((el->secHostPkts != NULL)
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
	 || (el->secHostPkts->malformedPktsRcvd.value.value > 0))) {
    if(riskFactor < 1) riskFactor = 1;
  }

  return(riskFactor);
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
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s "
		"<IMG ALT=\"High Risk\" SRC=/Risk_high.gif> "
		"<IMG ALT=\"Medium Risk\" SRC=/Risk_medium.gif> "
		"<IMG  ALT=\"Low Risk\" SRC=/Risk_low.gif>"
		"</TH><TD "TD_BG" ALIGN=RIGHT NOWRAP><OL>", getRowColor(),
		"Network Healthness") < 0) BufferTooShort();
    sendString(buf);

    if(hasWrongNetmask(el))
      sendString("<LI><IMG ALT=\"Medium Risk\" SRC=/Risk_medium.gif><A HREF=/" CONST_NTOP_HELP_HTML "#1>"
		 "Wrong network mask or bridging enabled</A>\n");

    if(hasDuplicatedMac(el))
      sendString("<LI><IMG ALT=\"High Risk\" SRC=/Risk_high.gif><A HREF=/" CONST_NTOP_HELP_HTML "#2>"
		 "Duplicated MAC found for this IP address (spoofing?)</A>\n");

    if(hasSentIpDataOnZeroPort(el))
      sendString("<LI><IMG ALT=\"High Risk\" SRC=/Risk_high.gif><A HREF=/" CONST_NTOP_HELP_HTML "#3>"
		 "Traffic on suspicious IP ports</A>\n");

    if((el->totContactedSentPeers > CONTACTED_PEERS_THRESHOLD)
       || (el->totContactedRcvdPeers > CONTACTED_PEERS_THRESHOLD)) {
      sendString("<LI><IMG ALT=\"Medium Risk\" SRC=/Risk_medium.gif><A HREF=/" CONST_NTOP_HELP_HTML "#4>"
		 "Suspicious activities: too many host contacts</A>\n");
    }

    if((el->secHostPkts != NULL)
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
	   || (el->secHostPkts->malformedPktsRcvd.value.value > 0))) {
      sendString("<LI><IMG ALT=\"Medium Risk\" SRC=/Risk_medium.gif><A HREF=/" CONST_NTOP_HELP_HTML "#5>"
		 "Unexpected packets (e.g. traffic to closed port or connection reset)</A>:<br>\n");
      if(el->secHostPkts->synFinPktsSent.value.value > 0) sendString("(Sent:syn-fin)&nbsp;");
      if(el->secHostPkts->rstPktsRcvd.value.value > 0) sendString("(Rcvd:rst)&nbsp;");
      if(el->secHostPkts->ackXmasFinSynNullScanSent.value.value > 0) sendString("(Sent:xmas)&nbsp;");
      if(el->secHostPkts->rejectedTCPConnRcvd.value.value > 0) sendString("(Rcvd:rejected)&nbsp;");
      if(el->secHostPkts->udpToClosedPortRcvd.value.value > 0) sendString("(Sent:udp to closed)&nbsp;");
      if(el->secHostPkts->udpToDiagnosticPortSent.value.value > 0) sendString("(Sent:udp to diag)&nbsp;");
      if(el->secHostPkts->tinyFragmentSent.value.value > 0) sendString("(Sent:Tiny frag)&nbsp;");
      if(el->secHostPkts->icmpFragmentSent.value.value > 0) sendString("(Sent:icmp frag)&nbsp;");
      if(el->secHostPkts->overlappingFragmentSent.value.value > 0) sendString("(Sent: overlapfrag)&nbsp;");
      if(el->secHostPkts->closedEmptyTCPConnSent.value.value > 0) sendString("(Sent:closed-empty)&nbsp;");
      if(el->secHostPkts->icmpPortUnreachRcvd.value.value > 0) sendString("(Rcvd:port unreac)&nbsp;");
      if(el->secHostPkts->icmpHostNetUnreachRcvd.value.value > 0) sendString("(Rcvd:hostnet unreac)&nbsp;");
      if(el->secHostPkts->icmpProtocolUnreachRcvd.value.value > 0) sendString("(Rcvd:proto unreac)&nbsp;");
      if(el->secHostPkts->icmpAdminProhibitedRcvd.value.value > 0) sendString("(Rcvd:admin prohib)&nbsp;");
      if(el->secHostPkts->malformedPktsRcvd.value.value > 0) sendString("(Rcvd:malformed)&nbsp;");
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

    if(snprintf(buf, sizeof(buf), "%s&nbsp;[", list->userName) < 0)
      BufferTooShort();
    sendString(buf);

    if(FD_ISSET(BITFLAG_POP_USER, &(list->userFlags))) sendString("&nbsp;POP&nbsp;");
    if(FD_ISSET(BITFLAG_IMAP_USER, &(list->userFlags))) sendString("&nbsp;IMAP&nbsp;");
    if(FD_ISSET(BITFLAG_SMTP_USER, &(list->userFlags))) sendString("&nbsp;SMTP&nbsp;");
    if(FD_ISSET(BITFLAG_P2P_USER, &(list->userFlags))) sendString("&nbsp;P2P&nbsp;");
    if(FD_ISSET(BITFLAG_FTP_USER, &(list->userFlags))) sendString("&nbsp;FTP&nbsp;");
    if(FD_ISSET(BITFLAG_MESSENGER_USER, &(list->userFlags))) sendString("&nbsp;MSG&nbsp;");

    sendString("]\n");
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
     || gatewayHost(el)
     || isSMTPhost(el) || isIMAPhost(el) || isPOPhost(el)
     || isDirectoryHost(el)
     || isFTPhost(el)
     || isHTTPhost(el)
     || isWINShost(el)
     || isDHCPClient(el) || isDHCPServer(el)
     ) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>", getRowColor(), "Host Type") < 0) BufferTooShort();
    sendString(buf);

    if(isServer(el))           sendString("Server<BR>\n");
    if(isWorkstation(el))      sendString("Workstation<BR>\n");
    if(isMasterBrowser(el))    sendString("Master Browser<BR>\n");
    if(isPrinter(el))          sendString("Printer&nbsp;<IMG ALT=Printer SRC=\"/printer.gif\" BORDER=0><BR>\n");
    if(isBridgeHost(el))       sendString("Layer-2 Switch/Bridge <IMG ALT=Bridge SRC=\"/bridge.gif\" BORDER=0><BR>\n");

    if(nameServerHost(el))     sendString("&nbsp;<IMG ALT=\"DNS Server\" SRC=\"/dns.gif\" BORDER=0>&nbsp;Name Server<BR>\n");
    if(isNtpServer(el))        sendString("&nbsp;<IMG ALT=\"NTP Server\" SRC=\"/clock.gif\" BORDER=0>&nbsp;NTP Server<BR>\n");
    if(gatewayHost(el))        sendString("Gateway&nbsp;<IMG ALT=Router SRC=\"/router.gif\" BORDER=0>&nbsp;<BR>\n");
    if(isSMTPhost(el))         sendString("SMTP Server&nbsp;<IMG ALT=\"Mail Server (SMTP)\"  SRC=\"/mail.gif\" BORDER=0>&nbsp;<BR>\n");
    if(isPOPhost(el))          sendString("POP Server<BR>\n");
    if(isIMAPhost(el))         sendString("IMAP Server<BR>\n");
    if(isDirectoryHost(el))    sendString("Directory Server<BR>\n");
    if(isFTPhost(el))          sendString("FTP Server<BR>\n");
    if(isHTTPhost(el))         sendString("HTTP Server&nbsp;<IMG ALT=\"HTTP Server\" SRC=\"/web.gif\" BORDER=0><BR>\n");
    if(isWINShost(el))         sendString("WINS Server<BR>\n");

    if(isDHCPClient(el))       sendString("BOOTP/DHCP Client&nbsp;<IMG ALT=\"DHCP Client\" SRC=\"/bulb.gif\" BORDER=0><BR>\n");
    if(isDHCPServer(el))       sendString("BOOTP/DHCP Server&nbsp;<IMG ALT=\"DHCP Server\" SRC=\"/antenna.gif\" BORDER=0>&nbsp;<BR>\n");

    sendString("</TD></TR>");
  }
}

/* ************************************ */

void printHostDetailedInfo(HostTraffic *el, int actualDeviceId) {
  char buf[LEN_GENERAL_WORK_BUFFER], buf1[64], buf2[128], sniffedName[MAXDNAME], osBuf[128];
  float percentage;
  Counter total;
  int printedHeader, i;
  char *dynIp, *multihomed;
  u_short as=0;
  HostTraffic *theHost, tmpEl;
  char formatBuf[32], formatBuf1[32], formatBuf2[32], hostLinkBuf[LEN_GENERAL_WORK_BUFFER];

  accessAddrResMutex("printAllSessionsHTML");

  buf1[0]=0;
  if(getSniffedDNSName(el->hostNumIpAddress, sniffedName, sizeof(sniffedName))) {
    if(el->hostSymIpAddress[0] == '\0' || strcmp(sniffedName, el->hostSymIpAddress))
      snprintf(buf1, sizeof(buf1), " (%s)", sniffedName);
  }

  if((el->hostSymIpAddress[0] != '\0') && (strcmp(el->hostSymIpAddress, el->hostNumIpAddress))) {
    if(snprintf(buf, sizeof(buf), "Info about "
		" <A HREF=\"http://%s/\" TARGET=\"_blank\" "
                "TITLE=\"Link to web server on host, IF available\">%s %s</A>\n",
                el->hostSymIpAddress,
		el->hostSymIpAddress, buf1) < 0)
      BufferTooShort();

    snprintf(buf2, sizeof(buf2), "Info about %s", el->hostSymIpAddress);
  } else if(el->hostNumIpAddress[0] != '\0') {
    if(snprintf(buf, sizeof(buf), "Info about "
		" <A HREF=\"http://%s%s%s/\" TARGET=\"_blank\" "
                "TITLE=\"Link to web server on host, if available\">%s %s</A>\n",
                el->hostIpAddress.hostFamily == AF_INET6 ? "[" : "",
		el->hostNumIpAddress,
                el->hostIpAddress.hostFamily == AF_INET6 ? "]" : "",
		el->hostNumIpAddress, buf1) < 0)
      BufferTooShort();

    snprintf(buf2, sizeof(buf2), "Info about %s", el->hostNumIpAddress);
  } else {
    if(snprintf(buf, sizeof(buf), "Info about %s", el->ethAddressString) < 0)
      BufferTooShort();

    snprintf(buf2, sizeof(buf2), "Info about %s", el->ethAddressString);
  }

  releaseAddrResMutex();
  printHTMLheader(buf2, buf, 0);
  sendString("<CENTER>\n<P>"TABLE_ON"<TABLE BORDER=1 WIDTH=80%%>\n");

  if(el->hostNumIpAddress[0] != '\0') {
    char *countryIcon, *hostType;

    accessAddrResMutex("printAllSessions-2");

    countryIcon = getHostCountryIconURL(el);

    if(broadcastHost(el)) hostType = "broadcast";
    else if(multicastHost(el)) hostType = "multicast";
    else hostType = "unicast";

    if(isDHCPClient(el))
      dynIp = "/dynamic";
    else
      dynIp = "";

    if(isMultihomed(el) && (!broadcastHost(el)))
      multihomed = "&nbsp;-&nbsp;multihomed&nbsp;<IMG ALT=\"Multihomed Host\" SRC=/multihomed.gif BORDER=0>";
    else
      multihomed = "";

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;%s&nbsp;[%s%s%s]",
		getRowColor(),
		"IP&nbsp;Address",
		el->hostNumIpAddress,
		countryIcon, hostType, dynIp, multihomed) < 0)
      BufferTooShort();
    sendString(buf);

    sendString("</TD></TR>\n");

    if(isMultihomed(el) && (!broadcastHost(el))) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD ALIGN=RIGHT>&nbsp;<OL>",
		  getRowColor(), "Multihomed Addresses") < 0)
	BufferTooShort();
      sendString(buf);

      for(theHost=getFirstHost(actualDeviceId);
	  theHost != NULL; theHost = getNextHost(actualDeviceId, theHost)) {
	if((theHost != el)
	   && (memcmp(theHost->ethAddress, el->ethAddress, LEN_ETHERNET_ADDRESS) == 0)) {
	  if(snprintf(buf, sizeof(buf), "<LI><A HREF=/%s.html>%s</A>",
		      theHost->hostNumIpAddress, theHost->hostNumIpAddress) < 0)
	    BufferTooShort();
	  sendString(buf);
	}
      } /* for */

      sendString("</TD></TR>");
    }

    if((el->protocolInfo != NULL) && (el->protocolInfo->dhcpStats != NULL)) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>",
		  getRowColor(), "DHCP Information") < 0)
	BufferTooShort();
      sendString(buf);

      sendString("<TD "TD_BG"><TABLE BORDER WIDTH=100%>\n");

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n", getRowColor(), "DHCP Server",
		  _intoa(el->protocolInfo->dhcpStats->dhcpServerIpAddress, buf1, sizeof(buf1))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n", getRowColor(), "Previous IP Address",
		  _intoa(el->protocolInfo->dhcpStats->previousIpAddress, buf1, sizeof(buf1))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n",
		  getRowColor(), "Address Assigned on",
		  formatTime(&(el->protocolInfo->dhcpStats->assignTime), 1, formatBuf, sizeof(formatBuf))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n",
		  getRowColor(), "To be Renewed Before",
		  formatTime(&(el->protocolInfo->dhcpStats->renewalTime), 1, formatBuf, sizeof(formatBuf))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n",
		  getRowColor(), "Lease Ends on",
		  formatTime(&(el->protocolInfo->dhcpStats->leaseTime), 1, formatBuf, sizeof(formatBuf))) < 0)
	BufferTooShort();
      sendString(buf);


      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">DHCP Packets</TH>"
		  "<TH "TH_BG" ALIGN=CENTER>Sent</TH><TH "TH_BG" ALIGN=RIGHT>Rcvd</TH></TR>\n",
		  getRowColor()) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Discover",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_DISCOVER_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_DISCOVER_MSG].value, formatBuf1, sizeof(formatBuf1))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Offer",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_OFFER_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_OFFER_MSG].value, formatBuf1, sizeof(formatBuf1))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Request",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_REQUEST_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_REQUEST_MSG].value, formatBuf1, sizeof(formatBuf1))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Decline",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_DECLINE_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_DECLINE_MSG].value, formatBuf1, sizeof(formatBuf1))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Ack",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_ACK_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_ACK_MSG].value, formatBuf1, sizeof(formatBuf1))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Nack",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_NACK_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_NACK_MSG].value, formatBuf1, sizeof(formatBuf1))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Release",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_RELEASE_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_RELEASE_MSG].value, formatBuf1, sizeof(formatBuf1))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Inform",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_INFORM_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_INFORM_MSG].value, formatBuf1, sizeof(formatBuf1))) < 0)
	BufferTooShort();
      sendString(buf);


      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Unknown Msg",
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgSent[FLAG_DHCP_UNKNOWN_MSG].value, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->protocolInfo->dhcpStats->dhcpMsgRcvd[FLAG_DHCP_UNKNOWN_MSG].value, formatBuf1, sizeof(formatBuf1))) < 0)
	BufferTooShort();
      sendString(buf);

      sendString("</TABLE>"TABLE_OFF"</TD></TR>\n");
    }
  }

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
	      "<TD "TD_BG" ALIGN=RIGHT>"
	      "%s&nbsp;&nbsp;-&nbsp;&nbsp;%s&nbsp;[%s]</TD></TR>\n",
	      getRowColor(),
	      "First/Last&nbsp;Seen",
	      formatTime(&(el->firstSeen), 1, formatBuf, sizeof(formatBuf)),
	      formatTime(&(el->lastSeen), 1, formatBuf1, sizeof(formatBuf1)),
	      formatSeconds(el->lastSeen - el->firstSeen, formatBuf2, sizeof(formatBuf2))) < 0)
    BufferTooShort();
  sendString(buf);

  if(el->hostAS != 0) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"<A HREF=\"http://ws.arin.net/cgi-bin/whois.pl?queryinput=AS%d\">%d</A></TD></TR>\n",
		getRowColor(), "Autonomous System", el->hostAS, el->hostAS) < 0) BufferTooShort();
    sendString(buf);
  }

  if(el->fullDomainName && (el->fullDomainName[0] != '\0')) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%s</TD></TR>\n", getRowColor(),
		"Domain", el->fullDomainName) < 0) BufferTooShort();
    sendString(buf);
  }

  if((el->ethAddressString[0] != '\0')
     && strcmp(el->ethAddressString, "00:00:00:00:00:00")
     && strcmp(el->ethAddressString, "00:01:02:03:04:05") /* dummy address */) {
    char *vendorName;

    if(isMultihomed(el)) {
      char *symMacAddr, symLink[32];
      char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

      symMacAddr = etheraddr_string(el->ethAddress, etherbuf);
      strcpy(symLink, symMacAddr);
      for(i=0; symLink[i] != '\0'; i++)
	if(symLink[i] == ':')
	  symLink[i] = '_';

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<A HREF=%s.html>%s</A>%s</TD></TR>\n",
		  getRowColor(), "Main Host MAC Address",
		  symLink, symMacAddr,
		  myGlobals.separator /* it avoids empty cells not to be rendered */) < 0)
	BufferTooShort();
      sendString(buf);

    } else {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "MAC&nbsp;Address <IMG ALT=\"Network Interface Card (NIC)\" SRC=/card.gif BORDER=0>",
		  el->ethAddressString,
		  myGlobals.separator /* it avoids empty cells not to be rendered */) < 0)
	BufferTooShort();
      sendString(buf);
    }

    vendorName = getVendorInfo(el->ethAddress, 1);
    if(vendorName[0] != '\0') {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT NOWRAP>%s%s</TD></TR>\n",
		  getRowColor(), "Nw&nbsp;Board&nbsp;Vendor",
		  vendorName,
		  myGlobals.separator /* it avoids empty cells not to be rendered */) < 0)
	BufferTooShort();
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

    symMacAddr = etheraddr_string(el->lastEthAddress, etherbuf);
    strcpy(symLink, symMacAddr);
    for(i=0; symLink[i] != '\0'; i++)
      if(symLink[i] == ':')
	symLink[i] = '_';

    if(!myGlobals.dontTrustMACaddr) {
      if(snprintf(shortBuf, sizeof(shortBuf), "<A HREF=%s.html>%s</A>", symLink, symMacAddr) < 0)
	BufferTooShort();
    } else {
      strcpy(shortBuf, symMacAddr);
    }

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%s"
		"%s</TD></TR>\n",
		getRowColor(),
		"Last MAC Address/Router <IMG ALT=\"Network Interface Card (NIC)/Router\" SRC=/card.gif BORDER=0>",
		shortBuf,
		myGlobals.separator /* it avoids empty cells not to be rendered */) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->hostNumIpAddress[0] != '\0') {
    setHostFingerprint(el);

    if((el->fingerprint != NULL) && (el->fingerprint[0] == ':') && (strlen(el->fingerprint) > 2)) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "OS&nbsp;Name",
		  getOSFlag(el, NULL, 1, osBuf, sizeof(osBuf)),
		  myGlobals.separator /* it avoids empty cells not to be rendered */) < 0)
	BufferTooShort();
      sendString(buf);
    }
  }

  if((as = getHostAS(el)) != 0) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%d</TD></TR>\n", getRowColor(), "Origin&nbsp;AS", as) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->vlanId != -1) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%d</TD></TR>\n", getRowColor(), "VLAN&nbsp;Id", el->vlanId) < 0)
      BufferTooShort();
      sendString(buf);
  }

  if(el->nonIPTraffic) {
    if((el->nonIPTraffic->nbHostName != NULL) || (el->nonIPTraffic->nbDomainName != NULL)) {
      if(el->nonIPTraffic->nbAccountName) {
	if(el->nonIPTraffic->nbDomainName != NULL) {
	  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		      "%s@%s&nbsp;[domain %s] (%s) %s</TD></TR>\n",
		      getRowColor(), "NetBios&nbsp;Name",
		      el->nonIPTraffic->nbAccountName, el->nonIPTraffic->nbHostName, el->nonIPTraffic->nbDomainName,
		      getNbNodeType(el->nonIPTraffic->nbNodeType),
		      el->nonIPTraffic->nbDescr ? el->nonIPTraffic->nbDescr : "") < 0)
	    BufferTooShort();
	} else {
	  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		      "%s@%s (%s) %s</TD></TR>\n",
		      getRowColor(), "NetBios&nbsp;Name",
		      el->nonIPTraffic->nbAccountName, el->nonIPTraffic->nbHostName,
		      getNbNodeType(el->nonIPTraffic->nbNodeType),
		      el->nonIPTraffic->nbDescr ? el->nonIPTraffic->nbDescr : "") < 0)
	    BufferTooShort();
	}
      } else {
	if(el->nonIPTraffic->nbDomainName != NULL) {
	  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		      "%s&nbsp;[domain %s] (%s) %s</TD></TR>\n",
		      getRowColor(), "NetBios&nbsp;Name",
		      el->nonIPTraffic->nbHostName != NULL ? el->nonIPTraffic->nbHostName : "",
		      el->nonIPTraffic->nbDomainName,
		      getNbNodeType(el->nonIPTraffic->nbNodeType),
		      el->nonIPTraffic->nbDescr ? el->nonIPTraffic->nbDescr : "") < 0)
	    BufferTooShort();
	} else {
	  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		      "%s (%s) %s</TD></TR>\n",
		      getRowColor(), "NetBios&nbsp;Name",
		      el->nonIPTraffic->nbHostName,
		      getNbNodeType(el->nonIPTraffic->nbNodeType),
		      el->nonIPTraffic->nbDescr ? el->nonIPTraffic->nbDescr : "") < 0)
	    BufferTooShort();
	}
      }

      sendString(buf);
    } else if(el->nonIPTraffic->nbHostName != NULL) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s&nbsp;(%s) %s</TD></TR>\n",
		  getRowColor(), "NetBios&nbsp;Name",
		  el->nonIPTraffic->nbHostName, getNbNodeType(el->nonIPTraffic->nbNodeType),
		  el->nonIPTraffic->nbDescr ? el->nonIPTraffic->nbDescr : "") < 0)
	BufferTooShort();
      sendString(buf);
    }

    if(el->nonIPTraffic->atNetwork != 0) {
      char *nodeName = el->nonIPTraffic->atNodeName;

      if(nodeName == NULL) nodeName = "";

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s&nbsp;\n",
		  getRowColor(), "AppleTalk&nbsp;Name",
		  nodeName) < 0) BufferTooShort();
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

      if(snprintf(buf, sizeof(buf), "[%d.%d]</TD></TR>\n",
		  el->nonIPTraffic->atNetwork, el->nonIPTraffic->atNode) < 0)
	BufferTooShort();
      sendString(buf);
    }

    if(el->nonIPTraffic->ipxHostName != NULL) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>"
		  "%s&nbsp;[", getRowColor(), "IPX&nbsp;Name",
		  el->nonIPTraffic->ipxHostName) < 0)
	BufferTooShort();
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
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s</TD></TR>\n", getRowColor(),
		  "Host&nbsp;Location",
		  "Local (inside specified/local subnet)") < 0)
	BufferTooShort();
    } else {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s</TD></TR>\n", getRowColor(),
		  "Host&nbsp;Location",
		  "Remote (outside specified/local subnet)") < 0)
	BufferTooShort();
    }
    sendString(buf);
  }

  if(el->minTTL > 0) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%d:%d&nbsp;[~%d&nbsp;hop(s)]</TD></TR>\n",
		getRowColor(), "IP&nbsp;TTL&nbsp;(Time to Live)",
		el->minTTL, el->maxTTL, guessHops(el)) < 0) BufferTooShort();
    sendString(buf);
  }

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s"
	      "</TH><TD "TD_BG" ALIGN=RIGHT>"
	      "%s/%s Pkts/%s Retran. Pkts [%d%%]</TD></TR>\n",
	      getRowColor(), "Total&nbsp;Data&nbsp;Sent",
	      formatBytes(el->bytesSent.value, 1, formatBuf, sizeof(formatBuf)),
	      formatPkts(el->pktSent.value, formatBuf1, sizeof(formatBuf1)),
	      formatPkts(el->pktDuplicatedAckSent.value, formatBuf2, sizeof(formatBuf2)),
	      (int)(((float)el->pktDuplicatedAckSent.value*100)/(float)(el->pktSent.value+1))
	      ) < 0) BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
	      "%s Pkts</TD></TR>\n",
	      getRowColor(), "Broadcast&nbsp;Pkts&nbsp;Sent",
	      formatPkts(el->pktBroadcastSent.value, formatBuf, sizeof(formatBuf))) < 0) BufferTooShort();
  sendString(buf);

  if(el->routedTraffic != NULL) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%s/%s Pkts</TD></TR>\n",
		getRowColor(), "Routed Traffic",
		formatBytes(el->routedTraffic->routedBytes.value, 1, formatBuf, sizeof(formatBuf)),
		formatPkts(el->routedTraffic->routedPkts.value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if((el->pktMulticastSent.value > 0) || (el->pktMulticastRcvd.value > 0)) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>",
		getRowColor(), "Multicast&nbsp;Traffic") < 0) BufferTooShort();
    sendString(buf);

    if(el->pktMulticastSent.value > 0) {
      if(snprintf(buf, sizeof(buf), "Sent&nbsp;%s/%s&nbsp;Pkts&nbsp;-",
		  formatBytes(el->bytesMulticastSent.value, 1, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->pktMulticastSent.value, formatBuf1, sizeof(formatBuf1))) < 0) BufferTooShort();
      sendString(buf);
    }

    if(el->pktMulticastRcvd.value > 0) {
      if(snprintf(buf, sizeof(buf), "Rcvd&nbsp;%s/%s&nbsp;Pkts",
		  formatBytes(el->bytesMulticastRcvd.value, 1, formatBuf, sizeof(formatBuf)),
		  formatPkts(el->pktMulticastRcvd.value, formatBuf1, sizeof(formatBuf1))) < 0) BufferTooShort();
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
			      "Local", "Rem", -1, percentage);

    if(el->bytesSent.value > 0) {
      percentage = (((float)el->ipBytesSent.value*100)/el->bytesSent.value);
      printTableEntryPercentage(buf, sizeof(buf), "IP&nbsp;vs.&nbsp;Non-IP&nbsp;Sent",
				"IP", "Non-IP", -1, percentage);
    }
  }

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s"
	      "</TH><TD "TD_BG" ALIGN=RIGHT>"
	      "%s/%s Pkts/%s Retran. Pkts [%d%%]</TD></TR>\n",
	      getRowColor(), "Total&nbsp;Data&nbsp;Rcvd",
	      formatBytes(el->bytesRcvd.value, 1, formatBuf, sizeof(formatBuf)),
	      formatPkts(el->pktRcvd.value, formatBuf1, sizeof(formatBuf1)),
	      formatPkts(el->pktDuplicatedAckRcvd.value, formatBuf2, sizeof(formatBuf2)),
	      (int)((float)(el->pktDuplicatedAckRcvd.value*100)/(float)(el->pktRcvd.value+1))) < 0)
    BufferTooShort();
  sendString(buf);

  if(el->bytesRcvd.value == 0)
    percentage = 0;
  else
    percentage = 100 - (((float)el->bytesRcvdFromRem.value*100)/el->bytesRcvd.value);

    if(el->hostNumIpAddress[0] != '\0')
      printTableEntryPercentage(buf, sizeof(buf), "Data&nbsp;Rcvd&nbsp;Stats",
				"Local", "Rem", -1, percentage);

  if(el->bytesRcvd.value > 0) {
    percentage = (((float)el->ipBytesRcvd.value*100)/el->bytesRcvd.value);
    printTableEntryPercentage(buf, sizeof(buf), "IP&nbsp;vs.&nbsp;Non-IP&nbsp;Rcvd",
			      "IP", "Non-IP", -1, percentage);
  }

  total = el->pktSent.value+el->pktRcvd.value;
  if(total > 0) {
    percentage = ((float)el->pktSent.value*100)/((float)total);
    printTableEntryPercentage(buf, sizeof(buf), "Sent&nbsp;vs.&nbsp;Rcvd&nbsp;Pkts",
			      "Sent", "Rcvd", -1, percentage);
  }

  total = el->bytesSent.value+el->bytesRcvd.value;
  if(total > 0) {
    percentage = ((float)el->bytesSent.value*100)/((float)total);
    printTableEntryPercentage(buf, sizeof(buf), "Sent&nbsp;vs.&nbsp;Rcvd&nbsp;Data",
			      "Sent", "Rcvd", -1, percentage);
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
	    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">"
			"Used&nbsp;Subnet&nbsp;Routers</TH><TD "TD_BG" ALIGN=RIGHT>\n",
			getRowColor()) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	  printedHeader++;

	  if(printedHeader > 1) sendString("<BR>");

	  if(snprintf(buf, sizeof(buf), "%s\n",
		      makeHostLink(router, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				   hostLinkBuf, sizeof(hostLinkBuf))) < 0)
	    BufferTooShort();
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
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">"
		"Known&nbsp;Users&nbsp;<IMG ALT=Users SRC=/users.gif BORDER=0></TH><TD "TD_BG" ALIGN=RIGHT>\n",
		getRowColor()) < 0)
      BufferTooShort();
    sendString(buf);

    printUserList(el);
    sendString("<br>\n</TD></TR>\n");
  }

  /* **************************** */

  if((el->hostNumIpAddress[0] != '\0')
     && (!subnetPseudoLocalHost(el))
     && (!multicastHost(el))
     && (!privateIPAddress(el))) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"[ <A HREF=\"http://www.radb.net/cgi-bin/radb/whois.cgi?obj=%s\">Whois</A> ]</TD></TR>\n",
		getRowColor(), "Further Host Information", el->hostNumIpAddress) < 0)
      BufferTooShort();
    sendString(buf);

    if(myGlobals.mapperURL) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<IMG SRC=\"%s?host=%s\" WIDTH=320 HEIGHT=200></TD></TR>\n",
		  getRowColor(),
		  "Host Physical Location",
		  myGlobals.mapperURL, el->hostNumIpAddress) < 0)
      BufferTooShort();
      sendString(buf);
    }
  }

  /* RRD */
  if(el->hostNumIpAddress[0] != '\0') {
    struct stat statbuf;
    char *key;

    if((!myGlobals.dontTrustMACaddr) && subnetPseudoLocalHost(el) 
       && (el->ethAddressString[0] != '\0') /* Really safe in case a host that was supposed to be local isn't really so*/)
      key = el->ethAddressString;
    else
      key = el->hostNumIpAddress;

    /* Do NOT add a '/' at the end of the path because Win32 will complain about it */
    snprintf(buf, sizeof(buf), "%s/interfaces/%s/hosts/%s",
	     myGlobals.rrdPath != NULL ? myGlobals.rrdPath : ".",
	     myGlobals.device[myGlobals.actualReportDeviceId].humanFriendlyName,
	     dotToSlash(key));

    if(stat(buf, &statbuf) == 0) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
                  "[ <A HREF=\"/plugins/rrdPlugin?action=list&key=interfaces/%s/hosts/%s&title=host%%20%s\">"
                   "<IMG BORDER=0 SRC=/graph.gif TITLE=\"link to rrd graphs\"></A> ]</TD></TR>\n",
		  getRowColor(), "RRD Stats",
                  myGlobals.device[myGlobals.actualReportDeviceId].humanFriendlyName,
                  dotToSlash(key),
		  el->hostSymIpAddress[0] != '\0' ? el->hostSymIpAddress : el->hostNumIpAddress) < 0)
	BufferTooShort();
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
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG">%s</TH>"
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
		    ) < 0) BufferTooShort();
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
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG">%s</TH>"
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
		) < 0) BufferTooShort();
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
    sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=100%>\n<TR "TR_ON" "DARK_BG">"
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
    sendString("<P>"TABLE_ON"<TABLE BORDER=1 WIDTH=100%>\n<TR "TR_ON" "DARK_BG">"
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
		     float total, float percentage) {
  int int_perc;
  char formatBuf[32];

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

  switch(int_perc) {
  case 0:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT WIDTH=150 "DARK_BG">%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT WIDTH=50>%s</TD><TD "TD_BG" ALIGN=RIGHT WIDTH=50>0%%</TD>"
		"<TD "TD_BG" WIDTH=200>&nbsp;</TD></TR>\n",
		getRowColor(), label, formatKBytes(total, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    break;
  case 100:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT WIDTH=150 "DARK_BG">%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT WIDTH=50>%s</TD><TD "TD_BG" ALIGN=RIGHT WIDTH=50>100%%</TD>"
		"<TD ALIGN=CENTER WIDTH=200><IMG ALT=\"100%%\" ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=200 HEIGHT=12>"
		"</TD></TR>\n",
		getRowColor(), label, formatKBytes(total, formatBuf, sizeof(formatBuf))) < 0)
      BufferTooShort();
    break;
  default:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT WIDTH=150 "DARK_BG">%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT WIDTH=50>%s</TD><TD "TD_BG" ALIGN=RIGHT WIDTH=50>%d%%</TD>"
		"<TD "TD_BG" WIDTH=200><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=200>"
		"<TR "TR_ON"><TD><IMG ALIGN=MIDDLE ALT=\"%d%%\" SRC=/gauge.jpg WIDTH=\"%d\" HEIGHT=12>"
		"</TD><TD "TD_BG" ALIGN=CENTER WIDTH=\"%d\" %s>"
		"<P>&nbsp;</TD></TR></TABLE>"TABLE_OFF"</TD></TR>\n",
		getRowColor(), label, formatKBytes(total, formatBuf, sizeof(formatBuf)), int_perc,
		int_perc, (200*int_perc)/100,
		(200*(100-int_perc))/100, getActualRowColor()) < 0)
      BufferTooShort();
  }

  sendString(buf);
}

/* ************************ */

char* buildHTMLBrowserWindowsLabel(int i, int j, u_short forIpTraffic) {
  static char buf[LEN_GENERAL_WORK_BUFFER];
  int idx = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts + j;
  char formatBuf[32], formatBuf1[32], formatBuf2[32], formatBuf3[32];

  accessAddrResMutex("buildHTMLBrowserWindowsLabel");

  if((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx] == NULL)
     || ((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value == 0)
	 && (myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value == 0)))
    buf[0]='\0';
  else if ((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value > 0)
	   && (myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value == 0)) {
    if(snprintf(buf, sizeof(buf), "(%s->%s)=%s/%s Pkts",
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostSymIpAddress,
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostSymIpAddress,
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value, 1, formatBuf, sizeof(formatBuf)),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsSent.value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
  } else if ((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value == 0)
	     && (myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value > 0)) {
    if(snprintf(buf, sizeof(buf), "(%s->%s)=%s/%s Pkts",
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostSymIpAddress,
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostSymIpAddress,
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value, 1, formatBuf, sizeof(formatBuf)),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsRcvd.value, formatBuf1, sizeof(formatBuf1))) < 0)
      BufferTooShort();
  } else {
    if(snprintf(buf, sizeof(buf), "(%s->%s)=%s/%s Pkts, (%s->%s)=%s/%s Pkts",
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostSymIpAddress,
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostSymIpAddress,
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value, 1, formatBuf, sizeof(formatBuf)),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsSent.value, formatBuf1, sizeof(formatBuf1)),
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostSymIpAddress,
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostSymIpAddress,
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value, 1, formatBuf2, sizeof(formatBuf2)),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsRcvd.value, formatBuf3, sizeof(formatBuf3))) < 0)
      BufferTooShort();
  }

  releaseAddrResMutex();
  return(buf);
}

/* *********************************** */

void printHostHourlyTrafficEntry(HostTraffic *el, int i,
				 Counter tcSent, Counter tcRcvd) {
  float pctg;
  char buf[LEN_GENERAL_WORK_BUFFER], formatBuf[32];

  if(el->trafficDistribution == NULL) return;

  if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
	      formatBytes(el->trafficDistribution->last24HoursBytesSent[i].value, 0, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

  if(tcSent > 0)
    pctg = (float)(el->trafficDistribution->last24HoursBytesSent[i].value*100)/(float)tcSent;
  else
    pctg = 0;

  if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, "<TD ALIGN=RIGHT %s>%.1f %%</TD>",
	   getBgPctgColor(pctg), pctg) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
	   formatBytes(el->trafficDistribution->last24HoursBytesRcvd[i].value, 0, formatBuf, sizeof(formatBuf))) < 0)
    BufferTooShort();
  sendString(buf);

 if(tcRcvd > 0)
    pctg = (float)(el->trafficDistribution->last24HoursBytesRcvd[i].value*100)/(float)tcRcvd;
  else
    pctg = 0;

  if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, "<TD ALIGN=RIGHT %s>%.1f %%</TD></TR>",
	      getBgPctgColor(pctg), pctg) < 0)
    BufferTooShort();
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

  snprintf(buf, LEN_GENERAL_WORK_BUFFER,
 	   "<CENTER>\n"
 	   "<P><IMG ALT=Warning SRC=/warning.gif>\n"
 	   "<P><FONT COLOR=\"#FF0000\" SIZE=+1>%s</FONT>\n"
 	   "</CENTER>\n", text);
  sendString(buf);
}

/* ********************************** */

void printSectionTitle(char *text) {
  switch (myGlobals.capturePackets) {
      case FLAG_NTOPSTATE_RUN:
          break;
          ;;
      case FLAG_NTOPSTATE_STOPCAP:
          sendString("<CENTER><FONT FACE=\"Helvetica, Arial, Sans Serif\" SIZE=+1><B>"
                     "Packet capture stopped"
                     "</B></FONT></CENTER>");
          break;
          ;;
      case FLAG_NTOPSTATE_TERM:
          sendString("<CENTER><FONT FACE=\"Helvetica, Arial, Sans Serif\" SIZE=+1><B>"
                     "ntop stopped"
                     "</B></FONT></CENTER>");
          break;
          ;;
  }

  sendString("<CENTER>\n<H1><FONT FACE=\"Helvetica, Arial, Sans Serif\">");
  sendString(text);
  sendString("</FONT></H1><P>\n</CENTER>\n");
}

/* ******************************** */

static void printLocalHostsCharacterization(void) {
  u_int a=0, b=0, c=0, d=0, e=0, f=0, g=0, h=0, i=0, unhealthy=0, totHosts=0;
  HostTraffic *el;
  char buf[LEN_GENERAL_WORK_BUFFER], hostLinkBuf[LEN_GENERAL_WORK_BUFFER], headerSent = 0;

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if((broadcastHost(el) == 0) /* No broadcast addresses please */
       && (multicastHost(el) == 0) /* No multicast addresses please */
       && subnetPseudoLocalHost(el)) {
      totHosts++;

      if(isPrinter(el)
	 || isBridgeHost(el)
	 || nameServerHost(el) || isNtpServer(el)
	 || gatewayHost(el)
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
	  sendString("<p><hr><p>\n<CENTER>\n");
	  printHTMLheader("Hosts Characterization", NULL, 0);

	  sendString(""TABLE_ON"<TABLE BORDER=1>\n<TR "TR_ON" "DARK_BG"><TH "TH_BG">Host</TH>"
		     "<TH>Unhealthy<br>Host</TH>"
		     "<TH>L2 Switch<br>Bridge</TH>"
		     "<TH>Gateway</TH>"
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

	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH ALIGN=LEFT>%s</TH>",
		    getRowColor(),
		    makeHostLink(el, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				 hostLinkBuf, sizeof(hostLinkBuf))) < 0)
	  BufferTooShort();
	sendString(buf);

	if(isHostHealthy(el) != 0) { sendString("<TD ALIGN=CENTER>X</TD>"); unhealthy++; } else sendString("<TD>&nbsp;</TD>");
	if(isBridgeHost(el)) { sendString("<TD ALIGN=CENTER>X</TD>"); a++; } else sendString("<TD>&nbsp;</TD>");
	if(gatewayHost(el)) { sendString("<TD ALIGN=CENTER>X</TD>"); b++; } else sendString("<TD>&nbsp;</TD>");
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

  if(headerSent) {
    sendString("<TR><TH>Total</TH>");
    if(unhealthy > 0) {
      snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>%d [%.1f %%]</TD>", unhealthy, (float)(unhealthy*100)/(float)totHosts);
      sendString(buf);
    } else
      sendString("<TD>&nbsp;</TD>");
    if(a > 0) { snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", a); sendString(buf); } else sendString("<TD>&nbsp;</TD>");
    if(b > 0) { snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", b); sendString(buf); } else sendString("<TD>&nbsp;</TD>");
    if(c > 0) { snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", c); sendString(buf); } else sendString("<TD>&nbsp;</TD>");
    if(d > 0) { snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", d); sendString(buf); } else sendString("<TD>&nbsp;</TD>");
    if(e > 0) { snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", e); sendString(buf); } else sendString("<TD>&nbsp;</TD>");
    if(f > 0) { snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", f); sendString(buf); } else sendString("<TD>&nbsp;</TD>");
    if(g > 0) { snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", g); sendString(buf); } else sendString("<TD>&nbsp;</TD>");
    if(h > 0) { snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", h); sendString(buf); } else sendString("<TD>&nbsp;</TD>");
    if(i > 0) { snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>%d</TD>", i); sendString(buf); } else sendString("<TD>&nbsp;</TD>");
    sendString("</TABLE></CENTER>\n");
  }
}

/* ******************************** */

#define MAX_NUM_OS           256

void printLocalHostsStats(void) {
  u_int idx, numEntries=0, maxHosts;
  HostTraffic *el, **tmpTable;
  OsNumInfo theOSs[MAX_NUM_OS];
  int i;
  char buf[LEN_GENERAL_WORK_BUFFER], hostLinkBuf[LEN_GENERAL_WORK_BUFFER];

  memset(theOSs, 0, sizeof(theOSs));

  printHTMLheader("OS Summary", NULL, BITFLAG_HTML_NO_REFRESH);

  if(myGlobals.device[myGlobals.actualReportDeviceId].dummyDevice) {
    printFlagedWarning("<I>Local host statistics (OS fingerprinting) are not available for virtual interfaces</I>");
    printLocalHostsCharacterization();
    return;
  }

  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */
  tmpTable = (HostTraffic**)malloc(maxHosts*sizeof(HostTraffic*));
  memset(tmpTable, 0, maxHosts*sizeof(HostTraffic*));

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if((broadcastHost(el) == 0) /* No broadcast addresses please */
       && (multicastHost(el) == 0) /* No multicast addresses please */
       && (((el->hostNumIpAddress[0] != '\0') && (!addrnull(&el->hostIpAddress)) /* This host speaks IP */
	    && subnetPseudoLocalHost(el))
	   || ((el->fingerprint != NULL) && (el->fingerprint[0] == ':'))) /* This host does not speak IP but its
									     fingerprint has been computed */
       ) {

      if(el->fingerprint == NULL)   { continue; }
      if(el->fingerprint[0] != ':') setHostFingerprint(el);
      if(el->fingerprint[0] != ':') { continue; }
      if(strlen(el->fingerprint) < 3) { continue; } /* Too short */
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
  }

  myGlobals.columnSort = 0;
  qsort(tmpTable, numEntries, sizeof(HostTraffic*), cmpFctn);

  if(numEntries > 0) {
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1>\n<TR "TR_ON" "DARK_BG"><TH "TH_BG">Host</TH>");

    for(i=0; i<MAX_NUM_OS; i++) {
      if(theOSs[i].name == NULL)
	break;
      else {
	snprintf(buf, sizeof(buf), "<TH>%s</TH>", theOSs[i].name);
	sendString(buf);
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

	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH ALIGN=LEFT>%s</TH>",
		    getRowColor(),
		    makeHostLink(el, FLAG_HOSTLINK_TEXT_FORMAT, 0, 0, hostLinkBuf, sizeof(hostLinkBuf))) < 0)
	  BufferTooShort();
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
		  snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>[ %s ]</TD>", el->nonIPTraffic->nbDomainName);
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

    sendString("</TABLE><P>");

    /* ********************************** */

    qsort(theOSs, MAX_NUM_OS, sizeof(OsNumInfo), cmpOSFctn);

    sendString(""TABLE_ON"<TABLE BORDER=1>\n<TR "TR_ON" "DARK_BG"><TH "TH_BG">OS</TH><TH "TH_BG">Total</TH></TR>");

    for(i=0; i<MAX_NUM_OS; i++) {
      if(theOSs[i].name != NULL) {
	snprintf(buf, sizeof(buf), "<TR><TH ALIGN=left>%s</TH><TD ALIGN=RIGHT>%d</TD></TR>\n", 
		 theOSs[i].name, theOSs[i].num);
	sendString(buf);
	free(theOSs[i].name);
      }
    }

    sendString("</TABLE></CENTER>");
  } else
    printNoDataYet();

  free(tmpTable);

  printLocalHostsCharacterization();
}

/* ******************************************************** */

#ifdef CFG_MULTITHREADED
void printMutexStatus(int textPrintFlag, PthreadMutex *mutexId, char *mutexName) {
  char buf[LEN_GENERAL_WORK_BUFFER], buf2[64];
  struct tm t;

  if(mutexId->numLocks == 0) /* Mutex never used */
    return;
  memset(buf2, 0, sizeof(buf2));
  strftime(buf2, sizeof(buf2), "%c", localtime_r(&mutexId->lockTime, &t));
  if(textPrintFlag == TRUE) {
    if(myGlobals.disableMutexExtraInfo) {
        if(snprintf(buf, sizeof(buf),
                    "Mutex %s is %s, locked: %u times.\n",
                    mutexName, mutexId->isLocked ? "locked" : "unlocked",
                    mutexId->numLocks) < 0)
          BufferTooShort();
        sendString(buf);
    } else if(mutexId->lockAttemptLine > 0) {
        if(snprintf(buf, sizeof(buf),
                    "Mutex %s is %s.\n"
                    "     locked: %u times, last was at %s %s:%d(%d)\n"
                    "     blocked: at %s:%d%(%d)\n",
                    mutexName, mutexId->isLocked ? "locked" : "unlocked",
                    mutexId->numLocks,
                    buf2,
                    mutexId->lockFile, mutexId->lockLine, mutexId->lockPid,
                    mutexId->lockAttemptFile, mutexId->lockAttemptLine, mutexId->lockAttemptPid) < 0)
          BufferTooShort();
		    sendString(buf);

        if(snprintf(buf, sizeof(buf),
                    "     unlocked: %u times, last was %s:%d(%d)\n"
                    "     longest: %d sec from %s:%d\n",
                    mutexId->numReleases, mutexId->unlockFile, mutexId->unlockLine, mutexId->unlockPid,
                    mutexId->maxLockedDuration, mutexId->maxLockedDurationUnlockFile,
		    mutexId->maxLockedDurationUnlockLine) < 0)
          BufferTooShort();
    } else {
        if(snprintf(buf, sizeof(buf),
                    "Mutex %s, is %s.\n"
                    "     locked: %u times, last was at %s %s:%d(%d)\n"
                    "     unlocked: %u times, last was %s:%d(%d)\n"
                    "     longest: %d sec from %s:%d\n",
                    mutexName,
                    mutexId->isLocked ? "locked" : "unlocked",
                    mutexId->numLocks,
                    buf2,
                    mutexId->lockFile, mutexId->lockLine, mutexId->lockPid,
                    mutexId->numReleases,
                    mutexId->unlockFile, mutexId->unlockLine, mutexId->unlockPid,
                    mutexId->maxLockedDuration,
                    mutexId->maxLockedDurationUnlockFile,
                    mutexId->maxLockedDurationUnlockLine) < 0)
          BufferTooShort();
    }
  } else {
    if(myGlobals.disableMutexExtraInfo) {
        if(snprintf(buf, sizeof(buf),
                    "<TR><TH ALIGN=LEFT>%s</TH><TD ALIGN=CENTER>%s</TD>"
                    "<TD ALIGN=RIGHT>%u</TD><TD ALIGN=RIGHT>%u</TD></TR>\n",
                    mutexName,
                    mutexId->isLocked ? "<FONT COLOR=\"RED\">locked</FONT>" : "unlocked",
                    mutexId->numLocks, mutexId->numReleases) < 0)
          BufferTooShort();
    } else if (mutexId->lockAttemptLine > 0) {
        if(snprintf(buf, sizeof(buf),
                    "<TR><TH ALIGN=LEFT>%s</TH><TD ALIGN=CENTER>%s</TD>"
                    "<TD ALIGN=RIGHT>at %s %s:%d(%d)</TD>"
                    "<TD ALIGN=RIGHT>%s:%d(%d)</TD>"
                    "<TD ALIGN=RIGHT>%s:%d(%d)</TD>"
                    "<TD ALIGN=RIGHT>%u</TD><TD ALIGN=RIGHT>%u</TD>"
                    "<TD ALIGN=RIGHT>%d sec [%s:%d]</TD></TR>\n",
                    mutexName,
                    mutexId->isLocked ? "<FONT COLOR=\"RED\">locked</FONT>" : "unlocked",
                    buf2,
                    mutexId->lockFile, mutexId->lockLine, mutexId->lockPid,
                    mutexId->lockAttemptFile, mutexId->lockAttemptLine, mutexId->lockAttemptPid,
                    mutexId->unlockFile, mutexId->unlockLine, mutexId->unlockPid,
                    mutexId->numLocks, mutexId->numReleases,
                    mutexId->maxLockedDuration,
                    mutexId->maxLockedDurationUnlockFile,
                    mutexId->maxLockedDurationUnlockLine) < 0)
          BufferTooShort();
    } else {
        if(snprintf(buf, sizeof(buf),
                    "<TR><TH ALIGN=LEFT>%s</TH><TD ALIGN=CENTER>%s</TD>"
                    "<TD ALIGN=RIGHT>at %s %s:%d(%d)</TD>"
                    "<TD ALIGN=RIGHT>&nbsp;</TD>"
                    "<TD ALIGN=RIGHT>%s:%d(%d)</TD>"
                    "<TD ALIGN=RIGHT>%u</TD><TD ALIGN=RIGHT>%u</TD>"
                    "<TD ALIGN=RIGHT>%d sec [%s:%d]</TD></TR>\n",
                    mutexName,
                    mutexId->isLocked ? "<FONT COLOR=\"RED\">locked</FONT>" : "unlocked",
                    buf2,
                    mutexId->lockFile, mutexId->lockLine, mutexId->lockPid,
                    mutexId->unlockFile, mutexId->unlockLine, mutexId->unlockPid,
                    mutexId->numLocks, mutexId->numReleases,
                    mutexId->maxLockedDuration,
                    mutexId->maxLockedDurationUnlockFile,
                    mutexId->maxLockedDurationUnlockLine) < 0)
          BufferTooShort();
    }
  }

  sendString(buf);
}
#endif
