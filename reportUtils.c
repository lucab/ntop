/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
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

/* #define PRINT_ALL_ACTIVE_SESSIONS 1  */

#ifndef MICRO_NTOP

/* ************************************ */

void formatUsageCounter(UsageCounter usageCtr,
			TrafficCounter topValue
			/* If this value != 0 then a percentage is printed */
			) {
  char buf[BUF_SIZE];
  int i, sendHeader=0;

  if(topValue == 0) {
    /* No percentage is printed */
    if(snprintf(buf, sizeof(buf), "<TD "TD_BG"  ALIGN=RIGHT>%s</TD>",
		formatPkts(usageCtr.value)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  } else {
    float pctg;

    pctg = ((float)usageCtr.value/(float)topValue)*100;

    if(pctg > 100) pctg = 100; /* This should not happen ! */

    if(snprintf(buf, sizeof(buf), "<TD "TD_BG"  ALIGN=RIGHT>%s [%.0f %%]</TD>",
		formatPkts(usageCtr.value), pctg) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

  }

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
    if((usageCtr.peersIndexes[i] != NO_PEER)
       && (usageCtr.peersIndexes[i] != 0 /* Safety check: broadcast */)) {
      struct hostTraffic *el1;

      el1 = device[actualReportDeviceId].
       hash_hostTraffic[checkSessionIdx(usageCtr.peersIndexes[i])];

      if(el1 != NULL) {
       if(!sendHeader) {
         sendString("<TD "TD_BG"  ALIGN=LEFT><ul>");
         sendHeader = 1;
       }
       sendString("\n<li>");
       sendString(makeHostLink(el1, 0, 0, 0));
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

  if((totalS == 0) && (totalR == 0)) return;
  int_perc = (int)percentageS;

  /* This shouldn't happen */
  if(int_perc < 0) {
    int_perc = 0;
    percentageS = 0;
  } else if(int_perc > 100) {
    int_perc = 100;
    percentageS = 100;
  }

  switch(int_perc) {
  case 0:
    if(snprintf(buf, bufLen, "<TR %s><TH WIDTH=100 "TH_BG" ALIGN=LEFT>%s</TH>"
           "<TD WIDTH=100 "TD_BG"  ALIGN=RIGHT>%s</TD>"
           "<TD WIDTH=100 "TD_BG">&nbsp;</TD>\n",
           getRowColor(), label, formatKBytes(totalS)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    break;
  case 100:
    if(snprintf(buf, bufLen, "<TR %s><TH WIDTH=100 "TH_BG" ALIGN=LEFT>%s</TH>"
           "<TD WIDTH=100 "TD_BG"  ALIGN=RIGHT>%s</TD>"
           "<TD WIDTH=100><IMG ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=100 HEIGHT=12></TD>\n",
           getRowColor(), label, formatKBytes(totalS)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    break;
  default:
    if(snprintf(buf, bufLen, "<TR %s><TH WIDTH=100 "TH_BG" ALIGN=LEFT>%s</TH>"
	     "<TD WIDTH=100 "TD_BG"  ALIGN=RIGHT>%s</TD>"
	     "<TD WIDTH=100 "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100\">"
	     "<TR><TD><IMG ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=\"%d\" HEIGHT=12></TD>"
	     "<TD "TD_BG"  ALIGN=CENTER WIDTH=\"%d\">"
	     "<P>&nbsp;</TD></TR></TABLE></TD>\n",
	     getRowColor(), label, formatKBytes(totalS),
	     (100*int_perc)/100, (100*(100-int_perc))/100) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  }

  sendString(buf);

  /* ************************ */

  if(totalR == 0) percentageR = 0;

  int_perc = (int)percentageR;

  /* This shouldn't happen */
  if(int_perc < 0) {
    int_perc = 0;
    percentageR = 0;
  } else if(int_perc > 100) {
    int_perc = 100;
    percentageS = 100;
  }

  switch(int_perc) {
  case 0:
    if(snprintf(buf, bufLen, "<TD WIDTH=100 "TD_BG"  ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100 "TD_BG">&nbsp;</TD></TR>\n",
		formatKBytes(totalR)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    break;
  case 100:
    if(snprintf(buf, bufLen, "<TD WIDTH=100 "TD_BG"  ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100><IMG ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=\"100\" HEIGHT=12></TD></TR>\n",
		formatKBytes(totalR)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    break;
  default:
    if(snprintf(buf, bufLen, "<TD WIDTH=100 "TD_BG"  ALIGN=RIGHT>%s</TD>"
           "<TD  WIDTH=100 "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100\">"
           "<TR><TD><IMG ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=\"%d\" HEIGHT=12>"
           "</TD><TD "TD_BG"  ALIGN=CENTER WIDTH=\"%d\">"
           "<P>&nbsp;</TD></TR></TABLE></TD></TR>\n",
           formatKBytes(totalR),
           (100*int_perc)/100, (100*(100-int_perc))/100) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  }

  sendString(buf);
}

/* ********************************** */

void printTableEntryPercentage(char *buf, int bufLen,
			       char *label, char* label_1,
			       char* label_2, float total,
			       float percentage) {
  int int_perc = (int)percentage;

  /* This shouldn't happen */
  if(int_perc < 0)
    int_perc = 0;
  else if(int_perc > 100)
    int_perc = 100;

  switch(int_perc) {
  case 0:
    if(total == -1) {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=CENTER BGCOLOR=\"%s\">%s&nbsp;(100&nbsp;%%)</TD></TR>\n",
		  getRowColor(), label, COLOR_2, label_2) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    } else {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>%s</TD>"
		  "<TD ALIGN=CENTER BGCOLOR=\"%s\">%s&nbsp;(100&nbsp;%%)</TD></TR>\n",
		  getRowColor(), label, formatKBytes(total), COLOR_2, label_2) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    }
    break;
  case 100:
    if(total == -1) {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=CENTER BGCOLOR=\"%s\">%s&nbsp;(100&nbsp;%%)</TD></TR>\n",
		  getRowColor(), label, COLOR_1, label_1) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    } else {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>%s</TD>"
		  "<TD ALIGN=CENTER BGCOLOR=\"%s\">%s&nbsp;(100&nbsp;%%)</TD></TR>\n",
		  getRowColor(), label, formatKBytes(total), COLOR_1, label_1) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    }
    break;
  default:
    if(total == -1) {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
             "<TD "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100%%\">"
             "<TR><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
             "<P>%s&nbsp;(%.1f&nbsp;%%)</TD><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
             "<P>%s&nbsp;(%.1f&nbsp;%%)</TD></TR></TABLE></TD></TR>\n",
             getRowColor(), label,
             int_perc, COLOR_1,
             label_1, percentage, (100-int_perc), COLOR_2,
             label_2, (100-percentage)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    } else {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>%s</TD>"
             "<TD "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100%%\">"
             "<TR><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
             "<P>%s&nbsp;(%.1f&nbsp;%%)</TD><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
             "<P>%s&nbsp;(%.1f&nbsp;%%)</TD></TR></TABLE></TD></TR>\n",
             getRowColor(), label, formatKBytes(total),
             int_perc, COLOR_1,
             label_1, percentage, (100-int_perc), COLOR_2,
		  label_2, (100-percentage)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    }
  }

  sendString(buf);
}

/* ******************************* */

void printHeader(int reportType, int revertOrder, u_int column) {
  char buf[BUF_SIZE];
  char *sign, *arrowGif, *arrow[48], *theAnchor[48];
  int i;
  char htmlAnchor[64], htmlAnchor1[64];

  /* printf("->%d<-\n",screenNumber); */

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG SRC=arrow_down.gif BORDER=0>";
  }

  memset(buf, 0, sizeof(buf));

  if(sortSendMode) {
   if((reportType == 0) || (reportType == 1)) {
      if(reportType == 0) {
	if(snprintf(htmlAnchor, sizeof(htmlAnchor),
		    "<A HREF=/%s?%s", STR_SORT_DATA_SENT_PROTOS, sign) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	if(snprintf(htmlAnchor1, sizeof(htmlAnchor1),
		    "<A HREF=/%s?", STR_SORT_DATA_SENT_PROTOS) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      } else {
	if(snprintf(htmlAnchor, sizeof(htmlAnchor),
		    "<A HREF=/%s?%s", STR_SORT_DATA_SENT_IP, sign) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	if(snprintf(htmlAnchor1, sizeof(htmlAnchor1),
		    "<A HREF=/%s?", STR_SORT_DATA_SENT_IP) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      }
    } else if(reportType == 2) {
      if(snprintf(htmlAnchor, sizeof(htmlAnchor),
		  "<A HREF=/%s?%s",   STR_SORT_DATA_SENT_THPT, sign) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      if(snprintf(htmlAnchor1, sizeof(htmlAnchor1),
		  "<A HREF=/%s?",   STR_SORT_DATA_SENT_THPT) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    } else if(reportType == 3) {
      if(snprintf(htmlAnchor, sizeof(htmlAnchor),
		  "<A HREF=/%s?%s",   STR_SORT_DATA_SENT_HOST_TRAFFIC, sign) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      if(snprintf(htmlAnchor1, sizeof(htmlAnchor1),
		  "<A HREF=/%s?",   STR_SORT_DATA_SENT_HOST_TRAFFIC) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    }

    if((reportType == 0) || (reportType == 1)) {
      if(abs(column) == HOST_DUMMY_IDX_VALUE)
	{ arrow[0] = arrowGif; theAnchor[0] = htmlAnchor; }
      else { arrow[0] = ""; theAnchor[0] = htmlAnchor1; }
      if(abs(column) == DOMAIN_DUMMY_IDX_VALUE)
	{ arrow[1] = arrowGif; theAnchor[1] = htmlAnchor;  }
      else { arrow[1] = "";  theAnchor[1] = htmlAnchor1;}
      if(abs(column) == 0)
	{ arrow[2] = arrowGif; theAnchor[2] = htmlAnchor;  }
      else { arrow[2] = ""; theAnchor[2] = htmlAnchor1; }
     sendString("<CENTER>\n");
     if(snprintf(buf, BUF_SIZE, ""TABLE_ON"<TABLE BORDER=1><TR>"
		  "<TH "TH_BG">%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>\n"
		  "<TH "TH_BG">%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
		  "<TH "TH_BG" COLSPAN=2>%s0>Sent%s</A></TH>\n",
		  theAnchor[0], arrow[0], theAnchor[1], arrow[1],
		  theAnchor[2], arrow[2]) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    } else {
      if(abs(column) == HOST_DUMMY_IDX_VALUE)
	{ arrow[0] = arrowGif; theAnchor[0] = htmlAnchor; }
      else { arrow[0] = ""; theAnchor[0] = htmlAnchor1; }
      if(abs(column) == DOMAIN_DUMMY_IDX_VALUE)
	{ arrow[1] = arrowGif; theAnchor[1] = htmlAnchor;  }
      else { arrow[1] = ""; theAnchor[1] = htmlAnchor1; }
      sendString("<CENTER>\n");
      if(snprintf(buf, BUF_SIZE, ""TABLE_ON"<TABLE BORDER=1><TR>"
		  "<TH "TH_BG">%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>"
		  "<TH "TH_BG">%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>\n\n",
		  theAnchor[0], arrow[0], theAnchor[1], arrow[1]) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    }

    sendString(buf);
  } else {
    if((reportType == 0) || (reportType == 1)) {
      if(reportType == 0) {
	if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s",
		    STR_SORT_DATA_RECEIVED_PROTOS, sign) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?",
		    STR_SORT_DATA_RECEIVED_PROTOS) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      } else {
	if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s",
		    STR_SORT_DATA_RECEIVED_IP, sign) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?",
		    STR_SORT_DATA_RECEIVED_IP) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      }
    } else if(reportType == 2) {
      if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s",
		  STR_SORT_DATA_RECEIVED_THPT, sign) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?",
		  STR_SORT_DATA_RECEIVED_THPT) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    } else if(reportType == 3) {
      if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s",
		  STR_SORT_DATA_RCVD_HOST_TRAFFIC, sign)  < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?",
		  STR_SORT_DATA_RCVD_HOST_TRAFFIC) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    }

    if((reportType == 0) || (reportType == 1)) {
      if(abs(column) == HOST_DUMMY_IDX_VALUE)
	{ arrow[0] = arrowGif; theAnchor[0] = htmlAnchor; }
      else { arrow[0] = ""; theAnchor[0] = htmlAnchor1; }
      if(abs(column) == DOMAIN_DUMMY_IDX_VALUE)
	{ arrow[1] = arrowGif; theAnchor[1] = htmlAnchor;  }
      else { arrow[1] = "";  theAnchor[1] = htmlAnchor1;}
      if(abs(column) == 0)
	{ arrow[2] = arrowGif; theAnchor[2] = htmlAnchor;  }
      else { arrow[2] = ""; theAnchor[2] = htmlAnchor1; }
      sendString("<CENTER>\n");
      if(snprintf(buf, BUF_SIZE, ""TABLE_ON"<TABLE BORDER=1><TR>"
	       "<TH "TH_BG">%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>\n"
	      "<TH "TH_BG">%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
	      "<TH "TH_BG" COLSPAN=2>%s0>Received%s</A></TH>\n",
	      theAnchor[0], arrow[0], theAnchor[1],
		  arrow[1], theAnchor[2], arrow[2]) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    } else {
      if(abs(column) == HOST_DUMMY_IDX_VALUE)
	{ arrow[0] = arrowGif; theAnchor[0] = htmlAnchor; }
      else { arrow[0] = ""; theAnchor[0] = htmlAnchor1; }
      if(abs(column) == DOMAIN_DUMMY_IDX_VALUE)
	{ arrow[1] = arrowGif; theAnchor[1] = htmlAnchor; }
      else { arrow[1] = ""; theAnchor[1] = htmlAnchor1;}
      sendString("<CENTER>\n");
      if(snprintf(buf, BUF_SIZE, ""TABLE_ON"<TABLE BORDER=1><TR>"
	       "<TH "TH_BG">%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>"
	      "<TH "TH_BG">%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>\n\n",
	      theAnchor[0], arrow[0], theAnchor[1], arrow[1]) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    }
    sendString(buf);
  }

  if(reportType == 0) {
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
    else { arrow[6] = ""; theAnchor[6] = htmlAnchor; }
    if(abs(column) == 8)
      { arrow[7] = arrowGif; theAnchor[7] = htmlAnchor;  }
    else { arrow[7] = ""; theAnchor[7] = htmlAnchor1;  }
    if(abs(column) == 9)
      { arrow[8] = arrowGif; theAnchor[8] = htmlAnchor;  }
    else { arrow[8] = ""; theAnchor[8] = htmlAnchor1; }
    if(abs(column) == 10)
      { arrow[9] = arrowGif; theAnchor[9] = htmlAnchor;  }
    else { arrow[9] = ""; theAnchor[9] = htmlAnchor1; }
    if(abs(column) == 11)
      { arrow[10] = arrowGif; theAnchor[10] = htmlAnchor;  }
    else { arrow[10] = "";  theAnchor[10] = htmlAnchor1;}
    if(abs(column) == 12)
      { arrow[11] = arrowGif; theAnchor[11] = htmlAnchor;  }
    else { arrow[11] = "";theAnchor[11] = htmlAnchor1; }
    if(abs(column) == 13)
      { arrow[12] = arrowGif; theAnchor[12] = htmlAnchor;  }
    else { arrow[12] = "";  theAnchor[12] = htmlAnchor1;  }
    if(abs(column) == 14)
      { arrow[13] = arrowGif; theAnchor[13] = htmlAnchor;  }
    else { arrow[13] = "";  theAnchor[13] = htmlAnchor1;  }
    if(abs(column) == 15)
      { arrow[14] = arrowGif; theAnchor[14] = htmlAnchor;  }
    else { arrow[14] = "";  theAnchor[14] = htmlAnchor1;  }

    if(snprintf(buf, BUF_SIZE, "<TH "TH_BG">%s1>TCP%s</A></TH>"
	     "<TH "TH_BG">%s2>UDP%s</A></TH><TH "TH_BG">%s3>ICMP%s</A></TH>"
	    "<TH "TH_BG">%s4>DLC%s</A></TH><TH "TH_BG">%s5>IPX%s</A>"
	     "</TH><TH "TH_BG">%s6>Decnet%s</A></TH>"
	     "<TH "TH_BG">%s7>(R)ARP%s</A></TH><TH "TH_BG">%s8>AppleTalk%s</A></TH>",
	    theAnchor[0], arrow[0], theAnchor[1], arrow[1],
	    theAnchor[2], arrow[2], theAnchor[3], arrow[3],
	    theAnchor[4], arrow[4], theAnchor[5], arrow[5],
	    theAnchor[6], arrow[6], theAnchor[7], arrow[7]) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
    if(snprintf(buf, BUF_SIZE,
		"<TH "TH_BG">%s9>OSPF%s</A></TH>"
		"<TH "TH_BG">%s10>NetBios%s</A></TH>"
		"<TH "TH_BG">%s11>IGMP%s</A></TH>"
		"<TH "TH_BG">%s12>OSI%s</A></TH>"
		"<TH "TH_BG">%s13>QNX%s</A></TH>"
		"<TH "TH_BG">%s14>STP%s</A></TH>"
		"<TH "TH_BG">%s15>Other%s</A></TH>",
		theAnchor[8], arrow[8],
		theAnchor[9], arrow[9],
		theAnchor[10], arrow[10],
		theAnchor[11], arrow[11],
		theAnchor[12], arrow[12],
		theAnchor[13], arrow[13],
		theAnchor[14], arrow[14]) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  } else if(reportType == 1) {
    int soFar=2;

    if(abs(column) == 1) {
	arrow[0] = arrowGif;
	theAnchor[0] = htmlAnchor;
      } else {
	arrow[0] = "";
	theAnchor[0] = htmlAnchor1;
      }

#ifdef ENABLE_NAPSTER
    if(snprintf(buf, BUF_SIZE, "<TH "TH_BG">%s%d>%s%s</A></TH>",
		theAnchor[0], 1, "Napster", arrow[0]) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
#endif

    for(i=0; i<numIpProtosToMonitor; i++) {
      if(abs(column) == soFar) {
	arrow[0] = arrowGif;
	theAnchor[0] = htmlAnchor;
      } else {
	arrow[0] = "";
	theAnchor[0] = htmlAnchor1;
      }
      if(snprintf(buf, BUF_SIZE, "<TH "TH_BG">%s%d>%s%s</A></TH>",
	      theAnchor[0], i+2, protoIPTrafficInfos[i], arrow[0]) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
      soFar++;
    }

    if(abs(column) == soFar) {
      arrow[0] = arrowGif; theAnchor[0] = htmlAnchor;
    } else {
      arrow[0] = "";  theAnchor[0] = htmlAnchor1;
    }
    if(snprintf(buf, BUF_SIZE, "<TH "TH_BG">%s%d>Other&nbsp;IP%s</A></TH>",
	     theAnchor[0], i+2, arrow[0]) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  } else if(reportType == 2) {
    updateThpt();
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

    if(snprintf(buf, BUF_SIZE, "<TH "TH_BG">%s1>Actual Thpt%s</A></TH>"
	     "<TH "TH_BG">%s2>Avg Thpt%s</A></TH>"
	     "<TH "TH_BG">%s3>Peak Thpt%s</A></TH>"
	    "<TH "TH_BG">%s4>Actual Pkt Thpt%s</A></TH><TH "TH_BG">%s5>Avg Pkt Thpt%s</A></TH>"
	     "<TH "TH_BG">%s6>Peak Pkt Thpt%s</A></TH>",
	    theAnchor[0], arrow[0], theAnchor[1], arrow[1], theAnchor[2], arrow[2],
	    theAnchor[3], arrow[3], theAnchor[4], arrow[4], theAnchor[5], arrow[5]) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  } else if(reportType == 3) {
    sendString("<TH "TH_BG">0<br>AM</TH><TH "TH_BG">1<br>AM</TH>"
	       "<TH "TH_BG">2<br>AM</TH><TH "TH_BG">3<br>AM</TH>"
	       "<TH "TH_BG">4<br>AM</TH><TH "TH_BG">5<br>AM</TH><TH "TH_BG">6<br>AM</TH>"
	       "<TH "TH_BG">7<br>AM</TH><TH "TH_BG">8<br>AM</TH><TH "TH_BG">9<br>AM</TH>"
	       "<TH "TH_BG">10<br>AM</TH><TH "TH_BG">11<br>AM</TH><TH "TH_BG">12<br>AM</TH>\n");
    sendString("<TH "TH_BG">1<br>PM</TH><TH "TH_BG">2<br>PM</TH><TH "TH_BG">3<br>PM</TH>"
	       "<TH "TH_BG">4<br>PM</TH><TH "TH_BG">5<br>PM</TH><TH "TH_BG">6<br>PM</TH>"
	       "<TH "TH_BG">7<br>PM</TH><TH "TH_BG">8<br>PM</TH><TH "TH_BG">9<br>PM</TH>"
	       "<TH "TH_BG">10<br>PM</TH><TH "TH_BG">11<br>PM</TH>\n");
  }
  sendString("</TR>\n");
}

/* ******************************* */

char* getOSFlag(char* osName, int showOsName) {
  static char tmpStr[96], *flagImg;

  if(strstr(osName, "Windows") != NULL)
    flagImg = "<IMG ALIGN=MIDDLE SRC=/statsicons/os/windows.gif>";
  else if(strstr(osName, "IRIX") != NULL)
    flagImg = "<IMG ALIGN=MIDDLE SRC=/statsicons/os/irix.gif>";
  else if(strstr(osName, "Linux") != NULL)
    flagImg = "<IMG ALIGN=MIDDLE SRC=/statsicons/os/linux.gif>";
  else if(strstr(osName, "SunOS") != NULL)
    flagImg = "<IMG ALIGN=MIDDLE SRC=/statsicons/os/sun.gif>";
  else if(strstr(osName, "Solaris") != NULL)
    flagImg = "<IMG ALIGN=MIDDLE SRC=/statsicons/os/sun.gif>";
  else if(strstr(osName, "HP/JETdirect") != NULL)
    flagImg = "<IMG ALIGN=MIDDLE SRC=/statsicons/os/hp.gif>";
  else if(strstr(osName, "Mac") != NULL)
    flagImg = "<IMG ALIGN=MIDDLE SRC=/statsicons/os/mac.gif>";
  else if(strstr(osName, "Novell") != NULL)
    flagImg = "<IMG ALIGN=MIDDLE SRC=/statsicons/os/novell.gif>";
  else if((strstr(osName, "BSD") != NULL) || (strstr(osName, "Unix") != NULL))
    flagImg = "<IMG ALIGN=MIDDLE SRC=/statsicons/os/bsd.gif>";
  else if(strstr(osName, "HP-UX") != NULL)
    flagImg = "<IMG ALIGN=MIDDLE SRC=/statsicons/os/hp.gif>";
  else if(strstr(osName, "AIX") != NULL)
    flagImg = "<IMG ALIGN=MIDDLE SRC=/statsicons/os/aix.gif>";
  else if(strstr(osName, "Berkeley") != NULL)
    flagImg = "<IMG ALIGN=MIDDLE SRC=/statsicons/os/bsd.gif>";
  else
    flagImg = NULL;

  if(!showOsName) {
    if(flagImg != NULL)
      strncpy(tmpStr, flagImg, sizeof(tmpStr));
    else
      strncpy(tmpStr, "", sizeof(tmpStr));
  } else {
    if(flagImg != NULL) {
      if(snprintf(tmpStr, sizeof(tmpStr), "%s&nbsp;[%s]", flagImg, osName) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    } else
      strncpy(tmpStr, osName, sizeof(tmpStr));
  }

  return(tmpStr);
}

/* ******************************* */

int sortHostFctn(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  int rc;
  char *nameA, *nameB, nameA_str[32], nameB_str[32];

  if((a == NULL) && (b != NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (1)\n");
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (2)\n");
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (3)\n");
    return(0);
  }

  switch(columnSort) {
  case 1:
#ifdef MULTITHREADED
    accessMutex(&addressResolutionMutex, "sortHostFctn");
#endif
    rc = strcasecmp((*a)->hostSymIpAddress[0] != '\0' ? (*a)->hostSymIpAddress : (*a)->ethAddressString,
		    (*b)->hostSymIpAddress[0] != '\0' ? (*b)->hostSymIpAddress : (*b)->ethAddressString);
#ifdef MULTITHREADED
    releaseMutex(&addressResolutionMutex);
#endif
    return(rc);
    break;
  case 2:
    if((*a)->hostIpAddress.s_addr > (*b)->hostIpAddress.s_addr)
      return(1);
    else if((*a)->hostIpAddress.s_addr < (*b)->hostIpAddress.s_addr)
      return(-1);
    else
      return(0);
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
    if((*a)->nbHostName != NULL)
      nameA = (*a)->nbHostName;
    else if((*a)->atNodeName != NULL)
      nameA = (*a)->atNodeName;
    else if((*a)->atNetwork != 0) {
      if(snprintf(nameA_str, sizeof(nameA_str), "%d.%d", (*a)->atNetwork, (*a)->atNode) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      nameA = nameA_str;
    } else if((*a)->ipxHostName != NULL)
      nameA = (*a)->ipxHostName;
    else
      nameA = "";

    if((*b)->nbHostName != NULL)
      nameB = (*b)->nbHostName;
    else if((*b)->atNodeName != NULL)
      nameB = (*b)->atNodeName;
    else if((*a)->atNetwork != 0) {
      if(snprintf(nameB_str, sizeof(nameB_str), "%d.%d", (*b)->atNetwork, (*b)->atNode) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      nameB = nameB_str;
    } else if((*b)->ipxHostName != NULL)
      nameB = (*b)->ipxHostName;
    else
      nameB = "";

    return(strcasecmp(nameA, nameB));
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
  TrafficCounter sum_a, sum_b;

  if((a == NULL) && (b != NULL)) {
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    return(0);
  }

  sum_a = (*a)->bytesSent + (*a)->bytesReceived;
  sum_b = (*b)->bytesSent + (*b)->bytesReceived;

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

  switch(columnSort) {
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
    if((*a)->bytesSent == (*b)->bytesSent)
      return(0);
    else if((*a)->bytesSent < (*b)->bytesSent)
      return(1);
    else return(-1);
    break;
  case 5: /* Rcvd */
    if((*a)->bytesReceived == (*b)->bytesReceived)
      return(0);
    else if((*a)->bytesReceived < (*b)->bytesReceived)
      return(1);
    else return(-1);
    break;
  default: /* Process name */
    return(strcasecmp((*a)->command, (*b)->command));
  }
}

/* ******************************* */

int cmpFctn(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  TrafficCounter a_=0, b_=0;
  float fa_=0, fb_=0;
  int idx;
  short oldColumnSort, floatCompare=0;

  if((a == NULL) && (b != NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (1)\n");
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (2)\n");
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (3)\n");
    return(0);
  }

#ifdef DEBUG
  printf("screenNumber=%d, columnSort=%d\n", screenNumber, columnSort);
#endif

  if(columnSort == HOST_DUMMY_IDX_VALUE) {
    int rc;

    /* Host name */
#ifdef MULTITHREADED
    accessMutex(&addressResolutionMutex, "cmpFctn");
#endif

    if((*a)->hostSymIpAddress[0] != '\0') {
      char *name1, *name2;

      name1 = (*a)->hostSymIpAddress;
      name2 = (*b)->hostSymIpAddress;

      if(name1[0] == '*') name1++;
      if(name2[0] == '*') name2++;
      rc = strcasecmp(name1, name2);
    } else
      rc = strcasecmp((*a)->ethAddressString, (*b)->ethAddressString);

#ifdef MULTITHREADED
    releaseMutex(&addressResolutionMutex);
#endif
    return(rc);
  } else if(columnSort == DOMAIN_DUMMY_IDX_VALUE) {
    int rc;

    fillDomainName(*a); fillDomainName(*b);

#ifdef DEBUG
    traceEvent(TRACE_INFO, "%s='%s'/'%s' - %s='%s'/'%s'\n",
	   (*a)->hostSymIpAddress,
	   (*a)->dotDomainName, (*a)->fullDomainName,
	   (*b)->hostSymIpAddress,
	   (*b)->dotDomainName, (*b)->fullDomainName
	   );
#endif
    rc = strcasecmp((*a)->dotDomainName, (*b)->dotDomainName);
    if(rc == 0)
      return(strcasecmp((*a)->fullDomainName, (*b)->fullDomainName));
    else
      return rc;
  }

  oldColumnSort = columnSort;

  if(screenNumber == DUMMY_IDX_VALUE) {
    /* dirty trick */
    idx = columnSort-1;
    if(idx == -1) {
      idx = 0;
      columnSort = 0;
    } else
      columnSort = 1;
  } else
    idx = (screenNumber-MAX_NUM_PROTOS_SCREENS)*3;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "idx=%d/columnSort=%d/sortSendMode=%d/screenNumber=%d/numIpProtosToMonitor=%d\n",
	 idx, columnSort, sortSendMode, screenNumber, numIpProtosToMonitor);
#endif

  switch(columnSort) {
  case 0:
    if(sortSendMode) {
      a_ = (*a)->bytesSent, b_ = (*b)->bytesSent;
    } else {
      a_ = (*a)->bytesReceived, b_ = (*b)->bytesReceived;
    }
    break;
  case 1:
    if(sortSendMode) {
      switch(screenNumber)
	{
	case 0:
	  a_ = (*a)->tcpSentLocally+(*a)->tcpSentRemotely;
	  b_ = (*b)->tcpSentLocally+(*b)->tcpSentRemotely;
	  break;
	case 1:
	  a_ = (*a)->dlcSent, b_ = (*b)->dlcSent;
	  break;
	case 2:
	  a_ = (*a)->arp_rarpSent, b_ = (*b)->arp_rarpSent;
	  break;
	case 3:
	  a_ = (*a)->netbiosSent, b_ = (*b)->netbiosSent;
	  break;
	case MAX_NUM_PROTOS_SCREENS:
	  fa_ = (*a)->actualSentThpt, fb_ = (*b)->actualSentThpt, floatCompare = 1;
	  break;
	default:

	  if(idx <= numIpProtosToMonitor) {
	    if(idx == 0) {
#ifdef ENABLE_NAPSTER
	      if((*a)->napsterStats == NULL)
		a_ = 0;
	      else
		a_ = (*a)->napsterStats->bytesSent;

	      if((*b)->napsterStats == NULL)
		b_ = 0;
	      else
		b_ = (*b)->napsterStats->bytesSent;
#else
	      a_ = b_ = 0;
#endif
	    } else {
	      a_ = (*a)->protoIPTrafficInfos[idx-1].sentLocally
		+(*a)->protoIPTrafficInfos[idx-1].sentRemotely;
	      b_ = (*b)->protoIPTrafficInfos[idx-1].sentLocally
		+(*b)->protoIPTrafficInfos[idx-1].sentRemotely;
	    }
	  } else {
	    int i;

	    a_ = 0, b_ = 0;

	    for(i=0; i<numIpProtosToMonitor; i++) {
	      a_ += (*a)->protoIPTrafficInfos[i].sentLocally
		+(*a)->protoIPTrafficInfos[i].sentRemotely;
	      b_ += (*b)->protoIPTrafficInfos[i].sentLocally
		+(*b)->protoIPTrafficInfos[i].sentRemotely;
	    }

	    if((*a)->bytesSent > a_)
	      a_ = (*a)->bytesSent-a_;
	    else
	      a_ = 0;

	    if((*b)->bytesSent > b_)
	      b_ = (*b)->bytesSent-b_;
	    else
	      b_ = 0;
	  }
	}
    } else {
      switch(screenNumber)
	{
	case 0:
	  a_ = (*a)->tcpReceivedLocally+(*a)->tcpReceivedFromRemote;
	  b_ = (*b)->tcpReceivedLocally+(*b)->tcpReceivedFromRemote;
	  break;
	case 1:
	  a_ = (*a)->dlcReceived, b_ = (*b)->dlcReceived;
	  break;
	case 2:
	  a_ = (*a)->arp_rarpReceived, b_ = (*b)->arp_rarpReceived;
	  break;
	case 3:
	  a_ = (*a)->netbiosReceived, b_ = (*b)->netbiosReceived;
	  break;
	case MAX_NUM_PROTOS_SCREENS:
	  fa_ = (*a)->actualRcvdThpt,
	    fb_ = (*b)->actualRcvdThpt, floatCompare = 1;
	  break;
	default:
	  if(idx <= numIpProtosToMonitor) {
	    if(idx == 0) {
#ifdef ENABLE_NAPSTER
	      if((*a)->napsterStats == NULL)
		a_ = 0;
	      else
		a_ = (*a)->napsterStats->bytesRcvd;

	      if((*b)->napsterStats == NULL)
		b_ = 0;
	      else
		b_ = (*b)->napsterStats->bytesRcvd;
#else
	      a_ = b_ = 0;
#endif
	    } else {
	      a_ = (*a)->protoIPTrafficInfos[idx-1].receivedLocally
		+(*a)->protoIPTrafficInfos[idx-1].receivedFromRemote;
	      b_ = (*b)->protoIPTrafficInfos[idx-1].receivedLocally
		+(*b)->protoIPTrafficInfos[idx-1].receivedFromRemote;
	    }
	  } else {
	    int i;

	    a_ = 0, b_ = 0;

	    for(i=0; i<numIpProtosToMonitor; i++) {
	      a_ += (*a)->protoIPTrafficInfos[i].receivedLocally
		+(*a)->protoIPTrafficInfos[i].receivedFromRemote;
	      b_ += (*b)->protoIPTrafficInfos[i].receivedLocally
		+(*b)->protoIPTrafficInfos[i].receivedFromRemote;
	    }

	    if((*a)->bytesReceived > a_)
	      a_ = (*a)->bytesReceived-a_;
	    else
	      a_ = 0;

	    if((*b)->bytesReceived > b_)
	      b_ = (*b)->bytesReceived-b_;
	    else
	      b_ = 0;

	    /*
	      traceEvent(TRACE_INFO, "=>%d (%s)<=>%d (%s)<=\n",
	      (int)a_, (*a)->hostSymIpAddress,
	      (int)b_, (*b)->hostSymIpAddress);
	    */
	  }
	}
    }
    break;
  case 2:
    if(sortSendMode) {
      switch(screenNumber)
	{
	case 0:
	  a_ = (*a)->udpSentLocally +(*a)->udpSentRemotely;
	  b_ = (*b)->udpSentLocally +(*b)->udpSentRemotely;
	  break;
	case 1:
	  a_ = (*a)->ipxSent, b_ = (*b)->ipxSent;
	  break;
	case 2:
	  a_ = (*a)->appletalkSent, b_ = (*b)->appletalkSent;
	  break;
	case 3:
	  a_ = (*a)->igmpSent, b_ = (*b)->igmpSent;
	  break;
	case MAX_NUM_PROTOS_SCREENS:
	  fa_ = (*a)->averageSentThpt,
	    fb_ = (*b)->averageSentThpt, floatCompare = 1;
	  break;
	default:
	  if(++idx < numIpProtosToMonitor) {
	    a_ = (*a)->protoIPTrafficInfos[idx].sentLocally
	      +(*a)->protoIPTrafficInfos[idx].sentRemotely;
	    b_ = (*b)->protoIPTrafficInfos[idx].sentLocally
	      +(*b)->protoIPTrafficInfos[idx].sentRemotely;
	  } else {
	    int i;

	    a_ = 0, b_ = 0;

	    for(i=0; i<numIpProtosToMonitor; i++) {
	      a_ += (*a)->protoIPTrafficInfos[i].sentLocally
		+(*a)->protoIPTrafficInfos[i].sentRemotely;
	      b_ += (*b)->protoIPTrafficInfos[i].sentLocally
		+(*b)->protoIPTrafficInfos[i].sentRemotely;
	    }

	    if((*a)->bytesSent > a_)
	      a_ = (*a)->bytesSent-a_;
	    else
	      a_ = 0;

	    if((*b)->bytesSent > b_)
	      b_ = (*b)->bytesSent-b_;
	    else
	      b_ = 0;
	  }
	}
    } else {
      switch(screenNumber)
	{
	case 0:
	  a_ = (*a)->udpReceivedLocally +(*a)->udpReceivedFromRemote;
	  b_ = (*b)->udpReceivedLocally +(*b)->udpReceivedFromRemote;
	  break;
	case 1:
	  a_ = (*a)->ipxReceived, b_ = (*b)->ipxReceived;
	  break;
	case 2:
	  a_ = (*a)->appletalkReceived, b_ = (*b)->appletalkReceived;
	  break;
	case 3:
	  a_ = (*a)->igmpReceived, b_ = (*b)->igmpReceived;
	  break;
	case MAX_NUM_PROTOS_SCREENS:
	  fa_ = (*a)->averageRcvdThpt,
	    fb_ = (*b)->averageRcvdThpt, floatCompare = 1;
	  break;
	default:
	  if(++idx < numIpProtosToMonitor) {
	    a_ = (*a)->protoIPTrafficInfos[idx].receivedLocally
	      +(*a)->protoIPTrafficInfos[idx].receivedFromRemote;
	    b_ = (*b)->protoIPTrafficInfos[idx].receivedLocally
	      +(*b)->protoIPTrafficInfos[idx].receivedFromRemote;
	  } else {
	    int i;

	    a_ = 0, b_ = 0;

	    for(i=0; i<numIpProtosToMonitor; i++) {
	      a_ += (*a)->protoIPTrafficInfos[i].receivedLocally
		+(*a)->protoIPTrafficInfos[i].receivedFromRemote;
	      b_ += (*b)->protoIPTrafficInfos[i].receivedLocally
		+(*b)->protoIPTrafficInfos[i].receivedFromRemote;
	    }

	    if((*a)->bytesReceived > a_)
	      a_ = (*a)->bytesReceived-a_;
	    else
	      a_ = 0;

	    if((*b)->bytesReceived > b_)
	      b_ = (*b)->bytesReceived-b_;
	    else
	      b_ = 0;
	  }
	}
    }
    break;
  case 3:
    if(sortSendMode) {
      switch(screenNumber)
	{
	case 0:
	  a_ = (*a)->icmpSent, b_ = (*b)->icmpSent;
	  break;
	case 1:
	  a_ = (*a)->decnetSent, b_ = (*b)->decnetSent;
	  break;
	case 2:
	  a_ = (*a)->ospfSent, b_ = (*b)->ospfSent;
	  break;
	case 3:
	  a_ = (*a)->osiSent, b_ = (*b)->osiSent;
	  break;
	case 4:
	  a_ = (*a)->qnxSent, b_ = (*b)->qnxSent;
	  break;
	case 5: /* MAX_NUM_PROTOS_SCREENS: */
	  fa_ = (*a)->peakSentThpt,
	    fb_ = (*b)->peakSentThpt, floatCompare = 1;
	  break;
	default:
	  idx+=2;
	  if(idx < numIpProtosToMonitor) {
	    a_ = (*a)->protoIPTrafficInfos[idx].sentLocally
	      +(*a)->protoIPTrafficInfos[idx].sentRemotely;
	    b_ = (*b)->protoIPTrafficInfos[idx].sentLocally
	      +(*b)->protoIPTrafficInfos[idx].sentRemotely;
	  } else {
	    int i;

	    a_ = 0, b_ = 0;

	    for(i=0; i<numIpProtosToMonitor; i++) {
	      a_ += (*a)->protoIPTrafficInfos[i].sentLocally
		+(*a)->protoIPTrafficInfos[i].sentRemotely;
	      b_ += (*b)->protoIPTrafficInfos[i].sentLocally
		+(*b)->protoIPTrafficInfos[i].sentRemotely;
	    }

	    if((*a)->bytesSent > a_)
	      a_ = (*a)->bytesSent-a_;
	    else
	      a_ = 0;

	    if((*b)->bytesSent > b_)
	      b_ = (*b)->bytesSent-b_;
	    else
	      b_ = 0;
	  }
	}
    } else {
      switch(screenNumber)
	{
	case 0:
	  a_ = (*a)->icmpReceived, b_ = (*b)->icmpReceived;
	  break;
	case 1:
	  a_ = (*a)->decnetReceived, b_ = (*b)->decnetReceived;
	  break;
	case 2:
	  a_ = (*a)->ospfReceived, b_ = (*b)->ospfReceived;
	  break;
	case 3:
	  a_ = (*a)->osiReceived, b_ = (*b)->osiReceived;
	  break;
	case MAX_NUM_PROTOS_SCREENS:
	  fa_ = (*a)->peakRcvdThpt,
	    fb_ = (*b)->peakRcvdThpt, floatCompare = 1;
	  break;
	default:
	  idx+=2;
	  if(idx < numIpProtosToMonitor) {
	    a_ = (*a)->protoIPTrafficInfos[idx].receivedLocally
	      +(*a)->protoIPTrafficInfos[idx].receivedFromRemote;
	    b_ = (*b)->protoIPTrafficInfos[idx].receivedLocally
	      +(*b)->protoIPTrafficInfos[idx].receivedFromRemote;
	  } else {
	    int i;

	    a_ = 0, b_ = 0;

	    for(i=0; i<numIpProtosToMonitor; i++) {
	      a_ += (*a)->protoIPTrafficInfos[i].receivedLocally
		+(*a)->protoIPTrafficInfos[i].receivedFromRemote;
	      b_ += (*b)->protoIPTrafficInfos[i].receivedLocally
		+(*b)->protoIPTrafficInfos[i].receivedFromRemote;
	    }

	    if((*a)->bytesReceived > a_)
	      a_ = (*a)->bytesReceived-a_;
	    else
	      a_ = 0;

	    if((*b)->bytesReceived > b_)
	      b_ = (*b)->bytesReceived-b_;
	    else
	      b_ = 0;
	  }
	}
      break;
    }
    break;
  case 4:
    if(sortSendMode)
      switch(screenNumber) {
      case 0:
	a_ = (*a)->qnxSent, b_ = (*b)->qnxSent;
	break;
      default:
	fa_ = (*a)->actualSentPktThpt, fb_ = (*b)->actualSentPktThpt, floatCompare = 1;
	break;
      }
    else
      switch(screenNumber) {
      case 0:
	a_ = (*a)->qnxReceived, b_ = (*b)->qnxReceived;
	break;
      case MAX_NUM_PROTOS_SCREENS:
	fa_ = (*a)->actualRcvdPktThpt, fb_ = (*b)->actualRcvdPktThpt, floatCompare = 1;
	break;
      }
    break;
  case 5:
    if(sortSendMode) {
      switch(screenNumber) {
      case 0:
	a_ = (*a)->otherSent, b_ = (*b)->otherSent;
	break;
      case 1:
	a_ = (*a)->stpSent, b_ = (*b)->stpSent;
	break;
      case MAX_NUM_PROTOS_SCREENS:
	fa_ = (*a)->averageSentPktThpt, fb_ = (*b)->averageSentPktThpt, floatCompare = 1;
	break;
      }
    } else {
      switch(screenNumber) {
      case 0:
	a_ = (*a)->otherReceived, b_ = (*b)->otherReceived;
	break;
      case 1:
	a_ = (*a)->stpReceived, b_ = (*b)->stpReceived;
	break;
      }
    }

    break;
  case 6:
    if(sortSendMode)
      fa_ = (*a)->peakSentPktThpt, fb_ = (*b)->peakSentPktThpt, floatCompare = 1;
    else
      fa_ = (*a)->peakRcvdPktThpt, fb_ = (*b)->peakRcvdPktThpt, floatCompare = 1;
  }

  columnSort = oldColumnSort;

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
    traceEvent(TRACE_WARNING, "WARNING (1)\n");
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (2)\n");
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (3)\n");
    return(0);
  }

  switch(columnSort) {
  case 2:
    if((*a)->pktMulticastSent < (*b)->pktMulticastSent)
      return(1);
    else if ((*a)->pktMulticastSent > (*b)->pktMulticastSent)
      return(-1);
    else
      return(0);
    break; /* NOTREACHED */
  case 3:
    if((*a)->bytesMulticastSent < (*b)->bytesMulticastSent)
      return(1);
    else if ((*a)->bytesMulticastSent > (*b)->bytesMulticastSent)
      return(-1);
    else
      return(0);
    break; /* NOTREACHED */
  case 4:
    if((*a)->pktMulticastRcvd < (*b)->pktMulticastRcvd)
      return(1);
    else if ((*a)->pktMulticastRcvd > (*b)->pktMulticastRcvd)
      return(-1);
    else
      return(0);
    break; /* NOTREACHED */
  case 5:
    if((*a)->bytesMulticastRcvd < (*b)->bytesMulticastRcvd)
      return(1);
    else if ((*a)->bytesMulticastRcvd > (*b)->bytesMulticastRcvd)
      return(-1);
    else
      return(0);
    break; /* NOTREACHED */

  default:
#ifdef MULTITHREADED
    accessMutex(&addressResolutionMutex, "cmpMulticastFctn");
#endif

    rc = strcmp((*a)->hostSymIpAddress, /* Host name */
		(*b)->hostSymIpAddress);
#ifdef MULTITHREADED
    releaseMutex(&addressResolutionMutex);
#endif
    return(rc);
  }
}

/* ******************************* */

void getProtocolDataSent(TrafficCounter *c,
			 TrafficCounter *d,
			 TrafficCounter *e,
			 HostTraffic *el) {
  int idx;

  switch(screenNumber) {
  case 0:
    (*c) = el->tcpSentLocally + el->tcpSentRemotely;
    (*d) = el->udpSentLocally + el->udpSentRemotely;
    (*e) = el->icmpSent;
    break;
  case 1:
    (*c) = el->dlcSent;
    (*d) = el->ipxSent;
    (*e) = el->decnetSent;
    break;
  case 2:
    (*c) = el->arp_rarpSent;
    (*d) = el->appletalkSent;
    (*e) = el->ospfSent;
    break;
  case 3:
    (*c) = el->netbiosSent;
    (*d) = el->igmpSent;
    (*e) = el->osiSent;
    break;
  case 4:
    (*c) = el->qnxSent;
    (*d) = el->otherSent;
    (*e) = 0;
    break;
  default:
    idx = (screenNumber-MAX_NUM_PROTOS_SCREENS)*3;
    if(idx < numIpProtosToMonitor)
      (*c) = el->protoIPTrafficInfos[idx].sentLocally
	+ el->protoIPTrafficInfos[idx].sentRemotely;
    else
      (*c) = 0;

    ++idx;
    if(idx < numIpProtosToMonitor)
      (*d) = el->protoIPTrafficInfos[idx].sentLocally
	+ el->protoIPTrafficInfos[idx].sentRemotely;
    else
      (*d) = 0;

    ++idx;
    if(idx < numIpProtosToMonitor)
      (*e) = el->protoIPTrafficInfos[idx].sentLocally
	+ el->protoIPTrafficInfos[idx].sentRemotely;
    else
      (*e) = 0;
  }
}

/* ******************************* */

void getProtocolDataReceived(TrafficCounter *c,
			     TrafficCounter *d,
			     TrafficCounter *e,
			     HostTraffic *el) {
  int idx;

  switch(screenNumber) {
  case 0:
    (*c) = el->tcpReceivedLocally + el->tcpReceivedFromRemote;
    (*d) = el->udpReceivedLocally + el->udpReceivedFromRemote;
    (*e) = el->icmpReceived;
    break;
  case 1:
    (*c) = el->dlcReceived;
    (*d) = el->ipxReceived;
    (*e) = el->decnetReceived;
    break;
  case 2:
    (*c) = el->arp_rarpReceived;
    (*d) = el->appletalkReceived;
    (*e) = el->ospfReceived;
    break;
  case 3:
    (*c) = el->netbiosReceived;
    (*d) = el->igmpReceived;
    (*e) = el->osiReceived;
    break;
  case 4:
    (*c) = el->qnxReceived;
    (*d) = el->otherReceived;
    (*e) = 0;
    break;
  default:
    idx = (screenNumber-MAX_NUM_PROTOS_SCREENS)*3;
    if(idx < numIpProtosToMonitor)
      (*c) = el->protoIPTrafficInfos[idx].receivedLocally
	+ el->protoIPTrafficInfos[idx].receivedFromRemote;
    else
      (*c) = 0;

    ++idx;
    if(idx < numIpProtosToMonitor)
      (*d) = el->protoIPTrafficInfos[idx].receivedLocally
	+ el->protoIPTrafficInfos[idx].receivedFromRemote;
    else
      (*d) = 0;

    ++idx;
    if(idx < numIpProtosToMonitor)
      (*e) = el->protoIPTrafficInfos[idx].receivedLocally
	+ el->protoIPTrafficInfos[idx].receivedFromRemote;
    else
      (*e) = 0;
  }
}

/* *********************************** */

static char* getBgPctgColor(float pctg) {
  if(pctg == 0)
    return("");
  else if(pctg <= 25)           /* < 25%       */
    return("BGCOLOR=#C6EEF7");  /* 25% <=> 75% */
  else if(pctg <= 75)
    return("BGCOLOR=#C6EFC8");  /* > 75%       */
  else
    return("BGCOLOR=#FF3118");
}

/* ******************************* */

void printHostThtpShort(HostTraffic *el, short dataSent) {
  int i;
  TrafficCounter tc;
  char buf[64];

  for(i=0, tc=0; i<24; i++) {
    if(dataSent)
      tc += el->last24HoursBytesSent[i];
    else
      tc += el->last24HoursBytesRcvd[i];
  }

  for(i=0; i<24; i++) {
    float pctg;

    if(tc > 0) {
      if(dataSent)
	pctg = (float)(el->last24HoursBytesSent[i]*100)/(float)tc;
      else
	pctg = (float)(el->last24HoursBytesRcvd[i]*100)/(float)tc;
    } else
      pctg = 0;

    if(snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT %s>&nbsp;</TD>",
		getBgPctgColor(pctg)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }
}

/* ******************************* */

int cmpHostsFctn(const void *_a, const void *_b) {
  struct hostTraffic **a = (struct hostTraffic **)_a;
  struct hostTraffic **b = (struct hostTraffic **)_b;
  char *name_a, *name_b;
  TrafficCounter a_=0, b_=0;
  int rc;

  switch(columnSort) {
  case 2: /* IP Address */
    if((*a)->hostIpAddress.s_addr > (*b)->hostIpAddress.s_addr)
      return(1);
    else if((*a)->hostIpAddress.s_addr < (*b)->hostIpAddress.s_addr)
      return(-1);
    else
      return(0);
    break;

  case 3: /* Data Sent */
    switch(sortFilter) {
    case REMOTE_TO_LOCAL_ACCOUNTING:
      a_ = (*a)->bytesSentLocally;
      b_ = (*b)->bytesSentLocally;
      break;
    case LOCAL_TO_REMOTE_ACCOUNTING:
      a_ = (*a)->bytesSentRemotely;
      b_ = (*b)->bytesSentRemotely;
      break;
    case LOCAL_TO_LOCAL_ACCOUNTING:
      a_ = (*a)->bytesSentLocally;
      b_ = (*b)->bytesSentLocally;
      break;
    }
    if(a_ < b_) return(1); else if (a_ > b_) return(-1); else return(0);
    break;

  case 4: /* Data Rcvd */
    switch(sortFilter) {
    case REMOTE_TO_LOCAL_ACCOUNTING:
      a_ = (*a)->bytesReceivedLocally;
      b_ = (*b)->bytesReceivedLocally;
      break;
    case LOCAL_TO_REMOTE_ACCOUNTING:
      a_ = (*a)->bytesReceivedFromRemote;
      b_ = (*b)->bytesReceivedFromRemote;
      break;
    case LOCAL_TO_LOCAL_ACCOUNTING:
      a_ = (*a)->bytesReceivedLocally;
      b_ = (*b)->bytesReceivedLocally;
      break;
    }
    if(a_ < b_) return(1); else if (a_ > b_) return(-1); else return(0);
    break;

  default: /* Host Name */
#ifdef MULTITHREADED
    accessMutex(&addressResolutionMutex, "cmpHostsFctn");
#endif

    name_a = (*a)->hostSymIpAddress;

    if(name_a == NULL)
      traceEvent(TRACE_WARNING, "Warning\n");
    if((name_a == NULL) || (strcmp(name_a, "0.0.0.0") == 0)) {
      name_a = (*a)->hostNumIpAddress;
      if((name_a == NULL) || (name_a[0] == '\0'))
	name_a = (*a)->ethAddressString;
    }

    name_b = (*b)->hostSymIpAddress;

    if(name_b == NULL)
      traceEvent(TRACE_WARNING, "Warning\n");
    if((name_b == NULL) || (strcmp(name_b, "0.0.0.0") == 0)) {
      name_b = (*b)->hostNumIpAddress;
      if((name_b == NULL) || (name_b[0] == '\0'))
	name_b = (*b)->ethAddressString;
    }

#ifdef MULTITHREADED
    releaseMutex(&addressResolutionMutex);
#endif

    rc = strcasecmp(name_a, name_b); /* case insensitive */

    return(rc);
  }
}

/* ************************************ */

void printPacketStats(HostTraffic *el) {
  char buf[BUF_SIZE];
  int headerSent = 0;
  char *tableHeader = "<center><TABLE BORDER=0><TR><TD>";

  /* *********************** */

  if(el->securityHostPkts != NULL) {
    if(((el->securityHostPkts->rejectedTCPConnSent.value+
	 el->securityHostPkts->rejectedTCPConnRcvd.value+
	 el->securityHostPkts->establishedTCPConnSent.value+
	 el->securityHostPkts->establishedTCPConnRcvd.value+
	 el->securityHostPkts->synPktsSent.value+
	 el->securityHostPkts->synPktsRcvd.value) > 0)) {

      if(!headerSent) { printSectionTitle("Packet Statistics"); sendString(tableHeader); headerSent = 1; }

      sendString("<CENTER>\n"
		 ""TABLE_ON"<TABLE BORDER=1 WIDTH=100%><TR><TH "TH_BG">TCP Connections</TH>"
		 "<TH "TH_BG" COLSPAN=2>Directed to</TH>"
		 "<TH "TH_BG" COLSPAN=2>Received From</TH></TR>\n");

      if((el->securityHostPkts->synPktsSent.value+el->securityHostPkts->synPktsRcvd.value) > 0) {
	sendString("<TR><TH "TH_BG" ALIGN=LEFT>Attempted</TH>");
	formatUsageCounter(el->securityHostPkts->synPktsSent, 0);
	formatUsageCounter(el->securityHostPkts->synPktsRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->establishedTCPConnSent.value+el->securityHostPkts->establishedTCPConnRcvd.value) > 0) {
	sendString("<TR><TH "TH_BG" ALIGN=LEFT>Established</TH>");
	formatUsageCounter(el->securityHostPkts->establishedTCPConnSent, el->securityHostPkts->synPktsSent.value);
	formatUsageCounter(el->securityHostPkts->establishedTCPConnRcvd, el->securityHostPkts->synPktsRcvd.value);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->rejectedTCPConnSent.value+el->securityHostPkts->rejectedTCPConnRcvd.value) > 0) {
	sendString("<TR><TH "TH_BG" ALIGN=LEFT>Rejected</TH>");
	formatUsageCounter(el->securityHostPkts->rejectedTCPConnSent, el->securityHostPkts->synPktsSent.value);
	formatUsageCounter(el->securityHostPkts->rejectedTCPConnRcvd, el->securityHostPkts->synPktsRcvd.value);
	sendString("</TR>\n");
      }

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }

    /* *********************** */

    if((el->securityHostPkts->synPktsSent.value+el->securityHostPkts->synPktsRcvd.value
	+el->securityHostPkts->rstAckPktsSent.value+el->securityHostPkts->rstAckPktsRcvd.value
	+el->securityHostPkts->rstPktsSent.value+el->securityHostPkts->rstPktsRcvd.value
	+el->securityHostPkts->synFinPktsSent.value+el->securityHostPkts->synFinPktsRcvd.value
	+el->securityHostPkts->finPushUrgPktsSent.value+el->securityHostPkts->finPushUrgPktsRcvd.value
	+el->securityHostPkts->nullPktsSent.value+el->securityHostPkts->nullPktsRcvd.value) > 0) {

      if(!headerSent) { printSectionTitle("Packet Statistics"); sendString(tableHeader); headerSent = 1; }

      sendString("<CENTER>\n"
		 ""TABLE_ON"<TABLE BORDER=1 WIDTH=100%><TR><TH "TH_BG">TCP Flags</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Sent</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Received</TH></TR>\n");

      if((el->securityHostPkts->synPktsSent.value+el->securityHostPkts->synPktsRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>SYN</TH>",
		    getRowColor()) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->synPktsSent, 0);
	formatUsageCounter(el->securityHostPkts->synPktsRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->rstAckPktsSent.value+el->securityHostPkts->rstAckPktsRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>RST|ACK</TH>",
		    getRowColor()) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->rstAckPktsSent, 0);
	formatUsageCounter(el->securityHostPkts->rstAckPktsRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->rstPktsSent.value+el->securityHostPkts->rstPktsRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>RST</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->rstPktsSent, 0);
	formatUsageCounter(el->securityHostPkts->rstPktsRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->synFinPktsSent.value+el->securityHostPkts->synFinPktsRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>SYN|FIN</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->synFinPktsSent, 0);
	formatUsageCounter(el->securityHostPkts->synFinPktsRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->finPushUrgPktsSent.value+el->securityHostPkts->finPushUrgPktsRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>FIN|PUSH|URG</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->finPushUrgPktsSent, 0);
	formatUsageCounter(el->securityHostPkts->finPushUrgPktsRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->nullPktsSent.value+el->securityHostPkts->nullPktsRcvd.value) > 0) {
	sendString("<TR><TH "TH_BG" ALIGN=LEFT>NULL</TH>");
	formatUsageCounter(el->securityHostPkts->nullPktsSent, 0);
	formatUsageCounter(el->securityHostPkts->nullPktsRcvd, 0);
	sendString("</TR>\n");
      }

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }

    /* *********************** */

    if(((el->securityHostPkts->ackScanSent.value+el->securityHostPkts->ackScanRcvd.value
	 +el->securityHostPkts->xmasScanSent.value+el->securityHostPkts->xmasScanRcvd.value
	 +el->securityHostPkts->finScanSent.value+el->securityHostPkts->finScanRcvd.value
	 +el->securityHostPkts->synFinPktsSent.value+el->securityHostPkts->synFinPktsRcvd.value
	 +el->securityHostPkts->nullScanSent.value+el->securityHostPkts->nullScanRcvd.value
	 +el->securityHostPkts->udpToClosedPortSent.value
	 +el->securityHostPkts->udpToClosedPortRcvd.value
	 +el->securityHostPkts->udpToDiagnosticPortSent.value
	 +el->securityHostPkts->udpToDiagnosticPortRcvd.value
	 +el->securityHostPkts->tcpToDiagnosticPortSent.value
	 +el->securityHostPkts->tcpToDiagnosticPortRcvd.value
	 +el->securityHostPkts->tinyFragmentSent.value
	 +el->securityHostPkts->tinyFragmentRcvd.value
	 +el->securityHostPkts->icmpFragmentSent.value
	 +el->securityHostPkts->icmpFragmentRcvd.value
	 +el->securityHostPkts->overlappingFragmentSent.value
	 +el->securityHostPkts->overlappingFragmentRcvd.value
	 +el->securityHostPkts->closedEmptyTCPConnSent.value
	 +el->securityHostPkts->closedEmptyTCPConnRcvd.value
	 +el->securityHostPkts->malformedPktsSent.value
	 +el->securityHostPkts->malformedPktsRcvd.value
	 ) > 0)) {

      if(!headerSent) { printSectionTitle("Packet Statistics"); sendString(tableHeader); headerSent = 1; }

      sendString("<CENTER>\n"
		 ""TABLE_ON"<TABLE BORDER=1 WIDTH=100%><TR><TH "TH_BG">Anomaly</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Sent&nbsp;to</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Received&nbsp;from</TH>"
		 "</TR>\n");

      if((el->securityHostPkts->ackScanSent.value+el->securityHostPkts->ackScanRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>ACK Scan</TH>",
		    getRowColor()) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->ackScanSent, 0);
	formatUsageCounter(el->securityHostPkts->ackScanRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->xmasScanSent.value+el->securityHostPkts->xmasScanRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>XMAS Scan</TH>",
		    getRowColor()) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->xmasScanSent, 0);
	formatUsageCounter(el->securityHostPkts->xmasScanRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->finScanSent.value+el->securityHostPkts->finScanRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>FIN Scan</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->finScanSent, 0);
	formatUsageCounter(el->securityHostPkts->finScanRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->nullScanSent.value+el->securityHostPkts->nullScanRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>NULL Scan</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->nullScanSent, 0);
	formatUsageCounter(el->securityHostPkts->nullScanRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->udpToClosedPortSent.value+
	  el->securityHostPkts->udpToClosedPortRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>UDP Pkt to Closed Port</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->udpToClosedPortSent, 0);
	formatUsageCounter(el->securityHostPkts->udpToClosedPortRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->udpToDiagnosticPortSent.value+
	  el->securityHostPkts->udpToDiagnosticPortRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>UDP Pkt Disgnostic Port</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->udpToDiagnosticPortSent, 0);
	formatUsageCounter(el->securityHostPkts->udpToDiagnosticPortRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->tcpToDiagnosticPortSent.value+
	  el->securityHostPkts->tcpToDiagnosticPortRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>TCP Pkt Disgnostic Port</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->tcpToDiagnosticPortSent, 0);
	formatUsageCounter(el->securityHostPkts->tcpToDiagnosticPortRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->tinyFragmentSent.value+
	  el->securityHostPkts->tinyFragmentRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Tiny Fragments</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->tinyFragmentSent, 0);
	formatUsageCounter(el->securityHostPkts->tinyFragmentRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->icmpFragmentSent.value+
	  el->securityHostPkts->icmpFragmentRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>ICMP Fragments</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->icmpFragmentSent, 0);
	formatUsageCounter(el->securityHostPkts->icmpFragmentRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->overlappingFragmentSent.value+
	  el->securityHostPkts->overlappingFragmentRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Overlapping Fragments</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->overlappingFragmentSent, 0);
	formatUsageCounter(el->securityHostPkts->overlappingFragmentRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->closedEmptyTCPConnSent.value+
	  el->securityHostPkts->closedEmptyTCPConnRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Closed Empty TCP Conn.</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->closedEmptyTCPConnSent, 0);
	formatUsageCounter(el->securityHostPkts->closedEmptyTCPConnRcvd, 0);
	sendString("</TR>\n");
      }

      if((el->securityHostPkts->malformedPktsSent.value+
	  el->securityHostPkts->malformedPktsRcvd.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Malformed Pkts</TH>",
		    getRowColor()) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
	formatUsageCounter(el->securityHostPkts->malformedPktsSent, 0);
	formatUsageCounter(el->securityHostPkts->malformedPktsRcvd, 0);
	sendString("</TR>\n");
      }

      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }
  }

  if(el->arpReqPktsSent+el->arpReplyPktsSent+el->arpReplyPktsRcvd > 0) {
    if(!headerSent) {
      printSectionTitle("Packet Statistics");
      sendString(tableHeader);
      headerSent = 1;
    }

    sendString("<CENTER>\n"
	       ""TABLE_ON"<TABLE BORDER=1 WIDTH=100%><TR>"
	       "<TH "TH_BG">ARP</TH>"
	       "<TH "TH_BG">Packet</TH>"
	       "</TR>\n");

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Request Sent</TH>"
		"<TD "TH_BG" ALIGN=RIGHT>%s</TD></TR>",
		getRowColor(),
		formatPkts(el->arpReqPktsSent)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Reply Rcvd</TH>"
		"<TD "TH_BG" ALIGN=RIGHT>%s (%.1f %%)</TD></TR>",
		getRowColor(),
		formatPkts(el->arpReplyPktsRcvd),
		((el->arpReqPktsSent > 0) ?
		(float)((el->arpReplyPktsRcvd*100)/(float)el->arpReqPktsSent) : 0)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Reply Sent</TH>"
		"<TD "TH_BG" ALIGN=RIGHT>%s</TD></TR>",
		getRowColor(),
		formatPkts(el->arpReplyPktsSent)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");
  }

  if(headerSent) { sendString("</TD></TR></TABLE></center>"); }
}

/* ************************************ */

void printHostTrafficStats(HostTraffic *el) {
  int i, a, b;
  TrafficCounter totalSent, totalReceived;
  TrafficCounter actTotalSent, actTotalReceived;
  char buf[BUF_SIZE];

  totalSent = el->tcpSentLocally+el->tcpSentRemotely+el->udpSentLocally+el->udpSentRemotely;
  totalSent += el->icmpSent+el->ospfSent+el->igmpSent+el->ipxSent+el->dlcSent+el->arp_rarpSent;
  totalSent +=  el->decnetSent+el->appletalkSent+el->netbiosSent+
    el->osiSent+el->qnxSent+el->stpSent+el->otherSent;

  totalReceived = el->tcpReceivedLocally+el->tcpReceivedFromRemote;
  totalReceived += el->udpReceivedLocally+el->udpReceivedFromRemote;
  totalReceived += el->icmpReceived+el->ospfReceived+el->igmpReceived;
  totalReceived += el->ipxReceived+el->dlcReceived+el->arp_rarpReceived;
  totalReceived += el->decnetReceived+el->appletalkReceived;
  totalReceived += el->osiReceived+el->netbiosReceived+el->qnxReceived
    +el->stpReceived+el->otherReceived;

  actTotalSent = el->tcpSentLocally+el->tcpSentRemotely;
  actTotalReceived = el->tcpReceivedLocally+el->tcpReceivedFromRemote;

  printHostEvents(el, -1, -1);
  printHostHourlyTraffic(el);
  printPacketStats(el);

  if((totalSent == 0 ) && (totalReceived == 0))
    return;

  printSectionTitle("Protocol Distribution");

  sendString("<CENTER>\n"
	     ""TABLE_ON"<TABLE BORDER=1><TR><TH "TH_BG" WIDTH=100>Protocol</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Sent</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Received</TH></TR>\n");

  printTableDoubleEntry(buf, sizeof(buf), "TCP", COLOR_1, (float)actTotalSent/1024,
			100*((float)SD(actTotalSent, totalSent)),
			(float)actTotalReceived/1024,
			100*((float)SD(actTotalReceived, totalReceived)));

  actTotalSent = el->udpSentLocally+el->udpSentRemotely;
  actTotalReceived = el->udpReceivedLocally+el->udpReceivedFromRemote;

/*#if 0 */
  printTableDoubleEntry(buf, sizeof(buf), "UDP", COLOR_1, (float)actTotalSent/1024,
			100*((float)SD(actTotalSent, totalSent)),
			(float)actTotalReceived/1024,
			100*((float)SD(actTotalReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "ICMP", COLOR_1, (float)el->icmpSent/1024,
			100*((float)SD(el->icmpSent, totalSent)),
			(float)el->icmpReceived/1024,
			100*((float)SD(el->icmpReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "(R)ARP", COLOR_1, (float)el->arp_rarpSent/1024,
			100*((float)SD(el->arp_rarpSent, totalSent)),
			(float)el->arp_rarpReceived/1024,
			100*((float)SD(el->arp_rarpReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "DLC", COLOR_1, (float)el->dlcSent/1024,
			100*((float)SD(el->dlcSent, totalSent)),
			(float)el->dlcReceived/1024,
			100*((float)SD(el->dlcReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "IPX", COLOR_1, (float)el->ipxSent/1024,
			100*((float)SD(el->ipxSent, totalSent)),
			(float)el->ipxReceived/1024,
			100*((float)SD(el->ipxReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "Decnet", COLOR_1, (float)el->decnetSent/1024,
			100*((float)SD(el->decnetSent, totalSent)),
			(float)el->decnetReceived/1024,
			100*((float)SD(el->decnetReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "AppleTalk", COLOR_1, (float)el->appletalkSent/1024,
			100*((float)SD(el->appletalkSent, totalSent)),
			(float)el->appletalkReceived/1024,
			100*((float)SD(el->appletalkReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "OSPF", COLOR_1, (float)el->ospfSent/1024,
			100*((float)SD(el->ospfSent, totalSent)),
			(float)el->ospfReceived/1024,
			100*((float)SD(el->ospfReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "NetBios", COLOR_1, (float)el->netbiosSent/1024,
			100*((float)SD(el->netbiosSent, totalSent)),
			(float)el->netbiosReceived/1024,
			100*((float)SD(el->netbiosReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "IGMP", COLOR_1, (float)el->igmpSent/1024,
			100*((float)SD(el->igmpSent, totalSent)),
			(float)el->igmpReceived/1024,
			100*((float)SD(el->igmpReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "OSI", COLOR_1, (float)el->osiSent/1024,
			100*((float)SD(el->osiSent, totalSent)),
			(float)el->osiReceived/1024,
			100*((float)SD(el->osiReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "QNX", COLOR_1, (float)el->qnxSent/1024,
			100*((float)SD(el->qnxSent, totalSent)),
			(float)el->qnxReceived/1024,
			100*((float)SD(el->qnxReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "STP", COLOR_1, (float)el->stpSent/1024,
			100*((float)SD(el->stpSent, totalSent)),
			(float)el->stpReceived/1024,
			100*((float)SD(el->stpReceived, totalReceived)));

  printTableDoubleEntry(buf, sizeof(buf), "Other", COLOR_1, (float)el->otherSent/1024,
			100*((float)SD(el->otherSent, totalSent)),
			(float)el->otherReceived/1024,
			100*((float)SD(el->otherReceived, totalReceived)));
/*#endif */

#ifdef HAVE_GDCHART
  {
    totalSent = el->tcpSentLocally+el->tcpSentRemotely+
      el->udpSentLocally+el->udpSentRemotely+
      el->icmpSent+el->ospfSent+el->igmpSent+el->stpSent+
      el->ipxSent+el->osiSent+el->dlcSent+
      el->arp_rarpSent+el->decnetSent+el->appletalkSent+
      el->netbiosSent+el->qnxSent+el->otherSent;

    totalReceived = el->tcpReceivedLocally+el->tcpReceivedFromRemote+
      el->udpReceivedLocally+el->udpReceivedFromRemote+
      el->icmpReceived+el->ospfReceived+el->igmpReceived+el->stpReceived+
      el->ipxReceived+el->osiReceived+el->dlcReceived+
      el->arp_rarpReceived+el->decnetReceived+el->appletalkReceived+
      el->netbiosReceived+el->qnxReceived+el->otherReceived;

    if((totalSent > 0) || (totalReceived > 0)) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Protocol Distribution</TH>",
		  getRowColor()) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(totalSent > 0) {
	if(snprintf(buf, sizeof(buf),
		    "<TD "TH_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostTrafficDistrib-%s"CHART_FORMAT"?1></TD>",
		    el->hostNumIpAddress[0] == '\0' ?  el->ethAddressString : el->hostNumIpAddress) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      } else {
	sendString("<TD "TH_BG" ALIGN=RIGHT COLSPAN=2>&nbsp;</TD>");
      }

      if(totalReceived > 0) {
	if(snprintf(buf, sizeof(buf),
		    "<TD "TH_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostTrafficDistrib-%s"CHART_FORMAT"></TD>",
		    el->hostNumIpAddress[0] == '\0' ?  el->ethAddressString : el->hostNumIpAddress) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      } else {
	sendString("<TD "TH_BG" ALIGN=RIGHT COLSPAN=2>&nbsp;</TD>");
      }


      sendString("</TD></TR>");
    }

#if 0
  if(((el->tcpSentLocally+el->tcpSentRemotely+
       el->udpSentLocally+el->udpSentRemotely+
       el->icmpSent+el->ospfSent+el->igmpSent+el->stpSent
       +el->ipxSent+el->osiSent+el->dlcSent+
       el->arp_rarpSent+el->decnetSent+el->appletalkSent+
       el->netbiosSent+el->qnxSent+el->otherSent) > 0)
     && ((el->tcpReceivedLocally+el->tcpReceivedFromRemote+
      el->udpReceivedLocally+el->udpReceivedFromRemote+
      el->icmpReceived+el->ospfReceived+el->igmpReceived+el->stpReceived
      +el->ipxReceived+el->osiReceived+el->dlcReceived+
      el->arp_rarpReceived+el->decnetReceived+el->appletalkReceived+
	  el->netbiosReceived+el->qnxReceived+el->otherReceived) > 0)) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>Protocol Distribution</TH>"
		"<TD "TH_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostTrafficDistrib-%s"CHART_FORMAT"?1>"
		"</TD>"
		"<TD "TH_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostTrafficDistrib-%s"CHART_FORMAT">"
		"</TD></TR>",
		getRowColor(),
		el->hostNumIpAddress,
		el->hostNumIpAddress) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }
#endif

  }
#endif

#ifndef ENABLE_NAPSTER
  a = b = 0;
#else
  if(el->napsterStats == NULL)
    a = 0, b = 0;
  else
    a = el->napsterStats->bytesSent, b = el->napsterStats->bytesRcvd;
#endif

  for(i=0; i<numIpProtosToMonitor; i++) {
    a += el->protoIPTrafficInfos[i].sentLocally+
      el->protoIPTrafficInfos[i].sentRemotely;
    b += el->protoIPTrafficInfos[i].receivedLocally+
      el->protoIPTrafficInfos[i].receivedFromRemote;
  }

  if((a > 0) && (b > 0)) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>IP Distribution</TH>"
		"<TD "TH_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostIPTrafficDistrib-%s"CHART_FORMAT"?1>"
		"</TD>"
		"<TD "TH_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostIPTrafficDistrib-%s"CHART_FORMAT">"
		"</TD></TR>",
		getRowColor(),
		el->hostNumIpAddress,
		el->hostNumIpAddress) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");
}

/* ************************************ */

void printHostContactedPeers(HostTraffic *el) {
  u_int numEntries, i;
  char buf[BUF_SIZE];

  if((el->pktSent != 0) || (el->pktReceived != 0)) {
    int ok =0;

    for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
      if((el->contactedSentPeers.peersIndexes[i] != NO_PEER)
	 || (el->contactedRcvdPeers.peersIndexes[i] != NO_PEER)) {
	ok = 1;
	break;
      }

    if(ok) {
      struct hostTraffic *el1;

      printSectionTitle("Last Contacted Peers");
      sendString("<CENTER>\n"
		 "<TABLE BORDER=0 WIDTH=100%%><TR><TD "TD_BG" VALIGN=TOP>\n");

      for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	if(el->contactedSentPeers.peersIndexes[i] != NO_PEER) {
	  el1 = device[actualReportDeviceId].hash_hostTraffic[
		       checkSessionIdx(el->contactedSentPeers.peersIndexes[i])];

	  if(el1 != NULL) {
	    if(numEntries == 0) {
	      sendString(""TABLE_ON"<TABLE BORDER=1 VALIGN=TOP WIDTH=100%%>"
			 "<TR><TH "TH_BG">Receiver Name</TH>"
			 "<TH "TH_BG">Receiver Address</TH></TR>\n");
	    }

	    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		    "<TD "TD_BG"  ALIGN=CENTER>%s&nbsp;</TD></TR>\n",
		    getRowColor(),
		    makeHostLink(el1, 0, 0, 0),
		    el1->hostNumIpAddress) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");

	    sendString(buf);
	    numEntries++;
	  }
	}

      if(numEntries > 0)
	sendString("</TABLE>"TABLE_OFF"</TD><TD "TD_BG" VALIGN=TOP>\n");
      else
	sendString("&nbsp;</TD><TD "TD_BG">\n");

      /* ***************************************************** */
      for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	if(el->contactedRcvdPeers.peersIndexes[i] != NO_PEER) {
	  el1 = device[actualReportDeviceId].hash_hostTraffic[
                       checkSessionIdx(el->contactedRcvdPeers.peersIndexes[i])];

	  if(el1 != NULL) {
	    if(numEntries == 0) {
	      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=100%%>"
			 "<TR><TH "TH_BG">Sender Name</TH>"
			 "<TH "TH_BG">Sender Address</TH></TR>\n");
	    }

	    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		     "<TD "TD_BG"  ALIGN=CENTER>%s&nbsp;</TD></TR>\n",
		    getRowColor(),
		    makeHostLink(el1, 0, 0, 0),
		    el1->hostNumIpAddress) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");

	    sendString(buf);
	    numEntries++;
	  }
	}

      if(numEntries > 0)
	sendString("</TABLE>"TABLE_OFF"\n");

      sendString("</TD></TR></TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    } /* ok */
  }
}

/* ************************************ */

/* Function below courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */

char *getSessionState(IPSession *session) {
  switch (session->sessionState) {
  case STATE_SYN:
    return("Sent Syn");
  case STATE_SYN_ACK:
    return("Rcvd Syn/Ack");
  case STATE_ACTIVE:
    return("Active");
  case STATE_FIN1_ACK0:
    return("Fin1 Ack0");
  case STATE_FIN1_ACK1:
    return("Fin1 Ack1");
  case STATE_FIN2_ACK0:
    return("Fin2 Ack0");
  case STATE_FIN2_ACK1:
    return("Fin2 Ack1");
  case STATE_FIN2_ACK2:
    return("Fin2 Ack2");
  case STATE_TIMEOUT:
    return("Timeout");
  case STATE_END:
    return("End");
  }

 return("*Unknown*");
}

/* ************************************ */

void printHostSessions(HostTraffic *el, u_int elIdx) {
  char buf[BUF_SIZE];
  IpGlobalSession *scanner=NULL;
  char *sessionType=NULL;
  u_short numSessions;
  u_int idx, i, sessionIdx;
  static char _sport[8], _dport[8];

  for(sessionIdx=0; sessionIdx<2; sessionIdx++) {
    if(sessionIdx == 0) {
      if(el->tcpSessionList != NULL) {
	printSectionTitle("IP Session History");
      }

      scanner = el->tcpSessionList;
      sessionType = "TCP";
    } else {
      if(el->udpSessionList != NULL) {
	printSectionTitle("IP Session History");
      }

      scanner = el->udpSessionList;
      sessionType = "UDP";
    }

    numSessions = 0;

    while(scanner != NULL) {
      char *whoswho, *svc=NULL, tmpSvc[16];

      if(scanner->initiator == CLIENT_ROLE)
	whoswho= "client";
      else
	whoswho= "server";

      if(sessionIdx == 0)
	svc = getPortByNum((int)(scanner->port), IPPROTO_TCP);
      else
	svc = getPortByNum((int)(scanner->port), IPPROTO_UDP);

      if(svc == NULL) {
	if(snprintf(tmpSvc, sizeof(tmpSvc), "%d", (int)(scanner->port)) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	svc = tmpSvc;
      }

      if(numSessions == 0) {
	sendString("<CENTER>\n");
	if(snprintf(buf, sizeof(buf), ""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\">\n<TR>"
		    "<TH "TH_BG" COLSPAN=2>%s&nbsp;Service</TH>"
		    "<TH "TH_BG">Role</TH><TH "TH_BG">"
		    "#&nbsp;Sessions</TH>"
		    "<TH "TH_BG">Bytes&nbsp;Sent</TH>"
		    "<TH "TH_BG">Bytes&nbsp;Rcvd</TH>"
		    "<TH "TH_BG">Last&nbsp;Seen</TH>"
		    "<TH "TH_BG">First&nbsp;Seen</TH>"
		    "<TH "TH_BG">Peers</TH></TR>\n",
		    sessionType) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=RIGHT>%s</TH>"
		  "<TD "TD_BG"  ALIGN=CENTER>%d</TD>"
		  "<TD "TD_BG"  ALIGN=CENTER>%s</TD><TD "TD_BG"  ALIGN=CENTER>%d"
		  "</TD><TD "TD_BG"  ALIGN=CENTER>%s</TD>"
		  "<TD "TD_BG"  ALIGN=CENTER>%s</TD><TD "TD_BG">"
		  "%s</TD><TD "TD_BG">%s</TD>\n",
		  getRowColor(), svc, scanner->port, whoswho,
		  (int)scanner->sessionCounter,
		  formatBytes(scanner->bytesSent, 1),
		  formatBytes(scanner->bytesReceived, 1),
		  formatTime(&(scanner->lastSeen), 1),
		  formatTime(&(scanner->firstSeen), 1)
		  ) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
      numSessions++;

      sendString("<TD "TD_BG"><UL>&nbsp;");
      for(i=0; i < MAX_NUM_CONTACTED_PEERS; i++) {
	u_int theIdx = scanner->peers.peersIndexes[i];

	if((theIdx != NO_PEER)
	   && (device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(theIdx)] != NULL)) {
	  HostTraffic *host = device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(theIdx)];

	  if(host != NULL) {
#ifdef MULTITHREADED
	    accessMutex(&addressResolutionMutex, "printSession");
#endif
	    if(host->hostNumIpAddress[0] == '&') {
	      if(snprintf(buf, sizeof(buf), "<LI>%s\n", host->hostSymIpAddress) < 0)
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	    } else {
	      if(snprintf(buf, sizeof(buf), "<LI><A HREF=%s.html>%s</A>\n",
			  host->hostNumIpAddress, host->hostSymIpAddress) < 0)
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	    }
#ifdef MULTITHREADED
	    releaseMutex(&addressResolutionMutex);
#endif
	    sendString(buf);
	  }
	}
      }
      sendString("</UL></TR>\n");

      scanner = (IpGlobalSession*)(scanner->next);
    }

    if(numSessions > 0) {
      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }

    if(sessionIdx == 0) {
      /* Now print currently established TCP sessions (if any) */
      for(idx=1, numSessions=0; idx<device[actualReportDeviceId].numTotSessions; idx++)
	if((device[actualReportDeviceId].tcpSession[idx] != NULL)
	   && ((device[actualReportDeviceId].tcpSession[idx]->initiatorIdx == elIdx)
	       || (device[actualReportDeviceId].tcpSession[idx]->remotePeerIdx == elIdx))
#ifndef PRINT_ALL_ACTIVE_SESSIONS
	   && (device[actualReportDeviceId].tcpSession[idx]->sessionState == STATE_ACTIVE)
#endif
	   ) {
	  char *sport, *dport, *remotePeer;
	  TrafficCounter dataSent, dataReceived, retrDataSent, retrDataRcvd;
	  TrafficCounter fragDataSent, fragDataRcvd;
	  int retrSentPercentage, retrRcvdPercentage;
	  char fragStrSent[64], fragStrRcvd[64], *moreSessionInfo;

	  if(device[actualReportDeviceId].
	     tcpSession[idx]->remotePeerIdx == NO_PEER) /* This should not happen */
	    continue;

	  if(numSessions == 0) {
	    printSectionTitle("Active TCP Sessions");
	    sendString("<CENTER>\n");
	    sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\"><TR>"
		       "<TH "TH_BG">Local&nbsp;Port</TH>"
		       "<TH "TH_BG">Remote&nbsp;Peer:Port</TH>"
		       "<TH "TH_BG">Data&nbsp;Sent</TH>"
#ifdef PRINT_RETRANSMISSION_DATA
		       "<TH "TH_BG">Retran.&nbsp;Data&nbsp;Sent</TH>"
#endif
		       "<TH "TH_BG">Data&nbsp;Rcvd</TH>"
#ifdef PRINT_RETRANSMISSION_DATA
		       "<TH "TH_BG">Retran.&nbsp;Data&nbsp;Rcvd</TH>"
#endif
		       "<TH "TH_BG">Window&nbsp;Size</TH>"
		       "<TH "TH_BG">Active&nbsp;Since</TH>"
		       "<TH "TH_BG">Last&nbsp;Seen</TH>"
		       "<TH "TH_BG">Duration</TH>"
		       "<TH "TH_BG">Latency</TH>"
#ifdef PRINT_ALL_ACTIVE_SESSIONS
		       "<TH "TH_BG">State</TH>"
#endif
		       "</TR>\n");
	  }

	  if(device[actualReportDeviceId].tcpSession[idx]->initiatorIdx == elIdx) {
	    sport = getPortByNum(device[actualReportDeviceId].tcpSession[idx]->sport, IPPROTO_TCP);
	    dport = getPortByNum(device[actualReportDeviceId].tcpSession[idx]->dport, IPPROTO_TCP);
	    if(sport == NULL) {
	      if(snprintf(_sport, sizeof(_sport), "%d",
			  device[actualReportDeviceId].tcpSession[idx]->sport) < 0)
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	      sport = _sport;
	    }

	    if(dport == NULL) {
	      if(snprintf(_dport, sizeof(_dport), "%d",
			  device[actualReportDeviceId].tcpSession[idx]->dport) < 0)
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	      dport = _dport;
	    }
	    remotePeer = makeHostLink(device[actualReportDeviceId].
				      hash_hostTraffic[checkSessionIdx(device[actualReportDeviceId].
								       tcpSession[idx]->remotePeerIdx)],
				      SHORT_FORMAT, 0, 0);
	    dataSent     = device[actualReportDeviceId].tcpSession[idx]->bytesSent;
	    dataReceived = device[actualReportDeviceId].tcpSession[idx]->bytesReceived;
	    retrDataSent = device[actualReportDeviceId].tcpSession[idx]->bytesRetranI2R;
	    retrDataRcvd = device[actualReportDeviceId].tcpSession[idx]->bytesRetranR2I;
	    fragDataSent = device[actualReportDeviceId].tcpSession[idx]->bytesFragmentedSent;
	    fragDataRcvd = device[actualReportDeviceId].tcpSession[idx]->bytesFragmentedReceived;
	  } else {
	    /* Responder */
	    sport = getPortByNum(device[actualReportDeviceId].tcpSession[idx]->dport, IPPROTO_TCP);
	    dport = getPortByNum(device[actualReportDeviceId].tcpSession[idx]->sport, IPPROTO_TCP);
	    if(sport == NULL) {
	      if(snprintf(_sport, sizeof(_sport), "%d",
			  device[actualReportDeviceId].tcpSession[idx]->dport) < 0)
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	      sport = _sport;
	    }

	    if(dport == NULL) {
	      if(snprintf(_dport, sizeof(_dport), "%d",
			  device[actualReportDeviceId].tcpSession[idx]->sport) < 0)
		traceEvent(TRACE_ERROR, "Buffer overflow!");
	      dport = _dport;
	    }

	    remotePeer = makeHostLink(device[actualReportDeviceId].
				      hash_hostTraffic[checkSessionIdx(device[actualReportDeviceId].
								       tcpSession[idx]->initiatorIdx)],
				      SHORT_FORMAT, 0, 0);
	    dataSent     = device[actualReportDeviceId].tcpSession[idx]->bytesReceived;
	    dataReceived = device[actualReportDeviceId].tcpSession[idx]->bytesSent;
	    retrDataSent = device[actualReportDeviceId].tcpSession[idx]->bytesRetranR2I;
	    retrDataRcvd = device[actualReportDeviceId].tcpSession[idx]->bytesRetranI2R;
	    fragDataSent = device[actualReportDeviceId].tcpSession[idx]->bytesFragmentedReceived;
	    fragDataRcvd = device[actualReportDeviceId].tcpSession[idx]->bytesFragmentedSent;
	  }

	  /* Sanity check */
	  if((actTime < device[actualReportDeviceId].tcpSession[idx]->firstSeen)
	     || (device[actualReportDeviceId].tcpSession[idx]->firstSeen == 0))
	    device[actualReportDeviceId].tcpSession[idx]->firstSeen = actTime;

	  retrSentPercentage = (int)((float)(retrDataSent*100))/((float)(dataSent+1));
	  retrRcvdPercentage = (int)((float)(retrDataRcvd*100))/((float)(dataReceived+1));

	  if(fragDataSent == 0)
	    fragStrSent[0] = '\0';
	  else {
	    if(snprintf(fragStrSent, sizeof(fragStrSent), "(%.1f fragmented)",
			(int)((float)(fragDataSent*100))/((float)(dataSent+1))) < 0)
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	  }
	  if(fragDataRcvd == 0)
	    fragStrRcvd[0] = '\0';
	  else {
	    if(snprintf(fragStrRcvd, sizeof(fragStrRcvd), "(%.1f fragmented)",
			(int)((float)(fragDataRcvd*100))/((float)(dataReceived+1))) < 0)
	      traceEvent(TRACE_ERROR, "Buffer overflow!");
	  }

#ifndef ENABLE_NAPSTER
	  moreSessionInfo = "";
#else
	  if(device[actualReportDeviceId].tcpSession[idx]->napsterSession)
	    moreSessionInfo = "&nbsp;[Napster]";
	  else
	    moreSessionInfo = "";
#endif

	  if(device[actualReportDeviceId].tcpSession[idx]->passiveFtpSession)
	    moreSessionInfo = "&nbsp;[FTP]";
	  else
	    moreSessionInfo = "";

	  if(snprintf(buf, sizeof(buf), "<TR %s>"
		      "<TD "TD_BG"  ALIGN=RIGHT>%s%s</TD>"
		      "<TD "TD_BG"  ALIGN=RIGHT>%s:%s</TD>"
		      "<TD "TD_BG"  ALIGN=RIGHT>%s %s</TD>"
#ifdef PRINT_RETRANSMISSION_DATA
		      "<TD "TD_BG"  ALIGN=RIGHT>%s [%d%%]</TD>"
#endif
		      "<TD "TD_BG"  ALIGN=RIGHT>%s %s</TD>"
#ifdef PRINT_RETRANSMISSION_DATA
		      "<TD "TD_BG"  ALIGN=RIGHT>%s [%d%%]</TD>"
#endif
		      , getRowColor(),
		      sport, moreSessionInfo,
		      remotePeer, dport,
		      formatBytes(dataSent, 1), fragStrSent,
#ifdef PRINT_RETRANSMISSION_DATA
		      formatBytes(retrDataSent, 1),
		      retrSentPercentage,
#endif
		      formatBytes(dataReceived, 1), fragStrRcvd
#ifdef PRINT_RETRANSMISSION_DATA
		      , formatBytes(retrDataRcvd, 1),
		      retrRcvdPercentage
#endif
		      ) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");

	  sendString(buf);

	  if(snprintf(buf, sizeof(buf),
		      "<TD "TD_BG"  ALIGN=CENTER NOWRAP>%d:%d</TD>"
		      "<TD "TD_BG"  ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG"  ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG"  ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG"  ALIGN=RIGHT>%s</TD>"
#ifdef PRINT_ALL_ACTIVE_SESSIONS
		      "<TD "TD_BG"  ALIGN=CENTER>%s</TD>"
#endif
		      "</TR>\n",
		      device[actualReportDeviceId].tcpSession[idx]->minWindow,
		      device[actualReportDeviceId].tcpSession[idx]->maxWindow,
		      formatTime(&(device[actualReportDeviceId].tcpSession[idx]->firstSeen), 1),
		      formatTime(&(device[actualReportDeviceId].tcpSession[idx]->lastSeen), 1),
		      formatSeconds(actTime-device[actualReportDeviceId].tcpSession[idx]->firstSeen),
		      formatLatency(device[actualReportDeviceId].tcpSession[idx]->nwLatency,
				    device[actualReportDeviceId].tcpSession[idx]->sessionState)
#ifdef PRINT_ALL_ACTIVE_SESSIONS
		      , getSessionState(device[actualReportDeviceId].tcpSession[idx])
#endif
		      ) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");

	  sendString(buf);

	  numSessions++;
	}

      if(numSessions > 0) {
	sendString("</TABLE>"TABLE_OFF"<P>\n");
	sendString("</CENTER>\n");
      }
    }
  }
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

  if(hasDuplicatedMac(el)) {
    if(riskFactor < 2) riskFactor = 2;
  }

  return(riskFactor);
}

/* ************************************ */

static void checkHostHealthness(HostTraffic *el) {
  char buf[BUF_SIZE];

  if(hasWrongNetmask(el)
     || hasDuplicatedMac(el)
     ) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s "
		"<IMG SRC=/Risk_high.gif> <IMG SRC=/Risk_medium.gif> <IMG SRC=/Risk_low.gif>"
		"</TH><TD "TD_BG" ALIGN=RIGHT NOWRAP><OL>", getRowColor(),
		"Network Healthness") < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

    if(hasWrongNetmask(el))
      sendString("<LI><IMG SRC=/Risk_medium.gif><A HREF=/help.html#1>"
		 "Wrong network mask or bridging enabled</A>\n");

    if(hasDuplicatedMac(el))
      sendString("<LI><IMG SRC=/Risk_high.gif><A HREF=/help.html#2>"
		 "Duplicated MAC found for this IP address (spoofing?)</A>\n");

    sendString("</OL></TD></TR>\n");
  }
}

/* ************************************ */

void printHostDetailedInfo(HostTraffic *el) {
  char buf[BUF_SIZE], buf1[64], sniffedName[MAXDNAME];
  float percentage;
  int printedHeader, i;
  char *dynIp, *multihomed;

#ifdef MULTITHREADED
  accessMutex(&addressResolutionMutex, "printAllSessionsHTML");
#endif

  buf1[0]=0;
  if(getSniffedDNSName(el->hostNumIpAddress, sniffedName, sizeof(sniffedName))) {
    if(el->hostSymIpAddress[0] == '\0' || strcmp(sniffedName, el->hostSymIpAddress))
      snprintf(buf1, sizeof(buf1), " (%s)", sniffedName);
  }

  if(el->hostSymIpAddress[0] == '\0') {
    if(snprintf(buf, sizeof(buf), "Info about host %s",
	    el->ethAddressString) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  } else {
    if(el->hostNumIpAddress[0] == '\0') {
    if(snprintf(buf, sizeof(buf), "Info about host %s", el->hostSymIpAddress) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");    
    } else {
      if(snprintf(buf, sizeof(buf), "Info about host"
		  " <A HREF=http://%s/>%s %s</A>\n",
		  el->hostNumIpAddress, el->hostSymIpAddress, buf1) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    }
  }

#ifdef MULTITHREADED
  releaseMutex(&addressResolutionMutex);
#endif

  printHTMLheader(buf, 0);
  sendString("<CENTER>\n");
  sendString("<P>"TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\">\n");

  if(el->hostNumIpAddress[0] != '\0') {
    char *countryIcon, *hostType;

#ifdef MULTITHREADED
    accessMutex(&addressResolutionMutex, "printAllSessions-2");
#endif

    /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
    if(strcmp(el->hostNumIpAddress, el->hostSymIpAddress) != 0) {
#ifdef MULTITHREADED
      releaseMutex(&addressResolutionMutex);
#endif
      countryIcon = getHostCountryIconURL(el);
    } else {
#ifdef MULTITHREADED
      releaseMutex(&addressResolutionMutex);
#endif
      countryIcon = "";
    }

    if(broadcastHost(el)) hostType = "broadcast";
    else if(multicastHost(el)) hostType = "multicast";
    else hostType = "unicast";

    if(isDHCPClient(el))
      dynIp = "/dynamic";
    else
      dynIp = "";

    if(isMultihomed(el))
      multihomed = "&nbsp;-&nbsp;multihomed&nbsp;<IMG SRC=/multihomed.gif BORDER=0>";
    else
      multihomed = "";

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		"<TD "TD_BG"  ALIGN=RIGHT>%s&nbsp;%s&nbsp;[%s%s%s]",
		getRowColor(),
		"IP&nbsp;Address",
		el->hostNumIpAddress,
		countryIcon, hostType, dynIp, multihomed) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

    sendString("</TD></TR>\n");

    if(isMultihomed(el)) {
      u_int elIdx;

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT><OL>",
		  getRowColor(), "Multihomed Addresses") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      for(elIdx=1; elIdx<device[actualReportDeviceId].actualHashSize; elIdx++) {
	HostTraffic *theHost = device[actualReportDeviceId].hash_hostTraffic[elIdx];

	if((theHost != NULL)
	   && (theHost != el)
	   && (memcmp(theHost->ethAddress, el->ethAddress, ETHERNET_ADDRESS_LEN) == 0)) {
	  if(snprintf(buf, sizeof(buf), "<LI><A HREF=/%s.html>%s</A>",
		      theHost->hostNumIpAddress, theHost->hostNumIpAddress) < 0)
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	  sendString(buf);
	}
      }
      
      sendString("</TD></TR>");
    }

    if(el->dhcpStats != NULL) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>",
		  getRowColor(), "DHCP Information") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      sendString("<TD "TD_BG"><TABLE BORDER WIDTH=100%%>\n");

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n", getRowColor(), "DHCP Server",
		  _intoa(el->dhcpStats->dhcpServerIpAddress, buf1, sizeof(buf1))) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n", getRowColor(), "Previous IP Address",
		  _intoa(el->dhcpStats->previousIpAddress, buf1, sizeof(buf1))) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n",
		  getRowColor(), "Address Assigned on",
		  formatTime(&(el->dhcpStats->assignTime), 1)) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n",
		  getRowColor(), "To be Renewed Before",
		  formatTime(&(el->dhcpStats->renewalTime), 1)) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n",
		  getRowColor(), "Lease Ends on",
		  formatTime(&(el->dhcpStats->leaseTime), 1)) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);


      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>DHCP Packets</TH>"
		  "<TH "TH_BG" ALIGN=CENTER>Sent</TH><TH "TH_BG" ALIGN=RIGHT>Rcvd</TH></TR>\n",
		  getRowColor()) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Discover",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_DISCOVER_MSG]),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_DISCOVER_MSG])) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Offer",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_OFFER_MSG]),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_OFFER_MSG])) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Request",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_REQUEST_MSG]),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_REQUEST_MSG])) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Decline",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_DECLINE_MSG]),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_DECLINE_MSG])) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Ack",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_ACK_MSG]),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_ACK_MSG])) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Nack",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_NACK_MSG]),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_NACK_MSG])) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Release",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_RELEASE_MSG]),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_RELEASE_MSG])) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);


      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Inform",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_INFORM_MSG]),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_INFORM_MSG])) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);


      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Unknown Msg",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_UNKNOWN_MSG]),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_UNKNOWN_MSG])) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      sendString("</TABLE></TD></TR>\n");
    }
  }

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
	      "<TD "TD_BG"  ALIGN=RIGHT>"
	  "%s&nbsp;&nbsp;-&nbsp;&nbsp;%s&nbsp;[%s]</TD></TR>\n",
	   getRowColor(),
	   "First/Last&nbsp;Seen",
           formatTime(&(el->firstSeen), 1),
           formatTime(&(el->lastSeen), 1),
	   formatSeconds(el->lastSeen - el->firstSeen)) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(el->fullDomainName && (el->fullDomainName[0] != '\0')) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
	    "%s</TD></TR>\n",
	    getRowColor(),
	    "Domain", el->fullDomainName) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }

  if((el->ethAddressString[0] != '\0')
     && strcmp(el->ethAddressString, "00:00:00:00:00:00")
     && strcmp(el->ethAddressString, "00:01:02:03:04:05") /* dummy address */) {
    char *vendorName;

    if(isMultihomed(el)) {
      char *symMacAddr, symLink[32];
      int i;

      symMacAddr = etheraddr_string(el->ethAddress);
      strcpy(symLink, symMacAddr);
      for(i=0; symLink[i] != '\0'; i++)
	if(symLink[i] == ':')
	  symLink[i] = '_';

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<A HREF=%s.html>%s</A>%s</TD></TR>\n",
		  getRowColor(), "Main Host MAC Address",
		  symLink, symMacAddr,
		  separator /* it avoids empty cells not to be rendered */) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

    } else {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "MAC&nbsp;Address <IMG SRC=/card.gif BORDER=0>",
		  el->ethAddressString,
		  separator /* it avoids empty cells not to be rendered */) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }

    vendorName = getVendorInfo(el->ethAddress, 1);
    if(vendorName[0] != '\0') {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
	      "%s%s</TD></TR>\n",
	      getRowColor(), "Nw&nbsp;Board&nbsp;Vendor",
	      vendorName,
	      separator /* it avoids empty cells not to be rendered */) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }
  }

  if(((el->lastEthAddress[0] != 0)
      || (el->lastEthAddress[1] != 0)
      || (el->lastEthAddress[2] != 0)
      || (el->lastEthAddress[3] != 0)
      || (el->lastEthAddress[4] != 0)
      || (el->lastEthAddress[5] != 0) /* The address isn't empty */)
     && (memcmp(el->lastEthAddress, el->ethAddress, ETHERNET_ADDRESS_LEN) != 0)) {
    /* Different MAC addresses */
    char *symMacAddr, symLink[32];
    int i;

    symMacAddr = etheraddr_string(el->lastEthAddress);
    strcpy(symLink, symMacAddr);
    for(i=0; symLink[i] != '\0'; i++)
      if(symLink[i] == ':')
	symLink[i] = '_';

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"<A HREF=%s.html>%s</A>%s</TD></TR>\n",
		getRowColor(), "Last MAC Address/Router <IMG SRC=/card.gif BORDER=0>",
		symLink, symMacAddr,
		separator /* it avoids empty cells not to be rendered */) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }

  if(el->hostNumIpAddress[0] != '\0') {
    updateOSName(el);

    if((el->osName != NULL) && (el->osName[0] != '\0')) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "OS&nbsp;Name",
		  getOSFlag(el->osName, 1),
		  separator /* it avoids empty cells not to be rendered */) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }
  }

  if((el->nbHostName != NULL) && (el->nbDomainName != NULL)) {
    if(el->nbAccountName) {
      if(el->nbDomainName != NULL) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
		  "%s@%s&nbsp;[domain %s] (%s) %s</TD></TR>\n",
		  getRowColor(), "NetBios&nbsp;Name",
		  el->nbAccountName, el->nbHostName, el->nbDomainName,
		  getNbNodeType(el->nbNodeType),
		  el->nbDescr ? el->nbDescr : "") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      } else {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
		  "%s@%s (%s) %s</TD></TR>\n",
		  getRowColor(), "NetBios&nbsp;Name",
		  el->nbAccountName, el->nbHostName,
		  getNbNodeType(el->nbNodeType),
		  el->nbDescr ? el->nbDescr : "") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      }
    } else {
      if(el->nbDomainName != NULL) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
		  "%s&nbsp;[domain %s] (%s) %s</TD></TR>\n",
		  getRowColor(), "NetBios&nbsp;Name",
		  el->nbHostName, el->nbDomainName,
		  getNbNodeType(el->nbNodeType),
		  el->nbDescr ? el->nbDescr : "") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      } else {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
		  "%s (%s) %s</TD></TR>\n",
		  getRowColor(), "NetBios&nbsp;Name",
		  el->nbHostName,
		  getNbNodeType(el->nbNodeType),
		  el->nbDescr ? el->nbDescr : "") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      }
    }

    sendString(buf);
  } else if(el->nbHostName != NULL) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
		"%s&nbsp;(%s) %s</TD></TR>\n",
		getRowColor(), "NetBios&nbsp;Name",
		el->nbHostName, getNbNodeType(el->nbNodeType),
		el->nbDescr ? el->nbDescr : "") < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }

  if(el->atNetwork != 0) {
    char *nodeName = el->atNodeName;

    if(nodeName == NULL) nodeName = "";

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
	    "%s&nbsp;\n",
	    getRowColor(), "AppleTalk&nbsp;Name",
	    nodeName) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

    if(el->atNodeType[0] != NULL) {
      int i;

      sendString("(");
      for(i=0; i<MAX_NODE_TYPES; i++)
	if(el->atNodeType[i] == NULL)
	  break;
	else {
	  if(i > 0) sendString("/");
	  sendString(el->atNodeType[i]);
	}

      sendString(")&nbsp;");
    }

    if(snprintf(buf, sizeof(buf), "[%d.%d]</TD></TR>\n",
	     el->atNetwork, el->atNode) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }

  if(el->ipxHostName != NULL) {
    int i;

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		"<TD "TD_BG"  ALIGN=RIGHT>"
	     "%s&nbsp;[", getRowColor(), "IPX&nbsp;Name",
	     el->ipxHostName) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

    for(i=0; i<el->numIpxNodeTypes; i++) {
      if(i>0) sendString("/");
      sendString(getSAPInfo(el->ipxNodeType[i], 1));
    }

    sendString("]</TD></TR>\n");
  }

  if(!multicastHost(el)) {
    if(subnetPseudoLocalHost(el)) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
	      "%s</TD></TR>\n", getRowColor(),
	      "Host&nbsp;Location",
	      "Local (inside specified/local subnet)") < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    } else {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
	      "%s</TD></TR>\n", getRowColor(),
	      "Host&nbsp;Location",
	      "Remote (outside specified/local subnet)") < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    }
    sendString(buf);
  }

  if(el->minTTL > 0) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
		"%d:%d&nbsp;hops</TD></TR>\n",
		getRowColor(), "IP&nbsp;TTL&nbsp;(Time to Live)",
		el->minTTL, el->maxTTL) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
	      "%s/%s Pkts/%s Retran. Pkts [%d%%]</TD></TR>\n",
	      getRowColor(), "Total&nbsp;Data&nbsp;Sent",
	      formatBytes(el->bytesSent, 1), formatPkts(el->pktSent),
	      formatPkts(el->pktDuplicatedAckSent),
	      (int)(((float)el->pktDuplicatedAckSent*100)/(float)(el->pktSent+1))
	      ) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
	  "%s Pkts</TD></TR>\n",
	  getRowColor(), "Broadcast&nbsp;Pkts&nbsp;Sent",
	  formatPkts(el->pktBroadcastSent)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(el->routedTraffic != NULL) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
		"%s/%s Pkts</TD></TR>\n",
		getRowColor(), "Routed Traffic",
		formatBytes(el->routedTraffic->routedBytes, 1),
		formatPkts(el->routedTraffic->routedPkts)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);    
  }

  if((el->pktMulticastSent > 0) || (el->pktMulticastRcvd > 0)) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
	    "Sent&nbsp;%s/%s&nbsp;Pkts&nbsp;-"
	    "&nbsp;Rcvd&nbsp;%s/%s&nbsp;Pkts</TD></TR>\n",
	    getRowColor(), "Multicast&nbsp;Traffic",
	    formatBytes(el->bytesMulticastSent, 1),
	    formatPkts(el->pktMulticastSent),
	    formatBytes(el->bytesMulticastRcvd, 1),
	    formatPkts(el->pktMulticastRcvd)
	    ) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }

  if(el->bytesSent == 0)
    percentage = 0;
  else
    percentage = 100 - (((float)el->bytesSentRemotely*100)/el->bytesSent);

  if(el->hostNumIpAddress[0] != '\0') {
    printTableEntryPercentage(buf, sizeof(buf), "Data&nbsp;Sent&nbsp;Stats",
			      "Local", "Remote", -1, percentage);
  }

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
	  "%s/%s Pkts/%s Retran. Pkts [%d%%]</TD></TR>\n",
	  getRowColor(), "Total&nbsp;Data&nbsp;Rcvd",
	  formatBytes(el->bytesReceived, 1), formatPkts(el->pktReceived),
	  formatPkts(el->pktDuplicatedAckRcvd),
	  (int)((float)(el->pktDuplicatedAckRcvd*100)/(float)(el->pktReceived+1))) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  if(el->bytesReceived == 0)
    percentage = 0;
  else
    percentage = 100 - (((float)el->bytesReceivedFromRemote*100)/el->bytesReceived);

  if(el->hostNumIpAddress[0] != '\0')
    printTableEntryPercentage(buf, sizeof(buf), "Data&nbsp;Received&nbsp;Stats",
			      "Local", "Remote", -1, percentage);

  /* ******************** */

  printedHeader=0;
  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
    if(el->contactedRouters.peersIndexes[i] != NO_PEER) {
      int routerIdx = el->contactedRouters.peersIndexes[i];

      if(!printedHeader) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>"
		"Used&nbsp;Subnet&nbsp;Routers</TH><TD "TD_BG"  ALIGN=RIGHT>\n", getRowColor()) < 0)
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }
      printedHeader++;

      if(printedHeader > 1) sendString("<BR>");

      if(snprintf(buf, sizeof(buf), "%s\n",
	      makeHostLink(device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(routerIdx)],
			   SHORT_FORMAT, 0, 0)) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
    }
  }

  if(gatewayHost(el)
     || nameServerHost(el)
     || isSMTPhost(el)
     || isPOPhost(el)
     || isIMAPhost(el)
     || isDirectoryHost(el)
     || isFTPhost(el)
     || isHTTPhost(el)
     || isWINShost(el)
     ) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>",
	    getRowColor(),
		"Provided&nbsp;Services") < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

    if(nameServerHost(el))     sendString("&nbsp;<IMG SRC=/dns.gif BORDER=0>&nbsp;Name Server<br>");
    if(gatewayHost(el))        sendString("Gateway&nbsp;<IMG SRC=router.gif BORDER=0>&nbsp;<br>");
    if(isSMTPhost(el))         sendString("SMTP Server<br>");
    if(isPOPhost(el))          sendString("POP Server<br>");
    if(isIMAPhost(el))         sendString("IMAP Server<br>");
    if(isDirectoryHost(el))    sendString("Directory Server<br>");
    if(isFTPhost(el))          sendString("FTP Server<br>");
    if(isHTTPhost(el))         sendString("HTTP Server<br>");
    if(isWINShost(el))         sendString("WINS Server<br>");

#ifdef ENABLE_NAPSTER
    if(isNapsterServer(el))    sendString("Napster Server<br>");
    if(isNapsterRedirector(el))    sendString("Napster Redirector<br>");
#endif

    sendString("</TD></TR>");
  }

  /* **************************** */

  if(isServer(el)
     || isWorkstation(el)
     || isMasterBrowser(el)
     || isPrinter(el)
     || isBridgeHost(el)
#ifdef ENABLE_NAPSTER
     || isNapsterRedirector(el) || isNapsterServer(el) || isNapsterClient(el)
#endif
     || isDHCPClient(el)        || isDHCPServer(el)
     ) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		"<TD "TD_BG"  ALIGN=RIGHT>", getRowColor(),
		"Host Type") < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);

    if(isServer(el))              sendString("Server<br>");
    if(isMasterBrowser(el))       sendString("Master Browser<br>");
    if(isWorkstation(el))         sendString("Workstation<br>");
    if(isPrinter(el))             sendString("Printer&nbsp;<IMG SRC=printer.gif BORDER=0><br>");
    if(isBridgeHost(el))          sendString("Bridge<br>");
#ifdef ENABLE_NAPSTER
    if(isNapsterRedirector(el))   sendString("Napster Redirector<br>");
    if(isNapsterServer(el))       sendString("Napster Server<br>");
    if(isNapsterClient(el))       sendString("Napster Client<br>");
#endif
    if(isDHCPClient(el))          sendString("BOOTP/DHCP Client<br>");
    if(isDHCPServer(el))          sendString("BOOTP/DHCP Server<br>");
    sendString("</TD></TR>");
  }

  /* **************************** */
  /*
    Fix courtesy of
    Albert Chin-A-Young <china@thewrittenword.com>
  */
  if(printedHeader > 1)
    sendString("</OL></TD></TR>\n");

  if((el->hostNumIpAddress[0] != '\0')
     && (!subnetPseudoLocalHost(el))
     && (!multicastHost(el))
     && (!privateIPAddress(el))
     && (mapperURL[0] > 0)) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG"  ALIGN=RIGHT>"
		"<IMG SRC=\"%s?host=%s\" WIDTH=320 HEIGHT=200></TD></TR>\n",
		getRowColor(),
		"Host Physical Location",
		mapperURL, el->hostNumIpAddress) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
  }



  checkHostHealthness(el);

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");
}

/* ************************************ */

void printServiceStats(char* svcName, ServiceStats* ss,
		       short printSentStats) {
  char buf[BUF_SIZE];
  TrafficCounter tot, tot1;
  float f1, f2, f3, f4;

  if(ss != NULL) {
    if(printSentStats) {
      tot = ss->numLocalReqSent+ss->numRemoteReqSent;

      if(tot == 0)
	f1 = f2 = 0;
      else {
	f1 = (ss->numLocalReqSent*100)/tot;
	f2 = (ss->numRemoteReqSent*100)/tot;
      }

      tot1 = ss->numPositiveReplRcvd+ss->numNegativeReplRcvd;
      if(tot1 == 0)
	f3 = f4 = 0;
      else {
	f3 = (ss->numPositiveReplRcvd*100)/tot1;
	f4 = (ss->numNegativeReplRcvd*100)/tot1;
      }

      if((tot > 0) || (tot1 > 0)) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG">%s</TH>"
	        "<TD "TD_BG"  ALIGN=CENTER>%s</TD><TD "TD_BG"  ALIGN=CENTER>%.1f%%</TD>"
		"<TD "TD_BG"  ALIGN=CENTER>%s</TD><TD "TD_BG"  ALIGN=CENTER>%.1f%%</TD>"
		"<TD "TD_BG"  ALIGN=CENTER>%s</TD><TD "TD_BG"  ALIGN=CENTER>%.1f%%</TD>"
		"<TD "TD_BG"  ALIGN=CENTER>%s</TD><TD "TD_BG"  ALIGN=CENTER>%.1f%%</TD>"
		"<TD "TD_BG"  ALIGN=CENTER>%s - %s</TD><TD "TD_BG"  ALIGN=CENTER>%s - %s</TD>"
		"</TR>\n",
		getRowColor(), svcName,
		formatPkts(ss->numLocalReqSent), f1,
		formatPkts(ss->numRemoteReqSent), f2,
		formatPkts(ss->numPositiveReplRcvd), f3,
		formatPkts(ss->numNegativeReplRcvd), f4,
		formatMicroSeconds(ss->fastestMicrosecLocalReqMade),
		formatMicroSeconds(ss->slowestMicrosecLocalReqMade),
		formatMicroSeconds(ss->fastestMicrosecRemoteReqMade),
		formatMicroSeconds(ss->slowestMicrosecRemoteReqMade)
		) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }
    } else {
      tot = ss->numLocalReqRcvd+ss->numRemoteReqRcvd;

      if(tot == 0)
	f1 = f2 = 0;
      else {
	f1 = (ss->numLocalReqRcvd*100)/tot;
	f2 = (ss->numRemoteReqRcvd*100)/tot;
      }

      tot1 = ss->numPositiveReplSent+ss->numNegativeReplSent;
      if(tot1 == 0)
	f3 = f4 = 0;
      else {
	f3 = (ss->numPositiveReplSent*100)/tot1;
	f4 = (ss->numNegativeReplSent*100)/tot1;
      }

      if((tot > 0) || (tot1 > 0)) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG">%s</TH>"
                "<TD "TD_BG"  ALIGN=CENTER>%s</TD><TD "TD_BG"  ALIGN=CENTER>%.1f%%</TD>"
		"<TD "TD_BG"  ALIGN=CENTER>%s</TD><TD "TD_BG"  ALIGN=CENTER>%.1f%%</TD>"
		"<TD "TD_BG"  ALIGN=CENTER>%s</TD><TD "TD_BG"  ALIGN=CENTER>%.1f%%</TD>"
		"<TD "TD_BG"  ALIGN=CENTER>%s</TD><TD "TD_BG"  ALIGN=CENTER>%.1f%%</TD>"
		"<TD "TD_BG"  ALIGN=CENTER>%s - %s</TD><TD "TD_BG"  ALIGN=CENTER>%s - %s</TD>"
		"</TR>\n",
		getRowColor(), svcName,
		formatPkts(ss->numLocalReqRcvd), f1,
		formatPkts(ss->numRemoteReqRcvd), f2,
		formatPkts(ss->numPositiveReplSent), f3,
		formatPkts(ss->numNegativeReplSent), f4,
		formatMicroSeconds(ss->fastestMicrosecLocalReqServed),
		formatMicroSeconds(ss->slowestMicrosecLocalReqServed),
		formatMicroSeconds(ss->fastestMicrosecRemoteReqServed),
		formatMicroSeconds(ss->slowestMicrosecRemoteReqServed)
		) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	sendString(buf);
      }
    }
  }
}

/* ************************************ */

#ifdef ENABLE_NAPSTER
static void printNapsterStats(HostTraffic *el) {

  printSectionTitle("Napster Stats");

  sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1>\n");
  sendString("<TR><TH "TH_BG" ALIGN=LEFT># Connections Requested</TH><TD ALIGN=RIGHT>");
  sendString(formatPkts(el->napsterStats->numConnectionsRequested));
  sendString("</TD></TR>\n");
  sendString("<TR><TH "TH_BG" ALIGN=LEFT># Connections Served</TH><TD ALIGN=RIGHT>");
  sendString(formatPkts(el->napsterStats->numConnectionsServed));
  sendString("</TD></TR>\n");
  sendString("<TR><TH "TH_BG" ALIGN=LEFT># Search Requested</TH><TD ALIGN=RIGHT>");
  sendString(formatPkts(el->napsterStats->numSearchSent));
  sendString("</TD></TR>\n");
  sendString("<TR><TH "TH_BG" ALIGN=LEFT># Search Served</TH><TD ALIGN=RIGHT>");
  sendString(formatPkts(el->napsterStats->numSearchRcvd));
  sendString("</TD></TR>\n");
  sendString("<TR><TH "TH_BG" ALIGN=LEFT># Downloads Requested</TH><TD ALIGN=RIGHT>");
  sendString(formatPkts(el->napsterStats->numDownloadsRequested));
  sendString("</TD></TR>\n");
  sendString("<TR><TH "TH_BG" ALIGN=LEFT># Downloads Served</TH><TD ALIGN=RIGHT>");
  sendString(formatPkts(el->napsterStats->numDownloadsServed));
  sendString("</TD></TR>\n");
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>Data Sent</TH><TD ALIGN=RIGHT>");
  sendString(formatBytes(el->napsterStats->bytesSent, 1));
  sendString("</TD></TR>\n");
  sendString("<TR><TH "TH_BG" ALIGN=LEFT>Data Received</TH><TD ALIGN=RIGHT>");
  sendString(formatBytes(el->napsterStats->bytesRcvd, 1));
  sendString("</TD></TR>\n");

  sendString("</TABLE>"TABLE_OFF"</CENTER>\n");
}
#endif

/* ************************************ */

void printHostUsedServices(HostTraffic *el) {
  TrafficCounter tot;

#ifdef ENABLE_NAPSTER
  if(el->napsterStats != NULL)
    printNapsterStats(el);
#endif

  if((el->dnsStats == NULL) && (el->httpStats == NULL))
    return;

  tot = 0;

  if(el->dnsStats)
    tot += el->dnsStats->numLocalReqSent+el->dnsStats->numRemoteReqSent;

  if(el->httpStats)
    tot += el->httpStats->numLocalReqSent+el->httpStats->numRemoteReqSent;

  if(tot > 0) {
    printSectionTitle("IP&nbsp;Service&nbsp;Stats:&nbsp;Client&nbsp;Role");
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=100%%>\n<TR>"
	       "<TH "TH_BG">&nbsp;</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Loc.&nbsp;Req.&nbsp;Sent</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Rem.&nbsp;Req.&nbsp;Sent</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Pos.&nbsp;Reply&nbsp;Rcvd</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Neg.&nbsp;Reply&nbsp;Rcvd</TH>"
	       "<TH "TH_BG">Local&nbsp;RndTrip</TH>"
	       "<TH "TH_BG">Remote&nbsp;RndTrip</TH>"
	       "</TR>\n");

    if(el->dnsStats) printServiceStats("DNS", el->dnsStats, 1);
    if(el->httpStats) printServiceStats("HTTP", el->httpStats, 1);

    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");
  }

  /* ************ */

  tot = 0;

  if(el->dnsStats)
    tot += el->dnsStats->numLocalReqRcvd+el->dnsStats->numRemoteReqRcvd;

  if(el->httpStats)
    tot += el->httpStats->numLocalReqRcvd+el->httpStats->numRemoteReqRcvd;

  if(tot > 0) {
    printSectionTitle("IP&nbsp;Service&nbsp;Stats:&nbsp;Server&nbsp;Role");
    sendString("<CENTER>\n");
    sendString("<P>"TABLE_ON"<TABLE BORDER=1 WIDTH=100%%>\n<TR>"
	       "<TH "TH_BG">&nbsp;</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Loc.&nbsp;Req.&nbsp;Rcvd</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Rem.&nbsp;Req.&nbsp;Rcvd</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Pos.&nbsp;Reply&nbsp;Sent</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Neg.&nbsp;Reply&nbsp;Sent</TH>"
	       "<TH "TH_BG">Local&nbsp;RndTrip</TH>"
	       "<TH "TH_BG">Remote&nbsp;RndTrip</TH>"
	       "</TR>\n");

    if(el->dnsStats) printServiceStats("DNS", el->dnsStats, 0);
    if(el->httpStats) printServiceStats("HTTP", el->httpStats, 0);

    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");
  }
}

/* ********************************** */

void printTableEntry(char *buf, int bufLen,
		     char *label, char* color,
		     float total, float percentage) {
  int int_perc;

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
    if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT WIDTH=150>%s</TH>"
		"<TD "TD_BG"  ALIGN=RIGHT WIDTH=100>%s</TD>"
		"<TD "TD_BG" WIDTH=250>&nbsp;</TD></TR>\n",
		getRowColor(), label, formatKBytes(total)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    break;
  case 100:
    if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT WIDTH=150>%s</TH>"
		"<TD "TD_BG"  ALIGN=RIGHT WIDTH=100>%s</TD>"
		"<TD ALIGN=CENTER WIDTH=250><IMG ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=\"250\" HEIGHT=12>"
		"</TD></TR>\n",
		getRowColor(), label, formatKBytes(total)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    break;
  default:
    if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT WIDTH=150>%s</TH>"
	    "<TD "TD_BG" ALIGN=RIGHT WIDTH=100>%s</TD>"
	    "<TD "TD_BG" WIDTH=250><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"250\">"
	    "<TR><TD><IMG ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=\"%d\" HEIGHT=12>"
	    "</TD><TD "TD_BG" ALIGN=CENTER WIDTH=\"%d\" %s>"
	    "<P>&nbsp;</TD></TR></TABLE></TD></TR>\n",
	    getRowColor(), label, formatKBytes(total),
	    (250*int_perc)/100, (250*(100-int_perc))/100, getActualRowColor()) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  }

  sendString(buf);
}

/* ************************ */

char* buildHTMLBrowserWindowsLabel(int i, int j) {
  static char buf[BUF_SIZE];
  int idx = i*device[actualReportDeviceId].numHosts + j;

#ifdef MULTITHREADED
  accessMutex(&addressResolutionMutex, "buildHTMLBrowserWindowsLabel");
#endif

  if((device[actualReportDeviceId].ipTrafficMatrix[idx] == NULL)
     || ((device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent == 0)
	 && (device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesReceived == 0)))
    buf[0]='\0';
  else if ((device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent > 0)
	   && (device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesReceived == 0)) {
    if(snprintf(buf, sizeof(buf), "(%s->%s)=%s",
		device[actualReportDeviceId].ipTrafficMatrixHosts[i]->hostSymIpAddress,
		device[actualReportDeviceId].ipTrafficMatrixHosts[j]->hostSymIpAddress,
		formatBytes(device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent, 1)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  } else if ((device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent == 0)
	     && (device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesReceived > 0)) {
    if(snprintf(buf, sizeof(buf), "(%s->%s)=%s",
		device[actualReportDeviceId].ipTrafficMatrixHosts[j]->hostSymIpAddress,
		device[actualReportDeviceId].ipTrafficMatrixHosts[i]->hostSymIpAddress,
		formatBytes(device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesReceived, 1)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  } else {
    if(snprintf(buf, sizeof(buf), "(%s->%s)=%s, (%s->%s)=%s",
		device[actualReportDeviceId].ipTrafficMatrixHosts[i]->hostSymIpAddress,
		device[actualReportDeviceId].ipTrafficMatrixHosts[j]->hostSymIpAddress,
		formatBytes(device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent, 1),
		device[actualReportDeviceId].ipTrafficMatrixHosts[j]->hostSymIpAddress,
		device[actualReportDeviceId].ipTrafficMatrixHosts[i]->hostSymIpAddress,
		formatBytes(device[actualReportDeviceId].ipTrafficMatrix[idx]->bytesReceived, 1)) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
  }

#ifdef MULTITHREADED
  releaseMutex(&addressResolutionMutex);
#endif

  return(buf);
}

/* ************************ */

int cmpEventsFctn(const void *_a, const void *_b) {
  EventMsg **a = (EventMsg**)_a;
  EventMsg **b = (EventMsg**)_b;

  switch(columnSort) {
  case 0: /* Event Time */
    if((*a)->eventTime > (*b)->eventTime)
      return(-1);
    else if((*a)->eventTime < (*b)->eventTime)
      return(1);
    else
      return(0);
    break;
  case 1: /* Severity */
    if((*a)->severity > (*b)->severity)
      return(-1);
    else if((*a)->severity < (*b)->severity)
      return(1);
    else
      return(0);
    break;
  case 2: /* Rule Id */
    if((*a)->ruleId > (*b)->ruleId)
      return(-1);
    else if((*a)->ruleId < (*b)->ruleId)
      return(1);
    else
      return(0);
    break;
  }

  return(0);
}

/* *********************************** */

void printHostHourlyTrafficEntry(HostTraffic *el, int i,
			    TrafficCounter tcSent,
			    TrafficCounter tcRcvd) {
  float pctg;
  char buf[BUF_SIZE];

  if(snprintf(buf, BUF_SIZE, "<TD "TD_BG"  ALIGN=RIGHT>%s</TD>",
	   formatBytes(el->last24HoursBytesSent[i], 0)) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  if(tcSent > 0)
    pctg = (float)(el->last24HoursBytesSent[i]*100)/(float)tcSent;
  else
    pctg = 0;
  if(snprintf(buf, BUF_SIZE, "<TD ALIGN=RIGHT %s>%.1f %%</TD>",
	   getBgPctgColor(pctg), pctg) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  if(snprintf(buf, BUF_SIZE, "<TD "TD_BG"  ALIGN=RIGHT>%s</TD>",
	   formatBytes(el->last24HoursBytesRcvd[i], 0)) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  if(tcRcvd > 0)
    pctg = (float)(el->last24HoursBytesRcvd[i]*100)/(float)tcRcvd;
  else
    pctg = 0;

  if(snprintf(buf, BUF_SIZE, "<TD ALIGN=RIGHT %s>%.1f %%</TD></TR>",
	   getBgPctgColor(pctg), pctg) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
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

#endif /* MICRO_NTOP */

 /* ********************************** */

void printFlagedWarning(char *text) {
  char buf[BUF_SIZE];

  snprintf(buf, BUF_SIZE,
 	   "<CENTER>\n"
 	   "<P><IMG SRC=/warning.gif>\n"
 	   "<P><FONT COLOR=\"#FF0000\" SIZE=+1>%s</FONT>\n"
 	   "</CENTER>\n", text);
  sendString(buf);
}

/* ********************************** */

void printSectionTitle(char *text) {
  char buf[BUF_SIZE];

  snprintf(buf, BUF_SIZE,
 	   "<CENTER>\n"
 	   "<H1><FONT FACE=\"Helvetica, Arial, Sans Serif\">%s</FONT></H1><P>\n"
 	   "</CENTER>\n", text);
  sendString(buf);
}


