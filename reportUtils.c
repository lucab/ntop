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

#ifndef MICRO_NTOP

/* ************************************ */

void formatUsageCounter(UsageCounter usageCtr,
			Counter topValue,
			/* If this value != 0 then a percentage is printed */
			int actualDeviceId) {
  char buf[BUF_SIZE];
  int i, sendHeader=0;
  HostTraffic el;

  if(topValue == 0) {
    /* No percentage is printed */
    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		formatPkts(usageCtr.value.value)) < 0)
      BufferTooShort();
    sendString(buf);
  } else {
    float pctg;

    pctg = ((float)usageCtr.value.value/(float)topValue)*100;

    if(pctg > 100) pctg = 100; /* This should not happen ! */

    if(snprintf(buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;[%.0f&nbsp;%%]</TD>",
		formatPkts(usageCtr.value.value), pctg) < 0)
      BufferTooShort();
    sendString(buf);
  }

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++) {
    if(usageCtr.peersIndexes[i] != NO_PEER) {
      if(retrieveHost(usageCtr.peersIndexes[i], &el) == 0) {
	if(!sendHeader) {
	  sendString("<TD "TD_BG" ALIGN=LEFT><ul>");
	  sendHeader = 1;
	}

	sendString("\n<li>");
	sendString(makeHostLink(&el, 0, 0, 0));
      } else
	traceEvent(TRACE_INFO, "Unable to find serial %u", usageCtr.peersIndexes[i]);
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
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH WIDTH=100 "TH_BG" ALIGN=LEFT>%s</TH>"
           "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
           "<TD WIDTH=100 "TD_BG">&nbsp;</TD>\n",
           getRowColor(), label, formatKBytes(totalS)) < 0)
      BufferTooShort();
    break;
  case 100:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH WIDTH=100 "TH_BG" ALIGN=LEFT>%s</TH>"
           "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
           "<TD WIDTH=100><IMG ALT=\"100%\"ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=100 HEIGHT=12></TD>\n",
           getRowColor(), label, formatKBytes(totalS)) < 0)
      BufferTooShort();
    break;
  default:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH WIDTH=100 "TH_BG" ALIGN=LEFT>%s</TH>"
		"<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100 "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100\">"
		"<TR "TR_ON"><TD><IMG  ALT=\"%d%%\" ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=\"%d\" HEIGHT=12></TD>"
		"<TD "TD_BG" ALIGN=CENTER WIDTH=\"%d\">"
		"<P>&nbsp;</TD></TR></TABLE>"TABLE_OFF"</TD>\n",
	     getRowColor(), label, formatKBytes(totalS),
	     int_perc, (100*int_perc)/100, (100*(100-int_perc))/100) < 0)
      BufferTooShort();
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
    if(snprintf(buf, bufLen, "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100 "TD_BG">&nbsp;</TD></TR>\n",
		formatKBytes(totalR)) < 0)
      BufferTooShort();
    break;
  case 100:
    if(snprintf(buf, bufLen, "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD WIDTH=100><IMG ALIGN=MIDDLE ALT=\"100\" SRC=/gauge.jpg WIDTH=\"100\" HEIGHT=12></TD></TR>\n",
		formatKBytes(totalR)) < 0) BufferTooShort();
    break;
  default:
    if(snprintf(buf, bufLen, "<TD WIDTH=100 "TD_BG" ALIGN=RIGHT>%s</TD>"
		"<TD  WIDTH=100 "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100\">"
		"<TR "TR_ON"><TD><IMG ALT=\"%d%%\" ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=\"%d\" HEIGHT=12>"
		"</TD><TD "TD_BG" ALIGN=CENTER WIDTH=\"%d\">"
		"<P>&nbsp;</TD></TR></TABLE></TD></TR>\n",
		formatKBytes(totalR),
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
	BufferTooShort();
    } else {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		  "<TD ALIGN=CENTER BGCOLOR=\"%s\">%s&nbsp;(100&nbsp;%%)</TD></TR>\n",
		  getRowColor(), label, formatKBytes(total), COLOR_2, label_2) < 0)
	BufferTooShort();
    }
    break;
  case 100:
    if(total == -1) {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD ALIGN=CENTER BGCOLOR=\"%s\">%s&nbsp;(100&nbsp;%%)</TD></TR>\n",
		  getRowColor(), label, COLOR_1, label_1) < 0)
	BufferTooShort();
    } else {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		  "<TD ALIGN=CENTER BGCOLOR=\"%s\">%s&nbsp;(100&nbsp;%%)</TD></TR>\n",
		  getRowColor(), label, formatKBytes(total), COLOR_1, label_1) < 0)
	BufferTooShort();
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
             label_2, (100-percentage)) < 0) BufferTooShort();
    } else {
      if(snprintf(buf, bufLen, "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>%s</TD>"
             "<TD "TD_BG"><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"100%%\">"
             "<TR><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
             "<P>%s&nbsp;(%.1f&nbsp;%%)</TD><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
             "<P>%s&nbsp;(%.1f&nbsp;%%)</TD></TR></TABLE></TD></TR>\n",
             getRowColor(), label, formatKBytes(total),
             int_perc, COLOR_1,
             label_1, percentage, (100-int_perc), COLOR_2,
		  label_2, (100-percentage)) < 0) BufferTooShort();
    }
  }

  sendString(buf);
}

/* ******************************* */

void printHeader(int reportType, int revertOrder, u_int column) {
  char buf[BUF_SIZE];
  char *sign, *arrowGif, *arrow[48], *theAnchor[48], *url=NULL;
  int i, soFar=2;
  char htmlAnchor[64], htmlAnchor1[64];

  /* printf("->%d<-\n",screenNumber); */

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG ALT=\"Ascending order, click to reverse\" SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG ALT=\"Descending order, click to reverse\" SRC=arrow_down.gif BORDER=0>";
  }

  memset(buf, 0, sizeof(buf));

  switch(reportType) {
  case 0: url = STR_SORT_DATA_RECEIVED_PROTOS; break;
  case 1: url = STR_SORT_DATA_RECEIVED_IP; break;
  case 2: url = STR_SORT_DATA_RECEIVED_THPT; break;
  case 3: url = STR_SORT_DATA_RCVD_HOST_TRAFFIC; break;
  case 4: url = STR_SORT_DATA_SENT_HOST_TRAFFIC; break;
  case 5: url = STR_SORT_DATA_SENT_PROTOS; break;
  case 6: url = STR_SORT_DATA_SENT_IP; break;
  case 7: url = STR_SORT_DATA_SENT_THPT; break;
  case 8: url = TRAFFIC_STATS_HTML; break;
  }

  if(snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", url, sign) < 0)
    BufferTooShort();
  if(snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=",  url) < 0)
    BufferTooShort();

  if(abs(column) == HOST_DUMMY_IDX_VALUE) {
    arrow[0] = arrowGif; theAnchor[0] = htmlAnchor;
  } else {
    arrow[0] = ""; theAnchor[0] = htmlAnchor1;
  }

  if(abs(column) == DOMAIN_DUMMY_IDX_VALUE) {
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
  case 0: /* STR_SORT_DATA_RECEIVED_PROTOS */
  case 5: /* STR_SORT_DATA_SENT_PROTOS */
    sendString("<CENTER>\n");
    if(snprintf(buf, BUF_SIZE, ""TABLE_ON"<TABLE BORDER=1><TR "TR_ON">"
		"<TH "TH_BG">%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>\n"
		"<TH "TH_BG">%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
		"<TH "TH_BG" COLSPAN=2>%s0>Data%s</A></TH>\n",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1],
		theAnchor[2], arrow[2]) < 0)
      BufferTooShort();
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
      BufferTooShort();
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
      BufferTooShort();
    sendString(buf);
    break;

  case 1: /* STR_SORT_DATA_RECEIVED_IP */
  case 6: /* STR_SORT_DATA_SENT_IP */
    sendString("<CENTER>\n");
    if(snprintf(buf, BUF_SIZE, ""TABLE_ON"<TABLE BORDER=1><TR "TR_ON">"
		"<TH "TH_BG">%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>\n"
		"<TH "TH_BG">%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
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
      if(snprintf(buf, BUF_SIZE, "<TH "TH_BG">%s%d>%s%s</A></TH>",
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
    if(snprintf(buf, BUF_SIZE, "<TH "TH_BG">%s%d>Other&nbsp;IP%s</A></TH>",
	     theAnchor[0], i+2, arrow[0]) < 0)
      BufferTooShort();
    sendString(buf);
    break;

  case 3: /* STR_SORT_DATA_RCVD_HOST_TRAFFIC */
  case 4: /* STR_SORT_DATA_SENT_HOST_TRAFFIC */
    sendString("<CENTER>\n");
    if(snprintf(buf, BUF_SIZE, ""TABLE_ON"<TABLE BORDER=1><TR >"
		"<TH "TH_BG">%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>"
		"<TH "TH_BG">%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>\n",
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
  case 2: /* STR_SORT_DATA_RECEIVED_THPT */
  case 7: /* STR_SORT_DATA_SENT_THPT */
    sendString("<CENTER>\n");
    if(snprintf(buf, BUF_SIZE, ""TABLE_ON"<TABLE BORDER=1><TR "TR_ON">"
		"<TH "TH_BG">%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>"
		"<TH "TH_BG">%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>\n\n",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1]) < 0)
      BufferTooShort();
    sendString(buf);
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
      BufferTooShort();
    sendString(buf);
    break;
  case 8: /* TRAFFIC_STATS_HTML */
    sendString("<CENTER>\n");
    if(snprintf(buf, BUF_SIZE, ""TABLE_ON"<TABLE BORDER=1><TR "TR_ON">"
		"<TH "TH_BG">%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>"
		"<TH "TH_BG">%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>\n\n",
		theAnchor[0], arrow[0], theAnchor[1], arrow[1]) < 0)
      BufferTooShort();
    sendString(buf);
    break;
  }

  sendString("</TR>\n");
}

/* ******************************* */

char* getOSFlag(char* theOsName, int showOsName) {
  /* Lengthen tmpString buffer - to handle long name given by nmap for Win2k
     Courtesy of Marcel Hauser <marcel_hauser@gmx.ch> */
  static char tmpStr[200], *flagImg;

  if(strstr(theOsName, "Windows") != NULL)
    flagImg = "<IMG ALT=\"OS: Windows\" ALIGN=MIDDLE SRC=/statsicons/os/windows.gif>";
  else if(strstr(theOsName, "IRIX") != NULL)
    flagImg = "<IMG ALT=\"OS: Irix\" ALIGN=MIDDLE SRC=/statsicons/os/irix.gif>";
  else if(strstr(theOsName, "Linux") != NULL)
    flagImg = "<IMG ALT=\"OS: Linux\" ALIGN=MIDDLE SRC=/statsicons/os/linux.gif>";
  else if(strstr(theOsName, "SunOS") != NULL)
    flagImg = "<IMG  ALT=\"OS: SunOS\" ALIGN=MIDDLE SRC=/statsicons/os/sun.gif>";
  else if(strstr(theOsName, "Solaris") != NULL)
    flagImg = "<IMG  ALT=\"OS: Solaris\" ALIGN=MIDDLE SRC=/statsicons/os/sun.gif>";
  else if(strstr(theOsName, "HP/JETdirect") != NULL)
    flagImg = "<IMG  ALT=\"OS: HP/JetDirect\" ALIGN=MIDDLE SRC=/statsicons/os/hp.gif>";
  else if(strstr(theOsName, "Mac") != NULL)
    flagImg = "<IMG  ALT=\"OS: Apple Mac\" ALIGN=MIDDLE SRC=/statsicons/os/mac.gif>";
  else if(strstr(theOsName, "Novell") != NULL)
    flagImg = "<IMG ALT=\"OS: Novell\" ALIGN=MIDDLE SRC=/statsicons/os/novell.gif>";
  else if((strstr(theOsName, "BSD") != NULL)
	  || (strstr(theOsName, "Unix") != NULL)
	  || (strstr(theOsName, "Berkeley") != NULL))
    flagImg = "<IMG ALT=\"OS: BSD Unix\" ALIGN=MIDDLE SRC=/statsicons/os/bsd.gif>";
  else if(strstr(theOsName, "HP-UX") != NULL)
    flagImg = "<IMG ALT=\"OS: HP-UX\" ALIGN=MIDDLE SRC=/statsicons/os/hp.gif>";
  else if(strstr(theOsName, "AIX") != NULL)
    flagImg = "<IMG ALT=\"OS: AIX\" ALIGN=MIDDLE SRC=/statsicons/os/aix.gif>";
  else
    flagImg = NULL;

  if(!showOsName) {
    if(flagImg != NULL)
      strncpy(tmpStr, flagImg, sizeof(tmpStr));
    else
      strncpy(tmpStr, "", sizeof(tmpStr));
  } else {
    if(flagImg != NULL) {
      if(snprintf(tmpStr, sizeof(tmpStr), "%s&nbsp;[%s]", flagImg, theOsName) < 0)
	BufferTooShort();
    } else
      strncpy(tmpStr, theOsName, sizeof(tmpStr));
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
    traceEvent(TRACE_WARNING, "WARNING (1)\n");
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (2)\n");
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (3)\n");
    return(0);
  }

  switch(myGlobals.columnSort) {
  case 1:
#ifdef MULTITHREADED
    if(myGlobals.numericFlag == 0)
      accessMutex(&myGlobals.addressResolutionMutex, "sortHostFctn");
#endif
    rc = strcasecmp((*a)->hostSymIpAddress[0] != '\0' ? (*a)->hostSymIpAddress : (*a)->ethAddressString,
		    (*b)->hostSymIpAddress[0] != '\0' ? (*b)->hostSymIpAddress : (*b)->ethAddressString);
#ifdef MULTITHREADED
    if(myGlobals.numericFlag == 0)
      releaseMutex(&myGlobals.addressResolutionMutex);
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
	BufferTooShort();
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
	BufferTooShort();
      nameB = nameB_str;
    } else if((*b)->ipxHostName != NULL)
      nameB = (*b)->ipxHostName;
    else
      nameB = "";

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

int cmpFctn(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter a_=0, b_=0, a_val, b_val;
  float fa_=0, fb_=0;
  short floatCompare=0, columnProtoId;

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

  if(myGlobals.columnSort == HOST_DUMMY_IDX_VALUE) {
    int rc;

    /* Host name */
#ifdef MULTITHREADED
    if(myGlobals.numericFlag == 0)
      accessMutex(&myGlobals.addressResolutionMutex, "cmpFctn");
#endif

    if((*a)->hostSymIpAddress[0] != '\0') {
      char *name1, *name2;

      name1 = (*a)->hostSymIpAddress;
      name2 = (*b)->hostSymIpAddress;

      rc = strcasecmp(name1, name2);
    } else
      rc = strcasecmp((*a)->ethAddressString, (*b)->ethAddressString);

#ifdef MULTITHREADED
    if(myGlobals.numericFlag == 0)
      releaseMutex(&myGlobals.addressResolutionMutex);
#endif
    return(rc);
  } else if(myGlobals.columnSort == DOMAIN_DUMMY_IDX_VALUE) {
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

#ifdef DEBUG
  traceEvent(TRACE_INFO,
	     "reportKind=%d/columnSort=%d/sortSendMode=%d/numIpProtosToMonitor=%d\n",
	     myGlobals.reportKind, myGlobals.columnSort, myGlobals.sortSendMode, myGlobals.numIpProtosToMonitor);
#endif


  switch(myGlobals.reportKind) {
  case 0: /* STR_SORT_DATA_RECEIVED_PROTOS */
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
      a_ = (*a)->dlcRcvd.value, b_ = (*b)->dlcRcvd.value;
      break;
    case 5:
      a_ = (*a)->ipxRcvd.value, b_ = (*b)->ipxRcvd.value;
      break;
    case 6:
      a_ = (*a)->decnetRcvd.value, b_ = (*b)->decnetRcvd.value;
      break;
    case 7:
      a_ = (*a)->arp_rarpRcvd.value, b_ = (*b)->arp_rarpRcvd.value;
      break;
    case 8:
      a_ = (*a)->appletalkRcvd.value, b_ = (*b)->appletalkRcvd.value;
      break;
    case 9:
      a_ = (*a)->ospfRcvd.value, b_ = (*b)->ospfRcvd.value;
      break;
    case 10:
      a_ = (*a)->netbiosRcvd.value, b_ = (*b)->netbiosRcvd.value;
      break;
    case 11:
      a_ = (*a)->igmpRcvd.value, b_ = (*b)->igmpRcvd.value;
      break;
    case 12:
      a_ = (*a)->osiRcvd.value, b_ = (*b)->osiRcvd.value;
      break;
    case 13:
      a_ = (*a)->qnxRcvd.value, b_ = (*b)->qnxRcvd.value;
      break;
    case 14:
      a_ = (*a)->stpRcvd.value, b_ = (*b)->stpRcvd.value;
      break;
    case 15:
      a_ = (*a)->otherRcvd.value, b_ = (*b)->otherRcvd.value;
      break;
    }
    break;
  case 1: /* STR_SORT_DATA_RECEIVED_IP */
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
  case 2: /* STR_SORT_DATA_RECEIVED_THPT */
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
  case 3: /* STR_SORT_DATA_RCVD_HOST_TRAFFIC */
  case 4: /* STR_SORT_DATA_SENT_HOST_TRAFFIC */
    /* Npthing */
    break;
  case 5: /* STR_SORT_DATA_SENT_PROTOS */
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
      a_ = (*a)->dlcSent.value, b_ = (*b)->dlcSent.value;
      break;
    case 5:
      a_ = (*a)->ipxSent.value, b_ = (*b)->ipxSent.value;
      break;
    case 6:
      a_ = (*a)->decnetSent.value, b_ = (*b)->decnetSent.value;
      break;
    case 7:
      a_ = (*a)->arp_rarpSent.value, b_ = (*b)->arp_rarpSent.value;
      break;
    case 8:
      a_ = (*a)->appletalkSent.value, b_ = (*b)->appletalkSent.value;
      break;
    case 9:
      a_ = (*a)->ospfSent.value, b_ = (*b)->ospfSent.value;
      break;
    case 10:
      a_ = (*a)->netbiosSent.value, b_ = (*b)->netbiosSent.value;
      break;
    case 11:
      a_ = (*a)->igmpSent.value, b_ = (*b)->igmpSent.value;
      break;
    case 12:
      a_ = (*a)->osiSent.value, b_ = (*b)->osiSent.value;
      break;
    case 13:
      a_ = (*a)->qnxSent.value, b_ = (*b)->qnxSent.value;
      break;
    case 14:
      a_ = (*a)->stpSent.value, b_ = (*b)->stpSent.value;
      break;
    case 15:
      a_ = (*a)->otherSent.value, b_ = (*b)->otherSent.value;
      break;
    }
    break;
  case 6: /* STR_SORT_DATA_SENT_IP */
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
  case 7: /* STR_SORT_DATA_SENT_THPT */
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
  case 8: /* TRAFFIC_STATS_HTML */
    /* Nothing */
    break;
  }

  /*
    traceEvent(TRACE_INFO, "%s=%u - %s=%u",
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
    traceEvent(TRACE_WARNING, "WARNING (1)\n");
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (2)\n");
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (3)\n");
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
#ifdef MULTITHREADED
    if(myGlobals.numericFlag == 0)
      accessMutex(&myGlobals.addressResolutionMutex, "cmpMulticastFctn");
#endif

    rc = strcmp((*a)->hostSymIpAddress, /* Host name */
		(*b)->hostSymIpAddress);
#ifdef MULTITHREADED
    if(myGlobals.numericFlag == 0)
      releaseMutex(&myGlobals.addressResolutionMutex);
#endif
    return(rc);
  }
}

/* *********************************** */

static char* getBgPctgColor(float pctg) {
  if(pctg == 0)
    return(TD_BG);
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
  Counter tc;
  char buf[64];

  for(i=0, tc=0; i<24; i++) {
    if(dataSent)
      tc += el->last24HoursBytesSent[i].value;
    else
      tc += el->last24HoursBytesRcvd[i].value;
  }

  for(i=0; i<24; i++) {
    float pctg;

    if(tc > 0) {
      if(dataSent)
	pctg = (float)(el->last24HoursBytesSent[i].value*100)/(float)tc;
      else
	pctg = (float)(el->last24HoursBytesRcvd[i].value*100)/(float)tc;
    } else
      pctg = 0;

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
    if((*a)->hostIpAddress.s_addr > (*b)->hostIpAddress.s_addr)
      return(1);
    else if((*a)->hostIpAddress.s_addr < (*b)->hostIpAddress.s_addr)
      return(-1);
    else
      return(0);
    break;

  case 3: /* Data Sent.value */
    switch(myGlobals.sortFilter) {
    case REMOTE_TO_LOCAL_ACCOUNTING:
      a_ = (*a)->bytesSentLoc.value;
      b_ = (*b)->bytesSentLoc.value;
      break;
    case LOCAL_TO_REMOTE_ACCOUNTING:
      a_ = (*a)->bytesSentRem.value;
      b_ = (*b)->bytesSentRem.value;
      break;
    case LOCAL_TO_LOCAL_ACCOUNTING:
      a_ = (*a)->bytesSentLoc.value;
      b_ = (*b)->bytesSentLoc.value;
      break;
    }
    if(a_ < b_) return(1); else if (a_ > b_) return(-1); else return(0);
    break;

  case 4: /* Data Rcvd.value */
    switch(myGlobals.sortFilter) {
    case REMOTE_TO_LOCAL_ACCOUNTING:
      a_ = (*a)->bytesRcvdLoc.value;
      b_ = (*b)->bytesRcvdLoc.value;
      break;
    case LOCAL_TO_REMOTE_ACCOUNTING:
      a_ = (*a)->bytesRcvdFromRem.value;
      b_ = (*b)->bytesRcvdFromRem.value;
      break;
    case LOCAL_TO_LOCAL_ACCOUNTING:
      a_ = (*a)->bytesRcvdLoc.value;
      b_ = (*b)->bytesRcvdLoc.value;
      break;
    }
    if(a_ < b_) return(1); else if (a_ > b_) return(-1); else return(0);
    break;

  default: /* Host Name */
#ifdef MULTITHREADED
    if(myGlobals.numericFlag == 0) accessMutex(&myGlobals.addressResolutionMutex, "cmpHostsFctn");
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
    if(myGlobals.numericFlag == 0) releaseMutex(&myGlobals.addressResolutionMutex);
#endif

    rc = strcasecmp(name_a, name_b); /* case insensitive */

    return(rc);
  }
}

/* ************************************ */

void printPacketStats(HostTraffic *el, int actualDeviceId) {
  char buf[BUF_SIZE];
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
		 ""TABLE_ON"<TABLE BORDER=1 WIDTH=100%><TR "TR_ON"><TH "TH_BG">TCP Connections</TH>"
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
		 ""TABLE_ON"<TABLE BORDER=1 WIDTH=100%><TR "TR_ON"><TH "TH_BG">TCP Flags</TH>"
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

    if(((el->secHostPkts->ackScanSent.value.value+el->secHostPkts->ackScanRcvd.value.value
	 +el->secHostPkts->xmasScanSent.value.value+el->secHostPkts->xmasScanRcvd.value.value
	 +el->secHostPkts->finScanSent.value.value+el->secHostPkts->finScanRcvd.value.value
	 +el->secHostPkts->synFinPktsSent.value.value+el->secHostPkts->synFinPktsRcvd.value.value
	 +el->secHostPkts->nullScanSent.value.value+el->secHostPkts->nullScanRcvd.value.value
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
	 +el->secHostPkts->malformedPktsSent.value.value
	 +el->secHostPkts->malformedPktsRcvd.value.value
	 ) > 0)) {

      if(!headerSent) { printSectionTitle("Packet Statistics"); sendString(tableHeader); headerSent = 1; }

      sendString("<CENTER>\n"
		 ""TABLE_ON"<TABLE BORDER=1 WIDTH=100%><TR "TR_ON"><TH "TH_BG">Anomaly</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Sent&nbsp;to</TH>"
		 "<TH "TH_BG" COLSPAN=2>Pkts&nbsp;Rcvd&nbsp;from</TH>"
		 "</TR>\n");

      if((el->secHostPkts->ackScanSent.value.value+el->secHostPkts->ackScanRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>ACK Scan</TH>",
		    getRowColor()) < 0)
	  BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->ackScanSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->ackScanRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->xmasScanSent.value.value+el->secHostPkts->xmasScanRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>XMAS Scan</TH>",
		    getRowColor()) < 0)
	  BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->xmasScanSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->xmasScanRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->finScanSent.value.value+el->secHostPkts->finScanRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>FIN Scan</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->finScanSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->finScanRcvd, 0, actualDeviceId);
	sendString("</TR>\n");
      }

      if((el->secHostPkts->nullScanSent.value.value+el->secHostPkts->nullScanRcvd.value.value) > 0) {
	if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>NULL Scan</TH>",
		    getRowColor()) < 0) BufferTooShort();
	sendString(buf);
	formatUsageCounter(el->secHostPkts->nullScanSent, 0, actualDeviceId);
	formatUsageCounter(el->secHostPkts->nullScanRcvd, 0, actualDeviceId);
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
	       ""TABLE_ON"<TABLE BORDER=1 WIDTH=100%><TR "TR_ON">"
	       "<TH "TH_BG">ARP</TH>"
	       "<TH "TH_BG">Packet</TH>"
	       "</TR>\n");

    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Request Sent</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		getRowColor(),
		formatPkts(el->arpReqPktsSent.value)) < 0)
      BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Reply Rcvd</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s (%.1f %%)</TD></TR>",
		getRowColor(),
		formatPkts(el->arpReplyPktsRcvd.value),
		((el->arpReqPktsSent.value > 0) ?
		(float)((el->arpReplyPktsRcvd.value*100)/(float)el->arpReqPktsSent.value) : 0)) < 0)
      BufferTooShort();
    sendString(buf);

    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Reply Sent</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		getRowColor(),
		formatPkts(el->arpReplyPktsSent.value)) < 0)
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
  char buf[BUF_SIZE];
#ifdef HAVE_GDCHART
  char linkName[BUF_SIZE/2];
  int i;
#endif

  totalSent = el->tcpFragmentsSent.value + el->udpFragmentsSent.value + el->icmpFragmentsSent.value;
  totalRcvd = el->tcpFragmentsRcvd.value + el->udpFragmentsRcvd.value + el->icmpFragmentsRcvd.value;

 if((totalSent == 0) && (totalRcvd == 0))
    return;

  printSectionTitle("IP Fragments Distribution");

  sendString("<CENTER>\n"
	     ""TABLE_ON"<TABLE BORDER=1><TR><TH "TH_BG" WIDTH=100>Protocol</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Sent</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Rcvd</TH></TR>\n");

  printTableDoubleEntry(buf, sizeof(buf), "TCP", COLOR_1, (float)el->tcpFragmentsSent.value/1024,
			100*((float)SD(el->tcpFragmentsSent.value, totalSent)),
			(float)el->tcpFragmentsRcvd.value/1024,
			100*((float)SD(el->tcpFragmentsRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "UDP", COLOR_1, (float)el->udpFragmentsSent.value/1024,
			100*((float)SD(el->udpFragmentsSent.value, totalSent)),
			(float)el->udpFragmentsRcvd.value/1024,
			100*((float)SD(el->udpFragmentsRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "ICMP", COLOR_1, (float)el->icmpFragmentsSent.value/1024,
			100*((float)SD(el->icmpFragmentsSent.value, totalSent)),
			(float)el->icmpFragmentsRcvd.value/1024,
			100*((float)SD(el->icmpFragmentsRcvd.value, totalRcvd)));

#ifdef HAVE_GDCHART
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
        for(i=0; linkName[i] != '\0'; i++)
          if(linkName[i] == ':')
            linkName[i] = '_';  /* to avoid escaping chars */
      }

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
#endif

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");
}

/* ************************************ */

void printHostTrafficStats(HostTraffic *el, int actualDeviceId) {
  Counter totalSent, totalRcvd;
  Counter actTotalSent, actTotalRcvd;
  char buf[BUF_SIZE];
#ifdef HAVE_GDCHART
  char linkName[BUF_SIZE/2];
  int i;
#endif

  totalSent = el->tcpSentLoc.value+el->tcpSentRem.value+el->udpSentLoc.value+el->udpSentRem.value;
  totalSent += el->icmpSent.value+el->ospfSent.value+el->igmpSent.value+el->ipxSent.value+el->dlcSent.value+el->arp_rarpSent.value;
  totalSent +=  el->decnetSent.value+el->appletalkSent.value+el->netbiosSent.value+
    el->osiSent.value+el->qnxSent.value+el->stpSent.value+el->otherSent.value;

  totalRcvd = el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value;
  totalRcvd += el->udpRcvdLoc.value+el->udpRcvdFromRem.value;
  totalRcvd += el->icmpRcvd.value+el->ospfRcvd.value+el->igmpRcvd.value;
  totalRcvd += el->ipxRcvd.value+el->dlcRcvd.value+el->arp_rarpRcvd.value;
  totalRcvd += el->decnetRcvd.value+el->appletalkRcvd.value;
  totalRcvd += el->osiRcvd.value+el->netbiosRcvd.value+el->qnxRcvd.value
    +el->stpRcvd.value+el->otherRcvd.value;

  actTotalSent = el->tcpSentLoc.value+el->tcpSentRem.value;
  actTotalRcvd = el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value;

  printHostHourlyTraffic(el);
  printPacketStats(el, actualDeviceId);

  if((totalSent == 0) && (totalRcvd == 0))
    return;

  printSectionTitle("Protocol Distribution");

  sendString("<CENTER>\n"
	     ""TABLE_ON"<TABLE BORDER=1><TR><TH "TH_BG" WIDTH=100>Protocol</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Sent</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=2>Data&nbsp;Rcvd</TH></TR>\n");

  printTableDoubleEntry(buf, sizeof(buf), "TCP", COLOR_1, (float)actTotalSent/1024,
			100*((float)SD(actTotalSent, totalSent)),
			(float)actTotalRcvd/1024,
			100*((float)SD(actTotalRcvd, totalRcvd)));

  actTotalSent = el->udpSentLoc.value+el->udpSentRem.value;
  actTotalRcvd = el->udpRcvdLoc.value+el->udpRcvdFromRem.value;

  printTableDoubleEntry(buf, sizeof(buf), "UDP", COLOR_1, (float)actTotalSent/1024,
			100*((float)SD(actTotalSent, totalSent)),
			(float)actTotalRcvd/1024,
			100*((float)SD(actTotalRcvd, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "ICMP", COLOR_1, (float)el->icmpSent.value/1024,
			100*((float)SD(el->icmpSent.value, totalSent)),
			(float)el->icmpRcvd.value/1024,
			100*((float)SD(el->icmpRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "(R)ARP", COLOR_1, (float)el->arp_rarpSent.value/1024,
			100*((float)SD(el->arp_rarpSent.value, totalSent)),
			(float)el->arp_rarpRcvd.value/1024,
			100*((float)SD(el->arp_rarpRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "DLC", COLOR_1, (float)el->dlcSent.value/1024,
			100*((float)SD(el->dlcSent.value, totalSent)),
			(float)el->dlcRcvd.value/1024,
			100*((float)SD(el->dlcRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "IPX", COLOR_1, (float)el->ipxSent.value/1024,
			100*((float)SD(el->ipxSent.value, totalSent)),
			(float)el->ipxRcvd.value/1024,
			100*((float)SD(el->ipxRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "Decnet", COLOR_1, (float)el->decnetSent.value/1024,
			100*((float)SD(el->decnetSent.value, totalSent)),
			(float)el->decnetRcvd.value/1024,
			100*((float)SD(el->decnetRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "AppleTalk", COLOR_1, (float)el->appletalkSent.value/1024,
			100*((float)SD(el->appletalkSent.value, totalSent)),
			(float)el->appletalkRcvd.value/1024,
			100*((float)SD(el->appletalkRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "OSPF", COLOR_1, (float)el->ospfSent.value/1024,
			100*((float)SD(el->ospfSent.value, totalSent)),
			(float)el->ospfRcvd.value/1024,
			100*((float)SD(el->ospfRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "NetBios", COLOR_1, (float)el->netbiosSent.value/1024,
			100*((float)SD(el->netbiosSent.value, totalSent)),
			(float)el->netbiosRcvd.value/1024,
			100*((float)SD(el->netbiosRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "IGMP", COLOR_1, (float)el->igmpSent.value/1024,
			100*((float)SD(el->igmpSent.value, totalSent)),
			(float)el->igmpRcvd.value/1024,
			100*((float)SD(el->igmpRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "OSI", COLOR_1, (float)el->osiSent.value/1024,
			100*((float)SD(el->osiSent.value, totalSent)),
			(float)el->osiRcvd.value/1024,
			100*((float)SD(el->osiRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "QNX", COLOR_1, (float)el->qnxSent.value/1024,
			100*((float)SD(el->qnxSent.value, totalSent)),
			(float)el->qnxRcvd.value/1024,
			100*((float)SD(el->qnxRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "STP", COLOR_1, (float)el->stpSent.value/1024,
			100*((float)SD(el->stpSent.value, totalSent)),
			(float)el->stpRcvd.value/1024,
			100*((float)SD(el->stpRcvd.value, totalRcvd)));

  printTableDoubleEntry(buf, sizeof(buf), "Other", COLOR_1, (float)el->otherSent.value/1024,
			100*((float)SD(el->otherSent.value, totalSent)),
			(float)el->otherRcvd.value/1024,
			100*((float)SD(el->otherRcvd.value, totalRcvd)));

#ifdef HAVE_GDCHART
  {
    totalSent = el->tcpSentLoc.value+el->tcpSentRem.value+
      el->udpSentLoc.value+el->udpSentRem.value+
      el->icmpSent.value+el->ospfSent.value+el->igmpSent.value+el->stpSent.value+
      el->ipxSent.value+el->osiSent.value+el->dlcSent.value+
      el->arp_rarpSent.value+el->decnetSent.value+el->appletalkSent.value+
      el->netbiosSent.value+el->qnxSent.value+el->otherSent.value;

    totalRcvd = el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value+
      el->udpRcvdLoc.value+el->udpRcvdFromRem.value+
      el->icmpRcvd.value+el->ospfRcvd.value+el->igmpRcvd.value+el->stpRcvd.value+
      el->ipxRcvd.value+el->osiRcvd.value+el->dlcRcvd.value+
      el->arp_rarpRcvd.value+el->decnetRcvd.value+el->appletalkRcvd.value+
      el->netbiosRcvd.value+el->qnxRcvd.value+el->otherRcvd.value;

    if((totalSent > 0) || (totalRcvd > 0)) {
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Protocol Distribution</TH>",
		  getRowColor()) < 0)
	BufferTooShort();
      sendString(buf);

      if(el->hostNumIpAddress[0] != '\0') {
        strncpy(linkName, el->hostNumIpAddress, sizeof(linkName));
      } else {
        strncpy(linkName, el->ethAddressString, sizeof(linkName));
        for(i=0; linkName[i] != '\0'; i++)
          if(linkName[i] == ':')
            linkName[i] = '_';  /* to avoid escaping chars */
      }

      if(totalSent > 0) {
	if(snprintf(buf, sizeof(buf),
		    "<TD WIDTH=250 "TD_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostTrafficDistrib-%s"CHART_FORMAT"?1 ALT=\"Sent Traffic Distribution for %s\"></TD>",
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
		      "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostIPTrafficDistrib-%s"CHART_FORMAT"?1 ALT=\"Sent IP Traffic Distribution for %s\"></TD>",
		      el->hostNumIpAddress, el->hostNumIpAddress) < 0)
	    BufferTooShort();
	  sendString(buf);
	} else
	  sendString("<TD "TD_BG" COLSPAN=2 WIDTH=250>&nbsp;</TD>");

	if((el->tcpRcvdLoc.value+el->tcpRcvdFromRem.value+el->udpRcvdLoc.value+el->udpRcvdFromRem.value) > 0) {
	  if(snprintf(buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2><IMG SRC=hostIPTrafficDistrib-"
		      "%s"CHART_FORMAT" ALT=\"Received IP Traffic Distribution for %s\"></TD></TR>",
		      el->hostNumIpAddress, el->hostNumIpAddress) < 0)
	    BufferTooShort();
	  sendString(buf);
	} else
	  sendString("<TD "TD_BG" COLSPAN=2 WIDTH=250>&nbsp;</TD>");

	sendString("</TR>");
      }
    }
  }
#endif

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");
}

/* ************************************ */

void printHostIcmpStats(HostTraffic *el) {
  char buf[BUF_SIZE];

  if(el->icmpInfo == NULL) return;

  sendString("<CENTER>\n<H1>ICMP Traffic</H1><p>\n");
  sendString("<TABLE BORDER>\n");
  sendString("<TR "TR_ON"><th>Type</th>"
	     "<TH "TH_BG" ALIGN=LEFT>Pkt&nbsp;Sent</TH>"
	     "<TH "TH_BG" ALIGN=LEFT>Pkt&nbsp;Rcvd</TH></TR>\n");

  if(el->icmpInfo->icmpMsgSent[ICMP_ECHO].value+el->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Echo Request</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_ECHO].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_ECHO].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value+el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Echo Reply</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_UNREACH].value+el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Unreach</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_UNREACH].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_REDIRECT].value+el->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Redirect</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_REDIRECT].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value+el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Router Advertisement</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value+el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Time Exceeded</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB].value+el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Parameter Problem</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_MASKREQ].value+el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Network Mask Request</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_MASKREQ].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY].value+el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Network Mask Reply</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH].value+el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Source Quench</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP].value+el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Timestamp</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST].value+el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Info Request</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY].value+el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY].value > 0) {
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON"><TH "TH_BG" ALIGN=LEFT>Info Reply</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>",
		formatPkts(el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY].value),
		formatPkts(el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY].value)) < 0)
      BufferTooShort();
    sendString(buf);
  }

  sendString("</TABLE>"TABLE_OFF"</CENTER>\n");
}

/* ************************************ */

void printHostHTTPVirtualHosts(HostTraffic *el, int actualDeviceId) {
  char buf[BUF_SIZE];

  if(el->httpVirtualHosts != NULL) {
    VirtualHostList *list = el->httpVirtualHosts;

    printSectionTitle("HTTP Virtual Hosts Traffic");
    sendString("<CENTER>\n<TABLE BORDER=0><TR><TD "TD_BG" VALIGN=TOP>\n");

    sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=100%>"
	       "<TR "TR_ON"><TH "TH_BG">Virtual Host</TH>"
	       "<TH "TH_BG">Sent</TH><TH "TH_BG">Rcvd</TH></TR>\n");

    while(list != NULL) {
      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=CENTER>%s&nbsp;</TD>"
		  "<TD "TD_BG" ALIGN=CENTER>%s&nbsp;</TD></TR>\n",
		  getRowColor(), list->virtualHostName,
		  formatBytes(list->bytesSent.value, 1),
		  formatBytes(list->bytesRcvd.value, 1)) < 0)
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

void printHostContactedPeers(HostTraffic *el, int actualDeviceId) {
  u_int i, titleSent = 0;
  char buf[BUF_SIZE];

  if((el->pktSent.value != 0) || (el->pktRcvd.value != 0)) {
    int ok =0;

    for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
      if(((el->contactedSentPeers.peersIndexes[i] != NO_PEER)
	  && (el->contactedSentPeers.peersIndexes[i] != myGlobals.otherHostEntryIdx))
	 || ((el->contactedRcvdPeers.peersIndexes[i] != NO_PEER)
	     && (el->contactedRcvdPeers.peersIndexes[i] != myGlobals.otherHostEntryIdx))) {
	  ok = 1;
	  break;
	}

    if(ok) {
      struct hostTraffic el2;
      int numEntries;

      for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	  if((el->contactedSentPeers.peersIndexes[i] != NO_PEER)
	     && (el->contactedSentPeers.peersIndexes[i] != myGlobals.otherHostEntryIdx)) {

	    if(retrieveHost(el->contactedSentPeers.peersIndexes[i], &el2) == 0) {
	      if(numEntries == 0) {
		printSectionTitle("Last Contacted Peers");
		titleSent = 1;
		sendString("<CENTER>\n"
			   "<TABLE BORDER=0><TR><TD "TD_BG" VALIGN=TOP>\n");

		sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=100%>"
			   "<TR "TR_ON"><TH "TH_BG">Sent To</TH>"
			   "<TH "TH_BG">Address</TH></TR>\n");
	      }

	      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
			  "<TD "TD_BG" ALIGN=CENTER>%s&nbsp;</TD></TR>\n",
			  getRowColor(), makeHostLink(&el2, 0, 0, 0),
			  el2.hostNumIpAddress) < 0)
		BufferTooShort();

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
	if((el->contactedRcvdPeers.peersIndexes[i] != NO_PEER)
	   && (el->contactedRcvdPeers.peersIndexes[i] != myGlobals.otherHostEntryIdx)) {

	  if(retrieveHost(el->contactedRcvdPeers.peersIndexes[i], &el2) == 0) {
	      if(numEntries == 0) {
		if(!titleSent) printSectionTitle("Last Contacted Peers");
		sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1>"
			   "<TR "TR_ON"><TH "TH_BG">Received From</TH>"
			   "<TH "TH_BG">Address</TH></TR>\n");
	      }

	      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
			  "<TD "TD_BG" ALIGN=CENTER>%s&nbsp;</TD></TR>\n",
			  getRowColor(), makeHostLink(&el2, 0, 0, 0),
			  el2.hostNumIpAddress) < 0)
		BufferTooShort();

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

/* Function below courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */

char *getSessionState(IPSession *session) {
  switch (session->sessionState) {
  case STATE_SYN:
    return("Sent&nbsp;Syn");
  case STATE_SYN_ACK:
    return("Rcvd&nbsp;Syn/Ack");
  case STATE_ACTIVE:
    return("Active");
  case STATE_FIN1_ACK0:
    return("Fin1&nbsp;Ack0");
  case STATE_FIN1_ACK1:
    return("Fin1&nbsp;Ack1");
  case STATE_FIN2_ACK0:
    return("Fin2&nbsp;Ack0");
  case STATE_FIN2_ACK1:
    return("Fin2&nbsp;Ack1");
  case STATE_FIN2_ACK2:
    return("Fin2&nbsp;Ack2");
  case STATE_TIMEOUT:
    return("Timeout");
  case STATE_END:
    return("End");
  }

 return("*Unknown*");
}

/* ************************************ */

void printHostSessions(HostTraffic *el, u_int elIdx, int actualDeviceId) {
  char buf[BUF_SIZE];
  IpGlobalSession *scanner=NULL;
  char *sessionType=NULL;
  u_short numSessions;
  u_int idx, i, sessionIdx;
  static char _sport[8], _dport[8];

  for(sessionIdx=0; sessionIdx<2; sessionIdx++) {
    if(sessionIdx == 0) {
      if(el->tcpSessionList != NULL) {
	printSectionTitle("TCP Session History");
      }

      scanner = el->tcpSessionList;
      sessionType = "TCP";
    } else {
      if(el->udpSessionList != NULL) {
	printSectionTitle("UDP Session History");
      }

      scanner = el->udpSessionList;
      sessionType = "UDP";
    }

    numSessions = 0;

    while(scanner != NULL) {
      char *whoswho, *svc=NULL, tmpSvc[16];

      if(scanner->magic != MAGIC_NUMBER) {
	traceEvent(TRACE_ERROR, "===> Magic assertion failed (3) for host %s", el->hostNumIpAddress);
      }

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
	  BufferTooShort();
	svc = tmpSvc;
      }

      if(numSessions == 0) {
	sendString("<CENTER>\n");
	if(snprintf(buf, sizeof(buf), ""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%%\">\n<TR "TR_ON">"
		    "<TH "TH_BG" COLSPAN=2>%s&nbsp;Service</TH>"
		    "<TH "TH_BG">Role</TH><TH "TH_BG">"
		    "#&nbsp;Sessions</TH>"
		    "<TH "TH_BG">Bytes&nbsp;Sent</TH>"
		    "<TH "TH_BG">Bytes&nbsp;Rcvd</TH>"
		    "<TH "TH_BG">Last&nbsp;Seen</TH>"
		    "<TH "TH_BG">First&nbsp;Seen</TH>"
		    "<TH "TH_BG">Peers</TH></TR>\n",
		    sessionType) < 0) BufferTooShort();
	sendString(buf);
      }

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=RIGHT>%s</TH>"
		  "<TD "TD_BG" ALIGN=CENTER>%d</TD>"
		  "<TD "TD_BG" ALIGN=CENTER>%s</TD><TD "TD_BG" ALIGN=CENTER>%d"
		  "</TD><TD "TD_BG" ALIGN=CENTER>%s</TD>"
		  "<TD "TD_BG" ALIGN=CENTER>%s</TD><TD "TD_BG">"
		  "%s</TD><TD "TD_BG">%s</TD>\n",
		  getRowColor(), svc, scanner->port, whoswho,
		  (int)scanner->sessionCounter,
		  formatBytes(scanner->bytesSent.value, 1),
		  formatBytes(scanner->bytesRcvd.value, 1),
		  formatTime(&(scanner->lastSeen), 1),
		  formatTime(&(scanner->firstSeen), 1)
		  ) < 0) BufferTooShort();
      sendString(buf);
      numSessions++;

      sendString("<TD "TD_BG"><UL>");
      for(i=0; i < MAX_NUM_CONTACTED_PEERS; i++) {
	u_int theIdx = scanner->peers.peersIndexes[i];

	if(theIdx != NO_PEER) {
	  HostTraffic host;

	  if(retrieveHost(theIdx, &host) == 0) {
	    sendString("\n<li>");
	    sendString(makeHostLink(&host, 0, 0, 0));
	  }
	}

      }

      sendString("</UL></TD></TR>\n");

      scanner = (IpGlobalSession*)(scanner->next);
    }

    if(numSessions > 0) {
      sendString("</TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    }

    if(sessionIdx == 0) {
      /* Now print currently established TCP sessions (if any) */
      for(idx=1, numSessions=0; idx<myGlobals.device[myGlobals.actualReportDeviceId].numTcpSessions; idx++)
	if((myGlobals.device[myGlobals.actualReportDeviceId].tcpSession[idx] != NULL)
	   && ((myGlobals.device[myGlobals.actualReportDeviceId].tcpSession[idx]->initiatorIdx == elIdx)
	       || (myGlobals.device[myGlobals.actualReportDeviceId].tcpSession[idx]->remotePeerIdx == elIdx))) {
	  char *sport, *dport, *remotePeer;
	  Counter dataSent, dataRcvd, retrDataSent, retrDataRcvd;
	  Counter fragDataSent, fragDataRcvd;
	  int retrSentPercentage, retrRcvdPercentage;
	  char fragStrSent[64], fragStrRcvd[64], *moreSessionInfo;
	  IPSession *session = myGlobals.device[myGlobals.actualReportDeviceId].tcpSession[idx];

	  while(session != NULL) {
#ifndef PRINT_ALL_SESSIONS
	    if(session->sessionState != STATE_ACTIVE) {
	      session = session->next;
	      continue;
	    }
#endif

	    if(session->remotePeerIdx == NO_PEER) {
	      /* This should not happen */
	      session = session->next;
	      continue;
	    }

	    if(numSessions == 0) {
	      printSectionTitle("Active TCP Sessions");
	      sendString("<CENTER>\n");
	      sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\"><TR "TR_ON">"
			 "<TH "TH_BG">Local&nbsp;Port</TH>"
			 "<TH "TH_BG">Rem&nbsp;Peer:Port</TH>"
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
#ifdef PRINT_ALL_SESSIONS
			 "<TH "TH_BG">State</TH>"
#endif
			 "</TR>\n");
	    }

	    if(session->initiatorIdx == elIdx) {
	      sport = getPortByNum(session->sport, IPPROTO_TCP);
	      dport = getPortByNum(session->dport, IPPROTO_TCP);
	      if(sport == NULL) {
		if(snprintf(_sport, sizeof(_sport), "%d",
			    session->sport) < 0)
		  BufferTooShort();
		sport = _sport;
	      }

	      if(dport == NULL) {
		if(snprintf(_dport, sizeof(_dport), "%d",
			    session->dport) < 0)
		  BufferTooShort();
		dport = _dport;
	      }
	      remotePeer = makeHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
					hash_hostTraffic[checkSessionIdx(myGlobals.device[myGlobals.actualReportDeviceId].
									 tcpSession[idx]->remotePeerIdx)],
					SHORT_FORMAT, 0, 0);
	      dataSent     = session->bytesSent.value;
	      dataRcvd     = session->bytesRcvd.value;
	      retrDataSent = session->bytesRetranI2R.value;
	      retrDataRcvd = session->bytesRetranR2I.value;
	      fragDataSent = session->bytesFragmentedSent.value;
	      fragDataRcvd = session->bytesFragmentedRcvd.value;
	    } else {
	      /* Responder */
	      sport = getPortByNum(session->dport, IPPROTO_TCP);
	      dport = getPortByNum(session->sport, IPPROTO_TCP);
	      if(sport == NULL) {
		if(snprintf(_sport, sizeof(_sport), "%d",
			    session->dport) < 0)
		  BufferTooShort();
		sport = _sport;
	      }

	      if(dport == NULL) {
		if(snprintf(_dport, sizeof(_dport), "%d",
			    session->sport) < 0)
		  BufferTooShort();
		dport = _dport;
	      }

	      remotePeer = makeHostLink(myGlobals.device[myGlobals.actualReportDeviceId].
					hash_hostTraffic[checkSessionIdx(myGlobals.device[myGlobals.actualReportDeviceId].
									 tcpSession[idx]->initiatorIdx)],
					SHORT_FORMAT, 0, 0);
	      dataSent     = session->bytesRcvd.value;
	      dataRcvd     = session->bytesSent.value;
	      retrDataSent = session->bytesRetranR2I.value;
	      retrDataRcvd = session->bytesRetranI2R.value;
	      fragDataSent = session->bytesFragmentedRcvd.value;
	      fragDataRcvd = session->bytesFragmentedSent.value;
	    }

	    /* Sanity check */
	    if((myGlobals.actTime < session->firstSeen)
	       || (session->firstSeen == 0))
	      session->firstSeen = myGlobals.actTime;

	    retrSentPercentage = (int)((float)(retrDataSent*100))/((float)(dataSent+1));
	    retrRcvdPercentage = (int)((float)(retrDataRcvd*100))/((float)(dataRcvd+1));

	    if(fragDataSent == 0)
	      fragStrSent[0] = '\0';
	    else {
	      if(snprintf(fragStrSent, sizeof(fragStrSent), "(%.1f fragmented)",
			  (int)((float)(fragDataSent*100))/((float)(dataSent+1))) < 0)
		BufferTooShort();
	    }
	    if(fragDataRcvd == 0)
	      fragStrRcvd[0] = '\0';
	    else {
	      if(snprintf(fragStrRcvd, sizeof(fragStrRcvd), "(%.1f fragmented)",
			  (int)((float)(fragDataRcvd*100))/((float)(dataRcvd+1))) < 0)
		BufferTooShort();
	    }

	    moreSessionInfo = "";

	    if(session->passiveFtpSession)
	      moreSessionInfo = "&nbsp;[FTP]";
	    else
	      moreSessionInfo = "";

	    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s>"
			"<TD "TD_BG" ALIGN=RIGHT>%s%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s:%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s %s</TD>"
#ifdef PRINT_RETRANSMISSION_DATA
			"<TD "TD_BG" ALIGN=RIGHT>%s [%d%%]</TD>"
#endif
			"<TD "TD_BG" ALIGN=RIGHT>%s %s</TD>"
#ifdef PRINT_RETRANSMISSION_DATA
			"<TD "TD_BG" ALIGN=RIGHT>%s [%d%%]</TD>"
#endif
			, getRowColor(),
			sport, moreSessionInfo,
			remotePeer, dport,
			formatBytes(dataSent, 1), fragStrSent,
#ifdef PRINT_RETRANSMISSION_DATA
			formatBytes(retrDataSent, 1),
			retrSentPercentage,
#endif
			formatBytes(dataRcvd, 1), fragStrRcvd
#ifdef PRINT_RETRANSMISSION_DATA
			, formatBytes(retrDataRcvd, 1),
			retrRcvdPercentage
#endif
			) < 0) BufferTooShort();

	    sendString(buf);

	    if(snprintf(buf, sizeof(buf),
			"<TD "TD_BG" ALIGN=CENTER NOWRAP>%d:%d</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
			"<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
#ifdef PRINT_ALL_SESSIONS
			"<TD "TD_BG" ALIGN=CENTER>%s</TD>"
#endif
			"</TR>\n",
			session->minWindow,
			session->maxWindow,
			formatTime(&(session->firstSeen), 1),
			formatTime(&(session->lastSeen), 1),
			formatSeconds(myGlobals.actTime-session->firstSeen),
			formatLatency(session->nwLatency,
				      session->sessionState)
#ifdef PRINT_ALL_SESSIONS
			, getSessionState(session)
#endif
			) < 0) BufferTooShort();

	    sendString(buf);

	    numSessions++;
	    session = session->next;
	  }
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
    if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s "
		"<IMG ALT=\"High Risk\" SRC=/Risk_high.gif> "
		"<IMG ALT=\"Medium Risk\" SRC=/Risk_medium.gif> "
		"<IMG  ALT=\"Low Risk\" SRC=/Risk_low.gif>"
		"</TH><TD "TD_BG" ALIGN=RIGHT NOWRAP><OL>", getRowColor(),
		"Network Healthness") < 0) BufferTooShort();
    sendString(buf);

    if(hasWrongNetmask(el))
      sendString("<LI><IMG ALT=\"Medium Risk\" SRC=/Risk_medium.gif><A HREF=/help.html#1>"
		 "Wrong network mask or bridging enabled</A>\n");

    if(hasDuplicatedMac(el))
      sendString("<LI><IMG ALT=\"High Risk\" SRC=/Risk_high.gif><A HREF=/help.html#2>"
		 "Duplicated MAC found for this IP address (spoofing?)</A>\n");

    sendString("</OL></TD></TR>\n");
  }
}

/* ************************************ */

void checkHostProvidedServices(HostTraffic *el) {
  char buf[BUF_SIZE];

  if(isServer(el)
     || isWorkstation(el)
     || isMasterBrowser(el)
     || isPrinter(el)
     || isBridgeHost(el)
     || nameServerHost(el)
     || gatewayHost(el)
     || isSMTPhost(el) || isIMAPhost(el) || isPOPhost(el)
     || isDirectoryHost(el)
     || isFTPhost(el)
     || isHTTPhost(el)
     || isWINShost(el)
     || isDHCPClient(el)        || isDHCPServer(el)
     ) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>", getRowColor(), "Host Type") < 0) BufferTooShort();
    sendString(buf);

    if(isServer(el))           sendString("Server<BR>\n");
    if(isWorkstation(el))      sendString("Workstation<BR>\n");
    if(isMasterBrowser(el))    sendString("Master Browser<BR>\n");
    if(isPrinter(el))          sendString("Printer&nbsp;<IMG ALT=Printer SRC=printer.gif BORDER=0><BR>\n");
    if(isBridgeHost(el))       sendString("Bridge<BR>\n");

    if(nameServerHost(el))     sendString("&nbsp;<IMG ALT=\"DNS Server\" SRC=/dns.gif BORDER=0>&nbsp;Name Server<BR>\n");
    if(gatewayHost(el))        sendString("Gateway&nbsp;<IMG ALT=Router SRC=/router.gif BORDER=0>&nbsp;<BR>\n");
    if(isSMTPhost(el))         sendString("SMTP Server&nbsp;<IMG ALT=\"Mail Server (SMTP)\"  SRC=/mail.gif BORDER=0>&nbsp;<BR>\n");
    if(isPOPhost(el))          sendString("POP Server<BR>\n");
    if(isIMAPhost(el))         sendString("IMAP Server<BR>\n");
    if(isDirectoryHost(el))    sendString("Directory Server<BR>\n");
    if(isFTPhost(el))          sendString("FTP Server<BR>\n");
    if(isHTTPhost(el))         sendString("HTTP Server&nbsp;<IMG ALT=\"HTTP Server\" SRC=/web.gif BORDER=0><BR>\n");
    if(isWINShost(el))         sendString("WINS Server<BR>\n");

    if(isDHCPClient(el))          sendString("BOOTP/DHCP Client&nbsp;<IMG ALT=\"DHCP Client\" SRC=/bulb.gif BORDER=0><BR>\n");
    if(isDHCPServer(el))          sendString("BOOTP/DHCP Server&nbsp;<IMG ALT=\"DHCP Server\" SRC=/antenna.gif BORDER=0>&nbsp;<BR>\n");
    sendString("</TD></TR>");
  }
}

/* ************************************ */

void printHostDetailedInfo(HostTraffic *el, int actualDeviceId) {
  char buf[BUF_SIZE], buf1[64], sniffedName[MAXDNAME];
  float percentage;
  Counter total;
  int printedHeader, i;
  char *dynIp, *multihomed;

#ifdef MULTITHREADED
  if(myGlobals.numericFlag == 0) accessMutex(&myGlobals.addressResolutionMutex, "printAllSessionsHTML");
#endif

  buf1[0]=0;
  if(getSniffedDNSName(el->hostNumIpAddress, sniffedName, sizeof(sniffedName))) {
    if(el->hostSymIpAddress[0] == '\0' || strcmp(sniffedName, el->hostSymIpAddress))
      snprintf(buf1, sizeof(buf1), " (%s)", sniffedName);
  }

  if(el->hostSymIpAddress[0] != '\0') {
    if(snprintf(buf, sizeof(buf), "Info about host"
		" <A HREF=http://%s/ TARGET=\"_blank\" "
                "TITLE=\"Link to web server on host, IF available\">%s %s</A>\n",
                el->hostNumIpAddress, el->hostSymIpAddress, buf1) < 0)
      BufferTooShort();
  } else if(el->hostNumIpAddress[0] != '\0') {
    if(snprintf(buf, sizeof(buf), "Info about host"
		" <A HREF=http://%s/ TARGET=\"_blank\" "
                "TITLE=\"Link to web server on host, IF available\">%s %s</A>\n",
                el->hostNumIpAddress, el->hostNumIpAddress, buf1) < 0)
      BufferTooShort();
  } else {
    if(snprintf(buf, sizeof(buf), "Info about host %s",	el->ethAddressString) < 0)
      BufferTooShort();
  }

#ifdef MULTITHREADED
  if(myGlobals.numericFlag == 0) releaseMutex(&myGlobals.addressResolutionMutex);
#endif

  printHTMLheader(buf, 0);
  sendString("<CENTER>\n");
  sendString("<P>"TABLE_ON"<TABLE BORDER=1 WIDTH=\"100%\">\n");

  if(el->hostNumIpAddress[0] != '\0') {
    char *countryIcon, *hostType;

#ifdef MULTITHREADED
    if(myGlobals.numericFlag == 0) accessMutex(&myGlobals.addressResolutionMutex, "printAllSessions-2");
#endif

    /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
    if(strcmp(el->hostNumIpAddress, el->hostSymIpAddress) != 0) {
#ifdef MULTITHREADED
      if(myGlobals.numericFlag == 0) releaseMutex(&myGlobals.addressResolutionMutex);
#endif
      countryIcon = getHostCountryIconURL(el);
    } else {
#ifdef MULTITHREADED
      if(myGlobals.numericFlag == 0) releaseMutex(&myGlobals.addressResolutionMutex);
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

    if(isMultihomed(el) && (!broadcastHost(el)))
      multihomed = "&nbsp;-&nbsp;multihomed&nbsp;<IMG ALT=\"Multihomed Host\" SRC=/multihomed.gif BORDER=0>";
    else
      multihomed = "";

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%s&nbsp;%s&nbsp;[%s%s%s]",
		getRowColor(),
		"IP&nbsp;Address",
		el->hostNumIpAddress,
		countryIcon, hostType, dynIp, multihomed) < 0)
      BufferTooShort();
    sendString(buf);

    sendString("</TD></TR>\n");

    if(isMultihomed(el) && (!broadcastHost(el))) {
      u_int elIdx;

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>&nbsp;<OL>",
		  getRowColor(), "Multihomed Addresses") < 0)
	BufferTooShort();
      sendString(buf);

      for(elIdx=1; elIdx<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; elIdx++) {
	HostTraffic *theHost;

	if(elIdx == myGlobals.otherHostEntryIdx) continue;

	theHost = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[elIdx];

	if((theHost != NULL)
	   && (theHost != el)
	   && (memcmp(theHost->ethAddress, el->ethAddress, ETHERNET_ADDRESS_LEN) == 0)) {
	  if(snprintf(buf, sizeof(buf), "<LI><A HREF=/%s.html>%s</A>",
		      theHost->hostNumIpAddress, theHost->hostNumIpAddress) < 0)
	    BufferTooShort();
	  sendString(buf);
	}
      }

      sendString("</TD></TR>");
    }

    if(el->dhcpStats != NULL) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>",
		  getRowColor(), "DHCP Information") < 0)
	BufferTooShort();
      sendString(buf);

      sendString("<TD "TD_BG"><TABLE BORDER WIDTH=100%>\n");

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n", getRowColor(), "DHCP Server",
		  _intoa(el->dhcpStats->dhcpServerIpAddress, buf1, sizeof(buf1))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n", getRowColor(), "Previous IP Address",
		  _intoa(el->dhcpStats->previousIpAddress, buf1, sizeof(buf1))) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n",
		  getRowColor(), "Address Assigned on",
		  formatTime(&(el->dhcpStats->assignTime), 1)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n",
		  getRowColor(), "To be Renewed Before",
		  formatTime(&(el->dhcpStats->renewalTime), 1)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2>%s</TD></TR>\n",
		  getRowColor(), "Lease Ends on",
		  formatTime(&(el->dhcpStats->leaseTime), 1)) < 0)
	BufferTooShort();
      sendString(buf);


      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>DHCP Packets</TH>"
		  "<TH "TH_BG" ALIGN=CENTER>Sent</TH><TH "TH_BG" ALIGN=RIGHT>Rcvd</TH></TR>\n",
		  getRowColor()) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Discover",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_DISCOVER_MSG].value),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_DISCOVER_MSG].value)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Offer",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_OFFER_MSG].value),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_OFFER_MSG].value)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Request",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_REQUEST_MSG].value),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_REQUEST_MSG].value)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Decline",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_DECLINE_MSG].value),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_DECLINE_MSG].value)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Ack",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_ACK_MSG].value),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_ACK_MSG].value)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Nack",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_NACK_MSG].value),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_NACK_MSG].value)) < 0)
	BufferTooShort();
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Release",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_RELEASE_MSG].value),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_RELEASE_MSG].value)) < 0)
	BufferTooShort();
      sendString(buf);


      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Inform",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_INFORM_MSG].value),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_INFORM_MSG].value)) < 0)
	BufferTooShort();
      sendString(buf);


      if(snprintf(buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		  "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
		  getRowColor(), "DHCP Unknown Msg",
		  formatPkts(el->dhcpStats->dhcpMsgSent[DHCP_UNKNOWN_MSG].value),
		  formatPkts(el->dhcpStats->dhcpMsgRcvd[DHCP_UNKNOWN_MSG].value)) < 0)
	BufferTooShort();
      sendString(buf);

      sendString("</TABLE>"TABLE_OFF"</TD></TR>\n");
    }
  }

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
	      "<TD "TD_BG" ALIGN=RIGHT>"
	      "%s&nbsp;&nbsp;-&nbsp;&nbsp;%s&nbsp;[%s]</TD></TR>\n",
	      getRowColor(),
	      "First/Last&nbsp;Seen",
	      formatTime(&(el->firstSeen), 1),
	      formatTime(&(el->lastSeen), 1),
	      formatSeconds(el->lastSeen - el->firstSeen)) < 0)
    BufferTooShort();
  sendString(buf);

  if(el->hostAS != 0) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"<A HREF=\"http://ws.arin.net/cgi-bin/whois.pl?queryinput=AS%d\">%d</A></TD></TR>\n",
		getRowColor(), "Autonomous System", el->hostAS, el->hostAS) < 0) BufferTooShort();
    sendString(buf);
  }

  if(el->fullDomainName && (el->fullDomainName[0] != '\0')) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%s</TD></TR>\n",
		getRowColor(),
		"Domain", el->fullDomainName) < 0) BufferTooShort();
    sendString(buf);
  }

  if((!myGlobals.dontTrustMACaddr)
     && (el->ethAddressString[0] != '\0')
     && strcmp(el->ethAddressString, "00:00:00:00:00:00")
     && strcmp(el->ethAddressString, "00:01:02:03:04:05") /* dummy address */) {
    char *vendorName;

    if(isMultihomed(el)) {
      char *symMacAddr, symLink[32];

      symMacAddr = etheraddr_string(el->ethAddress);
      strcpy(symLink, symMacAddr);
      for(i=0; symLink[i] != '\0'; i++)
	if(symLink[i] == ':')
	  symLink[i] = '_';

      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<A HREF=%s.html>%s</A>%s</TD></TR>\n",
		  getRowColor(), "Main Host MAC Address",
		  symLink, symMacAddr,
		  myGlobals.separator /* it avoids empty cells not to be rendered */) < 0)
	BufferTooShort();
      sendString(buf);

    } else {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "MAC&nbsp;Address <IMG ALT=\"Network Interface Card (NIC)\" SRC=/card.gif BORDER=0>",
		  el->ethAddressString,
		  myGlobals.separator /* it avoids empty cells not to be rendered */) < 0)
	BufferTooShort();
      sendString(buf);
    }

    vendorName = getVendorInfo(el->ethAddress, 1);
    if(vendorName[0] != '\0') {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
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
     && (memcmp(el->lastEthAddress, el->ethAddress, ETHERNET_ADDRESS_LEN) != 0)) {
    /* Different MAC addresses */
    char *symMacAddr, symLink[32], shortBuf[64];

    symMacAddr = etheraddr_string(el->lastEthAddress);
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

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
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
    updateOSName(el);

    if((el->osName != NULL) && (el->osName[0] != '\0')) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "OS&nbsp;Name",
		  getOSFlag(el->osName, 1),
		  myGlobals.separator /* it avoids empty cells not to be rendered */) < 0)
	BufferTooShort();
      sendString(buf);
    }
  }

  if((el->nbHostName != NULL) && (el->nbDomainName != NULL)) {
    if(el->nbAccountName) {
      if(el->nbDomainName != NULL) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		    "%s@%s&nbsp;[domain %s] (%s) %s</TD></TR>\n",
		    getRowColor(), "NetBios&nbsp;Name",
		    el->nbAccountName, el->nbHostName, el->nbDomainName,
		    getNbNodeType(el->nbNodeType),
		    el->nbDescr ? el->nbDescr : "") < 0)
	  BufferTooShort();
      } else {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		    "%s@%s (%s) %s</TD></TR>\n",
		    getRowColor(), "NetBios&nbsp;Name",
		    el->nbAccountName, el->nbHostName,
		    getNbNodeType(el->nbNodeType),
		    el->nbDescr ? el->nbDescr : "") < 0)
	  BufferTooShort();
      }
    } else {
      if(el->nbDomainName != NULL) {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		    "%s&nbsp;[domain %s] (%s) %s</TD></TR>\n",
		    getRowColor(), "NetBios&nbsp;Name",
		    el->nbHostName, el->nbDomainName,
		    getNbNodeType(el->nbNodeType),
		    el->nbDescr ? el->nbDescr : "") < 0)
	  BufferTooShort();
      } else {
	if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		    "%s (%s) %s</TD></TR>\n",
		    getRowColor(), "NetBios&nbsp;Name",
		    el->nbHostName,
		    getNbNodeType(el->nbNodeType),
		    el->nbDescr ? el->nbDescr : "") < 0)
	  BufferTooShort();
      }
    }

    sendString(buf);
  } else if(el->nbHostName != NULL) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%s&nbsp;(%s) %s</TD></TR>\n",
		getRowColor(), "NetBios&nbsp;Name",
		el->nbHostName, getNbNodeType(el->nbNodeType),
		el->nbDescr ? el->nbDescr : "") < 0)
      BufferTooShort();
    sendString(buf);
  }

  if(el->atNetwork != 0) {
    char *nodeName = el->atNodeName;

    if(nodeName == NULL) nodeName = "";

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%s&nbsp;\n",
		getRowColor(), "AppleTalk&nbsp;Name",
		nodeName) < 0) BufferTooShort();
    sendString(buf);

    if(el->atNodeType[0] != NULL) {
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
      BufferTooShort();
    sendString(buf);
  }

  if(el->ipxHostName != NULL) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>"
		"%s&nbsp;[", getRowColor(), "IPX&nbsp;Name",
		el->ipxHostName) < 0)
      BufferTooShort();
    sendString(buf);

    for(i=0; i<el->numIpxNodeTypes; i++) {
      if(i>0) sendString("/");
      sendString(getSAPInfo(el->ipxNodeType[i], 1));
    }

    sendString("]</TD></TR>\n");
  }

  if(!multicastHost(el)) {
    if(subnetPseudoLocalHost(el)) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s</TD></TR>\n", getRowColor(),
		  "Host&nbsp;Location",
		  "Local (inside specified/local subnet)") < 0)
	BufferTooShort();
    } else {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s</TD></TR>\n", getRowColor(),
		  "Host&nbsp;Location",
		  "Remote (outside specified/local subnet)") < 0)
	BufferTooShort();
    }
    sendString(buf);
  }

  if(el->minTTL > 0) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%d:%d&nbsp;[~%d&nbsp;hop(s)]</TD></TR>\n",
		getRowColor(), "IP&nbsp;TTL&nbsp;(Time to Live)",
		el->minTTL, el->maxTTL, guessHops(el)) < 0) BufferTooShort();
    sendString(buf);
  }

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s"
#ifdef HAVE_RRD_H
	      " <A HREF=javascript:popUp(\"http://athlon.netikos.com/cgi-bin/rrd.cgi?path=%s/pktSent.rrd\")><IMG BORDER=0 SRC=/graph.gif></A>"
#endif
	      "</TH><TD "TD_BG" ALIGN=RIGHT>"
	      "%s/%s Pkts/%s Retran. Pkts [%d%%]</TD></TR>\n",
	      getRowColor(), "Total&nbsp;Data&nbsp;Sent",
#ifdef HAVE_RRD_H
	      el->hostNumIpAddress,
#endif
	      formatBytes(el->bytesSent.value, 1), formatPkts(el->pktSent.value),
	      formatPkts(el->pktDuplicatedAckSent.value),
	      (int)(((float)el->pktDuplicatedAckSent.value*100)/(float)(el->pktSent.value+1))
	      ) < 0) BufferTooShort();
  sendString(buf);

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
	      "%s Pkts</TD></TR>\n",
	      getRowColor(), "Broadcast&nbsp;Pkts&nbsp;Sent",
	      formatPkts(el->pktBroadcastSent.value)) < 0) BufferTooShort();
  sendString(buf);

  if(el->routedTraffic != NULL) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"%s/%s Pkts</TD></TR>\n",
		getRowColor(), "Routed Traffic",
		formatBytes(el->routedTraffic->routedBytes.value, 1),
		formatPkts(el->routedTraffic->routedPkts.value)) < 0)
      BufferTooShort();
    sendString(buf);
  }


  if((el->pktMulticastSent.value > 0) || (el->pktMulticastRcvd.value > 0)) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>",
		getRowColor(), "Multicast&nbsp;Traffic") < 0) BufferTooShort();
    sendString(buf);

    if(el->pktMulticastSent.value > 0) {
      if(snprintf(buf, sizeof(buf), "Sent&nbsp;%s/%s&nbsp;Pkts&nbsp;-",
		  formatBytes(el->bytesMulticastSent.value, 1),
		  formatPkts(el->pktMulticastSent.value)) < 0) BufferTooShort();
      sendString(buf);
    }

    if(el->pktMulticastRcvd.value > 0) {
      if(snprintf(buf, sizeof(buf), "Rcvd&nbsp;%s/%s&nbsp;Pkts",
		  formatBytes(el->bytesMulticastRcvd.value, 1),
		  formatPkts(el->pktMulticastRcvd.value)) < 0) BufferTooShort();
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

  if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s"
#ifdef HAVE_RRD_H
	      " <A HREF=javascript:popUp(\"http://athlon.netikos.com/cgi-bin/rrd.cgi?path=%s/pktRcvd.rrd\")><IMG BORDER=0 SRC=/graph.gif></A>"
#endif
	      "</TH><TD "TD_BG" ALIGN=RIGHT>"
	      "%s/%s Pkts/%s Retran. Pkts [%d%%]</TD></TR>\n",
	      getRowColor(), "Total&nbsp;Data&nbsp;Rcvd",
#ifdef HAVE_RRD_H
	      el->hostNumIpAddress,
#endif
	      formatBytes(el->bytesRcvd.value, 1), formatPkts(el->pktRcvd.value),
	      formatPkts(el->pktDuplicatedAckRcvd.value),
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
    if(el->contactedRouters.peersIndexes[i] != NO_PEER) {
      HostSerial routerIdx = el->contactedRouters.peersIndexes[i];

      if(routerIdx != NO_PEER) {
	HostTraffic router;

	if(retrieveHost(routerIdx, &router) == 0) {
	  if(!printedHeader) {
	    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>"
			"Used&nbsp;Subnet&nbsp;Routers</TH><TD "TD_BG" ALIGN=RIGHT>\n",
			getRowColor()) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }
	  printedHeader++;

	  if(printedHeader > 1) sendString("<BR>");

	  if(snprintf(buf, sizeof(buf), "%s\n",
		      makeHostLink(&router, SHORT_FORMAT, 0, 0)) < 0)
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

  if(el->userList != NULL) {
    UserList *list = el->userList;

    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>"
		"Known&nbsp;Users&nbsp;<IMG ALT=Users SRC=/users.gif BORDER=0></TH><TD "TD_BG" ALIGN=RIGHT>\n",
		getRowColor()) < 0)
      BufferTooShort();
    sendString(buf);

    while(list != NULL) {
      if(snprintf(buf, sizeof(buf), "%s&nbsp;[", list->userName) < 0)
	BufferTooShort();
      sendString(buf);

      if(FD_ISSET(POP_USER, &(list->userFlags))) sendString("&nbsp;POP&nbsp;");
      if(FD_ISSET(IMAP_USER, &(list->userFlags))) sendString("&nbsp;IMAP&nbsp;");
      if(FD_ISSET(SMTP_USER, &(list->userFlags))) sendString("&nbsp;SMTP&nbsp;");
      if(FD_ISSET(P2P_USER, &(list->userFlags))) sendString("&nbsp;P2P&nbsp;");
      if(FD_ISSET(FTP_USER, &(list->userFlags))) sendString("&nbsp;FTP&nbsp;");

      sendString("]<br>\n");
      list = list->next;
    }

    sendString("</TD></TR>\n");
  }

  /* **************************** */

  if((el->hostNumIpAddress[0] != '\0')
     && (!subnetPseudoLocalHost(el))
     && (!multicastHost(el))
     && (!privateIPAddress(el))) {
    if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		"[ <A HREF=\"http://www.radb.net/cgi-bin/radb/whois.cgi?obj=%s\">Whois</A> ]</TD></TR>\n",
		getRowColor(), "Further Host Information", el->hostNumIpAddress) < 0)
      BufferTooShort();
    sendString(buf);

    if(myGlobals.mapperURL) {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "<IMG SRC=\"%s?host=%s\" WIDTH=320 HEIGHT=200></TD></TR>\n",
		  getRowColor(),
		  "Host Physical Location",
		  myGlobals.mapperURL, el->hostNumIpAddress) < 0)
      BufferTooShort();
      sendString(buf);
    }
  }

  if(haveTrafficHistory()) {
    if(el->hostNumIpAddress[0] != '\0') {
      if(snprintf(buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT>%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "[ <A HREF=\"/ntop-bin/hostTraf.pl?host=%s\">History</A> ]</TD></TR>\n",
		  getRowColor(), "Traffic Information", el->hostNumIpAddress) < 0)
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
  char buf[BUF_SIZE];
  Counter tot, tot1;
  float f1, f2, f3, f4;

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
		formatPkts(ss->numLocalReqSent.value), f1,
		formatPkts(ss->numRemReqSent.value), f2,
		formatPkts(ss->numPositiveReplRcvd.value), f3,
		formatPkts(ss->numNegativeReplRcvd.value), f4,
		formatMicroSeconds(ss->fastestMicrosecLocalReqMade),
		formatMicroSeconds(ss->slowestMicrosecLocalReqMade),
		formatMicroSeconds(ss->fastestMicrosecRemReqMade),
		formatMicroSeconds(ss->slowestMicrosecRemReqMade)
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
		formatPkts(ss->numLocalReqRcvd.value), f1,
		formatPkts(ss->numRemReqRcvd.value), f2,
		formatPkts(ss->numPositiveReplSent.value), f3,
		formatPkts(ss->numNegativeReplSent.value), f4,
		formatMicroSeconds(ss->fastestMicrosecLocalReqServed),
		formatMicroSeconds(ss->slowestMicrosecLocalReqServed),
		formatMicroSeconds(ss->fastestMicrosecRemReqServed),
		formatMicroSeconds(ss->slowestMicrosecRemReqServed)
		) < 0) BufferTooShort();
	sendString(buf);
      }
    }
  }
}

/* ************************************ */

void printHostUsedServices(HostTraffic *el, int actualDeviceId) {
  Counter tot;

  if((el->dnsStats == NULL) && (el->httpStats == NULL))
    return;

  tot = 0;

  if(el->dnsStats)
    tot += el->dnsStats->numLocalReqSent.value+el->dnsStats->numRemReqSent.value;

  if(el->httpStats)
    tot += el->httpStats->numLocalReqSent.value+el->httpStats->numRemReqSent.value;

  if(tot > 0) {
    printSectionTitle("IP&nbsp;Service&nbsp;Stats:&nbsp;Client&nbsp;Role");
    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1 WIDTH=100%>\n<TR "TR_ON">"
	       "<TH "TH_BG">&nbsp;</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Loc.&nbsp;Req.&nbsp;Sent</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Rem.&nbsp;Req.&nbsp;Sent</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Pos.&nbsp;Reply&nbsp;Rcvd</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Neg.&nbsp;Reply&nbsp;Rcvd</TH>"
	       "<TH "TH_BG">Local&nbsp;RndTrip</TH>"
	       "<TH "TH_BG">Rem&nbsp;RndTrip</TH>"
	       "</TR>\n");

    if(el->dnsStats) printServiceStats("DNS", el->dnsStats, 1);
    if(el->httpStats) printServiceStats("HTTP", el->httpStats, 1);

    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");
  }

  /* ************ */

  tot = 0;

  if(el->dnsStats)
    tot += el->dnsStats->numLocalReqRcvd.value+el->dnsStats->numRemReqRcvd.value;

  if(el->httpStats)
    tot += el->httpStats->numLocalReqRcvd.value+el->httpStats->numRemReqRcvd.value;

  if(tot > 0) {
    printSectionTitle("IP&nbsp;Service&nbsp;Stats:&nbsp;Server&nbsp;Role");
    sendString("<CENTER>\n");
    sendString("<P>"TABLE_ON"<TABLE BORDER=1 WIDTH=100%>\n<TR "TR_ON">"
	       "<TH "TH_BG">&nbsp;</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Loc.&nbsp;Req.&nbsp;Rcvd</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Rem.&nbsp;Req.&nbsp;Rcvd</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Pos.&nbsp;Reply&nbsp;Sent</TH>"
	       "<TH "TH_BG" COLSPAN=2>#&nbsp;Neg.&nbsp;Reply&nbsp;Sent</TH>"
	       "<TH "TH_BG">Local&nbsp;RndTrip</TH>"
	       "<TH "TH_BG">Rem&nbsp;RndTrip</TH>"
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
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT WIDTH=150>%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT WIDTH=100>%s</TD>"
		"<TD "TD_BG" WIDTH=250>&nbsp;</TD></TR>\n",
		getRowColor(), label, formatKBytes(total)) < 0)
      BufferTooShort();
    break;
  case 100:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT WIDTH=150>%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT WIDTH=100>%s</TD>"
		"<TD ALIGN=CENTER WIDTH=250><IMG ALT=\"100%%\" ALIGN=MIDDLE SRC=/gauge.jpg WIDTH=\"250\" HEIGHT=12>"
		"</TD></TR>\n",
		getRowColor(), label, formatKBytes(total)) < 0)
      BufferTooShort();
    break;
  default:
    if(snprintf(buf, bufLen, "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT WIDTH=150>%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT WIDTH=100>%s</TD>"
		"<TD "TD_BG" WIDTH=250><TABLE BORDER=0 CELLPADDING=0 CELLSPACING=0 WIDTH=\"250\">"
		"<TR "TR_ON"><TD><IMG ALIGN=MIDDLE ALT=\"%d%%\" SRC=/gauge.jpg WIDTH=\"%d\" HEIGHT=12>"
		"</TD><TD "TD_BG" ALIGN=CENTER WIDTH=\"%d\" %s>"
		"<P>&nbsp;</TD></TR></TABLE>"TABLE_OFF"</TD></TR>\n",
		getRowColor(), label, formatKBytes(total),
		int_perc, (250*int_perc)/100,
		(250*(100-int_perc))/100, getActualRowColor()) < 0)
      BufferTooShort();
  }

  sendString(buf);
}

/* ************************ */

char* buildHTMLBrowserWindowsLabel(int i, int j) {
  static char buf[BUF_SIZE];
  int idx = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts + j;

#ifdef MULTITHREADED
  if(myGlobals.numericFlag == 0)
    accessMutex(&myGlobals.addressResolutionMutex, "buildHTMLBrowserWindowsLabel");
#endif

  if((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx] == NULL)
     || ((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value == 0)
	 && (myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value == 0)))
    buf[0]='\0';
  else if ((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value > 0)
	   && (myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value == 0)) {
    if(snprintf(buf, sizeof(buf), "(%s->%s)=%s/%s Pkts",
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostSymIpAddress,
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostSymIpAddress,
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value, 1),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsSent.value)) < 0)
      BufferTooShort();
  } else if ((myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value == 0)
	     && (myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value > 0)) {
    if(snprintf(buf, sizeof(buf), "(%s->%s)=%s/%s Pkts",
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostSymIpAddress,
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostSymIpAddress,
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value, 1),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsRcvd.value)) < 0)
      BufferTooShort();
  } else {
    if(snprintf(buf, sizeof(buf), "(%s->%s)=%s/%s Pkts, (%s->%s)=%s/%s Pkts",
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostSymIpAddress,
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostSymIpAddress,
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesSent.value, 1),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsSent.value),
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[j]->hostSymIpAddress,
		myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrixHosts[i]->hostSymIpAddress,
		formatBytes(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->bytesRcvd.value, 1),
		formatPkts(myGlobals.device[myGlobals.actualReportDeviceId].ipTrafficMatrix[idx]->pktsRcvd.value)) < 0)
      BufferTooShort();
  }

#ifdef MULTITHREADED
  if(myGlobals.numericFlag == 0) releaseMutex(&myGlobals.addressResolutionMutex);
#endif

  return(buf);
}

/* *********************************** */

void printHostHourlyTrafficEntry(HostTraffic *el, int i,
				 Counter tcSent, Counter tcRcvd) {
  float pctg;
  char buf[BUF_SIZE];

  if(snprintf(buf, BUF_SIZE, "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
	   formatBytes(el->last24HoursBytesSent[i].value, 0)) < 0)
    BufferTooShort();
  sendString(buf);

  if(tcSent > 0)
    pctg = (float)(el->last24HoursBytesSent[i].value*100)/(float)tcSent;
  else
    pctg = 0;

  if(snprintf(buf, BUF_SIZE, "<TD ALIGN=RIGHT %s>%.1f %%</TD>",
	   getBgPctgColor(pctg), pctg) < 0)
    BufferTooShort();
  sendString(buf);

  if(snprintf(buf, BUF_SIZE, "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
	   formatBytes(el->last24HoursBytesRcvd[i].value, 0)) < 0)
    BufferTooShort();
  sendString(buf);

 if(tcRcvd > 0)
    pctg = (float)(el->last24HoursBytesRcvd[i].value*100)/(float)tcRcvd;
  else
    pctg = 0;

  if(snprintf(buf, BUF_SIZE, "<TD ALIGN=RIGHT %s>%.1f %%</TD></TR>",
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

#endif /* MICRO_NTOP */

 /* ********************************** */

void printFlagedWarning(char *text) {
  char buf[BUF_SIZE];

  snprintf(buf, BUF_SIZE,
 	   "<CENTER>\n"
 	   "<P><IMG ALT=Warning SRC=/warning.gif>\n"
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

/* ******************************** */

#define MAX_ENTRY     (u_short)-1

static char* formatElementData(ElementHash *hash, u_char dataSent, char *buf, int bufLen) {
  
  if((dataSent && (hash->bytesSent.value == 0)) 
     || ((!dataSent) && (hash->bytesRcvd.value == 0)))
    return("&nbsp;");

  if(dataSent) {
    if(snprintf(buf, bufLen, "%s/%s Pkts",
		formatBytes(hash->bytesSent.value, 1),
		formatPkts(hash->pktsSent.value)) < 0)
      BufferTooShort();    
  } else {
    if(snprintf(buf, bufLen, "%s/%s Pkts",
		formatBytes(hash->bytesRcvd.value, 1),
		formatPkts(hash->pktsRcvd.value)) < 0)
      BufferTooShort();    
  }

  return(buf);
}

/* ******************************** */

void dumpElementHash(ElementHash **theHash) {
  u_char entries[MAX_ENTRY];
  ElementHash *hashList[MAX_ENTRY];
  char buf[BUF_SIZE], buf1[96];
  ElementHash *hash, hashListEntry;
  int i, j;

  if(theHash == NULL) return;

  /* *********** */

#ifdef DEBUG
    for(i=0; i<ELEMENT_HASH_LEN; i++)
      if(theHash[i] != NULL) {
	printf("[%d] ", theHash[i]->id);
	hash = theHash[i]->next;

	while(hash != NULL) {
	  printf("%d ", hash->id);
	  hash = hash->next;
	}
	
	printf("\n");
      }
#endif

  /* *********** */

  memset(entries, 0, sizeof(entries));

  for(i=0; i<ELEMENT_HASH_LEN; i++) {
    if((theHash[i] != NULL) && (theHash[i]->id < MAX_ENTRY)) {
      entries[theHash[i]->id] = 1;

      hash = theHash[i];
      while(hash != NULL) {
	if(hash->id < MAX_ENTRY) {
	  entries[hash->id] = 1;
	}

	hash = hash->next;	
      }
    }
  }

  sendString("<TABLE BORDER>\n"
	     "<TR><TH>AS</TH><TH>Data Sent</TH><TH>Data Rcvd</TH><TH>Peers</TH></TR>\n");

  /* ****************** */

  for(i=0; i<MAX_ENTRY; i++) {
    if(entries[i] == 1) {            
      memset(hashList, 0, sizeof(hashList));
      memset(&hashListEntry, 0, sizeof(ElementHash));

      for(j=0; j<ELEMENT_HASH_LEN; j++) {
	if(theHash[j] != NULL) {
	  hash = theHash[j]->next;
	 
	  while(hash != NULL) {
	    if(hash->id < MAX_ENTRY) {
	      if(hash->id == i) {
		incrementTrafficCounter(&hashListEntry.bytesSent, hash->bytesSent.value);
		incrementTrafficCounter(&hashListEntry.pktsSent,  hash->pktsSent.value); 
		incrementTrafficCounter(&hashListEntry.bytesRcvd, hash->bytesRcvd.value);
		incrementTrafficCounter(&hashListEntry.pktsRcvd,  hash->pktsRcvd.value); 		
		hashList[theHash[j]->id] = theHash[j];
	      } else if(theHash[j]->id == i) {
		incrementTrafficCounter(&hashListEntry.bytesSent, theHash[j]->bytesSent.value);
		incrementTrafficCounter(&hashListEntry.pktsSent,  theHash[j]->pktsSent.value); 
		incrementTrafficCounter(&hashListEntry.bytesRcvd, theHash[j]->bytesRcvd.value);
		incrementTrafficCounter(&hashListEntry.pktsRcvd,  theHash[j]->pktsRcvd.value); 		
		hashList[theHash[j]->id] = hash;
	      }
	    }
	   
	    hash = hash->next;
	  }
	}     
      }

      if(snprintf(buf, sizeof(buf), "<TR><TH>%d</TH>"
		  "<TD>%s</TD><TD>%s</TD><TD>", i,
		  formatElementData(&hashListEntry, 1, buf1, sizeof(buf1)),
		  formatElementData(&hashListEntry, 0, buf1, sizeof(buf1))) < 0)		  
	BufferTooShort();
      sendString(buf);

      for(j=0; j<MAX_ENTRY; j++) {
	if(hashList[j] != NULL) {
	  sendString("<A HREF=# onMouseOver=\"window.status='");

	  if(hashList[j]->bytesSent.value > 0) {
	    if(snprintf(buf, sizeof(buf), "[(%d->%d)=%s/%s Pkts]",
			i, hashList[j]->id, formatBytes(hashList[j]->bytesSent.value, 1), formatPkts(hashList[j]->pktsSent.value)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }

	  if(hashList[j]->bytesRcvd.value > 0) {
	    if(snprintf(buf, sizeof(buf), "[(%d->%d)=%s/%s Pkts]",
			hashList[j]->id, i, formatBytes(hashList[j]->bytesRcvd.value, 1), formatPkts(hashList[j]->pktsRcvd.value)) < 0)
	      BufferTooShort();
	    sendString(buf);
	  }

	  if(snprintf(buf, sizeof(buf), 
		      "';return true\" onMouseOut=\"window.status='';return true\">%d</A>\n",
		      hashList[j]->id) < 0)
	    BufferTooShort();
	  sendString(buf);
	}
      }

      sendString("</TR>\n");
    }
  }

  sendString("</TR>\n</TABLE>\n");
}
