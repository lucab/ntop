/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 *  			  Centro SERRA, University of Pisa
 *  			  http://www.ntop.org/
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

static int sortSendMode=0;

/* #define PRINT_PKTS                 */
/* #define PRINT_ALL_ACTIVE_SESSIONS  */
/* #define PRINT_RETRANSMISSION_DATA  */

/*
  Courtesy of
  Peter Marquardt <wwwutz@mpimg-berlin-dahlem.mpg.de>
*/
#define SD(a,b) ((b)?((float)a)/(b):0)

/* Global */
static short sortFilter;

/* Static */
static short domainSort = 0;

/* *************************** */

#ifndef WIN32
void ignoreSignal(int signalId _UNUSED_) {
  closeNwSocket(&newSock);
  (void)setsignal(SIGPIPE, ignoreSignal);
}
#endif

/* ******************************* */

void initReports(void) {
  columnSort = 0;
  addDefaultAdminUser();

#ifdef MULTITHREADED
  if(logTimeout != 0)
    createThread(&logFileLoopThreadId, logFileLoop, NULL);
#endif
}

/* **************************************** */

void termReports(void) {
#ifdef MULTITHREADED
  if(logTimeout != 0)
    killThread(&logFileLoopThreadId);
#endif
}

/* **************************************** */

int reportValues(time_t *lastTime) {
  if(maxNumLines <= 0)
    maxNumLines = MAX_NUM_TABLE_ROWS;

  *lastTime = time(NULL) + refreshRate;

  /*
    Make sure that the other flags are't set. They have
    no effect in web mode
  */
  percentMode = 0;

  if(refreshRate == 0)
    refreshRate = REFRESH_TIME;
  else if(refreshRate < MIN_REFRESH_TIME)
    refreshRate = MIN_REFRESH_TIME;

#ifndef WIN32
  (void)setsignal(SIGPIPE, ignoreSignal);
#endif

  return(0);
}


/* ************************************ */

static void formatUsageCounter(UsageCounter usageCtr) {
  char buf[BUF_SIZE];
  int i, sendHeader=0;

  snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT>%s</TD>",
         formatPkts(usageCtr.value));
  sendString(buf);

  for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
    if(usageCtr.peersIndexes[i] != NO_PEER) {
      struct hostTraffic *el1;

      el1 = device[actualReportDeviceId].
       hash_hostTraffic[checkSessionIdx(usageCtr.peersIndexes[i])];

      if(el1 != NULL) {
       if(!sendHeader) {
         sendString("<TD ALIGN=LEFT><ul>");
         sendHeader = 1;
       }
       sendString("\n<li>");
       sendString(makeHostLink(el1, 0, 0, 0));
      }
    }

  if(sendHeader)
    sendString("</ul></TD>\n");
  else
    sendString("<TD>&nbsp;</TD>\n");
}

/* ********************************** */

static void printTableDoubleEntry(char *buf, int bufLen,
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
    snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH>"
           "<TD ALIGN=RIGHT>%s</TD>"
           "<TD>&nbsp;</TD>\n",
           getRowColor(), label, formatKBytes(totalS));
    break;
  case 100:
    snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH>"
           "<TD ALIGN=RIGHT>%s</TD>"
           "<TD ALIGN=CENTER BGCOLOR=\"%s\">100%%</TD>\n",
           getRowColor(), label, formatKBytes(totalS), color);
    break;
  default:
    snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH>"
           "<TD ALIGN=RIGHT>%s</TD>"
           "<TD><TABLE BORDER=\"0\" CELLPADDING=\"0\" CELLSPACING=\"0\" WIDTH=\"100%%\">"
           "<TR><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
           "<P>%.1f&nbsp;%%</TD><TD ALIGN=CENTER WIDTH=\"%d%%\" %s>"
           "<P>&nbsp;</TD></TR></TABLE></TD>\n",
           getRowColor(), label, formatKBytes(totalS),
           int_perc, color, percentageS, (100-int_perc), getActualRowColor());
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
    snprintf(buf, bufLen, "<TD ALIGN=RIGHT>%s</TD><TD>&nbsp;</TD></TR>\n",
           formatKBytes(totalR));
    break;
  case 100:
    snprintf(buf, bufLen, "<TD ALIGN=RIGHT>%s</TD>"
           "<TD ALIGN=CENTER BGCOLOR=\"%s\">100%%</TD></TR>\n",
           formatKBytes(totalR), color);
    break;
  default:
    snprintf(buf, bufLen, "<TD ALIGN=RIGHT>%s</TD>"
           "<TD><TABLE BORDER=\"0\" CELLPADDING=\"0\" CELLSPACING=\"0\" WIDTH=\"100%%\">"
           "<TR><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
           "<P>%.1f&nbsp;%%</TD><TD ALIGN=CENTER WIDTH=\"%d%%\" %s>"
           "<P>&nbsp;</TD></TR></TABLE></TD></TR>\n",
           formatKBytes(totalR),
           int_perc, color, percentageR,
           (100-int_perc), getActualRowColor());
  }

  sendString(buf);
}

/* ********************************** */

static void printTableEntryPercentage(char *buf, int bufLen,
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
    if(total == -1)
      snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH>"
             "<TD ALIGN=CENTER BGCOLOR=\"%s\">%s&nbsp;(100&nbsp;%%)</TD></TR>\n",
             getRowColor(), label, COLOR_2, label_2);
    else
      snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>%s</TD>"
             "<TD ALIGN=CENTER BGCOLOR=\"%s\">%s&nbsp;(100&nbsp;%%)</TD></TR>\n",
             getRowColor(), label, formatKBytes(total), COLOR_2, label_2);
    break;
  case 100:
    if(total == -1)
      snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH>"
             "<TD ALIGN=CENTER BGCOLOR=\"%s\">%s&nbsp;(100&nbsp;%%)</TD></TR>\n",
             getRowColor(), label, COLOR_1, label_1);
    else
      snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>%s</TD>"
             "<TD ALIGN=CENTER BGCOLOR=\"%s\">%s&nbsp;(100&nbsp;%%)</TD></TR>\n",
             getRowColor(), label, formatKBytes(total), COLOR_1, label_1);
    break;
  default:
    if(total == -1)
      snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH>"
             "<TD><TABLE BORDER=\"0\" CELLPADDING=\"0\" CELLSPACING=\"0\" WIDTH=\"100%%\">"
             "<TR><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
             "<P>%s&nbsp;(%.1f&nbsp;%%)</TD><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
             "<P>%s&nbsp;(%.1f&nbsp;%%)</TD></TR></TABLE></TD></TR>\n",
             getRowColor(), label,
             int_perc, COLOR_1,
             label_1, percentage, (100-int_perc), COLOR_2,
             label_2, (100-percentage));
    else
      snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>%s</TD>"
             "<TD><TABLE BORDER=\"0\" CELLPADDING=\"0\" CELLSPACING=\"0\" WIDTH=\"100%%\">"
             "<TR><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
             "<P>%s&nbsp;(%.1f&nbsp;%%)</TD><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
             "<P>%s&nbsp;(%.1f&nbsp;%%)</TD></TR></TABLE></TD></TR>\n",
             getRowColor(), label, formatKBytes(total),
             int_perc, COLOR_1,
             label_1, percentage, (100-int_perc), COLOR_2,
             label_2, (100-percentage));
  }

  sendString(buf);
}

/* ******************************* */

static void printHeader(int reportType, int revertOrder, u_int column) {
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

  printHTTPheader();

  if(sortSendMode) {
    if(sortSendMode == 1)
      sendString("<CENTER><P><H1>Network Traffic: Data Sent</H1><P>\n");
    else {
      sendString("<CENTER><P><H1>Host Information</H1><P>\n");
      return;
    }

    if((reportType == 0) || (reportType == 1)) {
      if(reportType == 0) {
	snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", STR_SORT_DATA_SENT_PROTOS, sign);
	snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", STR_SORT_DATA_SENT_PROTOS);
      } else {
	snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", STR_SORT_DATA_SENT_IP, sign);
	snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", STR_SORT_DATA_SENT_IP);
      }
    } else if(reportType == 2) {
      snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s",   STR_SORT_DATA_SENT_THPT, sign);
      snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?",   STR_SORT_DATA_SENT_THPT);
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
      snprintf(buf, BUF_SIZE, "<TABLE BORDER=1><TR><TH>%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>\n"
	      "<TH>%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
	      "<TH COLSPAN=2>%s0>Sent%s</A></TH>\n",
	      theAnchor[0], arrow[0], theAnchor[1], arrow[1], theAnchor[2], arrow[2]);
    } else {
      if(abs(column) == HOST_DUMMY_IDX_VALUE)
	{ arrow[0] = arrowGif; theAnchor[0] = htmlAnchor; }
      else { arrow[0] = ""; theAnchor[0] = htmlAnchor1; }
      if(abs(column) == DOMAIN_DUMMY_IDX_VALUE)
	{ arrow[1] = arrowGif; theAnchor[1] = htmlAnchor;  }
      else { arrow[1] = ""; theAnchor[1] = htmlAnchor1; }
      snprintf(buf, BUF_SIZE, "<TABLE BORDER=1><TR><TH>%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>"
	      "<TH>%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>\n\n",
	      theAnchor[0], arrow[0], theAnchor[1], arrow[1]);
    }

    sendString(buf);
  } else {
    sendString("<CENTER><P><H1>Network Traffic: Data Received</H1><P>\n");

    if((reportType == 0) || (reportType == 1)) {
      if(reportType == 0) {
	snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", STR_SORT_DATA_RECEIVED_PROTOS, sign);
	snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", STR_SORT_DATA_RECEIVED_PROTOS);
      } else {
	snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", STR_SORT_DATA_RECEIVED_IP, sign);
	snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", STR_SORT_DATA_RECEIVED_IP);
      }
    } else if(reportType == 2) {
      snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s",   STR_SORT_DATA_RECEIVED_THPT, sign);
      snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?",   STR_SORT_DATA_RECEIVED_THPT);
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
      snprintf(buf, BUF_SIZE, "<TABLE BORDER=1><TR><TH>%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>\n"
	      "<TH>%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
	      "<TH COLSPAN=2>%s0>Received%s</A></TH>\n",
	      theAnchor[0], arrow[0], theAnchor[1], arrow[1], theAnchor[2], arrow[2]);
    } else {
      if(abs(column) == HOST_DUMMY_IDX_VALUE)
	{ arrow[0] = arrowGif; theAnchor[0] = htmlAnchor; }
      else { arrow[0] = ""; theAnchor[0] = htmlAnchor1; }
      if(abs(column) == DOMAIN_DUMMY_IDX_VALUE)
	{ arrow[1] = arrowGif; theAnchor[1] = htmlAnchor; }
      else { arrow[1] = ""; theAnchor[1] = htmlAnchor1;}
      snprintf(buf, BUF_SIZE, "<TABLE BORDER=1><TR><TH>%s"HOST_DUMMY_IDX_STR">Host%s</A></TH>"
	      "<TH>%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>\n\n",
	      theAnchor[0], arrow[0], theAnchor[1], arrow[1]);
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

    snprintf(buf, BUF_SIZE, "<TH>%s1>TCP%s</A></TH><TH>%s2>UDP%s</A></TH><TH>%s3>ICMP%s</A></TH>"
	    "<TH>%s4>DLC%s</A></TH><TH>%s5>IPX%s</A></TH><TH>%s6>Decnet%s</A></TH>"
	    "<TH>%s7>(R)ARP%s</A></TH><TH>%s8>AppleTalk%s</A></TH>"
	    "<TH>%s9>OSPF%s</A></TH><TH>%s10>NetBios%s</A></TH><TH>%s11>IGMP%s</A></TH>"
	    "<TH>%s12>OSI%s</A><TH>%s13>QNX%s</A><TH>%s14>Other%s</A></TH>",
	    theAnchor[0], arrow[0], theAnchor[1], arrow[1],
	    theAnchor[2], arrow[2], theAnchor[3], arrow[3],
	    theAnchor[4], arrow[4], theAnchor[5], arrow[5],
	    theAnchor[6], arrow[6], theAnchor[7], arrow[7],
	    theAnchor[8], arrow[8], theAnchor[9], arrow[9],
	    theAnchor[10], arrow[10], theAnchor[11], arrow[11],
	    theAnchor[12], arrow[12], theAnchor[13], arrow[13]);
    sendString(buf);
  } else if(reportType == 1) {
    int soFar=1;

    for(i=0; i<numIpProtosToMonitor; i++) {
      if(abs(column) == soFar) {
	arrow[0] = arrowGif;
	theAnchor[0] = htmlAnchor;
      } else {
	arrow[0] = "";
	theAnchor[0] = htmlAnchor1;
      }
      snprintf(buf, BUF_SIZE, "<TH>%s%d>%s%s</A></TH>",
	      theAnchor[0], i+1, protoIPTrafficInfos[i], arrow[0]);
      sendString(buf);
      soFar++;
    }

    if(abs(column) == soFar) {
      arrow[0] = arrowGif; theAnchor[0] = htmlAnchor;
    } else {
      arrow[0] = "";  theAnchor[0] = htmlAnchor1;
    }
    snprintf(buf, BUF_SIZE, "<TH>%s%d>Other&nbsp;IP%s</A></TH>", theAnchor[0], i+1, arrow[0]);
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

    snprintf(buf, BUF_SIZE, "<TH>%s1>Actual Thpt%s</A></TH><TH>%s2>Avg Thpt%s</A><TH>%s3>Peak Thpt%s</A>"
	    "<TH>%s4>Actual Pkt Thpt%s</A></TH><TH>%s5>Avg Pkt Thpt%s</A><TH>%s6>Peak Pkt Thpt%s</A></TH>",
	    theAnchor[0], arrow[0], theAnchor[1], arrow[1], theAnchor[2], arrow[2],
	    theAnchor[3], arrow[3], theAnchor[4], arrow[4], theAnchor[5], arrow[5]);
    sendString(buf);
  }

  sendString("</TR>\n");
}

/* ******************************* */

static char* getOSFlag(char* osName, int showOsName) {
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
  else if(strstr(osName, "BSD") != NULL)
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
    if(flagImg != NULL)
      snprintf(tmpStr, sizeof(tmpStr), "%s&nbsp;[%s]", flagImg, osName);
    else
      strncpy(tmpStr, osName, sizeof(tmpStr));
  }

  return(tmpStr);
}

/* ******************************* */

static int sortHostFctn(const void *_a, const void *_b) {
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
    rc = strcasecmp((*a)->hostSymIpAddress, (*b)->hostSymIpAddress);
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
      snprintf(nameA_str, sizeof(nameA_str), "%d.%d", (*a)->atNetwork, (*a)->atNode);
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
      snprintf(nameB_str, sizeof(nameB_str), "%d.%d", (*b)->atNetwork, (*b)->atNode);
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

static int cmpUsersTraffic(const void *_a, const void *_b) {
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

static int cmpProcesses(const void *_a, const void *_b) {
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

static int cmpFctn(const void *_a, const void *_b) {
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

  if(columnSort == HOST_DUMMY_IDX_VALUE) {
    int rc;

    /* Host name */
#ifdef MULTITHREADED
    accessMutex(&addressResolutionMutex, "cmpFctn");
#endif
    if((*a)->hostSymIpAddress[0] != '\0')
      rc = strcasecmp((*a)->hostSymIpAddress, (*b)->hostSymIpAddress);
    else
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
    if(sortSendMode)
      switch(screenNumber) {
      case 0:
	a_ = (*a)->otherSent, b_ = (*b)->otherSent;
	break;
      case MAX_NUM_PROTOS_SCREENS:
	fa_ = (*a)->averageSentPktThpt, fb_ = (*b)->averageSentPktThpt, floatCompare = 1;
	break;
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

static int cmpMulticastFctn(const void *_a, const void *_b) {
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

static void getProtocolDataSent(TrafficCounter *c,
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

static void getProtocolDataReceived(TrafficCounter *c,
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

/* ******************************* */

RETSIGTYPE printHostsTraffic(int signumber_ignored,
			     int reportType,
			     int sortedColumn,
			     int revertOrder) {
  u_int idx, numEntries=0;
  int printedEntries=0;
  HostTraffic *el;
  HostTraffic* tmpTable[HASHNAMESIZE];
  char buf[BUF_SIZE], buf2[BUF_SIZE];
  float sentPercent, rcvdPercent;
  struct pcap_stat stat;

  memset(buf, 0, sizeof(buf));
  memset(tmpTable, 0, HASHNAMESIZE*sizeof(HostTraffic*));

  sortSendMode = signumber_ignored;

  if(signumber_ignored == 2)
    goto PRINT_TOTALS;

  printHeader(reportType, revertOrder, abs(sortedColumn));

  for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++) {
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && (broadcastHost(el) == 0)) {
      if((sortSendMode && (el->bytesSent > 0))
	 || ((!sortSendMode) && (el->bytesReceived > 0))) {
	if((reportType == 1) && (el->hostNumIpAddress[0] == '\0')) continue;
	tmpTable[numEntries++]=el;
      }
    }
  }

  if(numEntries > 0) {
    /*
      The switch below is needed to:
      - sort data according to the selected column
      - 'recycle' (somebody would call this "code reuse") the cmpFctn function
    */

    columnSort = 0;

    if(sortedColumn == HOST_DUMMY_IDX_VALUE)
      columnSort = HOST_DUMMY_IDX_VALUE; /* Host name */
    else if(sortedColumn == DOMAIN_DUMMY_IDX_VALUE)
      columnSort = DOMAIN_DUMMY_IDX_VALUE; /* domain name */
    else if(reportType == 0 /* Interactive mode */) {
      switch(sortedColumn) {
      case 0:
	/* Nothing to do */
	break;
      case 1: /* TCP */
	screenNumber = 0, columnSort = 1;
	break;
      case 2: /* UDP */
	screenNumber = 0, columnSort = 2;
	break;
      case 3: /* ICMP */
	screenNumber = 0, columnSort = 3;
	break;
      case 4: /* DLC */
	screenNumber = 1, columnSort = 1;
	break;
      case 5: /* IPX */
	screenNumber = 1, columnSort = 2;
	break;
      case 6: /* Decnet */
	screenNumber = 1, columnSort = 3;
	break;
      case 7: /* (R)ARP */
	screenNumber = 2, columnSort = 1;
	break;
      case 8: /* AppleTalk */
	screenNumber = 2, columnSort = 2;
	break;
      case 9: /* OSPF */
	screenNumber = 2, columnSort = 3;
	break;
      case 10: /* NetBios */
	screenNumber = 3, columnSort = 1;
	break;
      case 11: /* IGMP */
	screenNumber = 3, columnSort = 2;
	break;
      case 12: /* OSI */
	screenNumber = 3, columnSort = 3;
	break;
      case 13: /* QNX */
	screenNumber = 0, columnSort = 4;
	break;
      case 14: /* Other */
	screenNumber = 0, columnSort = 5;
	break;
      }
    } else if(reportType == 1) {
      /* if(sortedColumn == 0) sortedColumn = 1; */
      screenNumber = DUMMY_IDX_VALUE /* dirty trick */, columnSort = sortedColumn;
    } else if(reportType == 2) /* Thpt */ {
      if(sortedColumn == 0) sortedColumn = 1;
      screenNumber = MAX_NUM_PROTOS_SCREENS /* dirty trick */, columnSort = sortedColumn;
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, ">reportType=%d/sortedColumn=%d/columnSort=%d/screenNumber=%d<\n",
	   reportType, sortedColumn, columnSort, screenNumber);
#endif

    quicksort(tmpTable, numEntries, sizeof(HostTraffic*), cmpFctn);

    for(idx=0; idx<numEntries; idx++) {
      if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	sentPercent = (100*(float)el->bytesSent)/device[actualReportDeviceId].ethernetBytes;
	rcvdPercent = (100*(float)el->bytesReceived)/device[actualReportDeviceId].ethernetBytes;

	if(percentMode == 1) {
	  float a, b;
	  TrafficCounter c, d, e;

	  /* % mode */
	  if(!sortSendMode) {
	    a = rcvdPercent;
	    b = sentPercent;
	    getProtocolDataReceived(&c, &d, &e, el);
	  } else {
	    a = rcvdPercent;
	    b = sentPercent;
	    getProtocolDataSent(&c, &d, &e, el);
	  }
	} else {
	  int i;
	  TrafficCounter a, b, c, d, e;
	  char webHostName[256];

	  a = el->bytesReceived, b = el->bytesSent;

	  if(!sortSendMode)
	    getProtocolDataReceived(&c, &d, &e, el);
	  else
	    getProtocolDataSent(&c, &d, &e, el);

	  /* Fixed buffer overflow.
	     Courtesy of Rainer Tammer <rainer.tammer@spg.schulergroup.com>
	  */

	  strncpy(webHostName, makeHostLink(el, LONG_FORMAT, 0, 1), sizeof(webHostName));

	  if(sortSendMode) {
	    if(reportType == 0) /* Protos */ {
	      snprintf(buf, sizeof(buf), "<TR %s>%s"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%.1f%s%%</TD>"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>",
		      getRowColor(), webHostName,
		      formatBytes(el->bytesSent, 1), sentPercent, separator,
		      formatBytes(el->tcpSentLocally+el->tcpSentRemotely, 1),
		      formatBytes(el->udpSentLocally+el->udpSentRemotely, 1),
		      formatBytes(el->icmpSent, 1),
		      formatBytes(el->dlcSent, 1),
		      formatBytes(el->ipxSent, 1),
		      formatBytes(el->decnetSent, 1),
		      formatBytes(el->arp_rarpSent, 1),
		      formatBytes(el->appletalkSent, 1),
		      formatBytes(el->ospfSent, 1),
		      formatBytes(el->netbiosSent, 1),
		      formatBytes(el->igmpSent, 1),
		      formatBytes(el->osiSent, 1),
		      formatBytes(el->qnxSent, 1),
		      formatBytes(el->otherSent, 1)
		      );

	      sendString(buf);
	    } else if(reportType == 1) /* IP Protos */ {
	      TrafficCounter totalIPTraffic=0;

	      snprintf(buf, sizeof(buf), "<TR %s>%s"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%.1f%s%%</TD>",
		      getRowColor(), webHostName,
		      formatBytes(el->bytesSent, 1), sentPercent, separator);
	      sendString(buf);

	      for(i=0; i<numIpProtosToMonitor; i++) {
		totalIPTraffic += el->protoIPTrafficInfos[i].sentLocally+
		  el->protoIPTrafficInfos[i].sentRemotely;
		snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT>%s</TD>",
			formatBytes(el->protoIPTrafficInfos[i].sentLocally+
				    el->protoIPTrafficInfos[i].sentRemotely, 1));
		sendString(buf);
	      }

	      /* Rounding may cause troubles */
	      if(el->bytesSent > totalIPTraffic)
		totalIPTraffic = (el->tcpSentLocally
				  +el->tcpSentRemotely
				  +el->udpSentLocally
				  +el->udpSentRemotely
				  +el->icmpSent
				  +el->ospfSent
				  +el->igmpSent)
		  -totalIPTraffic;
	      else
		totalIPTraffic = 0;
	      snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT>%s</TD>", 
		       formatBytes(totalIPTraffic, 1));
	      sendString(buf);
	    } else if(reportType == 2) /* Throughtput */ {
	      snprintf(buf, sizeof(buf), "<TR %s>%s"
		      "<TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>"
		      "<TD ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>"
		      "<TD ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>",
		      getRowColor(), webHostName,
		      formatThroughput(el->actualSentThpt),
		      formatThroughput(el->averageSentThpt),
		      formatThroughput(el->peakSentThpt),
		      el->actualSentPktThpt,
		      el->averageSentPktThpt,
		      el->peakSentPktThpt);

	      sendString(buf);
	    }

	    sendString("</TR>\n");
	  } else {
	    if(reportType == 0) /* Protos */ {
	      snprintf(buf, sizeof(buf), "<TR %s>%s"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%.1f%s%%</TD>"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>",
		      getRowColor(), webHostName,
		      formatBytes(el->bytesReceived, 1), rcvdPercent, separator,
		      formatBytes(el->tcpReceivedLocally+el->tcpReceivedFromRemote, 1),
		      formatBytes(el->udpReceivedLocally+el->udpReceivedFromRemote, 1),
		      formatBytes(el->icmpReceived, 1),
		      formatBytes(el->dlcReceived, 1),
		      formatBytes(el->ipxReceived, 1),
		      formatBytes(el->decnetReceived, 1),
		      formatBytes(el->arp_rarpReceived, 1),
		      formatBytes(el->appletalkReceived, 1),
		      formatBytes(el->ospfReceived, 1),
		      formatBytes(el->netbiosReceived, 1),
		      formatBytes(el->igmpReceived, 1),
		      formatBytes(el->osiReceived, 1),
		      formatBytes(el->qnxReceived, 1),
		      formatBytes(el->otherReceived, 1)
		      );

	      sendString(buf);
	    } else if(reportType == 1) /* IP Protos */ {
	      TrafficCounter totalIPTraffic=0;

	      snprintf(buf, sizeof(buf), "<TR %s>%s"
		      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%.1f%s%%</TD>",
		      getRowColor(), webHostName,
		      formatBytes(el->bytesReceived, 1), rcvdPercent, separator);
	      sendString(buf);

	      for(i=0; i<numIpProtosToMonitor; i++) {
		totalIPTraffic += el->protoIPTrafficInfos[i].receivedLocally+
		  el->protoIPTrafficInfos[i].receivedFromRemote;
		snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT>%s</TD>",
			formatBytes(el->protoIPTrafficInfos[i].receivedLocally+
				    el->protoIPTrafficInfos[i].receivedFromRemote, 1));
		sendString(buf);
	      }

	      /* Rounding may cause troubles */
	      if(el->bytesReceived > totalIPTraffic)
		totalIPTraffic = (el->tcpReceivedLocally
				  +el->tcpReceivedFromRemote
				  +el->udpReceivedLocally
				  +el->udpReceivedFromRemote
				  +el->icmpReceived
				  +el->ospfReceived
				  +el->igmpReceived)-totalIPTraffic;
	      else
		totalIPTraffic = 0;
	      snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT>%s</TD>", formatBytes(totalIPTraffic, 1));
	      sendString(buf);
	    } else if(reportType == 2) /* Throughtput */ {
	      snprintf(buf, sizeof(buf), "<TR %s>%s"
		      "<TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%s</TD>"
		      "<TD ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>"
		      "<TD ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>"
		      "<TD ALIGN=RIGHT>%.1f&nbsp;Pkts/sec</TD>",
		      getRowColor(), webHostName,
		      formatThroughput(el->actualRcvdThpt),
		      formatThroughput(el->averageRcvdThpt),
		      formatThroughput(el->peakRcvdThpt),
		      el->actualRcvdPktThpt,
		      el->averageRcvdPktThpt,
		      el->peakRcvdPktThpt);
	      sendString(buf);
	    }

	    sendString("</TR>\n");
	  }
	}
      }
      /* Avoid huge tables */
      if(printedEntries++ > maxNumLines)
	break;
    }
  } else
    idx = 0;

 PRINT_TOTALS:
  if(signumber_ignored == 2) {
    TrafficCounter unicastPkts=0, avgPktLen;

    if(reportType == 0) {
      int i;

      sendString("<CENTER><P><H1>Global Traffic Statistics"
		 "</H1><P>\n<TABLE BORDER=1>\n");
      sendString("<TR><TH>Nw&nbsp;Interface&nbsp;Type</TH>"
		 "<TD ALIGN=RIGHT>");

      if(mergeInterfaces) {
	for(i=0; i<numDevices; i++) {
	  if(i > 0) sendString("<br>");

	  if(rFileName == NULL)
	    snprintf(buf2, sizeof(buf2), "%s [%s]",
		    getNwInterfaceType(i),
		    device[i].name);
	  else
	    snprintf(buf2, sizeof(buf2), "%s [%s]",
		    getNwInterfaceType(i),
		    PCAP_NW_INTERFACE);
	  sendString(buf2);
	}
      } else {
	if(rFileName == NULL)
	  snprintf(buf2, sizeof(buf2), "%s [%s]",
		  getNwInterfaceType(actualReportDeviceId),
		  device[actualReportDeviceId].name);
	else
	  snprintf(buf2, sizeof(buf2), "%s [%s]",
		  getNwInterfaceType(actualReportDeviceId),
		  PCAP_NW_INTERFACE);
	sendString(buf2);
      }

      sendString("</TD></TR>\n");

      if(domainName[0] != '\0') {
	snprintf(buf2, sizeof(buf2), "<TR><TH>Local&nbsp;Domain&nbsp;Name</TH>"
		"<TD ALIGN=RIGHT>%s&nbsp;</TD></TR>\n",
		domainName);
	sendString(buf2);
      }

      snprintf(buf2, sizeof(buf2), "<TR><TH>Sampling&nbsp;Since</TH>"
	      "<TD ALIGN=RIGHT>%s [%s]</TD></TR>\n",
	      ctime(&initialSniffTime),
	      formatSeconds(actTime-initialSniffTime));
      sendString(buf2);


      sendString("<TR><TH>Packets</TH><TH>\n<TABLE BORDER=1 WIDTH=100%%>");

#ifdef HAVE_GDCHART
      if(numDevices > 1) {
	sendString("<TR><TD ALIGN=CENTER COLSPAN=3>"
		   "<IMG SRC=interfaceTrafficPie.gif></TD></TR>\n");
      }
#endif
    }

    if(device[actualReportDeviceId].pcapPtr != NULL) {
      TrafficCounter droppedByKernel;

      if(reportType == 0) {
	int i;

	droppedByKernel=0;

	for(i=0; i<numDevices; i++) {
	  if (pcap_stats(device[i].pcapPtr, &stat) >= 0) {
	    droppedByKernel +=  stat.ps_drop;
	  }
	}

	unicastPkts = device[actualReportDeviceId].ethernetPkts
	  - device[actualReportDeviceId].broadcastPkts
	  - device[actualReportDeviceId].multicastPkts;
	/* if(unicastPkts < 0) unicastPkts = 0; */ /* It shouldn't happen */
	if(device[actualReportDeviceId].ethernetPkts <= 0) device[actualReportDeviceId].ethernetPkts = 1;

	snprintf(buf2, sizeof(buf2), 
		"<tr %s><th align=left>Total</th><td COLSPAN=2 align=right>%s</td></TR>\n",
		getRowColor(), formatPkts(device[actualReportDeviceId].ethernetPkts));
	sendString(buf2);
	snprintf(buf2, sizeof(buf2), 
		"<tr %s><th align=left>Dropped&nbsp;by&nbsp;the&nbsp;kernel</th>"
		"<td COLSPAN=2 align=right>%s</td></TR>\n",
		getRowColor(), formatPkts(droppedByKernel));
	sendString(buf2);
#ifdef MULTITHREADED
	snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Dropped&nbsp;by&nbsp;ntop</th>"
		"<td COLSPAN=2 align=right>%s</td></TR>\n",
		getRowColor(), formatPkts(device[actualReportDeviceId].droppedPackets));
	sendString(buf2);
#endif
      }
    }

    if(reportType == 0) {
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Unicast</th>"
	      "<td align=right>%.1f%%</td><td align=right>%s</td></TR>\n",
	      getRowColor(), (float)(100*unicastPkts)/(float)device[actualReportDeviceId].ethernetPkts,
	      formatPkts(unicastPkts));
      sendString(buf2);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Broadcast</th>"
	      "<td align=right>%.1f%%</td><td align=right>%s</td></TR>\n",
	      getRowColor(), (float)(100*device[actualReportDeviceId].broadcastPkts)/(float)device[actualReportDeviceId].ethernetPkts,
	      formatPkts(device[actualReportDeviceId].broadcastPkts));
      sendString(buf2);

      if(device[actualReportDeviceId].multicastPkts > 0) {
	snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Multicast</th>"
		"<td align=right>%.1f%%</td><td align=right>%s</td></TR>\n",
		getRowColor(), (float)(100*device[actualReportDeviceId].multicastPkts)/(float)device[actualReportDeviceId].ethernetPkts,
		formatPkts(device[actualReportDeviceId].multicastPkts));
	sendString(buf2);
      }

#ifdef HAVE_GDCHART
      sendString("<TR><TH ALIGN=CENTER COLSPAN=3><IMG SRC=pktCastDistribPie></TH></TR>\n");
#endif

      /*
	Very rudimental formula. Note that as specified in RMON, packets smaller
	than 64 or larger than 1518 octets are not counted.
      */
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Shortest</th>"
	      "<td align=right colspan=2>%s bytes</td></TR>\n",
	      getRowColor(), formatPkts((TrafficCounter)device[actualReportDeviceId].rcvdPktStats.shortest));
      sendString(buf2);
      avgPktLen = (96*device[actualReportDeviceId].rcvdPktStats.upTo128
		   +192*device[actualReportDeviceId].rcvdPktStats.upTo256
		   +384*device[actualReportDeviceId].rcvdPktStats.upTo512
		   +768*device[actualReportDeviceId].rcvdPktStats.upTo1024
		   +1271*device[actualReportDeviceId].rcvdPktStats.upTo1518)/
	(device[actualReportDeviceId].rcvdPktStats.upTo128+device[actualReportDeviceId].rcvdPktStats.upTo256
	 +device[actualReportDeviceId].rcvdPktStats.upTo512+device[actualReportDeviceId].rcvdPktStats.upTo1024
	 +device[actualReportDeviceId].rcvdPktStats.upTo1518+1);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Average&nbsp;Size</th>"
	      "<td align=right colspan=2>%s bytes</td></TR>\n",
	      getRowColor(), formatPkts(avgPktLen));
      sendString(buf2);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Longest</th>"
	      "<td align=right colspan=2>%s bytes</td></TR>\n",
	      getRowColor(), formatPkts(device[actualReportDeviceId].rcvdPktStats.longest));
      sendString(buf2);

      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>&lt;&nbsp;64&nbsp;bytes</th>"
	      "<td align=right>%.1f%%</td><td align=right>%s</td></TR>\n",
	      getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo64)/
	      (float)device[actualReportDeviceId].ethernetPkts,
	      formatPkts(device[actualReportDeviceId].rcvdPktStats.upTo64));
      sendString(buf2);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>&lt;&nbsp;128&nbsp;bytes</th>"
	      "<td align=right>%.1f%%</td><td align=right>%s</td></TR>\n",
	      getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo128)/
	      (float)device[actualReportDeviceId].ethernetPkts,
	      formatPkts(device[actualReportDeviceId].rcvdPktStats.upTo128));
      sendString(buf2);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>&lt;&nbsp;256&nbsp;bytes</th>"
	      "<td align=right>%.1f%%</td><td align=right>%s</td></TR>\n",
	      getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo256)/
	      (float)device[actualReportDeviceId].ethernetPkts,
	      formatPkts(device[actualReportDeviceId].rcvdPktStats.upTo256));
      sendString(buf2);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>&lt;&nbsp;512&nbsp;bytes</th>"
	      "<td align=right>%.1f%%</td><td align=right>%s</td></TR>\n",
	      getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo512)/
	      (float)device[actualReportDeviceId].ethernetPkts,
	      formatPkts(device[actualReportDeviceId].rcvdPktStats.upTo512));
      sendString(buf2);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>&lt;&nbsp;1024&nbsp;bytes</th>"
	      "<td align=right>%.1f%%</td><td align=right>%s</td></TR>\n",
	      getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo1024)/
	      (float)device[actualReportDeviceId].ethernetPkts,
	      formatPkts(device[actualReportDeviceId].rcvdPktStats.upTo1024));
      sendString(buf2);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>&lt;&nbsp;1518&nbsp;bytes</th>"
	      "<td align=right>%.1f%%</td><td align=right>%s</td></TR>\n",
	      getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo1518)/
	      (float)device[actualReportDeviceId].ethernetPkts,
	      formatPkts(device[actualReportDeviceId].rcvdPktStats.upTo1518));
      sendString(buf2);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>&gt;&nbsp;1518&nbsp;bytes</th>"
	      "<td align=right>%.1f%%</td><td align=right>%s</td></TR>\n",
	      getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.above1518)/
	      (float)device[actualReportDeviceId].ethernetPkts,
	      formatPkts(device[actualReportDeviceId].rcvdPktStats.above1518));
      sendString(buf2);

#ifdef HAVE_GDCHART
      sendString("<TR><TH ALIGN=CENTER COLSPAN=3><IMG SRC=pktSizeDistribPie></TH></TR>\n");
#endif

      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Packets&nbsp;too&nbsp;long</th>"
	      "<td align=right>%.1f%%</td><td align=right>%s</td></TR>\n",
	      getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.tooLong)/
	      (float)device[actualReportDeviceId].ethernetPkts,
	      formatPkts(device[actualReportDeviceId].rcvdPktStats.tooLong));
      sendString(buf2);

      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Bad&nbsp;Packets&nbsp;(Checksum)</th>"
	      "<td align=right>%.1f%%</td><td align=right>%s</td></TR>\n",
	      getRowColor(), (float)(100*device[actualReportDeviceId].rcvdPktStats.badChecksum)/
	      (float)device[actualReportDeviceId].ethernetPkts,
	      formatPkts(device[actualReportDeviceId].rcvdPktStats.badChecksum));
      sendString(buf2);

      sendString("</TABLE></TR><TR><TH>Traffic</TH><TH>\n<TABLE BORDER=1 WIDTH=100%%>");
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Total</th><td align=right>%s</td></TR>\n",
	      getRowColor(), formatBytes(device[actualReportDeviceId].ethernetBytes, 1));
      sendString(buf2);

      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>IP Traffic</th><td align=right>%s</td></TR>\n",
	      getRowColor(), formatBytes(device[actualReportDeviceId].ipBytes, 1));
      sendString(buf2);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Non IP Traffic</th><td align=right>%s</td></TR>\n",
	      getRowColor(),
	      formatBytes(device[actualReportDeviceId].ethernetBytes-device[actualReportDeviceId].ipBytes, 1));
      sendString(buf2);

#ifdef HAVE_GDCHART
      sendString("<TR><TH ALIGN=CENTER COLSPAN=2><IMG SRC=ipTrafficPie></TH></TR>\n");
#endif

      updateThpt();

      sendString("</TABLE></TR><TR><TH>Throughput</TH><TH>\n<TABLE BORDER=1 WIDTH=100%%>");
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Actual</th><td align=right>%s</td>"
	      "<td align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
	      getRowColor(), formatThroughput(device[actualReportDeviceId].actualThpt),
	      device[actualReportDeviceId].actualPktsThpt/8);
      sendString(buf2);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Last Minute</th><td align=right>%s</td>"
	      "<td align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
	      getRowColor(), formatThroughput(device[actualReportDeviceId].lastMinThpt/8), device[actualReportDeviceId].lastMinPktsThpt);
      sendString(buf2);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Last 5 Minutes</th><td align=right>%s</td>"
	      "<td align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
	      getRowColor(), formatThroughput(device[actualReportDeviceId].lastFiveMinsThpt/8), device[actualReportDeviceId].lastFiveMinsPktsThpt);
      sendString(buf2);
      snprintf(buf2, sizeof(buf2), "<tr %s><th align=left>Peak</th><td align=right>%s</td>"
	      "<td align=right>%.1f&nbsp;Pkts/sec</td></TR>\n",
	      getRowColor(), formatThroughput(device[actualReportDeviceId].peakThroughput/8), device[actualReportDeviceId].peakPacketThroughput);
      sendString(buf2);

      sendString("</TABLE></TR></TABLE></CENTER>\n");
    }
  } else {
    /* if(reportType == 0) */
    sendString("\n</TABLE><P>\n");
  }

  lastRefreshTime = actTime;
}

/* ******************************* */

static RETSIGTYPE _printHostsTraffic(int signumber_ignored) {
  printHostsTraffic(signumber_ignored, 0, 0, 0);
#ifndef WIN32
  (void)setsignal(SIGALRM, _printHostsTraffic);
#endif
}

/* ******************************* */

void printMulticastStats(int sortedColumn /* ignored so far */,
			 int revertOrder) {
  u_int idx, numEntries=0;
  int printedEntries=0;
  HostTraffic *el;
  HostTraffic* tmpTable[HASHNAMESIZE];
  char buf[BUF_SIZE], *sign, *theAnchor[6], *arrow[6], *arrowGif;
  char htmlAnchor[64], htmlAnchor1[64];

  memset(buf, 0, sizeof(buf));
  memset(tmpTable, 0, HASHNAMESIZE*sizeof(HostTraffic*));

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG SRC=arrow_down.gif BORDER=0>";
  }

  for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++) {
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && ((el->pktMulticastSent > 0) || (el->pktMulticastRcvd > 0))
       && (!broadcastHost(el))
       )
      tmpTable[numEntries++]=el;
  }

  printHTTPheader();
  sendString("<CENTER><P><H1>Multicast Statistics</H1><P>\n");

  if(numEntries > 0) {
    columnSort = sortedColumn; /* Host name */

    snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", STR_MULTICAST_STATS, sign);
    snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", STR_MULTICAST_STATS);

    if(abs(columnSort) == 0) {
      arrow[0] = arrowGif;
      theAnchor[0] = htmlAnchor;
    } else {
      arrow[0] = "";
      theAnchor[0] = htmlAnchor1;
    }

    if(abs(columnSort) == 1) {
      arrow[1] = arrowGif;
      theAnchor[1] = htmlAnchor;
    } else {
      arrow[1] = "";
      theAnchor[1] = htmlAnchor1;
    }

    if(abs(columnSort) == 2) {
      arrow[2] = arrowGif;
      theAnchor[2] = htmlAnchor;
    } else {
      arrow[2] = "";
      theAnchor[2] = htmlAnchor1;
    }

    if(abs(columnSort) == 3) {
      arrow[3] = arrowGif;
      theAnchor[3] = htmlAnchor;
    } else {
      arrow[3] = "";
      theAnchor[3] = htmlAnchor1;
    }

    if(abs(columnSort) == 4) {
      arrow[4] = arrowGif;
      theAnchor[4] = htmlAnchor;
    } else {
      arrow[4] = "";
      theAnchor[4] = htmlAnchor1;
    }

    if(abs(columnSort) == 5) {
      arrow[5] = arrowGif;
      theAnchor[5] = htmlAnchor;
    } else {
      arrow[5] = "";
      theAnchor[5] = htmlAnchor1;
    }

    snprintf(buf, sizeof(buf), "<TABLE BORDER=1><TR><TH>%s0>Host%s</A></TH>\n"
	    "<TH>%s1>Domain%s</A></TH>"
	    "<TH>%s2>Pkts Sent%s</A></TH>"
	    "<TH>%s3>Data Sent%s</A></TH>"
	    "<TH>%s4>Pkts Rcvd%s</A></TH>"
	    "<TH>%s5>Data Rcvd%s</A></TH>"
	    "</TR>\n",
	    theAnchor[0], arrow[0],
	    theAnchor[1], arrow[1],
	    theAnchor[2], arrow[2],
	    theAnchor[3], arrow[3],
	    theAnchor[4], arrow[4],
	    theAnchor[5], arrow[5]
	    );
    sendString(buf);

    quicksort(tmpTable, numEntries, sizeof(HostTraffic*), cmpMulticastFctn);

    for(idx=0; idx<numEntries; idx++) {
     if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	snprintf(buf, sizeof(buf), "<TR %s>%s"
		"<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
		"<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
		"</TR>\n",
		getRowColor(), makeHostLink(el, LONG_FORMAT, 0, 1),
		formatPkts(el->pktMulticastSent),
		formatBytes(el->bytesMulticastSent, 1),
		formatPkts(el->pktMulticastRcvd),
		formatBytes(el->bytesMulticastRcvd, 1)
		);

	sendString(buf);

      /* Avoid huge tables */
      if(printedEntries++ > maxNumLines)
		break;
      }
    }

    sendString("</TABLE>\n");
  } else
    printNoDataYet();
}

/* ******************************* */

static int cmpHostsFctn(const void *_a, const void *_b) {
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
      a_ = (*a)->bytesReceivedFromRemote;
      b_ = (*b)->bytesReceivedFromRemote;
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


/* ******************************* */

RETSIGTYPE printHostsInfo(int sortedColumn, int revertOrder) {
  u_int idx, numEntries;
  int printedEntries=0;
  unsigned short maxBandwidthUsage=1 /* avoid divisions by zero */;
  struct hostTraffic *el;
  struct hostTraffic* tmpTable[HASHNAMESIZE];
  char buf[BUF_SIZE], *arrowGif, *sign, *arrow[8], *theAnchor[8];
  char htmlAnchor[64], htmlAnchor1[64];

  memset(buf, 0, sizeof(buf));
  memset(tmpTable, 0, HASHNAMESIZE*sizeof(HostTraffic*));

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG SRC=arrow_down.gif BORDER=0>";
  }

  columnSort = sortedColumn;

  sortSendMode = 2; /* This is used by print header */

  printHeader(0, revertOrder, abs(sortedColumn));

  for(idx=1, numEntries=0; idx<device[actualDeviceId].actualHashSize; idx++)
    if((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL) {
      unsigned short actUsage;

      actUsage = (unsigned short)(100*((float)el->bytesSent/(float)device[actualReportDeviceId].ethernetBytes));

      el->actBandwidthUsage = actUsage;
      if(el->actBandwidthUsage > maxBandwidthUsage)
	maxBandwidthUsage = actUsage;

      tmpTable[numEntries++]=el;
    }

  if(numEntries > 0) {
    quicksort(tmpTable, numEntries, sizeof(struct hostTraffic*), sortHostFctn);

    snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", HOSTS_INFO_HTML, sign);
    snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", HOSTS_INFO_HTML);

    if(abs(columnSort) == 1) {
      arrow[1] = arrowGif;
      theAnchor[1] = htmlAnchor;
    } else {
      arrow[1] = "";
      theAnchor[1] = htmlAnchor1;
    }

    if(abs(columnSort) == 2) {
      arrow[2] = arrowGif;
      theAnchor[2] = htmlAnchor;
    } else {
      arrow[2] = "";
      theAnchor[2] = htmlAnchor1;
    }

    if(abs(columnSort) == 3) {
      arrow[3] = arrowGif;
      theAnchor[3] = htmlAnchor;
    } else {
      arrow[3] = "";
      theAnchor[3] = htmlAnchor1;
    }

    if(abs(columnSort) == 4) {
      arrow[4] = arrowGif;
      theAnchor[4] = htmlAnchor;
    } else {
      arrow[4] = "";
      theAnchor[4] = htmlAnchor1;
    }

    if(abs(columnSort) == 5) {
      arrow[5] = arrowGif;
      theAnchor[5] = htmlAnchor;
    } else {
      arrow[5] = "";
      theAnchor[5] = htmlAnchor1;
    }

    if(abs(columnSort) == 6) {
      arrow[6] = arrowGif;
      theAnchor[6] = htmlAnchor;
    } else {
      arrow[6] = "";
      theAnchor[6] = htmlAnchor1;
    }

    if(abs(columnSort) == DOMAIN_DUMMY_IDX_VALUE) {
      arrow[0] = arrowGif;
      theAnchor[0] = htmlAnchor;
    } else {
      arrow[0] = "";
      theAnchor[0] = htmlAnchor1;
    }

    snprintf(buf, sizeof(buf), "<TABLE BORDER=1>\n<TR><TH>%s1>Host%s</A>"
	    "<TH>%s"DOMAIN_DUMMY_IDX_STR">Domain%s</A></TH>"
	    "</TH><TH>%s2>IP&nbsp;Address%s</A></TH>\n"
	    "<TH>%s3>MAC&nbsp;Address%s</A></TH>"
	    "<TH>%s6>Other&nbsp;Name(s)%s</A></TH>"
	    "<TH>%s4>Sent&nbsp;Bandwidth%s</A></TH>"
	    "<TH>%s5>Nw&nbsp;Board&nbsp;Vendor%s</A></TH>"
	    "</TR>\n",
	    theAnchor[1], arrow[1],
	    theAnchor[0], arrow[0],
	    theAnchor[2], arrow[2],
	    theAnchor[3], arrow[3],
	    theAnchor[6], arrow[6],
	    theAnchor[4], arrow[4],
	    theAnchor[5], arrow[5]);
    sendString(buf);

    for(idx=0; idx<numEntries; idx++) {
      if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	char *tmpName1, *tmpName2, *tmpName3;

	if(broadcastHost(el) == 0) {
	  tmpName1 = el->hostNumIpAddress;
	  if((tmpName1[0] == '\0') || (strcmp(tmpName1, "0.0.0.0") == 0))
	    tmpName1 = separator;

	  tmpName2 = getVendorInfo(el->ethAddress, 1);
	  if(tmpName2[0] == '\0')
	    tmpName2 = separator;

	  tmpName3 = el->ethAddressString;
	  if((tmpName3[0] == '\0')
	     || (strcmp(tmpName3, "00:00:00:00:00:00") == 0))
	    tmpName3 = separator;

	  snprintf(buf, sizeof(buf), "<TR %s>"
		  "%s<TD ALIGN=RIGHT>%s</TD>"
		  "<TD ALIGN=RIGHT>%s</TD>",
		  getRowColor(),
		  makeHostLink(el, LONG_FORMAT, 0, 1),
		  tmpName1, tmpName3);
	  sendString(buf);

	  sendString("<TD ALIGN=RIGHT>");
	  if(el->nbHostName || el->atNetwork || el->ipxHostName) {
	    short numAddresses = 0;

	    if(el->nbDomainName) {
	      snprintf(buf, sizeof(buf), "%s&nbsp;%s&nbsp;[%s]", getOSFlag("Windows", 0),
		      el->nbHostName, el->nbDomainName);
	      sendString(buf);
	      numAddresses++;
	    }

	    if(el->atNetwork) {
	      char *nodeName = el->atNodeName;

	      if(numAddresses > 0) sendString("/");
	      if(nodeName == NULL) nodeName = "";

	      snprintf(buf, sizeof(buf), "%s&nbsp;%s&nbsp;[%d.%d]", getOSFlag("Mac", 0),
		      nodeName, el->atNetwork, el->atNode);
	      sendString(buf);
	      numAddresses++;
	    }

	    if(el->ipxHostName) {
	      if(numAddresses > 0) sendString("/");
	      snprintf(buf, sizeof(buf), "%s&nbsp;%s&nbsp;[%s]", getOSFlag("Novell", 0),
		      el->ipxHostName, getSAPInfo(el->ipxNodeType, 1));
	      sendString(buf);
	      numAddresses++;
	    }
	  }

	  sendString("&nbsp;</TD>");

	  printBar(buf, sizeof(buf), el->actBandwidthUsage, maxBandwidthUsage, 3);

	  snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT>%s</TD>", tmpName2); sendString(buf);

	  sendString("</TR>\n");
	}
      }

      /* Avoid huge tables */
      if(printedEntries++ > maxNumLines)
		break;
    }

    sendString("</TABLE><P>\n");
  }

}

/* ************************************ */

static char* getNbNodeType(char nodeType) {

  switch(nodeType) {
  case 0x0:
    return("Workstation");
  case 0x20:
  default:
    return("Server");
  }

  return(""); /* NOTREACHED */
}

/* ************************************ */

static void printTCPflagsStats(HostTraffic *el) {
  char buf[BUF_SIZE];

  if(((el->tcpSentLocally+el->tcpSentRemotely+
       el->tcpReceivedLocally+el->tcpReceivedFromRemote) == 0)
     || ((el->synPktsSent.value+el->synPktsRcvd.value
	  +el->rstPktsSent.value+el->rstPktsRcvd.value
	  +el->synFinPktsSent.value+el->synFinPktsRcvd.value
	  +el->finPushUrgPktsSent.value+el->finPushUrgPktsRcvd.value
	  +el->nullPktsSent.value+el->nullPktsRcvd.value) == 0))
    return;

  sendString("<P><H1>TCP Packets Stats</H1><P>\n"
	     "<TABLE BORDER=1><TR><TH>Flags</TH>"
	     "<TH COLSPAN=2>Pkts&nbsp;Sent</TH>"
	     "<TH COLSPAN=2>Pkts&nbsp;Received</TH></TR>\n");

  if((el->synPktsSent.value+el->synPktsRcvd.value) > 0) {

    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>SYN</TH>", getRowColor());
    sendString(buf);
    formatUsageCounter(el->synPktsSent);
    formatUsageCounter(el->synPktsRcvd);
    sendString("</TR>\n");
  }

  if((el->rstPktsSent.value+el->rstPktsRcvd.value) > 0) {
    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>RST</TH>", getRowColor());
    sendString(buf);
    formatUsageCounter(el->rstPktsSent);
    formatUsageCounter(el->rstPktsRcvd);
    sendString("</TR>\n");
  }

  if((el->synFinPktsSent.value+el->synFinPktsRcvd.value) > 0) {
    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>SYN|FIN</TH>", getRowColor());
    sendString(buf);
    formatUsageCounter(el->synFinPktsSent);
    formatUsageCounter(el->synFinPktsRcvd);
    sendString("</TR>\n");
  }

  if((el->finPushUrgPktsSent.value+el->finPushUrgPktsRcvd.value) > 0) {
    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>FIN|PUSH|URG</TH>", getRowColor());
    sendString(buf);
    formatUsageCounter(el->finPushUrgPktsSent);
    formatUsageCounter(el->finPushUrgPktsRcvd);
    sendString("</TR>\n");
  }

  if((el->nullPktsSent.value+el->nullPktsRcvd.value) > 0) {
    sendString("<TR><TH ALIGN=LEFT>NULL</TH>");
    formatUsageCounter(el->nullPktsSent);
    formatUsageCounter(el->nullPktsRcvd);
    sendString("</TR>\n");
  }
  sendString("</TABLE><P>\n");
}

/* ************************************ */

static void printHostTrafficStats(HostTraffic *el) {
  TrafficCounter totalSent, totalReceived;
  TrafficCounter actTotalSent, actTotalReceived;
  char buf[BUF_SIZE];

  totalSent = el->tcpSentLocally+el->tcpSentRemotely+el->udpSentLocally+el->udpSentRemotely;
  totalSent += el->icmpSent+el->ospfSent+el->igmpSent+el->ipxSent+el->dlcSent+el->arp_rarpSent;
  totalSent +=  el->decnetSent+el->appletalkSent+el->netbiosSent+
    el->osiSent+el->qnxSent+el->otherSent;

  totalReceived = el->tcpReceivedLocally+el->tcpReceivedFromRemote;
  totalReceived += el->udpReceivedLocally+el->udpReceivedFromRemote;
  totalReceived += el->icmpReceived+el->ospfReceived+el->igmpReceived;
  totalReceived += el->ipxReceived+el->dlcReceived+el->arp_rarpReceived;
  totalReceived += el->decnetReceived+el->appletalkReceived;
  totalReceived +=  el->osiReceived+el->netbiosReceived+el->qnxReceived+el->otherReceived;

  actTotalSent = el->tcpSentLocally+el->tcpSentRemotely;
  actTotalReceived = el->tcpReceivedLocally+el->tcpReceivedFromRemote;

  printHostEvents(el, -1, -1);

  printTCPflagsStats(el);

  if((el->tcpSentLocally+el->tcpSentRemotely+
      el->tcpReceivedLocally+el->tcpReceivedFromRemote+
      el->udpSentLocally+el->udpSentRemotely+
      el->udpReceivedLocally+el->udpReceivedFromRemote) == 0)
    return;

  sendString("<P><H1>IP Protocol Distribution</H1><P>\n"
	     "<TABLE BORDER=1 WIDTH=400><TR><TH WIDTH=20%%>Protocol</TH>"
	     "<TH WIDTH=40%% COLSPAN=2>Data&nbsp;Sent</TH>"
	     "<TH WIDTH=40%% COLSPAN=2>Data&nbsp;Received</TH></TR>\n");

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

  printTableDoubleEntry(buf, sizeof(buf), "Other", COLOR_1, (float)el->otherSent/1024,
			100*((float)SD(el->otherSent, totalSent)),
			(float)el->otherReceived/1024,
			100*((float)SD(el->otherReceived, totalReceived)));
/*#endif */
  sendString("</TABLE><P>\n");
}

/* ************************************ */

static void printHostContactedPeers(HostTraffic *el) {
  u_int numEntries, i;
  char buf[BUF_SIZE];

  if((el->pktSent != 0) || (el->pktReceived != 0)) {
    int ok =0;

    for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
      if((el->contactedSentPeersIndexes[i] != NO_PEER)
	 || (el->contactedRcvdPeersIndexes[i] != NO_PEER)) {
	ok = 1;
	break;
      }

    if(ok) {
      struct hostTraffic *el1;

      sendString("<P><H1>Last Contacted Peers</H1>\n"
		 "<TABLE BORDER=0><TR><TD>\n");

      for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	if(el->contactedSentPeersIndexes[i] != NO_PEER) {
	  el1 = device[actualReportDeviceId].hash_hostTraffic[
		       checkSessionIdx(el->contactedSentPeersIndexes[i])];

	  if(el1 != NULL) {
	    if(numEntries == 0) {
	      sendString("<TABLE BORDER=1>"
			 "<TR><TH>Receiver Name</TH>"
			 "<TH>Receiver Address</TH></TR>\n");
	    }

	    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH>"
		    "<TD ALIGN=CENTER>%s&nbsp;</TD></TR>\n",
		    getRowColor(),
		    makeHostLink(el1, 0, 0, 0),
		    el1->hostNumIpAddress);

	    sendString(buf);
	    numEntries++;
	  }
	}

      if(numEntries > 0)
	sendString("</TABLE></TD><TD>\n");
      else
	sendString("&nbsp;</TD><TD>\n");

      /* ***************************************************** */
      for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	if(el->contactedRcvdPeersIndexes[i] != NO_PEER) {
	  el1 = device[actualReportDeviceId].hash_hostTraffic[
                       checkSessionIdx(el->contactedRcvdPeersIndexes[i])];

	  if(el1 != NULL) {
	    if(numEntries == 0) {
	      sendString("<TABLE BORDER=1>"
			 "<TR><TH>Sender Name</TH><TH>Sender Address</TH></TR>\n");
	    }

	    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=CENTER>%s&nbsp;</TD></TR>\n",
		    getRowColor(),
		    makeHostLink(el1, 0, 0, 0),
		    el1->hostNumIpAddress);

	    sendString(buf);
	    numEntries++;
	  }
	}

      if(numEntries > 0)
	sendString("</TABLE>\n");

      sendString("</TD></TR></TABLE><P>\n");
    } /* ok */
  }
}

/* ************************************ */

/* Function below courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */

static char *getSessionState(IPSession *session) {
  switch (session->sessionState) {
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

static void printHostSessions(HostTraffic *el, u_int elIdx) {
  char buf[BUF_SIZE];
  struct ipGlobalSession *scanner=NULL;
  u_int scanIdx;
  char *sessionType=NULL;
  u_short numSessions;
  u_int idx, i;
  static char _sport[8], _dport[8];

  if((el->tcpSessionList != NULL) || (el->udpSessionList != NULL)) {
    sendString("<P><H1>IP Session History</H1><P>\n");
  }

  for(scanIdx=0; scanIdx<2; scanIdx++)
    {
      switch(scanIdx) {
      case 0:
	scanner = el->tcpSessionList;
	sessionType = "TCP";
	break;
      case 1:
	scanner = el->udpSessionList;
	sessionType = "UDP";
	break;
      }

      numSessions = 0;

      while(scanner != NULL) {
	char *whoswho, *svc=NULL, tmpSvc[16];

	if(scanner->initiator == CLIENT_ROLE)
	  whoswho= "client";
	else
	  whoswho= "server";

	switch(scanIdx) {
	case 0:
	  svc = getPortByNum((int)(scanner->port), IPPROTO_TCP);
	  break;
	case 1:
	  svc = getPortByNum((int)(scanner->port), IPPROTO_UDP);
	  break;
	}

	if(svc == NULL) {
	  snprintf(tmpSvc, sizeof(tmpSvc), "%d", (int)(scanner->port));
	  svc = tmpSvc;
	}

	if(numSessions == 0) {
	  snprintf(buf, sizeof(buf), "<TABLE BORDER WIDTH=\"100%%\">\n<TR>"
		  "<TH COLSPAN=2>%s&nbsp;Service</TH>"
		  "<TH>Role</TH><TH>"
		  "#&nbsp;Sessions</TH>"
		  "<TH>Bytes&nbsp;Sent</TH>"
		  "<TH>Bytes&nbsp;Rcvd</TH>"
		  "<TH>Last&nbsp;Seen</TH>"
		  "<TH>First&nbsp;Seen</TH>"
		  "<TH>Peers</TH></TR>\n",
		  sessionType);
	  sendString(buf);
	}

	snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=RIGHT>%s</TH><TD ALIGN=CENTER>%d</TD>"
		"<TD ALIGN=CENTER>%s</TD><TD ALIGN=CENTER>%d"
		"</TD><TD ALIGN=CENTER>%s</TD>"
		"<TD ALIGN=CENTER>%s</TD><TD>"
		"%s</TD><TD>%s</TD>\n",
		getRowColor(), svc, scanner->port, whoswho,
		(int)scanner->sessionCounter,
		formatBytes(scanner->bytesSent, 1),
		formatBytes(scanner->bytesReceived, 1),
		formatTime(&(scanner->lastSeen), 1),
		formatTime(&(scanner->firstSeen), 1)
		);
	sendString(buf);
	numSessions++;

	sendString("<TD><UL>");
	for(i=0; i < MAX_NUM_SESSION_PEERS; i++) {
	  if((scanner->peersIdx[i] != NO_PEER)
	     && (device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(scanner->peersIdx[i])] != NULL)) {
	    HostTraffic *host = device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(scanner->peersIdx[i])];


	    if(host != NULL) {
#ifdef MULTITHREADED
	      accessMutex(&addressResolutionMutex, "printSession");
#endif
	      if(host->hostNumIpAddress[0] == '&')
		snprintf(buf, sizeof(buf), "<LI>%s\n", host->hostSymIpAddress);
	      else
		snprintf(buf, sizeof(buf), "<LI><A HREF=%s.html>%s</A>\n",
			host->hostNumIpAddress,
			host->hostSymIpAddress);

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

      if(numSessions > 0)
	sendString("</TABLE><P>\n");
    }  /* while */


  /* Now print currently established TCP sessions (if any) */
  for(idx=1, numSessions=0; idx<HASHNAMESIZE; idx++)
    if((tcpSession[idx] != NULL)
       && ((tcpSession[idx]->initiatorIdx == elIdx)
	   || (tcpSession[idx]->remotePeerIdx == elIdx))
#ifndef PRINT_ALL_ACTIVE_SESSIONS
       && (tcpSession[idx]->sessionState == STATE_ACTIVE)
#endif
       ) {
      char *sport, *dport, *remotePeer;
      TrafficCounter dataSent, dataReceived, retrDataSent, retrDataRcvd;
      int retrSentPercentage, retrRcvdPercentage;

      if(numSessions == 0) {
	sendString("<P><H1>Active TCP Sessions</H1><P>\n");
	sendString("<TABLE BORDER=1 WIDTH=\"100%%\"><TR>"
		   "<TH>Local&nbsp;Port</TH>"
		   "<TH>Remote&nbsp;Peer:Port</TH>"
		   "<TH>Data&nbsp;Sent</TH>"
#ifdef PRINT_RETRANSMISSION_DATA
		   "<TH>Retran.&nbsp;Data&nbsp;Sent</TH>"
#endif
		   "<TH>Data&nbsp;Rcvd</TH>"
#ifdef PRINT_RETRANSMISSION_DATA
		   "<TH>Retran.&nbsp;Data&nbsp;Rcvd</TH>"
#endif
		   "<TH>Active&nbsp;Since</TH>"
		   "<TH>Last&nbsp;Seen</TH>"
		   "<TH>Duration</TH>"
#ifdef PRINT_ALL_ACTIVE_SESSIONS
		   "<TH>State</TH>"
#endif
		   "</TR>\n");
      }

      if(tcpSession[idx]->initiatorIdx == elIdx) {
	sport = getPortByNum(tcpSession[idx]->sport, IPPROTO_TCP);
	dport = getPortByNum(tcpSession[idx]->dport, IPPROTO_TCP);
	if(sport == NULL) {
	  snprintf(_sport, sizeof(_sport), "%d", tcpSession[idx]->sport); sport = _sport;
	}

	if(dport == NULL) {
	  snprintf(_dport, sizeof(_dport), "%d", tcpSession[idx]->dport); dport = _dport;
	}
	remotePeer = makeHostLink(device[actualReportDeviceId].
				  hash_hostTraffic[checkSessionIdx(tcpSession[idx]->remotePeerIdx)],
				  SHORT_FORMAT, 0, 0);
	dataSent = tcpSession[idx]->bytesSent;
	dataReceived = tcpSession[idx]->bytesReceived;
	retrDataSent = tcpSession[idx]->bytesRetranI2R;
	retrDataRcvd = tcpSession[idx]->bytesRetranR2I;
      } else {
	/* Responder */
	sport = getPortByNum(tcpSession[idx]->dport, IPPROTO_TCP);
	dport = getPortByNum(tcpSession[idx]->sport, IPPROTO_TCP);
	if(sport == NULL) {
	  snprintf(_sport, sizeof(_sport), "%d", tcpSession[idx]->dport); sport = _sport;
	}

	if(dport == NULL) {
	  snprintf(_dport, sizeof(_dport), "%d", tcpSession[idx]->sport); dport = _dport;
	}

	remotePeer = makeHostLink(device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(tcpSession[idx]->initiatorIdx)],
				  SHORT_FORMAT, 0, 0);
	dataSent = tcpSession[idx]->bytesReceived;
	dataReceived = tcpSession[idx]->bytesSent;
	retrDataSent = tcpSession[idx]->bytesRetranR2I;
	retrDataRcvd = tcpSession[idx]->bytesRetranI2R;
      }

      /* Sanity check */
      if((actTime < tcpSession[idx]->firstSeen)
	 || (tcpSession[idx]->firstSeen == 0))
	tcpSession[idx]->firstSeen = actTime;

      retrSentPercentage = (int)((float)(retrDataSent*100))/((float)(dataSent+1));
      retrRcvdPercentage = (int)((float)(retrDataRcvd*100))/((float)(dataReceived+1));

      snprintf(buf, sizeof(buf), "<TR %s>"
	      "<TD ALIGN=RIGHT>%s</TD>"
	      "<TD ALIGN=RIGHT>%s:%s</TD>"
	      "<TD ALIGN=RIGHT>%s</TD>"
#ifdef PRINT_RETRANSMISSION_DATA
	      "<TD ALIGN=RIGHT>%s [%d%%]</TD>"
#endif
	      "<TD ALIGN=RIGHT>%s</TD>"
#ifdef PRINT_RETRANSMISSION_DATA
	      "<TD ALIGN=RIGHT>%s [%d%%]</TD>"
#endif
	      , getRowColor(),
	      sport,
	      remotePeer, dport,
	      formatBytes(dataSent, 1),
#ifdef PRINT_RETRANSMISSION_DATA
	      formatBytes(retrDataSent, 1),
	      retrSentPercentage,
#endif
	      formatBytes(dataReceived, 1)
#ifdef PRINT_RETRANSMISSION_DATA
	      , formatBytes(retrDataRcvd, 1),
	      retrRcvdPercentage
#endif
	      );

      sendString(buf);


      snprintf(buf, sizeof(buf),
	      "<TD ALIGN=RIGHT>%s</TD>"
	      "<TD ALIGN=RIGHT>%s</TD>"
	      "<TD ALIGN=RIGHT>%s</TD>"
#ifdef PRINT_ALL_ACTIVE_SESSIONS
	      "<TD ALIGN=CENTER>%s</TD>"
#endif
	      "</TR>\n",
	      formatTime(&(tcpSession[idx]->firstSeen), 1),
	      formatTime(&(tcpSession[idx]->lastSeen), 1),
	      formatSeconds(actTime-tcpSession[idx]->firstSeen)
#ifdef PRINT_ALL_ACTIVE_SESSIONS
	      , getSessionState(tcpSession[idx])
#endif
	      );

      sendString(buf);

      numSessions++;
    }

  if(numSessions > 0)
    sendString("</TABLE><P>\n");
}

/* ************************************ */

static void printHostDetailedInfo(HostTraffic *el) {
  char buf[BUF_SIZE];
  float percentage;
  int printedHeader, i;

#ifdef MULTITHREADED
  accessMutex(&addressResolutionMutex, "printAllSessionsHTML");
#endif

  if(el->hostSymIpAddress[0] == '\0')
    snprintf(buf, sizeof(buf), "<center><P><H1>Info about"
	    " %s</H1><P>\n",
	    el->ethAddressString);
  else
    snprintf(buf, sizeof(buf), "<center><P><H1>Info about"
	     " <A HREF=http://%s/>%s</A></H1><P>\n",
	     el->hostNumIpAddress, el->hostSymIpAddress);

#ifdef MULTITHREADED
  releaseMutex(&addressResolutionMutex);
#endif

  sendString(buf);

  sendString("<P><TABLE BORDER=1 WIDTH=\"100%%\">\n");

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

    if(el->hostIpAddresses[1].s_addr == 0x0) {
      snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>%s&nbsp;%s&nbsp;[%s]",
	      getRowColor(),
	      "IP&nbsp;Address",
	      el->hostNumIpAddress,
	      countryIcon, hostType);
      sendString(buf);
    } else {
      int i;

      snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT><ol>",
	      getRowColor(), "IP&nbsp;Address");
      sendString(buf);

      for(i=0; i<MAX_MULTIHOMING_ADDRESSES; i++) {
	if(el->hostIpAddresses[i].s_addr != 0x0) {
	  snprintf(buf, sizeof(buf), "<LI>%s", _intoa(el->hostIpAddresses[i], buf, sizeof(buf)));
	  sendString(buf);
	} else
	  break;
      }

      snprintf(buf, sizeof(buf), "</ol><br>%s&nbsp;[%s - multihomed]", countryIcon, hostType);
      sendString(buf);
    }

    if(subnetLocalHost(el)
       && FD_ISSET((unsigned long)(el->hostIpAddress.s_addr) % 256 /* C-class */,
		   &ipTrafficMatrixPromiscHosts)) {
      /* Promiscuous mode */
      sendString("&nbsp;<BLINK><B><FONT COLOR=#FF0000>[Promiscuous Mode Host]</FONT>"
		 "</B></BLINK>");
      sendString("</TD></TR>\n");
    }
  }

  snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	  "%s&nbsp;&nbsp;-&nbsp;&nbsp;%s&nbsp;[%s]</TD></TR>\n",
	   getRowColor(),
	   "First/Last&nbsp;Seen",
           formatTime(&(el->firstSeen), 1),
           formatTime(&(el->lastSeen), 1),
	   formatSeconds(el->lastSeen - el->firstSeen));
  sendString(buf);

  if(el->fullDomainName && (el->fullDomainName[0] != '\0')) {
    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	    "%s&nbsp;</TD></TR>\n",
	    getRowColor(),
	    "Domain", el->fullDomainName);
    sendString(buf);
  }

  if((el->ethAddressString[0] != '\0')
     && strcmp(el->ethAddressString, "00:00:00:00:00:00")
     && strcmp(el->ethAddressString, "00:01:02:03:04:05") /* dummy address */) {
    char *vendorName;

    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	    "%s%s</TD></TR>\n",
	    getRowColor(), "MAC&nbsp;Address",
	    el->ethAddressString, separator /* it avoids empty cells not to be rendered */);
    sendString(buf);

    vendorName = getVendorInfo(el->ethAddress, 1);
    if(vendorName[0] != '\0') {
      snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	      "%s%s</TD></TR>\n",
	      getRowColor(), "Nw&nbsp;Board&nbsp;Vendor",
	      vendorName,
	      separator /* it avoids empty cells not to be rendered */);
      sendString(buf);
    }
  }

  if(el->hostNumIpAddress[0] != '\0') {
    updateOSName(el);

    if((el->osName != NULL) && (el->osName[0] != '\0')) {
      snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	      "%s%s</TD></TR>\n",
	      getRowColor(), "OS&nbsp;Name",
	      getOSFlag(el->osName, 1), separator /* it avoids empty cells not to be rendered */);
      sendString(buf);
    }
  }

  if((el->nbHostName != NULL) && (el->nbDomainName != NULL)) {
    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	    "%s&nbsp;[domain %s] (%s)</TD></TR>\n",
	    getRowColor(), "NetBios&nbsp;Name",
	    el->nbHostName, el->nbDomainName, getNbNodeType(el->nbNodeType));
    sendString(buf);
  }

  if(el->atNetwork != 0) {
    char *nodeName = el->atNodeName;

    if(nodeName == NULL) nodeName = "";

    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	    "%s&nbsp;[%d.%d]</TD></TR>\n",
	    getRowColor(), "AppleTalk&nbsp;Name",
	    nodeName, el->atNetwork, el->atNode);

    sendString(buf);
  }

  if(el->ipxHostName != NULL) {
    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	    "%s&nbsp;[%s]</TD></TR>\n",
	    getRowColor(), "IPX&nbsp;Name",
	    el->ipxHostName, getSAPInfo(el->ipxNodeType, 1));
    sendString(buf);
  }

  if(!multicastHost(el)) {
    if(subnetPseudoLocalHost(el))
      snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	      "%s</TD></TR>\n", getRowColor(),
	      "Host&nbsp;Location",
	      "Local (inside specified/local subnet)");
    else
      snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	      "%s</TD></TR>\n", getRowColor(),
	      "Host&nbsp;Location",
	      "Remote (outside specified/local subnet)");
    sendString(buf);
  }

  if(el->minTTL > 0) {
    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	    "%d:%d&nbsp;hops</TD></TR>\n",
	    getRowColor(), "IP&nbsp;TTL&nbsp;(Time to Live)",
	    el->minTTL, el->maxTTL);
    sendString(buf);
  }

  snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	  "%s/%s Pkts/%s Retran. Pkts [%d%%]</TD></TR>\n",
	  getRowColor(), "Total&nbsp;Data&nbsp;Sent",
	  formatBytes(el->bytesSent, 1), formatPkts(el->pktSent),
	  formatPkts(el->pktDuplicatedAckSent),
	  (int)(((float)el->pktDuplicatedAckSent*100)/(float)(el->pktSent+1))
	  );
  sendString(buf);

  snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	  "%s Pkts</TD></TR>\n",
	  getRowColor(), "Broadcast&nbsp;Pkts&nbsp;Sent",
	  formatPkts(el->pktBroadcastSent));
  sendString(buf);

  if((el->pktMulticastSent > 0) || (el->pktMulticastRcvd > 0)) {
    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	    "Sent&nbsp;%s/%s&nbsp;Pkts&nbsp;-"
	    "&nbsp;Rcvd&nbsp;%s/%s&nbsp;Pkts</TD></TR>\n",
	    getRowColor(), "Multicast&nbsp;Traffic",
	    formatBytes(el->bytesMulticastSent, 1),
	    formatPkts(el->pktMulticastSent),
	    formatBytes(el->bytesMulticastRcvd, 1),
	    formatPkts(el->pktMulticastRcvd)
	    );
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

  snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
	  "%s/%s Pkts/%s Retran. Pkts [%d%%]</TD></TR>\n",
	  getRowColor(), "Total&nbsp;Data&nbsp;Rcvd",
	  formatBytes(el->bytesReceived, 1), formatPkts(el->pktReceived),
	  formatPkts(el->pktDuplicatedAckRcvd),
	  (int)((float)(el->pktDuplicatedAckRcvd*100)/(float)(el->pktReceived+1)));
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
  for(i=0; i<MAX_NUM_HOST_ROUTERS; i++) {
    if(el->contactedRouters[i] != NO_PEER) {
      int routerIdx = el->contactedRouters[i];

      if(!printedHeader) {
	snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>"
		"Used&nbsp;Subnet&nbsp;Routers</TH><TD ALIGN=RIGHT>\n", getRowColor());
	sendString(buf);
      }
      printedHeader++;

      if(printedHeader > 1) sendString("<BR>");

      snprintf(buf, sizeof(buf), "%s\n",
	      makeHostLink(device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(routerIdx)],
			   SHORT_FORMAT, 0, 0));
      sendString(buf);
    }
  }

  if(gatewayHost(el) || dnsHost(el)) {
    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>",
	    getRowColor(),
	    "Provided&nbsp;Services");
    sendString(buf);

    if(dnsHost(el)) sendString("&nbsp;DNS&nbsp;");
    if(gatewayHost(el)) sendString("&nbsp;Gateway&nbsp;");
    sendString("</TD></TR>");
  }

  /*
    Fix courtesy of
    Albert Chin-A-Young <china@thewrittenword.com>
  */
  if(printedHeader > 1)
    sendString("</OL></TD></TR>\n");

  sendString("</TABLE><P>\n");
}

/* ************************************ */

static void printServiceStats(char* svcName, ServiceStats* ss,
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
	snprintf(buf, sizeof(buf), "<TR %s><TH>%s</TH><TD ALIGN=CENTER>%s</TD><TD ALIGN=CENTER>%.1f%%</TD>"
		"<TD ALIGN=CENTER>%s</TD><TD ALIGN=CENTER>%.1f%%</TD>"
		"<TD ALIGN=CENTER>%s</TD><TD ALIGN=CENTER>%.1f%%</TD>"
		"<TD ALIGN=CENTER>%s</TD><TD ALIGN=CENTER>%.1f%%</TD>"
		"<TD ALIGN=CENTER>%s - %s</TD><TD ALIGN=CENTER>%s - %s</TD>"
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
		);
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
	snprintf(buf, sizeof(buf), "<TR %s><TH>%s</TH><TD ALIGN=CENTER>%s</TD><TD ALIGN=CENTER>%.1f%%</TD>"
		"<TD ALIGN=CENTER>%s</TD><TD ALIGN=CENTER>%.1f%%</TD>"
		"<TD ALIGN=CENTER>%s</TD><TD ALIGN=CENTER>%.1f%%</TD>"
		"<TD ALIGN=CENTER>%s</TD><TD ALIGN=CENTER>%.1f%%</TD>"
		"<TD ALIGN=CENTER>%s - %s</TD><TD ALIGN=CENTER>%s - %s</TD>"
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
		);
	sendString(buf);
      }
    }
  }
}

/* ************************************ */

static void printHostUsedServices(HostTraffic *el) {
  TrafficCounter tot;

  if((el->dnsStats == NULL)
     && (el->httpStats == NULL))
    return;
  

  tot = 0;

  if(el->dnsStats)
    tot += el->dnsStats->numLocalReqSent+el->dnsStats->numRemoteReqSent;

  if(el->httpStats)
    tot += el->httpStats->numLocalReqSent+el->httpStats->numRemoteReqSent;

  if(tot > 0) {
    sendString("<P><H1>IP&nbsp;Service&nbsp;Stats:&nbsp;Client&nbsp;Role</H1><P>\n");

    sendString("<TABLE BORDER=1>\n<TR>"
	       "<TH>&nbsp;</TH>"
	       "<TH COLSPAN=2>#&nbsp;Loc.&nbsp;Req.&nbsp;Sent</TH>"
	       "<TH COLSPAN=2>#&nbsp;Rem.&nbsp;Req.&nbsp;Sent</TH>"
	       "<TH COLSPAN=2>#&nbsp;Pos.&nbsp;Reply&nbsp;Rcvd</TH>"
	       "<TH COLSPAN=2>#&nbsp;Neg.&nbsp;Reply&nbsp;Rcvd</TH>"
	       "<TH>Local&nbsp;RndTrip</TH>"
	       "<TH>Remote&nbsp;RndTrip</TH>"
	       "</TR>\n");

    if(el->dnsStats) printServiceStats("DNS", el->dnsStats, 1);
    if(el->httpStats) printServiceStats("HTTP", el->httpStats, 1);

    sendString("</TABLE>\n");
  }

  /* ************ */

  tot = 0;

  if(el->dnsStats)
    tot += el->dnsStats->numLocalReqRcvd+el->dnsStats->numRemoteReqRcvd;

  if(el->httpStats)
    tot += el->httpStats->numLocalReqRcvd+el->httpStats->numRemoteReqRcvd;

  if(tot > 0) {
    sendString("<P><H1>IP&nbsp;Service&nbsp;Stats:&nbsp;Server&nbsp;Role</H1><P>\n");

    sendString("<P><TABLE BORDER=1>\n<TR>"
	       "<TH>&nbsp;</TH>"
	       "<TH COLSPAN=2>#&nbsp;Loc.&nbsp;Req.&nbsp;Rcvd</TH>"
	       "<TH COLSPAN=2>#&nbsp;Rem.&nbsp;Req.&nbsp;Rcvd</TH>"
	       "<TH COLSPAN=2>#&nbsp;Pos.&nbsp;Reply&nbsp;Sent</TH>"
	       "<TH COLSPAN=2>#&nbsp;Neg.&nbsp;Reply&nbsp;Sent</TH>"
	       "<TH>Local&nbsp;RndTrip</TH>"
	       "<TH>Remote&nbsp;RndTrip</TH>"
	       "</TR>\n");

    if(el->dnsStats) printServiceStats("DNS", el->dnsStats, 0);
    if(el->httpStats) printServiceStats("HTTP", el->httpStats, 0);

    sendString("</TABLE>\n");
  }
}

/* ************************************ */

void printAllSessionsHTML(char* host) {
  u_int idx, elIdx, i;
  HostTraffic *el=NULL;
  char buf[BUF_SIZE];

  for(elIdx=1; elIdx<device[actualDeviceId].actualHashSize; elIdx++) {
    el = device[actualReportDeviceId].hash_hostTraffic[elIdx];

    if((elIdx != broadcastEntryIdx)
       && (el != NULL)
       && (el->hostNumIpAddress != NULL)
       && ((strcmp(el->hostNumIpAddress, host) == 0)
	   || (strcmp(el->ethAddressString, host) == 0)))
      break;
  }

  if(el == NULL) {
    snprintf(buf, sizeof(buf), "<CENTER><P><H1>Unable to generate "
	    "requested page [%s]</H1></CENTER>\n", host);
    sendString(buf);
    return;
  }

  /* ************************************ */

  printHostDetailedInfo(el);
  printHostTrafficStats(el);
  printHostContactedPeers(el);
  printHostUsedServices(el);

  /* ***************************************************** */

  i = 0;

  for(idx=1; idx<1024; idx++) {
    if(el->portsUsage[idx] != NULL) {
      char *svc = getAllPortByNum(idx);
      char webHostName[256];
      HostTraffic *peerHost;

      if(i == 0) {
	sendString("<P><H1>IP&nbsp;"
		   "Service/Port&nbsp;Usage</H1><P>\n");
	sendString("<TABLE BORDER=1>\n<TR>"
		   "<TH>IP&nbsp;Service</TH>"
		   "<TH>Port</TH>"
		   "<TH>#&nbsp;Client&nbsp;Sess.</TH>"
		   "<TH>Last&nbsp;Client&nbsp;Peer</TH>"
		   "<TH>#&nbsp;Server&nbsp;Sess.</TH>"
		   "<TH>Last&nbsp;Server&nbsp;Peer</TH>"
		   "</TR>\n");
	i++;
      }

      if(svc != NULL)
	snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH>"
		"<TD ALIGN=CENTER>%d</TD>", getRowColor(), svc, idx);
      else
	snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%d</TH>"
		"<TD ALIGN=CENTER>%d</TD>", getRowColor(), idx, idx);

      sendString(buf);

      if(el->portsUsage[idx]->clientUses > 0) {
	/* Fix below courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */
	peerHost = device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(el->portsUsage[idx]->clientUsesLastPeer)];

	if(peerHost == NULL) {
	  /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
	  strncpy(webHostName, "&nbsp;", sizeof(webHostName));
	} else
	  strncpy(webHostName, makeHostLink(peerHost, SHORT_FORMAT, 0, 0), sizeof(webHostName));

	snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>%d/%s</TD>"
		"<TD ALIGN=CENTER>%s</TD>",
		el->portsUsage[idx]->clientUses,
		formatBytes(el->portsUsage[idx]->clientTraffic, 1),
		webHostName);
	sendString(buf);
      } else
	sendString("<TD>&nbsp;</TD><TD>&nbsp;</TD>");

      if(el->portsUsage[idx]->serverUses > 0) {
	peerHost = device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(el->portsUsage[idx]->serverUsesLastPeer)];

	if(peerHost == NULL) {
	  /* Courtesy of Roberto De Luca <deluca@tandar.cnea.gov.ar> */
	  strncpy(webHostName, "&nbsp;", sizeof(webHostName));
	} else
	  strncpy(webHostName, makeHostLink(peerHost, SHORT_FORMAT, 0, 0), sizeof(webHostName));

	snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER>%d/%s</TD>"
		"<TD ALIGN=CENTER>%s</TD></TR>",
		el->portsUsage[idx]->serverUses,
		formatBytes(el->portsUsage[idx]->serverTraffic, 1),
		webHostName);
	sendString(buf);
      } else
	sendString("<TD>&nbsp;</TD><TD>&nbsp;</TD></TR>");
    }
  }

  if(i > 0)
    sendString("</TABLE></P>\n");

  printHostSessions(el, elIdx);
}

/* ************************************ */

void printLocalRoutersList(void) {
  char buf[BUF_SIZE];
  HostTraffic *el, *router;
  u_int idx, i, j, numEntries=0;
  u_int routerList[MAX_NUM_ROUTERS];

  for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++) {
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && subnetLocalHost(el)) {

      for(j=0; j<MAX_NUM_HOST_ROUTERS; j++)
	if(el->contactedRouters[j] != NO_PEER) {
	  short found = 0;

	  for(i=0; i<numEntries; i++) {
	    if(el->contactedRouters[j] == routerList[i]) {
	      found = 1;
	      break;
	    }
	  }

	  if((found == 0) && (numEntries < MAX_NUM_ROUTERS)) {
	    /* traceEvent(TRACE_INFO, "Adding '%d' in slot '%d'\n",
	       el->contactedRouters[j], numEntries); */
	    routerList[numEntries++] = el->contactedRouters[j];
	  }
	}
    }
  }

  sendString("<CENTER><P><H1>Local Subnet Routers</H1><p>\n");

  if(numEntries == 0) {
    printNoDataYet();
    return;
  } else {
    sendString("<TABLE BORDER=1><TR><TH>Router Name</TH>"
	       "<TH>Used by</TH></TR>\n");

    for(i=0; i<numEntries; i++) {
      router = device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(routerList[i])];
      if(router != NULL) {
	snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=left>%s</TH><TD ALIGN=LEFT><UL>\n",
		getRowColor(),
		makeHostLink(router, SHORT_FORMAT, 0, 0));
	sendString(buf);

	for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++)
	  if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
	     && subnetLocalHost(el)) {
	    for(j=0; j<MAX_NUM_HOST_ROUTERS; j++)
	      if(el->contactedRouters[j] == routerList[i]) {
		snprintf(buf, sizeof(buf), "<LI>%s</LI>\n",
			makeHostLink(el, SHORT_FORMAT, 0, 0));
		sendString(buf);
		break;
	      }
	  }

	sendString("</OL></TD></TR>\n");
      }
    }

    sendString("</TABLE></CENTER>\n");
  }

}

/* ************************************ */

#ifdef DEBUG
void printSession(IPSession *theSession, u_short sessionType,
		  u_short sessionCounter)
{
  char *_sport, *_dport, *_sessionType, *direction;

  _sport = getPortByNum(theSession->sport, sessionType);
  _dport = getPortByNum(theSession->dport, sessionType);

  if(_sport == NULL) {
    static char __sport[8];
    snprintf(__sport, 8, "%d", (int)theSession->sport);
    _sport = __sport;
  }

  if(_dport == NULL) {
    static char __dport[8];
    snprintf(__dport, 8, "%d", (int)theSession->dport);
    _dport = __dport;
  }

  if(sessionType == IPPROTO_TCP) {
    _sessionType = "TCP";
    direction = "<->";
  } else {
    _sessionType = "UDP";
    direction = " >";
  }

  printLogTime();

#ifdef MULTITHREADED
  accessMutex(&addressResolutionMutex, "printSessions");
#endif
  fprintf(logd," %s %s:%s %s %s:%s s=%lu/r=%lu\n",
	  _sessionType,
	  device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(theSession->initiatorIdx)]->hostSymIpAddress, _sport,
	  direction,
	  device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(theSession->remotePeerIdx)]->hostSymIpAddress, _dport,
	  (unsigned long)theSession->bytesSent,
	  (unsigned long)theSession->bytesReceived);
#ifdef MULTITHREADED
  releaseMutex(&addressResolutionMutex);
#endif
}

/* ************************************ */


static void printSessions(IPSession *sessions[], u_short type) {
  int idx;
  char* sessionType;

  if(type == IPPROTO_TCP)
    sessionType = "TCP";
  else
    sessionType = "UDP";


  if (logTimeout) {
    for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++)
      if(sessions[idx] != NULL) {

	char *_sport = getPortByNum(sessions[idx]->sport, type);
	char *_dport = getPortByNum(sessions[idx]->dport, type);

	if(_sport == NULL) {
	  static char __sport[8];
	  snprintf(__sport, 8, "%d", sessions[idx]->sport);
	  _sport = __sport;
	}

	if(_dport == NULL) {
	  static char __dport[8];
	  snprintf(__dport, 8, "%d", sessions[idx]->dport);
	  _dport = __dport;
	}

	printLogTime();
#ifdef MULTITHREADED
	accessMutex(&addressResolutionMutex, "printProcessInfo");
#endif
	fprintf(logd, "%s\t%s:%s <-> %s:%s\ts=%lu/r=%lu\n",
		sessionType,
		device[actualReportDeviceId].
		hash_hostTraffic[checkSessionIdx(sessions[idx]->initiatorIdx)]->hostSymIpAddress,
		_sport,
		device[actualReportDeviceId].
		hash_hostTraffic[checkSessionIdx(sessions[idx]->remotePeerIdx)]->hostSymIpAddress,
		_dport,
		(unsigned long)sessions[idx]->bytesSent,
		(unsigned long)sessions[idx]->bytesReceived);
#ifdef MULTITHREADED
	releaseMutex(&addressResolutionMutex);
#endif
      }
  }

}

void printTCPSessions(void) { printSessions(tcpSession, IPPROTO_TCP); }
void printUDPSessions(void) { printSessions(udpSession, IPPROTO_UDP); }

#endif /* DEBUG */

/* ************************************ */

RETSIGTYPE printIpAccounting(int remoteToLocal, int sortedColumn,
			     int revertOrder) {
  u_int idx, numEntries;
  int printedEntries=0;
  struct hostTraffic *el;
  struct hostTraffic* tmpTable[HASHNAMESIZE];
  char buf[BUF_SIZE], *str=NULL, *sign;
  TrafficCounter totalBytesSent, totalBytesReceived, totalBytes, a=0, b=0;
  float sentpct, rcvdpct;
  time_t timeDiff = time(NULL)-initialSniffTime;
  char *arrowGif, *arrow[48], *theAnchor[48];
  char htmlAnchor[64], htmlAnchor1[64];

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG SRC=arrow_down.gif BORDER=0>";
  }

 totalBytesSent=0, totalBytesReceived=0;
  memset(tmpTable, 0, HASHNAMESIZE*sizeof(HostTraffic*));

  for(idx=1, numEntries=0; idx<device[actualDeviceId].actualHashSize; idx++)
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && (broadcastHost(el) == 0) /* No broadcast addresses please */
       && ((el->hostNumIpAddress[0] != '\0')
	   && (el->hostNumIpAddress[0] != '0' /* 0.0.0.0 */)
	   /* This host speaks IP */)) {
      switch(remoteToLocal) {
      case REMOTE_TO_LOCAL_ACCOUNTING:
	if(!subnetPseudoLocalHost(el)) {
	  if((el->bytesSentLocally > 0) || (el->bytesReceivedLocally > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentLocally;
	    totalBytesReceived += el->bytesReceivedLocally;
	  }
	}
	break;
      case LOCAL_TO_REMOTE_ACCOUNTING:
	if(subnetPseudoLocalHost(el)) {
	  if((el->bytesSentRemotely > 0) || (el->bytesReceivedFromRemote > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentRemotely;
	    totalBytesReceived += el->bytesReceivedFromRemote;
	  }
	}
	break;
      case LOCAL_TO_LOCAL_ACCOUNTING:
	if(subnetPseudoLocalHost(el)) {
	  if((el->bytesSentLocally > 0) || (el->bytesReceivedLocally > 0)) {
	    tmpTable[numEntries++]=el;
	    totalBytesSent += el->bytesSentLocally;
	    totalBytesReceived += el->bytesReceivedLocally;
	  }
	}
	break;
      }
    }

  if(numEntries > 0) {
    columnSort = sortedColumn;
    sortFilter = remoteToLocal;
    quicksort(tmpTable, numEntries, sizeof(struct hostTraffic*), cmpHostsFctn);

    switch(remoteToLocal) {
    case REMOTE_TO_LOCAL_ACCOUNTING:
      str = IP_R_2_L_HTML;
      break;
    case LOCAL_TO_REMOTE_ACCOUNTING:
      str = IP_L_2_R_HTML;
      break;
    case LOCAL_TO_LOCAL_ACCOUNTING:
      str = IP_L_2_L_HTML;
      break;
    }

    snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", str, sign);
    snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", str);

    if(abs(columnSort) == 1) {
      arrow[1] = arrowGif;
      theAnchor[1] = htmlAnchor;
    } else {
      arrow[1] = "";
      theAnchor[1] = htmlAnchor1;
    }

    if(abs(columnSort) == 2)  {
      arrow[2] = arrowGif;
      theAnchor[2] = htmlAnchor;
    } else {
      arrow[2] = "";
      theAnchor[2] = htmlAnchor1;
    }

    if(abs(columnSort) == 3) {
      arrow[3] = arrowGif;
      theAnchor[3] = htmlAnchor;
    } else {
      arrow[3] = "";
      theAnchor[3] = htmlAnchor1;
    }

    if(abs(columnSort) == 4) {
      arrow[4] = arrowGif;
      theAnchor[4] = htmlAnchor;
    } else {
      arrow[4] = "";
      theAnchor[4] = htmlAnchor1;
    }

    snprintf(buf, sizeof(buf), "<TABLE BORDER=1 WIDTH=\"100%%\">\n<TR><TH>"
	    "%s1>Host%s</A></TH>"
	    "<TH>%s2>IP&nbsp;Address%s</A></TH>\n"
	    "<TH COLSPAN=2>%s3>Data&nbsp;Sent%s</A></TH>"
	    "<TH COLSPAN=2>%s4>Data&nbsp;Received%s</A></TH></TR>\n",
	    theAnchor[1], arrow[1],
	    theAnchor[2], arrow[2], theAnchor[3], arrow[3],
	    theAnchor[4], arrow[4]);

    sendString(buf);

    for(idx=0; idx<numEntries; idx++) {
      if(revertOrder)
	el = tmpTable[numEntries-idx-1];
      else
	el = tmpTable[idx];

      if(el != NULL) {
	char *tmpName1;
	tmpName1 = el->hostNumIpAddress;
	if((tmpName1[0] == '\0') || (strcmp(tmpName1, "0.0.0.0") == 0))
	  tmpName1 = separator;

	switch(remoteToLocal) {
	case REMOTE_TO_LOCAL_ACCOUNTING:
	  a = el->bytesSentLocally;
	  b = el->bytesReceivedLocally;
	  break;
	case LOCAL_TO_REMOTE_ACCOUNTING:
	  a = el->bytesSentRemotely;
	  b = el->bytesReceivedFromRemote;
	  break;
	case LOCAL_TO_LOCAL_ACCOUNTING:
	  a = el->bytesSentLocally;
	  b = el->bytesReceivedLocally;
	  break;
	}

	if(a < 100)  /* Avoid very small decimal values */
	  sentpct = 0;
	else
	  sentpct = (100*(float)a)/totalBytesSent;

	if(b < 100)  /* Avoid very small decimal values */
	  rcvdpct = 0;
	else
	  rcvdpct = (100*(float)b)/totalBytesReceived;

	snprintf(buf, sizeof(buf), "<TR %s>"
		"%s<TD ALIGN=RIGHT>%s</TD>"
		"</TD><TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%.1f%s%%</TD>"
		"<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%.1f%s%%</TD></TR>\n",
		getRowColor(),
		makeHostLink(el, LONG_FORMAT, 0, 0),
		tmpName1,
		formatBytes(a, 1),
		sentpct, separator,
		formatBytes(b, 1),
		rcvdpct, separator);
	sendString(buf);
      }

      /* Avoid huge tables */
      if(printedEntries++ > maxNumLines)
		break;
    }

    sendString("</TABLE>\n");
    sendString("<P><TABLE BORDER=1 WIDTH=\"100%%\">\n<TR>"
	       "<TH>Total Traffic</TH><TH>Data Sent</TH>\n"
	       "<TH>Data Received</TH><TH>Bandwidth</TH></TR>\n");

    totalBytes = totalBytesSent+totalBytesReceived;

    snprintf(buf, sizeof(buf), "<TR>"
	    "<TD ALIGN=RIGHT>%s</TD>"
	    "<TD ALIGN=RIGHT>%s</TD>"
	    "<TD ALIGN=RIGHT>%s</TD>"
	    "<TD ALIGN=RIGHT>%s</TD></TR>\n",
	    formatBytes(totalBytes, 1),
	    formatBytes(totalBytesSent, 1),
	    formatBytes(totalBytesReceived, 1),
	    formatThroughput((float)(totalBytes/timeDiff)));

    sendString(buf);
    sendString("</TABLE>\n");
  } else
    printNoDataYet();
}

/* ********************************** */

void printActiveTCPSessions(void) {
  int idx;
  char buf[BUF_SIZE];
  int numSessions;

  for(idx=1, numSessions=0; idx<HASHNAMESIZE; idx++)
    if((tcpSession[idx] != NULL)
#ifndef PRINT_ALL_ACTIVE_SESSIONS
       && (tcpSession[idx]->sessionState == STATE_ACTIVE)
#endif
       ) {

      char *sport, *dport;
      TrafficCounter dataSent, dataReceived;

      if(numSessions == 0) {
	sendString("<TABLE BORDER=1 WIDTH=\"100%%\"><TR>"
		   "<TH>Client</TH>"
		   "<TH>Server</TH>"
		   "<TH>Data&nbsp;Sent</TH>"
		   "<TH>Data&nbsp;Rcvd</TH>"
		   "<TH>Active&nbsp;Since</TH>"
		   "<TH>Last&nbsp;Seen</TH>"
		   "<TH>Duration</TH>"
#ifdef PRINT_ALL_ACTIVE_SESSIONS
		   "<TH>State</TH>"
#endif
		   "</TR>\n");
      }

      sport = getPortByNum(tcpSession[idx]->sport, IPPROTO_TCP);
      dport = getPortByNum(tcpSession[idx]->dport, IPPROTO_TCP);
      dataSent = tcpSession[idx]->bytesSent;
      dataReceived = tcpSession[idx]->bytesReceived;

      if(sport == NULL) {
	static char _sport[8];
	snprintf(_sport, 8, "%d", tcpSession[idx]->sport);
	sport = _sport;
      }

      if(dport == NULL) {
	static char _dport[8];
	snprintf(_dport, 8, "%d", tcpSession[idx]->dport);
	dport = _dport;
      }

      /* Sanity check */
      if((actTime < tcpSession[idx]->firstSeen)
	 || (tcpSession[idx]->firstSeen == 0))
	tcpSession[idx]->firstSeen = actTime;

      snprintf(buf, sizeof(buf), "<TR %s>"
	      "<TD ALIGN=RIGHT>%s:%s</TD>"
	      "<TD ALIGN=RIGHT>%s:%s</TD>"
	      "<TD ALIGN=RIGHT>%s</TD>"
	      "<TD ALIGN=RIGHT>%s</TD>"
	      "<TD ALIGN=RIGHT>%s</TD>"
	      "<TD ALIGN=RIGHT>%s</TD>"
	      "<TD ALIGN=RIGHT>%s</TD>"
#ifdef PRINT_ALL_ACTIVE_SESSIONS
	      "<TD ALIGN=CENTER>%s</TD>"
#endif
	      "</TR>\n",
	      getRowColor(),
	      makeHostLink(device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(tcpSession[idx]->initiatorIdx)], SHORT_FORMAT, 0, 0),
	      sport,
	      makeHostLink(device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(tcpSession[idx]->remotePeerIdx)], SHORT_FORMAT, 0, 0),
	      dport,
	      formatBytes(dataSent, 1),
	      formatBytes(dataReceived, 1),
	      formatTime(&(tcpSession[idx]->firstSeen), 1),
	      formatTime(&(tcpSession[idx]->lastSeen), 1),
	      formatSeconds(actTime-tcpSession[idx]->firstSeen)
#ifdef PRINT_ALL_ACTIVE_SESSIONS
	      , getSessionState(tcpSession[idx])
#endif
	      );

      sendString(buf);
      numSessions++;
    }

  if(numSessions > 0)
    sendString("</TABLE><P>\n");
  else
    sendString("<P><IMG SRC=/warning.gif><p><i>No Active TCP Sessions</i>\n");
}


/* ********************************** */

void printIpProtocolUsage(void) {
  HostTraffic *hosts[HASHNAMESIZE];
  u_short clientPorts[TOP_ASSIGNED_IP_PORTS], serverPorts[TOP_ASSIGNED_IP_PORTS];
  u_int i, j, idx1, hostsNum=0, numPorts=0;
  char buf[BUF_SIZE];

  memset(clientPorts, 0, sizeof(clientPorts));
  memset(serverPorts, 0, sizeof(serverPorts));

  for(i=0; i<device[actualDeviceId].actualHashSize; i++)
    if((device[actualReportDeviceId].hash_hostTraffic[i] != NULL)
       && subnetPseudoLocalHost(device[actualReportDeviceId].hash_hostTraffic[i])
       && (device[actualReportDeviceId].hash_hostTraffic[i]->hostNumIpAddress[0] != '\0')) {
      hosts[hostsNum++] = device[actualReportDeviceId].hash_hostTraffic[i];

      for(j=0; j<TOP_ASSIGNED_IP_PORTS; j++) {
	if(device[actualReportDeviceId].hash_hostTraffic[i]->portsUsage[j] != NULL)  {
	  clientPorts[j] += device[actualReportDeviceId].hash_hostTraffic[i]->portsUsage[j]->clientUses;
	  serverPorts[j] += device[actualReportDeviceId].hash_hostTraffic[i]->portsUsage[j]->serverUses;
	  numPorts++;
	}
      }
    }

  if(numPorts == 0) {
    printNoDataYet();
    return;
  }

  /* Hosts are now in a contiguous structure (hosts[])... */

  sendString("<TABLE BORDER=1><TR><TH COLSPAN=2>Service</TH>"
	     "<TH>Clients</TH><TH>Servers</TH>\n");

  for(j=0; j<TOP_ASSIGNED_IP_PORTS; j++)
    if((clientPorts[j] > 0) || (serverPorts[j] > 0)) {
      snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=CENTER>%d</TD>"
	      "<TD>\n", getRowColor(), getAllPortByNum(j), j);
      sendString(buf);

      if(clientPorts[j] > 0) {
	sendString("<UL>");
	for(idx1=0; idx1<hostsNum; idx1++)
	  if((hosts[idx1]->portsUsage[j] != NULL)
	     && (hosts[idx1]->portsUsage[j] != NULL) /* added 04.03.00 Ralf Amandi */
	     && (hosts[idx1]->portsUsage[j]->clientUses > 0)) {
	    snprintf(buf, sizeof(buf), "<li>%s\n", makeHostLink(hosts[idx1], SHORT_FORMAT, 1, 0));
	    sendString(buf);
	  }
	sendString("</UL>");
      } else
	sendString("&nbsp;");

      sendString("</TD><TD>");

      if(serverPorts[j] > 0) {
	sendString("<UL>");
	for(idx1=0; idx1<hostsNum; idx1++)
	  if((hosts[idx1]->portsUsage != NULL)
	     && (hosts[idx1]->portsUsage[j] != NULL) /* added 04.03.00 Ralf Amandi */
	     && (hosts[idx1]->portsUsage[j]->serverUses > 0)) {
	    snprintf(buf, sizeof(buf), "<li>%s\n", makeHostLink(hosts[idx1], SHORT_FORMAT, 1, 0));
	    sendString(buf);
	  }
	sendString("</UL>");
      } else
	sendString("&nbsp;");

      sendString("</TD></TR>");
    } /* for */

  sendString("</TABLE><P>\n");
}


/* ********************************** */

void printBar(char *buf, int bufLen, 
	      unsigned short percentage,
	      unsigned short maxPercentage,
	      unsigned short ratio) {
  int int_perc = (int)((100*percentage)/maxPercentage);

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
    snprintf(buf, bufLen, "<TD %s>&nbsp;</TD>\n", getActualRowColor());
    break;
  default:
    snprintf(buf, bufLen, "<TD ALIGN=LEFT><IMG ALIGN=ABSMIDDLE SRC=/gauge.jpg"
	    " WIDTH=%d HEIGHT=12>&nbsp;</TD>\n",
	    ratio*int_perc);
    break;
  }

  sendString(buf);
}


/* ********************************** */

#if 0
static void printShortTableEntry(char *buf, int bufLen,
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
    snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>%s</TD>"
	    "</TR>\n",
	    getRowColor(), label, formatKBytes(total));
    break;
  case 100:
    snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>%s</TD>"
	    "</TR>\n",
	    getRowColor(), label, formatKBytes(total));
    break;
  default:
    snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>%s</TD>"
	    "</TR>\n",
	    getRowColor(), label, formatKBytes(total));
  }

  sendString(buf);
}
#endif

/* ********************************** */

static void printTableEntry(char *buf, int bufLen,
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
    snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH>"
	    "<TD ALIGN=RIGHT>%s</TD>"
	    "<TD>&nbsp;</TD></TR>\n",
	    getRowColor(), label, formatKBytes(total));
    break;
  case 100:
    snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH>"
	    "<TD ALIGN=RIGHT>%s</TD>"
	    "<TD ALIGN=CENTER BGCOLOR=\"%s\">100%%</TD></TR>\n",
	    getRowColor(), label, formatKBytes(total), color);
    break;
  default:
    snprintf(buf, bufLen, "<TR %s><TH ALIGN=LEFT>%s</TH>"
	    "<TD ALIGN=RIGHT>%s</TD>"
	    "<TD><TABLE BORDER=\"0\" CELLPADDING=\"0\" CELLSPACING=\"0\" WIDTH=\"100%%\">"
	    "<TR><TD ALIGN=CENTER WIDTH=\"%d%%\" BGCOLOR=\"%s\">"
	    "<P>%.1f&nbsp;%%</TD><TD ALIGN=CENTER WIDTH=\"%d%%\" %s>"
	    "<P>&nbsp;</TD></TR></TABLE></TD></TR>\n",
	    getRowColor(), label, formatKBytes(total),
	    int_perc, color, percentage, (100-int_perc), getActualRowColor());
  }

  sendString(buf);
}

/* ********************************** */

void printIpProtocolDistribution(int mode, int revertOrder) {
  int i;
  char buf[2*BUF_SIZE], *sign;
  float total, partialTotal, remainingTraffic;
  float percentage;

  if(revertOrder)
    sign = "";
  else
    sign = "-";

 if(mode == SHORT_FORMAT) {
    sendString("<CENTER><P><H1>IP Protocol Distribution"
	       "</H1><br>\n");

#ifdef HAVE_GDCHART
    sendString("<IMG SRC=ipProtoDistribPie><p></CENTER>\n");
#endif

    sendString("<CENTER><P><H1>Local Traffic</H1><P>\n");

    total = (float)(device[actualReportDeviceId].tcpGlobalTrafficStats.local+
		    device[actualReportDeviceId].udpGlobalTrafficStats.local)/1024;
    if(total == 0)
      printNoDataYet();
    else {
      sendString("<TABLE BORDER=1 WIDTH=\"100%%\"><TR><TH WIDTH=20%%>IP&nbsp;Protocol</TH>"
		 "<TH WIDTH=10%%>Data</TH><TH WIDTH=70%%>Percentage</TH></TR>\n");
      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)device[actualReportDeviceId].tcpGlobalTrafficStats.local/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP", 
				"TCP", "UDP", total, percentage);

      for(i=0; i<numIpProtosToMonitor; i++) {
	partialTotal = (float)ipProtoStats[i].local/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), protoIPTrafficInfos[i], 
			  COLOR_1, partialTotal, percentage);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Prot.", 
			COLOR_1, remainingTraffic, percentage);
      }

      sendString("</TABLE><P>\n");
    }

    /* ********************************************************** */

    total = (float)(device[actualReportDeviceId].tcpGlobalTrafficStats.remote2local+
		    device[actualReportDeviceId].udpGlobalTrafficStats.remote2local)/1024;

    sendString("<H1>Remote to Local Traffic</H1><P>\n");

    if(total == 0)
      printNoDataYet();
    else {
      sendString("<TABLE BORDER=1 WIDTH=\"100%%\"><TR><TH WIDTH=20%%>IP&nbsp;Protocol</TH>"
		 "<TH WIDTH=10%%>Data</TH><TH WIDTH=70%%>Percentage</TH></TR>\n");

      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)device[actualReportDeviceId].tcpGlobalTrafficStats.remote2local/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP", 
				"TCP", "UDP", total, percentage);

      for(i=0; i<numIpProtosToMonitor; i++) {
	partialTotal = (float)ipProtoStats[i].remote2local/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), protoIPTrafficInfos[i],
			  COLOR_1, partialTotal, percentage);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Prot.",
			COLOR_1, remainingTraffic, percentage);
      }
      sendString("</TABLE>\n<P>\n");
    }

    /* ********************************************************** */

    sendString("<H1>Local to Remote Traffic</H1><P>\n");

    total = (float)(device[actualReportDeviceId].tcpGlobalTrafficStats.local2remote+
		    device[actualReportDeviceId].udpGlobalTrafficStats.local2remote)/1024;
    if(total == 0)
      printNoDataYet();
    else {
      sendString("<TABLE BORDER=1 WIDTH=\"100%%\"><TR><TH WIDTH=20%%>IP&nbsp;Protocol</TH>"
		 "<TH WIDTH=10%%>Data</TH><TH WIDTH=70%%>Percentage</TH></TR>\n");

      if(total == 0) total = 1; /* Avoids divisions by zero */
      remainingTraffic = 0;

      partialTotal = (float)device[actualReportDeviceId].tcpGlobalTrafficStats.local2remote/1024;
      percentage = ((float)(partialTotal*100))/((float)total);
      printTableEntryPercentage(buf, sizeof(buf), "TCP&nbsp;vs.&nbsp;UDP", 
				"TCP", "UDP", total, percentage);

      for(i=0; i<numIpProtosToMonitor; i++) {
	partialTotal = (float)ipProtoStats[i].local2remote/1024;

	if(partialTotal > 0) {
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), protoIPTrafficInfos[i], 
			  COLOR_1, partialTotal, percentage);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Prot.",
			COLOR_1, remainingTraffic, percentage);
      }
      sendString("</TABLE><P>\n");
    }

  } else {
    total = (float)device[actualReportDeviceId].ipBytes/1024; /* total is expressed in KBytes */

    sendString("<CENTER><P><H1>"
	       "Global IP Protocol Distribution"
	       "</H1><P>\n");

    if(total == 0)
      printNoDataYet();
    else {
      sendString("<TABLE BORDER=1 WIDTH=\"100%%\"><TR><TH WIDTH=20%%>"
		 "IP&nbsp;Protocol</TH>"
		 "<TH WIDTH=10%%>Data</TH><TH WIDTH=70%%>"
		 "Percentage</TH></TR>\n");

      remainingTraffic = 0;

      for(i=0; i<numIpProtosToMonitor; i++) {
	partialTotal  = (float)ipProtoStats[i].local+ipProtoStats[i].remote;
	partialTotal += (float)ipProtoStats[i].remote2local+ipProtoStats[i].local2remote;

	if(partialTotal > 0) {
	  partialTotal /= 1024;
	  remainingTraffic += partialTotal;
	  percentage = ((float)(partialTotal*100))/((float)total);
	  printTableEntry(buf, sizeof(buf), protoIPTrafficInfos[i], 
			  COLOR_1, partialTotal, percentage);
	}
      }

      if(total > remainingTraffic)
	remainingTraffic = total - remainingTraffic;
      else
	remainingTraffic = 0;

      if(remainingTraffic > 0) {
	percentage = ((float)(remainingTraffic*100))/((float)total);
	printTableEntry(buf, sizeof(buf), "Other&nbsp;TCP/UDP-based&nbsp;Prot.",
			COLOR_1, remainingTraffic, percentage);
      }

#ifdef HAVE_GDCHART
      sendString("<TR><TD COLSPAN=3 ALIGN=CENTER>"
		 "<IMG SRC=drawGlobalIpProtoDistribution.gif></TD></TR>\n");
#endif
      sendString("</TABLE><P>\n");
    }
  }
 sendString("</CENTER>");
}

/* ************************ */

void printProtoTraffic(void) {
  float total;
  char buf[BUF_SIZE];

  total = device[actualReportDeviceId].ethernetBytes/1024; /* total is expressed in KBytes */

  if(total == 0) {
    printNoDataYet();
    return;
  }

  sendString("<CENTER><P><H1>Global Protocol Distribution</H1><P>\n");
  sendString("<P><TABLE BORDER=1 WIDTH=\"100%%\"><TR><TH WIDTH=20%%>Protocol</TH>"
	     "<TH WIDTH=10%%>Data</TH><TH WIDTH=70%%>Percentage</TH></TR>\n");
  snprintf(buf, sizeof(buf), "<TH WIDTH=20%% ALIGN=LEFT>IP</TH><TD WIDTH=10%% ALIGN=RIGHT>%s"
	  "&nbsp;(%.1f%%)</TD><TD WIDTH=70%%>"
	  "<TABLE BORDER=1 WIDTH=\"100%%\">", formatBytes(device[actualReportDeviceId].ipBytes,
							  1),
	  100*((float)device[actualReportDeviceId].ipBytes/device[actualReportDeviceId].ethernetBytes));
  sendString(buf);

  printTableEntry(buf, sizeof(buf), "TCP", COLOR_1, 
		  (float)device[actualReportDeviceId].tcpBytes/1024,
		  100*((float)device[actualReportDeviceId].tcpBytes/device[actualReportDeviceId].ipBytes));
  printTableEntry(buf, sizeof(buf), "UDP", COLOR_1, 
		  (float)device[actualReportDeviceId].udpBytes/1024,
		  100*((float)device[actualReportDeviceId].udpBytes/device[actualReportDeviceId].ipBytes));
  printTableEntry(buf, sizeof(buf), "ICMP", COLOR_1, 
		  (float)device[actualReportDeviceId].icmpBytes/1024,
		  100*((float)device[actualReportDeviceId].icmpBytes/device[actualReportDeviceId].ipBytes));
  printTableEntry(buf, sizeof(buf), "Other&nbsp;IP", COLOR_1, 
		  (float)device[actualReportDeviceId].otherIpBytes/1024,
		  ((float)device[actualReportDeviceId].otherIpBytes/device[actualReportDeviceId].ipBytes));

  sendString("</TABLE></TR>");

  printTableEntry(buf, sizeof(buf), "(R)ARP", COLOR_1, 
		  (float)device[actualReportDeviceId].arpRarpBytes/1024,
		  100*((float)device[actualReportDeviceId].arpRarpBytes/device[actualReportDeviceId].ipBytes));
  printTableEntry(buf, sizeof(buf), "DLC", COLOR_1, 
		  (float)device[actualReportDeviceId].dlcBytes/1024,
		  100*((float)device[actualReportDeviceId].dlcBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "IPX", COLOR_1, 
		  (float)device[actualReportDeviceId].ipxBytes/1024,
		  100*((float)device[actualReportDeviceId].ipxBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "Decnet", COLOR_1, 
		  (float)device[actualReportDeviceId].decnetBytes/1024,
		  100*((float)device[actualReportDeviceId].decnetBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "AppleTalk", COLOR_1, 
		  (float)device[actualReportDeviceId].atalkBytes/1024,
		  100*((float)device[actualReportDeviceId].atalkBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "OSPF", COLOR_1, 
		  (float)device[actualReportDeviceId].ospfBytes/1024,
		  100*((float)device[actualReportDeviceId].ospfBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "NetBios", COLOR_1, 
		  (float)device[actualReportDeviceId].netbiosBytes/1024,
		  100*((float)device[actualReportDeviceId].netbiosBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "IGMP", COLOR_1, 
		  (float)device[actualReportDeviceId].igmpBytes/1024,
		  100*((float)device[actualReportDeviceId].igmpBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "OSI", COLOR_1, 
		  (float)device[actualReportDeviceId].osiBytes/1024,
		  100*((float)device[actualReportDeviceId].osiBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "QNX", COLOR_1, 
		  (float)device[actualReportDeviceId].qnxBytes/1024,
		  100*((float)device[actualReportDeviceId].qnxBytes/device[actualReportDeviceId].ethernetBytes));
  printTableEntry(buf, sizeof(buf), "Other", COLOR_1, 
		  (float)device[actualReportDeviceId].otherBytes/1024,
		  100*((float)device[actualReportDeviceId].otherBytes/device[actualReportDeviceId].ethernetBytes));

#ifdef HAVE_GDCHART
  sendString("<TR><TD COLSPAN=3 ALIGN=CENTER>"
	     "<IMG SRC=drawGlobalProtoDistribution.gif></TD></TR>\n");
#endif

  sendString("</TABLE><P></CENTER>\n");
}

/* ************************ */

void printProcessInfo(int processPid) {
  char buf[BUF_SIZE];
  int i, j, numEntries;

#ifdef MULTITHREADED
  accessMutex(&lsofMutex, "printLsofData");
#endif

  for(i=0; i<numProcesses; i++)
    if((processes[i] != NULL)
       && (processes[i]->pid == processPid))
      break;

  printHTTPheader();

  if(processes[i]->pid != processPid) {
    snprintf(buf, sizeof(buf), "<H1><CENTER>Unable to find process PID %d"
	    "<CENTER></H1><P>\n", processPid);
    sendString(buf);
#ifdef MULTITHREADED
    releaseMutex(&lsofMutex);
#endif
    return;
  }

  snprintf(buf, sizeof(buf), "<H1><CENTER>Info about process %s"
	  "<CENTER></H1><P>\n", processes[i]->command);
  sendString(buf);

  sendString("<TABLE BORDER=1>");

  snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>User&nbsp;Name</TH>", getRowColor());
  sendString(buf);
  snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT>%s</TD></TR>\n", processes[i]->user);
  sendString(buf);

  snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>Process&nbsp;PID</TH>", getRowColor());
  sendString(buf);
  snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT>%d</TD></TR>\n", processes[i]->pid);
  sendString(buf);

  snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>First&nbsp;Seen</TH>", getRowColor());
  sendString(buf);
  snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT>%s</TD></TR>\n",
	  formatTime(&processes[i]->firstSeen, 1));
  sendString(buf);

  snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>Last&nbsp;Seen</TH>", getRowColor());
  sendString(buf);
  snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT>%s</TD></TR>\n",
	  formatTime(&processes[i]->lastSeen, 1));
  sendString(buf);

  snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>Data&nbsp;Sent</TH>", getRowColor());
  sendString(buf);
  snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT>%s</TD></TR>\n",
	  formatBytes(processes[i]->bytesSent, 1));
  sendString(buf);

  snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>Data&nbsp;Rcvd</TH>", getRowColor());
  sendString(buf);
  snprintf(buf, sizeof(buf), "<TD ALIGN=RIGHT>%s</T></TR>\n",
	  formatBytes(processes[i]->bytesReceived, 1));
  sendString(buf);

  snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>Open&nbsp;TCP&nbsp;Ports"
	  "</TH><TD ALIGN=RIGHT>", getRowColor());
  sendString(buf);

  for(j=0; j<TOP_IP_PORT; j++)
    if(localPorts[j] != NULL) {
      ProcessInfoList *elem = localPorts[j];

      while(elem != NULL) {
	if(elem->element == processes[i]) {
	  snprintf(buf, sizeof(buf), "%d<BR>\n", j);
	  sendString(buf);
	  break;
	}
	elem = elem->next;
      }
    }

  sendString("</TD></TR>\n");

  for(j=0, numEntries=0; j<MAX_NUM_CONTACTED_PEERS; j++)
    if(processes[i]->contactedIpPeersIndexes[j] != NO_PEER) {

      if(numEntries == 0) {
	snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>Contacted&nbsp;Peers"
		"</TH><TD ALIGN=RIGHT>", getRowColor());
	sendString(buf);
      }

      snprintf(buf, sizeof(buf), "%s<BR>\n",
	      makeHostLink(device[actualReportDeviceId].hash_hostTraffic[checkSessionIdx(processes[i]->contactedIpPeersIndexes[j])],
			   0, 0, 0));
      sendString(buf);
      numEntries++;
    }

  sendString("</TD></TR>\n</TABLE></CENTER><P>\n");

#ifdef MULTITHREADED
  releaseMutex(&lsofMutex);
#endif
}

/* ************************ */

void printLsofData(int mode) {
  char buf[BUF_SIZE];
  int i, j, found;
  int numUsers;
  ProcessInfo *processesList[MAX_NUM_PROCESSES];
  UsersTraffic usersTraffic[256], *usersTrafficList[256];

  printHTTPheader();

  /* ************************ */

  sendString("<H1><CENTER>Local Network Usage by Process"
	     "</H1><P>\n");

  snprintf(buf, sizeof(buf), "<TABLE BORDER=1><TR>"
	  "<TH><A HREF=\"%s?1\">Process</A></TH>"
	  "<TH><A HREF=\"%s?2\">PID</A></TH>"
	  "<TH><A HREF=\"%s?3\">User</A></TH>"
	  "<TH><A HREF=\"%s?4\">Sent</A></TH>"
	  "<TH><A HREF=\"%s?5\">Rcvd</A></TH></TR>\n",
	  STR_LSOF_DATA, STR_LSOF_DATA, STR_LSOF_DATA,
	  STR_LSOF_DATA, STR_LSOF_DATA);
  sendString(buf);

#ifdef MULTITHREADED
  accessMutex(&lsofMutex, "buildHTMLBrowserWindowsLabel");
#endif

  memcpy(processesList, processes, sizeof(processes));
  columnSort = mode;
  quicksort(processesList, numProcesses, sizeof(ProcessInfo*), cmpProcesses);

  /* Avoid huge tables */
  if(numProcesses > maxNumLines)
    numProcesses = maxNumLines;

  for(i=0, numUsers=0; i<numProcesses; i++) {
    snprintf(buf, sizeof(buf), "<TR %s><TD><A HREF=\""PROCESS_INFO_HTML"?%d\">%s</A></TD>"
	    "<TD ALIGN=CENTER>%d</TD>"
	    "<TD ALIGN=CENTER>%s</TD>"
	    "<TD ALIGN=RIGHT>%s</TD>"
	    "<TD ALIGN=RIGHT>%s</TD></TR>\n",
	    getRowColor(),
	    processesList[i]->pid,
	    processesList[i]->command,
	    processesList[i]->pid,
	    processesList[i]->user,
	    formatBytes((TrafficCounter)processesList[i]->bytesSent, 1),
	    formatBytes((TrafficCounter)processesList[i]->bytesReceived, 1));
    sendString(buf);

    if((processesList[i]->bytesSent > 0) || (processesList[i]->bytesReceived > 0)) {
      for(j=0, found=0; j<numUsers; j++)
	if(strcmp(usersTraffic[j].userName, processesList[i]->user) == 0) {
	  found = 1;
	  break;
	}

      if(!found) {
	usersTraffic[numUsers].userName = processesList[i]->user;
	usersTrafficList[numUsers++] = &usersTraffic[numUsers];
	usersTraffic[j].bytesSent = usersTraffic[j].bytesReceived = 0;
      }

      usersTraffic[j].bytesSent     += processesList[i]->bytesSent;
      usersTraffic[j].bytesReceived += processesList[i]->bytesReceived;
    }
  }

  sendString("</TABLE><P>\n");

  /* ************************ */

  sendString("\n<P><H1>Local Network Usage by Port"
	     "</H1><P>\n");

  sendString("<TABLE BORDER=1><TR><TH>Port</TH><TH>Processes</TH></TR>\n");

  for(i=0; i<TOP_IP_PORT; i++)
    if(localPorts[i] != NULL) {
      ProcessInfoList *scanner;

      snprintf(buf, sizeof(buf), "<TR %s><TD ALIGN=CENTER>%d</TD><TD>", getRowColor(), i);
      sendString(buf);

      scanner = localPorts[i];

      while(scanner != NULL) {
	snprintf(buf, sizeof(buf), "<li><A HREF=\""PROCESS_INFO_HTML"?%d\">%s</A><BR>\n",
		scanner->element->pid, scanner->element->command);
	sendString(buf);
	scanner = scanner->next;
      }

      sendString("</TR>");
  }

  sendString("</TABLE><P></CENTER>\n\n");

  /* ******************************* */

  if(numUsers > 0) {
    quicksort(usersTrafficList, numUsers, sizeof(UsersTraffic**), cmpUsersTraffic);

    /* Avoid huge tables */
    if(numUsers > maxNumLines)
      numUsers = maxNumLines;

    sendString("<H1><CENTER>Local Network Usage by User"

	       "<CENTER></H1><P>\n");
    sendString("<TABLE BORDER=1><TR><TH>User</TH>"
	       "<TH>Traffic&nbsp;in/out</TH></TR>\n");

    for(i=0; i<numUsers; i++) {
      snprintf(buf, sizeof(buf), "<TR %s><TD>%s</TD>"
	      "<TD ALIGN=RIGHT>%s</TD></TR>\n",
	      getRowColor(),
	      usersTrafficList[i]->userName,
	      formatBytes((TrafficCounter)(usersTrafficList[i]->bytesSent+
			  usersTrafficList[i]->bytesReceived), 1));
      sendString(buf);
    }

    sendString("</TABLE><P></CENTER>\n");
  }

#ifdef MULTITHREADED
  releaseMutex(&lsofMutex);
#endif
}


/* ************************ */

static char* buildHTMLBrowserWindowsLabel(int i, int j) {
  static char buf[BUF_SIZE];

#ifdef MULTITHREADED
  accessMutex(&addressResolutionMutex, "buildHTMLBrowserWindowsLabel");
#endif

  if((ipTrafficMatrix[i][j].bytesSent == 0)
     && (ipTrafficMatrix[i][j].bytesReceived == 0))
    buf[0]='\0';
  else if ((ipTrafficMatrix[i][j].bytesSent > 0) 
	   && (ipTrafficMatrix[i][j].bytesReceived == 0))
    snprintf(buf, sizeof(buf), "(%s->%s)=%s", ipTrafficMatrixHosts[i]->hostSymIpAddress, 
	     ipTrafficMatrixHosts[j]->hostSymIpAddress, 
	     formatBytes(ipTrafficMatrix[i][j].bytesSent, 1));
  else if ((ipTrafficMatrix[i][j].bytesSent == 0) 
	   &&  (ipTrafficMatrix[i][j].bytesReceived > 0))
    snprintf(buf, sizeof(buf), "(%s->%s)=%s", ipTrafficMatrixHosts[j]->hostSymIpAddress, 
	     ipTrafficMatrixHosts[i]->hostSymIpAddress, 
	     formatBytes(ipTrafficMatrix[i][j].bytesReceived, 1));
  else
    snprintf(buf, sizeof(buf), "(%s->%s)=%s, (%s->%s)=%s",
	     ipTrafficMatrixHosts[i]->hostSymIpAddress, 
	     ipTrafficMatrixHosts[j]->hostSymIpAddress, 
	     formatBytes(ipTrafficMatrix[i][j].bytesSent, 1),
	     ipTrafficMatrixHosts[j]->hostSymIpAddress, 
	     ipTrafficMatrixHosts[i]->hostSymIpAddress, 
	     formatBytes(ipTrafficMatrix[i][j].bytesReceived, 1));

#ifdef MULTITHREADED
  releaseMutex(&addressResolutionMutex);
#endif

  return(buf);
}

/* ************************ */

void printIpTrafficMatrix(void) {
  int i, j, numEntries=0, numConsecutiveEmptyCells;
  char buf[BUF_SIZE];
  short activeHosts[256];
  TrafficCounter minTraffic=(TrafficCounter)LONG_MAX, maxTraffic=0, avgTraffic;
  TrafficCounter avgTrafficLow, avgTrafficHigh, tmpCounter;

  for(i=1; i<255; i++) {
    activeHosts[i] = 0;
    for(j=1; j<255; j++) {
      if((ipTrafficMatrix[i][j].bytesSent != 0)
	 || (ipTrafficMatrix[i][j].bytesReceived != 0)) {
	activeHosts[i] = 1;
	numEntries++;
	break;
      }
    }

    if(activeHosts[i] == 1) {
      if(numEntries == 1)
	sendString("<TABLE BORDER=1><TR><TH ALIGN=LEFT><SMALL>&nbsp;F&nbsp;"
		   "&nbsp;&nbsp;To<br>&nbsp;r<br>&nbsp;o<br>&nbsp;m</SMALL></TH>\n");

      snprintf(buf, sizeof(buf), "<TH ALIGN=CENTER><SMALL>%s</SMALL></TH>",
	      getHostName(ipTrafficMatrixHosts[i], 1));
      sendString(buf);
    }
  }

  if(numEntries == 0) {
    printNoDataYet();
    return;
  } else
    sendString("</TR>\n");

  for(i=1; i<255; i++)
    for(j=1; j<255; j++)
      if((ipTrafficMatrix[i][j].bytesSent != 0)
	 || (ipTrafficMatrix[i][j].bytesReceived != 0)) {
	if(minTraffic > ipTrafficMatrix[i][j].bytesSent)
	  minTraffic = ipTrafficMatrix[i][j].bytesSent;
	if(minTraffic > ipTrafficMatrix[i][j].bytesReceived)
	  minTraffic = ipTrafficMatrix[i][j].bytesReceived;
	if(maxTraffic < ipTrafficMatrix[i][j].bytesSent)
	  maxTraffic = ipTrafficMatrix[i][j].bytesSent;
	if(maxTraffic < ipTrafficMatrix[i][j].bytesReceived)
	  maxTraffic = ipTrafficMatrix[i][j].bytesReceived;
      }

  avgTraffic = (TrafficCounter)(((float)minTraffic+(float)maxTraffic)/2);
  avgTrafficLow  = (avgTraffic*15)/100; /* 15% of the average */
  avgTrafficHigh = 2*(maxTraffic/3);   /* 75% of max traffic */


  for(i=1; i<255; i++)
    if(activeHosts[i] == 1) {
      numConsecutiveEmptyCells=0;

      snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT><SMALL>%s</SMALL></TH>",
	      getRowColor(), makeHostLink(ipTrafficMatrixHosts[i], SHORT_FORMAT, 1, 0));
      sendString(buf);

      for(j=1; j<255; j++) {
	if((i == j) && strcmp(ipTrafficMatrixHosts[i]->hostNumIpAddress, "127.0.0.1"))
	  numConsecutiveEmptyCells++;
	else if(activeHosts[j] == 1) {
	  if((ipTrafficMatrix[i][j].bytesReceived == 0) && (ipTrafficMatrix[i][j].bytesSent == 0))
	    numConsecutiveEmptyCells++;
	  else {
	    if(numConsecutiveEmptyCells > 0) {
	      snprintf(buf, sizeof(buf), "<TD COLSPAN=%d>&nbsp;</TD>\n", numConsecutiveEmptyCells);
	      sendString(buf);
	      numConsecutiveEmptyCells = 0;
	    }

	    tmpCounter = ipTrafficMatrix[i][j].bytesSent+ipTrafficMatrix[i][j].bytesReceived;
	    /* Fix below courtesy of Danijel Doriae <danijel.doric@industrogradnja.tel.hr> */
	    snprintf(buf, sizeof(buf), "<TD ALIGN=CENTER %s><A HREF=# onMouseOver=\"window.status='"
		    "%s';return true\" onMouseOut="
		    "\"window.status='';return true\"><SMALL>%s</SMALL></A></TH>\n",
		    calculateCellColor(tmpCounter, avgTrafficLow, avgTrafficHigh),
		    buildHTMLBrowserWindowsLabel(i, j),
		    formatBytes(tmpCounter, 1));
	    sendString(buf);
	  }
	}
      }

      if(numConsecutiveEmptyCells > 0) {
	snprintf(buf, sizeof(buf), "<TD COLSPAN=%d>&nbsp;</TD>\n", numConsecutiveEmptyCells);
	sendString(buf);
	numConsecutiveEmptyCells = 0;
      }

      sendString("</TR>\n");
    }

  sendString("</TABLE>\n<P>\n");
}

/* ************************ */

void printThptStatsMatrix(int sortedColumn) {
  int i, ratio=1;
  char label[32], label1[32], buf[BUF_SIZE];
  time_t tmpTime;
  struct tm t;

  printHTTPheader();
  sendString("<CENTER><P><H1>Throughput Statistics Matrix</H1><P>\n");

  switch(sortedColumn) {
  case 1:
    sendString("<TABLE BORDER=1>\n<TR>"
	       "<TH>Sampling Period</TH>"
	       "<TH>Average Thpt</TH>"
	       "<TH>Top Hosts Sent Thpt</TH>"
	       "<TH>Top Hosts Rcvd Thpt</TH></TR>\n");

    for(i=0; i<60; i++) {
      if(device[actualReportDeviceId].last60MinutesThpt[i].trafficValue == 0)
	break;

      tmpTime = actTime-(i*60);
      strftime(label, 32, "%H:%M", localtime_r(&tmpTime, &t));
      tmpTime = actTime-((i+1)*60);
      strftime(label1, 32, "%H:%M", localtime_r(&tmpTime, &t));
      snprintf(buf, sizeof(buf), "<TR %s><TD ALIGN=CENTER><B>%s&nbsp;-&nbsp;%s</B></TH>"
	      "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=LEFT><TABLE BORDER=1 WIDTH=100%%>",
	      getRowColor(), label1, label,
	      formatThroughput(device[actualReportDeviceId].last60MinutesThpt[i].trafficValue/ratio));
      sendString(buf);

      if(device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].last60MinutesThpt[i].topHostSentIdx] != NULL) {
	snprintf(buf, sizeof(buf), "<TR>%s<TD ALIGN=RIGHT>%s</TD>\n",
		makeHostLink(device[actualReportDeviceId].
			     hash_hostTraffic[device[actualReportDeviceId].
					     last60MinutesThpt[i].topHostSentIdx],
			     LONG_FORMAT, 0, 0),
		formatThroughput(device[actualReportDeviceId].last60MinutesThpt[i].topSentTraffic/ratio));
	sendString(buf);

	if(device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
							last60MinutesThpt[i].secondHostSentIdx] != NULL) {
	  snprintf(buf, sizeof(buf), "<TR>%s<TD ALIGN=RIGHT>%s</TD>\n",
		  makeHostLink(device[actualReportDeviceId].
			       hash_hostTraffic[device[actualReportDeviceId].
					       last60MinutesThpt[i].secondHostSentIdx],
			       LONG_FORMAT, 0, 0),
		  formatThroughput(device[actualReportDeviceId].
				   last60MinutesThpt[i].secondSentTraffic/ratio));
	  sendString(buf);
	}

	if(device[actualReportDeviceId].
	   hash_hostTraffic[device[actualReportDeviceId].last60MinutesThpt[i].
			   thirdHostSentIdx] != NULL) {
	  snprintf(buf, sizeof(buf), "<TR>%s<TD ALIGN=RIGHT>%s</TD>\n",
		  makeHostLink(device[actualReportDeviceId].
			       hash_hostTraffic[device[actualReportDeviceId].
					       last60MinutesThpt[i].thirdHostSentIdx],
			       LONG_FORMAT, 0, 0),
		  formatThroughput(device[actualReportDeviceId].
				   last60MinutesThpt[i].thirdSentTraffic/ratio));
	  sendString(buf);
	}
      } else
	sendString("&nbsp;");

      sendString("</TABLE></TD><TD ALIGN=LEFT><TABLE BORDER=1 WIDTH=100%%>\n");

      /* *************************************** */

      if(device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
						      last60MinutesThpt[i].topHostRcvdIdx] != NULL) {
	snprintf(buf, sizeof(buf), "<TR>%s<TD ALIGN=RIGHT>%s</TD>\n",
		 makeHostLink(device[actualReportDeviceId].
			      hash_hostTraffic[device[actualReportDeviceId].
					     last60MinutesThpt[i].topHostRcvdIdx],
			      LONG_FORMAT, 0, 0),
		formatThroughput(device[actualReportDeviceId].
				 last60MinutesThpt[i].topRcvdTraffic/ratio));
	sendString(buf);

	if(device[actualReportDeviceId].
	   hash_hostTraffic[device[actualReportDeviceId].
			   last60MinutesThpt[i].secondHostRcvdIdx] != NULL) {
	  snprintf(buf, sizeof(buf), "<TR>%s<TD ALIGN=RIGHT>%s</TD>\n",
		  makeHostLink(device[actualReportDeviceId].
			       hash_hostTraffic[device[actualReportDeviceId].
					       last60MinutesThpt[i].secondHostRcvdIdx],
			       LONG_FORMAT, 0, 0),
		  formatThroughput(device[actualReportDeviceId].
				   last60MinutesThpt[i].secondRcvdTraffic/ratio));
	  sendString(buf);
	}

	if(device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
							last60MinutesThpt[i].thirdHostRcvdIdx] != NULL) {
	  snprintf(buf, sizeof(buf), "<TR>%s<TD ALIGN=RIGHT>%s</TD>\n",
		  makeHostLink(device[actualReportDeviceId].
			       hash_hostTraffic[device[actualReportDeviceId].
					       last60MinutesThpt[i].thirdHostRcvdIdx],
			       LONG_FORMAT, 0, 0),
		    formatThroughput(device[actualReportDeviceId].
				     last60MinutesThpt[i].thirdRcvdTraffic/ratio));
	  sendString(buf);
	}
      } else
	sendString("&nbsp;");

      sendString("</TABLE></TD></TR>\n");
    }
    break;
  case 2:
  default:
    if(device[actualReportDeviceId].numThptSamples < 60) {
      printNoDataYet();
      return;
    } else {
      sendString("<TABLE BORDER=1>\n<TR>"
		 "<TH>Sampling Period</TH>"
		 "<TH>Average Thpt</TH>"
		 "<TH>Top Thpt Sent Hosts</TH>"
		 "<TH>Top Rcvd Sent Hosts</TH>"
		 "</TR>\n");

      for(i=0; i<24; i++) {
	if(device[actualReportDeviceId].last24HoursThpt[i].trafficValue == 0)
	  break;

	tmpTime = actTime-(i*60*60);
	strftime(label, 32, "%H:%M", localtime_r(&tmpTime, &t));
	tmpTime = actTime-((i+1)*60*60);
	strftime(label1, 32, "%H:%M", localtime_r(&tmpTime, &t));
	snprintf(buf, sizeof(buf), "<TR %s><TD ALIGN=CENTER><B>%s&nbsp;-&nbsp;%s</B></TH>"
		"<TD ALIGN=RIGHT>%s</TD><TD ALIGN=LEFT><TABLE BORDER=1>",
		getRowColor(), label, label1,
		formatThroughput(device[actualReportDeviceId].last24HoursThpt[i].trafficValue/ratio));
	sendString(buf);

	if(device[actualReportDeviceId].
	   hash_hostTraffic[device[actualReportDeviceId].
			   last24HoursThpt[i].topHostSentIdx] != NULL) {
	  snprintf(buf, sizeof(buf), "<TR>%s<TD ALIGN=RIGHT>%s</TD>\n",
		  makeHostLink(device[actualReportDeviceId].
			       hash_hostTraffic[device[actualReportDeviceId].
					       last24HoursThpt[i].topHostSentIdx],
			       LONG_FORMAT, 0, 0),
		  formatThroughput(device[actualReportDeviceId].
				   last24HoursThpt[i].topSentTraffic/ratio));
	  sendString(buf);

	  if(device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
							  last24HoursThpt[i].secondHostSentIdx] != NULL) {
	    snprintf(buf, sizeof(buf), "<TR>%s<TD ALIGN=RIGHT>%s</TD>\n",
		    makeHostLink(device[actualReportDeviceId].
				 hash_hostTraffic[device[actualReportDeviceId].
						 last24HoursThpt[i].secondHostSentIdx],
				 LONG_FORMAT, 0, 0),
		    formatThroughput(device[actualReportDeviceId].
				     last24HoursThpt[i].secondSentTraffic/ratio));
	    sendString(buf);
	  }

	  if(device[actualReportDeviceId].
	     hash_hostTraffic[device[actualReportDeviceId].last24HoursThpt[i].thirdHostSentIdx] != NULL) {
	    snprintf(buf, sizeof(buf), "<TR>%s<TD ALIGN=RIGHT>%s</TD>\n",
		    makeHostLink(device[actualReportDeviceId].
				 hash_hostTraffic[device[actualReportDeviceId].
						 last24HoursThpt[i].thirdHostSentIdx],
				 LONG_FORMAT, 0, 0),
		    formatThroughput(device[actualReportDeviceId].
				     last24HoursThpt[i].thirdSentTraffic/ratio));
	    sendString(buf);
	  }
	}

	sendString("</TABLE></TD><TD ALIGN=LEFT><TABLE BORDER=1>\n");

	/* *************************************** */

	if(device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
							last24HoursThpt[i].topHostRcvdIdx] != NULL) {
	  snprintf(buf, sizeof(buf), "<TR>%s<TD ALIGN=RIGHT>%s</TD>\n",
		  makeHostLink(device[actualReportDeviceId].
			       hash_hostTraffic[device[actualReportDeviceId].
					       last24HoursThpt[i].topHostRcvdIdx],
			       LONG_FORMAT, 0, 0),
		  formatThroughput(device[actualReportDeviceId].
				   last24HoursThpt[i].topRcvdTraffic/ratio));
	  sendString(buf);

	  if(device[actualReportDeviceId].
	     hash_hostTraffic[device[actualReportDeviceId].
			     last24HoursThpt[i].secondHostRcvdIdx] != NULL) {
	    snprintf(buf, sizeof(buf), "<TR>%s<TD ALIGN=RIGHT>%s</TD>\n",
		    makeHostLink(device[actualReportDeviceId].
				 hash_hostTraffic[device[actualReportDeviceId].
						 last24HoursThpt[i].secondHostRcvdIdx],
				 LONG_FORMAT, 0, 0),
		    formatThroughput(device[actualReportDeviceId].
				     last24HoursThpt[i].secondRcvdTraffic/ratio));
	    sendString(buf);
	  }

	  if(device[actualReportDeviceId].hash_hostTraffic[device[actualReportDeviceId].
							  last24HoursThpt[i].thirdHostRcvdIdx] != NULL) {
	    snprintf(buf, sizeof(buf), "<TR>%s<TD ALIGN=RIGHT>%s</TD>\n",
		    makeHostLink(device[actualReportDeviceId].
				 hash_hostTraffic[device[actualReportDeviceId].
						 last24HoursThpt[i].thirdHostRcvdIdx],
				 LONG_FORMAT, 0, 0),
		    formatThroughput(device[actualReportDeviceId].
				     last24HoursThpt[i].thirdRcvdTraffic/ratio));
	    sendString(buf);
	  }

	  sendString("</TABLE></TD></TR>\n");
	}
      }
    }
    break;
  }

  sendString("</TABLE>\n");
}

/* ************************ */

void printThptStats(int sortedColumn _UNUSED_) {
  char tmpBuf[128];

  printHTTPheader();
  sendString("<CENTER><P><H1>Throughput Statistics</H1><P>\n");

  if(device[actualReportDeviceId].numThptSamples == 0) {
    printNoDataYet();
    return;
  }

#ifdef HAVE_GDCHART
   sendString("<A HREF=\"thptStatsMatrix.html?1\" BORDER=0>"
	      "<IMG SRC=\"thptGraph?1\"></A><BR>\n");
   snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4>",
	   formatTimeStamp(0, 0, 0),
	   formatTimeStamp(0, 0, 60));
#else
   sendString("<A HREF=\"thptStatsMatrix.html?1\" BORDER=0>");
   snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4></A><BR>",
	   formatTimeStamp(0, 0, 0),
	   formatTimeStamp(0, 0, 60));

#endif

   sendString(tmpBuf);

  if(device[actualReportDeviceId].numThptSamples > 60) {
#ifdef HAVE_GDCHART
    sendString("<P><A HREF=\"thptStatsMatrix.html?2\" BORDER=0>"
	       "<IMG SRC=\"thptGraph?2\"></A><BR>\n");
    snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4>",
	    formatTimeStamp(0, 0, 0),
	    formatTimeStamp(0, 24, 0));
#else
    sendString("<P><A HREF=\"thptStatsMatrix.html?2\" BORDER=0>");
    snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4></A><BR>",
	    formatTimeStamp(0, 0, 0),
	    formatTimeStamp(0, 24, 0));
#endif

    sendString(tmpBuf);

#ifdef HAVE_GDCHART
    if(device[actualReportDeviceId].numThptSamples > 1440 /* 60 * 24 */) {
      sendString("<P><IMG SRC=\"thptGraph?3\"><BR>\n");
      snprintf(tmpBuf, sizeof(tmpBuf), "<H4>Time [ %s - %s]</H4>",
	      formatTimeStamp(0, 0, 0),
	      formatTimeStamp(30, 0, 0));
      sendString(tmpBuf);
    }
#endif
  }
}

/* ************************ */

static int cmpStatsFctn(const void *_a, const void *_b) {
  DomainStats *a = (DomainStats *)_a;
  DomainStats *b = (DomainStats *)_b;
  TrafficCounter a_, b_;
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
  case 1:
    rc = strcasecmp(a->domainHost->dotDomainName, b->domainHost->dotDomainName);
    if(rc == 0)
      return(strcasecmp(a->domainHost->fullDomainName, b->domainHost->fullDomainName));
    else
      return rc;
  case 2: a_  = a->bytesSent, b_ = b->bytesSent; break;
  case 3: a_  = a->bytesRcvd, b_ = b->bytesRcvd; break;
  case 4: a_  = a->tcpSent  , b_ = b->tcpSent;   break;
  case 5: a_  = a->tcpRcvd  , b_ = b->tcpRcvd;   break;
  case 6: a_  = a->udpSent  , b_ = b->udpSent;   break;
  case 7: a_  = a->udpRcvd  , b_ = b->udpRcvd;   break;
  case 8: a_  = a->icmpSent , b_ = b->icmpSent;  break;
  case 9: a_  = a->icmpRcvd , b_ = b->icmpRcvd;  break;
  case 10: a_ = a->ospfSent , b_ = b->ospfSent;  break;
  case 11: a_ = a->ospfRcvd , b_ = b->ospfRcvd;  break;
  case 12: a_ = a->igmpSent , b_ = b->igmpSent;  break;
  case 13: a_ = a->igmpRcvd , b_ = b->igmpRcvd;  break;
  default:
  case 0:
    if(domainSort)
      return(strcasecmp(a->domainHost->fullDomainName, b->domainHost->fullDomainName));
    else {
#ifdef MULTITHREADED
      accessMutex(&addressResolutionMutex, "fillDomainName");
#endif
      rc = strcasecmp(a->domainHost->hostSymIpAddress, b->domainHost->hostSymIpAddress);
#ifdef MULTITHREADED
      releaseMutex(&addressResolutionMutex);
#endif
}

    return(rc);
  }

  if(a_ < b_)
    return(1);
  else if (a_ > b_)
    return(-1);
  else
    return(0);
}

/* ************************ */

/* if domainName == NULL -> print all domains */
void printDomainStats(char* domainName, int sortedColumn, int revertOrder) {
  u_int idx, tmpIdx, numEntries=0;
  u_short keyValue=0;
  HostTraffic *el;
  char buf[BUF_SIZE];
  DomainStats *stats[HASHNAMESIZE], tmpStats[HASHNAMESIZE], *statsEntry;
  char htmlAnchor[128], htmlAnchor1[128], *sign, *arrowGif, *arrow[48], *theAnchor[48];
  TrafficCounter totBytesSent=0, totBytesRcvd=0;

  /* traceEvent(TRACE_INFO, "'%s' '%d' '%d'\n", domainName, sortedColumn, revertOrder); */

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;<IMG SRC=arrow_up.gif BORDER=0>";
  } else {
    sign = "-";
    arrowGif = "&nbsp;<IMG SRC=arrow_down.gif BORDER=0>";
  }

  memset(stats, 0, sizeof(stats));

  if(domainName == NULL)
    domainSort = 1;
  else
    domainSort = 0;

  for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++) {
    if((el = device[actualReportDeviceId].hash_hostTraffic[idx]) == NULL)
      continue;
    else
      fillDomainName(el);

    if((el->fullDomainName == NULL)
       || (el->fullDomainName[0] == '\0')
       || (el->dotDomainName == NULL)
       || (el->dotDomainName == '\0'))
      continue;
    else if((domainName != NULL)
	    && (strcmp(el->fullDomainName, domainName) != 0))
      continue;

    if(domainName == NULL) {
      for(keyValue=0, tmpIdx=0; el->fullDomainName[tmpIdx] != '\0'; tmpIdx++)
	keyValue += (tmpIdx+1)*(u_short)el->fullDomainName[tmpIdx];

      keyValue %= device[actualDeviceId].actualHashSize;

      while((stats[keyValue] != NULL)
	    && (strcasecmp(stats[keyValue]->domainHost->fullDomainName, el->fullDomainName) != 0))
	keyValue = (keyValue+1) % device[actualDeviceId].actualHashSize;

      if(stats[keyValue] != NULL)
	statsEntry = stats[keyValue];
      else {
	statsEntry = &tmpStats[numEntries++];
	memset(statsEntry, 0, sizeof(DomainStats));
	statsEntry->domainHost = el;
	stats[keyValue] = statsEntry;
	/* traceEvent(TRACE_INFO, "[%d] %s/%s\n", numEntries, el->fullDomainName, el->dotDomainName); */
      }
    } else {
      statsEntry = &tmpStats[numEntries++];
      memset(statsEntry, 0, sizeof(DomainStats));
      statsEntry->domainHost = el;
      stats[keyValue++] = statsEntry;
    }

    totBytesSent          += el->bytesSent;
    statsEntry->bytesSent += el->bytesSent;
    statsEntry->bytesRcvd += el->bytesReceived;
    totBytesRcvd          += el->bytesReceived;
    statsEntry->tcpSent   += el->tcpSentLocally + el->tcpSentRemotely;
    statsEntry->udpSent   += el->udpSentLocally + el->udpSentRemotely;
    statsEntry->icmpSent  += el->icmpSent;
    statsEntry->ospfSent  += el->ospfSent;
    statsEntry->igmpSent  += el->igmpSent;
    statsEntry->tcpRcvd   += el->tcpReceivedLocally + el->tcpReceivedFromRemote;
    statsEntry->udpRcvd   += el->udpReceivedLocally + el->udpReceivedFromRemote;
    statsEntry->icmpRcvd  += el->icmpReceived;
    statsEntry->ospfRcvd  += el->ospfReceived;
    statsEntry->igmpRcvd  += el->igmpReceived;
  } /* for(;;) */

  printHTTPheader();

  if(numEntries == 0) {
    sendString("<CENTER><P><H1>Internet Domain Stats</H1><P>\n");
    printNoDataYet();
    return;
  }

  columnSort = sortedColumn;

  quicksort(tmpStats, numEntries, sizeof(DomainStats), cmpStatsFctn);

  /* avoid division by zero */
  if(totBytesSent == 0)
    totBytesSent = 1;
  if(totBytesRcvd == 0)
    totBytesRcvd = 1;

  if(domainName == NULL) {
    sendString("<CENTER><P><H1>Internet Domain Stats</H1><P>\n");
    snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", STR_DOMAIN_STATS, sign);
    snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", STR_DOMAIN_STATS);
 } else {
    snprintf(buf, sizeof(buf), "<CENTER><P><H1>Stats for "
	    "Domain %s</H1><P>\n", domainName);
    sendString(buf);
    snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s_%s.html?%s", DOMAIN_INFO_HTML, domainName, sign);
    snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s_%s.html?", DOMAIN_INFO_HTML, domainName);
  }

  if(abs(columnSort) == 0) {
    arrow[0] = arrowGif;
    theAnchor[0] = htmlAnchor;
  } else {
    arrow[0] = "";
    theAnchor[0] = htmlAnchor1;
  }

  if(abs(columnSort) == 1) {
    arrow[1] = arrowGif;
    theAnchor[1] = htmlAnchor;
  } else {
    arrow[1] = "";
    theAnchor[1] = htmlAnchor1;
  }

  if(abs(columnSort) == 2) {
    arrow[2] = arrowGif;
    theAnchor[2] = htmlAnchor;
  } else {
    arrow[2] = "";
    theAnchor[2] = htmlAnchor1;
  }

  if(abs(columnSort) == 3) {
    arrow[3] = arrowGif;
    theAnchor[3] = htmlAnchor;
  } else {
    arrow[3] = "";
    theAnchor[3] = htmlAnchor1;
  }

  if(abs(columnSort) == 4) {
    arrow[4] = arrowGif;
    theAnchor[4] = htmlAnchor;
  } else {
    arrow[4] = "";
    theAnchor[4] = htmlAnchor1;
  }

  if(abs(columnSort) == 5) {
    arrow[5] = arrowGif;
    theAnchor[5] = htmlAnchor;
  } else {
    arrow[5] = "";
    theAnchor[5] = htmlAnchor1;
  }

  if(abs(columnSort) == 6) {
    arrow[6] = arrowGif;
    theAnchor[6] = htmlAnchor;
  } else {
    arrow[6] = "";
    theAnchor[6] = htmlAnchor1;
  }

  if(abs(columnSort) == 7) {
    arrow[7] = arrowGif;
    theAnchor[7] = htmlAnchor;
  } else {
    arrow[7] = "";
    theAnchor[7] = htmlAnchor1;
  }

  if(abs(columnSort) == 8) {
    arrow[8] = arrowGif;
    theAnchor[8] = htmlAnchor;
  } else {
    arrow[8] = "";
    theAnchor[8] = htmlAnchor1;
  }

  if(abs(columnSort) == 9) {
    arrow[9] = arrowGif;
    theAnchor[9] = htmlAnchor;
  } else {
    arrow[9] = "";
    theAnchor[9] = htmlAnchor1;
  }

  if(abs(columnSort) == 10) {
    arrow[10] = arrowGif;
    theAnchor[10] = htmlAnchor;
  } else {
    arrow[10] = "";
    theAnchor[10] = htmlAnchor1;
  }

  if(abs(columnSort) == 11) {
    arrow[11] = arrowGif;
    theAnchor[11] = htmlAnchor;
  } else {
    arrow[11] = "";
    theAnchor[11] = htmlAnchor1;
  }

  if(abs(columnSort) == 12) {
    arrow[12] = arrowGif;
    theAnchor[12] = htmlAnchor;
  } else {
    arrow[12] = "";
    theAnchor[12] = htmlAnchor1;
  }

  if(abs(columnSort) == 13) {
    arrow[13] = arrowGif;
    theAnchor[13] = htmlAnchor;
  } else {
    arrow[13] = "";
    theAnchor[13] = htmlAnchor1;
  }

  if(abs(columnSort) == 14) {
    arrow[14] = arrowGif;
    theAnchor[14] = htmlAnchor;
  } else {
    arrow[14] = "";
    theAnchor[14] = htmlAnchor1;
  }

  /* Split below courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */
  snprintf(buf, sizeof(buf),
          "<TABLE BORDER=1><TR>"
          "<TH>%s0>Name%s</A>"
          "<TH>%s1>Domain%s</A>"
          "<TH COLSPAN=2>%s2>Sent%s</A></TH>"
          "<TH COLSPAN=2>%s3>Rcvd%s</A></TH>"
          "<TH>%s4>TCP&nbsp;Sent%s</A></TH>",
          theAnchor[0], arrow[0],
          theAnchor[1], arrow[1],
          theAnchor[2], arrow[2],
          theAnchor[3], arrow[3],
          theAnchor[4], arrow[4]);
  sendString(buf);

  snprintf(buf, sizeof(buf),
          "<TH>%s5>TCP&nbsp;Rcvd%s</A></TH>"
          "<TH>%s6>UDP&nbsp;Sent%s</A></TH>"
          "<TH>%s7>UDP&nbsp;Rcvd%s</A></TH>"
          "<TH>%s8>ICMP&nbsp;Sent%s</A></TH>"
          "<TH>%s9>ICMP&nbsp;Rcvd%s</A></TH>",
          theAnchor[5], arrow[5],
          theAnchor[6], arrow[6],
          theAnchor[7], arrow[7],
          theAnchor[8], arrow[8],
          theAnchor[9], arrow[9]);
  sendString(buf);

  snprintf(buf, sizeof(buf),
          "<TH>%s10>OSPF&nbsp;Sent%s</A></TH>"
          "<TH>%s11>OSP&nbsp;Rcvd%s</A></TH>"
          "<TH>%s12>IGMP&nbsp;Sent%s</A></TH>"
          "<TH>%s13>IGMP&nbsp;Rcvd%s</A></TH>"
          "</TR>\n",
          theAnchor[10], arrow[10],
          theAnchor[11], arrow[11],
          theAnchor[12], arrow[12],
          theAnchor[13], arrow[13]);

  sendString(buf);

  for(idx=0; idx<numEntries; idx++) {
    if(revertOrder)
      statsEntry = &tmpStats[numEntries-idx-1];
    else
      statsEntry = &tmpStats[idx];

    if(domainName == NULL)
      snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s_%s.html>%s</A>",
	      DOMAIN_INFO_HTML, statsEntry->domainHost->fullDomainName,
	      statsEntry->domainHost->fullDomainName);
    else {
      char tmpBuf[64];
      int blankId;

#ifdef MULTITHREADED
      accessMutex(&addressResolutionMutex, "getHostIcon");
#endif

      blankId = strlen(statsEntry->domainHost->hostSymIpAddress)-
	strlen(statsEntry->domainHost->fullDomainName)-1;

      strncpy(tmpBuf, statsEntry->domainHost->hostSymIpAddress, sizeof(tmpBuf));

#ifdef MULTITHREADED
      releaseMutex(&addressResolutionMutex);
#endif

      if((blankId > 0)
	 && (strcmp(&tmpBuf[blankId+1], domainName) == 0))
	tmpBuf[blankId] = '\0';

      snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s.html>%s</A>",
	      statsEntry->domainHost->hostNumIpAddress, tmpBuf);
    }

    snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=CENTER>%s</TD>"
	    "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%.1f%%</TD>"
	    "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%.1f%%</TD>"
	    "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
	    "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
	    "<TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD><TD ALIGN=RIGHT>%s</TD>"
	    "<TD ALIGN=RIGHT>%s</TD></TR>\n",
	    getRowColor(), htmlAnchor,
	    getHostCountryIconURL(statsEntry->domainHost),
	    formatBytes(statsEntry->bytesSent, 1),
	    (100*((float)statsEntry->bytesSent/(float)totBytesSent)),
	    formatBytes(statsEntry->bytesRcvd, 1),
	    (100*((float)statsEntry->bytesRcvd/(float)totBytesRcvd)),
	    formatBytes(statsEntry->tcpSent, 1),
	    formatBytes(statsEntry->tcpRcvd, 1),
	    formatBytes(statsEntry->udpSent, 1),
	    formatBytes(statsEntry->udpRcvd, 1),
	    formatBytes(statsEntry->icmpSent, 1),
	    formatBytes(statsEntry->icmpRcvd, 1),
	    formatBytes(statsEntry->ospfSent, 1),
	    formatBytes(statsEntry->ospfRcvd, 1),
	    formatBytes(statsEntry->igmpSent, 1),
	    formatBytes(statsEntry->igmpRcvd, 1)
	    );
    sendString(buf);
  }

  sendString("</TABLE></HTML>\n");
}


/* ************************ */

void printLogHeader(void) {

  if(logd != NULL) {
    int i;

    fprintf(logd, "# date totalPkts broadcastPkts multicastPkts "
	    "ethernetBytes ipBytes nonIpBytes peakThroughput TCP UDP ICMP");

    for(i=0; i<numIpProtosToMonitor; i++)
      fprintf(logd, " %s", protoIPTrafficInfos[i]);

    fprintf(logd, "\n");
  }
}


/* ************************* */

void printNoDataYet(void) {
  sendString("<CENTER><P><i>"
	     "<IMG SRC=/warning.gif><p>No Data To Display (yet)"
	     "</i></CENTER>\n");
}

/* ************************* */

void listNetFlows(void) {
  char buf[BUF_SIZE];
  int numEntries=0;
  FlowFilterList *list = flowsList;

  printHTTPheader();

  if(list != NULL) {
    while(list != NULL) {
      if((list->pluginStatus.activePlugin)
	 && (list->pluginStatus.pluginPtr->bpfFilter != NULL)) {
	if(numEntries == 0) {
	  sendString("<CENTER><P><H1>Network Flows</H1><P>"
		     "<TABLE BORDER=1><TR><TH>Flow Name</TH>"
		     "<TH>Packets</TH><TH>Traffic</TH></TR>");   
	}

	snprintf(buf, sizeof(buf), "<TR %s><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>%s"
		"</TD><TD ALIGN=RIGHT>%s</TD></TR>\n",
		getRowColor(), list->flowName,
		formatPkts(list->packets),
		formatBytes(list->bytes, 1));
	sendString(buf);

	numEntries++;
      }
      list = list->next;
    }

    if(numEntries > 0)
      sendString("</TABLE></CENTER>");
  }

  if(numEntries == 0) {
    sendString("<CENTER><P><H1>No available/active Network Flows</H1><p>"
	       " (see <A HREF=ntop.html>man</A> page)</CENTER>\n");
  }
}


/* ****************************************** */

static int cmpEventsFctn(const void *_a, const void *_b) {
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

/* ****************************************** */

void printHostEvents(HostTraffic *theHost, int column, int revertOrder) {
  datum key_data, data_data, return_data;
  char tmpBuf[96], *arrow[6], *theAnchor[6];
  EventMsg *theMsgTable[MAX_NUM_EVENTS];
  EventMsg theMsgs[MAX_NUM_EVENTS];
  unsigned long shost, dhost, evtTime;
  u_short numEntries = 0, i;
  char buf[BUF_SIZE], *arrowGif, *sign;
  char htmlAnchor[64], htmlAnchor1[64];

  if(theHost == NULL) printHTTPheader();

  memset(theMsgs, 0, sizeof(theMsgs));

  if(eventFile == NULL) {
    if(theHost == NULL) printNoDataYet();
    return; /* No rules are currently active */
  }

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "printHostEvent");
#endif
  return_data = gdbm_firstkey (eventFile);
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif

  while (return_data.dptr != NULL) {
    key_data = return_data;
#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "printHostEvents-2");
#endif
    return_data = gdbm_nextkey(eventFile, key_data);
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif

    strncpy(tmpBuf, key_data.dptr, key_data.dsize);
    tmpBuf[key_data.dsize] = 0;

    sscanf(tmpBuf, "%lu %lu %lu", &shost, &dhost, &evtTime);

    if((theHost == NULL) /* All the events */
       || (theHost->hostIpAddress.s_addr == shost)
       || (theHost->hostIpAddress.s_addr == dhost)) {
#ifdef MULTITHREADED
      accessMutex(&gdbmMutex, "printHostEvents-3");
#endif
      data_data = gdbm_fetch(eventFile, key_data);
#ifdef MULTITHREADED
      releaseMutex(&gdbmMutex);
#endif

      if(data_data.dptr != NULL) {
	if(numEntries < MAX_NUM_EVENTS) {
	  memcpy(&theMsgs[numEntries], data_data.dptr, sizeof(EventMsg));
	  theMsgTable[numEntries] = &(theMsgs[numEntries]);
	  numEntries++;
	}
	
	if(data_data.dptr != NULL) 
	  free(data_data.dptr);
      }
    }
    
    free(key_data.dptr);
  } /* while */
  
  if(numEntries == 0) {
    if(theHost == NULL)  {
      /* All the events */
      printNoDataYet();
    }
    
    return;
  }

  if(theHost != NULL) {
    columnSort = 0;
    sign = "";
    arrowGif = "";
    strncpy(htmlAnchor, "<!", sizeof(htmlAnchor));
    strncpy(htmlAnchor1, "<!", sizeof(htmlAnchor1));
  } else {
    columnSort = column;

    if(revertOrder) {
      sign = "";
      arrowGif = "&nbsp;<IMG SRC=arrow_up.gif BORDER=0>";
    } else {
      sign = "-";
      arrowGif = "&nbsp;<IMG SRC=arrow_down.gif BORDER=0>";
    }

    snprintf(htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?%s", NW_EVENTS_HTML, sign);
    snprintf(htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?", NW_EVENTS_HTML);
  }

  if(abs(column) == 0) {
    arrow[0] = arrowGif; theAnchor[0] = htmlAnchor;
  } else {
    arrow[0] = ""; theAnchor[0] = htmlAnchor1;
  }

  if(abs(column) == 1) {
    arrow[1] = arrowGif; theAnchor[1] = htmlAnchor;
  } else {
    arrow[1] = ""; theAnchor[1] = htmlAnchor1;
  }

  if(abs(column) == 2) {
    arrow[2] = arrowGif; theAnchor[2] = htmlAnchor;
  } else {
    arrow[2] = ""; theAnchor[2] = htmlAnchor1;
  }

  quicksort(theMsgTable, numEntries, sizeof(EventMsg*), cmpEventsFctn);

  if(theHost == NULL) sendString("<CENTER>\n");

  sendString("<P><H1>Network Events</H1>\n");
  sendString("<TABLE BORDER=1>\n<TR>\n");
  snprintf(buf, sizeof(buf), "<TH>%s0>Time%s</A></TH><TH>%s1>Severity%s</A></TH>"
	  "<TH>%s2>Matched Rule%s</A></TH><TH>Message</TH></TR>\n",
	  theAnchor[0], arrow[0], theAnchor[1], arrow[1],
	  theAnchor[2], arrow[2]);
  sendString(buf);

  for(i=0; i<numEntries; i++) {
    char *elem, *strtokState;

    if(i > MAX_NUM_EVENTS_TO_DISPLAY)
      break;

    if(revertOrder)
      elem = strtok_r(theMsgTable[numEntries-i-1]->message, " ", &strtokState);
    else
      elem = strtok_r(theMsgTable[i]->message, " ", &strtokState);

    snprintf(tmpBuf, sizeof(tmpBuf), "<TR %s><TD>", getRowColor());
    sendString(tmpBuf);
    sendString(elem); /* 2000-03-07 */
    sendString(" ");
    elem = strtok_r(NULL, " ", &strtokState);
    sendString(elem);  /* 12:12:53 */

    sendString("</TD><TD ALIGN=CENTER>");
    elem = strtok_r(NULL, " ", &strtokState);

    if(strcmp(elem, "ALARM") == 0) {
      sendString("<FONT COLOR=#FF0000>");
      sendString(elem); /* ALARM */
      sendString("</FONT>");
    } else
      sendString(elem); /* INFO,.... */

    sendString("</TD><TD ALIGN=CENTER>");
    elem = strtok_r(NULL, " ", &strtokState);
    sendString(elem);  /* stealth-scan */

    sendString("</TD><TD NOWRAP>");
    sendString(&elem[strlen(elem)+1]);

    sendString("</TD></TR>\n");
  }

  sendString("</TABLE>\n");

  if(theHost == NULL) sendString("</CENTER>\n");
}


/* ************************ */

void fillDomainName(HostTraffic *el) {
  u_int i;

  if(theDomainHasBeenComputed(el)
     || (el->hostSymIpAddress == NULL))
    return;

#ifdef MULTITHREADED
  accessMutex(&addressResolutionMutex, "fillDomainName");
#endif

  if((el->hostSymIpAddress[0] == '*')
     || (el->hostNumIpAddress[0] == '\0')
     || (isdigit(el->hostSymIpAddress[strlen(el->hostSymIpAddress)-1]) &&
	 isdigit(el->hostSymIpAddress[0]))) {
    /* NOTE: theDomainHasBeenComputed(el) = 0 */
    el->fullDomainName = el->dotDomainName = "";
#ifdef MULTITHREADED
    releaseMutex(&addressResolutionMutex);
#endif
    return;
  }

  FD_SET(THE_DOMAIN_HAS_BEEN_COMPUTED_FLAG, &el->flags);
  el->fullDomainName = el->dotDomainName = ""; /* Reset values... */

  i = strlen(el->hostSymIpAddress)-1;

  while(i > 0)
    if(el->hostSymIpAddress[i] == '.')
      break;
    else
      i--;

  if((i > 0)
     && strcmp(el->hostSymIpAddress, el->hostNumIpAddress)
     && (strlen(el->hostSymIpAddress) > (i+1)))
    el->dotDomainName = &el->hostSymIpAddress[i+1];
  else {
    /* Let's use the local domain name */
#ifdef DEBUG
    traceEvent(TRACE_INFO, "'%s' [%s/%s]\n",
	   el->hostSymIpAddress, domainName, shortDomainName);
#endif
    if((domainName[0] != '\0')
       && (strcmp(el->hostSymIpAddress, el->hostNumIpAddress))) {
      int len  = strlen(el->hostSymIpAddress);
      int len1 = strlen(domainName);

      /* traceEvent(TRACE_INFO, "%s [%s]\n", 
	 el->hostSymIpAddress, &el->hostSymIpAddress[len-len1]); */

      if((len > len1)
	 && (strcmp(&el->hostSymIpAddress[len-len1-1], domainName) == 0))
	el->hostSymIpAddress[len-len1-1] = '\0';

      el->fullDomainName = domainName;
      el->dotDomainName = shortDomainName;
    } else {
      el->fullDomainName = el->dotDomainName = "";
    }

#ifdef MULTITHREADED
    releaseMutex(&addressResolutionMutex);
#endif
    return;
  }

  for(i=0; el->hostSymIpAddress[i] != '\0'; i++)
    el->hostSymIpAddress[i] = tolower(el->hostSymIpAddress[i]);

  i = 0;
  while(el->hostSymIpAddress[i] != '\0')
    if(el->hostSymIpAddress[i] == '.')
      break;
    else
      i++;

  if((el->hostSymIpAddress[i] == '.')
	 && (strlen(el->hostSymIpAddress) > (i+1)))
    el->fullDomainName = &el->hostSymIpAddress[i+1];

  /* traceEvent(TRACE_INFO, "'%s'\n", el->domainName); */

#ifdef MULTITHREADED
    releaseMutex(&addressResolutionMutex);
#endif
}

/* ******************************** */

static void printFeatureConfigInfo(char* feature, char* status) {
  sendString("<TR><TH ALIGN=left>");
  sendString(feature);
  sendString("</TH><TD ALIGN=right>");
  sendString(status);
  sendString("</td></tr>\n");
}

/* ******************************** */

void printNtopConfigInfo(void) {
  char buf[BUF_SIZE];


  sendString("<CENTER><H1>Current ntop Configuration</H1>\n");

  sendString("<P><HR><P><TABLE BORDER=1>\n");

  printFeatureConfigInfo("OS", osName);
  printFeatureConfigInfo("ntop Version", version);
  printFeatureConfigInfo("Built on", buildDate);

#ifdef HAVE_OPENSSL
  printFeatureConfigInfo("<A HREF=http://www.openssl.org/>OpenSSL Support</A>", "Present");
#else
  printFeatureConfigInfo("<A HREF=http://www.openssl.org/>OpenSSL Support</A>", "Absent");
#endif

#ifdef MULTITHREADED
  printFeatureConfigInfo("Multithreaded", "Yes");
#else
  printFeatureConfigInfo("Multithreaded", "No");
#endif

#ifdef HAVE_GDCHART
  printFeatureConfigInfo("<A HREF=http://www.fred.net/brv/chart/>GD Chart</A>", "Present");
#else
  printFeatureConfigInfo("<A HREF=http://www.fred.net/brv/chart/>GD Chart</A>", "Absent");
#endif

#ifdef HAVE_UCD_SNMP_UCD_SNMP_AGENT_INCLUDES_H
  printFeatureConfigInfo("<A HREF=http://ucd-snmp.ucdavis.edu/>UCD SNMP</A>", "Present");
#else
  printFeatureConfigInfo("<A HREF=http://ucd-snmp.ucdavis.edu/>UCD SNMP </A>", "Absent");
#endif

#ifdef HAVE_LIBWRAP
  printFeatureConfigInfo("TCP Wrappers", "Present");
#else
  printFeatureConfigInfo("TCP Wrappers", "Absent");
#endif

#ifdef ASYNC_ADDRESS_RESOLUTION
  printFeatureConfigInfo("Async. Addr. Resolution", "Yes");
#else
  printFeatureConfigInfo("Async. Addr. Resolution", "No");
#endif

  snprintf(buf, sizeof(buf), "<TR><TH align=left>actualHashSize</TH><TD align=right>%d</TD></TR>\n",
	  (int)device[actualReportDeviceId].actualHashSize);
  sendString(buf);
  snprintf(buf, sizeof(buf), "<TR><TH align=left>Hash hosts</TH><TD align=right>%d [%d %%]</TD></TR>\n",
	  (int)device[actualReportDeviceId].hostsno,
	  (((int)device[actualReportDeviceId].hostsno*100)/
	   (int)device[actualReportDeviceId].actualHashSize));
  sendString(buf);

#ifdef MEMORY_DEBUG
  snprintf(buf, sizeof(buf), "<TR><TH align=left>Allocated Memory</TH><TD align=right>%s</TD></TR>\n",
	  formatBytes(allocatedMemory, 0));
  sendString(buf);
#endif

  sendString("</TABLE>\n");
}



