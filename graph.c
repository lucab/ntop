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

 /*
  * Do not use local defs for pnggraph
  * (included by ntop.h)
  */

#include "ntop.h"

#ifndef MICRO_NTOP
#ifdef HAVE_GDCHART

#define _GRAPH_C_
#include "globals-report.h"

static unsigned long clr[] = { 0xf08080L, 0x4682b4L, 0x66cdaaL,
                               0xf4a460L, 0xb0c4deL, 0x90ee90L,
                               0xffd700L, 0x87ceebL, 0xdda0ddL,
                               0x7fffd4L, 0xffb6c1L, 0x708090L,
                               0x6495edL, 0xdeb887L, 0x6b8e23L};

/* ************************ */

void _GDC_out_pie(short width,
                  short height,
                  FILE* filepointer,            /* open file pointer, can be stdout */
                  GDCPIE_TYPE pietype,
                  int   num_points,
                  char  *labels[],              /* slice labels */
                  float data[] ) {

  int status;
  pid_t wait_result, fork_result;
  FILE *fd;
  int idx, i, found, len;
  struct stat statbuf;
  char tmpStr[512];

  fork_result = fork();

  if (fork_result == (pid_t) -1) {
    traceEvent(TRACE_ERROR, "ERROR: GDC_out_pie(001) - fork failed!");
    return;
  }
  if (fork_result == (pid_t) 0) {

    traceEvent(TRACE_INFO, "INFO: GDC_out_pie - in child, calling\n");
    GDC_out_pie(width,
                height,
                filepointer,
                pietype,
                num_points,
                labels,
                data);
    traceEvent(TRACE_INFO, "INFO: GDC_out_pie - in child, returned\n");
    return;
  }

  /* parent */
  wait_result = wait(&status);
  if (wait_result == (pid_t) -1) {
      traceEvent(TRACE_ERROR, "ERROR: GDC_out_pie(002) - wait failed/interrupted");
  } else if (wait_result != fork_result) {
      traceEvent(TRACE_ERROR, "ERROR: GDC_out_pie(003) - unexpected child termination");
  } else if (status) {
       traceEvent(TRACE_ERROR, "ERROR: GDC_out_pie(004) - child abnormal termination");
  } else {
       traceEvent(TRACE_INFO, "INFO: GDC_out_pie - in parent, ran OK\n");
       return;
  }

  /* Some kind of failure -- send PIE-ERROR.png */

  /* Search in the local directory first... */
  found=0;
  for(idx=0; (!found) && (myGlobals.dataFileDirs[idx] != NULL); idx++) {

      if(snprintf(tmpStr, sizeof(tmpStr), "%s/html/%s",
                  myGlobals.dataFileDirs[idx], NTOP_GDC_OUT_PIE_ERROR) < 0)
          BufferTooShort();
  
#ifdef WIN32
      i=0;
      while(tmpStr[i] != '\0') {
          if(tmpStr[i] == '/') tmpStr[i] = '\\';
          i++;
      }
#endif
  
      if(stat(tmpStr, &statbuf) == 0) {
          if((fd = fopen(tmpStr, "rb")) != NULL) {
              found = 1;
              break;
          }
      }
  }
  
  if(fd != NULL) {
      for(;;) {
          len = fread(tmpStr, sizeof(char), sizeof(tmpStr), fd);
          if(len <= 0) break;
              sendStringLen(tmpStr, len);
      }

      fclose(fd);
  } else {
      traceEvent(TRACE_ERROR, "ERROR: GDC_out_pie(005) - unable to find %s\n", 
                              NTOP_GDC_OUT_PIE_ERROR);
  }
  return;
}

#define GDC_out_pie(w, h, file, type, slices, labels, data) _GDC_out_pie(w, h, file, type, slices, labels, data)

/* ************************ */

void sendGraphFile(char* fileName) {
  FILE *fd;
  int len;
  char tmpStr[256];

  if((fd = fopen(fileName, "rb")) != NULL) {
    for(;;) {
      len = fread(tmpStr, sizeof(char), sizeof(tmpStr)-1, fd);
      if(len <= 0) break;
      sendStringLen(tmpStr, len);
    }

    fclose(fd);
  } else 
    traceEvent(TRACE_WARNING, "WARNING: unable to open file %s", fileName);

  unlink(fileName);
}

/* ************************ */

void hostTrafficDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0, explodePieces[] = { 5, 10, 15, 20, 25, 30, 35, 40,
			45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95 };
  FILE *fd;
  TrafficCounter totTraffic;
  int useFdOpen = 0;

  if(dataSent) {
    totTraffic.value = theHost->tcpSentLoc.value+theHost->tcpSentRem.value+
      theHost->udpSentLoc.value+theHost->udpSentRem.value+
      theHost->icmpSent.value+theHost->ospfSent.value+theHost->igmpSent.value+theHost->stpSent.value
      +theHost->ipxSent.value+theHost->osiSent.value+theHost->dlcSent.value+
      theHost->arp_rarpSent.value+theHost->decnetSent.value+theHost->appletalkSent.value+
      theHost->netbiosSent.value+theHost->ipv6Sent.value+theHost->otherSent.value;
  } else {
    totTraffic.value = theHost->tcpRcvdLoc.value+theHost->tcpRcvdFromRem.value+
      theHost->udpRcvdLoc.value+theHost->udpRcvdFromRem.value+
      theHost->icmpRcvd.value+theHost->ospfRcvd.value+theHost->igmpRcvd.value+theHost->stpRcvd.value
      +theHost->ipxRcvd.value+theHost->osiRcvd.value+theHost->dlcRcvd.value+
      theHost->arp_rarpRcvd.value+theHost->decnetRcvd.value+theHost->appletalkRcvd.value+
      theHost->netbiosRcvd.value+theHost->ipv6Rcvd.value+theHost->otherRcvd.value;
  }

  if(totTraffic.value > 0) {
    if(dataSent) {
      if(theHost->tcpSentLoc.value+theHost->tcpSentRem.value > 0) {
	p[num] = (float)((100*(theHost->tcpSentLoc.value+
			       theHost->tcpSentRem.value))/totTraffic.value);
	lbl[num++] = "TCP";
      }

      if(theHost->udpSentLoc.value+theHost->udpSentRem.value > 0) {
	p[num] = (float)((100*(theHost->udpSentLoc.value+
			       theHost->udpSentRem.value))/totTraffic.value);
	lbl[num++] = "UDP";
      }

      if(theHost->icmpSent.value > 0) {
	p[num] = (float)((100*theHost->icmpSent.value)/totTraffic.value);
	lbl[num++] = "ICMP";
      }

      if(theHost->ospfSent.value > 0) {
	p[num] = (float)((100*theHost->ospfSent.value)/totTraffic.value);
	lbl[num++] = "OSPF";
      }

      if(theHost->igmpSent.value > 0) {
	p[num] = (float)((100*theHost->igmpSent.value)/totTraffic.value);
	lbl[num++] = "IGMP";
      }

      if(theHost->stpSent.value > 0) {
	p[num] = (float)((100*theHost->stpSent.value)/totTraffic.value);
	lbl[num++] = "STP";
      }

      if(theHost->ipxSent.value > 0) {
	p[num] = (float)((100*theHost->ipxSent.value)/totTraffic.value);
	lbl[num++] = "IPX";
      }

      if(theHost->dlcSent.value > 0) {
	p[num] = (float)((100*theHost->dlcSent.value)/totTraffic.value);
	lbl[num++] = "DLC";
      }

      if(theHost->osiSent.value > 0) {
	p[num] = (float)((100*theHost->osiSent.value)/totTraffic.value);
	lbl[num++] = "OSI";
      }

      if(theHost->arp_rarpSent.value > 0) {
	p[num] = (float)((100*theHost->arp_rarpSent.value)/totTraffic.value);
	lbl[num++] = "(R)ARP";
      }

      if(theHost->decnetSent.value > 0) {
	p[num] = (float)((100*theHost->decnetSent.value)/totTraffic.value);
	lbl[num++] = "DECNET";
      }

      if(theHost->appletalkSent.value > 0) {
	p[num] = (float)((100*theHost->appletalkSent.value)/totTraffic.value);
	lbl[num++] = "AppleTalk";
      }

      if(theHost->netbiosSent.value > 0) {
	p[num] = (float)((100*theHost->netbiosSent.value)/totTraffic.value);
	lbl[num++] = "NetBios";
      }

      if(theHost->ipv6Sent.value > 0) {
	p[num] = (float)((100*theHost->ipv6Sent.value)/totTraffic.value);
	lbl[num++] = "IPv6";
      }

      if(theHost->otherSent.value > 0) {
	p[num] = (float)((100*theHost->otherSent.value)/totTraffic.value);
	lbl[num++] = "Other";
      }
    } else {
      if(theHost->tcpRcvdLoc.value+theHost->tcpRcvdFromRem.value > 0) {
	p[num] = (float)((100*(theHost->tcpRcvdLoc.value+
			       theHost->tcpRcvdFromRem.value))/totTraffic.value);
	lbl[num++] = "TCP";
      }

      if(theHost->udpRcvdLoc.value+theHost->udpRcvdFromRem.value > 0) {
	p[num] = (float)((100*(theHost->udpRcvdLoc.value+
			       theHost->udpRcvdFromRem.value))/totTraffic.value);
	lbl[num++] = "UDP";
      }

      if(theHost->icmpRcvd.value > 0) {
	p[num] = (float)((100*theHost->icmpRcvd.value)/totTraffic.value);
	lbl[num++] = "ICMP";
      }

      if(theHost->ospfRcvd.value > 0) {
	p[num] = (float)((100*theHost->ospfRcvd.value)/totTraffic.value);
	lbl[num++] = "OSPF";
      }

      if(theHost->igmpRcvd.value > 0) {
	p[num] = (float)((100*theHost->igmpRcvd.value)/totTraffic.value);
	lbl[num++] = "IGMP";
      }

      if(theHost->stpRcvd.value > 0) {
	p[num] = (float)((100*theHost->stpRcvd.value)/totTraffic.value);
	lbl[num++] = "STP";
      }

      if(theHost->ipxRcvd.value > 0) {
	p[num] = (float)((100*theHost->ipxRcvd.value)/totTraffic.value);
	lbl[num++] = "IPX";
      }

      if(theHost->dlcRcvd.value > 0) {
	p[num] = (float)((100*theHost->dlcRcvd.value)/totTraffic.value);
	lbl[num++] = "DLC";
      }

      if(theHost->osiRcvd.value > 0) {
	p[num] = (float)((100*theHost->osiRcvd.value)/totTraffic.value);
	lbl[num++] = "OSI";
      }

      if(theHost->arp_rarpRcvd.value > 0) {
	p[num] = (float)((100*theHost->arp_rarpRcvd.value)/totTraffic.value);
	lbl[num++] = "(R)ARP";
      }

      if(theHost->decnetRcvd.value > 0) {
	p[num] = (float)((100*theHost->decnetRcvd.value)/totTraffic.value);
	lbl[num++] = "DECNET";
      }

      if(theHost->appletalkRcvd.value > 0) {
	p[num] = (float)((100*theHost->appletalkRcvd.value)/totTraffic.value);
	lbl[num++] = "AppleTalk";
      }

      if(theHost->netbiosRcvd.value > 0) {
	p[num] = (float)((100*theHost->netbiosRcvd.value)/totTraffic.value);
	lbl[num++] = "NetBios";
      }

      if(theHost->ipv6Rcvd.value > 0) {
	p[num] = (float)((100*theHost->ipv6Rcvd.value)/totTraffic.value);
	lbl[num++] = "IPv6";
      }

      if(theHost->otherRcvd.value > 0) {
	p[num] = (float)((100*theHost->otherRcvd.value)/totTraffic.value);
	lbl[num++] = "Other";
      }
    }

    if(num == 0) {
      traceEvent(TRACE_WARNING, "WARNING: Graph failure (1)");
      return; /* TODO: this has to be handled better */
    }

#ifdef MULTITHREADED
    accessMutex(&myGlobals.graphMutex, "pktHostTrafficDistrib");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

    GDCPIE_LineColor = 0x000000L;
    GDCPIE_explode   = explodePieces;    /* default: NULL - no explosion */
    GDCPIE_Color     = clr;
    GDCPIE_BGColor   = 0xFFFFFFL;
    GDCPIE_EdgeColor = 0x000000L;	/* default is GDCPIE_NOCOLOR */
    GDCPIE_percent_labels = GDCPIE_PCT_NONE;

    if(num == 1) p[0] = 100; /* just to be safe */

    GDC_out_pie(250,			/* width */
		250,			/* height */
		fd,			/* open file pointer */
		GDC_3DPIE,		/* or GDC_2DPIE */
		num,			/* number of slices */
		lbl,			/* slice labels (unlike out_png(), can be NULL */
		p);			/* data array */

    fclose(fd);

#ifdef MULTITHREADED
    releaseMutex(&myGlobals.graphMutex);
#endif

    if(!useFdOpen)
      sendGraphFile(fileName);
  }
}

/* ************************ */

void hostFragmentDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0, explodePieces[] = { 5, 10, 15, 20, 25, 30, 35, 40,
			45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95 };
  FILE *fd;
  TrafficCounter totTraffic;
  int useFdOpen = 0;

  if(dataSent)
    totTraffic.value = theHost->tcpFragmentsSent.value+theHost->udpFragmentsSent.value+theHost->icmpFragmentsSent.value;
  else
    totTraffic.value = theHost->tcpFragmentsRcvd.value+theHost->udpFragmentsRcvd.value+theHost->icmpFragmentsRcvd.value;

  if(totTraffic.value > 0) {
    if(dataSent) {
      if(theHost->tcpFragmentsSent.value > 0) {
	p[num] = (float)((100*(theHost->tcpFragmentsSent.value))/totTraffic.value);
	lbl[num++] = "TCP";
      }

      if(theHost->udpFragmentsSent.value > 0) {
	p[num] = (float)((100*(theHost->udpFragmentsSent.value))/totTraffic.value);
	lbl[num++] = "UDP";
      }

      if(theHost->icmpFragmentsSent.value > 0) {
	p[num] = (float)((100*(theHost->icmpFragmentsSent.value))/totTraffic.value);
	lbl[num++] = "ICMP";
      }
    } else {
      if(theHost->tcpFragmentsRcvd.value > 0) {
	p[num] = (float)((100*(theHost->tcpFragmentsRcvd.value))/totTraffic.value);
	lbl[num++] = "TCP";
      }

      if(theHost->udpFragmentsRcvd.value > 0) {
	p[num] = (float)((100*(theHost->udpFragmentsRcvd.value))/totTraffic.value);
	lbl[num++] = "UDP";
      }

      if(theHost->icmpFragmentsRcvd.value > 0) {
	p[num] = (float)((100*(theHost->icmpFragmentsRcvd.value))/totTraffic.value);
	lbl[num++] = "ICMP";
      }
    }

    if(num == 0) {
      traceEvent(TRACE_WARNING, "WARNING: Graph failure (2)");
      return; /* TODO: this has to be handled better */
    }

#ifdef MULTITHREADED
    accessMutex(&myGlobals.graphMutex, "pktHostFragmentDistrib");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

    GDCPIE_LineColor = 0x000000L;
    GDCPIE_explode   = explodePieces;    /* default: NULL - no explosion */
    GDCPIE_Color     = clr;
    GDCPIE_BGColor   = 0xFFFFFFL;
    GDCPIE_EdgeColor = 0x000000L;	/* default is GDCPIE_NOCOLOR */
    GDCPIE_percent_labels = GDCPIE_PCT_NONE;

    if(num == 1) p[0] = 100; /* just to be safe */
    GDC_out_pie(250,			/* width */
		250,			/* height */
		fd,			/* open file pointer */
		GDC_3DPIE,		/* or GDC_2DPIE */
		num,			/* number of slices */
		lbl,			/* slice labels (unlike out_png(), can be NULL */
		p);			/* data array */

    fclose(fd);

#ifdef MULTITHREADED
    releaseMutex(&myGlobals.graphMutex);
#endif

    if(!useFdOpen)
      sendGraphFile(fileName);
  }
}

/* ************************ */

void hostTotalFragmentDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0, explodePieces[] = { 5, 10, 15, 20, 25, 30, 35, 40,
			45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95 };
  FILE *fd;
  TrafficCounter totFragmentedTraffic, totTraffic;
  int useFdOpen = 0;

  if(dataSent) {
    totTraffic.value = theHost->ipBytesSent.value;
    totFragmentedTraffic.value = theHost->tcpFragmentsSent.value+theHost->udpFragmentsSent.value
      +theHost->icmpFragmentsSent.value;
  } else {
    totTraffic.value = theHost->ipBytesRcvd.value;
    totFragmentedTraffic.value = theHost->tcpFragmentsRcvd.value+theHost->udpFragmentsRcvd.value
      +theHost->icmpFragmentsRcvd.value;
  }

  if(totTraffic.value > 0) {
    p[num] = (float)((100*totFragmentedTraffic.value)/totTraffic.value);
    lbl[num++] = "Frag";

    p[num] = 100-((float)(100*totFragmentedTraffic.value)/totTraffic.value);
    if(p[num] > 0) { lbl[num++] = "Non Frag"; }

    if(num == 0) {
      traceEvent(TRACE_WARNING, "WARNING: Graph failure (3)");
      return; /* TODO: this has to be handled better */
    }

#ifdef MULTITHREADED
    accessMutex(&myGlobals.graphMutex, "pktHostFragmentDistrib");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

    GDCPIE_LineColor      = 0x000000L;
    GDCPIE_explode        = explodePieces;      /* default: NULL - no explosion */
    GDCPIE_Color          = clr;
    GDCPIE_BGColor        = 0xFFFFFFL;
    GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
    GDCPIE_percent_labels = GDCPIE_PCT_NONE;

    if(num == 1) p[0] = 100; /* just to be safe */
    GDC_out_pie(250,			/* width */
		250,			/* height */
		fd,			/* open file pointer */
		GDC_3DPIE,		/* or GDC_2DPIE */
		num,			/* number of slices */
		lbl,			/* slice labels (unlike out_png(), can be NULL */
		p);			/* data array */

    fclose(fd);

#ifdef MULTITHREADED
    releaseMutex(&myGlobals.graphMutex);
#endif

    if(!useFdOpen)
      sendGraphFile(fileName);
  }
}

/* ************************ */

void hostIPTrafficDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[MAX_NUM_PROTOS];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int i, num=0, explodePieces[MAX_NUM_PROTOS];
  FILE *fd;
  TrafficCounter traffic, totalIPTraffic, diffTraffic;
  int useFdOpen = 0;

  if(theHost->protoIPTrafficInfos == NULL) {
    traceEvent(TRACE_WARNING, "WARNING: Graph failure (5)");
    return;
  }

  totalIPTraffic.value = 0;
  diffTraffic.value = 0;

  if(dataSent)
    totalIPTraffic.value = theHost->ipBytesSent.value;
  else
    totalIPTraffic.value = theHost->ipBytesRcvd.value;
  
  if(totalIPTraffic.value > 0) {
    for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
      if(dataSent)
	traffic.value = theHost->protoIPTrafficInfos[i].sentLoc.value+theHost->protoIPTrafficInfos[i].sentRem.value;
      else
	traffic.value = theHost->protoIPTrafficInfos[i].rcvdLoc.value+theHost->protoIPTrafficInfos[i].rcvdFromRem.value;

      if(traffic.value > 0) {
	p[num] = (float)((100*traffic.value)/totalIPTraffic.value);
	diffTraffic.value += traffic.value;

        if(num == 0)
          explodePieces[num]=10;
        else
          explodePieces[num]=explodePieces[num-1];
	if (p[num]<5.0) explodePieces[num]+=9; else if (p[num]>10.0) explodePieces[num]=10;

	lbl[num++] = myGlobals.protoIPTrafficInfos[i];
      }

      if(num >= MAX_NUM_PROTOS) break; /* Too much stuff */
    }
  }

  if(num == 0) {
    p[num] = 1;
    explodePieces[num] = 10;
    lbl[num++] = "Other";
  } else {
    if(diffTraffic.value < totalIPTraffic.value) {
      diffTraffic.value = totalIPTraffic.value - diffTraffic.value;
      p[num] = (float)((100*diffTraffic.value)/totalIPTraffic.value);
      explodePieces[num]=explodePieces[num-1];
      if(p[num]<5.0) explodePieces[num]+=9; else if (p[num]>10.0) explodePieces[num]=10;
      lbl[num++] = "Other";
    }
  }

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "pktHostTrafficDistrib");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  GDCPIE_LineColor      = 0x000000L;
  GDCPIE_explode        = explodePieces;    /* default: NULL - no explosion */
  GDCPIE_Color          = clr;
  GDCPIE_BGColor        = 0xFFFFFFL;
  GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_NONE;
  if(num == 1) p[0] = 100;

  if(num == 1) p[0] = 100; /* just to be safe */
  GDC_out_pie(250,			/* width */
	      250,			/* height */
	      fd,			/* open file pointer */
	      GDC_3DPIE,		/* or GDC_2DPIE */
	      num,			/* number of slices */
	      lbl,			/* slice labels (unlike out_png(), can be NULL */
	      p);			/* data array */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.graphMutex);
#endif

  if(!useFdOpen)
    sendGraphFile(fileName);
}

/* ********************************** */

void pktSizeDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[7];
  char	*lbl[] = { "", "", "", "", "", "", "" };
  int num=0, explodePieces[] = { 5, 10, 15, 20, 25, 30, 35 };
  FILE *fd;
  int useFdOpen = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "< 64";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "< 128";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "< 256";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "< 512";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "< 1024";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "< 1518";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "> 1518";
  };


#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "pktSizeDistrib");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  GDCPIE_LineColor      = 0x000000L;
  GDCPIE_explode        = explodePieces;    /* default: NULL - no explosion */
  GDCPIE_Color          = clr;
  GDCPIE_BGColor        = 0xFFFFFFL;
  GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_NONE;

  if(num == 1) p[0] = 100; /* just to be safe */
  GDC_out_pie(250,			/* width */
	      250,			/* height */
	      fd,			/* open file pointer */
	      GDC_3DPIE,		/* or GDC_2DPIE */
	      num,			/* number of slices */
	      lbl,			/* slice labels (unlike out_png(), can be NULL */
	      p);			/* data array */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.graphMutex);
#endif

  if(!useFdOpen)
    sendGraphFile(fileName);
}

/* ********************************** */

void pktTTLDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[8];
  char	*lbl[] = { "", "", "", "", "", "", "" };
  int num=0, explodePieces[] = { 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55 };
  FILE *fd;
  int useFdOpen = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 32";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 64";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 96";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 128";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 160";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 192";
  };

 if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "< 224";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo255.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo255.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "<= 255";
  };

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "pktSizeDistrib");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  GDCPIE_LineColor      = 0x000000L;
  GDCPIE_explode        = explodePieces;    /* default: NULL - no explosion */
  GDCPIE_Color          = clr;
  GDCPIE_BGColor        = 0xFFFFFFL;
  GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_NONE;

  if(num == 1) p[0] = 100; /* just to be safe */
  GDC_out_pie(250,			/* width */
	      250,			/* height */
	      fd,			/* open file pointer */
	      GDC_3DPIE,		/* or GDC_2DPIE */
	      num,			/* number of slices */
	      lbl,			/* slice labels (unlike out_png(), can be NULL */
	      p);			/* data array */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.graphMutex);
#endif

  if(!useFdOpen)
    sendGraphFile(fileName);
}

/* ************************ */

void ipProtoDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[3];
  char	*lbl[] = { "Loc", "Rem->Loc", "Loc->Rem" };
  int num=0, explodePieces[] = { 0, 20, 30 };
  FILE *fd;
  int useFdOpen = 0;

  p[num] = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local.value+
		   myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.local.value)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Loc";
  }

  p[num] = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.remote2local.value+
		   myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.remote2local.value)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Rem->Loc";
  }

  p[num] = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local2remote.value+
		   myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.local2remote.value)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Loc->Rem";
  }

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "ipProtoDistribPie");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  GDCPIE_LineColor      = 0x000000L;
  GDCPIE_explode        = explodePieces;    /* default: NULL - no explosion */
  GDCPIE_Color          = clr;
  GDCPIE_BGColor        = 0xFFFFFFL;
  GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_NONE;

  if(num == 1) p[0] = 100; /* just to be safe */
  GDC_out_pie(250,			/* width */
	      250,			/* height */
	      fd,			/* open file pointer */
	      GDC_3DPIE,		/* or GDC_2DPIE */
	      num,			/* number of slices */
	      lbl,			/* slice labels (unlike out_png(), can be NULL */
	      p);			/* data array */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.graphMutex);
#endif

  if(!useFdOpen)
    sendGraphFile(fileName);
}

/* ************************ */

void interfaceTrafficPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[MAX_NUM_DEVICES];
  int i, explodePieces[MAX_NUM_DEVICES];
  FILE *fd;
  TrafficCounter totPkts;
  struct pcap_stat pcapStat;
  char	*lbl[MAX_NUM_DEVICES];
  int myDevices=0;
  int useFdOpen = 0;

  totPkts.value = 0;

  for(i=0; i<myGlobals.numDevices; i++)
    if(!myGlobals.device[i].virtualDevice) {
      if (pcap_stats(myGlobals.device[i].pcapPtr, &pcapStat) >= 0) {
	p[i] = (float)pcapStat.ps_recv;
	totPkts.value += pcapStat.ps_recv;
      }
      explodePieces[i] = 10*i;
    }

  if(totPkts.value == 0)
    totPkts.value++;

  for(i=0; i<myGlobals.numDevices; i++) {
    if((!myGlobals.device[i].virtualDevice) && (p[i] > 0))  {
      p[myDevices]   = 100*(((float)p[i])/totPkts.value);
      lbl[myDevices] = myGlobals.device[i].name;
      myDevices++;
    }
  }

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "interfaceTrafficPie");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  GDCPIE_LineColor      = 0x000000L;
  GDCPIE_explode        = explodePieces;
  GDCPIE_Color          = clr;
  GDCPIE_BGColor        = 0xFFFFFFL;
  GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_RIGHT;

  if(myDevices == 1) p[0] = 100; /* just to be safe */
  GDC_out_pie(250,	/* width */
	      250,		/* height */
	      fd,		/* open file pointer */
	      GDC_3DPIE,	/* or GDC_2DPIE */
	      myDevices,	/* number of slices */
	      lbl,		/* slice labels (unlike out_png(), can be NULL) */
	      p);		/* data array */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.graphMutex);
#endif

  if(!useFdOpen)
    sendGraphFile(fileName);
}

/* ************************ */

void pktCastDistribPie(void) {
  char fileName[64] = "/tmp/graph-XXXXXX";
  float p[3];
  char	*lbl[] = { "", "", "" };
  int num=0, explodePieces[] = { 0, 20, 30 }, useFdOpen = 0;
  FILE *fd;
  TrafficCounter unicastPkts;

  unicastPkts.value = myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value
    - myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value
    - myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value;

  if(unicastPkts.value > 0) {
    p[num] = (float)(100*unicastPkts.value)/(float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "Unicast";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "Broadcast";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value > 0) {
    int i;

    p[num] = 100;
    for(i=0; i<num; i++)
      p[num] -= p[i];

    if(p[num] < 0) p[num] = 0;
    lbl[num++] = "Multicast";
  };

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "pktCastDistribPie");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else   
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  GDCPIE_LineColor      = 0x000000L;
  GDCPIE_explode        = explodePieces;         /* default: NULL - no explosion */
  GDCPIE_Color          = clr;
  GDCPIE_BGColor        = 0xFFFFFFL;
  GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_NONE;

  if(num == 1) p[0] = 100;  /* just to be safe */
  GDC_out_pie(250,			/* width */
	      250,			/* height */
	      fd,			/* open file pointer */
	      GDC_3DPIE,		/* or GDC_2DPIE */
	      num,			/* number of slic2es */
	      lbl,			/* slice labels (unlike out_png(), can be NULL) */
	      p);			/* data array */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.graphMutex);
#endif

  if(!useFdOpen)
    sendGraphFile(fileName);
}

/* ************************ */

void drawTrafficPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  TrafficCounter ip;
  float p[2];
  char	*lbl[] = { "IP", "Non IP" };
  int num=0, explodePieces[] = { 5, 5 };
  FILE *fd;
  int useFdOpen = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value == 0) return;

  ip.value = myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value;
  
  p[0] = ip.value*100/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value; num++;
  p[1] = 100-p[0];

  if(p[1] > 0)
    num++;

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "drawTrafficPie");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  GDCPIE_LineColor = 0x000000L;
  GDCPIE_BGColor   = 0xFFFFFFL;
  GDCPIE_EdgeColor = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_explode   = explodePieces;    /* default: NULL - no explosion */
  GDCPIE_Color     = clr;

  if(num == 1) p[0] = 100; /* just to be safe */
  GDC_out_pie(250,			/* width */
	      250,			/* height */
	      fd,			/* open file pointer */
	      GDC_3DPIE,		/* or GDC_2DPIE */
	      num,			/* number of slices */
	      lbl,			/* slice labels (unlike out_png(), can be NULL */
	      p);			/* data array */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.graphMutex);
#endif

  if(!useFdOpen)
    sendGraphFile(fileName);
}

/* ************************ */

void drawThptGraph(int sortedColumn) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  int i, len;
  char  labels[60][32];
  char  *lbls[60];
  FILE *fd;
  time_t tmpTime;
  float graphData[60], maxBytesPerSecond;
  struct tm t;
  int useFdOpen = 0;

  memset(graphData, 0, sizeof(graphData));

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "drawThptGraph");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  GDC_BGColor    = 0xFFFFFFL;      /* backgound color (white) */
  GDC_LineColor  = 0x000000L;      /* line color      (black) */
  GDC_SetColor   = &(clr[0]);       /* assign set colors */
  GDC_ytitle     = "Throughput";
  GDC_yaxis      = 1;
  GDC_ylabel_fmt = "%d Bps";

  switch(sortedColumn) {
  case 1: /* 60 Minutes */
    for(i=0; i<60; i++) {
      lbls[59-i] = labels[i];
      labels[i][0] = '\0';
    }

    len = myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples;
    if(len > 60) len = 60;
    for(i=0; i<len; i++) {
      tmpTime = myGlobals.actTime-i*60;
      strftime(labels[i], 32, "%H:%M", localtime_r(&tmpTime, &t));
    }

    for(maxBytesPerSecond=0, i=0; i<len; i++) {
      graphData[59-i] = myGlobals.device[myGlobals.actualReportDeviceId].last60MinutesThpt[i].trafficValue*8 /* I want bits here */;
      if(graphData[59-i] > maxBytesPerSecond) maxBytesPerSecond = graphData[59-i];
    }

    if(maxBytesPerSecond > 1048576 /* 1024*1024 */) {
      for(i=0; i<len; i++)
	graphData[59-i] /= 1048576;
      GDC_ylabel_fmt = "%.1f Mbps";
    } else if(maxBytesPerSecond > 1024) {
      for(i=0; i<len; i++)
	graphData[59-i] /= 1024;
      GDC_ylabel_fmt = "%.1f Kbps";
    }

    GDC_title = "Last 60 Minutes Average Throughput";
    out_graph(600, 300,    /* width, height           */
	      fd,          /* open FILE pointer       */
	      myGlobals.throughput_chart_type,    /* chart type  */
	      60,          /* num points per data set */
	      (char**)lbls,        /* X labels array of char* */
	      1,           /* number of data sets     */
	      graphData);  /* dataset 1   */
    break;
  case 2: /* 24 Hours */
    for(i=0; i<24; i++) {
      lbls[23-i] = labels[i];
      labels[i][0] = '\0';
    }

    len = myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples/60;
    if(len > 24) len = 24;
    for(i=0; i<len; i++) {
      tmpTime = myGlobals.actTime-((i+1)*60*60);
      strftime(labels[i], 32, "%b %d %H:%M", localtime_r(&tmpTime, &t));
    }

    for(maxBytesPerSecond=0, i=0; i<len; i++) {
      graphData[23-i] = myGlobals.device[myGlobals.actualReportDeviceId].last24HoursThpt[i].trafficValue*8 /* I want bits here */;
      if(graphData[23-i] > maxBytesPerSecond) maxBytesPerSecond = graphData[23-i];
    }

    if(maxBytesPerSecond > 1048576 /* 1024*1024 */) {
      for(i=0; i<len; i++)
	graphData[23-i] /= 1048576;
      GDC_ylabel_fmt = "%.1f Mbps";
    } else if(maxBytesPerSecond > 1024) {
      for(i=0; i<len; i++)
	graphData[23-i] /= 1024;
      GDC_ylabel_fmt = "%.1f Kbps";
    }

    GDC_title = "Last 24 Hours Average Throughput";
    out_graph(600, 300,      /* width, height           */
	      fd,/* open FILE pointer       */
	      myGlobals.throughput_chart_type,      /* chart type  */
	      24,/* num points per data set */
	      lbls,          /* X labels array of char* */
	      1, /* number of data sets     */
	      graphData);    /* dataset 1   */
    break;
  case 3: /* 30 Days */
    for(i=0; i<30; i++) {
      lbls[29-i] = labels[i];
      labels[i][0] = '\0';
    }

    len = myGlobals.device[myGlobals.actualReportDeviceId].numThptSamples/(24*60);
    if(len > 30) len = 30;
    for(i=0; i<len; i++) {
      tmpTime = myGlobals.actTime-((i+1)*(60*60*24));
      strftime(labels[i], 32, "%b %d %H:%M", localtime_r(&tmpTime, &t));
    }

    for(maxBytesPerSecond=0, i=0; i<len; i++) {
      graphData[29-i] = myGlobals.device[myGlobals.actualReportDeviceId].last30daysThpt[i]*8 /* I want bits here */;
      if(graphData[29-i] > maxBytesPerSecond) maxBytesPerSecond = graphData[29-i];
    }

    GDC_title = "Last 30 Days Average Throughput";

    if(maxBytesPerSecond > 1048576 /* 1024*1024 */) {
      for(i=0; i<len; i++)
	graphData[29-i] /= 1048576;
      GDC_ylabel_fmt = "%.1f Mbps";
    } else if(maxBytesPerSecond > 1024) {
      for(i=0; i<len; i++)
	graphData[29-i] /= 1024;
      GDC_ylabel_fmt = "%.1f Kb";
    }

    out_graph(600, 300,          /* width, height           */
	      fd,    /* open FILE pointer       */
	      myGlobals.throughput_chart_type,          /* chart type  */
	      30,    /* num points per data set */
	      lbls,  /* X labels array of char* */
	      1,     /* number of data sets     */
	      graphData);        /* dataset 1   */
    break;
  }

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.graphMutex);
#endif

  if(!useFdOpen)
    sendGraphFile(fileName);
}

/* ************************ */

void drawGlobalProtoDistribution(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  TrafficCounter ip;
  float p[256]; /* Fix courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
  char	*lbl[16];
  FILE *fd;
  int idx = 0;
  int useFdOpen = 0;

  ip.value = myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value;

  if(myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value; lbl[idx] = "TCP";  idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value; lbl[idx] = "UDP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value; lbl[idx] = "ICMP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value; lbl[idx] = "Other IP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value; lbl[idx] = "(R)ARP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes.value; lbl[idx] = "DLC"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes.value; lbl[idx] = "IPX"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].decnetBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].decnetBytes.value;lbl[idx] = "Decnet";  idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes.value; lbl[idx] = "AppleTalk"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].ospfBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].ospfBytes.value; lbl[idx] = "OSPF"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value; lbl[idx] = "NetBios"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].igmpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].igmpBytes.value; lbl[idx] = "IGMP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].osiBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].osiBytes.value; lbl[idx] = "OSI"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value; lbl[idx] = "IPv6"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value; lbl[idx] = "STP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value; lbl[idx] = "Other"; idx++; }

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "drawGlobalProtoDistribution");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  GDC_LineColor      = 0x000000L;
  GDC_BGColor        = 0xFFFFFFL;
  GDC_SetColor       = &(clr[0]);
  GDC_yaxis          = 0;
  GDC_requested_ymin = 0;
  GDC_title          = "";

  out_graph(600, 250,	/* width/height */
	    fd,	        /* open file pointer */
	    GDC_3DBAR,	/* or GDC_2DBAR */
	    idx,	/* number of slices */
	    lbl,	/* slice labels (unlike out_png(), can be NULL */
	    1,
	    p);	        /* data array */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.graphMutex);
#endif

  if(!useFdOpen)
    sendGraphFile(fileName);
}

/* ************************ */

void drawGlobalIpProtoDistribution(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  int i, idx=0;
  float p[256];
  char *lbl[256];
  FILE *fd;
  int useFdOpen = 0;

  p[myGlobals.numIpProtosToMonitor] = 0;

  for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
    p[idx]  = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local.value
      +myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote.value;
     p[idx] += (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote2local.value
      +myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local2remote.value;
    if(p[idx] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[idx];
      lbl[idx] = myGlobals.protoIPTrafficInfos[i];
      idx++;
    }
  }

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "drawGlobalIpProtoDistribution");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif

  GDC_LineColor = 0x000000L;
  GDC_BGColor   = 0xFFFFFFL;
  GDC_SetColor  = &(clr[0]);
  GDC_yaxis     = 0;
  GDC_title     = "";

  out_graph(600, 250,		/* width/height */
	    fd,			/* open file pointer */
	    GDC_3DBAR,		/* or GDC_2DBAR */
	    idx,		/* number of slices */
	    lbl,		/* slice labels (unlike out_png(), can be NULL */
	    1,
	    p);			/* data array */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.graphMutex);
#endif

  if(!useFdOpen)
    sendGraphFile(fileName);
}

/* ******************************** */

void drawHostsDistanceGraph() {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  int i, j;
  char  *lbls[32], labels[32][8];
  FILE *fd;
  float graphData[60];
  int useFdOpen = 0;

  memset(graphData, 0, sizeof(graphData));

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "drawThptGraph");
#endif

#ifndef WIN32
  /* Unices */

  if(myGlobals.newSock < 0)
    useFdOpen = 0;
  else
    useFdOpen = 1;
  
  if(useFdOpen)
    fd = fdopen(abs(myGlobals.newSock), "ab");
  else
    fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */  
#else
  fd = getNewRandomFile(fileName, NAME_MAX); /* leave it inside the mutex */
#endif


  GDC_BGColor    = 0xFFFFFFL;      /* backgound color (white) */
  GDC_LineColor  = 0x000000L;      /* line color      (black) */
  GDC_SetColor   = &(clr[1]);       /* assign set colors */
  GDC_xtitle     = "Hops (TTL)";
  GDC_ytitle     = "Hosts";
  GDC_yaxis      = 1;
  /* GDC_ylabel_fmt = "%d"; */

  for(i=0; i<=30; i++) {
    sprintf(labels[i], "%d", i);
    lbls[i] = labels[i];
    graphData[i] = 0;
  }

#ifdef MULTITHREADED
  accessMutex(&myGlobals.hostsHashMutex, "drawHostsDistanceGraph");
#endif

  for(i=1; i<myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize; i++) {
    struct hostTraffic *el;

    if(i == myGlobals.otherHostEntryIdx)
      continue;

    el = myGlobals.device[myGlobals.actualReportDeviceId].hash_hostTraffic[i];

    if((el != NULL) && (!subnetPseudoLocalHost(el))) {
      j = guessHops(el);
      if((j > 0) && (j <= 30))
	graphData[j]++;
    }
  }

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.hostsHashMutex);
#endif

  GDC_title = "";
  out_graph(300, 250,    /* width, height           */
	    fd,          /* open FILE pointer       */
	    myGlobals.throughput_chart_type,    /* chart type  */
	    30,          /* num points per data set */
	    lbls,        /* X labels array of char* */
	    1,           /* number of data sets     */
	    graphData);  /* dataset 1   */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.graphMutex);
#endif

  GDC_xtitle = GDC_ytitle     = "";

  if(!useFdOpen)
    sendGraphFile(fileName);
}

/* ************************ */

#ifdef HAVE_RRD_H
void gdImageWBMP() {; }
#endif

#endif /* HAVE_GDCHART */
#endif /* MICRO_NTOP   */
