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

void hostTrafficDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0, expl[] = { 5, 10, 15, 20, 25, 30, 35, 40,
			45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95 };
  FILE *fd;
  TrafficCounter totTraffic;

  if(dataSent) {
    totTraffic = theHost->tcpSentLoc+theHost->tcpSentRem+
      theHost->udpSentLoc+theHost->udpSentRem+
      theHost->icmpSent+theHost->ospfSent+theHost->igmpSent+theHost->stpSent
      +theHost->ipxSent+theHost->osiSent+theHost->dlcSent+
      theHost->arp_rarpSent+theHost->decnetSent+theHost->appletalkSent+
      theHost->netbiosSent+theHost->qnxSent+theHost->otherSent;
  } else {
    totTraffic = theHost->tcpRcvdLoc+theHost->tcpRcvdFromRem+
      theHost->udpRcvdLoc+theHost->udpRcvdFromRem+
      theHost->icmpRcvd+theHost->ospfRcvd+theHost->igmpRcvd+theHost->stpRcvd
      +theHost->ipxRcvd+theHost->osiRcvd+theHost->dlcRcvd+
      theHost->arp_rarpRcvd+theHost->decnetRcvd+theHost->appletalkRcvd+
      theHost->netbiosRcvd+theHost->qnxRcvd+theHost->otherRcvd;
  }

  if(totTraffic > 0) {
    if(dataSent) {
      if(theHost->tcpSentLoc+theHost->tcpSentRem > 0) {
	p[num] = (float)((100*(theHost->tcpSentLoc+
			       theHost->tcpSentRem))/totTraffic);
	lbl[num++] = "TCP";
      }

      if(theHost->udpSentLoc+theHost->udpSentRem > 0) {
	p[num] = (float)((100*(theHost->udpSentLoc+
			       theHost->udpSentRem))/totTraffic);
	lbl[num++] = "UDP";
      }

      if(theHost->icmpSent > 0) {
	p[num] = (float)((100*theHost->icmpSent)/totTraffic);
	lbl[num++] = "ICMP";
      }

      if(theHost->ospfSent > 0) {
	p[num] = (float)((100*theHost->ospfSent)/totTraffic);
	lbl[num++] = "OSPF";
      }

      if(theHost->igmpSent > 0) {
	p[num] = (float)((100*theHost->igmpSent)/totTraffic);
	lbl[num++] = "IGMP";
      }

      if(theHost->stpSent > 0) {
	p[num] = (float)((100*theHost->stpSent)/totTraffic);
	lbl[num++] = "STP";
      }

      if(theHost->ipxSent > 0) {
	p[num] = (float)((100*theHost->ipxSent)/totTraffic);
	lbl[num++] = "IPX";
      }

      if(theHost->dlcSent > 0) {
	p[num] = (float)((100*theHost->dlcSent)/totTraffic);
	lbl[num++] = "DLC";
      }

      if(theHost->osiSent > 0) {
	p[num] = (float)((100*theHost->osiSent)/totTraffic);
	lbl[num++] = "OSI";
      }

      if(theHost->arp_rarpSent > 0) {
	p[num] = (float)((100*theHost->arp_rarpSent)/totTraffic);
	lbl[num++] = "(R)ARP";
      }

      if(theHost->decnetSent > 0) {
	p[num] = (float)((100*theHost->decnetSent)/totTraffic);
	lbl[num++] = "DECNET";
      }

      if(theHost->appletalkSent > 0) {
	p[num] = (float)((100*theHost->appletalkSent)/totTraffic);
	lbl[num++] = "AppleTalk";
      }

      if(theHost->netbiosSent > 0) {
	p[num] = (float)((100*theHost->netbiosSent)/totTraffic);
	lbl[num++] = "NetBios";
      }

      if(theHost->qnxSent > 0) {
	p[num] = (float)((100*theHost->qnxSent)/totTraffic);
	lbl[num++] = "QNX";
      }

      if(theHost->otherSent > 0) {
	p[num] = (float)((100*theHost->otherSent)/totTraffic);
	lbl[num++] = "Other";
      }
    } else {
      if(theHost->tcpRcvdLoc+theHost->tcpRcvdFromRem > 0) {
	p[num] = (float)((100*(theHost->tcpRcvdLoc+
			       theHost->tcpRcvdFromRem))/totTraffic);
	lbl[num++] = "TCP";
      }

      if(theHost->udpRcvdLoc+theHost->udpRcvdFromRem > 0) {
	p[num] = (float)((100*(theHost->udpRcvdLoc+
			       theHost->udpRcvdFromRem))/totTraffic);
	lbl[num++] = "UDP";
      }

      if(theHost->icmpRcvd > 0) {
	p[num] = (float)((100*theHost->icmpRcvd)/totTraffic);
	lbl[num++] = "ICMP";
      }

      if(theHost->ospfRcvd > 0) {
	p[num] = (float)((100*theHost->ospfRcvd)/totTraffic);
	lbl[num++] = "OSPF";
      }

      if(theHost->igmpRcvd > 0) {
	p[num] = (float)((100*theHost->igmpRcvd)/totTraffic);
	lbl[num++] = "IGMP";
      }

      if(theHost->stpRcvd > 0) {
	p[num] = (float)((100*theHost->stpRcvd)/totTraffic);
	lbl[num++] = "STP";
      }

      if(theHost->ipxRcvd > 0) {
	p[num] = (float)((100*theHost->ipxRcvd)/totTraffic);
	lbl[num++] = "IPX";
      }

      if(theHost->dlcRcvd > 0) {
	p[num] = (float)((100*theHost->dlcRcvd)/totTraffic);
	lbl[num++] = "DLC";
      }

      if(theHost->osiRcvd > 0) {
	p[num] = (float)((100*theHost->osiRcvd)/totTraffic);
	lbl[num++] = "OSI";
      }

      if(theHost->arp_rarpRcvd > 0) {
	p[num] = (float)((100*theHost->arp_rarpRcvd)/totTraffic);
	lbl[num++] = "(R)ARP";
      }

      if(theHost->decnetRcvd > 0) {
	p[num] = (float)((100*theHost->decnetRcvd)/totTraffic);
	lbl[num++] = "DECNET";
      }

      if(theHost->appletalkRcvd > 0) {
	p[num] = (float)((100*theHost->appletalkRcvd)/totTraffic);
	lbl[num++] = "AppleTalk";
      }

      if(theHost->netbiosRcvd > 0) {
	p[num] = (float)((100*theHost->netbiosRcvd)/totTraffic);
	lbl[num++] = "NetBios";
      }

      if(theHost->qnxRcvd > 0) {
	p[num] = (float)((100*theHost->qnxRcvd)/totTraffic);
	lbl[num++] = "QNX";
      }

      if(theHost->otherRcvd > 0) {
	p[num] = (float)((100*theHost->otherRcvd)/totTraffic);
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

    fd = fdopen(abs(myGlobals.newSock), "ab");

    GDCPIE_LineColor = 0x000000L;
    GDCPIE_explode   = expl;    /* default: NULL - no explosion */
    GDCPIE_Color     = clr;
    GDCPIE_BGColor   = 0xFFFFFFL;
    GDCPIE_EdgeColor = 0x000000L;	/* default is GDCPIE_NOCOLOR */
    GDCPIE_percent_labels = GDCPIE_PCT_NONE;

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
  }
}

/* ************************ */

void hostFragmentDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0, expl[] = { 5, 10, 15, 20, 25, 30, 35, 40,
			45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95 };
  FILE *fd;
  TrafficCounter totTraffic;

  if(dataSent)
    totTraffic = theHost->tcpFragmentsSent+theHost->udpFragmentsSent+theHost->icmpFragmentsSent;
  else
    totTraffic = theHost->tcpFragmentsRcvd+theHost->udpFragmentsRcvd+theHost->icmpFragmentsRcvd;

  if(totTraffic > 0) {
    if(dataSent) {
      if(theHost->tcpFragmentsSent > 0) {
	p[num] = (float)((100*(theHost->tcpFragmentsSent))/totTraffic);
	lbl[num++] = "TCP";
      }

      if(theHost->udpFragmentsSent > 0) {
	p[num] = (float)((100*(theHost->udpFragmentsSent))/totTraffic);
	lbl[num++] = "UDP";
      }

      if(theHost->icmpFragmentsSent > 0) {
	p[num] = (float)((100*(theHost->icmpFragmentsSent))/totTraffic);
	lbl[num++] = "ICMP";
      }
    } else {
      if(theHost->tcpFragmentsRcvd > 0) {
	p[num] = (float)((100*(theHost->tcpFragmentsRcvd))/totTraffic);
	lbl[num++] = "TCP";
      }

      if(theHost->udpFragmentsRcvd > 0) {
	p[num] = (float)((100*(theHost->udpFragmentsRcvd))/totTraffic);
	lbl[num++] = "UDP";
      }

      if(theHost->icmpFragmentsRcvd > 0) {
	p[num] = (float)((100*(theHost->icmpFragmentsRcvd))/totTraffic);
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

    fd = fdopen(abs(myGlobals.newSock), "ab");

    GDCPIE_LineColor = 0x000000L;
    GDCPIE_explode   = expl;    /* default: NULL - no explosion */
    GDCPIE_Color     = clr;
    GDCPIE_BGColor   = 0xFFFFFFL;
    GDCPIE_EdgeColor = 0x000000L;	/* default is GDCPIE_NOCOLOR */
    GDCPIE_percent_labels = GDCPIE_PCT_NONE;

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
  }
}

/* ************************ */

void hostTotalFragmentDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0, expl[] = { 5, 10, 15, 20, 25, 30, 35, 40,
			45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95 };
  FILE *fd;
  TrafficCounter totFragmentedTraffic, totTraffic;

  if(dataSent) {
    totTraffic = theHost->ipBytesSent;
    totFragmentedTraffic = theHost->tcpFragmentsSent+theHost->udpFragmentsSent
      +theHost->icmpFragmentsSent;
  } else {
    totTraffic = theHost->ipBytesRcvd;
    totFragmentedTraffic = theHost->tcpFragmentsRcvd+theHost->udpFragmentsRcvd
      +theHost->icmpFragmentsRcvd;
  }

  if(totTraffic > 0) {
    p[num] = (float)((100*totFragmentedTraffic)/totTraffic);
    lbl[num++] = "Frag";

    p[num] = 100-((float)(100*totFragmentedTraffic)/totTraffic);
    if(p[num] > 0) { lbl[num++] = "Non Frag"; }

    if(num == 0) {
      traceEvent(TRACE_WARNING, "WARNING: Graph failure (3)");
      return; /* TODO: this has to be handled better */
    }

#ifdef MULTITHREADED
    accessMutex(&myGlobals.graphMutex, "pktHostFragmentDistrib");
#endif

    fd = fdopen(abs(myGlobals.newSock), "ab");

    GDCPIE_LineColor      = 0x000000L;
    GDCPIE_explode        = expl;      /* default: NULL - no explosion */
    GDCPIE_Color          = clr;
    GDCPIE_BGColor        = 0xFFFFFFL;
    GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
    GDCPIE_percent_labels = GDCPIE_PCT_NONE;

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
  }
}

/* ************************ */

void hostIPTrafficDistrib(HostTraffic *theHost, short dataSent) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int i, num=0, expl[20];
  FILE *fd;
  TrafficCounter traffic, totalIPTraffic;

  if(theHost->protoIPTrafficInfos == NULL) {
    traceEvent(TRACE_WARNING, "WARNING: Graph failure (5)");
    return;
  }

#ifdef ENABLE_NAPSTER
  if(theHost->napsterStats == NULL)
    totalIPTraffic = 0;
  else {
    if(dataSent)
      totalIPTraffic = theHost->napsterStats->bytesSent;
    else
      totalIPTraffic = theHost->napsterStats->bytesRcvd;
  }
#else
  totalIPTraffic = 0;
#endif

  for(i=0; i<myGlobals.numIpProtosToMonitor; i++)
    if(dataSent)
      totalIPTraffic += theHost->protoIPTrafficInfos[i].sentLoc+
	theHost->protoIPTrafficInfos[i].sentRem;
    else
      totalIPTraffic += theHost->protoIPTrafficInfos[i].rcvdLoc+
	theHost->protoIPTrafficInfos[i].rcvdFromRem;

#ifdef ENABLE_NAPSTER
  if(theHost->napsterStats != NULL) {
    if(dataSent) {
      if(theHost->napsterStats->bytesSent > 0) {
	p[num] = (float)((100*theHost->napsterStats->bytesSent)/totalIPTraffic);
	lbl[num++] = "Napster";
      }
    } else {
      if(theHost->napsterStats->bytesRcvd > 0) {
	p[num] = (float)((100*theHost->napsterStats->bytesRcvd)/totalIPTraffic);
	lbl[num++] = "Napster";
      }
    }
  }
#endif

  if(totalIPTraffic > 0) {
    for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
      if(dataSent)
	traffic = theHost->protoIPTrafficInfos[i].sentLoc+
	  theHost->protoIPTrafficInfos[i].sentRem;
      else
	traffic = theHost->protoIPTrafficInfos[i].rcvdLoc+
	  theHost->protoIPTrafficInfos[i].rcvdFromRem;

      if(traffic > 0) {
	p[num] = (float)((100*traffic)/totalIPTraffic);

        if(num==0)
          expl[num]=10;
        else
          expl[num]=expl[num-1];
	if (p[num]<5.0)
	  expl[num]+=9;
	else if (p[num]>10.0)
	  expl[num]=10;

	lbl[num++] = myGlobals.protoIPTrafficInfos[i];
      }

      if(num >= 20) break; /* Too much stuff */
   }
  }

  if(num == 0) {
    traceEvent(TRACE_WARNING, "WARNING: Graph failure (4)");
    return; /* TODO: this has to be handled better */
  }

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "pktHostTrafficDistrib");
#endif

  fd = fdopen(abs(myGlobals.newSock), "ab");

  GDCPIE_LineColor      = 0x000000L;
  GDCPIE_explode        = expl;    /* default: NULL - no explosion */
  GDCPIE_Color          = clr;
  GDCPIE_BGColor        = 0xFFFFFFL;
  GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_NONE;

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
}

/* ********************************** */

void pktSizeDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[7];
  char	*lbl[] = { "", "", "", "", "", "", "" };
  int num=0, expl[] = { 5, 10, 15, 20, 25, 30, 35 };
  FILE *fd;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts;
    lbl[num++] = "< 64";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts;
    lbl[num++] = "< 128";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts;
    lbl[num++] = "< 256";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts;
    lbl[num++] = "< 512";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts;
    lbl[num++] = "< 1024";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts;
    lbl[num++] = "< 1518";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts;
    lbl[num++] = "> 1518";
  };


#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "pktSizeDistrib");
#endif

  fd = fdopen(abs(myGlobals.newSock), "ab");

  GDCPIE_LineColor      = 0x000000L;
  GDCPIE_explode        = expl;    /* default: NULL - no explosion */
  GDCPIE_Color          = clr;
  GDCPIE_BGColor        = 0xFFFFFFL;
  GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_NONE;

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
}

/* ********************************** */

void pktTTLDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[8];
  char	*lbl[] = { "", "", "", "", "", "", "" };
  int num=0, expl[] = { 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55 };
  FILE *fd;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts;
    lbl[num++] = "< 32";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts;
    lbl[num++] = "< 64";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts;
    lbl[num++] = "< 96";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts;
    lbl[num++] = "< 128";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts;
    lbl[num++] = "< 160";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts;
    lbl[num++] = "< 192";
  };

 if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts;
    lbl[num++] = "< 224";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo255 > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo255)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts;
    lbl[num++] = "<= 255";
  };

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "pktSizeDistrib");
#endif

  fd = fdopen(abs(myGlobals.newSock), "ab");

  GDCPIE_LineColor      = 0x000000L;
  GDCPIE_explode        = expl;    /* default: NULL - no explosion */
  GDCPIE_Color          = clr;
  GDCPIE_BGColor        = 0xFFFFFFL;
  GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_NONE;

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
}

/* ************************ */

void ipProtoDistribPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[3];
  char	*lbl[] = { "Loc", "Rem->Loc", "Loc->Rem" };
  int num=0, expl[] = { 0, 20, 30 };
  FILE *fd;

  p[num] = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local+
		   myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.local)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Loc";
  }

  p[num] = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.remote2local+
		   myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.remote2local)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Rem->Loc";
  }

  p[num] = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local2remote+
		   myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.local2remote)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Loc->Rem";
  }

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "ipProtoDistribPie");
#endif

  fd = fdopen(abs(myGlobals.newSock), "ab");

  GDCPIE_LineColor      = 0x000000L;
  GDCPIE_explode        = expl;    /* default: NULL - no explosion */
  GDCPIE_Color          = clr;
  GDCPIE_BGColor        = 0xFFFFFFL;
  GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_NONE;

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
}

/* ************************ */

void interfaceTrafficPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[MAX_NUM_DEVICES];
  int i, expl[MAX_NUM_DEVICES];
  FILE *fd;
  TrafficCounter totPkts=0;
  struct pcap_stat stat;
  char	*lbl[MAX_NUM_DEVICES];
  int myDevices=0;

  for(i=0; i<myGlobals.numDevices; i++)
    if(!myGlobals.device[i].virtualDevice) {
      if (pcap_stats(myGlobals.device[i].pcapPtr, &stat) >= 0) {
	p[i] = (float)stat.ps_recv;
	totPkts += stat.ps_recv;
      }
      expl[i] = 10*i;
    }

  if(totPkts == 0)
    totPkts++;

  for(i=0; i<myGlobals.numDevices; i++) {
    if((!myGlobals.device[i].virtualDevice) && (p[i] > 0))  {
      p[myDevices]   = 100*(((float)p[i])/totPkts);
      lbl[myDevices] = myGlobals.device[i].name;
      myDevices++;
    }
  }

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "interfaceTrafficPie");
#endif

  fd = fdopen(abs(myGlobals.newSock), "ab");

  GDCPIE_LineColor      = 0x000000L;
  GDCPIE_explode        = expl;
  GDCPIE_Color          = clr;
  GDCPIE_BGColor        = 0xFFFFFFL;
  GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_RIGHT;

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
}

/* ************************ */

void pktCastDistribPie(void) {
  char fileName[64] = "/tmp/graph-XXXXXX";
  float p[3];
  char	*lbl[] = { "", "", "" };
  int num=0, expl[] = { 0, 20, 30 };
  FILE *fd;
  TrafficCounter unicastPkts;

  unicastPkts = myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts
    - myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts
    - myGlobals.device[myGlobals.actualReportDeviceId]. multicastPkts;

  if(unicastPkts > 0) {
    p[num] = (float)(100*unicastPkts)/(float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts;
    lbl[num++] = "Unicast";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts;
    lbl[num++] = "Broadcast";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts > 0) {
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

  fd = fdopen(abs(myGlobals.newSock), "ab");

  GDCPIE_LineColor      = 0x000000L;
  GDCPIE_explode        = expl;    /* default: NULL - no explosion */
  GDCPIE_Color          = clr;
  GDCPIE_BGColor        = 0xFFFFFFL;
  GDCPIE_EdgeColor      = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_NONE;

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
}

/* ************************ */

void drawTrafficPie(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  TrafficCounter ip, nonIp;
  float p[2];
  char	*lbl[] = { "IP", "Non IP" };
  int num=0, expl[] = { 5, 5 };
  FILE *fd;

  if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes == 0) return;

  ip = myGlobals.device[myGlobals.actualReportDeviceId].ipBytes;
  nonIp = myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes-myGlobals.device[myGlobals.actualReportDeviceId].ipBytes;

  p[0] = ip*100/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes; num++;
  p[1] = 100-p[0];

  if(p[1] > 0)
    num++;

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "drawTrafficPie");
#endif

  fd = fdopen(abs(myGlobals.newSock), "ab");

  GDCPIE_LineColor = 0x000000L;
  GDCPIE_BGColor   = 0xFFFFFFL;
  GDCPIE_EdgeColor = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_explode   = expl;    /* default: NULL - no explosion */
  GDCPIE_Color     = clr;

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

  memset(graphData, 0, sizeof(graphData));

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "drawThptGraph");
#endif

  fd = fdopen(abs(myGlobals.newSock), "ab");

  GDC_BGColor    = 0xFFFFFFL;                  /* backgound color (white) */
  GDC_LineColor  = 0x000000L;                  /* line color      (black) */
  GDC_SetColor   = &(clr[0]);                   /* assign set colors */
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
	      myGlobals.throughput_chart_type,    /* chart type              */
	      60,          /* num points per data set */
	      lbls,        /* X labels array of char* */
	      1,           /* number of data sets     */
	      graphData);  /* dataset 1               */
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
	      fd,            /* open FILE pointer       */
	      myGlobals.throughput_chart_type,      /* chart type              */
	      24,            /* num points per data set */
	      lbls,          /* X labels array of char* */
	      1,             /* number of data sets     */
	      graphData);    /* dataset 1               */
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
	      fd,                /* open FILE pointer       */
	      myGlobals.throughput_chart_type,          /* chart type              */
	      30,                /* num points per data set */
	      lbls,              /* X labels array of char* */
	      1,                 /* number of data sets     */
	      graphData);        /* dataset 1               */
    break;
  }

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&myGlobals.graphMutex);
#endif
}


/* ************************ */

void drawGlobalProtoDistribution(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  TrafficCounter ip, nonIp;
  float p[256]; /* Fix courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
  char	*lbl[16];
  FILE *fd;
  int idx = 0;

  ip = myGlobals.device[myGlobals.actualReportDeviceId].ipBytes;
  nonIp = myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes-myGlobals.device[myGlobals.actualReportDeviceId].ipBytes;

  if(myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes; lbl[idx] = "TCP";  idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].udpBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].udpBytes; lbl[idx] = "UDP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes; lbl[idx] = "ICMP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes; lbl[idx] = "Other IP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes; lbl[idx] = "(R)ARP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes; lbl[idx] = "DLC"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes; lbl[idx] = "IPX"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].decnetBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].decnetBytes;lbl[idx] = "Decnet";  idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes; lbl[idx] = "AppleTalk"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].ospfBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].ospfBytes; lbl[idx] = "OSPF"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes; lbl[idx] = "NetBios"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].igmpBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].igmpBytes; lbl[idx] = "IGMP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].osiBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].osiBytes; lbl[idx] = "OSI"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].qnxBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].qnxBytes; lbl[idx] = "QNX"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].otherBytes > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].otherBytes; lbl[idx] = "Other"; idx++; }

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "drawGlobalProtoDistribution");
#endif

  fd = fdopen(abs(myGlobals.newSock), "ab");

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
}

/* ************************ */

void drawGlobalIpProtoDistribution(void) {
  char fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  int i, idx=0;
  float p[256];
  char *lbl[256];
  FILE *fd;

  p[myGlobals.numIpProtosToMonitor] = 0;

  for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
    p[idx]  = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local
      +myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote;
     p[idx] += (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote2local
      +myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local2remote;
    if(p[idx] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[idx];
      lbl[idx] = myGlobals.protoIPTrafficInfos[i];
      idx++;
    }
  }

#ifdef MULTITHREADED
  accessMutex(&myGlobals.graphMutex, "drawGlobalIpProtoDistribution");
#endif

  fd = fdopen(abs(myGlobals.newSock), "ab");

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
}

#endif /* HAVE_GDCHART */
#endif /* MICRO_NTOP   */
