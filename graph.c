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

 /*
  * Do not use local defs for pnggraph
  * (included by ntop.h)
  */

#include "ntop.h"

#ifdef HAVE_GDCHART

#define _GRAPH_C_
#include "globals-report.h"
static unsigned long clr[] = { 0x0000FF, 0x00FF00, 0xFF0000,
			       0xFF4040L, 0x80FF80L, 0x8080FFL,
			       0xFF80FFL, 0xFFFF80L, 0x80FFFFL,
			       0x0080FFL };

/* ************************ */

void pktSizeDistribPie(void) {
  char tmpStr[256], fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[7];
  char	*lbl[] = { "", "", "", "", "", "", "" };
  int len, num=0, expl[] = { 5, 10, 15, 20, 25, 30, 35 };
  FILE *fd;

  fd = getNewRandomFile(fileName, NAME_MAX);

  if(device[actualReportDeviceId].rcvdPktStats.upTo64 > 0) {
    p[num] = (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo64)/
      (float)device[actualReportDeviceId].ethernetPkts;
    lbl[num++] = "< 64";
  };

  if(device[actualReportDeviceId].rcvdPktStats.upTo128 > 0) {
    p[num] = (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo128)/
      (float)device[actualReportDeviceId].ethernetPkts;
    lbl[num++] = "< 128";
  };

  if(device[actualReportDeviceId].rcvdPktStats.upTo256 > 0) {
    p[num] = (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo256)/
      (float)device[actualReportDeviceId].ethernetPkts;
    lbl[num++] = "< 256";
  };

  if(device[actualReportDeviceId].rcvdPktStats.upTo512 > 0) {
    p[num] = (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo512)/
      (float)device[actualReportDeviceId].ethernetPkts;
    lbl[num++] = "< 512";
  };

  if(device[actualReportDeviceId].rcvdPktStats.upTo1024 > 0) {
    p[num] = (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo1024)/
      (float)device[actualReportDeviceId].ethernetPkts;
    lbl[num++] = "< 1024";
  };

  if(device[actualReportDeviceId].rcvdPktStats.upTo1518 > 0) {
    p[num] = (float)(100*device[actualReportDeviceId].rcvdPktStats.upTo1518)/
      (float)device[actualReportDeviceId].ethernetPkts;
    lbl[num++] = "< 1518";
  };

  if(device[actualReportDeviceId].rcvdPktStats.above1518 > 0) {
    p[num] = (float)(100*device[actualReportDeviceId].rcvdPktStats.above1518)/
      (float)device[actualReportDeviceId].ethernetPkts;
    lbl[num++] = "> 1518";
  };


  GDCPIE_LineColor = 0x000000L;
  GDCPIE_explode   = expl;    /* default: NULL - no explosion */
  GDCPIE_Color     = clr;
  GDCPIE_BGColor   = 0xFFFFFFL;
  GDCPIE_EdgeColor = 0x000000L;	/* default is GDCPIE_NOCOLOR */
  GDCPIE_percent_labels = GDCPIE_PCT_NONE;

#ifdef MULTITHREADED
  accessMutex(&graphMutex, "pktSizeDistrib");
#endif

  GDC_out_pie(250,			/* width */
	      250,			/* height */
	      fd,			/* open file pointer */
	      GDC_3DPIE,		/* or GDC_2DPIE */
	      num,			/* number of slices */
	      lbl,			/* slice labels (unlike out_png(), can be NULL */
	      p);			/* data array */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&graphMutex);
#endif

  if((fd = fopen(fileName, "rb")) != NULL) {
    for(;;) {
      len = fread(tmpStr, sizeof(char), 255, fd);
      if(len <= 0) break;
      sendStringLen(tmpStr, len);
    }

    fclose(fd);
  }

  unlink(fileName);
}

/* ************************ */

void ipProtoDistribPie(void) {
  char tmpStr[256], fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[3];
  char	*lbl[] = { "Loc", "Rem->Loc", "Loc->Rem" };
  int len, num=0, expl[] = { 0, 20, 30 };
  FILE *fd;
  TrafficCounter unicastPkts;

  fd = getNewRandomFile(fileName, NAME_MAX);

  unicastPkts = device[actualReportDeviceId].ethernetPkts
    - device[actualReportDeviceId].broadcastPkts
    - device[actualReportDeviceId].multicastPkts;

  p[num] = (float)(device[actualReportDeviceId].tcpGlobalTrafficStats.local+
		   device[actualReportDeviceId].udpGlobalTrafficStats.local)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Loc";
  }

  p[num] = (float)(device[actualReportDeviceId].tcpGlobalTrafficStats.remote2local+
		   device[actualReportDeviceId].udpGlobalTrafficStats.remote2local)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Rem->Loc";
  }

  p[2] = 100-p[0]-p[1]; if(p[2] < 0) p[2] = 0;
  if(p[num] > 0) {
    lbl[num++] = "Loc->Rem";
  }

#ifdef MULTITHREADED
  accessMutex(&graphMutex, "ipProtoDistribPie");
#endif

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
  releaseMutex(&graphMutex);
#endif

  if((fd = fopen(fileName, "rb")) != NULL) {
    for(;;) {
      len = fread(tmpStr, sizeof(char), 255, fd);
      if(len <= 0) break;
      sendStringLen(tmpStr, len);
    }

    fclose(fd);
  }

  unlink(fileName);
}

/* ************************ */

void interfaceTrafficPie(void) {
  char tmpStr[256], fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  float p[MAX_NUM_DEVICES];
  int i, len, expl[MAX_NUM_DEVICES];
  FILE *fd;
  TrafficCounter totPkts=0;
  struct pcap_stat stat;
  char	*lbl[MAX_NUM_DEVICES];
  int myDevices=0;

  fd = getNewRandomFile(fileName, NAME_MAX);

  for(i=0; i<numDevices; i++)     
    if(!device[i].virtualDevice) {
      if (pcap_stats(device[i].pcapPtr, &stat) >= 0) {
	p[i] = (float)stat.ps_recv;
	totPkts += stat.ps_recv;
      }
      expl[i] = 10*i;
    }
  
  if(totPkts == 0)
    totPkts++;

  for(i=0; i<numDevices; i++) {
    if((!device[i].virtualDevice) && (p[i] > 0))  {
      p[myDevices]   = 100*(((float)p[i])/totPkts);
      lbl[myDevices] = device[i].name;
      myDevices++;
    }
  }

#ifdef MULTITHREADED
  accessMutex(&graphMutex, "interfaceTrafficPie");
#endif

  GDCPIE_LineColor = 0x000000L;
  GDCPIE_explode   = expl;
  GDCPIE_Color     = clr;
  GDCPIE_BGColor   = 0xFFFFFFL;
  GDCPIE_EdgeColor = 0x000000L;	/* default is GDCPIE_NOCOLOR */
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
  releaseMutex(&graphMutex);
#endif

  if((fd = fopen(fileName, "rb")) != NULL) {
    for(;;) {
      len = fread(tmpStr, sizeof(char), 255, fd);
      if(len <= 0) break;
      sendStringLen(tmpStr, len);
    }
     
    fclose(fd);
  }

  unlink(fileName);
}

/* ************************ */

void pktCastDistribPie(void) {
  char tmpStr[256], fileName[64] = "/tmp/graph-XXXXXX";
  float p[3];
  char	*lbl[] = { "", "", "" };
  int len, num=0, expl[] = { 0, 20, 30 };
  FILE *fd;
  TrafficCounter unicastPkts;

  fd = getNewRandomFile(fileName, NAME_MAX);

  unicastPkts = device[actualReportDeviceId].ethernetPkts
    - device[actualReportDeviceId].broadcastPkts
    - device[actualReportDeviceId]. multicastPkts;

  if(unicastPkts > 0) {
    p[num] = (float)(100*unicastPkts)/(float)device[actualReportDeviceId].ethernetPkts;
    lbl[num++] = "Unicast";
  };

  if(device[actualReportDeviceId].broadcastPkts > 0) {
    p[num] = (float)(100*device[actualReportDeviceId].broadcastPkts)/(float)device[actualReportDeviceId].ethernetPkts;
    lbl[num++] = "Broadcast";
  };

  if(device[actualReportDeviceId].multicastPkts > 0) {
    int i;

    p[num] = 100;
    for(i=0; i<num; i++)
      p[num] -= p[i];

    if(p[num] < 0) p[num] = 0;
    lbl[num++] = "Multicast";
  };


#ifdef MULTITHREADED
  accessMutex(&graphMutex, "pktCastDistribPie");
#endif

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
  releaseMutex(&graphMutex);
#endif

  if((fd = fopen(fileName, "rb")) != NULL) {
    for(;;) {
      len = fread(tmpStr, sizeof(char), 255, fd);
      if(len <= 0) break;
      sendStringLen(tmpStr, len);
    }

    fclose(fd);
  }

  unlink(fileName);
}

/* ************************ */

void drawTrafficPie(void) {
  char tmpStr[256], fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  TrafficCounter ip, nonIp;
  float p[2];
  char	*lbl[] = { "IP", "Non IP" };
  int num=0, len, expl[] = { 5, 5 };
  FILE *fd;

  fd = getNewRandomFile(fileName, NAME_MAX);

  ip = device[actualReportDeviceId].ipBytes;
  nonIp = device[actualReportDeviceId].ethernetBytes-device[actualReportDeviceId].ipBytes;

  p[0] = ip*100/(device[actualReportDeviceId].ethernetBytes+1); num++;
  p[1] = 100-p[0];

  if(p[1] > 0)
    num++;

#ifdef MULTITHREADED
  accessMutex(&graphMutex, "drawTrafficPie");
#endif

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
  releaseMutex(&graphMutex);
#endif

  if((fd = fopen(fileName, "rb")) != NULL) {
    for(;;) {
      len = fread(tmpStr, sizeof(char), 255, fd);
      if(len <= 0) break;
      sendStringLen(tmpStr, len);
    }

    fclose(fd);
  }

  unlink(fileName);
}

/* ************************ */

void drawThptGraph(int sortedColumn) {
  char tmpStr[256], fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  int i, len;
  char  labels[60][32];
  char  *lbls[60];
  FILE *fd;
  time_t tmpTime;
  unsigned long  sc[2]    = { 0xFF0000, 0x8080FF };
  float graphData[60], maxData;
  struct tm t;

#ifdef MULTITHREADED
  accessMutex(&graphMutex, "drawThptGraph");
#endif

  memset(graphData, 0, sizeof(graphData));

  GDC_BGColor   = 0xFFFFFFL;                  /* backgound color (white) */
  GDC_LineColor = 0x000000L;                  /* line color      (black) */
  GDC_SetColor  = &(sc[0]);                   /* assign set colors */
  GDC_ytitle = "Throughput";
  GDC_yaxis=1;
  GDC_ylabel_fmt = "%d Bps";

  fd = getNewRandomFile(fileName, NAME_MAX);

  switch(sortedColumn) {
  case 1: /* 60 Minutes */
    for(i=0; i<60; i++) {
      lbls[59-i] = labels[i];
      labels[i][0] = '\0';
    }

    len = device[actualReportDeviceId].numThptSamples;
    if(len > 60) len = 60;
    for(i=0; i<len; i++) {
      tmpTime = actTime-i*60;
      strftime(labels[i], 32, "%H:%M", localtime_r(&tmpTime, &t));
    }

    for(maxData=0, i=0; i<len; i++) {
      graphData[59-i] = device[actualReportDeviceId].last60MinutesThpt[i].trafficValue;
      if(graphData[59-i] > maxData) maxData = graphData[59-i];
    }

    if(maxData > 1048576 /* 1024*1024 */) {
      for(i=0; i<len; i++)
	graphData[59-i] /= 1048576;
      GDC_ylabel_fmt = "%.1f Mbps";
    } else if(maxData > 1024) {
      for(i=0; i<len; i++)
	graphData[59-i] /= 1024;
      GDC_ylabel_fmt = "%.1f Kbps";
    }

    GDC_title = "Last 60 Minutes Average Throughput";
    out_graph(600, 300,    /* width, height           */
	      fd,          /* open FILE pointer       */
	      GDC_AREA,    /* chart type              */
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

    len = device[actualReportDeviceId].numThptSamples/60;
    if(len > 24) len = 24;
    for(i=0; i<len; i++) {
      tmpTime = actTime-((i+1)*60*60);
      strftime(labels[i], 32, "%b %d %H:%M", localtime_r(&tmpTime, &t));
    }

    for(maxData=0, i=0; i<len; i++) {
      graphData[23-i] = device[actualReportDeviceId].last24HoursThpt[i].trafficValue;
      if(graphData[23-i] > maxData) maxData = graphData[23-i];
    }

    if(maxData > 1048576 /* 1024*1024 */) {
      for(i=0; i<len; i++)
	graphData[23-i] /= 1048576;
      GDC_ylabel_fmt = "%.1f Mbps";
    } else if(maxData > 1024) {
      for(i=0; i<len; i++)
	graphData[23-i] /= 1024;
      GDC_ylabel_fmt = "%.1f Kbps";
    }

    GDC_title = "Last 24 Hours Average Throughput";
    out_graph(600, 300,      /* width, height           */
	      fd,            /* open FILE pointer       */
	      GDC_AREA,      /* chart type              */
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

    len = device[actualReportDeviceId].numThptSamples/(24*60);
    if(len > 30) len = 30;
    for(i=0; i<len; i++) {
      tmpTime = actTime-((i+1)*(60*60*24));
      strftime(labels[i], 32, "%b %d %H:%M", localtime_r(&tmpTime, &t));
    }

    for(maxData=0, i=0; i<len; i++) {
      graphData[29-i] = device[actualReportDeviceId].last30daysThpt[i];
      if(graphData[29-i] > maxData) maxData = graphData[29-i];
    }

    GDC_title = "Last 30 Days Average Throughput";

    if(maxData > 1048576 /* 1024*1024 */) {
      for(i=0; i<len; i++)
	graphData[29-i] /= 1048576;
      GDC_ylabel_fmt = "%.1f Mbps";
    } else if(maxData > 1024) {
      for(i=0; i<len; i++)
	graphData[29-i] /= 1024;
      GDC_ylabel_fmt = "%.1f Kb";
    }

    out_graph(600, 300,          /* width, height           */
	      fd,                /* open FILE pointer       */
	      GDC_AREA,          /* chart type              */
	      30,                /* num points per data set */
	      lbls,              /* X labels array of char* */
	      1,                 /* number of data sets     */
	      graphData);        /* dataset 1               */
    break;
  }

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&graphMutex);
#endif

  if((fd = fopen(fileName, "rb")) != NULL) {
    for(;;) {
      len = fread(tmpStr, sizeof(char), 255, fd);
      if(len <= 0) break;
      sendStringLen(tmpStr, len);
    }

    fclose(fd);
  }

  unlink(fileName);
}


/* ************************ */

void drawGlobalProtoDistribution(void) {
  char tmpStr[256], fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  TrafficCounter ip, nonIp;
  int len, totLen;
  float p[256]; /* Fix courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */
  unsigned long sc = 0xC8C8FF;
  char	*lbl[16];
  FILE *fd;
  int idx = 0;

  ip = device[actualReportDeviceId].ipBytes;
  nonIp = device[actualReportDeviceId].ethernetBytes-device[actualReportDeviceId].ipBytes;

  fd = getNewRandomFile(fileName, NAME_MAX);

  if(device[actualReportDeviceId].tcpBytes > 0) {
    p[idx] = device[actualReportDeviceId].tcpBytes; lbl[idx] = "TCP";  idx++; }
  if(device[actualReportDeviceId].udpBytes > 0) {
    p[idx] = device[actualReportDeviceId].udpBytes; lbl[idx] = "UDP"; idx++; }
  if(device[actualReportDeviceId].icmpBytes > 0) {
    p[idx] = device[actualReportDeviceId].icmpBytes; lbl[idx] = "ICMP"; idx++; }
  if(device[actualReportDeviceId].otherIpBytes > 0) {
    p[idx] = device[actualReportDeviceId].otherIpBytes; lbl[idx] = "Other IP"; idx++; }
  if(device[actualReportDeviceId].arpRarpBytes > 0) {
    p[idx] = device[actualReportDeviceId].arpRarpBytes; lbl[idx] = "(R)ARP"; idx++; }
  if(device[actualReportDeviceId].dlcBytes > 0) {
    p[idx] = device[actualReportDeviceId].dlcBytes; lbl[idx] = "DLC"; idx++; }
  if(device[actualReportDeviceId].ipxBytes > 0) {
    p[idx] = device[actualReportDeviceId].ipxBytes; lbl[idx] = "IPX"; idx++; }
  if(device[actualReportDeviceId].decnetBytes > 0) {
    p[idx] = device[actualReportDeviceId].decnetBytes;lbl[idx] = "Decnet";  idx++; }
  if(device[actualReportDeviceId].atalkBytes > 0) {
    p[idx] = device[actualReportDeviceId].atalkBytes; lbl[idx] = "AppleTalk"; idx++; }
  if(device[actualReportDeviceId].ospfBytes > 0) {
    p[idx] = device[actualReportDeviceId].ospfBytes; lbl[idx] = "OSPF"; idx++; }
  if(device[actualReportDeviceId].netbiosBytes > 0) {
    p[idx] = device[actualReportDeviceId].netbiosBytes; lbl[idx] = "NetBios"; idx++; }
  if(device[actualReportDeviceId].igmpBytes > 0) {
    p[idx] = device[actualReportDeviceId].igmpBytes; lbl[idx] = "IGMP"; idx++; }
  if(device[actualReportDeviceId].osiBytes > 0) {
    p[idx] = device[actualReportDeviceId].osiBytes; lbl[idx] = "OSI"; idx++; }
  if(device[actualReportDeviceId].qnxBytes > 0) {
    p[idx] = device[actualReportDeviceId].qnxBytes; lbl[idx] = "QNX"; idx++; }
  if(device[actualReportDeviceId].otherBytes > 0) {
    p[idx] = device[actualReportDeviceId].otherBytes; lbl[idx] = "Other"; idx++; }

#ifdef MULTITHREADED
  accessMutex(&graphMutex, "drawGlobalProtoDistribution");
#endif

  GDC_LineColor = 0x000000L;
  GDC_BGColor   = 0xFFFFFFL;
  GDC_SetColor  = &sc;
  GDC_yaxis=0;
  GDC_requested_ymin = 0;
  GDC_title = "";

  out_graph(600, 250,	/* width/height */
	    fd,	        /* open file pointer */
	    GDC_3DBAR,	/* or GDC_2DBAR */
	    idx,	/* number of slices */
	    lbl,	/* slice labels (unlike out_png(), can be NULL */
	    1,
	    p);	        /* data array */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&graphMutex);
#endif

  if((fd = fopen(fileName, "rb")) != NULL) {
    for(totLen=0;;) {
      len = fread(tmpStr, sizeof(char), 255, fd);
      if(len <= 0) break;
      totLen += len;
      sendStringLen(tmpStr, len);
    }

    fclose(fd);
  }

  unlink(fileName);
}

/* ************************ */

void drawGlobalIpProtoDistribution(void) {
  char tmpStr[256], fileName[NAME_MAX] = "/tmp/graph-XXXXXX";
  int len, i, idx=0;
  float p[256];
  unsigned long sc = 0xC8C8FF;
  char	*lbl[256];
  FILE *fd;

  p[numIpProtosToMonitor] = 0;

  for(i=0; i<numIpProtosToMonitor; i++) {
    p[idx]  = (float)ipProtoStats[i].local+ipProtoStats[i].remote;
    p[idx] += (float)ipProtoStats[i].remote2local+ipProtoStats[i].local2remote;
    if(p[idx] > 0) {
      p[numIpProtosToMonitor] += p[idx];
      lbl[idx] = protoIPTrafficInfos[i];
      idx++;
    }
  }

  fd = getNewRandomFile(fileName, NAME_MAX);
  
#ifdef MULTITHREADED
  accessMutex(&graphMutex, "drawGlobalIpProtoDistribution");
#endif

  GDC_LineColor = 0x000000L;
  GDC_BGColor   = 0xFFFFFFL;
  GDC_SetColor  = &sc;
  GDC_yaxis=0;
  GDC_title = "";

  out_graph(600, 250,		/* width/height */
	    fd,			/* open file pointer */
	    GDC_3DBAR,		/* or GDC_2DBAR */
	    idx,		/* number of slices */
	    lbl,		/* slice labels (unlike out_png(), can be NULL */
	    1,
	    p);			/* data array */

  fclose(fd);

#ifdef MULTITHREADED
  releaseMutex(&graphMutex);
#endif

  if((fd = fopen(fileName, "rb")) != NULL) {
    for(;;) {
      len = fread(tmpStr, sizeof(char), 255, fd);
      if(len <= 0) break;
      sendStringLen(tmpStr, len);
    }
    fclose(fd);
  }
  unlink(fileName);
}

#endif /* HAVE_GDCHART */
