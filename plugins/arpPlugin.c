/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
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


typedef struct arpEntries {
  HostTraffic* host;
  unsigned long sentPkts, rcvdPkts;
} ArpEntries;

struct	_arphdr {
  u_short	ar_hrd;		/* format of hardware address */
#define ARPHRD_ETHER 	1	/* ethernet hardware address */
#define ARPHRD_802 	6	/* any 802 network */
  u_short	ar_pro;		/* format of protocol address */
  u_char	ar_hln;		/* length of hardware address */
  u_char	ar_pln;		/* length of protocol address */
  u_short	ar_op;		/* one of: */
#define	ARPOP_REQUEST	1	/* request to resolve address */
#define	ARPOP_REPLY	2	/* response to previous request */
};

struct	_ether_arp {
  struct	_arphdr ea_hdr;	/* fixed-size header */
  u_char	arp_sha[6];	/* sender hardware address */
  u_char	arp_spa[4];	/* sender protocol address */
  u_char	arp_tha[6];	/* target hardware address */
  u_char	arp_tpa[4];	/* target protocol address */
};

#ifndef arp_hrd
#define	arp_hrd	ea_hdr.ar_hrd
#endif

#ifndef arp_pro
#define	arp_pro	ea_hdr.ar_pro
#endif

#ifndef arp_hln
#define	arp_hln	ea_hdr.ar_hln
#endif

#ifndef arp_pln
#define	arp_pln	ea_hdr.ar_pln
#endif

#ifndef arp_op
#define	arp_op	ea_hdr.ar_op
#endif

static int dumpArpPackets = 0;
#ifdef HAVE_GDBM_H
static GDBM_FILE arpDB;
#endif
static int arpColumnSort = 0;

#define MAX_NUM_ARP_ENTRIES  512
static ArpEntries theArpEntries[MAX_NUM_ARP_ENTRIES];



static void handleArpPacket(const struct pcap_pkthdr *h, const u_char *p) {
  struct _ether_arp *arpPkt;
  struct in_addr addr;
  u_short op;
  datum key_data, data_data;
  char *ipAddr, *macAddr, tmpStr[32], tmpStr1[32];
  unsigned long numPkts;

  if(arpDB == NULL)
    return;

#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "handleArpPacket");
#endif 

  arpPkt = (struct _ether_arp*)(p+sizeof(struct ether_header));
  op = (u_short)ntohs(*(u_short *)(&arpPkt->arp_pro));
  if (!((op != ETHERTYPE_IP && op != ETHERTYPE_TRAIL)
	|| arpPkt->arp_hln != sizeof(arpPkt->arp_sha)
	|| arpPkt->arp_pln != sizeof(arpPkt->arp_spa))) {
    op = (u_short)ntohs(*(u_short *)(&arpPkt->arp_op));

    if(op == ARPOP_REQUEST) {      
      memcpy(&addr.s_addr, arpPkt->arp_tpa, sizeof(addr.s_addr));
      NTOHL(addr.s_addr);
      if(dumpArpPackets) traceEvent(TRACE_INFO, "ARP Request: who-has %s ", intoa(addr));
      memcpy(&addr.s_addr, arpPkt->arp_spa, sizeof(addr.s_addr));
      NTOHL(addr.s_addr);
      ipAddr = intoa(addr);
      if(dumpArpPackets) traceEvent(TRACE_INFO, "tell %s\n", ipAddr);

      /* ******** */
#ifdef HAVE_GDBM_H
      snprintf(tmpStr, sizeof(tmpStr), "s%s", ipAddr);
      key_data.dptr = tmpStr; key_data.dsize = strlen(key_data.dptr)+1;
      data_data = gdbm_fetch(arpDB, key_data);
      if(data_data.dptr != NULL) {
	numPkts = atol(data_data.dptr)+1;
	free(data_data.dptr);
      } else
	numPkts = 1;

      snprintf(tmpStr1, sizeof(tmpStr1), "%lu", (unsigned long)numPkts);
      data_data.dptr = tmpStr1; data_data.dsize = strlen(data_data.dptr)+1;
      gdbm_store(arpDB, key_data, data_data, GDBM_REPLACE);	
#endif
      /* ******** */
    } else {
      memcpy(&addr.s_addr, arpPkt->arp_spa, sizeof(addr.s_addr));
      NTOHL(addr.s_addr);
      ipAddr = intoa(addr);
      macAddr = etheraddr_string(arpPkt->arp_sha);

      if(dumpArpPackets)
	traceEvent(TRACE_INFO, "ARP Reply: %s is-at %s\n", ipAddr, macAddr);
      
      /* ******** */
#ifdef HAVE_GDBM_H
      key_data.dptr = ipAddr; key_data.dsize = strlen(key_data.dptr)+1;
      data_data.dptr = macAddr; data_data.dsize = strlen(data_data.dptr)+1;
      gdbm_store(arpDB, key_data, data_data, GDBM_REPLACE);

      /* ******** */
      snprintf(tmpStr, sizeof(tmpStr), "r%s", ipAddr);
      key_data.dptr = tmpStr; key_data.dsize = strlen(key_data.dptr)+1;
      data_data = gdbm_fetch(arpDB, key_data);
      if(data_data.dptr != NULL) {
	numPkts = atol(data_data.dptr)+1;
	free(data_data.dptr);
      } else
	numPkts = 1;

      snprintf(tmpStr1, sizeof(tmpStr1), "%lu", (unsigned long)numPkts);
      data_data.dptr = tmpStr1; data_data.dsize = strlen(data_data.dptr)+1;
      gdbm_store(arpDB, key_data, data_data, GDBM_REPLACE);
#endif
      /* ******** */
    }
  }

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 
}

/* ******************************* */

static int sortARPhosts(const void *_a, const void *_b) {
  ArpEntries *a = (ArpEntries *)_a;
  ArpEntries *b = (ArpEntries *)_b;
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

  switch(arpColumnSort) {
  default:
  case 1:
#ifdef MULTITHREADED
    accessMutex(&addressResolutionMutex, "sortARPhosts");
#endif 
    rc = strcasecmp(a->host->hostSymIpAddress, b->host->hostSymIpAddress);
#ifdef MULTITHREADED
    releaseMutex(&addressResolutionMutex);
#endif 
    return(rc);
    break;
  case 2:
    if(a->host->hostIpAddress.s_addr > b->host->hostIpAddress.s_addr)
      return(1);
    else if(a->host->hostIpAddress.s_addr < b->host->hostIpAddress.s_addr)
      return(-1);
    else
      return(0);
    break;
  case 3:
    return(strcasecmp(a->host->ethAddressString, b->host->ethAddressString));
    break;

  case 4:
    if(a->sentPkts < b->sentPkts)
      return(1);
    else if (a->sentPkts > b->sentPkts)
      return(-1);
    else
      return(0);
    break;
  case 5:
    if(a->rcvdPkts < b->rcvdPkts)
      return(1);
    else if (a->rcvdPkts > b->rcvdPkts)
      return(-1);
    else
      return(0);
    break;
  }  
}

/* ****************************** */

static void handleArpWatchHTTPrequest(char* url) {
  datum data_data, key_data, fkey_data, return_data = gdbm_firstkey (arpDB);
  char tmpStr[BUF_SIZE], macAddr[32];
  int numEntries = 0, i, revertOrder=0;
  char *pluginName = "<A HREF=/plugins/arpWatch";
  char *sign = "-";

  if(url[0] =='\0')
    arpColumnSort = 0;
  else {
    if(url[0] == '-') {
      sign = "";
      revertOrder = 1;
      arpColumnSort = atoi(&url[1]);
    } else
      arpColumnSort = atoi(url);
  }
  
  sendHTTPProtoHeader(); sendHTTPHeaderType(); printHTTPheader();

  sendString("<HTML><BODY BGCOLOR=#FFFFFF><FONT FACE=Helvetica>"
	     "<CENTER><H1>Welcome to arpWatch</H1>\n<p>"
	     "<TABLE BORDER><TR>");

  snprintf(tmpStr, sizeof(tmpStr), "<TH>%s?%s1>Host</A></TH>"
	 "<TH>%s?%s2>IP&nbsp;Address</A></TH>"
	 "<TH>%s?%s3>MAC</A></TH>"
	 "<TH>%s?%s4>#&nbsp;ARP&nbsp;Req.&nbsp;Sent</A></TH>"
	 "<TH>%s?%s5>#&nbsp;ARP&nbsp;Resp.&nbsp;Sent</A></TH></TR>\n",
	 pluginName, sign,
	 pluginName, sign,
	 pluginName, sign,
	 pluginName, sign,
	 pluginName, sign);

  sendString(tmpStr);
 
#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "handleArpWatchHTTPrequest");
#endif 
 
  while (return_data.dptr != NULL) {
    key_data = return_data;

    if((key_data.dptr[0] != 'r')
       && (key_data.dptr[0] != 's')) {
      unsigned long sentPkts, rcvdPkts;
      HostTraffic* host;
      
      data_data = gdbm_fetch(arpDB, key_data);
      if(data_data.dptr != NULL) {
	strncpy(macAddr, data_data.dptr, sizeof(macAddr));
	free(data_data.dptr);
      } else
	strncpy(macAddr, "???", sizeof(macAddr));

      snprintf(tmpStr, sizeof(tmpStr), "s%s", key_data.dptr);
      fkey_data.dptr = tmpStr; fkey_data.dsize = strlen(fkey_data.dptr)+1;
      data_data = gdbm_fetch(arpDB, fkey_data);
      if(data_data.dptr != NULL) {
	sentPkts = atol(data_data.dptr)+1;
	free(data_data.dptr);
      } else
	sentPkts = 0;

      snprintf(tmpStr, sizeof(tmpStr), "r%s", key_data.dptr);
      fkey_data.dptr = tmpStr; fkey_data.dsize = strlen(fkey_data.dptr)+1;
      data_data = gdbm_fetch(arpDB, fkey_data);
      if(data_data.dptr != NULL) {
	rcvdPkts = atol(data_data.dptr)+1;
	free(data_data.dptr);
      } else
	rcvdPkts = 0;


      host = findHostByNumIP(key_data.dptr);

      if((host != NULL)
	 && (numEntries < MAX_NUM_ARP_ENTRIES)) {
	theArpEntries[numEntries].host = host;
	theArpEntries[numEntries].sentPkts = sentPkts;
	theArpEntries[numEntries++].rcvdPkts = rcvdPkts;
      }
    }

    return_data = gdbm_nextkey(arpDB, key_data);    
    free(key_data.dptr);
  }

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 

  /* traceEvent(TRACE_INFO, "---> %d\n", numEntries); */

  quicksort(theArpEntries, numEntries, sizeof(ArpEntries), sortARPhosts);

  for(i=0; i<numEntries; i++) {
    ArpEntries *theEntry;

    if(revertOrder)
      theEntry = &theArpEntries[numEntries-i-1];
    else
      theEntry = &theArpEntries[i];

    snprintf(tmpStr, sizeof(tmpStr), "<TR %s>%s"
	    "<TD ALIGN=RIGHT>%s</TD>"
	    "<TD ALIGN=RIGHT>%s</TD>"
	    "<TD ALIGN=CENTER>%lu</TD>"
	    "<TD ALIGN=CENTER>%lu</TD></TR>\n",
	    getRowColor(),
	    makeHostLink(theEntry->host, 1, 1, 0),
	    theEntry->host->hostNumIpAddress,
	    theEntry->host->ethAddressString,
	    theEntry->sentPkts,
	    theEntry->rcvdPkts);

    sendString(tmpStr);
  }


  sendString("</TABLE></CENTER><p>\n");
  printHTTPtrailer();
}

/* ****************************** */

static void termArpFunct() {
  traceEvent(TRACE_INFO, "Thanks for using arpWatch..."); fflush(stdout);
  
  if(arpDB != NULL) {
    gdbm_close(arpDB);
    arpDB = NULL;
  }

  traceEvent(TRACE_INFO, "Done.\n"); fflush(stdout);
}

/* ****************************** */

static PluginInfo arpPluginInfo[] = {
  { "arpWatchPlugin",
    "This plugin handles ARP packets",
    "1.0", /* version */
    "<A HREF=http://jake.unipi.it/~deri/>L.Deri</A>", 
    "arpWatch", /* http://<host>:<port>/plugins/arpWatch */
    1, /* Active */
    termArpFunct, /* TermFunc   */
    handleArpPacket, /* PluginFunc */
    handleArpWatchHTTPrequest,
    NULL,
    "arp" /* BPF filter: filter all the ARP packets */
  }
};
  
/* Plugin entry fctn */
#ifdef STATIC_PLUGIN
PluginInfo* arpPluginEntryFctn() {
#else
PluginInfo* PluginEntryFctn() {
#endif
  char tmpBuff[200];

  traceEvent(TRACE_INFO, "Welcome to %s. (C) 1999 by Luca Deri.\n", 
	     arpPluginInfo->pluginName);

  /* Fix courtesy of Ralf Amandi <Ralf.Amandi@accordata.net> */
  snprintf(tmpBuff, sizeof(tmpBuff), "%s/arpWatch.db", dbPath);
  arpDB = gdbm_open (tmpBuff, 0, GDBM_NEWDB, 00664, NULL);

  if(arpDB == NULL) 
    traceEvent(TRACE_ERROR, 
	       "Unable to open arpWatch database. This plugin will be disabled.\n");

  return(arpPluginInfo);
}
