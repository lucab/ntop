/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
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

typedef struct icmpData {
  struct icmp icmpPkt;
  char dummy_data[16];
} IcmpData;

typedef struct icmpPktInfo {
  time_t         pktTime;
  struct in_addr sourceHost;
  struct in_addr destHost;
  IcmpData       icmpData;
} IcmpPktInfo;

static time_t garbageTime;

#define ICMP_LIST_MAX_LEN  128
static IcmpPktInfo  icmpHostsList[ICMP_LIST_MAX_LEN+2];
static unsigned int icmpListEntries;

static void runICMPgarbageCollector(void);

/* ****************************** */

static GDBM_FILE icmpDB;
static int icmpColumnSort = 0;

struct tok {
  int v;    /* value  */
  char *s;  /* string */
};

/* Formats for most of the ICMP_UNREACH codes */
static struct tok unreach2str[] = {
  { ICMP_UNREACH_NET,		"net %s unreachable" },
  { ICMP_UNREACH_HOST,		"host %s unreachable" },
  { ICMP_UNREACH_SRCFAIL,
    "%s unreachable - source route failed" },
  { ICMP_UNREACH_NET_UNKNOWN,	"net %s unreachable - unknown" },
  { ICMP_UNREACH_HOST_UNKNOWN,	"host %s unreachable - unknown" },
  { ICMP_UNREACH_ISOLATED,
    "%s unreachable - source host isolated" },
  { ICMP_UNREACH_NET_PROHIB,
    "net %s unreachable - admin prohibited" },
  { ICMP_UNREACH_HOST_PROHIB,
    "host %s unreachable - admin prohibited" },
  { ICMP_UNREACH_TOSNET,
    "net %s unreachable - tos prohibited" },
  { ICMP_UNREACH_TOSHOST,
    "host %s unreachable - tos prohibited" },
  { ICMP_UNREACH_FILTER_PROHIB,
    "host %s unreachable - admin prohibited filter" },
  { ICMP_UNREACH_HOST_PRECEDENCE,
    "host %s unreachable - host precedence violation" },
  { ICMP_UNREACH_PRECEDENCE_CUTOFF,
    "host %s unreachable - precedence cutoff" },
  { 0,				NULL }
};

/* Formats for the ICMP_REDIRECT codes */
static struct tok type2str[] = {
	{ ICMP_REDIRECT_NET,		"redirect %s to net %s" },
	{ ICMP_REDIRECT_HOST,		"redirect %s to host %s" },
	{ ICMP_REDIRECT_TOSNET,		"redirect-tos %s to net %s" },
	{ ICMP_REDIRECT_TOSHOST,	"redirect-tos %s to net %s" },
	{ 0,				NULL }
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

static char *tok2str(register const struct tok *lp,
		     register const char *fmt,
		     register int v) {
  static char buf[128];

  while (lp->s != NULL) {
    if (lp->v == v)
      return (lp->s);
    ++lp;
  }
  if (fmt == NULL)
    fmt = "#%d";

 if(snprintf(buf, sizeof(buf), fmt, v) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
  return (buf);
}

/* ***************************** */

static void handleIcmpPacket(const struct pcap_pkthdr *h,
			     const u_char *p) {
  IcmpData icmpData;
  struct ip ip;
  u_int hlen, off;
  int src_idx, dst_idx;
  datum key_data, data_data;
  char tmpStr[32];
  IcmpPktInfo pktInfo;
  struct ether_header *ep;
  u_char *ether_src, *ether_dst;

  ep = (struct ether_header *)p;
  ether_src = ESRC(ep), ether_dst = EDST(ep);

  memcpy(&ip, (p+headerSize[device[deviceId].datalink]), sizeof(struct ip));
  hlen = (u_int)ip.ip_hl * 4;

  off = ntohs(ip.ip_off);

  if((off & 0x3fff) && (off & IP_MF)) {
    /*
      ntop skips ICMP fragments other than the main one.
      This is not a problem since fragments do not have
      to be counted.
    */
#ifdef DEBUG
    traceEvent(TRACE_INFO, "Skipping fragment \n");
#endif
    return;
  }

  memcpy(&icmpData, (p+headerSize[device[deviceId].datalink]+hlen),
	 sizeof(IcmpData));

  if(icmpData.icmpPkt.icmp_type > ICMP_MAXTYPE) return;

  NTOHL(ip.ip_src.s_addr);
  NTOHL(ip.ip_dst.s_addr);

  src_idx = checkSessionIdx(getHostInfo(&ip.ip_src, ether_src));
  dst_idx = checkSessionIdx(getHostInfo(&ip.ip_dst, ether_dst));

  if(device[actualDeviceId].hash_hostTraffic[src_idx] == NULL) {
    traceEvent(TRACE_WARNING, "Invalid index (src) %d\n", src_idx);
  }

  if(device[actualDeviceId].hash_hostTraffic[dst_idx] == NULL) {
    traceEvent(TRACE_WARNING, "Invalid index (dst) %d\n", dst_idx);
  }

  if(device[actualDeviceId].hash_hostTraffic[src_idx]->icmpInfo == NULL) {
    device[actualDeviceId].hash_hostTraffic[src_idx]->icmpInfo = 
      (IcmpHostInfo*)malloc(sizeof(IcmpHostInfo));
    memset(device[actualDeviceId].hash_hostTraffic[src_idx]->icmpInfo, 0,
	   sizeof(IcmpHostInfo));
  }

  device[actualDeviceId].hash_hostTraffic[src_idx]
    ->icmpInfo->icmpMsgSent[icmpData.icmpPkt.icmp_type]++;

  if(device[actualDeviceId].hash_hostTraffic[dst_idx]->icmpInfo == NULL) {
    device[actualDeviceId].hash_hostTraffic[dst_idx]->icmpInfo = 
      (IcmpHostInfo*)malloc(sizeof(IcmpHostInfo));
    memset(device[actualDeviceId].hash_hostTraffic[dst_idx]->icmpInfo, 0,
	   sizeof(IcmpHostInfo));
  }

  device[actualDeviceId].hash_hostTraffic[dst_idx]
    ->icmpInfo->icmpMsgRcvd[icmpData.icmpPkt.icmp_type]++;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "src) idx=%d [%s] - type=%d - tot=%d\n", 
	 src_idx, device[actualDeviceId].hash_hostTraffic[src_idx]->hostSymIpAddress,
	 icmpData.icmpPkt.icmp_type,
	 device[actualDeviceId].hash_hostTraffic[src_idx]->icmpInfo->
	 icmpMsgSent[icmpData.icmpPkt.icmp_type]);
  traceEvent(TRACE_INFO, "dst) idx=%d [%s] - type=%d - tot=%d\n", 
	 dst_idx, device[actualDeviceId].hash_hostTraffic[dst_idx]->hostSymIpAddress,
	 icmpData.icmpPkt.icmp_type,
	 device[actualDeviceId].hash_hostTraffic[dst_idx]->icmpInfo->
	 icmpMsgSent[icmpData.icmpPkt.icmp_type]);
#endif

  switch (icmpData.icmpPkt.icmp_type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
      /* Do not log anything */
      break;

    case ICMP_UNREACH:
    case ICMP_REDIRECT:
    case ICMP_ROUTERADVERT:
    case ICMP_TIMXCEED:
    case ICMP_PARAMPROB:
    case ICMP_MASKREPLY:
    case ICMP_MASKREQ:
    case ICMP_INFO_REQUEST:
    case ICMP_INFO_REPLY:
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
    case ICMP_SOURCE_QUENCH:
      if(snprintf(tmpStr, sizeof(tmpStr), "%lu/%lu",
	      (unsigned long)h->ts.tv_sec,
	      (unsigned long)h->ts.tv_usec) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      key_data.dptr = tmpStr; key_data.dsize = strlen(key_data.dptr)+1;
      pktInfo.pktTime = h->ts.tv_sec;
      pktInfo.sourceHost.s_addr = ip.ip_src.s_addr;
      pktInfo.destHost.s_addr = ip.ip_dst.s_addr;
      memcpy(&pktInfo.icmpData, &icmpData, sizeof(IcmpData));
      data_data.dptr = (char*)&pktInfo; data_data.dsize = sizeof(IcmpPktInfo)+1;

#ifdef DEBUG
      if(icmpData.icmpPkt.icmp_type == 5)
	printf("Adding %u/%u [%d] @ %s\n",
	       pktInfo.sourceHost.s_addr, pktInfo.destHost.s_addr,
	       pktInfo.icmpData.icmpPkt.icmp_type, tmpStr);
#endif

#ifdef MULTITHREADED
      accessMutex(&gdbmMutex, "sortICMPhosts");
#endif
      gdbm_store(icmpDB, key_data, data_data, GDBM_REPLACE);
#ifdef MULTITHREADED
      releaseMutex(&gdbmMutex);
#endif
      break;
    }


  /* Note: ipaddr2str uses the gdbm semaphore !!! */
}


/* ****************************** */

static int sortICMPhosts(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  unsigned long n1, n2;
  int rc;

  if(((*a) == NULL) && ((*b) != NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (1)\n");
    return(1);
  } else if(((*a) != NULL) && ((*b) == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (2)\n");
    return(-1);
  } else if(((*a) == NULL) && ((*b) == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (3)\n");
    return(0);
  }

  switch(icmpColumnSort) {
  case 2:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_ECHO] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_ECHO];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_ECHO] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_ECHO];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 12: /* Echo Reply */
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 3:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_UNREACH] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_UNREACH];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_UNREACH] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_UNREACH];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 4:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_REDIRECT] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_REDIRECT] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 5:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 6:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_TIMXCEED] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_TIMXCEED] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 7:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_PARAMPROB] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_PARAMPROB] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 8:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_MASKREQ] + (*a)->icmpInfo->icmpMsgSent[ICMP_MASKREPLY] +
      (*a)->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ]+ (*a)->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_MASKREQ] + (*b)->icmpInfo->icmpMsgSent[ICMP_MASKREPLY] +
      (*b)->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ]+ (*b)->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;


  case 9:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH] + (*a)->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH] + (*b)->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 10:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP] + (*a)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY] +
      (*a)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP]+ (*a)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP] + (*b)->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY] +
      (*b)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP]+ (*b)->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  case 11:
    n1 = (*a)->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST] + (*a)->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY] +
      (*a)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST]+ (*a)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY];
    n2 = (*b)->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST] + (*b)->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY] +
      (*b)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST]+ (*b)->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY];
    if(n1 > n2) return(1); else if(n1 < n2) return(-1); else return(0);
    break;

  default:
#ifdef MULTITHREADED
    accessMutex(&addressResolutionMutex, "addressResolution");
#endif

    rc = strcasecmp((*a)->hostSymIpAddress, (*b)->hostSymIpAddress);

#ifdef MULTITHREADED
    releaseMutex(&addressResolutionMutex);
#endif
    return(rc);
    break;
  }
}

/* ******************************* */

static void insertICMPPkt(IcmpPktInfo *icmpPktInfo) {
  if(icmpListEntries < ICMP_LIST_MAX_LEN) {
   memcpy(&icmpHostsList[icmpListEntries], icmpPktInfo, sizeof(IcmpPktInfo));
    icmpListEntries++;
  }
}

/* ******************************* */

static void printIcmpPkt(IcmpPktInfo *icmpPktInfo) {
  int s_idx, d_idx;
  char icmpBuf[512];
  struct ip *oip;
  u_int hlen;
  u_int dport, mtu;
  char *fmt, *cp;
  const struct udphdr *ouh;
  unsigned long theTime = icmpPktInfo->pktTime;

  s_idx = findHostInfo(&icmpPktInfo->sourceHost);
  d_idx = findHostInfo(&icmpPktInfo->destHost);

  if((s_idx == -1) || (d_idx == -1))
    return;

  sendString("<TR ");
  sendString(getRowColor());
  sendString("><TD>");
  sendString(ctime((time_t*)&theTime));
  sendString("</TD>");
  sendString(makeHostLink(device[actualReportDeviceId].
			  hash_hostTraffic[checkSessionIdx(s_idx)],
			  LONG_FORMAT, 0, 0));
  sendString(makeHostLink(device[actualReportDeviceId].
			  hash_hostTraffic[checkSessionIdx(d_idx)],
			  LONG_FORMAT, 0, 0));
  sendString("<TD>");

  switch (icmpPktInfo->icmpData.icmpPkt.icmp_type) {

  case ICMP_ECHOREPLY:
    strncpy(icmpBuf, "ECHO reply", sizeof(icmpBuf));
    break;

  case ICMP_ECHO:
    strncpy(icmpBuf, "ECHO request", sizeof(icmpBuf));
    break;

  case ICMP_UNREACH:
    switch (icmpPktInfo->icmpData.icmpPkt.icmp_code) {

    case ICMP_UNREACH_PROTOCOL:
       NTOHL(icmpPktInfo->icmpData.icmpPkt.icmp_ip.ip_dst.s_addr);
       if(snprintf(icmpBuf, sizeof(icmpBuf), "%s protocol 0x%X unreachable",
		    intoa(icmpPktInfo->icmpData.icmpPkt.icmp_ip.ip_dst),
		    icmpPktInfo->icmpData.icmpPkt.icmp_ip.ip_p) < 0) 
	 traceEvent(TRACE_ERROR, "Buffer overflow!");
      break;

    case ICMP_UNREACH_PORT:
      oip = &icmpPktInfo->icmpData.icmpPkt.icmp_ip;
      hlen = oip->ip_hl * 4;
      ouh = (struct udphdr *)(((u_char *)oip) + hlen);
#ifdef SLACKWARE
      dport = ntohs(ouh->dest);
#else
      dport = ntohs(ouh->uh_dport);
#endif
      NTOHL(oip->ip_dst.s_addr);
      switch (oip->ip_p) {

      case IPPROTO_TCP:
	if(snprintf(icmpBuf, sizeof(icmpBuf),
		      "%s tcp port %d unreachable",
		      intoa(oip->ip_dst),
		      dport) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	break;

      case IPPROTO_UDP:
	if(snprintf(icmpBuf, sizeof(icmpBuf),
		      "%s udp port %d unreachable",
		      intoa(oip->ip_dst),
		      dport) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	break;

      default:
	if(snprintf(icmpBuf, sizeof(icmpBuf),
		      "%s protocol 0x%X port %d unreachable",
		      intoa(oip->ip_dst),
		      oip->ip_p, dport) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	break;
      }
      break;

    case ICMP_UNREACH_NEEDFRAG:
      {
	register const struct mtu_discovery *mp;

	mp = (struct mtu_discovery *)&icmpPktInfo->icmpData.icmpPkt.icmp_void;
	mtu = EXTRACT_16BITS(&mp->nexthopmtu);
	NTOHL(icmpPktInfo->icmpData.icmpPkt.icmp_ip.ip_dst.s_addr);
	if (mtu) {
	  if(snprintf(icmpBuf, sizeof(icmpBuf),
			"%s unreachable - need to frag (mtu %d)",
			intoa(icmpPktInfo->icmpData.icmpPkt.icmp_ip.ip_dst), mtu) < 0) 
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	} else {
	  if(snprintf(icmpBuf, sizeof(icmpBuf),
			"%s unreachable - need to frag",
			intoa(icmpPktInfo->icmpData.icmpPkt.icmp_ip.ip_dst)) < 0) 
	    traceEvent(TRACE_ERROR, "Buffer overflow!");
	}
      }
      break;

    default:
      NTOHL(icmpPktInfo->icmpData.icmpPkt.icmp_ip.ip_dst.s_addr);
      fmt = tok2str(unreach2str, "#%d %%s unreachable",
		    icmpPktInfo->icmpData.icmpPkt.icmp_code);
      if(snprintf(icmpBuf, sizeof(icmpBuf), fmt,
		  intoa(icmpPktInfo->icmpData.icmpPkt.icmp_ip.ip_dst)) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      break;
    }
    break;

  case ICMP_REDIRECT:
    NTOHL(icmpPktInfo->icmpData.icmpPkt.icmp_ip.ip_dst.s_addr);
    NTOHL(icmpPktInfo->icmpData.icmpPkt.icmp_gwaddr.s_addr);
    fmt = tok2str(type2str, "redirect-#%d %%s to net %%s",
		  icmpPktInfo->icmpData.icmpPkt.icmp_code);
    if(snprintf(icmpBuf, sizeof(icmpBuf), fmt,
		intoa(icmpPktInfo->icmpData.icmpPkt.icmp_ip.ip_dst),
		intoa(icmpPktInfo->icmpData.icmpPkt.icmp_gwaddr)) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    break;

  case ICMP_ROUTERADVERT:
    {
      register const struct ih_rdiscovery *ihp;
      register const struct id_rdiscovery *idp;
      u_int lifetime, num, size;

      strncpy(icmpBuf, "router advertisement", sizeof(icmpBuf));
      cp = icmpBuf + strlen(icmpBuf);

      ihp = (struct ih_rdiscovery *)&icmpPktInfo->icmpData.icmpPkt.icmp_void;
      (void)strncpy(cp, " lifetime ", sizeof(icmpBuf));
      cp = icmpBuf + strlen(icmpBuf);
      lifetime = EXTRACT_16BITS(&ihp->ird_lifetime);
      if (lifetime < 60) {
	if(snprintf(cp, sizeof(icmpBuf), "%u", lifetime) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      } else if (lifetime < 60 * 60) {
	if(snprintf(cp, sizeof(icmpBuf), "%u:%02u",
		    lifetime / 60, lifetime % 60) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
     } else {
	if(snprintf(cp, sizeof(icmpBuf), "%u:%02u:%02u",
		    lifetime / 3600,
		    (lifetime % 3600) / 60,
		    lifetime % 60) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      }
      cp = icmpBuf + strlen(icmpBuf);

      num = ihp->ird_addrnum;
      if(snprintf(cp, sizeof(icmpBuf), " %d:", num) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      cp = icmpBuf + strlen(icmpBuf);

      size = ihp->ird_addrsiz;
      if (size != 2) {
	if(snprintf(cp, sizeof(icmpBuf), " [size %d]", size) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	break;
      }
      idp = (struct id_rdiscovery *)icmpPktInfo->icmpData.icmpPkt.icmp_data;
      while (num-- > 0) {
	struct in_addr theAddr;

	theAddr.s_addr = idp->ird_addr;
	NTOHL(theAddr.s_addr);
	if(snprintf(cp, sizeof(icmpBuf), " {%s %u}",
		    intoa(theAddr),
		    EXTRACT_32BITS(&idp->ird_pref)) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	cp = icmpBuf + strlen(icmpBuf);
      }
    }
    break;

  case ICMP_TIMXCEED:
    switch (icmpPktInfo->icmpData.icmpPkt.icmp_code) {

    case ICMP_TIMXCEED_INTRANS:
      strncpy(icmpBuf, "time exceeded in-transit", sizeof(icmpBuf));
      break;

    case ICMP_TIMXCEED_REASS:
      strncpy(icmpBuf, "ip reassembly time exceeded", sizeof(icmpBuf));
      break;

    default:
      if(snprintf(icmpBuf, sizeof(icmpBuf), "time exceeded-#%d",
		  icmpPktInfo->icmpData.icmpPkt.icmp_code) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      break;
    }
    break;

  case ICMP_PARAMPROB:
    if (icmpPktInfo->icmpData.icmpPkt.icmp_code)
      if(snprintf(icmpBuf, sizeof(icmpBuf), "parameter problem - code %d",
		  icmpPktInfo->icmpData.icmpPkt.icmp_code) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    else {
      if(snprintf(icmpBuf, sizeof(icmpBuf), "parameter problem - octet %d",
		  icmpPktInfo->icmpData.icmpPkt.icmp_pptr) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
    }
    break;

  case ICMP_MASKREQ:
    strncpy(icmpBuf, "ICMP network mask request", sizeof(icmpBuf));
    break;

  case ICMP_MASKREPLY:
    if(snprintf(icmpBuf, sizeof(icmpBuf), "address mask is 0x%08x",
		(u_int32_t)ntohl(icmpPktInfo->icmpData.icmpPkt.icmp_mask)) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    break;

  default:
    if(snprintf(icmpBuf, sizeof(icmpBuf), "type-#%d",
		icmpPktInfo->icmpData.icmpPkt.icmp_type) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    break;
  }

  sendString(icmpBuf);
  sendString("</TR>\n");
}

/* ******************************* */

static int sortICMPHostsInfo(const void *_a, const void *_b) {
  IcmpPktInfo *a = (IcmpPktInfo *)_a;
  IcmpPktInfo *b = (IcmpPktInfo *)_b;

    if(a->pktTime > b->pktTime)
      return(1);
    else if(a->pktTime < b->pktTime)
      return(-1);
    else
      return(0);
}

/* ******************************* */

static void runICMPgarbageCollector(void) {
  datum key_data;
  datum return_data;
  char tmpTime[32];
  time_t theTime;
  char *strtokState;

  if(actTime > garbageTime) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "runICMPgarbageCollector()\n");
#endif

#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "runICMPgarbageCollector");
#endif
    return_data = gdbm_firstkey (icmpDB);
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif

    while (return_data.dptr != NULL) {
      key_data = return_data;
#ifdef MULTITHREADED
      accessMutex(&gdbmMutex, "runICMPgrbageCollector-2");
#endif
      return_data = gdbm_nextkey(icmpDB, key_data);
#ifdef MULTITHREADED
      releaseMutex(&gdbmMutex);
#endif
      strncpy(tmpTime, key_data.dptr, sizeof(tmpTime));
      theTime = atol(strtok_r(tmpTime, "/", &strtokState));
      if(theTime < garbageTime) {
#ifdef DEBUG
	printf("Purging entry %u/%u\n", theTime,garbageTime);
#endif
#ifdef MULTITHREADED
	accessMutex(&gdbmMutex, "runICMPgarbageCollector-3");
#endif
	gdbm_delete(icmpDB, key_data);
#ifdef MULTITHREADED
	releaseMutex(&gdbmMutex);
#endif
      }
      free(key_data.dptr);
    }

    garbageTime = actTime+(15*60); /* 15 minutes */
  }
}

/* ******************************* */

static void printIcmpHostPkts(struct in_addr hostIpAddress,
			      int icmpId) {
  datum key_data, data_data;
  datum return_data;
  IcmpPktInfo icmpPktInfo;
  u_int num=0;

  runICMPgarbageCollector();

  icmpListEntries=0;
  memset(icmpHostsList, 0, sizeof(icmpHostsList));

#ifdef DEBUG
    traceEvent(TRACE_INFO, "Searching for '%u' [%d]...\n", hostIpAddress.s_addr, icmpId);
#endif

#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "printICMPHostsPkts");
#endif
  return_data = gdbm_firstkey (icmpDB);
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif

  while (return_data.dptr != NULL) {
    key_data = return_data;
#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "printICMPHostsPkts");
#endif
    return_data = gdbm_nextkey(icmpDB, key_data);
    data_data = gdbm_fetch(icmpDB, key_data);
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif

    if(data_data.dptr != NULL) {
      memcpy(&icmpPktInfo, data_data.dptr, sizeof(IcmpPktInfo));
#ifdef DEBUG
      traceEvent(TRACE_INFO, "%d) %u/%u [%d]\n", ++num,
	     icmpPktInfo.sourceHost.s_addr,
	     icmpPktInfo.destHost.s_addr,
	     icmpPktInfo.icmpData.icmpPkt.icmp_type);
#endif
      if((icmpPktInfo.sourceHost.s_addr == hostIpAddress.s_addr)
	 || (icmpPktInfo.destHost.s_addr == hostIpAddress.s_addr)) {
	switch(icmpId) {
	case ICMP_ECHO:
	  if((icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_ECHO)
	     || (icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_ECHOREPLY))
	    insertICMPPkt(&icmpPktInfo);
	  break;
	case ICMP_UNREACH:
	  if(icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_UNREACH)
	    insertICMPPkt(&icmpPktInfo);
	  break;
	case ICMP_REDIRECT:
	  if(icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_REDIRECT)
	    insertICMPPkt(&icmpPktInfo);
	  break;
	case ICMP_ROUTERADVERT:
	  if(icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_ROUTERADVERT)
	    insertICMPPkt(&icmpPktInfo);
	  break;
	case ICMP_TIMXCEED:
	  if(icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_TIMXCEED)
	    insertICMPPkt(&icmpPktInfo);
	  break;
	case ICMP_PARAMPROB:
	  if(icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_PARAMPROB)
	    insertICMPPkt(&icmpPktInfo);
	  break;
	case ICMP_MASKREQ:
	  if((icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_MASKREQ)
	     || (icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_MASKREPLY))
	    insertICMPPkt(&icmpPktInfo);
	  break;
	  break;
	case ICMP_SOURCE_QUENCH:
	  if(icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_SOURCE_QUENCH)
	    insertICMPPkt(&icmpPktInfo);
	  break;
	case ICMP_TIMESTAMP:
	  if((icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_TIMESTAMP)
	     || (icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_TIMESTAMPREPLY))
	    insertICMPPkt(&icmpPktInfo);
	  break;
	case ICMP_INFO_REQUEST:
	  if((icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_INFO_REQUEST)
	     || (icmpPktInfo.icmpData.icmpPkt.icmp_type == ICMP_INFO_REPLY))
	    insertICMPPkt(&icmpPktInfo);
	  break;
	}
      }
    }

    if(data_data.dptr != NULL) free(data_data.dptr);
    free(key_data.dptr);
  } /* while */

  /* ************************ */

  sendString("<CENTER><TABLE BORDER>\n");
  sendString("<TH>Time</TH><TH>Source</TH><TH>Dest</TH>"
	     "<TH>Packet</TH></TR>\n");

  quicksort(icmpHostsList, icmpListEntries,
	    sizeof(IcmpPktInfo), sortICMPHostsInfo);

  for(num=0; num<icmpListEntries; num++)
    printIcmpPkt(&icmpHostsList[num]);

  sendString("</TABLE></CENTER>\n");
  printHTMLtrailer();
}

/* ******************************* */

static void handleIcmpWatchHTTPrequest(char* url) {
  char buf[1024], anchor[256], fileName[NAME_MAX] = "ntop-icmpPlugin-XXXXXX";
  char *sign = "-";
  char *pluginName = "<A HREF=/plugins/icmpWatch";
  u_int i, revertOrder=0, num;
  int icmpId=-1;
  HostTraffic **hosts;
  struct in_addr hostIpAddress;
  char  **lbls, *strtokState;
  float *s, *r;
  FILE *fd;
  int tmpfd;

  fd = getNewRandomFile(fileName, NAME_MAX);

  i = sizeof(float)*device[actualReportDeviceId].actualHashSize;
  s = (float*)malloc(i); r = (float*)malloc(i);
  memset(s, 0, i); memset(r, 0, i);

  i = sizeof(char*)*device[actualReportDeviceId].actualHashSize;
  lbls = malloc(i);
  memset(lbls, 0, i);  

  i = sizeof(HostTraffic*)*device[actualReportDeviceId].actualHashSize;
  hosts = (HostTraffic**)malloc(i);

  for(i=0, num=0; i<device[actualReportDeviceId].actualHashSize; i++)
    if((device[actualReportDeviceId].hash_hostTraffic[i] != NULL)
       && (device[actualReportDeviceId].hash_hostTraffic[i]->icmpInfo != NULL)) {
      hosts[num++] = device[actualReportDeviceId].hash_hostTraffic[i];
    }

  hostIpAddress.s_addr = 0;

  if(url[0] == '\0')
    icmpColumnSort = 0;
  else if((url[0] == '-') || isdigit(url[0])) {
    if(url[0] == '-') {
      sign = "";
      revertOrder = 1;
      icmpColumnSort = atoi(&url[1]);
    } else
      icmpColumnSort = atoi(url);
  } else /* host=3240847503&icmp=3 */ {
    char *tmpStr;

#ifdef HAVE_GDCHART
    if(strncmp(url, "chart", strlen("chart")) == 0) {
      char tmpStr[256];
      u_int len, tot=0;
      unsigned long  sc[2] = { 0xFF0000, 0x8080FF };

      GDC_BGColor   = 0xFFFFFFL;                  /* backgound color (white) */
      GDC_LineColor = 0x000000L;                  /* line color      (black) */
      GDC_SetColor  = &(sc[0]);                   /* assign set colors */
      GDC_ytitle = "Packets";

      for(i=0; i<num; i++) {
	if(hosts[i] != NULL) {
	  int j;

	  s[tot] = 0, r[tot] = 0;

	  for(j=0; j<ICMP_MAXTYPE; j++) {
#ifdef DEBUG
	    traceEvent(TRACE_INFO, "idx=%d/type=%d: %d/%d\n", i, j, 
		   hosts[i]->icmpInfo->icmpMsgSent[j],
		   hosts[i]->icmpInfo->icmpMsgRcvd[j]);
#endif
	    s[tot] += (float)(hosts[i]->icmpInfo->icmpMsgSent[j]);
	    r[tot] += (float)(hosts[i]->icmpInfo->icmpMsgRcvd[j]);
	  }

	  lbls[tot++] = hosts[i]->hostSymIpAddress;
	}
      }

      /* traceEvent(TRACE_INFO, "file=%s\n", fileName); */

      GDC_title = "ICMP Host Traffic";
      /* The line below causes a crash on Solaris/SPARC (who knows why) */
      /* GDC_yaxis=1; */
      GDC_ylabel_fmt = NULL;
      out_graph(600, 450,           /* width, height           */
		fd,                 /* open FILE pointer       */
		GDC_3DBAR,          /* chart type              */
		tot,                /* num points per data set */
		lbls,               /* X labels array of char* */
		2,                  /* number of data sets     */
		s, r);              /* dataset 2               */

      fclose(fd);

      sendHTTPHeader(MIME_TYPE_CHART_FORMAT, 0);

      fd = fopen(fileName, "rb");
      for(;;) {
	len = fread(tmpStr, sizeof(char), 255, fd);
	if(len <= 0) break;
	sendStringLen(tmpStr, len);
      }

      fclose(fd);

      unlink(fileName);

      return;
    }
#endif

    strtok_r(url, "=", &strtokState);

    tmpStr = strtok_r(NULL, "&", &strtokState);
    hostIpAddress.s_addr = strtoul(tmpStr, (char **)NULL, 10);
#ifdef DEBUG
    traceEvent(TRACE_INFO, "-> %s [%u]\n", tmpStr, hostIpAddress.s_addr);
#endif
    strtok_r(NULL, "=", &strtokState);
    icmpId = atoi(strtok_r(NULL, "&", &strtokState));
  }

  sendHTTPHeader(HTTP_TYPE_HTML, 0);  
  printHTMLheader("ICMP Statistics", 0);

  if(num == 0) {
    printNoDataYet();
    printHTMLtrailer();
    return;
  }

#ifdef HAVE_GDCHART
  if(hostIpAddress.s_addr == 0)
    sendString("<br><IMG SRC=/plugins/icmpWatch?chart><p>\n");
#endif

  if(icmpId != -1) {
    printIcmpHostPkts(hostIpAddress, icmpId);
    return;
  }

  sendString("<CENTER>\n");
  sendString("<TABLE BORDER>\n");
  if(snprintf(buf, sizeof(buf), "<TR><TH>%s?%s1>Host</A><br>[Pkt&nbsp;Sent/Rcvd]</TH>"
	 "<TH>%s?%s2>Echo Req.</A></TH>"
	 "<TH>%s?%s12>Echo Reply</A></TH>"
	 "<TH>%s?%s3>Unreach</A></TH>"
	 "<TH>%s?%s4>Redirect</A></TH>"
	 "<TH>%s?%s5>Router<br>Advert.</A></TH>"
	 "<TH>%s?%s6>Time<br>Exceeded</A></TH>"
	 "<TH>%s?%s7>Param.<br>Problem</A></TH>"
	 "<TH>%s?%s8>Network<br>Mask</A></TH>"
	 "<TH>%s?%s9>Source<br>Quench</A></TH>"
	 "<TH>%s?%s10>Timestamp</A></TH>"
	 "<TH>%s?%s11>Info</A></TH>"
	 "</TR>\n",
	  pluginName, sign,
	  pluginName, sign,
	  pluginName, sign,
	  pluginName, sign,
	  pluginName, sign,
	  pluginName, sign,
	  pluginName, sign,
	  pluginName, sign,
	  pluginName, sign,
	  pluginName, sign,
	  pluginName, sign,
	  pluginName, sign) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);

  quicksort(hosts, num,
	    sizeof(HostTraffic **), sortICMPhosts);

  for(i=0; i<num; i++)
    if(hosts[i] != NULL) {
      unsigned long tot;
      char *postAnchor;
      int idx;

      if(revertOrder)
	idx = num-i-1;
      else
	idx = i;

      if(snprintf(buf, sizeof(buf), "<TR %s> %s",
	      getRowColor(),
	      makeHostLink(hosts[idx], LONG_FORMAT, 0, 0)) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s/%s</TD>",
	       formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_ECHO])),
	       formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_ECHO]))) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s/%s</TD>",
	       formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY])),
	       formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY]))) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);


      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_UNREACH]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_UNREACH];
      if(tot > 0) {
	if(snprintf(anchor, sizeof(anchor), "%s?host=%lu&icmp=%d>",
		pluginName,
		(unsigned long)hosts[idx]->hostIpAddress.s_addr,
		(int)ICMP_UNREACH) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	postAnchor = "</A>";
      } else {
	anchor[0] = '\0';
	postAnchor = "";
      }
      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>",
	      anchor,
	      formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			 icmpMsgSent[ICMP_UNREACH]),
	      formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			 icmpMsgRcvd[ICMP_UNREACH]),
	      postAnchor) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);


      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_REDIRECT]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_REDIRECT];
      if(tot > 0) {
	if(snprintf(anchor, sizeof(anchor), "%s?host=%lu&icmp=%d>",
		pluginName,
		(unsigned long)hosts[idx]->hostIpAddress.s_addr,
		(int)ICMP_REDIRECT) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	postAnchor = "</A>";
      } else {
	anchor[0] = '\0';
	postAnchor = "";
      }
      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
	      formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			 icmpMsgSent[ICMP_REDIRECT]),
	      formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			 icmpMsgRcvd[ICMP_REDIRECT]),
	      postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT];
      if(tot > 0) {
	if(snprintf(anchor, sizeof(anchor), "%s?host=%lu&icmp=%d>",
		pluginName,
		(unsigned long)hosts[idx]->hostIpAddress.s_addr,
		(int)ICMP_ROUTERADVERT) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	postAnchor = "</A>";
      } else {
	anchor[0] = '\0';
	postAnchor = "";
      }
      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
	      formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			 icmpMsgSent[ICMP_ROUTERADVERT]),
	      formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			 icmpMsgRcvd[ICMP_ROUTERADVERT]),
	      postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_TIMXCEED]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED];
      if(tot > 0) {
	if(snprintf(anchor, sizeof(anchor), "%s?host=%lu&icmp=%d>",
		pluginName,
		(unsigned long)hosts[idx]->hostIpAddress.s_addr,
		(int)ICMP_TIMXCEED) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	postAnchor = "</A>";
      } else {
	anchor[0] = '\0';
	postAnchor = "";
      }
      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
	      formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			 icmpMsgSent[ICMP_TIMXCEED]),
	     formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			icmpMsgRcvd[ICMP_TIMXCEED]),
	      postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_PARAMPROB]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB];
      if(tot > 0) {
	if(snprintf(anchor, sizeof(anchor), "%s?host=%lu&icmp=%d>",
		pluginName,
		(unsigned long)hosts[idx]->hostIpAddress.s_addr,
		(int)ICMP_PARAMPROB) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	postAnchor = "</A>";
      } else {
	anchor[0] = '\0';
	postAnchor = "";
      }
      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
	      formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			 icmpMsgSent[ICMP_PARAMPROB]),
	      formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			 icmpMsgRcvd[ICMP_PARAMPROB]),
	      postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_MASKREQ]+
	hosts[idx]->icmpInfo->icmpMsgSent[ICMP_MASKREPLY]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY];
      if(tot > 0) {
	if(snprintf(anchor, sizeof(anchor), "%s?host=%lu&icmp=%d>",
		pluginName,
		(unsigned long)hosts[idx]->hostIpAddress.s_addr,
		(int)ICMP_MASKREQ) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	postAnchor = "</A>";
      } else {
	anchor[0] = '\0';
	postAnchor = "";
      }
      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
	      formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->
					  icmpMsgSent[ICMP_MASKREQ]+
			 hosts[idx]->icmpInfo->icmpMsgSent[ICMP_MASKREPLY])),
	      formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->
					  icmpMsgRcvd[ICMP_MASKREQ]+
			 hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY])),
	      postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH];
      if(tot > 0) {
	if(snprintf(anchor, sizeof(anchor), "%s?host=%lu&icmp=%d>",
		pluginName,
		(unsigned long)hosts[idx]->hostIpAddress.s_addr,
		(int)ICMP_SOURCE_QUENCH) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	postAnchor = "</A>";
      } else {
	anchor[0] = '\0';
	postAnchor = "";
      }
      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
	      formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			 icmpMsgSent[ICMP_SOURCE_QUENCH]),
	      formatPkts((TrafficCounter)hosts[idx]->icmpInfo->
			 icmpMsgRcvd[ICMP_SOURCE_QUENCH]),
	      postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP]+
	hosts[idx]->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY];
      if(tot > 0) {
	if(snprintf(anchor, sizeof(anchor), "%s?host=%lu&icmp=%d>",
		pluginName,
		(unsigned long)hosts[idx]->hostIpAddress.s_addr,
		(int)ICMP_TIMESTAMP) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	postAnchor = "</A>";
      } else {
	anchor[0] = '\0';
	postAnchor = "";
      }
      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
	      formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->
					  icmpMsgSent[ICMP_TIMESTAMP]+
			 hosts[idx]->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY])),
	      formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->
					  icmpMsgRcvd[ICMP_TIMESTAMP]+
			 hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY])),
	      postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      tot=hosts[idx]->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST]+
	hosts[idx]->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST]+
	hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY];
      if(tot > 0) {
	if(snprintf(anchor, sizeof(anchor), "%s?host=%lu&icmp=%d>",
		pluginName,
		(unsigned long)hosts[idx]->hostIpAddress.s_addr,
		(int)ICMP_INFO_REQUEST) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
	postAnchor = "</A>";
      } else {
	anchor[0] = '\0';
	postAnchor = "";
      }
      if(snprintf(buf, sizeof(buf), "<TD ALIGN=center>%s%s/%s%s</TD>", anchor,
	      formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->
					  icmpMsgSent[ICMP_INFO_REQUEST]+
			 hosts[idx]->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY])),
	      formatPkts((TrafficCounter)(hosts[idx]->icmpInfo->
					  icmpMsgRcvd[ICMP_INFO_REQUEST]+
			 hosts[idx]->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY])),
	      postAnchor) < 0) traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);

      sendString("</TR>\n");
  }

  sendString("</TABLE>\n");

  sendString("<p></CENTER>\n");

  printHTMLtrailer();

  free(s);
  free(r); 
  free(lbls);
  free(hosts); 
}

/* ****************************** */

static void termIcmpFunct(void) {
  traceEvent(TRACE_INFO, "Thanks for using icmpWatch..."); fflush(stdout);

  if(icmpDB != NULL) {
    gdbm_close(icmpDB);
    icmpDB = NULL;
  }

  traceEvent(TRACE_INFO, "Done.\n"); fflush(stdout);
}

/* ****************************** */

static PluginInfo icmpPluginInfo[] = {
  { "icmpWatchPlugin",
    "This plugin handles ICMP packets",
    "1.0", /* version */
    "<A HREF=http://jake.unipi.it/~deri/>L.Deri</A>",
    "icmpWatch", /* http://<host>:<port>/plugins/icmpWatch */
    1, /* Active */
    NULL, /* no special startup after init */
    termIcmpFunct, /* TermFunc   */
    handleIcmpPacket, /* PluginFunc */
    handleIcmpWatchHTTPrequest,
    NULL,
    "icmp" /* BPF filter: filter all the ICMP packets */
  }
};

/* ***************************************** */

/* Plugin entry fctn */
#ifdef STATIC_PLUGIN
PluginInfo* icmpPluginEntryFctn(void) {
#else
PluginInfo* PluginEntryFctn(void) {
#endif
	char tmpBuf[200];

  traceEvent(TRACE_INFO, "Welcome to %s. (C) 1999 by Luca Deri.\n",
	 icmpPluginInfo->pluginName);

  /* Fix courtesy of Ralf Amandi <Ralf.Amandi@accordata.net> */
  if(snprintf(tmpBuf, sizeof(tmpBuf), "%s/icmpWatch.db",dbPath) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  icmpDB = gdbm_open (tmpBuf, 0, GDBM_NEWDB, 00664, NULL);

  if(icmpDB == NULL)
    traceEvent(TRACE_WARNING, 
	       "Unable to open icmpWatch database. This plugin will be disabled.\n");

  garbageTime = actTime+(15*60); /* 15 minutes */
  return(icmpPluginInfo);
}
