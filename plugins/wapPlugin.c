/*
 *  Copyright (C) 2000 Luca Deri <deri@ntop.org>
 *                      
 *  		       http://www.ntop.org/
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

static int wapColumnSort = 0;
 
/* ****************************** */

void printWMLheader(void)  {
  char tmpStr[64];

  sendString("HTTP/1.0 200 OK\n");
  snprintf(tmpStr, 64, "Server: ntop/%s (%s)\n", version, osName);
  sendString(tmpStr);
  sendString("Content-Type: text/vnd.wap.wml;charset=UTF-8\n\n"); 
}

/* ********************** */

static void printWmlNotFoundError(void) {

}

/* ********************** */

static void printWmlNoDataYet(void) {

}

/* ********************** */

static int cmpWapFctn(const void *_a, const void *_b) {
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  TrafficCounter a_, b_;

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

  if(wapColumnSort == 0) {
    /* Data Sent */
    a_ = (*a)->bytesSent;
    b_ = (*b)->bytesSent;
  } else  {
    /* Data Rcvd */
    a_ = (*a)->bytesReceived;
    b_ = (*b)->bytesReceived;
  }

  if(a_ < b_)
    return(1);
  else if (a_ > b_)
    return(-1);
  else
    return(0);
}

/* ********************** */

static void printWmlIndex(void) {
  int diff;
  u_int idx, numEntries=0;
  HostTraffic *el;
  HostTraffic* tmpTable[HASHNAMESIZE];
  char *tmpName, buf[BUF_SIZE];
  TrafficCounter unicastPkts=0;

  printWMLheader();

  for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++)
    if(((el = device[actualDeviceId].hash_hostTraffic[idx]) != NULL) 
       && (!broadcastHost(el)))
      tmpTable[numEntries++]=el;
  
  if(numEntries == 0) {
    printWmlNoDataYet();
    return;
  }

  sendString("<?xml version=\"1.0\"?>\n");
  sendString("<!DOCTYPE wml PUBLIC \"-//WAPFORUM//DTD WML 1.1//EN\" \"http:///www.wapforum.org/DTD/wml_1.1.xml\">\n\n");
  sendString("<wml>\n");
  sendString("  <card id=\"home\" title=\"ntop for Wap\">\n");
  sendString("	<p>\n");
  sendString("		<a href=\"#senders\">Top Senders</a><br/>\n");
  sendString("		<a href=\"#receivers\">Top Receivers</a><br/>\n");
  sendString("		<a href=\"#stats\">Stats</a><br/>\n");
  sendString("	</p>\n");
  sendString("  </card>\n");
  sendString("  <card id=\"senders\" title=\"Top Senders\"> \n");
  sendString("	<p>\n");
  sendString("	<table columns=\"2\" align=\"LCC\">\n");
  sendString("		<tr><td><b>Host</b></td><td><b>Total</b></td></tr>\n");
  
  /* Data Sent */
  wapColumnSort = 0;  
  quicksort(tmpTable, numEntries, sizeof(HostTraffic*), cmpWapFctn); 
  
  for(idx=0; idx<numEntries; idx++) {
    if(idx == 5) break;

    el = tmpTable[idx];
    tmpName = getHostName(el, 0);

    if((strcmp(tmpName, "0.0.0.0") == 0) || (tmpName[0] == '\0'))
      tmpName = el->ethAddressString;
	    
    snprintf(buf, sizeof(buf),
	    "<tr><td><a href=\"/ntop/host.wml?%s\">%s</a></td>"
	    "<td>%s</td></tr>\n",
	    tmpName, tmpName, 	    
	    formatBytes(el->bytesSent, 1));	
    sendString(buf);
  }

  sendString("</table>\n");
  sendString("	<a href=\"#home\">[Back Home]</a><br/>\n");
  sendString("  </p>\n");
  sendString("	</card>\n");
  sendString("  <card id=\"receivers\" title=\"Top Receivers\">\n");
  sendString("	<p>\n");
  sendString("	<table columns=\"2\" align=\"LCC\">\n");
  sendString("	<tr><td><b>Host</b></td><td><b>Total</b></td></tr>\n");

  /* Data Rcvd */
  wapColumnSort = 1;  
  quicksort(tmpTable, numEntries, sizeof(HostTraffic*), cmpFctn); 

  for(idx=0; idx<numEntries; idx++) {
    if(idx == 5) break;

    el = tmpTable[idx];
    tmpName = getHostName(el, 0);

    if((strcmp(tmpName, "0.0.0.0") == 0) || (tmpName[0] == '\0'))
      tmpName = el->ethAddressString;
	    
    snprintf(buf, sizeof(buf), 
	    "<tr><td><a href=\"/ntop/host.wml?%s\">%s</a></td>"
	    "<td>%s</td></tr>\n",
	    tmpName, tmpName, 	    
	    formatBytes(el->bytesReceived, 1));	
    sendString(buf);
  }

  sendString("</table>\n");
  sendString("	<a href=\"#home\">[Back Home]</a><br/>\n");
  sendString("  </p>\n");
  sendString("	</card>\n");
  /* ************************* */

  sendString("  <card id=\"stats\" title=\"Traffic Stats\">\n");
  sendString("	<p>\n");
  sendString("	<table columns=\"2\" align=\"LCC\">\n");

  /** **/

  snprintf(buf, sizeof(buf),"<tr><td>Sampling&nbsp;Time</td>"
	  "<td>%s</td></tr>\n",
	  formatSeconds(actTime-initialSniffTime));
  sendString(buf);

  /** **/
  
  diff = (int)(device[actualDeviceId].ethernetPkts -
	       device[actualDeviceId].broadcastPkts -
	       device[actualDeviceId].multicastPkts);
  if(diff > 0)
    unicastPkts = 0; /* It shouldn't happen */
  else 
    unicastPkts = (TrafficCounter)diff; 

  if(device[actualDeviceId].ethernetPkts <= 0) device[actualDeviceId].ethernetPkts = 1;
	
  snprintf(buf, sizeof(buf),"<tr><td>Total</td><td>%s</td></tr>\n",
	  formatPkts(device[actualDeviceId].ethernetPkts)); 
  sendString(buf);

  snprintf(buf, sizeof(buf),"<tr><td>Unicast</td>"
	  "<td>%s [%.1f%%]</td></tr>\n", 
	  formatPkts(unicastPkts),
	  (float)(100*unicastPkts)/(float)device[actualDeviceId].ethernetPkts);
  sendString(buf);
  snprintf(buf, sizeof(buf),"<tr><td>Broadcast</td>"
	  "<td>%s [%.1f%%]</td></tr>\n", 
	  formatPkts(device[actualDeviceId].broadcastPkts),
	  (float)(100*device[actualDeviceId].broadcastPkts)
	   /(float)device[actualDeviceId].ethernetPkts); 
  sendString(buf);

  if(device[actualDeviceId].multicastPkts > 0) {
    snprintf(buf, sizeof(buf),"<tr><td>Multicast</td>"
	    "<td>%s [%.1f%%]</td></tr>\n", 
	    formatPkts(device[actualDeviceId].multicastPkts),
	    (float)(100*device[actualDeviceId].multicastPkts)
	     /(float)device[actualDeviceId].ethernetPkts); 
    sendString(buf);
  }

  /** **/
  sendString("</table>\n");
  sendString("	<a href=\"#home\">[Back Home]</a><br/>\n");
  sendString("  </p>\n");
  sendString("	</card>\n");

  /* ************************* */

  sendString("</wml>\n");
}

/* ********************** */

static void printWmlHostInfo(char *host _UNUSED_) {

}

/* ********************** */

static void handleWAPrequest(char* url) {

  if((url == NULL) 
     || (url[0] == 0) 
     || (strncmp(url, "index.wml", 
		 strlen("index.wml")) == 0))  {
    printWmlIndex();
  } else if(strncmp(url, "host.wml", strlen("host.wml")) == 0)
    printWmlHostInfo(&url[strlen("host.wml")+1]);
  else
    printWmlNotFoundError();
}

/* ****************************** */

static void termWapFunct(void) {
  traceEvent(TRACE_INFO, "Thanks for using wapWatch...\n");
  traceEvent(TRACE_INFO, "Done.\n");
}

/* ****************************** */

static PluginInfo WAPPluginInfo[] = {
  { "WAPPlugin",
    "ntop WAP (Wireless Application protocol) Interface",
    "1.0",           /* version */
    "<A HREF=http://jake.unipi.it/~deri/>L.Deri</A>", 
    "WAPPlugin",      /* http://<host>:<port>/plugins/WAPPlugin */
    0, /* Not Active */
    NULL, /* no special startup after init */
    termWapFunct,    /* TermFunc   */
    NULL,    /* PluginFunc */
    handleWAPrequest,
    NULL,
    NULL /* BPF Filter */
  }
};

/* Plugin entry fctn */
#ifdef STATIC_PLUGIN
PluginInfo* wapPluginEntryFctn(void) {
#else
PluginInfo* PluginEntryFctn(void) {
#endif
  traceEvent(TRACE_INFO, "Welcome to %s. (C) 2000 by Luca Deri.\n",  
	 WAPPluginInfo->pluginName);

  return(WAPPluginInfo);
}
