/*
 *  Copyright (C) 1999 Andrea Marangoni <marangoni@unimc.it>
 *                     Universita' di Macerata
 *                     Italy
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

/* Forward */
static void NotesURL(char *addr, char *ip_addr);
static void addNotes(char *addr, char *PostNotes);
static void deletelastSeenURL( char *addr );
static void setPluginStatus(char * status);

/* ****************************** */

static GDBM_FILE LsDB = NULL;
static int disabled = 0;

typedef struct LsHostInfo {
  HostAddr HostIpAddress;
  time_t   LastUpdated;
} LsHostInfo;

typedef struct LsHostNote {
  char note[50];
} LsHostNote;

static void handleLsPacket(u_char *_deviceId, 
			   const struct pcap_pkthdr *h _UNUSED_,
			   const u_char *p) {
  struct ip ip;
  struct ether_header *ep;
  datum key_data, data_data;
  char tmpStr[32];
  LsHostInfo HostI;
  unsigned short rc;
  u_int deviceId;

  if ( disabled ) return;

#ifdef WIN32
  deviceId = 0;
#else
  deviceId = (u_int)(*_deviceId);
#endif

  ep = (struct ether_header *)p;
  memcpy(&ip, (p+sizeof(struct ether_header)), sizeof(struct ip));

  NTOHL(ip.ip_src.s_addr); NTOHL(ip.ip_dst.s_addr);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "%s [%x]", intoa(ip.ip_src), ip.ip_src.s_addr);
  traceEvent(CONST_TRACE_INFO, "->%s [%x]", intoa(ip.ip_dst), ip.ip_dst.s_addr);
#endif

  rc = in_isPseudoLocalAddress(&ip.ip_src, deviceId);

  if(rc == 0) 
    return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "-->>>>%s [%d]", intoa(ip.ip_src), rc); 
#endif

  addrinit(&HostI.HostIpAddress);
  HostI.HostIpAddress.addr._hostIp4Address = ip.ip_src;
  HostI.LastUpdated = myGlobals.actTime;

  if(snprintf(tmpStr, sizeof(tmpStr), "%u", (unsigned) ip.ip_src.s_addr) < 0)
    BufferTooShort();
  key_data.dptr = tmpStr; key_data.dsize = strlen(key_data.dptr)+1;
  data_data.dptr = (char *)&HostI;
  data_data.dsize = sizeof(HostI)+1;

  /* Test for disabled inside the protection of the mutex, also, so that if
   * we disabled the plugin since the test above, we don't seg fault
   */
  if (!disabled)
    gdbm_store(LsDB, key_data, data_data, GDBM_REPLACE);
}

/* Record sort */

static int SortLS(const void *_a, const void *_b) {
  LsHostInfo *a = (LsHostInfo *)_a;
  LsHostInfo *b = (LsHostInfo *)_b;
  unsigned long n1, n2;
  if(((a) == NULL) && ((b) != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "SortLS() (1)");
    return(1);
  } else if(((a) != NULL) && ((b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "SortLS() (2)");
    return(-1);
  } else if(((a) == NULL) && ((b) == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "SortLS() (3)");
    return(0);
  }

  n1 = (*a).HostIpAddress.Ip4Address.s_addr;
  n2 = (*b).HostIpAddress.Ip4Address.s_addr;
  
  if (n1 == n2)
    return(0);
  else if(n1 > n2)
    return(-1);
  else
    return(1);
}

/* ============================================================== */

static void handleLsHTTPrequest(char* url) {
  char tmpStr[LEN_GENERAL_WORK_BUFFER], hostLinkBuf[LEN_GENERAL_WORK_BUFFER];
  char tmpTime[25], postData[128];
  char *no_info = "<TH "TH_BG">-NO INFO-</TH>",*tmp, *no_note ="-";
  datum ret_data,key_data, content;
  LsHostInfo tablehost[MAX_LASTSEEN_TABLE_SIZE];
  LsHostNote HostN;
  HostTraffic *HostT;
  struct tm loctime;
  struct in_addr char_ip;
  int entry = 0, num_hosts;

  if(disabled) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);
    printHTMLheader("Status for the \"lastSeen\" Plugin", NULL, BITFLAG_HTML_NO_REFRESH);
    printFlagedWarning("<I>This plugin is disabled.<I>");
    sendString("<p><center>Return to <a href=\"../" CONST_SHOW_PLUGINS_HTML "\">plugins</a> menu</center></p>\n");
    printHTMLtrailer();
    return;
  }

  if ( url && strncmp(url,"N",1)==0 ) {
    char_ip.s_addr = strtoul(url+1,NULL,10);
    NotesURL(url+1, intoa(char_ip));
    return;
  }

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);
  printHTMLheader(NULL, NULL, 0);

  if ( url && strncmp(url,"P",1)==0 ) {
    entry = recv(myGlobals.newSock, &postData[0],127,0); 
    postData[entry] = '\0';
    addNotes( url+1, &postData[6]);	
    char_ip.s_addr = strtoul(url+1, NULL, 10);
    if(snprintf(tmpStr, sizeof(tmpStr), "<I>OK! Added comments for %s.</i>\n",
		intoa(char_ip)) < 0) BufferTooShort();
    printSectionTitle(tmpStr);
    sendString("<br><A HREF=/plugins/LastSeen>Reload</A>");
    sendString("<p><center>Return to <a href=\"../" CONST_SHOW_PLUGINS_HTML "\">plugins</a> menu</center></p>\n");
    printHTMLtrailer();
    return;
  }

  if ( url && strncmp(url,"D",1)==0 ) 
    deletelastSeenURL(url+1);
			
  /* Finding hosts... */

  ret_data = gdbm_firstkey(LsDB);

  while ( ret_data.dptr !=NULL ) {
    key_data = ret_data;
    content = gdbm_fetch(LsDB,key_data);
    if ( (key_data.dptr[1]!='_') && (entry < MAX_LASTSEEN_TABLE_SIZE) ) {
      memcpy(&tablehost[entry],(struct LsHostInfo *)content.dptr,sizeof(struct LsHostInfo)); 	
      entry++;
    }
    free(content.dptr);
    ret_data = gdbm_nextkey(LsDB,key_data);
    free(key_data.dptr); 
  }

  /* ========================================================================= */

  qsort(( void *)&tablehost[0],entry,sizeof(LsHostInfo),SortLS);
  num_hosts=entry;
  entry--;
  printSectionTitle("Last Seen Statistics");

  if (entry >= MAX_LASTSEEN_TABLE_SIZE - 1) {
    sendString("<P><CENTER>NOTE:&nbsp;Table size at/exceeds limit, some data may not be displayed.</CENTER></P>\n");
  }

  sendString("<CENTER><TABLE BORDER>\n");
  sendString("<TR "TR_ON"><TH "TH_BG">Host</TH><TH "TH_BG">Address</TH><TH "TH_BG">LastSeen</TH><TH "TH_BG">Comments</TH><TH "TH_BG">Options</TH></TR>\n");
  while ( entry >= 0 ) {
    HostAddr addr;

    /* Getting notes from the DN */

    if(snprintf(tmpStr, sizeof(tmpStr), "N_%u", (unsigned)tablehost[entry].HostIpAddress.Ip4Address.s_addr) < 0) 
      BufferTooShort();

    key_data.dptr = tmpStr;
    key_data.dsize = strlen(key_data.dptr)+1;
		
    content = gdbm_fetch(LsDB,key_data);
    strncpy(HostN.note, no_note, sizeof(HostN.note));	
    if ( content.dptr ) {
      memcpy(&HostN,(struct LsHostNote *)content.dptr,sizeof(struct LsHostNote)); 	
      free(content.dptr);
    }
    /* ================================================================== */

    addrcpy(&addr, &tablehost[entry].HostIpAddress);
    HostT = findHostByNumIP(addr, myGlobals.actualReportDeviceId);
    if(HostT)
      tmp = makeHostLink(HostT, FLAG_HOSTLINK_HTML_FORMAT, 
			 0, 0, hostLinkBuf, sizeof(hostLinkBuf));
    else
      tmp = no_info;

    localtime_r(&tablehost[entry].LastUpdated, &loctime);
    strftime(tmpTime,25,"%d-%m-%Y&nbsp;%H:%M", &loctime);

    if(snprintf(tmpStr, sizeof(tmpStr), "<TR "TR_ON" %s>%s</TH>"
		"<TH "TH_BG" ALIGN=LEFT>&nbsp;&nbsp;%s&nbsp;&nbsp</TH>"
		"<TH "TH_BG">&nbsp;&nbsp;%s&nbsp;&nbsp</TH><TH "TH_BG">%s</TH><TH "TH_BG">"
		"<A HREF=\"/plugins/LastSeen?D%u\">Del</A>&nbsp;&nbsp;&nbsp;"
		"<A HREF=\"/plugins/LastSeen?N%u\">Notes</A></TH></TR>\n",
		getRowColor(),
		tmp,
		addrtostr(&tablehost[entry].HostIpAddress),
		tmpTime,
		HostN.note,
		(unsigned) tablehost[entry].HostIpAddress.Ip4Address.s_addr,
		(unsigned) tablehost[entry].HostIpAddress.Ip4Address.s_addr) < 0)
      BufferTooShort();
    sendString(tmpStr);
    entry--;
  }
  sendString("</TABLE></CENTER><p>\n");
  if(snprintf(tmpStr, sizeof(tmpStr), 
	      "<CENTER><b>%u</b> host(s) collected.</CENTER><br>",
	      num_hosts) < 0) BufferTooShort();
  sendString(tmpStr);
  sendString("<p align=right>[ Back to <a href=\"../" CONST_SHOW_PLUGINS_HTML "\">plugins</a> ]&nbsp;</p>\n");
  printHTMLtrailer();
}

/* Adding notes changing the key */

static void addNotes(char *addr, char *PostNotes) {
  datum key_data, data_data;
  char tmpStr[32];
  LsHostNote HostN;
  int idx;

  if(disabled) return;

  for ( idx =0; PostNotes[idx]; idx++) {
    if ( PostNotes[idx]=='+') PostNotes[idx]=' ';
  }

  strncpy(HostN.note,PostNotes, sizeof(HostN.note));

  if(snprintf(tmpStr, sizeof(tmpStr), "N_%s",addr) < 0) BufferTooShort();

  key_data.dptr = tmpStr;
  key_data.dsize = strlen(key_data.dptr)+1;
  data_data.dptr = (char *)&HostN;
  data_data.dsize = sizeof(HostN)+1;

  if (strlen(PostNotes) > 2)
    gdbm_store(LsDB, key_data, data_data, GDBM_REPLACE);	
  else
    gdbm_delete(LsDB,key_data);
}

/* Preparing the page */

static void NotesURL(char *addr, char *ip_addr) {
  datum key_data, content;
  char tmpStr[32];
  char tmp[64];

  if(disabled) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);
    printFlagedWarning("<I>This plugin is disabled.<I>");
    printHTMLtrailer();
    return;
  }

  if(snprintf(tmpStr, sizeof(tmpStr), "N_%s",addr) < 0) BufferTooShort();
  key_data.dptr = tmpStr;
  key_data.dsize = strlen(key_data.dptr)+1;

  content = gdbm_fetch(LsDB,key_data);

  snprintf(tmp, sizeof(tmp), "Notes for %s", ip_addr);
  printHTMLheader(tmp, NULL, 0);
  
  sendString("<FONT FACE=Helvetica><P><HR>\n");
  sendString("<title>Manage Notes</title>\n");
  sendString("</head><BODY COLOR=#FFFFFF><FONT FACE=Helvetica>\n");
  if(snprintf(tmp, sizeof(tmp), "<H1><CENTER>Notes for %s</CENTER></H1><p><p><hr>\n",ip_addr) < 0) 
    BufferTooShort();
  sendString(tmp);
  if(snprintf(tmp, sizeof(tmp), "<FORM METHOD=POST ACTION=/plugins/LastSeen?P%s>\n",addr) < 0) 
    BufferTooShort();
  sendString(tmp);
  if (content.dptr) {
    if(snprintf(tmp, sizeof(tmp), "<INPUT TYPE=text NAME=Notes SIZE=49 VALUE=\"%s\">\n",
		content.dptr) < 0) BufferTooShort();
    sendString(tmp);
    free(content.dptr);
  } else {
    sendString("<INPUT TYPE=text NAME=Notes SIZE=49>\n");
  }
  sendString("<p>\n");
  sendString("<input type=submit value=\"Add Notes\"><input type=reset></form>\n");
  sendString("</FONT>\n");
}

static void deletelastSeenURL( char *addr ) {
  datum key_data;
  char tmpStr[32];

  if(disabled) return;

  if(snprintf(tmpStr, sizeof(tmpStr), "N_%s",addr) < 0)
    BufferTooShort();

  key_data.dptr = addr;
  key_data.dsize = strlen(key_data.dptr)+1;

  gdbm_delete(LsDB,key_data);  /* Record */
  key_data.dptr = tmpStr;
  key_data.dsize = strlen(key_data.dptr)+1;
  gdbm_delete(LsDB,key_data);  /* Notes */
}

static void termLsFunct(void) {
  traceEvent(CONST_TRACE_INFO, "LASTSEEN: Thanks for using LsWatch"); fflush(stdout);
    
  if(LsDB != NULL) {
    disabled = 1;
    sleep(1); /*
		Wait if there's an ongoing request
		being processed (otherwise we get an lseek_error if we
		close the DB while somebody is using it
	      */
    gdbm_close(LsDB);
    LsDB = NULL;
  }

  traceEvent(CONST_TRACE_INFO, "LASTSEEN: Done"); fflush(stdout);
}


/* ====================================================================== */

static PluginInfo LsPluginInfo[] = {
  { 
    VERSION, /* current ntop version */
    "LastSeenWatchPlugin",
    "This plugin produces a report about the last time packets were seen from "
    "each specific host.  A note card database is available for recording "
    "additional information.",
    "2.2", /* version */
    "<A HREF=\"mailto:&#109;&#097;&#114;&#097;&#110;&#103;&#111;&#110;&#105;&#064;&#117;&#110;&#105;&#109;&#099;&#046;&#105;&#116;\">A.Marangoni</A>", 
    "LastSeen", /* http://<host>:<port>/plugins/Ls */
    0, /* Active by default */
    0, /* Inactive setup */
    NULL, /* no special startup after init */
    termLsFunct, /* TermFunc   */
    handleLsPacket, /* PluginFunc */
    handleLsHTTPrequest,
    "ip", /* BPF filter: filter all the ICMP packets */
    NULL /* no status */
  }
};
  
/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGIN
PluginInfo* lsPluginEntryFctn(void) {
#else
  PluginInfo* PluginEntryFctn(void) {
#endif
    char tmpBuf[200];

    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "LASTSEEN: Welcome to %s. (C) 1999 by Andrea Marangoni", 
	       LsPluginInfo->pluginName);
  
    /* Fix courtesy of Ralf Amandi <Ralf.Amandi@accordata.net> */
    if(snprintf(tmpBuf, sizeof(tmpBuf), "%s/LsWatch.db", myGlobals.dbPath) < 0) 
      BufferTooShort();
    LsDB = gdbm_open (tmpBuf, 0, GDBM_WRCREAT, 00664, NULL);

    if(LsDB == NULL) {
      traceEvent(CONST_TRACE_ERROR, 
		 "LASTSEEN: Unable to open LsWatch database - the plugin will be disabled");
      setPluginStatus("Disabled - unable to open LsWatch database.");
      disabled = 1;
    } else {
      setPluginStatus(NULL);
    }
    return(LsPluginInfo);
  }

  static void setPluginStatus(char * status)
    {
      if (LsPluginInfo->pluginStatusMessage != NULL)
	free(LsPluginInfo->pluginStatusMessage);
      if (status == NULL) {
	LsPluginInfo->pluginStatusMessage = NULL;
      } else {
	LsPluginInfo->pluginStatusMessage = strdup(status);
      }
    }
