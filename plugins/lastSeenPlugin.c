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

#define MY_NETWORK 16

/* ****************************** */

extern int newSock;

static GDBM_FILE LsDB;
static int disabled = 0;

typedef struct LsHostInfo {
  struct in_addr HostIpAddress;
  time_t         LastUpdated;
} LsHostInfo;

typedef struct LsHostNote {
  char note[50];
} LsHostNote;

static void handleLsPacket(const struct pcap_pkthdr *h _UNUSED_,
			   const u_char *p) {
  struct ip ip;
  struct ether_header *ep;
  datum key_data, data_data;
  char tmpStr[32];
  LsHostInfo HostI;
  unsigned short rc;

  if ( disabled ) return;

  ep = (struct ether_header *)p;
  memcpy(&ip, (p+sizeof(struct ether_header)), sizeof(struct ip));

  NTOHL(ip.ip_src.s_addr); NTOHL(ip.ip_dst.s_addr);

#ifdef DEBUG
  traceEvent(TRACE_INFO, "%s [%x]", intoa(ip.ip_src), ip.ip_src.s_addr);
  traceEvent(TRACE_INFO, "->%s [%x]\n", intoa(ip.ip_dst), ip.ip_dst.s_addr);
#endif

  rc = isPseudoLocalAddress(&ip.ip_src);

  if(rc == 0) 
    return;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "-->>>>%s [%d]\n", intoa(ip.ip_src), rc); 
#endif

  HostI.HostIpAddress = ip.ip_src;
  HostI.LastUpdated = actTime;

  snprintf(tmpStr, sizeof(tmpStr), "%u", (unsigned) ip.ip_src.s_addr); 
  key_data.dptr = tmpStr; key_data.dsize = strlen(key_data.dptr)+1;
  data_data.dptr = (char *)&HostI;
  data_data.dsize = sizeof(HostI)+1;

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex,"handleLSPackage");
#endif 
  gdbm_store(LsDB, key_data, data_data, GDBM_REPLACE);	
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 
}

 /* Record sort */

static int SortLS(const void *_a, const void *_b) {
  LsHostInfo *a = (LsHostInfo *)_a;
  LsHostInfo *b = (LsHostInfo *)_b;
  unsigned long n1, n2;
  if(((a) == NULL) && ((b) != NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (1)\n");
    return(1);
  } else if(((a) != NULL) && ((b) == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (2)\n");
    return(-1);
  } else if(((a) == NULL) && ((b) == NULL)) {
    traceEvent(TRACE_WARNING, "WARNING (3)\n");
    return(0);
  }
  n1 = (*a).HostIpAddress.s_addr;
  n2 = (*b).HostIpAddress.s_addr;
  if ( n1==n2 )
    return(0);
  else if ( n1 > n2 )
    return(-1);
  else
    return(1);
}

/* ============================================================== */

static void handleLsHTTPrequest(char* url) {
  char tmpStr[BUF_SIZE];
  char tmpTime[25], postData[128];
  char *no_info = "<TH>-NO INFO-</TH>",*tmp, *no_note ="-";
  datum ret_data,key_data, content;
  LsHostInfo tablehost[MY_NETWORK*256];
  LsHostNote HostN;
  HostTraffic *HostT;
  struct tm loctime;
  struct in_addr char_ip;
  int entry = 0, num_hosts;

  if (disabled) {
    sendHTTPProtoHeader(); sendHTTPHeaderType(); printHTTPheader();
    sendString("<P><CENTER><H1><i>Plugin Disabled</i></H1></CENTER></FONT>\n");
    printHTTPtrailer();
    return;
  }

  if ( url && strncmp(url,"N",1)==0 ) {
    char_ip.s_addr = strtoul(url+1,NULL,10);
    NotesURL(url+1, intoa(char_ip));
    return;
  }

  sendHTTPProtoHeader(); sendHTTPHeaderType(); printHTTPheader();

  if ( url && strncmp(url,"P",1)==0 ) {
    entry = recv(newSock, &postData[0],127,0); 
    postData[entry] = '\0';
    addNotes( url+1, &postData[6]);	
    char_ip.s_addr = strtoul(url+1,NULL,10);
    snprintf(tmpStr, sizeof(tmpStr), "<P><CENTER><H1><i>OK! Added comments for %s.</i>"
	    "</H1></CENTER></FONT>\n",intoa(char_ip));
    sendString(tmpStr);
    sendString("<br><A HREF=/plugins/LastSeen>Reload</A>");
    printHTTPtrailer();
    return;
  }

  if ( url && strncmp(url,"D",1)==0 ) 
    deletelastSeenURL(url+1);
			
  /* Finding hosts... */

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "handleLSHTTPrequest");
#endif 
  ret_data = gdbm_firstkey(LsDB);
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 
  while ( ret_data.dptr !=NULL ) {
    key_data = ret_data;
#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "handleLSHTTPrequest");
#endif 
    content = gdbm_fetch(LsDB,key_data);
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif 
    if ( key_data.dptr[1]!='_') {
      memcpy(&tablehost[entry],(struct LsHostInfo *)content.dptr,sizeof(struct LsHostInfo)); 	
      entry++;
    }
    free(content.dptr);
#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "handleLSHTTPrequest");
#endif 
    ret_data = gdbm_nextkey(LsDB,key_data);
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif 
    free(key_data.dptr); 
  }

  /* ========================================================================= */

  quicksort(( void *)&tablehost[0],entry,sizeof(LsHostInfo),SortLS);
  num_hosts=entry;
  entry--;
  sendString("<CENTER><FONT FACE=Helvetica><H1>Last Seen Statistics</H1></CENTER><p>\n");
  sendString("<CENTER><TABLE BORDER>\n");
  sendString("<TR><TH>Host</TH><TH>Address</TH><TH>LastSeen</TH><TH>Comments</TH><TH>Options</TH></TR>\n");
  while ( entry >= 0 ) {

    /* Getting notes from the DN */

    snprintf(tmpStr, sizeof(tmpStr), "N_%u", (unsigned) tablehost[entry].HostIpAddress.s_addr);

    key_data.dptr = tmpStr;
    key_data.dsize = strlen(key_data.dptr)+1;
		
#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "quicksort");
#endif 
    content = gdbm_fetch(LsDB,key_data);
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif 
    strncpy(HostN.note, no_note, sizeof(HostN.note));	
    if ( content.dptr ) {
      memcpy(&HostN,(struct LsHostNote *)content.dptr,sizeof(struct LsHostNote)); 	
      free(content.dptr);
    }
    /* ================================================================== */


    HostT = findHostByNumIP(intoa(tablehost[entry].HostIpAddress));
    if ( HostT )
      tmp = makeHostLink(HostT,LONG_FORMAT,0,0);
    else
      tmp = no_info;

    localtime_r(&tablehost[entry].LastUpdated, &loctime);
    strftime(tmpTime,25,"%d-%m-%Y&nbsp;%H:%M", &loctime);

    snprintf(tmpStr, sizeof(tmpStr), "<TR %s>%s</TH>"
	    "<TH ALIGN=LEFT>&nbsp;&nbsp;%s&nbsp;&nbsp</TH>"
	    "<TH>&nbsp;&nbsp;%s&nbsp;&nbsp</TH><TH>%s</TH><TH>"
	    "<A HREF=\"/plugins/LastSeen?D%u\">Del</A>&nbsp;&nbsp;&nbsp;"
	    "<A HREF=\"/plugins/LastSeen?N%u\">Notes</A></TH></TR>\n",
	    getRowColor(),
	    tmp,
	    intoa(tablehost[entry].HostIpAddress),
	    tmpTime,
	    HostN.note,
	    (unsigned) tablehost[entry].HostIpAddress.s_addr,
	    (unsigned) tablehost[entry].HostIpAddress.s_addr);
    sendString(tmpStr);
    entry--;
  }
  sendString("</TABLE></CENTER><p>\n");
  snprintf(tmpStr, sizeof(tmpStr), 
	   "<hr><CENTER><b>%u</b> host(s) collected.</CENTER><br>",
	   num_hosts);
  sendString(tmpStr);
  printHTTPtrailer();
}

/* Adding notes changing the key */

static void addNotes(char *addr, char *PostNotes) {
  datum key_data, data_data;
  char tmpStr[32];
  LsHostNote HostN;
  int idx;

  for ( idx =0; PostNotes[idx]; idx++) {
    if ( PostNotes[idx]=='+') PostNotes[idx]=' ';
  }

  strncpy(HostN.note,PostNotes, sizeof(HostN.note));

  snprintf(tmpStr, sizeof(tmpStr), "N_%s",addr);

  key_data.dptr = tmpStr;
  key_data.dsize = strlen(key_data.dptr)+1;
  data_data.dptr = (char *)&HostN;
  data_data.dsize = sizeof(HostN)+1;

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "addNotes");
#endif 
  if ( strlen(PostNotes)>2 )
    gdbm_store(LsDB, key_data, data_data, GDBM_REPLACE);	
  else
    gdbm_delete(LsDB,key_data);
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 
}

/* Prepearing the page */

static void NotesURL(char *addr, char *ip_addr) {
  datum key_data, content;
  char tmpStr[32];
  char tmp[64];

  snprintf(tmpStr, sizeof(tmpStr), "N_%s",addr);
  key_data.dptr = tmpStr;
  key_data.dsize = strlen(key_data.dptr)+1;

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "NotesURL");
#endif 
  content = gdbm_fetch(LsDB,key_data);
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 

  printHTTPheader();
  sendString("<title>Manage Notes</title>\n");
  sendString("</head><BODY COLOR=#FFFFFF><FONT FACE=Helvetica>\n");
  snprintf(tmp, sizeof(tmp), "<H1><CENTER>Notes for %s</CENTER></H1><p><p><hr>\n",ip_addr);
  sendString(tmp);
  snprintf(tmp, sizeof(tmp), "<FORM METHOD=POST ACTION=/plugins/LastSeen?P%s>\n",addr);
  sendString(tmp);
  if ( content.dptr ) {
    snprintf(tmp, sizeof(tmp), "<INPUT TYPE=text NAME=Notes SIZE=49 VALUE=\"%s\">\n",content.dptr);
    sendString(tmp);
    free(content.dptr);
  } else {
    sendString("<INPUT TYPE=text NAME=Notes SIZE=49>\n");
  }
  sendString("<p>\n");
  sendString("<input type=submit value=\"Add Notes\"><input type=reset></form>\n");
}

static void deletelastSeenURL( char *addr ) {
  datum key_data;
  char tmpStr[32];

  snprintf(tmpStr, sizeof(tmpStr), "N_%s",addr);

  key_data.dptr = addr;
  key_data.dsize = strlen(key_data.dptr)+1;

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex,"deletelastSeenURL");
#endif 

  gdbm_delete(LsDB,key_data);  /* Record */
  key_data.dptr = tmpStr;
  key_data.dsize = strlen(key_data.dptr)+1;
  gdbm_delete(LsDB,key_data);  /* Notes */

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 

}

static void termLsFunct() {
  traceEvent(TRACE_INFO, "Thanks for using LsWatch..."); fflush(stdout);
    
  if(LsDB != NULL) {
#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "termLsFunct");
#endif 
    gdbm_close(LsDB);
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif 
    LsDB = NULL;
  }

  traceEvent(TRACE_INFO, "Done.\n"); fflush(stdout);
}


/* ====================================================================== */

static PluginInfo LsPluginInfo[] = {
  { "LastSeenWatchPlugin",
    "This plugin handles Last Seen Time Host",
    "1.0", /* version */
    "<A HREF=mailto:marangoni@unimc.it>A.Marangoni</A>", 
    "LastSeen", /* http://<host>:<port>/plugins/Ls */
    0, /* Not Active */
    NULL, /* no special startup after init */
    termLsFunct, /* TermFunc   */
    handleLsPacket, /* PluginFunc */
    handleLsHTTPrequest,
    NULL,
    "ip" /* BPF filter: filter all the ICMP packets */
  }
};
  
/* Plugin entry fctn */
#ifdef STATIC_PLUGIN
PluginInfo* lsPluginEntryFctn() {
#else
PluginInfo* PluginEntryFctn() {
#endif
  char tmpBuf[200];

  traceEvent(TRACE_INFO, "Welcome to %s. (C) 1999 by Andrea Marangoni.\n", 
	     LsPluginInfo->pluginName);

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "PluginEntry");
#endif 

  /* Fix courtesy of Ralf Amandi <Ralf.Amandi@accordata.net> */
  snprintf(tmpBuf, sizeof(tmpBuf), "%s/LsWatch.db",dbPath);
  LsDB = gdbm_open (tmpBuf, 0, GDBM_WRCREAT, 00664, NULL);

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 

  if(LsDB == NULL) {
    traceEvent(TRACE_ERROR, 
	       "Unable to open LsWatch database. This plugin will be disabled.\n");
    disabled = 1;
  }
  return(LsPluginInfo);
}
