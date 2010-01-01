/*
 *  Copyright (C) 2009-10 Luca Deri <deri@ntop.org>
 *
 * 		       http://www.ntop.org/
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

/* ************************************************* */

static char* flag2string(int eventValue) {
  static char buf[64];

  switch(eventValue) {
  case FLAG_THE_DOMAIN_HAS_BEEN_COMPUTED   : return("THE_DOMAIN_HAS_BEEN_COMPUTED");
  case FLAG_PRIVATE_IP_ADDRESS             : return("PRIVATE_IP_ADDRESS");
  case FLAG_SUBNET_LOCALHOST               : return("SUBNET_LOCALHOST");
  case FLAG_BROADCAST_HOST                 : return("BROADCAST_HOST");
  case FLAG_MULTICAST_HOST                 : return("MULTICAST_HOST");
  case FLAG_GATEWAY_HOST                   : return("GATEWAY_HOST");
  case FLAG_NAME_SERVER_HOST               : return("NAME_SERVER_HOST");
  case FLAG_SUBNET_PSEUDO_LOCALHOST        : return("SUBNET_PSEUDO_LOCALHOST");
  case FLAG_HOST_TYPE_SERVER               : return("HOST_TYPE_SERVER");
  case FLAG_HOST_TYPE_WORKSTATION          : return("HOST_TYPE_WORKSTATION");
  case FLAG_HOST_TYPE_PRINTER              : return("HOST_TYPE_PRINTER");
  case FLAG_HOST_TYPE_SVC_SMTP             : return("HOST_TYPE_SVC_SMTP");
  case FLAG_HOST_TYPE_SVC_POP              : return("HOST_TYPE_SVC_POP");
  case FLAG_HOST_TYPE_SVC_IMAP             : return("HOST_TYPE_SVC_IMAP");
  case FLAG_HOST_TYPE_SVC_DIRECTORY        : return("HOST_TYPE_SVC_DIRECTORY");
  case FLAG_HOST_TYPE_SVC_FTP              : return("HOST_TYPE_SVC_FTP");
  case FLAG_HOST_TYPE_SVC_HTTP             : return("HOST_TYPE_SVC_HTTP");
  case FLAG_HOST_TYPE_SVC_WINS             : return("HOST_TYPE_SVC_WINS");
  case FLAG_HOST_TYPE_SVC_BRIDGE           : return("HOST_TYPE_SVC_BRIDGE");   
  case FLAG_HOST_TYPE_SVC_DHCP_CLIENT      : return("HOST_TYPE_SVC_DHCP_CLIENT");
  case FLAG_HOST_TYPE_SVC_DHCP_SERVER      : return("HOST_TYPE_SVC_DHCP_SERVER");
  case FLAG_HOST_TYPE_MASTER_BROWSER       : return("HOST_TYPE_MASTER_BROWSER");
  case FLAG_HOST_TYPE_MULTIHOMED           : return("HOST_TYPE_MULTIHOMED");
  case FLAG_HOST_TYPE_SVC_NTP_SERVER       : return("HOST_TYPE_SVC_NTP_SERVER");
  case FLAG_HOST_TYPE_MULTIVLANED          : return("HOST_TYPE_MULTIVLANED");
  case FLAG_HOST_TYPE_SVC_VOIP_CLIENT      : return("HOST_TYPE_SVC_VOIP_CLIENT");
  case FLAG_HOST_TYPE_SVC_VOIP_GATEWAY     : return("HOST_TYPE_SVC_VOIP_GATEWAY");
  case FLAG_HOST_WRONG_NETMASK             : return("HOST_WRONG_NETMASK");
  case FLAG_HOST_DUPLICATED_MAC            : return("HOST_DUPLICATED_MAC");
  default:
    snprintf(buf, sizeof(buf), "%d", eventValue);
    return(buf);
  }
}

/* ************************************************* */

void notifyEvent(EventType evt, HostTraffic *el, IPSession *session, int eventValue) {
  char *event = NULL, *info = "";
  FILE *fd;

  if((el == NULL)
     || (!(myGlobals.event_mask && evt)) 
     || (myGlobals.event_log == NULL)
     || (myGlobals.event_log[0] == '\0')
     )
    return;

  switch(evt) {
  case hostCreation:
    event = "Host created";
    break;
  case hostDeletion:
    event = "Host deleted";
    break;
  case sessionCreation:
    event = "IP session created";
    break;
  case sessionDeletion:
    event = "IP session deleted";
    break;
  case hostFlagged:
    event = "Host flagged";
    info = flag2string(eventValue);
    break;
  case hostUnflagged:
    event = "Host un-flagged";
    info = flag2string(eventValue);
    break;
  }

  if((fd = fopen(myGlobals.event_log, "a")) != NULL) {
    time_t theTime = time(NULL);
    struct tm t;
    char bufTime[LEN_TIMEFORMAT_BUFFER];
  
    memset(bufTime, 0, sizeof(bufTime));
    strftime(bufTime, sizeof(bufTime), 
	     CONST_LOCALE_TIMESPEC, localtime_r(&theTime, &t));

    fprintf(fd, "%s [event: %s][target: %s/%s/%s]\n",
	    bufTime, event,
	    el->ethAddressString,
	    el->hostNumIpAddress,
	    info);
    fclose(fd);
  } else
    traceEvent(CONST_TRACE_WARNING, "Unable to write into log event [%s]", 
	       myGlobals.event_log);
}

/* ************************************************* */

void init_events(void) {
  char buf[64], *key;

  key = EVENTS_MASK;
  if(fetchPrefsValue(key, buf, sizeof(buf)) != -1) {
    myGlobals.event_mask = atoi(buf);
  } else {
    myGlobals.event_mask = 0;
    storePrefsValue(key, "0");
  }

  key = EVENTS_LOG;
  if(fetchPrefsValue(key, buf, sizeof(buf)) != -1) {
    myGlobals.event_log = strdup(buf);
  } else {
    myGlobals.event_log = NULL;
    storePrefsValue(key, "");
  }

  traceEvent(CONST_TRACE_INFO, "Initialized events [mask: %d][path: %s]",
	     myGlobals.event_mask,  myGlobals.event_log ?  myGlobals.event_log : "<none>");
}
