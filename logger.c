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


#include "ntop.h"

#ifdef HAVE_GDBM_H
static GDBM_FILE logDB;
#endif

/* *************************** */

void initLogger(void) {
#ifdef HAVE_GDBM_H
  char tmpBuff[200];
  if(snprintf(tmpBuff, sizeof(tmpBuff), "%s/logger.db",dbPath) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  logDB = gdbm_open (tmpBuff, 0, GDBM_NEWDB, 00664, NULL);
#endif
}

/* *************************** */

void termLogger(void) {
#ifdef HAVE_GDBM_H
  if(logDB != NULL) {
    gdbm_close(logDB);
    logDB = NULL;
  }
#endif
}

/* *************************** */
#ifdef HAVE_GDBM_H
void logMessage(char* message, u_short severity) {
  LogMessage msg;
  int len;
  datum key_data, data_data;
  char tmpStr[16];

  if((message == NULL) || (logDB == NULL))
    return;

  memset(&msg, 0, sizeof(LogMessage));
  msg.severity = severity;
  len = strlen(message);

  if(len > MESSAGE_MAX_LEN) len = MESSAGE_MAX_LEN;
  strncpy(msg.message, message, len);
  msg.message[len]= '\0';

  if(snprintf(tmpStr, sizeof(tmpStr), "%lu", time(NULL)) < 0)
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  key_data.dptr = tmpStr; key_data.dsize = strlen(key_data.dptr)+1;
  data_data.dptr = (char*)&msg; data_data.dsize = sizeof(LogMessage)+1;
  
#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "logMessage");
#endif 
  gdbm_store(logDB, key_data, data_data, GDBM_REPLACE);	
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 
}
#else
void logMessage(char* message, u_short severity) {
  traceEvent(TRACE_INFO,"%s [severity %d]\n", message, severity);
}
#endif

/* ************************ */

void LogStatsToFile(void) {
  if((logd != NULL) && (ipProtoStats != NULL)) {
    char tmpStr[255];
    int i;
    TrafficCounter tc;

    strncpy(tmpStr, ctime(&actTime), sizeof(tmpStr));
    tmpStr[strlen(tmpStr)-1] = '\0'; /* remove final \n */

    fprintf(logd, "\"%s\" %lu %lu %lu "
	    "%lu %lu %lu "
	    "%.1f",
	    tmpStr,
	    (unsigned long)(device[actualDeviceId].ethernetPkts
			    -device[actualDeviceId].lastethernetPkts),
	    (unsigned long)(device[actualDeviceId].broadcastPkts
			    -device[actualDeviceId].lastBroadcastPkts),
	    (unsigned long)(device[actualDeviceId].multicastPkts
			    -device[actualDeviceId].lastMulticastPkts),
	    (unsigned long)(device[actualDeviceId].ethernetBytes
			    -device[actualDeviceId].lastEthernetBytes),
	    (unsigned long)(device[actualDeviceId].ipBytes
			    -device[actualDeviceId].lastIpBytes),
	    (unsigned long)(device[actualDeviceId].ethernetBytes
			    -device[actualDeviceId].ipBytes
			    -device[actualDeviceId].lastNonIpBytes),
	    device[actualDeviceId].peakThroughput);
    fflush(logd); /* Courtesy of Robert Greimel <greimel@beluga.phys.uvic.ca> */
    device[actualDeviceId].lastethernetPkts = device[actualDeviceId].ethernetPkts;
    device[actualDeviceId].lastBroadcastPkts = device[actualDeviceId].broadcastPkts;
    device[actualDeviceId].lastMulticastPkts = device[actualDeviceId].multicastPkts;
    device[actualDeviceId].lastEthernetBytes = device[actualDeviceId].ethernetBytes;
    device[actualDeviceId].lastIpBytes = device[actualDeviceId].ipBytes;
    device[actualDeviceId].lastNonIpBytes = device[actualDeviceId].ethernetBytes
      -device[actualDeviceId].ipBytes;
    
    tc = device[actualDeviceId].tcpGlobalTrafficStats.local-
      device[actualDeviceId].tcpGlobalTrafficStats.lastLocal;
    tc += device[actualDeviceId].tcpGlobalTrafficStats.local2remote-
      device[actualDeviceId].tcpGlobalTrafficStats.lastLocal2remote;
    tc += device[actualDeviceId].tcpGlobalTrafficStats.remote-
      device[actualDeviceId].tcpGlobalTrafficStats.lastRemote;
    tc += device[actualDeviceId].tcpGlobalTrafficStats.remote2local-
      device[actualDeviceId].tcpGlobalTrafficStats.lastRemote2local;
    fprintf(logd, " %lu", (unsigned long)tc);

    tc = device[actualDeviceId].udpGlobalTrafficStats.local-
      device[actualDeviceId].udpGlobalTrafficStats.lastLocal;
    tc += device[actualDeviceId].udpGlobalTrafficStats.local2remote-
      device[actualDeviceId].udpGlobalTrafficStats.lastLocal2remote;
    tc += device[actualDeviceId].udpGlobalTrafficStats.remote-
      device[actualDeviceId].udpGlobalTrafficStats.lastRemote;
    tc += device[actualDeviceId].udpGlobalTrafficStats.remote2local-
      device[actualDeviceId].udpGlobalTrafficStats.lastRemote2local;
    fprintf(logd, " %lu", (unsigned long)tc);

    tc = device[actualDeviceId].icmpGlobalTrafficStats.local-
      device[actualDeviceId].icmpGlobalTrafficStats.lastLocal;
    tc += device[actualDeviceId].icmpGlobalTrafficStats.local2remote-
      device[actualDeviceId].icmpGlobalTrafficStats.lastLocal2remote;
    tc += device[actualDeviceId].icmpGlobalTrafficStats.remote-
      device[actualDeviceId].icmpGlobalTrafficStats.lastRemote;
    tc += device[actualDeviceId].icmpGlobalTrafficStats.remote2local-
      device[actualDeviceId].icmpGlobalTrafficStats.lastRemote2local;
    fprintf(logd, " %lu", (unsigned long)tc);

    /* Courtesy of Andrew Milne <admilne@hotmail.com> */
    device[actualDeviceId].tcpGlobalTrafficStats.lastLocal2remote = 
      device[actualDeviceId].tcpGlobalTrafficStats.local2remote;
    device[actualDeviceId].tcpGlobalTrafficStats.lastRemote= 
      device[actualDeviceId].tcpGlobalTrafficStats.remote;
    device[actualDeviceId]. tcpGlobalTrafficStats.lastRemote2local = 
      device[actualDeviceId].tcpGlobalTrafficStats.remote2local;
    device[actualDeviceId].udpGlobalTrafficStats.lastLocal = 
      device[actualDeviceId].udpGlobalTrafficStats.local;
    device[actualDeviceId].udpGlobalTrafficStats.lastLocal2remote = 
      device[actualDeviceId].udpGlobalTrafficStats.local2remote;
    device[actualDeviceId].udpGlobalTrafficStats.lastRemote = 
      device[actualDeviceId].udpGlobalTrafficStats.remote;
    device[actualDeviceId].udpGlobalTrafficStats.lastRemote2local = 
      device[actualDeviceId].udpGlobalTrafficStats.remote2local;
    device[actualDeviceId].icmpGlobalTrafficStats.lastLocal = 
      device[actualDeviceId].icmpGlobalTrafficStats.local;
    device[actualDeviceId].icmpGlobalTrafficStats.lastLocal2remote = 
      device[actualDeviceId].icmpGlobalTrafficStats.local2remote;
    device[actualDeviceId].icmpGlobalTrafficStats.lastRemote = 
      device[actualDeviceId].icmpGlobalTrafficStats.remote;
    device[actualDeviceId].icmpGlobalTrafficStats.lastRemote2local = 
      device[actualDeviceId].icmpGlobalTrafficStats.remote2local;

    for(i=0; i<numIpProtosToMonitor; i++) {
      TrafficCounter tc;

      tc = ipProtoStats[i].local-ipProtoStats[i].lastLocal;
      tc += ipProtoStats[i].local2remote-ipProtoStats[i].lastLocal2remote;
      tc += ipProtoStats[i].remote-ipProtoStats[i].lastRemote;
      tc += ipProtoStats[i].remote2local-ipProtoStats[i].lastRemote2local;

      fprintf(logd, " %lu", (unsigned long)tc);

      ipProtoStats[i].lastLocal        = ipProtoStats[i].local;
      ipProtoStats[i].lastLocal2remote = ipProtoStats[i].local2remote;
      ipProtoStats[i].lastRemote       = ipProtoStats[i].remote;
      ipProtoStats[i].lastRemote2local = ipProtoStats[i].remote2local;
    }

    fprintf(logd, "\n");
  }
}

/* **************************************** */

#ifdef MULTITHREADED
void* logFileLoop(void* notUsed _UNUSED_) {
  for(;;) {
    sleep(logTimeout);
    actTime = time(NULL);

    /* Don't purge hosts if the traffic is high */
    if(packetQueueLen < (PACKET_QUEUE_LENGTH/3)) {
      accessMutex(&hostsHashMutex, "logFileLoop");
      /* printf("Called LogStatsToFile()"); */
      LogStatsToFile();
      releaseMutex(&hostsHashMutex);
    }
  }
}

#endif

