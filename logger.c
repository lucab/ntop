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


#include "ntop.h"

static GDBM_FILE logDB;

/* *************************** */

void initLogger(void) {
  char tmpBuff[200];
  if(snprintf(tmpBuff, sizeof(tmpBuff), "%s/logger.db",dbPath) < 0) 
    traceEvent(TRACE_ERROR, "Buffer overflow!");
  logDB = gdbm_open (tmpBuff, 0, GDBM_NEWDB, 00664, NULL);
}

/* *************************** */

void termLogger(void) {
  if(logDB != NULL) {
#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "termLogger");
#endif 
    gdbm_close(logDB);
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif
    logDB = NULL;
  }
}

/* *************************** */
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
