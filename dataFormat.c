/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
 *
 *		 	    http://www.ntop.org/
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


char* formatKBytes(float numKBytes) {
  static char outStr[LEN_DATAFORMAT_BUFFER][32];
  static short bufIdx=0;

  if(numKBytes < 0) return(""); /* It shouldn't happen */

  bufIdx = (bufIdx+1)%LEN_DATAFORMAT_BUFFER;

  if(numKBytes < 1024) {
    if(snprintf(outStr[bufIdx], 32, "%.1f%sKB", numKBytes, myGlobals.separator) < 0) 
     BufferTooShort();
  } else {
    float tmpKBytes = numKBytes/1024;

    if(tmpKBytes < 1024) {
      if(snprintf(outStr[bufIdx], 32, "%.1f%sMB",  tmpKBytes, myGlobals.separator) < 0) 
	BufferTooShort();
    } else {
      float tmpGBytes = tmpKBytes/1024;

      if(tmpGBytes < 1024) {
	if(snprintf(outStr[bufIdx], 32, "%.1f%sGB", tmpGBytes, myGlobals.separator)  < 0) 
	 BufferTooShort();
      } else {
	if(snprintf(outStr[bufIdx], 32, "%.1f%sTB", ((float)(tmpGBytes)/1024), myGlobals.separator) < 0) 
	 BufferTooShort();
      }
    }
  }

  return(outStr[bufIdx]);
}

/* ******************************* */

char* formatBytes(Counter numBytes, short encodeString) {
  static char outStr[LEN_DATAFORMAT_BUFFER][32];
  static short bufIdx=0;
  char* locSeparator;

  if(encodeString)
    locSeparator = myGlobals.separator;
  else
    locSeparator = " ";

  bufIdx = (bufIdx+1)%LEN_DATAFORMAT_BUFFER;

  if(numBytes == 0) {
    return("0"); /* return("&nbsp;"); */
  } else if(numBytes < 1024) {
    if(snprintf(outStr[bufIdx], 32, "%lu", (unsigned long)numBytes) < 0) 
     BufferTooShort();
  } else if (numBytes < 1048576) {
    if(snprintf(outStr[bufIdx], 32, "%.1f%sKB",
		((float)(numBytes)/1024), locSeparator) < 0) 
     BufferTooShort();
  } else {
    float tmpMBytes = ((float)numBytes)/1048576;

    if(tmpMBytes < 1024) {
      if(snprintf(outStr[bufIdx], 32, "%.1f%sMB",
	      tmpMBytes, locSeparator) < 0) 
	BufferTooShort();
    } else {
      tmpMBytes /= 1024;

      if(tmpMBytes < 1024) {
	if(snprintf(outStr[bufIdx], 32, "%.1f%sGB", tmpMBytes, locSeparator) < 0) 
	 BufferTooShort();
      } else {
	if(snprintf(outStr[bufIdx], 32, "%.1f%sTB",
		((float)(tmpMBytes)/1024), locSeparator) < 0)
	 BufferTooShort();
      }
    }
  }

  return(outStr[bufIdx]);
}

/* ******************************* */

char* formatAdapterSpeed(Counter numBits) {
  static char outStr[LEN_DATAFORMAT_BUFFER][32];
  static short bufIdx=0;

  bufIdx = (bufIdx+1)%LEN_DATAFORMAT_BUFFER;

  if(numBits == 0) {
    return("0"); /* return("&nbsp;"); */
  } else if(numBits < 1000) {
    if(snprintf(outStr[bufIdx], 32, "%lu", (unsigned long)numBits) < 0) 
     BufferTooShort();
  } else if(numBits < 1000000) {
    if(snprintf(outStr[bufIdx], 32, "%.1f Kb", (float)(numBits)/1000) < 0) 
     BufferTooShort();
  } else {
    float tmpMBytes = ((float)numBits)/1000000;

    if(tmpMBytes < 1000) {
      if(snprintf(outStr[bufIdx], 32, "%.1f Mb", tmpMBytes) < 0) 
	BufferTooShort();
    } else {
      tmpMBytes /= 1000;

      if(tmpMBytes < 1000) {
	if(snprintf(outStr[bufIdx], 32, "%.1f Gb", tmpMBytes) < 0) 
	 BufferTooShort();
      } else {
	if(snprintf(outStr[bufIdx], 32, "%.1f Tb", ((float)(tmpMBytes)/1000)) < 0)
	 BufferTooShort();
      }
    }
  }

  return(outStr[bufIdx]);
}

/* ******************************* */

char* formatSeconds(unsigned long sec) {
  static char outStr[5][32];
  static short bufIdx=0;
  unsigned int hour=0, min=0, days=0;

  bufIdx = (bufIdx+1)%5;

  if(sec >= 3600) {
    hour = (sec / 3600);

    if(hour > 0) {
      if(hour > 24) {
	days = (hour / 24);
	hour = hour % 24;
	sec -= days*86400;
      }
      sec -= hour*3600;
    } else
      hour = 0;
  }

  min = (sec / 60);
  if(min > 0) sec -= min*60;

  if(days > 0) {
    if(snprintf(outStr[bufIdx], 32, "%u day(s) %u:%02u:%02lu", days, hour, min, sec) < 0) 
     BufferTooShort();
  } else if(hour > 0) {
    if(snprintf(outStr[bufIdx], 32, "%u:%02u:%02lu", hour, min, sec)  < 0) 
     BufferTooShort();
  } else if(min > 0) {
    if(snprintf(outStr[bufIdx], 32, "%u:%02lu", min, sec) < 0) 
     BufferTooShort();
  } else {
    if(snprintf(outStr[bufIdx], 32, "%lu sec", sec) < 0)
     BufferTooShort();
  }

  return(outStr[bufIdx]);
}

/* ******************************* */

char* formatMicroSeconds(unsigned long microsec) {
  static char outStr[5][32];
  static short bufIdx=0;
  float f = ((float)microsec)/1000;

  bufIdx = (bufIdx+1)%5;

  if(f < 1000) {
    if(snprintf(outStr[bufIdx], 32, "%.1f ms", f) < 0) 
     BufferTooShort();
  } else {
    if(snprintf(outStr[bufIdx], 32, "%.1f sec", (f/1000))  < 0) 
     BufferTooShort();
  } 
  return(outStr[bufIdx]);
}

/* ******************************* */

char* formatThroughput(float numBytes /* <=== Bytes/second */) {
  static char outStr[5][32];
  static short bufIdx=0;
  float numBits;
  static int divider = 1000;   /* As SNMP does instead of using 1024
				  ntop divides for 1000 */
  bufIdx = (bufIdx+1)%5;

  if(numBytes < 0) numBytes = 0; /* Sanity check */
  numBits = numBytes*8;

  if (numBits < 100)
    numBits = 0; /* Avoid very small decimal values */
  
  if (numBits < divider) {
    if(snprintf(outStr[bufIdx], 32, "%.1f%sbps", numBits, myGlobals.separator) < 0) 
     BufferTooShort();
  } else if (numBits < (divider*divider)) {
    if(snprintf(outStr[bufIdx], 32, "%.1f%sKbps", ((float)(numBits)/divider), myGlobals.separator) < 0) 
     BufferTooShort();
  } else {
    if(snprintf(outStr[bufIdx], 32, "%.1f%sMbps", ((float)(numBits)/1048576), myGlobals.separator) < 0) 
     BufferTooShort();
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "%.2f = %s\n", numBytes, outStr[bufIdx]);
#endif

  return(outStr[bufIdx]);
}

/* ******************************* */

char* formatLatency(struct timeval tv, u_short sessionState) {
  
  if(((tv.tv_sec == 0) && (tv.tv_usec == 0)) 
     || (sessionState < FLAG_STATE_ACTIVE) 
     /* Patch courtesy of  
	Andreas Pfaller <apfaller@yahoo.com.au>
     */) {
    /* 
       Latency not computed (the session was initiated
       before ntop started 
    */
    return("&nbsp;");
  } else {
    static char latBuf[32];
    
    snprintf(latBuf, sizeof(latBuf), "%.1f&nbsp;ms",
	    (float)(tv.tv_sec*1000+(float)tv.tv_usec/1000));
    return(latBuf);
  }
}

/* ******************************* */

char* formatTimeStamp(unsigned int ndays,
		      unsigned int nhours,
		      unsigned int nminutes) {
  time_t theTime;

  /* printf("%u - %u - %u\n", ndays, nhours, nminutes); */

  if((ndays == 0)
     && (nhours == 0)
     && (nminutes == 0))
    return("now");
  else {
    static char timeBuffer[LEN_TIME_STAMP_BUFFER][32];
    static short bufIdx=0;

    bufIdx = (bufIdx+1)%LEN_TIME_STAMP_BUFFER;
    theTime = myGlobals.actTime-(ndays*86500)-(nhours*3600)-(nminutes*60);
    strncpy(timeBuffer[bufIdx], ctime(&theTime), 32);
    timeBuffer[bufIdx][strlen(timeBuffer[bufIdx])-1] = '\0'; /* Remove trailer '\n' */
    return(timeBuffer[bufIdx]);
  }
}

/* ************************ */

char* formatPkts(Counter pktNr) {
  static short bufIdx=0;
  static char staticBuffer[8][32];

  bufIdx = (bufIdx+1)%8;

  if(pktNr < 1000) {
    if(snprintf(staticBuffer[bufIdx], 32, "%lu", (unsigned long)pktNr) < 0) 
     BufferTooShort();
  } else if(pktNr < 1000000) {
    if(snprintf(staticBuffer[bufIdx], 32, "%lu,%03lu",
	    (unsigned long)(pktNr/1000),
	    ((unsigned long)pktNr)%1000) < 0) 
     BufferTooShort();
  } else if(pktNr < 1000000000) {
    unsigned long a, b, c;
    a = (unsigned long)(pktNr/1000000);
    b = (unsigned long)((pktNr-a*1000000)/1000);
    c = ((unsigned long)pktNr)%1000;
    if(snprintf(staticBuffer[bufIdx], 32, "%lu,%03lu,%03lu", a, b, c) < 0) 
     BufferTooShort();
  } else {
    unsigned long a, b, c, a1, a2;
    a = (unsigned long)(pktNr/1000000);
    a1 = (unsigned long)(pktNr/1000); 
    a2 = a % 1000;
    b = (unsigned long)((pktNr-a*1000000)/1000);
    c = ((unsigned long)pktNr)%1000;
    if(snprintf(staticBuffer[bufIdx], 32, "%lu,%03lu,%03lu,%03lu", a1, a2, b, c) < 0) 
     BufferTooShort();
  }

  return(staticBuffer[bufIdx]);
}
