/*
 *  Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
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


/* ****************************************** */

char* formatKBytes(float numKBytes, char *outStr, int outStrLen) {
  if(numKBytes < 0) return(""); /* It shouldn't happen */

  if(numKBytes < 1024) {
    if(snprintf(outStr, outStrLen, "%.1f%sKB", numKBytes, myGlobals.separator) < 0) 
     BufferTooShort();
  } else {
    float tmpKBytes = numKBytes/1024;

    if(tmpKBytes < 1024) {
      if(snprintf(outStr, outStrLen, "%.1f%sMB",  tmpKBytes, myGlobals.separator) < 0) 
	BufferTooShort();
    } else {
      float tmpGBytes = tmpKBytes/1024;

      if(tmpGBytes < 1024) {
	if(snprintf(outStr, outStrLen, "%.1f%sGB", tmpGBytes, myGlobals.separator)  < 0) 
	 BufferTooShort();
      } else {
	if(snprintf(outStr, outStrLen, "%.1f%sTB", ((float)(tmpGBytes)/1024), myGlobals.separator) < 0) 
	 BufferTooShort();
      }
    }
  }

  return(outStr);
}

/* ******************************* */

char* formatBytes(Counter numBytes, short encodeString, char* outStr, int outStrLen) {
  char* locSeparator;

  if(encodeString)
    locSeparator = myGlobals.separator;
  else
    locSeparator = " ";

  if(numBytes == 0) {
    return("0"); /* return("&nbsp;"); */
  } else if(numBytes < 1024) {
    if(snprintf(outStr, outStrLen, "%lu", (unsigned long)numBytes) < 0) 
     BufferTooShort();
  } else if (numBytes < 1048576) {
    if(snprintf(outStr, outStrLen, "%.1f%sKB",
		((float)(numBytes)/1024), locSeparator) < 0) 
     BufferTooShort();
  } else {
    float tmpMBytes = ((float)numBytes)/1048576;

    if(tmpMBytes < 1024) {
      if(snprintf(outStr, outStrLen, "%.1f%sMB",
	      tmpMBytes, locSeparator) < 0) 
	BufferTooShort();
    } else {
      tmpMBytes /= 1024;

      if(tmpMBytes < 1024) {
	if(snprintf(outStr, outStrLen, "%.1f%sGB", tmpMBytes, locSeparator) < 0) 
	 BufferTooShort();
      } else {
	if(snprintf(outStr, outStrLen, "%.1f%sTB",
		((float)(tmpMBytes)/1024), locSeparator) < 0)
	 BufferTooShort();
      }
    }
  }

  return(outStr);
}

/* ******************************* */

char* formatAdapterSpeed(Counter numBits, char* outStr, int outStrLen) {
  if(numBits == 0) {
    return("0"); /* return("&nbsp;"); */
  } else if(numBits < 1000) {
    if(snprintf(outStr, outStrLen, "%lu", (unsigned long)numBits) < 0) 
     BufferTooShort();
  } else if(numBits < 1000000) {
    if(snprintf(outStr, outStrLen, "%.1f Kb", (float)(numBits)/1000) < 0) 
     BufferTooShort();
  } else {
    float tmpMBytes = ((float)numBits)/1000000;

    if(tmpMBytes < 1000) {
      if(snprintf(outStr, outStrLen, "%.1f Mb", tmpMBytes) < 0) 
	BufferTooShort();
    } else {
      tmpMBytes /= 1000;

      if(tmpMBytes < 1000) {
	if(snprintf(outStr, outStrLen, "%.1f Gb", tmpMBytes) < 0) 
	 BufferTooShort();
      } else {
	if(snprintf(outStr, outStrLen, "%.1f Tb", ((float)(tmpMBytes)/1000)) < 0)
	 BufferTooShort();
      }
    }
  }

  return(outStr);
}

/* ******************************* */

char* formatSeconds(unsigned long sec, char* outStr, int outStrLen) {
  unsigned int hour=0, min=0, days=0;

  if(sec >= 3600) {
    hour = (sec / 3600);

    if(hour > 0) {
      if(hour >= 24) {
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
    if(snprintf(outStr, outStrLen, "%u day%s %u:%02u:%02lu", days, (days>1)?"s":"", hour, min, sec) < 0) 
     BufferTooShort();
  } else if(hour > 0) {
    if(snprintf(outStr, outStrLen, "%u:%02u:%02lu", hour, min, sec)  < 0) 
     BufferTooShort();
  } else if(min > 0) {
    if(snprintf(outStr, outStrLen, "%u:%02lu", min, sec) < 0) 
     BufferTooShort();
  } else {
    if(snprintf(outStr, outStrLen, "%lu sec", sec) < 0)
     BufferTooShort();
  }

  return(outStr);
}

/* ******************************* */

char* formatMicroSeconds(unsigned long microsec, 
			 char* outStr, int outStrLen) {
  float f = ((float)microsec)/1000;

  if(f < 1000) {
    if(snprintf(outStr, outStrLen, "%.1f ms", f) < 0) 
     BufferTooShort();
  } else {
    if(snprintf(outStr, outStrLen, "%.1f sec", (f/1000))  < 0) 
     BufferTooShort();
  } 
  return(outStr);
}

/* ******************************* */

char* formatThroughput(float numBytes /* <=== Bytes/second */, u_char htmlFormat,
		       char* outStr, int outStrLen) {
  float numBits;
  int divider = 1000;   /* As SNMP does instead of using 1024 ntop divides for 1000 */
  char *separator;

  if(htmlFormat)
    separator = myGlobals.separator;
  else
    separator = " ";
  
  if(numBytes < 0) numBytes = 0; /* Sanity check */
  numBits = numBytes*8;

  if (numBits < 100)
    numBits = 0; /* Avoid very small decimal values */
  
  if (numBits < divider) {
    if(snprintf(outStr, outStrLen, "%.1f%sbps", numBits, separator) < 0) 
     BufferTooShort();
  } else if (numBits < (divider*divider)) {
    if(snprintf(outStr, outStrLen, "%.1f%sKbps", ((float)(numBits)/divider), separator) < 0) 
     BufferTooShort();
  } else {
    if(snprintf(outStr, outStrLen, "%.1f%sMbps", ((float)(numBits)/1048576), separator) < 0) 
     BufferTooShort();
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "%.2f = %s", numBytes, outStr);
#endif

  return(outStr);
}

/* ******************************* */

char* formatLatency(struct timeval tv, u_short sessionState, char* outStr, int outStrLen) {  
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
    if(snprintf(outStr, outStrLen, "%.1f&nbsp;ms",
	    (float)(tv.tv_sec*1000+(float)tv.tv_usec/1000)) < 0)
      BufferTooShort();
    return(outStr);
  }
}

/* ******************************* */

char* formatTimeStamp(unsigned int ndays,
		      unsigned int nhours,
		      unsigned int nminutes, char* outStr, int outStrLen) {
  time_t theTime;

  /* printf("%u - %u - %u\n", ndays, nhours, nminutes); */

  if((ndays == 0)
     && (nhours == 0)
     && (nminutes == 0))
    return("now");
  else {
    theTime = myGlobals.actTime-(ndays*86400)-(nhours*3600)-(nminutes*60);
    strncpy(outStr, ctime(&theTime), outStrLen);
    outStr[outStrLen-1] = '\0'; /* Remove trailer '\n' */
    return(outStr);
  }
}

/* ************************ */

char* formatPkts(Counter pktNr, char* outStr, int outStrLen) {
  if(pktNr < 1000) {
    if(snprintf(outStr, outStrLen, "%lu", (unsigned long)pktNr) < 0) 
     BufferTooShort();
  } else if(pktNr < 1000000) {
    if(snprintf(outStr, outStrLen, "%lu,%03lu",
	    (unsigned long)(pktNr/1000),
	    ((unsigned long)pktNr)%1000) < 0) 
     BufferTooShort();
  } else if(pktNr < 1000000000) {
    unsigned long a, b, c;
    a = (unsigned long)(pktNr/1000000);
    b = (unsigned long)((pktNr-a*1000000)/1000);
    c = ((unsigned long)pktNr)%1000;
    if(snprintf(outStr, outStrLen, "%lu,%03lu,%03lu", a, b, c) < 0) 
     BufferTooShort();
  } else {
    unsigned long a, b, c, a1, a2;
    a = (unsigned long)(pktNr/1000000);
    a1 = (unsigned long)(a/1000); 
    a2 = a % 1000;
    b = (unsigned long)((pktNr-a*1000000)/1000);
    c = ((unsigned long)pktNr)%1000;
    if(snprintf(outStr, outStrLen, "%lu,%03lu,%03lu,%03lu", a1, a2, b, c) < 0) 
     BufferTooShort();
  }

  return(outStr);
}

/* ************************************ */

char* formatTime(time_t *theTime, char* outStr, int outStrLen) {
  struct tm *locTime;
  struct tm myLocTime;

  locTime = localtime_r(theTime, &myLocTime);
  strftime(outStr, outStrLen, CONST_LOCALE_TIMESPEC, locTime);

  return(outStr);
}

