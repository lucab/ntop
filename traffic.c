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

#define getSerial(a) myGlobals.device[deviceToUpdate].hash_hostTraffic[a]->hostSerial

/* ******************************* */

static void updateThptStats(int deviceToUpdate,
			    u_int topSentIdx, u_int secondSentIdx,  u_int thirdSentIdx,
			    u_int topHourSentIdx, u_int secondHourSentIdx,
			    u_int thirdHourSentIdx,
			    u_int topRcvdIdx, u_int secondRcvdIdx, u_int thirdRcvdIdx,
			    u_int topHourRcvdIdx, u_int secondHourRcvdIdx,
			    u_int thirdHourRcvdIdx) {
  int i;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "updateThptStats(%d, %d, %d, %d, %d, %d)\n",
	 topSentIdx, secondSentIdx, thirdSentIdx,
	 topHourSentIdx, secondHourSentIdx,
	 thirdHourSentIdx);
#endif

  /* We never check enough... */
  if(topSentIdx == NO_PEER) 
    return;

  if(topRcvdIdx == NO_PEER) 
    return;

  if(secondSentIdx == NO_PEER) 
    secondSentIdx = 0;

  if(thirdSentIdx == NO_PEER)
    thirdSentIdx = 0;

  if(secondRcvdIdx == NO_PEER)
    secondRcvdIdx = 0;

  if(thirdRcvdIdx == NO_PEER)
    thirdRcvdIdx = 0;

  for(i=58; i>=0; i--)
    memcpy(&myGlobals.device[deviceToUpdate].last60MinutesThpt[i+1],
	   &myGlobals.device[deviceToUpdate].last60MinutesThpt[i], sizeof(ThptEntry));

  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].trafficValue = myGlobals.device[deviceToUpdate].lastMinThpt;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "LastMinThpt: %s", formatThroughput(myGlobals.device[deviceToUpdate].lastMinThpt));
#endif

  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].topHostSentSerial = getSerial(topSentIdx),
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].topSentTraffic = 
    myGlobals.device[deviceToUpdate].hash_hostTraffic[topSentIdx]->actualSentThpt;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].secondHostSentSerial = getSerial(secondSentIdx),
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].secondSentTraffic = 
    myGlobals.device[deviceToUpdate].hash_hostTraffic[secondSentIdx]->actualSentThpt;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].thirdHostSentSerial = getSerial(thirdSentIdx),
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].thirdSentTraffic = 
    myGlobals.device[deviceToUpdate].hash_hostTraffic[thirdSentIdx]->actualSentThpt;

  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].topHostRcvdSerial = getSerial(topRcvdIdx),
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].topRcvdTraffic = 
    myGlobals.device[deviceToUpdate].hash_hostTraffic[topRcvdIdx]->actualRcvdThpt;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].secondHostRcvdSerial = getSerial(secondRcvdIdx),
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].secondRcvdTraffic = 
    myGlobals.device[deviceToUpdate].hash_hostTraffic[secondRcvdIdx]->actualRcvdThpt;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].thirdHostRcvdSerial = getSerial(thirdRcvdIdx),
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].thirdRcvdTraffic = 
    myGlobals.device[deviceToUpdate].hash_hostTraffic[thirdRcvdIdx]->actualRcvdThpt;

  myGlobals.device[deviceToUpdate].last60MinutesThptIdx = (myGlobals.device[deviceToUpdate].last60MinutesThptIdx+1) % 60;

  if(topHourSentIdx != NO_PEER) { 
    /* It wrapped -> 1 hour is over */
    float average=0;
    int i;

    if(topHourSentIdx == NO_PEER) return;
    if(topHourRcvdIdx == NO_PEER) return;
    if(secondHourSentIdx == NO_PEER) secondHourSentIdx = 0;
    if(thirdHourSentIdx == NO_PEER)  thirdHourSentIdx = 0;
    if(secondHourRcvdIdx == NO_PEER) secondHourRcvdIdx = 0;
    if(thirdHourRcvdIdx == NO_PEER)  thirdHourRcvdIdx = 0;

    for(i=0; i<60; i++) {
      average += myGlobals.device[deviceToUpdate].last60MinutesThpt[i].trafficValue;
    }

    average /= 60;

    for(i=22; i>=0; i--)
      memcpy(&myGlobals.device[deviceToUpdate].last24HoursThpt[i+1], 
	     &myGlobals.device[deviceToUpdate].last24HoursThpt[i], sizeof(ThptEntry));

    myGlobals.device[deviceToUpdate].last24HoursThpt[0].trafficValue = average;

    myGlobals.device[deviceToUpdate].last24HoursThpt[0].topHostSentSerial = getSerial(topHourSentIdx),
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].topSentTraffic = 
      myGlobals.device[deviceToUpdate].hash_hostTraffic[topHourSentIdx]->lastHourSentThpt;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].secondHostSentSerial = getSerial(secondHourSentIdx),
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].secondSentTraffic = 
      myGlobals.device[deviceToUpdate].hash_hostTraffic[secondHourSentIdx]->lastHourSentThpt;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].thirdHostSentSerial = getSerial(thirdHourSentIdx),
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].thirdSentTraffic = 
      myGlobals.device[deviceToUpdate].hash_hostTraffic[thirdHourSentIdx]->lastHourSentThpt;

    myGlobals.device[deviceToUpdate].last24HoursThpt[0].topHostRcvdSerial = getSerial(topHourRcvdIdx),
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].topRcvdTraffic = 
      myGlobals.device[deviceToUpdate].hash_hostTraffic[topHourRcvdIdx]->lastHourRcvdThpt;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].secondHostRcvdSerial = getSerial(secondHourRcvdIdx),
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].secondRcvdTraffic = 
      myGlobals.device[deviceToUpdate].hash_hostTraffic[secondHourRcvdIdx]->lastHourRcvdThpt;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].thirdHostRcvdSerial = getSerial(thirdHourRcvdIdx),
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].thirdRcvdTraffic = 
      myGlobals.device[deviceToUpdate].hash_hostTraffic[thirdHourRcvdIdx]->lastHourRcvdThpt;

    myGlobals.device[deviceToUpdate].last24HoursThptIdx = 
      (myGlobals.device[deviceToUpdate].last24HoursThptIdx + 1) % 24;

    if(myGlobals.device[deviceToUpdate].last24HoursThptIdx == 0) {
      average=0;

      for(i=0; i<24; i++) {
	average += myGlobals.device[deviceToUpdate].last24HoursThpt[i].trafficValue;
      }

      average /= 24;

      for(i=28; i>=0; i--) {
	myGlobals.device[deviceToUpdate].last30daysThpt[i+1] = 
	  myGlobals.device[deviceToUpdate].last30daysThpt[i];
      }

      myGlobals.device[deviceToUpdate].last30daysThpt[0] = average;
      myGlobals.device[deviceToUpdate].last30daysThptIdx = 
	(myGlobals.device[deviceToUpdate].last30daysThptIdx + 1) % 30;
    }
  }

  myGlobals.device[deviceToUpdate].numThptSamples++;
  
#ifdef DEBUG
  traceEvent(TRACE_INFO, "updateThptStats() completed.\n");
#endif
}

/* ******************************* */

void updateDeviceThpt(int deviceToUpdate) {
  time_t timeDiff, timeMinDiff, timeHourDiff=0, totalTime;
  u_int idx;
  HostTraffic *el;

  timeDiff = myGlobals.actTime-myGlobals.device[deviceToUpdate].lastThptUpdate;

  if(timeDiff > 10 /* secs */) {
    u_int topSentIdx=NO_PEER, secondSentIdx=NO_PEER, thirdSentIdx=NO_PEER;
    u_int topHourSentIdx=NO_PEER, secondHourSentIdx=NO_PEER, thirdHourSentIdx=NO_PEER;
    u_int topRcvdIdx=NO_PEER, secondRcvdIdx=NO_PEER, thirdRcvdIdx=NO_PEER;
    u_int topHourRcvdIdx=NO_PEER, secondHourRcvdIdx=NO_PEER, thirdHourRcvdIdx=NO_PEER;
    short updateMinThpt, updateHourThpt;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "updateDeviceStats() called.");
#endif
    
    totalTime = myGlobals.actTime-myGlobals.initialSniffTime;

    updateHourThpt = 0;
    updateMinThpt = 0;

    if((timeMinDiff = myGlobals.actTime-myGlobals.
	device[deviceToUpdate].lastMinThptUpdate) >= 60 /* 1 minute */) {
      updateMinThpt = 1;
      myGlobals.device[deviceToUpdate].lastMinThptUpdate = myGlobals.actTime;
      if((timeHourDiff = myGlobals.actTime-myGlobals.
	  device[deviceToUpdate].lastHourThptUpdate) >= 60*60 /* 1 hour */) {
	updateHourThpt = 1;
	myGlobals.device[deviceToUpdate].lastHourThptUpdate = myGlobals.actTime;
      }
    }

    for(idx=1; idx<myGlobals.device[deviceToUpdate].actualHashSize; idx++) {
      if(((el = myGlobals.device[deviceToUpdate].hash_hostTraffic[idx]) != NULL) 
	 && (el->numUses > 0)) {
	if(broadcastHost(el))
	  continue;

	el->actualRcvdThpt       = (float)(el->bytesRcvd-el->lastBytesRcvd)/timeDiff;
	if(el->peakRcvdThpt      < el->actualRcvdThpt) el->peakRcvdThpt = el->actualRcvdThpt;
	el->actualSentThpt       = (float)(el->bytesSent-el->lastBytesSent)/timeDiff;
	if(el->peakSentThpt      < el->actualSentThpt) el->peakSentThpt = el->actualSentThpt;
	el->lastBytesSent        = el->bytesSent;
	el->lastBytesRcvd        = el->bytesRcvd;

	/* ******************************** */

	el->actualRcvdPktThpt    = (float)(el->pktRcvd-el->lastPktRcvd)/timeDiff;
	if(el->peakRcvdPktThpt   < el->actualRcvdPktThpt) el->peakRcvdPktThpt = el->actualRcvdPktThpt;
	el->actualSentPktThpt    = (float)(el->pktSent-el->lastPktSent)/timeDiff;
	if(el->peakSentPktThpt   < el->actualSentPktThpt) el->peakSentPktThpt = el->actualSentPktThpt;
	el->lastPktSent          = el->pktSent;
	el->lastPktRcvd          = el->pktRcvd;

	/* ******************************** */

	if(updateMinThpt) {
	  el->averageRcvdThpt    = ((float)el->bytesRcvd)/totalTime;
	  el->averageSentThpt    = ((float)el->bytesSent)/totalTime;
	  el->averageRcvdPktThpt = ((float)el->pktRcvd)/totalTime;
	  el->averageSentPktThpt = ((float)el->pktSent)/totalTime;

	  if((topSentIdx == NO_PEER) 
	     || (myGlobals.device[deviceToUpdate].hash_hostTraffic[topSentIdx] == NULL)) {
	    if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx))
	      topSentIdx = idx;
	  } else {
	    if(el->actualSentThpt > myGlobals.device[deviceToUpdate].
	       hash_hostTraffic[topSentIdx]->actualSentThpt) {
	      if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx)) {
	      secondSentIdx = topSentIdx;
	      topSentIdx = idx;
	      }
	    } else {
	      if((secondSentIdx == NO_PEER)
		 || (myGlobals.device[deviceToUpdate].hash_hostTraffic[secondSentIdx] == NULL)) {
		if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx))
		  secondSentIdx = idx;
	      } else {
		if(el->actualSentThpt > myGlobals.device[deviceToUpdate].
		   hash_hostTraffic[secondSentIdx]->actualSentThpt) {
		  if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx)) {
		  thirdSentIdx = secondSentIdx;
		  secondSentIdx = idx;
		  }
		} else {
		  if((thirdSentIdx == NO_PEER)
		     || (myGlobals.device[deviceToUpdate].hash_hostTraffic[thirdSentIdx] == NULL)) {
		    if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx)) {
		    thirdSentIdx = idx;
		    }
		  } else {
		    if(el->actualSentThpt > myGlobals.device[deviceToUpdate].
		       hash_hostTraffic[thirdSentIdx]->actualSentThpt) {
		      if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx)) {
		      thirdSentIdx = idx;
		      }
		    }
		  }
		}
	      }
	    }
	  }

	  if((topRcvdIdx == NO_PEER) 
	     || (myGlobals.device[deviceToUpdate].hash_hostTraffic[topRcvdIdx] == NULL)) {
	    if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx)) 
	    topRcvdIdx = idx;
	  } else {
	    if(el->actualRcvdThpt > myGlobals.device[deviceToUpdate].
	       hash_hostTraffic[topRcvdIdx]->actualRcvdThpt) {
	      if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx)) {
		secondRcvdIdx = topRcvdIdx;
		topRcvdIdx = idx;
	      }
	    } else {
	      if((secondRcvdIdx == NO_PEER)
		 || (myGlobals.device[deviceToUpdate].hash_hostTraffic[secondRcvdIdx] == NULL)) {
		if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx))
		  secondRcvdIdx = idx;
	      } else {
		if(el->actualRcvdThpt > myGlobals.device[deviceToUpdate].
		   hash_hostTraffic[secondRcvdIdx]->actualRcvdThpt) {
		  if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx)) {
		    thirdRcvdIdx = secondRcvdIdx;
		    secondRcvdIdx = idx;
		  }
		} else {
		  if((thirdRcvdIdx == NO_PEER)
		     || (myGlobals.device[deviceToUpdate].hash_hostTraffic[thirdRcvdIdx] == NULL)) {
		    if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx))
		      thirdRcvdIdx = idx;
		  } else {
		    if(el->actualRcvdThpt > myGlobals.device[deviceToUpdate].
		       hash_hostTraffic[thirdRcvdIdx]->actualRcvdThpt) {
		      if((idx != myGlobals.broadcastEntryIdx) && (idx != myGlobals.otherHostEntryIdx))
			thirdRcvdIdx = idx;
		    }
		  }
		}
	      }
	    }
	  }

	  if(updateHourThpt) {
	    el->lastHourRcvdThpt = (float)(el->bytesRcvd-el->lastHourBytesRcvd)/timeHourDiff;
	    el->lastHourSentThpt = (float)(el->bytesSent-el->lastHourBytesSent)/timeHourDiff;
	    el->lastHourBytesRcvd = el->bytesRcvd;
	    el->lastHourBytesSent = el->bytesSent;

	    if((topHourSentIdx == NO_PEER) 
	       || (myGlobals.device[deviceToUpdate].hash_hostTraffic[topHourSentIdx] == NULL)) {
	      topHourSentIdx = idx;
	    } else {
	      if(el->lastHourSentThpt > myGlobals.device[deviceToUpdate].
		 hash_hostTraffic[topHourSentIdx]->lastHourSentThpt) {
		secondHourSentIdx = topHourSentIdx;
		topHourSentIdx = idx;
	      } else {
		if((secondHourSentIdx == NO_PEER)
		   || (myGlobals.device[deviceToUpdate].hash_hostTraffic[secondHourSentIdx] == NULL)) {
		  secondHourSentIdx = idx;
		} else {
		  if(el->lastHourSentThpt > myGlobals.device[deviceToUpdate].
		     hash_hostTraffic[secondHourSentIdx]->lastHourSentThpt) {
		    thirdHourSentIdx = secondHourSentIdx;
		    secondHourSentIdx = idx;
		  } else {
		    if((thirdHourSentIdx == NO_PEER)
		       || (myGlobals.device[deviceToUpdate].hash_hostTraffic[thirdHourSentIdx] == NULL)) {
		      thirdHourSentIdx = idx;
		    } else {
		      if(el->lastHourSentThpt > myGlobals.device[deviceToUpdate].
			 hash_hostTraffic[thirdHourSentIdx]->lastHourSentThpt) {
			thirdHourSentIdx = idx;
		      }
		    }
		  }
		}
	      }
	    }

	    if((topHourRcvdIdx == NO_PEER) 
	       || (myGlobals.device[deviceToUpdate].hash_hostTraffic[topHourRcvdIdx] == NULL)) {
	      topHourRcvdIdx = idx;
	    } else {
	      if(el->lastHourRcvdThpt > myGlobals.device[deviceToUpdate].
		 hash_hostTraffic[topHourRcvdIdx]->lastHourRcvdThpt) {
		secondHourRcvdIdx = topHourRcvdIdx;
		topHourRcvdIdx = idx;
	      } else {
		if((secondHourRcvdIdx == NO_PEER)
		   || (myGlobals.device[deviceToUpdate].hash_hostTraffic[secondHourRcvdIdx] == NULL)) {
		  secondHourRcvdIdx = idx;
		} else {
		  if(el->lastHourRcvdThpt > myGlobals.device[deviceToUpdate].
		     hash_hostTraffic[secondHourRcvdIdx]->lastHourRcvdThpt) {
		    thirdHourRcvdIdx = secondHourRcvdIdx;
		    secondHourRcvdIdx = idx;
		  } else {
		    if((thirdHourRcvdIdx == NO_PEER)
		       || (myGlobals.device[deviceToUpdate].hash_hostTraffic[thirdHourRcvdIdx] == NULL)) {
		      thirdHourRcvdIdx = idx;
		    } else {
		      if(el->lastHourRcvdThpt > myGlobals.device[deviceToUpdate].
			 hash_hostTraffic[thirdHourRcvdIdx]->lastHourRcvdThpt) {
			thirdHourRcvdIdx = idx;
		      }
		    }
		  }
		}
	      }
	    }
	  }
	}
      }
    }

    /* ******************************** */

    myGlobals.device[deviceToUpdate].throughput =
      myGlobals.device[deviceToUpdate].ethernetBytes-myGlobals.device[deviceToUpdate].throughput;
    myGlobals.device[deviceToUpdate].packetThroughput = myGlobals.device[deviceToUpdate].ethernetPkts-
      myGlobals.device[deviceToUpdate].lastNumEthernetPkts;
    myGlobals.device[deviceToUpdate].lastNumEthernetPkts = myGlobals.device[deviceToUpdate].ethernetPkts;

    /* timeDiff++; */
    myGlobals.device[deviceToUpdate].actualThpt = (float)myGlobals.device[deviceToUpdate].throughput/(float)timeDiff;
    myGlobals.device[deviceToUpdate].actualPktsThpt = 
      (float)myGlobals.device[deviceToUpdate].packetThroughput/(float)timeDiff;

    if(myGlobals.device[deviceToUpdate].actualThpt > myGlobals.device[deviceToUpdate].peakThroughput)
      myGlobals.device[deviceToUpdate].peakThroughput = myGlobals.device[deviceToUpdate].actualThpt;

    if(myGlobals.device[deviceToUpdate].actualPktsThpt > myGlobals.device[deviceToUpdate].peakPacketThroughput)
      myGlobals.device[deviceToUpdate].peakPacketThroughput = myGlobals.device[deviceToUpdate].actualPktsThpt;

    myGlobals.device[deviceToUpdate].throughput = myGlobals.device[deviceToUpdate].ethernetBytes;
    myGlobals.device[deviceToUpdate].packetThroughput = myGlobals.device[deviceToUpdate].ethernetPkts;

    if(updateMinThpt) {
      myGlobals.device[deviceToUpdate].lastMinEthernetBytes = myGlobals.device[deviceToUpdate].ethernetBytes-
	myGlobals.device[deviceToUpdate].lastMinEthernetBytes;
      myGlobals.device[deviceToUpdate].lastMinThpt = 
	(float)(myGlobals.device[deviceToUpdate].lastMinEthernetBytes)/(float)timeMinDiff;
      myGlobals.device[deviceToUpdate].lastMinEthernetBytes = myGlobals.device[deviceToUpdate].ethernetBytes;
      /* ******************* */
      myGlobals.device[deviceToUpdate].lastMinEthernetPkts = myGlobals.device[deviceToUpdate].ethernetPkts-
	myGlobals.device[deviceToUpdate].lastMinEthernetPkts;
      myGlobals.device[deviceToUpdate].lastMinPktsThpt = 
	(float)myGlobals.device[deviceToUpdate].lastMinEthernetPkts/(float)timeMinDiff;
      myGlobals.device[deviceToUpdate].lastMinEthernetPkts = myGlobals.device[deviceToUpdate].ethernetPkts;
      myGlobals.device[deviceToUpdate].lastMinThptUpdate = myGlobals.actTime;
    }

    if((timeMinDiff = myGlobals.actTime-myGlobals.
	device[deviceToUpdate].lastFiveMinsThptUpdate) > 300 /* 5 minutes */) {
      myGlobals.device[deviceToUpdate].lastFiveMinsEthernetBytes = 
	myGlobals.device[deviceToUpdate].ethernetBytes 
	- myGlobals.device[deviceToUpdate].lastFiveMinsEthernetBytes;
      myGlobals.device[deviceToUpdate].lastFiveMinsThptUpdate = timeMinDiff;
      myGlobals.device[deviceToUpdate].lastFiveMinsThpt = 
	(float)myGlobals.device[deviceToUpdate].lastFiveMinsEthernetBytes/
	(float)myGlobals.device[deviceToUpdate].lastFiveMinsThptUpdate;
      myGlobals.device[deviceToUpdate].lastFiveMinsEthernetBytes = 
	myGlobals.device[deviceToUpdate].ethernetBytes;
      /* ******************* */
      myGlobals.device[deviceToUpdate].lastFiveMinsEthernetPkts = 
	myGlobals.device[deviceToUpdate].ethernetPkts 
	- myGlobals.device[deviceToUpdate].lastFiveMinsEthernetPkts;
      myGlobals.device[deviceToUpdate].lastFiveMinsPktsThpt = 
	(float)myGlobals.device[deviceToUpdate].lastFiveMinsEthernetPkts/
	(float)myGlobals.device[deviceToUpdate].lastFiveMinsThptUpdate;
      myGlobals.device[deviceToUpdate].lastFiveMinsEthernetPkts = 
	myGlobals.device[deviceToUpdate].ethernetPkts;
      myGlobals.device[deviceToUpdate].lastFiveMinsThptUpdate = myGlobals.actTime;
    }

    if((updateMinThpt || updateHourThpt) 
       && ((topSentIdx        != NO_PEER) 
	   || (topHourSentIdx != NO_PEER)
	   || (topRcvdIdx     != NO_PEER)
	   || (topHourRcvdIdx != NO_PEER)))
      updateThptStats(deviceToUpdate,
		      topSentIdx, secondSentIdx, thirdSentIdx,
		      topHourSentIdx, secondHourSentIdx, thirdHourSentIdx,
		      topRcvdIdx, secondRcvdIdx, thirdRcvdIdx,
		      topHourRcvdIdx, secondHourRcvdIdx, thirdHourRcvdIdx);

    myGlobals.device[deviceToUpdate].lastThptUpdate = myGlobals.actTime;
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "updateDeviceStats() completed.");
#endif
}

/* ******************************* */

void updateThpt(void) {
  int i;

#ifndef DEBUG
  traceEvent(TRACE_INFO, "updateThpt() called");
#endif

  if(myGlobals.mergeInterfaces)
    updateDeviceThpt(0);
  else {
    for(i=0; i<myGlobals.numDevices; i++)
      updateDeviceThpt(i);
  }
}

/* ******************************* */

static void updateHostThpt(HostTraffic *el, int hourId) {

  if(broadcastHost(el))
    return;
  
  el->lastCounterBytesSent = el->bytesSent;
  el->lastCounterBytesRcvd = el->bytesRcvd;

  if(hourId == 0) {
    el->lastDayBytesSent = el->bytesSent;
      el->lastDayBytesRcvd = el->bytesRcvd;
  }
}

/* ******************************* */

void updateHostsDeviceThpt(int deviceToUpdate, int hourId) {
  u_int idx;
  HostTraffic *el;
  
  for(idx=1; idx<myGlobals.device[deviceToUpdate].actualHashSize; idx++) {
    if((el = myGlobals.device[deviceToUpdate].hash_hostTraffic[idx]) != NULL) {
      updateHostThpt(el, hourId);
    }
  }
}

/* ******************************* */

void updateTrafficMatrix(HostTraffic *srcHost,
			 HostTraffic *dstHost,
			 TrafficCounter length, 
			 int actualDeviceId) {
  if(subnetLocalHost(srcHost) && subnetLocalHost(dstHost)) {
    unsigned long a, b, id;    

    a = (unsigned long)(srcHost->hostIpAddress.s_addr) % myGlobals.device[actualDeviceId].numHosts;
    b = (unsigned long)(dstHost->hostIpAddress.s_addr) % myGlobals.device[actualDeviceId].numHosts;

    myGlobals.device[actualDeviceId].ipTrafficMatrixHosts[a] = srcHost, 
      myGlobals.device[actualDeviceId].ipTrafficMatrixHosts[b] = dstHost;

    id = a*myGlobals.device[actualDeviceId].numHosts+b;
    if(myGlobals.device[actualDeviceId].ipTrafficMatrix[id] == NULL)
      myGlobals.device[actualDeviceId].ipTrafficMatrix[id] = (TrafficEntry*)calloc(1, sizeof(TrafficEntry));
    myGlobals.device[actualDeviceId].ipTrafficMatrix[id]->bytesSent += length;

    id = b*myGlobals.device[actualDeviceId].numHosts+a;
    if(myGlobals.device[actualDeviceId].ipTrafficMatrix[id] == NULL)
      myGlobals.device[actualDeviceId].ipTrafficMatrix[id] = (TrafficEntry*)calloc(1, sizeof(TrafficEntry));
    myGlobals.device[actualDeviceId].ipTrafficMatrix[id]->bytesRcvd += length;
  }
}

/* *********************************** */

void updateDbHostsTraffic(int deviceToUpdate) {
  u_int i;
  HostTraffic *el;

#ifndef DEBUG
  traceEvent(TRACE_INFO, "updateDbHostsTraffic(myGlobals.device=%d)", deviceToUpdate);
#endif

  for(i=0; i<myGlobals.device[deviceToUpdate].actualHashSize; i++) {
    el = myGlobals.device[deviceToUpdate].hash_hostTraffic[i]; /* (**) */

    if((el != NULL)
       && (!broadcastHost(el))
       && (el->nextDBupdate < myGlobals.actTime)) {
      if(el->nextDBupdate == 0) {
	/* traceEvent(TRACE_INFO, "1"); */
	notifyHostCreation(el);
#ifdef HAVE_MYSQL
	mySQLnotifyHostCreation(el);
#endif
	/* traceEvent(TRACE_INFO, "2"); */
      } else if(el->nextDBupdate < myGlobals.actTime) {
	/* traceEvent(TRACE_INFO, "3"); */
	updateHostTraffic(el);
	/* traceEvent(TRACE_INFO, "4"); */
#ifdef HAVE_MYSQL
	mySQLupdateHostTraffic(el);
#endif /* traceEvent(TRACE_INFO, "5"); */
	if(el->osName == NULL) {
	  /* traceEvent(TRACE_INFO, "6"); */
	  updateOSName(el);
	  /* traceEvent(TRACE_INFO, "7"); */
	}
      }

      el->nextDBupdate = myGlobals.actTime + DB_TIMEOUT_REFRESH_TIME;
    }
  }
}

/* ************************ */

int isInitialHttpData(char* packetData) {
  /* GET / HTTP/1.0 */
  if((strncmp(packetData,    "GET ",     4) == 0) /* HTTP/1.0 */
     || (strncmp(packetData, "HEAD ",    5) == 0)
     || (strncmp(packetData, "LINK ",    5) == 0)
     || (strncmp(packetData, "POST ",    5) == 0)
     || (strncmp(packetData, "OPTIONS ", 8) == 0) /* HTTP/1.1 */
     || (strncmp(packetData, "PUT ",     4) == 0)
     || (strncmp(packetData, "DELETE ",  7) == 0)
     || (strncmp(packetData, "TRACE ",   6) == 0)
     || (strncmp(packetData, "PROPFIND", 8) == 0) /* RFC 2518 */
     ) 
    return(1);
  else
    return(0);
}

/* ************************ */

int isInitialSshData(char* packetData) {
  /* SSH-1.99-OpenSSH_2.1.1 */
  if(strncmp(packetData, "SSH-", 4) == 0)
    return(1);
  else
    return(0);
}

/* ************************ */

int isInitialFtpData(char* packetData) {
  /* 220 linux.local FTP server (Version 6.4/OpenBSD/Linux-ftpd-0.16) ready. */
  if((strncmp(packetData, "220 ", 4) == 0)
     || (strncmp(packetData, "530", 3) == 0))
    return(1);
  else
    return(0);
}
