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

/* ******************************* */

static void updateThptStats(int deviceToUpdate,
			    u_int topSentIdx,
			    u_int secondSentIdx, 
			    u_int thirdSentIdx,
			    u_int topHourSentIdx, 
			    u_int secondHourSentIdx,
			    u_int thirdHourSentIdx,
			    u_int topRcvdIdx, 
			    u_int secondRcvdIdx, 
			    u_int thirdRcvdIdx,
			    u_int topHourRcvdIdx, 
			    u_int secondHourRcvdIdx,
			    u_int thirdHourRcvdIdx) {
  int i;

  if(myGlobals.device[deviceToUpdate].dummyDevice)
    return;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "updateThptStats(%d, %d, %d, %d, %d, %d)\n",
	 topSentIdx, secondSentIdx, thirdSentIdx,
	 topHourSentIdx, secondHourSentIdx,
	 thirdHourSentIdx);
#endif

  /* We never check enough... */
  if(topSentIdx == FLAG_NO_PEER) 
    return;

  if(topRcvdIdx == FLAG_NO_PEER) 
    return;

  if(secondSentIdx == FLAG_NO_PEER) 
    secondSentIdx = 0;

  if(thirdSentIdx == FLAG_NO_PEER)
    thirdSentIdx = 0;

  if(secondRcvdIdx == FLAG_NO_PEER)
    secondRcvdIdx = 0;

  if(thirdRcvdIdx == FLAG_NO_PEER)
    thirdRcvdIdx = 0;

  for(i=58; i>=0; i--)
    memcpy(&myGlobals.device[deviceToUpdate].last60MinutesThpt[i+1],
	   &myGlobals.device[deviceToUpdate].last60MinutesThpt[i], sizeof(ThptEntry));

  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].trafficValue = myGlobals.device[deviceToUpdate].lastMinThpt;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "LastMinThpt: %s", formatThroughput(myGlobals.device[deviceToUpdate].lastMinThpt));
#endif

  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].topHostSentSerial = getSerial(topSentIdx),
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].topSentTraffic.value = 
    myGlobals.device[deviceToUpdate].hash_hostTraffic[topSentIdx]->actualSentThpt;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].secondHostSentSerial = getSerial(secondSentIdx),
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].secondSentTraffic.value = 
    myGlobals.device[deviceToUpdate].hash_hostTraffic[secondSentIdx]->actualSentThpt;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].thirdHostSentSerial = getSerial(thirdSentIdx),
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].thirdSentTraffic.value = 
    myGlobals.device[deviceToUpdate].hash_hostTraffic[thirdSentIdx]->actualSentThpt;

  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].topHostRcvdSerial = getSerial(topRcvdIdx),
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].topRcvdTraffic.value = 
    myGlobals.device[deviceToUpdate].hash_hostTraffic[topRcvdIdx]->actualRcvdThpt;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].secondHostRcvdSerial = getSerial(secondRcvdIdx),
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].secondRcvdTraffic.value = 
    myGlobals.device[deviceToUpdate].hash_hostTraffic[secondRcvdIdx]->actualRcvdThpt;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].thirdHostRcvdSerial = getSerial(thirdRcvdIdx),
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].thirdRcvdTraffic.value = 
    myGlobals.device[deviceToUpdate].hash_hostTraffic[thirdRcvdIdx]->actualRcvdThpt;

  myGlobals.device[deviceToUpdate].last60MinutesThptIdx = (myGlobals.device[deviceToUpdate].last60MinutesThptIdx+1) % 60;

  if(topHourSentIdx != FLAG_NO_PEER) { 
    /* It wrapped -> 1 hour is over */
    float average=0;

    if(topHourSentIdx == FLAG_NO_PEER) return;
    if(topHourRcvdIdx == FLAG_NO_PEER) return;
    if(secondHourSentIdx == FLAG_NO_PEER) secondHourSentIdx = 0;
    if(thirdHourSentIdx == FLAG_NO_PEER)  thirdHourSentIdx = 0;
    if(secondHourRcvdIdx == FLAG_NO_PEER) secondHourRcvdIdx = 0;
    if(thirdHourRcvdIdx == FLAG_NO_PEER)  thirdHourRcvdIdx = 0;

    for(i=0; i<60; i++) {
      average += myGlobals.device[deviceToUpdate].last60MinutesThpt[i].trafficValue;
    }

    average /= 60;

    for(i=22; i>=0; i--)
      memcpy(&myGlobals.device[deviceToUpdate].last24HoursThpt[i+1], 
	     &myGlobals.device[deviceToUpdate].last24HoursThpt[i], sizeof(ThptEntry));

    myGlobals.device[deviceToUpdate].last24HoursThpt[0].trafficValue = average;

    myGlobals.device[deviceToUpdate].last24HoursThpt[0].topHostSentSerial = getSerial(topHourSentIdx),
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].topSentTraffic.value = 
      myGlobals.device[deviceToUpdate].hash_hostTraffic[topHourSentIdx]->lastHourSentThpt;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].secondHostSentSerial = getSerial(secondHourSentIdx),
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].secondSentTraffic.value = 
      myGlobals.device[deviceToUpdate].hash_hostTraffic[secondHourSentIdx]->lastHourSentThpt;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].thirdHostSentSerial = getSerial(thirdHourSentIdx),
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].thirdSentTraffic.value = 
      myGlobals.device[deviceToUpdate].hash_hostTraffic[thirdHourSentIdx]->lastHourSentThpt;

    myGlobals.device[deviceToUpdate].last24HoursThpt[0].topHostRcvdSerial = getSerial(topHourRcvdIdx),
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].topRcvdTraffic.value = 
      myGlobals.device[deviceToUpdate].hash_hostTraffic[topHourRcvdIdx]->lastHourRcvdThpt;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].secondHostRcvdSerial = getSerial(secondHourRcvdIdx),
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].secondRcvdTraffic.value = 
      myGlobals.device[deviceToUpdate].hash_hostTraffic[secondHourRcvdIdx]->lastHourRcvdThpt;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].thirdHostRcvdSerial = getSerial(thirdHourRcvdIdx),
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].thirdRcvdTraffic.value = 
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
  traceEvent(CONST_TRACE_INFO, "updateThptStats() completed.\n");
#endif
}

/* ******************************* */

void updateDeviceThpt(int deviceToUpdate) {
  time_t timeDiff, timeMinDiff, timeHourDiff=0, totalTime;
  u_int idx;
  HostTraffic *el;

  timeDiff = myGlobals.actTime-myGlobals.device[deviceToUpdate].lastThptUpdate;

  if(timeDiff > 10 /* secs */) {
    u_int topSentIdx=FLAG_NO_PEER, secondSentIdx=FLAG_NO_PEER, thirdSentIdx=FLAG_NO_PEER;
    u_int topHourSentIdx=FLAG_NO_PEER, secondHourSentIdx=FLAG_NO_PEER, thirdHourSentIdx=FLAG_NO_PEER;
    u_int topRcvdIdx=FLAG_NO_PEER, secondRcvdIdx=FLAG_NO_PEER, thirdRcvdIdx=FLAG_NO_PEER;
    u_int topHourRcvdIdx=FLAG_NO_PEER, secondHourRcvdIdx=FLAG_NO_PEER, thirdHourRcvdIdx=FLAG_NO_PEER;
    short updateMinThpt, updateHourThpt;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "updateDeviceStats() called.");
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
      if((el = myGlobals.device[deviceToUpdate].hash_hostTraffic[idx]) != NULL) {

	if(broadcastHost(el)) continue;

	el->actualRcvdThpt       = (float)(el->bytesRcvd.value-el->lastBytesRcvd.value)/timeDiff;
	if(el->peakRcvdThpt      < el->actualRcvdThpt) el->peakRcvdThpt = el->actualRcvdThpt;
	el->actualSentThpt       = (float)(el->bytesSent.value-el->lastBytesSent.value)/timeDiff;
	if(el->peakSentThpt      < el->actualSentThpt) el->peakSentThpt = el->actualSentThpt;
	el->actualTThpt          = (float)(el->bytesRcvd.value-el->lastBytesRcvd.value +
                                           el->bytesSent.value-el->lastBytesSent.value)/timeDiff;
	if(el->peakTThpt         < el->actualTThpt) el->peakTThpt = el->actualTThpt;
	el->lastBytesSent        = el->bytesSent;
	el->lastBytesRcvd        = el->bytesRcvd;

	/* ******************************** */

	el->actualRcvdPktThpt    = (float)(el->pktRcvd.value-el->lastPktRcvd.value)/timeDiff;
	if(el->peakRcvdPktThpt   < el->actualRcvdPktThpt) el->peakRcvdPktThpt = el->actualRcvdPktThpt;
	el->actualSentPktThpt    = (float)(el->pktSent.value-el->lastPktSent.value)/timeDiff;
	if(el->peakSentPktThpt   < el->actualSentPktThpt) el->peakSentPktThpt = el->actualSentPktThpt;
	el->actualTPktThpt       = (float)(el->pktRcvd.value-el->lastPktRcvd.value+
                                           el->pktSent.value-el->lastPktSent.value)/timeDiff;
	if(el->peakTPktThpt      < el->actualTPktThpt) el->peakTPktThpt = el->actualTPktThpt;
	el->lastPktSent          = el->pktSent;
	el->lastPktRcvd          = el->pktRcvd;

	/* ******************************** */

	if(updateMinThpt) {
	  el->averageRcvdThpt    = ((float)el->bytesRcvdSession.value)/totalTime;
	  el->averageSentThpt    = ((float)el->bytesSentSession.value)/totalTime;
	  el->averageTThpt       = ((float)el->bytesRcvdSession.value+
                                    (float)el->bytesSentSession.value)/totalTime;
	  el->averageRcvdPktThpt = ((float)el->pktRcvdSession.value)/totalTime;
	  el->averageSentPktThpt = ((float)el->pktSentSession.value)/totalTime;
	  el->averageTPktThpt    = ((float)el->pktRcvdSession.value+
                                    (float)el->pktSentSession.value)/totalTime;

	  if((topSentIdx == FLAG_NO_PEER) 
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
	      if((secondSentIdx == FLAG_NO_PEER)
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
		  if((thirdSentIdx == FLAG_NO_PEER)
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

	  if((topRcvdIdx == FLAG_NO_PEER) 
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
	      if((secondRcvdIdx == FLAG_NO_PEER)
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
		  if((thirdRcvdIdx == FLAG_NO_PEER)
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
	    el->lastHourRcvdThpt = (float)(el->bytesRcvd.value-el->lastHourBytesRcvd.value)/timeHourDiff;
	    el->lastHourSentThpt = (float)(el->bytesSent.value-el->lastHourBytesSent.value)/timeHourDiff;
	    el->lastHourBytesRcvd = el->bytesRcvd;
	    el->lastHourBytesSent = el->bytesSent;

	    if((topHourSentIdx == FLAG_NO_PEER) 
	       || (myGlobals.device[deviceToUpdate].hash_hostTraffic[topHourSentIdx] == NULL)) {
	      topHourSentIdx = idx;
	    } else {
	      if(el->lastHourSentThpt > myGlobals.device[deviceToUpdate].
		 hash_hostTraffic[topHourSentIdx]->lastHourSentThpt) {
		secondHourSentIdx = topHourSentIdx;
		topHourSentIdx = idx;
	      } else {
		if((secondHourSentIdx == FLAG_NO_PEER)
		   || (myGlobals.device[deviceToUpdate].hash_hostTraffic[secondHourSentIdx] == NULL)) {
		  secondHourSentIdx = idx;
		} else {
		  if(el->lastHourSentThpt > myGlobals.device[deviceToUpdate].
		     hash_hostTraffic[secondHourSentIdx]->lastHourSentThpt) {
		    thirdHourSentIdx = secondHourSentIdx;
		    secondHourSentIdx = idx;
		  } else {
		    if((thirdHourSentIdx == FLAG_NO_PEER)
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

	    if((topHourRcvdIdx == FLAG_NO_PEER) 
	       || (myGlobals.device[deviceToUpdate].hash_hostTraffic[topHourRcvdIdx] == NULL)) {
	      topHourRcvdIdx = idx;
	    } else {
	      if(el->lastHourRcvdThpt > myGlobals.device[deviceToUpdate].
		 hash_hostTraffic[topHourRcvdIdx]->lastHourRcvdThpt) {
		secondHourRcvdIdx = topHourRcvdIdx;
		topHourRcvdIdx = idx;
	      } else {
		if((secondHourRcvdIdx == FLAG_NO_PEER)
		   || (myGlobals.device[deviceToUpdate].hash_hostTraffic[secondHourRcvdIdx] == NULL)) {
		  secondHourRcvdIdx = idx;
		} else {
		  if(el->lastHourRcvdThpt > myGlobals.device[deviceToUpdate].
		     hash_hostTraffic[secondHourRcvdIdx]->lastHourRcvdThpt) {
		    thirdHourRcvdIdx = secondHourRcvdIdx;
		    secondHourRcvdIdx = idx;
		  } else {
		    if((thirdHourRcvdIdx == FLAG_NO_PEER)
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
      myGlobals.device[deviceToUpdate].ethernetBytes.value - myGlobals.device[deviceToUpdate].throughput;
    myGlobals.device[deviceToUpdate].packetThroughput = myGlobals.device[deviceToUpdate].ethernetPkts.value -
      myGlobals.device[deviceToUpdate].lastNumEthernetPkts.value;
    myGlobals.device[deviceToUpdate].lastNumEthernetPkts = myGlobals.device[deviceToUpdate].ethernetPkts;

    /* timeDiff++; */
    myGlobals.device[deviceToUpdate].actualThpt = (float)myGlobals.device[deviceToUpdate].throughput/(float)timeDiff;
    myGlobals.device[deviceToUpdate].actualPktsThpt = 
      (float)myGlobals.device[deviceToUpdate].packetThroughput/(float)timeDiff;

    if(myGlobals.device[deviceToUpdate].actualThpt > myGlobals.device[deviceToUpdate].peakThroughput)
      myGlobals.device[deviceToUpdate].peakThroughput = myGlobals.device[deviceToUpdate].actualThpt;

    if(myGlobals.device[deviceToUpdate].actualPktsThpt > myGlobals.device[deviceToUpdate].peakPacketThroughput)
      myGlobals.device[deviceToUpdate].peakPacketThroughput = myGlobals.device[deviceToUpdate].actualPktsThpt;

    myGlobals.device[deviceToUpdate].throughput = myGlobals.device[deviceToUpdate].ethernetBytes.value;
    myGlobals.device[deviceToUpdate].packetThroughput = myGlobals.device[deviceToUpdate].ethernetPkts.value;

    if(updateMinThpt) {
      myGlobals.device[deviceToUpdate].lastMinEthernetBytes.value = myGlobals.device[deviceToUpdate].ethernetBytes.value -
	myGlobals.device[deviceToUpdate].lastMinEthernetBytes.value;
      myGlobals.device[deviceToUpdate].lastMinThpt = 
	(float)(myGlobals.device[deviceToUpdate].lastMinEthernetBytes.value)/(float)timeMinDiff;
      myGlobals.device[deviceToUpdate].lastMinEthernetBytes = myGlobals.device[deviceToUpdate].ethernetBytes;
      /* ******************* */
      myGlobals.device[deviceToUpdate].lastMinEthernetPkts.value = myGlobals.device[deviceToUpdate].ethernetPkts.value-
	myGlobals.device[deviceToUpdate].lastMinEthernetPkts.value;
      myGlobals.device[deviceToUpdate].lastMinPktsThpt = 
	(float)myGlobals.device[deviceToUpdate].lastMinEthernetPkts.value/(float)timeMinDiff;
      myGlobals.device[deviceToUpdate].lastMinEthernetPkts = myGlobals.device[deviceToUpdate].ethernetPkts;
      myGlobals.device[deviceToUpdate].lastMinThptUpdate = myGlobals.actTime;
    }

    if((timeMinDiff = myGlobals.actTime-myGlobals.
	device[deviceToUpdate].lastFiveMinsThptUpdate) > 300 /* 5 minutes */) {
      myGlobals.device[deviceToUpdate].lastFiveMinsEthernetBytes.value = 
	myGlobals.device[deviceToUpdate].ethernetBytes.value - myGlobals.device[deviceToUpdate].lastFiveMinsEthernetBytes.value;
      myGlobals.device[deviceToUpdate].lastFiveMinsThptUpdate = timeMinDiff;
      myGlobals.device[deviceToUpdate].lastFiveMinsThpt = 
	(float)myGlobals.device[deviceToUpdate].lastFiveMinsEthernetBytes.value/
	(float)myGlobals.device[deviceToUpdate].lastFiveMinsThptUpdate;
      myGlobals.device[deviceToUpdate].lastFiveMinsEthernetBytes.value = 
	myGlobals.device[deviceToUpdate].ethernetBytes.value;
      /* ******************* */
      myGlobals.device[deviceToUpdate].lastFiveMinsEthernetPkts.value = 
	myGlobals.device[deviceToUpdate].ethernetPkts.value 
	- myGlobals.device[deviceToUpdate].lastFiveMinsEthernetPkts.value;
      myGlobals.device[deviceToUpdate].lastFiveMinsPktsThpt = 
	(float)myGlobals.device[deviceToUpdate].lastFiveMinsEthernetPkts.value/
	(float)myGlobals.device[deviceToUpdate].lastFiveMinsThptUpdate;
      myGlobals.device[deviceToUpdate].lastFiveMinsEthernetPkts.value = 
	myGlobals.device[deviceToUpdate].ethernetPkts.value;
      myGlobals.device[deviceToUpdate].lastFiveMinsThptUpdate = myGlobals.actTime;
    }

    if((updateMinThpt || updateHourThpt) 
       && ((topSentIdx        != FLAG_NO_PEER) 
	   || (topHourSentIdx != FLAG_NO_PEER)
	   || (topRcvdIdx     != FLAG_NO_PEER)
	   || (topHourRcvdIdx != FLAG_NO_PEER)))
      updateThptStats(deviceToUpdate,
		      topSentIdx, secondSentIdx, thirdSentIdx,
		      topHourSentIdx, secondHourSentIdx, thirdHourSentIdx,
		      topRcvdIdx, secondRcvdIdx, thirdRcvdIdx,
		      topHourRcvdIdx, secondHourRcvdIdx, thirdHourRcvdIdx);

    myGlobals.device[deviceToUpdate].lastThptUpdate = myGlobals.actTime;
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "updateDeviceStats() completed.");
#endif
}

/* ******************************* */

void updateThpt(void) {
  int i;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "updateThpt() called");
#endif

  if(myGlobals.mergeInterfaces)
    updateDeviceThpt(0);
  else {
    for(i=0; i<myGlobals.numDevices; i++)
      updateDeviceThpt(i);
  }
}

/* ******************************* */

void updateTrafficMatrix(HostTraffic *srcHost,
			 HostTraffic *dstHost,
			 TrafficCounter length, 
			 int actualDeviceId) {
  if((deviceLocalAddress(&srcHost->hostIpAddress, actualDeviceId) || multicastHost(srcHost))
     && (deviceLocalAddress(&dstHost->hostIpAddress, actualDeviceId) || multicastHost(dstHost))
     && (!broadcastHost(srcHost))
     && (!broadcastHost(dstHost))) {
    unsigned long a, b, id;    

    a = (unsigned long)(srcHost->hostIpAddress.s_addr) % myGlobals.device[actualDeviceId].numHosts;
    b = (unsigned long)(dstHost->hostIpAddress.s_addr) % myGlobals.device[actualDeviceId].numHosts;

    myGlobals.device[actualDeviceId].ipTrafficMatrixHosts[a] = srcHost, 
      myGlobals.device[actualDeviceId].ipTrafficMatrixHosts[b] = dstHost;

    id = a*myGlobals.device[actualDeviceId].numHosts+b;
    if(myGlobals.device[actualDeviceId].ipTrafficMatrix[id] == NULL)
      myGlobals.device[actualDeviceId].ipTrafficMatrix[id] = (TrafficEntry*)calloc(1, sizeof(TrafficEntry));
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipTrafficMatrix[id]->bytesSent, length.value);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipTrafficMatrix[id]->pktsSent, 1);

    id = b*myGlobals.device[actualDeviceId].numHosts+a;
    if(myGlobals.device[actualDeviceId].ipTrafficMatrix[id] == NULL)
      myGlobals.device[actualDeviceId].ipTrafficMatrix[id] = (TrafficEntry*)calloc(1, sizeof(TrafficEntry));
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipTrafficMatrix[id]->bytesRcvd, length.value);
    incrementTrafficCounter(&myGlobals.device[actualDeviceId].ipTrafficMatrix[id]->pktsRcvd, 1);
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
