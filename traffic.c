/*
 *  Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
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

void updateFcTrafficMatrix(HostTraffic *srcHost, HostTraffic *dstHost,
                           TrafficCounter length, int actualDeviceId);

/* ******************************* */

static void updateThptStats(int deviceToUpdate,
			    HostSerial topSentSerial,
			    HostSerial secondSentSerial, 
			    HostSerial thirdSentSerial,
			    HostSerial topHourSentSerial, 
			    HostSerial secondHourSentSerial,
			    HostSerial thirdHourSentSerial,
			    HostSerial topRcvdSerial, 
			    HostSerial secondRcvdSerial, 
			    HostSerial thirdRcvdSerial,
			    HostSerial topHourRcvdSerial, 
			    HostSerial secondHourRcvdSerial,
			    HostSerial thirdHourRcvdSerial) {
  int i;
  HostTraffic *topHost;
  float topThpt;
#ifdef DEBUG  
  char formatBuf[32];
#endif  

  /*
  if(myGlobals.device[deviceToUpdate].dummyDevice)
    return;
  */

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "updateThptStats(%d, %d, %d, %d, %d, %d)",
	 topSentSerial, secondSentSerial, thirdSentSerial,
	 topHourSentSerial, secondHourSentSerial,
	 thirdHourSentSerial);
#endif

  /* We never check enough... */
  if(emptySerial(&topSentSerial)) 
    return;

  if(emptySerial(&topRcvdSerial))
    return;

  if(emptySerial(&secondSentSerial))
      setEmptySerial(&secondSentSerial);

  if(emptySerial(&thirdSentSerial))
      setEmptySerial(&thirdSentSerial);

  if(emptySerial(&secondRcvdSerial))
      setEmptySerial(&secondRcvdSerial);

  if(emptySerial(&thirdRcvdSerial))
      setEmptySerial(&thirdRcvdSerial);

  for(i=58; i>=0; i--)
    memcpy(&myGlobals.device[deviceToUpdate].last60MinutesThpt[i+1],
	   &myGlobals.device[deviceToUpdate].last60MinutesThpt[i], sizeof(ThptEntry));

  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].trafficValue = myGlobals.device[deviceToUpdate].lastMinThpt;

#ifdef DEBUG  
  traceEvent (CONST_TRACE_ALWAYSDISPLAY, "LastMinThpt: %s",
              formatThroughput(myGlobals.device[deviceToUpdate].lastMinThpt, 0, formatBuf, sizeof (formatBuf)));
#endif  

  topHost = findHostBySerial(topSentSerial, deviceToUpdate); 
  if(topHost != NULL) topThpt = topHost->actualSentThpt; else topThpt = 0;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].topHostSentSerial = topSentSerial,
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].topSentTraffic.value = topThpt;

  topHost = findHostBySerial(secondSentSerial, deviceToUpdate); 
  if(topHost != NULL) topThpt = topHost->actualSentThpt; else topThpt = 0;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].secondHostSentSerial = secondSentSerial,
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].secondSentTraffic.value = topThpt;

  topHost = findHostBySerial(thirdSentSerial, deviceToUpdate); 
  if(topHost != NULL) topThpt = topHost->actualSentThpt; else topThpt = 0;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].thirdHostSentSerial = thirdSentSerial,
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].thirdSentTraffic.value = topThpt;

  topHost = findHostBySerial(topRcvdSerial, deviceToUpdate); 
  if(topHost != NULL) topThpt = topHost->actualRcvdThpt; else topThpt = 0;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].topHostRcvdSerial = topRcvdSerial,
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].topRcvdTraffic.value = topThpt;

  topHost = findHostBySerial(secondRcvdSerial, deviceToUpdate); 
  if(topHost != NULL) topThpt = topHost->actualRcvdThpt; else topThpt = 0;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].secondHostRcvdSerial = secondRcvdSerial,
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].secondRcvdTraffic.value = topThpt;

  topHost = findHostBySerial(thirdRcvdSerial, deviceToUpdate); 
  if(topHost != NULL) topThpt = topHost->actualRcvdThpt; else topThpt = 0;
  myGlobals.device[deviceToUpdate].last60MinutesThpt[0].thirdHostRcvdSerial = thirdRcvdSerial,
    myGlobals.device[deviceToUpdate].last60MinutesThpt[0].thirdRcvdTraffic.value = topThpt;

  myGlobals.device[deviceToUpdate].last60MinutesThptIdx = (myGlobals.device[deviceToUpdate].last60MinutesThptIdx+1) % 60;

  if(!emptySerial(&topHourSentSerial)) { 
    /* It wrapped -> 1 hour is over */
    float average=0;

    if(emptySerial(&topHourSentSerial)) return;
    if(emptySerial(&topHourRcvdSerial)) return;
    if(emptySerial(&secondHourSentSerial)) secondHourSentSerial.serialType = SERIAL_NONE;
    if(emptySerial(&thirdHourSentSerial))  thirdHourSentSerial.serialType = SERIAL_NONE;
    if(emptySerial(&secondHourRcvdSerial)) secondHourRcvdSerial.serialType = SERIAL_NONE;
    if(emptySerial(&thirdHourRcvdSerial))  thirdHourRcvdSerial.serialType = SERIAL_NONE;

    for(i=0; i<60; i++) {
      average += myGlobals.device[deviceToUpdate].last60MinutesThpt[i].trafficValue;
    }

    average /= 60;

    for(i=22; i>=0; i--)
      memcpy(&myGlobals.device[deviceToUpdate].last24HoursThpt[i+1], 
	     &myGlobals.device[deviceToUpdate].last24HoursThpt[i], sizeof(ThptEntry));

    myGlobals.device[deviceToUpdate].last24HoursThpt[0].trafficValue = average;

  topHost = findHostBySerial(topHourSentSerial, deviceToUpdate); 
  if(topHost != NULL) topThpt = topHost->lastHourSentThpt; else topThpt = 0;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].topHostSentSerial = topHourSentSerial,
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].topSentTraffic.value = topThpt;

  topHost = findHostBySerial(secondHourSentSerial, deviceToUpdate); 
  if(topHost != NULL) topThpt = topHost->lastHourSentThpt; else topThpt = 0;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].secondHostSentSerial = secondHourSentSerial,
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].secondSentTraffic.value = topThpt;

  topHost = findHostBySerial(thirdHourSentSerial, deviceToUpdate); 
  if(topHost != NULL) topThpt = topHost->lastHourSentThpt; else topThpt = 0;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].thirdHostSentSerial = thirdHourSentSerial,
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].thirdSentTraffic.value = topThpt;


  topHost = findHostBySerial(topHourRcvdSerial, deviceToUpdate); 
  if(topHost != NULL) topThpt = topHost->lastHourRcvdThpt; else topThpt = 0;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].topHostRcvdSerial = topHourRcvdSerial,
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].topRcvdTraffic.value = topThpt;

  topHost = findHostBySerial(secondHourRcvdSerial, deviceToUpdate); 
  if(topHost != NULL) topThpt = topHost->lastHourRcvdThpt; else topThpt = 0;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].secondHostRcvdSerial = secondHourRcvdSerial,
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].secondRcvdTraffic.value = topThpt;

  topHost = findHostBySerial(thirdHourRcvdSerial, deviceToUpdate); 
  if(topHost != NULL) topThpt = topHost->lastHourRcvdThpt; else topThpt = 0;
    myGlobals.device[deviceToUpdate].last24HoursThpt[0].thirdHostRcvdSerial = thirdHourRcvdSerial,
      myGlobals.device[deviceToUpdate].last24HoursThpt[0].thirdRcvdTraffic.value = topThpt;

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
  traceEvent(CONST_TRACE_INFO, "updateThptStats() completed.");
#endif
}

/* ******************************* */

void updateDeviceThpt(int deviceToUpdate, int quickUpdate) {
  time_t timeDiff, timeMinDiff, timeHourDiff=0, totalTime;
  HostTraffic *el, *topHost;
  float topThpt;
  HostSerial topSentSerial, secondSentSerial, thirdSentSerial;
  HostSerial topHourSentSerial, secondHourSentSerial, thirdHourSentSerial;
  HostSerial topRcvdSerial, secondRcvdSerial, thirdRcvdSerial;
  HostSerial topHourRcvdSerial, secondHourRcvdSerial, thirdHourRcvdSerial;
  short updateMinThpt=0, updateHourThpt=0;
  
  timeDiff = myGlobals.actTime-myGlobals.device[deviceToUpdate].lastThptUpdate;
  if(timeDiff < 10 /* secs */) return;

  /* ******************************** */

  setEmptySerial(&topSentSerial), setEmptySerial(&secondSentSerial), setEmptySerial(&thirdSentSerial);
  setEmptySerial(&topHourSentSerial), setEmptySerial(&secondHourSentSerial), setEmptySerial(&thirdHourSentSerial);
  setEmptySerial(&topRcvdSerial), setEmptySerial(&secondRcvdSerial), setEmptySerial(&thirdRcvdSerial);
  setEmptySerial(&topHourRcvdSerial), setEmptySerial(&secondHourRcvdSerial), setEmptySerial(&thirdHourRcvdSerial);

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

  if((timeMinDiff = myGlobals.actTime-myGlobals.device[deviceToUpdate].lastMinThptUpdate) > 60 /* 1 minute */) {
    updateMinThpt = 1;
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

  if((timeMinDiff = myGlobals.actTime-myGlobals.device[deviceToUpdate].lastFiveMinsThptUpdate) > 300 /* 5 minutes */) {
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

  if(quickUpdate) {
      myGlobals.device[deviceToUpdate].lastThptUpdate = myGlobals.actTime;
      return;
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "updateDeviceStats() called.");
#endif

  if (myGlobals.runningPref.rFileName != NULL) {
      totalTime = myGlobals.actTime-myGlobals.initialSniffTime;
  }
  else {
      totalTime = myGlobals.actTime;
  }

  if((timeHourDiff = myGlobals.actTime-myGlobals.
      device[deviceToUpdate].lastHourThptUpdate) >= 60*60 /* 1 hour */) {
    updateHourThpt = 1;
    myGlobals.device[deviceToUpdate].lastHourThptUpdate = myGlobals.actTime;
  }

  for(el=getFirstHost(deviceToUpdate); el != NULL; el = getNextHost(deviceToUpdate, el)) {
    if(!isFcHost (el) && broadcastHost(el)) {
      continue;
    }

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

      if(emptySerial(&topSentSerial)) {
	if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry))
	  topSentSerial = el->hostSerial;
      } else {
	topHost = findHostBySerial(topSentSerial, deviceToUpdate); 
	if(topHost != NULL) topThpt = topHost->actualSentThpt; else topThpt = 0;
	if(el->actualSentThpt > topThpt) {
	  if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry)) {
	    secondSentSerial = topSentSerial;
	    topSentSerial = el->hostSerial;
	  }
	} else {
	    if(emptySerial(&secondSentSerial)) {
                if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry))
                    secondSentSerial = el->hostSerial;
	  } else {
	    topHost = findHostBySerial(secondSentSerial, deviceToUpdate); 
	    if(topHost != NULL) topThpt = topHost->actualSentThpt; else topThpt = 0;
	    if(el->actualSentThpt > topThpt) {
	      if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry)) {
		thirdSentSerial = secondSentSerial;
		secondSentSerial = el->hostSerial;
	      }
	    } else {
		if(emptySerial(&thirdSentSerial)) {
		if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry)) {
		  thirdSentSerial = el->hostSerial;
		}
	      } else {
		topHost = findHostBySerial(thirdSentSerial, deviceToUpdate); 
		if(topHost != NULL) topThpt = topHost->actualSentThpt; else topThpt = 0;
		if(el->actualSentThpt > topThpt) {
		  if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry)) {
		    thirdSentSerial = el->hostSerial;
		  }
		}
	      }
	    }
	  }
	}
      }

      if(emptySerial(&topRcvdSerial)) {
	if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry)) 
	  topRcvdSerial = el->hostSerial;
      } else {
	topHost = findHostBySerial(topRcvdSerial, deviceToUpdate); 
	if(topHost != NULL) topThpt = topHost->actualRcvdThpt; else topThpt = 0;
	if(el->actualRcvdThpt > topThpt) {
	  if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry)) {
	    secondRcvdSerial = topRcvdSerial;
	    topRcvdSerial = el->hostSerial;
	  }
	} else {
	    if(emptySerial(&secondRcvdSerial)) {
	    if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry))
	      secondRcvdSerial = el->hostSerial;
	  } else {
	    topHost = findHostBySerial(secondRcvdSerial, deviceToUpdate); 
	    if(topHost != NULL) topThpt = topHost->actualRcvdThpt; else topThpt = 0;
	    if(el->actualRcvdThpt > topThpt) {
	      if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry)) {
		thirdRcvdSerial = secondRcvdSerial;
		secondRcvdSerial = el->hostSerial;
	      }
	    } else {
		if(emptySerial(&thirdRcvdSerial)) {
		if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry))
		  thirdRcvdSerial = el->hostSerial;
	      } else {
		topHost = findHostBySerial(secondRcvdSerial, deviceToUpdate); 
		if(topHost != NULL) topThpt = topHost->actualRcvdThpt; else topThpt = 0;
		if(el->actualRcvdThpt > topThpt) {
		  if((el != myGlobals.broadcastEntry) && (el != myGlobals.otherHostEntry))
		    thirdRcvdSerial = el->hostSerial;
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

	if(emptySerial(&topHourSentSerial)) {
	  topHourSentSerial = el->hostSerial;
	} else {
	  topHost = findHostBySerial(topHourSentSerial, deviceToUpdate); 
	  if(topHost != NULL) topThpt = topHost->lastHourSentThpt; else topThpt = 0;
	  if(el->lastHourSentThpt > topThpt) {
	    secondHourSentSerial = topHourSentSerial;
	    topHourSentSerial = el->hostSerial;
	  } else {
	      if(emptySerial(&secondHourSentSerial)) {
	      secondHourSentSerial = el->hostSerial;
	    } else {
	      topHost = findHostBySerial(secondHourSentSerial, deviceToUpdate); 
	      if(topHost != NULL) topThpt = topHost->lastHourSentThpt; else topThpt = 0;
	      if(el->lastHourSentThpt > topThpt) {
		thirdHourSentSerial = secondHourSentSerial;
		secondHourSentSerial = el->hostSerial;
	      } else {
		  if(emptySerial(&thirdHourSentSerial)) {
		  thirdHourSentSerial = el->hostSerial;
		} else {
		  topHost = findHostBySerial(thirdHourSentSerial, deviceToUpdate); 
		  if(topHost != NULL) topThpt = topHost->lastHourSentThpt; else topThpt = 0;

		  if(el->lastHourSentThpt > topThpt) {
		    thirdHourSentSerial = el->hostSerial;
		  }
		}
	      }
	    }
	  }
	}

	if(emptySerial(&topHourRcvdSerial)) {
	  topHourRcvdSerial = el->hostSerial;
	} else {
	  topHost = findHostBySerial(topHourRcvdSerial, deviceToUpdate); 
	  if(topHost != NULL) topThpt = topHost->lastHourRcvdThpt; else topThpt = 0;

	  if(el->lastHourRcvdThpt > topThpt) {
	    secondHourRcvdSerial = topHourRcvdSerial;
	    topHourRcvdSerial = el->hostSerial;
	  } else {
	      if(emptySerial(&secondHourRcvdSerial)) {
	      secondHourRcvdSerial = el->hostSerial;
	    } else {
	      topHost = findHostBySerial(secondHourRcvdSerial, deviceToUpdate); 
	      if(topHost != NULL) topThpt = topHost->lastHourRcvdThpt; else topThpt = 0;

	      if(el->lastHourRcvdThpt > topThpt) {
		thirdHourRcvdSerial = secondHourRcvdSerial;
		secondHourRcvdSerial = el->hostSerial;
	      } else {
		  if(emptySerial(&thirdHourRcvdSerial)) {
		  thirdHourRcvdSerial = el->hostSerial;
		} else {
		  topHost = findHostBySerial(thirdHourRcvdSerial, deviceToUpdate); 
		  if(topHost != NULL) topThpt = topHost->lastHourRcvdThpt; else topThpt = 0;

		  if(el->lastHourRcvdThpt > topThpt) {
		    thirdHourRcvdSerial = el->hostSerial;
		  }
		}
	      }
	    }
	  }
	}
      }
    }
  }

  if((updateMinThpt || updateHourThpt) 
     && ((!emptySerial(&topSentSerial))
	 || (!emptySerial(&topHourSentSerial))
	 || (!emptySerial(&topRcvdSerial))
	 || (!emptySerial(&topHourRcvdSerial))))
    updateThptStats(deviceToUpdate,
		    topSentSerial, secondSentSerial, thirdSentSerial,
		    topHourSentSerial, secondHourSentSerial, thirdHourSentSerial,
		    topRcvdSerial, secondRcvdSerial, thirdRcvdSerial,
		    topHourRcvdSerial, secondHourRcvdSerial, thirdHourRcvdSerial);

  myGlobals.device[deviceToUpdate].lastThptUpdate = myGlobals.actTime;
  
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "updateDeviceStats() completed.");
#endif
}

/* ******************************* */

void updateThpt(int fullUpdate) {
  int i;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "updateThpt() called");
#endif

  if(myGlobals.runningPref.mergeInterfaces)
    updateDeviceThpt(0, !fullUpdate);
  else {
    for(i=0; i<myGlobals.numDevices; i++)
      updateDeviceThpt(i, !fullUpdate);
  }
}

/* ******************************* */

/* Check if a host can be potentially added the host matrix */
int isMatrixHost(HostTraffic *host, int actualDeviceId) {
  if((deviceLocalAddress(&host->hostIpAddress, actualDeviceId) || multicastHost(host))
     && (!broadcastHost(host)))
    return(1);
  else
    return(0);
}

/* ******************************* */

unsigned int matrixHostHash(HostTraffic *host, int actualDeviceId, int rehash) {
  unsigned long hash;
  char tmpBuf[80], *str;
  int c;

  if(myGlobals.device[actualDeviceId].numHosts  == 0) return(0);

  if (host->l2Family == FLAG_HOST_TRAFFIC_AF_ETH) {
    if (host->hostIpAddress.hostFamily == AF_INET)
      hash = host->hostIp4Address.s_addr;
#ifdef INET6
    else if (host->hostIpAddress.hostFamily == AF_INET6)
      hash = *(u_int32_t *)&host->hostIp6Address.s6_addr[0];
#endif
  }
  else {
    if (host->fcCounters->vsanId) {
      hash ^= host->fcCounters->vsanId;
      hash ^= host->fcCounters->hostFcAddress.domain;
      hash ^= host->fcCounters->hostFcAddress.area;
      hash ^= host->fcCounters->hostFcAddress.port;
      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof (tmpBuf), "%x.%x.%x.%x.%x", host->fcCounters->vsanId, 
		  host->fcCounters->hostFcAddress.domain, host->fcCounters->hostFcAddress.area,
		  host->fcCounters->hostFcAddress.port, hash);
    } else {
      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof (tmpBuf), "%x.%x.%x.%x",
		   host->fcCounters->hostFcAddress.domain, host->fcCounters->hostFcAddress.area,
		   host->fcCounters->hostFcAddress.port, host);
    }
    str = tmpBuf;
	
    /* sdbm hash algorithm */
    hash = 0;
    while (c = *str++) {
      hash = c + (hash << 6) + (hash << 16) - hash;
    }

    /* Assuming that the numHosts for FC is always 1024, 1021 is nearest
     * prime */
    if (rehash) {
      c = (5 - hash%5);
      hash += c;
    }
  }
    
  return((unsigned int)(hash) % myGlobals.device[actualDeviceId].numHosts);
}

/* ******************************* */

void updateTrafficMatrix(HostTraffic *srcHost,
			 HostTraffic *dstHost,
			 TrafficCounter length, 
			 int actualDeviceId) {

  if(myGlobals.device[actualDeviceId].numHosts == 0) return;
  
  if(isMatrixHost(srcHost, actualDeviceId) 
     && isMatrixHost(dstHost, actualDeviceId)) {
    unsigned int a, b, id;    
    
    a = matrixHostHash(srcHost, actualDeviceId, 0), b = matrixHostHash(dstHost, actualDeviceId, 0);

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

void updateFcTrafficMatrix(HostTraffic *srcHost,
			 HostTraffic *dstHost,
			 TrafficCounter length, 
			   int actualDeviceId) {
  unsigned int a, b, id;

  a = matrixHostHash (srcHost, actualDeviceId, 0);
  b = matrixHostHash (dstHost, actualDeviceId, 0);

  if ((myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[a] != NULL) &&
      (myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[a] != srcHost)) {
    myGlobals.fcMatrixHashCollisions++;
    a = matrixHostHash (srcHost, actualDeviceId, 1);
    if ((myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[a] != NULL) &&
	(myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[a] != srcHost)) {
      traceEvent (CONST_TRACE_WARNING, "Unable to resolve conflict in matrix host hash for %s with %s\n",
		  myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[a]->fcCounters->hostNumFcAddress,
		  srcHost->fcCounters->hostNumFcAddress);
      myGlobals.fcMatrixHashUnresCollisions++;
      return;
    }
  }

  if ((myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[b] != NULL) &&
      (myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[b] != dstHost)) {
    myGlobals.fcMatrixHashCollisions++;
    b = matrixHostHash (dstHost, actualDeviceId, 1);
    if ((myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[b] != NULL) &&
	(myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[b] != dstHost)) {
      traceEvent (CONST_TRACE_WARNING, "Unable to resolve conflict in matrix host hash for %s with %s\n",
		  myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[b]->fcCounters->hostNumFcAddress,
		  dstHost->fcCounters->hostNumFcAddress);
      myGlobals.fcMatrixHashUnresCollisions++;
      return;
    }
  }
    
  myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[a] = srcHost, 
    myGlobals.device[actualDeviceId].fcTrafficMatrixHosts[b] = dstHost;

  id = a*myGlobals.device[actualDeviceId].numHosts+b;
  if (myGlobals.device[actualDeviceId].fcTrafficMatrix[id] == NULL) {
    myGlobals.device[actualDeviceId].fcTrafficMatrix[id] = (TrafficEntry*)calloc(1, sizeof(TrafficEntry));
    myGlobals.device[actualDeviceId].fcTrafficMatrix[id]->vsanId = srcHost->fcCounters->vsanId;
  }
    
  incrementTrafficCounter(&myGlobals.device[actualDeviceId].fcTrafficMatrix[id]->bytesSent, length.value);
  incrementTrafficCounter(&myGlobals.device[actualDeviceId].fcTrafficMatrix[id]->pktsSent, 1);

  id = b*myGlobals.device[actualDeviceId].numHosts+a;
  if(myGlobals.device[actualDeviceId].fcTrafficMatrix[id] == NULL) {
    myGlobals.device[actualDeviceId].fcTrafficMatrix[id] = (TrafficEntry*)calloc(1, sizeof(TrafficEntry));
    myGlobals.device[actualDeviceId].fcTrafficMatrix[id]->vsanId = dstHost->fcCounters->vsanId;
  }
    
  incrementTrafficCounter(&myGlobals.device[actualDeviceId].fcTrafficMatrix[id]->bytesRcvd, length.value);
  incrementTrafficCounter(&myGlobals.device[actualDeviceId].fcTrafficMatrix[id]->pktsRcvd, 1);
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
