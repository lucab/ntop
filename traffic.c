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

  /* We're never check enough... */
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
    memcpy(&device[deviceToUpdate].last60MinutesThpt[i+1],
	   &device[deviceToUpdate].last60MinutesThpt[i], sizeof(ThptEntry));

  device[deviceToUpdate].last60MinutesThpt[0].trafficValue = device[deviceToUpdate].lastMinThpt;

  traceEvent(TRACE_INFO, "LastMinThpt: ", formatThroughput(device[deviceToUpdate].lastMinThpt));

  device[deviceToUpdate].last60MinutesThpt[0].topHostSentIdx = topSentIdx,
    device[deviceToUpdate].last60MinutesThpt[0].topSentTraffic = 
    device[deviceToUpdate].hash_hostTraffic[topSentIdx]->actualSentThpt;
  device[deviceToUpdate].last60MinutesThpt[0].secondHostSentIdx = secondSentIdx,
    device[deviceToUpdate].last60MinutesThpt[0].secondSentTraffic = 
    device[deviceToUpdate].hash_hostTraffic[secondSentIdx]->actualSentThpt;
  device[deviceToUpdate].last60MinutesThpt[0].thirdHostSentIdx = thirdSentIdx,
    device[deviceToUpdate].last60MinutesThpt[0].thirdSentTraffic = 
    device[deviceToUpdate].hash_hostTraffic[thirdSentIdx]->actualSentThpt;

  device[deviceToUpdate].last60MinutesThpt[0].topHostRcvdIdx = topRcvdIdx,
    device[deviceToUpdate].last60MinutesThpt[0].topRcvdTraffic = 
    device[deviceToUpdate].hash_hostTraffic[topRcvdIdx]->actualRcvdThpt;
  device[deviceToUpdate].last60MinutesThpt[0].secondHostRcvdIdx = secondRcvdIdx,
    device[deviceToUpdate].last60MinutesThpt[0].secondRcvdTraffic = 
    device[deviceToUpdate].hash_hostTraffic[secondRcvdIdx]->actualRcvdThpt;
  device[deviceToUpdate].last60MinutesThpt[0].thirdHostRcvdIdx = thirdRcvdIdx,
    device[deviceToUpdate].last60MinutesThpt[0].thirdRcvdTraffic = 
    device[deviceToUpdate].hash_hostTraffic[thirdRcvdIdx]->actualRcvdThpt;

  device[deviceToUpdate].last60MinutesThptIdx = (device[deviceToUpdate].last60MinutesThptIdx+1) % 60;

  if(topHourSentIdx != NO_PEER) { /* It wrapped -> 1 hour is over */
    float average=0;
    int i;

    if(topHourSentIdx == NO_PEER) return;
    if(topHourRcvdIdx == NO_PEER) return;
    if(secondHourSentIdx == NO_PEER) secondHourSentIdx = 0;
    if(thirdHourSentIdx == NO_PEER)  thirdHourSentIdx = 0;
    if(secondHourRcvdIdx == NO_PEER) secondHourRcvdIdx = 0;
    if(thirdHourRcvdIdx == NO_PEER)  thirdHourRcvdIdx = 0;

    for(i=0; i<60; i++) {
      average += device[deviceToUpdate].last60MinutesThpt[i].trafficValue;
    }

    average /= 60;

    for(i=22; i>=0; i--)
      memcpy(&device[deviceToUpdate].last24HoursThpt[i+1], 
	     &device[deviceToUpdate].last24HoursThpt[i], sizeof(ThptEntry));

    device[deviceToUpdate].last24HoursThpt[0].trafficValue = average;

    device[deviceToUpdate].last24HoursThpt[0].topHostSentIdx = topHourSentIdx,
      device[deviceToUpdate].last24HoursThpt[0].topSentTraffic = 
      device[deviceToUpdate].hash_hostTraffic[topHourSentIdx]->lastHourSentThpt;
    device[deviceToUpdate].last24HoursThpt[0].secondHostSentIdx = secondHourSentIdx,
      device[deviceToUpdate].last24HoursThpt[0].secondSentTraffic = 
      device[deviceToUpdate].hash_hostTraffic[secondHourSentIdx]->lastHourSentThpt;
    device[deviceToUpdate].last24HoursThpt[0].thirdHostSentIdx = thirdHourSentIdx,
      device[deviceToUpdate].last24HoursThpt[0].thirdSentTraffic = 
      device[deviceToUpdate].hash_hostTraffic[thirdHourSentIdx]->lastHourSentThpt;

    device[deviceToUpdate].last24HoursThpt[0].topHostRcvdIdx = topHourRcvdIdx,
      device[deviceToUpdate].last24HoursThpt[0].topRcvdTraffic = 
      device[deviceToUpdate].hash_hostTraffic[topHourRcvdIdx]->lastHourRcvdThpt;
    device[deviceToUpdate].last24HoursThpt[0].secondHostRcvdIdx = secondHourRcvdIdx,
      device[deviceToUpdate].last24HoursThpt[0].secondRcvdTraffic = 
      device[deviceToUpdate].hash_hostTraffic[secondHourRcvdIdx]->lastHourRcvdThpt;
    device[deviceToUpdate].last24HoursThpt[0].thirdHostRcvdIdx = thirdHourRcvdIdx,
      device[deviceToUpdate].last24HoursThpt[0].thirdRcvdTraffic = 
      device[deviceToUpdate].hash_hostTraffic[thirdHourRcvdIdx]->lastHourRcvdThpt;

    device[deviceToUpdate].last24HoursThptIdx = 
      (device[deviceToUpdate].last24HoursThptIdx + 1) % 24;

    if(device[deviceToUpdate].last24HoursThptIdx == 0) {
      average=0;

      for(i=0; i<24; i++) {
	average += device[deviceToUpdate].last24HoursThpt[i].trafficValue;
      }

      average /= 24;

      for(i=28; i>=0; i--) {
	device[deviceToUpdate].last30daysThpt[i+1] = 
	  device[deviceToUpdate].last30daysThpt[i];
      }

      device[deviceToUpdate].last30daysThpt[0] = average;
      device[deviceToUpdate].last30daysThptIdx = 
	(device[deviceToUpdate].last30daysThptIdx + 1) % 30;
    }
  }

  device[deviceToUpdate].numThptSamples++;
  
#ifdef DEBUG
  traceEvent(TRACE_INFO, "updateThptStats() completed.\n");
#endif
}

/* ******************************* */

static void updateDeviceThpt(int deviceToUpdate) {
  time_t timeDiff, timeMinDiff, timeHourDiff=0, totalTime;
  u_int idx;
  HostTraffic *el;

  timeDiff = actTime-device[deviceToUpdate].lastThptUpdate;

  if(timeDiff > 10 /* secs */) {
    u_int topSentIdx=NO_PEER, secondSentIdx=NO_PEER, thirdSentIdx=NO_PEER;
    u_int topHourSentIdx=NO_PEER, secondHourSentIdx=NO_PEER, thirdHourSentIdx=NO_PEER;
    u_int topRcvdIdx=NO_PEER, secondRcvdIdx=NO_PEER, thirdRcvdIdx=NO_PEER;
    u_int topHourRcvdIdx=NO_PEER, secondHourRcvdIdx=NO_PEER, thirdHourRcvdIdx=NO_PEER;
    short updateMinThpt, updateHourThpt;
    
    totalTime = actTime-initialSniffTime;

    updateHourThpt = 0;
    updateMinThpt = 0;

    if((timeMinDiff = actTime-device[deviceToUpdate].lastMinThptUpdate) >= 60 /* 1 minute */) {
      updateMinThpt = 1;
      device[deviceToUpdate].lastMinThptUpdate = actTime;
      if((timeHourDiff = actTime-device[deviceToUpdate].lastHourThptUpdate) >= 60*60 /* 1 hour */) {
	updateHourThpt = 1;
	device[deviceToUpdate].lastHourThptUpdate = actTime;
      }
    }

    for(idx=1; idx<device[deviceToUpdate].actualHashSize; idx++) {
      if((el = device[deviceToUpdate].hash_hostTraffic[idx]) != NULL) {

	if(broadcastHost(el))
	  continue;

	el->actualRcvdThpt    = (float)(el->bytesReceived-el->lastBytesReceived)/timeDiff;
	if(el->peakRcvdThpt   < el->actualRcvdThpt) el->peakRcvdThpt = el->actualRcvdThpt;
	if(el->peakSentThpt   < el->actualSentThpt) el->peakSentThpt = el->actualSentThpt;
	el->actualSentThpt    = (float)(el->bytesSent-el->lastBytesSent)/timeDiff;
	el->lastBytesSent     = el->bytesSent;
	el->lastBytesReceived = el->bytesReceived;

	/* ******************************** */

	el->actualRcvdPktThpt  = (float)(el->pktReceived-el->lastPktReceived)/timeDiff;
	if(el->peakRcvdPktThpt < el->actualRcvdPktThpt) el->peakRcvdPktThpt = el->actualRcvdPktThpt;
	if(el->peakSentPktThpt < el->actualSentPktThpt) el->peakSentPktThpt = el->actualSentPktThpt;
	el->actualSentPktThpt  = (float)(el->pktSent-el->lastPktSent)/timeDiff;
	el->lastPktSent        = el->pktSent;
	el->lastPktReceived    = el->pktReceived;

	/* ******************************** */

	if(updateMinThpt) {
	  el->averageRcvdThpt = ((float)el->bytesReceived)/totalTime;
	  el->averageSentThpt = ((float)el->bytesSent)/totalTime;
	  el->averageRcvdPktThpt = ((float)el->pktReceived)/totalTime;
	  el->averageSentPktThpt = ((float)el->pktSent)/totalTime;

	  if(topSentIdx == NO_PEER) {
	    topSentIdx = idx;
	  } else {
	    if(el->actualSentThpt > device[deviceToUpdate].hash_hostTraffic[topSentIdx]->actualSentThpt) {
	      secondSentIdx = topSentIdx;
	      topSentIdx = idx;
	    } else {
	      if(secondSentIdx == NO_PEER)
		secondSentIdx = idx;
	      else {
		if(el->actualSentThpt > device[deviceToUpdate].hash_hostTraffic[secondSentIdx]->actualSentThpt) {
		  thirdSentIdx = secondSentIdx;
		  secondSentIdx = idx;
		} else {
		  if(thirdSentIdx == NO_PEER)
		    thirdSentIdx = idx;
		  else {
		    if(el->actualSentThpt > device[deviceToUpdate].hash_hostTraffic[thirdSentIdx]->actualSentThpt) {
		      thirdSentIdx = idx;
		    }
		  }
		}
	      }
	    }
	  }

	  if(topRcvdIdx == NO_PEER) {
	    topRcvdIdx = idx;
	  } else {
	    if(el->actualRcvdThpt > device[deviceToUpdate].hash_hostTraffic[topRcvdIdx]->actualRcvdThpt) {
	      secondRcvdIdx = topRcvdIdx;
	      topRcvdIdx = idx;
	    } else {
	      if(secondRcvdIdx == NO_PEER)
		secondRcvdIdx = idx;
	      else {
		if(el->actualRcvdThpt > device[deviceToUpdate].hash_hostTraffic[secondRcvdIdx]->actualRcvdThpt) {
		  thirdRcvdIdx = secondRcvdIdx;
		  secondRcvdIdx = idx;
		} else {
		  if(thirdRcvdIdx == NO_PEER)
		    thirdRcvdIdx = idx;
		  else {
		    if(el->actualRcvdThpt > device[deviceToUpdate].hash_hostTraffic[thirdRcvdIdx]->actualRcvdThpt) {
		      thirdRcvdIdx = idx;
		    }
		  }
		}
	      }
	    }
	  }

	  if(updateHourThpt) {
	    el->lastHourRcvdThpt = (float)(el->bytesReceived-el->lastHourBytesReceived)/timeHourDiff;
	    el->lastHourSentThpt = (float)(el->bytesSent-el->lastHourBytesSent)/timeHourDiff;
	    el->lastHourBytesReceived = el->bytesReceived;
	    el->lastHourBytesSent = el->bytesSent;

	    if(topHourSentIdx == NO_PEER) {
	      topHourSentIdx = idx;
	    } else {
	      if(el->lastHourSentThpt > device[deviceToUpdate].hash_hostTraffic[topHourSentIdx]->lastHourSentThpt) {
		secondHourSentIdx = topHourSentIdx;
		topHourSentIdx = idx;
	      } else {
		if(secondHourSentIdx == NO_PEER)
		  secondHourSentIdx = idx;
		else {
		  if(el->lastHourSentThpt > device[deviceToUpdate].hash_hostTraffic[secondHourSentIdx]->lastHourSentThpt) {
		    thirdHourSentIdx = secondHourSentIdx;
		    secondHourSentIdx = idx;
		  } else {
		    if(thirdHourSentIdx == NO_PEER)
		      thirdHourSentIdx = idx;
		    else {
		      if(el->lastHourSentThpt > device[deviceToUpdate].hash_hostTraffic[thirdHourSentIdx]->lastHourSentThpt) {
			thirdHourSentIdx = idx;
		      }
		    }
		  }
		}
	      }
	    }

	    if(topHourRcvdIdx == NO_PEER) {
	      topHourRcvdIdx = idx;
	    } else {
	      if(el->lastHourRcvdThpt > device[deviceToUpdate].hash_hostTraffic[topHourRcvdIdx]->lastHourRcvdThpt) {
		secondHourRcvdIdx = topHourRcvdIdx;
		topHourRcvdIdx = idx;
	      } else {
		if(secondHourRcvdIdx == NO_PEER)
		  secondHourRcvdIdx = idx;
		else {
		  if(el->lastHourRcvdThpt > device[deviceToUpdate].hash_hostTraffic[secondHourRcvdIdx]->lastHourRcvdThpt) {
		    thirdHourRcvdIdx = secondHourRcvdIdx;
		    secondHourRcvdIdx = idx;
		  } else {
		    if(thirdHourRcvdIdx == NO_PEER)
		      thirdHourRcvdIdx = idx;
		    else {
		      if(el->lastHourRcvdThpt > device[deviceToUpdate].hash_hostTraffic[thirdHourRcvdIdx]->lastHourRcvdThpt) {
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

    device[deviceToUpdate].throughput =
      device[deviceToUpdate].ethernetBytes-device[deviceToUpdate].throughput;
    device[deviceToUpdate].packetThroughput = device[deviceToUpdate].ethernetPkts-
      device[deviceToUpdate].lastNumEthernetPkts;
    device[deviceToUpdate].lastNumEthernetPkts = device[deviceToUpdate].ethernetPkts;

    /* timeDiff++; */
    device[deviceToUpdate].actualThpt = (float)device[deviceToUpdate].throughput/(float)timeDiff;
    device[deviceToUpdate].actualPktsThpt = 
      (float)device[deviceToUpdate].packetThroughput/(float)timeDiff;

    if(device[deviceToUpdate].actualThpt > device[deviceToUpdate].peakThroughput)
      device[deviceToUpdate].peakThroughput = device[deviceToUpdate].actualThpt;

    if(device[deviceToUpdate].actualPktsThpt > device[deviceToUpdate].peakPacketThroughput)
      device[deviceToUpdate].peakPacketThroughput = device[deviceToUpdate].actualPktsThpt;

    device[deviceToUpdate].throughput = device[deviceToUpdate].ethernetBytes;
    device[deviceToUpdate].packetThroughput = device[deviceToUpdate].ethernetPkts;

    if(updateMinThpt) {
      device[deviceToUpdate].lastMinEthernetBytes = device[deviceToUpdate].ethernetBytes-
	device[deviceToUpdate].lastMinEthernetBytes;
      device[deviceToUpdate].lastMinThpt = 
	(float)(device[deviceToUpdate].lastMinEthernetBytes)/(float)timeMinDiff;
      device[deviceToUpdate].lastMinEthernetBytes = device[deviceToUpdate].ethernetBytes;
      /* ******************* */
      device[deviceToUpdate].lastMinEthernetPkts = device[deviceToUpdate].ethernetPkts-
	device[deviceToUpdate].lastMinEthernetPkts;
      device[deviceToUpdate].lastMinPktsThpt = 
	(float)device[deviceToUpdate].lastMinEthernetPkts/(float)timeMinDiff;
      device[deviceToUpdate].lastMinEthernetPkts = device[deviceToUpdate].ethernetPkts;
      device[deviceToUpdate].lastMinThptUpdate = actTime;
    }

    if((timeMinDiff = actTime-device[deviceToUpdate].lastFiveMinsThptUpdate) > 300 /* 5 minutes */) {
      device[deviceToUpdate].lastFiveMinsEthernetBytes = 
	device[deviceToUpdate].ethernetBytes - device[deviceToUpdate].lastFiveMinsEthernetBytes;
      device[deviceToUpdate].lastFiveMinsThptUpdate = timeMinDiff;
      device[deviceToUpdate].lastFiveMinsThpt = 
	(float)device[deviceToUpdate].lastFiveMinsEthernetBytes/(float)device[deviceToUpdate].lastFiveMinsThptUpdate;
      device[deviceToUpdate].lastFiveMinsEthernetBytes = device[deviceToUpdate].ethernetBytes;
      /* ******************* */
      device[deviceToUpdate].lastFiveMinsEthernetPkts = 
	device[deviceToUpdate].ethernetPkts - device[deviceToUpdate].lastFiveMinsEthernetPkts;
      device[deviceToUpdate].lastFiveMinsPktsThpt = 
	(float)device[deviceToUpdate].lastFiveMinsEthernetPkts/(float)device[deviceToUpdate].lastFiveMinsThptUpdate;
      device[deviceToUpdate].lastFiveMinsEthernetPkts = device[deviceToUpdate].ethernetPkts;
      device[deviceToUpdate].lastFiveMinsThptUpdate = actTime;
    }

    if((updateMinThpt || updateHourThpt) 
       && ((topSentIdx    != NO_PEER) 
	   || (topHourSentIdx != NO_PEER)
	   || (topRcvdIdx     != NO_PEER)
	   || (topHourRcvdIdx != NO_PEER)))
      updateThptStats(deviceToUpdate,
		      topSentIdx, secondSentIdx, thirdSentIdx,
		      topHourSentIdx, secondHourSentIdx, thirdHourSentIdx,
		      topRcvdIdx, secondRcvdIdx, thirdRcvdIdx,
		      topHourRcvdIdx, secondHourRcvdIdx, thirdHourRcvdIdx);

    device[deviceToUpdate].lastThptUpdate = actTime;
  }
}

/* ******************************* */

void updateThpt(void) {
  int i;

  if(mergeInterfaces)
    updateDeviceThpt(0);
  else {
    for(i=0; i<numDevices; i++)
      updateDeviceThpt(i);  
  }
}

/* ******************************* */

static void updateHostThpt(HostTraffic *el, int hourId) {

  if(broadcastHost(el))
    return;
  
  el->lastCounterBytesSent = el->bytesSent;
  el->lastCounterBytesRcvd = el->bytesReceived;

  if(hourId == 0) {
    el->lastDayBytesSent = el->bytesSent;
      el->lastDayBytesRcvd = el->bytesReceived;
  }
}

/* ******************************* */

static void updateHostsDeviceThpt(int deviceToUpdate, int hourId) {
  u_int idx;
  HostTraffic *el;
  
  for(idx=1; idx<device[deviceToUpdate].actualHashSize; idx++) {
    if((el = device[deviceToUpdate].hash_hostTraffic[idx]) != NULL) {
      updateHostThpt(el, hourId);
    }
  }
}

/* ******************************* */

void updateHostTrafficStatsThpt(int hourId) {
  int i;

  if(mergeInterfaces)
    updateHostsDeviceThpt(0, hourId);
  else {
    for(i=0; i<numDevices; i++)
      updateHostsDeviceThpt(i, hourId);  
  }
}

/* ******************************* */

void updateTrafficMatrix(HostTraffic *srcHost,
			 HostTraffic *dstHost,
			 TrafficCounter length) {
  if(subnetLocalHost(srcHost) && subnetLocalHost(dstHost)) {
    unsigned long a = (unsigned long)(srcHost->hostIpAddress.s_addr) % 256 /* C-class */;
    unsigned long b = (unsigned long)(dstHost->hostIpAddress.s_addr) % 256 /* C-class */;

    ipTrafficMatrixHosts[a] = srcHost, ipTrafficMatrixHosts[b] = dstHost;
    ipTrafficMatrix[a][b].bytesSent += length,
      ipTrafficMatrix[b][a].bytesReceived += length;
  }
}

/* *********************************** */

void updateDbHostsTraffic(int deviceToUpdate) {
  u_int i;
  HostTraffic *el;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "updateDbHostsTraffic()\n");
#endif

  for(i=0; i<device[deviceToUpdate].actualHashSize; i++) {
    el = device[deviceToUpdate].hash_hostTraffic[i]; /* (**) */

    if((el != NULL)
       && (!broadcastHost(el))
       && (el->nextDBupdate < actTime)) {

      el->instanceInUse++;

      if(el->nextDBupdate == 0)
	notifyHostCreation(el);
      else if(el->nextDBupdate < actTime) {
	updateHostTraffic(el);
	if(el->osName == NULL) {
	  updateOSName(el);
	}
      }

      el->nextDBupdate = actTime + DB_TIMEOUT_REFRESH_TIME;
      el->instanceInUse--;
    }
  }
}

