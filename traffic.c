/*
 *  Copyright (C) 1998-2012 Luca Deri <deri@ntop.org>
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

static u_int8_t are_communities_defined = 0;

/* ******************************* */

static void dumpTopTalkers(time_t when, TopTalkers *lastMinTalkers) {
  datum data_data, key_data;

  // FIX - Implement periodic serial purging

  key_data.dptr = (char*)&when, key_data.dsize = sizeof(time_t);
  data_data.dptr = (char*)lastMinTalkers, data_data.dsize = sizeof(TopTalkers);

  if(gdbm_store(myGlobals.topTalkersFile, key_data, data_data, GDBM_REPLACE) != 0)
    traceEvent(CONST_TRACE_ERROR, "While adding top talkers at time %u", (unsigned int)when);
}

/* ******************************* */

static void updateThptStats(time_t when,
			    int deviceToUpdate,
			    TopTalkers *lastMinTalkers,
			    TopTalkers *lastHourTalkers) {
  int i;

#ifdef DEBUG
  char formatBuf[32];
#endif

  /*
    if(myGlobals.device[deviceToUpdate].dummyDevice)
    return;
  */

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "updateThptStats(%u, %d)", (unsigned int)myGlobals.actTime, deviceToUpdate);
#endif

  /* Shift */
  for(i=58; i>=0; i--)
    memcpy(&myGlobals.device[deviceToUpdate].last60MinTopTalkers[i+1],
	   &myGlobals.device[deviceToUpdate].last60MinTopTalkers[i], sizeof(TopTalkers));

  /* Copy value */
  memcpy(&myGlobals.device[deviceToUpdate].last60MinTopTalkers[0], lastMinTalkers, sizeof(TopTalkers));

  if(!emptySerial(&lastHourTalkers[0].senders[0].hostSerial)) {
    /* Shift */
    for(i=22; i>=0; i--)
      memcpy(&myGlobals.device[deviceToUpdate].last24HoursTopTalkers[i+1],
	     &myGlobals.device[deviceToUpdate].last24HoursTopTalkers[i], sizeof(TopTalkers));
    
    /* Copy value */
    memcpy(&myGlobals.device[deviceToUpdate].last24HoursTopTalkers[0], lastHourTalkers, sizeof(TopTalkers));
  }

  myGlobals.device[deviceToUpdate].numThptSamples++;
  
  /* Dump thpt stats on disk */
  dumpTopTalkers(when, lastMinTalkers);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "updateThptStats() completed.");
#endif
}

/* ******************************* */

/* talkers = HostTalker[MAX_NUM_TOP_TALKERS] */
static void updateTopThptDirection(HostTalker *talkers, 
				   HostSerialIndex serialHostIndex, 
				   float bps) {
  int i, j;

  if(talkers[MAX_NUM_TOP_TALKERS-1].bps > bps) 
    return; /* We're not a top talker */

  for(i=0; i<MAX_NUM_TOP_TALKERS; i++) {
    if(talkers[i].hostSerial == serialHostIndex) {
      if(talkers[i].bps < bps) talkers[i].bps = bps;
      break;
    }

    if(talkers[i].bps < bps) {
      /* 1 - shift other values down */
      if(talkers[i].hostSerial != UNKNOWN_SERIAL_INDEX) {
	for(j=MAX_NUM_TOP_TALKERS-1; j>i; j--)
	  talkers[j].hostSerial = talkers[j-1].hostSerial, talkers[j].bps = talkers[j-1].bps;	
      }

      /* 2 - set the value at slot i */
      talkers[i].hostSerial = serialHostIndex, talkers[i].bps = bps;
      break;
    }
  }
}

/* ******************************* */

static void updateTopThpt(TopTalkers *talkers, 
			  HostSerialIndex serialHostIndex, 
			  float sentBps, float rcvdBps) {
  if(serialHostIndex == UNKNOWN_SERIAL_INDEX) return;

  updateTopThptDirection((HostTalker*)&talkers->senders, serialHostIndex, sentBps);
  updateTopThptDirection((HostTalker*)&talkers->receivers, serialHostIndex, rcvdBps);
}

/* ******************************* */

void updateDeviceThpt(int deviceToUpdate, int quickUpdate) {
  int i;
  time_t timeDiff, timeMinDiff, timeHourDiff=0, totalTime, when;
  HostTraffic *el;
  short updateMinThpt=0, updateHourThpt=0;
  TopTalkers lastMinTalkers, lastHourTalkers;

  timeDiff = myGlobals.actTime-myGlobals.device[deviceToUpdate].lastThptUpdate;
  if(timeDiff < 10 /* secs */) return;

  when = myGlobals.actTime + 60;
  when -= (when % 60);
  
  /* ******************************** */
  
  memset(&lastMinTalkers, 0, sizeof(lastMinTalkers));
  memset(&lastHourTalkers, 0, sizeof(lastHourTalkers));

  for(i=0; i<MAX_NUM_TOP_TALKERS; i++) {
    setEmptySerial(&lastMinTalkers.senders[i].hostSerial);
    setEmptySerial(&lastHourTalkers.senders[i].hostSerial);
  }

  lastMinTalkers.when = lastHourTalkers.when = when;

  /* ******************************** */

  myGlobals.device[deviceToUpdate].throughput =
    (float)(myGlobals.device[deviceToUpdate].ethernetBytes.value - myGlobals.device[deviceToUpdate].throughput);
  myGlobals.device[deviceToUpdate].packetThroughput = (float)(myGlobals.device[deviceToUpdate].ethernetPkts.value -
							      myGlobals.device[deviceToUpdate].lastNumEthernetPkts.value);
  myGlobals.device[deviceToUpdate].lastNumEthernetPkts = myGlobals.device[deviceToUpdate].ethernetPkts;

  /* timeDiff++; */
  myGlobals.device[deviceToUpdate].actualThpt = (float)myGlobals.device[deviceToUpdate].throughput/(float)timeDiff;
  myGlobals.device[deviceToUpdate].actualPktsThpt =
    (float)myGlobals.device[deviceToUpdate].packetThroughput/(float)timeDiff;

  if(myGlobals.device[deviceToUpdate].actualThpt > myGlobals.device[deviceToUpdate].peakThroughput)
    myGlobals.device[deviceToUpdate].peakThroughput = myGlobals.device[deviceToUpdate].actualThpt;

  if(myGlobals.device[deviceToUpdate].actualPktsThpt > myGlobals.device[deviceToUpdate].peakPacketThroughput)
    myGlobals.device[deviceToUpdate].peakPacketThroughput = myGlobals.device[deviceToUpdate].actualPktsThpt;

  myGlobals.device[deviceToUpdate].throughput = (float)myGlobals.device[deviceToUpdate].ethernetBytes.value;
  myGlobals.device[deviceToUpdate].packetThroughput = (float)myGlobals.device[deviceToUpdate].ethernetPkts.value;

  if((timeMinDiff = myGlobals.actTime-myGlobals.device[deviceToUpdate].lastMinThptUpdate) >= 60 /* 1 minute */) {
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

  if((timeMinDiff = myGlobals.actTime-myGlobals.device[deviceToUpdate].lastFiveMinsThptUpdate) >= 300 /* 5 minutes */) {
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

  totalTime = myGlobals.actTime-myGlobals.initialSniffTime;

  if((timeHourDiff = myGlobals.actTime-myGlobals.device[deviceToUpdate].lastHourThptUpdate) >= 3600 /* 1 hour */) {
    updateHourThpt = 1;
    myGlobals.device[deviceToUpdate].lastHourThptUpdate = myGlobals.actTime;
  }

  /*
    By the time we update the throughtput we keep a list of top hosts
    senders/receivers that we'll use for top talkers statistics
  */

  for(el = getFirstHost(deviceToUpdate); el != NULL; el = getNextHost(deviceToUpdate, el)) {
    if(broadcastHost(el)) continue;

    /* We just care of L3 only for the time being */
    if(el->l2Host) continue;

    el->actualRcvdThpt = (float)((el->bytesRcvd.value-el->lastBytesRcvd.value)/timeDiff);
    if(el->peakRcvdThpt < el->actualRcvdThpt) el->peakRcvdThpt = el->actualRcvdThpt;
    el->actualSentThpt = (float)((el->bytesSent.value-el->lastBytesSent.value)/timeDiff);
    if(el->peakSentThpt < el->actualSentThpt) el->peakSentThpt = el->actualSentThpt;
    el->actualThpt = (float)((el->bytesRcvd.value-el->lastBytesRcvd.value + el->bytesSent.value-el->lastBytesSent.value)/timeDiff);
    if(el->peakThpt < el->actualThpt) el->peakThpt = el->actualThpt;
    el->lastBytesSent = el->bytesSent, el->lastBytesRcvd = el->bytesRcvd;

    /* ******************************** */

    /* 1 Minute Throughput */
    if(updateMinThpt) {
      el->averageRcvdThpt = (float)(((float)el->bytesRcvdSession.value)/totalTime);
      el->averageSentThpt = (float)(((float)el->bytesSentSession.value)/totalTime);

      updateTopThpt(&lastMinTalkers, el->serialHostIndex, el->averageSentThpt, el->averageRcvdThpt);

      /* 1 Hour Throughput */
      if(updateHourThpt) {
	el->lastHourRcvdThpt = (float)((float)(el->bytesRcvd.value-el->lastHourBytesRcvd.value)/timeHourDiff);
	el->lastHourSentThpt = (float)((float)(el->bytesSent.value-el->lastHourBytesSent.value)/timeHourDiff);
	
	el->lastHourBytesRcvd = el->bytesRcvd, el->lastHourBytesSent = el->bytesSent;

	updateTopThpt(&lastHourTalkers, el->serialHostIndex, el->lastHourSentThpt, el->lastHourRcvdThpt);
      }
    }
  }

  if(updateMinThpt || updateHourThpt)
    updateThptStats(when, deviceToUpdate, &lastMinTalkers, &lastHourTalkers);

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

/* ********************************** */

void checkCommunities() {
  datum key, nextkey;
  int len = strlen(COMMUNITY_PREFIX);

  key = gdbm_firstkey(myGlobals.prefsFile);

  while (key.dptr) {
    char val[256];

    if((fetchPrefsValue(key.dptr, val, sizeof(val)) == 0)
       && (!strncmp(key.dptr, COMMUNITY_PREFIX, len))) {
      free(key.dptr);
      are_communities_defined = 1;
      return;
    }

    nextkey = gdbm_nextkey(myGlobals.prefsFile, key);
    free (key.dptr);
    key = nextkey;
  }

  are_communities_defined = 0;
}

/* ********************************** */

char* findHostCommunity(u_int32_t host_ip, char *buf, u_short buf_len) {
  if(are_communities_defined) {
    datum key, nextkey;
    int len = strlen(COMMUNITY_PREFIX);

    key = gdbm_firstkey(myGlobals.prefsFile);
    while (key.dptr) {
      char val[256], localAddresses[2048], *communityName;
      NetworkStats localNetworks[MAX_NUM_NETWORKS]; /* [0]=network, [1]=mask, [2]=broadcast, [3]=mask_v6 */
      u_short numLocalNetworks = 0, i;

      if((fetchPrefsValue(key.dptr, val, sizeof(val)) == 0)
	 && (!strncmp(key.dptr, COMMUNITY_PREFIX, len))) {
	localAddresses[0] = '\0';
	communityName = (char*)&key.dptr[len];

	handleAddressLists(val, localNetworks, &numLocalNetworks,
			   localAddresses, sizeof(localAddresses),
			   CONST_HANDLEADDRESSLISTS_COMMUNITIES);

	// traceEvent(CONST_TRACE_WARNING, "--> Community %s has %d entries", communityName, numLocalNetworks);
	for(i=0; i<numLocalNetworks; i++) {
	  if((host_ip & localNetworks[i].address[1]) == localNetworks[i].address[0]) {
	    //traceEvent(CONST_TRACE_WARNING, "--> Found community %s [%d]", communityName, numLocalNetworks);
	    snprintf(buf, buf_len, "%s", communityName);
	    return(buf);
	  }
	}
      }

      nextkey = gdbm_nextkey(myGlobals.prefsFile, key);
      free (key.dptr);
      key = nextkey;
    }
  }

  return(NULL);
}

/* ********************************** */

void setHostCommunity(HostTraffic *el) {
  char *community, buf[64];

  if((el == NULL) || (el->hostIpAddress.hostFamily != AF_INET))
    return; /* Only IPv4 is supported */
  else if(el->community != NULL)
    return; /* Already set */

  community = findHostCommunity(el->hostIpAddress.addr._hostIp4Address.s_addr,
				buf, sizeof(buf));

  if(community)
    el->community = strdup(community);
}

/* ********************************** */

u_short isP2P(HostTraffic *a) {
  if((a != NULL)
     && ((a->totContactedSentPeers > CONTACTED_PEERS_THRESHOLD)
	 || (a->totContactedRcvdPeers > CONTACTED_PEERS_THRESHOLD))) {
    /* Now we need to check if this has really been a P2P server */
    int i;

    for(i=0; i<MAX_NUM_RECENT_PORTS; i++) {
      if((a->recentlyUsedServerPorts[i] == -1) || (a->recentlyUsedClientPorts[i] == -1))
	return(0); /* It's just a busy server */
    }

    return(1);
  } else
    return(0);
}

/* ********************************** */

char* httpSiteIcon(char *name, char *buf, u_int buf_len, u_short addName) {
  if(name == NULL)
    return("&nbsp;");
  
  safe_snprintf(__FILE__, __LINE__, buf, buf_len,
		"<IMG width=16 height=16 SRC=\"http://www.google.com/s2/favicons?domain=%s\" BORDER=0>", 
		name);

  return(buf);
}
