/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
 *                          Andrea Bettarini <abettarini@excitecorp.com>
 *
 *  			    Centro SERRA, University of Pisa
 *  			    http://www.ntop.org/
 *
 *     		            Excite Italia
 *  		            http://www.excite.it/
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
#include "remoteInterface.h"
#include "globals-report.h"

extern int webPort; /* main.c */

static pthread_t remIntTreadId;
static int remIntSock, locIntSock;

static void termRemIntFunct() {
  traceEvent(TRACE_INFO, "Thanks for using ntop Remote Interface..."); fflush(stdout);

  if(remIntSock > 0) {
    closeNwSocket(&remIntSock);
    remIntSock = 0;
  }
  if(locIntSock > 0) {
    closeNwSocket(&locIntSock);
    locIntSock = 0;
  }
  traceEvent(TRACE_INFO, "Done.\n"); fflush(stdout);
}

/* ****************************** */

void returnHostEntry(HostTraffic* theHost, char* udpBuf) {
  char theTime[64];

  char buf1[384], buf2[384], buf3[384], buf4[384];

  if(theHost == NULL) {
    snprintf(udpBuf, sizeof(udpBuf), "%s\n", EMPTY_SLOT_RC);
    return;    
  }

  strncpy(theTime, ctime(&theHost->lastSeen), sizeof(theTime));
  theTime[strlen(theTime)-1] = '\0';

  snprintf(buf1, sizeof(buf1), "%s\t" /* Return code */
	  "%s\t%s\t"
	  "%s\t%s\t"
	  "%s\t"
	  "%d\t%s\t%s\t" /* NetBIOS */
	  "%d\t%d\t%s\t" /* AppleTalk */
	  "%d\t%s\t",     /* IPX */
	  OK_RC, theTime,
	  (theHost->ethAddressString != NULL)? theHost->ethAddressString : "",
	  theHost->hostNumIpAddress, theHost->hostSymIpAddress, 
	  (theHost->osName != NULL)? theHost->osName : "",

	  (int)theHost->nbNodeType,
	  ((theHost->nbHostName != NULL)? theHost->nbHostName : ""),
	  ((theHost->nbDomainName != NULL)? theHost->nbDomainName : ""),

	  (int)theHost->atNetwork, (int)theHost->atNode, 
	  ((theHost->atNodeName != NULL)? theHost->atNodeName : ""),

	  (int)theHost->ipxNodeType,
	  ((theHost->ipxHostName != NULL)? theHost->ipxHostName : "")
	  );

  snprintf(buf2, sizeof(buf2), 
	  "%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t"
	  "%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t",
	  (unsigned long)theHost->pktSent,
	  (unsigned long)theHost->pktReceived,
	  (unsigned long)theHost->pktBroadcastSent, 
	  (unsigned long)theHost->bytesBroadcastSent,
	  (unsigned long)theHost->pktMulticastSent,
	  (unsigned long)theHost->bytesMulticastSent,
	  (unsigned long)theHost->pktMulticastRcvd,
	  (unsigned long)theHost->bytesMulticastRcvd,
	  (unsigned long)theHost->bytesSent,
	  (unsigned long)theHost->bytesSentLocally, 
	  (unsigned long)theHost->bytesSentRemotely,
	  (unsigned long)theHost->bytesReceived, 
	  (unsigned long)theHost->bytesReceivedLocally,
	  (unsigned long)theHost->bytesReceivedFromRemote);

  snprintf(buf3, sizeof(buf3), "%f\t%f\t%f\t%f\t%f\t%f\t%f\t"
	  "%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t",
	  (float)theHost->actualRcvdThpt,
	  (float)theHost->lastHourRcvdThpt, 
	  (float)theHost->averageRcvdThpt, 
	  (float)theHost->peakRcvdThpt,
	  (float)theHost->actualSentThpt,
	  (float)theHost->lastHourSentThpt, 
	  (float)theHost->averageSentThpt,
	  (float)theHost->peakSentThpt,
	  (float)theHost->actualRcvdPktThpt,
	  (float)theHost->averageRcvdPktThpt,
	  (float)theHost->peakRcvdPktThpt,
	  (float)theHost->actualSentPktThpt,
	  (float)theHost->averageSentPktThpt, 
	  (float)theHost->peakSentPktThpt,
	  (float)theHost->actBandwidthUsage);

  snprintf(buf4, sizeof(buf4),  
	  "%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t"
	  "%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\n",
	  (unsigned long)theHost->ipxSent, 
	  (unsigned long)theHost->ipxReceived,
	  (unsigned long)theHost->osiSent, 
	  (unsigned long)theHost->osiReceived,
	  (unsigned long)theHost->dlcSent, 
	  (unsigned long)theHost->dlcReceived,
	  (unsigned long)theHost->arp_rarpSent, 
	  (unsigned long)theHost->arp_rarpReceived,
	  (unsigned long)theHost->decnetSent,
	  (unsigned long)theHost->decnetReceived,
	  (unsigned long)theHost->appletalkSent, 
	  (unsigned long)theHost->appletalkReceived,
	  (unsigned long)theHost->netbiosSent, 
	  (unsigned long)theHost->netbiosReceived,
	  (unsigned long)theHost->qnxSent, 
	  (unsigned long)theHost->qnxReceived,
	  (unsigned long)theHost->otherSent, 
	  (unsigned long)theHost->otherReceived);


  snprintf(udpBuf, sizeof(udpBuf), "%s%s%s%s", buf1, buf2, buf3, buf4);
}

/* ****************************** */

void returnHostEntryIdx(int idx, char* udpBuf) {
  if((idx < 0) || (idx > device[actualReportDeviceId].actualHashSize)) {
    snprintf(udpBuf, sizeof(udpBuf), "%s\n", OUT_OF_RANGE_RC);
    return;
  }

  returnHostEntry(device[actualReportDeviceId].hash_hostTraffic[idx], udpBuf);
}

/* ****************************** */

#ifdef MULTITHREADED
void* remIntLoop(void* notUsed) {
#ifndef WIN32
  struct sockaddr_un sunix;
  int servlen;
#endif
  struct sockaddr_in sin;
  fd_set mask;
  int topSock, recvIntSock;

  remIntSock = socket(AF_INET, SOCK_DGRAM, 0);
  if (remIntSock < 0) {
    traceEvent(TRACE_INFO, "socket error: %d", errno);
    return(NULL);
  }

  sin.sin_family      = AF_INET;
  sin.sin_port        = htons((unsigned short int)webPort+2);
  sin.sin_addr.s_addr = INADDR_ANY;

  if(bind(remIntSock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    traceEvent(TRACE_INFO, "bind: port %d already in use.\n", webPort);
    closeNwSocket(&remIntSock);
    return(NULL);
  }

#ifndef WIN32
 locIntSock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (locIntSock < 0) {
    traceEvent(TRACE_INFO, "socket error: %d\n", errno);
    return(NULL);
  }

  unlink(NTOP_PATH);

  bzero((char *) &sunix, sizeof(sunix));
  sunix.sun_family      = AF_UNIX;
  strncpy(sunix.sun_path, NTOP_PATH, sizeof(sunix.sun_path));
  servlen = strlen(sunix.sun_path) + sizeof(sunix.sun_family);

  if(bind(locIntSock, (struct sockaddr *)&sunix, servlen) < 0) {
    traceEvent(TRACE_INFO, "remoteInterface [bind: can't bind local address]\n");
    closeNwSocket(&locIntSock);
    return(NULL);
  }
#endif

#ifndef WIN32
  traceEvent(TRACE_INFO, "Remote Interface started [port %d][%s]\n",
	 webPort+2, NTOP_PATH);
#else
  traceEvent(TRACE_INFO, "Remote Interface started [port %d]\n",
	     webPort+2);
#endif

  FD_ZERO(&mask);
  FD_SET((unsigned int)remIntSock, &mask);
  FD_SET((unsigned int)locIntSock, &mask);

  if(remIntSock > locIntSock)
    topSock = remIntSock+1;
  else
    topSock = locIntSock+1;

  while(1) {
    char udpBuf[4096];
    struct sockaddr_in source;
    char *strtokState;

    if(select(topSock+1, &mask, 0, 0, NULL) == 1) {
      int rc, length = sizeof(struct sockaddr);

      if(!capturePackets) break;
  
      if(FD_ISSET((unsigned int)remIntSock, &mask))
	recvIntSock = remIntSock;
      else
	recvIntSock = locIntSock;
      
      rc = recvfrom(recvIntSock, udpBuf, 4096, 0, (struct sockaddr*)&source, &length);
      
      if(rc > 0) {
	udpBuf[rc] = '\0';
#ifdef DEBUG
	printf("Received: [%s]\n", udpBuf);
#endif
      } else {
	printf("Error while reading from socket.\n");
      }

      if(strncasecmp(udpBuf, HELLO_CMD, strlen(HELLO_CMD)) == 0) {
	snprintf(udpBuf, sizeof(udpBuf), "%s\n%s",  OK_RC, HELLO_CMD);
	rc = sendto(recvIntSock, udpBuf, strlen(udpBuf), 0, 
		    (struct sockaddr*)&source, sizeof(source));
      } else if(strncasecmp(udpBuf, GETHOST_CMD, strlen(GETHOST_CMD)) == 0) {
	char *strIdx = strtok_r(&udpBuf[strlen(GETHOST_CMD)+1], " ", &strtokState);
	u_int idx;
	
	if(strIdx == NULL) {
	  snprintf(udpBuf, sizeof(udpBuf), "%s\n", WRONG_COMMAND_SYNTAX_RC);
	  rc = sendto(recvIntSock, udpBuf, strlen(udpBuf), 0, 
		      (struct sockaddr*)&source, sizeof(source));
	  continue;
	} 
	  
	idx = atoi(strIdx);
	
	returnHostEntryIdx(idx, udpBuf);
	rc = sendto(recvIntSock, udpBuf, strlen(udpBuf), 0, 
		    (struct sockaddr*)&source, sizeof(source));
      } else if(strncasecmp(udpBuf, FIND_HOST_BY_IP_CMD, 
			    strlen(FIND_HOST_BY_IP_CMD)) == 0) {
	char *ipAddress = strtok_r(&udpBuf[strlen(FIND_HOST_BY_IP_CMD)+1],
				   " ", &strtokState);
	if(ipAddress == NULL) {
	  snprintf(udpBuf, sizeof(udpBuf), "%s\n", WRONG_COMMAND_SYNTAX_RC);
	  rc = sendto(recvIntSock, udpBuf, strlen(udpBuf), 0, 
		      (struct sockaddr*)&source, sizeof(source));
	  continue;
	}
      } else if(strncasecmp(udpBuf, FIND_HOST_BY_MAC_CMD, 
			    strlen(FIND_HOST_BY_MAC_CMD)) == 0) {
	char *macAddress = strtok_r(&udpBuf[strlen(FIND_HOST_BY_MAC_CMD)+1],
				    " ", &strtokState);
	
	if(macAddress == NULL) {
	  snprintf(udpBuf, sizeof(udpBuf), "%s\n", WRONG_COMMAND_SYNTAX_RC);
	  rc = sendto(recvIntSock, udpBuf, strlen(udpBuf), 0, 
		      (struct sockaddr*)&source, sizeof(source));
	  continue;
	} 
	
	returnHostEntry(findHostByMAC(macAddress), udpBuf);
	rc = sendto(recvIntSock, udpBuf, strlen(udpBuf), 0, 
		    (struct sockaddr*)&source, sizeof(source));
      } else {
	printf("Error while reading from Remote Interface Socket.\n");
	break;
      }
    }
  }

  termRemIntFunct();  

  return(0);
}
#endif

/* ****************************** */
  
static void handleRemIntHTTPrequest(char* url) {
  sendHTTPProtoHeader();
  sendHTTPHeaderType();
  printHTTPheader();

  sendString("<CENTER><FONT FACE=Helvetica><H1>"
	     "ntop Remote Interface"
	     "</H1><p></CENTER>\n");
  printHTTPtrailer();
}

 /* ****************************** */
 
static void startRemIntFunct(void) {
#ifdef MULTITHREADED
  createThread(&remIntTreadId, remIntLoop, NULL);
#endif
}

/* ****************************** */

static PluginInfo pluginInfo[] = {
  { "remoteInterface",
    "Remote Perl/C++ handler",
    "1.0", /* plugin version */
    "<A HREF=http://jake.unipi.it/~deri/>L.Deri</A>",
    "remoteInterface", /* http://<host>:<port>/plugins/remoteInterface */
    0, /* Not Active */
    startRemIntFunct, /* StartFunc */
    termRemIntFunct, /* TermFunc */
    NULL, /* PluginFunc */
    handleRemIntHTTPrequest,
    NULL, 
    NULL /* BPF filter */
  }
};

/* Plugin entry fctn */
#ifdef STATIC_PLUGIN
PluginInfo* remIntPluginEntryFctn() {
#else
PluginInfo* PluginEntryFctn() {
#endif

  remIntSock = 0;

  traceEvent(TRACE_INFO, "Welcome to ntop Remote Interface\n");
  return(pluginInfo);
}

