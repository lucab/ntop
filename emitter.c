/*
 *  Copyright (C) 2001 Luca Deri <deri@ntop.org>
 *
 *  		       http://www.ntop.org/
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
#include "globals-report.h"

#define PERL_LANGUAGE       1
#define PHP_LANGUAGE        2
#define NO_LANGUAGE         3
#define NB_LANGUAGES        3
#define DEFAULT_LANGUAGE    NO_LANGUAGE


/* 
   This file has been significantly reworked
   by Philippe Bereski <Philippe.Bereski@ms.alcatel.fr>

   Many thanks Philippe!
*/
char * languages[] = {"", "perl", "php", "no" };
char buf[256];

/* *************************** */

void initWriteArray ( int lang ) {
  switch (lang) {
  case PERL_LANGUAGE :
    sendString("%ntopHash = (\n");
    break ;
  case PHP_LANGUAGE :
    sendString("$ntopHash = array(\n");
    break ;
  case NO_LANGUAGE :
    break ;
  }
}

/* *************************** */

void endWriteArray (int lang) {
  switch (lang) {
  case PERL_LANGUAGE :
  case PHP_LANGUAGE :
    sendString(");\n");
    break ;
  case NO_LANGUAGE :
    sendString("\n");
    break ;
  }
}

/* *************************** */

void initWriteKey (int lang,char * indent,char * keyName) {
  switch (lang) {
  case PERL_LANGUAGE :
    if(snprintf(buf, sizeof(buf), "%s'%s' => {\n",indent, keyName) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
    break ;
  case PHP_LANGUAGE :
    if(snprintf(buf, sizeof(buf), "%s'%s' => array(\n",indent, keyName) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
    break ;
  case NO_LANGUAGE :
	
    break ;
  }
}

/* *************************** */

void endWriteKey (int lang,char * indent, char last) {
  /* If there is no indentation, this was the first level of key,
     hence the end of the list. Don't add a ',' at end.
  */
  switch (lang) {
  case PERL_LANGUAGE :
    if(snprintf(buf, sizeof(buf),"%s}%c\n",indent,last) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
    break ;
  case PHP_LANGUAGE :
    if(snprintf(buf, sizeof(buf),"%s)%c\n",indent,last) < 0)
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(buf);
    break ;
  case NO_LANGUAGE :
    if ( indent == "") sendString("\n");
    break ;
  }
}

/* *************************** */

void wrtStrItm (int lang,char * indent,char * name,char * value,char last) {
  switch (lang) {
  case PERL_LANGUAGE :
  case PHP_LANGUAGE :
    /* In the case of hostNumIpAddress and hostSymIpAddress, 
       the pointer is not null, but the string is empty.
       In that case, don't create the key in the array.
    */
    if (( value != NULL ) && ( value[0] != '\0'))  {
      if(snprintf(buf, sizeof(buf), "%s'%s' => '%s'%c\n", indent,name,value,last) < 0) 
	traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
    }
    break ;
  case NO_LANGUAGE :
    if ( value != NULL ) {
      if(snprintf(buf, sizeof(buf), "%s|",value) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
    } else {       
      if(snprintf(buf, sizeof(buf), "%s|","") < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");  sendString(buf);
    }
    break ;
  }
}

/* *************************** */

void wrtIntItm (int lang,char * indent,char * name,int value,char last) {
  char buf[80];
  sprintf (buf,"%d",value);
  wrtStrItm (lang, indent, name,  buf, last);
}

/* *************************** */

void wrtIntStrItm (int lang, char * indent,int name,char * value,char useless) {
  char buf[80];
  sprintf (buf,"%d",name);
  wrtStrItm (lang, indent, buf,  value, ',');
}

/* *************************** */

void wrtUintItm (int lang,char * indent,char * name,unsigned int value,char useless) {
  char buf[80];
  sprintf (buf,"%d",value);
  wrtStrItm (lang, indent, name,  buf, ',');
}

/* *************************** */

void wrtUcharItm (int lang,char * indent,char * name,u_char value,char useless) {
  char buf[80];
  sprintf (buf,"%d",value);
  wrtStrItm (lang, indent, name,  buf, ',');
}

/* *************************** */

void wrtFloatItm (int lang,char * indent,char * name,float value,char last) {
  char buf[80];
  sprintf (buf,"%0.2f",value);
  wrtStrItm (lang, indent, name, buf, last);
}

/* *************************** */

void wrtIntFloatItm (int lang,char * indent,int name,float value,char last) {
  char buf[80];
  sprintf (buf,"%d",name);
  wrtFloatItm (lang, indent, buf, value, last);
}

/* *************************** */

void wrtUlongItm (int lang,char * indent,char * name,unsigned long value,char useless) {
  char buf[80];
  sprintf (buf,"%lu",value);
  wrtStrItm (lang, indent, name,  buf, ',');
}

/* *************************** */

void wrtLlongItm (int lang,char * indent,char * name,TrafficCounter value,char last) {
  char buf[80];
  sprintf (buf,"%llu",value);
  wrtStrItm (lang, indent, name, buf, last);
}

/* *************************** */

void wrtTime_tItm (int lang,char * indent,char * name,time_t value,char useless) {
  char buf[80];
  sprintf (buf,"%ld",value);
  wrtStrItm (lang, indent, name, buf, ',');
}

/* *************************** */

void wrtUshortItm (int lang,char * indent,char * name,u_short value,char useless) {
  char buf[80];
  sprintf (buf,"%d",value);
  wrtStrItm (lang, indent, name,  buf, ',');
}

/* ********************************** */

void dumpNtopHashes(char* options) {
  char key[64];
  unsigned int idx, numEntries=0, lang=DEFAULT_LANGUAGE, j;
  HostTraffic *el;

  memset(key, 0, sizeof(key));

  if(options != NULL) {
    /* language now defined into "languages[]" */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0; int j;

      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      /* If argument contains "language=something", then
	 look in the table "languages" of known language for
	 the choosen language. 
      */

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcasecmp(tmpStr, "language") == 0) {
	  lang=DEFAULT_LANGUAGE;
	  for (j=1;j <= NB_LANGUAGES;j++) {
	    if(strcasecmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	} else if(strcmp(tmpStr, "key") == 0) {
	  strncpy(key, &tmpStr[i+1], sizeof(key));
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }
  /* debut trace
     if(snprintf(buf, sizeof(buf), "%s\n", languages[lang]) < 0)
     traceEvent(TRACE_ERROR, "Buffer overflow!");
     sendString(buf);
     traceEvent (TRACE_ERROR, buf);
     end trace */
  initWriteArray (lang);

  for(idx=0; idx<device[actualDeviceId].actualHashSize; idx++) {
    if((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL) {
      char *hostKey;

      if(key[0] != '\0') {
	if(strcmp(el->hostNumIpAddress, key)
	   && strcmp(el->ethAddressString, key)
	   && strcmp(el->hostSymIpAddress, key))
	  continue;
      }

      if(el->hostNumIpAddress[0] != '\0')
	hostKey = el->hostNumIpAddress;
      else
	hostKey = el->ethAddressString;

      if(numEntries > 0) { endWriteKey (lang,"",','); }

      initWriteKey (lang, "", hostKey);

      /* ************************ */

      wrtUintItm (lang, "\t","index", idx,' ');

      wrtStrItm (lang, "\t", "hostNumIpAddress", el->hostNumIpAddress,',');
      wrtStrItm (lang, "\t", "hostSymIpAddress", el->hostSymIpAddress,',');

      wrtTime_tItm (lang, "\t", "firstSeen",   el->firstSeen,' ');
      wrtTime_tItm (lang, "\t", "lastSeen",    el->lastSeen,' ');
      wrtUshortItm(lang, "\t", "minTTL",       el->minTTL,' ');
      wrtUshortItm(lang, "\t", "maxTTL",       el->maxTTL,' ');
      wrtStrItm (lang, "\t", "nbHostName",     el->nbHostName,',');
      wrtStrItm (lang, "\t", "nbDomainName",   el->nbDomainName,',');
      wrtStrItm (lang, "\t", "nbDescr",        el->nbDescr,',');
      wrtUcharItm  (lang, "\t", "nodeType",    el->nbNodeType,' ');
      wrtStrItm (lang, "\t", "atNodeName",     el->atNodeName,',');
      wrtUshortItm(lang, "\t", "atNetwork",    el->atNetwork,' ');
      wrtUcharItm  (lang, "\t", "atNode",      el->atNode,' ');
      wrtStrItm (lang, "\t", "ipxHostName",    el->ipxHostName,',');
      wrtLlongItm  (lang, "\t", "pktSent",     el->pktSent,',');
      wrtLlongItm  (lang, "\t", "pktReceived", el->pktReceived,',');
      wrtLlongItm  (lang, "\t", "pktDuplicatedAckSent",el->pktDuplicatedAckSent,',');
      wrtLlongItm  (lang, "\t", "pktDuplicatedAckRcvd",el->pktDuplicatedAckRcvd,',');
      wrtLlongItm  (lang, "\t", "pktBroadcastSent",    el->pktBroadcastSent,',');
      wrtLlongItm  (lang, "\t", "bytesMulticastSent",  el->bytesMulticastSent,',');
      wrtLlongItm  (lang, "\t", "pktMulticastSent",    el->pktMulticastSent,',');
      wrtLlongItm  (lang, "\t", "bytesMulticastSent",  el->bytesMulticastSent,',');
      wrtLlongItm  (lang, "\t", "pktMulticastRcvd",    el->pktMulticastRcvd,',');
      wrtLlongItm  (lang, "\t", "bytesSent",           el->bytesSent,',');
      wrtLlongItm  (lang, "\t", "bytesSentLocally",    el->bytesSentLocally,',');
      wrtLlongItm  (lang, "\t", "bytesSentRemotely",   el->bytesSentRemotely,',');
      wrtLlongItm  (lang, "\t", "bytesReceived",       el->bytesReceived,',');
      wrtLlongItm  (lang, "\t", "bytesReceivedLocally", el->bytesReceivedLocally,',');
      wrtLlongItm  (lang, "\t", "bytesReceivedFromRemote",
		    el->bytesReceivedFromRemote,',');
      wrtFloatItm  (lang, "\t", "actualRcvdThpt",    el->actualRcvdThpt,',');
      wrtFloatItm  (lang, "\t", "lastHourRcvdThpt",  el->lastHourRcvdThpt,',');
      wrtFloatItm  (lang, "\t", "averageRcvdThpt",   el->averageRcvdThpt,',');
      wrtFloatItm  (lang, "\t", "peakRcvdThpt",      el->peakRcvdThpt,',');
      wrtFloatItm  (lang, "\t", "actualSentThpt",    el->actualSentThpt,',');
      wrtFloatItm  (lang, "\t", "lastHourSentThpt",  el->lastHourSentThpt,',');
      wrtFloatItm  (lang, "\t", "averageSentThpt",   el->averageSentThpt,',');
      wrtFloatItm  (lang, "\t", "peakSentThpt",      el->peakSentThpt,',');
      wrtFloatItm  (lang, "\t", "actualRcvdPktThpt", el->actualRcvdPktThpt,',');
      wrtFloatItm  (lang, "\t", "averageRcvdPktThpt",el->averageRcvdPktThpt,',');
      wrtFloatItm  (lang, "\t", "peakRcvdPktThpt",   el->peakRcvdPktThpt,',');
      wrtFloatItm  (lang, "\t", "actualSentPktThpt", el->actualSentPktThpt,',');
      wrtFloatItm  (lang, "\t", "averageSentPktThpt",el->tcpSentLocally,',');
      wrtLlongItm  (lang, "\t", "tcpSentRemotely",   el->tcpSentRemotely,',');
      wrtLlongItm  (lang, "\t", "udpSentLocally",    el->udpSentLocally,',');
      wrtLlongItm  (lang, "\t", "udpSentRemotely",   el->udpSentRemotely,',');
      wrtLlongItm  (lang, "\t", "icmpSent",          el->icmpSent,',');
      wrtLlongItm  (lang, "\t", "ospfSent",          el->ospfSent,',');
      wrtLlongItm  (lang, "\t", "igmpSent",          el->igmpSent,',');
      wrtLlongItm  (lang, "\t", "tcpReceivedLocally",el->tcpReceivedLocally,',');
      wrtLlongItm  (lang, "\t", "tcpReceivedFromRemote",el->tcpReceivedFromRemote,',');
      wrtLlongItm  (lang, "\t", "udpReceivedLocally",el->udpReceivedLocally,',');
      wrtLlongItm  (lang, "\t", "udpReceivedFromRemote",el->udpReceivedFromRemote,',');
      wrtLlongItm  (lang, "\t", "icmpReceived",      el->icmpReceived,',');
      wrtLlongItm  (lang, "\t", "ospfReceived",      el->ospfReceived,',');
      wrtLlongItm  (lang, "\t", "igmpReceived",      el->igmpReceived,',');

      /* ***************************** */

      wrtLlongItm  (lang, "\t", "stpSent",          el->stpSent,',');
      wrtLlongItm  (lang, "\t", "stpReceived",      el->stpReceived,',');
      wrtLlongItm  (lang, "\t", "ipxSent",          el->ipxSent,',');
      wrtLlongItm  (lang, "\t", "ipxReceived",      el->ipxReceived,',');
      wrtLlongItm  (lang, "\t", "osiSent",          el->osiSent,',');
      wrtLlongItm  (lang, "\t", "osiReceived",      el->osiReceived,',');
      wrtLlongItm  (lang, "\t", "dlcSent",          el->dlcSent,',');
      wrtLlongItm  (lang, "\t", "dlcReceived",      el->dlcReceived,',');
      wrtLlongItm  (lang, "\t", "arp_rarpSent",     el->arp_rarpSent,',');
      wrtLlongItm  (lang, "\t", "arp_rarpReceived", el->arp_rarpReceived,',');
      wrtLlongItm  (lang, "\t", "arpReqPktsSent",   el->arpReqPktsSent,',');
      wrtLlongItm  (lang, "\t", "arpReplyPktsSent", el->arpReplyPktsSent,',');
      wrtLlongItm  (lang, "\t", "arpReplyPktsRcvd", el->arpReplyPktsRcvd,',');
      wrtLlongItm  (lang, "\t", "decnetSent",       el->decnetSent,',');
      wrtLlongItm  (lang, "\t", "decnetReceived",   el->decnetReceived,',');
      wrtLlongItm  (lang, "\t", "appletalkSent",    el->appletalkSent,',');
      wrtLlongItm  (lang, "\t", "appletalkReceived",el->appletalkReceived,',');
      wrtLlongItm  (lang, "\t", "netbiosSent",      el->netbiosSent,',');
      wrtLlongItm  (lang, "\t", "netbiosReceived",  el->netbiosReceived,',');
      wrtLlongItm  (lang, "\t", "qnxSent",          el->qnxSent,',');
      wrtLlongItm  (lang, "\t", "qnxReceived",      el->qnxReceived,',');
      wrtLlongItm  (lang, "\t", "otherSent",        el->otherSent,',');
      wrtLlongItm  (lang, "\t", "otherReceived",    el->otherReceived,',');
      /* ********************************* */

      if(el->routedTraffic) {
	initWriteKey(lang, "\t", "RoutingCounter");
	wrtLlongItm(lang,"\t\t","routedPkts", el->routedTraffic->routedPkts,',');
	wrtLlongItm(lang,"\t\t","routedBytes", el->routedTraffic->routedBytes,',');
	endWriteKey(lang,"\t",',');
      }

      if(el->protoIPTrafficInfos) {
	initWriteKey (lang, "\t", "IP");
	
	for(j=0; j<numIpProtosToMonitor; j++) {
	  
	  if(j > 0) { endWriteKey (lang,"\t\t",','); }
	  
	  initWriteKey (lang, "\t\t", protoIPTrafficInfos[j]);
	  wrtLlongItm(lang,"\t\t\t","sentLocally",
		      el->protoIPTrafficInfos[j].sentLocally,',');
	  wrtLlongItm(lang,"\t\t\t","sentRemotely",
		      el->protoIPTrafficInfos[j].sentRemotely,',');
	  wrtLlongItm(lang,"\t\t\t","receivedLocally",
		      el->protoIPTrafficInfos[j].receivedLocally,',');
	  wrtLlongItm(lang,"\t\t\t","receivedFromRemote",
		      el->protoIPTrafficInfos[j].receivedFromRemote,' ');
	}
	endWriteKey (lang,"\t\t",',');
	endWriteKey (lang,"\t",',');
      }

      /* ***************************************** */

      if(el->icmpInfo != NULL) {
        initWriteKey (lang, "\t", "icmp");
        wrtUlongItm(lang,"\t\t","SENT_ECHO",
		    el->icmpInfo->icmpMsgSent[ICMP_ECHO],' ');
        wrtUlongItm(lang,"\t\t","SENT_ECHOREPLY",
		    el->icmpInfo->icmpMsgSent[ICMP_ECHOREPLY],' ');
        wrtUlongItm(lang,"\t\t","SENT_UNREACH",
		    el->icmpInfo->icmpMsgSent[ICMP_UNREACH],' ');
        wrtUlongItm(lang,"\t\t","SENT_ROUTERADVERT",
		    el->icmpInfo->icmpMsgSent[ICMP_ROUTERADVERT],' ');
        wrtUlongItm(lang,"\t\t","SENT_TMXCEED",
		    el->icmpInfo->icmpMsgSent[ICMP_TIMXCEED],' ');
        wrtUlongItm(lang,"\t\t","SENT_PARAMPROB",
		    el->icmpInfo->icmpMsgSent[ICMP_PARAMPROB],' ');
        wrtUlongItm(lang,"\t\t","SENT_MASKREPLY",
		    el->icmpInfo->icmpMsgSent[ICMP_MASKREPLY],' ');
        wrtUlongItm(lang,"\t\t","SENT_MASKREQ",
		    el->icmpInfo->icmpMsgSent[ICMP_MASKREQ],' ');
        wrtUlongItm(lang,"\t\t","SENT_INFO_REQUEST",
		    el->icmpInfo->icmpMsgSent[ICMP_INFO_REQUEST],' ');
        wrtUlongItm(lang,"\t\t","SENT_INFO_REPLY",
		    el->icmpInfo->icmpMsgSent[ICMP_INFO_REPLY],' ');
        wrtUlongItm(lang,"\t\t","SENT_TIMESTAMP",
		    el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMP],' ');
        wrtUlongItm(lang,"\t\t","SENT_TIMESTAMPREPLY",
		    el->icmpInfo->icmpMsgSent[ICMP_TIMESTAMPREPLY],' ');
        wrtUlongItm(lang,"\t\t","SENT_SOURCE_QUENCH",
		    el->icmpInfo->icmpMsgSent[ICMP_SOURCE_QUENCH],' ');

	/* *********************************************** */

        wrtUlongItm(lang,"\t\t","RCVD_ECHO",
		    el->icmpInfo->icmpMsgRcvd[ICMP_ECHO],' ');
        wrtUlongItm(lang,"\t\t","RCVD_ECHOREPLY",
		    el->icmpInfo->icmpMsgRcvd[ICMP_ECHOREPLY],' ');
        wrtUlongItm(lang,"\t\t","RCVD_UNREACH",
		    el->icmpInfo->icmpMsgRcvd[ICMP_UNREACH],' ');
        wrtUlongItm(lang,"\t\t","RCVD_ROUTERADVERT",
		    el->icmpInfo->icmpMsgRcvd[ICMP_ROUTERADVERT],' ');
        wrtUlongItm(lang,"\t\t","RCVD_TMXCEED",
		    el->icmpInfo->icmpMsgRcvd[ICMP_TIMXCEED],' ');
        wrtUlongItm(lang,"\t\t","RCVD_PARAMPROB",
		    el->icmpInfo->icmpMsgRcvd[ICMP_PARAMPROB],' ');
        wrtUlongItm(lang,"\t\t","RCVD_MASKREPLY",
		    el->icmpInfo->icmpMsgRcvd[ICMP_MASKREPLY],' ');
        wrtUlongItm(lang,"\t\t","RCVD_MASKREQ",
		    el->icmpInfo->icmpMsgRcvd[ICMP_MASKREQ],' ');
        wrtUlongItm(lang,"\t\t","RCVD_INFO_REQUEST",
		    el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REQUEST],' ');
        wrtUlongItm(lang,"\t\t","RCVD_INFO_REPLY",
		    el->icmpInfo->icmpMsgRcvd[ICMP_INFO_REPLY],' ');
        wrtUlongItm(lang,"\t\t","RCVD_TIMESTAMP",
		    el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMP],' ');
        wrtUlongItm(lang,"\t\t","RCVD_TIMESTAMPREPLY",
		    el->icmpInfo->icmpMsgRcvd[ICMP_TIMESTAMPREPLY],' ');
        wrtUlongItm(lang,"\t\t","RCVD_SOURCE_QUENCH",
		    el->icmpInfo->icmpMsgRcvd[ICMP_SOURCE_QUENCH],' ');

        endWriteKey (lang,"\t",',');
      }

      /* ********************************* */

      if(el->securityHostPkts != NULL) {
        initWriteKey (lang, "\t", "securityPkts");
  
        wrtLlongItm(lang,"\t\t","synPktsSent",
		    el->securityHostPkts->synPktsSent.value,',');
        wrtLlongItm(lang,"\t\t","synPktsRcvd",
		    el->securityHostPkts->synPktsRcvd.value,',');

        wrtLlongItm(lang,"\t\t","rstPktsSent",
		    el->securityHostPkts->rstPktsSent.value,',');
        wrtLlongItm(lang,"\t\t","rstPktsRcvd",
		    el->securityHostPkts->rstPktsRcvd.value,',');

        wrtLlongItm(lang,"\t\t","rstAckPktsSent",
		    el->securityHostPkts->rstAckPktsSent.value,',');
        wrtLlongItm(lang,"\t\t","rstAckPktsRcvd",
		    el->securityHostPkts->rstAckPktsRcvd.value,',');

        wrtLlongItm(lang,"\t\t","synFinPktsSent",
		    el->securityHostPkts->synFinPktsSent.value,',');
        wrtLlongItm(lang,"\t\t","synFinPktsRcvd",
		    el->securityHostPkts->synFinPktsRcvd.value,',');

        wrtLlongItm(lang,"\t\t","finPushUrgPktsSent",
		    el->securityHostPkts->finPushUrgPktsSent.value,',');
        wrtLlongItm(lang,"\t\t","finPushUrgPktsRcvd",
		    el->securityHostPkts->finPushUrgPktsRcvd.value,',');

        wrtLlongItm(lang,"\t\t","nullPktsSent",
		    el->securityHostPkts->nullPktsSent.value,',');
        wrtLlongItm(lang,"\t\t","nullPktsRcvd",
		    el->securityHostPkts->nullPktsRcvd.value,',');

        wrtLlongItm(lang,"\t\t","ackScanSent",
		    el->securityHostPkts->ackScanSent.value,',');
        wrtLlongItm(lang,"\t\t","ackScanRcvd",
		    el->securityHostPkts->ackScanRcvd.value,',');

        wrtLlongItm(lang,"\t\t","xmasScanSent",
		    el->securityHostPkts->xmasScanSent.value,',');
        wrtLlongItm(lang,"\t\t","xmasScanRcvd",
		    el->securityHostPkts->xmasScanRcvd.value,',');

        wrtLlongItm(lang,"\t\t","finScanSent",
		    el->securityHostPkts->finScanSent.value,',');
        wrtLlongItm(lang,"\t\t","finScanRcvd",
		    el->securityHostPkts->finScanRcvd.value,',');

        wrtLlongItm(lang,"\t\t","nullScanSent",
		    el->securityHostPkts->nullScanSent.value,',');
        wrtLlongItm(lang,"\t\t","nullScanRcvd",
		    el->securityHostPkts->nullScanRcvd.value,',');

        wrtLlongItm(lang,"\t\t","rejectedTCPConnSent",
		    el->securityHostPkts->rejectedTCPConnSent.value,',');
        wrtLlongItm(lang,"\t\t","rejectedTCPConnRcvd",
		    el->securityHostPkts->rejectedTCPConnRcvd.value,',');

        wrtLlongItm(lang,"\t\t","establishedTCPConnSent",
		    el->securityHostPkts->establishedTCPConnSent.value,',');
        wrtLlongItm(lang,"\t\t","establishedTCPConnRcvd",
		    el->securityHostPkts->establishedTCPConnRcvd.value,',');

        wrtLlongItm(lang,"\t\t","udpToClosedPortSent",
		    el->securityHostPkts->udpToClosedPortSent.value,',');
        wrtLlongItm(lang,"\t\t","udpToClosedPortRcvd",
		    el->securityHostPkts->udpToClosedPortRcvd.value,',');

        wrtLlongItm(lang,"\t\t","udpToDiagnosticPortSent",
		    el->securityHostPkts->udpToDiagnosticPortSent.value,',');
        wrtLlongItm(lang,"\t\t","udpToDiagnosticPortRcvd",
		    el->securityHostPkts->udpToDiagnosticPortRcvd.value,',');

        wrtLlongItm(lang,"\t\t","tcpToDiagnosticPortSent",
		    el->securityHostPkts->tcpToDiagnosticPortSent.value,',');
        wrtLlongItm(lang,"\t\t","tcpToDiagnosticPortRcvd",
		    el->securityHostPkts->tcpToDiagnosticPortRcvd.value,',');

        wrtLlongItm(lang,"\t\t","tinyFragmentSent",
		    el->securityHostPkts->tinyFragmentSent.value,',');
        wrtLlongItm(lang,"\t\t","tinyFragmentRcvd",
		    el->securityHostPkts->tinyFragmentRcvd.value,',');

        wrtLlongItm(lang,"\t\t","icmpFragmentSent",
		    el->securityHostPkts->icmpFragmentSent.value,',');
        wrtLlongItm(lang,"\t\t","icmpFragmentRcvd",
		    el->securityHostPkts->icmpFragmentRcvd.value,',');

        wrtLlongItm(lang,"\t\t","overlappingFragmentSent",
		    el->securityHostPkts->overlappingFragmentSent.value,',');
        wrtLlongItm(lang,"\t\t","overlappingFragmentRcvd",
		    el->securityHostPkts->overlappingFragmentRcvd.value,',');

        wrtLlongItm(lang,"\t\t","closedEmptyTCPConnSent",
		    el->securityHostPkts->closedEmptyTCPConnSent.value,',');
        wrtLlongItm(lang,"\t\t","closedEmptyTCPConnRcvd",
		    el->securityHostPkts->closedEmptyTCPConnRcvd.value,',');

        wrtLlongItm(lang,"\t\t","icmpPortUnreachSent",
		    el->securityHostPkts->icmpPortUnreachSent.value,',');
        wrtLlongItm(lang,"\t\t","icmpPortUnreachRcvd",
		    el->securityHostPkts->icmpPortUnreachRcvd.value,',');

        wrtLlongItm(lang,"\t\t","icmpHostNetUnreachSent",
		    el->securityHostPkts->icmpHostNetUnreachSent.value,',');
        wrtLlongItm(lang,"\t\t","icmpHostNetUnreachRcvd",
		    el->securityHostPkts->icmpHostNetUnreachRcvd.value,',');

        wrtLlongItm(lang,"\t\t","icmpProtocolUnreachSent",
		    el->securityHostPkts->icmpProtocolUnreachSent.value,',');
        wrtLlongItm(lang,"\t\t","icmpProtocolUnreachRcvd",
		    el->securityHostPkts->icmpProtocolUnreachRcvd.value,',');

        wrtLlongItm(lang,"\t\t","icmpAdminProhibitedSent",
		    el->securityHostPkts->icmpAdminProhibitedSent.value,',');
        wrtLlongItm(lang,"\t\t","icmpAdminProhibitedRcvd",
		    el->securityHostPkts->icmpAdminProhibitedRcvd.value,',');

        wrtLlongItm(lang,"\t\t","malformedPktsSent",
		    el->securityHostPkts->malformedPktsSent.value,',');
        wrtLlongItm(lang,"\t\t","malformedPktsRcvd",
		    el->securityHostPkts->malformedPktsRcvd.value,',');

	endWriteKey (lang,"\t",',');
      }

      /* ***************************** */
      wrtStrItm (lang, "\t", "ethAddressString",el->ethAddressString,' ');

      numEntries++;
    }
  }
  endWriteKey (lang,"",' ');
  endWriteArray(lang);
}

/* ********************************** */

void dumpNtopHashIndexes(char* options) {
  unsigned int idx, numEntries=0, lang=DEFAULT_LANGUAGE;
  HostTraffic *el;

  if(options != NULL) {
    /* language=[perl|php] */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0; int j;

      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcmp(tmpStr, "language") == 0) {

	  lang=DEFAULT_LANGUAGE;
	  for (j=1;j <= NB_LANGUAGES;j++) {
	    if(strcmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }
  initWriteArray (lang);

  for(idx=1; idx<device[actualDeviceId].actualHashSize; idx++) {
    if(((el = device[actualReportDeviceId].hash_hostTraffic[idx]) != NULL)
       && (broadcastHost(el) == 0)) {
      char *hostKey;

      if(el->hostNumIpAddress[0] != '\0')
	hostKey = el->hostNumIpAddress;
      else
	hostKey = el->ethAddressString;

      wrtIntStrItm ( lang, "", idx, hostKey,'\n');

      numEntries++;
    }
  }

  endWriteArray(lang);
}

/* ********************************** */

void dumpNtopTrafficInfo(char* options) {
  char intoabuf[32], key[16], localbuf[32];
  int lang=DEFAULT_LANGUAGE, i;

  memset(key, 0, sizeof(key));

  if(options != NULL) {
    /* language=[perl|php] */
    char *tmpStr, *strtokState;

    tmpStr = strtok_r(options, "&", &strtokState);

    while(tmpStr != NULL) {
      int i=0; int j;

      while((tmpStr[i] != '\0') && (tmpStr[i] != '='))
	i++;

      if(tmpStr[i] == '=') {
	tmpStr[i] = 0;

	if(strcmp(tmpStr, "language") == 0) {
	  lang=DEFAULT_LANGUAGE;
	  for (j=1;j <= NB_LANGUAGES;j++) {
	    if(strcmp(&tmpStr[i+1], languages[j]) == 0)
	      lang = j;
	  }
	} else if(strcmp(tmpStr, "key") == 0) {
	  strncpy(key, &tmpStr[i+1], sizeof(key));
	}
      }

      tmpStr = strtok_r(NULL, "&", &strtokState);
    }
  }
  initWriteArray (lang);

  for(i=0; i<numDevices; i++) {
    int j;

    if(device[i].virtualDevice) continue;


    if( i > 0) { endWriteKey (lang,"",','); }

    if((key[0] != '\0') && (strcmp(key, device[i].name) != 0))
      continue;

    initWriteKey (lang, "", device[i].name);


    wrtStrItm(lang, "\t", "ipdot", device[i].ipdot,',');
    wrtStrItm(lang, "\t", "fqdn", device[i].fqdn,',');

    snprintf(localbuf, sizeof(localbuf), "%s", 
	     _intoa(device[i].network, intoabuf, sizeof(intoabuf)));
    wrtStrItm(lang, "\t", "network",  localbuf,',');
    snprintf(localbuf, sizeof(localbuf), "%s", 
	     _intoa(device[i].netmask, intoabuf, sizeof(intoabuf)));
    wrtStrItm(lang, "\t", "netmask", localbuf,',');
    snprintf(localbuf, sizeof(localbuf), "%s", 
	     _intoa(device[i].ifAddr, intoabuf, sizeof(intoabuf)));
    wrtStrItm(lang, "\t", "ifAddr",  localbuf,',');

    wrtTime_tItm (lang, "\t", "started",  device[i].started,' ');
    wrtTime_tItm (lang, "\t", "firstpkt", device[i].firstpkt,' ');
    wrtTime_tItm (lang, "\t", "lastpkt",  device[i].lastpkt,' ');
    wrtIntItm    (lang, "\t", "virtualDevice",(int)device[i].virtualDevice,',');
    wrtIntItm    (lang, "\t", "snaplen",  device[i].snaplen,',');
    wrtIntItm    (lang, "\t", "datalink", device[i].datalink,',');
    wrtStrItm    (lang, "\t", "filter",   device[i].filter ? device[i].filter : "",',');
    wrtLlongItm  (lang, "\t", "droppedPkts",device[i].droppedPkts,',');
    wrtLlongItm  (lang, "\t", "ethernetPkts",device[i].ethernetPkts,',');
    wrtLlongItm  (lang, "\t", "broadcastPkts",device[i].broadcastPkts,',');
    wrtLlongItm  (lang, "\t", "multicastPkts",device[i].multicastPkts,',');
    wrtLlongItm  (lang, "\t", "ethernetBytes",device[i].ethernetBytes,',');
    wrtLlongItm  (lang, "\t", "ipBytes",device[i].ipBytes,',');
    wrtLlongItm  (lang, "\t", "tcpBytes",device[i].tcpBytes,',');
    wrtLlongItm  (lang, "\t", "udpBytes",device[i].udpBytes,',');
    wrtLlongItm  (lang, "\t", "otherIpBytes",device[i].otherIpBytes,',');
    wrtLlongItm  (lang, "\t", "icmpBytes",device[i].icmpBytes,',');
    wrtLlongItm  (lang, "\t", "dlcBytes",device[i].dlcBytes,',');
    wrtLlongItm  (lang, "\t", "ipxBytes",device[i].ipxBytes,',');
    wrtLlongItm  (lang, "\t", "stpBytes",device[i].stpBytes,',');
    wrtLlongItm  (lang, "\t", "decnetBytes",device[i].decnetBytes,',');
    wrtLlongItm  (lang, "\t", "netbiosBytes",device[i].netbiosBytes,',');
    wrtLlongItm  (lang, "\t", "arpRarpBytes",device[i].arpRarpBytes,',');
    wrtLlongItm  (lang, "\t", "atalkBytes",device[i].atalkBytes,',');
    wrtLlongItm  (lang, "\t", "ospfBytes",device[i].ospfBytes,',');
    wrtLlongItm  (lang, "\t", "egpBytes",device[i].egpBytes,',');
    wrtLlongItm  (lang, "\t", "igmpBytes",device[i].igmpBytes,',');
    wrtLlongItm  (lang, "\t", "osiBytes",device[i].osiBytes,',');
    wrtLlongItm  (lang, "\t", "qnxBytes",device[i].qnxBytes,',');
    wrtLlongItm  (lang, "\t", "otherBytes",device[i].otherBytes,',');
    wrtLlongItm  (lang, "\t", "lastMinEthernetBytes", 
		  device[i].lastMinEthernetBytes,',');
    wrtLlongItm  (lang, "\t", "lastFiveMinsEthernetBytes", 
		  device[i].lastFiveMinsEthernetBytes,',');
    wrtLlongItm  (lang, "\t", "lastMinEthernetPkts",device[i].lastMinEthernetPkts,',');
    wrtLlongItm  (lang, "\t", "lastFiveMinsEthernetPkts",
		  device[i].lastFiveMinsEthernetPkts,',');
    wrtLlongItm  (lang, "\t", "upTo64",device[i].rcvdPktStats.upTo64,',');
    wrtLlongItm  (lang, "\t", "upTo128",device[i].rcvdPktStats.upTo128,',');
    wrtLlongItm  (lang, "\t", "upTo256",device[i].rcvdPktStats.upTo256,',');
    wrtLlongItm  (lang, "\t", "upTo512",device[i].rcvdPktStats.upTo512,',');
    wrtLlongItm  (lang, "\t", "upTo1024",device[i].rcvdPktStats.upTo1024,',');
    wrtLlongItm  (lang, "\t", "upTo1518",device[i].rcvdPktStats.upTo1518,',');
    wrtLlongItm  (lang, "\t", "above1518",device[i].rcvdPktStats.above1518,',');
    wrtLlongItm  (lang, "\t", "shortest",device[i].rcvdPktStats.shortest,',');
    wrtLlongItm  (lang, "\t", "longest",device[i].rcvdPktStats.longest,',');
    wrtLlongItm  (lang, "\t", "badChecksum",device[i].rcvdPktStats.badChecksum,',');
    wrtLlongItm  (lang, "\t", "tooLong",device[i].rcvdPktStats.tooLong,',');
    wrtFloatItm  (lang, "\t", "peakThroughput",device[i].peakThroughput,',');
    wrtFloatItm  (lang, "\t", "actualThpt",device[i].actualThpt,',');
    wrtFloatItm  (lang, "\t", "lastMinThpt",device[i].lastMinThpt,',');
    wrtFloatItm  (lang, "\t", "lastFiveMinsThpt",device[i].lastFiveMinsThpt,',');
    wrtFloatItm  (lang, "\t", "peakPacketThroughput",device[i].peakPacketThroughput,',');
    wrtFloatItm  (lang, "\t", "actualPktsThpt",device[i].actualPktsThpt,',');
    wrtFloatItm  (lang, "\t", "lastMinPktsThpt",device[i].lastMinPktsThpt,',');
    wrtFloatItm  (lang, "\t", "lastFiveMinsPktsThpt",device[i].lastFiveMinsPktsThpt,',');
    wrtLlongItm  (lang, "\t", "throughput", device[i].throughput,',');
    wrtFloatItm  (lang, "\t", "packetThroughput",device[i].packetThroughput,',');

    /* ********************************* */
    initWriteKey (lang, "\t", "last60MinutesThpt");

    for(j=0; j<59; j++) {
      wrtIntFloatItm(lang,"\t\t",j+1,device[i].last60MinutesThpt[j].trafficValue,',');
    }
    wrtIntFloatItm(lang,"\t\t",j+1, device[i].last60MinutesThpt[j].trafficValue,' ');
    endWriteKey(lang,"\t",',');

    /* ********************************* */

    initWriteKey (lang, "\t", "last24HoursThpt");

    for(j=0; j<23; j++) {
      wrtIntFloatItm  (lang, "\t\t", j+1, device[i].last24HoursThpt[j].trafficValue,',');
    }
    wrtIntFloatItm(lang,"\t\t",j+1,device[i].last24HoursThpt[j].trafficValue,' ');
    endWriteKey(lang,"\t",',');

    /* ********************************* */

    initWriteKey (lang, "\t", "last30daysThpt");

    for(j=0; j<29; j++) {
      wrtIntFloatItm(lang,"\t\t",j+1,device[i].last30daysThpt[j],',');
    }
    wrtIntFloatItm(lang,"\t\t",j+1,device[i].last30daysThpt[j],' ');
    endWriteKey(lang,"\t",',');

    /* ********************************* */

    if(device[i].ipProtoStats != NULL) {
      initWriteKey (lang, "\t", "IP");

      for(j=0; j<numIpProtosToMonitor; j++) {
	if(j > 0) endWriteKey (lang, "\t\t",',');
        initWriteKey (lang, "\t\t", protoIPTrafficInfos[j]);
        wrtLlongItm(lang,"\t\t\t","local",
		    device[i].ipProtoStats[j].local,',');
        wrtLlongItm(lang,"\t\t\t","local2remote",
		    device[i].ipProtoStats[j].local2remote,',');
        wrtLlongItm(lang,"\t\t\t","remote2local",
		    device[i].ipProtoStats[j].remote2local,',');
        wrtLlongItm(lang,"\t\t\t","remote",
		    device[i].ipProtoStats[j].remote,' ');
      }
      endWriteKey(lang,"\t\t",',');
      endWriteKey(lang,"\t",',');
    }

    /* ********************************* */

    initWriteKey (lang, "\t", "TCPflags");

    wrtLlongItm(lang,"\t\t","numEstablishedTCPConnections",
		device[i].numEstablishedTCPConnections,' ');

    endWriteKey(lang,"\t",',');

    /* ********************************* */

    wrtLlongItm(lang,"\t","tcpLocal", 
		device[i].tcpGlobalTrafficStats.local,',');
    wrtLlongItm(lang,"\t","tcpLocal2Remote",  
		device[i].tcpGlobalTrafficStats.local2remote,',');
    wrtLlongItm(lang,"\t","tcpRemote",  
		device[i].tcpGlobalTrafficStats.remote,',');
    wrtLlongItm(lang,"\t","tcpRemote2Local",  
		device[i].tcpGlobalTrafficStats.remote2local,',');

    /* ********************************* */
    wrtLlongItm(lang,"\t","udpLocal",  
		device[i].udpGlobalTrafficStats.local,',');
    wrtLlongItm(lang,"\t","udpLocal2Remote",  
		device[i].udpGlobalTrafficStats.local2remote,',');
    wrtLlongItm(lang,"\t","udpRemote",  
		device[i].udpGlobalTrafficStats.remote,',');
    wrtLlongItm(lang,"\t","udpRemote2Local",  
		device[i].udpGlobalTrafficStats.remote2local,',');

    /* ********************************* */
    wrtLlongItm(lang,"\t","icmpLocal", 
		device[i].icmpGlobalTrafficStats.local,',');
    wrtLlongItm(lang,"\t","icmpLocal2Remote", 
		device[i].icmpGlobalTrafficStats.local2remote,',');
    wrtLlongItm(lang,"\t","icmpRemote",
		device[i].icmpGlobalTrafficStats.remote,',');
    wrtLlongItm(lang,"\t","icmpRemote2Local",
		device[i].icmpGlobalTrafficStats.remote2local,' ');
  }
  endWriteKey(lang,"",' ');
  endWriteArray(lang);
}


